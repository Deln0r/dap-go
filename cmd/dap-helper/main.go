// Command dap-helper runs the dap-go Helper-role aggregator as an HTTP server
// that speaks the divviup/janus interop test API. It is a proof-of-concept
// harness for the Janus cross-implementation smoke, not a production server:
// one in-memory store, one shared HPKE keypair, no request authentication.
//
// It serves three things:
//   - the interop test API: POST /internal/test/{ready,endpoint_for_task,add_task}
//   - the Helper HPKE config: GET /hpke_config (HpkeConfigList, §4.4.1)
//   - the DAP aggregation sub-protocol under /tasks/... (pkg/dap/helper.Handler)
//
// Tasks are registered in the Janus "dap-18" wire variant (see INTEROP_FINDINGS),
// so the Helper accepts PUT-to-resource init with the 3-field input-share AAD.
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"strings"

	"github.com/Deln0r/dap-go/internal/hpke"
	"github.com/Deln0r/dap-go/pkg/dap/helper"
	"github.com/Deln0r/dap-go/pkg/dap/wire"
)

const helperHpkeConfigID wire.HpkeConfigID = 1

// IANA HPKE code points for the suite below (X25519-HKDF-SHA256 / HKDF-SHA256 /
// AES-128-GCM), as carried in an HpkeConfig (§4.4.1).
const (
	kemX25519HkdfSha256 wire.HpkeKemID  = 0x0020
	kdfHkdfSha256       wire.HpkeKdfID  = 0x0001
	aeadAes128Gcm       wire.HpkeAeadID = 0x0001
)

var smokeSuite = hpke.Suite{
	KEM:  hpke.KEMX25519HKDFSHA256,
	KDF:  hpke.KDFHKDFSHA256,
	AEAD: hpke.AEADAES128GCM,
}

const hpkeConfigListMediaType = "application/ppm-dap;message=hpke-config-list"

// aggregatorAddTaskRequest mirrors the divviup/janus interop add_task body
// (interop_binaries AggregatorAddTaskRequest). Only the fields the Helper needs
// are read.
type aggregatorAddTaskRequest struct {
	TaskID              string          `json:"task_id"`         // unpadded base64url
	Leader              string          `json:"leader"`          // URL
	Helper              string          `json:"helper"`          // URL
	Vdaf                json.RawMessage `json:"vdaf"`            // {"type":"Prio3Count"}
	Role                string          `json:"role"`            // "Leader" / "Helper"
	VdafVerifyKey       string          `json:"vdaf_verify_key"` // unpadded base64url
	BatchMode           uint8           `json:"batch_mode"`
	MinBatchSize        uint64          `json:"min_batch_size"`
	TimePrecision       uint64          `json:"time_precision"`        // seconds
	CollectorHpkeConfig string          `json:"collector_hpke_config"` // unpadded base64url HpkeConfig
}

type addTaskResponse struct {
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

type endpointResponse struct {
	Status   string `json:"status"`
	Endpoint string `json:"endpoint"`
}

type server struct {
	store          helper.Store
	agg            *helper.Handler
	hpkeConfigList []byte // pre-encoded global HpkeConfigList
	hpkePublicKey  []byte
	hpkePrivateKey []byte
}

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	flag.Parse()

	pub, priv, err := hpke.GenerateKeyPair(smokeSuite)
	if err != nil {
		log.Fatalf("generate HPKE keypair: %v", err)
	}
	list := wire.HpkeConfigList{Configs: []wire.HpkeConfig{{
		ID:        helperHpkeConfigID,
		KemID:     kemX25519HkdfSha256,
		KdfID:     kdfHkdfSha256,
		AeadID:    aeadAes128Gcm,
		PublicKey: pub,
	}}}
	listBytes, err := list.MarshalBinary()
	if err != nil {
		log.Fatalf("encode HpkeConfigList: %v", err)
	}

	store := helper.NewMemStore()
	s := &server{
		store:          store,
		agg:            helper.NewHandler(store),
		hpkeConfigList: listBytes,
		hpkePublicKey:  pub,
		hpkePrivateKey: priv,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/internal/test/ready", s.handleReady)
	mux.HandleFunc("/internal/test/endpoint_for_task", s.handleEndpointForTask)
	mux.HandleFunc("/internal/test/add_task", s.handleAddTask)
	mux.HandleFunc("/hpke_config", s.handleHpkeConfig)
	mux.Handle("/", s.agg) // DAP aggregation endpoints under /tasks/...

	log.Printf("dap-helper listening on %s", *addr)
	if err := http.ListenAndServe(*addr, logRequests(mux)); err != nil {
		log.Fatal(err)
	}
}

// logRequests logs every request line so the cross-run shows the Leader driving
// the Helper (e.g. "PUT /tasks/.../aggregation_jobs/...").
func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.RequestURI())
		next.ServeHTTP(w, r)
	})
}

func (s *server) handleReady(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, addTaskResponse{Status: "success"})
}

func (s *server) handleEndpointForTask(w http.ResponseWriter, _ *http.Request) {
	// DAP endpoints are served at the root of this server.
	writeJSON(w, http.StatusOK, endpointResponse{Status: "success", Endpoint: "/"})
}

func (s *server) handleHpkeConfig(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", hpkeConfigListMediaType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(s.hpkeConfigList)
}

func (s *server) handleAddTask(w http.ResponseWriter, r *http.Request) {
	var req aggregatorAddTaskRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusOK, addTaskResponse{Status: "error", Error: "malformed add_task body: " + err.Error()})
		return
	}
	// The interop API serializes the role lowercase ("helper").
	if !strings.EqualFold(req.Role, "helper") {
		writeJSON(w, http.StatusOK, addTaskResponse{Status: "error", Error: "dap-go runs the Helper role only, got role=" + req.Role})
		return
	}

	var vdaf struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(req.Vdaf, &vdaf); err != nil || vdaf.Type != "Prio3Count" {
		writeJSON(w, http.StatusOK, addTaskResponse{Status: "error", Error: "only Prio3Count is supported"})
		return
	}

	taskIDBytes, err := base64.RawURLEncoding.DecodeString(req.TaskID)
	if err != nil || len(taskIDBytes) != wire.TaskIDSize {
		writeJSON(w, http.StatusOK, addTaskResponse{Status: "error", Error: "invalid task_id"})
		return
	}
	var taskID wire.TaskID
	copy(taskID[:], taskIDBytes)

	verifyKeyBytes, err := base64.RawURLEncoding.DecodeString(req.VdafVerifyKey)
	if err != nil {
		writeJSON(w, http.StatusOK, addTaskResponse{Status: "error", Error: "invalid vdaf_verify_key"})
		return
	}
	if len(verifyKeyBytes) != len(helper.VerifyKey{}) {
		writeJSON(w, http.StatusOK, addTaskResponse{
			Status: "error",
			Error:  "unexpected vdaf_verify_key length",
		})
		return
	}
	var verifyKey helper.VerifyKey
	copy(verifyKey[:], verifyKeyBytes)

	// The collector HPKE config is needed to seal the aggregate share at
	// collection time.
	collBytes, err := base64.RawURLEncoding.DecodeString(req.CollectorHpkeConfig)
	var collCfg wire.HpkeConfig
	if err != nil || collCfg.UnmarshalBinary(collBytes) != nil {
		writeJSON(w, http.StatusOK, addTaskResponse{Status: "error", Error: "invalid collector_hpke_config"})
		return
	}
	collSuite := hpke.Suite{KEM: hpke.KEM(collCfg.KemID), KDF: hpke.KDF(collCfg.KdfID), AEAD: hpke.AEAD(collCfg.AeadID)}
	if !collSuite.IsValid() {
		writeJSON(w, http.StatusOK, addTaskResponse{Status: "error", Error: "unsupported collector HPKE suite"})
		return
	}

	task := &helper.Task{
		TaskID: taskID,
		TaskConfig: wire.TaskConfiguration{
			TaskInfo:       []byte("dap-go interop smoke"),
			LeaderEndpoint: []byte(req.Leader),
			HelperEndpoint: []byte(req.Helper),
			TimePrecision:  req.TimePrecision,
			MinBatchSize:   req.MinBatchSize,
			BatchMode:      wire.BatchMode(req.BatchMode),
			VdafType:       wire.VdafTypePrio3Count,
		},
		VDAFContext:            helper.DAPVDAFContext(taskID),
		VerifyKeys:             map[uint8]helper.VerifyKey{0: verifyKey},
		HPKESuite:              smokeSuite,
		HPKEConfigID:           helperHpkeConfigID,
		HPKEPublicKey:          s.hpkePublicKey,
		HPKEPrivateKey:         s.hpkePrivateKey,
		CollectorHPKESuite:     collSuite,
		CollectorHPKEConfigID:  collCfg.ID,
		CollectorHPKEPublicKey: collCfg.PublicKey,
	}
	s.store.AddTask(task)

	log.Printf("add_task: registered Helper task %s (Prio3Count, batch_mode=%d)", req.TaskID, req.BatchMode)
	writeJSON(w, http.StatusOK, addTaskResponse{Status: "success"})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
