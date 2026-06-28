package helper_test

import (
	"fmt"
	"net/http"

	"github.com/Deln0r/dap-go/pkg/dap/helper"
	"github.com/Deln0r/dap-go/pkg/dap/wire"
)

// ExampleDAPVDAFContext builds the DAP-18 VDAF application context. DAP-18 binds
// the literal "dap-18" and the 32-byte task ID into every VDAF call (shard and
// all ping-pong transitions), raw-concatenated with no length prefix.
func ExampleDAPVDAFContext() {
	taskID := wire.TaskID{0x2a} // 0x2a then zeros
	ctx := helper.DAPVDAFContext(taskID)
	fmt.Printf("prefix=%q len=%d\n", ctx[:6], len(ctx))
	// Output:
	// prefix="dap-18" len=38
}

// ExampleNewHandler stands up a Helper-role aggregator over an in-memory store
// and mounts it on a mux. A real Helper learns its tasks at runtime, so the
// store accepts them after construction. The Handler implements http.Handler.
func ExampleNewHandler() {
	store := helper.NewMemStore()
	store.AddTask(&helper.Task{
		TaskID:     wire.TaskID{0x01},
		VerifyKeys: map[uint8]helper.VerifyKey{0: {}},
	})

	h := helper.NewHandler(store)

	mux := http.NewServeMux()
	mux.Handle("/", h) // h satisfies http.Handler
	_ = mux
}
