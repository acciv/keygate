package policy

/*
#cgo CFLAGS: -I${SRCDIR}/../../../rust/include
#cgo LDFLAGS: -L${SRCDIR}/../../../rust/target/release -lkeygate_policy -Wl,-rpath,${SRCDIR}/../../../rust/target/release
#include <stdlib.h>
#include "keygate_policy.h"
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"unsafe"
)

type Decision struct {
	Allow         bool     `json:"allow"`
	Reasons       []string `json:"reasons"`
	EffectiveTTL  int      `json:"effective_ttl"`
	PolicyVersion string   `json:"policy_version"`
}

func Version() string {
	return C.GoString(C.keygate_policy_version())
}

func Evaluate(requestJSON, configJSON string) (Decision, error) {
	req := C.CString(requestJSON)
	defer C.free(unsafe.Pointer(req))
	cfg := C.CString(configJSON)
	defer C.free(unsafe.Pointer(cfg))

	ptr := C.keygate_policy_evaluate(req, cfg)
	if ptr == nil {
		return Decision{}, fmt.Errorf("policy engine returned null")
	}
	defer C.keygate_policy_free(ptr)

	var decision Decision
	if err := json.Unmarshal([]byte(C.GoString(ptr)), &decision); err != nil {
		return Decision{}, fmt.Errorf("decode policy decision: %w", err)
	}
	return decision, nil
}
