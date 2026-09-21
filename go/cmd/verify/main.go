// Command verify re-verifies a saved QueryResponse using only the embedded
// public key and proofs -- the Go counterpart of the Python/C#/Java verifiers.
//
//	verify <response.json>
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/parag-labs/ledger-rag/go"
)

func main() {
	os.Exit(run(os.Args))
}

func run(argv []string) int {
	if len(argv) != 2 {
		fmt.Println("usage: verify <response.json>")
		return 2
	}
	data, err := os.ReadFile(argv[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	resp, err := ledgerrag.ParseQueryResponse(data)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	result, err := ledgerrag.VerifyResponse(resp)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if result.Verified {
		fmt.Println("\u2705 VERIFIED (Go)")
	} else {
		fmt.Println("\u274c TAMPERED / INVALID (Go)")
	}
	out, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(out))
	if result.Verified {
		return 0
	}
	return 1
}
