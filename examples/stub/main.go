//go:build linux

// This program demonstrates stubs: funcs in the .text.stub section, which no C
// code calls, for instructions generated at run time. It replaces the body of
// calc() in the calls_stub program with instructions that call the add() or
// mul() stub, then runs calls_stub and no_stub once.
package main

import (
	"flag"
	"fmt"
	"log"
	"slices"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go tool bpf2go -tags linux bpf stub.c -- -I../headers

func main() {
	stub := flag.String("stub", "mul", "the stub that calc() calls: add or mul")
	flag.Parse()
	if *stub != "add" && *stub != "mul" {
		log.Fatalf("unknown stub %q", *stub)
	}

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	spec, err := loadBpf()
	if err != nil {
		log.Fatalf("loading spec: %v", err)
	}

	// Generate the body of calc(): return add(a, b) or mul(a, b). a and b
	// are already in R1 and R2, which hold the first two args of a call.
	err = replaceFunc(spec.Programs["calls_stub"], "calc", asm.Instructions{
		asm.Call.Label(*stub),
		asm.Return(),
	})
	if err != nil {
		log.Fatal(err)
	}

	// Loading links the chosen stub into calls_stub, and no stub into
	// no_stub. bpf2go doesn't generate programs for the stubs, as they can't
	// be loaded on their own.
	var objs bpfObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	for _, p := range []struct {
		name string
		prog *ebpf.Program
	}{
		{"calls_stub", objs.CallsStub},
		{"no_stub", objs.NoStub},
	} {
		// A 15-byte context is the minimum the kernel accepts for running a
		// program once.
		ret, err := p.prog.Run(&ebpf.RunOptions{Data: make([]byte, 15)})
		if err != nil {
			log.Fatalf("running %s: %v", p.name, err)
		}
		fmt.Printf("%s returned %d\n", p.name, ret)
	}
}

// replaceFunc replaces the instructions of the func called name in prog with
// insns.
func replaceFunc(prog *ebpf.ProgramSpec, name string, insns asm.Instructions) error {
	start := slices.IndexFunc(prog.Instructions, func(ins asm.Instruction) bool {
		return ins.Symbol() == name
	})
	if start < 0 {
		return fmt.Errorf("func %s not found", name)
	}

	// The func ends where the next one starts.
	end := start + 1
	for end < len(prog.Instructions) && prog.Instructions[end].Symbol() == "" {
		end++
	}

	// Keep the symbol, the BTF and the line info of the func, which the
	// kernel needs for its first instruction.
	first := prog.Instructions[start]
	insns[0] = insns[0].WithSymbol(name).WithSource(first.Source())
	insns[0] = btf.WithFuncMetadata(insns[0], btf.FuncMetadata(&first))
	prog.Instructions = slices.Replace(prog.Instructions, start, end, insns...)
	return nil
}
