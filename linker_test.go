package ebpf

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/testutils"

	"github.com/go-quicktest/qt"
)

func TestFindReferences(t *testing.T) {
	progs := map[string]*ProgramSpec{
		"entrypoint": {
			Type: SocketFilter,
			Instructions: asm.Instructions{
				// Make sure the call doesn't happen at instruction 0
				// to exercise the relative offset calculation.
				asm.Mov.Reg(asm.R0, asm.R1),
				asm.Call.Label("my_func"),
				asm.Return(),
			},
			License: "MIT",
		},
		"my_other_func": {
			Instructions: asm.Instructions{
				asm.LoadImm(asm.R0, 1337, asm.DWord).WithSymbol("my_other_func"),
				asm.Return(),
			},
		},
		"my_func": {
			Instructions: asm.Instructions{
				asm.Call.Label("my_other_func").WithSymbol("my_func"),
				asm.Return(),
			},
		},
	}

	flattenPrograms(progs, []string{"entrypoint"})

	prog, err := newProgram(t, progs["entrypoint"], nil)
	testutils.SkipIfNotSupported(t, err)
	qt.Assert(t, qt.IsNil(err))

	ret := mustRun(t, prog, nil)

	if ret != 1337 {
		t.Errorf("Expected return code 1337, got %d", ret)
	}
}

func TestForwardFunctionDeclaration(t *testing.T) {
	file := testutils.NativeFile(t, "testdata/fwd_decl-%s.elf")
	coll, err := LoadCollectionSpec(file)
	if err != nil {
		t.Fatal(err)
	}

	spec := coll.Programs["call_fwd"]

	// This program calls an unimplemented forward function declaration.
	_, err = newProgram(t, spec, nil)
	if !errors.Is(err, asm.ErrUnsatisfiedProgramReference) {
		t.Fatal("Expected an error wrapping ErrUnsatisfiedProgramReference, got:", err)
	}

	// Append the implementation of fwd().
	spec.Instructions = append(spec.Instructions,
		asm.Mov.Imm32(asm.R0, 23).WithSymbol("fwd"),
		asm.Return(),
	)

	// The body of the subprog we appended does not come with BTF func_infos,
	// so the verifier will reject it. Load without BTF.
	for i, ins := range spec.Instructions {
		if btf.FuncMetadata(&ins) != nil || ins.Source() != nil {
			sym := ins.Symbol()
			ref := ins.Reference()
			ins.Metadata = asm.Metadata{}
			spec.Instructions[i] = ins.WithSymbol(sym).WithReference(ref)
		}
	}

	prog, err := newProgram(t, spec, nil)
	testutils.SkipIfNotSupported(t, err)
	qt.Assert(t, qt.IsNil(err))

	ret := mustRun(t, prog, nil)

	if ret != 23 {
		t.Fatalf("Expected 23, got %d", ret)
	}
}

func TestFlattenInstructionsAllocations(t *testing.T) {
	name := "entrypoint"
	instructions := asm.Instructions{
		asm.LoadImm(asm.R0, 0, asm.DWord),
		asm.Return(),
	}
	prog := &ProgramSpec{
		Name:         name,
		Instructions: instructions,
	}
	progs := map[string]*ProgramSpec{name: prog}
	refs := make(map[*ProgramSpec][]string)

	// ensure that flattenInstructions does not allocate memory
	// if there is no reference for the given program.
	allocs := testing.AllocsPerRun(5, func() {
		_ = flattenInstructions(name, progs, refs)
	})
	qt.Assert(t, qt.Equals(allocs, float64(0)))
}

// stubPrograms returns the programs of a CollectionSpec whose entrypoint calls
// funcs of .text.stub that the ELF reader didn't link into it: stub_a, and
// stub_b, which calls stub_c. stub_a and stub_c come with helper, as the ELF
// reader links the funcs that a stub calls into its instructions.
func stubPrograms() map[string]*ProgramSpec {
	return map[string]*ProgramSpec{
		"entrypoint": {
			Type: SocketFilter,
			Instructions: asm.Instructions{
				asm.Call.Label("stub_a"),
				asm.Mov.Reg(asm.R6, asm.R0),
				asm.Call.Label("stub_b"),
				asm.Add.Reg(asm.R0, asm.R6),
				asm.Return(),
			},
			License: "MIT",
		},
		"stub_a": {
			SectionName: ".text.stub",
			Instructions: asm.Instructions{
				asm.Call.Label("helper").WithSymbol("stub_a"),
				asm.Add.Imm(asm.R0, 300),
				asm.Return(),
				asm.Mov.Imm(asm.R0, 1000).WithSymbol("helper"),
				asm.Return(),
			},
		},
		"stub_b": {
			SectionName: ".text.stub",
			Instructions: asm.Instructions{
				asm.Call.Label("stub_c").WithSymbol("stub_b"),
				asm.Sub.Imm(asm.R0, 963),
				asm.Return(),
			},
		},
		"stub_c": {
			SectionName: ".text.stub",
			Instructions: asm.Instructions{
				asm.Call.Label("helper").WithSymbol("stub_c"),
				asm.Return(),
				asm.Mov.Imm(asm.R0, 1000).WithSymbol("helper"),
				asm.Return(),
			},
		},
		"not_a_stub": {
			SectionName: "other",
			Instructions: asm.Instructions{
				asm.Mov.Imm(asm.R0, 0).WithSymbol("not_a_stub"),
				asm.Return(),
			},
		},
	}
}

func TestLinkStubs(t *testing.T) {
	progs := stubPrograms()

	insns := linkStubs(progs["entrypoint"].Instructions, progs)

	var syms []string
	for _, ins := range insns {
		if sym := ins.Symbol(); sym != "" {
			syms = append(syms, sym)
		}
	}
	// helper comes with both stub_a and stub_c, but is linked once.
	qt.Assert(t, qt.DeepEquals(syms, []string{"stub_a", "helper", "stub_b", "stub_c"}))
	qt.Assert(t, qt.HasLen(insns, 5+5+3+2))

	// Only funcs of .text.stub are linked.
	insns = linkStubs(asm.Instructions{
		asm.Call.Label("not_a_stub"),
		asm.Return(),
	}, progs)
	qt.Assert(t, qt.HasLen(insns, 2))
}

func TestCollectionLinksStubs(t *testing.T) {
	spec := &CollectionSpec{
		Programs:  stubPrograms(),
		ByteOrder: internal.NativeEndian,
	}

	coll := mustNewCollection(t, spec, nil)

	// The stubs and not_a_stub have no program type, so they aren't loaded.
	qt.Assert(t, qt.HasLen(coll.Programs, 1))

	ret := mustRun(t, coll.Programs["entrypoint"], nil)
	qt.Assert(t, qt.Equals(ret, uint32(1337)))
}
