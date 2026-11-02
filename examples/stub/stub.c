//go:build ignore

#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// A stub is a func that no C code calls, for instructions generated at run
// time. Loading links it into the programs whose instructions call it. Keep it
// static, so that the verifier checks it with the args of each call.
#define __stub SEC(".text.stub") static __noinline

__stub u64 add(u64 a, u64 b) {
	return a + b;
}

__stub u64 mul(u64 a, u64 b) {
	return a * b;
}

// The args of calc(), volatile so that the compiler doesn't fold them into it.
volatile const u64 x = 6;
volatile const u64 y = 7;

// main.go replaces this placeholder body with instructions that call a stub.
static __noinline u64 calc(u64 a, u64 b) {
	return a ^ b;
}

SEC("socket")
int calls_stub(void *ctx) {
	return calc(x, y);
}

// no_stub calls no stub, so loading links none into it.
SEC("socket")
int no_stub(void *ctx) {
	return 0;
}
