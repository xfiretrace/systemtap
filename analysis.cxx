// systemtap analysis code
// Copyright (C) 2021 Red Hat Inc.
//
// This file is part of systemtap, and is free software.  You can
// redistribute it and/or modify it under the terms of the GNU General
// Public License (GPL); either version 2, or (at your option) any
// later version.

#include "config.h"

#ifdef HAVE_DYNINST

#include "loc2stap.h"
#include "analysis.h"
#include <dyninst/Symtab.h>
#include <dyninst/Function.h>
#include <dyninst/liveness.h>

using namespace Dyninst;
using namespace SymtabAPI;
using namespace ParseAPI;
using namespace std;


class analysis {
public:
	analysis(char *name);
	SymtabCodeSource *sts;
	CodeObject *co;
};

//  Get the binary set up for anaysis
analysis::analysis(char *name)
{
	// Should see if binary already cached
	sts = NULL;
	co = NULL;

	// If not seen before
	// Create a new binary code object from the filename argument
	sts = new SymtabCodeSource(name);
	if(!sts) return;

	co = new CodeObject(sts);
	if(!co) return;
}

#if defined(__i386__) || defined(__x86_64__)
static const MachRegister dyninst_register_64[] = {
	x86_64::rax,
	x86_64::rdx,
	x86_64::rcx,
	x86_64::rbx,
	x86_64::rsi,
	x86_64::rdi,
	x86_64::rbp,
	x86_64::rsp,
	x86_64::r8,
	x86_64::r9,
	x86_64::r10,
	x86_64::r11,
	x86_64::r12,
	x86_64::r13,
	x86_64::r14,
	x86_64::r15,
	x86_64::rip
};

static const MachRegister dyninst_register_32[] = {
	x86::eax,
	x86::edx,
	x86::ecx,
	x86::ebx,
	x86::esi,
	x86::edi,
	x86::ebp,
	x86::esp
};

#elif defined(__aarch64__)
static const MachRegister dyninst_register_64[] = {
	aarch64::x0,
	aarch64::x1,
	aarch64::x2,
	aarch64::x3,
	aarch64::x4,
	aarch64::x5,
	aarch64::x6,
	aarch64::x7,
	aarch64::x8,
	aarch64::x9,
	aarch64::x10,
	aarch64::x11,
	aarch64::x12,
	aarch64::x13,
	aarch64::x14,
	aarch64::x15,
	aarch64::x16,
	aarch64::x17,
	aarch64::x18,
	aarch64::x19,
	aarch64::x20,
	aarch64::x21,
	aarch64::x22,
	aarch64::x23,
	aarch64::x24,
	aarch64::x25,
	aarch64::x26,
	aarch64::x27,
	aarch64::x28,
	aarch64::x29,
	aarch64::x30,
	aarch64::sp
};

static const MachRegister dyninst_register_32[1]; // No 32-bit support

#elif defined(__powerpc__)
static const MachRegister dyninst_register_64[] = {
    ppc64::r0,
    ppc64::r1,
    ppc64::r2,
    ppc64::r3,
    ppc64::r4,
    ppc64::r5,
    ppc64::r6,
    ppc64::r7,
    ppc64::r8,
    ppc64::r9,
    ppc64::r10,
    ppc64::r11,
    ppc64::r12,
    ppc64::r13,
    ppc64::r14,
    ppc64::r15,
    ppc64::r16,
    ppc64::r17,
    ppc64::r18,
    ppc64::r19,
    ppc64::r20,
    ppc64::r21,
    ppc64::r22,
    ppc64::r23,
    ppc64::r24,
    ppc64::r25,
    ppc64::r26,
    ppc64::r27,
    ppc64::r28,
    ppc64::r29,
    ppc64::r30,
    ppc64::r31
};

static const MachRegister dyninst_register_32[] = {
    ppc32::r0,
    ppc32::r1,
    ppc32::r2,
    ppc32::r3,
    ppc32::r4,
    ppc32::r5,
    ppc32::r6,
    ppc32::r7,
    ppc32::r8,
    ppc32::r9,
    ppc32::r10,
    ppc32::r11,
    ppc32::r12,
    ppc32::r13,
    ppc32::r14,
    ppc32::r15,
    ppc32::r16,
    ppc32::r17,
    ppc32::r18,
    ppc32::r19,
    ppc32::r20,
    ppc32::r21,
    ppc32::r22,
    ppc32::r23,
    ppc32::r24,
    ppc32::r25,
    ppc32::r26,
    ppc32::r27,
    ppc32::r28,
    ppc32::r29,
    ppc32::r30,
    ppc32::r31
};
#endif

int liveness(const char *executable,
	     Dwarf_Addr addr,
	     location_context ctx)
{
	// should cache the executable names like the other things
	char *exe = strdup(executable);
	analysis func_to_analyze(exe);
	MachRegister r;

	// Determine whether 32-bit or 64-bit code as the register names are different in dyninst
	int reg_width = func_to_analyze.co->cs()->getAddressWidth();

	// Find where the variable is located
	location *loc = ctx.locations.back ();

	// If variable isn't in a register, punt (return 0)
	if (loc->type != loc_register) return 0;

	// Map dwarf number to dyninst register name, punt if out of range
	unsigned int regno = loc->regno;
	switch (reg_width){
	case 4:
		if (regno >= (sizeof(dyninst_register_32)/sizeof(MachRegister))) return 0;
		r = dyninst_register_32[regno]; break;
	case 8:
		if (regno >= (sizeof(dyninst_register_64)/sizeof(MachRegister))) return 0;
		r = dyninst_register_64[regno]; break;
	default:
		cout << "Reg width " << reg_width << " bytes not understood." << endl;
		return 0;
	}

	// Find the function containing the probe point.
	std::set<ParseAPI::Function*> ff_s;
	if(func_to_analyze.co->findFuncs(NULL, addr, ff_s) <= 0) return 0;
	ParseAPI::Function *func = *ff_s.begin();

	// FIXME Check to see if a previous liveness information exists for function to reuse
	// Otherwise create new liveness analysis
	LivenessAnalyzer la(reg_width);
	la.analyze(func);

	// Get the basic block and instruction containing the the probe point.
	set<Block *> bb_s;
	if (func_to_analyze.co->findBlocks(NULL, addr, bb_s) != 1 )
		return 0; // too many (or too few) basic blocks, punt
	Block *bb = *bb_s.begin();
	Instruction curInsn = bb->getInsn(addr);

	// Construct a liveness query location for the probe point.
	InsnLoc i(bb,  addr, curInsn);
	Location iloc(func, i);

	// Query to see if whether the register is live at that point
	bool used;
	la.query(iloc, LivenessAnalyzer::Before, r, used);
	cout << "liveness analysis " << executable << " " << func->name()
	     << " " << hex << addr << endl;
	cout << r.name() <<  (used ? " used"  : " unused") << endl;
	return (used ? 1 : -1);
}

#endif // HAVE_DYNINST
