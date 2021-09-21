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

// FIXME: Currently only support x86_64 will need to set up for powerpc and aarch64
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
	x86::esp,
};

int liveness(const char *executable,
	     Dwarf_Addr addr,
	     location_context ctx __attribute__ ((unused)))
{
	// should cache the executable names like the other things
	char *exe = strdup(executable);
	analysis func_to_analyze(exe);
	MachRegister r;

	// Determine whether 32-bit or 64-bit code as the register names are different in dyninst
	int reg_width = func_to_analyze.co->cs()->getAddressWidth();

	#if 0
	// Find where the variable is located
	location *loc = ctx.locations.back ();

	// If variable isn't in a register, punt (return 0)
	if (loc->type != loc_register) return 0;

	// Map dwarf number to dyninst register name, punt if out of range
	unsigned int regno = loc->offset;
	#else
	unsigned int regno = 5; // Dummy up to arg1 of x86
	#endif
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
	vector<CodeRegion *> rr = func_to_analyze.co->cs()->regions();
	std::set<ParseAPI::Function*> ff_s;
	if(func_to_analyze.co->findFuncs(rr[0], addr, ff_s) <= 0) return 0;
	ParseAPI::Function *func = *ff_s.begin();

	// FIXME Check to see if a previous liveness information exists for function to reuse
	// Otherwise create new liveness analysis
	LivenessAnalyzer la(reg_width);
	la.analyze(func);

	// Get the basic block and instruction containing the the probe point.
	set<Block *> bb_s;
	if (func_to_analyze.co->findBlocks(rr[0], addr, bb_s) != 1 )
		return 0; // too many (or too few) basic blocks, punt
	Block *bb = *bb_s.begin();
	Instruction curInsn = bb->getInsn(addr);

	// Construct a liveness query location for the probe point.
	InsnLoc i(bb,  addr, curInsn);
	Location iloc(func, i);

	// Query to see if whether the register is live at that point
	bool used;
	la.query(iloc, LivenessAnalyzer::Before, r, used);
	cout << "liveness analysis " << executable << " " << hex << addr << endl;
	cout << r.name() <<  (used ? " used"  : " unused") << endl;
	return (used ? 1 : -1);
}

#endif // HAVE_DYNINST
