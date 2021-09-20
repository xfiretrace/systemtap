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
static const MachRegister dyninst_register[] = {
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


int liveness(const char *executable,
	     Dwarf_Addr addr,
	     location_context ctx __attribute__ ((unused)))
{
	// should cache the executable names like the other things
	char *exe = strdup(executable);
	analysis func_to_analyze(exe);

	#if 0
	// Find where the variable is located
	location *loc = ctx.locations.back ();

	// If variable isn't in a register, punt (return 0)
	if (loc->type != loc_register) return 0;

	// Map dwarf number to dyninst number, skip if out of range
	if (loc->offset >= sizeof(dyninst_register)/sizeof(MachRegister)) return 0;
	MachRegister r = dyninst_register[loc->offset];
	#endif

	// Find the function containing address
	cout << "liveness analysis " << executable << " " << hex << addr << endl;
	vector<CodeRegion *> rr = func_to_analyze.co->cs()->regions();
	std::set<ParseAPI::Function*> ff;
	if(func_to_analyze.co->findFuncs(rr[0], addr, ff) <= 0) return 0;
	ParseAPI::Function *func = *ff.begin();
	cout << "<" << func->addr() << ">:" << func->name() << "[" << addr << "]" << endl;
	// Check to see if a previous liveness information exists for function to reuse
	// Otherwise create new liveness analysis
	LivenessAnalyzer la(func->obj()->cs()->getAddressWidth());
	la.analyze(func);
	// Construct a liveness query location for the function entry.
	// Get basic block containing the instruction
	set<Block *> bb_s;
	if (func_to_analyze.co->findBlocks(rr[0], addr, bb_s) != 1 )
		return 0; // problem find basic block, punt
	Block *bb = *bb_s.begin();
	Instruction curInsn = bb->getInsn(addr);

	// Construct a liveness query location for the function entry.
	InsnLoc i(bb,  addr, curInsn);
	Location iloc(func, i);

	#if 0
	// Query to see if whether the register is live at that point
	bool used;
	la.query(iloc, LivenessAnalyzer::Before, r, used);
	cout << r <<  (used ? " used"  : "unused") << endl;
	return (used ? 1 : -1);
	#else
	// Query to list out the registers that are live at that point
	// FIXME: This is because not currently getting the actual register
	bitArray liveRegs;
	la.query(iloc, LivenessAnalyzer::Before, liveRegs);
	cout << "liveRegs " << liveRegs << endl;
	return 0;
	#endif
}

#endif // HAVE_DYNINST
