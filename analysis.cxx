// systemtap analysis code
// Copyright (C) 2021 Red Hat Inc.
//
// This file is part of systemtap, and is free software.  You can
// redistribute it and/or modify it under the terms of the GNU General
// Public License (GPL); either version 2, or (at your option) any
// later version.

#include "config.h"

#ifdef HAVE_DYNINST

#include <libdwarf/libdwarf.h>
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
	return;

	co = new CodeObject(sts);
	if(!co) return;
}


int liveness(char *executable,
	     Dwarf_Addr addr  __attribute__ ((unused))
	     /*, variable */)
{
	analysis func_to_analyze(executable);
	// Find where the variable is located
	// If variable isn't in a register, punt (return 0)
	// Find the function containing address
	// Check to see if a previous liveness information exists for function to reuse
	// Otherwise create new liveness analysis
	// Query to see if whether the register is live at that point
	return 0;
}

#endif // HAVE_DYNINST
