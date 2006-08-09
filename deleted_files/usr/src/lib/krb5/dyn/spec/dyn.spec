#
# Copyright (c) 1999 by Sun Microsystems, Inc.
# All rights reserved.
#
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/krb5/dyn/spec/dyn.spec

function	DynAdd
include		"dynP.h"
declaration	int DynAdd(DynObject obj, void *el)
version		SUNWprivate_1.1
end

function	DynAppend
include		"dynP.h"
declaration	int DynAppend(DynObjectP obj, DynPtr els, int num)
version		SUNWprivate_1.1
end

function	DynArray
include		"dynP.h"
declaration	DynPtr DynArray(DynObject obj)
version		SUNWprivate_1.1
end

function	DynCapacity
include		"dynP.h"
declaration	int DynCapacity(DynObject obj)
version		SUNWprivate_1.1
end

function	DynCopy
include		"dynP.h"
declaration	DynObject DynCopy(DynObject obj)
version		SUNWprivate_1.1
end

function	DynCreate
include		"dynP.h"
declaration	DynObject DynCreate(int el_size, int inc)
version		SUNWprivate_1.1
end

function	DynDebug
include		"dynP.h"
declaration	int DynDebug(DynObject obj, int state)
version		SUNWprivate_1.1
end

function	DynDelete
include		"dynP.h"
declaration	int DynDelete(DynObject obj, int idx)
version		SUNWprivate_1.1
end

function	DynDestroy
include		"dynP.h"
declaration	int DynDestroy(DynObject obj)
version		SUNWprivate_1.1
end

function	DynGet
include		"dynP.h"
declaration	DynPtr DynGet(DynObject obj, int num)
version		SUNWprivate_1.1
end

function	DynInitzero
include		"dynP.h"
declaration	int DynInitzero(DynObject obj, int state)
version		SUNWprivate_1.1
end

function	DynInsert
include		"dynP.h"
declaration	int DynInsert(DynObject obj, int idx, void *els, int num)
version		SUNWprivate_1.1
end

function	DynParanoid
include		"dynP.h"
declaration	int DynParanoid(DynObject obj, int state)
version		SUNWprivate_1.1
end

function	DynPut
include		"dynP.h"
declaration	int DynPut(DynObject obj, void *el, int idx)
version		SUNWprivate_1.1
end

function	DynRelease
include		"dynP.h"
declaration	int DynRelease(DynObject obj)
version		SUNWprivate_1.1
end

function	DynSize
include		"dynP.h"
declaration	int DynSize(DynObject obj)
version		SUNWprivate_1.1
end

