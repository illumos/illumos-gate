/*
 * Copyright (c) 1997-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _KRB5_DYN_DYNP_H
#define	_KRB5_DYN_DYNP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif


/*
 * This file is part of libdyn.a, the C Dynamic Object library.  It
 * contains the private header file.
 *
 * There are no restrictions on this code; however, if you make any
 * changes, I request that you document them so that I do not get
 * credit or blame for your modifications.
 *
 * Written by Barr3y Jaspan, Student Information Processing Board (SIPB)
 * and MIT-Project Athena, 1989.
 */


/*
 * dynP.h -- private header file included by source files for libdyn.a.
 */


#include "dyn.h"
#ifdef USE_DBMALLOC
#include <sys/stdtypes.h>
#include <malloc.h>
#endif

/*
 * Rep invariant:
 * 1) el_size is the number of bytes per element in the object
 * 2) num_el is the number of elements currently in the object.  It is
 * one higher than the highest index at which an element lives.
 * 3) size is the number of elements the object can hold without
 * resizing.  num_el <= index.
 * 4) inc is a multiple of the number of elements the object grows by
 * each time it is reallocated.
 */

typedef struct _DynObject DynObjectRecP, *DynObjectP;

/* Internal functions */
int _DynRealloc(), _DynResize();

/*
 * N.B. The original code had the following comment line after that last #endif:
 * DON'T ADD STUFF AFTER THIS #endif *
 * Ignoring the fact that this line itself was after the #endif, the line
 * caused unacceptable hdrchk breakage. If this results in a build breakage,
 * the build MUST be fixed in a more acceptable fashion.
 */

#ifdef	__cplusplus
}
#endif

#endif	/* !_KRB5_DYN_DYNP_H */
