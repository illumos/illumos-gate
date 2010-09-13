/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */



#include "Trace.h"
#include "HBAList.h"
#include "Handle.h"
#include "Exceptions.h"

#define	    HANDLE_ERROR 0
#ifdef	__cplusplus
extern "C" {
#endif

/**
 * @memo	    Opens a named adapter.
 * @precondition    Library already loaded
 * @postcondition   Open handle must be closed at a later point in time
 * @return	    An open handle, or (0) on error
 * @param	    name The name of the adapter to open
 */
HBA_HANDLE Sun_fcOpenAdapter(char *name) {
	Trace log("Sun_fcOpenAdapter");
	if (name == NULL) {
	    log.userError("Null argument");
	    return (HANDLE_ERROR);
	}

	try {
	    return (HBAList::instance()->openHBA(name)->getHandle());
	} catch (HBAException &e) {
	    return (0);
	} catch (...) {
	    log.internalError("Uncaught exception");
	    return (0);
	}
}
#ifdef	__cplusplus
}
#endif
