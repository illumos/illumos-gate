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



#include "Handle.h"
#include "Trace.h"
#ifdef	__cplusplus
extern "C" {
#endif

/**
 * @memo	    Closes an adapter
 * @precondition    Handle must be valid and open
 * @postcondition   Handle will be closed and should be discarded by caller
 * @param	    handle the handle to close
 * 
 * @doc		    See T11 FC-HBA for standard definition
 */
void Sun_fcCloseAdapter(HBA_HANDLE handle) {
	Trace log("Sun_fcCloseAdapter");
	try {
	    Handle::closeHandle(handle);
	} catch (...) {
	    log.internalError("Uncaught exception");
	    return;
	}
}

#ifdef	__cplusplus
}
#endif
