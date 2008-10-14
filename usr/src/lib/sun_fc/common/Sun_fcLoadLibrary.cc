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



#include "HBAList.h"
#include "Exceptions.h"
#include "Trace.h"
#ifdef	__cplusplus
extern "C" {
#endif

/**
 * @memo	    Loads the HBA Library.
 * @precondition    Load library not called previouslly (or free called)
 * @postcondition   On success, other library APIs may be called
 * @exception	    LIST_OF_EXCEPTIONS
 * @return	    HBA_STATUS_OK	    library properly loaded
 * @return	    HBA_STATUS_ERROR    library loaded incorrectly
 * 
 * @doc		    Must be called before calling any HBA library functions
 */
HBA_STATUS Sun_fcLoadLibrary() {
	Trace log("Sun_fcLoadLibrary");
	try {
	    HBAList* list = HBAList::instance();
	    return (list->load());
	} catch (...) {
	    log.internalError(
		"Uncaught exception");
	    return (HBA_STATUS_ERROR);
	}
}
#ifdef	__cplusplus
}
#endif
