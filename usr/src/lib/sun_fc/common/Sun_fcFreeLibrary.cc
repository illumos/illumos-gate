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
#include "Trace.h"
#ifdef	__cplusplus
extern "C" {
#endif

/**
 * @memo	    Frees the HBA Library.  
 * @precondition    Library must have been loaded previously
 * @postcondition   Library will be free.  No further APIs should be called
 *		    except LoadLibrary
 * @return	    HBA_STATUS_OK if library was unloaded properly
 * @return	    HBA_STATUS_ERROR if library was not unloaded
 * 
 * @doc		    See T11 FC-HBA for standard definition
 */
HBA_STATUS Sun_fcFreeLibrary() {
	Trace log("Sun_fcFreeLibrary");
	try {
	    HBAList* list = HBAList::instance();
	    HBA_STATUS status = list->unload();
	    delete (list);
	    return (status);
	} catch (...) {
	    log.internalError("Uncaught exception");
	    return (HBA_STATUS_ERROR);
	}
}
#ifdef	__cplusplus
}
#endif
