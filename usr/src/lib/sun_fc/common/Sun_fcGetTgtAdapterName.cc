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
#include "Exceptions.h"
#ifdef	__cplusplus
extern "C" {
#endif

/**
 * @memo	    Get the adapters name
 * @precondition    name parameter must be sufficient length to fit the name
 * @postcondition   name contains the name of the given adapter
 * @return	    HBA_STATUS_OK on success, or other error code
 * @param	    index	the index to which adapter to retrieve the name
 * @param	    name	buffer to which the adapter name will be placed
 * 
 * @doc		    
 * Returns the text string which describes this adapter and which is used to
 * open the adapter with the library.
 */
HBA_STATUS Sun_fcGetTgtAdapterName(HBA_UINT32 index, char *name) {
	Trace log("Sun_fcGetTgtAdapterName");
	if (name == NULL) {
	    log.userError(
		"NULL name pointer");
	    return (HBA_STATUS_ERROR_ARG);
	}
	try {
	    HBAList* list = HBAList::instance();
	    std::string sname = list->getTgtHBAName(index);
	    strcpy(name, sname.c_str());
	    return (HBA_STATUS_OK);
	} catch (HBAException &e) {
	    return (e.getErrorCode());
	} catch (...) {
	    log.internalError(
		"Uncaught exception");
	    return (HBA_STATUS_ERROR);
	}
}

#ifdef	__cplusplus
}
#endif
