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
#include <libdevinfo.h>

/**
 * @memo	    Returns the number of HBAs supported by the library.
 * @precondition    Load library must have been called
 * @return	    The number of adapters detected by this VSL
 * @doc		    Refer to the HBAList documentation for behavior
 * @see		    HBAList::getNnumberofAdapters
 *		    
 */
extern "C" HBA_UINT32 Sun_fcGetNumberOfAdapters() {
	Trace log("Sun_fcGetNumberOfAdapters");
	try {
	    HBAList* list = HBAList::instance();
	    HBA_UINT32 ret = list->getNumberofAdapters();
	    if (ret == 0) {
		/* run di_init to forceattach fp and retry it */
		di_node_t root_node;
		if ((root_node = di_init("/", DINFOSUBTREE|DINFOFORCE)) != DI_NODE_NIL) {
			di_fini(root_node);
			return (list->getNumberofAdapters());
		}
	    }
	    return (ret);
	} catch (...) {
	    log.internalError(
		"Uncaught exception");
	    return (0);
	}
}
