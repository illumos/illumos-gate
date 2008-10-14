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
#include "Exceptions.h"
#include "sun_fc_version.h"
#include "HBAList.h"

#ifdef	__cplusplus
extern "C" {
#endif

/**
 * @memo	    Return information about this vendor library
 * @return	    The version of the API we support
 * @param	    attrs The user-allocated buffer
 */
HBA_UINT32
Sun_fcGetVendorLibraryAttributes(HBA_LIBRARYATTRIBUTES *attrs) {
	Trace log("Sun_fcGetVendorLibraryAttributes");

	/* Validate the arguments */
	if (attrs == NULL) {
	    log.userError("NULL attrs structure");
	    return (VSL_NUMERIC_VERSION);
	}
	try {
	    HBAList* list = HBAList::instance();
	    *attrs = list->getVSLAttributes();
	    return (VSL_NUMERIC_VERSION);
	} catch (...) {
	    log.internalError("Uncaught exception");
	    memset(attrs, 0, sizeof (*attrs));
	    return (VSL_NUMERIC_VERSION);
	}
}
#ifdef	__cplusplus
}
#endif
