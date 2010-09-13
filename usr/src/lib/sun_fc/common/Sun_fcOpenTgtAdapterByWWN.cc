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
#include "HBAList.h"
#include "Exceptions.h"
#include "Trace.h"
#include "sun_fc.h"
#ifdef	__cplusplus
extern "C" {
#endif

/**
 * @memo	    Opens a adapter based on the specified WWN.
 * @return	    HBA_STATUS_OK if adapter was opened
 * @param	    handle Output argument where open handle is stored
 * @param	    wwn The Node or Port WWN of the HBA to open
 */
HBA_STATUS Sun_fcOpenTgtAdapterByWWN(HBA_HANDLE *handle, HBA_WWN wwn) {
	Trace log("Sun_fcOpenTgtAdapterByWWN");

	// Validate args
	if (handle == NULL) {
	    log.userError("NULL handle pointer");
	    return (HBA_STATUS_ERROR_ARG);
	}
	try {
	    *handle = HBAList::instance()->
		    openTgtHBA(wwnConversion(wwn.wwn))->getHandle();
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
