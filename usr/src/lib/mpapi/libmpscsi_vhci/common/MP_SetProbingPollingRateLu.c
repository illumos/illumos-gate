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

#include <syslog.h>

#include "mp_utils.h"


MP_STATUS
MP_SetProbingPollingRateLu(MP_OID oid, MP_UINT32 pollingRate)
{
	log(LOG_INFO, "MP_SetProbingPollingRateLu()", " - enter");


	log(LOG_INFO, "MP_SetProbingPollingRateLu()",
	    " - oid.objectSequenceNumber: %llx",
	    oid.objectSequenceNumber);

	log(LOG_INFO, "MP_SetProbingPollingRateLu()",
	    " - pollingRate: %d",
	    pollingRate);


	log(LOG_INFO, "MP_SetProbingPollingRateLu()", " - exit");

	return (MP_STATUS_UNSUPPORTED);
}
