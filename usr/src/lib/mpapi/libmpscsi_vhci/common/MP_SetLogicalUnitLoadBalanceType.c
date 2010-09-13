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
MP_SetLogicalUnitLoadBalanceType(MP_OID logicalUnitOid,
    MP_LOAD_BALANCE_TYPE loadBalance)
{
	log(LOG_INFO, "MP_SetLogicalUnitLoadBalanceType()", " - enter");


	log(LOG_INFO, "MP_SetLogicalUnitLoadBalanceType()",
	    " - logicalUnitOid.objectSequenceNumber: %llx",
	    logicalUnitOid.objectSequenceNumber);

	log(LOG_INFO, "MP_SetLogicalUnitLoadBalanceType()",
	    " - loadBalance: %d",
	    loadBalance);


	log(LOG_INFO, "MP_SetLogicalUnitLoadBalanceType()", " - exit");

	return (MP_STATUS_UNSUPPORTED);
}
