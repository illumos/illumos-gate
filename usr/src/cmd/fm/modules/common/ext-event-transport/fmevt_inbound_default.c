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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include "fmevt.h"

/*
 * Post-processing according to the FMEV_RULESET_UNREGISTERED ruleset.
 *
 * Generate a class of ireport.unregistered.<raw-class>.<raw-subclass>
 * with attributes just those of the raw event.  If either the raw
 * class or subclass is NULL or empty then drop the event.
 */
/*ARGSUSED*/
uint_t
fmevt_pp_unregistered(char *classes[FMEVT_FANOUT_MAX],
    nvlist_t *attr[FMEVT_FANOUT_MAX], const char *ruleset,
    const nvlist_t *detector, nvlist_t *rawattr,
    const struct fmevt_ppargs *eap)
{
	if (eap->pp_rawclass == NULL || eap->pp_rawsubclass == NULL)
		return (0);

	if (snprintf(classes[0], FMEVT_MAX_CLASS, "%s.%s.%s.%s",
	    FM_IREPORT_CLASS, "unregistered",
	    eap->pp_rawclass, eap->pp_rawsubclass) >= FMEVT_MAX_CLASS - 1)
		return (0);

	attr[0] = rawattr;
	return (1);
}
