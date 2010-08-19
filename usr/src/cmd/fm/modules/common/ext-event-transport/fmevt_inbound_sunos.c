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

#include <string.h>
#include "fmevt.h"

/*
 * Support for the FMEV_RULESET_ON_SUNOS ruleset.
 */

/*
 * Panic events.
 */

/*ARGSUSED*/
static int
pp_sunos_panic(char *classes[FMEVT_FANOUT_MAX],
    nvlist_t *attr[FMEVT_FANOUT_MAX], const char *ruleset,
    const nvlist_t *detector, nvlist_t *rawattr,
    const struct fmevt_ppargs *eap)

{
	nvlist_t *myattr;
	time_t panictime32;
	int64_t panictime;
	char buf[128];
	struct tm ts;

	if (strcmp(eap->pp_rawsubclass, "dump_pending_on_device") != 0 &&
	    strcmp(eap->pp_rawsubclass, "savecore_failure") != 0 &&
	    strcmp(eap->pp_rawsubclass, "dump_available") != 0)
		return (0);

	if (snprintf(classes[0], FMEVT_MAX_CLASS, "%s.%s.%s", FM_IREPORT_CLASS,
	    "os.sunos.panic", eap->pp_rawsubclass) >= FMEVT_MAX_CLASS - 1)
		return (0);

	if (nvlist_lookup_int64(rawattr, "crashtime", &panictime) != 0)
		return (0);

	panictime32 = (time_t)panictime;

	myattr = fmd_nvl_dup(fmevt_hdl, rawattr, FMD_SLEEP);

	if (localtime_r(&panictime32, &ts) != NULL &&
	    strftime(buf, sizeof (buf), "%c %Z", &ts) != 0)
		(void) nvlist_add_string(myattr, "panic-time", buf);

	attr[0] = myattr;
	return (1);
}


/*ARGSUSED*/
uint_t
fmevt_pp_on_sunos(char *classes[FMEVT_FANOUT_MAX],
    nvlist_t *attr[FMEVT_FANOUT_MAX], const char *ruleset,
    const nvlist_t *detector, nvlist_t *rawattr,
    const struct fmevt_ppargs *eap)
{
	if (strcmp(eap->pp_rawclass, "panic") == 0)
		return (pp_sunos_panic(classes, attr, ruleset,
		    detector, rawattr, eap));

	return (0);
}
