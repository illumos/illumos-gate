/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1994, by Sun Microsytems, Inc.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Interfaces to print error codes and to map an errno to an error code.
 */

#include <string.h>
#include <libintl.h>

#include "tnfctl_int.h"
#include "dbg.h"


#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

/*
 * prb_status_str() - this routine returns a pointer to a static string
 * describing the error argument.
 */
const char	 *
prb_status_str(prb_status_t prbstat)
{
	/* if this is in the errno range, use the errno string */
	if (prbstat >= PRB_STATUS_MINERRNO &&
		prbstat <= PRB_STATUS_MAXERRNO) {
		return (strerror(prbstat));
	} else {
		switch (prbstat) {
		case PRB_STATUS_OK:
			return (dgettext(TEXT_DOMAIN, "success"));
		case PRB_STATUS_ALLOCFAIL:
			return (dgettext(TEXT_DOMAIN,
				"memory allocation failed"));
		case PRB_STATUS_BADARG:
			return (dgettext(TEXT_DOMAIN, "bad input argument"));
		case PRB_STATUS_BADSYNC:
			return (dgettext(TEXT_DOMAIN,
				"couldn't sync with rtld"));
		case PRB_STATUS_BADLMAPSTATE:
			return (dgettext(TEXT_DOMAIN, "inconsistent link map"));
		default:
			return (dgettext(TEXT_DOMAIN,
				"Unknown libtnfctl.so prb layer error code"));
		}
	}
}

/*
 * prb_status_map() - this routine converts an errno value into a
 * prb_status_t.
 */
prb_status_t
prb_status_map(int val)
{
	return (val);

}
