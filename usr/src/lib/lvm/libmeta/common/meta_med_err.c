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
 * Copyright 1992-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Just in case we're not in a build environment, make sure that
 * TEXT_DOMAIN gets set to something.
 */
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif

#include <meta.h>
#include <metamed.h>

char *
med_errnum_to_str(int errnum)
{
	switch (errnum) {
	    case MDE_MED_NOERROR:
		return (dgettext(TEXT_DOMAIN, "No Error"));
	    case MDE_MED_HOSTNOMED:
		return (dgettext(TEXT_DOMAIN,
		    "mediator host has no mediator data for host"));
	    case MDE_MED_DBNOTINIT:
		return (dgettext(TEXT_DOMAIN,
		    "mediator database is not initialized"));
	    case MDE_MED_DBSZBAD:
		return (dgettext(TEXT_DOMAIN,
		    "mediator database size is not valid"));
	    case MDE_MED_DBKEYADDFAIL:
		return (dgettext(TEXT_DOMAIN,
		    "unable to add key to mediator database"));
	    case MDE_MED_DBKEYDELFAIL:
		return (dgettext(TEXT_DOMAIN,
		    "unable to delete key from mediator database"));
	    case MDE_MED_DBHDRSZBAD:
		return (dgettext(TEXT_DOMAIN,
		    "mediator database header record size is not valid"));
	    case MDE_MED_DBHDRMAGBAD:
		return (dgettext(TEXT_DOMAIN,
		    "mediator database header magic is not valid"));
	    case MDE_MED_DBHDRREVBAD:
		return (dgettext(TEXT_DOMAIN,
		    "mediator database header revision is not valid"));
	    case MDE_MED_DBHDRCKSBAD:
		return (dgettext(TEXT_DOMAIN,
		    "mediator database header checksum is not valid"));
	    case MDE_MED_DBRECSZBAD:
		return (dgettext(TEXT_DOMAIN,
		    "mediator database record record size is not valid"));
	    case MDE_MED_DBRECMAGBAD:
		return (dgettext(TEXT_DOMAIN,
		    "mediator database record magic is not valid"));
	    case MDE_MED_DBRECREVBAD:
		return (dgettext(TEXT_DOMAIN,
		    "mediator database record revision is not valid"));
	    case MDE_MED_DBRECCKSBAD:
		return (dgettext(TEXT_DOMAIN,
		    "mediator database record checksum is not valid"));
	    case MDE_MED_DBRECOFFBAD:
		return (dgettext(TEXT_DOMAIN,
		    "mediator database record offset in not valid"));
	    case MDE_MED_DBRECNOENT:
		return (dgettext(TEXT_DOMAIN,
		    "no matching mediator record found"));
	    case MDE_MED_DBARGSMISMATCH:
		return (dgettext(TEXT_DOMAIN, "set number in arguments "
		    "different from set number in data"));
	    default:
		return (NULL);
	}
}
