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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _WRSMCONF_MSGS_H
#define	_WRSMCONF_MSGS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#define	MSG_FILE	gettext("%s: failed reading file %s\n")
#define	MSG_NOT_FOUND	gettext("%s: controller %d not found in file %s\n")
#define	MSG_INPUT1	gettext("Enter netlist in the form:\n")
#define	MSG_INPUT2	gettext("   hostname.wci.link=hostname.wci.link\n")
#define	MSG_INPUT3	gettext("Hit CTRL-D when done.\n")
#define	MSG_LINK_IN_USE	gettext("%s: %s.%d.%d already in use\n")
#define	MSG_INVALID	gettext("%s: invalid value for %s: %d\n")
#define	MSG_UNKNOWN	gettext("%s: unknown option '%s'\n")
#define	MSG_PARSE_ERR	gettext("%s: could not parse line: %s")
#define	MSG_LINK_RANGE	gettext("%s: link number out of range: %s\n")
#define	MSG_NUM_HOSTS	gettext("%s: number of hosts exceeds limit of %d\n")
#define	MSG_NO_ROUTE	gettext("%s: no route from %s to %s\n")

#ifdef __cplusplus
}
#endif

#endif /* _WRSMCONF_MSGS_H */
