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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <devfsadm.h>
#include <strings.h>
#include <stdio.h>
#include <sys/dtrace.h>

static int dtrace(di_minor_t minor, di_node_t node);
static int dtrace_provider(di_minor_t minor, di_node_t node);

static devfsadm_create_t dtrace_create_cbt[] = {
	{ "pseudo", "ddi_pseudo", "dtrace",
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, dtrace },
	{ "pseudo", "ddi_pseudo", "fasttrap",
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, dtrace_provider },
	{ "pseudo", "ddi_pseudo", "fbt",
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, dtrace_provider },
	{ "pseudo", "ddi_pseudo", "lockstat",
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, dtrace_provider },
	{ "pseudo", "ddi_pseudo", "profile",
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, dtrace_provider },
	{ "pseudo", "ddi_pseudo", "sdt",
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, dtrace_provider },
	{ "pseudo", "ddi_pseudo", "systrace",
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, dtrace_provider },
};

DEVFSADM_CREATE_INIT_V0(dtrace_create_cbt);

static int
dtrace(di_minor_t minor, di_node_t node)
{
	char *mname = di_minor_name(minor);
	char path[MAXPATHLEN];

	(void) snprintf(path, sizeof (path), "dtrace/%s", mname);
	(void) devfsadm_mklink(path, node, minor, 0);

	return (DEVFSADM_CONTINUE);
}

static int
dtrace_provider(di_minor_t minor, di_node_t node)
{
	char *mname = di_minor_name(minor);
	char path[MAXPATHLEN];

	(void) snprintf(path, sizeof (path), "dtrace/provider/%s", mname);
	(void) devfsadm_mklink(path, node, minor, 0);

	return (DEVFSADM_CONTINUE);
}
