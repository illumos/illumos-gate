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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <devfsadm.h>
#include <strings.h>
#include <stdlib.h>
#include <limits.h>
#include <bsm/devalloc.h>

extern int system_labeled;

static int tape_process(di_minor_t minor, di_node_t node);

static devfsadm_create_t tape_cbt[] = {
	{ "tape", "ddi_byte:tape", NULL,
	TYPE_EXACT, ILEVEL_0,	tape_process
	},
};

DEVFSADM_CREATE_INIT_V0(tape_cbt);

#define	TAPE_LINK_RE "^rmt/[0-9]+[cbhlmnu]*"

static devfsadm_remove_t tape_remove_cbt[] = {
	{ "tape", TAPE_LINK_RE, RM_PRE, ILEVEL_0, devfsadm_rm_all
	}
};

DEVFSADM_REMOVE_INIT_V0(tape_remove_cbt);


/*
 * This function is called for every tape minor node.
 * Calls enumerate to assign a logical tape id, and then
 * devfsadm_mklink to make the link.
 */
static int
tape_process(di_minor_t minor, di_node_t node)
{
	int flags = 0;
	char l_path[PATH_MAX + 1];
	char *buf;
	char *mn;
	char *devfspath;
	devfsadm_enumerate_t rules[1] = {"rmt/([0-9]+)", 1, MATCH_ADDR};

	mn = di_minor_name(minor);


	if ((mn != NULL) && (*mn >= '0') && (*mn <= '9')) {
		/*
		 * first character cannot be a digit as it would combine
		 * with the tape instance number to make an ambiguous quantity.
		 */
		return (DEVFSADM_CONTINUE);
	}

	devfspath = di_devfs_path(node);

	(void) strcpy(l_path, devfspath);
	(void) strcat(l_path, ":");
	(void) strcat(l_path, mn);

	di_devfs_path_free(devfspath);

	/*
	 *  devfsadm_enumerate finds the logical tape id from the physical path,
	 *  omitting minor name field. The logical tape id is returned in buf.
	 */
	if (devfsadm_enumerate_int(l_path, 0, &buf, rules, 1)) {
		return (DEVFSADM_CONTINUE);
	}

	(void) strcpy(l_path, "rmt/");
	(void) strcat(l_path, buf);
	(void) strcat(l_path, mn);
	free(buf);

	if (system_labeled)
		flags = DA_ADD|DA_TAPE;

	(void) devfsadm_mklink(l_path, node, minor, flags);

	return (DEVFSADM_CONTINUE);
}
