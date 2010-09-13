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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <libnvpair.h>
#include <stdio.h>
#include <unistd.h>
#include <scsi/libses.h>

static void fatal(int, const char *, ...) __NORETURN;

static void
fatal(int err, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void) vfprintf(stderr, fmt, ap);
	va_end(ap);

	(void) fprintf(stderr, "\n");
	(void) fflush(stderr);

	_exit(err);
}

/*ARGSUSED*/
static ses_walk_action_t
node(ses_node_t *np, void *arg)
{
	ses_node_type_t type;
	uint64_t val;
	nvlist_t *props;
	char *t;

	type = ses_node_type(np);
	(void) printf("Node Type: %d\n", type);
	if ((props = ses_node_props(np)) == NULL) {
		(void) printf("No properties\n");
		return (SES_WALK_ACTION_CONTINUE);
	}
	if (type == SES_NODE_ELEMENT || type == SES_NODE_AGGREGATE) {
		(void) nvlist_lookup_uint64(props, SES_PROP_ELEMENT_TYPE, &val);
		if (nvlist_lookup_string(props, LIBSES_PROP_ELEMENT_TYPE_NAME,
		    &t) != 0)
			t = NULL;
		(void) printf("Element Type: %s\n", t ? t : "<unknown>");
	}
	nvlist_print(stdout, props);

	return (SES_WALK_ACTION_CONTINUE);
}

int
main(int argc, char *argv[])
{
	ses_target_t *tp;
	ses_snap_t *sp;

	if (argc != 2)
		fatal(1, "Usage: %s <device>", argv[0]);

	if ((tp = ses_open(LIBSES_VERSION, argv[1])) == NULL)
		fatal(-1, "failed to open %s: %s", argv[1], ses_errmsg());

	sp = ses_snap_hold(tp);

	(void) ses_walk(sp, node, NULL);

	ses_snap_rele(sp);
	ses_close(tp);

	return (0);
}
