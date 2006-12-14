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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <libintl.h>
#include <locale.h>
#include <unistd.h>
#include <picl.h>

#define	DEFAULT_NAME		"system"

typedef struct locator_info {
	int		(*locator_func)(picl_nodehdl_t, struct locator_info *);
	int		found; 		/* Nonzero if found during walk */
	int		err;   		/* Last error from picl */
	char		*name; 		/* Name/LocatorName of locator node */
	int		new_state;	/* 0 = logical off, 1 = logical on */
	char		*on;		/* Logical on value for State */
	char		*off;		/* Logical off value for State */
} locator_info_t;

static void
usage(char *prog_name)
{
	(void) fprintf(stderr, gettext("usage: %s [-n | -f]\n"), prog_name);
	exit(1);
}

static int
change_locator_state(picl_nodehdl_t locator_node, locator_info_t *locator_info)
{
	picl_prophdl_t	state_prop;
	char		state[PICL_PROPNAMELEN_MAX];
	int		err;
	char		*new_state;

	err = picl_get_prop_by_name(locator_node, "State", &state_prop);
	if (err != PICL_SUCCESS) {
		(void) fprintf(stderr,
			gettext("picl_get_prop_by_name failed: %s\n"),
			picl_strerror(err));
		return (err);
	}

	err = picl_get_propval(state_prop, state, sizeof (state));
	if (err != PICL_SUCCESS) {
		(void) fprintf(stderr,
			gettext("picl_get_propval failed: %s\n"),
			picl_strerror(err));
		return (err);
	}

	new_state = (locator_info->new_state) ? locator_info->on :
	    locator_info->off;

	if (strcmp(state, new_state) != 0) {
		picl_propinfo_t prop_info;
		err = picl_get_propinfo(state_prop, &prop_info);
		if (err != PICL_SUCCESS) {
			(void) fprintf(stderr,
				gettext("picl_get_propinfo failed: %s\n"),
				picl_strerror(err));
			return (err);
		}
		err = picl_set_propval(state_prop, new_state, prop_info.size);
		if (err != PICL_SUCCESS) {
			(void) fprintf(stderr,
				gettext("picl_set_propval failed: %s\n"),
				picl_strerror(err));
			return (err);
		}
	}
	return (err);
}

static int
display_locator_state(picl_nodehdl_t locator_node,
    locator_info_t *locator_info)
{
	char		state[PICL_PROPNAMELEN_MAX];
	char		*display_state;
	int		err;

	err = picl_get_propval_by_name(locator_node, "State",
		state, sizeof (state));
	if (err != PICL_SUCCESS) {
		(void) fprintf(stderr,
			gettext("picl_get_propval_by_name failed: %s\n"),
			picl_strerror(err));
		return (err);
	}

	if (strcmp(state, locator_info->on) == 0)
		display_state = gettext("on");
	else if (strcmp(state, locator_info->off) == 0)
		display_state = gettext("off");
	else
		display_state = state;

	(void) printf(gettext("The '%s' locator is %s.\n"),
		locator_info->name, display_state);
	return (err);
}

static int
locator_walker_func(picl_nodehdl_t nodeh, void *arg)
{
	locator_info_t	*locator_info = (locator_info_t *)arg;
	int		err;
	char		is_locator[PICL_PROPNAMELEN_MAX];
	char		name[PICL_PROPNAMELEN_MAX];
	char		locator_on[PICL_PROPNAMELEN_MAX];
	char		locator_off[PICL_PROPNAMELEN_MAX];

	err = picl_get_propval_by_name(nodeh, "IsLocator", is_locator,
		sizeof (is_locator));

	if (err != PICL_SUCCESS)
		return (PICL_WALK_CONTINUE);

	if (strcmp(is_locator, "true") != 0)
		return (PICL_WALK_CONTINUE);

	err = picl_get_propval_by_name(nodeh, "LocatorName", name,
		sizeof (name));

	if (err == PICL_PROPNOTFOUND)
		err = picl_get_propval_by_name(nodeh, PICL_PROP_NAME, name,
			sizeof (name));

	if (err != PICL_SUCCESS)
		return (err);

	if (strcmp(name, locator_info->name) != 0)
		return (PICL_WALK_CONTINUE);

	err = picl_get_propval_by_name(nodeh, "LocatorOn", locator_on,
		sizeof (locator_on));

	if (err == PICL_SUCCESS) {
		locator_info->on = locator_on;
	} else if (err == PICL_PROPNOTFOUND) {
		locator_info->on = "ON";
	} else {
		return (err);
	}

	err = picl_get_propval_by_name(nodeh, "LocatorOff", locator_off,
		sizeof (locator_off));

	if (err == PICL_SUCCESS) {
		locator_info->off = locator_off;
	} else if (err == PICL_PROPNOTFOUND) {
		locator_info->off = "OFF";
	} else {
		return (err);
	}

	locator_info->err = (locator_info->locator_func)(nodeh,
		locator_info);
	locator_info->found = 1;

	return (PICL_WALK_TERMINATE);
}

int
main(int argc, char **argv)
{
	locator_info_t	locator_info = {0, 0, 0, 0, 0};
	picl_nodehdl_t	rooth;
	int		err;
	int		c;
	int		on_flag = 0;
	int		off_flag = 0;
	char		*progname;
	char		*locator_name = DEFAULT_NAME;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	if ((progname = strrchr(argv[0], '/')) == NULL)
		progname = argv[0];
	else
		progname++;

	while ((c = getopt(argc, argv, "nf")) != EOF) {
		switch (c) {
		case 'n':
			on_flag++;
			break;
		case 'f':
			off_flag++;
			break;
		case '?':
			/*FALLTHROUGH*/
		default:
			usage(progname);
		}
	}
	if (argc != optind)
		usage(progname);

	/* We only take one option */
	if (on_flag && off_flag)
		usage(progname);

	err = picl_initialize();
	if (err != PICL_SUCCESS) {
		(void) fprintf(stderr, gettext("picl_initialize failed: %s\n"),
			picl_strerror(err));
		exit(2);
	}

	err = picl_get_root(&rooth);
	if (err != PICL_SUCCESS) {
		(void) fprintf(stderr, gettext("picl_get_root failed: %s\n"),
			picl_strerror(err));
		err = 2;
		goto OUT;
	}

	if (on_flag) {
		locator_info.locator_func = change_locator_state;
		locator_info.new_state = 1;
	} else if (off_flag) {
		locator_info.locator_func = change_locator_state;
		locator_info.new_state = 0;
	} else {
		locator_info.locator_func = display_locator_state;
	}

	locator_info.name = locator_name;

	err = picl_walk_tree_by_class(rooth, "led", &locator_info,
		locator_walker_func);
	if (err != PICL_SUCCESS) {
		(void) fprintf(stderr,
			gettext("picl_walk_tree_by_class failed: %s\n"),
			picl_strerror(err));
		err = 2;
		goto OUT;
	}

	if (locator_info.found == 0) {
		(void) fprintf(stderr, gettext("'%s' locator not found\n"),
			locator_name);
		err = 2;
	}
	if (locator_info.err != PICL_SUCCESS)
		err = 2;
OUT:
	(void) picl_shutdown();
	return (err);
}
