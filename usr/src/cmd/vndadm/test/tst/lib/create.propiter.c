/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2014 Joyent, Inc.  All rights reserved.
 */

/*
 * Ensure that vnd_prop_iter sees all props;
 */

#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <assert.h>
#include <libvnd.h>

static boolean_t *g_props;

/* ARGSUSED */
static int
prop_cb(vnd_handle_t *vhp, vnd_prop_t prop, void *unused)
{
	assert(prop < VND_PROP_MAX);
	g_props[prop] = B_TRUE;

	return (0);
}

int
main(int argc, const char *argv[])
{
	int syserr, i, ret;
	vnd_errno_t vnderr;
	vnd_handle_t *vhp;

	if (argc < 2) {
		(void) fprintf(stderr, "missing arguments...\n");
		return (1);
	}

	if (strlen(argv[1]) >= LIBVND_NAMELEN) {
		(void) fprintf(stderr, "vnic name too long...\n");
		return (1);
	}

	g_props = malloc(sizeof (boolean_t) * VND_PROP_MAX);
	if (g_props == NULL) {
		(void) fprintf(stderr, "failed to alloc memory for %d "
		    "boolean_t\n", VND_PROP_MAX);
		return (1);
	}
	for (i = 0; i < VND_PROP_MAX; i++)
		g_props[i] = B_FALSE;

	vhp = vnd_create(NULL, argv[1], argv[1], &vnderr, &syserr);
	assert(vhp != NULL);
	assert(vnderr == 0);
	assert(syserr == 0);

	ret = vnd_prop_iter(vhp, prop_cb, NULL);
	assert(ret == 0);

	for (i = 0; i < VND_PROP_MAX; i++)
		assert(g_props[i] == B_TRUE);

	free(g_props);
	vnd_close(vhp);

	return (0);
}
