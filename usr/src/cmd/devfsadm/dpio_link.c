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
 * Copyright 2022 Oxide Computer Company
 */

/*
 * Our goal is to create the /dev/dpio/%s links that need to exist for each
 * dpio(7) related entry. The kgpio driver creates a minor node for each dpio of
 * the form 'dpio:<name>' and uses the type DDI_NT_GPIO_DPIO. For exmaple, the
 * name 'dpio:foobar' would cause us to create /dev/dpio/foobar.
 */

#include <devfsadm.h>
#include <string.h>

static int
dpio_link(di_minor_t minor, di_node_t node)
{
	const char *name, *colon;
	char buf[PATH_MAX];

	name = di_minor_name(minor);
	if (name == NULL) {
		return (DEVFSADM_CONTINUE);
	}

	colon = strchr(name, ':');
	if (colon == NULL) {
		return (DEVFSADM_CONTINUE);
	}

	if (snprintf(buf, sizeof (buf), "dpio/%s", colon + 1) < sizeof (buf)) {
		(void) devfsadm_mklink(buf, node, minor, 0);
	}

	return (DEVFSADM_CONTINUE);
}

static devfsadm_create_t dpio_create_cbt[] = {
	{ "pseudo", DDI_NT_GPIO_DPIO, "kgpio", TYPE_EXACT | DRV_EXACT, ILEVEL_0,
	    dpio_link }
};

static devfsadm_remove_t dpio_remove_cbt[] = {
	{ "pseudo", "^dpio/[A-Za-z0-9]+$", RM_POST | RM_HOT | RM_ALWAYS,
	    ILEVEL_0, devfsadm_rm_all },
};

DEVFSADM_CREATE_INIT_V0(dpio_create_cbt);
DEVFSADM_REMOVE_INIT_V0(dpio_remove_cbt);
