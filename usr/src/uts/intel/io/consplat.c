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

/*
 * isa-specific console configuration routines
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/cmn_err.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/esunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/promif.h>
#include <sys/modctl.h>
#include <sys/termios.h>

int
plat_use_polled_debug() {
	return (0);
}

int
plat_support_serial_kbd_and_ms() {
	return (0);
}

#define	CONS_INVALID	-1
#define	CONS_SCREEN	0
#define	CONS_TTYA	1
#define	CONS_TTYB	2

static int
console_type()
{
	static int boot_console = CONS_INVALID;

	char *cons;
	dev_info_t *root;

	if (boot_console != CONS_INVALID)
		return (boot_console);

	/*
	 * console is defined by "console" property, with
	 * fallback on the old "input-device" property.
	 */
	boot_console = CONS_SCREEN;	/* default is screen/kb */
	root = ddi_root_node();
	if ((ddi_prop_lookup_string(DDI_DEV_T_ANY, root,
	    DDI_PROP_DONTPASS, "console", &cons) == DDI_SUCCESS) ||
	    (ddi_prop_lookup_string(DDI_DEV_T_ANY, root,
	    DDI_PROP_DONTPASS, "input-device", &cons) == DDI_SUCCESS)) {
		if (strcmp(cons, "ttya") == 0)
			boot_console = CONS_TTYA;
		else if (strcmp(cons, "ttyb") == 0)
			boot_console = CONS_TTYB;
		ddi_prop_free(cons);
	}
	return (boot_console);
}

int
plat_stdin_is_keyboard(void)
{
	return (console_type() == CONS_SCREEN);
}

int
plat_stdout_is_framebuffer(void)
{
	return (console_type() == CONS_SCREEN);
}

/*
 * Return generic path to keyboard device from the alias.
 */
char *
plat_kbdpath(void)
{
	/*
	 * Hardcode to isa keyboard path
	 * XXX make it settable via bootprop?
	 */
	return ("/isa/i8042@1,60/keyboard@0");
}

/*
 * Return generic path to display device from the alias.
 */
char *
plat_fbpath(void)
{
	static char *fbpath = NULL;
	static char fbpath_buf[MAXPATHLEN];
	major_t major;
	dev_info_t *dip;

	if (fbpath)
		return (fbpath);

	/*
	 * look for first instance of vgatext
	 */
	major = ddi_name_to_major("vgatext");
	if (major != (major_t)-1) {
		dip = devnamesp[major].dn_head;
		if (dip && i_ddi_attach_node_hierarchy(dip) == DDI_SUCCESS) {
			(void) ddi_pathname(dip, fbpath_buf);
			fbpath = fbpath_buf;
		}
	}

	if (fbpath)
		return (fbpath);

	/*
	 * Workaround for nvdia (the intrusive and unsupportable) driver
	 */
	major = ddi_name_to_major("nvidia");
	if (major != (major_t)-1) {
		dip = devnamesp[major].dn_head;
		if (dip && i_ddi_attach_node_hierarchy(dip) == DDI_SUCCESS) {
			(void) ddi_pathname(dip, fbpath_buf);
			fbpath = fbpath_buf;
		}
	}

	return (fbpath);
}

char *
plat_mousepath(void)
{
	/*
	 * Hardcode to isa mouse path
	 * XXX make it settable via bootprop?
	 */
	return ("/isa/i8042@1,60/mouse@1");
}

/*
 * Lacking support for com2 and com3, if that matters.
 * Another possible enhancement could be to use properties
 * for the port mapping rather than simply hard-code them.
 */
char *
plat_stdinpath(void)
{
	switch (console_type()) {
	case CONS_TTYA:
		return ("/isa/asy@1,3f8:a");
	case CONS_TTYB:
		return ("/isa/asy@1,2f8:b");
	case CONS_SCREEN:
	default:
		break;
	};
	return (plat_kbdpath());
}

char *
plat_stdoutpath(void)
{
	switch (console_type()) {
	case CONS_TTYA:
		return ("/isa/asy@1,3f8:a");
	case CONS_TTYB:
		return ("/isa/asy@1,2f8:b");
	case CONS_SCREEN:
	default:
		break;
	};
	return (plat_fbpath());
}
