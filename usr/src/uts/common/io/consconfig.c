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

/*
 * Console and mouse configuration
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/cmn_err.h>
#include <sys/user.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/systm.h>
#include <sys/file.h>
#include <sys/klwp.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strsubr.h>

#include <sys/consdev.h>
#include <sys/kbio.h>
#include <sys/debug.h>
#include <sys/reboot.h>
#include <sys/termios.h>

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/ddi_impldefs.h>

#include <sys/strsubr.h>
#include <sys/errno.h>
#include <sys/devops.h>
#include <sys/note.h>


/*
 * On supported configurations, the firmware defines the keyboard and mouse
 * paths.  However, during USB development, it is useful to be able to use
 * the USB keyboard and mouse on machines without full USB firmware support.
 * These variables may be set in /etc/system according to a machine's
 * USB configuration.  This module will override the firmware's values
 * with these.
 */
static char *usb_kb_path = NULL;
static char *usb_ms_path = NULL;

/*
 * This is the loadable module wrapper.
 */
extern struct mod_ops mod_miscops;

/*
 * Module linkage information for the kernel.
 */
static struct modlmisc modlmisc = {
	&mod_miscops, "console configuration"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

extern void dynamic_console_config(void);

/*
 * Configure keyboard and mouse. Main entry here.
 */
void
consconfig(void)
{
	dynamic_console_config();
}

extern char *
consconfig_get_usb_kb_path(void) {
	if (usb_kb_path)
		return (i_ddi_strdup(usb_kb_path, KM_SLEEP));
	return (NULL);
}

extern char *
consconfig_get_usb_ms_path(void) {
	if (usb_ms_path)
		return (i_ddi_strdup(usb_ms_path, KM_SLEEP));
	return (NULL);
}
