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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
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
#include <sys/sunndi.h>
#include <sys/esunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/promif.h>
#include <sys/modctl.h>
#include <sys/termios.h>
#if defined(__xpv)
#include <sys/hypervisor.h>
#include <sys/boot_console.h>
#endif

/* The names of currently supported graphics drivers on x86 */
static char *
gfxdrv_name[] = {
	"vgatext",
	"i915",
	"nvidia"
};

int
plat_use_polled_debug() {
	return (0);
}

int
plat_support_serial_kbd_and_ms() {
	return (0);
}

#define	A_CNT(arr)	(sizeof (arr) / sizeof (arr[0]))

#define	CONS_INVALID	-1
#define	CONS_SCREEN	0
#define	CONS_TTYA	1
#define	CONS_TTYB	2
#define	CONS_USBSER	3
#define	CONS_HYPERVISOR	4

static int
console_type()
{
	static int boot_console = CONS_INVALID;

	char *cons;
	dev_info_t *root;

	if (boot_console != CONS_INVALID)
		return (boot_console);

#if defined(__xpv)
	if (!DOMAIN_IS_INITDOMAIN(xen_info) || bcons_hypervisor_redirect()) {
		boot_console = CONS_HYPERVISOR;
		return (boot_console);
	}
#endif /* __xpv */

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
		if (strcmp(cons, "ttya") == 0) {
			boot_console = CONS_TTYA;
		} else if (strcmp(cons, "ttyb") == 0) {
			boot_console = CONS_TTYB;
		} else if (strcmp(cons, "usb-serial") == 0) {
			(void) i_ddi_attach_hw_nodes("ehci");
			(void) i_ddi_attach_hw_nodes("uhci");
			(void) i_ddi_attach_hw_nodes("ohci");
			/*
			 * USB device enumerate asynchronously.
			 * Wait 2 seconds for USB serial devices to attach.
			 */
			delay(drv_usectohz(2000000));
			boot_console = CONS_USBSER;
#if defined(__xpv)
		} else if (strcmp(cons, "hypervisor") == 0) {
			boot_console = CONS_HYPERVISOR;
#endif /* __xpv */
		}
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
	dev_info_t *dip, *dip_pseudo = NULL;
	int i;

	/* lookup the dip for the pseudo device */
	(void) resolve_pathname("/pseudo", &dip_pseudo, NULL, NULL);

	for (i = 0; i < A_CNT(gfxdrv_name); i++) {
		/*
		 * look for first instance of each driver
		 */
		if ((major = ddi_name_to_major(gfxdrv_name[i])) == (major_t)-1)
			continue;

		if ((dip = devnamesp[major].dn_head) == NULL)
			continue;

		/*
		 * We're looking for a real hardware device here so skip
		 * any pseudo devices.  When could a framebuffer hardware
		 * driver also have a pseudo node?  Well, some framebuffer
		 * hardware drivers (nvidia) also create pseudo nodes for
		 * administration purposes, and these nodes will exist
		 * regardless of if the actual associated hardware
		 * is present or not.
		 */
		if (ddi_get_parent(dip) == dip_pseudo)
			continue;

		if (i_ddi_attach_node_hierarchy(dip) == DDI_SUCCESS) {
			(void) ddi_pathname(dip, fbpath_buf);
			fbpath = fbpath_buf;
		}

		if (fbpath)
			break;
	}

	if (dip_pseudo != NULL)
		ddi_release_devi(dip_pseudo);

	/* No screen found */
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

/* return path of first usb serial device */
static char *
plat_usbser_path(void)
{
	extern dev_info_t *usbser_first_device(void);

	dev_info_t *us_dip;
	static char *us_path = NULL;

	if (us_path)
		return (us_path);

	us_dip = usbser_first_device();
	if (us_dip == NULL)
		return (NULL);

	us_path = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	(void) ddi_pathname(us_dip, us_path);
	ndi_rele_devi(us_dip);	/* held from usbser_first_device */
	return (us_path);
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
#if defined(__xpv)
	case CONS_HYPERVISOR:
		return ("/xpvd/xencons@0");
#endif /* __xpv */
	case CONS_TTYA:
		return ("/isa/asy@1,3f8:a");
	case CONS_TTYB:
		return ("/isa/asy@1,2f8:b");
	case CONS_USBSER:
		return (plat_usbser_path());
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
#if defined(__xpv)
	case CONS_HYPERVISOR:
		return ("/xpvd/xencons@0");
#endif /* __xpv */
	case CONS_TTYA:
		return ("/isa/asy@1,3f8:a");
	case CONS_TTYB:
		return ("/isa/asy@1,2f8:b");
	case CONS_USBSER:
		return (plat_usbser_path());
	case CONS_SCREEN:
	default:
		break;
	};
	return (plat_fbpath());
}

/*
 * If VIS_PIXEL mode will be implemented on x86, these following
 * functions should be re-considered. Now these functions are
 * unused on x86.
 */
void
plat_tem_get_inverses(int *inverse, int *inverse_screen)
{
	*inverse = 0;
	*inverse_screen = 0;
}

void
plat_tem_get_prom_font_size(int *charheight, int *windowtop)
{
	*charheight = 0;
	*windowtop = 0;
}

/*ARGSUSED*/
void
plat_tem_get_prom_size(size_t *height, size_t *width)
{
	panic("unimplemented at line %d of %s", __LINE__, __FILE__);
}

void
plat_tem_hide_prom_cursor(void)
{
	panic("unimplemented at line %d of %s", __LINE__, __FILE__);
}

/*ARGSUSED*/
void
plat_tem_get_prom_pos(uint32_t *row, uint32_t *col)
{
	panic("unimplemented at line %d of %s", __LINE__, __FILE__);
}
