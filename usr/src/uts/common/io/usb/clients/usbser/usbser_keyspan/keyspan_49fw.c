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


#include <sys/types.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/usb/clients/usbser/usbser_keyspan/keyspan_var.h>

#include <sys/usb/clients/usbser/usbser_keyspan/keyspan_49fw.h>

/* Get the address of firmware structure */
const usbser_keyspan_fw_record_t *
keyspan_usa49wlc_fw(void)
{
#ifdef KEYSPAN_NO_FIRMWARE_SOURCE

	return (NULL);
#else

	return (keyspan_usa49wlc_firmware);
#endif
}

extern struct mod_ops mod_miscops;

static struct modlmisc modlmisc = {
#ifdef KEYSPAN_NO_FIRMWARE_SOURCE
	&mod_miscops, "Placeholder module for the firmware of Keyspan"
	    " usb2serial adapter (usa49wlc)"
#else
	&mod_miscops, "Firmware for Keyspan usb2serial adapter (usa49wlc)"
#endif
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
