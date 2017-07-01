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
 * Copyright 2019, Joyent, Inc.
 */

/* private devlink info interfaces */

#ifndef	_CFG_LINK_H
#define	_CFG_LINK_H

#include <devfsadm.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	SCSI_CFG_LINK_RE	"^cfg/c[0-9]+$"
#define	SBD_CFG_LINK_RE		"^cfg/((((N[0-9]+[.])?(SB|IB))?[0-9]+)|[abcd])$"
#define	USB_CFG_LINK_RE		"^cfg/((usb[0-9]+)/([0-9]+)([.]([0-9])+)*)$"
#define	PCI_CFG_LINK_RE		"^cfg/[:alnum:]$"
#define	IB_CFG_LINK_RE		"^cfg/(hca[0-9A-F]+)$"
#define	SATA_CFG_LINK_RE	"^cfg/((sata[0-9]+)/([0-9]+)([.]([0-9])+)*)$"
#define	SDCARD_CFG_LINK_RE	"^cfg/sdcard[0-9]+/[0-9]+$"
#define	PCI_CFG_PATH_LINK_RE	\
	"^cfg/(.*(pci[0-9]|pcie[0-9]|Slot[0-9]|\\<pci\\>|\\<pcie\\>).*)$"
#define	CCID_CFG_LINK_RE	"^cfg/ccid[0-9]+/slot[0-9]+$"

#define	CFG_DIRNAME		"cfg"

#define	PROPVAL_PCIEX		"pciex"
#define	DEVTYPE_PCIE		"pcie"
#define	IOB_PRE			"iob"
#define	AP_PATH_SEP		":"
#define	AP_PATH_IOB_SEP		"."
#define	IEEE_SUN_ID		0x080020
#define	APNODE_DEFNAME		0x1
#define	PCIDEV_NIL		((minor_t)-1)

/* converts size in bits to a mask covering those bit positions */
#define	SIZE2MASK(s)		((1 << (s)) - 1)
#define	SIZE2MASK64(s)		((1LL << (s)) - 1LL)

/*
 * macros for the ieee1275 "reg" property
 * naming format and semantics:
 *
 * REG_<cell>_SIZE_<field> = bit size of <field> in <cell>
 * REG_<cell>_OFF_<field> = starting bit position of <field> in <cell>
 *
 * REG_<cell>_<field>(r) = returns the value of <field> in <cell> using:
 *	(((r) >> REG_<cell>_OFF_<field>) & SIZE2MASK(REG_<cell>_SIZE_<field>))
 */
#define	REG_PHYSHI_SIZE_PCIDEV	5
#define	REG_PHYSHI_OFF_PCIDEV	11
#define	REG_PHYSHI_PCIDEV(r)	\
	(((r) >> REG_PHYSHI_OFF_PCIDEV) & SIZE2MASK(REG_PHYSHI_SIZE_PCIDEV))

/* rp = ptr to 5-tuple int array */
#define	REG_PHYSHI_INDEX	0
#define	REG_PHYSHI(rp)		((rp)[REG_PHYSHI_INDEX])

#define	REG_PCIDEV(rp)		(REG_PHYSHI_PCIDEV(REG_PHYSHI(rp)))


#define	DEV "/dev"
#define	DEV_LEN 4
#define	DEVICES "/devices"
#define	DEVICES_LEN 8

#ifdef	__cplusplus
}
#endif

#endif /* _CFG_LINK_H */
