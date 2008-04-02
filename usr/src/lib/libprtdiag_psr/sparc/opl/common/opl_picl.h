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
 *
 * Opl Platform header file.
 *
 * 	called when :
 *	machine_type == MTYPE_OPL
 */

#ifndef	_OPL_PICL_H
#define	_OPL_PICL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Property names
 */
#define	OBP_PROP_REG			"reg"
#define	OBP_PROP_CLOCK_FREQ		"clock-frequency"
#define	OBP_PROP_BOARD_NUM		"board#"
#define	OBP_PROP_REVISION_ID		"revision-id"
#define	OBP_PROP_VENDOR_ID		"vendor-id"
#define	OBP_PROP_DEVICE_ID		"device-id"
#define	OBP_PROP_VERSION_NUM		"version#"
#define	OBP_PROP_BOARD_TYPE		"board_type"
#define	OBP_PROP_ECACHE_SIZE		"ecache-size"
#define	OBP_PROP_IMPLEMENTATION		"implementation#"
#define	OBP_PROP_MASK			"mask#"
#define	OBP_PROP_COMPATIBLE		"compatible"
#define	OBP_PROP_BANNER_NAME		"banner-name"
#define	OBP_PROP_MODEL			"model"
#define	OBP_PROP_66MHZ_CAPABLE		"66mhz-capable"
#define	OBP_PROP_VERSION		"version"
#define	OBP_PROP_INSTANCE		"instance"

/* PCI BUS types */

#define	PCI_UNKN	-1
#define	PCI	10
#define	PCIX	20
#define	PCIE	30

/* PCI device defines */

#define	PCI_CONF_VENID		0x0		/* vendor id, 2 bytes */
#define	PCI_CONF_DEVID		0x2		/* device id, 2 bytes */
#define	PCI_CONF_CAP_PTR	0x34		/* 1 byte capability pointer */
#define	PCI_CAP_ID_PCI_E	0x10		/* PCI Express supported */
#define	PCIE_LINKCAP		0x0C		/* Link Capability */
#define	PCIE_LINKSTS		0x12		/* Link Status */
#define	PCI_CAP_MASK		0xff		/* CAP Mask */
#define	PCI_DEV_MASK		0xF800		/* Dev# Mask */
#define	PCI_FUNC_MASK		0x700		/* Func# Mask */
#define	PCI_BUS_MASK		0x1ff0000	/* Bus# Mask */
#define	PCI_LINK_MASK		0x1f		/* Link Mask */

#define	PCI_LINK_SHIFT		4		/* Link shift Bits */
#define	PCI_FREQ_66		66		/* PCI default freq */
#define	PCI_FREQ_100		100

/* PCI frequencies */

#define	PCI_FREQ_133		133
#define	PCI_FREQ_266		266
#define	PCI_FREQ_533		533

/* PCI frequency shift bits */

#define	PCI_SHIFT_133		17
#define	PCI_SHIFT_266		30
#define	PCI_SHIFT_533		31

/* PCI frequency modes */

#define	PCI_MODE_66		1
#define	PCI_MODE_100		2
#define	PCI_MODE_133		3

/* PCI frequency SEC status masks */

#define	PCI_SEC_133		0x2
#define	PCI_SEC_266		0x4000
#define	PCI_SEC_533		0x8000
#define	PCI_LEAF_ULONG		1UL


/* Invalid property value */
#define	PROP_INVALID		-1

/* Macros */

#define	IS_PCI(name) \
	(((name) != NULL) && (strncmp((name), "pci", 3) == 0))

#define	IS_EBUS(class) \
	(((class) != NULL) && (strncmp((class), "ebus", 4) == 0))

#define	ROUND_TO_MHZ(x)	(((x) + 500000)/ 1000000)

#define	PRINT_FREQ_FMT(arg_1, arg_2) \
		if (((arg_1) != 0) && \
			((arg_2) != 0)) \
				log_printf("%4d, %4d  ", (arg_1), (arg_2)); \
			else if ((arg_2) != 0) \
				log_printf("  --, %4d  ", (arg_2)); \
			else if ((arg_1) != 0) \
				log_printf("%4d,  -- ", (arg_1)); \
			else \
				log_printf("  --,  --  ");

#define	PRINT_FMT(arg_1, arg_2) \
		if (((arg_1) != PROP_INVALID) && \
			((arg_2) != PROP_INVALID)) \
				log_printf("%4d, %4d  ", (arg_1), (arg_2)); \
			else if ((arg_2) != PROP_INVALID) \
				log_printf("  --, %4d  ", (arg_2)); \
			else if ((arg_1) != PROP_INVALID) \
				log_printf("%4d,  -- ", (arg_1)); \
			else \
				log_printf("  --,  --  ");



#ifdef __cplusplus
}
#endif

#endif /* _OPL_PICL_H */
