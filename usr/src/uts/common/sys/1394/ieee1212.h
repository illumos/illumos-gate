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
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_1394_IEEE1212_H
#define	_SYS_1394_IEEE1212_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * ieee1212.h
 *     This file contains various defines for config rom entries
 */

#ifdef	__cplusplus
extern "C" {
#endif

#define	IEEE1212_NODE_CAP_QUAD			2	/* node capability */
#define	IEEE1212_ROOT_DIR_QUAD			5	/* root dir quad */

#define	IEEE1212_DIR_LEN(data) 			(((data) >> 16) & 0xFFFF)
#define	IEEE1212_DIR_CRC(data)			((uint16_t)((data) & 0xFFFF))

#define	CONFIG_ROM_GEN(rom_ptr) \
	(((rom_ptr)[IEEE1212_NODE_CAP_QUAD] & 0x000000F0) >> 4)

#define	CFGROM_ROOT_DIR(cfgrom) 	(&(cfgrom)[IEEE1212_ROOT_DIR_QUAD])
#define	CFGROM_DIR_LEN(dirptr)		(((dirptr)[0] >> 16) & 0xFF)
#define	CFGROM_TYPE_KEY_VALUE(q, t, k, v) {				     \
	(t) = (((q) & IEEE1212_KEY_TYPE_MASK) >> IEEE1212_KEY_TYPE_SHIFT);   \
	(k) = (((q) & IEEE1212_KEY_VALUE_MASK) >> IEEE1212_KEY_VALUE_SHIFT); \
	(v) = (q) & IEEE1212_ENTRY_VALUE_MASK;				     \
}

/* Key types */
#define	IEEE1212_IMMEDIATE_TYPE			0
#define	IEEE1212_CSR_OFFSET_TYPE		1
#define	IEEE1212_LEAF_TYPE			2
#define	IEEE1212_DIRECTORY_TYPE			3

/* Key values */
#define	IEEE1212_TEXTUAL_DESCRIPTOR		0x01
#define	IEEE1212_BUS_DEPENDENT_INFO		0x02
#define	IEEE1212_MODULE_VENDOR_ID		0x03
#define	IEEE1212_MODULE_HW_VERSION		0x04
#define	IEEE1212_MODULE_SPEC_ID			0x05
#define	IEEE1212_MODULE_SW_VERSION		0x06
#define	IEEE1212_MODULE_DEPENDENT_INFO		0x07
#define	IEEE1212_NODE_VENDOR_ID			0x08
#define	IEEE1212_NODE_HW_VERSION		0x09
#define	IEEE1212_NODE_SPEC_ID			0x0A
#define	IEEE1212_NODE_SW_VERSION		0x0B
#define	IEEE1212_NODE_CAPABILITIES		0x0C
#define	IEEE1212_NODE_UNIQUE_ID			0x0D
#define	IEEE1212_NODE_UNITS_EXTENT		0x0E
#define	IEEE1212_NODE_MEMORY_EXTENT		0x0F
#define	IEEE1212_NODE_DEPENDENT_INFO		0x10
#define	IEEE1212_UNIT_DIRECTORY			0x11
#define	IEEE1212_UNIT_SPEC_ID			0x12
#define	IEEE1212_UNIT_SW_VERSION		0x13
#define	IEEE1212_UNIT_DEPENDENT_INFO		0x14
#define	IEEE1212_UNIT_LOCATION			0x15
#define	IEEE1212_UNIT_POLL_MASK			0x16

#define	IEEE1212_KEY_TYPE_MASK			0xC0000000
#define	IEEE1212_KEY_TYPE_SHIFT			30
#define	IEEE1212_KEY_VALUE_MASK			0x3F000000
#define	IEEE1212_KEY_VALUE_SHIFT		24
#define	IEEE1212_ENTRY_VALUE_MASK		0x00FFFFFF

#define	IEEE1212_NODE_CAPABILITIES_MASK		0x0000FFFF

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_1394_IEEE1212_H */
