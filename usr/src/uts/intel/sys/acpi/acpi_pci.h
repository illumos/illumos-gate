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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2016 Joyent, Inc.
 */

#ifndef	_ACPI_PCI_H
#define	_ACPI_PCI_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Memory mapped configuration space address description table documented
 * in ACPI 3.0.  These definitions are currently not the same as in the
 * actbl2.h from Intel.  This file might be removed if the code can be ported
 * to use the definition provided by Intel.
 */
#pragma pack(1)

typedef struct cfg_base_addr_alloc {
	UINT64	base_addr;
	UINT16	segment;
	UINT8	start_bno;
	UINT8	end_bno;
	UINT32	reserved;
} CFG_BASE_ADDR_ALLOC;

typedef struct mcfg_table {
	char	Signature[4];		/* MCFG signature */
	UINT32	Length;			/* Length of table, in bytes */
	UINT8	Revision;		/* ACPI Specification minor version # */
	UINT8	Checksum;		/* To make sum of entire table == 0 */
	char	OemId[6];		/* OEM identification */
	char	OemTableId[8];		/* OEM table identification */
	UINT32	OemRevision;		/* OEM revision number */
	char	CreatorId[4];		/* Table creator vendor Id */
	UINT32	CreatorRevision;	/* Table creator utility revision no */
	UINT8	Reserved[8];		/* Reserved */
	/* List of memory mapped cfg base address allocation structures */
	CFG_BASE_ADDR_ALLOC	CfgBaseAddrAllocList[1];
} MCFG_TABLE;

#pragma pack()

#ifdef	__cplusplus
}
#endif

#endif	/* _ACPI_PCI_H */
