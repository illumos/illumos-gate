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
 *
 * mps_table.h -- MP Specification table definitions
 */

#ifndef	_MPS_TABLE_H
#define	_MPS_TABLE_H

#ifdef	__cplusplus
extern "C" {
#endif


struct mps_fps_hdr {		/* MP Floating Pointer Structure	*/
	uint32_t fps_sig;	/* _MP_ (0x5F4D505F)			*/
	uint32_t fps_mpct_paddr; /* paddr of MP Configuration Table	*/
	uchar_t	fps_len;	/* in paragraph (16-bytes units)	*/
	uchar_t	fps_spec_rev;	/* MP Spec. version no.			*/
	uchar_t	fps_cksum;	/* checksum of complete structure	*/
	uchar_t	fps_featinfo1;	/* mp feature info byte 1		*/
	uchar_t	fps_featinfo2;	/* mp feature info byte 2		*/
	uchar_t	fps_featinfo3;	/* mp feature info byte 3		*/
	uchar_t	fps_featinfo4;	/* mp feature info byte 4		*/
	uchar_t	fps_featinfo5;	/* mp feature info byte 5		*/
};

struct mps_ct_hdr {		/* MP Configuration Table Header	*/
	uint32_t ct_sig;	/* "PCMP"				*/
	uint16_t ct_len;	/* base configuration in bytes		*/
	uchar_t	ct_spec_rev;	/* MP Spec. version no.			*/
	uchar_t	ct_cksum;	/* base configuration table checksum	*/
	char	ct_oem_id[8];	/* string identifies the manufacturer	*/
	char	ct_prod_id[12]; /* string identifies the product	*/
	uint32_t ct_oem_ptr;	/* paddr to an OEM-defined table	*/
	uint16_t ct_oem_tbl_len; /* size of base OEM table in bytes	*/
	uint16_t ct_entry_cnt;	/* no. of entries in the base table	*/
	uint32_t ct_local_apic;	/* paddr of local APIC			*/
	uint16_t ct_ext_tbl_len; /* extended table in bytes		*/
	uchar_t	ct_ext_cksum;	/* checksum for the extended table	*/
};

/* Base MP Configuration Table entry type definitions */
#define	CPU_TYPE	0
#define	BUS_TYPE	1
#define	IO_APIC_TYPE	2
#define	IO_INTR_TYPE	3
#define	LOCAL_INTR_TYPE	4

/* Base MP Configuration Table entry size definitions */
#define	CPU_SIZE	20
#define	BUS_SIZE	8
#define	IO_APIC_SIZE	8
#define	IO_INTR_SIZE	8
#define	LOCAL_INTR_SIZE	8

/* Extended MP Configuration Table entry type definitions */
#define	SYS_AS_MAPPING		128
#define	BUS_HIERARCHY_DESC	129
#define	COMP_BUS_AS_MODIFIER	130

/* Extended MP Configuration Table entry size definitions */
#define	SYS_AS_MAPPING_SIZE		20
#define	BUS_HIERARCHY_DESC_SIZE		8
#define	COMP_BUS_AS_MODIFIER_SIZE	8

struct sasm {			/* System Address Space Mapping Entry	*/
	uchar_t sasm_type;	/* type 128				*/
	uchar_t sasm_len;	/* entry length in bytes (20)		*/
	uchar_t sasm_bus_id;	/* bus id where this is mapped		*/
	uchar_t sasm_as_type;	/* system address type			*/
/* system address type definitions */
#define	IO_TYPE		0
#define	MEM_TYPE	1
#define	PREFETCH_TYPE	2
#define	BUSRANGE_TYPE	3
	uint32_t sasm_as_base;	/* starting address			*/
	uint32_t sasm_as_base_hi;
	uint32_t sasm_as_len;	/* no. of addresses visiblie to the bus	*/
	uint32_t sasm_as_len_hi;
};

struct bhd {			/* Bus Hierarchy Descriptor Entry	*/
	uchar_t bhd_type;	/* type 129				*/
	uchar_t bhd_len;	/* entry length in bytes (8)		*/
	uchar_t bhd_bus_id;	/* bus id of this bus			*/
	uchar_t bhd_bus_info;	/* bus information			*/
/* Bus Information bit definition */
#define	BHD_BUS_INFO_SD	1	/* Subtractive Decode Bus		*/
	uchar_t bhd_parent;
};

struct cbasm {	/* Compatibility Bus Address Space Modifier Entry */
	uchar_t cbasm_type;	/* type 130				*/
	uchar_t cbasm_len;	/* entry length in bytes (8)		*/
	uchar_t cbasm_bus_id;	/* bus to be modified			*/
	uchar_t cbasm_addr_mod;	/* address modifier			*/
/* Address Modifier bit definiton */
#define	CBASM_ADDR_MOD_PR	1	/* 1 = subtracted, 0 = added */
	uint32_t cbasm_pr_list;	/* identify list of predefined address ranges */
};

#ifdef	__cplusplus
}
#endif

#endif	/* _MPS_TABLE_H */
