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
 */

#ifndef	_SYS_NXGE_NXGE_FFLP_HW_H
#define	_SYS_NXGE_NXGE_FFLP_HW_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <nxge_defs.h>


/* FZC_FFLP Offsets */
#define	    FFLP_ENET_VLAN_TBL_REG	(FZC_FFLP + 0x00000)

/* defines for FFLP_ENET_VLAN_TBL */
#define	ENET_VLAN_TBL_VLANRDCTBLN0_MASK 	0x0000000000000003ULL
#define	ENET_VLAN_TBL_VLANRDCTBLN0_SHIFT 	0
#define	ENET_VLAN_TBL_VPR0_MASK			0x00000000000000008ULL
#define	ENET_VLAN_TBL_VPR0_SHIFT		3

#define	ENET_VLAN_TBL_VLANRDCTBLN1_MASK 	0x0000000000000030ULL
#define	ENET_VLAN_TBL_VLANRDCTBLN1_SHIFT	4
#define	ENET_VLAN_TBL_VPR1_MASK			0x00000000000000080ULL
#define	ENET_VLAN_TBL_VPR1_SHIFT		7

#define	ENET_VLAN_TBL_VLANRDCTBLN2_MASK 	0x0000000000000300ULL
#define	ENET_VLAN_TBL_VLANRDCTBLN2_SHIFT 	8
#define	ENET_VLAN_TBL_VPR2_MASK			0x00000000000000800ULL
#define	ENET_VLAN_TBL_VPR2_SHIFT		11

#define	ENET_VLAN_TBL_VLANRDCTBLN3_MASK 	0x0000000000003000ULL
#define	ENET_VLAN_TBL_VLANRDCTBLN3_SHIFT 	12
#define	ENET_VLAN_TBL_VPR3_MASK			0x0000000000008000ULL
#define	ENET_VLAN_TBL_VPR3_SHIFT		15

#define	ENET_VLAN_TBL_PARITY0_MASK		0x0000000000010000ULL
#define	ENET_VLAN_TBL_PARITY0_SHIFT		16
#define	ENET_VLAN_TBL_PARITY1_MASK		0x0000000000020000ULL
#define	ENET_VLAN_TBL_PARITY1_SHIFT		17

typedef union _fflp_enet_vlan_tbl_t {
    uint64_t value;
    struct {
#if	defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#ifdef _BIT_FIELDS_HTOL
			uint32_t rsrvd:14;
			uint32_t parity1:1;
			uint32_t parity0:1;
			uint32_t vpr3:1;
			uint32_t vlanrdctbln3:3;
			uint32_t vpr2:1;
			uint32_t vlanrdctbln2:3;
			uint32_t vpr1:1;
			uint32_t vlanrdctbln1:3;
			uint32_t vpr0:1;
			uint32_t vlanrdctbln0:3;
#else
			uint32_t vlanrdctbln0:3;
			uint32_t vpr0:1;
			uint32_t vlanrdctbln1:3;
			uint32_t vpr1:1;
			uint32_t vlanrdctbln2:3;
			uint32_t vpr2:1;
			uint32_t vlanrdctbln3:3;
			uint32_t vpr3:1;
			uint32_t parity0:1;
			uint32_t parity1:1;
			uint32_t rsrvd:14;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} fflp_enet_vlan_tbl_t, *p_fflp_enet_vlan_tbl_t;

#define	FFLP_TCAM_CLS_BASE_OFFSET (FZC_FFLP + 0x20000)
#define	FFLP_L2_CLS_ENET1_REG	  (FZC_FFLP + 0x20000)
#define	FFLP_L2_CLS_ENET2_REG	  (FZC_FFLP + 0x20008)

typedef union _tcam_class_prg_ether_t {
#define	TCAM_ENET_USR_CLASS_ENABLE   0x1
#define	TCAM_ENET_USR_CLASS_DISABLE  0x0

    uint64_t value;
    struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#ifdef _BIT_FIELDS_HTOL
			uint32_t rsrvd:15;
			uint32_t valid:1;
			uint32_t etype:16;
#else
			uint32_t etype:16;
			uint32_t valid:1;
			uint32_t rsrvd:15;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} tcam_class_prg_ether_t, *p_tcam_class_prg_ether_t;

#define		FFLP_L3_CLS_IP_U4_REG	(FZC_FFLP + 0x20010)
#define		FFLP_L3_CLS_IP_U5_REG	(FZC_FFLP + 0x20018)
#define		FFLP_L3_CLS_IP_U6_REG	(FZC_FFLP + 0x20020)
#define		FFLP_L3_CLS_IP_U7_REG	(FZC_FFLP + 0x20028)

typedef union _tcam_class_prg_ip_t {
#define	TCAM_IP_USR_CLASS_ENABLE   0x1
#define	TCAM_IP_USR_CLASS_DISABLE  0x0

    uint64_t value;
    struct {
#if	defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#ifdef _BIT_FIELDS_HTOL
			uint32_t rsrvd:6;
			uint32_t valid:1;
			uint32_t ipver:1;
			uint32_t pid:8;
			uint32_t tosmask:8;
			uint32_t tos:8;
#else
			uint32_t tos:8;
			uint32_t tosmask:8;
			uint32_t pid:8;
			uint32_t ipver:1;
			uint32_t valid:1;
			uint32_t rsrvd:6;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} tcam_class_prg_ip_t, *p_tcam_class_prg_ip_t;

/*
 * New fields added to the L3 programmable class register for RF-NIU
 * and Neptune-L.
 */
#define	L3_UCLS_TOS_SH		0
#define	L3_UCLS_TOS_MSK		0xff
#define	L3_UCLS_TOSM_SH		8
#define	L3_UCLS_TOSM_MSK	0xff
#define	L3_UCLS_PID_SH		16
#define	L3_UCLS_PID_MSK		0xff
#define	L3_UCLS_VALID_SH	25
#define	L3_UCLS_VALID_MSK	0x01
#define	L3_UCLS_L4B23_SEL_SH	26
#define	L3_UCLS_L4B23_SEL_MSK	0x01
#define	L3_UCLS_L4B23_VAL_SH	27
#define	L3_UCLS_L4B23_VAL_MSK	0xffff
#define	L3_UCLS_L4B0_MASK_SH	43
#define	L3_UCLS_L4B0_MASK_MSK	0xff
#define	L3_UCLS_L4B0_VAL_SH	51
#define	L3_UCLS_L4B0_VAL_MSK	0xff
#define	L3_UCLS_L4_MODE_SH	59
#define	L3_UCLS_L4_MODE_MSK	0x01
/* define the classes which use the above structure */

typedef enum fflp_tcam_class {
    TCAM_CLASS_INVALID = 0,
    TCAM_CLASS_DUMMY = 1,
    TCAM_CLASS_ETYPE_1 = 2,
    TCAM_CLASS_ETYPE_2,
    TCAM_CLASS_IP_USER_4,
    TCAM_CLASS_IP_USER_5,
    TCAM_CLASS_IP_USER_6,
    TCAM_CLASS_IP_USER_7,
    TCAM_CLASS_TCP_IPV4,
    TCAM_CLASS_UDP_IPV4,
    TCAM_CLASS_AH_ESP_IPV4,
    TCAM_CLASS_SCTP_IPV4,
    TCAM_CLASS_TCP_IPV6,
    TCAM_CLASS_UDP_IPV6,
    TCAM_CLASS_AH_ESP_IPV6,
    TCAM_CLASS_SCTP_IPV6,
    TCAM_CLASS_ARP,
    TCAM_CLASS_RARP,
    TCAM_CLASS_DUMMY_12,
    TCAM_CLASS_DUMMY_13,
    TCAM_CLASS_DUMMY_14,
    TCAM_CLASS_DUMMY_15,
    TCAM_CLASS_IPV6_FRAG = 0x1F
} tcam_class_t;

#define	TCAM_CLASS_MAX	TCAM_CLASS_IPV6_FRAG

/*
 * Specify how to build TCAM key for L3
 * IP Classes. Both User configured and
 * hardwired IP services are included.
 * These are the supported 12 classes.
 */
#define		FFLP_TCAM_KEY_BASE_OFFSET	(FZC_FFLP + 0x20030)
#define		FFLP_TCAM_KEY_IP_USR4_REG		(FZC_FFLP + 0x20030)
#define		FFLP_TCAM_KEY_IP_USR5_REG		(FZC_FFLP + 0x20038)
#define		FFLP_TCAM_KEY_IP_USR6_REG		(FZC_FFLP + 0x20040)
#define		FFLP_TCAM_KEY_IP_USR7_REG		(FZC_FFLP + 0x20048)
#define		FFLP_TCAM_KEY_IP4_TCP_REG		(FZC_FFLP + 0x20050)
#define		FFLP_TCAM_KEY_IP4_UDP_REG		(FZC_FFLP + 0x20058)
#define		FFLP_TCAM_KEY_IP4_AH_ESP_REG	(FZC_FFLP + 0x20060)
#define		FFLP_TCAM_KEY_IP4_SCTP_REG		(FZC_FFLP + 0x20068)
#define		FFLP_TCAM_KEY_IP6_TCP_REG		(FZC_FFLP + 0x20070)
#define		FFLP_TCAM_KEY_IP6_UDP_REG		(FZC_FFLP + 0x20078)
#define		FFLP_TCAM_KEY_IP6_AH_ESP_REG	(FZC_FFLP + 0x20080)
#define		FFLP_TCAM_KEY_IP6_SCTP_REG		(FZC_FFLP + 0x20088)


typedef union _tcam_class_key_ip_t {
    uint64_t value;
    struct {
#if	defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#ifdef _BIT_FIELDS_HTOL
			uint32_t rsrvd2:28;
			uint32_t discard:1;
			uint32_t tsel:1;
			uint32_t rsrvd:1;
			uint32_t ipaddr:1;
#else
			uint32_t ipaddr:1;
			uint32_t rsrvd:1;
			uint32_t tsel:1;
			uint32_t discard:1;
			uint32_t rsrvd2:28;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} tcam_class_key_ip_t, *p_tcam_class_key_ip_t;



#define	FFLP_TCAM_KEY_0_REG			(FZC_FFLP + 0x20090)
#define	FFLP_TCAM_KEY_1_REG		(FZC_FFLP + 0x20098)
#define	FFLP_TCAM_KEY_2_REG		(FZC_FFLP + 0x200A0)
#define	FFLP_TCAM_KEY_3_REG	(FZC_FFLP + 0x200A8)
#define	FFLP_TCAM_MASK_0_REG	(FZC_FFLP + 0x200B0)
#define	FFLP_TCAM_MASK_1_REG	(FZC_FFLP + 0x200B8)
#define	FFLP_TCAM_MASK_2_REG	(FZC_FFLP + 0x200C0)
#define	FFLP_TCAM_MASK_3_REG	(FZC_FFLP + 0x200C8)

#define		FFLP_TCAM_CTL_REG		(FZC_FFLP + 0x200D0)

/* bit defines for FFLP_TCAM_CTL register */
#define	   TCAM_CTL_TCAM_WR		  0x0ULL
#define	   TCAM_CTL_TCAM_RD		  0x040000ULL
#define	   TCAM_CTL_TCAM_CMP		  0x080000ULL
#define	   TCAM_CTL_RAM_WR		  0x100000ULL
#define	   TCAM_CTL_RAM_RD		  0x140000ULL
#define	   TCAM_CTL_RWC_STAT		  0x0020000ULL
#define	   TCAM_CTL_RWC_MATCH		  0x0010000ULL


typedef union _tcam_ctl_t {
#define	TCAM_CTL_RWC_TCAM_WR	0x0
#define	TCAM_CTL_RWC_TCAM_RD	0x1
#define	TCAM_CTL_RWC_TCAM_CMP	0x2
#define	TCAM_CTL_RWC_RAM_WR	0x4
#define	TCAM_CTL_RWC_RAM_RD	0x5
#define	TCAM_CTL_RWC_RWC_STAT	0x1
#define	TCAM_CTL_RWC_RWC_MATCH	0x1

	uint64_t value;
	struct {
#if	defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#ifdef _BIT_FIELDS_HTOL
			uint32_t rsrvd2:11;
			uint32_t rwc:3;
			uint32_t stat:1;
			uint32_t match:1;
			uint32_t rsrvd:6;
			uint32_t location:10;
#else
			uint32_t location:10;
			uint32_t rsrvd:6;
			uint32_t match:1;
			uint32_t stat:1;
			uint32_t rwc:3;
			uint32_t rsrvd2:11;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} tcam_ctl_t, *p_tcam_ctl_t;



/* Bit defines for TCAM ASC RAM */


typedef union _tcam_res_t {
	uint64_t value;
	struct {
#if	defined(_BIG_ENDIAN)
		struct {
			uint32_t rsrvd:22;
			uint32_t syndrome:10;
		} hdw;
#endif
		struct {
#ifdef _BIT_FIELDS_HTOL
			uint32_t syndrome:6;
			uint32_t zfid:12;
			uint32_t v4_ecc_ck:1;
			uint32_t disc:1;
			uint32_t tres:2;
			uint32_t rdctbl:3;
			uint32_t offset:5;
			uint32_t zfld:1;
			uint32_t age:1;
#else
			uint32_t age:1;
			uint32_t zfld:1;
			uint32_t offset:5;
			uint32_t rdctbl:3;
			uint32_t tres:2;
			uint32_t disc:1;
			uint32_t v4_ecc_ck:1;
			uint32_t zfid:12;
			uint32_t syndrome:6;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		struct {
			uint32_t syndrome:10;
			uint32_t rsrvd:22;
		} hdw;
#endif
	} bits;
} tcam_res_t, *p_tcam_res_t;



#define	TCAM_ASC_DATA_AGE		0x0000000000000001ULL
#define	TCAM_ASC_DATA_AGE_SHIFT		0x0
#define	TCAM_ASC_DATA_ZFVLD		0x0000000000000002ULL
#define	TCAM_ASC_DATA_ZFVLD_SHIFT	1

#define	TCAM_ASC_DATA_OFFSET_MASK	0x000000000000007CULL
#define	TCAM_ASC_DATA_OFFSET_SHIFT	2

#define	TCAM_ASC_DATA_RDCTBL_MASK	0x0000000000000038ULL
#define	TCAM_ASC_DATA_RDCTBL_SHIFT	7
#define	TCAM_ASC_DATA_TRES_MASK		0x0000000000000C00ULL
#define	TRES_CONT_USE_L2RDC		0x00
#define	TRES_TERM_USE_OFFSET		0x01
#define	TRES_CONT_OVRD_L2RDC		0x02
#define	TRES_TERM_OVRD_L2RDC		0x03

#define	TCAM_ASC_DATA_TRES_SHIFT	10
#define	TCAM_TRES_CONT_USE_L2RDC	\
		(0x0000000000000000ULL << TCAM_ASC_DATA_TRES_SHIFT)
#define	TCAM_TRES_TERM_USE_OFFSET	\
		(0x0000000000000001ULL << TCAM_ASC_DATA_TRES_SHIFT)
#define	TCAM_TRES_CONT_OVRD_L2RDC	\
		(0x0000000000000002ULL << TCAM_ASC_DATA_TRES_SHIFT)
#define	TCAM_TRES_TERM_OVRD_L2RDC	\
		(0x0000000000000003ULL << TCAM_ASC_DATA_TRES_SHIFT)

#define	TCAM_ASC_DATA_DISC_MASK		0x0000000000001000ULL
#define	TCAM_ASC_DATA_DISC_SHIFT	12
#define	TCAM_ASC_DATA_V4_ECC_OK_MASK    0x0000000000002000ULL
#define	TCAM_ASC_DATA_V4_ECC_OK_SHIFT	13
#define	TCAM_ASC_DATA_V4_ECC_OK		\
		(0x0000000000000001ULL << TCAM_ASC_DATA_V4_ECC_OK_MASK_SHIFT)

#define	TCAM_ASC_DATA_ZFID_MASK		0x0000000003FF3000ULL
#define	TCAM_ASC_DATA_ZFID_SHIFT	14
#define	TCAM_ASC_DATA_ZFID(value)	\
		((value & TCAM_ASC_DATA_ZFID_MASK) >> TCAM_ASC_DATA_ZFID_SHIFT)

#define	TCAM_ASC_DATA_SYNDR_MASK	0x000003FFF3000000ULL
#define	TCAM_ASC_DATA_SYNDR_SHIFT	26
#define	TCAM_ASC_DATA_SYNDR(value)  \
	((value & TCAM_ASC_DATA_SYNDR_MASK) >> TCAM_ASC_DATA_SYNDR_SHIFT)


	/* error registers */

#define	FFLP_VLAN_PAR_ERR_REG		(FZC_FFLP + 0x08000)

typedef union _vlan_par_err_t {
    uint64_t value;
    struct {
#if	defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#ifdef _BIT_FIELDS_HTOL
			uint32_t err:1;
			uint32_t m_err:1;
			uint32_t addr:12;
			uint32_t data:18;
#else
			uint32_t data:18;
			uint32_t addr:12;
			uint32_t m_err:1;
			uint32_t err:1;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} vlan_par_err_t, *p_vlan_par_err_t;


#define		FFLP_TCAM_ERR_REG		(FZC_FFLP + 0x200D8)

typedef union _tcam_err_t {
    uint64_t value;
    struct {
#if	defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#ifdef _BIT_FIELDS_HTOL
			uint32_t err:1;
			uint32_t p_ecc:1;
			uint32_t mult:1;
			uint32_t rsrvd:5;
			uint32_t addr:8;
			uint32_t syndrome:16;
#else
			uint32_t syndrome:16;
			uint32_t addr:8;
			uint32_t rsrvd:5;
			uint32_t mult:1;
			uint32_t p_ecc:1;
			uint32_t err:1;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} tcam_err_t, *p_tcam_err_t;


#define		TCAM_ERR_SYNDROME_MASK		0x000000000000FFFFULL
#define		TCAM_ERR_MULT_SHIFT		29
#define		TCAM_ERR_MULT			0x0000000020000000ULL
#define		TCAM_ERR_P_ECC			0x0000000040000000ULL
#define		TCAM_ERR_ERR			0x0000000080000000ULL

#define		HASH_LKUP_ERR_LOG1_REG		(FZC_FFLP + 0x200E0)
#define		HASH_LKUP_ERR_LOG2_REG		(FZC_FFLP + 0x200E8)



typedef union _hash_lookup_err_log1_t {
    uint64_t value;
    struct {
#if	defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#ifdef _BIT_FIELDS_HTOL
			uint32_t rsrvd:28;
			uint32_t ecc_err:1;
			uint32_t mult_lk:1;
			uint32_t cu:1;
			uint32_t mult_bit:1;
#else
			uint32_t mult_bit:1;
			uint32_t cu:1;
			uint32_t mult_lk:1;
			uint32_t ecc_err:1;
			uint32_t rsrvd:28;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} hash_lookup_err_log1_t, *p_hash_lookup_err_log1_t;



typedef union _hash_lookup_err_log2_t {
    uint64_t value;
    struct {
#if	defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#ifdef _BIT_FIELDS_HTOL
			uint32_t rsrvd:1;
			uint32_t h1:20;
			uint32_t subarea:3;
			uint32_t syndrome:8;
#else
			uint32_t syndrome:8;
			uint32_t subarea:3;
			uint32_t h1:20;
			uint32_t rsrvd:1;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} hash_lookup_err_log2_t, *p_hash_lookup_err_log2_t;



#define		FFLP_FCRAM_ERR_TST0_REG	(FZC_FFLP + 0x20128)

typedef union _fcram_err_tst0_t {
    uint64_t value;
    struct {
#if	defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#ifdef _BIT_FIELDS_HTOL
			uint32_t rsrvd:24;
			uint32_t syndrome_mask:8;
#else
			uint32_t syndrome_mask:10;
			uint32_t rsrvd:24;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} fcram_err_tst0_t, *p_fcram_err_tst0_t;


#define		FFLP_FCRAM_ERR_TST1_REG	(FZC_FFLP + 0x20130)
#define		FFLP_FCRAM_ERR_TST2_REG	(FZC_FFLP + 0x20138)

typedef union _fcram_err_tst_t {
    uint64_t value;
    struct {
#if	defined(_BIG_ENDIAN)
		struct {
			uint32_t dat;
		} hdw;
#endif
		struct {
			uint32_t dat;
		} ldw;
#ifndef _BIG_ENDIAN
		struct {
			uint32_t dat;
		} hdw;
#endif
	} bits;
} fcram_err_tst1_t, *p_fcram_err_tst1_t,
	fcram_err_tst2_t, *p_fcram_err_tst2_t,
	fcram_err_data_t, *p_fcram_err_data_t;



#define		FFLP_ERR_MSK_REG	(FZC_FFLP + 0x20140)

typedef union _fflp_err_mask_t {
    uint64_t value;
    struct {
#if	defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#ifdef _BIT_FIELDS_HTOL
			uint32_t rsrvd:21;
			uint32_t hash_tbl_dat:8;
			uint32_t hash_tbl_lkup:1;
			uint32_t tcam:1;
			uint32_t vlan:1;
#else
			uint32_t vlan:1;
			uint32_t tcam:1;
			uint32_t hash_tbl_lkup:1;
			uint32_t hash_tbl_dat:8;
			uint32_t rsrvd:21;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} fflp_err_mask_t, *p_fflp_err_mask_t;

#define	FFLP_ERR_VLAN_MASK 0x00000001ULL
#define	FFLP_ERR_VLAN 0x00000001ULL
#define	FFLP_ERR_VLAN_SHIFT 0x0

#define	FFLP_ERR_TCAM_MASK 0x00000002ULL
#define	FFLP_ERR_TCAM 0x00000001ULL
#define	FFLP_ERR_TCAM_SHIFT 0x1

#define	FFLP_ERR_HASH_TBL_LKUP_MASK 0x00000004ULL
#define	FFLP_ERR_HASH_TBL_LKUP 0x00000001ULL
#define	FFLP_ERR_HASH_TBL_LKUP_SHIFT 0x2

#define	FFLP_ERR_HASH_TBL_DAT_MASK 0x00000007F8ULL
#define	FFLP_ERR_HASH_TBL_DAT 0x0000000FFULL
#define	FFLP_ERR_HASH_TBL_DAT_SHIFT 0x3

#define	FFLP_ERR_MASK_ALL (FFLP_ERR_VLAN_MASK | FFLP_ERR_TCAM_MASK | \
			    FFLP_ERR_HASH_TBL_LKUP_MASK | \
			    FFLP_ERR_HASH_TBL_DAT_MASK)


#define		FFLP_CFG_1_REG	(FZC_FFLP + 0x20100)

typedef union _fflp_cfg_1_t {
    uint64_t value;
    struct {
#if	defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#ifdef _BIT_FIELDS_HTOL
			uint32_t rsrvd:5;
			uint32_t tcam_disable:1;
			uint32_t pio_dbg_sel:3;
			uint32_t pio_fio_rst:1;
			uint32_t pio_fio_lat:2;
			uint32_t camlatency:4;
			uint32_t camratio:4;
			uint32_t fcramratio:4;
			uint32_t fcramoutdr:4;
			uint32_t fcramqs:1;
			uint32_t errordis:1;
			uint32_t fflpinitdone:1;
			uint32_t llcsnap:1;
#else
			uint32_t llcsnap:1;
			uint32_t fflpinitdone:1;
			uint32_t errordis:1;
			uint32_t fcramqs:1;
			uint32_t fcramoutdr:4;
			uint32_t fcramratio:4;
			uint32_t camratio:4;
			uint32_t camlatency:4;
			uint32_t pio_fio_lat:2;
			uint32_t pio_fio_rst:1;
			uint32_t pio_dbg_sel:3;
			uint32_t tcam_disable:1;
			uint32_t rsrvd:5;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} fflp_cfg_1_t, *p_fflp_cfg_1_t;


typedef	enum fflp_fcram_output_drive {
    FCRAM_OUTDR_NORMAL	= 0x0,
    FCRAM_OUTDR_STRONG	= 0x5,
    FCRAM_OUTDR_WEAK	= 0xa
} fflp_fcram_output_drive_t;


typedef	enum fflp_fcram_qs {
    FCRAM_QS_MODE_QS	= 0x0,
    FCRAM_QS_MODE_FREE	= 0x1
} fflp_fcram_qs_t;

#define		FCRAM_PIO_HIGH_PRI	0xf
#define		FCRAM_PIO_MED_PRI	0xa
#define		FCRAM_LOOKUP_HIGH_PRI	0x0
#define		FCRAM_LOOKUP_HIGH_PRI	0x0
#define		FCRAM_IO_DEFAULT_PRI	FCRAM_PIO_MED_PRI

#define		TCAM_PIO_HIGH_PRI	0xf
#define		TCAM_PIO_MED_PRI	0xa
#define		TCAM_LOOKUP_HIGH_PRI	0x0
#define		TCAM_LOOKUP_HIGH_PRI	0x0
#define		TCAM_IO_DEFAULT_PRI	TCAM_PIO_MED_PRI

#define		TCAM_DEFAULT_LATENCY	0x4


#define		FFLP_DBG_TRAIN_VCT_REG	(FZC_FFLP + 0x20148)

typedef union _fflp_dbg_train_vct_t {
    uint64_t value;
    struct {
#if	defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#ifdef _BIT_FIELDS_HTOL
			uint32_t vector;
#else
			uint32_t vector;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} fflp_dbg_train_vct_t, *p_fflp_dbg_train_vct_t;



#define		FFLP_TCP_CFLAG_MSK_REG	(FZC_FFLP + 0x20108)

typedef union _tcp_cflag_mask_t {
    uint64_t value;
    struct {
#if	defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#ifdef _BIT_FIELDS_HTOL
			uint32_t rsrvd:20;
			uint32_t mask:12;
#else
			uint32_t mask:12;
			uint32_t rsrvd:20;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} tcp_cflag_mask_t, *p_tcp_cflag_mask_t;



#define		FFLP_FCRAM_REF_TMR_REG		(FZC_FFLP + 0x20110)


typedef union _fcram_ref_tmr_t {
#define		FCRAM_REFRESH_DEFAULT_MAX_TIME	0x200
#define		FCRAM_REFRESH_DEFAULT_MIN_TIME	0x200
#define		FCRAM_REFRESH_DEFAULT_SYS_TIME	0x200
#define		FCRAM_REFRESH_MAX_TICK		39 /* usecs */
#define		FCRAM_REFRESH_MIN_TICK		400 /* nsecs */

    uint64_t value;
    struct {
#if	defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#ifdef _BIT_FIELDS_HTOL
			uint32_t max:16;
			uint32_t min:16;
#else
			uint32_t min:16;
			uint32_t max:16;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} fcram_ref_tmr_t, *p_fcram_ref_tmr_t;




#define		FFLP_FCRAM_FIO_ADDR_REG	(FZC_FFLP + 0x20118)

typedef union _fcram_fio_addr_t {
    uint64_t value;
    struct {
#if	defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#ifdef _BIT_FIELDS_HTOL
			uint32_t rsrvd:22;
			uint32_t addr:10;
#else
			uint32_t addr:10;
			uint32_t rsrvd:22;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} fcram_fio_addr_t, *p_fcram_fio_addr_t;


#define		FFLP_FCRAM_FIO_DAT_REG	(FZC_FFLP + 0x20120)

typedef union _fcram_fio_dat_t {
    uint64_t value;
    struct {
#if	defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#ifdef _BIT_FIELDS_HTOL
			uint32_t rsrvd:22;
			uint32_t addr:10;
#else
			uint32_t addr:10;
			uint32_t rsrvd:22;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} fcram_fio_dat_t, *p_fcram_fio_dat_t;


#define	FFLP_FCRAM_PHY_RD_LAT_REG	(FZC_FFLP + 0x20150)

typedef union _fcram_phy_rd_lat_t {
	uint64_t value;
	struct {
#if	defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#ifdef _BIT_FIELDS_HTOL
			uint32_t rsrvd:24;
			uint32_t lat:8;
#else
			uint32_t lat:8;
			uint32_t rsrvd:24;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} fcram_phy_rd_lat_t, *p_fcram_phy_rd_lat_t;


/*
 * Specify how to build a flow key for IP
 * classes, both programmable and hardwired
 */
#define		FFLP_FLOW_KEY_BASE_OFFSET		(FZC_FFLP + 0x40000)
#define		FFLP_FLOW_KEY_IP_USR4_REG		(FZC_FFLP + 0x40000)
#define		FFLP_FLOW_KEY_IP_USR5_REG		(FZC_FFLP + 0x40008)
#define		FFLP_FLOW_KEY_IP_USR6_REG		(FZC_FFLP + 0x40010)
#define		FFLP_FLOW_KEY_IP_USR7_REG		(FZC_FFLP + 0x40018)
#define		FFLP_FLOW_KEY_IP4_TCP_REG		(FZC_FFLP + 0x40020)
#define		FFLP_FLOW_KEY_IP4_UDP_REG		(FZC_FFLP + 0x40028)
#define		FFLP_FLOW_KEY_IP4_AH_ESP_REG	(FZC_FFLP + 0x40030)
#define		FFLP_FLOW_KEY_IP4_SCTP_REG		(FZC_FFLP + 0x40038)
#define		FFLP_FLOW_KEY_IP6_TCP_REG		(FZC_FFLP + 0x40040)
#define		FFLP_FLOW_KEY_IP6_UDP_REG		(FZC_FFLP + 0x40048)
#define		FFLP_FLOW_KEY_IP6_AH_ESP_REG	(FZC_FFLP + 0x40050)
#define		FFLP_FLOW_KEY_IP6_SCTP_REG		(FZC_FFLP + 0x40058)
/*
 * New FLOW KEY register added for IPV6 Fragments for RF-NIU
 * and Neptune-L.
 */
#define		FFLP_FLOW_KEY_IP6_FRAG_REG		(FZC_FFLP + 0x400B0)

#define	FL_KEY_USR_L4XOR_MSK	0x03ff

typedef union _flow_class_key_ip_t {
    uint64_t value;
    struct {
#if	defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#ifdef _BIT_FIELDS_HTOL
			uint32_t rsrvd2:10;
/* These bits added for L3 programmable classes in RF-NIU and Neptune-L */
			uint32_t l4_xor:10;
			uint32_t l4_mode:1;
/* This bit added for SNORT support in RF-NIU and Neptune-L */
			uint32_t sym:1;
			uint32_t port:1;
			uint32_t l2da:1;
			uint32_t vlan:1;
			uint32_t ipsa:1;
			uint32_t ipda:1;
			uint32_t proto:1;
			uint32_t l4_0:2;
			uint32_t l4_1:2;
#else
			uint32_t l4_1:2;
			uint32_t l4_0:2;
			uint32_t proto:1;
			uint32_t ipda:1;
			uint32_t ipsa:1;
			uint32_t vlan:1;
			uint32_t l2da:1;
			uint32_t port:1;
			uint32_t sym:1;
			uint32_t l4_mode:1;
			uint32_t l4_xor:10;
			uint32_t rsrvd2:10;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} flow_class_key_ip_t, *p_flow_class_key_ip_t;

#define		FFLP_H1POLY_REG		(FZC_FFLP + 0x40060)


typedef union _hash_h1poly_t {
    uint64_t value;
    struct {
#if	defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
			uint32_t init_value;
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} hash_h1poly_t, *p_hash_h1poly_t;

#define		FFLP_H2POLY_REG		(FZC_FFLP + 0x40068)

typedef union _hash_h2poly_t {
    uint64_t value;
    struct {
#if	defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#ifdef _BIT_FIELDS_HTOL
			uint32_t rsrvd:16;
			uint32_t init_value:16;
#else
			uint32_t init_value:16;
			uint32_t rsrvd:16;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} hash_h2poly_t, *p_hash_h2poly_t;

#define		FFLP_FLW_PRT_SEL_REG		(FZC_FFLP + 0x40070)


typedef union _flow_prt_sel_t {
#define		FFLP_FCRAM_MAX_PARTITION	8
    uint64_t value;
    struct {
#if	defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#ifdef _BIT_FIELDS_HTOL
			uint32_t rsrvd3:15;
			uint32_t ext:1;
			uint32_t rsrvd2:3;
			uint32_t mask:5;
			uint32_t rsrvd:3;
			uint32_t base:5;
#else
			uint32_t base:5;
			uint32_t rsrvd:3;
			uint32_t mask:5;
			uint32_t rsrvd2:3;
			uint32_t ext:1;
			uint32_t rsrvd3:15;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} flow_prt_sel_t, *p_flow_prt_sel_t;



/* FFLP Offsets */


#define		FFLP_HASH_TBL_ADDR_REG		(FFLP + 0x00000)

typedef union _hash_tbl_addr_t {
    uint64_t value;
    struct {
#if	defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#ifdef _BIT_FIELDS_HTOL
			uint32_t rsrvd:8;
			uint32_t autoinc:1;
			uint32_t addr:23;
#else
			uint32_t addr:23;
			uint32_t autoinc:1;
			uint32_t rsrvd:8;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} hash_tbl_addr_t, *p_hash_tbl_addr_t;


#define		FFLP_HASH_TBL_DATA_REG		(FFLP + 0x00008)

typedef union _hash_tbl_data_t {
    uint64_t value;
    struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
		uint32_t ldw;
#else
		uint32_t ldw;
		uint32_t hdw;
#endif
	} bits;
} hash_tbl_data_t, *p_hash_tbl_data_t;


#define		FFLP_HASH_TBL_DATA_LOG_REG		(FFLP + 0x00010)


typedef union _hash_tbl_data_log_t {
    uint64_t value;
    struct {
#if	defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#ifdef _BIT_FIELDS_HTOL
			uint32_t pio_err:1;
			uint32_t fcram_addr:23;
			uint32_t syndrome:8;
#else
			uint32_t syndrome:8;
			uint32_t fcram_addr:23;
			uint32_t pio_err:1;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} hash_tbl_data_log_t, *p_hash_tbl_data_log_t;



#define	REG_PIO_WRITE64(handle, offset, value) \
		NXGE_REG_WR64((handle), (offset), (value))
#define	REG_PIO_READ64(handle, offset, val_p) \
		NXGE_REG_RD64((handle), (offset), (val_p))


#define	WRITE_TCAM_REG_CTL(handle, ctl) \
		REG_PIO_WRITE64(handle, FFLP_TCAM_CTL_REG, ctl)

#define	READ_TCAM_REG_CTL(handle, val_p) \
		REG_PIO_READ64(handle, FFLP_TCAM_CTL_REG, val_p)


#define	WRITE_TCAM_REG_KEY0(handle, key)	\
		REG_PIO_WRITE64(handle,  FFLP_TCAM_KEY_0_REG, key)
#define	WRITE_TCAM_REG_KEY1(handle, key) \
		REG_PIO_WRITE64(handle,  FFLP_TCAM_KEY_1_REG, key)
#define	WRITE_TCAM_REG_KEY2(handle, key) \
		REG_PIO_WRITE64(handle,  FFLP_TCAM_KEY_2_REG, key)
#define	WRITE_TCAM_REG_KEY3(handle, key) \
		REG_PIO_WRITE64(handle,  FFLP_TCAM_KEY_3_REG, key)
#define	WRITE_TCAM_REG_MASK0(handle, mask)   \
		REG_PIO_WRITE64(handle,  FFLP_TCAM_MASK_0_REG, mask)
#define	WRITE_TCAM_REG_MASK1(handle, mask)   \
		REG_PIO_WRITE64(handle,  FFLP_TCAM_MASK_1_REG, mask)
#define	WRITE_TCAM_REG_MASK2(handle, mask)   \
		REG_PIO_WRITE64(handle,  FFLP_TCAM_MASK_2_REG, mask)
#define	WRITE_TCAM_REG_MASK3(handle, mask)   \
		REG_PIO_WRITE64(handle,  FFLP_TCAM_MASK_3_REG, mask)

#define	READ_TCAM_REG_KEY0(handle, val_p)	\
		REG_PIO_READ64(handle,  FFLP_TCAM_KEY_0_REG, val_p)
#define	READ_TCAM_REG_KEY1(handle, val_p)	\
		REG_PIO_READ64(handle,  FFLP_TCAM_KEY_1_REG, val_p)
#define	READ_TCAM_REG_KEY2(handle, val_p)	\
		REG_PIO_READ64(handle,  FFLP_TCAM_KEY_2_REG, val_p)
#define	READ_TCAM_REG_KEY3(handle, val_p)	\
		REG_PIO_READ64(handle,  FFLP_TCAM_KEY_3_REG, val_p)
#define	READ_TCAM_REG_MASK0(handle, val_p)	\
		REG_PIO_READ64(handle,  FFLP_TCAM_MASK_0_REG, val_p)
#define	READ_TCAM_REG_MASK1(handle, val_p)	\
		REG_PIO_READ64(handle,  FFLP_TCAM_MASK_1_REG, val_p)
#define	READ_TCAM_REG_MASK2(handle, val_p)	\
		REG_PIO_READ64(handle,  FFLP_TCAM_MASK_2_REG, val_p)
#define	READ_TCAM_REG_MASK3(handle, val_p)	\
		REG_PIO_READ64(handle,  FFLP_TCAM_MASK_3_REG, val_p)




typedef struct tcam_ipv4 {
#if defined(_BIG_ENDIAN)
	uint32_t	reserved6;		/* 255 : 224 */
	uint32_t	reserved5 : 24;		/* 223 : 200 */
	uint32_t	cls_code : 5;		/* 199 : 195 */
	uint32_t	reserved4 : 3;		/* 194 : 192 */
	uint32_t	l2rd_tbl_num : 5;	/* 191: 187  */
	uint32_t	noport : 1;		/* 186 */
	uint32_t	reserved3 : 26;		/* 185: 160  */
	uint32_t	reserved2;		/* 159: 128  */
	uint32_t	reserved : 16;		/* 127 : 112 */
	uint32_t	tos : 8;		/* 111 : 104 */
	uint32_t	proto : 8;		/* 103 : 96  */
	uint32_t	l4_port_spi;		/* 95 : 64   */
	uint32_t	ip_src;			/* 63 : 32   */
	uint32_t	ip_dest;		/* 31 : 0    */
#else
	uint32_t	ip_dest;		/* 31 : 0    */
	uint32_t	ip_src;			/* 63 : 32   */
	uint32_t	l4_port_spi;		/* 95 : 64   */
	uint32_t	proto : 8;		/* 103 : 96  */
	uint32_t	tos : 8;		/* 111 : 104 */
	uint32_t	reserved : 16;		/* 127 : 112 */
	uint32_t	reserved2;		/* 159: 128  */
	uint32_t	reserved3 : 26;		/* 185: 160  */
	uint32_t	noport : 1;		/* 186	*/
	uint32_t	l2rd_tbl_num : 5;	/* 191: 187  */
	uint32_t	reserved4 : 3;		/* 194 : 192 */
	uint32_t	cls_code : 5;		/* 199 : 195 */
	uint32_t	reserved5 : 24;		/* 223 : 200 */
	uint32_t	reserved6;		/* 255 : 224 */
#endif
} tcam_ipv4_t;



typedef struct tcam_reg {
#if defined(_BIG_ENDIAN)
    uint64_t		reg0;
    uint64_t		reg1;
    uint64_t		reg2;
    uint64_t		reg3;
#else
    uint64_t		reg3;
    uint64_t		reg2;
    uint64_t		reg1;
    uint64_t		reg0;
#endif
} tcam_reg_t;


typedef struct tcam_ether {
#if defined(_BIG_ENDIAN)
	uint8_t		reserved3[7];		/* 255 : 200 */
	uint8_t		cls_code : 5;		/* 199 : 195 */
	uint8_t		reserved2 : 3;		/* 194 : 192 */
	uint8_t		ethframe[11];		/* 191 : 104 */
	uint8_t		reserved[13];		/* 103 : 0   */
#else
	uint8_t		reserved[13];		/* 103 : 0   */
	uint8_t		ethframe[11];		/* 191 : 104 */
	uint8_t		reserved2 : 3;		/* 194 : 192 */
	uint8_t		cls_code : 5;		/* 199 : 195 */
	uint8_t		reserved3[7];		/* 255 : 200 */
#endif
} tcam_ether_t;


typedef struct tcam_ipv6 {
#if defined(_BIG_ENDIAN)
	uint32_t	reserved4;		/* 255 : 224 */
	uint32_t	reserved3 : 24;		/* 223 : 200 */
	uint32_t	cls_code : 5;		/* 199 : 195 */
	uint32_t	reserved2 : 3;		/* 194 : 192 */
	uint32_t	l2rd_tbl_num : 5;	/* 191: 187  */
	uint32_t	noport : 1;		/* 186  */
	uint32_t	reserved : 10;		/* 185 : 176 */
	uint32_t	tos : 8;		/* 175 : 168 */
	uint32_t	nxt_hdr : 8;		/* 167 : 160 */
	uint32_t	l4_port_spi;		/* 159 : 128 */
	uint32_t	ip_addr[4];		/* 127 : 0   */
#else
	uint32_t	ip_addr[4];		/* 127 : 0   */
	uint32_t	l4_port_spi;		/* 159 : 128 */
	uint32_t	nxt_hdr : 8;		/* 167 : 160 */
	uint32_t	tos : 8;		/* 175 : 168 */
	uint32_t	reserved : 10;		/* 185 : 176 */
	uint32_t	noport : 1;		/* 186 */
	uint32_t	l2rd_tbl_num : 5;	/* 191: 187  */
	uint32_t	reserved2 : 3;		/* 194 : 192 */
	uint32_t	cls_code : 5;		/* 199 : 195 */
	uint32_t	reserved3 : 24;		/* 223 : 200 */
	uint32_t	reserved4;		/* 255 : 224 */
#endif
} tcam_ipv6_t;


typedef struct tcam_entry {
    union  _tcam_entry {
	tcam_reg_t	   regs_e;
	tcam_ether_t	   ether_e;
	tcam_ipv4_t	   ipv4_e;
	tcam_ipv6_t	   ipv6_e;
	} key, mask;
	tcam_res_t	match_action;
} tcam_entry_t;


#define		key_reg0		key.regs_e.reg0
#define		key_reg1		key.regs_e.reg1
#define		key_reg2		key.regs_e.reg2
#define		key_reg3		key.regs_e.reg3
#define		mask_reg0		mask.regs_e.reg0
#define		mask_reg1		mask.regs_e.reg1
#define		mask_reg2		mask.regs_e.reg2
#define		mask_reg3		mask.regs_e.reg3


#define		key0			key.regs_e.reg0
#define		key1			key.regs_e.reg1
#define		key2			key.regs_e.reg2
#define		key3			key.regs_e.reg3
#define		mask0			mask.regs_e.reg0
#define		mask1			mask.regs_e.reg1
#define		mask2			mask.regs_e.reg2
#define		mask3			mask.regs_e.reg3


#define		ip4_src_key		key.ipv4_e.ip_src
#define		ip4_dest_key		key.ipv4_e.ip_dest
#define		ip4_proto_key		key.ipv4_e.proto
#define		ip4_port_key		key.ipv4_e.l4_port_spi
#define		ip4_tos_key		key.ipv4_e.tos
#define		ip4_noport_key		key.ipv4_e.noport
#define		ip4_nrdc_key		key.ipv4_e.l2rdc_tbl_num
#define		ip4_class_key		key.ipv4_e.cls_code

#define		ip4_src_mask		mask.ipv4_e.ip_src
#define		ip4_dest_mask		mask.ipv4_e.ip_dest
#define		ip4_proto_mask		mask.ipv4_e.proto
#define		ip4_port_mask		mask.ipv4_e.l4_port_spi
#define		ip4_tos_mask		mask.ipv4_e.tos
#define		ip4_nrdc_mask		mask.ipv4_e.l2rdc_tbl_num
#define		ip4_noport_mask		mask.ipv4_e.noport
#define		ip4_class_mask		mask.ipv4_e.cls_code


#define		ip6_ip_addr_key		key.ipv6_e.ip_addr
#define		ip6_port_key		key.ipv6_e.l4_port_spi
#define		ip6_nxt_hdr_key		key.ipv6_e.nxt_hdr
#define		ip6_tos_key		key.ipv6_e.tos
#define		ip6_nrdc_key		key.ipv6_e.l2rdc_tbl_num
#define		ip6_noport_key		key.ipv6_e.noport
#define		ip6_class_key		key.ipv6_e.cls_code


#define		ip6_ip_addr_mask	mask.ipv6_e.ip_addr
#define		ip6_port_mask		mask.ipv6_e.l4_port_spi
#define		ip6_nxt_hdr_mask	mask.ipv6_e.nxt_hdr
#define		ip6_tos_mask		mask.ipv6_e.tos
#define		ip6_nrdc_mask		mask.ipv6_e.l2rdc_tbl_num
#define		ip6_noport_mask		mask.ipv6_e.noport
#define		ip6_class_mask		mask.ipv6_e.cls_code

#define		ether_class_key		key.ether_e.cls_code
#define		ether_ethframe_key	key.ether_e.ethframe
#define		ether_class_mask	mask.ether_e.cls_code
#define		ether_ethframe_mask	mask.ether_e.ethframe


/*
 * flow template structure
 * The flow header is passed through the hash function
 * which generates the H1 (and the H2 ) hash value.
 * Hash computation is started at the 22 zeros.
 *
 * Since this structure uses the ip address fields,
 * /usr/include/netinet/in.h has to be included
 * before this header file.
 * Need to move these includes to impl files ...
 */

#include <netinet/in.h>

typedef union flow_template {

	struct {
#if defined(_BIG_ENDIAN)
		uint32_t l4_0:16;  /* src port */
		uint32_t l4_1:16;  /* dest Port */

		uint32_t pid:8;
		uint32_t port:2;
		uint32_t zeros:22; /* 0 */

		union {
			struct {
				struct in6_addr daddr;
				struct in6_addr saddr;
			} ip6_addr;

			struct  {
				uint32_t rsrvd1;
				struct in_addr daddr;
				uint32_t rsrvd2[3];
				struct in_addr saddr;
				uint32_t rsrvd5[2];
			} ip4_addr;
		} ipaddr;

		union {
			uint64_t l2_info;
			struct {
				uint32_t vlan_valid : 4;
				uint32_t l2da_1 : 28;
				uint32_t l2da_0 : 20;
				uint32_t vlanid : 12;

			}l2_bits;
		}l2;
#else

		uint32_t l4_1:16;  /* dest Port */
		uint32_t l4_0:16;  /* src port */

		uint32_t zeros:22; /* 0 */
		uint32_t port:2;
		uint32_t pid:8;

		union {
			struct {
				struct in6_addr daddr;
				struct in6_addr saddr;
			} ip6_addr;

			struct  {
				uint32_t rsrvd1;
				struct in_addr daddr;
				uint32_t rsrvd2[3];
				struct in_addr saddr;
				uint32_t rsrvd5[2];
			} ip4_addr;
		} ipaddr;

		union {
			uint64_t l2_info;
			struct {

				uint32_t l2da_1 : 28;
				uint32_t vlan_valid : 4;

				uint32_t vlanid : 12;
				uint32_t l2da_0 : 20;
			}l2_bits;
		}l2;
#endif
	} bits;

} flow_template_t;



#define	ip4_saddr bits.ipaddr.ip4_addr.saddr.s_addr
#define	ip4_daddr bits.ipaddr.ip4_addr.daddr.s_addr

#define	ip_src_port  bits.l4_0
#define	ip_dst_port  bits.l4_1
#define	ip_proto  bits.pid

#define	ip6_saddr bits.ipaddr.ip6_addr.saddr
#define	ip6_daddr bits.ipaddr.ip6_addr.daddr




typedef struct _flow_key_cfg_t {
    uint32_t rsrvd:11;
/* The following 3 bit fields added for RF-NIU and Neptune-L */
    uint32_t l4_xor_sel:10;
    uint32_t use_l4_md:1;
    uint32_t use_sym:1;
    uint32_t use_portnum:1;
    uint32_t use_l2da:1;
    uint32_t use_vlan:1;
    uint32_t use_saddr:1;
    uint32_t use_daddr:1;
    uint32_t use_sport:1;
    uint32_t use_dport:1;
    uint32_t use_proto:1;
    uint32_t ip_opts_exist:1;
} flow_key_cfg_t;


typedef struct _tcam_key_cfg_t {
    uint32_t rsrvd:28;
    uint32_t use_ip_daddr:1;
    uint32_t use_ip_saddr:1;
    uint32_t lookup_enable:1;
    uint32_t discard:1;
} tcam_key_cfg_t;



/*
 * FCRAM Entry Formats
 *
 * ip6 and ip4 entries, the first 64 bits layouts are identical
 * optimistic entry has only 64 bit layout
 * The first three bits, fmt, ext and valid are the same
 * accoross all the entries
 */

typedef union hash_optim {
    uint64_t value;
    struct _bits {
#if defined(_BIG_ENDIAN)
		uint32_t	fmt : 1;	/* 63  set to zero */
		uint32_t	ext : 1;	/* 62  set to zero */
		uint32_t	valid : 1;	/* 61 */
		uint32_t	rdc_offset : 5;	/* 60 : 56 */
		uint32_t	h2 : 16;	/* 55 : 40 */
		uint32_t	rsrvd : 8;	/* 32 : 32 */
		uint32_t	usr_info;	/* 31 : 0   */
#else
		uint32_t	usr_info;	/* 31 : 0   */
		uint32_t	rsrvd : 8;	/* 39 : 32  */
		uint32_t	h2 : 16;	/* 55 : 40  */
		uint32_t	rdc_offset : 5;	/* 60 : 56  */
		uint32_t	valid : 1;	/* 61 */
		uint32_t	ext : 1;	/* 62  set to zero */
		uint32_t	fmt : 1;	/* 63  set to zero */
#endif
	} bits;
} hash_optim_t;


typedef    union _hash_hdr {
    uint64_t value;
    struct _exact_hdr {
#if defined(_BIG_ENDIAN)
		uint32_t	fmt : 1;	/* 63  1 for ipv6, 0 for ipv4 */
		uint32_t	ext : 1;	/* 62  set to 1 */
		uint32_t	valid : 1;	/* 61 */
		uint32_t	rsrvd : 1;	/* 60 */
		uint32_t	l2da_1 : 28;	/* 59 : 32 */
		uint32_t	l2da_0 : 20;	/* 31 : 12 */
		uint32_t	vlan : 12;	/* 12 : 0   */
#else
		uint32_t	vlan : 12;	/* 12 : 0   */
		uint32_t	l2da_0 : 20;	/* 31 : 12 */
		uint32_t	l2da_1 : 28;	/* 59 : 32 */
		uint32_t	rsrvd : 1;	/* 60 */
		uint32_t	valid : 1;	/* 61 */
		uint32_t	ext : 1;	/* 62  set to 1 */
		uint32_t	fmt : 1;	/* 63  1 for ipv6, 0 for ipv4 */
#endif
	} exact_hdr;
    hash_optim_t optim_hdr;
} hash_hdr_t;



typedef    union _hash_ports {
    uint64_t value;
    struct _ports_bits {
#if defined(_BIG_ENDIAN)
		uint32_t	ip_dport : 16;	/* 63 : 48 */
		uint32_t	ip_sport : 16;	/* 47 : 32 */
		uint32_t	proto : 8;	/* 31 : 24 */
		uint32_t	port : 2;	/* 23 : 22 */
		uint32_t	rsrvd : 22;	/* 21 : 0   */
#else
		uint32_t	rsrvd : 22;	/* 21 : 0   */
		uint32_t	port : 2;	/* 23 : 22 */
		uint32_t	proto : 8;	/* 31 : 24 */
		uint32_t	ip_sport : 16;	/* 47 : 32 */
		uint32_t	ip_dport : 16;	/* 63 : 48 */
#endif
	} ports_bits;
} hash_ports_t;



typedef    union _hash_match_action {
    uint64_t value;
    struct _action_bits {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd2 : 3;	/* 63 : 61  */
		uint32_t	rdc_offset : 5;	/* 60 : 56 */
		uint32_t	zfvld : 1;	/* 55 */
		uint32_t	rsrvd : 3;	/* 54 : 52   */
		uint32_t	zfid : 12;	/* 51 : 40 */
		uint32_t	_rsrvd : 8;	/* 39 : 32 */
		uint32_t	usr_info;	/* 31 : 0   */
#else
		uint32_t	usr_info;	/* 31 : 0   */
		uint32_t	_rsrvd : 8;	/* 39 : 32  */
		uint32_t	zfid : 12;	/* 51 : 40 */
		uint32_t	rsrvd : 3;	/* 54 : 52   */
		uint32_t	zfvld : 1;	/* 55 */
		uint32_t	rdc_offset : 5;	/* 60 : 56 */
		uint32_t	rsrvd2 : 1;	/* 63 : 61  */
#endif
	} action_bits;
} hash_match_action_t;


typedef    struct _ipaddr6 {
    struct in6_addr	 saddr;
    struct in6_addr	 daddr;
} ip6_addr_t;


typedef    struct   _ipaddr4   {
#if defined(_BIG_ENDIAN)
    struct in_addr	saddr;
    struct in_addr	daddr;
#else
    struct in_addr	daddr;
    struct in_addr	saddr;
#endif
} ip4_addr_t;


	/* ipv4 has 32 byte layout */

typedef struct hash_ipv4 {
    hash_hdr_t		 hdr;
    ip4_addr_t		 ip_addr;
    hash_ports_t	 proto_ports;
    hash_match_action_t	 action;
} hash_ipv4_t;


	/* ipv4 has 56 byte layout */
typedef struct hash_ipv6 {
	hash_hdr_t	hdr;
    ip6_addr_t		  ip_addr;
    hash_ports_t	  proto_ports;
    hash_match_action_t	  action;
} hash_ipv6_t;



typedef union fcram_entry {
    uint64_t		  value[8];
    hash_tbl_data_t	  dreg[8];
    hash_ipv6_t		  ipv6_entry;
    hash_ipv4_t		  ipv4_entry;
    hash_optim_t	  optim_entry;
} fcram_entry_t;



#define	hash_hdr_fmt	ipv4_entry.hdr.exact_hdr.fmt
#define	hash_hdr_ext	ipv4_entry.hdr.exact_hdr.ext
#define	hash_hdr_valid	ipv4_entry.hdr.exact_hdr.valid

#define	HASH_ENTRY_EXACT(fc)	\
	(fc->ipv4_entry.hdr.exact_hdr.ext == 1)
#define	HASH_ENTRY_OPTIM(fc)	\
	((fc->ipv4_entry.hdr.exact_hdr.ext == 0) && \
	(fc->ipv6_entry.hdr.exact_hdr.fmt == 0))
#define	HASH_ENTRY_EXACT_IP6(fc) \
	((fc->ipv6_entry.hdr.exact_hdr.fmt == 1) && \
	(fc->ipv4_entry.hdr.exact_hdr.ext == 1))

#define	HASH_ENTRY_EXACT_IP4(fc) \
	((fc->ipv6_entry.hdr.exact_hdr.fmt == 0) && \
	(fc->ipv4_entry.hdr.exact_hdr.ext == 1))

#define	HASH_ENTRY_TYPE(fc)	\
	(fc->ipv4_entry.hdr.exact_hdr.ext | \
	(fc->ipv4_entry.hdr.exact_hdr.fmt << 1))



typedef enum fcram_entry_format {
	FCRAM_ENTRY_OPTIM = 0x0,
	FCRAM_ENTRY_EX_IP4 = 0x2,
	FCRAM_ENTRY_EX_IP6 = 0x3,
	FCRAM_ENTRY_UNKOWN = 0x1
} fcram_entry_format_t;


#define		HASH_ENTRY_TYPE_OPTIM		FCRAM_ENTRY_OPTIM
#define		HASH_ENTRY_TYPE_OPTIM_IP4	FCRAM_ENTRY_OPTIM
#define		HASH_ENTRY_TYPE_OPTIM_IP4	FCRAM_ENTRY_OPTIM
#define		HASH_ENTRY_TYPE_EX_IP4		FCRAM_ENTRY_EX_IP4
#define		HASH_ENTRY_TYPE_EX_IP6		FCRAM_ENTRY_EX_IP6




	/* error xxx formats */


typedef struct _hash_lookup_err_log {
    uint32_t rsrvd:28;
    uint32_t lookup_err:1;
    uint32_t ecc_err:1;
    uint32_t uncor_err:1;
    uint32_t multi_lkup:1;
    uint32_t multi_bit:1;
    uint32_t subarea:3;
    uint32_t syndrome:8;
    uint32_t h1:20;
} hash_lookup_err_log_t, *p_hash_lookup_err_log_t;



typedef struct _hash_pio_err_log {
    uint32_t rsrvd:32;
    uint32_t pio_err:1;
    uint32_t syndrome:8;
    uint32_t addr:23;
} hash_pio_err_log_t, *p_hash_pio_err_log_t;



typedef struct _tcam_err_log {
    uint32_t rsrvd:2;
    uint32_t tcam_err:1;
    uint32_t parity_err:1;
    uint32_t ecc_err:1;
    uint32_t multi_lkup:1;
    uint32_t location:8;
    uint32_t syndrome:16;
} tcam_err_log_t, *p_tcam_err_log_t;


typedef struct _vlan_tbl_err_log {
    uint32_t rsrvd:32;
    uint32_t err:1;
    uint32_t multi:1;
    uint32_t addr:12;
    uint32_t data:18;
} vlan_tbl_err_log_t, *p_vlan_tbl_err_log_t;


#define		NEPTUNE_TCAM_SIZE		0x100
#define		NIU_TCAM_SIZE			0x80
#define		FCRAM_SIZE			0x100000

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_NXGE_NXGE_FFLP_HW_H */
