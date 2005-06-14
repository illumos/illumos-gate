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
 * Copyright 2000-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_DR_MBX_H
#define	_SYS_DR_MBX_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL
#include <sys/mboxsc.h>
#endif /* _KERNEL */
#include <post/scat_const.h>

/* this version of the DR - SC mailbox interface */
#define	DRMBX_VERSION				0x0016

#define	DR_KEY(a, b, c, d)	\
	(((uint_t)(a) << 24) | ((uint_t)(b) << 16) \
	| ((uint_t)(c) <<  8) | ((uint_t)(d)))
#define	KEY_DRSC		DR_KEY('D', 'R', 'S', 'C')
#define	KEY_SCDR		DR_KEY('S', 'C', 'D', 'R')

#define	DRSC_TIMEOUT		30
#define	BD_TYPELEN		16
#define	DR_HPOPTLEN		512	/* maximum length of hpost options */

/* Commands */
#define	DRMSG_BOARDEVENT	0x1	/* must be 0x1 in every vesion */
#define	DRMSG_MBOX_INIT		0x2	/* must be 0x2 in every version */
#define	DRMSG_ASSIGN		0x3
#define	DRMSG_UNASSIGN		0x4
#define	DRMSG_CLAIM		0x5
#define	DRMSG_UNCLAIM		0x6
#define	DRMSG_POWERON		0x7
#define	DRMSG_POWEROFF		0x8
#define	DRMSG_TESTBOARD		0x9
#define	DRMSG_ABORT_TEST	0xa
#define	DRMSG_SHOWBOARD		0xb
#define	DRMSG_UNCONFIG		0xc


/* Test status definitions */
#define	DR_TEST_STATUS_UNKNOWN	0x1
#define	DR_TEST_STATUS_IPOST	0x2
#define	DR_TEST_STATUS_PASSED	0x3
#define	DR_TEST_STATUS_FAILED	0x4
#define	DR_TEST_STATUS_ABORTED	0x5

/* Message reply status definitions */
#define	DRMSG_REPLY_OK		0x0
#define	DRMSG_REPLY_FAIL	0x1

/* Error Code definitions */
#define	DRERR_NOACL		0x1	/* Board is not in domain's ACL */
#define	DRERR_NOT_ASSIGNED	0x2	/* Board isn't assigned to domain */
#define	DRERR_NOT_ACTIVE	0x3	/* Board is not active */
#define	DRERR_EMPTY_SLOT	0x4	/* The board (slot) is empty */
#define	DRERR_POWER_OFF		0x5	/* The specified board is powered off */
#define	DRERR_TEST_IN_PROGRESS	0x6	/* The board is being tested */
#define	DRERR_TESTING_BUSY	0x7	/* All SC test resources are in use */
#define	DRERR_TEST_REQUIRED	0x8	/* Board requires test prior to use */
#define	DRERR_UNAVAILABLE	0x9	/* Slot is not available to domain */
#define	DRERR_RECOVERABLE	0xa	/* Failed, may safely retry */
#define	DRERR_UNRECOVERABLE	0xb	/* Failed, resource unusable */

/*
 *	Protocol Header and message structure definitions
 */

/* DR-SC Protocol Header */
typedef struct {
	uint32_t	message_id;
	uint16_t	drproto_version;
	uint8_t		command;
	uint8_t		expbrd;
	uint8_t		slot;
	uint8_t		reply_status;
	uint8_t		error_code;
	uint8_t		pad[1];		/* explicit pad to 4 byte alignment */
} dr_proto_hdr_t;

/* Showboard reply structure (from SC) */
typedef struct {
	uint8_t		slot_empty	:1,
			power_on	:1,
			bd_assigned	:1,
			bd_active	:1,
			test_status	:4;
	uint8_t		test_level;
	char		board_type[BD_TYPELEN];
} dr_showboard_t;

/* CPU Memory Controller constants and macros */
#define	DRMACH_MC_VALID_MASK		(0x1ull		<< 63)
#define	DRMACH_MC_UK_MASK		(0xFFFull	<< 41)
#define	DRMACH_MC_UM_MASK		(0x1FFFFFull	<< 20)
#define	DRMACH_MC_LK_MASK		(0xFull		<< 14)
#define	DRMACH_MC_LM_MASK		(0xFull		<< 8)

#define	DRMACH_MC_UK(madr)		(((madr) & DRMACH_MC_UK_MASK) >> 41)
#define	DRMACH_MC_UM_TO_PA(madr)	(((madr) & DRMACH_MC_UM_MASK) << 6)
#define	DRMACH_MC_LM_TO_PA(madr)	(((madr) & DRMACH_MC_LM_MASK) >> 2)
#define	DRMACH_MC_PA_TO_UM(pa)		(((pa) >> 6) & DRMACH_MC_UM_MASK)
#define	DRMACH_MC_PA_TO_LM(pa)		(((pa) << 2) & DRMACH_MC_LM_MASK)

/* Claim/Unclaim/Unconfig request structures */
typedef struct {
	uint8_t	valid	:1,
		unused	:2,
		slice	:5;
} dr_memslice_t;

/*
 * Since uint64_t can't be used in DR mailbox messages due to alignment and
 * backwards compatibility issues, the 64 bit MADR and MACR register values must
 * be broken into high and low uint32_t values.
 */
#define	DRMACH_MCREG_TO_U64(mcreg)	(((uint64_t)mcreg.hi) << 32 | \
						((uint64_t)mcreg.lo))
#define	DRMACH_U64_TO_MCREGHI(u64)	((uint32_t)((u64) >> 32))
#define	DRMACH_U64_TO_MCREGLO(u64)	((uint32_t)(u64))
typedef struct {
	uint32_t	hi;
	uint32_t	lo;
} dr_mcreg_t;

/*
 * Each expander can contain S0_LPORT_COUNT memory controllers (each CPU has one
 * memory controller, and slot 1 doesn't support memory), and each controller
 * contains PMBANKS_PER_PORT * LMBANKS_PER_PMBANK (the total number of memory
 * banks supported by each controller) MADR registers
 */
typedef struct {
	dr_mcreg_t	madr[S0_LPORT_COUNT][PMBANKS_PER_PORT *
				LMBANKS_PER_PMBANK];
} dr_memregs_t;

typedef struct {
	dr_memslice_t	mem_slice[18];
	uint8_t		mem_clear;
	uint8_t		pad[1];		/* explicit pad to 4 byte alignment */
	dr_memregs_t	mem_regs[18];
} dr_unclaim_t;

typedef struct {
	dr_memslice_t	mem_slice[18];
	uint8_t		pad[2];		/* explicit pad to 4 byte alignment */
	dr_memregs_t	mem_regs[18];
} dr_claim_t;

typedef struct {
	dr_memslice_t	mem_slice[18];
	uint8_t		pad[2];		/* explicit pad to 4 byte alignment */
	dr_memregs_t	mem_regs[18];
} dr_unconfig_t;

/* CPU Portid macros */
#define	DRMBX_PORTID2EXP(cpu_portid) \
	(((cpu_portid) >> 5) & 0x1F)
#define	DRMBX_PORTID2SLOT(cpu_portid) \
	(((((cpu_portid) >> 4) & 0x7E) | (((cpu_portid) >> 3) & 0x01)) & 1)
#define	DRMBX_PORTID2AGID(cpu_portid)	((cpu_portid) & 0x1F)

/* Test board request structure */
typedef struct {
	uint32_t	memaddrhi;
	uint32_t	memaddrlo;
	uint32_t	memlen;
	uint16_t	cpu_portid;
	uint8_t		force		:1,
			immediate 	:1,
			reserved 	:6;
	char		hpost_opts[DR_HPOPTLEN];
} dr_testboard_req_t;

/* Test board reply structure (from SC) */
typedef struct {
	uint32_t	memaddrhi;
	uint32_t	memaddrlo;
	uint32_t	memlen;
	uint16_t	cpu_portid;
	uint8_t		cpu_recovered	:1,
			test_status 	:4,
			reserved 	:3;
} dr_testboard_reply_t;

/* Test Abort structure (bi-directional) */
typedef struct {
	uint32_t	memaddrhi;
	uint32_t	memaddrlo;
	uint32_t	memlen;
	uint16_t	cpu_portid;
} dr_abort_test_t;


/* Board event structure (from SC) */
typedef struct {
	uint16_t	initialized	:1,
			board_insertion	:1,
			board_removal	:1,
			slot_assign	:1,
			slot_unassign	:1,
			slot_avail	:1,
			slot_unavail	:1,
			power_on	:1,
			power_off	:1,
			reserved	:7;
} dr_boardevent_t;

/*
 * NOTE: The structures in this union all require 4 byte alignment or less.  It
 * is forbidden to add any structure that requires 8 byte alignment, as doing so
 * will alter the dr_mbox_msg_t structure, thereby breaking compatibility with
 * older software.  (Since the dr_proto_hdr_t structure is 12 bytes long, it
 * can't be followed immediately by an 8 byte aligned structure, and the
 * compiler will implicitly insert 4 padding bytes.)
 */
typedef union {
	dr_showboard_t		dm_sb;
	dr_unclaim_t		dm_ur;
	dr_claim_t		dm_cr;
	dr_unconfig_t		dm_uc;
	dr_testboard_req_t	dm_tb;
	dr_testboard_reply_t	dm_tr;
	dr_abort_test_t		dm_ta;
	dr_boardevent_t		dm_be;
} dr_msg_t;

typedef struct {
	dr_proto_hdr_t		p_hdr;
	dr_msg_t		msgdata;
} dr_mbox_msg_t;

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_DR_MBX_H */
