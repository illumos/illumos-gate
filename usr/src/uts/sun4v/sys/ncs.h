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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_NCS_H
#define	_SYS_NCS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * NCS HV API versioni definitions.
 */
#define	NCS_MAJOR_VER		1
#define	NCS_MINOR_VER		0

#define	HV_NCS_REQUEST		0x110

#ifndef _ASM
/* Forward typedefs */
typedef union ma_ctl		ma_ctl_t;
typedef union ma_mpa		ma_mpa_t;
typedef union ma_ma		ma_ma_t;
typedef uint64_t		ma_np_t;

/*
 * Modulare Arithmetic Unit (MA) control register definition.
 */
union ma_ctl {
	uint64_t	value;
	struct {
		uint64_t	reserved1:50;
		uint64_t	invert_parity:1;
		uint64_t	thread:2;
		uint64_t	busy:1;
		uint64_t	interrupt:1;
		uint64_t	operation:3;
		uint64_t	length:6;
	} bits;
};
#endif	/* !_ASM */

/* Values for ma_ctl operation field */
#define	MA_OP_LOAD		0x0
#define	MA_OP_STORE		0x1
#define	MA_OP_MULTIPLY		0x2
#define	MA_OP_REDUCE		0x3
#define	MA_OP_EXPONENTIATE	0x4

/* The MA memory is 1280 bytes (160 8 byte words) */
#define	MA_SIZE		1280
/* Make driver MA buffer the next power of 2 */
#define	MA_BUF_SIZE	2048

/* We can only load 64 8 byte words at a time */
#define	MA_LOAD_MAX	64

#ifndef _ASM
union ma_mpa {
	uint64_t	value;
	struct {
		uint64_t	reserved0:24;
		uint64_t	address:37;
		uint64_t	reserved1:3;
	} bits;
};

union ma_ma {
	uint64_t	value;
	struct {
		uint64_t	reserved0:16;
		uint64_t	address5:8;
		uint64_t	address4:8;
		uint64_t	address3:8;
		uint64_t	address2:8;
		uint64_t	address1:8;
		uint64_t	address0:8;
	} bits;
};

#endif	/* !_ASM */


/*
 * NCS API definitions
 */

#ifndef _ASM
#include <sys/mutex.h>
#endif	/* !_ASM */

/*
 * NCS API definitions
 */

/*
 * NCS Crtypo Function Numbers
 */
#define	NCS_QCONF		0x1
#define	NCS_QTAIL_UPDATE	0x2
/*
 * The following are parameters to the NCS_QTAIL_UPDATE call:
 *
 *      NCS_SYNC	Perform MA operations synchronously,
 *			i.e. wait for each enqueued operation
 *			to complete before progressing to
 *			next one.
 *      NCS_ASYNC	Perform MA operations asynchronously,
 *			i.e. kick off the next MA operation
 *			without waiting for its completion.
 *			XXX - not supported yet.
 */
#define	NCS_SYNC	0
#define	NCS_ASYNC	1

#ifndef _ASM
typedef struct ncs_qconf_arg {
	uint64_t	nq_mid;
	uint64_t	nq_base;
	uint64_t	nq_end;
	uint64_t	nq_nentries;
} ncs_qconf_arg_t;

typedef struct ncs_qtail_update_arg {
	uint64_t	nu_mid;
	uint64_t	nu_tail;
	uint64_t	nu_syncflag;
} ncs_qtail_update_arg_t;

/*
 * The interface to the MAU is via the following data structures. The
 * structure consists of a copy of all relevant registers required to perform
 * the requested operation.
 */
typedef struct ma_regs {
	union ma_ctl	mr_ctl;
	union ma_mpa	mr_mpa;
	union ma_ma	mr_ma;
	uint64_t	mr_np;
} ma_regs_t;

#define	ND_TYPE_UNASSIGNED	0
#define	ND_TYPE_MA		1
#define	ND_TYPE_SPU		2

#define	ND_STATE_FREE		0
#define	ND_STATE_PENDING	1
#define	ND_STATE_BUSY		2
#define	ND_STATE_DONE		3
#define	ND_STATE_ERROR		4

/*
 * The ncs_hvdesc structure MUST MATCH corresponding one in HV.
 * Structure padded to the next power of 2.
 */
typedef struct ncs_hvdesc {
	uint64_t	nhd_state;	/* ND_STATE_... */
	uint64_t	nhd_type;	/* ND_TYPE_... */
	ma_regs_t	nhd_regs;
	uint64_t	_padding[2];
} ncs_hvdesc_t;

#define	NCS_HVDESC_SHIFT	6	/* log2(NCS_HVDESC_SIZE) */
#define	NCS_HVDESC_SIZE_EXPECTED	(1 << NCS_HVDESC_SHIFT)
#define	NCS_HVDESC_SIZE_ACTUAL		(sizeof (ncs_hvdesc_t))

extern uint64_t hv_ncs_request(int, uint64_t, size_t);

#endif	/* !_ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_NCS_H */
