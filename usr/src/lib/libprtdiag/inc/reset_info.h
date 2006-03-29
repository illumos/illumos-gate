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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_RESET_INFO_H
#define	_RESET_INFO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * All of the following data structures and defines come from sun4u server
 * POST. If the data in POST changes, then these structures must reflect
 * those changes.
 */

#include <sys/fhc.h>	/* To get MAX_BOARDS constant	*/

/* BDA bit assignments */
#define	BOARD_PRESENT		(1<<0)
#define	BOARD_OK		(1<<1)
#define	BOARD_TYPE_MSK		(7<<2)
#define	BOARD_TYPE(x)		(((x) & BOARD_TYPE_MSK) >> 2)

/* Board state mask and defines */
#define	BD_STATE_MASK		0x3
#define	BD_LPM_FZN		0
#define	BD_ONLINE_FAIL		1
#define	BD_NOT_PRESENT		2
#define	BD_ONLINE_NORMAL	3

/* define CPU 0 fields */
#define	CPU0_PRESENT		(1<<8)
#define	CPU0_OK			(1<<9)
#define	CPU0_FAIL_CODE_MSK	(7<<10)

/* define CPU 1 fields */
#define	CPU1_PRESENT		(1<<16)
#define	CPU1_OK			(1<<17)
#define	CPU1_FAIL_CODE_MSK	(7<<18)

/* supported board types */
#define	CPU_TYPE 0
#define	MEM_TYPE 1		/* CPU/MEM board with only memory */
#define	IO_TYPE1 2
#define	IO_TYPE2 3
#define	IO_TYPE3 4
#define	IO_TYPE4 5		/* same as IO TYPE 1 but no HM or PHY chip */
#define	CLOCK_TYPE 7

/* for CPU type UPA ports */
typedef struct {
	u_longlong_t afsr;	/* Fault status register for CPU */
	u_longlong_t afar;	/* Fault address register for CPU */
} cpu_reset_state;

/* For the clock board */
typedef struct {
	unsigned long clk_ssr_1;	/* reset status for the clock board */
} clock_reset_state;

struct board_info {
	u_longlong_t board_desc;
	cpu_reset_state cpu[2];	/* could be a CPU */
	u_longlong_t ac_error_status;
	u_longlong_t dc_shadow_chain;
	uint_t fhc_csr;
	uint_t fhc_rcsr;
};

struct reset_info {
	int length;			/* size of the structure */
	int version;			/* Version of the structure */
	struct board_info bd_reset_info[MAX_BOARDS];
	clock_reset_state clk;	/* one clock board */
	unsigned char tod_timestamp[7];
};

#ifdef	__cplusplus
}
#endif

#endif	/* _RESET_INFO_H */
