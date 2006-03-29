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
 * Copyright 2001 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SBDP_MBOX_H
#define	_SBDP_MBOX_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	SBDP_POWER_OFF		0x0
#define	SBDP_POWER_ON		0x1
#define	SBDP_UNASSIGN		0x0
#define	SBDP_ASSIGN		0x1

/*
 * DR Mailbox definitions
 */
#define	DR_MBOX_SHOW_BOARD	0x2002
#define	DR_MBOX_POWER		0x2003
#define	DR_MBOX_ASSIGN		0x2004
#define	DR_MBOX_TEST_BD		0x2005
#define	DR_MBOX_STICK_ADM	0x2006
#define	DR_MBOX_SWAP_SLICES	0x2007
#define	DR_MBOX_START_CPU	0x2008
#define	DR_MBOX_STOP_CPU	0x2009
#define	DR_MBOX_START_CPU_PAIRS	0x2010
#define	DR_MBOX_CLAIM		0x2011
#define	DR_MBOX_UNCLAIM		0x2012
#define	DR_MBOX_NOOP		0x2013

/*
 * DR Mailbox data structures
 */
typedef struct {
	int	revision;	/* temp */
	int	node;		/* Node ID */
	int	board;		/* Board number */
	int	extra;		/* for assign and power */
} info2_t;

typedef struct {
	info2_t		info;	/* Normal information */
	uint32_t	flag;	/* Force operation */
} testb_t;

typedef struct {
	int revision;	/* temp */
	int node;	/* Node ID */
	int board;	/* Board number */
} info_t;

typedef struct {
	int	revision;
	int	s_cond;		/* 0 = unknown, 1 = ok, 2 =  failing,	*/
				/* 3 = failed, 4 = unusable		*/
	int	s_power;	/* 0 = off, 1 = on */
	int	s_assigned;	/* 0 = unassigned, 1 = assigned */
	int	s_claimed;	/* 0 = unclaimed, 1 = claimed */
	int	s_present;	/* 0 = slot empty 1 = present */
	int	s_ledstatus;	/* LEDs status */
	char	s_type[12];	/* type of board */
	char	s_info[64];	/* TBD */
} show_board_t;

typedef struct {
	int	board1;
	int	board2;
} swap_slices_t;


int sbdp_start_cpu(processorid_t);
int sbdp_start_cpu_pairs(processorid_t);
int sbdp_stop_cpu(processorid_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _SBDP_MBOX_H */
