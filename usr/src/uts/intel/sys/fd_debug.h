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
 * Copyright (c) 1989-1997,1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_FD_DEBUG_H
#define	_SYS_FD_DEBUG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * flags/masks for error printing.
 * the levels are for severity
 */
#define	FDEP_L0		0	/* chatty as can be - for debug! */
#define	FDEP_L1		1	/* best for debug */
#define	FDEP_L2		2	/* minor errors - retries, etc. */
#define	FDEP_L3		3	/* major errors */
#define	FDEP_L4		4	/* catastrophic errors, don't mask! */
#define	FDEP_LMAX	4	/* catastrophic errors, don't mask! */

#ifdef DEBUG
#define	FDERRPRINT(l, m, args)	\
	{ if (((l) >= fderrlevel) && ((m) & fderrmask)) cmn_err args; }
#define	FCERRPRINT(l, m, args)	\
	{ if (((l) >= fcerrlevel) && ((m) & fcerrmask)) cmn_err args; }
#else
#define	FDERRPRINT(l, m, args)	{ }
#define	FCERRPRINT(l, m, args)	{ }
#endif /* DEBUG */

/*
 * for each function, we can mask off its printing by clearing its bit in
 * the fderrmask.  Some functions (attach, ident) share a mask bit
 */
#define	FDEM_IDEN 0x00000001	/* fdidentify */
#define	FDEM_ATTA 0x00000001	/* fdattach */
#define	FDEM_SIZE 0x00000002	/* fdsize */
#define	FDEM_OPEN 0x00000004	/* fdopen */
#define	FDEM_GETL 0x00000008	/* fdgetlabel */
#define	FDEM_CLOS 0x00000010	/* fdclose */
#define	FDEM_STRA 0x00000020	/* fdstrategy */
#define	FDEM_STRT 0x00000040	/* fdstart */
#define	FDEM_RDWR 0x00000080	/* fdrdwr */
#define	FDEM_CMD  0x00000100	/* fdcmd */
#define	FDEM_EXEC 0x00000200	/* fdexec */
#define	FDEM_RECO 0x00000400	/* fdrecover */
#define	FDEM_INTR 0x00000800	/* fdintr */
#define	FDEM_WATC 0x00001000	/* fdwatch */
#define	FDEM_IOCT 0x00002000	/* fdioctl */
#define	FDEM_RAWI 0x00004000	/* fdrawioctl */
#define	FDEM_PROP 0x00008000	/* fd_prop_op */
#define	FDEM_GETC 0x00010000	/* fdgetcsb */
#define	FDEM_RETC 0x00020000	/* fdretcsb */
#define	FDEM_RESE 0x00040000	/* fdreset */
#define	FDEM_RECA 0x00080000	/* fdrecalseek */
#define	FDEM_FORM 0x00100000	/* fdformat */
#define	FDEM_RW   0x00200000	/* fdrw */
#define	FDEM_CHEK 0x00400000	/* fdcheckdisk */
#define	FDEM_DSEL 0x00800000	/* fdselect */
#define	FDEM_EJEC 0x01000000	/* fdeject */
#define	FDEM_SCHG 0x02000000	/* fdsense_chng */
#define	FDEM_PACK 0x04000000	/* fdpacklabel */
#define	FDEM_MODS 0x08000000	/* _init, _info, _fini */
#define	FDEM_ALL  0xFFFFFFFF	/* all */

#ifdef	__cplusplus
}
#endif

#endif	/* !_SYS_FD_DEBUG_H */
