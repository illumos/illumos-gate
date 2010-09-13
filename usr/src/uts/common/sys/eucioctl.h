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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ifndef _SYS_EUCIOCTL_H
#define	_SYS_EUCIOCTL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.4	*/

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * /usr/include/sys/eucioctl.h:
 *
 *	Header for EUC width information to LD modules.
 */

#ifndef EUC_IOC
#define	EUC_IOC		(('E' | 128) << 8)
#endif
#define	EUC_WSET	(EUC_IOC | 1)
#define	EUC_WGET	(EUC_IOC | 2)
#define	EUC_MSAVE	(EUC_IOC | 3)
#define	EUC_MREST	(EUC_IOC | 4)
#define	EUC_IXLOFF	(EUC_IOC | 5)
#define	EUC_IXLON	(EUC_IOC | 6)
#define	EUC_OXLOFF	(EUC_IOC | 7)
#define	EUC_OXLON	(EUC_IOC | 8)

/*
 * This structure should really be the same one as defined in "euc.h",
 * but we want to minimize the number of bytes sent downstream to each
 * module -- this should make it 8 bytes -- therefore, we take only the
 * info we need.  The major assumptions here are that no EUC character
 * set has a character width greater than 255 bytes, and that no EUC
 * character consumes more than 255 screen columns.  Let me know if this
 * is an unsafe assumption...
 */

struct eucioc {
	unsigned char eucw[4];
	unsigned char scrw[4];
};
typedef struct eucioc	eucioc_t;

/*
 * The following defines are for LD modules to broadcast the state of
 * their "icanon" bit.
 *
 * The message type is M_CTL; message block 1 has a data block containing
 * an "iocblk"; EUC_BCAST is put into the "ioc_cmd" field.  The "b_cont"
 * of the first message block points to a second message block.  The second
 * message block is type M_DATA; it contains 1 byte that is either EUC_B_RAW
 * or EUC_B_CANON depending on the state of the "icanon" bit.  EUC line
 * disciplines should take care to broadcast this information when they are
 * in multibyte character mode.
 */

#define	EUC_BCAST	EUC_IOC|16

#define	EUC_B_CANON	'\177'
#define	EUC_B_RAW	'\001'	/* MUST be non-zero! */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_EUCIOCTL_H */
