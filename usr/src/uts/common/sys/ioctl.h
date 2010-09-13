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
 * Copyright 1991 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#ifndef _SYS_IOCTL_H
#define	_SYS_IOCTL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 *	There are some inherent problems in having a single file
 *	ioctl.h, with both System V and BSD flags. Introducing
 *	BSD flags into this file creates compilation problems
 *	with flags such as ECHO, NL1 etc., if termio.h and ioctl.h
 *	are included by the same file. Since these two files can
 *	be only included by System V applications, /usr/inclule/sys/ioctl.h
 *	will be System V mode and all the BSD flags will be turned off
 *	using #ifdef BSD_COMP. This file will also exist in
 *	/usr/ucbinclude/sys/ioctl.h for BSD applications but without the
 *	BSD flags turned off. System V appliactions can use ioctl.h without
 *	any changes, System V applications requiring BSD flags should
 *	-D BSD_COMP when compiling (and be warned about the common
 *	flags between System V and BSD) and BSD applications should
 *	use /usr/ucbinclude/sys/ioctl.h.
 *
 */

#define	IOCTYPE	0xff00

#define	LIOC	('l'<<8)
#define	LIOCGETP	(LIOC|1)
#define	LIOCSETP	(LIOC|2)
#define	LIOCGETS	(LIOC|5)
#define	LIOCSETS	(LIOC|6)

#define	DIOC	('d'<<8)
#define	DIOCGETC	(DIOC|1)
#define	DIOCGETB	(DIOC|2)
#define	DIOCSETE	(DIOC|3)

#ifdef	__cplusplus
}
#endif

/* BSD related defines */

#ifdef BSD_COMP

#include <sys/ttychars.h>
#include <sys/ttydev.h>
#include <sys/ttold.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	TANDEM		O_TANDEM
#define	CBREAK		O_CBREAK
#ifndef _SGTTY_H
#define	LCASE		O_LCASE
#define	ECHO		O_ECHO
#define	CRMOD		O_CRMOD
#define	RAW		O_RAW
#define	ODDP		O_ODDP
#define	EVENP		O_EVENP
#define	ANYP		O_ANYP
#define	NLDELAY		O_NLDELAY
#define		NL0		O_NL0
#define		NL1		O_NL1
#define		NL2		O_NL2
#define		NL3		O_NL3
#define	TBDELAY		O_TBDELAY
#define		TAB0		O_TAB0
#define		TAB1		O_TAB1
#define		TAB2		O_TAB2
#define	XTABS		O_XTABS
#define	CRDELAY		O_CRDELAY
#define		CR0		O_CR0
#define		CR1		O_CR1
#define		CR2		O_CR2
#define		CR3		O_CR3
#define	VTDELAY		O_VTDELAY
#define		FF0		O_FF0
#define		FF1		O_FF1
#define	BSDELAY		O_BSDELAY
#define		BS0		O_BS0
#define		BS1		O_BS1
#define		ALLDELAY	O_ALLDELAY
#endif /* _SGTTY_H */
#define	CRTBS		O_CRTBS
#define	PRTERA		O_PRTERA
#define	CRTERA		O_CRTERA
#define	TILDE		O_TILDE
#define	MDMBUF		O_MDMBUF
#define	LITOUT		O_LITOUT
#define	TOSTOP		O_TOSTOP
#define	FLUSHO		O_FLUSHO
#define	NOHANG		O_NOHANG
#define	L001000		O_L001000
#define	CRTKIL		O_CRTKIL
#define	PASS8		O_PASS8
#define	CTLECH		O_CTLECH
#define	PENDIN		O_PENDIN
#define	DECCTQ		O_DECCTQ
#define	NOFLSH		O_NOFLSH

#ifdef	__cplusplus
}
#endif

#include <sys/filio.h>
#include <sys/sockio.h>

#endif /* BSD_COMP */

#endif	/* _SYS_IOCTL_H */
