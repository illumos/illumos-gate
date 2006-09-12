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

#ifndef _SYS_LDLINUX_H
#define	_SYS_LDLINUX_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * The ldlinux streams module is only intended for use in lx branded zones.
 * This streams module implements the following ioctls:
 * 	TIOCSETLD and TIOCGETLD
 *
 * These ioctls are special ioctls supported only by the ldlinux streams
 * module and invoked only by the lx brand emulation library.  These ioctls
 * do not exist on native Linux systems.
 *
 * The TIOCSETLD ioctl is used when emulating the following Linux ioctls:
 *	TCSETS/TCSETSW/TCSETSF
 *	TCSETA/TCSETAW/TCSETAF
 *
 * The TIOCGETLD ioctl is used when emulating the following Linux ioctls:
 *	TCGETS/TCGETA
 *
 * This module is needed to emulate these ioctls because the following arrays:
 *	termio.c_cc
 *	termios.c_cc
 * which are parameters for the following ioctls:
 *	TCSETS/TCSETSW/TCSETSF
 *	TCSETA/TCSETAW/TCSETAF
 *	TCGETS/TCGETA
 *
 * are defined differently on Solaris and Linux.
 *
 * According to the termio(7I) man page on Solaris the following is true of
 * the members of the c_cc array:
 *	The VMIN element is the same element as the VEOF element.
 *	The VTIME element is the same element as the VEOL element.
 *
 * But on Linux the termios(3) man page states:
 *	These symbolic subscript values are all different, except that
 *	VTIME, VMIN may have the same value as VEOL, VEOF, respectively.
 *
 * While the man page indicates that these values may be the same empirical
 * tests shows them to be different.  Since these values are different on
 * Linux systems it's possible that applications could set the members of
 * the c_cc array to different values and then later expect to be able to
 * read back those same separate values.  The ldlinux module exists to provide
 * a per-stream storage area where the lx_brand emulation library can save
 * these values.  The values are set and retrieved via the TIOCSETLD and
 * TIOCGETLD ioctls respectively.
 */

#include <sys/termios.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	LDLINUX_MOD	"ldlinux"

#ifdef _KERNEL

/*
 * LDLINUX_MODID - This should be a unique number associated with
 * this particular module.  Unfortunatly there is no authority responsible
 * for administering this name space, hence there's no real guarantee that
 * whatever number we choose will be unique.  Luckily, this constant
 * is not really used anywhere by the system.  It is used by some
 * kernel subsystems to check for the presence of certain streams
 * modules with known id vaules.  Since no other kernel subsystem
 * checks for the presence of this module we'll just set the id to 0.
 */
#define	LDLINUX_MODID	0

struct ldlinux {
	int	state;		/* state information */
				/* Linux expects the next four c_cc values */
				/* to be distinct, whereas solaris (legally) */
				/* overlaps their storage */
	unsigned char veof;	/* veof value */
	unsigned char veol;	/* veol value */
	unsigned char vmin;	/* vmin value */
	unsigned char vtime;	/* vtime value */
};

#define	ISPTSTTY	0x01

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_LDLINUX_H */
