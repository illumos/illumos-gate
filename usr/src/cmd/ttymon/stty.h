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
 * Copyright 1999-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T
 * All Rights Reserved
 *
 */

#ifndef	_STTY_H
#define	_STTY_H

#ifdef	__cplusplus
extern "C" {
#endif

/* Stty flags. */
#define	ASYNC   1
#define	FLOW	2
#define	WINDOW	4
#define	TERMIOS 8
#ifdef EUC
#define	EUCW	16
#define	CSIW	32
#endif /* EUC */

/* Path to the locale-specific ldterm.dat file. */
#ifdef EUC
#define	_LDTERM_DAT_PATH	"/usr/lib/locale/%s/LC_CTYPE/ldterm.dat"
#endif /* EUC */

#define	MAX_CC	NCCS-1	/* max number of ctrl char fields printed by stty -g */
#define	NUM_MODES 4	/* number of modes printed by stty -g */
#define	NUM_FIELDS NUM_MODES+MAX_CC /* num modes + ctrl char fields (stty -g) */

struct	speeds {
	const char	*string;	/* Speed in string form, e.g. "9600" */
	int		code;		/* speed_t code for speed, e.g. B9600 */
	int		value;		/* Integer value of speed, e.g. 9600 */
};

struct	mds {
	const char	*string;
	long	set;
	long	reset;
};

extern	const struct	speeds	speeds[];
extern	const struct	mds	lmodes[];
extern	const struct	mds	nlmodes[];
extern	const struct	mds	cmodes[];
extern	const struct	mds	ncmodes[];
extern	const struct	mds	imodes[];
extern	const struct	mds	nimodes[];
extern	const struct	mds	omodes[];
extern	const struct	mds	hmodes[];
extern	const struct	mds	clkmodes[];

#ifdef	__cplusplus
}
#endif

#endif	/* _STTY_H */
