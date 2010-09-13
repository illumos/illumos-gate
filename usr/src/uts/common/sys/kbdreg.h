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
 * Copyright (c) 1985-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_KBDREG_H
#define	_SYS_KBDREG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SunOS4.0 1.7	*/

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Keyboard implementation private definitions.
 */

struct keyboardstate {
	int	k_id;
	uchar_t	k_idstate;
	uchar_t	k_state;
	uchar_t	k_rptkey;
	uint_t	k_buckybits;
	uint_t	k_shiftmask;
	struct	keyboard *k_curkeyboard;
	uint_t	k_togglemask;	/* Toggle shifts state */
};

/*
 * States of keyboard ID recognizer
 */
#define	KID_NONE		0	/* startup */
#define	KID_GOT_PREFACE		1	/* got id preface */
#define	KID_OK			2	/* locked on ID */
#define	KID_GOT_LAYOUT		3	/* got layout prefix */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_KBDREG_H */
