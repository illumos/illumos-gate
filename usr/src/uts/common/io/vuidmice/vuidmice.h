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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _VUIDMICE_H
#define	_VUIDMICE_H

#if _KERNEL
struct MouseStateInfo {
	unsigned long	last_event_lbolt;
	uchar_t		wheel_state_bf;
	uchar_t		format;
	uchar_t		state;
	uchar_t		buttons;		/* current button state */
	int		deltax;			/* delta X value */
	int		deltay;			/* delta Y value */
	int		vuid_mouse_mode;
	uchar_t		oldbuttons;		/* previous button state */
	uchar_t		sync_byte;
	uchar_t		inited;
	uchar_t		nbuttons;
	timeout_id_t	init_tid;		/* used for initialization */
	uchar_t		init_count;		/* track down init count */
};

typedef struct Mouse_iocstate {
	int		ioc_state;
	caddr_t		u_addr;
} Mouse_iocstate_t;

#define	STATEP		((struct MouseStateInfo *)qp->q_ptr)
#define	VUIDMICE_NUM_WHEELS		2
#define	VUIDMICE_VERTICAL_WHEEL_ID	0
#define	VUIDMICE_HORIZONTAL_WHEEL_ID	1

#ifdef	VUIDM3P
#define	VUID_NAME		"vuidm3p"
#define	VUID_PUTNEXT		vuidm3p_putnext
#define	VUID_QUEUE		vuidm3p
#define	VUID_OPEN		vuidm3p_open
#endif

#ifdef	VUIDM4P
#define	VUID_NAME		"vuidm4p"
#define	VUID_PUTNEXT		vuidm4p_putnext
#define	VUID_QUEUE		vuidm4p
#define	VUID_OPEN		vuidm4p_open
#endif

#ifdef	VUIDM5P
#define	VUID_NAME		"vuidm5p"
#define	VUID_PUTNEXT		vuidm5p_putnext
#define	VUID_QUEUE		vuidm5p
#define	VUID_OPEN		vuidm5p_open
#endif

#ifdef	VUID2PS2
#define	VUID_NAME		"vuid2ps2"
#define	VUID_PUTNEXT		vuid2ps2_putnext
#define	VUID_INIT_TIMEOUT	vuid2ps2_init_timeout
#define	VUID_QUEUE		vuid2ps2
#define	VUID_OPEN		vuid2ps2_open
#define	VUID_CLOSE		vuid2ps2_close
#endif

#ifdef	VUID3PS2
#define	VUID_NAME		"vuid3ps2"
#define	VUID_PUTNEXT		vuid3ps2_putnext
#define	VUID_INIT_TIMEOUT	vuid3ps2_init_timeout
#define	VUID_QUEUE		vuid3ps2
#define	VUID_OPEN		vuid3ps2_open
#define	VUID_CLOSE		vuid3ps2_close
#endif

#ifdef	VUIDPS2
#define	VUID_NAME		"vuidps2"
#define	VUID_PUTNEXT		vuidps2_putnext
#define	VUID_INIT_TIMEOUT	vuidps2_init_timeout
#define	VUID_QUEUE		vuidps2
#define	VUID_OPEN		vuidps2_open
#define	VUID_CLOSE		vuidps2_close
#endif

#ifndef	VUID_NAME
#define	VUID_NAME		"vuidmice"
#endif

#endif /* _KERNEL */

#endif /* _VUIDMICE_H */
