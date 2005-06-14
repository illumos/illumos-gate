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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Software mouse registers
 */

#ifndef _SYS_MSREG_H
#define	_SYS_MSREG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SunOS4.0 4.24 */


#include <sys/types.h>
#include <sys/types32.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Mouse sample.
 */
struct	mouseinfo {
	char	mi_x;		/* current X coordinate */
	char	mi_y;		/* current Y coordinate */
	char	mi_z;		/* current wheel */
	char	mi_buttons;	/* set of buttons that are currently down */
#define	MS_HW_BUT1	0x4	/* left button position */
#define	MS_HW_BUT2	0x2	/* middle button position */
#define	MS_HW_BUT3	0x1	/* right button position */
	struct	timeval32 mi_time; /* timestamp */
};

/*
 * Circular buffer storing mouse events.
 */
struct	mousebuf {
	short	mb_size;	/* size (in mouseinfo units) of buf */
	short	mb_off;		/* current offset in buffer */
	struct	mouseinfo mb_info[1];	/* however many samples */
};

struct	ms_softc {
	struct	mousebuf *ms_buf;	/* pointer to mouse buffer */
	short	ms_bufbytes;		/* buffer size (in bytes) */
	short	ms_flags;		/* currently unused */
	short	ms_oldoff;		/* index into mousebuf */
	short	ms_eventstate;		/* current event being generated */
	short	ms_readformat;		/* format of read stream */
#define	MS_3BYTE_FORMAT	VUID_NATIVE	/* 3 byte format (buts/x/y) */
#define	MS_VUID_FORMAT	VUID_FIRM_EVENT	/* vuid Firm_event format */
	short	ms_vuidaddr;		/* vuid addr for MS_VUID_FORMAT */
	char	ms_prevbuttons;		/* button state as of last message */
					/* sent upstream */
};

#define	EVENT_X		0	/* generating delta-X event */
#define	EVENT_Y		1	/* generating delta-Y event */
#define	EVENT_BUT1	2	/* generating button 1 event */
#define	EVENT_BUT2	3	/* generating button 2 event */
#define	EVENT_BUT3	4	/* generating button 3 event */
#define	EVENT_BUT4	5	/* generating button 4 event */
#define	EVENT_BUT5	6	/* generating button 5 event */
#define	EVENT_BUT6	7	/* generating button 6 event */
#define	EVENT_BUT7	8	/* generating button 7 event */
#define	EVENT_BUT8	9	/* generating button 8 event */
#define	EVENT_BUT9	10	/* generating button 9 event */
#define	EVENT_BUT10	11	/* generating button 10 event */
#define	EVENT_WHEEL	12	/* generating wheel    event */

#define	EVENT_BUT(i)	(i + 1)

#ifdef _KERNEL
#define	MSIOGETBUF	_IOWR('m', 1, int)	/* MSIOGETBUF is OBSOLETE */
	/* Get mouse buffer ptr so (window system in particular) can chase */
	/* around buffer to get events. */
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MSREG_H */
