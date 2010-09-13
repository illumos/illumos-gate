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
 * Copyright 1992 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#define OLDPACKSIZE	128

#define	PACKSIZE	64
#define MINPACKSIZE	32
#define MAXPACKSIZE   4096

#define	WINDOWS		7
#define	MINWINDOWS	1
#define	MAXWINDOWS	7


struct header {
	char	sync;
	char	ksize;
	unsigned short sum;
	char	cntl;
	char	ccntl;
};
#define	HDRSIZ	6

struct pack {
	short	p_state;	/* line state */
	short	p_bits;		/* mask for getepack */
	short	p_rsize;	/* input packet size */
	short	p_xsize;	/* output packet size */
	struct	header p_ihbuf;	/* input header */
	struct	header p_ohbuf; /* output header */
	char	*p_rptr;
	char	**p_ipool;
	char	p_xcount;	/* # active output buffers */
	char	p_rcount;
	char	p_nout,p_tout;
	char	p_lpsize;	/* log(psize/32) */
	char	p_timer;
	char	p_obusy;
	char	p_srxmit;
	char	p_rwindow;	/* window size */
	char	p_swindow;
	char	p_msg;		/* control msg */
	char	p_rmsg;		/* repeated control msg */
	char	p_ps,p_pr;	/* last packet sent, recv'd */
	char	p_rpr;
	char	p_nxtps;	/* next output seq number */
	char	p_imap;		/* bit map of input buffers */
	char	p_pscopy;	/* newest output packet */
	char	*p_ob[8];	/* output buffers */
	char	*p_ib[8];	/* input buffers */
	char	p_os[8];	/* output buffer status */
	char	p_is[8];	/* input buffer status */
	short	p_osum[8];	/* output checksums */
	short	p_isum[8];	/* input checksums */
	int	p_ifn, p_ofn;
};
#define	CHECK	0125252
#define	SYN	020
#define	MOD8	7
#define	ISCNTL(a)	((a & 0300)==0)
#ifndef MIN
#define	MIN(a,b)	((a<b)? a:b)
#endif

extern char	next[8];
extern char	mask[8];
extern int	npbits;
extern int	pkactive;
extern int	pkdebug;
extern int	pksizes[];
extern struct pack *Pk;

/*
 * driver state
 */
#define	DEAD	0
#define	INITa	1
#define	INITb	2
#define	INITab	3
#define	LIVE	010
#define	RXMIT	020
#define	RREJ	040
#define PDEBUG	0200
#define	DRAINO	0400
#define	WAITO	01000
#define	DOWN	02000
#define	RCLOSE	04000
#define	BADFRAME 020000

/*
 * io buffer states
 */
#define	B_NULL	0
#define	B_READY	1
#define	B_SENT	2
#define	B_RESID	010
#define	B_COPY	020
#define	B_MARK	040
#define	B_SHORT	0100

/*
 * control messages
 */
#define	CLOSE	1
#define	RJ	2
/* #define	SRJ	3 */	/* not supported */
#define	RR	4
#define	INITC	5
#define	INITB	6
#define	INITA	7

#define	M_RJ	4
/* #define	M_SRJ	010 */	/* not used */
#define	M_RR	020
#define	M_INITC	040
#define	M_CLOSE	2
#define	M_INITA	0200
#define	M_INITB	0100

/*
 * packet ioctl buf
 */
struct	piocb {
	unsigned t;
	short	psize;
	short	mode;
	short	state;
	char	window;
};
