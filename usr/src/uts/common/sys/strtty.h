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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

#ifndef _SYS_STRTTY_H
#define	_SYS_STRTTY_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * header file for STREAMS TTY subsystem
 */

/*
 * The t_buf data structure holds information about a message
 * block and its associated data buffer.  One is used for received
 * blocks, and another is used for blocks to be transmitted to
 * a user terminal or a printer.
 */

struct t_buf
{
	mblk_t *bu_bp;	/* message block pointer */
	unsigned char *bu_ptr;	/* data buffer pointer */
	ushort_t bu_cnt;	/* data buffer character count */
};

/*
 * A tty structure is needed for each character device used for normal
 * tty I/O.  Each PORTS board supports 4 user terminals and 1 CENTRONICS-
 * TYPE printer.
 */

struct strtty
{
	struct t_buf t_in;	/* input buffer info */
	struct t_buf t_out;	/* output buffer info */
	queue_t *t_rdqp;	/* pointer to tty read queue */
	mblk_t  *t_ioctlp;	/* ioctl block pointer */
	mblk_t  *t_lbuf;	/* pointer to a large data buffer */
	int	t_dev;		/* tty minor device number */
	int	t_iflag;	/* input setting  flags */
	int	t_oflag;	/* output setting flags */
	int	t_cflag;	/* physical setting flags */
	int	t_lflag;	/* "line discipline" flags */
	short	t_state;	/* internal state */
	char	t_line;		/* active line discipline */
	char	t_dstat;	/* more internal state flags */
	unsigned char t_cc[NCCS]; /* settable control chars */
};

/*
 * Size of internal ports data buffer, one per port
 */
#define	LARGEBUFSZ	512

#define	TTIPRI	28
#define	TTOPRI	29

/* Internal state */
#define	TIMEOUT	01		/* Delay timeout in progress */
#define	WOPEN	02		/* Waiting for open to complete */
#define	ISOPEN	04		/* Device is open */
#define	TBLOCK	010
#define	CARR_ON	020		/* Software copy of carrier-present */
#define	BUSY	040		/* Output in progress */
#define	WIOC	0100		/* Wait for ioctl to complete */
#define	WGETTY	0200		/* opened by supergetty, waiting for getty */
#define	TTSTOP	0400		/* Output stopped by ctl-s */
#define	EXTPROC	01000		/* External processing */
#define	TACT	02000
#define	CLESC	04000		/* Last char escape */
#define	RTO	010000		/* Raw Timeout */
#define	TTIOW	020000
#define	TTXON	040000
#define	TTXOFF	0100000

/* l_output status */
#define	CPRES	0100000

/* device commands */
#define	T_OUTPUT	0
#define	T_TIME		1
#define	T_SUSPEND	2
#define	T_RESUME	3
#define	T_BLOCK		4
#define	T_UNBLOCK	5
#define	T_RFLUSH	6
#define	T_WFLUSH	7
#define	T_BREAK		8
#define	T_INPUT		9
#define	T_DISCONNECT	10
#define	T_PARM		11
#define	T_SWTCH		12
/*
 * M_CTL message types.
 */
#define	MC_NO_CANON	0	/* module below saying it will canonicalize */
#define	MC_DO_CANON	1	/* module below saying it won't canonicalize */
#define	MC_CANONQUERY	2	/* module above asking whether module below */
				/* canonicalizes */
#define	MC_PART_CANON	3	/* tell line discipline to do some */
				/* canonicalization */
/* XXX - These seem pretty device dependent... */
#define	MC_SERVICEIMM	3	/* tell the ZS driver to return input */
				/* immediately */
#define	MC_SERVICEDEF	4	/* tell the ZS driver it can wait */
#define	MC_POSIXQUERY	5	/* check if driver has POSIX close semantics */
#define	MC_HAS_POSIX	6	/* driver does support POSIX */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_STRTTY_H */
