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
 * Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#ifndef _SYS_TTY_H
#define	_SYS_TTY_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/ttychars.h>
#include <sys/ttydev.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * A clist structure is the head of a linked list queue of characters.
 * The routines getc* and putc* manipulate these structures.
 */

struct clist {
	int	c_cc;		/* character count */
	struct cblock *c_cf;	/* pointer to first */
	struct cblock *c_cl;	/* pointer to last */
};

/* Macro to find clist structure given pointer into it	*/
#define	CMATCH(pointer)		(char *)(cfree + (pointer - cfree))

/* Character control block for interrupt level control	*/

struct ccblock {
	caddr_t	c_ptr;		/* buffer address	*/
	ushort_t c_count;	/* character count	*/
	ushort_t c_size;	/* buffer size		*/
};

/*
 * A tty structure is needed for each UNIX character device that
 * is used for normal terminal IO.
 */
#define	NCC	8
struct tty {
	struct	clist t_rawq;	/* raw input queue */
	struct	clist t_canq;	/* canonical queue */
	struct	clist t_outq;	/* output queue */
	struct	ccblock	t_tbuf;	/* tx control block */
	struct	ccblock t_rbuf;	/* rx control block */
	int	(* t_proc)();	/* routine for device functions */
	ushort_t t_iflag;	/* input modes */
	ushort_t t_oflag;	/* output modes */
	ushort_t t_cflag;	/* control modes */
	ushort_t t_lflag;	/* line discipline modes */
	short	t_state;	/* internal state */
	o_pid_t	t_pgrp;		/* process group name */
	char	t_line;		/* line discipline */
	char	t_delct;	/* delimiter count */
	char	t_term;		/* terminal type */
	char	t_tmflag;	/* terminal flags */
	char	t_col;		/* current column */
	char	t_row;		/* current row */
	char	t_vrow;		/* variable row */
	char	t_lrow;		/* last physical row */
	char	t_hqcnt;	/* no. high queue packets on t_outq */
	char	t_dstat;
			/* used by terminal handlers and line disciplines */
	unsigned char	t_cc[NCC];	/* settable control chars */
};

/*
 * The structure of a clist block
 */
#define	CLSIZE	64
struct cblock {
	struct cblock *c_next;
	char	c_first;
	char	c_last;
	char	c_data[CLSIZE];
};

extern struct cblock	*cfree;
extern struct cblock	*getcb();
extern struct cblock	*getcf();
extern struct clist	ttnulq;
extern int		cfreecnt;

struct chead {
	struct cblock *c_next;
	int	c_size;
	int	c_flag;
};
extern struct chead cfreelist;

struct inter {
	int	cnt;
};

#define	QESC	0200	/* queue escape */
#define	HQEND	01	/* high queue end */

#define	TTIPRI	28
#define	TTOPRI	29

#ifdef u3b15
/*
 * following defs allow for job control in both vpm and
 * stand-alone tty environments
 */
#define	VPMTTY	1
#define	SATTY	2
#endif

/* limits */
extern int ttlowat[], tthiwat[];
#define	TTYHOG	256
#define	TTXOLO	132
#define	TTXOHI	180

/* Hardware bits */
#define	DONE	0200
#define	IENABLE	0100
#define	OVERRUN	040000
#define	FRERROR	020000
#define	PERROR	010000

/* Internal state */
#define	TIMEOUT	01		/* Delay timeout in progress */
#define	WOPEN	02		/* Waiting for open to complete */
#define	ISOPEN	04		/* Device is open */
#define	TBLOCK	010
#define	CARR_ON	020		/* Software copy of carrier-present */
#define	BUSY	040		/* Output in progress */
#define	OASLP	0100		/* Wakeup when output done */
#define	IASLP	0200		/* Wakeup when input done */
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
 * Terminal flags (set in t_tmflgs).
 */

#define	SNL	1		/* non-standard new-line needed */
#define	ANL	2		/* automatic new-line */
#define	LCF	4		/* Special treatment of last col, row */
#define	TERM_CTLECHO	010	/* Echo terminal control characters */
#define	TERM_INVIS	020	/* do not send escape sequences to user */
#define	QLOCKB		040	/* high queue locked for base level */
#define	QLOCKI		0100	/* high queue locked for interrupts */
#define	TERM_BIT 0200		/* Bit reserved for terminal drivers. */
				/* Usually used to indicate that an esc */
				/* character has arrived and that the */
				/* next character is special. */
				/* This bit is the same as the TM_SET */
				/* bit which may never be set by a user */
/*
 *	device reports
 */
#define	L_BUF		0
#define	L_BREAK		3

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_TTY_H */
