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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ifndef _SYS_LDTERM_H
#define	_SYS_LDTERM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 11.5	*/

#ifdef	__cplusplus
extern "C" {
#endif

#define	IBSIZE	16		/* "standard" input data block size */
#define	OBSIZE	64		/* "standard" output data block size */
#define	EBSIZE	16		/* "standard" echo data block size */

#ifndef MIN
#define	MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

#define	V_MIN 		tp->t_modes.c_cc[VMIN]
#define	V_TIME		tp->t_modes.c_cc[VTIME]
#define	RAW_MODE	!(tp->t_modes.c_lflag & ICANON)
#define	CANON_MODE	(tp->t_modes.c_lflag & ICANON)

/* flow control defines */
#define	TTXOLO	132
#define	TTXOHI	180
#define	HIWAT	1024
#define	LOWAT	200
#define	LDCHUNK	512


/*
 * The following for EUC and also other types of codesets.
 */

#define	EUCSIZE	sizeof (struct eucioc)
#define	EUCIN	0	/* copying eucioc_t IN from ioctl */
#define	EUCOUT	1	/* copying it OUT to user format */

/*
 * One assumption made throughout this module is:  EUC characters have
 * a display width less than 255.  Also, assumed around, is that they
 * consist of < 256 bytes, but we don't worry much about that.
 */

#define	EUC_TWIDTH	255	/* Width of a TAB, as returned by */
				/* "ldterm_dispwidth" */
#define	EUC_BSWIDTH	254	/* Width of a backspace as returned */
#define	EUC_NLWIDTH	253	/* newline & cr */
#define	EUC_CRWIDTH	252

#define	UNKNOWN_WIDTH	251

#define	EUC_MAXW	4	/* max display width and memory width, both */
#define	EUC_WARNCNT	20	/* # bad EUC erase attempts before hollering */

/* The next version will be the current LDTERM_DATA_VERSION + 1. */
#define	LDTERM_DATA_VERSION		1

/*
 * Supported codeset types:
 * When you are adding a new codeset type,  do not add any new codeset type
 * value that is smaller than LDTERM_CS_TYPE_MIN. You will also need to
 * add the new codeset type sequentially and also increase LDTERM_CS_TYPE_MAX
 * so that the LDTERM_CS_TYPE_MAX will be always equal to the last, new
 * codeset type value.
 *
 * Whenever you increase the LDTERM_CS_TYPE_MAX, you will also need to
 * increase the LDTERM_DATA_VERSION and also update the ldterm.c so that
 * ldterm will have proper version control.
 */
#define	LDTERM_CS_TYPE_MIN		1

#define	LDTERM_CS_TYPE_EUC		1
#define	LDTERM_CS_TYPE_PCCS		2
#define	LDTERM_CS_TYPE_UTF8		3

#define	LDTERM_CS_TYPE_MAX		3

/*
 * The maximum number of bytes in a character of the codeset that
 * can be handled by ldterm.
 */
#define	LDTERM_CS_MAX_BYTE_LENGTH	8

/*
 * The maximum number of sub-codesets in a codeset that can be
 * handled by ldterm.
 */
#define	LDTERM_CS_MAX_CODESETS		10

/* The maximum and minimum sub-codeset numbers possible in EUC codeset. */
#define	LDTERM_CS_TYPE_EUC_MIN_SUBCS	0
#define	LDTERM_CS_TYPE_EUC_MAX_SUBCS	3

/* The maximum and minimum sub-codeset numbers possible in PCCS codeset. */
#define	LDTERM_CS_TYPE_PCCS_MIN_SUBCS	1
#define	LDTERM_CS_TYPE_PCCS_MAX_SUBCS	LDTERM_CS_MAX_CODESETS

/* Some UTF-8 related values: */
/* The maximum and minimum UTF-8 character subsequent byte values. */
#define	LDTERM_CS_TYPE_UTF8_MIN_BYTE	0x80
#define	LDTERM_CS_TYPE_UTF8_MAX_BYTE	0xbf

/* Some maximum and minimum character values in UTF-32. */
#define	LDTERM_CS_TYPE_UTF8_MAX_P00	0x00ffff
#define	LDTERM_CS_TYPE_UTF8_MAX_P01	0x01ffff
#define	LDTERM_CS_TYPE_UTF8_MIN_CJKEXTB	0x020000
#define	LDTERM_CS_TYPE_UTF8_MAX_CJKEXTB	0x02a6d6
#define	LDTERM_CS_TYPE_UTF8_MIN_CJKCOMP	0x02f800
#define	LDTERM_CS_TYPE_UTF8_MAX_CJKCOMP	0x02fa1d
#define	LDTERM_CS_TYPE_UTF8_MIN_P14	0x0e0000
#define	LDTERM_CS_TYPE_UTF8_MAX_P14	0x0e007f
#define	LDTERM_CS_TYPE_UTF8_MIN_VARSEL	0x0e0100
#define	LDTERM_CS_TYPE_UTF8_MAX_VARSEL	0x0e01ef
#define	LDTERM_CS_TYPE_UTF8_MIN_P15	0x0f0000
#define	LDTERM_CS_TYPE_UTF8_MAX_P15	0x0ffffd
#define	LDTERM_CS_TYPE_UTF8_MIN_P16	0x100000
#define	LDTERM_CS_TYPE_UTF8_MAX_P16	0x10fffd

/* Bit shift number and mask values for conversion from UTF-8 to UCS-4. */
#define	LDTERM_CS_TYPE_UTF8_SHIFT_BITS	6
#define	LDTERM_CS_TYPE_UTF8_BIT_MASK	0x3f

/*
 * The following data structure is to provide codeset-specific
 * information for EUC and PC originated codesets (ldterm_eucpc_data_t)
 */
struct _ldterm_eucpc_data {
	uchar_t	byte_length;
	uchar_t	screen_width;
	uchar_t	msb_start;
	uchar_t	msb_end;
};
typedef struct _ldterm_eucpc_data ldterm_eucpc_data_t;

/* ldterm codeset data information for user side. */
struct _ldterm_cs_data_user {
	uchar_t	version;	/* version: 1 ~ 255 */
	uchar_t	codeset_type;
	uchar_t	csinfo_num;	/* the # of codesets */
	uchar_t	pad;
	char	locale_name[MAXNAMELEN];
	ldterm_eucpc_data_t	eucpc_data[LDTERM_CS_MAX_CODESETS];
						/* width data */
};
typedef struct _ldterm_cs_data_user ldterm_cs_data_user_t;

/* ldterm codeset data information for ldterm. */
struct _ldterm_cs_data {
	uchar_t	version;	/* version: 1 ~ 255 */
	uchar_t	codeset_type;
	uchar_t	csinfo_num;	/* the # of codesets */
	uchar_t	pad;
	char	*locale_name;
	ldterm_eucpc_data_t	eucpc_data[LDTERM_CS_MAX_CODESETS];
						/* width data */
};
typedef struct _ldterm_cs_data ldterm_cs_data_t;

/*
 * The following data structure is to handle Unicode codeset.
 * To represent a single Unicode plane, it requires to have 16384
 * 'ldterm_unicode_data_cell_t' elements.
 */
struct _ldterm_unicode_data_cell {
	uchar_t	u0:2;
	uchar_t	u1:2;
	uchar_t	u2:2;
	uchar_t	u3:2;
};
typedef struct _ldterm_unicode_data_cell ldterm_unicode_data_cell_t;

/* The following function pointers point the current codeset methods.  */
typedef struct _ldterm_cs_methods {
	int (*ldterm_dispwidth)(uchar_t, void *, int);
	int (*ldterm_memwidth)(uchar_t, void *);
} ldterm_cs_methods_t;

typedef struct ldterm_mod {
	struct termios t_modes;	/* Effective modes set by the provider below */
	struct termios t_amodes; /* Apparent modes for user programs */
	struct termios t_dmodes; /* Modes that driver wishes to process */
	unsigned int t_state;	/* internal state of ldterm module */
	int	t_line;		/* output line of tty */
	int	t_col;		/* output column of tty */
	int	t_rocount;	/* number of chars echoed since last output */
	int	t_rocol;	/* column in which first such char appeared */
	mblk_t	*t_message;	/* pointer to first mblk in message being */
				/* built */
	mblk_t	*t_endmsg;	/* pointer to last mblk in that message */
	size_t	t_msglen;	/* number of characters in that message */
	mblk_t	*t_echomp;	/* echoed output being assembled */
	int	t_rd_request;   /* Number of bytes requested by M_READ */
				/* during vmin/vtime read */
	int	t_iocid;	/* ID of ioctl reply being awaited */
	bufcall_id_t t_wbufcid;	/* ID of pending write-side bufcall */
	timeout_id_t t_vtid;	/* vtime timer id */

	/*
	 * The following are for EUC and also other types of codeset
	 * processing. Please read 'euc' as 'multi-byte codeset' instead.
	 */
	uchar_t	t_codeset;	/* current code set indicator (read side) */
	uchar_t	t_eucleft;	/* bytes left to get in current char (read) */
	uchar_t	t_eucign;	/* bytes left to ignore (output post proc) */
	uchar_t	t_eucpad;	/* padding ... for eucwioc */
	eucioc_t eucwioc;	/* eucioc structure (have to use bcopy) */
	uchar_t	*t_eucp;	/* ptr to parallel array of column widths */
	mblk_t	*t_eucp_mp;	/* the m_blk that holds parallel array */
	uchar_t	t_maxeuc;	/* the max length in memory bytes of an EUC */
	int	t_eucwarn;	/* bad EUC counter */

	/*
	 * The t_csdata, t_csmethods, t_scratch, and, t_scratch_len data
	 * fields are to support various non-EUC codesets.
	 */
	ldterm_cs_data_t	t_csdata;
	struct _ldterm_cs_methods t_csmethods;
	uchar_t			t_scratch[LDTERM_CS_MAX_BYTE_LENGTH];
	uchar_t			t_scratch_len;

	mblk_t	*t_closeopts;	/* preallocated stroptions for close */
	mblk_t	*t_drainmsg;	/* preallocated TCSBRK drain message */
} ldtermstd_state_t;

/*
 * Internal state bits.
 */
#define	TS_XCLUDE	0x00000001	/* exclusive-use flag against open */
#define	TS_TTSTOP	0x00000002	/* output stopped by ^S */
#define	TS_TBLOCK	0x00000004	/* input stopped by IXOFF mode */
#define	TS_QUOT		0x00000008	/* last character input was \ */
#define	TS_ERASE	0x00000010	/* within a \.../ for PRTRUB */
#define	TS_SLNCH	0x00000020	/* next character service routine */
					/* sees is literal */
#define	TS_PLNCH	0x00000040	/* next character put routine sees */
					/* is literal */

#define	TS_TTCR		0x00000080	/* mapping NL to CR-NL */
#define	TS_NOCANON	0x00000100	/* canonicalization done by somebody */
					/* below us */
#define	TS_RESCAN	0x00000400	/* canonicalization mode changed, */
					/* rescan input queue */
#define	TS_MREAD	0x00000800	/* timer started for vmin/vtime */
#define	TS_FLUSHWAIT	0x00001000	/* waiting for flush on write side */
#define	TS_MEUC		0x00010000	/* TRUE if multi-byte codesets used */
#define	TS_WARNED	0x00020000	/* already warned on console */
#define	TS_CLOSE	0x00040000	/* close in progress */
#define	TS_IOCWAIT	0x00080000	/* waiting for reply to ioctl message */
#define	TS_IFBLOCK	0x00100000	/* input flow blocked */
#define	TS_OFBLOCK	0x00200000	/* output flow blocked */
#define	TS_ISPTSTTY	0x00400000	/* is x/open terminal */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_LDTERM_H */
