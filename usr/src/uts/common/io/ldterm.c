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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2014, Joyent, Inc.  All rights reserved.
 * Copyright 2018 OmniOS Community Edition (OmniOSce) Association.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/* All Rights Reserved					*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*
 * Standard Streams Terminal Line Discipline module.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/termio.h>
#include <sys/stream.h>
#include <sys/conf.h>
#include <sys/stropts.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/strtty.h>
#include <sys/signal.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/euc.h>
#include <sys/eucioctl.h>
#include <sys/csiioctl.h>
#include <sys/ptms.h>
#include <sys/ldterm.h>
#include <sys/cred.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/kmem.h>
#include <sys/modctl.h>

/* Time limit when draining during a close(9E) invoked by exit(2) */
/* Can be set to zero to emulate the old, broken behavior */
int ldterm_drain_limit = 15000000;

/*
 * Character types.
 */
#define	ORDINARY	0
#define	CONTROL		1
#define	BACKSPACE	2
#define	NEWLINE		3
#define	TAB		4
#define	VTAB		5
#define	RETURN		6

/*
 * The following for EUC handling:
 */
#define	T_SS2		7
#define	T_SS3		8

/*
 * Table indicating character classes to tty driver.  In particular,
 * if the class is ORDINARY, then the character needs no special
 * processing on output.
 *
 * Characters in the C1 set are all considered CONTROL; this will
 * work with terminals that properly use the ANSI/ISO extensions,
 * but might cause distress with terminals that put graphics in
 * the range 0200-0237.  On the other hand, characters in that
 * range cause even greater distress to other UNIX terminal drivers....
 */

static char typetab[256] = {
/* 000 */	CONTROL,	CONTROL,	CONTROL,	CONTROL,
/* 004 */	CONTROL,	CONTROL,	CONTROL,	CONTROL,
/* 010 */	BACKSPACE,	TAB,		NEWLINE,	CONTROL,
/* 014 */	VTAB,		RETURN,		CONTROL,	CONTROL,
/* 020 */	CONTROL,	CONTROL,	CONTROL,	CONTROL,
/* 024 */	CONTROL,	CONTROL,	CONTROL,	CONTROL,
/* 030 */	CONTROL,	CONTROL,	CONTROL,	CONTROL,
/* 034 */	CONTROL,	CONTROL,	CONTROL,	CONTROL,
/* 040 */	ORDINARY,	ORDINARY,	ORDINARY,	ORDINARY,
/* 044 */	ORDINARY,	ORDINARY,	ORDINARY,	ORDINARY,
/* 050 */	ORDINARY,	ORDINARY,	ORDINARY,	ORDINARY,
/* 054 */	ORDINARY,	ORDINARY,	ORDINARY,	ORDINARY,
/* 060 */	ORDINARY,	ORDINARY,	ORDINARY,	ORDINARY,
/* 064 */	ORDINARY,	ORDINARY,	ORDINARY,	ORDINARY,
/* 070 */	ORDINARY,	ORDINARY,	ORDINARY,	ORDINARY,
/* 074 */	ORDINARY,	ORDINARY,	ORDINARY,	ORDINARY,
/* 100 */	ORDINARY,	ORDINARY,	ORDINARY,	ORDINARY,
/* 104 */	ORDINARY,	ORDINARY,	ORDINARY,	ORDINARY,
/* 110 */	ORDINARY,	ORDINARY,	ORDINARY,	ORDINARY,
/* 114 */	ORDINARY,	ORDINARY,	ORDINARY,	ORDINARY,
/* 120 */	ORDINARY,	ORDINARY,	ORDINARY,	ORDINARY,
/* 124 */	ORDINARY,	ORDINARY,	ORDINARY,	ORDINARY,
/* 130 */	ORDINARY,	ORDINARY,	ORDINARY,	ORDINARY,
/* 134 */	ORDINARY,	ORDINARY,	ORDINARY,	ORDINARY,
/* 140 */	ORDINARY,	ORDINARY,	ORDINARY,	ORDINARY,
/* 144 */	ORDINARY,	ORDINARY,	ORDINARY,	ORDINARY,
/* 150 */	ORDINARY,	ORDINARY,	ORDINARY,	ORDINARY,
/* 154 */	ORDINARY,	ORDINARY,	ORDINARY,	ORDINARY,
/* 160 */	ORDINARY,	ORDINARY,	ORDINARY,	ORDINARY,
/* 164 */	ORDINARY,	ORDINARY,	ORDINARY,	ORDINARY,
/* 170 */	ORDINARY,	ORDINARY,	ORDINARY,	ORDINARY,
/* 174 */	ORDINARY,	ORDINARY,	ORDINARY,	CONTROL,
/* 200 */	CONTROL,	CONTROL,	CONTROL,	CONTROL,
/* 204 */	CONTROL,	CONTROL,	T_SS2,		T_SS3,
/* 210 */	CONTROL,	CONTROL,	CONTROL,	CONTROL,
/* 214 */	CONTROL,	CONTROL,	CONTROL,	CONTROL,
/* 220 */	CONTROL,	CONTROL,	CONTROL,	CONTROL,
/* 224 */	CONTROL,	CONTROL,	CONTROL,	CONTROL,
/* 230 */	CONTROL,	CONTROL,	CONTROL,	CONTROL,
/* 234 */	CONTROL,	CONTROL,	CONTROL,	CONTROL,
/* 240 */	ORDINARY,	ORDINARY,	ORDINARY,	ORDINARY,
/* 244 */	ORDINARY,	ORDINARY,	ORDINARY,	ORDINARY,
/* 250 */	ORDINARY,	ORDINARY,	ORDINARY,	ORDINARY,
/* 254 */	ORDINARY,	ORDINARY,	ORDINARY,	ORDINARY,
/* 260 */	ORDINARY,	ORDINARY,	ORDINARY,	ORDINARY,
/* 264 */	ORDINARY,	ORDINARY,	ORDINARY,	ORDINARY,
/* 270 */	ORDINARY,	ORDINARY,	ORDINARY,	ORDINARY,
/* 274 */	ORDINARY,	ORDINARY,	ORDINARY,	ORDINARY,
/* 300 */	ORDINARY,	ORDINARY,	ORDINARY,	ORDINARY,
/* 304 */	ORDINARY,	ORDINARY,	ORDINARY,	ORDINARY,
/* 310 */	ORDINARY,	ORDINARY,	ORDINARY,	ORDINARY,
/* 314 */	ORDINARY,	ORDINARY,	ORDINARY,	ORDINARY,
/* 320 */	ORDINARY,	ORDINARY,	ORDINARY,	ORDINARY,
/* 324 */	ORDINARY,	ORDINARY,	ORDINARY,	ORDINARY,
/* 330 */	ORDINARY,	ORDINARY,	ORDINARY,	ORDINARY,
/* 334 */	ORDINARY,	ORDINARY,	ORDINARY,	ORDINARY,
/* 340 */	ORDINARY,	ORDINARY,	ORDINARY,	ORDINARY,
/* 344 */	ORDINARY,	ORDINARY,	ORDINARY,	ORDINARY,
/* 350 */	ORDINARY,	ORDINARY,	ORDINARY,	ORDINARY,
/* 354 */	ORDINARY,	ORDINARY,	ORDINARY,	ORDINARY,
/* 360 */	ORDINARY,	ORDINARY,	ORDINARY,	ORDINARY,
/* 364 */	ORDINARY,	ORDINARY,	ORDINARY,	ORDINARY,
/* 370 */	ORDINARY,	ORDINARY,	ORDINARY,	ORDINARY,
/*
 * WARNING:  For EUC, 0xFF must be an ordinary character.  It is used with
 * single-byte EUC in some of the "ISO Latin Alphabet" codesets, and occupies
 * a screen position; in those ISO sets where that position isn't used, it
 * shouldn't make any difference.
 */
/* 374 */	ORDINARY,	ORDINARY,	ORDINARY,	ORDINARY,
};

/*
 * Translation table for output without OLCUC.  All ORDINARY-class characters
 * translate to themselves.  All other characters have a zero in the table,
 * which stops the copying.
 */
static unsigned char notrantab[256] = {
/* 000 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 010 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 020 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 030 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 040 */	' ',	'!',	'"',	'#',	'$',	'%',	'&',	'\'',
/* 050 */	'(',	')',	'*',	'+',	',',	'-',	'.',	'/',
/* 060 */	'0',	'1',	'2',	'3',	'4',	'5',	'6',	'7',
/* 070 */	'8',	'9',	':',	';',	'<',	'=',	'>',	'?',
/* 100 */	'@',	'A',	'B',	'C',	'D',	'E',	'F',	'G',
/* 110 */	'H',	'I',	'J',	'K',	'L',	'M',	'N',	'O',
/* 120 */	'P',	'Q',	'R',	'S',	'T',	'U',	'V',	'W',
/* 130 */	'X',	'Y',	'Z',	'[',	'\\',	']',	'^',	'_',
/* 140 */	'`',	'a',	'b',	'c',	'd',	'e',	'f',	'g',
/* 150 */	'h',	'i',	'j',	'k',	'l',	'm',	'n',	'o',
/* 160 */	'p',	'q',	'r',	's',	't',	'u',	'v',	'w',
/* 170 */	'x',	'y',	'z',	'{',	'|',	'}',	'~',	0,
/* 200 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 210 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 220 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 230 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 240 */	0240,	0241,	0242,	0243,	0244,	0245,	0246,	0247,
/* 250 */	0250,	0251,	0252,	0253,	0254,	0255,	0256,	0257,
/* 260 */	0260,	0261,	0262,	0263,	0264,	0265,	0266,	0267,
/* 270 */	0270,	0271,	0272,	0273,	0274,	0275,	0276,	0277,
/* 300 */	0300,	0301,	0302,	0303,	0304,	0305,	0306,	0307,
/* 310 */	0310,	0311,	0312,	0313,	0314,	0315,	0316,	0317,
/* 320 */	0320,	0321,	0322,	0323,	0324,	0325,	0326,	0327,
/* 330 */	0330,	0331,	0332,	0333,	0334,	0335,	0336,	0337,
/* 340 */	0340,	0341,	0342,	0343,	0344,	0345,	0346,	0347,
/* 350 */	0350,	0351,	0352,	0353,	0354,	0355,	0356,	0357,
/* 360 */	0360,	0361,	0362,	0363,	0364,	0365,	0366,	0367,
/*
 * WARNING: as for above ISO sets, \377 may be used.  Translate it to
 * itself.
 */
/* 370 */	0370,	0371,	0372,	0373,	0374,	0375,	0376,	0377,
};

/*
 * Translation table for output with OLCUC.  All ORDINARY-class characters
 * translate to themselves, except for lower-case letters which translate
 * to their upper-case equivalents.  All other characters have a zero in
 * the table, which stops the copying.
 */
static unsigned char lcuctab[256] = {
/* 000 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 010 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 020 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 030 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 040 */	' ',	'!',	'"',	'#',	'$',	'%',	'&',	'\'',
/* 050 */	'(',	')',	'*',	'+',	',',	'-',	'.',	'/',
/* 060 */	'0',	'1',	'2',	'3',	'4',	'5',	'6',	'7',
/* 070 */	'8',	'9',	':',	';',	'<',	'=',	'>',	'?',
/* 100 */	'@',	'A',	'B',	'C',	'D',	'E',	'F',	'G',
/* 110 */	'H',	'I',	'J',	'K',	'L',	'M',	'N',	'O',
/* 120 */	'P',	'Q',	'R',	'S',	'T',	'U',	'V',	'W',
/* 130 */	'X',	'Y',	'Z',	'[',	'\\',	']',	'^',	'_',
/* 140 */	'`',	'A',	'B',	'C',	'D',	'E',	'F',	'G',
/* 150 */	'H',	'I',	'J',	'K',	'L',	'M',	'N',	'O',
/* 160 */	'P',	'Q',	'R',	'S',	'T',	'U',	'V',	'W',
/* 170 */	'X',	'Y',	'Z',	'{',	'|',	'}',	'~',	0,
/* 200 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 210 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 220 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 230 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 240 */	0240,	0241,	0242,	0243,	0244,	0245,	0246,	0247,
/* 250 */	0250,	0251,	0252,	0253,	0254,	0255,	0256,	0257,
/* 260 */	0260,	0261,	0262,	0263,	0264,	0265,	0266,	0267,
/* 270 */	0270,	0271,	0272,	0273,	0274,	0275,	0276,	0277,
/* 300 */	0300,	0301,	0302,	0303,	0304,	0305,	0306,	0307,
/* 310 */	0310,	0311,	0312,	0313,	0314,	0315,	0316,	0317,
/* 320 */	0320,	0321,	0322,	0323,	0324,	0325,	0326,	0327,
/* 330 */	0330,	0331,	0332,	0333,	0334,	0335,	0336,	0337,
/* 340 */	0340,	0341,	0342,	0343,	0344,	0345,	0346,	0347,
/* 350 */	0350,	0351,	0352,	0353,	0354,	0355,	0356,	0357,
/* 360 */	0360,	0361,	0362,	0363,	0364,	0365,	0366,	0367,
/*
 * WARNING: as for above ISO sets, \377 may be used.  Translate it to
 * itself.
 */
/* 370 */	0370,	0371,	0372,	0373,	0374,	0375,	0376,	0377,
};

/*
 * Input mapping table -- if an entry is non-zero, and XCASE is set,
 * when the corresponding character is typed preceded by "\" the escape
 * sequence is replaced by the table value.  Mostly used for
 * upper-case only terminals.
 */
static char	imaptab[256] = {
/* 000 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 010 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 020 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 030 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 040 */	0,	'|',	0,	0,	0,	0,	0,	'`',
/* 050 */	'{',	'}',	0,	0,	0,	0,	0,	0,
/* 060 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 070 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 100 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 110 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 120 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 130 */	0,	0,	0,	0,	'\\',	0,	'~',	0,
/* 140 */	0,	'A',	'B',	'C',	'D',	'E',	'F',	'G',
/* 150 */	'H',	'I',	'J',	'K',	'L',	'M',	'N',	'O',
/* 160 */	'P',	'Q',	'R',	'S',	'T',	'U',	'V',	'W',
/* 170 */	'X',	'Y',	'Z',	0,	0,	0,	0,	0,
/* 200-377 aren't mapped */
};

/*
 * Output mapping table -- if an entry is non-zero, and XCASE is set,
 * the corresponding character is printed as "\" followed by the table
 * value.  Mostly used for upper-case only terminals.
 */
static char	omaptab[256] = {
/* 000 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 010 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 020 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 030 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 040 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 050 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 060 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 070 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 100 */	0,	'A',	'B',	'C',	'D',	'E',	'F',	'G',
/* 110 */	'H',	'I',	'J',	'K',	'L',	'M',	'N',	'O',
/* 120 */	'P',	'Q',	'R',	'S',	'T',	'U',	'V',	'W',
/* 130 */	'X',	'Y',	'Z',	0,	0,	0,	0,	0,
/* 140 */	'\'',	0,	0,	0,	0,	0,	0,	0,
/* 150 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 160 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 170 */	0,	0,	0,	'(',	'!',	')',	'^',	0,
/* 200-377 aren't mapped */
};

/*
 * Translation table for TS_MEUC output without OLCUC.  All printing ASCII
 * characters translate to themselves.  All other _bytes_ have a zero in
 * the table, which stops the copying.  This and the following table exist
 * only so we can use the existing movtuc processing with or without OLCUC.
 * Maybe it speeds up something...because we can copy a block of characters
 * by only looking for zeros in the table.
 *
 * If we took the simple expedient of DISALLOWING "olcuc" with multi-byte
 * processing, we could rid ourselves of both these tables and save 512 bytes;
 * seriously, it doesn't make much sense to use olcuc with multi-byte, and
 * it will probably never be used.  Consideration should be given to disallowing
 * the combination TS_MEUC & OLCUC.
 */
static unsigned char enotrantab[256] = {
/* 000 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 010 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 020 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 030 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 040 */	' ',	'!',	'"',	'#',	'$',	'%',	'&',	'\'',
/* 050 */	'(',	')',	'*',	'+',	',',	'-',	'.',	'/',
/* 060 */	'0',	'1',	'2',	'3',	'4',	'5',	'6',	'7',
/* 070 */	'8',	'9',	':',	';',	'<',	'=',	'>',	'?',
/* 100 */	'@',	'A',	'B',	'C',	'D',	'E',	'F',	'G',
/* 110 */	'H',	'I',	'J',	'K',	'L',	'M',	'N',	'O',
/* 120 */	'P',	'Q',	'R',	'S',	'T',	'U',	'V',	'W',
/* 130 */	'X',	'Y',	'Z',	'[',	'\\',	']',	'^',	'_',
/* 140 */	'`',	'a',	'b',	'c',	'd',	'e',	'f',	'g',
/* 150 */	'h',	'i',	'j',	'k',	'l',	'm',	'n',	'o',
/* 160 */	'p',	'q',	'r',	's',	't',	'u',	'v',	'w',
/* 170 */	'x',	'y',	'z',	'{',	'|',	'}',	'~',	0,
/* 200 - 377 aren't mapped (they're stoppers). */
};

/*
 * Translation table for TS_MEUC output with OLCUC.  All printing ASCII
 * translate to themselves, except for lower-case letters which translate
 * to their upper-case equivalents.  All other bytes have a zero in
 * the table, which stops the copying.  Useless for ISO Latin Alphabet
 * translations, but *sigh* OLCUC is really only defined for ASCII anyway.
 * We only have this table so we can use the existing OLCUC processing with
 * TS_MEUC set (multi-byte mode).  Nobody would ever think of actually
 * _using_ it...would they?
 */
static unsigned char elcuctab[256] = {
/* 000 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 010 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 020 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 030 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 040 */	' ',	'!',	'"',	'#',	'$',	'%',	'&',	'\'',
/* 050 */	'(',	')',	'*',	'+',	',',	'-',	'.',	'/',
/* 060 */	'0',	'1',	'2',	'3',	'4',	'5',	'6',	'7',
/* 070 */	'8',	'9',	':',	';',	'<',	'=',	'>',	'?',
/* 100 */	'@',	'A',	'B',	'C',	'D',	'E',	'F',	'G',
/* 110 */	'H',	'I',	'J',	'K',	'L',	'M',	'N',	'O',
/* 120 */	'P',	'Q',	'R',	'S',	'T',	'U',	'V',	'W',
/* 130 */	'X',	'Y',	'Z',	'[',	'\\',	']',	'^',	'_',
/* 140 */	'`',	'A',	'B',	'C',	'D',	'E',	'F',	'G',
/* 150 */	'H',	'I',	'J',	'K',	'L',	'M',	'N',	'O',
/* 160 */	'P',	'Q',	'R',	'S',	'T',	'U',	'V',	'W',
/* 170 */	'X',	'Y',	'Z',	'{',	'|',	'}',	'~',	0,
/* 200 - 377 aren't mapped (they're stoppers). */
};

static struct streamtab ldtrinfo;

static struct fmodsw fsw = {
	"ldterm",
	&ldtrinfo,
	D_MTQPAIR | D_MP | _D_SINGLE_INSTANCE
};

static struct modlstrmod modlstrmod = {
	&mod_strmodops, "terminal line discipline", &fsw
};


static struct modlinkage modlinkage = {
	MODREV_1, &modlstrmod, NULL
};


int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


static int	ldtermopen(queue_t *, dev_t *, int, int, cred_t *);
static int	ldtermclose(queue_t *, int, cred_t *);
static void	ldtermrput(queue_t *, mblk_t *);
static void	ldtermrsrv(queue_t *);
static int	ldtermrmsg(queue_t *, mblk_t *);
static void	ldtermwput(queue_t *, mblk_t *);
static void	ldtermwsrv(queue_t *);
static int	ldtermwmsg(queue_t *, mblk_t *);
static mblk_t	*ldterm_docanon(unsigned char, mblk_t *, size_t, queue_t *,
				ldtermstd_state_t *, int *);
static int	ldterm_unget(ldtermstd_state_t *);
static void	ldterm_trim(ldtermstd_state_t *);
static void	ldterm_rubout(unsigned char, queue_t *, size_t,
				ldtermstd_state_t *);
static int	ldterm_tabcols(ldtermstd_state_t *);
static void	ldterm_erase(queue_t *, size_t, ldtermstd_state_t *);
static void	ldterm_werase(queue_t *, size_t, ldtermstd_state_t *);
static void	ldterm_kill(queue_t *, size_t, ldtermstd_state_t *);
static void	ldterm_reprint(queue_t *, size_t, ldtermstd_state_t *);
static mblk_t	*ldterm_dononcanon(mblk_t *, mblk_t *, size_t, queue_t *,
					ldtermstd_state_t *);
static int	ldterm_echo(unsigned char, queue_t *, size_t,
				ldtermstd_state_t *);
static void	ldterm_outchar(unsigned char, queue_t *, size_t,
				ldtermstd_state_t *);
static void	ldterm_outstring(unsigned char *, int, queue_t *, size_t,
					ldtermstd_state_t *tp);
static mblk_t	*newmsg(ldtermstd_state_t *);
static void	ldterm_msg_upstream(queue_t *, ldtermstd_state_t *);
static void	ldterm_wenable(void *);
static mblk_t	*ldterm_output_msg(queue_t *, mblk_t *, mblk_t **,
				ldtermstd_state_t *, size_t, int);
static void	ldterm_flush_output(unsigned char, queue_t *,
					ldtermstd_state_t *);
static void	ldterm_dosig(queue_t *, int, unsigned char, int, int);
static void	ldterm_do_ioctl(queue_t *, mblk_t *);
static int	chgstropts(struct termios *, ldtermstd_state_t *, queue_t *);
static void	ldterm_ioctl_reply(queue_t *, mblk_t *);
static void	vmin_satisfied(queue_t *, ldtermstd_state_t *, int);
static void	vmin_settimer(queue_t *);
static void	vmin_timed_out(void *);
static void	ldterm_adjust_modes(ldtermstd_state_t *);
static void	ldterm_eucwarn(ldtermstd_state_t *);
static void	cp_eucwioc(eucioc_t *, eucioc_t *, int);
static int	ldterm_codeset(uchar_t, uchar_t);

static void	ldterm_csi_erase(queue_t *, size_t, ldtermstd_state_t *);
static void	ldterm_csi_werase(queue_t *, size_t, ldtermstd_state_t *);

static uchar_t	ldterm_utf8_width(uchar_t *, int);

/* Codeset type specific methods for EUC, PCCS, and, UTF-8 codeset types. */
static int	__ldterm_dispwidth_euc(uchar_t, void *, int);
static int	__ldterm_memwidth_euc(uchar_t, void *);

static int	__ldterm_dispwidth_pccs(uchar_t, void *, int);
static int	__ldterm_memwidth_pccs(uchar_t, void *);

static int	__ldterm_dispwidth_utf8(uchar_t, void *, int);
static int	__ldterm_memwidth_utf8(uchar_t, void *);

static const ldterm_cs_methods_t cs_methods[LDTERM_CS_TYPE_MAX + 1] = {
	{
		NULL,
		NULL
	},
	{
		__ldterm_dispwidth_euc,
		__ldterm_memwidth_euc
	},
	{
		__ldterm_dispwidth_pccs,
		__ldterm_memwidth_pccs
	},
	{
		__ldterm_dispwidth_utf8,
		__ldterm_memwidth_utf8
	}
};

/*
 * The default codeset is presumably C locale's ISO 646 in EUC but
 * the data structure at below defined as the default codeset data also
 * support any single byte (EUC) locales.
 */
static const ldterm_cs_data_t default_cs_data = {
	LDTERM_DATA_VERSION,
	LDTERM_CS_TYPE_EUC,
	(uchar_t)0,
	(uchar_t)0,
	(char *)NULL,
	{
		'\0', '\0', '\0', '\0',
		'\0', '\0', '\0', '\0',
		'\0', '\0', '\0', '\0',
		'\0', '\0', '\0', '\0',
		'\0', '\0', '\0', '\0',
		'\0', '\0', '\0', '\0',
		'\0', '\0', '\0', '\0',
		'\0', '\0', '\0', '\0',
		'\0', '\0', '\0', '\0',
		'\0', '\0', '\0', '\0'
	}
};

/*
 * The following tables are from either u8_textprep.c or uconv.c at
 * usr/src/common/unicode/. The tables are used to figure out corresponding
 * UTF-8 character byte lengths and also the validity of given character bytes.
 */
extern const int8_t u8_number_of_bytes[];
extern const uchar_t u8_masks_tbl[];
extern const uint8_t u8_valid_min_2nd_byte[];
extern const uint8_t u8_valid_max_2nd_byte[];

/*
 * Unicode character width definition tables from uwidth.c:
 */
extern const ldterm_unicode_data_cell_t ldterm_ucode[][16384];

#ifdef LDDEBUG
int	ldterm_debug = 0;
#define	DEBUG1(a)	if (ldterm_debug == 1) printf a
#define	DEBUG2(a)	if (ldterm_debug >= 2) printf a	/* allocations */
#define	DEBUG3(a)	if (ldterm_debug >= 3) printf a	/* M_CTL Stuff */
#define	DEBUG4(a)	if (ldterm_debug >= 4) printf a	/* M_READ Stuff */
#define	DEBUG5(a)	if (ldterm_debug >= 5) printf a
#define	DEBUG6(a)	if (ldterm_debug >= 6) printf a
#define	DEBUG7(a)	if (ldterm_debug >= 7) printf a
#else
#define	DEBUG1(a)
#define	DEBUG2(a)
#define	DEBUG3(a)
#define	DEBUG4(a)
#define	DEBUG5(a)
#define	DEBUG6(a)
#define	DEBUG7(a)
#endif		/* LDDEBUG */


/*
 * Since most of the buffering occurs either at the stream head or in
 * the "message currently being assembled" buffer, we have a
 * relatively small input queue, so that blockages above us get
 * reflected fairly quickly to the module below us.  We also have a
 * small maximum packet size, since you can put a message of that
 * size on an empty queue no matter how much bigger than the high
 * water mark it is.
 */
static struct module_info ldtermmiinfo = {
	0x0bad,
	"ldterm",
	0,
	_TTY_BUFSIZ,
	_TTY_BUFSIZ,
	LOWAT
};


static struct qinit ldtermrinit = {
	(int (*)())ldtermrput,
	(int (*)())ldtermrsrv,
	ldtermopen,
	ldtermclose,
	NULL,
	&ldtermmiinfo
};


static struct module_info ldtermmoinfo = {
	0x0bad,
	"ldterm",
	0,
	INFPSZ,
	1,
	0
};


static struct qinit ldtermwinit = {
	(int (*)())ldtermwput,
	(int (*)())ldtermwsrv,
	ldtermopen,
	ldtermclose,
	NULL,
	&ldtermmoinfo
};


static struct streamtab ldtrinfo = {
	&ldtermrinit,
	&ldtermwinit,
	NULL,
	NULL
};

/*
 * Dummy qbufcall callback routine used by open and close.
 * The framework will wake up qwait_sig when we return from
 * this routine (as part of leaving the perimeters.)
 * (The framework enters the perimeters before calling the qbufcall() callback
 * and leaves the perimeters after the callback routine has executed. The
 * framework performs an implicit wakeup of any thread in qwait/qwait_sig
 * when it leaves the perimeter. See qwait(9E).)
 */
/* ARGSUSED */
static void
dummy_callback(void *arg)
{}


static mblk_t *
open_ioctl(queue_t *q, uint_t cmd)
{
	mblk_t *mp;
	bufcall_id_t id;
	int retv;

	while ((mp = mkiocb(cmd)) == NULL) {
		id = qbufcall(q, sizeof (struct iocblk), BPRI_MED,
		    dummy_callback, NULL);
		retv = qwait_sig(q);
		qunbufcall(q, id);
		if (retv == 0)
			break;
	}
	return (mp);
}

static mblk_t *
open_mblk(queue_t *q, size_t len)
{
	mblk_t *mp;
	bufcall_id_t id;
	int retv;

	while ((mp = allocb(len, BPRI_MED)) == NULL) {
		id = qbufcall(q, len, BPRI_MED, dummy_callback, NULL);
		retv = qwait_sig(q);
		qunbufcall(q, id);
		if (retv == 0)
			break;
	}
	return (mp);
}

/*
 * Line discipline open.
 */
/* ARGSUSED1 */
static int
ldtermopen(queue_t *q, dev_t *devp, int oflag, int sflag, cred_t *crp)
{
	ldtermstd_state_t *tp;
	mblk_t *bp, *qryp;
	int len;
	struct stroptions *strop;
	struct termios *termiosp;
	queue_t *wq;

	if (q->q_ptr != NULL) {
		return (0);	/* already attached */
	}

	tp = (ldtermstd_state_t *)kmem_zalloc(sizeof (ldtermstd_state_t),
	    KM_SLEEP);

	/*
	 * Get termios defaults.  These are stored as
	 * a property in the "options" node.
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, ddi_root_node(), DDI_PROP_NOTPROM,
	    "ttymodes", (caddr_t)&termiosp, &len) == DDI_PROP_SUCCESS &&
	    len == sizeof (struct termios)) {
		tp->t_modes = *termiosp;
		tp->t_amodes = *termiosp;
		kmem_free(termiosp, len);
	} else {
		/*
		 * Gack!  Whine about it.
		 */
		cmn_err(CE_WARN, "ldterm: Couldn't get ttymodes property!");
	}
	bzero(&tp->t_dmodes, sizeof (struct termios));

	tp->t_state = 0;

	tp->t_line = 0;
	tp->t_col = 0;

	tp->t_rocount = 0;
	tp->t_rocol = 0;

	tp->t_message = NULL;
	tp->t_endmsg = NULL;
	tp->t_msglen = 0;
	tp->t_rd_request = 0;

	tp->t_echomp = NULL;
	tp->t_iocid = 0;
	tp->t_wbufcid = 0;
	tp->t_vtid = 0;

	q->q_ptr = (caddr_t)tp;
	WR(q)->q_ptr = (caddr_t)tp;
	/*
	 * The following for EUC and also non-EUC codesets:
	 */
	tp->t_codeset = tp->t_eucleft = tp->t_eucign = tp->t_scratch_len = 0;
	bzero(&tp->eucwioc, EUCSIZE);
	tp->eucwioc.eucw[0] = 1;	/* ASCII mem & screen width */
	tp->eucwioc.scrw[0] = 1;
	tp->t_maxeuc = 1;	/* the max len in bytes of an EUC char */
	tp->t_eucp = NULL;
	tp->t_eucp_mp = NULL;
	tp->t_eucwarn = 0;	/* no bad chars seen yet */

	tp->t_csdata = default_cs_data;
	tp->t_csmethods = cs_methods[LDTERM_CS_TYPE_EUC];

	qprocson(q);

	/*
	 * Find out if the module below us does canonicalization; if
	 * so, we won't do it ourselves.
	 */

	if ((qryp = open_ioctl(q, MC_CANONQUERY)) == NULL)
		goto open_abort;

	/*
	 * Reformulate as an M_CTL message. The actual data will
	 * be in the b_cont field.
	 */
	qryp->b_datap->db_type = M_CTL;
	wq = OTHERQ(q);
	putnext(wq, qryp);

	/* allocate a TCSBRK ioctl in case we'll need it on close */
	if ((qryp = open_ioctl(q, TCSBRK)) == NULL)
		goto open_abort;
	tp->t_drainmsg = qryp;
	if ((bp = open_mblk(q, sizeof (int))) == NULL)
		goto open_abort;
	qryp->b_cont = bp;

	/*
	 * Find out if the underlying driver supports proper POSIX close
	 * semantics.  If not, we'll have to approximate it using TCSBRK.  If
	 * it does, it will respond with MC_HAS_POSIX, and we'll catch that in
	 * the ldtermrput routine.
	 *
	 * When the ldterm_drain_limit tunable is set to zero, we behave the
	 * same as old ldterm: don't send this new message, and always use
	 * TCSBRK during close.
	 */
	if (ldterm_drain_limit != 0) {
		if ((qryp = open_ioctl(q, MC_POSIXQUERY)) == NULL)
			goto open_abort;
		qryp->b_datap->db_type = M_CTL;
		putnext(wq, qryp);
	}

	/* prepare to clear the water marks on close */
	if ((bp = open_mblk(q, sizeof (struct stroptions))) == NULL)
		goto open_abort;
	tp->t_closeopts = bp;

	/*
	 * Set the high-water and low-water marks on the stream head
	 * to values appropriate for a terminal.  Also set the "vmin"
	 * and "vtime" values to 1 and 0, turn on message-nondiscard
	 * mode (as we're in ICANON mode), and turn on "old-style
	 * NODELAY" mode.
	 */
	if ((bp = open_mblk(q, sizeof (struct stroptions))) == NULL)
		goto open_abort;
	strop = (struct stroptions *)bp->b_wptr;
	strop->so_flags = SO_READOPT|SO_HIWAT|SO_LOWAT|SO_NDELON|SO_ISTTY;
	strop->so_readopt = RMSGN;
	strop->so_hiwat = _TTY_BUFSIZ;
	strop->so_lowat = LOWAT;
	bp->b_wptr += sizeof (struct stroptions);
	bp->b_datap->db_type = M_SETOPTS;
	putnext(q, bp);

	return (0);		/* this can become a controlling TTY */

open_abort:
	qprocsoff(q);
	q->q_ptr = NULL;
	WR(q)->q_ptr = NULL;
	freemsg(tp->t_closeopts);
	freemsg(tp->t_drainmsg);
	/* Dump the state structure */
	kmem_free(tp, sizeof (ldtermstd_state_t));
	return (EINTR);
}

struct close_timer {
	timeout_id_t id;
	ldtermstd_state_t *tp;
};

static void
drain_timed_out(void *arg)
{
	struct close_timer *ctp = arg;

	ctp->id = 0;
	ctp->tp->t_state &= ~TS_IOCWAIT;
}

/* ARGSUSED2 */
static int
ldtermclose(queue_t *q, int cflag, cred_t *crp)
{
	ldtermstd_state_t *tp = (ldtermstd_state_t *)q->q_ptr;
	struct stroptions *strop;
	mblk_t *bp;
	struct close_timer cltimer;

	/*
	 * If we have an outstanding vmin timeout, cancel it.
	 */
	tp->t_state |= TS_CLOSE;
	if (tp->t_vtid != 0)
		(void) quntimeout(q, tp->t_vtid);
	tp->t_vtid = 0;

	/*
	 * Cancel outstanding qbufcall request.
	 */
	if (tp->t_wbufcid != 0)
		qunbufcall(q, tp->t_wbufcid);

	/*
	 * Reset the high-water and low-water marks on the stream
	 * head (?), turn on byte-stream mode, and turn off
	 * "old-style NODELAY" mode.
	 */
	bp = tp->t_closeopts;
	strop = (struct stroptions *)bp->b_wptr;
	strop->so_flags = SO_READOPT|SO_NDELOFF;
	strop->so_readopt = RNORM;
	bp->b_wptr += sizeof (struct stroptions);
	bp->b_datap->db_type = M_SETOPTS;
	putnext(q, bp);

	if (cflag & (FNDELAY|FNONBLOCK)) {
		freemsg(tp->t_drainmsg);
	} else if ((bp = tp->t_drainmsg) != NULL) {
		struct iocblk *iocb;

		/*
		 * If the driver isn't known to have POSIX close semantics,
		 * then we have to emulate this the old way.  This is done by
		 * sending down TCSBRK,1 to drain the output and waiting for
		 * the reply.
		 */
		iocb = (struct iocblk *)bp->b_rptr;
		iocb->ioc_count = sizeof (int);
		*(int *)bp->b_cont->b_rptr = 1;
		bp->b_cont->b_wptr += sizeof (int);
		tp->t_state |= TS_IOCWAIT;
		tp->t_iocid = iocb->ioc_id;
		if (!putq(WR(q), bp))
			putnext(WR(q), bp);

		/*
		 * If we're not able to receive signals at this point, then
		 * launch a timer.  This timer will prevent us from waiting
		 * forever for a signal that won't arrive.
		 */
		cltimer.id = 0;
		if (!ddi_can_receive_sig() && ldterm_drain_limit != 0) {
			cltimer.tp = tp;
			cltimer.id = qtimeout(q, drain_timed_out, &cltimer,
			    drv_usectohz(ldterm_drain_limit));
		}

		/*
		 * Note that the read side of ldterm and the qtimeout are
		 * protected by D_MTQPAIR, so no additional locking is needed
		 * here.
		 */
		while (tp->t_state & TS_IOCWAIT) {
			if (qwait_sig(q) == 0)
				break;
		}
		if (cltimer.id != 0)
			(void) quntimeout(q, cltimer.id);
	}

	/*
	 * From here to the end, the routine does not sleep and does not
	 * reference STREAMS, so it's guaranteed to run to completion.
	 */

	qprocsoff(q);

	freemsg(tp->t_message);
	freemsg(tp->t_eucp_mp);

	/* Dump the state structure, then unlink it */
	if (tp->t_csdata.locale_name != NULL)
		kmem_free(tp->t_csdata.locale_name,
		    strlen(tp->t_csdata.locale_name) + 1);
	kmem_free(tp, sizeof (ldtermstd_state_t));
	q->q_ptr = NULL;
	return (0);
}


/*
 * Put procedure for input from driver end of stream (read queue).
 */
static void
ldtermrput(queue_t *q, mblk_t *mp)
{
	ldtermstd_state_t *tp;
	unsigned char c;
	queue_t *wrq = WR(q);		/* write queue of ldterm mod */
	queue_t *nextq = q->q_next;	/* queue below us */
	mblk_t *bp;
	struct iocblk *qryp;
	unsigned char *readp;
	unsigned char *writep;
	struct termios *emodes;		/* effective modes set by driver */
	int dbtype;

	tp = (ldtermstd_state_t *)q->q_ptr;
	/*
	 * We received our ack from the driver saying there is nothing left to
	 * shovel out, so wake up the close routine.
	 */
	dbtype = DB_TYPE(mp);
	if ((dbtype == M_IOCACK || dbtype == M_IOCNAK) &&
	    (tp->t_state & (TS_CLOSE|TS_IOCWAIT)) == (TS_CLOSE|TS_IOCWAIT)) {
		struct iocblk *iocp = (struct iocblk *)mp->b_rptr;

		if (iocp->ioc_id == tp->t_iocid) {
			tp->t_state &= ~TS_IOCWAIT;
			freemsg(mp);
			return;
		}
	}

	switch (dbtype) {

	default:
		(void) putq(q, mp);
		return;

		/*
		 * Send these up unmolested
		 *
		 */
	case M_PCSIG:
	case M_SIG:
	case M_IOCNAK:

		putnext(q, mp);
		return;

	case M_IOCACK:

		ldterm_ioctl_reply(q, mp);
		return;

	case M_BREAK:

		/*
		 * Parity errors are sent up as M_BREAKS with single
		 * character data (formerly handled in the driver)
		 */
		if (mp->b_wptr - mp->b_rptr == 1) {
			/*
			 * IGNPAR	PARMRK		RESULT
			 * off		off		0
			 * off		on		3 byte sequence
			 * on		either		ignored
			 */
			if (!(tp->t_amodes.c_iflag & IGNPAR)) {
				mp->b_wptr = mp->b_rptr;
				if (tp->t_amodes.c_iflag & PARMRK) {
					unsigned char c;

					c = *mp->b_rptr;
					freemsg(mp);
					if ((mp = allocb(3, BPRI_HI)) == NULL) {
						cmn_err(CE_WARN,
						    "ldtermrput: no blocks");
						return;
					}
					mp->b_datap->db_type = M_DATA;
					*mp->b_wptr++ = (uchar_t)'\377';
					*mp->b_wptr++ = '\0';
					*mp->b_wptr++ = c;
					putnext(q, mp);
				} else {
					mp->b_datap->db_type = M_DATA;
					*mp->b_wptr++ = '\0';
					putnext(q, mp);
				}
			} else {
				freemsg(mp);
			}
			return;
		}
		/*
		 * We look at the apparent modes here instead of the
		 * effective modes. Effective modes cannot be used if
		 * IGNBRK, BRINT and PARMRK have been negotiated to
		 * be handled by the driver. Since M_BREAK should be
		 * sent upstream only if break processing was not
		 * already done, it should be ok to use the apparent
		 * modes.
		 */

		if (!(tp->t_amodes.c_iflag & IGNBRK)) {
			if (tp->t_amodes.c_iflag & BRKINT) {
				ldterm_dosig(q, SIGINT, '\0', M_PCSIG, FLUSHRW);
				freemsg(mp);
			} else if (tp->t_amodes.c_iflag & PARMRK) {
				/*
				 * Send '\377','\0', '\0'.
				 */
				freemsg(mp);
				if ((mp = allocb(3, BPRI_HI)) == NULL) {
					cmn_err(CE_WARN,
					    "ldtermrput: no blocks");
					return;
				}
				mp->b_datap->db_type = M_DATA;
				*mp->b_wptr++ = (uchar_t)'\377';
				*mp->b_wptr++ = '\0';
				*mp->b_wptr++ = '\0';
				putnext(q, mp);
			} else {
				/*
				 * Act as if a '\0' came in.
				 */
				freemsg(mp);
				if ((mp = allocb(1, BPRI_HI)) == NULL) {
					cmn_err(CE_WARN,
					    "ldtermrput: no blocks");
					return;
				}
				mp->b_datap->db_type = M_DATA;
				*mp->b_wptr++ = '\0';
				putnext(q, mp);
			}
		} else {
			freemsg(mp);
		}
		return;

	case M_CTL:
		DEBUG3(("ldtermrput: M_CTL received\n"));
		/*
		 * The M_CTL has been standardized to look like an
		 * M_IOCTL message.
		 */

		if ((mp->b_wptr - mp->b_rptr) != sizeof (struct iocblk)) {
			DEBUG3((
			    "Non standard M_CTL received by ldterm module\n"));
			/* May be for someone else; pass it on */
			putnext(q, mp);
			return;
		}
		qryp = (struct iocblk *)mp->b_rptr;

		switch (qryp->ioc_cmd) {

		case MC_PART_CANON:

			DEBUG3(("ldtermrput: M_CTL Query Reply\n"));
			if (!mp->b_cont) {
				DEBUG3(("No information in Query Message\n"));
				break;
			}
			if ((mp->b_cont->b_wptr - mp->b_cont->b_rptr) ==
			    sizeof (struct termios)) {
				DEBUG3(("ldtermrput: M_CTL GrandScheme\n"));
				/* elaborate turning off scheme */
				emodes = (struct termios *)mp->b_cont->b_rptr;
				bcopy(emodes, &tp->t_dmodes,
					sizeof (struct termios));
				ldterm_adjust_modes(tp);
				break;
			} else {
				DEBUG3(("Incorrect query replysize\n"));
				break;
			}

		case MC_NO_CANON:
			tp->t_state |= TS_NOCANON;
			/*
			 * Note: this is very nasty.  It's not clear
			 * what the right thing to do with a partial
			 * message is; We throw it out
			 */
			if (tp->t_message != NULL) {
				freemsg(tp->t_message);
				tp->t_message = NULL;
				tp->t_endmsg = NULL;
				tp->t_msglen = 0;
				tp->t_rocount = 0;
				tp->t_rocol = 0;
				if (tp->t_state & TS_MEUC) {
					ASSERT(tp->t_eucp_mp);
					tp->t_eucp = tp->t_eucp_mp->b_rptr;
					tp->t_codeset = 0;
					tp->t_eucleft = 0;
				}
			}
			break;

		case MC_DO_CANON:
			tp->t_state &= ~TS_NOCANON;
			break;

		case MC_HAS_POSIX:
			/* no longer any reason to drain from ldterm */
			if (ldterm_drain_limit != 0) {
				freemsg(tp->t_drainmsg);
				tp->t_drainmsg = NULL;
			}
			break;

		default:
			DEBUG3(("Unknown M_CTL Message\n"));
			break;
		}
		putnext(q, mp);	/* In case anyone else has to see it */
		return;

	case M_FLUSH:
		/*
		 * Flush everything we haven't looked at yet.
		 */

		if ((tp->t_state & TS_ISPTSTTY) && (*mp->b_rptr & FLUSHBAND))
			flushband(q, *(mp->b_rptr + 1), FLUSHDATA);
		else
			flushq(q, FLUSHDATA);

		/*
		 * Flush everything we have looked at.
		 */
		freemsg(tp->t_message);
		tp->t_message = NULL;
		tp->t_endmsg = NULL;
		tp->t_msglen = 0;
		tp->t_rocount = 0;
		tp->t_rocol = 0;
		if (tp->t_state & TS_MEUC) {	/* EUC multi-byte */
			ASSERT(tp->t_eucp_mp);
			tp->t_eucp = tp->t_eucp_mp->b_rptr;
		}
		putnext(q, mp);	/* pass it on */

		/*
		 * Relieve input flow control
		 */
		if ((tp->t_modes.c_iflag & IXOFF) &&
		    (tp->t_state & TS_TBLOCK) &&
		    !(tp->t_state & TS_IFBLOCK) && q->q_count <= TTXOLO) {
			tp->t_state &= ~TS_TBLOCK;
			(void) putnextctl(wrq, M_STARTI);
			DEBUG1(("M_STARTI down\n"));
		}
		return;

	case M_DATA:
		break;
	}
	(void) drv_setparm(SYSRAWC, msgdsize(mp));

	/*
	 * Flow control: send "start input" message if blocked and
	 * our queue is below its low water mark.
	 */
	if ((tp->t_modes.c_iflag & IXOFF) && (tp->t_state & TS_TBLOCK) &&
	    !(tp->t_state & TS_IFBLOCK) && q->q_count <= TTXOLO) {
		tp->t_state &= ~TS_TBLOCK;
		(void) putnextctl(wrq, M_STARTI);
		DEBUG1(("M_STARTI down\n"));
	}
	/*
	 * If somebody below us ("intelligent" communications
	 * board, pseudo-tty controlled by an editor) is doing
	 * canonicalization, don't scan it for special characters.
	 */
	if (tp->t_state & TS_NOCANON) {
		(void) putq(q, mp);
		return;
	}
	bp = mp;

	do {
		readp = bp->b_rptr;
		writep = readp;
		if (tp->t_modes.c_iflag & (INLCR|IGNCR|ICRNL|IUCLC|IXON) ||
		    tp->t_modes.c_lflag & (ISIG|ICANON)) {
			/*
			 * We're doing some sort of non-trivial
			 * processing of input; look at every
			 * character.
			 */
			while (readp < bp->b_wptr) {
				c = *readp++;

				if (tp->t_modes.c_iflag & ISTRIP)
					c &= 0177;

				/*
				 * First, check that this hasn't been
				 * escaped with the "literal next"
				 * character.
				 */
				if (tp->t_state & TS_PLNCH) {
					tp->t_state &= ~TS_PLNCH;
					tp->t_modes.c_lflag &= ~FLUSHO;
					*writep++ = c;
					continue;
				}
				/*
				 * Setting a special character to NUL
				 * disables it, so if this character
				 * is NUL, it should not be compared
				 * with any of the special characters.
				 * It should, however, restart frozen
				 * output if IXON and IXANY are set.
				 */
				if (c == _POSIX_VDISABLE) {
					if (tp->t_modes.c_iflag & IXON &&
					    tp->t_state & TS_TTSTOP &&
					    tp->t_modes.c_lflag & IEXTEN &&
					    tp->t_modes.c_iflag & IXANY) {
						tp->t_state &=
						    ~(TS_TTSTOP|TS_OFBLOCK);
						(void) putnextctl(wrq, M_START);
					}
					tp->t_modes.c_lflag &= ~FLUSHO;
					*writep++ = c;
					continue;
				}
				/*
				 * If stopped, start if you can; if
				 * running, stop if you must.
				 */
				if (tp->t_modes.c_iflag & IXON) {
					if (tp->t_state & TS_TTSTOP) {
						if (c ==
						    tp->t_modes.c_cc[VSTART] ||
						    (tp->t_modes.c_lflag &
						    IEXTEN &&
						    tp->t_modes.c_iflag &
						    IXANY)) {
							tp->t_state &=
							    ~(TS_TTSTOP |
							    TS_OFBLOCK);
							(void) putnextctl(wrq,
							    M_START);
						}
					} else {
						if (c ==
						    tp->t_modes.c_cc[VSTOP]) {
							tp->t_state |=
							    TS_TTSTOP;
							(void) putnextctl(wrq,
							    M_STOP);
						}
					}
					if (c == tp->t_modes.c_cc[VSTOP] ||
					    c == tp->t_modes.c_cc[VSTART])
						continue;
				}
				/*
				 * Check for "literal next" character
				 * and "flush output" character.
				 * Note that we omit checks for ISIG
				 * and ICANON, since the IEXTEN
				 * setting subsumes them.
				 */
				if (tp->t_modes.c_lflag & IEXTEN) {
					if (c == tp->t_modes.c_cc[VLNEXT]) {
						/*
						 * Remember that we saw a
						 * "literal next" while
						 * scanning input, but leave
						 * leave it in the message so
						 * that the service routine
						 * can see it too.
						 */
						tp->t_state |= TS_PLNCH;
						tp->t_modes.c_lflag &= ~FLUSHO;
						*writep++ = c;
						continue;
					}
					if (c == tp->t_modes.c_cc[VDISCARD]) {
						ldterm_flush_output(c, wrq, tp);
						continue;
					}
				}
				tp->t_modes.c_lflag &= ~FLUSHO;

				/*
				 * Check for signal-generating
				 * characters.
				 */
				if (tp->t_modes.c_lflag & ISIG) {
					if (c == tp->t_modes.c_cc[VINTR]) {
						ldterm_dosig(q, SIGINT, c,
						    M_PCSIG, FLUSHRW);
						continue;
					}
					if (c == tp->t_modes.c_cc[VQUIT]) {
						ldterm_dosig(q, SIGQUIT, c,
						    M_PCSIG, FLUSHRW);
						continue;
					}
					if (c == tp->t_modes.c_cc[VSWTCH]) {
						/*
						 * Ancient SXT support; discard
						 * character without action.
						 */
						continue;
					}
					if (c == tp->t_modes.c_cc[VSUSP]) {
						ldterm_dosig(q, SIGTSTP, c,
						    M_PCSIG, FLUSHRW);
						continue;
					}
					if ((tp->t_modes.c_lflag & IEXTEN) &&
					    (c == tp->t_modes.c_cc[VDSUSP])) {
						ldterm_dosig(q, SIGTSTP, c,
						    M_SIG, 0);
						continue;
					}

					/*
					 * Consumers do not expect the ^T to be
					 * echoed out when we generate a
					 * VSTATUS.
					 */
					if (c == tp->t_modes.c_cc[VSTATUS]) {
						ldterm_dosig(q, SIGINFO, '\0',
						    M_PCSIG, FLUSHRW);
						continue;
					}
				}
				/*
				 * Throw away CR if IGNCR set, or
				 * turn it into NL if ICRNL set.
				 */
				if (c == '\r') {
					if (tp->t_modes.c_iflag & IGNCR)
						continue;
					if (tp->t_modes.c_iflag & ICRNL)
						c = '\n';
				} else {
					/*
					 * Turn NL into CR if INLCR
					 * set.
					 */
					if (c == '\n' &&
					    tp->t_modes.c_iflag & INLCR)
						c = '\r';
				}

				/*
				 * Map upper case input to lower case
				 * if IUCLC flag set.
				 */
				if (tp->t_modes.c_iflag & IUCLC &&
				    c >= 'A' && c <= 'Z')
					c += 'a' - 'A';

				/*
				 * Put the possibly-transformed
				 * character back in the message.
				 */
				*writep++ = c;
			}

			/*
			 * If we didn't copy some characters because
			 * we were ignoring them, fix the size of the
			 * data block by adjusting the write pointer.
			 * XXX This may result in a zero-length
			 * block; will this cause anybody gastric
			 * distress?
			 */
			bp->b_wptr -= (readp - writep);
		} else {
			/*
			 * We won't be doing anything other than
			 * possibly stripping the input.
			 */
			if (tp->t_modes.c_iflag & ISTRIP) {
				while (readp < bp->b_wptr)
					*writep++ = *readp++ & 0177;
			}
			tp->t_modes.c_lflag &= ~FLUSHO;
		}

	} while ((bp = bp->b_cont) != NULL);	/* next block, if any */

	/*
	 * Queue the message for service procedure if the
	 * queue is not empty or canputnext() fails or
	 * tp->t_state & TS_RESCAN is true.
	 */

	if (q->q_first != NULL || !bcanputnext(q, mp->b_band) ||
	    (tp->t_state & TS_RESCAN))
		(void) putq(q, mp);
	else
		(void) ldtermrmsg(q, mp);

	/*
	 * Flow control: send "stop input" message if our queue is
	 * approaching its high-water mark. The message will be
	 * dropped on the floor in the service procedure, if we
	 * cannot ship it up and we have had it upto our neck!
	 *
	 * Set QWANTW to ensure that the read queue service procedure
	 * gets run when nextq empties up again, so that it can
	 * unstop the input.
	 */
	if ((tp->t_modes.c_iflag & IXOFF) && !(tp->t_state & TS_TBLOCK) &&
	    q->q_count >= TTXOHI) {
		mutex_enter(QLOCK(nextq));
		nextq->q_flag |= QWANTW;
		mutex_exit(QLOCK(nextq));
		tp->t_state |= TS_TBLOCK;
		(void) putnextctl(wrq, M_STOPI);
		DEBUG1(("M_STOPI down\n"));
	}
}


/*
 * Line discipline input server processing.  Erase/kill and escape
 * ('\') processing, gathering into messages, upper/lower case input
 * mapping.
 */
static void
ldtermrsrv(queue_t *q)
{
	ldtermstd_state_t *tp;
	mblk_t *mp;

	tp = (ldtermstd_state_t *)q->q_ptr;

	if (tp->t_state & TS_RESCAN) {
		/*
		 * Canonicalization was turned on or off. Put the
		 * message being assembled back in the input queue,
		 * so that we rescan it.
		 */
		if (tp->t_message != NULL) {
			DEBUG5(("RESCAN WAS SET; put back in q\n"));
			if (tp->t_msglen != 0)
				(void) putbq(q, tp->t_message);
			else
				freemsg(tp->t_message);
			tp->t_message = NULL;
			tp->t_endmsg = NULL;
			tp->t_msglen = 0;
		}
		if (tp->t_state & TS_MEUC) {
			ASSERT(tp->t_eucp_mp);
			tp->t_eucp = tp->t_eucp_mp->b_rptr;
			tp->t_codeset = 0;
			tp->t_eucleft = 0;
		}
		tp->t_state &= ~TS_RESCAN;
	}

	while ((mp = getq(q)) != NULL) {
		if (!ldtermrmsg(q, mp))
			break;
	}

	/*
	 * Flow control: send start message if blocked and our queue
	 * is below its low water mark.
	 */
	if ((tp->t_modes.c_iflag & IXOFF) && (tp->t_state & TS_TBLOCK) &&
	    !(tp->t_state & TS_IFBLOCK) && q->q_count <= TTXOLO) {
		tp->t_state &= ~TS_TBLOCK;
		(void) putctl(WR(q), M_STARTI);
	}
}

/*
 * This routine is called from both ldtermrput and ldtermrsrv to
 * do the actual work of dealing with mp. Return 1 on sucesss and
 * 0 on failure.
 */
static int
ldtermrmsg(queue_t *q, mblk_t *mp)
{
	unsigned char c;
	int dofree;
	int status = 1;
	size_t   ebsize;
	mblk_t *bp;
	mblk_t *bpt;
	ldtermstd_state_t *tp;

	bpt = NULL;

	tp = (ldtermstd_state_t *)q->q_ptr;

	if (mp->b_datap->db_type <= QPCTL && !bcanputnext(q, mp->b_band)) {
		/*
		 * Stream head is flow controlled. If echo is
		 * turned on, flush the read side or send a
		 * bell down the line to stop input and
		 * process the current message.
		 * Otherwise(putbq) the user will not see any
		 * response to to the typed input. Typically
		 * happens if there is no reader process.
		 * Note that you will loose the data in this
		 * case if the data is coming too fast. There
		 * is an assumption here that if ECHO is
		 * turned on its some user typing the data on
		 * a terminal and its not network.
		 */
		if (tp->t_modes.c_lflag & ECHO) {
			if ((tp->t_modes.c_iflag & IMAXBEL) &&
			    (tp->t_modes.c_lflag & ICANON)) {
				freemsg(mp);
				if (canputnext(WR(q)))
					ldterm_outchar(CTRL('g'), WR(q), 4, tp);
				status = 0;
				goto echo;
			} else {
				(void) putctl1(q, M_FLUSH, FLUSHR);
			}
		} else {
			(void) putbq(q, mp);
			status = 0;
			goto out;	/* read side is blocked */
		}
	}
	switch (mp->b_datap->db_type) {

	default:
		putnext(q, mp);	/* pass it on */
		goto out;

	case M_HANGUP:
		/*
		 * Flush everything we haven't looked at yet.
		 */
		flushq(q, FLUSHDATA);

		/*
		 * Flush everything we have looked at.
		 */
		freemsg(tp->t_message);
		tp->t_message = NULL;
		tp->t_endmsg = NULL;
		tp->t_msglen = 0;
		/*
		 * XXX  should we set read request
		 * tp->t_rd_request to NULL?
		 */
		tp->t_rocount = 0;	/* if it hasn't been typed */
		tp->t_rocol = 0;	/* it hasn't been echoed :-) */
		if (tp->t_state & TS_MEUC) {
			ASSERT(tp->t_eucp_mp);
			tp->t_eucp = tp->t_eucp_mp->b_rptr;
		}
		/*
		 * Restart output, since it's probably got
		 * nowhere to go anyway, and we're probably
		 * not going to see another ^Q for a while.
		 */
		if (tp->t_state & TS_TTSTOP) {
			tp->t_state &= ~(TS_TTSTOP|TS_OFBLOCK);
			(void) putnextctl(WR(q), M_START);
		}
		/*
		 * This message will travel up the read
		 * queue, flushing as it goes, get turned
		 * around at the stream head, and travel back
		 * down the write queue, flushing as it goes.
		 */
		(void) putnextctl1(q, M_FLUSH, FLUSHW);

		/*
		 * This message will travel down the write
		 * queue, flushing as it goes, get turned
		 * around at the driver, and travel back up
		 * the read queue, flushing as it goes.
		 */
		(void) putctl1(WR(q), M_FLUSH, FLUSHR);

		/*
		 * Now that that's done, we send a SIGCONT
		 * upstream, followed by the M_HANGUP.
		 */
		/* (void) putnextctl1(q, M_PCSIG, SIGCONT); */
		putnext(q, mp);
		goto out;

	case M_IOCACK:

		/*
		 * Augment whatever information the driver is
		 * returning  with the information we supply.
		 */
		ldterm_ioctl_reply(q, mp);
		goto out;

	case M_DATA:
		break;
	}

	/*
	 * This is an M_DATA message.
	 */

	/*
	 * If somebody below us ("intelligent" communications
	 * board, pseudo-tty controlled by an editor) is
	 * doing canonicalization, don't scan it for special
	 * characters.
	 */
	if (tp->t_state & TS_NOCANON) {
		putnext(q, mp);
		goto out;
	}
	bp = mp;

	if ((bpt = newmsg(tp)) != NULL) {
		mblk_t *bcont;

		do {
			ASSERT(bp->b_wptr >= bp->b_rptr);
			ebsize = bp->b_wptr - bp->b_rptr;
			if (ebsize > EBSIZE)
				ebsize = EBSIZE;
			bcont = bp->b_cont;
			if (CANON_MODE) {
				/*
				 * By default, free the message once processed
				 */
				dofree = 1;

				/*
				 * update sysinfo canch
				 * character. The value of
				 * canch may vary as compared
				 * to character tty
				 * implementation.
				 */
				while (bp->b_rptr < bp->b_wptr) {
					c = *bp->b_rptr++;
					if ((bpt = ldterm_docanon(c,
					    bpt, ebsize, q, tp, &dofree)) ==
					    NULL)
						break;
				}
				/*
				 * Release this block or put back on queue.
				 */
				if (dofree)
					freeb(bp);
				else {
					(void) putbq(q, bp);
					break;
				}
			} else
				bpt = ldterm_dononcanon(bp, bpt, ebsize, q, tp);
			if (bpt == NULL) {
				cmn_err(CE_WARN,
				    "ldtermrsrv: out of blocks");
				freemsg(bcont);
				break;
			}
		} while ((bp = bcont) != NULL);
	}
echo:
	/*
	 * Send whatever we echoed downstream.
	 */
	if (tp->t_echomp != NULL) {
		if (canputnext(WR(q)))
			putnext(WR(q), tp->t_echomp);
		else
			freemsg(tp->t_echomp);
		tp->t_echomp = NULL;
	}

out:
	return (status);
}


/*
 * Do canonical mode input; check whether this character is to be
 * treated as a special character - if so, check whether it's equal
 * to any of the special characters and handle it accordingly.
 * Otherwise, just add it to the current line.
 */
static mblk_t *
ldterm_docanon(uchar_t c, mblk_t *bpt, size_t ebsize, queue_t *q,
    ldtermstd_state_t *tp, int *dofreep)
{
	queue_t *wrq = WR(q);
	int i;

	/*
	 * If the previous character was the "literal next"
	 * character, treat this character as regular input.
	 */
	if (tp->t_state & TS_SLNCH)
		goto escaped;

	/*
	 * Setting a special character to NUL disables it, so if this
	 * character is NUL, it should not be compared with any of
	 * the special characters.
	 */
	if (c == _POSIX_VDISABLE) {
		tp->t_state &= ~TS_QUOT;
		goto escaped;
	}
	/*
	 * If this character is the literal next character, echo it
	 * as '^', backspace over it, and record that fact.
	 */
	if ((tp->t_modes.c_lflag & IEXTEN) && c == tp->t_modes.c_cc[VLNEXT]) {
		if (tp->t_modes.c_lflag & ECHO)
			ldterm_outstring((unsigned char *)"^\b", 2, wrq,
			    ebsize, tp);
		tp->t_state |= TS_SLNCH;
		goto out;
	}
	/*
	 * Check for the editing character. If the display width of
	 * the last byte at the canonical buffer is not one and also
	 * smaller than or equal to UNKNOWN_WIDTH, the character at
	 * the end of the buffer is a multi-byte and/or multi-column
	 * character.
	 */
	if (c == tp->t_modes.c_cc[VERASE] || c == tp->t_modes.c_cc[VERASE2]) {
		if (tp->t_state & TS_QUOT) {
			/*
			 * Get rid of the backslash, and put the
			 * erase character in its place.
			 */
			ldterm_erase(wrq, ebsize, tp);
			bpt = tp->t_endmsg;
			goto escaped;
		} else {
			if ((tp->t_state & TS_MEUC) && tp->t_msglen &&
			    (*(tp->t_eucp - 1) != 1 &&
			    *(tp->t_eucp - 1) <= UNKNOWN_WIDTH))
				ldterm_csi_erase(wrq, ebsize, tp);
			else
				ldterm_erase(wrq, ebsize, tp);
			bpt = tp->t_endmsg;
			goto out;
		}
	}
	if ((tp->t_modes.c_lflag & IEXTEN) && c == tp->t_modes.c_cc[VWERASE]) {
		/*
		 * Do "ASCII word" or "multibyte character token/chunk" erase.
		 */
		if (tp->t_state & TS_MEUC)
			ldterm_csi_werase(wrq, ebsize, tp);
		else
			ldterm_werase(wrq, ebsize, tp);
		bpt = tp->t_endmsg;
		goto out;
	}
	if (c == tp->t_modes.c_cc[VKILL]) {
		if (tp->t_state & TS_QUOT) {
			/*
			 * Get rid of the backslash, and put the kill
			 * character in its place.
			 */
			ldterm_erase(wrq, ebsize, tp);
			bpt = tp->t_endmsg;
			goto escaped;
		} else {
			ldterm_kill(wrq, ebsize, tp);
			bpt = tp->t_endmsg;
			goto out;
		}
	}
	if ((tp->t_modes.c_lflag & IEXTEN) && c == tp->t_modes.c_cc[VREPRINT]) {
		ldterm_reprint(wrq, ebsize, tp);
		goto out;
	}
	/*
	 * If the preceding character was a backslash: if the current
	 * character is an EOF, get rid of the backslash and treat
	 * the EOF as data; if we're in XCASE mode and the current
	 * character is part of a backslash-X escape sequence,
	 * process it; otherwise, just treat the current character
	 * normally.
	 */
	if (tp->t_state & TS_QUOT) {
		tp->t_state &= ~TS_QUOT;
		if (c == tp->t_modes.c_cc[VEOF]) {
			/*
			 * EOF character. Since it's escaped, get rid
			 * of the backslash and put the EOF character
			 * in its place.
			 */
			ldterm_erase(wrq, ebsize, tp);
			bpt = tp->t_endmsg;
		} else {
			/*
			 * If we're in XCASE mode, and the current
			 * character is part of a backslash-X
			 * sequence, get rid of the backslash and
			 * replace the current character with what
			 * that sequence maps to.
			 */
			if ((tp->t_modes.c_lflag & XCASE) &&
			    imaptab[c] != '\0') {
				ldterm_erase(wrq, ebsize, tp);
				bpt = tp->t_endmsg;
				c = imaptab[c];
			}
		}
	} else {
		/*
		 * Previous character wasn't backslash; check whether
		 * this was the EOF character.
		 */
		if (c == tp->t_modes.c_cc[VEOF]) {
			/*
			 * EOF character. Don't echo it unless
			 * ECHOCTL is set, don't stuff it in the
			 * current line, but send the line up the
			 * stream.
			 */
			if ((tp->t_modes.c_lflag & ECHOCTL) &&
			    (tp->t_modes.c_lflag & IEXTEN) &&
			    (tp->t_modes.c_lflag & ECHO)) {
				i = ldterm_echo(c, wrq, ebsize, tp);
				while (i > 0) {
					ldterm_outchar('\b', wrq, ebsize, tp);
					i--;
				}
			}
			bpt->b_datap->db_type = M_DATA;
			ldterm_msg_upstream(q, tp);
			if (!canputnext(q)) {
				bpt = NULL;
				*dofreep = 0;
			} else {
				bpt = newmsg(tp);
				*dofreep = 1;
			}
			goto out;
		}
	}

escaped:
	/*
	 * First, make sure we can fit one WHOLE multi-byte char in the
	 * buffer.  This is one place where we have overhead even if
	 * not in multi-byte mode; the overhead is subtracting
	 * tp->t_maxeuc from MAX_CANON before checking.
	 *
	 * Allows MAX_CANON bytes in the buffer before throwing awaying
	 * the the overflow of characters.
	 */
	if ((tp->t_msglen > ((_TTY_BUFSIZ + 1) - (int)tp->t_maxeuc)) &&
	    !((tp->t_state & TS_MEUC) && tp->t_eucleft)) {

		/*
		 * Byte will cause line to overflow, or the next EUC
		 * won't fit: Ring the bell or discard all input, and
		 * don't save the byte away.
		 */
		if (tp->t_modes.c_iflag & IMAXBEL) {
			if (canputnext(wrq))
				ldterm_outchar(CTRL('g'), wrq, ebsize, tp);
			goto out;
		} else {
			/*
			 * MAX_CANON processing. free everything in
			 * the current line and start with the
			 * current character as the first character.
			 */
			DEBUG7(("ldterm_docanon: MAX_CANON processing\n"));
			freemsg(tp->t_message);
			tp->t_message = NULL;
			tp->t_endmsg = NULL;
			tp->t_msglen = 0;
			tp->t_rocount = 0;	/* if it hasn't been type */
			tp->t_rocol = 0;	/* it hasn't been echoed :-) */
			if (tp->t_state & TS_MEUC) {
				ASSERT(tp->t_eucp_mp);
				tp->t_eucp = tp->t_eucp_mp->b_rptr;
			}
			tp->t_state &= ~TS_SLNCH;
			bpt = newmsg(tp);
		}
	}
	/*
	 * Add the character to the current line.
	 */
	if (bpt->b_wptr >= bpt->b_datap->db_lim) {
		/*
		 * No more room in this mblk; save this one away, and
		 * allocate a new one.
		 */
		bpt->b_datap->db_type = M_DATA;
		if ((bpt = allocb(IBSIZE, BPRI_MED)) == NULL)
			goto out;

		/*
		 * Chain the new one to the end of the old one, and
		 * mark it as the last block in the current line.
		 */
		tp->t_endmsg->b_cont = bpt;
		tp->t_endmsg = bpt;
	}
	*bpt->b_wptr++ = c;
	tp->t_msglen++;		/* message length in BYTES */

	/*
	 * In multi-byte mode, we have to keep track of where we are.
	 * The first bytes of multi-byte chars get the full count for the
	 * whole character.  We don't do any column calculations
	 * here, but we need the information for when we do. We could
	 * come across cases where we are getting garbage on the
	 * line, but we're in multi-byte mode.  In that case, we may
	 * see ASCII controls come in the middle of what should have been a
	 * multi-byte character.  Call ldterm_eucwarn...eventually, a
	 * warning message will be printed about it.
	 */
	if (tp->t_state & TS_MEUC) {
		if (tp->t_eucleft) {	/* if in a multi-byte char already */
			--tp->t_eucleft;
			*tp->t_eucp++ = 0;	/* is a subsequent byte */
			if (c < (uchar_t)0x20)
				ldterm_eucwarn(tp);
		} else { /* is the first byte of a multi-byte, or is ASCII */
			if (ISASCII(c)) {
				*tp->t_eucp++ =
				    tp->t_csmethods.ldterm_dispwidth(c,
				    (void *)tp, tp->t_modes.c_lflag & ECHOCTL);
				tp->t_codeset = 0;
			} else {
				*tp->t_eucp++ =
				    tp->t_csmethods.ldterm_dispwidth(c,
				    (void *)tp, tp->t_modes.c_lflag & ECHOCTL);
				tp->t_eucleft =
				    tp->t_csmethods.ldterm_memwidth(c,
				    (void *)tp) - 1;
				tp->t_codeset = ldterm_codeset(
				    tp->t_csdata.codeset_type, c);
			}
		}
	}
	/*
	 * AT&T is concerned about the following but we aren't since
	 * we have already shipped code that works.
	 *
	 * EOL2/XCASE should be conditioned with IEXTEN to be truly
	 * POSIX conformant. This is going to cause problems for
	 * pre-SVR4.0 programs that don't know about IEXTEN. Hence
	 * EOL2/IEXTEN is not conditioned with IEXTEN.
	 */
	if (!(tp->t_state & TS_SLNCH) &&
	    (c == '\n' || (c != '\0' && (c == tp->t_modes.c_cc[VEOL] ||
	    (c == tp->t_modes.c_cc[VEOL2]))))) {
		/*
		 * || ((tp->t_modes.c_lflag & IEXTEN) && c ==
		 * tp->t_modes.c_cc[VEOL2]))))) {
		 */
		/*
		 * It's a line-termination character; send the line
		 * up the stream.
		 */
		bpt->b_datap->db_type = M_DATA;
		ldterm_msg_upstream(q, tp);
		if (tp->t_state & TS_MEUC) {
			ASSERT(tp->t_eucp_mp);
			tp->t_eucp = tp->t_eucp_mp->b_rptr;
		}
		if ((bpt = newmsg(tp)) == NULL)
			goto out;
	} else {
		/*
		 * Character was escaped with LNEXT.
		 */
		if (tp->t_rocount++ == 0)
			tp->t_rocol = tp->t_col;
		tp->t_state &= ~(TS_SLNCH|TS_QUOT);
		/*
		 * If the current character is a single byte and single
		 * column character and it is the backslash character and
		 * IEXTEN, then the state will have TS_QUOT.
		 */
		if ((c == '\\') && (tp->t_modes.c_lflag & IEXTEN) &&
		    (!(tp->t_state & TS_MEUC) ||
		    ((tp->t_state & TS_MEUC) && (!tp->t_eucleft))))
			tp->t_state |= TS_QUOT;
	}

	/*
	 * Echo it.
	 */
	if (tp->t_state & TS_ERASE) {
		tp->t_state &= ~TS_ERASE;
		if (tp->t_modes.c_lflag & ECHO)
			ldterm_outchar('/', wrq, ebsize, tp);
	}
	if (tp->t_modes.c_lflag & ECHO)
		(void) ldterm_echo(c, wrq, ebsize, tp);
	else {
		/*
		 * Echo NL when ECHO turned off, if ECHONL flag is
		 * set.
		 */
		if (c == '\n' && (tp->t_modes.c_lflag & ECHONL))
			ldterm_outchar(c, wrq, ebsize, tp);
	}

out:

	return (bpt);
}


static int
ldterm_unget(ldtermstd_state_t *tp)
{
	mblk_t *bpt;

	if ((bpt = tp->t_endmsg) == NULL)
		return (-1);	/* no buffers */
	if (bpt->b_rptr == bpt->b_wptr)
		return (-1);	/* zero-length record */
	tp->t_msglen--;		/* one fewer character */
	return (*--bpt->b_wptr);
}


static void
ldterm_trim(ldtermstd_state_t *tp)
{
	mblk_t *bpt;
	mblk_t *bp;

	ASSERT(tp->t_endmsg);
	bpt = tp->t_endmsg;

	if (bpt->b_rptr == bpt->b_wptr) {
		/*
		 * This mblk is now empty. Find the previous mblk;
		 * throw this one away, unless it's the first one.
		 */
		bp = tp->t_message;
		if (bp != bpt) {
			while (bp->b_cont != bpt) {
				ASSERT(bp->b_cont);
				bp = bp->b_cont;
			}
			bp->b_cont = NULL;
			freeb(bpt);
			tp->t_endmsg = bp;	/* point to that mblk */
		}
	}
}


/*
 * Rubout one character from the current line being built for tp as
 * cleanly as possible.  q is the write queue for tp. Most of this
 * can't be applied to multi-byte processing.  We do our own thing
 * for that... See the "ldterm_eucerase" routine.  We never call
 * ldterm_rubout on a multi-byte or multi-column character.
 */
static void
ldterm_rubout(uchar_t c, queue_t *q, size_t ebsize, ldtermstd_state_t *tp)
{
	int tabcols;
	static unsigned char crtrubout[] = "\b \b\b \b";
#define	RUBOUT1	&crtrubout[3]	/* rub out one position */
#define	RUBOUT2	&crtrubout[0]	/* rub out two positions */

	if (!(tp->t_modes.c_lflag & ECHO))
		return;
	if (tp->t_modes.c_lflag & ECHOE) {
		/*
		 * "CRT rubout"; try erasing it from the screen.
		 */
		if (tp->t_rocount == 0) {
			/*
			 * After the character being erased was
			 * echoed, some data was written to the
			 * terminal; we can't erase it cleanly, so we
			 * just reprint the whole line as if the user
			 * had typed the reprint character.
			 */
			ldterm_reprint(q, ebsize, tp);
			return;
		} else {
			/*
			 * XXX what about escaped characters?
			 */
			switch (typetab[c]) {

			case ORDINARY:
				if ((tp->t_modes.c_lflag & XCASE) &&
				    omaptab[c])
					ldterm_outstring(RUBOUT1, 3, q, ebsize,
					    tp);
				ldterm_outstring(RUBOUT1, 3, q, ebsize, tp);
				break;

			case VTAB:
			case BACKSPACE:
			case CONTROL:
			case RETURN:
			case NEWLINE:
				if ((tp->t_modes.c_lflag & ECHOCTL) &&
				    (tp->t_modes.c_lflag & IEXTEN))
					ldterm_outstring(RUBOUT2, 6, q, ebsize,
					    tp);
				break;

			case TAB:
				if (tp->t_rocount < tp->t_msglen) {
					/*
					 * While the tab being erased was
					 * expanded, some data was written
					 * to the terminal; we can't erase
					 * it cleanly, so we just reprint
					 * the whole line as if the user
					 * had typed the reprint character.
					 */
					ldterm_reprint(q, ebsize, tp);
					return;
				}
				tabcols = ldterm_tabcols(tp);
				while (--tabcols >= 0)
					ldterm_outchar('\b', q, ebsize, tp);
				break;
			}
		}
	} else if ((tp->t_modes.c_lflag & ECHOPRT) &&
	    (tp->t_modes.c_lflag & IEXTEN)) {
		/*
		 * "Printing rubout"; echo it between \ and /.
		 */
		if (!(tp->t_state & TS_ERASE)) {
			ldterm_outchar('\\', q, ebsize, tp);
			tp->t_state |= TS_ERASE;
		}
		(void) ldterm_echo(c, q, ebsize, tp);
	} else
		(void) ldterm_echo(tp->t_modes.c_cc[VERASE], q, ebsize, tp);
	tp->t_rocount--;	/* we "unechoed" this character */
}


/*
 * Find the number of characters the tab we just deleted took up by
 * zipping through the current line and recomputing the column
 * number.
 */
static int
ldterm_tabcols(ldtermstd_state_t *tp)
{
	int col;
	int i;
	mblk_t *bp;
	unsigned char *readp, *endp;
	unsigned char c;
	uchar_t *startp;
	char errflg;
	uchar_t u8[LDTERM_CS_MAX_BYTE_LENGTH];

	col = tp->t_rocol;
	/*
	 * If we're doing multi-byte stuff, zip through the list of
	 * widths to figure out where we are (we've kept track in most
	 * cases).
	 */
	if (tp->t_state & TS_MEUC) {
		ASSERT(tp->t_eucp_mp);
		bp = tp->t_message;
		startp = bp->b_datap->db_base;
		readp = tp->t_eucp_mp->b_rptr;
		endp = tp->t_eucp;
		errflg = (char)0;
		while (readp < endp) {
			switch (*readp) {
			case EUC_TWIDTH:	/* it's a tab */
				col |= 07;	/* bump up */
				col++;
				break;
			case EUC_BSWIDTH:	/* backspace */
				if (col)
					col--;
				break;
			case EUC_NLWIDTH:	/* newline */
				if (tp->t_modes.c_oflag & ONLRET)
					col = 0;
				break;
			case EUC_CRWIDTH:	/* return */
				col = 0;
				break;
			case UNKNOWN_WIDTH:	/* UTF-8 unknown width */
				if (tp->t_csdata.codeset_type !=
				    LDTERM_CS_TYPE_UTF8 || errflg) {
					*readp = 1;
					col++;
					break;
				}
				/*
				 * Collect the current UTF-8 character bytes
				 * from (possibly multiple) data buffers so
				 * that we can figure out the display width.
				 */
				u8[0] = *startp;
				for (i = 1; (i < LDTERM_CS_MAX_BYTE_LENGTH) &&
				    (*(readp + i) == 0); i++) {
					startp++;
					if (startp >= bp->b_datap->db_lim) {
						if (bp->b_cont) {
							bp = bp->b_cont;
							startp =
							    bp->b_datap->
							    db_base;
						} else {
							*readp = 1;
							col++;
							break;
						}
					}
					u8[i] = *startp;
				}

				/* tp->t_eucp_mp contains wrong info?? */
				if (*readp == 1)
					break;

				*readp = ldterm_utf8_width(u8, i);

				col += *readp;
				readp += (i - 1);
				break;
			default:
				col += *readp;
				break;
			}
			++readp;
			++startp;
			if (startp >= bp->b_datap->db_lim) {
				if (bp->b_cont) {
					bp = bp->b_cont;
					startp = bp->b_datap->db_base;
				} else {
					/*
					 * This will happen only if
					 * tp->t_eucp_mp contains wrong
					 * display width info.
					 */
					errflg = (char)1;
					startp--;
				}
			}
		}
		goto eucout;	/* finished! */
	}
	bp = tp->t_message;
	do {
		readp = bp->b_rptr;
		while (readp < bp->b_wptr) {
			c = *readp++;
			if ((tp->t_modes.c_lflag & ECHOCTL) &&
			    (tp->t_modes.c_lflag & IEXTEN)) {
				if (c <= 037 && c != '\t' && c != '\n' ||
				    c == 0177) {
					col += 2;
					continue;
				}
			}
			/*
			 * Column position calculated here.
			 */
			switch (typetab[c]) {

				/*
				 * Ordinary characters; advance by
				 * one.
				 */
			case ORDINARY:
				col++;
				break;

				/*
				 * Non-printing characters; nothing
				 * happens.
				 */
			case CONTROL:
				break;

				/* Backspace */
			case BACKSPACE:
				if (col != 0)
					col--;
				break;

				/* Newline; column depends on flags. */
			case NEWLINE:
				if (tp->t_modes.c_oflag & ONLRET)
					col = 0;
				break;

				/* tab */
			case TAB:
				col |= 07;
				col++;
				break;

				/* vertical motion */
			case VTAB:
				break;

				/* carriage return */
			case RETURN:
				col = 0;
				break;
			}
		}
	} while ((bp = bp->b_cont) != NULL);	/* next block, if any */

	/*
	 * "col" is now the column number before the tab. "tp->t_col"
	 * is still the column number after the tab, since we haven't
	 * erased the tab yet. Thus "tp->t_col - col" is the number
	 * of positions the tab moved.
	 */
eucout:
	col = tp->t_col - col;
	if (col > 8)
		col = 8;	/* overflow screw */
	return (col);
}


/*
 * Erase a single character; We ONLY ONLY deal with ASCII or
 * single-column single-byte codeset character.  For multi-byte characters,
 * see "ldterm_csi_erase".
 */
static void
ldterm_erase(queue_t *q, size_t ebsize, ldtermstd_state_t *tp)
{
	int c;

	if ((c = ldterm_unget(tp)) != -1) {
		ldterm_rubout((unsigned char) c, q, ebsize, tp);
		ldterm_trim(tp);
		if (tp->t_state & TS_MEUC)
			--tp->t_eucp;
	}
}


/*
 * Erase an entire word, single-byte EUC only please.
 */
static void
ldterm_werase(queue_t *q, size_t ebsize, ldtermstd_state_t *tp)
{
	int c;

	/*
	 * Erase trailing white space, if any.
	 */
	while ((c = ldterm_unget(tp)) == ' ' || c == '\t') {
		ldterm_rubout((unsigned char) c, q, ebsize, tp);
		ldterm_trim(tp);
	}

	/*
	 * Erase non-white-space characters, if any.
	 */
	while (c != -1 && c != ' ' && c != '\t') {
		ldterm_rubout((unsigned char) c, q, ebsize, tp);
		ldterm_trim(tp);
		c = ldterm_unget(tp);
	}
	if (c != -1) {
		/*
		 * We removed one too many characters; put the last
		 * one back.
		 */
		tp->t_endmsg->b_wptr++;	/* put 'c' back */
		tp->t_msglen++;
	}
}


/*
 * ldterm_csi_werase - This is multi-byte equivalent of "word erase".
 * "Word erase" only makes sense in languages which space between words,
 * and it's presumptuous for us to attempt "word erase" when we don't
 * know anything about what's really going on.  It makes no sense for
 * many languages, as the criteria for defining words and tokens may
 * be completely different.
 *
 * In the TS_MEUC case (which is how we got here), we define a token to
 * be space- or tab-delimited, and erase one of them.  It helps to
 * have this for command lines, but it's otherwise useless for text
 * editing applications; you need more sophistication than we can
 * provide here.
 */
static void
ldterm_csi_werase(queue_t *q, size_t ebsize, ldtermstd_state_t *tp)
{
	int c, i;
	int len;
	uchar_t *ip;
	uchar_t	u8[LDTERM_CS_MAX_BYTE_LENGTH];
	uchar_t	u8_2[LDTERM_CS_MAX_BYTE_LENGTH];

	/*
	 * ip points to the width of the actual bytes.  t_eucp points
	 * one byte beyond, where the next thing will be inserted.
	 */
	ip = tp->t_eucp - 1;
	/*
	 * Erase trailing white space, if any.
	 */
	while ((c = ldterm_unget(tp)) == ' ' || c == '\t') {
		tp->t_eucp--;
		ldterm_rubout((unsigned char) c, q, ebsize, tp);
		ldterm_trim(tp);
		--ip;
	}

	/*
	 * Erase non-white-space characters, if any.  The outer loop
	 * bops through each byte in the buffer. Multi-byte is removed, as
	 * is ASCII, one byte at a time. The inner loop (for) is only
	 * executed for first bytes of multi-byte.  The inner loop erases
	 * the number of columns required for the multi-byte char.  We check
	 * for ASCII first, and ldterm_rubout knows about ASCII.
	 */
	len = 0;
	while (c != -1 && c != ' ' && c != '\t') {
		tp->t_eucp--;
		if (len < LDTERM_CS_MAX_BYTE_LENGTH) {
			u8[len++] = (uchar_t)c;
		}
		/*
		 * Unlike EUC, except the leading byte, some bytes of
		 * a non-EUC multi-byte characters are in the ASCII code
		 * range, esp., 0x41 ~ 0x7a. Thus, we cannot simply check
		 * ISASCII().
		 * Checking the (*ip == 1 || *ip == 2 || *ip > UNKNOWN_WIDTH)
		 * will ensure that it is a single byte character (even though
		 * it is on display width not byte length) and can be further
		 * checked whether it is an ASCII character or not.
		 *
		 * When ECHOCTL is on and 'c' is an ASCII control character,
		 * *ip == 2 happens.
		 */
		if ((*ip == 1 || *ip == 2 || *ip > UNKNOWN_WIDTH) &&
		    ISASCII(c)) {
			ldterm_rubout((unsigned char) c, q, ebsize, tp);
			len = 0;
		} else if (*ip) {
			if (*ip == UNKNOWN_WIDTH) {
				if (tp->t_csdata.codeset_type ==
				    LDTERM_CS_TYPE_UTF8) {
					for (i = 0; i < len; i++)
						u8_2[i] = u8[len - i - 1];
					*ip = ldterm_utf8_width(u8_2, len);
				} else {
					*ip = 1;
				}
			}
			/*
			 * erase for number of columns required for
			 * this multi-byte character. Hopefully, matches
			 * ldterm_dispwidth!
			 */
			for (i = 0; i < (int)*ip; i++)
				ldterm_rubout(' ', q, ebsize, tp);
			len = 0;
		}
		ldterm_trim(tp);
		--ip;
		c = ldterm_unget(tp);
	}
	if (c != -1) {
		/*
		 * We removed one too many characters; put the last
		 * one back.
		 */
		tp->t_endmsg->b_wptr++;	/* put 'c' back */
		tp->t_msglen++;
	}
}


/*
 * Kill an entire line, erasing each character one-by-one (if ECHOKE
 * is set) or just echoing the kill character, followed by a newline
 * (if ECHOK is set).  Multi-byte processing is included here.
 */

static void
ldterm_kill(queue_t *q, size_t ebsize, ldtermstd_state_t *tp)
{
	int c, i;
	int len;
	uchar_t *ip;
	uchar_t u8[LDTERM_CS_MAX_BYTE_LENGTH];
	uchar_t u8_2[LDTERM_CS_MAX_BYTE_LENGTH];

	if ((tp->t_modes.c_lflag & ECHOKE) &&
	    (tp->t_modes.c_lflag & IEXTEN) &&
	    (tp->t_msglen == tp->t_rocount)) {
		if (tp->t_state & TS_MEUC) {
			ip = tp->t_eucp - 1;
			/*
			 * This loop similar to "ldterm_csi_werase" above.
			 */
			len = 0;
			while ((c = ldterm_unget(tp)) != (-1)) {
				tp->t_eucp--;
				if (len < LDTERM_CS_MAX_BYTE_LENGTH) {
					u8[len++] = (uchar_t)c;
				}
				if ((*ip == 1 || *ip == 2 ||
				    *ip > UNKNOWN_WIDTH) && ISASCII(c)) {
					ldterm_rubout((unsigned char) c, q,
					    ebsize, tp);
					len = 0;
				} else if (*ip) {
					if (*ip == UNKNOWN_WIDTH) {
						if (tp->t_csdata.codeset_type
						    == LDTERM_CS_TYPE_UTF8) {
							for (i = 0; i < len;
							    i++)
								u8_2[i] =
								    u8[len-i-1];
							*ip = ldterm_utf8_width(
							    u8_2, len);
						} else {
							*ip = 1;
						}
					}
					for (i = 0; i < (int)*ip; i++)
						ldterm_rubout(' ', q, ebsize,
						    tp);
					len = 0;
				}
				ldterm_trim(tp);
				--ip;
			}
		} else {
			while ((c = ldterm_unget(tp)) != -1) {
				ldterm_rubout((unsigned char) c, q, ebsize, tp);
				ldterm_trim(tp);
			}
		}
	} else {
		(void) ldterm_echo(tp->t_modes.c_cc[VKILL], q, ebsize, tp);
		if (tp->t_modes.c_lflag & ECHOK)
			(void) ldterm_echo('\n', q, ebsize, tp);
		while (ldterm_unget(tp) != -1) {
			if (tp->t_state & TS_MEUC)
				--tp->t_eucp;
			ldterm_trim(tp);
		}
		tp->t_rocount = 0;
		if (tp->t_state & TS_MEUC)
			tp->t_eucp = tp->t_eucp_mp->b_rptr;
	}
	tp->t_state &= ~(TS_QUOT|TS_ERASE|TS_SLNCH);
}


/*
 * Reprint the current input line. We assume c_cc has already been
 * checked. XXX just the current line, not the whole queue? What
 * about DEFECHO mode?
 */
static void
ldterm_reprint(queue_t *q, size_t ebsize, ldtermstd_state_t *tp)
{
	mblk_t *bp;
	unsigned char *readp;

	if (tp->t_modes.c_cc[VREPRINT] != (unsigned char) 0)
		(void) ldterm_echo(tp->t_modes.c_cc[VREPRINT], q, ebsize, tp);
	ldterm_outchar('\n', q, ebsize, tp);

	bp = tp->t_message;
	do {
		readp = bp->b_rptr;
		while (readp < bp->b_wptr)
			(void) ldterm_echo(*readp++, q, ebsize, tp);
	} while ((bp = bp->b_cont) != NULL);	/* next block, if any */

	tp->t_state &= ~TS_ERASE;
	tp->t_rocount = tp->t_msglen;	/* we reechoed the entire line */
	tp->t_rocol = 0;
}


/*
 * Non canonical processing. Called with q locked from  ldtermrsrv.
 *
 */
static mblk_t *
ldterm_dononcanon(mblk_t *bp, mblk_t *bpt, size_t ebsize, queue_t *q,
    ldtermstd_state_t *tp)
{
	queue_t *wrq = WR(q);
	unsigned char *rptr;
	size_t bytes_in_bp;
	size_t roomleft;
	size_t bytes_to_move;
	int free_flag = 0;

	if (tp->t_modes.c_lflag & (ECHO|ECHONL|IEXTEN)) {
		unsigned char *wptr;
		unsigned char c;

		/*
		 * Either we must echo the characters, or we must
		 * echo NL, or we must check for VLNEXT. Process
		 * characters one at a time.
		 */
		rptr = bp->b_rptr;
		wptr = bp->b_rptr;
		while (rptr < bp->b_wptr) {
			c = *rptr++;
			/*
			 * If this character is the literal next
			 * character, echo it as '^' and backspace
			 * over it if echoing is enabled, indicate
			 * that the next character is to be treated
			 * literally, and remove the LNEXT from the
			 * input stream.
			 *
			 * If the *previous* character was the literal
			 * next character, don't check whether this
			 * is a literal next or not.
			 */
			if ((tp->t_modes.c_lflag & IEXTEN) &&
			    !(tp->t_state & TS_SLNCH) &&
			    c != _POSIX_VDISABLE &&
			    c == tp->t_modes.c_cc[VLNEXT]) {
				if (tp->t_modes.c_lflag & ECHO)
					ldterm_outstring(
					    (unsigned char *)"^\b",
					    2, wrq, ebsize, tp);
				tp->t_state |= TS_SLNCH;
				continue;	/* and ignore it */
			}
			/*
			 * Not a "literal next" character, so it
			 * should show up as input. If it was
			 * literal-nexted, turn off the literal-next
			 * flag.
			 */
			tp->t_state &= ~TS_SLNCH;
			*wptr++ = c;
			if (tp->t_modes.c_lflag & ECHO) {
				/*
				 * Echo the character.
				 */
				(void) ldterm_echo(c, wrq, ebsize, tp);
			} else if (tp->t_modes.c_lflag & ECHONL) {
				/*
				 * Echo NL, even though ECHO is not
				 * set.
				 */
				if (c == '\n')
					ldterm_outchar('\n', wrq, 1, tp);
			}
		}
		bp->b_wptr = wptr;
	} else {
		/*
		 * If there are any characters in this buffer, and
		 * the first of them was literal-nexted, turn off the
		 * literal-next flag.
		 */
		if (bp->b_rptr != bp->b_wptr)
			tp->t_state &= ~TS_SLNCH;
	}

	ASSERT(bp->b_wptr >= bp->b_rptr);
	bytes_in_bp = bp->b_wptr - bp->b_rptr;
	rptr = bp->b_rptr;
	while (bytes_in_bp != 0) {
		roomleft = bpt->b_datap->db_lim - bpt->b_wptr;
		if (roomleft == 0) {
			/*
			 * No more room in this mblk; save this one
			 * away, and allocate a new one.
			 */
			if ((bpt = allocb(IBSIZE, BPRI_MED)) == NULL) {
				freeb(bp);
				DEBUG4(("ldterm_do_noncanon: allcob failed\n"));
				return (bpt);
			}
			/*
			 * Chain the new one to the end of the old
			 * one, and mark it as the last block in the
			 * current lump.
			 */
			tp->t_endmsg->b_cont = bpt;
			tp->t_endmsg = bpt;
			roomleft = IBSIZE;
		}
		DEBUG5(("roomleft=%d, bytes_in_bp=%d, tp->t_rd_request=%d\n",
		    roomleft, bytes_in_bp, tp->t_rd_request));
		/*
		 * if there is a read pending before this data got
		 * here move bytes according to the minimum of room
		 * left in this buffer, bytes in the message and byte
		 * count requested in the read. If there is no read
		 * pending, move the minimum of the first two
		 */
		if (tp->t_rd_request == 0)
			bytes_to_move = MIN(roomleft, bytes_in_bp);
		else
			bytes_to_move =
			    MIN(MIN(roomleft, bytes_in_bp), tp->t_rd_request);
		DEBUG5(("Bytes to move = %lu\n", bytes_to_move));
		if (bytes_to_move == 0)
			break;
		bcopy(rptr, bpt->b_wptr, bytes_to_move);
		bpt->b_wptr += bytes_to_move;
		rptr += bytes_to_move;
		tp->t_msglen += bytes_to_move;
		bytes_in_bp -= bytes_to_move;
	}
	if (bytes_in_bp == 0) {
		DEBUG4(("bytes_in_bp is zero\n"));
		freeb(bp);
	} else
		free_flag = 1;	/* for debugging olny */

	DEBUG4(("ldterm_do_noncanon: VMIN = %d, VTIME = %d, msglen = %d, \
		tid = %d\n", V_MIN, V_TIME, tp->t_msglen, tp->t_vtid));
	/*
	 * If there is a pending read request at the stream head we
	 * need to do VMIN/VTIME processing. The four possible cases
	 * are:
	 *	MIN = 0, TIME > 0
	 *	MIN = >, TIME = 0
	 *	MIN > 0, TIME > 0
	 *	MIN = 0, TIME = 0
	 * If we can satisfy VMIN, send it up, and start a new
	 * timer if necessary.  These four cases of VMIN/VTIME
	 * are also dealt with in the write side put routine
	 * when the M_READ is first seen.
	 */

	DEBUG4(("Incoming data while M_READ'ing\n"));
	/*
	 * Case 1:  Any data will satisfy the read, so send
	 * it upstream.
	 */
	if (V_MIN == 0 && V_TIME > 0) {
		if (tp->t_msglen)
			vmin_satisfied(q, tp, 1);
		else {
			/* EMPTY */
			DEBUG4(("ldterm_do_noncanon called, but no data!\n"));
		}
		/*
		 * Case 2:  This should never time out, so
		 * until there's enough data, do nothing.
		 */
	} else if (V_MIN > 0 && V_TIME == 0) {
		if (tp->t_msglen >= (int)V_MIN)
			vmin_satisfied(q, tp, 1);

		/*
		 * Case 3:  If MIN is satisfied, send it up.
		 * Also, remember to start a new timer *every*
		 * time we see something if MIN isn't
		 * safisfied
		 */
	} else if (V_MIN > 0 && V_TIME > 0) {
		if (tp->t_msglen >= (int)V_MIN)
			vmin_satisfied(q, tp, 1);
		else
			vmin_settimer(q);
		/*
		 * Case 4:  Not possible.  This request
		 * should always be satisfied from the write
		 * side, left here for debugging.
		 */
	} else {	/* V_MIN == 0 && V_TIME == 0 */
			vmin_satisfied(q, tp, 1);
	}

	if (free_flag) {
		/* EMPTY */
		DEBUG4(("CAUTION message block not freed\n"));
	}
	return (newmsg(tp));
}


/*
 * Echo a typed byte to the terminal.  Returns the number of bytes
 * printed. Bytes of EUC characters drop through the ECHOCTL stuff
 * and are just output as themselves.
 */
static int
ldterm_echo(uchar_t c, queue_t *q, size_t ebsize, ldtermstd_state_t *tp)
{
	int i;

	if (!(tp->t_modes.c_lflag & ECHO))
		return (0);
	i = 0;

	/*
	 * Echo control characters (c <= 37) only if the ECHOCTRL
	 * flag is set as ^X.
	 */

	if ((tp->t_modes.c_lflag & ECHOCTL) &&
	    (tp->t_modes.c_lflag & IEXTEN)) {
		if (c <= 037 && c != '\t' && c != '\n') {
			ldterm_outchar('^', q, ebsize, tp);
			i++;
			if (tp->t_modes.c_oflag & OLCUC)
				c += 'a' - 1;
			else
				c += 'A' - 1;
		} else if (c == 0177) {
			ldterm_outchar('^', q, ebsize, tp);
			i++;
			c = '?';
		}
		ldterm_outchar(c, q, ebsize, tp);
		return (i + 1);
		/* echo only special control character and the Bell */
	} else if ((c > 037 && c != 0177) || c == '\t' || c == '\n' ||
	    c == '\r' || c == '\b' || c == 007 ||
	    c == tp->t_modes.c_cc[VKILL]) {
		ldterm_outchar(c, q, ebsize, tp);
		return (i + 1);
	}
	return (i);
}


/*
 * Put a character on the output queue.
 */
static void
ldterm_outchar(uchar_t c, queue_t *q, size_t bsize, ldtermstd_state_t *tp)
{
	mblk_t *curbp;

	/*
	 * Don't even look at the characters unless we have something
	 * useful to do with them.
	 */
	if ((tp->t_modes.c_oflag & OPOST) ||
	    ((tp->t_modes.c_lflag & XCASE) &&
	    (tp->t_modes.c_lflag & ICANON))) {
		mblk_t *mp;

		if ((mp = allocb(4, BPRI_HI)) == NULL) {
			cmn_err(CE_WARN,
			    "ldterm: (ldterm_outchar) out of blocks");
			return;
		}
		*mp->b_wptr++ = c;
		mp = ldterm_output_msg(q, mp, &tp->t_echomp, tp, bsize, 1);
		if (mp != NULL)
			freemsg(mp);

	} else {
		if ((curbp = tp->t_echomp) != NULL) {
			while (curbp->b_cont != NULL)
				curbp = curbp->b_cont;
			if (curbp->b_datap->db_lim == curbp->b_wptr) {
				mblk_t *newbp;

				if ((newbp = allocb(bsize, BPRI_HI)) == NULL) {
					cmn_err(CE_WARN,
					    "ldterm_outchar: out of blocks");
					return;
				}
				curbp->b_cont = newbp;
				curbp = newbp;
			}
		} else {
			if ((curbp = allocb(bsize, BPRI_HI)) == NULL) {
				cmn_err(CE_WARN,
				    "ldterm_outchar: out of blocks");
				return;
			}
			tp->t_echomp = curbp;
		}
		*curbp->b_wptr++ = c;
	}
}


/*
 * Copy a string, of length len, to the output queue.
 */
static void
ldterm_outstring(uchar_t *cp, int len, queue_t *q, size_t bsize,
    ldtermstd_state_t *tp)
{
	while (len > 0) {
		ldterm_outchar(*cp++, q, bsize, tp);
		len--;
	}
}


static mblk_t *
newmsg(ldtermstd_state_t *tp)
{
	mblk_t *bp;

	/*
	 * If no current message, allocate a block for it.
	 */
	if ((bp = tp->t_endmsg) == NULL) {
		if ((bp = allocb(IBSIZE, BPRI_MED)) == NULL) {
			cmn_err(CE_WARN,
			    "ldterm: (ldtermrsrv/newmsg) out of blocks");
			return (bp);
		}
		tp->t_message = bp;
		tp->t_endmsg = bp;
	}
	return (bp);
}


static void
ldterm_msg_upstream(queue_t *q, ldtermstd_state_t *tp)
{
	ssize_t s;
	mblk_t *bp;

	bp = tp->t_message;
	s = msgdsize(bp);
	if (bp)
		putnext(q, tp->t_message);

	/*
	 * update sysinfo canch character.
	 */
	if (CANON_MODE)
		(void) drv_setparm(SYSCANC, s);
	tp->t_message = NULL;
	tp->t_endmsg = NULL;
	tp->t_msglen = 0;
	tp->t_rocount = 0;
	tp->t_rd_request = 0;
	if (tp->t_state & TS_MEUC) {
		ASSERT(tp->t_eucp_mp);
		tp->t_eucp = tp->t_eucp_mp->b_rptr;
		/* can't reset everything, as we may have other input */
	}
}


/*
 * Re-enable the write-side service procedure.  When an allocation
 * failure causes write-side processing to stall, we disable the
 * write side and arrange to call this function when allocation once
 * again becomes possible.
 */
static void
ldterm_wenable(void *addr)
{
	queue_t *q = addr;
	ldtermstd_state_t *tp;

	tp = (ldtermstd_state_t *)q->q_ptr;
	/*
	 * The bufcall is no longer pending.
	 */
	tp->t_wbufcid = 0;
	enableok(q);
	qenable(q);
}


/*
 * Line discipline output queue put procedure.  Attempts to process
 * the message directly and send it on downstream, queueing it only
 * if there's already something pending or if its downstream neighbor
 * is clogged.
 */
static void
ldtermwput(queue_t *q, mblk_t *mp)
{
	ldtermstd_state_t *tp;
	unsigned char type = mp->b_datap->db_type;

	tp = (ldtermstd_state_t *)q->q_ptr;

	/*
	 * Always process priority messages, regardless of whether or
	 * not our queue is nonempty.
	 */
	if (type >= QPCTL) {
		switch (type) {

		case M_FLUSH:
			/*
			 * Get rid of it, see comment in
			 * ldterm_dosig().
			 */
			if ((tp->t_state & TS_FLUSHWAIT) &&
			    (*mp->b_rptr == FLUSHW)) {
				tp->t_state &= ~TS_FLUSHWAIT;
				freemsg(mp);
				return;
			}
			/*
			 * This is coming from above, so we only
			 * handle the write queue here.  If FLUSHR is
			 * set, it will get turned around at the
			 * driver, and the read procedure will see it
			 * eventually.
			 */
			if (*mp->b_rptr & FLUSHW) {
				if ((tp->t_state & TS_ISPTSTTY) &&
				    (*mp->b_rptr & FLUSHBAND))
					flushband(q, *(mp->b_rptr + 1),
					    FLUSHDATA);
				else
					flushq(q, FLUSHDATA);
			}

			putnext(q, mp);
			/*
			 * If a timed read is interrupted, there is
			 * no way to cancel an existing M_READ
			 * request.  We kludge by allowing a flush to
			 * do so.
			 */
			if (tp->t_state & TS_MREAD)
				vmin_satisfied(RD(q), tp, 0);
			break;

		case M_READ:
			DEBUG1(("ldtermwmsg:M_READ RECEIVED\n"));
			/*
			 * Stream head needs data to satisfy timed
			 * read. Has meaning only if ICANON flag is
			 * off indicating raw mode
			 */

			DEBUG4((
			    "M_READ: RAW_MODE=%d, CNT=%d, VMIN=%d, VTIME=%d\n",
			    RAW_MODE, *(unsigned int *)mp->b_rptr, V_MIN,
			    V_TIME));

			tp->t_rd_request = *(unsigned int *)mp->b_rptr;

			if (RAW_MODE) {
				if (newmsg(tp) != NULL) {
					/*
					 * VMIN/VTIME processing...
					 * The four possible cases are:
					 *	MIN = 0, TIME > 0
					 *	MIN = >, TIME = 0
					 *	MIN > 0, TIME > 0
					 *	MIN = 0, TIME = 0
					 * These four conditions must be dealt
					 * with on the read side as well in
					 * ldterm_do_noncanon(). Set TS_MREAD
					 * so that the read side will know
					 * there is a pending read request
					 * waiting at the stream head.  If we
					 * can satisfy MIN do it here, rather
					 * than on the read side.  If we can't,
					 * start timers if necessary and let
					 * the other side deal with it.
					 *
					 * We got another M_READ before the
					 * pending one completed, cancel any
					 * existing timeout.
					 */
					if (tp->t_state & TS_MREAD) {
						vmin_satisfied(RD(q),
						    tp, 0);
					}
					tp->t_state |= TS_MREAD;
					/*
					 * Case 1:  Any data will
					 * satisfy read, otherwise
					 * start timer
					 */
					if (V_MIN == 0 && V_TIME > 0) {
						if (tp->t_msglen)
							vmin_satisfied(RD(q),
							    tp, 1);
						else
							vmin_settimer(RD(q));

						/*
						 * Case 2:  If we have enough
						 * data, send up now.
						 * Otherwise, the read side
						 * should wait forever until MIN
						 * is satisified.
						 */
					} else if (V_MIN > 0 && V_TIME == 0) {
						if (tp->t_msglen >= (int)V_MIN)
							vmin_satisfied(RD(q),
							    tp, 1);

						/*
						 * Case 3:  If we can satisfy
						 * the read, send it up. If we
						 * don't have enough data, but
						 * there is at least one char,
						 * start a timer.  Otherwise,
						 * let the read side start
						 * the timer.
						 */
					} else if (V_MIN > 0 && V_TIME > 0) {
						if (tp->t_msglen >= (int)V_MIN)
							vmin_satisfied(RD(q),
							    tp, 1);
						else if (tp->t_msglen)
							vmin_settimer(RD(q));
						/*
						 * Case 4:  Read returns
						 * whatever data is available
						 * or zero if none.
						 */
					} else { /* V_MIN == 0 && V_TIME == 0 */
						vmin_satisfied(RD(q), tp, 1);
					}

				} else	/* should do bufcall, really! */
					cmn_err(CE_WARN,
					    "ldtermwmsg: out of blocks");
			}
			/*
			 * pass M_READ down
			 */
			putnext(q, mp);
			break;

		default:
			/* Pass it through unmolested. */
			putnext(q, mp);
			break;
		}
		return;
	}
	/*
	 * If our queue is nonempty or there's a traffic jam
	 * downstream, this message must get in line.
	 */
	if (q->q_first != NULL || !bcanputnext(q, mp->b_band)) {
		/*
		 * Exception: ioctls, except for those defined to
		 * take effect after output has drained, should be
		 * processed immediately.
		 */
		if (type == M_IOCTL) {
			struct iocblk *iocp;

			iocp = (struct iocblk *)mp->b_rptr;
			switch (iocp->ioc_cmd) {

				/*
				 * Queue these.
				 */
			case TCSETSW:
			case TCSETSF:
			case TCSETAW:
			case TCSETAF:
			case TCSBRK:
				break;

				/*
				 * Handle all others immediately.
				 */
			default:
				(void) ldtermwmsg(q, mp);
				return;
			}
		}
		(void) putq(q, mp);
		return;
	}
	/*
	 * We can take the fast path through, by simply calling
	 * ldtermwmsg to dispose of mp.
	 */
	(void) ldtermwmsg(q, mp);
}


/*
 * Line discipline output queue service procedure.
 */
static void
ldtermwsrv(queue_t *q)
{
	mblk_t *mp;

	/*
	 * We expect this loop to iterate at most once, but must be
	 * prepared for more in case our upstream neighbor isn't
	 * paying strict attention to what canput tells it.
	 */
	while ((mp = getq(q)) != NULL) {
		/*
		 * N.B.: ldtermwput has already handled high-priority
		 * messages, so we don't have to worry about them
		 * here. Hence, the putbq call is safe.
		 */
		if (!bcanputnext(q, mp->b_band)) {
			(void) putbq(q, mp);
			break;
		}
		if (!ldtermwmsg(q, mp)) {
			/*
			 * Couldn't handle the whole thing; give up
			 * for now and wait to be rescheduled.
			 */
			break;
		}
	}
}


/*
 * Process the write-side message denoted by mp.  If mp can't be
 * processed completely (due to allocation failures), put the
 * residual unprocessed part on the front of the write queue, disable
 * the queue, and schedule a qbufcall to arrange to complete its
 * processing later.
 *
 * Return 1 if the message was processed completely and 0 if not.
 *
 * This routine is called from both ldtermwput and ldtermwsrv to do the
 * actual work of dealing with mp.  ldtermwput will have already
 * dealt with high priority messages.
 */
static int
ldtermwmsg(queue_t *q, mblk_t *mp)
{
	ldtermstd_state_t *tp;
	mblk_t *residmp = NULL;
	size_t size;

	tp = (ldtermstd_state_t *)q->q_ptr;

	switch (mp->b_datap->db_type) {

	case M_IOCTL:
		ldterm_do_ioctl(q, mp);
		break;

	case M_DATA:
		{
			mblk_t *omp = NULL;

			if ((tp->t_modes.c_lflag & FLUSHO) &&
			    (tp->t_modes.c_lflag & IEXTEN)) {
				freemsg(mp);	/* drop on floor */
				break;
			}
			tp->t_rocount = 0;
			/*
			 * Don't even look at the characters unless
			 * we have something useful to do with them.
			 */
			if (((tp->t_modes.c_oflag & OPOST) ||
			    ((tp->t_modes.c_lflag & XCASE) &&
			    (tp->t_modes.c_lflag & ICANON))) &&
			    (msgdsize(mp) || !(tp->t_state & TS_ISPTSTTY))) {
				unsigned char band = mp->b_band;
				short flag = mp->b_flag;

				residmp = ldterm_output_msg(q, mp, &omp,
				    tp, OBSIZE, 0);
				if ((mp = omp) == NULL)
					break;
				mp->b_band |= band;
				mp->b_flag |= flag;
			}
			/* Update sysinfo outch */
			(void) drv_setparm(SYSOUTC, msgdsize(mp));
			putnext(q, mp);
			break;
		}

	default:
		putnext(q, mp);	/* pass it through unmolested */
		break;
	}

	if (residmp == NULL)
		return (1);

	/*
	 * An allocation failure occurred that prevented the message
	 * from being completely processed.  First, disable our
	 * queue, since it's pointless to attempt further processing
	 * until the allocation situation is resolved.  (This must
	 * precede the putbq call below, which would otherwise mark
	 * the queue to be serviced.)
	 */
	noenable(q);
	/*
	 * Stuff the remnant on our write queue so that we can
	 * complete it later when times become less lean.  Note that
	 * this sets QFULL, so that our upstream neighbor will be
	 * blocked by flow control.
	 */
	(void) putbq(q, residmp);
	/*
	 * Schedule a qbufcall to re-enable the queue.  The failure
	 * won't have been for an allocation of more than OBSIZE
	 * bytes, so don't ask for more than that from bufcall.
	 */
	size = msgdsize(residmp);
	if (size > OBSIZE)
		size = OBSIZE;
	if (tp->t_wbufcid)
		qunbufcall(q, tp->t_wbufcid);
	tp->t_wbufcid = qbufcall(q, size, BPRI_MED, ldterm_wenable, q);

	return (0);
}


/*
 * Perform output processing on a message, accumulating the output
 * characters in a new message.
 */
static mblk_t *
ldterm_output_msg(queue_t *q, mblk_t *imp, mblk_t **omp,
    ldtermstd_state_t *tp, size_t bsize, int echoing)
{
	mblk_t *ibp;		/* block we're examining from input message */
	mblk_t *obp;		/* block we're filling in output message */
	mblk_t *cbp;		/* continuation block */
	mblk_t *oobp;		/* old value of obp; valid if NEW_BLOCK fails */
	mblk_t **contpp;	/* where to stuff ptr to newly-allocated blk */
	unsigned char c, n;
	int count, ctype;
	ssize_t bytes_left;

	mblk_t *bp;		/* block to stuff an M_DELAY message in */


	/*
	 * Allocate a new block into which to put bytes. If we can't,
	 * we just drop the rest of the message on the floor. If x is
	 * non-zero, just fall thru; failure requires cleanup before
	 * going out
	 */

#define	NEW_BLOCK(x) \
	{ \
		oobp = obp; \
		if ((obp = allocb(bsize, BPRI_MED)) == NULL) { \
			if (x == 0) \
				goto outofbufs; \
		} else { \
			*contpp = obp; \
			contpp = &obp->b_cont; \
			bytes_left = obp->b_datap->db_lim - obp->b_wptr; \
		} \
	}

	ibp = imp;

	/*
	 * When we allocate the first block of a message, we should
	 * stuff the pointer to it in "*omp".  All subsequent blocks
	 * should have the pointer to them stuffed into the "b_cont"
	 * field of the previous block.  "contpp" points to the place
	 * where we should stuff the pointer.
	 *
	 * If we already have a message we're filling in, continue doing
	 * so.
	 */
	if ((obp = *omp) != NULL) {
		while (obp->b_cont != NULL)
			obp = obp->b_cont;
		contpp = &obp->b_cont;
		bytes_left = obp->b_datap->db_lim - obp->b_wptr;
	} else {
		contpp = omp;
		bytes_left = 0;
	}

	do {
		while (ibp->b_rptr < ibp->b_wptr) {
			/*
			 * Make sure there's room for one more
			 * character.  At most, we'll need "t_maxeuc"
			 * bytes.
			 */
			if ((bytes_left < (int)tp->t_maxeuc)) {
				/* LINTED */
				NEW_BLOCK(0);
			}
			/*
			 * If doing XCASE processing (not very
			 * likely, in this day and age), look at each
			 * character individually.
			 */
			if ((tp->t_modes.c_lflag & XCASE) &&
			    (tp->t_modes.c_lflag & ICANON)) {
				c = *ibp->b_rptr++;

				/*
				 * We need to make sure that this is not
				 * a following byte of a multibyte character
				 * before applying an XCASE processing.
				 *
				 * tp->t_eucign will be 0 if and only
				 * if the current 'c' is an ASCII character
				 * and also a byte. Otherwise, it will have
				 * the byte length of a multibyte character.
				 */
				if ((tp->t_state & TS_MEUC) &&
				    tp->t_eucign == 0 && NOTASCII(c)) {
					tp->t_eucign =
					    tp->t_csmethods.ldterm_memwidth(
					    c, (void *)tp);
					tp->t_scratch_len = tp->t_eucign;

					if (tp->t_csdata.codeset_type !=
					    LDTERM_CS_TYPE_UTF8) {
						tp->t_col +=
						    tp->
						    t_csmethods.
						    ldterm_dispwidth(c,
						    (void *)tp,
						    tp->t_modes.c_lflag &
						    ECHOCTL);
					}
				}

				/*
				 * If character is mapped on output,
				 * put out a backslash followed by
				 * what it is mapped to.
				 */
				if (tp->t_eucign == 0 && omaptab[c] != 0 &&
				    (!echoing || c != '\\')) {
					/* backslash is an ordinary character */
					tp->t_col++;
					*obp->b_wptr++ = '\\';
					bytes_left--;
					if (bytes_left == 0) {
						/* LINTED */
						NEW_BLOCK(1);
					}
					/*
					 * Allocation failed, make
					 * state consistent before
					 * returning
					 */
					if (obp == NULL) {
						ibp->b_rptr--;
						tp->t_col--;
						oobp->b_wptr--;
						goto outofbufs;
					}
					c = omaptab[c];
				}
				/*
				 * If no other output processing is
				 * required, push the character into
				 * the block and get another.
				 */
				if (!(tp->t_modes.c_oflag & OPOST)) {
					if (tp->t_eucign > 0) {
						--tp->t_eucign;
					} else {
						tp->t_col++;
					}
					*obp->b_wptr++ = c;
					bytes_left--;
					continue;
				}
				/*
				 * OPOST output flag is set. Map
				 * lower case to upper case if OLCUC
				 * flag is set and the 'c' is a lowercase
				 * ASCII character.
				 */
				if (tp->t_eucign == 0 &&
				    (tp->t_modes.c_oflag & OLCUC) &&
				    c >= 'a' && c <= 'z')
					c -= 'a' - 'A';
			} else {
				/*
				 * Copy all the ORDINARY characters,
				 * possibly mapping upper case to
				 * lower case.  We use "movtuc",
				 * STOPPING when we can't move some
				 * character. For multi-byte or
				 * multi-column EUC, we can't depend
				 * on the regular tables. Rather than
				 * just drop through to the "big
				 * switch" for all characters, it
				 * _might_ be faster to let "movtuc"
				 * move a bunch of characters.
				 * Chances are, even in multi-byte
				 * mode we'll have lots of ASCII
				 * going through. We check the flag
				 * once, and call movtuc with the
				 * appropriate table as an argument.
				 *
				 * "movtuc will work for all codeset
				 * types since it stops at the beginning
				 * byte of a multibyte character.
				 */
				size_t bytes_to_move;
				size_t bytes_moved;

				ASSERT(ibp->b_wptr >= ibp->b_rptr);
				bytes_to_move = ibp->b_wptr - ibp->b_rptr;
				if (bytes_to_move > bytes_left)
					bytes_to_move = bytes_left;
				if (tp->t_state & TS_MEUC) {
					bytes_moved = movtuc(bytes_to_move,
					    ibp->b_rptr, obp->b_wptr,
					    (tp->t_modes.c_oflag & OLCUC ?
					    elcuctab : enotrantab));
				} else {
					bytes_moved = movtuc(bytes_to_move,
					    ibp->b_rptr, obp->b_wptr,
					    (tp->t_modes.c_oflag & OLCUC ?
					    lcuctab : notrantab));
				}
				/*
				 * We're save to just do this column
				 * calculation, because if TS_MEUC is
				 * set, we used the proper EUC
				 * tables, and won't have copied any
				 * EUC bytes.
				 */
				tp->t_col += bytes_moved;
				ibp->b_rptr += bytes_moved;
				obp->b_wptr += bytes_moved;
				bytes_left -= bytes_moved;
				if (ibp->b_rptr >= ibp->b_wptr)
					continue;	/* moved all of block */
				if (bytes_left == 0) {
					/* LINTED */
					NEW_BLOCK(0);
				}
				c = *ibp->b_rptr++;	/* stopper */
			}

			/*
			 * Again, we need to make sure that this is not
			 * a following byte of a multibyte character at
			 * here.
			 *
			 * 'tp->t_eucign' will be 0 iff the current 'c' is
			 * an ASCII character. Otherwise, it will have
			 * the byte length of a multibyte character.
			 * We also add the display width to 'tp->t_col' if
			 * the current codeset is not UTF-8 since this is
			 * a leading byte of a multibyte character.
			 * For UTF-8 codeset type, we add the display width
			 * when we get the last byte of a character.
			 */
			if ((tp->t_state & TS_MEUC) && tp->t_eucign == 0 &&
			    NOTASCII(c)) {
				tp->t_eucign = tp->t_csmethods.ldterm_memwidth(
				    c, (void *)tp);
				tp->t_scratch_len = tp->t_eucign;

				if (tp->t_csdata.codeset_type !=
				    LDTERM_CS_TYPE_UTF8) {
					tp->t_col +=
					    tp->t_csmethods.ldterm_dispwidth(c,
					    (void *)tp,
					    tp->t_modes.c_lflag & ECHOCTL);
				}
			}

			/*
			 * If the driver has requested, don't process
			 * output flags.  However, if we're in
			 * multi-byte mode, we HAVE to look at
			 * EVERYTHING going out to maintain column
			 * position properly. Therefore IF the driver
			 * says don't AND we're not doing multi-byte,
			 * then don't do it.  Otherwise, do it.
			 *
			 * NOTE:  Hardware USUALLY doesn't expand tabs
			 * properly for multi-byte situations anyway;
			 * that's a known problem with the 3B2
			 * "PORTS" board firmware, and any other
			 * hardware that doesn't ACTUALLY know about
			 * the current EUC mapping that WE are using
			 * at this very moment.  The problem is that
			 * memory width is INDEPENDENT of screen
			 * width - no relation - so WE know how wide
			 * the characters are, but an off-the-host
			 * board probably doesn't.  So, until we're
			 * SURE that the hardware below us can
			 * correctly expand tabs in a
			 * multi-byte/multi-column EUC situation, we
			 * do it ourselves.
			 */
			/*
			 * Map <CR>to<NL> on output if OCRNL flag
			 * set. ONLCR processing is not done if OCRNL
			 * is set.
			 */
			if (c == '\r' && (tp->t_modes.c_oflag & OCRNL)) {
				c = '\n';
				ctype = typetab[c];
				goto jocrnl;
			}

			if (tp->t_csdata.codeset_type == LDTERM_CS_TYPE_EUC) {
				ctype = typetab[c];
			} else {
				/*
				 * In other codeset types, we safely assume
				 * any byte of a multibyte character will have
				 * 'ORDINARY' type. For ASCII characters, we
				 * still use the typetab[].
				 */
				if (tp->t_eucign == 0)
					ctype = typetab[c];
				else
					ctype = ORDINARY;
			}

			/*
			 * Map <NL> to <CR><NL> on output if ONLCR
			 * flag is set.
			 */
			if (c == '\n' && (tp->t_modes.c_oflag & ONLCR)) {
				if (!(tp->t_state & TS_TTCR)) {
					tp->t_state |= TS_TTCR;
					c = '\r';
					ctype = typetab['\r'];
					--ibp->b_rptr;
				} else
					tp->t_state &= ~TS_TTCR;
			}
			/*
			 * Delay values and column position
			 * calculated here.  For EUC chars in
			 * multi-byte mode, we use "t_eucign" to help
			 * calculate columns.  When we see the first
			 * byte of an EUC, we set t_eucign to the
			 * number of bytes that will FOLLOW it, and
			 * we add the screen width of the WHOLE EUC
			 * character to the column position.  In
			 * particular, we can't count SS2 or SS3 as
			 * printing characters.  Remember, folks, the
			 * screen width and memory width are
			 * independent - no relation. We could have
			 * dropped through for ASCII, but we want to
			 * catch any bad characters (i.e., t_eucign
			 * set and an ASCII char received) and
			 * possibly report the garbage situation.
			 */
	jocrnl:

			count = 0;
			switch (ctype) {

			case T_SS2:
			case T_SS3:
			case ORDINARY:
				if (tp->t_state & TS_MEUC) {
					if (tp->t_eucign) {
						*obp->b_wptr++ = c;
						bytes_left--;

						tp->t_scratch[tp->t_scratch_len
						    - tp->t_eucign] = c;

						--tp->t_eucign;

						if (tp->t_csdata.codeset_type
						    == LDTERM_CS_TYPE_UTF8 &&
						    tp->t_eucign <= 0) {
							tp->t_col +=
							    ldterm_utf8_width(
							    tp->t_scratch,
							    tp->t_scratch_len);
						}
					} else {
						if (tp->t_modes.c_oflag & OLCUC)
							n = elcuctab[c];
						else
							n = enotrantab[c];
						if (n)
							c = n;
						tp->t_col++;
						*obp->b_wptr++ = c;
						bytes_left--;
					}
				} else {	/* ho hum, ASCII mode... */
					if (tp->t_modes.c_oflag & OLCUC)
						n = lcuctab[c];
					else
						n = notrantab[c];
					if (n)
						c = n;
					tp->t_col++;
					*obp->b_wptr++ = c;
					bytes_left--;
				}
				break;

				/*
				 * If we're doing ECHOCTL, we've
				 * already mapped the thing during
				 * the process of canonising.  Don't
				 * bother here, as it's not one that
				 * we did.
				 */
			case CONTROL:
				*obp->b_wptr++ = c;
				bytes_left--;
				break;

				/*
				 * This is probably a backspace
				 * received, not one that we're
				 * echoing.  Let it go as a
				 * single-column backspace.
				 */
			case BACKSPACE:
				if (tp->t_col)
					tp->t_col--;
				if (tp->t_modes.c_oflag & BSDLY) {
					if (tp->t_modes.c_oflag & OFILL)
						count = 1;
				}
				*obp->b_wptr++ = c;
				bytes_left--;
				break;

			case NEWLINE:
				if (tp->t_modes.c_oflag & ONLRET)
					goto cr;
				if ((tp->t_modes.c_oflag & NLDLY) == NL1)
					count = 2;
				*obp->b_wptr++ = c;
				bytes_left--;
				break;

			case TAB:
				/*
				 * Map '\t' to spaces if XTABS flag
				 * is set.  The calculation of
				 * "t_eucign" has probably insured
				 * that column will be correct, as we
				 * bumped t_col by the DISP width,
				 * not the memory width.
				 */
				if ((tp->t_modes.c_oflag & TABDLY) == XTABS) {
					for (;;) {
						*obp->b_wptr++ = ' ';
						bytes_left--;
						tp->t_col++;
						if ((tp->t_col & 07) == 0)
							break;	/* every 8th */
						/*
						 * If we don't have
						 * room to fully
						 * expand this tab in
						 * this block, back
						 * up to continue
						 * expanding it into
						 * the next block.
						 */
						if (obp->b_wptr >=
						    obp->b_datap->db_lim) {
							ibp->b_rptr--;
							break;
						}
					}
				} else {
					tp->t_col |= 07;
					tp->t_col++;
					if (tp->t_modes.c_oflag & OFILL) {
						if (tp->t_modes.c_oflag &
						    TABDLY)
							count = 2;
					} else {
						switch (tp->t_modes.c_oflag &
						    TABDLY) {
						case TAB2:
							count = 6;
							break;

						case TAB1:
							count = 1 + (tp->t_col |
							    ~07);
							if (count < 5)
								count = 0;
							break;
						}
					}
					*obp->b_wptr++ = c;
					bytes_left--;
				}
				break;

			case VTAB:
				if ((tp->t_modes.c_oflag & VTDLY) &&
				    !(tp->t_modes.c_oflag & OFILL))
					count = 127;
				*obp->b_wptr++ = c;
				bytes_left--;
				break;

			case RETURN:
				/*
				 * Ignore <CR> in column 0 if ONOCR
				 * flag set.
				 */
				if (tp->t_col == 0 &&
				    (tp->t_modes.c_oflag & ONOCR))
					break;

		cr:
				switch (tp->t_modes.c_oflag & CRDLY) {

				case CR1:
					if (tp->t_modes.c_oflag & OFILL)
						count = 2;
					else
						count = tp->t_col % 2;
					break;

				case CR2:
					if (tp->t_modes.c_oflag & OFILL)
						count = 4;
					else
						count = 6;
					break;

				case CR3:
					if (tp->t_modes.c_oflag & OFILL)
						count = 0;
					else
						count = 9;
					break;
				}
				tp->t_col = 0;
				*obp->b_wptr++ = c;
				bytes_left--;
				break;
			}

			if (count != 0) {
				if (tp->t_modes.c_oflag & OFILL) {
					do {
						if (bytes_left == 0) {
							/* LINTED */
							NEW_BLOCK(0);
						}
						if (tp->t_modes.c_oflag & OFDEL)
							*obp->b_wptr++ = CDEL;
						else
							*obp->b_wptr++ = CNUL;
						bytes_left--;
					} while (--count != 0);
				} else {
					if ((tp->t_modes.c_lflag & FLUSHO) &&
					    (tp->t_modes.c_lflag & IEXTEN)) {
						/* drop on floor */
						freemsg(*omp);
					} else {
						/*
						 * Update sysinfo
						 * outch
						 */
						(void) drv_setparm(SYSOUTC,
						    msgdsize(*omp));
						putnext(q, *omp);
						/*
						 * Send M_DELAY
						 * downstream
						 */
						if ((bp =
						    allocb(1, BPRI_MED)) !=
						    NULL) {
							bp->b_datap->db_type =
							    M_DELAY;
							*bp->b_wptr++ =
							    (uchar_t)count;
							putnext(q, bp);
						}
					}
					bytes_left = 0;
					/*
					 * We have to start a new
					 * message; the delay
					 * introduces a break between
					 * messages.
					 */
					*omp = NULL;
					contpp = omp;
				}
			}
		}
		cbp = ibp->b_cont;
		freeb(ibp);
	} while ((ibp = cbp) != NULL);	/* next block, if any */

outofbufs:
	return (ibp);
#undef NEW_BLOCK
}


#if !defined(__sparc)
int
movtuc(size_t size, unsigned char *from, unsigned char *origto,
    unsigned char *table)
{
	unsigned char *to = origto;
	unsigned char c;

	while (size != 0 && (c = table[*from++]) != 0) {
		*to++ = c;
		size--;
	}
	return (to - origto);
}
#endif

static void
ldterm_flush_output(uchar_t c, queue_t *q, ldtermstd_state_t *tp)
{
	/* Already conditioned with IEXTEN during VDISCARD processing */
	if (tp->t_modes.c_lflag & FLUSHO)
		tp->t_modes.c_lflag &= ~FLUSHO;
	else {
		flushq(q, FLUSHDATA);	/* flush our write queue */
		/* flush ones below us */
		(void) putnextctl1(q, M_FLUSH, FLUSHW);
		if ((tp->t_echomp = allocb(EBSIZE, BPRI_HI)) != NULL) {
			(void) ldterm_echo(c, q, 1, tp);
			if (tp->t_msglen != 0)
				ldterm_reprint(q, EBSIZE, tp);
			if (tp->t_echomp != NULL) {
				putnext(q, tp->t_echomp);
				tp->t_echomp = NULL;
			}
		}
		tp->t_modes.c_lflag |= FLUSHO;
	}
}


/*
 * Signal generated by the reader: M_PCSIG and M_FLUSH messages sent.
 */
static void
ldterm_dosig(queue_t *q, int sig, uchar_t c, int mtype, int mode)
{
	ldtermstd_state_t *tp = (ldtermstd_state_t *)q->q_ptr;
	int sndsig = 0;

	/*
	 * c == \0 is brk case; need to flush on BRKINT even if
	 * noflsh is set.
	 */
	if ((!(tp->t_modes.c_lflag & NOFLSH)) || (c == '\0')) {
		if (mode) {
			if (tp->t_state & TS_TTSTOP) {
				sndsig = 1;
				(void) putnextctl1(q, mtype, sig);
			}
			/*
			 * Flush read or write side.
			 * Restart the input or output.
			 */
			if (mode & FLUSHR) {
				flushq(q, FLUSHDATA);
				(void) putnextctl1(WR(q), M_FLUSH, mode);
				if (tp->t_state & (TS_TBLOCK|TS_IFBLOCK)) {
					(void) putnextctl(WR(q), M_STARTI);
					tp->t_state &= ~(TS_TBLOCK|TS_IFBLOCK);
				}
			}
			if (mode & FLUSHW) {
				flushq(WR(q), FLUSHDATA);
				/*
				 * XXX This is extremely gross.
				 * Since we can't be sure our M_FLUSH
				 * will have run its course by the
				 * time we do the echo below, we set
				 * state and toss it in the write put
				 * routine to prevent flushing our
				 * own data.  Note that downstream
				 * modules on the write side will be
				 * flushed by the M_FLUSH sent above.
				 */
				tp->t_state |= TS_FLUSHWAIT;
				(void) putnextctl1(q, M_FLUSH, FLUSHW);
				if (tp->t_state & TS_TTSTOP) {
					(void) putnextctl(WR(q), M_START);
					tp->t_state &= ~(TS_TTSTOP|TS_OFBLOCK);
				}
			}
		}
	}
	tp->t_state &= ~TS_QUOT;
	if (sndsig == 0)
		(void) putnextctl1(q, mtype, sig);

	if (c != '\0') {
		if ((tp->t_echomp = allocb(4, BPRI_HI)) != NULL) {
			if (ldterm_echo(c, WR(q), 4, tp) > 0)
				putnext(WR(q), tp->t_echomp);
			else
				freemsg(tp->t_echomp);
			tp->t_echomp = NULL;
		}
	}
}


/*
 * Called when an M_IOCTL message is seen on the write queue; does
 * whatever we're supposed to do with it, and either replies
 * immediately or passes it to the next module down.
 */
static void
ldterm_do_ioctl(queue_t *q, mblk_t *mp)
{
	ldtermstd_state_t *tp;
	struct iocblk *iocp;
	struct eucioc *euciocp;	/* needed for EUC ioctls */
	ldterm_cs_data_user_t *csdp;
	int i;
	int locale_name_sz;
	uchar_t maxbytelen;
	uchar_t maxscreenlen;
	int error;

	iocp = (struct iocblk *)mp->b_rptr;
	tp = (ldtermstd_state_t *)q->q_ptr;

	switch (iocp->ioc_cmd) {

	case TCSETS:
	case TCSETSW:
	case TCSETSF:
		{
			/*
			 * Set current parameters and special
			 * characters.
			 */
			struct termios *cb;
			struct termios oldmodes;

			error = miocpullup(mp, sizeof (struct termios));
			if (error != 0) {
				miocnak(q, mp, 0, error);
				return;
			}

			cb = (struct termios *)mp->b_cont->b_rptr;

			oldmodes = tp->t_amodes;
			tp->t_amodes = *cb;
			if ((tp->t_amodes.c_lflag & PENDIN) &&
			    (tp->t_modes.c_lflag & IEXTEN)) {
				/*
				 * Yuk.  The C shell file completion
				 * code actually uses this "feature",
				 * so we have to support it.
				 */
				if (tp->t_message != NULL) {
					tp->t_state |= TS_RESCAN;
					qenable(RD(q));
				}
				tp->t_amodes.c_lflag &= ~PENDIN;
			}
			bcopy(tp->t_amodes.c_cc, tp->t_modes.c_cc, NCCS);

			/*
			 * ldterm_adjust_modes does not deal with
			 * cflags
			 */
			tp->t_modes.c_cflag = tp->t_amodes.c_cflag;

			ldterm_adjust_modes(tp);
			if (chgstropts(&oldmodes, tp, RD(q)) == (-1)) {
				miocnak(q, mp, 0, EAGAIN);
				return;
			}
			/*
			 * The driver may want to know about the
			 * following iflags: IGNBRK, BRKINT, IGNPAR,
			 * PARMRK, INPCK, IXON, IXANY.
			 */
			break;
		}

	case TCSETA:
	case TCSETAW:
	case TCSETAF:
		{
			/*
			 * Old-style "ioctl" to set current
			 * parameters and special characters. Don't
			 * clear out the unset portions, leave them
			 * as they are.
			 */
			struct termio *cb;
			struct termios oldmodes;

			error = miocpullup(mp, sizeof (struct termio));
			if (error != 0) {
				miocnak(q, mp, 0, error);
				return;
			}

			cb = (struct termio *)mp->b_cont->b_rptr;

			oldmodes = tp->t_amodes;
			tp->t_amodes.c_iflag =
			    (tp->t_amodes.c_iflag & 0xffff0000 | cb->c_iflag);
			tp->t_amodes.c_oflag =
			    (tp->t_amodes.c_oflag & 0xffff0000 | cb->c_oflag);
			tp->t_amodes.c_cflag =
			    (tp->t_amodes.c_cflag & 0xffff0000 | cb->c_cflag);
			tp->t_amodes.c_lflag =
			    (tp->t_amodes.c_lflag & 0xffff0000 | cb->c_lflag);

			bcopy(cb->c_cc, tp->t_modes.c_cc, NCC);
			/* TCGETS returns amodes, so update that too */
			bcopy(cb->c_cc, tp->t_amodes.c_cc, NCC);

			/* ldterm_adjust_modes does not deal with cflags */

			tp->t_modes.c_cflag = tp->t_amodes.c_cflag;

			ldterm_adjust_modes(tp);
			if (chgstropts(&oldmodes, tp, RD(q)) == (-1)) {
				miocnak(q, mp, 0, EAGAIN);
				return;
			}
			/*
			 * The driver may want to know about the
			 * following iflags: IGNBRK, BRKINT, IGNPAR,
			 * PARMRK, INPCK, IXON, IXANY.
			 */
			break;
		}

	case TCFLSH:
		/*
		 * Do the flush on the write queue immediately, and
		 * queue up any flush on the read queue for the
		 * service procedure to see.  Then turn it into the
		 * appropriate M_FLUSH message, so that the module
		 * below us doesn't have to know about TCFLSH.
		 */
		error = miocpullup(mp, sizeof (int));
		if (error != 0) {
			miocnak(q, mp, 0, error);
			return;
		}

		ASSERT(mp->b_datap != NULL);
		if (*(int *)mp->b_cont->b_rptr == 0) {
			ASSERT(mp->b_datap != NULL);
			(void) putnextctl1(q, M_FLUSH, FLUSHR);
			(void) putctl1(RD(q), M_FLUSH, FLUSHR);
		} else if (*(int *)mp->b_cont->b_rptr == 1) {
			flushq(q, FLUSHDATA);
			ASSERT(mp->b_datap != NULL);
			tp->t_state |= TS_FLUSHWAIT;
			(void) putnextctl1(RD(q), M_FLUSH, FLUSHW);
			(void) putnextctl1(q, M_FLUSH, FLUSHW);
		} else if (*(int *)mp->b_cont->b_rptr == 2) {
			flushq(q, FLUSHDATA);
			ASSERT(mp->b_datap != NULL);
			(void) putnextctl1(q, M_FLUSH, FLUSHRW);
			tp->t_state |= TS_FLUSHWAIT;
			(void) putnextctl1(RD(q), M_FLUSH, FLUSHRW);
		} else {
			miocnak(q, mp, 0, EINVAL);
			return;
		}
		ASSERT(mp->b_datap != NULL);
		iocp->ioc_rval = 0;
		miocack(q, mp, 0, 0);
		return;

	case TCXONC:
		error = miocpullup(mp, sizeof (int));
		if (error != 0) {
			miocnak(q, mp, 0, error);
			return;
		}

		switch (*(int *)mp->b_cont->b_rptr) {
		case 0:
			if (!(tp->t_state & TS_TTSTOP)) {
				(void) putnextctl(q, M_STOP);
				tp->t_state |= (TS_TTSTOP|TS_OFBLOCK);
			}
			break;

		case 1:
			if (tp->t_state & TS_TTSTOP) {
				(void) putnextctl(q, M_START);
				tp->t_state &= ~(TS_TTSTOP|TS_OFBLOCK);
			}
			break;

		case 2:
			(void) putnextctl(q, M_STOPI);
			tp->t_state |= (TS_TBLOCK|TS_IFBLOCK);
			break;

		case 3:
			(void) putnextctl(q, M_STARTI);
			tp->t_state &= ~(TS_TBLOCK|TS_IFBLOCK);
			break;

		default:
			miocnak(q, mp, 0, EINVAL);
			return;
		}
		ASSERT(mp->b_datap != NULL);
		iocp->ioc_rval = 0;
		miocack(q, mp, 0, 0);
		return;
		/*
		 * TCSBRK is expected to be handled by the driver.
		 * The reason its left for the driver is that when
		 * the argument to TCSBRK is zero driver has to drain
		 * the data and sending a M_IOCACK from LDTERM before
		 * the driver drains the data is going to cause
		 * problems.
		 */

		/*
		 * The following are EUC related ioctls.  For
		 * EUC_WSET, we have to pass the information on, even
		 * though we ACK the call.  It's vital in the EUC
		 * environment that everybody downstream knows about
		 * the EUC codeset widths currently in use; we
		 * therefore pass down the information in an M_CTL
		 * message.  It will bottom out in the driver.
		 */
	case EUC_WSET:
		{

			/* only needed for EUC_WSET */
			struct iocblk *riocp;

			mblk_t *dmp, *dmp_cont;

			/*
			 * If the user didn't supply any information,
			 * NAK it.
			 */
			error = miocpullup(mp, sizeof (struct eucioc));
			if (error != 0) {
				miocnak(q, mp, 0, error);
				return;
			}

			euciocp = (struct eucioc *)mp->b_cont->b_rptr;
			/*
			 * Check here for something reasonable.  If
			 * anything will take more than EUC_MAXW
			 * columns or more than EUC_MAXW bytes
			 * following SS2 or SS3, then just reject it
			 * out of hand. It's not impossible for us to
			 * do it, it just isn't reasonable.  So far,
			 * in the world, we've seen the absolute max
			 * columns to be 2 and the max number of
			 * bytes to be 3.  This allows room for some
			 * expansion of that, but it probably won't
			 * even be necessary. At the moment, we
			 * return a "range" error.  If you really
			 * need to, you can push EUC_MAXW up to over
			 * 200; it doesn't make sense, though, with
			 * only a CANBSIZ sized input limit (usually
			 * 256)!
			 */
			for (i = 0; i < 4; i++) {
				if ((euciocp->eucw[i] > EUC_MAXW) ||
				    (euciocp->scrw[i] > EUC_MAXW)) {
					miocnak(q, mp, 0, ERANGE);
					return;
				}
			}
			/*
			 * Otherwise, save the information in tp,
			 * force codeset 0 (ASCII) to be one byte,
			 * one column.
			 */
			cp_eucwioc(euciocp, &tp->eucwioc, EUCIN);
			tp->eucwioc.eucw[0] = tp->eucwioc.scrw[0] = 1;
			/*
			 * Now, check out whether we're doing
			 * multibyte processing. if we are, we need
			 * to allocate a block to hold the parallel
			 * array. By convention, we've been passed
			 * what amounts to a CSWIDTH definition.  We
			 * actually NEED the number of bytes for
			 * Codesets 2 & 3.
			 */
			tp->t_maxeuc = 0;	/* reset to say we're NOT */

			tp->t_state &= ~TS_MEUC;
			/*
			 * We'll set TS_MEUC if we're doing
			 * multi-column OR multi- byte OR both.  It
			 * makes things easier...  NOTE:  If we fail
			 * to get the buffer we need to hold display
			 * widths, then DON'T let the TS_MEUC bit get
			 * set!
			 */
			for (i = 0; i < 4; i++) {
				if (tp->eucwioc.eucw[i] > tp->t_maxeuc)
					tp->t_maxeuc = tp->eucwioc.eucw[i];
				if (tp->eucwioc.scrw[i] > 1)
					tp->t_state |= TS_MEUC;
			}
			if ((tp->t_maxeuc > 1) || (tp->t_state & TS_MEUC)) {
				if (!tp->t_eucp_mp) {
					if ((tp->t_eucp_mp = allocb(_TTY_BUFSIZ,
					    BPRI_HI)) == NULL) {
						tp->t_maxeuc = 1;
						tp->t_state &= ~TS_MEUC;
						cmn_err(CE_WARN,
						    "Can't allocate eucp_mp");
						miocnak(q, mp, 0, ENOSR);
						return;
					}
					/*
					 * here, if there's junk in
					 * the canonical buffer, then
					 * move the eucp pointer past
					 * it, so we don't run off
					 * the beginning.  This is a
					 * total botch, but will
					 * hopefully keep stuff from
					 * getting too messed up
					 * until the user flushes
					 * this line!
					 */
					if (tp->t_msglen) {
						tp->t_eucp =
						    tp->t_eucp_mp->b_rptr;
						for (i = tp->t_msglen; i; i--)
							*tp->t_eucp++ = 1;
					} else {
						tp->t_eucp =
						    tp->t_eucp_mp->b_rptr;
					}
				}
				/* doing multi-byte handling */
				tp->t_state |= TS_MEUC;

			} else if (tp->t_eucp_mp) {
				freemsg(tp->t_eucp_mp);
				tp->t_eucp_mp = NULL;
				tp->t_eucp = NULL;
			}

			/*
			 * Save the EUC width data we have at
			 * the t_csdata, set t_csdata.codeset_type to
			 * EUC one, and, switch the codeset methods at
			 * t_csmethods.
			 */
			bzero(&tp->t_csdata.eucpc_data,
			    (sizeof (ldterm_eucpc_data_t) *
			    LDTERM_CS_MAX_CODESETS));
			tp->t_csdata.eucpc_data[0].byte_length =
			    tp->eucwioc.eucw[1];
			tp->t_csdata.eucpc_data[0].screen_width =
			    tp->eucwioc.scrw[1];
			tp->t_csdata.eucpc_data[1].byte_length =
			    tp->eucwioc.eucw[2];
			tp->t_csdata.eucpc_data[1].screen_width =
			    tp->eucwioc.scrw[2];
			tp->t_csdata.eucpc_data[2].byte_length =
			    tp->eucwioc.eucw[3];
			tp->t_csdata.eucpc_data[2].screen_width =
			    tp->eucwioc.scrw[3];
			tp->t_csdata.version = LDTERM_DATA_VERSION;
			tp->t_csdata.codeset_type = LDTERM_CS_TYPE_EUC;
			/*
			 * We are not using the 'csinfo_num' anyway if the
			 * current codeset type is EUC. So, set it to
			 * the maximum possible.
			 */
			tp->t_csdata.csinfo_num =
			    LDTERM_CS_TYPE_EUC_MAX_SUBCS;
			if (tp->t_csdata.locale_name != (char *)NULL) {
				kmem_free(tp->t_csdata.locale_name,
				    strlen(tp->t_csdata.locale_name) + 1);
				tp->t_csdata.locale_name = (char *)NULL;
			}
			tp->t_csmethods = cs_methods[LDTERM_CS_TYPE_EUC];

			/*
			 * If we are able to allocate two blocks (the
			 * iocblk and the associated data), then pass
			 * it downstream, otherwise we'll need to NAK
			 * it, and drop whatever we WERE able to
			 * allocate.
			 */
			if ((dmp = mkiocb(EUC_WSET)) == NULL) {
				miocnak(q, mp, 0, ENOSR);
				return;
			}
			if ((dmp_cont = allocb(EUCSIZE, BPRI_HI)) == NULL) {
				freemsg(dmp);
				miocnak(q, mp, 0, ENOSR);
				return;
			}

			/*
			 * We got both buffers.  Copy out the EUC
			 * information (as we received it, not what
			 * we're using!) & pass it on.
			 */
			bcopy(mp->b_cont->b_rptr, dmp_cont->b_rptr, EUCSIZE);
			dmp_cont->b_wptr += EUCSIZE;
			dmp->b_cont = dmp_cont;
			dmp->b_datap->db_type = M_CTL;
			dmp_cont->b_datap->db_type = M_DATA;
			riocp = (struct iocblk *)dmp->b_rptr;
			riocp->ioc_count = EUCSIZE;
			putnext(q, dmp);

			/*
			 * Now ACK the ioctl.
			 */
			iocp->ioc_rval = 0;
			miocack(q, mp, 0, 0);
			return;
		}

	case EUC_WGET:
		error = miocpullup(mp, sizeof (struct eucioc));
		if (error != 0) {
			miocnak(q, mp, 0, error);
			return;
		}
		euciocp = (struct eucioc *)mp->b_cont->b_rptr;
		cp_eucwioc(&tp->eucwioc, euciocp, EUCOUT);
		iocp->ioc_rval = 0;
		miocack(q, mp, EUCSIZE, 0);
		return;

	case CSDATA_SET:
		error = miocpullup(mp, sizeof (ldterm_cs_data_user_t));
		if (error != 0) {
			miocnak(q, mp, 0, error);
			return;
		}

		csdp = (ldterm_cs_data_user_t *)mp->b_cont->b_rptr;

		/* Validate the codeset data provided. */
		if (csdp->version > LDTERM_DATA_VERSION ||
		    csdp->codeset_type < LDTERM_CS_TYPE_MIN ||
		    csdp->codeset_type > LDTERM_CS_TYPE_MAX) {
			miocnak(q, mp, 0, ERANGE);
			return;
		}

		if ((csdp->codeset_type == LDTERM_CS_TYPE_EUC &&
		    csdp->csinfo_num > LDTERM_CS_TYPE_EUC_MAX_SUBCS) ||
		    (csdp->codeset_type == LDTERM_CS_TYPE_PCCS &&
		    (csdp->csinfo_num < LDTERM_CS_TYPE_PCCS_MIN_SUBCS ||
		    csdp->csinfo_num > LDTERM_CS_TYPE_PCCS_MAX_SUBCS))) {
			miocnak(q, mp, 0, ERANGE);
			return;
		}

		maxbytelen = maxscreenlen = 0;
		if (csdp->codeset_type == LDTERM_CS_TYPE_EUC) {
			for (i = 0; i < LDTERM_CS_TYPE_EUC_MAX_SUBCS; i++) {
				if (csdp->eucpc_data[i].byte_length >
				    EUC_MAXW ||
				    csdp->eucpc_data[i].screen_width >
				    EUC_MAXW) {
					miocnak(q, mp, 0, ERANGE);
					return;
				}

				if (csdp->eucpc_data[i].byte_length >
				    maxbytelen)
					maxbytelen =
					    csdp->eucpc_data[i].byte_length;
				if (csdp->eucpc_data[i].screen_width >
				    maxscreenlen)
					maxscreenlen =
					    csdp->eucpc_data[i].screen_width;
			}
			/* POSIX/C locale? */
			if (maxbytelen == 0 && maxscreenlen == 0)
				maxbytelen = maxscreenlen = 1;
		} else if (csdp->codeset_type == LDTERM_CS_TYPE_PCCS) {
			for (i = 0; i < LDTERM_CS_MAX_CODESETS; i++) {
				if (csdp->eucpc_data[i].byte_length >
				    LDTERM_CS_MAX_BYTE_LENGTH) {
					miocnak(q, mp, 0, ERANGE);
					return;
				}
				if (csdp->eucpc_data[i].byte_length >
				    maxbytelen)
					maxbytelen =
					    csdp->eucpc_data[i].byte_length;
				if (csdp->eucpc_data[i].screen_width >
				    maxscreenlen)
					maxscreenlen =
					    csdp->eucpc_data[i].screen_width;
			}
		} else if (csdp->codeset_type == LDTERM_CS_TYPE_UTF8) {
			maxbytelen = 4;
			maxscreenlen = 2;
		}

		locale_name_sz = 0;
		if (csdp->locale_name) {
			for (i = 0; i < MAXNAMELEN; i++)
				if (csdp->locale_name[i] == '\0')
					break;
			/*
			 * We cannot have any string that is not NULL byte
			 * terminated.
			 */
			if (i >= MAXNAMELEN) {
				miocnak(q, mp, 0, ERANGE);
				return;
			}

			locale_name_sz = i + 1;
		}

		/*
		 * As the final check, if there was invalid codeset_type
		 * given, or invalid byte_length was specified, it's an error.
		 */
		if (maxbytelen <= 0 || maxscreenlen <= 0) {
			miocnak(q, mp, 0, ERANGE);
			return;
		}

		/* Do the switching. */
		tp->t_maxeuc = maxbytelen;
		tp->t_state &= ~TS_MEUC;
		if (maxbytelen > 1 || maxscreenlen > 1) {
			if (!tp->t_eucp_mp) {
				if (!(tp->t_eucp_mp = allocb(_TTY_BUFSIZ,
				    BPRI_HI))) {
					cmn_err(CE_WARN,
					    "Can't allocate eucp_mp");
					miocnak(q, mp, 0, ENOSR);
					return;
				}
				/*
				 * If there's junk in the canonical buffer,
				 * then move the eucp pointer past it,
				 * so we don't run off the beginning. This is
				 * a total botch, but will hopefully keep
				 * stuff from getting too messed up until
				 * the user flushes this line!
				 */
				if (tp->t_msglen) {
					tp->t_eucp = tp->t_eucp_mp->b_rptr;
					for (i = tp->t_msglen; i; i--)
						*tp->t_eucp++ = 1;
				} else {
					tp->t_eucp = tp->t_eucp_mp->b_rptr;
				}
			}

			/*
			 * We only set TS_MEUC for a multibyte/multi-column
			 * codeset.
			 */
			tp->t_state |= TS_MEUC;

			tp->t_csdata.version = csdp->version;
			tp->t_csdata.codeset_type = csdp->codeset_type;
			tp->t_csdata.csinfo_num = csdp->csinfo_num;
			bcopy(csdp->eucpc_data, tp->t_csdata.eucpc_data,
			    sizeof (ldterm_eucpc_data_t) *
			    LDTERM_CS_MAX_CODESETS);
			tp->t_csmethods = cs_methods[csdp->codeset_type];

			if (csdp->codeset_type == LDTERM_CS_TYPE_EUC) {
				tp->eucwioc.eucw[0] = 1;
				tp->eucwioc.scrw[0] = 1;

				tp->eucwioc.eucw[1] =
				    csdp->eucpc_data[0].byte_length;
				tp->eucwioc.scrw[1] =
				    csdp->eucpc_data[0].screen_width;

				tp->eucwioc.eucw[2] =
				    csdp->eucpc_data[1].byte_length + 1;
				tp->eucwioc.scrw[2] =
				    csdp->eucpc_data[1].screen_width;

				tp->eucwioc.eucw[3] =
				    csdp->eucpc_data[2].byte_length + 1;
				tp->eucwioc.scrw[3] =
				    csdp->eucpc_data[2].screen_width;
			} else {
				/*
				 * We are not going to use this data
				 * structure. So, clear it. Also, stty(1) will
				 * make use of the cleared tp->eucwioc when
				 * it prints out codeset width setting.
				 */
				bzero(&tp->eucwioc, EUCSIZE);
			}
		} else {
			/*
			 * If this codeset is a single byte codeset that
			 * requires only single display column for all
			 * characters, we switch to default EUC codeset
			 * methods and data setting.
			 */

			if (tp->t_eucp_mp) {
				freemsg(tp->t_eucp_mp);
				tp->t_eucp_mp = NULL;
				tp->t_eucp = NULL;
			}

			bzero(&tp->eucwioc, EUCSIZE);
			tp->eucwioc.eucw[0] = 1;
			tp->eucwioc.scrw[0] = 1;
			if (tp->t_csdata.locale_name != (char *)NULL) {
				kmem_free(tp->t_csdata.locale_name,
				    strlen(tp->t_csdata.locale_name) + 1);
			}
			tp->t_csdata = default_cs_data;
			tp->t_csmethods = cs_methods[LDTERM_CS_TYPE_EUC];
		}

		/* Copy over locale_name. */
		if (tp->t_csdata.locale_name != (char *)NULL) {
			kmem_free(tp->t_csdata.locale_name,
			    strlen(tp->t_csdata.locale_name) + 1);
		}
		if (locale_name_sz > 1) {
			tp->t_csdata.locale_name = (char *)kmem_alloc(
			    locale_name_sz, KM_SLEEP);
			(void) strcpy(tp->t_csdata.locale_name,
			    csdp->locale_name);
		} else {
			tp->t_csdata.locale_name = (char *)NULL;
		}

		/*
		 * Now ACK the ioctl.
		 */
		iocp->ioc_rval = 0;
		miocack(q, mp, 0, 0);
		return;

	case CSDATA_GET:
		error = miocpullup(mp, sizeof (ldterm_cs_data_user_t));
		if (error != 0) {
			miocnak(q, mp, 0, error);
			return;
		}

		csdp = (ldterm_cs_data_user_t *)mp->b_cont->b_rptr;

		csdp->version = tp->t_csdata.version;
		csdp->codeset_type = tp->t_csdata.codeset_type;
		csdp->csinfo_num = tp->t_csdata.csinfo_num;
		csdp->pad = tp->t_csdata.pad;
		if (tp->t_csdata.locale_name) {
			(void) strcpy(csdp->locale_name,
			    tp->t_csdata.locale_name);
		} else {
			csdp->locale_name[0] = '\0';
		}
		bcopy(tp->t_csdata.eucpc_data, csdp->eucpc_data,
		    sizeof (ldterm_eucpc_data_t) * LDTERM_CS_MAX_CODESETS);
		/*
		 * If the codeset is an EUC codeset and if it has 2nd and/or
		 * 3rd supplementary codesets, we subtract one from each
		 * byte length of the supplementary codesets. This is
		 * because single shift characters, SS2 and SS3, are not
		 * included in the byte lengths in the user space.
		 */
		if (csdp->codeset_type == LDTERM_CS_TYPE_EUC) {
			if (csdp->eucpc_data[1].byte_length)
				csdp->eucpc_data[1].byte_length -= 1;
			if (csdp->eucpc_data[2].byte_length)
				csdp->eucpc_data[2].byte_length -= 1;
		}
		iocp->ioc_rval = 0;
		miocack(q, mp, sizeof (ldterm_cs_data_user_t), 0);
		return;

	case PTSSTTY:
		tp->t_state |= TS_ISPTSTTY;
		break;

	}

	putnext(q, mp);
}


/*
 * Send an M_SETOPTS message upstream if any mode changes are being
 * made that affect the stream head options. returns -1 if allocb
 * fails, else returns 0.
 */
static int
chgstropts(struct termios *oldmodep, ldtermstd_state_t *tp, queue_t *q)
{
	struct stroptions optbuf;
	mblk_t *bp;

	optbuf.so_flags = 0;
	if ((oldmodep->c_lflag ^ tp->t_modes.c_lflag) & ICANON) {
		/*
		 * Canonical mode is changing state; switch the
		 * stream head to message-nondiscard or byte-stream
		 * mode.  Also, rerun the service procedure so it can
		 * change its mind about whether to send data
		 * upstream or not.
		 */
		if (tp->t_modes.c_lflag & ICANON) {
			DEBUG4(("CHANGING TO CANON MODE\n"));
			optbuf.so_flags = SO_READOPT|SO_MREADOFF;
			optbuf.so_readopt = RMSGN;

			/*
			 * if there is a pending raw mode timeout,
			 * clear it
			 */

			/*
			 * Clear VMIN/VTIME state, cancel timers
			 */
			vmin_satisfied(q, tp, 0);
		} else {
			DEBUG4(("CHANGING TO RAW MODE\n"));
			optbuf.so_flags = SO_READOPT|SO_MREADON;
			optbuf.so_readopt = RNORM;
		}
	}
	if ((oldmodep->c_lflag ^ tp->t_modes.c_lflag) & TOSTOP) {
		/*
		 * The "stop on background write" bit is changing.
		 */
		if (tp->t_modes.c_lflag & TOSTOP)
			optbuf.so_flags |= SO_TOSTOP;
		else
			optbuf.so_flags |= SO_TONSTOP;
	}
	if (optbuf.so_flags != 0) {
		if ((bp = allocb(sizeof (struct stroptions), BPRI_HI)) ==
		    NULL) {
			return (-1);
		}
		*(struct stroptions *)bp->b_wptr = optbuf;
		bp->b_wptr += sizeof (struct stroptions);
		bp->b_datap->db_type = M_SETOPTS;
		DEBUG4(("M_SETOPTS to stream head\n"));
		putnext(q, bp);
	}
	return (0);
}


/*
 * Called when an M_IOCACK message is seen on the read queue;
 * modifies the data being returned, if necessary, and passes the
 * reply up.
 */
static void
ldterm_ioctl_reply(queue_t *q, mblk_t *mp)
{
	ldtermstd_state_t *tp;
	struct iocblk *iocp;

	iocp = (struct iocblk *)mp->b_rptr;
	tp = (ldtermstd_state_t *)q->q_ptr;

	switch (iocp->ioc_cmd) {

	case TCGETS:
		{
			/*
			 * Get current parameters and return them to
			 * stream head eventually.
			 */
			struct termios *cb =
			    (struct termios *)mp->b_cont->b_rptr;

			/*
			 * cflag has cflags sent upstream by the
			 * driver
			 */
			tcflag_t cflag = cb->c_cflag;

			*cb = tp->t_amodes;
			if (cflag != 0)
				cb->c_cflag = cflag;	/* set by driver */
			break;
		}

	case TCGETA:
		{
			/*
			 * Old-style "ioctl" to get current
			 * parameters and return them to stream head
			 * eventually.
			 */
			struct termio *cb =
			    (struct termio *)mp->b_cont->b_rptr;

			cb->c_iflag = tp->t_amodes.c_iflag; /* all except the */
			cb->c_oflag = tp->t_amodes.c_oflag; /* cb->c_cflag */
			cb->c_lflag = tp->t_amodes.c_lflag;

			if (cb->c_cflag == 0)	/* not set by driver */
				cb->c_cflag = tp->t_amodes.c_cflag;

			cb->c_line = 0;
			bcopy(tp->t_amodes.c_cc, cb->c_cc, NCC);
			break;
		}
	}
	putnext(q, mp);
}


/*
 * A VMIN/VTIME request has been satisfied. Cancel outstanding timers
 * if they exist, clear TS_MREAD state, and send upstream. If a NULL
 * queue ptr is passed, just reset VMIN/VTIME state.
 */
static void
vmin_satisfied(queue_t *q, ldtermstd_state_t *tp, int sendup)
{
	ASSERT(q);
	if (tp->t_vtid != 0)  {
		DEBUG4(("vmin_satisfied: cancelled timer id %d\n", tp->t_vtid));
		(void) quntimeout(q, tp->t_vtid);
		tp->t_vtid = 0;
	}
	if (sendup) {
		if (tp->t_msglen == 0 && V_MIN) {
			/* EMPTY */
			DEBUG4(("vmin_satisfied: data swiped, msglen = 0\n"));
		} else {
			if ((!q->q_first) ||
			    (q->q_first->b_datap->db_type != M_DATA) ||
			    (tp->t_msglen >= LDCHUNK)) {
				ldterm_msg_upstream(q, tp);
				DEBUG4(("vmin_satisfied: delivering data\n"));
			}
		}
	} else {
		/* EMPTY */
		DEBUG4(("vmin_satisfied: VMIN/TIME state reset\n"));
	}
	tp->t_state &= ~TS_MREAD;
}

static void
vmin_settimer(queue_t *q)
{
	ldtermstd_state_t *tp;

	tp = (ldtermstd_state_t *)q->q_ptr;

	/*
	 * Don't start any time bombs.
	 */
	if (tp->t_state & TS_CLOSE)
		return;

	/*
	 * tp->t_vtid should NOT be set here unless VMIN > 0 and
	 * VTIME > 0.
	 */
	if (tp->t_vtid) {
		if (V_MIN && V_TIME) {
			/* EMPTY */
			DEBUG4(("vmin_settimer: timer restarted, old tid=%d\n",
			    tp->t_vtid));
		} else {
			/* EMPTY */
			DEBUG4(("vmin_settimer: tid = %d was still active!\n",
			    tp->t_vtid));
		}
		(void) quntimeout(q, tp->t_vtid);
		tp->t_vtid = 0;
	}
	tp->t_vtid = qtimeout(q, vmin_timed_out, q,
	    (clock_t)(V_TIME * (hz / 10)));
	DEBUG4(("vmin_settimer: timer started, tid = %d\n", tp->t_vtid));
}


/*
 * BRRrrringgg!! VTIME was satisfied instead of VMIN
 */
static void
vmin_timed_out(void *arg)
{
	queue_t *q = arg;
	ldtermstd_state_t *tp;

	tp = (ldtermstd_state_t *)q->q_ptr;

	DEBUG4(("vmin_timed_out: tid = %d\n", tp->t_vtid));
	/* don't call untimeout now that we are in the timeout */
	tp->t_vtid = 0;
	vmin_satisfied(q, tp, 1);
}


/*
 * Routine to adjust termios flags to be processed by the line
 * discipline. Driver below sends a termios structure, with the flags
 * the driver intends to process. XOR'ing the driver sent termios
 * structure with current termios structure with the default values
 * (or set by ioctls from userland), we come up with a new termios
 * structrue, the flags of which will be used by the line discipline
 * in processing input and output. On return from this routine, we
 * will have the following fields set in tp structure -->
 * tp->t_modes:	modes the line discipline will process tp->t_amodes:
 * modes the user process thinks the line discipline is processing
 */

static void
ldterm_adjust_modes(ldtermstd_state_t *tp)
{

	DEBUG6(("original iflag = %o\n", tp->t_modes.c_iflag));
	tp->t_modes.c_iflag = tp->t_amodes.c_iflag & ~(tp->t_dmodes.c_iflag);
	tp->t_modes.c_oflag = tp->t_amodes.c_oflag & ~(tp->t_dmodes.c_oflag);
	tp->t_modes.c_lflag = tp->t_amodes.c_lflag & ~(tp->t_dmodes.c_lflag);
	DEBUG6(("driver iflag = %o\n", tp->t_dmodes.c_iflag));
	DEBUG6(("apparent iflag = %o\n", tp->t_amodes.c_iflag));
	DEBUG6(("effective iflag = %o\n", tp->t_modes.c_iflag));

	/* No negotiation of clfags  c_cc array special characters */
	/*
	 * Copy from amodes to modes already done by TCSETA/TCSETS
	 * code
	 */
}


/*
 * Erase one multi-byte character.  If TS_MEUC is set AND this
 * is a multi-byte character, then this should be called instead of
 * ldterm_erase.  "ldterm_erase" will handle ASCII nicely, thank you.
 *
 * We'd better be pointing to the last byte.  If we aren't, it will get
 * screwed up.
 */
static void
ldterm_csi_erase(queue_t *q, size_t ebsize, ldtermstd_state_t *tp)
{
	int i, ung;
	uchar_t *p, *bottom;
	uchar_t u8[LDTERM_CS_MAX_BYTE_LENGTH];
	int c;
	int j;
	int len;

	if (tp->t_eucleft) {
		/* XXX Ick.  We're in the middle of an EUC! */
		/* What to do now? */
		ldterm_eucwarn(tp);
		return;		/* ignore it??? */
	}
	bottom = tp->t_eucp_mp->b_rptr;
	p = tp->t_eucp - 1;	/* previous byte */
	if (p < bottom)
		return;
	ung = 1;		/* number of bytes to un-get from buffer */
	/*
	 * go through the buffer until we find the beginning of the
	 * multi-byte char.
	 */
	while ((*p == 0) && (p > bottom)) {
		p--;
		++ung;
	}

	/*
	 * Now, "ung" is the number of bytes to unget from the buffer
	 * and "*p" is the disp width of it. Fool "ldterm_rubout"
	 * into thinking we're rubbing out ASCII characters.  Do that
	 * for the display width of the character.
	 *
	 * Also we accumulate bytes of the character so that if the character
	 * is a UTF-8 character, we will get the display width of the UTF-8
	 * character.
	 */
	if (ung >= LDTERM_CS_MAX_BYTE_LENGTH) {
		j = len = LDTERM_CS_MAX_BYTE_LENGTH;
	} else {
		j = len = ung;
	}
	for (i = 0; i < ung; i++) {	/* remove from buf */
		if ((c = ldterm_unget(tp)) != (-1)) {
			ldterm_trim(tp);
			if (j > 0)
				u8[--j] = (uchar_t)c;
		}
	}
	if (*p == UNKNOWN_WIDTH) {
		if (tp->t_csdata.codeset_type == LDTERM_CS_TYPE_UTF8) {
			*p = ldterm_utf8_width(u8, len);
		} else {
			*p = 1;
		}
	}
	for (i = 0; i < (int)*p; i++)	/* remove from screen */
		ldterm_rubout(' ', q, ebsize, tp);
	/*
	 * Adjust the parallel array pointer.  Zero out the contents
	 * of parallel array for this position, just to make sure...
	 */
	tp->t_eucp = p;
	*p = 0;
}


/*
 * This is kind of a safety valve.  Whenever we see a bad sequence
 * come up, we call eucwarn.  It just tallies the junk until a
 * threshold is reached.  Then it prints ONE message on the console
 * and not any more. Hopefully, we can catch garbage; maybe it will
 * be useful to somebody.
 */
static void
ldterm_eucwarn(ldtermstd_state_t *tp)
{
	++tp->t_eucwarn;
#ifdef DEBUG
	if ((tp->t_eucwarn > EUC_WARNCNT) && !(tp->t_state & TS_WARNED)) {
		cmn_err(CE_WARN,
		    "ldterm: tty at addr %p in multi-byte mode --",
		    (void *)tp);
		cmn_err(CE_WARN,
		    "Over %d bad EUC characters this session", EUC_WARNCNT);
		tp->t_state |= TS_WARNED;
	}
#endif
}


/*
 * Copy an "eucioc_t" structure.  We use the structure with
 * incremented values for Codesets 2 & 3.  The specification in
 * eucioctl is that the sames values as the CSWIDTH definition at
 * user level are passed to us. When we copy it "in" to ourselves, we
 * do the increment.  That allows us to avoid treating each character
 * set separately for "t_eucleft" purposes. When we copy it "out" to
 * return it to the user, we decrement the values so the user gets
 * what it expects, and it matches CSWIDTH in the environment (if
 * things are consistent!).
 */
static void
cp_eucwioc(eucioc_t *from, eucioc_t *to, int dir)
{
	bcopy(from, to, EUCSIZE);
	if (dir == EUCOUT) {	/* copying out to user */
		if (to->eucw[2])
			--to->eucw[2];
		if (to->eucw[3])
			--to->eucw[3];
	} else {		/* copying in */
		if (to->eucw[2])
			++to->eucw[2];
		if (to->eucw[3])
			++to->eucw[3];
	}
}


/*
 * Take the first byte of a multi-byte, or an ASCII char.  Return its
 * codeset. If it's NOT the first byte of an EUC, then the return
 * value may be garbage, as it's probably not SS2 or SS3, and
 * therefore must be in codeset 1.  Another bizarre catch here is the
 * fact that we don't do anything about the "C1" control codes.  In
 * real life, we should; but nobody's come up with a good way of
 * treating them.
 */

static int
ldterm_codeset(uchar_t codeset_type, uchar_t c)
{

	if (ISASCII(c))
		return (0);

	if (codeset_type != LDTERM_CS_TYPE_EUC)
		return (1);

	switch (c) {
	case SS2:
		return (2);
	case SS3:
		return (3);
	default:
		return (1);
	}
}

/* The following two functions are additional EUC codeset specific methods. */
/*
 * ldterm_dispwidth - Take the first byte of an EUC (or ASCII) and
 * return the display width.  Since this is intended mostly for
 * multi-byte handling, it returns EUC_TWIDTH for tabs so they can be
 * differentiated from EUC characters (assumption: EUC require fewer
 * than 255 columns).  Also, if it's a backspace and !flag, it
 * returns EUC_BSWIDTH.  Newline & CR also depend on flag.  This
 * routine SHOULD be cleaner than this, but we have the situation
 * where we may or may not be counting control characters as having a
 * column width. Therefore, the computation of ASCII is pretty messy.
 * The caller will be storing the value, and then switching on it
 * when it's used.  We really should define the EUC_TWIDTH and other
 * constants in a header so that the routine could be used in other
 * modules in the kernel.
 */
static int
__ldterm_dispwidth_euc(uchar_t c, void *p, int mode)
{
	ldtermstd_state_t *tp = (ldtermstd_state_t *)p;

	if (ISASCII(c)) {
		if (c <= '\037') {
			switch (c) {
			case '\t':
				return (EUC_TWIDTH);
			case '\b':
				return (mode ? 2 : EUC_BSWIDTH);
			case '\n':
				return (EUC_NLWIDTH);
			case '\r':
				return (mode ? 2 : EUC_CRWIDTH);
			default:
				return (mode ? 2 : 0);
			}
		}
		return (1);
	}
	switch (c) {
	case SS2:
		return (tp->eucwioc.scrw[2]);
	case SS3:
		return (tp->eucwioc.scrw[3]);
	default:
		return (tp->eucwioc.scrw[1]);
	}
}

/*
 * ldterm_memwidth_euc - Take the first byte of an EUC (or an ASCII char)
 * and return its memory width.  The routine could have been
 * implemented to use only the codeset number, but that would require
 * the caller to have that value available.  Perhaps the user doesn't
 * want to make the extra call or keep the value of codeset around.
 * Therefore, we use the actual character with which they're
 * concerned.  This should never be called with anything but the
 * first byte of an EUC, otherwise it will return a garbage value.
 */
static int
__ldterm_memwidth_euc(uchar_t c, void *p)
{
	ldtermstd_state_t *tp = (ldtermstd_state_t *)p;

	if (ISASCII(c))
		return (1);
	switch (c) {
	case SS2:
		return (tp->eucwioc.eucw[2]);
	case SS3:
		return (tp->eucwioc.eucw[3]);
	default:
		return (tp->eucwioc.eucw[1]);
	}
}


/* The following two functions are PCCS codeset specific methods. */
static int
__ldterm_dispwidth_pccs(uchar_t c, void *p, int mode)
{
	ldtermstd_state_t *tp = (ldtermstd_state_t *)p;
	int i;

	if (ISASCII(c)) {
		if (c <= '\037') {
			switch (c) {
			case '\t':
				return (EUC_TWIDTH);
			case '\b':
				return (mode ? 2 : EUC_BSWIDTH);
			case '\n':
				return (EUC_NLWIDTH);
			case '\r':
				return (mode ? 2 : EUC_CRWIDTH);
			default:
				return (mode ? 2 : 0);
			}
		}
		return (1);
	}

	for (i = 0; i < tp->t_csdata.csinfo_num; i++) {
		if (c >= tp->t_csdata.eucpc_data[i].msb_start &&
		    c <= tp->t_csdata.eucpc_data[i].msb_end)
			return (tp->t_csdata.eucpc_data[i].screen_width);
	}

	/*
	 * If this leading byte is not in the range list, either provided
	 * locale data is not sufficient or we encountered an invalid
	 * character. We return 1 in this case as a fallback value.
	 */
	return (1);
}

static int
__ldterm_memwidth_pccs(uchar_t c, void *p)
{
	ldtermstd_state_t *tp = (ldtermstd_state_t *)p;
	int i;

	for (i = 0; i < tp->t_csdata.csinfo_num; i++) {
		if (c >= tp->t_csdata.eucpc_data[i].msb_start &&
		    c <= tp->t_csdata.eucpc_data[i].msb_end)
			return (tp->t_csdata.eucpc_data[i].byte_length);
	}

	/*
	 * If this leading byte is not in the range list, either provided
	 * locale data is not sufficient or we encountered an invalid
	 * character. We return 1 in this case as a fallback value.
	 */
	return (1);
}


/* The following two functions are UTF-8 codeset specific methods. */
static int
__ldterm_dispwidth_utf8(uchar_t c, void *p, int mode)
{
	ldtermstd_state_t *tp = (ldtermstd_state_t *)p;

	if (ISASCII(c)) {
		if (c <= '\037') {
			switch (c) {
			case '\t':
				return (EUC_TWIDTH);
			case '\b':
				return (mode ? 2 : EUC_BSWIDTH);
			case '\n':
				return (EUC_NLWIDTH);
			case '\r':
				return (mode ? 2 : EUC_CRWIDTH);
			default:
				return (mode ? 2 : 0);
			}
		}
		return (1);
	}

	/* This is to silence the lint. */
	if (tp->t_csdata.codeset_type != LDTERM_CS_TYPE_UTF8)
		return (1);

	/*
	 * If it is a valid leading byte of a UTF-8 character, we set
	 * the width as 'UNKNOWN_WIDTH' for now. We need to have all
	 * the bytes to figure out the display width.
	 */
	if (c >= (uchar_t)0xc0 && c <= (uchar_t)0xfd)
		return (UNKNOWN_WIDTH);

	/*
	 * If it is an invalid leading byte, we just do our best by
	 * giving the display width of 1.
	 */
	return (1);
}


static int
__ldterm_memwidth_utf8(uchar_t c, void *p)
{
	ldtermstd_state_t *tp = (ldtermstd_state_t *)p;
	int len;

	/*
	 * If the codeset type doesn't match, we treat them as
	 * an illegal character and return 1.
	 */
	if (tp->t_csdata.codeset_type != LDTERM_CS_TYPE_UTF8)
		return (1);

	len = u8_number_of_bytes[c];

	/*
	 * If this is a start of an illegal character, we treat
	 * such as an 1 byte character and screen out.
	 */
	return ((len <= 0) ? 1 : len);
}

static uchar_t
ldterm_utf8_width(uchar_t *u8, int length)
{
	int i;
	int j;
	uint_t intcode = 0;

	if (length == 0)
		return ('\0');

	j = u8_number_of_bytes[u8[0]] - 1;

	/*
	 * If the UTF-8 character is out of UTF-16 code range, or,
	 * if it is either an ASCII character or an invalid leading byte for
	 * a UTF-8 character, return 1.
	 */
	if (length > 4 || j <= 0)
		return ('\1');

	intcode = u8[0] & u8_masks_tbl[j];
	for (i = 1; j > 0; j--, i++) {
		/*
		 * The following additional checking is needed to conform to
		 * the "UTF-8 Corrigendum" introduced at the Unicode 3.1 and
		 * then updated one more time at the Unicode 3.2.
		 */
		if (i == 1) {
			if (u8[i] < u8_valid_min_2nd_byte[u8[0]] ||
			    u8[i] > u8_valid_max_2nd_byte[u8[0]])
				return ('\1');
		} else if (u8[i] < (uchar_t)LDTERM_CS_TYPE_UTF8_MIN_BYTE ||
		    u8[i] > (uchar_t)LDTERM_CS_TYPE_UTF8_MAX_BYTE)
			return ('\1');

		/*
		 * All subsequent bytes of UTF-8 character has the following
		 * binary encoding:
		 *
		 * 10xx xxxx
		 *
		 * hence left shift six bits to make space and then get
		 * six bits from the new byte.
		 */
		intcode = (intcode << LDTERM_CS_TYPE_UTF8_SHIFT_BITS) |
		    (u8[i] & LDTERM_CS_TYPE_UTF8_BIT_MASK);
	}

	i = 0;
	if (intcode <= LDTERM_CS_TYPE_UTF8_MAX_P00) {
		/* Basic Multilingual Plane. */
		i = intcode / 4;
		j = intcode % 4;
		switch (j) {
		case 0:
			i = ldterm_ucode[0][i].u0;
			break;
		case 1:
			i = ldterm_ucode[0][i].u1;
			break;
		case 2:
			i = ldterm_ucode[0][i].u2;
			break;
		case 3:
			i = ldterm_ucode[0][i].u3;
			break;
		}
	} else if (intcode <= LDTERM_CS_TYPE_UTF8_MAX_P01) {
		/* Secondary Multilingual Plane. */
		intcode = intcode & (uint_t)0xffff;
		i = intcode / 4;
		j = intcode % 4;
		switch (j) {
		case 0:
			i = ldterm_ucode[1][i].u0;
			break;
		case 1:
			i = ldterm_ucode[1][i].u1;
			break;
		case 2:
			i = ldterm_ucode[1][i].u2;
			break;
		case 3:
			i = ldterm_ucode[1][i].u3;
			break;
		}
	} else if ((intcode >= LDTERM_CS_TYPE_UTF8_MIN_CJKEXTB &&
	    intcode <= LDTERM_CS_TYPE_UTF8_MAX_CJKEXTB) ||
	    (intcode >= LDTERM_CS_TYPE_UTF8_MIN_CJKCOMP &&
	    intcode <= LDTERM_CS_TYPE_UTF8_MAX_CJKCOMP) ||
	    (intcode >= LDTERM_CS_TYPE_UTF8_MIN_P15 &&
	    intcode <= LDTERM_CS_TYPE_UTF8_MAX_P15) ||
	    (intcode >= LDTERM_CS_TYPE_UTF8_MIN_P16 &&
	    intcode <= LDTERM_CS_TYPE_UTF8_MAX_P16)) {
		/*
		 * Supplementary Plane for CJK Ideographs and
		 * Private Use Planes.
		 */
		return ('\2');
	} else if ((intcode >= LDTERM_CS_TYPE_UTF8_MIN_P14 &&
	    intcode <= LDTERM_CS_TYPE_UTF8_MAX_P14) ||
	    (intcode >= LDTERM_CS_TYPE_UTF8_MIN_VARSEL &&
	    intcode <= LDTERM_CS_TYPE_UTF8_MAX_VARSEL)) {
		/*
		 * Some Special Purpose Plane characters:
		 * These are like control characters and not printable.
		 */
		return ('\0');
	}

	/*
	 * We return the display width of 1 for all character code points
	 * that we didn't catch from the above logic and also for combining
	 * and conjoining characters with width value of zero.
	 *
	 * In particular, the reason why we are returning 1 for combining
	 * and conjoining characters is because the GUI-based terminal
	 * emulators are not yet capable of properly handling such characters
	 * and in most of the cases, they just treat such characters as if
	 * they occupy a display cell. If the terminal emulators are capable of
	 * handling the characters correctly, then, this logic of returning
	 * 1 should be revisited and changed. See CR 6660526 for more
	 * details on this.
	 */
	return ((i == 0) ? '\1' : (uchar_t)i);
}
