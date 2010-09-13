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
 * Copyright 1988 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include "codeset.h"
#include "mbextern.h"
#include "iso2022.h"

#define TO_MULTI	2
#define TO_SINGLE	1

#define BIT7ENV		7	/* 7bit enviornment */
#define BIT8ENV		8	/* 8bit environment */
#define NUM_OF_STATES	4	/* G0, G1, G2, G3 */
#define BIT8(_ch)	(_ch & 0x80)
#define MAXSIZE		100	/* ESC LOCK upper lower */

#define USE_STATE	0	/* use the actual _state info */
#define USE_CONTROL	1	/* use C0 or C1 */
#define USE_SS2		2	/* use Single shift 2 */
#define USE_SS3		3	/* use Single shift 3 */

#define G0MASK	0x0000
#define G1MASK	0x0080
#define G2MASK	0x8000
#define G3MASK	0x8080
#define FINAL	0x33		/* Temporary final character */

#define MMB_CUR_MAX 128

/*
 * Keep state informations
 */
struct state {
	char width;	/* 1 or 2 */
	char final;	/* final character */
};

static char _my_env = BIT7ENV;	/* default 7bits environment */
static struct state Invoked_G0, Invoked_G1;
static char _currentG0 = G0;
static char _currentG1 = G1;
static struct state _des_states[NUM_OF_STATES] = {
	{-1, 0}, {-1, 0}, {-1, 0}, {01, 0}
};

void _savestates(void);	/* save states */
void _restorestates(void);	/* restore states */
void _initializestates(void);/* Initialize states */


/*
 * Variables for wc*tomb*()
 */
static char _currentOUT = G0; /* G0, G1, G2 or G3 */
static int	prevcsize = 1;

/*
 * mbtowc - subroutine for most iso codeset sequences
 */
int
_mbtowc_iso(wchar_t *pwc, char *s, size_t n)
{
	unsigned char ch;		
	unsigned char tch;	/* temporary use */
	unsigned char *us = (unsigned char *)s;
	int gen_wide_state = USE_STATE; /* used in gen_wide: */
	int length = 0;
	int len = 0;
	wchar_t wide;
	int mask;
	int i;

	isowidth_t * isoinfo = (isowidth_t *) _code_set_info.code_info;

	/*
	 * initialize _g0_stuff
	 */
	if (_des_states[G0].width == -1) {
		_des_states[G0].width = isoinfo->g0_len;
		_des_states[G1].width = isoinfo->g1_len;
		_des_states[G2].width = isoinfo->g2_len;
		_des_states[G3].width = isoinfo->g3_len;
		_my_env = isoinfo->bit_env;

		Invoked_G0 = _des_states[G0];
		Invoked_G1 = _des_states[G1];
	}
		
	/*
	 * get character and proceed
	 */
loop:
	ch = *us++; 
	if (++length > n) return (-1);		/* too long */
	switch (ch) {	/* get a character */
	/* escape sequence or locking shifts */
	case ESC:	/* escape sequence */
		gen_wide_state = USE_STATE; /* used in gen_wide: */
		ch = *us++; 
		if (++length > n) return (-1);	/* too long */
		switch (ch) {
		/* DESIGNATE */
		case 0x24:		/* designate */
			ch = *us++; 
			if (++length > n) return (-1);	/* too long */
			switch (ch) {
			case 0x28:	case 0x29:
			case 0x2A:	case 0x2B:
			case 0x2D:	case 0x2E:
			case 0x2F:
				tch = ch;	/* save this to decide _des_state */
				/* Skip intermidiates */
				do {
					ch = *us++;
					if (++length > n) return (-1);	/* too long */
				} while (ch >= 0x20 && ch <= 0x2F);
				if (ch < 0x30)		/* ch should be a final character */
					return (-1);	/* error */
				if (tch == 0x28)	
					i = G0;
				else if (tch == 0x29 || tch == 0x2D)
					i = G1;
				else if (tch == 0x2A || tch == 0x2E)
					i = G2;
				else /* (tch == 0x2B || tch == 0x2F) */
					i = G3;
				/* updates state info */
				_des_states[i].width = TO_MULTI;
				_des_states[i].final = ch;

				goto loop;
				break;
			default:
				/* This is an illegal sequence */
				return (-1);
				break;
			}
			break;
		case 0x28:		/* designate */
		case 0x29: case 0x2A: case 0x2B:
		case 0x2D: case 0x2E: case 0x2F:
			tch = ch;	/* save this to decide _des_state */
			/* Skip intermidiates */
			do {
				ch = *us++;
				if (++length > n) return (-1);	/* too long */
			} while (ch >= 0x20 && ch <= 0x2F);
			if (ch < 0x30)		/* ch should be a final character */
				return (-1);	/* error */
			if (tch == 0x28)	
				i = G0;
			else if (tch == 0x29 || tch == 0x2D)
				i = G1;
			else if (tch == 0x2A || tch == 0x2E)
				i = G2;
			else /* (tch == 0x2B || tch == 0x2F) */
				i = G3;
			/* updates state info */
			_des_states[i].width = TO_SINGLE;
			_des_states[i].final = ch;

			goto loop;
			break;

		/* LOCKING SHIFTS */
		case LS1R:		/* locking shift LS1R */;
			Invoked_G1 = _des_states[G1];
			_currentG1 = G1;
			goto loop;
			break;
		case LS2:		/* locking shift LS2 */
			Invoked_G0 = _des_states[G2];
			_currentG0 = G2;
			goto loop;
			break;
		case LS2R:		/* locking shift LS2R */
			Invoked_G1 = _des_states[G2];
			_currentG1 = G2;
			goto loop;
			break;
		case LS3:		/* locking shift LS3 */
			Invoked_G0 = _des_states[G3];
			_currentG0 = G3;
			goto loop;
			break;
		case LS3R:		/* locking shift LS3R */
			Invoked_G1 = _des_states[G3];
			_currentG1 = G3;
			goto loop;
			break;

		/* CONTROL FUNCTIONS */
		case 0x21:		/* C0 sets */
		case 0x22:		/* C1 sets */
			do {
				ch = *us++;
				if (++length > n) return (-1);	/* too long */
			} while (ch >= 0x20 && ch <= 0x2F);
			if (ch < 0x30)		/* ch should be a final character */
				return (-1);	/* error */
			goto loop;
			break;
		
		/* SINGLE SHIFT for 7bit environment */
		case SS2_7B:		/* Single shift SS2 for 7bits */
		case SS3_7B:		/* Single shoft SS3 for 7bits */
			if (ch == SS2_7B)
				gen_wide_state = USE_SS2;
			else
				gen_wide_state = USE_SS3;
			goto loop;
			break;

		default:		/* should be an error */
			return (-1);
			break;
		}
	/* locking shifts */
	case LS0:
		gen_wide_state = USE_STATE; /* used in gen_wide: */
		Invoked_G0 = _des_states[G0];
		_currentG0 = G0;
		goto loop;
		break;

	case LS1:
		gen_wide_state = USE_STATE; /* used in gen_wide: */
		Invoked_G0 = _des_states[G1];
		_currentG0 = G1;
		goto loop;
		break;

	/* Single shift SS3 and SS2 for 8bits */
	case SS2_8B:
	case SS3_8B:
		if (ch == SS2_8B)
			gen_wide_state = USE_SS2;
		else
			gen_wide_state = USE_SS3;
		goto loop;
		break;

	/* This character is not any special character/
	 * It does not change any state.
	 * Goto where it generates wide character.
	 */
	default:
		/*
		 * Use this ch to generate pwc.
		 */
		if (ch == 0) {	/* end of string or 0 */
			wide = 0;
			mask = 0;
			goto gen_wide;
		}
		break;
	}


	/*
	 * Generate pwc here.
	 * The information here is 
	 * 	current state and length. If the length is two, you need to
	 *      read one more character. 
	 */
	switch (gen_wide_state) {
	case USE_STATE:
		if (BIT8(ch)) {	/* 8bit environment ? */
			/* current mode is G1 mode */
			if (Invoked_G1.width == 2) {
				tch = *us++;
				if (++length > n) return (-1);
				wide = ch;
				wide = (wide << 8 | tch);
			}
			else {
				wide = ch;
			}
			if (_currentG1 == G0)	mask = G0MASK;
			else if (_currentG1 == G1) mask = G1MASK;
			else if (_currentG1 == G2) mask = G2MASK;
			else mask = G3MASK;
		}	
		else {
			/* current mode is G0 mode */
			if (Invoked_G0.width == 2) {
				tch = *us++;
				if (++length > n) return (-1);
				wide = ch;
				wide = (wide << 8 | tch);
			}
			else {
				wide = ch;
			}
			if (_currentG0 == G0)	mask = G0MASK;
			else if (_currentG0 == G1) mask = G1MASK;
			else if (_currentG0 == G2) mask = G2MASK;
			else mask = G3MASK;
		}
		break;
	case USE_SS2:
		if (_des_states[G2].width == 2) {
			tch = *us++;
			if (++length > n) return (-1);
			wide = ch;
			wide = (wide << 8 | tch);
		}
		else {
			wide = ch;
		}
		mask = G2MASK;
		break;
	case USE_SS3:
		if (_des_states[G3].width == 2) {
			tch = *us++;
			if (++length > n) return (-1);
			wide = ch;
			wide = (wide << 8 | tch);
		}
		else {
			wide = ch;
		}
		mask = G3MASK;
		break;
	default: 
		/* shoult be internal error */
		return (-1);
		break;
	}
gen_wide:
	wide &= 0x7F7F;			/* strip off the top bit */
	wide = wide | mask;
	if (pwc != NULL)
		*pwc = wide;
	return (length);
}


#define MAXMBSIZE	128
/*
 *  mbstowcs()
 */ 
size_t
_mbstowcs_iso(wchar_t *pwcs, unsigned char *s, size_t n)
{
	int ret1;
	int accsum = 0;
	wchar_t pwc;

	/*
	 * If pwcs == 0, do nothing.
	 */
	if (pwcs == 0)
		return (0);
	/*
	 * States things
	 */
	 _savestates(); _initializestates();
	 while (accsum < n) {
		ret1 = _mbtowc_iso (&pwc, (char *)s, MAXMBSIZE);
		if (ret1 < 0)
			return (-1);	/* error */
		if (ret1 == 0 || pwc == 0) {
			if (pwcs == 0)
				*pwcs = 0;
			/*
			 * Restore states
			 */
			_restorestates();
			return (accsum);
		}
		s = s + ret1;		/* increment the pointer */
		*pwcs++ = pwc;
		++accsum;
	}
	/*
	 * Restore states
	 */
	_restorestates();
	return (accsum);
}

/*
 * wctomb - 
 */
int
_wctomb_iso(unsigned char *s, wchar_t pwc)
{
	unsigned char ch;		
	unsigned char tch;	/* temporary use */
	unsigned char *us = (unsigned char *)s;
	int gen_wide_state = USE_STATE; /* used in gen_wide: */
	int length = 0;
	int len = 0;
	wchar_t wide;
	unsigned short mode;
	unsigned char buf[MAXSIZE];
	unsigned char *bp;
	int csize, i;
	int n = MMB_CUR_MAX;

	isowidth_t * isoinfo = (isowidth_t *) _code_set_info.code_info;

	/*
	 * If pwc is 0, do this first.
	 */
	if (pwc  == 0) {
		if (s != 0) {
			*s = 0;
			return (1);
		}
		else {
			return (0);
		}
	}

	mode = pwc & G3MASK;	/* The mode of this character */
	if (((pwc >> 8) & 0x007f) == 0)
		csize = 1;
	else
		csize = 2;
	bp = buf;
	length = 0;
#ifdef DDDebug
	if (_my_env == BIT7ENV)
		printf ("7b ");
	else
		printf ("8b ");
	printf ("csize = %d, prevcsize = %d, (%x,%x) ",csize, prevcsize, (pwc>>8)&0x00ff, pwc&0x00ff);
	switch (mode) {
	case G0MASK:
		printf ("G0"); break;
	case G1MASK:
		printf ("G1"); break;
	case G2MASK:
		printf ("G2"); break;
	case G3MASK:
		printf ("G3"); break;
	default:
		printf ("XXXX"); break;
	}
#endif

	switch (_my_env) {
	case BIT7ENV:	/* 7 bit environment */
		switch (mode) {
		case G0MASK:
			if (_currentOUT != G0 || prevcsize != csize) {
				 _currentOUT = G0;
				if (csize == 2) {
					/*
					 * Emit escape sequences
					 */
					 *bp++ = ESC;
					 *bp++ = 0x24;
					 *bp++ = 0x28;
					 *bp++ = FINAL;
					 length += 4;
				}
				else {
					/*
					 * Emit escape sequences
					 */
					 *bp++ = ESC;
					 *bp++ = 0x28;
					 *bp++ = FINAL;
					 length += 3;
				}
				*bp++ = SI;
				++length;
			}
			if (csize == 1) {
				*bp++ = pwc & 0x007f;
				++length;
			}
			else {
				*bp++ = (pwc & 0x7f00) >> 8;
				++length;
				*bp++ = pwc & 0x007f;
				++length;
			}
			break;
		case G1MASK:
			if (_currentOUT != G1 || prevcsize != csize) {
				 _currentOUT = G1;
				if (csize == 2) {
					/*
					 * Emit escape sequences
					 */
					 *bp++ = ESC;
					 *bp++ = 0x24;
					 *bp++ = 0x29;
					 *bp++ = FINAL;
					 length += 4;
				}
				else {
					/*
					 * Emit escape sequences
					 */
					 *bp++ = ESC;
					 *bp++ = 0x29;
					 *bp++ = FINAL;
					 length += 3;
				}
				*bp++ = SO;
				++length;
			}
			if (csize == 1) {
				*bp++ = pwc & 0x007f;
				++length;
			}
			else {
				*bp++ = (pwc & 0x7f00) >> 8;
				++length;
				*bp++ = pwc & 0x007f;
				++length;
			}
			break;
		case G2MASK:
			if (_currentOUT != G2 || prevcsize != csize) {
				 _currentOUT = G2;
				if (csize == 2) {
					/*
					 * Emit escape sequences
					 */
					 *bp++ = ESC;
					 *bp++ = 0x24;
					 *bp++ = 0x2A;
					 *bp++ = FINAL;
					 length += 4;
				}
				else {
					/*
					 * Emit escape sequences
					 */
					 *bp++ = ESC;
					 *bp++ = 0x2A;
					 *bp++ = FINAL;
					 length += 3;
				}
				*bp++ = ESC; *bp++ = LS2;
				length += 2;
			}
			if (csize == 1) {
				*bp++ = pwc & 0x007f;
				++length;
			}
			else {
				*bp++ = (pwc & 0x7f00) >> 8;
				++length;
				*bp++ = pwc & 0x007f;
				++length;
			}
			break;
		case G3MASK:
			if (_currentOUT != G3 || prevcsize != csize) {
				 _currentOUT = G3;
				if (csize == 2) {
					/*
					 * Emit escape sequences
					 */
					 *bp++ = ESC;
					 *bp++ = 0x24;
					 *bp++ = 0x2B;
					 *bp++ = FINAL;
					 length += 4;
				}
				else {
					/*
					 * Emit escape sequences
					 */
					 *bp++ = ESC;
					 *bp++ = 0x2B;
					 *bp++ = FINAL;
					 length += 3;
				}
				*bp++ = ESC; *bp++ = LS3;
				length += 2;
			}
			if (csize == 1) {
				*bp++ = pwc & 0x007f;
				++length;
			}
			else {
				*bp++ = (pwc & 0x7f00) >> 8;
				++length;
				*bp++ = pwc & 0x007f;
				++length;
			}
			break;
		}
		break;
	case BIT8ENV:	/* 8 bit environment */
		switch (mode) {
		case G0MASK:
			if (_currentOUT != G0 || prevcsize != csize) {
				_currentOUT = G0;
				if (csize == 2) {
					/*
					 * Emit escape sequences
					 */
					 *bp++ = ESC;
					 *bp++ = 0x24;
					 *bp++ = 0x28;
					 *bp++ = FINAL;
					 length += 4;
				}
				else {
					/*
					 * Emit escape sequences
					 */
					 *bp++ = ESC;
					 *bp++ = 0x28;
					 *bp++ = FINAL;
					 length += 3;
				}
				*bp++ = LS0;
				++length;
			}
			if (csize == 1) {
				*bp++ = pwc & 0x007f;
				++length;
			}
			else {
				*bp++ = (pwc & 0x7f00) >> 8;
				++length;
				*bp++ = pwc & 0x007f;
				++length;
			}
			break;
		case G1MASK:
			if (_currentOUT != G1 || prevcsize != csize) {
				_currentOUT = G1;
				if (csize == 2) {
					/*
					 * Emit escape sequences
					 */
					 *bp++ = ESC;
					 *bp++ = 0x24;
					 *bp++ = 0x29;
					 *bp++ = FINAL;
					 length += 4;
				}
				else {
					/*
					 * Emit escape sequences
					 */
					 *bp++ = ESC;
					 *bp++ = 0x29;
					 *bp++ = FINAL;
					 length += 3;
				}
				*bp++ = ESC; *bp++ = LS1R;
				length += 2;
			}

			/*
			 * If state is G1 or G2, or G3, assume that
			 * this is 8bit characters. To do this more
			 * accurately, wide character needs to be
			 * larger than 16 bits to keep more information.
			 */
			pwc |= 0x8080;
			if (csize == 1) {
				*bp++ = pwc & 0x00ff;
				++length;
			}
			else {
				*bp++ = (pwc & 0xff00) >> 8;
				++length;
				*bp++ = pwc & 0x00ff;
				++length;
			}
			break;
		case G2MASK:
			if (_currentOUT != G2 || prevcsize != csize) {
				_currentOUT = G2;
				if (csize == 2) {
					/*
					 * Emit escape sequences
					 */
					 *bp++ = ESC;
					 *bp++ = 0x24;
					 *bp++ = 0x2A;
					 *bp++ = FINAL;
					 length += 4;
				}
				else {
					/*
					 * Emit escape sequences
					 */
					 *bp++ = ESC;
					 *bp++ = 0x2A;
					 *bp++ = FINAL;
					 length += 3;
				}
				*bp++ = ESC; *bp++ = LS2R;
				length += 2;
			}
			/*
			 * If state is G1 or G2, or G3, assume that
			 * this is 8bit characters. To do this more
			 * accurately, wide character needs to be
			 * larger than 16 bits to keep more information.
			 */
			pwc |= 0x8080;
			if (csize == 1) {
				*bp++ = pwc & 0x00ff;
				++length;
			}
			else {
				*bp++ = (pwc & 0xff00) >> 8;
				++length;
				*bp++ = pwc & 0x00ff;
				++length;
			}
			break;
		case G3MASK:
			if (_currentOUT != G3 || prevcsize != csize) {
				_currentOUT = G3;
				if (csize == 2) {
					/*
					 * Emit escape sequences
					 */
					 *bp++ = ESC;
					 *bp++ = 0x24;
					 *bp++ = 0x2B;
					 *bp++ = FINAL;
					 length += 4;
				}
				else {
					/*
					 * Emit escape sequences
					 */
					 *bp++ = ESC;
					 *bp++ = 0x2B;
					 *bp++ = FINAL;
					 length += 3;
				}
				*bp++ = ESC; *bp++ = LS3R;
				length += 2;
			}
			/*
			 * If state is G1 or G2, or G3, assume that
			 * this is 8bit characters. To do this more
			 * accurately, wide character needs to be
			 * larger than 16 bits to keep more information.
			 */
			pwc |= 0x8080;
			if (csize == 1) {
				*bp++ = pwc & 0x00ff;
				++length;
			}
			else {
				*bp++ = (pwc & 0xff00) >> 8;
				++length;
				*bp++ = pwc & 0x00ff;
				++length;
			}
			break;
		}
		break;
	default:	/* Should never happens */
		return (-1);
		break;
	}

	prevcsize = csize;
	
	if (length > n) {
		return (-1);	/* buffer too small */
	}
	for (i = 0; i < length; i++) {
		*s++ = buf[i];
	}
#ifdef DDDebug
	printf ("\t(");
	for (i = 0; i < length; i++) {
		printf ("%x,", buf[i]);
	}
	printf (")\n");
#endif
	return (length);
}

/*
 * wcstombs
 */
size_t
_wcstombs_iso(char *s, wchar_t *pwcs, int n)
{
	int acclen = 0;
	char buf[MMB_CUR_MAX];
	int ret1;
	int i;

	if (n < 0)
		return (-1);
	/*
	 * Initialize State
	 */
	 _savestates(); _initializestates();
	 while (acclen < n) {
		ret1 = _wctomb_iso ((unsigned char *)buf, *pwcs);
		/*
		 * end of string ?
		 */
		if (ret1 == 1 && buf[0] == 0) {
			*s = 0;
			/*
			 * restore states
			 */
			_restorestates();
			return (acclen);
		}
		/*
		 * Error ?
		 */
		if (ret1 < 0)
			return (-1);
		acclen += ret1;
		for (i = 0; i < ret1; i++)
			*s++ = buf[i];
		++pwcs;
	 }

	/*
	 * restore states
	 */
	_restorestates();

	 /*
	  * return the length
	  */
	 return (acclen);
}


/*
 * Supplementary routines
 */

void
_initializestates(void)
{
	_currentG0 = G0;
	_currentG1 = G1;

	_des_states[G0].width = -1;	/* This makes it Initialize */

	_currentOUT = G0;
	prevcsize = 1;
}

static char SAVED_currentG0;
static char SAVED_currentG1;
static struct state SAVED_des_states[NUM_OF_STATES];
static struct state SAVED_Invoked_G0, SAVED_Invoked_G1;
static char SAVED_currentOUT = G0; /* G0, G1, G2 or G3 */
static int	SAVED_prevcsize = 1;

void
_savestates(void)
{

	SAVED_currentG0 = _currentG0;
	SAVED_currentG1 = _currentG1;

	SAVED_des_states[G0] = _des_states[G0];
	SAVED_des_states[G1] = _des_states[G1];
	SAVED_des_states[G2] = _des_states[G2];
	SAVED_des_states[G3] = _des_states[G3];

	SAVED_Invoked_G0 = Invoked_G0;
	SAVED_Invoked_G1 = Invoked_G1;

	SAVED_currentOUT = _currentOUT;
	SAVED_prevcsize = prevcsize;
}

void
_restorestates(void)
{
	_currentG0 = SAVED_currentG0;
	_currentG1 = SAVED_currentG1;

	_des_states[G0] = SAVED_des_states[G0];
	_des_states[G1] = SAVED_des_states[G1];
	_des_states[G2] = SAVED_des_states[G2];
	_des_states[G3] = SAVED_des_states[G3];

	Invoked_G0 = SAVED_Invoked_G0;
	Invoked_G1 = SAVED_Invoked_G1;

	_currentOUT = SAVED_currentOUT;
	prevcsize = SAVED_prevcsize;
}
