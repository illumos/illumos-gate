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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

#include	<sys/types.h>
#include	<stdlib.h>
#include	<string.h>
#include	"curses_inc.h"

static	short	keycodes[] = {
		    KEY_BACKSPACE,
		    KEY_CATAB,
		    KEY_CLEAR,
		    KEY_CTAB,
		    KEY_DC,
		    KEY_DL,
		    KEY_DOWN,
		    KEY_EIC,
		    KEY_EOL,
		    KEY_EOS,
		    KEY_F(0),
		    KEY_F(1),
		    KEY_F(10),
		    KEY_F(2),
		    KEY_F(3),
		    KEY_F(4),
		    KEY_F(5),
		    KEY_F(6),
		    KEY_F(7),
		    KEY_F(8),
		    KEY_F(9),
		    KEY_HOME,
		    KEY_IC,
		    KEY_IL,
		    KEY_LEFT,
		    KEY_LL,
		    KEY_NPAGE,
		    KEY_PPAGE,
		    KEY_RIGHT,
		    KEY_SF,
		    KEY_SR,
		    KEY_STAB,
		    KEY_UP,
		    KEY_A1,
		    KEY_A3,
		    KEY_B2,
		    KEY_C1,
		    KEY_C3,
		    KEY_BTAB,
		    KEY_BEG,
		    KEY_CANCEL,
		    KEY_CLOSE,
		    KEY_COMMAND,
		    KEY_COPY,
		    KEY_CREATE,
		    KEY_END,
		    KEY_ENTER,
		    KEY_EXIT,
		    KEY_FIND,
		    KEY_HELP,
		    KEY_MARK,
		    KEY_MESSAGE,
		    KEY_MOVE,
		    KEY_NEXT,
		    KEY_OPEN,
		    KEY_OPTIONS,
		    KEY_PREVIOUS,
		    KEY_PRINT,
		    KEY_REDO,
		    KEY_REFERENCE,
		    KEY_REFRESH,
		    KEY_REPLACE,
		    KEY_RESTART,
		    KEY_RESUME,
		    KEY_SAVE,
		    KEY_SUSPEND,
		    KEY_UNDO,
		    KEY_SBEG,
		    KEY_SCANCEL,
		    KEY_SCOMMAND,
		    KEY_SCOPY,
		    KEY_SCREATE,
		    KEY_SDC,
		    KEY_SDL,
		    KEY_SELECT,
		    KEY_SEND,
		    KEY_SEOL,
		    KEY_SEXIT,
		    KEY_SFIND,
		    KEY_SHELP,
		    KEY_SHOME,
		    KEY_SIC,
		    KEY_SLEFT,
		    KEY_SMESSAGE,
		    KEY_SMOVE,
		    KEY_SNEXT,
		    KEY_SOPTIONS,
		    KEY_SPREVIOUS,
		    KEY_SPRINT,
		    KEY_SREDO,
		    KEY_SREPLACE,
		    KEY_SRIGHT,
		    KEY_SRSUME,
		    KEY_SSAVE,
		    KEY_SSUSPEND,
		    KEY_SUNDO,
		    KEY_MOUSE
		};

static	_KEY_MAP	*p;
static	bool		*funckey;
static	short		*codeptr;

static	void
_laddone(char *txt)
{
	p->_sends = (txt);
	p->_keyval = *codeptr;
	funckey[(unsigned char)(txt)[0]] |= _KEY;
	p++;
}

/* Map text into num, updating the map structure p. */

static	void
_keyfunc(char **keyptr, char **lastkey)
{
	for (; keyptr <= lastkey; keyptr++, codeptr++)
		if (*keyptr) {
			p->_sends = (*keyptr);
			p->_keyval = *codeptr;
			funckey[(unsigned char)(*keyptr)[0]] |= _KEY;
			p++;
		}
}

/* Map text into num, updating the map structure p. */

static	void
_keyfunc2(char **keyptr, char **lastkey)
{
	short code_value = KEY_F(11);

	for (; *keyptr && keyptr <= lastkey; keyptr++, code_value++) {
		p->_sends = *keyptr;
		p->_keyval = (short) code_value;
		funckey[(unsigned char)*keyptr[0]] |= _KEY;
		p++;
	}
}

int
setkeymap(void)
{
	_KEY_MAP	keymap[((sizeof (keycodes) / sizeof (short)) +
			    ((KEY_F(63) - KEY_F(11)) + 1))], **key_ptrs;
	short		numkeys;
	int		numbytes, key_size = cur_term->_ksz;

	if (cur_term->internal_keys != NULL)
		return (ERR);
	p = keymap;
	codeptr = keycodes;
	funckey = cur_term->funckeystarter;

	/* If backspace key sends \b, don't map it. */
	if (key_backspace && strcmp(key_backspace, "\b"))
		_laddone(key_backspace);
	codeptr++;

	_keyfunc(&key_catab, &key_dl);

	/* If down arrow key sends \n, don't map it. */
	if (key_down && strcmp(key_down, "\n"))
		_laddone(key_down);
	codeptr++;

	_keyfunc(&key_eic, &key_il);

	/* If left arrow key sends \b, don't map it. */
	if (key_left && strcmp(key_left, "\b"))
		_laddone(key_left);
	codeptr++;

	_keyfunc(&key_ll, &key_up);
	_keyfunc(&key_a1, &key_c3);
	_keyfunc(&key_btab, &key_btab);
	_keyfunc(&key_beg, &key_sundo);
	_keyfunc2(&key_f11, &key_f63);
	_keyfunc(&key_mouse, &key_mouse);

	/*
	 * malloc returns the address of a list of pointers to
	 * (_KEY_MAP *) structures
	 */

	if ((key_ptrs = (_KEY_MAP **)
	    /* LINTED */
	    malloc((key_size + (numkeys = (short)(p - keymap))) *
	    sizeof (_KEY_MAP *))) == NULL) {
		goto out;
	}

	/*
	 * Number of bytes needed is the number of structures times their size
	 * malloc room for our array of _KEY_MAP structures
	 */

	if ((p = (_KEY_MAP *) malloc((unsigned)
	    /* LINTED */
	    (numbytes = (int)(sizeof (_KEY_MAP) * numkeys)))) == NULL) {
		/* Can't do it, free list of pointers, indicate */
		/* error upon return. */
		free((char *) key_ptrs);
out:
		term_errno = TERM_BAD_MALLOC;
#ifdef	DEBUG
		strcpy(term_parm_err, "setkeymap");
		termerr();
#endif	/* DEBUG */
		return (ERR);
	}

	if (key_size != 0) {
		(void) memcpy((char *) &(key_ptrs[numkeys]),
		    (char *) cur_term->_keys, (key_size *
		    sizeof (_KEY_MAP *)));
		free(cur_term->_keys);
	}
	(void) memcpy((char *) (cur_term->internal_keys = p),
	    (char *) keymap, numbytes);
	cur_term->_keys = key_ptrs;
	cur_term->_ksz += numkeys;
	/*
	 * Reset _lastkey_ordered to -1 since we put the keys read in
	 * from terminfo at the beginning of the keys table.
	 */
	cur_term->_lastkey_ordered = -1;
	cur_term->_lastmacro_ordered += numkeys;
	cur_term->_first_macro += numkeys;

	/* Initialize our pointers to the structures */
	while (numkeys--)
		*key_ptrs++ = p++;
#ifdef	DEBUG
	if (outf)
		fprintf(outf, "return key structure %x, ending at %x\n",
		    keymap, p);
#endif	/* DEBUG */
	return (OK);
}
