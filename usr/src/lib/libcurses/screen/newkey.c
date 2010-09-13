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

#include	<stdlib.h>
#include	<string.h>
#include	<sys/types.h>
#include	"curses_inc.h"

/*
 * Set a new key or a new macro.
 *
 * rcvchars: the pattern identifying the key
 * keyval: the value to return when the key is recognized
 * macro: if this is not a function key but a macro,
 * 	tgetch() will block on macros.
 */

int
newkey(char *rcvchars, short keyval, bool macro)
{
	_KEY_MAP	**keys, *key_info,
					**prev_keys = cur_term->_keys;
	short		*numkeys = &cur_term->_ksz;
	char		*str;
	size_t		len;

	if ((!rcvchars) || (*rcvchars == '\0') || (keyval < 0) ||
	    (((keys = (_KEY_MAP **) malloc(sizeof (_KEY_MAP *) *
	    (*numkeys + 1))) == NULL))) {
		goto bad;
	}

	len = strlen(rcvchars) + 1;

	if ((key_info = (_KEY_MAP *) malloc(sizeof (_KEY_MAP) + len)) ==
	    NULL) {
		free(keys);
bad :
		term_errno = TERM_BAD_MALLOC;
#ifdef	DEBUG
		strcpy(term_parm_err, "newkey");
#endif	/* DEBUG */
		return (ERR);
	}

	if (macro) {
		(void) memcpy((char *) keys, (char *) prev_keys,
		    (*numkeys * sizeof (_KEY_MAP *)));
		keys[*numkeys] = key_info;
	} else {
		short	*first = &(cur_term->_first_macro);

		(void) memcpy((char *) keys, (char *) prev_keys,
		    (*first * sizeof (_KEY_MAP *)));
		(void) memcpy((char *) &(keys[*first + 1]),
		    (char *) &(prev_keys[*first]),
		    ((*numkeys - *first) * sizeof (_KEY_MAP *)));
		keys[(*first)++] = key_info;
		cur_term->_lastmacro_ordered++;
	}
	if (prev_keys != NULL)
		free(prev_keys);
	cur_term->_keys = keys;

	(*numkeys)++;
	key_info->_sends = str = (char *) key_info + sizeof (_KEY_MAP);
	(void) memcpy(str, rcvchars, len);
	key_info->_keyval = keyval;
	cur_term->funckeystarter[*str] |= (macro ? _MACRO : _KEY);

	return (OK);
}
