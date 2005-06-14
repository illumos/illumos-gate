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
#include	<sys/types.h>
#include	"curses_inc.h"

/*
 * When the keyboard can send more than eight bits, offsets array
 * should be changed from chars to shorts.
 * The offsets MUST match what is in curses.h.
 */

static	unsigned	char	offsets[][2] = {
				    { '`', '*' },	/* ACS_DIAMOND */
				    { 'a', ':' },	/* ACS_CKBOARD */
				    { 'f', '\'' },	/* ACS_DEGREE */
				    { 'g', '#' },	/* ACS_PLMINUS */
				    { 'o', '-' },	/* ACS_S1 */
				    { 'q', '-' },	/* ACS_HLINE */
				    { 's', '_' },	/* ACS_S9 */
				    { 'x', '|' },	/* ACS_VLINE */
				    { '~', 'o' },	/* ACS_BULLET */
				    { ',', '<' },	/* ACS_LARROW */
				    { '+', '>' },	/* ACS_RARROW */
				    { '.', 'v' },	/* ACS_DARROW */
				    { '-', '^' },	/* ACS_UARROW */
				    { 'h', '#' },	/* ACS_BOARD */
				    { 'i', '#' },	/* ACS_LANTERN */
				    { '0', '#' },	/* ACS_BLOCK */
				};

int
init_acs(void)
{
	chtype	*nacsmap;
	char	*cp;
	int	i = sizeof (offsets) / 2, to_get, must_output;

#ifdef	_VR3_COMPAT_CODE
	if ((nacsmap = cur_term->_acs32map = (chtype *)
	    malloc(sizeof (chtype) * 0400)) == NULL)
#else	/* _VR3_COMPAT_CODE */
	if ((nacsmap = cur_term->_acsmap = (chtype *)
	    malloc(sizeof (chtype) * 0400)) == NULL)
#endif	/* _VR3_COMPAT_CODE */
	{
#ifdef	_VR3_COMPAT_CODE
bad:
#endif	/* _VR3_COMPAT_CODE */
		term_errno = TERM_BAD_MALLOC;
#ifdef	DEBUG
		strcpy(term_parm_err, "init_acs");
#endif	/* DEBUG */
		return (ERR);
	}

	/* Default acs chars for regular ASCII terminals are plus signs. */

	memSset(nacsmap, (chtype) '+', 0400);

	/*
	* Now load in defaults for some of the characters which have close
	* approximations in the normal ascii set.
	*/

	while (i-- > 0)
		nacsmap[offsets[i][0]] = offsets[i][1];

	/* Now do mapping for terminals own ACS, if any */

	if ((cp = acs_chars) != 0)
		while (*cp) {
			to_get = *cp++;		/* to get this ... */
			must_output = *cp++;	/* must output this ... */
#ifdef	DEBUG
			if (outf)
				fprintf(outf, "acs %d, was %d, now %d\n",
				    to_get, nacsmap[to_get], must_output);
#endif	/* DEBUG */
			nacsmap[to_get] = ( must_output & 0xFF ) | A_ALTCHARSET;
		}

	acs_map = nacsmap;

#ifdef	_VR3_COMPAT_CODE
	if (_y16update) {
		_ochtype	*n16acsmap;

		if ((n16acsmap = cur_term->_acsmap = (_ochtype *)
		    malloc(sizeof (_ochtype) * 0400)) == NULL) {
			goto bad;
		}

		for (i = 0; i < 0400; i++)
			/*LINTED*/
			n16acsmap[i] = _TO_OCHTYPE(nacsmap[i]);
#undef	acs_map
			acs_map = n16acsmap;
	}
#endif	/* _VR3_COMPAT_CODE */
	return (OK);
}
