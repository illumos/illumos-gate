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
 * Copyright 2003 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms.
 */


/*
 *      i18n.cc
 *
 *      Deal with internationalization conversions
 */

/*
 * Included files
 */
#include <mksh/i18n.h>
#include <mksh/misc.h>		/* setup_char_semantics() */

/*
 *	get_char_semantics_value(ch)
 *
 *	Return value:
 *		The character semantics of ch.
 *
 *	Parameters:
 *		ch		character we want semantics for.
 *
 */
char
get_char_semantics_value(wchar_t ch)
{
	static Boolean	char_semantics_setup;

	if (!char_semantics_setup) {
		setup_char_semantics();
		char_semantics_setup = true;
	}
	return char_semantics[get_char_semantics_entry(ch)];
}

/*
 *	get_char_semantics_entry(ch)
 *
 *	Return value:
 *		The slot number in the array for special make chars,
 *		else the slot number of the last array entry.
 *
 *	Parameters:
 *		ch		The wide character
 *
 *	Global variables used:
 *		char_semantics_char[]	array of special wchar_t chars
 *					"&*@`\\|[]:$=!>-\n#()%?;^<'\""
 */
int
get_char_semantics_entry(wchar_t ch)
{
	wchar_t		*char_sem_char;

	char_sem_char = (wchar_t *) wcschr(char_semantics_char, ch);
	if (char_sem_char == NULL) {
		/*
		 * Return the integer entry for the last slot,
		 * whose content is empty.
		 */
		return (CHAR_SEMANTICS_ENTRIES - 1);
	} else {
		return (char_sem_char - char_semantics_char);
	}
}

