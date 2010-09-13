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

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "curses_inc.h"

/* Delete keys matching pat or key from the key map. */

int
delkey(char *sends, int keyval)
{
	_KEY_MAP	*kp, **kpp = cur_term->_keys, **fpp, **dpp;
	int		mask = 0, cmp, numkeys = cur_term->_ksz;
	int		counter = 0, i, num_deleted_keys = 0;
	short		*lkorder = &(cur_term->_lastkey_ordered),
			*first_macro = &(cur_term->_first_macro),
			*lmorder = &(cur_term->_lastmacro_ordered);

	/* for ease of determination of key to delete */
	if (sends)
		mask |= 01;
	if (keyval >= 0)
		mask |= 02;

	/* check each key */
	while (++counter < numkeys) {
		kp = *kpp;
		cmp = 0;
		if (sends && (strcmp(sends, kp->_sends) == 0))
			cmp |= 01;
		if (kp->_keyval == keyval)
			cmp |= 02;

		/* found one to delete */
		if (cmp == mask) {
			num_deleted_keys++;
			/*
			 * If it was an externally created key, then the address
			 * of the sequence will be right after the structure.
			 * See the malloc in newkey.
			 */
			if (kp->_sends == ((char *)kp + sizeof (_KEY_MAP)))
				free(kp);

			/* shift left other keys */
			i = (numkeys - counter) - 1;
			for (fpp = kpp, dpp = kpp + 1; i > 0; i--, fpp++, dpp++)
				*fpp = *dpp;
			if (counter <= *lmorder) {
				if (counter < *first_macro) {
					if (counter <= *lkorder)
						(*lkorder)--;
					(*first_macro)--;
				}
				(*lmorder)--;
			}
		} else
			kpp++;
	}

/* Check if we've crossed boundary and/or hit 0 */

	if ((cur_term->_ksz -= num_deleted_keys) == 0)
		(void) delkeymap(cur_term);
	else
		cur_term->_keys = (_KEY_MAP **) realloc((char *)
		    cur_term->_keys, (unsigned)cur_term->_ksz);

	return (num_deleted_keys);
}
