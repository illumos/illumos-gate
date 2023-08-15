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
 * Copyright (c) 1994, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ident	"%Z%%M%	%I%	%E% SMI"	/* SMI4.1 1.4 */

#include <ctype.h>
#include "util.h"
#include "table.h"



/*
 * Hash table manager. Store/lookup strings, keyed by string
 */

/*
 * Generate the key into the table using the first two letters
 * of "str".  The table is alphabetized, with no distinction between
 * upper and lower case.  Non-letters are given least significance.
 */
int
tablekey(str)
	register char *str;
{
#define	TOLOWER(c) (islower(c) ? c : \
			(isupper(c) ? tolower(c) : ('a'+NUMLETTERS-1)))

	register int c1, c2;

	c1 = *str++;
	c2 = *str;
	if (c1 == EOS) {
		c2 = EOS;	/* just in case */
	}
	c1 = TOLOWER(c1) - 'a';
	c2 = TOLOWER(c2) - 'a';
	return (c1*NUMLETTERS + c2);
}


void
store(table, key, datum)
	stringtable table;
	char *key;
	char *datum;
{
	int index;
	tablelist cur, new;

	index = tablekey(key);
	cur = table[index];

	new = MALLOC(tablenode);
	new->key = key;
	new->datum = datum;
	new->next = cur;
	table[index] = new;
}


char *
lookup(table, key)
	stringtable table;
	char *key;
{
	tablelist cur;

	cur = table[tablekey(key)];
	while (cur && strcmp(cur->key, key)) {
		cur = cur->next;
	}
	if (cur) {
		return (cur->datum);
	} else {
		return (NULL);
	}
}
