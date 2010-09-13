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
 *	db_item.cc
 *
 *	Copyright (c) 1988-2000 by Sun Microsystems, Inc.
 *	All Rights Reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "db_headers.h"
#include "db_item.h"
#include "nisdb_mt.h"

#define	HASHSHIFT	3
#define	HASHMASK	0x1f

#ifdef TDRPC
#define	LOWER(c)	(isupper((c)) ? tolower((c)) : (c))
extern "C" {
	int strncasecmp(const char *s1, const char *s2, int n);
};
#else
#define	LOWER(c)	(isupper((c)) ? _tolower((c)) : (c))
#endif


/* Constructor: creates item using given character sequence and length */
item::item(char *str, int n)
{
	len = n;
	if ((value = new char[len]) == NULL)
		FATAL("item::item: cannot allocate space", DB_MEMORY_LIMIT);

	(void) memcpy(value, str, len);
}


/* Constructor: creates item by copying given item */
item::item(item *model)
{
	len = model->len;
	if ((value = new char[len]) == NULL)
		FATAL(" item::item: cannot allocate space (2)",
			DB_MEMORY_LIMIT);

	(void) memcpy(value, model->value, len);
}

/* Prints contents of item to stdout */
void
item::print()
{
	int i;
	for (i = 0; i < len; i++)
		putchar(value[i]);
}

/* Equality test.  'casein' TRUE means case insensitive test. */
bool_t
item::equal(item* other, bool_t casein)
{
	if (casein)	// case-insensitive
		return ((len == other->len) &&
			(!strncasecmp(value, other->value, len)));
	else		// case sensitive
		return ((len == other->len) &&
			(!memcmp(value, other->value, len)));
}

bool_t
item::equal(char* other, int olen, bool_t casein)
{
	if (casein)	// case-insensitive
		return ((len == olen) && (!strncasecmp(value, other, len)));
	else		// case sensitive
		return ((len == olen) && (!memcmp(value, other, len)));
}

/* Return hash value.  'casein' TRUE means case insensitive test. */
u_int
item::get_hashval(bool_t casein)
{
	int i;
	u_int hval = 0;

	// we want to separate the cases so that we don't needlessly do
	// an extra test for the case-sensitive branch in the for loop
	if (casein) {	// case insensitive
		for (i = 0; i < len; i++) {
			hval = ((hval<<HASHSHIFT)^hval);
			hval += (LOWER(value[i]) & HASHMASK);
		}
	}  else {	// case sensitive
		for (i = 0; i < len; i++) {
			hval = ((hval<<HASHSHIFT)^hval);
			hval += (value[i] & HASHMASK);
		}
	}

	return (hval);
}
