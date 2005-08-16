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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

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

/*
*************************************************************************
*			COPYRIGHT NOTICE				*
*************************************************************************
*	This software is copyright(C) 1982 by Pavel Curtis		*
*									*
*	Permission is granted to reproduce and distribute		*
*	this file by any means so long as no fee is charged		*
*	above a nominal handling fee and so long as this		*
*	notice is always included in the copies.			*
*									*
*	Other rights are reserved except as explicitly granted		*
*	by written permission of the author.				*
*		Pavel Curtis						*
*		Computer Science Dept.					*
*		405 Upson Hall						*
*		Cornell University					*
*		Ithaca, NY 14853					*
*									*
*		Ph- (607) 256-4934					*
*									*
*		Pavel.Cornell@Udel-Relay(ARPAnet)			*
*		decvax!cornell!pavel(UUCPnet)				*
*********************************************************************** */

/*
 *	comp_hash.c --- Routines to deal with the hashtable of capability
 *			names.
 *
 *  $Log:	RCS/comp_hash.v $
 * Revision 2.1  82/10/25  14:45:34  pavel
 * Added Copyright Notice
 *
 * Revision 2.0  82/10/24  15:16:34  pavel
 * Beta-one Test Release
 *
 * Revision 1.3  82/08/23  22:29:33  pavel
 * The REAL Alpha-one Release Version
 *
 * Revision 1.2  82/08/19  19:09:46  pavel
 * Alpha Test Release One
 *
 * Revision 1.1  82/08/12  18:36:23  pavel
 * Initial revision
 *
 *
 */

#include <strings.h>
#include "curses_inc.h"
#include "compiler.h"

static void make_nte(void);
static int hash_function(char *);

/*
 *	make_hash_table()
 *
 *	Takes the entries in cap_table[] and hashes them into cap_hash_table[]
 *	by name.  There are Captabsize entries in cap_table[] and Hashtabsize
 *	slots in cap_hash_table[].
 *
 */

void
make_hash_table()
{
	int	i;
	int	hashvalue;
	int	collisions = 0;

	make_nte();
	for (i = 0; i < Captabsize; i++) {
		hashvalue = hash_function(cap_table[i].nte_name);
		DEBUG(9, "%d\n", hashvalue);

		if (cap_hash_table[hashvalue] != (struct name_table_entry *) 0)
			collisions++;

		cap_table[i].nte_link = cap_hash_table[hashvalue];
		cap_hash_table[hashvalue] = &cap_table[i];
	}

	DEBUG(3, "Hash table complete\n%d collisions ", collisions);
	DEBUG(3, "out of %d entries\n", Captabsize);
	return;
}

/*
 * Make the name_table_entry from the capnames.c set of tables.
 */
static void
make_nte(void)
{
	int i, n;
	extern char *boolnames[], *numnames[], *strnames[];

	n = 0;

	for (i = 0; boolnames[i]; i++) {
		cap_table[n].nte_link = NULL;
		cap_table[n].nte_name = boolnames[i];
		cap_table[n].nte_type = BOOLEAN;
		cap_table[n].nte_index = i;
		n++;
	}
	BoolCount = i;

	for (i = 0; numnames[i]; i++) {
		cap_table[n].nte_link = NULL;
		cap_table[n].nte_name = numnames[i];
		cap_table[n].nte_type = NUMBER;
		cap_table[n].nte_index = i;
		n++;
	}
	NumCount = i;

	for (i 	= 0; strnames[i]; i++) {
		cap_table[n].nte_link = NULL;
		cap_table[n].nte_name = strnames[i];
		cap_table[n].nte_type = STRING;
		cap_table[n].nte_index = i;
		n++;
	}
	StrCount = i;

	Captabsize = n;
}


/*
 *	int hash_function(string)
 *
 *	Computes the hashing function on the given string.
 *
 *	The current hash function is the sum of each consectutive pair
 *	of characters, taken as two-byte integers, mod Hashtabsize.
 *
 */

static int
hash_function(char *string)
{
	long	sum = 0;

	while (*string) {
		sum += *string + (*(string + 1) << 8);
		string++;
	}

	return (sum % Hashtabsize);
}



/*
 *	struct name_table_entry *
 *	find_entry(string)
 *
 *	Finds the entry for the given string in the hash table if present.
 *	Returns a pointer to the entry in the table or 0 if not found.
 *
 */

struct name_table_entry *
find_entry(char *string)
{
	int	hashvalue;
	struct name_table_entry	*ptr;

	hashvalue = hash_function(string);

	ptr = cap_hash_table[hashvalue];

	while (ptr != (struct name_table_entry *) 0 &&
	    strcmp(ptr->nte_name, string) != 0)
		ptr = ptr->nte_link;

	return (ptr);
}
