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
// ------------------------------------------------------------
//
//		flist.cxx
//
// Defines the flist class.

#pragma ident	"%Z%%M%	%I%	%E% SMI"
// Copyright (c) 1994 by Sun Microsystems, Inc.

#include <stdio.h>
#include <stdlib.h>
#include "flist.h"

// ------------------------------------------------------------
//
//		flist
//
// Description:
//	Constructor for the flist class.
// Arguments:
// Returns:
// Preconditions:

flist::flist()
{
	f_count = 0;
	f_index = 0;
}

// ------------------------------------------------------------
//
//		fl_push
//
// Description:
//	Adds the specified pointer to the top of the list
//	if there is room.  If there is no more room then
//	nothing happens.
// Arguments:
// Returns:
// Preconditions:

void flist::fl_push(void *ptr)
{
	if (f_count < FLIST_SIZE) {
		f_items[f_count] = (char *)ptr;
		f_count++;
	}
}

// ------------------------------------------------------------
//
//		fl_pop
//
// Description:
//	Removes the top item from the list.
//	No action is taken if the list is empty.
// Arguments:
// Returns:
// Preconditions:

void
flist::fl_pop()
{
	if (f_count > 0)
		f_count--;
}

// ------------------------------------------------------------
//
//		fl_top
//
// Description:
//	Returns the top item on the list.
//	Sets the internal state so that a following call to
//	next() will return the second item on the list.
//	Returns NULL if the list is empty.
// Arguments:
// Returns:
// Preconditions:

void *
flist::fl_top()
{
	f_index = f_count;
	return (fl_next());
}

// ------------------------------------------------------------
//
//		fl_next
//
// Description:
//	Returns the next item on the list.  NULL if there
//	is no next item.
// Arguments:
// Returns:
// Preconditions:

void *
flist::fl_next()
{
	if (f_index > 0) {
		f_index--;
		return (f_items[ f_index ]);
	} else {
		return (NULL);
	}
}

// ------------------------------------------------------------
//
//		fl_clear
//
// Description:
//	Removes all items from the list and frees them.
// Arguments:
// Returns:
// Preconditions:

void
flist::fl_clear()
{
	void *p1;
	while ((p1 = fl_top()) != NULL) {
		free(p1);
		fl_pop();
	}
}
