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
//			flist.h
//
//   Defines a simple fixed size stack oriented list class
//

#pragma ident	"%Z%%M%	%I%	%E% SMI"
// Copyright (c) 1994 by Sun Microsystems, Inc.

// .LIBRARY Base
// .FILE flist.cxx
// .FILE flist.h
// .NAME flist - simple list manager class

// .DESCRIPTION
// The flist class is a simple list manager class designed specifically
// for use by the mdbug package.
// There is no destuctor for the class, so when an flist object is
// deleted any objects still on the list are forgotten.

#ifndef FLIST_H
#define	FLIST_H

const int FLIST_SIZE = 10;	// The number of items that will fit on list.

class flist
{
private:
	char	*f_items[FLIST_SIZE];	// Pointers to the items.
	int	 f_index;		// Index of item returned by next().
	int	 f_count;		// Number of items on list.

public:
	flist();			// Constructor
	void	 fl_push(void *);	// Place on top of list.
	void	 fl_pop();		// Remove top of list.
	void	*fl_top();		// Return top item on list.
	void	*fl_next();		// Return next item on list.
	void	 fl_clear();		// Removes and frees all items on list.
	int	 fl_count();		// Return number of items on list.
	int	 fl_space();		// Return amount of free space on list.
};

// ------------------------------------------------------------
//
//		fl_count
//
// Description:
// Arguments:
// Returns:
//	Returns the number of items on the list.
// Errors:
// Preconditions:

inline int
flist::fl_count()
{
	return (f_count);
}

// ------------------------------------------------------------
//
//		fl_space
//
// Description:
// Arguments:
// Returns:
//	Returns the number of free slots on the list.
// Errors:
// Preconditions:

inline int
flist::fl_space()
{
	return (FLIST_SIZE - f_count);
}

#endif /* FLIST_H */
