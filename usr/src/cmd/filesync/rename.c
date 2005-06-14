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
 * Copyright (c) 1995 Sun Microsystems, Inc.  All Rights Reserved
 *
 * module:
 *	rename.c
 *
 * purpose:
 *	routines to determine whether or not any renames have taken place
 *	and note them (for reconciliation) if we find any
 *
 * contents:
 *	find_renames . look for files that have been renamed
 *	find_oldname . (static) find the file we were renamed from
 *	note_rename .. (static) note the rename for subsequent reconciliation
 *
 * notes:
 *	the reason renames warrant special attention is because the tree
 *	we have constructed is name based, and a directory rename can
 *	appear as zillions of changes.  We attempt to find and deal with
 *	renames prior to doing the difference analysis.
 *
 *	The only case we deal with here is simple renames.  If new links
 *	have been created beneath other directories (i.e. a file has been
 *	moved from one directory to another), the generalized link finding
 *	stuff will deal with it.
 *
 *	This is still under construction, and to completely deal with
 *	directory renames may require some non-trivial tree restructuring.
 *	There is a whole design note on this subject.  In the mean time,
 *	we still detect file renames, so that the user will see them
 *	reported as "mv"s rather than as "ln"s and "rm"s.  Until directory
 *	renames are fully implemented, they will instead be handled as
 *	mkdirs, massive links and unlinks, and rmdirs.
 */
#ident	"%W%	%E% SMI"

#include <stdio.h>

#include "filesync.h"
#include "database.h"


/* local routines */
static struct file *find_oldname(struct file *, struct file *, side_t);
static errmask_t
	note_rename(struct file *, struct file *, struct file *, side_t);

/*
 * routine:
 *	find_renames
 *
 * purpose:
 *	recursively perform rename analysis on a directory
 *
 * parameters:
 *	file node for the suspected directory
 *
 * returns:
 *	error mask
 *
 * note:
 *	the basic algorithm here is to search every directory
 *	for files that have been newly created on one side,
 *	and then look to see if they correspond to an identical
 *	file that has been newly deleted on the same side.
 */
errmask_t
find_renames(struct file *fp)
{	struct file *np, *rp;
	errmask_t errs = 0;
	int stype, dtype, btype, side;

	/* if this isn't a directory, there is nothing to analyze	*/
	if (fp->f_files == 0)
		return (0);

	/* look for any files under this directory that may have been renamed */
	for (np = fp->f_files; np; np = np->f_next) {
		btype = np->f_info[OPT_BASE].f_type;
		stype = np->f_info[OPT_SRC].f_type;
		dtype = np->f_info[OPT_DST].f_type;

		/* a rename must be a file that is new on only one side */
		if (btype == 0 && stype != dtype && (!stype || !dtype)) {
			side = stype ? OPT_SRC : OPT_DST;
			rp = find_oldname(fp, np, side);
			if (rp)
				errs |= note_rename(fp, np, rp, side);
		}
	}

	/* recursively examine all my children			*/
	for (np = fp->f_files; np; np = np->f_next) {
		errs |= find_renames(np);
	}

	return (errs);
}

/*
 * routine:
 *	find_oldname
 *
 * purpose:
 *	to search for an old name for a newly discovered file
 *
 * parameters:
 *	file node for the containing directory
 *	file node for the new file
 *	which side the rename is believed to have happened on
 *
 * returns:
 *	pointer to likely previous file
 *	0	no candidate found
 *
 * note:
 *	this routine only deals with simple renames within a single
 *	directory.
 */
static struct file *find_oldname(struct file *dirp, struct file *new,
	side_t side)
{	struct file *fp;
	long maj, min;
	ino_t inum;
	off_t size;
	side_t otherside = (side == OPT_SRC) ? OPT_DST : OPT_SRC;

	/* figure out what we're looking for		*/
	inum = new->f_info[side].f_ino;
	maj  = new->f_info[side].f_d_maj;
	min  = new->f_info[side].f_d_min;
	size = new->f_info[side].f_size;

	/*
	 * search the same directory for any entry that might describe
	 * the previous name of the new file.
	 */
	for (fp = dirp->f_files; fp; fp = fp->f_next) {
		/* previous name on changed side must no longer exist	*/
		if (fp->f_info[side].f_type != 0)
			continue;

		/* previous name on the other side must still exist	*/
		if (fp->f_info[otherside].f_type == 0)
			continue;

		/* it must describe the same inode as the new file	*/
		if (fp->f_info[OPT_BASE].f_type != new->f_info[side].f_type)
			continue;	/* must be same type		*/
		if (((side == OPT_SRC) ? fp->f_s_inum : fp->f_d_inum) != inum)
			continue;	/* must be same inode #		*/
		if (((side == OPT_SRC) ? fp->f_s_maj : fp->f_d_maj) != maj)
			continue;	/* must be same major #		*/
		if (((side == OPT_SRC) ? fp->f_s_min : fp->f_d_min) != min)
			continue;	/* must be same minor #		*/

		/*
		 * occasionally a prompt delete and create can reuse the
		 * same i-node in the same directory.  What we really
		 * want is generation, but that isn't available just
		 * yet, so our poor-man's approximation is the size.
		 * There is little point in checking ownership and
		 * modes, since the fact that it is in the same
		 * directory strongly suggests that it is the same
		 * user who is doing the deleting and creating.
		 */
		if (fp->f_info[OPT_BASE].f_size != size)
			continue;

		/* looks like we found a match				*/
		return (fp);
	}

	/* no joy	*/
	return (0);
}

/*
 * routine:
 *	note_rename
 *
 * purpose:
 *	to record a discovered rename, so that the reconciliation
 *	phase will deal with it as a rename rather than as link
 *	followed by an unlink.
 *
 * parameters:
 *	file node for the containing directory
 *	file node for the new file
 *	file node for the old file
 *	which side the rename is believed to have happened on
 *
 * returns:
 *	error mask
 */
static errmask_t
note_rename(struct file *dirp, struct file *new,
			struct file *old, side_t side)
{
	int dir;
	errmask_t errs = 0;
	static char *sidenames[] = {"base", "source", "dest"};

	dir = new->f_info[side].f_type == S_IFDIR;

	if (opt_debug & DBG_ANAL)
		fprintf(stderr, "ANAL: NOTE RENAME %s %s/%s -> %s/%s on %s\n",
			dir ? "directory" : "file",
			dirp->f_name, old->f_name, dirp->f_name, new->f_name,
			sidenames[side]);

	/* FIX: we don't deal with directory renames yet	*/
	if (dir)
		return (0);

	/* note that a rename has taken place			*/
	if (side == OPT_SRC) {
		new->f_srcdiffs |= D_RENAME_TO;
		old->f_srcdiffs |= D_RENAME_FROM;
	} else {
		new->f_dstdiffs |= D_RENAME_TO;
		old->f_dstdiffs |= D_RENAME_FROM;
	}

	/* put a link to the old name in the new name		*/
	new->f_previous = old;

	/* for most files, there is nothing else we have to do	*/
	if (!dir)
		return (errs);

	/*
	 * FIX ... someday we are going to have to merge the old and
	 *	   new children into a single tree, but there are
	 *	   horrendous backout problems if we are unable to
	 *	   do the mvdir, so I have postponed this feature.
	 */

	return (errs);
}
