/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 1980, 1986, 1990 The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that: (1) source distributions retain this entire copyright
 * notice and comment, and (2) distributions including binaries display
 * the following acknowledgement:  ``This product includes software
 * developed by the University of California, Berkeley and its contributors''
 * in the documentation or other materials provided with the distribution
 * and in all advertising materials mentioning features or use of this
 * software. Neither the name of the University nor the names of its
 * contributors may be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/fs/ufs_fs.h>
#include <sys/fs/ufs_fsdir.h>
#include "fsck.h"

/* XXX should convert pass2a to using avl tree */

/*
 * Directory contents table is keyed first by name length, and
 * then the actual name.
 */
typedef struct dirtree {
	caddr_t name;
	int len;
	fsck_ino_t ino;
} dirtree_t;

/*
 * Tree of contents of directory currently being traversed.
 * Elements are pointers to dirtree_t instances.
 */
static void *contents;

static int pass2acheck(struct inodesc *);
static void discard_contents(void);
static int dirtree_cmp(const void *, const void *);

/*
 * Make sure directories don't contain duplicate names.
 */
void
pass2a(void)
{
	struct inodesc idesc;
	struct inoinfo *inp, **inpp, **inpend;
	struct dinode *dp;

	inpend = &inpsort[inplast];
	for (inpp = inpsort; inpp < inpend; inpp++) {
		inp = *inpp;

		if (inp->i_isize == 0)
			continue;

		/* != DSTATE also covers case of == USTATE */
		if (((statemap[inp->i_number] & STMASK) != DSTATE) ||
		    ((statemap[inp->i_number] & INCLEAR) == INCLEAR))
			continue;

		dp = ginode(inp->i_number);
		init_inodesc(&idesc);
		idesc.id_filesize = dp->di_size;
		idesc.id_type = DATA;
		idesc.id_func = pass2acheck;
		idesc.id_number = inp->i_number;
		idesc.id_parent = inp->i_parent;
		idesc.id_fix = NOFIX;
		(void) ckinode(dp, &idesc, CKI_TRAVERSE);

		discard_contents();
	}
}

/*
 * Used to scan a particular directory, noting what entries it contains.
 * If a duplicate entry is found, it is reported and the user given
 * the option of clearing said entry.
 */
static int
pass2acheck(struct inodesc *idesc)
{
	struct direct *dirp = idesc->id_dirp;
	dirtree_t key;
	void **foundp;
	dirtree_t *firstp;
	int retval = KEEPON;

	/*
	 * We've reached the end of the valid part of the directory.
	 */
	if (idesc->id_blkno == 0) {
		return (STOP);
	}

	if (dirp->d_ino != 0) {
		key.name = dirp->d_name;
		key.len = dirp->d_namlen;
		foundp = tfind((void *)&key, &contents, dirtree_cmp);
		if ((foundp != NULL) && (*foundp != NULL)) {
			firstp = (dirtree_t *)*foundp;

			pfatal(
		    "Duplicate entries in dir I=%d for ``%s'': I=%d and I=%d",
			    idesc->id_number, dirp->d_name,
			    firstp->ino, dirp->d_ino);
			if (reply("Clear second entry") == 1) {
				dirp->d_ino = 0;
				retval |= ALTERED;
			} else {
				iscorrupt = 1;
			}
		} else {
			firstp = (dirtree_t *)malloc(sizeof (dirtree_t));
			if ((firstp == NULL) ||
			    ((firstp->name = strdup(dirp->d_name)) == NULL)) {
				goto nomem;
			}
			firstp->len = dirp->d_namlen;
			firstp->ino = dirp->d_ino;
			if (tsearch((void *)firstp,
				    &contents, dirtree_cmp) == NULL) {
				goto nomem;
			}
		}
	}

	return (retval);

nomem:
	if (firstp != NULL) {
		if (firstp->name != NULL)
			free(firstp->name);
		free(firstp);
	}

	pfatal(
	    "Out of memory while looking for duplicate names in directory I=%d",
	    idesc->id_number);
	if (reply("SKIP REST OF DUP NAME CHECK") == 0)
		errexit("Program terminated.");

	discard_contents();
	retval |= STOP;

	return (retval);
}

static void
discard_contents(void)
{
	dirtree_t *victim;

	while (contents != NULL) {
		victim = *(dirtree_t **)contents;
		(void) tdelete((void *)victim, &contents, dirtree_cmp);
		free((void *)victim->name);
		free((void *)victim);
	}
}

static int
dirtree_cmp(const void *left, const void *right)
{
	int cmp;
	const dirtree_t *lp = (const dirtree_t *)left;
	const dirtree_t *rp = (const dirtree_t *)right;

	cmp = lp->len - rp->len;
	if (cmp == 0)
		cmp = strcmp(lp->name, rp->name);

	return (cmp);
}
