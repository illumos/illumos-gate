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
/*
 *
 *			res.c
 *
 * Implements routines to create a cache resource file.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <sys/fs/cachefs_fs.h>
#include "res.h"

struct res {
	int			 p_magic;	/* magic number */
	int			 p_done:1;	/* 1 if res_done called */
	int			 p_verbose:1;	/* 1 means print errors */
	void			*p_addrp;	/* address of mapped file */
	long			 p_size;	/* size of mapped file */
	struct cache_usage	*p_cusagep;	/* ptr to cache_usage */
	struct cachefs_rl_info	*p_linfop;	/* ptr to rl_info */
	rl_entry_t		*p_rlentp;	/* ptr to first rl_entry */
	int			 p_totentries;	/* max number of rl entries */
	char		 p_name[MAXPATHLEN];	/* name of resource file */
};

#define	MAGIC 8272
#define	precond(A) assert(A)
#define	MININDEX 1

#define	RL_HEAD(resp, type) \
	(&(resp->p_linfop->rl_items[CACHEFS_RL_INDEX(type)]))
#define	CVBLKS(nbytes) ((nbytes + MAXBSIZE - 1) / MAXBSIZE)

/* forward references */
void res_rlent_moveto(res *resp, enum cachefs_rl_type type, uint_t entno,
    long blks);
void res_reset(res *resp);
void res_clear(res *resp);
int res_listcheck(res *, enum cachefs_rl_type);

/*
 *
 *			res_create
 *
 * Description:
 *	Creates a res object and returns a pointer to it.
 *	The specified file is used to store resource file data.
 * Arguments:
 *	namep	name of the resource file
 *	entries	max number of rl entries in the file
 *	verbose 1 means print out error messages
 * Returns:
 *	Returns a pointer to the object or NULL if an error occurred.
 * Preconditions:
 *	precond(namep)
 *	precond(entries > 3)
 *	precond(strlen(namep) < MAXPATHLEN)
 */

res *
res_create(char *namep, int entries, int verbose)
{
	int xx;
	long size;
	int fd;
	char buf[1024];
	long cnt;
	unsigned int amt;
	ssize_t result;
	void *addrp;
	res *resp;
	struct stat64 statinfo;

	precond(namep);
	precond(entries > MININDEX);

	/* determine the size needed for the resource file */
	size = MAXBSIZE;
	size += MAXBSIZE * (entries / CACHEFS_RLPMBS);
	if ((entries %  CACHEFS_RLPMBS) != 0)
		size += MAXBSIZE;

	/* if the file does not exist or is the wrong size/type */
	xx = lstat64(namep, &statinfo);
	/* resource file will be <2GB */
	if ((xx == -1) || (statinfo.st_size != (offset_t)size) ||
	    !(S_ISREG(statinfo.st_mode))) {

		/* remove the resource file */
		xx = unlink(namep);
		if ((xx == -1) && (errno != ENOENT))
			return (NULL);

		/* create and open the file */
		fd = open(namep, O_CREAT | O_RDWR, 0600);
		if (fd == -1)
			return (NULL);

		/* fill the file with zeros */
		memset(buf, 0, sizeof (buf));
		for (cnt = size; cnt > 0; cnt -= result) {
			amt = sizeof (buf);
			if (amt > cnt)
				amt = cnt;
			result = write(fd, buf, amt);
			if (result == -1) {
				close(fd);
				return (NULL);
			}
		}
	}

	/* else open the file */
	else {
		fd = open(namep, O_RDWR);
		if (fd == -1)
			return (NULL);
	}

	/* mmap the file into our address space */
	addrp = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (addrp == (void *)-1) {
		close(fd);
		return (NULL);
	}

	/* close the file descriptor, we do not need it anymore */
	close(fd);

	/* allocate memory for the res object */
	resp = malloc(sizeof (res));
	if (resp == NULL) {
		munmap(addrp, size);
		return (NULL);
	}

	/* initialize the object */
	resp->p_magic = MAGIC;
	resp->p_done = 0;
	resp->p_addrp = addrp;
	resp->p_size = size;
	resp->p_verbose = verbose;
	resp->p_cusagep = (struct cache_usage *)addrp;
	resp->p_linfop = (struct cachefs_rl_info *)((char *)addrp +
	    sizeof (struct cache_usage));
	resp->p_rlentp = (rl_entry_t *)((char *)addrp + MAXBSIZE);
	resp->p_totentries = entries;
	strcpy(resp->p_name, namep);

	/* reset the resource file in preperation to rebuild it */
	res_reset(resp);

	/* return the object */
	return (resp);
}

/*
 *
 *			res_destroy
 *
 * Description:
 *	Destroys the specifed res object.
 *	If res_done has not been called on the object or if res_done
 *	failed, then the resource file will be deleted.
 * Arguments:
 *	resp	object to destroy
 * Returns:
 * Preconditions:
 *	precond(resp is a valid res object)
 */

void
res_destroy(res *resp)
{
	precond(resp);
	precond(resp->p_magic == MAGIC);

	/* unmap the file */
	munmap(resp->p_addrp, resp->p_size);

	/* if res_done not performed */
	if (resp->p_done == 0) {
		/* remove the resource file */
		unlink(resp->p_name);
	}

	/* destroy the object */
	resp->p_magic = -MAGIC;
	free(resp);
}

rl_entry_t *
res_rlent_get(res *resp, uint_t entno)
{
	rl_entry_t *rlentp, *window;
	uint_t whichwindow, winoffset;

	precond((entno >= MININDEX) && (entno < resp->p_totentries));

	whichwindow = entno / CACHEFS_RLPMBS;
	winoffset = entno % CACHEFS_RLPMBS;

	window = (rl_entry_t *)
	    (((caddr_t)resp->p_rlentp) + (MAXBSIZE * whichwindow));
	rlentp = window + winoffset;

	return (rlentp);
}

/*
 *
 *			res_reset
 *
 * Description:
 *	Resets the resource file in preparation to rebuild it.
 * Arguments:
 *	resp	res object
 * Returns:
 * Preconditions:
 *	precond(resp is a valid res object)
 */

void
res_reset(res *resp)
{
	int index;
	rl_entry_t *rlentp;
	int ret;
	cachefs_rl_listhead_t *lhp;

	precond(resp);
	precond(resp->p_magic == MAGIC);

	resp->p_cusagep->cu_blksused = 0;
	resp->p_cusagep->cu_filesused = 0;
	resp->p_cusagep->cu_flags = CUSAGE_ACTIVE;	/* dirty cache */

	/* clear out the non-pointer info */
	for (index = MININDEX; index < resp->p_totentries; index++) {
		rlentp = res_rlent_get(resp, index);

		rlentp->rl_attrc = 0;
		rlentp->rl_fsck = 0;
		rlentp->rl_local = 0;
		rlentp->rl_fsid = 0LL;
		rlentp->rl_fileno = 0;
	}

	/* verify validity of the various lists */
	ret = res_listcheck(resp, CACHEFS_RL_GC);
	if (ret == 1) {
		ret = res_listcheck(resp, CACHEFS_RL_ATTRFILE);
		if (ret == 1) {
			ret = res_listcheck(resp, CACHEFS_RL_MODIFIED);
			if (ret == 1) {
				ret = res_listcheck(resp, CACHEFS_RL_PACKED);
				if (ret == 1) {
					ret = res_listcheck(resp,
					    CACHEFS_RL_PACKED_PENDING);
				}
			}
		}
	}

	/* if an error occurred on one of the lists */
	if (ret == 0) {
		res_clear(resp);
		return;
	}

	/* zero out total sizes, they get fixed up as we add items */
	RL_HEAD(resp, CACHEFS_RL_GC)->rli_blkcnt = 0;
	RL_HEAD(resp, CACHEFS_RL_ATTRFILE)->rli_blkcnt = 0;
	RL_HEAD(resp, CACHEFS_RL_MODIFIED)->rli_blkcnt = 0;
	RL_HEAD(resp, CACHEFS_RL_PACKED)->rli_blkcnt = 0;
	RL_HEAD(resp, CACHEFS_RL_PACKED_PENDING)->rli_blkcnt = 0;

	/* null out the heads of the lists we do not want to preserve */
	lhp = RL_HEAD(resp, CACHEFS_RL_FREE);
	memset(lhp, 0, sizeof (cachefs_rl_listhead_t));
	lhp = RL_HEAD(resp, CACHEFS_RL_NONE);
	memset(lhp, 0, sizeof (cachefs_rl_listhead_t));
	lhp = RL_HEAD(resp, CACHEFS_RL_MF);
	memset(lhp, 0, sizeof (cachefs_rl_listhead_t));
	lhp = RL_HEAD(resp, CACHEFS_RL_ACTIVE);
	memset(lhp, 0, sizeof (cachefs_rl_listhead_t));
}

/*
 *
 *			res_listcheck
 *
 * Description:
 *	Checks the specified list.
 * Arguments:
 *	resp	res object
 *	type	list to check
 * Returns:
 *	Returns 1 if the list is ok, 0 if there is a problem.
 * Preconditions:
 *	precond(resp is a valid res object)
 */

int
res_listcheck(res *resp, enum cachefs_rl_type type)
{
	rl_entry_t *rlentp;
	int previndex, index;
	cachefs_rl_listhead_t *lhp;
	int itemcnt = 0;

	lhp = RL_HEAD(resp, type);
	index = lhp->rli_front;
	previndex = 0;

	/* walk the list */
	while (index != 0) {
		itemcnt++;

		/* make sure offset is in bounds */
		if ((index < MININDEX) || (index >= resp->p_totentries)) {
			if (resp->p_verbose)
				pr_err("index out of bounds %d", index);
			return (0);
		}

		/* get pointer to rl_entry object */
		rlentp = res_rlent_get(resp, index);

		/* check forward pointer */
		if (rlentp->rl_fwd_idx != previndex) {
			/* bad back pointer in rl list */
			if (resp->p_verbose)
				pr_err(gettext("bad forward pointer %d %d"),
				    rlentp->rl_fwd_idx, previndex);
			return (0);
		}

		/* check for cycle */
		if (rlentp->rl_fsck) {
			/* cycle found in list */
			if (resp->p_verbose)
				pr_err(gettext("cycle found in list %d"),
				    index);
			return (0);
		}

		/* check type */
		if (rlentp->rl_current != type) {
			/* entry doesn't belong here */
			if (resp->p_verbose)
				pr_err(gettext(
				    "bad entry %d type %d in list type %d"),
				    index, (int)rlentp->rl_current, (int)type);
			return (0);
		}

		/* indicate we have seen this pointer */
		rlentp->rl_fsck = 1;
		previndex = index;
		index = rlentp->rl_bkwd_idx;
	}

	/* verify number of items match */
	if (itemcnt != lhp->rli_itemcnt) {
		if (resp->p_verbose)
			pr_err(gettext("itemcnt wrong old %d  new %d"),
			    lhp->rli_itemcnt, itemcnt);
		return (0);
	}

	return (1);
}

/*
 *
 *			res_clear
 *
 * Description:
 *	Deletes all information from the resource file.
 * Arguments:
 *	resp	res object
 * Returns:
 * Preconditions:
 *	precond(resp is a valid res object)
 */

void
res_clear(res *resp)
{
	memset(resp->p_addrp, 0, resp->p_size);
}


/*
 *
 *			res_done
 *
 * Description:
 *	Called when through performing res_addfile and res_addident
 *	to complete the resource file and flush the contents to
 *	the disk file.
 * Arguments:
 *	resp	res object
 * Returns:
 *	Returns 0 for success, -1 for an error with errno set
 *	appropriatly.
 * Preconditions:
 *	precond(resp is a valid res object)
 */

int
res_done(res *resp)
{
	rl_entry_t *rlentp;
	int index;
	int xx;
	int ret;

	precond(resp);
	precond(resp->p_magic == MAGIC);

	/* scan the ident list to find the max allocated entry */
	resp->p_linfop->rl_entries = 0;
	for (index = MININDEX; index < resp->p_totentries; index++) {
		rlentp = res_rlent_get(resp, index);
		if (rlentp->rl_fsid && (ino64_t)rlentp->rl_fsck) {
			resp->p_linfop->rl_entries = index;
		}
	}

	/* scan the ident list to fix up the free list */
	for (index = MININDEX; index < resp->p_totentries; index++) {
		rlentp = res_rlent_get(resp, index);

		/* if entry is not valid */
		if ((rlentp->rl_fsid == 0LL) || (rlentp->rl_fsck == 0)) {
			/* if entry should appear on the free list */
			if (index <= resp->p_linfop->rl_entries) {
				res_rlent_moveto(resp,
				    CACHEFS_RL_FREE, index, 0);
			}
		}
		rlentp->rl_fsck = 0; /* prepare to re-check */
	}

	/*
	 * Sanity check that we do not have an internal error in
	 * fsck.  Eventually turn this stuff off.
	 */
#if 1
	ret = res_listcheck(resp, CACHEFS_RL_GC);
	assert(ret == 1);
	ret = res_listcheck(resp, CACHEFS_RL_ATTRFILE);
	assert(ret == 1);
	ret = res_listcheck(resp, CACHEFS_RL_MODIFIED);
	assert(ret == 1);
	ret = res_listcheck(resp, CACHEFS_RL_PACKED);
	assert(ret == 1);
	ret = res_listcheck(resp, CACHEFS_RL_PACKED_PENDING);
	assert(ret == 1);
	ret = res_listcheck(resp, CACHEFS_RL_FREE);
	assert(ret == 1);
	ret = res_listcheck(resp, CACHEFS_RL_NONE);
	assert(ret == 1);
	ret = res_listcheck(resp, CACHEFS_RL_MF);
	assert(ret == 1);
	ret = res_listcheck(resp, CACHEFS_RL_ACTIVE);
	assert(ret == 1);
#endif

	/* indicate the cache is clean */
	resp->p_cusagep->cu_flags &= ~CUSAGE_ACTIVE;

	/* sync the data to the file */
	xx = msync(resp->p_addrp, resp->p_size, MS_SYNC);
	if (xx == -1)
		return (-1);

	resp->p_done = 1;

	/* return success */
	return (0);
}

/*
 *
 *			res_addfile
 *
 * Description:
 *	Increments the number of files and blocks resource counts.
 * Arguments:
 *	resp	res object
 *	nbytes	number of bytes in the file
 * Returns:
 * Preconditions:
 *	precond(resp is a valid res object)
 */

void
res_addfile(res *resp, long nbytes)
{
	precond(resp);
	precond(resp->p_magic == MAGIC);

	/* update resource counts */
	resp->p_cusagep->cu_blksused += CVBLKS(nbytes);
	resp->p_cusagep->cu_filesused += 1;
}

/*
 *
 *			res_addident
 *
 * Description:
 *	Adds the specified file to the ident list.
 *	Updates resource counts.
 * Arguments:
 *	resp	res object
 *	index	index into idents/pointers tables
 *	dp	ident information
 *	nbytes	number of bytes of item
 *	file	number of files of item
 * Returns:
 *	Returns 0 for success or -1 if the index is already in use
 *	or is not valid.
 * Preconditions:
 *	precond(resp is a valid res object)
 *	precond(dp)
 */

int
res_addident(res *resp, int index, rl_entry_t *dp, long nbytes, int file)
{
	rl_entry_t *rlentp;

	precond(resp);
	precond(resp->p_magic == MAGIC);
	precond(dp);

	/* check index for sanity */
	if ((index < MININDEX) || (index >= resp->p_totentries)) {
		return (-1);
	}

	/* get pointer to ident */
	rlentp = res_rlent_get(resp, index);

	/* if something already there */
	if (rlentp->rl_fsid != 0LL) {
		return (-1);
	}

	/* if not on the right list, move it there */
	if ((rlentp->rl_fsck == 0) || (rlentp->rl_current != dp->rl_current))
		res_rlent_moveto(resp, dp->rl_current, index, CVBLKS(nbytes));

	rlentp->rl_fsck = 1;
	rlentp->rl_local = dp->rl_local;
	rlentp->rl_attrc = dp->rl_attrc;
	rlentp->rl_fsid = dp->rl_fsid;
	rlentp->rl_fileno = dp->rl_fileno;

	/* update resource counts */
	resp->p_cusagep->cu_blksused += CVBLKS(nbytes);
	resp->p_cusagep->cu_filesused += file;

	/* return success */
	return (0);
}

/*
 *
 *			res_clearident
 *
 * Description:
 *	Removes the specified file from the ident list.
 *	Updates resource counts.
 * Arguments:
 *	resp	res object
 *	index	index into idents/pointers tables
 *	nbytes	number of bytes in the file
 *	file	number of files
 * Returns:
 *	Returns 0.
 * Preconditions:
 *	precond(resp is a valid res object)
 *	precond(index is valid)
 *	precond(ident is in use)
 */

void
res_clearident(res *resp, int index, int nbytes, int file)
{
	rl_entry_t *rlentp;

	precond(resp);
	precond(resp->p_magic == MAGIC);
	precond((index >= MININDEX) && (index < resp->p_totentries));

	/* get pointer to ident */
	rlentp = res_rlent_get(resp, index);
	precond(rlentp->rl_fsid != 0LL);

	/* clear the ident */
	rlentp->rl_fsid = 0LL;
	rlentp->rl_fileno = 0;
	rlentp->rl_attrc = 0;
	rlentp->rl_local = 0;

	/* update resource counts */
	resp->p_cusagep->cu_blksused -= CVBLKS(nbytes);
	resp->p_cusagep->cu_filesused -= file;
	assert(resp->p_cusagep->cu_blksused >= 0);
}

/*
 * This function moves an RL entry from whereever it currently is to
 * the requested list.
 */

void
res_rlent_moveto(res *resp, enum cachefs_rl_type type, uint_t entno, long blks)
{
	rl_entry_t *rl_ent;
	uint_t prev, next;
	cachefs_rl_listhead_t *lhp;
	enum cachefs_rl_type otype;

	precond((CACHEFS_RL_START <= type) && (type <= CACHEFS_RL_END));
	precond((entno >= MININDEX) && (entno < resp->p_totentries));

	rl_ent = res_rlent_get(resp, entno);
	if (rl_ent->rl_fsck) {
		/* remove entry from its previous list */

		next = rl_ent->rl_fwd_idx;
		prev = rl_ent->rl_bkwd_idx;
		otype = rl_ent->rl_current;
		assert((CACHEFS_RL_START <= otype) &&
		    (otype <= CACHEFS_RL_END));

		lhp = RL_HEAD(resp, otype);
		if ((lhp->rli_back == 0) || (lhp->rli_front == 0))
			assert((lhp->rli_back == 0) && (lhp->rli_front == 0));

		if (lhp->rli_back == entno)
			lhp->rli_back = next;
		if (lhp->rli_front == entno)
			lhp->rli_front = prev;
		if (prev != 0) {
			rl_ent = res_rlent_get(resp, prev);
			rl_ent->rl_fwd_idx = next;
		}
		if (next != 0) {
			rl_ent = res_rlent_get(resp, next);
			rl_ent->rl_bkwd_idx = prev;
		}
		lhp->rli_blkcnt -= blks;
		lhp->rli_itemcnt--;
	}

	/* add entry to its new list */

	lhp = RL_HEAD(resp, type);
	rl_ent = res_rlent_get(resp, entno);
	rl_ent->rl_current = type;
	rl_ent->rl_bkwd_idx = 0;
	rl_ent->rl_fwd_idx = lhp->rli_back;

	if (lhp->rli_back != 0) {
		assert(lhp->rli_front != 0);
		rl_ent = res_rlent_get(resp, lhp->rli_back);
		rl_ent->rl_bkwd_idx = entno;
	} else {
		assert(lhp->rli_front == 0);
		lhp->rli_front = entno;
	}
	lhp->rli_back = entno;
	lhp->rli_blkcnt += blks;
	lhp->rli_itemcnt++;

	rl_ent = res_rlent_get(resp, entno);
	rl_ent->rl_current = type;
	rl_ent->rl_fsck = 1;
}
