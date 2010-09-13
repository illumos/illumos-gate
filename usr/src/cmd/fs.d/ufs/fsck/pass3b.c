/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
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
#include <sys/param.h>
#include <sys/types.h>
#include <sys/mntent.h>
#include <sys/acl.h>
#include <sys/fs/ufs_acl.h>
#include <sys/fs/ufs_fs.h>
#include <sys/vnode.h>
#include <string.h>
#include <sys/fs/ufs_inode.h>
#include "fsck.h"

/*
 * We can be run on multiple filesystems (processed serially), so
 * these need to be re-initialized each time we start the pass.
 */
static caddr_t aclbuf;		/* hold acl's for parsing */
static int64_t aclbufoff;	/* offset into aclbuf */
static int64_t maxaclsize;	/* how big aclbuf is */

static int aclblksort(const void *, const void *);
static int bufchk(char *, int64_t, fsck_ino_t);
static void clear_shadow_client(struct shadowclientinfo *,
	    struct shadowclients *, int);

void
pass3b(void)
{
	fsck_ino_t inumber;
	struct dinode *dp;
	struct inoinfo *aclp;
	struct inodesc curino;
	struct shadowclientinfo *sci;
	struct shadowclients *scc;
	int64_t acl_size_limit;
	int i;

	/*
	 * Sort the acl list into disk block order.
	 */
	qsort((char *)aclpsort, (int)aclplast, sizeof (*aclpsort), aclblksort);
	/*
	 * Scan all the acl inodes, finding the largest acl file.
	 *
	 * The largest legal size is (4 * MAX_ACL_ENTRIES + 8) entries.
	 * The four are the categories of specific users, specific
	 * groups, default specific users, and default specific groups.
	 * The eight are the entries for the owning user/group/other/class
	 * plus the equivalent defaults.
	 *
	 * We double this to allow for a truly worst-case but legal
	 * situation of every single acl having its own fsd_t wrapper.
	 * Doubling is a bit pessimistic (sizeof (acl_t) > sizeof (fsd_t)).
	 */
	acl_size_limit = sizeof (ufs_acl_t) * (4 * MAX_ACL_ENTRIES + 8);
	acl_size_limit *= 2;

	maxaclsize = 0;
	for (inumber = 0; inumber < aclplast; inumber++) {
		aclp = aclpsort[inumber];
		if ((int64_t)aclp->i_isize > acl_size_limit) {
			(void) printf(
			    "ACL I=%d is excessively large (%lld > %lld)",
			    inumber,
			    (longlong_t)aclp->i_isize,
			    (longlong_t)acl_size_limit);
			if (preen) {
				(void) printf(" (IGNORING)\n");
			} else if (reply("CLEAR") == 1) {
				freeino(inumber, TI_PARENT);
			} else {
				iscorrupt = 1;
				(void) printf("IGNORING SHADOW I=%d\n",
				    inumber);
			}
			continue;
		}
		if ((int64_t)aclp->i_isize > maxaclsize)
			maxaclsize = (int64_t)aclp->i_isize;
	}

	maxaclsize = ((maxaclsize / sblock.fs_bsize) + 1) * sblock.fs_bsize;
	if (maxaclsize == 0)
		goto noacls;

	if (aclbuf != NULL) {
		free((void *)aclbuf);
	}
	if ((aclbuf = malloc(maxaclsize)) == NULL) {
		errexit("cannot alloc %lld bytes for aclbuf\n",
			(longlong_t)maxaclsize);
	}
	/*
	 * Scan all the acl inodes, checking contents
	 */
	for (inumber = 0; inumber < aclplast; inumber++) {
		aclp = aclpsort[inumber];
		if ((int64_t)aclp->i_isize > acl_size_limit) {
			continue;
		}
		if ((statemap[aclp->i_number] & STMASK) != SSTATE) {
			continue;
		}
		dp = ginode(aclp->i_number);
		init_inodesc(&curino);
		curino.id_fix = FIX;
		curino.id_type = ACL;
		curino.id_func = pass3bcheck;
		curino.id_number = aclp->i_number;
		curino.id_filesize = aclp->i_isize;
		aclbufoff = 0;
		(void) memset(aclbuf, 0, (size_t)maxaclsize);
		if ((ckinode(dp, &curino, CKI_TRAVERSE) & KEEPON) == 0 ||
		    bufchk(aclbuf, (int64_t)aclp->i_isize, aclp->i_number)) {
			dp = ginode(aclp->i_number); /* defensive no-op */
			if (dp->di_nlink <= 0) {
				statemap[aclp->i_number] = FSTATE;
				continue;
			}
			(void) printf("ACL I=%d BAD/CORRUPT", aclp->i_number);
			if (preen || reply("CLEAR") == 1) {
				if (preen)
					(void) printf("\n");
				freeino(aclp->i_number, TI_PARENT);
			} else {
				iscorrupt = 1;
			}
		}
	}
	/*
	 * Now scan all shadow inodes, checking that any inodes that previously
	 * had an acl still have an acl.
	 */
noacls:
	for (sci = shadowclientinfo; sci; sci = sci->next) {
		if ((statemap[sci->shadow] & STMASK) != SSTATE) {
			for (scc = sci->clients; scc; scc = scc->next) {
				for (i = 0; i < scc->nclients; i++) {
					clear_shadow_client(sci, scc, i);
				}
			}
		}
	}
	free((void *)aclbuf);
	aclbuf = NULL;
}

static void
clear_shadow_client(struct shadowclientinfo *sci, struct shadowclients *scc,
	int client)
{
	int suppress_update = 0;
	caddr_t flow;
	struct inodesc ldesc;
	struct dinode *dp;

	(void) printf("I=%d HAS BAD/CLEARED ACL I=%d",
	    scc->client[client], sci->shadow);
	if (preen || reply("FIX") == 1) {
		if (preen)
			(void) printf("\n");

		/*
		 * If we clear the ACL, then the permissions should
		 * be as restrictive as possible until the user can
		 * set it to something reasonable.  If we keep the
		 * ACL, then the permissions are pretty much
		 * irrelevant.  So, just always clear the permission
		 * bits.
		 */
		dp = ginode(scc->client[client]);
		dp->di_mode &= IFMT;
		dp->di_shadow = 0;
		inodirty();

		/*
		 * Decrement in-memory link count - pass1 made sure
		 * the shadow inode # is a valid inode number.  But
		 * first, see if we're going to overflow our sixteen
		 * bits.
		 */
		LINK_RANGE(flow, lncntp[dp->di_shadow], 1);
		if (flow != NULL) {
			LINK_CLEAR(flow, scc->client[client], dp->di_mode,
			    &ldesc);
			if (statemap[scc->client[client]] == USTATE)
				suppress_update = 1;
		}

		/*
		 * We don't touch the shadow's on-disk link count,
		 * because we've already cleared its state in pass3b().
		 * Here we're just trying to keep lncntp[] in sync, so
		 * we can detect spurious links.
		 */
		if (!suppress_update)
			TRACK_LNCNTP(sci->shadow, lncntp[sci->shadow]++);
	} else {
		iscorrupt = 1;
	}
}

/*
 * Collect all the (data) blocks of an acl file into a buffer.
 * Later we'll scan the buffer and validate the acl data.
 */
int
pass3bcheck(struct inodesc *idesc)
{
	struct bufarea *bp;
	size_t size, bsize;

	if (aclbufoff == idesc->id_filesize) {
		return (STOP);
	}
	bsize = size = sblock.fs_fsize * idesc->id_numfrags;
	if ((size + aclbufoff) > idesc->id_filesize)
		size = idesc->id_filesize - aclbufoff;
	if (aclbufoff + size > maxaclsize)
		errexit("acl size %lld exceeds maximum calculated "
			"size of %lld bytes",
			(longlong_t)aclbufoff + size, (longlong_t)maxaclsize);
	bp = getdatablk(idesc->id_blkno, bsize);
	if (bp->b_errs != 0) {
		brelse(bp);
		return (STOP);
	}
	(void) memmove((void *)(aclbuf + aclbufoff), (void *)bp->b_un.b_buf,
		(size_t)size);
	aclbufoff += size;
	brelse(bp);
	return (KEEPON);
}

/*
 * Routine to sort disk blocks.
 */
static int
aclblksort(const void *pp1, const void *pp2)
{
	const struct inoinfo **aclpp1 = (const struct inoinfo **)pp1;
	const struct inoinfo **aclpp2 = (const struct inoinfo **)pp2;

	return ((*aclpp1)->i_blks[0] - (*aclpp2)->i_blks[0]);
}

/*
 * Scan a chunk of a shadow file.  Return zero if no ACLs were found,
 * or when all that were found were valid.
 */
static int
bufchk(char *buf, int64_t len, fsck_ino_t inum)
{
	ufs_fsd_t *fsdp;
	ufs_acl_t *ufsaclp = NULL;
	int numacls;
	int curacl;
	struct type_counts_s {
		int nuser_objs;
		int ngroup_objs;
		int nother_objs;
		int nclass_objs;
		int ndef_user_objs;
		int ndef_group_objs;
		int ndef_other_objs;
		int ndef_class_objs;
		int nusers;
		int ngroups;
		int ndef_users;
		int ndef_groups;
	} type_counts[3];	/* indexed by FSD_ACL and FSD_DFACL */
	struct type_counts_s *tcp, *tcp_all, *tcp_def, *tcp_norm;
	int numdefs;
	caddr_t bad;
	caddr_t end = buf + len;
	int64_t recsz = 0;
	int64_t min_recsz = FSD_RECSZ(fsdp, sizeof (*fsdp));
	struct shadowclientinfo *sci;
	struct shadowclients *scc;
	fsck_ino_t target;
	int numtargets = 0;

	/*
	 * check we have a non-zero length for this shadow inode
	 */
	if (len == 0) {
		pwarn("ACL I=%d HAS ZERO LENGTH\n", inum);
		return (1);
	}

	(void) memset(type_counts, 0, sizeof (type_counts));

	/* LINTED pointer cast alignment (aligned buffer always passed in) */
	for (fsdp = (ufs_fsd_t *)buf;
	    (caddr_t)fsdp < end;
	    /* LINTED as per the above */
	    fsdp = (ufs_fsd_t *)((caddr_t)fsdp + recsz)) {

		recsz = FSD_RECSZ(fsdp, fsdp->fsd_size);
		if ((recsz < min_recsz) ||
		    (((caddr_t)fsdp + recsz) > (buf + len))) {
			pwarn("Bad FSD entry size %lld in shadow inode %d",
			    recsz, inum);
			if (reply("CLEAR SHADOW INODE") == 1) {
				freeino(inum, TI_PARENT);
			} else {
				/*
				 * Bad size can cause the kernel to
				 * go traipsing off into never-never land.
				 */
				iscorrupt = 1;
			}
			return (0);
		}

		switch (fsdp->fsd_type) {
		case FSD_FREE:	/* ignore empty slots */
			break;
		case FSD_ACL:
		case FSD_DFACL:
			/*
			 * Subtract out the two ints in the fsd_type,
			 * leaving us just the size of fsd_data[].
			 */
			numacls = (fsdp->fsd_size - 2 * sizeof (int)) /
							sizeof (ufs_acl_t);
			tcp = &type_counts[fsdp->fsd_type];
			curacl = 0;
			/* LINTED pointer cast alignment */
			for (ufsaclp = (ufs_acl_t *)fsdp->fsd_data;
						numacls; ufsaclp++, curacl++) {
				switch (ufsaclp->acl_tag) {
				case USER_OBJ:		/* Owner */
					tcp->nuser_objs++;
					break;
				case GROUP_OBJ:		/* Group */
					tcp->ngroup_objs++;
					break;
				case OTHER_OBJ:		/* Other */
					tcp->nother_objs++;
					break;
				case CLASS_OBJ:		/* Mask */
					tcp->nclass_objs++;
					break;
				case DEF_USER_OBJ:	/* Default Owner */
					tcp->ndef_user_objs++;
					break;
				case DEF_GROUP_OBJ:	/* Default Group */
					tcp->ndef_group_objs++;
					break;
				case DEF_OTHER_OBJ:	/* Default Other */
					tcp->ndef_other_objs++;
					break;
				case DEF_CLASS_OBJ:	/* Default Mask */
					tcp->ndef_class_objs++;
					break;
				case USER:		/* Users */
					tcp->nusers++;
					break;
				case GROUP:		/* Groups */
					tcp->ngroups++;
					break;
				case DEF_USER:		/* Default Users */
					tcp->ndef_users++;
					break;
				case DEF_GROUP:		/* Default Groups */
					tcp->ndef_groups++;
					break;
				default:
					return (1);
				}

				if ((ufsaclp->acl_perm & ~07) != 0) {
					/*
					 * Caller will report inode, etc
					 */
					pwarn("Bad permission 0%o in ACL\n",
					    ufsaclp->acl_perm);
					return (1);
				}

				numacls--;
			}
			break;
		default:
			if (fsdp->fsd_type >= FSD_RESERVED3 &&
			    fsdp->fsd_type <= FSD_RESERVED7)
				bad = "Unexpected";
			else
				bad = "Unknown";
			pwarn("%s FSD type %d in shadow inode %d",
			    bad, fsdp->fsd_type, inum);
			/*
			 * This is relatively harmless, since the
			 * kernel will ignore any entries it doesn't
			 * recognize.  Don't bother with iscorrupt.
			 */
			if (preen) {
				(void) printf(" (IGNORED)\n");
			} else if (reply("IGNORE") == 0) {
				if (reply("CLEAR SHADOW INODE") == 1) {
					freeino(inum, TI_PARENT);
				}
				return (0);
			}
			break;
		}
	}
	if ((caddr_t)fsdp != (buf + len)) {
		return (1);
	}

	/* If we didn't find any acls, ignore the unknown attribute */
	if (ufsaclp == NULL)
		return (0);

	/*
	 * Should only have default ACLs in FSD_DFACL records.
	 * However, the kernel can handle it, so just report that
	 * something odd might be going on.
	 */
	tcp = &type_counts[FSD_DFACL];
	if (verbose &&
	    (tcp->nuser_objs != 0 ||
	    tcp->ngroup_objs != 0 ||
	    tcp->nother_objs != 0 ||
	    tcp->nclass_objs != 0 ||
	    tcp->nusers != 0 ||
	    tcp->ngroups != 0)) {
		(void) printf("NOTE: ACL I=%d has miscategorized ACLs.  ",
		    inum);
		(void) printf("This is harmless, but not normal.\n");
	}

	/*
	 * Similarly for default ACLs in FSD_ACL records.
	 */
	tcp = &type_counts[FSD_ACL];
	if (verbose &&
	    (tcp->ndef_user_objs != 0 ||
	    tcp->ndef_group_objs != 0 ||
	    tcp->ndef_other_objs != 0 ||
	    tcp->ndef_class_objs != 0 ||
	    tcp->ndef_users != 0 ||
	    tcp->ndef_groups != 0)) {
		(void) printf("NOTE: ACL I=%d has miscategorized ACLs.",
		    inum);
		(void) printf("  This is harmless, but not normal.\n");
	}

	/*
	 * Get consolidated totals, now that we're done with checking
	 * the segregation above.  Assumes that neither FSD_ACL nor
	 * FSD_DFACL are zero.
	 */
	tcp_all = &type_counts[0];
	tcp_norm = &type_counts[FSD_ACL];
	tcp_def = &type_counts[FSD_DFACL];

	tcp_all->nuser_objs = tcp_def->nuser_objs + tcp_norm->nuser_objs;
	tcp_all->ngroup_objs = tcp_def->ngroup_objs + tcp_norm->ngroup_objs;
	tcp_all->nother_objs = tcp_def->nother_objs + tcp_norm->nother_objs;
	tcp_all->nclass_objs = tcp_def->nclass_objs + tcp_norm->nclass_objs;
	tcp_all->ndef_user_objs =
		tcp_def->ndef_user_objs + tcp_norm->ndef_user_objs;
	tcp_all->ndef_group_objs =
		tcp_def->ndef_group_objs + tcp_norm->ndef_group_objs;
	tcp_all->ndef_other_objs =
		tcp_def->ndef_other_objs + tcp_norm->ndef_other_objs;
	tcp_all->ndef_class_objs =
		tcp_def->ndef_class_objs + tcp_norm->ndef_class_objs;
	tcp_all->nusers = tcp_def->nusers + tcp_norm->nusers;
	tcp_all->ngroups = tcp_def->ngroups + tcp_norm->ngroups;
	tcp_all->ndef_users = tcp_def->ndef_users + tcp_norm->ndef_users;
	tcp_all->ndef_groups = tcp_def->ndef_groups + tcp_norm->ndef_groups;

	/*
	 * Check relationships among acls
	 */
	if (tcp_all->nuser_objs != 1 ||
	    tcp_all->ngroup_objs != 1 ||
	    tcp_all->nother_objs != 1 ||
	    tcp_all->nclass_objs > 1) {
		return (1);
	}

	if (tcp_all->ngroups && !tcp_all->nclass_objs) {
		return (1);
	}

	if (tcp_all->ndef_user_objs > 1 ||
	    tcp_all->ndef_group_objs > 1 ||
	    tcp_all->ndef_other_objs > 1 ||
	    tcp_all->ndef_class_objs > 1) {
		return (1);
	}

	/*
	 * Check relationships among default acls
	 */
	numdefs = tcp_all->ndef_other_objs + tcp_all->ndef_user_objs +
		tcp_all->ndef_group_objs;

	if (numdefs != 0 && numdefs != 3) {
		return (1);
	}

	/*
	 * If there are default acls, then the shadow inode's clients
	 * must be a directory or an xattr directory.
	 */
	if (numdefs != 0) {
		/* This is an ACL so find it's clients */
		for (sci = shadowclientinfo; sci != NULL; sci = sci->next)
			if (sci->shadow == inum)
			    break;
		if ((sci ==  NULL) || (sci->clients == NULL))
			return (1);

		/* Got shadow info, now look at clients */
		for (scc = sci->clients; scc != NULL; scc = scc->next) {
			for (numtargets = 0; numtargets < scc->nclients;
			    numtargets++) {
				target = scc->client[numtargets];
				if (!INO_IS_DVALID(target))
					return (1);
			}
		}
	}

	if (tcp_all->ndef_groups && !tcp_all->ndef_class_objs) {
		return (1);
	}

	if ((tcp_all->ndef_users || tcp_all->ndef_groups) &&
	    ((numdefs != 3) && !tcp_all->ndef_class_objs)) {
		return (1);
	}

	return (0);
}
