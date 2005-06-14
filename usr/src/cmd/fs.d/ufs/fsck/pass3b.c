/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
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

#define	bcopy(f, t, n)	memcpy(t, f, n)
#define	bzero(s, n)	memset(s, 0, n)
#define	bcmp(s, d, n)	memcmp(s, d, n)

#define	index(s, r)	strchr(s, r)
#define	rindex(s, r)	strrchr(s, r)

#include <sys/fs/ufs_fs.h>
#include <sys/vnode.h>
#include <string.h>
#include <sys/fs/ufs_inode.h>
#include "fsck.h"

int pass3bcheck(struct inodesc *);
int aclblksort();
void dodump(char *, int);
int bufchk(char *, int64_t);
void listshadows(void);

pass3b()
{
	ino_t inumber;
	struct dinode *dp;
	struct aclinfo *aclp;
	struct inodesc curino;
	char pathbuf[MAXPATHLEN + 1];
	int64_t maxaclsize = 0;
	struct shadowclientinfo *sci;
	struct shadowclients *scc;
	int i;

	/*
	 * Sort the acl list into disk block order.
	 */
	qsort((char *)aclpsort, (int)aclplast, sizeof (*aclpsort), aclblksort);
	/*
	 * Scan all the acl inodes, finding the largest acl file.
	 */
	for (inumber = 0; inumber < aclplast; inumber++) {
		aclp = aclpsort[inumber];
		/* ACL file will not be >=2GB */
		if ((int64_t)aclp->i_isize > maxaclsize)
			maxaclsize = (int64_t)aclp->i_isize;
	}
	maxaclsize = ((maxaclsize / sblock.fs_bsize) + 1) *
				sblock.fs_bsize;
	if ((aclbuf = malloc(maxaclsize)) == NULL) {
		printf("cannot alloc %ld bytes for aclbuf\n", maxaclsize);
		return (1);
	}
	/*
	 * Scan all the acl inodes, checking contents
	 */
	for (inumber = 0; inumber < aclplast; inumber++) {
		aclp = aclpsort[inumber];
		dp = ginode(aclp->i_number);
		curino.id_fix = FIX;
		curino.id_type = ACL;
		curino.id_func = pass3bcheck;
		curino.id_number = aclp->i_number;
		curino.id_filesize = aclp->i_isize;
		aclbufoff = 0;
		bzero(aclbuf, (size_t)maxaclsize);
		if ((ckinode(dp, &curino) & KEEPON) == 0 ||
				bufchk(aclbuf, (int64_t)aclp->i_isize)) {
			if (dp->di_nlink <= 0) {
				statemap[aclp->i_number] = FSTATE;
				continue;
			}
			printf("ACL I=%d BAD/CORRUPT", aclp->i_number);
			if (preen || reply("CLEAR") == 1) {
				if (preen)
					printf("\n");
				freeino(aclp->i_number);
			}
		}
	}
	/*
	 * Now scan all shadow inodes, checking that any inodes that previously
	 * had an acl still have an acl.
	 */
	for (sci = shadowclientinfo; sci; sci = sci->next) {
		if (statemap[sci->shadow] != SSTATE) {
			for (scc = sci->clients; scc; scc = scc->next) {
				for (i = 0; i < scc->nclients; i++) {
					printf("I=%d HAS BAD/CLEARED ACL I=%d",
					    scc->client[i], sci->shadow);
					if (preen || reply("FIX") == 1) {
						if (preen)
							printf("\n");
						dp = ginode(scc->client[i]);
						dp->di_mode &= IFMT;
						dp->di_smode = dp->di_mode;
						/*
						 * Decrement link count -
						 * pass1 made sure the shadow
						 * inode # is a valid inode
						 * number.
						 */
						lncntp[dp->di_shadow]++;
						dp->di_shadow = 0;
						inodirty();
					}
				}
			}
		}
	}
	/* listshadows(); */
}

/*
 * Collect all the (data) blocks of an acl file into a buffer.
 * Later we'll scan the buffer and validate the acl data.
 */
int
pass3bcheck(struct inodesc *idesc)
{
	struct bufarea *bp;
	int size, bsize;

	if (aclbufoff == idesc->id_filesize) {
		return (STOP);
	}
	bsize = size = sblock.fs_fsize * idesc->id_numfrags;
	if ((size + aclbufoff) > idesc->id_filesize)
		size = idesc->id_filesize - aclbufoff;
	bp = getdatablk(idesc->id_blkno, bsize);
	bcopy(bp->b_un.b_buf, aclbuf + aclbufoff, (size_t)size);
	aclbufoff += size;
	brelse(bp);
	return (KEEPON);
}

/*
 * Routine to sort disk blocks.
 */
aclblksort(aclpp1, aclpp2)
	struct aclinfo **aclpp1, **aclpp2;
{

	return ((*aclpp1)->i_blks[0] - (*aclpp2)->i_blks[0]);
}

int
bufchk(char *buf, int64_t len)
{
	ufs_fsd_t *fsdp;
	ufs_acl_t *ufsaclp = NULL;
	int numacls;
	int i;
	int nuser_objs = 0;
	int ngroup_objs = 0;
	int nother_objs = 0;
	int nclass_objs = 0;
	int ndef_user_objs = 0;
	int ndef_group_objs = 0;
	int ndef_other_objs = 0;
	int ndef_class_objs = 0;
	int nusers = 0;
	int ngroups = 0;
	int ndef_users = 0;
	int ndef_groups = 0;
	int numdefs = 0;

	for (fsdp = (ufs_fsd_t *)buf;
	    (caddr_t)fsdp < (buf + len) &&
	    ((caddr_t)fsdp + fsdp->fsd_size) <= (buf + len);
	    fsdp = (ufs_fsd_t *)((caddr_t)fsdp +
	    FSD_RECSZ(fsdp, fsdp->fsd_size))) {
		switch (fsdp->fsd_type) {
		case FSD_ACL:
		case FSD_DFACL:
			numacls = (fsdp->fsd_size - 2 * sizeof (int)) /
							sizeof (ufs_acl_t);
			for (ufsaclp = (ufs_acl_t *)fsdp->fsd_data;
							numacls; ufsaclp++) {
				switch (ufsaclp->acl_tag) {
				case USER_OBJ:		/* Owner */
					nuser_objs++;
					break;
				case GROUP_OBJ:		/* Group */
					ngroup_objs++;
					break;
				case OTHER_OBJ:		/* Other */
					nother_objs++;
					break;
				case CLASS_OBJ:		/* Mask */
					nclass_objs++;
					break;
				case DEF_USER_OBJ:	/* Default Owner */
					ndef_user_objs++;
					break;
				case DEF_GROUP_OBJ:	/* Default Group */
					ndef_group_objs++;
					break;
				case DEF_OTHER_OBJ:	/* Default Other */
					ndef_other_objs++;
					break;
				case DEF_CLASS_OBJ:	/* Default Mask */
					ndef_class_objs++;
					break;
				case USER:		/* Users */
					nusers++;
					break;
				case GROUP:		/* Groups */
					ngroups++;
					break;
				case DEF_USER:		/* Default Users */
					ndef_users++;
					break;
				case DEF_GROUP:		/* Default Groups */
					ndef_groups++;
					break;
				default:
					return (1);
				}
/*
 *				if ((ufsaclp->acl_perm & ~07) != 0) {
 *					return (1);
 *				}
 */
				numacls--;
			}
			break;
		default:
			break;
		}
	}
	if ((caddr_t)fsdp != (buf + len)) {
		return (1);
	}

	/* If we didn't find any acls, ignore the unknown attribute */
	if (ufsaclp == NULL)
		return (0);

	/* Check relationships amoung acls */
	if (nuser_objs != 1 || ngroup_objs != 1 ||
	    nother_objs != 1 || nclass_objs > 1) {
		return (1);
	}
	if (ngroups && !nclass_objs) {
		return (1);
	}
	if (ndef_other_objs > 1 || ndef_user_objs > 1 ||
	    ndef_group_objs > 1 || ndef_class_objs > 1) {
		return (1);
	}

	/* Check relationships amoung default acls */
	numdefs = ndef_other_objs + ndef_user_objs + ndef_group_objs;
	if (numdefs != 0 && numdefs != 3) {
		return (1);
	}
	if (ndef_groups && !ndef_class_objs) {
		return (1);
	}
	if ((ndef_users || ndef_groups) &&
	    ((numdefs != 3) && !ndef_class_objs)) {
		return (1);
	}
	return (0);
}
