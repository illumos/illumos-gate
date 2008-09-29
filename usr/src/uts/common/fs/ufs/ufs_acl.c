/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/t_lock.h>
#include <sys/ksynch.h>
#include <sys/buf.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/mode.h>
#include <sys/systm.h>
#include <vm/seg.h>
#include <sys/file.h>
#include <sys/acl.h>
#include <sys/fs/ufs_inode.h>
#include <sys/fs/ufs_acl.h>
#include <sys/fs/ufs_quota.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>
#include <sys/policy.h>

/* Cache routines */
static int si_signature(si_t *);
static int si_cachei_get(struct inode *, si_t **);
static int si_cachea_get(struct inode *, si_t *, si_t **);
static int si_cmp(si_t *, si_t *);
static void si_cache_put(si_t *);
void si_cache_del(si_t *, int);
void si_cache_init(void);

static void ufs_si_free_mem(si_t *);
static int ufs_si_store(struct inode *, si_t *, int, cred_t *);
static si_t *ufs_acl_cp(si_t *);
static int ufs_sectobuf(si_t *, caddr_t *, size_t *);
static int acl_count(ufs_ic_acl_t *);
static int acl_validate(aclent_t *, int, int);
static int vsecattr2aclentry(vsecattr_t *, si_t **);
static int aclentry2vsecattr(si_t *, vsecattr_t *);

krwlock_t si_cache_lock;		/* Protects si_cache */
int	si_cachecnt = 64;		/* # buckets in si_cache[a|i] */
si_t	**si_cachea;			/* The 'by acl' cache chains */
si_t	**si_cachei;			/* The 'by inode' cache chains */
long	si_cachehit = 0;
long	si_cachemiss = 0;

#define	SI_HASH(S)	((int)(S) & (si_cachecnt - 1))

/*
 * Store the new acls in aclp.  Attempts to make things atomic.
 * Search the acl cache for an identical sp and, if found, attach
 * the cache'd acl to ip. If the acl is new (not in the cache),
 * add it to the cache, then attach it to ip.  Last, remove and
 * decrement the reference count of any prior acl list attached
 * to the ip.
 *
 * Parameters:
 * ip - Ptr to inode to receive the acl list
 * sp - Ptr to in-core acl structure to attach to the inode.
 * puship - 0 do not push the object inode(ip) 1 push the ip
 * cr - Ptr to credentials
 *
 * Returns:	0 - Success
 * 		N - From errno.h
 */
static int
ufs_si_store(struct inode *ip, si_t *sp, int puship, cred_t *cr)
{
	struct vfs	*vfsp;
	struct inode	*sip;
	si_t		*oldsp;
	si_t		*csp;
	caddr_t		acldata;
	ino_t		oldshadow;
	size_t		acldatalen;
	off_t		offset;
	int		shadow;
	int		err;
	int		refcnt;
	int		usecnt;
	int		signature;
	int		resid;
	struct ufsvfs	*ufsvfsp	= ip->i_ufsvfs;
	struct fs	*fs		= ufsvfsp->vfs_fs;

	ASSERT(RW_WRITE_HELD(&ip->i_contents));
	ASSERT(ip->i_ufs_acl != sp);

	if (!CHECK_ACL_ALLOWED(ip->i_mode & IFMT))
		return (ENOSYS);

	/*
	 * if there are only the three owner/group/other then do not
	 * create a shadow inode.  If there is already a shadow with
	 * the file, remove it.
	 *
	 */
	if (!sp->ausers &&
	    !sp->agroups &&
	    !sp->downer &&
	    !sp->dgroup &&
	    !sp->dother &&
	    sp->dclass.acl_ismask == 0 &&
	    !sp->dusers &&
	    !sp->dgroups) {
		if (ip->i_ufs_acl)
			err = ufs_si_free(ip->i_ufs_acl, ITOV(ip)->v_vfsp, cr);
		ip->i_ufs_acl = NULL;
		ip->i_shadow = 0;
		ip->i_flag |= IMOD | IACC;
		ip->i_mode = (ip->i_smode & ~0777) |
		    ((sp->aowner->acl_ic_perm & 07) << 6) |
		    (MASK2MODE(sp)) |
		    (sp->aother->acl_ic_perm & 07);
		TRANS_INODE(ip->i_ufsvfs, ip);
		ufs_iupdat(ip, 1);
		ufs_si_free_mem(sp);
		return (0);
	}

loop:

	/*
	 * Check cache. If in cache, use existing shadow inode.
	 * Increment the shadow link count, then attach to the
	 * cached ufs_acl_entry struct, and increment it's reference
	 * count.  Then discard the passed-in ufs_acl_entry and
	 * return.
	 */
	if (si_cachea_get(ip, sp, &csp) == 0) {
		ASSERT(RW_WRITE_HELD(&csp->s_lock));
		if (ip->i_ufs_acl == csp) {
			rw_exit(&csp->s_lock);
			(void) ufs_si_free_mem(sp);
			return (0);
		}
		vfsp = ITOV(ip)->v_vfsp;
		ASSERT(csp->s_shadow <= INT_MAX);
		shadow = (int)csp->s_shadow;
		/*
		 * We can't call ufs_iget while holding the csp locked,
		 * because we might deadlock.  So we drop the
		 * lock on csp, then go search the si_cache again
		 * to see if the csp is still there.
		 */
		rw_exit(&csp->s_lock);
		if ((err = ufs_iget(vfsp, shadow, &sip, cr)) != 0) {
			(void) ufs_si_free_mem(sp);
			return (EIO);
		}
		rw_enter(&sip->i_contents, RW_WRITER);
		if ((sip->i_mode & IFMT) != IFSHAD || sip->i_nlink <= 0) {
			rw_exit(&sip->i_contents);
			VN_RELE(ITOV(sip));
			goto loop;
		}
		/* Get the csp again */
		if (si_cachea_get(ip, sp, &csp) != 0) {
			rw_exit(&sip->i_contents);
			VN_RELE(ITOV(sip));
			goto loop;
		}
		ASSERT(RW_WRITE_HELD(&csp->s_lock));
		/* See if we got the right shadow */
		if (csp->s_shadow != shadow) {
			rw_exit(&csp->s_lock);
			rw_exit(&sip->i_contents);
			VN_RELE(ITOV(sip));
			goto loop;
		}
		ASSERT(RW_WRITE_HELD(&sip->i_contents));
		ASSERT(sip->i_dquot == 0);
		/* Increment link count */
		ASSERT(sip->i_nlink > 0);
		sip->i_nlink++;
		TRANS_INODE(ufsvfsp, sip);
		csp->s_use = sip->i_nlink;
		csp->s_ref++;
		ASSERT(sp->s_ref >= 0 && sp->s_ref <= sp->s_use);
		sip->i_flag |= ICHG | IMOD;
		sip->i_seq++;
		ITIMES_NOLOCK(sip);
		/*
		 * Always release s_lock before both releasing i_contents
		 * and calling VN_RELE.
		 */
		rw_exit(&csp->s_lock);
		rw_exit(&sip->i_contents);
		VN_RELE(ITOV(sip));
		(void) ufs_si_free_mem(sp);
		sp = csp;
		si_cachehit++;
		goto switchshadows;
	}

	/* Alloc a shadow inode and fill it in */
	err = ufs_ialloc(ip, ip->i_number, (mode_t)IFSHAD, &sip, cr);
	if (err) {
		(void) ufs_si_free_mem(sp);
		return (err);
	}
	rw_enter(&sip->i_contents, RW_WRITER);
	sip->i_flag |= IACC | IUPD | ICHG;
	sip->i_seq++;
	sip->i_mode = (o_mode_t)IFSHAD;
	ITOV(sip)->v_type = VREG;
	ufs_reset_vnode(ITOV(sip));
	sip->i_nlink = 1;
	sip->i_uid = crgetuid(cr);
	sip->i_suid = (ulong_t)sip->i_uid > (ulong_t)USHRT_MAX ?
	    UID_LONG : sip->i_uid;
	sip->i_gid = crgetgid(cr);
	sip->i_sgid = (ulong_t)sip->i_gid > (ulong_t)USHRT_MAX ?
	    GID_LONG : sip->i_gid;
	sip->i_shadow = 0;
	TRANS_INODE(ufsvfsp, sip);
	sip->i_ufs_acl = NULL;
	ASSERT(sip->i_size == 0);

	sp->s_shadow = sip->i_number;

	if ((err = ufs_sectobuf(sp, &acldata, &acldatalen)) != 0)
		goto errout;
	offset = 0;

	/*
	 * We don't actually care about the residual count upon failure,
	 * but giving ufs_rdwri() the pointer means it won't translate
	 * all failures to EIO.  Our caller needs to know when ENOSPC
	 * gets hit.
	 */
	resid = 0;
	if (((err = ufs_rdwri(UIO_WRITE, FWRITE|FSYNC, sip, acldata,
	    acldatalen, (offset_t)0, UIO_SYSSPACE, &resid, cr)) != 0) ||
	    (resid != 0)) {
		kmem_free(acldata, acldatalen);
		if ((resid != 0) && (err == 0))
			err = ENOSPC;
		goto errout;
	}

	offset += acldatalen;
	if ((acldatalen + fs->fs_bsize) > ufsvfsp->vfs_maxacl)
		ufsvfsp->vfs_maxacl = acldatalen + fs->fs_bsize;

	kmem_free(acldata, acldatalen);
	/* Sync & free the shadow inode */
	ufs_iupdat(sip, 1);
	rw_exit(&sip->i_contents);
	VN_RELE(ITOV(sip));

	/* We're committed to using this sp */
	sp->s_use = 1;
	sp->s_ref = 1;

	/* Now put the new acl stuff in the cache */
	/* XXX Might make a duplicate */
	si_cache_put(sp);
	si_cachemiss++;

switchshadows:
	/* Now switch the parent inode to use the new shadow inode */
	ASSERT(RW_WRITE_HELD(&ip->i_contents));
	rw_enter(&sp->s_lock, RW_READER);
	oldsp = ip->i_ufs_acl;
	oldshadow = ip->i_shadow;
	ip->i_ufs_acl = sp;
	ASSERT(sp->s_shadow <= INT_MAX);
	ip->i_shadow = (int32_t)sp->s_shadow;
	ASSERT(oldsp != sp);
	ASSERT(oldshadow != ip->i_number);
	ASSERT(ip->i_number != ip->i_shadow);
	/*
	 * Change the mode bits to follow the acl list
	 *
	 * NOTE:	a directory is not required to have a "regular" acl
	 *		bug id's 1238908,  1257173, 1263171 and 1263188
	 *
	 *		but if a "regular" acl is present, it must contain
	 *		an "owner", "group", and "other" acl
	 *
	 *		If an ACL mask exists, the effective group rights are
	 *		set to the mask.  Otherwise, the effective group rights
	 * 		are set to the object group bits.
	 */
	if (sp->aowner) {				/* Owner */
		ip->i_mode &= ~0700;			/* clear Owner */
		ip->i_mode |= (sp->aowner->acl_ic_perm & 07) << 6;
		ip->i_uid = sp->aowner->acl_ic_who;
	}

	if (sp->agroup) {				/* Group */
		ip->i_mode &= ~0070;			/* clear Group */
		ip->i_mode |= MASK2MODE(sp);		/* apply mask */
		ip->i_gid = sp->agroup->acl_ic_who;
	}

	if (sp->aother) {				/* Other */
		ip->i_mode &= ~0007;			/* clear Other */
		ip->i_mode |= (sp->aother->acl_ic_perm & 07);
	}

	if (sp->aclass.acl_ismask)
		ip->i_mode = (ip->i_mode & ~070) |
		    (((sp->aclass.acl_maskbits & 07) << 3) &
		    ip->i_mode);

	TRANS_INODE(ufsvfsp, ip);
	rw_exit(&sp->s_lock);
	ip->i_flag |= ICHG;
	ip->i_seq++;
	/*
	 * when creating a file there is no need to push the inode, it
	 * is pushed later
	 */
	if (puship == 1)
		ufs_iupdat(ip, 1);

	/*
	 * Decrement link count on the old shadow inode,
	 * and decrement reference count on the old aclp,
	 */
	if (oldshadow) {
		/* Get the shadow inode */
		ASSERT(RW_WRITE_HELD(&ip->i_contents));
		vfsp = ITOV(ip)->v_vfsp;
		if ((err = ufs_iget_alloced(vfsp, oldshadow, &sip, cr)) != 0) {
			return (EIO);
		}
		/* Decrement link count */
		rw_enter(&sip->i_contents, RW_WRITER);
		if (oldsp)
			rw_enter(&oldsp->s_lock, RW_WRITER);
		ASSERT(sip->i_dquot == 0);
		ASSERT(sip->i_nlink > 0);
		usecnt = --sip->i_nlink;
		ufs_setreclaim(sip);
		TRANS_INODE(ufsvfsp, sip);
		sip->i_flag |= ICHG | IMOD;
		sip->i_seq++;
		ITIMES_NOLOCK(sip);
		if (oldsp) {
			oldsp->s_use = usecnt;
			refcnt = --oldsp->s_ref;
			signature = oldsp->s_signature;
			/*
			 * Always release s_lock before both releasing
			 * i_contents and calling VN_RELE.
			 */
			rw_exit(&oldsp->s_lock);
		}
		rw_exit(&sip->i_contents);
		VN_RELE(ITOV(sip));
		if (oldsp && (refcnt == 0))
			si_cache_del(oldsp, signature);
	}
	return (0);

errout:
	/* Throw the newly alloc'd inode away */
	sip->i_nlink = 0;
	ufs_setreclaim(sip);
	TRANS_INODE(ufsvfsp, sip);
	ITIMES_NOLOCK(sip);
	rw_exit(&sip->i_contents);
	VN_RELE(ITOV(sip));
	ASSERT(!sp->s_use && !sp->s_ref && !(sp->s_flags & SI_CACHED));
	(void) ufs_si_free_mem(sp);
	return (err);
}

/*
 * Load the acls for inode ip either from disk (adding to the cache),
 * or search the cache and attach the cache'd acl list to the ip.
 * In either case, maintain the proper reference count on the cached entry.
 *
 * Parameters:
 * ip - Ptr to the inode which needs the acl list loaded
 * cr - Ptr to credentials
 *
 * Returns:	0 - Success
 * 		N - From errno.h
 */
int
ufs_si_load(struct inode *ip, cred_t *cr)
/*
 *	ip	parent inode in
 *	cr	credentials in
 */
{
	struct vfs	*vfsp;
	struct inode	*sip;
	ufs_fsd_t	*fsdp;
	si_t		*sp;
	vsecattr_t	vsecattr = {
				(uint_t)0,
				(int)0,
				(void *)NULL,
				(int)0,
				(void *)NULL};
	aclent_t	*aclp;
	ufs_acl_t	*ufsaclp;
	caddr_t		acldata = NULL;
	ino_t		maxino;
	int		err;
	size_t		acldatalen;
	int		numacls;
	int		shadow;
	int		usecnt;
	struct ufsvfs	*ufsvfsp	= ip->i_ufsvfs;
	struct fs	*fs		= ufsvfsp->vfs_fs;

	ASSERT(ip != NULL);
	ASSERT(RW_WRITE_HELD(&ip->i_contents));
	ASSERT(ip->i_shadow && ip->i_ufs_acl == NULL);
	ASSERT((ip->i_mode & IFMT) != IFSHAD);

	if (!CHECK_ACL_ALLOWED(ip->i_mode & IFMT))
		return (ENOSYS);

	if (ip->i_shadow == ip->i_number)
		return (EIO);

	maxino = (ino_t)(ITOF(ip)->fs_ncg * ITOF(ip)->fs_ipg);
	if (ip->i_shadow < UFSROOTINO || ip->i_shadow > maxino)
		return (EIO);

	/*
	 * XXX Check cache.  If in cache, link to it and increment
	 * the reference count, then return.
	 */
	if (si_cachei_get(ip, &sp) == 0) {
		ASSERT(RW_WRITE_HELD(&sp->s_lock));
		ip->i_ufs_acl = sp;
		sp->s_ref++;
		ASSERT(sp->s_ref >= 0 && sp->s_ref <= sp->s_use);
		rw_exit(&sp->s_lock);
		si_cachehit++;
		return (0);
	}

	/* Get the shadow inode */
	vfsp = ITOV(ip)->v_vfsp;
	shadow = ip->i_shadow;
	if ((err = ufs_iget_alloced(vfsp, shadow, &sip, cr)) != 0) {
		return (err);
	}
	rw_enter(&sip->i_contents, RW_WRITER);

	if ((sip->i_mode & IFMT) != IFSHAD) {
		rw_exit(&sip->i_contents);
		err = EINVAL;
		goto alldone;
	}

	ASSERT(sip->i_dquot == 0);
	usecnt = sip->i_nlink;
	if ((!ULOCKFS_IS_NOIACC(&ufsvfsp->vfs_ulockfs)) &&
	    (!(sip)->i_ufsvfs->vfs_noatime)) {
		sip->i_flag |= IACC;
	}
	rw_downgrade(&sip->i_contents);

	ASSERT(sip->i_size <= MAXOFF_T);
	/* Read the acl's and other stuff from disk */
	acldata	 = kmem_zalloc((size_t)sip->i_size, KM_SLEEP);
	acldatalen = sip->i_size;

	err = ufs_rdwri(UIO_READ, FREAD, sip, acldata, acldatalen, (offset_t)0,
	    UIO_SYSSPACE, (int *)0, cr);

	rw_exit(&sip->i_contents);

	if (err)
		goto alldone;

	/*
	 * Convert from disk format
	 * Result is a vsecattr struct which we then convert to the
	 * si struct.
	 */
	bzero((caddr_t)&vsecattr, sizeof (vsecattr_t));
	for (fsdp = (ufs_fsd_t *)acldata;
			fsdp < (ufs_fsd_t *)(acldata + acldatalen);
			fsdp = (ufs_fsd_t *)((caddr_t)fsdp +
				FSD_RECSZ(fsdp, fsdp->fsd_size))) {
		if (fsdp->fsd_size <= 0)
			break;
		switch (fsdp->fsd_type) {
		case FSD_ACL:
			numacls = vsecattr.vsa_aclcnt =
				(int)((fsdp->fsd_size - 2 * sizeof (int)) /
							sizeof (ufs_acl_t));
			aclp = vsecattr.vsa_aclentp =
			kmem_zalloc(numacls * sizeof (aclent_t), KM_SLEEP);
			for (ufsaclp = (ufs_acl_t *)fsdp->fsd_data;
							numacls; ufsaclp++) {
				aclp->a_type = ufsaclp->acl_tag;
				aclp->a_id = ufsaclp->acl_who;
				aclp->a_perm = ufsaclp->acl_perm;
				aclp++;
				numacls--;
			}
			break;
		case FSD_DFACL:
			numacls = vsecattr.vsa_dfaclcnt =
				(int)((fsdp->fsd_size - 2 * sizeof (int)) /
							sizeof (ufs_acl_t));
			aclp = vsecattr.vsa_dfaclentp =
			kmem_zalloc(numacls * sizeof (aclent_t), KM_SLEEP);
			for (ufsaclp = (ufs_acl_t *)fsdp->fsd_data;
							numacls; ufsaclp++) {
				aclp->a_type = ufsaclp->acl_tag;
				aclp->a_id = ufsaclp->acl_who;
				aclp->a_perm = ufsaclp->acl_perm;
				aclp++;
				numacls--;
			}
			break;
		}
	}
	/* Sort the lists */
	if (vsecattr.vsa_aclentp) {
		ksort((caddr_t)vsecattr.vsa_aclentp, vsecattr.vsa_aclcnt,
				sizeof (aclent_t), cmp2acls);
		if ((err = acl_validate(vsecattr.vsa_aclentp,
				vsecattr.vsa_aclcnt, ACL_CHECK)) != 0) {
			goto alldone;
		}
	}
	if (vsecattr.vsa_dfaclentp) {
		ksort((caddr_t)vsecattr.vsa_dfaclentp, vsecattr.vsa_dfaclcnt,
				sizeof (aclent_t), cmp2acls);
		if ((err = acl_validate(vsecattr.vsa_dfaclentp,
				vsecattr.vsa_dfaclcnt, DEF_ACL_CHECK)) != 0) {
			goto alldone;
		}
	}

	/* ignore shadow inodes without ACLs */
	if (!vsecattr.vsa_aclentp && !vsecattr.vsa_dfaclentp) {
		err = 0;
		goto alldone;
	}

	/* Convert from vsecattr struct to ufs_acl_entry struct */
	if ((err = vsecattr2aclentry(&vsecattr, &sp)) != 0) {
		goto alldone;
	}

	/* There aren't filled in by vsecattr2aclentry */
	sp->s_shadow = ip->i_shadow;
	sp->s_dev = ip->i_dev;
	sp->s_use = usecnt;
	sp->s_ref = 1;
	ASSERT(sp->s_ref >= 0 && sp->s_ref <= sp->s_use);

	/* XXX Might make a duplicate */
	si_cache_put(sp);

	/* Signal anyone waiting on this shadow to be loaded */
	ip->i_ufs_acl = sp;
	err = 0;
	si_cachemiss++;
	if ((acldatalen + fs->fs_bsize) > ufsvfsp->vfs_maxacl)
		ufsvfsp->vfs_maxacl = acldatalen + fs->fs_bsize;
alldone:
	/*
	 * Common exit point. Mark shadow inode as ISTALE
	 * if we detect an internal inconsistency, to
	 * prevent stray inodes appearing in the cache.
	 */
	if (err) {
		rw_enter(&sip->i_contents, RW_READER);
		mutex_enter(&sip->i_tlock);
		sip->i_flag |= ISTALE;
		mutex_exit(&sip->i_tlock);
		rw_exit(&sip->i_contents);
	}
	VN_RELE(ITOV(sip));

	/*
	 * Cleanup of data structures allocated
	 * on the fly.
	 */
	if (acldata)
		kmem_free(acldata, acldatalen);

	if (vsecattr.vsa_aclentp)
		kmem_free(vsecattr.vsa_aclentp,
			vsecattr.vsa_aclcnt * sizeof (aclent_t));
	if (vsecattr.vsa_dfaclentp)
		kmem_free(vsecattr.vsa_dfaclentp,
			vsecattr.vsa_dfaclcnt * sizeof (aclent_t));
	return (err);
}

/*
 * Check the inode's ACL's to see if this mode of access is
 * allowed; return 0 if allowed, EACCES if not.
 *
 * We follow the procedure defined in Sec. 3.3.5, ACL Access
 * Check Algorithm, of the POSIX 1003.6 Draft Standard.
 */
int
ufs_acl_access(struct inode *ip, int mode, cred_t *cr)
/*
 *	ip 	parent inode
 *	mode 	mode of access read, write, execute/examine
 *	cr	credentials
 */
{
	ufs_ic_acl_t *acl;
	int ismask, mask = 0;
	int gperm = 0;
	int ngroup = 0;
	si_t	*sp = NULL;
	uid_t uid = crgetuid(cr);
	uid_t owner;

	ASSERT(ip->i_ufs_acl != NULL);
	ASSERT(RW_LOCK_HELD(&ip->i_contents));

	sp = ip->i_ufs_acl;

	ismask = sp->aclass.acl_ismask ?
	    sp->aclass.acl_ismask : NULL;

	if (ismask)
		mask = sp->aclass.acl_maskbits;
	else
		mask = -1;

	/*
	 * (1) If user owns the file, obey user mode bits
	 */
	owner = sp->aowner->acl_ic_who;
	if (uid == owner) {
		return (MODE_CHECK(owner, mode, (sp->aowner->acl_ic_perm << 6),
							    cr, ip));
	}

	/*
	 * (2) Obey any matching ACL_USER entry
	 */
	if (sp->ausers)
		for (acl = sp->ausers; acl != NULL; acl = acl->acl_ic_next) {
			if (acl->acl_ic_who == uid) {
				return (MODE_CHECK(owner, mode,
				    (mask & acl->acl_ic_perm) << 6, cr, ip));
			}
		}

	/*
	 * (3) If user belongs to file's group, obey group mode bits
	 * if no ACL mask is defined; if there is an ACL mask, we look
	 * at both the group mode bits and any ACL_GROUP entries.
	 */
	if (groupmember((uid_t)sp->agroup->acl_ic_who, cr)) {
		ngroup++;
		gperm = (sp->agroup->acl_ic_perm);
		if (!ismask)
			return (MODE_CHECK(owner, mode, (gperm << 6), cr, ip));
	}

	/*
	 * (4) Accumulate the permissions in matching ACL_GROUP entries
	 */
	if (sp->agroups)
		for (acl = sp->agroups; acl != NULL; acl = acl->acl_ic_next)
		{
			if (groupmember(acl->acl_ic_who, cr)) {
				ngroup++;
				gperm |= acl->acl_ic_perm;
			}
		}

	if (ngroup != 0)
		return (MODE_CHECK(owner, mode, ((gperm & mask) << 6), cr, ip));

	/*
	 * (5) Finally, use the "other" mode bits
	 */
	return (MODE_CHECK(owner, mode, sp->aother->acl_ic_perm << 6, cr, ip));
}

/*ARGSUSED2*/
int
ufs_acl_get(struct inode *ip, vsecattr_t *vsap, int flag, cred_t *cr)
{
	aclent_t	*aclentp;

	ASSERT(RW_LOCK_HELD(&ip->i_contents));

	/* XXX Range check, sanity check, shadow check */
	/* If an ACL is present, get the data from the shadow inode info */
	if (ip->i_ufs_acl)
		return (aclentry2vsecattr(ip->i_ufs_acl, vsap));

	/*
	 * If no ACLs are present, fabricate one from the mode bits.
	 * This code is almost identical to fs_fab_acl(), but we
	 * already have the mode bits handy, so we'll avoid going
	 * through VOP_GETATTR() again.
	 */

	vsap->vsa_aclcnt    = 0;
	vsap->vsa_aclentp   = NULL;
	vsap->vsa_dfaclcnt  = 0;	/* Default ACLs are not fabricated */
	vsap->vsa_dfaclentp = NULL;

	if (vsap->vsa_mask & (VSA_ACLCNT | VSA_ACL))
		vsap->vsa_aclcnt    = 4;  /* USER, GROUP, OTHER, and CLASS */

	if (vsap->vsa_mask & VSA_ACL) {
		vsap->vsa_aclentp = kmem_zalloc(4 * sizeof (aclent_t),
		    KM_SLEEP);
		if (vsap->vsa_aclentp == NULL)
			return (ENOMEM);
		aclentp = vsap->vsa_aclentp;

		/* Owner */
		aclentp->a_type = USER_OBJ;
		aclentp->a_perm = ((ushort_t)(ip->i_mode & 0700)) >> 6;
		aclentp->a_id = ip->i_uid;	/* Really undefined */
		aclentp++;

		/* Group */
		aclentp->a_type = GROUP_OBJ;
		aclentp->a_perm = ((ushort_t)(ip->i_mode & 0070)) >> 3;
		aclentp->a_id = ip->i_gid; 	/* Really undefined */
		aclentp++;

		/* Other */
		aclentp->a_type = OTHER_OBJ;
		aclentp->a_perm = ip->i_mode & 0007;
		aclentp->a_id = 0;		/* Really undefined */
		aclentp++;

		/* Class */
		aclentp->a_type = CLASS_OBJ;
		aclentp->a_perm = ((ushort_t)(ip->i_mode & 0070)) >> 3;
		aclentp->a_id = 0;		/* Really undefined */
		ksort((caddr_t)vsap->vsa_aclentp, vsap->vsa_aclcnt,
		    sizeof (aclent_t), cmp2acls);
	}

	return (0);
}

/*ARGSUSED2*/
int
ufs_acl_set(struct inode *ip, vsecattr_t *vsap, int flag, cred_t *cr)
{
	si_t	*sp;
	int	err;

	ASSERT(RW_WRITE_HELD(&ip->i_contents));

	if (!CHECK_ACL_ALLOWED(ip->i_mode & IFMT))
		return (ENOSYS);

	/*
	 * only the owner of the file or privileged users can change the ACLs
	 */
	if (secpolicy_vnode_setdac(cr, ip->i_uid) != 0)
		return (EPERM);

	/* Convert from vsecattr struct to ufs_acl_entry struct */
	if ((err = vsecattr2aclentry(vsap, &sp)) != 0)
		return (err);
	sp->s_dev = ip->i_dev;

	/*
	 * Make the user & group objs in the acl list follow what's
	 * in the inode.
	 */
#ifdef DEBUG
	if (vsap->vsa_mask == VSA_ACL) {
		ASSERT(sp->aowner);
		ASSERT(sp->agroup);
		ASSERT(sp->aother);
	}
#endif	/* DEBUG */

	if (sp->aowner)
		sp->aowner->acl_ic_who = ip->i_uid;
	if (sp->agroup)
		sp->agroup->acl_ic_who = ip->i_gid;

	/*
	 * Write and cache the new acl list
	 */
	err = ufs_si_store(ip, sp, 1, cr);

	return (err);
}

/*
 * XXX Scan sorted array of acl's, checking for:
 * 1) Any duplicate/conflicting entries (same type and id)
 * 2) More than 1 of USER_OBJ, GROUP_OBJ, OTHER_OBJ, CLASS_OBJ
 * 3) More than 1 of DEF_USER_OBJ, DEF_GROUP_OBJ, DEF_OTHER_OBJ, DEF_CLASS_OBJ
 *
 * Parameters:
 * aclentp - ptr to sorted list of acl entries.
 * nentries - # acl entries on the list
 * flag - Bitmap (ACL_CHECK and/or DEF_ACL_CHECK) indicating whether the
 * list contains regular acls, default acls, or both.
 *
 * Returns:	0 - Success
 * EINVAL - Invalid list (dups or multiple entries of type USER_OBJ, etc)
 */
static int
acl_validate(aclent_t *aclentp, int nentries, int flag)
{
	int	i;
	int	nuser_objs = 0;
	int	ngroup_objs = 0;
	int	nother_objs = 0;
	int	nclass_objs = 0;
	int	ndef_user_objs = 0;
	int	ndef_group_objs = 0;
	int	ndef_other_objs = 0;
	int	ndef_class_objs = 0;
	int	nusers = 0;
	int	ngroups = 0;
	int	ndef_users = 0;
	int	ndef_groups = 0;
	int	numdefs = 0;

	/* Null list or list of one */
	if (aclentp == NULL)
		return (0);

	if (nentries <= 0)
		return (EINVAL);

	for (i = 1; i < nentries; i++) {
		if (((aclentp[i - 1].a_type == aclentp[i].a_type) &&
		    (aclentp[i - 1].a_id   == aclentp[i].a_id)) ||
		    (aclentp[i - 1].a_perm > 07)) {
			return (EINVAL);
		}
	}

	if (flag == 0 || (flag != ACL_CHECK && flag != DEF_ACL_CHECK))
		return (EINVAL);

	/* Count types */
	for (i = 0; i < nentries; i++) {
		switch (aclentp[i].a_type) {
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
		default:		/* Unknown type */
			return (EINVAL);
		}
	}

	/*
	 * For normal acl's, we require there be one (and only one)
	 * USER_OBJ, GROUP_OBJ and OTHER_OBJ.  There is either zero
	 * or one CLASS_OBJ.
	 */
	if (flag & ACL_CHECK) {
		if (nuser_objs != 1 || ngroup_objs != 1 ||
		    nother_objs != 1 || nclass_objs > 1) {
			return (EINVAL);
		}
		/*
		 * If there are ANY group acls, there MUST be a
		 * class_obj(mask) acl (1003.6/D12 p. 29 lines 75-80).
		 */
		if (ngroups && !nclass_objs) {
			return (EINVAL);
		}
		if (nuser_objs + ngroup_objs + nother_objs + nclass_objs +
		    ngroups + nusers > MAX_ACL_ENTRIES)
			return (EINVAL);
	}

	/*
	 * For default acl's, we require that there be either one (and only one)
	 * DEF_USER_OBJ, DEF_GROUP_OBJ and DEF_OTHER_OBJ
	 * or  there be none of them.
	 */
	if (flag & DEF_ACL_CHECK) {
		if (ndef_other_objs > 1 || ndef_user_objs > 1 ||
		    ndef_group_objs > 1 || ndef_class_objs > 1) {
			return (EINVAL);
		}

		numdefs = ndef_other_objs + ndef_user_objs + ndef_group_objs;

		if (numdefs != 0 && numdefs != 3) {
			return (EINVAL);
		}
		/*
		 * If there are ANY def_group acls, there MUST be a
		 * def_class_obj(mask) acl (1003.6/D12 P. 29 lines 75-80).
		 * XXX(jimh) This is inferred.
		 */
		if (ndef_groups && !ndef_class_objs) {
			return (EINVAL);
		}
		if ((ndef_users || ndef_groups) &&
		    ((numdefs != 3) && !ndef_class_objs)) {
			return (EINVAL);
		}
		if (ndef_user_objs + ndef_group_objs + ndef_other_objs +
		    ndef_class_objs + ndef_users + ndef_groups >
		    MAX_ACL_ENTRIES)
			return (EINVAL);
	}
	return (0);
}

static int
formacl(ufs_ic_acl_t **aclpp, aclent_t *aclentp)
{
	ufs_ic_acl_t *uaclp;

	uaclp = kmem_alloc(sizeof (ufs_ic_acl_t), KM_SLEEP);
	uaclp->acl_ic_perm = aclentp->a_perm;
	uaclp->acl_ic_who = aclentp->a_id;
	uaclp->acl_ic_next = *aclpp;
	*aclpp = uaclp;
	return (0);
}

/*
 * XXX - Make more efficient
 * Convert from the vsecattr struct, used by the VOP interface, to
 * the ufs_acl_entry struct used for in-core storage of acl's.
 *
 * Parameters:
 * vsap - Ptr to array of security attributes.
 * spp - Ptr to ptr to si struct for the results
 *
 * Returns:	0 - Success
 * 		N - From errno.h
 */
static int
vsecattr2aclentry(vsecattr_t *vsap, si_t **spp)
{
	aclent_t	*aclentp, *aclp;
	si_t		*sp;
	int		err;
	int		i;

	/* Sort & validate the lists on the vsap */
	ksort((caddr_t)vsap->vsa_aclentp, vsap->vsa_aclcnt,
	    sizeof (aclent_t), cmp2acls);
	ksort((caddr_t)vsap->vsa_dfaclentp, vsap->vsa_dfaclcnt,
	    sizeof (aclent_t), cmp2acls);
	if ((err = acl_validate(vsap->vsa_aclentp,
	    vsap->vsa_aclcnt, ACL_CHECK)) != 0)
		return (err);
	if ((err = acl_validate(vsap->vsa_dfaclentp,
	    vsap->vsa_dfaclcnt, DEF_ACL_CHECK)) != 0)
		return (err);

	/* Create new si struct and hang acl's off it */
	sp = kmem_zalloc(sizeof (si_t), KM_SLEEP);
	rw_init(&sp->s_lock, NULL, RW_DEFAULT, NULL);

	/* Process acl list */
	aclp = (aclent_t *)vsap->vsa_aclentp;
	aclentp = aclp + vsap->vsa_aclcnt - 1;
	for (i = 0; i < vsap->vsa_aclcnt; i++) {
		switch (aclentp->a_type) {
		case USER_OBJ:		/* Owner */
			if (err = formacl(&sp->aowner, aclentp))
				goto error;
			break;
		case GROUP_OBJ:		/* Group */
			if (err = formacl(&sp->agroup, aclentp))
				goto error;
			break;
		case OTHER_OBJ:		/* Other */
			if (err = formacl(&sp->aother, aclentp))
				goto error;
			break;
		case USER:
			if (err = formacl(&sp->ausers, aclentp))
				goto error;
			break;
		case CLASS_OBJ:		/* Mask */
			sp->aclass.acl_ismask = 1;
			sp->aclass.acl_maskbits = aclentp->a_perm;
			break;
		case GROUP:
			if (err = formacl(&sp->agroups, aclentp))
				goto error;
			break;
		default:
			break;
		}
		aclentp--;
	}

	/* Process default acl list */
	aclp = (aclent_t *)vsap->vsa_dfaclentp;
	aclentp = aclp + vsap->vsa_dfaclcnt - 1;
	for (i = 0; i < vsap->vsa_dfaclcnt; i++) {
		switch (aclentp->a_type) {
		case DEF_USER_OBJ:	/* Default Owner */
			if (err = formacl(&sp->downer, aclentp))
				goto error;
			break;
		case DEF_GROUP_OBJ:	/* Default Group */
			if (err = formacl(&sp->dgroup, aclentp))
				goto error;
			break;
		case DEF_OTHER_OBJ:	/* Default Other */
			if (err = formacl(&sp->dother, aclentp))
				goto error;
			break;
		case DEF_USER:
			if (err = formacl(&sp->dusers, aclentp))
				goto error;
			break;
		case DEF_CLASS_OBJ:	/* Default Mask */
			sp->dclass.acl_ismask = 1;
			sp->dclass.acl_maskbits = aclentp->a_perm;
			break;
		case DEF_GROUP:
			if (err = formacl(&sp->dgroups, aclentp))
				goto error;
			break;
		default:
			break;
		}
		aclentp--;
	}
	*spp = sp;
	return (0);

error:
	ufs_si_free_mem(sp);
	return (err);
}

void
formvsec(int obj_type, ufs_ic_acl_t *aclp, aclent_t **aclentpp)
{
	for (; aclp; aclp = aclp->acl_ic_next) {
		(*aclentpp)->a_type = obj_type;
		(*aclentpp)->a_perm = aclp->acl_ic_perm;
		(*aclentpp)->a_id = aclp->acl_ic_who;
		(*aclentpp)++;
	}
}

/*
 * XXX - Make more efficient
 * Convert from the ufs_acl_entry struct used for in-core storage of acl's
 * to the vsecattr struct,  used by the VOP interface.
 *
 * Parameters:
 * sp - Ptr to si struct with the acls
 * vsap - Ptr to a vsecattr struct which will take the results.
 *
 * Returns:	0 - Success
 *		N - From errno table
 */
static int
aclentry2vsecattr(si_t *sp, vsecattr_t *vsap)
{
	aclent_t	*aclentp;
	int		numacls = 0;
	int		err;

	vsap->vsa_aclentp = vsap->vsa_dfaclentp = NULL;

	numacls = acl_count(sp->aowner) +
	    acl_count(sp->agroup) +
	    acl_count(sp->aother) +
	    acl_count(sp->ausers) +
	    acl_count(sp->agroups);
	if (sp->aclass.acl_ismask)
		numacls++;

	if (vsap->vsa_mask & (VSA_ACLCNT | VSA_ACL))
		vsap->vsa_aclcnt = numacls;

	if (numacls == 0)
		goto do_defaults;

	if (vsap->vsa_mask & VSA_ACL) {
		vsap->vsa_aclentp = kmem_zalloc(numacls * sizeof (aclent_t),
		    KM_SLEEP);
		aclentp = vsap->vsa_aclentp;

		formvsec(USER_OBJ, sp->aowner, &aclentp);
		formvsec(USER, sp->ausers, &aclentp);
		formvsec(GROUP_OBJ, sp->agroup, &aclentp);
		formvsec(GROUP, sp->agroups, &aclentp);
		formvsec(OTHER_OBJ, sp->aother, &aclentp);

		if (sp->aclass.acl_ismask) {
			aclentp->a_type = CLASS_OBJ;		/* Mask */
			aclentp->a_perm = sp->aclass.acl_maskbits;
			aclentp->a_id = 0;
			aclentp++;
		}

		/* Sort the acl list */
		ksort((caddr_t)vsap->vsa_aclentp, vsap->vsa_aclcnt,
		    sizeof (aclent_t), cmp2acls);
		/* Check the acl list */
		if ((err = acl_validate(vsap->vsa_aclentp,
		    vsap->vsa_aclcnt, ACL_CHECK)) != 0) {
			kmem_free(vsap->vsa_aclentp,
			    numacls * sizeof (aclent_t));
			vsap->vsa_aclentp = NULL;
			return (err);
		}

	}
do_defaults:
	/* Process Defaults */

	numacls = acl_count(sp->downer) +
	    acl_count(sp->dgroup) +
	    acl_count(sp->dother) +
	    acl_count(sp->dusers) +
	    acl_count(sp->dgroups);
	if (sp->dclass.acl_ismask)
		numacls++;

	if (vsap->vsa_mask & (VSA_DFACLCNT | VSA_DFACL))
		vsap->vsa_dfaclcnt = numacls;

	if (numacls == 0)
		goto do_others;

	if (vsap->vsa_mask & VSA_DFACL) {
		vsap->vsa_dfaclentp =
		    kmem_zalloc(numacls * sizeof (aclent_t), KM_SLEEP);
		aclentp = vsap->vsa_dfaclentp;
		formvsec(DEF_USER_OBJ, sp->downer, &aclentp);
		formvsec(DEF_USER, sp->dusers, &aclentp);
		formvsec(DEF_GROUP_OBJ, sp->dgroup, &aclentp);
		formvsec(DEF_GROUP, sp->dgroups, &aclentp);
		formvsec(DEF_OTHER_OBJ, sp->dother, &aclentp);

		if (sp->dclass.acl_ismask) {
			aclentp->a_type = DEF_CLASS_OBJ;	/* Mask */
			aclentp->a_perm = sp->dclass.acl_maskbits;
			aclentp->a_id = 0;
			aclentp++;
		}

		/* Sort the default acl list */
		ksort((caddr_t)vsap->vsa_dfaclentp, vsap->vsa_dfaclcnt,
		    sizeof (aclent_t), cmp2acls);
		if ((err = acl_validate(vsap->vsa_dfaclentp,
		    vsap->vsa_dfaclcnt, DEF_ACL_CHECK)) != 0) {
			if (vsap->vsa_aclentp != NULL)
				kmem_free(vsap->vsa_aclentp,
				    vsap->vsa_aclcnt * sizeof (aclent_t));
			kmem_free(vsap->vsa_dfaclentp,
			    vsap->vsa_dfaclcnt * sizeof (aclent_t));
			vsap->vsa_aclentp = vsap->vsa_dfaclentp = NULL;
			return (err);
		}
	}

do_others:
	return (0);
}

static void
acl_free(ufs_ic_acl_t *aclp)
{
	while (aclp != NULL) {
		ufs_ic_acl_t *nextaclp = aclp->acl_ic_next;
		kmem_free(aclp, sizeof (ufs_ic_acl_t));
		aclp = nextaclp;
	}
}

/*
 * ufs_si_free_mem will discard the sp, and the acl hanging off of the
 * sp.  It is required that the sp not be locked, and not be in the
 * cache.
 *
 * input: pointer to sp to discard.
 *
 * return - nothing.
 *
 */
static void
ufs_si_free_mem(si_t *sp)
{
	ASSERT(!(sp->s_flags & SI_CACHED));
	ASSERT(!RW_LOCK_HELD(&sp->s_lock));
	/*
	 *	remove from the cache
	 *	free the acl entries
	 */
	acl_free(sp->aowner);
	acl_free(sp->agroup);
	acl_free(sp->aother);
	acl_free(sp->ausers);
	acl_free(sp->agroups);

	acl_free(sp->downer);
	acl_free(sp->dgroup);
	acl_free(sp->dother);
	acl_free(sp->dusers);
	acl_free(sp->dgroups);

	rw_destroy(&sp->s_lock);
	kmem_free(sp, sizeof (si_t));
}

void
acl_cpy(ufs_ic_acl_t *saclp, ufs_ic_acl_t *daclp)
{
	ufs_ic_acl_t  *aclp, *prev_aclp = NULL, *aclp1;

	if (saclp == NULL) {
		daclp = NULL;
		return;
	}
	prev_aclp = daclp;

	for (aclp = saclp; aclp != NULL; aclp = aclp->acl_ic_next) {
		aclp1 = kmem_alloc(sizeof (ufs_ic_acl_t), KM_SLEEP);
		aclp1->acl_ic_next = NULL;
		aclp1->acl_ic_who = aclp->acl_ic_who;
		aclp1->acl_ic_perm = aclp->acl_ic_perm;
		prev_aclp->acl_ic_next = aclp1;
		prev_aclp = (ufs_ic_acl_t *)&aclp1->acl_ic_next;
	}
}

/*
 *	ufs_si_inherit takes a parent acl structure (saclp) and the inode
 *	of the object that is inheriting an acl and returns the inode
 *	with the acl linked to it.  It also writes the acl to disk if
 *	it is a unique inode.
 *
 *	ip - pointer to inode of object inheriting the acl (contents lock)
 *	tdp - parent inode (rw_lock and contents lock)
 *	mode - creation modes
 *	cr - credentials pointer
 */
int
ufs_si_inherit(struct inode *ip, struct inode *tdp, o_mode_t mode, cred_t *cr)
{
	si_t *tsp, *sp = tdp->i_ufs_acl;
	int error;
	o_mode_t old_modes, old_uid, old_gid;
	int mask;

	ASSERT(RW_WRITE_HELD(&ip->i_contents));
	ASSERT(RW_WRITE_HELD(&tdp->i_rwlock));
	ASSERT(RW_WRITE_HELD(&tdp->i_contents));

	/*
	 * if links/symbolic links, or other invalid acl objects are copied
	 * or moved to a directory with a default acl do not allow inheritance
	 * just return.
	 */
	if (!CHECK_ACL_ALLOWED(ip->i_mode & IFMT))
		return (0);

	/* lock the parent security information */
	rw_enter(&sp->s_lock, RW_READER);

	ASSERT(((tdp->i_mode & IFMT) == IFDIR) ||
	    ((tdp->i_mode & IFMT) == IFATTRDIR));

	mask = ((sp->downer != NULL) ? 1 : 0) |
	    ((sp->dgroup != NULL) ? 2 : 0) |
	    ((sp->dother != NULL) ? 4 : 0);

	if (mask == 0) {
		rw_exit(&sp->s_lock);
		return (0);
	}

	if (mask != 7) {
		rw_exit(&sp->s_lock);
		return (EINVAL);
	}

	tsp = kmem_zalloc(sizeof (si_t), KM_SLEEP);
	rw_init(&tsp->s_lock, NULL, RW_DEFAULT, NULL);

	/* copy the default acls */

	ASSERT(RW_READ_HELD(&sp->s_lock));
	acl_cpy(sp->downer, (ufs_ic_acl_t *)&tsp->aowner);
	acl_cpy(sp->dgroup, (ufs_ic_acl_t *)&tsp->agroup);
	acl_cpy(sp->dother, (ufs_ic_acl_t *)&tsp->aother);
	acl_cpy(sp->dusers, (ufs_ic_acl_t *)&tsp->ausers);
	acl_cpy(sp->dgroups, (ufs_ic_acl_t *)&tsp->agroups);
	tsp->aclass.acl_ismask = sp->dclass.acl_ismask;
	tsp->aclass.acl_maskbits = sp->dclass.acl_maskbits;

	/*
	 * set the owner, group, and other values from the master
	 * inode.
	 */

	MODE2ACL(tsp->aowner, (mode >> 6), ip->i_uid);
	MODE2ACL(tsp->agroup, (mode >> 3), ip->i_gid);
	MODE2ACL(tsp->aother, (mode), 0);

	if (tsp->aclass.acl_ismask) {
		tsp->aclass.acl_maskbits &= mode >> 3;
	}


	/* copy default acl if necessary */

	if (((ip->i_mode & IFMT) == IFDIR) ||
	    ((ip->i_mode & IFMT) == IFATTRDIR)) {
		acl_cpy(sp->downer, (ufs_ic_acl_t *)&tsp->downer);
		acl_cpy(sp->dgroup, (ufs_ic_acl_t *)&tsp->dgroup);
		acl_cpy(sp->dother, (ufs_ic_acl_t *)&tsp->dother);
		acl_cpy(sp->dusers, (ufs_ic_acl_t *)&tsp->dusers);
		acl_cpy(sp->dgroups, (ufs_ic_acl_t *)&tsp->dgroups);
		tsp->dclass.acl_ismask = sp->dclass.acl_ismask;
		tsp->dclass.acl_maskbits = sp->dclass.acl_maskbits;
	}
	/*
	 * save the new 9 mode bits in the inode (ip->ic_smode) for
	 * ufs_getattr.  Be sure the mode can be recovered if the store
	 * fails.
	 */
	old_modes = ip->i_mode;
	old_uid = ip->i_uid;
	old_gid = ip->i_gid;
	/*
	 * store the acl, and get back a new security anchor if
	 * it is a duplicate.
	 */
	rw_exit(&sp->s_lock);
	rw_enter(&ip->i_rwlock, RW_WRITER);

	/*
	 * Suppress out of inodes messages if instructed in the
	 * tdp inode.
	 */
	ip->i_flag |= tdp->i_flag & IQUIET;

	if ((error = ufs_si_store(ip, tsp, 0, cr)) != 0) {
		ip->i_mode = old_modes;
		ip->i_uid = old_uid;
		ip->i_gid = old_gid;
	}
	ip->i_flag &= ~IQUIET;
	rw_exit(&ip->i_rwlock);
	return (error);
}

si_t *
ufs_acl_cp(si_t *sp)
{

	si_t *dsp;

	ASSERT(RW_READ_HELD(&sp->s_lock));
	ASSERT(sp->s_ref && sp->s_use);

	dsp = kmem_zalloc(sizeof (si_t), KM_SLEEP);
	rw_init(&dsp->s_lock, NULL, RW_DEFAULT, NULL);

	acl_cpy(sp->aowner, (ufs_ic_acl_t *)&dsp->aowner);
	acl_cpy(sp->agroup, (ufs_ic_acl_t *)&dsp->agroup);
	acl_cpy(sp->aother, (ufs_ic_acl_t *)&dsp->aother);
	acl_cpy(sp->ausers, (ufs_ic_acl_t *)&dsp->ausers);
	acl_cpy(sp->agroups, (ufs_ic_acl_t *)&dsp->agroups);

	dsp->aclass.acl_ismask = sp->aclass.acl_ismask;
	dsp->aclass.acl_maskbits = sp->aclass.acl_maskbits;

	acl_cpy(sp->downer, (ufs_ic_acl_t *)&dsp->downer);
	acl_cpy(sp->dgroup, (ufs_ic_acl_t *)&dsp->dgroup);
	acl_cpy(sp->dother, (ufs_ic_acl_t *)&dsp->dother);
	acl_cpy(sp->dusers, (ufs_ic_acl_t *)&dsp->dusers);
	acl_cpy(sp->dgroups, (ufs_ic_acl_t *)&dsp->dgroups);

	dsp->dclass.acl_ismask = sp->dclass.acl_ismask;
	dsp->dclass.acl_maskbits = sp->dclass.acl_maskbits;

	return (dsp);

}

int
ufs_acl_setattr(struct inode *ip, struct vattr *vap, cred_t *cr)
{

	si_t *sp;
	int mask = vap->va_mask;
	int error = 0;

	ASSERT(RW_WRITE_HELD(&ip->i_contents));

	if (!(mask & (AT_MODE|AT_UID|AT_GID)))
		return (0);

	/*
	 * if no regular acl's, nothing to do, so let's get out
	 */
	if (!(ip->i_ufs_acl) || !(ip->i_ufs_acl->aowner))
		return (0);

	rw_enter(&ip->i_ufs_acl->s_lock, RW_READER);
	sp = ufs_acl_cp(ip->i_ufs_acl);
	ASSERT(sp != ip->i_ufs_acl);

	/*
	 * set the mask to the group permissions if a mask entry
	 * exists.  Otherwise, set the group obj bits to the group
	 * permissions.  Since non-trivial ACLs always have a mask,
	 * and the mask is the final arbiter of group permissions,
	 * setting the mask has the effect of changing the effective
	 * group permissions, even if the group_obj permissions in
	 * the ACL aren't changed.  Posix P1003.1e states that when
	 * an ACL mask exists, chmod(2) must set the acl mask (NOT the
	 * group_obj permissions) to the requested group permissions.
	 */
	if (mask & AT_MODE) {
		sp->aowner->acl_ic_perm = (o_mode_t)(ip->i_mode & 0700) >> 6;
		if (sp->aclass.acl_ismask)
			sp->aclass.acl_maskbits =
			    (o_mode_t)(ip->i_mode & 070) >> 3;
		else
			sp->agroup->acl_ic_perm =
			    (o_mode_t)(ip->i_mode & 070) >> 3;
		sp->aother->acl_ic_perm = (o_mode_t)(ip->i_mode & 07);
	}

	if (mask & AT_UID) {
		/* Caller has verified our privileges */
		sp->aowner->acl_ic_who = ip->i_uid;
	}

	if (mask & AT_GID) {
		sp->agroup->acl_ic_who = ip->i_gid;
	}

	rw_exit(&ip->i_ufs_acl->s_lock);
	error = ufs_si_store(ip, sp, 0, cr);
	return (error);
}

static int
acl_count(ufs_ic_acl_t *p)
{
	ufs_ic_acl_t	*acl;
	int		count;

	for (count = 0, acl = p; acl; acl = acl->acl_ic_next, count++)
		;
	return (count);
}

/*
 *	Takes as input a security structure and generates a buffer
 *	with fsd's in a form which be written to the shadow inode.
 */
static int
ufs_sectobuf(si_t *sp, caddr_t *buf, size_t *len)
{
	size_t		acl_size;
	size_t		def_acl_size;
	caddr_t		buffer;
	struct ufs_fsd	*fsdp;
	ufs_acl_t	*bufaclp;

	/*
	 * Calc size of buffer to hold all the acls
	 */
	acl_size = acl_count(sp->aowner) +		/* owner */
	    acl_count(sp->agroup) +			/* owner group */
	    acl_count(sp->aother) +			/* owner other */
	    acl_count(sp->ausers) +			/* acl list */
	    acl_count(sp->agroups);			/* group alcs */
	if (sp->aclass.acl_ismask)
		acl_size++;

	/* Convert to bytes */
	acl_size *= sizeof (ufs_acl_t);

	/* Add fsd header */
	if (acl_size)
		acl_size += 2 * sizeof (int);

	/*
	 * Calc size of buffer to hold all the default acls
	 */
	def_acl_size =
	    acl_count(sp->downer) +	/* def owner */
	    acl_count(sp->dgroup) +	/* def owner group */
	    acl_count(sp->dother) +	/* def owner other */
	    acl_count(sp->dusers) +	/* def users  */
	    acl_count(sp->dgroups);	/* def group acls */
	if (sp->dclass.acl_ismask)
		def_acl_size++;

	/*
	 * Convert to bytes
	 */
	def_acl_size *= sizeof (ufs_acl_t);

	/*
	 * Add fsd header
	 */
	if (def_acl_size)
		def_acl_size += 2 * sizeof (int);

	if (acl_size + def_acl_size == 0)
		return (0);

	buffer = kmem_zalloc((acl_size + def_acl_size), KM_SLEEP);
	bufaclp = (ufs_acl_t *)buffer;

	if (acl_size == 0)
		goto wrtdefs;

	/* create fsd and copy acls */
	fsdp = (struct ufs_fsd *)bufaclp;
	fsdp->fsd_type = FSD_ACL;
	bufaclp = (ufs_acl_t *)&fsdp->fsd_data[0];

	ACL_MOVE(sp->aowner, USER_OBJ, bufaclp);
	ACL_MOVE(sp->agroup, GROUP_OBJ, bufaclp);
	ACL_MOVE(sp->aother, OTHER_OBJ, bufaclp);
	ACL_MOVE(sp->ausers, USER, bufaclp);
	ACL_MOVE(sp->agroups, GROUP, bufaclp);

	if (sp->aclass.acl_ismask) {
		bufaclp->acl_tag = CLASS_OBJ;
		bufaclp->acl_who = (uid_t)sp->aclass.acl_ismask;
		bufaclp->acl_perm = (o_mode_t)sp->aclass.acl_maskbits;
		bufaclp++;
	}
	ASSERT(acl_size <= INT_MAX);
	fsdp->fsd_size = (int)acl_size;

wrtdefs:
	if (def_acl_size == 0)
		goto alldone;

	/* if defaults exist then create fsd and copy default acls */
	fsdp = (struct ufs_fsd *)bufaclp;
	fsdp->fsd_type = FSD_DFACL;
	bufaclp = (ufs_acl_t *)&fsdp->fsd_data[0];

	ACL_MOVE(sp->downer, DEF_USER_OBJ, bufaclp);
	ACL_MOVE(sp->dgroup, DEF_GROUP_OBJ, bufaclp);
	ACL_MOVE(sp->dother, DEF_OTHER_OBJ, bufaclp);
	ACL_MOVE(sp->dusers, DEF_USER, bufaclp);
	ACL_MOVE(sp->dgroups, DEF_GROUP, bufaclp);
	if (sp->dclass.acl_ismask) {
		bufaclp->acl_tag = DEF_CLASS_OBJ;
		bufaclp->acl_who = (uid_t)sp->dclass.acl_ismask;
		bufaclp->acl_perm = (o_mode_t)sp->dclass.acl_maskbits;
		bufaclp++;
	}
	ASSERT(def_acl_size <= INT_MAX);
	fsdp->fsd_size = (int)def_acl_size;

alldone:
	*buf = buffer;
	*len = acl_size + def_acl_size;

	return (0);
}

/*
 *  free a shadow inode  on disk and in memory
 */
int
ufs_si_free(si_t *sp, struct vfs *vfsp, cred_t *cr)
{
	struct inode 	*sip;
	int 		shadow;
	int 		err = 0;
	int		refcnt;
	int		signature;

	ASSERT(vfsp);
	ASSERT(sp);

	rw_enter(&sp->s_lock, RW_READER);
	ASSERT(sp->s_shadow <= INT_MAX);
	shadow = (int)sp->s_shadow;
	ASSERT(sp->s_ref);
	rw_exit(&sp->s_lock);

	/*
	 * Decrement link count on the shadow inode,
	 * and decrement reference count on the sip.
	 */
	if ((err = ufs_iget_alloced(vfsp, shadow, &sip, cr)) == 0) {
		rw_enter(&sip->i_contents, RW_WRITER);
		rw_enter(&sp->s_lock, RW_WRITER);
		ASSERT(sp->s_shadow == shadow);
		ASSERT(sip->i_dquot == 0);
		/* Decrement link count */
		ASSERT(sip->i_nlink > 0);
		/*
		 * bug #1264710 assertion failure below
		 */
		sp->s_use = --sip->i_nlink;
		ufs_setreclaim(sip);
		TRANS_INODE(sip->i_ufsvfs, sip);
		sip->i_flag |= ICHG | IMOD;
		sip->i_seq++;
		ITIMES_NOLOCK(sip);
		/* Dec ref counts on si referenced by this ip */
		refcnt = --sp->s_ref;
		signature = sp->s_signature;
		ASSERT(sp->s_ref >= 0 && sp->s_ref <= sp->s_use);
		/*
		 * Release s_lock before calling VN_RELE
		 * (which may want to acquire i_contents).
		 */
		rw_exit(&sp->s_lock);
		rw_exit(&sip->i_contents);
		VN_RELE(ITOV(sip));
	} else {
		rw_enter(&sp->s_lock, RW_WRITER);
		/* Dec ref counts on si referenced by this ip */
		refcnt = --sp->s_ref;
		signature = sp->s_signature;
		ASSERT(sp->s_ref >= 0 && sp->s_ref <= sp->s_use);
		rw_exit(&sp->s_lock);
	}

	if (refcnt == 0)
		si_cache_del(sp, signature);
	return (err);
}

/*
 * Seach the si cache for an si structure by inode #.
 * Returns a locked si structure.
 *
 * Parameters:
 * ip - Ptr to an inode on this fs
 * spp - Ptr to ptr to si struct for the results, if found.
 *
 * Returns:	0 - Success (results in spp)
 *		1 - Failure (spp undefined)
 */
static int
si_cachei_get(struct inode *ip, si_t **spp)
{
	si_t	*sp;

	rw_enter(&si_cache_lock, RW_READER);
loop:
	for (sp = si_cachei[SI_HASH(ip->i_shadow)]; sp; sp = sp->s_forw)
		if (sp->s_shadow == ip->i_shadow && sp->s_dev == ip->i_dev)
			break;

	if (sp == NULL) {
		/* Not in cache */
		rw_exit(&si_cache_lock);
		return (1);
	}
	/* Found it */
	rw_enter(&sp->s_lock, RW_WRITER);
alldone:
	rw_exit(&si_cache_lock);
	*spp = sp;
	return (0);
}

/*
 * Seach the si cache by si structure (ie duplicate of the one passed in).
 * In order for a match the signatures must be the same and
 * the devices must be the same, the acls must match and
 * link count of the cached shadow must be less than the
 * size of ic_nlink - 1.  MAXLINK - 1 is used to allow the count
 * to be incremented one more time by the caller.
 * Returns a locked si structure.
 *
 * Parameters:
 * ip - Ptr to an inode on this fs
 * spi - Ptr to si the struct we're searching the cache for.
 * spp - Ptr to ptr to si struct for the results, if found.
 *
 * Returns:	0 - Success (results in spp)
 *		1 - Failure (spp undefined)
 */
static int
si_cachea_get(struct inode *ip, si_t *spi, si_t **spp)
{
	si_t	*sp;

	spi->s_dev = ip->i_dev;
	spi->s_signature = si_signature(spi);
	rw_enter(&si_cache_lock, RW_READER);
loop:
	for (sp = si_cachea[SI_HASH(spi->s_signature)]; sp; sp = sp->s_next) {
		if (sp->s_signature == spi->s_signature &&
		    sp->s_dev == spi->s_dev &&
		    sp->s_use > 0 &&			/* deleting */
		    sp->s_use <= (MAXLINK - 1) &&	/* Too many links */
		    !si_cmp(sp, spi))
			break;
	}

	if (sp == NULL) {
		/* Cache miss */
		rw_exit(&si_cache_lock);
		return (1);
	}
	/* Found it */
	rw_enter(&sp->s_lock, RW_WRITER);
alldone:
	spi->s_shadow = sp->s_shadow; /* XXX For debugging */
	rw_exit(&si_cache_lock);
	*spp = sp;
	return (0);
}

/*
 * Place an si structure in the si cache.  May cause duplicates.
 *
 * Parameters:
 * sp - Ptr to the si struct to add to the cache.
 *
 * Returns: Nothing (void)
 */
static void
si_cache_put(si_t *sp)
{
	si_t	**tspp;

	ASSERT(sp->s_fore == NULL);
	rw_enter(&si_cache_lock, RW_WRITER);
	if (!sp->s_signature)
		sp->s_signature = si_signature(sp);
	sp->s_flags |= SI_CACHED;
	sp->s_fore = NULL;

	/* The 'by acl' chains */
	tspp = &si_cachea[SI_HASH(sp->s_signature)];
	sp->s_next = *tspp;
	*tspp = sp;

	/* The 'by inode' chains */
	tspp = &si_cachei[SI_HASH(sp->s_shadow)];
	sp->s_forw = *tspp;
	*tspp = sp;

	rw_exit(&si_cache_lock);
}

/*
 * The sp passed in is a candidate for deletion from the cache.  We acquire
 * the cache lock first, so no cache searches can be done.  Then we search
 * for the acl in the cache, and if we find it we can lock it and check that
 * nobody else attached to it while we were acquiring the locks.  If the acl
 * is in the cache and still has a zero reference count, then we remove it
 * from the cache and deallocate it.  If the reference count is non-zero or
 * it is not found in the cache, then someone else attached to it or has
 * already freed it, so we just return.
 *
 * Parameters:
 * sp - Ptr to the sp struct which is the candicate for deletion.
 * signature - the signature for the acl for lookup in the hash table
 *
 * Returns: Nothing (void)
 */
void
si_cache_del(si_t *sp, int signature)
{
	si_t	**tspp;
	int	hash;
	int	foundacl = 0;

	/*
	 * Unlink & free the sp from the other queues, then destroy it.
	 * Search the 'by acl' chain first, then the 'by inode' chain
	 * after the acl is locked.
	 */
	rw_enter(&si_cache_lock, RW_WRITER);
	hash = SI_HASH(signature);
	for (tspp = &si_cachea[hash]; *tspp; tspp = &(*tspp)->s_next) {
		if (*tspp == sp) {
			/*
			 * Wait to grab the acl lock until after the acl has
			 * been found in the cache.  Otherwise it might try to
			 * grab a lock that has already been destroyed, or
			 * delete an acl that has already been freed.
			 */
			rw_enter(&sp->s_lock, RW_WRITER);
			/* See if someone else attached to it */
			if (sp->s_ref) {
				rw_exit(&sp->s_lock);
				rw_exit(&si_cache_lock);
				return;
			}
			ASSERT(sp->s_fore == NULL);
			ASSERT(sp->s_flags & SI_CACHED);
			foundacl = 1;
			*tspp = sp->s_next;
			break;
		}
	}

	/*
	 * If the acl was not in the cache, we assume another thread has
	 * deleted it already. This could happen if another thread attaches to
	 * the acl and then releases it after this thread has already found the
	 * reference count to be zero but has not yet taken the cache lock.
	 * Both threads end up seeing a reference count of zero, and call into
	 * si_cache_del.  See bug 4244827 for details on the race condition.
	 */
	if (foundacl == 0) {
		rw_exit(&si_cache_lock);
		return;
	}

	/* Now check the 'by inode' chain */
	hash = SI_HASH(sp->s_shadow);
	for (tspp = &si_cachei[hash]; *tspp; tspp = &(*tspp)->s_forw) {
		if (*tspp == sp) {
			*tspp = sp->s_forw;
			break;
		}
	}

	/*
	 * At this point, we can unlock everything because this si
	 * is no longer in the cache, thus cannot be attached to.
	 */
	rw_exit(&sp->s_lock);
	rw_exit(&si_cache_lock);
	sp->s_flags &= ~SI_CACHED;
	(void) ufs_si_free_mem(sp);
}

/*
 * Alloc the hash buckets for the si cache & initialize
 * the unreferenced anchor and the cache lock.
 */
void
si_cache_init(void)
{
	rw_init(&si_cache_lock, NULL, RW_DEFAULT, NULL);

	/* The 'by acl' headers */
	si_cachea = kmem_zalloc(si_cachecnt * sizeof (si_t *), KM_SLEEP);
	/* The 'by inode' headers */
	si_cachei = kmem_zalloc(si_cachecnt * sizeof (si_t *), KM_SLEEP);
}

/*
 *  aclcksum takes an acl and generates a checksum.  It takes as input
 *  the acl to start at.
 *
 *  s_aclp - pointer to starting acl
 *
 *  returns checksum
 */
static int
aclcksum(ufs_ic_acl_t *s_aclp)
{
	ufs_ic_acl_t *aclp;
	int signature = 0;
	for (aclp = s_aclp; aclp; aclp = aclp->acl_ic_next) {
		signature += aclp->acl_ic_perm;
		signature += aclp->acl_ic_who;
	}
	return (signature);
}

/*
 * Generate a unique signature for an si structure.  Used by the
 * search routine si_cachea_get() to quickly identify candidates
 * prior to calling si_cmp().
 * Parameters:
 * sp - Ptr to the si struct to generate the signature for.
 *
 * Returns:  A signature for the si struct (really a checksum)
 */
static int
si_signature(si_t *sp)
{
	int signature = sp->s_dev;

	signature += aclcksum(sp->aowner) + aclcksum(sp->agroup) +
	    aclcksum(sp->aother) + aclcksum(sp->ausers) +
	    aclcksum(sp->agroups) + aclcksum(sp->downer) +
	    aclcksum(sp->dgroup) + aclcksum(sp->dother) +
	    aclcksum(sp->dusers) + aclcksum(sp->dgroups);
	if (sp->aclass.acl_ismask)
		signature += sp->aclass.acl_maskbits;
	if (sp->dclass.acl_ismask)
		signature += sp->dclass.acl_maskbits;

	return (signature);
}

/*
 * aclcmp compares to acls to see if they are identical.
 *
 * sp1 is source
 * sp2 is sourceb
 *
 * returns 0 if equal and 1 if not equal
 */
static int
aclcmp(ufs_ic_acl_t *aclin1p, ufs_ic_acl_t *aclin2p)
{
	ufs_ic_acl_t *aclp1;
	ufs_ic_acl_t *aclp2;

	/*
	 * if the starting pointers are equal then they are equal so
	 * just return.
	 */
	if (aclin1p == aclin2p)
		return (0);
	/*
	 * check element by element
	 */
	for (aclp1 = aclin1p, aclp2 = aclin2p; aclp1 && aclp2;
	    aclp1 = aclp1->acl_ic_next, aclp2 = aclp2->acl_ic_next) {
		if (aclp1->acl_ic_perm != aclp2->acl_ic_perm ||
		    aclp1->acl_ic_who != aclp2->acl_ic_who)
			return (1);
	}
	/*
	 * both must be zero (at the end of the acl)
	 */
	if (aclp1 || aclp2)
		return (1);

	return (0);
}

/*
 * Do extensive, field-by-field compare of two si structures.  Returns
 * 0 if they are exactly identical, 1 otherwise.
 *
 * Paramters:
 * sp1 - Ptr to 1st si struct
 * sp2 - Ptr to 2nd si struct
 *
 * Returns:
 *		0 - Not identical
 * 		1 - Identical
 */
static int
si_cmp(si_t *sp1, si_t *sp2)
{
	if (sp1->s_dev != sp2->s_dev)
		return (1);
	if (aclcmp(sp1->aowner, sp2->aowner) ||
	    aclcmp(sp1->agroup, sp2->agroup) ||
	    aclcmp(sp1->aother, sp2->aother) ||
	    aclcmp(sp1->ausers, sp2->ausers) ||
	    aclcmp(sp1->agroups, sp2->agroups) ||
	    aclcmp(sp1->downer, sp2->downer) ||
	    aclcmp(sp1->dgroup, sp2->dgroup) ||
	    aclcmp(sp1->dother, sp2->dother) ||
	    aclcmp(sp1->dusers, sp2->dusers) ||
	    aclcmp(sp1->dgroups, sp2->dgroups))
		return (1);
	if (sp1->aclass.acl_ismask != sp2->aclass.acl_ismask)
		return (1);
	if (sp1->dclass.acl_ismask != sp2->dclass.acl_ismask)
		return (1);
	if (sp1->aclass.acl_ismask &&
	    sp1->aclass.acl_maskbits != sp2->aclass.acl_maskbits)
		return (1);
	if (sp1->dclass.acl_ismask &&
	    sp1->dclass.acl_maskbits != sp2->dclass.acl_maskbits)
		return (1);

	return (0);
}

/*
 * Remove all acls associated with a device.  All acls must have
 * a reference count of zero.
 *
 * inputs:
 *	device - device to remove from the cache
 *
 * outputs:
 *	none
 */
void
ufs_si_cache_flush(dev_t dev)
{
	si_t *tsp, **tspp;
	int i;

	rw_enter(&si_cache_lock, RW_WRITER);
	for (i = 0; i < si_cachecnt; i++) {
		tspp = &si_cachea[i];
		while (*tspp) {
			if ((*tspp)->s_dev == dev) {
				*tspp = (*tspp)->s_next;
			} else {
				tspp = &(*tspp)->s_next;
			}
		}
	}
	for (i = 0; i < si_cachecnt; i++) {
		tspp = &si_cachei[i];
		while (*tspp) {
			if ((*tspp)->s_dev == dev) {
				tsp = *tspp;
				*tspp = (*tspp)->s_forw;
				tsp->s_flags &= ~SI_CACHED;
				ufs_si_free_mem(tsp);
			} else {
				tspp = &(*tspp)->s_forw;
			}
		}
	}
	rw_exit(&si_cache_lock);
}

/*
 * ufs_si_del is used to unhook a sp from a inode in memory
 *
 * ip is the inode to remove the sp from.
 */
void
ufs_si_del(struct inode *ip)
{
	si_t    *sp = ip->i_ufs_acl;
	int	refcnt;
	int	signature;

	if (sp) {
		rw_enter(&sp->s_lock, RW_WRITER);
		refcnt = --sp->s_ref;
		signature = sp->s_signature;
		ASSERT(sp->s_ref >= 0 && sp->s_ref <= sp->s_use);
		rw_exit(&sp->s_lock);
		if (refcnt == 0)
			si_cache_del(sp, signature);
		ip->i_ufs_acl = NULL;
	}
}
