/*
 * Copyright (c) 2000-2001 Boris Popov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Boris Popov.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: smbfs_node.c,v 1.54.52.1 2005/05/27 02:35:28 lindak Exp $
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/cred.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/kmem.h>
#include <sys/stat.h>
#include <sys/atomic.h>
#include <sys/cmn_err.h>
#include <sys/sysmacros.h>
#include <sys/bitmap.h>

#ifdef APPLE
#include <sys/smb_apple.h>
#else
#include <netsmb/smb_osdep.h>
#endif

#include <netsmb/smb.h>
#include <netsmb/smb_conn.h>
#include <netsmb/smb_subr.h>

#include <smbfs/smbfs.h>
#include <smbfs/smbfs_node.h>
#include <smbfs/smbfs_subr.h>

#if defined(DEBUG) || defined(lint)
#define	SMBFS_NAME_DEBUG
#endif

/*
 * Lack of inode numbers leads us to the problem of generating them.
 * Partially this problem can be solved by having a dir/file cache
 * with inode numbers generated from the incremented by one counter.
 * However this way will require too much kernel memory, gives all
 * sorts of locking and consistency problems, not to mentinon counter
 * overflows. So, I'm decided to use a hash function to generate
 * pseudo random (and [often?] unique) inode numbers.
 */

/* Magic constants for name hashing. */
#define	FNV_32_PRIME ((uint32_t)0x01000193UL)
#define	FNV1_32_INIT ((uint32_t)33554467UL)

uint32_t
smbfs_hash3(uint32_t ival, const char *name, int nmlen)
{
	uint32_t v;

	for (v = ival; nmlen; name++, nmlen--) {
		v *= FNV_32_PRIME;
		v ^= (uint32_t)*name;
	}
	return (v);
}

uint32_t
smbfs_hash(const char *name, int nmlen)
{
	uint32_t v;

	v = smbfs_hash3(FNV1_32_INIT, name, nmlen);
	return (v);
}

/*
 * This is basically a hash of the full path name, but
 * computed without having the full path contiguously.
 * The path building logic needs to match what
 * smbfs_fullpath does.
 *
 * Note that smbfs_make_node computes inode numbers by
 * calling smbfs_hash on the full path name.  This will
 * compute the same result given the directory path and
 * the last component separately.
 */
uint32_t
smbfs_getino(struct smbnode *dnp, const char *name, int nmlen)
{
	uint32_t ino;

	/* Start with directory hash */
	ino = (uint32_t)dnp->n_ino;

	/*
	 * If not the root, hash a slash.
	 */
	if (dnp->n_rplen > 1)
		ino = smbfs_hash3(ino, "\\", 1);

	/* Now hash this component. */
	ino = smbfs_hash3(ino, name, nmlen);

	return (ino);
}

#define	CHAR_FC '\374' /* 0xFC */
#define	CHAR_FE '\376' /* 0xFE */
char *
smbfs_name_alloc(const char *name, int nmlen)
{
	char *cp;
	size_t alen;

#ifdef SMBFS_NAME_DEBUG
	/*
	 * Note: The passed length is strlen(name),
	 * and does NOT include the terminating nul.
	 * Allocated space holds: (in order)
	 *   (int)strlen
	 *   char 0xFC (1st marker)
	 *   copy of string
	 *   terminating null
	 *   char 0xFE (2nd marker)
	 */
	alen = sizeof (int) + 1 + nmlen + 1 + 1;
	cp = kmem_alloc(alen, KM_SLEEP);
	/*LINTED*/
	*(int *)cp = nmlen;
	cp += sizeof (int);
	cp[0] = CHAR_FC;
	cp++;
	bcopy(name, cp, nmlen);
	cp[nmlen] = 0;
	cp[nmlen + 1] = CHAR_FE;
#else
	alen = nmlen + 1; /* Passed length does NOT include the nul. */
	cp = kmem_alloc(alen,  KM_SLEEP);
	bcopy(name, cp, nmlen);
	cp[nmlen] = 0;
#endif
	return (cp);
}

/*
 * Note: Passed length does NOT include the nul,
 * the same as with smbfs_name_alloc().
 */
void
smbfs_name_free(const char *name, int nmlen)
{
	size_t alen;
#ifdef SMBFS_NAME_DEBUG
	int lnmlen;
	char *cp;

	/*
	 * See comment in smbfs_name_alloc
	 * about the layout of this memory.
	 */
	alen = sizeof (int) + 1 + nmlen + 1 + 1;
	cp = (char *)name;
	cp--;
	if (*cp != CHAR_FC) {
		debug_enter("smbfs_name_free: name[-1] != 0xFC");
	}
	cp -= sizeof (int);
	/*LINTED*/
	lnmlen = *(int *)cp;
	if (lnmlen != nmlen) {
		debug_enter("smbfs_name_free: name[-5] != nmlen");
	}
	if (name[nmlen + 1] != CHAR_FE) {
		debug_enter("smbfs_name_free: name[nmlen+1] != 0xFE");
	}
	kmem_free(cp, alen);
#else
	alen = nmlen + 1;
	kmem_free((char *)name, alen);
#endif
}

/*
 * smbfs_nget()
 *
 * NOTES:
 *
 * It would be nice to be able to pass in a flag when the caller is sure
 * that the node does not exist and should just be allocated.
 */
int
smbfs_nget(vnode_t *dvp, const char *name, int nmlen,
    struct smbfattr *fap, vnode_t **vpp)
{
	struct smbnode *dnp = VTOSMB(dvp);
	struct smbnode *np;
	vnode_t *vp;
	char sep;

	*vpp = NULL;

	/* Don't expect "." or ".." here anymore. */
	if ((nmlen == 1 && name[0] == '.') ||
	    (nmlen == 2 && name[0] == '.' && name[1] == '.')) {
		DEBUG_ENTER("smbfs_nget: name is '.' or '..'");
		return (EINVAL);
	}

	/*
	 * See the comment near the top of smbfs_xattr.c about
	 * the logic for what separators to use where.
	 */
	sep = (dnp->n_flag & N_XATTR) ? 0 : '\\';

	/* Find or create the node. */
	vp = smbfs_make_node(dvp->v_vfsp,
	    dnp->n_rpath, dnp->n_rplen,
	    name, nmlen, sep, fap);

	/*
	 * We always have a vp now, because
	 * smbfs_make_node / make_smbnode
	 * calls kmem_alloc with KM_SLEEP.
	 */
	ASSERT(vp);
	np = VTOSMB(vp);

	/*
	 * Files in an XATTR dir are also XATTR.
	 */
	if (dnp->n_flag & N_XATTR) {
		mutex_enter(&np->r_statelock);
		np->n_flag |= N_XATTR;
		mutex_exit(&np->r_statelock);
	}

#ifdef NOT_YET
	/* update the attr_cache info if the file is clean */
	if (fap && !(VTOSMB(vp)->n_flag & NFLUSHWIRE))
		smbfs_attr_cacheenter(vp, fap);
	if (dvp && makeentry) {
		/* add entry to DNLC */
		cache_enter(dvp, vp, &cn);
	}
#endif /* NOT_YET */

	/* BSD symlink hack removed (smb_symmagic) */

#ifdef NOT_YET
	smbfs_attr_cacheenter(vp, fap);	/* update the attr_cache info */
#endif /* NOT_YET */

	*vpp = vp;

	return (0);
}

/*
 * routines to maintain vnode attributes cache
 * smbfs_attr_cacheenter: unpack np.i to vnode_vattr structure
 *
 * Note that some SMB servers do not exhibit POSIX behaviour
 * with regard to the mtime on directories.  To work around
 * this, we never allow the mtime on a directory to go backwards,
 * and bump it forwards elsewhere to simulate the correct
 * behaviour.
 */
void
smbfs_attr_cacheenter(vnode_t *vp, struct smbfattr *fap)
{
	struct smbnode *np = VTOSMB(vp);
	int vtype;
	struct timespec ts;

	mutex_enter(&np->r_statelock);

	vtype = (fap->fa_attr & SMB_FA_DIR) ? VDIR : VREG;
	if (vp->v_type != vtype)
		SMBVDEBUG("vtype change %d to %d\n",
		    vp->v_type, vtype);
	vp->v_type = vtype;

	if (vtype == VREG) {
		if (np->n_size != fap->fa_size) {
			/*
			 * Had Darwin ubc_sync_range call here,
			 * invalidating the truncated range.
			 * XXX: Solaris equivalent?
			 */
			SMBVDEBUG("Update size?\n");
		}
		np->n_size = fap->fa_size;
	} else if (vtype == VDIR) {
		np->n_size = 16384; 	/* XXX should be a better way ... */
		/*
		 * Don't allow mtime to go backwards.
		 * Yes this has its flaws.  Better ideas are welcome!
		 */
		/*CSTYLED*/
		if (timespeccmp(&fap->fa_mtime, &np->n_mtime, <))
			fap->fa_mtime = np->n_mtime;
	} else if (vtype != VLNK)
		goto out;

	np->n_atime = fap->fa_atime;
	np->n_ctime = fap->fa_ctime;
	np->n_mtime = fap->fa_mtime;
	np->n_dosattr = fap->fa_attr;

	np->n_flag &= ~NATTRCHANGED;
	gethrestime(&ts);
	np->n_attrage = ts.tv_sec;

out:
	mutex_exit(&np->r_statelock);
}

int
smbfs_attr_cachelookup(vnode_t *vp, struct vattr *vap)
{
	struct smbnode *np = VTOSMB(vp);
	struct smbmntinfo *smi = VTOSMI(vp);
	time_t attrtimeo;
	struct timespec ts, *stime;
	mode_t	type;

	/*
	 * Determine attrtimeo. It will be something between SMB_MINATTRTIMO and
	 * SMB_MAXATTRTIMO where recently modified files have a short timeout
	 * and files that haven't been modified in a long time have a long
	 * timeout. This is the same algorithm used by NFS.
	 */
	gethrestime(&ts);
	stime = &np->r_mtime;
	attrtimeo = (ts.tv_sec - stime->tv_sec) / 10;
	if (attrtimeo < SMB_MINATTRTIMO) {
		attrtimeo = SMB_MINATTRTIMO;
	} else if (attrtimeo > SMB_MAXATTRTIMO)
		attrtimeo = SMB_MAXATTRTIMO;
	/* has too much time passed? */
	stime = (struct timespec *)&np->r_attrtime;
	if ((ts.tv_sec - stime->tv_sec) > attrtimeo)
		return (ENOENT);

	if (!vap)
		return (0);

	switch (vp->v_type) {
	case VREG:
		type = S_IFREG;
		break;
	case VLNK:
		type = S_IFLNK;
		break;
	case VDIR:
		type = S_IFDIR;
		break;
	default:
		SMBSDEBUG("unknown vnode_vtype %d\n", vp->v_type);
		return (EINVAL);
	}

	mutex_enter(&np->r_statelock);

	if (!(np->n_flag & NGOTIDS)) {
		np->n_mode = type;
#ifdef APPLE
		if (smi->smi_fsattr & FILE_PERSISTENT_ACLS) {
			/* XXX: Can this block?  Drop r_statelock? */
			if (!smbfs_getids(np, scredp)) {
				np->n_flag |= NGOTIDS;
				np->n_mode |= ACCESSPERMS; /* 0777 */
			}
		}
#endif /* APPLE */
		if (!(np->n_flag & NGOTIDS)) {
			np->n_flag |= NGOTIDS;
			np->n_uid = smi->smi_args.uid;
			np->n_gid = smi->smi_args.gid;
		}
	}

	if (vap->va_mask & AT_TYPE)
		vap->va_type = vp->v_type;
	if (vap->va_mask & AT_MODE) {
		np->n_mode = 0;
		if (vp->v_type == VDIR)
			np->n_mode |= smi->smi_args.dir_mode;
		else	/* symlink and regular file */
			np->n_mode |= smi->smi_args.file_mode;
		vap->va_mode = np->n_mode;
	}
	if (vap->va_mask & AT_SIZE)
		vap->va_size = np->n_size;
	if (vap->va_mask & AT_NODEID)
		vap->va_nodeid = np->n_ino;
	if (vap->va_mask & AT_ATIME)
		vap->va_atime = np->n_atime;
	if (vap->va_mask & AT_CTIME)
		vap->va_ctime = np->n_ctime;
	if (vap->va_mask & AT_MTIME)
		vap->va_mtime = np->n_mtime;
	vap->va_nlink = 1;
	vap->va_uid = np->n_uid;
	vap->va_gid = np->n_gid;
	vap->va_fsid = vp->v_vfsp->vfs_dev;
	vap->va_rdev = 0;
	vap->va_blksize = MAXBSIZE;
	vap->va_nblocks = (fsblkcnt64_t)btod(np->n_size);
	vap->va_seq = 0;

	mutex_exit(&np->r_statelock);

	return (0);
}

/*
 * Some SMB servers don't exhibit POSIX behaviour with regard to
 * updating the directory mtime when the directory's contents
 * change.
 *
 * We force the issue here by updating our cached copy of the mtime
 * whenever we perform such an action ourselves, and then mark the
 * cache invalid.  Subsequently when the invalidated cache entry is
 * updated, we disallow an update that would move the mtime backwards.
 *
 * This preserves correct or near-correct behaviour with a
 * compliant server, and gives near-correct behaviour with
 * a non-compliant server in the most common case (we are the
 * only client changing the directory).
 *
 * There are also complications if a server's time is ahead
 * of our own.  We must 'touch' a directory when it is first
 * created, to ensure that the timestamp starts out sane,
 * however it may have a timestamp well ahead of the 'touch'
 * point which will be returned and cached the first time the
 * directory's attributes are fetched.  Subsequently, the
 * directory's mtime will not appear to us to change at all
 * until our local time catches up to the server.
 *
 * Thus, any time a directory is 'touched', the saved timestamp
 * must advance at least far enough forwards to be visible to
 * the stat(2) interface.
 *
 * XXX note that better behaviour with non-compliant servers
 *     could be obtained by bumping the mtime forwards when
 *     an update for an invalidated entry returns a nonsensical
 *     mtime.
 */

void
smbfs_attr_touchdir(struct smbnode *dnp)
{
	struct timespec ts, ta;

	mutex_enter(&dnp->r_statelock);

	/*
	 * XXX - not sure about this...
	 * Creep the saved time forwards far enough that
	 * layers above the kernel will notice.
	 */
	ta.tv_sec = 1;
	ta.tv_nsec = 0;
	timespecadd(&dnp->n_mtime, &ta);
	/*
	 * If the current time is later than the updated
	 * saved time, apply it instead.
	 */
	gethrestime(&ts);
	/*CSTYLED*/
	if (timespeccmp(&dnp->n_mtime, &ts, <))
		dnp->n_mtime = ts;
	/*
	 * Invalidate the cache, so that we go to the wire
	 * to check that the server doesn't have a better
	 * timestamp next time we care.
	 */
	smbfs_attr_cacheremove(dnp);
	mutex_exit(&dnp->r_statelock);
}
