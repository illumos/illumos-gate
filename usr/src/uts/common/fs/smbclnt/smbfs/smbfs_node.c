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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/cred.h>
#include <sys/time.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/kmem.h>
#include <sys/stat.h>
#include <sys/atomic.h>
#include <sys/cmn_err.h>
#include <sys/sysmacros.h>
#include <sys/bitmap.h>

#include <netsmb/smb_osdep.h>

#include <netsmb/smb.h>
#include <netsmb/smb_conn.h>
#include <netsmb/smb_subr.h>

#include <smbfs/smbfs.h>
#include <smbfs/smbfs_node.h>
#include <smbfs/smbfs_subr.h>

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

static inline uint32_t
smbfs_hash(uint32_t ival, const char *name, int nmlen)
{
	uint32_t v;

	for (v = ival; nmlen; name++, nmlen--) {
		v *= FNV_32_PRIME;
		v ^= (uint32_t)*name;
	}
	return (v);
}

/*
 * Compute the hash of the full (remote) path name
 * using the three parts supplied separately.
 */
uint32_t
smbfs_gethash(const char *rpath, int rplen)
{
	uint32_t v;

	v = smbfs_hash(FNV1_32_INIT, rpath, rplen);
	return (v);
}

/*
 * Like smbfs_gethash, but optimized a little by
 * starting with the directory hash.
 */
uint32_t
smbfs_getino(struct smbnode *dnp, const char *name, int nmlen)
{
	uint32_t ino;
	char sep;

	/* Start with directory hash */
	ino = (uint32_t)dnp->n_ino;

	/* separator (maybe) */
	sep = SMBFS_DNP_SEP(dnp);
	if (sep)
		ino = smbfs_hash(ino, &sep, 1);

	/* Now hash this component. */
	ino = smbfs_hash(ino, name, nmlen);

	return (ino);
}

/*
 * Allocate and copy a string of passed length.
 * The passed length does NOT include the null.
 */
char *
smbfs_name_alloc(const char *name, int nmlen)
{
	char *cp;

	cp = kmem_alloc(nmlen + 1, KM_SLEEP);
	bcopy(name, cp, nmlen);
	cp[nmlen] = 0;

	return (cp);
}

/*
 * Free string from smbfs_name_alloc().  Again,
 * the passed length does NOT include the null.
 */
void
smbfs_name_free(const char *name, int nmlen)
{
	kmem_free((char *)name, nmlen + 1);
}

/*
 * smbfs_nget()
 *
 * Find or create a node under some directory node.
 */
int
smbfs_nget(vnode_t *dvp, const char *name, int nmlen,
	struct smbfattr *fap, vnode_t **vpp)
{
	struct smbnode *dnp = VTOSMB(dvp);
	struct smbnode *np;
	vnode_t *vp;
	char sep;

	ASSERT(fap != NULL);
	*vpp = NULL;

	/* Don't expect "" or "." or ".." here anymore. */
	if (nmlen == 0 || (nmlen == 1 && name[0] == '.') ||
	    (nmlen == 2 && name[0] == '.' && name[1] == '.')) {
		return (EINVAL);
	}
	sep = SMBFS_DNP_SEP(dnp);

	/* Find or create the node. */
	np = smbfs_node_findcreate(dnp->n_mount,
	    dnp->n_rpath, dnp->n_rplen,
	    name, nmlen, sep, fap);

	/*
	 * We should have np now, because we passed
	 * fap != NULL to smbfs_node_findcreate.
	 */
	ASSERT(np != NULL);
	vp = SMBTOV(np);

	/*
	 * Files in an XATTR dir are also XATTR.
	 */
	if (dnp->n_flag & N_XATTR) {
		mutex_enter(&np->r_statelock);
		np->n_flag |= N_XATTR;
		mutex_exit(&np->r_statelock);
	}

	/* BSD symlink hack removed (smb_symmagic) */

	*vpp = vp;

	return (0);
}

/*
 * Update the local notion of the mtime of some directory.
 * See comments re. r_mtime in smbfs_node.h
 */
void
smbfs_attr_touchdir(struct smbnode *dnp)
{

	mutex_enter(&dnp->r_statelock);

	/*
	 * Now that we keep the client's notion of mtime
	 * separately from the server, this is easy.
	 */
	dnp->r_mtime = gethrtime();

	/*
	 * Invalidate the cache, so that we go to the wire
	 * to check that the server doesn't have a better
	 * timestamp next time we care.
	 */
	smbfs_attrcache_rm_locked(dnp);
	mutex_exit(&dnp->r_statelock);
}

void
smbfs_attrcache_remove(struct smbnode *np)
{
	mutex_enter(&np->r_statelock);
	/* smbfs_attrcache_rm_locked(np); */
	np->r_attrtime = gethrtime();
	mutex_exit(&np->r_statelock);
}

/* See smbfs_node.h */
#undef smbfs_attrcache_rm_locked
void
smbfs_attrcache_rm_locked(struct smbnode *np)
{
	ASSERT(MUTEX_HELD(&np->r_statelock));
	np->r_attrtime = gethrtime();
}
