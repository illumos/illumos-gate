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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <sys/types32.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <rpc/types.h>
#include <sys/vfs.h>
#include <sys/siginfo.h>
#include <sys/proc.h>		/* for exit() declaration */
#include <sys/kmem.h>
#include <sys/pathname.h>
#include <sys/debug.h>
#include <sys/vtrace.h>
#include <sys/cmn_err.h>
#include <sys/atomic.h>
#include <sys/policy.h>

#include <sharefs/sharefs.h>

/*
 * A macro to avoid cut-and-paste errors on getting a string field
 * from user-land.
 */
#define	SHARETAB_COPYIN(field)						\
	if (copyinstr(STRUCT_FGETP(u_sh, sh_##field),			\
			buf,						\
			bufsz + 1,	/* Add one for extra NUL */	\
			&len)) {					\
		error = EFAULT;						\
		goto cleanup;						\
	}								\
	/*								\
	 * Need to remove 1 because copyinstr() counts the NUL.		\
	 */								\
	len--;								\
	sh->sh_##field = kmem_alloc(len + 1, KM_SLEEP);			\
	bcopy(buf, sh->sh_##field, len);				\
	sh->sh_##field[len] = '\0';					\
	shl.shl_##field = (int)len;					\
	sh->sh_size += shl.shl_##field;	/* Debug counting */

#define	SHARETAB_DELETE_FIELD(field)					\
	if (sh->sh_##field) {						\
		kmem_free(sh->sh_##field,				\
			shl ? shl->shl_##field + 1 :			\
			strlen(sh->sh_##field) + 1);			\
	}

sharetab_t	*sharefs_sharetab = NULL;	/* The incore sharetab. */
size_t		sharetab_size;
uint_t		sharetab_count;

krwlock_t	sharetab_lock;	/* lock to protect the cached sharetab */

krwlock_t	sharefs_lock;	/* lock to protect the vnode ops */

timestruc_t	sharetab_mtime;
timestruc_t	sharetab_snap_time;

uint_t		sharetab_generation;	/* Only increments and wraps! */

/*
 * Take care of cleaning up a share.
 * If passed in a length array, use it to determine how much
 * space to clean up. Else, figure that out.
 */
static void
sharefree(share_t *sh, sharefs_lens_t *shl)
{
	if (!sh)
		return;

	SHARETAB_DELETE_FIELD(path);
	SHARETAB_DELETE_FIELD(res);
	SHARETAB_DELETE_FIELD(fstype);
	SHARETAB_DELETE_FIELD(opts);
	SHARETAB_DELETE_FIELD(descr);

	kmem_free(sh, sizeof (share_t));
}

/*
 * If there is no error, then this function is responsible for
 * cleaning up the memory associated with the share argument.
 */
static int
sharefs_remove(share_t *sh, sharefs_lens_t *shl)
{
	int		iHash;
	sharetab_t	*sht;
	share_t		*s, *p;
	int		iPath;

	if (!sh)
		return (ENOENT);

	rw_enter(&sharetab_lock, RW_WRITER);
	for (sht = sharefs_sharetab; sht != NULL; sht = sht->s_next) {
		if (strcmp(sh->sh_fstype, sht->s_fstype) == 0) {
			break;
		}
	}

	/*
	 * There does not exist a fstype in memory which
	 * matches the share passed in.
	 */
	if (!sht) {
		rw_exit(&sharetab_lock);
		return (ENOENT);
	}

	iPath = shl ? shl->shl_path : strlen(sh->sh_path);
	iHash = pkp_tab_hash(sh->sh_path, strlen(sh->sh_path));

	/*
	 * Now walk down the hash table and find the entry to free!
	 */
	for (p = NULL, s = sht->s_buckets[iHash].ssh_sh;
	    s != NULL; s = s->sh_next) {
		/*
		 * We need exact matches.
		 */
		if (strcmp(sh->sh_path, s->sh_path) == 0 &&
		    strlen(s->sh_path) == iPath) {
			if (p) {
				p->sh_next = s->sh_next;
			} else {
				sht->s_buckets[iHash].ssh_sh = s->sh_next;
			}

			ASSERT(sht->s_buckets[iHash].ssh_count != 0);
			atomic_dec_32(&sht->s_buckets[iHash].ssh_count);
			atomic_dec_32(&sht->s_count);
			atomic_dec_32(&sharetab_count);

			ASSERT(sharetab_size >= s->sh_size);
			sharetab_size -= s->sh_size;

			gethrestime(&sharetab_mtime);
			atomic_inc_32(&sharetab_generation);

			break;
		}

		p = s;
	}

	rw_exit(&sharetab_lock);

	if (!s) {
		return (ENOENT);
	}

	s->sh_next = NULL;
	sharefree(s, NULL);

	/*
	 * We need to free the share for the caller.
	 */
	sharefree(sh, shl);

	return (0);
}

/*
 * The caller must have allocated memory for us to use.
 */
static int
sharefs_add(share_t *sh, sharefs_lens_t *shl)
{
	int		iHash;
	sharetab_t	*sht;
	share_t		*s, *p;
	int		iPath;
	int		n;

	if (!sh) {
		return (ENOENT);
	}

	/*
	 * We need to find the hash buckets for the fstype.
	 */
	rw_enter(&sharetab_lock, RW_WRITER);
	for (sht = sharefs_sharetab; sht != NULL; sht = sht->s_next) {
		if (strcmp(sh->sh_fstype, sht->s_fstype) == 0) {
			break;
		}
	}

	/*
	 * Did not exist, so allocate one and add it to the
	 * sharetab.
	 */
	if (!sht) {
		sht = kmem_zalloc(sizeof (*sht), KM_SLEEP);
		n = strlen(sh->sh_fstype);
		sht->s_fstype = kmem_zalloc(n + 1, KM_SLEEP);
		(void) strncpy(sht->s_fstype, sh->sh_fstype, n);

		sht->s_next = sharefs_sharetab;
		sharefs_sharetab = sht;
	}

	/*
	 * Now we need to find where we have to add the entry.
	 */
	iHash = pkp_tab_hash(sh->sh_path, strlen(sh->sh_path));

	iPath = shl ? shl->shl_path : strlen(sh->sh_path);

	if (shl) {
		sh->sh_size = shl->shl_path + shl->shl_res +
		    shl->shl_fstype + shl->shl_opts + shl->shl_descr;
	} else {
		sh->sh_size = strlen(sh->sh_path) +
		    strlen(sh->sh_res) + strlen(sh->sh_fstype) +
		    strlen(sh->sh_opts) + strlen(sh->sh_descr);
	}

	/*
	 * We need to account for field seperators and
	 * the EOL.
	 */
	sh->sh_size += 5;

	/*
	 * Now walk down the hash table and add the new entry!
	 */
	for (p = NULL, s = sht->s_buckets[iHash].ssh_sh;
	    s != NULL; s = s->sh_next) {
		/*
		 * We need exact matches.
		 *
		 * We found a matching path. Either we have a
		 * duplicate path in a share command or we are
		 * being asked to replace an existing entry.
		 */
		if (strcmp(sh->sh_path, s->sh_path) == 0 &&
		    strlen(s->sh_path) == iPath) {
			if (p) {
				p->sh_next = sh;
			} else {
				sht->s_buckets[iHash].ssh_sh = sh;
			}

			sh->sh_next = s->sh_next;

			ASSERT(sharetab_size >= s->sh_size);
			sharetab_size -= s->sh_size;
			sharetab_size += sh->sh_size;

			/*
			 * Get rid of the old node.
			 */
			sharefree(s, NULL);

			gethrestime(&sharetab_mtime);
			atomic_inc_32(&sharetab_generation);

			ASSERT(sht->s_buckets[iHash].ssh_count != 0);
			rw_exit(&sharetab_lock);

			return (0);
		}

		p = s;
	}

	/*
	 * Okay, we have gone through the entire hash chain and not
	 * found a match. We just need to add this node.
	 */
	sh->sh_next = sht->s_buckets[iHash].ssh_sh;
	sht->s_buckets[iHash].ssh_sh = sh;
	atomic_inc_32(&sht->s_buckets[iHash].ssh_count);
	atomic_inc_32(&sht->s_count);
	atomic_inc_32(&sharetab_count);
	sharetab_size += sh->sh_size;

	gethrestime(&sharetab_mtime);
	atomic_inc_32(&sharetab_generation);

	rw_exit(&sharetab_lock);

	return (0);
}

void
sharefs_sharetab_init(void)
{
	rw_init(&sharetab_lock, NULL, RW_DEFAULT, NULL);
	rw_init(&sharefs_lock, NULL, RW_DEFAULT, NULL);

	sharetab_size = 0;
	sharetab_count = 0;
	sharetab_generation = 1;

	gethrestime(&sharetab_mtime);
	gethrestime(&sharetab_snap_time);
}

int
sharefs_impl(enum sharefs_sys_op opcode, share_t *sh_in, uint32_t iMaxLen)
{
	int		error = 0;
	size_t		len;
	size_t		bufsz;
	share_t		*sh;

	sharefs_lens_t	shl;

	model_t		model;

	char		*buf = NULL;

	STRUCT_DECL(share, u_sh);

	bufsz = iMaxLen;

	/*
	 * Before we do anything, lets make sure we have
	 * a sharetab in memory if we need one.
	 */
	rw_enter(&sharetab_lock, RW_READER);
	switch (opcode) {
	case (SHAREFS_REMOVE) :
	case (SHAREFS_REPLACE) :
		if (!sharefs_sharetab) {
			rw_exit(&sharetab_lock);
			return (set_errno(ENOENT));
		}
		break;
	case (SHAREFS_ADD) :
	default :
		break;
	}
	rw_exit(&sharetab_lock);

	model = get_udatamodel();

	/*
	 * Initialize the data pointers.
	 */
	STRUCT_INIT(u_sh, model);
	if (copyin(sh_in, STRUCT_BUF(u_sh), STRUCT_SIZE(u_sh))) {
		return (set_errno(EFAULT));
	}

	/*
	 * Get the share.
	 */
	sh = kmem_zalloc(sizeof (share_t), KM_SLEEP);

	/*
	 * Get some storage for copying in the strings.
	 */
	buf = kmem_zalloc(bufsz + 1, KM_SLEEP);
	bzero(&shl, sizeof (sharefs_lens_t));

	/*
	 * Only grab these two until we know what we want.
	 */
	SHARETAB_COPYIN(path);
	SHARETAB_COPYIN(fstype);

	switch (opcode) {
	case (SHAREFS_ADD) :
	case (SHAREFS_REPLACE) :
		SHARETAB_COPYIN(res);
		SHARETAB_COPYIN(opts);
		SHARETAB_COPYIN(descr);

		error = sharefs_add(sh, &shl);
		break;

	case (SHAREFS_REMOVE) :

		error = sharefs_remove(sh, &shl);
		break;

	default:
		error = EINVAL;
		break;
	}

cleanup:

	/*
	 * If there is no error, then we have stashed the structure
	 * away in the sharetab hash table or have deleted it.
	 *
	 * Either way, the only reason to blow away the data is if
	 * there was an error.
	 */
	if (error != 0) {
		sharefree(sh, &shl);
	}

	if (buf) {
		kmem_free(buf, bufsz + 1);
	}

	return ((error != 0) ? set_errno(error) : 0);
}

int
sharefs(enum sharefs_sys_op opcode, share_t *sh_in, uint32_t iMaxLen)
{
	if (secpolicy_sys_config(CRED(), B_FALSE) != 0)
		return (set_errno(EPERM));

	return (sharefs_impl(opcode, sh_in, iMaxLen));
}
