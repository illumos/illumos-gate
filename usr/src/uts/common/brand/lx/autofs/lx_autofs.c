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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2016 Joyent, Inc.
 */

/*
 * See the big theory statement in ../sys/lx_autofs.h
 */

#include <fs/fs_subr.h>
#include <sys/atomic.h>
#include <sys/cmn_err.h>
#include <sys/dirent.h>
#include <sys/fs/fifonode.h>
#include <sys/modctl.h>
#include <sys/mount.h>
#include <sys/policy.h>
#include <sys/sunddi.h>
#include <sys/sdt.h>

#include <sys/sysmacros.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>

#include <sys/dnlc.h>
#include <nfs/rnode.h>
#include <nfs/rnode4.h>
#include <sys/lx_autofs_impl.h>
#include <sys/lx_types.h>

/*
 * External functions
 */
extern uintptr_t		space_fetch(char *key);
extern int			space_store(char *key, uintptr_t ptr);
extern int			umount2_engine(vfs_t *, int, cred_t *, int);

/*
 * Globals
 */
static vfsops_t			*lx_autofs_vfsops;
static vnodeops_t		*lx_autofs_vn_ops = NULL;
static int			lx_autofs_fstype;
static major_t			lx_autofs_major;
static minor_t			lx_autofs_minor = 0;

/*
 * Support functions
 */
static void
lx_autofs_strfree(char *str)
{
	kmem_free(str, strlen(str) + 1);
}

static char *
lx_autofs_strdup(char *str)
{
	int	n = strlen(str);
	char	*ptr = kmem_alloc(n + 1, KM_SLEEP);
	bcopy(str, ptr, n + 1);
	return (ptr);
}

static int
lx_autofs_str_to_int(char *str, int *val)
{
	long	res;

	if (str == NULL)
		return (-1);

	if ((ddi_strtol(str, NULL, 10, &res) != 0) ||
	    (res < INT_MIN) || (res > INT_MAX))
		return (-1);

	*val = res;
	return (0);
}

static void
ls_autofs_stack_init(list_t *lp)
{
	list_create(lp,
	    sizeof (stack_elem_t), offsetof(stack_elem_t, se_list));
}

static void
lx_autofs_stack_fini(list_t *lp)
{
	ASSERT(list_head(lp) == NULL);
	list_destroy(lp);
}

static void
lx_autofs_stack_push(list_t *lp, caddr_t ptr1, caddr_t ptr2, caddr_t ptr3)
{
	stack_elem_t	*se;

	se = kmem_alloc(sizeof (*se), KM_SLEEP);
	se->se_ptr1 = ptr1;
	se->se_ptr2 = ptr2;
	se->se_ptr3 = ptr3;
	list_insert_head(lp, se);
}

static int
lx_autofs_stack_pop(list_t *lp, caddr_t *ptr1, caddr_t *ptr2, caddr_t *ptr3)
{
	stack_elem_t	*se;

	if ((se = list_head(lp)) == NULL)
		return (-1);
	list_remove(lp, se);
	if (ptr1 != NULL)
		*ptr1 = se->se_ptr1;
	if (ptr2 != NULL)
		*ptr2 = se->se_ptr2;
	if (ptr3 != NULL)
		*ptr3 = se->se_ptr3;
	kmem_free(se, sizeof (*se));
	return (0);
}

static vnode_t *
lx_autofs_fifo_peer_vp(vnode_t *vp)
{
	fifonode_t *fnp = VTOF(vp);
	fifonode_t *fn_dest = fnp->fn_dest;
	return (FTOV(fn_dest));
}

static vnode_t *
lx_autofs_vn_alloc(vfs_t *vfsp, vnode_t *uvp)
{
	lx_autofs_vfs_t	*data = vfsp->vfs_data;
	vnode_t		*vp, *vp_old;

	/* Allocate a new vnode structure in case we need it. */
	vp = vn_alloc(KM_SLEEP);
	vn_setops(vp, lx_autofs_vn_ops);
	VN_SET_VFS_TYPE_DEV(vp, vfsp, uvp->v_type, uvp->v_rdev);
	vp->v_data = uvp;
	ASSERT(vp->v_count == 1);

	/*
	 * Take a hold on the vfs structure.  This is how unmount will
	 * determine if there are any active vnodes in the file system.
	 */
	VFS_HOLD(vfsp);

	/*
	 * Check if we already have a vnode allocated for this underlying
	 * vnode_t.
	 */
	mutex_enter(&data->lav_lock);
	if (mod_hash_find(data->lav_vn_hash,
	    (mod_hash_key_t)uvp, (mod_hash_val_t *)&vp_old) != 0) {

		/*
		 * Didn't find an existing node.
		 * Add this node to the hash and return.
		 */
		VERIFY(mod_hash_insert(data->lav_vn_hash,
		    (mod_hash_key_t)uvp,
		    (mod_hash_val_t)vp) == 0);
		mutex_exit(&data->lav_lock);
		return (vp);
	}

	/* Get a hold on the existing vnode and free up the one we allocated. */
	VN_HOLD(vp_old);
	mutex_exit(&data->lav_lock);

	/* Free up the new vnode we allocated. */
	VN_RELE(uvp);
	VFS_RELE(vfsp);
	vn_invalid(vp);
	vn_free(vp);

	return (vp_old);
}

static void
lx_autofs_vn_free(vnode_t *vp)
{
	vfs_t		*vfsp = vp->v_vfsp;
	lx_autofs_vfs_t	*data = vfsp->vfs_data;
	vnode_t		*uvp = vp->v_data;
	vnode_t	*vp_tmp;

	ASSERT(MUTEX_HELD((&data->lav_lock)));
	ASSERT(MUTEX_HELD((&vp->v_lock)));

	ASSERT(vp->v_count == 0);

	/* We're about to free this vnode so take it out of the hash. */
	(void) mod_hash_remove(data->lav_vn_hash,
	    (mod_hash_key_t)uvp, (mod_hash_val_t)&vp_tmp);

	/*
	 * No one else can lookup this vnode any more so there's no need
	 * to hold locks.
	 */
	mutex_exit(&data->lav_lock);
	mutex_exit(&vp->v_lock);

	/* Release the underlying vnode. */
	VN_RELE(uvp);
	VFS_RELE(vfsp);
	vn_invalid(vp);
	vn_free(vp);
}

static lx_autofs_automnt_req_t *
lx_autofs_la_alloc(lx_autofs_vfs_t *data, boolean_t *is_dup, boolean_t expire,
    char *nm)
{
	lx_autofs_automnt_req_t	*laar, *laar_dup;

	/* Pre-allocate a new automounter request before grabbing locks. */
	laar = kmem_zalloc(sizeof (*laar), KM_SLEEP);
	mutex_init(&laar->laar_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&laar->laar_cv, NULL, CV_DEFAULT, NULL);
	laar->laar_ref = 1;

	if (data->lav_min_proto == 5) {
		laar->laar_pkt.lap_protover = LX_AUTOFS_PROTO_VERS5;

		if (data->lav_mnttype == LXAMT_INDIR) {
			if (expire) {
				laar->laar_pkt.lap_type =
				    LX_AUTOFS_PTYPE_EXPIRE_INDIR;
			} else {
				laar->laar_pkt.lap_type =
				    LX_AUTOFS_PTYPE_MISSING_INDIR;
			}
		} else {
			if (expire) {
				laar->laar_pkt.lap_type =
				    LX_AUTOFS_PTYPE_EXPIRE_DIRECT;
			} else {
				laar->laar_pkt.lap_type =
				    LX_AUTOFS_PTYPE_MISSING_DIRECT;
			}
		}
		laar->laar_pkt_size = sizeof (lx_autofs_v5_pkt_t);

		laar->laar_pkt.lap_v5.lap_dev = data->lav_dev;
		laar->laar_pkt.lap_v5.lap_ino = data->lav_ino;
		/*
		 * Note that we're currently not filling in the other v5 pkt
		 * fields (pid, uid, etc.) since they don't appear to be used
		 * by the automounter. We can fill those in later if it proves
		 * necessary.
		 */

		/*
		 * For indirect mounts the token expected by the automounter is
		 * the name of the directory entry to look up (not the entire
		 * path that is being accessed.) For direct mounts the Linux
		 * kernel passes a dummy name, so this is just as good.
		 */
		laar->laar_pkt.lap_v5.lap_name_len = strlen(nm);
		if (laar->laar_pkt.lap_v5.lap_name_len >
		    (sizeof (laar->laar_pkt.lap_v5.lap_name) - 1)) {
			zcmn_err(getzoneid(), CE_NOTE,
			    "invalid autofs automnt req: \"%s\"", nm);
			kmem_free(laar, sizeof (*laar));
			return (NULL);
		}
		(void) strlcpy(laar->laar_pkt.lap_v5.lap_name, nm,
		    sizeof (laar->laar_pkt.lap_v5.lap_name));

	} else if (expire) {
		zcmn_err(getzoneid(), CE_WARN,
		    "unsupported expire protocol request: \"%s\"", nm);
		kmem_free(laar, sizeof (*laar));
		return (NULL);

	} else {
		ASSERT(expire == B_FALSE);

		/* Older protocol pkt (really v2) */
		laar->laar_pkt.lap_protover = LX_AUTOFS_PROTO_VERS2;
		laar->laar_pkt.lap_type = LX_AUTOFS_PTYPE_MISSING;
		laar->laar_pkt_size = sizeof (lx_autofs_v2_pkt_t);

		/*
		 * The token expected by the linux automount is the name of
		 * the directory entry to look up.  (And not the entire
		 * path that is being accessed.)
		 */
		laar->laar_pkt.lap_v2.lap_name_len = strlen(nm);
		if (laar->laar_pkt.lap_v2.lap_name_len >
		    (sizeof (laar->laar_pkt.lap_v2.lap_name) - 1)) {
			zcmn_err(getzoneid(), CE_NOTE,
			    "invalid autofs lookup: \"%s\"", nm);
			kmem_free(laar, sizeof (*laar));
			return (NULL);
		}
		(void) strlcpy(laar->laar_pkt.lap_v2.lap_name, nm,
		    sizeof (laar->laar_pkt.lap_v2.lap_name));
	}

	/* Assign a unique id for this request. */
	laar->laar_pkt.lap_id = id_alloc(data->lav_ids);

	/* Check for an outstanding request for this path. */
	mutex_enter(&data->lav_lock);
	if (mod_hash_find(data->lav_path_hash,
	    (mod_hash_key_t)nm, (mod_hash_val_t *)&laar_dup) == 0) {
		/*
		 * There's already an outstanding request for this
		 * path so we don't need a new one.
		 */
		id_free(data->lav_ids, laar->laar_pkt.lap_id);
		kmem_free(laar, sizeof (*laar));
		laar = laar_dup;

		/* Bump the ref count on the old request. */
		atomic_add_int(&laar->laar_ref, 1);

		*is_dup = 1;
	} else {
		/* Add it to the hashes. */
		VERIFY(mod_hash_insert(data->lav_id_hash,
		    (mod_hash_key_t)(uintptr_t)laar->laar_pkt.lap_id,
		    (mod_hash_val_t)laar) == 0);
		VERIFY(mod_hash_insert(data->lav_path_hash,
		    (mod_hash_key_t)lx_autofs_strdup(nm),
		    (mod_hash_val_t)laar) == 0);

		*is_dup = 0;
	}
	mutex_exit(&data->lav_lock);

	return (laar);
}

static lx_autofs_automnt_req_t *
lx_autofs_la_find(lx_autofs_vfs_t *data, int id)
{
	lx_autofs_automnt_req_t	*laar;

	/* Check for an outstanding request for this id. */
	mutex_enter(&data->lav_lock);
	if (mod_hash_find(data->lav_id_hash, (mod_hash_key_t)(uintptr_t)id,
	    (mod_hash_val_t *)&laar) != 0) {
		mutex_exit(&data->lav_lock);
		return (NULL);
	}
	atomic_add_int(&laar->laar_ref, 1);
	mutex_exit(&data->lav_lock);
	return (laar);
}

static void
lx_autofs_la_complete(lx_autofs_vfs_t *data, lx_autofs_automnt_req_t *laar)
{
	lx_autofs_automnt_req_t	*laar_tmp;

	/* Remove this request from the hashes so no one can look it up. */
	mutex_enter(&data->lav_lock);
	(void) mod_hash_remove(data->lav_id_hash,
	    (mod_hash_key_t)(uintptr_t)laar->laar_pkt.lap_id,
	    (mod_hash_val_t)&laar_tmp);
	if (data->lav_min_proto == 5) {
		(void) mod_hash_remove(data->lav_path_hash,
		    (mod_hash_key_t)laar->laar_pkt.lap_v5.lap_name,
		    (mod_hash_val_t)&laar_tmp);
	} else {
		(void) mod_hash_remove(data->lav_path_hash,
		    (mod_hash_key_t)laar->laar_pkt.lap_v2.lap_name,
		    (mod_hash_val_t)&laar_tmp);
	}
	mutex_exit(&data->lav_lock);

	/* Mark this requst as complete and wakeup anyone waiting on it. */
	mutex_enter(&laar->laar_lock);
	laar->laar_complete = 1;
	cv_broadcast(&laar->laar_cv);
	mutex_exit(&laar->laar_lock);
}

static void
lx_autofs_la_release(lx_autofs_vfs_t *data, lx_autofs_automnt_req_t *laar)
{
	ASSERT(!MUTEX_HELD(&laar->laar_lock));
	if (atomic_add_int_nv(&laar->laar_ref, -1) > 0)
		return;
	ASSERT(laar->laar_ref == 0);
	id_free(data->lav_ids, laar->laar_pkt.lap_id);
	kmem_free(laar, sizeof (*laar));
}

static void
lx_autofs_la_abort(lx_autofs_vfs_t *data, lx_autofs_automnt_req_t *laar)
{
	lx_autofs_automnt_req_t	*laar_tmp;

	/*
	 * This is a little tricky.  We're aborting the wait for this
	 * request.  So if anyone else is waiting for this request we
	 * can't free it, but if no one else is waiting for the request
	 * we should free it.
	 */
	mutex_enter(&data->lav_lock);
	if (atomic_add_int_nv(&laar->laar_ref, -1) > 0) {
		mutex_exit(&data->lav_lock);
		return;
	}
	ASSERT(laar->laar_ref == 0);

	/* Remove this request from the hashes so no one can look it up. */
	(void) mod_hash_remove(data->lav_id_hash,
	    (mod_hash_key_t)(uintptr_t)laar->laar_pkt.lap_id,
	    (mod_hash_val_t)&laar_tmp);
	if (data->lav_min_proto == 5) {
		(void) mod_hash_remove(data->lav_path_hash,
		    (mod_hash_key_t)laar->laar_pkt.lap_v5.lap_name,
		    (mod_hash_val_t)&laar_tmp);
	} else {
		(void) mod_hash_remove(data->lav_path_hash,
		    (mod_hash_key_t)laar->laar_pkt.lap_v2.lap_name,
		    (mod_hash_val_t)&laar_tmp);
	}
	mutex_exit(&data->lav_lock);

	/* It's ok to free this now because the ref count was zero. */
	id_free(data->lav_ids, laar->laar_pkt.lap_id);
	kmem_free(laar, sizeof (*laar));
}

static int
lx_autofs_fifo_lookup(pid_t pgrp, int fd, file_t **fpp_wr, file_t **fpp_rd)
{
	proc_t		*prp;
	uf_info_t	*fip;
	uf_entry_t	*ufp_wr, *ufp_rd = NULL;
	file_t		*fp_wr, *fp_rd = NULL;
	vnode_t		*vp_wr, *vp_rd;
	int		i;

	/*
	 * sprlock() is zone aware, so assuming this mount call was
	 * initiated by a process in a zone, if it tries to specify
	 * a pgrp outside of it's zone this call will fail.
	 *
	 * Also, we want to grab hold of the main automounter process
	 * and its going to be the group leader for pgrp, so its
	 * pid will be equal to pgrp.
	 */
	prp = sprlock(pgrp);
	if (prp == NULL)
		return (-1);
	mutex_exit(&prp->p_lock);

	/* Now we want to access the processes open file descriptors. */
	fip = P_FINFO(prp);
	mutex_enter(&fip->fi_lock);

	/* Sanity check fifo write fd. */
	if (fd >= fip->fi_nfiles) {
		mutex_exit(&fip->fi_lock);
		mutex_enter(&prp->p_lock);
		sprunlock(prp);
		return (-1);
	}

	/* Get a pointer to the write fifo. */
	UF_ENTER(ufp_wr, fip, fd);
	if (((fp_wr = ufp_wr->uf_file) == NULL) ||
	    ((vp_wr = fp_wr->f_vnode) == NULL) || (vp_wr->v_type != VFIFO)) {
		/* Invalid fifo fd. */
		UF_EXIT(ufp_wr);
		mutex_exit(&fip->fi_lock);
		mutex_enter(&prp->p_lock);
		sprunlock(prp);
		return (-1);
	}

	/*
	 * Now we need to find the read end of the fifo (for reasons
	 * explained below.)  We assume that the read end of the fifo
	 * is in the same process as the write end.
	 */
	vp_rd = lx_autofs_fifo_peer_vp(fp_wr->f_vnode);
	for (i = 0; i < fip->fi_nfiles; i++) {
		if (i == fd)
			continue;
		UF_ENTER(ufp_rd, fip, i);
		if (((fp_rd = ufp_rd->uf_file) != NULL) &&
		    (fp_rd->f_vnode == vp_rd))
			break;
		UF_EXIT(ufp_rd);
	}
	if (i == fip->fi_nfiles) {
		/* Didn't find it. */
		UF_EXIT(ufp_wr);
		mutex_exit(&fip->fi_lock);
		mutex_enter(&prp->p_lock);
		sprunlock(prp);
		return (-1);
	}

	/*
	 * We need to drop fi_lock before we can try to acquire f_tlock
	 * the good news is that the file pointers are protected because
	 * we're still holding uf_lock.
	 */
	mutex_exit(&fip->fi_lock);

	/*
	 * Here we bump the open counts on the fifos.  The reason
	 * that we do this is because when we go to write to the
	 * fifo we want to ensure that they are actually open (and
	 * not in the process of being closed) without having to
	 * stop the automounter.  (If the write end of the fifo
	 * were closed and we tried to write to it we would panic.
	 * If the read end of the fifo was closed and we tried to
	 * write to the other end, the process that invoked the
	 * lookup operation would get an unexpected SIGPIPE.)
	 */
	mutex_enter(&fp_wr->f_tlock);
	fp_wr->f_count++;
	ASSERT(fp_wr->f_count >= 2);
	mutex_exit(&fp_wr->f_tlock);

	mutex_enter(&fp_rd->f_tlock);
	fp_rd->f_count++;
	ASSERT(fp_rd->f_count >= 2);
	mutex_exit(&fp_rd->f_tlock);

	/* Release all our locks. */
	UF_EXIT(ufp_wr);
	UF_EXIT(ufp_rd);
	mutex_enter(&prp->p_lock);
	sprunlock(prp);

	/* Return the file pointers. */
	*fpp_rd = fp_rd;
	*fpp_wr = fp_wr;
	return (0);
}

static uint_t
/*ARGSUSED*/
lx_autofs_fifo_close_cb(mod_hash_key_t key, mod_hash_val_t *val, void *arg)
{
	int	*id = (int *)arg;
	/* Return the key and terminate the walk. */
	*id = (uintptr_t)key;
	return (MH_WALK_TERMINATE);
}

static void
lx_autofs_fifo_close(lx_autofs_vfs_t *data)
{
	/*
	 * Close the fifo to prevent any future requests from
	 * getting sent to the automounter.
	 */
	mutex_enter(&data->lav_lock);
	if (data->lav_fifo_wr != NULL) {
		(void) closef(data->lav_fifo_wr);
		data->lav_fifo_wr = NULL;
	}
	if (data->lav_fifo_rd != NULL) {
		(void) closef(data->lav_fifo_rd);
		data->lav_fifo_rd = NULL;
	}
	mutex_exit(&data->lav_lock);

	/*
	 * Wakeup any threads currently waiting for the automounter
	 * note that it's possible for multiple threads to have entered
	 * this function and to be doing the work below simultaneously.
	 */
	for (;;) {
		lx_autofs_automnt_req_t	*laar;
		int			id;

		/* Lookup the first entry in the hash. */
		id = -1;
		mod_hash_walk(data->lav_id_hash,
		    lx_autofs_fifo_close_cb, &id);
		if (id == -1) {
			/* No more id's in the hash. */
			break;
		}
		if ((laar = lx_autofs_la_find(data, id)) == NULL) {
			/* Someone else beat us to it. */
			continue;
		}

		/* Mark the request as complete and release it. */
		lx_autofs_la_complete(data, laar);
		lx_autofs_la_release(data, laar);
	}
}

static int
lx_autofs_fifo_verify_rd(lx_autofs_vfs_t *data)
{
	proc_t		*prp;
	uf_info_t	*fip;
	uf_entry_t	*ufp_rd = NULL;
	file_t		*fp_rd =  NULL;
	vnode_t		*vp_rd;
	int		i;

	ASSERT(MUTEX_HELD((&data->lav_lock)));

	/* Check if we've already been shut down. */
	if (data->lav_fifo_wr == NULL) {
		ASSERT(data->lav_fifo_rd == NULL);
		return (-1);
	}
	vp_rd = lx_autofs_fifo_peer_vp(data->lav_fifo_wr->f_vnode);

	/*
	 * sprlock() is zone aware, so assuming this mount call was
	 * initiated by a process in a zone, if it tries to specify
	 * a pgrp outside of it's zone this call will fail.
	 *
	 * Also, we want to grab hold of the main automounter process
	 * and its going to be the group leader for pgrp, so its
	 * pid will be equal to pgrp.
	 */
	prp = sprlock(data->lav_pgrp);
	if (prp == NULL)
		return (-1);
	mutex_exit(&prp->p_lock);

	/* Now we want to access the processes open file descriptors. */
	fip = P_FINFO(prp);
	mutex_enter(&fip->fi_lock);

	/*
	 * Now we need to find the read end of the fifo (for reasons
	 * explained below.)  We assume that the read end of the fifo
	 * is in the same process as the write end.
	 */
	for (i = 0; i < fip->fi_nfiles; i++) {
		UF_ENTER(ufp_rd, fip, i);
		if (((fp_rd = ufp_rd->uf_file) != NULL) &&
		    (fp_rd->f_vnode == vp_rd))
			break;
		UF_EXIT(ufp_rd);
	}
	if (i == fip->fi_nfiles) {
		/* Didn't find it. */
		mutex_exit(&fip->fi_lock);
		mutex_enter(&prp->p_lock);
		sprunlock(prp);
		return (-1);
	}

	/*
	 * Seems the automounter still has the read end of the fifo
	 * open, we're done here.  Release all our locks and exit.
	 */
	mutex_exit(&fip->fi_lock);
	UF_EXIT(ufp_rd);
	mutex_enter(&prp->p_lock);
	sprunlock(prp);

	return (0);
}

static int
lx_autofs_fifo_write(lx_autofs_vfs_t *data, lx_autofs_automnt_req_t *laarp)
{
	struct uio	uio;
	struct iovec	iov;
	file_t		*fp_wr, *fp_rd;
	int		error;

	/*
	 * The catch here is we need to make sure _we_ don't close
	 * the the fifo while writing to it.  (Another thread could come
	 * along and realize the automounter process is gone and close
	 * the fifo.  To do this we bump the open count before we
	 * write to the fifo.
	 */
	mutex_enter(&data->lav_lock);
	if (data->lav_fifo_wr == NULL) {
		ASSERT(data->lav_fifo_rd == NULL);
		mutex_exit(&data->lav_lock);
		return (ENOENT);
	}
	fp_wr = data->lav_fifo_wr;
	fp_rd = data->lav_fifo_rd;

	/* Bump the open count on the write fifo. */
	mutex_enter(&fp_wr->f_tlock);
	fp_wr->f_count++;
	mutex_exit(&fp_wr->f_tlock);

	/* Bump the open count on the read fifo. */
	mutex_enter(&fp_rd->f_tlock);
	fp_rd->f_count++;
	mutex_exit(&fp_rd->f_tlock);

	mutex_exit(&data->lav_lock);

	iov.iov_base = (caddr_t)&laarp->laar_pkt;
	iov.iov_len = laarp->laar_pkt_size;
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_loffset = 0;
	uio.uio_segflg = (short)UIO_SYSSPACE;
	uio.uio_resid = laarp->laar_pkt_size;
	uio.uio_llimit = 0;
	uio.uio_fmode = FWRITE | FNDELAY | FNONBLOCK;

	error = VOP_WRITE(fp_wr->f_vnode, &uio, 0, kcred, NULL);
	(void) closef(fp_wr);
	(void) closef(fp_rd);

	/*
	 * After every write we verify that the automounter still has
	 * these files open.
	 */
	mutex_enter(&data->lav_lock);
	if (lx_autofs_fifo_verify_rd(data) != 0) {
		/*
		 * Something happened to the automounter.
		 * Close down the communication pipe we setup.
		 */
		mutex_exit(&data->lav_lock);
		lx_autofs_fifo_close(data);
		if (error != 0)
			return (error);
		return (ENOENT);
	}
	mutex_exit(&data->lav_lock);

	return (error);
}

static int
lx_autofs_bs_readdir(vnode_t *dvp, list_t *dir_stack, list_t *file_stack)
{
	struct iovec	iov;
	struct uio	uio;
	dirent64_t	*dp, *dbuf;
	vnode_t		*vp;
	size_t		dlen, dbuflen;
	int		eof, error, ndirents = 64;
	char		*nm;

	dlen = ndirents * (sizeof (*dbuf));
	dbuf = kmem_alloc(dlen, KM_SLEEP);

	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_fmode = 0;
	uio.uio_extflg = UIO_COPY_CACHED;
	uio.uio_loffset = 0;
	uio.uio_llimit = MAXOFFSET_T;

	eof = 0;
	error = 0;
	while (!error && !eof) {
		uio.uio_resid = dlen;
		iov.iov_base = (char *)dbuf;
		iov.iov_len = dlen;

		(void) VOP_RWLOCK(dvp, V_WRITELOCK_FALSE, NULL);
		if (VOP_READDIR(dvp, &uio, kcred, &eof, NULL, 0) != 0) {
			VOP_RWUNLOCK(dvp, V_WRITELOCK_FALSE, NULL);
			kmem_free(dbuf, dlen);
			return (-1);
		}
		VOP_RWUNLOCK(dvp, V_WRITELOCK_FALSE, NULL);

		if ((dbuflen = dlen - uio.uio_resid) == 0) {
			/* We're done. */
			break;
		}

		for (dp = dbuf; ((intptr_t)dp < (intptr_t)dbuf + dbuflen);
		    dp = (dirent64_t *)((intptr_t)dp + dp->d_reclen)) {

			nm = dp->d_name;

			if (strcmp(nm, ".") == 0 || strcmp(nm, "..") == 0)
				continue;

			if (VOP_LOOKUP(dvp, nm, &vp, NULL, 0, NULL, kcred,
			    NULL, NULL, NULL) != 0) {
				kmem_free(dbuf, dlen);
				return (-1);
			}
			if (vp->v_type == VDIR) {
				if (dir_stack != NULL) {
					lx_autofs_stack_push(dir_stack,
					    (caddr_t)dvp,
					    (caddr_t)vp, lx_autofs_strdup(nm));
				} else {
					VN_RELE(vp);
				}
			} else {
				if (file_stack != NULL) {
					lx_autofs_stack_push(file_stack,
					    (caddr_t)dvp,
					    (caddr_t)vp, lx_autofs_strdup(nm));
				} else {
					VN_RELE(vp);
				}
			}
		}
	}
	kmem_free(dbuf, dlen);
	return (0);
}

static void
lx_autofs_bs_destroy(vnode_t *dvp, char *path)
{
	list_t	search_stack;
	list_t	dir_stack;
	list_t	file_stack;
	vnode_t	*pdvp, *vp;
	char	*dpath, *fpath;
	int	ret;

	if (VOP_LOOKUP(dvp, path, &vp, NULL, 0, NULL, kcred,
	    NULL, NULL, NULL) != 0) {
		/* A directory entry with this name doesn't actually exist. */
		return;
	}

	if ((vp->v_type & VDIR) == 0) {
		/* Easy, the directory entry is a file so delete it. */
		VN_RELE(vp);
		(void) VOP_REMOVE(dvp, path, kcred, NULL, 0);
		return;
	}

	/*
	 * The directory entry is a subdirectory, now we have a bit more
	 * work to do.  (We'll have to recurse into the sub directory.)
	 * It would have been much easier to do this recursively but kernel
	 * stacks are notoriously small.
	 */
	ls_autofs_stack_init(&search_stack);
	ls_autofs_stack_init(&dir_stack);
	ls_autofs_stack_init(&file_stack);

	/* Save our newfound subdirectory into a list. */
	lx_autofs_stack_push(&search_stack, (caddr_t)dvp, (caddr_t)vp,
	    lx_autofs_strdup(path));

	/* Do a recursive depth first search into the subdirectories. */
	while (lx_autofs_stack_pop(&search_stack,
	    (caddr_t *)&pdvp, (caddr_t *)&dvp, &dpath) == 0) {

		/* Get a list of the subdirectories in this directory. */
		if (lx_autofs_bs_readdir(dvp, &search_stack, NULL) != 0)
			goto exit;

		/* Save the current directory a separate stack. */
		lx_autofs_stack_push(&dir_stack, (caddr_t)pdvp, (caddr_t)dvp,
		    dpath);
	}

	/*
	 * Now dir_stack contains a list of directories, the deepest paths
	 * are at the top of the list.  So let's go through and process them.
	 */
	while (lx_autofs_stack_pop(&dir_stack,
	    (caddr_t *)&pdvp, (caddr_t *)&dvp, &dpath) == 0) {

		/* Get a list of the files in this directory. */
		if (lx_autofs_bs_readdir(dvp, NULL, &file_stack) != 0) {
			VN_RELE(dvp);
			lx_autofs_strfree(dpath);
			goto exit;
		}

		/* Delete all the files in this directory. */
		while (lx_autofs_stack_pop(&file_stack,
		    NULL, (caddr_t *)&vp, &fpath) == 0) {
			VN_RELE(vp)
			ret = VOP_REMOVE(dvp, fpath, kcred, NULL, 0);
			lx_autofs_strfree(fpath);
			if (ret != 0) {
				lx_autofs_strfree(dpath);
				goto exit;
			}
		}

		/* Delete this directory. */
		VN_RELE(dvp);
		ret = VOP_RMDIR(pdvp, dpath, pdvp, kcred, NULL, 0);
		lx_autofs_strfree(dpath);
		if (ret != 0)
			goto exit;
	}

exit:
	while (
	    (lx_autofs_stack_pop(&search_stack, NULL, (caddr_t *)&vp,
	    &path) == 0) ||
	    (lx_autofs_stack_pop(&dir_stack, NULL, (caddr_t *)&vp,
	    &path) == 0) ||
	    (lx_autofs_stack_pop(&file_stack, NULL, (caddr_t *)&vp,
	    &path) == 0)) {
		VN_RELE(vp);
		lx_autofs_strfree(path);
	}
	lx_autofs_stack_fini(&search_stack);
	lx_autofs_stack_fini(&dir_stack);
	lx_autofs_stack_fini(&file_stack);
}

static vnode_t *
lx_autofs_bs_create(vnode_t *dvp, char *bs_name)
{
	vnode_t	*vp;
	vattr_t	vattr;

	/*
	 * After looking at the mkdir syscall path it seems we don't need
	 * to initialize all of the vattr_t structure.
	 */
	bzero(&vattr, sizeof (vattr));
	vattr.va_type = VDIR;
	vattr.va_mode = 0755; /* u+rwx,og=rx */
	vattr.va_mask = AT_TYPE|AT_MODE;

	if (VOP_MKDIR(dvp, bs_name, &vattr, &vp, kcred, NULL, 0, NULL) != 0)
		return (NULL);
	return (vp);
}

static int
lx_autofs_automounter_call(vnode_t *dvp, char *nm)
{
	lx_autofs_automnt_req_t	*laar;
	lx_autofs_vfs_t		*data;
	int			error;
	boolean_t		is_dup;

	/* Get a pointer to the vfs mount data. */
	data = dvp->v_vfsp->vfs_data;

	/* The automounter only supports queries in the root directory. */
	if (dvp != data->lav_root)
		return (ENOENT);

	/*
	 * Check if the current process is in the automounters process
	 * group.  (If it is, the current process is either the autmounter
	 * itself or one of it's forked child processes.)  If so, don't
	 * redirect this call back into the automounter because we'll
	 * hang.
	 */
	mutex_enter(&pidlock);
	if (data->lav_pgrp == curproc->p_pgrp) {
		mutex_exit(&pidlock);
		return (ENOENT);
	}
	mutex_exit(&pidlock);

	/* Verify that the automount process pipe still exists. */
	mutex_enter(&data->lav_lock);
	if (data->lav_fifo_wr == NULL) {
		ASSERT(data->lav_fifo_rd == NULL);
		mutex_exit(&data->lav_lock);
		return (ENOENT);
	}
	mutex_exit(&data->lav_lock);

	/* Allocate an automounter request structure. */
	if ((laar = lx_autofs_la_alloc(data, &is_dup, B_FALSE,
	    nm)) == NULL)
		return (ENOENT);

	/*
	 * If we were the first one to allocate this request then we
	 * need to send it to the automounter.
	 */
	if ((!is_dup) &&
	    ((error = lx_autofs_fifo_write(data, laar)) != 0)) {
		/*
		 * Unable to send the request to the automounter.
		 * Unblock any other threads waiting on the request
		 * and release the request.
		 */
		lx_autofs_la_complete(data, laar);
		lx_autofs_la_release(data, laar);
		return (error);
	}

	/* Wait for someone to signal us that this request has completed. */
	mutex_enter(&laar->laar_lock);
	while (!laar->laar_complete) {
		if (cv_wait_sig(&laar->laar_cv, &laar->laar_lock) == 0) {
			/* We got a signal, abort this call. */
			mutex_exit(&laar->laar_lock);
			lx_autofs_la_abort(data, laar);
			return (EINTR);
		}
	}
	mutex_exit(&laar->laar_lock);

	if (laar->laar_result == LXACR_READY) {
		/*
		 * Mount succeeded, keep track for future expire calls.
		 *
		 * See vfs lav_vn_hash. Is this something we could use for
		 * iterating mounts under this autofs? Used by
		 * lx_autofs_vn_alloc
		 */
		lx_autofs_mntent_t *mp;

		mp = kmem_zalloc(sizeof (lx_autofs_mntent_t), KM_SLEEP);
		mp->lxafme_len = strlen(nm) + 1;
		mp->lxafme_path = kmem_zalloc(mp->lxafme_len, KM_SLEEP);
		mp->lxafme_ts = TICK_TO_SEC(ddi_get_lbolt64());
		(void) strlcpy(mp->lxafme_path, nm, mp->lxafme_len);

		mutex_enter(&data->lav_lock);
		list_insert_tail(&data->lav_mnt_list, mp);
		mutex_exit(&data->lav_lock);
	}

	lx_autofs_la_release(data, laar);

	return (0);
}

/*
 * Same preliminary checks as in lx_autofs_unmount.
 */
static boolean_t
lx_autofs_may_unmount(vfs_t *vfsp, struct cred *cr)
{
	lx_autofs_vfs_t *data;

	if (secpolicy_fs_unmount(cr, vfsp) != 0)
		return (B_FALSE);

	/*
	 * We should never have a reference count of less than 2: one for the
	 * caller, one for the root vnode.
	 */
	ASSERT(vfsp->vfs_count >= 2);

	/* If there are any outstanding vnodes, we can't unmount. */
	if (vfsp->vfs_count > 2)
		return (B_FALSE);

	/* Check for any remaining holds on the root vnode. */
	data = vfsp->vfs_data;
	ASSERT(data->lav_root->v_vfsp == vfsp);
	if (data->lav_root->v_count > 1)
		return (B_FALSE);

	return (B_TRUE);
}

static vfs_t *
lx_autofs_get_mountvfs(char *fs_mntpt, int *cnt)
{
	struct vfs *vfsp;
	struct vfs *vfslist;
	vfs_t *fnd_vfs = NULL;
	int fsmplen;
	int acnt = 0;

	fsmplen = strlen(fs_mntpt);

	vfs_list_read_lock();

	vfsp = vfslist = curzone->zone_vfslist;
	if (vfslist == NULL) {
		vfs_list_unlock();
		*cnt = 0;
		return (NULL);
	}

	do {
		/* Skip mounts we shouldn't show. */
		if (!(vfsp->vfs_flag & VFS_NOMNTTAB)) {
			char *mntpt;

			mntpt = (char *)refstr_value(vfsp->vfs_mntpt);
			if (strncmp(fs_mntpt, mntpt, fsmplen) == 0 &&
			    (mntpt[fsmplen] == '\0' || mntpt[fsmplen] == '/')) {
				/*
				 * We'll return the first one we find but don't
				 * return a mount that is actually autofs (i.e.
				 * autofs direct or offset mount).
				 */
				if (vfsp->vfs_op == lx_autofs_vfsops) {
					acnt++;
				} else if (fnd_vfs == NULL) {
					fnd_vfs = vfsp;
					VFS_HOLD(fnd_vfs)
				}
			}
		}
		vfsp = vfsp->vfs_zone_next;
	} while (vfsp != vfslist);

	vfs_list_unlock();

	*cnt = acnt;
	return (fnd_vfs);
}

/*
 * Unmount all autofs offset mounts below the given path.
 */
static boolean_t
lx_autofs_umount_offset(char *fs_mntpt, struct cred *cr)
{
	struct vfs *vfsp;
	struct vfs *vfslist;
	boolean_t busy = B_FALSE;
	int fsmplen = strlen(fs_mntpt);

restart:
	vfs_list_read_lock();

	vfsp = vfslist = curzone->zone_vfslist;
	if (vfslist == NULL) {
		vfs_list_unlock();
		return (B_FALSE);
	}

	do {
		char *mntpt;
		lx_autofs_vfs_t *data;

		/* Skip mounts we should ignore. */
		if ((vfsp->vfs_flag & VFS_NOMNTTAB)) {
			vfsp = vfsp->vfs_zone_next;
			continue;
		}

		mntpt = (char *)refstr_value(vfsp->vfs_mntpt);
		if (strncmp(fs_mntpt, mntpt, fsmplen) != 0 ||
		    (mntpt[fsmplen] != '\0' && mntpt[fsmplen] != '/')) {
			vfsp = vfsp->vfs_zone_next;
			continue;
		}

		if (vfsp->vfs_op != lx_autofs_vfsops) {
			/*
			 * Something got mounted over the autofs mountpoint
			 * after we checked that this inidrect hierarchy was
			 * not busy.
			 */
			busy = B_TRUE;
			break;
		}

		data = (lx_autofs_vfs_t *)vfsp->vfs_data;
		if (data->lav_mnttype != LXAMT_OFFSET) {
			/*
			 * Something mounted a non-offset autofs fs under this
			 * indirect mnt!
			 */
			busy = B_TRUE;
			break;
		}

		/*
		 * Attempt to umount - set busy if fails.
		 *
		 * umount2_engine will call VFS_RELE, so we need to take an
		 * extra hold to match the behavior during the normal umount
		 * path.
		 *
		 * We also need to drop the list lock to prevent deadlock
		 * during umount.
		 */
		VFS_HOLD(vfsp);
		vfs_list_unlock();
		if (umount2_engine(vfsp, 0, cr, 0) != 0) {
			busy = B_TRUE;
			goto errexit;
		}

		/* Retake list lock and look for more. */
		goto restart;
	} while (vfsp != vfslist);

	vfs_list_unlock();

errexit:
	return (busy);
}


/*
 * Note that lx_autofs_automounter_call() only supports queries in the root
 * directory, so all mntent names are relative to that.
 */
static void
lx_autofs_expire(vfs_t *vfsp, struct cred *cr)
{
	lx_autofs_vfs_t *data;
	lx_autofs_mntent_t *mp;
	lx_autofs_automnt_req_t	*laar;
	boolean_t is_dup;
	vfs_t *fnd_vfs;
	int autofs_cnt;
	boolean_t busy = B_FALSE;
	char exp_path[MAXPATHLEN];

	data = vfsp->vfs_data;

	/*
	 * We process only the first element (i.e. do not do multi). This
	 * works fine for the automounter.
	 */
	mutex_enter(&data->lav_lock);
	mp = (lx_autofs_mntent_t *)list_remove_head(&data->lav_mnt_list);
	mutex_exit(&data->lav_lock);
	if (mp == NULL)
		return;

	/*
	 * We only return an expired mount if it is inactive for the full
	 * timeout. This reduces overly aggressive umount/mount activity.
	 */
	if (data->lav_timeout > 0) {
		uint64_t now = TICK_TO_SEC(ddi_get_lbolt64());

		if ((now - mp->lxafme_ts) < data->lav_timeout) {
			/* put it back at the end of the line */
			mutex_enter(&data->lav_lock);
			list_insert_tail(&data->lav_mnt_list, mp);
			mutex_exit(&data->lav_lock);
			return;
		}
	}

	if (data->lav_mnttype == LXAMT_INDIR) {
		(void) snprintf(exp_path, sizeof (exp_path), "%s/%s",
		    (char *)refstr_value(vfsp->vfs_mntpt), mp->lxafme_path);
	} else {
		(void) strlcpy(exp_path, (char *)refstr_value(vfsp->vfs_mntpt),
		    sizeof (exp_path));
	}

	fnd_vfs = lx_autofs_get_mountvfs(exp_path, &autofs_cnt);
	if (fnd_vfs != NULL) {
		boolean_t skip = B_FALSE;
		vfssw_t *vfssw;
		char *vfsmp = (char *)refstr_value(fnd_vfs->vfs_mntpt);

		/*
		 * Check if we found a sub-mount. This happens with an offset
		 * mount below an indirect mount subdirectory.
		 */
		if (strcmp(exp_path, vfsmp) != 0) {
			busy = B_TRUE;
			skip = B_TRUE;
		}

		/*
		 * If it's an NFS file system (typical) then we check in
		 * advance to see if it can be unmounted, otherwise, proceed.
		 * The fs-specific umount attempted by the automounter will
		 * either succeed or fail. Both are valid outcomes but checking
		 * now for nfs will save a bunch of work by the automounter
		 * if the fs is busy.
		 *
		 * Unfortunately, for NFS the vfs_fstype is the same for all
		 * versions of NFS, so we need to check the vfs_op member to
		 * determine which version of NFS we're dealing with.
		 */
		if (!skip && (vfssw = vfs_getvfssw("nfs4")) != NULL) {
			if (vfs_matchops(fnd_vfs, &vfssw->vsw_vfsops)) {
				(void) dnlc_purge_vfsp(fnd_vfs, 0);
				if (check_rtable4(fnd_vfs))
					busy = B_TRUE;
				skip = B_TRUE;
			}
			vfs_unrefvfssw(vfssw);
		}

		if (!skip && (vfssw = vfs_getvfssw("nfs3")) != NULL) {
			if (vfs_matchops(fnd_vfs, &vfssw->vsw_vfsops)) {
				(void) dnlc_purge_vfsp(fnd_vfs, 0);
				if (check_rtable(fnd_vfs))
					busy = B_TRUE;
			}
			vfs_unrefvfssw(vfssw);
		}

		VFS_RELE(fnd_vfs);

	} else if (autofs_cnt > 0) {
		/*
		 * The automounter is asking us to expire and we pulled this
		 * name from our vfs mountpoint list, but if
		 * lx_autofs_get_mountvfs returns null then that means we
		 * didn't find a non-autofs mount under this name. Thus, the
		 * name could be a subdirectory under an autofs toplevel
		 * indirect mount with one or more offset mounts below.
		 * autofs_cnt will indicate how many autofs mounts exist below
		 * this subdirectory name.
		 *
		 * The automounter will take care of unmounting any fs mounted
		 * over one of these offset mounts (i.e. offset is like a
		 * direct mount which the automounter will manage) but the
		 * automounter will not unmount the actual autofs offset mount
		 * itself, so we have to do that before we can expire the
		 * top-level subrectory name.
		 */
		busy = lx_autofs_umount_offset(exp_path, cr);
	}

	if (busy) {
		/*
		 * Can't unmount this one right now, put it at the end of the
		 * list and return. The caller will return EAGAIN for the
		 * expire ioctl and the automounter will check again later.
		 */
		mp->lxafme_ts = TICK_TO_SEC(ddi_get_lbolt64());
		mutex_enter(&data->lav_lock);
		list_insert_tail(&data->lav_mnt_list, mp);
		mutex_exit(&data->lav_lock);
		return;
	}

	/*
	 * See lx_autofs_automounter_call. We want to send a msg up the pipe
	 * to the automounter in a similar way.
	 */

	/* Verify that the automount process pipe still exists. */
	mutex_enter(&data->lav_lock);
	if (data->lav_fifo_wr == NULL) {
		ASSERT(data->lav_fifo_rd == NULL);
		mutex_exit(&data->lav_lock);
		goto err_free;
	}
	mutex_exit(&data->lav_lock);

	/* Allocate an automounter expire structure. */
	if ((laar = lx_autofs_la_alloc(data, &is_dup, B_TRUE,
	    mp->lxafme_path)) == NULL)
		goto err_free;

	/*
	 * If we were the first one to allocate this request then we
	 * need to send it to the automounter.
	 */
	if (!is_dup && lx_autofs_fifo_write(data, laar) != 0) {
		/*
		 * Unable to send the request to the automounter.
		 * Unblock any other threads waiting on the request
		 * and release the request.
		 */
		lx_autofs_la_complete(data, laar);
		lx_autofs_la_release(data, laar);
		goto err_free;
	}

	/* Wait for someone to signal us that this request has completed. */
	mutex_enter(&laar->laar_lock);
	while (!laar->laar_complete) {
		if (cv_wait_sig(&laar->laar_cv, &laar->laar_lock) == 0) {
			/* We got a signal, abort this request. */
			mutex_exit(&laar->laar_lock);
			lx_autofs_la_abort(data, laar);
			goto err_free;
		}
	}
	mutex_exit(&laar->laar_lock);

	/*
	 * If it failed or if the file system is still mounted after we get the
	 * response from our expire msg, then that means the automounter tried
	 * to unmount it but failed because the file system is busy, so we put
	 * this entry back on our list to try to expire it again later.
	 */
	fnd_vfs = NULL;
	if (laar->laar_result == LXACR_FAIL ||
	    (fnd_vfs = lx_autofs_get_mountvfs(exp_path, &autofs_cnt)) != NULL ||
	    autofs_cnt > 0) {
		if (fnd_vfs != NULL)
			VFS_RELE(fnd_vfs);
		mp->lxafme_ts = TICK_TO_SEC(ddi_get_lbolt64());
		mutex_enter(&data->lav_lock);
		list_insert_tail(&data->lav_mnt_list, mp);
		mutex_exit(&data->lav_lock);
	} else {
		kmem_free(mp->lxafme_path, mp->lxafme_len);
		kmem_free(mp, sizeof (lx_autofs_mntent_t));
	}

	lx_autofs_la_release(data, laar);
	return;

err_free:
	kmem_free(mp->lxafme_path, mp->lxafme_len);
	kmem_free(mp, sizeof (lx_autofs_mntent_t));
}

static int
lx_autofs_automounter_ioctl(vnode_t *vp, int cmd, intptr_t arg, cred_t *cr)
{
	lx_autofs_vfs_t *data = (lx_autofs_vfs_t *)vp->v_vfsp->vfs_data;
	lx_autofs_automnt_req_t	*laar;
	int			id = arg;
	int			v;

	/*
	 * Be strict.
	 * We only accept ioctls from the automounter process group.
	 */
	mutex_enter(&pidlock);
	if (data->lav_pgrp != curproc->p_pgrp) {
		mutex_exit(&pidlock);
		return (ENOENT);
	}
	mutex_exit(&pidlock);

	switch (cmd) {
	case LX_AUTOFS_IOC_READY:
	case LX_AUTOFS_IOC_FAIL:
		/*
		 * We don't actually care if the request failed or succeeded.
		 * We do the same thing either way.
		 */
		if ((laar = lx_autofs_la_find(data, id)) == NULL)
			return (ENXIO);

		laar->laar_result = ((cmd == LX_AUTOFS_IOC_READY) ?
		    LXACR_READY : LXACR_FAIL);

		/* Mark the request as complete and release it. */
		lx_autofs_la_complete(data, laar);
		lx_autofs_la_release(data, laar);
		return (0);

	case LX_AUTOFS_IOC_CATATONIC:
		/* The automounter is shutting down. */
		lx_autofs_fifo_close(data);
		return (0);

	case LX_AUTOFS_IOC_PROTOVER:
		v = LX_AUTOFS_PROTO_VERS5;
		if (copyout(&v, (caddr_t)arg, sizeof (int)))
			return (set_errno(EFAULT));
		return (0);

	case LX_AUTOFS_IOC_PROTOSUBVER:
		v = LX_AUTOFS_PROTO_SUBVERSION;
		if (copyout(&v, (caddr_t)arg, sizeof (int)))
			return (set_errno(EFAULT));
		return (0);

	case LX_AUTOFS_IOC_ASKUMOUNT:
		/*
		 * This is asking if autofs can be unmounted, not asking to
		 * actually unmount it. We return 1 if it is busy or 0 if it
		 * can be unmounted.
		 */
		v = 1;
		if (lx_autofs_may_unmount(vp->v_vfsp, cr))
			v = 0;

		if (copyout(&v, (caddr_t)arg, sizeof (int)))
			return (set_errno(EFAULT));
		return (0);

	case LX_AUTOFS_IOC_SETTIMEOUT:
		/*
		 * We currently don't use the timeout, but we keep track of
		 * it in case we want to use it as an expiration hint in the
		 * future.
		 */
		if (copyin((caddr_t)arg, &data->lav_timeout, sizeof (ulong_t)))
			return (set_errno(EFAULT));
		return (0);

	case LX_AUTOFS_IOC_EXPIRE:
		return (ENOTSUP);

	case LX_AUTOFS_IOC_EXPIRE_MULTI:
		lx_autofs_expire(vp->v_vfsp, cr);
		return (EAGAIN);

	default:
		ASSERT(0);
		return (ENOTSUP);
	}
}

static int
lx_autofs_parse_mntopt(vfs_t *vfsp, lx_autofs_vfs_t *data)
{
	char		*fd_str, *pgrp_str, *minproto_str, *maxproto_str;
	int		fd, pgrp, minproto, maxproto;
	file_t		*fp_wr, *fp_rd;

	/* Require these options to be present. */
	if ((vfs_optionisset(vfsp, LX_MNTOPT_FD, &fd_str) != 1) ||
	    (vfs_optionisset(vfsp, LX_MNTOPT_PGRP, &pgrp_str) != 1) ||
	    (vfs_optionisset(vfsp, LX_MNTOPT_MINPROTO, &minproto_str) != 1) ||
	    (vfs_optionisset(vfsp, LX_MNTOPT_MAXPROTO, &maxproto_str) != 1))
		return (EINVAL);

	/* Get the values for each parameter. */
	if ((lx_autofs_str_to_int(fd_str, &fd) != 0) ||
	    (lx_autofs_str_to_int(pgrp_str, &pgrp) != 0) ||
	    (lx_autofs_str_to_int(minproto_str, &minproto) != 0) ||
	    (lx_autofs_str_to_int(maxproto_str, &maxproto) != 0))
		return (EINVAL);

	/*
	 * We primarily support v2 & v5 of the linux kernel automounter
	 * protocol. The userland daemon typically needs v5. We'll reject
	 * unsupported ioctls later if we get one.
	 */
	if ((minproto > 5) || (maxproto < 2))
		return (EINVAL);

	/*
	 * Now we need to lookup the fifos we'll be using
	 * to talk to the userland automounter process.
	 */
	if (lx_autofs_fifo_lookup(pgrp, fd, &fp_wr, &fp_rd) != 0) {
		/*
		 * The automounter doesn't always have the same id as the pgrp.
		 * This happens when it is started via one of the various
		 * service managers. In this case the fifo lookup will fail
		 * so we retry with our own pid.
		 */
		int pid = (int)curproc->p_pid;

		if (lx_autofs_fifo_lookup(pid, fd, &fp_wr, &fp_rd) != 0)
			return (EINVAL);
	}

	if (vfs_optionisset(vfsp, LX_MNTOPT_INDIRECT, NULL)) {
		data->lav_mnttype = LXAMT_INDIR;
	}
	if (vfs_optionisset(vfsp, LX_MNTOPT_DIRECT, NULL)) {
		if (data->lav_mnttype != LXAMT_NONE)
			return (EINVAL);
		data->lav_mnttype = LXAMT_DIRECT;
	}
	if (vfs_optionisset(vfsp, LX_MNTOPT_OFFSET, NULL)) {
		if (data->lav_mnttype != LXAMT_NONE)
			return (EINVAL);
		data->lav_mnttype = LXAMT_OFFSET;
	}
	/* The automounter does test mounts with none of the options */
	if (data->lav_mnttype == LXAMT_NONE)
		data->lav_mnttype = LXAMT_DIRECT;

	/* Save the mount options and fifo pointers. */
	data->lav_fd = fd;
	data->lav_min_proto = minproto;
	data->lav_pgrp = pgrp;
	data->lav_fifo_rd = fp_rd;
	data->lav_fifo_wr = fp_wr;
	return (0);
}

static uint64_t
s2l_dev(dev_t dev)
{
	major_t	maj = getmajor(dev);
	minor_t	min = getminor(dev);

	return (LX_MAKEDEVICE(maj, min));
}

/*
 * VFS entry points
 */
static int
lx_autofs_mount(vfs_t *vfsp, vnode_t *mvp, struct mounta *uap, cred_t *cr)
{
	lx_autofs_vfs_t	*data;
	dev_t		dev;
	char		name[40];
	int		error;
	vattr_t		va;

	if (secpolicy_fs_mount(cr, mvp, vfsp) != 0)
		return (EPERM);

	if (mvp->v_type != VDIR)
		return (ENOTDIR);

	if ((uap->flags & MS_OVERLAY) == 0 &&
	    (mvp->v_count > 1 || (mvp->v_flag & VROOT)))
		return (EBUSY);

	/* We don't support mounts in the global zone. */
	if (getzoneid() == GLOBAL_ZONEID)
		return (EPERM);

	/*
	 * Offset mounts will occur below the top-level mountpoint so we
	 * need to allow for autofs mounts even though mvp is an autofs.
	 */

	/* Allocate a vfs struct. */
	data = kmem_zalloc(sizeof (lx_autofs_vfs_t), KM_SLEEP);

	/* Parse mount options. */
	if ((error = lx_autofs_parse_mntopt(vfsp, data)) != 0) {
		kmem_free(data, sizeof (lx_autofs_vfs_t));
		return (error);
	}

	/* Initialize the backing store. */
	lx_autofs_bs_destroy(mvp, LX_AUTOFS_BS_DIR);
	data->lav_bs_vp = lx_autofs_bs_create(mvp, LX_AUTOFS_BS_DIR);
	if (data->lav_bs_vp == NULL) {
		kmem_free(data, sizeof (lx_autofs_vfs_t));
		return (EBUSY);
	}
	data->lav_bs_name = LX_AUTOFS_BS_DIR;

	/* Get the backing store inode for use in v5 protocol msgs */
	va.va_mask = AT_STAT;
	if ((error = VOP_GETATTR(data->lav_bs_vp, &va, 0, cr, NULL)) != 0) {
		kmem_free(data, sizeof (lx_autofs_vfs_t));
		return (error);
	}
	data->lav_ino = va.va_nodeid;

	/* We have to hold the underlying vnode we're mounted on. */
	data->lav_mvp = mvp;
	VN_HOLD(mvp);

	/* Initialize vfs fields */
	vfsp->vfs_bsize = DEV_BSIZE;
	vfsp->vfs_fstype = lx_autofs_fstype;
	vfsp->vfs_data = data;

	/* Invent a dev_t (sigh) */
	do {
		dev = makedevice(lx_autofs_major,
		    atomic_add_32_nv(&lx_autofs_minor, 1) & L_MAXMIN32);
	} while (vfs_devismounted(dev));
	vfsp->vfs_dev = dev;
	vfs_make_fsid(&vfsp->vfs_fsid, dev, lx_autofs_fstype);

	data->lav_dev = s2l_dev(vfsp->vfs_dev);

	/* Create an id space arena for automounter requests. */
	(void) snprintf(name, sizeof (name), "lx_autofs_id_%d",
	    getminor(vfsp->vfs_dev));
	data->lav_ids = id_space_create(name, 1, INT_MAX);

	/* Create hashes to keep track of automounter requests. */
	mutex_init(&data->lav_lock, NULL, MUTEX_DEFAULT, NULL);
	(void) snprintf(name, sizeof (name), "lx_autofs_path_hash_%d",
	    getminor(vfsp->vfs_dev));
	data->lav_path_hash = mod_hash_create_strhash(name,
	    LX_AUTOFS_VFS_PATH_HASH_SIZE, mod_hash_null_valdtor);
	(void) snprintf(name, sizeof (name), "lx_autofs_id_hash_%d",
	    getminor(vfsp->vfs_dev));
	data->lav_id_hash = mod_hash_create_idhash(name,
	    LX_AUTOFS_VFS_ID_HASH_SIZE, mod_hash_null_valdtor);

	/* Create a hash to keep track of vnodes. */
	(void) snprintf(name, sizeof (name), "lx_autofs_vn_hash_%d",
	    getminor(vfsp->vfs_dev));
	data->lav_vn_hash = mod_hash_create_ptrhash(name,
	    LX_AUTOFS_VFS_VN_HASH_SIZE, mod_hash_null_valdtor,
	    sizeof (vnode_t));

	list_create(&data->lav_mnt_list, sizeof (lx_autofs_mntent_t),
	    offsetof(lx_autofs_mntent_t, lxafme_lst));

	/* Create root vnode */
	data->lav_root = lx_autofs_vn_alloc(vfsp, data->lav_bs_vp);

	data->lav_root->v_flag |= VROOT | VNOCACHE | VNOMAP | VNOSWAP;

	/*
	 * For a direct mountpoint we need to allow a filesystem to be
	 * mounted overtop of this autofs mount. Otherwise, disallow that.
	 */
	if (data->lav_mnttype == LXAMT_INDIR)
		data->lav_root->v_flag |= VNOMOUNT;

	return (0);
}

static int
lx_autofs_unmount(vfs_t *vfsp, int flag, struct cred *cr)
{
	lx_autofs_vfs_t *data;

	if (secpolicy_fs_unmount(cr, vfsp) != 0)
		return (EPERM);

	/* We do not currently support forced unmounts. */
	if (flag & MS_FORCE)
		return (ENOTSUP);

	/*
	 * We should never have a reference count of less than 2: one for the
	 * caller, one for the root vnode.
	 */
	ASSERT(vfsp->vfs_count >= 2);

	/* If there are any outstanding vnodes, we can't unmount. */
	if (vfsp->vfs_count > 2)
		return (EBUSY);

	/* Check for any remaining holds on the root vnode. */
	data = vfsp->vfs_data;
	ASSERT(data->lav_root->v_vfsp == vfsp);
	if (data->lav_root->v_count > 1)
		return (EBUSY);

	/* Close the fifo to the automount process. */
	if (data->lav_fifo_wr != NULL)
		(void) closef(data->lav_fifo_wr);
	if (data->lav_fifo_rd != NULL)
		(void) closef(data->lav_fifo_rd);

	/*
	 * We have to release our hold on our root vnode before we can
	 * delete the backing store.  (Since the root vnode is linked
	 * to the backing store.)
	 */
	VN_RELE(data->lav_root);

	/* Cleanup the backing store. */
	lx_autofs_bs_destroy(data->lav_mvp, data->lav_bs_name);
	VN_RELE(data->lav_mvp);

	/*
	 * Delete all listed mounts.
	 */
	for (;;) {
		lx_autofs_mntent_t *mp;

		mp = list_remove_head(&data->lav_mnt_list);
		if (mp == NULL)
			break;
		kmem_free(mp->lxafme_path, mp->lxafme_len);
		kmem_free(mp, sizeof (lx_autofs_mntent_t));
	}

	/* Cleanup out remaining data structures. */
	mod_hash_destroy_strhash(data->lav_path_hash);
	mod_hash_destroy_idhash(data->lav_id_hash);
	mod_hash_destroy_ptrhash(data->lav_vn_hash);
	id_space_destroy(data->lav_ids);
	list_destroy(&data->lav_mnt_list);
	kmem_free(data, sizeof (lx_autofs_vfs_t));

	return (0);
}

static int
lx_autofs_root(vfs_t *vfsp, vnode_t **vpp)
{
	lx_autofs_vfs_t	*data = vfsp->vfs_data;

	*vpp = data->lav_root;
	VN_HOLD(*vpp);

	return (0);
}

static int
lx_autofs_statvfs(vfs_t *vfsp, statvfs64_t *sp)
{
	lx_autofs_vfs_t	*data = vfsp->vfs_data;
	vnode_t		*urvp = data->lav_root->v_data;
	dev32_t		d32;
	int		error;

	if ((error = VFS_STATVFS(urvp->v_vfsp, sp)) != 0)
		return (error);

	/* Update some of values before returning. */
	(void) cmpldev(&d32, vfsp->vfs_dev);
	sp->f_fsid = d32;
	(void) strlcpy(sp->f_basetype, vfssw[vfsp->vfs_fstype].vsw_name,
	    sizeof (sp->f_basetype));
	sp->f_flag = vf_to_stf(vfsp->vfs_flag);
	bzero(sp->f_fstr, sizeof (sp->f_fstr));
	return (0);
}

static const fs_operation_def_t lx_autofs_vfstops[] = {
	{ VFSNAME_MOUNT,	{ .vfs_mount = lx_autofs_mount } },
	{ VFSNAME_UNMOUNT,	{ .vfs_unmount = lx_autofs_unmount } },
	{ VFSNAME_ROOT,		{ .vfs_root = lx_autofs_root } },
	{ VFSNAME_STATVFS,	{ .vfs_statvfs = lx_autofs_statvfs } },
	{ NULL, NULL }
};

/*
 * VOP entry points - simple passthrough
 *
 * For most VOP entry points we can simply pass the request on to
 * the underlying filesystem we're mounted on.
 */
static int
lx_autofs_close(vnode_t *vp, int flag, int count, offset_t offset, cred_t *cr,
    caller_context_t *ctp)
{
	vnode_t *uvp = vp->v_data;
	return (VOP_CLOSE(uvp, flag, count, offset, cr, ctp));
}

static int
lx_autofs_readdir(vnode_t *vp, uio_t *uiop, cred_t *cr, int *eofp,
    caller_context_t *ctp, int flags)
{
	vnode_t *uvp = vp->v_data;
	return (VOP_READDIR(uvp, uiop, cr, eofp, ctp, flags));
}

static int
lx_autofs_access(vnode_t *vp, int mode, int flags, cred_t *cr,
    caller_context_t *ctp)
{
	vnode_t *uvp = vp->v_data;
	return (VOP_ACCESS(uvp, mode, flags, cr, ctp));
}

static int
lx_autofs_rwlock(struct vnode *vp, int write_lock, caller_context_t *ctp)
{
	vnode_t *uvp = vp->v_data;
	return (VOP_RWLOCK(uvp, write_lock, ctp));
}

static void
lx_autofs_rwunlock(struct vnode *vp, int write_lock, caller_context_t *ctp)
{
	vnode_t *uvp = vp->v_data;
	VOP_RWUNLOCK(uvp, write_lock, ctp);
}

/*
 * Check if attempting to access a 'direct' mount and if so, call the
 * automounter to perform the mount. Once the mount occurs, the new filesystem
 * will be mounted overtop of this autofs mountpoint and we will no longer
 * come through this path.
 */
static vnode_t *
lx_autofs_do_direct(vnode_t *vp)
{
	vfs_t	*vfsp = vp->v_vfsp;
	lx_autofs_vfs_t *data = vfsp->vfs_data;
	vnode_t *nvp;
	boolean_t skip_am_call = B_FALSE;

	if (data->lav_mnttype == LXAMT_INDIR)
		return (NULL);

	/*
	 * Check if the current process is in the automounter's process group.
	 * If it is, the current process is either the automounter itself or
	 * one of it's children. If so, don't call back into the automounter.
	 */
	mutex_enter(&pidlock);
	if (data->lav_pgrp == curproc->p_pgrp) {
		skip_am_call = B_TRUE;
	}
	mutex_exit(&pidlock);

	/*
	 * It is possible there is already a new fs mounted on top of our vnode.
	 * This can happen if the caller first did a lookup of a file name
	 * using our vnode as the directory vp. The lookup would trigger the
	 * autofs mount on top of ourself, but if the caller then uses our
	 * vnode to do a getattr on the directory, it will use the autofs
	 * vnode and not the newly mounted vnode. We need to skip re-calling
	 * the automounter for this case.
	 */
	if (!skip_am_call && vn_mountedvfs(vp) == NULL) {
		char tbuf[MAXPATHLEN];
		char *nm;

		(void) strlcpy(tbuf, (char *)refstr_value(vfsp->vfs_mntpt),
		    sizeof (tbuf));
		nm = tbuf + strlen(tbuf);
		while (*nm != '/' && nm != tbuf)
			nm--;
		if (*nm == '/')
			nm++;
		(void) lx_autofs_automounter_call(vp, nm);
	}

	/*
	 * We need to take an extra hold on our vp (which is the autofs
	 * root vp) to account for the rele done in traverse. traverse will
	 * take a hold on the new vp so the caller is responsible for calling
	 * VN_RELE on the returned vp.
	 */
	VN_HOLD(vp);
	nvp = vp;
	if (traverse(&nvp) != 0) {
		VN_RELE(nvp);
		return (NULL);
	}

	/* Confirm that we have a non-autofs fs mounted now */
	if (nvp->v_op == lx_autofs_vn_ops) {
		VN_RELE(nvp);
		return (NULL);
	}

	return (nvp);
}

/*ARGSUSED*/
static int
lx_autofs_rmdir(vnode_t *dvp, char *nm, vnode_t *cdir, cred_t *cr,
    caller_context_t *ctp, int flags)
{
	vnode_t *udvp = dvp->v_data;
	vnode_t		*nvp;

	/* handle direct mount here */
	if ((nvp = lx_autofs_do_direct(dvp)) != NULL) {
		int error;

		error = VOP_RMDIR(nvp, nm, cdir, cr, ctp, flags);
		VN_RELE(nvp);
		return (error);
	}

	/*
	 * cdir is the calling processes current directory.
	 * If cdir is lx_autofs vnode then get its real underlying
	 * vnode ptr.  (It seems like the only thing cdir is
	 * ever used for is to make sure the user doesn't delete
	 * their current directory.)
	 */
	if (vn_matchops(cdir, lx_autofs_vn_ops)) {
		vnode_t *ucdir = cdir->v_data;
		return (VOP_RMDIR(udvp, nm, ucdir, cr, ctp, flags));
	}

	return (VOP_RMDIR(udvp, nm, cdir, cr, ctp, flags));
}

/*
 * VOP entry points - special passthrough
 *
 * For some VOP entry points we will first pass the request on to
 * the underlying filesystem we're mounted on.  If there's an error
 * then we immediately return the error, but if the request succeeds
 * we have to do some extra work before returning.
 */
static int
lx_autofs_open(vnode_t **vpp, int flag, cred_t *cr, caller_context_t *ctp)
{
	vnode_t		*ovp = *vpp;
	vnode_t		*uvp = ovp->v_data;
	int		error;

	/* direct mounts were handled by the lookup to get *vpp */

	if ((error = VOP_OPEN(&uvp, flag, cr, ctp)) != 0)
		return (error);

	/* Check for clone opens. */
	if (uvp == ovp->v_data)
		return (0);

	/* Deal with clone opens by returning a new vnode. */
	*vpp = lx_autofs_vn_alloc(ovp->v_vfsp, uvp);
	VN_RELE(ovp);
	return (0);
}

static int
lx_autofs_getattr(vnode_t *vp, vattr_t *vap, int flags, cred_t *cr,
    caller_context_t *ctp)
{
	vnode_t		*uvp = vp->v_data;
	vnode_t		*dvp;
	int		error;

	if ((dvp = lx_autofs_do_direct(vp)) != NULL) {
		uvp = dvp;
	}

	error = VOP_GETATTR(uvp, vap, flags, cr, ctp);

	if (dvp != NULL) {
		/* we operated on the direct mounted fs */
		VN_RELE(dvp);
	} else if (error == 0) {
		/* Update the attributes with our filesystem id. */
		vap->va_fsid = vp->v_vfsp->vfs_dev;
	}

	return (error);
}

static int
lx_autofs_mkdir(vnode_t *dvp, char *nm, struct vattr *vap, vnode_t **vpp,
    cred_t *cr, caller_context_t *ctp, int flags, vsecattr_t *vsecp)
{
	vnode_t		*udvp = dvp->v_data;
	vnode_t		*nvp;
	int		error;

	if ((nvp = lx_autofs_do_direct(dvp)) != NULL) {
		udvp = nvp;
	}

	error = VOP_MKDIR(udvp, nm, vap, vpp, cr, ctp, flags, vsecp);

	if (nvp != NULL) {
		/* we operated on the direct mounted fs */
		VN_RELE(nvp);
	} else if (error == 0) {
		vnode_t		*uvp = NULL;

		/* Update the attributes with our filesystem id. */
		vap->va_fsid = dvp->v_vfsp->vfs_dev;

		/* Allocate our new vnode. */
		uvp = *vpp;
		*vpp = lx_autofs_vn_alloc(dvp->v_vfsp, uvp);
	}

	return (error);
}

/*
 * VOP entry points - custom
 */
/*ARGSUSED*/
static void
lx_autofs_inactive(struct vnode *vp, struct cred *cr, caller_context_t *ctp)
{
	lx_autofs_vfs_t	*data = vp->v_vfsp->vfs_data;

	/*
	 * We need to hold the vfs lock because if we're going to free
	 * this vnode we have to prevent anyone from looking it up
	 * in the vnode hash.
	 */
	mutex_enter(&data->lav_lock);
	mutex_enter(&vp->v_lock);

	if (vp->v_count < 1) {
		panic("lx_autofs_inactive: bad v_count");
		/*NOTREACHED*/
	}

	/* Drop the temporary hold by vn_rele now. */
	if (--vp->v_count > 0) {
		mutex_exit(&vp->v_lock);
		mutex_exit(&data->lav_lock);
		return;
	}

	/*
	 * No one should have been blocked on this lock because we're
	 * about to free this vnode.
	 */
	lx_autofs_vn_free(vp);
}

static int
lx_autofs_lookup(vnode_t *dvp, char *nm, vnode_t **vpp, struct pathname *pnp,
    int flags, vnode_t *rdir, cred_t *cr, caller_context_t *ctp,
    int *direntflags, pathname_t *realpnp)
{
	vnode_t			*udvp = dvp->v_data;
	vnode_t			*uvp = NULL;
	lx_autofs_vfs_t		*data = dvp->v_vfsp->vfs_data;
	int			error = ENOENT;

	/*
	 * For an indirect mount first try to lookup if this path component
	 * already exists.
	 */
	if (data->lav_mnttype == LXAMT_INDIR) {
		if ((error = VOP_LOOKUP(udvp, nm, &uvp, pnp, flags, rdir, cr,
		    ctp, direntflags, realpnp)) == 0) {
			*vpp = lx_autofs_vn_alloc(dvp->v_vfsp, uvp);
			return (0);
		}
	}

	/* Only query the automounter if the path does not exist. */
	if (error != ENOENT)
		return (error);

	/* Refer the lookup to the automounter. */
	if ((error = lx_autofs_automounter_call(dvp, nm)) != 0)
		return (error);

	if (data->lav_mnttype == LXAMT_INDIR) {
		/*
		 * Indirect mount. The automounter call should have mounted
		 * something on nm. Retry the lookup operation.
		 */
		if ((error = VOP_LOOKUP(udvp, nm, &uvp, pnp, flags, rdir, cr,
		    ctp, direntflags, realpnp)) == 0) {
			*vpp = lx_autofs_vn_alloc(dvp->v_vfsp, uvp);
			return (0);
		}
	} else {
		/*
		 * Direct or offset mount. The automounter call should have
		 * covered our 'dvp' with a new filesystem. Traverse into the
		 * new mount and retry the lookup.
		 *
		 * We need to take an extra hold on our vp (which is the autofs
		 * root vp) to acount for the rele done in traverse. Our caller
		 * will also do a rele on the original dvp and that would leave
		 * us one ref short on our autofs root vnode.
		 */
		VN_HOLD(dvp);
		if ((error = traverse(&dvp)) != 0) {
			VN_RELE(dvp);
			return (error);
		}

		error = VOP_LOOKUP(dvp, nm, vpp, pnp, flags, rdir, cr, ctp,
		    direntflags, realpnp);

		/* release the traverse hold */
		VN_RELE(dvp);
	}
	return (error);
}

static int
lx_autofs_ioctl(vnode_t *vp, int cmd, intptr_t arg, int mode, cred_t *cr,
    int *rvalp, caller_context_t *ctp)
{
	vnode_t			*uvp = vp->v_data;

	/* Intercept our ioctls. */
	switch ((uint_t)cmd) {
	case LX_AUTOFS_IOC_READY:
	case LX_AUTOFS_IOC_FAIL:
	case LX_AUTOFS_IOC_CATATONIC:
	case LX_AUTOFS_IOC_PROTOVER:
	case LX_AUTOFS_IOC_SETTIMEOUT:
	case LX_AUTOFS_IOC_EXPIRE:
	case LX_AUTOFS_IOC_EXPIRE_MULTI:
	case LX_AUTOFS_IOC_PROTOSUBVER:
	case LX_AUTOFS_IOC_ASKUMOUNT:
		return (lx_autofs_automounter_ioctl(vp, cmd, arg, cr));
	}

	/* Pass any remaining ioctl on. */
	return (VOP_IOCTL(uvp, cmd, arg, mode, cr, rvalp, ctp));
}

/*
 * VOP entry points definitions
 */
static const fs_operation_def_t lx_autofs_tops_root[] = {
	{ VOPNAME_OPEN,		{ .vop_open = lx_autofs_open } },
	{ VOPNAME_CLOSE,	{ .vop_close = lx_autofs_close } },
	{ VOPNAME_IOCTL,	{ .vop_ioctl = lx_autofs_ioctl } },
	{ VOPNAME_RWLOCK,	{ .vop_rwlock = lx_autofs_rwlock } },
	{ VOPNAME_RWUNLOCK,	{ .vop_rwunlock = lx_autofs_rwunlock } },
	{ VOPNAME_GETATTR,	{ .vop_getattr = lx_autofs_getattr } },
	{ VOPNAME_ACCESS,	{ .vop_access = lx_autofs_access } },
	{ VOPNAME_READDIR,	{ .vop_readdir = lx_autofs_readdir } },
	{ VOPNAME_LOOKUP,	{ .vop_lookup = lx_autofs_lookup } },
	{ VOPNAME_INACTIVE,	{ .vop_inactive = lx_autofs_inactive } },
	{ VOPNAME_MKDIR,	{ .vop_mkdir = lx_autofs_mkdir } },
	{ VOPNAME_RMDIR,	{ .vop_rmdir = lx_autofs_rmdir } },
	{ NULL }
};

/*
 * lx_autofs_init() gets invoked via the mod_install() call in
 * this modules _init() routine.  Therefor, the code that cleans
 * up the structures we allocate below is actually found in
 * our _fini() routine.
 */
/* ARGSUSED */
static int
lx_autofs_init(int fstype, char *name)
{
	int		error;

	if ((lx_autofs_major =
	    (major_t)space_fetch(LX_AUTOFS_SPACE_KEY_UDEV)) == 0) {

		if ((lx_autofs_major = getudev()) == (major_t)-1) {
			cmn_err(CE_WARN, "lx_autofs_init: "
			    "can't get unique device number");
			return (EAGAIN);
		}

		if (space_store(LX_AUTOFS_SPACE_KEY_UDEV,
		    (uintptr_t)lx_autofs_major) != 0) {
			cmn_err(CE_WARN, "lx_autofs_init: "
			    "can't save unique device number");
			return (EAGAIN);
		}
	}

	lx_autofs_fstype = fstype;
	if ((error = vfs_setfsops(fstype, lx_autofs_vfstops,
	    &lx_autofs_vfsops)) != 0) {
		cmn_err(CE_WARN, "lx_autofs_init: bad vfs ops template");
		return (error);
	}

	if ((error = vn_make_ops(name, lx_autofs_tops_root,
	    &lx_autofs_vn_ops)) != 0) {
		VERIFY(vfs_freevfsops_by_type(fstype) == 0);
		lx_autofs_vn_ops = NULL;
		return (error);
	}

	return (0);
}


/*
 * Module linkage
 */
static mntopt_t lx_autofs_mntopt[] = {
	{ LX_MNTOPT_FD,		NULL,	0,	MO_HASVALUE },
	{ LX_MNTOPT_PGRP,	NULL,	0,	MO_HASVALUE },
	{ LX_MNTOPT_MINPROTO,	NULL,	0,	MO_HASVALUE },
	{ LX_MNTOPT_MAXPROTO,	NULL,	0,	MO_HASVALUE },
	{ LX_MNTOPT_INDIRECT,	NULL,	0,	0 },
	{ LX_MNTOPT_DIRECT,	NULL,	0,	0 },
	{ LX_MNTOPT_OFFSET,	NULL,	0,	0 }
};

static mntopts_t lx_autofs_mntopts = {
	sizeof (lx_autofs_mntopt) / sizeof (mntopt_t),
	lx_autofs_mntopt
};

static vfsdef_t vfw = {
	VFSDEF_VERSION,
	LX_AUTOFS_NAME,
	lx_autofs_init,
	VSW_HASPROTO | VSW_VOLATILEDEV | VSW_ZMOUNT,
	&lx_autofs_mntopts
};

extern struct mod_ops mod_fsops;

static struct modlfs modlfs = {
	&mod_fsops, "lx autofs filesystem", &vfw
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlfs, NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	int		error;

	if ((error = mod_remove(&modlinkage)) != 0)
		return (error);

	if (lx_autofs_vn_ops != NULL) {
		vn_freevnodeops(lx_autofs_vn_ops);
		lx_autofs_vn_ops = NULL;
	}

	/*
	 * In our init routine, if we get an error after calling
	 * vfs_setfsops() we cleanup by calling vfs_freevfsops_by_type().
	 * But we don't need to call vfs_freevfsops_by_type() here
	 * because the fs framework did this for us as part of the
	 * mod_remove() call above.
	 */
	return (0);
}
