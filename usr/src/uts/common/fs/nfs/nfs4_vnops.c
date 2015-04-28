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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *	Copyright 1983,1984,1985,1986,1987,1988,1989 AT&T.
 *	All Rights Reserved
 */

/*
 * Copyright (c) 2013, Joyent, Inc. All rights reserved.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/cred.h>
#include <sys/time.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/file.h>
#include <sys/filio.h>
#include <sys/uio.h>
#include <sys/buf.h>
#include <sys/mman.h>
#include <sys/pathname.h>
#include <sys/dirent.h>
#include <sys/debug.h>
#include <sys/vmsystm.h>
#include <sys/fcntl.h>
#include <sys/flock.h>
#include <sys/swap.h>
#include <sys/errno.h>
#include <sys/strsubr.h>
#include <sys/sysmacros.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/pathconf.h>
#include <sys/utsname.h>
#include <sys/dnlc.h>
#include <sys/acl.h>
#include <sys/systeminfo.h>
#include <sys/policy.h>
#include <sys/sdt.h>
#include <sys/list.h>
#include <sys/stat.h>
#include <sys/zone.h>

#include <rpc/types.h>
#include <rpc/auth.h>
#include <rpc/clnt.h>

#include <nfs/nfs.h>
#include <nfs/nfs_clnt.h>
#include <nfs/nfs_acl.h>
#include <nfs/lm.h>
#include <nfs/nfs4.h>
#include <nfs/nfs4_kprot.h>
#include <nfs/rnode4.h>
#include <nfs/nfs4_clnt.h>

#include <vm/hat.h>
#include <vm/as.h>
#include <vm/page.h>
#include <vm/pvn.h>
#include <vm/seg.h>
#include <vm/seg_map.h>
#include <vm/seg_kpm.h>
#include <vm/seg_vn.h>

#include <fs/fs_subr.h>

#include <sys/ddi.h>
#include <sys/int_fmtio.h>
#include <sys/fs/autofs.h>

typedef struct {
	nfs4_ga_res_t	*di_garp;
	cred_t		*di_cred;
	hrtime_t	di_time_call;
} dirattr_info_t;

typedef enum nfs4_acl_op {
	NFS4_ACL_GET,
	NFS4_ACL_SET
} nfs4_acl_op_t;

static struct lm_sysid *nfs4_find_sysid(mntinfo4_t *mi);

static void	nfs4_update_dircaches(change_info4 *, vnode_t *, vnode_t *,
			char *, dirattr_info_t *);

static void	nfs4close_otw(rnode4_t *, cred_t *, nfs4_open_owner_t *,
		    nfs4_open_stream_t *, int *, int *, nfs4_close_type_t,
		    nfs4_error_t *, int *);
static int	nfs4_rdwrlbn(vnode_t *, page_t *, u_offset_t, size_t, int,
			cred_t *);
static int	nfs4write(vnode_t *, caddr_t, u_offset_t, int, cred_t *,
			stable_how4 *);
static int	nfs4read(vnode_t *, caddr_t, offset_t, int, size_t *,
			cred_t *, bool_t, struct uio *);
static int	nfs4setattr(vnode_t *, struct vattr *, int, cred_t *,
			vsecattr_t *);
static int	nfs4openattr(vnode_t *, vnode_t **, int, cred_t *);
static int	nfs4lookup(vnode_t *, char *, vnode_t **, cred_t *, int);
static int	nfs4lookup_xattr(vnode_t *, char *, vnode_t **, int, cred_t *);
static int	nfs4lookupvalidate_otw(vnode_t *, char *, vnode_t **, cred_t *);
static int	nfs4lookupnew_otw(vnode_t *, char *, vnode_t **, cred_t *);
static int	nfs4mknod(vnode_t *, char *, struct vattr *, enum vcexcl,
			int, vnode_t **, cred_t *);
static int	nfs4open_otw(vnode_t *, char *, struct vattr *, vnode_t **,
			cred_t *, int, int, enum createmode4, int);
static int	nfs4rename(vnode_t *, char *, vnode_t *, char *, cred_t *,
			caller_context_t *);
static int	nfs4rename_persistent_fh(vnode_t *, char *, vnode_t *,
			vnode_t *, char *, cred_t *, nfsstat4 *);
static int	nfs4rename_volatile_fh(vnode_t *, char *, vnode_t *,
			vnode_t *, char *, cred_t *, nfsstat4 *);
static int	do_nfs4readdir(vnode_t *, rddir4_cache *, cred_t *);
static void	nfs4readdir(vnode_t *, rddir4_cache *, cred_t *);
static int	nfs4_bio(struct buf *, stable_how4 *, cred_t *, bool_t);
static int	nfs4_getapage(vnode_t *, u_offset_t, size_t, uint_t *,
			page_t *[], size_t, struct seg *, caddr_t,
			enum seg_rw, cred_t *);
static void	nfs4_readahead(vnode_t *, u_offset_t, caddr_t, struct seg *,
			cred_t *);
static int	nfs4_sync_putapage(vnode_t *, page_t *, u_offset_t, size_t,
			int, cred_t *);
static int	nfs4_sync_pageio(vnode_t *, page_t *, u_offset_t, size_t,
			int, cred_t *);
static int	nfs4_commit(vnode_t *, offset4, count4, cred_t *);
static void	nfs4_set_mod(vnode_t *);
static void	nfs4_get_commit(vnode_t *);
static void	nfs4_get_commit_range(vnode_t *, u_offset_t, size_t);
static int	nfs4_putpage_commit(vnode_t *, offset_t, size_t, cred_t *);
static int	nfs4_commit_vp(vnode_t *, u_offset_t, size_t, cred_t *, int);
static int	nfs4_sync_commit(vnode_t *, page_t *, offset3, count3,
			cred_t *);
static void	do_nfs4_async_commit(vnode_t *, page_t *, offset3, count3,
			cred_t *);
static int	nfs4_update_attrcache(nfsstat4, nfs4_ga_res_t *,
			hrtime_t, vnode_t *, cred_t *);
static int	nfs4_open_non_reg_file(vnode_t **, int, cred_t *);
static int	nfs4_safelock(vnode_t *, const struct flock64 *, cred_t *);
static void	nfs4_register_lock_locally(vnode_t *, struct flock64 *, int,
			u_offset_t);
static int 	nfs4_lockrelease(vnode_t *, int, offset_t, cred_t *);
static int	nfs4_block_and_wait(clock_t *, rnode4_t *);
static cred_t  *state_to_cred(nfs4_open_stream_t *);
static void	denied_to_flk(LOCK4denied *, flock64_t *, LOCKT4args *);
static pid_t	lo_to_pid(lock_owner4 *);
static void	nfs4_reinstitute_local_lock_state(vnode_t *, flock64_t *,
			cred_t *, nfs4_lock_owner_t *);
static void	push_reinstate(vnode_t *, int, flock64_t *, cred_t *,
			nfs4_lock_owner_t *);
static int 	open_and_get_osp(vnode_t *, cred_t *, nfs4_open_stream_t **);
static void	nfs4_delmap_callback(struct as *, void *, uint_t);
static void	nfs4_free_delmapcall(nfs4_delmapcall_t *);
static nfs4_delmapcall_t	*nfs4_init_delmapcall();
static int	nfs4_find_and_delete_delmapcall(rnode4_t *, int *);
static int	nfs4_is_acl_mask_valid(uint_t, nfs4_acl_op_t);
static int	nfs4_create_getsecattr_return(vsecattr_t *, vsecattr_t *,
			uid_t, gid_t, int);

/*
 * Routines that implement the setting of v4 args for the misc. ops
 */
static void	nfs4args_lock_free(nfs_argop4 *);
static void	nfs4args_lockt_free(nfs_argop4 *);
static void	nfs4args_setattr(nfs_argop4 *, vattr_t *, vsecattr_t *,
			int, rnode4_t *, cred_t *, bitmap4, int *,
			nfs4_stateid_types_t *);
static void	nfs4args_setattr_free(nfs_argop4 *);
static int	nfs4args_verify(nfs_argop4 *, vattr_t *, enum nfs_opnum4,
			bitmap4);
static void	nfs4args_verify_free(nfs_argop4 *);
static void	nfs4args_write(nfs_argop4 *, stable_how4, rnode4_t *, cred_t *,
			WRITE4args **, nfs4_stateid_types_t *);

/*
 * These are the vnode ops functions that implement the vnode interface to
 * the networked file system.  See more comments below at nfs4_vnodeops.
 */
static int	nfs4_open(vnode_t **, int, cred_t *, caller_context_t *);
static int	nfs4_close(vnode_t *, int, int, offset_t, cred_t *,
			caller_context_t *);
static int	nfs4_read(vnode_t *, struct uio *, int, cred_t *,
			caller_context_t *);
static int	nfs4_write(vnode_t *, struct uio *, int, cred_t *,
			caller_context_t *);
static int	nfs4_ioctl(vnode_t *, int, intptr_t, int, cred_t *, int *,
			caller_context_t *);
static int	nfs4_setattr(vnode_t *, struct vattr *, int, cred_t *,
			caller_context_t *);
static int	nfs4_access(vnode_t *, int, int, cred_t *, caller_context_t *);
static int	nfs4_readlink(vnode_t *, struct uio *, cred_t *,
			caller_context_t *);
static int	nfs4_fsync(vnode_t *, int, cred_t *, caller_context_t *);
static int	nfs4_create(vnode_t *, char *, struct vattr *, enum vcexcl,
			int, vnode_t **, cred_t *, int, caller_context_t *,
			vsecattr_t *);
static int	nfs4_remove(vnode_t *, char *, cred_t *, caller_context_t *,
			int);
static int	nfs4_link(vnode_t *, vnode_t *, char *, cred_t *,
			caller_context_t *, int);
static int	nfs4_rename(vnode_t *, char *, vnode_t *, char *, cred_t *,
			caller_context_t *, int);
static int	nfs4_mkdir(vnode_t *, char *, struct vattr *, vnode_t **,
			cred_t *, caller_context_t *, int, vsecattr_t *);
static int	nfs4_rmdir(vnode_t *, char *, vnode_t *, cred_t *,
			caller_context_t *, int);
static int	nfs4_symlink(vnode_t *, char *, struct vattr *, char *,
			cred_t *, caller_context_t *, int);
static int	nfs4_readdir(vnode_t *, struct uio *, cred_t *, int *,
			caller_context_t *, int);
static int	nfs4_seek(vnode_t *, offset_t, offset_t *, caller_context_t *);
static int	nfs4_getpage(vnode_t *, offset_t, size_t, uint_t *,
			page_t *[], size_t, struct seg *, caddr_t,
			enum seg_rw, cred_t *, caller_context_t *);
static int	nfs4_putpage(vnode_t *, offset_t, size_t, int, cred_t *,
			caller_context_t *);
static int	nfs4_map(vnode_t *, offset_t, struct as *, caddr_t *, size_t,
			uchar_t, uchar_t, uint_t, cred_t *, caller_context_t *);
static int	nfs4_addmap(vnode_t *, offset_t, struct as *, caddr_t, size_t,
			uchar_t, uchar_t, uint_t, cred_t *, caller_context_t *);
static int	nfs4_cmp(vnode_t *, vnode_t *, caller_context_t *);
static int	nfs4_frlock(vnode_t *, int, struct flock64 *, int, offset_t,
			struct flk_callback *, cred_t *, caller_context_t *);
static int	nfs4_space(vnode_t *, int, struct flock64 *, int, offset_t,
			cred_t *, caller_context_t *);
static int	nfs4_delmap(vnode_t *, offset_t, struct as *, caddr_t, size_t,
			uint_t, uint_t, uint_t, cred_t *, caller_context_t *);
static int	nfs4_pageio(vnode_t *, page_t *, u_offset_t, size_t, int,
			cred_t *, caller_context_t *);
static void	nfs4_dispose(vnode_t *, page_t *, int, int, cred_t *,
			caller_context_t *);
static int	nfs4_setsecattr(vnode_t *, vsecattr_t *, int, cred_t *,
			caller_context_t *);
/*
 * These vnode ops are required to be called from outside this source file,
 * e.g. by ephemeral mount stub vnode ops, and so may not be declared
 * as static.
 */
int	nfs4_getattr(vnode_t *, struct vattr *, int, cred_t *,
	    caller_context_t *);
void	nfs4_inactive(vnode_t *, cred_t *, caller_context_t *);
int	nfs4_lookup(vnode_t *, char *, vnode_t **,
	    struct pathname *, int, vnode_t *, cred_t *,
	    caller_context_t *, int *, pathname_t *);
int	nfs4_fid(vnode_t *, fid_t *, caller_context_t *);
int	nfs4_rwlock(vnode_t *, int, caller_context_t *);
void	nfs4_rwunlock(vnode_t *, int, caller_context_t *);
int	nfs4_realvp(vnode_t *, vnode_t **, caller_context_t *);
int	nfs4_pathconf(vnode_t *, int, ulong_t *, cred_t *,
	    caller_context_t *);
int	nfs4_getsecattr(vnode_t *, vsecattr_t *, int, cred_t *,
	    caller_context_t *);
int	nfs4_shrlock(vnode_t *, int, struct shrlock *, int, cred_t *,
	    caller_context_t *);

/*
 * Used for nfs4_commit_vp() to indicate if we should
 * wait on pending writes.
 */
#define	NFS4_WRITE_NOWAIT	0
#define	NFS4_WRITE_WAIT		1

#define	NFS4_BASE_WAIT_TIME 1	/* 1 second */

/*
 * Error flags used to pass information about certain special errors
 * which need to be handled specially.
 */
#define	NFS_EOF			-98
#define	NFS_VERF_MISMATCH	-97

/*
 * Flags used to differentiate between which operation drove the
 * potential CLOSE OTW. (see nfs4_close_otw_if_necessary)
 */
#define	NFS4_CLOSE_OP		0x1
#define	NFS4_DELMAP_OP		0x2
#define	NFS4_INACTIVE_OP	0x3

#define	ISVDEV(t) ((t == VBLK) || (t == VCHR) || (t == VFIFO))

/* ALIGN64 aligns the given buffer and adjust buffer size to 64 bit */
#define	ALIGN64(x, ptr, sz)						\
	x = ((uintptr_t)(ptr)) & (sizeof (uint64_t) - 1);		\
	if (x) {							\
		x = sizeof (uint64_t) - (x);				\
		sz -= (x);						\
		ptr += (x);						\
	}

#ifdef DEBUG
int nfs4_client_attr_debug = 0;
int nfs4_client_state_debug = 0;
int nfs4_client_shadow_debug = 0;
int nfs4_client_lock_debug = 0;
int nfs4_seqid_sync = 0;
int nfs4_client_map_debug = 0;
static int nfs4_pageio_debug = 0;
int nfs4_client_inactive_debug = 0;
int nfs4_client_recov_debug = 0;
int nfs4_client_failover_debug = 0;
int nfs4_client_call_debug = 0;
int nfs4_client_lookup_debug = 0;
int nfs4_client_zone_debug = 0;
int nfs4_lost_rqst_debug = 0;
int nfs4_rdattrerr_debug = 0;
int nfs4_open_stream_debug = 0;

int nfs4read_error_inject;

static int nfs4_create_misses = 0;

static int nfs4_readdir_cache_shorts = 0;
static int nfs4_readdir_readahead = 0;

static int nfs4_bio_do_stop = 0;

static int nfs4_lostpage = 0;	/* number of times we lost original page */

int nfs4_mmap_debug = 0;

static int nfs4_pathconf_cache_hits = 0;
static int nfs4_pathconf_cache_misses = 0;

int nfs4close_all_cnt;
int nfs4close_one_debug = 0;
int nfs4close_notw_debug = 0;

int denied_to_flk_debug = 0;
void *lockt_denied_debug;

#endif

/*
 * How long to wait before trying again if OPEN_CONFIRM gets ETIMEDOUT
 * or NFS4ERR_RESOURCE.
 */
static int confirm_retry_sec = 30;

static int nfs4_lookup_neg_cache = 1;

/*
 * number of pages to read ahead
 * optimized for 100 base-T.
 */
static int nfs4_nra = 4;

static int nfs4_do_symlink_cache = 1;

static int nfs4_pathconf_disable_cache = 0;

/*
 * These are the vnode ops routines which implement the vnode interface to
 * the networked file system.  These routines just take their parameters,
 * make them look networkish by putting the right info into interface structs,
 * and then calling the appropriate remote routine(s) to do the work.
 *
 * Note on directory name lookup cacheing:  If we detect a stale fhandle,
 * we purge the directory cache relative to that vnode.  This way, the
 * user won't get burned by the cache repeatedly.  See <nfs/rnode4.h> for
 * more details on rnode locking.
 */

struct vnodeops *nfs4_vnodeops;

const fs_operation_def_t nfs4_vnodeops_template[] = {
	VOPNAME_OPEN,		{ .vop_open = nfs4_open },
	VOPNAME_CLOSE,		{ .vop_close = nfs4_close },
	VOPNAME_READ,		{ .vop_read = nfs4_read },
	VOPNAME_WRITE,		{ .vop_write = nfs4_write },
	VOPNAME_IOCTL,		{ .vop_ioctl = nfs4_ioctl },
	VOPNAME_GETATTR,	{ .vop_getattr = nfs4_getattr },
	VOPNAME_SETATTR,	{ .vop_setattr = nfs4_setattr },
	VOPNAME_ACCESS,		{ .vop_access = nfs4_access },
	VOPNAME_LOOKUP,		{ .vop_lookup = nfs4_lookup },
	VOPNAME_CREATE,		{ .vop_create = nfs4_create },
	VOPNAME_REMOVE,		{ .vop_remove = nfs4_remove },
	VOPNAME_LINK,		{ .vop_link = nfs4_link },
	VOPNAME_RENAME,		{ .vop_rename = nfs4_rename },
	VOPNAME_MKDIR,		{ .vop_mkdir = nfs4_mkdir },
	VOPNAME_RMDIR,		{ .vop_rmdir = nfs4_rmdir },
	VOPNAME_READDIR,	{ .vop_readdir = nfs4_readdir },
	VOPNAME_SYMLINK,	{ .vop_symlink = nfs4_symlink },
	VOPNAME_READLINK,	{ .vop_readlink = nfs4_readlink },
	VOPNAME_FSYNC,		{ .vop_fsync = nfs4_fsync },
	VOPNAME_INACTIVE,	{ .vop_inactive = nfs4_inactive },
	VOPNAME_FID,		{ .vop_fid = nfs4_fid },
	VOPNAME_RWLOCK,		{ .vop_rwlock = nfs4_rwlock },
	VOPNAME_RWUNLOCK,	{ .vop_rwunlock = nfs4_rwunlock },
	VOPNAME_SEEK,		{ .vop_seek = nfs4_seek },
	VOPNAME_FRLOCK,		{ .vop_frlock = nfs4_frlock },
	VOPNAME_SPACE,		{ .vop_space = nfs4_space },
	VOPNAME_REALVP,		{ .vop_realvp = nfs4_realvp },
	VOPNAME_GETPAGE,	{ .vop_getpage = nfs4_getpage },
	VOPNAME_PUTPAGE,	{ .vop_putpage = nfs4_putpage },
	VOPNAME_MAP,		{ .vop_map = nfs4_map },
	VOPNAME_ADDMAP,		{ .vop_addmap = nfs4_addmap },
	VOPNAME_DELMAP,		{ .vop_delmap = nfs4_delmap },
	/* no separate nfs4_dump */
	VOPNAME_DUMP,		{ .vop_dump = nfs_dump },
	VOPNAME_PATHCONF,	{ .vop_pathconf = nfs4_pathconf },
	VOPNAME_PAGEIO,		{ .vop_pageio = nfs4_pageio },
	VOPNAME_DISPOSE,	{ .vop_dispose = nfs4_dispose },
	VOPNAME_SETSECATTR,	{ .vop_setsecattr = nfs4_setsecattr },
	VOPNAME_GETSECATTR,	{ .vop_getsecattr = nfs4_getsecattr },
	VOPNAME_SHRLOCK,	{ .vop_shrlock = nfs4_shrlock },
	VOPNAME_VNEVENT, 	{ .vop_vnevent = fs_vnevent_support },
	NULL,			NULL
};

/*
 * The following are subroutines and definitions to set args or get res
 * for the different nfsv4 ops
 */

void
nfs4args_lookup_free(nfs_argop4 *argop, int arglen)
{
	int		i;

	for (i = 0; i < arglen; i++) {
		if (argop[i].argop == OP_LOOKUP) {
			kmem_free(
			    argop[i].nfs_argop4_u.oplookup.
			    objname.utf8string_val,
			    argop[i].nfs_argop4_u.oplookup.
			    objname.utf8string_len);
		}
	}
}

static void
nfs4args_lock_free(nfs_argop4 *argop)
{
	locker4 *locker = &argop->nfs_argop4_u.oplock.locker;

	if (locker->new_lock_owner == TRUE) {
		open_to_lock_owner4 *open_owner;

		open_owner = &locker->locker4_u.open_owner;
		if (open_owner->lock_owner.owner_val != NULL) {
			kmem_free(open_owner->lock_owner.owner_val,
			    open_owner->lock_owner.owner_len);
		}
	}
}

static void
nfs4args_lockt_free(nfs_argop4 *argop)
{
	lock_owner4 *lowner = &argop->nfs_argop4_u.oplockt.owner;

	if (lowner->owner_val != NULL) {
		kmem_free(lowner->owner_val, lowner->owner_len);
	}
}

static void
nfs4args_setattr(nfs_argop4 *argop, vattr_t *vap, vsecattr_t *vsap, int flags,
    rnode4_t *rp, cred_t *cr, bitmap4 supp, int *error,
    nfs4_stateid_types_t *sid_types)
{
	fattr4		*attr = &argop->nfs_argop4_u.opsetattr.obj_attributes;
	mntinfo4_t	*mi;

	argop->argop = OP_SETATTR;
	/*
	 * The stateid is set to 0 if client is not modifying the size
	 * and otherwise to whatever nfs4_get_stateid() returns.
	 *
	 * XXX Note: nfs4_get_stateid() returns 0 if no lockowner and/or no
	 * state struct could be found for the process/file pair.  We may
	 * want to change this in the future (by OPENing the file).  See
	 * bug # 4474852.
	 */
	if (vap->va_mask & AT_SIZE) {

		ASSERT(rp != NULL);
		mi = VTOMI4(RTOV4(rp));

		argop->nfs_argop4_u.opsetattr.stateid =
		    nfs4_get_stateid(cr, rp, curproc->p_pidp->pid_id, mi,
		    OP_SETATTR, sid_types, FALSE);
	} else {
		bzero(&argop->nfs_argop4_u.opsetattr.stateid,
		    sizeof (stateid4));
	}

	*error = vattr_to_fattr4(vap, vsap, attr, flags, OP_SETATTR, supp);
	if (*error)
		bzero(attr, sizeof (*attr));
}

static void
nfs4args_setattr_free(nfs_argop4 *argop)
{
	nfs4_fattr4_free(&argop->nfs_argop4_u.opsetattr.obj_attributes);
}

static int
nfs4args_verify(nfs_argop4 *argop, vattr_t *vap, enum nfs_opnum4 op,
    bitmap4 supp)
{
	fattr4 *attr;
	int error = 0;

	argop->argop = op;
	switch (op) {
	case OP_VERIFY:
		attr = &argop->nfs_argop4_u.opverify.obj_attributes;
		break;
	case OP_NVERIFY:
		attr = &argop->nfs_argop4_u.opnverify.obj_attributes;
		break;
	default:
		return (EINVAL);
	}
	if (!error)
		error = vattr_to_fattr4(vap, NULL, attr, 0, op, supp);
	if (error)
		bzero(attr, sizeof (*attr));
	return (error);
}

static void
nfs4args_verify_free(nfs_argop4 *argop)
{
	switch (argop->argop) {
	case OP_VERIFY:
		nfs4_fattr4_free(&argop->nfs_argop4_u.opverify.obj_attributes);
		break;
	case OP_NVERIFY:
		nfs4_fattr4_free(&argop->nfs_argop4_u.opnverify.obj_attributes);
		break;
	default:
		break;
	}
}

static void
nfs4args_write(nfs_argop4 *argop, stable_how4 stable, rnode4_t *rp, cred_t *cr,
    WRITE4args **wargs_pp, nfs4_stateid_types_t *sid_tp)
{
	WRITE4args *wargs = &argop->nfs_argop4_u.opwrite;
	mntinfo4_t *mi = VTOMI4(RTOV4(rp));

	argop->argop = OP_WRITE;
	wargs->stable = stable;
	wargs->stateid = nfs4_get_w_stateid(cr, rp, curproc->p_pidp->pid_id,
	    mi, OP_WRITE, sid_tp);
	wargs->mblk = NULL;
	*wargs_pp = wargs;
}

void
nfs4args_copen_free(OPEN4cargs *open_args)
{
	if (open_args->owner.owner_val) {
		kmem_free(open_args->owner.owner_val,
		    open_args->owner.owner_len);
	}
	if ((open_args->opentype == OPEN4_CREATE) &&
	    (open_args->mode != EXCLUSIVE4)) {
		nfs4_fattr4_free(&open_args->createhow4_u.createattrs);
	}
}

/*
 * XXX:  This is referenced in modstubs.s
 */
struct vnodeops *
nfs4_getvnodeops(void)
{
	return (nfs4_vnodeops);
}

/*
 * The OPEN operation opens a regular file.
 */
/*ARGSUSED3*/
static int
nfs4_open(vnode_t **vpp, int flag, cred_t *cr, caller_context_t *ct)
{
	vnode_t *dvp = NULL;
	rnode4_t *rp, *drp;
	int error;
	int just_been_created;
	char fn[MAXNAMELEN];

	NFS4_DEBUG(nfs4_client_state_debug, (CE_NOTE, "nfs4_open: "));
	if (nfs_zone() != VTOMI4(*vpp)->mi_zone)
		return (EIO);
	rp = VTOR4(*vpp);

	/*
	 * Check to see if opening something besides a regular file;
	 * if so skip the OTW call
	 */
	if ((*vpp)->v_type != VREG) {
		error = nfs4_open_non_reg_file(vpp, flag, cr);
		return (error);
	}

	/*
	 * XXX - would like a check right here to know if the file is
	 * executable or not, so as to skip OTW
	 */

	if ((error = vtodv(*vpp, &dvp, cr, TRUE)) != 0)
		return (error);

	drp = VTOR4(dvp);
	if (nfs_rw_enter_sig(&drp->r_rwlock, RW_READER, INTR4(dvp)))
		return (EINTR);

	if ((error = vtoname(*vpp, fn, MAXNAMELEN)) != 0) {
		nfs_rw_exit(&drp->r_rwlock);
		return (error);
	}

	/*
	 * See if this file has just been CREATEd.
	 * If so, clear the flag and update the dnlc, which was previously
	 * skipped in nfs4_create.
	 * XXX need better serilization on this.
	 * XXX move this into the nf4open_otw call, after we have
	 * XXX acquired the open owner seqid sync.
	 */
	mutex_enter(&rp->r_statev4_lock);
	if (rp->created_v4) {
		rp->created_v4 = 0;
		mutex_exit(&rp->r_statev4_lock);

		dnlc_update(dvp, fn, *vpp);
		/* This is needed so we don't bump the open ref count */
		just_been_created = 1;
	} else {
		mutex_exit(&rp->r_statev4_lock);
		just_been_created = 0;
	}

	/*
	 * If caller specified O_TRUNC/FTRUNC, then be sure to set
	 * FWRITE (to drive successful setattr(size=0) after open)
	 */
	if (flag & FTRUNC)
		flag |= FWRITE;

	error = nfs4open_otw(dvp, fn, NULL, vpp, cr, 0, flag, 0,
	    just_been_created);

	if (!error && !((*vpp)->v_flag & VROOT))
		dnlc_update(dvp, fn, *vpp);

	nfs_rw_exit(&drp->r_rwlock);

	/* release the hold from vtodv */
	VN_RELE(dvp);

	/* exchange the shadow for the master vnode, if needed */

	if (error == 0 && IS_SHADOW(*vpp, rp))
		sv_exchange(vpp);

	return (error);
}

/*
 * See if there's a "lost open" request to be saved and recovered.
 */
static void
nfs4open_save_lost_rqst(int error, nfs4_lost_rqst_t *lost_rqstp,
    nfs4_open_owner_t *oop, cred_t *cr, vnode_t *vp,
    vnode_t *dvp, OPEN4cargs *open_args)
{
	vfs_t *vfsp;
	char *srccfp;

	vfsp = (dvp ? dvp->v_vfsp : vp->v_vfsp);

	if (error != ETIMEDOUT && error != EINTR &&
	    !NFS4_FRC_UNMT_ERR(error, vfsp)) {
		lost_rqstp->lr_op = 0;
		return;
	}

	NFS4_DEBUG(nfs4_lost_rqst_debug, (CE_NOTE,
	    "nfs4open_save_lost_rqst: error %d", error));

	lost_rqstp->lr_op = OP_OPEN;

	/*
	 * The vp (if it is not NULL) and dvp are held and rele'd via
	 * the recovery code.  See nfs4_save_lost_rqst.
	 */
	lost_rqstp->lr_vp = vp;
	lost_rqstp->lr_dvp = dvp;
	lost_rqstp->lr_oop = oop;
	lost_rqstp->lr_osp = NULL;
	lost_rqstp->lr_lop = NULL;
	lost_rqstp->lr_cr = cr;
	lost_rqstp->lr_flk = NULL;
	lost_rqstp->lr_oacc = open_args->share_access;
	lost_rqstp->lr_odeny = open_args->share_deny;
	lost_rqstp->lr_oclaim = open_args->claim;
	if (open_args->claim == CLAIM_DELEGATE_CUR) {
		lost_rqstp->lr_ostateid =
		    open_args->open_claim4_u.delegate_cur_info.delegate_stateid;
		srccfp = open_args->open_claim4_u.delegate_cur_info.cfile;
	} else {
		srccfp = open_args->open_claim4_u.cfile;
	}
	lost_rqstp->lr_ofile.utf8string_len = 0;
	lost_rqstp->lr_ofile.utf8string_val = NULL;
	(void) str_to_utf8(srccfp, &lost_rqstp->lr_ofile);
	lost_rqstp->lr_putfirst = FALSE;
}

struct nfs4_excl_time {
	uint32 seconds;
	uint32 nseconds;
};

/*
 * The OPEN operation creates and/or opens a regular file
 *
 * ARGSUSED
 */
static int
nfs4open_otw(vnode_t *dvp, char *file_name, struct vattr *in_va,
    vnode_t **vpp, cred_t *cr, int create_flag, int open_flag,
    enum createmode4 createmode, int file_just_been_created)
{
	rnode4_t *rp;
	rnode4_t *drp = VTOR4(dvp);
	vnode_t *vp = NULL;
	vnode_t *vpi = *vpp;
	bool_t needrecov = FALSE;

	int doqueue = 1;

	COMPOUND4args_clnt args;
	COMPOUND4res_clnt res;
	nfs_argop4 *argop;
	nfs_resop4 *resop;
	int argoplist_size;
	int idx_open, idx_fattr;

	GETFH4res *gf_res = NULL;
	OPEN4res *op_res = NULL;
	nfs4_ga_res_t *garp;
	fattr4 *attr = NULL;
	struct nfs4_excl_time verf;
	bool_t did_excl_setup = FALSE;
	int created_osp;

	OPEN4cargs *open_args;
	nfs4_open_owner_t	*oop = NULL;
	nfs4_open_stream_t	*osp = NULL;
	seqid4 seqid = 0;
	bool_t retry_open = FALSE;
	nfs4_recov_state_t recov_state;
	nfs4_lost_rqst_t lost_rqst;
	nfs4_error_t e = { 0, NFS4_OK, RPC_SUCCESS };
	hrtime_t t;
	int acc = 0;
	cred_t *cred_otw = NULL;	/* cred used to do the RPC call */
	cred_t *ncr = NULL;

	nfs4_sharedfh_t *otw_sfh;
	nfs4_sharedfh_t *orig_sfh;
	int fh_differs = 0;
	int numops, setgid_flag;
	int num_bseqid_retry = NFS4_NUM_RETRY_BAD_SEQID + 1;

	/*
	 * Make sure we properly deal with setting the right gid on
	 * a newly created file to reflect the parent's setgid bit
	 */
	setgid_flag = 0;
	if (create_flag && in_va) {

		/*
		 * If there is grpid mount flag used or
		 * the parent's directory has the setgid bit set
		 * _and_ the client was able to get a valid mapping
		 * for the parent dir's owner_group, we want to
		 * append NVERIFY(owner_group == dva.va_gid) and
		 * SETATTR to the CREATE compound.
		 */
		mutex_enter(&drp->r_statelock);
		if ((VTOMI4(dvp)->mi_flags & MI4_GRPID ||
		    drp->r_attr.va_mode & VSGID) &&
		    drp->r_attr.va_gid != GID_NOBODY) {
			in_va->va_mask |= AT_GID;
			in_va->va_gid = drp->r_attr.va_gid;
			setgid_flag = 1;
		}
		mutex_exit(&drp->r_statelock);
	}

	/*
	 * Normal/non-create compound:
	 * PUTFH(dfh) + OPEN(create) + GETFH + GETATTR(new)
	 *
	 * Open(create) compound no setgid:
	 * PUTFH(dfh) + SAVEFH + OPEN(create) + GETFH + GETATTR(new) +
	 * RESTOREFH + GETATTR
	 *
	 * Open(create) setgid:
	 * PUTFH(dfh) + OPEN(create) + GETFH + GETATTR(new) +
	 * SAVEFH + PUTFH(dfh) + GETATTR(dvp) + RESTOREFH +
	 * NVERIFY(grp) + SETATTR
	 */
	if (setgid_flag) {
		numops = 10;
		idx_open = 1;
		idx_fattr = 3;
	} else if (create_flag) {
		numops = 7;
		idx_open = 2;
		idx_fattr = 4;
	} else {
		numops = 4;
		idx_open = 1;
		idx_fattr = 3;
	}

	args.array_len = numops;
	argoplist_size = numops * sizeof (nfs_argop4);
	argop = kmem_alloc(argoplist_size, KM_SLEEP);

	NFS4_DEBUG(nfs4_client_state_debug, (CE_NOTE, "nfs4open_otw: "
	    "open %s open flag 0x%x cred %p", file_name, open_flag,
	    (void *)cr));

	ASSERT(nfs_zone() == VTOMI4(dvp)->mi_zone);
	if (create_flag) {
		/*
		 * We are to create a file.  Initialize the passed in vnode
		 * pointer.
		 */
		vpi = NULL;
	} else {
		/*
		 * Check to see if the client owns a read delegation and is
		 * trying to open for write.  If so, then return the delegation
		 * to avoid the server doing a cb_recall and returning DELAY.
		 * NB - we don't use the statev4_lock here because we'd have
		 * to drop the lock anyway and the result would be stale.
		 */
		if ((open_flag & FWRITE) &&
		    VTOR4(vpi)->r_deleg_type == OPEN_DELEGATE_READ)
			(void) nfs4delegreturn(VTOR4(vpi), NFS4_DR_REOPEN);

		/*
		 * If the file has a delegation, then do an access check up
		 * front.  This avoids having to an access check later after
		 * we've already done start_op, which could deadlock.
		 */
		if (VTOR4(vpi)->r_deleg_type != OPEN_DELEGATE_NONE) {
			if (open_flag & FREAD &&
			    nfs4_access(vpi, VREAD, 0, cr, NULL) == 0)
				acc |= VREAD;
			if (open_flag & FWRITE &&
			    nfs4_access(vpi, VWRITE, 0, cr, NULL) == 0)
				acc |= VWRITE;
		}
	}

	drp = VTOR4(dvp);

	recov_state.rs_flags = 0;
	recov_state.rs_num_retry_despite_err = 0;
	cred_otw = cr;

recov_retry:
	fh_differs = 0;
	nfs4_error_zinit(&e);

	e.error = nfs4_start_op(VTOMI4(dvp), dvp, vpi, &recov_state);
	if (e.error) {
		if (ncr != NULL)
			crfree(ncr);
		kmem_free(argop, argoplist_size);
		return (e.error);
	}

	args.ctag = TAG_OPEN;
	args.array_len = numops;
	args.array = argop;

	/* putfh directory fh */
	argop[0].argop = OP_CPUTFH;
	argop[0].nfs_argop4_u.opcputfh.sfh = drp->r_fh;

	/* OPEN: either op 1 or op 2 depending upon create/setgid flags */
	argop[idx_open].argop = OP_COPEN;
	open_args = &argop[idx_open].nfs_argop4_u.opcopen;
	open_args->claim = CLAIM_NULL;

	/* name of file */
	open_args->open_claim4_u.cfile = file_name;
	open_args->owner.owner_len = 0;
	open_args->owner.owner_val = NULL;

	if (create_flag) {
		/* CREATE a file */
		open_args->opentype = OPEN4_CREATE;
		open_args->mode = createmode;
		if (createmode == EXCLUSIVE4) {
			if (did_excl_setup == FALSE) {
				verf.seconds = zone_get_hostid(NULL);
				if (verf.seconds != 0)
					verf.nseconds = newnum();
				else {
					timestruc_t now;

					gethrestime(&now);
					verf.seconds = now.tv_sec;
					verf.nseconds = now.tv_nsec;
				}
				/*
				 * Since the server will use this value for the
				 * mtime, make sure that it can't overflow. Zero
				 * out the MSB. The actual value does not matter
				 * here, only its uniqeness.
				 */
				verf.seconds &= INT32_MAX;
				did_excl_setup = TRUE;
			}

			/* Now copy over verifier to OPEN4args. */
			open_args->createhow4_u.createverf = *(uint64_t *)&verf;
		} else {
			int v_error;
			bitmap4 supp_attrs;
			servinfo4_t *svp;

			attr = &open_args->createhow4_u.createattrs;

			svp = drp->r_server;
			(void) nfs_rw_enter_sig(&svp->sv_lock, RW_READER, 0);
			supp_attrs = svp->sv_supp_attrs;
			nfs_rw_exit(&svp->sv_lock);

			/* GUARDED4 or UNCHECKED4 */
			v_error = vattr_to_fattr4(in_va, NULL, attr, 0, OP_OPEN,
			    supp_attrs);
			if (v_error) {
				bzero(attr, sizeof (*attr));
				nfs4args_copen_free(open_args);
				nfs4_end_op(VTOMI4(dvp), dvp, vpi,
				    &recov_state, FALSE);
				if (ncr != NULL)
					crfree(ncr);
				kmem_free(argop, argoplist_size);
				return (v_error);
			}
		}
	} else {
		/* NO CREATE */
		open_args->opentype = OPEN4_NOCREATE;
	}

	if (recov_state.rs_sp != NULL) {
		mutex_enter(&recov_state.rs_sp->s_lock);
		open_args->owner.clientid = recov_state.rs_sp->clientid;
		mutex_exit(&recov_state.rs_sp->s_lock);
	} else {
		/* XXX should we just fail here? */
		open_args->owner.clientid = 0;
	}

	/*
	 * This increments oop's ref count or creates a temporary 'just_created'
	 * open owner that will become valid when this OPEN/OPEN_CONFIRM call
	 * completes.
	 */
	mutex_enter(&VTOMI4(dvp)->mi_lock);

	/* See if a permanent or just created open owner exists */
	oop = find_open_owner_nolock(cr, NFS4_JUST_CREATED, VTOMI4(dvp));
	if (!oop) {
		/*
		 * This open owner does not exist so create a temporary
		 * just created one.
		 */
		oop = create_open_owner(cr, VTOMI4(dvp));
		ASSERT(oop != NULL);
	}
	mutex_exit(&VTOMI4(dvp)->mi_lock);

	/* this length never changes, do alloc before seqid sync */
	open_args->owner.owner_len = sizeof (oop->oo_name);
	open_args->owner.owner_val =
	    kmem_alloc(open_args->owner.owner_len, KM_SLEEP);

	e.error = nfs4_start_open_seqid_sync(oop, VTOMI4(dvp));
	if (e.error == EAGAIN) {
		open_owner_rele(oop);
		nfs4args_copen_free(open_args);
		nfs4_end_op(VTOMI4(dvp), dvp, vpi, &recov_state, TRUE);
		if (ncr != NULL) {
			crfree(ncr);
			ncr = NULL;
		}
		goto recov_retry;
	}

	/* Check to see if we need to do the OTW call */
	if (!create_flag) {
		if (!nfs4_is_otw_open_necessary(oop, open_flag, vpi,
		    file_just_been_created, &e.error, acc, &recov_state)) {

			/*
			 * The OTW open is not necessary.  Either
			 * the open can succeed without it (eg.
			 * delegation, error == 0) or the open
			 * must fail due to an access failure
			 * (error != 0).  In either case, tidy
			 * up and return.
			 */

			nfs4_end_open_seqid_sync(oop);
			open_owner_rele(oop);
			nfs4args_copen_free(open_args);
			nfs4_end_op(VTOMI4(dvp), dvp, vpi, &recov_state, FALSE);
			if (ncr != NULL)
				crfree(ncr);
			kmem_free(argop, argoplist_size);
			return (e.error);
		}
	}

	bcopy(&oop->oo_name, open_args->owner.owner_val,
	    open_args->owner.owner_len);

	seqid = nfs4_get_open_seqid(oop) + 1;
	open_args->seqid = seqid;
	open_args->share_access = 0;
	if (open_flag & FREAD)
		open_args->share_access |= OPEN4_SHARE_ACCESS_READ;
	if (open_flag & FWRITE)
		open_args->share_access |= OPEN4_SHARE_ACCESS_WRITE;
	open_args->share_deny = OPEN4_SHARE_DENY_NONE;



	/*
	 * getfh w/sanity check for idx_open/idx_fattr
	 */
	ASSERT((idx_open + 1) == (idx_fattr - 1));
	argop[idx_open + 1].argop = OP_GETFH;

	/* getattr */
	argop[idx_fattr].argop = OP_GETATTR;
	argop[idx_fattr].nfs_argop4_u.opgetattr.attr_request = NFS4_VATTR_MASK;
	argop[idx_fattr].nfs_argop4_u.opgetattr.mi = VTOMI4(dvp);

	if (setgid_flag) {
		vattr_t	_v;
		servinfo4_t *svp;
		bitmap4	supp_attrs;

		svp = drp->r_server;
		(void) nfs_rw_enter_sig(&svp->sv_lock, RW_READER, 0);
		supp_attrs = svp->sv_supp_attrs;
		nfs_rw_exit(&svp->sv_lock);

		/*
		 * For setgid case, we need to:
		 * 4:savefh(new) 5:putfh(dir) 6:getattr(dir) 7:restorefh(new)
		 */
		argop[4].argop = OP_SAVEFH;

		argop[5].argop = OP_CPUTFH;
		argop[5].nfs_argop4_u.opcputfh.sfh = drp->r_fh;

		argop[6].argop = OP_GETATTR;
		argop[6].nfs_argop4_u.opgetattr.attr_request = NFS4_VATTR_MASK;
		argop[6].nfs_argop4_u.opgetattr.mi = VTOMI4(dvp);

		argop[7].argop = OP_RESTOREFH;

		/*
		 * nverify
		 */
		_v.va_mask = AT_GID;
		_v.va_gid = in_va->va_gid;
		if (!(e.error = nfs4args_verify(&argop[8], &_v, OP_NVERIFY,
		    supp_attrs))) {

			/*
			 * setattr
			 *
			 * We _know_ we're not messing with AT_SIZE or
			 * AT_XTIME, so no need for stateid or flags.
			 * Also we specify NULL rp since we're only
			 * interested in setting owner_group attributes.
			 */
			nfs4args_setattr(&argop[9], &_v, NULL, 0, NULL, cr,
			    supp_attrs, &e.error, 0);
			if (e.error)
				nfs4args_verify_free(&argop[8]);
		}

		if (e.error) {
			/*
			 * XXX - Revisit the last argument to nfs4_end_op()
			 *	 once 5020486 is fixed.
			 */
			nfs4_end_open_seqid_sync(oop);
			open_owner_rele(oop);
			nfs4args_copen_free(open_args);
			nfs4_end_op(VTOMI4(dvp), dvp, vpi, &recov_state, TRUE);
			if (ncr != NULL)
				crfree(ncr);
			kmem_free(argop, argoplist_size);
			return (e.error);
		}
	} else if (create_flag) {
		argop[1].argop = OP_SAVEFH;

		argop[5].argop = OP_RESTOREFH;

		argop[6].argop = OP_GETATTR;
		argop[6].nfs_argop4_u.opgetattr.attr_request = NFS4_VATTR_MASK;
		argop[6].nfs_argop4_u.opgetattr.mi = VTOMI4(dvp);
	}

	NFS4_DEBUG(nfs4_client_call_debug, (CE_NOTE,
	    "nfs4open_otw: %s call, nm %s, rp %s",
	    needrecov ? "recov" : "first", file_name,
	    rnode4info(VTOR4(dvp))));

	t = gethrtime();

	rfs4call(VTOMI4(dvp), &args, &res, cred_otw, &doqueue, 0, &e);

	if (!e.error && nfs4_need_to_bump_seqid(&res))
		nfs4_set_open_seqid(seqid, oop, args.ctag);

	needrecov = nfs4_needs_recovery(&e, TRUE, dvp->v_vfsp);

	if (e.error || needrecov) {
		bool_t abort = FALSE;

		if (needrecov) {
			nfs4_bseqid_entry_t *bsep = NULL;

			nfs4open_save_lost_rqst(e.error, &lost_rqst, oop,
			    cred_otw, vpi, dvp, open_args);

			if (!e.error && res.status == NFS4ERR_BAD_SEQID) {
				bsep = nfs4_create_bseqid_entry(oop, NULL,
				    vpi, 0, args.ctag, open_args->seqid);
				num_bseqid_retry--;
			}

			abort = nfs4_start_recovery(&e, VTOMI4(dvp), dvp, vpi,
			    NULL, lost_rqst.lr_op == OP_OPEN ?
			    &lost_rqst : NULL, OP_OPEN, bsep, NULL, NULL);

			if (bsep)
				kmem_free(bsep, sizeof (*bsep));
			/* give up if we keep getting BAD_SEQID */
			if (num_bseqid_retry == 0)
				abort = TRUE;
			if (abort == TRUE && e.error == 0)
				e.error = geterrno4(res.status);
		}
		nfs4_end_open_seqid_sync(oop);
		open_owner_rele(oop);
		nfs4_end_op(VTOMI4(dvp), dvp, vpi, &recov_state, needrecov);
		nfs4args_copen_free(open_args);
		if (setgid_flag) {
			nfs4args_verify_free(&argop[8]);
			nfs4args_setattr_free(&argop[9]);
		}
		if (!e.error)
			(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
		if (ncr != NULL) {
			crfree(ncr);
			ncr = NULL;
		}
		if (!needrecov || abort == TRUE || e.error == EINTR ||
		    NFS4_FRC_UNMT_ERR(e.error, dvp->v_vfsp)) {
			kmem_free(argop, argoplist_size);
			return (e.error);
		}
		goto recov_retry;
	}

	/*
	 * Will check and update lease after checking the rflag for
	 * OPEN_CONFIRM in the successful OPEN call.
	 */
	if (res.status != NFS4_OK && res.array_len <= idx_fattr + 1) {

		/*
		 * XXX what if we're crossing mount points from server1:/drp
		 * to server2:/drp/rp.
		 */

		/* Signal our end of use of the open seqid */
		nfs4_end_open_seqid_sync(oop);

		/*
		 * This will destroy the open owner if it was just created,
		 * and no one else has put a reference on it.
		 */
		open_owner_rele(oop);
		if (create_flag && (createmode != EXCLUSIVE4) &&
		    res.status == NFS4ERR_BADOWNER)
			nfs4_log_badowner(VTOMI4(dvp), OP_OPEN);

		e.error = geterrno4(res.status);
		nfs4args_copen_free(open_args);
		if (setgid_flag) {
			nfs4args_verify_free(&argop[8]);
			nfs4args_setattr_free(&argop[9]);
		}
		(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
		nfs4_end_op(VTOMI4(dvp), dvp, vpi, &recov_state, needrecov);
		/*
		 * If the reply is NFS4ERR_ACCESS, it may be because
		 * we are root (no root net access).  If the real uid
		 * is not root, then retry with the real uid instead.
		 */
		if (ncr != NULL) {
			crfree(ncr);
			ncr = NULL;
		}
		if (res.status == NFS4ERR_ACCESS &&
		    (ncr = crnetadjust(cred_otw)) != NULL) {
			cred_otw = ncr;
			goto recov_retry;
		}
		kmem_free(argop, argoplist_size);
		return (e.error);
	}

	resop = &res.array[idx_open];  /* open res */
	op_res = &resop->nfs_resop4_u.opopen;

#ifdef DEBUG
	/*
	 * verify attrset bitmap
	 */
	if (create_flag &&
	    (createmode == UNCHECKED4 || createmode == GUARDED4)) {
		/* make sure attrset returned is what we asked for */
		/* XXX Ignore this 'error' for now */
		if (attr->attrmask != op_res->attrset)
			/* EMPTY */;
	}
#endif

	if (op_res->rflags & OPEN4_RESULT_LOCKTYPE_POSIX) {
		mutex_enter(&VTOMI4(dvp)->mi_lock);
		VTOMI4(dvp)->mi_flags |= MI4_POSIX_LOCK;
		mutex_exit(&VTOMI4(dvp)->mi_lock);
	}

	resop = &res.array[idx_open + 1];  /* getfh res */
	gf_res = &resop->nfs_resop4_u.opgetfh;

	otw_sfh = sfh4_get(&gf_res->object, VTOMI4(dvp));

	/*
	 * The open stateid has been updated on the server but not
	 * on the client yet.  There is a path: makenfs4node->nfs4_attr_cache->
	 * flush_pages->VOP_PUTPAGE->...->nfs4write where we will issue an OTW
	 * WRITE call.  That, however, will use the old stateid, so go ahead
	 * and upate the open stateid now, before any call to makenfs4node.
	 */
	if (vpi) {
		nfs4_open_stream_t	*tmp_osp;
		rnode4_t		*tmp_rp = VTOR4(vpi);

		tmp_osp = find_open_stream(oop, tmp_rp);
		if (tmp_osp) {
			tmp_osp->open_stateid = op_res->stateid;
			mutex_exit(&tmp_osp->os_sync_lock);
			open_stream_rele(tmp_osp, tmp_rp);
		}

		/*
		 * We must determine if the file handle given by the otw open
		 * is the same as the file handle which was passed in with
		 * *vpp.  This case can be reached if the file we are trying
		 * to open has been removed and another file has been created
		 * having the same file name.  The passed in vnode is released
		 * later.
		 */
		orig_sfh = VTOR4(vpi)->r_fh;
		fh_differs = nfs4cmpfh(&orig_sfh->sfh_fh, &otw_sfh->sfh_fh);
	}

	garp = &res.array[idx_fattr].nfs_resop4_u.opgetattr.ga_res;

	if (create_flag || fh_differs) {
		int rnode_err = 0;

		vp = makenfs4node(otw_sfh, garp, dvp->v_vfsp, t, cr,
		    dvp, fn_get(VTOSV(dvp)->sv_name, file_name, otw_sfh));

		if (e.error)
			PURGE_ATTRCACHE4(vp);
		/*
		 * For the newly created vp case, make sure the rnode
		 * isn't bad before using it.
		 */
		mutex_enter(&(VTOR4(vp))->r_statelock);
		if (VTOR4(vp)->r_flags & R4RECOVERR)
			rnode_err = EIO;
		mutex_exit(&(VTOR4(vp))->r_statelock);

		if (rnode_err) {
			nfs4_end_open_seqid_sync(oop);
			nfs4args_copen_free(open_args);
			if (setgid_flag) {
				nfs4args_verify_free(&argop[8]);
				nfs4args_setattr_free(&argop[9]);
			}
			(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
			nfs4_end_op(VTOMI4(dvp), dvp, vpi, &recov_state,
			    needrecov);
			open_owner_rele(oop);
			VN_RELE(vp);
			if (ncr != NULL)
				crfree(ncr);
			sfh4_rele(&otw_sfh);
			kmem_free(argop, argoplist_size);
			return (EIO);
		}
	} else {
		vp = vpi;
	}
	sfh4_rele(&otw_sfh);

	/*
	 * It seems odd to get a full set of attrs and then not update
	 * the object's attrcache in the non-create case.  Create case uses
	 * the attrs since makenfs4node checks to see if the attrs need to
	 * be updated (and then updates them).  The non-create case should
	 * update attrs also.
	 */
	if (! create_flag && ! fh_differs && !e.error) {
		nfs4_attr_cache(vp, garp, t, cr, TRUE, NULL);
	}

	nfs4_error_zinit(&e);
	if (op_res->rflags & OPEN4_RESULT_CONFIRM) {
		/* This does not do recovery for vp explicitly. */
		nfs4open_confirm(vp, &seqid, &op_res->stateid, cred_otw, FALSE,
		    &retry_open, oop, FALSE, &e, &num_bseqid_retry);

		if (e.error || e.stat) {
			nfs4_end_open_seqid_sync(oop);
			nfs4args_copen_free(open_args);
			if (setgid_flag) {
				nfs4args_verify_free(&argop[8]);
				nfs4args_setattr_free(&argop[9]);
			}
			(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
			nfs4_end_op(VTOMI4(dvp), dvp, vpi, &recov_state,
			    needrecov);
			open_owner_rele(oop);
			if (create_flag || fh_differs) {
				/* rele the makenfs4node */
				VN_RELE(vp);
			}
			if (ncr != NULL) {
				crfree(ncr);
				ncr = NULL;
			}
			if (retry_open == TRUE) {
				NFS4_DEBUG(nfs4_client_recov_debug, (CE_NOTE,
				    "nfs4open_otw: retry the open since OPEN "
				    "CONFIRM failed with error %d stat %d",
				    e.error, e.stat));
				if (create_flag && createmode == GUARDED4) {
					NFS4_DEBUG(nfs4_client_recov_debug,
					    (CE_NOTE, "nfs4open_otw: switch "
					    "createmode from GUARDED4 to "
					    "UNCHECKED4"));
					createmode = UNCHECKED4;
				}
				goto recov_retry;
			}
			if (!e.error) {
				if (create_flag && (createmode != EXCLUSIVE4) &&
				    e.stat == NFS4ERR_BADOWNER)
					nfs4_log_badowner(VTOMI4(dvp), OP_OPEN);

				e.error = geterrno4(e.stat);
			}
			kmem_free(argop, argoplist_size);
			return (e.error);
		}
	}

	rp = VTOR4(vp);

	mutex_enter(&rp->r_statev4_lock);
	if (create_flag)
		rp->created_v4 = 1;
	mutex_exit(&rp->r_statev4_lock);

	mutex_enter(&oop->oo_lock);
	/* Doesn't matter if 'oo_just_created' already was set as this */
	oop->oo_just_created = NFS4_PERM_CREATED;
	if (oop->oo_cred_otw)
		crfree(oop->oo_cred_otw);
	oop->oo_cred_otw = cred_otw;
	crhold(oop->oo_cred_otw);
	mutex_exit(&oop->oo_lock);

	/* returns with 'os_sync_lock' held */
	osp = find_or_create_open_stream(oop, rp, &created_osp);
	if (!osp) {
		NFS4_DEBUG(nfs4_client_state_debug, (CE_NOTE,
		    "nfs4open_otw: failed to create an open stream"));
		NFS4_DEBUG(nfs4_seqid_sync, (CE_NOTE, "nfs4open_otw: "
		    "signal our end of use of the open seqid"));

		nfs4_end_open_seqid_sync(oop);
		open_owner_rele(oop);
		nfs4args_copen_free(open_args);
		if (setgid_flag) {
			nfs4args_verify_free(&argop[8]);
			nfs4args_setattr_free(&argop[9]);
		}
		(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
		nfs4_end_op(VTOMI4(dvp), dvp, vpi, &recov_state, needrecov);
		if (create_flag || fh_differs)
			VN_RELE(vp);
		if (ncr != NULL)
			crfree(ncr);

		kmem_free(argop, argoplist_size);
		return (EINVAL);

	}

	osp->open_stateid = op_res->stateid;

	if (open_flag & FREAD)
		osp->os_share_acc_read++;
	if (open_flag & FWRITE)
		osp->os_share_acc_write++;
	osp->os_share_deny_none++;

	/*
	 * Need to reset this bitfield for the possible case where we were
	 * going to OTW CLOSE the file, got a non-recoverable error, and before
	 * we could retry the CLOSE, OPENed the file again.
	 */
	ASSERT(osp->os_open_owner->oo_seqid_inuse);
	osp->os_final_close = 0;
	osp->os_force_close = 0;
#ifdef DEBUG
	if (osp->os_failed_reopen)
		NFS4_DEBUG(nfs4_open_stream_debug, (CE_NOTE, "nfs4open_otw:"
		    " clearing os_failed_reopen for osp %p, cr %p, rp %s",
		    (void *)osp, (void *)cr, rnode4info(rp)));
#endif
	osp->os_failed_reopen = 0;

	mutex_exit(&osp->os_sync_lock);

	nfs4_end_open_seqid_sync(oop);

	if (created_osp && recov_state.rs_sp != NULL) {
		mutex_enter(&recov_state.rs_sp->s_lock);
		nfs4_inc_state_ref_count_nolock(recov_state.rs_sp, VTOMI4(dvp));
		mutex_exit(&recov_state.rs_sp->s_lock);
	}

	/* get rid of our reference to find oop */
	open_owner_rele(oop);

	open_stream_rele(osp, rp);

	/* accept delegation, if any */
	nfs4_delegation_accept(rp, CLAIM_NULL, op_res, garp, cred_otw);

	nfs4_end_op(VTOMI4(dvp), dvp, vpi, &recov_state, needrecov);

	if (createmode == EXCLUSIVE4 &&
	    (in_va->va_mask & ~(AT_GID | AT_SIZE))) {
		NFS4_DEBUG(nfs4_client_state_debug, (CE_NOTE, "nfs4open_otw:"
		    " EXCLUSIVE4: sending a SETATTR"));
		/*
		 * If doing an exclusive create, then generate
		 * a SETATTR to set the initial attributes.
		 * Try to set the mtime and the atime to the
		 * server's current time.  It is somewhat
		 * expected that these fields will be used to
		 * store the exclusive create cookie.  If not,
		 * server implementors will need to know that
		 * a SETATTR will follow an exclusive create
		 * and the cookie should be destroyed if
		 * appropriate.
		 *
		 * The AT_GID and AT_SIZE bits are turned off
		 * so that the SETATTR request will not attempt
		 * to process these.  The gid will be set
		 * separately if appropriate.  The size is turned
		 * off because it is assumed that a new file will
		 * be created empty and if the file wasn't empty,
		 * then the exclusive create will have failed
		 * because the file must have existed already.
		 * Therefore, no truncate operation is needed.
		 */
		in_va->va_mask &= ~(AT_GID | AT_SIZE);
		in_va->va_mask |= (AT_MTIME | AT_ATIME);

		e.error = nfs4setattr(vp, in_va, 0, cr, NULL);
		if (e.error) {
			/*
			 * Couldn't correct the attributes of
			 * the newly created file and the
			 * attributes are wrong.  Remove the
			 * file and return an error to the
			 * application.
			 */
			/* XXX will this take care of client state ? */
			NFS4_DEBUG(nfs4_client_state_debug, (CE_NOTE,
			    "nfs4open_otw: EXCLUSIVE4: error %d on SETATTR:"
			    " remove file", e.error));
			VN_RELE(vp);
			(void) nfs4_remove(dvp, file_name, cr, NULL, 0);
			/*
			 * Since we've reled the vnode and removed
			 * the file we now need to return the error.
			 * At this point we don't want to update the
			 * dircaches, call nfs4_waitfor_purge_complete
			 * or set vpp to vp so we need to skip these
			 * as well.
			 */
			goto skip_update_dircaches;
		}
	}

	/*
	 * If we created or found the correct vnode, due to create_flag or
	 * fh_differs being set, then update directory cache attribute, readdir
	 * and dnlc caches.
	 */
	if (create_flag || fh_differs) {
		dirattr_info_t dinfo, *dinfop;

		/*
		 * Make sure getattr succeeded before using results.
		 * note: op 7 is getattr(dir) for both flavors of
		 * open(create).
		 */
		if (create_flag && res.status == NFS4_OK) {
			dinfo.di_time_call = t;
			dinfo.di_cred = cr;
			dinfo.di_garp =
			    &res.array[6].nfs_resop4_u.opgetattr.ga_res;
			dinfop = &dinfo;
		} else {
			dinfop = NULL;
		}

		nfs4_update_dircaches(&op_res->cinfo, dvp, vp, file_name,
		    dinfop);
	}

	/*
	 * If the page cache for this file was flushed from actions
	 * above, it was done asynchronously and if that is true,
	 * there is a need to wait here for it to complete.  This must
	 * be done outside of start_fop/end_fop.
	 */
	(void) nfs4_waitfor_purge_complete(vp);

	/*
	 * It is implicit that we are in the open case (create_flag == 0) since
	 * fh_differs can only be set to a non-zero value in the open case.
	 */
	if (fh_differs != 0 && vpi != NULL)
		VN_RELE(vpi);

	/*
	 * Be sure to set *vpp to the correct value before returning.
	 */
	*vpp = vp;

skip_update_dircaches:

	nfs4args_copen_free(open_args);
	if (setgid_flag) {
		nfs4args_verify_free(&argop[8]);
		nfs4args_setattr_free(&argop[9]);
	}
	(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);

	if (ncr)
		crfree(ncr);
	kmem_free(argop, argoplist_size);
	return (e.error);
}

/*
 * Reopen an open instance.  cf. nfs4open_otw().
 *
 * Errors are returned by the nfs4_error_t parameter.
 * - ep->error contains an errno value or zero.
 * - if it is zero, ep->stat is set to an NFS status code, if any.
 *   If the file could not be reopened, but the caller should continue, the
 *   file is marked dead and no error values are returned.  If the caller
 *   should stop recovering open files and start over, either the ep->error
 *   value or ep->stat will indicate an error (either something that requires
 *   recovery or EAGAIN).  Note that some recovery (e.g., expired volatile
 *   filehandles) may be handled silently by this routine.
 * - if it is EINTR, ETIMEDOUT, or NFS4_FRC_UNMT_ERR, recovery for lost state
 *   will be started, so the caller should not do it.
 *
 * Gotos:
 * - kill_file : reopen failed in such a fashion to constitute marking the
 *    file dead and setting the open stream's 'os_failed_reopen' as 1.  This
 *   is for cases where recovery is not possible.
 * - failed_reopen : same as above, except that the file has already been
 *   marked dead, so no need to do it again.
 * - bailout : reopen failed but we are able to recover and retry the reopen -
 *   either within this function immediately or via the calling function.
 */

void
nfs4_reopen(vnode_t *vp, nfs4_open_stream_t *osp, nfs4_error_t *ep,
    open_claim_type4 claim, bool_t frc_use_claim_previous,
    bool_t is_recov)
{
	COMPOUND4args_clnt args;
	COMPOUND4res_clnt res;
	nfs_argop4 argop[4];
	nfs_resop4 *resop;
	OPEN4res *op_res = NULL;
	OPEN4cargs *open_args;
	GETFH4res *gf_res;
	rnode4_t *rp = VTOR4(vp);
	int doqueue = 1;
	cred_t *cr = NULL, *cred_otw = NULL;
	nfs4_open_owner_t *oop = NULL;
	seqid4 seqid;
	nfs4_ga_res_t *garp;
	char fn[MAXNAMELEN];
	nfs4_recov_state_t recov = {NULL, 0};
	nfs4_lost_rqst_t lost_rqst;
	mntinfo4_t *mi = VTOMI4(vp);
	bool_t abort;
	char *failed_msg = "";
	int fh_different;
	hrtime_t t;
	nfs4_bseqid_entry_t *bsep = NULL;

	ASSERT(nfs4_consistent_type(vp));
	ASSERT(nfs_zone() == mi->mi_zone);

	nfs4_error_zinit(ep);

	/* this is the cred used to find the open owner */
	cr = state_to_cred(osp);
	if (cr == NULL) {
		failed_msg = "Couldn't reopen: no cred";
		goto kill_file;
	}
	/* use this cred for OTW operations */
	cred_otw = nfs4_get_otw_cred(cr, mi, osp->os_open_owner);

top:
	nfs4_error_zinit(ep);

	if (mi->mi_vfsp->vfs_flag & VFS_UNMOUNTED) {
		/* File system has been unmounted, quit */
		ep->error = EIO;
		failed_msg = "Couldn't reopen: file system has been unmounted";
		goto kill_file;
	}

	oop = osp->os_open_owner;

	ASSERT(oop != NULL);
	if (oop == NULL) {	/* be defensive in non-DEBUG */
		failed_msg = "can't reopen: no open owner";
		goto kill_file;
	}
	open_owner_hold(oop);

	ep->error = nfs4_start_open_seqid_sync(oop, mi);
	if (ep->error) {
		open_owner_rele(oop);
		oop = NULL;
		goto bailout;
	}

	/*
	 * If the rnode has a delegation and the delegation has been
	 * recovered and the server didn't request a recall and the caller
	 * didn't specifically ask for CLAIM_PREVIOUS (nfs4frlock during
	 * recovery) and the rnode hasn't been marked dead, then install
	 * the delegation stateid in the open stream.  Otherwise, proceed
	 * with a CLAIM_PREVIOUS or CLAIM_NULL OPEN.
	 */
	mutex_enter(&rp->r_statev4_lock);
	if (rp->r_deleg_type != OPEN_DELEGATE_NONE &&
	    !rp->r_deleg_return_pending &&
	    (rp->r_deleg_needs_recovery == OPEN_DELEGATE_NONE) &&
	    !rp->r_deleg_needs_recall &&
	    claim != CLAIM_DELEGATE_CUR && !frc_use_claim_previous &&
	    !(rp->r_flags & R4RECOVERR)) {
		mutex_enter(&osp->os_sync_lock);
		osp->os_delegation = 1;
		osp->open_stateid = rp->r_deleg_stateid;
		mutex_exit(&osp->os_sync_lock);
		mutex_exit(&rp->r_statev4_lock);
		goto bailout;
	}
	mutex_exit(&rp->r_statev4_lock);

	/*
	 * If the file failed recovery, just quit.  This failure need not
	 * affect other reopens, so don't return an error.
	 */
	mutex_enter(&rp->r_statelock);
	if (rp->r_flags & R4RECOVERR) {
		mutex_exit(&rp->r_statelock);
		ep->error = 0;
		goto failed_reopen;
	}
	mutex_exit(&rp->r_statelock);

	/*
	 * argop is empty here
	 *
	 * PUTFH, OPEN, GETATTR
	 */
	args.ctag = TAG_REOPEN;
	args.array_len = 4;
	args.array = argop;

	NFS4_DEBUG(nfs4_client_failover_debug, (CE_NOTE,
	    "nfs4_reopen: file is type %d, id %s",
	    vp->v_type, rnode4info(VTOR4(vp))));

	argop[0].argop = OP_CPUTFH;

	if (claim != CLAIM_PREVIOUS) {
		/*
		 * if this is a file mount then
		 * use the mntinfo parentfh
		 */
		argop[0].nfs_argop4_u.opcputfh.sfh =
		    (vp->v_flag & VROOT) ? mi->mi_srvparentfh :
		    VTOSV(vp)->sv_dfh;
	} else {
		/* putfh fh to reopen */
		argop[0].nfs_argop4_u.opcputfh.sfh = rp->r_fh;
	}

	argop[1].argop = OP_COPEN;
	open_args = &argop[1].nfs_argop4_u.opcopen;
	open_args->claim = claim;

	if (claim == CLAIM_NULL) {

		if ((ep->error = vtoname(vp, fn, MAXNAMELEN)) != 0) {
			nfs_cmn_err(ep->error, CE_WARN, "nfs4_reopen: vtoname "
			    "failed for vp 0x%p for CLAIM_NULL with %m",
			    (void *)vp);
			failed_msg = "Couldn't reopen: vtoname failed for "
			    "CLAIM_NULL";
			/* nothing allocated yet */
			goto kill_file;
		}

		open_args->open_claim4_u.cfile = fn;
	} else if (claim == CLAIM_PREVIOUS) {

		/*
		 * We have two cases to deal with here:
		 * 1) We're being called to reopen files in order to satisfy
		 *    a lock operation request which requires us to explicitly
		 *    reopen files which were opened under a delegation.  If
		 *    we're in recovery, we *must* use CLAIM_PREVIOUS.  In
		 *    that case, frc_use_claim_previous is TRUE and we must
		 *    use the rnode's current delegation type (r_deleg_type).
		 * 2) We're reopening files during some form of recovery.
		 *    In this case, frc_use_claim_previous is FALSE and we
		 *    use the delegation type appropriate for recovery
		 *    (r_deleg_needs_recovery).
		 */
		mutex_enter(&rp->r_statev4_lock);
		open_args->open_claim4_u.delegate_type =
		    frc_use_claim_previous ?
		    rp->r_deleg_type :
		    rp->r_deleg_needs_recovery;
		mutex_exit(&rp->r_statev4_lock);

	} else if (claim == CLAIM_DELEGATE_CUR) {

		if ((ep->error = vtoname(vp, fn, MAXNAMELEN)) != 0) {
			nfs_cmn_err(ep->error, CE_WARN, "nfs4_reopen: vtoname "
			    "failed for vp 0x%p for CLAIM_DELEGATE_CUR "
			    "with %m", (void *)vp);
			failed_msg = "Couldn't reopen: vtoname failed for "
			    "CLAIM_DELEGATE_CUR";
			/* nothing allocated yet */
			goto kill_file;
		}

		mutex_enter(&rp->r_statev4_lock);
		open_args->open_claim4_u.delegate_cur_info.delegate_stateid =
		    rp->r_deleg_stateid;
		mutex_exit(&rp->r_statev4_lock);

		open_args->open_claim4_u.delegate_cur_info.cfile = fn;
	}
	open_args->opentype = OPEN4_NOCREATE;
	open_args->owner.clientid = mi2clientid(mi);
	open_args->owner.owner_len = sizeof (oop->oo_name);
	open_args->owner.owner_val =
	    kmem_alloc(open_args->owner.owner_len, KM_SLEEP);
	bcopy(&oop->oo_name, open_args->owner.owner_val,
	    open_args->owner.owner_len);
	open_args->share_access = 0;
	open_args->share_deny = 0;

	mutex_enter(&osp->os_sync_lock);
	NFS4_DEBUG(nfs4_client_recov_debug, (CE_NOTE, "nfs4_reopen: osp %p rp "
	    "%p: read acc %"PRIu64" write acc %"PRIu64": open ref count %d: "
	    "mmap read %"PRIu64" mmap write %"PRIu64" claim %d ",
	    (void *)osp, (void *)rp, osp->os_share_acc_read,
	    osp->os_share_acc_write, osp->os_open_ref_count,
	    osp->os_mmap_read, osp->os_mmap_write, claim));

	if (osp->os_share_acc_read || osp->os_mmap_read)
		open_args->share_access |= OPEN4_SHARE_ACCESS_READ;
	if (osp->os_share_acc_write || osp->os_mmap_write)
		open_args->share_access |= OPEN4_SHARE_ACCESS_WRITE;
	if (osp->os_share_deny_read)
		open_args->share_deny |= OPEN4_SHARE_DENY_READ;
	if (osp->os_share_deny_write)
		open_args->share_deny |= OPEN4_SHARE_DENY_WRITE;
	mutex_exit(&osp->os_sync_lock);

	seqid = nfs4_get_open_seqid(oop) + 1;
	open_args->seqid = seqid;

	/* Construct the getfh part of the compound */
	argop[2].argop = OP_GETFH;

	/* Construct the getattr part of the compound */
	argop[3].argop = OP_GETATTR;
	argop[3].nfs_argop4_u.opgetattr.attr_request = NFS4_VATTR_MASK;
	argop[3].nfs_argop4_u.opgetattr.mi = mi;

	t = gethrtime();

	rfs4call(mi, &args, &res, cred_otw, &doqueue, 0, ep);

	if (ep->error) {
		if (!is_recov && !frc_use_claim_previous &&
		    (ep->error == EINTR || ep->error == ETIMEDOUT ||
		    NFS4_FRC_UNMT_ERR(ep->error, vp->v_vfsp))) {
			nfs4open_save_lost_rqst(ep->error, &lost_rqst, oop,
			    cred_otw, vp, NULL, open_args);
			abort = nfs4_start_recovery(ep,
			    VTOMI4(vp), vp, NULL, NULL,
			    lost_rqst.lr_op == OP_OPEN ?
			    &lost_rqst : NULL, OP_OPEN, NULL, NULL, NULL);
			nfs4args_copen_free(open_args);
			goto bailout;
		}

		nfs4args_copen_free(open_args);

		if (ep->error == EACCES && cred_otw != cr) {
			crfree(cred_otw);
			cred_otw = cr;
			crhold(cred_otw);
			nfs4_end_open_seqid_sync(oop);
			open_owner_rele(oop);
			oop = NULL;
			goto top;
		}
		if (ep->error == ETIMEDOUT)
			goto bailout;
		failed_msg = "Couldn't reopen: rpc error";
		goto kill_file;
	}

	if (nfs4_need_to_bump_seqid(&res))
		nfs4_set_open_seqid(seqid, oop, args.ctag);

	switch (res.status) {
	case NFS4_OK:
		if (recov.rs_flags & NFS4_RS_DELAY_MSG) {
			mutex_enter(&rp->r_statelock);
			rp->r_delay_interval = 0;
			mutex_exit(&rp->r_statelock);
		}
		break;
	case NFS4ERR_BAD_SEQID:
		bsep = nfs4_create_bseqid_entry(oop, NULL, vp, 0,
		    args.ctag, open_args->seqid);

		abort = nfs4_start_recovery(ep, VTOMI4(vp), vp, NULL,
		    NULL, lost_rqst.lr_op == OP_OPEN ? &lost_rqst :
		    NULL, OP_OPEN, bsep, NULL, NULL);

		nfs4args_copen_free(open_args);
		(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
		nfs4_end_open_seqid_sync(oop);
		open_owner_rele(oop);
		oop = NULL;
		kmem_free(bsep, sizeof (*bsep));

		goto kill_file;
	case NFS4ERR_NO_GRACE:
		nfs4args_copen_free(open_args);
		(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
		nfs4_end_open_seqid_sync(oop);
		open_owner_rele(oop);
		oop = NULL;
		if (claim == CLAIM_PREVIOUS) {
			/*
			 * Retry as a plain open. We don't need to worry about
			 * checking the changeinfo: it is acceptable for a
			 * client to re-open a file and continue processing
			 * (in the absence of locks).
			 */
			NFS4_DEBUG(nfs4_client_recov_debug, (CE_NOTE,
			    "nfs4_reopen: CLAIM_PREVIOUS: NFS4ERR_NO_GRACE; "
			    "will retry as CLAIM_NULL"));
			claim = CLAIM_NULL;
			nfs4_mi_kstat_inc_no_grace(mi);
			goto top;
		}
		failed_msg =
		    "Couldn't reopen: tried reclaim outside grace period. ";
		goto kill_file;
	case NFS4ERR_GRACE:
		nfs4_set_grace_wait(mi);
		nfs4args_copen_free(open_args);
		(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
		nfs4_end_open_seqid_sync(oop);
		open_owner_rele(oop);
		oop = NULL;
		ep->error = nfs4_wait_for_grace(mi, &recov);
		if (ep->error != 0)
			goto bailout;
		goto top;
	case NFS4ERR_DELAY:
		nfs4_set_delay_wait(vp);
		nfs4args_copen_free(open_args);
		(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
		nfs4_end_open_seqid_sync(oop);
		open_owner_rele(oop);
		oop = NULL;
		ep->error = nfs4_wait_for_delay(vp, &recov);
		nfs4_mi_kstat_inc_delay(mi);
		if (ep->error != 0)
			goto bailout;
		goto top;
	case NFS4ERR_FHEXPIRED:
		/* recover filehandle and retry */
		abort = nfs4_start_recovery(ep,
		    mi, vp, NULL, NULL, NULL, OP_OPEN, NULL, NULL, NULL);
		nfs4args_copen_free(open_args);
		(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
		nfs4_end_open_seqid_sync(oop);
		open_owner_rele(oop);
		oop = NULL;
		if (abort == FALSE)
			goto top;
		failed_msg = "Couldn't reopen: recovery aborted";
		goto kill_file;
	case NFS4ERR_RESOURCE:
	case NFS4ERR_STALE_CLIENTID:
	case NFS4ERR_WRONGSEC:
	case NFS4ERR_EXPIRED:
		/*
		 * Do not mark the file dead and let the calling
		 * function initiate recovery.
		 */
		nfs4args_copen_free(open_args);
		(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
		nfs4_end_open_seqid_sync(oop);
		open_owner_rele(oop);
		oop = NULL;
		goto bailout;
	case NFS4ERR_ACCESS:
		if (cred_otw != cr) {
			crfree(cred_otw);
			cred_otw = cr;
			crhold(cred_otw);
			nfs4args_copen_free(open_args);
			(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
			nfs4_end_open_seqid_sync(oop);
			open_owner_rele(oop);
			oop = NULL;
			goto top;
		}
		/* fall through */
	default:
		NFS4_DEBUG(nfs4_client_failover_debug, (CE_NOTE,
		    "nfs4_reopen: r_server 0x%p, mi_curr_serv 0x%p, rnode %s",
		    (void*)VTOR4(vp)->r_server, (void*)mi->mi_curr_serv,
		    rnode4info(VTOR4(vp))));
		failed_msg = "Couldn't reopen: NFSv4 error";
		nfs4args_copen_free(open_args);
		(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
		goto kill_file;
	}

	resop = &res.array[1];  /* open res */
	op_res = &resop->nfs_resop4_u.opopen;

	garp = &res.array[3].nfs_resop4_u.opgetattr.ga_res;

	/*
	 * Check if the path we reopened really is the same
	 * file. We could end up in a situation where the file
	 * was removed and a new file created with the same name.
	 */
	resop = &res.array[2];
	gf_res = &resop->nfs_resop4_u.opgetfh;
	(void) nfs_rw_enter_sig(&mi->mi_fh_lock, RW_READER, 0);
	fh_different = (nfs4cmpfh(&rp->r_fh->sfh_fh, &gf_res->object) != 0);
	if (fh_different) {
		if (mi->mi_fh_expire_type == FH4_PERSISTENT ||
		    mi->mi_fh_expire_type & FH4_NOEXPIRE_WITH_OPEN) {
			/* Oops, we don't have the same file */
			if (mi->mi_fh_expire_type == FH4_PERSISTENT)
				failed_msg = "Couldn't reopen: Persistent "
				    "file handle changed";
			else
				failed_msg = "Couldn't reopen: Volatile "
				    "(no expire on open) file handle changed";

			nfs4args_copen_free(open_args);
			(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
			nfs_rw_exit(&mi->mi_fh_lock);
			goto kill_file;

		} else {
			/*
			 * We have volatile file handles that don't compare.
			 * If the fids are the same then we assume that the
			 * file handle expired but the rnode still refers to
			 * the same file object.
			 *
			 * First check that we have fids or not.
			 * If we don't we have a dumb server so we will
			 * just assume every thing is ok for now.
			 */
			if (!ep->error && garp->n4g_va.va_mask & AT_NODEID &&
			    rp->r_attr.va_mask & AT_NODEID &&
			    rp->r_attr.va_nodeid != garp->n4g_va.va_nodeid) {
				/*
				 * We have fids, but they don't
				 * compare. So kill the file.
				 */
				failed_msg =
				    "Couldn't reopen: file handle changed"
				    " due to mismatched fids";
				nfs4args_copen_free(open_args);
				(void) xdr_free(xdr_COMPOUND4res_clnt,
				    (caddr_t)&res);
				nfs_rw_exit(&mi->mi_fh_lock);
				goto kill_file;
			} else {
				/*
				 * We have volatile file handles that refers
				 * to the same file (at least they have the
				 * same fid) or we don't have fids so we
				 * can't tell. :(. We'll be a kind and accepting
				 * client so we'll update the rnode's file
				 * handle with the otw handle.
				 *
				 * We need to drop mi->mi_fh_lock since
				 * sh4_update acquires it. Since there is
				 * only one recovery thread there is no
				 * race.
				 */
				nfs_rw_exit(&mi->mi_fh_lock);
				sfh4_update(rp->r_fh, &gf_res->object);
			}
		}
	} else {
		nfs_rw_exit(&mi->mi_fh_lock);
	}

	ASSERT(nfs4_consistent_type(vp));

	/*
	 * If the server wanted an OPEN_CONFIRM but that fails, just start
	 * over.  Presumably if there is a persistent error it will show up
	 * when we resend the OPEN.
	 */
	if (op_res->rflags & OPEN4_RESULT_CONFIRM) {
		bool_t retry_open = FALSE;

		nfs4open_confirm(vp, &seqid, &op_res->stateid,
		    cred_otw, is_recov, &retry_open,
		    oop, FALSE, ep, NULL);
		if (ep->error || ep->stat) {
			nfs4args_copen_free(open_args);
			(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
			nfs4_end_open_seqid_sync(oop);
			open_owner_rele(oop);
			oop = NULL;
			goto top;
		}
	}

	mutex_enter(&osp->os_sync_lock);
	osp->open_stateid = op_res->stateid;
	osp->os_delegation = 0;
	/*
	 * Need to reset this bitfield for the possible case where we were
	 * going to OTW CLOSE the file, got a non-recoverable error, and before
	 * we could retry the CLOSE, OPENed the file again.
	 */
	ASSERT(osp->os_open_owner->oo_seqid_inuse);
	osp->os_final_close = 0;
	osp->os_force_close = 0;
	if (claim == CLAIM_DELEGATE_CUR || claim == CLAIM_PREVIOUS)
		osp->os_dc_openacc = open_args->share_access;
	mutex_exit(&osp->os_sync_lock);

	nfs4_end_open_seqid_sync(oop);

	/* accept delegation, if any */
	nfs4_delegation_accept(rp, claim, op_res, garp, cred_otw);

	nfs4args_copen_free(open_args);

	nfs4_attr_cache(vp, garp, t, cr, TRUE, NULL);

	(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);

	ASSERT(nfs4_consistent_type(vp));

	open_owner_rele(oop);
	crfree(cr);
	crfree(cred_otw);
	return;

kill_file:
	nfs4_fail_recov(vp, failed_msg, ep->error, ep->stat);
failed_reopen:
	NFS4_DEBUG(nfs4_open_stream_debug, (CE_NOTE,
	    "nfs4_reopen: setting os_failed_reopen for osp %p, cr %p, rp %s",
	    (void *)osp, (void *)cr, rnode4info(rp)));
	mutex_enter(&osp->os_sync_lock);
	osp->os_failed_reopen = 1;
	mutex_exit(&osp->os_sync_lock);
bailout:
	if (oop != NULL) {
		nfs4_end_open_seqid_sync(oop);
		open_owner_rele(oop);
	}
	if (cr != NULL)
		crfree(cr);
	if (cred_otw != NULL)
		crfree(cred_otw);
}

/* for . and .. OPENs */
/* ARGSUSED */
static int
nfs4_open_non_reg_file(vnode_t **vpp, int flag, cred_t *cr)
{
	rnode4_t *rp;
	nfs4_ga_res_t gar;

	ASSERT(nfs_zone() == VTOMI4(*vpp)->mi_zone);

	/*
	 * If close-to-open consistency checking is turned off or
	 * if there is no cached data, we can avoid
	 * the over the wire getattr.  Otherwise, force a
	 * call to the server to get fresh attributes and to
	 * check caches. This is required for close-to-open
	 * consistency.
	 */
	rp = VTOR4(*vpp);
	if (VTOMI4(*vpp)->mi_flags & MI4_NOCTO ||
	    (rp->r_dir == NULL && !nfs4_has_pages(*vpp)))
		return (0);

	gar.n4g_va.va_mask = AT_ALL;
	return (nfs4_getattr_otw(*vpp, &gar, cr, 0));
}

/*
 * CLOSE a file
 */
/* ARGSUSED */
static int
nfs4_close(vnode_t *vp, int flag, int count, offset_t offset, cred_t *cr,
	caller_context_t *ct)
{
	rnode4_t	*rp;
	int		 error = 0;
	int		 r_error = 0;
	int		 n4error = 0;
	nfs4_error_t	 e = { 0, NFS4_OK, RPC_SUCCESS };

	/*
	 * Remove client state for this (lockowner, file) pair.
	 * Issue otw v4 call to have the server do the same.
	 */

	rp = VTOR4(vp);

	/*
	 * zone_enter(2) prevents processes from changing zones with NFS files
	 * open; if we happen to get here from the wrong zone we can't do
	 * anything over the wire.
	 */
	if (VTOMI4(vp)->mi_zone != nfs_zone()) {
		/*
		 * We could attempt to clean up locks, except we're sure
		 * that the current process didn't acquire any locks on
		 * the file: any attempt to lock a file belong to another zone
		 * will fail, and one can't lock an NFS file and then change
		 * zones, as that fails too.
		 *
		 * Returning an error here is the sane thing to do.  A
		 * subsequent call to VN_RELE() which translates to a
		 * nfs4_inactive() will clean up state: if the zone of the
		 * vnode's origin is still alive and kicking, the inactive
		 * thread will handle the request (from the correct zone), and
		 * everything (minus the OTW close call) should be OK.  If the
		 * zone is going away nfs4_async_inactive() will throw away
		 * delegations, open streams and cached pages inline.
		 */
		return (EIO);
	}

	/*
	 * If we are using local locking for this filesystem, then
	 * release all of the SYSV style record locks.  Otherwise,
	 * we are doing network locking and we need to release all
	 * of the network locks.  All of the locks held by this
	 * process on this file are released no matter what the
	 * incoming reference count is.
	 */
	if (VTOMI4(vp)->mi_flags & MI4_LLOCK) {
		cleanlocks(vp, ttoproc(curthread)->p_pid, 0);
		cleanshares(vp, ttoproc(curthread)->p_pid);
	} else
		e.error = nfs4_lockrelease(vp, flag, offset, cr);

	if (e.error) {
		struct lm_sysid *lmsid;
		lmsid = nfs4_find_sysid(VTOMI4(vp));
		if (lmsid == NULL) {
			DTRACE_PROBE2(unknown__sysid, int, e.error,
			    vnode_t *, vp);
		} else {
			cleanlocks(vp, ttoproc(curthread)->p_pid,
			    (lm_sysidt(lmsid) | LM_SYSID_CLIENT));
		}
		return (e.error);
	}

	if (count > 1)
		return (0);

	/*
	 * If the file has been `unlinked', then purge the
	 * DNLC so that this vnode will get reycled quicker
	 * and the .nfs* file on the server will get removed.
	 */
	if (rp->r_unldvp != NULL)
		dnlc_purge_vp(vp);

	/*
	 * If the file was open for write and there are pages,
	 * do a synchronous flush and commit of all of the
	 * dirty and uncommitted pages.
	 */
	ASSERT(!e.error);
	if ((flag & FWRITE) && nfs4_has_pages(vp))
		error = nfs4_putpage_commit(vp, 0, 0, cr);

	mutex_enter(&rp->r_statelock);
	r_error = rp->r_error;
	rp->r_error = 0;
	mutex_exit(&rp->r_statelock);

	/*
	 * If this file type is one for which no explicit 'open' was
	 * done, then bail now (ie. no need for protocol 'close'). If
	 * there was an error w/the vm subsystem, return _that_ error,
	 * otherwise, return any errors that may've been reported via
	 * the rnode.
	 */
	if (vp->v_type != VREG)
		return (error ? error : r_error);

	/*
	 * The sync putpage commit may have failed above, but since
	 * we're working w/a regular file, we need to do the protocol
	 * 'close' (nfs4close_one will figure out if an otw close is
	 * needed or not). Report any errors _after_ doing the protocol
	 * 'close'.
	 */
	nfs4close_one(vp, NULL, cr, flag, NULL, &e, CLOSE_NORM, 0, 0, 0);
	n4error = e.error ? e.error : geterrno4(e.stat);

	/*
	 * Error reporting prio (Hi -> Lo)
	 *
	 *   i) nfs4_putpage_commit (error)
	 *  ii) rnode's (r_error)
	 * iii) nfs4close_one (n4error)
	 */
	return (error ? error : (r_error ? r_error : n4error));
}

/*
 * Initialize *lost_rqstp.
 */

static void
nfs4close_save_lost_rqst(int error, nfs4_lost_rqst_t *lost_rqstp,
    nfs4_open_owner_t *oop, nfs4_open_stream_t *osp, cred_t *cr,
    vnode_t *vp)
{
	if (error != ETIMEDOUT && error != EINTR &&
	    !NFS4_FRC_UNMT_ERR(error, vp->v_vfsp)) {
		lost_rqstp->lr_op = 0;
		return;
	}

	NFS4_DEBUG(nfs4_lost_rqst_debug, (CE_NOTE,
	    "nfs4close_save_lost_rqst: error %d", error));

	lost_rqstp->lr_op = OP_CLOSE;
	/*
	 * The vp is held and rele'd via the recovery code.
	 * See nfs4_save_lost_rqst.
	 */
	lost_rqstp->lr_vp = vp;
	lost_rqstp->lr_dvp = NULL;
	lost_rqstp->lr_oop = oop;
	lost_rqstp->lr_osp = osp;
	ASSERT(osp != NULL);
	ASSERT(mutex_owned(&osp->os_sync_lock));
	osp->os_pending_close = 1;
	lost_rqstp->lr_lop = NULL;
	lost_rqstp->lr_cr = cr;
	lost_rqstp->lr_flk = NULL;
	lost_rqstp->lr_putfirst = FALSE;
}

/*
 * Assumes you already have the open seqid sync grabbed as well as the
 * 'os_sync_lock'.  Note: this will release the open seqid sync and
 * 'os_sync_lock' if client recovery starts.  Calling functions have to
 * be prepared to handle this.
 *
 * 'recov' is returned as 1 if the CLOSE operation detected client recovery
 * was needed and was started, and that the calling function should retry
 * this function; otherwise it is returned as 0.
 *
 * Errors are returned via the nfs4_error_t parameter.
 */
static void
nfs4close_otw(rnode4_t *rp, cred_t *cred_otw, nfs4_open_owner_t *oop,
    nfs4_open_stream_t *osp, int *recov, int *did_start_seqid_syncp,
    nfs4_close_type_t close_type, nfs4_error_t *ep, int *have_sync_lockp)
{
	COMPOUND4args_clnt args;
	COMPOUND4res_clnt res;
	CLOSE4args *close_args;
	nfs_resop4 *resop;
	nfs_argop4 argop[3];
	int doqueue = 1;
	mntinfo4_t *mi;
	seqid4 seqid;
	vnode_t *vp;
	bool_t needrecov = FALSE;
	nfs4_lost_rqst_t lost_rqst;
	hrtime_t t;

	ASSERT(nfs_zone() == VTOMI4(RTOV4(rp))->mi_zone);

	ASSERT(MUTEX_HELD(&osp->os_sync_lock));

	NFS4_DEBUG(nfs4_client_state_debug, (CE_NOTE, "nfs4close_otw"));

	/* Only set this to 1 if recovery is started */
	*recov = 0;

	/* do the OTW call to close the file */

	if (close_type == CLOSE_RESEND)
		args.ctag = TAG_CLOSE_LOST;
	else if (close_type == CLOSE_AFTER_RESEND)
		args.ctag = TAG_CLOSE_UNDO;
	else
		args.ctag = TAG_CLOSE;

	args.array_len = 3;
	args.array = argop;

	vp = RTOV4(rp);

	mi = VTOMI4(vp);

	/* putfh target fh */
	argop[0].argop = OP_CPUTFH;
	argop[0].nfs_argop4_u.opcputfh.sfh = rp->r_fh;

	argop[1].argop = OP_GETATTR;
	argop[1].nfs_argop4_u.opgetattr.attr_request = NFS4_VATTR_MASK;
	argop[1].nfs_argop4_u.opgetattr.mi = mi;

	argop[2].argop = OP_CLOSE;
	close_args = &argop[2].nfs_argop4_u.opclose;

	seqid = nfs4_get_open_seqid(oop) + 1;

	close_args->seqid = seqid;
	close_args->open_stateid = osp->open_stateid;

	NFS4_DEBUG(nfs4_client_call_debug, (CE_NOTE,
	    "nfs4close_otw: %s call, rp %s", needrecov ? "recov" : "first",
	    rnode4info(rp)));

	t = gethrtime();

	rfs4call(mi, &args, &res, cred_otw, &doqueue, 0, ep);

	if (!ep->error && nfs4_need_to_bump_seqid(&res)) {
		nfs4_set_open_seqid(seqid, oop, args.ctag);
	}

	needrecov = nfs4_needs_recovery(ep, TRUE, mi->mi_vfsp);
	if (ep->error && !needrecov) {
		/*
		 * if there was an error and no recovery is to be done
		 * then then set up the file to flush its cache if
		 * needed for the next caller.
		 */
		mutex_enter(&rp->r_statelock);
		PURGE_ATTRCACHE4_LOCKED(rp);
		rp->r_flags &= ~R4WRITEMODIFIED;
		mutex_exit(&rp->r_statelock);
		return;
	}

	if (needrecov) {
		bool_t abort;
		nfs4_bseqid_entry_t *bsep = NULL;

		if (close_type != CLOSE_RESEND)
			nfs4close_save_lost_rqst(ep->error, &lost_rqst, oop,
			    osp, cred_otw, vp);

		if (!ep->error && res.status == NFS4ERR_BAD_SEQID)
			bsep = nfs4_create_bseqid_entry(oop, NULL, vp,
			    0, args.ctag, close_args->seqid);

		NFS4_DEBUG(nfs4_client_recov_debug, (CE_NOTE,
		    "nfs4close_otw: initiating recovery. error %d "
		    "res.status %d", ep->error, res.status));

		/*
		 * Drop the 'os_sync_lock' here so we don't hit
		 * a potential recursive mutex_enter via an
		 * 'open_stream_hold()'.
		 */
		mutex_exit(&osp->os_sync_lock);
		*have_sync_lockp = 0;
		abort = nfs4_start_recovery(ep, VTOMI4(vp), vp, NULL, NULL,
		    (close_type != CLOSE_RESEND &&
		    lost_rqst.lr_op == OP_CLOSE) ? &lost_rqst : NULL,
		    OP_CLOSE, bsep, NULL, NULL);

		/* drop open seq sync, and let the calling function regrab it */
		nfs4_end_open_seqid_sync(oop);
		*did_start_seqid_syncp = 0;

		if (bsep)
			kmem_free(bsep, sizeof (*bsep));
		/*
		 * For signals, the caller wants to quit, so don't say to
		 * retry.  For forced unmount, if it's a user thread, it
		 * wants to quit.  If it's a recovery thread, the retry
		 * will happen higher-up on the call stack.  Either way,
		 * don't say to retry.
		 */
		if (abort == FALSE && ep->error != EINTR &&
		    !NFS4_FRC_UNMT_ERR(ep->error, mi->mi_vfsp) &&
		    close_type != CLOSE_RESEND &&
		    close_type != CLOSE_AFTER_RESEND)
			*recov = 1;
		else
			*recov = 0;

		if (!ep->error)
			(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
		return;
	}

	if (res.status) {
		(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
		return;
	}

	mutex_enter(&rp->r_statev4_lock);
	rp->created_v4 = 0;
	mutex_exit(&rp->r_statev4_lock);

	resop = &res.array[2];
	osp->open_stateid = resop->nfs_resop4_u.opclose.open_stateid;
	osp->os_valid = 0;

	/*
	 * This removes the reference obtained at OPEN; ie, when the
	 * open stream structure was created.
	 *
	 * We don't have to worry about calling 'open_stream_rele'
	 * since we our currently holding a reference to the open
	 * stream which means the count cannot go to 0 with this
	 * decrement.
	 */
	ASSERT(osp->os_ref_count >= 2);
	osp->os_ref_count--;

	if (!ep->error)
		nfs4_attr_cache(vp,
		    &res.array[1].nfs_resop4_u.opgetattr.ga_res,
		    t, cred_otw, TRUE, NULL);

	NFS4_DEBUG(nfs4_client_state_debug, (CE_NOTE, "nfs4close_otw:"
	    " returning %d", ep->error));

	(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
}

/* ARGSUSED */
static int
nfs4_read(vnode_t *vp, struct uio *uiop, int ioflag, cred_t *cr,
    caller_context_t *ct)
{
	rnode4_t *rp;
	u_offset_t off;
	offset_t diff;
	uint_t on;
	uint_t n;
	caddr_t base;
	uint_t flags;
	int error;
	mntinfo4_t *mi;

	rp = VTOR4(vp);

	ASSERT(nfs_rw_lock_held(&rp->r_rwlock, RW_READER));

	if (IS_SHADOW(vp, rp))
		vp = RTOV4(rp);

	if (vp->v_type != VREG)
		return (EISDIR);

	mi = VTOMI4(vp);

	if (nfs_zone() != mi->mi_zone)
		return (EIO);

	if (uiop->uio_resid == 0)
		return (0);

	if (uiop->uio_loffset < 0 || uiop->uio_loffset + uiop->uio_resid < 0)
		return (EINVAL);

	mutex_enter(&rp->r_statelock);
	if (rp->r_flags & R4RECOVERRP)
		error = (rp->r_error ? rp->r_error : EIO);
	else
		error = 0;
	mutex_exit(&rp->r_statelock);
	if (error)
		return (error);

	/*
	 * Bypass VM if caching has been disabled (e.g., locking) or if
	 * using client-side direct I/O and the file is not mmap'd and
	 * there are no cached pages.
	 */
	if ((vp->v_flag & VNOCACHE) ||
	    (((rp->r_flags & R4DIRECTIO) || (mi->mi_flags & MI4_DIRECTIO)) &&
	    rp->r_mapcnt == 0 && rp->r_inmap == 0 && !nfs4_has_pages(vp))) {
		size_t resid = 0;

		return (nfs4read(vp, NULL, uiop->uio_loffset,
		    uiop->uio_resid, &resid, cr, FALSE, uiop));
	}

	error = 0;

	do {
		off = uiop->uio_loffset & MAXBMASK; /* mapping offset */
		on = uiop->uio_loffset & MAXBOFFSET; /* Relative offset */
		n = MIN(MAXBSIZE - on, uiop->uio_resid);

		if (error = nfs4_validate_caches(vp, cr))
			break;

		mutex_enter(&rp->r_statelock);
		while (rp->r_flags & R4INCACHEPURGE) {
			if (!cv_wait_sig(&rp->r_cv, &rp->r_statelock)) {
				mutex_exit(&rp->r_statelock);
				return (EINTR);
			}
		}
		diff = rp->r_size - uiop->uio_loffset;
		mutex_exit(&rp->r_statelock);
		if (diff <= 0)
			break;
		if (diff < n)
			n = (uint_t)diff;

		if (vpm_enable) {
			/*
			 * Copy data.
			 */
			error = vpm_data_copy(vp, off + on, n, uiop,
			    1, NULL, 0, S_READ);
		} else {
			base = segmap_getmapflt(segkmap, vp, off + on, n, 1,
			    S_READ);

			error = uiomove(base + on, n, UIO_READ, uiop);
		}

		if (!error) {
			/*
			 * If read a whole block or read to eof,
			 * won't need this buffer again soon.
			 */
			mutex_enter(&rp->r_statelock);
			if (n + on == MAXBSIZE ||
			    uiop->uio_loffset == rp->r_size)
				flags = SM_DONTNEED;
			else
				flags = 0;
			mutex_exit(&rp->r_statelock);
			if (vpm_enable) {
				error = vpm_sync_pages(vp, off, n, flags);
			} else {
				error = segmap_release(segkmap, base, flags);
			}
		} else {
			if (vpm_enable) {
				(void) vpm_sync_pages(vp, off, n, 0);
			} else {
				(void) segmap_release(segkmap, base, 0);
			}
		}
	} while (!error && uiop->uio_resid > 0);

	return (error);
}

/* ARGSUSED */
static int
nfs4_write(vnode_t *vp, struct uio *uiop, int ioflag, cred_t *cr,
    caller_context_t *ct)
{
	rlim64_t limit = uiop->uio_llimit;
	rnode4_t *rp;
	u_offset_t off;
	caddr_t base;
	uint_t flags;
	int remainder;
	size_t n;
	int on;
	int error;
	int resid;
	u_offset_t offset;
	mntinfo4_t *mi;
	uint_t bsize;

	rp = VTOR4(vp);

	if (IS_SHADOW(vp, rp))
		vp = RTOV4(rp);

	if (vp->v_type != VREG)
		return (EISDIR);

	mi = VTOMI4(vp);

	if (nfs_zone() != mi->mi_zone)
		return (EIO);

	if (uiop->uio_resid == 0)
		return (0);

	mutex_enter(&rp->r_statelock);
	if (rp->r_flags & R4RECOVERRP)
		error = (rp->r_error ? rp->r_error : EIO);
	else
		error = 0;
	mutex_exit(&rp->r_statelock);
	if (error)
		return (error);

	if (ioflag & FAPPEND) {
		struct vattr va;

		/*
		 * Must serialize if appending.
		 */
		if (nfs_rw_lock_held(&rp->r_rwlock, RW_READER)) {
			nfs_rw_exit(&rp->r_rwlock);
			if (nfs_rw_enter_sig(&rp->r_rwlock, RW_WRITER,
			    INTR4(vp)))
				return (EINTR);
		}

		va.va_mask = AT_SIZE;
		error = nfs4getattr(vp, &va, cr);
		if (error)
			return (error);
		uiop->uio_loffset = va.va_size;
	}

	offset = uiop->uio_loffset + uiop->uio_resid;

	if (uiop->uio_loffset < (offset_t)0 || offset < 0)
		return (EINVAL);

	if (limit == RLIM64_INFINITY || limit > MAXOFFSET_T)
		limit = MAXOFFSET_T;

	/*
	 * Check to make sure that the process will not exceed
	 * its limit on file size.  It is okay to write up to
	 * the limit, but not beyond.  Thus, the write which
	 * reaches the limit will be short and the next write
	 * will return an error.
	 */
	remainder = 0;
	if (offset > uiop->uio_llimit) {
		remainder = offset - uiop->uio_llimit;
		uiop->uio_resid = uiop->uio_llimit - uiop->uio_loffset;
		if (uiop->uio_resid <= 0) {
			proc_t *p = ttoproc(curthread);

			uiop->uio_resid += remainder;
			mutex_enter(&p->p_lock);
			(void) rctl_action(rctlproc_legacy[RLIMIT_FSIZE],
			    p->p_rctls, p, RCA_UNSAFE_SIGINFO);
			mutex_exit(&p->p_lock);
			return (EFBIG);
		}
	}

	/* update the change attribute, if we have a write delegation */

	mutex_enter(&rp->r_statev4_lock);
	if (rp->r_deleg_type == OPEN_DELEGATE_WRITE)
		rp->r_deleg_change++;

	mutex_exit(&rp->r_statev4_lock);

	if (nfs_rw_enter_sig(&rp->r_lkserlock, RW_READER, INTR4(vp)))
		return (EINTR);

	/*
	 * Bypass VM if caching has been disabled (e.g., locking) or if
	 * using client-side direct I/O and the file is not mmap'd and
	 * there are no cached pages.
	 */
	if ((vp->v_flag & VNOCACHE) ||
	    (((rp->r_flags & R4DIRECTIO) || (mi->mi_flags & MI4_DIRECTIO)) &&
	    rp->r_mapcnt == 0 && rp->r_inmap == 0 && !nfs4_has_pages(vp))) {
		size_t bufsize;
		int count;
		u_offset_t org_offset;
		stable_how4 stab_comm;
nfs4_fwrite:
		if (rp->r_flags & R4STALE) {
			resid = uiop->uio_resid;
			offset = uiop->uio_loffset;
			error = rp->r_error;
			/*
			 * A close may have cleared r_error, if so,
			 * propagate ESTALE error return properly
			 */
			if (error == 0)
				error = ESTALE;
			goto bottom;
		}

		bufsize = MIN(uiop->uio_resid, mi->mi_stsize);
		base = kmem_alloc(bufsize, KM_SLEEP);
		do {
			if (ioflag & FDSYNC)
				stab_comm = DATA_SYNC4;
			else
				stab_comm = FILE_SYNC4;
			resid = uiop->uio_resid;
			offset = uiop->uio_loffset;
			count = MIN(uiop->uio_resid, bufsize);
			org_offset = uiop->uio_loffset;
			error = uiomove(base, count, UIO_WRITE, uiop);
			if (!error) {
				error = nfs4write(vp, base, org_offset,
				    count, cr, &stab_comm);
				if (!error) {
					mutex_enter(&rp->r_statelock);
					if (rp->r_size < uiop->uio_loffset)
						rp->r_size = uiop->uio_loffset;
					mutex_exit(&rp->r_statelock);
				}
			}
		} while (!error && uiop->uio_resid > 0);
		kmem_free(base, bufsize);
		goto bottom;
	}

	bsize = vp->v_vfsp->vfs_bsize;

	do {
		off = uiop->uio_loffset & MAXBMASK; /* mapping offset */
		on = uiop->uio_loffset & MAXBOFFSET; /* Relative offset */
		n = MIN(MAXBSIZE - on, uiop->uio_resid);

		resid = uiop->uio_resid;
		offset = uiop->uio_loffset;

		if (rp->r_flags & R4STALE) {
			error = rp->r_error;
			/*
			 * A close may have cleared r_error, if so,
			 * propagate ESTALE error return properly
			 */
			if (error == 0)
				error = ESTALE;
			break;
		}

		/*
		 * Don't create dirty pages faster than they
		 * can be cleaned so that the system doesn't
		 * get imbalanced.  If the async queue is
		 * maxed out, then wait for it to drain before
		 * creating more dirty pages.  Also, wait for
		 * any threads doing pagewalks in the vop_getattr
		 * entry points so that they don't block for
		 * long periods.
		 */
		mutex_enter(&rp->r_statelock);
		while ((mi->mi_max_threads != 0 &&
		    rp->r_awcount > 2 * mi->mi_max_threads) ||
		    rp->r_gcount > 0) {
			if (INTR4(vp)) {
				klwp_t *lwp = ttolwp(curthread);

				if (lwp != NULL)
					lwp->lwp_nostop++;
				if (!cv_wait_sig(&rp->r_cv, &rp->r_statelock)) {
					mutex_exit(&rp->r_statelock);
					if (lwp != NULL)
						lwp->lwp_nostop--;
					error = EINTR;
					goto bottom;
				}
				if (lwp != NULL)
					lwp->lwp_nostop--;
			} else
				cv_wait(&rp->r_cv, &rp->r_statelock);
		}
		mutex_exit(&rp->r_statelock);

		/*
		 * Touch the page and fault it in if it is not in core
		 * before segmap_getmapflt or vpm_data_copy can lock it.
		 * This is to avoid the deadlock if the buffer is mapped
		 * to the same file through mmap which we want to write.
		 */
		uio_prefaultpages((long)n, uiop);

		if (vpm_enable) {
			/*
			 * It will use kpm mappings, so no need to
			 * pass an address.
			 */
			error = writerp4(rp, NULL, n, uiop, 0);
		} else  {
			if (segmap_kpm) {
				int pon = uiop->uio_loffset & PAGEOFFSET;
				size_t pn = MIN(PAGESIZE - pon,
				    uiop->uio_resid);
				int pagecreate;

				mutex_enter(&rp->r_statelock);
				pagecreate = (pon == 0) && (pn == PAGESIZE ||
				    uiop->uio_loffset + pn >= rp->r_size);
				mutex_exit(&rp->r_statelock);

				base = segmap_getmapflt(segkmap, vp, off + on,
				    pn, !pagecreate, S_WRITE);

				error = writerp4(rp, base + pon, n, uiop,
				    pagecreate);

			} else {
				base = segmap_getmapflt(segkmap, vp, off + on,
				    n, 0, S_READ);
				error = writerp4(rp, base + on, n, uiop, 0);
			}
		}

		if (!error) {
			if (mi->mi_flags & MI4_NOAC)
				flags = SM_WRITE;
			else if ((uiop->uio_loffset % bsize) == 0 ||
			    IS_SWAPVP(vp)) {
				/*
				 * Have written a whole block.
				 * Start an asynchronous write
				 * and mark the buffer to
				 * indicate that it won't be
				 * needed again soon.
				 */
				flags = SM_WRITE | SM_ASYNC | SM_DONTNEED;
			} else
				flags = 0;
			if ((ioflag & (FSYNC|FDSYNC)) ||
			    (rp->r_flags & R4OUTOFSPACE)) {
				flags &= ~SM_ASYNC;
				flags |= SM_WRITE;
			}
			if (vpm_enable) {
				error = vpm_sync_pages(vp, off, n, flags);
			} else {
				error = segmap_release(segkmap, base, flags);
			}
		} else {
			if (vpm_enable) {
				(void) vpm_sync_pages(vp, off, n, 0);
			} else {
				(void) segmap_release(segkmap, base, 0);
			}
			/*
			 * In the event that we got an access error while
			 * faulting in a page for a write-only file just
			 * force a write.
			 */
			if (error == EACCES)
				goto nfs4_fwrite;
		}
	} while (!error && uiop->uio_resid > 0);

bottom:
	if (error) {
		uiop->uio_resid = resid + remainder;
		uiop->uio_loffset = offset;
	} else {
		uiop->uio_resid += remainder;

		mutex_enter(&rp->r_statev4_lock);
		if (rp->r_deleg_type == OPEN_DELEGATE_WRITE) {
			gethrestime(&rp->r_attr.va_mtime);
			rp->r_attr.va_ctime = rp->r_attr.va_mtime;
		}
		mutex_exit(&rp->r_statev4_lock);
	}

	nfs_rw_exit(&rp->r_lkserlock);

	return (error);
}

/*
 * Flags are composed of {B_ASYNC, B_INVAL, B_FREE, B_DONTNEED}
 */
static int
nfs4_rdwrlbn(vnode_t *vp, page_t *pp, u_offset_t off, size_t len,
    int flags, cred_t *cr)
{
	struct buf *bp;
	int error;
	page_t *savepp;
	uchar_t fsdata;
	stable_how4 stab_comm;

	ASSERT(nfs_zone() == VTOMI4(vp)->mi_zone);
	bp = pageio_setup(pp, len, vp, flags);
	ASSERT(bp != NULL);

	/*
	 * pageio_setup should have set b_addr to 0.  This
	 * is correct since we want to do I/O on a page
	 * boundary.  bp_mapin will use this addr to calculate
	 * an offset, and then set b_addr to the kernel virtual
	 * address it allocated for us.
	 */
	ASSERT(bp->b_un.b_addr == 0);

	bp->b_edev = 0;
	bp->b_dev = 0;
	bp->b_lblkno = lbtodb(off);
	bp->b_file = vp;
	bp->b_offset = (offset_t)off;
	bp_mapin(bp);

	if ((flags & (B_WRITE|B_ASYNC)) == (B_WRITE|B_ASYNC) &&
	    freemem > desfree)
		stab_comm = UNSTABLE4;
	else
		stab_comm = FILE_SYNC4;

	error = nfs4_bio(bp, &stab_comm, cr, FALSE);

	bp_mapout(bp);
	pageio_done(bp);

	if (stab_comm == UNSTABLE4)
		fsdata = C_DELAYCOMMIT;
	else
		fsdata = C_NOCOMMIT;

	savepp = pp;
	do {
		pp->p_fsdata = fsdata;
	} while ((pp = pp->p_next) != savepp);

	return (error);
}

/*
 */
static int
nfs4rdwr_check_osid(vnode_t *vp, nfs4_error_t *ep, cred_t *cr)
{
	nfs4_open_owner_t	*oop;
	nfs4_open_stream_t	*osp;
	rnode4_t		*rp = VTOR4(vp);
	mntinfo4_t 		*mi = VTOMI4(vp);
	int 			reopen_needed;

	ASSERT(nfs_zone() == mi->mi_zone);


	oop = find_open_owner(cr, NFS4_PERM_CREATED, mi);
	if (!oop)
		return (EIO);

	/* returns with 'os_sync_lock' held */
	osp = find_open_stream(oop, rp);
	if (!osp) {
		open_owner_rele(oop);
		return (EIO);
	}

	if (osp->os_failed_reopen) {
		mutex_exit(&osp->os_sync_lock);
		open_stream_rele(osp, rp);
		open_owner_rele(oop);
		return (EIO);
	}

	/*
	 * Determine whether a reopen is needed.  If this
	 * is a delegation open stream, then the os_delegation bit
	 * should be set.
	 */

	reopen_needed = osp->os_delegation;

	mutex_exit(&osp->os_sync_lock);
	open_owner_rele(oop);

	if (reopen_needed) {
		nfs4_error_zinit(ep);
		nfs4_reopen(vp, osp, ep, CLAIM_NULL, FALSE, FALSE);
		mutex_enter(&osp->os_sync_lock);
		if (ep->error || ep->stat || osp->os_failed_reopen) {
			mutex_exit(&osp->os_sync_lock);
			open_stream_rele(osp, rp);
			return (EIO);
		}
		mutex_exit(&osp->os_sync_lock);
	}
	open_stream_rele(osp, rp);

	return (0);
}

/*
 * Write to file.  Writes to remote server in largest size
 * chunks that the server can handle.  Write is synchronous.
 */
static int
nfs4write(vnode_t *vp, caddr_t base, u_offset_t offset, int count, cred_t *cr,
    stable_how4 *stab_comm)
{
	mntinfo4_t *mi;
	COMPOUND4args_clnt args;
	COMPOUND4res_clnt res;
	WRITE4args *wargs;
	WRITE4res *wres;
	nfs_argop4 argop[2];
	nfs_resop4 *resop;
	int tsize;
	stable_how4 stable;
	rnode4_t *rp;
	int doqueue = 1;
	bool_t needrecov;
	nfs4_recov_state_t recov_state;
	nfs4_stateid_types_t sid_types;
	nfs4_error_t e = { 0, NFS4_OK, RPC_SUCCESS };
	int recov;

	rp = VTOR4(vp);
	mi = VTOMI4(vp);

	ASSERT(nfs_zone() == mi->mi_zone);

	stable = *stab_comm;
	*stab_comm = FILE_SYNC4;

	needrecov = FALSE;
	recov_state.rs_flags = 0;
	recov_state.rs_num_retry_despite_err = 0;
	nfs4_init_stateid_types(&sid_types);

	/* Is curthread the recovery thread? */
	mutex_enter(&mi->mi_lock);
	recov = (mi->mi_recovthread == curthread);
	mutex_exit(&mi->mi_lock);

recov_retry:
	args.ctag = TAG_WRITE;
	args.array_len = 2;
	args.array = argop;

	if (!recov) {
		e.error = nfs4_start_fop(VTOMI4(vp), vp, NULL, OH_WRITE,
		    &recov_state, NULL);
		if (e.error)
			return (e.error);
	}

	/* 0. putfh target fh */
	argop[0].argop = OP_CPUTFH;
	argop[0].nfs_argop4_u.opcputfh.sfh = rp->r_fh;

	/* 1. write */
	nfs4args_write(&argop[1], stable, rp, cr, &wargs, &sid_types);

	do {

		wargs->offset = (offset4)offset;
		wargs->data_val = base;

		if (mi->mi_io_kstats) {
			mutex_enter(&mi->mi_lock);
			kstat_runq_enter(KSTAT_IO_PTR(mi->mi_io_kstats));
			mutex_exit(&mi->mi_lock);
		}

		if ((vp->v_flag & VNOCACHE) ||
		    (rp->r_flags & R4DIRECTIO) ||
		    (mi->mi_flags & MI4_DIRECTIO))
			tsize = MIN(mi->mi_stsize, count);
		else
			tsize = MIN(mi->mi_curwrite, count);
		wargs->data_len = (uint_t)tsize;
		rfs4call(mi, &args, &res, cr, &doqueue, 0, &e);

		if (mi->mi_io_kstats) {
			mutex_enter(&mi->mi_lock);
			kstat_runq_exit(KSTAT_IO_PTR(mi->mi_io_kstats));
			mutex_exit(&mi->mi_lock);
		}

		if (!recov) {
			needrecov = nfs4_needs_recovery(&e, FALSE, mi->mi_vfsp);
			if (e.error && !needrecov) {
				nfs4_end_fop(VTOMI4(vp), vp, NULL, OH_WRITE,
				    &recov_state, needrecov);
				return (e.error);
			}
		} else {
			if (e.error)
				return (e.error);
		}

		/*
		 * Do handling of OLD_STATEID outside
		 * of the normal recovery framework.
		 *
		 * If write receives a BAD stateid error while using a
		 * delegation stateid, retry using the open stateid (if it
		 * exists).  If it doesn't have an open stateid, reopen the
		 * file first, then retry.
		 */
		if (!e.error && res.status == NFS4ERR_OLD_STATEID &&
		    sid_types.cur_sid_type != SPEC_SID) {
			nfs4_save_stateid(&wargs->stateid, &sid_types);
			if (!recov)
				nfs4_end_fop(VTOMI4(vp), vp, NULL, OH_WRITE,
				    &recov_state, needrecov);
			(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
			goto recov_retry;
		} else if (e.error == 0 && res.status == NFS4ERR_BAD_STATEID &&
		    sid_types.cur_sid_type == DEL_SID) {
			nfs4_save_stateid(&wargs->stateid, &sid_types);
			mutex_enter(&rp->r_statev4_lock);
			rp->r_deleg_return_pending = TRUE;
			mutex_exit(&rp->r_statev4_lock);
			if (nfs4rdwr_check_osid(vp, &e, cr)) {
				if (!recov)
					nfs4_end_fop(mi, vp, NULL, OH_WRITE,
					    &recov_state, needrecov);
				(void) xdr_free(xdr_COMPOUND4res_clnt,
				    (caddr_t)&res);
				return (EIO);
			}
			if (!recov)
				nfs4_end_fop(mi, vp, NULL, OH_WRITE,
				    &recov_state, needrecov);
			/* hold needed for nfs4delegreturn_thread */
			VN_HOLD(vp);
			nfs4delegreturn_async(rp, (NFS4_DR_PUSH|NFS4_DR_REOPEN|
			    NFS4_DR_DISCARD), FALSE);
			(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
			goto recov_retry;
		}

		if (needrecov) {
			bool_t abort;

			NFS4_DEBUG(nfs4_client_recov_debug, (CE_NOTE,
			    "nfs4write: client got error %d, res.status %d"
			    ", so start recovery", e.error, res.status));

			abort = nfs4_start_recovery(&e,
			    VTOMI4(vp), vp, NULL, &wargs->stateid,
			    NULL, OP_WRITE, NULL, NULL, NULL);
			if (!e.error) {
				e.error = geterrno4(res.status);
				(void) xdr_free(xdr_COMPOUND4res_clnt,
				    (caddr_t)&res);
			}
			nfs4_end_fop(VTOMI4(vp), vp, NULL, OH_WRITE,
			    &recov_state, needrecov);
			if (abort == FALSE)
				goto recov_retry;
			return (e.error);
		}

		if (res.status) {
			e.error = geterrno4(res.status);
			(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
			if (!recov)
				nfs4_end_fop(VTOMI4(vp), vp, NULL, OH_WRITE,
				    &recov_state, needrecov);
			return (e.error);
		}

		resop = &res.array[1];	/* write res */
		wres = &resop->nfs_resop4_u.opwrite;

		if ((int)wres->count > tsize) {
			(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);

			zcmn_err(getzoneid(), CE_WARN,
			    "nfs4write: server wrote %u, requested was %u",
			    (int)wres->count, tsize);
			if (!recov)
				nfs4_end_fop(VTOMI4(vp), vp, NULL, OH_WRITE,
				    &recov_state, needrecov);
			return (EIO);
		}
		if (wres->committed == UNSTABLE4) {
			*stab_comm = UNSTABLE4;
			if (wargs->stable == DATA_SYNC4 ||
			    wargs->stable == FILE_SYNC4) {
				(void) xdr_free(xdr_COMPOUND4res_clnt,
				    (caddr_t)&res);
				zcmn_err(getzoneid(), CE_WARN,
				    "nfs4write: server %s did not commit "
				    "to stable storage",
				    rp->r_server->sv_hostname);
				if (!recov)
					nfs4_end_fop(VTOMI4(vp), vp, NULL,
					    OH_WRITE, &recov_state, needrecov);
				return (EIO);
			}
		}

		tsize = (int)wres->count;
		count -= tsize;
		base += tsize;
		offset += tsize;
		if (mi->mi_io_kstats) {
			mutex_enter(&mi->mi_lock);
			KSTAT_IO_PTR(mi->mi_io_kstats)->writes++;
			KSTAT_IO_PTR(mi->mi_io_kstats)->nwritten +=
			    tsize;
			mutex_exit(&mi->mi_lock);
		}
		lwp_stat_update(LWP_STAT_OUBLK, 1);
		mutex_enter(&rp->r_statelock);
		if (rp->r_flags & R4HAVEVERF) {
			if (rp->r_writeverf != wres->writeverf) {
				nfs4_set_mod(vp);
				rp->r_writeverf = wres->writeverf;
			}
		} else {
			rp->r_writeverf = wres->writeverf;
			rp->r_flags |= R4HAVEVERF;
		}
		PURGE_ATTRCACHE4_LOCKED(rp);
		rp->r_flags |= R4WRITEMODIFIED;
		gethrestime(&rp->r_attr.va_mtime);
		rp->r_attr.va_ctime = rp->r_attr.va_mtime;
		mutex_exit(&rp->r_statelock);
		(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
	} while (count);

	if (!recov)
		nfs4_end_fop(VTOMI4(vp), vp, NULL, OH_WRITE, &recov_state,
		    needrecov);

	return (e.error);
}

/*
 * Read from a file.  Reads data in largest chunks our interface can handle.
 */
static int
nfs4read(vnode_t *vp, caddr_t base, offset_t offset, int count,
    size_t *residp, cred_t *cr, bool_t async, struct uio *uiop)
{
	mntinfo4_t *mi;
	COMPOUND4args_clnt args;
	COMPOUND4res_clnt res;
	READ4args *rargs;
	nfs_argop4 argop[2];
	int tsize;
	int doqueue;
	rnode4_t *rp;
	int data_len;
	bool_t is_eof;
	bool_t needrecov = FALSE;
	nfs4_recov_state_t recov_state;
	nfs4_stateid_types_t sid_types;
	nfs4_error_t e = { 0, NFS4_OK, RPC_SUCCESS };

	rp = VTOR4(vp);
	mi = VTOMI4(vp);
	doqueue = 1;

	ASSERT(nfs_zone() == mi->mi_zone);

	args.ctag = async ? TAG_READAHEAD : TAG_READ;

	args.array_len = 2;
	args.array = argop;

	nfs4_init_stateid_types(&sid_types);

	recov_state.rs_flags = 0;
	recov_state.rs_num_retry_despite_err = 0;

recov_retry:
	e.error = nfs4_start_fop(mi, vp, NULL, OH_READ,
	    &recov_state, NULL);
	if (e.error)
		return (e.error);

	/* putfh target fh */
	argop[0].argop = OP_CPUTFH;
	argop[0].nfs_argop4_u.opcputfh.sfh = rp->r_fh;

	/* read */
	argop[1].argop = OP_READ;
	rargs = &argop[1].nfs_argop4_u.opread;
	rargs->stateid = nfs4_get_stateid(cr, rp, curproc->p_pidp->pid_id, mi,
	    OP_READ, &sid_types, async);

	do {
		if (mi->mi_io_kstats) {
			mutex_enter(&mi->mi_lock);
			kstat_runq_enter(KSTAT_IO_PTR(mi->mi_io_kstats));
			mutex_exit(&mi->mi_lock);
		}

		NFS4_DEBUG(nfs4_client_call_debug, (CE_NOTE,
		    "nfs4read: %s call, rp %s",
		    needrecov ? "recov" : "first",
		    rnode4info(rp)));

		if ((vp->v_flag & VNOCACHE) ||
		    (rp->r_flags & R4DIRECTIO) ||
		    (mi->mi_flags & MI4_DIRECTIO))
			tsize = MIN(mi->mi_tsize, count);
		else
			tsize = MIN(mi->mi_curread, count);

		rargs->offset = (offset4)offset;
		rargs->count = (count4)tsize;
		rargs->res_data_val_alt = NULL;
		rargs->res_mblk = NULL;
		rargs->res_uiop = NULL;
		rargs->res_maxsize = 0;
		rargs->wlist = NULL;

		if (uiop)
			rargs->res_uiop = uiop;
		else
			rargs->res_data_val_alt = base;
		rargs->res_maxsize = tsize;

		rfs4call(mi, &args, &res, cr, &doqueue, 0, &e);
#ifdef	DEBUG
		if (nfs4read_error_inject) {
			res.status = nfs4read_error_inject;
			nfs4read_error_inject = 0;
		}
#endif

		if (mi->mi_io_kstats) {
			mutex_enter(&mi->mi_lock);
			kstat_runq_exit(KSTAT_IO_PTR(mi->mi_io_kstats));
			mutex_exit(&mi->mi_lock);
		}

		needrecov = nfs4_needs_recovery(&e, FALSE, mi->mi_vfsp);
		if (e.error != 0 && !needrecov) {
			nfs4_end_fop(mi, vp, NULL, OH_READ,
			    &recov_state, needrecov);
			return (e.error);
		}

		/*
		 * Do proper retry for OLD and BAD stateid errors outside
		 * of the normal recovery framework.  There are two differences
		 * between async and sync reads.  The first is that we allow
		 * retry on BAD_STATEID for async reads, but not sync reads.
		 * The second is that we mark the file dead for a failed
		 * attempt with a special stateid for sync reads, but just
		 * return EIO for async reads.
		 *
		 * If a sync read receives a BAD stateid error while using a
		 * delegation stateid, retry using the open stateid (if it
		 * exists).  If it doesn't have an open stateid, reopen the
		 * file first, then retry.
		 */
		if (e.error == 0 && (res.status == NFS4ERR_OLD_STATEID ||
		    res.status == NFS4ERR_BAD_STATEID) && async) {
			nfs4_end_fop(mi, vp, NULL, OH_READ,
			    &recov_state, needrecov);
			if (sid_types.cur_sid_type == SPEC_SID) {
				(void) xdr_free(xdr_COMPOUND4res_clnt,
				    (caddr_t)&res);
				return (EIO);
			}
			nfs4_save_stateid(&rargs->stateid, &sid_types);
			(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
			goto recov_retry;
		} else if (e.error == 0 && res.status == NFS4ERR_OLD_STATEID &&
		    !async && sid_types.cur_sid_type != SPEC_SID) {
			nfs4_save_stateid(&rargs->stateid, &sid_types);
			nfs4_end_fop(mi, vp, NULL, OH_READ,
			    &recov_state, needrecov);
			(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
			goto recov_retry;
		} else if (e.error == 0 && res.status == NFS4ERR_BAD_STATEID &&
		    sid_types.cur_sid_type == DEL_SID) {
			nfs4_save_stateid(&rargs->stateid, &sid_types);
			mutex_enter(&rp->r_statev4_lock);
			rp->r_deleg_return_pending = TRUE;
			mutex_exit(&rp->r_statev4_lock);
			if (nfs4rdwr_check_osid(vp, &e, cr)) {
				nfs4_end_fop(mi, vp, NULL, OH_READ,
				    &recov_state, needrecov);
				(void) xdr_free(xdr_COMPOUND4res_clnt,
				    (caddr_t)&res);
				return (EIO);
			}
			nfs4_end_fop(mi, vp, NULL, OH_READ,
			    &recov_state, needrecov);
			/* hold needed for nfs4delegreturn_thread */
			VN_HOLD(vp);
			nfs4delegreturn_async(rp, (NFS4_DR_PUSH|NFS4_DR_REOPEN|
			    NFS4_DR_DISCARD), FALSE);
			(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
			goto recov_retry;
		}
		if (needrecov) {
			bool_t abort;

			NFS4_DEBUG(nfs4_client_recov_debug, (CE_NOTE,
			    "nfs4read: initiating recovery\n"));
			abort = nfs4_start_recovery(&e,
			    mi, vp, NULL, &rargs->stateid,
			    NULL, OP_READ, NULL, NULL, NULL);
			nfs4_end_fop(mi, vp, NULL, OH_READ,
			    &recov_state, needrecov);
			/*
			 * Do not retry if we got OLD_STATEID using a special
			 * stateid.  This avoids looping with a broken server.
			 */
			if (e.error == 0 && res.status == NFS4ERR_OLD_STATEID &&
			    sid_types.cur_sid_type == SPEC_SID)
				abort = TRUE;

			if (abort == FALSE) {
				/*
				 * Need to retry all possible stateids in
				 * case the recovery error wasn't stateid
				 * related or the stateids have become
				 * stale (server reboot).
				 */
				nfs4_init_stateid_types(&sid_types);
				(void) xdr_free(xdr_COMPOUND4res_clnt,
				    (caddr_t)&res);
				goto recov_retry;
			}

			if (!e.error) {
				e.error = geterrno4(res.status);
				(void) xdr_free(xdr_COMPOUND4res_clnt,
				    (caddr_t)&res);
			}
			return (e.error);
		}

		if (res.status) {
			e.error = geterrno4(res.status);
			nfs4_end_fop(mi, vp, NULL, OH_READ,
			    &recov_state, needrecov);
			(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
			return (e.error);
		}

		data_len = res.array[1].nfs_resop4_u.opread.data_len;
		count -= data_len;
		if (base)
			base += data_len;
		offset += data_len;
		if (mi->mi_io_kstats) {
			mutex_enter(&mi->mi_lock);
			KSTAT_IO_PTR(mi->mi_io_kstats)->reads++;
			KSTAT_IO_PTR(mi->mi_io_kstats)->nread += data_len;
			mutex_exit(&mi->mi_lock);
		}
		lwp_stat_update(LWP_STAT_INBLK, 1);
		is_eof = res.array[1].nfs_resop4_u.opread.eof;
		(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);

	} while (count && !is_eof);

	*residp = count;

	nfs4_end_fop(mi, vp, NULL, OH_READ, &recov_state, needrecov);

	return (e.error);
}

/* ARGSUSED */
static int
nfs4_ioctl(vnode_t *vp, int cmd, intptr_t arg, int flag, cred_t *cr, int *rvalp,
	caller_context_t *ct)
{
	if (nfs_zone() != VTOMI4(vp)->mi_zone)
		return (EIO);
	switch (cmd) {
		case _FIODIRECTIO:
			return (nfs4_directio(vp, (int)arg, cr));
		default:
			return (ENOTTY);
	}
}

/* ARGSUSED */
int
nfs4_getattr(vnode_t *vp, struct vattr *vap, int flags, cred_t *cr,
    caller_context_t *ct)
{
	int error;
	rnode4_t *rp = VTOR4(vp);

	if (nfs_zone() != VTOMI4(vp)->mi_zone)
		return (EIO);
	/*
	 * If it has been specified that the return value will
	 * just be used as a hint, and we are only being asked
	 * for size, fsid or rdevid, then return the client's
	 * notion of these values without checking to make sure
	 * that the attribute cache is up to date.
	 * The whole point is to avoid an over the wire GETATTR
	 * call.
	 */
	if (flags & ATTR_HINT) {
		if (!(vap->va_mask & ~(AT_SIZE | AT_FSID | AT_RDEV))) {
			mutex_enter(&rp->r_statelock);
			if (vap->va_mask & AT_SIZE)
				vap->va_size = rp->r_size;
			if (vap->va_mask & AT_FSID)
				vap->va_fsid = rp->r_attr.va_fsid;
			if (vap->va_mask & AT_RDEV)
				vap->va_rdev = rp->r_attr.va_rdev;
			mutex_exit(&rp->r_statelock);
			return (0);
		}
	}

	/*
	 * Only need to flush pages if asking for the mtime
	 * and if there any dirty pages or any outstanding
	 * asynchronous (write) requests for this file.
	 */
	if (vap->va_mask & AT_MTIME) {
		rp = VTOR4(vp);
		if (nfs4_has_pages(vp)) {
			mutex_enter(&rp->r_statev4_lock);
			if (rp->r_deleg_type != OPEN_DELEGATE_WRITE) {
				mutex_exit(&rp->r_statev4_lock);
				if (rp->r_flags & R4DIRTY ||
				    rp->r_awcount > 0) {
					mutex_enter(&rp->r_statelock);
					rp->r_gcount++;
					mutex_exit(&rp->r_statelock);
					error =
					    nfs4_putpage(vp, (u_offset_t)0,
					    0, 0, cr, NULL);
					mutex_enter(&rp->r_statelock);
					if (error && (error == ENOSPC ||
					    error == EDQUOT)) {
						if (!rp->r_error)
							rp->r_error = error;
					}
					if (--rp->r_gcount == 0)
						cv_broadcast(&rp->r_cv);
					mutex_exit(&rp->r_statelock);
				}
			} else {
				mutex_exit(&rp->r_statev4_lock);
			}
		}
	}
	return (nfs4getattr(vp, vap, cr));
}

int
nfs4_compare_modes(mode_t from_server, mode_t on_client)
{
	/*
	 * If these are the only two bits cleared
	 * on the server then return 0 (OK) else
	 * return 1 (BAD).
	 */
	on_client &= ~(S_ISUID|S_ISGID);
	if (on_client == from_server)
		return (0);
	else
		return (1);
}

/*ARGSUSED4*/
static int
nfs4_setattr(vnode_t *vp, struct vattr *vap, int flags, cred_t *cr,
    caller_context_t *ct)
{
	int error;

	if (vap->va_mask & AT_NOSET)
		return (EINVAL);

	if (nfs_zone() != VTOMI4(vp)->mi_zone)
		return (EIO);

	/*
	 * Don't call secpolicy_vnode_setattr, the client cannot
	 * use its cached attributes to make security decisions
	 * as the server may be faking mode bits or mapping uid/gid.
	 * Always just let the server to the checking.
	 * If we provide the ability to remove basic priviledges
	 * to setattr (e.g. basic without chmod) then we will
	 * need to add a check here before calling the server.
	 */
	error = nfs4setattr(vp, vap, flags, cr, NULL);

	if (error == 0 && (vap->va_mask & AT_SIZE) && vap->va_size == 0)
		vnevent_truncate(vp, ct);

	return (error);
}

/*
 * To replace the "guarded" version 3 setattr, we use two types of compound
 * setattr requests:
 * 1. The "normal" setattr, used when the size of the file isn't being
 *    changed - { Putfh <fh>; Setattr; Getattr }/
 * 2. If the size is changed, precede Setattr with: Getattr; Verify
 *    with only ctime as the argument. If the server ctime differs from
 *    what is cached on the client, the verify will fail, but we would
 *    already have the ctime from the preceding getattr, so just set it
 *    and retry. Thus the compound here is - { Putfh <fh>; Getattr; Verify;
 *	Setattr; Getattr }.
 *
 * The vsecattr_t * input parameter will be non-NULL if ACLs are being set in
 * this setattr and NULL if they are not.
 */
static int
nfs4setattr(vnode_t *vp, struct vattr *vap, int flags, cred_t *cr,
    vsecattr_t *vsap)
{
	COMPOUND4args_clnt args;
	COMPOUND4res_clnt res, *resp = NULL;
	nfs4_ga_res_t *garp = NULL;
	int numops = 3;			/* { Putfh; Setattr; Getattr } */
	nfs_argop4 argop[5];
	int verify_argop = -1;
	int setattr_argop = 1;
	nfs_resop4 *resop;
	vattr_t va;
	rnode4_t *rp;
	int doqueue = 1;
	uint_t mask = vap->va_mask;
	mode_t omode;
	vsecattr_t *vsp;
	timestruc_t ctime;
	bool_t needrecov = FALSE;
	nfs4_recov_state_t recov_state;
	nfs4_stateid_types_t sid_types;
	stateid4 stateid;
	hrtime_t t;
	nfs4_error_t e = { 0, NFS4_OK, RPC_SUCCESS };
	servinfo4_t *svp;
	bitmap4 supp_attrs;

	ASSERT(nfs_zone() == VTOMI4(vp)->mi_zone);
	rp = VTOR4(vp);
	nfs4_init_stateid_types(&sid_types);

	/*
	 * Only need to flush pages if there are any pages and
	 * if the file is marked as dirty in some fashion.  The
	 * file must be flushed so that we can accurately
	 * determine the size of the file and the cached data
	 * after the SETATTR returns.  A file is considered to
	 * be dirty if it is either marked with R4DIRTY, has
	 * outstanding i/o's active, or is mmap'd.  In this
	 * last case, we can't tell whether there are dirty
	 * pages, so we flush just to be sure.
	 */
	if (nfs4_has_pages(vp) &&
	    ((rp->r_flags & R4DIRTY) ||
	    rp->r_count > 0 ||
	    rp->r_mapcnt > 0)) {
		ASSERT(vp->v_type != VCHR);
		e.error = nfs4_putpage(vp, (offset_t)0, 0, 0, cr, NULL);
		if (e.error && (e.error == ENOSPC || e.error == EDQUOT)) {
			mutex_enter(&rp->r_statelock);
			if (!rp->r_error)
				rp->r_error = e.error;
			mutex_exit(&rp->r_statelock);
		}
	}

	if (mask & AT_SIZE) {
		/*
		 * Verification setattr compound for non-deleg AT_SIZE:
		 *	{ Putfh; Getattr; Verify; Setattr; Getattr }
		 * Set ctime local here (outside the do_again label)
		 * so that subsequent retries (after failed VERIFY)
		 * will use ctime from GETATTR results (from failed
		 * verify compound) as VERIFY arg.
		 * If file has delegation, then VERIFY(time_metadata)
		 * is of little added value, so don't bother.
		 */
		mutex_enter(&rp->r_statev4_lock);
		if (rp->r_deleg_type == OPEN_DELEGATE_NONE ||
		    rp->r_deleg_return_pending) {
			numops = 5;
			ctime = rp->r_attr.va_ctime;
		}
		mutex_exit(&rp->r_statev4_lock);
	}

	recov_state.rs_flags = 0;
	recov_state.rs_num_retry_despite_err = 0;

	args.ctag = TAG_SETATTR;
do_again:
recov_retry:
	setattr_argop = numops - 2;

	args.array = argop;
	args.array_len = numops;

	e.error = nfs4_start_op(VTOMI4(vp), vp, NULL, &recov_state);
	if (e.error)
		return (e.error);


	/* putfh target fh */
	argop[0].argop = OP_CPUTFH;
	argop[0].nfs_argop4_u.opcputfh.sfh = rp->r_fh;

	if (numops == 5) {
		/*
		 * We only care about the ctime, but need to get mtime
		 * and size for proper cache update.
		 */
		/* getattr */
		argop[1].argop = OP_GETATTR;
		argop[1].nfs_argop4_u.opgetattr.attr_request = NFS4_VATTR_MASK;
		argop[1].nfs_argop4_u.opgetattr.mi = VTOMI4(vp);

		/* verify - set later in loop */
		verify_argop = 2;
	}

	/* setattr */
	svp = rp->r_server;
	(void) nfs_rw_enter_sig(&svp->sv_lock, RW_READER, 0);
	supp_attrs = svp->sv_supp_attrs;
	nfs_rw_exit(&svp->sv_lock);

	nfs4args_setattr(&argop[setattr_argop], vap, vsap, flags, rp, cr,
	    supp_attrs, &e.error, &sid_types);
	stateid = argop[setattr_argop].nfs_argop4_u.opsetattr.stateid;
	if (e.error) {
		/* req time field(s) overflow - return immediately */
		nfs4_end_op(VTOMI4(vp), vp, NULL, &recov_state, needrecov);
		nfs4_fattr4_free(&argop[setattr_argop].nfs_argop4_u.
		    opsetattr.obj_attributes);
		return (e.error);
	}
	omode = rp->r_attr.va_mode;

	/* getattr */
	argop[numops-1].argop = OP_GETATTR;
	argop[numops-1].nfs_argop4_u.opgetattr.attr_request = NFS4_VATTR_MASK;
	/*
	 * If we are setting the ACL (indicated only by vsap != NULL), request
	 * the ACL in this getattr.  The ACL returned from this getattr will be
	 * used in updating the ACL cache.
	 */
	if (vsap != NULL)
		argop[numops-1].nfs_argop4_u.opgetattr.attr_request |=
		    FATTR4_ACL_MASK;
	argop[numops-1].nfs_argop4_u.opgetattr.mi = VTOMI4(vp);

	/*
	 * setattr iterates if the object size is set and the cached ctime
	 * does not match the file ctime. In that case, verify the ctime first.
	 */

	do {
		if (verify_argop != -1) {
			/*
			 * Verify that the ctime match before doing setattr.
			 */
			va.va_mask = AT_CTIME;
			va.va_ctime = ctime;
			svp = rp->r_server;
			(void) nfs_rw_enter_sig(&svp->sv_lock, RW_READER, 0);
			supp_attrs = svp->sv_supp_attrs;
			nfs_rw_exit(&svp->sv_lock);
			e.error = nfs4args_verify(&argop[verify_argop], &va,
			    OP_VERIFY, supp_attrs);
			if (e.error) {
				/* req time field(s) overflow - return */
				nfs4_end_op(VTOMI4(vp), vp, NULL, &recov_state,
				    needrecov);
				break;
			}
		}

		doqueue = 1;

		t = gethrtime();

		rfs4call(VTOMI4(vp), &args, &res, cr, &doqueue, 0, &e);

		/*
		 * Purge the access cache and ACL cache if changing either the
		 * owner of the file, the group owner, or the mode.  These may
		 * change the access permissions of the file, so purge old
		 * information and start over again.
		 */
		if (mask & (AT_UID | AT_GID | AT_MODE)) {
			(void) nfs4_access_purge_rp(rp);
			if (rp->r_secattr != NULL) {
				mutex_enter(&rp->r_statelock);
				vsp = rp->r_secattr;
				rp->r_secattr = NULL;
				mutex_exit(&rp->r_statelock);
				if (vsp != NULL)
					nfs4_acl_free_cache(vsp);
			}
		}

		/*
		 * If res.array_len == numops, then everything succeeded,
		 * except for possibly the final getattr.  If only the
		 * last getattr failed, give up, and don't try recovery.
		 */
		if (res.array_len == numops) {
			nfs4_end_op(VTOMI4(vp), vp, NULL, &recov_state,
			    needrecov);
			if (! e.error)
				resp = &res;
			break;
		}

		/*
		 * if either rpc call failed or completely succeeded - done
		 */
		needrecov = nfs4_needs_recovery(&e, FALSE, vp->v_vfsp);
		if (e.error) {
			PURGE_ATTRCACHE4(vp);
			if (!needrecov) {
				nfs4_end_op(VTOMI4(vp), vp, NULL, &recov_state,
				    needrecov);
				break;
			}
		}

		/*
		 * Do proper retry for OLD_STATEID outside of the normal
		 * recovery framework.
		 */
		if (e.error == 0 && res.status == NFS4ERR_OLD_STATEID &&
		    sid_types.cur_sid_type != SPEC_SID &&
		    sid_types.cur_sid_type != NO_SID) {
			nfs4_end_op(VTOMI4(vp), vp, NULL, &recov_state,
			    needrecov);
			nfs4_save_stateid(&stateid, &sid_types);
			nfs4_fattr4_free(&argop[setattr_argop].nfs_argop4_u.
			    opsetattr.obj_attributes);
			if (verify_argop != -1) {
				nfs4args_verify_free(&argop[verify_argop]);
				verify_argop = -1;
			}
			(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
			goto recov_retry;
		}

		if (needrecov) {
			bool_t abort;

			abort = nfs4_start_recovery(&e,
			    VTOMI4(vp), vp, NULL, NULL, NULL,
			    OP_SETATTR, NULL, NULL, NULL);
			nfs4_end_op(VTOMI4(vp), vp, NULL, &recov_state,
			    needrecov);
			/*
			 * Do not retry if we failed with OLD_STATEID using
			 * a special stateid.  This is done to avoid looping
			 * with a broken server.
			 */
			if (e.error == 0 && res.status == NFS4ERR_OLD_STATEID &&
			    (sid_types.cur_sid_type == SPEC_SID ||
			    sid_types.cur_sid_type == NO_SID))
				abort = TRUE;
			if (!e.error) {
				if (res.status == NFS4ERR_BADOWNER)
					nfs4_log_badowner(VTOMI4(vp),
					    OP_SETATTR);

				e.error = geterrno4(res.status);
				(void) xdr_free(xdr_COMPOUND4res_clnt,
				    (caddr_t)&res);
			}
			nfs4_fattr4_free(&argop[setattr_argop].nfs_argop4_u.
			    opsetattr.obj_attributes);
			if (verify_argop != -1) {
				nfs4args_verify_free(&argop[verify_argop]);
				verify_argop = -1;
			}
			if (abort == FALSE) {
				/*
				 * Need to retry all possible stateids in
				 * case the recovery error wasn't stateid
				 * related or the stateids have become
				 * stale (server reboot).
				 */
				nfs4_init_stateid_types(&sid_types);
				goto recov_retry;
			}
			return (e.error);
		}

		/*
		 * Need to call nfs4_end_op before nfs4getattr to
		 * avoid potential nfs4_start_op deadlock. See RFE
		 * 4777612.  Calls to nfs4_invalidate_pages() and
		 * nfs4_purge_stale_fh() might also generate over the
		 * wire calls which my cause nfs4_start_op() deadlock.
		 */
		nfs4_end_op(VTOMI4(vp), vp, NULL, &recov_state, needrecov);

		/*
		 * Check to update lease.
		 */
		resp = &res;
		if (res.status == NFS4_OK) {
			break;
		}

		/*
		 * Check if verify failed to see if try again
		 */
		if ((verify_argop == -1) || (res.array_len != 3)) {
			/*
			 * can't continue...
			 */
			if (res.status == NFS4ERR_BADOWNER)
				nfs4_log_badowner(VTOMI4(vp), OP_SETATTR);

			e.error = geterrno4(res.status);
		} else {
			/*
			 * When the verify request fails, the client ctime is
			 * not in sync with the server. This is the same as
			 * the version 3 "not synchronized" error, and we
			 * handle it in a similar manner (XXX do we need to???).
			 * Use the ctime returned in the first getattr for
			 * the input to the next verify.
			 * If we couldn't get the attributes, then we give up
			 * because we can't complete the operation as required.
			 */
			garp = &res.array[1].nfs_resop4_u.opgetattr.ga_res;
		}
		if (e.error) {
			PURGE_ATTRCACHE4(vp);
			nfs4_purge_stale_fh(e.error, vp, cr);
		} else {
			/*
			 * retry with a new verify value
			 */
			ctime = garp->n4g_va.va_ctime;
			(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
			resp = NULL;
		}
		if (!e.error) {
			nfs4_fattr4_free(&argop[setattr_argop].nfs_argop4_u.
			    opsetattr.obj_attributes);
			if (verify_argop != -1) {
				nfs4args_verify_free(&argop[verify_argop]);
				verify_argop = -1;
			}
			(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
			goto do_again;
		}
	} while (!e.error);

	if (e.error) {
		/*
		 * If we are here, rfs4call has an irrecoverable error - return
		 */
		nfs4_fattr4_free(&argop[setattr_argop].nfs_argop4_u.
		    opsetattr.obj_attributes);
		if (verify_argop != -1) {
			nfs4args_verify_free(&argop[verify_argop]);
			verify_argop = -1;
		}
		if (resp)
			(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)resp);
		return (e.error);
	}



	/*
	 * If changing the size of the file, invalidate
	 * any local cached data which is no longer part
	 * of the file.  We also possibly invalidate the
	 * last page in the file.  We could use
	 * pvn_vpzero(), but this would mark the page as
	 * modified and require it to be written back to
	 * the server for no particularly good reason.
	 * This way, if we access it, then we bring it
	 * back in.  A read should be cheaper than a
	 * write.
	 */
	if (mask & AT_SIZE) {
		nfs4_invalidate_pages(vp, (vap->va_size & PAGEMASK), cr);
	}

	/* either no error or one of the postop getattr failed */

	/*
	 * XXX Perform a simplified version of wcc checking. Instead of
	 * have another getattr to get pre-op, just purge cache if
	 * any of the ops prior to and including the getattr failed.
	 * If the getattr succeeded then update the attrcache accordingly.
	 */

	garp = NULL;
	if (res.status == NFS4_OK) {
		/*
		 * Last getattr
		 */
		resop = &res.array[numops - 1];
		garp = &resop->nfs_resop4_u.opgetattr.ga_res;
	}
	/*
	 * In certain cases, nfs4_update_attrcache() will purge the attrcache,
	 * rather than filling it.  See the function itself for details.
	 */
	e.error = nfs4_update_attrcache(res.status, garp, t, vp, cr);
	if (garp != NULL) {
		if (garp->n4g_resbmap & FATTR4_ACL_MASK) {
			nfs4_acl_fill_cache(rp, &garp->n4g_vsa);
			vs_ace4_destroy(&garp->n4g_vsa);
		} else {
			if (vsap != NULL) {
				/*
				 * The ACL was supposed to be set and to be
				 * returned in the last getattr of this
				 * compound, but for some reason the getattr
				 * result doesn't contain the ACL.  In this
				 * case, purge the ACL cache.
				 */
				if (rp->r_secattr != NULL) {
					mutex_enter(&rp->r_statelock);
					vsp = rp->r_secattr;
					rp->r_secattr = NULL;
					mutex_exit(&rp->r_statelock);
					if (vsp != NULL)
						nfs4_acl_free_cache(vsp);
				}
			}
		}
	}

	if (res.status == NFS4_OK && (mask & AT_SIZE)) {
		/*
		 * Set the size, rather than relying on getting it updated
		 * via a GETATTR.  With delegations the client tries to
		 * suppress GETATTR calls.
		 */
		mutex_enter(&rp->r_statelock);
		rp->r_size = vap->va_size;
		mutex_exit(&rp->r_statelock);
	}

	/*
	 * Can free up request args and res
	 */
	nfs4_fattr4_free(&argop[setattr_argop].nfs_argop4_u.
	    opsetattr.obj_attributes);
	if (verify_argop != -1) {
		nfs4args_verify_free(&argop[verify_argop]);
		verify_argop = -1;
	}
	(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);

	/*
	 * Some servers will change the mode to clear the setuid
	 * and setgid bits when changing the uid or gid.  The
	 * client needs to compensate appropriately.
	 */
	if (mask & (AT_UID | AT_GID)) {
		int terror, do_setattr;

		do_setattr = 0;
		va.va_mask = AT_MODE;
		terror = nfs4getattr(vp, &va, cr);
		if (!terror &&
		    (((mask & AT_MODE) && va.va_mode != vap->va_mode) ||
		    (!(mask & AT_MODE) && va.va_mode != omode))) {
			va.va_mask = AT_MODE;
			if (mask & AT_MODE) {
				/*
				 * We asked the mode to be changed and what
				 * we just got from the server in getattr is
				 * not what we wanted it to be, so set it now.
				 */
				va.va_mode = vap->va_mode;
				do_setattr = 1;
			} else {
				/*
				 * We did not ask the mode to be changed,
				 * Check to see that the server just cleared
				 * I_SUID and I_GUID from it. If not then
				 * set mode to omode with UID/GID cleared.
				 */
				if (nfs4_compare_modes(va.va_mode, omode)) {
					omode &= ~(S_ISUID|S_ISGID);
					va.va_mode = omode;
					do_setattr = 1;
				}
			}

			if (do_setattr)
				(void) nfs4setattr(vp, &va, 0, cr, NULL);
		}
	}

	return (e.error);
}

/* ARGSUSED */
static int
nfs4_access(vnode_t *vp, int mode, int flags, cred_t *cr, caller_context_t *ct)
{
	COMPOUND4args_clnt args;
	COMPOUND4res_clnt res;
	int doqueue;
	uint32_t acc, resacc, argacc;
	rnode4_t *rp;
	cred_t *cred, *ncr, *ncrfree = NULL;
	nfs4_access_type_t cacc;
	int num_ops;
	nfs_argop4 argop[3];
	nfs_resop4 *resop;
	bool_t needrecov = FALSE, do_getattr;
	nfs4_recov_state_t recov_state;
	int rpc_error;
	hrtime_t t;
	nfs4_error_t e = { 0, NFS4_OK, RPC_SUCCESS };
	mntinfo4_t *mi = VTOMI4(vp);

	if (nfs_zone() != mi->mi_zone)
		return (EIO);

	acc = 0;
	if (mode & VREAD)
		acc |= ACCESS4_READ;
	if (mode & VWRITE) {
		if ((vp->v_vfsp->vfs_flag & VFS_RDONLY) && !ISVDEV(vp->v_type))
			return (EROFS);
		if (vp->v_type == VDIR)
			acc |= ACCESS4_DELETE;
		acc |= ACCESS4_MODIFY | ACCESS4_EXTEND;
	}
	if (mode & VEXEC) {
		if (vp->v_type == VDIR)
			acc |= ACCESS4_LOOKUP;
		else
			acc |= ACCESS4_EXECUTE;
	}

	if (VTOR4(vp)->r_acache != NULL) {
		e.error = nfs4_validate_caches(vp, cr);
		if (e.error)
			return (e.error);
	}

	rp = VTOR4(vp);
	if (vp->v_type == VDIR)
		argacc = ACCESS4_READ | ACCESS4_DELETE | ACCESS4_MODIFY |
		    ACCESS4_EXTEND | ACCESS4_LOOKUP;
	else
		argacc = ACCESS4_READ | ACCESS4_MODIFY | ACCESS4_EXTEND |
		    ACCESS4_EXECUTE;
	recov_state.rs_flags = 0;
	recov_state.rs_num_retry_despite_err = 0;

	cred = cr;
	/*
	 * ncr and ncrfree both initially
	 * point to the memory area returned
	 * by crnetadjust();
	 * ncrfree not NULL when exiting means
	 * that we need to release it
	 */
	ncr = crnetadjust(cred);
	ncrfree = ncr;

tryagain:
	cacc = nfs4_access_check(rp, acc, cred);
	if (cacc == NFS4_ACCESS_ALLOWED) {
		if (ncrfree != NULL)
			crfree(ncrfree);
		return (0);
	}
	if (cacc == NFS4_ACCESS_DENIED) {
		/*
		 * If the cred can be adjusted, try again
		 * with the new cred.
		 */
		if (ncr != NULL) {
			cred = ncr;
			ncr = NULL;
			goto tryagain;
		}
		if (ncrfree != NULL)
			crfree(ncrfree);
		return (EACCES);
	}

recov_retry:
	/*
	 * Don't take with r_statev4_lock here. r_deleg_type could
	 * change as soon as lock is released.  Since it is an int,
	 * there is no atomicity issue.
	 */
	do_getattr = (rp->r_deleg_type == OPEN_DELEGATE_NONE);
	num_ops = do_getattr ? 3 : 2;

	args.ctag = TAG_ACCESS;

	args.array_len = num_ops;
	args.array = argop;

	if (e.error = nfs4_start_fop(mi, vp, NULL, OH_ACCESS,
	    &recov_state, NULL)) {
		if (ncrfree != NULL)
			crfree(ncrfree);
		return (e.error);
	}

	/* putfh target fh */
	argop[0].argop = OP_CPUTFH;
	argop[0].nfs_argop4_u.opcputfh.sfh = VTOR4(vp)->r_fh;

	/* access */
	argop[1].argop = OP_ACCESS;
	argop[1].nfs_argop4_u.opaccess.access = argacc;

	/* getattr */
	if (do_getattr) {
		argop[2].argop = OP_GETATTR;
		argop[2].nfs_argop4_u.opgetattr.attr_request = NFS4_VATTR_MASK;
		argop[2].nfs_argop4_u.opgetattr.mi = mi;
	}

	NFS4_DEBUG(nfs4_client_call_debug, (CE_NOTE,
	    "nfs4_access: %s call, rp %s", needrecov ? "recov" : "first",
	    rnode4info(VTOR4(vp))));

	doqueue = 1;
	t = gethrtime();
	rfs4call(VTOMI4(vp), &args, &res, cred, &doqueue, 0, &e);
	rpc_error = e.error;

	needrecov = nfs4_needs_recovery(&e, FALSE, vp->v_vfsp);
	if (needrecov) {
		NFS4_DEBUG(nfs4_client_recov_debug, (CE_NOTE,
		    "nfs4_access: initiating recovery\n"));

		if (nfs4_start_recovery(&e, VTOMI4(vp), vp, NULL, NULL,
		    NULL, OP_ACCESS, NULL, NULL, NULL) == FALSE) {
			nfs4_end_fop(VTOMI4(vp), vp, NULL, OH_ACCESS,
			    &recov_state, needrecov);
			if (!e.error)
				(void) xdr_free(xdr_COMPOUND4res_clnt,
				    (caddr_t)&res);
			goto recov_retry;
		}
	}
	nfs4_end_fop(mi, vp, NULL, OH_ACCESS, &recov_state, needrecov);

	if (e.error)
		goto out;

	if (res.status) {
		e.error = geterrno4(res.status);
		/*
		 * This might generate over the wire calls throught
		 * nfs4_invalidate_pages. Hence we need to call nfs4_end_op()
		 * here to avoid a deadlock.
		 */
		nfs4_purge_stale_fh(e.error, vp, cr);
		goto out;
	}
	resop = &res.array[1];	/* access res */

	resacc = resop->nfs_resop4_u.opaccess.access;

	if (do_getattr) {
		resop++;	/* getattr res */
		nfs4_attr_cache(vp, &resop->nfs_resop4_u.opgetattr.ga_res,
		    t, cr, FALSE, NULL);
	}

	if (!e.error) {
		nfs4_access_cache(rp, argacc, resacc, cred);
		/*
		 * we just cached results with cred; if cred is the
		 * adjusted credentials from crnetadjust, we do not want
		 * to release them before exiting: hence setting ncrfree
		 * to NULL
		 */
		if (cred != cr)
			ncrfree = NULL;
		/* XXX check the supported bits too? */
		if ((acc & resacc) != acc) {
			/*
			 * The following code implements the semantic
			 * that a setuid root program has *at least* the
			 * permissions of the user that is running the
			 * program.  See rfs3call() for more portions
			 * of the implementation of this functionality.
			 */
			/* XXX-LP */
			if (ncr != NULL) {
				(void) xdr_free(xdr_COMPOUND4res_clnt,
				    (caddr_t)&res);
				cred = ncr;
				ncr = NULL;
				goto tryagain;
			}
			e.error = EACCES;
		}
	}

out:
	if (!rpc_error)
		(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);

	if (ncrfree != NULL)
		crfree(ncrfree);

	return (e.error);
}

/* ARGSUSED */
static int
nfs4_readlink(vnode_t *vp, struct uio *uiop, cred_t *cr, caller_context_t *ct)
{
	COMPOUND4args_clnt args;
	COMPOUND4res_clnt res;
	int doqueue;
	rnode4_t *rp;
	nfs_argop4 argop[3];
	nfs_resop4 *resop;
	READLINK4res *lr_res;
	nfs4_ga_res_t *garp;
	uint_t len;
	char *linkdata;
	bool_t needrecov = FALSE;
	nfs4_recov_state_t recov_state;
	hrtime_t t;
	nfs4_error_t e = { 0, NFS4_OK, RPC_SUCCESS };

	if (nfs_zone() != VTOMI4(vp)->mi_zone)
		return (EIO);
	/*
	 * Can't readlink anything other than a symbolic link.
	 */
	if (vp->v_type != VLNK)
		return (EINVAL);

	rp = VTOR4(vp);
	if (nfs4_do_symlink_cache && rp->r_symlink.contents != NULL) {
		e.error = nfs4_validate_caches(vp, cr);
		if (e.error)
			return (e.error);
		mutex_enter(&rp->r_statelock);
		if (rp->r_symlink.contents != NULL) {
			e.error = uiomove(rp->r_symlink.contents,
			    rp->r_symlink.len, UIO_READ, uiop);
			mutex_exit(&rp->r_statelock);
			return (e.error);
		}
		mutex_exit(&rp->r_statelock);
	}
	recov_state.rs_flags = 0;
	recov_state.rs_num_retry_despite_err = 0;

recov_retry:
	args.array_len = 3;
	args.array = argop;
	args.ctag = TAG_READLINK;

	e.error = nfs4_start_op(VTOMI4(vp), vp, NULL, &recov_state);
	if (e.error) {
		return (e.error);
	}

	/* 0. putfh symlink fh */
	argop[0].argop = OP_CPUTFH;
	argop[0].nfs_argop4_u.opcputfh.sfh = VTOR4(vp)->r_fh;

	/* 1. readlink */
	argop[1].argop = OP_READLINK;

	/* 2. getattr */
	argop[2].argop = OP_GETATTR;
	argop[2].nfs_argop4_u.opgetattr.attr_request = NFS4_VATTR_MASK;
	argop[2].nfs_argop4_u.opgetattr.mi = VTOMI4(vp);

	doqueue = 1;

	NFS4_DEBUG(nfs4_client_call_debug, (CE_NOTE,
	    "nfs4_readlink: %s call, rp %s", needrecov ? "recov" : "first",
	    rnode4info(VTOR4(vp))));

	t = gethrtime();

	rfs4call(VTOMI4(vp), &args, &res, cr, &doqueue, 0, &e);

	needrecov = nfs4_needs_recovery(&e, FALSE, vp->v_vfsp);
	if (needrecov) {
		NFS4_DEBUG(nfs4_client_recov_debug, (CE_NOTE,
		    "nfs4_readlink: initiating recovery\n"));

		if (nfs4_start_recovery(&e, VTOMI4(vp), vp, NULL, NULL,
		    NULL, OP_READLINK, NULL, NULL, NULL) == FALSE) {
			if (!e.error)
				(void) xdr_free(xdr_COMPOUND4res_clnt,
				    (caddr_t)&res);

			nfs4_end_op(VTOMI4(vp), vp, NULL, &recov_state,
			    needrecov);
			goto recov_retry;
		}
	}

	nfs4_end_op(VTOMI4(vp), vp, NULL, &recov_state, needrecov);

	if (e.error)
		return (e.error);

	/*
	 * There is an path in the code below which calls
	 * nfs4_purge_stale_fh(), which may generate otw calls through
	 * nfs4_invalidate_pages. Hence we need to call nfs4_end_op()
	 * here to avoid nfs4_start_op() deadlock.
	 */

	if (res.status && (res.array_len < args.array_len)) {
		/*
		 * either Putfh or Link failed
		 */
		e.error = geterrno4(res.status);
		nfs4_purge_stale_fh(e.error, vp, cr);
		(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
		return (e.error);
	}

	resop = &res.array[1];	/* readlink res */
	lr_res = &resop->nfs_resop4_u.opreadlink;

	/*
	 * treat symlink names as data
	 */
	linkdata = utf8_to_str((utf8string *)&lr_res->link, &len, NULL);
	if (linkdata != NULL) {
		int uio_len = len - 1;
		/* len includes null byte, which we won't uiomove */
		e.error = uiomove(linkdata, uio_len, UIO_READ, uiop);
		if (nfs4_do_symlink_cache && rp->r_symlink.contents == NULL) {
			mutex_enter(&rp->r_statelock);
			if (rp->r_symlink.contents == NULL) {
				rp->r_symlink.contents = linkdata;
				rp->r_symlink.len = uio_len;
				rp->r_symlink.size = len;
				mutex_exit(&rp->r_statelock);
			} else {
				mutex_exit(&rp->r_statelock);
				kmem_free(linkdata, len);
			}
		} else {
			kmem_free(linkdata, len);
		}
	}
	if (res.status == NFS4_OK) {
		resop++;	/* getattr res */
		garp = &resop->nfs_resop4_u.opgetattr.ga_res;
	}
	e.error = nfs4_update_attrcache(res.status, garp, t, vp, cr);

	(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);

	/*
	 * The over the wire error for attempting to readlink something
	 * other than a symbolic link is ENXIO.  However, we need to
	 * return EINVAL instead of ENXIO, so we map it here.
	 */
	return (e.error == ENXIO ? EINVAL : e.error);
}

/*
 * Flush local dirty pages to stable storage on the server.
 *
 * If FNODSYNC is specified, then there is nothing to do because
 * metadata changes are not cached on the client before being
 * sent to the server.
 */
/* ARGSUSED */
static int
nfs4_fsync(vnode_t *vp, int syncflag, cred_t *cr, caller_context_t *ct)
{
	int error;

	if ((syncflag & FNODSYNC) || IS_SWAPVP(vp))
		return (0);
	if (nfs_zone() != VTOMI4(vp)->mi_zone)
		return (EIO);
	error = nfs4_putpage_commit(vp, (offset_t)0, 0, cr);
	if (!error)
		error = VTOR4(vp)->r_error;
	return (error);
}

/*
 * Weirdness: if the file was removed or the target of a rename
 * operation while it was open, it got renamed instead.  Here we
 * remove the renamed file.
 */
/* ARGSUSED */
void
nfs4_inactive(vnode_t *vp, cred_t *cr, caller_context_t *ct)
{
	rnode4_t *rp;

	ASSERT(vp != DNLC_NO_VNODE);

	rp = VTOR4(vp);

	if (IS_SHADOW(vp, rp)) {
		sv_inactive(vp);
		return;
	}

	/*
	 * If this is coming from the wrong zone, we let someone in the right
	 * zone take care of it asynchronously.  We can get here due to
	 * VN_RELE() being called from pageout() or fsflush().  This call may
	 * potentially turn into an expensive no-op if, for instance, v_count
	 * gets incremented in the meantime, but it's still correct.
	 */
	if (nfs_zone() != VTOMI4(vp)->mi_zone) {
		nfs4_async_inactive(vp, cr);
		return;
	}

	/*
	 * Some of the cleanup steps might require over-the-wire
	 * operations.  Since VOP_INACTIVE can get called as a result of
	 * other over-the-wire operations (e.g., an attribute cache update
	 * can lead to a DNLC purge), doing those steps now would lead to a
	 * nested call to the recovery framework, which can deadlock.  So
	 * do any over-the-wire cleanups asynchronously, in a separate
	 * thread.
	 */

	mutex_enter(&rp->r_os_lock);
	mutex_enter(&rp->r_statelock);
	mutex_enter(&rp->r_statev4_lock);

	if (vp->v_type == VREG && list_head(&rp->r_open_streams) != NULL) {
		mutex_exit(&rp->r_statev4_lock);
		mutex_exit(&rp->r_statelock);
		mutex_exit(&rp->r_os_lock);
		nfs4_async_inactive(vp, cr);
		return;
	}

	if (rp->r_deleg_type == OPEN_DELEGATE_READ ||
	    rp->r_deleg_type == OPEN_DELEGATE_WRITE) {
		mutex_exit(&rp->r_statev4_lock);
		mutex_exit(&rp->r_statelock);
		mutex_exit(&rp->r_os_lock);
		nfs4_async_inactive(vp, cr);
		return;
	}

	if (rp->r_unldvp != NULL) {
		mutex_exit(&rp->r_statev4_lock);
		mutex_exit(&rp->r_statelock);
		mutex_exit(&rp->r_os_lock);
		nfs4_async_inactive(vp, cr);
		return;
	}
	mutex_exit(&rp->r_statev4_lock);
	mutex_exit(&rp->r_statelock);
	mutex_exit(&rp->r_os_lock);

	rp4_addfree(rp, cr);
}

/*
 * nfs4_inactive_otw - nfs4_inactive, plus over-the-wire calls to free up
 * various bits of state.  The caller must not refer to vp after this call.
 */

void
nfs4_inactive_otw(vnode_t *vp, cred_t *cr)
{
	rnode4_t *rp = VTOR4(vp);
	nfs4_recov_state_t recov_state;
	nfs4_error_t e = { 0, NFS4_OK, RPC_SUCCESS };
	vnode_t *unldvp;
	char *unlname;
	cred_t *unlcred;
	COMPOUND4args_clnt args;
	COMPOUND4res_clnt res, *resp;
	nfs_argop4 argop[2];
	int doqueue;
#ifdef DEBUG
	char *name;
#endif

	ASSERT(nfs_zone() == VTOMI4(vp)->mi_zone);
	ASSERT(!IS_SHADOW(vp, rp));

#ifdef DEBUG
	name = fn_name(VTOSV(vp)->sv_name);
	NFS4_DEBUG(nfs4_client_inactive_debug, (CE_NOTE, "nfs4_inactive_otw: "
	    "release vnode %s", name));
	kmem_free(name, MAXNAMELEN);
#endif

	if (vp->v_type == VREG) {
		bool_t recov_failed = FALSE;

		e.error = nfs4close_all(vp, cr);
		if (e.error) {
			/* Check to see if recovery failed */
			mutex_enter(&(VTOMI4(vp)->mi_lock));
			if (VTOMI4(vp)->mi_flags & MI4_RECOV_FAIL)
				recov_failed = TRUE;
			mutex_exit(&(VTOMI4(vp)->mi_lock));
			if (!recov_failed) {
				mutex_enter(&rp->r_statelock);
				if (rp->r_flags & R4RECOVERR)
					recov_failed = TRUE;
				mutex_exit(&rp->r_statelock);
			}
			if (recov_failed) {
				NFS4_DEBUG(nfs4_client_recov_debug,
				    (CE_NOTE, "nfs4_inactive_otw: "
				    "close failed (recovery failure)"));
			}
		}
	}

redo:
	if (rp->r_unldvp == NULL) {
		rp4_addfree(rp, cr);
		return;
	}

	/*
	 * Save the vnode pointer for the directory where the
	 * unlinked-open file got renamed, then set it to NULL
	 * to prevent another thread from getting here before
	 * we're done with the remove.  While we have the
	 * statelock, make local copies of the pertinent rnode
	 * fields.  If we weren't to do this in an atomic way, the
	 * the unl* fields could become inconsistent with respect
	 * to each other due to a race condition between this
	 * code and nfs_remove().  See bug report 1034328.
	 */
	mutex_enter(&rp->r_statelock);
	if (rp->r_unldvp == NULL) {
		mutex_exit(&rp->r_statelock);
		rp4_addfree(rp, cr);
		return;
	}

	unldvp = rp->r_unldvp;
	rp->r_unldvp = NULL;
	unlname = rp->r_unlname;
	rp->r_unlname = NULL;
	unlcred = rp->r_unlcred;
	rp->r_unlcred = NULL;
	mutex_exit(&rp->r_statelock);

	/*
	 * If there are any dirty pages left, then flush
	 * them.  This is unfortunate because they just
	 * may get thrown away during the remove operation,
	 * but we have to do this for correctness.
	 */
	if (nfs4_has_pages(vp) &&
	    ((rp->r_flags & R4DIRTY) || rp->r_count > 0)) {
		ASSERT(vp->v_type != VCHR);
		e.error = nfs4_putpage(vp, (u_offset_t)0, 0, 0, cr, NULL);
		if (e.error) {
			mutex_enter(&rp->r_statelock);
			if (!rp->r_error)
				rp->r_error = e.error;
			mutex_exit(&rp->r_statelock);
		}
	}

	recov_state.rs_flags = 0;
	recov_state.rs_num_retry_despite_err = 0;
recov_retry_remove:
	/*
	 * Do the remove operation on the renamed file
	 */
	args.ctag = TAG_INACTIVE;

	/*
	 * Remove ops: putfh dir; remove
	 */
	args.array_len = 2;
	args.array = argop;

	e.error = nfs4_start_op(VTOMI4(unldvp), unldvp, NULL, &recov_state);
	if (e.error) {
		kmem_free(unlname, MAXNAMELEN);
		crfree(unlcred);
		VN_RELE(unldvp);
		/*
		 * Try again; this time around r_unldvp will be NULL, so we'll
		 * just call rp4_addfree() and return.
		 */
		goto redo;
	}

	/* putfh directory */
	argop[0].argop = OP_CPUTFH;
	argop[0].nfs_argop4_u.opcputfh.sfh = VTOR4(unldvp)->r_fh;

	/* remove */
	argop[1].argop = OP_CREMOVE;
	argop[1].nfs_argop4_u.opcremove.ctarget = unlname;

	doqueue = 1;
	resp = &res;

#if 0 /* notyet */
	/*
	 * Can't do this yet.  We may be being called from
	 * dnlc_purge_XXX while that routine is holding a
	 * mutex lock to the nc_rele list.  The calls to
	 * nfs3_cache_wcc_data may result in calls to
	 * dnlc_purge_XXX.  This will result in a deadlock.
	 */
	rfs4call(VTOMI4(unldvp), &args, &res, unlcred, &doqueue, 0, &e);
	if (e.error) {
		PURGE_ATTRCACHE4(unldvp);
		resp = NULL;
	} else if (res.status) {
		e.error = geterrno4(res.status);
		PURGE_ATTRCACHE4(unldvp);
		/*
		 * This code is inactive right now
		 * but if made active there should
		 * be a nfs4_end_op() call before
		 * nfs4_purge_stale_fh to avoid start_op()
		 * deadlock. See BugId: 4948726
		 */
		nfs4_purge_stale_fh(error, unldvp, cr);
	} else {
		nfs_resop4 *resop;
		REMOVE4res *rm_res;

		resop = &res.array[1];
		rm_res = &resop->nfs_resop4_u.opremove;
		/*
		 * Update directory cache attribute,
		 * readdir and dnlc caches.
		 */
		nfs4_update_dircaches(&rm_res->cinfo, unldvp, NULL, NULL, NULL);
	}
#else
	rfs4call(VTOMI4(unldvp), &args, &res, unlcred, &doqueue, 0, &e);

	PURGE_ATTRCACHE4(unldvp);
#endif

	if (nfs4_needs_recovery(&e, FALSE, unldvp->v_vfsp)) {
		if (nfs4_start_recovery(&e, VTOMI4(unldvp), unldvp, NULL,
		    NULL, NULL, OP_REMOVE, NULL, NULL, NULL) == FALSE) {
			if (!e.error)
				(void) xdr_free(xdr_COMPOUND4res_clnt,
				    (caddr_t)&res);
			nfs4_end_op(VTOMI4(unldvp), unldvp, NULL,
			    &recov_state, TRUE);
			goto recov_retry_remove;
		}
	}
	nfs4_end_op(VTOMI4(unldvp), unldvp, NULL, &recov_state, FALSE);

	/*
	 * Release stuff held for the remove
	 */
	VN_RELE(unldvp);
	if (!e.error && resp)
		(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)resp);

	kmem_free(unlname, MAXNAMELEN);
	crfree(unlcred);
	goto redo;
}

/*
 * Remote file system operations having to do with directory manipulation.
 */
/* ARGSUSED3 */
int
nfs4_lookup(vnode_t *dvp, char *nm, vnode_t **vpp, struct pathname *pnp,
    int flags, vnode_t *rdir, cred_t *cr, caller_context_t *ct,
    int *direntflags, pathname_t *realpnp)
{
	int error;
	vnode_t *vp, *avp = NULL;
	rnode4_t *drp;

	*vpp = NULL;
	if (nfs_zone() != VTOMI4(dvp)->mi_zone)
		return (EPERM);
	/*
	 * if LOOKUP_XATTR, must replace dvp (object) with
	 * object's attrdir before continuing with lookup
	 */
	if (flags & LOOKUP_XATTR) {
		error = nfs4lookup_xattr(dvp, nm, &avp, flags, cr);
		if (error)
			return (error);

		dvp = avp;

		/*
		 * If lookup is for "", just return dvp now.  The attrdir
		 * has already been activated (from nfs4lookup_xattr), and
		 * the caller will RELE the original dvp -- not
		 * the attrdir.  So, set vpp and return.
		 * Currently, when the LOOKUP_XATTR flag is
		 * passed to VOP_LOOKUP, the name is always empty, and
		 * shortcircuiting here avoids 3 unneeded lock/unlock
		 * pairs.
		 *
		 * If a non-empty name was provided, then it is the
		 * attribute name, and it will be looked up below.
		 */
		if (*nm == '\0') {
			*vpp = dvp;
			return (0);
		}

		/*
		 * The vfs layer never sends a name when asking for the
		 * attrdir, so we should never get here (unless of course
		 * name is passed at some time in future -- at which time
		 * we'll blow up here).
		 */
		ASSERT(0);
	}

	drp = VTOR4(dvp);
	if (nfs_rw_enter_sig(&drp->r_rwlock, RW_READER, INTR4(dvp)))
		return (EINTR);

	error = nfs4lookup(dvp, nm, vpp, cr, 0);
	nfs_rw_exit(&drp->r_rwlock);

	/*
	 * If vnode is a device, create special vnode.
	 */
	if (!error && ISVDEV((*vpp)->v_type)) {
		vp = *vpp;
		*vpp = specvp(vp, vp->v_rdev, vp->v_type, cr);
		VN_RELE(vp);
	}

	return (error);
}

/* ARGSUSED */
static int
nfs4lookup_xattr(vnode_t *dvp, char *nm, vnode_t **vpp, int flags, cred_t *cr)
{
	int error;
	rnode4_t *drp;
	int cflag = ((flags & CREATE_XATTR_DIR) != 0);
	mntinfo4_t *mi;

	mi = VTOMI4(dvp);
	if (!(mi->mi_vfsp->vfs_flag & VFS_XATTR) &&
	    !vfs_has_feature(mi->mi_vfsp, VFSFT_SYSATTR_VIEWS))
		return (EINVAL);

	drp = VTOR4(dvp);
	if (nfs_rw_enter_sig(&drp->r_rwlock, RW_READER, INTR4(dvp)))
		return (EINTR);

	mutex_enter(&drp->r_statelock);
	/*
	 * If the server doesn't support xattrs just return EINVAL
	 */
	if (drp->r_xattr_dir == NFS4_XATTR_DIR_NOTSUPP) {
		mutex_exit(&drp->r_statelock);
		nfs_rw_exit(&drp->r_rwlock);
		return (EINVAL);
	}

	/*
	 * If there is a cached xattr directory entry,
	 * use it as long as the attributes are valid. If the
	 * attributes are not valid, take the simple approach and
	 * free the cached value and re-fetch a new value.
	 *
	 * We don't negative entry cache for now, if we did we
	 * would need to check if the file has changed on every
	 * lookup. But xattrs don't exist very often and failing
	 * an openattr is not much more expensive than and NVERIFY or GETATTR
	 * so do an openattr over the wire for now.
	 */
	if (drp->r_xattr_dir != NULL) {
		if (ATTRCACHE4_VALID(dvp)) {
			VN_HOLD(drp->r_xattr_dir);
			*vpp = drp->r_xattr_dir;
			mutex_exit(&drp->r_statelock);
			nfs_rw_exit(&drp->r_rwlock);
			return (0);
		}
		VN_RELE(drp->r_xattr_dir);
		drp->r_xattr_dir = NULL;
	}
	mutex_exit(&drp->r_statelock);

	error = nfs4openattr(dvp, vpp, cflag, cr);

	nfs_rw_exit(&drp->r_rwlock);

	return (error);
}

static int
nfs4lookup(vnode_t *dvp, char *nm, vnode_t **vpp, cred_t *cr, int skipdnlc)
{
	int error;
	rnode4_t *drp;

	ASSERT(nfs_zone() == VTOMI4(dvp)->mi_zone);

	/*
	 * If lookup is for "", just return dvp.  Don't need
	 * to send it over the wire, look it up in the dnlc,
	 * or perform any access checks.
	 */
	if (*nm == '\0') {
		VN_HOLD(dvp);
		*vpp = dvp;
		return (0);
	}

	/*
	 * Can't do lookups in non-directories.
	 */
	if (dvp->v_type != VDIR)
		return (ENOTDIR);

	/*
	 * If lookup is for ".", just return dvp.  Don't need
	 * to send it over the wire or look it up in the dnlc,
	 * just need to check access.
	 */
	if (nm[0] == '.' && nm[1] == '\0') {
		error = nfs4_access(dvp, VEXEC, 0, cr, NULL);
		if (error)
			return (error);
		VN_HOLD(dvp);
		*vpp = dvp;
		return (0);
	}

	drp = VTOR4(dvp);
	if (!(drp->r_flags & R4LOOKUP)) {
		mutex_enter(&drp->r_statelock);
		drp->r_flags |= R4LOOKUP;
		mutex_exit(&drp->r_statelock);
	}

	*vpp = NULL;
	/*
	 * Lookup this name in the DNLC.  If there is no entry
	 * lookup over the wire.
	 */
	if (!skipdnlc)
		*vpp = dnlc_lookup(dvp, nm);
	if (*vpp == NULL) {
		/*
		 * We need to go over the wire to lookup the name.
		 */
		return (nfs4lookupnew_otw(dvp, nm, vpp, cr));
	}

	/*
	 * We hit on the dnlc
	 */
	if (*vpp != DNLC_NO_VNODE ||
	    (dvp->v_vfsp->vfs_flag & VFS_RDONLY)) {
		/*
		 * But our attrs may not be valid.
		 */
		if (ATTRCACHE4_VALID(dvp)) {
			error = nfs4_waitfor_purge_complete(dvp);
			if (error) {
				VN_RELE(*vpp);
				*vpp = NULL;
				return (error);
			}

			/*
			 * If after the purge completes, check to make sure
			 * our attrs are still valid.
			 */
			if (ATTRCACHE4_VALID(dvp)) {
				/*
				 * If we waited for a purge we may have
				 * lost our vnode so look it up again.
				 */
				VN_RELE(*vpp);
				*vpp = dnlc_lookup(dvp, nm);
				if (*vpp == NULL)
					return (nfs4lookupnew_otw(dvp,
					    nm, vpp, cr));

				/*
				 * The access cache should almost always hit
				 */
				error = nfs4_access(dvp, VEXEC, 0, cr, NULL);

				if (error) {
					VN_RELE(*vpp);
					*vpp = NULL;
					return (error);
				}
				if (*vpp == DNLC_NO_VNODE) {
					VN_RELE(*vpp);
					*vpp = NULL;
					return (ENOENT);
				}
				return (0);
			}
		}
	}

	ASSERT(*vpp != NULL);

	/*
	 * We may have gotten here we have one of the following cases:
	 *	1) vpp != DNLC_NO_VNODE, our attrs have timed out so we
	 *		need to validate them.
	 *	2) vpp == DNLC_NO_VNODE, a negative entry that we always
	 *		must validate.
	 *
	 * Go to the server and check if the directory has changed, if
	 * it hasn't we are done and can use the dnlc entry.
	 */
	return (nfs4lookupvalidate_otw(dvp, nm, vpp, cr));
}

/*
 * Go to the server and check if the directory has changed, if
 * it hasn't we are done and can use the dnlc entry.  If it
 * has changed we get a new copy of its attributes and check
 * the access for VEXEC, then relookup the filename and
 * get its filehandle and attributes.
 *
 * PUTFH dfh NVERIFY GETATTR ACCESS LOOKUP GETFH GETATTR
 *	if the NVERIFY failed we must
 *		purge the caches
 *		cache new attributes (will set r_time_attr_inval)
 *		cache new access
 *		recheck VEXEC access
 *		add name to dnlc, possibly negative
 *		if LOOKUP succeeded
 *			cache new attributes
 *	else
 *		set a new r_time_attr_inval for dvp
 *		check to make sure we have access
 *
 * The vpp returned is the vnode passed in if the directory is valid,
 * a new vnode if successful lookup, or NULL on error.
 */
static int
nfs4lookupvalidate_otw(vnode_t *dvp, char *nm, vnode_t **vpp, cred_t *cr)
{
	COMPOUND4args_clnt args;
	COMPOUND4res_clnt res;
	fattr4 *ver_fattr;
	fattr4_change dchange;
	int32_t *ptr;
	int argoplist_size  = 7 * sizeof (nfs_argop4);
	nfs_argop4 *argop;
	int doqueue;
	mntinfo4_t *mi;
	nfs4_recov_state_t recov_state;
	hrtime_t t;
	int isdotdot;
	vnode_t *nvp;
	nfs_fh4 *fhp;
	nfs4_sharedfh_t *sfhp;
	nfs4_access_type_t cacc;
	rnode4_t *nrp;
	rnode4_t *drp = VTOR4(dvp);
	nfs4_ga_res_t *garp = NULL;
	nfs4_error_t e = { 0, NFS4_OK, RPC_SUCCESS };

	ASSERT(nfs_zone() == VTOMI4(dvp)->mi_zone);
	ASSERT(nm != NULL);
	ASSERT(nm[0] != '\0');
	ASSERT(dvp->v_type == VDIR);
	ASSERT(nm[0] != '.' || nm[1] != '\0');
	ASSERT(*vpp != NULL);

	if (nm[0] == '.' && nm[1] == '.' && nm[2] == '\0') {
		isdotdot = 1;
		args.ctag = TAG_LOOKUP_VPARENT;
	} else {
		/*
		 * If dvp were a stub, it should have triggered and caused
		 * a mount for us to get this far.
		 */
		ASSERT(!RP_ISSTUB(VTOR4(dvp)));

		isdotdot = 0;
		args.ctag = TAG_LOOKUP_VALID;
	}

	mi = VTOMI4(dvp);
	recov_state.rs_flags = 0;
	recov_state.rs_num_retry_despite_err = 0;

	nvp = NULL;

	/* Save the original mount point security information */
	(void) save_mnt_secinfo(mi->mi_curr_serv);

recov_retry:
	e.error = nfs4_start_fop(mi, dvp, NULL, OH_LOOKUP,
	    &recov_state, NULL);
	if (e.error) {
		(void) check_mnt_secinfo(mi->mi_curr_serv, nvp);
		VN_RELE(*vpp);
		*vpp = NULL;
		return (e.error);
	}

	argop = kmem_alloc(argoplist_size, KM_SLEEP);

	/* PUTFH dfh NVERIFY GETATTR ACCESS LOOKUP GETFH GETATTR */
	args.array_len = 7;
	args.array = argop;

	/* 0. putfh file */
	argop[0].argop = OP_CPUTFH;
	argop[0].nfs_argop4_u.opcputfh.sfh = VTOR4(dvp)->r_fh;

	/* 1. nverify the change info */
	argop[1].argop = OP_NVERIFY;
	ver_fattr = &argop[1].nfs_argop4_u.opnverify.obj_attributes;
	ver_fattr->attrmask = FATTR4_CHANGE_MASK;
	ver_fattr->attrlist4 = (char *)&dchange;
	ptr = (int32_t *)&dchange;
	IXDR_PUT_HYPER(ptr, VTOR4(dvp)->r_change);
	ver_fattr->attrlist4_len = sizeof (fattr4_change);

	/* 2. getattr directory */
	argop[2].argop = OP_GETATTR;
	argop[2].nfs_argop4_u.opgetattr.attr_request = NFS4_VATTR_MASK;
	argop[2].nfs_argop4_u.opgetattr.mi = VTOMI4(dvp);

	/* 3. access directory */
	argop[3].argop = OP_ACCESS;
	argop[3].nfs_argop4_u.opaccess.access = ACCESS4_READ | ACCESS4_DELETE |
	    ACCESS4_MODIFY | ACCESS4_EXTEND | ACCESS4_LOOKUP;

	/* 4. lookup name */
	if (isdotdot) {
		argop[4].argop = OP_LOOKUPP;
	} else {
		argop[4].argop = OP_CLOOKUP;
		argop[4].nfs_argop4_u.opclookup.cname = nm;
	}

	/* 5. resulting file handle */
	argop[5].argop = OP_GETFH;

	/* 6. resulting file attributes */
	argop[6].argop = OP_GETATTR;
	argop[6].nfs_argop4_u.opgetattr.attr_request = NFS4_VATTR_MASK;
	argop[6].nfs_argop4_u.opgetattr.mi = VTOMI4(dvp);

	doqueue = 1;
	t = gethrtime();

	rfs4call(VTOMI4(dvp), &args, &res, cr, &doqueue, 0, &e);

	if (!isdotdot && res.status == NFS4ERR_MOVED) {
		e.error = nfs4_setup_referral(dvp, nm, vpp, cr);
		if (e.error != 0 && *vpp != NULL)
			VN_RELE(*vpp);
		nfs4_end_fop(mi, dvp, NULL, OH_LOOKUP,
		    &recov_state, FALSE);
		(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
		kmem_free(argop, argoplist_size);
		return (e.error);
	}

	if (nfs4_needs_recovery(&e, FALSE, dvp->v_vfsp)) {
		/*
		 * For WRONGSEC of a non-dotdot case, send secinfo directly
		 * from this thread, do not go thru the recovery thread since
		 * we need the nm information.
		 *
		 * Not doing dotdot case because there is no specification
		 * for (PUTFH, SECINFO "..") yet.
		 */
		if (!isdotdot && res.status == NFS4ERR_WRONGSEC) {
			if ((e.error = nfs4_secinfo_vnode_otw(dvp, nm, cr)))
				nfs4_end_fop(mi, dvp, NULL, OH_LOOKUP,
				    &recov_state, FALSE);
			else
				nfs4_end_fop(mi, dvp, NULL, OH_LOOKUP,
				    &recov_state, TRUE);
			(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
			kmem_free(argop, argoplist_size);
			if (!e.error)
				goto recov_retry;
			(void) check_mnt_secinfo(mi->mi_curr_serv, nvp);
			VN_RELE(*vpp);
			*vpp = NULL;
			return (e.error);
		}

		if (nfs4_start_recovery(&e, mi, dvp, NULL, NULL, NULL,
		    OP_LOOKUP, NULL, NULL, NULL) == FALSE) {
			nfs4_end_fop(mi, dvp, NULL, OH_LOOKUP,
			    &recov_state, TRUE);

			(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
			kmem_free(argop, argoplist_size);
			goto recov_retry;
		}
	}

	nfs4_end_fop(mi, dvp, NULL, OH_LOOKUP, &recov_state, FALSE);

	if (e.error || res.array_len == 0) {
		/*
		 * If e.error isn't set, then reply has no ops (or we couldn't
		 * be here).  The only legal way to reply without an op array
		 * is via NFS4ERR_MINOR_VERS_MISMATCH.  An ops array should
		 * be in the reply for all other status values.
		 *
		 * For valid replies without an ops array, return ENOTSUP
		 * (geterrno4 xlation of VERS_MISMATCH).  For illegal replies,
		 * return EIO -- don't trust status.
		 */
		if (e.error == 0)
			e.error = (res.status == NFS4ERR_MINOR_VERS_MISMATCH) ?
			    ENOTSUP : EIO;
		VN_RELE(*vpp);
		*vpp = NULL;
		kmem_free(argop, argoplist_size);
		(void) check_mnt_secinfo(mi->mi_curr_serv, nvp);
		return (e.error);
	}

	if (res.status != NFS4ERR_SAME) {
		e.error = geterrno4(res.status);

		/*
		 * The NVERIFY "failed" so the directory has changed
		 * First make sure PUTFH succeeded and NVERIFY "failed"
		 * cleanly.
		 */
		if ((res.array[0].nfs_resop4_u.opputfh.status != NFS4_OK) ||
		    (res.array[1].nfs_resop4_u.opnverify.status != NFS4_OK)) {
			nfs4_purge_stale_fh(e.error, dvp, cr);
			VN_RELE(*vpp);
			*vpp = NULL;
			goto exit;
		}

		/*
		 * We know the NVERIFY "failed" so we must:
		 *	purge the caches (access and indirectly dnlc if needed)
		 */
		nfs4_purge_caches(dvp, NFS4_NOPURGE_DNLC, cr, TRUE);

		if (res.array[2].nfs_resop4_u.opgetattr.status != NFS4_OK) {
			nfs4_purge_stale_fh(e.error, dvp, cr);
			VN_RELE(*vpp);
			*vpp = NULL;
			goto exit;
		}

		/*
		 * Install new cached attributes for the directory
		 */
		nfs4_attr_cache(dvp,
		    &res.array[2].nfs_resop4_u.opgetattr.ga_res,
		    t, cr, FALSE, NULL);

		if (res.array[3].nfs_resop4_u.opaccess.status != NFS4_OK) {
			nfs4_purge_stale_fh(e.error, dvp, cr);
			VN_RELE(*vpp);
			*vpp = NULL;
			e.error = geterrno4(res.status);
			goto exit;
		}

		/*
		 * Now we know the directory is valid,
		 * cache new directory access
		 */
		nfs4_access_cache(drp,
		    args.array[3].nfs_argop4_u.opaccess.access,
		    res.array[3].nfs_resop4_u.opaccess.access, cr);

		/*
		 * recheck VEXEC access
		 */
		cacc = nfs4_access_check(drp, ACCESS4_LOOKUP, cr);
		if (cacc != NFS4_ACCESS_ALLOWED) {
			/*
			 * Directory permissions might have been revoked
			 */
			if (cacc == NFS4_ACCESS_DENIED) {
				e.error = EACCES;
				VN_RELE(*vpp);
				*vpp = NULL;
				goto exit;
			}

			/*
			 * Somehow we must not have asked for enough
			 * so try a singleton ACCESS, should never happen.
			 */
			e.error = nfs4_access(dvp, VEXEC, 0, cr, NULL);
			if (e.error) {
				VN_RELE(*vpp);
				*vpp = NULL;
				goto exit;
			}
		}

		e.error = geterrno4(res.status);
		if (res.array[4].nfs_resop4_u.oplookup.status != NFS4_OK) {
			/*
			 * The lookup failed, probably no entry
			 */
			if (e.error == ENOENT && nfs4_lookup_neg_cache) {
				dnlc_update(dvp, nm, DNLC_NO_VNODE);
			} else {
				/*
				 * Might be some other error, so remove
				 * the dnlc entry to make sure we start all
				 * over again, next time.
				 */
				dnlc_remove(dvp, nm);
			}
			VN_RELE(*vpp);
			*vpp = NULL;
			goto exit;
		}

		if (res.array[5].nfs_resop4_u.opgetfh.status != NFS4_OK) {
			/*
			 * The file exists but we can't get its fh for
			 * some unknown reason.  Remove it from the dnlc
			 * and error out to be safe.
			 */
			dnlc_remove(dvp, nm);
			VN_RELE(*vpp);
			*vpp = NULL;
			goto exit;
		}
		fhp = &res.array[5].nfs_resop4_u.opgetfh.object;
		if (fhp->nfs_fh4_len == 0) {
			/*
			 * The file exists but a bogus fh
			 * some unknown reason.  Remove it from the dnlc
			 * and error out to be safe.
			 */
			e.error = ENOENT;
			dnlc_remove(dvp, nm);
			VN_RELE(*vpp);
			*vpp = NULL;
			goto exit;
		}
		sfhp = sfh4_get(fhp, mi);

		if (res.array[6].nfs_resop4_u.opgetattr.status == NFS4_OK)
			garp = &res.array[6].nfs_resop4_u.opgetattr.ga_res;

		/*
		 * Make the new rnode
		 */
		if (isdotdot) {
			e.error = nfs4_make_dotdot(sfhp, t, dvp, cr, &nvp, 1);
			if (e.error) {
				sfh4_rele(&sfhp);
				VN_RELE(*vpp);
				*vpp = NULL;
				goto exit;
			}
			/*
			 * XXX if nfs4_make_dotdot uses an existing rnode
			 * XXX it doesn't update the attributes.
			 * XXX for now just save them again to save an OTW
			 */
			nfs4_attr_cache(nvp, garp, t, cr, FALSE, NULL);
		} else {
			nvp = makenfs4node(sfhp, garp, dvp->v_vfsp, t, cr,
			    dvp, fn_get(VTOSV(dvp)->sv_name, nm, sfhp));
			/*
			 * If v_type == VNON, then garp was NULL because
			 * the last op in the compound failed and makenfs4node
			 * could not find the vnode for sfhp. It created
			 * a new vnode, so we have nothing to purge here.
			 */
			if (nvp->v_type == VNON) {
				vattr_t vattr;

				vattr.va_mask = AT_TYPE;
				/*
				 * N.B. We've already called nfs4_end_fop above.
				 */
				e.error = nfs4getattr(nvp, &vattr, cr);
				if (e.error) {
					sfh4_rele(&sfhp);
					VN_RELE(*vpp);
					*vpp = NULL;
					VN_RELE(nvp);
					goto exit;
				}
				nvp->v_type = vattr.va_type;
			}
		}
		sfh4_rele(&sfhp);

		nrp = VTOR4(nvp);
		mutex_enter(&nrp->r_statev4_lock);
		if (!nrp->created_v4) {
			mutex_exit(&nrp->r_statev4_lock);
			dnlc_update(dvp, nm, nvp);
		} else
			mutex_exit(&nrp->r_statev4_lock);

		VN_RELE(*vpp);
		*vpp = nvp;
	} else {
		hrtime_t now;
		hrtime_t delta = 0;

		e.error = 0;

		/*
		 * Because the NVERIFY "succeeded" we know that the
		 * directory attributes are still valid
		 * so update r_time_attr_inval
		 */
		now = gethrtime();
		mutex_enter(&drp->r_statelock);
		if (!(mi->mi_flags & MI4_NOAC) && !(dvp->v_flag & VNOCACHE)) {
			delta = now - drp->r_time_attr_saved;
			if (delta < mi->mi_acdirmin)
				delta = mi->mi_acdirmin;
			else if (delta > mi->mi_acdirmax)
				delta = mi->mi_acdirmax;
		}
		drp->r_time_attr_inval = now + delta;
		mutex_exit(&drp->r_statelock);
		dnlc_update(dvp, nm, *vpp);

		/*
		 * Even though we have a valid directory attr cache
		 * and dnlc entry, we may not have access.
		 * This should almost always hit the cache.
		 */
		e.error = nfs4_access(dvp, VEXEC, 0, cr, NULL);
		if (e.error) {
			VN_RELE(*vpp);
			*vpp = NULL;
		}

		if (*vpp == DNLC_NO_VNODE) {
			VN_RELE(*vpp);
			*vpp = NULL;
			e.error = ENOENT;
		}
	}

exit:
	(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
	kmem_free(argop, argoplist_size);
	(void) check_mnt_secinfo(mi->mi_curr_serv, nvp);
	return (e.error);
}

/*
 * We need to go over the wire to lookup the name, but
 * while we are there verify the directory has not
 * changed but if it has, get new attributes and check access
 *
 * PUTFH dfh SAVEFH LOOKUP nm GETFH GETATTR RESTOREFH
 *					NVERIFY GETATTR ACCESS
 *
 * With the results:
 *	if the NVERIFY failed we must purge the caches, add new attributes,
 *		and cache new access.
 *	set a new r_time_attr_inval
 *	add name to dnlc, possibly negative
 *	if LOOKUP succeeded
 *		cache new attributes
 */
static int
nfs4lookupnew_otw(vnode_t *dvp, char *nm, vnode_t **vpp, cred_t *cr)
{
	COMPOUND4args_clnt args;
	COMPOUND4res_clnt res;
	fattr4 *ver_fattr;
	fattr4_change dchange;
	int32_t *ptr;
	nfs4_ga_res_t *garp = NULL;
	int argoplist_size  = 9 * sizeof (nfs_argop4);
	nfs_argop4 *argop;
	int doqueue;
	mntinfo4_t *mi;
	nfs4_recov_state_t recov_state;
	hrtime_t t;
	int isdotdot;
	vnode_t *nvp;
	nfs_fh4 *fhp;
	nfs4_sharedfh_t *sfhp;
	nfs4_access_type_t cacc;
	rnode4_t *nrp;
	rnode4_t *drp = VTOR4(dvp);
	nfs4_error_t e = { 0, NFS4_OK, RPC_SUCCESS };

	ASSERT(nfs_zone() == VTOMI4(dvp)->mi_zone);
	ASSERT(nm != NULL);
	ASSERT(nm[0] != '\0');
	ASSERT(dvp->v_type == VDIR);
	ASSERT(nm[0] != '.' || nm[1] != '\0');
	ASSERT(*vpp == NULL);

	if (nm[0] == '.' && nm[1] == '.' && nm[2] == '\0') {
		isdotdot = 1;
		args.ctag = TAG_LOOKUP_PARENT;
	} else {
		/*
		 * If dvp were a stub, it should have triggered and caused
		 * a mount for us to get this far.
		 */
		ASSERT(!RP_ISSTUB(VTOR4(dvp)));

		isdotdot = 0;
		args.ctag = TAG_LOOKUP;
	}

	mi = VTOMI4(dvp);
	recov_state.rs_flags = 0;
	recov_state.rs_num_retry_despite_err = 0;

	nvp = NULL;

	/* Save the original mount point security information */
	(void) save_mnt_secinfo(mi->mi_curr_serv);

recov_retry:
	e.error = nfs4_start_fop(mi, dvp, NULL, OH_LOOKUP,
	    &recov_state, NULL);
	if (e.error) {
		(void) check_mnt_secinfo(mi->mi_curr_serv, nvp);
		return (e.error);
	}

	argop = kmem_alloc(argoplist_size, KM_SLEEP);

	/* PUTFH SAVEFH LOOKUP GETFH GETATTR RESTOREFH NVERIFY GETATTR ACCESS */
	args.array_len = 9;
	args.array = argop;

	/* 0. putfh file */
	argop[0].argop = OP_CPUTFH;
	argop[0].nfs_argop4_u.opcputfh.sfh = VTOR4(dvp)->r_fh;

	/* 1. savefh for the nverify */
	argop[1].argop = OP_SAVEFH;

	/* 2. lookup name */
	if (isdotdot) {
		argop[2].argop = OP_LOOKUPP;
	} else {
		argop[2].argop = OP_CLOOKUP;
		argop[2].nfs_argop4_u.opclookup.cname = nm;
	}

	/* 3. resulting file handle */
	argop[3].argop = OP_GETFH;

	/* 4. resulting file attributes */
	argop[4].argop = OP_GETATTR;
	argop[4].nfs_argop4_u.opgetattr.attr_request = NFS4_VATTR_MASK;
	argop[4].nfs_argop4_u.opgetattr.mi = VTOMI4(dvp);

	/* 5. restorefh back the directory for the nverify */
	argop[5].argop = OP_RESTOREFH;

	/* 6. nverify the change info */
	argop[6].argop = OP_NVERIFY;
	ver_fattr = &argop[6].nfs_argop4_u.opnverify.obj_attributes;
	ver_fattr->attrmask = FATTR4_CHANGE_MASK;
	ver_fattr->attrlist4 = (char *)&dchange;
	ptr = (int32_t *)&dchange;
	IXDR_PUT_HYPER(ptr, VTOR4(dvp)->r_change);
	ver_fattr->attrlist4_len = sizeof (fattr4_change);

	/* 7. getattr directory */
	argop[7].argop = OP_GETATTR;
	argop[7].nfs_argop4_u.opgetattr.attr_request = NFS4_VATTR_MASK;
	argop[7].nfs_argop4_u.opgetattr.mi = VTOMI4(dvp);

	/* 8. access directory */
	argop[8].argop = OP_ACCESS;
	argop[8].nfs_argop4_u.opaccess.access = ACCESS4_READ | ACCESS4_DELETE |
	    ACCESS4_MODIFY | ACCESS4_EXTEND | ACCESS4_LOOKUP;

	doqueue = 1;
	t = gethrtime();

	rfs4call(VTOMI4(dvp), &args, &res, cr, &doqueue, 0, &e);

	if (!isdotdot && res.status == NFS4ERR_MOVED) {
		e.error = nfs4_setup_referral(dvp, nm, vpp, cr);
		if (e.error != 0 && *vpp != NULL)
			VN_RELE(*vpp);
		nfs4_end_fop(mi, dvp, NULL, OH_LOOKUP,
		    &recov_state, FALSE);
		(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
		kmem_free(argop, argoplist_size);
		return (e.error);
	}

	if (nfs4_needs_recovery(&e, FALSE, dvp->v_vfsp)) {
		/*
		 * For WRONGSEC of a non-dotdot case, send secinfo directly
		 * from this thread, do not go thru the recovery thread since
		 * we need the nm information.
		 *
		 * Not doing dotdot case because there is no specification
		 * for (PUTFH, SECINFO "..") yet.
		 */
		if (!isdotdot && res.status == NFS4ERR_WRONGSEC) {
			if ((e.error = nfs4_secinfo_vnode_otw(dvp, nm, cr)))
				nfs4_end_fop(mi, dvp, NULL, OH_LOOKUP,
				    &recov_state, FALSE);
			else
				nfs4_end_fop(mi, dvp, NULL, OH_LOOKUP,
				    &recov_state, TRUE);
			(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
			kmem_free(argop, argoplist_size);
			if (!e.error)
				goto recov_retry;
			(void) check_mnt_secinfo(mi->mi_curr_serv, nvp);
			return (e.error);
		}

		if (nfs4_start_recovery(&e, mi, dvp, NULL, NULL, NULL,
		    OP_LOOKUP, NULL, NULL, NULL) == FALSE) {
			nfs4_end_fop(mi, dvp, NULL, OH_LOOKUP,
			    &recov_state, TRUE);

			(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
			kmem_free(argop, argoplist_size);
			goto recov_retry;
		}
	}

	nfs4_end_fop(mi, dvp, NULL, OH_LOOKUP, &recov_state, FALSE);

	if (e.error || res.array_len == 0) {
		/*
		 * If e.error isn't set, then reply has no ops (or we couldn't
		 * be here).  The only legal way to reply without an op array
		 * is via NFS4ERR_MINOR_VERS_MISMATCH.  An ops array should
		 * be in the reply for all other status values.
		 *
		 * For valid replies without an ops array, return ENOTSUP
		 * (geterrno4 xlation of VERS_MISMATCH).  For illegal replies,
		 * return EIO -- don't trust status.
		 */
		if (e.error == 0)
			e.error = (res.status == NFS4ERR_MINOR_VERS_MISMATCH) ?
			    ENOTSUP : EIO;

		kmem_free(argop, argoplist_size);
		(void) check_mnt_secinfo(mi->mi_curr_serv, nvp);
		return (e.error);
	}

	e.error = geterrno4(res.status);

	/*
	 * The PUTFH and SAVEFH may have failed.
	 */
	if ((res.array[0].nfs_resop4_u.opputfh.status != NFS4_OK) ||
	    (res.array[1].nfs_resop4_u.opsavefh.status != NFS4_OK)) {
		nfs4_purge_stale_fh(e.error, dvp, cr);
		goto exit;
	}

	/*
	 * Check if the file exists, if it does delay entering
	 * into the dnlc until after we update the directory
	 * attributes so we don't cause it to get purged immediately.
	 */
	if (res.array[2].nfs_resop4_u.oplookup.status != NFS4_OK) {
		/*
		 * The lookup failed, probably no entry
		 */
		if (e.error == ENOENT && nfs4_lookup_neg_cache)
			dnlc_update(dvp, nm, DNLC_NO_VNODE);
		goto exit;
	}

	if (res.array[3].nfs_resop4_u.opgetfh.status != NFS4_OK) {
		/*
		 * The file exists but we can't get its fh for
		 * some unknown reason. Error out to be safe.
		 */
		goto exit;
	}

	fhp = &res.array[3].nfs_resop4_u.opgetfh.object;
	if (fhp->nfs_fh4_len == 0) {
		/*
		 * The file exists but a bogus fh
		 * some unknown reason.  Error out to be safe.
		 */
		e.error = EIO;
		goto exit;
	}
	sfhp = sfh4_get(fhp, mi);

	if (res.array[4].nfs_resop4_u.opgetattr.status != NFS4_OK) {
		sfh4_rele(&sfhp);
		goto exit;
	}
	garp = &res.array[4].nfs_resop4_u.opgetattr.ga_res;

	/*
	 * The RESTOREFH may have failed
	 */
	if (res.array[5].nfs_resop4_u.oprestorefh.status != NFS4_OK) {
		sfh4_rele(&sfhp);
		e.error = EIO;
		goto exit;
	}

	if (res.array[6].nfs_resop4_u.opnverify.status != NFS4ERR_SAME) {
		/*
		 * First make sure the NVERIFY failed as we expected,
		 * if it didn't then be conservative and error out
		 * as we can't trust the directory.
		 */
		if (res.array[6].nfs_resop4_u.opnverify.status != NFS4_OK) {
			sfh4_rele(&sfhp);
			e.error = EIO;
			goto exit;
		}

		/*
		 * We know the NVERIFY "failed" so the directory has changed,
		 * so we must:
		 *	purge the caches (access and indirectly dnlc if needed)
		 */
		nfs4_purge_caches(dvp, NFS4_NOPURGE_DNLC, cr, TRUE);

		if (res.array[7].nfs_resop4_u.opgetattr.status != NFS4_OK) {
			sfh4_rele(&sfhp);
			goto exit;
		}
		nfs4_attr_cache(dvp,
		    &res.array[7].nfs_resop4_u.opgetattr.ga_res,
		    t, cr, FALSE, NULL);

		if (res.array[8].nfs_resop4_u.opaccess.status != NFS4_OK) {
			nfs4_purge_stale_fh(e.error, dvp, cr);
			sfh4_rele(&sfhp);
			e.error = geterrno4(res.status);
			goto exit;
		}

		/*
		 * Now we know the directory is valid,
		 * cache new directory access
		 */
		nfs4_access_cache(drp,
		    args.array[8].nfs_argop4_u.opaccess.access,
		    res.array[8].nfs_resop4_u.opaccess.access, cr);

		/*
		 * recheck VEXEC access
		 */
		cacc = nfs4_access_check(drp, ACCESS4_LOOKUP, cr);
		if (cacc != NFS4_ACCESS_ALLOWED) {
			/*
			 * Directory permissions might have been revoked
			 */
			if (cacc == NFS4_ACCESS_DENIED) {
				sfh4_rele(&sfhp);
				e.error = EACCES;
				goto exit;
			}

			/*
			 * Somehow we must not have asked for enough
			 * so try a singleton ACCESS should never happen
			 */
			e.error = nfs4_access(dvp, VEXEC, 0, cr, NULL);
			if (e.error) {
				sfh4_rele(&sfhp);
				goto exit;
			}
		}

		e.error = geterrno4(res.status);
	} else {
		hrtime_t now;
		hrtime_t delta = 0;

		e.error = 0;

		/*
		 * Because the NVERIFY "succeeded" we know that the
		 * directory attributes are still valid
		 * so update r_time_attr_inval
		 */
		now = gethrtime();
		mutex_enter(&drp->r_statelock);
		if (!(mi->mi_flags & MI4_NOAC) && !(dvp->v_flag & VNOCACHE)) {
			delta = now - drp->r_time_attr_saved;
			if (delta < mi->mi_acdirmin)
				delta = mi->mi_acdirmin;
			else if (delta > mi->mi_acdirmax)
				delta = mi->mi_acdirmax;
		}
		drp->r_time_attr_inval = now + delta;
		mutex_exit(&drp->r_statelock);

		/*
		 * Even though we have a valid directory attr cache,
		 * we may not have access.
		 * This should almost always hit the cache.
		 */
		e.error = nfs4_access(dvp, VEXEC, 0, cr, NULL);
		if (e.error) {
			sfh4_rele(&sfhp);
			goto exit;
		}
	}

	/*
	 * Now we have successfully completed the lookup, if the
	 * directory has changed we now have the valid attributes.
	 * We also know we have directory access.
	 * Create the new rnode and insert it in the dnlc.
	 */
	if (isdotdot) {
		e.error = nfs4_make_dotdot(sfhp, t, dvp, cr, &nvp, 1);
		if (e.error) {
			sfh4_rele(&sfhp);
			goto exit;
		}
		/*
		 * XXX if nfs4_make_dotdot uses an existing rnode
		 * XXX it doesn't update the attributes.
		 * XXX for now just save them again to save an OTW
		 */
		nfs4_attr_cache(nvp, garp, t, cr, FALSE, NULL);
	} else {
		nvp = makenfs4node(sfhp, garp, dvp->v_vfsp, t, cr,
		    dvp, fn_get(VTOSV(dvp)->sv_name, nm, sfhp));
	}
	sfh4_rele(&sfhp);

	nrp = VTOR4(nvp);
	mutex_enter(&nrp->r_statev4_lock);
	if (!nrp->created_v4) {
		mutex_exit(&nrp->r_statev4_lock);
		dnlc_update(dvp, nm, nvp);
	} else
		mutex_exit(&nrp->r_statev4_lock);

	*vpp = nvp;

exit:
	(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
	kmem_free(argop, argoplist_size);
	(void) check_mnt_secinfo(mi->mi_curr_serv, nvp);
	return (e.error);
}

#ifdef DEBUG
void
nfs4lookup_dump_compound(char *where, nfs_argop4 *argbase, int argcnt)
{
	uint_t i, len;
	zoneid_t zoneid = getzoneid();
	char *s;

	zcmn_err(zoneid, CE_NOTE, "%s: dumping cmpd", where);
	for (i = 0; i < argcnt; i++) {
		nfs_argop4 *op = &argbase[i];
		switch (op->argop) {
		case OP_CPUTFH:
		case OP_PUTFH:
			zcmn_err(zoneid, CE_NOTE, "\t op %d, putfh", i);
			break;
		case OP_PUTROOTFH:
			zcmn_err(zoneid, CE_NOTE, "\t op %d, putrootfh", i);
			break;
		case OP_CLOOKUP:
			s = op->nfs_argop4_u.opclookup.cname;
			zcmn_err(zoneid, CE_NOTE, "\t op %d, lookup %s", i, s);
			break;
		case OP_LOOKUP:
			s = utf8_to_str(&op->nfs_argop4_u.oplookup.objname,
			    &len, NULL);
			zcmn_err(zoneid, CE_NOTE, "\t op %d, lookup %s", i, s);
			kmem_free(s, len);
			break;
		case OP_LOOKUPP:
			zcmn_err(zoneid, CE_NOTE, "\t op %d, lookupp ..", i);
			break;
		case OP_GETFH:
			zcmn_err(zoneid, CE_NOTE, "\t op %d, getfh", i);
			break;
		case OP_GETATTR:
			zcmn_err(zoneid, CE_NOTE, "\t op %d, getattr", i);
			break;
		case OP_OPENATTR:
			zcmn_err(zoneid, CE_NOTE, "\t op %d, openattr", i);
			break;
		default:
			zcmn_err(zoneid, CE_NOTE, "\t op %d, opcode %d", i,
			    op->argop);
			break;
		}
	}
}
#endif

/*
 * nfs4lookup_setup - constructs a multi-lookup compound request.
 *
 * Given the path "nm1/nm2/.../nmn", the following compound requests
 * may be created:
 *
 * Note: Getfh is not be needed because filehandle attr is mandatory, but it
 * is faster, for now.
 *
 * l4_getattrs indicates the type of compound requested.
 *
 * LKP4_NO_ATTRIBUTE - no attributes (used by secinfo):
 *
 *	compound { Put*fh; Lookup {nm1}; Lookup {nm2}; ...  Lookup {nmn} }
 *
 *   total number of ops is n + 1.
 *
 * LKP4_LAST_NAMED_ATTR - multi-component path for a named
 *      attribute: create lookups plus one OPENATTR/GETFH/GETATTR
 *      before the last component, and only get attributes
 *      for the last component.  Note that the second-to-last
 *	pathname component is XATTR_RPATH, which does NOT go
 *	over-the-wire as a lookup.
 *
 *      compound { Put*fh; Lookup {nm1}; Lookup {nm2}; ... Lookup {nmn-2};
 *		Openattr; Getfh; Getattr; Lookup {nmn}; Getfh; Getattr }
 *
 *   and total number of ops is n + 5.
 *
 * LKP4_LAST_ATTRDIR - multi-component path for the hidden named
 *      attribute directory: create lookups plus an OPENATTR
 *	replacing the last lookup.  Note that the last pathname
 *	component is XATTR_RPATH, which does NOT go over-the-wire
 *	as a lookup.
 *
 *      compound { Put*fh; Lookup {nm1}; Lookup {nm2}; ... Getfh; Getattr;
 *		Openattr; Getfh; Getattr }
 *
 *   and total number of ops is n + 5.
 *
 * LKP4_ALL_ATTRIBUTES - create lookups and get attributes for intermediate
 *	nodes too.
 *
 *	compound { Put*fh; Lookup {nm1}; Getfh; Getattr;
 *		Lookup {nm2}; ...  Lookup {nmn}; Getfh; Getattr }
 *
 *   and total number of ops is 3*n + 1.
 *
 * All cases: returns the index in the arg array of the final LOOKUP op, or
 * -1 if no LOOKUPs were used.
 */
int
nfs4lookup_setup(char *nm, lookup4_param_t *lookupargp, int needgetfh)
{
	enum lkp4_attr_setup l4_getattrs = lookupargp->l4_getattrs;
	nfs_argop4 *argbase, *argop;
	int arglen, argcnt;
	int n = 1;	/* number of components */
	int nga = 1;	/* number of Getattr's in request */
	char c = '\0', *s, *p;
	int lookup_idx = -1;
	int argoplist_size;

	/* set lookuparg response result to 0 */
	lookupargp->resp->status = NFS4_OK;

	/* skip leading "/" or "." e.g. ".//./" if there is */
	for (; ; nm++) {
		if (*nm != '/' && *nm != '.')
			break;

		/* ".." is counted as 1 component */
		if (*nm == '.' && *(nm + 1) != '/')
			break;
	}

	/*
	 * Find n = number of components - nm must be null terminated
	 * Skip "." components.
	 */
	if (*nm != '\0')
		for (n = 1, s = nm; *s != '\0'; s++) {
			if ((*s == '/') && (*(s + 1) != '/') &&
			    (*(s + 1) != '\0') &&
			    !(*(s + 1) == '.' && (*(s + 2) == '/' ||
			    *(s + 2) == '\0')))
				n++;
		}
	else
		n = 0;

	/*
	 * nga is number of components that need Getfh+Getattr
	 */
	switch (l4_getattrs) {
	case LKP4_NO_ATTRIBUTES:
		nga = 0;
		break;
	case LKP4_ALL_ATTRIBUTES:
		nga = n;
		/*
		 * Always have at least 1 getfh, getattr pair
		 */
		if (nga == 0)
			nga++;
		break;
	case LKP4_LAST_ATTRDIR:
	case LKP4_LAST_NAMED_ATTR:
		nga = n+1;
		break;
	}

	/*
	 * If change to use the filehandle attr instead of getfh
	 * the following line can be deleted.
	 */
	nga *= 2;

	/*
	 * calculate number of ops in request as
	 * header + trailer + lookups + getattrs
	 */
	arglen = lookupargp->header_len + lookupargp->trailer_len + n + nga;

	argoplist_size = arglen * sizeof (nfs_argop4);
	argop = argbase = kmem_alloc(argoplist_size, KM_SLEEP);
	lookupargp->argsp->array = argop;

	argcnt = lookupargp->header_len;
	argop += argcnt;

	/*
	 * loop and create a lookup op and possibly getattr/getfh for
	 * each component. Skip "." components.
	 */
	for (s = nm; *s != '\0'; s = p) {
		/*
		 * Set up a pathname struct for each component if needed
		 */
		while (*s == '/')
			s++;
		if (*s == '\0')
			break;

		for (p = s; (*p != '/') && (*p != '\0'); p++)
			;
		c = *p;
		*p = '\0';

		if (s[0] == '.' && s[1] == '\0') {
			*p = c;
			continue;
		}
		if (l4_getattrs == LKP4_LAST_ATTRDIR &&
		    strcmp(s, XATTR_RPATH) == 0) {
			/* getfh XXX may not be needed in future */
			argop->argop = OP_GETFH;
			argop++;
			argcnt++;

			/* getattr */
			argop->argop = OP_GETATTR;
			argop->nfs_argop4_u.opgetattr.attr_request =
			    lookupargp->ga_bits;
			argop->nfs_argop4_u.opgetattr.mi =
			    lookupargp->mi;
			argop++;
			argcnt++;

			/* openattr */
			argop->argop = OP_OPENATTR;
		} else if (l4_getattrs == LKP4_LAST_NAMED_ATTR &&
		    strcmp(s, XATTR_RPATH) == 0) {
			/* openattr */
			argop->argop = OP_OPENATTR;
			argop++;
			argcnt++;

			/* getfh XXX may not be needed in future */
			argop->argop = OP_GETFH;
			argop++;
			argcnt++;

			/* getattr */
			argop->argop = OP_GETATTR;
			argop->nfs_argop4_u.opgetattr.attr_request =
			    lookupargp->ga_bits;
			argop->nfs_argop4_u.opgetattr.mi =
			    lookupargp->mi;
			argop++;
			argcnt++;
			*p = c;
			continue;
		} else if (s[0] == '.' && s[1] == '.' && s[2] == '\0') {
			/* lookupp */
			argop->argop = OP_LOOKUPP;
		} else {
			/* lookup */
			argop->argop = OP_LOOKUP;
			(void) str_to_utf8(s,
			    &argop->nfs_argop4_u.oplookup.objname);
		}
		lookup_idx = argcnt;
		argop++;
		argcnt++;

		*p = c;

		if (l4_getattrs == LKP4_ALL_ATTRIBUTES) {
			/* getfh XXX may not be needed in future */
			argop->argop = OP_GETFH;
			argop++;
			argcnt++;

			/* getattr */
			argop->argop = OP_GETATTR;
			argop->nfs_argop4_u.opgetattr.attr_request =
			    lookupargp->ga_bits;
			argop->nfs_argop4_u.opgetattr.mi =
			    lookupargp->mi;
			argop++;
			argcnt++;
		}
	}

	if ((l4_getattrs != LKP4_NO_ATTRIBUTES) &&
	    ((l4_getattrs != LKP4_ALL_ATTRIBUTES) || (lookup_idx < 0))) {
		if (needgetfh) {
			/* stick in a post-lookup getfh */
			argop->argop = OP_GETFH;
			argcnt++;
			argop++;
		}
		/* post-lookup getattr */
		argop->argop = OP_GETATTR;
		argop->nfs_argop4_u.opgetattr.attr_request =
		    lookupargp->ga_bits;
		argop->nfs_argop4_u.opgetattr.mi = lookupargp->mi;
		argcnt++;
	}
	argcnt += lookupargp->trailer_len;	/* actual op count */
	lookupargp->argsp->array_len = argcnt;
	lookupargp->arglen = arglen;

#ifdef DEBUG
	if (nfs4_client_lookup_debug)
		nfs4lookup_dump_compound("nfs4lookup_setup", argbase, argcnt);
#endif

	return (lookup_idx);
}

static int
nfs4openattr(vnode_t *dvp, vnode_t **avp, int cflag, cred_t *cr)
{
	COMPOUND4args_clnt	args;
	COMPOUND4res_clnt	res;
	GETFH4res	*gf_res = NULL;
	nfs_argop4	argop[4];
	nfs_resop4	*resop = NULL;
	nfs4_sharedfh_t *sfhp;
	hrtime_t t;
	nfs4_error_t	e;

	rnode4_t	*drp;
	int		doqueue = 1;
	vnode_t		*vp;
	int		needrecov = 0;
	nfs4_recov_state_t recov_state;

	ASSERT(nfs_zone() == VTOMI4(dvp)->mi_zone);

	*avp = NULL;
	recov_state.rs_flags = 0;
	recov_state.rs_num_retry_despite_err = 0;

recov_retry:
	/* COMPOUND: putfh, openattr, getfh, getattr */
	args.array_len = 4;
	args.array = argop;
	args.ctag = TAG_OPENATTR;

	e.error = nfs4_start_op(VTOMI4(dvp), dvp, NULL, &recov_state);
	if (e.error)
		return (e.error);

	drp = VTOR4(dvp);

	/* putfh */
	argop[0].argop = OP_CPUTFH;
	argop[0].nfs_argop4_u.opcputfh.sfh = drp->r_fh;

	/* openattr */
	argop[1].argop = OP_OPENATTR;
	argop[1].nfs_argop4_u.opopenattr.createdir = (cflag ? TRUE : FALSE);

	/* getfh */
	argop[2].argop = OP_GETFH;

	/* getattr */
	argop[3].argop = OP_GETATTR;
	argop[3].nfs_argop4_u.opgetattr.attr_request = NFS4_VATTR_MASK;
	argop[3].nfs_argop4_u.opgetattr.mi = VTOMI4(dvp);

	NFS4_DEBUG(nfs4_client_call_debug, (CE_NOTE,
	    "nfs4openattr: %s call, drp %s", needrecov ? "recov" : "first",
	    rnode4info(drp)));

	t = gethrtime();

	rfs4call(VTOMI4(dvp), &args, &res, cr, &doqueue, 0, &e);

	needrecov = nfs4_needs_recovery(&e, FALSE, dvp->v_vfsp);
	if (needrecov) {
		bool_t abort;

		NFS4_DEBUG(nfs4_client_recov_debug, (CE_NOTE,
		    "nfs4openattr: initiating recovery\n"));

		abort = nfs4_start_recovery(&e,
		    VTOMI4(dvp), dvp, NULL, NULL, NULL,
		    OP_OPENATTR, NULL, NULL, NULL);
		nfs4_end_op(VTOMI4(dvp), dvp, NULL, &recov_state, needrecov);
		if (!e.error) {
			e.error = geterrno4(res.status);
			(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
		}
		if (abort == FALSE)
			goto recov_retry;
		return (e.error);
	}

	if (e.error) {
		nfs4_end_op(VTOMI4(dvp), dvp, NULL, &recov_state, needrecov);
		return (e.error);
	}

	if (res.status) {
		/*
		 * If OTW errro is NOTSUPP, then it should be
		 * translated to EINVAL.  All Solaris file system
		 * implementations return EINVAL to the syscall layer
		 * when the attrdir cannot be created due to an
		 * implementation restriction or noxattr mount option.
		 */
		if (res.status == NFS4ERR_NOTSUPP) {
			mutex_enter(&drp->r_statelock);
			if (drp->r_xattr_dir)
				VN_RELE(drp->r_xattr_dir);
			VN_HOLD(NFS4_XATTR_DIR_NOTSUPP);
			drp->r_xattr_dir = NFS4_XATTR_DIR_NOTSUPP;
			mutex_exit(&drp->r_statelock);

			e.error = EINVAL;
		} else {
			e.error = geterrno4(res.status);
		}

		if (e.error) {
			(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
			nfs4_end_op(VTOMI4(dvp), dvp, NULL, &recov_state,
			    needrecov);
			return (e.error);
		}
	}

	resop = &res.array[0];  /* putfh res */
	ASSERT(resop->nfs_resop4_u.opgetfh.status == NFS4_OK);

	resop = &res.array[1];  /* openattr res */
	ASSERT(resop->nfs_resop4_u.opopenattr.status == NFS4_OK);

	resop = &res.array[2];  /* getfh res */
	gf_res = &resop->nfs_resop4_u.opgetfh;
	if (gf_res->object.nfs_fh4_len == 0) {
		*avp = NULL;
		(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
		nfs4_end_op(VTOMI4(dvp), dvp, NULL, &recov_state, needrecov);
		return (ENOENT);
	}

	sfhp = sfh4_get(&gf_res->object, VTOMI4(dvp));
	vp = makenfs4node(sfhp, &res.array[3].nfs_resop4_u.opgetattr.ga_res,
	    dvp->v_vfsp, t, cr, dvp,
	    fn_get(VTOSV(dvp)->sv_name, XATTR_RPATH, sfhp));
	sfh4_rele(&sfhp);

	if (e.error)
		PURGE_ATTRCACHE4(vp);

	mutex_enter(&vp->v_lock);
	vp->v_flag |= V_XATTRDIR;
	mutex_exit(&vp->v_lock);

	*avp = vp;

	mutex_enter(&drp->r_statelock);
	if (drp->r_xattr_dir)
		VN_RELE(drp->r_xattr_dir);
	VN_HOLD(vp);
	drp->r_xattr_dir = vp;

	/*
	 * Invalidate pathconf4 cache because r_xattr_dir is no longer
	 * NULL.  xattrs could be created at any time, and we have no
	 * way to update pc4_xattr_exists in the base object if/when
	 * it happens.
	 */
	drp->r_pathconf.pc4_xattr_valid = 0;

	mutex_exit(&drp->r_statelock);

	nfs4_end_op(VTOMI4(dvp), dvp, NULL, &recov_state, needrecov);

	(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);

	return (0);
}

/* ARGSUSED */
static int
nfs4_create(vnode_t *dvp, char *nm, struct vattr *va, enum vcexcl exclusive,
	int mode, vnode_t **vpp, cred_t *cr, int flags, caller_context_t *ct,
	vsecattr_t *vsecp)
{
	int error;
	vnode_t *vp = NULL;
	rnode4_t *rp;
	struct vattr vattr;
	rnode4_t *drp;
	vnode_t *tempvp;
	enum createmode4 createmode;
	bool_t must_trunc = FALSE;
	int	truncating = 0;

	if (nfs_zone() != VTOMI4(dvp)->mi_zone)
		return (EPERM);
	if (exclusive == EXCL && (dvp->v_flag & V_XATTRDIR)) {
		return (EINVAL);
	}

	/* . and .. have special meaning in the protocol, reject them. */

	if (nm[0] == '.' && (nm[1] == '\0' || (nm[1] == '.' && nm[2] == '\0')))
		return (EISDIR);

	drp = VTOR4(dvp);

	if (nfs_rw_enter_sig(&drp->r_rwlock, RW_WRITER, INTR4(dvp)))
		return (EINTR);

top:
	/*
	 * We make a copy of the attributes because the caller does not
	 * expect us to change what va points to.
	 */
	vattr = *va;

	/*
	 * If the pathname is "", then dvp is the root vnode of
	 * a remote file mounted over a local directory.
	 * All that needs to be done is access
	 * checking and truncation.  Note that we avoid doing
	 * open w/ create because the parent directory might
	 * be in pseudo-fs and the open would fail.
	 */
	if (*nm == '\0') {
		error = 0;
		VN_HOLD(dvp);
		vp = dvp;
		must_trunc = TRUE;
	} else {
		/*
		 * We need to go over the wire, just to be sure whether the
		 * file exists or not.  Using the DNLC can be dangerous in
		 * this case when making a decision regarding existence.
		 */
		error = nfs4lookup(dvp, nm, &vp, cr, 1);
	}

	if (exclusive)
		createmode = EXCLUSIVE4;
	else
		createmode = GUARDED4;

	/*
	 * error would be set if the file does not exist on the
	 * server, so lets go create it.
	 */
	if (error) {
		goto create_otw;
	}

	/*
	 * File does exist on the server
	 */
	if (exclusive == EXCL)
		error = EEXIST;
	else if (vp->v_type == VDIR && (mode & VWRITE))
		error = EISDIR;
	else {
		/*
		 * If vnode is a device, create special vnode.
		 */
		if (ISVDEV(vp->v_type)) {
			tempvp = vp;
			vp = specvp(vp, vp->v_rdev, vp->v_type, cr);
			VN_RELE(tempvp);
		}
		if (!(error = VOP_ACCESS(vp, mode, 0, cr, ct))) {
			if ((vattr.va_mask & AT_SIZE) &&
			    vp->v_type == VREG) {
				rp = VTOR4(vp);
				/*
				 * Check here for large file handled
				 * by LF-unaware process (as
				 * ufs_create() does)
				 */
				if (!(flags & FOFFMAX)) {
					mutex_enter(&rp->r_statelock);
					if (rp->r_size > MAXOFF32_T)
						error = EOVERFLOW;
					mutex_exit(&rp->r_statelock);
				}

				/* if error is set then we need to return */
				if (error) {
					nfs_rw_exit(&drp->r_rwlock);
					VN_RELE(vp);
					return (error);
				}

				if (must_trunc) {
					vattr.va_mask = AT_SIZE;
					error = nfs4setattr(vp, &vattr, 0, cr,
					    NULL);
				} else {
				/*
				 * we know we have a regular file that already
				 * exists and we may end up truncating the file
				 * as a result of the open_otw, so flush out
				 * any dirty pages for this file first.
				 */
					if (nfs4_has_pages(vp) &&
					    ((rp->r_flags & R4DIRTY) ||
					    rp->r_count > 0 ||
					    rp->r_mapcnt > 0)) {
						error = nfs4_putpage(vp,
						    (offset_t)0, 0, 0, cr, ct);
						if (error && (error == ENOSPC ||
						    error == EDQUOT)) {
							mutex_enter(
							    &rp->r_statelock);
							if (!rp->r_error)
								rp->r_error =
								    error;
							mutex_exit(
							    &rp->r_statelock);
						}
					}
					vattr.va_mask = (AT_SIZE |
					    AT_TYPE | AT_MODE);
					vattr.va_type = VREG;
					createmode = UNCHECKED4;
					truncating = 1;
					goto create_otw;
				}
			}
		}
	}
	nfs_rw_exit(&drp->r_rwlock);
	if (error) {
		VN_RELE(vp);
	} else {
		vnode_t *tvp;
		rnode4_t *trp;
		tvp = vp;
		if (vp->v_type == VREG) {
			trp = VTOR4(vp);
			if (IS_SHADOW(vp, trp))
				tvp = RTOV4(trp);
		}

		if (must_trunc) {
			/*
			 * existing file got truncated, notify.
			 */
			vnevent_create(tvp, ct);
		}

		*vpp = vp;
	}
	return (error);

create_otw:
	dnlc_remove(dvp, nm);

	ASSERT(vattr.va_mask & AT_TYPE);

	/*
	 * If not a regular file let nfs4mknod() handle it.
	 */
	if (vattr.va_type != VREG) {
		error = nfs4mknod(dvp, nm, &vattr, exclusive, mode, vpp, cr);
		nfs_rw_exit(&drp->r_rwlock);
		return (error);
	}

	/*
	 * It _is_ a regular file.
	 */
	ASSERT(vattr.va_mask & AT_MODE);
	if (MANDMODE(vattr.va_mode)) {
		nfs_rw_exit(&drp->r_rwlock);
		return (EACCES);
	}

	/*
	 * If this happens to be a mknod of a regular file, then flags will
	 * have neither FREAD or FWRITE.  However, we must set at least one
	 * for the call to nfs4open_otw.  If it's open(O_CREAT) driving
	 * nfs4_create, then either FREAD, FWRITE, or FRDWR has already been
	 * set (based on openmode specified by app).
	 */
	if ((flags & (FREAD|FWRITE)) == 0)
		flags |= (FREAD|FWRITE);

	error = nfs4open_otw(dvp, nm, &vattr, vpp, cr, 1, flags, createmode, 0);

	if (vp != NULL) {
		/* if create was successful, throw away the file's pages */
		if (!error && (vattr.va_mask & AT_SIZE))
			nfs4_invalidate_pages(vp, (vattr.va_size & PAGEMASK),
			    cr);
		/* release the lookup hold */
		VN_RELE(vp);
		vp = NULL;
	}

	/*
	 * validate that we opened a regular file. This handles a misbehaving
	 * server that returns an incorrect FH.
	 */
	if ((error == 0) && *vpp && (*vpp)->v_type != VREG) {
		error = EISDIR;
		VN_RELE(*vpp);
	}

	/*
	 * If this is not an exclusive create, then the CREATE
	 * request will be made with the GUARDED mode set.  This
	 * means that the server will return EEXIST if the file
	 * exists.  The file could exist because of a retransmitted
	 * request.  In this case, we recover by starting over and
	 * checking to see whether the file exists.  This second
	 * time through it should and a CREATE request will not be
	 * sent.
	 *
	 * This handles the problem of a dangling CREATE request
	 * which contains attributes which indicate that the file
	 * should be truncated.  This retransmitted request could
	 * possibly truncate valid data in the file if not caught
	 * by the duplicate request mechanism on the server or if
	 * not caught by other means.  The scenario is:
	 *
	 * Client transmits CREATE request with size = 0
	 * Client times out, retransmits request.
	 * Response to the first request arrives from the server
	 *  and the client proceeds on.
	 * Client writes data to the file.
	 * The server now processes retransmitted CREATE request
	 *  and truncates file.
	 *
	 * The use of the GUARDED CREATE request prevents this from
	 * happening because the retransmitted CREATE would fail
	 * with EEXIST and would not truncate the file.
	 */
	if (error == EEXIST && exclusive == NONEXCL) {
#ifdef DEBUG
		nfs4_create_misses++;
#endif
		goto top;
	}
	nfs_rw_exit(&drp->r_rwlock);
	if (truncating && !error && *vpp) {
		vnode_t *tvp;
		rnode4_t *trp;
		/*
		 * existing file got truncated, notify.
		 */
		tvp = *vpp;
		trp = VTOR4(tvp);
		if (IS_SHADOW(tvp, trp))
			tvp = RTOV4(trp);
		vnevent_create(tvp, ct);
	}
	return (error);
}

/*
 * Create compound (for mkdir, mknod, symlink):
 * { Putfh <dfh>; Create; Getfh; Getattr }
 * It's okay if setattr failed to set gid - this is not considered
 * an error, but purge attrs in that case.
 */
static int
call_nfs4_create_req(vnode_t *dvp, char *nm, void *data, struct vattr *va,
    vnode_t **vpp, cred_t *cr, nfs_ftype4 type)
{
	int need_end_op = FALSE;
	COMPOUND4args_clnt args;
	COMPOUND4res_clnt res, *resp = NULL;
	nfs_argop4 *argop;
	nfs_resop4 *resop;
	int doqueue;
	mntinfo4_t *mi;
	rnode4_t *drp = VTOR4(dvp);
	change_info4 *cinfo;
	GETFH4res *gf_res;
	struct vattr vattr;
	vnode_t *vp;
	fattr4 *crattr;
	bool_t needrecov = FALSE;
	nfs4_recov_state_t recov_state;
	nfs4_sharedfh_t *sfhp = NULL;
	hrtime_t t;
	nfs4_error_t e = { 0, NFS4_OK, RPC_SUCCESS };
	int numops, argoplist_size, setgid_flag, idx_create, idx_fattr;
	dirattr_info_t dinfo, *dinfop;
	servinfo4_t *svp;
	bitmap4 supp_attrs;

	ASSERT(type == NF4DIR || type == NF4LNK || type == NF4BLK ||
	    type == NF4CHR || type == NF4SOCK || type == NF4FIFO);

	mi = VTOMI4(dvp);

	/*
	 * Make sure we properly deal with setting the right gid
	 * on a new directory to reflect the parent's setgid bit
	 */
	setgid_flag = 0;
	if (type == NF4DIR) {
		struct vattr dva;

		va->va_mode &= ~VSGID;
		dva.va_mask = AT_MODE | AT_GID;
		if (VOP_GETATTR(dvp, &dva, 0, cr, NULL) == 0) {

			/*
			 * If the parent's directory has the setgid bit set
			 * _and_ the client was able to get a valid mapping
			 * for the parent dir's owner_group, we want to
			 * append NVERIFY(owner_group == dva.va_gid) and
			 * SETTATTR to the CREATE compound.
			 */
			if (mi->mi_flags & MI4_GRPID || dva.va_mode & VSGID) {
				setgid_flag = 1;
				va->va_mode |= VSGID;
				if (dva.va_gid != GID_NOBODY) {
					va->va_mask |= AT_GID;
					va->va_gid = dva.va_gid;
				}
			}
		}
	}

	/*
	 * Create ops:
	 *	0:putfh(dir) 1:savefh(dir) 2:create 3:getfh(new) 4:getattr(new)
	 *	5:restorefh(dir) 6:getattr(dir)
	 *
	 * if (setgid)
	 *	0:putfh(dir) 1:create 2:getfh(new) 3:getattr(new)
	 *	4:savefh(new) 5:putfh(dir) 6:getattr(dir) 7:restorefh(new)
	 *	8:nverify 9:setattr
	 */
	if (setgid_flag) {
		numops = 10;
		idx_create = 1;
		idx_fattr = 3;
	} else {
		numops = 7;
		idx_create = 2;
		idx_fattr = 4;
	}

	ASSERT(nfs_zone() == mi->mi_zone);
	if (nfs_rw_enter_sig(&drp->r_rwlock, RW_WRITER, INTR4(dvp))) {
		return (EINTR);
	}
	recov_state.rs_flags = 0;
	recov_state.rs_num_retry_despite_err = 0;

	argoplist_size = numops * sizeof (nfs_argop4);
	argop = kmem_alloc(argoplist_size, KM_SLEEP);

recov_retry:
	if (type == NF4LNK)
		args.ctag = TAG_SYMLINK;
	else if (type == NF4DIR)
		args.ctag = TAG_MKDIR;
	else
		args.ctag = TAG_MKNOD;

	args.array_len = numops;
	args.array = argop;

	if (e.error = nfs4_start_op(mi, dvp, NULL, &recov_state)) {
		nfs_rw_exit(&drp->r_rwlock);
		kmem_free(argop, argoplist_size);
		return (e.error);
	}
	need_end_op = TRUE;


	/* 0: putfh directory */
	argop[0].argop = OP_CPUTFH;
	argop[0].nfs_argop4_u.opcputfh.sfh = drp->r_fh;

	/* 1/2: Create object */
	argop[idx_create].argop = OP_CCREATE;
	argop[idx_create].nfs_argop4_u.opccreate.cname = nm;
	argop[idx_create].nfs_argop4_u.opccreate.type = type;
	if (type == NF4LNK) {
		/*
		 * symlink, treat name as data
		 */
		ASSERT(data != NULL);
		argop[idx_create].nfs_argop4_u.opccreate.ftype4_u.clinkdata =
		    (char *)data;
	}
	if (type == NF4BLK || type == NF4CHR) {
		ASSERT(data != NULL);
		argop[idx_create].nfs_argop4_u.opccreate.ftype4_u.devdata =
		    *((specdata4 *)data);
	}

	crattr = &argop[idx_create].nfs_argop4_u.opccreate.createattrs;

	svp = drp->r_server;
	(void) nfs_rw_enter_sig(&svp->sv_lock, RW_READER, 0);
	supp_attrs = svp->sv_supp_attrs;
	nfs_rw_exit(&svp->sv_lock);

	if (vattr_to_fattr4(va, NULL, crattr, 0, OP_CREATE, supp_attrs)) {
		nfs_rw_exit(&drp->r_rwlock);
		nfs4_end_op(mi, dvp, NULL, &recov_state, needrecov);
		e.error = EINVAL;
		kmem_free(argop, argoplist_size);
		return (e.error);
	}

	/* 2/3: getfh fh of created object */
	ASSERT(idx_create + 1 == idx_fattr - 1);
	argop[idx_create + 1].argop = OP_GETFH;

	/* 3/4: getattr of new object */
	argop[idx_fattr].argop = OP_GETATTR;
	argop[idx_fattr].nfs_argop4_u.opgetattr.attr_request = NFS4_VATTR_MASK;
	argop[idx_fattr].nfs_argop4_u.opgetattr.mi = mi;

	if (setgid_flag) {
		vattr_t	_v;

		argop[4].argop = OP_SAVEFH;

		argop[5].argop = OP_CPUTFH;
		argop[5].nfs_argop4_u.opcputfh.sfh = drp->r_fh;

		argop[6].argop = OP_GETATTR;
		argop[6].nfs_argop4_u.opgetattr.attr_request = NFS4_VATTR_MASK;
		argop[6].nfs_argop4_u.opgetattr.mi = mi;

		argop[7].argop = OP_RESTOREFH;

		/*
		 * nverify
		 *
		 * XXX - Revisit the last argument to nfs4_end_op()
		 *	 once 5020486 is fixed.
		 */
		_v.va_mask = AT_GID;
		_v.va_gid = va->va_gid;
		if (e.error = nfs4args_verify(&argop[8], &_v, OP_NVERIFY,
		    supp_attrs)) {
			nfs4_end_op(mi, dvp, *vpp, &recov_state, TRUE);
			nfs_rw_exit(&drp->r_rwlock);
			nfs4_fattr4_free(crattr);
			kmem_free(argop, argoplist_size);
			return (e.error);
		}

		/*
		 * setattr
		 *
		 * We _know_ we're not messing with AT_SIZE or AT_XTIME,
		 * so no need for stateid or flags. Also we specify NULL
		 * rp since we're only interested in setting owner_group
		 * attributes.
		 */
		nfs4args_setattr(&argop[9], &_v, NULL, 0, NULL, cr, supp_attrs,
		    &e.error, 0);

		if (e.error) {
			nfs4_end_op(mi, dvp, *vpp, &recov_state, TRUE);
			nfs_rw_exit(&drp->r_rwlock);
			nfs4_fattr4_free(crattr);
			nfs4args_verify_free(&argop[8]);
			kmem_free(argop, argoplist_size);
			return (e.error);
		}
	} else {
		argop[1].argop = OP_SAVEFH;

		argop[5].argop = OP_RESTOREFH;

		argop[6].argop = OP_GETATTR;
		argop[6].nfs_argop4_u.opgetattr.attr_request = NFS4_VATTR_MASK;
		argop[6].nfs_argop4_u.opgetattr.mi = mi;
	}

	dnlc_remove(dvp, nm);

	doqueue = 1;
	t = gethrtime();
	rfs4call(mi, &args, &res, cr, &doqueue, 0, &e);

	needrecov = nfs4_needs_recovery(&e, FALSE, mi->mi_vfsp);
	if (e.error) {
		PURGE_ATTRCACHE4(dvp);
		if (!needrecov)
			goto out;
	}

	if (needrecov) {
		if (nfs4_start_recovery(&e, mi, dvp, NULL, NULL, NULL,
		    OP_CREATE, NULL, NULL, NULL) == FALSE) {
			nfs4_end_op(mi, dvp, NULL, &recov_state,
			    needrecov);
			need_end_op = FALSE;
			nfs4_fattr4_free(crattr);
			if (setgid_flag) {
				nfs4args_verify_free(&argop[8]);
				nfs4args_setattr_free(&argop[9]);
			}
			(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
			goto recov_retry;
		}
	}

	resp = &res;

	if (res.status != NFS4_OK && res.array_len <= idx_fattr + 1) {

		if (res.status == NFS4ERR_BADOWNER)
			nfs4_log_badowner(mi, OP_CREATE);

		e.error = geterrno4(res.status);

		/*
		 * This check is left over from when create was implemented
		 * using a setattr op (instead of createattrs).  If the
		 * putfh/create/getfh failed, the error was returned.  If
		 * setattr/getattr failed, we keep going.
		 *
		 * It might be better to get rid of the GETFH also, and just
		 * do PUTFH/CREATE/GETATTR since the FH attr is mandatory.
		 * Then if any of the operations failed, we could return the
		 * error now, and remove much of the error code below.
		 */
		if (res.array_len <= idx_fattr) {
			/*
			 * Either Putfh, Create or Getfh failed.
			 */
			PURGE_ATTRCACHE4(dvp);
			/*
			 * nfs4_purge_stale_fh() may generate otw calls through
			 * nfs4_invalidate_pages. Hence the need to call
			 * nfs4_end_op() here to avoid nfs4_start_op() deadlock.
			 */
			nfs4_end_op(mi, dvp, NULL, &recov_state,
			    needrecov);
			need_end_op = FALSE;
			nfs4_purge_stale_fh(e.error, dvp, cr);
			goto out;
		}
	}

	resop = &res.array[idx_create];	/* create res */
	cinfo = &resop->nfs_resop4_u.opcreate.cinfo;

	resop = &res.array[idx_create + 1]; /* getfh res */
	gf_res = &resop->nfs_resop4_u.opgetfh;

	sfhp = sfh4_get(&gf_res->object, mi);
	if (e.error) {
		*vpp = vp = makenfs4node(sfhp, NULL, dvp->v_vfsp, t, cr, dvp,
		    fn_get(VTOSV(dvp)->sv_name, nm, sfhp));
		if (vp->v_type == VNON) {
			vattr.va_mask = AT_TYPE;
			/*
			 * Need to call nfs4_end_op before nfs4getattr to avoid
			 * potential nfs4_start_op deadlock. See RFE 4777612.
			 */
			nfs4_end_op(mi, dvp, NULL, &recov_state,
			    needrecov);
			need_end_op = FALSE;
			e.error = nfs4getattr(vp, &vattr, cr);
			if (e.error) {
				VN_RELE(vp);
				*vpp = NULL;
				goto out;
			}
			vp->v_type = vattr.va_type;
		}
		e.error = 0;
	} else {
		*vpp = vp = makenfs4node(sfhp,
		    &res.array[idx_fattr].nfs_resop4_u.opgetattr.ga_res,
		    dvp->v_vfsp, t, cr,
		    dvp, fn_get(VTOSV(dvp)->sv_name, nm, sfhp));
	}

	/*
	 * If compound succeeded, then update dir attrs
	 */
	if (res.status == NFS4_OK) {
		dinfo.di_garp = &res.array[6].nfs_resop4_u.opgetattr.ga_res;
		dinfo.di_cred = cr;
		dinfo.di_time_call = t;
		dinfop = &dinfo;
	} else
		dinfop = NULL;

	/* Update directory cache attribute, readdir and dnlc caches */
	nfs4_update_dircaches(cinfo, dvp, vp, nm, dinfop);

out:
	if (sfhp != NULL)
		sfh4_rele(&sfhp);
	nfs_rw_exit(&drp->r_rwlock);
	nfs4_fattr4_free(crattr);
	if (setgid_flag) {
		nfs4args_verify_free(&argop[8]);
		nfs4args_setattr_free(&argop[9]);
	}
	if (resp)
		(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)resp);
	if (need_end_op)
		nfs4_end_op(mi, dvp, NULL, &recov_state, needrecov);

	kmem_free(argop, argoplist_size);
	return (e.error);
}

/* ARGSUSED */
static int
nfs4mknod(vnode_t *dvp, char *nm, struct vattr *va, enum vcexcl exclusive,
    int mode, vnode_t **vpp, cred_t *cr)
{
	int error;
	vnode_t *vp;
	nfs_ftype4 type;
	specdata4 spec, *specp = NULL;

	ASSERT(nfs_zone() == VTOMI4(dvp)->mi_zone);

	switch (va->va_type) {
	case VCHR:
	case VBLK:
		type = (va->va_type == VCHR) ? NF4CHR : NF4BLK;
		spec.specdata1 = getmajor(va->va_rdev);
		spec.specdata2 = getminor(va->va_rdev);
		specp = &spec;
		break;

	case VFIFO:
		type = NF4FIFO;
		break;
	case VSOCK:
		type = NF4SOCK;
		break;

	default:
		return (EINVAL);
	}

	error = call_nfs4_create_req(dvp, nm, specp, va, &vp, cr, type);
	if (error) {
		return (error);
	}

	/*
	 * This might not be needed any more; special case to deal
	 * with problematic v2/v3 servers.  Since create was unable
	 * to set group correctly, not sure what hope setattr has.
	 */
	if (va->va_gid != VTOR4(vp)->r_attr.va_gid) {
		va->va_mask = AT_GID;
		(void) nfs4setattr(vp, va, 0, cr, NULL);
	}

	/*
	 * If vnode is a device create special vnode
	 */
	if (ISVDEV(vp->v_type)) {
		*vpp = specvp(vp, vp->v_rdev, vp->v_type, cr);
		VN_RELE(vp);
	} else {
		*vpp = vp;
	}
	return (error);
}

/*
 * Remove requires that the current fh be the target directory.
 * After the operation, the current fh is unchanged.
 * The compound op structure is:
 *      PUTFH(targetdir), REMOVE
 *
 * Weirdness: if the vnode to be removed is open
 * we rename it instead of removing it and nfs_inactive
 * will remove the new name.
 */
/* ARGSUSED */
static int
nfs4_remove(vnode_t *dvp, char *nm, cred_t *cr, caller_context_t *ct, int flags)
{
	COMPOUND4args_clnt args;
	COMPOUND4res_clnt res, *resp = NULL;
	REMOVE4res *rm_res;
	nfs_argop4 argop[3];
	nfs_resop4 *resop;
	vnode_t *vp;
	char *tmpname;
	int doqueue;
	mntinfo4_t *mi;
	rnode4_t *rp;
	rnode4_t *drp;
	int needrecov = 0;
	nfs4_recov_state_t recov_state;
	int isopen;
	nfs4_error_t e = { 0, NFS4_OK, RPC_SUCCESS };
	dirattr_info_t dinfo;

	if (nfs_zone() != VTOMI4(dvp)->mi_zone)
		return (EPERM);
	drp = VTOR4(dvp);
	if (nfs_rw_enter_sig(&drp->r_rwlock, RW_WRITER, INTR4(dvp)))
		return (EINTR);

	e.error = nfs4lookup(dvp, nm, &vp, cr, 0);
	if (e.error) {
		nfs_rw_exit(&drp->r_rwlock);
		return (e.error);
	}

	if (vp->v_type == VDIR) {
		VN_RELE(vp);
		nfs_rw_exit(&drp->r_rwlock);
		return (EISDIR);
	}

	/*
	 * First just remove the entry from the name cache, as it
	 * is most likely the only entry for this vp.
	 */
	dnlc_remove(dvp, nm);

	rp = VTOR4(vp);

	/*
	 * For regular file types, check to see if the file is open by looking
	 * at the open streams.
	 * For all other types, check the reference count on the vnode.  Since
	 * they are not opened OTW they never have an open stream.
	 *
	 * If the file is open, rename it to .nfsXXXX.
	 */
	if (vp->v_type != VREG) {
		/*
		 * If the file has a v_count > 1 then there may be more than one
		 * entry in the name cache due multiple links or an open file,
		 * but we don't have the real reference count so flush all
		 * possible entries.
		 */
		if (vp->v_count > 1)
			dnlc_purge_vp(vp);

		/*
		 * Now we have the real reference count.
		 */
		isopen = vp->v_count > 1;
	} else {
		mutex_enter(&rp->r_os_lock);
		isopen = list_head(&rp->r_open_streams) != NULL;
		mutex_exit(&rp->r_os_lock);
	}

	mutex_enter(&rp->r_statelock);
	if (isopen &&
	    (rp->r_unldvp == NULL || strcmp(nm, rp->r_unlname) == 0)) {
		mutex_exit(&rp->r_statelock);
		tmpname = newname();
		e.error = nfs4rename(dvp, nm, dvp, tmpname, cr, ct);
		if (e.error)
			kmem_free(tmpname, MAXNAMELEN);
		else {
			mutex_enter(&rp->r_statelock);
			if (rp->r_unldvp == NULL) {
				VN_HOLD(dvp);
				rp->r_unldvp = dvp;
				if (rp->r_unlcred != NULL)
					crfree(rp->r_unlcred);
				crhold(cr);
				rp->r_unlcred = cr;
				rp->r_unlname = tmpname;
			} else {
				kmem_free(rp->r_unlname, MAXNAMELEN);
				rp->r_unlname = tmpname;
			}
			mutex_exit(&rp->r_statelock);
		}
		VN_RELE(vp);
		nfs_rw_exit(&drp->r_rwlock);
		return (e.error);
	}
	/*
	 * Actually remove the file/dir
	 */
	mutex_exit(&rp->r_statelock);

	/*
	 * We need to flush any dirty pages which happen to
	 * be hanging around before removing the file.
	 * This shouldn't happen very often since in NFSv4
	 * we should be close to open consistent.
	 */
	if (nfs4_has_pages(vp) &&
	    ((rp->r_flags & R4DIRTY) || rp->r_count > 0)) {
		e.error = nfs4_putpage(vp, (u_offset_t)0, 0, 0, cr, ct);
		if (e.error && (e.error == ENOSPC || e.error == EDQUOT)) {
			mutex_enter(&rp->r_statelock);
			if (!rp->r_error)
				rp->r_error = e.error;
			mutex_exit(&rp->r_statelock);
		}
	}

	mi = VTOMI4(dvp);

	(void) nfs4delegreturn(rp, NFS4_DR_REOPEN);
	recov_state.rs_flags = 0;
	recov_state.rs_num_retry_despite_err = 0;

recov_retry:
	/*
	 * Remove ops: putfh dir; remove
	 */
	args.ctag = TAG_REMOVE;
	args.array_len = 3;
	args.array = argop;

	e.error = nfs4_start_op(VTOMI4(dvp), dvp, NULL, &recov_state);
	if (e.error) {
		nfs_rw_exit(&drp->r_rwlock);
		VN_RELE(vp);
		return (e.error);
	}

	/* putfh directory */
	argop[0].argop = OP_CPUTFH;
	argop[0].nfs_argop4_u.opcputfh.sfh = drp->r_fh;

	/* remove */
	argop[1].argop = OP_CREMOVE;
	argop[1].nfs_argop4_u.opcremove.ctarget = nm;

	/* getattr dir */
	argop[2].argop = OP_GETATTR;
	argop[2].nfs_argop4_u.opgetattr.attr_request = NFS4_VATTR_MASK;
	argop[2].nfs_argop4_u.opgetattr.mi = mi;

	doqueue = 1;
	dinfo.di_time_call = gethrtime();
	rfs4call(mi, &args, &res, cr, &doqueue, 0, &e);

	PURGE_ATTRCACHE4(vp);

	needrecov = nfs4_needs_recovery(&e, FALSE, mi->mi_vfsp);
	if (e.error)
		PURGE_ATTRCACHE4(dvp);

	if (needrecov) {
		if (nfs4_start_recovery(&e, VTOMI4(dvp), dvp,
		    NULL, NULL, NULL, OP_REMOVE, NULL, NULL, NULL) == FALSE) {
			if (!e.error)
				(void) xdr_free(xdr_COMPOUND4res_clnt,
				    (caddr_t)&res);
			nfs4_end_op(VTOMI4(dvp), dvp, NULL, &recov_state,
			    needrecov);
			goto recov_retry;
		}
	}

	/*
	 * Matching nfs4_end_op() for start_op() above.
	 * There is a path in the code below which calls
	 * nfs4_purge_stale_fh(), which may generate otw calls through
	 * nfs4_invalidate_pages. Hence we need to call nfs4_end_op()
	 * here to avoid nfs4_start_op() deadlock.
	 */
	nfs4_end_op(VTOMI4(dvp), dvp, NULL, &recov_state, needrecov);

	if (!e.error) {
		resp = &res;

		if (res.status) {
			e.error = geterrno4(res.status);
			PURGE_ATTRCACHE4(dvp);
			nfs4_purge_stale_fh(e.error, dvp, cr);
		} else {
			resop = &res.array[1];	/* remove res */
			rm_res = &resop->nfs_resop4_u.opremove;

			dinfo.di_garp =
			    &res.array[2].nfs_resop4_u.opgetattr.ga_res;
			dinfo.di_cred = cr;

			/* Update directory attr, readdir and dnlc caches */
			nfs4_update_dircaches(&rm_res->cinfo, dvp, NULL, NULL,
			    &dinfo);
		}
	}
	nfs_rw_exit(&drp->r_rwlock);
	if (resp)
		(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)resp);

	if (e.error == 0) {
		vnode_t *tvp;
		rnode4_t *trp;
		trp = VTOR4(vp);
		tvp = vp;
		if (IS_SHADOW(vp, trp))
			tvp = RTOV4(trp);
		vnevent_remove(tvp, dvp, nm, ct);
	}
	VN_RELE(vp);
	return (e.error);
}

/*
 * Link requires that the current fh be the target directory and the
 * saved fh be the source fh. After the operation, the current fh is unchanged.
 * Thus the compound op structure is:
 *	PUTFH(file), SAVEFH, PUTFH(targetdir), LINK, RESTOREFH,
 *	GETATTR(file)
 */
/* ARGSUSED */
static int
nfs4_link(vnode_t *tdvp, vnode_t *svp, char *tnm, cred_t *cr,
    caller_context_t *ct, int flags)
{
	COMPOUND4args_clnt args;
	COMPOUND4res_clnt res, *resp = NULL;
	LINK4res *ln_res;
	int argoplist_size  = 7 * sizeof (nfs_argop4);
	nfs_argop4 *argop;
	nfs_resop4 *resop;
	vnode_t *realvp, *nvp;
	int doqueue;
	mntinfo4_t *mi;
	rnode4_t *tdrp;
	bool_t needrecov = FALSE;
	nfs4_recov_state_t recov_state;
	hrtime_t t;
	nfs4_error_t e = { 0, NFS4_OK, RPC_SUCCESS };
	dirattr_info_t dinfo;

	ASSERT(*tnm != '\0');
	ASSERT(tdvp->v_type == VDIR);
	ASSERT(nfs4_consistent_type(tdvp));
	ASSERT(nfs4_consistent_type(svp));

	if (nfs_zone() != VTOMI4(tdvp)->mi_zone)
		return (EPERM);
	if (VOP_REALVP(svp, &realvp, ct) == 0) {
		svp = realvp;
		ASSERT(nfs4_consistent_type(svp));
	}

	tdrp = VTOR4(tdvp);
	mi = VTOMI4(svp);

	if (!(mi->mi_flags & MI4_LINK)) {
		return (EOPNOTSUPP);
	}
	recov_state.rs_flags = 0;
	recov_state.rs_num_retry_despite_err = 0;

	if (nfs_rw_enter_sig(&tdrp->r_rwlock, RW_WRITER, INTR4(tdvp)))
		return (EINTR);

recov_retry:
	argop = kmem_alloc(argoplist_size, KM_SLEEP);

	args.ctag = TAG_LINK;

	/*
	 * Link ops: putfh fl; savefh; putfh tdir; link; getattr(dir);
	 * restorefh; getattr(fl)
	 */
	args.array_len = 7;
	args.array = argop;

	e.error = nfs4_start_op(VTOMI4(svp), svp, tdvp, &recov_state);
	if (e.error) {
		kmem_free(argop, argoplist_size);
		nfs_rw_exit(&tdrp->r_rwlock);
		return (e.error);
	}

	/* 0. putfh file */
	argop[0].argop = OP_CPUTFH;
	argop[0].nfs_argop4_u.opcputfh.sfh = VTOR4(svp)->r_fh;

	/* 1. save current fh to free up the space for the dir */
	argop[1].argop = OP_SAVEFH;

	/* 2. putfh targetdir */
	argop[2].argop = OP_CPUTFH;
	argop[2].nfs_argop4_u.opcputfh.sfh = tdrp->r_fh;

	/* 3. link: current_fh is targetdir, saved_fh is source */
	argop[3].argop = OP_CLINK;
	argop[3].nfs_argop4_u.opclink.cnewname = tnm;

	/* 4. Get attributes of dir */
	argop[4].argop = OP_GETATTR;
	argop[4].nfs_argop4_u.opgetattr.attr_request = NFS4_VATTR_MASK;
	argop[4].nfs_argop4_u.opgetattr.mi = mi;

	/* 5. If link was successful, restore current vp to file */
	argop[5].argop = OP_RESTOREFH;

	/* 6. Get attributes of linked object */
	argop[6].argop = OP_GETATTR;
	argop[6].nfs_argop4_u.opgetattr.attr_request = NFS4_VATTR_MASK;
	argop[6].nfs_argop4_u.opgetattr.mi = mi;

	dnlc_remove(tdvp, tnm);

	doqueue = 1;
	t = gethrtime();

	rfs4call(VTOMI4(svp), &args, &res, cr, &doqueue, 0, &e);

	needrecov = nfs4_needs_recovery(&e, FALSE, svp->v_vfsp);
	if (e.error != 0 && !needrecov) {
		PURGE_ATTRCACHE4(tdvp);
		PURGE_ATTRCACHE4(svp);
		nfs4_end_op(VTOMI4(svp), svp, tdvp, &recov_state, needrecov);
		goto out;
	}

	if (needrecov) {
		bool_t abort;

		abort = nfs4_start_recovery(&e, VTOMI4(svp), svp, tdvp,
		    NULL, NULL, OP_LINK, NULL, NULL, NULL);
		if (abort == FALSE) {
			nfs4_end_op(VTOMI4(svp), svp, tdvp, &recov_state,
			    needrecov);
			kmem_free(argop, argoplist_size);
			if (!e.error)
				(void) xdr_free(xdr_COMPOUND4res_clnt,
				    (caddr_t)&res);
			goto recov_retry;
		} else {
			if (e.error != 0) {
				PURGE_ATTRCACHE4(tdvp);
				PURGE_ATTRCACHE4(svp);
				nfs4_end_op(VTOMI4(svp), svp, tdvp,
				    &recov_state, needrecov);
				goto out;
			}
			/* fall through for res.status case */
		}
	}

	nfs4_end_op(VTOMI4(svp), svp, tdvp, &recov_state, needrecov);

	resp = &res;
	if (res.status) {
		/* If link succeeded, then don't return error */
		e.error = geterrno4(res.status);
		if (res.array_len <= 4) {
			/*
			 * Either Putfh, Savefh, Putfh dir, or Link failed
			 */
			PURGE_ATTRCACHE4(svp);
			PURGE_ATTRCACHE4(tdvp);
			if (e.error == EOPNOTSUPP) {
				mutex_enter(&mi->mi_lock);
				mi->mi_flags &= ~MI4_LINK;
				mutex_exit(&mi->mi_lock);
			}
			/* Remap EISDIR to EPERM for non-root user for SVVS */
			/* XXX-LP */
			if (e.error == EISDIR && crgetuid(cr) != 0)
				e.error = EPERM;
			goto out;
		}
	}

	/* either no error or one of the postop getattr failed */

	/*
	 * XXX - if LINK succeeded, but no attrs were returned for link
	 * file, purge its cache.
	 *
	 * XXX Perform a simplified version of wcc checking. Instead of
	 * have another getattr to get pre-op, just purge cache if
	 * any of the ops prior to and including the getattr failed.
	 * If the getattr succeeded then update the attrcache accordingly.
	 */

	/*
	 * update cache with link file postattrs.
	 * Note: at this point resop points to link res.
	 */
	resop = &res.array[3];	/* link res */
	ln_res = &resop->nfs_resop4_u.oplink;
	if (res.status == NFS4_OK)
		e.error = nfs4_update_attrcache(res.status,
		    &res.array[6].nfs_resop4_u.opgetattr.ga_res,
		    t, svp, cr);

	/*
	 * Call makenfs4node to create the new shadow vp for tnm.
	 * We pass NULL attrs because we just cached attrs for
	 * the src object.  All we're trying to accomplish is to
	 * to create the new shadow vnode.
	 */
	nvp = makenfs4node(VTOR4(svp)->r_fh, NULL, tdvp->v_vfsp, t, cr,
	    tdvp, fn_get(VTOSV(tdvp)->sv_name, tnm, VTOR4(svp)->r_fh));

	/* Update target cache attribute, readdir and dnlc caches */
	dinfo.di_garp = &res.array[4].nfs_resop4_u.opgetattr.ga_res;
	dinfo.di_time_call = t;
	dinfo.di_cred = cr;

	nfs4_update_dircaches(&ln_res->cinfo, tdvp, nvp, tnm, &dinfo);
	ASSERT(nfs4_consistent_type(tdvp));
	ASSERT(nfs4_consistent_type(svp));
	ASSERT(nfs4_consistent_type(nvp));
	VN_RELE(nvp);

	if (!e.error) {
		vnode_t *tvp;
		rnode4_t *trp;
		/*
		 * Notify the source file of this link operation.
		 */
		trp = VTOR4(svp);
		tvp = svp;
		if (IS_SHADOW(svp, trp))
			tvp = RTOV4(trp);
		vnevent_link(tvp, ct);
	}
out:
	kmem_free(argop, argoplist_size);
	if (resp)
		(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)resp);

	nfs_rw_exit(&tdrp->r_rwlock);

	return (e.error);
}

/* ARGSUSED */
static int
nfs4_rename(vnode_t *odvp, char *onm, vnode_t *ndvp, char *nnm, cred_t *cr,
    caller_context_t *ct, int flags)
{
	vnode_t *realvp;

	if (nfs_zone() != VTOMI4(odvp)->mi_zone)
		return (EPERM);
	if (VOP_REALVP(ndvp, &realvp, ct) == 0)
		ndvp = realvp;

	return (nfs4rename(odvp, onm, ndvp, nnm, cr, ct));
}

/*
 * nfs4rename does the real work of renaming in NFS Version 4.
 *
 * A file handle is considered volatile for renaming purposes if either
 * of the volatile bits are turned on. However, the compound may differ
 * based on the likelihood of the filehandle to change during rename.
 */
static int
nfs4rename(vnode_t *odvp, char *onm, vnode_t *ndvp, char *nnm, cred_t *cr,
    caller_context_t *ct)
{
	int error;
	mntinfo4_t *mi;
	vnode_t *nvp = NULL;
	vnode_t *ovp = NULL;
	char *tmpname = NULL;
	rnode4_t *rp;
	rnode4_t *odrp;
	rnode4_t *ndrp;
	int did_link = 0;
	int do_link = 1;
	nfsstat4 stat = NFS4_OK;

	ASSERT(nfs_zone() == VTOMI4(odvp)->mi_zone);
	ASSERT(nfs4_consistent_type(odvp));
	ASSERT(nfs4_consistent_type(ndvp));

	if (onm[0] == '.' && (onm[1] == '\0' ||
	    (onm[1] == '.' && onm[2] == '\0')))
		return (EINVAL);

	if (nnm[0] == '.' && (nnm[1] == '\0' ||
	    (nnm[1] == '.' && nnm[2] == '\0')))
		return (EINVAL);

	odrp = VTOR4(odvp);
	ndrp = VTOR4(ndvp);
	if ((intptr_t)odrp < (intptr_t)ndrp) {
		if (nfs_rw_enter_sig(&odrp->r_rwlock, RW_WRITER, INTR4(odvp)))
			return (EINTR);
		if (nfs_rw_enter_sig(&ndrp->r_rwlock, RW_WRITER, INTR4(ndvp))) {
			nfs_rw_exit(&odrp->r_rwlock);
			return (EINTR);
		}
	} else {
		if (nfs_rw_enter_sig(&ndrp->r_rwlock, RW_WRITER, INTR4(ndvp)))
			return (EINTR);
		if (nfs_rw_enter_sig(&odrp->r_rwlock, RW_WRITER, INTR4(odvp))) {
			nfs_rw_exit(&ndrp->r_rwlock);
			return (EINTR);
		}
	}

	/*
	 * Lookup the target file.  If it exists, it needs to be
	 * checked to see whether it is a mount point and whether
	 * it is active (open).
	 */
	error = nfs4lookup(ndvp, nnm, &nvp, cr, 0);
	if (!error) {
		int	isactive;

		ASSERT(nfs4_consistent_type(nvp));
		/*
		 * If this file has been mounted on, then just
		 * return busy because renaming to it would remove
		 * the mounted file system from the name space.
		 */
		if (vn_ismntpt(nvp)) {
			VN_RELE(nvp);
			nfs_rw_exit(&odrp->r_rwlock);
			nfs_rw_exit(&ndrp->r_rwlock);
			return (EBUSY);
		}

		/*
		 * First just remove the entry from the name cache, as it
		 * is most likely the only entry for this vp.
		 */
		dnlc_remove(ndvp, nnm);

		rp = VTOR4(nvp);

		if (nvp->v_type != VREG) {
			/*
			 * Purge the name cache of all references to this vnode
			 * so that we can check the reference count to infer
			 * whether it is active or not.
			 */
			if (nvp->v_count > 1)
				dnlc_purge_vp(nvp);

			isactive = nvp->v_count > 1;
		} else {
			mutex_enter(&rp->r_os_lock);
			isactive = list_head(&rp->r_open_streams) != NULL;
			mutex_exit(&rp->r_os_lock);
		}

		/*
		 * If the vnode is active and is not a directory,
		 * arrange to rename it to a
		 * temporary file so that it will continue to be
		 * accessible.  This implements the "unlink-open-file"
		 * semantics for the target of a rename operation.
		 * Before doing this though, make sure that the
		 * source and target files are not already the same.
		 */
		if (isactive && nvp->v_type != VDIR) {
			/*
			 * Lookup the source name.
			 */
			error = nfs4lookup(odvp, onm, &ovp, cr, 0);

			/*
			 * The source name *should* already exist.
			 */
			if (error) {
				VN_RELE(nvp);
				nfs_rw_exit(&odrp->r_rwlock);
				nfs_rw_exit(&ndrp->r_rwlock);
				return (error);
			}

			ASSERT(nfs4_consistent_type(ovp));

			/*
			 * Compare the two vnodes.  If they are the same,
			 * just release all held vnodes and return success.
			 */
			if (VN_CMP(ovp, nvp)) {
				VN_RELE(ovp);
				VN_RELE(nvp);
				nfs_rw_exit(&odrp->r_rwlock);
				nfs_rw_exit(&ndrp->r_rwlock);
				return (0);
			}

			/*
			 * Can't mix and match directories and non-
			 * directories in rename operations.  We already
			 * know that the target is not a directory.  If
			 * the source is a directory, return an error.
			 */
			if (ovp->v_type == VDIR) {
				VN_RELE(ovp);
				VN_RELE(nvp);
				nfs_rw_exit(&odrp->r_rwlock);
				nfs_rw_exit(&ndrp->r_rwlock);
				return (ENOTDIR);
			}
link_call:
			/*
			 * The target file exists, is not the same as
			 * the source file, and is active.  We first
			 * try to Link it to a temporary filename to
			 * avoid having the server removing the file
			 * completely (which could cause data loss to
			 * the user's POV in the event the Rename fails
			 * -- see bug 1165874).
			 */
			/*
			 * The do_link and did_link booleans are
			 * introduced in the event we get NFS4ERR_FILE_OPEN
			 * returned for the Rename.  Some servers can
			 * not Rename over an Open file, so they return
			 * this error.  The client needs to Remove the
			 * newly created Link and do two Renames, just
			 * as if the server didn't support LINK.
			 */
			tmpname = newname();
			error = 0;

			if (do_link) {
				error = nfs4_link(ndvp, nvp, tmpname, cr,
				    NULL, 0);
			}
			if (error == EOPNOTSUPP || !do_link) {
				error = nfs4_rename(ndvp, nnm, ndvp, tmpname,
				    cr, NULL, 0);
				did_link = 0;
			} else {
				did_link = 1;
			}
			if (error) {
				kmem_free(tmpname, MAXNAMELEN);
				VN_RELE(ovp);
				VN_RELE(nvp);
				nfs_rw_exit(&odrp->r_rwlock);
				nfs_rw_exit(&ndrp->r_rwlock);
				return (error);
			}

			mutex_enter(&rp->r_statelock);
			if (rp->r_unldvp == NULL) {
				VN_HOLD(ndvp);
				rp->r_unldvp = ndvp;
				if (rp->r_unlcred != NULL)
					crfree(rp->r_unlcred);
				crhold(cr);
				rp->r_unlcred = cr;
				rp->r_unlname = tmpname;
			} else {
				if (rp->r_unlname)
					kmem_free(rp->r_unlname, MAXNAMELEN);
				rp->r_unlname = tmpname;
			}
			mutex_exit(&rp->r_statelock);
		}

		(void) nfs4delegreturn(VTOR4(nvp), NFS4_DR_PUSH|NFS4_DR_REOPEN);

		ASSERT(nfs4_consistent_type(nvp));
	}

	if (ovp == NULL) {
		/*
		 * When renaming directories to be a subdirectory of a
		 * different parent, the dnlc entry for ".." will no
		 * longer be valid, so it must be removed.
		 *
		 * We do a lookup here to determine whether we are renaming
		 * a directory and we need to check if we are renaming
		 * an unlinked file.  This might have already been done
		 * in previous code, so we check ovp == NULL to avoid
		 * doing it twice.
		 */
		error = nfs4lookup(odvp, onm, &ovp, cr, 0);
		/*
		 * The source name *should* already exist.
		 */
		if (error) {
			nfs_rw_exit(&odrp->r_rwlock);
			nfs_rw_exit(&ndrp->r_rwlock);
			if (nvp) {
				VN_RELE(nvp);
			}
			return (error);
		}
		ASSERT(ovp != NULL);
		ASSERT(nfs4_consistent_type(ovp));
	}

	/*
	 * Is the object being renamed a dir, and if so, is
	 * it being renamed to a child of itself?  The underlying
	 * fs should ultimately return EINVAL for this case;
	 * however, buggy beta non-Solaris NFSv4 servers at
	 * interop testing events have allowed this behavior,
	 * and it caused our client to panic due to a recursive
	 * mutex_enter in fn_move.
	 *
	 * The tedious locking in fn_move could be changed to
	 * deal with this case, and the client could avoid the
	 * panic; however, the client would just confuse itself
	 * later and misbehave.  A better way to handle the broken
	 * server is to detect this condition and return EINVAL
	 * without ever sending the the bogus rename to the server.
	 * We know the rename is invalid -- just fail it now.
	 */
	if (ovp->v_type == VDIR && VN_CMP(ndvp, ovp)) {
		VN_RELE(ovp);
		nfs_rw_exit(&odrp->r_rwlock);
		nfs_rw_exit(&ndrp->r_rwlock);
		if (nvp) {
			VN_RELE(nvp);
		}
		return (EINVAL);
	}

	(void) nfs4delegreturn(VTOR4(ovp), NFS4_DR_PUSH|NFS4_DR_REOPEN);

	/*
	 * If FH4_VOL_RENAME or FH4_VOLATILE_ANY bits are set, it is
	 * possible for the filehandle to change due to the rename.
	 * If neither of these bits is set, but FH4_VOL_MIGRATION is set,
	 * the fh will not change because of the rename, but we still need
	 * to update its rnode entry with the new name for
	 * an eventual fh change due to migration. The FH4_NOEXPIRE_ON_OPEN
	 * has no effect on these for now, but for future improvements,
	 * we might want to use it too to simplify handling of files
	 * that are open with that flag on. (XXX)
	 */
	mi = VTOMI4(odvp);
	if (NFS4_VOLATILE_FH(mi))
		error = nfs4rename_volatile_fh(odvp, onm, ovp, ndvp, nnm, cr,
		    &stat);
	else
		error = nfs4rename_persistent_fh(odvp, onm, ovp, ndvp, nnm, cr,
		    &stat);

	ASSERT(nfs4_consistent_type(odvp));
	ASSERT(nfs4_consistent_type(ndvp));
	ASSERT(nfs4_consistent_type(ovp));

	if (stat == NFS4ERR_FILE_OPEN && did_link) {
		do_link = 0;
		/*
		 * Before the 'link_call' code, we did a nfs4_lookup
		 * that puts a VN_HOLD on nvp.  After the nfs4_link
		 * call we call VN_RELE to match that hold.  We need
		 * to place an additional VN_HOLD here since we will
		 * be hitting that VN_RELE again.
		 */
		VN_HOLD(nvp);

		(void) nfs4_remove(ndvp, tmpname, cr, NULL, 0);

		/* Undo the unlinked file naming stuff we just did */
		mutex_enter(&rp->r_statelock);
		if (rp->r_unldvp) {
			VN_RELE(ndvp);
			rp->r_unldvp = NULL;
			if (rp->r_unlcred != NULL)
				crfree(rp->r_unlcred);
			rp->r_unlcred = NULL;
			/* rp->r_unlanme points to tmpname */
			if (rp->r_unlname)
				kmem_free(rp->r_unlname, MAXNAMELEN);
			rp->r_unlname = NULL;
		}
		mutex_exit(&rp->r_statelock);

		if (nvp) {
			VN_RELE(nvp);
		}
		goto link_call;
	}

	if (error) {
		VN_RELE(ovp);
		nfs_rw_exit(&odrp->r_rwlock);
		nfs_rw_exit(&ndrp->r_rwlock);
		if (nvp) {
			VN_RELE(nvp);
		}
		return (error);
	}

	/*
	 * when renaming directories to be a subdirectory of a
	 * different parent, the dnlc entry for ".." will no
	 * longer be valid, so it must be removed
	 */
	rp = VTOR4(ovp);
	if (ndvp != odvp) {
		if (ovp->v_type == VDIR) {
			dnlc_remove(ovp, "..");
			if (rp->r_dir != NULL)
				nfs4_purge_rddir_cache(ovp);
		}
	}

	/*
	 * If we are renaming the unlinked file, update the
	 * r_unldvp and r_unlname as needed.
	 */
	mutex_enter(&rp->r_statelock);
	if (rp->r_unldvp != NULL) {
		if (strcmp(rp->r_unlname, onm) == 0) {
			(void) strncpy(rp->r_unlname, nnm, MAXNAMELEN);
			rp->r_unlname[MAXNAMELEN - 1] = '\0';
			if (ndvp != rp->r_unldvp) {
				VN_RELE(rp->r_unldvp);
				rp->r_unldvp = ndvp;
				VN_HOLD(ndvp);
			}
		}
	}
	mutex_exit(&rp->r_statelock);

	/*
	 * Notify the rename vnevents to source vnode, and to the target
	 * vnode if it already existed.
	 */
	if (error == 0) {
		vnode_t *tvp;
		rnode4_t *trp;
		/*
		 * Notify the vnode. Each links is represented by
		 * a different vnode, in nfsv4.
		 */
		if (nvp) {
			trp = VTOR4(nvp);
			tvp = nvp;
			if (IS_SHADOW(nvp, trp))
				tvp = RTOV4(trp);
			vnevent_rename_dest(tvp, ndvp, nnm, ct);
		}

		/*
		 * if the source and destination directory are not the
		 * same notify the destination directory.
		 */
		if (VTOR4(odvp) != VTOR4(ndvp)) {
			trp = VTOR4(ndvp);
			tvp = ndvp;
			if (IS_SHADOW(ndvp, trp))
				tvp = RTOV4(trp);
			vnevent_rename_dest_dir(tvp, ct);
		}

		trp = VTOR4(ovp);
		tvp = ovp;
		if (IS_SHADOW(ovp, trp))
			tvp = RTOV4(trp);
		vnevent_rename_src(tvp, odvp, onm, ct);
	}

	if (nvp) {
		VN_RELE(nvp);
	}
	VN_RELE(ovp);

	nfs_rw_exit(&odrp->r_rwlock);
	nfs_rw_exit(&ndrp->r_rwlock);

	return (error);
}

/*
 * When the parent directory has changed, sv_dfh must be updated
 */
static void
update_parentdir_sfh(vnode_t *vp, vnode_t *ndvp)
{
	svnode_t *sv = VTOSV(vp);
	nfs4_sharedfh_t *old_dfh = sv->sv_dfh;
	nfs4_sharedfh_t *new_dfh = VTOR4(ndvp)->r_fh;

	sfh4_hold(new_dfh);
	sv->sv_dfh = new_dfh;
	sfh4_rele(&old_dfh);
}

/*
 * nfs4rename_persistent does the otw portion of renaming in NFS Version 4,
 * when it is known that the filehandle is persistent through rename.
 *
 * Rename requires that the current fh be the target directory and the
 * saved fh be the source directory. After the operation, the current fh
 * is unchanged.
 * The compound op structure for persistent fh rename is:
 *      PUTFH(sourcdir), SAVEFH, PUTFH(targetdir), RENAME
 * Rather than bother with the directory postop args, we'll simply
 * update that a change occurred in the cache, so no post-op getattrs.
 */
static int
nfs4rename_persistent_fh(vnode_t *odvp, char *onm, vnode_t *renvp,
    vnode_t *ndvp, char *nnm, cred_t *cr, nfsstat4 *statp)
{
	COMPOUND4args_clnt args;
	COMPOUND4res_clnt res, *resp = NULL;
	nfs_argop4 *argop;
	nfs_resop4 *resop;
	int doqueue, argoplist_size;
	mntinfo4_t *mi;
	rnode4_t *odrp = VTOR4(odvp);
	rnode4_t *ndrp = VTOR4(ndvp);
	RENAME4res *rn_res;
	bool_t needrecov;
	nfs4_recov_state_t recov_state;
	nfs4_error_t e = { 0, NFS4_OK, RPC_SUCCESS };
	dirattr_info_t dinfo, *dinfop;

	ASSERT(nfs_zone() == VTOMI4(odvp)->mi_zone);

	recov_state.rs_flags = 0;
	recov_state.rs_num_retry_despite_err = 0;

	/*
	 * Rename ops: putfh sdir; savefh; putfh tdir; rename; getattr tdir
	 *
	 * If source/target are different dirs, then append putfh(src); getattr
	 */
	args.array_len = (odvp == ndvp) ? 5 : 7;
	argoplist_size = args.array_len * sizeof (nfs_argop4);
	args.array = argop = kmem_alloc(argoplist_size, KM_SLEEP);

recov_retry:
	*statp = NFS4_OK;

	/* No need to Lookup the file, persistent fh */
	args.ctag = TAG_RENAME;

	mi = VTOMI4(odvp);
	e.error = nfs4_start_op(mi, odvp, ndvp, &recov_state);
	if (e.error) {
		kmem_free(argop, argoplist_size);
		return (e.error);
	}

	/* 0: putfh source directory */
	argop[0].argop = OP_CPUTFH;
	argop[0].nfs_argop4_u.opcputfh.sfh = odrp->r_fh;

	/* 1: Save source fh to free up current for target */
	argop[1].argop = OP_SAVEFH;

	/* 2: putfh targetdir */
	argop[2].argop = OP_CPUTFH;
	argop[2].nfs_argop4_u.opcputfh.sfh = ndrp->r_fh;

	/* 3: current_fh is targetdir, saved_fh is sourcedir */
	argop[3].argop = OP_CRENAME;
	argop[3].nfs_argop4_u.opcrename.coldname = onm;
	argop[3].nfs_argop4_u.opcrename.cnewname = nnm;

	/* 4: getattr (targetdir) */
	argop[4].argop = OP_GETATTR;
	argop[4].nfs_argop4_u.opgetattr.attr_request = NFS4_VATTR_MASK;
	argop[4].nfs_argop4_u.opgetattr.mi = mi;

	if (ndvp != odvp) {

		/* 5: putfh (sourcedir) */
		argop[5].argop = OP_CPUTFH;
		argop[5].nfs_argop4_u.opcputfh.sfh = ndrp->r_fh;

		/* 6: getattr (sourcedir) */
		argop[6].argop = OP_GETATTR;
		argop[6].nfs_argop4_u.opgetattr.attr_request = NFS4_VATTR_MASK;
		argop[6].nfs_argop4_u.opgetattr.mi = mi;
	}

	dnlc_remove(odvp, onm);
	dnlc_remove(ndvp, nnm);

	doqueue = 1;
	dinfo.di_time_call = gethrtime();
	rfs4call(mi, &args, &res, cr, &doqueue, 0, &e);

	needrecov = nfs4_needs_recovery(&e, FALSE, mi->mi_vfsp);
	if (e.error) {
		PURGE_ATTRCACHE4(odvp);
		PURGE_ATTRCACHE4(ndvp);
	} else {
		*statp = res.status;
	}

	if (needrecov) {
		if (nfs4_start_recovery(&e, mi, odvp, ndvp, NULL, NULL,
		    OP_RENAME, NULL, NULL, NULL) == FALSE) {
			nfs4_end_op(mi, odvp, ndvp, &recov_state, needrecov);
			if (!e.error)
				(void) xdr_free(xdr_COMPOUND4res_clnt,
				    (caddr_t)&res);
			goto recov_retry;
		}
	}

	if (!e.error) {
		resp = &res;
		/*
		 * as long as OP_RENAME
		 */
		if (res.status != NFS4_OK && res.array_len <= 4) {
			e.error = geterrno4(res.status);
			PURGE_ATTRCACHE4(odvp);
			PURGE_ATTRCACHE4(ndvp);
			/*
			 * System V defines rename to return EEXIST, not
			 * ENOTEMPTY if the target directory is not empty.
			 * Over the wire, the error is NFSERR_ENOTEMPTY
			 * which geterrno4 maps to ENOTEMPTY.
			 */
			if (e.error == ENOTEMPTY)
				e.error = EEXIST;
		} else {

			resop = &res.array[3];	/* rename res */
			rn_res = &resop->nfs_resop4_u.oprename;

			if (res.status == NFS4_OK) {
				/*
				 * Update target attribute, readdir and dnlc
				 * caches.
				 */
				dinfo.di_garp =
				    &res.array[4].nfs_resop4_u.opgetattr.ga_res;
				dinfo.di_cred = cr;
				dinfop = &dinfo;
			} else
				dinfop = NULL;

			nfs4_update_dircaches(&rn_res->target_cinfo,
			    ndvp, NULL, NULL, dinfop);

			/*
			 * Update source attribute, readdir and dnlc caches
			 *
			 */
			if (ndvp != odvp) {
				update_parentdir_sfh(renvp, ndvp);

				if (dinfop)
					dinfo.di_garp =
					    &(res.array[6].nfs_resop4_u.
					    opgetattr.ga_res);

				nfs4_update_dircaches(&rn_res->source_cinfo,
				    odvp, NULL, NULL, dinfop);
			}

			fn_move(VTOSV(renvp)->sv_name, VTOSV(ndvp)->sv_name,
			    nnm);
		}
	}

	if (resp)
		(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)resp);
	nfs4_end_op(mi, odvp, ndvp, &recov_state, needrecov);
	kmem_free(argop, argoplist_size);

	return (e.error);
}

/*
 * nfs4rename_volatile_fh does the otw part of renaming in NFS Version 4, when
 * it is possible for the filehandle to change due to the rename.
 *
 * The compound req in this case includes a post-rename lookup and getattr
 * to ensure that we have the correct fh and attributes for the object.
 *
 * Rename requires that the current fh be the target directory and the
 * saved fh be the source directory. After the operation, the current fh
 * is unchanged.
 *
 * We need the new filehandle (hence a LOOKUP and GETFH) so that we can
 * update the filehandle for the renamed object.  We also get the old
 * filehandle for historical reasons; this should be taken out sometime.
 * This results in a rather cumbersome compound...
 *
 *    PUTFH(sourcdir), SAVEFH, LOOKUP(src), GETFH(old),
 *    PUTFH(targetdir), RENAME, LOOKUP(trgt), GETFH(new), GETATTR
 *
 */
static int
nfs4rename_volatile_fh(vnode_t *odvp, char *onm, vnode_t *ovp,
    vnode_t *ndvp, char *nnm, cred_t *cr, nfsstat4 *statp)
{
	COMPOUND4args_clnt args;
	COMPOUND4res_clnt res, *resp = NULL;
	int argoplist_size;
	nfs_argop4 *argop;
	nfs_resop4 *resop;
	int doqueue;
	mntinfo4_t *mi;
	rnode4_t *odrp = VTOR4(odvp);	/* old directory */
	rnode4_t *ndrp = VTOR4(ndvp);	/* new directory */
	rnode4_t *orp = VTOR4(ovp);	/* object being renamed */
	RENAME4res *rn_res;
	GETFH4res *ngf_res;
	bool_t needrecov;
	nfs4_recov_state_t recov_state;
	hrtime_t t;
	nfs4_error_t e = { 0, NFS4_OK, RPC_SUCCESS };
	dirattr_info_t dinfo, *dinfop = &dinfo;

	ASSERT(nfs_zone() == VTOMI4(odvp)->mi_zone);

	recov_state.rs_flags = 0;
	recov_state.rs_num_retry_despite_err = 0;

recov_retry:
	*statp = NFS4_OK;

	/*
	 * There is a window between the RPC and updating the path and
	 * filehandle stored in the rnode.  Lock out the FHEXPIRED recovery
	 * code, so that it doesn't try to use the old path during that
	 * window.
	 */
	mutex_enter(&orp->r_statelock);
	while (orp->r_flags & R4RECEXPFH) {
		klwp_t *lwp = ttolwp(curthread);

		if (lwp != NULL)
			lwp->lwp_nostop++;
		if (cv_wait_sig(&orp->r_cv, &orp->r_statelock) == 0) {
			mutex_exit(&orp->r_statelock);
			if (lwp != NULL)
				lwp->lwp_nostop--;
			return (EINTR);
		}
		if (lwp != NULL)
			lwp->lwp_nostop--;
	}
	orp->r_flags |= R4RECEXPFH;
	mutex_exit(&orp->r_statelock);

	mi = VTOMI4(odvp);

	args.ctag = TAG_RENAME_VFH;
	args.array_len = (odvp == ndvp) ? 10 : 12;
	argoplist_size  = args.array_len * sizeof (nfs_argop4);
	argop = kmem_alloc(argoplist_size, KM_SLEEP);

	/*
	 * Rename ops:
	 *    PUTFH(sourcdir), SAVEFH, LOOKUP(src), GETFH(old),
	 *    PUTFH(targetdir), RENAME, GETATTR(targetdir)
	 *    LOOKUP(trgt), GETFH(new), GETATTR,
	 *
	 *    if (odvp != ndvp)
	 *	add putfh(sourcedir), getattr(sourcedir) }
	 */
	args.array = argop;

	e.error = nfs4_start_fop(mi, odvp, ndvp, OH_VFH_RENAME,
	    &recov_state, NULL);
	if (e.error) {
		kmem_free(argop, argoplist_size);
		mutex_enter(&orp->r_statelock);
		orp->r_flags &= ~R4RECEXPFH;
		cv_broadcast(&orp->r_cv);
		mutex_exit(&orp->r_statelock);
		return (e.error);
	}

	/* 0: putfh source directory */
	argop[0].argop = OP_CPUTFH;
	argop[0].nfs_argop4_u.opcputfh.sfh = odrp->r_fh;

	/* 1: Save source fh to free up current for target */
	argop[1].argop = OP_SAVEFH;

	/* 2: Lookup pre-rename fh of renamed object */
	argop[2].argop = OP_CLOOKUP;
	argop[2].nfs_argop4_u.opclookup.cname = onm;

	/* 3: getfh fh of renamed object (before rename) */
	argop[3].argop = OP_GETFH;

	/* 4: putfh targetdir */
	argop[4].argop = OP_CPUTFH;
	argop[4].nfs_argop4_u.opcputfh.sfh = ndrp->r_fh;

	/* 5: current_fh is targetdir, saved_fh is sourcedir */
	argop[5].argop = OP_CRENAME;
	argop[5].nfs_argop4_u.opcrename.coldname = onm;
	argop[5].nfs_argop4_u.opcrename.cnewname = nnm;

	/* 6: getattr of target dir (post op attrs) */
	argop[6].argop = OP_GETATTR;
	argop[6].nfs_argop4_u.opgetattr.attr_request = NFS4_VATTR_MASK;
	argop[6].nfs_argop4_u.opgetattr.mi = mi;

	/* 7: Lookup post-rename fh of renamed object */
	argop[7].argop = OP_CLOOKUP;
	argop[7].nfs_argop4_u.opclookup.cname = nnm;

	/* 8: getfh fh of renamed object (after rename) */
	argop[8].argop = OP_GETFH;

	/* 9: getattr of renamed object */
	argop[9].argop = OP_GETATTR;
	argop[9].nfs_argop4_u.opgetattr.attr_request = NFS4_VATTR_MASK;
	argop[9].nfs_argop4_u.opgetattr.mi = mi;

	/*
	 * If source/target dirs are different, then get new post-op
	 * attrs for source dir also.
	 */
	if (ndvp != odvp) {
		/* 10: putfh (sourcedir) */
		argop[10].argop = OP_CPUTFH;
		argop[10].nfs_argop4_u.opcputfh.sfh = ndrp->r_fh;

		/* 11: getattr (sourcedir) */
		argop[11].argop = OP_GETATTR;
		argop[11].nfs_argop4_u.opgetattr.attr_request = NFS4_VATTR_MASK;
		argop[11].nfs_argop4_u.opgetattr.mi = mi;
	}

	dnlc_remove(odvp, onm);
	dnlc_remove(ndvp, nnm);

	doqueue = 1;
	t = gethrtime();
	rfs4call(mi, &args, &res, cr, &doqueue, 0, &e);

	needrecov = nfs4_needs_recovery(&e, FALSE, mi->mi_vfsp);
	if (e.error) {
		PURGE_ATTRCACHE4(odvp);
		PURGE_ATTRCACHE4(ndvp);
		if (!needrecov) {
			nfs4_end_fop(mi, odvp, ndvp, OH_VFH_RENAME,
			    &recov_state, needrecov);
			goto out;
		}
	} else {
		*statp = res.status;
	}

	if (needrecov) {
		bool_t abort;

		abort = nfs4_start_recovery(&e, mi, odvp, ndvp, NULL, NULL,
		    OP_RENAME, NULL, NULL, NULL);
		if (abort == FALSE) {
			nfs4_end_fop(mi, odvp, ndvp, OH_VFH_RENAME,
			    &recov_state, needrecov);
			kmem_free(argop, argoplist_size);
			if (!e.error)
				(void) xdr_free(xdr_COMPOUND4res_clnt,
				    (caddr_t)&res);
			mutex_enter(&orp->r_statelock);
			orp->r_flags &= ~R4RECEXPFH;
			cv_broadcast(&orp->r_cv);
			mutex_exit(&orp->r_statelock);
			goto recov_retry;
		} else {
			if (e.error != 0) {
				nfs4_end_fop(mi, odvp, ndvp, OH_VFH_RENAME,
				    &recov_state, needrecov);
				goto out;
			}
			/* fall through for res.status case */
		}
	}

	resp = &res;
	/*
	 * If OP_RENAME (or any prev op) failed, then return an error.
	 * OP_RENAME is index 5, so if array len <= 6 we return an error.
	 */
	if ((res.status != NFS4_OK) && (res.array_len <= 6)) {
		/*
		 * Error in an op other than last Getattr
		 */
		e.error = geterrno4(res.status);
		PURGE_ATTRCACHE4(odvp);
		PURGE_ATTRCACHE4(ndvp);
		/*
		 * System V defines rename to return EEXIST, not
		 * ENOTEMPTY if the target directory is not empty.
		 * Over the wire, the error is NFSERR_ENOTEMPTY
		 * which geterrno4 maps to ENOTEMPTY.
		 */
		if (e.error == ENOTEMPTY)
			e.error = EEXIST;
		nfs4_end_fop(mi, odvp, ndvp, OH_VFH_RENAME, &recov_state,
		    needrecov);
		goto out;
	}

	/* rename results */
	rn_res = &res.array[5].nfs_resop4_u.oprename;

	if (res.status == NFS4_OK) {
		/* Update target attribute, readdir and dnlc caches */
		dinfo.di_garp =
		    &res.array[6].nfs_resop4_u.opgetattr.ga_res;
		dinfo.di_cred = cr;
		dinfo.di_time_call = t;
	} else
		dinfop = NULL;

	/* Update source cache attribute, readdir and dnlc caches */
	nfs4_update_dircaches(&rn_res->target_cinfo, ndvp, NULL, NULL, dinfop);

	/* Update source cache attribute, readdir and dnlc caches */
	if (ndvp != odvp) {
		update_parentdir_sfh(ovp, ndvp);

		/*
		 * If dinfop is non-NULL, then compound succeded, so
		 * set di_garp to attrs for source dir.  dinfop is only
		 * set to NULL when compound fails.
		 */
		if (dinfop)
			dinfo.di_garp =
			    &res.array[11].nfs_resop4_u.opgetattr.ga_res;
		nfs4_update_dircaches(&rn_res->source_cinfo, odvp, NULL, NULL,
		    dinfop);
	}

	/*
	 * Update the rnode with the new component name and args,
	 * and if the file handle changed, also update it with the new fh.
	 * This is only necessary if the target object has an rnode
	 * entry and there is no need to create one for it.
	 */
	resop = &res.array[8];	/* getfh new res */
	ngf_res = &resop->nfs_resop4_u.opgetfh;

	/*
	 * Update the path and filehandle for the renamed object.
	 */
	nfs4rename_update(ovp, ndvp, &ngf_res->object, nnm);

	nfs4_end_fop(mi, odvp, ndvp, OH_VFH_RENAME, &recov_state, needrecov);

	if (res.status == NFS4_OK) {
		resop++;	/* getattr res */
		e.error = nfs4_update_attrcache(res.status,
		    &resop->nfs_resop4_u.opgetattr.ga_res,
		    t, ovp, cr);
	}

out:
	kmem_free(argop, argoplist_size);
	if (resp)
		(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)resp);
	mutex_enter(&orp->r_statelock);
	orp->r_flags &= ~R4RECEXPFH;
	cv_broadcast(&orp->r_cv);
	mutex_exit(&orp->r_statelock);

	return (e.error);
}

/* ARGSUSED */
static int
nfs4_mkdir(vnode_t *dvp, char *nm, struct vattr *va, vnode_t **vpp, cred_t *cr,
    caller_context_t *ct, int flags, vsecattr_t *vsecp)
{
	int error;
	vnode_t *vp;

	if (nfs_zone() != VTOMI4(dvp)->mi_zone)
		return (EPERM);
	/*
	 * As ".." has special meaning and rather than send a mkdir
	 * over the wire to just let the server freak out, we just
	 * short circuit it here and return EEXIST
	 */
	if (nm[0] == '.' && nm[1] == '.' && nm[2] == '\0')
		return (EEXIST);

	/*
	 * Decision to get the right gid and setgid bit of the
	 * new directory is now made in call_nfs4_create_req.
	 */
	va->va_mask |= AT_MODE;
	error = call_nfs4_create_req(dvp, nm, NULL, va, &vp, cr, NF4DIR);
	if (error)
		return (error);

	*vpp = vp;
	return (0);
}


/*
 * rmdir is using the same remove v4 op as does remove.
 * Remove requires that the current fh be the target directory.
 * After the operation, the current fh is unchanged.
 * The compound op structure is:
 *      PUTFH(targetdir), REMOVE
 */
/*ARGSUSED4*/
static int
nfs4_rmdir(vnode_t *dvp, char *nm, vnode_t *cdir, cred_t *cr,
    caller_context_t *ct, int flags)
{
	int need_end_op = FALSE;
	COMPOUND4args_clnt args;
	COMPOUND4res_clnt res, *resp = NULL;
	REMOVE4res *rm_res;
	nfs_argop4 argop[3];
	nfs_resop4 *resop;
	vnode_t *vp;
	int doqueue;
	mntinfo4_t *mi;
	rnode4_t *drp;
	bool_t needrecov = FALSE;
	nfs4_recov_state_t recov_state;
	nfs4_error_t e = { 0, NFS4_OK, RPC_SUCCESS };
	dirattr_info_t dinfo, *dinfop;

	if (nfs_zone() != VTOMI4(dvp)->mi_zone)
		return (EPERM);
	/*
	 * As ".." has special meaning and rather than send a rmdir
	 * over the wire to just let the server freak out, we just
	 * short circuit it here and return EEXIST
	 */
	if (nm[0] == '.' && nm[1] == '.' && nm[2] == '\0')
		return (EEXIST);

	drp = VTOR4(dvp);
	if (nfs_rw_enter_sig(&drp->r_rwlock, RW_WRITER, INTR4(dvp)))
		return (EINTR);

	/*
	 * Attempt to prevent a rmdir(".") from succeeding.
	 */
	e.error = nfs4lookup(dvp, nm, &vp, cr, 0);
	if (e.error) {
		nfs_rw_exit(&drp->r_rwlock);
		return (e.error);
	}
	if (vp == cdir) {
		VN_RELE(vp);
		nfs_rw_exit(&drp->r_rwlock);
		return (EINVAL);
	}

	/*
	 * Since nfsv4 remove op works on both files and directories,
	 * check that the removed object is indeed a directory.
	 */
	if (vp->v_type != VDIR) {
		VN_RELE(vp);
		nfs_rw_exit(&drp->r_rwlock);
		return (ENOTDIR);
	}

	/*
	 * First just remove the entry from the name cache, as it
	 * is most likely an entry for this vp.
	 */
	dnlc_remove(dvp, nm);

	/*
	 * If there vnode reference count is greater than one, then
	 * there may be additional references in the DNLC which will
	 * need to be purged.  First, trying removing the entry for
	 * the parent directory and see if that removes the additional
	 * reference(s).  If that doesn't do it, then use dnlc_purge_vp
	 * to completely remove any references to the directory which
	 * might still exist in the DNLC.
	 */
	if (vp->v_count > 1) {
		dnlc_remove(vp, "..");
		if (vp->v_count > 1)
			dnlc_purge_vp(vp);
	}

	mi = VTOMI4(dvp);
	recov_state.rs_flags = 0;
	recov_state.rs_num_retry_despite_err = 0;

recov_retry:
	args.ctag = TAG_RMDIR;

	/*
	 * Rmdir ops: putfh dir; remove
	 */
	args.array_len = 3;
	args.array = argop;

	e.error = nfs4_start_op(VTOMI4(dvp), dvp, NULL, &recov_state);
	if (e.error) {
		nfs_rw_exit(&drp->r_rwlock);
		return (e.error);
	}
	need_end_op = TRUE;

	/* putfh directory */
	argop[0].argop = OP_CPUTFH;
	argop[0].nfs_argop4_u.opcputfh.sfh = drp->r_fh;

	/* remove */
	argop[1].argop = OP_CREMOVE;
	argop[1].nfs_argop4_u.opcremove.ctarget = nm;

	/* getattr (postop attrs for dir that contained removed dir) */
	argop[2].argop = OP_GETATTR;
	argop[2].nfs_argop4_u.opgetattr.attr_request = NFS4_VATTR_MASK;
	argop[2].nfs_argop4_u.opgetattr.mi = mi;

	dinfo.di_time_call = gethrtime();
	doqueue = 1;
	rfs4call(mi, &args, &res, cr, &doqueue, 0, &e);

	PURGE_ATTRCACHE4(vp);

	needrecov = nfs4_needs_recovery(&e, FALSE, mi->mi_vfsp);
	if (e.error) {
		PURGE_ATTRCACHE4(dvp);
	}

	if (needrecov) {
		if (nfs4_start_recovery(&e, VTOMI4(dvp), dvp, NULL, NULL,
		    NULL, OP_REMOVE, NULL, NULL, NULL) == FALSE) {
			if (!e.error)
				(void) xdr_free(xdr_COMPOUND4res_clnt,
				    (caddr_t)&res);

			nfs4_end_op(VTOMI4(dvp), dvp, NULL, &recov_state,
			    needrecov);
			need_end_op = FALSE;
			goto recov_retry;
		}
	}

	if (!e.error) {
		resp = &res;

		/*
		 * Only return error if first 2 ops (OP_REMOVE or earlier)
		 * failed.
		 */
		if (res.status != NFS4_OK && res.array_len <= 2) {
			e.error = geterrno4(res.status);
			PURGE_ATTRCACHE4(dvp);
			nfs4_end_op(VTOMI4(dvp), dvp, NULL,
			    &recov_state, needrecov);
			need_end_op = FALSE;
			nfs4_purge_stale_fh(e.error, dvp, cr);
			/*
			 * System V defines rmdir to return EEXIST, not
			 * ENOTEMPTY if the directory is not empty.  Over
			 * the wire, the error is NFSERR_ENOTEMPTY which
			 * geterrno4 maps to ENOTEMPTY.
			 */
			if (e.error == ENOTEMPTY)
				e.error = EEXIST;
		} else {
			resop = &res.array[1];	/* remove res */
			rm_res = &resop->nfs_resop4_u.opremove;

			if (res.status == NFS4_OK) {
				resop = &res.array[2];	/* dir attrs */
				dinfo.di_garp =
				    &resop->nfs_resop4_u.opgetattr.ga_res;
				dinfo.di_cred = cr;
				dinfop = &dinfo;
			} else
				dinfop = NULL;

			/* Update dir attribute, readdir and dnlc caches */
			nfs4_update_dircaches(&rm_res->cinfo, dvp, NULL, NULL,
			    dinfop);

			/* destroy rddir cache for dir that was removed */
			if (VTOR4(vp)->r_dir != NULL)
				nfs4_purge_rddir_cache(vp);
		}
	}

	if (need_end_op)
		nfs4_end_op(VTOMI4(dvp), dvp, NULL, &recov_state, needrecov);

	nfs_rw_exit(&drp->r_rwlock);

	if (resp)
		(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)resp);

	if (e.error == 0) {
		vnode_t *tvp;
		rnode4_t *trp;
		trp = VTOR4(vp);
		tvp = vp;
		if (IS_SHADOW(vp, trp))
			tvp = RTOV4(trp);
		vnevent_rmdir(tvp, dvp, nm, ct);
	}

	VN_RELE(vp);

	return (e.error);
}

/* ARGSUSED */
static int
nfs4_symlink(vnode_t *dvp, char *lnm, struct vattr *tva, char *tnm, cred_t *cr,
    caller_context_t *ct, int flags)
{
	int error;
	vnode_t *vp;
	rnode4_t *rp;
	char *contents;
	mntinfo4_t *mi = VTOMI4(dvp);

	if (nfs_zone() != mi->mi_zone)
		return (EPERM);
	if (!(mi->mi_flags & MI4_SYMLINK))
		return (EOPNOTSUPP);

	error = call_nfs4_create_req(dvp, lnm, tnm, tva, &vp, cr, NF4LNK);
	if (error)
		return (error);

	ASSERT(nfs4_consistent_type(vp));
	rp = VTOR4(vp);
	if (nfs4_do_symlink_cache && rp->r_symlink.contents == NULL) {

		contents = kmem_alloc(MAXPATHLEN, KM_SLEEP);

		if (contents != NULL) {
			mutex_enter(&rp->r_statelock);
			if (rp->r_symlink.contents == NULL) {
				rp->r_symlink.len = strlen(tnm);
				bcopy(tnm, contents, rp->r_symlink.len);
				rp->r_symlink.contents = contents;
				rp->r_symlink.size = MAXPATHLEN;
				mutex_exit(&rp->r_statelock);
			} else {
				mutex_exit(&rp->r_statelock);
				kmem_free((void *)contents, MAXPATHLEN);
			}
		}
	}
	VN_RELE(vp);

	return (error);
}


/*
 * Read directory entries.
 * There are some weird things to look out for here.  The uio_loffset
 * field is either 0 or it is the offset returned from a previous
 * readdir.  It is an opaque value used by the server to find the
 * correct directory block to read. The count field is the number
 * of blocks to read on the server.  This is advisory only, the server
 * may return only one block's worth of entries.  Entries may be compressed
 * on the server.
 */
/* ARGSUSED */
static int
nfs4_readdir(vnode_t *vp, struct uio *uiop, cred_t *cr, int *eofp,
	caller_context_t *ct, int flags)
{
	int error;
	uint_t count;
	rnode4_t *rp;
	rddir4_cache *rdc;
	rddir4_cache *rrdc;

	if (nfs_zone() != VTOMI4(vp)->mi_zone)
		return (EIO);
	rp = VTOR4(vp);

	ASSERT(nfs_rw_lock_held(&rp->r_rwlock, RW_READER));

	/*
	 * Make sure that the directory cache is valid.
	 */
	if (rp->r_dir != NULL) {
		if (nfs_disable_rddir_cache != 0) {
			/*
			 * Setting nfs_disable_rddir_cache in /etc/system
			 * allows interoperability with servers that do not
			 * properly update the attributes of directories.
			 * Any cached information gets purged before an
			 * access is made to it.
			 */
			nfs4_purge_rddir_cache(vp);
		}

		error = nfs4_validate_caches(vp, cr);
		if (error)
			return (error);
	}

	count = MIN(uiop->uio_iov->iov_len, MAXBSIZE);

	/*
	 * Short circuit last readdir which always returns 0 bytes.
	 * This can be done after the directory has been read through
	 * completely at least once.  This will set r_direof which
	 * can be used to find the value of the last cookie.
	 */
	mutex_enter(&rp->r_statelock);
	if (rp->r_direof != NULL &&
	    uiop->uio_loffset == rp->r_direof->nfs4_ncookie) {
		mutex_exit(&rp->r_statelock);
#ifdef DEBUG
		nfs4_readdir_cache_shorts++;
#endif
		if (eofp)
			*eofp = 1;
		return (0);
	}

	/*
	 * Look for a cache entry.  Cache entries are identified
	 * by the NFS cookie value and the byte count requested.
	 */
	rdc = rddir4_cache_lookup(rp, uiop->uio_loffset, count);

	/*
	 * If rdc is NULL then the lookup resulted in an unrecoverable error.
	 */
	if (rdc == NULL) {
		mutex_exit(&rp->r_statelock);
		return (EINTR);
	}

	/*
	 * Check to see if we need to fill this entry in.
	 */
	if (rdc->flags & RDDIRREQ) {
		rdc->flags &= ~RDDIRREQ;
		rdc->flags |= RDDIR;
		mutex_exit(&rp->r_statelock);

		/*
		 * Do the readdir.
		 */
		nfs4readdir(vp, rdc, cr);

		/*
		 * Reacquire the lock, so that we can continue
		 */
		mutex_enter(&rp->r_statelock);
		/*
		 * The entry is now complete
		 */
		rdc->flags &= ~RDDIR;
	}

	ASSERT(!(rdc->flags & RDDIR));

	/*
	 * If an error occurred while attempting
	 * to fill the cache entry, mark the entry invalid and
	 * just return the error.
	 */
	if (rdc->error) {
		error = rdc->error;
		rdc->flags |= RDDIRREQ;
		rddir4_cache_rele(rp, rdc);
		mutex_exit(&rp->r_statelock);
		return (error);
	}

	/*
	 * The cache entry is complete and good,
	 * copyout the dirent structs to the calling
	 * thread.
	 */
	error = uiomove(rdc->entries, rdc->actlen, UIO_READ, uiop);

	/*
	 * If no error occurred during the copyout,
	 * update the offset in the uio struct to
	 * contain the value of the next NFS 4 cookie
	 * and set the eof value appropriately.
	 */
	if (!error) {
		uiop->uio_loffset = rdc->nfs4_ncookie;
		if (eofp)
			*eofp = rdc->eof;
	}

	/*
	 * Decide whether to do readahead.  Don't if we
	 * have already read to the end of directory.
	 */
	if (rdc->eof) {
		/*
		 * Make the entry the direof only if it is cached
		 */
		if (rdc->flags & RDDIRCACHED)
			rp->r_direof = rdc;
		rddir4_cache_rele(rp, rdc);
		mutex_exit(&rp->r_statelock);
		return (error);
	}

	/* Determine if a readdir readahead should be done */
	if (!(rp->r_flags & R4LOOKUP)) {
		rddir4_cache_rele(rp, rdc);
		mutex_exit(&rp->r_statelock);
		return (error);
	}

	/*
	 * Now look for a readahead entry.
	 *
	 * Check to see whether we found an entry for the readahead.
	 * If so, we don't need to do anything further, so free the new
	 * entry if one was allocated.  Otherwise, allocate a new entry, add
	 * it to the cache, and then initiate an asynchronous readdir
	 * operation to fill it.
	 */
	rrdc = rddir4_cache_lookup(rp, rdc->nfs4_ncookie, count);

	/*
	 * A readdir cache entry could not be obtained for the readahead.  In
	 * this case we skip the readahead and return.
	 */
	if (rrdc == NULL) {
		rddir4_cache_rele(rp, rdc);
		mutex_exit(&rp->r_statelock);
		return (error);
	}

	/*
	 * Check to see if we need to fill this entry in.
	 */
	if (rrdc->flags & RDDIRREQ) {
		rrdc->flags &= ~RDDIRREQ;
		rrdc->flags |= RDDIR;
		rddir4_cache_rele(rp, rdc);
		mutex_exit(&rp->r_statelock);
#ifdef DEBUG
		nfs4_readdir_readahead++;
#endif
		/*
		 * Do the readdir.
		 */
		nfs4_async_readdir(vp, rrdc, cr, do_nfs4readdir);
		return (error);
	}

	rddir4_cache_rele(rp, rrdc);
	rddir4_cache_rele(rp, rdc);
	mutex_exit(&rp->r_statelock);
	return (error);
}

static int
do_nfs4readdir(vnode_t *vp, rddir4_cache *rdc, cred_t *cr)
{
	int error;
	rnode4_t *rp;

	ASSERT(nfs_zone() == VTOMI4(vp)->mi_zone);

	rp = VTOR4(vp);

	/*
	 * Obtain the readdir results for the caller.
	 */
	nfs4readdir(vp, rdc, cr);

	mutex_enter(&rp->r_statelock);
	/*
	 * The entry is now complete
	 */
	rdc->flags &= ~RDDIR;

	error = rdc->error;
	if (error)
		rdc->flags |= RDDIRREQ;
	rddir4_cache_rele(rp, rdc);
	mutex_exit(&rp->r_statelock);

	return (error);
}

/*
 * Read directory entries.
 * There are some weird things to look out for here.  The uio_loffset
 * field is either 0 or it is the offset returned from a previous
 * readdir.  It is an opaque value used by the server to find the
 * correct directory block to read. The count field is the number
 * of blocks to read on the server.  This is advisory only, the server
 * may return only one block's worth of entries.  Entries may be compressed
 * on the server.
 *
 * Generates the following compound request:
 * 1. If readdir offset is zero and no dnlc entry for parent exists,
 *    must include a Lookupp as well. In this case, send:
 *    { Putfh <fh>; Readdir; Lookupp; Getfh; Getattr }
 * 2. Otherwise just do: { Putfh <fh>; Readdir }
 *
 * Get complete attributes and filehandles for entries if this is the
 * first read of the directory. Otherwise, just get fileid's.
 */
static void
nfs4readdir(vnode_t *vp, rddir4_cache *rdc, cred_t *cr)
{
	COMPOUND4args_clnt args;
	COMPOUND4res_clnt res;
	READDIR4args *rargs;
	READDIR4res_clnt *rd_res;
	bitmap4 rd_bitsval;
	nfs_argop4 argop[5];
	nfs_resop4 *resop;
	rnode4_t *rp = VTOR4(vp);
	mntinfo4_t *mi = VTOMI4(vp);
	int doqueue;
	u_longlong_t nodeid, pnodeid;	/* id's of dir and its parents */
	vnode_t *dvp;
	nfs_cookie4 cookie = (nfs_cookie4)rdc->nfs4_cookie;
	int num_ops, res_opcnt;
	bool_t needrecov = FALSE;
	nfs4_recov_state_t recov_state;
	hrtime_t t;
	nfs4_error_t e = { 0, NFS4_OK, RPC_SUCCESS };

	ASSERT(nfs_zone() == mi->mi_zone);
	ASSERT(rdc->flags & RDDIR);
	ASSERT(rdc->entries == NULL);

	/*
	 * If rp were a stub, it should have triggered and caused
	 * a mount for us to get this far.
	 */
	ASSERT(!RP_ISSTUB(rp));

	num_ops = 2;
	if (cookie == (nfs_cookie4)0 || cookie == (nfs_cookie4)1) {
		/*
		 * Since nfsv4 readdir may not return entries for "." and "..",
		 * the client must recreate them:
		 * To find the correct nodeid, do the following:
		 * For current node, get nodeid from dnlc.
		 * - if current node is rootvp, set pnodeid to nodeid.
		 * - else if parent is in the dnlc, get its nodeid from there.
		 * - else add LOOKUPP+GETATTR to compound.
		 */
		nodeid = rp->r_attr.va_nodeid;
		if (vp->v_flag & VROOT) {
			pnodeid = nodeid;	/* root of mount point */
		} else {
			dvp = dnlc_lookup(vp, "..");
			if (dvp != NULL && dvp != DNLC_NO_VNODE) {
				/* parent in dnlc cache - no need for otw */
				pnodeid = VTOR4(dvp)->r_attr.va_nodeid;
			} else {
				/*
				 * parent not in dnlc cache,
				 * do lookupp to get its id
				 */
				num_ops = 5;
				pnodeid = 0; /* set later by getattr parent */
			}
			if (dvp)
				VN_RELE(dvp);
		}
	}
	recov_state.rs_flags = 0;
	recov_state.rs_num_retry_despite_err = 0;

	/* Save the original mount point security flavor */
	(void) save_mnt_secinfo(mi->mi_curr_serv);

recov_retry:
	args.ctag = TAG_READDIR;

	args.array = argop;
	args.array_len = num_ops;

	if (e.error = nfs4_start_fop(VTOMI4(vp), vp, NULL, OH_READDIR,
	    &recov_state, NULL)) {
		/*
		 * If readdir a node that is a stub for a crossed mount point,
		 * keep the original secinfo flavor for the current file
		 * system, not the crossed one.
		 */
		(void) check_mnt_secinfo(mi->mi_curr_serv, vp);
		rdc->error = e.error;
		return;
	}

	/*
	 * Determine which attrs to request for dirents.  This code
	 * must be protected by nfs4_start/end_fop because of r_server
	 * (which will change during failover recovery).
	 *
	 */
	if (rp->r_flags & (R4LOOKUP | R4READDIRWATTR)) {
		/*
		 * Get all vattr attrs plus filehandle and rdattr_error
		 */
		rd_bitsval = NFS4_VATTR_MASK |
		    FATTR4_RDATTR_ERROR_MASK |
		    FATTR4_FILEHANDLE_MASK;

		if (rp->r_flags & R4READDIRWATTR) {
			mutex_enter(&rp->r_statelock);
			rp->r_flags &= ~R4READDIRWATTR;
			mutex_exit(&rp->r_statelock);
		}
	} else {
		servinfo4_t *svp = rp->r_server;

		/*
		 * Already read directory. Use readdir with
		 * no attrs (except for mounted_on_fileid) for updates.
		 */
		rd_bitsval = FATTR4_RDATTR_ERROR_MASK;

		/*
		 * request mounted on fileid if supported, else request
		 * fileid.  maybe we should verify that fileid is supported
		 * and request something else if not.
		 */
		(void) nfs_rw_enter_sig(&svp->sv_lock, RW_READER, 0);
		if (svp->sv_supp_attrs & FATTR4_MOUNTED_ON_FILEID_MASK)
			rd_bitsval |= FATTR4_MOUNTED_ON_FILEID_MASK;
		nfs_rw_exit(&svp->sv_lock);
	}

	/* putfh directory fh */
	argop[0].argop = OP_CPUTFH;
	argop[0].nfs_argop4_u.opcputfh.sfh = rp->r_fh;

	argop[1].argop = OP_READDIR;
	rargs = &argop[1].nfs_argop4_u.opreaddir;
	/*
	 * 1 and 2 are reserved for client "." and ".." entry offset.
	 * cookie 0 should be used over-the-wire to start reading at
	 * the beginning of the directory excluding "." and "..".
	 */
	if (rdc->nfs4_cookie == 0 ||
	    rdc->nfs4_cookie == 1 ||
	    rdc->nfs4_cookie == 2) {
		rargs->cookie = (nfs_cookie4)0;
		rargs->cookieverf = 0;
	} else {
		rargs->cookie = (nfs_cookie4)rdc->nfs4_cookie;
		mutex_enter(&rp->r_statelock);
		rargs->cookieverf = rp->r_cookieverf4;
		mutex_exit(&rp->r_statelock);
	}
	rargs->dircount = MIN(rdc->buflen, mi->mi_tsize);
	rargs->maxcount = mi->mi_tsize;
	rargs->attr_request = rd_bitsval;
	rargs->rdc = rdc;
	rargs->dvp = vp;
	rargs->mi = mi;
	rargs->cr = cr;


	/*
	 * If count < than the minimum required, we return no entries
	 * and fail with EINVAL
	 */
	if (rargs->dircount < (DIRENT64_RECLEN(1) + DIRENT64_RECLEN(2))) {
		rdc->error = EINVAL;
		goto out;
	}

	if (args.array_len == 5) {
		/*
		 * Add lookupp and getattr for parent nodeid.
		 */
		argop[2].argop = OP_LOOKUPP;

		argop[3].argop = OP_GETFH;

		/* getattr parent */
		argop[4].argop = OP_GETATTR;
		argop[4].nfs_argop4_u.opgetattr.attr_request = NFS4_VATTR_MASK;
		argop[4].nfs_argop4_u.opgetattr.mi = mi;
	}

	doqueue = 1;

	if (mi->mi_io_kstats) {
		mutex_enter(&mi->mi_lock);
		kstat_runq_enter(KSTAT_IO_PTR(mi->mi_io_kstats));
		mutex_exit(&mi->mi_lock);
	}

	/* capture the time of this call */
	rargs->t = t = gethrtime();

	rfs4call(mi, &args, &res, cr, &doqueue, 0, &e);

	if (mi->mi_io_kstats) {
		mutex_enter(&mi->mi_lock);
		kstat_runq_exit(KSTAT_IO_PTR(mi->mi_io_kstats));
		mutex_exit(&mi->mi_lock);
	}

	needrecov = nfs4_needs_recovery(&e, FALSE, mi->mi_vfsp);

	/*
	 * If RPC error occurred and it isn't an error that
	 * triggers recovery, then go ahead and fail now.
	 */
	if (e.error != 0 && !needrecov) {
		rdc->error = e.error;
		goto out;
	}

	if (needrecov) {
		bool_t abort;

		NFS4_DEBUG(nfs4_client_recov_debug, (CE_NOTE,
		    "nfs4readdir: initiating recovery.\n"));

		abort = nfs4_start_recovery(&e, VTOMI4(vp), vp, NULL, NULL,
		    NULL, OP_READDIR, NULL, NULL, NULL);
		if (abort == FALSE) {
			nfs4_end_fop(VTOMI4(vp), vp, NULL, OH_READDIR,
			    &recov_state, needrecov);
			if (!e.error)
				(void) xdr_free(xdr_COMPOUND4res_clnt,
				    (caddr_t)&res);
			if (rdc->entries != NULL) {
				kmem_free(rdc->entries, rdc->entlen);
				rdc->entries = NULL;
			}
			goto recov_retry;
		}

		if (e.error != 0) {
			rdc->error = e.error;
			goto out;
		}

		/* fall through for res.status case */
	}

	res_opcnt = res.array_len;

	/*
	 * If compound failed first 2 ops (PUTFH+READDIR), then return
	 * failure here.  Subsequent ops are for filling out dot-dot
	 * dirent, and if they fail, we still want to give the caller
	 * the dirents returned by (the successful) READDIR op, so we need
	 * to silently ignore failure for subsequent ops (LOOKUPP+GETATTR).
	 *
	 * One example where PUTFH+READDIR ops would succeed but
	 * LOOKUPP+GETATTR would fail would be a dir that has r perm
	 * but lacks x.  In this case, a POSIX server's VOP_READDIR
	 * would succeed; however, VOP_LOOKUP(..) would fail since no
	 * x perm.  We need to come up with a non-vendor-specific way
	 * for a POSIX server to return d_ino from dotdot's dirent if
	 * client only requests mounted_on_fileid, and just say the
	 * LOOKUPP succeeded and fill out the GETATTR.  However, if
	 * client requested any mandatory attrs, server would be required
	 * to fail the GETATTR op because it can't call VOP_LOOKUP+VOP_GETATTR
	 * for dotdot.
	 */

	if (res.status) {
		if (res_opcnt <= 2) {
			e.error = geterrno4(res.status);
			nfs4_end_fop(VTOMI4(vp), vp, NULL, OH_READDIR,
			    &recov_state, needrecov);
			nfs4_purge_stale_fh(e.error, vp, cr);
			rdc->error = e.error;
			(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
			if (rdc->entries != NULL) {
				kmem_free(rdc->entries, rdc->entlen);
				rdc->entries = NULL;
			}
			/*
			 * If readdir a node that is a stub for a
			 * crossed mount point, keep the original
			 * secinfo flavor for the current file system,
			 * not the crossed one.
			 */
			(void) check_mnt_secinfo(mi->mi_curr_serv, vp);
			return;
		}
	}

	resop = &res.array[1];	/* readdir res */
	rd_res = &resop->nfs_resop4_u.opreaddirclnt;

	mutex_enter(&rp->r_statelock);
	rp->r_cookieverf4 = rd_res->cookieverf;
	mutex_exit(&rp->r_statelock);

	/*
	 * For "." and ".." entries
	 * e.g.
	 *	seek(cookie=0) -> "." entry with d_off = 1
	 *	seek(cookie=1) -> ".." entry with d_off = 2
	 */
	if (cookie == (nfs_cookie4) 0) {
		if (rd_res->dotp)
			rd_res->dotp->d_ino = nodeid;
		if (rd_res->dotdotp)
			rd_res->dotdotp->d_ino = pnodeid;
	}
	if (cookie == (nfs_cookie4) 1) {
		if (rd_res->dotdotp)
			rd_res->dotdotp->d_ino = pnodeid;
	}


	/* LOOKUPP+GETATTR attemped */
	if (args.array_len == 5 && rd_res->dotdotp) {
		if (res.status == NFS4_OK && res_opcnt == 5) {
			nfs_fh4 *fhp;
			nfs4_sharedfh_t *sfhp;
			vnode_t *pvp;
			nfs4_ga_res_t *garp;

			resop++;	/* lookupp */
			resop++;	/* getfh   */
			fhp = &resop->nfs_resop4_u.opgetfh.object;

			resop++;	/* getattr of parent */

			/*
			 * First, take care of finishing the
			 * readdir results.
			 */
			garp = &resop->nfs_resop4_u.opgetattr.ga_res;
			/*
			 * The d_ino of .. must be the inode number
			 * of the mounted filesystem.
			 */
			if (garp->n4g_va.va_mask & AT_NODEID)
				rd_res->dotdotp->d_ino =
				    garp->n4g_va.va_nodeid;


			/*
			 * Next, create the ".." dnlc entry
			 */
			sfhp = sfh4_get(fhp, mi);
			if (!nfs4_make_dotdot(sfhp, t, vp, cr, &pvp, 0)) {
				dnlc_update(vp, "..", pvp);
				VN_RELE(pvp);
			}
			sfh4_rele(&sfhp);
		}
	}

	if (mi->mi_io_kstats) {
		mutex_enter(&mi->mi_lock);
		KSTAT_IO_PTR(mi->mi_io_kstats)->reads++;
		KSTAT_IO_PTR(mi->mi_io_kstats)->nread += rdc->actlen;
		mutex_exit(&mi->mi_lock);
	}

	(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);

out:
	/*
	 * If readdir a node that is a stub for a crossed mount point,
	 * keep the original secinfo flavor for the current file system,
	 * not the crossed one.
	 */
	(void) check_mnt_secinfo(mi->mi_curr_serv, vp);

	nfs4_end_fop(mi, vp, NULL, OH_READDIR, &recov_state, needrecov);
}


static int
nfs4_bio(struct buf *bp, stable_how4 *stab_comm, cred_t *cr, bool_t readahead)
{
	rnode4_t *rp = VTOR4(bp->b_vp);
	int count;
	int error;
	cred_t *cred_otw = NULL;
	offset_t offset;
	nfs4_open_stream_t *osp = NULL;
	bool_t first_time = TRUE;	/* first time getting otw cred */
	bool_t last_time = FALSE;	/* last time getting otw cred */

	ASSERT(nfs_zone() == VTOMI4(bp->b_vp)->mi_zone);

	DTRACE_IO1(start, struct buf *, bp);
	offset = ldbtob(bp->b_lblkno);

	if (bp->b_flags & B_READ) {
	read_again:
		/*
		 * Releases the osp, if it is provided.
		 * Puts a hold on the cred_otw and the new osp (if found).
		 */
		cred_otw = nfs4_get_otw_cred_by_osp(rp, cr, &osp,
		    &first_time, &last_time);
		error = bp->b_error = nfs4read(bp->b_vp, bp->b_un.b_addr,
		    offset, bp->b_bcount, &bp->b_resid, cred_otw,
		    readahead, NULL);
		crfree(cred_otw);
		if (!error) {
			if (bp->b_resid) {
				/*
				 * Didn't get it all because we hit EOF,
				 * zero all the memory beyond the EOF.
				 */
				/* bzero(rdaddr + */
				bzero(bp->b_un.b_addr +
				    bp->b_bcount - bp->b_resid, bp->b_resid);
			}
			mutex_enter(&rp->r_statelock);
			if (bp->b_resid == bp->b_bcount &&
			    offset >= rp->r_size) {
				/*
				 * We didn't read anything at all as we are
				 * past EOF.  Return an error indicator back
				 * but don't destroy the pages (yet).
				 */
				error = NFS_EOF;
			}
			mutex_exit(&rp->r_statelock);
		} else if (error == EACCES && last_time == FALSE) {
				goto read_again;
		}
	} else {
		if (!(rp->r_flags & R4STALE)) {
write_again:
			/*
			 * Releases the osp, if it is provided.
			 * Puts a hold on the cred_otw and the new
			 * osp (if found).
			 */
			cred_otw = nfs4_get_otw_cred_by_osp(rp, cr, &osp,
			    &first_time, &last_time);
			mutex_enter(&rp->r_statelock);
			count = MIN(bp->b_bcount, rp->r_size - offset);
			mutex_exit(&rp->r_statelock);
			if (count < 0)
				cmn_err(CE_PANIC, "nfs4_bio: write count < 0");
#ifdef DEBUG
			if (count == 0) {
				zoneid_t zoneid = getzoneid();

				zcmn_err(zoneid, CE_WARN,
				    "nfs4_bio: zero length write at %lld",
				    offset);
				zcmn_err(zoneid, CE_CONT, "flags=0x%x, "
				    "b_bcount=%ld, file size=%lld",
				    rp->r_flags, (long)bp->b_bcount,
				    rp->r_size);
				sfh4_printfhandle(VTOR4(bp->b_vp)->r_fh);
				if (nfs4_bio_do_stop)
					debug_enter("nfs4_bio");
			}
#endif
			error = nfs4write(bp->b_vp, bp->b_un.b_addr, offset,
			    count, cred_otw, stab_comm);
			if (error == EACCES && last_time == FALSE) {
				crfree(cred_otw);
				goto write_again;
			}
			bp->b_error = error;
			if (error && error != EINTR &&
			    !(bp->b_vp->v_vfsp->vfs_flag & VFS_UNMOUNTED)) {
				/*
				 * Don't print EDQUOT errors on the console.
				 * Don't print asynchronous EACCES errors.
				 * Don't print EFBIG errors.
				 * Print all other write errors.
				 */
				if (error != EDQUOT && error != EFBIG &&
				    (error != EACCES ||
				    !(bp->b_flags & B_ASYNC)))
					nfs4_write_error(bp->b_vp,
					    error, cred_otw);
				/*
				 * Update r_error and r_flags as appropriate.
				 * If the error was ESTALE, then mark the
				 * rnode as not being writeable and save
				 * the error status.  Otherwise, save any
				 * errors which occur from asynchronous
				 * page invalidations.  Any errors occurring
				 * from other operations should be saved
				 * by the caller.
				 */
				mutex_enter(&rp->r_statelock);
				if (error == ESTALE) {
					rp->r_flags |= R4STALE;
					if (!rp->r_error)
						rp->r_error = error;
				} else if (!rp->r_error &&
				    (bp->b_flags &
				    (B_INVAL|B_FORCE|B_ASYNC)) ==
				    (B_INVAL|B_FORCE|B_ASYNC)) {
					rp->r_error = error;
				}
				mutex_exit(&rp->r_statelock);
			}
			crfree(cred_otw);
		} else {
			error = rp->r_error;
			/*
			 * A close may have cleared r_error, if so,
			 * propagate ESTALE error return properly
			 */
			if (error == 0)
				error = ESTALE;
		}
	}

	if (error != 0 && error != NFS_EOF)
		bp->b_flags |= B_ERROR;

	if (osp)
		open_stream_rele(osp, rp);

	DTRACE_IO1(done, struct buf *, bp);

	return (error);
}

/* ARGSUSED */
int
nfs4_fid(vnode_t *vp, fid_t *fidp, caller_context_t *ct)
{
	return (EREMOTE);
}

/* ARGSUSED2 */
int
nfs4_rwlock(vnode_t *vp, int write_lock, caller_context_t *ctp)
{
	rnode4_t *rp = VTOR4(vp);

	if (!write_lock) {
		(void) nfs_rw_enter_sig(&rp->r_rwlock, RW_READER, FALSE);
		return (V_WRITELOCK_FALSE);
	}

	if ((rp->r_flags & R4DIRECTIO) ||
	    (VTOMI4(vp)->mi_flags & MI4_DIRECTIO)) {
		(void) nfs_rw_enter_sig(&rp->r_rwlock, RW_READER, FALSE);
		if (rp->r_mapcnt == 0 && !nfs4_has_pages(vp))
			return (V_WRITELOCK_FALSE);
		nfs_rw_exit(&rp->r_rwlock);
	}

	(void) nfs_rw_enter_sig(&rp->r_rwlock, RW_WRITER, FALSE);
	return (V_WRITELOCK_TRUE);
}

/* ARGSUSED */
void
nfs4_rwunlock(vnode_t *vp, int write_lock, caller_context_t *ctp)
{
	rnode4_t *rp = VTOR4(vp);

	nfs_rw_exit(&rp->r_rwlock);
}

/* ARGSUSED */
static int
nfs4_seek(vnode_t *vp, offset_t ooff, offset_t *noffp, caller_context_t *ct)
{
	if (nfs_zone() != VTOMI4(vp)->mi_zone)
		return (EIO);

	/*
	 * Because we stuff the readdir cookie into the offset field
	 * someone may attempt to do an lseek with the cookie which
	 * we want to succeed.
	 */
	if (vp->v_type == VDIR)
		return (0);
	if (*noffp < 0)
		return (EINVAL);
	return (0);
}


/*
 * Return all the pages from [off..off+len) in file
 */
/* ARGSUSED */
static int
nfs4_getpage(vnode_t *vp, offset_t off, size_t len, uint_t *protp,
    page_t *pl[], size_t plsz, struct seg *seg, caddr_t addr,
	enum seg_rw rw, cred_t *cr, caller_context_t *ct)
{
	rnode4_t *rp;
	int error;
	mntinfo4_t *mi;

	if (nfs_zone() != VTOMI4(vp)->mi_zone)
		return (EIO);
	rp = VTOR4(vp);
	if (IS_SHADOW(vp, rp))
		vp = RTOV4(rp);

	if (vp->v_flag & VNOMAP)
		return (ENOSYS);

	if (protp != NULL)
		*protp = PROT_ALL;

	/*
	 * Now validate that the caches are up to date.
	 */
	if (error = nfs4_validate_caches(vp, cr))
		return (error);

	mi = VTOMI4(vp);
retry:
	mutex_enter(&rp->r_statelock);

	/*
	 * Don't create dirty pages faster than they
	 * can be cleaned so that the system doesn't
	 * get imbalanced.  If the async queue is
	 * maxed out, then wait for it to drain before
	 * creating more dirty pages.  Also, wait for
	 * any threads doing pagewalks in the vop_getattr
	 * entry points so that they don't block for
	 * long periods.
	 */
	if (rw == S_CREATE) {
		while ((mi->mi_max_threads != 0 &&
		    rp->r_awcount > 2 * mi->mi_max_threads) ||
		    rp->r_gcount > 0)
			cv_wait(&rp->r_cv, &rp->r_statelock);
	}

	/*
	 * If we are getting called as a side effect of an nfs_write()
	 * operation the local file size might not be extended yet.
	 * In this case we want to be able to return pages of zeroes.
	 */
	if (off + len > rp->r_size + PAGEOFFSET && seg != segkmap) {
		NFS4_DEBUG(nfs4_pageio_debug,
		    (CE_NOTE, "getpage beyond EOF: off=%lld, "
		    "len=%llu, size=%llu, attrsize =%llu", off,
		    (u_longlong_t)len, rp->r_size, rp->r_attr.va_size));
		mutex_exit(&rp->r_statelock);
		return (EFAULT);		/* beyond EOF */
	}

	mutex_exit(&rp->r_statelock);

	error = pvn_getpages(nfs4_getapage, vp, off, len, protp,
	    pl, plsz, seg, addr, rw, cr);
	NFS4_DEBUG(nfs4_pageio_debug && error,
	    (CE_NOTE, "getpages error %d; off=%lld, len=%lld",
	    error, off, (u_longlong_t)len));

	switch (error) {
	case NFS_EOF:
		nfs4_purge_caches(vp, NFS4_NOPURGE_DNLC, cr, FALSE);
		goto retry;
	case ESTALE:
		nfs4_purge_stale_fh(error, vp, cr);
	}

	return (error);
}

/*
 * Called from pvn_getpages to get a particular page.
 */
/* ARGSUSED */
static int
nfs4_getapage(vnode_t *vp, u_offset_t off, size_t len, uint_t *protp,
    page_t *pl[], size_t plsz, struct seg *seg, caddr_t addr,
    enum seg_rw rw, cred_t *cr)
{
	rnode4_t *rp;
	uint_t bsize;
	struct buf *bp;
	page_t *pp;
	u_offset_t lbn;
	u_offset_t io_off;
	u_offset_t blkoff;
	u_offset_t rablkoff;
	size_t io_len;
	uint_t blksize;
	int error;
	int readahead;
	int readahead_issued = 0;
	int ra_window; /* readahead window */
	page_t *pagefound;
	page_t *savepp;

	if (nfs_zone() != VTOMI4(vp)->mi_zone)
		return (EIO);

	rp = VTOR4(vp);
	ASSERT(!IS_SHADOW(vp, rp));
	bsize = MAX(vp->v_vfsp->vfs_bsize, PAGESIZE);

reread:
	bp = NULL;
	pp = NULL;
	pagefound = NULL;

	if (pl != NULL)
		pl[0] = NULL;

	error = 0;
	lbn = off / bsize;
	blkoff = lbn * bsize;

	/*
	 * Queueing up the readahead before doing the synchronous read
	 * results in a significant increase in read throughput because
	 * of the increased parallelism between the async threads and
	 * the process context.
	 */
	if ((off & ((vp->v_vfsp->vfs_bsize) - 1)) == 0 &&
	    rw != S_CREATE &&
	    !(vp->v_flag & VNOCACHE)) {
		mutex_enter(&rp->r_statelock);

		/*
		 * Calculate the number of readaheads to do.
		 * a) No readaheads at offset = 0.
		 * b) Do maximum(nfs4_nra) readaheads when the readahead
		 *    window is closed.
		 * c) Do readaheads between 1 to (nfs4_nra - 1) depending
		 *    upon how far the readahead window is open or close.
		 * d) No readaheads if rp->r_nextr is not within the scope
		 *    of the readahead window (random i/o).
		 */

		if (off == 0)
			readahead = 0;
		else if (blkoff == rp->r_nextr)
			readahead = nfs4_nra;
		else if (rp->r_nextr > blkoff &&
		    ((ra_window = (rp->r_nextr - blkoff) / bsize)
		    <= (nfs4_nra - 1)))
			readahead = nfs4_nra - ra_window;
		else
			readahead = 0;

		rablkoff = rp->r_nextr;
		while (readahead > 0 && rablkoff + bsize < rp->r_size) {
			mutex_exit(&rp->r_statelock);
			if (nfs4_async_readahead(vp, rablkoff + bsize,
			    addr + (rablkoff + bsize - off),
			    seg, cr, nfs4_readahead) < 0) {
				mutex_enter(&rp->r_statelock);
				break;
			}
			readahead--;
			rablkoff += bsize;
			/*
			 * Indicate that we did a readahead so
			 * readahead offset is not updated
			 * by the synchronous read below.
			 */
			readahead_issued = 1;
			mutex_enter(&rp->r_statelock);
			/*
			 * set readahead offset to
			 * offset of last async readahead
			 * request.
			 */
			rp->r_nextr = rablkoff;
		}
		mutex_exit(&rp->r_statelock);
	}

again:
	if ((pagefound = page_exists(vp, off)) == NULL) {
		if (pl == NULL) {
			(void) nfs4_async_readahead(vp, blkoff, addr, seg, cr,
			    nfs4_readahead);
		} else if (rw == S_CREATE) {
			/*
			 * Block for this page is not allocated, or the offset
			 * is beyond the current allocation size, or we're
			 * allocating a swap slot and the page was not found,
			 * so allocate it and return a zero page.
			 */
			if ((pp = page_create_va(vp, off,
			    PAGESIZE, PG_WAIT, seg, addr)) == NULL)
				cmn_err(CE_PANIC, "nfs4_getapage: page_create");
			io_len = PAGESIZE;
			mutex_enter(&rp->r_statelock);
			rp->r_nextr = off + PAGESIZE;
			mutex_exit(&rp->r_statelock);
		} else {
			/*
			 * Need to go to server to get a block
			 */
			mutex_enter(&rp->r_statelock);
			if (blkoff < rp->r_size &&
			    blkoff + bsize > rp->r_size) {
				/*
				 * If less than a block left in
				 * file read less than a block.
				 */
				if (rp->r_size <= off) {
					/*
					 * Trying to access beyond EOF,
					 * set up to get at least one page.
					 */
					blksize = off + PAGESIZE - blkoff;
				} else
					blksize = rp->r_size - blkoff;
			} else if ((off == 0) ||
			    (off != rp->r_nextr && !readahead_issued)) {
				blksize = PAGESIZE;
				blkoff = off; /* block = page here */
			} else
				blksize = bsize;
			mutex_exit(&rp->r_statelock);

			pp = pvn_read_kluster(vp, off, seg, addr, &io_off,
			    &io_len, blkoff, blksize, 0);

			/*
			 * Some other thread has entered the page,
			 * so just use it.
			 */
			if (pp == NULL)
				goto again;

			/*
			 * Now round the request size up to page boundaries.
			 * This ensures that the entire page will be
			 * initialized to zeroes if EOF is encountered.
			 */
			io_len = ptob(btopr(io_len));

			bp = pageio_setup(pp, io_len, vp, B_READ);
			ASSERT(bp != NULL);

			/*
			 * pageio_setup should have set b_addr to 0.  This
			 * is correct since we want to do I/O on a page
			 * boundary.  bp_mapin will use this addr to calculate
			 * an offset, and then set b_addr to the kernel virtual
			 * address it allocated for us.
			 */
			ASSERT(bp->b_un.b_addr == 0);

			bp->b_edev = 0;
			bp->b_dev = 0;
			bp->b_lblkno = lbtodb(io_off);
			bp->b_file = vp;
			bp->b_offset = (offset_t)off;
			bp_mapin(bp);

			/*
			 * If doing a write beyond what we believe is EOF,
			 * don't bother trying to read the pages from the
			 * server, we'll just zero the pages here.  We
			 * don't check that the rw flag is S_WRITE here
			 * because some implementations may attempt a
			 * read access to the buffer before copying data.
			 */
			mutex_enter(&rp->r_statelock);
			if (io_off >= rp->r_size && seg == segkmap) {
				mutex_exit(&rp->r_statelock);
				bzero(bp->b_un.b_addr, io_len);
			} else {
				mutex_exit(&rp->r_statelock);
				error = nfs4_bio(bp, NULL, cr, FALSE);
			}

			/*
			 * Unmap the buffer before freeing it.
			 */
			bp_mapout(bp);
			pageio_done(bp);

			savepp = pp;
			do {
				pp->p_fsdata = C_NOCOMMIT;
			} while ((pp = pp->p_next) != savepp);

			if (error == NFS_EOF) {
				/*
				 * If doing a write system call just return
				 * zeroed pages, else user tried to get pages
				 * beyond EOF, return error.  We don't check
				 * that the rw flag is S_WRITE here because
				 * some implementations may attempt a read
				 * access to the buffer before copying data.
				 */
				if (seg == segkmap)
					error = 0;
				else
					error = EFAULT;
			}

			if (!readahead_issued && !error) {
				mutex_enter(&rp->r_statelock);
				rp->r_nextr = io_off + io_len;
				mutex_exit(&rp->r_statelock);
			}
		}
	}

out:
	if (pl == NULL)
		return (error);

	if (error) {
		if (pp != NULL)
			pvn_read_done(pp, B_ERROR);
		return (error);
	}

	if (pagefound) {
		se_t se = (rw == S_CREATE ? SE_EXCL : SE_SHARED);

		/*
		 * Page exists in the cache, acquire the appropriate lock.
		 * If this fails, start all over again.
		 */
		if ((pp = page_lookup(vp, off, se)) == NULL) {
#ifdef DEBUG
			nfs4_lostpage++;
#endif
			goto reread;
		}
		pl[0] = pp;
		pl[1] = NULL;
		return (0);
	}

	if (pp != NULL)
		pvn_plist_init(pp, pl, plsz, off, io_len, rw);

	return (error);
}

static void
nfs4_readahead(vnode_t *vp, u_offset_t blkoff, caddr_t addr, struct seg *seg,
    cred_t *cr)
{
	int error;
	page_t *pp;
	u_offset_t io_off;
	size_t io_len;
	struct buf *bp;
	uint_t bsize, blksize;
	rnode4_t *rp = VTOR4(vp);
	page_t *savepp;

	ASSERT(nfs_zone() == VTOMI4(vp)->mi_zone);

	bsize = MAX(vp->v_vfsp->vfs_bsize, PAGESIZE);

	mutex_enter(&rp->r_statelock);
	if (blkoff < rp->r_size && blkoff + bsize > rp->r_size) {
		/*
		 * If less than a block left in file read less
		 * than a block.
		 */
		blksize = rp->r_size - blkoff;
	} else
		blksize = bsize;
	mutex_exit(&rp->r_statelock);

	pp = pvn_read_kluster(vp, blkoff, segkmap, addr,
	    &io_off, &io_len, blkoff, blksize, 1);
	/*
	 * The isra flag passed to the kluster function is 1, we may have
	 * gotten a return value of NULL for a variety of reasons (# of free
	 * pages < minfree, someone entered the page on the vnode etc). In all
	 * cases, we want to punt on the readahead.
	 */
	if (pp == NULL)
		return;

	/*
	 * Now round the request size up to page boundaries.
	 * This ensures that the entire page will be
	 * initialized to zeroes if EOF is encountered.
	 */
	io_len = ptob(btopr(io_len));

	bp = pageio_setup(pp, io_len, vp, B_READ);
	ASSERT(bp != NULL);

	/*
	 * pageio_setup should have set b_addr to 0.  This is correct since
	 * we want to do I/O on a page boundary. bp_mapin() will use this addr
	 * to calculate an offset, and then set b_addr to the kernel virtual
	 * address it allocated for us.
	 */
	ASSERT(bp->b_un.b_addr == 0);

	bp->b_edev = 0;
	bp->b_dev = 0;
	bp->b_lblkno = lbtodb(io_off);
	bp->b_file = vp;
	bp->b_offset = (offset_t)blkoff;
	bp_mapin(bp);

	/*
	 * If doing a write beyond what we believe is EOF, don't bother trying
	 * to read the pages from the server, we'll just zero the pages here.
	 * We don't check that the rw flag is S_WRITE here because some
	 * implementations may attempt a read access to the buffer before
	 * copying data.
	 */
	mutex_enter(&rp->r_statelock);
	if (io_off >= rp->r_size && seg == segkmap) {
		mutex_exit(&rp->r_statelock);
		bzero(bp->b_un.b_addr, io_len);
		error = 0;
	} else {
		mutex_exit(&rp->r_statelock);
		error = nfs4_bio(bp, NULL, cr, TRUE);
		if (error == NFS_EOF)
			error = 0;
	}

	/*
	 * Unmap the buffer before freeing it.
	 */
	bp_mapout(bp);
	pageio_done(bp);

	savepp = pp;
	do {
		pp->p_fsdata = C_NOCOMMIT;
	} while ((pp = pp->p_next) != savepp);

	pvn_read_done(pp, error ? B_READ | B_ERROR : B_READ);

	/*
	 * In case of error set readahead offset
	 * to the lowest offset.
	 * pvn_read_done() calls VN_DISPOSE to destroy the pages
	 */
	if (error && rp->r_nextr > io_off) {
		mutex_enter(&rp->r_statelock);
		if (rp->r_nextr > io_off)
			rp->r_nextr = io_off;
		mutex_exit(&rp->r_statelock);
	}
}

/*
 * Flags are composed of {B_INVAL, B_FREE, B_DONTNEED, B_FORCE}
 * If len == 0, do from off to EOF.
 *
 * The normal cases should be len == 0 && off == 0 (entire vp list) or
 * len == MAXBSIZE (from segmap_release actions), and len == PAGESIZE
 * (from pageout).
 */
/* ARGSUSED */
static int
nfs4_putpage(vnode_t *vp, offset_t off, size_t len, int flags, cred_t *cr,
	caller_context_t *ct)
{
	int error;
	rnode4_t *rp;

	ASSERT(cr != NULL);

	if (!(flags & B_ASYNC) && nfs_zone() != VTOMI4(vp)->mi_zone)
		return (EIO);

	rp = VTOR4(vp);
	if (IS_SHADOW(vp, rp))
		vp = RTOV4(rp);

	/*
	 * XXX - Why should this check be made here?
	 */
	if (vp->v_flag & VNOMAP)
		return (ENOSYS);

	if (len == 0 && !(flags & B_INVAL) &&
	    (vp->v_vfsp->vfs_flag & VFS_RDONLY))
		return (0);

	mutex_enter(&rp->r_statelock);
	rp->r_count++;
	mutex_exit(&rp->r_statelock);
	error = nfs4_putpages(vp, off, len, flags, cr);
	mutex_enter(&rp->r_statelock);
	rp->r_count--;
	cv_broadcast(&rp->r_cv);
	mutex_exit(&rp->r_statelock);

	return (error);
}

/*
 * Write out a single page, possibly klustering adjacent dirty pages.
 */
int
nfs4_putapage(vnode_t *vp, page_t *pp, u_offset_t *offp, size_t *lenp,
    int flags, cred_t *cr)
{
	u_offset_t io_off;
	u_offset_t lbn_off;
	u_offset_t lbn;
	size_t io_len;
	uint_t bsize;
	int error;
	rnode4_t *rp;

	ASSERT(!(vp->v_vfsp->vfs_flag & VFS_RDONLY));
	ASSERT(pp != NULL);
	ASSERT(cr != NULL);
	ASSERT((flags & B_ASYNC) || nfs_zone() == VTOMI4(vp)->mi_zone);

	rp = VTOR4(vp);
	ASSERT(rp->r_count > 0);
	ASSERT(!IS_SHADOW(vp, rp));

	bsize = MAX(vp->v_vfsp->vfs_bsize, PAGESIZE);
	lbn = pp->p_offset / bsize;
	lbn_off = lbn * bsize;

	/*
	 * Find a kluster that fits in one block, or in
	 * one page if pages are bigger than blocks.  If
	 * there is less file space allocated than a whole
	 * page, we'll shorten the i/o request below.
	 */
	pp = pvn_write_kluster(vp, pp, &io_off, &io_len, lbn_off,
	    roundup(bsize, PAGESIZE), flags);

	/*
	 * pvn_write_kluster shouldn't have returned a page with offset
	 * behind the original page we were given.  Verify that.
	 */
	ASSERT((pp->p_offset / bsize) >= lbn);

	/*
	 * Now pp will have the list of kept dirty pages marked for
	 * write back.  It will also handle invalidation and freeing
	 * of pages that are not dirty.  Check for page length rounding
	 * problems.
	 */
	if (io_off + io_len > lbn_off + bsize) {
		ASSERT((io_off + io_len) - (lbn_off + bsize) < PAGESIZE);
		io_len = lbn_off + bsize - io_off;
	}
	/*
	 * The R4MODINPROGRESS flag makes sure that nfs4_bio() sees a
	 * consistent value of r_size. R4MODINPROGRESS is set in writerp4().
	 * When R4MODINPROGRESS is set it indicates that a uiomove() is in
	 * progress and the r_size has not been made consistent with the
	 * new size of the file. When the uiomove() completes the r_size is
	 * updated and the R4MODINPROGRESS flag is cleared.
	 *
	 * The R4MODINPROGRESS flag makes sure that nfs4_bio() sees a
	 * consistent value of r_size. Without this handshaking, it is
	 * possible that nfs4_bio() picks  up the old value of r_size
	 * before the uiomove() in writerp4() completes. This will result
	 * in the write through nfs4_bio() being dropped.
	 *
	 * More precisely, there is a window between the time the uiomove()
	 * completes and the time the r_size is updated. If a VOP_PUTPAGE()
	 * operation intervenes in this window, the page will be picked up,
	 * because it is dirty (it will be unlocked, unless it was
	 * pagecreate'd). When the page is picked up as dirty, the dirty
	 * bit is reset (pvn_getdirty()). In nfs4write(), r_size is
	 * checked. This will still be the old size. Therefore the page will
	 * not be written out. When segmap_release() calls VOP_PUTPAGE(),
	 * the page will be found to be clean and the write will be dropped.
	 */
	if (rp->r_flags & R4MODINPROGRESS) {
		mutex_enter(&rp->r_statelock);
		if ((rp->r_flags & R4MODINPROGRESS) &&
		    rp->r_modaddr + MAXBSIZE > io_off &&
		    rp->r_modaddr < io_off + io_len) {
			page_t *plist;
			/*
			 * A write is in progress for this region of the file.
			 * If we did not detect R4MODINPROGRESS here then this
			 * path through nfs_putapage() would eventually go to
			 * nfs4_bio() and may not write out all of the data
			 * in the pages. We end up losing data. So we decide
			 * to set the modified bit on each page in the page
			 * list and mark the rnode with R4DIRTY. This write
			 * will be restarted at some later time.
			 */
			plist = pp;
			while (plist != NULL) {
				pp = plist;
				page_sub(&plist, pp);
				hat_setmod(pp);
				page_io_unlock(pp);
				page_unlock(pp);
			}
			rp->r_flags |= R4DIRTY;
			mutex_exit(&rp->r_statelock);
			if (offp)
				*offp = io_off;
			if (lenp)
				*lenp = io_len;
			return (0);
		}
		mutex_exit(&rp->r_statelock);
	}

	if (flags & B_ASYNC) {
		error = nfs4_async_putapage(vp, pp, io_off, io_len, flags, cr,
		    nfs4_sync_putapage);
	} else
		error = nfs4_sync_putapage(vp, pp, io_off, io_len, flags, cr);

	if (offp)
		*offp = io_off;
	if (lenp)
		*lenp = io_len;
	return (error);
}

static int
nfs4_sync_putapage(vnode_t *vp, page_t *pp, u_offset_t io_off, size_t io_len,
    int flags, cred_t *cr)
{
	int error;
	rnode4_t *rp;

	ASSERT(nfs_zone() == VTOMI4(vp)->mi_zone);

	flags |= B_WRITE;

	error = nfs4_rdwrlbn(vp, pp, io_off, io_len, flags, cr);

	rp = VTOR4(vp);

	if ((error == ENOSPC || error == EDQUOT || error == EFBIG ||
	    error == EACCES) &&
	    (flags & (B_INVAL|B_FORCE)) != (B_INVAL|B_FORCE)) {
		if (!(rp->r_flags & R4OUTOFSPACE)) {
			mutex_enter(&rp->r_statelock);
			rp->r_flags |= R4OUTOFSPACE;
			mutex_exit(&rp->r_statelock);
		}
		flags |= B_ERROR;
		pvn_write_done(pp, flags);
		/*
		 * If this was not an async thread, then try again to
		 * write out the pages, but this time, also destroy
		 * them whether or not the write is successful.  This
		 * will prevent memory from filling up with these
		 * pages and destroying them is the only alternative
		 * if they can't be written out.
		 *
		 * Don't do this if this is an async thread because
		 * when the pages are unlocked in pvn_write_done,
		 * some other thread could have come along, locked
		 * them, and queued for an async thread.  It would be
		 * possible for all of the async threads to be tied
		 * up waiting to lock the pages again and they would
		 * all already be locked and waiting for an async
		 * thread to handle them.  Deadlock.
		 */
		if (!(flags & B_ASYNC)) {
			error = nfs4_putpage(vp, io_off, io_len,
			    B_INVAL | B_FORCE, cr, NULL);
		}
	} else {
		if (error)
			flags |= B_ERROR;
		else if (rp->r_flags & R4OUTOFSPACE) {
			mutex_enter(&rp->r_statelock);
			rp->r_flags &= ~R4OUTOFSPACE;
			mutex_exit(&rp->r_statelock);
		}
		pvn_write_done(pp, flags);
		if (freemem < desfree)
			(void) nfs4_commit_vp(vp, (u_offset_t)0, 0, cr,
			    NFS4_WRITE_NOWAIT);
	}

	return (error);
}

#ifdef DEBUG
int nfs4_force_open_before_mmap = 0;
#endif

/* ARGSUSED */
static int
nfs4_map(vnode_t *vp, offset_t off, struct as *as, caddr_t *addrp,
    size_t len, uchar_t prot, uchar_t maxprot, uint_t flags, cred_t *cr,
    caller_context_t *ct)
{
	struct segvn_crargs vn_a;
	int error = 0;
	rnode4_t *rp = VTOR4(vp);
	mntinfo4_t *mi = VTOMI4(vp);

	if (nfs_zone() != VTOMI4(vp)->mi_zone)
		return (EIO);

	if (vp->v_flag & VNOMAP)
		return (ENOSYS);

	if (off < 0 || (off + len) < 0)
		return (ENXIO);

	if (vp->v_type != VREG)
		return (ENODEV);

	/*
	 * If the file is delegated to the client don't do anything.
	 * If the file is not delegated, then validate the data cache.
	 */
	mutex_enter(&rp->r_statev4_lock);
	if (rp->r_deleg_type == OPEN_DELEGATE_NONE) {
		mutex_exit(&rp->r_statev4_lock);
		error = nfs4_validate_caches(vp, cr);
		if (error)
			return (error);
	} else {
		mutex_exit(&rp->r_statev4_lock);
	}

	/*
	 * Check to see if the vnode is currently marked as not cachable.
	 * This means portions of the file are locked (through VOP_FRLOCK).
	 * In this case the map request must be refused.  We use
	 * rp->r_lkserlock to avoid a race with concurrent lock requests.
	 *
	 * Atomically increment r_inmap after acquiring r_rwlock. The
	 * idea here is to acquire r_rwlock to block read/write and
	 * not to protect r_inmap. r_inmap will inform nfs4_read/write()
	 * that we are in nfs4_map(). Now, r_rwlock is acquired in order
	 * and we can prevent the deadlock that would have occurred
	 * when nfs4_addmap() would have acquired it out of order.
	 *
	 * Since we are not protecting r_inmap by any lock, we do not
	 * hold any lock when we decrement it. We atomically decrement
	 * r_inmap after we release r_lkserlock.
	 */

	if (nfs_rw_enter_sig(&rp->r_rwlock, RW_WRITER, INTR4(vp)))
		return (EINTR);
	atomic_inc_uint(&rp->r_inmap);
	nfs_rw_exit(&rp->r_rwlock);

	if (nfs_rw_enter_sig(&rp->r_lkserlock, RW_READER, INTR4(vp))) {
		atomic_dec_uint(&rp->r_inmap);
		return (EINTR);
	}


	if (vp->v_flag & VNOCACHE) {
		error = EAGAIN;
		goto done;
	}

	/*
	 * Don't allow concurrent locks and mapping if mandatory locking is
	 * enabled.
	 */
	if (flk_has_remote_locks(vp)) {
		struct vattr va;
		va.va_mask = AT_MODE;
		error = nfs4getattr(vp, &va, cr);
		if (error != 0)
			goto done;
		if (MANDLOCK(vp, va.va_mode)) {
			error = EAGAIN;
			goto done;
		}
	}

	/*
	 * It is possible that the rnode has a lost lock request that we
	 * are still trying to recover, and that the request conflicts with
	 * this map request.
	 *
	 * An alternative approach would be for nfs4_safemap() to consider
	 * queued lock requests when deciding whether to set or clear
	 * VNOCACHE.  This would require the frlock code path to call
	 * nfs4_safemap() after enqueing a lost request.
	 */
	if (nfs4_map_lost_lock_conflict(vp)) {
		error = EAGAIN;
		goto done;
	}

	as_rangelock(as);
	error = choose_addr(as, addrp, len, off, ADDR_VACALIGN, flags);
	if (error != 0) {
		as_rangeunlock(as);
		goto done;
	}

	if (vp->v_type == VREG) {
		/*
		 * We need to retrieve the open stream
		 */
		nfs4_open_stream_t	*osp = NULL;
		nfs4_open_owner_t	*oop = NULL;

		oop = find_open_owner(cr, NFS4_PERM_CREATED, mi);
		if (oop != NULL) {
			/* returns with 'os_sync_lock' held */
			osp = find_open_stream(oop, rp);
			open_owner_rele(oop);
		}
		if (osp == NULL) {
#ifdef DEBUG
			if (nfs4_force_open_before_mmap) {
				error = EIO;
				goto done;
			}
#endif
			/* returns with 'os_sync_lock' held */
			error = open_and_get_osp(vp, cr, &osp);
			if (osp == NULL) {
				NFS4_DEBUG(nfs4_mmap_debug, (CE_NOTE,
				    "nfs4_map: we tried to OPEN the file "
				    "but again no osp, so fail with EIO"));
				goto done;
			}
		}

		if (osp->os_failed_reopen) {
			mutex_exit(&osp->os_sync_lock);
			open_stream_rele(osp, rp);
			NFS4_DEBUG(nfs4_open_stream_debug, (CE_NOTE,
			    "nfs4_map: os_failed_reopen set on "
			    "osp %p, cr %p, rp %s", (void *)osp,
			    (void *)cr, rnode4info(rp)));
			error = EIO;
			goto done;
		}
		mutex_exit(&osp->os_sync_lock);
		open_stream_rele(osp, rp);
	}

	vn_a.vp = vp;
	vn_a.offset = off;
	vn_a.type = (flags & MAP_TYPE);
	vn_a.prot = (uchar_t)prot;
	vn_a.maxprot = (uchar_t)maxprot;
	vn_a.flags = (flags & ~MAP_TYPE);
	vn_a.cred = cr;
	vn_a.amp = NULL;
	vn_a.szc = 0;
	vn_a.lgrp_mem_policy_flags = 0;

	error = as_map(as, *addrp, len, segvn_create, &vn_a);
	as_rangeunlock(as);

done:
	nfs_rw_exit(&rp->r_lkserlock);
	atomic_dec_uint(&rp->r_inmap);
	return (error);
}

/*
 * We're most likely dealing with a kernel module that likes to READ
 * and mmap without OPENing the file (ie: lookup/read/mmap), so lets
 * officially OPEN the file to create the necessary client state
 * for bookkeeping of os_mmap_read/write counts.
 *
 * Since VOP_MAP only passes in a pointer to the vnode rather than
 * a double pointer, we can't handle the case where nfs4open_otw()
 * returns a different vnode than the one passed into VOP_MAP (since
 * VOP_DELMAP will not see the vnode nfs4open_otw used).  In this case,
 * we return NULL and let nfs4_map() fail.  Note: the only case where
 * this should happen is if the file got removed and replaced with the
 * same name on the server (in addition to the fact that we're trying
 * to VOP_MAP withouth VOP_OPENing the file in the first place).
 */
static int
open_and_get_osp(vnode_t *map_vp, cred_t *cr, nfs4_open_stream_t **ospp)
{
	rnode4_t		*rp, *drp;
	vnode_t			*dvp, *open_vp;
	char			file_name[MAXNAMELEN];
	int			just_created;
	nfs4_open_stream_t	*osp;
	nfs4_open_owner_t	*oop;
	int			error;

	*ospp = NULL;
	open_vp = map_vp;

	rp = VTOR4(open_vp);
	if ((error = vtodv(open_vp, &dvp, cr, TRUE)) != 0)
		return (error);
	drp = VTOR4(dvp);

	if (nfs_rw_enter_sig(&drp->r_rwlock, RW_READER, INTR4(dvp))) {
		VN_RELE(dvp);
		return (EINTR);
	}

	if ((error = vtoname(open_vp, file_name, MAXNAMELEN)) != 0) {
		nfs_rw_exit(&drp->r_rwlock);
		VN_RELE(dvp);
		return (error);
	}

	mutex_enter(&rp->r_statev4_lock);
	if (rp->created_v4) {
		rp->created_v4 = 0;
		mutex_exit(&rp->r_statev4_lock);

		dnlc_update(dvp, file_name, open_vp);
		/* This is needed so we don't bump the open ref count */
		just_created = 1;
	} else {
		mutex_exit(&rp->r_statev4_lock);
		just_created = 0;
	}

	VN_HOLD(map_vp);

	error = nfs4open_otw(dvp, file_name, NULL, &open_vp, cr, 0, FREAD, 0,
	    just_created);
	if (error) {
		nfs_rw_exit(&drp->r_rwlock);
		VN_RELE(dvp);
		VN_RELE(map_vp);
		return (error);
	}

	nfs_rw_exit(&drp->r_rwlock);
	VN_RELE(dvp);

	/*
	 * If nfs4open_otw() returned a different vnode then "undo"
	 * the open and return failure to the caller.
	 */
	if (!VN_CMP(open_vp, map_vp)) {
		nfs4_error_t e;

		NFS4_DEBUG(nfs4_mmap_debug, (CE_NOTE, "open_and_get_osp: "
		    "open returned a different vnode"));
		/*
		 * If there's an error, ignore it,
		 * and let VOP_INACTIVE handle it.
		 */
		(void) nfs4close_one(open_vp, NULL, cr, FREAD, NULL, &e,
		    CLOSE_NORM, 0, 0, 0);
		VN_RELE(map_vp);
		return (EIO);
	}

	VN_RELE(map_vp);

	oop = find_open_owner(cr, NFS4_PERM_CREATED, VTOMI4(open_vp));
	if (!oop) {
		nfs4_error_t e;

		NFS4_DEBUG(nfs4_mmap_debug, (CE_NOTE, "open_and_get_osp: "
		    "no open owner"));
		/*
		 * If there's an error, ignore it,
		 * and let VOP_INACTIVE handle it.
		 */
		(void) nfs4close_one(open_vp, NULL, cr, FREAD, NULL, &e,
		    CLOSE_NORM, 0, 0, 0);
		return (EIO);
	}
	osp = find_open_stream(oop, rp);
	open_owner_rele(oop);
	*ospp = osp;
	return (0);
}

/*
 * Please be aware that when this function is called, the address space write
 * a_lock is held.  Do not put over the wire calls in this function.
 */
/* ARGSUSED */
static int
nfs4_addmap(vnode_t *vp, offset_t off, struct as *as, caddr_t addr,
    size_t len, uchar_t prot, uchar_t maxprot, uint_t flags, cred_t *cr,
    caller_context_t *ct)
{
	rnode4_t		*rp;
	int			error = 0;
	mntinfo4_t		*mi;

	mi = VTOMI4(vp);
	rp = VTOR4(vp);

	if (nfs_zone() != mi->mi_zone)
		return (EIO);
	if (vp->v_flag & VNOMAP)
		return (ENOSYS);

	/*
	 * Don't need to update the open stream first, since this
	 * mmap can't add any additional share access that isn't
	 * already contained in the open stream (for the case where we
	 * open/mmap/only update rp->r_mapcnt/server reboots/reopen doesn't
	 * take into account os_mmap_read[write] counts).
	 */
	atomic_add_long((ulong_t *)&rp->r_mapcnt, btopr(len));

	if (vp->v_type == VREG) {
		/*
		 * We need to retrieve the open stream and update the counts.
		 * If there is no open stream here, something is wrong.
		 */
		nfs4_open_stream_t	*osp = NULL;
		nfs4_open_owner_t	*oop = NULL;

		oop = find_open_owner(cr, NFS4_PERM_CREATED, mi);
		if (oop != NULL) {
			/* returns with 'os_sync_lock' held */
			osp = find_open_stream(oop, rp);
			open_owner_rele(oop);
		}
		if (osp == NULL) {
			NFS4_DEBUG(nfs4_mmap_debug, (CE_NOTE,
			    "nfs4_addmap: we should have an osp"
			    "but we don't, so fail with EIO"));
			error = EIO;
			goto out;
		}

		NFS4_DEBUG(nfs4_mmap_debug, (CE_NOTE, "nfs4_addmap: osp %p,"
		    " pages %ld, prot 0x%x", (void *)osp, btopr(len), prot));

		/*
		 * Update the map count in the open stream.
		 * This is necessary in the case where we
		 * open/mmap/close/, then the server reboots, and we
		 * attempt to reopen.  If the mmap doesn't add share
		 * access then we send an invalid reopen with
		 * access = NONE.
		 *
		 * We need to specifically check each PROT_* so a mmap
		 * call of (PROT_WRITE | PROT_EXEC) will ensure us both
		 * read and write access.  A simple comparison of prot
		 * to ~PROT_WRITE to determine read access is insufficient
		 * since prot can be |= with PROT_USER, etc.
		 */

		/*
		 * Unless we're MAP_SHARED, no sense in adding os_mmap_write
		 */
		if ((flags & MAP_SHARED) && (maxprot & PROT_WRITE))
			osp->os_mmap_write += btopr(len);
		if (maxprot & PROT_READ)
			osp->os_mmap_read += btopr(len);
		if (maxprot & PROT_EXEC)
			osp->os_mmap_read += btopr(len);
		/*
		 * Ensure that os_mmap_read gets incremented, even if
		 * maxprot were to look like PROT_NONE.
		 */
		if (!(maxprot & PROT_READ) && !(maxprot & PROT_WRITE) &&
		    !(maxprot & PROT_EXEC))
			osp->os_mmap_read += btopr(len);
		osp->os_mapcnt += btopr(len);
		mutex_exit(&osp->os_sync_lock);
		open_stream_rele(osp, rp);
	}

out:
	/*
	 * If we got an error, then undo our
	 * incrementing of 'r_mapcnt'.
	 */

	if (error) {
		atomic_add_long((ulong_t *)&rp->r_mapcnt, -btopr(len));
		ASSERT(rp->r_mapcnt >= 0);
	}
	return (error);
}

/* ARGSUSED */
static int
nfs4_cmp(vnode_t *vp1, vnode_t *vp2, caller_context_t *ct)
{

	return (VTOR4(vp1) == VTOR4(vp2));
}

/* ARGSUSED */
static int
nfs4_frlock(vnode_t *vp, int cmd, struct flock64 *bfp, int flag,
    offset_t offset, struct flk_callback *flk_cbp, cred_t *cr,
    caller_context_t *ct)
{
	int rc;
	u_offset_t start, end;
	rnode4_t *rp;
	int error = 0, intr = INTR4(vp);
	nfs4_error_t e;

	if (nfs_zone() != VTOMI4(vp)->mi_zone)
		return (EIO);

	/* check for valid cmd parameter */
	if (cmd != F_GETLK && cmd != F_SETLK && cmd != F_SETLKW)
		return (EINVAL);

	/* Verify l_type. */
	switch (bfp->l_type) {
	case F_RDLCK:
		if (cmd != F_GETLK && !(flag & FREAD))
			return (EBADF);
		break;
	case F_WRLCK:
		if (cmd != F_GETLK && !(flag & FWRITE))
			return (EBADF);
		break;
	case F_UNLCK:
		intr = 0;
		break;

	default:
		return (EINVAL);
	}

	/* check the validity of the lock range */
	if (rc = flk_convert_lock_data(vp, bfp, &start, &end, offset))
		return (rc);
	if (rc = flk_check_lock_data(start, end, MAXEND))
		return (rc);

	/*
	 * If the filesystem is mounted using local locking, pass the
	 * request off to the local locking code.
	 */
	if (VTOMI4(vp)->mi_flags & MI4_LLOCK || vp->v_type != VREG) {
		if (cmd == F_SETLK || cmd == F_SETLKW) {
			/*
			 * For complete safety, we should be holding
			 * r_lkserlock.  However, we can't call
			 * nfs4_safelock and then fs_frlock while
			 * holding r_lkserlock, so just invoke
			 * nfs4_safelock and expect that this will
			 * catch enough of the cases.
			 */
			if (!nfs4_safelock(vp, bfp, cr))
				return (EAGAIN);
		}
		return (fs_frlock(vp, cmd, bfp, flag, offset, flk_cbp, cr, ct));
	}

	rp = VTOR4(vp);

	/*
	 * Check whether the given lock request can proceed, given the
	 * current file mappings.
	 */
	if (nfs_rw_enter_sig(&rp->r_lkserlock, RW_WRITER, intr))
		return (EINTR);
	if (cmd == F_SETLK || cmd == F_SETLKW) {
		if (!nfs4_safelock(vp, bfp, cr)) {
			rc = EAGAIN;
			goto done;
		}
	}

	/*
	 * Flush the cache after waiting for async I/O to finish.  For new
	 * locks, this is so that the process gets the latest bits from the
	 * server.  For unlocks, this is so that other clients see the
	 * latest bits once the file has been unlocked.  If currently dirty
	 * pages can't be flushed, then don't allow a lock to be set.  But
	 * allow unlocks to succeed, to avoid having orphan locks on the
	 * server.
	 */
	if (cmd != F_GETLK) {
		mutex_enter(&rp->r_statelock);
		while (rp->r_count > 0) {
			if (intr) {
				klwp_t *lwp = ttolwp(curthread);

				if (lwp != NULL)
					lwp->lwp_nostop++;
				if (cv_wait_sig(&rp->r_cv,
				    &rp->r_statelock) == 0) {
					if (lwp != NULL)
						lwp->lwp_nostop--;
					rc = EINTR;
					break;
				}
				if (lwp != NULL)
					lwp->lwp_nostop--;
				} else
					cv_wait(&rp->r_cv, &rp->r_statelock);
		}
		mutex_exit(&rp->r_statelock);
		if (rc != 0)
			goto done;
		error = nfs4_putpage(vp, (offset_t)0, 0, B_INVAL, cr, ct);
		if (error) {
			if (error == ENOSPC || error == EDQUOT) {
				mutex_enter(&rp->r_statelock);
				if (!rp->r_error)
					rp->r_error = error;
				mutex_exit(&rp->r_statelock);
			}
			if (bfp->l_type != F_UNLCK) {
				rc = ENOLCK;
				goto done;
			}
		}
	}

	/*
	 * Call the lock manager to do the real work of contacting
	 * the server and obtaining the lock.
	 */
	nfs4frlock(NFS4_LCK_CTYPE_NORM, vp, cmd, bfp, flag, offset,
	    cr, &e, NULL, NULL);
	rc = e.error;

	if (rc == 0)
		nfs4_lockcompletion(vp, cmd);

done:
	nfs_rw_exit(&rp->r_lkserlock);

	return (rc);
}

/*
 * Free storage space associated with the specified vnode.  The portion
 * to be freed is specified by bfp->l_start and bfp->l_len (already
 * normalized to a "whence" of 0).
 *
 * This is an experimental facility whose continued existence is not
 * guaranteed.  Currently, we only support the special case
 * of l_len == 0, meaning free to end of file.
 */
/* ARGSUSED */
static int
nfs4_space(vnode_t *vp, int cmd, struct flock64 *bfp, int flag,
    offset_t offset, cred_t *cr, caller_context_t *ct)
{
	int error;

	if (nfs_zone() != VTOMI4(vp)->mi_zone)
		return (EIO);
	ASSERT(vp->v_type == VREG);
	if (cmd != F_FREESP)
		return (EINVAL);

	error = convoff(vp, bfp, 0, offset);
	if (!error) {
		ASSERT(bfp->l_start >= 0);
		if (bfp->l_len == 0) {
			struct vattr va;

			va.va_mask = AT_SIZE;
			va.va_size = bfp->l_start;
			error = nfs4setattr(vp, &va, 0, cr, NULL);

			if (error == 0 && bfp->l_start == 0)
				vnevent_truncate(vp, ct);
		} else
			error = EINVAL;
	}

	return (error);
}

/* ARGSUSED */
int
nfs4_realvp(vnode_t *vp, vnode_t **vpp, caller_context_t *ct)
{
	rnode4_t *rp;
	rp = VTOR4(vp);

	if (vp->v_type == VREG && IS_SHADOW(vp, rp)) {
		vp = RTOV4(rp);
	}
	*vpp = vp;
	return (0);
}

/*
 * Setup and add an address space callback to do the work of the delmap call.
 * The callback will (and must be) deleted in the actual callback function.
 *
 * This is done in order to take care of the problem that we have with holding
 * the address space's a_lock for a long period of time (e.g. if the NFS server
 * is down).  Callbacks will be executed in the address space code while the
 * a_lock is not held.  Holding the address space's a_lock causes things such
 * as ps and fork to hang because they are trying to acquire this lock as well.
 */
/* ARGSUSED */
static int
nfs4_delmap(vnode_t *vp, offset_t off, struct as *as, caddr_t addr,
    size_t len, uint_t prot, uint_t maxprot, uint_t flags, cred_t *cr,
    caller_context_t *ct)
{
	int			caller_found;
	int			error;
	rnode4_t		*rp;
	nfs4_delmap_args_t	*dmapp;
	nfs4_delmapcall_t	*delmap_call;

	if (vp->v_flag & VNOMAP)
		return (ENOSYS);

	/*
	 * A process may not change zones if it has NFS pages mmap'ed
	 * in, so we can't legitimately get here from the wrong zone.
	 */
	ASSERT(nfs_zone() == VTOMI4(vp)->mi_zone);

	rp = VTOR4(vp);

	/*
	 * The way that the address space of this process deletes its mapping
	 * of this file is via the following call chains:
	 * - as_free()->SEGOP_UNMAP()/segvn_unmap()->VOP_DELMAP()/nfs4_delmap()
	 * - as_unmap()->SEGOP_UNMAP()/segvn_unmap()->VOP_DELMAP()/nfs4_delmap()
	 *
	 * With the use of address space callbacks we are allowed to drop the
	 * address space lock, a_lock, while executing the NFS operations that
	 * need to go over the wire.  Returning EAGAIN to the caller of this
	 * function is what drives the execution of the callback that we add
	 * below.  The callback will be executed by the address space code
	 * after dropping the a_lock.  When the callback is finished, since
	 * we dropped the a_lock, it must be re-acquired and segvn_unmap()
	 * is called again on the same segment to finish the rest of the work
	 * that needs to happen during unmapping.
	 *
	 * This action of calling back into the segment driver causes
	 * nfs4_delmap() to get called again, but since the callback was
	 * already executed at this point, it already did the work and there
	 * is nothing left for us to do.
	 *
	 * To Summarize:
	 * - The first time nfs4_delmap is called by the current thread is when
	 * we add the caller associated with this delmap to the delmap caller
	 * list, add the callback, and return EAGAIN.
	 * - The second time in this call chain when nfs4_delmap is called we
	 * will find this caller in the delmap caller list and realize there
	 * is no more work to do thus removing this caller from the list and
	 * returning the error that was set in the callback execution.
	 */
	caller_found = nfs4_find_and_delete_delmapcall(rp, &error);
	if (caller_found) {
		/*
		 * 'error' is from the actual delmap operations.  To avoid
		 * hangs, we need to handle the return of EAGAIN differently
		 * since this is what drives the callback execution.
		 * In this case, we don't want to return EAGAIN and do the
		 * callback execution because there are none to execute.
		 */
		if (error == EAGAIN)
			return (0);
		else
			return (error);
	}

	/* current caller was not in the list */
	delmap_call = nfs4_init_delmapcall();

	mutex_enter(&rp->r_statelock);
	list_insert_tail(&rp->r_indelmap, delmap_call);
	mutex_exit(&rp->r_statelock);

	dmapp = kmem_alloc(sizeof (nfs4_delmap_args_t), KM_SLEEP);

	dmapp->vp = vp;
	dmapp->off = off;
	dmapp->addr = addr;
	dmapp->len = len;
	dmapp->prot = prot;
	dmapp->maxprot = maxprot;
	dmapp->flags = flags;
	dmapp->cr = cr;
	dmapp->caller = delmap_call;

	error = as_add_callback(as, nfs4_delmap_callback, dmapp,
	    AS_UNMAP_EVENT, addr, len, KM_SLEEP);

	return (error ? error : EAGAIN);
}

static nfs4_delmapcall_t *
nfs4_init_delmapcall()
{
	nfs4_delmapcall_t	*delmap_call;

	delmap_call = kmem_alloc(sizeof (nfs4_delmapcall_t), KM_SLEEP);
	delmap_call->call_id = curthread;
	delmap_call->error = 0;

	return (delmap_call);
}

static void
nfs4_free_delmapcall(nfs4_delmapcall_t *delmap_call)
{
	kmem_free(delmap_call, sizeof (nfs4_delmapcall_t));
}

/*
 * Searches for the current delmap caller (based on curthread) in the list of
 * callers.  If it is found, we remove it and free the delmap caller.
 * Returns:
 *      0 if the caller wasn't found
 *      1 if the caller was found, removed and freed.  *errp will be set
 *	to what the result of the delmap was.
 */
static int
nfs4_find_and_delete_delmapcall(rnode4_t *rp, int *errp)
{
	nfs4_delmapcall_t	*delmap_call;

	/*
	 * If the list doesn't exist yet, we create it and return
	 * that the caller wasn't found.  No list = no callers.
	 */
	mutex_enter(&rp->r_statelock);
	if (!(rp->r_flags & R4DELMAPLIST)) {
		/* The list does not exist */
		list_create(&rp->r_indelmap, sizeof (nfs4_delmapcall_t),
		    offsetof(nfs4_delmapcall_t, call_node));
		rp->r_flags |= R4DELMAPLIST;
		mutex_exit(&rp->r_statelock);
		return (0);
	} else {
		/* The list exists so search it */
		for (delmap_call = list_head(&rp->r_indelmap);
		    delmap_call != NULL;
		    delmap_call = list_next(&rp->r_indelmap, delmap_call)) {
			if (delmap_call->call_id == curthread) {
				/* current caller is in the list */
				*errp = delmap_call->error;
				list_remove(&rp->r_indelmap, delmap_call);
				mutex_exit(&rp->r_statelock);
				nfs4_free_delmapcall(delmap_call);
				return (1);
			}
		}
	}
	mutex_exit(&rp->r_statelock);
	return (0);
}

/*
 * Remove some pages from an mmap'd vnode.  Just update the
 * count of pages.  If doing close-to-open, then flush and
 * commit all of the pages associated with this file.
 * Otherwise, start an asynchronous page flush to write out
 * any dirty pages.  This will also associate a credential
 * with the rnode which can be used to write the pages.
 */
/* ARGSUSED */
static void
nfs4_delmap_callback(struct as *as, void *arg, uint_t event)
{
	nfs4_error_t		e = { 0, NFS4_OK, RPC_SUCCESS };
	rnode4_t		*rp;
	mntinfo4_t		*mi;
	nfs4_delmap_args_t	*dmapp = (nfs4_delmap_args_t *)arg;

	rp = VTOR4(dmapp->vp);
	mi = VTOMI4(dmapp->vp);

	atomic_add_long((ulong_t *)&rp->r_mapcnt, -btopr(dmapp->len));
	ASSERT(rp->r_mapcnt >= 0);

	/*
	 * Initiate a page flush and potential commit if there are
	 * pages, the file system was not mounted readonly, the segment
	 * was mapped shared, and the pages themselves were writeable.
	 */
	if (nfs4_has_pages(dmapp->vp) &&
	    !(dmapp->vp->v_vfsp->vfs_flag & VFS_RDONLY) &&
	    dmapp->flags == MAP_SHARED && (dmapp->maxprot & PROT_WRITE)) {
		mutex_enter(&rp->r_statelock);
		rp->r_flags |= R4DIRTY;
		mutex_exit(&rp->r_statelock);
		e.error = nfs4_putpage_commit(dmapp->vp, dmapp->off,
		    dmapp->len, dmapp->cr);
		if (!e.error) {
			mutex_enter(&rp->r_statelock);
			e.error = rp->r_error;
			rp->r_error = 0;
			mutex_exit(&rp->r_statelock);
		}
	} else
		e.error = 0;

	if ((rp->r_flags & R4DIRECTIO) || (mi->mi_flags & MI4_DIRECTIO))
		(void) nfs4_putpage(dmapp->vp, dmapp->off, dmapp->len,
		    B_INVAL, dmapp->cr, NULL);

	if (e.error) {
		e.stat = puterrno4(e.error);
		nfs4_queue_fact(RF_DELMAP_CB_ERR, mi, e.stat, 0,
		    OP_COMMIT, FALSE, NULL, 0, dmapp->vp);
		dmapp->caller->error = e.error;
	}

	/* Check to see if we need to close the file */

	if (dmapp->vp->v_type == VREG) {
		nfs4close_one(dmapp->vp, NULL, dmapp->cr, 0, NULL, &e,
		    CLOSE_DELMAP, dmapp->len, dmapp->maxprot, dmapp->flags);

		if (e.error != 0 || e.stat != NFS4_OK) {
			/*
			 * Since it is possible that e.error == 0 and
			 * e.stat != NFS4_OK (and vice versa),
			 * we do the proper checking in order to get both
			 * e.error and e.stat reporting the correct info.
			 */
			if (e.stat == NFS4_OK)
				e.stat = puterrno4(e.error);
			if (e.error == 0)
				e.error = geterrno4(e.stat);

			nfs4_queue_fact(RF_DELMAP_CB_ERR, mi, e.stat, 0,
			    OP_CLOSE, FALSE, NULL, 0, dmapp->vp);
			dmapp->caller->error = e.error;
		}
	}

	(void) as_delete_callback(as, arg);
	kmem_free(dmapp, sizeof (nfs4_delmap_args_t));
}


static uint_t
fattr4_maxfilesize_to_bits(uint64_t ll)
{
	uint_t l = 1;

	if (ll == 0) {
		return (0);
	}

	if (ll & 0xffffffff00000000) {
		l += 32; ll >>= 32;
	}
	if (ll & 0xffff0000) {
		l += 16; ll >>= 16;
	}
	if (ll & 0xff00) {
		l += 8; ll >>= 8;
	}
	if (ll & 0xf0) {
		l += 4; ll >>= 4;
	}
	if (ll & 0xc) {
		l += 2; ll >>= 2;
	}
	if (ll & 0x2) {
		l += 1;
	}
	return (l);
}

static int
nfs4_have_xattrs(vnode_t *vp, ulong_t *valp, cred_t *cr)
{
	vnode_t *avp = NULL;
	int error;

	if ((error = nfs4lookup_xattr(vp, "", &avp,
	    LOOKUP_XATTR, cr)) == 0)
		error = do_xattr_exists_check(avp, valp, cr);
	if (avp)
		VN_RELE(avp);

	return (error);
}

/* ARGSUSED */
int
nfs4_pathconf(vnode_t *vp, int cmd, ulong_t *valp, cred_t *cr,
	caller_context_t *ct)
{
	int error;
	hrtime_t t;
	rnode4_t *rp;
	nfs4_ga_res_t gar;
	nfs4_ga_ext_res_t ger;

	gar.n4g_ext_res = &ger;

	if (nfs_zone() != VTOMI4(vp)->mi_zone)
		return (EIO);
	if (cmd == _PC_PATH_MAX || cmd == _PC_SYMLINK_MAX) {
		*valp = MAXPATHLEN;
		return (0);
	}
	if (cmd == _PC_ACL_ENABLED) {
		*valp = _ACL_ACE_ENABLED;
		return (0);
	}

	rp = VTOR4(vp);
	if (cmd == _PC_XATTR_EXISTS) {
		/*
		 * The existence of the xattr directory is not sufficient
		 * for determining whether generic user attributes exists.
		 * The attribute directory could only be a transient directory
		 * used for Solaris sysattr support.  Do a small readdir
		 * to verify if the only entries are sysattrs or not.
		 *
		 * pc4_xattr_valid can be only be trusted when r_xattr_dir
		 * is NULL.  Once the xadir vp exists, we can create xattrs,
		 * and we don't have any way to update the "base" object's
		 * pc4_xattr_exists from the xattr or xadir.  Maybe FEM
		 * could help out.
		 */
		if (ATTRCACHE4_VALID(vp) && rp->r_pathconf.pc4_xattr_valid &&
		    rp->r_xattr_dir == NULL) {
			return (nfs4_have_xattrs(vp, valp, cr));
		}
	} else {  /* OLD CODE */
		if (ATTRCACHE4_VALID(vp)) {
			mutex_enter(&rp->r_statelock);
			if (rp->r_pathconf.pc4_cache_valid) {
				error = 0;
				switch (cmd) {
				case _PC_FILESIZEBITS:
					*valp =
					    rp->r_pathconf.pc4_filesizebits;
					break;
				case _PC_LINK_MAX:
					*valp =
					    rp->r_pathconf.pc4_link_max;
					break;
				case _PC_NAME_MAX:
					*valp =
					    rp->r_pathconf.pc4_name_max;
					break;
				case _PC_CHOWN_RESTRICTED:
					*valp =
					    rp->r_pathconf.pc4_chown_restricted;
					break;
				case _PC_NO_TRUNC:
					*valp =
					    rp->r_pathconf.pc4_no_trunc;
					break;
				default:
					error = EINVAL;
					break;
				}
				mutex_exit(&rp->r_statelock);
#ifdef DEBUG
				nfs4_pathconf_cache_hits++;
#endif
				return (error);
			}
			mutex_exit(&rp->r_statelock);
		}
	}
#ifdef DEBUG
	nfs4_pathconf_cache_misses++;
#endif

	t = gethrtime();

	error = nfs4_attr_otw(vp, TAG_PATHCONF, &gar, NFS4_PATHCONF_MASK, cr);

	if (error) {
		mutex_enter(&rp->r_statelock);
		rp->r_pathconf.pc4_cache_valid = FALSE;
		rp->r_pathconf.pc4_xattr_valid = FALSE;
		mutex_exit(&rp->r_statelock);
		return (error);
	}

	/* interpret the max filesize */
	gar.n4g_ext_res->n4g_pc4.pc4_filesizebits =
	    fattr4_maxfilesize_to_bits(gar.n4g_ext_res->n4g_maxfilesize);

	/* Store the attributes we just received */
	nfs4_attr_cache(vp, &gar, t, cr, TRUE, NULL);

	switch (cmd) {
	case _PC_FILESIZEBITS:
		*valp = gar.n4g_ext_res->n4g_pc4.pc4_filesizebits;
		break;
	case _PC_LINK_MAX:
		*valp = gar.n4g_ext_res->n4g_pc4.pc4_link_max;
		break;
	case _PC_NAME_MAX:
		*valp = gar.n4g_ext_res->n4g_pc4.pc4_name_max;
		break;
	case _PC_CHOWN_RESTRICTED:
		*valp = gar.n4g_ext_res->n4g_pc4.pc4_chown_restricted;
		break;
	case _PC_NO_TRUNC:
		*valp = gar.n4g_ext_res->n4g_pc4.pc4_no_trunc;
		break;
	case _PC_XATTR_EXISTS:
		if (gar.n4g_ext_res->n4g_pc4.pc4_xattr_exists) {
			if (error = nfs4_have_xattrs(vp, valp, cr))
				return (error);
		}
		break;
	default:
		return (EINVAL);
	}

	return (0);
}

/*
 * Called by async thread to do synchronous pageio. Do the i/o, wait
 * for it to complete, and cleanup the page list when done.
 */
static int
nfs4_sync_pageio(vnode_t *vp, page_t *pp, u_offset_t io_off, size_t io_len,
    int flags, cred_t *cr)
{
	int error;

	ASSERT(nfs_zone() == VTOMI4(vp)->mi_zone);

	error = nfs4_rdwrlbn(vp, pp, io_off, io_len, flags, cr);
	if (flags & B_READ)
		pvn_read_done(pp, (error ? B_ERROR : 0) | flags);
	else
		pvn_write_done(pp, (error ? B_ERROR : 0) | flags);
	return (error);
}

/* ARGSUSED */
static int
nfs4_pageio(vnode_t *vp, page_t *pp, u_offset_t io_off, size_t io_len,
	int flags, cred_t *cr, caller_context_t *ct)
{
	int error;
	rnode4_t *rp;

	if (!(flags & B_ASYNC) && nfs_zone() != VTOMI4(vp)->mi_zone)
		return (EIO);

	if (pp == NULL)
		return (EINVAL);

	rp = VTOR4(vp);
	mutex_enter(&rp->r_statelock);
	rp->r_count++;
	mutex_exit(&rp->r_statelock);

	if (flags & B_ASYNC) {
		error = nfs4_async_pageio(vp, pp, io_off, io_len, flags, cr,
		    nfs4_sync_pageio);
	} else
		error = nfs4_rdwrlbn(vp, pp, io_off, io_len, flags, cr);
	mutex_enter(&rp->r_statelock);
	rp->r_count--;
	cv_broadcast(&rp->r_cv);
	mutex_exit(&rp->r_statelock);
	return (error);
}

/* ARGSUSED */
static void
nfs4_dispose(vnode_t *vp, page_t *pp, int fl, int dn, cred_t *cr,
	caller_context_t *ct)
{
	int error;
	rnode4_t *rp;
	page_t *plist;
	page_t *pptr;
	offset3 offset;
	count3 len;
	k_sigset_t smask;

	/*
	 * We should get called with fl equal to either B_FREE or
	 * B_INVAL.  Any other value is illegal.
	 *
	 * The page that we are either supposed to free or destroy
	 * should be exclusive locked and its io lock should not
	 * be held.
	 */
	ASSERT(fl == B_FREE || fl == B_INVAL);
	ASSERT((PAGE_EXCL(pp) && !page_iolock_assert(pp)) || panicstr);

	rp = VTOR4(vp);

	/*
	 * If the page doesn't need to be committed or we shouldn't
	 * even bother attempting to commit it, then just make sure
	 * that the p_fsdata byte is clear and then either free or
	 * destroy the page as appropriate.
	 */
	if (pp->p_fsdata == C_NOCOMMIT || (rp->r_flags & R4STALE)) {
		pp->p_fsdata = C_NOCOMMIT;
		if (fl == B_FREE)
			page_free(pp, dn);
		else
			page_destroy(pp, dn);
		return;
	}

	/*
	 * If there is a page invalidation operation going on, then
	 * if this is one of the pages being destroyed, then just
	 * clear the p_fsdata byte and then either free or destroy
	 * the page as appropriate.
	 */
	mutex_enter(&rp->r_statelock);
	if ((rp->r_flags & R4TRUNCATE) && pp->p_offset >= rp->r_truncaddr) {
		mutex_exit(&rp->r_statelock);
		pp->p_fsdata = C_NOCOMMIT;
		if (fl == B_FREE)
			page_free(pp, dn);
		else
			page_destroy(pp, dn);
		return;
	}

	/*
	 * If we are freeing this page and someone else is already
	 * waiting to do a commit, then just unlock the page and
	 * return.  That other thread will take care of commiting
	 * this page.  The page can be freed sometime after the
	 * commit has finished.  Otherwise, if the page is marked
	 * as delay commit, then we may be getting called from
	 * pvn_write_done, one page at a time.   This could result
	 * in one commit per page, so we end up doing lots of small
	 * commits instead of fewer larger commits.  This is bad,
	 * we want do as few commits as possible.
	 */
	if (fl == B_FREE) {
		if (rp->r_flags & R4COMMITWAIT) {
			page_unlock(pp);
			mutex_exit(&rp->r_statelock);
			return;
		}
		if (pp->p_fsdata == C_DELAYCOMMIT) {
			pp->p_fsdata = C_COMMIT;
			page_unlock(pp);
			mutex_exit(&rp->r_statelock);
			return;
		}
	}

	/*
	 * Check to see if there is a signal which would prevent an
	 * attempt to commit the pages from being successful.  If so,
	 * then don't bother with all of the work to gather pages and
	 * generate the unsuccessful RPC.  Just return from here and
	 * let the page be committed at some later time.
	 */
	sigintr(&smask, VTOMI4(vp)->mi_flags & MI4_INT);
	if (ttolwp(curthread) != NULL && ISSIG(curthread, JUSTLOOKING)) {
		sigunintr(&smask);
		page_unlock(pp);
		mutex_exit(&rp->r_statelock);
		return;
	}
	sigunintr(&smask);

	/*
	 * We are starting to need to commit pages, so let's try
	 * to commit as many as possible at once to reduce the
	 * overhead.
	 *
	 * Set the `commit inprogress' state bit.  We must
	 * first wait until any current one finishes.  Then
	 * we initialize the c_pages list with this page.
	 */
	while (rp->r_flags & R4COMMIT) {
		rp->r_flags |= R4COMMITWAIT;
		cv_wait(&rp->r_commit.c_cv, &rp->r_statelock);
		rp->r_flags &= ~R4COMMITWAIT;
	}
	rp->r_flags |= R4COMMIT;
	mutex_exit(&rp->r_statelock);
	ASSERT(rp->r_commit.c_pages == NULL);
	rp->r_commit.c_pages = pp;
	rp->r_commit.c_commbase = (offset3)pp->p_offset;
	rp->r_commit.c_commlen = PAGESIZE;

	/*
	 * Gather together all other pages which can be committed.
	 * They will all be chained off r_commit.c_pages.
	 */
	nfs4_get_commit(vp);

	/*
	 * Clear the `commit inprogress' status and disconnect
	 * the list of pages to be committed from the rnode.
	 * At this same time, we also save the starting offset
	 * and length of data to be committed on the server.
	 */
	plist = rp->r_commit.c_pages;
	rp->r_commit.c_pages = NULL;
	offset = rp->r_commit.c_commbase;
	len = rp->r_commit.c_commlen;
	mutex_enter(&rp->r_statelock);
	rp->r_flags &= ~R4COMMIT;
	cv_broadcast(&rp->r_commit.c_cv);
	mutex_exit(&rp->r_statelock);

	if (curproc == proc_pageout || curproc == proc_fsflush ||
	    nfs_zone() != VTOMI4(vp)->mi_zone) {
		nfs4_async_commit(vp, plist, offset, len,
		    cr, do_nfs4_async_commit);
		return;
	}

	/*
	 * Actually generate the COMMIT op over the wire operation.
	 */
	error = nfs4_commit(vp, (offset4)offset, (count4)len, cr);

	/*
	 * If we got an error during the commit, just unlock all
	 * of the pages.  The pages will get retransmitted to the
	 * server during a putpage operation.
	 */
	if (error) {
		while (plist != NULL) {
			pptr = plist;
			page_sub(&plist, pptr);
			page_unlock(pptr);
		}
		return;
	}

	/*
	 * We've tried as hard as we can to commit the data to stable
	 * storage on the server.  We just unlock the rest of the pages
	 * and clear the commit required state.  They will be put
	 * onto the tail of the cachelist if they are nolonger
	 * mapped.
	 */
	while (plist != pp) {
		pptr = plist;
		page_sub(&plist, pptr);
		pptr->p_fsdata = C_NOCOMMIT;
		page_unlock(pptr);
	}

	/*
	 * It is possible that nfs4_commit didn't return error but
	 * some other thread has modified the page we are going
	 * to free/destroy.
	 *    In this case we need to rewrite the page. Do an explicit check
	 * before attempting to free/destroy the page. If modified, needs to
	 * be rewritten so unlock the page and return.
	 */
	if (hat_ismod(pp)) {
		pp->p_fsdata = C_NOCOMMIT;
		page_unlock(pp);
		return;
	}

	/*
	 * Now, as appropriate, either free or destroy the page
	 * that we were called with.
	 */
	pp->p_fsdata = C_NOCOMMIT;
	if (fl == B_FREE)
		page_free(pp, dn);
	else
		page_destroy(pp, dn);
}

/*
 * Commit requires that the current fh be the file written to.
 * The compound op structure is:
 *      PUTFH(file), COMMIT
 */
static int
nfs4_commit(vnode_t *vp, offset4 offset, count4 count, cred_t *cr)
{
	COMPOUND4args_clnt args;
	COMPOUND4res_clnt res;
	COMMIT4res *cm_res;
	nfs_argop4 argop[2];
	nfs_resop4 *resop;
	int doqueue;
	mntinfo4_t *mi;
	rnode4_t *rp;
	cred_t *cred_otw = NULL;
	bool_t needrecov = FALSE;
	nfs4_recov_state_t recov_state;
	nfs4_open_stream_t *osp = NULL;
	bool_t first_time = TRUE;	/* first time getting OTW cred */
	bool_t last_time = FALSE;	/* last time getting OTW cred */
	nfs4_error_t e = { 0, NFS4_OK, RPC_SUCCESS };

	ASSERT(nfs_zone() == VTOMI4(vp)->mi_zone);

	rp = VTOR4(vp);

	mi = VTOMI4(vp);
	recov_state.rs_flags = 0;
	recov_state.rs_num_retry_despite_err = 0;
get_commit_cred:
	/*
	 * Releases the osp, if a valid open stream is provided.
	 * Puts a hold on the cred_otw and the new osp (if found).
	 */
	cred_otw = nfs4_get_otw_cred_by_osp(rp, cr, &osp,
	    &first_time, &last_time);
	args.ctag = TAG_COMMIT;
recov_retry:
	/*
	 * Commit ops: putfh file; commit
	 */
	args.array_len = 2;
	args.array = argop;

	e.error = nfs4_start_fop(VTOMI4(vp), vp, NULL, OH_COMMIT,
	    &recov_state, NULL);
	if (e.error) {
		crfree(cred_otw);
		if (osp != NULL)
			open_stream_rele(osp, rp);
		return (e.error);
	}

	/* putfh directory */
	argop[0].argop = OP_CPUTFH;
	argop[0].nfs_argop4_u.opcputfh.sfh = rp->r_fh;

	/* commit */
	argop[1].argop = OP_COMMIT;
	argop[1].nfs_argop4_u.opcommit.offset = offset;
	argop[1].nfs_argop4_u.opcommit.count = count;

	doqueue = 1;
	rfs4call(mi, &args, &res, cred_otw, &doqueue, 0, &e);

	needrecov = nfs4_needs_recovery(&e, FALSE, mi->mi_vfsp);
	if (!needrecov && e.error) {
		nfs4_end_fop(VTOMI4(vp), vp, NULL, OH_COMMIT, &recov_state,
		    needrecov);
		crfree(cred_otw);
		if (e.error == EACCES && last_time == FALSE)
			goto get_commit_cred;
		if (osp != NULL)
			open_stream_rele(osp, rp);
		return (e.error);
	}

	if (needrecov) {
		if (nfs4_start_recovery(&e, VTOMI4(vp), vp, NULL, NULL,
		    NULL, OP_COMMIT, NULL, NULL, NULL) == FALSE) {
			nfs4_end_fop(VTOMI4(vp), vp, NULL, OH_COMMIT,
			    &recov_state, needrecov);
			if (!e.error)
				(void) xdr_free(xdr_COMPOUND4res_clnt,
				    (caddr_t)&res);
			goto recov_retry;
		}
		if (e.error) {
			nfs4_end_fop(VTOMI4(vp), vp, NULL, OH_COMMIT,
			    &recov_state, needrecov);
			crfree(cred_otw);
			if (osp != NULL)
				open_stream_rele(osp, rp);
			return (e.error);
		}
		/* fall through for res.status case */
	}

	if (res.status) {
		e.error = geterrno4(res.status);
		if (e.error == EACCES && last_time == FALSE) {
			crfree(cred_otw);
			nfs4_end_fop(VTOMI4(vp), vp, NULL, OH_COMMIT,
			    &recov_state, needrecov);
			(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
			goto get_commit_cred;
		}
		/*
		 * Can't do a nfs4_purge_stale_fh here because this
		 * can cause a deadlock.  nfs4_commit can
		 * be called from nfs4_dispose which can be called
		 * indirectly via pvn_vplist_dirty.  nfs4_purge_stale_fh
		 * can call back to pvn_vplist_dirty.
		 */
		if (e.error == ESTALE) {
			mutex_enter(&rp->r_statelock);
			rp->r_flags |= R4STALE;
			if (!rp->r_error)
				rp->r_error = e.error;
			mutex_exit(&rp->r_statelock);
			PURGE_ATTRCACHE4(vp);
		} else {
			mutex_enter(&rp->r_statelock);
			if (!rp->r_error)
				rp->r_error = e.error;
			mutex_exit(&rp->r_statelock);
		}
	} else {
		ASSERT(rp->r_flags & R4HAVEVERF);
		resop = &res.array[1];	/* commit res */
		cm_res = &resop->nfs_resop4_u.opcommit;
		mutex_enter(&rp->r_statelock);
		if (cm_res->writeverf == rp->r_writeverf) {
			mutex_exit(&rp->r_statelock);
			(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
			nfs4_end_fop(VTOMI4(vp), vp, NULL, OH_COMMIT,
			    &recov_state, needrecov);
			crfree(cred_otw);
			if (osp != NULL)
				open_stream_rele(osp, rp);
			return (0);
		}
		nfs4_set_mod(vp);
		rp->r_writeverf = cm_res->writeverf;
		mutex_exit(&rp->r_statelock);
		e.error = NFS_VERF_MISMATCH;
	}

	(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
	nfs4_end_fop(VTOMI4(vp), vp, NULL, OH_COMMIT, &recov_state, needrecov);
	crfree(cred_otw);
	if (osp != NULL)
		open_stream_rele(osp, rp);

	return (e.error);
}

static void
nfs4_set_mod(vnode_t *vp)
{
	ASSERT(nfs_zone() == VTOMI4(vp)->mi_zone);

	/* make sure we're looking at the master vnode, not a shadow */
	pvn_vplist_setdirty(RTOV4(VTOR4(vp)), nfs_setmod_check);
}

/*
 * This function is used to gather a page list of the pages which
 * can be committed on the server.
 *
 * The calling thread must have set R4COMMIT.  This bit is used to
 * serialize access to the commit structure in the rnode.  As long
 * as the thread has set R4COMMIT, then it can manipulate the commit
 * structure without requiring any other locks.
 *
 * When this function is called from nfs4_dispose() the page passed
 * into nfs4_dispose() will be SE_EXCL locked, and so this function
 * will skip it. This is not a problem since we initially add the
 * page to the r_commit page list.
 *
 */
static void
nfs4_get_commit(vnode_t *vp)
{
	rnode4_t *rp;
	page_t *pp;
	kmutex_t *vphm;

	rp = VTOR4(vp);

	ASSERT(rp->r_flags & R4COMMIT);

	/* make sure we're looking at the master vnode, not a shadow */

	if (IS_SHADOW(vp, rp))
		vp = RTOV4(rp);

	vphm = page_vnode_mutex(vp);
	mutex_enter(vphm);

	/*
	 * If there are no pages associated with this vnode, then
	 * just return.
	 */
	if ((pp = vp->v_pages) == NULL) {
		mutex_exit(vphm);
		return;
	}

	/*
	 * Step through all of the pages associated with this vnode
	 * looking for pages which need to be committed.
	 */
	do {
		/* Skip marker pages. */
		if (pp->p_hash == PVN_VPLIST_HASH_TAG)
			continue;

		/*
		 * First short-cut everything (without the page_lock)
		 * and see if this page does not need to be committed
		 * or is modified if so then we'll just skip it.
		 */
		if (pp->p_fsdata == C_NOCOMMIT || hat_ismod(pp))
			continue;

		/*
		 * Attempt to lock the page.  If we can't, then
		 * someone else is messing with it or we have been
		 * called from nfs4_dispose and this is the page that
		 * nfs4_dispose was called with.. anyway just skip it.
		 */
		if (!page_trylock(pp, SE_EXCL))
			continue;

		/*
		 * Lets check again now that we have the page lock.
		 */
		if (pp->p_fsdata == C_NOCOMMIT || hat_ismod(pp)) {
			page_unlock(pp);
			continue;
		}

		/* this had better not be a free page */
		ASSERT(PP_ISFREE(pp) == 0);

		/*
		 * The page needs to be committed and we locked it.
		 * Update the base and length parameters and add it
		 * to r_pages.
		 */
		if (rp->r_commit.c_pages == NULL) {
			rp->r_commit.c_commbase = (offset3)pp->p_offset;
			rp->r_commit.c_commlen = PAGESIZE;
		} else if (pp->p_offset < rp->r_commit.c_commbase) {
			rp->r_commit.c_commlen = rp->r_commit.c_commbase -
			    (offset3)pp->p_offset + rp->r_commit.c_commlen;
			rp->r_commit.c_commbase = (offset3)pp->p_offset;
		} else if ((rp->r_commit.c_commbase + rp->r_commit.c_commlen)
		    <= pp->p_offset) {
			rp->r_commit.c_commlen = (offset3)pp->p_offset -
			    rp->r_commit.c_commbase + PAGESIZE;
		}
		page_add(&rp->r_commit.c_pages, pp);
	} while ((pp = pp->p_vpnext) != vp->v_pages);

	mutex_exit(vphm);
}

/*
 * This routine is used to gather together a page list of the pages
 * which are to be committed on the server.  This routine must not
 * be called if the calling thread holds any locked pages.
 *
 * The calling thread must have set R4COMMIT.  This bit is used to
 * serialize access to the commit structure in the rnode.  As long
 * as the thread has set R4COMMIT, then it can manipulate the commit
 * structure without requiring any other locks.
 */
static void
nfs4_get_commit_range(vnode_t *vp, u_offset_t soff, size_t len)
{

	rnode4_t *rp;
	page_t *pp;
	u_offset_t end;
	u_offset_t off;
	ASSERT(len != 0);
	rp = VTOR4(vp);
	ASSERT(rp->r_flags & R4COMMIT);

	ASSERT(nfs_zone() == VTOMI4(vp)->mi_zone);

	/* make sure we're looking at the master vnode, not a shadow */

	if (IS_SHADOW(vp, rp))
		vp = RTOV4(rp);

	/*
	 * If there are no pages associated with this vnode, then
	 * just return.
	 */
	if ((pp = vp->v_pages) == NULL)
		return;
	/*
	 * Calculate the ending offset.
	 */
	end = soff + len;
	for (off = soff; off < end; off += PAGESIZE) {
		/*
		 * Lookup each page by vp, offset.
		 */
		if ((pp = page_lookup_nowait(vp, off, SE_EXCL)) == NULL)
			continue;
		/*
		 * If this page does not need to be committed or is
		 * modified, then just skip it.
		 */
		if (pp->p_fsdata == C_NOCOMMIT || hat_ismod(pp)) {
			page_unlock(pp);
			continue;
		}

		ASSERT(PP_ISFREE(pp) == 0);
		/*
		 * The page needs to be committed and we locked it.
		 * Update the base and length parameters and add it
		 * to r_pages.
		 */
		if (rp->r_commit.c_pages == NULL) {
			rp->r_commit.c_commbase = (offset3)pp->p_offset;
			rp->r_commit.c_commlen = PAGESIZE;
		} else {
			rp->r_commit.c_commlen = (offset3)pp->p_offset -
			    rp->r_commit.c_commbase + PAGESIZE;
		}
		page_add(&rp->r_commit.c_pages, pp);
	}
}

/*
 * Called from nfs4_close(), nfs4_fsync() and nfs4_delmap().
 * Flushes and commits data to the server.
 */
static int
nfs4_putpage_commit(vnode_t *vp, offset_t poff, size_t plen, cred_t *cr)
{
	int error;
	verifier4 write_verf;
	rnode4_t *rp = VTOR4(vp);

	ASSERT(nfs_zone() == VTOMI4(vp)->mi_zone);

	/*
	 * Flush the data portion of the file and then commit any
	 * portions which need to be committed.  This may need to
	 * be done twice if the server has changed state since
	 * data was last written.  The data will need to be
	 * rewritten to the server and then a new commit done.
	 *
	 * In fact, this may need to be done several times if the
	 * server is having problems and crashing while we are
	 * attempting to do this.
	 */

top:
	/*
	 * Do a flush based on the poff and plen arguments.  This
	 * will synchronously write out any modified pages in the
	 * range specified by (poff, plen). This starts all of the
	 * i/o operations which will be waited for in the next
	 * call to nfs4_putpage
	 */

	mutex_enter(&rp->r_statelock);
	write_verf = rp->r_writeverf;
	mutex_exit(&rp->r_statelock);

	error = nfs4_putpage(vp, poff, plen, B_ASYNC, cr, NULL);
	if (error == EAGAIN)
		error = 0;

	/*
	 * Do a flush based on the poff and plen arguments.  This
	 * will synchronously write out any modified pages in the
	 * range specified by (poff, plen) and wait until all of
	 * the asynchronous i/o's in that range are done as well.
	 */
	if (!error)
		error = nfs4_putpage(vp, poff, plen, 0, cr, NULL);

	if (error)
		return (error);

	mutex_enter(&rp->r_statelock);
	if (rp->r_writeverf != write_verf) {
		mutex_exit(&rp->r_statelock);
		goto top;
	}
	mutex_exit(&rp->r_statelock);

	/*
	 * Now commit any pages which might need to be committed.
	 * If the error, NFS_VERF_MISMATCH, is returned, then
	 * start over with the flush operation.
	 */
	error = nfs4_commit_vp(vp, poff, plen, cr, NFS4_WRITE_WAIT);

	if (error == NFS_VERF_MISMATCH)
		goto top;

	return (error);
}

/*
 * nfs4_commit_vp()  will wait for other pending commits and
 * will either commit the whole file or a range, plen dictates
 * if we commit whole file. a value of zero indicates the whole
 * file. Called from nfs4_putpage_commit() or nfs4_sync_putapage()
 */
static int
nfs4_commit_vp(vnode_t *vp, u_offset_t poff, size_t plen,
    cred_t *cr, int wait_on_writes)
{
	rnode4_t *rp;
	page_t *plist;
	offset3 offset;
	count3 len;

	ASSERT(nfs_zone() == VTOMI4(vp)->mi_zone);

	rp = VTOR4(vp);

	/*
	 *  before we gather commitable pages make
	 *  sure there are no outstanding async writes
	 */
	if (rp->r_count && wait_on_writes == NFS4_WRITE_WAIT) {
		mutex_enter(&rp->r_statelock);
		while (rp->r_count > 0) {
			cv_wait(&rp->r_cv, &rp->r_statelock);
		}
		mutex_exit(&rp->r_statelock);
	}

	/*
	 * Set the `commit inprogress' state bit.  We must
	 * first wait until any current one finishes.
	 */
	mutex_enter(&rp->r_statelock);
	while (rp->r_flags & R4COMMIT) {
		rp->r_flags |= R4COMMITWAIT;
		cv_wait(&rp->r_commit.c_cv, &rp->r_statelock);
		rp->r_flags &= ~R4COMMITWAIT;
	}
	rp->r_flags |= R4COMMIT;
	mutex_exit(&rp->r_statelock);

	/*
	 * Gather all of the pages which need to be
	 * committed.
	 */
	if (plen == 0)
		nfs4_get_commit(vp);
	else
		nfs4_get_commit_range(vp, poff, plen);

	/*
	 * Clear the `commit inprogress' bit and disconnect the
	 * page list which was gathered by nfs4_get_commit.
	 */
	plist = rp->r_commit.c_pages;
	rp->r_commit.c_pages = NULL;
	offset = rp->r_commit.c_commbase;
	len = rp->r_commit.c_commlen;
	mutex_enter(&rp->r_statelock);
	rp->r_flags &= ~R4COMMIT;
	cv_broadcast(&rp->r_commit.c_cv);
	mutex_exit(&rp->r_statelock);

	/*
	 * If any pages need to be committed, commit them and
	 * then unlock them so that they can be freed some
	 * time later.
	 */
	if (plist == NULL)
		return (0);

	/*
	 * No error occurred during the flush portion
	 * of this operation, so now attempt to commit
	 * the data to stable storage on the server.
	 *
	 * This will unlock all of the pages on the list.
	 */
	return (nfs4_sync_commit(vp, plist, offset, len, cr));
}

static int
nfs4_sync_commit(vnode_t *vp, page_t *plist, offset3 offset, count3 count,
    cred_t *cr)
{
	int error;
	page_t *pp;

	ASSERT(nfs_zone() == VTOMI4(vp)->mi_zone);

	error = nfs4_commit(vp, (offset4)offset, (count3)count, cr);

	/*
	 * If we got an error, then just unlock all of the pages
	 * on the list.
	 */
	if (error) {
		while (plist != NULL) {
			pp = plist;
			page_sub(&plist, pp);
			page_unlock(pp);
		}
		return (error);
	}
	/*
	 * We've tried as hard as we can to commit the data to stable
	 * storage on the server.  We just unlock the pages and clear
	 * the commit required state.  They will get freed later.
	 */
	while (plist != NULL) {
		pp = plist;
		page_sub(&plist, pp);
		pp->p_fsdata = C_NOCOMMIT;
		page_unlock(pp);
	}

	return (error);
}

static void
do_nfs4_async_commit(vnode_t *vp, page_t *plist, offset3 offset, count3 count,
    cred_t *cr)
{

	(void) nfs4_sync_commit(vp, plist, offset, count, cr);
}

/*ARGSUSED*/
static int
nfs4_setsecattr(vnode_t *vp, vsecattr_t *vsecattr, int flag, cred_t *cr,
	caller_context_t *ct)
{
	int		error = 0;
	mntinfo4_t	*mi;
	vattr_t		va;
	vsecattr_t	nfsace4_vsap;

	mi = VTOMI4(vp);
	if (nfs_zone() != mi->mi_zone)
		return (EIO);
	if (mi->mi_flags & MI4_ACL) {
		/* if we have a delegation, return it */
		if (VTOR4(vp)->r_deleg_type != OPEN_DELEGATE_NONE)
			(void) nfs4delegreturn(VTOR4(vp),
			    NFS4_DR_REOPEN|NFS4_DR_PUSH);

		error = nfs4_is_acl_mask_valid(vsecattr->vsa_mask,
		    NFS4_ACL_SET);
		if (error) /* EINVAL */
			return (error);

		if (vsecattr->vsa_mask & (VSA_ACL | VSA_DFACL)) {
			/*
			 * These are aclent_t type entries.
			 */
			error = vs_aent_to_ace4(vsecattr, &nfsace4_vsap,
			    vp->v_type == VDIR, FALSE);
			if (error)
				return (error);
		} else {
			/*
			 * These are ace_t type entries.
			 */
			error = vs_acet_to_ace4(vsecattr, &nfsace4_vsap,
			    FALSE);
			if (error)
				return (error);
		}
		bzero(&va, sizeof (va));
		error = nfs4setattr(vp, &va, flag, cr, &nfsace4_vsap);
		vs_ace4_destroy(&nfsace4_vsap);
		return (error);
	}
	return (ENOSYS);
}

/* ARGSUSED */
int
nfs4_getsecattr(vnode_t *vp, vsecattr_t *vsecattr, int flag, cred_t *cr,
	caller_context_t *ct)
{
	int		error;
	mntinfo4_t	*mi;
	nfs4_ga_res_t	gar;
	rnode4_t	*rp = VTOR4(vp);

	mi = VTOMI4(vp);
	if (nfs_zone() != mi->mi_zone)
		return (EIO);

	bzero(&gar, sizeof (gar));
	gar.n4g_vsa.vsa_mask = vsecattr->vsa_mask;

	/*
	 * vsecattr->vsa_mask holds the original acl request mask.
	 * This is needed when determining what to return.
	 * (See: nfs4_create_getsecattr_return())
	 */
	error = nfs4_is_acl_mask_valid(vsecattr->vsa_mask, NFS4_ACL_GET);
	if (error) /* EINVAL */
		return (error);

	/*
	 * If this is a referral stub, don't try to go OTW for an ACL
	 */
	if (RP_ISSTUB_REFERRAL(VTOR4(vp)))
		return (fs_fab_acl(vp, vsecattr, flag, cr, ct));

	if (mi->mi_flags & MI4_ACL) {
		/*
		 * Check if the data is cached and the cache is valid.  If it
		 * is we don't go over the wire.
		 */
		if (rp->r_secattr != NULL && ATTRCACHE4_VALID(vp)) {
			mutex_enter(&rp->r_statelock);
			if (rp->r_secattr != NULL) {
				error = nfs4_create_getsecattr_return(
				    rp->r_secattr, vsecattr, rp->r_attr.va_uid,
				    rp->r_attr.va_gid,
				    vp->v_type == VDIR);
				if (!error) { /* error == 0 - Success! */
					mutex_exit(&rp->r_statelock);
					return (error);
				}
			}
			mutex_exit(&rp->r_statelock);
		}

		/*
		 * The getattr otw call will always get both the acl, in
		 * the form of a list of nfsace4's, and the number of acl
		 * entries; independent of the value of gar.n4g_vsa.vsa_mask.
		 */
		gar.n4g_va.va_mask = AT_ALL;
		error =  nfs4_getattr_otw(vp, &gar, cr, 1);
		if (error) {
			vs_ace4_destroy(&gar.n4g_vsa);
			if (error == ENOTSUP || error == EOPNOTSUPP)
				error = fs_fab_acl(vp, vsecattr, flag, cr, ct);
			return (error);
		}

		if (!(gar.n4g_resbmap & FATTR4_ACL_MASK)) {
			/*
			 * No error was returned, but according to the response
			 * bitmap, neither was an acl.
			 */
			vs_ace4_destroy(&gar.n4g_vsa);
			error = fs_fab_acl(vp, vsecattr, flag, cr, ct);
			return (error);
		}

		/*
		 * Update the cache with the ACL.
		 */
		nfs4_acl_fill_cache(rp, &gar.n4g_vsa);

		error = nfs4_create_getsecattr_return(&gar.n4g_vsa,
		    vsecattr, gar.n4g_va.va_uid, gar.n4g_va.va_gid,
		    vp->v_type == VDIR);
		vs_ace4_destroy(&gar.n4g_vsa);
		if ((error) && (vsecattr->vsa_mask &
		    (VSA_ACL | VSA_ACLCNT | VSA_DFACL | VSA_DFACLCNT)) &&
		    (error != EACCES)) {
			error = fs_fab_acl(vp, vsecattr, flag, cr, ct);
		}
		return (error);
	}
	error = fs_fab_acl(vp, vsecattr, flag, cr, ct);
	return (error);
}

/*
 * The function returns:
 * 	- 0 (zero) if the passed in "acl_mask" is a valid request.
 * 	- EINVAL if the passed in "acl_mask" is an invalid request.
 *
 * In the case of getting an acl (op == NFS4_ACL_GET) the mask is invalid if:
 * - We have a mixture of ACE and ACL requests (e.g. VSA_ACL | VSA_ACE)
 *
 * In the case of setting an acl (op == NFS4_ACL_SET) the mask is invalid if:
 * - We have a mixture of ACE and ACL requests (e.g. VSA_ACL | VSA_ACE)
 * - We have a count field set without the corresponding acl field set. (e.g. -
 * VSA_ACECNT is set, but VSA_ACE is not)
 */
static int
nfs4_is_acl_mask_valid(uint_t acl_mask, nfs4_acl_op_t op)
{
	/* Shortcut the masks that are always valid. */
	if (acl_mask == (VSA_ACE | VSA_ACECNT))
		return (0);
	if (acl_mask == (VSA_ACL | VSA_ACLCNT | VSA_DFACL | VSA_DFACLCNT))
		return (0);

	if (acl_mask & (VSA_ACE | VSA_ACECNT)) {
		/*
		 * We can't have any VSA_ACL type stuff in the mask now.
		 */
		if (acl_mask & (VSA_ACL | VSA_ACLCNT | VSA_DFACL |
		    VSA_DFACLCNT))
			return (EINVAL);

		if (op == NFS4_ACL_SET) {
			if ((acl_mask & VSA_ACECNT) && !(acl_mask & VSA_ACE))
				return (EINVAL);
		}
	}

	if (acl_mask & (VSA_ACL | VSA_ACLCNT | VSA_DFACL | VSA_DFACLCNT)) {
		/*
		 * We can't have any VSA_ACE type stuff in the mask now.
		 */
		if (acl_mask & (VSA_ACE | VSA_ACECNT))
			return (EINVAL);

		if (op == NFS4_ACL_SET) {
			if ((acl_mask & VSA_ACLCNT) && !(acl_mask & VSA_ACL))
				return (EINVAL);

			if ((acl_mask & VSA_DFACLCNT) &&
			    !(acl_mask & VSA_DFACL))
				return (EINVAL);
		}
	}
	return (0);
}

/*
 * The theory behind creating the correct getsecattr return is simply this:
 * "Don't return anything that the caller is not expecting to have to free."
 */
static int
nfs4_create_getsecattr_return(vsecattr_t *filled_vsap, vsecattr_t *vsap,
    uid_t uid, gid_t gid, int isdir)
{
	int error = 0;
	/* Save the mask since the translators modify it. */
	uint_t	orig_mask = vsap->vsa_mask;

	if (orig_mask & (VSA_ACE | VSA_ACECNT)) {
		error = vs_ace4_to_acet(filled_vsap, vsap, uid, gid, FALSE);

		if (error)
			return (error);

		/*
		 * If the caller only asked for the ace count (VSA_ACECNT)
		 * don't give them the full acl (VSA_ACE), free it.
		 */
		if (!orig_mask & VSA_ACE) {
			if (vsap->vsa_aclentp != NULL) {
				kmem_free(vsap->vsa_aclentp,
				    vsap->vsa_aclcnt * sizeof (ace_t));
				vsap->vsa_aclentp = NULL;
			}
		}
		vsap->vsa_mask = orig_mask;

	} else if (orig_mask & (VSA_ACL | VSA_ACLCNT | VSA_DFACL |
	    VSA_DFACLCNT)) {
		error = vs_ace4_to_aent(filled_vsap, vsap, uid, gid,
		    isdir, FALSE);

		if (error)
			return (error);

		/*
		 * If the caller only asked for the acl count (VSA_ACLCNT)
		 * and/or the default acl count (VSA_DFACLCNT) don't give them
		 * the acl (VSA_ACL) or default acl (VSA_DFACL), free it.
		 */
		if (!orig_mask & VSA_ACL) {
			if (vsap->vsa_aclentp != NULL) {
				kmem_free(vsap->vsa_aclentp,
				    vsap->vsa_aclcnt * sizeof (aclent_t));
				vsap->vsa_aclentp = NULL;
			}
		}

		if (!orig_mask & VSA_DFACL) {
			if (vsap->vsa_dfaclentp != NULL) {
				kmem_free(vsap->vsa_dfaclentp,
				    vsap->vsa_dfaclcnt * sizeof (aclent_t));
				vsap->vsa_dfaclentp = NULL;
			}
		}
		vsap->vsa_mask = orig_mask;
	}
	return (0);
}

/* ARGSUSED */
int
nfs4_shrlock(vnode_t *vp, int cmd, struct shrlock *shr, int flag, cred_t *cr,
    caller_context_t *ct)
{
	int error;

	if (nfs_zone() != VTOMI4(vp)->mi_zone)
		return (EIO);
	/*
	 * check for valid cmd parameter
	 */
	if (cmd != F_SHARE && cmd != F_UNSHARE && cmd != F_HASREMOTELOCKS)
		return (EINVAL);

	/*
	 * Check access permissions
	 */
	if ((cmd & F_SHARE) &&
	    (((shr->s_access & F_RDACC) && (flag & FREAD) == 0) ||
	    (shr->s_access == F_WRACC && (flag & FWRITE) == 0)))
		return (EBADF);

	/*
	 * If the filesystem is mounted using local locking, pass the
	 * request off to the local share code.
	 */
	if (VTOMI4(vp)->mi_flags & MI4_LLOCK)
		return (fs_shrlock(vp, cmd, shr, flag, cr, ct));

	switch (cmd) {
	case F_SHARE:
	case F_UNSHARE:
		/*
		 * This will be properly implemented later,
		 * see RFE: 4823948 .
		 */
		error = EAGAIN;
		break;

	case F_HASREMOTELOCKS:
		/*
		 * NFS client can't store remote locks itself
		 */
		shr->s_access = 0;
		error = 0;
		break;

	default:
		error = EINVAL;
		break;
	}

	return (error);
}

/*
 * Common code called by directory ops to update the attrcache
 */
static int
nfs4_update_attrcache(nfsstat4 status, nfs4_ga_res_t *garp,
    hrtime_t t, vnode_t *vp, cred_t *cr)
{
	int error = 0;

	ASSERT(nfs_zone() == VTOMI4(vp)->mi_zone);

	if (status != NFS4_OK) {
		/* getattr not done or failed */
		PURGE_ATTRCACHE4(vp);
		return (error);
	}

	if (garp) {
		nfs4_attr_cache(vp, garp, t, cr, FALSE, NULL);
	} else {
		PURGE_ATTRCACHE4(vp);
	}
	return (error);
}

/*
 * Update directory caches for directory modification ops (link, rename, etc.)
 * When dinfo is NULL, manage dircaches in the old way.
 */
static void
nfs4_update_dircaches(change_info4 *cinfo, vnode_t *dvp, vnode_t *vp, char *nm,
    dirattr_info_t *dinfo)
{
	rnode4_t	*drp = VTOR4(dvp);

	ASSERT(nfs_zone() == VTOMI4(dvp)->mi_zone);

	/* Purge rddir cache for dir since it changed */
	if (drp->r_dir != NULL)
		nfs4_purge_rddir_cache(dvp);

	/*
	 * If caller provided dinfo, then use it to manage dir caches.
	 */
	if (dinfo != NULL) {
		if (vp != NULL) {
			mutex_enter(&VTOR4(vp)->r_statev4_lock);
			if (!VTOR4(vp)->created_v4) {
				mutex_exit(&VTOR4(vp)->r_statev4_lock);
				dnlc_update(dvp, nm, vp);
			} else {
				/*
				 * XXX don't update if the created_v4 flag is
				 * set
				 */
				mutex_exit(&VTOR4(vp)->r_statev4_lock);
				NFS4_DEBUG(nfs4_client_state_debug,
				    (CE_NOTE, "nfs4_update_dircaches: "
				    "don't update dnlc: created_v4 flag"));
			}
		}

		nfs4_attr_cache(dvp, dinfo->di_garp, dinfo->di_time_call,
		    dinfo->di_cred, FALSE, cinfo);

		return;
	}

	/*
	 * Caller didn't provide dinfo, then check change_info4 to update DNLC.
	 * Since caller modified dir but didn't receive post-dirmod-op dir
	 * attrs, the dir's attrs must be purged.
	 *
	 * XXX this check and dnlc update/purge should really be atomic,
	 * XXX but can't use rnode statelock because it'll deadlock in
	 * XXX dnlc_purge_vp, however, the risk is minimal even if a race
	 * XXX does occur.
	 *
	 * XXX We also may want to check that atomic is true in the
	 * XXX change_info struct. If it is not, the change_info may
	 * XXX reflect changes by more than one clients which means that
	 * XXX our cache may not be valid.
	 */
	PURGE_ATTRCACHE4(dvp);
	if (drp->r_change == cinfo->before) {
		/* no changes took place in the directory prior to our link */
		if (vp != NULL) {
			mutex_enter(&VTOR4(vp)->r_statev4_lock);
			if (!VTOR4(vp)->created_v4) {
				mutex_exit(&VTOR4(vp)->r_statev4_lock);
				dnlc_update(dvp, nm, vp);
			} else {
				/*
				 * XXX dont' update if the created_v4 flag
				 * is set
				 */
				mutex_exit(&VTOR4(vp)->r_statev4_lock);
				NFS4_DEBUG(nfs4_client_state_debug, (CE_NOTE,
				    "nfs4_update_dircaches: don't"
				    " update dnlc: created_v4 flag"));
			}
		}
	} else {
		/* Another client modified directory - purge its dnlc cache */
		dnlc_purge_vp(dvp);
	}
}

/*
 * The OPEN_CONFIRM operation confirms the sequence number used in OPENing a
 * file.
 *
 * The 'reopening_file' boolean should be set to TRUE if we are reopening this
 * file (ie: client recovery) and otherwise set to FALSE.
 *
 * 'nfs4_start/end_op' should have been called by the proper (ie: not recovery
 * initiated) calling functions.
 *
 * 'resend' is set to TRUE if this is a OPEN_CONFIRM issued as a result
 * of resending a 'lost' open request.
 *
 * 'num_bseqid_retryp' makes sure we don't loop forever on a broken
 * server that hands out BAD_SEQID on open confirm.
 *
 * Errors are returned via the nfs4_error_t parameter.
 */
void
nfs4open_confirm(vnode_t *vp, seqid4 *seqid, stateid4 *stateid, cred_t *cr,
    bool_t reopening_file, bool_t *retry_open, nfs4_open_owner_t *oop,
    bool_t resend, nfs4_error_t *ep, int *num_bseqid_retryp)
{
	COMPOUND4args_clnt args;
	COMPOUND4res_clnt res;
	nfs_argop4 argop[2];
	nfs_resop4 *resop;
	int doqueue = 1;
	mntinfo4_t *mi;
	OPEN_CONFIRM4args *open_confirm_args;
	int needrecov;

	ASSERT(nfs_zone() == VTOMI4(vp)->mi_zone);
#if DEBUG
	mutex_enter(&oop->oo_lock);
	ASSERT(oop->oo_seqid_inuse);
	mutex_exit(&oop->oo_lock);
#endif

recov_retry_confirm:
	nfs4_error_zinit(ep);
	*retry_open = FALSE;

	if (resend)
		args.ctag = TAG_OPEN_CONFIRM_LOST;
	else
		args.ctag = TAG_OPEN_CONFIRM;

	args.array_len = 2;
	args.array = argop;

	/* putfh target fh */
	argop[0].argop = OP_CPUTFH;
	argop[0].nfs_argop4_u.opcputfh.sfh = VTOR4(vp)->r_fh;

	argop[1].argop = OP_OPEN_CONFIRM;
	open_confirm_args = &argop[1].nfs_argop4_u.opopen_confirm;

	(*seqid) += 1;
	open_confirm_args->seqid = *seqid;
	open_confirm_args->open_stateid = *stateid;

	mi = VTOMI4(vp);

	rfs4call(mi, &args, &res, cr, &doqueue, 0, ep);

	if (!ep->error && nfs4_need_to_bump_seqid(&res)) {
		nfs4_set_open_seqid((*seqid), oop, args.ctag);
	}

	needrecov = nfs4_needs_recovery(ep, FALSE, mi->mi_vfsp);
	if (!needrecov && ep->error)
		return;

	if (needrecov) {
		bool_t abort = FALSE;

		if (reopening_file == FALSE) {
			nfs4_bseqid_entry_t *bsep = NULL;

			if (!ep->error && res.status == NFS4ERR_BAD_SEQID)
				bsep = nfs4_create_bseqid_entry(oop, NULL,
				    vp, 0, args.ctag,
				    open_confirm_args->seqid);

			abort = nfs4_start_recovery(ep, VTOMI4(vp), vp, NULL,
			    NULL, NULL, OP_OPEN_CONFIRM, bsep, NULL, NULL);
			if (bsep) {
				kmem_free(bsep, sizeof (*bsep));
				if (num_bseqid_retryp &&
				    --(*num_bseqid_retryp) == 0)
					abort = TRUE;
			}
		}
		if ((ep->error == ETIMEDOUT ||
		    res.status == NFS4ERR_RESOURCE) &&
		    abort == FALSE && resend == FALSE) {
			if (!ep->error)
				(void) xdr_free(xdr_COMPOUND4res_clnt,
				    (caddr_t)&res);

			delay(SEC_TO_TICK(confirm_retry_sec));
			goto recov_retry_confirm;
		}
		/* State may have changed so retry the entire OPEN op */
		if (abort == FALSE)
			*retry_open = TRUE;
		else
			*retry_open = FALSE;
		if (!ep->error)
			(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
		return;
	}

	if (res.status) {
		(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
		return;
	}

	resop = &res.array[1];  /* open confirm res */
	bcopy(&resop->nfs_resop4_u.opopen_confirm.open_stateid,
	    stateid, sizeof (*stateid));

	(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
}

/*
 * Return the credentials associated with a client state object.  The
 * caller is responsible for freeing the credentials.
 */

static cred_t *
state_to_cred(nfs4_open_stream_t *osp)
{
	cred_t *cr;

	/*
	 * It's ok to not lock the open stream and open owner to get
	 * the oo_cred since this is only written once (upon creation)
	 * and will not change.
	 */
	cr = osp->os_open_owner->oo_cred;
	crhold(cr);

	return (cr);
}

/*
 * nfs4_find_sysid
 *
 * Find the sysid for the knetconfig associated with the given mi.
 */
static struct lm_sysid *
nfs4_find_sysid(mntinfo4_t *mi)
{
	ASSERT(nfs_zone() == mi->mi_zone);

	/*
	 * Switch from RDMA knconf to original mount knconf
	 */
	return (lm_get_sysid(ORIG_KNCONF(mi), &mi->mi_curr_serv->sv_addr,
	    mi->mi_curr_serv->sv_hostname, NULL));
}

#ifdef DEBUG
/*
 * Return a string version of the call type for easy reading.
 */
static char *
nfs4frlock_get_call_type(nfs4_lock_call_type_t ctype)
{
	switch (ctype) {
	case NFS4_LCK_CTYPE_NORM:
		return ("NORMAL");
	case NFS4_LCK_CTYPE_RECLAIM:
		return ("RECLAIM");
	case NFS4_LCK_CTYPE_RESEND:
		return ("RESEND");
	case NFS4_LCK_CTYPE_REINSTATE:
		return ("REINSTATE");
	default:
		cmn_err(CE_PANIC, "nfs4frlock_get_call_type: got illegal "
		    "type %d", ctype);
		return ("");
	}
}
#endif

/*
 * Map the frlock cmd and lock type to the NFSv4 over-the-wire lock type
 * Unlock requests don't have an over-the-wire locktype, so we just return
 * something non-threatening.
 */

static nfs_lock_type4
flk_to_locktype(int cmd, int l_type)
{
	ASSERT(l_type == F_RDLCK || l_type == F_WRLCK || l_type == F_UNLCK);

	switch (l_type) {
	case F_UNLCK:
		return (READ_LT);
	case F_RDLCK:
		if (cmd == F_SETLK)
			return (READ_LT);
		else
			return (READW_LT);
	case F_WRLCK:
		if (cmd == F_SETLK)
			return (WRITE_LT);
		else
			return (WRITEW_LT);
	}
	panic("flk_to_locktype");
	/*NOTREACHED*/
}

/*
 * Do some preliminary checks for nfs4frlock.
 */
static int
nfs4frlock_validate_args(int cmd, flock64_t *flk, int flag, vnode_t *vp,
    u_offset_t offset)
{
	int error = 0;

	/*
	 * If we are setting a lock, check that the file is opened
	 * with the correct mode.
	 */
	if (cmd == F_SETLK || cmd == F_SETLKW) {
		if ((flk->l_type == F_RDLCK && (flag & FREAD) == 0) ||
		    (flk->l_type == F_WRLCK && (flag & FWRITE) == 0)) {
			NFS4_DEBUG(nfs4_client_lock_debug, (CE_NOTE,
			    "nfs4frlock_validate_args: file was opened with "
			    "incorrect mode"));
			return (EBADF);
		}
	}

	/* Convert the offset. It may need to be restored before returning. */
	if (error = convoff(vp, flk, 0, offset)) {
		NFS4_DEBUG(nfs4_client_lock_debug, (CE_NOTE,
		    "nfs4frlock_validate_args: convoff  =>  error= %d\n",
		    error));
		return (error);
	}

	return (error);
}

/*
 * Set the flock64's lm_sysid for nfs4frlock.
 */
static int
nfs4frlock_get_sysid(struct lm_sysid **lspp, vnode_t *vp, flock64_t *flk)
{
	ASSERT(nfs_zone() == VTOMI4(vp)->mi_zone);

	/* Find the lm_sysid */
	*lspp = nfs4_find_sysid(VTOMI4(vp));

	if (*lspp == NULL) {
		NFS4_DEBUG(nfs4_client_lock_debug, (CE_NOTE,
		    "nfs4frlock_get_sysid: no sysid, return ENOLCK"));
		return (ENOLCK);
	}

	flk->l_sysid = lm_sysidt(*lspp);

	return (0);
}

/*
 * Do the remaining preliminary setup for nfs4frlock.
 */
static void
nfs4frlock_pre_setup(clock_t *tick_delayp, nfs4_recov_state_t *recov_statep,
    flock64_t *flk, short *whencep, vnode_t *vp, cred_t *search_cr,
    cred_t **cred_otw)
{
	/*
	 * set tick_delay to the base delay time.
	 * (NFS4_BASE_WAIT_TIME is in secs)
	 */

	*tick_delayp = drv_usectohz(NFS4_BASE_WAIT_TIME * 1000 * 1000);

	/*
	 * If lock is relative to EOF, we need the newest length of the
	 * file. Therefore invalidate the ATTR_CACHE.
	 */

	*whencep = flk->l_whence;

	if (*whencep == 2)		/* SEEK_END */
		PURGE_ATTRCACHE4(vp);

	recov_statep->rs_flags = 0;
	recov_statep->rs_num_retry_despite_err = 0;
	*cred_otw = nfs4_get_otw_cred(search_cr, VTOMI4(vp), NULL);
}

/*
 * Initialize and allocate the data structures necessary for
 * the nfs4frlock call.
 * Allocates argsp's op array, frees up the saved_rqstpp if there is one.
 */
static void
nfs4frlock_call_init(COMPOUND4args_clnt *argsp, COMPOUND4args_clnt **argspp,
    nfs_argop4 **argopp, nfs4_op_hint_t *op_hintp, flock64_t *flk, int cmd,
    bool_t *retry, bool_t *did_start_fop, COMPOUND4res_clnt **respp,
    bool_t *skip_get_err, nfs4_lost_rqst_t *lost_rqstp)
{
	int		argoplist_size;
	int		num_ops = 2;

	*retry = FALSE;
	*did_start_fop = FALSE;
	*skip_get_err = FALSE;
	lost_rqstp->lr_op = 0;
	argoplist_size  = num_ops * sizeof (nfs_argop4);
	/* fill array with zero */
	*argopp = kmem_zalloc(argoplist_size, KM_SLEEP);

	*argspp = argsp;
	*respp = NULL;

	argsp->array_len = num_ops;
	argsp->array = *argopp;

	/* initialize in case of error; will get real value down below */
	argsp->ctag = TAG_NONE;

	if ((cmd == F_SETLK || cmd == F_SETLKW) && flk->l_type == F_UNLCK)
		*op_hintp = OH_LOCKU;
	else
		*op_hintp = OH_OTHER;
}

/*
 * Call the nfs4_start_fop() for nfs4frlock, if necessary.  Assign
 * the proper nfs4_server_t for this instance of nfs4frlock.
 * Returns 0 (success) or an errno value.
 */
static int
nfs4frlock_start_call(nfs4_lock_call_type_t ctype, vnode_t *vp,
    nfs4_op_hint_t op_hint, nfs4_recov_state_t *recov_statep,
    bool_t *did_start_fop, bool_t *startrecovp)
{
	int error = 0;
	rnode4_t *rp;

	ASSERT(nfs_zone() == VTOMI4(vp)->mi_zone);

	if (ctype == NFS4_LCK_CTYPE_NORM) {
		error = nfs4_start_fop(VTOMI4(vp), vp, NULL, op_hint,
		    recov_statep, startrecovp);
		if (error)
			return (error);
		*did_start_fop = TRUE;
	} else {
		*did_start_fop = FALSE;
		*startrecovp = FALSE;
	}

	if (!error) {
		rp = VTOR4(vp);

		/* If the file failed recovery, just quit. */
		mutex_enter(&rp->r_statelock);
		if (rp->r_flags & R4RECOVERR) {
			error = EIO;
		}
		mutex_exit(&rp->r_statelock);
	}

	return (error);
}

/*
 * Setup the LOCK4/LOCKU4 arguments for resending a lost lock request.  A
 * resend nfs4frlock call is initiated by the recovery framework.
 * Acquires the lop and oop seqid synchronization.
 */
static void
nfs4frlock_setup_resend_lock_args(nfs4_lost_rqst_t *resend_rqstp,
    COMPOUND4args_clnt *argsp, nfs_argop4 *argop, nfs4_lock_owner_t **lopp,
    nfs4_open_owner_t **oopp, nfs4_open_stream_t **ospp,
    LOCK4args **lock_argsp, LOCKU4args **locku_argsp)
{
	mntinfo4_t *mi = VTOMI4(resend_rqstp->lr_vp);
	int error;

	NFS4_DEBUG((nfs4_lost_rqst_debug || nfs4_client_lock_debug),
	    (CE_NOTE,
	    "nfs4frlock_setup_resend_lock_args: have lost lock to resend"));
	ASSERT(resend_rqstp != NULL);
	ASSERT(resend_rqstp->lr_op == OP_LOCK ||
	    resend_rqstp->lr_op == OP_LOCKU);

	*oopp = resend_rqstp->lr_oop;
	if (resend_rqstp->lr_oop) {
		open_owner_hold(resend_rqstp->lr_oop);
		error = nfs4_start_open_seqid_sync(resend_rqstp->lr_oop, mi);
		ASSERT(error == 0);	/* recov thread always succeeds */
	}

	/* Must resend this lost lock/locku request. */
	ASSERT(resend_rqstp->lr_lop != NULL);
	*lopp = resend_rqstp->lr_lop;
	lock_owner_hold(resend_rqstp->lr_lop);
	error = nfs4_start_lock_seqid_sync(resend_rqstp->lr_lop, mi);
	ASSERT(error == 0);	/* recov thread always succeeds */

	*ospp = resend_rqstp->lr_osp;
	if (*ospp)
		open_stream_hold(resend_rqstp->lr_osp);

	if (resend_rqstp->lr_op == OP_LOCK) {
		LOCK4args *lock_args;

		argop->argop = OP_LOCK;
		*lock_argsp = lock_args = &argop->nfs_argop4_u.oplock;
		lock_args->locktype = resend_rqstp->lr_locktype;
		lock_args->reclaim =
		    (resend_rqstp->lr_ctype == NFS4_LCK_CTYPE_RECLAIM);
		lock_args->offset = resend_rqstp->lr_flk->l_start;
		lock_args->length = resend_rqstp->lr_flk->l_len;
		if (lock_args->length == 0)
			lock_args->length = ~lock_args->length;
		nfs4_setup_lock_args(*lopp, *oopp, *ospp,
		    mi2clientid(mi), &lock_args->locker);

		switch (resend_rqstp->lr_ctype) {
		case NFS4_LCK_CTYPE_RESEND:
			argsp->ctag = TAG_LOCK_RESEND;
			break;
		case NFS4_LCK_CTYPE_REINSTATE:
			argsp->ctag = TAG_LOCK_REINSTATE;
			break;
		case NFS4_LCK_CTYPE_RECLAIM:
			argsp->ctag = TAG_LOCK_RECLAIM;
			break;
		default:
			argsp->ctag = TAG_LOCK_UNKNOWN;
			break;
		}
	} else {
		LOCKU4args *locku_args;
		nfs4_lock_owner_t *lop = resend_rqstp->lr_lop;

		argop->argop = OP_LOCKU;
		*locku_argsp = locku_args = &argop->nfs_argop4_u.oplocku;
		locku_args->locktype = READ_LT;
		locku_args->seqid = lop->lock_seqid + 1;
		mutex_enter(&lop->lo_lock);
		locku_args->lock_stateid = lop->lock_stateid;
		mutex_exit(&lop->lo_lock);
		locku_args->offset = resend_rqstp->lr_flk->l_start;
		locku_args->length = resend_rqstp->lr_flk->l_len;
		if (locku_args->length == 0)
			locku_args->length = ~locku_args->length;

		switch (resend_rqstp->lr_ctype) {
		case NFS4_LCK_CTYPE_RESEND:
			argsp->ctag = TAG_LOCKU_RESEND;
			break;
		case NFS4_LCK_CTYPE_REINSTATE:
			argsp->ctag = TAG_LOCKU_REINSTATE;
			break;
		default:
			argsp->ctag = TAG_LOCK_UNKNOWN;
			break;
		}
	}
}

/*
 * Setup the LOCKT4 arguments.
 */
static void
nfs4frlock_setup_lockt_args(nfs4_lock_call_type_t ctype, nfs_argop4 *argop,
    LOCKT4args **lockt_argsp, COMPOUND4args_clnt *argsp, flock64_t *flk,
    rnode4_t *rp)
{
	LOCKT4args *lockt_args;

	ASSERT(nfs_zone() == VTOMI4(RTOV4(rp))->mi_zone);
	ASSERT(ctype == NFS4_LCK_CTYPE_NORM);
	argop->argop = OP_LOCKT;
	argsp->ctag = TAG_LOCKT;
	lockt_args = &argop->nfs_argop4_u.oplockt;

	/*
	 * The locktype will be READ_LT unless it's
	 * a write lock. We do this because the Solaris
	 * system call allows the combination of
	 * F_UNLCK and F_GETLK* and so in that case the
	 * unlock is mapped to a read.
	 */
	if (flk->l_type == F_WRLCK)
		lockt_args->locktype = WRITE_LT;
	else
		lockt_args->locktype = READ_LT;

	lockt_args->owner.clientid = mi2clientid(VTOMI4(RTOV4(rp)));
	/* set the lock owner4 args */
	nfs4_setlockowner_args(&lockt_args->owner, rp,
	    ctype == NFS4_LCK_CTYPE_NORM ? curproc->p_pidp->pid_id :
	    flk->l_pid);
	lockt_args->offset = flk->l_start;
	lockt_args->length = flk->l_len;
	if (flk->l_len == 0)
		lockt_args->length = ~lockt_args->length;

	*lockt_argsp = lockt_args;
}

/*
 * If the client is holding a delegation, and the open stream to be used
 * with this lock request is a delegation open stream, then re-open the stream.
 * Sets the nfs4_error_t to all zeros unless the open stream has already
 * failed a reopen or we couldn't find the open stream.  NFS4ERR_DELAY
 * means the caller should retry (like a recovery retry).
 */
static void
nfs4frlock_check_deleg(vnode_t *vp, nfs4_error_t *ep, cred_t *cr, int lt)
{
	open_delegation_type4	dt;
	bool_t			reopen_needed, force;
	nfs4_open_stream_t	*osp;
	open_claim_type4 	oclaim;
	rnode4_t		*rp = VTOR4(vp);
	mntinfo4_t		*mi = VTOMI4(vp);

	ASSERT(nfs_zone() == mi->mi_zone);

	nfs4_error_zinit(ep);

	mutex_enter(&rp->r_statev4_lock);
	dt = rp->r_deleg_type;
	mutex_exit(&rp->r_statev4_lock);

	if (dt != OPEN_DELEGATE_NONE) {
		nfs4_open_owner_t	*oop;

		oop = find_open_owner(cr, NFS4_PERM_CREATED, mi);
		if (!oop) {
			ep->stat = NFS4ERR_IO;
			return;
		}
		/* returns with 'os_sync_lock' held */
		osp = find_open_stream(oop, rp);
		if (!osp) {
			open_owner_rele(oop);
			ep->stat = NFS4ERR_IO;
			return;
		}

		if (osp->os_failed_reopen) {
			NFS4_DEBUG((nfs4_open_stream_debug ||
			    nfs4_client_lock_debug), (CE_NOTE,
			    "nfs4frlock_check_deleg: os_failed_reopen set "
			    "for osp %p, cr %p, rp %s", (void *)osp,
			    (void *)cr, rnode4info(rp)));
			mutex_exit(&osp->os_sync_lock);
			open_stream_rele(osp, rp);
			open_owner_rele(oop);
			ep->stat = NFS4ERR_IO;
			return;
		}

		/*
		 * Determine whether a reopen is needed.  If this
		 * is a delegation open stream, then send the open
		 * to the server to give visibility to the open owner.
		 * Even if it isn't a delegation open stream, we need
		 * to check if the previous open CLAIM_DELEGATE_CUR
		 * was sufficient.
		 */

		reopen_needed = osp->os_delegation ||
		    ((lt == F_RDLCK &&
		    !(osp->os_dc_openacc & OPEN4_SHARE_ACCESS_READ)) ||
		    (lt == F_WRLCK &&
		    !(osp->os_dc_openacc & OPEN4_SHARE_ACCESS_WRITE)));

		mutex_exit(&osp->os_sync_lock);
		open_owner_rele(oop);

		if (reopen_needed) {
			/*
			 * Always use CLAIM_PREVIOUS after server reboot.
			 * The server will reject CLAIM_DELEGATE_CUR if
			 * it is used during the grace period.
			 */
			mutex_enter(&mi->mi_lock);
			if (mi->mi_recovflags & MI4R_SRV_REBOOT) {
				oclaim = CLAIM_PREVIOUS;
				force = TRUE;
			} else {
				oclaim = CLAIM_DELEGATE_CUR;
				force = FALSE;
			}
			mutex_exit(&mi->mi_lock);

			nfs4_reopen(vp, osp, ep, oclaim, force, FALSE);
			if (ep->error == EAGAIN) {
				nfs4_error_zinit(ep);
				ep->stat = NFS4ERR_DELAY;
			}
		}
		open_stream_rele(osp, rp);
		osp = NULL;
	}
}

/*
 * Setup the LOCKU4 arguments.
 * Returns errors via the nfs4_error_t.
 * NFS4_OK		no problems.  *go_otwp is TRUE if call should go
 *			over-the-wire.  The caller must release the
 *			reference on *lopp.
 * NFS4ERR_DELAY	caller should retry (like recovery retry)
 * (other)		unrecoverable error.
 */
static void
nfs4frlock_setup_locku_args(nfs4_lock_call_type_t ctype, nfs_argop4 *argop,
    LOCKU4args **locku_argsp, flock64_t *flk,
    nfs4_lock_owner_t **lopp, nfs4_error_t *ep, COMPOUND4args_clnt *argsp,
    vnode_t *vp, int flag, u_offset_t offset, cred_t *cr,
    bool_t *skip_get_err, bool_t *go_otwp)
{
	nfs4_lock_owner_t	*lop = NULL;
	LOCKU4args		*locku_args;
	pid_t			pid;
	bool_t			is_spec = FALSE;
	rnode4_t		*rp = VTOR4(vp);

	ASSERT(nfs_zone() == VTOMI4(vp)->mi_zone);
	ASSERT(ctype == NFS4_LCK_CTYPE_NORM);

	nfs4frlock_check_deleg(vp, ep, cr, F_UNLCK);
	if (ep->error || ep->stat)
		return;

	argop->argop = OP_LOCKU;
	if (ctype == NFS4_LCK_CTYPE_REINSTATE)
		argsp->ctag = TAG_LOCKU_REINSTATE;
	else
		argsp->ctag = TAG_LOCKU;
	locku_args = &argop->nfs_argop4_u.oplocku;
	*locku_argsp = locku_args;

	/*
	 * XXX what should locku_args->locktype be?
	 * setting to ALWAYS be READ_LT so at least
	 * it is a valid locktype.
	 */

	locku_args->locktype = READ_LT;

	pid = ctype == NFS4_LCK_CTYPE_NORM ? curproc->p_pidp->pid_id :
	    flk->l_pid;

	/*
	 * Get the lock owner stateid.  If no lock owner
	 * exists, return success.
	 */
	lop = find_lock_owner(rp, pid, LOWN_ANY);
	*lopp = lop;
	if (lop && CLNT_ISSPECIAL(&lop->lock_stateid))
		is_spec = TRUE;
	if (!lop || is_spec) {
		/*
		 * No lock owner so no locks to unlock.
		 * Return success.  If there was a failed
		 * reclaim earlier, the lock might still be
		 * registered with the local locking code,
		 * so notify it of the unlock.
		 *
		 * If the lockowner is using a special stateid,
		 * then the original lock request (that created
		 * this lockowner) was never successful, so we
		 * have no lock to undo OTW.
		 */
		NFS4_DEBUG(nfs4_client_lock_debug, (CE_NOTE,
		    "nfs4frlock_setup_locku_args: LOCKU: no lock owner "
		    "(%ld) so return success", (long)pid));

		if (ctype == NFS4_LCK_CTYPE_NORM)
			flk->l_pid = curproc->p_pid;
		nfs4_register_lock_locally(vp, flk, flag, offset);
		/*
		 * Release our hold and NULL out so final_cleanup
		 * doesn't try to end a lock seqid sync we
		 * never started.
		 */
		if (is_spec) {
			lock_owner_rele(lop);
			*lopp = NULL;
		}
		*skip_get_err = TRUE;
		*go_otwp = FALSE;
		return;
	}

	ep->error = nfs4_start_lock_seqid_sync(lop, VTOMI4(vp));
	if (ep->error == EAGAIN) {
		lock_owner_rele(lop);
		*lopp = NULL;
		return;
	}

	mutex_enter(&lop->lo_lock);
	locku_args->lock_stateid = lop->lock_stateid;
	mutex_exit(&lop->lo_lock);
	locku_args->seqid = lop->lock_seqid + 1;

	/* leave the ref count on lop, rele after RPC call */

	locku_args->offset = flk->l_start;
	locku_args->length = flk->l_len;
	if (flk->l_len == 0)
		locku_args->length = ~locku_args->length;

	*go_otwp = TRUE;
}

/*
 * Setup the LOCK4 arguments.
 *
 * Returns errors via the nfs4_error_t.
 * NFS4_OK		no problems
 * NFS4ERR_DELAY	caller should retry (like recovery retry)
 * (other)		unrecoverable error
 */
static void
nfs4frlock_setup_lock_args(nfs4_lock_call_type_t ctype, LOCK4args **lock_argsp,
    nfs4_open_owner_t **oopp, nfs4_open_stream_t **ospp,
    nfs4_lock_owner_t **lopp, nfs_argop4 *argop, COMPOUND4args_clnt *argsp,
    flock64_t *flk, int cmd, vnode_t *vp, cred_t *cr, nfs4_error_t *ep)
{
	LOCK4args		*lock_args;
	nfs4_open_owner_t	*oop = NULL;
	nfs4_open_stream_t	*osp = NULL;
	nfs4_lock_owner_t	*lop = NULL;
	pid_t			pid;
	rnode4_t		*rp = VTOR4(vp);

	ASSERT(nfs_zone() == VTOMI4(vp)->mi_zone);

	nfs4frlock_check_deleg(vp, ep, cr, flk->l_type);
	if (ep->error || ep->stat != NFS4_OK)
		return;

	argop->argop = OP_LOCK;
	if (ctype == NFS4_LCK_CTYPE_NORM)
		argsp->ctag = TAG_LOCK;
	else if (ctype == NFS4_LCK_CTYPE_RECLAIM)
		argsp->ctag = TAG_RELOCK;
	else
		argsp->ctag = TAG_LOCK_REINSTATE;
	lock_args = &argop->nfs_argop4_u.oplock;
	lock_args->locktype = flk_to_locktype(cmd, flk->l_type);
	lock_args->reclaim = ctype == NFS4_LCK_CTYPE_RECLAIM ? 1 : 0;
	/*
	 * Get the lock owner.  If no lock owner exists,
	 * create a 'temporary' one and grab the open seqid
	 * synchronization (which puts a hold on the open
	 * owner and open stream).
	 * This also grabs the lock seqid synchronization.
	 */
	pid = ctype == NFS4_LCK_CTYPE_NORM ? curproc->p_pid : flk->l_pid;
	ep->stat =
	    nfs4_find_or_create_lock_owner(pid, rp, cr, &oop, &osp, &lop);

	if (ep->stat != NFS4_OK)
		goto out;

	nfs4_setup_lock_args(lop, oop, osp, mi2clientid(VTOMI4(vp)),
	    &lock_args->locker);

	lock_args->offset = flk->l_start;
	lock_args->length = flk->l_len;
	if (flk->l_len == 0)
		lock_args->length = ~lock_args->length;
	*lock_argsp = lock_args;
out:
	*oopp = oop;
	*ospp = osp;
	*lopp = lop;
}

/*
 * After we get the reply from the server, record the proper information
 * for possible resend lock requests.
 *
 * Allocates memory for the saved_rqstp if we have a lost lock to save.
 */
static void
nfs4frlock_save_lost_rqst(nfs4_lock_call_type_t ctype, int error,
    nfs_lock_type4 locktype, nfs4_open_owner_t *oop,
    nfs4_open_stream_t *osp, nfs4_lock_owner_t *lop, flock64_t *flk,
    nfs4_lost_rqst_t *lost_rqstp, cred_t *cr, vnode_t *vp)
{
	bool_t unlock = (flk->l_type == F_UNLCK);

	ASSERT(nfs_zone() == VTOMI4(vp)->mi_zone);
	ASSERT(ctype == NFS4_LCK_CTYPE_NORM ||
	    ctype == NFS4_LCK_CTYPE_REINSTATE);

	if (error != 0 && !unlock) {
		NFS4_DEBUG((nfs4_lost_rqst_debug ||
		    nfs4_client_lock_debug), (CE_NOTE,
		    "nfs4frlock_save_lost_rqst: set lo_pending_rqsts to 1 "
		    " for lop %p", (void *)lop));
		ASSERT(lop != NULL);
		mutex_enter(&lop->lo_lock);
		lop->lo_pending_rqsts = 1;
		mutex_exit(&lop->lo_lock);
	}

	lost_rqstp->lr_putfirst = FALSE;
	lost_rqstp->lr_op = 0;

	/*
	 * For lock/locku requests, we treat EINTR as ETIMEDOUT for
	 * recovery purposes so that the lock request that was sent
	 * can be saved and re-issued later.  Ditto for EIO from a forced
	 * unmount.  This is done to have the client's local locking state
	 * match the v4 server's state; that is, the request was
	 * potentially received and accepted by the server but the client
	 * thinks it was not.
	 */
	if (error == ETIMEDOUT || error == EINTR ||
	    NFS4_FRC_UNMT_ERR(error, vp->v_vfsp)) {
		NFS4_DEBUG((nfs4_lost_rqst_debug ||
		    nfs4_client_lock_debug), (CE_NOTE,
		    "nfs4frlock_save_lost_rqst: got a lost %s lock for "
		    "lop %p oop %p osp %p", unlock ? "LOCKU" : "LOCK",
		    (void *)lop, (void *)oop, (void *)osp));
		if (unlock)
			lost_rqstp->lr_op = OP_LOCKU;
		else {
			lost_rqstp->lr_op = OP_LOCK;
			lost_rqstp->lr_locktype = locktype;
		}
		/*
		 * Objects are held and rele'd via the recovery code.
		 * See nfs4_save_lost_rqst.
		 */
		lost_rqstp->lr_vp = vp;
		lost_rqstp->lr_dvp = NULL;
		lost_rqstp->lr_oop = oop;
		lost_rqstp->lr_osp = osp;
		lost_rqstp->lr_lop = lop;
		lost_rqstp->lr_cr = cr;
		switch (ctype) {
		case NFS4_LCK_CTYPE_NORM:
			flk->l_pid = ttoproc(curthread)->p_pid;
			lost_rqstp->lr_ctype = NFS4_LCK_CTYPE_RESEND;
			break;
		case NFS4_LCK_CTYPE_REINSTATE:
			lost_rqstp->lr_putfirst = TRUE;
			lost_rqstp->lr_ctype = ctype;
			break;
		default:
			break;
		}
		lost_rqstp->lr_flk = flk;
	}
}

/*
 * Update lop's seqid.  Also update the seqid stored in a resend request,
 * if any.  (Some recovery errors increment the seqid, and we may have to
 * send the resend request again.)
 */

static void
nfs4frlock_bump_seqid(LOCK4args *lock_args, LOCKU4args *locku_args,
    nfs4_open_owner_t *oop, nfs4_lock_owner_t *lop, nfs4_tag_type_t tag_type)
{
	if (lock_args) {
		if (lock_args->locker.new_lock_owner == TRUE)
			nfs4_get_and_set_next_open_seqid(oop, tag_type);
		else {
			ASSERT(lop->lo_flags & NFS4_LOCK_SEQID_INUSE);
			nfs4_set_lock_seqid(lop->lock_seqid + 1, lop);
		}
	} else if (locku_args) {
		ASSERT(lop->lo_flags & NFS4_LOCK_SEQID_INUSE);
		nfs4_set_lock_seqid(lop->lock_seqid +1, lop);
	}
}

/*
 * Calls nfs4_end_fop, drops the seqid syncs, and frees up the
 * COMPOUND4 args/res for calls that need to retry.
 * Switches the *cred_otwp to base_cr.
 */
static void
nfs4frlock_check_access(vnode_t *vp, nfs4_op_hint_t op_hint,
    nfs4_recov_state_t *recov_statep, int needrecov, bool_t *did_start_fop,
    COMPOUND4args_clnt **argspp, COMPOUND4res_clnt **respp, int error,
    nfs4_lock_owner_t **lopp, nfs4_open_owner_t **oopp,
    nfs4_open_stream_t **ospp, cred_t *base_cr, cred_t **cred_otwp)
{
	nfs4_open_owner_t	*oop = *oopp;
	nfs4_open_stream_t	*osp = *ospp;
	nfs4_lock_owner_t	*lop = *lopp;
	nfs_argop4		*argop = (*argspp)->array;

	if (*did_start_fop) {
		nfs4_end_fop(VTOMI4(vp), vp, NULL, op_hint, recov_statep,
		    needrecov);
		*did_start_fop = FALSE;
	}
	ASSERT((*argspp)->array_len == 2);
	if (argop[1].argop == OP_LOCK)
		nfs4args_lock_free(&argop[1]);
	else if (argop[1].argop == OP_LOCKT)
		nfs4args_lockt_free(&argop[1]);
	kmem_free(argop, 2 * sizeof (nfs_argop4));
	if (!error)
		(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)*respp);
	*argspp = NULL;
	*respp = NULL;

	if (lop) {
		nfs4_end_lock_seqid_sync(lop);
		lock_owner_rele(lop);
		*lopp = NULL;
	}

	/* need to free up the reference on osp for lock args */
	if (osp != NULL) {
		open_stream_rele(osp, VTOR4(vp));
		*ospp = NULL;
	}

	/* need to free up the reference on oop for lock args */
	if (oop != NULL) {
		nfs4_end_open_seqid_sync(oop);
		open_owner_rele(oop);
		*oopp = NULL;
	}

	crfree(*cred_otwp);
	*cred_otwp = base_cr;
	crhold(*cred_otwp);
}

/*
 * Function to process the client's recovery for nfs4frlock.
 * Returns TRUE if we should retry the lock request; FALSE otherwise.
 *
 * Calls nfs4_end_fop, drops the seqid syncs, and frees up the
 * COMPOUND4 args/res for calls that need to retry.
 *
 * Note: the rp's r_lkserlock is *not* dropped during this path.
 */
static bool_t
nfs4frlock_recovery(int needrecov, nfs4_error_t *ep,
    COMPOUND4args_clnt **argspp, COMPOUND4res_clnt **respp,
    LOCK4args *lock_args, LOCKU4args *locku_args,
    nfs4_open_owner_t **oopp, nfs4_open_stream_t **ospp,
    nfs4_lock_owner_t **lopp, rnode4_t *rp, vnode_t *vp,
    nfs4_recov_state_t *recov_statep, nfs4_op_hint_t op_hint,
    bool_t *did_start_fop, nfs4_lost_rqst_t *lost_rqstp, flock64_t *flk)
{
	nfs4_open_owner_t	*oop = *oopp;
	nfs4_open_stream_t	*osp = *ospp;
	nfs4_lock_owner_t	*lop = *lopp;

	bool_t abort, retry;

	ASSERT(nfs_zone() == VTOMI4(vp)->mi_zone);
	ASSERT((*argspp) != NULL);
	ASSERT((*respp) != NULL);
	if (lock_args || locku_args)
		ASSERT(lop != NULL);

	NFS4_DEBUG((nfs4_client_lock_debug || nfs4_client_recov_debug),
	    (CE_NOTE, "nfs4frlock_recovery: initiating recovery\n"));

	retry = TRUE;
	abort = FALSE;
	if (needrecov) {
		nfs4_bseqid_entry_t *bsep = NULL;
		nfs_opnum4 op;

		op = lock_args ? OP_LOCK : locku_args ? OP_LOCKU : OP_LOCKT;

		if (!ep->error && ep->stat == NFS4ERR_BAD_SEQID) {
			seqid4 seqid;

			if (lock_args) {
				if (lock_args->locker.new_lock_owner == TRUE)
					seqid = lock_args->locker.locker4_u.
					    open_owner.open_seqid;
				else
					seqid = lock_args->locker.locker4_u.
					    lock_owner.lock_seqid;
			} else if (locku_args) {
				seqid = locku_args->seqid;
			} else {
				seqid = 0;
			}

			bsep = nfs4_create_bseqid_entry(oop, lop, vp,
			    flk->l_pid, (*argspp)->ctag, seqid);
		}

		abort = nfs4_start_recovery(ep, VTOMI4(vp), vp, NULL, NULL,
		    (lost_rqstp && (lost_rqstp->lr_op == OP_LOCK ||
		    lost_rqstp->lr_op == OP_LOCKU)) ? lost_rqstp :
		    NULL, op, bsep, NULL, NULL);

		if (bsep)
			kmem_free(bsep, sizeof (*bsep));
	}

	/*
	 * Return that we do not want to retry the request for 3 cases:
	 * 1. If we received EINTR or are bailing out because of a forced
	 *    unmount, we came into this code path just for the sake of
	 *    initiating recovery, we now need to return the error.
	 * 2. If we have aborted recovery.
	 * 3. We received NFS4ERR_BAD_SEQID.
	 */
	if (ep->error == EINTR || NFS4_FRC_UNMT_ERR(ep->error, vp->v_vfsp) ||
	    abort == TRUE || (ep->error == 0 && ep->stat == NFS4ERR_BAD_SEQID))
		retry = FALSE;

	if (*did_start_fop == TRUE) {
		nfs4_end_fop(VTOMI4(vp), vp, NULL, op_hint, recov_statep,
		    needrecov);
		*did_start_fop = FALSE;
	}

	if (retry == TRUE) {
		nfs_argop4	*argop;

		argop = (*argspp)->array;
		ASSERT((*argspp)->array_len == 2);

		if (argop[1].argop == OP_LOCK)
			nfs4args_lock_free(&argop[1]);
		else if (argop[1].argop == OP_LOCKT)
			nfs4args_lockt_free(&argop[1]);
		kmem_free(argop, 2 * sizeof (nfs_argop4));
		if (!ep->error)
			(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)*respp);
		*respp = NULL;
		*argspp = NULL;
	}

	if (lop != NULL) {
		nfs4_end_lock_seqid_sync(lop);
		lock_owner_rele(lop);
	}

	*lopp = NULL;

	/* need to free up the reference on osp for lock args */
	if (osp != NULL) {
		open_stream_rele(osp, rp);
		*ospp = NULL;
	}

	/* need to free up the reference on oop for lock args */
	if (oop != NULL) {
		nfs4_end_open_seqid_sync(oop);
		open_owner_rele(oop);
		*oopp = NULL;
	}

	return (retry);
}

/*
 * Handles the successful reply from the server for nfs4frlock.
 */
static void
nfs4frlock_results_ok(nfs4_lock_call_type_t ctype, int cmd, flock64_t *flk,
    vnode_t *vp, int flag, u_offset_t offset,
    nfs4_lost_rqst_t *resend_rqstp)
{
	ASSERT(nfs_zone() == VTOMI4(vp)->mi_zone);
	if ((cmd == F_SETLK || cmd == F_SETLKW) &&
	    (flk->l_type == F_RDLCK || flk->l_type == F_WRLCK)) {
		if (ctype == NFS4_LCK_CTYPE_NORM) {
			flk->l_pid = ttoproc(curthread)->p_pid;
			/*
			 * We do not register lost locks locally in
			 * the 'resend' case since the user/application
			 * doesn't think we have the lock.
			 */
			ASSERT(!resend_rqstp);
			nfs4_register_lock_locally(vp, flk, flag, offset);
		}
	}
}

/*
 * Handle the DENIED reply from the server for nfs4frlock.
 * Returns TRUE if we should retry the request; FALSE otherwise.
 *
 * Calls nfs4_end_fop, drops the seqid syncs, and frees up the
 * COMPOUND4 args/res for calls that need to retry.  Can also
 * drop and regrab the r_lkserlock.
 */
static bool_t
nfs4frlock_results_denied(nfs4_lock_call_type_t ctype, LOCK4args *lock_args,
    LOCKT4args *lockt_args, nfs4_open_owner_t **oopp,
    nfs4_open_stream_t **ospp, nfs4_lock_owner_t **lopp, int cmd,
    vnode_t *vp, flock64_t *flk, nfs4_op_hint_t op_hint,
    nfs4_recov_state_t *recov_statep, int needrecov,
    COMPOUND4args_clnt **argspp, COMPOUND4res_clnt **respp,
    clock_t *tick_delayp, short *whencep, int *errorp,
    nfs_resop4 *resop, cred_t *cr, bool_t *did_start_fop,
    bool_t *skip_get_err)
{
	ASSERT(nfs_zone() == VTOMI4(vp)->mi_zone);

	if (lock_args) {
		nfs4_open_owner_t	*oop = *oopp;
		nfs4_open_stream_t	*osp = *ospp;
		nfs4_lock_owner_t	*lop = *lopp;
		int			intr;

		/*
		 * Blocking lock needs to sleep and retry from the request.
		 *
		 * Do not block and wait for 'resend' or 'reinstate'
		 * lock requests, just return the error.
		 *
		 * Note: reclaim requests have cmd == F_SETLK, not F_SETLKW.
		 */
		if (cmd == F_SETLKW) {
			rnode4_t *rp = VTOR4(vp);
			nfs_argop4 *argop = (*argspp)->array;

			ASSERT(ctype == NFS4_LCK_CTYPE_NORM);

			nfs4_end_fop(VTOMI4(vp), vp, NULL, op_hint,
			    recov_statep, needrecov);
			*did_start_fop = FALSE;
			ASSERT((*argspp)->array_len == 2);
			if (argop[1].argop == OP_LOCK)
				nfs4args_lock_free(&argop[1]);
			else if (argop[1].argop == OP_LOCKT)
				nfs4args_lockt_free(&argop[1]);
			kmem_free(argop, 2 * sizeof (nfs_argop4));
			if (*respp)
				(void) xdr_free(xdr_COMPOUND4res_clnt,
				    (caddr_t)*respp);
			*argspp = NULL;
			*respp = NULL;
			nfs4_end_lock_seqid_sync(lop);
			lock_owner_rele(lop);
			*lopp = NULL;
			if (osp != NULL) {
				open_stream_rele(osp, rp);
				*ospp = NULL;
			}
			if (oop != NULL) {
				nfs4_end_open_seqid_sync(oop);
				open_owner_rele(oop);
				*oopp = NULL;
			}

			nfs_rw_exit(&rp->r_lkserlock);

			intr = nfs4_block_and_wait(tick_delayp, rp);

			if (intr) {
				(void) nfs_rw_enter_sig(&rp->r_lkserlock,
				    RW_WRITER, FALSE);
				*errorp = EINTR;
				return (FALSE);
			}

			(void) nfs_rw_enter_sig(&rp->r_lkserlock,
			    RW_WRITER, FALSE);

			/*
			 * Make sure we are still safe to lock with
			 * regards to mmapping.
			 */
			if (!nfs4_safelock(vp, flk, cr)) {
				*errorp = EAGAIN;
				return (FALSE);
			}

			return (TRUE);
		}
		if (ctype == NFS4_LCK_CTYPE_NORM)
			*errorp = EAGAIN;
		*skip_get_err = TRUE;
		flk->l_whence = 0;
		*whencep = 0;
		return (FALSE);
	} else if (lockt_args) {
		NFS4_DEBUG(nfs4_client_lock_debug, (CE_NOTE,
		    "nfs4frlock_results_denied: OP_LOCKT DENIED"));

		denied_to_flk(&resop->nfs_resop4_u.oplockt.denied,
		    flk, lockt_args);

		/* according to NLM code */
		*errorp = 0;
		*whencep = 0;
		*skip_get_err = TRUE;
		return (FALSE);
	}
	return (FALSE);
}

/*
 * Handles all NFS4 errors besides NFS4_OK and NFS4ERR_DENIED for nfs4frlock.
 */
static void
nfs4frlock_results_default(COMPOUND4res_clnt *resp, int *errorp)
{
	switch (resp->status) {
	case NFS4ERR_ACCESS:
	case NFS4ERR_ADMIN_REVOKED:
	case NFS4ERR_BADHANDLE:
	case NFS4ERR_BAD_RANGE:
	case NFS4ERR_BAD_SEQID:
	case NFS4ERR_BAD_STATEID:
	case NFS4ERR_BADXDR:
	case NFS4ERR_DEADLOCK:
	case NFS4ERR_DELAY:
	case NFS4ERR_EXPIRED:
	case NFS4ERR_FHEXPIRED:
	case NFS4ERR_GRACE:
	case NFS4ERR_INVAL:
	case NFS4ERR_ISDIR:
	case NFS4ERR_LEASE_MOVED:
	case NFS4ERR_LOCK_NOTSUPP:
	case NFS4ERR_LOCK_RANGE:
	case NFS4ERR_MOVED:
	case NFS4ERR_NOFILEHANDLE:
	case NFS4ERR_NO_GRACE:
	case NFS4ERR_OLD_STATEID:
	case NFS4ERR_OPENMODE:
	case NFS4ERR_RECLAIM_BAD:
	case NFS4ERR_RECLAIM_CONFLICT:
	case NFS4ERR_RESOURCE:
	case NFS4ERR_SERVERFAULT:
	case NFS4ERR_STALE:
	case NFS4ERR_STALE_CLIENTID:
	case NFS4ERR_STALE_STATEID:
		return;
	default:
		NFS4_DEBUG(nfs4_client_lock_debug, (CE_NOTE,
		    "nfs4frlock_results_default: got unrecognizable "
		    "res.status %d", resp->status));
		*errorp = NFS4ERR_INVAL;
	}
}

/*
 * The lock request was successful, so update the client's state.
 */
static void
nfs4frlock_update_state(LOCK4args *lock_args, LOCKU4args *locku_args,
    LOCKT4args *lockt_args, nfs_resop4 *resop, nfs4_lock_owner_t *lop,
    vnode_t *vp, flock64_t *flk, cred_t *cr,
    nfs4_lost_rqst_t *resend_rqstp)
{
	ASSERT(nfs_zone() == VTOMI4(vp)->mi_zone);

	if (lock_args) {
		LOCK4res *lock_res;

		lock_res = &resop->nfs_resop4_u.oplock;
		/* update the stateid with server's response */

		if (lock_args->locker.new_lock_owner == TRUE) {
			mutex_enter(&lop->lo_lock);
			lop->lo_just_created = NFS4_PERM_CREATED;
			mutex_exit(&lop->lo_lock);
		}

		nfs4_set_lock_stateid(lop, lock_res->LOCK4res_u.lock_stateid);

		/*
		 * If the lock was the result of a resending a lost
		 * request, we've synched up the stateid and seqid
		 * with the server, but now the server might be out of sync
		 * with what the application thinks it has for locks.
		 * Clean that up here.  It's unclear whether we should do
		 * this even if the filesystem has been forcibly unmounted.
		 * For most servers, it's probably wasted effort, but
		 * RFC3530 lets servers require that unlocks exactly match
		 * the locks that are held.
		 */
		if (resend_rqstp != NULL &&
		    resend_rqstp->lr_ctype != NFS4_LCK_CTYPE_REINSTATE) {
			nfs4_reinstitute_local_lock_state(vp, flk, cr, lop);
		} else {
			flk->l_whence = 0;
		}
	} else if (locku_args) {
		LOCKU4res *locku_res;

		locku_res = &resop->nfs_resop4_u.oplocku;

		/* Update the stateid with the server's response */
		nfs4_set_lock_stateid(lop, locku_res->lock_stateid);
	} else if (lockt_args) {
		/* Switch the lock type to express success, see fcntl */
		flk->l_type = F_UNLCK;
		flk->l_whence = 0;
	}
}

/*
 * Do final cleanup before exiting nfs4frlock.
 * Calls nfs4_end_fop, drops the seqid syncs, and frees up the
 * COMPOUND4 args/res for calls that haven't already.
 */
static void
nfs4frlock_final_cleanup(nfs4_lock_call_type_t ctype, COMPOUND4args_clnt *argsp,
    COMPOUND4res_clnt *resp, vnode_t *vp, nfs4_op_hint_t op_hint,
    nfs4_recov_state_t *recov_statep, int needrecov, nfs4_open_owner_t *oop,
    nfs4_open_stream_t *osp, nfs4_lock_owner_t *lop, flock64_t *flk,
    short whence, u_offset_t offset, struct lm_sysid *ls,
    int *errorp, LOCK4args *lock_args, LOCKU4args *locku_args,
    bool_t did_start_fop, bool_t skip_get_err,
    cred_t *cred_otw, cred_t *cred)
{
	mntinfo4_t	*mi = VTOMI4(vp);
	rnode4_t	*rp = VTOR4(vp);
	int		error = *errorp;
	nfs_argop4	*argop;
	int	do_flush_pages = 0;

	ASSERT(nfs_zone() == mi->mi_zone);
	/*
	 * The client recovery code wants the raw status information,
	 * so don't map the NFS status code to an errno value for
	 * non-normal call types.
	 */
	if (ctype == NFS4_LCK_CTYPE_NORM) {
		if (*errorp == 0 && resp != NULL && skip_get_err == FALSE)
			*errorp = geterrno4(resp->status);
		if (did_start_fop == TRUE)
			nfs4_end_fop(mi, vp, NULL, op_hint, recov_statep,
			    needrecov);

		/*
		 * We've established a new lock on the server, so invalidate
		 * the pages associated with the vnode to get the most up to
		 * date pages from the server after acquiring the lock. We
		 * want to be sure that the read operation gets the newest data.
		 * N.B.
		 * We used to do this in nfs4frlock_results_ok but that doesn't
		 * work since VOP_PUTPAGE can call nfs4_commit which calls
		 * nfs4_start_fop. We flush the pages below after calling
		 * nfs4_end_fop above
		 * The flush of the page cache must be done after
		 * nfs4_end_open_seqid_sync() to avoid a 4-way hang.
		 */
		if (!error && resp && resp->status == NFS4_OK)
			do_flush_pages = 1;
	}
	if (argsp) {
		ASSERT(argsp->array_len == 2);
		argop = argsp->array;
		if (argop[1].argop == OP_LOCK)
			nfs4args_lock_free(&argop[1]);
		else if (argop[1].argop == OP_LOCKT)
			nfs4args_lockt_free(&argop[1]);
		kmem_free(argop, 2 * sizeof (nfs_argop4));
		if (resp)
			(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)resp);
	}

	/* free the reference on the lock owner */
	if (lop != NULL) {
		nfs4_end_lock_seqid_sync(lop);
		lock_owner_rele(lop);
	}

	/* need to free up the reference on osp for lock args */
	if (osp != NULL)
		open_stream_rele(osp, rp);

	/* need to free up the reference on oop for lock args */
	if (oop != NULL) {
		nfs4_end_open_seqid_sync(oop);
		open_owner_rele(oop);
	}

	if (do_flush_pages)
		nfs4_flush_pages(vp, cred);

	(void) convoff(vp, flk, whence, offset);

	lm_rel_sysid(ls);

	/*
	 * Record debug information in the event we get EINVAL.
	 */
	mutex_enter(&mi->mi_lock);
	if (*errorp == EINVAL && (lock_args || locku_args) &&
	    (!(mi->mi_flags & MI4_POSIX_LOCK))) {
		if (!(mi->mi_flags & MI4_LOCK_DEBUG)) {
			zcmn_err(getzoneid(), CE_NOTE,
			    "%s operation failed with "
			    "EINVAL probably since the server, %s,"
			    " doesn't support POSIX style locking",
			    lock_args ? "LOCK" : "LOCKU",
			    mi->mi_curr_serv->sv_hostname);
			mi->mi_flags |= MI4_LOCK_DEBUG;
		}
	}
	mutex_exit(&mi->mi_lock);

	if (cred_otw)
		crfree(cred_otw);
}

/*
 * This calls the server and the local locking code.
 *
 * Client locks are registerred locally by oring the sysid with
 * LM_SYSID_CLIENT. The server registers locks locally using just the sysid.
 * We need to distinguish between the two to avoid collision in case one
 * machine is used as both client and server.
 *
 * Blocking lock requests will continually retry to acquire the lock
 * forever.
 *
 * The ctype is defined as follows:
 * NFS4_LCK_CTYPE_NORM: normal lock request.
 *
 * NFS4_LCK_CTYPE_RECLAIM:  bypass the usual calls for synchronizing with client
 * recovery, get the pid from flk instead of curproc, and don't reregister
 * the lock locally.
 *
 * NFS4_LCK_CTYPE_RESEND: same as NFS4_LCK_CTYPE_RECLAIM, with the addition
 * that we will use the information passed in via resend_rqstp to setup the
 * lock/locku request.  This resend is the exact same request as the 'lost
 * lock', and is initiated by the recovery framework. A successful resend
 * request can initiate one or more reinstate requests.
 *
 * NFS4_LCK_CTYPE_REINSTATE: same as NFS4_LCK_CTYPE_RESEND, except that it
 * does not trigger additional reinstate requests.  This lock call type is
 * set for setting the v4 server's locking state back to match what the
 * client's local locking state is in the event of a received 'lost lock'.
 *
 * Errors are returned via the nfs4_error_t parameter.
 */
void
nfs4frlock(nfs4_lock_call_type_t ctype, vnode_t *vp, int cmd, flock64_t *flk,
    int flag, u_offset_t offset, cred_t *cr, nfs4_error_t *ep,
    nfs4_lost_rqst_t *resend_rqstp, int *did_reclaimp)
{
	COMPOUND4args_clnt	args, *argsp = NULL;
	COMPOUND4res_clnt	res, *resp = NULL;
	nfs_argop4	*argop;
	nfs_resop4	*resop;
	rnode4_t	*rp;
	int		doqueue = 1;
	clock_t		tick_delay;  /* delay in clock ticks */
	struct lm_sysid	*ls;
	LOCK4args	*lock_args = NULL;
	LOCKU4args	*locku_args = NULL;
	LOCKT4args	*lockt_args = NULL;
	nfs4_open_owner_t *oop = NULL;
	nfs4_open_stream_t *osp = NULL;
	nfs4_lock_owner_t *lop = NULL;
	bool_t		needrecov = FALSE;
	nfs4_recov_state_t recov_state;
	short		whence;
	nfs4_op_hint_t	op_hint;
	nfs4_lost_rqst_t lost_rqst;
	bool_t		retry = FALSE;
	bool_t		did_start_fop = FALSE;
	bool_t		skip_get_err = FALSE;
	cred_t		*cred_otw = NULL;
	bool_t		recovonly;	/* just queue request */
	int		frc_no_reclaim = 0;
#ifdef DEBUG
	char *name;
#endif

	ASSERT(nfs_zone() == VTOMI4(vp)->mi_zone);

#ifdef DEBUG
	name = fn_name(VTOSV(vp)->sv_name);
	NFS4_DEBUG(nfs4_client_lock_debug, (CE_NOTE, "nfs4frlock: "
	    "%s: cmd %d, type %d, offset %llu, start %"PRIx64", "
	    "length %"PRIu64", pid %d, sysid %d, call type %s, "
	    "resend request %s", name, cmd, flk->l_type, offset, flk->l_start,
	    flk->l_len, ctype == NFS4_LCK_CTYPE_NORM ? curproc->p_pid :
	    flk->l_pid, flk->l_sysid, nfs4frlock_get_call_type(ctype),
	    resend_rqstp ? "TRUE" : "FALSE"));
	kmem_free(name, MAXNAMELEN);
#endif

	nfs4_error_zinit(ep);
	ep->error = nfs4frlock_validate_args(cmd, flk, flag, vp, offset);
	if (ep->error)
		return;
	ep->error = nfs4frlock_get_sysid(&ls, vp, flk);
	if (ep->error)
		return;
	nfs4frlock_pre_setup(&tick_delay, &recov_state, flk, &whence,
	    vp, cr, &cred_otw);

recov_retry:
	nfs4frlock_call_init(&args, &argsp, &argop, &op_hint, flk, cmd,
	    &retry, &did_start_fop, &resp, &skip_get_err, &lost_rqst);
	rp = VTOR4(vp);

	ep->error = nfs4frlock_start_call(ctype, vp, op_hint, &recov_state,
	    &did_start_fop, &recovonly);

	if (ep->error)
		goto out;

	if (recovonly) {
		/*
		 * Leave the request for the recovery system to deal with.
		 */
		ASSERT(ctype == NFS4_LCK_CTYPE_NORM);
		ASSERT(cmd != F_GETLK);
		ASSERT(flk->l_type == F_UNLCK);

		nfs4_error_init(ep, EINTR);
		needrecov = TRUE;
		lop = find_lock_owner(rp, curproc->p_pid, LOWN_ANY);
		if (lop != NULL) {
			nfs4frlock_save_lost_rqst(ctype, ep->error, READ_LT,
			    NULL, NULL, lop, flk, &lost_rqst, cr, vp);
			(void) nfs4_start_recovery(ep,
			    VTOMI4(vp), vp, NULL, NULL,
			    (lost_rqst.lr_op == OP_LOCK ||
			    lost_rqst.lr_op == OP_LOCKU) ?
			    &lost_rqst : NULL, OP_LOCKU, NULL, NULL, NULL);
			lock_owner_rele(lop);
			lop = NULL;
		}
		flk->l_pid = curproc->p_pid;
		nfs4_register_lock_locally(vp, flk, flag, offset);
		goto out;
	}

	/* putfh directory fh */
	argop[0].argop = OP_CPUTFH;
	argop[0].nfs_argop4_u.opcputfh.sfh = rp->r_fh;

	/*
	 * Set up the over-the-wire arguments and get references to the
	 * open owner, etc.
	 */

	if (ctype == NFS4_LCK_CTYPE_RESEND ||
	    ctype == NFS4_LCK_CTYPE_REINSTATE) {
		nfs4frlock_setup_resend_lock_args(resend_rqstp, argsp,
		    &argop[1], &lop, &oop, &osp, &lock_args, &locku_args);
	} else {
		bool_t go_otw = TRUE;

		ASSERT(resend_rqstp == NULL);

		switch (cmd) {
		case F_GETLK:
		case F_O_GETLK:
			nfs4frlock_setup_lockt_args(ctype, &argop[1],
			    &lockt_args, argsp, flk, rp);
			break;
		case F_SETLKW:
		case F_SETLK:
			if (flk->l_type == F_UNLCK)
				nfs4frlock_setup_locku_args(ctype,
				    &argop[1], &locku_args, flk,
				    &lop, ep, argsp,
				    vp, flag, offset, cr,
				    &skip_get_err, &go_otw);
			else
				nfs4frlock_setup_lock_args(ctype,
				    &lock_args, &oop, &osp, &lop, &argop[1],
				    argsp, flk, cmd, vp, cr, ep);

			if (ep->error)
				goto out;

			switch (ep->stat) {
			case NFS4_OK:
				break;
			case NFS4ERR_DELAY:
				/* recov thread never gets this error */
				ASSERT(resend_rqstp == NULL);
				ASSERT(did_start_fop);

				nfs4_end_fop(VTOMI4(vp), vp, NULL, op_hint,
				    &recov_state, TRUE);
				did_start_fop = FALSE;
				if (argop[1].argop == OP_LOCK)
					nfs4args_lock_free(&argop[1]);
				else if (argop[1].argop == OP_LOCKT)
					nfs4args_lockt_free(&argop[1]);
				kmem_free(argop, 2 * sizeof (nfs_argop4));
				argsp = NULL;
				goto recov_retry;
			default:
				ep->error = EIO;
				goto out;
			}
			break;
		default:
			NFS4_DEBUG(nfs4_client_lock_debug, (CE_NOTE,
			    "nfs4_frlock: invalid cmd %d", cmd));
			ep->error = EINVAL;
			goto out;
		}

		if (!go_otw)
			goto out;
	}

	/* XXX should we use the local reclock as a cache ? */
	/*
	 * Unregister the lock with the local locking code before
	 * contacting the server.  This avoids a potential race where
	 * another process gets notified that it has been granted a lock
	 * before we can unregister ourselves locally.
	 */
	if ((cmd == F_SETLK || cmd == F_SETLKW) && flk->l_type == F_UNLCK) {
		if (ctype == NFS4_LCK_CTYPE_NORM)
			flk->l_pid = ttoproc(curthread)->p_pid;
		nfs4_register_lock_locally(vp, flk, flag, offset);
	}

	/*
	 * Send the server the lock request.  Continually loop with a delay
	 * if get error NFS4ERR_DENIED (for blocking locks) or NFS4ERR_GRACE.
	 */
	resp = &res;

	NFS4_DEBUG((nfs4_client_call_debug || nfs4_client_lock_debug),
	    (CE_NOTE,
	    "nfs4frlock: %s call, rp %s", needrecov ? "recov" : "first",
	    rnode4info(rp)));

	if (lock_args && frc_no_reclaim) {
		ASSERT(ctype == NFS4_LCK_CTYPE_RECLAIM);
		NFS4_DEBUG(nfs4_client_lock_debug, (CE_NOTE,
		    "nfs4frlock: frc_no_reclaim: clearing reclaim"));
		lock_args->reclaim = FALSE;
		if (did_reclaimp)
			*did_reclaimp = 0;
	}

	/*
	 * Do the OTW call.
	 */
	rfs4call(VTOMI4(vp), argsp, resp, cred_otw, &doqueue, 0, ep);

	NFS4_DEBUG(nfs4_client_lock_debug, (CE_NOTE,
	    "nfs4frlock: error %d, status %d", ep->error, resp->status));

	needrecov = nfs4_needs_recovery(ep, TRUE, vp->v_vfsp);
	NFS4_DEBUG(nfs4_client_lock_debug, (CE_NOTE,
	    "nfs4frlock: needrecov %d", needrecov));

	if (ep->error == 0 && nfs4_need_to_bump_seqid(resp))
		nfs4frlock_bump_seqid(lock_args, locku_args, oop, lop,
		    args.ctag);

	/*
	 * Check if one of these mutually exclusive error cases has
	 * happened:
	 *   need to swap credentials due to access error
	 *   recovery is needed
	 *   different error (only known case is missing Kerberos ticket)
	 */

	if ((ep->error == EACCES ||
	    (ep->error == 0 && resp->status == NFS4ERR_ACCESS)) &&
	    cred_otw != cr) {
		nfs4frlock_check_access(vp, op_hint, &recov_state, needrecov,
		    &did_start_fop, &argsp, &resp, ep->error, &lop, &oop, &osp,
		    cr, &cred_otw);
		goto recov_retry;
	}

	if (needrecov) {
		/*
		 * LOCKT requests don't need to recover from lost
		 * requests since they don't create/modify state.
		 */
		if ((ep->error == EINTR ||
		    NFS4_FRC_UNMT_ERR(ep->error, vp->v_vfsp)) &&
		    lockt_args)
			goto out;
		/*
		 * Do not attempt recovery for requests initiated by
		 * the recovery framework.  Let the framework redrive them.
		 */
		if (ctype != NFS4_LCK_CTYPE_NORM)
			goto out;
		else {
			ASSERT(resend_rqstp == NULL);
		}

		nfs4frlock_save_lost_rqst(ctype, ep->error,
		    flk_to_locktype(cmd, flk->l_type),
		    oop, osp, lop, flk, &lost_rqst, cred_otw, vp);

		retry = nfs4frlock_recovery(needrecov, ep, &argsp,
		    &resp, lock_args, locku_args, &oop, &osp, &lop,
		    rp, vp, &recov_state, op_hint, &did_start_fop,
		    cmd != F_GETLK ? &lost_rqst : NULL, flk);

		if (retry) {
			ASSERT(oop == NULL);
			ASSERT(osp == NULL);
			ASSERT(lop == NULL);
			goto recov_retry;
		}
		goto out;
	}

	/*
	 * Bail out if have reached this point with ep->error set. Can
	 * happen if (ep->error == EACCES && !needrecov && cred_otw == cr).
	 * This happens if Kerberos ticket has expired or has been
	 * destroyed.
	 */
	if (ep->error != 0)
		goto out;

	/*
	 * Process the reply.
	 */
	switch (resp->status) {
	case NFS4_OK:
		resop = &resp->array[1];
		nfs4frlock_results_ok(ctype, cmd, flk, vp, flag, offset,
		    resend_rqstp);
		/*
		 * Have a successful lock operation, now update state.
		 */
		nfs4frlock_update_state(lock_args, locku_args, lockt_args,
		    resop, lop, vp, flk, cr, resend_rqstp);
		break;

	case NFS4ERR_DENIED:
		resop = &resp->array[1];
		retry = nfs4frlock_results_denied(ctype, lock_args, lockt_args,
		    &oop, &osp, &lop, cmd, vp, flk, op_hint,
		    &recov_state, needrecov, &argsp, &resp,
		    &tick_delay, &whence, &ep->error, resop, cr,
		    &did_start_fop, &skip_get_err);

		if (retry) {
			ASSERT(oop == NULL);
			ASSERT(osp == NULL);
			ASSERT(lop == NULL);
			goto recov_retry;
		}
		break;
	/*
	 * If the server won't let us reclaim, fall-back to trying to lock
	 * the file from scratch. Code elsewhere will check the changeinfo
	 * to ensure the file hasn't been changed.
	 */
	case NFS4ERR_NO_GRACE:
		if (lock_args && lock_args->reclaim == TRUE) {
			ASSERT(ctype == NFS4_LCK_CTYPE_RECLAIM);
			NFS4_DEBUG(nfs4_client_lock_debug, (CE_NOTE,
			    "nfs4frlock: reclaim: NFS4ERR_NO_GRACE"));
			frc_no_reclaim = 1;
			/* clean up before retrying */
			needrecov = 0;
			(void) nfs4frlock_recovery(needrecov, ep, &argsp, &resp,
			    lock_args, locku_args, &oop, &osp, &lop, rp, vp,
			    &recov_state, op_hint, &did_start_fop, NULL, flk);
			goto recov_retry;
		}
		/* FALLTHROUGH */

	default:
		nfs4frlock_results_default(resp, &ep->error);
		break;
	}
out:
	/*
	 * Process and cleanup from error.  Make interrupted unlock
	 * requests look successful, since they will be handled by the
	 * client recovery code.
	 */
	nfs4frlock_final_cleanup(ctype, argsp, resp, vp, op_hint, &recov_state,
	    needrecov, oop, osp, lop, flk, whence, offset, ls, &ep->error,
	    lock_args, locku_args, did_start_fop,
	    skip_get_err, cred_otw, cr);

	if (ep->error == EINTR && flk->l_type == F_UNLCK &&
	    (cmd == F_SETLK || cmd == F_SETLKW))
		ep->error = 0;
}

/*
 * nfs4_safelock:
 *
 * Return non-zero if the given lock request can be handled without
 * violating the constraints on concurrent mapping and locking.
 */

static int
nfs4_safelock(vnode_t *vp, const struct flock64 *bfp, cred_t *cr)
{
	rnode4_t *rp = VTOR4(vp);
	struct vattr va;
	int error;

	ASSERT(nfs_zone() == VTOMI4(vp)->mi_zone);
	ASSERT(rp->r_mapcnt >= 0);
	NFS4_DEBUG(nfs4_client_lock_debug, (CE_NOTE, "nfs4_safelock %s: "
	    "(%"PRIx64", %"PRIx64"); mapcnt = %ld", bfp->l_type == F_WRLCK ?
	    "write" : bfp->l_type == F_RDLCK ? "read" : "unlock",
	    bfp->l_start, bfp->l_len, rp->r_mapcnt));

	if (rp->r_mapcnt == 0)
		return (1);		/* always safe if not mapped */

	/*
	 * If the file is already mapped and there are locks, then they
	 * should be all safe locks.  So adding or removing a lock is safe
	 * as long as the new request is safe (i.e., whole-file, meaning
	 * length and starting offset are both zero).
	 */

	if (bfp->l_start != 0 || bfp->l_len != 0) {
		NFS4_DEBUG(nfs4_client_lock_debug, (CE_NOTE, "nfs4_safelock: "
		    "cannot lock a memory mapped file unless locking the "
		    "entire file: start %"PRIx64", len %"PRIx64,
		    bfp->l_start, bfp->l_len));
		return (0);
	}

	/* mandatory locking and mapping don't mix */
	va.va_mask = AT_MODE;
	error = VOP_GETATTR(vp, &va, 0, cr, NULL);
	if (error != 0) {
		NFS4_DEBUG(nfs4_client_lock_debug, (CE_NOTE, "nfs4_safelock: "
		    "getattr error %d", error));
		return (0);		/* treat errors conservatively */
	}
	if (MANDLOCK(vp, va.va_mode)) {
		NFS4_DEBUG(nfs4_client_lock_debug, (CE_NOTE, "nfs4_safelock: "
		    "cannot mandatory lock and mmap a file"));
		return (0);
	}

	return (1);
}


/*
 * Register the lock locally within Solaris.
 * As the client, we "or" the sysid with LM_SYSID_CLIENT when
 * recording locks locally.
 *
 * This should handle conflicts/cooperation with NFS v2/v3 since all locks
 * are registered locally.
 */
void
nfs4_register_lock_locally(vnode_t *vp, struct flock64 *flk, int flag,
    u_offset_t offset)
{
	int oldsysid;
	int error;
#ifdef DEBUG
	char *name;
#endif

	ASSERT(nfs_zone() == VTOMI4(vp)->mi_zone);

#ifdef DEBUG
	name = fn_name(VTOSV(vp)->sv_name);
	NFS4_DEBUG(nfs4_client_lock_debug,
	    (CE_NOTE, "nfs4_register_lock_locally: %s: type %d, "
	    "start %"PRIx64", length %"PRIx64", pid %ld, sysid %d",
	    name, flk->l_type, flk->l_start, flk->l_len, (long)flk->l_pid,
	    flk->l_sysid));
	kmem_free(name, MAXNAMELEN);
#endif

	/* register the lock with local locking */
	oldsysid = flk->l_sysid;
	flk->l_sysid |= LM_SYSID_CLIENT;
	error = reclock(vp, flk, SETFLCK, flag, offset, NULL);
#ifdef DEBUG
	if (error != 0) {
		NFS4_DEBUG(nfs4_client_lock_debug, (CE_NOTE,
		    "nfs4_register_lock_locally: could not register with"
		    " local locking"));
		NFS4_DEBUG(nfs4_client_lock_debug, (CE_CONT,
		    "error %d, vp 0x%p, pid %d, sysid 0x%x",
		    error, (void *)vp, flk->l_pid, flk->l_sysid));
		NFS4_DEBUG(nfs4_client_lock_debug, (CE_CONT,
		    "type %d off 0x%" PRIx64 " len 0x%" PRIx64,
		    flk->l_type, flk->l_start, flk->l_len));
		(void) reclock(vp, flk, 0, flag, offset, NULL);
		NFS4_DEBUG(nfs4_client_lock_debug, (CE_CONT,
		    "blocked by pid %d sysid 0x%x type %d "
		    "off 0x%" PRIx64 " len 0x%" PRIx64,
		    flk->l_pid, flk->l_sysid, flk->l_type, flk->l_start,
		    flk->l_len));
	}
#endif
	flk->l_sysid = oldsysid;
}

/*
 * nfs4_lockrelease:
 *
 * Release any locks on the given vnode that are held by the current
 * process.  Also removes the lock owner (if one exists) from the rnode's
 * list.
 */
static int
nfs4_lockrelease(vnode_t *vp, int flag, offset_t offset, cred_t *cr)
{
	flock64_t ld;
	int ret, error;
	rnode4_t *rp;
	nfs4_lock_owner_t *lop;
	nfs4_recov_state_t recov_state;
	mntinfo4_t *mi;
	bool_t possible_orphan = FALSE;
	bool_t recovonly;

	ASSERT((uintptr_t)vp > KERNELBASE);
	ASSERT(nfs_zone() == VTOMI4(vp)->mi_zone);

	rp = VTOR4(vp);
	mi = VTOMI4(vp);

	/*
	 * If we have not locked anything then we can
	 * just return since we have no work to do.
	 */
	if (rp->r_lo_head.lo_next_rnode == &rp->r_lo_head) {
		return (0);
	}

	/*
	 * We need to comprehend that another thread may
	 * kick off recovery and the lock_owner we have stashed
	 * in lop might be invalid so we should NOT cache it
	 * locally!
	 */
	recov_state.rs_flags = 0;
	recov_state.rs_num_retry_despite_err = 0;
	error = nfs4_start_fop(mi, vp, NULL, OH_LOCKU, &recov_state,
	    &recovonly);
	if (error) {
		mutex_enter(&rp->r_statelock);
		rp->r_flags |= R4LODANGLERS;
		mutex_exit(&rp->r_statelock);
		return (error);
	}

	lop = find_lock_owner(rp, curproc->p_pid, LOWN_ANY);

	/*
	 * Check if the lock owner might have a lock (request was sent but
	 * no response was received).  Also check if there are any remote
	 * locks on the file.  (In theory we shouldn't have to make this
	 * second check if there's no lock owner, but for now we'll be
	 * conservative and do it anyway.)  If either condition is true,
	 * send an unlock for the entire file to the server.
	 *
	 * Note that no explicit synchronization is needed here.  At worst,
	 * flk_has_remote_locks() will return a false positive, in which case
	 * the unlock call wastes time but doesn't harm correctness.
	 */

	if (lop) {
		mutex_enter(&lop->lo_lock);
		possible_orphan = lop->lo_pending_rqsts;
		mutex_exit(&lop->lo_lock);
		lock_owner_rele(lop);
	}

	nfs4_end_fop(mi, vp, NULL, OH_LOCKU, &recov_state, 0);

	NFS4_DEBUG(nfs4_client_lock_debug, (CE_NOTE,
	    "nfs4_lockrelease: possible orphan %d, remote locks %d, for "
	    "lop %p.", possible_orphan, flk_has_remote_locks(vp),
	    (void *)lop));

	if (possible_orphan || flk_has_remote_locks(vp)) {
		ld.l_type = F_UNLCK;    /* set to unlock entire file */
		ld.l_whence = 0;	/* unlock from start of file */
		ld.l_start = 0;
		ld.l_len = 0;		/* do entire file */

		ret = VOP_FRLOCK(vp, F_SETLK, &ld, flag, offset, NULL,
		    cr, NULL);

		if (ret != 0) {
			/*
			 * If VOP_FRLOCK fails, make sure we unregister
			 * local locks before we continue.
			 */
			ld.l_pid = ttoproc(curthread)->p_pid;
			nfs4_register_lock_locally(vp, &ld, flag, offset);
			NFS4_DEBUG(nfs4_client_lock_debug, (CE_NOTE,
			    "nfs4_lockrelease: lock release error on vp"
			    " %p: error %d.\n", (void *)vp, ret));
		}
	}

	recov_state.rs_flags = 0;
	recov_state.rs_num_retry_despite_err = 0;
	error = nfs4_start_fop(mi, vp, NULL, OH_LOCKU, &recov_state,
	    &recovonly);
	if (error) {
		mutex_enter(&rp->r_statelock);
		rp->r_flags |= R4LODANGLERS;
		mutex_exit(&rp->r_statelock);
		return (error);
	}

	/*
	 * So, here we're going to need to retrieve the lock-owner
	 * again (in case recovery has done a switch-a-roo) and
	 * remove it because we can.
	 */
	lop = find_lock_owner(rp, curproc->p_pid, LOWN_ANY);

	if (lop) {
		nfs4_rnode_remove_lock_owner(rp, lop);
		lock_owner_rele(lop);
	}

	nfs4_end_fop(mi, vp, NULL, OH_LOCKU, &recov_state, 0);
	return (0);
}

/*
 * Wait for 'tick_delay' clock ticks.
 * Implement exponential backoff until hit the lease_time of this nfs4_server.
 * NOTE: lock_lease_time is in seconds.
 *
 * XXX For future improvements, should implement a waiting queue scheme.
 */
static int
nfs4_block_and_wait(clock_t *tick_delay, rnode4_t *rp)
{
	long milliseconds_delay;
	time_t lock_lease_time;

	/* wait tick_delay clock ticks or siginteruptus */
	if (delay_sig(*tick_delay)) {
		return (EINTR);
	}
	NFS4_DEBUG(nfs4_client_lock_debug, (CE_NOTE, "nfs4_block_and_wait: "
	    "reissue the lock request: blocked for %ld clock ticks: %ld "
	    "milliseconds", *tick_delay, drv_hztousec(*tick_delay) / 1000));

	/* get the lease time */
	lock_lease_time = r2lease_time(rp);

	/* drv_hztousec converts ticks to microseconds */
	milliseconds_delay = drv_hztousec(*tick_delay) / 1000;
	if (milliseconds_delay < lock_lease_time * 1000) {
		*tick_delay = 2 * *tick_delay;
		if (drv_hztousec(*tick_delay) > lock_lease_time * 1000 * 1000)
			*tick_delay = drv_usectohz(lock_lease_time*1000*1000);
	}
	return (0);
}


void
nfs4_vnops_init(void)
{
}

void
nfs4_vnops_fini(void)
{
}

/*
 * Return a reference to the directory (parent) vnode for a given vnode,
 * using the saved pathname information and the directory file handle.  The
 * caller is responsible for disposing of the reference.
 * Returns zero or an errno value.
 *
 * Caller should set need_start_op to FALSE if it is the recovery
 * thread, or if a start_fop has already been done.  Otherwise, TRUE.
 */
int
vtodv(vnode_t *vp, vnode_t **dvpp, cred_t *cr, bool_t need_start_op)
{
	svnode_t *svnp;
	vnode_t *dvp = NULL;
	servinfo4_t *svp;
	nfs4_fname_t *mfname;
	int error;

	ASSERT(nfs_zone() == VTOMI4(vp)->mi_zone);

	if (vp->v_flag & VROOT) {
		nfs4_sharedfh_t *sfh;
		nfs_fh4 fh;
		mntinfo4_t *mi;

		ASSERT(vp->v_type == VREG);

		mi = VTOMI4(vp);
		svp = mi->mi_curr_serv;
		(void) nfs_rw_enter_sig(&svp->sv_lock, RW_READER, 0);
		fh.nfs_fh4_len = svp->sv_pfhandle.fh_len;
		fh.nfs_fh4_val = svp->sv_pfhandle.fh_buf;
		sfh = sfh4_get(&fh, VTOMI4(vp));
		nfs_rw_exit(&svp->sv_lock);
		mfname = mi->mi_fname;
		fn_hold(mfname);
		dvp = makenfs4node_by_fh(sfh, NULL, &mfname, NULL, mi, cr, 0);
		sfh4_rele(&sfh);

		if (dvp->v_type == VNON)
			dvp->v_type = VDIR;
		*dvpp = dvp;
		return (0);
	}

	svnp = VTOSV(vp);

	if (svnp == NULL) {
		NFS4_DEBUG(nfs4_client_shadow_debug, (CE_NOTE, "vtodv: "
		    "shadow node is NULL"));
		return (EINVAL);
	}

	if (svnp->sv_name == NULL || svnp->sv_dfh == NULL) {
		NFS4_DEBUG(nfs4_client_shadow_debug, (CE_NOTE, "vtodv: "
		    "shadow node name or dfh val == NULL"));
		return (EINVAL);
	}

	error = nfs4_make_dotdot(svnp->sv_dfh, 0, vp, cr, &dvp,
	    (int)need_start_op);
	if (error != 0) {
		NFS4_DEBUG(nfs4_client_shadow_debug, (CE_NOTE, "vtodv: "
		    "nfs4_make_dotdot returned %d", error));
		return (error);
	}
	if (!dvp) {
		NFS4_DEBUG(nfs4_client_shadow_debug, (CE_NOTE, "vtodv: "
		    "nfs4_make_dotdot returned a NULL dvp"));
		return (EIO);
	}
	if (dvp->v_type == VNON)
		dvp->v_type = VDIR;
	ASSERT(dvp->v_type == VDIR);
	if (VTOR4(vp)->r_flags & R4ISXATTR) {
		mutex_enter(&dvp->v_lock);
		dvp->v_flag |= V_XATTRDIR;
		mutex_exit(&dvp->v_lock);
	}
	*dvpp = dvp;
	return (0);
}

/*
 * Copy the (final) component name of vp to fnamep.  maxlen is the maximum
 * length that fnamep can accept, including the trailing null.
 * Returns 0 if okay, returns an errno value if there was a problem.
 */

int
vtoname(vnode_t *vp, char *fnamep, ssize_t maxlen)
{
	char *fn;
	int err = 0;
	servinfo4_t *svp;
	svnode_t *shvp;

	/*
	 * If the file being opened has VROOT set, then this is
	 * a "file" mount.  sv_name will not be interesting, so
	 * go back to the servinfo4 to get the original mount
	 * path and strip off all but the final edge.  Otherwise
	 * just return the name from the shadow vnode.
	 */

	if (vp->v_flag & VROOT) {

		svp = VTOMI4(vp)->mi_curr_serv;
		(void) nfs_rw_enter_sig(&svp->sv_lock, RW_READER, 0);

		fn = strrchr(svp->sv_path, '/');
		if (fn == NULL)
			err = EINVAL;
		else
			fn++;
	} else {
		shvp = VTOSV(vp);
		fn = fn_name(shvp->sv_name);
	}

	if (err == 0)
		if (strlen(fn) < maxlen)
			(void) strcpy(fnamep, fn);
		else
			err = ENAMETOOLONG;

	if (vp->v_flag & VROOT)
		nfs_rw_exit(&svp->sv_lock);
	else
		kmem_free(fn, MAXNAMELEN);

	return (err);
}

/*
 * Bookkeeping for a close that doesn't need to go over the wire.
 * *have_lockp is set to 0 if 'os_sync_lock' is released; otherwise
 * it is left at 1.
 */
void
nfs4close_notw(vnode_t *vp, nfs4_open_stream_t *osp, int *have_lockp)
{
	rnode4_t		*rp;
	mntinfo4_t		*mi;

	mi = VTOMI4(vp);
	rp = VTOR4(vp);

	NFS4_DEBUG(nfs4close_notw_debug, (CE_NOTE, "nfs4close_notw: "
	    "rp=%p osp=%p", (void *)rp, (void *)osp));
	ASSERT(nfs_zone() == mi->mi_zone);
	ASSERT(mutex_owned(&osp->os_sync_lock));
	ASSERT(*have_lockp);

	if (!osp->os_valid ||
	    osp->os_open_ref_count > 0 || osp->os_mapcnt > 0) {
		return;
	}

	/*
	 * This removes the reference obtained at OPEN; ie,
	 * when the open stream structure was created.
	 *
	 * We don't have to worry about calling 'open_stream_rele'
	 * since we our currently holding a reference to this
	 * open stream which means the count can not go to 0 with
	 * this decrement.
	 */
	ASSERT(osp->os_ref_count >= 2);
	osp->os_ref_count--;
	osp->os_valid = 0;
	mutex_exit(&osp->os_sync_lock);
	*have_lockp = 0;

	nfs4_dec_state_ref_count(mi);
}

/*
 * Close all remaining open streams on the rnode.  These open streams
 * could be here because:
 * - The close attempted at either close or delmap failed
 * - Some kernel entity did VOP_OPEN but never did VOP_CLOSE
 * - Someone did mknod on a regular file but never opened it
 */
int
nfs4close_all(vnode_t *vp, cred_t *cr)
{
	nfs4_open_stream_t *osp;
	int error;
	nfs4_error_t e = { 0, NFS4_OK, RPC_SUCCESS };
	rnode4_t *rp;

	ASSERT(nfs_zone() == VTOMI4(vp)->mi_zone);

	error = 0;
	rp = VTOR4(vp);

	/*
	 * At this point, all we know is that the last time
	 * someone called vn_rele, the count was 1.  Since then,
	 * the vnode could have been re-activated.  We want to
	 * loop through the open streams and close each one, but
	 * we have to be careful since once we release the rnode
	 * hash bucket lock, someone else is free to come in and
	 * re-activate the rnode and add new open streams.  The
	 * strategy is take the rnode hash bucket lock, verify that
	 * the count is still 1, grab the open stream off the
	 * head of the list and mark it invalid, then release the
	 * rnode hash bucket lock and proceed with that open stream.
	 * This is ok because nfs4close_one() will acquire the proper
	 * open/create to close/destroy synchronization for open
	 * streams, and will ensure that if someone has reopened
	 * the open stream after we've dropped the hash bucket lock
	 * then we'll just simply return without destroying the
	 * open stream.
	 * Repeat until the list is empty.
	 */

	for (;;) {

		/* make sure vnode hasn't been reactivated */
		rw_enter(&rp->r_hashq->r_lock, RW_READER);
		mutex_enter(&vp->v_lock);
		if (vp->v_count > 1) {
			mutex_exit(&vp->v_lock);
			rw_exit(&rp->r_hashq->r_lock);
			break;
		}
		/*
		 * Grabbing r_os_lock before releasing v_lock prevents
		 * a window where the rnode/open stream could get
		 * reactivated (and os_force_close set to 0) before we
		 * had a chance to set os_force_close to 1.
		 */
		mutex_enter(&rp->r_os_lock);
		mutex_exit(&vp->v_lock);

		osp = list_head(&rp->r_open_streams);
		if (!osp) {
			/* nothing left to CLOSE OTW, so return */
			mutex_exit(&rp->r_os_lock);
			rw_exit(&rp->r_hashq->r_lock);
			break;
		}

		mutex_enter(&rp->r_statev4_lock);
		/* the file can't still be mem mapped */
		ASSERT(rp->r_mapcnt == 0);
		if (rp->created_v4)
			rp->created_v4 = 0;
		mutex_exit(&rp->r_statev4_lock);

		/*
		 * Grab a ref on this open stream; nfs4close_one
		 * will mark it as invalid
		 */
		mutex_enter(&osp->os_sync_lock);
		osp->os_ref_count++;
		osp->os_force_close = 1;
		mutex_exit(&osp->os_sync_lock);
		mutex_exit(&rp->r_os_lock);
		rw_exit(&rp->r_hashq->r_lock);

		nfs4close_one(vp, osp, cr, 0, NULL, &e, CLOSE_FORCE, 0, 0, 0);

		/* Update error if it isn't already non-zero */
		if (error == 0) {
			if (e.error)
				error = e.error;
			else if (e.stat)
				error = geterrno4(e.stat);
		}

#ifdef	DEBUG
		nfs4close_all_cnt++;
#endif
		/* Release the ref on osp acquired above. */
		open_stream_rele(osp, rp);

		/* Proceed to the next open stream, if any */
	}
	return (error);
}

/*
 * nfs4close_one - close one open stream for a file if needed.
 *
 * "close_type" indicates which close path this is:
 * CLOSE_NORM: close initiated via VOP_CLOSE.
 * CLOSE_DELMAP: close initiated via VOP_DELMAP.
 * CLOSE_FORCE: close initiated via VOP_INACTIVE.  This path forces
 *	the close and release of client state for this open stream
 *	(unless someone else has the open stream open).
 * CLOSE_RESEND: indicates the request is a replay of an earlier request
 *	(e.g., due to abort because of a signal).
 * CLOSE_AFTER_RESEND: close initiated to "undo" a successful resent OPEN.
 *
 * CLOSE_RESEND and CLOSE_AFTER_RESEND will not attempt to retry after client
 * recovery.  Instead, the caller is expected to deal with retries.
 *
 * The caller can either pass in the osp ('provided_osp') or not.
 *
 * 'access_bits' represents the access we are closing/downgrading.
 *
 * 'len', 'prot', and 'mmap_flags' are used for CLOSE_DELMAP.  'len' is the
 * number of bytes we are unmapping, 'maxprot' is the mmap protection, and
 * 'mmap_flags' tells us the type of sharing (MAP_PRIVATE or MAP_SHARED).
 *
 * Errors are returned via the nfs4_error_t.
 */
void
nfs4close_one(vnode_t *vp, nfs4_open_stream_t *provided_osp, cred_t *cr,
    int access_bits, nfs4_lost_rqst_t *lrp, nfs4_error_t *ep,
    nfs4_close_type_t close_type, size_t len, uint_t maxprot,
    uint_t mmap_flags)
{
	nfs4_open_owner_t *oop;
	nfs4_open_stream_t *osp = NULL;
	int retry = 0;
	int num_retries = NFS4_NUM_RECOV_RETRIES;
	rnode4_t *rp;
	mntinfo4_t *mi;
	nfs4_recov_state_t recov_state;
	cred_t *cred_otw = NULL;
	bool_t recovonly = FALSE;
	int isrecov;
	int force_close;
	int close_failed = 0;
	int did_dec_count = 0;
	int did_start_op = 0;
	int did_force_recovlock = 0;
	int did_start_seqid_sync = 0;
	int have_sync_lock = 0;

	ASSERT(nfs_zone() == VTOMI4(vp)->mi_zone);

	NFS4_DEBUG(nfs4close_one_debug, (CE_NOTE, "closing vp %p osp %p, "
	    "lrp %p, close type %d len %ld prot %x mmap flags %x bits %x",
	    (void *)vp, (void *)provided_osp, (void *)lrp, close_type,
	    len, maxprot, mmap_flags, access_bits));

	nfs4_error_zinit(ep);
	rp = VTOR4(vp);
	mi = VTOMI4(vp);
	isrecov = (close_type == CLOSE_RESEND ||
	    close_type == CLOSE_AFTER_RESEND);

	/*
	 * First get the open owner.
	 */
	if (!provided_osp) {
		oop = find_open_owner(cr, NFS4_PERM_CREATED, mi);
	} else {
		oop = provided_osp->os_open_owner;
		ASSERT(oop != NULL);
		open_owner_hold(oop);
	}

	if (!oop) {
		NFS4_DEBUG(nfs4_client_recov_debug, (CE_NOTE,
		    "nfs4close_one: no oop, rp %p, mi %p, cr %p, osp %p, "
		    "close type %d", (void *)rp, (void *)mi, (void *)cr,
		    (void *)provided_osp, close_type));
		ep->error = EIO;
		goto out;
	}

	cred_otw = nfs4_get_otw_cred(cr, mi, oop);
recov_retry:
	osp = NULL;
	close_failed = 0;
	force_close = (close_type == CLOSE_FORCE);
	retry = 0;
	did_start_op = 0;
	did_force_recovlock = 0;
	did_start_seqid_sync = 0;
	have_sync_lock = 0;
	recovonly = FALSE;
	recov_state.rs_flags = 0;
	recov_state.rs_num_retry_despite_err = 0;

	/*
	 * Second synchronize with recovery.
	 */
	if (!isrecov) {
		ep->error = nfs4_start_fop(mi, vp, NULL, OH_CLOSE,
		    &recov_state, &recovonly);
		if (!ep->error) {
			did_start_op = 1;
		} else {
			close_failed = 1;
			/*
			 * If we couldn't get start_fop, but have to
			 * cleanup state, then at least acquire the
			 * mi_recovlock so we can synchronize with
			 * recovery.
			 */
			if (close_type == CLOSE_FORCE) {
				(void) nfs_rw_enter_sig(&mi->mi_recovlock,
				    RW_READER, FALSE);
				did_force_recovlock = 1;
			} else
				goto out;
		}
	}

	/*
	 * We cannot attempt to get the open seqid sync if nfs4_start_fop
	 * set 'recovonly' to TRUE since most likely this is due to
	 * reovery being active (MI4_RECOV_ACTIV).  If recovery is active,
	 * nfs4_start_open_seqid_sync() will fail with EAGAIN asking us
	 * to retry, causing us to loop until recovery finishes.  Plus we
	 * don't need protection over the open seqid since we're not going
	 * OTW, hence don't need to use the seqid.
	 */
	if (recovonly == FALSE) {
		/* need to grab the open owner sync before 'os_sync_lock' */
		ep->error = nfs4_start_open_seqid_sync(oop, mi);
		if (ep->error == EAGAIN) {
			ASSERT(!isrecov);
			if (did_start_op)
				nfs4_end_fop(mi, vp, NULL, OH_CLOSE,
				    &recov_state, TRUE);
			if (did_force_recovlock)
				nfs_rw_exit(&mi->mi_recovlock);
			goto recov_retry;
		}
		did_start_seqid_sync = 1;
	}

	/*
	 * Third get an open stream and acquire 'os_sync_lock' to
	 * sychronize the opening/creating of an open stream with the
	 * closing/destroying of an open stream.
	 */
	if (!provided_osp) {
		/* returns with 'os_sync_lock' held */
		osp = find_open_stream(oop, rp);
		if (!osp) {
			ep->error = EIO;
			goto out;
		}
	} else {
		osp = provided_osp;
		open_stream_hold(osp);
		mutex_enter(&osp->os_sync_lock);
	}
	have_sync_lock = 1;

	ASSERT(oop == osp->os_open_owner);

	/*
	 * Fourth, do any special pre-OTW CLOSE processing
	 * based on the specific close type.
	 */
	if ((close_type == CLOSE_NORM || close_type == CLOSE_AFTER_RESEND) &&
	    !did_dec_count) {
		ASSERT(osp->os_open_ref_count > 0);
		osp->os_open_ref_count--;
		did_dec_count = 1;
		if (osp->os_open_ref_count == 0)
			osp->os_final_close = 1;
	}

	if (close_type == CLOSE_FORCE) {
		/* see if somebody reopened the open stream. */
		if (!osp->os_force_close) {
			NFS4_DEBUG(nfs4close_one_debug, (CE_NOTE,
			    "nfs4close_one: skip CLOSE_FORCE as osp %p "
			    "was reopened, vp %p", (void *)osp, (void *)vp));
			ep->error = 0;
			ep->stat = NFS4_OK;
			goto out;
		}

		if (!osp->os_final_close && !did_dec_count) {
			osp->os_open_ref_count--;
			did_dec_count = 1;
		}

		/*
		 * We can't depend on os_open_ref_count being 0 due to the
		 * way executables are opened (VN_RELE to match a VOP_OPEN).
		 */
#ifdef	NOTYET
		ASSERT(osp->os_open_ref_count == 0);
#endif
		if (osp->os_open_ref_count != 0) {
			NFS4_DEBUG(nfs4close_one_debug, (CE_NOTE,
			    "nfs4close_one: should panic here on an "
			    "ASSERT(osp->os_open_ref_count == 0). Ignoring "
			    "since this is probably the exec problem."));

			osp->os_open_ref_count = 0;
		}

		/*
		 * There is the possibility that nfs4close_one()
		 * for close_type == CLOSE_DELMAP couldn't find the
		 * open stream, thus couldn't decrement its os_mapcnt;
		 * therefore we can't use this ASSERT yet.
		 */
#ifdef	NOTYET
		ASSERT(osp->os_mapcnt == 0);
#endif
		osp->os_mapcnt = 0;
	}

	if (close_type == CLOSE_DELMAP && !did_dec_count) {
		ASSERT(osp->os_mapcnt >= btopr(len));

		if ((mmap_flags & MAP_SHARED) && (maxprot & PROT_WRITE))
			osp->os_mmap_write -= btopr(len);
		if (maxprot & PROT_READ)
			osp->os_mmap_read -= btopr(len);
		if (maxprot & PROT_EXEC)
			osp->os_mmap_read -= btopr(len);
		/* mirror the PROT_NONE check in nfs4_addmap() */
		if (!(maxprot & PROT_READ) && !(maxprot & PROT_WRITE) &&
		    !(maxprot & PROT_EXEC))
			osp->os_mmap_read -= btopr(len);
		osp->os_mapcnt -= btopr(len);
		did_dec_count = 1;
	}

	if (recovonly) {
		nfs4_lost_rqst_t lost_rqst;

		/* request should not already be in recovery queue */
		ASSERT(lrp == NULL);
		nfs4_error_init(ep, EINTR);
		nfs4close_save_lost_rqst(ep->error, &lost_rqst, oop,
		    osp, cred_otw, vp);
		mutex_exit(&osp->os_sync_lock);
		have_sync_lock = 0;
		(void) nfs4_start_recovery(ep, mi, vp, NULL, NULL,
		    lost_rqst.lr_op == OP_CLOSE ?
		    &lost_rqst : NULL, OP_CLOSE, NULL, NULL, NULL);
		close_failed = 1;
		force_close = 0;
		goto close_cleanup;
	}

	/*
	 * If a previous OTW call got NFS4ERR_BAD_SEQID, then
	 * we stopped operating on the open owner's <old oo_name, old seqid>
	 * space, which means we stopped operating on the open stream
	 * too.  So don't go OTW (as the seqid is likely bad, and the
	 * stateid could be stale, potentially triggering a false
	 * setclientid), and just clean up the client's internal state.
	 */
	if (osp->os_orig_oo_name != oop->oo_name) {
		NFS4_DEBUG(nfs4close_one_debug || nfs4_client_recov_debug,
		    (CE_NOTE, "nfs4close_one: skip OTW close for osp %p "
		    "oop %p due to bad seqid (orig oo_name %" PRIx64 " current "
		    "oo_name %" PRIx64")",
		    (void *)osp, (void *)oop, osp->os_orig_oo_name,
		    oop->oo_name));
		close_failed = 1;
	}

	/* If the file failed recovery, just quit. */
	mutex_enter(&rp->r_statelock);
	if (rp->r_flags & R4RECOVERR) {
		close_failed = 1;
	}
	mutex_exit(&rp->r_statelock);

	/*
	 * If the force close path failed to obtain start_fop
	 * then skip the OTW close and just remove the state.
	 */
	if (close_failed)
		goto close_cleanup;

	/*
	 * Fifth, check to see if there are still mapped pages or other
	 * opens using this open stream.  If there are then we can't
	 * close yet but we can see if an OPEN_DOWNGRADE is necessary.
	 */
	if (osp->os_open_ref_count > 0 || osp->os_mapcnt > 0) {
		nfs4_lost_rqst_t	new_lost_rqst;
		bool_t			needrecov = FALSE;
		cred_t			*odg_cred_otw = NULL;
		seqid4			open_dg_seqid = 0;

		if (osp->os_delegation) {
			/*
			 * If this open stream was never OPENed OTW then we
			 * surely can't DOWNGRADE it (especially since the
			 * osp->open_stateid is really a delegation stateid
			 * when os_delegation is 1).
			 */
			if (access_bits & FREAD)
				osp->os_share_acc_read--;
			if (access_bits & FWRITE)
				osp->os_share_acc_write--;
			osp->os_share_deny_none--;
			nfs4_error_zinit(ep);
			goto out;
		}
		nfs4_open_downgrade(access_bits, 0, oop, osp, vp, cr,
		    lrp, ep, &odg_cred_otw, &open_dg_seqid);
		needrecov = nfs4_needs_recovery(ep, TRUE, mi->mi_vfsp);
		if (needrecov && !isrecov) {
			bool_t abort;
			nfs4_bseqid_entry_t *bsep = NULL;

			if (!ep->error && ep->stat == NFS4ERR_BAD_SEQID)
				bsep = nfs4_create_bseqid_entry(oop, NULL,
				    vp, 0,
				    lrp ? TAG_OPEN_DG_LOST : TAG_OPEN_DG,
				    open_dg_seqid);

			nfs4open_dg_save_lost_rqst(ep->error, &new_lost_rqst,
			    oop, osp, odg_cred_otw, vp, access_bits, 0);
			mutex_exit(&osp->os_sync_lock);
			have_sync_lock = 0;
			abort = nfs4_start_recovery(ep, mi, vp, NULL, NULL,
			    new_lost_rqst.lr_op == OP_OPEN_DOWNGRADE ?
			    &new_lost_rqst : NULL, OP_OPEN_DOWNGRADE,
			    bsep, NULL, NULL);
			if (odg_cred_otw)
				crfree(odg_cred_otw);
			if (bsep)
				kmem_free(bsep, sizeof (*bsep));

			if (abort == TRUE)
				goto out;

			if (did_start_seqid_sync) {
				nfs4_end_open_seqid_sync(oop);
				did_start_seqid_sync = 0;
			}
			open_stream_rele(osp, rp);

			if (did_start_op)
				nfs4_end_fop(mi, vp, NULL, OH_CLOSE,
				    &recov_state, FALSE);
			if (did_force_recovlock)
				nfs_rw_exit(&mi->mi_recovlock);

			goto recov_retry;
		} else {
			if (odg_cred_otw)
				crfree(odg_cred_otw);
		}
		goto out;
	}

	/*
	 * If this open stream was created as the results of an open
	 * while holding a delegation, then just release it; no need
	 * to do an OTW close.  Otherwise do a "normal" OTW close.
	 */
	if (osp->os_delegation) {
		nfs4close_notw(vp, osp, &have_sync_lock);
		nfs4_error_zinit(ep);
		goto out;
	}

	/*
	 * If this stream is not valid, we're done.
	 */
	if (!osp->os_valid) {
		nfs4_error_zinit(ep);
		goto out;
	}

	/*
	 * Last open or mmap ref has vanished, need to do an OTW close.
	 * First check to see if a close is still necessary.
	 */
	if (osp->os_failed_reopen) {
		NFS4_DEBUG(nfs4_client_recov_debug, (CE_NOTE,
		    "don't close OTW osp %p since reopen failed.",
		    (void *)osp));
		/*
		 * Reopen of the open stream failed, hence the
		 * stateid of the open stream is invalid/stale, and
		 * sending this OTW would incorrectly cause another
		 * round of recovery.  In this case, we need to set
		 * the 'os_valid' bit to 0 so another thread doesn't
		 * come in and re-open this open stream before
		 * this "closing" thread cleans up state (decrementing
		 * the nfs4_server_t's state_ref_count and decrementing
		 * the os_ref_count).
		 */
		osp->os_valid = 0;
		/*
		 * This removes the reference obtained at OPEN; ie,
		 * when the open stream structure was created.
		 *
		 * We don't have to worry about calling 'open_stream_rele'
		 * since we our currently holding a reference to this
		 * open stream which means the count can not go to 0 with
		 * this decrement.
		 */
		ASSERT(osp->os_ref_count >= 2);
		osp->os_ref_count--;
		nfs4_error_zinit(ep);
		close_failed = 0;
		goto close_cleanup;
	}

	ASSERT(osp->os_ref_count > 1);

	/*
	 * Sixth, try the CLOSE OTW.
	 */
	nfs4close_otw(rp, cred_otw, oop, osp, &retry, &did_start_seqid_sync,
	    close_type, ep, &have_sync_lock);

	if (ep->error == EINTR || NFS4_FRC_UNMT_ERR(ep->error, vp->v_vfsp)) {
		/*
		 * Let the recovery thread be responsible for
		 * removing the state for CLOSE.
		 */
		close_failed = 1;
		force_close = 0;
		retry = 0;
	}

	/* See if we need to retry with a different cred */
	if ((ep->error == EACCES ||
	    (ep->error == 0 && ep->stat == NFS4ERR_ACCESS)) &&
	    cred_otw != cr) {
		crfree(cred_otw);
		cred_otw = cr;
		crhold(cred_otw);
		retry = 1;
	}

	if (ep->error || ep->stat)
		close_failed = 1;

	if (retry && !isrecov && num_retries-- > 0) {
		if (have_sync_lock) {
			mutex_exit(&osp->os_sync_lock);
			have_sync_lock = 0;
		}
		if (did_start_seqid_sync) {
			nfs4_end_open_seqid_sync(oop);
			did_start_seqid_sync = 0;
		}
		open_stream_rele(osp, rp);

		if (did_start_op)
			nfs4_end_fop(mi, vp, NULL, OH_CLOSE,
			    &recov_state, FALSE);
		if (did_force_recovlock)
			nfs_rw_exit(&mi->mi_recovlock);
		NFS4_DEBUG(nfs4_client_recov_debug, (CE_NOTE,
		    "nfs4close_one: need to retry the close "
		    "operation"));
		goto recov_retry;
	}
close_cleanup:
	/*
	 * Seventh and lastly, process our results.
	 */
	if (close_failed && force_close) {
		/*
		 * It's ok to drop and regrab the 'os_sync_lock' since
		 * nfs4close_notw() will recheck to make sure the
		 * "close"/removal of state should happen.
		 */
		if (!have_sync_lock) {
			mutex_enter(&osp->os_sync_lock);
			have_sync_lock = 1;
		}
		/*
		 * This is last call, remove the ref on the open
		 * stream created by open and clean everything up.
		 */
		osp->os_pending_close = 0;
		nfs4close_notw(vp, osp, &have_sync_lock);
		nfs4_error_zinit(ep);
	}

	if (!close_failed) {
		if (have_sync_lock) {
			osp->os_pending_close = 0;
			mutex_exit(&osp->os_sync_lock);
			have_sync_lock = 0;
		} else {
			mutex_enter(&osp->os_sync_lock);
			osp->os_pending_close = 0;
			mutex_exit(&osp->os_sync_lock);
		}
		if (did_start_op && recov_state.rs_sp != NULL) {
			mutex_enter(&recov_state.rs_sp->s_lock);
			nfs4_dec_state_ref_count_nolock(recov_state.rs_sp, mi);
			mutex_exit(&recov_state.rs_sp->s_lock);
		} else {
			nfs4_dec_state_ref_count(mi);
		}
		nfs4_error_zinit(ep);
	}

out:
	if (have_sync_lock)
		mutex_exit(&osp->os_sync_lock);
	if (did_start_op)
		nfs4_end_fop(mi, vp, NULL, OH_CLOSE, &recov_state,
		    recovonly ? TRUE : FALSE);
	if (did_force_recovlock)
		nfs_rw_exit(&mi->mi_recovlock);
	if (cred_otw)
		crfree(cred_otw);
	if (osp)
		open_stream_rele(osp, rp);
	if (oop) {
		if (did_start_seqid_sync)
			nfs4_end_open_seqid_sync(oop);
		open_owner_rele(oop);
	}
}

/*
 * Convert information returned by the server in the LOCK4denied
 * structure to the form required by fcntl.
 */
static void
denied_to_flk(LOCK4denied *lockt_denied, flock64_t *flk, LOCKT4args *lockt_args)
{
	nfs4_lo_name_t *lo;

#ifdef	DEBUG
	if (denied_to_flk_debug) {
		lockt_denied_debug = lockt_denied;
		debug_enter("lockt_denied");
	}
#endif

	flk->l_type = lockt_denied->locktype == READ_LT ? F_RDLCK : F_WRLCK;
	flk->l_whence = 0;	/* aka SEEK_SET */
	flk->l_start = lockt_denied->offset;
	flk->l_len = lockt_denied->length;

	/*
	 * If the blocking clientid matches our client id, then we can
	 * interpret the lockowner (since we built it).  If not, then
	 * fabricate a sysid and pid.  Note that the l_sysid field
	 * in *flk already has the local sysid.
	 */

	if (lockt_denied->owner.clientid == lockt_args->owner.clientid) {

		if (lockt_denied->owner.owner_len == sizeof (*lo)) {
			lo = (nfs4_lo_name_t *)
			    lockt_denied->owner.owner_val;

			flk->l_pid = lo->ln_pid;
		} else {
			NFS4_DEBUG(nfs4_client_lock_debug, (CE_NOTE,
			    "denied_to_flk: bad lock owner length\n"));

			flk->l_pid = lo_to_pid(&lockt_denied->owner);
		}
	} else {
		NFS4_DEBUG(nfs4_client_lock_debug, (CE_NOTE,
		"denied_to_flk: foreign clientid\n"));

		/*
		 * Construct a new sysid which should be different from
		 * sysids of other systems.
		 */

		flk->l_sysid++;
		flk->l_pid = lo_to_pid(&lockt_denied->owner);
	}
}

static pid_t
lo_to_pid(lock_owner4 *lop)
{
	pid_t pid = 0;
	uchar_t *cp;
	int i;

	cp = (uchar_t *)&lop->clientid;

	for (i = 0; i < sizeof (lop->clientid); i++)
		pid += (pid_t)*cp++;

	cp = (uchar_t *)lop->owner_val;

	for (i = 0; i < lop->owner_len; i++)
		pid += (pid_t)*cp++;

	return (pid);
}

/*
 * Given a lock pointer, returns the length of that lock.
 * "end" is the last locked offset the "l_len" covers from
 * the start of the lock.
 */
static off64_t
lock_to_end(flock64_t *lock)
{
	off64_t lock_end;

	if (lock->l_len == 0)
		lock_end = (off64_t)MAXEND;
	else
		lock_end = lock->l_start + lock->l_len - 1;

	return (lock_end);
}

/*
 * Given the end of a lock, it will return you the length "l_len" for that lock.
 */
static off64_t
end_to_len(off64_t start, off64_t end)
{
	off64_t lock_len;

	ASSERT(end >= start);
	if (end == MAXEND)
		lock_len = 0;
	else
		lock_len = end - start + 1;

	return (lock_len);
}

/*
 * On given end for a lock it determines if it is the last locked offset
 * or not, if so keeps it as is, else adds one to return the length for
 * valid start.
 */
static off64_t
start_check(off64_t x)
{
	if (x == MAXEND)
		return (x);
	else
		return (x + 1);
}

/*
 * See if these two locks overlap, and if so return 1;
 * otherwise, return 0.
 */
static int
locks_intersect(flock64_t *llfp, flock64_t *curfp)
{
	off64_t llfp_end, curfp_end;

	llfp_end = lock_to_end(llfp);
	curfp_end = lock_to_end(curfp);

	if (((llfp_end >= curfp->l_start) &&
	    (llfp->l_start <= curfp->l_start)) ||
	    ((curfp->l_start <= llfp->l_start) && (curfp_end >= llfp->l_start)))
		return (1);
	return (0);
}

/*
 * Determine what the intersecting lock region is, and add that to the
 * 'nl_llpp' locklist in increasing order (by l_start).
 */
static void
nfs4_add_lock_range(flock64_t *lost_flp, flock64_t *local_flp,
    locklist_t **nl_llpp, vnode_t *vp)
{
	locklist_t *intersect_llp, *tmp_fllp, *cur_fllp;
	off64_t lost_flp_end, local_flp_end, len, start;

	NFS4_DEBUG(nfs4_lost_rqst_debug, (CE_NOTE, "nfs4_add_lock_range:"));

	if (!locks_intersect(lost_flp, local_flp))
		return;

	NFS4_DEBUG(nfs4_lost_rqst_debug, (CE_NOTE, "nfs4_add_lock_range: "
	    "locks intersect"));

	lost_flp_end = lock_to_end(lost_flp);
	local_flp_end = lock_to_end(local_flp);

	/* Find the starting point of the intersecting region */
	if (local_flp->l_start > lost_flp->l_start)
		start = local_flp->l_start;
	else
		start = lost_flp->l_start;

	/* Find the lenght of the intersecting region */
	if (lost_flp_end < local_flp_end)
		len = end_to_len(start, lost_flp_end);
	else
		len = end_to_len(start, local_flp_end);

	/*
	 * Prepare the flock structure for the intersection found and insert
	 * it into the new list in increasing l_start order. This list contains
	 * intersections of locks registered by the client with the local host
	 * and the lost lock.
	 * The lock type of this lock is the same as that of the local_flp.
	 */
	intersect_llp = (locklist_t *)kmem_alloc(sizeof (locklist_t), KM_SLEEP);
	intersect_llp->ll_flock.l_start = start;
	intersect_llp->ll_flock.l_len = len;
	intersect_llp->ll_flock.l_type = local_flp->l_type;
	intersect_llp->ll_flock.l_pid = local_flp->l_pid;
	intersect_llp->ll_flock.l_sysid = local_flp->l_sysid;
	intersect_llp->ll_flock.l_whence = 0;	/* aka SEEK_SET */
	intersect_llp->ll_vp = vp;

	tmp_fllp = *nl_llpp;
	cur_fllp = NULL;
	while (tmp_fllp != NULL && tmp_fllp->ll_flock.l_start <
	    intersect_llp->ll_flock.l_start) {
			cur_fllp = tmp_fllp;
			tmp_fllp = tmp_fllp->ll_next;
	}
	if (cur_fllp == NULL) {
		/* first on the list */
		intersect_llp->ll_next = *nl_llpp;
		*nl_llpp = intersect_llp;
	} else {
		intersect_llp->ll_next = cur_fllp->ll_next;
		cur_fllp->ll_next = intersect_llp;
	}

	NFS4_DEBUG(nfs4_lost_rqst_debug, (CE_NOTE, "nfs4_add_lock_range: "
	    "created lock region: start %"PRIx64" end %"PRIx64" : %s\n",
	    intersect_llp->ll_flock.l_start,
	    intersect_llp->ll_flock.l_start + intersect_llp->ll_flock.l_len,
	    intersect_llp->ll_flock.l_type == F_RDLCK ? "READ" : "WRITE"));
}

/*
 * Our local locking current state is potentially different than
 * what the NFSv4 server thinks we have due to a lost lock that was
 * resent and then received.  We need to reset our "NFSv4" locking
 * state to match the current local locking state for this pid since
 * that is what the user/application sees as what the world is.
 *
 * We cannot afford to drop the open/lock seqid sync since then we can
 * get confused about what the current local locking state "is" versus
 * "was".
 *
 * If we are unable to fix up the locks, we send SIGLOST to the affected
 * process.  This is not done if the filesystem has been forcibly
 * unmounted, in case the process has already exited and a new process
 * exists with the same pid.
 */
static void
nfs4_reinstitute_local_lock_state(vnode_t *vp, flock64_t *lost_flp, cred_t *cr,
    nfs4_lock_owner_t *lop)
{
	locklist_t *locks, *llp, *ri_llp, *tmp_llp;
	mntinfo4_t *mi = VTOMI4(vp);
	const int cmd = F_SETLK;
	off64_t cur_start, llp_ll_flock_end, lost_flp_end;
	flock64_t ul_fl;

	NFS4_DEBUG(nfs4_lost_rqst_debug, (CE_NOTE,
	    "nfs4_reinstitute_local_lock_state"));

	/*
	 * Find active locks for this vp from the local locking code.
	 * Scan through this list and find out the locks that intersect with
	 * the lost lock. Once we find the lock that intersects, add the
	 * intersection area as a new lock to a new list "ri_llp". The lock
	 * type of the intersection region lock added to ri_llp is the same
	 * as that found in the active lock list, "list". The intersecting
	 * region locks are added to ri_llp in increasing l_start order.
	 */
	ASSERT(nfs_zone() == mi->mi_zone);

	locks = flk_active_locks_for_vp(vp);
	ri_llp = NULL;

	for (llp = locks; llp != NULL; llp = llp->ll_next) {
		ASSERT(llp->ll_vp == vp);
		/*
		 * Pick locks that belong to this pid/lockowner
		 */
		if (llp->ll_flock.l_pid != lost_flp->l_pid)
			continue;

		nfs4_add_lock_range(lost_flp, &llp->ll_flock, &ri_llp, vp);
	}

	/*
	 * Now we have the list of intersections with the lost lock. These are
	 * the locks that were/are active before the server replied to the
	 * last/lost lock. Issue these locks to the server here. Playing these
	 * locks to the server will re-establish aur current local locking state
	 * with the v4 server.
	 * If we get an error, send SIGLOST to the application for that lock.
	 */

	for (llp = ri_llp; llp != NULL; llp = llp->ll_next) {
		NFS4_DEBUG(nfs4_lost_rqst_debug, (CE_NOTE,
		    "nfs4_reinstitute_local_lock_state: need to issue "
		    "flock: [%"PRIx64" - %"PRIx64"] : %s",
		    llp->ll_flock.l_start,
		    llp->ll_flock.l_start + llp->ll_flock.l_len,
		    llp->ll_flock.l_type == F_RDLCK ? "READ" :
		    llp->ll_flock.l_type == F_WRLCK ? "WRITE" : "INVALID"));
		/*
		 * No need to relock what we already have
		 */
		if (llp->ll_flock.l_type == lost_flp->l_type)
			continue;

		push_reinstate(vp, cmd, &llp->ll_flock, cr, lop);
	}

	/*
	 * Now keeping the start of the lost lock as our reference parse the
	 * newly created ri_llp locklist to find the ranges that we have locked
	 * with the v4 server but not in the current local locking. We need
	 * to unlock these ranges.
	 * These ranges can also be reffered to as those ranges, where the lost
	 * lock does not overlap with the locks in the ri_llp but are locked
	 * since the server replied to the lost lock.
	 */
	cur_start = lost_flp->l_start;
	lost_flp_end = lock_to_end(lost_flp);

	ul_fl.l_type = F_UNLCK;
	ul_fl.l_whence = 0;	/* aka SEEK_SET */
	ul_fl.l_sysid = lost_flp->l_sysid;
	ul_fl.l_pid = lost_flp->l_pid;

	for (llp = ri_llp; llp != NULL; llp = llp->ll_next) {
		llp_ll_flock_end = lock_to_end(&llp->ll_flock);

		if (llp->ll_flock.l_start <= cur_start) {
			cur_start = start_check(llp_ll_flock_end);
			continue;
		}
		NFS4_DEBUG(nfs4_lost_rqst_debug, (CE_NOTE,
		    "nfs4_reinstitute_local_lock_state: "
		    "UNLOCK [%"PRIx64" - %"PRIx64"]",
		    cur_start, llp->ll_flock.l_start));

		ul_fl.l_start = cur_start;
		ul_fl.l_len = end_to_len(cur_start,
		    (llp->ll_flock.l_start - 1));

		push_reinstate(vp, cmd, &ul_fl, cr, lop);
		cur_start = start_check(llp_ll_flock_end);
	}

	/*
	 * In the case where the lost lock ends after all intersecting locks,
	 * unlock the last part of the lost lock range.
	 */
	if (cur_start != start_check(lost_flp_end)) {
		NFS4_DEBUG(nfs4_lost_rqst_debug, (CE_NOTE,
		    "nfs4_reinstitute_local_lock_state: UNLOCK end of the "
		    "lost lock region [%"PRIx64" - %"PRIx64"]",
		    cur_start, lost_flp->l_start + lost_flp->l_len));

		ul_fl.l_start = cur_start;
		/*
		 * Is it an to-EOF lock? if so unlock till the end
		 */
		if (lost_flp->l_len == 0)
			ul_fl.l_len = 0;
		else
			ul_fl.l_len = start_check(lost_flp_end) - cur_start;

		push_reinstate(vp, cmd, &ul_fl, cr, lop);
	}

	if (locks != NULL)
		flk_free_locklist(locks);

	/* Free up our newly created locklist */
	for (llp = ri_llp; llp != NULL; ) {
		tmp_llp = llp->ll_next;
		kmem_free(llp, sizeof (locklist_t));
		llp = tmp_llp;
	}

	/*
	 * Now return back to the original calling nfs4frlock()
	 * and let us naturally drop our seqid syncs.
	 */
}

/*
 * Create a lost state record for the given lock reinstantiation request
 * and push it onto the lost state queue.
 */
static void
push_reinstate(vnode_t *vp, int cmd, flock64_t *flk, cred_t *cr,
    nfs4_lock_owner_t *lop)
{
	nfs4_lost_rqst_t req;
	nfs_lock_type4 locktype;
	nfs4_error_t e = { EINTR, NFS4_OK, RPC_SUCCESS };

	ASSERT(nfs_zone() == VTOMI4(vp)->mi_zone);

	locktype = flk_to_locktype(cmd, flk->l_type);
	nfs4frlock_save_lost_rqst(NFS4_LCK_CTYPE_REINSTATE, EINTR, locktype,
	    NULL, NULL, lop, flk, &req, cr, vp);
	(void) nfs4_start_recovery(&e, VTOMI4(vp), vp, NULL, NULL,
	    (req.lr_op == OP_LOCK || req.lr_op == OP_LOCKU) ?
	    &req : NULL, flk->l_type == F_UNLCK ? OP_LOCKU : OP_LOCK,
	    NULL, NULL, NULL);
}
