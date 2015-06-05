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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _SYS_FEM_H
#define	_SYS_FEM_H

#include <sys/types.h>
#include <sys/mutex.h>
#include <sys/pathname.h>
#include <sys/uio.h>
#include <sys/file.h>
#include <sys/cred.h>
#include <sys/vfs.h>
#include <sys/vnode.h>


#ifdef	__cplusplus
extern "C" {
#endif

#if defined(_KERNEL) || defined(_FAKE_KERNEL)

struct fs_operation_def;	/* from vfs.h */

/*
 * overview:
 *
 * fem - file event monitoring
 *
 * File Event Monitoring is a formalized mechanism to monitor events on a
 * vnode or vfs by intercepting the vnode/vfs operations.  The framework enables
 * the consumer to request event notifications for specified files and
 * directories.  The consumers, which intercept the events, are responsible for
 * delivering the event to the next interceptor or the terminal destination.
 *
 */

/*
 * protocol:
 *
 *  vnode ->  fem_head.
 *	There can only be one fem_head for a vnode.
 *	Once attached, the fem_head persists until explicitly detached
 *	or the vnode expires.
 *
 * fem_head -> fem_list.
 *	There can be many lists for a head, as each reconfiguration of
 *	the list causes a new one to be created and initialized from the
 *	old one.  For this reason, modules cannot assume that they can
 *	reach thier list by vnode->fem_head->fem_list->list[n] == mod;
 *
 * fem_arg -> vnode, &vnode.
 *	This relationship is established at the head of the call (ie. in
 *	femhead_open()) where the fem_arg is allocated.  Intermediate nodes
 *	have direct access to this.
 *
 * fem_arg -> fem_node
 *	This relationship is established at the head of the call (ie. in
 *	femhead_open()) where the fem_arg is allocated.  The fem_arg is
 *	updated as intermediate nodes are invoked, however not as they
 *	return.  For this reason, nodes which are interested in maintaining
 *	context following a "next" should store a copy of the fem_available
 *	field before invoking the 'next'.
 */
typedef struct fem_arg femarg_t, fsemarg_t;
typedef struct fem fem_t;
typedef struct fsem    fsem_t;

typedef int femop_t();

typedef void (*fem_func_t)(void *);

/*
 * The following enumerations specify the conditions
 * under which a monitor (operation/argument combination)
 * should be installed.  These are used when calling
 * fem_install() and fsem_install()
 */
typedef enum femhow {
	FORCE		= 0,	/* Force the installation of this monitor */
	OPUNIQ		= 1,	/* Install if operation set is unique */
	OPARGUNIQ	= 2	/* Install if op/arg combination is unique */
} femhow_t;

struct fem_node {
	void		*fn_available;
	union {
		fem_t		*fem;
		vnodeops_t	*vnode;
		fsem_t		*fsem;
		vfsops_t	*vfs;
		void		*anon; /* anonymous, for updates */
	}		fn_op;
	void		(*fn_av_hold)(void *);	/* Hold for "fn_available" */
	void		(*fn_av_rele)(void *);	/* Release for "fn_available" */
};

struct fem_arg {
	union {
		vnode_t	*vp,
			**vpp;
		vfs_t	*vfsp;
		void	*anon;
	}		fa_vnode;
	struct fem_node	*fa_fnode;
};


struct fem_list {
	uint_t	feml_refc;	/* reference count */
	int	feml_tos;	/* top of stack pointer(index) */
	int	feml_ssize;	/* stack size */
	int	feml_pad;	/* alignment */
	struct fem_node feml_nodes[1]; /* variable bounds */
};

struct fem_head {
	kmutex_t	femh_lock;
	struct fem_list *femh_list;
};

/*
 * FEM_OPS defines all the FEM operations.  It is used to define
 * the fem structure (below) and the fs_func_p union (vfs_opreg.h).
 */
#define	FEM_OPS								\
	int (*femop_open)(femarg_t *vf, int mode, cred_t *cr,		\
			caller_context_t *ct);				\
	int (*femop_close)(femarg_t *vf, int flag, int count,		\
			offset_t offset, cred_t *cr,			\
			caller_context_t *ct);				\
	int (*femop_read)(femarg_t *vf, uio_t *uiop, int ioflag,	\
			cred_t *cr, caller_context_t *ct);		\
	int (*femop_write)(femarg_t *vf, uio_t *uiop, int ioflag,	\
			cred_t *cr, caller_context_t *ct);		\
	int (*femop_ioctl)(femarg_t *vf, int cmd, intptr_t arg,		\
			int flag, cred_t *cr, int *rvalp,		\
			caller_context_t *ct);				\
	int (*femop_setfl)(femarg_t *vf, int oflags, int nflags,	\
			cred_t *cr, caller_context_t *ct);		\
	int (*femop_getattr)(femarg_t *vf, vattr_t *vap, int flags,	\
			cred_t *cr, caller_context_t *ct);		\
	int (*femop_setattr)(femarg_t *vf, vattr_t *vap, int flags,	\
			cred_t *cr, caller_context_t *ct);		\
	int (*femop_access)(femarg_t *vf, int mode, int flags,		\
			cred_t *cr, caller_context_t *ct);		\
	int (*femop_lookup)(femarg_t *vf, char *nm, vnode_t **vpp,	\
			pathname_t *pnp, int flags, vnode_t *rdir,	\
			cred_t *cr, caller_context_t *ct,		\
			int *direntflags, pathname_t *realpnp);		\
	int (*femop_create)(femarg_t *vf, char *name, vattr_t *vap,	\
			vcexcl_t excl, int mode, vnode_t **vpp,		\
			cred_t *cr, int flag, caller_context_t *ct,	\
			vsecattr_t *vsecp);				\
	int (*femop_remove)(femarg_t *vf, char *nm, cred_t *cr,		\
			caller_context_t *ct, int flags);		\
	int (*femop_link)(femarg_t *vf, vnode_t *svp, char *tnm,	\
			cred_t *cr, caller_context_t *ct, int flags);	\
	int (*femop_rename)(femarg_t *vf, char *snm, vnode_t *tdvp,	\
			char *tnm, cred_t *cr, caller_context_t *ct,	\
			int flags);					\
	int (*femop_mkdir)(femarg_t *vf, char *dirname, vattr_t *vap,	\
			vnode_t **vpp, cred_t *cr,			\
			caller_context_t *ct, int flags,		\
			vsecattr_t *vsecp);				\
	int (*femop_rmdir)(femarg_t *vf, char *nm, vnode_t *cdir,	\
			cred_t *cr, caller_context_t *ct, int flags);	\
	int (*femop_readdir)(femarg_t *vf, uio_t *uiop, cred_t *cr,	\
			int *eofp, caller_context_t *ct, int flags);	\
	int (*femop_symlink)(femarg_t *vf, char *linkname,		\
			vattr_t *vap, char *target, cred_t *cr,		\
			caller_context_t *ct, int flags);		\
	int (*femop_readlink)(femarg_t *vf, uio_t *uiop, cred_t *cr,	\
			caller_context_t *ct);				\
	int (*femop_fsync)(femarg_t *vf, int syncflag, cred_t *cr,	\
			caller_context_t *ct);				\
	void (*femop_inactive)(femarg_t *vf, cred_t *cr,		\
			caller_context_t *ct);				\
	int (*femop_fid)(femarg_t *vf, fid_t *fidp,			\
			caller_context_t *ct);				\
	int (*femop_rwlock)(femarg_t *vf, int write_lock,		\
			caller_context_t *ct);				\
	void (*femop_rwunlock)(femarg_t *vf, int write_lock,		\
			caller_context_t *ct);				\
	int (*femop_seek)(femarg_t *vf, offset_t ooff,			\
			offset_t *noffp, caller_context_t *ct);		\
	int (*femop_cmp)(femarg_t *vf, vnode_t *vp2,			\
			caller_context_t *ct);				\
	int (*femop_frlock)(femarg_t *vf, int cmd, struct flock64 *bfp,	\
			int flag, offset_t offset,			\
			struct flk_callback *flk_cbp, cred_t *cr,	\
			caller_context_t *ct);				\
	int (*femop_space)(femarg_t *vf, int cmd, struct flock64 *bfp,	\
			int flag, offset_t offset, cred_t *cr,		\
			caller_context_t *ct);				\
	int (*femop_realvp)(femarg_t *vf, vnode_t **vpp,		\
			caller_context_t *ct);				\
	int (*femop_getpage)(femarg_t *vf, offset_t off, size_t len,	\
			uint_t *protp, struct page **plarr,		\
			size_t plsz, struct seg *seg, caddr_t addr,	\
			enum seg_rw rw,	cred_t *cr,			\
			caller_context_t *ct);				\
	int (*femop_putpage)(femarg_t *vf, offset_t off, size_t len,	\
			int flags, cred_t *cr, caller_context_t *ct);	\
	int (*femop_map)(femarg_t *vf, offset_t off, struct as *as,	\
			caddr_t *addrp, size_t len, uchar_t prot,	\
			uchar_t maxprot, uint_t flags, cred_t *cr,	\
			caller_context_t *ct);				\
	int (*femop_addmap)(femarg_t *vf, offset_t off, struct as *as,	\
			caddr_t addr, size_t len, uchar_t prot,		\
			uchar_t maxprot, uint_t flags, cred_t *cr,	\
			caller_context_t *ct);				\
	int (*femop_delmap)(femarg_t *vf, offset_t off, struct as *as,	\
			caddr_t addr, size_t len, uint_t prot,		\
			uint_t maxprot, uint_t flags, cred_t *cr,	\
			caller_context_t *ct);				\
	int (*femop_poll)(femarg_t *vf, short events, int anyyet,	\
			short *reventsp, struct pollhead **phpp,	\
			caller_context_t *ct);				\
	int (*femop_dump)(femarg_t *vf, caddr_t addr, offset_t lbdn,	\
			offset_t dblks, caller_context_t *ct);		\
	int (*femop_pathconf)(femarg_t *vf, int cmd, ulong_t *valp,	\
			cred_t *cr, caller_context_t *ct);		\
	int (*femop_pageio)(femarg_t *vf, struct page *pp,		\
			u_offset_t io_off, size_t io_len, int flags,	\
			cred_t *cr, caller_context_t *ct);		\
	int (*femop_dumpctl)(femarg_t *vf, int action, offset_t *blkp,	\
			caller_context_t *ct);				\
	void (*femop_dispose)(femarg_t *vf, struct page *pp, int flag,	\
			int dn, cred_t *cr, caller_context_t *ct);	\
	int (*femop_setsecattr)(femarg_t *vf, vsecattr_t *vsap,		\
			int flag, cred_t *cr, caller_context_t *ct);	\
	int (*femop_getsecattr)(femarg_t *vf, vsecattr_t *vsap,		\
			int flag, cred_t *cr, caller_context_t *ct);	\
	int (*femop_shrlock)(femarg_t *vf, int cmd,			\
			struct shrlock *shr, int flag, cred_t *cr,	\
			caller_context_t *ct);				\
	int (*femop_vnevent)(femarg_t *vf, vnevent_t vnevent,		\
			vnode_t *dvp, char *cname, 			\
			caller_context_t *ct);				\
	int (*femop_reqzcbuf)(femarg_t *vf, enum uio_rw ioflag,		\
			xuio_t *xuio, cred_t *cr,			\
			caller_context_t *ct);				\
	int (*femop_retzcbuf)(femarg_t *vf, xuio_t *xuio, cred_t *cr,	\
			caller_context_t *ct)
	/* NB: No ";" */

struct fem {
	const char *name;
	const struct fs_operation_def *templ;
	FEM_OPS;	/* Signatures of all FEM operations (femops) */
};

/*
 * FSEM_OPS defines all the FSEM operations.  It is used to define
 * the fsem structure (below) and the fs_func_p union (vfs_opreg.h).
 */
#define	FSEM_OPS							\
	int (*fsemop_mount)(fsemarg_t *vf, vnode_t *mvp,		\
			struct mounta *uap, cred_t *cr);		\
	int (*fsemop_unmount)(fsemarg_t *vf, int flag, cred_t *cr);	\
	int (*fsemop_root)(fsemarg_t *vf, vnode_t **vpp);		\
	int (*fsemop_statvfs)(fsemarg_t *vf, statvfs64_t *sp);		\
	int (*fsemop_sync)(fsemarg_t *vf, short flag, cred_t *cr);	\
	int (*fsemop_vget)(fsemarg_t *vf, vnode_t **vpp, fid_t *fidp);	\
	int (*fsemop_mountroot)(fsemarg_t *vf,				\
			enum whymountroot reason);			\
	void (*fsemop_freevfs)(fsemarg_t *vf);				\
	int (*fsemop_vnstate)(fsemarg_t *vf, vnode_t *vp,		\
			vntrans_t nstate)		/* NB: No ";" */

struct fsem {
	const char *name;
	const struct fs_operation_def *templ;
	FSEM_OPS;	/* Signatures of all FSEM operations (fsemops) */
};

extern int vnext_open(femarg_t *vf, int mode, cred_t *cr,
		caller_context_t *ct);
extern int vnext_close(femarg_t *vf, int flag, int count, offset_t offset,
		cred_t *cr, caller_context_t *ct);
extern int vnext_read(femarg_t *vf, uio_t *uiop, int ioflag, cred_t *cr,
		caller_context_t *ct);
extern int vnext_write(femarg_t *vf, uio_t *uiop, int ioflag, cred_t *cr,
		caller_context_t *ct);
extern int vnext_ioctl(femarg_t *vf, int cmd, intptr_t arg, int flag,
		cred_t *cr, int *rvalp, caller_context_t *ct);
extern int vnext_setfl(femarg_t *vf, int oflags, int nflags, cred_t *cr,
		caller_context_t *ct);
extern int vnext_getattr(femarg_t *vf, vattr_t *vap, int flags, cred_t *cr,
		caller_context_t *ct);
extern int vnext_setattr(femarg_t *vf, vattr_t *vap, int flags, cred_t *cr,
		caller_context_t *ct);
extern int vnext_access(femarg_t *vf, int mode, int flags, cred_t *cr,
		caller_context_t *ct);
extern int vnext_lookup(femarg_t *vf, char *nm, vnode_t **vpp,
			pathname_t *pnp, int flags, vnode_t *rdir,
			cred_t *cr, caller_context_t *ct,
			int *direntflags, pathname_t *realpnp);
extern int vnext_create(femarg_t *vf, char *name, vattr_t *vap,
			vcexcl_t excl, int mode, vnode_t **vpp, cred_t *cr,
			int flag, caller_context_t *ct, vsecattr_t *vsecp);
extern int vnext_remove(femarg_t *vf, char *nm, cred_t *cr,
			caller_context_t *ct, int flags);
extern int vnext_link(femarg_t *vf, vnode_t *svp, char *tnm, cred_t *cr,
			caller_context_t *ct, int flags);
extern int vnext_rename(femarg_t *vf, char *snm, vnode_t *tdvp, char *tnm,
			cred_t *cr, caller_context_t *ct, int flags);
extern int vnext_mkdir(femarg_t *vf, char *dirname, vattr_t *vap,
			vnode_t **vpp, cred_t *cr, caller_context_t *ct,
			int flags, vsecattr_t *vsecp);
extern int vnext_rmdir(femarg_t *vf, char *nm, vnode_t *cdir, cred_t *cr,
			caller_context_t *ct, int flags);
extern int vnext_readdir(femarg_t *vf, uio_t *uiop, cred_t *cr, int *eofp,
			caller_context_t *ct, int flags);
extern int vnext_symlink(femarg_t *vf, char *linkname, vattr_t *vap,
			char *target, cred_t *cr, caller_context_t *ct,
			int flags);
extern int vnext_readlink(femarg_t *vf, uio_t *uiop, cred_t *cr,
			caller_context_t *ct);
extern int vnext_fsync(femarg_t *vf, int syncflag, cred_t *cr,
			caller_context_t *ct);
extern void vnext_inactive(femarg_t *vf, cred_t *cr, caller_context_t *ct);
extern int vnext_fid(femarg_t *vf, fid_t *fidp, caller_context_t *ct);
extern int vnext_rwlock(femarg_t *vf, int write_lock, caller_context_t *ct);
extern void vnext_rwunlock(femarg_t *vf, int write_lock, caller_context_t *ct);
extern int vnext_seek(femarg_t *vf, offset_t ooff, offset_t *noffp,
			caller_context_t *ct);
extern int vnext_cmp(femarg_t *vf, vnode_t *vp2, caller_context_t *ct);
extern int vnext_frlock(femarg_t *vf, int cmd, struct flock64 *bfp,
			int flag, offset_t offset,
			struct flk_callback *flk_cbp, cred_t *cr,
			caller_context_t *ct);
extern int vnext_space(femarg_t *vf, int cmd, struct flock64 *bfp,
			int flag, offset_t offset, cred_t *cr,
			caller_context_t *ct);
extern int vnext_realvp(femarg_t *vf, vnode_t **vpp, caller_context_t *ct);
extern int vnext_getpage(femarg_t *vf, offset_t off, size_t len,
			uint_t *protp, struct page **plarr, size_t plsz,
			struct seg *seg, caddr_t addr, enum seg_rw rw,
			cred_t *cr, caller_context_t *ct);
extern int vnext_putpage(femarg_t *vf, offset_t off, size_t len, int flags,
			cred_t *cr, caller_context_t *ct);
extern int vnext_map(femarg_t *vf, offset_t off, struct as *as,
		caddr_t *addrp, size_t len, uchar_t prot, uchar_t maxprot,
		uint_t flags, cred_t *cr, caller_context_t *ct);
extern int vnext_addmap(femarg_t *vf, offset_t off, struct as *as,
			caddr_t addr, size_t len, uchar_t prot,
			uchar_t maxprot, uint_t flags, cred_t *cr,
			caller_context_t *ct);
extern int vnext_delmap(femarg_t *vf, offset_t off, struct as *as,
			caddr_t addr, size_t len, uint_t prot,
			uint_t maxprot, uint_t flags, cred_t *cr,
			caller_context_t *ct);
extern int vnext_poll(femarg_t *vf, short events, int anyyet,
			short *reventsp, struct pollhead **phpp,
			caller_context_t *ct);
extern int vnext_dump(femarg_t *vf, caddr_t addr, offset_t lbdn,
    offset_t dblks, caller_context_t *ct);
extern int vnext_pathconf(femarg_t *vf, int cmd, ulong_t *valp, cred_t *cr,
			caller_context_t *ct);
extern int vnext_pageio(femarg_t *vf, struct page *pp, u_offset_t io_off,
			size_t io_len, int flags, cred_t *cr,
			caller_context_t *ct);
extern int vnext_dumpctl(femarg_t *vf, int action, offset_t *blkp,
			caller_context_t *ct);
extern void vnext_dispose(femarg_t *vf, struct page *pp, int flag, int dn,
			cred_t *cr, caller_context_t *ct);
extern int vnext_setsecattr(femarg_t *vf, vsecattr_t *vsap, int flag,
			cred_t *cr, caller_context_t *ct);
extern int vnext_getsecattr(femarg_t *vf, vsecattr_t *vsap, int flag,
			cred_t *cr, caller_context_t *ct);
extern int vnext_shrlock(femarg_t *vf, int cmd, struct shrlock *shr,
			int flag, cred_t *cr, caller_context_t *ct);
extern int vnext_vnevent(femarg_t *vf, vnevent_t vevent, vnode_t *dvp,
			char *cname, caller_context_t *ct);
extern int vnext_reqzcbuf(femarg_t *vf, enum uio_rw ioflag, xuio_t *xuiop,
			cred_t *cr, caller_context_t *ct);
extern int vnext_retzcbuf(femarg_t *vf, xuio_t *xuiop, cred_t *cr,
			caller_context_t *ct);

extern int vfsnext_mount(fsemarg_t *vf, vnode_t *mvp, struct mounta *uap,
			cred_t *cr);
extern int vfsnext_unmount(fsemarg_t *vf, int flag, cred_t *cr);
extern int vfsnext_root(fsemarg_t *vf, vnode_t **vpp);
extern int vfsnext_statvfs(fsemarg_t *vf, statvfs64_t *sp);
extern int vfsnext_sync(fsemarg_t *vf, short flag, cred_t *cr);
extern int vfsnext_vget(fsemarg_t *vf, vnode_t **vpp, fid_t *fidp);
extern int vfsnext_mountroot(fsemarg_t *vf, enum whymountroot reason);
extern void vfsnext_freevfs(fsemarg_t *vf);
extern int vfsnext_vnstate(fsemarg_t *vf, vnode_t *vp, vntrans_t nstate);


extern void fem_init(void); /* called once, by startup */

/* fem api */
extern int fem_create(char *name, const struct fs_operation_def *templ,
			fem_t **actual);
extern void fem_free(fem_t *fem);
extern int fem_install(struct vnode *v, fem_t *mon, void *arg, femhow_t how,
		void (*arg_hold)(void *), void (*arg_rele)(void *));
extern int fem_is_installed(struct vnode *v, fem_t *mon, void *arg);
extern int fem_uninstall(struct vnode *v, fem_t *mon, void *arg);
extern vnodeops_t *fem_getvnops(struct vnode *v);
extern void fem_setvnops(struct vnode *v, struct vnodeops *nops);


extern int fsem_create(char *name, const struct fs_operation_def *templ,
			fsem_t **actual);
extern void fsem_free(fsem_t *fsem);
extern int fsem_is_installed(struct vfs *v, fsem_t *mon, void *arg);
extern int fsem_install(struct vfs *v, fsem_t *mon, void *arg, femhow_t how,
		void (*arg_hold)(void *), void (*arg_rele)(void *));
extern int fsem_uninstall(struct vfs *v, fsem_t *mon, void *arg);
extern vfsops_t *fsem_getvfsops(struct vfs *v);
extern void fsem_setvfsops(struct vfs *v, struct vfsops *nops);

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FEM_H */
