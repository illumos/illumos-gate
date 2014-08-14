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
 */

#include <sys/types.h>
#include <sys/atomic.h>
#include <sys/kmem.h>
#include <sys/mutex.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>

#include <sys/fem.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/vfs_opreg.h>

#define	NNODES_DEFAULT	8	/* Default number of nodes in a fem_list */
/*
 * fl_ntob(n) - Fem_list: number of nodes to bytes
 * Given the number of nodes in a fem_list return the size, in bytes,
 * of the fem_list structure.
 */
#define	fl_ntob(n)	(sizeof (struct fem_list) + \
			((n) - 1) * sizeof (struct fem_node))

typedef enum {
	FEMTYPE_NULL,	/* Uninitialized */
	FEMTYPE_VNODE,
	FEMTYPE_VFS,
	FEMTYPE_NTYPES
} femtype_t;

#define	FEM_HEAD(_t) femtype[(_t)].head.fn_op.anon
#define	FEM_GUARD(_t) femtype[(_t)].guard

static struct fem_type_info {
	struct fem_node		head;
	struct fem_node		guard;
	femop_t			*errf;
}	femtype[FEMTYPE_NTYPES];


/*
 * For each type, two tables - the translation offset definition, which
 * is used by fs_build_vector to layout the operation(s) vector; and the
 * guard_operation_vector which protects from stack under-run.
 */

int fem_err();
int fsem_err();


#define	_FEMOPDEF(name, member)  \
	{ VOPNAME_##name, offsetof(fem_t, femop_##member), NULL, fem_err }

static fs_operation_trans_def_t	fem_opdef[] = {
	_FEMOPDEF(OPEN,		open),
	_FEMOPDEF(CLOSE,	close),
	_FEMOPDEF(READ,		read),
	_FEMOPDEF(WRITE,	write),
	_FEMOPDEF(IOCTL,	ioctl),
	_FEMOPDEF(SETFL,	setfl),
	_FEMOPDEF(GETATTR,	getattr),
	_FEMOPDEF(SETATTR,	setattr),
	_FEMOPDEF(ACCESS,	access),
	_FEMOPDEF(LOOKUP,	lookup),
	_FEMOPDEF(CREATE,	create),
	_FEMOPDEF(REMOVE,	remove),
	_FEMOPDEF(LINK,		link),
	_FEMOPDEF(RENAME,	rename),
	_FEMOPDEF(MKDIR,	mkdir),
	_FEMOPDEF(RMDIR,	rmdir),
	_FEMOPDEF(READDIR,	readdir),
	_FEMOPDEF(SYMLINK,	symlink),
	_FEMOPDEF(READLINK,	readlink),
	_FEMOPDEF(FSYNC,	fsync),
	_FEMOPDEF(INACTIVE,	inactive),
	_FEMOPDEF(FID,		fid),
	_FEMOPDEF(RWLOCK,	rwlock),
	_FEMOPDEF(RWUNLOCK,	rwunlock),
	_FEMOPDEF(SEEK,		seek),
	_FEMOPDEF(CMP,		cmp),
	_FEMOPDEF(FRLOCK,	frlock),
	_FEMOPDEF(SPACE,	space),
	_FEMOPDEF(REALVP,	realvp),
	_FEMOPDEF(GETPAGE,	getpage),
	_FEMOPDEF(PUTPAGE,	putpage),
	_FEMOPDEF(MAP,		map),
	_FEMOPDEF(ADDMAP,	addmap),
	_FEMOPDEF(DELMAP,	delmap),
	_FEMOPDEF(POLL,		poll),
	_FEMOPDEF(DUMP,		dump),
	_FEMOPDEF(PATHCONF,	pathconf),
	_FEMOPDEF(PAGEIO,	pageio),
	_FEMOPDEF(DUMPCTL,	dumpctl),
	_FEMOPDEF(DISPOSE,	dispose),
	_FEMOPDEF(SETSECATTR,	setsecattr),
	_FEMOPDEF(GETSECATTR,	getsecattr),
	_FEMOPDEF(SHRLOCK,	shrlock),
	_FEMOPDEF(VNEVENT,	vnevent),
	_FEMOPDEF(REQZCBUF,	reqzcbuf),
	_FEMOPDEF(RETZCBUF,	retzcbuf),
	{ NULL, 0, NULL, NULL }
};


#define	_FEMGUARD(name, ignore)  \
	{ VOPNAME_##name, (femop_t *)fem_err }

static struct fs_operation_def fem_guard_ops[] = {
	_FEMGUARD(OPEN,		open),
	_FEMGUARD(CLOSE,	close),
	_FEMGUARD(READ,		read),
	_FEMGUARD(WRITE,	write),
	_FEMGUARD(IOCTL,	ioctl),
	_FEMGUARD(SETFL,	setfl),
	_FEMGUARD(GETATTR,	getattr),
	_FEMGUARD(SETATTR,	setattr),
	_FEMGUARD(ACCESS,	access),
	_FEMGUARD(LOOKUP,	lookup),
	_FEMGUARD(CREATE,	create),
	_FEMGUARD(REMOVE,	remove),
	_FEMGUARD(LINK,		link),
	_FEMGUARD(RENAME,	rename),
	_FEMGUARD(MKDIR,	mkdir),
	_FEMGUARD(RMDIR,	rmdir),
	_FEMGUARD(READDIR,	readdir),
	_FEMGUARD(SYMLINK,	symlink),
	_FEMGUARD(READLINK,	readlink),
	_FEMGUARD(FSYNC,	fsync),
	_FEMGUARD(INACTIVE,	inactive),
	_FEMGUARD(FID,		fid),
	_FEMGUARD(RWLOCK,	rwlock),
	_FEMGUARD(RWUNLOCK,	rwunlock),
	_FEMGUARD(SEEK,		seek),
	_FEMGUARD(CMP,		cmp),
	_FEMGUARD(FRLOCK,	frlock),
	_FEMGUARD(SPACE,	space),
	_FEMGUARD(REALVP,	realvp),
	_FEMGUARD(GETPAGE,	getpage),
	_FEMGUARD(PUTPAGE,	putpage),
	_FEMGUARD(MAP,		map),
	_FEMGUARD(ADDMAP,	addmap),
	_FEMGUARD(DELMAP,	delmap),
	_FEMGUARD(POLL,		poll),
	_FEMGUARD(DUMP,		dump),
	_FEMGUARD(PATHCONF,	pathconf),
	_FEMGUARD(PAGEIO,	pageio),
	_FEMGUARD(DUMPCTL,	dumpctl),
	_FEMGUARD(DISPOSE,	dispose),
	_FEMGUARD(SETSECATTR,	setsecattr),
	_FEMGUARD(GETSECATTR,	getsecattr),
	_FEMGUARD(SHRLOCK,	shrlock),
	_FEMGUARD(VNEVENT,	vnevent),
	_FEMGUARD(REQZCBUF,	reqzcbuf),
	_FEMGUARD(RETZCBUF,	retzcbuf),
	{ NULL, NULL }
};


#define	_FSEMOPDEF(name, member)  \
	{ VFSNAME_##name, offsetof(fsem_t, fsemop_##member), NULL, fsem_err }

static fs_operation_trans_def_t fsem_opdef[] = {
	_FSEMOPDEF(MOUNT, 	mount),
	_FSEMOPDEF(UNMOUNT,	unmount),
	_FSEMOPDEF(ROOT,	root),
	_FSEMOPDEF(STATVFS,	statvfs),
	_FSEMOPDEF(SYNC,	sync),
	_FSEMOPDEF(VGET,	vget),
	_FSEMOPDEF(MOUNTROOT,	mountroot),
	_FSEMOPDEF(FREEVFS,	freevfs),
	_FSEMOPDEF(VNSTATE,	vnstate),
	{ NULL, 0, NULL, NULL }
};

#define	_FSEMGUARD(name, ignore)  \
	{ VFSNAME_##name, (femop_t *)fsem_err }

static struct fs_operation_def fsem_guard_ops[] = {
	_FSEMGUARD(MOUNT, 	mount),
	_FSEMGUARD(UNMOUNT,	unmount),
	_FSEMGUARD(ROOT,	root),
	_FSEMGUARD(STATVFS,	statvfs),
	_FSEMGUARD(SYNC,	sync),
	_FSEMGUARD(VGET,	vget),
	_FSEMGUARD(MOUNTROOT,	mountroot),
	_FSEMGUARD(FREEVFS,	freevfs),
	_FSEMGUARD(VNSTATE,	vnstate),
	{ NULL, NULL}
};


/*
 * vsop_find, vfsop_find -
 *
 * These macros descend the stack until they find either a basic
 * vnode/vfs operation [ indicated by a null fn_available ] or a
 * stacked item where this method is non-null [_vsop].
 *
 * The DEBUG one is written with a single function which manually applies
 * the structure offsets.  It can have additional debugging support.
 */

#ifndef DEBUG

#define	vsop_find(ap, func, funct, arg0, _vop, _vsop) \
for (;;) { \
	if ((ap)->fa_fnode->fn_available == NULL) { \
		*(func) = (funct (*)())((ap)->fa_fnode->fn_op.vnode->_vop); \
		*(arg0) = (void *)(ap)->fa_vnode.vp; \
		break;	\
	} else if ((*(func) = (funct (*)())((ap)->fa_fnode->fn_op.fem->_vsop))\
		    != NULL) { \
		*(arg0) = (void *) (ap); \
		break;	\
	} else { \
		(ap)->fa_fnode--; \
	} \
} \

#define	vfsop_find(ap, func, funct, arg0, _vop, _vsop) \
for (;;) { \
	if ((ap)->fa_fnode->fn_available == NULL) { \
		*(func) = (funct (*)())((ap)->fa_fnode->fn_op.vfs->_vop); \
		*(arg0) = (void *)(ap)->fa_vnode.vp; \
		break; \
	} else if ((*(func) = (funct (*)())((ap)->fa_fnode->fn_op.fsem->_vsop))\
		    != NULL) { \
		*(arg0) = (void *) (ap); \
		break; \
	} else { \
		(ap)->fa_fnode--; \
	} \
} \

#else

#define	vsop_find(ap, func, funct, arg0, _vop, _vsop) \
	*(arg0) = _op_find((ap), (void **)(func), \
			offsetof(vnodeops_t, _vop), offsetof(fem_t, _vsop))

#define	vfsop_find(ap, func, funct, arg0, _fop, _fsop) \
	*(arg0) = _op_find((ap), (void **)(func), \
			offsetof(vfsops_t, _fop), offsetof(fsem_t, _fsop))

static void *
_op_find(femarg_t *ap, void **fp, int offs0, int offs1)
{
	void *ptr;
	for (;;) {
		struct fem_node	*fnod = ap->fa_fnode;
		if (fnod->fn_available == NULL) {
			*fp = *(void **)((char *)fnod->fn_op.anon + offs0);
			ptr = (void *)(ap->fa_vnode.anon);
			break;
		} else if ((*fp = *(void **)((char *)fnod->fn_op.anon+offs1))
		    != NULL) {
			ptr = (void *)(ap);
			break;
		} else {
			ap->fa_fnode--;
		}
	}
	return (ptr);
}
#endif

static fem_t *
fem_alloc()
{
	fem_t	*p;

	p = (fem_t *)kmem_alloc(sizeof (*p), KM_SLEEP);
	return (p);
}

void
fem_free(fem_t *p)
{
	kmem_free(p, sizeof (*p));
}

static fsem_t *
fsem_alloc()
{
	fsem_t	*p;

	p = (fsem_t *)kmem_alloc(sizeof (*p), KM_SLEEP);
	return (p);
}

void
fsem_free(fsem_t *p)
{
	kmem_free(p, sizeof (*p));
}


/*
 * fem_get, fem_release - manage reference counts on the stack.
 *
 * The list of monitors can be updated while operations are in
 * progress on the object.
 *
 * The reference count facilitates this by counting the number of
 * current accessors, and deconstructing the list when it is exhausted.
 *
 * fem_lock() is required to:
 *	look at femh_list
 *	update what femh_list points to
 *	update femh_list
 *	increase femh_list->feml_refc.
 *
 * the feml_refc can decrement without holding the lock;
 * when feml_refc becomes zero, the list is destroyed.
 *
 */

static struct fem_list *
fem_lock(struct fem_head *fp)
{
	struct fem_list	*sp = NULL;

	ASSERT(fp != NULL);
	mutex_enter(&fp->femh_lock);
	sp = fp->femh_list;
	return (sp);
}

static void
fem_unlock(struct fem_head *fp)
{
	ASSERT(fp != NULL);
	mutex_exit(&fp->femh_lock);
}

/*
 * Addref can only be called while its head->lock is held.
 */

static void
fem_addref(struct fem_list *sp)
{
	atomic_inc_32(&sp->feml_refc);
}

static uint32_t
fem_delref(struct fem_list *sp)
{
	return (atomic_dec_32_nv(&sp->feml_refc));
}

static struct fem_list *
fem_get(struct fem_head *fp)
{
	struct fem_list *sp = NULL;

	if (fp != NULL) {
		if ((sp = fem_lock(fp)) != NULL) {
			fem_addref(sp);
		}
		fem_unlock(fp);
	}
	return (sp);
}

static void
fem_release(struct fem_list *sp)
{
	int	i;

	ASSERT(sp->feml_refc != 0);
	if (fem_delref(sp) == 0) {
		/*
		 * Before freeing the list, we need to release the
		 * caller-provided data.
		 */
		for (i = sp->feml_tos; i > 0; i--) {
			struct fem_node *fnp = &sp->feml_nodes[i];

			if (fnp->fn_av_rele)
				(*(fnp->fn_av_rele))(fnp->fn_available);
		}
		kmem_free(sp, fl_ntob(sp->feml_ssize));
	}
}


/*
 * These are the 'head' operations which perform the interposition.
 *
 * This set must be 1:1, onto with the (vnodeops, vfsos).
 *
 * If there is a desire to globally disable interposition for a particular
 * method, the corresponding 'head' routine should unearth the base method
 * and invoke it directly rather than bypassing the function.
 *
 * All the functions are virtually the same, save for names, types & args.
 *  1. get a reference to the monitor stack for this object.
 *  2. store the top of stack into the femarg structure.
 *  3. store the basic object (vnode *, vnode **, vfs *) in the femarg struc.
 *  4. invoke the "top" method for this object.
 *  5. release the reference to the monitor stack.
 *
 */

static int
vhead_open(vnode_t **vpp, int mode, cred_t *cr, caller_context_t *ct)
{
	femarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	if ((femsp = fem_lock((*vpp)->v_femhead)) == NULL) {
		func = (int (*)()) ((*vpp)->v_op->vop_open);
		arg0 = (void *)vpp;
		fem_unlock((*vpp)->v_femhead);
		errc = (*func)(arg0, mode, cr, ct);
	} else {
		fem_addref(femsp);
		fem_unlock((*vpp)->v_femhead);
		farg.fa_vnode.vpp = vpp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vsop_find(&farg, &func, int, &arg0, vop_open, femop_open);
		errc = (*func)(arg0, mode, cr, ct);
		fem_release(femsp);
	}
	return (errc);
}

static int
vhead_close(vnode_t *vp, int flag, int count, offset_t offset, cred_t *cr,
	caller_context_t *ct)
{
	femarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	if ((femsp = fem_lock(vp->v_femhead)) == NULL) {
		func = (int (*)()) (vp->v_op->vop_close);
		arg0 = vp;
		fem_unlock(vp->v_femhead);
		errc = (*func)(arg0, flag, count, offset, cr, ct);
	} else {
		fem_addref(femsp);
		fem_unlock(vp->v_femhead);
		farg.fa_vnode.vp = vp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vsop_find(&farg, &func, int, &arg0, vop_close, femop_close);
		errc = (*func)(arg0, flag, count, offset, cr, ct);
		fem_release(femsp);
	}
	return (errc);
}

static int
vhead_read(vnode_t *vp, uio_t *uiop, int ioflag, cred_t *cr,
	caller_context_t *ct)
{
	femarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	if ((femsp = fem_lock(vp->v_femhead)) == NULL) {
		func = (int (*)()) (vp->v_op->vop_read);
		arg0 = vp;
		fem_unlock(vp->v_femhead);
		errc = (*func)(arg0, uiop, ioflag, cr, ct);
	} else {
		fem_addref(femsp);
		fem_unlock(vp->v_femhead);
		farg.fa_vnode.vp = vp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vsop_find(&farg, &func, int, &arg0, vop_read, femop_read);
		errc = (*func)(arg0, uiop, ioflag, cr, ct);
		fem_release(femsp);
	}
	return (errc);
}

static int
vhead_write(vnode_t *vp, uio_t *uiop, int ioflag, cred_t *cr,
	caller_context_t *ct)
{
	femarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	if ((femsp = fem_lock(vp->v_femhead)) == NULL) {
		func = (int (*)()) (vp->v_op->vop_write);
		arg0 = vp;
		fem_unlock(vp->v_femhead);
		errc = (*func)(arg0, uiop, ioflag, cr, ct);
	} else {
		fem_addref(femsp);
		fem_unlock(vp->v_femhead);
		farg.fa_vnode.vp = vp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vsop_find(&farg, &func, int, &arg0, vop_write, femop_write);
		errc = (*func)(arg0, uiop, ioflag, cr, ct);
		fem_release(femsp);
	}
	return (errc);
}

static int
vhead_ioctl(vnode_t *vp, int cmd, intptr_t arg, int flag, cred_t *cr,
	int *rvalp, caller_context_t *ct)
{
	femarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	if ((femsp = fem_lock(vp->v_femhead)) == NULL) {
		func = (int (*)()) (vp->v_op->vop_ioctl);
		arg0 = vp;
		fem_unlock(vp->v_femhead);
		errc = (*func)(arg0, cmd, arg, flag, cr, rvalp, ct);
	} else {
		fem_addref(femsp);
		fem_unlock(vp->v_femhead);
		farg.fa_vnode.vp = vp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vsop_find(&farg, &func, int, &arg0, vop_ioctl, femop_ioctl);
		errc = (*func)(arg0, cmd, arg, flag, cr, rvalp, ct);
		fem_release(femsp);
	}
	return (errc);
}

static int
vhead_setfl(vnode_t *vp, int oflags, int nflags, cred_t *cr,
	caller_context_t *ct)
{
	femarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	if ((femsp = fem_lock(vp->v_femhead)) == NULL) {
		func = (int (*)()) (vp->v_op->vop_setfl);
		arg0 = vp;
		fem_unlock(vp->v_femhead);
		errc = (*func)(arg0, oflags, nflags, cr, ct);
	} else {
		fem_addref(femsp);
		fem_unlock(vp->v_femhead);
		farg.fa_vnode.vp = vp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vsop_find(&farg, &func, int, &arg0, vop_setfl, femop_setfl);
		errc = (*func)(arg0, oflags, nflags, cr, ct);
		fem_release(femsp);
	}
	return (errc);
}

static int
vhead_getattr(vnode_t *vp, vattr_t *vap, int flags, cred_t *cr,
	caller_context_t *ct)
{
	femarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	if ((femsp = fem_lock(vp->v_femhead)) == NULL) {
		func = (int (*)()) (vp->v_op->vop_getattr);
		arg0 = vp;
		fem_unlock(vp->v_femhead);
		errc = (*func)(arg0, vap, flags, cr, ct);
	} else {
		fem_addref(femsp);
		fem_unlock(vp->v_femhead);
		farg.fa_vnode.vp = vp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vsop_find(&farg, &func, int, &arg0, vop_getattr,
		    femop_getattr);
		errc = (*func)(arg0, vap, flags, cr, ct);
		fem_release(femsp);
	}
	return (errc);
}

static int
vhead_setattr(vnode_t *vp, vattr_t *vap, int flags, cred_t *cr,
	caller_context_t *ct)
{
	femarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	if ((femsp = fem_lock(vp->v_femhead)) == NULL) {
		func = (int (*)()) (vp->v_op->vop_setattr);
		arg0 = vp;
		fem_unlock(vp->v_femhead);
		errc = (*func)(arg0, vap, flags, cr, ct);
	} else {
		fem_addref(femsp);
		fem_unlock(vp->v_femhead);
		farg.fa_vnode.vp = vp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vsop_find(&farg, &func, int, &arg0, vop_setattr,
		    femop_setattr);
		errc = (*func)(arg0, vap, flags, cr, ct);
		fem_release(femsp);
	}
	return (errc);
}

static int
vhead_access(vnode_t *vp, int mode, int flags, cred_t *cr,
	caller_context_t *ct)
{
	femarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	if ((femsp = fem_lock(vp->v_femhead)) == NULL) {
		func = (int (*)()) (vp->v_op->vop_access);
		arg0 = vp;
		fem_unlock(vp->v_femhead);
		errc = (*func)(arg0, mode, flags, cr, ct);
	} else {
		fem_addref(femsp);
		fem_unlock(vp->v_femhead);
		farg.fa_vnode.vp = vp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vsop_find(&farg, &func, int, &arg0, vop_access,
		    femop_access);
		errc = (*func)(arg0, mode, flags, cr, ct);
		fem_release(femsp);
	}
	return (errc);
}

static int
vhead_lookup(vnode_t *dvp, char *nm, vnode_t **vpp, pathname_t *pnp,
	int flags, vnode_t *rdir, cred_t *cr, caller_context_t *ct,
	int *direntflags, pathname_t *realpnp)
{
	femarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	if ((femsp = fem_lock(dvp->v_femhead)) == NULL) {
		func = (int (*)()) (dvp->v_op->vop_lookup);
		arg0 = dvp;
		fem_unlock(dvp->v_femhead);
		errc = (*func)(arg0, nm, vpp, pnp, flags, rdir, cr, ct,
		    direntflags, realpnp);
	} else {
		fem_addref(femsp);
		fem_unlock(dvp->v_femhead);
		farg.fa_vnode.vp = dvp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vsop_find(&farg, &func, int, &arg0, vop_lookup,
		    femop_lookup);
		errc = (*func)(arg0, nm, vpp, pnp, flags, rdir, cr, ct,
		    direntflags, realpnp);
		fem_release(femsp);
	}
	return (errc);
}

static int
vhead_create(vnode_t *dvp, char *name, vattr_t *vap, vcexcl_t excl,
	int mode, vnode_t **vpp, cred_t *cr, int flag, caller_context_t *ct,
	vsecattr_t *vsecp)
{
	femarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	if ((femsp = fem_lock(dvp->v_femhead)) == NULL) {
		func = (int (*)()) (dvp->v_op->vop_create);
		arg0 = dvp;
		fem_unlock(dvp->v_femhead);
		errc = (*func)(arg0, name, vap, excl, mode, vpp, cr, flag,
		    ct, vsecp);
	} else {
		fem_addref(femsp);
		fem_unlock(dvp->v_femhead);
		farg.fa_vnode.vp = dvp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vsop_find(&farg, &func, int, &arg0, vop_create,
		    femop_create);
		errc = (*func)(arg0, name, vap, excl, mode, vpp, cr, flag,
		    ct, vsecp);
		fem_release(femsp);
	}
	return (errc);
}

static int
vhead_remove(vnode_t *dvp, char *nm, cred_t *cr, caller_context_t *ct,
	int flags)
{
	femarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	if ((femsp = fem_lock(dvp->v_femhead)) == NULL) {
		func = (int (*)()) (dvp->v_op->vop_remove);
		arg0 = dvp;
		fem_unlock(dvp->v_femhead);
		errc = (*func)(arg0, nm, cr, ct, flags);
	} else {
		fem_addref(femsp);
		fem_unlock(dvp->v_femhead);
		farg.fa_vnode.vp = dvp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vsop_find(&farg, &func, int, &arg0, vop_remove,
		    femop_remove);
		errc = (*func)(arg0, nm, cr, ct, flags);
		fem_release(femsp);
	}
	return (errc);
}

static int
vhead_link(vnode_t *tdvp, vnode_t *svp, char *tnm, cred_t *cr,
	caller_context_t *ct, int flags)
{
	femarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	if ((femsp = fem_lock(tdvp->v_femhead)) == NULL) {
		func = (int (*)()) (tdvp->v_op->vop_link);
		arg0 = tdvp;
		fem_unlock(tdvp->v_femhead);
		errc = (*func)(arg0, svp, tnm, cr, ct, flags);
	} else {
		fem_addref(femsp);
		fem_unlock(tdvp->v_femhead);
		farg.fa_vnode.vp = tdvp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vsop_find(&farg, &func, int, &arg0, vop_link, femop_link);
		errc = (*func)(arg0, svp, tnm, cr, ct, flags);
		fem_release(femsp);
	}
	return (errc);
}

static int
vhead_rename(vnode_t *sdvp, char *snm, vnode_t *tdvp, char *tnm,
	cred_t *cr, caller_context_t *ct, int flags)
{
	femarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	if ((femsp = fem_lock(sdvp->v_femhead)) == NULL) {
		func = (int (*)()) (sdvp->v_op->vop_rename);
		arg0 = sdvp;
		fem_unlock(sdvp->v_femhead);
		errc = (*func)(arg0, snm, tdvp, tnm, cr, ct, flags);
	} else {
		fem_addref(femsp);
		fem_unlock(sdvp->v_femhead);
		farg.fa_vnode.vp = sdvp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vsop_find(&farg, &func, int, &arg0, vop_rename,
		    femop_rename);
		errc = (*func)(arg0, snm, tdvp, tnm, cr, ct, flags);
		fem_release(femsp);
	}
	return (errc);
}

static int
vhead_mkdir(vnode_t *dvp, char *dirname, vattr_t *vap, vnode_t **vpp,
	cred_t *cr, caller_context_t *ct, int flags, vsecattr_t *vsecp)
{
	femarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	if ((femsp = fem_lock(dvp->v_femhead)) == NULL) {
		func = (int (*)()) (dvp->v_op->vop_mkdir);
		arg0 = dvp;
		fem_unlock(dvp->v_femhead);
		errc = (*func)(arg0, dirname, vap, vpp, cr, ct, flags, vsecp);
	} else {
		fem_addref(femsp);
		fem_unlock(dvp->v_femhead);
		farg.fa_vnode.vp = dvp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vsop_find(&farg, &func, int, &arg0, vop_mkdir, femop_mkdir);
		errc = (*func)(arg0, dirname, vap, vpp, cr, ct, flags, vsecp);
		fem_release(femsp);
	}
	return (errc);
}

static int
vhead_rmdir(vnode_t *dvp, char *nm, vnode_t *cdir, cred_t *cr,
	caller_context_t *ct, int flags)
{
	femarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	if ((femsp = fem_lock(dvp->v_femhead)) == NULL) {
		func = (int (*)()) (dvp->v_op->vop_rmdir);
		arg0 = dvp;
		fem_unlock(dvp->v_femhead);
		errc = (*func)(arg0, nm, cdir, cr, ct, flags);
	} else {
		fem_addref(femsp);
		fem_unlock(dvp->v_femhead);
		farg.fa_vnode.vp = dvp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vsop_find(&farg, &func, int, &arg0, vop_rmdir, femop_rmdir);
		errc = (*func)(arg0, nm, cdir, cr, ct, flags);
		fem_release(femsp);
	}
	return (errc);
}

static int
vhead_readdir(vnode_t *vp, uio_t *uiop, cred_t *cr, int *eofp,
	caller_context_t *ct, int flags)
{
	femarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	if ((femsp = fem_lock(vp->v_femhead)) == NULL) {
		func = (int (*)()) (vp->v_op->vop_readdir);
		arg0 = vp;
		fem_unlock(vp->v_femhead);
		errc = (*func)(arg0, uiop, cr, eofp, ct, flags);
	} else {
		fem_addref(femsp);
		fem_unlock(vp->v_femhead);
		farg.fa_vnode.vp = vp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vsop_find(&farg, &func, int, &arg0, vop_readdir,
		    femop_readdir);
		errc = (*func)(arg0, uiop, cr, eofp, ct, flags);
		fem_release(femsp);
	}
	return (errc);
}

static int
vhead_symlink(vnode_t *dvp, char *linkname, vattr_t *vap, char *target,
	cred_t *cr, caller_context_t *ct, int flags)
{
	femarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	if ((femsp = fem_lock(dvp->v_femhead)) == NULL) {
		func = (int (*)()) (dvp->v_op->vop_symlink);
		arg0 = dvp;
		fem_unlock(dvp->v_femhead);
		errc = (*func)(arg0, linkname, vap, target, cr, ct, flags);
	} else {
		fem_addref(femsp);
		fem_unlock(dvp->v_femhead);
		farg.fa_vnode.vp = dvp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vsop_find(&farg, &func, int, &arg0, vop_symlink,
		    femop_symlink);
		errc = (*func)(arg0, linkname, vap, target, cr, ct, flags);
		fem_release(femsp);
	}
	return (errc);
}

static int
vhead_readlink(vnode_t *vp, uio_t *uiop, cred_t *cr, caller_context_t *ct)
{
	femarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	if ((femsp = fem_lock(vp->v_femhead)) == NULL) {
		func = (int (*)()) (vp->v_op->vop_readlink);
		arg0 = vp;
		fem_unlock(vp->v_femhead);
		errc = (*func)(arg0, uiop, cr, ct);
	} else {
		fem_addref(femsp);
		fem_unlock(vp->v_femhead);
		farg.fa_vnode.vp = vp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vsop_find(&farg, &func, int, &arg0, vop_readlink,
		    femop_readlink);
		errc = (*func)(arg0, uiop, cr, ct);
		fem_release(femsp);
	}
	return (errc);
}

static int
vhead_fsync(vnode_t *vp, int syncflag, cred_t *cr, caller_context_t *ct)
{
	femarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	if ((femsp = fem_lock(vp->v_femhead)) == NULL) {
		func = (int (*)()) (vp->v_op->vop_fsync);
		arg0 = vp;
		fem_unlock(vp->v_femhead);
		errc = (*func)(arg0, syncflag, cr, ct);
	} else {
		fem_addref(femsp);
		fem_unlock(vp->v_femhead);
		farg.fa_vnode.vp = vp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vsop_find(&farg, &func, int, &arg0, vop_fsync, femop_fsync);
		errc = (*func)(arg0, syncflag, cr, ct);
		fem_release(femsp);
	}
	return (errc);
}

static void
vhead_inactive(vnode_t *vp, cred_t *cr, caller_context_t *ct)
{
	femarg_t	farg;
	struct fem_list	*femsp;
	void		(*func)();
	void		*arg0;

	if ((femsp = fem_lock(vp->v_femhead)) == NULL) {
		func = (void (*)()) (vp->v_op->vop_inactive);
		arg0 = vp;
		fem_unlock(vp->v_femhead);
		(*func)(arg0, cr, ct);
	} else {
		fem_addref(femsp);
		fem_unlock(vp->v_femhead);
		farg.fa_vnode.vp = vp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vsop_find(&farg, &func, void, &arg0, vop_inactive,
		    femop_inactive);
		(*func)(arg0, cr, ct);
		fem_release(femsp);
	}
}

static int
vhead_fid(vnode_t *vp, fid_t *fidp, caller_context_t *ct)
{
	femarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	if ((femsp = fem_lock(vp->v_femhead)) == NULL) {
		func = (int (*)()) (vp->v_op->vop_fid);
		arg0 = vp;
		fem_unlock(vp->v_femhead);
		errc = (*func)(arg0, fidp, ct);
	} else {
		fem_addref(femsp);
		fem_unlock(vp->v_femhead);
		farg.fa_vnode.vp = vp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vsop_find(&farg, &func, int, &arg0, vop_fid, femop_fid);
		errc = (*func)(arg0, fidp, ct);
		fem_release(femsp);
	}
	return (errc);
}

static int
vhead_rwlock(vnode_t *vp, int write_lock, caller_context_t *ct)
{
	femarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	if ((femsp = fem_lock(vp->v_femhead)) == NULL) {
		func = (int (*)()) (vp->v_op->vop_rwlock);
		arg0 = vp;
		fem_unlock(vp->v_femhead);
		errc = (*func)(arg0, write_lock, ct);
	} else {
		fem_addref(femsp);
		fem_unlock(vp->v_femhead);
		farg.fa_vnode.vp = vp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vsop_find(&farg, &func, int, &arg0, vop_rwlock,
		    femop_rwlock);
		errc = (*func)(arg0, write_lock, ct);
		fem_release(femsp);
	}
	return (errc);
}

static void
vhead_rwunlock(vnode_t *vp, int write_lock, caller_context_t *ct)
{
	femarg_t	farg;
	struct fem_list	*femsp;
	void		(*func)();
	void		*arg0;

	if ((femsp = fem_lock(vp->v_femhead)) == NULL) {
		func = (void (*)()) (vp->v_op->vop_rwunlock);
		arg0 = vp;
		fem_unlock(vp->v_femhead);
		(*func)(arg0, write_lock, ct);
	} else {
		fem_addref(femsp);
		fem_unlock(vp->v_femhead);
		farg.fa_vnode.vp = vp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vsop_find(&farg, &func, void, &arg0, vop_rwunlock,
		    femop_rwunlock);
		(*func)(arg0, write_lock, ct);
		fem_release(femsp);
	}
}

static int
vhead_seek(vnode_t *vp, offset_t ooff, offset_t *noffp, caller_context_t *ct)
{
	femarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	if ((femsp = fem_lock(vp->v_femhead)) == NULL) {
		func = (int (*)()) (vp->v_op->vop_seek);
		arg0 = vp;
		fem_unlock(vp->v_femhead);
		errc = (*func)(arg0, ooff, noffp, ct);
	} else {
		fem_addref(femsp);
		fem_unlock(vp->v_femhead);
		farg.fa_vnode.vp = vp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vsop_find(&farg, &func, int, &arg0, vop_seek, femop_seek);
		errc = (*func)(arg0, ooff, noffp, ct);
		fem_release(femsp);
	}
	return (errc);
}

static int
vhead_cmp(vnode_t *vp1, vnode_t *vp2, caller_context_t *ct)
{
	femarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	if ((femsp = fem_lock(vp1->v_femhead)) == NULL) {
		func = (int (*)()) (vp1->v_op->vop_cmp);
		arg0 = vp1;
		fem_unlock(vp1->v_femhead);
		errc = (*func)(arg0, vp2, ct);
	} else {
		fem_addref(femsp);
		fem_unlock(vp1->v_femhead);
		farg.fa_vnode.vp = vp1;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vsop_find(&farg, &func, int, &arg0, vop_cmp, femop_cmp);
		errc = (*func)(arg0, vp2, ct);
		fem_release(femsp);
	}
	return (errc);
}

static int
vhead_frlock(vnode_t *vp, int cmd, struct flock64 *bfp, int flag,
	offset_t offset, struct flk_callback *flk_cbp, cred_t *cr,
	caller_context_t *ct)
{
	femarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	if ((femsp = fem_lock(vp->v_femhead)) == NULL) {
		func = (int (*)()) (vp->v_op->vop_frlock);
		arg0 = vp;
		fem_unlock(vp->v_femhead);
		errc = (*func)(arg0, cmd, bfp, flag, offset, flk_cbp, cr, ct);
	} else {
		fem_addref(femsp);
		fem_unlock(vp->v_femhead);
		farg.fa_vnode.vp = vp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vsop_find(&farg, &func, int, &arg0, vop_frlock,
		    femop_frlock);
		errc = (*func)(arg0, cmd, bfp, flag, offset, flk_cbp, cr, ct);
		fem_release(femsp);
	}
	return (errc);
}

static int
vhead_space(vnode_t *vp, int cmd, struct flock64 *bfp, int flag,
	offset_t offset, cred_t *cr, caller_context_t *ct)
{
	femarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	if ((femsp = fem_lock(vp->v_femhead)) == NULL) {
		func = (int (*)()) (vp->v_op->vop_space);
		arg0 = vp;
		fem_unlock(vp->v_femhead);
		errc = (*func)(arg0, cmd, bfp, flag, offset, cr, ct);
	} else {
		fem_addref(femsp);
		fem_unlock(vp->v_femhead);
		farg.fa_vnode.vp = vp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vsop_find(&farg, &func, int, &arg0, vop_space, femop_space);
		errc = (*func)(arg0, cmd, bfp, flag, offset, cr, ct);
		fem_release(femsp);
	}
	return (errc);
}

static int
vhead_realvp(vnode_t *vp, vnode_t **vpp, caller_context_t *ct)
{
	femarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	if ((femsp = fem_lock(vp->v_femhead)) == NULL) {
		func = (int (*)()) (vp->v_op->vop_realvp);
		arg0 = vp;
		fem_unlock(vp->v_femhead);
		errc = (*func)(arg0, vpp, ct);
	} else {
		fem_addref(femsp);
		fem_unlock(vp->v_femhead);
		farg.fa_vnode.vp = vp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vsop_find(&farg, &func, int, &arg0, vop_realvp,
		    femop_realvp);
		errc = (*func)(arg0, vpp, ct);
		fem_release(femsp);
	}
	return (errc);
}

static int
vhead_getpage(vnode_t *vp, offset_t off, size_t len, uint_t *protp,
	struct page **plarr, size_t plsz, struct seg *seg, caddr_t addr,
	enum seg_rw rw, cred_t *cr, caller_context_t *ct)
{
	femarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	if ((femsp = fem_lock(vp->v_femhead)) == NULL) {
		func = (int (*)()) (vp->v_op->vop_getpage);
		arg0 = vp;
		fem_unlock(vp->v_femhead);
		errc = (*func)(arg0, off, len, protp, plarr, plsz, seg,
		    addr, rw, cr, ct);
	} else {
		fem_addref(femsp);
		fem_unlock(vp->v_femhead);
		farg.fa_vnode.vp = vp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vsop_find(&farg, &func, int, &arg0, vop_getpage,
		    femop_getpage);
		errc = (*func)(arg0, off, len, protp, plarr, plsz, seg,
		    addr, rw, cr, ct);
		fem_release(femsp);
	}
	return (errc);
}

static int
vhead_putpage(vnode_t *vp, offset_t off, size_t len, int flags, cred_t *cr,
	caller_context_t *ct)
{
	femarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	if ((femsp = fem_lock(vp->v_femhead)) == NULL) {
		func = (int (*)()) (vp->v_op->vop_putpage);
		arg0 = vp;
		fem_unlock(vp->v_femhead);
		errc = (*func)(arg0, off, len, flags, cr, ct);
	} else {
		fem_addref(femsp);
		fem_unlock(vp->v_femhead);
		farg.fa_vnode.vp = vp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vsop_find(&farg, &func, int, &arg0, vop_putpage,
		    femop_putpage);
		errc = (*func)(arg0, off, len, flags, cr, ct);
		fem_release(femsp);
	}
	return (errc);
}

static int
vhead_map(vnode_t *vp, offset_t off, struct as *as, caddr_t *addrp,
	size_t len, uchar_t prot, uchar_t maxprot, uint_t flags,
	cred_t *cr, caller_context_t *ct)
{
	femarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	if ((femsp = fem_lock(vp->v_femhead)) == NULL) {
		func = (int (*)()) (vp->v_op->vop_map);
		arg0 = vp;
		fem_unlock(vp->v_femhead);
		errc = (*func)(arg0, off, as, addrp, len, prot, maxprot,
		    flags, cr, ct);
	} else {
		fem_addref(femsp);
		fem_unlock(vp->v_femhead);
		farg.fa_vnode.vp = vp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vsop_find(&farg, &func, int, &arg0, vop_map, femop_map);
		errc = (*func)(arg0, off, as, addrp, len, prot, maxprot,
		    flags, cr, ct);
		fem_release(femsp);
	}
	return (errc);
}

static int
vhead_addmap(vnode_t *vp, offset_t off, struct as *as, caddr_t addr,
	size_t len, uchar_t prot, uchar_t maxprot, uint_t flags,
	cred_t *cr, caller_context_t *ct)
{
	femarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	if ((femsp = fem_lock(vp->v_femhead)) == NULL) {
		func = (int (*)()) (vp->v_op->vop_addmap);
		arg0 = vp;
		fem_unlock(vp->v_femhead);
		errc = (*func)(arg0, off, as, addr, len, prot, maxprot,
		    flags, cr, ct);
	} else {
		fem_addref(femsp);
		fem_unlock(vp->v_femhead);
		farg.fa_vnode.vp = vp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vsop_find(&farg, &func, int, &arg0, vop_addmap,
		    femop_addmap);
		errc = (*func)(arg0, off, as, addr, len, prot, maxprot,
		    flags, cr, ct);
		fem_release(femsp);
	}
	return (errc);
}

static int
vhead_delmap(vnode_t *vp, offset_t off, struct as *as, caddr_t addr,
	size_t len, uint_t prot, uint_t maxprot, uint_t flags, cred_t *cr,
	caller_context_t *ct)
{
	femarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	if ((femsp = fem_lock(vp->v_femhead)) == NULL) {
		func = (int (*)()) (vp->v_op->vop_delmap);
		arg0 = vp;
		fem_unlock(vp->v_femhead);
		errc = (*func)(arg0, off, as, addr, len, prot, maxprot,
		    flags, cr, ct);
	} else {
		fem_addref(femsp);
		fem_unlock(vp->v_femhead);
		farg.fa_vnode.vp = vp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vsop_find(&farg, &func, int, &arg0, vop_delmap,
		    femop_delmap);
		errc = (*func)(arg0, off, as, addr, len, prot, maxprot,
		    flags, cr, ct);
		fem_release(femsp);
	}
	return (errc);
}

static int
vhead_poll(vnode_t *vp, short events, int anyyet, short *reventsp,
	struct pollhead **phpp, caller_context_t *ct)
{
	femarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	if ((femsp = fem_lock(vp->v_femhead)) == NULL) {
		func = (int (*)()) (vp->v_op->vop_poll);
		arg0 = vp;
		fem_unlock(vp->v_femhead);
		errc = (*func)(arg0, events, anyyet, reventsp, phpp, ct);
	} else {
		fem_addref(femsp);
		fem_unlock(vp->v_femhead);
		farg.fa_vnode.vp = vp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vsop_find(&farg, &func, int, &arg0, vop_poll, femop_poll);
		errc = (*func)(arg0, events, anyyet, reventsp, phpp, ct);
		fem_release(femsp);
	}
	return (errc);
}

static int
vhead_dump(vnode_t *vp, caddr_t addr, offset_t lbdn, offset_t dblks,
    caller_context_t *ct)
{
	femarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	if ((femsp = fem_lock(vp->v_femhead)) == NULL) {
		func = (int (*)()) (vp->v_op->vop_dump);
		arg0 = vp;
		fem_unlock(vp->v_femhead);
		errc = (*func)(arg0, addr, lbdn, dblks, ct);
	} else {
		fem_addref(femsp);
		fem_unlock(vp->v_femhead);
		farg.fa_vnode.vp = vp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vsop_find(&farg, &func, int, &arg0, vop_dump, femop_dump);
		errc = (*func)(arg0, addr, lbdn, dblks, ct);
		fem_release(femsp);
	}
	return (errc);
}

static int
vhead_pathconf(vnode_t *vp, int cmd, ulong_t *valp, cred_t *cr,
	caller_context_t *ct)
{
	femarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	if ((femsp = fem_lock(vp->v_femhead)) == NULL) {
		func = (int (*)()) (vp->v_op->vop_pathconf);
		arg0 = vp;
		fem_unlock(vp->v_femhead);
		errc = (*func)(arg0, cmd, valp, cr, ct);
	} else {
		fem_addref(femsp);
		fem_unlock(vp->v_femhead);
		farg.fa_vnode.vp = vp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vsop_find(&farg, &func, int, &arg0, vop_pathconf,
		    femop_pathconf);
		errc = (*func)(arg0, cmd, valp, cr, ct);
		fem_release(femsp);
	}
	return (errc);
}

static int
vhead_pageio(vnode_t *vp, struct page *pp, u_offset_t io_off,
	size_t io_len, int flags, cred_t *cr, caller_context_t *ct)
{
	femarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	if ((femsp = fem_lock(vp->v_femhead)) == NULL) {
		func = (int (*)()) (vp->v_op->vop_pageio);
		arg0 = vp;
		fem_unlock(vp->v_femhead);
		errc = (*func)(arg0, pp, io_off, io_len, flags, cr, ct);
	} else {
		fem_addref(femsp);
		fem_unlock(vp->v_femhead);
		farg.fa_vnode.vp = vp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vsop_find(&farg, &func, int, &arg0, vop_pageio,
		    femop_pageio);
		errc = (*func)(arg0, pp, io_off, io_len, flags, cr, ct);
		fem_release(femsp);
	}
	return (errc);
}

static int
vhead_dumpctl(vnode_t *vp, int action, offset_t *blkp, caller_context_t *ct)
{
	femarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	if ((femsp = fem_lock(vp->v_femhead)) == NULL) {
		func = (int (*)()) (vp->v_op->vop_dumpctl);
		arg0 = vp;
		fem_unlock(vp->v_femhead);
		errc = (*func)(arg0, action, blkp, ct);
	} else {
		fem_addref(femsp);
		fem_unlock(vp->v_femhead);
		farg.fa_vnode.vp = vp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vsop_find(&farg, &func, int, &arg0, vop_dumpctl,
		    femop_dumpctl);
		errc = (*func)(arg0, action, blkp, ct);
		fem_release(femsp);
	}
	return (errc);
}

static void
vhead_dispose(vnode_t *vp, struct page *pp, int flag, int dn, cred_t *cr,
	caller_context_t *ct)
{
	femarg_t	farg;
	struct fem_list	*femsp;
	void		(*func)();
	void		*arg0;

	if ((femsp = fem_lock(vp->v_femhead)) == NULL) {
		func = (void (*)()) (vp->v_op->vop_dispose);
		arg0 = vp;
		fem_unlock(vp->v_femhead);
		(*func)(arg0, pp, flag, dn, cr, ct);
	} else {
		fem_addref(femsp);
		fem_unlock(vp->v_femhead);
		farg.fa_vnode.vp = vp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vsop_find(&farg, &func, void, &arg0, vop_dispose,
		    femop_dispose);
		(*func)(arg0, pp, flag, dn, cr, ct);
		fem_release(femsp);
	}
}

static int
vhead_setsecattr(vnode_t *vp, vsecattr_t *vsap, int flag, cred_t *cr,
	caller_context_t *ct)
{
	femarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	if ((femsp = fem_lock(vp->v_femhead)) == NULL) {
		func = (int (*)()) (vp->v_op->vop_setsecattr);
		arg0 = vp;
		fem_unlock(vp->v_femhead);
		errc = (*func)(arg0, vsap, flag, cr, ct);
	} else {
		fem_addref(femsp);
		fem_unlock(vp->v_femhead);
		farg.fa_vnode.vp = vp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vsop_find(&farg, &func, int, &arg0, vop_setsecattr,
		    femop_setsecattr);
		errc = (*func)(arg0, vsap, flag, cr, ct);
		fem_release(femsp);
	}
	return (errc);
}

static int
vhead_getsecattr(vnode_t *vp, vsecattr_t *vsap, int flag, cred_t *cr,
	caller_context_t *ct)
{
	femarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	if ((femsp = fem_lock(vp->v_femhead)) == NULL) {
		func = (int (*)()) (vp->v_op->vop_getsecattr);
		arg0 = vp;
		fem_unlock(vp->v_femhead);
		errc = (*func)(arg0, vsap, flag, cr, ct);
	} else {
		fem_addref(femsp);
		fem_unlock(vp->v_femhead);
		farg.fa_vnode.vp = vp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vsop_find(&farg, &func, int, &arg0, vop_getsecattr,
		    femop_getsecattr);
		errc = (*func)(arg0, vsap, flag, cr, ct);
		fem_release(femsp);
	}
	return (errc);
}

static int
vhead_shrlock(vnode_t *vp, int cmd, struct shrlock *shr, int flag,
	cred_t *cr, caller_context_t *ct)
{
	femarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	if ((femsp = fem_lock(vp->v_femhead)) == NULL) {
		func = (int (*)()) (vp->v_op->vop_shrlock);
		arg0 = vp;
		fem_unlock(vp->v_femhead);
		errc = (*func)(arg0, cmd, shr, flag, cr, ct);
	} else {
		fem_addref(femsp);
		fem_unlock(vp->v_femhead);
		farg.fa_vnode.vp = vp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vsop_find(&farg, &func, int, &arg0, vop_shrlock,
		    femop_shrlock);
		errc = (*func)(arg0, cmd, shr, flag, cr, ct);
		fem_release(femsp);
	}
	return (errc);
}

static int
vhead_vnevent(vnode_t *vp, vnevent_t vnevent, vnode_t *dvp, char *cname,
    caller_context_t *ct)
{
	femarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	if ((femsp = fem_lock(vp->v_femhead)) == NULL) {
		func = (int (*)()) (vp->v_op->vop_vnevent);
		arg0 = vp;
		fem_unlock(vp->v_femhead);
		errc = (*func)(arg0, vnevent, dvp, cname, ct);
	} else {
		fem_addref(femsp);
		fem_unlock(vp->v_femhead);
		farg.fa_vnode.vp = vp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vsop_find(&farg, &func, int, &arg0, vop_vnevent,
		    femop_vnevent);
		errc = (*func)(arg0, vnevent, dvp, cname, ct);
		fem_release(femsp);
	}
	return (errc);
}

static int
vhead_reqzcbuf(vnode_t *vp, enum uio_rw ioflag, xuio_t *xuiop, cred_t *cr,
    caller_context_t *ct)
{
	femarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	if ((femsp = fem_lock(vp->v_femhead)) == NULL) {
		func = (int (*)()) (vp->v_op->vop_reqzcbuf);
		arg0 = vp;
		fem_unlock(vp->v_femhead);
		errc = (*func)(arg0, ioflag, xuiop, cr, ct);
	} else {
		fem_addref(femsp);
		fem_unlock(vp->v_femhead);
		farg.fa_vnode.vp = vp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vsop_find(&farg, &func, int, &arg0, vop_reqzcbuf,
		    femop_reqzcbuf);
		errc = (*func)(arg0, ioflag, xuiop, cr, ct);
		fem_release(femsp);
	}
	return (errc);
}

static int
vhead_retzcbuf(vnode_t *vp, xuio_t *xuiop, cred_t *cr, caller_context_t *ct)
{
	femarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	if ((femsp = fem_lock(vp->v_femhead)) == NULL) {
		func = (int (*)()) (vp->v_op->vop_retzcbuf);
		arg0 = vp;
		fem_unlock(vp->v_femhead);
		errc = (*func)(arg0, xuiop, cr, ct);
	} else {
		fem_addref(femsp);
		fem_unlock(vp->v_femhead);
		farg.fa_vnode.vp = vp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vsop_find(&farg, &func, int, &arg0, vop_retzcbuf,
		    femop_retzcbuf);
		errc = (*func)(arg0, xuiop, cr, ct);
		fem_release(femsp);
	}
	return (errc);
}

static int
fshead_mount(vfs_t *vfsp, vnode_t *mvp, struct mounta *uap, cred_t *cr)
{
	fsemarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	ASSERT(vfsp->vfs_implp);

	if ((femsp = fem_lock(vfsp->vfs_femhead)) == NULL) {
		func = (int (*)()) vfsp->vfs_op->vfs_mount;
		fem_unlock(vfsp->vfs_femhead);
		errc = (*func)(vfsp, mvp, uap, cr);
	} else {
		fem_addref(femsp);
		fem_unlock(vfsp->vfs_femhead);
		farg.fa_vnode.vfsp = vfsp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vfsop_find(&farg, &func, int, &arg0, vfs_mount,
		    fsemop_mount);
		errc = (*func)(arg0, mvp, uap, cr);
		fem_release(femsp);
	}
	return (errc);
}

static int
fshead_unmount(vfs_t *vfsp, int flag, cred_t *cr)
{
	fsemarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	ASSERT(vfsp->vfs_implp);

	if ((femsp = fem_lock(vfsp->vfs_femhead)) == NULL) {
		func = (int (*)()) vfsp->vfs_op->vfs_unmount;
		fem_unlock(vfsp->vfs_femhead);
		errc = (*func)(vfsp, flag, cr);
	} else {
		fem_addref(femsp);
		fem_unlock(vfsp->vfs_femhead);
		farg.fa_vnode.vfsp = vfsp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vfsop_find(&farg, &func, int, &arg0, vfs_unmount,
		    fsemop_unmount);
		errc = (*func)(arg0, flag, cr);
		fem_release(femsp);
	}
	return (errc);
}

static int
fshead_root(vfs_t *vfsp, vnode_t **vpp)
{
	fsemarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	ASSERT(vfsp->vfs_implp);

	if ((femsp = fem_lock(vfsp->vfs_femhead)) == NULL) {
		func = (int (*)()) vfsp->vfs_op->vfs_root;
		fem_unlock(vfsp->vfs_femhead);
		errc = (*func)(vfsp, vpp);
	} else {
		fem_addref(femsp);
		fem_unlock(vfsp->vfs_femhead);
		farg.fa_vnode.vfsp = vfsp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vfsop_find(&farg, &func, int, &arg0, vfs_root, fsemop_root);
		errc = (*func)(arg0, vpp);
		fem_release(femsp);
	}
	return (errc);
}

static int
fshead_statvfs(vfs_t *vfsp, statvfs64_t *sp)
{
	fsemarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	ASSERT(vfsp->vfs_implp);

	if ((femsp = fem_lock(vfsp->vfs_femhead)) == NULL) {
		func = (int (*)()) vfsp->vfs_op->vfs_statvfs;
		fem_unlock(vfsp->vfs_femhead);
		errc = (*func)(vfsp, sp);
	} else {
		fem_addref(femsp);
		fem_unlock(vfsp->vfs_femhead);
		farg.fa_vnode.vfsp = vfsp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vfsop_find(&farg, &func, int, &arg0, vfs_statvfs,
		    fsemop_statvfs);
		errc = (*func)(arg0, sp);
		fem_release(femsp);
	}
	return (errc);
}

static int
fshead_sync(vfs_t *vfsp, short flag, cred_t *cr)
{
	fsemarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	ASSERT(vfsp->vfs_implp);

	if ((femsp = fem_lock(vfsp->vfs_femhead)) == NULL) {
		func = (int (*)()) vfsp->vfs_op->vfs_sync;
		fem_unlock(vfsp->vfs_femhead);
		errc = (*func)(vfsp, flag, cr);
	} else {
		fem_addref(femsp);
		fem_unlock(vfsp->vfs_femhead);
		farg.fa_vnode.vfsp = vfsp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vfsop_find(&farg, &func, int, &arg0, vfs_sync, fsemop_sync);
		errc = (*func)(arg0, flag, cr);
		fem_release(femsp);
	}
	return (errc);
}

static int
fshead_vget(vfs_t *vfsp, vnode_t **vpp, fid_t *fidp)
{
	fsemarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	ASSERT(vfsp->vfs_implp);

	if ((femsp = fem_lock(vfsp->vfs_femhead)) == NULL) {
		func = (int (*)()) vfsp->vfs_op->vfs_vget;
		fem_unlock(vfsp->vfs_femhead);
		errc = (*func)(vfsp, vpp, fidp);
	} else {
		fem_addref(femsp);
		fem_unlock(vfsp->vfs_femhead);
		farg.fa_vnode.vfsp = vfsp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vfsop_find(&farg, &func, int, &arg0, vfs_vget, fsemop_vget);
		errc = (*func)(arg0, vpp, fidp);
		fem_release(femsp);
	}
	return (errc);
}

static int
fshead_mountroot(vfs_t *vfsp, enum whymountroot reason)
{
	fsemarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	ASSERT(vfsp->vfs_implp);

	if ((femsp = fem_lock(vfsp->vfs_femhead)) == NULL) {
		func = (int (*)()) vfsp->vfs_op->vfs_mountroot;
		fem_unlock(vfsp->vfs_femhead);
		errc = (*func)(vfsp, reason);
	} else {
		fem_addref(femsp);
		fem_unlock(vfsp->vfs_femhead);
		farg.fa_vnode.vfsp = vfsp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vfsop_find(&farg, &func, int, &arg0, vfs_mountroot,
		    fsemop_mountroot);
		errc = (*func)(arg0, reason);
		fem_release(femsp);
	}
	return (errc);
}

static void
fshead_freevfs(vfs_t *vfsp)
{
	fsemarg_t	farg;
	struct fem_list	*femsp;
	void		(*func)();
	void		*arg0;

	ASSERT(vfsp->vfs_implp);

	if ((femsp = fem_lock(vfsp->vfs_femhead)) == NULL) {
		func = (void (*)()) vfsp->vfs_op->vfs_freevfs;
		fem_unlock(vfsp->vfs_femhead);
		(*func)(vfsp);
	} else {
		fem_addref(femsp);
		fem_unlock(vfsp->vfs_femhead);
		farg.fa_vnode.vfsp = vfsp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vfsop_find(&farg, &func, void, &arg0, vfs_freevfs,
		    fsemop_freevfs);
		(*func)(arg0);
		fem_release(femsp);
	}
}

static int
fshead_vnstate(vfs_t *vfsp, vnode_t *vp, vntrans_t nstate)
{
	fsemarg_t	farg;
	struct fem_list	*femsp;
	int		(*func)();
	void		*arg0;
	int		errc;

	ASSERT(vfsp->vfs_implp);

	if ((femsp = fem_lock(vfsp->vfs_femhead)) == NULL) {
		func = (int (*)()) vfsp->vfs_op->vfs_vnstate;
		fem_unlock(vfsp->vfs_femhead);
		errc = (*func)(vfsp, vp, nstate);
	} else {
		fem_addref(femsp);
		fem_unlock(vfsp->vfs_femhead);
		farg.fa_vnode.vfsp = vfsp;
		farg.fa_fnode = femsp->feml_nodes + femsp->feml_tos;
		vfsop_find(&farg, &func, int, &arg0, vfs_vnstate,
		    fsemop_vnstate);
		errc = (*func)(arg0, vp, nstate);
		fem_release(femsp);
	}
	return (errc);
}


/*
 * specification table for the vhead vnode operations.
 * It is an error for any operations to be missing.
 */

static struct fs_operation_def fhead_vn_spec[] = {
	{ VOPNAME_OPEN, (femop_t *)vhead_open },
	{ VOPNAME_CLOSE, (femop_t *)vhead_close },
	{ VOPNAME_READ, (femop_t *)vhead_read },
	{ VOPNAME_WRITE, (femop_t *)vhead_write },
	{ VOPNAME_IOCTL, (femop_t *)vhead_ioctl },
	{ VOPNAME_SETFL, (femop_t *)vhead_setfl },
	{ VOPNAME_GETATTR, (femop_t *)vhead_getattr },
	{ VOPNAME_SETATTR, (femop_t *)vhead_setattr },
	{ VOPNAME_ACCESS, (femop_t *)vhead_access },
	{ VOPNAME_LOOKUP, (femop_t *)vhead_lookup },
	{ VOPNAME_CREATE, (femop_t *)vhead_create },
	{ VOPNAME_REMOVE, (femop_t *)vhead_remove },
	{ VOPNAME_LINK, (femop_t *)vhead_link },
	{ VOPNAME_RENAME, (femop_t *)vhead_rename },
	{ VOPNAME_MKDIR, (femop_t *)vhead_mkdir },
	{ VOPNAME_RMDIR, (femop_t *)vhead_rmdir },
	{ VOPNAME_READDIR, (femop_t *)vhead_readdir },
	{ VOPNAME_SYMLINK, (femop_t *)vhead_symlink },
	{ VOPNAME_READLINK, (femop_t *)vhead_readlink },
	{ VOPNAME_FSYNC, (femop_t *)vhead_fsync },
	{ VOPNAME_INACTIVE, (femop_t *)vhead_inactive },
	{ VOPNAME_FID, (femop_t *)vhead_fid },
	{ VOPNAME_RWLOCK, (femop_t *)vhead_rwlock },
	{ VOPNAME_RWUNLOCK, (femop_t *)vhead_rwunlock },
	{ VOPNAME_SEEK, (femop_t *)vhead_seek },
	{ VOPNAME_CMP, (femop_t *)vhead_cmp },
	{ VOPNAME_FRLOCK, (femop_t *)vhead_frlock },
	{ VOPNAME_SPACE, (femop_t *)vhead_space },
	{ VOPNAME_REALVP, (femop_t *)vhead_realvp },
	{ VOPNAME_GETPAGE, (femop_t *)vhead_getpage },
	{ VOPNAME_PUTPAGE, (femop_t *)vhead_putpage },
	{ VOPNAME_MAP, (femop_t *)vhead_map },
	{ VOPNAME_ADDMAP, (femop_t *)vhead_addmap },
	{ VOPNAME_DELMAP, (femop_t *)vhead_delmap },
	{ VOPNAME_POLL, (femop_t *)vhead_poll },
	{ VOPNAME_DUMP, (femop_t *)vhead_dump },
	{ VOPNAME_PATHCONF, (femop_t *)vhead_pathconf },
	{ VOPNAME_PAGEIO, (femop_t *)vhead_pageio },
	{ VOPNAME_DUMPCTL, (femop_t *)vhead_dumpctl },
	{ VOPNAME_DISPOSE, (femop_t *)vhead_dispose },
	{ VOPNAME_SETSECATTR, (femop_t *)vhead_setsecattr },
	{ VOPNAME_GETSECATTR, (femop_t *)vhead_getsecattr },
	{ VOPNAME_SHRLOCK, (femop_t *)vhead_shrlock },
	{ VOPNAME_VNEVENT, (femop_t *)vhead_vnevent },
	{ VOPNAME_REQZCBUF, (femop_t *)vhead_reqzcbuf },
	{ VOPNAME_RETZCBUF, (femop_t *)vhead_retzcbuf },
	{	NULL,	NULL	}
};

/*
 * specification table for the vfshead vnode operations.
 * It is an error for any operations to be missing.
 */

static struct fs_operation_def fshead_vfs_spec[]  = {
	{ VFSNAME_MOUNT, (femop_t *)fshead_mount },
	{ VFSNAME_UNMOUNT, (femop_t *)fshead_unmount },
	{ VFSNAME_ROOT, (femop_t *)fshead_root },
	{ VFSNAME_STATVFS, (femop_t *)fshead_statvfs },
	{ VFSNAME_SYNC, (femop_t *)fshead_sync },
	{ VFSNAME_VGET, (femop_t *)fshead_vget },
	{ VFSNAME_MOUNTROOT, (femop_t *)fshead_mountroot },
	{ VFSNAME_FREEVFS, (femop_t *)fshead_freevfs },
	{ VFSNAME_VNSTATE, (femop_t *)fshead_vnstate },
	{	NULL,	NULL	}
};

/*
 * This set of routines transfer control to the next stacked monitor.
 *
 * Each routine is identical except for naming, types and arguments.
 *
 * The basic steps are:
 * 1.  Decrease the stack pointer by one.
 * 2.  If the current item is a base operation (vnode, vfs), goto 5.
 * 3.  If the current item does not have a corresponding operation, goto 1
 * 4.  Return by invoking the current item with the argument handle.
 * 5.  Return by invoking the base operation with the base object.
 *
 * for each classification, there needs to be at least one "next" operation
 * for each "head"operation.
 *
 */

int
vnext_open(femarg_t *vf, int mode, cred_t *cr, caller_context_t *ct)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vsop_find(vf, &func, int, &arg0, vop_open, femop_open);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, mode, cr, ct));
}

int
vnext_close(femarg_t *vf, int flag, int count, offset_t offset, cred_t *cr,
	caller_context_t *ct)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vsop_find(vf, &func, int, &arg0, vop_close, femop_close);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, flag, count, offset, cr, ct));
}

int
vnext_read(femarg_t *vf, uio_t *uiop, int ioflag, cred_t *cr,
	caller_context_t *ct)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vsop_find(vf, &func, int, &arg0, vop_read, femop_read);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, uiop, ioflag, cr, ct));
}

int
vnext_write(femarg_t *vf, uio_t *uiop, int ioflag, cred_t *cr,
	caller_context_t *ct)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vsop_find(vf, &func, int, &arg0, vop_write, femop_write);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, uiop, ioflag, cr, ct));
}

int
vnext_ioctl(femarg_t *vf, int cmd, intptr_t arg, int flag, cred_t *cr,
	int *rvalp, caller_context_t *ct)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vsop_find(vf, &func, int, &arg0, vop_ioctl, femop_ioctl);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, cmd, arg, flag, cr, rvalp, ct));
}

int
vnext_setfl(femarg_t *vf, int oflags, int nflags, cred_t *cr,
	caller_context_t *ct)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vsop_find(vf, &func, int, &arg0, vop_setfl, femop_setfl);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, oflags, nflags, cr, ct));
}

int
vnext_getattr(femarg_t *vf, vattr_t *vap, int flags, cred_t *cr,
	caller_context_t *ct)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vsop_find(vf, &func, int, &arg0, vop_getattr, femop_getattr);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, vap, flags, cr, ct));
}

int
vnext_setattr(femarg_t *vf, vattr_t *vap, int flags, cred_t *cr,
	caller_context_t *ct)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vsop_find(vf, &func, int, &arg0, vop_setattr, femop_setattr);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, vap, flags, cr, ct));
}

int
vnext_access(femarg_t *vf, int mode, int flags, cred_t *cr,
	caller_context_t *ct)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vsop_find(vf, &func, int, &arg0, vop_access, femop_access);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, mode, flags, cr, ct));
}

int
vnext_lookup(femarg_t *vf, char *nm, vnode_t **vpp, pathname_t *pnp,
	int flags, vnode_t *rdir, cred_t *cr, caller_context_t *ct,
	int *direntflags, pathname_t *realpnp)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vsop_find(vf, &func, int, &arg0, vop_lookup, femop_lookup);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, nm, vpp, pnp, flags, rdir, cr, ct,
	    direntflags, realpnp));
}

int
vnext_create(femarg_t *vf, char *name, vattr_t *vap, vcexcl_t excl,
	int mode, vnode_t **vpp, cred_t *cr, int flag, caller_context_t *ct,
	vsecattr_t *vsecp)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vsop_find(vf, &func, int, &arg0, vop_create, femop_create);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, name, vap, excl, mode, vpp, cr, flag, ct, vsecp));
}

int
vnext_remove(femarg_t *vf, char *nm, cred_t *cr, caller_context_t *ct,
	int flags)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vsop_find(vf, &func, int, &arg0, vop_remove, femop_remove);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, nm, cr, ct, flags));
}

int
vnext_link(femarg_t *vf, vnode_t *svp, char *tnm, cred_t *cr,
	caller_context_t *ct, int flags)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vsop_find(vf, &func, int, &arg0, vop_link, femop_link);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, svp, tnm, cr, ct, flags));
}

int
vnext_rename(femarg_t *vf, char *snm, vnode_t *tdvp, char *tnm, cred_t *cr,
	caller_context_t *ct, int flags)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vsop_find(vf, &func, int, &arg0, vop_rename, femop_rename);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, snm, tdvp, tnm, cr, ct, flags));
}

int
vnext_mkdir(femarg_t *vf, char *dirname, vattr_t *vap, vnode_t **vpp,
	cred_t *cr, caller_context_t *ct, int flags, vsecattr_t *vsecp)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vsop_find(vf, &func, int, &arg0, vop_mkdir, femop_mkdir);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, dirname, vap, vpp, cr, ct, flags, vsecp));
}

int
vnext_rmdir(femarg_t *vf, char *nm, vnode_t *cdir, cred_t *cr,
	caller_context_t *ct, int flags)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vsop_find(vf, &func, int, &arg0, vop_rmdir, femop_rmdir);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, nm, cdir, cr, ct, flags));
}

int
vnext_readdir(femarg_t *vf, uio_t *uiop, cred_t *cr, int *eofp,
	caller_context_t *ct, int flags)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vsop_find(vf, &func, int, &arg0, vop_readdir, femop_readdir);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, uiop, cr, eofp, ct, flags));
}

int
vnext_symlink(femarg_t *vf, char *linkname, vattr_t *vap, char *target,
	cred_t *cr, caller_context_t *ct, int flags)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vsop_find(vf, &func, int, &arg0, vop_symlink, femop_symlink);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, linkname, vap, target, cr, ct, flags));
}

int
vnext_readlink(femarg_t *vf, uio_t *uiop, cred_t *cr, caller_context_t *ct)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vsop_find(vf, &func, int, &arg0, vop_readlink, femop_readlink);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, uiop, cr, ct));
}

int
vnext_fsync(femarg_t *vf, int syncflag, cred_t *cr, caller_context_t *ct)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vsop_find(vf, &func, int, &arg0, vop_fsync, femop_fsync);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, syncflag, cr, ct));
}

void
vnext_inactive(femarg_t *vf, cred_t *cr, caller_context_t *ct)
{
	void (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vsop_find(vf, &func, void, &arg0, vop_inactive, femop_inactive);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	(*func)(arg0, cr, ct);
}

int
vnext_fid(femarg_t *vf, fid_t *fidp, caller_context_t *ct)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vsop_find(vf, &func, int, &arg0, vop_fid, femop_fid);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, fidp, ct));
}

int
vnext_rwlock(femarg_t *vf, int write_lock, caller_context_t *ct)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vsop_find(vf, &func, int, &arg0, vop_rwlock, femop_rwlock);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, write_lock, ct));
}

void
vnext_rwunlock(femarg_t *vf, int write_lock, caller_context_t *ct)
{
	void (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vsop_find(vf, &func, void, &arg0, vop_rwunlock, femop_rwunlock);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	(*func)(arg0, write_lock, ct);
}

int
vnext_seek(femarg_t *vf, offset_t ooff, offset_t *noffp, caller_context_t *ct)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vsop_find(vf, &func, int, &arg0, vop_seek, femop_seek);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, ooff, noffp, ct));
}

int
vnext_cmp(femarg_t *vf, vnode_t *vp2, caller_context_t *ct)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vsop_find(vf, &func, int, &arg0, vop_cmp, femop_cmp);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, vp2, ct));
}

int
vnext_frlock(femarg_t *vf, int cmd, struct flock64 *bfp, int flag,
	offset_t offset, struct flk_callback *flk_cbp, cred_t *cr,
	caller_context_t *ct)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vsop_find(vf, &func, int, &arg0, vop_frlock, femop_frlock);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, cmd, bfp, flag, offset, flk_cbp, cr, ct));
}

int
vnext_space(femarg_t *vf, int cmd, struct flock64 *bfp, int flag,
	offset_t offset, cred_t *cr, caller_context_t *ct)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vsop_find(vf, &func, int, &arg0, vop_space, femop_space);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, cmd, bfp, flag, offset, cr, ct));
}

int
vnext_realvp(femarg_t *vf, vnode_t **vpp, caller_context_t *ct)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vsop_find(vf, &func, int, &arg0, vop_realvp, femop_realvp);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, vpp, ct));
}

int
vnext_getpage(femarg_t *vf, offset_t off, size_t len, uint_t *protp,
	struct page **plarr, size_t plsz, struct seg *seg, caddr_t addr,
	enum seg_rw rw, cred_t *cr, caller_context_t *ct)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vsop_find(vf, &func, int, &arg0, vop_getpage, femop_getpage);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, off, len, protp, plarr, plsz, seg, addr, rw,
	    cr, ct));
}

int
vnext_putpage(femarg_t *vf, offset_t off, size_t len, int flags,
	cred_t *cr, caller_context_t *ct)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vsop_find(vf, &func, int, &arg0, vop_putpage, femop_putpage);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, off, len, flags, cr, ct));
}

int
vnext_map(femarg_t *vf, offset_t off, struct as *as, caddr_t *addrp,
	size_t len, uchar_t prot, uchar_t maxprot, uint_t flags,
	cred_t *cr, caller_context_t *ct)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vsop_find(vf, &func, int, &arg0, vop_map, femop_map);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, off, as, addrp, len, prot, maxprot, flags,
	    cr, ct));
}

int
vnext_addmap(femarg_t *vf, offset_t off, struct as *as, caddr_t addr,
	size_t len, uchar_t prot, uchar_t maxprot, uint_t flags,
	cred_t *cr, caller_context_t *ct)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vsop_find(vf, &func, int, &arg0, vop_addmap, femop_addmap);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, off, as, addr, len, prot, maxprot, flags,
	    cr, ct));
}

int
vnext_delmap(femarg_t *vf, offset_t off, struct as *as, caddr_t addr,
	size_t len, uint_t prot, uint_t maxprot, uint_t flags,
	cred_t *cr, caller_context_t *ct)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vsop_find(vf, &func, int, &arg0, vop_delmap, femop_delmap);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, off, as, addr, len, prot, maxprot, flags,
	    cr, ct));
}

int
vnext_poll(femarg_t *vf, short events, int anyyet, short *reventsp,
	struct pollhead **phpp, caller_context_t *ct)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vsop_find(vf, &func, int, &arg0, vop_poll, femop_poll);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, events, anyyet, reventsp, phpp, ct));
}

int
vnext_dump(femarg_t *vf, caddr_t addr, offset_t lbdn, offset_t dblks,
	caller_context_t *ct)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vsop_find(vf, &func, int, &arg0, vop_dump, femop_dump);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, addr, lbdn, dblks, ct));
}

int
vnext_pathconf(femarg_t *vf, int cmd, ulong_t *valp, cred_t *cr,
	caller_context_t *ct)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vsop_find(vf, &func, int, &arg0, vop_pathconf, femop_pathconf);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, cmd, valp, cr, ct));
}

int
vnext_pageio(femarg_t *vf, struct page *pp, u_offset_t io_off,
	size_t io_len, int flags, cred_t *cr, caller_context_t *ct)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vsop_find(vf, &func, int, &arg0, vop_pageio, femop_pageio);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, pp, io_off, io_len, flags, cr, ct));
}

int
vnext_dumpctl(femarg_t *vf, int action, offset_t *blkp, caller_context_t *ct)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vsop_find(vf, &func, int, &arg0, vop_dumpctl, femop_dumpctl);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, action, blkp, ct));
}

void
vnext_dispose(femarg_t *vf, struct page *pp, int flag, int dn, cred_t *cr,
	caller_context_t *ct)
{
	void (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vsop_find(vf, &func, void, &arg0, vop_dispose, femop_dispose);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	(*func)(arg0, pp, flag, dn, cr, ct);
}

int
vnext_setsecattr(femarg_t *vf, vsecattr_t *vsap, int flag, cred_t *cr,
	caller_context_t *ct)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vsop_find(vf, &func, int, &arg0, vop_setsecattr, femop_setsecattr);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, vsap, flag, cr, ct));
}

int
vnext_getsecattr(femarg_t *vf, vsecattr_t *vsap, int flag, cred_t *cr,
	caller_context_t *ct)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vsop_find(vf, &func, int, &arg0, vop_getsecattr, femop_getsecattr);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, vsap, flag, cr, ct));
}

int
vnext_shrlock(femarg_t *vf, int cmd, struct shrlock *shr, int flag,
	cred_t *cr, caller_context_t *ct)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vsop_find(vf, &func, int, &arg0, vop_shrlock, femop_shrlock);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, cmd, shr, flag, cr, ct));
}

int
vnext_vnevent(femarg_t *vf, vnevent_t vnevent, vnode_t *dvp, char *cname,
    caller_context_t *ct)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vsop_find(vf, &func, int, &arg0, vop_vnevent, femop_vnevent);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, vnevent, dvp, cname, ct));
}

int
vnext_reqzcbuf(femarg_t *vf, enum uio_rw ioflag, xuio_t *xuiop, cred_t *cr,
    caller_context_t *ct)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vsop_find(vf, &func, int, &arg0, vop_reqzcbuf, femop_reqzcbuf);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, ioflag, xuiop, cr, ct));
}

int
vnext_retzcbuf(femarg_t *vf, xuio_t *xuiop, cred_t *cr, caller_context_t *ct)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vsop_find(vf, &func, int, &arg0, vop_retzcbuf, femop_retzcbuf);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, xuiop, cr, ct));
}

int
vfsnext_mount(fsemarg_t *vf, vnode_t *mvp, struct mounta *uap, cred_t *cr)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vfsop_find(vf, &func, int, &arg0, vfs_mount, fsemop_mount);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, mvp, uap, cr));
}

int
vfsnext_unmount(fsemarg_t *vf, int flag, cred_t *cr)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vfsop_find(vf, &func, int, &arg0, vfs_unmount, fsemop_unmount);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, flag, cr));
}

int
vfsnext_root(fsemarg_t *vf, vnode_t **vpp)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vfsop_find(vf, &func, int, &arg0, vfs_root, fsemop_root);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, vpp));
}

int
vfsnext_statvfs(fsemarg_t *vf, statvfs64_t *sp)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vfsop_find(vf, &func, int, &arg0, vfs_statvfs, fsemop_statvfs);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, sp));
}

int
vfsnext_sync(fsemarg_t *vf, short flag, cred_t *cr)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vfsop_find(vf, &func, int, &arg0, vfs_sync, fsemop_sync);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, flag, cr));
}

int
vfsnext_vget(fsemarg_t *vf, vnode_t **vpp, fid_t *fidp)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vfsop_find(vf, &func, int, &arg0, vfs_vget, fsemop_vget);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, vpp, fidp));
}

int
vfsnext_mountroot(fsemarg_t *vf, enum whymountroot reason)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vfsop_find(vf, &func, int, &arg0, vfs_mountroot, fsemop_mountroot);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, reason));
}

void
vfsnext_freevfs(fsemarg_t *vf)
{
	void (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vfsop_find(vf, &func, void, &arg0, vfs_freevfs, fsemop_freevfs);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	(*func)(arg0);
}

int
vfsnext_vnstate(fsemarg_t *vf, vnode_t *vp, vntrans_t nstate)
{
	int (*func)() = NULL;
	void *arg0 = NULL;

	ASSERT(vf != NULL);
	vf->fa_fnode--;
	vfsop_find(vf, &func, int, &arg0, vfs_vnstate, fsemop_vnstate);
	ASSERT(func != NULL);
	ASSERT(arg0 != NULL);
	return ((*func)(arg0, vp, nstate));
}


/*
 * Create a new fem_head and associate with the vnode.
 * To keep the unaugmented vnode access path lock free, we spin
 * update this - create a new one, then try and install it. If
 * we fail to install, release the old one and pretend we succeeded.
 */

static struct fem_head *
new_femhead(struct fem_head **hp)
{
	struct fem_head	*head;

	head = kmem_alloc(sizeof (*head), KM_SLEEP);
	mutex_init(&head->femh_lock, NULL, MUTEX_DEFAULT, NULL);
	head->femh_list = NULL;
	if (atomic_cas_ptr(hp, NULL, head) != NULL) {
		kmem_free(head, sizeof (*head));
		head = *hp;
	}
	return (head);
}

/*
 * Create a fem_list.  The fem_list that gets returned is in a
 * very rudimentary state and MUST NOT be used until it's initialized
 * (usually by femlist_construct() or fem_dup_list()).  The refcount
 * and size is set properly and top-of-stack is set to the "guard" node
 * just to be consistent.
 *
 * If anyone were to accidentally trying to run on this fem_list before
 * it's initialized then the system would likely panic trying to defererence
 * the (NULL) fn_op pointer.
 *
 */
static struct fem_list *
femlist_create(int numnodes)
{
	struct fem_list	*sp;

	sp = kmem_alloc(fl_ntob(numnodes), KM_SLEEP);
	sp->feml_refc  = 1;
	sp->feml_ssize = numnodes;
	sp->feml_nodes[0] = FEM_GUARD(FEMTYPE_NULL);
	sp->feml_tos = 0;
	return (sp);
}

/*
 * Construct a new femlist.
 * The list is constructed with the appropriate type of guard to
 * anchor it, and inserts the original ops.
 */

static struct fem_list *
femlist_construct(void *baseops, int type, int numnodes)
{
	struct fem_list	*sp;

	sp = femlist_create(numnodes);
	sp->feml_nodes[0] = FEM_GUARD(type);
	sp->feml_nodes[1].fn_op.anon = baseops;
	sp->feml_nodes[1].fn_available = NULL;
	sp->feml_nodes[1].fn_av_hold = NULL;
	sp->feml_nodes[1].fn_av_rele = NULL;
	sp->feml_tos = 1;
	return (sp);
}

/*
 * Duplicate a list.  Copy the original list to the clone.
 *
 * NOTE: The caller must have the fem_head for the lists locked.
 * Assuming the appropriate lock is held and the caller has done the
 * math right, the clone list should be big enough to old the original.
 */

static void
fem_dup_list(struct fem_list *orig, struct fem_list *clone)
{
	int		i;

	ASSERT(clone->feml_ssize >= orig->feml_ssize);

	bcopy(orig->feml_nodes, clone->feml_nodes,
	    sizeof (orig->feml_nodes[0]) * orig->feml_ssize);
	clone->feml_tos = orig->feml_tos;
	/*
	 * Now that we've copied the old list (orig) to the new list (clone),
	 * we need to walk the new list and put another hold on fn_available.
	 */
	for (i = clone->feml_tos; i > 0; i--) {
		struct fem_node *fnp = &clone->feml_nodes[i];

		if (fnp->fn_av_hold)
			(*(fnp->fn_av_hold))(fnp->fn_available);
	}
}


static int
fem_push_node(
	struct fem_head **hp,
	void **baseops,
	int type,
	struct fem_node *nnode,
	femhow_t how)
{
	struct fem_head	*hd;
	struct fem_list	*list;
	void		*oldops;
	int		retry;
	int		error = 0;
	int		i;

	/* Validate the node */
	if ((nnode->fn_op.anon == NULL) || (nnode->fn_available == NULL)) {
		return (EINVAL);
	}

	if ((hd = *hp) == NULL) { /* construct a proto-list */
		hd = new_femhead(hp);
	}
	/*
	 * RULE: once a femhead has been pushed onto a object, it cannot be
	 * removed until the object is destroyed.  It can be deactivated by
	 * placing the original 'object operations' onto the object, which
	 * will ignore the femhead.
	 * The loop will exist when the femh_list has space to push a monitor
	 * onto it.
	 */
	do {
		retry = 1;
		list = fem_lock(hd);
		oldops = *baseops;

		if (list != NULL) {
			if (list->feml_tos+1 < list->feml_ssize) {
				retry = 0;
			} else {
				struct fem_list	*olist = list;

				fem_addref(olist);
				fem_unlock(hd);
				list = femlist_create(olist->feml_ssize * 2);
				(void) fem_lock(hd);
				if (hd->femh_list == olist) {
					if (list->feml_ssize <=
					    olist->feml_ssize) {
						/*
						 * We have a new list, but it
						 * is too small to hold the
						 * original contents plus the
						 * one to push.  Release the
						 * new list and start over.
						 */
						fem_release(list);
						fem_unlock(hd);
					} else {
						/*
						 * Life is good:  Our new list
						 * is big enough to hold the
						 * original list (olist) + 1.
						 */
						fem_dup_list(olist, list);
						/* orphan this list */
						hd->femh_list = list;
						(void) fem_delref(olist);
						retry = 0;
					}
				} else {
					/* concurrent update, retry */
					fem_release(list);
					fem_unlock(hd);
				}
				/* remove the reference we added above */
				fem_release(olist);
			}
		} else {
			fem_unlock(hd);
			list = femlist_construct(oldops, type, NNODES_DEFAULT);
			(void) fem_lock(hd);
			if (hd->femh_list != NULL || *baseops != oldops) {
				/* concurrent update, retry */
				fem_release(list);
				fem_unlock(hd);
			} else {
				hd->femh_list = list;
				*baseops = FEM_HEAD(type);
				retry = 0;
			}
		}
	} while (retry);

	ASSERT(mutex_owner(&hd->femh_lock) == curthread);
	ASSERT(list->feml_tos+1 < list->feml_ssize);

	/*
	 * The presence of "how" will modify the behavior of how/if
	 * nodes are pushed.  If it's FORCE, then we can skip
	 * all the checks and push it on.
	 */
	if (how != FORCE) {
		/* Start at the top and work our way down */
		for (i = list->feml_tos; i > 0; i--) {
			void *fn_av = list->feml_nodes[i].fn_available;
			void *fn_op = list->feml_nodes[i].fn_op.anon;

			/*
			 * OPARGUNIQ means that this node should not
			 * be pushed on if a node with the same op/avail
			 * combination exists.  This situation returns
			 * EBUSY.
			 *
			 * OPUNIQ means that this node should not be
			 * pushed on if a node with the same op exists.
			 * This situation also returns EBUSY.
			 */
			switch (how) {

			case OPUNIQ:
				if (fn_op == nnode->fn_op.anon) {
					error = EBUSY;
				}
				break;

			case OPARGUNIQ:
				if ((fn_op == nnode->fn_op.anon) &&
				    (fn_av == nnode->fn_available)) {
					error = EBUSY;
				}
				break;

			default:
				error = EINVAL;	/* Unexpected value */
				break;
			}

			if (error)
				break;
		}
	}

	if (error == 0) {
		/*
		 * If no errors, slap the node on the list.
		 * Note: The following is a structure copy.
		 */
		list->feml_nodes[++(list->feml_tos)] = *nnode;
	}

	fem_unlock(hd);
	return (error);
}

/*
 * Remove a node by copying the list above it down a notch.
 * If the list is busy, replace it with an idle one and work
 * upon it.
 * A node matches if the opset matches and the datap matches or is
 * null.
 */

static int
remove_node(struct fem_list *sp, void **baseops, void *opset, void *datap)
{
	int	i;
	struct fem_node	*fn;

	for (i = sp->feml_tos; i > 0; i--) {
		fn = sp->feml_nodes+i;
		if (fn->fn_op.anon == opset &&
		    (fn->fn_available == datap || datap == NULL)) {
			break;
		}
	}
	if (i == 0) {
		return (EINVAL);
	}

	/*
	 * At this point we have a node in-hand (*fn) that we are about
	 * to remove by overwriting it and adjusting the stack.  This is
	 * our last chance to do anything with this node so we do the
	 * release on the arg.
	 */
	if (fn->fn_av_rele)
		(*(fn->fn_av_rele))(fn->fn_available);

	while (i++ < sp->feml_tos) {
		sp->feml_nodes[i-1] = sp->feml_nodes[i];
	}
	if (--(sp->feml_tos) == 1) { /* Empty, restore ops */
		*baseops = sp->feml_nodes[1].fn_op.anon;
	}
	return (0);
}

static int
fem_remove_node(struct fem_head *fh, void **baseops, void *opset, void *datap)
{
	struct fem_list *sp;
	int		error = 0;
	int		retry;

	if (fh == NULL) {
		return (EINVAL);
	}

	do {
		retry = 0;
		if ((sp = fem_lock(fh)) == NULL) {
			fem_unlock(fh);
			error = EINVAL;
		} else if (sp->feml_refc == 1) {
			error = remove_node(sp, baseops, opset, datap);
			if (sp->feml_tos == 1) {
				/*
				 * The top-of-stack was decremented by
				 * remove_node().  If it got down to 1,
				 * then the base ops were replaced and we
				 * call fem_release() which will free the
				 * fem_list.
				 */
				fem_release(sp);
				fh->femh_list = NULL;
				/* XXX - Do we need a membar_producer() call? */
			}
			fem_unlock(fh);
		} else {
			/* busy - install a new one without this monitor */
			struct fem_list *nsp;	/* New fem_list being cloned */

			fem_addref(sp);
			fem_unlock(fh);
			nsp = femlist_create(sp->feml_ssize);
			if (fem_lock(fh) == sp) {
				/*
				 * We popped out of the lock, created a
				 * list, then relocked.  If we're in here
				 * then the fem_head points to the same list
				 * it started with.
				 */
				fem_dup_list(sp, nsp);
				error = remove_node(nsp, baseops, opset, datap);
				if (error != 0) {
					fem_release(nsp);
				} else if (nsp->feml_tos == 1) {
					/* New list now empty, tear it down */
					fem_release(nsp);
					fh->femh_list = NULL;
				} else {
					fh->femh_list = nsp;
				}
				(void) fem_delref(sp);
			} else {
				/* List changed while locked, try again... */
				fem_release(nsp);
				retry = 1;
			}
			/*
			 * If error is set, then we tried to remove a node
			 * from the list, but failed.  This means that we
			 * will still be using this list so don't release it.
			 */
			if (error == 0)
				fem_release(sp);
			fem_unlock(fh);
		}
	} while (retry);
	return (error);
}


/*
 * perform operation on each element until one returns non zero
 */
static int
fem_walk_list(
	struct fem_list *sp,
	int (*f)(struct fem_node *, void *, void *),
	void *mon,
	void *arg)
{
	int	i;

	ASSERT(sp != NULL);
	for (i = sp->feml_tos; i > 0; i--) {
		if ((*f)(sp->feml_nodes+i, mon, arg) != 0) {
			break;
		}
	}
	return (i);
}

/*
 * companion comparison functions.
 */
static int
fem_compare_mon(struct fem_node *n, void *mon, void *arg)
{
	return ((n->fn_op.anon == mon) && (n->fn_available == arg));
}

/*
 * VNODE interposition.
 */

int
fem_create(char *name, const struct fs_operation_def *templ,
    fem_t **actual)
{
	int	unused_ops = 0;
	int	e;
	fem_t	*newf;

	newf = fem_alloc();
	newf->name = name;
	newf->templ = templ;

	e =  fs_build_vector(newf, &unused_ops, fem_opdef, templ);
	if (e != 0) {
#ifdef DEBUG
		cmn_err(CE_WARN, "fem_create: error %d building vector", e);
#endif
		fem_free(newf);
	} else {
		*actual = newf;
	}
	return (e);
}

int
fem_install(
	vnode_t *vp,		/* Vnode on which monitor is being installed */
	fem_t *mon,		/* Monitor operations being installed */
	void *arg,		/* Opaque data used by monitor */
	femhow_t how,		/* Installation control */
	void (*arg_hold)(void *),	/* Hold routine for "arg" */
	void (*arg_rele)(void *))	/* Release routine for "arg" */
{
	int	error;
	struct fem_node	nnode;

	nnode.fn_available = arg;
	nnode.fn_op.fem = mon;
	nnode.fn_av_hold = arg_hold;
	nnode.fn_av_rele = arg_rele;
	/*
	 * If we have a non-NULL hold function, do the hold right away.
	 * The release is done in remove_node().
	 */
	if (arg_hold)
		(*arg_hold)(arg);

	error = fem_push_node(&vp->v_femhead, (void **)&vp->v_op, FEMTYPE_VNODE,
	    &nnode, how);

	/* If there was an error then the monitor wasn't pushed */
	if (error && arg_rele)
		(*arg_rele)(arg);

	return (error);
}

int
fem_is_installed(vnode_t *v, fem_t *mon, void *arg)
{
	int	e;
	struct fem_list	*fl;

	fl = fem_get(v->v_femhead);
	if (fl != NULL) {
		e = fem_walk_list(fl, fem_compare_mon, (void *)mon, arg);
		fem_release(fl);
		return (e);
	}
	return (0);
}

int
fem_uninstall(vnode_t *v, fem_t *mon, void *arg)
{
	int	e;
	e = fem_remove_node(v->v_femhead, (void **)&v->v_op,
	    (void *)mon, arg);
	return (e);
}

void
fem_setvnops(vnode_t *v, vnodeops_t *newops)
{
	vnodeops_t	*r;

	ASSERT(v != NULL);
	ASSERT(newops != NULL);

	do {
		r = v->v_op;
		membar_consumer();
		if (v->v_femhead != NULL) {
			struct fem_list	*fl;
			if ((fl = fem_lock(v->v_femhead)) != NULL) {
				fl->feml_nodes[1].fn_op.vnode = newops;
				fem_unlock(v->v_femhead);
				return;
			}
			fem_unlock(v->v_femhead);
		}
	} while (atomic_cas_ptr(&v->v_op, r, newops) != r);
}

vnodeops_t *
fem_getvnops(vnode_t *v)
{
	vnodeops_t	*r;

	ASSERT(v != NULL);

	r = v->v_op;
	membar_consumer();
	if (v->v_femhead != NULL) {
		struct fem_list	*fl;
		if ((fl = fem_lock(v->v_femhead)) != NULL) {
			r = fl->feml_nodes[1].fn_op.vnode;
		}
		fem_unlock(v->v_femhead);
	}
	return (r);
}


/*
 * VFS interposition
 */
int
fsem_create(char *name, const struct fs_operation_def *templ,
    fsem_t **actual)
{
	int	unused_ops = 0;
	int	e;
	fsem_t	*newv;

	newv = fsem_alloc();
	newv->name = (const char *)name;
	newv->templ = templ;

	e = fs_build_vector(newv, &unused_ops, fsem_opdef, templ);
	if (e != 0) {
#ifdef DEBUG
		cmn_err(CE_WARN, "fsem_create: error %d building vector", e);
#endif
		fsem_free(newv);
	} else {
		*actual = newv;
	}
	return (e);
}

/*
 * These need to be re-written, but there should be more common bits.
 */

int
fsem_is_installed(struct vfs *v, fsem_t *mon, void *arg)
{
	struct fem_list	*fl;

	if (v->vfs_implp == NULL)
		return (0);

	fl = fem_get(v->vfs_femhead);
	if (fl != NULL) {
		int	e;
		e = fem_walk_list(fl, fem_compare_mon, (void *)mon, arg);
		fem_release(fl);
		return (e);
	}
	return (0);
}

int
fsem_install(
	struct vfs *vfsp,	/* VFS on which monitor is being installed */
	fsem_t *mon,		/* Monitor operations being installed */
	void *arg,		/* Opaque data used by monitor */
	femhow_t how,		/* Installation control */
	void (*arg_hold)(void *),	/* Hold routine for "arg" */
	void (*arg_rele)(void *))	/* Release routine for "arg" */
{
	int	error;
	struct fem_node	nnode;

	/* If this vfs hasn't been properly initialized, fail the install */
	if (vfsp->vfs_implp == NULL)
		return (EINVAL);

	nnode.fn_available = arg;
	nnode.fn_op.fsem = mon;
	nnode.fn_av_hold = arg_hold;
	nnode.fn_av_rele = arg_rele;
	/*
	 * If we have a non-NULL hold function, do the hold right away.
	 * The release is done in remove_node().
	 */
	if (arg_hold)
		(*arg_hold)(arg);

	error = fem_push_node(&vfsp->vfs_femhead, (void **)&vfsp->vfs_op,
	    FEMTYPE_VFS, &nnode, how);

	/* If there was an error then the monitor wasn't pushed */
	if (error && arg_rele)
		(*arg_rele)(arg);

	return (error);
}

int
fsem_uninstall(struct vfs *v, fsem_t *mon, void *arg)
{
	int	e;

	if (v->vfs_implp == NULL)
		return (EINVAL);

	e = fem_remove_node(v->vfs_femhead, (void **)&v->vfs_op,
	    (void *)mon, arg);
	return (e);
}

void
fsem_setvfsops(vfs_t *v, vfsops_t *newops)
{
	vfsops_t	*r;

	ASSERT(v != NULL);
	ASSERT(newops != NULL);
	ASSERT(v->vfs_implp);

	do {
		r = v->vfs_op;
		membar_consumer();
		if (v->vfs_femhead != NULL) {
			struct fem_list	*fl;
			if ((fl = fem_lock(v->vfs_femhead)) != NULL) {
				fl->feml_nodes[1].fn_op.vfs = newops;
				fem_unlock(v->vfs_femhead);
				return;
			}
			fem_unlock(v->vfs_femhead);
		}
	} while (atomic_cas_ptr(&v->vfs_op, r, newops) != r);
}

vfsops_t *
fsem_getvfsops(vfs_t *v)
{
	vfsops_t	*r;

	ASSERT(v != NULL);
	ASSERT(v->vfs_implp);

	r = v->vfs_op;
	membar_consumer();
	if (v->vfs_femhead != NULL) {
		struct fem_list	*fl;
		if ((fl = fem_lock(v->vfs_femhead)) != NULL) {
			r = fl->feml_nodes[1].fn_op.vfs;
		}
		fem_unlock(v->vfs_femhead);
	}
	return (r);
}

/*
 * Setup FEM.
 */
void
fem_init()
{
	struct fem_type_info   *fi;

	/*
	 * This femtype is only used for fem_list creation so we only
	 * need the "guard" to be initialized so that feml_tos has
	 * some rudimentary meaning.  A fem_list must not be used until
	 * it has been initialized (either via femlist_construct() or
	 * fem_dup_list()).  Anything that tries to use this fem_list
	 * before it's actually initialized would panic the system as
	 * soon as "fn_op" (NULL) is dereferenced.
	 */
	fi = femtype + FEMTYPE_NULL;
	fi->errf = fem_err;
	fi->guard.fn_available = (void *)&fi->guard;
	fi->guard.fn_av_hold = NULL;
	fi->guard.fn_av_rele = NULL;
	fi->guard.fn_op.anon = NULL;

	fi = femtype + FEMTYPE_VNODE;
	fi->errf = fem_err;
	fi->head.fn_available = NULL;
	fi->head.fn_av_hold = NULL;
	fi->head.fn_av_rele = NULL;
	(void) vn_make_ops("fem-head", fhead_vn_spec, &fi->head.fn_op.vnode);
	fi->guard.fn_available = (void *)&fi->guard;
	fi->guard.fn_av_hold = NULL;
	fi->guard.fn_av_rele = NULL;
	(void) fem_create("fem-guard", fem_guard_ops, &fi->guard.fn_op.fem);

	fi = femtype + FEMTYPE_VFS;
	fi->errf = fsem_err;
	fi->head.fn_available = NULL;
	fi->head.fn_av_hold = NULL;
	fi->head.fn_av_rele = NULL;
	(void) vfs_makefsops(fshead_vfs_spec, &fi->head.fn_op.vfs);

	fi->guard.fn_available = (void *)&fi->guard;
	fi->guard.fn_av_hold = NULL;
	fi->guard.fn_av_rele = NULL;
	(void) fsem_create("fem-guard", fsem_guard_ops, &fi->guard.fn_op.fsem);
}


int
fem_err()
{
	cmn_err(CE_PANIC, "fem/vnode operations corrupt");
	return (0);
}

int
fsem_err()
{
	cmn_err(CE_PANIC, "fem/vfs operations corrupt");
	return (0);
}
