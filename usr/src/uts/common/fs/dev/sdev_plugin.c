/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

/*
 * Dynamic directory plugin interface for sdev.
 *
 * The sdev plugin interfaces provides a means for a dynamic directory based on
 * in-kernel state to be simply created. Traditionally, dynamic directories were
 * built into sdev itself. While these legacy plugins are useful, it makes more
 * sense for these pieces of functionality to live with the individual drivers.
 *
 * The plugin interface requires folks to implement three interfaces and
 * provides a series of callbacks that can be made in the context of those
 * interfaces to interrogate the sdev_node_t without having to leak
 * implementation details of the sdev_node_t. These interfaces are:
 *
 *   o spo_validate
 *
 *   Given a particular node, answer the question as to whether or not this
 *   entry is still valid. Here, plugins should use the name and the dev_t
 *   associated with the node to verify that it matches something that still
 *   exists.
 *
 *   o spo_filldir
 *
 *   Fill all the entries inside of a directory. Note that some of these entries
 *   may already exist.
 *
 *   o spo_inactive
 *
 *   The given node is no longer being used. This allows the consumer to
 *   potentially tear down anything that was being held open related to this.
 *   Note that this only fires when the given sdev_node_t becomes a zombie.
 *
 * During these callbacks a consumer is not allowed to register or unregister a
 * plugin, especially their own. They may call the sdev_ctx style functions. All
 * callbacks fire in a context where blocking is allowed (eg. the spl is below
 * LOCK_LEVEL).
 *
 * When a plugin is added, we create its directory in the global zone. By doing
 * that, we ensure that something isn't already there and that nothing else can
 * come along and try and create something without our knowledge. We only have
 * to create it in the GZ and not for all other instances of sdev because an
 * instance of sdev that isn't at /dev does not have dynamic directories, and
 * second, any instance of sdev present in a non-global zone cannot create
 * anything, therefore we know that by it not being in the global zone's
 * instance of sdev that we're good to go.
 *
 * Lock Ordering
 * -------------
 *
 * The global sdev_plugin_lock must be held before any of the individual
 * sdev_plugin_t`sp_lock. Further, once any plugin related lock has been held,
 * it is not legal to take any holds on any sdev_node_t or to grab the
 * sdev_node_t`contents_lock in any way.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fs/sdev_impl.h>
#include <sys/fs/sdev_plugin.h>
#include <fs/fs_subr.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ksynch.h>
#include <sys/sysmacros.h>
#include <sys/list.h>
#include <sys/ctype.h>

kmutex_t sdev_plugin_lock;
list_t sdev_plugin_list;
kmem_cache_t *sdev_plugin_cache;
struct vnodeops *sdev_plugin_vnops;

#define	SDEV_PLUGIN_NAMELEN	64

typedef struct sdev_plugin {
	list_node_t sp_link;
	char sp_name[SDEV_PLUGIN_NAMELEN];	/* E */
	int sp_nflags;				/* E */
	struct vnodeops *sp_vnops;		/* E */
	sdev_plugin_ops_t *sp_pops;		/* E */
	boolean_t sp_islegacy;			/* E */
	int (*sp_lvtor)(sdev_node_t *);		/* E */
	kmutex_t sp_lock;			/* Protects everything below */
	kcondvar_t sp_nodecv;
	size_t sp_nnodes;
} sdev_plugin_t;

/* ARGSUSED */
static int
sdev_plugin_cache_constructor(void *buf, void *arg, int tags)
{
	sdev_plugin_t *spp = buf;
	mutex_init(&spp->sp_lock, NULL, MUTEX_DRIVER, 0);
	cv_init(&spp->sp_nodecv, NULL, CV_DRIVER, NULL);
	return (0);
}

/* ARGSUSED */
static void
sdev_plugin_cache_destructor(void *buf, void *arg)
{
	sdev_plugin_t *spp = buf;
	cv_destroy(&spp->sp_nodecv);
	mutex_destroy(&spp->sp_lock);
}

enum vtype
sdev_ctx_vtype(sdev_ctx_t ctx)
{
	sdev_node_t *sdp = (sdev_node_t *)ctx;

	ASSERT(RW_LOCK_HELD(&sdp->sdev_contents));
	return (sdp->sdev_vnode->v_type);
}

const char *
sdev_ctx_path(sdev_ctx_t ctx)
{
	sdev_node_t *sdp = (sdev_node_t *)ctx;

	ASSERT(RW_LOCK_HELD(&sdp->sdev_contents));
	return (sdp->sdev_path);
}

const char *
sdev_ctx_name(sdev_ctx_t ctx)
{
	sdev_node_t *sdp = (sdev_node_t *)ctx;

	ASSERT(RW_LOCK_HELD(&sdp->sdev_contents));
	return (sdp->sdev_name);
}

int
sdev_ctx_minor(sdev_ctx_t ctx, minor_t *minorp)
{
	sdev_node_t *sdp = (sdev_node_t *)ctx;

	ASSERT(RW_LOCK_HELD(&sdp->sdev_contents));
	ASSERT(minorp != NULL);
	if (sdp->sdev_vnode->v_type == VCHR ||
	    sdp->sdev_vnode->v_type == VBLK) {
		*minorp = getminor(sdp->sdev_vnode->v_rdev);
		return (0);
	}

	return (ENODEV);
}

/*
 * Currently we only support psasing through a single flag -- SDEV_IS_GLOBAL.
 */
sdev_ctx_flags_t
sdev_ctx_flags(sdev_ctx_t ctx)
{
	sdev_node_t *sdp = (sdev_node_t *)ctx;

	ASSERT(RW_LOCK_HELD(&sdp->sdev_contents));
	return (sdp->sdev_flags & SDEV_GLOBAL);
}

/*
 * Use the same rules as zones for a name. isalphanum + '-', '_', and '.'.
 */
static int
sdev_plugin_name_isvalid(const char *c, int buflen)
{
	int i;

	for (i = 0; i < buflen; i++, c++) {
		if (*c == '\0')
			return (1);

		if (!isalnum(*c) && *c != '-' && *c != '_' && *c != '.')
			return (0);
	}
	/* Never found a null terminator */
	return (0);
}

static int
sdev_plugin_mknode(sdev_plugin_t *spp, sdev_node_t *sdvp, char *name,
    vattr_t *vap)
{
	int ret;
	sdev_node_t *svp;

	ASSERT(RW_WRITE_HELD(&sdvp->sdev_contents));
	ASSERT(spp != NULL);
	svp = sdev_cache_lookup(sdvp, name);
	if (svp != NULL) {
		SDEV_SIMPLE_RELE(svp);
		return (EEXIST);
	}

	ret = sdev_mknode(sdvp, name, &svp, vap, NULL, NULL, kcred,
	    SDEV_READY);
	if (ret != 0)
		return (ret);
	SDEV_SIMPLE_RELE(svp);

	return (0);
}

/*
 * Plugin node creation callbacks
 */
int
sdev_plugin_mkdir(sdev_ctx_t ctx, char *name)
{
	sdev_node_t *sdvp;
	timestruc_t now;
	struct vattr vap;

	if (sdev_plugin_name_isvalid(name, SDEV_PLUGIN_NAMELEN) == 0)
		return (EINVAL);

	sdvp = (sdev_node_t *)ctx;
	ASSERT(sdvp->sdev_private != NULL);
	ASSERT(RW_WRITE_HELD(&sdvp->sdev_contents));

	vap = *sdev_getdefault_attr(VDIR);
	gethrestime(&now);
	vap.va_atime = now;
	vap.va_mtime = now;
	vap.va_ctime = now;

	return (sdev_plugin_mknode(sdvp->sdev_private, sdvp, name, &vap));
}

int
sdev_plugin_mknod(sdev_ctx_t ctx, char *name, mode_t mode, dev_t dev)
{
	sdev_node_t *sdvp;
	timestruc_t now;
	struct vattr vap;
	mode_t type = mode & S_IFMT;
	mode_t access = mode & S_IAMB;

	if (sdev_plugin_name_isvalid(name, SDEV_PLUGIN_NAMELEN) == 0)
		return (EINVAL);

	sdvp = (sdev_node_t *)ctx;
	ASSERT(RW_WRITE_HELD(&sdvp->sdev_contents));

	/*
	 * Ensure only type and user/group/other permission bits are present.
	 * Do not allow setuid, setgid, etc.
	 */
	if ((mode & ~(S_IFMT | S_IAMB)) != 0)
		return (EINVAL);

	/* Disallow types other than character and block devices */
	if (type != S_IFCHR && type != S_IFBLK)
		return (EINVAL);

	/* Disallow execute bits */
	if ((access & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0)
		return (EINVAL);

	/* No bits other than 0666 in access */
	ASSERT((access &
	    ~(S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)) == 0);

	/* Default to relatively safe access bits if none specified. */
	if (access == 0)
		access = 0600;

	ASSERT(sdvp->sdev_private != NULL);

	vap = *sdev_getdefault_attr(type == S_IFCHR ? VCHR : VBLK);
	gethrestime(&now);
	vap.va_atime = now;
	vap.va_mtime = now;
	vap.va_ctime = now;
	vap.va_rdev = dev;
	vap.va_mode = type | access;

	/* Despite the similar name, this is in fact a different function */
	return (sdev_plugin_mknode(sdvp->sdev_private, sdvp, name, &vap));
}

static int
sdev_plugin_validate(sdev_node_t *sdp)
{
	int ret;
	sdev_plugin_t *spp;

	ASSERT(sdp->sdev_private != NULL);
	spp = sdp->sdev_private;
	ASSERT(spp->sp_islegacy == B_FALSE);
	ASSERT(spp->sp_pops != NULL);
	rw_enter(&sdp->sdev_contents, RW_READER);
	ret = spp->sp_pops->spo_validate((uintptr_t)sdp);
	rw_exit(&sdp->sdev_contents);
	return (ret);
}

static void
sdev_plugin_validate_dir(sdev_node_t *sdvp)
{
	int ret;
	sdev_node_t *svp, *next;

	ASSERT(RW_WRITE_HELD(&sdvp->sdev_contents));

	for (svp = SDEV_FIRST_ENTRY(sdvp); svp != NULL; svp = next) {

		next = SDEV_NEXT_ENTRY(sdvp, svp);
		ASSERT(svp->sdev_state != SDEV_ZOMBIE);
		/* skip nodes that aren't ready */
		if (svp->sdev_state == SDEV_INIT)
			continue;

		switch (sdev_plugin_validate(svp)) {
		case SDEV_VTOR_VALID:
		case SDEV_VTOR_SKIP:
			continue;
		case SDEV_VTOR_INVALID:
		case SDEV_VTOR_STALE:
			break;
		}

		SDEV_HOLD(svp);

		/*
		 * Clean out everything underneath this node before we
		 * remove it.
		 */
		if (svp->sdev_vnode->v_type == VDIR) {
			ret = sdev_cleandir(svp, NULL, 0);
			ASSERT(ret == 0);
		}
		/* remove the cache node */
		(void) sdev_cache_update(sdvp, &svp, svp->sdev_name,
		    SDEV_CACHE_DELETE);
		SDEV_RELE(svp);
	}
}

/* ARGSUSED */
static int
sdev_plugin_vop_readdir(struct vnode *dvp, struct uio *uiop, struct cred *cred,
    int *eofp, caller_context_t *ct_unused, int flags_unused)
{
	int ret;
	sdev_node_t *sdvp = VTOSDEV(dvp);
	sdev_plugin_t *spp;

	ASSERT(RW_READ_HELD(&sdvp->sdev_contents));

	/* Sanity check we're not a zombie before we do anyting else */
	if (sdvp->sdev_state == SDEV_ZOMBIE)
		return (ENOENT);

	spp = sdvp->sdev_private;
	ASSERT(spp != NULL);
	ASSERT(spp->sp_islegacy == B_FALSE);
	ASSERT(spp->sp_pops != NULL);

	if (crgetzoneid(cred) == GLOBAL_ZONEID && !SDEV_IS_GLOBAL(sdvp))
		return (EPERM);

	if (uiop->uio_offset == 0) {
		/*
		 * We upgrade to a write lock and grab the plugin's lock along
		 * the way. We're almost certainly going to get creation
		 * callbacks, so this is the only safe way to go.
		 */
		if (rw_tryupgrade(&sdvp->sdev_contents) == 0) {
			rw_exit(&sdvp->sdev_contents);
			rw_enter(&sdvp->sdev_contents, RW_WRITER);
			if (sdvp->sdev_state == SDEV_ZOMBIE) {
				rw_downgrade(&sdvp->sdev_contents);
				return (ENOENT);
			}
		}

		sdev_plugin_validate_dir(sdvp);
		ret = spp->sp_pops->spo_filldir((uintptr_t)sdvp);
		rw_downgrade(&sdvp->sdev_contents);
		if (ret != 0)
			return (ret);
	}

	return (devname_readdir_func(dvp, uiop, cred, eofp, 0));
}

/*
 * If we don't have a callback function that returns a failure, then sdev will
 * try to create a node for us which violates all of our basic assertions. To
 * work around that we create our own callback for devname_lookup_func which
 * always returns ENOENT as at this point either it was created with the filldir
 * callback or it was not.
 */
/*ARGSUSED*/
static int
sdev_plugin_vop_lookup_cb(sdev_node_t *ddv, char *nm, void **arg, cred_t *cred,
    void *unused, char *unused2)
{
	return (ENOENT);
}

/* ARGSUSED */
static int
sdev_plugin_vop_lookup(struct vnode *dvp, char *nm, struct vnode **vpp,
    struct pathname *pnp, int flags, struct vnode *rdir, struct cred *cred,
    caller_context_t *ct, int *direntflags, pathname_t *realpnp)
{
	int ret;
	sdev_node_t *sdvp;
	sdev_plugin_t *spp;

	/* execute access is required to search the directory */
	if ((ret = VOP_ACCESS(dvp, VEXEC, 0, cred, ct)) != 0)
		return (ret);

	sdvp = VTOSDEV(dvp);
	spp = sdvp->sdev_private;
	ASSERT(spp != NULL);
	ASSERT(spp->sp_islegacy == B_FALSE);
	ASSERT(spp->sp_pops != NULL);

	if (crgetzoneid(cred) == GLOBAL_ZONEID && !SDEV_IS_GLOBAL(sdvp))
		return (EPERM);

	/*
	 * Go straight for the write lock.
	 */
	rw_enter(&sdvp->sdev_contents, RW_WRITER);
	if (sdvp->sdev_state == SDEV_ZOMBIE) {
		rw_exit(&sdvp->sdev_contents);
		return (ENOENT);
	}
	sdev_plugin_validate_dir(sdvp);
	ret = spp->sp_pops->spo_filldir((uintptr_t)sdvp);
	rw_exit(&sdvp->sdev_contents);
	if (ret != 0)
		return (ret);

	return (devname_lookup_func(sdvp, nm, vpp, cred,
	    sdev_plugin_vop_lookup_cb, SDEV_VATTR));
}

/*
 * sdev is not a good citizen. We get inactive callbacks whenever a vnode goes
 * to zero, but isn't necessairily a zombie yet. As such, to make things easier
 * for users, we only fire the inactive callback when the node becomes a zombie
 * and thus will be torn down here.
 */
static void
sdev_plugin_vop_inactive_cb(struct vnode *dvp)
{
	sdev_node_t *sdp = VTOSDEV(dvp);
	sdev_plugin_t *spp = sdp->sdev_private;

	rw_enter(&sdp->sdev_contents, RW_READER);
	if (sdp->sdev_state != SDEV_ZOMBIE) {
		rw_exit(&sdp->sdev_contents);
		return;
	}
	spp->sp_pops->spo_inactive((uintptr_t)sdp);
	mutex_enter(&spp->sp_lock);
	VERIFY(spp->sp_nnodes > 0);
	spp->sp_nnodes--;
	cv_signal(&spp->sp_nodecv);
	mutex_exit(&spp->sp_lock);
	rw_exit(&sdp->sdev_contents);
}

/*ARGSUSED*/
static void
sdev_plugin_vop_inactive(struct vnode *dvp, struct cred *cred,
    caller_context_t *ct)
{
	sdev_node_t *sdp = VTOSDEV(dvp);
	sdev_plugin_t *spp = sdp->sdev_private;
	ASSERT(sdp->sdev_private != NULL);
	ASSERT(spp->sp_islegacy == B_FALSE);
	devname_inactive_func(dvp, cred, sdev_plugin_vop_inactive_cb);
}

const fs_operation_def_t sdev_plugin_vnodeops_tbl[] = {
	VOPNAME_READDIR,	{ .vop_readdir = sdev_plugin_vop_readdir },
	VOPNAME_LOOKUP,		{ .vop_lookup = sdev_plugin_vop_lookup },
	VOPNAME_INACTIVE,	{ .vop_inactive = sdev_plugin_vop_inactive },
	VOPNAME_CREATE,		{ .error = fs_nosys },
	VOPNAME_REMOVE,		{ .error = fs_nosys },
	VOPNAME_MKDIR,		{ .error = fs_nosys },
	VOPNAME_RMDIR,		{ .error = fs_nosys },
	VOPNAME_SYMLINK,	{ .error = fs_nosys },
	VOPNAME_SETSECATTR,	{ .error = fs_nosys },
	NULL,			NULL
};

/*
 * construct a new template with overrides from vtab
 */
static fs_operation_def_t *
sdev_merge_vtab(const fs_operation_def_t tab[])
{
	fs_operation_def_t *new;
	const fs_operation_def_t *tab_entry;

	/* make a copy of standard vnode ops table */
	new = kmem_alloc(sdev_vnodeops_tbl_size, KM_SLEEP);
	bcopy((void *)sdev_vnodeops_tbl, new, sdev_vnodeops_tbl_size);

	/* replace the overrides from tab */
	for (tab_entry = tab; tab_entry->name != NULL; tab_entry++) {
		fs_operation_def_t *std_entry = new;
		while (std_entry->name) {
			if (strcmp(tab_entry->name, std_entry->name) == 0) {
				std_entry->func = tab_entry->func;
				break;
			}
			std_entry++;
		}
	}

	return (new);
}

/* free memory allocated by sdev_merge_vtab */
static void
sdev_free_vtab(fs_operation_def_t *new)
{
	kmem_free(new, sdev_vnodeops_tbl_size);
}

/*
 * Register a new plugin.
 */
sdev_plugin_hdl_t
sdev_plugin_register(const char *name, sdev_plugin_ops_t *ops, int *errp)
{
	int ret, err;
	sdev_plugin_t *spp, *iter;
	vnode_t *vp, *nvp;
	sdev_node_t *sdp, *slp;
	timestruc_t now;
	struct vattr vap;

	/*
	 * Some consumers don't care about why they failed. To keep the code
	 * simple, we'll just pretend they gave us something.
	 */
	if (errp == NULL)
		errp = &err;

	if (sdev_plugin_name_isvalid(name, SDEV_PLUGIN_NAMELEN) == 0) {
		*errp = EINVAL;
		return (NULL);
	}

	if (ops->spo_version != 1) {
		*errp = EINVAL;
		return (NULL);
	}

	if (ops->spo_validate == NULL || ops->spo_filldir == NULL ||
	    ops->spo_inactive == NULL) {
		*errp = EINVAL;
		return (NULL);
	}

	if ((ops->spo_flags & ~SDEV_PLUGIN_FLAGS_MASK) != 0) {
		*errp = EINVAL;
		return (NULL);
	}

	spp = kmem_cache_alloc(sdev_plugin_cache, KM_SLEEP);
	(void) strlcpy(spp->sp_name, name, SDEV_PLUGIN_NAMELEN);

	spp->sp_pops = ops;
	spp->sp_nflags = SDEV_DYNAMIC | SDEV_VTOR;
	if (ops->spo_flags & SDEV_PLUGIN_NO_NCACHE)
		spp->sp_nflags |= SDEV_NO_NCACHE;
	if (ops->spo_flags & SDEV_PLUGIN_SUBDIR)
		spp->sp_nflags |= SDEV_SUBDIR;
	spp->sp_vnops = sdev_plugin_vnops;
	spp->sp_islegacy = B_FALSE;
	spp->sp_lvtor = NULL;
	spp->sp_nnodes = 0;

	/*
	 * Make sure it's unique, nothing exists with this name already, and add
	 * it to the list. We also need to go through and grab the sdev
	 * root node as we cannot grab any sdev node locks once we've grabbed
	 * the sdev_plugin_lock. We effectively assert that if a directory is
	 * not present in the GZ's /dev, then it doesn't exist in any of the
	 * local zones.
	 */
	ret = vn_openat("/dev", UIO_SYSSPACE, FREAD, 0, &vp, 0, 0, rootdir, -1);
	if (ret != 0) {
		*errp = ret;
		kmem_cache_free(sdev_plugin_cache, spp);
		return (NULL);
	}
	/* Make sure we have the real vnode */
	if (VOP_REALVP(vp, &nvp, NULL) == 0) {
		VN_HOLD(nvp);
		VN_RELE(vp);
		vp = nvp;
		nvp = NULL;
	}
	VERIFY(vp->v_op == sdev_vnodeops);
	sdp = VTOSDEV(vp);
	rw_enter(&sdp->sdev_contents, RW_WRITER);
	slp = sdev_cache_lookup(sdp, spp->sp_name);
	if (slp != NULL) {
		SDEV_RELE(slp);
		rw_exit(&sdp->sdev_contents);
		VN_RELE(vp);
		*errp = EEXIST;
		kmem_cache_free(sdev_plugin_cache, spp);
		return (NULL);
	}

	mutex_enter(&sdev_plugin_lock);
	for (iter = list_head(&sdev_plugin_list); iter != NULL;
	    iter = list_next(&sdev_plugin_list, iter)) {
		if (strcmp(spp->sp_name, iter->sp_name) == 0) {
			mutex_exit(&sdev_plugin_lock);
			rw_exit(&sdp->sdev_contents);
			VN_RELE(vp);
			*errp = EEXIST;
			kmem_cache_free(sdev_plugin_cache, spp);
			return (NULL);
		}
	}

	list_insert_tail(&sdev_plugin_list, spp);
	mutex_exit(&sdev_plugin_lock);

	/*
	 * Now go ahead and create the top level directory for the global zone.
	 */
	vap = *sdev_getdefault_attr(VDIR);
	gethrestime(&now);
	vap.va_atime = now;
	vap.va_mtime = now;
	vap.va_ctime = now;

	(void) sdev_plugin_mknode(spp, sdp, spp->sp_name, &vap);

	rw_exit(&sdp->sdev_contents);
	VN_RELE(vp);

	*errp = 0;

	return ((sdev_plugin_hdl_t)spp);
}

static void
sdev_plugin_unregister_cb(sdev_node_t *rdp, void *arg)
{
	sdev_plugin_t *spp = arg;
	sdev_node_t *sdp;

	rw_enter(&rdp->sdev_contents, RW_WRITER);
	sdp = sdev_cache_lookup(rdp, spp->sp_name);
	/* If it doesn't exist, we're done here */
	if (sdp == NULL) {
		rw_exit(&rdp->sdev_contents);
		return;
	}

	/*
	 * We first delete the directory before recursively marking everything
	 * else stale. This ordering should ensure that we don't accidentally
	 * miss anything.
	 */
	sdev_cache_update(rdp, &sdp, spp->sp_name, SDEV_CACHE_DELETE);
	sdev_stale(sdp);
	SDEV_RELE(sdp);
	rw_exit(&rdp->sdev_contents);
}

/*
 * Remove a plugin. This will block until everything has become a zombie, thus
 * guaranteeing the caller that nothing will call into them again once this call
 * returns. While the call is ongoing, it could be called into. Note that while
 * this is ongoing, it will block other mounts.
 */
int
sdev_plugin_unregister(sdev_plugin_hdl_t hdl)
{
	sdev_plugin_t *spp = (sdev_plugin_t *)hdl;
	if (spp->sp_islegacy)
		return (EINVAL);

	mutex_enter(&sdev_plugin_lock);
	list_remove(&sdev_plugin_list, spp);
	mutex_exit(&sdev_plugin_lock);

	sdev_mnt_walk(sdev_plugin_unregister_cb, spp);
	mutex_enter(&spp->sp_lock);
	while (spp->sp_nnodes > 0)
		cv_wait(&spp->sp_nodecv, &spp->sp_lock);
	mutex_exit(&spp->sp_lock);
	kmem_cache_free(sdev_plugin_cache, spp);
	return (0);
}

/*
 * Register an old sdev style plugin to deal with what used to be in the vtab.
 */
static int
sdev_plugin_register_legacy(struct sdev_vop_table *vtp)
{
	sdev_plugin_t *spp;

	spp = kmem_cache_alloc(sdev_plugin_cache, KM_SLEEP);
	(void) strlcpy(spp->sp_name, vtp->vt_name, SDEV_PLUGIN_NAMELEN);
	spp->sp_islegacy = B_TRUE;
	spp->sp_pops = NULL;
	spp->sp_nflags = vtp->vt_flags;
	spp->sp_lvtor = vtp->vt_vtor;
	spp->sp_nnodes = 0;

	if (vtp->vt_service != NULL) {
		fs_operation_def_t *templ;
		templ = sdev_merge_vtab(vtp->vt_service);
		if (vn_make_ops(vtp->vt_name,
		    (const fs_operation_def_t *)templ,
		    &spp->sp_vnops) != 0) {
			cmn_err(CE_WARN, "%s: malformed vnode ops\n",
			    vtp->vt_name);
			sdev_free_vtab(templ);
			kmem_cache_free(sdev_plugin_cache, spp);
			return (1);
		}

		if (vtp->vt_global_vops) {
			*(vtp->vt_global_vops) = spp->sp_vnops;
		}

		sdev_free_vtab(templ);
	} else {
		spp->sp_vnops = sdev_vnodeops;
	}

	/*
	 * No need to check for EEXIST here. These are loaded as a part of the
	 * sdev's initialization function. Further, we don't have to create them
	 * as that's taken care of in sdev's mount for the GZ.
	 */
	mutex_enter(&sdev_plugin_lock);
	list_insert_tail(&sdev_plugin_list, spp);
	mutex_exit(&sdev_plugin_lock);

	return (0);
}

/*
 * We need to match off of the sdev_path, not the sdev_name. We are only allowed
 * to exist directly under /dev.
 */
static sdev_plugin_t *
sdev_match(sdev_node_t *dv)
{
	int vlen;
	const char *path;
	sdev_plugin_t *spp;

	if (strlen(dv->sdev_path) <= 5)
		return (NULL);

	if (strncmp(dv->sdev_path, "/dev/", 5) != 0)
		return (NULL);
	path = dv->sdev_path + 5;

	mutex_enter(&sdev_plugin_lock);

	for (spp = list_head(&sdev_plugin_list); spp != NULL;
	    spp = list_next(&sdev_plugin_list, spp)) {
		if (strcmp(spp->sp_name, path) == 0) {
			mutex_exit(&sdev_plugin_lock);
			return (spp);
		}

		if (spp->sp_nflags & SDEV_SUBDIR) {
			vlen = strlen(spp->sp_name);
			if ((strncmp(spp->sp_name, path,
			    vlen - 1) == 0) && path[vlen] == '/') {
				mutex_exit(&sdev_plugin_lock);
				return (spp);
			}

		}
	}

	mutex_exit(&sdev_plugin_lock);
	return (NULL);
}

void
sdev_set_no_negcache(sdev_node_t *dv)
{
	char *path;
	sdev_plugin_t *spp;

	ASSERT(dv->sdev_path);
	path = dv->sdev_path + strlen("/dev/");

	mutex_enter(&sdev_plugin_lock);
	for (spp = list_head(&sdev_plugin_list); spp != NULL;
	    spp = list_next(&sdev_plugin_list, spp)) {
		if (strcmp(spp->sp_name, path) == 0) {
			if (spp->sp_nflags & SDEV_NO_NCACHE)
				dv->sdev_flags |= SDEV_NO_NCACHE;
			break;
		}
	}
	mutex_exit(&sdev_plugin_lock);
}

struct vnodeops *
sdev_get_vop(sdev_node_t *dv)
{
	char *path;
	sdev_plugin_t *spp;

	path = dv->sdev_path;
	ASSERT(path);

	/* gets the relative path to /dev/ */
	path += 5;

	if ((spp = sdev_match(dv)) != NULL) {
		dv->sdev_flags |= spp->sp_nflags;
		if (SDEV_IS_PERSIST(dv->sdev_dotdot) &&
		    (SDEV_IS_PERSIST(dv) || !SDEV_IS_DYNAMIC(dv)))
			dv->sdev_flags |= SDEV_PERSIST;
		return (spp->sp_vnops);
	}

	/* child inherits the persistence of the parent */
	if (SDEV_IS_PERSIST(dv->sdev_dotdot))
		dv->sdev_flags |= SDEV_PERSIST;
	return (sdev_vnodeops);
}

void *
sdev_get_vtor(sdev_node_t *dv)
{
	sdev_plugin_t *spp;

	if (dv->sdev_private == NULL) {
		spp = sdev_match(dv);
		if (spp == NULL)
			return (NULL);
	} else {
		spp = dv->sdev_private;
	}

	if (spp->sp_islegacy)
		return ((void *)spp->sp_lvtor);
	else
		return ((void *)sdev_plugin_validate);
}

void
sdev_plugin_nodeready(sdev_node_t *sdp)
{
	sdev_plugin_t *spp;

	ASSERT(RW_WRITE_HELD(&sdp->sdev_contents));
	ASSERT(sdp->sdev_private == NULL);

	spp = sdev_match(sdp);
	if (spp == NULL)
		return;
	if (spp->sp_islegacy)
		return;
	sdp->sdev_private = spp;
	mutex_enter(&spp->sp_lock);
	spp->sp_nnodes++;
	mutex_exit(&spp->sp_lock);
}

int
sdev_plugin_init(void)
{
	sdev_vop_table_t *vtp;
	fs_operation_def_t *templ;

	sdev_plugin_cache = kmem_cache_create("sdev_plugin",
	    sizeof (sdev_plugin_t), 0, sdev_plugin_cache_constructor,
	    sdev_plugin_cache_destructor, NULL, NULL, NULL, 0);
	if (sdev_plugin_cache == NULL)
		return (1);
	mutex_init(&sdev_plugin_lock, NULL, MUTEX_DRIVER, NULL);
	list_create(&sdev_plugin_list, sizeof (sdev_plugin_t),
	    offsetof(sdev_plugin_t, sp_link));

	/*
	 * Register all of the legacy vnops
	 */
	for (vtp = &vtab[0]; vtp->vt_name != NULL; vtp++)
		if (sdev_plugin_register_legacy(vtp) != 0)
			return (1);

	templ = sdev_merge_vtab(sdev_plugin_vnodeops_tbl);
	if (vn_make_ops("sdev_plugin",
	    (const fs_operation_def_t *)templ,
	    &sdev_plugin_vnops) != 0) {
		sdev_free_vtab(templ);
		return (1);
	}

	sdev_free_vtab(templ);
	return (0);
}
