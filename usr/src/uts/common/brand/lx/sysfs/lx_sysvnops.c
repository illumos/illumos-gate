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
 * Copyright 2016 Joyent, Inc.
 */

/*
 * lx_sysfs -- a Linux-compatible /sys for the LX brand
 */

#include <vm/seg_vn.h>
#include <sys/sdt.h>
#include <sys/strlog.h>
#include <sys/stropts.h>
#include <sys/cmn_err.h>
#include <sys/lx_brand.h>
#include <sys/x86_archext.h>
#include <sys/archsystm.h>
#include <sys/fp.h>
#include <sys/pool_pset.h>
#include <sys/pset.h>
#include <sys/zone.h>
#include <sys/pghw.h>
#include <sys/vfs_opreg.h>
#include <sys/param.h>
#include <sys/utsname.h>
#include <sys/lx_misc.h>
#include <sys/brand.h>
#include <sys/cred_impl.h>
#include <sys/tihdr.h>
#include <sys/sunddi.h>
#include <sys/vnode.h>
#include <sys/netstack.h>
#include <sys/ethernet.h>
#include <inet/ip_arp.h>
#include <sys/kstat.h>
#include <sys/zfs_ioctl.h>

#include "lx_sysfs.h"

/*
 * Pointer to the vnode ops vector for this fs.
 * This is instantiated in lxsys_init() in lx_sysvfsops.c
 */
vnodeops_t *lxsys_vnodeops;

static int lxsys_open(vnode_t **, int, cred_t *, caller_context_t *);
static int lxsys_close(vnode_t *, int, int, offset_t, cred_t *,
    caller_context_t *);
static int lxsys_read(vnode_t *, uio_t *, int, cred_t *, caller_context_t *);
static int lxsys_getattr(vnode_t *, vattr_t *, int, cred_t *,
    caller_context_t *);
static int lxsys_access(vnode_t *, int, int, cred_t *, caller_context_t *);
static int lxsys_lookup(vnode_t *, char *, vnode_t **,
    pathname_t *, int, vnode_t *, cred_t *, caller_context_t *, int *,
    pathname_t *);
static int lxsys_readdir(vnode_t *, uio_t *, cred_t *, int *,
    caller_context_t *, int);
static int lxsys_readlink(vnode_t *, uio_t *, cred_t *, caller_context_t *);
static int lxsys_cmp(vnode_t *, vnode_t *, caller_context_t *);
static int lxsys_sync(void);
static void lxsys_inactive(vnode_t *, cred_t *, caller_context_t *);

static vnode_t *lxsys_lookup_static(lxsys_node_t *, char *);
static vnode_t *lxsys_lookup_class_netdir(lxsys_node_t *, char *);
static vnode_t *lxsys_lookup_devices_virtual_netdir(lxsys_node_t *, char *);
static vnode_t *lxsys_lookup_blockdir(lxsys_node_t *, char *);
static vnode_t *lxsys_lookup_devices_virtual_bdidir(lxsys_node_t *, char *);
static vnode_t *lxsys_lookup_devices_zfsdir(lxsys_node_t *, char *);

static int lxsys_read_devices_virtual_net(lxsys_node_t *, lxsys_uiobuf_t *);
static int lxsys_read_devices_zfs_block(lxsys_node_t *, lxsys_uiobuf_t *);

static int lxsys_readdir_static(lxsys_node_t *, uio_t *, int *);
static int lxsys_readdir_class_netdir(lxsys_node_t *, uio_t *, int *);
static int lxsys_readdir_devices_virtual_netdir(lxsys_node_t *, uio_t *, int *);
static int lxsys_readdir_blockdir(lxsys_node_t *, uio_t *, int *);
static int lxsys_readdir_devices_virtual_bdidir(lxsys_node_t *, uio_t *, int *);
static int lxsys_readdir_devices_zfsdir(lxsys_node_t *, uio_t *, int *);

static int lxsys_readlink_class_net(lxsys_node_t *, char *, size_t);
static int lxsys_readlink_block(lxsys_node_t *, char *, size_t);

static void lxsys_zfs_list_zvols(ldi_ident_t, list_t *);

extern int zvol_name2minor(const char *, minor_t *);
extern int zvol_create_minor(const char *);

/*
 * The lx /sys vnode operations vector
 */
const fs_operation_def_t lxsys_vnodeops_template[] = {
	VOPNAME_OPEN,		{ .vop_open = lxsys_open },
	VOPNAME_CLOSE,		{ .vop_close = lxsys_close },
	VOPNAME_READ,		{ .vop_read = lxsys_read },
	VOPNAME_GETATTR,	{ .vop_getattr = lxsys_getattr },
	VOPNAME_ACCESS,		{ .vop_access = lxsys_access },
	VOPNAME_LOOKUP,		{ .vop_lookup = lxsys_lookup },
	VOPNAME_READDIR,	{ .vop_readdir = lxsys_readdir },
	VOPNAME_READLINK,	{ .vop_readlink = lxsys_readlink },
	VOPNAME_FSYNC,		{ .error = lxsys_sync },
	VOPNAME_SEEK,		{ .error = lxsys_sync },
	VOPNAME_INACTIVE,	{ .vop_inactive = lxsys_inactive },
	VOPNAME_CMP,		{ .vop_cmp = lxsys_cmp },
	NULL,			NULL
};

/*
 * Sysfs Inode format:
 * 0000AABBBBCC
 *
 * AA - TYPE
 * BBBB - INSTANCE
 * CC - ENDPOINT
 *
 * Where TYPE is one of:
 * 1 - SYS_STATIC
 * 2 - SYS_CLASS_NET
 * 3 - SYS_DEVICES_NET
 * 4 - SYS_BLOCK
 * 5 - SYS_DEVICES_BDI
 * 6 - SYS_DEVICES_ZFS
 *
 * Static entries will have assigned INSTANCE identifiers:
 * - 0x00: /sys
 * - 0x01: /sys/class
 * - 0x02: /sys/devices
 * - 0x03: /sys/fs
 * - 0x04: /sys/class/net
 * - 0x05: /sys/devices/virtual
 * - 0x06: /sys/devices/system
 * - 0x07: /sys/fs/cgroup
 * - 0x08: /sys/devices/virtual/net
 * - 0x09: /sys/block
 * - 0x0a: /sys/devices/virtual/bdi
 * - 0x0b: /sys/devices/zfs
 *
 * Dynamic /sys/class/net/<interface> symlinks will use an INSTANCE derived
 * from the corresonding ifindex.
 *
 * Dynamic /sys/devices/virtual/net/<interface>/<entries> directories will use
 * an INSTANCE derived from the ifindex and statically assigned ENDPOINT IDs
 * for the contained entries.
 *
 * Dynamic /sys/block/<dev> symlinks will use an INSTANCE derived from the
 * device major and instance from records listed in kstat or zvols.
 *
 * Dynamic /sys/devices/virtual/bdi/<dev> directories will use an INSTANCE
 * derived from the device major and instance from records listed in kstat.
 *
 * Dynamic /sys/devices/zfs/<dev> directories will use an INSTANCE derived from
 * the zvols.
 */

#define	LXSYS_INST_CLASSDIR			0x1
#define	LXSYS_INST_DEVICESDIR			0x2
#define	LXSYS_INST_FSDIR			0x3
#define	LXSYS_INST_CLASS_NETDIR			0x4
#define	LXSYS_INST_DEVICES_VIRTUALDIR		0x5
#define	LXSYS_INST_DEVICES_SYSTEMDIR		0x6
#define	LXSYS_INST_FS_CGROUPDIR			0x7
#define	LXSYS_INST_DEVICES_VIRTUAL_NETDIR	0x8
#define	LXSYS_INST_BLOCKDIR			0x9
#define	LXSYS_INST_DEVICES_VIRTUAL_BDIDIR	0xa
#define	LXSYS_INST_DEVICES_ZFSDIR		0xb

/*
 * file contents of an lx /sys directory.
 */
static lxsys_dirent_t dirlist_root[] = {
	{ LXSYS_INST_BLOCKDIR,		"block" },
	{ LXSYS_INST_CLASSDIR,		"class" },
	{ LXSYS_INST_DEVICESDIR,	"devices" },
	{ LXSYS_INST_FSDIR,		"fs" }
};
static lxsys_dirent_t dirlist_empty[] = {};
static lxsys_dirent_t dirlist_class[] = {
	{ LXSYS_INST_CLASS_NETDIR,	"net" }
};
static lxsys_dirent_t dirlist_fs[] = {
	{ LXSYS_INST_FS_CGROUPDIR,	"cgroup" }
};
static lxsys_dirent_t dirlist_devices[] = {
	{ LXSYS_INST_DEVICES_SYSTEMDIR,		"system" },
	{ LXSYS_INST_DEVICES_VIRTUALDIR,	"virtual" },
	{ LXSYS_INST_DEVICES_ZFSDIR,		"zfs" }
};
static lxsys_dirent_t dirlist_devices_virtual[] = {
	{ LXSYS_INST_DEVICES_VIRTUAL_BDIDIR,	"bdi" },
	{ LXSYS_INST_DEVICES_VIRTUAL_NETDIR,	"net" }
};


#define	LXSYS_ENDP_NET_ADDRESS	1
#define	LXSYS_ENDP_NET_ADDRLEN	2
#define	LXSYS_ENDP_NET_FLAGS	3
#define	LXSYS_ENDP_NET_IFINDEX	4
#define	LXSYS_ENDP_NET_MTU	5
#define	LXSYS_ENDP_NET_TXQLEN	6
#define	LXSYS_ENDP_NET_TYPE	7

#define	LXSYS_ENDP_BLOCK_DEVICE	1

static lxsys_dirent_t dirlist_devices_virtual_net[] = {
	{ LXSYS_ENDP_NET_ADDRESS,	"address" },
	{ LXSYS_ENDP_NET_ADDRLEN,	"addr_len" },
	{ LXSYS_ENDP_NET_FLAGS,		"flags" },
	{ LXSYS_ENDP_NET_IFINDEX,	"ifindex" },
	{ LXSYS_ENDP_NET_MTU,		"mtu" },
	{ LXSYS_ENDP_NET_TXQLEN,	"tx_queue_len" },
	{ LXSYS_ENDP_NET_TYPE,		"type" }
};

static lxsys_dirent_t dirlist_devices_zfs_block[] = {
	{ LXSYS_ENDP_BLOCK_DEVICE,	"device" }
};

#define	SYSDIRLISTSZ(l)	(sizeof (l) / sizeof ((l)[0]))

#define	SYSDLENT(i, l)	{ i, l, SYSDIRLISTSZ(l) }
static lxsys_dirlookup_t lxsys_dirlookup[] = {
	SYSDLENT(LXSYS_INST_ROOT, dirlist_root),
	SYSDLENT(LXSYS_INST_CLASSDIR, dirlist_class),
	SYSDLENT(LXSYS_INST_FSDIR, dirlist_fs),
	SYSDLENT(LXSYS_INST_FS_CGROUPDIR, dirlist_empty),
	SYSDLENT(LXSYS_INST_DEVICESDIR, dirlist_devices),
	SYSDLENT(LXSYS_INST_DEVICES_SYSTEMDIR, dirlist_empty),
	SYSDLENT(LXSYS_INST_DEVICES_VIRTUALDIR, dirlist_devices_virtual)
};


/*
 * Array of lookup functions, indexed by lx /sys file type.
 */
static vnode_t *(*lxsys_lookup_function[LXSYS_MAXTYPE])() = {
	NULL,					/* LXSYS_NONE		*/
	lxsys_lookup_static,			/* LXSYS_STATIC		*/
	lxsys_lookup_class_netdir,		/* LXSYS_CLASS_NET	*/
	lxsys_lookup_devices_virtual_netdir,	/* LXSYS_DEVICES_NET	*/
	lxsys_lookup_blockdir,			/* LXSYS_BLOCK		*/
	lxsys_lookup_devices_virtual_bdidir,	/* LXSYS_DEVICES_BDI	*/
	lxsys_lookup_devices_zfsdir,		/* LXSYS_DEVICES_ZFS	*/
};

/*
 * Array of readdir functions, indexed by /sys file type.
 */
static int (*lxsys_readdir_function[LXSYS_MAXTYPE])() = {
	NULL,					/* LXSYS_NONE		*/
	lxsys_readdir_static,			/* LXSYS_STATIC		*/
	lxsys_readdir_class_netdir,		/* LXSYS_CLASS_NET	*/
	lxsys_readdir_devices_virtual_netdir,	/* LXSYS_DEVICES_NET	*/
	lxsys_readdir_blockdir,			/* LXSYS_BLOCK		*/
	lxsys_readdir_devices_virtual_bdidir,	/* LXSYS_DEVICES_BDI	*/
	lxsys_readdir_devices_zfsdir,		/* LXSYS_DEVICES_ZFS	*/
};

/*
 * Array of read functions, indexed by /sys file type.
 */
static int (*lxsys_read_function[LXSYS_MAXTYPE])() = {
	NULL,					/* LXSYS_NONE		*/
	NULL,					/* LXSYS_STATIC		*/
	NULL,					/* LXSYS_CLASS_NET	*/
	lxsys_read_devices_virtual_net,		/* LXSYS_DEVICES_NET	*/
	NULL,					/* LXSYS_BLOCK		*/
	NULL,					/* LXSYS_DEVICES_BDI	*/
	lxsys_read_devices_zfs_block,		/* LXSYS_DEVICES_ZFS	*/
};

/*
 * Array of readlink functions, indexed by /sys file type.
 */
static int (*lxsys_readlink_function[LXSYS_MAXTYPE])() = {
	NULL,					/* LXSYS_NONE		*/
	NULL,					/* LXSYS_STATIC		*/
	lxsys_readlink_class_net,		/* LXSYS_CLASS_NET	*/
	NULL,					/* LXSYS_DEVICES_NET	*/
	lxsys_readlink_block,			/* LXSYS_BLOCK		*/
	NULL,					/* LXSYS_DEVICES_BDI	*/
	NULL,					/* LXSYS_DEVICES_ZFS	*/
};

typedef struct lxsys_zfs_ds {
	list_node_t	ds_link;
	char		ds_name[MAXPATHLEN];
	uint64_t	ds_cookie;
} lxsys_zfs_ds_t;

/*
 * Utility functions
 */
static void *
lxsys_kstat_read(kstat_t *kn, boolean_t byname, size_t *size, int *num)
{
	kstat_t *kp;
	int i, nrec = 0;
	size_t bufsize;
	void *buf = NULL;

	if (byname == B_TRUE) {
		kp = kstat_hold_byname(kn->ks_module, kn->ks_instance,
		    kn->ks_name, getzoneid());
	} else {
		kp = kstat_hold_bykid(kn->ks_kid, getzoneid());
	}
	if (kp == NULL) {
		return (NULL);
	}
	if (kp->ks_flags & KSTAT_FLAG_INVALID) {
		kstat_rele(kp);
		return (NULL);
	}

	bufsize = kp->ks_data_size + 1;
	kstat_rele(kp);

	/*
	 * The kstat in question is released so that kmem_alloc(KM_SLEEP) is
	 * performed without it held.  After the alloc, the kstat is reacquired
	 * and its size is checked again. If the buffer is no longer large
	 * enough, the alloc and check are repeated up to three times.
	 */
	for (i = 0; i < 2; i++) {
		buf = kmem_alloc(bufsize, KM_SLEEP);

		/* Check if bufsize still appropriate */
		if (byname == B_TRUE) {
			kp = kstat_hold_byname(kn->ks_module, kn->ks_instance,
			    kn->ks_name, getzoneid());
		} else {
			kp = kstat_hold_bykid(kn->ks_kid, getzoneid());
		}
		if (kp == NULL || kp->ks_flags & KSTAT_FLAG_INVALID) {
			if (kp != NULL) {
				kstat_rele(kp);
			}
			kmem_free(buf, bufsize);
			return (NULL);
		}
		KSTAT_ENTER(kp);
		(void) KSTAT_UPDATE(kp, KSTAT_READ);
		if (bufsize < kp->ks_data_size) {
			kmem_free(buf, bufsize);
			buf = NULL;
			bufsize = kp->ks_data_size + 1;
			KSTAT_EXIT(kp);
			kstat_rele(kp);
			continue;
		} else {
			if (KSTAT_SNAPSHOT(kp, buf, KSTAT_READ) != 0) {
				kmem_free(buf, bufsize);
				buf = NULL;
			}
			nrec = kp->ks_ndata;
			KSTAT_EXIT(kp);
			kstat_rele(kp);
			break;
		}
	}

	if (buf != NULL) {
		*size = bufsize;
		*num = nrec;
	}
	return (buf);
}

static int
lxsys_disk_instance(kstat_t *ksp)
{
	int result;

	/*
	 * Use a naive method to generate the 16-bit disk instance number for
	 * calculating the inode.  This is adequate when module and disk counts
	 * remain low.
	 *
	 * The high order bit in the 2nd byte indicates a zvol.
	 */
	result = (mod_name_to_major(ksp->ks_module) & 0x7f) << 8;
	result |= (ksp->ks_instance & 0xff);
	return (result);
}

static int
lxsys_zvol_instance(char *znm)
{
	int result;
	minor_t m;

	/*
	 * Use a naive method to generate the 16-bit disk instance number for
	 * calculating the inode. This is adequate when zvol counts remain low
	 * (< 32k).
	 *
	 * The high order bit in the 2nd byte indicates a zvol.
	 */
	result = 0x80 << 8;

	/*
	 * zvol_name2minor simplifies things here but the call won't succeed
	 * unless the minor has first been created, so we can't count on this.
	 */
	if (zvol_name2minor(znm, &m) != 0) {
		(void) zvol_create_minor(znm);
		if (zvol_name2minor(znm, &m) != 0)
			return (0);
	}

	result |= (m & 0xffff);
	return (result);
}

/*
 * lxsys_open(): Vnode operation for VOP_OPEN()
 */
static int
lxsys_open(vnode_t **vpp, int flag, cred_t *cr, caller_context_t *ct)
{
	/*
	 * We only allow reading in this file system
	 */
	if (flag & FWRITE)
		return (EROFS);

	return (0);
}


/*
 * lxsys_close(): Vnode operation for VOP_CLOSE()
 */
/* ARGSUSED */
static int
lxsys_close(vnode_t *vp, int flag, int count, offset_t offset, cred_t *cr,
    caller_context_t *ct)
{
	return (0);
}


/*
 * lxsys_read(): Vnode operation for VOP_READ()
 * All we currently have in this fs are directories.
 */
/* ARGSUSED */
static int
lxsys_read(vnode_t *vp, uio_t *uiop, int ioflag, cred_t *cr,
    caller_context_t *ct)
{
	lxsys_node_t *lnp = VTOLXS(vp);
	lxsys_nodetype_t type = lnp->lxsys_type;
	int (*rlfunc)();
	int error;
	lxsys_uiobuf_t *luio;

	VERIFY(type > LXSYS_NONE && type < LXSYS_MAXTYPE);

	if (vp->v_type == VDIR) {
		return (EISDIR);
	}

	rlfunc = lxsys_read_function[type];
	if (rlfunc != NULL) {
		luio = lxsys_uiobuf_new(uiop);
		if ((error = rlfunc(lnp, luio)) == 0) {
			error = lxsys_uiobuf_flush(luio);
		}
		lxsys_uiobuf_free(luio);
	} else {
		error = EIO;
	}

	return (error);
}

/*
 * lxsys_getattr(): Vnode operation for VOP_GETATTR()
 */
static int
lxsys_getattr(vnode_t *vp, vattr_t *vap, int flags, cred_t *cr,
    caller_context_t *ct)
{
	register lxsys_node_t *lxsnp = VTOLXS(vp);

	/* Default attributes, that may be overridden below */
	bzero(vap, sizeof (*vap));
	vap->va_atime = vap->va_mtime = vap->va_ctime = lxsnp->lxsys_time;
	vap->va_nlink = 1;
	vap->va_type = vp->v_type;
	vap->va_mode = lxsnp->lxsys_mode;
	vap->va_fsid = vp->v_vfsp->vfs_dev;
	vap->va_blksize = DEV_BSIZE;
	vap->va_uid = lxsnp->lxsys_uid;
	vap->va_gid = lxsnp->lxsys_gid;
	vap->va_nodeid = lxsnp->lxsys_ino;

	vap->va_nblocks = (fsblkcnt64_t)btod(vap->va_size);
	return (0);
}

/*
 * lxsys_access(): Vnode operation for VOP_ACCESS()
 */
static int
lxsys_access(vnode_t *vp, int mode, int flags, cred_t *cr, caller_context_t *ct)
{
	lxsys_node_t *lxsnp = VTOLXS(vp);
	int shift = 0;

	/*
	 * Although our lx sysfs is basically a read only file system, Linux
	 * expects it to be writable so we can't just error if (mode & VWRITE).
	 */

	/* If user is root allow access regardless of permission bits */
	if (secpolicy_proc_access(cr) == 0)
		return (0);

	/*
	 * Access check is based on only one of owner, group, public.  If not
	 * owner, then check group.  If not a member of the group, then check
	 * public access.
	 */
	if (crgetuid(cr) != lxsnp->lxsys_uid) {
		shift += 3;
		if (!groupmember((uid_t)lxsnp->lxsys_gid, cr))
			shift += 3;
	}

	mode &= ~(lxsnp->lxsys_mode << shift);

	if (mode == 0)
		return (0);

	return (EACCES);
}

/*
 * lxsys_lookup(): Vnode operation for VOP_LOOKUP()
 */
/* ARGSUSED */
static int
lxsys_lookup(vnode_t *dp, char *comp, vnode_t **vpp, pathname_t *pathp,
    int flags, vnode_t *rdir, cred_t *cr, caller_context_t *ct,
    int *direntflags, pathname_t *realpnp)
{
	lxsys_node_t *lxsnp = VTOLXS(dp);
	lxsys_nodetype_t type = lxsnp->lxsys_type;
	int error;

	VERIFY(dp->v_type == VDIR);
	VERIFY(type > LXSYS_NONE && type < LXSYS_MAXTYPE);

	/*
	 * restrict lookup permission to owner or root
	 */
	if ((error = lxsys_access(dp, VEXEC, 0, cr, ct)) != 0) {
		return (error);
	}

	/*
	 * Just return the parent vnode if that's where we are trying to go.
	 */
	if (strcmp(comp, "..") == 0) {
		VN_HOLD(lxsnp->lxsys_parentvp);
		*vpp = lxsnp->lxsys_parentvp;
		return (0);
	}

	/*
	 * Special handling for directory searches.  Note: null component name
	 * denotes that the current directory is being searched.
	 */
	if ((dp->v_type == VDIR) && (*comp == '\0' || strcmp(comp, ".") == 0)) {
		VN_HOLD(dp);
		*vpp = dp;
		return (0);
	}

	*vpp = (lxsys_lookup_function[type](lxsnp, comp));
	return ((*vpp == NULL) ? ENOENT : 0);
}

/* zvol basename to flatten namespace */
static char *
lxsys_zv_basename(char *ds_name)
{
	char *nm;

	if ((nm = strrchr(ds_name, '/')) != NULL) {
		nm++;
		ASSERT(*nm != '\0');
	} else {
		nm = ds_name;
	}

	return (nm);
}

/* Cleanup zvol list */
static int
lxsys_zvol_cleanup(list_t *zvol_lst)
{
	lxsys_zfs_ds_t *zv;
	int fnd = 0;

	zv = list_remove_head(zvol_lst);
	while (zv != NULL) {
		fnd = 1;
		kmem_free(zv, sizeof (lxsys_zfs_ds_t));
		zv = list_remove_head(zvol_lst);
	}

	list_destroy(zvol_lst);

	return (fnd);
}

static lxsys_node_t *
lxsys_lookup_disk(lxsys_node_t *ldp, char *comp, lxsys_nodetype_t type)
{
	kstat_t ks0, *ksr;
	int nidx, i;
	size_t sidx;
	lxsys_node_t *lnp = NULL;
	int inst;
	ldi_ident_t li = VTOLXSM(LXSTOV(ldp))->lxsysm_li;
	list_t	zvol_lst;
	lxsys_zfs_ds_t *zv;

	ks0.ks_kid = 0;
	ksr = (kstat_t *)lxsys_kstat_read(&ks0, B_FALSE, &sidx, &nidx);
	if (ksr == NULL) {
		return (NULL);
	}
	for (i = 1; i < nidx; i++) {
		kstat_t *ksp = &ksr[i];

		if (ksp->ks_type != KSTAT_TYPE_IO ||
		    strcmp(ksp->ks_class, "disk") != 0) {
			continue;
		}
		if (strncmp(ksp->ks_name, comp, KSTAT_STRLEN) == 0 &&
		    (inst = lxsys_disk_instance(ksp)) != 0) {
			lnp = lxsys_getnode(ldp->lxsys_vnode, type, inst, 0);
			break;
		}
	}
	kmem_free(ksr, sidx);

	if (lnp != NULL)
		return (lnp);

	/* try a zvol */
	list_create(&zvol_lst, sizeof (lxsys_zfs_ds_t),
	    offsetof(lxsys_zfs_ds_t, ds_link));

	lxsys_zfs_list_zvols(li, &zvol_lst);

	zv = list_remove_head(&zvol_lst);
	while (zv != NULL) {
		char *nm = lxsys_zv_basename(zv->ds_name);

		if (strcmp(nm, comp) == 0 &&
		    (inst = lxsys_zvol_instance(zv->ds_name)) != 0) {
			lnp = lxsys_getnode(ldp->lxsys_vnode, type, inst, 0);
			kmem_free(zv, sizeof (lxsys_zfs_ds_t));
			break;
		}

		kmem_free(zv, sizeof (lxsys_zfs_ds_t));
		zv = list_remove_head(&zvol_lst);
	}

	(void) lxsys_zvol_cleanup(&zvol_lst);

	return (lnp);
}

static vnode_t *
lxsys_lookup_static(lxsys_node_t *ldp, char *comp)
{
	lxsys_dirent_t *dirent = NULL;
	int i, len = 0;

	for (i = 0; i < SYSDIRLISTSZ(lxsys_dirlookup); i++) {
		if (ldp->lxsys_instance == lxsys_dirlookup[i].dl_instance) {
			dirent = lxsys_dirlookup[i].dl_list;
			len = lxsys_dirlookup[i].dl_length;
			break;
		}
	}
	if (dirent == NULL) {
		return (NULL);
	}

	for (i = 0; i < len; i++) {
		if (strncmp(comp, dirent[i].d_name, MAXPATHLEN) == 0) {
			lxsys_nodetype_t node_type = ldp->lxsys_type;
			unsigned int node_instance = 0;
			lxsys_node_t *lnp;

			switch (dirent[i].d_idnum) {
			case LXSYS_INST_BLOCKDIR:
				node_type = LXSYS_BLOCK;
				break;
			case LXSYS_INST_CLASS_NETDIR:
				node_type = LXSYS_CLASS_NET;
				break;
			case LXSYS_INST_DEVICES_VIRTUAL_NETDIR:
				node_type = LXSYS_DEVICES_NET;
				break;
			case LXSYS_INST_DEVICES_VIRTUAL_BDIDIR:
				node_type = LXSYS_DEVICES_BDI;
				break;
			case LXSYS_INST_DEVICES_ZFSDIR:
				node_type = LXSYS_DEVICES_ZFS;
				break;
			default:
				/* Another static node */
				node_instance = dirent[i].d_idnum;
			}
			if (node_type == LXSYS_STATIC) {
				lnp = lxsys_getnode_static(ldp->lxsys_vnode,
				    node_instance);
			} else {
				lnp = lxsys_getnode(ldp->lxsys_vnode,
				    node_type, node_instance, 0);
			}
			return (lnp->lxsys_vnode);
		}
	}
	return (NULL);
}

static vnode_t *
lxsys_lookup_class_netdir(lxsys_node_t *ldp, char *comp)
{
	vnode_t *result = NULL;
	lxsys_node_t *lnp;
	netstack_t *ns;
	ip_stack_t *ipst;
	avl_tree_t *phytree;
	phyint_t *phyi;
	char ifname[LIFNAMSIZ];

	if (ldp->lxsys_type != LXSYS_CLASS_NET ||
	    ldp->lxsys_instance != 0) {
		/* Lookups only allowed at directory level */
		return (NULL);
	}

	(void) strncpy(ifname, comp, LIFNAMSIZ);
	lx_ifname_convert(ifname, LX_IF_TONATIVE);

	if ((ns = lxsys_netstack(ldp)) == NULL) {
		return (NULL);
	}
	ipst = ns->netstack_ip;
	rw_enter(&ipst->ips_ill_g_lock, RW_READER);

	phytree = &ipst->ips_phyint_g_list->phyint_list_avl_by_name;
	phyi = avl_find(phytree, ifname, NULL);
	if (phyi != NULL) {
		lnp = lxsys_getnode(ldp->lxsys_vnode, ldp->lxsys_type,
		    phyi->phyint_ifindex, 0);
		result = lnp->lxsys_vnode;
		result->v_type = VLNK;
	}

	rw_exit(&ipst->ips_ill_g_lock);
	netstack_rele(ns);

	return (result);
}

static vnode_t *
lxsys_lookup_devices_virtual_netdir(lxsys_node_t *ldp, char *comp)
{
	lxsys_node_t *lnp;

	if (ldp->lxsys_instance == 0) {
		/* top-level interface listing */
		vnode_t *result = NULL;
		netstack_t *ns;
		ip_stack_t *ipst;
		avl_tree_t *phytree;
		phyint_t *phyi;
		char ifname[LIFNAMSIZ];

		(void) strncpy(ifname, comp, LIFNAMSIZ);
		lx_ifname_convert(ifname, LX_IF_TONATIVE);

		if ((ns = lxsys_netstack(ldp)) == NULL) {
			return (NULL);
		}
		ipst = ns->netstack_ip;
		rw_enter(&ipst->ips_ill_g_lock, RW_READER);

		phytree = &ipst->ips_phyint_g_list->phyint_list_avl_by_name;
		phyi = avl_find(phytree, ifname, NULL);
		if (phyi != NULL) {
			lnp = lxsys_getnode(ldp->lxsys_vnode, ldp->lxsys_type,
			    phyi->phyint_ifindex, 0);
			result = lnp->lxsys_vnode;
		}

		rw_exit(&ipst->ips_ill_g_lock);
		netstack_rele(ns);

		return (result);
	} else if (ldp->lxsys_endpoint == 0) {
		/* interface-level sub-item listing */
		int i, size;
		lxsys_dirent_t *dirent;

		size = SYSDIRLISTSZ(dirlist_devices_virtual_net);
		for (i = 0; i < size; i++) {
			dirent = &dirlist_devices_virtual_net[i];
			if (strncmp(comp, dirent->d_name, LXSNSIZ) == 0) {
				lnp = lxsys_getnode(ldp->lxsys_vnode,
				    ldp->lxsys_type, ldp->lxsys_instance,
				    dirent->d_idnum);
				lnp->lxsys_vnode->v_type = VREG;
				lnp->lxsys_mode = 0444;
				return (lnp->lxsys_vnode);
			}
		}
	}

	return (NULL);
}

static vnode_t *
lxsys_lookup_blockdir(lxsys_node_t *ldp, char *comp)
{
	lxsys_node_t *lnp;

	if (ldp->lxsys_instance == 0) {
		/* top-level dev listing */
		lnp = lxsys_lookup_disk(ldp, comp, LXSYS_BLOCK);

		if (lnp != NULL) {
			lnp->lxsys_vnode->v_type = VLNK;
			return (lnp->lxsys_vnode);
		}
	}

	return (NULL);
}

static vnode_t *
lxsys_lookup_devices_virtual_bdidir(lxsys_node_t *ldp, char *comp)
{
	lxsys_node_t *lnp;

	if (ldp->lxsys_instance == 0) {
		/* top-level dev listing */
		lnp = lxsys_lookup_disk(ldp, comp, LXSYS_DEVICES_BDI);

		if (lnp != NULL) {
			return (lnp->lxsys_vnode);
		}
	}

	return (NULL);
}

static vnode_t *
lxsys_lookup_devices_zfsdir(lxsys_node_t *ldp, char *comp)
{
	lxsys_node_t *lnp;

	if (ldp->lxsys_instance == 0) {
		/* top-level dev listing */
		lnp = lxsys_lookup_disk(ldp, comp, LXSYS_DEVICES_ZFS);

		if (lnp != NULL) {
			return (lnp->lxsys_vnode);
		}
	} else if (ldp->lxsys_endpoint == 0) {
		/* disk-level sub-item listing */
		int i, size;
		lxsys_dirent_t *dirent;

		/*
		 * All of these entries currently look like regular files
		 * but on a real Linux system some will be subdirs. This should
		 * be fixed when we populate the directory for real.
		 */
		size = SYSDIRLISTSZ(dirlist_devices_zfs_block);
		for (i = 0; i < size; i++) {
			dirent = &dirlist_devices_zfs_block[i];
			if (strncmp(comp, dirent->d_name, LXSNSIZ) == 0) {
				lnp = lxsys_getnode(ldp->lxsys_vnode,
				    ldp->lxsys_type, ldp->lxsys_instance,
				    dirent->d_idnum);
				lnp->lxsys_vnode->v_type = VREG;
				lnp->lxsys_mode = 0444;
				return (lnp->lxsys_vnode);
			}
		}
	}

	return (NULL);
}

static int
lxsys_read_devices_virtual_net(lxsys_node_t *lnp, lxsys_uiobuf_t *luio)
{
	netstack_t *ns;
	ill_t *ill;
	uint_t ifindex = lnp->lxsys_instance;
	uint8_t *addr;
	uint64_t flags;
	int error = 0;

	if (ifindex == 0 || lnp->lxsys_endpoint == 0) {
		return (EISDIR);
	}

	if ((ns = lxsys_netstack(lnp)) == NULL) {
		return (EIO);
	}

	ill = lxsys_find_ill(ns->netstack_ip, ifindex);
	if (ill == NULL) {
		netstack_rele(ns);
		return (EIO);
	}

	switch (lnp->lxsys_endpoint) {
	case LXSYS_ENDP_NET_ADDRESS:
		if (ill->ill_phys_addr_length != ETHERADDRL) {
			lxsys_uiobuf_printf(luio, "00:00:00:00:00:00\n");
			break;
		}
		addr = ill->ill_phys_addr;
		lxsys_uiobuf_printf(luio,
		    "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n",
		    addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
		break;
	case LXSYS_ENDP_NET_ADDRLEN:
		lxsys_uiobuf_printf(luio, "%u\n",
		    IS_LOOPBACK(ill) ? ETHERADDRL : ill->ill_phys_addr_length);
		break;
	case LXSYS_ENDP_NET_FLAGS:
		flags = (ill->ill_flags | ill->ill_ipif->ipif_flags |
		    ill->ill_phyint->phyint_flags) & 0xffff;
		lx_ifflags_convert(&flags, LX_IF_FROMNATIVE);
		lxsys_uiobuf_printf(luio, "0x%x\n", flags);
		break;
	case LXSYS_ENDP_NET_IFINDEX:
		lxsys_uiobuf_printf(luio, "%u\n", ifindex);
		break;
	case LXSYS_ENDP_NET_MTU:
		lxsys_uiobuf_printf(luio, "%u\n", ill->ill_mtu);
		break;
	case LXSYS_ENDP_NET_TXQLEN:
		/* perpetuate the txqlen lie */
		if (IS_LOOPBACK(ill)) {
			lxsys_uiobuf_printf(luio, "0\n");
		} else {
			lxsys_uiobuf_printf(luio, "1\n");
		}
		break;
	case LXSYS_ENDP_NET_TYPE:
		lxsys_uiobuf_printf(luio, "%u\n",
		    IS_LOOPBACK(ill) ? LX_ARPHRD_LOOPBACK :
		    arp_hw_type(ill->ill_mactype));
		break;
	default:
		error = EIO;
	}

	ill_refrele(ill);
	netstack_rele(ns);
	return (error);
}

static int
lxsys_read_devices_zfs_block(lxsys_node_t *lnp, lxsys_uiobuf_t *luio)
{
	uint_t dskindex = lnp->lxsys_instance;

	if (dskindex == 0 || lnp->lxsys_endpoint == 0) {
		return (EISDIR);
	}

	return (EIO);
}
/*
 * lxsys_readdir(): Vnode operation for VOP_READDIR()
 */
/* ARGSUSED */
static int
lxsys_readdir(vnode_t *dp, uio_t *uiop, cred_t *cr, int *eofp,
    caller_context_t *ct, int flags)
{
	lxsys_node_t *lxsnp = VTOLXS(dp);
	lxsys_nodetype_t type = lxsnp->lxsys_type;
	ssize_t uresid;
	off_t uoffset;
	int error, leof;

	ASSERT(dp->v_type == VDIR);
	VERIFY(type > LXSYS_NONE && type < LXSYS_MAXTYPE);

	/*
	 * restrict readdir permission to owner or root
	 */
	if ((error = lxsys_access(dp, VREAD, 0, cr, ct)) != 0)
		return (error);

	uoffset = uiop->uio_offset;
	uresid = uiop->uio_resid;

	/* can't do negative reads */
	if (uoffset < 0 || uresid <= 0)
		return (EINVAL);

	/* can't read directory entries that don't exist! */
	if (uoffset % LXSYS_SDSIZE)
		return (ENOENT);

	/* Free lower functions from having to check eofp == NULL */
	if (eofp == NULL) {
		eofp = &leof;
	}

	return (lxsys_readdir_function[lxsnp->lxsys_type](lxsnp, uiop, eofp));
}

static int
lxsys_dirent_out(dirent64_t *d, ushort_t n, struct uio *uio)
{
	int error;
	off_t offset = uio->uio_offset;

	/*
	 * uiomove() updates both uiop->uio_resid and uiop->uio_offset by the
	 * same amount.  But we want uiop->uio_offset to change in increments
	 * of LXSYS_SDSIZE, which is different from the number of bytes being
	 * returned to the user.  To accomplish this, we set uiop->uio_offset
	 * separately on success, overriding what uiomove() does.
	 */
	d->d_off = (off64_t)(offset + LXSYS_SDSIZE);
	d->d_reclen = n;
	if ((error = uiomove(d, n, UIO_READ, uio)) != 0) {
		return (error);
	}
	uio->uio_offset = offset + LXSYS_SDSIZE;
	return (0);
}

/*
 * This has the common logic for returning directory entries
 */
static int
lxsys_readdir_common(lxsys_node_t *lxsnp, uio_t *uiop, int *eofp,
    lxsys_dirent_t *dirtab, int dirtablen)
{
	/* bp holds one dirent64 structure */
	longlong_t bp[DIRENT64_RECLEN(LXSNSIZ) / sizeof (longlong_t)];
	dirent64_t *dirent = (dirent64_t *)bp;
	ssize_t oresid;	/* save a copy for testing later */
	ssize_t uresid;

	oresid = uiop->uio_resid;

	/* clear out the dirent buffer */
	bzero(bp, sizeof (bp));

	/* Satisfy user request */
	while ((uresid = uiop->uio_resid) > 0) {
		int dirindex;
		off_t uoffset;
		int reclen;
		int error;

		uoffset = uiop->uio_offset;
		dirindex  = (uoffset / LXSYS_SDSIZE) - 2;

		if (uoffset == 0) {

			dirent->d_ino = lxsnp->lxsys_ino;
			dirent->d_name[0] = '.';
			dirent->d_name[1] = '\0';
			reclen = DIRENT64_RECLEN(1);

		} else if (uoffset == LXSYS_SDSIZE) {

			dirent->d_ino = lxsys_parentinode(lxsnp);
			dirent->d_name[0] = '.';
			dirent->d_name[1] = '.';
			dirent->d_name[2] = '\0';
			reclen = DIRENT64_RECLEN(2);

		} else if (dirindex >= 0 && dirindex < dirtablen) {

			int slen = strlen(dirtab[dirindex].d_name);

			dirent->d_ino = lxsys_inode(LXSYS_STATIC,
			    dirtab[dirindex].d_idnum, 0);
			(void) strcpy(dirent->d_name, dirtab[dirindex].d_name);
			reclen = DIRENT64_RECLEN(slen);

		} else {
			/* Run out of table entries */
			*eofp = 1;
			return (0);
		}

		/*
		 * If the size of the data to transfer is greater than the
		 * user-provided buffer, we cannot continue.
		 */
		if (reclen > uresid) {
			/* Error if no entries have been returned yet. */
			if (uresid == oresid) {
				return (EINVAL);
			}
			break;
		}

		if ((error = lxsys_dirent_out(dirent, reclen, uiop)) != 0) {
			return (error);
		}
	}

	/* Have run out of space, but could have just done last table entry */
	*eofp = (uiop->uio_offset >= ((dirtablen+2) * LXSYS_SDSIZE)) ?  1 : 0;
	return (0);
}

static int
lxsys_readdir_subdir(lxsys_node_t *lxsnp, uio_t *uiop, int *eofp,
    lxsys_dirent_t *dirtab, int dirtablen)
{
	/* bp holds one dirent64 structure */
	longlong_t bp[DIRENT64_RECLEN(LXSNSIZ) / sizeof (longlong_t)];
	dirent64_t *dirent = (dirent64_t *)bp;
	ssize_t oresid;	/* save a copy for testing later */
	ssize_t uresid;

	oresid = uiop->uio_resid;

	/* clear out the dirent buffer */
	bzero(bp, sizeof (bp));

	/* Satisfy user request */
	while ((uresid = uiop->uio_resid) > 0) {
		int dirindex;
		off_t uoffset;
		int reclen;
		int error;

		uoffset = uiop->uio_offset;
		dirindex  = (uoffset / LXSYS_SDSIZE) - 2;

		if (uoffset == 0) {

			dirent->d_ino = lxsnp->lxsys_ino;
			dirent->d_name[0] = '.';
			dirent->d_name[1] = '\0';
			reclen = DIRENT64_RECLEN(1);

		} else if (uoffset == LXSYS_SDSIZE) {

			dirent->d_ino = lxsys_parentinode(lxsnp);
			dirent->d_name[0] = '.';
			dirent->d_name[1] = '.';
			dirent->d_name[2] = '\0';
			reclen = DIRENT64_RECLEN(2);

		} else if (dirindex >= 0 && dirindex < dirtablen) {

			int slen = strlen(dirtab[dirindex].d_name);

			dirent->d_ino = lxsys_inode(lxsnp->lxsys_type,
			    lxsnp->lxsys_instance, dirtab[dirindex].d_idnum);
			(void) strcpy(dirent->d_name, dirtab[dirindex].d_name);
			reclen = DIRENT64_RECLEN(slen);

		} else {
			/* Run out of table entries */
			*eofp = 1;
			return (0);
		}

		/*
		 * If the size of the data to transfer is greater than the
		 * user-provided buffer, we cannot continue.
		 */
		if (reclen > uresid) {
			/* Error if no entries have been returned yet. */
			if (uresid == oresid) {
				return (EINVAL);
			}
			break;
		}

		if ((error = lxsys_dirent_out(dirent, reclen, uiop)) != 0) {
			return (error);
		}
	}

	/* Have run out of space, but could have just done last table entry */
	*eofp = (uiop->uio_offset >= ((dirtablen+2) * LXSYS_SDSIZE)) ?  1 : 0;
	return (0);
}

static int
lxsys_readdir_ifaces(lxsys_node_t *ldp, struct uio *uiop, int *eofp,
    lxsys_nodetype_t type)
{
	longlong_t bp[DIRENT64_RECLEN(LXSNSIZ) / sizeof (longlong_t)];
	dirent64_t *dirent = (dirent64_t *)bp;
	ssize_t oresid, uresid;
	netstack_t *ns;
	ip_stack_t *ipst;
	avl_tree_t *phytree;
	phyint_t *phyi;
	int error, i;


	/* Emit "." and ".." entries */
	oresid = uiop->uio_resid;
	error = lxsys_readdir_common(ldp, uiop, eofp, NULL, 0);
	if (error != 0 || *eofp == 0) {
		return (error);
	}

	if ((ns = lxsys_netstack(ldp)) == NULL) {
		*eofp = 1;
		return (0);
	}
	ipst = ns->netstack_ip;

	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	phytree = &ipst->ips_phyint_g_list->phyint_list_avl_by_index;
	phyi = avl_first(phytree);
	if (phyi == NULL) {
		*eofp = 1;
	}
	bzero(bp, sizeof (bp));

	/*
	 * Skip records we have already passed with the offset.
	 * This accounts for the two "." and ".." records already seen.
	 */
	for (i = (uiop->uio_offset/LXSYS_SDSIZE) - 2; i > 0; i--) {
		if ((phyi = avl_walk(phytree, phyi, AVL_AFTER)) == NULL) {
			*eofp = 1;
			break;
		}
	}

	while ((uresid = uiop->uio_resid) > 0 && phyi != NULL) {
		uint_t ifindex;
		int reclen;

		ifindex = phyi->phyint_ifindex;
		(void) strncpy(dirent->d_name, phyi->phyint_name, LIFNAMSIZ);
		lx_ifname_convert(dirent->d_name, LX_IF_FROMNATIVE);
		dirent->d_ino = lxsys_inode(type, ifindex, 0);
		reclen = DIRENT64_RECLEN(strlen(dirent->d_name));

		if (reclen > uresid) {
			if (uresid == oresid) {
				/* Not enough space for one record */
				error = EINVAL;
			}
			break;
		}
		if ((error = lxsys_dirent_out(dirent, reclen, uiop)) != 0) {
			break;
		}

		if ((phyi = avl_walk(phytree, phyi, AVL_AFTER)) == NULL) {
			*eofp = 1;
			break;
		}
	}

	rw_exit(&ipst->ips_ill_g_lock);
	netstack_rele(ns);
	return (error);
}

static int
lxsys_zfs_ioctl(ldi_handle_t lh, int cmd, zfs_cmd_t *zc, size_t *dst_alloc_size)
{
	uint64_t	cookie;
	size_t		dstsize = 8192;
	int		rc, unused;

	cookie = zc->zc_cookie;

again:
	zc->zc_nvlist_dst = (uint64_t)(intptr_t)kmem_alloc(dstsize, KM_SLEEP);
	zc->zc_nvlist_dst_size = dstsize;

	rc = ldi_ioctl(lh, cmd, (intptr_t)zc, FKIOCTL, kcred, &unused);
	if (rc == ENOMEM) {
		/*
		 * Our nvlist_dst buffer was too small, retry with a bigger
		 * buffer. ZFS will tell us the exact needed size.
		 */
		size_t newsize = zc->zc_nvlist_dst_size;
		ASSERT(newsize > dstsize);

		kmem_free((void *)(uintptr_t)zc->zc_nvlist_dst, dstsize);
		dstsize = newsize;
		zc->zc_cookie = cookie;

		goto again;
	}

	if (dst_alloc_size != NULL) {
		*dst_alloc_size = dstsize;
	} else {
		/* Caller didn't want the nvlist_dst anyway */
		kmem_free((void *)(uintptr_t)zc->zc_nvlist_dst, dstsize);
		zc->zc_nvlist_dst = NULL;
	}

	return (rc);
}

static void
lxsys_zfs_list_zvols(ldi_ident_t li, list_t *zvol_lst)
{
	int	rc;
	size_t	size;
	ldi_handle_t lh;
	dev_t zfs_dv;
	zfs_cmd_t *zc;
	nvpair_t *elem = NULL;
	nvlist_t *pnv = NULL;
	list_t	ds_lst;

	if (ldi_open_by_name("/dev/zfs", FREAD | FWRITE, kcred, &lh, li) != 0)
		return;

	if (ldi_get_dev(lh, &zfs_dv) != 0) {
		ldi_close(lh, FREAD|FWRITE, kcred);
		return;
	}

	zc = kmem_zalloc(sizeof (zfs_cmd_t), KM_SLEEP);
	bzero(zc, sizeof (zfs_cmd_t));

	rc = lxsys_zfs_ioctl(lh, ZFS_IOC_POOL_CONFIGS, zc, &size);
	if (rc != 0)
		goto out;

	ASSERT(zc->zc_cookie > 0);

	rc = nvlist_unpack((char *)(uintptr_t)zc->zc_nvlist_dst,
	    zc->zc_nvlist_dst_size, &pnv, 0);

	kmem_free((void *)(uintptr_t)zc->zc_nvlist_dst, size);

	if (rc != 0)
		goto out;

	/*
	 * We use a dataset list to process all of the datasets in the pool
	 * without doing recursion so that we don't risk blowing the kernel
	 * stack.
	 */
	list_create(&ds_lst, sizeof (lxsys_zfs_ds_t),
	    offsetof(lxsys_zfs_ds_t, ds_link));

	while ((elem = nvlist_next_nvpair(pnv, elem)) != NULL) {
		lxsys_zfs_ds_t *ds;

		ds = kmem_zalloc(sizeof (lxsys_zfs_ds_t), KM_SLEEP);
		(void) strcpy(ds->ds_name, nvpair_name(elem));

		list_insert_head(&ds_lst, ds);

		while (ds != NULL) {
			bzero(zc, sizeof (zfs_cmd_t));
			zc->zc_cookie = ds->ds_cookie;
			(void) strcpy(zc->zc_name, ds->ds_name);

			rc = lxsys_zfs_ioctl(lh, ZFS_IOC_DATASET_LIST_NEXT, zc,
			    NULL);

			/* Update the cookie before doing anything else. */
			ds->ds_cookie = zc->zc_cookie;

			if (rc != 0) {
				list_remove(&ds_lst, ds);
				kmem_free(ds, sizeof (lxsys_zfs_ds_t));
				ds = list_tail(&ds_lst);
				continue;
			}

			/* Reserved internal names, skip over these. */
			if (strchr(zc->zc_name, '$') != NULL ||
			    strchr(zc->zc_name, '%') != NULL)
				continue;

			if (zc->zc_objset_stats.dds_type == DMU_OST_ZVOL) {
				/* add it to the zvol list */
				lxsys_zfs_ds_t *zv;

				zv = kmem_zalloc(sizeof (lxsys_zfs_ds_t),
				    KM_SLEEP);
				(void) strcpy(zv->ds_name, zc->zc_name);
				list_insert_tail(zvol_lst, zv);
			} else {
				lxsys_zfs_ds_t *nds;

				/* Create a new ds_t for the child. */
				nds = kmem_zalloc(sizeof (lxsys_zfs_ds_t),
				    KM_SLEEP);
				(void) strcpy(nds->ds_name, zc->zc_name);
				list_insert_after(&ds_lst, ds, nds);

				/* Depth-first, so do the one just created. */
				ds = nds;
			}
		}

		ASSERT(list_is_empty(&ds_lst));
	}

	ASSERT(list_is_empty(&ds_lst));
	list_destroy(&ds_lst);

out:
	nvlist_free(pnv);
	ldi_close(lh, FREAD|FWRITE, kcred);
	kmem_free(zc, sizeof (zfs_cmd_t));
}

static int
lxsys_readdir_disks(lxsys_node_t *ldp, struct uio *uiop, int *eofp,
    lxsys_nodetype_t type)
{
	longlong_t bp[DIRENT64_RECLEN(LXSNSIZ) / sizeof (longlong_t)];
	dirent64_t *dirent = (dirent64_t *)bp;
	ssize_t oresid, uresid;
	kstat_t ks0, *ksr;
	int nidx, i, skip, error;
	size_t sidx;
	int reclen;
	uint_t instance;
	ldi_ident_t li = VTOLXSM(LXSTOV(ldp))->lxsysm_li;
	list_t	zvol_lst;
	lxsys_zfs_ds_t *zv;
	boolean_t zv_done;

	/* Emit "." and ".." entries */
	oresid = uiop->uio_resid;
	error = lxsys_readdir_common(ldp, uiop, eofp, NULL, 0);
	if (error != 0 || *eofp == 0) {
		return (error);
	}

	skip = (uiop->uio_offset/LXSYS_SDSIZE) - 2;
	i = nidx = 0;

	/*
	 * We show all disks (virtual and physical) for LXSYS_BLOCK, only
	 * virtual disks for LXSYS_DEVICES_BDI and only physical disks for
	 * LXSYS_DEVICES_ZFS.
	 */
	if (type == LXSYS_DEVICES_ZFS)
		goto zvols;

	ks0.ks_kid = 0;
	ksr = (kstat_t *)lxsys_kstat_read(&ks0, B_FALSE, &sidx, &nidx);
	if (ksr == NULL) {
		*eofp = 1;
		return (0);
	}
	for (i = 1; i < nidx; i++) {
		kstat_t *ksp = &ksr[i];

		if (ksp->ks_type != KSTAT_TYPE_IO ||
		    strcmp(ksp->ks_class, "disk") != 0) {
			continue;
		}
		if ((instance = lxsys_disk_instance(ksp)) == 0) {
			continue;
		}
		if (skip > 0) {
			skip--;
			continue;
		}

		(void) strncpy(dirent->d_name, ksp->ks_name, KSTAT_STRLEN);
		dirent->d_ino = lxsys_inode(type, instance, 0);
		reclen = DIRENT64_RECLEN(strlen(dirent->d_name));

		uresid = uiop->uio_resid;
		if (reclen > uresid) {
			if (uresid == oresid) {
				/* Not enough space for one record */
				error = EINVAL;
			}
			break;
		}
		if ((error = lxsys_dirent_out(dirent, reclen, uiop)) != 0) {
			break;
		}
	}

	kmem_free(ksr, sidx);

zvols:
	zv_done = B_TRUE;
	if (type == LXSYS_DEVICES_BDI)
		goto done;

	list_create(&zvol_lst, sizeof (lxsys_zfs_ds_t),
	    offsetof(lxsys_zfs_ds_t, ds_link));

	lxsys_zfs_list_zvols(li, &zvol_lst);

	zv = list_remove_head(&zvol_lst);
	while (zv != NULL) {
		char *nm;

		if (skip > 0) {
			skip--;
			kmem_free(zv, sizeof (lxsys_zfs_ds_t));
			zv = list_remove_head(&zvol_lst);
			continue;
		}

		nm = lxsys_zv_basename(zv->ds_name);
		if (strlen(nm) > LXSNSIZ) {
			kmem_free(zv, sizeof (lxsys_zfs_ds_t));
			zv = list_remove_head(&zvol_lst);
			continue;
		}

		(void) strncpy(dirent->d_name, nm, LXSNSIZ);
		instance = lxsys_zvol_instance(zv->ds_name);
		if (instance == 0) {
			kmem_free(zv, sizeof (lxsys_zfs_ds_t));
			zv = list_remove_head(&zvol_lst);
			continue;
		}

		kmem_free(zv, sizeof (lxsys_zfs_ds_t));

		dirent->d_ino = lxsys_inode(type, instance, 0);
		reclen = DIRENT64_RECLEN(strlen(dirent->d_name));

		uresid = uiop->uio_resid;
		if (reclen > uresid) {
			if (uresid == oresid) {
				/* Not enough space for one record */
				error = EINVAL;
			}
			break;
		}
		if ((error = lxsys_dirent_out(dirent, reclen, uiop)) != 0) {
			break;
		}

		zv = list_remove_head(&zvol_lst);
	}

	if (lxsys_zvol_cleanup(&zvol_lst) != 0)
		zv_done = B_FALSE;	/* we didn't process all of them */

done:
	/* Indicate EOF if we reached the end of the kstats and zvols. */
	if (i >= nidx && zv_done) {
		*eofp = 1;
	}

	return (error);
}


static int
lxsys_readdir_static(lxsys_node_t *lnp, uio_t *uiop, int *eofp)
{
	lxsys_dirent_t *dirent = NULL;
	int i, len = 0;

	for (i = 0; i < SYSDIRLISTSZ(lxsys_dirlookup); i++) {
		if (lnp->lxsys_instance == lxsys_dirlookup[i].dl_instance) {
			dirent = lxsys_dirlookup[i].dl_list;
			len = lxsys_dirlookup[i].dl_length;
			break;
		}
	}

	if (dirent == NULL) {
		return (ENOTDIR);
	}

	return (lxsys_readdir_common(lnp, uiop, eofp, dirent, len));
}

static int
lxsys_readdir_class_netdir(lxsys_node_t *lnp, uio_t *uiop, int *eofp)
{
	if (lnp->lxsys_type != LXSYS_CLASS_NET ||
	    lnp->lxsys_instance != 0) {
		/*
		 * Since /sys/class/net contains only symlinks, readdir
		 * operations should not be performed anywhere except the top
		 * level (instance == 0).
		 */
		return (ENOTDIR);
	}

	return (lxsys_readdir_ifaces(lnp, uiop, eofp, LXSYS_CLASS_NET));
}

static int
lxsys_readdir_devices_virtual_netdir(lxsys_node_t *lnp, uio_t *uiop, int *eofp)
{
	int error;

	if (lnp->lxsys_instance == 0) {
		/* top-level interface listing */
		error = lxsys_readdir_ifaces(lnp, uiop, eofp,
		    LXSYS_DEVICES_NET);
	} else if (lnp->lxsys_endpoint == 0) {
		/* interface-level sub-item listing */
		error = lxsys_readdir_subdir(lnp, uiop, eofp,
		    dirlist_devices_virtual_net,
		    SYSDIRLISTSZ(dirlist_devices_virtual_net));
	} else {
		/* there shouldn't be subdirs below this */
		error = ENOTDIR;
	}

	return (error);
}

static int
lxsys_readdir_blockdir(lxsys_node_t *lnp, uio_t *uiop, int *eofp)
{
	if (lnp->lxsys_type != LXSYS_BLOCK ||
	    lnp->lxsys_instance != 0) {
		/*
		 * Since /sys/block contains only symlinks, readdir operations
		 * should not be performed anywhere except the top level
		 * (instance == 0).
		 */
		return (ENOTDIR);
	}

	return (lxsys_readdir_disks(lnp, uiop, eofp, LXSYS_BLOCK));
}

static int
lxsys_readdir_devices_virtual_bdidir(lxsys_node_t *lnp, uio_t *uiop, int *eofp)
{
	int error;

	if (lnp->lxsys_instance == 0) {
		/* top-level dev listing */
		error = lxsys_readdir_disks(lnp, uiop, eofp,
		    LXSYS_DEVICES_BDI);
	} else if (lnp->lxsys_endpoint == 0) {
		/* disk-level sub-item listing (empty for now) */
		error = lxsys_readdir_subdir(lnp, uiop, eofp, NULL, 0);
	} else {
		/* there shouldn't be subdirs below this */
		error = ENOTDIR;
	}

	return (error);
}

static int
lxsys_readdir_devices_zfsdir(lxsys_node_t *lnp, uio_t *uiop, int *eofp)
{
	int error;

	if (lnp->lxsys_instance == 0) {
		/* top-level dev listing */
		error = lxsys_readdir_disks(lnp, uiop, eofp,
		    LXSYS_DEVICES_ZFS);
	} else if (lnp->lxsys_endpoint == 0) {
		/* disk-level sub-item listing */
		error = lxsys_readdir_subdir(lnp, uiop, eofp,
		    dirlist_devices_zfs_block,
		    SYSDIRLISTSZ(dirlist_devices_zfs_block));
	} else {
		/*
		 * Currently there shouldn't be subdirs below this but
		 * on a real Linux system some will be subdirs. This should
		 * be fixed when we populate the directory for real.
		 */
		error = ENOTDIR;
	}

	return (error);
}

/*
 * lxsys_readlink(): Vnode operation for VOP_READLINK()
 */
/* ARGSUSED */
static int
lxsys_readlink(vnode_t *vp, uio_t *uiop, cred_t *cr, caller_context_t *ct)
{
	char buf[MAXPATHLEN + 1];
	lxsys_node_t *lnp = VTOLXS(vp);
	lxsys_nodetype_t type = lnp->lxsys_type;
	int (*rlfunc)();
	int error;

	VERIFY(type > LXSYS_NONE && type < LXSYS_MAXTYPE);

	if (vp->v_type != VLNK) {
		return (EINVAL);
	}

	rlfunc = lxsys_readlink_function[lnp->lxsys_type];
	if (rlfunc != NULL) {
		if ((error = rlfunc(lnp, buf, sizeof (buf))) == 0) {
			error = uiomove(buf, strlen(buf), UIO_READ, uiop);
		}
	} else {
		error = EINVAL;
	}

	return (error);
}


static int
lxsys_readlink_class_net(lxsys_node_t *lnp, char *buf, size_t len)
{
	netstack_t *ns;
	ip_stack_t *ipst;
	avl_tree_t *phytree;
	phyint_t *phyi;
	uint_t ifindex;
	char ifname[LIFNAMSIZ];
	int error = EINVAL;

	if ((ifindex = lnp->lxsys_instance) == 0) {
		return (error);
	}

	if ((ns = lxsys_netstack(lnp)) == NULL) {
		return (error);
	}
	ipst = ns->netstack_ip;
	rw_enter(&ipst->ips_ill_g_lock, RW_READER);

	phytree = &ipst->ips_phyint_g_list->phyint_list_avl_by_index;
	phyi = avl_find(phytree, &ifindex, NULL);
	if (phyi != NULL) {
		(void) strncpy(ifname, phyi->phyint_name, LIFNAMSIZ);
		lx_ifname_convert(ifname, LX_IF_FROMNATIVE);
		(void) snprintf(buf, len, "/sys/devices/virtual/net/%s",
		    ifname);
		error = 0;
	}

	rw_exit(&ipst->ips_ill_g_lock);
	netstack_rele(ns);
	return (error);
}

static int
lxsys_readlink_block(lxsys_node_t *lnp, char *buf, size_t len)
{
	kstat_t *ksr;
	kstat_t ks0;
	int nidx, i, inst, error = EINVAL;
	size_t sidx;
	ldi_ident_t li = VTOLXSM(LXSTOV(lnp))->lxsysm_li;
	list_t	zvol_lst;
	lxsys_zfs_ds_t *zv;

	if ((inst = lnp->lxsys_instance) == 0) {
		return (error);
	}

	ks0.ks_kid = 0;
	ksr = (kstat_t *)lxsys_kstat_read(&ks0, B_FALSE, &sidx, &nidx);
	if (ksr == NULL) {
		return (error);
	}
	for (i = 1; i < nidx; i++) {
		kstat_t *ksp = &ksr[i];

		if (ksp->ks_type != KSTAT_TYPE_IO ||
		    strcmp(ksp->ks_class, "disk") != 0) {
			continue;
		}
		if (lxsys_disk_instance(ksp) == inst) {
			(void) snprintf(buf, len,
			    "../devices/virtual/bdi/%s", ksp->ks_name);
			error = 0;
			break;
		}
	}
	kmem_free(ksr, sidx);

	if (error == 0)
		return (0);

	/* try a zvol */
	list_create(&zvol_lst, sizeof (lxsys_zfs_ds_t),
	    offsetof(lxsys_zfs_ds_t, ds_link));

	lxsys_zfs_list_zvols(li, &zvol_lst);

	zv = list_remove_head(&zvol_lst);
	while (zv != NULL) {
		if (lxsys_zvol_instance(zv->ds_name) == inst) {
			char *nm = lxsys_zv_basename(zv->ds_name);

			(void) snprintf(buf, len,
			    "../devices/zfs/%s", nm);
			error = 0;
			kmem_free(zv, sizeof (lxsys_zfs_ds_t));
			break;
		}

		kmem_free(zv, sizeof (lxsys_zfs_ds_t));
		zv = list_remove_head(&zvol_lst);
	}

	(void) lxsys_zvol_cleanup(&zvol_lst);

	return (error);
}

/*
 * lxsys_inactive(): Vnode operation for VOP_INACTIVE()
 * Vnode is no longer referenced, deallocate the file
 * and all its resources.
 */
/* ARGSUSED */
static void
lxsys_inactive(vnode_t *vp, cred_t *cr, caller_context_t *ct)
{
	lxsys_freenode(VTOLXS(vp));
}

/*
 * lxsys_sync(): Vnode operation for VOP_SYNC()
 */
static int
lxsys_sync()
{
	/*
	 * Nothing to sync but this function must never fail
	 */
	return (0);
}

/*
 * lxsys_cmp(): Vnode operation for VOP_CMP()
 */
static int
lxsys_cmp(vnode_t *vp1, vnode_t *vp2, caller_context_t *ct)
{
	if (vn_matchops(vp1, lxsys_vnodeops) ||
	    vn_matchops(vp2, lxsys_vnodeops))
		return (vp1 == vp2);
	return (VOP_CMP(vp1, vp2, ct));
}
