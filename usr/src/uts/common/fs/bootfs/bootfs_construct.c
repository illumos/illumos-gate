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
 * Copyright (c) 2015 Joyent, Inc.  All rights reserved.
 */

/*
 * This file takes care of reading the boot time modules and constructing them
 * into the appropriate series of vnodes.
 */

#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/vfs.h>
#include <sys/sysmacros.h>
#include <sys/stat.h>

#include <sys/fs/bootfs_impl.h>

kmem_cache_t *bootfs_node_cache;

static const vattr_t bootfs_vattr_dir = {
	AT_ALL,					/* va_mask */
	VDIR,					/* va_type */
	S_IFDIR | 0555,				/* va_mode */
	0,					/* va_uid */
	0,					/* va_gid */
	0,					/* va_fsid */
	0,					/* va_nodeid */
	1,					/* va_nlink */
	0,					/* va_size */
	0,					/* va_atime */
	0,					/* va_mtime */
	0,					/* va_ctime */
	0,					/* va_rdev */
	0,					/* va_blksize */
	0,					/* va_nblocks */
	0					/* va_seq */
};

static const vattr_t bootfs_vattr_reg = {
	AT_ALL,					/* va_mask */
	VREG,					/* va_type */
	S_IFREG | 0555,				/* va_mode */
	0,					/* va_uid */
	0,					/* va_gid */
	0,					/* va_fsid */
	0,					/* va_nodeid */
	1,					/* va_nlink */
	0,					/* va_size */
	0,					/* va_atime */
	0,					/* va_mtime */
	0,					/* va_ctime */
	0,					/* va_rdev */
	0,					/* va_blksize */
	0,					/* va_nblocks */
	0					/* va_seq */
};

/*ARGSUSED*/
int
bootfs_node_constructor(void *buf, void *arg, int kmflags)
{
	bootfs_node_t *bnp = buf;

	bnp->bvn_vnp = vn_alloc(kmflags);
	if (bnp->bvn_vnp == NULL)
		return (-1);

	return (0);
}

/*ARGSUSED*/
void
bootfs_node_destructor(void *buf, void *arg)
{
	bootfs_node_t *bnp = buf;

	vn_free(bnp->bvn_vnp);
}

static int
bootfs_comparator(const void *a, const void *b)
{
	const bootfs_node_t *lfs, *rfs;
	int ret;

	lfs = a;
	rfs = b;

	ret = strcmp(lfs->bvn_name, rfs->bvn_name);
	if (ret > 0)
		ret = 1;
	if (ret < 0)
		ret = -1;
	return (ret);
}

static void
bootfs_node_init(bootfs_t *bfs, bootfs_node_t *bnp, const struct vattr *vap,
    const char *name, size_t namelen)
{
	timestruc_t now;

	vn_reinit(bnp->bvn_vnp);

	bnp->bvn_vnp->v_flag |= VNOSWAP;
	bnp->bvn_vnp->v_type = vap->va_type;
	bnp->bvn_vnp->v_vfsp = bfs->bfs_vfsp;
	bnp->bvn_vnp->v_rdev = 0;
	bnp->bvn_vnp->v_data = (caddr_t)bnp;
	vn_setops(bnp->bvn_vnp, bootfs_vnodeops);

	bnp->bvn_name = kmem_alloc(namelen + 1, KM_SLEEP);
	bcopy(name, bnp->bvn_name, namelen);
	bnp->bvn_name[namelen] = '\0';
	if (vap->va_type == VDIR) {
		avl_create(&bnp->bvn_dir, bootfs_comparator,
		    sizeof (bootfs_node_t),
		    offsetof(bootfs_node_t, bvn_link));
	}
	bzero(&bnp->bvn_link, sizeof (avl_node_t));
	bcopy(vap, &bnp->bvn_attr, sizeof (vattr_t));

	gethrestime(&now);
	bnp->bvn_attr.va_atime = now;
	bnp->bvn_attr.va_ctime = now;
	bnp->bvn_attr.va_mtime = now;
	bnp->bvn_attr.va_fsid = makedevice(bootfs_major, bfs->bfs_minor);
	bnp->bvn_attr.va_nodeid = bfs->bfs_ninode;
	bnp->bvn_attr.va_blksize = PAGESIZE;
	bfs->bfs_ninode++;
	list_insert_tail(&bfs->bfs_nodes, bnp);
}

static void
bootfs_mkroot(bootfs_t *bfs)
{
	bootfs_node_t *bnp;

	bnp = kmem_cache_alloc(bootfs_node_cache, KM_SLEEP);
	bootfs_node_init(bfs, bnp, &bootfs_vattr_dir, "/", 1);
	bnp->bvn_vnp->v_flag |= VROOT;
	bnp->bvn_parent = bnp;
	bfs->bfs_rootvn = bnp;
	bfs->bfs_stat.bfss_ndirs.value.ui32++;
	vn_exists(bnp->bvn_vnp);
}

static int
bootfs_mknode(bootfs_t *bfs, bootfs_node_t *parent, bootfs_node_t **outp,
    const char *name, size_t namelen, const vattr_t *vap, uintptr_t addr,
    uint64_t size)
{
	bootfs_node_t *bnp;
	bootfs_node_t sn;
	avl_index_t where;
	char *buf;

	ASSERT(parent->bvn_attr.va_type == VDIR);
	buf = kmem_alloc(namelen + 1, KM_SLEEP);
	bcopy(name, buf, namelen);
	buf[namelen] = '\0';
	sn.bvn_name = buf;
	if ((bnp = avl_find(&parent->bvn_dir, &sn, &where)) != NULL) {
		kmem_free(buf, namelen + 1);
		/* Directories can collide, files cannot */
		if (vap->va_type == VDIR) {
			*outp = bnp;
			return (0);
		}
		return (EEXIST);
	}
	kmem_free(buf, namelen + 1);

	bnp = kmem_cache_alloc(bootfs_node_cache, KM_SLEEP);
	bootfs_node_init(bfs, bnp, vap, name, namelen);
	bnp->bvn_parent = parent;
	avl_add(&parent->bvn_dir, bnp);
	*outp = bnp;

	if (vap->va_type == VDIR) {
		parent->bvn_attr.va_size++;
		parent->bvn_attr.va_nlink++;
		bfs->bfs_stat.bfss_ndirs.value.ui32++;
	} else {
		bnp->bvn_addr = addr;
		bnp->bvn_size = size;
		bfs->bfs_stat.bfss_nfiles.value.ui32++;
		bfs->bfs_stat.bfss_nbytes.value.ui64 += size;
		bnp->bvn_attr.va_nblocks = P2ROUNDUP(size, 512) >> 9;
		bnp->bvn_attr.va_size = size;
	}

	vn_exists(bnp->bvn_vnp);

	return (0);
}

/*
 * Given the address, size, and path a boot-time module would like, go through
 * and create all of the directory entries that are required and then the file
 * itself. If someone has passed in a module that has the same name as another
 * one, we honor the first one.
 */
static int
bootfs_construct_entry(bootfs_t *bfs, uintptr_t addr, uint64_t size,
    const char *mname)
{
	char *sp;
	size_t nlen;
	int ret;
	bootfs_node_t *nbnp;

	const char *p = mname;
	bootfs_node_t *bnp = bfs->bfs_rootvn;

	if (*p == '\0')
		return (EINVAL);

	for (;;) {
		/* First eliminate all leading / characters. */
		while (*p == '/')
			p++;

		/* A name with all slashes or ending in a / */
		if (*p == '\0')
			return (EINVAL);

		sp = strchr(p, '/');
		if (sp == NULL)
			break;
		nlen = (ptrdiff_t)sp - (ptrdiff_t)p;
		if (strncmp(p, ".", nlen) == 0) {
			p = sp + 1;
			continue;
		}

		if (strncmp(p, "..", nlen) == 0) {
			bnp = bnp->bvn_parent;
			p = sp + 1;
			continue;
		}

		VERIFY(bootfs_mknode(bfs, bnp, &nbnp, p, nlen,
		    &bootfs_vattr_dir, addr, size) == 0);
		p = sp + 1;
		bnp = nbnp;
	}

	nlen = strlen(p);
	ret = bootfs_mknode(bfs, bnp, &nbnp, p, nlen, &bootfs_vattr_reg,
	    addr, size);
	if (ret != 0)
		return (ret);

	return (0);
}

/*
 * We're going to go through every boot time module and construct the
 * appropriate vnodes for them now. Because there are very few of these that
 * exist, generally on the order of a handful, we're going to create them all
 * when the file system is initialized and then tear them all down when the
 * module gets unloaded.
 *
 * The information about the modules is contained in properties on the root of
 * the devinfo tree. Specifically there are three properties per module:
 *
 *   - module-size-%d	int64_t size, in bytes, of the boot time module.
 *   - module-addr-%d	The address of the boot time module
 *   - module-name-%d	The string name of the boot time module
 *
 * Note that the module-size and module-addr fields are always 64-bit values
 * regardless of being on a 32-bit or 64-bit kernel. module-name is a string
 * property.
 *
 * There is no property that indicates the total number of such modules. Modules
 * start at 0 and work their way up incrementally. The first time we can't find
 * a module or a property, then we stop.
 */
void
bootfs_construct(bootfs_t *bfs)
{
	uint_t id = 0, ndata;
	char paddr[64], psize[64], pname[64], *mname;
	dev_info_t *root;
	uchar_t *datap;
	uint64_t size = 0, addr = 0;
	int ret;

	bootfs_mkroot(bfs);
	root = ddi_root_node();

	for (;;) {
		if (id == UINT32_MAX)
			break;

		if (snprintf(paddr, sizeof (paddr), "module-addr-%d", id) >
		    sizeof (paddr))
			break;

		if (snprintf(psize, sizeof (paddr), "module-size-%d", id) >
		    sizeof (paddr))
			break;

		if (snprintf(pname, sizeof (paddr), "module-name-%d", id) >
		    sizeof (paddr))
			break;

		if (ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, root,
		    DDI_PROP_DONTPASS, paddr, &datap, &ndata) !=
		    DDI_PROP_SUCCESS)
			break;

		if (ndata == 8)
			bcopy(datap, &addr, sizeof (uint64_t));
		ddi_prop_free(datap);
		if (ndata != 8)
			break;

		if (ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, root,
		    DDI_PROP_DONTPASS, psize, &datap, &ndata) !=
		    DDI_PROP_SUCCESS)
			break;
		if (ndata == 8)
			bcopy(datap, &size, sizeof (uint64_t));
		ddi_prop_free(datap);
		if (ndata != 8)
			break;

		if (ddi_prop_lookup_string(DDI_DEV_T_ANY, root,
		    DDI_PROP_DONTPASS, pname, &mname) != DDI_PROP_SUCCESS)
			break;

		ret = bootfs_construct_entry(bfs, addr, size, mname);
		if (ret == EINVAL)
			bfs->bfs_stat.bfss_ndiscards.value.ui32++;
		if (ret == EEXIST)
			bfs->bfs_stat.bfss_ndups.value.ui32++;
		ddi_prop_free(mname);

		id++;
	}
}

void
bootfs_destruct(bootfs_t *bfs)
{
	bootfs_node_t *bnp;

	while ((bnp = list_remove_head(&bfs->bfs_nodes)) != NULL) {
		ASSERT(bnp->bvn_vnp->v_count == 1);
		VN_RELE(bnp->bvn_vnp);
		kmem_free(bnp->bvn_name, strlen(bnp->bvn_name) + 1);
		kmem_cache_free(bootfs_node_cache, bnp);
	}
}
