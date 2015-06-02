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
 * Copyright 2015 Joyent, Inc.  All rights reserved.
 */

/*
 * varpd persistence backend
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <strings.h>
#include <librename.h>
#include <md5.h>
#include <sys/sysmacros.h>
#include <dirent.h>
#include <sys/mman.h>
#include <umem.h>
#include <sys/debug.h>

#include <libvarpd_impl.h>

static uint8_t varpd_persist_magic[4] = {
	'v',
	'a',
	'r',
	'p',
};

#define	VARPD_PERSIST_MAXWRITE		4096
#define	VARPD_PERSIST_VERSION_ONE	1
#define	VARPD_PERSIST_SUFFIX		".varpd"

typedef struct varpd_persist_header {
	uint8_t		vph_magic[4];
	uint32_t	vph_version;
	uint8_t		vph_md5[16];
} varpd_persist_header_t;

void
libvarpd_persist_init(varpd_impl_t *vip)
{
	vip->vdi_persistfd = -1;
	if (rwlock_init(&vip->vdi_pfdlock, USYNC_THREAD, NULL) != 0)
		libvarpd_panic("failed to create rw vdi_pfdlock");
}

void
libvarpd_persist_fini(varpd_impl_t *vip)
{
	/*
	 * Clean up for someone that left something behind.
	 */
	if (vip->vdi_persistfd != -1) {
		if (close(vip->vdi_persistfd) != 0)
			libvarpd_panic("failed to close persist fd %d: %d",
			    vip->vdi_persistfd, errno);
		vip->vdi_persistfd = -1;
	}
	if (rwlock_destroy(&vip->vdi_pfdlock) != 0)
		libvarpd_panic("failed to destroy rw vdi_pfdlock");
}

int
libvarpd_persist_enable(varpd_handle_t *vhp, const char *rootdir)
{
	int fd;
	struct stat st;
	varpd_impl_t *vip = (varpd_impl_t *)vhp;

	fd = open(rootdir, O_RDONLY);
	if (fd < 0)
		return (errno);

	if (fstat(fd, &st) != 0) {
		int ret = errno;
		if (close(fd) != 0)
			libvarpd_panic("failed to close rootdir fd (%s) %d: %d",
			    rootdir, fd, errno);
		return (ret);
	}

	if (!S_ISDIR(st.st_mode)) {
		if (close(fd) != 0)
			libvarpd_panic("failed to close rootdir fd (%s) %d: %d",
			    rootdir, fd, errno);
		return (EINVAL);
	}


	VERIFY0(rw_wrlock(&vip->vdi_pfdlock));
	if (vip->vdi_persistfd != -1) {
		VERIFY0(rw_unlock(&vip->vdi_pfdlock));
		if (close(fd) != 0)
			libvarpd_panic("failed to close rootdir fd (%s) %d: %d",
			    rootdir, fd, errno);
		return (EEXIST);
	}
	vip->vdi_persistfd = fd;
	VERIFY0(rw_unlock(&vip->vdi_pfdlock));

	return (0);
}

static int
libvarpd_persist_write(int fd, const void *buf, size_t buflen)
{
	ssize_t ret;
	off_t off = 0;

	while (buflen > 0) {
		ret = write(fd, (void *)((uintptr_t)buf + off),
		    MIN(buflen, VARPD_PERSIST_MAXWRITE));
		if (ret == -1 && errno == EINTR)
			continue;
		if (ret == -1)
			return (errno);

		off += ret;
		buflen -= ret;
	}

	return (0);
}

static int
libvarpd_persist_nvlist(int dirfd, uint64_t id, nvlist_t *nvl)
{
	int err, fd;
	size_t size;
	varpd_persist_header_t hdr;
	librename_atomic_t *lrap;
	char *buf = NULL, *name;

	if ((err = nvlist_pack(nvl, &buf, &size, NV_ENCODE_XDR, 0)) != 0)
		return (err);

	if (asprintf(&name, "%llu%s", (unsigned long long)id, ".varpd") == -1) {
		err = errno;
		free(buf);
		return (err);
	}

	if ((err = librename_atomic_fdinit(dirfd, name, NULL, 0600, 0,
	    &lrap)) != 0) {
		free(name);
		free(buf);
		return (err);
	}

	fd = librename_atomic_fd(lrap);

	bzero(&hdr, sizeof (varpd_persist_header_t));
	bcopy(varpd_persist_magic, hdr.vph_magic, sizeof (varpd_persist_magic));
	hdr.vph_version = VARPD_PERSIST_VERSION_ONE;
	md5_calc(hdr.vph_md5, buf, size);

	if ((err = libvarpd_persist_write(fd, &hdr,
	    sizeof (varpd_persist_header_t))) != 0) {
		librename_atomic_fini(lrap);
		free(name);
		free(buf);
		return (err);
	}

	if ((err = libvarpd_persist_write(fd, buf, size)) != 0) {
		librename_atomic_fini(lrap);
		free(name);
		free(buf);
		return (err);
	}

	do {
		err = librename_atomic_commit(lrap);
	} while (err == EINTR);

	librename_atomic_fini(lrap);
	free(name);
	free(buf);
	return (err);
}

int
libvarpd_persist_instance(varpd_impl_t *vip, varpd_instance_t *inst)
{
	int err = 0;
	nvlist_t *nvl = NULL, *cvl = NULL;

	VERIFY0(rw_rdlock(&vip->vdi_pfdlock));
	/* Check if persistence exists */
	if (vip->vdi_persistfd == -1)
		goto out;

	if ((err = nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0)) != 0)
		goto out;

	if ((err = nvlist_alloc(&cvl, NV_UNIQUE_NAME, 0)) != 0)
		goto out;

	if ((err = nvlist_add_uint64(nvl, "vri_id", inst->vri_id)) != 0)
		goto out;

	if ((err = nvlist_add_uint32(nvl, "vri_linkid", inst->vri_linkid)) != 0)
		goto out;

	if ((err = nvlist_add_uint32(nvl, "vri_dest",
	    (uint32_t)inst->vri_dest)) != 0)
		goto out;
	if ((err = nvlist_add_uint32(nvl, "vri_mode",
	    (uint32_t)inst->vri_mode)) != 0)
		goto out;

	if ((err = nvlist_add_string(nvl, "vri_plugin",
	    inst->vri_plugin->vpp_name)) != 0)
		goto out;

	err = inst->vri_plugin->vpp_ops->vpo_save(inst->vri_private, cvl);
	if (err != 0)
		goto out;

	if ((err = nvlist_add_nvlist(nvl, "vri_private", cvl)) != 0)
		goto out;

	err = libvarpd_persist_nvlist(vip->vdi_persistfd, inst->vri_id, nvl);
out:
	nvlist_free(nvl);
	nvlist_free(cvl);
	VERIFY0(rw_unlock(&vip->vdi_pfdlock));
	return (err);
}

void
libvarpd_torch_instance(varpd_impl_t *vip, varpd_instance_t *inst)
{
	char buf[32];
	int ret;

	VERIFY0(rw_rdlock(&vip->vdi_pfdlock));
	if (vip->vdi_persistfd == -1) {
		VERIFY0(rw_unlock(&vip->vdi_pfdlock));
		return;
	}

	if (snprintf(buf, sizeof (buf), "%lld.varpd", inst->vri_id) >= 32)
		libvarpd_panic("somehow exceeded static value for "
		    "libvarpd_torch_instance buffer");

	do {
		ret = unlinkat(vip->vdi_persistfd, buf, 0);
	} while (ret == -1 && errno == EINTR);
	if (ret != 0) {
		switch (errno) {
		case ENOENT:
			break;
		default:
			libvarpd_panic("failed to unlinkat %d`%s: %s",
			    vip->vdi_persistfd, buf, strerror(errno));
		}
	}

	VERIFY0(rw_unlock(&vip->vdi_pfdlock));
}

static int
libvarpd_persist_restore_instance(varpd_impl_t *vip, nvlist_t *nvl)
{
	int err;
	nvlist_t *pvl;
	uint64_t id, flags, vid;
	uint32_t linkid, dest, mode;
	char *pluginstr;
	varpd_plugin_t *plugin;
	overlay_plugin_dest_t adest;
	varpd_instance_t *inst, lookup;

	if (nvlist_lookup_uint64(nvl, "vri_id", &id) != 0)
		return (EINVAL);

	if (nvlist_lookup_uint32(nvl, "vri_linkid", &linkid) != 0)
		return (EINVAL);

	if (nvlist_lookup_uint32(nvl, "vri_dest", &dest) != 0)
		return (EINVAL);

	if (nvlist_lookup_uint32(nvl, "vri_mode", &mode) != 0)
		return (EINVAL);

	if (nvlist_lookup_string(nvl, "vri_plugin", &pluginstr) != 0)
		return (EINVAL);

	if (nvlist_lookup_nvlist(nvl, "vri_private", &pvl) != 0)
		return (EINVAL);

	plugin = libvarpd_plugin_lookup(vip, pluginstr);
	if (plugin == NULL)
		return (EINVAL);

	if (plugin->vpp_mode != mode)
		return (EINVAL);

	if (libvarpd_overlay_info(vip, linkid, &adest, &flags, &vid) != 0)
		return (EINVAL);

	if (dest != adest)
		return (EINVAL);

	inst = umem_alloc(sizeof (varpd_instance_t), UMEM_DEFAULT);
	if (inst == NULL)
		libvarpd_panic("failed to allocate instance for restore");

	inst->vri_id = id_alloc_specific(vip->vdi_idspace, id);
	if (inst->vri_id != id) {
		umem_free(inst, sizeof (varpd_instance_t));
		return (EINVAL);
	}

	inst->vri_linkid = linkid;
	inst->vri_vnetid = vid;
	inst->vri_mode = plugin->vpp_mode;
	inst->vri_dest = dest;
	inst->vri_plugin = plugin;
	inst->vri_impl = vip;
	inst->vri_flags = 0;
	if (plugin->vpp_ops->vpo_restore(pvl, (varpd_provider_handle_t *)inst,
	    dest, &inst->vri_private) != 0) {
		id_free(vip->vdi_idspace, id);
		umem_free(inst, sizeof (varpd_instance_t));
		return (EINVAL);
	}

	if (mutex_init(&inst->vri_lock, USYNC_THREAD | LOCK_ERRORCHECK,
	    NULL) != 0)
		libvarpd_panic("failed to create vri_lock mutex");

	mutex_enter(&vip->vdi_lock);
	lookup.vri_id = inst->vri_id;
	if (avl_find(&vip->vdi_instances, &lookup, NULL) != NULL)
		libvarpd_panic("found duplicate instance with id %d",
		    lookup.vri_id);
	avl_add(&vip->vdi_instances, inst);
	lookup.vri_linkid = inst->vri_linkid;
	if (avl_find(&vip->vdi_linstances, &lookup, NULL) != NULL)
		libvarpd_panic("found duplicate linstance with id %d",
		    lookup.vri_linkid);
	avl_add(&vip->vdi_linstances, inst);
	mutex_exit(&vip->vdi_lock);

	if (plugin->vpp_ops->vpo_start(inst->vri_private) != 0) {
		libvarpd_instance_destroy((varpd_instance_handle_t *)inst);
		return (EINVAL);
	}

	if (flags & OVERLAY_TARG_INFO_F_ACTIVE)
		(void) libvarpd_overlay_disassociate(inst);

	if (libvarpd_overlay_associate(inst) != 0) {
		libvarpd_instance_destroy((varpd_instance_handle_t *)inst);
		return (EINVAL);
	}

	if (flags & OVERLAY_TARG_INFO_F_DEGRADED) {
		if ((err = libvarpd_overlay_restore(inst)) != 0) {
			libvarpd_panic("failed to restore instance %p: %d\n",
			    inst, err);
		}
	}

	mutex_enter(&inst->vri_lock);
	inst->vri_flags |= VARPD_INSTANCE_F_ACTIVATED;
	mutex_exit(&inst->vri_lock);

	return (0);
}

static int
libvarpd_persist_restore_one(varpd_impl_t *vip, int fd)
{
	int err;
	size_t fsize;
	struct stat st;
	void *buf, *datap;
	varpd_persist_header_t *hdr;
	uint8_t md5[16];
	nvlist_t *nvl;

	if (fstat(fd, &st) != 0)
		return (errno);

	if (st.st_size <= sizeof (varpd_persist_header_t))
		return (EINVAL);
	fsize = st.st_size - sizeof (varpd_persist_header_t);

	buf = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (buf == MAP_FAILED)
		return (errno);

	hdr = buf;
	if (bcmp(varpd_persist_magic, hdr->vph_magic,
	    sizeof (varpd_persist_magic)) != 0) {
		if (munmap(buf, st.st_size) != 0)
			libvarpd_panic("failed to munmap %p: %d", buf, errno);
		return (EINVAL);
	}

	if (hdr->vph_version != VARPD_PERSIST_VERSION_ONE) {
		if (munmap(buf, st.st_size) != 0)
			libvarpd_panic("failed to munmap %p: %d", buf, errno);
		return (EINVAL);
	}

	datap = (void *)((uintptr_t)buf + sizeof (varpd_persist_header_t));
	md5_calc(md5, datap, fsize);
	if (bcmp(md5, hdr->vph_md5, sizeof (uint8_t) * 16) != 0) {
		if (munmap(buf, st.st_size) != 0)
			libvarpd_panic("failed to munmap %p: %d", buf, errno);
		return (EINVAL);
	}

	err = nvlist_unpack(datap, fsize, &nvl, 0);
	if (munmap(buf, st.st_size) != 0)
		libvarpd_panic("failed to munmap %p: %d", buf, errno);

	if (err != 0)
		return (EINVAL);

	err = libvarpd_persist_restore_instance(vip, nvl);
	nvlist_free(nvl);
	return (err);
}

/* ARGSUSED */
static int
libvarpd_check_degrade_cb(varpd_impl_t *vip, datalink_id_t linkid, void *arg)
{
	varpd_instance_t *inst;

	mutex_enter(&vip->vdi_lock);
	for (inst = avl_first(&vip->vdi_instances); inst != NULL;
	    inst = AVL_NEXT(&vip->vdi_instances, inst)) {
		if (inst->vri_linkid == linkid) {
			mutex_exit(&vip->vdi_lock);
			return (0);
		}
	}

	mutex_exit(&vip->vdi_lock);

	(void) libvarpd_overlay_degrade_datalink(vip, linkid,
	    "no varpd instance exists");
	return (0);
}

static void
libvarpd_check_degrade(varpd_impl_t *vip)
{
	(void) libvarpd_overlay_iter(vip, libvarpd_check_degrade_cb, NULL);
}

int
libvarpd_persist_restore(varpd_handle_t *vhp)
{
	int dirfd;
	int ret = 0;
	DIR *dirp = NULL;
	struct dirent *dp;
	varpd_impl_t *vip = (varpd_impl_t *)vhp;

	VERIFY0(rw_rdlock(&vip->vdi_pfdlock));
	if ((dirfd = dup(vip->vdi_persistfd)) < 0) {
		ret = errno;
		goto out;
	}

	if ((dirp = fdopendir(dirfd)) == NULL) {
		ret = errno;
		if (close(dirfd) != 0)
			libvarpd_panic("failed to close dirfd %d: %d",
			    dirfd, errno);
		goto out;
	}

	for (;;) {
		int fd;
		uint64_t id;
		char *eptr;
		struct stat st;

		errno = 0;
		dp = readdir(dirp);
		if (dp == NULL) {
			ret = errno;
			break;
		}

		if (strcmp(dp->d_name, ".") == 0 ||
		    strcmp(dp->d_name, "..") == 0)
			continue;

		/*
		 * Leave files that we don't recognize alone. A valid file has
		 * the format `%llu.varpd`.
		 */
		errno = 0;
		id = strtoull(dp->d_name, &eptr, 10);
		if ((id == 0 && errno == EINVAL) ||
		    (id == ULLONG_MAX && errno == ERANGE))
			continue;

		if (strcmp(eptr, VARPD_PERSIST_SUFFIX) != 0)
			continue;

		fd = openat(vip->vdi_persistfd, dp->d_name, O_RDONLY);
		if (fd < 0) {
			ret = errno;
			break;
		}

		if (fstat(fd, &st) != 0) {
			ret = errno;
			break;
		}

		if (!S_ISREG(st.st_mode)) {
			if (close(fd) != 0)
				libvarpd_panic("failed to close fd (%s) %d: "
				    "%d\n", dp->d_name, fd, errno);
			continue;
		}

		ret = libvarpd_persist_restore_one(vip, fd);
		if (close(fd) != 0)
			libvarpd_panic("failed to close fd (%s) %d: "
			    "%d\n", dp->d_name, fd, errno);
		/*
		 * This is an invalid file. We'll unlink it to save us this
		 * trouble in the future.
		 */
		if (ret != 0) {
			if (unlinkat(vip->vdi_persistfd, dp->d_name, 0) != 0) {
				ret = errno;
				break;
			}
		}
	}

	libvarpd_check_degrade(vip);

out:
	if (dirp != NULL)
		(void) closedir(dirp);
	VERIFY0(rw_unlock(&vip->vdi_pfdlock));
	return (ret);
}

int
libvarpd_persist_disable(varpd_handle_t *vhp)
{
	varpd_impl_t *vip = (varpd_impl_t *)vhp;

	VERIFY0(rw_wrlock(&vip->vdi_pfdlock));
	if (vip->vdi_persistfd == -1) {
		mutex_exit(&vip->vdi_lock);
		VERIFY0(rw_unlock(&vip->vdi_pfdlock));
		return (ENOENT);
	}
	if (close(vip->vdi_persistfd) != 0)
		libvarpd_panic("failed to close persist fd %d: %d",
		    vip->vdi_persistfd, errno);
	vip->vdi_persistfd = -1;
	VERIFY0(rw_unlock(&vip->vdi_pfdlock));
	return (0);
}
