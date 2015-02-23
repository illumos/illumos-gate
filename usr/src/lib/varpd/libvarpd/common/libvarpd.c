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
 * Copyright 2015 Joyent, Inc.
 */

/*
 * varpd library
 */

#include <stdlib.h>
#include <errno.h>
#include <umem.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/avl.h>
#include <stddef.h>
#include <stdio.h>
#include <strings.h>

#include <libvarpd_impl.h>

static int
libvarpd_instance_comparator(const void *lp, const void *rp)
{
	const varpd_instance_t *lpp, *rpp;
	lpp = lp;
	rpp = rp;

	if (lpp->vri_id > rpp->vri_id)
		return (1);
	if (lpp->vri_id < rpp->vri_id)
		return (-1);
	return (0);
}

static int
libvarpd_instance_lcomparator(const void *lp, const void *rp)
{
	const varpd_instance_t *lpp, *rpp;
	lpp = lp;
	rpp = rp;

	if (lpp->vri_linkid > rpp->vri_linkid)
		return (1);
	if (lpp->vri_linkid < rpp->vri_linkid)
		return (-1);
	return (0);
}

int
libvarpd_create(varpd_handle_t **vphp)
{
	int ret;
	varpd_impl_t *vip;
	char buf[32];

	if (vphp == NULL)
		return (EINVAL);

	*vphp = NULL;
	vip = umem_alloc(sizeof (varpd_impl_t), UMEM_DEFAULT);
	if (vip == NULL)
		return (errno);

	bzero(vip, sizeof (varpd_impl_t));
	(void) snprintf(buf, sizeof (buf), "varpd_%p", vip);
	vip->vdi_idspace = id_space_create(buf, LIBVARPD_ID_MIN,
	    LIBVARPD_ID_MAX);
	if (vip->vdi_idspace == NULL) {
		int ret = errno;
		umem_free(vip, sizeof (varpd_impl_t));
		return (ret);
	}

	vip->vdi_qcache = umem_cache_create("query", sizeof (varpd_query_t), 0,
	    NULL, NULL, NULL, NULL, NULL, 0);
	if (vip->vdi_qcache == NULL) {
		int ret = errno;
		id_space_destroy(vip->vdi_idspace);
		umem_free(vip, sizeof (varpd_impl_t));
		return (ret);
	}

	if ((ret = libvarpd_overlay_init(vip)) != 0) {
		umem_cache_destroy(vip->vdi_qcache);
		id_space_destroy(vip->vdi_idspace);
		umem_free(vip, sizeof (varpd_impl_t));
		return (ret);
	}

	libvarpd_persist_init(vip);

	avl_create(&vip->vdi_plugins, libvarpd_plugin_comparator,
	    sizeof (varpd_plugin_t), offsetof(varpd_plugin_t, vpp_node));

	avl_create(&vip->vdi_instances, libvarpd_instance_comparator,
	    sizeof (varpd_instance_t), offsetof(varpd_instance_t, vri_inode));
	avl_create(&vip->vdi_linstances, libvarpd_instance_lcomparator,
	    sizeof (varpd_instance_t), offsetof(varpd_instance_t, vri_lnode));

	if (mutex_init(&vip->vdi_lock, USYNC_THREAD | LOCK_ERRORCHECK,
	    NULL) != 0)
		libvarpd_panic("failed to create mutex: %d", errno);

	vip->vdi_doorfd = -1;
	*vphp = (varpd_handle_t *)vip;
	return (0);
}

void
libvarpd_destroy(varpd_handle_t *vhp)
{
	varpd_impl_t *vip = (varpd_impl_t *)vhp;

	libvarpd_overlay_lookup_quiesce(vhp);
	if (mutex_destroy(&vip->vdi_lock) != 0)
		libvarpd_panic("failed to destroy mutex: %d", errno);
	libvarpd_persist_fini(vip);
	libvarpd_overlay_fini(vip);
	umem_cache_destroy(vip->vdi_qcache);
	id_space_destroy(vip->vdi_idspace);
	umem_free(vip, sizeof (varpd_impl_t));
}

int
libvarpd_instance_create(varpd_handle_t *vhp, datalink_id_t linkid,
    const char *pname, varpd_instance_handle_t **outp)
{
	int ret;
	varpd_impl_t *vip = (varpd_impl_t *)vhp;
	varpd_plugin_t *plugin;
	varpd_instance_t *inst, lookup;
	overlay_plugin_dest_t dest;
	uint64_t vid;

	/*
	 * We should really have our own errnos.
	 */
	plugin = libvarpd_plugin_lookup(vip, pname);
	if (plugin == NULL)
		return (ENOENT);

	if ((ret = libvarpd_overlay_info(vip, linkid, &dest, NULL, &vid)) != 0)
		return (ret);

	inst = umem_alloc(sizeof (varpd_instance_t), UMEM_DEFAULT);
	if (inst == NULL)
		return (ENOMEM);

	inst->vri_id = id_alloc(vip->vdi_idspace);
	if (inst->vri_id == -1)
		libvarpd_panic("failed to allocate id from vdi_idspace: %d",
		    errno);
	inst->vri_linkid = linkid;
	inst->vri_vnetid = vid;
	inst->vri_mode = plugin->vpp_mode;
	inst->vri_dest = dest;
	inst->vri_plugin = plugin;
	inst->vri_impl = vip;
	inst->vri_flags = 0;
	if ((ret = plugin->vpp_ops->vpo_create((varpd_provider_handle_t *)inst,
	    &inst->vri_private, dest)) != 0) {
		id_free(vip->vdi_idspace, inst->vri_id);
		umem_free(inst, sizeof (varpd_instance_t));
		return (ret);
	}

	if (mutex_init(&inst->vri_lock, USYNC_THREAD | LOCK_ERRORCHECK,
	    NULL) != 0)
		libvarpd_panic("failed to create mutex: %d", errno);

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
	*outp = (varpd_instance_handle_t *)inst;
	return (0);
}

uint64_t
libvarpd_instance_id(varpd_instance_handle_t *ihp)
{
	varpd_instance_t *inst = (varpd_instance_t *)ihp;
	return (inst->vri_id);
}

uint64_t
libvarpd_plugin_vnetid(varpd_provider_handle_t *vhp)
{
	varpd_instance_t *inst = (varpd_instance_t *)vhp;
	return (inst->vri_vnetid);
}

varpd_instance_handle_t *
libvarpd_instance_lookup(varpd_handle_t *vhp, uint64_t id)
{
	varpd_impl_t *vip = (varpd_impl_t *)vhp;
	varpd_instance_t lookup, *retp;

	lookup.vri_id = id;
	mutex_enter(&vip->vdi_lock);
	retp = avl_find(&vip->vdi_instances, &lookup, NULL);
	mutex_exit(&vip->vdi_lock);
	return ((varpd_instance_handle_t *)retp);
}

/*
 * If this function becomes external to varpd, we need to change it to return a
 * varpd_instance_handle_t.
 */
varpd_instance_t *
libvarpd_instance_lookup_by_dlid(varpd_impl_t *vip, datalink_id_t linkid)
{
	varpd_instance_t lookup, *retp;

	lookup.vri_linkid = linkid;
	mutex_enter(&vip->vdi_lock);
	retp = avl_find(&vip->vdi_linstances, &lookup, NULL);
	mutex_exit(&vip->vdi_lock);
	return (retp);
}

/*
 * When an instance is being destroyed, that means we should deactivate it, as
 * well as clean it up. That means here, the proper order is calling the plug-in
 * stop and then the destroy function.
 */
void
libvarpd_instance_destroy(varpd_instance_handle_t *ihp)
{
	varpd_instance_t *inst = (varpd_instance_t *)ihp;
	varpd_impl_t *vip = inst->vri_impl;

	/*
	 * First things first, remove it from global visibility.
	 */
	mutex_enter(&vip->vdi_lock);
	avl_remove(&vip->vdi_instances, inst);
	avl_remove(&vip->vdi_linstances, inst);
	mutex_exit(&vip->vdi_lock);

	mutex_enter(&inst->vri_lock);

	/*
	 * We need to clean up this instance, that means remove it from
	 * persistence and stopping it. Then finally we'll have to clean it up
	 * entirely.
	 */
	if (inst->vri_flags & VARPD_INSTANCE_F_ACTIVATED) {
		inst->vri_flags &= ~VARPD_INSTANCE_F_ACTIVATED;
		libvarpd_torch_instance(vip, inst);
		inst->vri_plugin->vpp_ops->vpo_stop(inst->vri_private);
		inst->vri_plugin->vpp_ops->vpo_destroy(inst->vri_private);
		inst->vri_private = NULL;
	}
	mutex_exit(&inst->vri_lock);

	/* Do the full clean up of the instance */
	if (mutex_destroy(&inst->vri_lock) != 0)
		libvarpd_panic("failed to destroy instance vri_lock");
	id_free(vip->vdi_idspace, inst->vri_id);
	umem_free(inst, sizeof (varpd_instance_t));
}

int
libvarpd_instance_activate(varpd_instance_handle_t *ihp)
{
	int ret;
	varpd_instance_t *inst = (varpd_instance_t *)ihp;

	mutex_enter(&inst->vri_lock);

	if (inst->vri_flags & VARPD_INSTANCE_F_ACTIVATED) {
		ret = EEXIST;
		goto out;
	}

	if ((ret = inst->vri_plugin->vpp_ops->vpo_start(inst->vri_private)) !=
	    0)
		goto out;

	if ((ret = libvarpd_persist_instance(inst->vri_impl, inst)) != 0)
		goto out;

	/*
	 * If this fails, we don't need to call stop, as the caller should end
	 * up calling destroy on the instance, which takes care of calling stop
	 * and destroy.
	 */
	if ((ret = libvarpd_overlay_associate(inst)) != 0)
		goto out;

	inst->vri_flags |= VARPD_INSTANCE_F_ACTIVATED;

out:
	mutex_exit(&inst->vri_lock);
	return (ret);
}

static void
libvarpd_prefork(void)
{
	libvarpd_plugin_prefork();
}

static void
libvarpd_postfork(void)
{
	libvarpd_plugin_postfork();
}

#pragma init(libvarpd_init)
static void
libvarpd_init(void)
{
	libvarpd_plugin_init();
	if (pthread_atfork(libvarpd_prefork, libvarpd_postfork,
	    libvarpd_postfork) != 0)
		libvarpd_panic("failed to create varpd atfork: %d", errno);
}

#pragma fini(libvarpd_fini)
static void
libvarpd_fini(void)
{
	libvarpd_plugin_fini();
}
