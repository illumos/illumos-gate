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
 * Interactions with /dev/overlay
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <stropts.h>
#include <strings.h>
#include <umem.h>

#include <libvarpd_impl.h>
#include <sys/overlay_target.h>

#define	OVERLAY_PATH	"/dev/overlay"

int
libvarpd_overlay_init(varpd_impl_t *vip)
{
	vip->vdi_overlayfd = open(OVERLAY_PATH, O_RDWR | O_EXCL);
	if (vip->vdi_overlayfd == -1)
		return (errno);
	return (0);
}

void
libvarpd_overlay_fini(varpd_impl_t *vip)
{
	assert(vip->vdi_overlayfd > 0);
	if (close(vip->vdi_overlayfd) != 0)
		libvarpd_panic("failed to close /dev/overlay fd %d: %d",
		    vip->vdi_overlayfd, errno);
}

int
libvarpd_overlay_info(varpd_impl_t *vip, datalink_id_t linkid,
    overlay_plugin_dest_t *destp, uint64_t *flags, uint64_t *vnetid)
{
	overlay_targ_info_t oti;

	oti.oti_linkid = linkid;
	if (ioctl(vip->vdi_overlayfd, OVERLAY_TARG_INFO, &oti) != 0)
		return (errno);

	if (destp != NULL)
		*destp = oti.oti_needs;
	if (flags != NULL)
		*flags = oti.oti_flags;
	if (vnetid != NULL)
		*vnetid = oti.oti_vnetid;
	return (0);
}

int
libvarpd_overlay_associate(varpd_instance_t *inst)
{
	overlay_targ_associate_t ota;
	varpd_impl_t *vip = inst->vri_impl;

	bzero(&ota, sizeof (overlay_targ_associate_t));
	ota.ota_linkid = inst->vri_linkid;
	ota.ota_mode = inst->vri_mode;
	ota.ota_id = inst->vri_id;
	ota.ota_provides = inst->vri_dest;

	if (ota.ota_mode == OVERLAY_TARGET_POINT) {
		int ret;
		ret = inst->vri_plugin->vpp_ops->vpo_default(inst->vri_private,
		    &ota.ota_point);
		if (ret != VARPD_LOOKUP_OK)
			return (ret);
	}

	if (ioctl(vip->vdi_overlayfd, OVERLAY_TARG_ASSOCIATE, &ota) != 0)
		return (errno);

	return (0);
}

int
libvarpd_overlay_disassociate(varpd_instance_t *inst)
{
	overlay_targ_id_t otid;
	varpd_impl_t *vip = inst->vri_impl;

	otid.otid_linkid = inst->vri_linkid;
	if (ioctl(vip->vdi_overlayfd, OVERLAY_TARG_DISASSOCIATE, &otid) != 0)
		return (errno);
	return (0);
}

int
libvarpd_overlay_degrade_datalink(varpd_impl_t *vip, datalink_id_t linkid,
    const char *msg)
{
	overlay_targ_degrade_t otd;

	otd.otd_linkid = linkid;
	(void) strlcpy(otd.otd_buf, msg, OVERLAY_STATUS_BUFLEN);
	if (ioctl(vip->vdi_overlayfd, OVERLAY_TARG_DEGRADE, &otd) != 0)
		return (errno);
	return (0);

}

int
libvarpd_overlay_degrade(varpd_instance_t *inst, const char *msg)
{
	return (libvarpd_overlay_degrade_datalink(inst->vri_impl,
	    inst->vri_linkid, msg));
}

int
libvarpd_overlay_restore(varpd_instance_t *inst)
{
	overlay_targ_id_t otid;
	varpd_impl_t *vip = inst->vri_impl;

	otid.otid_linkid = inst->vri_linkid;
	if (ioctl(vip->vdi_overlayfd, OVERLAY_TARG_RESTORE, &otid) != 0)
		return (errno);
	return (0);
}

int
libvarpd_overlay_packet(varpd_impl_t *vip, const overlay_targ_lookup_t *otl,
    void *buf, size_t *buflen)
{
	int ret;
	overlay_targ_pkt_t otp;

	otp.otp_linkid = UINT64_MAX;
	otp.otp_reqid = otl->otl_reqid;
	otp.otp_size = *buflen;
	otp.otp_buf = buf;

	do {
		ret = ioctl(vip->vdi_overlayfd, OVERLAY_TARG_PKT, &otp);
	} while (ret != 0 && errno == EINTR);
	if (ret != 0 && errno == EFAULT)
		libvarpd_panic("OVERLAY_TARG_PKT ioctl efault");
	else if (ret != 0)
		ret = errno;

	if (ret == 0)
		*buflen = otp.otp_size;

	return (ret);
}

static int
libvarpd_overlay_inject_common(varpd_impl_t *vip, varpd_instance_t *inst,
    const overlay_targ_lookup_t *otl, void *buf, size_t buflen, int cmd)
{
	int ret;
	overlay_targ_pkt_t otp;

	if (otl == NULL) {
		otp.otp_linkid = inst->vri_linkid;
		otp.otp_reqid = 0;
	} else {
		otp.otp_linkid = UINT64_MAX;
		otp.otp_reqid = otl->otl_reqid;
	}
	otp.otp_size = buflen;
	otp.otp_buf = buf;

	do {
		ret = ioctl(vip->vdi_overlayfd, cmd, &otp);
	} while (ret != 0 && errno == EINTR);
	if (ret != 0 && errno == EFAULT)
		libvarpd_panic("overlay_inject_common ioctl EFAULT");
	else if (ret != 0)
		ret = errno;

	return (ret);
}

int
libvarpd_overlay_inject(varpd_impl_t *vip, const overlay_targ_lookup_t *otl,
    void *buf, size_t buflen)
{
	return (libvarpd_overlay_inject_common(vip, NULL, otl, buf, buflen,
	    OVERLAY_TARG_INJECT));
}

int
libvarpd_overlay_instance_inject(varpd_instance_t *inst, void *buf,
    size_t buflen)
{
	return (libvarpd_overlay_inject_common(inst->vri_impl, inst, NULL, buf,
	    buflen, OVERLAY_TARG_INJECT));
}

int
libvarpd_overlay_resend(varpd_impl_t *vip, const overlay_targ_lookup_t *otl,
    void *buf, size_t buflen)
{
	return (libvarpd_overlay_inject_common(vip, NULL, otl, buf, buflen,
	    OVERLAY_TARG_RESEND));
}

static void
libvarpd_overlay_lookup_reply(varpd_impl_t *vip,
    const overlay_targ_lookup_t *otl, overlay_targ_resp_t *otr, int cmd)
{
	int ret;

	otr->otr_reqid = otl->otl_reqid;
	do {
		ret = ioctl(vip->vdi_overlayfd, cmd, otr);
	} while (ret != 0 && errno == EINTR);

	/*
	 * The only errors that should cause us to end up here are due to
	 * programmer errors. Aruably the EINAVL case indicates that something
	 * is a bit off; however, at this time we don't opt to kill varpd.
	 */
	if (ret != 0 && errno != EINVAL)
		libvarpd_panic("receieved bad errno from lookup_reply "
		    "(cmd %d): %d\n", cmd, errno);
}

static void
libvarpd_overlay_lookup_handle(varpd_impl_t *vip)
{
	int ret;
	varpd_query_t *vqp;
	overlay_targ_lookup_t *otl;
	overlay_targ_resp_t *otr;
	varpd_instance_t *inst;

	vqp = umem_cache_alloc(vip->vdi_qcache, UMEM_DEFAULT);
	otl = &vqp->vq_lookup;
	otr = &vqp->vq_response;
	/*
	 * abort doesn't really help here that much, maybe we can instead try
	 * and for a reap or something?
	 */
	if (vqp == NULL)
		libvarpd_panic("failed to allocate memory for lookup "
		    "handle..., we should not panic()");
	ret = ioctl(vip->vdi_overlayfd, OVERLAY_TARG_LOOKUP, otl);
	if (ret != 0 && errno != ETIME && errno != EINTR)
		libvarpd_panic("received bad errno from OVERLAY_TARG_LOOKUP: "
		    "%d", errno);

	if (ret != 0) {
		umem_cache_free(vip->vdi_qcache, vqp);
		return;
	}

	inst = (varpd_instance_t *)libvarpd_instance_lookup(
	    (varpd_handle_t *)vip, otl->otl_varpdid);
	if (inst == NULL) {
		libvarpd_overlay_lookup_reply(vip, otl, otr,
		    OVERLAY_TARG_DROP);
		umem_cache_free(vip->vdi_qcache, vqp);
		return;
	}
	vqp->vq_instance = inst;

	inst->vri_plugin->vpp_ops->vpo_lookup(inst->vri_private,
	    (varpd_query_handle_t *)vqp, otl, &otr->otr_answer);
}

void
libvarpd_overlay_lookup_run(varpd_handle_t *vhp)
{
	varpd_impl_t *vip = (varpd_impl_t *)vhp;

	mutex_enter(&vip->vdi_lock);
	if (vip->vdi_lthr_quiesce == B_TRUE) {
		mutex_exit(&vip->vdi_lock);
		return;
	}
	vip->vdi_lthr_count++;

	for (;;) {
		mutex_exit(&vip->vdi_lock);
		libvarpd_overlay_lookup_handle(vip);
		mutex_enter(&vip->vdi_lock);
		if (vip->vdi_lthr_quiesce == B_TRUE)
			break;
	}
	assert(vip->vdi_lthr_count > 0);
	vip->vdi_lthr_count--;
	(void) cond_signal(&vip->vdi_lthr_cv);
	mutex_exit(&vip->vdi_lock);
}

void
libvarpd_overlay_lookup_quiesce(varpd_handle_t *vhp)
{
	varpd_impl_t *vip = (varpd_impl_t *)vhp;

	mutex_enter(&vip->vdi_lock);
	if (vip->vdi_lthr_count == 0) {
		mutex_exit(&vip->vdi_lock);
		return;
	}
	vip->vdi_lthr_quiesce = B_TRUE;
	while (vip->vdi_lthr_count > 0)
		(void) cond_wait(&vip->vdi_lthr_cv, &vip->vdi_lock);
	vip->vdi_lthr_quiesce = B_FALSE;
	mutex_exit(&vip->vdi_lock);
}

int
libvarpd_overlay_iter(varpd_impl_t *vip, libvarpd_overlay_iter_f func,
    void *arg)
{
	uint32_t curents = 0, i;
	size_t size;
	overlay_targ_list_t *otl;

	for (;;) {
		size = sizeof (overlay_targ_list_t) +
		    sizeof (uint32_t) * curents;
		otl = umem_alloc(size, UMEM_DEFAULT);
		if (otl == NULL)
			return (ENOMEM);

		otl->otl_nents = curents;
		if (ioctl(vip->vdi_overlayfd, OVERLAY_TARG_LIST, otl) != 0) {
			if (errno == EFAULT)
				libvarpd_panic("OVERLAY_TARG_LIST ioctl "
				    "efault");
			umem_free(otl, size);
			if (errno == EINTR)
				continue;
			else
				return (errno);
		}

		if (otl->otl_nents == curents)
			break;

		curents = otl->otl_nents;
		umem_free(otl, size);
	}

	for (i = 0; i < otl->otl_nents; i++) {
		if (func(vip, otl->otl_ents[i], arg) != 0)
			break;
	}
	umem_free(otl, size);
	return (0);
}

int
libvarpd_overlay_cache_flush(varpd_instance_t *inst)
{
	int ret;
	overlay_targ_cache_t cache;
	varpd_impl_t *vip = inst->vri_impl;

	bzero(&cache, sizeof (overlay_targ_cache_t));
	cache.otc_linkid = inst->vri_linkid;

	ret = ioctl(vip->vdi_overlayfd, OVERLAY_TARG_CACHE_FLUSH, &cache);
	if (ret != 0 && errno == EFAULT)
		libvarpd_panic("OVERLAY_TARG_CACHE_FLUSH ioctl efault");
	else if (ret != 0)
		ret = errno;

	return (ret);
}

int
libvarpd_overlay_cache_delete(varpd_instance_t *inst, const uint8_t *key)
{
	int ret;
	overlay_targ_cache_t cache;
	varpd_impl_t *vip = inst->vri_impl;

	bzero(&cache, sizeof (overlay_targ_cache_t));
	cache.otc_linkid = inst->vri_linkid;
	bcopy(key, cache.otc_entry.otce_mac, ETHERADDRL);

	ret = ioctl(vip->vdi_overlayfd, OVERLAY_TARG_CACHE_REMOVE, &cache);
	if (ret != 0 && errno == EFAULT)
		libvarpd_panic("OVERLAY_TARG_CACHE_REMOVE ioctl efault");
	else if (ret != 0)
		ret = errno;

	return (ret);

}

int
libvarpd_overlay_cache_get(varpd_instance_t *inst, const uint8_t *key,
    varpd_client_cache_entry_t *entry)
{
	int ret;
	overlay_targ_cache_t cache;
	varpd_impl_t *vip = inst->vri_impl;

	bzero(&cache, sizeof (overlay_targ_cache_t));
	cache.otc_linkid = inst->vri_linkid;
	bcopy(key, cache.otc_entry.otce_mac, ETHERADDRL);

	ret = ioctl(vip->vdi_overlayfd, OVERLAY_TARG_CACHE_GET, &cache);
	if (ret != 0 && errno == EFAULT)
		libvarpd_panic("OVERLAY_TARG_CACHE_GET ioctl efault");
	else if (ret != 0)
		return (errno);

	bcopy(cache.otc_entry.otce_dest.otp_mac, &entry->vcp_mac, ETHERADDRL);
	entry->vcp_flags = cache.otc_entry.otce_flags;
	entry->vcp_ip = cache.otc_entry.otce_dest.otp_ip;
	entry->vcp_port = cache.otc_entry.otce_dest.otp_port;

	return (0);
}

int
libvarpd_overlay_cache_set(varpd_instance_t *inst, const uint8_t *key,
    const varpd_client_cache_entry_t *entry)
{
	int ret;
	overlay_targ_cache_t cache;
	varpd_impl_t *vip = inst->vri_impl;

	bzero(&cache, sizeof (overlay_targ_cache_t));
	cache.otc_linkid = inst->vri_linkid;
	bcopy(key, cache.otc_entry.otce_mac, ETHERADDRL);
	bcopy(&entry->vcp_mac, cache.otc_entry.otce_dest.otp_mac, ETHERADDRL);
	cache.otc_entry.otce_flags = entry->vcp_flags;
	cache.otc_entry.otce_dest.otp_ip = entry->vcp_ip;
	cache.otc_entry.otce_dest.otp_port = entry->vcp_port;

	ret = ioctl(vip->vdi_overlayfd, OVERLAY_TARG_CACHE_SET, &cache);
	if (ret != 0 && errno == EFAULT)
		libvarpd_panic("OVERLAY_TARG_CACHE_SET ioctl efault");
	else if (ret != 0)
		return (errno);

	return (0);
}

int
libvarpd_overlay_cache_walk_fill(varpd_instance_t *inst, uint64_t *markerp,
    uint64_t *countp, overlay_targ_cache_entry_t *ents)
{
	int ret;
	size_t asize;
	overlay_targ_cache_iter_t *iter;
	varpd_impl_t *vip = inst->vri_impl;

	if (*countp > 200)
		return (E2BIG);

	asize = sizeof (overlay_targ_cache_iter_t) +
	    *countp * sizeof (overlay_targ_cache_entry_t);
	iter = umem_alloc(asize, UMEM_DEFAULT);
	if (iter == NULL)
		return (ENOMEM);

	iter->otci_linkid = inst->vri_linkid;
	iter->otci_marker = *markerp;
	iter->otci_count = *countp;
	ret = ioctl(vip->vdi_overlayfd, OVERLAY_TARG_CACHE_ITER, iter);
	if (ret != 0 && errno == EFAULT)
		libvarpd_panic("OVERLAY_TARG_CACHE_ITER ioctl efault");
	else if (ret != 0) {
		ret = errno;
		goto out;
	}

	*markerp = iter->otci_marker;
	*countp = iter->otci_count;
	bcopy(iter->otci_ents, ents,
	    *countp * sizeof (overlay_targ_cache_entry_t));
out:
	umem_free(iter, asize);
	return (ret);
}

void
libvarpd_plugin_query_reply(varpd_query_handle_t *vqh, int action)
{
	varpd_query_t *vqp = (varpd_query_t *)vqh;

	if (vqp == NULL)
		libvarpd_panic("unkonwn plugin passed invalid "
		    "varpd_query_handle_t");

	if (action == VARPD_LOOKUP_DROP)
		libvarpd_overlay_lookup_reply(vqp->vq_instance->vri_impl,
		    &vqp->vq_lookup, &vqp->vq_response, OVERLAY_TARG_DROP);
	else if (action == VARPD_LOOKUP_OK)
		libvarpd_overlay_lookup_reply(vqp->vq_instance->vri_impl,
		    &vqp->vq_lookup, &vqp->vq_response, OVERLAY_TARG_RESPOND);
	else
		libvarpd_panic("plugin %s passed in an invalid action: %d",
		    vqp->vq_instance->vri_plugin->vpp_name, action);

	umem_cache_free(vqp->vq_instance->vri_impl->vdi_qcache, vqp);
}

void
libvarpd_inject_varp(varpd_provider_handle_t *vph, const uint8_t *mac,
    const overlay_target_point_t *otp)
{
	int ret;
	overlay_targ_cache_t otc;
	varpd_instance_t *inst = (varpd_instance_t *)vph;
	varpd_impl_t *vip = inst->vri_impl;

	if (otp == NULL) {
		(void) libvarpd_overlay_cache_delete(inst, mac);
		return;
	}

	otc.otc_linkid = inst->vri_linkid;
	otc.otc_entry.otce_flags = 0;
	bcopy(mac, otc.otc_entry.otce_mac, ETHERADDRL);
	bcopy(otp, &otc.otc_entry.otce_dest, sizeof (overlay_target_point_t));

	ret = ioctl(vip->vdi_overlayfd, OVERLAY_TARG_CACHE_SET, &otc);
	if (ret != 0) {
		switch (errno) {
		case EBADF:
		case EFAULT:
		case ENOTSUP:
			libvarpd_panic("received bad errno from "
			    "OVERLAY_TARG_CACHE_SET: %d", errno);
		default:
			break;
		}
	}
}

void
libvarpd_fma_degrade(varpd_provider_handle_t *vph, const char *msg)
{
	int ret;
	varpd_instance_t *inst = (varpd_instance_t *)vph;

	ret = libvarpd_overlay_degrade(inst, msg);
	switch (ret) {
	case ENOENT:
	case EFAULT:
		libvarpd_panic("received bad errno from degrade ioctl: %d",
		    errno);
	default:
		break;
	}
}

void
libvarpd_fma_restore(varpd_provider_handle_t *vph)
{
	int ret;
	varpd_instance_t *inst = (varpd_instance_t *)vph;

	ret = libvarpd_overlay_restore(inst);
	switch (ret) {
	case ENOENT:
	case EFAULT:
		libvarpd_panic("received bad errno from restore ioctl: %d",
		    errno);
	default:
		break;
	}
}
