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
 * Point to point plug-in for varpd.
 *
 * This plugin implements a simple point to point plugin for a packet. It
 * represents the traditional tunnel, just in overlay form. As such, the only
 * properties it needs are those to determine where to send everything. At this
 * time, we don't allow a multicast address; however, there's no reason that the
 * direct plugin shouldn't in theory support multicast, though when implementing
 * it the best path will become clear.
 *
 * In general this module has been designed to make it easy to support a
 * destination of either IP or IP and port; however, we restrict it to the
 * latter as we don't currently have an implementation that would allow us to
 * test that.
 */

#include <libvarpd_provider.h>
#include <umem.h>
#include <errno.h>
#include <thread.h>
#include <synch.h>
#include <strings.h>
#include <assert.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <libnvpair.h>

typedef struct varpd_direct {
	overlay_plugin_dest_t	vad_dest;	/* RO */
	mutex_t			vad_lock;	/* Protects the rest */
	boolean_t		vad_hip;
	boolean_t		vad_hport;
	struct in6_addr		vad_ip;
	uint16_t		vad_port;
} varpd_direct_t;

static const char *varpd_direct_props[] = {
	"direct/dest_ip",
	"direct/dest_port"
};

static boolean_t
varpd_direct_valid_dest(overlay_plugin_dest_t dest)
{
	if (dest & ~(OVERLAY_PLUGIN_D_IP | OVERLAY_PLUGIN_D_PORT))
		return (B_FALSE);

	if (!(dest & (OVERLAY_PLUGIN_D_IP | OVERLAY_PLUGIN_D_PORT)))
		return (B_FALSE);

	return (B_TRUE);
}

/* ARGSUSED */
static int
varpd_direct_create(varpd_provider_handle_t *hdl, void **outp,
    overlay_plugin_dest_t dest)
{
	int ret;
	varpd_direct_t *vdp;

	if (varpd_direct_valid_dest(dest) == B_FALSE)
		return (ENOTSUP);

	vdp = umem_alloc(sizeof (varpd_direct_t), UMEM_DEFAULT);
	if (vdp == NULL)
		return (ENOMEM);

	if ((ret = mutex_init(&vdp->vad_lock, USYNC_THREAD | LOCK_ERRORCHECK,
	    NULL)) != 0) {
		umem_free(vdp, sizeof (varpd_direct_t));
		return (ret);
	}

	vdp->vad_dest = dest;
	vdp->vad_hip = B_FALSE;
	vdp->vad_hport = B_FALSE;
	*outp = vdp;
	return (0);
}

static int
varpd_direct_start(void *arg)
{
	varpd_direct_t *vdp = arg;

	mutex_enter(&vdp->vad_lock);
	if (vdp->vad_hip == B_FALSE ||((vdp->vad_dest & OVERLAY_PLUGIN_D_IP) &&
	    vdp->vad_hport == B_FALSE)) {
		mutex_exit(&vdp->vad_lock);
		return (EAGAIN);
	}
	mutex_exit(&vdp->vad_lock);

	return (0);
}

/* ARGSUSED */
static void
varpd_direct_stop(void *arg)
{
}

static void
varpd_direct_destroy(void *arg)
{
	varpd_direct_t *vdp = arg;

	if (mutex_destroy(&vdp->vad_lock) != 0)
		abort();
	umem_free(vdp, sizeof (varpd_direct_t));
}

static int
varpd_direct_default(void *arg, overlay_target_point_t *otp)
{
	varpd_direct_t *vdp = arg;

	mutex_enter(&vdp->vad_lock);
	bcopy(&vdp->vad_ip, &otp->otp_ip, sizeof (struct in6_addr));
	otp->otp_port = vdp->vad_port;
	mutex_exit(&vdp->vad_lock);

	return (VARPD_LOOKUP_OK);
}

static int
varpd_direct_nprops(void *arg, uint_t *nprops)
{
	const varpd_direct_t *vdp = arg;

	*nprops = 0;
	if (vdp->vad_dest & OVERLAY_PLUGIN_D_ETHERNET)
		*nprops += 1;

	if (vdp->vad_dest & OVERLAY_PLUGIN_D_IP)
		*nprops += 1;

	if (vdp->vad_dest & OVERLAY_PLUGIN_D_PORT)
		*nprops += 1;

	assert(*nprops == 1 || *nprops == 2);

	return (0);
}

static int
varpd_direct_propinfo(void *arg, uint_t propid, varpd_prop_handle_t *vph)
{
	varpd_direct_t *vdp = arg;

	/*
	 * Because we only support IP + port combos right now, prop 0 should
	 * always be the IP. We don't support a port without an IP.
	 */
	assert(vdp->vad_dest & OVERLAY_PLUGIN_D_IP);
	if (propid == 0) {
		libvarpd_prop_set_name(vph, varpd_direct_props[0]);
		libvarpd_prop_set_prot(vph, OVERLAY_PROP_PERM_RRW);
		libvarpd_prop_set_type(vph, OVERLAY_PROP_T_IP);
		libvarpd_prop_set_nodefault(vph);
		return (0);
	}

	if (propid == 1 && vdp->vad_dest & OVERLAY_PLUGIN_D_PORT) {
		libvarpd_prop_set_name(vph, varpd_direct_props[1]);
		libvarpd_prop_set_prot(vph, OVERLAY_PROP_PERM_RRW);
		libvarpd_prop_set_type(vph, OVERLAY_PROP_T_UINT);
		libvarpd_prop_set_nodefault(vph);
		libvarpd_prop_set_range_uint32(vph, 1, UINT16_MAX);
		return (0);
	}

	return (EINVAL);
}

static int
varpd_direct_getprop(void *arg, const char *pname, void *buf, uint32_t *sizep)
{
	varpd_direct_t *vdp = arg;

	/* direct/dest_ip */
	if (strcmp(pname, varpd_direct_props[0]) == 0) {
		if (*sizep < sizeof (struct in6_addr))
			return (EOVERFLOW);
		mutex_enter(&vdp->vad_lock);
		if (vdp->vad_hip == B_FALSE) {
			*sizep = 0;
		} else {
			bcopy(&vdp->vad_ip, buf, sizeof (struct in6_addr));
			*sizep = sizeof (struct in6_addr);
		}
		mutex_exit(&vdp->vad_lock);
		return (0);
	}

	/* direct/dest_port */
	if (strcmp(pname, varpd_direct_props[1]) == 0) {
		uint64_t val;

		if (*sizep < sizeof (uint64_t))
			return (EOVERFLOW);
		mutex_enter(&vdp->vad_lock);
		if (vdp->vad_hport == B_FALSE) {
			*sizep = 0;
		} else {
			val = vdp->vad_port;
			bcopy(&val, buf, sizeof (uint64_t));
			*sizep = sizeof (uint64_t);
		}
		mutex_exit(&vdp->vad_lock);
		return (0);
	}

	return (EINVAL);
}

static int
varpd_direct_setprop(void *arg, const char *pname, const void *buf,
    const uint32_t size)
{
	varpd_direct_t *vdp = arg;

	/* direct/dest_ip */
	if (strcmp(pname, varpd_direct_props[0]) == 0) {
		const struct in6_addr *ipv6 = buf;

		if (size < sizeof (struct in6_addr))
			return (EOVERFLOW);

		if (IN6_IS_ADDR_V4COMPAT(ipv6))
			return (EINVAL);

		if (IN6_IS_ADDR_6TO4(ipv6))
			return (EINVAL);

		mutex_enter(&vdp->vad_lock);
		bcopy(buf, &vdp->vad_ip, sizeof (struct in6_addr));
		vdp->vad_hip = B_TRUE;
		mutex_exit(&vdp->vad_lock);
		return (0);
	}

	/* direct/dest_port */
	if (strcmp(pname, varpd_direct_props[1]) == 0) {
		const uint64_t *valp = buf;
		if (size < sizeof (uint64_t))
			return (EOVERFLOW);

		if (*valp == 0 || *valp > UINT16_MAX)
			return (EINVAL);

		mutex_enter(&vdp->vad_lock);
		vdp->vad_port = (uint16_t)*valp;
		vdp->vad_hport = B_TRUE;
		mutex_exit(&vdp->vad_lock);
		return (0);
	}

	return (EINVAL);
}

static int
varpd_direct_save(void *arg, nvlist_t *nvp)
{
	int ret;
	varpd_direct_t *vdp = arg;

	mutex_enter(&vdp->vad_lock);
	if (vdp->vad_hport == B_TRUE) {
		if ((ret = nvlist_add_uint16(nvp, varpd_direct_props[1],
		    vdp->vad_port)) != 0) {
			mutex_exit(&vdp->vad_lock);
			return (ret);
		}
	}

	if (vdp->vad_hip == B_TRUE) {
		char buf[INET6_ADDRSTRLEN];

		if (inet_ntop(AF_INET6, &vdp->vad_ip, buf, sizeof (buf)) ==
		    NULL)
			abort();
		if ((ret = nvlist_add_string(nvp, varpd_direct_props[0],
		    buf)) != 0) {
			mutex_exit(&vdp->vad_lock);
			return (ret);
		}
	}
	mutex_exit(&vdp->vad_lock);

	return (0);
}

/* ARGSUSED */
static int
varpd_direct_restore(nvlist_t *nvp, varpd_provider_handle_t *hdl,
    overlay_plugin_dest_t dest, void **outp)
{
	int ret;
	char *ipstr;
	varpd_direct_t *vdp;

	if (varpd_direct_valid_dest(dest) == B_FALSE)
		return (ENOTSUP);

	vdp = umem_alloc(sizeof (varpd_direct_t), UMEM_DEFAULT);
	if (vdp == NULL)
		return (ENOMEM);

	if ((ret = mutex_init(&vdp->vad_lock, USYNC_THREAD | LOCK_ERRORCHECK,
	    NULL)) != 0) {
		umem_free(vdp, sizeof (varpd_direct_t));
		return (ret);
	}

	if ((ret = nvlist_lookup_uint16(nvp, varpd_direct_props[1],
	    &vdp->vad_port)) != 0) {
		if (ret != ENOENT) {
			if (mutex_destroy(&vdp->vad_lock) != 0)
				abort();
			umem_free(vdp, sizeof (varpd_direct_t));
			return (ret);
		}
		vdp->vad_hport = B_FALSE;
	} else {
		vdp->vad_hport = B_TRUE;
	}

	if ((ret = nvlist_lookup_string(nvp, varpd_direct_props[0],
	    &ipstr)) != 0) {
		if (ret != ENOENT) {
			if (mutex_destroy(&vdp->vad_lock) != 0)
				abort();
			umem_free(vdp, sizeof (varpd_direct_t));
			return (ret);
		}
		vdp->vad_hip = B_FALSE;
	} else {
		ret = inet_pton(AF_INET6, ipstr, &vdp->vad_ip);
		/*
		 * inet_pton is only defined to return -1 with errno set to
		 * EAFNOSUPPORT, which really, shouldn't happen.
		 */
		if (ret == -1) {
			assert(errno == EAFNOSUPPORT);
			abort();
		}
		if (ret == 0) {
			if (mutex_destroy(&vdp->vad_lock) != 0)
				abort();
			umem_free(vdp, sizeof (varpd_direct_t));
			return (EINVAL);
		}
	}

	*outp = vdp;
	return (0);
}

static const varpd_plugin_ops_t varpd_direct_ops = {
	0,
	varpd_direct_create,
	varpd_direct_start,
	varpd_direct_stop,
	varpd_direct_destroy,
	varpd_direct_default,
	NULL,
	varpd_direct_nprops,
	varpd_direct_propinfo,
	varpd_direct_getprop,
	varpd_direct_setprop,
	varpd_direct_save,
	varpd_direct_restore
};

#pragma init(varpd_direct_init)
static void
varpd_direct_init(void)
{
	int err;
	varpd_plugin_register_t *vpr;

	vpr = libvarpd_plugin_alloc(VARPD_CURRENT_VERSION, &err);
	if (vpr == NULL)
		return;

	vpr->vpr_mode = OVERLAY_TARGET_POINT;
	vpr->vpr_name = "direct";
	vpr->vpr_ops = &varpd_direct_ops;
	(void) libvarpd_plugin_register(vpr);
	libvarpd_plugin_free(vpr);
}
