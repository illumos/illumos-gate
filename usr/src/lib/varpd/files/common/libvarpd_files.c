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
 * Copyright 2015, Joyent, Inc.
 */

/*
 * Files based plug-in for varpd
 *
 * This is a dynamic varpd plug-in that has a static backing store. It's really
 * nothing more than a glorified version of /etc/ethers, though it facilitates
 * a bit more. The files module allows for the full set of mappings to be fixed
 * at creation time. In addition, it also provides support for proxying ARP,
 * NDP, and DHCP.
 *
 * At this time, the plugin requires that the destination type involve both an
 * IP address and a port; however, there's no reason that this cannot be made
 * more flexible as we have additional encapsulation algorithms that support it.
 * The plug-in only has a single property, which is the location of the JSON
 * file. The JSON file itself looks something like:
 *
 *	{
 *		"aa:bb:cc:dd:ee:ff": {
 *			"arp": "10.23.69.1",
 *			"ndp": "2600:3c00::f03c:91ff:fe96:a264",
 *			"ip": "192.168.1.1",
 *			"port": 8080
 *		},
 *		...
 *	}
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
#include <sys/stat.h>
#include <fcntl.h>
#include <libnvpair.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ethernet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libvarpd_files_json.h>

typedef struct varpd_files {
	overlay_plugin_dest_t	vaf_dest;	/* RO */
	varpd_provider_handle_t	*vaf_hdl;	/* RO */
	char			*vaf_path;	/* WO */
	nvlist_t		*vaf_nvl;	/* WO */
	uint64_t		vaf_nmisses;	/* Atomic */
	uint64_t		vaf_narp;	/* Atomic */
} varpd_files_t;

static const char *varpd_files_props[] = {
	"files/config"
};

static boolean_t
varpd_files_valid_dest(overlay_plugin_dest_t dest)
{
	if (dest & ~(OVERLAY_PLUGIN_D_IP | OVERLAY_PLUGIN_D_PORT))
		return (B_FALSE);

	if (!(dest & (OVERLAY_PLUGIN_D_IP | OVERLAY_PLUGIN_D_PORT)))
		return (B_FALSE);

	return (B_TRUE);
}

static int
varpd_files_create(varpd_provider_handle_t *hdl, void **outp,
    overlay_plugin_dest_t dest)
{
	varpd_files_t *vaf;

	if (varpd_files_valid_dest(dest) == B_FALSE)
		return (ENOTSUP);

	vaf = umem_alloc(sizeof (varpd_files_t), UMEM_DEFAULT);
	if (vaf == NULL)
		return (ENOMEM);

	bzero(vaf, sizeof (varpd_files_t));
	vaf->vaf_dest = dest;
	vaf->vaf_path = NULL;
	vaf->vaf_nvl = NULL;
	vaf->vaf_hdl = hdl;
	*outp = vaf;
	return (0);
}

static int
varpd_files_normalize_nvlist(varpd_files_t *vaf, nvlist_t *nvl)
{
	int ret;
	nvlist_t *out;
	nvpair_t *pair;

	if ((ret = nvlist_alloc(&out, NV_UNIQUE_NAME, 0)) != 0)
		return (ret);

	for (pair = nvlist_next_nvpair(nvl, NULL); pair != NULL;
	    pair = nvlist_next_nvpair(nvl, pair)) {
		char *name, fname[ETHERADDRSTRL];
		nvlist_t *data;
		struct ether_addr ether, *e;
		e = &ether;

		if (nvpair_type(pair) != DATA_TYPE_NVLIST) {
			nvlist_free(out);
			return (EINVAL);
		}

		name = nvpair_name(pair);
		if ((ret = nvpair_value_nvlist(pair, &data)) != 0) {
			nvlist_free(out);
			return (EINVAL);
		}

		if (ether_aton_r(name, e) == NULL) {
			nvlist_free(out);
			return (EINVAL);
		}

		if (ether_ntoa_r(e, fname) == NULL) {
			nvlist_free(out);
			return (ENOMEM);
		}

		if ((ret = nvlist_add_nvlist(out, fname, data)) != 0) {
			nvlist_free(out);
			return (EINVAL);
		}
	}

	vaf->vaf_nvl = out;
	return (0);
}

static int
varpd_files_start(void *arg)
{
	int fd, ret;
	void *maddr;
	struct stat st;
	nvlist_t *nvl;
	varpd_files_t *vaf = arg;

	if (vaf->vaf_path == NULL)
		return (EAGAIN);

	if ((fd = open(vaf->vaf_path, O_RDONLY)) < 0)
		return (errno);

	if (fstat(fd, &st) != 0) {
		ret = errno;
		if (close(fd) != 0)
			abort();
		return (ret);
	}

	maddr = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE,
	    fd, 0);
	if (maddr == NULL) {
		ret = errno;
		if (close(fd) != 0)
			abort();
		return (ret);
	}

	ret = nvlist_parse_json(maddr, st.st_size, &nvl,
	    NVJSON_FORCE_INTEGER, NULL);
	if (ret == 0) {
		ret = varpd_files_normalize_nvlist(vaf, nvl);
		nvlist_free(nvl);
	}
	if (munmap(maddr, st.st_size) != 0)
		abort();
	if (close(fd) != 0)
		abort();

	return (ret);
}

static void
varpd_files_stop(void *arg)
{
	varpd_files_t *vaf = arg;

	nvlist_free(vaf->vaf_nvl);
	vaf->vaf_nvl = NULL;
}

static void
varpd_files_destroy(void *arg)
{
	varpd_files_t *vaf = arg;

	assert(vaf->vaf_nvl == NULL);
	if (vaf->vaf_path != NULL) {
		umem_free(vaf->vaf_path, strlen(vaf->vaf_path) + 1);
		vaf->vaf_path = NULL;
	}
	umem_free(vaf, sizeof (varpd_files_t));
}

static void
varpd_files_lookup(void *arg, varpd_query_handle_t *qh,
    const overlay_targ_lookup_t *otl, overlay_target_point_t *otp)
{
	char macstr[ETHERADDRSTRL], *ipstr;
	nvlist_t *nvl;
	varpd_files_t *vaf = arg;
	int32_t port;
	static const uint8_t bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

	/* We don't support a default */
	if (otl == NULL) {
		libvarpd_plugin_query_reply(qh, VARPD_LOOKUP_DROP);
		return;
	}

	if (otl->otl_sap == ETHERTYPE_ARP) {
		libvarpd_plugin_proxy_arp(vaf->vaf_hdl, qh, otl);
		return;
	}

	if (otl->otl_sap == ETHERTYPE_IPV6 &&
	    otl->otl_dstaddr[0] == 0x33 &&
	    otl->otl_dstaddr[1] == 0x33) {
		libvarpd_plugin_proxy_ndp(vaf->vaf_hdl, qh, otl);
		return;
	}

	if (otl->otl_sap == ETHERTYPE_IP &&
	    bcmp(otl->otl_dstaddr, bcast, ETHERADDRL) == 0) {
		char *mac;
		struct ether_addr a, *addr;

		addr = &a;
		if (ether_ntoa_r((struct ether_addr *)otl->otl_srcaddr,
		    macstr) == NULL) {
			libvarpd_plugin_query_reply(qh, VARPD_LOOKUP_DROP);
			return;
		}

		if (nvlist_lookup_nvlist(vaf->vaf_nvl, macstr, &nvl) != 0) {
			libvarpd_plugin_query_reply(qh, VARPD_LOOKUP_DROP);
			return;
		}

		if (nvlist_lookup_string(nvl, "dhcp-proxy", &mac) != 0) {
			libvarpd_plugin_query_reply(qh, VARPD_LOOKUP_DROP);
			return;
		}

		if (ether_aton_r(mac, addr) == NULL) {
			libvarpd_plugin_query_reply(qh, VARPD_LOOKUP_DROP);
			return;
		}

		libvarpd_plugin_proxy_dhcp(vaf->vaf_hdl, qh, otl);
		return;
	}

	if (ether_ntoa_r((struct ether_addr *)otl->otl_dstaddr,
	    macstr) == NULL) {
		libvarpd_plugin_query_reply(qh, VARPD_LOOKUP_DROP);
		return;
	}

	if (nvlist_lookup_nvlist(vaf->vaf_nvl, macstr, &nvl) != 0) {
		libvarpd_plugin_query_reply(qh, VARPD_LOOKUP_DROP);
		return;
	}

	if (nvlist_lookup_int32(nvl, "port", &port) != 0) {
		libvarpd_plugin_query_reply(qh, VARPD_LOOKUP_DROP);
		return;
	}

	if (port <= 0 || port > UINT16_MAX) {
		libvarpd_plugin_query_reply(qh, VARPD_LOOKUP_DROP);
		return;
	}
	otp->otp_port = port;

	if (nvlist_lookup_string(nvl, "ip", &ipstr) != 0) {
		libvarpd_plugin_query_reply(qh, VARPD_LOOKUP_DROP);
		return;
	}

	/*
	 * Try to parse it as a v6 address and then if it's not, try to
	 * transform it into a v4 address which we'll then wrap it into a v4
	 * mapped address.
	 */
	if (inet_pton(AF_INET6, ipstr, &otp->otp_ip) != 1) {
		uint32_t v4;
		if (inet_pton(AF_INET, ipstr, &v4) != 1) {
			libvarpd_plugin_query_reply(qh, VARPD_LOOKUP_DROP);
			return;
		}
		IN6_IPADDR_TO_V4MAPPED(v4, &otp->otp_ip);
	}

	libvarpd_plugin_query_reply(qh, VARPD_LOOKUP_OK);
}

/* ARGSUSED */
static int
varpd_files_nprops(void *arg, uint_t *nprops)
{
	*nprops = 1;
	return (0);
}

/* ARGSUSED */
static int
varpd_files_propinfo(void *arg, uint_t propid, varpd_prop_handle_t *vph)
{
	if (propid != 0)
		return (EINVAL);

	libvarpd_prop_set_name(vph, varpd_files_props[0]);
	libvarpd_prop_set_prot(vph, OVERLAY_PROP_PERM_RRW);
	libvarpd_prop_set_type(vph, OVERLAY_PROP_T_STRING);
	libvarpd_prop_set_nodefault(vph);
	return (0);
}

static int
varpd_files_getprop(void *arg, const char *pname, void *buf, uint32_t *sizep)
{
	varpd_files_t *vaf = arg;

	if (strcmp(pname, varpd_files_props[0]) != 0)
		return (EINVAL);

	if (vaf->vaf_path != NULL) {
		size_t len = strlen(vaf->vaf_path) + 1;
		if (*sizep < len)
			return (EOVERFLOW);
		*sizep = len;
		(void) strlcpy(buf, vaf->vaf_path, *sizep);

	} else {
		*sizep = 0;
	}

	return (0);
}

static int
varpd_files_setprop(void *arg, const char *pname, const void *buf,
    const uint32_t size)
{
	varpd_files_t *vaf = arg;

	if (strcmp(pname, varpd_files_props[0]) != 0)
		return (EINVAL);

	if (vaf->vaf_path != NULL)
		umem_free(vaf->vaf_path, strlen(vaf->vaf_path) + 1);

	vaf->vaf_path = umem_alloc(size, UMEM_DEFAULT);
	if (vaf->vaf_path == NULL)
		return (ENOMEM);
	(void) strlcpy(vaf->vaf_path, buf, size);
	return (0);
}

static int
varpd_files_save(void *arg, nvlist_t *nvp)
{
	int ret;
	varpd_files_t *vaf = arg;

	if (vaf->vaf_path == NULL)
		return (0);

	if ((ret = nvlist_add_string(nvp, varpd_files_props[0],
	    vaf->vaf_path)) != 0)
		return (ret);

	if ((ret = nvlist_add_uint64(nvp, "files/vaf_nmisses",
	    vaf->vaf_nmisses)) != 0)
		return (ret);

	if ((ret = nvlist_add_uint64(nvp, "files/vaf_narp",
	    vaf->vaf_narp)) != 0)
		return (ret);
	return (0);
}

static int
varpd_files_restore(nvlist_t *nvp, varpd_provider_handle_t *hdl,
    overlay_plugin_dest_t dest, void **outp)
{
	varpd_files_t *vaf;
	char *str;
	int ret;
	uint64_t nmisses, narp;

	if (varpd_files_valid_dest(dest) == B_FALSE)
		return (EINVAL);

	ret = nvlist_lookup_string(nvp, varpd_files_props[0], &str);
	if (ret != 0 && ret != ENOENT)
		return (ret);
	else if (ret == ENOENT)
		str = NULL;

	if (nvlist_lookup_uint64(nvp, "files/vaf_nmisses", &nmisses) != 0)
		return (EINVAL);
	if (nvlist_lookup_uint64(nvp, "files/vaf_narp", &narp) != 0)
		return (EINVAL);

	vaf = umem_alloc(sizeof (varpd_files_t), UMEM_DEFAULT);
	if (vaf == NULL)
		return (ENOMEM);

	bzero(vaf, sizeof (varpd_files_t));
	vaf->vaf_dest = dest;
	if (str != NULL) {
		size_t len = strlen(str) + 1;
		vaf->vaf_path = umem_alloc(len, UMEM_DEFAULT);
		if (vaf->vaf_path == NULL) {
			umem_free(vaf, sizeof (varpd_files_t));
			return (ENOMEM);
		}
		(void) strlcpy(vaf->vaf_path, str, len);
	}

	vaf->vaf_hdl = hdl;
	*outp = vaf;
	return (0);
}

static void
varpd_files_proxy_arp(void *arg, varpd_arp_handle_t *vah, int kind,
    const struct sockaddr *sock, uint8_t *out)
{
	varpd_files_t *vaf = arg;
	const struct sockaddr_in *ip;
	const struct sockaddr_in6 *ip6;
	nvpair_t *pair;

	if (kind != VARPD_QTYPE_ETHERNET) {
		libvarpd_plugin_arp_reply(vah, VARPD_LOOKUP_DROP);
		return;
	}

	if (sock->sa_family != AF_INET && sock->sa_family != AF_INET6) {
		libvarpd_plugin_arp_reply(vah, VARPD_LOOKUP_DROP);
		return;
	}

	ip = (const struct sockaddr_in *)sock;
	ip6 = (const struct sockaddr_in6 *)sock;
	for (pair = nvlist_next_nvpair(vaf->vaf_nvl, NULL); pair != NULL;
	    pair = nvlist_next_nvpair(vaf->vaf_nvl, pair)) {
		char *mac, *ipstr;
		nvlist_t *data;
		struct in_addr ia;
		struct in6_addr ia6;
		struct ether_addr ether, *e;
		e = &ether;

		if (nvpair_type(pair) != DATA_TYPE_NVLIST)
			continue;

		mac = nvpair_name(pair);
		if (nvpair_value_nvlist(pair, &data) != 0)
			continue;


		if (sock->sa_family == AF_INET) {
			if (nvlist_lookup_string(data, "arp", &ipstr) != 0)
				continue;

			if (inet_pton(AF_INET, ipstr, &ia) != 1)
				continue;

			if (bcmp(&ia, &ip->sin_addr,
			    sizeof (struct in_addr)) != 0)
				continue;
		} else {
			if (nvlist_lookup_string(data, "ndp", &ipstr) != 0)
				continue;

			if (inet_pton(AF_INET6, ipstr, &ia6) != 1)
				continue;

			if (bcmp(&ia6, &ip6->sin6_addr,
			    sizeof (struct in6_addr)) != 0)
				continue;
		}

		if (ether_aton_r(mac, e) == NULL) {
			libvarpd_plugin_arp_reply(vah, VARPD_LOOKUP_DROP);
			return;
		}

		bcopy(e, out, ETHERADDRL);
		libvarpd_plugin_arp_reply(vah, VARPD_LOOKUP_OK);
		return;
	}

	libvarpd_plugin_arp_reply(vah, VARPD_LOOKUP_DROP);
}

static void
varpd_files_proxy_dhcp(void *arg, varpd_dhcp_handle_t *vdh, int type,
    const overlay_targ_lookup_t *otl, uint8_t *out)
{
	varpd_files_t *vaf = arg;
	nvlist_t *nvl;
	char macstr[ETHERADDRSTRL], *mac;
	struct ether_addr a, *addr;

	addr = &a;
	if (type != VARPD_QTYPE_ETHERNET) {
		libvarpd_plugin_dhcp_reply(vdh, VARPD_LOOKUP_DROP);
		return;
	}

	if (ether_ntoa_r((struct ether_addr *)otl->otl_srcaddr,
	    macstr) == NULL) {
		libvarpd_plugin_dhcp_reply(vdh, VARPD_LOOKUP_DROP);
		return;
	}

	if (nvlist_lookup_nvlist(vaf->vaf_nvl, macstr, &nvl) != 0) {
		libvarpd_plugin_dhcp_reply(vdh, VARPD_LOOKUP_DROP);
		return;
	}

	if (nvlist_lookup_string(nvl, "dhcp-proxy", &mac) != 0) {
		libvarpd_plugin_dhcp_reply(vdh, VARPD_LOOKUP_DROP);
		return;
	}

	if (ether_aton_r(mac, addr) == NULL) {
		libvarpd_plugin_dhcp_reply(vdh, VARPD_LOOKUP_DROP);
		return;
	}

	bcopy(addr, out, ETHERADDRL);
	libvarpd_plugin_dhcp_reply(vdh, VARPD_LOOKUP_OK);
}

static const varpd_plugin_ops_t varpd_files_ops = {
	0,
	varpd_files_create,
	varpd_files_start,
	varpd_files_stop,
	varpd_files_destroy,
	NULL,
	varpd_files_lookup,
	varpd_files_nprops,
	varpd_files_propinfo,
	varpd_files_getprop,
	varpd_files_setprop,
	varpd_files_save,
	varpd_files_restore,
	varpd_files_proxy_arp,
	varpd_files_proxy_dhcp
};

#pragma init(varpd_files_init)
static void
varpd_files_init(void)
{
	int err;
	varpd_plugin_register_t *vpr;

	vpr = libvarpd_plugin_alloc(VARPD_CURRENT_VERSION, &err);
	if (vpr == NULL)
		return;

	vpr->vpr_mode = OVERLAY_TARGET_DYNAMIC;
	vpr->vpr_name = "files";
	vpr->vpr_ops = &varpd_files_ops;
	(void) libvarpd_plugin_register(vpr);
	libvarpd_plugin_free(vpr);
}
