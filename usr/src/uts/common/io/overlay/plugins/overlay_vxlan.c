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
 * Copyright 2018 Joyent, Inc.
 */

/*
 * VXLAN encapsulation module
 *
 *
 * The VXLAN header looks as follows in network byte order:
 *
 * |0        3| 4 |5                     31|
 * +----------+---+------------------------+
 * | Reserved | I | Reserved               |
 * +---------------------------------------+
 * | Virtual Network ID         | Reserved |
 * +----------------------------+----------+
 * |0                         23|24      31|
 *
 * All reserved values must be 0. The I bit must be 1. We call the top
 * word the VXLAN magic field for the time being. The second word is
 * definitely not the most friendly way to operate. Specifically, the ID
 * is a 24-bit big endian value, but we have to make sure not to use the
 * reserved byte.
 *
 * For us, VXLAN encapsulation is a fairly straightforward implementation. It
 * only has two properties, a listen_ip and a listen_port. These determine on
 * what address we should be listening on. While we do not have a default
 * address to listen upon, we do have a default port, which is the IANA assigned
 * port for VXLAN -- 4789.
 */

#include <sys/overlay_plugin.h>
#include <sys/modctl.h>
#include <sys/errno.h>
#include <sys/byteorder.h>
#include <sys/vxlan.h>
#include <inet/ip.h>
#include <netinet/in.h>
#include <sys/strsun.h>
#include <netinet/udp.h>

static const char *vxlan_ident = "vxlan";
static uint16_t vxlan_defport = IPPORT_VXLAN;

/*
 * Should we enable UDP source port hashing for fanout.
 */
boolean_t vxlan_fanout = B_TRUE;

/*
 * This represents the size in bytes that we want to allocate when allocating a
 * vxlan header block. This is intended such that lower levels can try and use
 * the message block that we allocate for the IP and UPD header. The hope is
 * that even if this is tunneled, that this is enough space.
 *
 * The vxlan_noalloc_min value represents the minimum amount of space we need to
 * consider not allocating a message block and just passing it down the stack in
 * this form. This number assumes that we have a VLAN tag, so 18 byte Ethernet
 * header, 20 byte IP header, 8 byte UDP header, and 8 byte VXLAN header.
 */
uint_t vxlan_alloc_size = 128;
uint_t vxlan_noalloc_min = 54;

static const char *vxlan_props[] = {
	"vxlan/listen_ip",
	"vxlan/listen_port",
	NULL
};

typedef struct vxlan {
	kmutex_t vxl_lock;
	overlay_handle_t vxl_oh;
	uint16_t vxl_lport;
	boolean_t vxl_hladdr;
	struct in6_addr vxl_laddr;
} vxlan_t;

static int
vxlan_o_init(overlay_handle_t oh, void **outp)
{
	vxlan_t *vxl;

	vxl = kmem_alloc(sizeof (vxlan_t), KM_SLEEP);
	*outp = vxl;
	mutex_init(&vxl->vxl_lock, NULL, MUTEX_DRIVER, NULL);
	vxl->vxl_oh = oh;
	vxl->vxl_lport = vxlan_defport;
	vxl->vxl_hladdr = B_FALSE;

	return (0);
}

static void
vxlan_o_fini(void *arg)
{
	vxlan_t *vxl = arg;

	mutex_destroy(&vxl->vxl_lock);
	kmem_free(arg, sizeof (vxlan_t));
}

static int
vxlan_o_socket(void *arg, int *dp, int *fp, int *pp, struct sockaddr *addr,
    socklen_t *slenp)
{
	vxlan_t *vxl = arg;
	struct sockaddr_in6 *in;

	in = (struct sockaddr_in6 *)addr;
	*dp = AF_INET6;
	*fp = SOCK_DGRAM;
	*pp = 0;
	bzero(in, sizeof (struct sockaddr_in6));
	in->sin6_family = AF_INET6;

	/*
	 * We should consider a more expressive private errno set that
	 * provider's can use.
	 */
	mutex_enter(&vxl->vxl_lock);
	if (vxl->vxl_hladdr == B_FALSE) {
		mutex_exit(&vxl->vxl_lock);
		return (EINVAL);
	}
	in->sin6_port = htons(vxl->vxl_lport);
	in->sin6_addr = vxl->vxl_laddr;
	mutex_exit(&vxl->vxl_lock);
	*slenp = sizeof (struct sockaddr_in6);

	return (0);
}

static int
vxlan_o_sockopt(ksocket_t ksock)
{
	int val, err;
	if (vxlan_fanout == B_FALSE)
		return (0);

	val = UDP_HASH_VXLAN;
	err = ksocket_setsockopt(ksock, IPPROTO_UDP, UDP_SRCPORT_HASH, &val,
	    sizeof (val), kcred);
	return (err);
}

/* ARGSUSED */
static int
vxlan_o_encap(void *arg, mblk_t *mp, ovep_encap_info_t *einfop,
    mblk_t **outp)
{
	mblk_t *ob;
	vxlan_hdr_t *vxh;

	ASSERT(einfop->ovdi_id < (1 << 24));

	if (DB_REF(mp) != 1 || mp->b_rptr - vxlan_noalloc_min < DB_BASE(mp)) {
		/*
		 * This allocation could get hot. We may want to have a good
		 * way to cache and handle this allocation the same way that IP
		 * does with keeping around a message block per entry, or
		 * basically treating this as an immutable message block in the
		 * system. Basically freemsg() will be a nop, but we'll do the
		 * right thing with respect to the rest of the chain.
		 */
		ob = allocb(vxlan_alloc_size, 0);
		if (ob == NULL)
			return (ENOMEM);

		ob->b_wptr = DB_LIM(ob);
		ob->b_rptr = ob->b_wptr;
		ob->b_cont = mp;
	} else {
		ob = mp;
	}
	ob->b_rptr -= VXLAN_HDR_LEN;

	vxh = (vxlan_hdr_t *)ob->b_rptr;
	vxh->vxlan_flags = ntohl(VXLAN_F_VDI);
	vxh->vxlan_id = htonl((uint32_t)einfop->ovdi_id << VXLAN_ID_SHIFT);
	*outp = ob;

	return (0);
}

/* ARGSUSED */
static int
vxlan_o_decap(void *arg, mblk_t *mp, ovep_encap_info_t *dinfop)
{
	vxlan_hdr_t *vxh;

	if (MBLKL(mp) < sizeof (vxlan_hdr_t))
		return (EINVAL);
	vxh = (vxlan_hdr_t *)mp->b_rptr;
	if ((ntohl(vxh->vxlan_flags) & VXLAN_F_VDI) == 0)
		return (EINVAL);

	dinfop->ovdi_id = ntohl(vxh->vxlan_id) >> VXLAN_ID_SHIFT;
	dinfop->ovdi_hdr_size = VXLAN_HDR_LEN;

	return (0);
}

static int
vxlan_o_getprop(void *arg, const char *pr_name, void *buf, uint32_t *bufsize)
{
	vxlan_t *vxl = arg;

	/* vxlan/listen_ip */
	if (strcmp(pr_name, vxlan_props[0]) == 0) {
		if (*bufsize < sizeof (struct in6_addr))
			return (EOVERFLOW);

		mutex_enter(&vxl->vxl_lock);
		if (vxl->vxl_hladdr == B_FALSE) {
			*bufsize = 0;
		} else {
			bcopy(&vxl->vxl_laddr, buf, sizeof (struct in6_addr));
			*bufsize = sizeof (struct in6_addr);
		}
		mutex_exit(&vxl->vxl_lock);
		return (0);
	}

	/* vxlan/listen_port */
	if (strcmp(pr_name, vxlan_props[1]) == 0) {
		uint64_t val;
		if (*bufsize < sizeof (uint64_t))
			return (EOVERFLOW);

		mutex_enter(&vxl->vxl_lock);
		val = vxl->vxl_lport;
		bcopy(&val, buf, sizeof (uint64_t));
		*bufsize = sizeof (uint64_t);
		mutex_exit(&vxl->vxl_lock);
		return (0);
	}

	return (EINVAL);
}

static int
vxlan_o_setprop(void *arg, const char *pr_name, const void *buf,
    uint32_t bufsize)
{
	vxlan_t *vxl = arg;

	/* vxlan/listen_ip */
	if (strcmp(pr_name, vxlan_props[0]) == 0) {
		const struct in6_addr *ipv6 = buf;
		if (bufsize != sizeof (struct in6_addr))
			return (EINVAL);

		if (IN6_IS_ADDR_V4COMPAT(ipv6))
			return (EINVAL);

		if (IN6_IS_ADDR_MULTICAST(ipv6))
			return (EINVAL);

		if (IN6_IS_ADDR_6TO4(ipv6))
			return (EINVAL);

		if (IN6_IS_ADDR_V4MAPPED(ipv6)) {
			ipaddr_t v4;
			IN6_V4MAPPED_TO_IPADDR(ipv6, v4);
			if (IN_MULTICAST(v4))
				return (EINVAL);
		}

		mutex_enter(&vxl->vxl_lock);
		vxl->vxl_hladdr = B_TRUE;
		bcopy(ipv6, &vxl->vxl_laddr, sizeof (struct in6_addr));
		mutex_exit(&vxl->vxl_lock);

		return (0);
	}

	/* vxlan/listen_port */
	if (strcmp(pr_name, vxlan_props[1]) == 0) {
		const uint64_t *valp = buf;
		if (bufsize != 8)
			return (EINVAL);

		if (*valp == 0 || *valp > UINT16_MAX)
			return (EINVAL);

		mutex_enter(&vxl->vxl_lock);
		vxl->vxl_lport = *valp;
		mutex_exit(&vxl->vxl_lock);
		return (0);
	}
	return (EINVAL);
}

static int
vxlan_o_propinfo(const char *pr_name, overlay_prop_handle_t phdl)
{
	/* vxlan/listen_ip */
	if (strcmp(pr_name, vxlan_props[0]) == 0) {
		overlay_prop_set_name(phdl, vxlan_props[0]);
		overlay_prop_set_prot(phdl, OVERLAY_PROP_PERM_RRW);
		overlay_prop_set_type(phdl, OVERLAY_PROP_T_IP);
		overlay_prop_set_nodefault(phdl);
		return (0);
	}

	if (strcmp(pr_name, vxlan_props[1]) == 0) {
		overlay_prop_set_name(phdl, vxlan_props[1]);
		overlay_prop_set_prot(phdl, OVERLAY_PROP_PERM_RRW);
		overlay_prop_set_type(phdl, OVERLAY_PROP_T_UINT);
		(void) overlay_prop_set_default(phdl, &vxlan_defport,
		    sizeof (vxlan_defport));
		overlay_prop_set_range_uint32(phdl, 1, UINT16_MAX);
		return (0);
	}

	return (EINVAL);
}

static struct overlay_plugin_ops vxlan_o_ops = {
	0,
	vxlan_o_init,
	vxlan_o_fini,
	vxlan_o_encap,
	vxlan_o_decap,
	vxlan_o_socket,
	vxlan_o_sockopt,
	vxlan_o_getprop,
	vxlan_o_setprop,
	vxlan_o_propinfo
};

static struct modlmisc vxlan_modlmisc = {
	&mod_miscops,
	"VXLAN encap plugin"
};

static struct modlinkage vxlan_modlinkage = {
	MODREV_1,
	&vxlan_modlmisc
};

int
_init(void)
{
	int err;
	overlay_plugin_register_t *ovrp;

	ovrp = overlay_plugin_alloc(OVEP_VERSION);
	if (ovrp == NULL)
		return (ENOTSUP);
	ovrp->ovep_name = vxlan_ident;
	ovrp->ovep_ops = &vxlan_o_ops;
	ovrp->ovep_id_size = VXLAN_ID_LEN;
	ovrp->ovep_flags = OVEP_F_VLAN_TAG;
	ovrp->ovep_dest = OVERLAY_PLUGIN_D_IP | OVERLAY_PLUGIN_D_PORT;
	ovrp->ovep_props = vxlan_props;

	if ((err = overlay_plugin_register(ovrp)) == 0) {
		if ((err = mod_install(&vxlan_modlinkage)) != 0) {
			(void) overlay_plugin_unregister(vxlan_ident);
		}
	}

	overlay_plugin_free(ovrp);
	return (err);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&vxlan_modlinkage, modinfop));
}

int
_fini(void)
{
	int err;

	if ((err = overlay_plugin_unregister(vxlan_ident)) != 0)
		return (err);

	return (mod_remove(&vxlan_modlinkage));
}
