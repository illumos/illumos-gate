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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*
 * gld - Generic LAN Driver Version 2, PSARC/1997/382
 *
 * This is a utility module that provides generic facilities for
 * LAN	drivers.  The DLPI protocol and most STREAMS interfaces
 * are handled here.
 *
 * It no longer provides compatibility with drivers
 * implemented according to the GLD v0 documentation published
 * in 1993. (See PSARC 2003/728)
 */


#include <sys/types.h>
#include <sys/errno.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/kmem.h>
#include <sys/stat.h>
#include <sys/modctl.h>
#include <sys/kstat.h>
#include <sys/debug.h>
#include <sys/note.h>
#include <sys/sysmacros.h>

#include <sys/byteorder.h>
#include <sys/strsun.h>
#include <sys/strsubr.h>
#include <sys/dlpi.h>
#include <sys/pattr.h>
#include <sys/ethernet.h>
#include <sys/ib/clients/ibd/ibd.h>
#include <sys/policy.h>
#include <sys/atomic.h>

#include <sys/multidata.h>
#include <sys/gld.h>
#include <sys/gldpriv.h>

#include <sys/ddi.h>
#include <sys/sunddi.h>

/*
 * Macros to increment statistics.
 */

/*
 * Increase kstats. Note this operation is not atomic. It can be used when
 * GLDM_LOCK_HELD_WRITE(macinfo).
 */
#define	BUMP(stats, vstats, stat, delta)	do {			\
	((stats)->stat) += (delta);					\
	_NOTE(CONSTANTCONDITION)					\
	if ((vstats) != NULL)						\
		((struct gld_stats *)(vstats))->stat += (delta);	\
	_NOTE(CONSTANTCONDITION)					\
} while (0)

#define	ATOMIC_BUMP_STAT(stat, delta)	do {			\
	_NOTE(CONSTANTCONDITION)				\
	if (sizeof ((stat)) == sizeof (uint32_t)) {		\
		atomic_add_32((uint32_t *)&(stat), (delta));	\
	_NOTE(CONSTANTCONDITION)				\
	} else if (sizeof ((stat)) == sizeof (uint64_t)) {	\
		atomic_add_64((uint64_t *)&(stat), (delta));	\
	}							\
	_NOTE(CONSTANTCONDITION)				\
} while (0)

#define	ATOMIC_BUMP(stats, vstats, stat, delta)	do {			\
	ATOMIC_BUMP_STAT((stats)->stat, (delta));			\
	_NOTE(CONSTANTCONDITION)					\
	if ((vstats) != NULL) {						\
		ATOMIC_BUMP_STAT(((struct gld_stats *)(vstats))->stat,	\
		    (delta));						\
	}								\
	_NOTE(CONSTANTCONDITION)					\
} while (0)

#define	UPDATE_STATS(stats, vstats, pktinfo, delta) {			\
	if ((pktinfo).isBroadcast) {					\
		ATOMIC_BUMP((stats), (vstats),				\
		    glds_brdcstxmt, (delta));				\
	} else if ((pktinfo).isMulticast) {				\
		ATOMIC_BUMP((stats), (vstats), glds_multixmt, (delta));	\
	}								\
	ATOMIC_BUMP((stats), (vstats), glds_bytexmt64,			\
	    ((pktinfo).pktLen));					\
	ATOMIC_BUMP((stats), (vstats), glds_pktxmt64, (delta));		\
}

#ifdef GLD_DEBUG
int gld_debug = GLDERRS;
#endif

/* called from gld_register */
static int gld_initstats(gld_mac_info_t *);

/* called from kstat mechanism, and from wsrv's get_statistics */
static int gld_update_kstat(kstat_t *, int);

/* statistics for additional vlans */
static int gld_init_vlan_stats(gld_vlan_t *);
static int gld_update_vlan_kstat(kstat_t *, int);

/* called from gld_getinfo */
static dev_info_t *gld_finddevinfo(dev_t);

/* called from wput, wsrv, unidata, and v0_sched to send a packet */
/* also from the source routing stuff for sending RDE protocol packets */
static int gld_start(queue_t *, mblk_t *, int, uint32_t);
static int gld_start_mdt(queue_t *, mblk_t *, int);

/* called from gld_start[_mdt] to loopback packet(s) in promiscuous mode */
static void gld_precv(gld_mac_info_t *, mblk_t *, uint32_t, struct gld_stats *);
static void gld_precv_mdt(gld_mac_info_t *, gld_vlan_t *, mblk_t *,
    pdesc_t *, pktinfo_t *);

/* receive group: called from gld_recv and gld_precv* with maclock held */
static void gld_sendup(gld_mac_info_t *, pktinfo_t *, mblk_t *,
    int (*)());
static int gld_accept(gld_t *, pktinfo_t *);
static int gld_mcmatch(gld_t *, pktinfo_t *);
static int gld_multicast(unsigned char *, gld_t *);
static int gld_paccept(gld_t *, pktinfo_t *);
static void gld_passon(gld_t *, mblk_t *, pktinfo_t *,
    void (*)(queue_t *, mblk_t *));
static mblk_t *gld_addudind(gld_t *, mblk_t *, pktinfo_t *, boolean_t);

/* wsrv group: called from wsrv, single threaded per queue */
static int gld_ioctl(queue_t *, mblk_t *);
static void gld_fastpath(gld_t *, queue_t *, mblk_t *);
static int gld_cmds(queue_t *, mblk_t *);
static mblk_t *gld_bindack(queue_t *, mblk_t *);
static int gld_notify_req(queue_t *, mblk_t *);
static int gld_udqos(queue_t *, mblk_t *);
static int gld_bind(queue_t *, mblk_t *);
static int gld_unbind(queue_t *, mblk_t *);
static int gld_inforeq(queue_t *, mblk_t *);
static int gld_unitdata(queue_t *, mblk_t *);
static int gldattach(queue_t *, mblk_t *);
static int gldunattach(queue_t *, mblk_t *);
static int gld_enable_multi(queue_t *, mblk_t *);
static int gld_disable_multi(queue_t *, mblk_t *);
static void gld_send_disable_multi(gld_mac_info_t *, gld_mcast_t *);
static int gld_promisc(queue_t *, mblk_t *, t_uscalar_t, boolean_t);
static int gld_physaddr(queue_t *, mblk_t *);
static int gld_setaddr(queue_t *, mblk_t *);
static int gld_get_statistics(queue_t *, mblk_t *);
static int gld_cap(queue_t *, mblk_t *);
static int gld_cap_ack(queue_t *, mblk_t *);
static int gld_cap_enable(queue_t *, mblk_t *);

/* misc utilities, some requiring various mutexes held */
static int gld_start_mac(gld_mac_info_t *);
static void gld_stop_mac(gld_mac_info_t *);
static void gld_set_ipq(gld_t *);
static void gld_flushqueue(queue_t *);
static glddev_t *gld_devlookup(int);
static int gld_findminor(glddev_t *);
static void gldinsque(void *, void *);
static void gldremque(void *);
void gld_bitrevcopy(caddr_t, caddr_t, size_t);
void gld_bitreverse(uchar_t *, size_t);
char *gld_macaddr_sprintf(char *, unsigned char *, int);
static gld_vlan_t *gld_add_vlan(gld_mac_info_t *, uint32_t vid);
static void gld_rem_vlan(gld_vlan_t *);
gld_vlan_t *gld_find_vlan(gld_mac_info_t *, uint32_t);
gld_vlan_t *gld_get_vlan(gld_mac_info_t *, uint32_t);

#ifdef GLD_DEBUG
static void gld_check_assertions(void);
extern void gld_sr_dump(gld_mac_info_t *);
#endif

/*
 * Allocate and zero-out "number" structures each of type "structure" in
 * kernel memory.
 */
#define	GLD_GETSTRUCT(structure, number)   \
	(kmem_zalloc((uint_t)(sizeof (structure) * (number)), KM_NOSLEEP))

#define	abs(a) ((a) < 0 ? -(a) : a)

uint32_t gld_global_options = GLD_OPT_NO_ETHRXSNAP;

/*
 * The device is of DL_ETHER type and is able to support VLAN by itself.
 */
#define	VLAN_CAPABLE(macinfo) \
	((macinfo)->gldm_type == DL_ETHER && \
	(macinfo)->gldm_send_tagged != NULL)

/*
 * The set of notifications generatable by GLD itself, the additional
 * set that can be generated if the MAC driver provide the link-state
 * tracking callback capability, and the set supported by the GLD
 * notification code below.
 *
 * PLEASE keep these in sync with what the code actually does!
 */
static const uint32_t gld_internal_notes =	DL_NOTE_PROMISC_ON_PHYS |
						DL_NOTE_PROMISC_OFF_PHYS |
						DL_NOTE_PHYS_ADDR;
static const uint32_t gld_linkstate_notes =	DL_NOTE_LINK_DOWN |
						DL_NOTE_LINK_UP |
						DL_NOTE_SPEED;
static const uint32_t gld_supported_notes =	DL_NOTE_PROMISC_ON_PHYS |
						DL_NOTE_PROMISC_OFF_PHYS |
						DL_NOTE_PHYS_ADDR |
						DL_NOTE_LINK_DOWN |
						DL_NOTE_LINK_UP |
						DL_NOTE_SPEED;

/* Media must correspond to #defines in gld.h */
static char *gld_media[] = {
	"unknown",	/* GLDM_UNKNOWN - driver cannot determine media */
	"aui",		/* GLDM_AUI */
	"bnc",		/* GLDM_BNC */
	"twpair",	/* GLDM_TP */
	"fiber",	/* GLDM_FIBER */
	"100baseT",	/* GLDM_100BT */
	"100vgAnyLan",	/* GLDM_VGANYLAN */
	"10baseT",	/* GLDM_10BT */
	"ring4",	/* GLDM_RING4 */
	"ring16",	/* GLDM_RING16 */
	"PHY/MII",	/* GLDM_PHYMII */
	"100baseTX",	/* GLDM_100BTX */
	"100baseT4",	/* GLDM_100BT4 */
	"unknown",	/* skip */
	"ipib",		/* GLDM_IB */
};

/* Must correspond to #defines in gld.h */
static char *gld_duplex[] = {
	"unknown",	/* GLD_DUPLEX_UNKNOWN - not known or not applicable */
	"half",		/* GLD_DUPLEX_HALF */
	"full"		/* GLD_DUPLEX_FULL */
};

/*
 * Interface types currently supported by GLD.
 * If you add new types, you must check all "XXX" strings in the GLD source
 * for implementation issues that may affect the support of your new type.
 * In particular, any type with gldm_addrlen > 6, or gldm_saplen != -2, will
 * require generalizing this GLD source to handle the new cases.  In other
 * words there are assumptions built into the code in a few places that must
 * be fixed.  Be sure to turn on DEBUG/ASSERT code when testing a new type.
 */
static gld_interface_t interfaces[] = {

	/* Ethernet Bus */
	{
		DL_ETHER,
		(uint_t)-1,
		sizeof (struct ether_header),
		gld_interpret_ether,
		NULL,
		gld_fastpath_ether,
		gld_unitdata_ether,
		gld_init_ether,
		gld_uninit_ether,
		"ether"
	},

	/* Fiber Distributed data interface */
	{
		DL_FDDI,
		4352,
		sizeof (struct fddi_mac_frm),
		gld_interpret_fddi,
		NULL,
		gld_fastpath_fddi,
		gld_unitdata_fddi,
		gld_init_fddi,
		gld_uninit_fddi,
		"fddi"
	},

	/* Token Ring interface */
	{
		DL_TPR,
		17914,
		-1,			/* variable header size */
		gld_interpret_tr,
		NULL,
		gld_fastpath_tr,
		gld_unitdata_tr,
		gld_init_tr,
		gld_uninit_tr,
		"tpr"
	},

	/* Infiniband */
	{
		DL_IB,
		4092,
		sizeof (struct ipoib_header),
		gld_interpret_ib,
		gld_interpret_mdt_ib,
		gld_fastpath_ib,
		gld_unitdata_ib,
		gld_init_ib,
		gld_uninit_ib,
		"ipib"
	},
};

/*
 * bit reversal lookup table.
 */
static	uchar_t bit_rev[] = {
	0x00, 0x80, 0x40, 0xc0, 0x20, 0xa0, 0x60, 0xe0, 0x10, 0x90, 0x50, 0xd0,
	0x30, 0xb0, 0x70, 0xf0, 0x08, 0x88, 0x48, 0xc8, 0x28, 0xa8, 0x68, 0xe8,
	0x18, 0x98, 0x58, 0xd8, 0x38, 0xb8, 0x78, 0xf8, 0x04, 0x84, 0x44, 0xc4,
	0x24, 0xa4, 0x64, 0xe4, 0x14, 0x94, 0x54, 0xd4, 0x34, 0xb4, 0x74, 0xf4,
	0x0c, 0x8c, 0x4c, 0xcc, 0x2c, 0xac, 0x6c, 0xec, 0x1c, 0x9c, 0x5c, 0xdc,
	0x3c, 0xbc, 0x7c, 0xfc, 0x02, 0x82, 0x42, 0xc2, 0x22, 0xa2, 0x62, 0xe2,
	0x12, 0x92, 0x52, 0xd2, 0x32, 0xb2, 0x72, 0xf2, 0x0a, 0x8a, 0x4a, 0xca,
	0x2a, 0xaa, 0x6a, 0xea, 0x1a, 0x9a, 0x5a, 0xda, 0x3a, 0xba, 0x7a, 0xfa,
	0x06, 0x86, 0x46, 0xc6, 0x26, 0xa6, 0x66, 0xe6, 0x16, 0x96, 0x56, 0xd6,
	0x36, 0xb6, 0x76, 0xf6, 0x0e, 0x8e, 0x4e, 0xce, 0x2e, 0xae, 0x6e, 0xee,
	0x1e, 0x9e, 0x5e, 0xde, 0x3e, 0xbe, 0x7e, 0xfe, 0x01, 0x81, 0x41, 0xc1,
	0x21, 0xa1, 0x61, 0xe1, 0x11, 0x91, 0x51, 0xd1, 0x31, 0xb1, 0x71, 0xf1,
	0x09, 0x89, 0x49, 0xc9, 0x29, 0xa9, 0x69, 0xe9, 0x19, 0x99, 0x59, 0xd9,
	0x39, 0xb9, 0x79, 0xf9, 0x05, 0x85, 0x45, 0xc5, 0x25, 0xa5, 0x65, 0xe5,
	0x15, 0x95, 0x55, 0xd5, 0x35, 0xb5, 0x75, 0xf5, 0x0d, 0x8d, 0x4d, 0xcd,
	0x2d, 0xad, 0x6d, 0xed, 0x1d, 0x9d, 0x5d, 0xdd, 0x3d, 0xbd, 0x7d, 0xfd,
	0x03, 0x83, 0x43, 0xc3, 0x23, 0xa3, 0x63, 0xe3, 0x13, 0x93, 0x53, 0xd3,
	0x33, 0xb3, 0x73, 0xf3, 0x0b, 0x8b, 0x4b, 0xcb, 0x2b, 0xab, 0x6b, 0xeb,
	0x1b, 0x9b, 0x5b, 0xdb, 0x3b, 0xbb, 0x7b, 0xfb, 0x07, 0x87, 0x47, 0xc7,
	0x27, 0xa7, 0x67, 0xe7, 0x17, 0x97, 0x57, 0xd7, 0x37, 0xb7, 0x77, 0xf7,
	0x0f, 0x8f, 0x4f, 0xcf, 0x2f, 0xaf, 0x6f, 0xef, 0x1f, 0x9f, 0x5f, 0xdf,
	0x3f, 0xbf, 0x7f, 0xff,
};

/*
 * User priorities, mapped from b_band.
 */
static uint32_t user_priority[] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
	4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
	5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
	5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
	6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
	6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
	7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
	7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7
};

#define	UPRI(gld, band)	((band != 0) ? user_priority[(band)] : (gld)->gld_upri)

static struct glddevice gld_device_list;  /* Per-system root of GLD tables */

/*
 * Module linkage information for the kernel.
 */

static struct modldrv modlmisc = {
	&mod_miscops,		/* Type of module - a utility provider */
	"Generic LAN Driver (" GLD_VERSION_STRING ")"
#ifdef GLD_DEBUG
	" DEBUG"
#endif
};

static struct modlinkage modlinkage = {
	MODREV_1, &modlmisc, NULL
};

int
_init(void)
{
	int e;

	/* initialize gld_device_list mutex */
	mutex_init(&gld_device_list.gld_devlock, NULL, MUTEX_DRIVER, NULL);

	/* initialize device driver (per-major) list */
	gld_device_list.gld_next =
	    gld_device_list.gld_prev = &gld_device_list;

	if ((e = mod_install(&modlinkage)) != 0)
		mutex_destroy(&gld_device_list.gld_devlock);

	return (e);
}

int
_fini(void)
{
	int e;

	if ((e = mod_remove(&modlinkage)) != 0)
		return (e);

	ASSERT(gld_device_list.gld_next ==
	    (glddev_t *)&gld_device_list.gld_next);
	ASSERT(gld_device_list.gld_prev ==
	    (glddev_t *)&gld_device_list.gld_next);
	mutex_destroy(&gld_device_list.gld_devlock);

	return (e);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * GLD service routines
 */

/* So this gld binary maybe can be forward compatible with future v2 drivers */
#define	GLD_MAC_RESERVED (16 * sizeof (caddr_t))

/*ARGSUSED*/
gld_mac_info_t *
gld_mac_alloc(dev_info_t *devinfo)
{
	gld_mac_info_t *macinfo;

	macinfo = kmem_zalloc(sizeof (gld_mac_info_t) + GLD_MAC_RESERVED,
	    KM_SLEEP);

	/*
	 * The setting of gldm_driver_version will not be documented or allowed
	 * until a future release.
	 */
	macinfo->gldm_driver_version = GLD_VERSION_200;

	/*
	 * GLD's version.  This also is undocumented for now, but will be
	 * available if needed in the future.
	 */
	macinfo->gldm_GLD_version = GLD_VERSION;

	return (macinfo);
}

/*
 * gld_mac_free must be called after the driver has removed interrupts
 * and completely stopped calling gld_recv() and gld_sched().  At that
 * point the interrupt routine is guaranteed by the system to have been
 * exited and the maclock is no longer needed.  Of course, it is
 * expected (required) that (assuming gld_register() succeeded),
 * gld_unregister() was called before gld_mac_free().
 */
void
gld_mac_free(gld_mac_info_t *macinfo)
{
	ASSERT(macinfo);
	ASSERT(macinfo->gldm_GLD_version == GLD_VERSION);

	/*
	 * Assert that if we made it through gld_register, then we must
	 * have unregistered.
	 */
	ASSERT(!GLDM_LOCK_INITED(macinfo) ||
	    (macinfo->gldm_GLD_flags & GLD_UNREGISTERED));

	GLDM_LOCK_DESTROY(macinfo);

	kmem_free(macinfo, sizeof (gld_mac_info_t) + GLD_MAC_RESERVED);
}

/*
 * gld_register -- called once per device instance (PPA)
 *
 * During its attach routine, a real device driver will register with GLD
 * so that later opens and dl_attach_reqs will work.  The arguments are the
 * devinfo pointer, the device name, and a macinfo structure describing the
 * physical device instance.
 */
int
gld_register(dev_info_t *devinfo, char *devname, gld_mac_info_t *macinfo)
{
	int mediatype;
	int major = ddi_name_to_major(devname), i;
	glddev_t *glddev;
	gld_mac_pvt_t *mac_pvt;
	char minordev[32];
	char pbuf[3*GLD_MAX_ADDRLEN];
	gld_interface_t *ifp;

	ASSERT(devinfo != NULL);
	ASSERT(macinfo != NULL);

	if (macinfo->gldm_driver_version != GLD_VERSION)
		return (DDI_FAILURE);

	mediatype = macinfo->gldm_type;

	/*
	 * Entry points should be ready for us.
	 * ioctl is optional.
	 * set_multicast and get_stats are optional in v0.
	 * intr is only required if you add an interrupt.
	 */
	ASSERT(macinfo->gldm_reset != NULL);
	ASSERT(macinfo->gldm_start != NULL);
	ASSERT(macinfo->gldm_stop != NULL);
	ASSERT(macinfo->gldm_set_mac_addr != NULL);
	ASSERT(macinfo->gldm_set_promiscuous != NULL);
	ASSERT(macinfo->gldm_send != NULL);

	ASSERT(macinfo->gldm_maxpkt >= macinfo->gldm_minpkt);
	ASSERT(macinfo->gldm_GLD_version == GLD_VERSION);
	ASSERT(macinfo->gldm_broadcast_addr != NULL);
	ASSERT(macinfo->gldm_vendor_addr != NULL);
	ASSERT(macinfo->gldm_ident != NULL);

	if (macinfo->gldm_addrlen > GLD_MAX_ADDRLEN) {
		cmn_err(CE_WARN, "GLD: %s driver gldm_addrlen %d > %d not sup"
		    "ported", devname, macinfo->gldm_addrlen, GLD_MAX_ADDRLEN);
		return (DDI_FAILURE);
	}

	/*
	 * GLD only functions properly with saplen == -2
	 */
	if (macinfo->gldm_saplen != -2) {
		cmn_err(CE_WARN, "GLD: %s driver gldm_saplen %d != -2 "
		    "not supported", devname, macinfo->gldm_saplen);
		return (DDI_FAILURE);
	}

	/* see gld_rsrv() */
	if (ddi_getprop(DDI_DEV_T_NONE, devinfo, 0, "fast_recv", 0))
		macinfo->gldm_options |= GLDOPT_FAST_RECV;

	mutex_enter(&gld_device_list.gld_devlock);
	glddev = gld_devlookup(major);

	/*
	 *  Allocate per-driver (major) data structure if necessary
	 */
	if (glddev == NULL) {
		/* first occurrence of this device name (major number) */
		glddev = GLD_GETSTRUCT(glddev_t, 1);
		if (glddev == NULL) {
			mutex_exit(&gld_device_list.gld_devlock);
			return (DDI_FAILURE);
		}
		(void) strncpy(glddev->gld_name, devname,
		    sizeof (glddev->gld_name) - 1);
		glddev->gld_major = major;
		glddev->gld_nextminor = GLD_MIN_CLONE_MINOR;
		glddev->gld_mac_next = glddev->gld_mac_prev =
		    (gld_mac_info_t *)&glddev->gld_mac_next;
		glddev->gld_str_next = glddev->gld_str_prev =
		    (gld_t *)&glddev->gld_str_next;
		mutex_init(&glddev->gld_devlock, NULL, MUTEX_DRIVER, NULL);

		/* allow increase of number of supported multicast addrs */
		glddev->gld_multisize = ddi_getprop(DDI_DEV_T_NONE,
		    devinfo, 0, "multisize", GLD_MAX_MULTICAST);

		/*
		 * Optionally restrict DLPI provider style
		 *
		 * -1 - don't create style 1 nodes
		 * -2 - don't create style 2 nodes
		 */
		glddev->gld_styles = ddi_getprop(DDI_DEV_T_NONE, devinfo, 0,
		    "gld-provider-styles", 0);

		/* Stuff that's needed before any PPA gets attached */
		glddev->gld_type = macinfo->gldm_type;
		glddev->gld_minsdu = macinfo->gldm_minpkt;
		glddev->gld_saplen = macinfo->gldm_saplen;
		glddev->gld_addrlen = macinfo->gldm_addrlen;
		glddev->gld_broadcast = kmem_zalloc(macinfo->gldm_addrlen,
		    KM_SLEEP);
		bcopy(macinfo->gldm_broadcast_addr,
		    glddev->gld_broadcast, macinfo->gldm_addrlen);
		glddev->gld_maxsdu = macinfo->gldm_maxpkt;
		gldinsque(glddev, gld_device_list.gld_prev);
	}
	glddev->gld_ndevice++;
	/* Now glddev can't go away until we unregister this mac (or fail) */
	mutex_exit(&gld_device_list.gld_devlock);

	/*
	 *  Per-instance initialization
	 */

	/*
	 * Initialize per-mac structure that is private to GLD.
	 * Set up interface pointer. These are device class specific pointers
	 * used to handle FDDI/TR/ETHER/IPoIB specific packets.
	 */
	for (i = 0; i < sizeof (interfaces)/sizeof (*interfaces); i++) {
		if (mediatype != interfaces[i].mac_type)
			continue;

		macinfo->gldm_mac_pvt = kmem_zalloc(sizeof (gld_mac_pvt_t),
		    KM_SLEEP);
		((gld_mac_pvt_t *)macinfo->gldm_mac_pvt)->interfacep = ifp =
		    &interfaces[i];
		break;
	}

	if (ifp == NULL) {
		cmn_err(CE_WARN, "GLD: this version does not support %s driver "
		    "of type %d", devname, mediatype);
		goto failure;
	}

	/*
	 * Driver can only register MTU within legal media range.
	 */
	if (macinfo->gldm_maxpkt > ifp->mtu_size) {
		cmn_err(CE_WARN, "GLD: oversize MTU is specified by driver %s",
		    devname);
		goto failure;
	}

	/*
	 * Correct margin size if it is not set.
	 */
	if (VLAN_CAPABLE(macinfo) && (macinfo->gldm_margin == 0))
		macinfo->gldm_margin = VTAG_SIZE;

	/*
	 * For now, only Infiniband drivers can use MDT. Do not add
	 * support for Ethernet, FDDI or TR.
	 */
	if (macinfo->gldm_mdt_pre != NULL) {
		if (mediatype != DL_IB) {
			cmn_err(CE_WARN, "GLD: MDT not supported for %s "
			    "driver of type %d", devname, mediatype);
			goto failure;
		}

		/*
		 * Validate entry points.
		 */
		if ((macinfo->gldm_mdt_send == NULL) ||
		    (macinfo->gldm_mdt_post == NULL)) {
			cmn_err(CE_WARN, "GLD: invalid MDT entry points for "
			    "%s driver of type %d", devname, mediatype);
			goto failure;
		}
		macinfo->gldm_options |= GLDOPT_MDT;
	}

	mac_pvt = (gld_mac_pvt_t *)macinfo->gldm_mac_pvt;
	mac_pvt->major_dev = glddev;

	mac_pvt->curr_macaddr = kmem_zalloc(macinfo->gldm_addrlen, KM_SLEEP);
	/*
	 * XXX Do bit-reversed devices store gldm_vendor in canonical
	 * format or in wire format?  Also gldm_broadcast.  For now
	 * we are assuming canonical, but I'm not sure that makes the
	 * most sense for ease of driver implementation.
	 */
	bcopy(macinfo->gldm_vendor_addr, mac_pvt->curr_macaddr,
	    macinfo->gldm_addrlen);
	mac_pvt->statistics = kmem_zalloc(sizeof (struct gld_stats), KM_SLEEP);

	/*
	 * The available set of notifications is those generatable by GLD
	 * itself, plus those corresponding to the capabilities of the MAC
	 * driver, intersected with those supported by gld_notify_ind() above.
	 */
	mac_pvt->notifications = gld_internal_notes;
	if (macinfo->gldm_capabilities & GLD_CAP_LINKSTATE)
		mac_pvt->notifications |= gld_linkstate_notes;
	mac_pvt->notifications &= gld_supported_notes;

	GLDM_LOCK_INIT(macinfo);

	ddi_set_driver_private(devinfo, macinfo);

	/*
	 * Now atomically get a PPA and put ourselves on the mac list.
	 */
	mutex_enter(&glddev->gld_devlock);

#ifdef DEBUG
	if (macinfo->gldm_ppa != ddi_get_instance(devinfo))
		cmn_err(CE_WARN, "%s%d instance != ppa %d",
		    ddi_driver_name(devinfo), ddi_get_instance(devinfo),
		    macinfo->gldm_ppa);
#endif

	/*
	 * Create style 2 node (gated by gld-provider-styles property).
	 *
	 * NOTE: When the CLONE_DEV flag is specified to
	 *	 ddi_create_minor_node() the minor number argument is
	 *	 immaterial. Opens of that node will go via the clone
	 *	 driver and gld_open() will always be passed a dev_t with
	 *	 minor of zero.
	 */
	if (glddev->gld_styles != -2) {
		if (ddi_create_minor_node(devinfo, glddev->gld_name, S_IFCHR,
		    0, DDI_NT_NET, CLONE_DEV) == DDI_FAILURE) {
			mutex_exit(&glddev->gld_devlock);
			goto late_failure;
		}
	}

	/*
	 * Create style 1 node (gated by gld-provider-styles property)
	 */
	if (glddev->gld_styles != -1) {
		(void) sprintf(minordev, "%s%d", glddev->gld_name,
		    macinfo->gldm_ppa);
		if (ddi_create_minor_node(devinfo, minordev, S_IFCHR,
		    GLD_STYLE1_PPA_TO_MINOR(macinfo->gldm_ppa), DDI_NT_NET,
		    0) != DDI_SUCCESS) {
			mutex_exit(&glddev->gld_devlock);
			goto late_failure;
		}
	}

	/* add ourselves to this major device's linked list of instances */
	gldinsque(macinfo, glddev->gld_mac_prev);

	mutex_exit(&glddev->gld_devlock);

	/*
	 * Unfortunately we need the ppa before we call gld_initstats();
	 * otherwise we would like to do this just above the mutex_enter
	 * above.  In which case we could have set MAC_READY inside the
	 * mutex and we wouldn't have needed to check it in open and
	 * DL_ATTACH.  We wouldn't like to do the initstats/kstat_create
	 * inside the mutex because it might get taken in our kstat_update
	 * routine and cause a deadlock with kstat_chain_lock.
	 */

	/* gld_initstats() calls (*ifp->init)() */
	if (gld_initstats(macinfo) != GLD_SUCCESS) {
		mutex_enter(&glddev->gld_devlock);
		gldremque(macinfo);
		mutex_exit(&glddev->gld_devlock);
		goto late_failure;
	}

	/*
	 * Need to indicate we are NOW ready to process interrupts;
	 * any interrupt before this is set is for someone else.
	 * This flag is also now used to tell open, et. al. that this
	 * mac is now fully ready and available for use.
	 */
	GLDM_LOCK(macinfo, RW_WRITER);
	macinfo->gldm_GLD_flags |= GLD_MAC_READY;
	GLDM_UNLOCK(macinfo);

	/* log local ethernet address -- XXX not DDI compliant */
	if (macinfo->gldm_addrlen == sizeof (struct ether_addr))
		(void) localetheraddr(
		    (struct ether_addr *)macinfo->gldm_vendor_addr, NULL);

	/* now put announcement into the message buffer */
	cmn_err(CE_CONT, "!%s%d: %s: type \"%s\" mac address %s\n",
	    glddev->gld_name,
	    macinfo->gldm_ppa, macinfo->gldm_ident,
	    mac_pvt->interfacep->mac_string,
	    gld_macaddr_sprintf(pbuf, macinfo->gldm_vendor_addr,
	    macinfo->gldm_addrlen));

	ddi_report_dev(devinfo);
	return (DDI_SUCCESS);

late_failure:
	ddi_remove_minor_node(devinfo, NULL);
	GLDM_LOCK_DESTROY(macinfo);
	if (mac_pvt->curr_macaddr != NULL)
		kmem_free(mac_pvt->curr_macaddr, macinfo->gldm_addrlen);
	if (mac_pvt->statistics != NULL)
		kmem_free(mac_pvt->statistics, sizeof (struct gld_stats));
	kmem_free(macinfo->gldm_mac_pvt, sizeof (gld_mac_pvt_t));
	macinfo->gldm_mac_pvt = NULL;

failure:
	mutex_enter(&gld_device_list.gld_devlock);
	glddev->gld_ndevice--;
	/*
	 * Note that just because this goes to zero here does not necessarily
	 * mean that we were the one who added the glddev above.  It's
	 * possible that the first mac unattached while were were in here
	 * failing to attach the second mac.  But we're now the last.
	 */
	if (glddev->gld_ndevice == 0) {
		/* There should be no macinfos left */
		ASSERT(glddev->gld_mac_next ==
		    (gld_mac_info_t *)&glddev->gld_mac_next);
		ASSERT(glddev->gld_mac_prev ==
		    (gld_mac_info_t *)&glddev->gld_mac_next);

		/*
		 * There should be no DL_UNATTACHED streams: the system
		 * should not have detached the "first" devinfo which has
		 * all the open style 2 streams.
		 *
		 * XXX This is not clear.  See gld_getinfo and Bug 1165519
		 */
		ASSERT(glddev->gld_str_next == (gld_t *)&glddev->gld_str_next);
		ASSERT(glddev->gld_str_prev == (gld_t *)&glddev->gld_str_next);

		gldremque(glddev);
		mutex_destroy(&glddev->gld_devlock);
		if (glddev->gld_broadcast != NULL)
			kmem_free(glddev->gld_broadcast, glddev->gld_addrlen);
		kmem_free(glddev, sizeof (glddev_t));
	}
	mutex_exit(&gld_device_list.gld_devlock);

	return (DDI_FAILURE);
}

/*
 * gld_unregister (macinfo)
 * remove the macinfo structure from local structures
 * this is cleanup for a driver to be unloaded
 */
int
gld_unregister(gld_mac_info_t *macinfo)
{
	gld_mac_pvt_t *mac_pvt = (gld_mac_pvt_t *)macinfo->gldm_mac_pvt;
	glddev_t *glddev = mac_pvt->major_dev;
	gld_interface_t *ifp;
	int multisize = sizeof (gld_mcast_t) * glddev->gld_multisize;

	mutex_enter(&glddev->gld_devlock);
	GLDM_LOCK(macinfo, RW_WRITER);

	if (mac_pvt->nvlan > 0) {
		GLDM_UNLOCK(macinfo);
		mutex_exit(&glddev->gld_devlock);
		return (DDI_FAILURE);
	}

#ifdef	GLD_DEBUG
	{
		int i;

		for (i = 0; i < VLAN_HASHSZ; i++) {
			if ((mac_pvt->vlan_hash[i] != NULL))
				cmn_err(CE_PANIC,
				    "%s, line %d: "
				    "mac_pvt->vlan_hash[%d] != NULL",
				    __FILE__, __LINE__, i);
		}
	}
#endif

	/* Delete this mac */
	gldremque(macinfo);

	/* Disallow further entries to gld_recv() and gld_sched() */
	macinfo->gldm_GLD_flags |= GLD_UNREGISTERED;

	GLDM_UNLOCK(macinfo);
	mutex_exit(&glddev->gld_devlock);

	ifp = ((gld_mac_pvt_t *)macinfo->gldm_mac_pvt)->interfacep;
	(*ifp->uninit)(macinfo);

	ASSERT(mac_pvt->kstatp);
	kstat_delete(mac_pvt->kstatp);

	ASSERT(GLDM_LOCK_INITED(macinfo));
	kmem_free(mac_pvt->curr_macaddr, macinfo->gldm_addrlen);
	kmem_free(mac_pvt->statistics, sizeof (struct gld_stats));

	if (mac_pvt->mcast_table != NULL)
		kmem_free(mac_pvt->mcast_table, multisize);
	kmem_free(macinfo->gldm_mac_pvt, sizeof (gld_mac_pvt_t));
	macinfo->gldm_mac_pvt = (caddr_t)NULL;

	/* We now have one fewer instance for this major device */
	mutex_enter(&gld_device_list.gld_devlock);
	glddev->gld_ndevice--;
	if (glddev->gld_ndevice == 0) {
		/* There should be no macinfos left */
		ASSERT(glddev->gld_mac_next ==
		    (gld_mac_info_t *)&glddev->gld_mac_next);
		ASSERT(glddev->gld_mac_prev ==
		    (gld_mac_info_t *)&glddev->gld_mac_next);

		/*
		 * There should be no DL_UNATTACHED streams: the system
		 * should not have detached the "first" devinfo which has
		 * all the open style 2 streams.
		 *
		 * XXX This is not clear.  See gld_getinfo and Bug 1165519
		 */
		ASSERT(glddev->gld_str_next == (gld_t *)&glddev->gld_str_next);
		ASSERT(glddev->gld_str_prev == (gld_t *)&glddev->gld_str_next);

		ddi_remove_minor_node(macinfo->gldm_devinfo, NULL);
		gldremque(glddev);
		mutex_destroy(&glddev->gld_devlock);
		if (glddev->gld_broadcast != NULL)
			kmem_free(glddev->gld_broadcast, glddev->gld_addrlen);
		kmem_free(glddev, sizeof (glddev_t));
	}
	mutex_exit(&gld_device_list.gld_devlock);

	return (DDI_SUCCESS);
}

/*
 * gld_initstats
 * called from gld_register
 */
static int
gld_initstats(gld_mac_info_t *macinfo)
{
	gld_mac_pvt_t *mac_pvt = (gld_mac_pvt_t *)macinfo->gldm_mac_pvt;
	struct gldkstats *sp;
	glddev_t *glddev;
	kstat_t *ksp;
	gld_interface_t *ifp;

	glddev = mac_pvt->major_dev;

	if ((ksp = kstat_create(glddev->gld_name, macinfo->gldm_ppa,
	    NULL, "net", KSTAT_TYPE_NAMED,
	    sizeof (struct gldkstats) / sizeof (kstat_named_t), 0)) == NULL) {
		cmn_err(CE_WARN,
		    "GLD: failed to create kstat structure for %s%d",
		    glddev->gld_name, macinfo->gldm_ppa);
		return (GLD_FAILURE);
	}
	mac_pvt->kstatp = ksp;

	ksp->ks_update = gld_update_kstat;
	ksp->ks_private = (void *)macinfo;

	sp = ksp->ks_data;
	kstat_named_init(&sp->glds_pktrcv, "ipackets", KSTAT_DATA_UINT32);
	kstat_named_init(&sp->glds_pktxmt, "opackets", KSTAT_DATA_UINT32);
	kstat_named_init(&sp->glds_errrcv, "ierrors", KSTAT_DATA_ULONG);
	kstat_named_init(&sp->glds_errxmt, "oerrors", KSTAT_DATA_ULONG);
	kstat_named_init(&sp->glds_bytexmt, "obytes", KSTAT_DATA_UINT32);
	kstat_named_init(&sp->glds_bytercv, "rbytes", KSTAT_DATA_UINT32);
	kstat_named_init(&sp->glds_multixmt, "multixmt", KSTAT_DATA_ULONG);
	kstat_named_init(&sp->glds_multircv, "multircv", KSTAT_DATA_ULONG);
	kstat_named_init(&sp->glds_brdcstxmt, "brdcstxmt", KSTAT_DATA_ULONG);
	kstat_named_init(&sp->glds_brdcstrcv, "brdcstrcv", KSTAT_DATA_ULONG);
	kstat_named_init(&sp->glds_blocked, "blocked", KSTAT_DATA_ULONG);
	kstat_named_init(&sp->glds_noxmtbuf, "noxmtbuf", KSTAT_DATA_ULONG);
	kstat_named_init(&sp->glds_norcvbuf, "norcvbuf", KSTAT_DATA_ULONG);
	kstat_named_init(&sp->glds_xmtretry, "xmtretry", KSTAT_DATA_ULONG);
	kstat_named_init(&sp->glds_intr, "intr", KSTAT_DATA_ULONG);
	kstat_named_init(&sp->glds_pktrcv64, "ipackets64", KSTAT_DATA_UINT64);
	kstat_named_init(&sp->glds_pktxmt64, "opackets64", KSTAT_DATA_UINT64);
	kstat_named_init(&sp->glds_bytexmt64, "obytes64", KSTAT_DATA_UINT64);
	kstat_named_init(&sp->glds_bytercv64, "rbytes64", KSTAT_DATA_UINT64);
	kstat_named_init(&sp->glds_unknowns, "unknowns", KSTAT_DATA_ULONG);
	kstat_named_init(&sp->glds_speed, "ifspeed", KSTAT_DATA_UINT64);
	kstat_named_init(&sp->glds_media, "media", KSTAT_DATA_CHAR);
	kstat_named_init(&sp->glds_prom, "promisc", KSTAT_DATA_CHAR);

	kstat_named_init(&sp->glds_overflow, "oflo", KSTAT_DATA_ULONG);
	kstat_named_init(&sp->glds_underflow, "uflo", KSTAT_DATA_ULONG);
	kstat_named_init(&sp->glds_missed, "missed", KSTAT_DATA_ULONG);

	kstat_named_init(&sp->glds_xmtbadinterp, "xmt_badinterp",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&sp->glds_rcvbadinterp, "rcv_badinterp",
	    KSTAT_DATA_UINT32);

	ifp = ((gld_mac_pvt_t *)macinfo->gldm_mac_pvt)->interfacep;

	(*ifp->init)(macinfo);

	kstat_install(ksp);

	return (GLD_SUCCESS);
}

/* called from kstat mechanism, and from wsrv's get_statistics_req */
static int
gld_update_kstat(kstat_t *ksp, int rw)
{
	gld_mac_info_t	*macinfo;
	gld_mac_pvt_t	*mac_pvt;
	struct gldkstats *gsp;
	struct gld_stats *stats;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	macinfo = (gld_mac_info_t *)ksp->ks_private;
	ASSERT(macinfo != NULL);

	GLDM_LOCK(macinfo, RW_WRITER);

	if (!(macinfo->gldm_GLD_flags & GLD_MAC_READY)) {
		GLDM_UNLOCK(macinfo);
		return (EIO);	/* this one's not ready yet */
	}

	if (macinfo->gldm_GLD_flags & GLD_UNREGISTERED) {
		GLDM_UNLOCK(macinfo);
		return (EIO);	/* this one's not ready any more */
	}

	mac_pvt = (gld_mac_pvt_t *)macinfo->gldm_mac_pvt;
	gsp = mac_pvt->kstatp->ks_data;
	ASSERT(gsp);
	stats = mac_pvt->statistics;

	if (macinfo->gldm_get_stats)
		(void) (*macinfo->gldm_get_stats)(macinfo, stats);

	gsp->glds_pktxmt.value.ui32 = stats->glds_pktxmt64 & 0xffffffff;
	gsp->glds_bytexmt.value.ui32 = stats->glds_bytexmt64 & 0xffffffff;
	gsp->glds_multixmt.value.ul = stats->glds_multixmt;
	gsp->glds_brdcstxmt.value.ul = stats->glds_brdcstxmt;
	gsp->glds_noxmtbuf.value.ul = stats->glds_noxmtbuf;	/* 0 for now */
	gsp->glds_xmtretry.value.ul = stats->glds_xmtretry;

	gsp->glds_pktxmt64.value.ui64 = stats->glds_pktxmt64;
	gsp->glds_bytexmt64.value.ui64 = stats->glds_bytexmt64;
	gsp->glds_xmtbadinterp.value.ui32 = stats->glds_xmtbadinterp;

	gsp->glds_pktrcv.value.ui32 = stats->glds_pktrcv64 & 0xffffffff;
	gsp->glds_errxmt.value.ul = stats->glds_errxmt;
	gsp->glds_errrcv.value.ul = stats->glds_errrcv;
	gsp->glds_bytercv.value.ui32 = stats->glds_bytercv64 & 0xffffffff;
	gsp->glds_multircv.value.ul = stats->glds_multircv;
	gsp->glds_brdcstrcv.value.ul = stats->glds_brdcstrcv;
	gsp->glds_blocked.value.ul = stats->glds_blocked;
	gsp->glds_overflow.value.ul = stats->glds_overflow;
	gsp->glds_underflow.value.ul = stats->glds_underflow;
	gsp->glds_missed.value.ul = stats->glds_missed;
	gsp->glds_norcvbuf.value.ul = stats->glds_norcvbuf +
	    stats->glds_gldnorcvbuf;
	gsp->glds_intr.value.ul = stats->glds_intr;

	gsp->glds_speed.value.ui64 = stats->glds_speed;
	gsp->glds_unknowns.value.ul = stats->glds_unknowns;
	gsp->glds_pktrcv64.value.ui64 = stats->glds_pktrcv64;
	gsp->glds_bytercv64.value.ui64 = stats->glds_bytercv64;
	gsp->glds_rcvbadinterp.value.ui32 = stats->glds_rcvbadinterp;

	if (mac_pvt->nprom)
		(void) strcpy(gsp->glds_prom.value.c, "phys");
	else if (mac_pvt->nprom_multi)
		(void) strcpy(gsp->glds_prom.value.c, "multi");
	else
		(void) strcpy(gsp->glds_prom.value.c, "off");

	(void) strcpy(gsp->glds_media.value.c, gld_media[
	    stats->glds_media < sizeof (gld_media) / sizeof (gld_media[0])
	    ? stats->glds_media : 0]);

	switch (macinfo->gldm_type) {
	case DL_ETHER:
		gsp->glds_frame.value.ul = stats->glds_frame;
		gsp->glds_crc.value.ul = stats->glds_crc;
		gsp->glds_collisions.value.ul = stats->glds_collisions;
		gsp->glds_excoll.value.ul = stats->glds_excoll;
		gsp->glds_defer.value.ul = stats->glds_defer;
		gsp->glds_short.value.ul = stats->glds_short;
		gsp->glds_xmtlatecoll.value.ul = stats->glds_xmtlatecoll;
		gsp->glds_nocarrier.value.ul = stats->glds_nocarrier;
		gsp->glds_dot3_first_coll.value.ui32 =
		    stats->glds_dot3_first_coll;
		gsp->glds_dot3_multi_coll.value.ui32 =
		    stats->glds_dot3_multi_coll;
		gsp->glds_dot3_sqe_error.value.ui32 =
		    stats->glds_dot3_sqe_error;
		gsp->glds_dot3_mac_xmt_error.value.ui32 =
		    stats->glds_dot3_mac_xmt_error;
		gsp->glds_dot3_mac_rcv_error.value.ui32 =
		    stats->glds_dot3_mac_rcv_error;
		gsp->glds_dot3_frame_too_long.value.ui32 =
		    stats->glds_dot3_frame_too_long;
		(void) strcpy(gsp->glds_duplex.value.c, gld_duplex[
		    stats->glds_duplex <
		    sizeof (gld_duplex) / sizeof (gld_duplex[0]) ?
		    stats->glds_duplex : 0]);
		break;
	case DL_TPR:
		gsp->glds_dot5_line_error.value.ui32 =
		    stats->glds_dot5_line_error;
		gsp->glds_dot5_burst_error.value.ui32 =
		    stats->glds_dot5_burst_error;
		gsp->glds_dot5_signal_loss.value.ui32 =
		    stats->glds_dot5_signal_loss;
		gsp->glds_dot5_ace_error.value.ui32 =
		    stats->glds_dot5_ace_error;
		gsp->glds_dot5_internal_error.value.ui32 =
		    stats->glds_dot5_internal_error;
		gsp->glds_dot5_lost_frame_error.value.ui32 =
		    stats->glds_dot5_lost_frame_error;
		gsp->glds_dot5_frame_copied_error.value.ui32 =
		    stats->glds_dot5_frame_copied_error;
		gsp->glds_dot5_token_error.value.ui32 =
		    stats->glds_dot5_token_error;
		gsp->glds_dot5_freq_error.value.ui32 =
		    stats->glds_dot5_freq_error;
		break;
	case DL_FDDI:
		gsp->glds_fddi_mac_error.value.ui32 =
		    stats->glds_fddi_mac_error;
		gsp->glds_fddi_mac_lost.value.ui32 =
		    stats->glds_fddi_mac_lost;
		gsp->glds_fddi_mac_token.value.ui32 =
		    stats->glds_fddi_mac_token;
		gsp->glds_fddi_mac_tvx_expired.value.ui32 =
		    stats->glds_fddi_mac_tvx_expired;
		gsp->glds_fddi_mac_late.value.ui32 =
		    stats->glds_fddi_mac_late;
		gsp->glds_fddi_mac_ring_op.value.ui32 =
		    stats->glds_fddi_mac_ring_op;
		break;
	case DL_IB:
		break;
	default:
		break;
	}

	GLDM_UNLOCK(macinfo);

#ifdef GLD_DEBUG
	gld_check_assertions();
	if (gld_debug & GLDRDE)
		gld_sr_dump(macinfo);
#endif

	return (0);
}

static int
gld_init_vlan_stats(gld_vlan_t *vlan)
{
	gld_mac_info_t *mac = vlan->gldv_mac;
	gld_mac_pvt_t *mac_pvt = (gld_mac_pvt_t *)mac->gldm_mac_pvt;
	struct gldkstats *sp;
	glddev_t *glddev;
	kstat_t *ksp;
	char *name;
	int instance;

	glddev = mac_pvt->major_dev;
	name = glddev->gld_name;
	instance = (vlan->gldv_id * GLD_VLAN_SCALE) + mac->gldm_ppa;

	if ((ksp = kstat_create(name, instance,
	    NULL, "net", KSTAT_TYPE_NAMED,
	    sizeof (struct gldkstats) / sizeof (kstat_named_t), 0)) == NULL) {
		cmn_err(CE_WARN,
		    "GLD: failed to create kstat structure for %s%d",
		    name, instance);
		return (GLD_FAILURE);
	}

	vlan->gldv_kstatp = ksp;

	ksp->ks_update = gld_update_vlan_kstat;
	ksp->ks_private = (void *)vlan;

	sp = ksp->ks_data;
	kstat_named_init(&sp->glds_pktrcv, "ipackets", KSTAT_DATA_UINT32);
	kstat_named_init(&sp->glds_pktxmt, "opackets", KSTAT_DATA_UINT32);
	kstat_named_init(&sp->glds_errrcv, "ierrors", KSTAT_DATA_ULONG);
	kstat_named_init(&sp->glds_errxmt, "oerrors", KSTAT_DATA_ULONG);
	kstat_named_init(&sp->glds_bytexmt, "obytes", KSTAT_DATA_UINT32);
	kstat_named_init(&sp->glds_bytercv, "rbytes", KSTAT_DATA_UINT32);
	kstat_named_init(&sp->glds_multixmt, "multixmt", KSTAT_DATA_ULONG);
	kstat_named_init(&sp->glds_multircv, "multircv", KSTAT_DATA_ULONG);
	kstat_named_init(&sp->glds_brdcstxmt, "brdcstxmt", KSTAT_DATA_ULONG);
	kstat_named_init(&sp->glds_brdcstrcv, "brdcstrcv", KSTAT_DATA_ULONG);
	kstat_named_init(&sp->glds_blocked, "blocked", KSTAT_DATA_ULONG);
	kstat_named_init(&sp->glds_noxmtbuf, "noxmtbuf", KSTAT_DATA_ULONG);
	kstat_named_init(&sp->glds_norcvbuf, "norcvbuf", KSTAT_DATA_ULONG);
	kstat_named_init(&sp->glds_xmtretry, "xmtretry", KSTAT_DATA_ULONG);
	kstat_named_init(&sp->glds_intr, "intr", KSTAT_DATA_ULONG);
	kstat_named_init(&sp->glds_pktrcv64, "ipackets64", KSTAT_DATA_UINT64);
	kstat_named_init(&sp->glds_pktxmt64, "opackets64", KSTAT_DATA_UINT64);
	kstat_named_init(&sp->glds_bytexmt64, "obytes64", KSTAT_DATA_UINT64);
	kstat_named_init(&sp->glds_bytercv64, "rbytes64", KSTAT_DATA_UINT64);
	kstat_named_init(&sp->glds_unknowns, "unknowns", KSTAT_DATA_ULONG);
	kstat_named_init(&sp->glds_speed, "ifspeed", KSTAT_DATA_UINT64);
	kstat_named_init(&sp->glds_media, "media", KSTAT_DATA_CHAR);
	kstat_named_init(&sp->glds_prom, "promisc", KSTAT_DATA_CHAR);

	kstat_named_init(&sp->glds_overflow, "oflo", KSTAT_DATA_ULONG);
	kstat_named_init(&sp->glds_underflow, "uflo", KSTAT_DATA_ULONG);
	kstat_named_init(&sp->glds_missed, "missed", KSTAT_DATA_ULONG);

	kstat_named_init(&sp->glds_xmtbadinterp, "xmt_badinterp",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&sp->glds_rcvbadinterp, "rcv_badinterp",
	    KSTAT_DATA_UINT32);

	kstat_install(ksp);
	return (GLD_SUCCESS);
}

static int
gld_update_vlan_kstat(kstat_t *ksp, int rw)
{
	gld_vlan_t	*vlan;
	gld_mac_info_t	*macinfo;
	struct gldkstats *gsp;
	struct gld_stats *stats;
	gld_mac_pvt_t *mac_pvt;
	uint32_t media;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	vlan = (gld_vlan_t *)ksp->ks_private;
	ASSERT(vlan != NULL);

	macinfo = vlan->gldv_mac;
	GLDM_LOCK(macinfo, RW_WRITER);

	mac_pvt = (gld_mac_pvt_t *)macinfo->gldm_mac_pvt;

	gsp = vlan->gldv_kstatp->ks_data;
	ASSERT(gsp);
	stats = vlan->gldv_stats;

	gsp->glds_pktxmt.value.ui32 = stats->glds_pktxmt64 & 0xffffffff;
	gsp->glds_bytexmt.value.ui32 = stats->glds_bytexmt64 & 0xffffffff;
	gsp->glds_errxmt.value.ul = stats->glds_errxmt;
	gsp->glds_multixmt.value.ul = stats->glds_multixmt;
	gsp->glds_brdcstxmt.value.ul = stats->glds_brdcstxmt;
	gsp->glds_noxmtbuf.value.ul = stats->glds_noxmtbuf;
	gsp->glds_xmtretry.value.ul = stats->glds_xmtretry;
	gsp->glds_pktxmt64.value.ui64 = stats->glds_pktxmt64;
	gsp->glds_bytexmt64.value.ui64 = stats->glds_bytexmt64;

	gsp->glds_pktrcv.value.ui32 = stats->glds_pktrcv64 & 0xffffffff;
	gsp->glds_bytercv.value.ui32 = stats->glds_bytercv64 & 0xffffffff;
	gsp->glds_errrcv.value.ul = stats->glds_errrcv;
	gsp->glds_multircv.value.ul = stats->glds_multircv;
	gsp->glds_brdcstrcv.value.ul = stats->glds_brdcstrcv;
	gsp->glds_blocked.value.ul = stats->glds_blocked;
	gsp->glds_pktrcv64.value.ui64 = stats->glds_pktrcv64;
	gsp->glds_bytercv64.value.ui64 = stats->glds_bytercv64;
	gsp->glds_unknowns.value.ul = stats->glds_unknowns;
	gsp->glds_xmtbadinterp.value.ui32 = stats->glds_xmtbadinterp;
	gsp->glds_rcvbadinterp.value.ui32 = stats->glds_rcvbadinterp;

	gsp->glds_speed.value.ui64 = mac_pvt->statistics->glds_speed;
	media = mac_pvt->statistics->glds_media;
	(void) strcpy(gsp->glds_media.value.c,
	    gld_media[media < sizeof (gld_media) / sizeof (gld_media[0]) ?
	    media : 0]);

	GLDM_UNLOCK(macinfo);
	return (0);
}

/*
 * The device dependent driver specifies gld_getinfo as its getinfo routine.
 */
/*ARGSUSED*/
int
gld_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **resultp)
{
	dev_info_t	*devinfo;
	minor_t		minor = getminor((dev_t)arg);
	int		rc = DDI_FAILURE;

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if ((devinfo = gld_finddevinfo((dev_t)arg)) != NULL) {
			*(dev_info_t **)resultp = devinfo;
			rc = DDI_SUCCESS;
		}
		break;
	case DDI_INFO_DEVT2INSTANCE:
		/* Need static mapping for deferred attach */
		if (minor == GLD_USE_STYLE2) {
			/*
			 * Style 2:  this minor number does not correspond to
			 * any particular instance number.
			 */
			rc = DDI_FAILURE;
		} else if (minor <= GLD_MAX_STYLE1_MINOR) {
			/* Style 1:  calculate the PPA from the minor */
			*resultp = (void *)(uintptr_t)
			    GLD_STYLE1_MINOR_TO_PPA(minor);
			rc = DDI_SUCCESS;
		} else {
			/* Clone:  look for it.  Not a static mapping */
			if ((devinfo = gld_finddevinfo((dev_t)arg)) != NULL) {
				*resultp = (void *)(uintptr_t)
				    ddi_get_instance(devinfo);
				rc = DDI_SUCCESS;
			}
		}
		break;
	}

	return (rc);
}

/* called from gld_getinfo */
dev_info_t *
gld_finddevinfo(dev_t dev)
{
	minor_t		minor = getminor(dev);
	glddev_t	*device;
	gld_mac_info_t	*mac;
	gld_vlan_t	*vlan;
	gld_t		*str;
	dev_info_t	*devinfo = NULL;
	int		i;

	if (minor == GLD_USE_STYLE2) {
		/*
		 * Style 2:  this minor number does not correspond to
		 * any particular instance number.
		 *
		 * XXX We don't know what to say.  See Bug 1165519.
		 */
		return (NULL);
	}

	mutex_enter(&gld_device_list.gld_devlock);	/* hold the device */

	device = gld_devlookup(getmajor(dev));
	if (device == NULL) {
		/* There are no attached instances of this device */
		mutex_exit(&gld_device_list.gld_devlock);
		return (NULL);
	}

	/*
	 * Search all attached macs and streams.
	 *
	 * XXX We don't bother checking the DL_UNATTACHED streams since
	 * we don't know what devinfo we should report back even if we
	 * found the minor.  Maybe we should associate streams that are
	 * not currently attached to a PPA with the "first" devinfo node
	 * of the major device to attach -- the one that created the
	 * minor node for the generic device.
	 */
	mutex_enter(&device->gld_devlock);

	for (mac = device->gld_mac_next;
	    mac != (gld_mac_info_t *)&device->gld_mac_next;
	    mac = mac->gldm_next) {
		gld_mac_pvt_t *pvt = (gld_mac_pvt_t *)mac->gldm_mac_pvt;

		if (!(mac->gldm_GLD_flags & GLD_MAC_READY))
			continue;	/* this one's not ready yet */
		if (minor <= GLD_MAX_STYLE1_MINOR) {
			/* Style 1 -- look for the corresponding PPA */
			if (minor == GLD_STYLE1_PPA_TO_MINOR(mac->gldm_ppa)) {
				devinfo = mac->gldm_devinfo;
				goto out;	/* found it! */
			} else
				continue;	/* not this PPA */
		}

		/* We are looking for a clone */
		for (i = 0; i < VLAN_HASHSZ; i++) {
			for (vlan = pvt->vlan_hash[i];
			    vlan != NULL; vlan = vlan->gldv_next) {
				for (str = vlan->gldv_str_next;
				    str != (gld_t *)&vlan->gldv_str_next;
				    str = str->gld_next) {
					ASSERT(str->gld_mac_info == mac);
					if (minor == str->gld_minor) {
						devinfo = mac->gldm_devinfo;
						goto out;
					}
				}
			}
		}
	}
out:
	mutex_exit(&device->gld_devlock);
	mutex_exit(&gld_device_list.gld_devlock);
	return (devinfo);
}

/*
 * STREAMS open routine.  The device dependent driver specifies this as its
 * open entry point.
 */
/*ARGSUSED2*/
int
gld_open(queue_t *q, dev_t *dev, int flag, int sflag, cred_t *cred)
{
	gld_mac_pvt_t *mac_pvt;
	gld_t *gld;
	glddev_t *glddev;
	gld_mac_info_t *macinfo;
	minor_t minor = getminor(*dev);
	gld_vlan_t *vlan;
	t_uscalar_t ppa;

	ASSERT(q != NULL);

	if (minor > GLD_MAX_STYLE1_MINOR)
		return (ENXIO);

	ASSERT(q->q_ptr == NULL);	/* Clone device gives us a fresh Q */

	/* Find our per-major glddev_t structure */
	mutex_enter(&gld_device_list.gld_devlock);
	glddev = gld_devlookup(getmajor(*dev));

	/*
	 * This glddev will hang around since detach (and therefore
	 * gld_unregister) can't run while we're here in the open routine.
	 */
	mutex_exit(&gld_device_list.gld_devlock);

	if (glddev == NULL)
		return (ENXIO);

#ifdef GLD_DEBUG
	if (gld_debug & GLDPROT) {
		if (minor == GLD_USE_STYLE2)
			cmn_err(CE_NOTE, "gld_open(%p, Style 2)", (void *)q);
		else
			cmn_err(CE_NOTE, "gld_open(%p, Style 1, minor = %d)",
			    (void *)q, minor);
	}
#endif

	/*
	 * get a per-stream structure and link things together so we
	 * can easily find them later.
	 */
	gld = kmem_zalloc(sizeof (gld_t), KM_SLEEP);

	/*
	 * fill in the structure and state info
	 */
	gld->gld_qptr = q;
	gld->gld_device = glddev;
	gld->gld_state = DL_UNATTACHED;

	/*
	 * we must atomically find a free minor number and add the stream
	 * to a list, because gld_findminor has to traverse the lists to
	 * determine which minor numbers are free.
	 */
	mutex_enter(&glddev->gld_devlock);

	/* find a free minor device number for the clone */
	gld->gld_minor = gld_findminor(glddev);
	if (gld->gld_minor == 0) {
		mutex_exit(&glddev->gld_devlock);
		kmem_free(gld, sizeof (gld_t));
		return (ENOSR);
	}

#ifdef GLD_VERBOSE_DEBUG
	if (gld_debug & GLDPROT)
		cmn_err(CE_NOTE, "gld_open() gld ptr: %p minor: %d",
		    (void *)gld, gld->gld_minor);
#endif

	if (minor == GLD_USE_STYLE2) {
		gld->gld_style = DL_STYLE2;
		*dev = makedevice(getmajor(*dev), gld->gld_minor);
		WR(q)->q_ptr = q->q_ptr = (caddr_t)gld;
		gldinsque(gld, glddev->gld_str_prev);
#ifdef GLD_VERBOSE_DEBUG
		if (gld_debug & GLDPROT)
			cmn_err(CE_NOTE, "GLDstruct added to device list");
#endif
		(void) qassociate(q, -1);
		goto done;
	}

	gld->gld_style = DL_STYLE1;

	/* the PPA is actually 1 less than the minordev */
	ppa = GLD_STYLE1_MINOR_TO_PPA(minor);

	for (macinfo = glddev->gld_mac_next;
	    macinfo != (gld_mac_info_t *)(&glddev->gld_mac_next);
	    macinfo = macinfo->gldm_next) {
		ASSERT(macinfo != NULL);
		if (macinfo->gldm_ppa != ppa)
			continue;

		if (!(macinfo->gldm_GLD_flags & GLD_MAC_READY))
			continue;	/* this one's not ready yet */

		/*
		 * we found the correct PPA
		 */
		GLDM_LOCK(macinfo, RW_WRITER);

		gld->gld_mac_info = macinfo;

		if (macinfo->gldm_send_tagged != NULL)
			gld->gld_send = macinfo->gldm_send_tagged;
		else
			gld->gld_send = macinfo->gldm_send;

		/* now ready for action */
		gld->gld_state = DL_UNBOUND;

		if ((vlan = gld_get_vlan(macinfo, VLAN_VID_NONE)) == NULL) {
			GLDM_UNLOCK(macinfo);
			mutex_exit(&glddev->gld_devlock);
			kmem_free(gld, sizeof (gld_t));
			return (EIO);
		}

		mac_pvt = (gld_mac_pvt_t *)macinfo->gldm_mac_pvt;
		if (!mac_pvt->started) {
			if (gld_start_mac(macinfo) != GLD_SUCCESS) {
				gld_rem_vlan(vlan);
				GLDM_UNLOCK(macinfo);
				mutex_exit(&glddev->gld_devlock);
				kmem_free(gld, sizeof (gld_t));
				return (EIO);
			}
		}

		gld->gld_vlan = vlan;
		vlan->gldv_nstreams++;
		gldinsque(gld, vlan->gldv_str_prev);
		*dev = makedevice(getmajor(*dev), gld->gld_minor);
		WR(q)->q_ptr = q->q_ptr = (caddr_t)gld;

		GLDM_UNLOCK(macinfo);
#ifdef GLD_VERBOSE_DEBUG
		if (gld_debug & GLDPROT)
			cmn_err(CE_NOTE,
			    "GLDstruct added to instance list");
#endif
		break;
	}

	if (gld->gld_state == DL_UNATTACHED) {
		mutex_exit(&glddev->gld_devlock);
		kmem_free(gld, sizeof (gld_t));
		return (ENXIO);
	}

done:
	mutex_exit(&glddev->gld_devlock);
	noenable(WR(q));	/* We'll do the qenables manually */
	qprocson(q);		/* start the queues running */
	qenable(WR(q));
	return (0);
}

/*
 * normal stream close call checks current status and cleans up
 * data structures that were dynamically allocated
 */
/*ARGSUSED1*/
int
gld_close(queue_t *q, int flag, cred_t *cred)
{
	gld_t	*gld = (gld_t *)q->q_ptr;
	glddev_t *glddev = gld->gld_device;

	ASSERT(q);
	ASSERT(gld);

#ifdef GLD_DEBUG
	if (gld_debug & GLDPROT) {
		cmn_err(CE_NOTE, "gld_close(%p, Style %d)",
		    (void *)q, (gld->gld_style & 0x1) + 1);
	}
#endif

	/* Hold all device streams lists still while we check for a macinfo */
	mutex_enter(&glddev->gld_devlock);

	if (gld->gld_mac_info != NULL) {
		/* If there's a macinfo, block recv while we change state */
		GLDM_LOCK(gld->gld_mac_info, RW_WRITER);
		gld->gld_flags |= GLD_STR_CLOSING; /* no more rcv putnexts */
		GLDM_UNLOCK(gld->gld_mac_info);
	} else {
		/* no mac DL_ATTACHED right now */
		gld->gld_flags |= GLD_STR_CLOSING;
	}

	mutex_exit(&glddev->gld_devlock);

	/*
	 * qprocsoff before we call gld_unbind/gldunattach, so that
	 * we know wsrv isn't in there trying to undo what we're doing.
	 */
	qprocsoff(q);

	ASSERT(gld->gld_wput_count == 0);
	gld->gld_wput_count = 0;	/* just in case */

	if (gld->gld_state == DL_IDLE) {
		/* Need to unbind */
		ASSERT(gld->gld_mac_info != NULL);
		(void) gld_unbind(WR(q), NULL);
	}

	if (gld->gld_state == DL_UNBOUND) {
		/*
		 * Need to unattach
		 * For style 2 stream, gldunattach also
		 * associate queue with NULL dip
		 */
		ASSERT(gld->gld_mac_info != NULL);
		(void) gldunattach(WR(q), NULL);
	}

	/* disassociate the stream from the device */
	q->q_ptr = WR(q)->q_ptr = NULL;

	/*
	 * Since we unattached above (if necessary), we know that we're
	 * on the per-major list of unattached streams, rather than a
	 * per-PPA list.  So we know we should hold the devlock.
	 */
	mutex_enter(&glddev->gld_devlock);
	gldremque(gld);			/* remove from Style 2 list */
	mutex_exit(&glddev->gld_devlock);

	kmem_free(gld, sizeof (gld_t));

	return (0);
}

/*
 * gld_rsrv (q)
 *	simple read service procedure
 *	purpose is to avoid the time it takes for packets
 *	to move through IP so we can get them off the board
 *	as fast as possible due to limited PC resources.
 *
 *	This is not normally used in the current implementation.  It
 *	can be selected with the undocumented property "fast_recv".
 *	If that property is set, gld_recv will send the packet
 *	upstream with a putq() rather than a putnext(), thus causing
 *	this routine to be scheduled.
 */
int
gld_rsrv(queue_t *q)
{
	mblk_t *mp;

	while ((mp = getq(q)) != NULL) {
		if (canputnext(q)) {
			putnext(q, mp);
		} else {
			freemsg(mp);
		}
	}
	return (0);
}

/*
 * gld_wput (q, mp)
 * general gld stream write put routine. Receives fastpath data from upper
 * modules and processes it immediately.  ioctl and M_PROTO/M_PCPROTO are
 * queued for later processing by the service procedure.
 */

int
gld_wput(queue_t *q, mblk_t *mp)
{
	gld_t  *gld = (gld_t *)(q->q_ptr);
	int	rc;
	boolean_t multidata = B_TRUE;
	uint32_t upri;

#ifdef GLD_DEBUG
	if (gld_debug & GLDTRACE)
		cmn_err(CE_NOTE, "gld_wput(%p %p): type %x",
		    (void *)q, (void *)mp, DB_TYPE(mp));
#endif
	switch (DB_TYPE(mp)) {

	case M_DATA:
		/* fast data / raw support */
		/* we must be DL_ATTACHED and DL_BOUND to do this */
		/* Tricky to access memory without taking the mutex */
		if ((gld->gld_flags & (GLD_RAW | GLD_FAST)) == 0 ||
		    gld->gld_state != DL_IDLE) {
			merror(q, mp, EPROTO);
			break;
		}
		/*
		 * Cleanup MBLK_VTAG in case it is set by other
		 * modules. MBLK_VTAG is used to save the vtag information.
		 */
		GLD_CLEAR_MBLK_VTAG(mp);
		multidata = B_FALSE;
		/* LINTED: E_CASE_FALLTHRU */
	case M_MULTIDATA:
		/* Only call gld_start() directly if nothing queued ahead */
		/* No guarantees about ordering with different threads */
		if (q->q_first)
			goto use_wsrv;

		/*
		 * This can happen if wsrv has taken off the last mblk but
		 * is still processing it.
		 */
		membar_consumer();
		if (gld->gld_in_wsrv)
			goto use_wsrv;

		/*
		 * Keep a count of current wput calls to start.
		 * Nonzero count delays any attempted DL_UNBIND.
		 * See comments above gld_start().
		 */
		atomic_inc_32((uint32_t *)&gld->gld_wput_count);
		membar_enter();

		/* Recheck state now wput_count is set to prevent DL_UNBIND */
		/* If this Q is in process of DL_UNBIND, don't call start */
		if (gld->gld_state != DL_IDLE || gld->gld_in_unbind) {
			/* Extremely unlikely */
			atomic_dec_32((uint32_t *)&gld->gld_wput_count);
			goto use_wsrv;
		}

		/*
		 * Get the priority value. Note that in raw mode, the
		 * per-packet priority value kept in b_band is ignored.
		 */
		upri = (gld->gld_flags & GLD_RAW) ? gld->gld_upri :
		    UPRI(gld, mp->b_band);

		rc = (multidata) ? gld_start_mdt(q, mp, GLD_WPUT) :
		    gld_start(q, mp, GLD_WPUT, upri);

		/* Allow DL_UNBIND again */
		membar_exit();
		atomic_dec_32((uint32_t *)&gld->gld_wput_count);

		if (rc == GLD_NORESOURCES)
			qenable(q);
		break;	/*  Done with this packet */

use_wsrv:
		/* Q not empty, in DL_DETACH, or start gave NORESOURCES */
		(void) putq(q, mp);
		qenable(q);
		break;

	case M_IOCTL:
		/* ioctl relies on wsrv single threading per queue */
		(void) putq(q, mp);
		qenable(q);
		break;

	case M_CTL:
		(void) putq(q, mp);
		qenable(q);
		break;

	case M_FLUSH:		/* canonical flush handling */
		/* XXX Should these be FLUSHALL? */
		if (*mp->b_rptr & FLUSHW)
			flushq(q, 0);
		if (*mp->b_rptr & FLUSHR) {
			flushq(RD(q), 0);
			*mp->b_rptr &= ~FLUSHW;
			qreply(q, mp);
		} else
			freemsg(mp);
		break;

	case M_PROTO:
	case M_PCPROTO:
		/* these rely on wsrv single threading per queue */
		(void) putq(q, mp);
		qenable(q);
		break;

	default:
#ifdef GLD_DEBUG
		if (gld_debug & GLDETRACE)
			cmn_err(CE_WARN,
			    "gld: Unexpected packet type from queue: 0x%x",
			    DB_TYPE(mp));
#endif
		freemsg(mp);
	}
	return (0);
}

/*
 * gld_wsrv - Incoming messages are processed according to the DLPI protocol
 * specification.
 *
 * wsrv is single-threaded per Q.  We make use of this to avoid taking the
 * lock for reading data items that are only ever written by us.
 */

int
gld_wsrv(queue_t *q)
{
	mblk_t *mp;
	gld_t *gld = (gld_t *)q->q_ptr;
	gld_mac_info_t *macinfo;
	union DL_primitives *prim;
	int err;
	boolean_t multidata;
	uint32_t upri;

#ifdef GLD_DEBUG
	if (gld_debug & GLDTRACE)
		cmn_err(CE_NOTE, "gld_wsrv(%p)", (void *)q);
#endif

	ASSERT(!gld->gld_in_wsrv);

	gld->gld_xwait = B_FALSE; /* We are now going to process this Q */

	if (q->q_first == NULL)
		return (0);

	macinfo = gld->gld_mac_info;

	/*
	 * Help wput avoid a call to gld_start if there might be a message
	 * previously queued by that thread being processed here.
	 */
	gld->gld_in_wsrv = B_TRUE;
	membar_enter();

	while ((mp = getq(q)) != NULL) {
		switch (DB_TYPE(mp)) {
		case M_DATA:
		case M_MULTIDATA:
			multidata = (DB_TYPE(mp) == M_MULTIDATA);

			/*
			 * retry of a previously processed UNITDATA_REQ
			 * or is a RAW or FAST message from above.
			 */
			if (macinfo == NULL) {
				/* No longer attached to a PPA, drop packet */
				freemsg(mp);
				break;
			}

			gld->gld_sched_ran = B_FALSE;
			membar_enter();

			/*
			 * Get the priority value. Note that in raw mode, the
			 * per-packet priority value kept in b_band is ignored.
			 */
			upri = (gld->gld_flags & GLD_RAW) ? gld->gld_upri :
			    UPRI(gld, mp->b_band);

			err = (multidata) ? gld_start_mdt(q, mp, GLD_WSRV) :
			    gld_start(q, mp, GLD_WSRV, upri);
			if (err == GLD_NORESOURCES) {
				/* gld_sched will qenable us later */
				gld->gld_xwait = B_TRUE; /* want qenable */
				membar_enter();
				/*
				 * v2:  we're not holding the lock; it's
				 * possible that the driver could have already
				 * called gld_sched (following up on its
				 * return of GLD_NORESOURCES), before we got a
				 * chance to do the putbq() and set gld_xwait.
				 * So if we saw a call to gld_sched that
				 * examined this queue, since our call to
				 * gld_start() above, then it's possible we've
				 * already seen the only call to gld_sched()
				 * we're ever going to see.  So we better retry
				 * transmitting this packet right now.
				 */
				if (gld->gld_sched_ran) {
#ifdef GLD_DEBUG
					if (gld_debug & GLDTRACE)
						cmn_err(CE_NOTE, "gld_wsrv: "
						    "sched was called");
#endif
					break;	/* try again right now */
				}
				gld->gld_in_wsrv = B_FALSE;
				return (0);
			}
			break;

		case M_IOCTL:
			(void) gld_ioctl(q, mp);
			break;

		case M_CTL:
			if (macinfo == NULL) {
				freemsg(mp);
				break;
			}

			if (macinfo->gldm_mctl != NULL) {
				GLDM_LOCK(macinfo, RW_WRITER);
				(void) (*macinfo->gldm_mctl) (macinfo, q, mp);
				GLDM_UNLOCK(macinfo);
			} else {
				/* This driver doesn't recognize, just drop */
				freemsg(mp);
			}
			break;

		case M_PROTO:	/* Will be an DLPI message of some type */
		case M_PCPROTO:
			if ((err = gld_cmds(q, mp)) != GLDE_OK) {
				if (err == GLDE_RETRY) {
					gld->gld_in_wsrv = B_FALSE;
					return (0); /* quit while we're ahead */
				}
				prim = (union DL_primitives *)mp->b_rptr;
				dlerrorack(q, mp, prim->dl_primitive, err, 0);
			}
			break;

		default:
			/* This should never happen */
#ifdef GLD_DEBUG
			if (gld_debug & GLDERRS)
				cmn_err(CE_WARN,
				    "gld_wsrv: db_type(%x) not supported",
				    mp->b_datap->db_type);
#endif
			freemsg(mp);	/* unknown types are discarded */
			break;
		}
	}

	membar_exit();
	gld->gld_in_wsrv = B_FALSE;
	return (0);
}

/*
 * gld_start() can get called from gld_wput(), gld_wsrv(), or gld_unitdata().
 *
 * We only come directly from wput() in the GLD_FAST (fastpath) or RAW case.
 *
 * In particular, we must avoid calling gld_precv*() if we came from wput().
 * gld_precv*() is where we, on the transmit side, loop back our outgoing
 * packets to the receive side if we are in physical promiscuous mode.
 * Since the receive side holds a lock across its call to the upstream
 * putnext, and that upstream module could well have looped back to our
 * wput() routine on the same thread, we cannot call gld_precv* from here
 * for fear of causing a recursive lock entry in our receive code.
 *
 * There is a problem here when coming from gld_wput().  While wput
 * only comes here if the queue is attached to a PPA and bound to a SAP
 * and there are no messages on the queue ahead of the M_DATA that could
 * change that, it is theoretically possible that another thread could
 * now wput a DL_UNBIND and a DL_DETACH message, and the wsrv() routine
 * could wake up and process them, before we finish processing this
 * send of the M_DATA.  This can only possibly happen on a Style 2 RAW or
 * FAST (fastpath) stream:  non RAW/FAST streams always go through wsrv(),
 * and Style 1 streams only DL_DETACH in the close routine, where
 * qprocsoff() protects us.  If this happens we could end up calling
 * gldm_send() after we have detached the stream and possibly called
 * gldm_stop().  Worse, once the number of attached streams goes to zero,
 * detach/unregister could be called, and the macinfo could go away entirely.
 *
 * No one has ever seen this happen.
 *
 * It is some trouble to fix this, and we would rather not add any mutex
 * logic into the wput() routine, which is supposed to be a "fast"
 * path.
 *
 * What I've done is use an atomic counter to keep a count of the number
 * of threads currently calling gld_start() from wput() on this stream.
 * If DL_DETACH sees this as nonzero, it putbqs the request back onto
 * the queue and qenables, hoping to have better luck next time.  Since
 * people shouldn't be trying to send after they've asked to DL_DETACH,
 * hopefully very soon all the wput=>start threads should have returned
 * and the DL_DETACH will succeed.  It's hard to test this since the odds
 * of the failure even trying to happen are so small.  I probably could
 * have ignored the whole issue and never been the worse for it.
 *
 * Because some GLDv2 Ethernet drivers do not allow the size of transmitted
 * packet to be greater than ETHERMAX, we must first strip the VLAN tag
 * from a tagged packet before passing it to the driver's gld_send() entry
 * point function, and pass the VLAN tag as a separate argument. The
 * gld_send() function may fail. In that case, the packet will need to be
 * queued in order to be processed again in GLD's service routine. As the
 * VTAG has already been stripped at that time, we save the VTAG information
 * in (the unused fields of) dblk using GLD_SAVE_MBLK_VTAG(), so that the
 * VTAG can also be queued and be able to be got when gld_start() is called
 * next time from gld_wsrv().
 *
 * Some rules to use GLD_{CLEAR|SAVE}_MBLK_VTAG macros:
 *
 * - GLD_SAVE_MBLK_VTAG() must be called to save the VTAG information each time
 *   the message is queued by putbq().
 *
 * - GLD_CLEAR_MBLK_VTAG() must be called to clear the bogus VTAG information
 *   (if any) in dblk before the message is passed to the gld_start() function.
 */
static int
gld_start(queue_t *q, mblk_t *mp, int caller, uint32_t upri)
{
	mblk_t *nmp;
	gld_t *gld = (gld_t *)q->q_ptr;
	gld_mac_info_t *macinfo;
	gld_mac_pvt_t *mac_pvt;
	int rc;
	gld_interface_t *ifp;
	pktinfo_t pktinfo;
	uint32_t vtag, vid;
	uint32_t raw_vtag = 0;
	gld_vlan_t *vlan;
	struct gld_stats *stats0, *stats = NULL;

	ASSERT(DB_TYPE(mp) == M_DATA);
	macinfo = gld->gld_mac_info;
	mac_pvt = (gld_mac_pvt_t *)macinfo->gldm_mac_pvt;
	ifp = mac_pvt->interfacep;
	vlan = (gld_vlan_t *)gld->gld_vlan;
	vid = vlan->gldv_id;

	/*
	 * If this interface is a VLAN, the kstats of corresponding
	 * "VLAN 0" should also be updated. Note that the gld_vlan_t
	 * structure for VLAN 0 might not exist if there are no DLPI
	 * consumers attaching on VLAN 0. Fortunately we can directly
	 * access VLAN 0's kstats from macinfo.
	 *
	 * Therefore, stats0 (VLAN 0's kstats) must always be
	 * updated, and stats must to be updated if it is not NULL.
	 */
	stats0 = mac_pvt->statistics;
	if (vid != VLAN_VID_NONE)
		stats = vlan->gldv_stats;

	if ((*ifp->interpreter)(macinfo, mp, &pktinfo, GLD_TX) != 0) {
#ifdef GLD_DEBUG
		if (gld_debug & GLDERRS)
			cmn_err(CE_WARN,
			    "gld_start: failed to interpret outbound packet");
#endif
		goto badarg;
	}

	vtag = VLAN_VID_NONE;
	raw_vtag = GLD_GET_MBLK_VTAG(mp);
	if (GLD_VTAG_TCI(raw_vtag) != 0) {
		uint16_t raw_pri, raw_vid, evid;

		/*
		 * Tagged packet.
		 */
		raw_pri = GLD_VTAG_PRI(raw_vtag);
		raw_vid = GLD_VTAG_VID(raw_vtag);
		GLD_CLEAR_MBLK_VTAG(mp);

		if (gld->gld_flags & GLD_RAW) {
			/*
			 * In raw mode, we only expect untagged packets or
			 * special priority-tagged packets on a VLAN stream.
			 * Drop the packet if its VID is not zero.
			 */
			if (vid != VLAN_VID_NONE && raw_vid != VLAN_VID_NONE)
				goto badarg;

			/*
			 * If it is raw mode, use the per-stream priority if
			 * the priority is not specified in the packet.
			 * Otherwise, ignore the priority bits in the packet.
			 */
			upri = (raw_pri != 0) ? raw_pri : upri;
		}

		if (vid == VLAN_VID_NONE && vid != raw_vid) {
			gld_vlan_t *tmp_vlan;

			/*
			 * This link is a physical link but the packet is
			 * a VLAN tagged packet, the kstats of corresponding
			 * VLAN (if any) should also be updated.
			 */
			tmp_vlan = gld_find_vlan(macinfo, raw_vid);
			if (tmp_vlan != NULL)
				stats = tmp_vlan->gldv_stats;
		}

		evid = (vid == VLAN_VID_NONE) ? raw_vid : vid;
		if (evid != VLAN_VID_NONE || upri != 0)
			vtag = GLD_MAKE_VTAG(upri, VLAN_CFI_ETHER, evid);
	} else {
		/*
		 * Untagged packet:
		 * Get vtag from the attached PPA of this stream.
		 */
		if ((vid != VLAN_VID_NONE) ||
		    ((macinfo->gldm_type == DL_ETHER) && (upri != 0))) {
			vtag = GLD_MAKE_VTAG(upri, VLAN_CFI_ETHER, vid);
		}
	}

	/*
	 * We're not holding the lock for this check.  If the promiscuous
	 * state is in flux it doesn't matter much if we get this wrong.
	 */
	if (mac_pvt->nprom > 0) {
		/*
		 * We want to loopback to the receive side, but to avoid
		 * recursive lock entry:  if we came from wput(), which
		 * could have looped back via IP from our own receive
		 * interrupt thread, we decline this request.  wput()
		 * will then queue the packet for wsrv().  This means
		 * that when snoop is running we don't get the advantage
		 * of the wput() multithreaded direct entry to the
		 * driver's send routine.
		 */
		if (caller == GLD_WPUT) {
			GLD_SAVE_MBLK_VTAG(mp, raw_vtag);
			(void) putbq(q, mp);
			return (GLD_NORESOURCES);
		}
		if (macinfo->gldm_capabilities & GLD_CAP_ZEROCOPY)
			nmp = dupmsg_noloan(mp);
		else
			nmp = dupmsg(mp);
	} else
		nmp = NULL;		/* we need no loopback */

	if (ifp->hdr_size > 0 &&
	    pktinfo.pktLen > ifp->hdr_size + (vtag == 0 ? 0 : VTAG_SIZE) +
	    macinfo->gldm_maxpkt) {
		if (nmp)
			freemsg(nmp);	/* free the duped message */
#ifdef GLD_DEBUG
		if (gld_debug & GLDERRS)
			cmn_err(CE_WARN,
			    "gld_start: oversize outbound packet, size %d,"
			    "max %d", pktinfo.pktLen,
			    ifp->hdr_size + (vtag == 0 ? 0 : VTAG_SIZE) +
			    macinfo->gldm_maxpkt);
#endif
		goto badarg;
	}

	rc = (*gld->gld_send)(macinfo, mp, vtag);

	if (rc != GLD_SUCCESS) {
		if (rc == GLD_NORESOURCES) {
			ATOMIC_BUMP(stats0, stats, glds_xmtretry, 1);
			GLD_SAVE_MBLK_VTAG(mp, raw_vtag);
			(void) putbq(q, mp);
		} else {
			/* transmit error; drop the packet */
			freemsg(mp);
			/* We're supposed to count failed attempts as well */
			UPDATE_STATS(stats0, stats, pktinfo, 1);
#ifdef GLD_DEBUG
			if (gld_debug & GLDERRS)
				cmn_err(CE_WARN,
				    "gld_start: gldm_send failed %d", rc);
#endif
		}
		if (nmp)
			freemsg(nmp);	/* free the dupped message */
		return (rc);
	}

	UPDATE_STATS(stats0, stats, pktinfo, 1);

	/*
	 * Loopback case. The message needs to be returned back on
	 * the read side. This would silently fail if the dupmsg fails
	 * above. This is probably OK, if there is no memory to dup the
	 * block, then there isn't much we could do anyway.
	 */
	if (nmp) {
		GLDM_LOCK(macinfo, RW_WRITER);
		gld_precv(macinfo, nmp, vtag, stats);
		GLDM_UNLOCK(macinfo);
	}

	return (GLD_SUCCESS);
badarg:
	freemsg(mp);

	ATOMIC_BUMP(stats0, stats, glds_xmtbadinterp, 1);
	return (GLD_BADARG);
}

/*
 * With MDT V.2 a single message mp can have one header area and multiple
 * payload areas. A packet is described by dl_pkt_info, and each packet can
 * span multiple payload areas (currently with TCP, each packet will have one
 * header and at the most two payload areas). MACs might have a limit on the
 * number of payload segments (i.e. per packet scatter-gather limit), and
 * MDT V.2 has a way of specifying that with mdt_span_limit; the MAC driver
 * might also have a limit on the total number of payloads in a message, and
 * that is specified by mdt_max_pld.
 */
static int
gld_start_mdt(queue_t *q, mblk_t *mp, int caller)
{
	mblk_t *nextmp;
	gld_t *gld = (gld_t *)q->q_ptr;
	gld_mac_info_t *macinfo = gld->gld_mac_info;
	gld_mac_pvt_t *mac_pvt = (gld_mac_pvt_t *)macinfo->gldm_mac_pvt;
	int numpacks, mdtpacks;
	gld_interface_t *ifp = mac_pvt->interfacep;
	pktinfo_t pktinfo;
	gld_vlan_t *vlan = (gld_vlan_t *)gld->gld_vlan;
	boolean_t doloop = B_FALSE;
	multidata_t *dlmdp;
	pdescinfo_t pinfo;
	pdesc_t *dl_pkt;
	void *cookie;
	uint_t totLen = 0;

	ASSERT(DB_TYPE(mp) == M_MULTIDATA);

	/*
	 * We're not holding the lock for this check.  If the promiscuous
	 * state is in flux it doesn't matter much if we get this wrong.
	 */
	if (mac_pvt->nprom > 0) {
		/*
		 * We want to loopback to the receive side, but to avoid
		 * recursive lock entry:  if we came from wput(), which
		 * could have looped back via IP from our own receive
		 * interrupt thread, we decline this request.  wput()
		 * will then queue the packet for wsrv().  This means
		 * that when snoop is running we don't get the advantage
		 * of the wput() multithreaded direct entry to the
		 * driver's send routine.
		 */
		if (caller == GLD_WPUT) {
			(void) putbq(q, mp);
			return (GLD_NORESOURCES);
		}
		doloop = B_TRUE;

		/*
		 * unlike the M_DATA case, we don't have to call
		 * dupmsg_noloan here because mmd_transform
		 * (called by gld_precv_mdt) will make a copy of
		 * each dblk.
		 */
	}

	while (mp != NULL) {
		/*
		 * The lower layer driver only gets a single multidata
		 * message; this also makes it easier to handle noresources.
		 */
		nextmp = mp->b_cont;
		mp->b_cont = NULL;

		/*
		 * Get number of packets in this message; if nothing
		 * to transmit, go to next message.
		 */
		dlmdp = mmd_getmultidata(mp);
		if ((mdtpacks = (int)mmd_getcnt(dlmdp, NULL, NULL)) == 0) {
			freemsg(mp);
			mp = nextmp;
			continue;
		}

		/*
		 * Run interpreter to populate media specific pktinfo fields.
		 * This collects per MDT message information like sap,
		 * broad/multicast etc.
		 */
		(void) (*ifp->interpreter_mdt)(macinfo, mp, NULL, &pktinfo,
		    GLD_MDT_TX);

		numpacks = (*macinfo->gldm_mdt_pre)(macinfo, mp, &cookie);

		if (numpacks > 0) {
			/*
			 * Driver indicates it can transmit at least 1, and
			 * possibly all, packets in MDT message.
			 */
			int count = numpacks;

			for (dl_pkt = mmd_getfirstpdesc(dlmdp, &pinfo);
			    (dl_pkt != NULL);
			    dl_pkt = mmd_getnextpdesc(dl_pkt, &pinfo)) {
				/*
				 * Format this packet by adding link header and
				 * adjusting pdescinfo to include it; get
				 * packet length.
				 */
				(void) (*ifp->interpreter_mdt)(macinfo, NULL,
				    &pinfo, &pktinfo, GLD_MDT_TXPKT);

				totLen += pktinfo.pktLen;

				/*
				 * Loop back packet before handing to the
				 * driver.
				 */
				if (doloop &&
				    mmd_adjpdesc(dl_pkt, &pinfo) != NULL) {
					GLDM_LOCK(macinfo, RW_WRITER);
					gld_precv_mdt(macinfo, vlan, mp,
					    dl_pkt, &pktinfo);
					GLDM_UNLOCK(macinfo);
				}

				/*
				 * And send off to driver.
				 */
				(*macinfo->gldm_mdt_send)(macinfo, cookie,
				    &pinfo);

				/*
				 * Be careful not to invoke getnextpdesc if we
				 * already sent the last packet, since driver
				 * might have posted it to hardware causing a
				 * completion and freemsg() so the MDT data
				 * structures might not be valid anymore.
				 */
				if (--count == 0)
					break;
			}
			(*macinfo->gldm_mdt_post)(macinfo, mp, cookie);
			pktinfo.pktLen = totLen;
			UPDATE_STATS(vlan->gldv_stats, NULL, pktinfo, numpacks);

			/*
			 * In the noresources case (when driver indicates it
			 * can not transmit all packets in the MDT message),
			 * adjust to skip the first few packets on retrial.
			 */
			if (numpacks != mdtpacks) {
				/*
				 * Release already processed packet descriptors.
				 */
				for (count = 0; count < numpacks; count++) {
					dl_pkt = mmd_getfirstpdesc(dlmdp,
					    &pinfo);
					mmd_rempdesc(dl_pkt);
				}
				ATOMIC_BUMP(vlan->gldv_stats, NULL,
				    glds_xmtretry, 1);
				mp->b_cont = nextmp;
				(void) putbq(q, mp);
				return (GLD_NORESOURCES);
			}
		} else if (numpacks == 0) {
			/*
			 * Driver indicates it can not transmit any packets
			 * currently and will request retrial later.
			 */
			ATOMIC_BUMP(vlan->gldv_stats, NULL, glds_xmtretry, 1);
			mp->b_cont = nextmp;
			(void) putbq(q, mp);
			return (GLD_NORESOURCES);
		} else {
			ASSERT(numpacks == -1);
			/*
			 * We're supposed to count failed attempts as well.
			 */
			dl_pkt = mmd_getfirstpdesc(dlmdp, &pinfo);
			while (dl_pkt != NULL) {
				/*
				 * Call interpreter to determine total packet
				 * bytes that are being dropped.
				 */
				(void) (*ifp->interpreter_mdt)(macinfo, NULL,
				    &pinfo, &pktinfo, GLD_MDT_TXPKT);

				totLen += pktinfo.pktLen;

				dl_pkt = mmd_getnextpdesc(dl_pkt, &pinfo);
			}
			pktinfo.pktLen = totLen;
			UPDATE_STATS(vlan->gldv_stats, NULL, pktinfo, mdtpacks);

			/*
			 * Transmit error; drop the message, move on
			 * to the next one.
			 */
			freemsg(mp);
		}

		/*
		 * Process the next multidata block, if there is one.
		 */
		mp = nextmp;
	}

	return (GLD_SUCCESS);
}

/*
 * gld_intr (macinfo)
 */
uint_t
gld_intr(gld_mac_info_t *macinfo)
{
	ASSERT(macinfo != NULL);

	if (!(macinfo->gldm_GLD_flags & GLD_MAC_READY))
		return (DDI_INTR_UNCLAIMED);

	return ((*macinfo->gldm_intr)(macinfo));
}

/*
 * gld_sched (macinfo)
 *
 * This routine scans the streams that refer to a specific macinfo
 * structure and causes the STREAMS scheduler to try to run them if
 * they are marked as waiting for the transmit buffer.
 */
void
gld_sched(gld_mac_info_t *macinfo)
{
	gld_mac_pvt_t *mac_pvt;
	gld_t *gld;
	gld_vlan_t *vlan;
	int i;

	ASSERT(macinfo != NULL);

	GLDM_LOCK(macinfo, RW_WRITER);

	if (macinfo->gldm_GLD_flags & GLD_UNREGISTERED) {
		/* We're probably being called from a leftover interrupt */
		GLDM_UNLOCK(macinfo);
		return;
	}

	mac_pvt = (gld_mac_pvt_t *)macinfo->gldm_mac_pvt;

	for (i = 0; i < VLAN_HASHSZ; i++) {
		for (vlan = mac_pvt->vlan_hash[i];
		    vlan != NULL; vlan = vlan->gldv_next) {
			for (gld = vlan->gldv_str_next;
			    gld != (gld_t *)&vlan->gldv_str_next;
			    gld = gld->gld_next) {
				ASSERT(gld->gld_mac_info == macinfo);
				gld->gld_sched_ran = B_TRUE;
				membar_enter();
				if (gld->gld_xwait) {
					gld->gld_xwait = B_FALSE;
					qenable(WR(gld->gld_qptr));
				}
			}
		}
	}

	GLDM_UNLOCK(macinfo);
}

/*
 * gld_precv (macinfo, mp, vtag, stats)
 * called from gld_start to loopback a packet when in promiscuous mode
 *
 * VLAN 0's statistics need to be updated. If stats is not NULL,
 * it needs to be updated as well.
 */
static void
gld_precv(gld_mac_info_t *macinfo, mblk_t *mp, uint32_t vtag,
    struct gld_stats *stats)
{
	gld_mac_pvt_t *mac_pvt;
	gld_interface_t *ifp;
	pktinfo_t pktinfo;

	ASSERT(GLDM_LOCK_HELD_WRITE(macinfo));

	mac_pvt = (gld_mac_pvt_t *)macinfo->gldm_mac_pvt;
	ifp = mac_pvt->interfacep;

	/*
	 * call the media specific packet interpreter routine
	 */
	if ((*ifp->interpreter)(macinfo, mp, &pktinfo, GLD_RXLOOP) != 0) {
		freemsg(mp);
		BUMP(mac_pvt->statistics, stats, glds_rcvbadinterp, 1);
#ifdef GLD_DEBUG
		if (gld_debug & GLDERRS)
			cmn_err(CE_WARN,
			    "gld_precv: interpreter failed");
#endif
		return;
	}

	/*
	 * Update the vtag information.
	 */
	pktinfo.isTagged = (vtag != VLAN_VID_NONE);
	pktinfo.vid = GLD_VTAG_VID(vtag);
	pktinfo.cfi = GLD_VTAG_CFI(vtag);
	pktinfo.user_pri = GLD_VTAG_PRI(vtag);

	gld_sendup(macinfo, &pktinfo, mp, gld_paccept);
}

/*
 * Called from gld_start_mdt to loopback packet(s) when in promiscuous mode.
 * Note that 'vlan' is always a physical link, because MDT can only be
 * enabled on non-VLAN streams.
 */
/*ARGSUSED*/
static void
gld_precv_mdt(gld_mac_info_t *macinfo, gld_vlan_t *vlan, mblk_t *mp,
    pdesc_t *dl_pkt, pktinfo_t *pktinfo)
{
	mblk_t *adjmp;
	gld_mac_pvt_t *mac_pvt = (gld_mac_pvt_t *)macinfo->gldm_mac_pvt;
	gld_interface_t *ifp = mac_pvt->interfacep;

	ASSERT(GLDM_LOCK_HELD_WRITE(macinfo));

	/*
	 * Get source/destination.
	 */
	(void) (*ifp->interpreter_mdt)(macinfo, mp, NULL, pktinfo,
	    GLD_MDT_RXLOOP);
	if ((adjmp = mmd_transform(dl_pkt)) != NULL)
		gld_sendup(macinfo, pktinfo, adjmp, gld_paccept);
}

/*
 * gld_recv (macinfo, mp)
 * called with an mac-level packet in a mblock; take the maclock,
 * try the ip4q and ip6q hack, and otherwise call gld_sendup.
 *
 * V0 drivers already are holding the mutex when they call us.
 */
void
gld_recv(gld_mac_info_t *macinfo, mblk_t *mp)
{
	gld_recv_tagged(macinfo, mp, VLAN_VTAG_NONE);
}

void
gld_recv_tagged(gld_mac_info_t *macinfo, mblk_t *mp, uint32_t vtag)
{
	gld_mac_pvt_t *mac_pvt;
	char pbuf[3*GLD_MAX_ADDRLEN];
	pktinfo_t pktinfo;
	gld_interface_t *ifp;
	queue_t *ipq = NULL;
	gld_vlan_t *vlan = NULL, *vlan0 = NULL, *vlann = NULL;
	struct gld_stats *stats0, *stats = NULL;
	uint32_t vid;
	int err;

	ASSERT(macinfo != NULL);
	ASSERT(mp->b_datap->db_ref);

	GLDM_LOCK(macinfo, RW_READER);

	if (macinfo->gldm_GLD_flags & GLD_UNREGISTERED) {
		/* We're probably being called from a leftover interrupt */
		freemsg(mp);
		goto done;
	}

	/*
	 * If this packet is a VLAN tagged packet, the kstats of corresponding
	 * "VLAN 0" should also be updated. We can directly access VLAN 0's
	 * kstats from macinfo.
	 *
	 * Further, the packets needs to be passed to VLAN 0 if there is
	 * any DLPI consumer on VLAN 0 who is interested in tagged packets
	 * (DL_PROMISC_SAP is on or is bounded to ETHERTYPE_VLAN SAP).
	 */
	mac_pvt = (gld_mac_pvt_t *)macinfo->gldm_mac_pvt;
	stats0 = mac_pvt->statistics;

	vid = GLD_VTAG_VID(vtag);
	vlan0 = gld_find_vlan(macinfo, VLAN_VID_NONE);
	if (vid != VLAN_VID_NONE) {
		/*
		 * If there are no physical DLPI consumers interested in the
		 * VLAN packet, clear vlan0.
		 */
		if ((vlan0 != NULL) && (vlan0->gldv_nvlan_sap == 0))
			vlan0 = NULL;
		/*
		 * vlann is the VLAN with the same VID as the VLAN packet.
		 */
		vlann = gld_find_vlan(macinfo, vid);
		if (vlann != NULL)
			stats = vlann->gldv_stats;
	}

	vlan = (vid == VLAN_VID_NONE) ? vlan0 : vlann;

	ifp = mac_pvt->interfacep;
	err = (*ifp->interpreter)(macinfo, mp, &pktinfo, GLD_RXQUICK);

	BUMP(stats0, stats, glds_bytercv64, pktinfo.pktLen);
	BUMP(stats0, stats, glds_pktrcv64, 1);

	if ((vlann == NULL) && (vlan0 == NULL)) {
		freemsg(mp);
		goto done;
	}

	/*
	 * Check whether underlying media code supports the IPQ hack:
	 *
	 * - the interpreter could quickly parse the packet
	 * - the device type supports IPQ (ethernet and IPoIB)
	 * - there is one, and only one, IP stream bound (to this VLAN)
	 * - that stream is a "fastpath" stream
	 * - the packet is of type ETHERTYPE_IP or ETHERTYPE_IPV6
	 * - there are no streams in promiscuous mode (on this VLAN)
	 * - if this packet is tagged, there is no need to send this
	 *   packet to physical streams
	 */
	if ((err != 0) && ((vlan != NULL) && (vlan->gldv_nprom == 0)) &&
	    (vlan == vlan0 || vlan0 == NULL)) {
		switch (pktinfo.ethertype) {
		case ETHERTYPE_IP:
			ipq = vlan->gldv_ipq;
			break;
		case ETHERTYPE_IPV6:
			ipq = vlan->gldv_ipv6q;
			break;
		}
	}

	/*
	 * Special case for IP; we can simply do the putnext here, if:
	 * o The IPQ hack is possible (ipq != NULL).
	 * o the packet is specifically for me, and therefore:
	 * - the packet is not multicast or broadcast (fastpath only
	 *   wants unicast packets).
	 *
	 * o the stream is not asserting flow control.
	 */
	if (ipq != NULL &&
	    pktinfo.isForMe &&
	    canputnext(ipq)) {
		/*
		 * Skip the mac header. We know there is no LLC1/SNAP header
		 * in this packet
		 */
		mp->b_rptr += pktinfo.macLen;
		putnext(ipq, mp);
		goto done;
	}

	/*
	 * call the media specific packet interpreter routine
	 */
	if ((*ifp->interpreter)(macinfo, mp, &pktinfo, GLD_RX) != 0) {
		BUMP(stats0, stats, glds_rcvbadinterp, 1);
#ifdef GLD_DEBUG
		if (gld_debug & GLDERRS)
			cmn_err(CE_WARN,
			    "gld_recv_tagged: interpreter failed");
#endif
		freemsg(mp);
		goto done;
	}

	/*
	 * This is safe even if vtag is VLAN_VTAG_NONE
	 */
	pktinfo.vid = vid;
	pktinfo.cfi = GLD_VTAG_CFI(vtag);
#ifdef GLD_DEBUG
	if (pktinfo.cfi != VLAN_CFI_ETHER)
		cmn_err(CE_WARN, "gld_recv_tagged: non-ETHER CFI");
#endif
	pktinfo.user_pri = GLD_VTAG_PRI(vtag);
	pktinfo.isTagged = (vtag != VLAN_VID_NONE);

#ifdef GLD_DEBUG
	if ((gld_debug & GLDRECV) &&
	    (!(gld_debug & GLDNOBR) ||
	    (!pktinfo.isBroadcast && !pktinfo.isMulticast))) {
		char pbuf2[3*GLD_MAX_ADDRLEN];

		cmn_err(CE_CONT, "gld_recv_tagged: machdr=<%s -> %s>\n",
		    gld_macaddr_sprintf(pbuf, pktinfo.shost,
		    macinfo->gldm_addrlen), gld_macaddr_sprintf(pbuf2,
		    pktinfo.dhost, macinfo->gldm_addrlen));
		cmn_err(CE_CONT, "gld_recv_tagged: VlanId %d UserPri %d\n",
		    pktinfo.vid,
		    pktinfo.user_pri);
		cmn_err(CE_CONT, "gld_recv_tagged: ethertype: %4x Len: %4d "
		    "Hdr: %d,%d isMulticast: %s\n",
		    pktinfo.ethertype,
		    pktinfo.pktLen,
		    pktinfo.macLen,
		    pktinfo.hdrLen,
		    pktinfo.isMulticast ? "Y" : "N");
	}
#endif

	gld_sendup(macinfo, &pktinfo, mp, gld_accept);

done:
	GLDM_UNLOCK(macinfo);
}

/* =================================================================== */
/* receive group: called from gld_recv and gld_precv* with maclock held */
/* =================================================================== */

/*
 * Search all the streams attached to the specified VLAN looking for
 * those eligible to receive the packet.
 * Note that in order to avoid an extra dupmsg(), if this is the first
 * eligible stream, remember it (in fgldp) so that we can send up the
 * message after this function.
 *
 * Return errno if fails. Currently the only error is ENOMEM.
 */
static int
gld_sendup_vlan(gld_vlan_t *vlan, pktinfo_t *pktinfo, mblk_t *mp,
    int (*acceptfunc)(), void (*send)(), int (*cansend)(), gld_t **fgldp)
{
	mblk_t *nmp;
	gld_t *gld;
	int err = 0;

	ASSERT(vlan != NULL);
	for (gld = vlan->gldv_str_next; gld != (gld_t *)&vlan->gldv_str_next;
	    gld = gld->gld_next) {
#ifdef GLD_VERBOSE_DEBUG
		cmn_err(CE_NOTE, "gld_sendup_vlan: SAP: %4x QPTR: %p "
		    "QSTATE: %s", gld->gld_sap, (void *)gld->gld_qptr,
		    gld->gld_state == DL_IDLE ? "IDLE" : "NOT IDLE");
#endif
		ASSERT(gld->gld_qptr != NULL);
		ASSERT(gld->gld_state == DL_IDLE ||
		    gld->gld_state == DL_UNBOUND);
		ASSERT(gld->gld_vlan == vlan);

		if (gld->gld_state != DL_IDLE)
			continue;	/* not eligible to receive */
		if (gld->gld_flags & GLD_STR_CLOSING)
			continue;	/* not eligible to receive */

#ifdef GLD_DEBUG
		if ((gld_debug & GLDRECV) &&
		    (!(gld_debug & GLDNOBR) ||
		    (!pktinfo->isBroadcast && !pktinfo->isMulticast)))
			cmn_err(CE_NOTE,
			    "gld_sendup: queue sap: %4x promis: %s %s %s",
			    gld->gld_sap,
			    gld->gld_flags & GLD_PROM_PHYS ? "phys " : "     ",
			    gld->gld_flags & GLD_PROM_SAP  ? "sap  " : "     ",
			    gld->gld_flags & GLD_PROM_MULT ? "multi" : "     ");
#endif

		/*
		 * The accept function differs depending on whether this is
		 * a packet that we received from the wire or a loopback.
		 */
		if ((*acceptfunc)(gld, pktinfo)) {
			/* sap matches */
			pktinfo->wasAccepted = 1; /* known protocol */

			if (!(*cansend)(gld->gld_qptr)) {
				/*
				 * Upper stream is not accepting messages, i.e.
				 * it is flow controlled, therefore we will
				 * forgo sending the message up this stream.
				 */
#ifdef GLD_DEBUG
				if (gld_debug & GLDETRACE)
					cmn_err(CE_WARN,
					    "gld_sendup: canput failed");
#endif
				BUMP(vlan->gldv_stats, NULL, glds_blocked, 1);
				qenable(gld->gld_qptr);
				continue;
			}

			/*
			 * In order to avoid an extra dupmsg(), remember this
			 * gld if this is the first eligible stream.
			 */
			if (*fgldp == NULL) {
				*fgldp = gld;
				continue;
			}

			/* duplicate the packet for this stream */
			nmp = dupmsg(mp);
			if (nmp == NULL) {
				BUMP(vlan->gldv_stats, NULL,
				    glds_gldnorcvbuf, 1);
#ifdef GLD_DEBUG
				if (gld_debug & GLDERRS)
					cmn_err(CE_WARN,
					    "gld_sendup: dupmsg failed");
#endif
				/* couldn't get resources; drop it */
				err = ENOMEM;
				break;
			}
			/* pass the message up the stream */
			gld_passon(gld, nmp, pktinfo, send);
		}
	}
	return (err);
}

/*
 * gld_sendup (macinfo, pktinfo, mp, acceptfunc)
 * called with an ethernet packet in an mblk; must decide whether
 * packet is for us and which streams to queue it to.
 */
static void
gld_sendup(gld_mac_info_t *macinfo, pktinfo_t *pktinfo,
    mblk_t *mp, int (*acceptfunc)())
{
	gld_t *fgld = NULL;
	void (*send)(queue_t *qp, mblk_t *mp);
	int (*cansend)(queue_t *qp);
	gld_vlan_t *vlan0, *vlann = NULL;
	struct gld_stats *stats0, *stats = NULL;
	int err = 0;

#ifdef GLD_DEBUG
	if (gld_debug & GLDTRACE)
		cmn_err(CE_NOTE, "gld_sendup(%p, %p)", (void *)mp,
		    (void *)macinfo);
#endif

	ASSERT(mp != NULL);
	ASSERT(macinfo != NULL);
	ASSERT(pktinfo != NULL);
	ASSERT(GLDM_LOCK_HELD(macinfo));

	/*
	 * The tagged packets should also be looped back (transmit-side)
	 * or sent up (receive-side) to VLAN 0 if VLAN 0 is set to
	 * DL_PROMISC_SAP or there is any DLPI consumer bind to the
	 * ETHERTYPE_VLAN SAP. The kstats of VLAN 0 needs to be updated
	 * as well.
	 */
	stats0 = ((gld_mac_pvt_t *)macinfo->gldm_mac_pvt)->statistics;
	vlan0 = gld_find_vlan(macinfo, VLAN_VID_NONE);
	if (pktinfo->vid != VLAN_VID_NONE) {
		if ((vlan0 != NULL) && (vlan0->gldv_nvlan_sap == 0))
			vlan0 = NULL;
		vlann = gld_find_vlan(macinfo, pktinfo->vid);
		if (vlann != NULL)
			stats = vlann->gldv_stats;
	}

	ASSERT((vlan0 != NULL) || (vlann != NULL));

	/*
	 * The "fast" in "GLDOPT_FAST_RECV" refers to the speed at which
	 * gld_recv returns to the caller's interrupt routine.  The total
	 * network throughput would normally be lower when selecting this
	 * option, because we putq the messages and process them later,
	 * instead of sending them with putnext now.  Some time critical
	 * device might need this, so it's here but undocumented.
	 */
	if (macinfo->gldm_options & GLDOPT_FAST_RECV) {
		send = (void (*)(queue_t *, mblk_t *))putq;
		cansend = canput;
	} else {
		send = (void (*)(queue_t *, mblk_t *))putnext;
		cansend = canputnext;
	}

	/*
	 * Send the packets for all eligible streams.
	 */
	if (vlan0 != NULL) {
		err = gld_sendup_vlan(vlan0, pktinfo, mp, acceptfunc, send,
		    cansend, &fgld);
	}
	if ((err == 0) && (vlann != NULL)) {
		err = gld_sendup_vlan(vlann, pktinfo, mp, acceptfunc, send,
		    cansend, &fgld);
	}

	ASSERT(mp);
	/* send the original dup of the packet up the first stream found */
	if (fgld)
		gld_passon(fgld, mp, pktinfo, send);
	else
		freemsg(mp);	/* no streams matched */

	/* We do not count looped back packets */
	if (acceptfunc == gld_paccept)
		return;		/* transmit loopback case */

	if (pktinfo->isBroadcast)
		BUMP(stats0, stats, glds_brdcstrcv, 1);
	else if (pktinfo->isMulticast)
		BUMP(stats0, stats, glds_multircv, 1);

	/* No stream accepted this packet */
	if (!pktinfo->wasAccepted)
		BUMP(stats0, stats, glds_unknowns, 1);
}

#define	GLD_IS_PHYS(gld)	\
	(((gld_vlan_t *)gld->gld_vlan)->gldv_id == VLAN_VID_NONE)

/*
 * A packet matches a stream if:
 *      The stream's VLAN id is the same as the one in the packet.
 *  and the stream accepts EtherType encoded packets and the type matches
 *  or  the stream accepts LLC packets and the packet is an LLC packet
 */
#define	MATCH(stream, pktinfo) \
	((((gld_vlan_t *)stream->gld_vlan)->gldv_id == pktinfo->vid) && \
	((stream->gld_ethertype && stream->gld_sap == pktinfo->ethertype) || \
	(!stream->gld_ethertype && pktinfo->isLLC)))

/*
 * This function validates a packet for sending up a particular
 * stream. The message header has been parsed and its characteristic
 * are recorded in the pktinfo data structure. The streams stack info
 * are presented in gld data structures.
 */
static int
gld_accept(gld_t *gld, pktinfo_t *pktinfo)
{
	/*
	 * if there is no match do not bother checking further.
	 * Note that it is okay to examine gld_vlan because
	 * macinfo->gldm_lock is held.
	 *
	 * Because all tagged packets have SAP value ETHERTYPE_VLAN,
	 * these packets will pass the SAP filter check if the stream
	 * is a ETHERTYPE_VLAN listener.
	 */
	if ((!MATCH(gld, pktinfo) && !(gld->gld_flags & GLD_PROM_SAP) &&
	    !(GLD_IS_PHYS(gld) && gld->gld_sap == ETHERTYPE_VLAN &&
	    pktinfo->isTagged)))
		return (0);

	/*
	 * We don't accept any packet from the hardware if we originated it.
	 * (Contrast gld_paccept, the send-loopback accept function.)
	 */
	if (pktinfo->isLooped)
		return (0);

	/*
	 * If the packet is broadcast or sent to us directly we will accept it.
	 * Also we will accept multicast packets requested by the stream.
	 */
	if (pktinfo->isForMe || pktinfo->isBroadcast ||
	    gld_mcmatch(gld, pktinfo))
		return (1);

	/*
	 * Finally, accept anything else if we're in promiscuous mode
	 */
	if (gld->gld_flags & GLD_PROM_PHYS)
		return (1);

	return (0);
}

/*
 * Return TRUE if the given multicast address is one
 * of those that this particular Stream is interested in.
 */
static int
gld_mcmatch(gld_t *gld, pktinfo_t *pktinfo)
{
	/*
	 * Return FALSE if not a multicast address.
	 */
	if (!pktinfo->isMulticast)
		return (0);

	/*
	 * Check if all multicasts have been enabled for this Stream
	 */
	if (gld->gld_flags & GLD_PROM_MULT)
		return (1);

	/*
	 * Return FALSE if no multicast addresses enabled for this Stream.
	 */
	if (!gld->gld_mcast)
		return (0);

	/*
	 * Otherwise, look for it in the table.
	 */
	return (gld_multicast(pktinfo->dhost, gld));
}

/*
 * gld_multicast determines if the address is a multicast address for
 * this stream.
 */
static int
gld_multicast(unsigned char *macaddr, gld_t *gld)
{
	int i;

	ASSERT(GLDM_LOCK_HELD(gld->gld_mac_info));

	if (!gld->gld_mcast)
		return (0);

	for (i = 0; i < gld->gld_multicnt; i++) {
		if (gld->gld_mcast[i]) {
			ASSERT(gld->gld_mcast[i]->gldm_refcnt);
			if (mac_eq(gld->gld_mcast[i]->gldm_addr, macaddr,
			    gld->gld_mac_info->gldm_addrlen))
				return (1);
		}
	}

	return (0);
}

/*
 * accept function for looped back packets
 */
static int
gld_paccept(gld_t *gld, pktinfo_t *pktinfo)
{
	/*
	 * Note that it is okay to examine gld_vlan because macinfo->gldm_lock
	 * is held.
	 *
	 * If a stream is a ETHERTYPE_VLAN listener, it must
	 * accept all tagged packets as those packets have SAP value
	 * ETHERTYPE_VLAN.
	 */
	return (gld->gld_flags & GLD_PROM_PHYS &&
	    (MATCH(gld, pktinfo) || gld->gld_flags & GLD_PROM_SAP ||
	    (GLD_IS_PHYS(gld) && gld->gld_sap == ETHERTYPE_VLAN &&
	    pktinfo->isTagged)));

}

static void
gld_passon(gld_t *gld, mblk_t *mp, pktinfo_t *pktinfo,
	void (*send)(queue_t *qp, mblk_t *mp))
{
	boolean_t is_phys = GLD_IS_PHYS(gld);
	int skiplen;
	boolean_t addtag = B_FALSE;
	uint32_t vtag = 0;

#ifdef GLD_DEBUG
	if (gld_debug & GLDTRACE)
		cmn_err(CE_NOTE, "gld_passon(%p, %p, %p)", (void *)gld,
		    (void *)mp, (void *)pktinfo);

	if ((gld_debug & GLDRECV) && (!(gld_debug & GLDNOBR) ||
	    (!pktinfo->isBroadcast && !pktinfo->isMulticast)))
		cmn_err(CE_NOTE, "gld_passon: q: %p mblk: %p minor: %d sap: %x",
		    (void *)gld->gld_qptr->q_next, (void *)mp, gld->gld_minor,
		    gld->gld_sap);
#endif
	/*
	 * Figure out how much of the packet header to throw away.
	 *
	 * Normal DLPI (non RAW/FAST) streams also want the
	 * DL_UNITDATA_IND M_PROTO message block prepended to the M_DATA.
	 */
	if (gld->gld_flags & GLD_RAW) {
		/*
		 * The packet will be tagged in the following cases:
		 *   - if priority is not 0
		 *   - a tagged packet sent on a physical link
		 */
		if ((pktinfo->isTagged && is_phys) || (pktinfo->user_pri != 0))
			addtag = B_TRUE;
		skiplen = 0;
	} else {
		/*
		 * The packet will be tagged if it meets all below conditions:
		 *   -  this is a physical stream
		 *   -  this packet is tagged packet
		 *   -  the stream is either a DL_PROMISC_SAP listener or a
		 *	ETHERTYPE_VLAN listener
		 */
		if (is_phys && pktinfo->isTagged &&
		    ((gld->gld_sap == ETHERTYPE_VLAN) ||
		    (gld->gld_flags & GLD_PROM_SAP))) {
			addtag = B_TRUE;
		}

		skiplen = pktinfo->macLen;		/* skip mac header */
		if (gld->gld_ethertype)
			skiplen += pktinfo->hdrLen;	/* skip any extra */
	}
	if (skiplen >= pktinfo->pktLen) {
		/*
		 * If the interpreter did its job right, then it cannot be
		 * asking us to skip more bytes than are in the packet!
		 * However, there could be zero data bytes left after the
		 * amount to skip.  DLPI specifies that passed M_DATA blocks
		 * should contain at least one byte of data, so if we have
		 * none we just drop it.
		 */
		ASSERT(!(skiplen > pktinfo->pktLen));
		freemsg(mp);
		return;
	}

	if (addtag) {
		mblk_t *savemp = mp;

		vtag = GLD_MAKE_VTAG(pktinfo->user_pri, pktinfo->cfi,
		    is_phys ? pktinfo->vid : VLAN_VID_NONE);
		if ((mp = gld_insert_vtag_ether(mp, vtag)) == NULL) {
			freemsg(savemp);
			return;
		}
	}

	/*
	 * Skip over the header(s), taking care to possibly handle message
	 * fragments shorter than the amount we need to skip.  Hopefully
	 * the driver will put the entire packet, or at least the entire
	 * header, into a single message block.  But we handle it if not.
	 */
	while (skiplen >= MBLKL(mp)) {
		mblk_t *savemp = mp;
		skiplen -= MBLKL(mp);
		mp = mp->b_cont;
		ASSERT(mp != NULL);	/* because skiplen < pktinfo->pktLen */
		freeb(savemp);
	}
	mp->b_rptr += skiplen;

	/* Add M_PROTO if necessary, and pass upstream */
	if (((gld->gld_flags & GLD_FAST) && !pktinfo->isMulticast &&
	    !pktinfo->isBroadcast) || (gld->gld_flags & GLD_RAW)) {
		/* RAW/FAST: just send up the M_DATA */
		(*send)(gld->gld_qptr, mp);
	} else {
		/* everybody else wants to see a unitdata_ind structure */
		mp = gld_addudind(gld, mp, pktinfo, addtag);
		if (mp)
			(*send)(gld->gld_qptr, mp);
		/* if it failed, gld_addudind already bumped statistic */
	}
}

/*
 * gld_addudind(gld, mp, pktinfo)
 * format a DL_UNITDATA_IND message to be sent upstream to the user
 */
static mblk_t *
gld_addudind(gld_t *gld, mblk_t *mp, pktinfo_t *pktinfo, boolean_t tagged)
{
	gld_mac_info_t		*macinfo = gld->gld_mac_info;
	gld_vlan_t		*vlan = (gld_vlan_t *)gld->gld_vlan;
	dl_unitdata_ind_t	*dludindp;
	mblk_t			*nmp;
	int			size;
	int			type;

#ifdef GLD_DEBUG
	if (gld_debug & GLDTRACE)
		cmn_err(CE_NOTE, "gld_addudind(%p, %p, %p)", (void *)gld,
		    (void *)mp, (void *)pktinfo);
#endif
	ASSERT(macinfo != NULL);

	/*
	 * Allocate the DL_UNITDATA_IND M_PROTO header, if allocation fails
	 * might as well discard since we can't go further
	 */
	size = sizeof (dl_unitdata_ind_t) +
	    2 * (macinfo->gldm_addrlen + abs(macinfo->gldm_saplen));
	if ((nmp = allocb(size, BPRI_MED)) == NULL) {
		freemsg(mp);
		BUMP(vlan->gldv_stats, NULL, glds_gldnorcvbuf, 1);
#ifdef GLD_DEBUG
		if (gld_debug & GLDERRS)
			cmn_err(CE_WARN,
			    "gld_addudind: allocb failed");
#endif
		return ((mblk_t *)NULL);
	}
	DB_TYPE(nmp) = M_PROTO;
	nmp->b_rptr = nmp->b_datap->db_lim - size;

	if (tagged)
		type = ETHERTYPE_VLAN;
	else
		type = (gld->gld_ethertype) ? pktinfo->ethertype : 0;


	/*
	 * now setup the DL_UNITDATA_IND header
	 *
	 * XXX This looks broken if the saps aren't two bytes.
	 */
	dludindp = (dl_unitdata_ind_t *)nmp->b_rptr;
	dludindp->dl_primitive = DL_UNITDATA_IND;
	dludindp->dl_src_addr_length =
	    dludindp->dl_dest_addr_length = macinfo->gldm_addrlen +
	    abs(macinfo->gldm_saplen);
	dludindp->dl_dest_addr_offset = sizeof (dl_unitdata_ind_t);
	dludindp->dl_src_addr_offset = dludindp->dl_dest_addr_offset +
	    dludindp->dl_dest_addr_length;

	dludindp->dl_group_address = (pktinfo->isMulticast ||
	    pktinfo->isBroadcast);

	nmp->b_wptr = nmp->b_rptr + dludindp->dl_dest_addr_offset;

	mac_copy(pktinfo->dhost, nmp->b_wptr, macinfo->gldm_addrlen);
	nmp->b_wptr += macinfo->gldm_addrlen;

	ASSERT(macinfo->gldm_saplen == -2);	/* XXX following code assumes */
	*(ushort_t *)(nmp->b_wptr) = type;
	nmp->b_wptr += abs(macinfo->gldm_saplen);

	ASSERT(nmp->b_wptr == nmp->b_rptr + dludindp->dl_src_addr_offset);

	mac_copy(pktinfo->shost, nmp->b_wptr, macinfo->gldm_addrlen);
	nmp->b_wptr += macinfo->gldm_addrlen;

	*(ushort_t *)(nmp->b_wptr) = type;
	nmp->b_wptr += abs(macinfo->gldm_saplen);

	if (pktinfo->nosource)
		dludindp->dl_src_addr_offset = dludindp->dl_src_addr_length = 0;
	linkb(nmp, mp);
	return (nmp);
}

/* ======================================================= */
/* wsrv group: called from wsrv, single threaded per queue */
/* ======================================================= */

/*
 * We go to some trouble to avoid taking the same lock during normal
 * transmit processing as we do during normal receive processing.
 *
 * Elements of the per-instance macinfo and per-stream gld_t structures
 * are for the most part protected by the GLDM_LOCK rwlock/mutex.
 * (Elements of the gld_mac_pvt_t structure are considered part of the
 * macinfo structure for purposes of this discussion).
 *
 * However, it is more complicated than that:
 *
 *	Elements of the macinfo structure that are set before the macinfo
 *	structure is added to its device list by gld_register(), and never
 *	thereafter modified, are accessed without requiring taking the lock.
 *	A similar rule applies to those elements of the gld_t structure that
 *	are written by gld_open() before the stream is added to any list.
 *
 *	Most other elements of the macinfo structure may only be read or
 *	written while holding the maclock.
 *
 *	Most writable elements of the gld_t structure are written only
 *	within the single-threaded domain of wsrv() and subsidiaries.
 *	(This domain includes open/close while qprocs are not on.)
 *	The maclock need not be taken while within that domain
 *	simply to read those elements.  Writing to them, even within
 *	that domain, or reading from it outside that domain, requires
 *	holding the maclock.  Exception:  if the stream is not
 *	presently attached to a PPA, there is no associated macinfo,
 *	and no maclock need be taken.
 *
 *	The curr_macaddr element of the mac private structure is also
 *      protected by the GLDM_LOCK rwlock/mutex, like most other members
 *      of that structure. However, there are a few instances in the
 *      transmit path where we choose to forgo lock protection when
 *      reading this variable. This is to avoid lock contention between
 *      threads executing the DL_UNITDATA_REQ case and receive threads.
 *      In doing so we will take a small risk or a few corrupted packets
 *      during the short an rare times when someone is changing the interface's
 *      physical address. We consider the small cost in this rare case to be
 *      worth the benefit of reduced lock contention under normal operating
 *      conditions. The risk/cost is small because:
 *          1. there is no guarantee at this layer of uncorrupted delivery.
 *          2. the physaddr doesn't change very often - no performance hit.
 *          3. if the physaddr changes, other stuff is going to be screwed
 *             up for a while anyway, while other sites refigure ARP, etc.,
 *             so losing a couple of packets is the least of our worries.
 *
 *	The list of streams associated with a macinfo is protected by
 *	two locks:  the per-macinfo maclock, and the per-major-device
 *	gld_devlock.  Both must be held to modify the list, but either
 *	may be held to protect the list during reading/traversing.  This
 *	allows independent locking for multiple instances in the receive
 *	path (using macinfo), while facilitating routines that must search
 *	the entire set of streams associated with a major device, such as
 *	gld_findminor(), gld_finddevinfo(), close().  The "nstreams"
 *	macinfo	element, and the gld_mac_info gld_t element, are similarly
 *	protected, since they change at exactly the same time macinfo
 *	streams list does.
 *
 *	The list of macinfo structures associated with a major device
 *	structure is protected by the gld_devlock, as is the per-major
 *	list of Style 2 streams in the DL_UNATTACHED state.
 *
 *	The list of major devices is kept on a module-global list
 *	gld_device_list, which has its own lock to protect the list.
 *
 *	When it is necessary to hold more than one lock at a time, they
 *	are acquired in this "outside in" order:
 *		gld_device_list.gld_devlock
 *		glddev->gld_devlock
 *		GLDM_LOCK(macinfo)
 *
 *	Finally, there are some "volatile" elements of the gld_t structure
 *	used for synchronization between various routines that don't share
 *	the same mutexes.  See the routines for details.  These are:
 *		gld_xwait	between gld_wsrv() and gld_sched()
 *		gld_sched_ran	between gld_wsrv() and gld_sched()
 *		gld_in_unbind	between gld_wput() and wsrv's gld_unbind()
 *		gld_wput_count	between gld_wput() and wsrv's gld_unbind()
 *		gld_in_wsrv	between gld_wput() and gld_wsrv()
 *				(used in conjunction with q->q_first)
 */

/*
 * gld_ioctl (q, mp)
 * handles all ioctl requests passed downstream. This routine is
 * passed a pointer to the message block with the ioctl request in it, and a
 * pointer to the queue so it can respond to the ioctl request with an ack.
 */
int
gld_ioctl(queue_t *q, mblk_t *mp)
{
	struct iocblk *iocp;
	gld_t *gld;
	gld_mac_info_t *macinfo;

#ifdef GLD_DEBUG
	if (gld_debug & GLDTRACE)
		cmn_err(CE_NOTE, "gld_ioctl(%p %p)", (void *)q, (void *)mp);
#endif
	gld = (gld_t *)q->q_ptr;
	iocp = (struct iocblk *)mp->b_rptr;
	switch (iocp->ioc_cmd) {
	case DLIOCRAW:		/* raw M_DATA mode */
		gld->gld_flags |= GLD_RAW;
		DB_TYPE(mp) = M_IOCACK;
		qreply(q, mp);
		break;

	case DL_IOC_HDR_INFO:	/* fastpath */
		/*
		 * DL_IOC_HDR_INFO should only come from IP. The one
		 * initiated from user-land should not be allowed.
		 */
		if ((gld_global_options & GLD_OPT_NO_FASTPATH) ||
		    (iocp->ioc_cr != kcred)) {
			miocnak(q, mp, 0, EINVAL);
			break;
		}
		gld_fastpath(gld, q, mp);
		break;

	case DLIOCMARGININFO: {	/* margin size */
		int err;

		if ((macinfo = gld->gld_mac_info) == NULL) {
			miocnak(q, mp, 0, EINVAL);
			break;
		}

		if ((err = miocpullup(mp, sizeof (uint32_t))) != 0) {
			miocnak(q, mp, 0, err);
			break;
		}

		*((uint32_t *)mp->b_cont->b_rptr) = macinfo->gldm_margin;
		miocack(q, mp, sizeof (uint32_t), 0);
		break;
	}
	default:
		macinfo	 = gld->gld_mac_info;
		if (macinfo == NULL || macinfo->gldm_ioctl == NULL) {
			miocnak(q, mp, 0, EINVAL);
			break;
		}

		GLDM_LOCK(macinfo, RW_WRITER);
		(void) (*macinfo->gldm_ioctl) (macinfo, q, mp);
		GLDM_UNLOCK(macinfo);
		break;
	}
	return (0);
}

/*
 * Since the rules for "fastpath" mode don't seem to be documented
 * anywhere, I will describe GLD's rules for fastpath users here:
 *
 * Once in this mode you remain there until close.
 * If you unbind/rebind you should get a new header using DL_IOC_HDR_INFO.
 * You must be bound (DL_IDLE) to transmit.
 * There are other rules not listed above.
 */
static void
gld_fastpath(gld_t *gld, queue_t *q, mblk_t *mp)
{
	gld_interface_t *ifp;
	gld_mac_info_t *macinfo;
	dl_unitdata_req_t *dludp;
	mblk_t *nmp;
	t_scalar_t off, len;
	uint_t maclen;
	int error;

	if (gld->gld_state != DL_IDLE) {
		miocnak(q, mp, 0, EINVAL);
		return;
	}

	macinfo = gld->gld_mac_info;
	ASSERT(macinfo != NULL);
	maclen = macinfo->gldm_addrlen + abs(macinfo->gldm_saplen);

	error = miocpullup(mp, sizeof (dl_unitdata_req_t) + maclen);
	if (error != 0) {
		miocnak(q, mp, 0, error);
		return;
	}

	dludp = (dl_unitdata_req_t *)mp->b_cont->b_rptr;
	off = dludp->dl_dest_addr_offset;
	len = dludp->dl_dest_addr_length;
	if (dludp->dl_primitive != DL_UNITDATA_REQ ||
	    !MBLKIN(mp->b_cont, off, len) || len != maclen) {
		miocnak(q, mp, 0, EINVAL);
		return;
	}

	/*
	 * We take the fastpath request as a declaration that they will accept
	 * M_DATA messages from us, whether or not we are willing to accept
	 * M_DATA from them.  This allows us to have fastpath in one direction
	 * (flow upstream) even on media with Source Routing, where we are
	 * unable to provide a fixed MAC header to be prepended to downstream
	 * flowing packets.  So we set GLD_FAST whether or not we decide to
	 * allow them to send M_DATA down to us.
	 */
	GLDM_LOCK(macinfo, RW_WRITER);
	gld->gld_flags |= GLD_FAST;
	GLDM_UNLOCK(macinfo);

	ifp = ((gld_mac_pvt_t *)macinfo->gldm_mac_pvt)->interfacep;

	/* This will fail for Source Routing media */
	/* Also on Ethernet on 802.2 SAPs */
	if ((nmp = (*ifp->mkfastpath)(gld, mp)) == NULL) {
		miocnak(q, mp, 0, ENOMEM);
		return;
	}

	/*
	 * Link new mblk in after the "request" mblks.
	 */
	linkb(mp, nmp);
	miocack(q, mp, msgdsize(mp->b_cont), 0);
}

/*
 * gld_cmds (q, mp)
 *	process the DL commands as defined in dlpi.h
 *	note that the primitives return status which is passed back
 *	to the service procedure.  If the value is GLDE_RETRY, then
 *	it is assumed that processing must stop and the primitive has
 *	been put back onto the queue.  If the value is any other error,
 *	then an error ack is generated by the service procedure.
 */
static int
gld_cmds(queue_t *q, mblk_t *mp)
{
	union DL_primitives *dlp = (union DL_primitives *)mp->b_rptr;
	gld_t *gld = (gld_t *)(q->q_ptr);
	int result = DL_BADPRIM;
	int mblkl = MBLKL(mp);
	t_uscalar_t dlreq;

	/* Make sure we have at least dlp->dl_primitive */
	if (mblkl < sizeof (dlp->dl_primitive))
		return (DL_BADPRIM);

	dlreq = dlp->dl_primitive;
#ifdef	GLD_DEBUG
	if (gld_debug & GLDTRACE)
		cmn_err(CE_NOTE,
		    "gld_cmds(%p, %p):dlp=%p, dlp->dl_primitive=%d",
		    (void *)q, (void *)mp, (void *)dlp, dlreq);
#endif

	switch (dlreq) {
	case DL_UDQOS_REQ:
		if (mblkl < DL_UDQOS_REQ_SIZE)
			break;
		result = gld_udqos(q, mp);
		break;

	case DL_BIND_REQ:
		if (mblkl < DL_BIND_REQ_SIZE)
			break;
		result = gld_bind(q, mp);
		break;

	case DL_UNBIND_REQ:
		if (mblkl < DL_UNBIND_REQ_SIZE)
			break;
		result = gld_unbind(q, mp);
		break;

	case DL_UNITDATA_REQ:
		if (mblkl < DL_UNITDATA_REQ_SIZE)
			break;
		result = gld_unitdata(q, mp);
		break;

	case DL_INFO_REQ:
		if (mblkl < DL_INFO_REQ_SIZE)
			break;
		result = gld_inforeq(q, mp);
		break;

	case DL_ATTACH_REQ:
		if (mblkl < DL_ATTACH_REQ_SIZE)
			break;
		if (gld->gld_style == DL_STYLE2)
			result = gldattach(q, mp);
		else
			result = DL_NOTSUPPORTED;
		break;

	case DL_DETACH_REQ:
		if (mblkl < DL_DETACH_REQ_SIZE)
			break;
		if (gld->gld_style == DL_STYLE2)
			result = gldunattach(q, mp);
		else
			result = DL_NOTSUPPORTED;
		break;

	case DL_ENABMULTI_REQ:
		if (mblkl < DL_ENABMULTI_REQ_SIZE)
			break;
		result = gld_enable_multi(q, mp);
		break;

	case DL_DISABMULTI_REQ:
		if (mblkl < DL_DISABMULTI_REQ_SIZE)
			break;
		result = gld_disable_multi(q, mp);
		break;

	case DL_PHYS_ADDR_REQ:
		if (mblkl < DL_PHYS_ADDR_REQ_SIZE)
			break;
		result = gld_physaddr(q, mp);
		break;

	case DL_SET_PHYS_ADDR_REQ:
		if (mblkl < DL_SET_PHYS_ADDR_REQ_SIZE)
			break;
		result = gld_setaddr(q, mp);
		break;

	case DL_PROMISCON_REQ:
		if (mblkl < DL_PROMISCON_REQ_SIZE)
			break;
		result = gld_promisc(q, mp, dlreq, B_TRUE);
		break;

	case DL_PROMISCOFF_REQ:
		if (mblkl < DL_PROMISCOFF_REQ_SIZE)
			break;
		result = gld_promisc(q, mp, dlreq, B_FALSE);
		break;

	case DL_GET_STATISTICS_REQ:
		if (mblkl < DL_GET_STATISTICS_REQ_SIZE)
			break;
		result = gld_get_statistics(q, mp);
		break;

	case DL_CAPABILITY_REQ:
		if (mblkl < DL_CAPABILITY_REQ_SIZE)
			break;
		result = gld_cap(q, mp);
		break;

	case DL_NOTIFY_REQ:
		if (mblkl < DL_NOTIFY_REQ_SIZE)
			break;
		result = gld_notify_req(q, mp);
		break;

	case DL_XID_REQ:
	case DL_XID_RES:
	case DL_TEST_REQ:
	case DL_TEST_RES:
	case DL_CONTROL_REQ:
	case DL_PASSIVE_REQ:
		result = DL_NOTSUPPORTED;
		break;

	default:
#ifdef	GLD_DEBUG
		if (gld_debug & GLDERRS)
			cmn_err(CE_WARN,
			    "gld_cmds: unknown M_PROTO message: %d",
			    dlreq);
#endif
		result = DL_BADPRIM;
	}

	return (result);
}

static int
gld_cap(queue_t *q, mblk_t *mp)
{
	gld_t *gld = (gld_t *)q->q_ptr;
	dl_capability_req_t *dlp = (dl_capability_req_t *)mp->b_rptr;

	if (gld->gld_state == DL_UNATTACHED)
		return (DL_OUTSTATE);

	if (dlp->dl_sub_length == 0)
		return (gld_cap_ack(q, mp));

	return (gld_cap_enable(q, mp));
}

static int
gld_cap_ack(queue_t *q, mblk_t *mp)
{
	gld_t *gld = (gld_t *)q->q_ptr;
	gld_mac_info_t *macinfo = gld->gld_mac_info;
	gld_interface_t *ifp;
	dl_capability_ack_t *dlap;
	dl_capability_sub_t *dlsp;
	size_t size = sizeof (dl_capability_ack_t);
	size_t subsize = 0;

	ifp = ((gld_mac_pvt_t *)macinfo->gldm_mac_pvt)->interfacep;

	if (macinfo->gldm_capabilities & GLD_CAP_CKSUM_ANY)
		subsize += sizeof (dl_capability_sub_t) +
		    sizeof (dl_capab_hcksum_t);
	if (macinfo->gldm_capabilities & GLD_CAP_ZEROCOPY)
		subsize += sizeof (dl_capability_sub_t) +
		    sizeof (dl_capab_zerocopy_t);
	if (macinfo->gldm_options & GLDOPT_MDT)
		subsize += (sizeof (dl_capability_sub_t) +
		    sizeof (dl_capab_mdt_t));

	if ((mp = mexchange(q, mp, size + subsize, M_PROTO,
	    DL_CAPABILITY_ACK)) == NULL)
		return (GLDE_OK);

	dlap = (dl_capability_ack_t *)mp->b_rptr;
	dlap->dl_sub_offset = 0;
	if ((dlap->dl_sub_length = subsize) != 0)
		dlap->dl_sub_offset = sizeof (dl_capability_ack_t);
	dlsp = (dl_capability_sub_t *)&dlap[1];

	if (macinfo->gldm_capabilities & GLD_CAP_CKSUM_ANY) {
		dl_capab_hcksum_t *dlhp = (dl_capab_hcksum_t *)&dlsp[1];

		dlsp->dl_cap = DL_CAPAB_HCKSUM;
		dlsp->dl_length = sizeof (dl_capab_hcksum_t);

		dlhp->hcksum_version = HCKSUM_VERSION_1;

		dlhp->hcksum_txflags = 0;
		if (macinfo->gldm_capabilities & GLD_CAP_CKSUM_PARTIAL)
			dlhp->hcksum_txflags |= HCKSUM_INET_PARTIAL;
		if (macinfo->gldm_capabilities & GLD_CAP_CKSUM_FULL_V4)
			dlhp->hcksum_txflags |= HCKSUM_INET_FULL_V4;
		if (macinfo->gldm_capabilities & GLD_CAP_CKSUM_FULL_V6)
			dlhp->hcksum_txflags |= HCKSUM_INET_FULL_V6;
		if (macinfo->gldm_capabilities & GLD_CAP_CKSUM_IPHDR)
			dlhp->hcksum_txflags |= HCKSUM_IPHDRCKSUM;

		dlcapabsetqid(&(dlhp->hcksum_mid), RD(q));
		dlsp = (dl_capability_sub_t *)&dlhp[1];
	}

	if (macinfo->gldm_capabilities & GLD_CAP_ZEROCOPY) {
		dl_capab_zerocopy_t *dlzp = (dl_capab_zerocopy_t *)&dlsp[1];

		dlsp->dl_cap = DL_CAPAB_ZEROCOPY;
		dlsp->dl_length = sizeof (dl_capab_zerocopy_t);
		dlzp->zerocopy_version = ZEROCOPY_VERSION_1;
		dlzp->zerocopy_flags = DL_CAPAB_VMSAFE_MEM;

		dlcapabsetqid(&(dlzp->zerocopy_mid), RD(q));
		dlsp = (dl_capability_sub_t *)&dlzp[1];
	}

	if (macinfo->gldm_options & GLDOPT_MDT) {
		dl_capab_mdt_t *dlmp = (dl_capab_mdt_t *)&dlsp[1];

		dlsp->dl_cap = DL_CAPAB_MDT;
		dlsp->dl_length = sizeof (dl_capab_mdt_t);

		dlmp->mdt_version = MDT_VERSION_2;
		dlmp->mdt_max_pld = macinfo->gldm_mdt_segs;
		dlmp->mdt_span_limit = macinfo->gldm_mdt_sgl;
		dlcapabsetqid(&dlmp->mdt_mid, OTHERQ(q));
		dlmp->mdt_flags = DL_CAPAB_MDT_ENABLE;
		dlmp->mdt_hdr_head = ifp->hdr_size;
		dlmp->mdt_hdr_tail = 0;
	}

	qreply(q, mp);
	return (GLDE_OK);
}

static int
gld_cap_enable(queue_t *q, mblk_t *mp)
{
	dl_capability_req_t *dlp;
	dl_capability_sub_t *dlsp;
	dl_capab_hcksum_t *dlhp;
	offset_t off;
	size_t len;
	size_t size;
	offset_t end;

	dlp = (dl_capability_req_t *)mp->b_rptr;
	dlp->dl_primitive = DL_CAPABILITY_ACK;

	off = dlp->dl_sub_offset;
	len = dlp->dl_sub_length;

	if (!MBLKIN(mp, off, len))
		return (DL_BADPRIM);

	end = off + len;
	while (off < end) {
		dlsp = (dl_capability_sub_t *)(mp->b_rptr + off);
		size = sizeof (dl_capability_sub_t) + dlsp->dl_length;
		if (off + size > end)
			return (DL_BADPRIM);

		switch (dlsp->dl_cap) {
		case DL_CAPAB_HCKSUM:
			dlhp = (dl_capab_hcksum_t *)&dlsp[1];
			/* nothing useful we can do with the contents */
			dlcapabsetqid(&(dlhp->hcksum_mid), RD(q));
			break;
		default:
			break;
		}

		off += size;
	}

	qreply(q, mp);
	return (GLDE_OK);
}

/*
 * Send a copy of the DL_NOTIFY_IND message <mp> to each stream that has
 * requested the specific <notification> that the message carries AND is
 * eligible and ready to receive the notification immediately.
 *
 * This routine ignores flow control. Notifications will be sent regardless.
 *
 * In all cases, the original message passed in is freed at the end of
 * the routine.
 */
static void
gld_notify_qs(gld_mac_info_t *macinfo, mblk_t *mp, uint32_t notification)
{
	gld_mac_pvt_t *mac_pvt;
	gld_vlan_t *vlan;
	gld_t *gld;
	mblk_t *nmp;
	int i;

	ASSERT(GLDM_LOCK_HELD_WRITE(macinfo));

	mac_pvt = (gld_mac_pvt_t *)macinfo->gldm_mac_pvt;

	/*
	 * Search all the streams attached to this macinfo looking
	 * for those eligible to receive the present notification.
	 */
	for (i = 0; i < VLAN_HASHSZ; i++) {
		for (vlan = mac_pvt->vlan_hash[i];
		    vlan != NULL; vlan = vlan->gldv_next) {
			for (gld = vlan->gldv_str_next;
			    gld != (gld_t *)&vlan->gldv_str_next;
			    gld = gld->gld_next) {
				ASSERT(gld->gld_qptr != NULL);
				ASSERT(gld->gld_state == DL_IDLE ||
				    gld->gld_state == DL_UNBOUND);
				ASSERT(gld->gld_mac_info == macinfo);

				if (gld->gld_flags & GLD_STR_CLOSING)
					continue; /* not eligible - skip */
				if (!(notification & gld->gld_notifications))
					continue; /* not wanted - skip */
				if ((nmp = dupmsg(mp)) == NULL)
					continue; /* can't copy - skip */

				/*
				 * All OK; send dup'd notification up this
				 * stream
				 */
				qreply(WR(gld->gld_qptr), nmp);
			}
		}
	}

	/*
	 * Drop the original message block now
	 */
	freemsg(mp);
}

/*
 * For each (understood) bit in the <notifications> argument, contruct
 * a DL_NOTIFY_IND message and send it to the specified <q>, or to all
 * eligible queues if <q> is NULL.
 */
static void
gld_notify_ind(gld_mac_info_t *macinfo, uint32_t notifications, queue_t *q)
{
	gld_mac_pvt_t *mac_pvt;
	dl_notify_ind_t *dlnip;
	struct gld_stats *stats;
	mblk_t *mp;
	size_t size;
	uint32_t bit;

	GLDM_LOCK(macinfo, RW_WRITER);

	/*
	 * The following cases shouldn't happen, but just in case the
	 * MAC driver calls gld_linkstate() at an inappropriate time, we
	 * check anyway ...
	 */
	if (!(macinfo->gldm_GLD_flags & GLD_MAC_READY)) {
		GLDM_UNLOCK(macinfo);
		return;				/* not ready yet	*/
	}

	if (macinfo->gldm_GLD_flags & GLD_UNREGISTERED) {
		GLDM_UNLOCK(macinfo);
		return;				/* not ready anymore	*/
	}

	/*
	 * Make sure the kstats are up to date, 'cos we use some of
	 * the kstat values below, specifically the link speed ...
	 */
	mac_pvt = (gld_mac_pvt_t *)macinfo->gldm_mac_pvt;
	stats = mac_pvt->statistics;
	if (macinfo->gldm_get_stats)
		(void) (*macinfo->gldm_get_stats)(macinfo, stats);

	for (bit = 1; notifications != 0; bit <<= 1) {
		if ((notifications & bit) == 0)
			continue;
		notifications &= ~bit;

		size = DL_NOTIFY_IND_SIZE;
		if (bit == DL_NOTE_PHYS_ADDR)
			size += macinfo->gldm_addrlen;
		if ((mp = allocb(size, BPRI_MED)) == NULL)
			continue;

		mp->b_datap->db_type = M_PROTO;
		mp->b_wptr = mp->b_rptr + size;
		dlnip = (dl_notify_ind_t *)mp->b_rptr;
		dlnip->dl_primitive = DL_NOTIFY_IND;
		dlnip->dl_notification = 0;
		dlnip->dl_data = 0;
		dlnip->dl_addr_length = 0;
		dlnip->dl_addr_offset = 0;

		switch (bit) {
		case DL_NOTE_PROMISC_ON_PHYS:
		case DL_NOTE_PROMISC_OFF_PHYS:
			if (mac_pvt->nprom != 0)
				dlnip->dl_notification = bit;
			break;

		case DL_NOTE_LINK_DOWN:
			if (macinfo->gldm_linkstate == GLD_LINKSTATE_DOWN)
				dlnip->dl_notification = bit;
			break;

		case DL_NOTE_LINK_UP:
			if (macinfo->gldm_linkstate == GLD_LINKSTATE_UP)
				dlnip->dl_notification = bit;
			break;

		case DL_NOTE_SPEED:
			/*
			 * Conversion required here:
			 *	GLD keeps the speed in bit/s in a uint64
			 *	DLPI wants it in kb/s in a uint32
			 * Fortunately this is still big enough for 10Gb/s!
			 */
			dlnip->dl_notification = bit;
			dlnip->dl_data = stats->glds_speed/1000ULL;
			break;

		case DL_NOTE_PHYS_ADDR:
			dlnip->dl_notification = bit;
			dlnip->dl_data = DL_CURR_PHYS_ADDR;
			dlnip->dl_addr_offset = sizeof (dl_notify_ind_t);
			dlnip->dl_addr_length = macinfo->gldm_addrlen +
			    abs(macinfo->gldm_saplen);
			mac_pvt = (gld_mac_pvt_t *)macinfo->gldm_mac_pvt;
			mac_copy(mac_pvt->curr_macaddr,
			    mp->b_rptr + sizeof (dl_notify_ind_t),
			    macinfo->gldm_addrlen);
			break;

		default:
			break;
		}

		if (dlnip->dl_notification == 0)
			freemsg(mp);
		else if (q != NULL)
			qreply(q, mp);
		else
			gld_notify_qs(macinfo, mp, bit);
	}

	GLDM_UNLOCK(macinfo);
}

/*
 * gld_notify_req - handle a DL_NOTIFY_REQ message
 */
static int
gld_notify_req(queue_t *q, mblk_t *mp)
{
	gld_t *gld = (gld_t *)q->q_ptr;
	gld_mac_info_t *macinfo;
	gld_mac_pvt_t *pvt;
	dl_notify_req_t *dlnrp;
	dl_notify_ack_t *dlnap;

	ASSERT(gld != NULL);
	ASSERT(gld->gld_qptr == RD(q));

	dlnrp = (dl_notify_req_t *)mp->b_rptr;

#ifdef GLD_DEBUG
	if (gld_debug & GLDTRACE)
		cmn_err(CE_NOTE, "gld_notify_req(%p %p)",
		    (void *)q, (void *)mp);
#endif

	if (gld->gld_state == DL_UNATTACHED) {
#ifdef GLD_DEBUG
		if (gld_debug & GLDERRS)
			cmn_err(CE_NOTE, "gld_notify_req: wrong state (%d)",
			    gld->gld_state);
#endif
		return (DL_OUTSTATE);
	}

	/*
	 * Remember what notifications are required by this stream
	 */
	macinfo = gld->gld_mac_info;
	pvt = (gld_mac_pvt_t *)macinfo->gldm_mac_pvt;

	gld->gld_notifications = dlnrp->dl_notifications & pvt->notifications;

	/*
	 * The return DL_NOTIFY_ACK carries the bitset of notifications
	 * that this driver can provide, independently of which ones have
	 * previously been or are now being requested.
	 */
	if ((mp = mexchange(q, mp, sizeof (dl_notify_ack_t), M_PCPROTO,
	    DL_NOTIFY_ACK)) == NULL)
		return (DL_SYSERR);

	dlnap = (dl_notify_ack_t *)mp->b_rptr;
	dlnap->dl_notifications = pvt->notifications;
	qreply(q, mp);

	/*
	 * A side effect of a DL_NOTIFY_REQ is that after the DL_NOTIFY_ACK
	 * reply, the the requestor gets zero or more DL_NOTIFY_IND messages
	 * that provide the current status.
	 */
	gld_notify_ind(macinfo, gld->gld_notifications, q);

	return (GLDE_OK);
}

/*
 * gld_linkstate()
 *	Called by driver to tell GLD the state of the physical link.
 *	As a side effect, sends a DL_NOTE_LINK_UP or DL_NOTE_LINK_DOWN
 *	notification to each client that has previously requested such
 *	notifications
 */
void
gld_linkstate(gld_mac_info_t *macinfo, int32_t newstate)
{
	uint32_t notification;

	switch (newstate) {
	default:
		return;

	case GLD_LINKSTATE_DOWN:
		notification = DL_NOTE_LINK_DOWN;
		break;

	case GLD_LINKSTATE_UP:
		notification = DL_NOTE_LINK_UP | DL_NOTE_SPEED;
		break;

	case GLD_LINKSTATE_UNKNOWN:
		notification = 0;
		break;
	}

	GLDM_LOCK(macinfo, RW_WRITER);
	if (macinfo->gldm_linkstate == newstate)
		notification = 0;
	else
		macinfo->gldm_linkstate = newstate;
	GLDM_UNLOCK(macinfo);

	if (notification)
		gld_notify_ind(macinfo, notification, NULL);
}

/*
 * gld_udqos - set the current QoS parameters (priority only at the moment).
 */
static int
gld_udqos(queue_t *q, mblk_t *mp)
{
	dl_udqos_req_t *dlp;
	gld_t  *gld = (gld_t *)q->q_ptr;
	int off;
	int len;
	dl_qos_cl_sel1_t *selp;

	ASSERT(gld);
	ASSERT(gld->gld_qptr == RD(q));

#ifdef GLD_DEBUG
	if (gld_debug & GLDTRACE)
		cmn_err(CE_NOTE, "gld_udqos(%p %p)", (void *)q, (void *)mp);
#endif

	if (gld->gld_state != DL_IDLE) {
#ifdef GLD_DEBUG
		if (gld_debug & GLDERRS)
			cmn_err(CE_NOTE, "gld_udqos: wrong state (%d)",
			    gld->gld_state);
#endif
		return (DL_OUTSTATE);
	}

	dlp = (dl_udqos_req_t *)mp->b_rptr;
	off = dlp->dl_qos_offset;
	len = dlp->dl_qos_length;

	if (len != sizeof (dl_qos_cl_sel1_t) || !MBLKIN(mp, off, len))
		return (DL_BADQOSTYPE);

	selp = (dl_qos_cl_sel1_t *)(mp->b_rptr + off);
	if (selp->dl_qos_type != DL_QOS_CL_SEL1)
		return (DL_BADQOSTYPE);

	if (selp->dl_trans_delay != 0 &&
	    selp->dl_trans_delay != DL_QOS_DONT_CARE)
		return (DL_BADQOSPARAM);
	if (selp->dl_protection != 0 &&
	    selp->dl_protection != DL_QOS_DONT_CARE)
		return (DL_BADQOSPARAM);
	if (selp->dl_residual_error != 0 &&
	    selp->dl_residual_error != DL_QOS_DONT_CARE)
		return (DL_BADQOSPARAM);
	if (selp->dl_priority < 0 || selp->dl_priority > 7)
		return (DL_BADQOSPARAM);

	gld->gld_upri = selp->dl_priority;

	dlokack(q, mp, DL_UDQOS_REQ);
	return (GLDE_OK);
}

static mblk_t *
gld_bindack(queue_t *q, mblk_t *mp)
{
	gld_t *gld = (gld_t *)q->q_ptr;
	gld_mac_info_t *macinfo = gld->gld_mac_info;
	gld_mac_pvt_t *mac_pvt = (gld_mac_pvt_t *)macinfo->gldm_mac_pvt;
	dl_bind_ack_t *dlp;
	size_t size;
	t_uscalar_t addrlen;
	uchar_t *sapp;

	addrlen = macinfo->gldm_addrlen + abs(macinfo->gldm_saplen);
	size = sizeof (dl_bind_ack_t) + addrlen;
	if ((mp = mexchange(q, mp, size, M_PCPROTO, DL_BIND_ACK)) == NULL)
		return (NULL);

	dlp = (dl_bind_ack_t *)mp->b_rptr;
	dlp->dl_sap = gld->gld_sap;
	dlp->dl_addr_length = addrlen;
	dlp->dl_addr_offset = sizeof (dl_bind_ack_t);
	dlp->dl_max_conind = 0;
	dlp->dl_xidtest_flg = 0;

	mac_copy(mac_pvt->curr_macaddr, (uchar_t *)&dlp[1],
	    macinfo->gldm_addrlen);
	sapp = mp->b_rptr + dlp->dl_addr_offset + macinfo->gldm_addrlen;
	*(ushort_t *)sapp = gld->gld_sap;

	return (mp);
}

/*
 * gld_bind - determine if a SAP is already allocated and whether it is legal
 * to do the bind at this time
 */
static int
gld_bind(queue_t *q, mblk_t *mp)
{
	ulong_t	sap;
	dl_bind_req_t *dlp;
	gld_t *gld = (gld_t *)q->q_ptr;
	gld_mac_info_t *macinfo = gld->gld_mac_info;

	ASSERT(gld);
	ASSERT(gld->gld_qptr == RD(q));

#ifdef GLD_DEBUG
	if (gld_debug & GLDTRACE)
		cmn_err(CE_NOTE, "gld_bind(%p %p)", (void *)q, (void *)mp);
#endif

	dlp = (dl_bind_req_t *)mp->b_rptr;
	sap = dlp->dl_sap;

#ifdef GLD_DEBUG
	if (gld_debug & GLDPROT)
		cmn_err(CE_NOTE, "gld_bind: lsap=%lx", sap);
#endif

	if (gld->gld_state != DL_UNBOUND) {
#ifdef GLD_DEBUG
		if (gld_debug & GLDERRS)
			cmn_err(CE_NOTE, "gld_bind: bound or not attached (%d)",
			    gld->gld_state);
#endif
		return (DL_OUTSTATE);
	}
	ASSERT(macinfo);

	if (dlp->dl_service_mode != DL_CLDLS) {
		return (DL_UNSUPPORTED);
	}
	if (dlp->dl_xidtest_flg & (DL_AUTO_XID | DL_AUTO_TEST)) {
		return (DL_NOAUTO);
	}

	/*
	 * Check sap validity and decide whether this stream accepts
	 * IEEE 802.2 (LLC) packets.
	 */
	if (sap > ETHERTYPE_MAX)
		return (DL_BADSAP);

	/*
	 * Decide whether the SAP value selects EtherType encoding/decoding.
	 * For compatibility with monolithic ethernet drivers, the range of
	 * SAP values is different for DL_ETHER media.
	 */
	switch (macinfo->gldm_type) {
	case DL_ETHER:
		gld->gld_ethertype = (sap > ETHERMTU);
		break;
	default:
		gld->gld_ethertype = (sap > GLD_MAX_802_SAP);
		break;
	}

	/* if we get to here, then the SAP is legal enough */
	GLDM_LOCK(macinfo, RW_WRITER);
	gld->gld_state = DL_IDLE;	/* bound and ready */
	gld->gld_sap = sap;
	if ((macinfo->gldm_type == DL_ETHER) && (sap == ETHERTYPE_VLAN))
		((gld_vlan_t *)gld->gld_vlan)->gldv_nvlan_sap++;
	gld_set_ipq(gld);

#ifdef GLD_DEBUG
	if (gld_debug & GLDPROT)
		cmn_err(CE_NOTE, "gld_bind: ok - sap = %d", gld->gld_sap);
#endif

	/* ACK the BIND */
	mp = gld_bindack(q, mp);
	GLDM_UNLOCK(macinfo);

	if (mp != NULL) {
		qreply(q, mp);
		return (GLDE_OK);
	}

	return (DL_SYSERR);
}

/*
 * gld_unbind - perform an unbind of an LSAP or ether type on the stream.
 * The stream is still open and can be re-bound.
 */
static int
gld_unbind(queue_t *q, mblk_t *mp)
{
	gld_t *gld = (gld_t *)q->q_ptr;
	gld_mac_info_t *macinfo = gld->gld_mac_info;

	ASSERT(gld);

#ifdef GLD_DEBUG
	if (gld_debug & GLDTRACE)
		cmn_err(CE_NOTE, "gld_unbind(%p %p)", (void *)q, (void *)mp);
#endif

	if (gld->gld_state != DL_IDLE) {
#ifdef GLD_DEBUG
		if (gld_debug & GLDERRS)
			cmn_err(CE_NOTE, "gld_unbind: wrong state (%d)",
			    gld->gld_state);
#endif
		return (DL_OUTSTATE);
	}
	ASSERT(macinfo);

	/*
	 * Avoid unbinding (DL_UNBIND_REQ) while FAST/RAW is inside wput.
	 * See comments above gld_start().
	 */
	gld->gld_in_unbind = B_TRUE;	/* disallow wput=>start */
	membar_enter();
	if (gld->gld_wput_count != 0) {
		gld->gld_in_unbind = B_FALSE;
		ASSERT(mp);		/* we didn't come from close */
#ifdef GLD_DEBUG
		if (gld_debug & GLDETRACE)
			cmn_err(CE_NOTE, "gld_unbind: defer for wput");
#endif
		(void) putbq(q, mp);
		qenable(q);		/* try again soon */
		return (GLDE_RETRY);
	}

	GLDM_LOCK(macinfo, RW_WRITER);
	if ((macinfo->gldm_type == DL_ETHER) &&
	    (gld->gld_sap == ETHERTYPE_VLAN)) {
		((gld_vlan_t *)gld->gld_vlan)->gldv_nvlan_sap--;
	}
	gld->gld_state = DL_UNBOUND;
	gld->gld_sap = 0;
	gld_set_ipq(gld);
	GLDM_UNLOCK(macinfo);

	membar_exit();
	gld->gld_in_unbind = B_FALSE;

	/* mp is NULL if we came from close */
	if (mp) {
		gld_flushqueue(q);	/* flush the queues */
		dlokack(q, mp, DL_UNBIND_REQ);
	}
	return (GLDE_OK);
}

/*
 * gld_inforeq - generate the response to an info request
 */
static int
gld_inforeq(queue_t *q, mblk_t *mp)
{
	gld_t		*gld;
	dl_info_ack_t	*dlp;
	int		bufsize;
	glddev_t	*glddev;
	gld_mac_info_t	*macinfo;
	gld_mac_pvt_t	*mac_pvt;
	int		sel_offset = 0;
	int		range_offset = 0;
	int		addr_offset;
	int		addr_length;
	int		sap_length;
	int		brdcst_offset;
	int		brdcst_length;
	uchar_t		*sapp;

#ifdef GLD_DEBUG
	if (gld_debug & GLDTRACE)
		cmn_err(CE_NOTE, "gld_inforeq(%p %p)", (void *)q, (void *)mp);
#endif
	gld = (gld_t *)q->q_ptr;
	ASSERT(gld);
	glddev = gld->gld_device;
	ASSERT(glddev);

	if (gld->gld_state == DL_IDLE || gld->gld_state == DL_UNBOUND) {
		macinfo = gld->gld_mac_info;
		ASSERT(macinfo != NULL);

		mac_pvt = (gld_mac_pvt_t *)macinfo->gldm_mac_pvt;

		addr_length = macinfo->gldm_addrlen;
		sap_length = macinfo->gldm_saplen;
		brdcst_length = macinfo->gldm_addrlen;
	} else {
		addr_length = glddev->gld_addrlen;
		sap_length = glddev->gld_saplen;
		brdcst_length = glddev->gld_addrlen;
	}

	bufsize = sizeof (dl_info_ack_t);

	addr_offset = bufsize;
	bufsize += addr_length;
	bufsize += abs(sap_length);

	brdcst_offset = bufsize;
	bufsize += brdcst_length;

	if (((gld_vlan_t *)gld->gld_vlan) != NULL) {
		sel_offset = P2ROUNDUP(bufsize, sizeof (int64_t));
		bufsize = sel_offset + sizeof (dl_qos_cl_sel1_t);

		range_offset = P2ROUNDUP(bufsize, sizeof (int64_t));
		bufsize = range_offset + sizeof (dl_qos_cl_range1_t);
	}

	if ((mp = mexchange(q, mp, bufsize, M_PCPROTO, DL_INFO_ACK)) == NULL)
		return (GLDE_OK);	/* nothing more to be done */

	bzero(mp->b_rptr, bufsize);

	dlp = (dl_info_ack_t *)mp->b_rptr;
	dlp->dl_primitive = DL_INFO_ACK;
	dlp->dl_version = DL_VERSION_2;
	dlp->dl_service_mode = DL_CLDLS;
	dlp->dl_current_state = gld->gld_state;
	dlp->dl_provider_style = gld->gld_style;

	if (sel_offset != 0) {
		dl_qos_cl_sel1_t	*selp;
		dl_qos_cl_range1_t	*rangep;

		ASSERT(range_offset != 0);

		dlp->dl_qos_offset = sel_offset;
		dlp->dl_qos_length = sizeof (dl_qos_cl_sel1_t);
		dlp->dl_qos_range_offset = range_offset;
		dlp->dl_qos_range_length = sizeof (dl_qos_cl_range1_t);

		selp = (dl_qos_cl_sel1_t *)(mp->b_rptr + sel_offset);
		selp->dl_qos_type = DL_QOS_CL_SEL1;
		selp->dl_priority = gld->gld_upri;

		rangep = (dl_qos_cl_range1_t *)(mp->b_rptr + range_offset);
		rangep->dl_qos_type = DL_QOS_CL_RANGE1;
		rangep->dl_priority.dl_min = 0;
		rangep->dl_priority.dl_max = 7;
	}

	if (gld->gld_state == DL_IDLE || gld->gld_state == DL_UNBOUND) {
		dlp->dl_min_sdu = macinfo->gldm_minpkt;
		dlp->dl_max_sdu = macinfo->gldm_maxpkt;
		dlp->dl_mac_type = macinfo->gldm_type;
		dlp->dl_addr_length = addr_length + abs(sap_length);
		dlp->dl_sap_length = sap_length;

		if (gld->gld_state == DL_IDLE) {
			/*
			 * If we are bound to a non-LLC SAP on any medium
			 * other than Ethernet, then we need room for a
			 * SNAP header.  So we have to adjust the MTU size
			 * accordingly.  XXX I suppose this should be done
			 * in gldutil.c, but it seems likely that this will
			 * always be true for everything GLD supports but
			 * Ethernet.  Check this if you add another medium.
			 */
			if ((macinfo->gldm_type == DL_TPR ||
			    macinfo->gldm_type == DL_FDDI) &&
			    gld->gld_ethertype)
				dlp->dl_max_sdu -= LLC_SNAP_HDR_LEN;

			/* copy macaddr and sap */
			dlp->dl_addr_offset = addr_offset;

			mac_copy(mac_pvt->curr_macaddr, mp->b_rptr +
			    addr_offset, macinfo->gldm_addrlen);
			sapp = mp->b_rptr + addr_offset +
			    macinfo->gldm_addrlen;
			*(ushort_t *)sapp = gld->gld_sap;
		} else {
			dlp->dl_addr_offset = 0;
		}

		/* copy broadcast addr */
		dlp->dl_brdcst_addr_length = macinfo->gldm_addrlen;
		dlp->dl_brdcst_addr_offset = brdcst_offset;
		mac_copy((caddr_t)macinfo->gldm_broadcast_addr,
		    mp->b_rptr + brdcst_offset, brdcst_length);
	} else {
		/*
		 * No PPA is attached.
		 * The best we can do is use the values provided
		 * by the first mac that called gld_register.
		 */
		dlp->dl_min_sdu = glddev->gld_minsdu;
		dlp->dl_max_sdu = glddev->gld_maxsdu;
		dlp->dl_mac_type = glddev->gld_type;
		dlp->dl_addr_length = addr_length + abs(sap_length);
		dlp->dl_sap_length = sap_length;
		dlp->dl_addr_offset = 0;
		dlp->dl_brdcst_addr_offset = brdcst_offset;
		dlp->dl_brdcst_addr_length = brdcst_length;
		mac_copy((caddr_t)glddev->gld_broadcast,
		    mp->b_rptr + brdcst_offset, brdcst_length);
	}
	qreply(q, mp);
	return (GLDE_OK);
}

/*
 * gld_unitdata (q, mp)
 * send a datagram.  Destination address/lsap is in M_PROTO
 * message (first mblock), data is in remainder of message.
 *
 */
static int
gld_unitdata(queue_t *q, mblk_t *mp)
{
	gld_t *gld = (gld_t *)q->q_ptr;
	dl_unitdata_req_t *dlp = (dl_unitdata_req_t *)mp->b_rptr;
	gld_mac_info_t *macinfo = gld->gld_mac_info;
	size_t	msglen;
	mblk_t	*nmp;
	gld_interface_t *ifp;
	uint32_t start;
	uint32_t stuff;
	uint32_t end;
	uint32_t value;
	uint32_t flags;
	uint32_t upri;

#ifdef GLD_DEBUG
	if (gld_debug & GLDTRACE)
		cmn_err(CE_NOTE, "gld_unitdata(%p %p)", (void *)q, (void *)mp);
#endif

	if (gld->gld_state != DL_IDLE) {
#ifdef GLD_DEBUG
		if (gld_debug & GLDERRS)
			cmn_err(CE_NOTE, "gld_unitdata: wrong state (%d)",
			    gld->gld_state);
#endif
		dluderrorind(q, mp, mp->b_rptr + dlp->dl_dest_addr_offset,
		    dlp->dl_dest_addr_length, DL_OUTSTATE, 0);
		return (GLDE_OK);
	}
	ASSERT(macinfo != NULL);

	if (!MBLKIN(mp, dlp->dl_dest_addr_offset, dlp->dl_dest_addr_length) ||
	    dlp->dl_dest_addr_length !=
	    macinfo->gldm_addrlen + abs(macinfo->gldm_saplen)) {
		dluderrorind(q, mp, mp->b_rptr + dlp->dl_dest_addr_offset,
		    dlp->dl_dest_addr_length, DL_BADADDR, 0);
		return (GLDE_OK);
	}

	upri = dlp->dl_priority.dl_max;

	msglen = msgdsize(mp);
	if (msglen == 0 || msglen > macinfo->gldm_maxpkt) {
#ifdef GLD_DEBUG
		if (gld_debug & GLDERRS)
			cmn_err(CE_NOTE, "gld_unitdata: bad msglen (%d)",
			    (int)msglen);
#endif
		dluderrorind(q, mp, mp->b_rptr + dlp->dl_dest_addr_offset,
		    dlp->dl_dest_addr_length, DL_BADDATA, 0);
		return (GLDE_OK);
	}

	ASSERT(mp->b_cont != NULL);	/* because msgdsize(mp) is nonzero */

	ifp = ((gld_mac_pvt_t *)macinfo->gldm_mac_pvt)->interfacep;

	/* grab any checksum information that may be present */
	hcksum_retrieve(mp->b_cont, NULL, NULL, &start, &stuff, &end,
	    &value, &flags);

	/*
	 * Prepend a valid header for transmission
	 */
	if ((nmp = (*ifp->mkunitdata)(gld, mp)) == NULL) {
#ifdef GLD_DEBUG
		if (gld_debug & GLDERRS)
			cmn_err(CE_NOTE, "gld_unitdata: mkunitdata failed.");
#endif
		dluderrorind(q, mp, mp->b_rptr + dlp->dl_dest_addr_offset,
		    dlp->dl_dest_addr_length, DL_SYSERR, ENOSR);
		return (GLDE_OK);
	}

	/* apply any checksum information to the first block in the chain */
	(void) hcksum_assoc(nmp, NULL, NULL, start, stuff, end, value,
	    flags, 0);

	GLD_CLEAR_MBLK_VTAG(nmp);
	if (gld_start(q, nmp, GLD_WSRV, upri) == GLD_NORESOURCES) {
		qenable(q);
		return (GLDE_RETRY);
	}

	return (GLDE_OK);
}

/*
 * gldattach(q, mp)
 * DLPI DL_ATTACH_REQ
 * this attaches the stream to a PPA
 */
static int
gldattach(queue_t *q, mblk_t *mp)
{
	dl_attach_req_t *at;
	gld_mac_info_t *macinfo;
	gld_t  *gld = (gld_t *)q->q_ptr;
	glddev_t *glddev;
	gld_mac_pvt_t *mac_pvt;
	uint32_t ppa;
	uint32_t vid;
	gld_vlan_t *vlan;

	at = (dl_attach_req_t *)mp->b_rptr;

	if (gld->gld_state != DL_UNATTACHED)
		return (DL_OUTSTATE);

	ASSERT(!gld->gld_mac_info);

	ppa = at->dl_ppa % GLD_VLAN_SCALE;	/* 0 .. 999	*/
	vid = at->dl_ppa / GLD_VLAN_SCALE;	/* 0 .. 4094	*/
	if (vid > VLAN_VID_MAX)
		return (DL_BADPPA);

	glddev = gld->gld_device;
	mutex_enter(&glddev->gld_devlock);
	for (macinfo = glddev->gld_mac_next;
	    macinfo != (gld_mac_info_t *)&glddev->gld_mac_next;
	    macinfo = macinfo->gldm_next) {
		int inst;

		ASSERT(macinfo != NULL);
		if (macinfo->gldm_ppa != ppa)
			continue;

		if (!(macinfo->gldm_GLD_flags & GLD_MAC_READY))
			continue;	/* this one's not ready yet */

		/*
		 * VLAN sanity check
		 */
		if (vid != VLAN_VID_NONE && !VLAN_CAPABLE(macinfo)) {
			mutex_exit(&glddev->gld_devlock);
			return (DL_BADPPA);
		}

		/*
		 * We found the correct PPA, hold the instance
		 */
		inst = ddi_get_instance(macinfo->gldm_devinfo);
		if (inst == -1 || qassociate(q, inst) != 0) {
			mutex_exit(&glddev->gld_devlock);
			return (DL_BADPPA);
		}

		/* Take the stream off the per-driver-class list */
		gldremque(gld);

		/*
		 * We must hold the lock to prevent multiple calls
		 * to the reset and start routines.
		 */
		GLDM_LOCK(macinfo, RW_WRITER);

		gld->gld_mac_info = macinfo;

		if (macinfo->gldm_send_tagged != NULL)
			gld->gld_send = macinfo->gldm_send_tagged;
		else
			gld->gld_send = macinfo->gldm_send;

		if ((vlan = gld_get_vlan(macinfo, vid)) == NULL) {
			GLDM_UNLOCK(macinfo);
			gldinsque(gld, glddev->gld_str_prev);
			mutex_exit(&glddev->gld_devlock);
			(void) qassociate(q, -1);
			return (DL_BADPPA);
		}

		mac_pvt = (gld_mac_pvt_t *)macinfo->gldm_mac_pvt;
		if (!mac_pvt->started) {
			if (gld_start_mac(macinfo) != GLD_SUCCESS) {
				gld_rem_vlan(vlan);
				GLDM_UNLOCK(macinfo);
				gldinsque(gld, glddev->gld_str_prev);
				mutex_exit(&glddev->gld_devlock);
				dlerrorack(q, mp, DL_ATTACH_REQ, DL_SYSERR,
				    EIO);
				(void) qassociate(q, -1);
				return (GLDE_OK);
			}
		}

		gld->gld_vlan = vlan;
		vlan->gldv_nstreams++;
		gldinsque(gld, vlan->gldv_str_prev);
		gld->gld_state = DL_UNBOUND;
		GLDM_UNLOCK(macinfo);

#ifdef GLD_DEBUG
		if (gld_debug & GLDPROT) {
			cmn_err(CE_NOTE, "gldattach(%p, %p, PPA = %d)",
			    (void *)q, (void *)mp, macinfo->gldm_ppa);
		}
#endif
		mutex_exit(&glddev->gld_devlock);
		dlokack(q, mp, DL_ATTACH_REQ);
		return (GLDE_OK);
	}
	mutex_exit(&glddev->gld_devlock);
	return (DL_BADPPA);
}

/*
 * gldunattach(q, mp)
 * DLPI DL_DETACH_REQ
 * detaches the mac layer from the stream
 */
int
gldunattach(queue_t *q, mblk_t *mp)
{
	gld_t  *gld = (gld_t *)q->q_ptr;
	glddev_t *glddev = gld->gld_device;
	gld_mac_info_t *macinfo = gld->gld_mac_info;
	int	state = gld->gld_state;
	int	i;
	gld_mac_pvt_t *mac_pvt;
	gld_vlan_t *vlan;
	boolean_t phys_off;
	boolean_t mult_off;
	int op = GLD_MAC_PROMISC_NOOP;

	if (state != DL_UNBOUND)
		return (DL_OUTSTATE);

	ASSERT(macinfo != NULL);
	ASSERT(gld->gld_sap == 0);
	mac_pvt = (gld_mac_pvt_t *)macinfo->gldm_mac_pvt;

#ifdef GLD_DEBUG
	if (gld_debug & GLDPROT) {
		cmn_err(CE_NOTE, "gldunattach(%p, %p, PPA = %d)",
		    (void *)q, (void *)mp, macinfo->gldm_ppa);
	}
#endif

	GLDM_LOCK(macinfo, RW_WRITER);

	if (gld->gld_mcast) {
		for (i = 0; i < gld->gld_multicnt; i++) {
			gld_mcast_t *mcast;

			if ((mcast = gld->gld_mcast[i]) != NULL) {
				ASSERT(mcast->gldm_refcnt);
				gld_send_disable_multi(macinfo, mcast);
			}
		}
		kmem_free(gld->gld_mcast,
		    sizeof (gld_mcast_t *) * gld->gld_multicnt);
		gld->gld_mcast = NULL;
		gld->gld_multicnt = 0;
	}

	/* decide if we need to turn off any promiscuity */
	phys_off = (gld->gld_flags & GLD_PROM_PHYS &&
	    --mac_pvt->nprom == 0);
	mult_off = (gld->gld_flags & GLD_PROM_MULT &&
	    --mac_pvt->nprom_multi == 0);

	if (phys_off) {
		op = (mac_pvt->nprom_multi == 0) ? GLD_MAC_PROMISC_NONE :
		    GLD_MAC_PROMISC_MULTI;
	} else if (mult_off) {
		op = (mac_pvt->nprom == 0) ? GLD_MAC_PROMISC_NONE :
		    GLD_MAC_PROMISC_NOOP;	/* phys overrides multi */
	}

	if (op != GLD_MAC_PROMISC_NOOP)
		(void) (*macinfo->gldm_set_promiscuous)(macinfo, op);

	vlan = (gld_vlan_t *)gld->gld_vlan;
	if (gld->gld_flags & GLD_PROM_PHYS)
		vlan->gldv_nprom--;
	if (gld->gld_flags & GLD_PROM_MULT)
		vlan->gldv_nprom--;
	if (gld->gld_flags & GLD_PROM_SAP) {
		vlan->gldv_nprom--;
		vlan->gldv_nvlan_sap--;
	}

	gld->gld_flags &= ~(GLD_PROM_PHYS | GLD_PROM_SAP | GLD_PROM_MULT);

	GLDM_UNLOCK(macinfo);

	if (phys_off)
		gld_notify_ind(macinfo, DL_NOTE_PROMISC_OFF_PHYS, NULL);

	/*
	 * We need to hold both locks when modifying the mac stream list
	 * to protect findminor as well as everyone else.
	 */
	mutex_enter(&glddev->gld_devlock);
	GLDM_LOCK(macinfo, RW_WRITER);

	/* disassociate this stream with its vlan and underlying mac */
	gldremque(gld);

	if (--vlan->gldv_nstreams == 0) {
		gld_rem_vlan(vlan);
		gld->gld_vlan = NULL;
	}

	gld->gld_mac_info = NULL;
	gld->gld_state = DL_UNATTACHED;

	/* cleanup mac layer if last vlan */
	if (mac_pvt->nvlan == 0) {
		gld_stop_mac(macinfo);
		macinfo->gldm_GLD_flags &= ~GLD_INTR_WAIT;
	}

	/* make sure no references to this gld for gld_v0_sched */
	if (mac_pvt->last_sched == gld)
		mac_pvt->last_sched = NULL;

	GLDM_UNLOCK(macinfo);

	/* put the stream on the unattached Style 2 list */
	gldinsque(gld, glddev->gld_str_prev);

	mutex_exit(&glddev->gld_devlock);

	/* There will be no mp if we were called from close */
	if (mp) {
		dlokack(q, mp, DL_DETACH_REQ);
	}
	if (gld->gld_style == DL_STYLE2)
		(void) qassociate(q, -1);
	return (GLDE_OK);
}

/*
 * gld_enable_multi (q, mp)
 * Enables multicast address on the stream.  If the mac layer
 * isn't enabled for this address, enable at that level as well.
 */
static int
gld_enable_multi(queue_t *q, mblk_t *mp)
{
	gld_t  *gld = (gld_t *)q->q_ptr;
	glddev_t *glddev;
	gld_mac_info_t *macinfo = gld->gld_mac_info;
	unsigned char *maddr;
	dl_enabmulti_req_t *multi;
	gld_mcast_t *mcast;
	int	i, rc;
	gld_mac_pvt_t *mac_pvt;

#ifdef GLD_DEBUG
	if (gld_debug & GLDPROT) {
		cmn_err(CE_NOTE, "gld_enable_multi(%p, %p)", (void *)q,
		    (void *)mp);
	}
#endif

	if (gld->gld_state == DL_UNATTACHED)
		return (DL_OUTSTATE);

	ASSERT(macinfo != NULL);
	mac_pvt = (gld_mac_pvt_t *)macinfo->gldm_mac_pvt;

	if (macinfo->gldm_set_multicast == NULL) {
		return (DL_UNSUPPORTED);
	}

	multi = (dl_enabmulti_req_t *)mp->b_rptr;

	if (!MBLKIN(mp, multi->dl_addr_offset, multi->dl_addr_length) ||
	    multi->dl_addr_length != macinfo->gldm_addrlen)
		return (DL_BADADDR);

	/* request appears to be valid */

	glddev = mac_pvt->major_dev;
	ASSERT(glddev == gld->gld_device);

	maddr = mp->b_rptr + multi->dl_addr_offset;

	/*
	 * The multicast addresses live in a per-device table, along
	 * with a reference count.  Each stream has a table that
	 * points to entries in the device table, with the reference
	 * count reflecting the number of streams pointing at it.  If
	 * this multicast address is already in the per-device table,
	 * all we have to do is point at it.
	 */
	GLDM_LOCK(macinfo, RW_WRITER);

	/* does this address appear in current table? */
	if (gld->gld_mcast == NULL) {
		/* no mcast addresses -- allocate table */
		gld->gld_mcast = GLD_GETSTRUCT(gld_mcast_t *,
		    glddev->gld_multisize);
		if (gld->gld_mcast == NULL) {
			GLDM_UNLOCK(macinfo);
			dlerrorack(q, mp, DL_ENABMULTI_REQ, DL_SYSERR, ENOSR);
			return (GLDE_OK);
		}
		gld->gld_multicnt = glddev->gld_multisize;
	} else {
		for (i = 0; i < gld->gld_multicnt; i++) {
			if (gld->gld_mcast[i] &&
			    mac_eq(gld->gld_mcast[i]->gldm_addr,
			    maddr, macinfo->gldm_addrlen)) {
				/* this is a match -- just succeed */
				ASSERT(gld->gld_mcast[i]->gldm_refcnt);
				GLDM_UNLOCK(macinfo);
				dlokack(q, mp, DL_ENABMULTI_REQ);
				return (GLDE_OK);
			}
		}
	}

	/*
	 * it wasn't in the stream so check to see if the mac layer has it
	 */
	mcast = NULL;
	if (mac_pvt->mcast_table == NULL) {
		mac_pvt->mcast_table = GLD_GETSTRUCT(gld_mcast_t,
		    glddev->gld_multisize);
		if (mac_pvt->mcast_table == NULL) {
			GLDM_UNLOCK(macinfo);
			dlerrorack(q, mp, DL_ENABMULTI_REQ, DL_SYSERR, ENOSR);
			return (GLDE_OK);
		}
	} else {
		for (i = 0; i < glddev->gld_multisize; i++) {
			if (mac_pvt->mcast_table[i].gldm_refcnt &&
			    mac_eq(mac_pvt->mcast_table[i].gldm_addr,
			    maddr, macinfo->gldm_addrlen)) {
				mcast = &mac_pvt->mcast_table[i];
				break;
			}
		}
	}
	if (mcast == NULL) {
		/* not in mac layer -- find an empty mac slot to fill in */
		for (i = 0; i < glddev->gld_multisize; i++) {
			if (mac_pvt->mcast_table[i].gldm_refcnt == 0) {
				mcast = &mac_pvt->mcast_table[i];
				mac_copy(maddr, mcast->gldm_addr,
				    macinfo->gldm_addrlen);
				break;
			}
		}
	}
	if (mcast == NULL) {
		/* couldn't get a mac layer slot */
		GLDM_UNLOCK(macinfo);
		return (DL_TOOMANY);
	}

	/* now we have a mac layer slot in mcast -- get a stream slot */
	for (i = 0; i < gld->gld_multicnt; i++) {
		if (gld->gld_mcast[i] != NULL)
			continue;
		/* found an empty slot */
		if (!mcast->gldm_refcnt) {
			/* set mcast in hardware */
			unsigned char cmaddr[GLD_MAX_ADDRLEN];

			ASSERT(sizeof (cmaddr) >= macinfo->gldm_addrlen);
			cmac_copy(maddr, cmaddr,
			    macinfo->gldm_addrlen, macinfo);

			rc = (*macinfo->gldm_set_multicast)
			    (macinfo, cmaddr, GLD_MULTI_ENABLE);
			if (rc == GLD_NOTSUPPORTED) {
				GLDM_UNLOCK(macinfo);
				return (DL_NOTSUPPORTED);
			} else if (rc == GLD_NORESOURCES) {
				GLDM_UNLOCK(macinfo);
				return (DL_TOOMANY);
			} else if (rc == GLD_BADARG) {
				GLDM_UNLOCK(macinfo);
				return (DL_BADADDR);
			} else if (rc == GLD_RETRY) {
				/*
				 * The putbq and gld_xwait must be
				 * within the lock to prevent races
				 * with gld_sched.
				 */
				(void) putbq(q, mp);
				gld->gld_xwait = B_TRUE;
				GLDM_UNLOCK(macinfo);
				return (GLDE_RETRY);
			} else if (rc != GLD_SUCCESS) {
				GLDM_UNLOCK(macinfo);
				dlerrorack(q, mp, DL_ENABMULTI_REQ,
				    DL_SYSERR, EIO);
				return (GLDE_OK);
			}
		}
		gld->gld_mcast[i] = mcast;
		mcast->gldm_refcnt++;
		GLDM_UNLOCK(macinfo);
		dlokack(q, mp, DL_ENABMULTI_REQ);
		return (GLDE_OK);
	}

	/* couldn't get a stream slot */
	GLDM_UNLOCK(macinfo);
	return (DL_TOOMANY);
}


/*
 * gld_disable_multi (q, mp)
 * Disable the multicast address on the stream.  If last
 * reference for the mac layer, disable there as well.
 */
static int
gld_disable_multi(queue_t *q, mblk_t *mp)
{
	gld_t  *gld;
	gld_mac_info_t *macinfo;
	unsigned char *maddr;
	dl_disabmulti_req_t *multi;
	int i;
	gld_mcast_t *mcast;

#ifdef GLD_DEBUG
	if (gld_debug & GLDPROT) {
		cmn_err(CE_NOTE, "gld_disable_multi(%p, %p)", (void *)q,
		    (void *)mp);
	}
#endif

	gld = (gld_t *)q->q_ptr;
	if (gld->gld_state == DL_UNATTACHED)
		return (DL_OUTSTATE);

	macinfo = gld->gld_mac_info;
	ASSERT(macinfo != NULL);
	if (macinfo->gldm_set_multicast == NULL) {
		return (DL_UNSUPPORTED);
	}

	multi = (dl_disabmulti_req_t *)mp->b_rptr;

	if (!MBLKIN(mp, multi->dl_addr_offset, multi->dl_addr_length) ||
	    multi->dl_addr_length != macinfo->gldm_addrlen)
		return (DL_BADADDR);

	maddr = mp->b_rptr + multi->dl_addr_offset;

	/* request appears to be valid */
	/* does this address appear in current table? */
	GLDM_LOCK(macinfo, RW_WRITER);
	if (gld->gld_mcast != NULL) {
		for (i = 0; i < gld->gld_multicnt; i++)
			if (((mcast = gld->gld_mcast[i]) != NULL) &&
			    mac_eq(mcast->gldm_addr,
			    maddr, macinfo->gldm_addrlen)) {
				ASSERT(mcast->gldm_refcnt);
				gld_send_disable_multi(macinfo, mcast);
				gld->gld_mcast[i] = NULL;
				GLDM_UNLOCK(macinfo);
				dlokack(q, mp, DL_DISABMULTI_REQ);
				return (GLDE_OK);
			}
	}
	GLDM_UNLOCK(macinfo);
	return (DL_NOTENAB); /* not an enabled address */
}

/*
 * gld_send_disable_multi(macinfo, mcast)
 * this function is used to disable a multicast address if the reference
 * count goes to zero. The disable request will then be forwarded to the
 * lower stream.
 */
static void
gld_send_disable_multi(gld_mac_info_t *macinfo, gld_mcast_t *mcast)
{
	ASSERT(macinfo != NULL);
	ASSERT(GLDM_LOCK_HELD_WRITE(macinfo));
	ASSERT(mcast != NULL);
	ASSERT(mcast->gldm_refcnt);

	if (!mcast->gldm_refcnt) {
		return;			/* "cannot happen" */
	}

	if (--mcast->gldm_refcnt > 0) {
		return;
	}

	/*
	 * This must be converted from canonical form to device form.
	 * The refcnt is now zero so we can trash the data.
	 */
	if (macinfo->gldm_options & GLDOPT_CANONICAL_ADDR)
		gld_bitreverse(mcast->gldm_addr, macinfo->gldm_addrlen);

	/* XXX Ought to check for GLD_NORESOURCES or GLD_FAILURE */
	(void) (*macinfo->gldm_set_multicast)
	    (macinfo, mcast->gldm_addr, GLD_MULTI_DISABLE);
}

/*
 * gld_promisc (q, mp, req, on)
 *	enable or disable the use of promiscuous mode with the hardware
 */
static int
gld_promisc(queue_t *q, mblk_t *mp, t_uscalar_t req, boolean_t on)
{
	gld_t *gld;
	gld_mac_info_t *macinfo;
	gld_mac_pvt_t *mac_pvt;
	gld_vlan_t *vlan;
	union DL_primitives *prim;
	int macrc = GLD_SUCCESS;
	int dlerr = GLDE_OK;
	int op = GLD_MAC_PROMISC_NOOP;

#ifdef GLD_DEBUG
	if (gld_debug & GLDTRACE)
		cmn_err(CE_NOTE, "gld_promisc(%p, %p, %d, %d)",
		    (void *)q, (void *)mp, req, on);
#endif

	ASSERT(mp != NULL);
	prim = (union DL_primitives *)mp->b_rptr;

	/* XXX I think spec allows promisc in unattached state */
	gld = (gld_t *)q->q_ptr;
	if (gld->gld_state == DL_UNATTACHED)
		return (DL_OUTSTATE);

	macinfo = gld->gld_mac_info;
	ASSERT(macinfo != NULL);
	mac_pvt = (gld_mac_pvt_t *)macinfo->gldm_mac_pvt;

	vlan = (gld_vlan_t *)gld->gld_vlan;
	ASSERT(vlan != NULL);

	GLDM_LOCK(macinfo, RW_WRITER);

	/*
	 * Work out what request (if any) has to be made to the MAC layer
	 */
	if (on) {
		switch (prim->promiscon_req.dl_level) {
		default:
			dlerr = DL_UNSUPPORTED;	/* this is an error */
			break;

		case DL_PROMISC_PHYS:
			if (mac_pvt->nprom == 0)
				op = GLD_MAC_PROMISC_PHYS;
			break;

		case DL_PROMISC_MULTI:
			if (mac_pvt->nprom_multi == 0)
				if (mac_pvt->nprom == 0)
					op = GLD_MAC_PROMISC_MULTI;
			break;

		case DL_PROMISC_SAP:
			/* We can do this without reference to the MAC */
			break;
		}
	} else {
		switch (prim->promiscoff_req.dl_level) {
		default:
			dlerr = DL_UNSUPPORTED;	/* this is an error */
			break;

		case DL_PROMISC_PHYS:
			if (!(gld->gld_flags & GLD_PROM_PHYS))
				dlerr = DL_NOTENAB;
			else if (mac_pvt->nprom == 1)
				if (mac_pvt->nprom_multi)
					op = GLD_MAC_PROMISC_MULTI;
				else
					op = GLD_MAC_PROMISC_NONE;
			break;

		case DL_PROMISC_MULTI:
			if (!(gld->gld_flags & GLD_PROM_MULT))
				dlerr = DL_NOTENAB;
			else if (mac_pvt->nprom_multi == 1)
				if (mac_pvt->nprom == 0)
					op = GLD_MAC_PROMISC_NONE;
			break;

		case DL_PROMISC_SAP:
			if (!(gld->gld_flags & GLD_PROM_SAP))
				dlerr = DL_NOTENAB;

			/* We can do this without reference to the MAC */
			break;
		}
	}

	/*
	 * The request was invalid in some way so no need to continue.
	 */
	if (dlerr != GLDE_OK) {
		GLDM_UNLOCK(macinfo);
		return (dlerr);
	}

	/*
	 * Issue the request to the MAC layer, if required
	 */
	if (op != GLD_MAC_PROMISC_NOOP) {
		macrc = (*macinfo->gldm_set_promiscuous)(macinfo, op);
	}

	/*
	 * On success, update the appropriate flags & refcounts
	 */
	if (macrc == GLD_SUCCESS) {
		if (on) {
			switch (prim->promiscon_req.dl_level) {
			case DL_PROMISC_PHYS:
				mac_pvt->nprom++;
				vlan->gldv_nprom++;
				gld->gld_flags |= GLD_PROM_PHYS;
				break;

			case DL_PROMISC_MULTI:
				mac_pvt->nprom_multi++;
				vlan->gldv_nprom++;
				gld->gld_flags |= GLD_PROM_MULT;
				break;

			case DL_PROMISC_SAP:
				gld->gld_flags |= GLD_PROM_SAP;
				vlan->gldv_nprom++;
				vlan->gldv_nvlan_sap++;
				break;

			default:
				break;
			}
		} else {
			switch (prim->promiscoff_req.dl_level) {
			case DL_PROMISC_PHYS:
				mac_pvt->nprom--;
				vlan->gldv_nprom--;
				gld->gld_flags &= ~GLD_PROM_PHYS;
				break;

			case DL_PROMISC_MULTI:
				mac_pvt->nprom_multi--;
				vlan->gldv_nprom--;
				gld->gld_flags &= ~GLD_PROM_MULT;
				break;

			case DL_PROMISC_SAP:
				gld->gld_flags &= ~GLD_PROM_SAP;
				vlan->gldv_nvlan_sap--;
				vlan->gldv_nprom--;
				break;

			default:
				break;
			}
		}
	} else if (macrc == GLD_RETRY) {
		/*
		 * The putbq and gld_xwait must be within the lock to
		 * prevent races with gld_sched.
		 */
		(void) putbq(q, mp);
		gld->gld_xwait = B_TRUE;
	}

	GLDM_UNLOCK(macinfo);

	/*
	 * Finally, decide how to reply.
	 *
	 * If <macrc> is not GLD_SUCCESS, the request was put to the MAC
	 * layer but failed.  In such cases, we can return a DL_* error
	 * code and let the caller send an error-ack reply upstream, or
	 * we can send a reply here and then return GLDE_OK so that the
	 * caller doesn't also respond.
	 *
	 * If physical-promiscuous mode was (successfully) switched on or
	 * off, send a notification (DL_NOTIFY_IND) to anyone interested.
	 */
	switch (macrc) {
	case GLD_NOTSUPPORTED:
		return (DL_NOTSUPPORTED);

	case GLD_NORESOURCES:
		dlerrorack(q, mp, req, DL_SYSERR, ENOSR);
		return (GLDE_OK);

	case GLD_RETRY:
		return (GLDE_RETRY);

	default:
		dlerrorack(q, mp, req, DL_SYSERR, EIO);
		return (GLDE_OK);

	case GLD_SUCCESS:
		dlokack(q, mp, req);
		break;
	}

	switch (op) {
	case GLD_MAC_PROMISC_NOOP:
		break;

	case GLD_MAC_PROMISC_PHYS:
		gld_notify_ind(macinfo, DL_NOTE_PROMISC_ON_PHYS, NULL);
		break;

	default:
		gld_notify_ind(macinfo, DL_NOTE_PROMISC_OFF_PHYS, NULL);
		break;
	}

	return (GLDE_OK);
}

/*
 * gld_physaddr()
 *	get the current or factory physical address value
 */
static int
gld_physaddr(queue_t *q, mblk_t *mp)
{
	gld_t *gld = (gld_t *)q->q_ptr;
	gld_mac_info_t *macinfo;
	union DL_primitives *prim = (union DL_primitives *)mp->b_rptr;
	unsigned char addr[GLD_MAX_ADDRLEN];

	if (gld->gld_state == DL_UNATTACHED)
		return (DL_OUTSTATE);

	macinfo = (gld_mac_info_t *)gld->gld_mac_info;
	ASSERT(macinfo != NULL);
	ASSERT(macinfo->gldm_addrlen <= GLD_MAX_ADDRLEN);

	switch (prim->physaddr_req.dl_addr_type) {
	case DL_FACT_PHYS_ADDR:
		mac_copy((caddr_t)macinfo->gldm_vendor_addr,
		    (caddr_t)addr, macinfo->gldm_addrlen);
		break;
	case DL_CURR_PHYS_ADDR:
		/* make a copy so we don't hold the lock across qreply */
		GLDM_LOCK(macinfo, RW_WRITER);
		mac_copy((caddr_t)
		    ((gld_mac_pvt_t *)macinfo->gldm_mac_pvt)->curr_macaddr,
		    (caddr_t)addr, macinfo->gldm_addrlen);
		GLDM_UNLOCK(macinfo);
		break;
	default:
		return (DL_BADPRIM);
	}
	dlphysaddrack(q, mp, (caddr_t)addr, macinfo->gldm_addrlen);
	return (GLDE_OK);
}

/*
 * gld_setaddr()
 *	change the hardware's physical address to a user specified value
 */
static int
gld_setaddr(queue_t *q, mblk_t *mp)
{
	gld_t *gld = (gld_t *)q->q_ptr;
	gld_mac_info_t *macinfo;
	gld_mac_pvt_t *mac_pvt;
	union DL_primitives *prim = (union DL_primitives *)mp->b_rptr;
	unsigned char *addr;
	unsigned char cmaddr[GLD_MAX_ADDRLEN];
	int rc;
	gld_vlan_t *vlan;

	if (gld->gld_state == DL_UNATTACHED)
		return (DL_OUTSTATE);

	vlan = (gld_vlan_t *)gld->gld_vlan;
	ASSERT(vlan != NULL);

	if (vlan->gldv_id != VLAN_VID_NONE)
		return (DL_NOTSUPPORTED);

	macinfo = (gld_mac_info_t *)gld->gld_mac_info;
	ASSERT(macinfo != NULL);
	mac_pvt = (gld_mac_pvt_t *)macinfo->gldm_mac_pvt;

	if (!MBLKIN(mp, prim->set_physaddr_req.dl_addr_offset,
	    prim->set_physaddr_req.dl_addr_length) ||
	    prim->set_physaddr_req.dl_addr_length != macinfo->gldm_addrlen)
		return (DL_BADADDR);

	GLDM_LOCK(macinfo, RW_WRITER);

	/* now do the set at the hardware level */
	addr = mp->b_rptr + prim->set_physaddr_req.dl_addr_offset;
	ASSERT(sizeof (cmaddr) >= macinfo->gldm_addrlen);
	cmac_copy(addr, cmaddr, macinfo->gldm_addrlen, macinfo);

	rc = (*macinfo->gldm_set_mac_addr)(macinfo, cmaddr);
	if (rc == GLD_SUCCESS)
		mac_copy(addr, mac_pvt->curr_macaddr,
		    macinfo->gldm_addrlen);

	GLDM_UNLOCK(macinfo);

	switch (rc) {
	case GLD_SUCCESS:
		break;
	case GLD_NOTSUPPORTED:
		return (DL_NOTSUPPORTED);
	case GLD_BADARG:
		return (DL_BADADDR);
	case GLD_NORESOURCES:
		dlerrorack(q, mp, DL_SET_PHYS_ADDR_REQ, DL_SYSERR, ENOSR);
		return (GLDE_OK);
	default:
		dlerrorack(q, mp, DL_SET_PHYS_ADDR_REQ, DL_SYSERR, EIO);
		return (GLDE_OK);
	}

	gld_notify_ind(macinfo, DL_NOTE_PHYS_ADDR, NULL);

	dlokack(q, mp, DL_SET_PHYS_ADDR_REQ);
	return (GLDE_OK);
}

int
gld_get_statistics(queue_t *q, mblk_t *mp)
{
	dl_get_statistics_ack_t *dlsp;
	gld_t  *gld = (gld_t *)q->q_ptr;
	gld_mac_info_t *macinfo = gld->gld_mac_info;
	gld_mac_pvt_t *mac_pvt;

	if (gld->gld_state == DL_UNATTACHED)
		return (DL_OUTSTATE);

	ASSERT(macinfo != NULL);

	mac_pvt = (gld_mac_pvt_t *)macinfo->gldm_mac_pvt;
	(void) gld_update_kstat(mac_pvt->kstatp, KSTAT_READ);

	mp = mexchange(q, mp, DL_GET_STATISTICS_ACK_SIZE +
	    sizeof (struct gldkstats), M_PCPROTO, DL_GET_STATISTICS_ACK);

	if (mp == NULL)
		return (GLDE_OK);	/* mexchange already sent merror */

	dlsp = (dl_get_statistics_ack_t *)mp->b_rptr;
	dlsp->dl_primitive = DL_GET_STATISTICS_ACK;
	dlsp->dl_stat_length = sizeof (struct gldkstats);
	dlsp->dl_stat_offset = DL_GET_STATISTICS_ACK_SIZE;

	GLDM_LOCK(macinfo, RW_WRITER);
	bcopy(mac_pvt->kstatp->ks_data,
	    (mp->b_rptr + DL_GET_STATISTICS_ACK_SIZE),
	    sizeof (struct gldkstats));
	GLDM_UNLOCK(macinfo);

	qreply(q, mp);
	return (GLDE_OK);
}

/* =================================================== */
/* misc utilities, some requiring various mutexes held */
/* =================================================== */

/*
 * Initialize and start the driver.
 */
static int
gld_start_mac(gld_mac_info_t *macinfo)
{
	int	rc;
	unsigned char cmaddr[GLD_MAX_ADDRLEN];
	gld_mac_pvt_t *mac_pvt = (gld_mac_pvt_t *)macinfo->gldm_mac_pvt;

	ASSERT(GLDM_LOCK_HELD_WRITE(macinfo));
	ASSERT(!mac_pvt->started);

	rc = (*macinfo->gldm_reset)(macinfo);
	if (rc != GLD_SUCCESS)
		return (GLD_FAILURE);

	/* set the addr after we reset the device */
	ASSERT(sizeof (cmaddr) >= macinfo->gldm_addrlen);
	cmac_copy(((gld_mac_pvt_t *)macinfo->gldm_mac_pvt)
	    ->curr_macaddr, cmaddr, macinfo->gldm_addrlen, macinfo);

	rc = (*macinfo->gldm_set_mac_addr)(macinfo, cmaddr);
	ASSERT(rc != GLD_BADARG);  /* this address was good before */
	if (rc != GLD_SUCCESS && rc != GLD_NOTSUPPORTED)
		return (GLD_FAILURE);

	rc = (*macinfo->gldm_start)(macinfo);
	if (rc != GLD_SUCCESS)
		return (GLD_FAILURE);

	mac_pvt->started = B_TRUE;
	return (GLD_SUCCESS);
}

/*
 * Stop the driver.
 */
static void
gld_stop_mac(gld_mac_info_t *macinfo)
{
	gld_mac_pvt_t *mac_pvt = (gld_mac_pvt_t *)macinfo->gldm_mac_pvt;

	ASSERT(GLDM_LOCK_HELD_WRITE(macinfo));
	ASSERT(mac_pvt->started);

	(void) (*macinfo->gldm_stop)(macinfo);

	mac_pvt->started = B_FALSE;
}


/*
 * gld_set_ipq will set a pointer to the queue which is bound to the
 * IP sap if:
 * o the device type is ethernet or IPoIB.
 * o there is no stream in SAP promiscuous mode.
 * o there is exactly one stream bound to the IP sap.
 * o the stream is in "fastpath" mode.
 */
static void
gld_set_ipq(gld_t *gld)
{
	gld_vlan_t	*vlan;
	gld_mac_info_t	*macinfo = gld->gld_mac_info;
	gld_t		*ip_gld = NULL;
	uint_t		ipq_candidates = 0;
	gld_t		*ipv6_gld = NULL;
	uint_t		ipv6q_candidates = 0;

	ASSERT(GLDM_LOCK_HELD_WRITE(macinfo));

	/* The ipq code in gld_recv() is intimate with ethernet/IPoIB */
	if (((macinfo->gldm_type != DL_ETHER) &&
	    (macinfo->gldm_type != DL_IB)) ||
	    (gld_global_options & GLD_OPT_NO_IPQ))
		return;

	vlan = (gld_vlan_t *)gld->gld_vlan;
	ASSERT(vlan != NULL);

	/* clear down any previously defined ipqs */
	vlan->gldv_ipq = NULL;
	vlan->gldv_ipv6q = NULL;

	/* Try to find a single stream eligible to receive IP packets */
	for (gld = vlan->gldv_str_next;
	    gld != (gld_t *)&vlan->gldv_str_next; gld = gld->gld_next) {
		if (gld->gld_state != DL_IDLE)
			continue;	/* not eligible to receive */
		if (gld->gld_flags & GLD_STR_CLOSING)
			continue;	/* not eligible to receive */

		if (gld->gld_sap == ETHERTYPE_IP) {
			ip_gld = gld;
			ipq_candidates++;
		}

		if (gld->gld_sap == ETHERTYPE_IPV6) {
			ipv6_gld = gld;
			ipv6q_candidates++;
		}
	}

	if (ipq_candidates == 1) {
		ASSERT(ip_gld != NULL);

		if (ip_gld->gld_flags & GLD_FAST)	/* eligible for ipq */
			vlan->gldv_ipq = ip_gld->gld_qptr;
	}

	if (ipv6q_candidates == 1) {
		ASSERT(ipv6_gld != NULL);

		if (ipv6_gld->gld_flags & GLD_FAST)	/* eligible for ipq */
			vlan->gldv_ipv6q = ipv6_gld->gld_qptr;
	}
}

/*
 * gld_flushqueue (q)
 *	used by DLPI primitives that require flushing the queues.
 *	essentially, this is DL_UNBIND_REQ.
 */
static void
gld_flushqueue(queue_t *q)
{
	/* flush all data in both queues */
	/* XXX Should these be FLUSHALL? */
	flushq(q, FLUSHDATA);
	flushq(WR(q), FLUSHDATA);
	/* flush all the queues upstream */
	(void) putctl1(q, M_FLUSH, FLUSHRW);
}

/*
 * gld_devlookup (major)
 * search the device table for the device with specified
 * major number and return a pointer to it if it exists
 */
static glddev_t *
gld_devlookup(int major)
{
	struct glddevice *dev;

	ASSERT(mutex_owned(&gld_device_list.gld_devlock));

	for (dev = gld_device_list.gld_next;
	    dev != &gld_device_list;
	    dev = dev->gld_next) {
		ASSERT(dev);
		if (dev->gld_major == major)
			return (dev);
	}
	return (NULL);
}

/*
 * gld_findminor(device)
 * Returns a minor number currently unused by any stream in the current
 * device class (major) list.
 */
static int
gld_findminor(glddev_t *device)
{
	gld_t		*next;
	gld_mac_info_t	*nextmac;
	gld_vlan_t	*nextvlan;
	int		minor;
	int		i;

	ASSERT(mutex_owned(&device->gld_devlock));

	/* The fast way */
	if (device->gld_nextminor >= GLD_MIN_CLONE_MINOR &&
	    device->gld_nextminor <= GLD_MAX_CLONE_MINOR)
		return (device->gld_nextminor++);

	/* The steady way */
	for (minor = GLD_MIN_CLONE_MINOR; minor <= GLD_MAX_CLONE_MINOR;
	    minor++) {
		/* Search all unattached streams */
		for (next = device->gld_str_next;
		    next != (gld_t *)&device->gld_str_next;
		    next = next->gld_next) {
			if (minor == next->gld_minor)
				goto nextminor;
		}
		/* Search all attached streams; we don't need maclock because */
		/* mac stream list is protected by devlock as well as maclock */
		for (nextmac = device->gld_mac_next;
		    nextmac != (gld_mac_info_t *)&device->gld_mac_next;
		    nextmac = nextmac->gldm_next) {
			gld_mac_pvt_t *pvt =
			    (gld_mac_pvt_t *)nextmac->gldm_mac_pvt;

			if (!(nextmac->gldm_GLD_flags & GLD_MAC_READY))
				continue;	/* this one's not ready yet */

			for (i = 0; i < VLAN_HASHSZ; i++) {
				for (nextvlan = pvt->vlan_hash[i];
				    nextvlan != NULL;
				    nextvlan = nextvlan->gldv_next) {
					for (next = nextvlan->gldv_str_next;
					    next !=
					    (gld_t *)&nextvlan->gldv_str_next;
					    next = next->gld_next) {
						if (minor == next->gld_minor)
							goto nextminor;
					}
				}
			}
		}

		return (minor);
nextminor:
		/* don't need to do anything */
		;
	}
	cmn_err(CE_WARN, "GLD ran out of minor numbers for %s",
	    device->gld_name);
	return (0);
}

/*
 * version of insque/remque for use by this driver
 */
struct qelem {
	struct qelem *q_forw;
	struct qelem *q_back;
	/* rest of structure */
};

static void
gldinsque(void *elem, void *pred)
{
	struct qelem *pelem = elem;
	struct qelem *ppred = pred;
	struct qelem *pnext = ppred->q_forw;

	pelem->q_forw = pnext;
	pelem->q_back = ppred;
	ppred->q_forw = pelem;
	pnext->q_back = pelem;
}

static void
gldremque(void *arg)
{
	struct qelem *pelem = arg;
	struct qelem *elem = arg;

	pelem->q_forw->q_back = pelem->q_back;
	pelem->q_back->q_forw = pelem->q_forw;
	elem->q_back = elem->q_forw = NULL;
}

static gld_vlan_t *
gld_add_vlan(gld_mac_info_t *macinfo, uint32_t vid)
{
	gld_mac_pvt_t	*mac_pvt = (gld_mac_pvt_t *)macinfo->gldm_mac_pvt;
	gld_vlan_t	**pp;
	gld_vlan_t	*p;

	pp = &(mac_pvt->vlan_hash[vid % VLAN_HASHSZ]);
	while ((p = *pp) != NULL) {
		ASSERT(p->gldv_id != vid);
		pp = &(p->gldv_next);
	}

	if ((p = kmem_zalloc(sizeof (gld_vlan_t), KM_NOSLEEP)) == NULL)
		return (NULL);

	p->gldv_mac = macinfo;
	p->gldv_id = vid;

	if (vid == VLAN_VID_NONE) {
		p->gldv_ptag = VLAN_VTAG_NONE;
		p->gldv_stats = mac_pvt->statistics;
		p->gldv_kstatp = NULL;
	} else {
		p->gldv_ptag = GLD_MK_PTAG(VLAN_CFI_ETHER, vid);
		p->gldv_stats = kmem_zalloc(sizeof (struct gld_stats),
		    KM_SLEEP);

		if (gld_init_vlan_stats(p) != GLD_SUCCESS) {
			kmem_free(p->gldv_stats, sizeof (struct gld_stats));
			kmem_free(p, sizeof (gld_vlan_t));
			return (NULL);
		}
	}

	p->gldv_str_next = p->gldv_str_prev = (gld_t *)&p->gldv_str_next;
	mac_pvt->nvlan++;
	*pp = p;

	return (p);
}

static void
gld_rem_vlan(gld_vlan_t *vlan)
{
	gld_mac_info_t	*macinfo = vlan->gldv_mac;
	gld_mac_pvt_t	*mac_pvt = (gld_mac_pvt_t *)macinfo->gldm_mac_pvt;
	gld_vlan_t	**pp;
	gld_vlan_t	*p;

	pp = &(mac_pvt->vlan_hash[vlan->gldv_id % VLAN_HASHSZ]);
	while ((p = *pp) != NULL) {
		if (p->gldv_id == vlan->gldv_id)
			break;
		pp = &(p->gldv_next);
	}
	ASSERT(p != NULL);

	*pp = p->gldv_next;
	mac_pvt->nvlan--;
	if (p->gldv_id != VLAN_VID_NONE) {
		ASSERT(p->gldv_kstatp != NULL);
		kstat_delete(p->gldv_kstatp);
		kmem_free(p->gldv_stats, sizeof (struct gld_stats));
	}
	kmem_free(p, sizeof (gld_vlan_t));
}

gld_vlan_t *
gld_find_vlan(gld_mac_info_t *macinfo, uint32_t vid)
{
	gld_mac_pvt_t	*mac_pvt = (gld_mac_pvt_t *)macinfo->gldm_mac_pvt;
	gld_vlan_t	*p;

	p = mac_pvt->vlan_hash[vid % VLAN_HASHSZ];
	while (p != NULL) {
		if (p->gldv_id == vid)
			return (p);
		p = p->gldv_next;
	}
	return (NULL);
}

gld_vlan_t *
gld_get_vlan(gld_mac_info_t *macinfo, uint32_t vid)
{
	gld_vlan_t	*vlan;

	if ((vlan = gld_find_vlan(macinfo, vid)) == NULL)
		vlan = gld_add_vlan(macinfo, vid);

	return (vlan);
}

/*
 * gld_bitrevcopy()
 * This is essentially bcopy, with the ability to bit reverse the
 * the source bytes. The MAC addresses bytes as transmitted by FDDI
 * interfaces are bit reversed.
 */
void
gld_bitrevcopy(caddr_t src, caddr_t target, size_t n)
{
	while (n--)
		*target++ = bit_rev[(uchar_t)*src++];
}

/*
 * gld_bitreverse()
 * Convert the bit order by swaping all the bits, using a
 * lookup table.
 */
void
gld_bitreverse(uchar_t *rptr, size_t n)
{
	while (n--) {
		*rptr = bit_rev[*rptr];
		rptr++;
	}
}

char *
gld_macaddr_sprintf(char *etherbuf, unsigned char *ap, int len)
{
	int i;
	char *cp = etherbuf;
	static char digits[] = "0123456789abcdef";

	for (i = 0; i < len; i++) {
		*cp++ = digits[*ap >> 4];
		*cp++ = digits[*ap++ & 0xf];
		*cp++ = ':';
	}
	*--cp = 0;
	return (etherbuf);
}

#ifdef GLD_DEBUG
static void
gld_check_assertions()
{
	glddev_t	*dev;
	gld_mac_info_t	*mac;
	gld_t		*str;
	gld_vlan_t	*vlan;
	int		i;

	mutex_enter(&gld_device_list.gld_devlock);

	for (dev = gld_device_list.gld_next;
	    dev != (glddev_t *)&gld_device_list.gld_next;
	    dev = dev->gld_next) {
		mutex_enter(&dev->gld_devlock);
		ASSERT(dev->gld_broadcast != NULL);
		for (str = dev->gld_str_next;
		    str != (gld_t *)&dev->gld_str_next;
		    str = str->gld_next) {
			ASSERT(str->gld_device == dev);
			ASSERT(str->gld_mac_info == NULL);
			ASSERT(str->gld_qptr != NULL);
			ASSERT(str->gld_minor >= GLD_MIN_CLONE_MINOR);
			ASSERT(str->gld_multicnt == 0);
			ASSERT(str->gld_mcast == NULL);
			ASSERT(!(str->gld_flags &
			    (GLD_PROM_PHYS|GLD_PROM_MULT|GLD_PROM_SAP)));
			ASSERT(str->gld_sap == 0);
			ASSERT(str->gld_state == DL_UNATTACHED);
		}
		for (mac = dev->gld_mac_next;
		    mac != (gld_mac_info_t *)&dev->gld_mac_next;
		    mac = mac->gldm_next) {
			int nvlan = 0;
			gld_mac_pvt_t *pvt = (gld_mac_pvt_t *)mac->gldm_mac_pvt;

			if (!(mac->gldm_GLD_flags & GLD_MAC_READY))
				continue;	/* this one's not ready yet */

			GLDM_LOCK(mac, RW_WRITER);
			ASSERT(mac->gldm_devinfo != NULL);
			ASSERT(mac->gldm_mac_pvt != NULL);
			ASSERT(pvt->interfacep != NULL);
			ASSERT(pvt->kstatp != NULL);
			ASSERT(pvt->statistics != NULL);
			ASSERT(pvt->major_dev == dev);

			for (i = 0; i < VLAN_HASHSZ; i++) {
				for (vlan = pvt->vlan_hash[i];
				    vlan != NULL; vlan = vlan->gldv_next) {
					int nstr = 0;

					ASSERT(vlan->gldv_mac == mac);

					for (str = vlan->gldv_str_next;
					    str !=
					    (gld_t *)&vlan->gldv_str_next;
					    str = str->gld_next) {
						ASSERT(str->gld_device == dev);
						ASSERT(str->gld_mac_info ==
						    mac);
						ASSERT(str->gld_qptr != NULL);
						ASSERT(str->gld_minor >=
						    GLD_MIN_CLONE_MINOR);
						ASSERT(
						    str->gld_multicnt == 0 ||
						    str->gld_mcast);
						nstr++;
					}
					ASSERT(vlan->gldv_nstreams == nstr);
					nvlan++;
				}
			}
			ASSERT(pvt->nvlan == nvlan);
			GLDM_UNLOCK(mac);
		}
		mutex_exit(&dev->gld_devlock);
	}
	mutex_exit(&gld_device_list.gld_devlock);
}
#endif
