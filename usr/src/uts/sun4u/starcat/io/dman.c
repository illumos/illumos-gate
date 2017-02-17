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
 * Starcat Management Network Driver
 *
 * ****** NOTICE **** This file also resides in the SSC gate as
 * ****** NOTICE **** usr/src/uts/sun4u/scman/scman.c. Any changes
 * ****** NOTICE **** made here must be propogated there as well.
 *
 */

#include <sys/types.h>
#include <sys/proc.h>
#include <sys/disp.h>
#include <sys/kmem.h>
#include <sys/stat.h>
#include <sys/kstat.h>
#include <sys/ksynch.h>
#include <sys/stream.h>
#include <sys/dlpi.h>
#include <sys/stropts.h>
#include <sys/strsubr.h>
#include <sys/debug.h>
#include <sys/conf.h>
#include <sys/kstr.h>
#include <sys/errno.h>
#include <sys/ethernet.h>
#include <sys/byteorder.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunldi.h>
#include <sys/modctl.h>
#include <sys/strsun.h>
#include <sys/callb.h>
#include <sys/pci.h>
#include <netinet/in.h>
#include <inet/common.h>
#include <inet/mi.h>
#include <inet/nd.h>
#include <sys/socket.h>
#include <netinet/igmp_var.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <sys/file.h>
#include <sys/dman.h>
#include <sys/autoconf.h>
#include <sys/zone.h>

extern int ddi_create_internal_pathname(dev_info_t *, char *, int, minor_t);

#define	MAN_IDNAME	"dman"
#define	DMAN_INT_PATH	"/devices/pseudo/dman@0:dman"
#define	DMAN_PATH	"/devices/pseudo/clone@0:dman"
#define	ERI_IDNAME	"eri"
#define	ERI_PATH	"/devices/pseudo/clone@0:eri"

#if defined(DEBUG)

static void man_print_msp(manstr_t *);
static void man_print_man(man_t *);
static void man_print_mdp(man_dest_t *);
static void man_print_dev(man_dev_t *);
static void man_print_mip(mi_path_t *);
static void man_print_mtp(mi_time_t *);
static void man_print_mpg(man_pg_t *);
static void man_print_path(man_path_t *);
static void man_print_work(man_work_t *);

/*
 * Set manstr_t dlpistate (upper half of multiplexor)
 */
#define	SETSTATE(msp, state) \
	MAN_DBG(MAN_DLPI, ("msp=0x%p @ %d state %s=>%s\n",		\
		    (void *)msp, __LINE__, dss[msp->ms_dlpistate],	\
		    dss[(state)]));					\
		    msp->ms_dlpistate = (state);
/*
 * Set man_dest_t dlpistate (lower half of multiplexor)
 */
#define	D_SETSTATE(mdp, state) \
	MAN_DBG(MAN_DLPI, ("dst=0x%p @ %d state %s=>%s\n",	   \
		    (void *)mdp, __LINE__, dss[mdp->md_dlpistate], \
		    dss[(state)]));				   \
		    mdp->md_dlpistate = (state);

static char *promisc[] = {	/* DLPI promisc Strings */
	"not used",		/* 0x00 */
	"DL_PROMISC_PHYS",	/* 0x01 */
	"DL_PROMISC_SAP",	/* 0x02 */
	"DL_PROMISC_MULTI"	/* 0x03 */
};

static char *dps[] = {			/* DLPI Primitive Strings */
	"DL_INFO_REQ",			/* 0x00 */
	"DL_BIND_REQ",			/* 0x01 */
	"DL_UNBIND_REQ",		/* 0x02 */
	"DL_INFO_ACK",			/* 0x03 */
	"DL_BIND_ACK",			/* 0x04 */
	"DL_ERROR_ACK",			/* 0x05 */
	"DL_OK_ACK",			/* 0x06 */
	"DL_UNITDATA_REQ",		/* 0x07 */
	"DL_UNITDATA_IND",		/* 0x08 */
	"DL_UDERROR_IND",		/* 0x09 */
	"DL_UDQOS_REQ",			/* 0x0a */
	"DL_ATTACH_REQ",		/* 0x0b */
	"DL_DETACH_REQ",		/* 0x0c */
	"DL_CONNECT_REQ",		/* 0x0d */
	"DL_CONNECT_IND",		/* 0x0e */
	"DL_CONNECT_RES",		/* 0x0f */
	"DL_CONNECT_CON",		/* 0x10 */
	"DL_TOKEN_REQ",			/* 0x11 */
	"DL_TOKEN_ACK",			/* 0x12 */
	"DL_DISCONNECT_REQ",		/* 0x13 */
	"DL_DISCONNECT_IND",		/* 0x14 */
	"DL_SUBS_UNBIND_REQ",		/* 0x15 */
	"DL_LIARLIARPANTSONFIRE",	/* 0x16 */
	"DL_RESET_REQ",			/* 0x17 */
	"DL_RESET_IND",			/* 0x18 */
	"DL_RESET_RES",			/* 0x19 */
	"DL_RESET_CON",			/* 0x1a */
	"DL_SUBS_BIND_REQ",		/* 0x1b */
	"DL_SUBS_BIND_ACK",		/* 0x1c */
	"DL_ENABMULTI_REQ",		/* 0x1d */
	"DL_DISABMULTI_REQ",		/* 0x1e */
	"DL_PROMISCON_REQ",		/* 0x1f */
	"DL_PROMISCOFF_REQ",		/* 0x20 */
	"DL_DATA_ACK_REQ",		/* 0x21 */
	"DL_DATA_ACK_IND",		/* 0x22 */
	"DL_DATA_ACK_STATUS_IND",	/* 0x23 */
	"DL_REPLY_REQ",			/* 0x24 */
	"DL_REPLY_IND",			/* 0x25 */
	"DL_REPLY_STATUS_IND",		/* 0x26 */
	"DL_REPLY_UPDATE_REQ",		/* 0x27 */
	"DL_REPLY_UPDATE_STATUS_IND",	/* 0x28 */
	"DL_XID_REQ",			/* 0x29 */
	"DL_XID_IND",			/* 0x2a */
	"DL_XID_RES",			/* 0x2b */
	"DL_XID_CON",			/* 0x2c */
	"DL_TEST_REQ",			/* 0x2d */
	"DL_TEST_IND",			/* 0x2e */
	"DL_TEST_RES",			/* 0x2f */
	"DL_TEST_CON",			/* 0x30 */
	"DL_PHYS_ADDR_REQ",		/* 0x31 */
	"DL_PHYS_ADDR_ACK",		/* 0x32 */
	"DL_SET_PHYS_ADDR_REQ",		/* 0x33 */
	"DL_GET_STATISTICS_REQ",	/* 0x34 */
	"DL_GET_STATISTICS_ACK",	/* 0x35 */
};

#define	MAN_DLPI_MAX_PRIM	0x35

static char *dss[] = {			/* DLPI State Strings */
	"DL_UNBOUND",			/* 0x00	*/
	"DL_BIND_PENDING",		/* 0x01	*/
	"DL_UNBIND_PENDING",		/* 0x02	*/
	"DL_IDLE",			/* 0x03	*/
	"DL_UNATTACHED",		/* 0x04	*/
	"DL_ATTACH_PENDING",		/* 0x05	*/
	"DL_DETACH_PENDING",		/* 0x06	*/
	"DL_UDQOS_PENDING",		/* 0x07	*/
	"DL_OUTCON_PENDING",		/* 0x08	*/
	"DL_INCON_PENDING",		/* 0x09	*/
	"DL_CONN_RES_PENDING",		/* 0x0a	*/
	"DL_DATAXFER",			/* 0x0b	*/
	"DL_USER_RESET_PENDING",	/* 0x0c	*/
	"DL_PROV_RESET_PENDING",	/* 0x0d	*/
	"DL_RESET_RES_PENDING",		/* 0x0e	*/
	"DL_DISCON8_PENDING",		/* 0x0f	*/
	"DL_DISCON9_PENDING",		/* 0x10	*/
	"DL_DISCON11_PENDING",		/* 0x11	*/
	"DL_DISCON12_PENDING",		/* 0x12	*/
	"DL_DISCON13_PENDING",		/* 0x13	*/
	"DL_SUBS_BIND_PND",		/* 0x14	*/
	"DL_SUBS_UNBIND_PND",		/* 0x15	*/
};

static const char *lss[] = {
	"UNKNOWN",	/* 0x0 */
	"INIT",		/* 0x1 */
	"GOOD",		/* 0x2 */
	"STALE",	/* 0x3 */
	"FAIL",		/* 0x4 */
};

static char *_mw_type[] = {
	"OPEN_CTL",		/* 0x0 */
	"CLOSE_CTL",		/* 0x1 */
	"SWITCH",		/* 0x2 */
	"PATH_UPDATE",		/* 0x3 */
	"CLOSE",		/* 0x4 */
	"CLOSE_STREAM",	/* 0x5 */
	"DRATTACH",		/* 0x6 */
	"DRDETACH",		/* 0x7 */
	"STOP",			/* 0x8 */
	"DRSWITCH",		/* 0x9 */
	"KSTAT_UPDATE"		/* 0xA */
};

uint32_t		man_debug = MAN_WARN;

#define	man_kzalloc(a, b)	man_dbg_kzalloc(__LINE__, a, b)
#define	man_kfree(a, b)		man_dbg_kfree(__LINE__, a, b)
void	*man_dbg_kzalloc(int line, size_t size, int kmflags);
void	man_dbg_kfree(int line, void *buf, size_t size);

#else	/* DEBUG */

uint32_t		man_debug = 0;
/*
 * Set manstr_t dlpistate (upper half of multiplexor)
 */
#define	SETSTATE(msp, state) msp->ms_dlpistate = (state);
/*
 * Set man_dest_t dlpistate (lower half of multiplexor)
 */
#define	D_SETSTATE(mdp, state) mdp->md_dlpistate = (state);

#define	man_kzalloc(a, b)	kmem_zalloc(a, b)
#define	man_kfree(a, b)		kmem_free(a, b)

#endif	/* DEBUG */

#define	DL_PRIM(mp)	(((union DL_primitives *)(mp)->b_rptr)->dl_primitive)
#define	DL_PROMISCON_TYPE(mp)	\
		(((union DL_primitives *)(mp)->b_rptr)->promiscon_req.dl_level)
#define	IOC_CMD(mp)	(((struct iocblk *)(mp)->b_rptr)->ioc_cmd)

/*
 * Start of kstat-related declarations
 */
#define	MK_NOT_COUNTER		(1<<0)	/* is it a counter? */
#define	MK_ERROR		(1<<2)	/* for error statistics */
#define	MK_NOT_PHYSICAL		(1<<3)	/* no matching physical stat */

typedef struct man_kstat_info_s {
	char		*mk_name;	/* e.g. align_errors */
	char		*mk_physname;	/* e.g. framing (NULL for same) */
	char		*mk_physalias;	/* e.g. framing (NULL for same) */
	uchar_t		mk_type;	/* e.g. KSTAT_DATA_UINT32 */
	int		mk_flags;
} man_kstat_info_t;

/*
 * Master declaration macro, note that it uses token pasting
 */
#define	MK_DECLARE(name, pname, palias, bits, flags) \
	{ name,		pname,	palias,	KSTAT_DATA_UINT ## bits, flags }

/*
 * Obsolete forms don't have the _sinceswitch forms, they are all errors
 */
#define	MK_OBSOLETE32(name, alias) MK_DECLARE(alias, name, alias, 32, MK_ERROR)
#define	MK_OBSOLETE64(name, alias) MK_DECLARE(alias, name, alias, 64, MK_ERROR)

/*
 * The only non-counters don't have any other aliases
 */
#define	MK_NOTCOUNTER32(name) MK_DECLARE(name, name, NULL, 32, MK_NOT_COUNTER)
#define	MK_NOTCOUNTER64(name) MK_DECLARE(name, name, NULL, 64, MK_NOT_COUNTER)

/*
 * Normal counter forms
 */
#define	MK_DECLARE32(name, alias) \
	MK_DECLARE(name, name, alias, 32, 0)
#define	MK_DECLARE64(name, alias) \
	MK_DECLARE(name, name, alias, 64, 0)

/*
 * Error counters need special MK_ERROR flag only for the non-AP form
 */
#define	MK_ERROR32(name, alias) \
	MK_DECLARE(name, name, alias, 32, MK_ERROR)
#define	MK_ERROR64(name, alias) \
	MK_DECLARE(name, name, alias, 64, MK_ERROR)

/*
 * These AP-specific stats are not backed by physical statistics
 */
#define	MK_NOTPHYS32(name) MK_DECLARE(name, NULL, NULL, 32, MK_NOT_PHYSICAL)
#define	MK_NOTPHYS64(name) MK_DECLARE(name, NULL, NULL, 64, MK_NOT_PHYSICAL)

/*
 * START of the actual man_kstat_info declaration using above macros
 */
static man_kstat_info_t man_kstat_info[] = {
	/*
	 * Link Input/Output stats
	 */
	MK_DECLARE32("ipackets", NULL),
	MK_ERROR32("ierrors", NULL),
	MK_DECLARE32("opackets", NULL),
	MK_ERROR32("oerrors", NULL),
	MK_ERROR32("collisions", NULL),
	MK_NOTCOUNTER64("ifspeed"),
	/*
	 * These are new MIB-II stats, per PSARC 1997/198
	 */
	MK_DECLARE32("rbytes", NULL),
	MK_DECLARE32("obytes", NULL),
	MK_DECLARE32("multircv", NULL),
	MK_DECLARE32("multixmt", NULL),
	MK_DECLARE32("brdcstrcv", NULL),
	MK_DECLARE32("brdcstxmt", NULL),
	/*
	 * Error values
	 */
	MK_ERROR32("norcvbuf", NULL),
	MK_ERROR32("noxmtbuf", NULL),
	MK_ERROR32("unknowns", NULL),
	/*
	 * These are the 64-bit values, they fallback to 32-bit values
	 */
	MK_DECLARE64("ipackets64", "ipackets"),
	MK_DECLARE64("opackets64", "opackets"),
	MK_DECLARE64("rbytes64", "rbytes"),
	MK_DECLARE64("obytes64", "obytes"),

	/* New AP switching statistics */
	MK_NOTPHYS64("man_switches"),
	MK_NOTPHYS64("man_link_fails"),
	MK_NOTPHYS64("man_link_stales"),
	MK_NOTPHYS64("man_icmpv4_probes"),
	MK_NOTPHYS64("man_icmpv6_probes"),

	MK_ERROR32("align_errors", "framing"),
	MK_ERROR32("fcs_errors", "crc"),
	MK_ERROR32("first_collisions", NULL),
	MK_ERROR32("multi_collisions", NULL),
	MK_ERROR32("sqe_errors", "sqe"),

	MK_ERROR32("tx_late_collisions", NULL),
	MK_ERROR32("ex_collisions", "excollisions"),
	MK_ERROR32("macxmt_errors", NULL),
	MK_ERROR32("carrier_errors", "nocarrier"),
	MK_ERROR32("toolong_errors", "buff"),
	MK_ERROR32("macrcv_errors", NULL),

	MK_OBSOLETE32("framing", "align_errors"),
	MK_OBSOLETE32("crc", "fcs_errors"),
	MK_OBSOLETE32("sqe", "sqe_errors"),
	MK_OBSOLETE32("excollisions", "ex_collisions"),
	MK_OBSOLETE32("nocarrier", "carrier_errors"),
	MK_OBSOLETE32("buff", "toolong_errors"),
};

#define	MAN_NUMSTATS (sizeof (man_kstat_info) / sizeof (man_kstat_info_t))

/*
 * Miscellaneous ethernet stuff.
 *
 * MANs DL_INFO_ACK template.
 */
static	dl_info_ack_t man_infoack = {
	DL_INFO_ACK,				/* dl_primitive */
	ETHERMTU,				/* dl_max_sdu */
	0,					/* dl_min_sdu */
	MAN_ADDRL,				/* dl_addr_length */
	DL_ETHER,				/* dl_mac_type */
	0,					/* dl_reserved */
	0,					/* dl_current_state */
	-2,					/* dl_sap_length */
	DL_CLDLS,				/* dl_service_mode */
	0,					/* dl_qos_length */
	0,					/* dl_qos_offset */
	0,					/* dl_range_length */
	0,					/* dl_range_offset */
	DL_STYLE2,				/* dl_provider_style */
	sizeof (dl_info_ack_t),			/* dl_addr_offset */
	DL_VERSION_2,				/* dl_version */
	ETHERADDRL,				/* dl_brdcst_addr_length */
	sizeof (dl_info_ack_t) + MAN_ADDRL,	/* dl_brdcst_addr_offset */
	0					/* dl_growth */
};

/*
 * Ethernet broadcast address definition.
 */
static	struct ether_addr	etherbroadcast = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

static struct ether_addr zero_ether_addr = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/*
 * Set via MAN_SET_SC_IPADDRS ioctl.
 */
man_sc_ipaddrs_t	man_sc_ipaddrs = { 0xffffffffU, 0xffffffffU };

/*
 * Set via MAN_SET_SC_IP6ADDRS ioctl.
 */
man_sc_ip6addrs_t	man_sc_ip6addrs = { 0, 0, 0, 0, 0, 0, 0, 0 };

/*
 * IP & ICMP constants
 */
#ifndef	ETHERTYPE_IPV6
#define	ETHERTYPE_IPV6 0x86DD
#endif

/*
 * Function prototypes.
 *
 * Upper multiplexor functions.
 */
static int	man_attach(dev_info_t *, ddi_attach_cmd_t);
static int	man_detach(dev_info_t *, ddi_detach_cmd_t);
static int	man_info(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int	man_open(register queue_t *, dev_t *, int, int, cred_t *);
static int	man_configure(queue_t *);
static int	man_deconfigure(void);
static int	man_init_dests(man_t *, manstr_t *);
static void	man_start_dest(man_dest_t *, manstr_t *, man_pg_t *);
static void	man_set_optimized_dest(manstr_t *);
static int	man_close(queue_t *);
static void	man_cancel_timers(man_adest_t *);
static int	man_uwput(queue_t *, mblk_t *);
static int	man_start(queue_t *, mblk_t *, eaddr_t *);
static void	man_ioctl(queue_t *, mblk_t *);
static void	man_set_linkcheck_time(queue_t *, mblk_t *);
static void	man_setpath(queue_t *, mblk_t *);
static void	man_geteaddr(queue_t *, mblk_t *);
static void	man_set_sc_ipaddrs(queue_t *, mblk_t *);
static void	man_set_sc_ip6addrs(queue_t *, mblk_t *);
static int	man_get_our_etheraddr(eaddr_t *eap);
static void	man_nd_getset(queue_t *, mblk_t *);
static void	man_dl_ioc_hdr_info(queue_t *, mblk_t *);
static int	man_uwsrv(queue_t *);
static int	man_proto(queue_t *, mblk_t *);
static int	man_udreq(queue_t *, mblk_t *);
static void	man_areq(queue_t *, mblk_t *);
static mblk_t	*man_alloc_physreq_mp(eaddr_t *);
static void	man_dreq(queue_t *, mblk_t *);
static void	man_dodetach(manstr_t *, man_work_t *);
static void	man_dl_clean(mblk_t **);
static void	man_breq(queue_t *, mblk_t *);
static void	man_ubreq(queue_t *, mblk_t *);
static void	man_ireq(queue_t *, mblk_t *);
static void	man_ponreq(queue_t *, mblk_t *);
static void	man_poffreq(queue_t *, mblk_t *);
static void	man_emreq(queue_t *, mblk_t *);
static void	man_dmreq(queue_t *, mblk_t *);
static void	man_pareq(queue_t *, mblk_t *);
static void	man_spareq(queue_t *, mblk_t *);
static int	man_dlpi(manstr_t *, mblk_t *);
static int	man_dlioc(manstr_t *, mblk_t *);
static int	man_dl_catch(mblk_t **, mblk_t *);
static void	man_dl_release(mblk_t **, mblk_t *);
static int	man_match_proto(mblk_t *, mblk_t *);
static int	man_open_ctl();
static void	man_close_ctl();
/*
 * upper/lower multiplexor functions.
 */
static int	man_dlpi_senddown(manstr_t *, mblk_t *);
static int	man_start_lower(man_dest_t *, mblk_t *, queue_t *, int caller);
static int	man_lrput(queue_t *, mblk_t *);
/*
 * Lower multiplexor functions.
 */
static int	man_lwsrv(queue_t *);
static int	man_lrsrv(queue_t *);
static void	man_dlpi_replay(man_dest_t *, mblk_t *);
static int	man_dlioc_replay(man_dest_t *);
/*
 * Link failover routines.
 */
static int	man_gettimer(int, man_dest_t *);
static void	man_linkcheck_timer(void *);
static int	man_needs_linkcheck(man_dest_t *);
static int	man_do_autoswitch(man_dest_t *);
static int	man_autoswitch(man_pg_t *, man_dev_t *, man_work_t *);
static int	man_prep_dests_for_switch(man_pg_t *, man_dest_t **, int *);
static int	man_str_uses_pg(manstr_t *, man_pg_t *);
static void	man_do_icmp_bcast(man_dest_t *, t_uscalar_t);
static mblk_t	*man_alloc_udreq(int, man_dladdr_t *);
static mblk_t	*man_pinger(t_uscalar_t);
/*
 * Functions normally executing outside of the STREAMs perimeter.
 */
/*
 * Functions supporting/processing work requests.
 */
static void	man_bwork(void);
static void	man_iwork(void);		/* inside perimeter */
void		man_work_add(man_workq_t *, man_work_t *);
man_work_t	*man_work_alloc(int, int);
void		man_work_free(man_work_t *);
/*
 * Functions implementing/supporting failover.
 *
 * Executed inside perimeter.
 */
static int	man_do_dr_attach(man_work_t *);
static int	man_do_dr_switch(man_work_t *);
static void	man_do_dr_detach(man_work_t *);
static int	man_iswitch(man_work_t *);
static void	man_ifail_dest(man_dest_t *);
static man_dest_t *man_switch_match(man_dest_t *, int, void *);
static void	man_add_dests(man_pg_t *);
static void	man_reset_dlpi(void *);
static mblk_t	*man_dup_mplist(mblk_t *);
static mblk_t	*man_alloc_ubreq_dreq();
/*
 * Executed outside perimeter (us man_lock for synchronization).
 */
static void	man_bclose(man_adest_t *);
static void	man_bswitch(man_adest_t *, man_work_t *);
static int	man_plumb(man_dest_t *);
static void	man_unplumb(man_dest_t *);
static void	man_plink(queue_t *, mblk_t *);
static void	man_unplink(queue_t *, mblk_t *);
static void	man_linkrec_insert(man_linkrec_t *);
static queue_t	*man_linkrec_find(int);
/*
 * Functions supporting pathgroups
 */
int	man_pg_cmd(mi_path_t *, man_work_t *);
static int	man_pg_assign(man_pg_t **, mi_path_t *, int);
static int	man_pg_create(man_pg_t **, man_pg_t **, mi_path_t *);
static int	man_pg_unassign(man_pg_t **, mi_path_t *);
static int	man_pg_activate(man_t *, mi_path_t *, man_work_t *);
static int	man_pg_read(man_pg_t *, mi_path_t *);
static man_pg_t	*man_find_path_by_dev(man_pg_t *, man_dev_t *, man_path_t **);
static man_pg_t	*man_find_pg_by_id(man_pg_t *, int);
static man_path_t	*man_find_path_by_ppa(man_path_t *, int);
static man_path_t	*man_find_active_path(man_path_t *);
static man_path_t	*man_find_alternate_path(man_path_t *);
static void	man_path_remove(man_path_t **, man_path_t *);
static void	man_path_insert(man_path_t **, man_path_t *);
static void	man_path_merge(man_path_t **, man_path_t *);
static int	man_path_kstat_init(man_path_t *);
static void	man_path_kstat_uninit(man_path_t *);
/*
 * Functions supporting kstat reporting.
 */
static int	man_kstat_update(kstat_t *, int);
static void	man_do_kstats(man_work_t *);
static void	man_update_path_kstats(man_t *);
static void 	man_update_dev_kstats(kstat_named_t *, man_path_t *);
static void	man_sum_dests_kstats(kstat_named_t *, man_pg_t *);
static void	man_kstat_named_init(kstat_named_t *, int);
static int	man_kstat_byname(kstat_t *, char *, kstat_named_t *);
static void	man_sum_kstats(kstat_named_t *, kstat_t *, kstat_named_t *);
/*
 * Functions supporting ndd.
 */
static int	man_param_register(param_t *, int);
static int	man_pathgroups_report(queue_t *, mblk_t *, caddr_t, cred_t *);
static void	man_preport(man_path_t *, mblk_t *);
static int	man_set_active_path(queue_t *, mblk_t *, char *, caddr_t,
			cred_t *);
static int	man_get_hostinfo(queue_t *, mblk_t *, caddr_t, cred_t *);
static char	*man_inet_ntoa(in_addr_t);
static int	man_param_get(queue_t *, mblk_t *, caddr_t, cred_t *);
static int	man_param_set(queue_t *, mblk_t *, char *, caddr_t, cred_t *);
static  void    man_param_cleanup(void);
static  void    man_nd_free(caddr_t *nd_pparam);
/*
 * MAN SSC/Domain specific externs.
 */
extern int	man_get_iosram(manc_t *);
extern int	man_domain_configure(void);
extern int	man_domain_deconfigure(void);
extern int	man_dossc_switch(uint32_t);
extern int	man_is_on_domain;

/*
 * Driver Globals protected by inner perimeter.
 */
static manstr_t	*man_strup = NULL;	/* list of MAN STREAMS */
static caddr_t	man_ndlist = NULL;	/* head of ndd var list */
void		*man_softstate = NULL;

/*
 * Driver globals protected by man_lock.
 */
kmutex_t		man_lock;		/* lock protecting vars below */
static kthread_id_t	man_bwork_id = NULL;	/* background thread ID */
man_workq_t		*man_bwork_q;		/* bgthread work q */
man_workq_t		*man_iwork_q;		/* inner perim (uwsrv) work q */
static man_linkrec_t	*man_linkrec_head = NULL;	/* list of linkblks */
ldi_handle_t		man_ctl_lh = NULL;	/* MAN control handle */
queue_t			*man_ctl_wq = NULL;	/* MAN control rq */
static int		man_config_state = MAN_UNCONFIGURED;
static int		man_config_error = ENODEV;

/*
 * These parameters are accessed via ndd to report the link configuration
 * for the MAN driver. They can also be used to force configuration changes.
 */
#define	MAN_NOTUSR	0x0f000000

/* ------------------------------------------------------------------------- */

static  param_t	man_param_arr[] = {
	/* min		max		value		name */
	{  0,		0xFFFF,		0,		"man_debug_level"},
};

#define	MAN_NDD_GETABLE	1
#define	MAN_NDD_SETABLE	2

static  uint32_t	man_param_display[] = {
/* DISPLAY */
MAN_NDD_SETABLE,	/* man_debug_level */
};

/*
 * STREAMs information.
 */
static struct module_info man_m_info = {
	MAN_IDNUM,			/* mi_idnum */
	MAN_IDNAME,			/* mi_idname */
	MAN_MINPSZ,			/* mi_minpsz */
	MAN_MAXPSZ,			/* mi_maxpsz */
	MAN_HIWAT,			/* mi_hiwat */
	MAN_LOWAT			/* mi_lowat */
};

/*
 * Upper read queue does not do anything.
 */
static struct qinit man_urinit = {
	NULL,				/* qi_putp */
	NULL,				/* qi_srvp */
	man_open,			/* qi_qopen */
	man_close,			/* qi_qclose */
	NULL,				/* qi_qadmin */
	&man_m_info,			/* qi_minfo */
	NULL				/* qi_mstat */
};

static struct qinit man_lrinit = {
	man_lrput,			/* qi_putp */
	man_lrsrv,			/* qi_srvp */
	man_open,			/* qi_qopen */
	man_close,			/* qi_qclose */
	NULL,				/* qi_qadmin */
	&man_m_info,			/* qi_minfo */
	NULL				/* qi_mstat */
};

static struct qinit man_uwinit = {
	man_uwput,			/* qi_putp */
	man_uwsrv,			/* qi_srvp */
	man_open,			/* qi_qopen */
	man_close,			/* qi_qclose */
	NULL,				/* qi_qadmin */
	&man_m_info,			/* qi_minfo */
	NULL				/* qi_mstat */
};

static struct qinit man_lwinit = {
	NULL,				/* qi_putp */
	man_lwsrv,			/* qi_srvp */
	man_open,			/* qi_qopen */
	man_close,			/* qi_qclose */
	NULL,				/* qi_qadmin */
	&man_m_info,			/* qi_minfo */
	NULL				/* qi_mstat */
};

static struct streamtab man_maninfo = {
	&man_urinit,			/* st_rdinit */
	&man_uwinit,			/* st_wrinit */
	&man_lrinit,			/* st_muxrinit */
	&man_lwinit			/* st_muxwrinit */
};


/*
 * Module linkage information for the kernel.
 *
 * Locking Theory:
 * 	D_MTPERMOD -	Only an inner perimeter: All routines single
 * 			threaded (except put, see below).
 *	D_MTPUTSHARED -	Put routines enter inner perimeter shared (not
 *			exclusive) for concurrency/performance reasons.
 *
 *	Anyone who needs exclusive outer perimeter permission (changing
 *	global data structures) does so via qwriter() calls. The
 *	background thread does all its work outside of perimeter and
 *	submits work via qtimeout() when data structures need to be
 *	modified.
 */

#define	MAN_MDEV_FLAGS	(D_MP|D_MTPERMOD|D_MTPUTSHARED)

DDI_DEFINE_STREAM_OPS(man_ops, nulldev, nulldev, man_attach,
    man_detach, nodev, man_info, MAN_MDEV_FLAGS, &man_maninfo,
    ddi_quiesce_not_supported);

extern int nodev(), nulldev();

static struct modldrv modldrv = {
	&mod_driverops, 	/* Module type.  This one is a pseudo driver */
	"MAN MetaDriver",
	&man_ops,		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *) &modldrv,
	NULL
};


/* Virtual Driver loader entry points */

int
_init(void)
{
	int		status = DDI_FAILURE;

	MAN_DBG(MAN_INIT, ("_init:"));

	status = mod_install(&modlinkage);
	if (status != 0) {
		cmn_err(CE_WARN, "man_init: mod_install failed"
		    " error = %d", status);
		return (status);
	}

	status = ddi_soft_state_init(&man_softstate, sizeof (man_t), 4);
	if (status != 0) {
		cmn_err(CE_WARN, "man_init: ddi_soft_state_init failed"
		    " error = %d", status);
		(void) mod_remove(&modlinkage);
		return (status);
	}

	man_bwork_q = man_kzalloc(sizeof (man_workq_t), KM_SLEEP);
	man_iwork_q = man_kzalloc(sizeof (man_workq_t), KM_SLEEP);

	mutex_init(&man_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&man_bwork_q->q_cv, NULL, CV_DRIVER, NULL);
	cv_init(&man_iwork_q->q_cv, NULL, CV_DRIVER, NULL);

	return (0);
}

/*
 * _info is called by modinfo().
 */
int
_info(struct modinfo *modinfop)
{
	int	status;

	MAN_DBG(MAN_INIT, ("_info:"));

	status = mod_info(&modlinkage, modinfop);

	MAN_DBG(MAN_INIT, ("_info: returns %d", status));

	return (status);
}

/*
 * _fini called by modunload() just before driver is unloaded from memory.
 */
int
_fini(void)
{
	int status = 0;

	MAN_DBG(MAN_INIT, ("_fini:"));


	/*
	 * The only upper stream left should be man_ctl_lh. Note that
	 * man_close (upper stream) is synchronous (i.e. it waits for
	 * all STREAMS framework associated with the upper stream to be
	 * torn down). This guarantees that man_ctl_lh will never become
	 * NULL until noone is around to notice. This assumption is made
	 * in a few places like man_plumb, man_unplumb, etc.
	 */
	if (man_strup && (man_strup->ms_next != NULL))
		return (EBUSY);

	/*
	 * Deconfigure the driver.
	 */
	status = man_deconfigure();
	if (status)
		goto exit;

	/*
	 * need to detach every instance of the driver
	 */
	status = mod_remove(&modlinkage);
	if (status != 0)
		goto exit;

	ddi_soft_state_fini(&man_softstate);

	/*
	 * Free up locks.
	 */
	mutex_destroy(&man_lock);
	cv_destroy(&man_bwork_q->q_cv);
	cv_destroy(&man_iwork_q->q_cv);

	man_kfree(man_bwork_q, sizeof (man_workq_t));
	man_kfree(man_iwork_q, sizeof (man_workq_t));

exit:

	MAN_DBG(MAN_INIT, ("_fini: returns %d", status));

	return (status);
}

/*
 * Deconfigure the MAN driver.
 */
static int
man_deconfigure()
{
	man_work_t	*wp;
	int		status = 0;

	MAN_DBG(MAN_CONFIG, ("man_deconfigure:\n"));

	mutex_enter(&man_lock);

	if (man_is_on_domain) {
		status = man_domain_deconfigure();
		if (status != 0)
			goto exit;
	}

	man_param_cleanup();	/* Free up NDD resources */

	/*
	 * I may have to handle straggling work requests. Just qwait?
	 * or cvwait? Called from _fini - TBD
	 */
	ASSERT(man_bwork_q->q_work == NULL);
	ASSERT(man_iwork_q->q_work == NULL);

	MAN_DBG(MAN_CONFIG, ("man_deconfigure: submitting CLOSE_CTL\n"));

	if (man_ctl_lh != NULL) {
		wp = man_work_alloc(MAN_WORK_CLOSE_CTL, KM_SLEEP);
		wp->mw_flags = MAN_WFLAGS_CVWAITER;
		man_work_add(man_bwork_q, wp);

		while (!(wp->mw_flags & MAN_WFLAGS_DONE)) {
			cv_wait(&wp->mw_cv, &man_lock);
		}
		man_work_free(wp);
	}

	MAN_DBG(MAN_CONFIG, ("man_deconfigure: submitting STOP\n"));
	if (man_bwork_id != NULL) {

		wp = man_work_alloc(MAN_WORK_STOP, KM_SLEEP);
		wp->mw_flags = MAN_WFLAGS_CVWAITER;
		man_work_add(man_bwork_q, wp);

		while (!(wp->mw_flags & MAN_WFLAGS_DONE)) {
			cv_wait(&wp->mw_cv, &man_lock);
		}
		man_work_free(wp);
	}
	man_config_state = MAN_UNCONFIGURED;

exit:
	mutex_exit(&man_lock);

	MAN_DBG(MAN_CONFIG, ("man_deconfigure: returns %d\n", status));

	return (status);
}

/*
 * man_attach - allocate resources and attach an instance of the MAN driver
 * The <man>.conf file controls how many instances of the MAN driver are
 * available.
 *
 *	dip - devinfo of node
 * 	cmd - one of DDI_ATTACH | DDI_RESUME
 *
 *	returns	- success - DDI_SUCCESS
 *		- failure - DDI_FAILURE
 */
static int
man_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	man_t		*manp;		/* per instance data */
	uchar_t		flag = KSTAT_FLAG_WRITABLE; /* support netstat -kc */
	kstat_t		*ksp;
	int		minor_node_created = 0;
	int		instance;
	eaddr_t		man_eaddr;

	MAN_DBG(MAN_INIT, ("man_attach: \n"));

	if (cmd != DDI_ATTACH) {
		MAN_DBG(MAN_INIT, ("man_attach: bad command %d\n", cmd));
		return (DDI_FAILURE);
	}

	if (man_get_our_etheraddr(&man_eaddr))
		return (DDI_FAILURE);

	instance = ddi_get_instance(dip);

	/*
	 * we assume that instance is always equal to zero.
	 * and there will always only be one instance.
	 * this is done because when dman opens itself via DMAN_INT_PATH,
	 * the path assumes that the instance number is zero.
	 * if we ever need to support multiple instances of the dman
	 * driver or non-zero instances, this will have to change.
	 */
	ASSERT(instance == 0);

	/*
	 * Allocate per device info pointer and link in to global list of
	 * MAN devices.
	 */
	if ((ddi_soft_state_zalloc(man_softstate, instance) != DDI_SUCCESS) ||
	    ((manp = ddi_get_soft_state(man_softstate, instance)) == NULL)) {
		cmn_err(CE_WARN, "man_attach: cannot zalloc soft state!");
		return (DDI_FAILURE);
	}

	ddi_set_driver_private(dip, manp);
	manp->man_dip = dip;
	manp->man_meta_major = ddi_driver_major(dip);
	manp->man_meta_ppa = instance;

	/*
	 * Set ethernet address. Note that this address is duplicated
	 * at md_src_eaddr.
	 */
	ether_copy(&man_eaddr, &manp->man_eaddr);
	manp->man_eaddr_v = 1;

	MAN_DBG(MAN_INIT, ("man_attach: set ether to %s",
	    ether_sprintf(&manp->man_eaddr)));

	/*
	 * Initialize failover-related fields (timers and such),
	 * taking values from properties if present.
	 */
	manp->man_init_time = ddi_getprop(DDI_DEV_T_ANY, dip, 0,
	    "init_time", MAN_INIT_TIME);

	manp->man_linkcheck_time = ddi_getprop(DDI_DEV_T_ANY, dip, 0,
	    "linkcheck_time", MAN_LINKCHECK_TIME);

	manp->man_linkstale_time = ddi_getprop(DDI_DEV_T_ANY, dip, 0,
	    "man_linkstale_time", MAN_LINKSTALE_TIME);

	manp->man_linkstale_retries = ddi_getprop(DDI_DEV_T_ANY, dip, 0,
	    "man_linkstale_retries", MAN_LINKSTALE_RETRIES);

	manp->man_dr_delay = ddi_getprop(DDI_DEV_T_ANY, dip, 0,
	    "man_dr_delay", MAN_DR_DELAY);

	manp->man_dr_retries = ddi_getprop(DDI_DEV_T_ANY, dip, 0,
	    "man_dr_retries", MAN_DR_RETRIES);

	manp->man_kstat_waittime = ddi_getprop(DDI_DEV_T_ANY, dip, 0,
	    "man_kstat_waittime", MAN_KSTAT_WAITTIME);

	manp->man_dlpireset_time = ddi_getprop(DDI_DEV_T_ANY, dip, 0,
	    "man_dlpireset_time", MAN_DLPIRESET_TIME);

	if (ddi_create_internal_pathname(dip, MAN_IDNAME, S_IFCHR,
	    ddi_get_instance(dip)) == DDI_SUCCESS) {
		minor_node_created = 1;
	} else {
		cmn_err(CE_WARN, "man_attach: failed for instance %d",
		    ddi_get_instance(dip));
		goto exit;
	}

	if (ddi_create_minor_node(dip, MAN_IDNAME, S_IFCHR,
	    ddi_get_instance(dip), DDI_NT_NET, CLONE_DEV) == DDI_SUCCESS) {
		minor_node_created = 1;
	} else {
		cmn_err(CE_WARN, "man_attach: failed for instance %d",
		    ddi_get_instance(dip));
		goto exit;
	}

	/*
	 * Allocate meta kstat_t for this instance of the driver.
	 * Note that each of man_path_t keeps track of the kstats
	 * for the real devices via mp_last_knp.
	 */
#ifdef	kstat
	flag |= KSTAT_FLAG_PERSISTENT;
#endif
	ksp = kstat_create(MAN_IDNAME, ddi_get_instance(dip), NULL, "net",
	    KSTAT_TYPE_NAMED, MAN_NUMSTATS, flag);

	if (ksp == NULL) {
		cmn_err(CE_WARN, "man_attach(%d): kstat_create failed"
		    " - manp(0x%p)", manp->man_meta_ppa,
		    (void *)manp);
		goto exit;
	}

	man_kstat_named_init(ksp->ks_data, MAN_NUMSTATS);
	ksp->ks_update = man_kstat_update;
	ksp->ks_private = (void *) manp;
	manp->man_ksp = ksp;
	kstat_install(manp->man_ksp);

	ddi_report_dev(dip);

	MAN_DBG(MAN_INIT, ("man_attach(%d) returns DDI_SUCCESS",
	    ddi_get_instance(dip)));

	return (DDI_SUCCESS);

exit:
	if (minor_node_created)
		ddi_remove_minor_node(dip, NULL);
	ddi_set_driver_private(dip, NULL);
	ddi_soft_state_free(man_softstate, instance);

	MAN_DBG(MAN_INIT, ("man_attach(%d) eaddr returns DDI_FAILIRE",
	    ddi_get_instance(dip)));

	return (DDI_FAILURE);

}

static int
man_get_our_etheraddr(eaddr_t *eap)
{
	manc_t	manc;
	int	status = 0;

	if (man_is_on_domain) {
		if (status = man_get_iosram(&manc))
			return (status);
		ether_copy(&manc.manc_dom_eaddr, eap);
	} else {
		(void) localetheraddr((struct ether_addr *)NULL, eap);
	}

	return (status);
}

/*
 * man_detach - detach an instance of a driver
 *
 *	dip - devinfo of node
 * 	cmd - one of DDI_DETACH | DDI_SUSPEND
 *
 *	returns	- success - DDI_SUCCESS
 *		- failure - DDI_FAILURE
 */
static int
man_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	register man_t	*manp;		/* per instance data */
	int		instance;

	MAN_DBG(MAN_INIT, ("man_detach(%d):\n", ddi_get_instance(dip)));

	if (cmd != DDI_DETACH) {
		MAN_DBG(MAN_INIT, ("man_detach: bad command %d\n", cmd));
		return (DDI_FAILURE);
	}

	if (dip == NULL) {
		MAN_DBG(MAN_INIT, ("man_detach: dip == NULL\n"));
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(dip);

	mutex_enter(&man_lock);

	manp = (man_t *)ddi_get_soft_state(man_softstate, instance);
	if (manp == NULL) {
		mutex_exit(&man_lock);

		cmn_err(CE_WARN, "man_detach: unable to get softstate"
		    " for instance = %d, dip = 0x%p!\n", instance,
		    (void *)dip);
		return (DDI_FAILURE);
	}

	if (manp->man_refcnt != 0) {
		mutex_exit(&man_lock);

		cmn_err(CE_WARN, "man_detach: %s%d refcnt %d", MAN_IDNAME,
		    instance, manp->man_refcnt);
		MAN_DBGCALL(MAN_INIT, man_print_man(manp));

		return (DDI_FAILURE);
	}

	ddi_remove_minor_node(dip, NULL);

	mutex_exit(&man_lock);

	kstat_delete(manp->man_ksp);
	ddi_soft_state_free(man_softstate, instance);
	ddi_set_driver_private(dip, NULL);

	MAN_DBG(MAN_INIT, ("man_detach returns DDI_SUCCESS"));

	return (DDI_SUCCESS);
}

/*
 * man_info:
 *	As a standard DLPI style-2, man_info() should always return
 *	DDI_FAILURE.
 *
 *	However, man_open() has special treatment for a direct open
 *	via kstr_open() without going through the CLONE driver.
 *	To make this special kstr_open() work, we need to map
 *	minor of 0 to instance 0.
 */
/*ARGSUSED*/
static int
man_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	minor_t minor;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		break;

	case DDI_INFO_DEVT2INSTANCE:
		minor = getminor((dev_t)arg);
		if (minor == 0) {
			*result = (void *)(uintptr_t)minor;
			return (DDI_SUCCESS);
		}
		break;
	default:
		break;
	}
	return (DDI_FAILURE);
}

/* Standard Device Driver entry points */

/*
 * man_open - open the device
 *
 *	rq - upper read queue of the stream
 *	devp - pointer to a device number
 *	flag - information passed from the user program open(2) system call
 *	sflag - stream flags
 *	credp - pointer to the cred(9S) user credential structure
 *
 *	returns	- success - 0
 *		- failure - errno value for failure
 */
/*ARGSUSED*/
static int
man_open(queue_t *rq, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	int			minordev = -1;
	manstr_t		*msp;
	manstr_t		*tsp;
	manstr_t		**prevmsp;
	int			status = 0;

	MAN_DBG(MAN_OCLOSE, ("man_open: rq(0x%p) sflag(0x%x)\n",
	    (void *)rq, sflag));

	ASSERT(rq);
	ASSERT(sflag != MODOPEN);

	/*
	 * reopen; q_ptr set to msp at open completion.
	 */
	if (rq->q_ptr) {
		return (0);
	}

	/*
	 * Allocate and initialize manstr_t for this device.
	 */
	msp = man_kzalloc(sizeof (manstr_t), KM_SLEEP);
	SETSTATE(msp, DL_UNATTACHED);
	msp->ms_meta_ppa = -1;
	msp->ms_rq = rq;
	rq->q_ptr = WR(rq)->q_ptr = msp;

	/*
	 * Get the MAN driver configured on 1st open.  Note that the only way
	 * we get sflag != CLONEOPEN is via the call in man_plumbctl().  All
	 * CLONEOPEN calls to man_open will be via the file system
	 * device node /dev/man, a pseudo clone device.
	 */

	qprocson(rq);

	if (sflag == CLONEOPEN && man_config_state != MAN_CONFIGURED) {
		/*
		 * First open calls man_configure. Everyone qwaits until
		 * we get it open. See man_open_ctl() comments for mutex
		 * lock/synchronization info.
		 */

		mutex_enter(&man_lock);

		if (man_config_state == MAN_UNCONFIGURED) {
			man_config_state = MAN_CONFIGURING;
			mutex_exit(&man_lock);
			status = man_configure(rq);
			if (status != 0)
				goto exit;
		} else {
			while (man_config_state == MAN_CONFIGURING) {

				mutex_exit(&man_lock);
				status = qwait_sig(rq);

				if (status == 0) {
					status = EINTR;
					goto exit;
				}

				mutex_enter(&man_lock);
			}
			mutex_exit(&man_lock);

			if (man_config_error) {
				status = man_config_error;
				goto exit;
			}
		}
	}

	/*
	 * Determine minor device number. man_open serialized by
	 * D_MTPERMOD.
	 */
	prevmsp = &man_strup;
	if (sflag == CLONEOPEN) {

		minordev = 0;
		for (; (tsp = *prevmsp) != NULL; prevmsp = &tsp->ms_next) {
			if (minordev < tsp->ms_minor)
				break;
			minordev++;
		}
		*devp = makedevice(getmajor(*devp), minordev);

	} else {
		/*
		 * Should only get here from man_plumbctl().
		 */
		/*LINTED E_ASSIGN_UINT_TO_SIGNED_INT*/
		minordev = getminor(*devp);

		/*
		 * No need to protect this here as all opens are
		 * qwaiting, and the bgthread (who is doing this open)
		 * is the only one who mucks with this variable.
		 */
		man_ctl_wq = WR(rq);

		ASSERT(minordev == 0);	/* TBD delete this */
	}

	msp->ms_meta_maj = getmajor(*devp);
	msp->ms_minor = minordev;
	if (minordev == 0)
		msp->ms_flags = MAN_SFLAG_CONTROL;

	/*
	 * Link new entry into global list of active entries.
	 */
	msp->ms_next = *prevmsp;
	*prevmsp = msp;


	/*
	 * Disable automatic enabling of our write service procedure.
	 * We control this explicitly.
	 */
	noenable(WR(rq));

exit:
	MAN_DBG(MAN_OCLOSE, ("man_open: exit rq(0x%p) minor %d errno %d\n",
	    (void *)rq, minordev, status));

	/*
	 * Clean up on error.
	 */
	if (status) {
		qprocsoff(rq);
		rq->q_ptr = WR(rq)->q_ptr = NULL;
		man_kfree((char *)msp, sizeof (manstr_t));
	} else
		(void) qassociate(rq, -1);

	return (status);
}

/*
 * Get the driver configured.  Called from first man_open with exclusive
 * inner perimeter.
 */
static int
man_configure(queue_t *rq)
{
	man_work_t	*wp;
	int		status = 0;

	MAN_DBG(MAN_CONFIG, ("man_configure:"));

	/*
	 * Initialize NDD parameters.
	 */
	if (!man_ndlist &&
	    !man_param_register(man_param_arr, A_CNT(man_param_arr))) {
		cmn_err(CE_WARN, "man_configure: man_param_register failed!");
		man_config_error = ENOMEM;
		goto exit;
	}

	mutex_enter(&man_lock);

	/*
	 * Start up background thread.
	 */
	if (man_bwork_id == NULL)
		man_bwork_id = thread_create(NULL, 2 * DEFAULTSTKSZ,
		    man_bwork, NULL, 0, &p0, TS_RUN, minclsyspri);

	/*
	 * Submit work to get control stream opened. Qwait until its
	 * done. See man_open_ctl for mutex lock/synchronization info.
	 */

	if (man_ctl_lh == NULL) {
		wp = man_work_alloc(MAN_WORK_OPEN_CTL, KM_SLEEP);
		wp->mw_flags |= MAN_WFLAGS_QWAITER;
		wp->mw_q = WR(rq);

		/*
		 * Submit work and wait. When man_open_ctl exits
		 * man_open, it will cause qwait below to return.
		 */
		man_work_add(man_bwork_q, wp);
		while (!(wp->mw_flags & MAN_WFLAGS_DONE)) {
			mutex_exit(&man_lock);
			qwait(rq);
			mutex_enter(&man_lock);
		}
		status = wp->mw_status;
		man_work_free(wp);

	}
	mutex_exit(&man_lock);

	/*
	 * If on domain, setup IOSRAM and build the pathgroups
	 * automatically.
	 */
	if ((status == 0) && man_is_on_domain)
		status = man_domain_configure();

exit:
	mutex_enter(&man_lock);

	man_config_error = status;
	if (status != 0)
		man_config_state = MAN_UNCONFIGURED;
	else
		man_config_state = MAN_CONFIGURED;

	mutex_exit(&man_lock);

	MAN_DBG(MAN_CONFIG, ("man_configure: returns %d\n", status));

	return (status);
}

/*
 * man_close - close the device
 *
 *	rq - upper read queue of the stream
 *
 *	returns	- success - 0
 *		- failure - errno value for failure
 */
static int
man_close(queue_t *rq)
{
	manstr_t		*close_msp;
	manstr_t		*msp;

	MAN_DBG(MAN_OCLOSE, ("man_close: rq(0x%p)\n", (void *)rq));

	qprocsoff(rq);
	close_msp = (manstr_t *)rq->q_ptr;

	/*
	 * Unlink the per-Stream entry from the active list and free it.
	 */
	if (close_msp == man_strup)
		man_strup = close_msp->ms_next;
	else {
		for (msp = man_strup; msp && msp->ms_next != close_msp; )
			msp = msp->ms_next;

		if (msp == NULL) {
			cmn_err(CE_WARN, "man_close: no stream!");
			return (ENODEV);
		}

		msp->ms_next = close_msp->ms_next;
	}

	if (close_msp->ms_dests != NULL) {
		/*
		 * Still DL_ATTACHED
		 */
		man_work_t *wp;

		wp = man_work_alloc(MAN_WORK_CLOSE_STREAM, KM_SLEEP);
		man_dodetach(close_msp, wp);
	}

	if (close_msp->ms_flags & MAN_SFLAG_CONTROL) {
		/*
		 * Driver about to unload.
		 */
		man_ctl_wq = NULL;
	}

	rq->q_ptr = WR(rq)->q_ptr = NULL;
	man_kfree((char *)close_msp, sizeof (manstr_t));
	(void) qassociate(rq, -1);

	MAN_DBG(MAN_OCLOSE, ("man_close: exit\n"));

	return (0);
}

/*
 * Ask bgthread to tear down lower stream and qwait
 * until its done.
 */
static void
man_dodetach(manstr_t *msp, man_work_t *wp)
{
	man_dest_t	*mdp;
	int		i;
	mblk_t		*mp;

	mdp = msp->ms_dests;
	msp->ms_dests = NULL;
	msp->ms_destp = NULL;

	/*
	 * Excise lower dests array, set it closing and hand it to
	 * background thread to dispose of.
	 */
	for (i = 0; i < MAN_MAX_DESTS; i++) {

		mdp[i].md_state |= MAN_DSTATE_CLOSING;
		mdp[i].md_msp = NULL;
		mdp[i].md_rq = NULL;

		if (mdp[i].md_lc_timer_id != 0) {
			(void) quntimeout(man_ctl_wq, mdp[i].md_lc_timer_id);
			mdp[i].md_lc_timer_id = 0;
		}
		if (mdp[i].md_bc_id != 0) {
			qunbufcall(man_ctl_wq, mdp[i].md_bc_id);
			mdp[i].md_bc_id = 0;
		}

		mutex_enter(&mdp[i].md_lock);
		while ((mp = mdp[i].md_dmp_head) != NULL) {
			mdp[i].md_dmp_head = mp->b_next;
			mp->b_next = NULL;
			freemsg(mp);
		}
		mdp[i].md_dmp_count = 0;
		mdp[i].md_dmp_tail = NULL;
		mutex_exit(&mdp[i].md_lock);
	}

	/*
	 * Dump any DL type messages previously caught.
	 */
	man_dl_clean(&msp->ms_dl_mp);
	man_dl_clean(&msp->ms_dlioc_mp);

	/*
	 * We need to clear fast path flag when dlioc messages are cleaned.
	 */
	msp->ms_flags &= ~MAN_SFLAG_FAST;

	/*
	 * MAN_WORK_CLOSE_STREAM work request preallocated by caller.
	 */
	ASSERT(wp->mw_type == MAN_WORK_CLOSE_STREAM);
	ASSERT(mdp != NULL);
	wp->mw_arg.a_mdp = mdp;
	wp->mw_arg.a_ndests = MAN_MAX_DESTS;
	wp->mw_arg.a_pg_id = -1;	/* Don't care */

	mutex_enter(&man_lock);
	man_work_add(man_bwork_q, wp);
	msp->ms_manp->man_refcnt--;
	mutex_exit(&man_lock);

	msp->ms_manp = NULL;

}


/*
 * man_uwput - handle DLPI messages issued from upstream, the write
 * side of the upper half of multiplexor. Called with shared access to
 * the inner perimeter.
 *
 *	wq - upper write queue of mxx
 *	mp - mblk ptr to DLPI request
 */
static int
man_uwput(register queue_t *wq, register mblk_t *mp)
{
	register manstr_t	*msp;		/* per stream data */
	register man_t		*manp;		/* per instance data */

	msp = (manstr_t *)wq->q_ptr;

	MAN_DBG(MAN_UWPUT, ("man_uwput: wq(0x%p) mp(0x%p) db_type(0x%x)"
	    " msp(0x%p)\n",
	    (void *)wq, (void *)mp, DB_TYPE(mp), (void *)msp));
#if DEBUG
	if (man_debug & MAN_UWPUT) {
		if (DB_TYPE(mp) == M_IOCTL) {
			struct iocblk	*iocp = (struct iocblk *)mp->b_rptr;
			MAN_DBG(MAN_UWPUT,
			    ("man_uwput: M_IOCTL ioc_cmd(0x%x)\n",
			    iocp->ioc_cmd));
		} else if (DB_TYPE(mp) == M_CTL) {
			struct iocblk	*iocp = (struct iocblk *)mp->b_rptr;
			MAN_DBG(MAN_UWPUT,
			    ("man_uwput: M_CTL ioc_cmd(0x%x)\n",
			    iocp->ioc_cmd));
		}
	}
#endif	/* DEBUG */


	switch (DB_TYPE(mp)) {
	case M_DATA:
		manp = msp->ms_manp;

		if (((msp->ms_flags & (MAN_SFLAG_FAST | MAN_SFLAG_RAW)) == 0) ||
		    (msp->ms_dlpistate != DL_IDLE) ||
		    (manp == NULL)) {

			merror(wq, mp, EPROTO);
			break;
		}

		if (wq->q_first) {
			(void) putq(wq, mp);
			qenable(wq);
		} else {
			ehdr_t	*ep = (ehdr_t *)mp->b_rptr;

			(void) man_start(wq, mp, &ep->ether_dhost);
		}
		break;

	case M_PROTO:
	case M_PCPROTO:
		if ((DL_PRIM(mp) == DL_UNITDATA_IND) && !wq->q_first) {
			(void) man_udreq(wq, mp);
		} else {
			(void) putq(wq, mp);
			qenable(wq);
		}
		break;

	case M_IOCTL:
	case M_IOCDATA:
		qwriter(wq, mp, man_ioctl, PERIM_INNER);
		break;

	case M_CTL:
		freemsg(mp);
		break;

	case M_FLUSH:
		MAN_DBG(MAN_UWPUT, ("man_wput: M_FLUSH\n"));
		if (*mp->b_rptr & FLUSHW)
			flushq(wq, FLUSHDATA);
		if (*mp->b_rptr & FLUSHR) {
			flushq(RD(wq), FLUSHDATA);
			*mp->b_rptr &= ~FLUSHW;
			qreply(wq, mp);
		} else {
			freemsg(mp);
		}
		break;

	default:
		MAN_DBG(MAN_WARN,
		    ("man_uwput: illegal mblk(0x%p) type(0x%x)\n",
		    (void *)mp, DB_TYPE(mp)));
		freemsg(mp);
		break;
	} /* End switch */

	MAN_DBG(MAN_UWPUT, ("man_uwput: exit wq(0x%p) mp(0x%p)\n",
	    (void *)wq, (void *)mp));

	return (0);
}

/*
 * man_start - handle data messages issued from upstream.  Send down
 * to particular man_dest based on ether_addr, otherwise send out to all
 * valid man_dests.
 *
 *	wq - upper write queue of mxx
 *	mp - mblk ptr to DLPI request
 * 	caller - Caller ID for decision making on canput failure
 *
 * Returns:
 *	0	- Data xmitted or No flow control situation detected.
 *	1	- Flow control situation detected.
 *
 * STREAMS Flow Control: can be used if there is only one destination
 * for a stream (1 to 1 multiplexor). In this case, we will use the upper
 * write queue to store mblks when in flow control. If there are multiple
 * destinations, we cannot use the STREAMs based flow control (1 to many
 * multiplexor). In this case, we will use the lower write queue to store
 * mblks when in flow control. Since destinations come and go, we may
 * transition between 1-to-1 and 1-to-m. So it may be the case that we have
 * some mblks stored on the upper queue, and some on the lower queue. However,
 * we will never send mblks out of order. See man_uwput and man_start_lower().
 *
 * A simple flow control mechanism is implemented for the deferred mblk list,
 * as this list is expected to be used temporarily for a very short
 * period required for switching paths. This flow control mechanism is
 * used only as a defensive approach to avoid infinite growth of this list.
 */
static int
man_start(register queue_t *wq, register mblk_t *mp, eaddr_t *eap)
{
	register manstr_t	*msp;		/* per stream data */
	register man_dest_t	*mdp = NULL;	/* destination */
	mblk_t			*tmp;
	int			i;
	int			status = 0;

	msp = (manstr_t *)wq->q_ptr;

	MAN_DBG(MAN_DATA, ("man_start: msp(0x%p) ether_addr(%s)\n",
	    (void *)msp, ether_sprintf(eap)));

	if (msp->ms_dests == NULL) {
		cmn_err(CE_WARN, "man_start: no destinations");
		freemsg(mp);
		return (0);
	}

	/*
	 * Optimization if only one valid destination.
	 */
	mdp = msp->ms_destp;

	if (IS_UNICAST(eap)) {
		queue_t			*flow_wq = NULL;

		if (mdp == NULL) {
			/*
			 * TDB - This needs to be optimized (some bits in
			 * ehp->dhost will act as an index.
			 */
			for (i = 0; i < MAN_MAX_DESTS; i++) {

				mdp = &msp->ms_dests[i];

				if ((mdp->md_state == MAN_DSTATE_READY) &&
				    (ether_cmp(eap, &mdp->md_dst_eaddr) == 0))
					break;
				mdp = NULL;
			}
		} else {
			/*
			 * 1 to 1 multiplexing, use upper wq for flow control.
			 */
			flow_wq = wq;
		}

		if (mdp != NULL) {
			/*
			 * Its going somewhere specific
			 */
			status =  man_start_lower(mdp, mp, flow_wq, MAN_UPPER);

		} else {
			MAN_DBG(MAN_DATA, ("man_start: no destination"
			    " for eaddr %s\n", ether_sprintf(eap)));
			freemsg(mp);
		}
	} else {
		/*
		 * Broadcast or multicast - send everone a copy.
		 */
		if (mdp == NULL) {
			for (i = 0; i < MAN_MAX_DESTS; i++) {
				mdp = &msp->ms_dests[i];

				if (mdp->md_state != MAN_DSTATE_READY)
					continue;

				if ((tmp = copymsg(mp)) != NULL) {
					(void) man_start_lower(mdp, tmp,
					    NULL, MAN_UPPER);
				} else {
					MAN_DBG(MAN_DATA, ("man_start: copymsg"
					    " failed!"));
				}
			}
			freemsg(mp);
		} else {
			if (mdp->md_state == MAN_DSTATE_READY)
				status =  man_start_lower(mdp, mp, wq,
				    MAN_UPPER);
			else
				freemsg(mp);
		}
	}
	return (status);
}

/*
 * Send a DL_UNITDATA or M_DATA fastpath data mblk to a particular
 * destination. Others mblk types sent down via * man_dlpi_senddown().
 *
 * Returns:
 *	0	- Data xmitted
 *	1	- Data not xmitted due to flow control.
 */
static int
man_start_lower(man_dest_t *mdp, mblk_t *mp, queue_t *flow_wq, int caller)
{
	queue_t		*wq = mdp->md_wq;
	int		status = 0;

	/*
	 * Lower stream ready for data transmit.
	 */
	if (mdp->md_state == MAN_DSTATE_READY &&
	    mdp->md_dlpistate == DL_IDLE) {

		ASSERT(mdp->md_wq != NULL);

		if (caller == MAN_UPPER) {
			/*
			 * Check for flow control conditions for lower
			 * stream.
			 */
			if (mdp->md_dmp_head == NULL &&
			    wq->q_first == NULL && canputnext(wq)) {

				(void) putnext(wq, mp);

			} else {
				mutex_enter(&mdp->md_lock);
				if (mdp->md_dmp_head != NULL) {
					/*
					 * A simple flow control mechanism.
					 */
					if (mdp->md_dmp_count >= MAN_HIWAT) {
						freemsg(mp);
					} else {
						/*
						 * Add 'mp' to the deferred
						 * msg list.
						 */
						mdp->md_dmp_tail->b_next = mp;
						mdp->md_dmp_tail = mp;
						mdp->md_dmp_count +=
						    msgsize(mp);
					}
					mutex_exit(&mdp->md_lock);
					/*
					 * Inform flow control situation
					 * to the caller.
					 */
					status = 1;
					qenable(wq);
					goto exit;
				}
				mutex_exit(&mdp->md_lock);
				/*
				 * If 1 to 1 mux, use upper write queue for
				 * flow control.
				 */
				if (flow_wq != NULL) {
					/*
					 * putbq() message and indicate
					 * flow control situation to the
					 * caller.
					 */
					(void) putbq(flow_wq, mp);
					qenable(flow_wq);
					status = 1;
					goto exit;
				}
				/*
				 * 1 to many mux, use lower write queue for
				 * flow control. Be mindful not to overflow
				 * the lower MAN STREAM q.
				 */
				if (canput(wq)) {
					(void) putq(wq, mp);
					qenable(wq);
				} else {
					MAN_DBG(MAN_DATA, ("man_start_lower:"
					    " lower q flow controlled -"
					    " discarding packet"));
					freemsg(mp);
					goto exit;
				}
			}

		} else {
			/*
			 * man_lwsrv  is draining flow controlled mblks.
			 */
			if (canputnext(wq))
				(void) putnext(wq, mp);
			else
				status = 1;
		}
		goto exit;
	}

	/*
	 * Lower stream in transition, do flow control.
	 */
	status = 1;

	if (mdp->md_state == MAN_DSTATE_NOTPRESENT) {
nodest:
		cmn_err(CE_WARN,
		    "man_start_lower: no dest for mdp(0x%p), caller(%d)!",
		    (void *)mdp, caller);
		if (caller == MAN_UPPER)
			freemsg(mp);
		goto exit;
	}

	if (mdp->md_state & MAN_DSTATE_CLOSING) {
		MAN_DBG(MAN_DATA, ("man_start_lower: mdp(0x%p) closing",
		    (void *)mdp));
		if (caller == MAN_UPPER)
			freemsg(mp);
		goto exit;
	}

	if ((mdp->md_state & MAN_DSTATE_PLUMBING) ||
	    (mdp->md_state == MAN_DSTATE_INITIALIZING) ||
	    (mdp->md_dlpistate != DL_IDLE)) {
		/*
		 * Defer until PLUMBED and DL_IDLE. See man_lwsrv().
		 */
		if (caller == MAN_UPPER) {
			/*
			 * Upper stream sending data down, add to defered mblk
			 * list for stream.
			 */
			mutex_enter(&mdp->md_lock);
			if (mdp->md_dmp_count >= MAN_HIWAT) {
				freemsg(mp);
			} else {
				if (mdp->md_dmp_head == NULL) {
					ASSERT(mdp->md_dmp_tail == NULL);
					mdp->md_dmp_head = mp;
					mdp->md_dmp_tail = mp;
				} else {
					mdp->md_dmp_tail->b_next = mp;
					mdp->md_dmp_tail = mp;
				}
				mdp->md_dmp_count += msgsize(mp);
			}
			mutex_exit(&mdp->md_lock);
		}

		goto exit;
	}

exit:
	return (status);
}

/*
 * man_ioctl - handle ioctl requests for this driver (I_PLINK/I_PUNLINK)
 * or pass thru to the physical driver below.  Note that most M_IOCTLs we
 * care about come down the control msp, but the IOC ones come down the IP.
 * Called with exclusive inner perimeter.
 *
 *	wq - upper write queue of mxx
 *	mp - mblk ptr to DLPI ioctl request
 */
static void
man_ioctl(register queue_t *wq, register mblk_t *mp)
{
	manstr_t		*msp;
	struct iocblk		*iocp;

	iocp = (struct iocblk *)mp->b_rptr;
	msp = (manstr_t *)wq->q_ptr;

#ifdef DEBUG
	{
		char			ioc_cmd[30];

		(void) sprintf(ioc_cmd, "not handled IOCTL 0x%x",
		    iocp->ioc_cmd);
		MAN_DBG((MAN_SWITCH | MAN_PATH | MAN_DLPI),
		    ("man_ioctl: wq(0x%p) mp(0x%p) cmd(%s)\n",
		    (void *)wq, (void *)mp,
		    (iocp->ioc_cmd == I_PLINK) ? "I_PLINK" :
		    (iocp->ioc_cmd == I_PUNLINK) ? "I_PUNLINK" :
		    (iocp->ioc_cmd == MAN_SETPATH) ? "MAN_SETPATH" :
		    (iocp->ioc_cmd == DL_IOC_HDR_INFO) ? "DL_IOC_HDR_INFO" :
		    (iocp->ioc_cmd == DLIOCRAW) ? "DLIOCRAW" : ioc_cmd));
	}
#endif /* DEBUG */


	/*
	 *  Handle the requests...
	 */
	switch ((unsigned int)iocp->ioc_cmd) {

	case I_PLINK:
		man_plink(wq, mp);
		break;

	case I_PUNLINK:
		man_unplink(wq, mp);
		break;

	case MAN_SETPATH:
		man_setpath(wq, mp);
		break;

	case MAN_GETEADDR:
		man_geteaddr(wq, mp);
		break;

	case MAN_SET_LINKCHECK_TIME:
		man_set_linkcheck_time(wq, mp);
		break;

	case MAN_SET_SC_IPADDRS:
		man_set_sc_ipaddrs(wq, mp);
		break;

	case MAN_SET_SC_IP6ADDRS:
		man_set_sc_ip6addrs(wq, mp);
		break;

	case DLIOCRAW:
		if (man_dlioc(msp, mp))
			miocnak(wq, mp, 0, ENOMEM);
		else {
			msp->ms_flags |= MAN_SFLAG_RAW;
			miocack(wq, mp, 0, 0);
		}
		break;

	case DL_IOC_HDR_INFO:
		man_dl_ioc_hdr_info(wq, mp);
		break;

	case MAN_ND_GET:
	case MAN_ND_SET:
		man_nd_getset(wq, mp);
		break;

	default:
		MAN_DBG(MAN_DDI, ("man_ioctl: unknown ioc_cmd %d\n",
		    (unsigned int)iocp->ioc_cmd));
		miocnak(wq, mp, 0, EINVAL);
		break;
	}
exit:
	MAN_DBG((MAN_SWITCH | MAN_PATH | MAN_DLPI), ("man_ioctl: exit\n"));

}

/*
 * man_plink: handle I_PLINK requests on the control stream
 */
void
man_plink(queue_t *wq, mblk_t *mp)
{
	struct linkblk	*linkp;
	man_linkrec_t	*lrp;
	int		status = 0;

	linkp = (struct linkblk *)mp->b_cont->b_rptr;

	/*
	 * Create a record to hold lower stream info. man_plumb will
	 * retrieve it after calling ldi_ioctl(I_PLINK)
	 */
	lrp = man_kzalloc(sizeof (man_linkrec_t), KM_NOSLEEP);
	if (lrp == NULL) {
		status = ENOMEM;
		goto exit;
	}

	lrp->l_muxid = linkp->l_index;
	lrp->l_wq = linkp->l_qbot;
	lrp->l_rq = RD(linkp->l_qbot);

	man_linkrec_insert(lrp);

exit:
	if (status)
		miocnak(wq, mp, 0, status);
	else
		miocack(wq, mp, 0, 0);

}

/*
 * man_unplink - handle I_PUNLINK requests on the control stream
 */
void
man_unplink(queue_t *wq, mblk_t *mp)
{
	struct linkblk	*linkp;

	linkp = (struct linkblk *)mp->b_cont->b_rptr;
	RD(linkp->l_qbot)->q_ptr = NULL;
	WR(linkp->l_qbot)->q_ptr = NULL;
	miocack(wq, mp, 0, 0);
}

void
man_linkrec_insert(man_linkrec_t *lrp)
{
	mutex_enter(&man_lock);

	lrp->l_next = man_linkrec_head;
	man_linkrec_head = lrp;

	mutex_exit(&man_lock);

}

static queue_t *
man_linkrec_find(int muxid)
{
	man_linkrec_t	*lpp;
	man_linkrec_t	*lp;
	queue_t		*wq = NULL;

	mutex_enter(&man_lock);

	if (man_linkrec_head == NULL)
		goto exit;

	lp = lpp = man_linkrec_head;
	if (lpp->l_muxid == muxid) {
		man_linkrec_head = lpp->l_next;
	} else {
		for (lp = lpp->l_next; lp; lp = lp->l_next) {
			if (lp->l_muxid == muxid)
				break;
			lpp = lp;
		}
	}

	if (lp == NULL)
		goto exit;

	wq = lp->l_wq;
	ASSERT(wq != NULL);

	lpp->l_next = lp->l_next;
	man_kfree(lp, sizeof (man_linkrec_t));

exit:
	mutex_exit(&man_lock);

	return (wq);
}

/*
 * Set instance linkcheck timer value.
 */
static void
man_set_linkcheck_time(queue_t *wq, mblk_t *mp)
{
	mi_time_t	*mtp;
	int		error;
	man_t		*manp;

	MAN_DBG(MAN_LINK, ("man_set_linkcheck_time: enter"));

	error = miocpullup(mp, sizeof (mi_time_t));
	if (error != 0)
		goto exit;

	mtp = (mi_time_t *)mp->b_cont->b_rptr;

	MAN_DBG(MAN_LINK, ("man_set_linkcheck_time: mtp"));
	MAN_DBGCALL(MAN_LINK, man_print_mtp(mtp));

	manp = ddi_get_soft_state(man_softstate, mtp->mtp_man_ppa);
	if (manp == NULL) {
		error = ENODEV;
		goto exit;
	}

	manp->man_linkcheck_time = mtp->mtp_time;
exit:
	if (error)
		miocnak(wq, mp, 0, error);
	else
		miocack(wq, mp, sizeof (mi_time_t), 0);
}

/*
 * Man path ioctl processing. Should only happen on the SSC. Called
 * with exclusive inner perimeter.
 */
static void
man_setpath(queue_t *wq, mblk_t *mp)
{
	mi_path_t		*mip;
	int			error;

	error = miocpullup(mp, sizeof (mi_path_t));
	if (error != 0)
		goto exit;

	mip = (mi_path_t *)mp->b_cont->b_rptr;
	mutex_enter(&man_lock);
	error = man_pg_cmd(mip, NULL);
	mutex_exit(&man_lock);

exit:
	if (error)
		miocnak(wq, mp, 0, error);
	else
		miocack(wq, mp, sizeof (mi_path_t), 0);
}

/*
 * Get the local ethernet address of this machine.
 */
static void
man_geteaddr(queue_t *wq, mblk_t *mp)
{
	eaddr_t			*eap;
	int			error;

	error = miocpullup(mp, sizeof (eaddr_t));
	if (error != 0) {
		miocnak(wq, mp, 0, error);
		return;
	}

	eap = (eaddr_t *)mp->b_cont->b_rptr;
	(void) localetheraddr(NULL, eap);
	miocack(wq, mp, sizeof (eaddr_t), 0);
}

/*
 * Set my SC and other SC IPv4 addresses for use in man_pinger routine.
 */
static void
man_set_sc_ipaddrs(queue_t *wq, mblk_t *mp)
{
	int			error;

	error = miocpullup(mp, sizeof (man_sc_ipaddrs_t));
	if (error != 0)
		goto exit;

	man_sc_ipaddrs = *(man_sc_ipaddrs_t *)mp->b_cont->b_rptr;

#ifdef DEBUG
	{
		char	buf[INET_ADDRSTRLEN];

		(void) inet_ntop(AF_INET,
		    (void *) &man_sc_ipaddrs.ip_other_sc_ipaddr,
		    buf, INET_ADDRSTRLEN);
		MAN_DBG(MAN_CONFIG, ("ip_other_sc_ipaddr = %s", buf));
		(void) inet_ntop(AF_INET,
		    (void *) &man_sc_ipaddrs.ip_my_sc_ipaddr,
		    buf, INET_ADDRSTRLEN);
		MAN_DBG(MAN_CONFIG, ("ip_my_sc_ipaddr = %s", buf));
	}
#endif /* DEBUG */
exit:
	if (error)
		miocnak(wq, mp, 0, error);
	else
		miocack(wq, mp, sizeof (man_sc_ipaddrs_t), 0);
}

/*
 * Set my SC and other SC IPv6 addresses for use in man_pinger routine.
 */
static void
man_set_sc_ip6addrs(queue_t *wq, mblk_t *mp)
{
	int			error;

	error = miocpullup(mp, sizeof (man_sc_ip6addrs_t));
	if (error != 0)
		goto exit;

	man_sc_ip6addrs = *(man_sc_ip6addrs_t *)mp->b_cont->b_rptr;

#ifdef DEBUG
	{
		char	buf[INET6_ADDRSTRLEN];

		(void) inet_ntop(AF_INET6,
		    (void *) &man_sc_ip6addrs.ip6_other_sc_ipaddr,
		    buf, INET6_ADDRSTRLEN);
		MAN_DBG(MAN_CONFIG, ("ip6_other_sc_ipaddr = %s", buf));
		(void) inet_ntop(AF_INET6,
		    (void *) &man_sc_ip6addrs.ip6_my_sc_ipaddr,
		    buf, INET6_ADDRSTRLEN);
		MAN_DBG(MAN_CONFIG, ("ip6_my_sc_ipaddr = %s", buf));
	}
#endif /* DEBUG */
exit:
	if (error)
		miocnak(wq, mp, 0, error);
	else
		miocack(wq, mp, sizeof (man_sc_ip6addrs_t), 0);
}

/*
 * M_DATA fastpath info request.
 */
static void
man_dl_ioc_hdr_info(queue_t *wq, mblk_t *mp)
{
	manstr_t		*msp;
	man_t			*manp;
	mblk_t			*nmp;
	man_dladdr_t		*dlap;
	dl_unitdata_req_t	*dludp;
	struct	ether_header	*headerp;
	t_uscalar_t		off, len;
	int			status = 0;

	MAN_DBG(MAN_DLPI, ("man_dl_ioc_hdr_info: enter"));

	msp = (manstr_t *)wq->q_ptr;
	manp = msp->ms_manp;
	if (manp == NULL) {
		status = EINVAL;
		goto exit;
	}

	status = miocpullup(mp, sizeof (dl_unitdata_req_t) + MAN_ADDRL);
	if (status != 0)
		goto exit;

	/*
	 * Sanity check the DL_UNITDATA_REQ destination address
	 * offset and length values.
	 */
	dludp = (dl_unitdata_req_t *)mp->b_cont->b_rptr;
	off = dludp->dl_dest_addr_offset;
	len = dludp->dl_dest_addr_length;
	if (dludp->dl_primitive != DL_UNITDATA_REQ ||
	    !MBLKIN(mp->b_cont, off, len) || len != MAN_ADDRL) {
		status = EINVAL;
		goto exit;
	}

	dlap = (man_dladdr_t  *)(mp->b_cont->b_rptr + off);

	/*
	 * Allocate a new mblk to hold the ether header.
	 */
	if ((nmp = allocb(ETHERHEADER_SIZE, BPRI_MED)) == NULL) {
		status = ENOMEM;
		goto exit;
	}

	/* We only need one dl_ioc_hdr mblk for replay */
	if (!(msp->ms_flags & MAN_SFLAG_FAST))
		status = man_dl_catch(&msp->ms_dlioc_mp, mp);

	/* Forward the packet to all lower destinations. */
	if ((status != 0) || ((status = man_dlpi_senddown(msp, mp)) != 0)) {
		freemsg(nmp);
		goto exit;
	}

	nmp->b_wptr += ETHERHEADER_SIZE;

	/*
	 * Fill in the ether header.
	 */
	headerp = (struct ether_header *)nmp->b_rptr;
	ether_copy(&dlap->dl_phys, &headerp->ether_dhost);
	ether_copy(&manp->man_eaddr, &headerp->ether_shost);
	put_ether_type(headerp, dlap->dl_sap);

	/*
	 * Link new mblk in after the "request" mblks.
	 */
	linkb(mp, nmp);

exit:
	MAN_DBG(MAN_DLPI, ("man_dl_ioc_hdr_info: returns, status = %d",
	    status));

	if (status) {
		miocnak(wq, mp, 0, status);
	} else {
		msp = (manstr_t *)wq->q_ptr;
		msp->ms_flags |= MAN_SFLAG_FAST;
		miocack(wq, mp, msgsize(mp->b_cont), 0);
	}

}

/*
 * man_uwsrv - Upper write queue service routine to handle deferred
 * DLPI messages issued from upstream, the write side of the upper half
 * of multiplexor. It is also used by man_bwork to switch the lower
 * multiplexor.
 *
 *	wq - upper write queue of mxx
 */
static int
man_uwsrv(queue_t *wq)
{
	register mblk_t		*mp;
	manstr_t		*msp;		/* per stream data */
	man_t			*manp;		/* per instance data */
	ehdr_t			*ep;
	int			status;

	msp = (manstr_t *)wq->q_ptr;

	MAN_DBG(MAN_UWSRV, ("man_uwsrv: wq(0x%p) msp", (void *)wq));
	MAN_DBGCALL(MAN_UWSRV, man_print_msp(msp));

	if (msp == NULL)
		goto done;

	manp = msp->ms_manp;

	while (mp = getq(wq)) {

		switch (DB_TYPE(mp)) {
		/*
		 * Can probably remove this as I never put data messages
		 * here.
		 */
		case M_DATA:
			if (manp) {
				ep = (ehdr_t *)mp->b_rptr;
				status = man_start(wq, mp, &ep->ether_dhost);
				if (status) {
					/*
					 * man_start() indicated flow control
					 * situation, stop processing now.
					 */
					goto break_loop;
				}
			} else
				freemsg(mp);
			break;

		case M_PROTO:
		case M_PCPROTO:
			status = man_proto(wq, mp);
			if (status) {
				/*
				 * man_proto() indicated flow control
				 * situation detected by man_start(),
				 * stop processing now.
				 */
				goto break_loop;
			}
			break;

		default:
			MAN_DBG(MAN_UWSRV, ("man_uwsrv: discarding mp(0x%p)",
			    (void *)mp));
			freemsg(mp);
			break;
		}
	}

break_loop:
	/*
	 * Check to see if bgthread wants us to do something inside the
	 * perimeter.
	 */
	if ((msp->ms_flags & MAN_SFLAG_CONTROL) &&
	    man_iwork_q->q_work != NULL) {

		man_iwork();
	}

done:

	MAN_DBG(MAN_UWSRV, ("man_uwsrv: returns"));

	return (0);
}


/*
 * man_proto - handle DLPI protocol requests issued from upstream.
 * Called by man_uwsrv().  We disassociate upper and lower multiplexor
 * DLPI state transitions. The upper stream here (manstr_t) transitions
 * appropriately, saves the DLPI requests via man_dlpi(), and then
 * arranges for the DLPI request to be sent down via man_dlpi_senddown() if
 * appropriate.
 *
 *	wq - upper write queue of mxx
 *	mp - mbl ptr to protocol request
 */
static int
man_proto(queue_t *wq, mblk_t *mp)
{
	union DL_primitives	*dlp;
	int			flow_status = 0;

	dlp = (union DL_primitives *)mp->b_rptr;

	MAN_DBG((MAN_UWSRV | MAN_DLPI),
	    ("man_proto: mp(0x%p) prim(%s)\n", (void *)mp,
	    dps[dlp->dl_primitive]));

	switch (dlp->dl_primitive) {
	case DL_UNITDATA_REQ:
		flow_status = man_udreq(wq, mp);
		break;

	case DL_ATTACH_REQ:
		man_areq(wq, mp);
		break;

	case DL_DETACH_REQ:
		man_dreq(wq, mp);
		break;

	case DL_BIND_REQ:
		man_breq(wq, mp);
		break;

	case DL_UNBIND_REQ:
		man_ubreq(wq, mp);
		break;

	case DL_INFO_REQ:
		man_ireq(wq, mp);
		break;

	case DL_PROMISCON_REQ:
		man_ponreq(wq, mp);
		break;

	case DL_PROMISCOFF_REQ:
		man_poffreq(wq, mp);
		break;

	case DL_ENABMULTI_REQ:
		man_emreq(wq, mp);
		break;

	case DL_DISABMULTI_REQ:
		man_dmreq(wq, mp);
		break;

	case DL_PHYS_ADDR_REQ:
		man_pareq(wq, mp);
		break;

	case DL_SET_PHYS_ADDR_REQ:
		man_spareq(wq, mp);
		break;

	default:
		MAN_DBG((MAN_UWSRV | MAN_DLPI), ("man_proto: prim(%d)\n",
		    dlp->dl_primitive));
		dlerrorack(wq, mp, dlp->dl_primitive, DL_UNSUPPORTED, 0);
		break;

	} /* End switch */

	MAN_DBG((MAN_UWSRV | MAN_DLPI), ("man_proto: exit\n"));
	return (flow_status);

}

static int
man_udreq(queue_t *wq, mblk_t *mp)
{
	manstr_t		*msp;
	dl_unitdata_req_t	*dludp;
	mblk_t	*nmp;
	man_dladdr_t		*dlap;
	t_uscalar_t 		off, len;
	int 			flow_status = 0;

	msp = (manstr_t *)wq->q_ptr;


	if (msp->ms_dlpistate != DL_IDLE) {
		dlerrorack(wq, mp, DL_UNITDATA_REQ, DL_OUTSTATE, 0);
		return (flow_status);
	}
	dludp = (dl_unitdata_req_t *)mp->b_rptr;
	off = dludp->dl_dest_addr_offset;
	len = dludp->dl_dest_addr_length;

	/*
	 * Validate destination address format.
	 */
	if (!MBLKIN(mp, off, len) || (len != MAN_ADDRL)) {
		dluderrorind(wq, mp, mp->b_rptr + off, len, DL_BADADDR, 0);
		return (flow_status);
	}

	/*
	 * Error if no M_DATA follows.
	 */
	nmp = mp->b_cont;
	if (nmp == NULL) {
		dluderrorind(wq, mp, mp->b_rptr + off, len, DL_BADDATA, 0);
		return (flow_status);
	}

	dlap = (man_dladdr_t *)(mp->b_rptr + off);

	flow_status = man_start(wq, mp, &dlap->dl_phys);
	return (flow_status);
}

/*
 * Handle DL_ATTACH_REQ.
 */
static void
man_areq(queue_t *wq, mblk_t *mp)
{
	man_t			*manp;	/* per instance data */
	manstr_t		*msp;	/* per stream data */
	short			ppa;
	union DL_primitives	*dlp;
	mblk_t			*preq = NULL;
	int			did_refcnt = FALSE;
	int			dlerror = 0;
	int			status = 0;

	msp = (manstr_t *)wq->q_ptr;
	dlp = (union DL_primitives *)mp->b_rptr;

	/*
	 * Attach us to MAN PPA (device instance).
	 */
	if (MBLKL(mp) < DL_ATTACH_REQ_SIZE) {
		dlerror = DL_BADPRIM;
		goto exit;
	}

	if (msp->ms_dlpistate != DL_UNATTACHED) {
		dlerror = DL_OUTSTATE;
		goto exit;
	}

	ppa = dlp->attach_req.dl_ppa;
	if (ppa == -1 || qassociate(wq, ppa) != 0) {
		dlerror = DL_BADPPA;
		MAN_DBG(MAN_WARN, ("man_areq: bad PPA %d", ppa));
		goto exit;
	}

	mutex_enter(&man_lock);
	manp = ddi_get_soft_state(man_softstate, ppa);
	ASSERT(manp != NULL);	/* qassociate() succeeded */

	manp->man_refcnt++;
	did_refcnt = TRUE;
	mutex_exit(&man_lock);

	/*
	 * Create a DL replay list for the lower stream. These wont
	 * actually be sent down until the lower streams are made active
	 * (sometime after the call to man_init_dests below).
	 */
	preq = man_alloc_physreq_mp(&manp->man_eaddr);
	if (preq == NULL) {
		dlerror = DL_SYSERR;
		status = ENOMEM;
		goto exit;
	}

	/*
	 * Make copy for dlpi resync of upper and lower streams.
	 */
	if (man_dlpi(msp, mp)) {
		dlerror = DL_SYSERR;
		status = ENOMEM;
		goto exit;
	}

	/* TBD - need to clean off ATTACH req on failure here. */
	if (man_dlpi(msp, preq)) {
		dlerror = DL_SYSERR;
		status = ENOMEM;
		goto exit;
	}

	/*
	 * man_init_dests/man_start_dest needs these set before call.
	 */
	msp->ms_manp = manp;
	msp->ms_meta_ppa = ppa;

	/*
	 *  Allocate and init lower destination structures.
	 */
	ASSERT(msp->ms_dests == NULL);
	if (man_init_dests(manp, msp)) {
		mblk_t	 *tmp;

		/*
		 * If we cant get the lower streams ready, then
		 * remove the messages from the DL replay list and
		 * fail attach.
		 */
		while ((tmp = msp->ms_dl_mp) != NULL) {
			msp->ms_dl_mp = msp->ms_dl_mp->b_next;
			tmp->b_next = tmp->b_prev = NULL;
			freemsg(tmp);
		}

		msp->ms_manp = NULL;
		msp->ms_meta_ppa = -1;

		dlerror = DL_SYSERR;
		status = ENOMEM;
		goto exit;
	}

	MAN_DBG(MAN_DLPI, ("man_areq: ppa 0x%x man_refcnt: %d\n",
	    ppa, manp->man_refcnt));

	SETSTATE(msp, DL_UNBOUND);

exit:
	if (dlerror == 0) {
		dlokack(wq, mp, DL_ATTACH_REQ);
	} else {
		if (did_refcnt) {
			mutex_enter(&man_lock);
			manp->man_refcnt--;
			mutex_exit(&man_lock);
		}
		dlerrorack(wq, mp, DL_ATTACH_REQ, dlerror, status);
		(void) qassociate(wq, -1);
	}
	if (preq != NULL)
		freemsg(preq);

}

/*
 * Called at DL_ATTACH time.
 * Man_lock is held to protect pathgroup list(man_pg).
 */
static int
man_init_dests(man_t *manp, manstr_t *msp)
{
	man_dest_t	*mdp;
	man_pg_t	*mpg;
	int		i;

	mdp = man_kzalloc(MAN_DEST_ARRAY_SIZE, KM_NOSLEEP);
	if (mdp == NULL)
		return (ENOMEM);

	msp->ms_dests = mdp;

	mutex_enter(&man_lock);
	for (i = 0; i < MAN_MAX_DESTS; i++) {

		mdp[i].md_muxid = -1;	/* muxid 0 is valid */
		mutex_init(&mdp->md_lock, NULL, MUTEX_DRIVER, NULL);

		mpg = man_find_pg_by_id(manp->man_pg, i);

		if (mpg && man_find_active_path(mpg->mpg_pathp))
			man_start_dest(&mdp[i], msp, mpg);
	}
	mutex_exit(&man_lock);

	return (0);
}

/*
 * Get a destination ready for use.
 */
static void
man_start_dest(man_dest_t *mdp, manstr_t *msp, man_pg_t *mpg)
{
	man_path_t	*ap;

	mdp->md_muxid = -1;
	mdp->md_dlpistate = DL_UNATTACHED;
	mdp->md_msp = msp;
	mdp->md_rq = msp->ms_rq;
	mdp->md_pg_id = mpg->mpg_pg_id;

	ASSERT(msp->ms_manp);

	ether_copy(&msp->ms_manp->man_eaddr, &mdp->md_src_eaddr);
	ether_copy(&mpg->mpg_dst_eaddr, &mdp->md_dst_eaddr);

	ap = man_find_active_path(mpg->mpg_pathp);
	ASSERT(ap);
	mdp->md_device = ap->mp_device;

	/*
	 * Set up linktimers so that first time through, we will do
	 * a failover.
	 */
	mdp->md_linkstate = MAN_LINKFAIL;
	mdp->md_state = MAN_DSTATE_INITIALIZING;
	mdp->md_lc_timer_id = qtimeout(man_ctl_wq, man_linkcheck_timer,
	    (void *)mdp, man_gettimer(MAN_TIMER_INIT, mdp));

	/*
	 * As an optimization, if there is only one destination,
	 * remember the destination pointer. Used by man_start().
	 */
	man_set_optimized_dest(msp);

	MAN_DBG(MAN_DEST, ("man_start_dest: mdp"));
	MAN_DBGCALL(MAN_DEST, man_print_mdp(mdp));
}

static void
man_set_optimized_dest(manstr_t *msp)
{
	int		count = 0;
	int		i;
	man_dest_t	*mdp = NULL;

	for (i = 0; i < MAN_MAX_DESTS; i++) {
		if (msp->ms_dests[i].md_msp != NULL) {
			count++;
			mdp = &msp->ms_dests[i];
		}
	}

	if (count == 1)
		msp->ms_destp = mdp;
	else
		msp->ms_destp = NULL;

}

/*
 * Catch dlpi message for replaying, and arrange to send it down
 * to any destinations not PLUMBING. See man_dlpi_replay().
 */
static int
man_dlpi(manstr_t *msp, mblk_t *mp)
{
	int	status;

	status = man_dl_catch(&msp->ms_dl_mp, mp);
	if (status == 0)
		status = man_dlpi_senddown(msp, mp);

	return (status);
}

/*
 * Catch IOCTL type DL_ messages.
 */
static int
man_dlioc(manstr_t *msp, mblk_t *mp)
{
	int status;

	status = man_dl_catch(&msp->ms_dlioc_mp, mp);
	if (status == 0)
		status = man_dlpi_senddown(msp, mp);

	return (status);
}

/*
 * We catch all DLPI messages that we have to resend to a new AP'ed
 * device to put it in the right state.  We link these messages together
 * w/ their b_next fields and hang it off of msp->ms_dl_mp.  We
 * must be careful to restore b_next fields before doing dupmsg/freemsg!
 *
 *	msp - pointer of stream struct to process
 *	mblk - pointer to DLPI request to catch
 */
static int
man_dl_catch(mblk_t **mplist, mblk_t *mp)
{
	mblk_t			*dupmp;
	mblk_t			*tmp;
	unsigned		prim;
	int			status = 0;

	dupmp = copymsg(mp);
	if (dupmp == NULL) {
		status = ENOMEM;
		goto exit;
	}


	if (*mplist == NULL)
		*mplist = dupmp;
	else {
		for (tmp = *mplist; tmp->b_next; )
			tmp = tmp->b_next;

		tmp->b_next = dupmp;
	}

	prim = DL_PRIM(mp);
	MAN_DBG(MAN_DLPI,
	    ("man_dl_catch: adding %s\n",
	    (prim == DL_IOC_HDR_INFO) ? "DL_IOC_HDR_INFO" :
	    (prim == DLIOCRAW) ? "DLIOCRAW" :
	    (prim == DL_PROMISCON_REQ) ? promisc[DL_PROMISCON_TYPE(mp)] :
	    dps[prim]));

exit:

	return (status);
}

/*
 * Send down a single DLPI M_[PC]PROTO to all currently valid dests.
 *
 *	msp - ptr to NDM stream structure DL_ messages was received on.
 *	mp - ptr to mblk containing DL_ request.
 */
static int
man_dlpi_senddown(manstr_t *msp, mblk_t *mp)
{
	man_dest_t	*mdp;
	int		i;
	mblk_t		*rmp[MAN_MAX_DESTS];	/* Copy to replay */
	int		dstate[MAN_MAX_DESTS];
	int		no_dests = TRUE;
	int		status = 0;

	if (msp->ms_dests == NULL)
		goto exit;

	for (i = 0; i < MAN_MAX_DESTS; i++) {
		mdp = &msp->ms_dests[i];
		if (mdp->md_state == MAN_DSTATE_READY) {
			dstate[i] = TRUE;
			no_dests = FALSE;
		} else {
			dstate[i] = FALSE;
		}
		rmp[i] = NULL;
	}

	if (no_dests)
		goto exit;

	/*
	 * Build replay and duplicate list for all possible destinations.
	 */
	for (i = 0; i < MAN_MAX_DESTS; i++) {
		if (dstate[i]) {
			rmp[i] = copymsg(mp);
			if (rmp[i] == NULL) {
				status = ENOMEM;
				break;
			}
		}
	}

	if (status == 0) {
		for (i = 0; i < MAN_MAX_DESTS; i++)
			if (dstate[i]) {
				mdp = &msp->ms_dests[i];

				ASSERT(mdp->md_wq != NULL);
				ASSERT(mp->b_next == NULL);
				ASSERT(mp->b_prev == NULL);

				man_dlpi_replay(mdp, rmp[i]);
			}
	} else {
		for (; i >= 0; i--)
			if (dstate[i] && rmp[i])
				freemsg(rmp[i]);
	}

exit:
	return (status);
}

/*
 * man_dlpi_replay - traverse the list of DLPI requests and reapply them to
 * get the upper and lower streams into the same state. Called holding inner
 * perimeter lock exclusive. Note thet we defer M_IOCTL type dlpi messages
 * until we get an OK_ACK to our ATTACH (see man_lrsrv and
 * man_dlioc_replay).
 *
 * 	mdp - pointer to lower queue (destination)
 *	rmp - list of mblks to send down stream.
 */
static void
man_dlpi_replay(man_dest_t *mdp, mblk_t *rmp)
{
	mblk_t			*mp;
	union DL_primitives	*dlp = NULL;

	MAN_DBG(MAN_DLPI, ("man_dlpi_replay: mdp(0x%p)", (void *)mdp));

	while (rmp) {
		mp = rmp;
		rmp = rmp->b_next;
		mp->b_prev = mp->b_next = NULL;

		dlp = (union DL_primitives *)mp->b_rptr;
		MAN_DBG(MAN_DLPI,
		    ("man_dlpi_replay: mdp(0x%p) sending %s\n",
		    (void *)mdp,
		    (dlp->dl_primitive == DL_IOC_HDR_INFO) ?
		    "DL_IOC_HDR_INFO" : (dlp->dl_primitive == DLIOCRAW) ?
		    "DLIOCRAW" : dps[(unsigned)(dlp->dl_primitive)]));

		if (dlp->dl_primitive == DL_ATTACH_REQ) {
			/*
			 * insert the lower devices ppa.
			 */
			dlp->attach_req.dl_ppa = mdp->md_device.mdev_ppa;
		}

		(void) putnext(mdp->md_wq, mp);
	}

}

static void
man_dreq(queue_t *wq, mblk_t *mp)
{
	manstr_t	*msp;	/* per stream data */
	man_work_t	*wp;

	msp = (manstr_t *)wq->q_ptr;

	if (MBLKL(mp) < DL_DETACH_REQ_SIZE) {
		dlerrorack(wq, mp, DL_DETACH_REQ, DL_BADPRIM, 0);
		return;
	}

	if (msp->ms_dlpistate != DL_UNBOUND) {
		dlerrorack(wq, mp, DL_DETACH_REQ, DL_OUTSTATE, 0);
		return;
	}

	ASSERT(msp->ms_dests != NULL);

	wp = man_work_alloc(MAN_WORK_CLOSE_STREAM, KM_NOSLEEP);
	if (wp == NULL) {
		dlerrorack(wq, mp, DL_DETACH_REQ, DL_SYSERR, ENOMEM);
		return;
	}
	man_dodetach(msp, wp);
	(void) qassociate(wq, -1);

	SETSTATE(msp, DL_UNATTACHED);

	dlokack(wq, mp, DL_DETACH_REQ);
}

static void
man_dl_clean(mblk_t **mplist)
{
	mblk_t	*tmp;

	/*
	 * Toss everything.
	 */
	while ((tmp = *mplist) != NULL) {
		*mplist = (*mplist)->b_next;
		tmp->b_next = tmp->b_prev = NULL;
		freemsg(tmp);
	}

}

/*
 * man_dl_release - Remove the corresponding DLPI request from the
 * catch list. Walk thru the catch list looking for the other half of
 * the pair and delete it.  If we are detaching, delete the entire list.
 *
 *	msp - pointer of stream struct to process
 *	mp  - pointer to mblk to first half of pair.  We will delete other
 * 		half of pair based on this.
 */
static void
man_dl_release(mblk_t **mplist, mblk_t *mp)
{
	uchar_t			match_dbtype;
	mblk_t			*tmp;
	mblk_t			*tmpp;
	int			matched = FALSE;

	if (*mplist == NULL)
		goto exit;

	match_dbtype = DB_TYPE(mp);

	/*
	 * Currently we only clean DL_ PROTO type messages. There is
	 * no way to turn off M_CTL or DL_IOC stuff other than sending
	 * down a DL_DETACH, which resets everything.
	 */
	if (match_dbtype != M_PROTO && match_dbtype != M_PCPROTO) {
		goto exit;
	}

	/*
	 * Selectively find a caught mblk that matches this one and
	 * remove it from the list
	 */
	tmp = tmpp = *mplist;
	matched = man_match_proto(mp, tmp);
	if (matched) {
		*mplist = tmp->b_next;
		tmp->b_next = tmp->b_prev = NULL;
	} else {
		for (tmp = tmp->b_next; tmp != NULL; tmp = tmp->b_next) {
			if (matched = man_match_proto(mp, tmp))
				break;
			tmpp = tmp;
		}

		if (matched) {
			tmpp->b_next = tmp->b_next;
			tmp->b_next = tmp->b_prev = NULL;
		}
	}

exit:
	if (matched) {

		MAN_DBG(MAN_DLPI, ("man_dl_release: release %s",
		    (DL_PRIM(mp) == DL_IOC_HDR_INFO) ? "DL_IOC_HDR_INFO" :
		    (DL_PRIM(mp) == DLIOCRAW) ? "DLIOCRAW" :
		    dps[(int)DL_PRIM(mp)]));

		freemsg(tmp);
	}
	MAN_DBG(MAN_DLPI, ("man_dl_release: returns"));

}

/*
 * Compare two DL_ messages. If they are complimentary (e.g. DL_UNBIND
 * compliments DL_BIND), return true.
 */
static int
man_match_proto(mblk_t *mp1, mblk_t *mp2)
{
	t_uscalar_t	prim1;
	t_uscalar_t	prim2;
	int		matched = FALSE;

	/*
	 * Primitive to clean off list.
	 */
	prim1 = DL_PRIM(mp1);
	prim2 = DL_PRIM(mp2);

	switch (prim1) {
	case DL_UNBIND_REQ:
		if (prim2 == DL_BIND_REQ)
			matched = TRUE;
		break;

	case DL_PROMISCOFF_REQ:
		if (prim2 == DL_PROMISCON_REQ) {
			dl_promiscoff_req_t	*poff1;
			dl_promiscoff_req_t	*poff2;

			poff1 = (dl_promiscoff_req_t *)mp1->b_rptr;
			poff2 = (dl_promiscoff_req_t *)mp2->b_rptr;

			if (poff1->dl_level == poff2->dl_level)
				matched = TRUE;
		}
		break;

	case DL_DISABMULTI_REQ:
		if (prim2 == DL_ENABMULTI_REQ) {
			union DL_primitives	*dlp;
			t_uscalar_t		off;
			eaddr_t			*addrp1;
			eaddr_t			*addrp2;

			dlp = (union DL_primitives *)mp1->b_rptr;
			off = dlp->disabmulti_req.dl_addr_offset;
			addrp1 = (eaddr_t *)(mp1->b_rptr + off);

			dlp = (union DL_primitives *)mp2->b_rptr;
			off = dlp->disabmulti_req.dl_addr_offset;
			addrp2 = (eaddr_t *)(mp2->b_rptr + off);

			if (ether_cmp(addrp1, addrp2) == 0)
				matched = 1;
		}
		break;

	default:
		break;
	}

	MAN_DBG(MAN_DLPI, ("man_match_proto returns %d", matched));

	return (matched);
}

/*
 * Bind upper stream to a particular SAP. Called with exclusive innerperim
 * QPAIR, shared outerperim.
 */
static void
man_breq(queue_t *wq, mblk_t *mp)
{
	man_t			*manp;	/* per instance data */
	manstr_t		*msp;	/* per stream data */
	union DL_primitives	*dlp;
	man_dladdr_t		man_addr;
	t_uscalar_t		sap;
	t_uscalar_t		xidtest;

	msp = (manstr_t *)wq->q_ptr;

	if (MBLKL(mp) < DL_BIND_REQ_SIZE) {
		dlerrorack(wq, mp, DL_BIND_REQ, DL_BADPRIM, 0);
		return;
	}

	if (msp->ms_dlpistate != DL_UNBOUND) {
		dlerrorack(wq, mp, DL_BIND_REQ, DL_OUTSTATE, 0);
		return;
	}

	dlp = (union DL_primitives *)mp->b_rptr;
	manp = msp->ms_manp;			/* valid after attach */
	sap = dlp->bind_req.dl_sap;
	xidtest = dlp->bind_req.dl_xidtest_flg;

	ASSERT(manp);

	if (xidtest) {
		dlerrorack(wq, mp, DL_BIND_REQ, DL_NOAUTO, 0);
		return;
	}

	if (sap > ETHERTYPE_MAX) {
		dlerrorack(wq, mp, DL_BIND_REQ, DL_BADSAP, 0);
		return;
	}

	if (man_dlpi(msp, mp)) {
		dlerrorack(wq, mp, DL_BIND_REQ, DL_SYSERR, ENOMEM);
		return;
	}

	msp->ms_sap = sap;

	SETSTATE(msp, DL_IDLE);

	man_addr.dl_sap = msp->ms_sap;
	ether_copy(&msp->ms_manp->man_eaddr, &man_addr.dl_phys);

	dlbindack(wq, mp, msp->ms_sap, &man_addr, MAN_ADDRL, 0, 0);

}

static void
man_ubreq(queue_t *wq, mblk_t *mp)
{
	manstr_t		*msp;	/* per stream data */

	msp = (manstr_t *)wq->q_ptr;

	if (MBLKL(mp) < DL_UNBIND_REQ_SIZE) {
		dlerrorack(wq, mp, DL_UNBIND_REQ, DL_BADPRIM, 0);
		return;
	}

	if (msp->ms_dlpistate != DL_IDLE) {
		dlerrorack(wq, mp, DL_UNBIND_REQ, DL_OUTSTATE, 0);
		return;
	}

	if (man_dlpi_senddown(msp, mp)) {
		dlerrorack(wq, mp, DL_UNBIND_REQ, DL_SYSERR, ENOMEM);
		return;
	}

	man_dl_release(&msp->ms_dl_mp, mp);

	SETSTATE(msp, DL_UNBOUND);

	dlokack(wq, mp, DL_UNBIND_REQ);

}

static void
man_ireq(queue_t *wq, mblk_t *mp)
{
	manstr_t	*msp;
	dl_info_ack_t	*dlip;
	man_dladdr_t	*dlap;
	eaddr_t		*ep;
	size_t	size;

	msp = (manstr_t *)wq->q_ptr;

	if (MBLKL(mp) < DL_INFO_REQ_SIZE) {
		dlerrorack(wq, mp, DL_INFO_REQ, DL_BADPRIM, 0);
		return;
	}

	/* Exchange current msg for a DL_INFO_ACK. */
	size = sizeof (dl_info_ack_t) + MAN_ADDRL + ETHERADDRL;
	mp = mexchange(wq, mp, size, M_PCPROTO, DL_INFO_ACK);
	if (mp == NULL) {
		MAN_DBG(MAN_DLPI, ("man_ireq: man_ireq: mp == NULL."));
		return;
	}

	/* Fill in the DL_INFO_ACK fields and reply. */
	dlip = (dl_info_ack_t *)mp->b_rptr;
	*dlip = man_infoack;
	dlip->dl_current_state = msp->ms_dlpistate;
	dlap = (man_dladdr_t *)(mp->b_rptr + dlip->dl_addr_offset);
	dlap->dl_sap = msp->ms_sap;

	/*
	 * If attached, return physical address.
	 */
	if (msp->ms_manp != NULL) {
		ether_copy(&msp->ms_manp->man_eaddr, &dlap->dl_phys);
	} else {
		bzero((caddr_t)&dlap->dl_phys, ETHERADDRL);
	}

	ep = (struct ether_addr *)(mp->b_rptr + dlip->dl_brdcst_addr_offset);
	ether_copy(&etherbroadcast, ep);

	qreply(wq, mp);

}


static void
man_ponreq(queue_t *wq, mblk_t *mp)
{
	manstr_t	*msp;
	int		flag;

	msp = (manstr_t *)wq->q_ptr;

	if (MBLKL(mp) < DL_PROMISCON_REQ_SIZE) {
		dlerrorack(wq, mp, DL_PROMISCON_REQ, DL_BADPRIM, 0);
		return;
	}

	switch (((dl_promiscon_req_t *)mp->b_rptr)->dl_level) {
	case DL_PROMISC_PHYS:
		flag = MAN_SFLAG_ALLPHYS;
		break;

	case DL_PROMISC_SAP:
		flag = MAN_SFLAG_ALLSAP;
		break;

	case DL_PROMISC_MULTI:
		flag = MAN_SFLAG_ALLMULTI;
		break;

	default:
		dlerrorack(wq, mp, DL_PROMISCON_REQ, DL_NOTSUPPORTED, 0);
		return;
	}

	/*
	 * Catch request for replay, and forward down to any lower
	 * lower stream.
	 */
	if (man_dlpi(msp, mp)) {
		dlerrorack(wq, mp, DL_PROMISCON_REQ, DL_SYSERR, ENOMEM);
		return;
	}

	msp->ms_flags |= flag;

	dlokack(wq, mp, DL_PROMISCON_REQ);

}

static void
man_poffreq(queue_t *wq, mblk_t *mp)
{
	manstr_t		*msp;
	int			flag;

	msp = (manstr_t *)wq->q_ptr;

	if (MBLKL(mp) < DL_PROMISCOFF_REQ_SIZE) {
		dlerrorack(wq, mp, DL_PROMISCOFF_REQ, DL_BADPRIM, 0);
		return;
	}

	switch (((dl_promiscoff_req_t *)mp->b_rptr)->dl_level) {
	case DL_PROMISC_PHYS:
		flag = MAN_SFLAG_ALLPHYS;
		break;

	case DL_PROMISC_SAP:
		flag = MAN_SFLAG_ALLSAP;
		break;

	case DL_PROMISC_MULTI:
		flag = MAN_SFLAG_ALLMULTI;
		break;

	default:
		dlerrorack(wq, mp, DL_PROMISCOFF_REQ, DL_NOTSUPPORTED, 0);
		return;
	}

	if ((msp->ms_flags & flag) == 0) {
		dlerrorack(wq, mp, DL_PROMISCOFF_REQ, DL_NOTENAB, 0);
		return;
	}

	if (man_dlpi_senddown(msp, mp)) {
		dlerrorack(wq, mp, DL_PROMISCOFF_REQ, DL_SYSERR, ENOMEM);
		return;
	}

	man_dl_release(&msp->ms_dl_mp, mp);

	msp->ms_flags &= ~flag;

	dlokack(wq, mp, DL_PROMISCOFF_REQ);

}

/*
 * Enable multicast requests. We might need to track addresses instead of
 * just passing things through (see eri_dmreq) - TBD.
 */
static void
man_emreq(queue_t *wq, mblk_t *mp)
{
	manstr_t		*msp;
	union DL_primitives	*dlp;
	eaddr_t			*addrp;
	t_uscalar_t		off;
	t_uscalar_t		len;

	msp = (manstr_t *)wq->q_ptr;

	if (MBLKL(mp) < DL_ENABMULTI_REQ_SIZE) {
		dlerrorack(wq, mp, DL_ENABMULTI_REQ, DL_BADPRIM, 0);
		return;
	}

	if (msp->ms_dlpistate == DL_UNATTACHED) {
		dlerrorack(wq, mp, DL_ENABMULTI_REQ, DL_OUTSTATE, 0);
		return;
	}

	dlp = (union DL_primitives *)mp->b_rptr;
	len = dlp->enabmulti_req.dl_addr_length;
	off = dlp->enabmulti_req.dl_addr_offset;
	addrp = (struct ether_addr *)(mp->b_rptr + off);

	if ((len != ETHERADDRL) ||
	    !MBLKIN(mp, off, len) ||
	    ((addrp->ether_addr_octet[0] & 01) == 0)) {
		dlerrorack(wq, mp, DL_ENABMULTI_REQ, DL_BADADDR, 0);
		return;
	}

	/*
	 * Catch request for replay, and forward down to any lower
	 * lower stream.
	 */
	if (man_dlpi(msp, mp)) {
		dlerrorack(wq, mp, DL_ENABMULTI_REQ, DL_SYSERR, ENOMEM);
		return;
	}

	dlokack(wq, mp, DL_ENABMULTI_REQ);

}

static void
man_dmreq(queue_t *wq, mblk_t *mp)
{
	manstr_t		*msp;
	union DL_primitives	*dlp;
	eaddr_t			*addrp;
	t_uscalar_t		off;
	t_uscalar_t		len;

	msp = (manstr_t *)wq->q_ptr;

	if (MBLKL(mp) < DL_DISABMULTI_REQ_SIZE) {
		dlerrorack(wq, mp, DL_DISABMULTI_REQ, DL_BADPRIM, 0);
		return;
	}

	if (msp->ms_dlpistate == DL_UNATTACHED) {
		dlerrorack(wq, mp, DL_ENABMULTI_REQ, DL_OUTSTATE, 0);
		return;
	}

	dlp = (union DL_primitives *)mp->b_rptr;
	len = dlp->enabmulti_req.dl_addr_length;
	off = dlp->enabmulti_req.dl_addr_offset;
	addrp = (struct ether_addr *)(mp->b_rptr + off);

	if ((len != ETHERADDRL) ||
	    !MBLKIN(mp, off, len) ||
	    ((addrp->ether_addr_octet[0] & 01) == 0)) {
		dlerrorack(wq, mp, DL_ENABMULTI_REQ, DL_BADADDR, 0);
		return;
	}

	if (man_dlpi_senddown(msp, mp)) {
		dlerrorack(wq, mp, DL_ENABMULTI_REQ, DL_SYSERR, ENOMEM);
		return;
	}

	man_dl_release(&msp->ms_dl_mp, mp);

	dlokack(wq, mp, DL_DISABMULTI_REQ);

}

static void
man_pareq(queue_t *wq, mblk_t *mp)
{
	manstr_t		*msp;
	union	DL_primitives	*dlp;
	uint32_t		type;
	struct	ether_addr	addr;

	msp = (manstr_t *)wq->q_ptr;

	if (MBLKL(mp) < DL_PHYS_ADDR_REQ_SIZE) {
		dlerrorack(wq, mp, DL_PHYS_ADDR_REQ, DL_BADPRIM, 0);
		return;
	}

	dlp = (union DL_primitives *)mp->b_rptr;
	type = dlp->physaddr_req.dl_addr_type;
	if (msp->ms_manp == NULL) {
		dlerrorack(wq, mp, DL_PHYS_ADDR_REQ, DL_OUTSTATE, 0);
		return;
	}

	switch (type) {
	case	DL_FACT_PHYS_ADDR:
		(void) localetheraddr((struct ether_addr *)NULL, &addr);
		break;

	case	DL_CURR_PHYS_ADDR:
		ether_bcopy(&msp->ms_manp->man_eaddr, &addr);
		break;

	default:
		dlerrorack(wq, mp, DL_PHYS_ADDR_REQ, DL_NOTSUPPORTED, 0);
		return;
	}

	dlphysaddrack(wq, mp, &addr, ETHERADDRL);
}

/*
 * TBD - this routine probably should be protected w/ an ndd
 * tuneable, or a man.conf parameter.
 */
static void
man_spareq(queue_t *wq, mblk_t *mp)
{
	manstr_t		*msp;
	union DL_primitives	*dlp;
	t_uscalar_t		off;
	t_uscalar_t		len;
	eaddr_t			*addrp;

	msp = (manstr_t *)wq->q_ptr;

	if (MBLKL(mp) < DL_SET_PHYS_ADDR_REQ_SIZE) {
		dlerrorack(wq, mp, DL_SET_PHYS_ADDR_REQ, DL_BADPRIM, 0);
		return;
	}

	dlp = (union DL_primitives *)mp->b_rptr;
	len = dlp->set_physaddr_req.dl_addr_length;
	off = dlp->set_physaddr_req.dl_addr_offset;

	if (!MBLKIN(mp, off, len)) {
		dlerrorack(wq, mp, DL_SET_PHYS_ADDR_REQ, DL_BADPRIM, 0);
		return;
	}

	addrp = (struct ether_addr *)(mp->b_rptr + off);

	/*
	 * Error if length of address isn't right or the address
	 * specified is a multicast or broadcast address.
	 */
	if ((len != ETHERADDRL) ||
	    ((addrp->ether_addr_octet[0] & 01) == 1) ||
	    (ether_cmp(addrp, &etherbroadcast) == 0)) {
		dlerrorack(wq, mp, DL_SET_PHYS_ADDR_REQ, DL_BADADDR, 0);
		return;
	}
	/*
	 * Error if this stream is not attached to a device.
	 */
	if (msp->ms_manp == NULL) {
		dlerrorack(wq, mp, DL_SET_PHYS_ADDR_REQ, DL_OUTSTATE, 0);
		return;
	}

	/*
	 * We will also resend DL_SET_PHYS_ADDR_REQ for each dest
	 * when it is linked under us.
	 */
	if (man_dlpi_senddown(msp, mp)) {
		dlerrorack(wq, mp, DL_SET_PHYS_ADDR_REQ, DL_SYSERR, ENOMEM);
		return;
	}

	ether_copy(addrp, msp->ms_manp->man_eaddr.ether_addr_octet);

	MAN_DBG(MAN_DLPI, ("man_sareq: snagged %s\n",
	    ether_sprintf(&msp->ms_manp->man_eaddr)));

	dlokack(wq, mp, DL_SET_PHYS_ADDR_REQ);

}

/*
 * These routines make up the lower part of the MAN streams framework.
 */

/*
 * man_lwsrv - Deferred mblks for down stream. We end up here when
 * the destination is not DL_IDLE when traffic comes downstream.
 *
 *	wq - lower write queue of mxx
 */
static int
man_lwsrv(queue_t *wq)
{
	mblk_t		*mp;
	mblk_t		*mlistp;
	man_dest_t	*mdp;
	size_t		count;

	mdp = (man_dest_t *)wq->q_ptr;

	MAN_DBG(MAN_LWSRV, ("man_lwsrv: wq(0x%p) mdp(0x%p)"
	    " md_rq(0x%p)\n", (void *)wq, (void *)mdp,
	    mdp ? (void *)mdp->md_rq : NULL));

	if (mdp == NULL)
		goto exit;

	if (mdp->md_state & MAN_DSTATE_CLOSING) {
			flushq(wq, FLUSHDATA);
			flushq(RD(wq), FLUSHDATA);
			goto exit;
	}

	/*
	 * Arrange to send deferred mp's first, then mblks on the
	 * service queue. Since we are exclusive in the inner perimeter,
	 * we dont have to worry about md_lock, like the put procedures,
	 * which are MTPUTSHARED.
	 */
	mutex_enter(&mdp->md_lock);
	mlistp = mdp->md_dmp_head;
	mdp->md_dmp_head = NULL;
	count = mdp->md_dmp_count;
	mdp->md_dmp_count = 0;
	mutex_exit(&mdp->md_lock);

	while (mlistp != NULL) {
		mp = mlistp;
		mlistp = mp->b_next;
		mp->b_next = NULL;
		count -= msgsize(mp);
		if (man_start_lower(mdp, mp, NULL, MAN_LOWER)) {

			mutex_enter(&mdp->md_lock);
			mdp->md_dmp_count += count + msgsize(mp);
			mp->b_next = mlistp;
			mdp->md_dmp_head = mp;
			mutex_exit(&mdp->md_lock);
			goto exit;
		}
	}
	mdp->md_dmp_tail = NULL;

	while (mp = getq(wq)) {
		if (man_start_lower(mdp, mp, NULL, MAN_LOWER)) {
			/*
			 * Put it back on queue, making sure to avoid
			 * infinite loop mentioned in putbq(9F)
			 */
			noenable(wq);
			(void) putbq(wq, mp);
			enableok(wq);

			break;
		}
	}

exit:

	return (0);
}

/*
 * man_lrput - handle DLPI messages issued from downstream.
 *
 *	rq - lower read queue of mxx
 *	mp - mblk ptr to DLPI request
 *
 *	returns 0
 */
static int
man_lrput(queue_t *rq, mblk_t *mp)
{
	man_dest_t	*mdp;
	manstr_t	*msp;

#if defined(DEBUG)
	union DL_primitives	*dlp;
	t_uscalar_t		prim = MAN_DLPI_MAX_PRIM + 1;
	char			*prim_str;
#endif  /* DEBUG */

	mdp = (man_dest_t *)rq->q_ptr;

#if defined(DEBUG)
	if (DB_TYPE(mp) == M_PROTO) {
		dlp = (union DL_primitives *)mp->b_rptr;
		prim = dlp->dl_primitive;
	}

	prim_str = (prim > MAN_DLPI_MAX_PRIM) ? "NON DLPI" :
	    (prim == DL_IOC_HDR_INFO) ? "DL_IOC_HDR_INFO" :
	    (prim == DLIOCRAW) ? "DLIOCRAW" :
	    dps[(unsigned int)prim];
	MAN_DBG(MAN_LRPUT, ("man_lrput: rq(0x%p) mp(0x%p) mdp(0x%p)"
	    " db_type(0x%x) dl_prim %s", (void *)rq,
	    (void *)mp, (void *)mdp, DB_TYPE(mp), prim_str));
	MAN_DBGCALL(MAN_LRPUT2, man_print_mdp(mdp));
#endif  /* DEBUG */

	if (DB_TYPE(mp) == M_FLUSH) {
		/* Turn around */
		if (*mp->b_rptr & FLUSHW) {
			*mp->b_rptr &= ~FLUSHR;
			qreply(rq, mp);
		} else
			freemsg(mp);
		return (0);
	}

	if (mdp == NULL || mdp->md_state != MAN_DSTATE_READY) {

		MAN_DBG(MAN_LRPUT, ("man_lrput: not ready mdp(0x%p),"
		    " state(%d)", (void *)mdp, mdp ? mdp->md_state : -1));
		freemsg(mp);
		return (0);
	}

	/*
	 * If we have a destination in the right state, forward on datagrams.
	 */
	if (MAN_IS_DATA(mp)) {
		if (mdp->md_dlpistate == DL_IDLE && canputnext(mdp->md_rq)) {

			msp = mdp->md_msp;
			if (!(msp->ms_flags & MAN_SFLAG_PROMISC))
				mdp->md_rcvcnt++; /* Count for failover */
			/*
			 * go put mblk_t directly up to next queue.
			 */
			MAN_DBG(MAN_LRPUT, ("man_lrput: putnext to rq(0x%p)",
			    (void *)mdp->md_rq));
			(void) putnext(mdp->md_rq, mp);
		} else {
			freemsg(mp);
		}
	} else {
		/*
		 * Handle in man_lrsrv with exclusive inner perimeter lock.
		 */
		(void) putq(rq, mp);
	}

	return (0);
}

/*
 * Either this is a response from our attempt to sync the upper and lower
 * stream states, or its data. If its not data. Do DL_* response processing
 * and transition md_dlpistate accordingly. If its data, toss it.
 */
static int
man_lrsrv(queue_t *rq)
{
	man_dest_t		*mdp;
	mblk_t			*mp;
	union DL_primitives	*dlp;
	ulong_t			prim;
	ulong_t			cprim;
	int			need_dl_reset = FALSE;

#if defined(DEBUG)
		struct iocblk	*iocp;
		char		ioc_cmd[256];
#endif  /* DEBUG */

	MAN_DBG(MAN_LRSRV, ("man_lrsrv: rq(0x%p)", (void *)rq));

	mdp = (man_dest_t *)rq->q_ptr;

	if ((mdp == NULL) || (mdp->md_state & MAN_DSTATE_CLOSING)) {
			flushq(rq, FLUSHDATA);
			flushq(WR(rq), FLUSHDATA);
			goto exit;
	}

	while (mp = getq(rq)) {


	/*
	 * If we're not connected, or its a datagram, toss it.
	 */
	if (MAN_IS_DATA(mp) || mdp->md_state != MAN_DSTATE_READY) {

		MAN_DBG(MAN_LRSRV, ("man_lrsrv: dropping mblk mdp(0x%p)"
		    " is_data(%d)", (void *)mdp, MAN_IS_DATA(mp)));
		freemsg(mp);
		continue;
	}

	/*
	 * Should be response to man_dlpi_replay. Discard unless there
	 * is a failure we care about.
	 */

	switch (DB_TYPE(mp)) {
	case M_PROTO:
	case M_PCPROTO:
		/* Do proto processing below. */
		break;

	case M_IOCNAK:
		/*
		 * DL_IOC* failed for some reason.
		 */
		need_dl_reset = TRUE;

#if defined(DEBUG)
		iocp = (struct iocblk *)mp->b_rptr;

		(void) sprintf(ioc_cmd, "0x%x", iocp->ioc_cmd);
		MAN_DBG(MAN_LRSRV, ("man_lrsrv: M_IOCNAK err %d for cmd(%s)\n",
		    iocp->ioc_error,
		    (iocp->ioc_cmd == DL_IOC_HDR_INFO) ? "DL_IOC_HDR_INFO" :
		    (iocp->ioc_cmd == DLIOCRAW) ? "DLIOCRAW" : ioc_cmd));
#endif  /* DEBUG */

		/* FALLTHRU */

	case M_IOCACK:
	case M_CTL:
		/*
		 * OK response from DL_IOC*, ignore.
		 */
		goto dl_reset;
	}

	dlp = (union DL_primitives *)mp->b_rptr;
	prim = dlp->dl_primitive;

	MAN_DBG(MAN_LRSRV, ("man_lrsrv: prim %s", dps[(int)prim]));

	/*
	 * DLPI state processing big theory: We do not rigorously check
	 * DLPI states (e.g. PENDING stuff). Simple rules:
	 *
	 * 	1) If we see an OK_ACK to an ATTACH_REQ, dlpistate = DL_UNBOUND.
	 *	2) If we see an BIND_ACK to a BIND_REQ, dlpistate = DL_IDLE.
	 *	3) If we see a OK_ACK response to an UNBIND_REQ
	 *	   dlpistate = DL_UNBOUND.
	 *	4) If we see a OK_ACK response to a DETACH_REQ,
	 *	   dlpistate = DL_UNATTACHED.
	 *
	 * Everything that isn't handle by 1-4 above is handled by 5)
	 *
	 *	5) A NAK to any DL_* messages we care about causes
	 *	   dlpistate = DL_UNATTACHED and man_reset_dlpi to run
	 *
	 * TBD - need a reset counter so we can try a switch if it gets
	 * too high.
	 */

	switch (prim) {
	case DL_OK_ACK:
		cprim = dlp->ok_ack.dl_correct_primitive;

		switch (cprim) {
		case DL_ATTACH_REQ:
			if (man_dlioc_replay(mdp)) {
				D_SETSTATE(mdp, DL_UNBOUND);
			} else {
				need_dl_reset = TRUE;
				break;
			}
			break;

		case DL_DETACH_REQ:
			D_SETSTATE(mdp, DL_UNATTACHED);
			break;

		case DL_UNBIND_REQ:
			/*
			 * Cancel timer and set md_dlpistate.
			 */
			D_SETSTATE(mdp, DL_UNBOUND);

			ASSERT(mdp->md_bc_id == 0);
			if (mdp->md_lc_timer_id != 0) {
				(void) quntimeout(man_ctl_wq,
				    mdp->md_lc_timer_id);
				mdp->md_lc_timer_id = 0;
			}
		}
		MAN_DBG(MAN_DLPI,
		    ("		cprim %s", dps[(int)cprim]));
		break;

	case DL_BIND_ACK:
		/*
		 * We're ready for data. Get man_lwsrv to run to
		 * process any defered data and start linkcheck timer.
		 */
		D_SETSTATE(mdp, DL_IDLE);
		qenable(mdp->md_wq);
		mdp->md_linkstate = MAN_LINKGOOD;
		if (man_needs_linkcheck(mdp)) {
			mdp->md_lc_timer_id = qtimeout(man_ctl_wq,
			    man_linkcheck_timer, (void *)mdp,
			    man_gettimer(MAN_TIMER_LINKCHECK, mdp));
		}

		break;

	case DL_ERROR_ACK:
		cprim = dlp->error_ack.dl_error_primitive;
		switch (cprim) {
		case DL_ATTACH_REQ:
		case DL_BIND_REQ:
		case DL_DISABMULTI_REQ:
		case DL_ENABMULTI_REQ:
		case DL_PROMISCON_REQ:
		case DL_PROMISCOFF_REQ:
		case DL_SET_PHYS_ADDR_REQ:
			need_dl_reset = TRUE;
			break;

		/*
		 * ignore error TBD (better comment)
		 */
		case DL_UNBIND_REQ:
		case DL_DETACH_REQ:
			break;
		}

		MAN_DBG(MAN_DLPI,
		    ("\tdl_errno %d dl_unix_errno %d cprim %s",
		    dlp->error_ack.dl_errno, dlp->error_ack.dl_unix_errno,
		    dps[(int)cprim]));
		break;

	case DL_UDERROR_IND:
		MAN_DBG(MAN_DLPI,
		    ("\tdl_errno %d unix_errno %d",
		    dlp->uderror_ind.dl_errno,
		    dlp->uderror_ind.dl_unix_errno));
		break;

	case DL_INFO_ACK:
		break;

	default:
		/*
		 * We should not get here.
		 */
		cmn_err(CE_WARN, "man_lrsrv: unexpected DL prim 0x%lx!",
		    prim);
		need_dl_reset = TRUE;
		break;
	}

dl_reset:
	freemsg(mp);

	if (need_dl_reset) {
		man_pg_t	*mpg;
		man_path_t	*mp;

		if (qsize(rq)) {	/* Dump all messages. */
			flushq(rq, FLUSHDATA);
			flushq(WR(rq), FLUSHDATA);
		}

		mdp->md_dlpierrors++;
		D_SETSTATE(mdp, DL_UNATTACHED);
		if (mdp->md_lc_timer_id != 0) {
			(void) quntimeout(man_ctl_wq, mdp->md_lc_timer_id);
			mdp->md_lc_timer_id = 0;
		}

		mutex_enter(&man_lock);
		ASSERT(mdp->md_msp != NULL);
		ASSERT(mdp->md_msp->ms_manp != NULL);
		mpg = man_find_pg_by_id(mdp->md_msp->ms_manp->man_pg,
		    mdp->md_pg_id);
		ASSERT(mpg != NULL);
		mp = man_find_path_by_ppa(mpg->mpg_pathp,
		    mdp->md_device.mdev_ppa);
		ASSERT(mp != NULL);
		mp->mp_device.mdev_state |= MDEV_FAILED;
		if ((mdp->md_dlpierrors >= MAN_MAX_DLPIERRORS) &&
		    (man_is_on_domain ||
		    mdp->md_msp->ms_manp->man_meta_ppa == 1)) {
			/*
			 * Autoswitching is disabled for instance 0
			 * on the SC as we expect the domain to
			 * initiate the path switching.
			 */
			(void) man_do_autoswitch((man_dest_t *)mdp);
			MAN_DBG(MAN_WARN, ("man_lrsrv: dlpi failure(%d,%d),"
			    " switching path", mdp->md_device.mdev_major,
			    mdp->md_device.mdev_ppa));
		} else {
			mdp->md_lc_timer_id = qtimeout(man_ctl_wq,
			    man_reset_dlpi, (void *)mdp,
			    man_gettimer(MAN_TIMER_DLPIRESET, mdp));
		}
		mutex_exit(&man_lock);
	}


	} /* End while (getq()) */

exit:
	MAN_DBG(MAN_DLPI, ("man_lrsrv: returns"));

	return (0);
}

static int
man_needs_linkcheck(man_dest_t *mdp)
{
	/*
	 * Not ready for linkcheck.
	 */
	if (mdp->md_msp == NULL || mdp->md_msp->ms_manp == NULL)
		return (0);

	/*
	 * Linkchecking needs to be done on IP streams. For domain, all
	 * driver instances need checking, for SC only instance 1 needs it.
	 */
	if ((man_is_on_domain || mdp->md_msp->ms_manp->man_meta_ppa == 1) &&
	    (mdp->md_msp->ms_sap == ETHERTYPE_IP ||
	    mdp->md_msp->ms_sap == ETHERTYPE_IPV6))

		return (1);

	/*
	 * Linkcheck not need on this link.
	 */
	return (0);
}

/*
 * The following routines process work requests posted to man_iwork_q
 * from the non-STREAMS half of the driver (see man_bwork.c). The work
 * requires access to the inner perimeter lock of the driver. This
 * lock is acquired by man_uwsrv, who calls man_iwork to process the
 * man_iwork_q->
 */

/*
 * The man_bwork has posted some work for us to do inside the
 * perimeter. This mainly involves updating lower multiplexor data
 * structures (non-blocking type stuff). So, we can hold the man_lock
 * until we are done processing all work items. Note that some of these
 * routines in turn submit work back to the bgthread, which they can do
 * since we hold the man_lock.
 */
static void
man_iwork()
{
	man_work_t	*wp;
	int		wp_finished;

	MAN_DBG(MAN_SWITCH, ("man_iwork: q_work(0x%p)",
	    (void *)man_iwork_q->q_work));

	mutex_enter(&man_lock);

	while (man_iwork_q->q_work) {

		wp = man_iwork_q->q_work;
		man_iwork_q->q_work = wp->mw_next;
		wp->mw_next = NULL;

		mutex_exit(&man_lock);

		MAN_DBG(MAN_SWITCH, ("man_iwork: type %s",
		    _mw_type[wp->mw_type]));

		wp_finished = TRUE;

		switch (wp->mw_type) {
		case MAN_WORK_DRATTACH:
			(void) man_do_dr_attach(wp);
			break;

		case MAN_WORK_DRSWITCH:
			/*
			 * Return status to man_dr_detach immediately. If
			 * no error submitting SWITCH request, man_iswitch
			 * or man_bclose will cv_signal man_dr_detach on
			 * completion of SWITCH work request.
			 */
			if (man_do_dr_switch(wp) == 0)
				wp_finished = FALSE;
			break;

		case MAN_WORK_DRDETACH:
			man_do_dr_detach(wp);
			break;

		case MAN_WORK_SWITCH:
			if (man_iswitch(wp))
				wp_finished = FALSE;
			break;

		case MAN_WORK_KSTAT_UPDATE:
			man_do_kstats(wp);
			break;

		default:
			cmn_err(CE_WARN, "man_iwork: "
			    "illegal work type(%d)", wp->mw_type);
			break;
		}

		mutex_enter(&man_lock);

		/*
		 * If we've completed the work request, delete, or
		 * cv_signal waiter.
		 */
		if (wp_finished) {
			wp->mw_flags |= MAN_WFLAGS_DONE;

			if (wp->mw_flags & MAN_WFLAGS_CVWAITER)
				cv_signal(&wp->mw_cv);
			else
				man_work_free(wp);
		}
	}

	mutex_exit(&man_lock);
}

/*
 * man_dr_detach has submitted a request to DRSWITCH a path.
 * It is in cv_wait_sig(wp->mw_cv). We forward the work request on to
 * man_bwork as a switch request. It should end up back at
 * man_iwork, who will cv_signal(wp->mw_cv) man_dr_detach.
 *
 * Called holding inner perimeter lock.
 * man_lock is held to synchronize access to pathgroup list(man_pg).
 */
static int
man_do_dr_switch(man_work_t *wp)
{
	man_t		*manp;
	man_pg_t	*mpg;
	man_path_t	*mp;
	man_path_t	*ap;
	man_adest_t	*adp;
	mi_path_t	mpath;
	int		status = 0;

	adp = &wp->mw_arg;

	MAN_DBG(MAN_SWITCH, ("man_do_dr_switch: pg_id %d work:", adp->a_pg_id));
	MAN_DBGCALL(MAN_SWITCH, man_print_work(wp));

	mutex_enter(&man_lock);
	manp = ddi_get_soft_state(man_softstate, adp->a_man_ppa);
	if (manp == NULL || manp->man_pg == NULL) {
		status = ENODEV;
		goto exit;
	}

	mpg = man_find_pg_by_id(manp->man_pg, adp->a_pg_id);
	if (mpg == NULL) {
		status = ENODEV;
		goto exit;
	}

	if (mpg->mpg_flags & MAN_PG_SWITCHING) {
		status = EAGAIN;
		goto exit;
	}

	/*
	 * Check to see if detaching device is active. If so, activate
	 * an alternate.
	 */
	mp = man_find_active_path(mpg->mpg_pathp);
	if (mp && mp->mp_device.mdev_ppa == adp->a_sf_dev.mdev_ppa) {

		ap = man_find_alternate_path(mpg->mpg_pathp);
		if (ap == NULL) {
			status = EBUSY;
			goto exit;
		}

		bzero((char *)&mpath, sizeof (mi_path_t));

		mpath.mip_cmd = MI_PATH_ACTIVATE;
		mpath.mip_man_ppa = 0;
		mpath.mip_pg_id = 0;
		mpath.mip_devs[0] = ap->mp_device;
		mpath.mip_ndevs = 1;
		ether_copy(&manp->man_eaddr, &mpath.mip_eaddr);

		/*
		 * DR thread is sleeping on wp->mw_cv. We change the work
		 * request from DRSWITCH to SWITCH and submit it to
		 * for processing by man_bwork (via man_pg_cmd). At
		 * completion the SWITCH work request is processed by
		 * man_iswitch() or man_bclose and the DR thread will
		 * be cv_signal'd.
		 */
		wp->mw_type = MAN_WORK_SWITCH;
		if (status = man_pg_cmd(&mpath, wp))
			goto exit;

	} else {
		/*
		 * Tell man_dr_detach that detaching device is not currently
		 * in use.
		 */
		status = ENODEV;
	}

exit:
	if (status) {
		/*
		 * ENODEV is a noop, not really an error.
		 */
		if (status != ENODEV)
			wp->mw_status = status;
	}
	mutex_exit(&man_lock);

	return (status);
}

/*
 * man_dr_attach has submitted a request to DRATTACH a path,
 * add that path to the path list.
 *
 * Called holding perimeter lock.
 */
static int
man_do_dr_attach(man_work_t *wp)
{
	man_t		*manp;
	man_adest_t	*adp;
	mi_path_t	mpath;
	manc_t		manc;
	int		status = 0;

	adp = &wp->mw_arg;

	MAN_DBG(MAN_SWITCH, ("man_do_dr_attach: pg_id %d work:", adp->a_pg_id));
	MAN_DBGCALL(MAN_SWITCH, man_print_work(wp));

	mutex_enter(&man_lock);
	manp = ddi_get_soft_state(man_softstate, adp->a_man_ppa);
	if (manp == NULL || manp->man_pg == NULL) {
		status = ENODEV;
		goto exit;
	}

	if (status = man_get_iosram(&manc)) {
		goto exit;
	}
	/*
	 * Extract SC ethernet address from IOSRAM.
	 */
	ether_copy(&manc.manc_sc_eaddr, &mpath.mip_eaddr);

	mpath.mip_pg_id = adp->a_pg_id;
	mpath.mip_man_ppa = adp->a_man_ppa;
	/*
	 * man_dr_attach passes the new device info in a_sf_dev.
	 */
	MAN_DBG(MAN_DR, ("man_do_dr_attach: "));
	MAN_DBGCALL(MAN_DR, man_print_dev(&adp->a_sf_dev));
	mpath.mip_devs[0] = adp->a_sf_dev;
	mpath.mip_ndevs = 1;
	mpath.mip_cmd = MI_PATH_ADD;
	status = man_pg_cmd(&mpath, NULL);

exit:
	mutex_exit(&man_lock);
	return (status);
}

/*
 * man_dr_detach has submitted a request to DRDETACH a path.
 * It is in cv_wait_sig(wp->mw_cv). We remove the path and
 * cv_signal(wp->mw_cv) man_dr_detach.
 *
 * Called holding perimeter lock.
 */
static void
man_do_dr_detach(man_work_t *wp)
{
	man_t		*manp;
	man_pg_t	*mpg;
	man_path_t	*mp;
	man_adest_t	*adp;
	manc_t		manc;
	mi_path_t	mpath;
	int		i;
	int		found;
	int		status = 0;

	adp = &wp->mw_arg;

	MAN_DBG(MAN_SWITCH, ("man_do_dr_detach: pg_id %d work:", adp->a_pg_id));
	MAN_DBGCALL(MAN_SWITCH, man_print_work(wp));

	mutex_enter(&man_lock);
	manp = ddi_get_soft_state(man_softstate, adp->a_man_ppa);
	if (manp == NULL || manp->man_pg == NULL) {
		status = ENODEV;
		goto exit;
	}

	mpg = man_find_pg_by_id(manp->man_pg, adp->a_pg_id);
	if (mpg == NULL) {
		status = ENODEV;
		goto exit;
	}

	if (mpg->mpg_flags & MAN_PG_SWITCHING) {
		status = EAGAIN;
		goto exit;
	}

	/*
	 * We should have switched detaching path if it was active.
	 */
	mp = man_find_active_path(mpg->mpg_pathp);
	if (mp && mp->mp_device.mdev_ppa == adp->a_sf_dev.mdev_ppa) {
		status = EAGAIN;
		goto exit;
	}

	/*
	 * Submit an ASSIGN command, minus the detaching device.
	 */
	bzero((char *)&mpath, sizeof (mi_path_t));

	if (status = man_get_iosram(&manc)) {
		goto exit;
	}

	mpath.mip_cmd = MI_PATH_ASSIGN;
	mpath.mip_man_ppa = 0;
	mpath.mip_pg_id = 0;

	mp = mpg->mpg_pathp;
	i = 0;
	found = FALSE;
	while (mp != NULL) {
		if (mp->mp_device.mdev_ppa != adp->a_sf_dev.mdev_ppa) {
			mpath.mip_devs[i] = mp->mp_device;
			i++;
		} else {
			found = TRUE;
		}
		mp = mp->mp_next;
	}

	if (found) {
		/*
		 * Need to include SCs ethernet address in command.
		 */
		mpath.mip_ndevs = i;
		ether_copy(&manc.manc_sc_eaddr, &mpath.mip_eaddr);

		status = man_pg_cmd(&mpath, NULL);
	}

	/*
	 * Hand back status to man_dr_detach request.
	 */
exit:
	if (status != ENODEV)
		wp->mw_status = status;

	mutex_exit(&man_lock);

}


/*
 * The background thread has configured new lower multiplexor streams for
 * the given destinations. Update the appropriate destination data structures
 * inside the inner perimeter. We must take care to deal with destinations
 * whose upper stream has closed or detached from lower streams.
 *
 * Returns
 *	0		Done with work request.
 *	1		Reused work request.
 */
static int
man_iswitch(man_work_t *wp)
{
	man_adest_t	*adp;
	man_t		*manp;
	man_pg_t	*mpg;
	man_path_t	*mp = NULL;
	man_dest_t	*mdp;
	man_dest_t	*tdp;
	int		i;
	int		switch_ok = TRUE;

	adp = &wp->mw_arg;

	if (wp->mw_status != 0) {
		switch_ok = FALSE;	/* Never got things opened */
	}

	/*
	 * Update destination structures as appropriate.
	 */
	for (i = 0; i < adp->a_ndests; i++) {
		man_dest_t	tmp;

		/*
		 * Check to see if lower stream we just switch is still
		 * around.
		 */
		tdp = &adp->a_mdp[i];
		mdp = man_switch_match(tdp, adp->a_pg_id, tdp->md_switch_id);

		if (mdp == NULL)
			continue;

		if (switch_ok == FALSE) {
			/*
			 * Switch failed for some reason.  Clear
			 * PLUMBING flag and retry switch again later.
			 */
			man_ifail_dest(mdp);
			continue;
		}

		/*
		 * Swap new info, for old. We return the old info to
		 * man_bwork to close things up below.
		 */
		bcopy((char *)mdp, (char *)&tmp, sizeof (man_dest_t));

		ASSERT(mdp->md_state & MAN_DSTATE_PLUMBING);
		ASSERT(mdp->md_state == tdp->md_state);

		mdp->md_state = tdp->md_state;

		/*
		 * save the wq from the destination passed(tdp).
		 */
		mdp->md_wq = tdp->md_wq;
		RD(mdp->md_wq)->q_ptr = (void *)(mdp);
		WR(mdp->md_wq)->q_ptr = (void *)(mdp);

		mdp->md_state &= ~MAN_DSTATE_INITIALIZING;
		mdp->md_state |= MAN_DSTATE_READY;

		ASSERT(mdp->md_device.mdev_major == adp->a_sf_dev.mdev_major);

		ASSERT(tdp->md_device.mdev_ppa == adp->a_st_dev.mdev_ppa);
		ASSERT(tdp->md_device.mdev_major == adp->a_st_dev.mdev_major);

		mdp->md_device = tdp->md_device;
		mdp->md_muxid = tdp->md_muxid;
		mdp->md_linkstate = MAN_LINKUNKNOWN;
		(void) drv_getparm(TIME, &mdp->md_lastswitch);
		mdp->md_state &= ~MAN_DSTATE_PLUMBING;
		mdp->md_switch_id = 0;
		mdp->md_switches++;
		mdp->md_dlpierrors = 0;
		D_SETSTATE(mdp, DL_UNATTACHED);

		/*
		 * Resync lower w/ upper dlpi state. This will start link
		 * timer if/when lower stream goes to DL_IDLE (see man_lrsrv).
		 */
		man_reset_dlpi((void *)mdp);

		bcopy((char *)&tmp, (char *)tdp, sizeof (man_dest_t));
	}

	if (switch_ok) {
		for (i = 0; i < adp->a_ndests; i++) {
			tdp = &adp->a_mdp[i];

			tdp->md_state &= ~MAN_DSTATE_PLUMBING;
			tdp->md_state &= ~MAN_DSTATE_INITIALIZING;
			tdp->md_state |= MAN_DSTATE_READY;
		}
	} else {
		/*
		 * Never got switch-to destinations open, free them.
		 */
		man_kfree(adp->a_mdp,
		    sizeof (man_dest_t) * adp->a_ndests);
	}

	/*
	 * Clear pathgroup switching flag and update path flags.
	 */
	mutex_enter(&man_lock);
	manp = ddi_get_soft_state(man_softstate, adp->a_man_ppa);

	ASSERT(manp != NULL);
	ASSERT(manp->man_pg != NULL);

	mpg = man_find_pg_by_id(manp->man_pg, adp->a_pg_id);
	ASSERT(mpg != NULL);
	ASSERT(mpg->mpg_flags & MAN_PG_SWITCHING);
	mpg->mpg_flags &= ~MAN_PG_SWITCHING;

	/*
	 * Switch succeeded, mark path we switched from as failed, and
	 * device we switch to as active and clear its failed flag (if set).
	 * Sync up kstats.
	 */
	if (switch_ok) {
		mp = man_find_active_path(mpg->mpg_pathp);
		if (mp != NULL) {

			ASSERT(adp->a_sf_dev.mdev_major != 0);

			MAN_DBG(MAN_SWITCH, ("man_iswitch: switch from dev:"));
			MAN_DBGCALL(MAN_SWITCH, man_print_dev(&adp->a_sf_dev));

			mp->mp_device.mdev_state &= ~MDEV_ACTIVE;
		} else
			ASSERT(adp->a_sf_dev.mdev_major == 0);

		MAN_DBG(MAN_SWITCH, ("man_iswitch: switch to dev:"));
		MAN_DBGCALL(MAN_SWITCH, man_print_dev(&adp->a_st_dev));

		ASSERT(adp->a_st_dev.mdev_major != 0);

		mp = man_find_path_by_ppa(mpg->mpg_pathp,
		    adp->a_st_dev.mdev_ppa);

		ASSERT(mp != NULL);

		mp->mp_device.mdev_state |= MDEV_ACTIVE;
	}

	/*
	 * Decrement manp reference count and hand back work request if
	 * needed.
	 */
	manp->man_refcnt--;

	if (switch_ok) {
		wp->mw_type = MAN_WORK_CLOSE;
		man_work_add(man_bwork_q, wp);
	}

	mutex_exit(&man_lock);

	return (switch_ok);
}

/*
 * Find the destination in the upper stream that we just switched.
 */
man_dest_t *
man_switch_match(man_dest_t *sdp, int pg_id, void *sid)
{
	man_dest_t	*mdp = NULL;
	manstr_t	*msp;

	for (msp = man_strup; msp != NULL; msp = msp->ms_next) {
		/*
		 * Check if upper stream closed, or detached.
		 */
		if (msp != sdp->md_msp)
			continue;

		if (msp->ms_dests == NULL)
			break;

		mdp = &msp->ms_dests[pg_id];

		/*
		 * Upper stream detached and reattached while we were
		 * switching.
		 */
		if (mdp->md_switch_id != sid) {
			mdp = NULL;
			break;
		}
	}

	return (mdp);
}

/*
 * bg_thread cant complete the switch for some reason. (Re)start the
 * linkcheck timer again.
 */
static void
man_ifail_dest(man_dest_t *mdp)
{
	ASSERT(mdp->md_lc_timer_id == 0);
	ASSERT(mdp->md_bc_id == 0);
	ASSERT(mdp->md_state & MAN_DSTATE_PLUMBING);

	MAN_DBG(MAN_SWITCH, ("man_ifail_dest"));
	MAN_DBGCALL(MAN_SWITCH, man_print_mdp(mdp));

	mdp->md_state &= ~MAN_DSTATE_PLUMBING;
	mdp->md_linkstate = MAN_LINKFAIL;

	/*
	 * If we have not yet initialized link, or the upper stream is
	 * DL_IDLE, restart the linktimer.
	 */
	if ((mdp->md_state & MAN_DSTATE_INITIALIZING) ||
	    ((mdp->md_msp->ms_sap == ETHERTYPE_IPV6 ||
	    mdp->md_msp->ms_sap == ETHERTYPE_IP) &&
	    mdp->md_msp->ms_dlpistate == DL_IDLE)) {

		mdp->md_lc_timer_id = qtimeout(man_ctl_wq, man_linkcheck_timer,
		    (void *)mdp, man_gettimer(MAN_TIMER_LINKCHECK, mdp));
	}

}

/*
 * Arrange to replay all of ms_dl_mp on the new lower stream to get it
 * in sync with the upper stream. Note that this includes setting the
 * physical address.
 *
 * Called from qtimeout with inner perimeter lock.
 */
static void
man_reset_dlpi(void *argp)
{
	man_dest_t	*mdp = (man_dest_t *)argp;
	manstr_t	*msp;
	mblk_t		*mp;
	mblk_t		*rmp = NULL;
	mblk_t		*tmp;

	mdp->md_lc_timer_id = 0;

	if (mdp->md_state != MAN_DSTATE_READY) {
		MAN_DBG(MAN_DLPI, ("man_reset_dlpi: not ready!"));
		return;
	}

	msp = mdp->md_msp;

	rmp = man_dup_mplist(msp->ms_dl_mp);
	if (rmp == NULL)
		goto fail;

	/*
	 * Send down an unbind and detach request, just to clean things
	 * out, we ignore ERROR_ACKs for unbind and detach in man_lrsrv.
	 */
	tmp = man_alloc_ubreq_dreq();
	if (tmp == NULL) {
		goto fail;
	}
	mp = tmp;
	while (mp->b_next != NULL)
		mp = mp->b_next;
	mp->b_next = rmp;
	rmp = tmp;

	man_dlpi_replay(mdp, rmp);

	return;

fail:

	while (rmp) {
		mp = rmp;
		rmp = rmp->b_next;
		mp->b_next = mp->b_prev = NULL;
		freemsg(mp);
	}

	ASSERT(mdp->md_lc_timer_id == 0);
	ASSERT(mdp->md_bc_id == 0);

	/*
	 * If low on memory, try again later. I Could use qbufcall, but that
	 * could fail and I would have to try and recover from that w/
	 * qtimeout anyway.
	 */
	mdp->md_lc_timer_id = qtimeout(man_ctl_wq, man_reset_dlpi,
	    (void *)mdp, man_gettimer(MAN_TIMER_LINKCHECK, mdp));
}

/*
 * Once we receive acknowledgement that DL_ATTACH_REQ was successful,
 * we can send down the DL_* related IOCTLs (e.g. DL_IOC_HDR). If we
 * try and send them downsteam w/o waiting, the ioctl's get processed before
 * the ATTACH_REQ and they are rejected. TBD - could just do the lower
 * dlpi state change in lock step. TBD
 */
static int
man_dlioc_replay(man_dest_t *mdp)
{
	mblk_t		*rmp;
	int		status = 1;

	if (mdp->md_msp->ms_dlioc_mp == NULL)
		goto exit;

	rmp = man_dup_mplist(mdp->md_msp->ms_dlioc_mp);
	if (rmp == NULL) {
		status = 0;
		goto exit;
	}

	man_dlpi_replay(mdp, rmp);
exit:
	return (status);
}

static mblk_t *
man_alloc_ubreq_dreq()
{
	mblk_t			*dreq;
	mblk_t			*ubreq = NULL;
	union DL_primitives	*dlp;

	dreq = allocb(DL_DETACH_REQ_SIZE, BPRI_MED);
	if (dreq == NULL)
		goto exit;

	dreq->b_datap->db_type = M_PROTO;
	dlp = (union DL_primitives *)dreq->b_rptr;
	dlp->dl_primitive = DL_DETACH_REQ;
	dreq->b_wptr += DL_DETACH_REQ_SIZE;

	ubreq = allocb(DL_UNBIND_REQ_SIZE, BPRI_MED);
	if (ubreq == NULL) {
		freemsg(dreq);
		goto exit;
	}

	ubreq->b_datap->db_type = M_PROTO;
	dlp = (union DL_primitives *)ubreq->b_rptr;
	dlp->dl_primitive = DL_UNBIND_REQ;
	ubreq->b_wptr += DL_UNBIND_REQ_SIZE;

	ubreq->b_next = dreq;

exit:

	return (ubreq);
}

static mblk_t *
man_dup_mplist(mblk_t *mp)
{
	mblk_t	*listp = NULL;
	mblk_t	*tailp = NULL;

	for (; mp != NULL; mp = mp->b_next) {

		mblk_t	*nmp;
		mblk_t	*prev;
		mblk_t	*next;

		prev = mp->b_prev;
		next = mp->b_next;
		mp->b_prev = mp->b_next = NULL;

		nmp = copymsg(mp);

		mp->b_prev = prev;
		mp->b_next = next;

		if (nmp == NULL)
			goto nomem;

		if (listp == NULL) {
			listp = tailp = nmp;
		} else {
			tailp->b_next = nmp;
			tailp = nmp;
		}
	}

	return (listp);
nomem:

	while (listp) {
		mp = listp;
		listp = mp->b_next;
		mp->b_next = mp->b_prev = NULL;
		freemsg(mp);
	}

	return (NULL);

}

static mblk_t *
man_alloc_physreq_mp(eaddr_t *man_eap)
{

	mblk_t			*mp;
	union DL_primitives	*dlp;
	t_uscalar_t		off;
	eaddr_t			*eap;

	mp = allocb(DL_SET_PHYS_ADDR_REQ_SIZE + ETHERADDRL, BPRI_MED);
	if (mp == NULL)
		goto exit;

	mp->b_datap->db_type = M_PROTO;
	dlp = (union DL_primitives *)mp->b_wptr;
	dlp->set_physaddr_req.dl_primitive = DL_SET_PHYS_ADDR_REQ;
	dlp->set_physaddr_req.dl_addr_length = ETHERADDRL;
	off = DL_SET_PHYS_ADDR_REQ_SIZE;
	dlp->set_physaddr_req.dl_addr_offset =  off;
	mp->b_wptr += DL_SET_PHYS_ADDR_REQ_SIZE + ETHERADDRL;

	eap = (eaddr_t *)(mp->b_rptr + off);
	ether_copy(man_eap, eap);

exit:
	MAN_DBG(MAN_DLPI, ("man_alloc_physreq: physaddr %s\n",
	    ether_sprintf(eap)));

	return (mp);
}

/*
 * A new path in a pathgroup has become active for the first time. Setup
 * the lower destinations in prepartion for man_pg_activate to call
 * man_autoswitch.
 */
static void
man_add_dests(man_pg_t *mpg)
{
	manstr_t	*msp;
	man_dest_t	*mdp;

	for (msp = man_strup; msp != NULL; msp = msp->ms_next) {

		if (!man_str_uses_pg(msp, mpg))
			continue;

		mdp = &msp->ms_dests[mpg->mpg_pg_id];

/*
 * TBD - Take out
 *		ASSERT(mdp->md_device.mdev_state == MDEV_UNASSIGNED);
 *		ASSERT(mdp->md_state == MAN_DSTATE_NOTPRESENT);
 */
		if (mdp->md_device.mdev_state != MDEV_UNASSIGNED) {
			cmn_err(CE_NOTE, "man_add_dests mdev !unassigned");
			MAN_DBGCALL(MAN_PATH, man_print_mdp(mdp));
		}

		man_start_dest(mdp, msp, mpg);
	}

}

static int
man_remove_dests(man_pg_t *mpg)
{
	manstr_t	*msp;
	int		close_cnt = 0;
	man_dest_t	*cdp;
	man_dest_t	*mdp;
	man_dest_t	*tdp;
	man_work_t	*wp;
	mblk_t		*mp;
	int		status = 0;

	wp = man_work_alloc(MAN_WORK_CLOSE, KM_NOSLEEP);
	if (wp == NULL) {
		status = ENOMEM;
		goto exit;
	}

	/*
	 * Count up number of destinations we need to close.
	 */
	for (msp = man_strup; msp != NULL; msp = msp->ms_next) {
		if (!man_str_uses_pg(msp, mpg))
			continue;

		close_cnt++;
	}

	if (close_cnt == 0)
		goto exit;

	cdp = man_kzalloc(sizeof (man_dest_t) * close_cnt, KM_NOSLEEP);
	if (cdp == NULL) {
		status = ENOMEM;
		man_work_free(wp);
		goto exit;
	}

	tdp = cdp;
	for (msp = man_strup; msp != NULL; msp = msp->ms_next) {
		if (!man_str_uses_pg(msp, mpg))
			continue;

		mdp = &msp->ms_dests[mpg->mpg_pg_id];

		mdp->md_state |= MAN_DSTATE_CLOSING;
		mdp->md_device.mdev_state = MDEV_UNASSIGNED;
		mdp->md_msp = NULL;
		mdp->md_rq = NULL;

		/*
		 * Clean up optimized destination pointer if we are
		 * closing it.
		 */
		man_set_optimized_dest(msp);

		if (mdp->md_lc_timer_id != 0) {
			(void) quntimeout(man_ctl_wq, mdp->md_lc_timer_id);
			mdp->md_lc_timer_id = 0;
		}
		if (mdp->md_bc_id != 0) {
			qunbufcall(man_ctl_wq, mdp->md_bc_id);
			mdp->md_bc_id = 0;
		}

		mutex_enter(&mdp->md_lock);
		while ((mp = mdp->md_dmp_head) != NULL) {
			mdp->md_dmp_head = mp->b_next;
			mp->b_next = NULL;
			freemsg(mp);
		}
		mdp->md_dmp_count = 0;
		mdp->md_dmp_tail = NULL;
		mutex_exit(&mdp->md_lock);

		*tdp++ = *mdp;

		mdp->md_state = MAN_DSTATE_NOTPRESENT;
		mdp->md_muxid = -1;
	}

	wp->mw_arg.a_mdp = cdp;
	wp->mw_arg.a_ndests = close_cnt;
	man_work_add(man_bwork_q, wp);

exit:
	return (status);

}

/*
 * Returns TRUE if stream uses pathgroup, FALSE otherwise.
 */
static int
man_str_uses_pg(manstr_t *msp, man_pg_t *mpg)
{
	int	status;

	status = ((msp->ms_flags & MAN_SFLAG_CONTROL)	||
	    (msp->ms_dests == NULL)	||
	    (msp->ms_manp == NULL)	||
	    (msp->ms_manp->man_meta_ppa != mpg->mpg_man_ppa));

	return (!status);
}

static int
man_gettimer(int timer, man_dest_t *mdp)
{

	int attached = TRUE;
	int time = 0;

	if (mdp == NULL || mdp->md_msp == NULL || mdp->md_msp->ms_manp == NULL)
		attached = FALSE;

	switch (timer) {
	case MAN_TIMER_INIT:
		if (attached)
			time = mdp->md_msp->ms_manp->man_init_time;
		else
			time = MAN_INIT_TIME;
		break;

	case MAN_TIMER_LINKCHECK:
		if (attached) {
			if (mdp->md_linkstate == MAN_LINKSTALE)
				time = mdp->md_msp->ms_manp->man_linkstale_time;
			else
				time = mdp->md_msp->ms_manp->man_linkcheck_time;
		} else
			time = MAN_LINKCHECK_TIME;
		break;

	case MAN_TIMER_DLPIRESET:
		if (attached)
			time = mdp->md_msp->ms_manp->man_dlpireset_time;
		else
			time = MAN_DLPIRESET_TIME;
		break;

	default:
		MAN_DBG(MAN_LINK, ("man_gettimer: unknown timer %d", timer));
		time = MAN_LINKCHECK_TIME;
		break;
	}

	return (drv_usectohz(time));
}

/*
 * Check the links for each active destination. Called inside inner
 * perimeter via qtimeout. This timer only runs on the domain side of the
 * driver. It should never run on the SC side.
 *
 * On a MAN_LINKGOOD link, we check/probe the link health every
 * MAN_LINKCHECK_TIME seconds. If the link goes MAN_LINKSTALE, the we probe
 * the link every MAN_LINKSTALE_TIME seconds, and fail the link after probing
 * the link MAN_LINKSTALE_RETRIES times.
 * The man_lock is held to synchronize access pathgroup list(man_pg).
 */
void
man_linkcheck_timer(void *argp)
{
	man_dest_t		*mdp = (man_dest_t *)argp;
	int			restart_timer = TRUE;
	int			send_ping = TRUE;
	int			newstate;
	int			oldstate;
	man_pg_t		*mpg;
	man_path_t		*mp;

	MAN_DBG(MAN_LINK, ("man_linkcheck_timer: mdp"));
	MAN_DBGCALL(MAN_LINK, man_print_mdp(mdp));

	/*
	 * Clear timeout id and check if someones waiting on us to
	 * complete a close.
	 */
	mdp->md_lc_timer_id = 0;

	if (mdp->md_state == MAN_DSTATE_NOTPRESENT ||
	    mdp->md_state & MAN_DSTATE_BUSY) {

		MAN_DBG(MAN_LINK, ("man_linkcheck_timer: not ready mdp"));
		MAN_DBGCALL(MAN_LINK, man_print_mdp(mdp));
		goto exit;
	}

	mutex_enter(&man_lock);
	/*
	 * If the lower stream needs initializing, just go straight to
	 * switch code. As the linkcheck timer is started for all
	 * SAPs, do not send ping packets during the initialization.
	 */
	if (mdp->md_state == MAN_DSTATE_INITIALIZING) {
		send_ping = FALSE;
		goto do_switch;
	}

	newstate = oldstate = mdp->md_linkstate;

	if (!man_needs_linkcheck(mdp)) {
		cmn_err(CE_NOTE,
		    "man_linkcheck_timer: unneeded linkcheck on mdp(0x%p)",
		    (void *)mdp);
		mutex_exit(&man_lock);
		return;
	}

	/*
	 * The above call to  man_needs_linkcheck() validates
	 * mdp->md_msp and mdp->md_msp->ms_manp pointers.
	 */
	mpg = man_find_pg_by_id(mdp->md_msp->ms_manp->man_pg, mdp->md_pg_id);
	ASSERT(mpg != NULL);
	mp = man_find_path_by_ppa(mpg->mpg_pathp, mdp->md_device.mdev_ppa);
	ASSERT(mp != NULL);

	/*
	 * This is the most common case, when traffic is flowing.
	 */
	if (mdp->md_rcvcnt != mdp->md_lastrcvcnt) {

		newstate = MAN_LINKGOOD;
		mdp->md_lastrcvcnt = mdp->md_rcvcnt;
		send_ping = FALSE;

		/*
		 * Clear the FAILED flag and update lru.
		 */
		mp->mp_device.mdev_state &= ~MDEV_FAILED;
		(void) drv_getparm(TIME, &mp->mp_lru);

		if (mdp->md_link_updown_msg == MAN_LINK_DOWN_MSG) {
			man_t *manp = mdp->md_msp->ms_manp;

			cmn_err(CE_NOTE, "%s%d Link up",
			    ddi_major_to_name(manp->man_meta_major),
			    manp->man_meta_ppa);

			mdp->md_link_updown_msg = MAN_LINK_UP_MSG;
		}

		goto done;
	}

	/*
	 * If we're here, it means we have not seen any traffic
	 */
	switch (oldstate) {
	case MAN_LINKINIT:
	case MAN_LINKGOOD:
		newstate = MAN_LINKSTALE;
		mdp->md_linkstales++;
		mdp->md_linkstale_retries =
		    mdp->md_msp->ms_manp->man_linkstale_retries;
		break;

	case MAN_LINKSTALE:
	case MAN_LINKFAIL:
		mdp->md_linkstales++;
		mdp->md_linkstale_retries--;
		if (mdp->md_linkstale_retries < 0) {
			newstate = MAN_LINKFAIL;
			mdp->md_linkfails++;
			mdp->md_linkstale_retries =
			    mdp->md_msp->ms_manp->man_linkstale_retries;
			/*
			 * Mark the destination as FAILED and
			 * update lru.
			 */
			if (oldstate != MAN_LINKFAIL) {
				mp->mp_device.mdev_state |= MDEV_FAILED;
				(void) drv_getparm(TIME, &mp->mp_lru);
			}
		}
		break;

	default:
		cmn_err(CE_WARN, "man_linkcheck_timer: illegal link"
		    " state %d", oldstate);
		break;
	}
done:

	if (oldstate != newstate) {

		MAN_DBG(MAN_LINK, ("man_linkcheck_timer"
		    " link state %s -> %s", lss[oldstate],
		    lss[newstate]));

		mdp->md_linkstate = newstate;
	}

	/*
	 * Do any work required from state transitions above.
	 */
	if (newstate == MAN_LINKFAIL) {
do_switch:
		if (!man_do_autoswitch(mdp)) {
			/*
			 * Stop linkcheck timer until switch completes.
			 */
			restart_timer = FALSE;
			send_ping = FALSE;
		}
	}

	mutex_exit(&man_lock);
	if (send_ping)
		man_do_icmp_bcast(mdp, mdp->md_msp->ms_sap);

	if (restart_timer)
		mdp->md_lc_timer_id = qtimeout(man_ctl_wq, man_linkcheck_timer,
		    (void *)mdp, man_gettimer(MAN_TIMER_LINKCHECK, mdp));

exit:
	MAN_DBG(MAN_LINK, ("man_linkcheck_timer: returns"));

}

/*
 * Handle linkcheck initiated autoswitching.
 * Called with man_lock held.
 */
static int
man_do_autoswitch(man_dest_t *mdp)
{
	man_pg_t	*mpg;
	man_path_t	*ap;
	int		status = 0;

	ASSERT(MUTEX_HELD(&man_lock));
	/*
	 * Set flags and refcnt. Cleared in man_iswitch when SWITCH completes.
	 */
	mdp->md_msp->ms_manp->man_refcnt++;

	mpg = man_find_pg_by_id(mdp->md_msp->ms_manp->man_pg, mdp->md_pg_id);
	ASSERT(mpg);

	if (mpg->mpg_flags & MAN_PG_SWITCHING)
		return (EBUSY);

	mpg->mpg_flags |= MAN_PG_SWITCHING;

	if (mdp->md_state == MAN_DSTATE_INITIALIZING) {
		/*
		 * We're initializing, ask for a switch to our currently
		 * active device.
		 */
		status = man_autoswitch(mpg, &mdp->md_device, NULL);
	} else {

		if (mdp->md_msp != NULL && mdp->md_msp->ms_manp != NULL &&
		    mdp->md_link_updown_msg == MAN_LINK_UP_MSG) {

			man_t *manp = mdp->md_msp->ms_manp;

			cmn_err(CE_NOTE, "%s%d Link down",
			    ddi_major_to_name(manp->man_meta_major),
			    manp->man_meta_ppa);
		}
		mdp->md_link_updown_msg = MAN_LINK_DOWN_MSG;

		MAN_DBG(MAN_LINK, ("man_linkcheck_timer: link failure on %s%d",
		    ddi_major_to_name(mdp->md_device.mdev_major),
		    mdp->md_device.mdev_ppa));

		ap = man_find_alternate_path(mpg->mpg_pathp);

		if (ap == NULL) {
			status = ENODEV;
			goto exit;
		}
		status = man_autoswitch(mpg, &ap->mp_device, NULL);
	}
exit:
	if (status != 0) {
		/*
		 * man_iswitch not going to run, clean up.
		 */
		mpg->mpg_flags &= ~MAN_PG_SWITCHING;
		mdp->md_msp->ms_manp->man_refcnt--;
	}

	return (status);
}

/*
 * Gather up all lower multiplexor streams that have this link open and
 * try to switch them. Called from inner perimeter and holding man_lock.
 *
 *	pg_id		- Pathgroup to do switch for.
 *	st_devp		- New device to switch to.
 *	wait_for_switch	- whether or not to qwait for completion.
 */
static int
man_autoswitch(man_pg_t *mpg, man_dev_t *st_devp, man_work_t *waiter_wp)
{
	man_work_t	*wp;
	int		sdp_cnt = 0;
	man_dest_t	*sdp;
	int		status = 0;

	ASSERT(MUTEX_HELD(&man_lock));
	if (waiter_wp == NULL) {
		wp = man_work_alloc(MAN_WORK_SWITCH, KM_NOSLEEP);
		if (wp == NULL) {
			status = ENOMEM;
			goto exit;
		}
	} else {
		ASSERT(waiter_wp->mw_type == MAN_WORK_SWITCH);
		wp = waiter_wp;
	}

	/*
	 * Set dests as PLUMBING, cancel timers and return array of dests
	 * that need a switch.
	 */
	status = man_prep_dests_for_switch(mpg, &sdp, &sdp_cnt);
	if (status) {
		if (waiter_wp == NULL)
			man_work_free(wp);
		goto exit;
	}

	/*
	 * If no streams are active, there are no streams to switch.
	 * Return ENODEV (see man_pg_activate).
	 */
	if (sdp_cnt == 0) {
		if (waiter_wp == NULL)
			man_work_free(wp);
		status = ENODEV;
		goto exit;
	}

	/*
	 * Ask the bgthread to switch. See man_bwork.
	 */
	wp->mw_arg.a_sf_dev = sdp->md_device;
	wp->mw_arg.a_st_dev = *st_devp;
	wp->mw_arg.a_pg_id = mpg->mpg_pg_id;
	wp->mw_arg.a_man_ppa = mpg->mpg_man_ppa;

	wp->mw_arg.a_mdp = sdp;
	wp->mw_arg.a_ndests = sdp_cnt;
	man_work_add(man_bwork_q, wp);

exit:

	return (status);
}

/*
 * If an alternate path exists for pathgroup, arrange for switch to
 * happen. Note that we need to switch each of msp->dests[pg_id], for
 * all on man_strup. We must:
 *
 *		Cancel any timers
 *		Mark dests as PLUMBING
 *		Submit switch request to man_bwork_q->
 */
static int
man_prep_dests_for_switch(man_pg_t *mpg, man_dest_t **mdpp, int *cntp)
{
	manstr_t	*msp;
	man_dest_t	*mdp;
	int		sdp_cnt = 0;
	man_dest_t	*sdp = NULL;
	man_dest_t	*tdp;
	int		status = 0;

	MAN_DBG(MAN_SWITCH, ("man_prep_dests_for_switch: pg_id %d",
	    mpg->mpg_pg_id));

	/*
	 * Count up number of streams, there is one destination that needs
	 * switching per stream.
	 */
	for (msp = man_strup; msp != NULL; msp = msp->ms_next) {
		if (man_str_uses_pg(msp, mpg))
			sdp_cnt++;
	}

	if (sdp_cnt == 0)
		goto exit;

	sdp = man_kzalloc(sizeof (man_dest_t) * sdp_cnt, KM_NOSLEEP);
	if (sdp == NULL) {
		status = ENOMEM;
		goto exit;
	}
	tdp = sdp;
	/*
	 * Mark each destination as unusable.
	 */
	for (msp = man_strup; msp != NULL; msp = msp->ms_next) {
		if (man_str_uses_pg(msp, mpg)) {

			/*
			 * Mark destination as plumbing and store the
			 * address of sdp as a way to identify the
			 * SWITCH request when it comes back (see man_iswitch).
			 */
			mdp = &msp->ms_dests[mpg->mpg_pg_id];
			mdp->md_state |= MAN_DSTATE_PLUMBING;
			mdp->md_switch_id = sdp;

			/*
			 * Copy destination info.
			 */
			bcopy(mdp, tdp, sizeof (man_dest_t));
			tdp++;

			/*
			 * Cancel timers.
			 */
			if (mdp->md_lc_timer_id) {
				(void) quntimeout(man_ctl_wq,
				    mdp->md_lc_timer_id);
				mdp->md_lc_timer_id = 0;
			}
			if (mdp->md_bc_id) {
				qunbufcall(man_ctl_wq, mdp->md_bc_id);
				mdp->md_bc_id = 0;
			}
		}
	}

	*mdpp = sdp;
	*cntp = sdp_cnt;
	status = 0;
exit:

	MAN_DBG(MAN_SWITCH, ("man_prep_dests_for_switch: returns %d"
	    " sdp(0x%p) sdp_cnt(%d)", status, (void *)sdp, sdp_cnt));

	return (status);

}

/*
 * The code below generates an ICMP echo packet and sends it to the
 * broadcast address in the hopes that the other end will respond
 * and the man_linkcheck_timer logic will see the traffic.
 *
 * This assumes ethernet-like media.
 */
/*
 * Generate an ICMP packet. Called exclusive inner perimeter.
 *
 *	mdp - destination to send packet to.
 *	sap - either ETHERTYPE_ARP or ETHERTYPE_IPV6
 */
static void
man_do_icmp_bcast(man_dest_t *mdp, t_uscalar_t sap)
{
	mblk_t			*mp = NULL;

	/* TBD - merge pinger and this routine. */

	ASSERT(sap == ETHERTYPE_IPV6 || sap == ETHERTYPE_IP);

	if (sap == ETHERTYPE_IPV6) {
		mdp->md_icmpv6probes++;
	} else {
		mdp->md_icmpv4probes++;
	}
	/*
	 * Send the ICMP message
	 */
	mp = man_pinger(sap);

	MAN_DBG(MAN_LINK, ("man_do_icmp_bcast: sap=0x%x mp=0x%p",
	    sap, (void *)mp));
	if (mp == NULL)
		return;

	/*
	 * Send it out.
	 */
	if (man_start_lower(mdp, mp, NULL, MAN_LOWER)) {

		MAN_DBG(MAN_LINK, ("man_do_icmp_broadcast: xmit failed"));

		freemsg(mp);
	}

}

static mblk_t *
man_pinger(t_uscalar_t sap)
{
	mblk_t		*mp = NULL;
	man_dladdr_t	dlsap;
	icmph_t		*icmph;
	int		ipver;
	ipha_t		*ipha;
	ip6_t		*ip6h;
	int		iph_hdr_len;
	int		datalen = 64;
	uchar_t		*datap;
	uint16_t	size;
	uchar_t		i;

	dlsap.dl_sap = htons(sap);
	bcopy(&etherbroadcast, &dlsap.dl_phys, sizeof (dlsap.dl_phys));

	if (sap == ETHERTYPE_IPV6) {
		ipver = IPV6_VERSION;
		iph_hdr_len = sizeof (ip6_t);
		size = ICMP6_MINLEN;
	} else {
		ipver = IPV4_VERSION;
		iph_hdr_len = sizeof (ipha_t);
		size = ICMPH_SIZE;
	}
	size += (uint16_t)iph_hdr_len;
	size += datalen;

	mp = man_alloc_udreq(size, &dlsap);
	if (mp == NULL)
		goto exit;

	/*
	 * fill out the ICMP echo packet headers
	 */
	mp->b_cont->b_wptr += iph_hdr_len;
	if (ipver == IPV4_VERSION) {
		ipha = (ipha_t *)mp->b_cont->b_rptr;
		ipha->ipha_version_and_hdr_length = (IP_VERSION << 4)
		    | IP_SIMPLE_HDR_LENGTH_IN_WORDS;
		ipha->ipha_type_of_service = 0;
		ipha->ipha_length = size;
		ipha->ipha_fragment_offset_and_flags = IPH_DF;
		ipha->ipha_ttl = 1;
		ipha->ipha_protocol = IPPROTO_ICMP;
		if (man_is_on_domain) {
			manc_t		manc;

			if (man_get_iosram(&manc)) {
				freemsg(mp);
				mp = NULL;
				goto exit;
			}

			/*
			 * Domain generates ping packets for domain to
			 * SC network (dman0 <--> scman0).
			 */
			ipha->ipha_dst = manc.manc_sc_ipaddr;
			ipha->ipha_src = manc.manc_dom_ipaddr;
		} else {
			/*
			 * Note that ping packets are only generated
			 * by the SC across scman1 (SC to SC network).
			 */
			ipha->ipha_dst = man_sc_ipaddrs.ip_other_sc_ipaddr;
			ipha->ipha_src = man_sc_ipaddrs.ip_my_sc_ipaddr;
		}

		ipha->ipha_ident = 0;

		ipha->ipha_hdr_checksum = 0;
		ipha->ipha_hdr_checksum = IP_CSUM(mp->b_cont, 0, 0);

	} else {
		ip6h = (ip6_t *)mp->b_cont->b_rptr;
		/*
		 * IP version = 6, priority = 0, flow = 0
		 */
		ip6h->ip6_flow = (IPV6_VERSION << 28);
		ip6h->ip6_plen =
		    htons((short)(size - iph_hdr_len));
		ip6h->ip6_nxt = IPPROTO_ICMPV6;
		ip6h->ip6_hlim = 1;	/* stay on link */

		if (man_is_on_domain) {
			manc_t		manc;

			if (man_get_iosram(&manc)) {
				freemsg(mp);
				mp = NULL;
				goto exit;
			}

			/*
			 * Domain generates ping packets for domain to
			 * SC network (dman0 <--> scman0).
			 */
			ip6h->ip6_src = manc.manc_dom_ipv6addr;
			ip6h->ip6_dst = manc.manc_sc_ipv6addr;
		} else {
			/*
			 * Note that ping packets are only generated
			 * by the SC across scman1 (SC to SC network).
			 */
			ip6h->ip6_src = man_sc_ip6addrs.ip6_my_sc_ipaddr;
			ip6h->ip6_dst = man_sc_ip6addrs.ip6_other_sc_ipaddr;
		}
	}

	/*
	 * IPv6 and IP are the same for ICMP as far as I'm concerned.
	 */
	icmph = (icmph_t *)mp->b_cont->b_wptr;
	if (ipver == IPV4_VERSION) {
		mp->b_cont->b_wptr += ICMPH_SIZE;
		icmph->icmph_type = ICMP_ECHO_REQUEST;
		icmph->icmph_code = 0;
	} else {
		mp->b_cont->b_wptr += ICMP6_MINLEN;
		icmph->icmph_type = ICMP6_ECHO_REQUEST;
		icmph->icmph_code = 0;
	}

	datap = mp->b_cont->b_wptr;
	mp->b_cont->b_wptr += datalen;

	for (i = 0; i < datalen; i++)
		*datap++ = i;

	if (ipver == IPV4_VERSION) {
		icmph->icmph_checksum = IP_CSUM(mp->b_cont, iph_hdr_len, 0);
	} else {
		uint32_t	sum;

		sum = htons(IPPROTO_ICMPV6) + ip6h->ip6_plen;
		icmph->icmph_checksum = IP_CSUM(mp->b_cont, iph_hdr_len - 32,
		    (sum & 0xffff) + (sum >> 16));
	}

/*
 * TBD
 *	icp->icmp_time =  ???;
 */

exit:
	return (mp);
}

static mblk_t *
man_alloc_udreq(int size, man_dladdr_t *dlsap)
{
	dl_unitdata_req_t	*udreq;
	mblk_t			*bp;
	mblk_t			*mp;

	mp = allocb(sizeof (dl_unitdata_req_t) + sizeof (*dlsap), BPRI_MED);

	if (mp == NULL) {
		cmn_err(CE_NOTE, "man_preparepkt: allocb failed");
		return (NULL);
	}

	if ((bp = allocb(size, BPRI_MED)) == NULL) {
		freemsg(mp);
		cmn_err(CE_NOTE, "man_preparepkts: allocb failed");
		return (NULL);
	}
	bzero(bp->b_rptr, size);

	mp->b_cont = bp;
	mp->b_datap->db_type = M_PROTO;
	udreq = (dl_unitdata_req_t *)mp->b_wptr;
	mp->b_wptr += sizeof (dl_unitdata_req_t);

	/*
	 * phys addr first - TBD
	 */
	bcopy((char *)dlsap, mp->b_wptr, sizeof (*dlsap));
	mp->b_wptr += sizeof (*dlsap);

	udreq->dl_primitive = DL_UNITDATA_REQ;
	udreq->dl_dest_addr_length = sizeof (*dlsap);
	udreq->dl_dest_addr_offset = sizeof (*udreq);
	udreq->dl_priority.dl_min = 0;
	udreq->dl_priority.dl_max = 0;

	return (mp);
}


/*
 * The routines in this file are executed by the MAN background thread,
 * which executes outside of the STREAMS framework (see man_str.c). It is
 * allowed to do the things required to modify the STREAMS driver (things
 * that are normally done from a user process). These routines do things like
 * open and close drivers, PLINK and PUNLINK streams to/from the multiplexor,
 * etc.
 *
 * The mechanism of communication between the STREAMS portion of the driver
 * and the background thread portion are two work queues, man_bwork_q
 * and man_iwork_q (background work q and streams work q).  Work
 * requests are placed on those queues when one half of the driver wants
 * the other half to do some work for it.
 *
 * The MAN background thread executes the man_bwork routine. Its sole
 * job is to process work requests placed on this work q. The MAN upper
 * write service routine is responsible for processing work requests posted
 * to the man_iwork_q->
 *
 * Both work queues are protected by the global mutex man_lock. The
 * man_bwork is signalged via the condvarman_bwork_q->q_cv. The man_uwsrv
 * routine is signaled by calling qenable (forcing man_uwsrv to run).
 */

/*
 * man_bwork - Work thread for this device.  It is responsible for
 * performing operations which can't occur within the STREAMS framework.
 *
 * Locking:
 *	- Called holding no locks
 *	- Obtains the global mutex man_lock to remove work from
 *	  man_bwork_q, and post work to man_iwork_q->
 *	- Note that we do not want to hold any locks when making
 *	  any ldi_ calls.
 */
void
man_bwork()
{
	man_work_t	*wp;
	int		done = 0;
	callb_cpr_t	cprinfo;
	int		wp_finished;

	CALLB_CPR_INIT(&cprinfo, &man_lock, callb_generic_cpr,
	    "mn_work_thrd");

	MAN_DBG(MAN_CONFIG, ("man_bwork: enter"));

	while (done == 0) {

		mutex_enter(&man_lock);
		/*
		 * While there is nothing to do, sit in cv_wait.  If work
		 * request is made, requester will signal.
		 */
		while (man_bwork_q->q_work == NULL) {

			CALLB_CPR_SAFE_BEGIN(&cprinfo);

			cv_wait(&man_bwork_q->q_cv, &man_lock);

			CALLB_CPR_SAFE_END(&cprinfo, &man_lock);
		}

		wp = man_bwork_q->q_work;
		man_bwork_q->q_work = wp->mw_next;
		wp->mw_next = NULL;
		mutex_exit(&man_lock);

		wp_finished = TRUE;

		MAN_DBG(MAN_SWITCH, ("man_bwork: type %s",
		    _mw_type[wp->mw_type]));

		switch (wp->mw_type) {
		case MAN_WORK_OPEN_CTL:
			wp->mw_status = man_open_ctl();
			break;

		case MAN_WORK_CLOSE_CTL:
			man_close_ctl();
			break;

		case MAN_WORK_CLOSE:
		case MAN_WORK_CLOSE_STREAM:
			man_bclose(&wp->mw_arg);
			break;

		case MAN_WORK_SWITCH:
			man_bswitch(&wp->mw_arg, wp);
			wp_finished = FALSE;
			break;

		case MAN_WORK_STOP:		/* man_bwork_stop() */
			done = 1;
			mutex_enter(&man_lock);
			CALLB_CPR_EXIT(&cprinfo); /* Unlocks man_lock */
			break;

		default:
			cmn_err(CE_WARN, "man_bwork: "
			    "illegal work type(%d)", wp->mw_type);
			break;
		}

		mutex_enter(&man_lock);

		if (wp_finished) {
			wp->mw_flags |= MAN_WFLAGS_DONE;
			if (wp->mw_flags & MAN_WFLAGS_CVWAITER)
				cv_signal(&wp->mw_cv);
			else if (wp->mw_flags & MAN_WFLAGS_QWAITER)
				qenable(wp->mw_q);
			else
				man_work_free(wp);
		}

		mutex_exit(&man_lock);
	}

	MAN_DBG(MAN_CONFIG, ("man_bwork: thread_exit"));

	mutex_enter(&man_lock);
	man_bwork_id = NULL;
	mutex_exit(&man_lock);

	thread_exit();
}

/*
 * man_open_ctl - Open the control stream.
 *
 *	returns	- success - 0
 *		- failure - errno code
 *
 * Mutex Locking Notes:
 *	We need a way to keep the CLONE_OPEN qwaiters in man_open from
 *	checking the man_config variables after the ldi_open call below
 *	returns from man_open, leaving the inner perimeter. So, we use the
 *	man_lock to synchronize the threads in man_open_ctl and man_open.  We
 *	hold man_lock across this call into man_open, which in general is a
 *	no-no. But, the STREAMs portion of the driver (other than open)
 *	doesn't use it. So, if ldi_open gets hijacked to run any part of
 *	the MAN streams driver, it wont end up recursively trying to acquire
 *	man_lock. Note that the non-CLONE_OPEN portion of man_open doesnt
 *	acquire it either, so again no recursive mutex.
 */
static int
man_open_ctl()
{
	int		status = 0;
	ldi_handle_t	ctl_lh = NULL;
	ldi_ident_t	li = NULL;

	MAN_DBG(MAN_CONFIG, ("man_open_ctl: plumbing control stream\n"));

	/*
	 * Get eri driver loaded and kstats initialized. Is there a better
	 * way to do this? - TBD.
	 */
	status = ldi_ident_from_mod(&modlinkage, &li);
	if (status) {
		cmn_err(CE_WARN,
		    "man_open_ctl: ident alloc failed, error %d", status);
		goto exit;
	}

	status = ldi_open_by_name(ERI_PATH, FREAD | FWRITE | FNOCTTY,
	    kcred, &ctl_lh, li);
	if (status) {
		cmn_err(CE_WARN,
		    "man_open_ctl: eri open failed, error %d", status);
		ctl_lh = NULL;
		goto exit;
	}
	(void) ldi_close(ctl_lh, NULL, kcred);
	ctl_lh = NULL;

	mutex_enter(&man_lock);

	if (man_ctl_lh != NULL) {
		mutex_exit(&man_lock);
		goto exit;
	}

	ASSERT(man_ctl_wq == NULL);
	mutex_exit(&man_lock);

	status = ldi_open_by_name(DMAN_INT_PATH, FREAD | FWRITE | FNOCTTY,
	    kcred, &ctl_lh, li);
	if (status) {
		cmn_err(CE_WARN,
		    "man_open_ctl: man control dev open failed, "
		    "error %d", status);
		goto exit;
	}

	/*
	 * Update global config state. TBD - dont need lock here, since
	 * everyone is stuck in open until we finish. Only other modifier
	 * is man_deconfigure via _fini, which returns EBUSY if there is
	 * any open streams (other than control). Do need to signal qwaiters
	 * on error.
	 */
	mutex_enter(&man_lock);
	ASSERT(man_config_state == MAN_CONFIGURING);
	ASSERT(man_ctl_lh == NULL);
	man_ctl_lh = ctl_lh;
	mutex_exit(&man_lock);

exit:
	if (li)
		ldi_ident_release(li);

	MAN_DBG(MAN_CONFIG, ("man_open_ctl: man_ctl_lh(0x%p) errno = %d\n",
	    (void *)man_ctl_lh, status));

	return (status);
}

/*
 * man_close_ctl - Close control stream, we are about to unload driver.
 *
 * Locking:
 *	- Called holding no locks.
 */
static void
man_close_ctl()
{
	ldi_handle_t tlh;

	MAN_DBG(MAN_CONFIG, ("man_close_ctl: unplumbing control stream\n"));

	mutex_enter(&man_lock);
	if ((tlh = man_ctl_lh) != NULL)
		man_ctl_lh = NULL;
	mutex_exit(&man_lock);

	if (tlh != NULL) {
		(void) ldi_close(tlh, NULL, kcred);
	}

}

/*
 * Close the lower streams. Get all the timers canceled, close the lower
 * stream and delete the dest array.
 *
 * Returns:
 *	0	Closed all streams.
 *	1	Couldn't close one or more streams, timers still running.
 *
 * Locking:
 *	- Called holding no locks.
 */
static void
man_bclose(man_adest_t *adp)
{
	int		i;
	man_dest_t	*mdp;

	man_cancel_timers(adp);

	for (i = 0; i < adp->a_ndests; i++) {
		mdp = &adp->a_mdp[i];

		if (mdp->md_muxid != -1)
			man_unplumb(mdp);
	}

	mutex_destroy(&mdp->md_lock);
	man_kfree(adp->a_mdp, sizeof (man_dest_t) * adp->a_ndests);
	adp->a_mdp = NULL;
}

/*
 * We want to close down all lower streams. Need to wait until all
 * timers and work related to these lower streams is quiesced.
 *
 * Returns 1 if lower streams are quiesced, 0 if we need to wait
 * a bit longer.
 */
static void
man_cancel_timers(man_adest_t *adp)
{
	man_dest_t	*mdp;
	int		cnt;
	int		i;

	mdp = adp->a_mdp;
	cnt = adp->a_ndests;

	MAN_DBG(MAN_SWITCH, ("man_cancel_timers: mdp(0x%p) cnt %d",
	    (void *)mdp, cnt));

	for (i = 0; i < cnt; i++) {

		if (mdp[i].md_lc_timer_id != 0) {
			(void) quntimeout(man_ctl_wq, mdp[i].md_lc_timer_id);
			mdp[i].md_lc_timer_id = 0;
		}

		if (mdp[i].md_bc_id != 0) {
			qunbufcall(man_ctl_wq, mdp[i].md_bc_id);
			mdp[i].md_bc_id = 0;
		}
	}

	MAN_DBG(MAN_SWITCH, ("man_cancel_timers: returns"));
}

/*
 * A failover is started at start of day, when the driver detects a
 * link failure (see man_linkcheck_timer), or when DR detaches
 * the IO board containing the current active link between SC and
 * domain (see man_dr_detach, man_iwork, and man_do_dr_detach). A
 * MAN_WORK_SWITCH work request containing all the lower streams that
 * should be switched is posted on the man_bwork_q-> This work request is
 * processed here. Once all lower streams have been switched to an
 * alternate path, the MAN_WORK_SWITCH work request is passed back to
 * man_iwork_q where it is processed within the inner perimeter of the
 * STREAMS framework (see man_iswitch).
 *
 * Note that when the switch fails for whatever reason, we just hand
 * back the lower streams untouched and let another failover happen.
 * Hopefully we will sooner or later succeed at the failover.
 */
static void
man_bswitch(man_adest_t *adp, man_work_t *wp)
{
	man_dest_t	*tdp;
	man_t		*manp;
	int		i;
	int		status = 0;

	/*
	 * Make a temporary copy of dest array, updating device to the
	 * alternate and try to open all lower streams. bgthread can sleep.
	 */

	tdp = man_kzalloc(sizeof (man_dest_t) * adp->a_ndests,
	    KM_SLEEP);
	bcopy(adp->a_mdp, tdp, sizeof (man_dest_t) * adp->a_ndests);

	/*
	 * Before we switch to the new path, lets sync the kstats.
	 */
	mutex_enter(&man_lock);

	manp = ddi_get_soft_state(man_softstate, adp->a_man_ppa);
	if (manp != NULL) {
		man_update_path_kstats(manp);
	} else
		status = ENODEV;

	mutex_exit(&man_lock);

	if (status != 0)
		goto exit;

	for (i = 0; i < adp->a_ndests; i++) {

		tdp[i].md_device = adp->a_st_dev;
		tdp[i].md_muxid = -1;

		if (man_plumb(&tdp[i]))
			break;
	}

	/*
	 * Didn't plumb everyone, unplumb new lower stuff and return.
	 */
	if (i < adp->a_ndests) {
		int	j;

		for (j = 0; j <= i; j++)
			man_unplumb(&tdp[j]);
		status = EAGAIN;
		goto exit;
	}

	if (man_is_on_domain && man_dossc_switch(adp->a_st_dev.mdev_exp_id)) {
		/*
		 * If we cant set new path on the SSC, then fail the
		 * failover.
		 */
		for (i = 0; i < adp->a_ndests; i++)
			man_unplumb(&tdp[i]);
		status = EAGAIN;
		goto exit;
	}

	man_kfree(adp->a_mdp, sizeof (man_dest_t) * adp->a_ndests);
	adp->a_mdp = tdp;

exit:
	if (status)
		man_kfree(tdp, sizeof (man_dest_t) * adp->a_ndests);


	MAN_DBG(MAN_SWITCH, ("man_bswitch: returns %d", status));

	/*
	 * Hand processed switch request back to man_iwork for
	 * processing in man_iswitch.
	 */
	wp->mw_status = status;

	mutex_enter(&man_lock);
	man_work_add(man_iwork_q, wp);
	mutex_exit(&man_lock);

}

/*
 * man_plumb - Configure a lower stream for this destination.
 *
 * Locking:
 * 	- Called holding no locks.
 *
 * Returns:
 *	- success - 0
 *	- failure - error code of failure
 */
static int
man_plumb(man_dest_t *mdp)
{
	int		status;
	int		muxid;
	ldi_handle_t	lh;
	ldi_ident_t	li = NULL;

	MAN_DBG(MAN_SWITCH, ("man_plumb: mdp(0x%p) %s%d exp(%d)",
	    (void *)mdp, ddi_major_to_name(mdp->md_device.mdev_major),
	    mdp->md_device.mdev_ppa, mdp->md_device.mdev_exp_id));

	/*
	 * Control stream should already be open.
	 */
	if (man_ctl_lh == NULL) {
		status = EAGAIN;
		goto exit;
	}

	mutex_enter(&man_lock);
	ASSERT(man_ctl_wq != NULL);
	status = ldi_ident_from_stream(man_ctl_wq, &li);
	if (status != 0) {
		cmn_err(CE_WARN,
		    "man_plumb: ident alloc failed, error %d", status);
		goto exit;
	}
	mutex_exit(&man_lock);

	/*
	 * previously opens were done by a dev_t of makedev(clone_major,
	 * mdev_major) which should always map to /devices/pseudo/clone@0:eri
	 */
	ASSERT(strcmp(ERI_IDNAME,
	    ddi_major_to_name(mdp->md_device.mdev_major)) == 0);

	status = ldi_open_by_name(ERI_PATH, FREAD | FWRITE | FNOCTTY,
	    kcred, &lh, li);
	if (status) {
		cmn_err(CE_WARN,
		    "man_plumb: eri open failed, error %d", status);
		goto exit;
	}

	/*
	 * Link netdev under MAN.
	 */
	ASSERT(mdp->md_muxid == -1);

	status = ldi_ioctl(man_ctl_lh, I_PLINK, (intptr_t)lh,
	    FREAD+FWRITE+FNOCTTY+FKIOCTL, kcred, &muxid);
	if (status) {
		cmn_err(CE_WARN,
		    "man_plumb: ldi_ioctl(I_PLINK) failed, error %d", status);
		(void) ldi_close(lh, NULL, kcred);
		goto exit;

	}
	mdp->md_muxid = muxid;
	mdp->md_wq = man_linkrec_find(muxid);
	/*
	 * If we can't find the linkrec then return an
	 * error. It will be automatically unplumbed on failure.
	 */
	if (mdp->md_wq == NULL)
		status = EAGAIN;

	(void) ldi_close(lh, NULL, kcred);
exit:
	if (li)
		ldi_ident_release(li);

	MAN_DBG(MAN_SWITCH, ("man_plumb: exit\n"));

	return (status);
}

/*
 * man_unplumb - tear down the STREAMs framework for the lower multiplexor.
 *
 *	mdp - destination struct of interest
 *
 *	returns	- success - 0
 *		- failure - return error from ldi_ioctl
 */
static void
man_unplumb(man_dest_t *mdp)
{
	int	status, rval;

	MAN_DBG(MAN_SWITCH, ("man_unplumb: mdp"));
	MAN_DBGCALL(MAN_SWITCH, man_print_mdp(mdp));

	if (mdp->md_muxid == -1)
		return;

	ASSERT(man_ctl_lh != NULL);

	/*
	 * I_PUNLINK causes the multiplexor resources to be freed.
	 */
	status = ldi_ioctl(man_ctl_lh, I_PUNLINK, (intptr_t)mdp->md_muxid,
	    FREAD+FWRITE+FNOCTTY+FKIOCTL, kcred, &rval);
	if (status) {
		cmn_err(CE_WARN, "man_unplumb: ldi_ioctl(I_PUNLINK) failed"
		    " errno %d\n", status);
	}
	/*
	 * Delete linkrec if it exists.
	 */
	(void) man_linkrec_find(mdp->md_muxid);
	mdp->md_muxid = -1;

}

/*
 * The routines below deal with paths and pathgroups. These data structures
 * are used to track the physical devices connecting the domain and SSC.
 * These devices make up the lower streams of the MAN multiplexor. The
 * routines all expect the man_lock to be held.
 *
 * A pathgroup consists of all paths that connect a particular domain and the
 * SSC. The concept of a pathgroup id (pg_id) is used to uniquely identify
 * a pathgroup.  For Domains, there is just one pathgroup, that connecting
 * the domain to the SSC (pg_id == 0). On the SSC, there is one pathgroup per
 * domain. The pg_id field corresponds to the domain tags A-R. A pg_id of
 * 0 means domain tag A, a pg_id of 1 means domain B, etc.
 *
 * The path data structure identifies one path between the SSC and a domain.
 * It describes the information for the path: the major and minor number of
 * the physical device; kstat pointers; and ethernet address of the
 * other end of the path.
 *
 * The pathgroups are anchored at man_pg_head and are protected by the
 * by the inner perimeter. The routines are only called by the STREAMs
 * portion of the driver.
 */

/*
 * Update man instance pathgroup info. Exclusive inner perimeter assures
 * this code is single threaded. man_refcnt assures man_t wont detach
 * while we are playing with man_pg stuff.
 *
 * Returns 0 on success, errno on failure.
 */
int
man_pg_cmd(mi_path_t *mip, man_work_t *waiter_wp)
{
	int		status = 0;
	man_t		*manp;

	if (mip->mip_ndevs < 0) {
		status = EINVAL;
		cmn_err(CE_WARN, "man_pg_cmd: EINVAL: mip_ndevs %d",
		    mip->mip_ndevs);
		goto exit;
	}

	ASSERT(MUTEX_HELD(&man_lock));
	manp = ddi_get_soft_state(man_softstate, mip->mip_man_ppa);
	if (manp == NULL) {
		status = ENODEV;
		goto exit;
	}

	MAN_DBG(MAN_PATH, ("man_pg_cmd: mip"));
	MAN_DBGCALL(MAN_PATH, man_print_mip(mip));

	MAN_DBG(MAN_PATH, ("\tman_t"));
	MAN_DBGCALL(MAN_PATH, man_print_man(manp));

	switch (mip->mip_cmd) {
	case MI_PATH_ASSIGN:
		status = man_pg_assign(&manp->man_pg, mip, FALSE);
		break;

	case MI_PATH_ADD:
		status = man_pg_assign(&manp->man_pg, mip, TRUE);
		break;

	case MI_PATH_UNASSIGN:
		status = man_pg_unassign(&manp->man_pg, mip);
		break;

	case MI_PATH_ACTIVATE:
		status = man_pg_activate(manp, mip, waiter_wp);
		break;

	case MI_PATH_READ:
		status = man_pg_read(manp->man_pg, mip);
		break;

	default:
		status = EINVAL;
		cmn_err(CE_NOTE, "man_pg_cmd: invalid command");
		break;
	}

exit:
	MAN_DBG(MAN_PATH, ("man_pg_cmd: returns %d", status));

	return (status);
}

/*
 * Assign paths to a pathgroup. If pathgroup doesnt exists, create it.
 * If path doesnt exist, create it. If ethernet address of existing
 * pathgroup different, change it. If an existing path is not in the new
 * list, remove it.  If anything changed, send PATH_UPDATE request to
 * man_iwork to update all man_dest_t's.
 *
 * 	mplpp	- man pathgroup list point to point.
 *	mip	- new/updated pathgroup info to assign.
 */
static int
man_pg_assign(man_pg_t **mplpp, mi_path_t *mip, int add_only)
{
	man_pg_t	*mpg;
	man_path_t	*mp;
	man_path_t	*add_paths = NULL;
	int		cnt;
	int		i;
	int		first_pass = TRUE;
	int		status = 0;

	ASSERT(MUTEX_HELD(&man_lock));

	cnt = mip->mip_ndevs;
	if (cnt == 0) {
		status = EINVAL;
		cmn_err(CE_NOTE, "man_pg_assign: mip_ndevs == 0");
		goto exit;
	}

	/*
	 * Assure the devices to be assigned are not assigned to some other
	 * pathgroup.
	 */
	for (i = 0; i < cnt; i++) {
		mpg = man_find_path_by_dev(*mplpp, &mip->mip_devs[i], NULL);

		if (mpg == NULL)
			continue;

		if ((mpg->mpg_man_ppa != mip->mip_man_ppa) ||
		    (mpg->mpg_pg_id != mip->mip_pg_id)) {
			/*
			 * Already assigned to some other man instance
			 * or pathgroup.
			 */
			status = EEXIST;
			goto exit;
		}
	}

	/*
	 * Find pathgroup, or allocate new one if it doesnt exist and
	 * add it to list at mplpp. Result is that mpg points to
	 * pathgroup to modify.
	 */
	mpg = man_find_pg_by_id(*mplpp, mip->mip_pg_id);
	if (mpg == NULL) {

		status = man_pg_create(mplpp, &mpg, mip);
		if (status)
			goto exit;

	} else if (ether_cmp(&mip->mip_eaddr, &mpg->mpg_dst_eaddr) != 0) {

		cmn_err(CE_WARN, "man_pg_assign: ethernet address mismatch");
		cmn_err(CE_CONT, "existing %s",
		    ether_sprintf(&mpg->mpg_dst_eaddr));
		cmn_err(CE_CONT, "new %s",
		    ether_sprintf(&mip->mip_eaddr));

		status = EINVAL;
		goto exit;
	}

	/*
	 * Create list of new paths to add to pathgroup.
	 */
	for (i = 0; i < cnt; i++) {

		if (man_find_path_by_dev(*mplpp, &mip->mip_devs[i], NULL))
			continue;	/* Already exists in this pathgroup */

		mp = man_kzalloc(sizeof (man_path_t), KM_NOSLEEP);
		if (mp == NULL) {
			status = ENOMEM;
			goto exit;
		}

		mp->mp_device = mip->mip_devs[i];
		mp->mp_device.mdev_state = MDEV_ASSIGNED;

		MAN_DBG(MAN_PATH, ("man_pg_assign: assigning mdp"));
		MAN_DBGCALL(MAN_PATH, man_print_dev(&mp->mp_device));

		status = man_path_kstat_init(mp);
		if (status) {
			man_kfree(mp, sizeof (man_path_t));
			goto exit;
		}

		man_path_insert(&add_paths, mp);
	}

	/*
	 * man_dr_attach passes only the path which is being DRd in.
	 * So just add the path and don't worry about removing paths.
	 */
	if (add_only == TRUE)
		goto exit;


	/*
	 * Check if any paths we want to remove are ACTIVE. If not,
	 * do a second pass and remove them.
	 */
again:
	mp = mpg->mpg_pathp;
	while (mp != NULL) {
		int		in_new_list;
		man_path_t	*rp;

		rp = NULL;
		in_new_list = FALSE;

		for (i = 0; i < cnt; i++) {
			if (mp->mp_device.mdev_ppa ==
			    mip->mip_devs[i].mdev_ppa) {

				in_new_list = TRUE;
				break;
			}
		}

		if (!in_new_list) {
			if (first_pass) {
				if (mp->mp_device.mdev_state & MDEV_ACTIVE) {
					status = EBUSY;
					goto exit;
				}
			} else {
				rp = mp;
			}
		}
		mp = mp->mp_next;

		if (rp != NULL)
			man_path_remove(&mpg->mpg_pathp, rp);
	}

	if (first_pass == TRUE) {
		first_pass = FALSE;
		goto again;
	}

exit:
	if (status == 0) {
		if (add_paths)
			man_path_merge(&mpg->mpg_pathp, add_paths);
	} else {
		while (add_paths != NULL) {
			mp = add_paths;
			add_paths = mp->mp_next;
			mp->mp_next = NULL;

			man_path_kstat_uninit(mp);
			man_kfree(mp, sizeof (man_path_t));
		}
	}

	return (status);
}

/*
 * Remove all paths from a pathgroup (domain shutdown). If there is an
 * active path in the group, shut down all destinations referencing it
 * first.
 */
static int
man_pg_unassign(man_pg_t **plpp, mi_path_t *mip)
{
	man_pg_t	*mpg;
	man_pg_t	*tpg;
	man_pg_t	*tppg;
	man_path_t	*mp = NULL;
	int		status = 0;

	ASSERT(MUTEX_HELD(&man_lock));

	/*
	 * Check for existence of pathgroup.
	 */
	if ((mpg = man_find_pg_by_id(*plpp, mip->mip_pg_id)) == NULL)
		goto exit;

	if (man_find_active_path(mpg->mpg_pathp) != NULL) {
		status = man_remove_dests(mpg);
		if (status)
			goto exit;
	}

	/*
	 * Free all the paths for this pathgroup.
	 */
	while (mpg->mpg_pathp) {
		mp = mpg->mpg_pathp;
		mpg->mpg_pathp = mp->mp_next;
		mp->mp_next = NULL;

		man_path_kstat_uninit(mp);
		man_kfree(mp, sizeof (man_path_t));
	}

	/*
	 * Remove this pathgroup from the list, and free it.
	 */
	tpg = tppg = *plpp;
	if (tpg == mpg) {
		*plpp = tpg->mpg_next;
		goto free_pg;
	}

	for (tpg = tpg->mpg_next; tpg != NULL; tpg = tpg->mpg_next) {
		if (tpg == mpg)
			break;
		tppg = tpg;
	}

	ASSERT(tpg != NULL);

	tppg->mpg_next = tpg->mpg_next;
	tpg->mpg_next = NULL;

free_pg:
	man_kfree(tpg, sizeof (man_pg_t));

exit:
	return (status);

}

/*
 * Set a new active path. This is done via man_ioctl so we are
 * exclusive in the inner perimeter.
 */
static int
man_pg_activate(man_t *manp, mi_path_t *mip, man_work_t *waiter_wp)
{
	man_pg_t	*mpg1;
	man_pg_t	*mpg2;
	man_pg_t	*plp;
	man_path_t	*mp;
	man_path_t	*ap;
	int		status = 0;

	ASSERT(MUTEX_HELD(&man_lock));
	MAN_DBG(MAN_PATH, ("man_pg_activate: dev"));
	MAN_DBGCALL(MAN_PATH, man_print_dev(mip->mip_devs));

	if (mip->mip_ndevs != 1) {
		status = EINVAL;
		goto exit;
	}

	plp = manp->man_pg;
	mpg1 = man_find_pg_by_id(plp, mip->mip_pg_id);
	if (mpg1 == NULL) {
		status = EINVAL;
		goto exit;
	}

	mpg2 = man_find_path_by_dev(plp, mip->mip_devs, &mp);
	if (mpg2 == NULL) {
		status = ENODEV;
		goto exit;
	}

	if (mpg1 != mpg2) {
		status = EINVAL;
		goto exit;
	}

	ASSERT(mp->mp_device.mdev_ppa == mip->mip_devs->mdev_ppa);

	if (mpg1->mpg_flags & MAN_PG_SWITCHING) {
		status = EAGAIN;
		goto exit;
	}

	ap = man_find_active_path(mpg1->mpg_pathp);
	if (ap == NULL) {
		/*
		 * This is the first time a path has been activated for
		 * this pathgroup. Initialize all upper streams dest
		 * structure for this pathgroup so autoswitch will find
		 * them.
		 */
		mp->mp_device.mdev_state |= MDEV_ACTIVE;
		man_add_dests(mpg1);
		goto exit;
	}

	/*
	 * Path already active, nothing to do.
	 */
	if (ap == mp)
		goto exit;

	/*
	 * Try to autoswitch to requested device. Set flags and refcnt.
	 * Cleared in man_iswitch when SWITCH completes.
	 */
	manp->man_refcnt++;
	mpg1->mpg_flags |= MAN_PG_SWITCHING;

	/*
	 * Switch to path specified.
	 */
	status = man_autoswitch(mpg1, mip->mip_devs, waiter_wp);

	if (status != 0) {
		/*
		 * man_iswitch not going to run, clean up.
		 */
		manp->man_refcnt--;
		mpg1->mpg_flags &= ~MAN_PG_SWITCHING;

		if (status == ENODEV) {
			/*
			 * Device not plumbed isn't really an error. Change
			 * active device setting here, since man_iswitch isn't
			 * going to be run to do it.
			 */
			status = 0;
			ap->mp_device.mdev_state &= ~MDEV_ACTIVE;
			mp->mp_device.mdev_state |= MDEV_ACTIVE;
		}
	}

exit:
	MAN_DBG(MAN_PATH, ("man_pg_activate: returns %d", status));

	return (status);
}

static int
man_pg_read(man_pg_t *plp, mi_path_t *mip)
{
	man_pg_t	*mpg;
	man_path_t	*mp;
	int		cnt;
	int		status = 0;

	ASSERT(MUTEX_HELD(&man_lock));

	if ((mpg = man_find_pg_by_id(plp, mip->mip_pg_id)) == NULL) {
		status = ENODEV;
		goto exit;
	}

	cnt = 0;
	for (mp = mpg->mpg_pathp; mp != NULL; mp = mp->mp_next) {
		bcopy(&mp->mp_device, &mip->mip_devs[cnt], sizeof (man_dev_t));
		if (cnt == mip->mip_ndevs)
			break;
		cnt++;
	}

	MAN_DBG(MAN_PATH, ("man_pg_read: pg(0x%p) id(%d) found %d paths",
	    (void *)mpg, mpg->mpg_pg_id, cnt));

	mip->mip_ndevs = cnt;

	/*
	 * TBD - What should errno be if user buffer too small ?
	 */
	if (mp != NULL) {
		status = ENOMEM;
	}

exit:

	return (status);
}

/*
 * return existing pathgroup, or create it. TBD - Need to update
 * all of destinations if we added a pathgroup. Also, need to update
 * all of man_strup if we add a path.
 *
 * 	mplpp	- man pathgroup list point to pointer.
 * 	mpgp	- returns newly created man pathgroup.
 *	mip	- info to fill in mpgp.
 */
static int
man_pg_create(man_pg_t **mplpp, man_pg_t **mpgp, mi_path_t *mip)
{
	man_pg_t	*mpg;
	man_pg_t	*tpg;
	int		status = 0;

	ASSERT(MUTEX_HELD(&man_lock));

	if (ether_cmp(&mip->mip_eaddr, &zero_ether_addr) == 0) {
		cmn_err(CE_NOTE, "man_ioctl: man_pg_create: ether"
		    " addresss not set!");
		status = EINVAL;
		goto exit;
	}

	mpg = man_kzalloc(sizeof (man_pg_t), KM_NOSLEEP);
	if (mpg == NULL) {
		status = ENOMEM;
		goto exit;
	}

	mpg->mpg_flags = MAN_PG_IDLE;
	mpg->mpg_pg_id = mip->mip_pg_id;
	mpg->mpg_man_ppa = mip->mip_man_ppa;
	ether_copy(&mip->mip_eaddr, &mpg->mpg_dst_eaddr);

	MAN_DBG(MAN_PATH, ("man_pg_create: new mpg"));
	MAN_DBGCALL(MAN_PATH, man_print_mpg(mpg));

	tpg = *mplpp;
	if (tpg == NULL) {
		*mplpp = mpg;
	} else {
		while (tpg->mpg_next != NULL)
			tpg = tpg->mpg_next;
		tpg->mpg_next = mpg;
	}

exit:
	*mpgp = mpg;

	return (status);
}

/*
 * Return pointer to pathgroup containing mdevp, null otherwise. Also,
 * if a path pointer is passed in, set it to matching path in pathgroup.
 *
 * Called holding man_lock.
 */
static man_pg_t *
man_find_path_by_dev(man_pg_t *plp, man_dev_t *mdevp, man_path_t **mpp)
{
	man_pg_t	*mpg;
	man_path_t	*mp;

	ASSERT(MUTEX_HELD(&man_lock));
	for (mpg = plp; mpg != NULL; mpg = mpg->mpg_next) {
		for (mp  = mpg->mpg_pathp; mp != NULL; mp = mp->mp_next) {
			if (mp->mp_device.mdev_major == mdevp->mdev_major &&
			    mp->mp_device.mdev_ppa == mdevp->mdev_ppa) {

				if (mpp != NULL)
					*mpp = mp;
				return (mpg);
			}
		}
	}

	return (NULL);
}

/*
 * Return pointer to pathgroup assigned to destination, null if not found.
 *
 * Called holding man_lock.
 */
static man_pg_t *
man_find_pg_by_id(man_pg_t *mpg, int pg_id)
{
	ASSERT(MUTEX_HELD(&man_lock));
	for (; mpg != NULL; mpg = mpg->mpg_next) {
		if (mpg->mpg_pg_id == pg_id)
			return (mpg);
	}

	return (NULL);
}

static man_path_t *
man_find_path_by_ppa(man_path_t *mplist, int ppa)
{
	man_path_t	*mp;

	ASSERT(MUTEX_HELD(&man_lock));
	for (mp = mplist; mp != NULL; mp = mp->mp_next) {
		if (mp->mp_device.mdev_ppa == ppa)
			return (mp);
	}

	return (NULL);
}

static man_path_t *
man_find_active_path(man_path_t *mplist)
{
	man_path_t	*mp;

	ASSERT(MUTEX_HELD(&man_lock));
	for (mp = mplist; mp != NULL; mp = mp->mp_next)
		if (mp->mp_device.mdev_state & MDEV_ACTIVE)
			return (mp);

	return (NULL);
}

/*
 * Try and find an alternate path.
 */
static man_path_t *
man_find_alternate_path(man_path_t *mlp)
{
	man_path_t	*ap;		/* Active path */
	man_path_t	*np;		/* New alternate path */
	man_path_t	*fp = NULL;	/* LRU failed path */

	ASSERT(MUTEX_HELD(&man_lock));
	ap = man_find_active_path(mlp);

	/*
	 * Find a non-failed path, or the lru failed path and switch to it.
	 */
	for (np = mlp; np != NULL; np = np->mp_next) {
		if (np == ap)
			continue;

		if (np->mp_device.mdev_state == MDEV_ASSIGNED)
			goto exit;

		if (np->mp_device.mdev_state & MDEV_FAILED) {
			if (fp == NULL)
				fp = np;
			else
				if (fp->mp_lru > np->mp_lru)
						fp = np;
		}
	}

	/*
	 * Nowhere to switch to.
	 */
	if (np == NULL && (np =  fp) == NULL)
		goto exit;

exit:
	return (np);
}

/*
 * Assumes caller has verified existence.
 */
static void
man_path_remove(man_path_t **lpp, man_path_t *mp)
{
	man_path_t	*tp;
	man_path_t	*tpp;

	ASSERT(MUTEX_HELD(&man_lock));
	MAN_DBG(MAN_PATH, ("man_path_remove: removing path"));
	MAN_DBGCALL(MAN_PATH, man_print_path(mp));

	tp = tpp = *lpp;
	if (tp == mp) {
		*lpp = tp->mp_next;
		goto exit;
	}

	for (tp = tp->mp_next; tp != NULL; tp = tp->mp_next) {
		if (tp == mp)
			break;
		tpp = tp;
	}

	ASSERT(tp != NULL);

	tpp->mp_next = tp->mp_next;
	tp->mp_next = NULL;

exit:
	man_path_kstat_uninit(tp);
	man_kfree(tp, sizeof (man_path_t));

}

/*
 * Insert path into list, ascending order by ppa.
 */
static void
man_path_insert(man_path_t **lpp, man_path_t *mp)
{
	man_path_t	*tp;
	man_path_t	*tpp;

	ASSERT(MUTEX_HELD(&man_lock));
	if (*lpp == NULL) {
		*lpp = mp;
		return;
	}

	tp = tpp = *lpp;
	if (tp->mp_device.mdev_ppa > mp->mp_device.mdev_ppa) {
		mp->mp_next = tp;
		*lpp = mp;
		return;
	}

	for (tp = tp->mp_next; tp != NULL; tp =  tp->mp_next) {
		if (tp->mp_device.mdev_ppa > mp->mp_device.mdev_ppa)
			break;
		tpp = tp;
	}

	if (tp == NULL) {
		tpp->mp_next = mp;
	} else {
		tpp->mp_next = mp;
		mp->mp_next = tp;
	}
}

/*
 * Merge npp into lpp, ascending order by ppa. Assumes no
 * duplicates in either list.
 */
static void
man_path_merge(man_path_t **lpp, man_path_t *np)
{
	man_path_t	*tmp;

	ASSERT(MUTEX_HELD(&man_lock));
	while (np != NULL) {
		tmp = np;
		np = np->mp_next;
		tmp->mp_next = NULL;

		man_path_insert(lpp, tmp);
	}

}

static int
man_path_kstat_init(man_path_t *mpp)
{

	kstat_named_t	*dev_knp;
	int		status = 0;

	ASSERT(MUTEX_HELD(&man_lock));
	MAN_DBG(MAN_PATH, ("man_path_kstat_init: mpp(0x%p)\n", (void *)mpp));

	/*
	 * Create named kstats for accounting purposes.
	 */
	dev_knp = man_kzalloc(MAN_NUMSTATS * sizeof (kstat_named_t),
	    KM_NOSLEEP);
	if (dev_knp == NULL) {
		status = ENOMEM;
		goto exit;
	}
	man_kstat_named_init(dev_knp, MAN_NUMSTATS);
	mpp->mp_last_knp = dev_knp;

exit:

	MAN_DBG(MAN_PATH, ("man_path_kstat_init: returns %d\n", status));

	return (status);
}

static void
man_path_kstat_uninit(man_path_t *mp)
{
	ASSERT(MUTEX_HELD(&man_lock));
	man_kfree(mp->mp_last_knp, MAN_NUMSTATS * sizeof (kstat_named_t));
}

/*
 * man_work_alloc - allocate and initiate a work request structure
 *
 *	type - type of request to allocate
 *	returns	- success - ptr to an initialized work structure
 *		- failure - NULL
 */
man_work_t *
man_work_alloc(int type, int kmflag)
{
	man_work_t	*wp;

	wp = man_kzalloc(sizeof (man_work_t), kmflag);
	if (wp == NULL)
		goto exit;

	cv_init(&wp->mw_cv, NULL, CV_DRIVER, NULL); \
	wp->mw_type = type;

exit:
	return (wp);
}

/*
 * man_work_free - deallocate a work request structure
 *
 *	wp - ptr to work structure to be freed
 */
void
man_work_free(man_work_t *wp)
{
	cv_destroy(&wp->mw_cv);
	man_kfree((void *)wp, sizeof (man_work_t));
}

/*
 * Post work to a work queue.  The man_bwork sleeps on
 * man_bwork_q->q_cv, and work requesters may sleep on mw_cv.
 * The man_lock is used to protect both cv's.
 */
void
man_work_add(man_workq_t *q, man_work_t *wp)
{
	man_work_t	*lp = q->q_work;

	if (lp) {
		while (lp->mw_next != NULL)
			lp = lp->mw_next;

		lp->mw_next = wp;

	} else {
		q->q_work = wp;
	}

	/*
	 * cv_signal for man_bwork_q, qenable for man_iwork_q
	 */
	if (q == man_bwork_q) {
		cv_signal(&q->q_cv);

	} else {	/* q == man_iwork_q */

		if (man_ctl_wq != NULL)
			qenable(man_ctl_wq);
	}

}

/* <<<<<<<<<<<<<<<<<<<<<<< NDD SUPPORT FUNCTIONS	>>>>>>>>>>>>>>>>>>> */
/*
 * ndd support functions to get/set parameters
 */

/*
 * Register each element of the parameter array with the
 * named dispatch handler. Each element is loaded using
 * nd_load()
 *
 * 	cnt	- the number of elements present in the parameter array
 */
static int
man_param_register(param_t *manpa, int cnt)
{
	int	i;
	ndgetf_t getp;
	ndsetf_t setp;
	int	status = B_TRUE;

	MAN_DBG(MAN_CONFIG, ("man_param_register: manpa(0x%p) cnt %d\n",
	    (void *)manpa, cnt));

	getp = man_param_get;

	for (i = 0; i < cnt; i++, manpa++) {
		switch (man_param_display[i]) {
		case MAN_NDD_GETABLE:
			setp = NULL;
			break;

		case MAN_NDD_SETABLE:
			setp = man_param_set;
			break;

		default:
			continue;
		}

		if (!nd_load(&man_ndlist, manpa->param_name, getp,
		    setp, (caddr_t)manpa)) {

			(void) man_nd_free(&man_ndlist);
			status = B_FALSE;
			goto exit;
		}
	}

	if (!nd_load(&man_ndlist, "man_pathgroups_report",
	    man_pathgroups_report, NULL, NULL)) {

		(void) man_nd_free(&man_ndlist);
		status = B_FALSE;
		goto exit;
	}

	if (!nd_load(&man_ndlist, "man_set_active_path",
	    NULL, man_set_active_path, NULL)) {

		(void) man_nd_free(&man_ndlist);
		status = B_FALSE;
		goto exit;
	}

	if (!nd_load(&man_ndlist, "man_get_hostinfo",
	    man_get_hostinfo, NULL, NULL)) {

		(void) man_nd_free(&man_ndlist);
		status = B_FALSE;
		goto exit;
	}

exit:

	MAN_DBG(MAN_CONFIG, ("man_param_register: returns %d\n", status));

	return (status);
}

static void
man_nd_getset(queue_t *wq, mblk_t *mp)
{

	if (!nd_getset(wq, man_ndlist, mp))
		miocnak(wq, mp, 0, ENOENT);
	else
		qreply(wq, mp);
}

/*ARGSUSED*/
static int
man_pathgroups_report(queue_t *wq, mblk_t *mp, caddr_t cp, cred_t *cr)
{

	man_t		*manp;
	man_pg_t	*mpg;
	int		i;
	char		pad[] = "                 "; /* 17 spaces */
	int		pad_end;


	MAN_DBG(MAN_PATH, ("man_pathgroups_report: wq(0x%p) mp(0x%p)"
	    " caddr 0x%p", (void *)wq, (void *)mp, (void *)cp));

	(void) mi_mpprintf(mp, "MAN Pathgroup report: (* == failed)");
	(void) mi_mpprintf(mp, "====================================="
	    "==========================================");

	mutex_enter(&man_lock);

	for (i = 0; i < 2; i++) {
		manp = ddi_get_soft_state(man_softstate, i);
		if (manp == NULL)
			continue;

	(void) mi_mpprintf(mp,
	    "Interface\tDestination\t\tActive Path\tAlternate Paths");
	(void) mi_mpprintf(mp, "---------------------------------------"
	    "----------------------------------------");

		for (mpg = manp->man_pg; mpg != NULL; mpg = mpg->mpg_next) {

			(void) mi_mpprintf(mp, "%s%d\t\t",
			    ddi_major_to_name(manp->man_meta_major),
			    manp->man_meta_ppa);

			if (man_is_on_domain) {
				(void) mi_mpprintf_nr(mp, "Master SSC\t");
				man_preport(mpg->mpg_pathp, mp);
			} else {
				if (i == 0) {
					pad_end = 17 - strlen(ether_sprintf(
					    &mpg->mpg_dst_eaddr));
					if (pad_end < 0 || pad_end > 16)
					pad_end = 0;
					pad[pad_end] = '\0';

					(void) mi_mpprintf_nr(mp, "%c %s%s",
					    mpg->mpg_pg_id + 'A',
					    ether_sprintf(&mpg->mpg_dst_eaddr),
					    pad);

					pad[pad_end] = ' ';
				} else {
					(void) mi_mpprintf_nr(mp,
					    "Other SSC\t");
				}
				man_preport(mpg->mpg_pathp, mp);
			}
			(void) mi_mpprintf_nr(mp, "\n");
		}
	}

	mutex_exit(&man_lock);
	MAN_DBG(MAN_PATH, ("man_pathgroups_report: returns"));

	return (0);
}

static void
man_preport(man_path_t *plist, mblk_t *mp)
{
	man_path_t	*ap;

	ap = man_find_active_path(plist);
	/*
	 * Active path
	 */
	if (ap != NULL) {
		(void) mi_mpprintf_nr(mp, "\t%s%d\t\t",
		    ddi_major_to_name(ap->mp_device.mdev_major),
		    ap->mp_device.mdev_ppa);
	} else {
		(void) mi_mpprintf_nr(mp, "None \t");
	}

	/*
	 * Alternate Paths.
	 */
	while (plist != NULL) {
		(void) mi_mpprintf_nr(mp, "%s%d exp %d",
		    ddi_major_to_name(plist->mp_device.mdev_major),
		    plist->mp_device.mdev_ppa,
		    plist->mp_device.mdev_exp_id);
		if (plist->mp_device.mdev_state & MDEV_FAILED)
			(void) mi_mpprintf_nr(mp, "*");
		plist = plist->mp_next;
		if (plist)
			(void) mi_mpprintf_nr(mp, ", ");
	}
}

/*
 * NDD request to set active path. Calling context is man_ioctl, so we are
 * exclusive in the inner perimeter.
 *
 *	Syntax is "ndd -set /dev/dman <man ppa> <pg_id> <phys ppa>"
 */
/* ARGSUSED3 */
static int
man_set_active_path(queue_t *wq, mblk_t *mp, char *value, caddr_t cp,
    cred_t *cr)
{
	char		*end, *meta_ppap, *phys_ppap, *pg_idp;
	int		meta_ppa;
	int		phys_ppa;
	int		pg_id;
	man_t		*manp;
	man_pg_t	*mpg;
	man_path_t	*np;
	mi_path_t	mpath;
	int		status = 0;

	MAN_DBG(MAN_PATH, ("man_set_active_path: wq(0x%p) mp(0x%p)"
	    " args %s", (void *)wq, (void *)mp, value));

	meta_ppap = value;

	if ((pg_idp = strchr(value, ' ')) == NULL) {
		status = EINVAL;
		goto exit;
	}

	*pg_idp++ = '\0';

	if ((phys_ppap = strchr(pg_idp, ' ')) == NULL) {
		status = EINVAL;
		goto exit;
	}

	*phys_ppap++ = '\0';

	meta_ppa = (int)mi_strtol(meta_ppap, &end, 10);
	pg_id = (int)mi_strtol(pg_idp, &end, 10);
	phys_ppa = (int)mi_strtol(phys_ppap, &end, 10);

	mutex_enter(&man_lock);
	manp = ddi_get_soft_state(man_softstate, meta_ppa);
	if (manp == NULL || manp->man_pg == NULL) {
		status = EINVAL;
		mutex_exit(&man_lock);
		goto exit;
	}

	mpg = man_find_pg_by_id(manp->man_pg, pg_id);
	if (mpg == NULL) {
		status = EINVAL;
		mutex_exit(&man_lock);
		goto exit;
	}

	np = man_find_path_by_ppa(mpg->mpg_pathp, phys_ppa);

	if (np == NULL) {
		status = EINVAL;
		mutex_exit(&man_lock);
		goto exit;
	}

	mpath.mip_cmd = MI_PATH_ACTIVATE;
	mpath.mip_pg_id = pg_id;
	mpath.mip_man_ppa = meta_ppa;
	mpath.mip_devs[0] = np->mp_device;
	mpath.mip_ndevs = 1;

	status = man_pg_cmd(&mpath, NULL);
	mutex_exit(&man_lock);

exit:

	MAN_DBG(MAN_PATH, ("man_set_active_path: returns %d", status));

	return (status);
}

/*
 * Dump out the contents of the IOSRAM handoff structure. Note that if
 * anything changes here, you must make sure that the sysinit script
 * stays in sync with this output.
 */
/* ARGSUSED */
static int
man_get_hostinfo(queue_t *wq, mblk_t *mp, caddr_t cp, cred_t *cr)
{
	manc_t	manc;
	char	*ipaddr;
	char	ipv6addr[INET6_ADDRSTRLEN];
	int	i;
	int	status;

	if (!man_is_on_domain)
		return (0);

	if (status = man_get_iosram(&manc)) {
		return (status);
	}

	(void) mi_mpprintf(mp, "manc_magic = 0x%x", manc.manc_magic);
	(void) mi_mpprintf(mp, "manc_version = 0%d", manc.manc_version);
	(void) mi_mpprintf(mp, "manc_csum = 0x%x", manc.manc_csum);

	if (manc.manc_ip_type == AF_INET) {
		in_addr_t	netnum;

		(void) mi_mpprintf(mp, "manc_ip_type = AF_INET");

		ipaddr = man_inet_ntoa(manc.manc_dom_ipaddr);
		(void) mi_mpprintf(mp, "manc_dom_ipaddr = %s", ipaddr);

		ipaddr = man_inet_ntoa(manc.manc_dom_ip_netmask);
		(void) mi_mpprintf(mp, "manc_dom_ip_netmask = %s", ipaddr);

		netnum = manc.manc_dom_ipaddr & manc.manc_dom_ip_netmask;
		ipaddr = man_inet_ntoa(netnum);
		(void) mi_mpprintf(mp, "manc_dom_ip_netnum = %s", ipaddr);

		ipaddr = man_inet_ntoa(manc.manc_sc_ipaddr);
		(void) mi_mpprintf(mp, "manc_sc_ipaddr = %s", ipaddr);

	} else if (manc.manc_ip_type == AF_INET6) {

		(void) mi_mpprintf(mp, "manc_ip_type = AF_INET6");

		(void) inet_ntop(AF_INET6, (void *)&manc.manc_dom_ipv6addr,
		    ipv6addr, INET6_ADDRSTRLEN);
		(void) mi_mpprintf(mp, "manc_dom_ipv6addr = %s", ipv6addr);

		(void) mi_mpprintf(mp, "manc_dom_ipv6_netmask = %d",
		    manc.manc_dom_ipv6_netmask.s6_addr[0]);

		(void) inet_ntop(AF_INET6, (void *)&manc.manc_sc_ipv6addr,
		    ipv6addr, INET6_ADDRSTRLEN);
		(void) mi_mpprintf(mp, "manc_sc_ipv6addr = %s", ipv6addr);

	} else {

		(void) mi_mpprintf(mp, "manc_ip_type = NONE");
	}

	(void) mi_mpprintf(mp, "manc_dom_eaddr = %s",
	    ether_sprintf(&manc.manc_dom_eaddr));
	(void) mi_mpprintf(mp, "manc_sc_eaddr = %s",
	    ether_sprintf(&manc.manc_sc_eaddr));

	(void) mi_mpprintf(mp, "manc_iob_bitmap = 0x%x\tio boards = ",
	    manc.manc_iob_bitmap);
	for (i = 0; i < MAN_MAX_EXPANDERS; i++) {
		if ((manc.manc_iob_bitmap >> i) & 0x1) {
			(void) mi_mpprintf_nr(mp, "%d.1, ", i);
		}
	}
	(void) mi_mpprintf(mp, "manc_golden_iob = %d", manc.manc_golden_iob);

	return (0);
}

static char *
man_inet_ntoa(in_addr_t in)
{
	static char b[18];
	unsigned char *p;

	p = (unsigned char *)&in;
	(void) sprintf(b, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return (b);
}

/*
 * parameter value. cp points to the required parameter.
 */
/* ARGSUSED */
static int
man_param_get(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *cr)
{
	param_t	*manpa = (param_t *)cp;

	(void) mi_mpprintf(mp, "%u", manpa->param_val);
	return (0);
}

/*
 * Sets the man parameter to the value in the param_register using
 * nd_load().
 */
/* ARGSUSED */
static int
man_param_set(queue_t *q, mblk_t *mp, char *value, caddr_t cp, cred_t *cr)
{
	char *end;
	size_t new_value;
	param_t	*manpa = (param_t *)cp;

	new_value = mi_strtol(value, &end, 10);

	if (end == value || new_value < manpa->param_min ||
	    new_value > manpa->param_max) {
			return (EINVAL);
	}

	manpa->param_val = new_value;

	return (0);

}

/*
 * Free the Named Dispatch Table by calling man_nd_free
 */
static void
man_param_cleanup()
{
	if (man_ndlist != NULL)
		nd_free(&man_ndlist);
}

/*
 * Free the table pointed to by 'ndp'
 */
static void
man_nd_free(caddr_t *nd_pparam)
{
	ND	*nd;

	if ((nd = (ND *)(*nd_pparam)) != NULL) {
		if (nd->nd_tbl)
			mi_free((char *)nd->nd_tbl);
		mi_free((char *)nd);
		*nd_pparam = NULL;
	}
}


/*
 * man_kstat_update - update the statistics for a meta-interface.
 *
 *	ksp - kstats struct
 *	rw - flag indicating whether stats are to be read or written.
 *
 *	returns	0
 *
 * The destination specific kstat information is protected by the
 * perimeter lock, so we submit a work request to get the stats
 * updated (see man_do_kstats()), and then collect the results
 * when cv_signal'd. Note that we are doing cv_timedwait_sig()
 * as a precautionary measure only.
 */
static int
man_kstat_update(kstat_t *ksp, int rw)
{
	man_t			*manp;		/* per instance data */
	man_work_t		*wp;
	int			status = 0;
	kstat_named_t		*knp;
	kstat_named_t		*man_knp;
	int			i;

	MAN_DBG(MAN_KSTAT, ("man_kstat_update: %s\n", rw ? "KSTAT_WRITE" :
	    "KSTAT_READ"));

	mutex_enter(&man_lock);
	manp = (man_t *)ksp->ks_private;
	manp->man_refcnt++;

	/*
	 * If the driver has been configured, get kstats updated by inner
	 * perimeter prior to retrieving.
	 */
	if (man_config_state == MAN_CONFIGURED) {
		clock_t wait_status;

		man_update_path_kstats(manp);
		wp = man_work_alloc(MAN_WORK_KSTAT_UPDATE, KM_SLEEP);
		wp->mw_arg.a_man_ppa = manp->man_meta_ppa;
		wp->mw_flags = MAN_WFLAGS_CVWAITER;
		man_work_add(man_iwork_q, wp);

		wait_status = cv_reltimedwait_sig(&wp->mw_cv, &man_lock,
		    drv_usectohz(manp->man_kstat_waittime), TR_CLOCK_TICK);

		if (wp->mw_flags & MAN_WFLAGS_DONE) {
			status = wp->mw_status;
			man_work_free(wp);
		} else {
			ASSERT(wait_status <= 0);
			wp->mw_flags &= ~MAN_WFLAGS_CVWAITER;
			if (wait_status == 0)
				status = EINTR;
			else {
				MAN_DBG(MAN_KSTAT, ("man_kstat_update: "
				    "timedout, returning stale stats."));
				status = 0;
			}
		}
		if (status)
			goto exit;
	}

	knp = (kstat_named_t *)ksp->ks_data;
	man_knp = (kstat_named_t *)manp->man_ksp->ks_data;

	if (rw == KSTAT_READ) {
		for (i = 0; i < MAN_NUMSTATS; i++) {
			knp[i].value.ui64 = man_knp[i].value.ui64;
		}
	} else {
		for (i = 0; i < MAN_NUMSTATS; i++) {
			man_knp[i].value.ui64 = knp[i].value.ui64;
		}
	}

exit:
	manp->man_refcnt--;
	mutex_exit(&man_lock);

	MAN_DBG(MAN_KSTAT, ("man_kstat_update: returns %d", status));

	return (status);
}

/*
 * Sum destination kstats for all active paths for a given instance of the
 * MAN driver. Called with perimeter lock.
 */
static void
man_do_kstats(man_work_t *wp)
{
	man_t		*manp;
	man_pg_t	*mpg;
	man_path_t	*mp;

	MAN_DBG(MAN_KSTAT, ("man_do_kstats:"));

	mutex_enter(&man_lock);
	/*
	 * Sync mp_last_knp for each path associated with the MAN instance.
	 */
	manp = (man_t *)ddi_get_soft_state(man_softstate,
	    wp->mw_arg.a_man_ppa);
	for (mpg = manp->man_pg; mpg != NULL; mpg = mpg->mpg_next) {

		ASSERT(mpg->mpg_man_ppa == manp->man_meta_ppa);

		if ((mp = man_find_active_path(mpg->mpg_pathp)) != NULL) {

			MAN_DBG(MAN_KSTAT, ("\tkstat: path"));
			MAN_DBGCALL(MAN_KSTAT, man_print_path(mp));

			/*
			 * We just to update the destination statistics here.
			 */
			man_sum_dests_kstats(mp->mp_last_knp, mpg);
		}
	}
	mutex_exit(&man_lock);
	MAN_DBG(MAN_KSTAT, ("man_do_kstats: returns"));
}

/*
 * Sum device kstats for all active paths for a given instance of the
 * MAN driver. Called with man_lock.
 */
static void
man_update_path_kstats(man_t *manp)
{
	kstat_named_t	*man_knp;
	man_pg_t	*mpg;
	man_path_t	*mp;

	ASSERT(MUTEX_HELD(&man_lock));
	MAN_DBG(MAN_KSTAT, ("man_update_path_kstats:"));

	man_knp = (kstat_named_t *)manp->man_ksp->ks_data;

	for (mpg = manp->man_pg; mpg != NULL; mpg = mpg->mpg_next) {

		ASSERT(mpg->mpg_man_ppa == manp->man_meta_ppa);

		if ((mp = man_find_active_path(mpg->mpg_pathp)) != NULL) {

			man_update_dev_kstats(man_knp, mp);

		}
	}
	MAN_DBG(MAN_KSTAT, ("man_update_path_kstats: returns"));
}

/*
 * Update the device kstats.
 * As man_kstat_update() is called with kstat_chain_lock held,
 * we can safely update the statistics from the underlying driver here.
 */
static void
man_update_dev_kstats(kstat_named_t *man_knp, man_path_t *mp)
{
	kstat_t		*dev_ksp;
	major_t		major;
	int		instance;
	char		buf[KSTAT_STRLEN];


	major = mp->mp_device.mdev_major;
	instance = mp->mp_device.mdev_ppa;
	(void) sprintf(buf, "%s%d", ddi_major_to_name(major), instance);

	dev_ksp = kstat_hold_byname(ddi_major_to_name(major), instance, buf,
	    ALL_ZONES);
	if (dev_ksp != NULL) {

		KSTAT_ENTER(dev_ksp);
		KSTAT_UPDATE(dev_ksp, KSTAT_READ);
		man_sum_kstats(man_knp, dev_ksp, mp->mp_last_knp);
		KSTAT_EXIT(dev_ksp);
		kstat_rele(dev_ksp);

	} else {
		MAN_DBG(MAN_KSTAT,
		    ("man_update_dev_kstats: no kstat data found for %s(%d,%d)",
		    buf, major, instance));
	}
}

static void
man_sum_dests_kstats(kstat_named_t *knp, man_pg_t *mpg)
{
	int		i;
	int		flags;
	char		*statname;
	manstr_t	*msp;
	man_dest_t	*mdp;
	uint64_t	switches = 0;
	uint64_t	linkfails = 0;
	uint64_t	linkstales = 0;
	uint64_t	icmpv4probes = 0;
	uint64_t	icmpv6probes = 0;

	MAN_DBG(MAN_KSTAT, ("man_sum_dests_kstats: mpg 0x%p", (void *)mpg));

	for (msp = man_strup; msp != NULL; msp = msp->ms_next) {

		if (!man_str_uses_pg(msp, mpg))
			continue;

		mdp = &msp->ms_dests[mpg->mpg_pg_id];

		switches += mdp->md_switches;
		linkfails += mdp->md_linkfails;
		linkstales += mdp->md_linkstales;
		icmpv4probes += mdp->md_icmpv4probes;
		icmpv6probes += mdp->md_icmpv6probes;
	}

	for (i = 0; i < MAN_NUMSTATS; i++) {

		statname = man_kstat_info[i].mk_name;
		flags = man_kstat_info[i].mk_flags;

		if (!(flags & MK_NOT_PHYSICAL))
			continue;

		if (strcmp(statname, "man_switches") == 0) {
			knp[i].value.ui64 = switches;
		} else if (strcmp(statname, "man_link_fails") == 0) {
			knp[i].value.ui64 = linkfails;
		} else if (strcmp(statname, "man_link_stales") == 0) {
			knp[i].value.ui64 = linkstales;
		} else if (strcmp(statname, "man_icmpv4_probes") == 0) {
			knp[i].value.ui64 = icmpv4probes;
		} else if (strcmp(statname, "man_icmpv6_probes") == 0) {
			knp[i].value.ui64 = icmpv6probes;
		}
	}

	MAN_DBG(MAN_KSTAT, ("man_sum_dests_kstats: returns"));
}

/*
 * Initialize MAN named kstats in the space provided.
 */
static void
man_kstat_named_init(kstat_named_t *knp, int num_stats)
{
	int	i;

	MAN_DBG(MAN_KSTAT, ("man_kstat_named_init: knp(0x%p) num_stats = %d",
	    (void *)knp, num_stats));

	for (i = 0; i < num_stats; i++) {
		kstat_named_init(&knp[i], man_kstat_info[i].mk_name,
		    man_kstat_info[i].mk_type);
	}

	MAN_DBG(MAN_KSTAT, ("man_kstat_named_init: returns"));

}

/*
 * man_kstat_byname - get a kernel stat value from its structure
 *
 *	ksp - kstat_t structure to play with
 *	s   - string to match names with
 *	res - in/out result data pointer
 *
 *	returns	- success - 1 (found)
 *		- failure - 0 (not found)
 */
static int
man_kstat_byname(kstat_t *ksp, char *s, kstat_named_t *res)
{
	int		found = 0;

	MAN_DBG(MAN_KSTAT2, ("man_kstat_byname: GETTING %s\n", s));

	if (ksp->ks_type == KSTAT_TYPE_NAMED) {
		kstat_named_t *knp;

		for (knp = KSTAT_NAMED_PTR(ksp);
		    (caddr_t)knp < ((caddr_t)ksp->ks_data+ksp->ks_data_size);
		    knp++) {

			if (strcmp(s, knp->name) == NULL) {

				res->data_type = knp->data_type;
				res->value = knp->value;
				found++;

				MAN_DBG(MAN_KSTAT2, ("\t%s: %d\n", knp->name,
				    (int)knp->value.ul));
			}
		}
	} else {
		MAN_DBG(MAN_KSTAT2, ("\tbad kstats type %d\n", ksp->ks_type));
	}

	/*
	 * if getting a value but couldn't find the namestring, result = 0.
	 */
	if (!found) {
		/*
		 * a reasonable default
		 */
		res->data_type = KSTAT_DATA_ULONG;
		res->value.l = 0;
		MAN_DBG(MAN_KSTAT2, ("\tcouldn't find, using defaults\n"));
	}

	MAN_DBG(MAN_KSTAT2, ("man_kstat_byname: returns\n"));

	return (found);
}


/*
 *
 * Accumulate MAN driver kstats from the incremental values of the underlying
 * physical interfaces.
 *
 * Parameters:
 *	sum_knp		- The named kstat area to put cumulative value,
 *			  NULL if we just want to sync next two params.
 *	phys_ksp	- Physical interface kstat_t pointer. Contains
 *			  more current counts.
 * 	phys_last_knp	- counts from the last time we were called for this
 *			  physical interface. Note that the name kstats
 *			  pointed to are actually in MAN format, but they
 *			  hold the mirrored physical devices last read
 *			  kstats.
 * Basic algorithm is:
 *
 * 	for each named kstat variable {
 *	    sum_knp[i] += (phys_ksp->ksp_data[i] - phys_last_knp[i]);
 *	    phys_last_knp[i] = phys_ksp->ksp_data[i];
 *	}
 *
 */
static void
man_sum_kstats(kstat_named_t *sum_knp, kstat_t *phys_ksp,
	kstat_named_t *phys_last_knp)
{
	char		*physname;
	char		*physalias;
	char		*statname;
	kstat_named_t	phys_kn_entry;
	uint64_t	delta64;
	int		i;

	MAN_DBG(MAN_KSTAT, ("man_sum_kstats: sum_knp(0x%p) phys_ksp(0x%p)"
	    " phys_last_knp(0x%p)\n", (void *)sum_knp, (void *)phys_ksp,
	    (void *)phys_last_knp));

	/*
	 * Now for each entry in man_kstat_info, sum the named kstat.
	 * Not that all MAN specific kstats will end up !found.
	 */
	for (i = 0; i < MAN_NUMSTATS; i++) {
		int	found = 0;
		int	flags = 0;

		delta64 = 0;

		statname = man_kstat_info[i].mk_name;
		physname = man_kstat_info[i].mk_physname;
		physalias = man_kstat_info[i].mk_physalias;
		flags = man_kstat_info[i].mk_flags;

		/*
		 * Update MAN private kstats.
		 */
		if (flags & MK_NOT_PHYSICAL) {

			kstat_named_t	*knp = phys_last_knp;

			if (sum_knp == NULL)
				continue;

			if (strcmp(statname, "man_switches") == 0) {
				sum_knp[i].value.ui64 = knp[i].value.ui64;
			} else if (strcmp(statname, "man_link_fails") == 0) {
				sum_knp[i].value.ui64 = knp[i].value.ui64;
			} else if (strcmp(statname, "man_link_stales") == 0) {
				sum_knp[i].value.ui64 = knp[i].value.ui64;
			} else if (strcmp(statname, "man_icmpv4_probes") == 0) {
				sum_knp[i].value.ui64 = knp[i].value.ui64;
			} else if (strcmp(statname, "man_icmpv6_probes") == 0) {
				sum_knp[i].value.ui64 = knp[i].value.ui64;
			}

			continue;	/* phys_ksp doesnt have this stat */
		}

		/*
		 * first try it by the "official" name
		 */
		if (phys_ksp) {
			if (man_kstat_byname(phys_ksp, physname,
			    &phys_kn_entry)) {

				found = 1;

			} else if ((physalias) && (man_kstat_byname(phys_ksp,
			    physalias, &phys_kn_entry))) {

				found = 1;
			}
		}

		if (!found) {
			/*
			 * clear up the "last" value, no change to the sum
			 */
			phys_last_knp[i].value.ui64 = 0;
			continue;
		}

		/*
		 * at this point, we should have the good underlying
		 * kstat value stored in phys_kn_entry
		 */
		if (flags & MK_NOT_COUNTER) {
			/*
			 * it isn't a counter, so store the value and
			 * move on (e.g. ifspeed)
			 */
			phys_last_knp[i].value = phys_kn_entry.value;
			continue;
		}

		switch (phys_kn_entry.data_type) {
		case KSTAT_DATA_UINT32:

			/*
			 * this handles 32-bit wrapping
			 */
			if (phys_kn_entry.value.ui32 <
			    phys_last_knp[i].value.ui32) {

				/*
				 * we've wrapped!
				 */
				delta64 += (UINT_MAX -
				    phys_last_knp[i].value.ui32);
				phys_last_knp[i].value.ui32 = 0;
			}

			delta64 += phys_kn_entry.value.ui32 -
			    phys_last_knp[i].value.ui32;
			phys_last_knp[i].value.ui32 = phys_kn_entry.value.ui32;
			break;

		default:
			/*
			 * must be a 64-bit value, we ignore 64-bit
			 * wraps, since they shouldn't ever happen
			 * within the life of a machine (if we assume
			 * machines don't stay up for more than a few
			 * hundred years without a reboot...)
			 */
			delta64 = phys_kn_entry.value.ui64 -
			    phys_last_knp[i].value.ui64;
			phys_last_knp[i].value.ui64 = phys_kn_entry.value.ui64;
		}

		if (sum_knp != NULL) {
			/*
			 * now we need to save the value
			 */
			switch (sum_knp[i].data_type) {
			case KSTAT_DATA_UINT32:
				/* trunk down to 32 bits, possibly lossy */
				sum_knp[i].value.ui32 += (uint32_t)delta64;
				break;

			default:
				sum_knp[i].value.ui64 += delta64;
				break;
			}
		}
	}

	MAN_DBG(MAN_KSTAT, ("man_sum_kstats: returns\n"));
}


#if defined(DEBUG)


static char *_ms_flags[] = {
	"NONE",
	"FAST", 	/* 0x1 */
	"RAW",		/* 0x2 */
	"ALLPHYS",	/* 0x4 */
	"ALLMULTI",	/* 0x8 */
	"ALLSAP",	/* 0x10 */
	"CKSUM",	/* 0x20 */
	"MULTI",	/* 0x40 */
	"SERLPBK",	/* 0x80 */
	"MACLPBK",	/* 0x100 */
	"CLOSING",	/* 0x200 */
	"CLOSE_DONE",	/* 0x400 */
	"CONTROL"	/* 0x800 */
};

static void
man_print_msp(manstr_t *msp)
{
	char	buf[512];
	char	prbuf[512];
	uint_t	flags;
	int	i;

	cmn_err(CE_CONT, "\tmsp(0x%p)\n", (void *)msp);

	if (msp == NULL)
		return;

	cmn_err(CE_CONT, "\t%s%d SAP(0x%x):\n",
	    ddi_major_to_name(msp->ms_meta_maj), msp->ms_meta_ppa,
	    msp->ms_sap);

	buf[0] = '\0';
	prbuf[0] = '\0';
	flags = msp->ms_flags;
	for (i = 0; i < A_CNT(_ms_flags); i++) {
		if ((flags >> i) & 0x1) {
			(void) sprintf(buf, " %s |", _ms_flags[i+1]);
			(void) strcat(prbuf, buf);
		}
	}
	prbuf[strlen(prbuf) - 1] = '\0';
	cmn_err(CE_CONT, "\tms_flags: %s\n", prbuf);

	cmn_err(CE_CONT, "\tms_dlpistate: %s\n", dss[msp->ms_dlpistate]);

	cmn_err(CE_CONT, "\tms_dl_mp: 0x%p\n", (void *)msp->ms_dl_mp);

	cmn_err(CE_CONT, "\tms_manp: 0x%p\n", (void *)msp->ms_manp);

	cmn_err(CE_CONT, "\tms_dests: 0x%p\n", (void *)msp->ms_dests);

}

static char *_md_state[] = {
	"NOTPRESENT",		/* 0x0 */
	"INITIALIZING",		/* 0x1 */
	"READY",		/* 0x2 */
	"PLUMBING",		/* 0x4 */
	"CLOSING"		/* 0x8 */
};

static void
man_print_mdp(man_dest_t *mdp)
{
	uint_t		state;
	int		i;
	char		buf[64];
	char		prbuf[512];

	buf[0] = '\0';
	prbuf[0] = '\0';

	cmn_err(CE_CONT, "\tmdp(0x%p)\n", (void *)mdp);

	if (mdp == NULL)
		return;

	cmn_err(CE_CONT, "\tmd_pg_id: %d\n", mdp->md_pg_id);
	cmn_err(CE_CONT, "\tmd_dst_eaddr: %s\n",
	    ether_sprintf(&mdp->md_dst_eaddr));
	cmn_err(CE_CONT, "\tmd_src_eaddr: %s\n",
	    ether_sprintf(&mdp->md_src_eaddr));
	cmn_err(CE_CONT, "\tmd_dlpistate: %s", dss[mdp->md_dlpistate]);
	cmn_err(CE_CONT, "\tmd_muxid: 0x%u", mdp->md_muxid);
	cmn_err(CE_CONT, "\tmd_rcvcnt %lu md_lastrcvcnt %lu", mdp->md_rcvcnt,
	    mdp->md_lastrcvcnt);

	/*
	 * Print out state as text.
	 */
	state = mdp->md_state;

	if (state == 0) {
		(void) strcat(prbuf, _md_state[0]);
	} else {

		for (i = 0; i < A_CNT(_md_state); i++) {
			if ((state >> i) & 0x1)  {
				(void) sprintf(buf, " %s |", _md_state[i+1]);
				(void) strcat(prbuf, buf);
			}
		}
		prbuf[strlen(prbuf) -1] = '\0';
	}
	cmn_err(CE_CONT, "\tmd_state: %s", prbuf);

	cmn_err(CE_CONT, "\tmd_device:\n");
	man_print_dev(&mdp->md_device);

}

static void
man_print_man(man_t *manp)
{
	char	buf[512];
	char	prbuf[512];

	buf[0] = '\0';
	prbuf[0] = '\0';

	if (manp == NULL)
		return;

	if (ddi_major_to_name(manp->man_meta_major)) {
		(void) sprintf(buf, "\t man_device: %s%d\n",
		    ddi_major_to_name(manp->man_meta_major),
		    manp->man_meta_ppa);
	} else {
		(void) sprintf(buf, "\t major: %d", manp->man_meta_major);
		(void) sprintf(buf, "\t ppa: %d", manp->man_meta_ppa);
	}

	cmn_err(CE_CONT, "%s", buf);

}

static char *_mdev_state[] = {
	"UNASSIGNED  ",
	"ASSIGNED",
	"ACTIVE",
	"FAILED"
};

static void
man_print_dev(man_dev_t *mdevp)
{
	char	buf[512];
	char	prbuf[512];
	int	i;
	uint_t	state;

	buf[0] = '\0';
	prbuf[0] = '\0';

	if (mdevp == NULL)
		return;

	if (mdevp->mdev_major == 0) {
number:
		(void) sprintf(buf, "\t mdev_major: %d\n", mdevp->mdev_major);
	} else if (ddi_major_to_name(mdevp->mdev_major)) {
		(void) sprintf(buf, "\t mdev_device: %s%d\n",
		    ddi_major_to_name(mdevp->mdev_major),
		    mdevp->mdev_ppa);
	} else
		goto number;

	cmn_err(CE_CONT, "%s", buf);

	cmn_err(CE_CONT, "\t mdev_exp_id: %d\n", mdevp->mdev_exp_id);

	buf[0] = '\0';
	prbuf[0] = '\0';
	state = mdevp->mdev_state;

	if (state == 0) {
		(void) strcat(prbuf, _mdev_state[0]);
	} else {
		for (i = 0; i < A_CNT(_mdev_state); i++) {
			if ((state >> i) & 0x1) {
				(void) sprintf(buf, " %s |", _mdev_state[i+1]);
				(void) strcat(prbuf, buf);
			}
		}
	}

	prbuf[strlen(prbuf) - 2] = '\0';

	cmn_err(CE_CONT, "\t mdev_state: %s\n", prbuf);

}

static char *_mip_cmd[] = {
	"MI_PATH_READ",
	"MI_PATH_ASSIGN",
	"MI_PATH_ACTIVATE",
	"MI_PATH_DEACTIVATE",
	"MI_PATH_UNASSIGN"
};

static void
man_print_mtp(mi_time_t *mtp)
{
	cmn_err(CE_CONT, "\tmtp(0x%p)\n", (void *)mtp);

	if (mtp == NULL)
		return;

	cmn_err(CE_CONT, "\tmtp_instance: %d\n", mtp->mtp_man_ppa);

	cmn_err(CE_CONT, "\tmtp_time: %d\n", mtp->mtp_time);

}

static void
man_print_mip(mi_path_t *mip)
{
	cmn_err(CE_CONT, "\tmip(0x%p)\n", (void *)mip);

	if (mip == NULL)
		return;

	cmn_err(CE_CONT, "\tmip_pg_id: %d\n", mip->mip_pg_id);

	cmn_err(CE_CONT, "\tmip_cmd: %s\n", _mip_cmd[mip->mip_cmd]);

	cmn_err(CE_CONT, "\tmip_eaddr: %s\n", ether_sprintf(&mip->mip_eaddr));

	cmn_err(CE_CONT, "\tmip_devs: 0x%p\n", (void *)mip->mip_devs);

	cmn_err(CE_CONT, "\tmip_ndevs: %d\n", mip->mip_ndevs);

}

static void
man_print_mpg(man_pg_t *mpg)
{
	cmn_err(CE_CONT, "\tmpg(0x%p)\n", (void *)mpg);

	if (mpg == NULL)
		return;

	cmn_err(CE_CONT, "\tmpg_next: 0x%p\n", (void *)mpg->mpg_next);

	cmn_err(CE_CONT, "\tmpg_pg_id: %d\n", mpg->mpg_pg_id);

	cmn_err(CE_CONT, "\tmpg_man_ppa: %d\n", mpg->mpg_man_ppa);

	cmn_err(CE_CONT, "\tmpg_dst_eaddr: %s\n",
	    ether_sprintf(&mpg->mpg_dst_eaddr));

	cmn_err(CE_CONT, "\tmpg_pathp: 0x%p\n", (void *)mpg->mpg_pathp);

}

static char *_mw_flags[] = {
	"NOWAITER",		/* 0x0 */
	"CVWAITER",		/* 0x1 */
	"QWAITER",		/* 0x2 */
	"DONE"		/* 0x3 */
};

static void
man_print_work(man_work_t *wp)
{
	int 	i;

	cmn_err(CE_CONT, "\twp(0x%p)\n\n", (void *)wp);

	if (wp == NULL)
		return;

	cmn_err(CE_CONT, "\tmw_type: %s\n", _mw_type[wp->mw_type]);

	cmn_err(CE_CONT, "\tmw_flags: ");
	for (i = 0; i < A_CNT(_mw_flags); i++) {
		if ((wp->mw_flags >> i) & 0x1)
			cmn_err(CE_CONT, "%s", _mw_flags[i]);
	}
	cmn_err(CE_CONT, "\n");

	cmn_err(CE_CONT, "\twp_status: %d\n", wp->mw_status);

	cmn_err(CE_CONT, "\twp_arg: 0x%p\n", (void *)&wp->mw_arg);

	cmn_err(CE_CONT, "\tmw_next: 0x%p\n", (void *)wp->mw_next);

	cmn_err(CE_CONT, "\twp_q: 0x%p", (void *)wp->mw_q);

}

static void
man_print_path(man_path_t *mp)
{
	cmn_err(CE_CONT, "\tmp(0x%p)\n\n", (void *)mp);

	if (mp == NULL)
		return;

	cmn_err(CE_CONT, "\tmp_device:");
	man_print_dev(&mp->mp_device);

	cmn_err(CE_CONT, "\tmp_next: 0x%p\n", (void *)mp->mp_next);

	cmn_err(CE_CONT, "\tmp_last_knp: 0x%p\n", (void *)mp->mp_last_knp);

	cmn_err(CE_CONT, "\tmp_lru: 0x%lx", mp->mp_lru);

}

void *
man_dbg_kzalloc(int line, size_t size, int kmflags)
{
	void *tmp;

	tmp = kmem_zalloc(size, kmflags);
	MAN_DBG(MAN_KMEM, ("0x%p %lu\tzalloc'd @ %d\n", (void *)tmp,
	    size, line));

	return (tmp);

}

void
man_dbg_kfree(int line, void *buf, size_t size)
{

	MAN_DBG(MAN_KMEM, ("0x%p %lu\tfree'd @ %d\n", (void *)buf, size, line));

	kmem_free(buf, size);

}

#endif  /* DEBUG */
