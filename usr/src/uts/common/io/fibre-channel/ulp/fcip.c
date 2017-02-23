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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*
 * SunOS 5.x Multithreaded STREAMS DLPI FCIP Module
 * This is a pseudo driver module to handle encapsulation of IP and ARP
 * datagrams over FibreChannel interfaces. FCIP is a cloneable STREAMS
 * driver module which interfaces with IP/ARP using DLPI. This module
 * is a Style-2 DLS provider.
 *
 * The implementation of this module is based on RFC 2625 which gives
 * details on the encapsulation of IP/ARP data over FibreChannel.
 * The fcip module needs to resolve an IP address to a port address before
 * sending data to a destination port. A FC device port has 2 addresses
 * associated with it: A 8 byte World Wide unique Port Name and a 3 byte
 * volatile Port number or Port_ID.
 *
 * The mapping between a IP address and the World Wide Port Name is handled
 * by the ARP layer since the IP over FC draft requires the MAC address to
 * be the least significant six bytes of the WorldWide Port Names. The
 * fcip module however needs to identify the destination port uniquely when
 * the destination FC device has multiple FC ports.
 *
 * The FC layer mapping between the World Wide Port Name and the Port_ID
 * will be handled through the use of a fabric name server or through the
 * use of the FARP ELS command as described in the draft. Since the Port_IDs
 * are volatile, the mapping between the World Wide Port Name and Port_IDs
 * must be maintained and validated before use each time a datagram
 * needs to be sent to the destination ports. The FC transport module
 * informs the fcip module of all changes to states of ports on the
 * fabric through registered callbacks. This enables the fcip module
 * to maintain the WW_PN to Port_ID mappings current.
 *
 * For details on how this module interfaces with the FibreChannel Transport
 * modules, refer to PSARC/1997/385. Chapter 3 of the FibreChannel Transport
 * Programming guide details the APIs between ULPs and the Transport.
 *
 * Now for some Caveats:
 *
 * RFC 2625 requires that a FibreChannel Port name (the Port WWN) have
 * the NAA bits set to '0001' indicating a IEEE 48bit address which
 * corresponds to a ULA (Universal LAN MAC address). But with FibreChannel
 * adapters containing 2 or more ports, IEEE naming cannot identify the
 * ports on an adapter uniquely so we will in the first implementation
 * be operating only on Port 0 of each adapter.
 */

#include	<sys/types.h>
#include	<sys/errno.h>
#include	<sys/debug.h>
#include	<sys/time.h>
#include	<sys/sysmacros.h>
#include	<sys/systm.h>
#include	<sys/user.h>
#include	<sys/stropts.h>
#include	<sys/stream.h>
#include	<sys/strlog.h>
#include	<sys/strsubr.h>
#include	<sys/cmn_err.h>
#include	<sys/cpu.h>
#include	<sys/kmem.h>
#include	<sys/conf.h>
#include	<sys/ddi.h>
#include	<sys/sunddi.h>
#include	<sys/ksynch.h>
#include	<sys/stat.h>
#include	<sys/kstat.h>
#include	<sys/vtrace.h>
#include	<sys/strsun.h>
#include	<sys/varargs.h>
#include	<sys/modctl.h>
#include 	<sys/thread.h>
#include 	<sys/var.h>
#include 	<sys/proc.h>
#include	<inet/common.h>
#include	<netinet/ip6.h>
#include	<inet/ip.h>
#include	<inet/arp.h>
#include	<inet/mi.h>
#include	<inet/nd.h>
#include	<sys/dlpi.h>
#include	<sys/ethernet.h>
#include	<sys/file.h>
#include	<sys/syslog.h>
#include	<sys/disp.h>
#include	<sys/taskq.h>

/*
 * Leadville includes
 */

#include	<sys/fibre-channel/fc.h>
#include	<sys/fibre-channel/impl/fc_ulpif.h>
#include	<sys/fibre-channel/ulp/fcip.h>

/*
 * TNF Probe/trace facility include
 */
#if defined(lint) || defined(FCIP_TNF_ENABLED)
#include <sys/tnf_probe.h>
#endif

#define	FCIP_ESBALLOC

/*
 * Function prototypes
 */

/* standard loadable modules entry points */
static int	fcip_attach(dev_info_t *, ddi_attach_cmd_t);
static int 	fcip_detach(dev_info_t *, ddi_detach_cmd_t);
static void 	fcip_dodetach(struct fcipstr *slp);
static int fcip_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd,
    void *arg, void **result);


/* streams specific */
static void fcip_setipq(struct fcip *fptr);
static int fcip_wput(queue_t *, mblk_t *);
static int fcip_wsrv(queue_t *);
static void fcip_proto(queue_t *, mblk_t *);
static void fcip_ioctl(queue_t *, mblk_t *);
static int fcip_open(queue_t *wq, dev_t *devp, int flag,
		int sflag, cred_t *credp);
static int fcip_close(queue_t *rq, int flag, int otyp, cred_t *credp);
static int fcip_start(queue_t *wq, mblk_t *mp, struct fcip *fptr,
    struct fcip_dest *fdestp, int flags);
static void fcip_sendup(struct fcip *fptr, mblk_t *mp,
    struct fcipstr *(*acceptfunc)());
static struct fcipstr *fcip_accept(struct fcipstr *slp, struct fcip *fptr,
    int type, la_wwn_t *dhostp);
static mblk_t *fcip_addudind(struct fcip *fptr, mblk_t *mp,
    fcph_network_hdr_t *nhdr, int type);
static int fcip_setup_mac_addr(struct fcip *fptr);
static void fcip_kstat_init(struct fcip *fptr);
static int fcip_stat_update(kstat_t *, int);


/* dlpi specific */
static void fcip_spareq(queue_t *wq, mblk_t *mp);
static void fcip_pareq(queue_t *wq, mblk_t *mp);
static void fcip_ubreq(queue_t *wq, mblk_t *mp);
static void fcip_breq(queue_t *wq, mblk_t *mp);
static void fcip_dreq(queue_t *wq, mblk_t *mp);
static void fcip_areq(queue_t *wq, mblk_t *mp);
static void fcip_udreq(queue_t *wq, mblk_t *mp);
static void fcip_ireq(queue_t *wq, mblk_t *mp);
static void fcip_dl_ioc_hdr_info(queue_t *wq, mblk_t *mp);


/* solaris sundry, DR/CPR etc */
static int fcip_cache_constructor(void *buf, void *arg, int size);
static void fcip_cache_destructor(void *buf, void *size);
static int fcip_handle_suspend(fcip_port_info_t *fport, fc_detach_cmd_t cmd);
static int fcip_handle_resume(fcip_port_info_t *fport,
    fc_ulp_port_info_t *port_info, fc_attach_cmd_t cmd);
static fcip_port_info_t *fcip_softstate_free(fcip_port_info_t *fport);
static int fcip_port_attach_handler(struct fcip *fptr);


/*
 * ulp - transport interface function prototypes
 */
static int fcip_port_attach(opaque_t ulp_handle, fc_ulp_port_info_t *,
    fc_attach_cmd_t cmd, uint32_t sid);
static int fcip_port_detach(opaque_t ulp_handle, fc_ulp_port_info_t *,
    fc_detach_cmd_t cmd);
static int fcip_port_ioctl(opaque_t ulp_handle,  opaque_t port_handle,
    dev_t dev, int cmd, intptr_t data, int mode, cred_t *credp, int *rval,
    uint32_t claimed);
static void fcip_statec_cb(opaque_t ulp_handle, opaque_t phandle,
    uint32_t port_state, uint32_t port_top, fc_portmap_t changelist[],
    uint32_t listlen, uint32_t sid);
static int fcip_els_cb(opaque_t ulp_handle, opaque_t phandle,
    fc_unsol_buf_t *buf, uint32_t claimed);
static int fcip_data_cb(opaque_t ulp_handle, opaque_t phandle,
    fc_unsol_buf_t *payload, uint32_t claimed);


/* Routing table specific */
static void fcip_handle_topology(struct fcip *fptr);
static int fcip_init_port(struct fcip *fptr);
struct fcip_routing_table *fcip_lookup_rtable(struct fcip *fptr,
    la_wwn_t *pwwn, int matchflag);
static void fcip_rt_update(struct fcip *fptr, fc_portmap_t *devlist,
    uint32_t listlen);
static void fcip_rt_flush(struct fcip *fptr);
static void fcip_rte_remove_deferred(void *arg);
static int fcip_do_plogi(struct fcip *fptr, struct fcip_routing_table *frp);


/* dest table specific */
static struct fcip_dest *fcip_get_dest(struct fcip *fptr,
    la_wwn_t *dlphys);
static struct fcip_dest *fcip_add_dest(struct fcip *fptr,
    struct fcip_routing_table *frp);
static int fcip_dest_add_broadcast_entry(struct fcip *fptr, int new_flag);
static uint32_t fcip_get_broadcast_did(struct fcip *fptr);
static void fcip_cleanup_dest(struct fcip *fptr);


/* helper functions */
static fcip_port_info_t *fcip_get_port(opaque_t phandle);
static int fcip_wwn_compare(la_wwn_t *wwn1, la_wwn_t *wwn2, int flag);
static void fcip_ether_to_str(struct ether_addr *e, caddr_t s);
static int fcip_port_get_num_pkts(struct fcip *fptr);
static int fcip_check_port_busy(struct fcip *fptr);
static void fcip_check_remove_minor_node(void);
static int fcip_set_wwn(la_wwn_t *pwwn);
static int fcip_plogi_in_progress(struct fcip *fptr);
static int fcip_check_port_exists(struct fcip *fptr);
static int fcip_is_supported_fc_topology(int fc_topology);


/* pkt specific */
static fcip_pkt_t *fcip_pkt_alloc(struct fcip *fptr, mblk_t *bp,
    int flags, int datalen);
static void fcip_pkt_free(struct fcip_pkt *fcip_pkt, int flags);
static fcip_pkt_t *fcip_ipkt_alloc(struct fcip *fptr, int cmdlen,
    int resplen, opaque_t pd, int flags);
static void fcip_ipkt_free(fcip_pkt_t *fcip_pkt);
static void fcip_ipkt_callback(fc_packet_t *fc_pkt);
static void fcip_free_pkt_dma(fcip_pkt_t *fcip_pkt);
static void fcip_pkt_callback(fc_packet_t *fc_pkt);
static void fcip_init_unicast_pkt(fcip_pkt_t *fcip_pkt, fc_portid_t sid,
    fc_portid_t did, void (*comp) ());
static int fcip_transport(fcip_pkt_t *fcip_pkt);
static void fcip_pkt_timeout(void *arg);
static void fcip_timeout(void *arg);
static void fcip_fdestp_enqueue_pkt(struct fcip_dest *fdestp,
    fcip_pkt_t *fcip_pkt);
static int fcip_fdestp_dequeue_pkt(struct fcip_dest *fdestp,
    fcip_pkt_t *fcip_pkt);
static int fcip_sendup_constructor(void *buf, void *arg, int flags);
static void fcip_sendup_thr(void *arg);
static int fcip_sendup_alloc_enque(struct fcip *ftpr, mblk_t *mp,
    struct fcipstr *(*f)());

/*
 * zero copy inbound data handling
 */
#ifdef FCIP_ESBALLOC
static void fcip_ubfree(char *arg);
#endif /* FCIP_ESBALLOC */

#if !defined(FCIP_ESBALLOC)
static void *fcip_allocb(size_t size, uint_t pri);
#endif


/* FCIP FARP support functions */
static struct fcip_dest *fcip_do_farp(struct fcip *fptr, la_wwn_t *pwwn,
    char *ip_addr, size_t ip_addr_len, int flags);
static void fcip_init_broadcast_pkt(fcip_pkt_t *fcip_pkt, void (*comp) (),
    int is_els);
static int fcip_handle_farp_request(struct fcip *fptr, la_els_farp_t *fcmd);
static int fcip_handle_farp_response(struct fcip *fptr, la_els_farp_t *fcmd);
static void fcip_cache_arp_broadcast(struct fcip *ftpr, fc_unsol_buf_t *buf);
static void fcip_port_ns(void *arg);

#ifdef DEBUG

#include <sys/debug.h>

#define	FCIP_DEBUG_DEFAULT	0x1
#define	FCIP_DEBUG_ATTACH	0x2
#define	FCIP_DEBUG_INIT		0x4
#define	FCIP_DEBUG_DETACH	0x8
#define	FCIP_DEBUG_DLPI		0x10
#define	FCIP_DEBUG_ELS		0x20
#define	FCIP_DEBUG_DOWNSTREAM	0x40
#define	FCIP_DEBUG_UPSTREAM	0x80
#define	FCIP_DEBUG_MISC		0x100

#define	FCIP_DEBUG_STARTUP	(FCIP_DEBUG_ATTACH|FCIP_DEBUG_INIT)
#define	FCIP_DEBUG_DATAOUT	(FCIP_DEBUG_DLPI|FCIP_DEBUG_DOWNSTREAM)
#define	FCIP_DEBUG_DATAIN	(FCIP_DEBUG_ELS|FCIP_DEBUG_UPSTREAM)

static int fcip_debug = FCIP_DEBUG_DEFAULT;

#define	FCIP_DEBUG(level, args)	\
	if (fcip_debug & (level))	cmn_err args;

#else	/* DEBUG */

#define	FCIP_DEBUG(level, args)		/* do nothing */

#endif	/* DEBUG */

#define	KIOIP	KSTAT_INTR_PTR(fcip->fcip_intrstats)

/*
 * Endian independent ethernet to WWN copy
 */
#define	ether_to_wwn(E, W)	\
	bzero((void *)(W), sizeof (la_wwn_t)); \
	bcopy((void *)(E), (void *)&((W)->raw_wwn[2]), ETHERADDRL); \
	(W)->raw_wwn[0] |= 0x10

/*
 * wwn_to_ether : Endian independent, copies a WWN to struct ether_addr.
 * The args to the macro are pointers to WWN and ether_addr structures
 */
#define	wwn_to_ether(W, E)	\
	bcopy((void *)&((W)->raw_wwn[2]), (void *)E, ETHERADDRL)

/*
 * The module_info structure contains identification and limit values.
 * All queues associated with a certain driver share the same module_info
 * structures. This structure defines the characteristics of that driver/
 * module's queues. The module name must be unique. The max and min packet
 * sizes limit the no. of characters in M_DATA messages. The Hi and Lo
 * water marks are for flow control when a module has a service procedure.
 */
static struct module_info	fcipminfo = {
	FCIPIDNUM,	/* mi_idnum : Module ID num */
	FCIPNAME, 	/* mi_idname: Module Name */
	FCIPMINPSZ,	/* mi_minpsz: Min packet size */
	FCIPMAXPSZ,	/* mi_maxpsz: Max packet size */
	FCIPHIWAT,	/* mi_hiwat : High water mark */
	FCIPLOWAT	/* mi_lowat : Low water mark */
};

/*
 * The qinit structres contain the module put, service. open and close
 * procedure pointers. All modules and drivers with the same streamtab
 * file (i.e same fmodsw or cdevsw entry points) point to the same
 * upstream (read) and downstream (write) qinit structs.
 */
static struct qinit	fcip_rinit = {
	NULL,		/* qi_putp */
	NULL,		/* qi_srvp */
	fcip_open,	/* qi_qopen */
	fcip_close,	/* qi_qclose */
	NULL,		/* qi_qadmin */
	&fcipminfo,	/* qi_minfo */
	NULL		/* qi_mstat */
};

static struct qinit	fcip_winit = {
	fcip_wput,	/* qi_putp */
	fcip_wsrv,	/* qi_srvp */
	NULL,		/* qi_qopen */
	NULL,		/* qi_qclose */
	NULL,		/* qi_qadmin */
	&fcipminfo,	/* qi_minfo */
	NULL		/* qi_mstat */
};

/*
 * streamtab contains pointers to the read and write qinit structures
 */

static struct streamtab fcip_info = {
	&fcip_rinit,	/* st_rdinit */
	&fcip_winit,	/* st_wrinit */
	NULL,		/* st_muxrinit */
	NULL,		/* st_muxwrinit */
};

static struct cb_ops  fcip_cb_ops = {
	nodev,				/* open */
	nodev,				/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	nodev,				/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* poll */
	ddi_prop_op,			/* cb_prop_op */
	&fcip_info,			/* streamtab  */
	D_MP | D_HOTPLUG,		/* Driver compatibility flag */
	CB_REV,				/* rev */
	nodev,				/* int (*cb_aread)() */
	nodev				/* int (*cb_awrite)() */
};

/*
 * autoconfiguration routines.
 */
static struct dev_ops fcip_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	fcip_getinfo,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	fcip_attach,		/* attach */
	fcip_detach,		/* detach */
	nodev,			/* RESET */
	&fcip_cb_ops,		/* driver operations */
	NULL,			/* bus operations */
	ddi_power		/* power management */
};

#define	FCIP_VERSION	"1.61"
#define	FCIP_NAME	"SunFC FCIP v" FCIP_VERSION

#define	PORT_DRIVER	"fp"

#define	GETSTRUCT(struct, number)	\
	((struct *)kmem_zalloc((size_t)(sizeof (struct) * (number)), \
		KM_SLEEP))

static struct modldrv modldrv = {
	&mod_driverops,			/* Type of module - driver */
	FCIP_NAME,			/* Name of module */
	&fcip_ops,			/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
};


/*
 * Now for some global statics
 */
static uint32_t	fcip_ub_nbufs = FCIP_UB_NBUFS;
static uint32_t fcip_ub_size = FCIP_UB_SIZE;
static int fcip_pkt_ttl_ticks = FCIP_PKT_TTL;
static int fcip_tick_incr = 1;
static int fcip_wait_cmds = FCIP_WAIT_CMDS;
static int fcip_num_attaching = 0;
static int fcip_port_attach_pending = 0;
static int fcip_create_nodes_on_demand = 1;	/* keep it similar to fcp */
static int fcip_cache_on_arp_broadcast = 0;
static int fcip_farp_supported = 0;
static int fcip_minor_node_created = 0;

/*
 * Supported FCAs
 */
#define	QLC_PORT_1_ID_BITS		0x100
#define	QLC_PORT_2_ID_BITS		0x101
#define	QLC_PORT_NAA			0x2
#define	QLC_MODULE_NAME			"qlc"
#define	IS_QLC_PORT(port_dip)		\
			(strcmp(ddi_driver_name(ddi_get_parent((port_dip))),\
			QLC_MODULE_NAME) == 0)


/*
 * fcip softstate structures head.
 */

static void *fcip_softp = NULL;

/*
 * linked list of active (inuse) driver streams
 */

static int fcip_num_instances = 0;
static dev_info_t *fcip_module_dip = (dev_info_t *)0;


/*
 * Ethernet broadcast address: Broadcast addressing in IP over fibre
 * channel should be the IEEE ULA (also the low 6 bytes of the Port WWN).
 *
 * The broadcast addressing varies for differing topologies a node may be in:
 *	- On a private loop the ARP broadcast is a class 3 sequence sent
 *	  using OPNfr (Open Broadcast Replicate primitive) followed by
 *	  the ARP frame to D_ID 0xFFFFFF
 *
 *	- On a public Loop the broadcast sequence is sent to AL_PA 0x00
 *	  (no OPNfr primitive).
 *
 *	- For direct attach and point to point topologies we just send
 *	  the frame to D_ID 0xFFFFFF
 *
 * For public loop the handling would probably be different - for now
 * I'll just declare this struct - It can be deleted if not necessary.
 *
 */


/*
 * DL_INFO_ACK template for the fcip module. The dl_info_ack_t structure is
 * returned as a part of an  DL_INFO_ACK message which is a M_PCPROTO message
 * returned in response to a DL_INFO_REQ message sent to us from a DLS user
 * Let us fake an ether header as much as possible.
 *
 * dl_addr_length is the Provider's DLSAP addr which is SAP addr +
 *                Physical addr of the provider. We set this to
 *                ushort_t + sizeof (la_wwn_t) for Fibre Channel ports.
 * dl_mac_type    Lets just use DL_ETHER - we can try using DL_IPFC, a new
 *		  dlpi.h define later.
 * dl_sap_length  -2 indicating the SAP address follows the Physical addr
 *		  component in the DLSAP addr.
 * dl_service_mode: DLCLDS - connectionless data link service.
 *
 */

static dl_info_ack_t fcip_infoack = {
	DL_INFO_ACK,				/* dl_primitive */
	FCIPMTU,				/* dl_max_sdu */
	0,					/* dl_min_sdu */
	FCIPADDRL,				/* dl_addr_length */
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
	sizeof (dl_info_ack_t) + FCIPADDRL,	/* dl_brdcst_addr_offset */
	0					/* dl_growth */
};

/*
 * FCIP broadcast address definition.
 */
static	struct ether_addr	fcipnhbroadcastaddr = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

/*
 * RFC2625 requires the broadcast ARP address in the ARP data payload to
 * be set to 0x00 00 00 00 00 00 for ARP broadcast packets
 */
static	struct ether_addr	fcip_arpbroadcast_addr = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};


#define	ether_bcopy(src, dest)	bcopy((src), (dest), ETHERADDRL);

/*
 * global kernel locks
 */
static kcondvar_t	fcip_global_cv;
static kmutex_t		fcip_global_mutex;

/*
 * fctl external defines
 */
extern int fc_ulp_add(fc_ulp_modinfo_t *);

/*
 * fctl data structures
 */

#define	FCIP_REV	0x07

/* linked list of port info structures */
static fcip_port_info_t *fcip_port_head = NULL;

/* linked list of fcip structures */
static struct fcipstr	*fcipstrup = NULL;
static krwlock_t	fcipstruplock;


/*
 * Module information structure. This structure gives the FC Transport modules
 * information about an ULP that registers with it.
 */
static fc_ulp_modinfo_t	fcip_modinfo = {
	0,			/* for xref checks? */
	FCTL_ULP_MODREV_4,	/* FCIP revision */
	FC_TYPE_IS8802_SNAP,	/* type 5 for SNAP encapsulated datagrams */
	FCIP_NAME,		/* module name as in the modldrv struct */
	0x0,			/* get all statec callbacks for now */
	fcip_port_attach,	/* port attach callback */
	fcip_port_detach,	/* port detach callback */
	fcip_port_ioctl,	/* port ioctl callback */
	fcip_els_cb,		/* els callback */
	fcip_data_cb,		/* data callback */
	fcip_statec_cb		/* state change callback */
};


/*
 * Solaris 9 and up, the /kernel/drv/fp.conf file will have the following entry
 *
 * ddi-forceattach=1;
 *
 * This will ensure that fp is loaded at bootup. No additional checks are needed
 */
int
_init(void)
{
	int	rval;

	FCIP_TNF_LOAD();

	/*
	 * Initialize the mutexs used by port attach and other callbacks.
	 * The transport can call back into our port_attach_callback
	 * routine even before _init() completes and bad things can happen.
	 */
	mutex_init(&fcip_global_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&fcip_global_cv, NULL, CV_DRIVER, NULL);
	rw_init(&fcipstruplock, NULL, RW_DRIVER, NULL);

	mutex_enter(&fcip_global_mutex);
	fcip_port_attach_pending = 1;
	mutex_exit(&fcip_global_mutex);

	/*
	 * Now attempt to register fcip with the transport.
	 * If fc_ulp_add fails, fcip module will not be loaded.
	 */
	rval = fc_ulp_add(&fcip_modinfo);
	if (rval != FC_SUCCESS) {
		mutex_destroy(&fcip_global_mutex);
		cv_destroy(&fcip_global_cv);
		rw_destroy(&fcipstruplock);
		switch (rval) {
		case FC_ULP_SAMEMODULE:
			FCIP_DEBUG(FCIP_DEBUG_DEFAULT, (CE_WARN,
			    "!fcip: module is already registered with"
			    " transport"));
			rval = EEXIST;
			break;
		case FC_ULP_SAMETYPE:
			FCIP_DEBUG(FCIP_DEBUG_DEFAULT, (CE_WARN,
			    "!fcip: Another module of the same ULP type 0x%x"
			    " is already registered with the transport",
			    fcip_modinfo.ulp_type));
			rval = EEXIST;
			break;
		case FC_BADULP:
			FCIP_DEBUG(FCIP_DEBUG_DEFAULT, (CE_WARN,
			    "!fcip: Current fcip version 0x%x does not match"
			    " fctl version",
			    fcip_modinfo.ulp_rev));
			rval = ENODEV;
			break;
		default:
			FCIP_DEBUG(FCIP_DEBUG_DEFAULT, (CE_WARN,
			    "!fcip: fc_ulp_add failed with status 0x%x", rval));
			rval = ENODEV;
			break;
		}
		FCIP_TNF_UNLOAD(&modlinkage);
		return (rval);
	}

	if ((rval = ddi_soft_state_init(&fcip_softp, sizeof (struct fcip),
			FCIP_NUM_INSTANCES)) != 0) {
		mutex_destroy(&fcip_global_mutex);
		cv_destroy(&fcip_global_cv);
		rw_destroy(&fcipstruplock);
		(void) fc_ulp_remove(&fcip_modinfo);
		FCIP_TNF_UNLOAD(&modlinkage);
		return (rval);
	}

	if ((rval = mod_install(&modlinkage)) != 0) {
		FCIP_TNF_UNLOAD(&modlinkage);
		(void) fc_ulp_remove(&fcip_modinfo);
		mutex_destroy(&fcip_global_mutex);
		cv_destroy(&fcip_global_cv);
		rw_destroy(&fcipstruplock);
		ddi_soft_state_fini(&fcip_softp);
	}
	return (rval);
}

/*
 * Unload the port driver if this was the only ULP loaded and then
 * deregister with the transport.
 */
int
_fini(void)
{
	int	rval;
	int	rval1;

	/*
	 * Do not permit the module to be unloaded before a port
	 * attach callback has happened.
	 */
	mutex_enter(&fcip_global_mutex);
	if (fcip_num_attaching || fcip_port_attach_pending) {
		mutex_exit(&fcip_global_mutex);
		return (EBUSY);
	}
	mutex_exit(&fcip_global_mutex);

	if ((rval = mod_remove(&modlinkage)) != 0) {
		return (rval);
	}

	/*
	 * unregister with the transport layer
	 */
	rval1 = fc_ulp_remove(&fcip_modinfo);

	/*
	 * If the ULP was not registered with the transport, init should
	 * have failed. If transport has no knowledge of our existence
	 * we should simply bail out and succeed
	 */
#ifdef DEBUG
	if (rval1 == FC_BADULP) {
		FCIP_DEBUG(FCIP_DEBUG_DEFAULT, (CE_WARN,
		"fcip: ULP was never registered with the transport"));
		rval = ENODEV;
	} else if (rval1 == FC_BADTYPE) {
		FCIP_DEBUG(FCIP_DEBUG_DEFAULT, (CE_WARN,
			"fcip: No ULP of this type 0x%x was registered with "
			"transport", fcip_modinfo.ulp_type));
		rval = ENODEV;
	}
#endif /* DEBUG */

	mutex_destroy(&fcip_global_mutex);
	rw_destroy(&fcipstruplock);
	cv_destroy(&fcip_global_cv);
	ddi_soft_state_fini(&fcip_softp);

	FCIP_TNF_UNLOAD(&modlinkage);

	return (rval);
}

/*
 * Info about this loadable module
 */
int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * The port attach callback is invoked by the port driver when a FCA
 * port comes online and binds with the transport layer. The transport
 * then callsback into all ULP modules registered with it. The Port attach
 * call back will also provide the ULP module with the Port's WWN and S_ID
 */
/* ARGSUSED */
static int
fcip_port_attach(opaque_t ulp_handle, fc_ulp_port_info_t *port_info,
    fc_attach_cmd_t cmd, uint32_t sid)
{
	int 			rval = FC_FAILURE;
	int 			instance;
	struct fcip		*fptr;
	fcip_port_info_t	*fport = NULL;
	fcip_port_info_t	*cur_fport;
	fc_portid_t		src_id;

	switch (cmd) {
	case FC_CMD_ATTACH: {
		la_wwn_t	*ww_pn = NULL;
		/*
		 * It was determined that, as per spec, the lower 48 bits of
		 * the port-WWN will always be unique. This will make the MAC
		 * address (i.e the lower 48 bits of the WWN), that IP/ARP
		 * depend on, unique too. Hence we should be able to remove the
		 * restriction of attaching to only one of the ports of
		 * multi port FCAs.
		 *
		 * Earlier, fcip used to attach only to qlc module and fail
		 * silently for attach failures resulting from unknown FCAs or
		 * unsupported FCA ports. Now, we'll do no such checks.
		 */
		ww_pn = &port_info->port_pwwn;

		FCIP_TNF_PROBE_2((fcip_port_attach, "fcip io", /* CSTYLED */,
			tnf_string, msg, "port id bits",
			tnf_opaque, nport_id, ww_pn->w.nport_id));
		FCIP_DEBUG(FCIP_DEBUG_ATTACH, (CE_NOTE,
		    "port id bits: 0x%x", ww_pn->w.nport_id));
		/*
		 * A port has come online
		 */
		mutex_enter(&fcip_global_mutex);
		fcip_num_instances++;
		fcip_num_attaching++;

		if (fcip_port_head == NULL) {
			/* OK to sleep here ? */
			fport = kmem_zalloc(sizeof (fcip_port_info_t),
						KM_NOSLEEP);
			if (fport == NULL) {
				fcip_num_instances--;
				fcip_num_attaching--;
				ASSERT(fcip_num_attaching >= 0);
				mutex_exit(&fcip_global_mutex);
				rval = FC_FAILURE;
				cmn_err(CE_WARN, "!fcip(%d): port attach "
				    "failed: alloc failed",
				    ddi_get_instance(port_info->port_dip));
				goto done;
			}
			fcip_port_head = fport;
		} else {
			/*
			 * traverse the port list and also check for
			 * duplicate port attaches - Nothing wrong in being
			 * paranoid Heh Heh.
			 */
			cur_fport = fcip_port_head;
			while (cur_fport != NULL) {
				if (cur_fport->fcipp_handle ==
				    port_info->port_handle) {
					fcip_num_instances--;
					fcip_num_attaching--;
					ASSERT(fcip_num_attaching >= 0);
					mutex_exit(&fcip_global_mutex);
					FCIP_DEBUG(FCIP_DEBUG_ATTACH, (CE_WARN,
					    "!fcip(%d): port already "
					    "attached!!", ddi_get_instance(
					    port_info->port_dip)));
					rval = FC_FAILURE;
					goto done;
				}
				cur_fport = cur_fport->fcipp_next;
			}
			fport = kmem_zalloc(sizeof (fcip_port_info_t),
						KM_NOSLEEP);
			if (fport == NULL) {
				rval = FC_FAILURE;
				fcip_num_instances--;
				fcip_num_attaching--;
				ASSERT(fcip_num_attaching >= 0);
				mutex_exit(&fcip_global_mutex);
				cmn_err(CE_WARN, "!fcip(%d): port attach "
				    "failed: alloc failed",
				    ddi_get_instance(port_info->port_dip));
				goto done;
			}
			fport->fcipp_next = fcip_port_head;
			fcip_port_head = fport;
		}

		mutex_exit(&fcip_global_mutex);

		/*
		 * now fill in the details about the port itself
		 */
		fport->fcipp_linkage = *port_info->port_linkage;
		fport->fcipp_handle = port_info->port_handle;
		fport->fcipp_dip = port_info->port_dip;
		fport->fcipp_topology = port_info->port_flags;
		fport->fcipp_pstate = port_info->port_state;
		fport->fcipp_naa = port_info->port_pwwn.w.naa_id;
		bcopy(&port_info->port_pwwn, &fport->fcipp_pwwn,
		    sizeof (la_wwn_t));
		bcopy(&port_info->port_nwwn, &fport->fcipp_nwwn,
		    sizeof (la_wwn_t));
		fport->fcipp_fca_pkt_size = port_info->port_fca_pkt_size;
		fport->fcipp_cmd_dma_attr = *port_info->port_cmd_dma_attr;
		fport->fcipp_resp_dma_attr = *port_info->port_resp_dma_attr;
		fport->fcipp_fca_acc_attr = *port_info->port_acc_attr;
		src_id.port_id = sid;
		src_id.priv_lilp_posit = 0;
		fport->fcipp_sid = src_id;

		/*
		 * allocate soft state for this instance
		 */
		instance = ddi_get_instance(fport->fcipp_dip);
		if (ddi_soft_state_zalloc(fcip_softp,
		    instance) != DDI_SUCCESS) {
			rval = FC_FAILURE;
			cmn_err(CE_WARN, "!fcip(%d): port attach failed: "
			    "soft state alloc failed", instance);
			goto failure;
		}

		fptr = ddi_get_soft_state(fcip_softp, instance);

		if (fptr == NULL) {
			rval = FC_FAILURE;
			cmn_err(CE_WARN, "!fcip(%d): port attach failed: "
			    "failure to get soft state", instance);
			goto failure;
		}

		/*
		 * initialize all mutexes and locks required for this module
		 */
		mutex_init(&fptr->fcip_mutex, NULL, MUTEX_DRIVER, NULL);
		mutex_init(&fptr->fcip_ub_mutex, NULL, MUTEX_DRIVER, NULL);
		mutex_init(&fptr->fcip_rt_mutex, NULL, MUTEX_DRIVER, NULL);
		mutex_init(&fptr->fcip_dest_mutex, NULL, MUTEX_DRIVER, NULL);
		mutex_init(&fptr->fcip_sendup_mutex, NULL, MUTEX_DRIVER, NULL);
		cv_init(&fptr->fcip_farp_cv, NULL, CV_DRIVER, NULL);
		cv_init(&fptr->fcip_sendup_cv, NULL, CV_DRIVER, NULL);
		cv_init(&fptr->fcip_ub_cv, NULL, CV_DRIVER, NULL);

		mutex_enter(&fptr->fcip_mutex);

		fptr->fcip_dip = fport->fcipp_dip;	/* parent's dip */
		fptr->fcip_instance = instance;
		fptr->fcip_ub_upstream = 0;

		if (FC_PORT_STATE_MASK(port_info->port_state) ==
		    FC_STATE_ONLINE) {
			fptr->fcip_port_state = FCIP_PORT_ONLINE;
			if (fptr->fcip_flags & FCIP_LINK_DOWN) {
				fptr->fcip_flags &= ~FCIP_LINK_DOWN;
			}
		} else {
			fptr->fcip_port_state = FCIP_PORT_OFFLINE;
		}

		fptr->fcip_flags |= FCIP_ATTACHING;
		fptr->fcip_port_info = fport;

		/*
		 * Extract our MAC addr from our port's WWN. The lower 48
		 * bits will be our MAC address
		 */
		wwn_to_ether(&fport->fcipp_nwwn, &fptr->fcip_macaddr);

		fport->fcipp_fcip = fptr;

		FCIP_DEBUG(FCIP_DEBUG_ATTACH,
		    (CE_NOTE, "fcipdest : 0x%lx, rtable : 0x%lx",
		    (long)(sizeof (fptr->fcip_dest)),
		    (long)(sizeof (fptr->fcip_rtable))));

		bzero(fptr->fcip_dest, sizeof (fptr->fcip_dest));
		bzero(fptr->fcip_rtable, sizeof (fptr->fcip_rtable));

		/*
		 * create a taskq to handle sundry jobs for the driver
		 * This way we can have jobs run in parallel
		 */
		fptr->fcip_tq = taskq_create("fcip_tasks",
		    FCIP_NUM_THREADS, MINCLSYSPRI, FCIP_MIN_TASKS,
		    FCIP_MAX_TASKS, TASKQ_PREPOPULATE);

		mutex_exit(&fptr->fcip_mutex);

		/*
		 * create a separate thread to handle all unsolicited
		 * callback handling. This is because unsolicited_callback
		 * can happen from an interrupt context and the upstream
		 * modules can put new messages right back in the same
		 * thread context. This usually works fine, but sometimes
		 * we may have to block to obtain the dest struct entries
		 * for some remote ports.
		 */
		mutex_enter(&fptr->fcip_sendup_mutex);
		if (thread_create(NULL, DEFAULTSTKSZ,
		    (void (*)())fcip_sendup_thr, (caddr_t)fptr, 0, &p0,
		    TS_RUN, minclsyspri) == NULL) {
			mutex_exit(&fptr->fcip_sendup_mutex);
			cmn_err(CE_WARN,
			    "!unable to create fcip sendup thread for "
			    " instance: 0x%x", instance);
			rval = FC_FAILURE;
			goto done;
		}
		fptr->fcip_sendup_thr_initted = 1;
		fptr->fcip_sendup_head = fptr->fcip_sendup_tail = NULL;
		mutex_exit(&fptr->fcip_sendup_mutex);


		/* Let the attach handler do the rest */
		if (fcip_port_attach_handler(fptr) != FC_SUCCESS) {
			/*
			 * We have already cleaned up so return
			 */
			rval = FC_FAILURE;
			cmn_err(CE_WARN, "!fcip(%d): port attach failed",
			    instance);
			goto done;
		}

		FCIP_DEBUG(FCIP_DEBUG_ATTACH, (CE_CONT,
		    "!fcip attach for port instance (0x%x) successful",
		    instance));

		rval = FC_SUCCESS;
		goto done;
	}
	case FC_CMD_POWER_UP:
	/* FALLTHROUGH */
	case FC_CMD_RESUME:
		mutex_enter(&fcip_global_mutex);
		fport = fcip_port_head;
		while (fport != NULL) {
			if (fport->fcipp_handle == port_info->port_handle) {
				break;
			}
			fport = fport->fcipp_next;
		}
		if (fport == NULL) {
			rval = FC_SUCCESS;
			mutex_exit(&fcip_global_mutex);
			goto done;
		}
		rval = fcip_handle_resume(fport, port_info, cmd);
		mutex_exit(&fcip_global_mutex);
		goto done;

	default:
		FCIP_TNF_PROBE_2((fcip_port_attach, "fcip io", /* CSTYLED */,
			tnf_string, msg, "unknown command type",
			tnf_uint, cmd, cmd));
		FCIP_DEBUG(FCIP_DEBUG_ATTACH, (CE_WARN,
		    "unknown cmd type 0x%x in port_attach", cmd));
		rval = FC_FAILURE;
		goto done;
	}

failure:
	if (fport) {
		mutex_enter(&fcip_global_mutex);
		fcip_num_attaching--;
		ASSERT(fcip_num_attaching >= 0);
		(void) fcip_softstate_free(fport);
		fcip_port_attach_pending = 0;
		mutex_exit(&fcip_global_mutex);
	}
	return (rval);

done:
	mutex_enter(&fcip_global_mutex);
	fcip_port_attach_pending = 0;
	mutex_exit(&fcip_global_mutex);
	return (rval);
}

/*
 * fcip_port_attach_handler : Completes the port attach operation after
 * the ulp_port_attach routine has completed its ground work. The job
 * of this function among other things is to obtain and handle topology
 * specifics, initialize a port, setup broadcast address entries in
 * the fcip tables etc. This routine cleans up behind itself on failures.
 * Returns FC_SUCCESS or FC_FAILURE.
 */
static int
fcip_port_attach_handler(struct fcip *fptr)
{
	fcip_port_info_t		*fport = fptr->fcip_port_info;
	int				rval = FC_FAILURE;

	ASSERT(fport != NULL);

	mutex_enter(&fcip_global_mutex);

	FCIP_DEBUG(FCIP_DEBUG_ATTACH, (CE_NOTE,
	    "fcip module dip: %p instance: %d",
	    (void *)fcip_module_dip, ddi_get_instance(fptr->fcip_dip)));

	if (fcip_module_dip == NULL) {
		clock_t		fcip_lbolt;

		fcip_lbolt = ddi_get_lbolt();
		/*
		 * we need to use the fcip devinfo for creating
		 * the clone device node, but the fcip attach
		 * (from its conf file entry claiming to be a
		 * child of pseudo) may not have happened yet.
		 * wait here for 10 seconds and fail port attach
		 * if the fcip devinfo is not attached yet
		 */
		fcip_lbolt += drv_usectohz(FCIP_INIT_DELAY);

		FCIP_DEBUG(FCIP_DEBUG_ATTACH,
		    (CE_WARN, "cv_timedwait lbolt %lx", fcip_lbolt));

		(void) cv_timedwait(&fcip_global_cv, &fcip_global_mutex,
		    fcip_lbolt);

		if (fcip_module_dip == NULL) {
			mutex_exit(&fcip_global_mutex);

			FCIP_DEBUG(FCIP_DEBUG_ATTACH, (CE_WARN,
				"fcip attach did not happen"));
			goto port_attach_cleanup;
		}
	}

	if ((!fcip_minor_node_created) &&
	    fcip_is_supported_fc_topology(fport->fcipp_topology)) {
		/*
		 * Checking for same topologies which are considered valid
		 * by fcip_handle_topology(). Dont create a minor node if
		 * nothing is hanging off the FC port.
		 */
		if (ddi_create_minor_node(fcip_module_dip, "fcip", S_IFCHR,
		    ddi_get_instance(fptr->fcip_dip), DDI_PSEUDO,
		    CLONE_DEV) == DDI_FAILURE) {
			mutex_exit(&fcip_global_mutex);
			FCIP_DEBUG(FCIP_DEBUG_ATTACH, (CE_WARN,
			    "failed to create minor node for fcip(%d)",
			    ddi_get_instance(fptr->fcip_dip)));
			goto port_attach_cleanup;
		}
		fcip_minor_node_created++;
	}
	mutex_exit(&fcip_global_mutex);

	/*
	 * initialize port for traffic
	 */
	if (fcip_init_port(fptr) != FC_SUCCESS) {
		/* fcip_init_port has already cleaned up its stuff */

		mutex_enter(&fcip_global_mutex);

		if ((fcip_num_instances == 1) &&
		    (fcip_minor_node_created == 1)) {
			/* Remove minor node iff this is the last instance */
			ddi_remove_minor_node(fcip_module_dip, NULL);
		}

		mutex_exit(&fcip_global_mutex);

		goto port_attach_cleanup;
	}

	mutex_enter(&fptr->fcip_mutex);
	fptr->fcip_flags &= ~FCIP_ATTACHING;
	fptr->fcip_flags |= FCIP_INITED;
	fptr->fcip_timeout_ticks = 0;

	/*
	 * start the timeout threads
	 */
	fptr->fcip_timeout_id = timeout(fcip_timeout, fptr,
	    drv_usectohz(1000000));

	mutex_exit(&fptr->fcip_mutex);
	mutex_enter(&fcip_global_mutex);
	fcip_num_attaching--;
	ASSERT(fcip_num_attaching >= 0);
	mutex_exit(&fcip_global_mutex);
	rval = FC_SUCCESS;
	return (rval);

port_attach_cleanup:
	mutex_enter(&fcip_global_mutex);
	(void) fcip_softstate_free(fport);
	fcip_num_attaching--;
	ASSERT(fcip_num_attaching >= 0);
	mutex_exit(&fcip_global_mutex);
	rval = FC_FAILURE;
	return (rval);
}


/*
 * Handler for DDI_RESUME operations. Port must be ready to restart IP
 * traffic on resume
 */
static int
fcip_handle_resume(fcip_port_info_t *fport, fc_ulp_port_info_t *port_info,
    fc_attach_cmd_t cmd)
{
	int 		rval = FC_SUCCESS;
	struct fcip	*fptr = fport->fcipp_fcip;
	struct fcipstr	*tslp;
	int		index;


	ASSERT(fptr != NULL);

	mutex_enter(&fptr->fcip_mutex);

	if (cmd == FC_CMD_POWER_UP) {
		fptr->fcip_flags &= ~(FCIP_POWER_DOWN);
		if (fptr->fcip_flags & FCIP_SUSPENDED) {
			mutex_exit(&fptr->fcip_mutex);
			return (FC_SUCCESS);
		}
	} else if (cmd == FC_CMD_RESUME) {
		fptr->fcip_flags &= ~(FCIP_SUSPENDED);
	} else {
		mutex_exit(&fptr->fcip_mutex);
		return (FC_FAILURE);
	}

	/*
	 * set the current port state and topology
	 */
	fport->fcipp_topology = port_info->port_flags;
	fport->fcipp_pstate = port_info->port_state;

	rw_enter(&fcipstruplock, RW_READER);
	for (tslp = fcipstrup; tslp; tslp = tslp->sl_nextp) {
		if (tslp->sl_fcip == fptr) {
			break;
		}
	}
	rw_exit(&fcipstruplock);

	/*
	 * No active streams on this port
	 */
	if (tslp == NULL) {
		rval = FC_SUCCESS;
		goto done;
	}

	mutex_enter(&fptr->fcip_rt_mutex);
	for (index = 0; index < FCIP_RT_HASH_ELEMS; index++) {
		struct fcip_routing_table 	*frp;

		frp = fptr->fcip_rtable[index];
		while (frp) {
			uint32_t		did;
			/*
			 * Mark the broadcast RTE available again. It
			 * was marked SUSPENDED during SUSPEND.
			 */
			did = fcip_get_broadcast_did(fptr);
			if (frp->fcipr_d_id.port_id == did) {
				frp->fcipr_state = 0;
				index = FCIP_RT_HASH_ELEMS;
				break;
			}
			frp = frp->fcipr_next;
		}
	}
	mutex_exit(&fptr->fcip_rt_mutex);

	/*
	 * fcip_handle_topology will update the port entries in the
	 * routing table.
	 * fcip_handle_topology also takes care of resetting the
	 * fcipr_state field in the routing table structure. The entries
	 * were set to RT_INVALID during suspend.
	 */
	fcip_handle_topology(fptr);

done:
	/*
	 * Restart the timeout thread
	 */
	fptr->fcip_timeout_id = timeout(fcip_timeout, fptr,
	    drv_usectohz(1000000));
	mutex_exit(&fptr->fcip_mutex);
	return (rval);
}


/*
 * Insert a destination port entry into the routing table for
 * this port
 */
static void
fcip_rt_update(struct fcip *fptr, fc_portmap_t *devlist, uint32_t listlen)
{
	struct fcip_routing_table	*frp;
	fcip_port_info_t		*fport = fptr->fcip_port_info;
	int				hash_bucket, i;
	fc_portmap_t			*pmap;
	char				wwn_buf[20];

	FCIP_TNF_PROBE_2((fcip_rt_update, "fcip io", /* CSTYLED */,
		tnf_string, msg, "enter",
		tnf_int, listlen, listlen));

	ASSERT(!mutex_owned(&fptr->fcip_mutex));
	mutex_enter(&fptr->fcip_rt_mutex);

	for (i = 0; i < listlen; i++) {
		pmap = &(devlist[i]);

		frp = fcip_lookup_rtable(fptr, &(pmap->map_pwwn),
		    FCIP_COMPARE_PWWN);
		/*
		 * If an entry for a port in the devlist exists in the
		 * in the per port routing table, make sure the data
		 * is current. We need to do this irrespective of the
		 * underlying port topology.
		 */
		switch (pmap->map_type) {
		/* FALLTHROUGH */
		case PORT_DEVICE_NOCHANGE:
		/* FALLTHROUGH */
		case PORT_DEVICE_USER_LOGIN:
		/* FALLTHROUGH */
		case PORT_DEVICE_CHANGED:
		/* FALLTHROUGH */
		case PORT_DEVICE_NEW:
			if (frp == NULL) {
				goto add_new_entry;
			} else if (frp) {
				goto update_entry;
			} else {
				continue;
			}

		case PORT_DEVICE_OLD:
		/* FALLTHROUGH */
		case PORT_DEVICE_USER_LOGOUT:
			/*
			 * Mark entry for removal from Routing Table if
			 * one exists. Let the timeout thread actually
			 * remove the entry after we've given up hopes
			 * of the port ever showing up.
			 */
			if (frp) {
				uint32_t		did;

				/*
				 * Mark the routing table as invalid to bail
				 * the packets early that are in transit
				 */
				did = fptr->fcip_broadcast_did;
				if (frp->fcipr_d_id.port_id != did) {
					frp->fcipr_pd = NULL;
					frp->fcipr_state = FCIP_RT_INVALID;
					frp->fcipr_invalid_timeout =
					    fptr->fcip_timeout_ticks +
					    FCIP_RTE_TIMEOUT;
				}
			}
			continue;

		default:
			FCIP_DEBUG(FCIP_DEBUG_INIT, (CE_WARN,
			    "unknown map flags in rt_update"));
			continue;
		}
add_new_entry:
		ASSERT(frp == NULL);
		hash_bucket = FCIP_RT_HASH(pmap->map_pwwn.raw_wwn);

		ASSERT(hash_bucket < FCIP_RT_HASH_ELEMS);

		FCIP_TNF_PROBE_2((fcip_rt_update, "cfip io", /* CSTYLED */,
			tnf_string, msg,
			"add new entry",
			tnf_int, hashbucket, hash_bucket));

		frp = (struct fcip_routing_table *)
		    kmem_zalloc(sizeof (struct fcip_routing_table), KM_SLEEP);
		/* insert at beginning of hash bucket */
		frp->fcipr_next = fptr->fcip_rtable[hash_bucket];
		fptr->fcip_rtable[hash_bucket] = frp;
		fc_wwn_to_str(&pmap->map_pwwn, wwn_buf);
		FCIP_DEBUG(FCIP_DEBUG_ATTACH, (CE_NOTE,
		    "added entry for pwwn %s and d_id 0x%x",
		    wwn_buf, pmap->map_did.port_id));
update_entry:
		bcopy((void *)&pmap->map_pwwn,
		    (void *)&frp->fcipr_pwwn, sizeof (la_wwn_t));
		bcopy((void *)&pmap->map_nwwn, (void *)&frp->fcipr_nwwn,
		    sizeof (la_wwn_t));
		frp->fcipr_d_id = pmap->map_did;
		frp->fcipr_state = pmap->map_state;
		frp->fcipr_pd = pmap->map_pd;

		/*
		 * If there is no pd for a destination port that is not
		 * a broadcast entry, the port is pretty much unusable - so
		 * mark the port for removal so we can try adding back the
		 * entry again.
		 */
		if ((frp->fcipr_pd == NULL) &&
		    (frp->fcipr_d_id.port_id != fptr->fcip_broadcast_did)) {
			frp->fcipr_state = PORT_DEVICE_INVALID;
			frp->fcipr_invalid_timeout = fptr->fcip_timeout_ticks +
			    (FCIP_RTE_TIMEOUT / 2);
		}
		frp->fcipr_fca_dev =
		    fc_ulp_get_fca_device(fport->fcipp_handle, pmap->map_did);

		/*
		 * login to the remote port. Don't worry about
		 * plogi failures for now
		 */
		if (pmap->map_pd != NULL) {
			(void) fcip_do_plogi(fptr, frp);
		} else if (FC_TOP_EXTERNAL(fport->fcipp_topology)) {
			fc_wwn_to_str(&frp->fcipr_pwwn, wwn_buf);
			FCIP_DEBUG(FCIP_DEBUG_MISC, (CE_NOTE,
			    "logging into pwwn %s, d_id 0x%x",
			    wwn_buf, frp->fcipr_d_id.port_id));
			(void) fcip_do_plogi(fptr, frp);
		}

		FCIP_TNF_BYTE_ARRAY(fcip_rt_update, "fcip io", "detail",
			"new wwn in rt", pwwn,
			&frp->fcipr_pwwn, sizeof (la_wwn_t));
	}
	mutex_exit(&fptr->fcip_rt_mutex);
}


/*
 * return a matching routing table entry for a given fcip instance
 */
struct fcip_routing_table *
fcip_lookup_rtable(struct fcip *fptr, la_wwn_t *wwn, int matchflag)
{
	struct fcip_routing_table	*frp = NULL;
	int				hash_bucket;


	FCIP_TNF_PROBE_1((fcip_lookup_rtable, "fcip io", /* CSTYLED */,
		tnf_string, msg, "enter"));
	FCIP_TNF_BYTE_ARRAY(fcip_lookup_rtable, "fcip io", "detail",
		"rtable lookup for", wwn,
		&wwn->raw_wwn, sizeof (la_wwn_t));
	FCIP_TNF_PROBE_2((fcip_lookup_rtable, "fcip io", /* CSTYLED */,
		tnf_string, msg, "match by",
		tnf_int, matchflag, matchflag));

	ASSERT(mutex_owned(&fptr->fcip_rt_mutex));

	hash_bucket = FCIP_RT_HASH(wwn->raw_wwn);
	frp = fptr->fcip_rtable[hash_bucket];
	while (frp != NULL) {

		FCIP_TNF_BYTE_ARRAY(fcip_lookup_rtable, "fcip io", "detail",
			"rtable entry", nwwn,
			&(frp->fcipr_nwwn.raw_wwn), sizeof (la_wwn_t));

		if (fcip_wwn_compare(&frp->fcipr_pwwn, wwn, matchflag) == 0) {
			break;
		}

		frp = frp->fcipr_next;
	}
	FCIP_TNF_PROBE_2((fcip_lookup_rtable, "fcip io", /* CSTYLED */,
		tnf_string, msg, "lookup result",
		tnf_opaque, frp, frp));
	return (frp);
}

/*
 * Attach of fcip under pseudo. The actual setup of the interface
 * actually happens in fcip_port_attach on a callback from the
 * transport. The port_attach callback however can proceed only
 * after the devinfo for fcip has been created under pseudo
 */
static int
fcip_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch ((int)cmd) {

	case DDI_ATTACH: {
		ASSERT(fcip_module_dip == NULL);
		fcip_module_dip = dip;

		/*
		 * this call originates as a result of fcip's conf
		 * file entry and will result in a fcip instance being
		 * a child of pseudo. We should ensure here that the port
		 * driver (fp) has been loaded and initted since we would
		 * never get a port attach callback without fp being loaded.
		 * If we are unable to succesfully load and initalize fp -
		 * just fail this attach.
		 */
		mutex_enter(&fcip_global_mutex);

		FCIP_DEBUG(FCIP_DEBUG_ATTACH,
		    (CE_WARN, "global cv - signaling"));

		cv_signal(&fcip_global_cv);

		FCIP_DEBUG(FCIP_DEBUG_ATTACH,
		    (CE_WARN, "global cv - signaled"));
		mutex_exit(&fcip_global_mutex);
		return (DDI_SUCCESS);
	}
	case DDI_RESUME:
		/*
		 * Resume appears trickier
		 */
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
}


/*
 * The detach entry point to permit unloading fcip. We make sure
 * there are no active streams before we proceed with the detach
 */
/* ARGSUSED */
static int
fcip_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	struct fcip		*fptr;
	fcip_port_info_t	*fport;
	int			detached;

	switch (cmd) {
	case DDI_DETACH: {
		/*
		 * If we got here, any active streams should have been
		 * unplumbed but check anyway
		 */
		mutex_enter(&fcip_global_mutex);
		if (fcipstrup != NULL) {
			mutex_exit(&fcip_global_mutex);
			return (DDI_FAILURE);
		}

		if (fcip_port_head != NULL) {
			/*
			 * Check to see if we have unattached/unbound
			 * ports. If all the ports are unattached/unbound go
			 * ahead and unregister with the transport
			 */
			fport = fcip_port_head;
			while (fport != NULL) {
				fptr = fport->fcipp_fcip;
				if (fptr == NULL) {
					continue;
				}
				mutex_enter(&fptr->fcip_mutex);
				fptr->fcip_flags |= FCIP_DETACHING;
				if (fptr->fcip_ipq ||
				    fptr->fcip_flags & (FCIP_IN_TIMEOUT |
				    FCIP_IN_CALLBACK | FCIP_ATTACHING |
				    FCIP_SUSPENDED | FCIP_POWER_DOWN |
				    FCIP_REG_INPROGRESS)) {
					FCIP_TNF_PROBE_1((fcip_detach,
					    "fcip io", /* CSTYLED */,
					    tnf_string, msg,
					    "fcip instance busy"));

					mutex_exit(&fptr->fcip_mutex);
					FCIP_DEBUG(FCIP_DEBUG_DETACH, (CE_WARN,
					    "fcip instance busy"));
					break;
				}
				/*
				 * Check for any outstanding pkts. If yes
				 * fail the detach
				 */
				mutex_enter(&fptr->fcip_dest_mutex);
				if (fcip_port_get_num_pkts(fptr) > 0) {
					mutex_exit(&fptr->fcip_dest_mutex);
					mutex_exit(&fptr->fcip_mutex);
					FCIP_DEBUG(FCIP_DEBUG_DETACH, (CE_WARN,
					    "fcip instance busy - pkts "
					    "pending"));
					break;
				}
				mutex_exit(&fptr->fcip_dest_mutex);

				mutex_enter(&fptr->fcip_rt_mutex);
				if (fcip_plogi_in_progress(fptr)) {
					mutex_exit(&fptr->fcip_rt_mutex);
					mutex_exit(&fptr->fcip_mutex);
					FCIP_DEBUG(FCIP_DEBUG_DETACH, (CE_WARN,
					    "fcip instance busy - plogi in "
					    "progress"));
					break;
				}
				mutex_exit(&fptr->fcip_rt_mutex);

				mutex_exit(&fptr->fcip_mutex);
				fport = fport->fcipp_next;
			}
			/*
			 * if fport is non NULL - we have active ports
			 */
			if (fport != NULL) {
				/*
				 * Remove the DETACHING flags on the ports
				 */
				fport = fcip_port_head;
				while (fport != NULL) {
					fptr = fport->fcipp_fcip;
					mutex_enter(&fptr->fcip_mutex);
					fptr->fcip_flags &= ~(FCIP_DETACHING);
					mutex_exit(&fptr->fcip_mutex);
					fport = fport->fcipp_next;
				}
				mutex_exit(&fcip_global_mutex);
				return (DDI_FAILURE);
			}
		}

		/*
		 * free up all softstate structures
		 */
		fport = fcip_port_head;
		while (fport != NULL) {
			detached = 1;

			fptr = fport->fcipp_fcip;
			if (fptr) {
				mutex_enter(&fptr->fcip_mutex);
				/*
				 * Check to see if somebody beat us to the
				 * punch
				 */
				detached = fptr->fcip_flags & FCIP_DETACHED;
				fptr->fcip_flags &= ~(FCIP_DETACHING);
				fptr->fcip_flags |= FCIP_DETACHED;
				mutex_exit(&fptr->fcip_mutex);
			}

			if (!detached) {
				fport = fcip_softstate_free(fport);
			} else {
				/*
				 * If the port was marked as detached
				 * but it was still in the list, that
				 * means another thread has marked it
				 * but we got in while it released the
				 * fcip_global_mutex in softstate_free.
				 * Given that, we're still safe to use
				 * fport->fcipp_next to find out what
				 * the next port on the list is.
				 */
				fport = fport->fcipp_next;
			}

			FCIP_DEBUG(FCIP_DEBUG_DETACH,
			    (CE_NOTE, "detaching port"));

			FCIP_TNF_PROBE_1((fcip_detach,
				"fcip io", /* CSTYLED */, tnf_string,
				msg, "detaching port"));
		}

		/*
		 * If we haven't removed all the port structures, we
		 * aren't yet ready to be detached.
		 */
		if (fcip_port_head != NULL) {
			mutex_exit(&fcip_global_mutex);
			return (DDI_FAILURE);
		}

		fcip_num_instances = 0;
		mutex_exit(&fcip_global_mutex);
		fcip_module_dip = NULL;
		return (DDI_SUCCESS);
	}
	case DDI_SUSPEND:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
}

/*
 * The port_detach callback is called from the transport when a
 * FC port is being removed from the transport's control. This routine
 * provides fcip with an opportunity to cleanup all activities and
 * structures on the port marked for removal.
 */
/* ARGSUSED */
static int
fcip_port_detach(opaque_t ulp_handle, fc_ulp_port_info_t *port_info,
    fc_detach_cmd_t cmd)
{
	int 			rval = FC_FAILURE;
	fcip_port_info_t	*fport;
	struct fcip		*fptr;
	struct fcipstr		*strp;

	switch (cmd) {
	case FC_CMD_DETACH: {
		mutex_enter(&fcip_global_mutex);

		if (fcip_port_head == NULL) {
			/*
			 * we are all done but our fini has not been
			 * called yet!! Let's hope we have no active
			 * fcip instances here. - strange secnario but
			 * no harm in having this return a success.
			 */
			fcip_check_remove_minor_node();

			mutex_exit(&fcip_global_mutex);
			return (FC_SUCCESS);
		} else {
			/*
			 * traverse the port list
			 */
			fport = fcip_port_head;
			while (fport != NULL) {
				if (fport->fcipp_handle ==
				    port_info->port_handle) {
					fptr = fport->fcipp_fcip;

					/*
					 * Fail the port detach if there is
					 * still an attached, bound stream on
					 * this interface.
					 */

					rw_enter(&fcipstruplock, RW_READER);

					for (strp = fcipstrup; strp != NULL;
					    strp = strp->sl_nextp) {
						if (strp->sl_fcip == fptr) {
							rw_exit(&fcipstruplock);
							mutex_exit(
							    &fcip_global_mutex);
							return (FC_FAILURE);
						}
					}

					rw_exit(&fcipstruplock);

					/*
					 * fail port detach if we are in
					 * the middle of a deferred port attach
					 * or if the port has outstanding pkts
					 */
					if (fptr != NULL) {
						mutex_enter(&fptr->fcip_mutex);
						if (fcip_check_port_busy
						    (fptr) ||
						    (fptr->fcip_flags &
						    FCIP_DETACHED)) {
							mutex_exit(
							    &fptr->fcip_mutex);
							mutex_exit(
							    &fcip_global_mutex);
							return (FC_FAILURE);
						}

						fptr->fcip_flags |=
						    FCIP_DETACHED;
						mutex_exit(&fptr->fcip_mutex);
					}
					(void) fcip_softstate_free(fport);

					fcip_check_remove_minor_node();
					mutex_exit(&fcip_global_mutex);
					return (FC_SUCCESS);
				}
				fport = fport->fcipp_next;
			}
			ASSERT(fport == NULL);
		}
		mutex_exit(&fcip_global_mutex);
		break;
	}
	case FC_CMD_POWER_DOWN:
	/* FALLTHROUGH */
	case FC_CMD_SUSPEND:
		mutex_enter(&fcip_global_mutex);
		fport = fcip_port_head;
		while (fport != NULL) {
			if (fport->fcipp_handle == port_info->port_handle) {
				break;
			}
			fport = fport->fcipp_next;
		}
		if (fport == NULL) {
			mutex_exit(&fcip_global_mutex);
			break;
		}
		rval = fcip_handle_suspend(fport, cmd);
		mutex_exit(&fcip_global_mutex);
		break;
	default:
		FCIP_DEBUG(FCIP_DEBUG_DETACH,
		    (CE_WARN, "unknown port detach command!!"));
		break;
	}
	return (rval);
}


/*
 * Returns 0 if the port is not busy, else returns non zero.
 */
static int
fcip_check_port_busy(struct fcip *fptr)
{
	int rval = 0, num_pkts = 0;

	ASSERT(fptr != NULL);
	ASSERT(MUTEX_HELD(&fptr->fcip_mutex));

	mutex_enter(&fptr->fcip_dest_mutex);

	if (fptr->fcip_flags & FCIP_PORT_BUSY ||
	    ((num_pkts = fcip_port_get_num_pkts(fptr)) > 0) ||
	    fptr->fcip_num_ipkts_pending) {
		rval = 1;
		FCIP_DEBUG(FCIP_DEBUG_DETACH,
		    (CE_NOTE, "!fcip_check_port_busy: port is busy "
		    "fcip_flags: 0x%x, num_pkts: 0x%x, ipkts_pending: 0x%lx!",
		    fptr->fcip_flags, num_pkts, fptr->fcip_num_ipkts_pending));
	}

	mutex_exit(&fptr->fcip_dest_mutex);
	return (rval);
}

/*
 * Helper routine to remove fcip's minor node
 * There is one minor node per system and it should be removed if there are no
 * other fcip instances (which has a 1:1 mapping for fp instances) present
 */
static void
fcip_check_remove_minor_node(void)
{
	ASSERT(MUTEX_HELD(&fcip_global_mutex));

	/*
	 * If there are no more fcip (fp) instances, remove the
	 * minor node for fcip.
	 * Reset fcip_minor_node_created to invalidate it.
	 */
	if (fcip_num_instances == 0 && (fcip_module_dip != NULL)) {
		ddi_remove_minor_node(fcip_module_dip, NULL);
		fcip_minor_node_created = 0;
	}
}

/*
 * This routine permits the suspend operation during a CPR/System
 * power management operation. The routine basically quiesces I/Os
 * on all active interfaces
 */
static int
fcip_handle_suspend(fcip_port_info_t *fport, fc_detach_cmd_t cmd)
{
	struct fcip	*fptr = fport->fcipp_fcip;
	timeout_id_t	tid;
	int 		index;
	int		tryagain = 0;
	int		count;
	struct fcipstr	*tslp;


	ASSERT(fptr != NULL);
	mutex_enter(&fptr->fcip_mutex);

	/*
	 * Fail if we are in the middle of a callback. Don't use delay during
	 * suspend since clock intrs are not available so busy wait
	 */
	count = 0;
	while (count++ < 15 &&
	    ((fptr->fcip_flags & FCIP_IN_CALLBACK) ||
	    (fptr->fcip_flags & FCIP_IN_TIMEOUT))) {
		mutex_exit(&fptr->fcip_mutex);
		drv_usecwait(1000000);
		mutex_enter(&fptr->fcip_mutex);
	}

	if (fptr->fcip_flags & FCIP_IN_CALLBACK ||
	    fptr->fcip_flags & FCIP_IN_TIMEOUT) {
		mutex_exit(&fptr->fcip_mutex);
		return (FC_FAILURE);
	}

	if (cmd == FC_CMD_POWER_DOWN) {
		if (fptr->fcip_flags & FCIP_SUSPENDED) {
			fptr->fcip_flags |= FCIP_POWER_DOWN;
			mutex_exit(&fptr->fcip_mutex);
			goto success;
		} else {
			fptr->fcip_flags |= FCIP_POWER_DOWN;
		}
	} else if (cmd == FC_CMD_SUSPEND) {
		fptr->fcip_flags |= FCIP_SUSPENDED;
	} else {
		mutex_exit(&fptr->fcip_mutex);
		return (FC_FAILURE);
	}

	mutex_exit(&fptr->fcip_mutex);
	/*
	 * If no streams are plumbed - its the easiest case - Just
	 * bail out without having to do much
	 */

	rw_enter(&fcipstruplock, RW_READER);
	for (tslp = fcipstrup; tslp; tslp = tslp->sl_nextp) {
		if (tslp->sl_fcip == fptr) {
			break;
		}
	}
	rw_exit(&fcipstruplock);

	/*
	 * No active streams on this port
	 */
	if (tslp == NULL) {
		goto success;
	}

	/*
	 * Walk through each Routing table structure and check if
	 * the destination table has any outstanding commands. If yes
	 * wait for the commands to drain. Since we go through each
	 * routing table entry in succession, it may be wise to wait
	 * only a few seconds for each entry.
	 */
	mutex_enter(&fptr->fcip_rt_mutex);
	while (!tryagain) {

		tryagain = 0;
		for (index = 0; index < FCIP_RT_HASH_ELEMS; index++) {
			struct fcip_routing_table 	*frp;
			struct fcip_dest 		*fdestp;
			la_wwn_t			*pwwn;
			int				hash_bucket;

			frp = fptr->fcip_rtable[index];
			while (frp) {
				/*
				 * Mark the routing table as SUSPENDED. Even
				 * mark the broadcast entry SUSPENDED to
				 * prevent any ARP or other broadcasts. We
				 * can reset the state of the broadcast
				 * RTE when we resume.
				 */
				frp->fcipr_state = FCIP_RT_SUSPENDED;
				pwwn = &frp->fcipr_pwwn;

				/*
				 * Get hold of destination pointer
				 */
				mutex_enter(&fptr->fcip_dest_mutex);

				hash_bucket = FCIP_DEST_HASH(pwwn->raw_wwn);
				ASSERT(hash_bucket < FCIP_DEST_HASH_ELEMS);

				fdestp = fptr->fcip_dest[hash_bucket];
				while (fdestp != NULL) {
					mutex_enter(&fdestp->fcipd_mutex);
					if (fdestp->fcipd_rtable) {
						if (fcip_wwn_compare(pwwn,
						    &fdestp->fcipd_pwwn,
						    FCIP_COMPARE_PWWN) == 0) {
							mutex_exit(
							&fdestp->fcipd_mutex);
							break;
						}
					}
					mutex_exit(&fdestp->fcipd_mutex);
					fdestp = fdestp->fcipd_next;
				}

				mutex_exit(&fptr->fcip_dest_mutex);
				if (fdestp == NULL) {
					frp = frp->fcipr_next;
					continue;
				}

				/*
				 * Wait for fcip_wait_cmds seconds for
				 * the commands to drain.
				 */
				count = 0;
				mutex_enter(&fdestp->fcipd_mutex);
				while (fdestp->fcipd_ncmds &&
				    count < fcip_wait_cmds) {
					mutex_exit(&fdestp->fcipd_mutex);
					mutex_exit(&fptr->fcip_rt_mutex);
					drv_usecwait(1000000);
					mutex_enter(&fptr->fcip_rt_mutex);
					mutex_enter(&fdestp->fcipd_mutex);
					count++;
				}
				/*
				 * Check if we were able to drain all cmds
				 * successfully. Else continue with other
				 * ports and try during the second pass
				 */
				if (fdestp->fcipd_ncmds) {
					tryagain++;
				}
				mutex_exit(&fdestp->fcipd_mutex);

				frp = frp->fcipr_next;
			}
		}
		if (tryagain == 0) {
			break;
		}
	}
	mutex_exit(&fptr->fcip_rt_mutex);

	if (tryagain) {
		mutex_enter(&fptr->fcip_mutex);
		fptr->fcip_flags &= ~(FCIP_SUSPENDED | FCIP_POWER_DOWN);
		mutex_exit(&fptr->fcip_mutex);
		return (FC_FAILURE);
	}

success:
	mutex_enter(&fptr->fcip_mutex);
	tid = fptr->fcip_timeout_id;
	fptr->fcip_timeout_id = NULL;
	mutex_exit(&fptr->fcip_mutex);

	(void) untimeout(tid);

	return (FC_SUCCESS);
}

/*
 * the getinfo(9E) entry point
 */
/* ARGSUSED */
static int
fcip_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	int rval = DDI_FAILURE;

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = fcip_module_dip;
		if (*result)
			rval = DDI_SUCCESS;
		break;

	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;
		rval = DDI_SUCCESS;
		break;
	default:
		break;
	}

	return (rval);
}

/*
 * called from fcip_attach to initialize kstats for the link
 */
/* ARGSUSED */
static void
fcip_kstat_init(struct fcip *fptr)
{
	int instance;
	char buf[16];
	struct fcipstat	*fcipstatp;

	ASSERT(mutex_owned(&fptr->fcip_mutex));

	instance = ddi_get_instance(fptr->fcip_dip);
	(void) sprintf(buf, "fcip%d", instance);

#ifdef	kstat
	fptr->fcip_kstatp = kstat_create("fcip", instance, buf, "net",
	    KSTAT_TYPE_NAMED,
	    (sizeof (struct fcipstat)/ sizeof (kstat_named_t)),
	    KSTAT_FLAG_PERSISTENT);
#else
	fptr->fcip_kstatp = kstat_create("fcip", instance, buf, "net",
	    KSTAT_TYPE_NAMED,
	    (sizeof (struct fcipstat)/ sizeof (kstat_named_t)), 0);
#endif
	if (fptr->fcip_kstatp == NULL) {
		FCIP_DEBUG(FCIP_DEBUG_INIT, (CE_WARN, "kstat created failed"));
		return;
	}

	fcipstatp = (struct  fcipstat *)fptr->fcip_kstatp->ks_data;
	kstat_named_init(&fcipstatp->fcips_ipackets,	"ipackets",
		KSTAT_DATA_ULONG);
	kstat_named_init(&fcipstatp->fcips_ierrors,	"ierrors",
		KSTAT_DATA_ULONG);
	kstat_named_init(&fcipstatp->fcips_opackets,	"opackets",
		KSTAT_DATA_ULONG);
	kstat_named_init(&fcipstatp->fcips_oerrors,	"oerrors",
		KSTAT_DATA_ULONG);
	kstat_named_init(&fcipstatp->fcips_collisions,	"collisions",
		KSTAT_DATA_ULONG);
	kstat_named_init(&fcipstatp->fcips_nocanput,	"nocanput",
		KSTAT_DATA_ULONG);
	kstat_named_init(&fcipstatp->fcips_allocbfail,	"allocbfail",
		KSTAT_DATA_ULONG);

	kstat_named_init(&fcipstatp->fcips_defer, "defer",
		KSTAT_DATA_ULONG);
	kstat_named_init(&fcipstatp->fcips_fram, "fram",
		KSTAT_DATA_ULONG);
	kstat_named_init(&fcipstatp->fcips_crc, "crc",
		KSTAT_DATA_ULONG);
	kstat_named_init(&fcipstatp->fcips_oflo, "oflo",
		KSTAT_DATA_ULONG);
	kstat_named_init(&fcipstatp->fcips_uflo, "uflo",
		KSTAT_DATA_ULONG);
	kstat_named_init(&fcipstatp->fcips_missed, "missed",
		KSTAT_DATA_ULONG);
	kstat_named_init(&fcipstatp->fcips_tlcol, "tlcol",
		KSTAT_DATA_ULONG);
	kstat_named_init(&fcipstatp->fcips_trtry, "trtry",
		KSTAT_DATA_ULONG);
	kstat_named_init(&fcipstatp->fcips_tnocar, "tnocar",
		KSTAT_DATA_ULONG);
	kstat_named_init(&fcipstatp->fcips_inits, "inits",
		KSTAT_DATA_ULONG);
	kstat_named_init(&fcipstatp->fcips_notbufs, "notbufs",
		KSTAT_DATA_ULONG);
	kstat_named_init(&fcipstatp->fcips_norbufs, "norbufs",
		KSTAT_DATA_ULONG);
	kstat_named_init(&fcipstatp->fcips_allocbfail, "allocbfail",
		KSTAT_DATA_ULONG);

	/*
	 * required by kstat for MIB II objects(RFC 1213)
	 */
	kstat_named_init(&fcipstatp->fcips_rcvbytes, "fcips_rcvbytes",
		KSTAT_DATA_ULONG);	/* # octets received */
					/* MIB - ifInOctets */
	kstat_named_init(&fcipstatp->fcips_xmtbytes, "fcips_xmtbytes",
		KSTAT_DATA_ULONG);	/* # octets xmitted */
					/* MIB - ifOutOctets */
	kstat_named_init(&fcipstatp->fcips_multircv,	"fcips_multircv",
		KSTAT_DATA_ULONG);	/* # multicast packets */
					/* delivered to upper layer */
					/* MIB - ifInNUcastPkts */
	kstat_named_init(&fcipstatp->fcips_multixmt,	"fcips_multixmt",
		KSTAT_DATA_ULONG);	/* # multicast packets */
					/* requested to be sent */
					/* MIB - ifOutNUcastPkts */
	kstat_named_init(&fcipstatp->fcips_brdcstrcv, "fcips_brdcstrcv",
		KSTAT_DATA_ULONG); /* # broadcast packets */
					/* delivered to upper layer */
					/* MIB - ifInNUcastPkts */
	kstat_named_init(&fcipstatp->fcips_brdcstxmt, "fcips_brdcstxmt",
		KSTAT_DATA_ULONG);	/* # broadcast packets */
					/* requested to be sent */
					/* MIB - ifOutNUcastPkts */
	kstat_named_init(&fcipstatp->fcips_norcvbuf,	"fcips_norcvbuf",
		KSTAT_DATA_ULONG);	/* # rcv packets discarded */
					/* MIB - ifInDiscards */
	kstat_named_init(&fcipstatp->fcips_noxmtbuf,	"fcips_noxmtbuf",
		KSTAT_DATA_ULONG);	/* # xmt packets discarded */

	fptr->fcip_kstatp->ks_update = fcip_stat_update;
	fptr->fcip_kstatp->ks_private = (void *) fptr;
	kstat_install(fptr->fcip_kstatp);
}

/*
 * Update the defined kstats for netstat et al to use
 */
/* ARGSUSED */
static int
fcip_stat_update(kstat_t *fcip_statp, int val)
{
	struct fcipstat	*fcipstatp;
	struct fcip	*fptr;

	fptr = (struct fcip *)fcip_statp->ks_private;
	fcipstatp = (struct fcipstat *)fcip_statp->ks_data;

	if (val == KSTAT_WRITE) {
		fptr->fcip_ipackets	= fcipstatp->fcips_ipackets.value.ul;
		fptr->fcip_ierrors	= fcipstatp->fcips_ierrors.value.ul;
		fptr->fcip_opackets	= fcipstatp->fcips_opackets.value.ul;
		fptr->fcip_oerrors	= fcipstatp->fcips_oerrors.value.ul;
		fptr->fcip_collisions	= fcipstatp->fcips_collisions.value.ul;
		fptr->fcip_defer	= fcipstatp->fcips_defer.value.ul;
		fptr->fcip_fram	= fcipstatp->fcips_fram.value.ul;
		fptr->fcip_crc	= fcipstatp->fcips_crc.value.ul;
		fptr->fcip_oflo	= fcipstatp->fcips_oflo.value.ul;
		fptr->fcip_uflo	= fcipstatp->fcips_uflo.value.ul;
		fptr->fcip_missed	= fcipstatp->fcips_missed.value.ul;
		fptr->fcip_tlcol	= fcipstatp->fcips_tlcol.value.ul;
		fptr->fcip_trtry	= fcipstatp->fcips_trtry.value.ul;
		fptr->fcip_tnocar	= fcipstatp->fcips_tnocar.value.ul;
		fptr->fcip_inits	= fcipstatp->fcips_inits.value.ul;
		fptr->fcip_notbufs	= fcipstatp->fcips_notbufs.value.ul;
		fptr->fcip_norbufs	= fcipstatp->fcips_norbufs.value.ul;
		fptr->fcip_nocanput	= fcipstatp->fcips_nocanput.value.ul;
		fptr->fcip_allocbfail	= fcipstatp->fcips_allocbfail.value.ul;
		fptr->fcip_rcvbytes	= fcipstatp->fcips_rcvbytes.value.ul;
		fptr->fcip_xmtbytes	= fcipstatp->fcips_xmtbytes.value.ul;
		fptr->fcip_multircv	= fcipstatp->fcips_multircv.value.ul;
		fptr->fcip_multixmt	= fcipstatp->fcips_multixmt.value.ul;
		fptr->fcip_brdcstrcv	= fcipstatp->fcips_brdcstrcv.value.ul;
		fptr->fcip_norcvbuf	= fcipstatp->fcips_norcvbuf.value.ul;
		fptr->fcip_noxmtbuf	= fcipstatp->fcips_noxmtbuf.value.ul;
		fptr->fcip_allocbfail	= fcipstatp->fcips_allocbfail.value.ul;
		fptr->fcip_allocbfail	= fcipstatp->fcips_allocbfail.value.ul;
		fptr->fcip_allocbfail	= fcipstatp->fcips_allocbfail.value.ul;
		fptr->fcip_allocbfail	= fcipstatp->fcips_allocbfail.value.ul;
		fptr->fcip_allocbfail	= fcipstatp->fcips_allocbfail.value.ul;
		fptr->fcip_allocbfail	= fcipstatp->fcips_allocbfail.value.ul;
		fptr->fcip_allocbfail	= fcipstatp->fcips_allocbfail.value.ul;
		fptr->fcip_allocbfail	= fcipstatp->fcips_allocbfail.value.ul;

	} else {
		fcipstatp->fcips_ipackets.value.ul	= fptr->fcip_ipackets;
		fcipstatp->fcips_ierrors.value.ul	= fptr->fcip_ierrors;
		fcipstatp->fcips_opackets.value.ul	= fptr->fcip_opackets;
		fcipstatp->fcips_oerrors.value.ul	= fptr->fcip_oerrors;
		fcipstatp->fcips_collisions.value.ul	= fptr->fcip_collisions;
		fcipstatp->fcips_nocanput.value.ul	= fptr->fcip_nocanput;
		fcipstatp->fcips_allocbfail.value.ul	= fptr->fcip_allocbfail;
		fcipstatp->fcips_defer.value.ul	= fptr->fcip_defer;
		fcipstatp->fcips_fram.value.ul	= fptr->fcip_fram;
		fcipstatp->fcips_crc.value.ul	= fptr->fcip_crc;
		fcipstatp->fcips_oflo.value.ul	= fptr->fcip_oflo;
		fcipstatp->fcips_uflo.value.ul	= fptr->fcip_uflo;
		fcipstatp->fcips_missed.value.ul	= fptr->fcip_missed;
		fcipstatp->fcips_tlcol.value.ul	= fptr->fcip_tlcol;
		fcipstatp->fcips_trtry.value.ul	= fptr->fcip_trtry;
		fcipstatp->fcips_tnocar.value.ul	= fptr->fcip_tnocar;
		fcipstatp->fcips_inits.value.ul	= fptr->fcip_inits;
		fcipstatp->fcips_norbufs.value.ul	= fptr->fcip_norbufs;
		fcipstatp->fcips_notbufs.value.ul	= fptr->fcip_notbufs;
		fcipstatp->fcips_rcvbytes.value.ul	= fptr->fcip_rcvbytes;
		fcipstatp->fcips_xmtbytes.value.ul	= fptr->fcip_xmtbytes;
		fcipstatp->fcips_multircv.value.ul	= fptr->fcip_multircv;
		fcipstatp->fcips_multixmt.value.ul	= fptr->fcip_multixmt;
		fcipstatp->fcips_brdcstrcv.value.ul	= fptr->fcip_brdcstrcv;
		fcipstatp->fcips_brdcstxmt.value.ul	= fptr->fcip_brdcstxmt;
		fcipstatp->fcips_norcvbuf.value.ul	= fptr->fcip_norcvbuf;
		fcipstatp->fcips_noxmtbuf.value.ul	= fptr->fcip_noxmtbuf;

	}
	return (0);
}


/*
 * fcip_statec_cb: handles all required state change callback notifications
 * it receives from the transport
 */
/* ARGSUSED */
static void
fcip_statec_cb(opaque_t ulp_handle, opaque_t phandle,
    uint32_t port_state, uint32_t port_top, fc_portmap_t changelist[],
    uint32_t listlen, uint32_t sid)
{
	fcip_port_info_t	*fport;
	struct fcip 		*fptr;
	struct fcipstr		*slp;
	queue_t			*wrq;
	int			instance;
	int 			index;
	struct fcip_routing_table 	*frtp;

	fport = fcip_get_port(phandle);

	if (fport == NULL) {
		return;
	}

	fptr = fport->fcipp_fcip;
	ASSERT(fptr != NULL);

	if (fptr == NULL) {
		return;
	}

	instance = ddi_get_instance(fport->fcipp_dip);

	FCIP_TNF_PROBE_4((fcip_statec_cb, "fcip io", /* CSTYLED */,
		tnf_string, msg, "state change callback",
		tnf_uint, instance, instance,
		tnf_uint, S_ID, sid,
		tnf_int, count, listlen));
	FCIP_DEBUG(FCIP_DEBUG_ELS,
	    (CE_NOTE, "fcip%d, state change callback: state:0x%x, "
	    "S_ID:0x%x, count:0x%x", instance, port_state, sid, listlen));

	mutex_enter(&fptr->fcip_mutex);

	if ((fptr->fcip_flags & (FCIP_DETACHING | FCIP_DETACHED)) ||
	    (fptr->fcip_flags & (FCIP_SUSPENDED | FCIP_POWER_DOWN))) {
		mutex_exit(&fptr->fcip_mutex);
		return;
	}

	/*
	 * set fcip flags to indicate we are in the middle of a
	 * state change callback so we can wait till the statechange
	 * is handled before succeeding/failing the SUSPEND/POWER DOWN.
	 */
	fptr->fcip_flags |= FCIP_IN_SC_CB;

	fport->fcipp_pstate = port_state;

	/*
	 * Check if topology changed. If Yes - Modify the broadcast
	 * RTE entries to understand the new broadcast D_IDs
	 */
	if (fport->fcipp_topology != port_top &&
	    (port_top != FC_TOP_UNKNOWN)) {
		/* REMOVE later */
		FCIP_DEBUG(FCIP_DEBUG_ELS, (CE_NOTE,
		    "topology changed: Old topology: 0x%x New topology 0x%x",
		    fport->fcipp_topology, port_top));
		/*
		 * If topology changed - attempt a rediscovery of
		 * devices. Helps specially in Fabric/Public loops
		 * and if on_demand_node_creation is disabled
		 */
		fport->fcipp_topology = port_top;
		fcip_handle_topology(fptr);
	}

	mutex_exit(&fptr->fcip_mutex);

	switch (FC_PORT_STATE_MASK(port_state)) {
	case FC_STATE_ONLINE:
	/* FALLTHROUGH */
	case FC_STATE_LIP:
	/* FALLTHROUGH */
	case FC_STATE_LIP_LBIT_SET:

		/*
		 * nothing to do here actually other than if we
		 * were actually logged onto a port in the devlist
		 * (which indicates active communication between
		 * the host port and the port in the changelist).
		 * If however we are in a private loop or point to
		 * point mode, we need to check for any IP capable
		 * ports and update our routing table.
		 */
		switch (port_top) {
		case FC_TOP_FABRIC:
			/*
			 * This indicates a fabric port with a NameServer.
			 * Check the devlist to see if we are in active
			 * communication with a port on the devlist.
			 */
			FCIP_DEBUG(FCIP_DEBUG_ELS, (CE_NOTE,
			    "Statec_cb: fabric topology"));
			fcip_rt_update(fptr, changelist, listlen);
			break;
		case FC_TOP_NO_NS:
			/*
			 * No nameserver - so treat it like a Private loop
			 * or point to point topology and get a map of
			 * devices on the link and get IP capable ports to
			 * to update the routing table.
			 */
			FCIP_DEBUG(FCIP_DEBUG_ELS,
			    (CE_NOTE, "Statec_cb: NO_NS topology"));
		/* FALLTHROUGH */
		case FC_TOP_PRIVATE_LOOP:
			FCIP_DEBUG(FCIP_DEBUG_ELS, (CE_NOTE,
			    "Statec_cb: Pvt_Loop topology"));
		/* FALLTHROUGH */
		case FC_TOP_PT_PT:
			/*
			 * call get_port_map() and update routing table
			 */
			fcip_rt_update(fptr, changelist, listlen);
			break;
		default:
			FCIP_DEBUG(FCIP_DEBUG_ELS,
			    (CE_NOTE, "Statec_cb: Unknown topology"));
		}

		/*
		 * We should now enable the Queues and permit I/Os
		 * to flow through downstream. The update of routing
		 * table should have flushed out any port entries that
		 * don't exist or are not available after the state change
		 */
		mutex_enter(&fptr->fcip_mutex);
		fptr->fcip_port_state = FCIP_PORT_ONLINE;
		if (fptr->fcip_flags & FCIP_LINK_DOWN) {
			fptr->fcip_flags &= ~FCIP_LINK_DOWN;
		}
		mutex_exit(&fptr->fcip_mutex);

		/*
		 * Enable write queues
		 */
		rw_enter(&fcipstruplock, RW_READER);
		for (slp = fcipstrup; slp != NULL; slp = slp->sl_nextp) {
			if (slp && slp->sl_fcip == fptr) {
				wrq = WR(slp->sl_rq);
				if (wrq->q_flag & QFULL) {
					qenable(wrq);
				}
			}
		}
		rw_exit(&fcipstruplock);
		break;
	case FC_STATE_OFFLINE:
		/*
		 * mark the port_state OFFLINE and wait for it to
		 * become online. Any new messages in this state will
		 * simply be queued back up. If the port does not
		 * come online in a short while, we can begin failing
		 * messages and flush the routing table
		 */
		mutex_enter(&fptr->fcip_mutex);
		fptr->fcip_mark_offline = fptr->fcip_timeout_ticks +
		    FCIP_OFFLINE_TIMEOUT;
		fptr->fcip_port_state = FCIP_PORT_OFFLINE;
		mutex_exit(&fptr->fcip_mutex);

		/*
		 * Mark all Routing table entries as invalid to prevent
		 * any commands from trickling through to ports that
		 * have disappeared from under us
		 */
		mutex_enter(&fptr->fcip_rt_mutex);
		for (index = 0; index < FCIP_RT_HASH_ELEMS; index++) {
			frtp = fptr->fcip_rtable[index];
			while (frtp) {
				frtp->fcipr_state = PORT_DEVICE_INVALID;
				frtp = frtp->fcipr_next;
			}
		}
		mutex_exit(&fptr->fcip_rt_mutex);

		break;

	case FC_STATE_RESET_REQUESTED:
		/*
		 * Release all Unsolicited buffers back to transport/FCA.
		 * This also means the port state is marked offline - so
		 * we may have to do what OFFLINE state requires us to do.
		 * Care must be taken to wait for any active unsolicited
		 * buffer with the other Streams modules - so wait for
		 * a freeb if the unsolicited buffer is passed back all
		 * the way upstream.
		 */
		mutex_enter(&fptr->fcip_mutex);

#ifdef FCIP_ESBALLOC
		while (fptr->fcip_ub_upstream) {
			cv_wait(&fptr->fcip_ub_cv, &fptr->fcip_mutex);
		}
#endif	/* FCIP_ESBALLOC */

		fptr->fcip_mark_offline = fptr->fcip_timeout_ticks +
		    FCIP_OFFLINE_TIMEOUT;
		fptr->fcip_port_state = FCIP_PORT_OFFLINE;
		mutex_exit(&fptr->fcip_mutex);
		break;

	case FC_STATE_DEVICE_CHANGE:
		if (listlen) {
			fcip_rt_update(fptr, changelist, listlen);
		}
		break;
	case FC_STATE_RESET:
		/*
		 * Not much to do I guess - wait for port to become
		 * ONLINE. If the port doesn't become online in a short
		 * while, the upper layers abort any request themselves.
		 * We can just putback the messages in the streams queues
		 * if the link is offline
		 */
		break;
	}
	mutex_enter(&fptr->fcip_mutex);
	fptr->fcip_flags &= ~(FCIP_IN_SC_CB);
	mutex_exit(&fptr->fcip_mutex);
}

/*
 * Given a port handle, return the fcip_port_info structure corresponding
 * to that port handle. The transport allocates and communicates with
 * ULPs using port handles
 */
static fcip_port_info_t *
fcip_get_port(opaque_t phandle)
{
	fcip_port_info_t *fport;

	ASSERT(phandle != NULL);

	mutex_enter(&fcip_global_mutex);
	fport = fcip_port_head;

	while (fport != NULL) {
		if (fport->fcipp_handle == phandle) {
			/* found */
			break;
		}
		fport = fport->fcipp_next;
	}

	mutex_exit(&fcip_global_mutex);

	return (fport);
}

/*
 * Handle inbound ELS requests received by the transport. We are only
 * intereseted in FARP/InARP mostly.
 */
/* ARGSUSED */
static int
fcip_els_cb(opaque_t ulp_handle, opaque_t phandle,
    fc_unsol_buf_t *buf, uint32_t claimed)
{
	fcip_port_info_t	*fport;
	struct fcip 		*fptr;
	int			instance;
	uchar_t			r_ctl;
	uchar_t			ls_code;
	la_els_farp_t		farp_cmd;
	la_els_farp_t		*fcmd;
	int			rval = FC_UNCLAIMED;

	fport = fcip_get_port(phandle);
	if (fport == NULL) {
		return (FC_UNCLAIMED);
	}

	fptr = fport->fcipp_fcip;
	ASSERT(fptr != NULL);
	if (fptr == NULL) {
		return (FC_UNCLAIMED);
	}

	instance = ddi_get_instance(fport->fcipp_dip);

	mutex_enter(&fptr->fcip_mutex);
	if ((fptr->fcip_flags & (FCIP_DETACHING | FCIP_DETACHED)) ||
	    (fptr->fcip_flags & (FCIP_SUSPENDED | FCIP_POWER_DOWN))) {
		mutex_exit(&fptr->fcip_mutex);
		return (FC_UNCLAIMED);
	}

	/*
	 * set fcip flags to indicate we are in the middle of a
	 * ELS callback so we can wait till the statechange
	 * is handled before succeeding/failing the SUSPEND/POWER DOWN.
	 */
	fptr->fcip_flags |= FCIP_IN_ELS_CB;
	mutex_exit(&fptr->fcip_mutex);

	FCIP_TNF_PROBE_2((fcip_els_cb, "fcip io", /* CSTYLED */,
		tnf_string, msg, "ELS callback",
		tnf_uint, instance, instance));

	FCIP_DEBUG(FCIP_DEBUG_ELS,
	    (CE_NOTE, "fcip%d, ELS callback , ", instance));

	r_ctl = buf->ub_frame.r_ctl;
	switch (r_ctl & R_CTL_ROUTING) {
	case R_CTL_EXTENDED_SVC:
		if (r_ctl == R_CTL_ELS_REQ) {
			ls_code = buf->ub_buffer[0];
			if (ls_code == LA_ELS_FARP_REQ) {
				/*
				 * Inbound FARP broadcast request
				 */
				if (buf->ub_bufsize != sizeof (la_els_farp_t)) {
					FCIP_DEBUG(FCIP_DEBUG_ELS, (CE_WARN,
					    "Invalid FARP req buffer size "
					    "expected 0x%lx, got 0x%x",
					    (long)(sizeof (la_els_farp_t)),
					    buf->ub_bufsize));
					rval = FC_UNCLAIMED;
					goto els_cb_done;
				}
				fcmd = (la_els_farp_t *)buf;
				if (fcip_wwn_compare(&fcmd->resp_nwwn,
				    &fport->fcipp_nwwn,
				    FCIP_COMPARE_NWWN) != 0) {
					rval = FC_UNCLAIMED;
					goto els_cb_done;
				}
				/*
				 * copy the FARP request and release the
				 * unsolicited buffer
				 */
				fcmd = &farp_cmd;
				bcopy((void *)buf, (void *)fcmd,
				    sizeof (la_els_farp_t));
				(void) fc_ulp_ubrelease(fport->fcipp_handle, 1,
				    &buf->ub_token);

				if (fcip_farp_supported &&
				    fcip_handle_farp_request(fptr, fcmd) ==
				    FC_SUCCESS) {
					/*
					 * We successfully sent out a FARP
					 * reply to the requesting port
					 */
					rval = FC_SUCCESS;
					goto els_cb_done;
				} else {
					rval = FC_UNCLAIMED;
					goto els_cb_done;
				}
			}
		} else if (r_ctl == R_CTL_ELS_RSP) {
			ls_code = buf->ub_buffer[0];
			if (ls_code == LA_ELS_FARP_REPLY) {
				/*
				 * We received a REPLY to our FARP request
				 */
				if (buf->ub_bufsize != sizeof (la_els_farp_t)) {
					FCIP_DEBUG(FCIP_DEBUG_ELS, (CE_WARN,
					    "Invalid FARP req buffer size "
					    "expected 0x%lx, got 0x%x",
					    (long)(sizeof (la_els_farp_t)),
					    buf->ub_bufsize));
					rval = FC_UNCLAIMED;
					goto els_cb_done;
				}
				fcmd = &farp_cmd;
				bcopy((void *)buf, (void *)fcmd,
				    sizeof (la_els_farp_t));
				(void) fc_ulp_ubrelease(fport->fcipp_handle, 1,
				    &buf->ub_token);
				if (fcip_farp_supported &&
				    fcip_handle_farp_response(fptr, fcmd) ==
				    FC_SUCCESS) {
					FCIP_DEBUG(FCIP_DEBUG_ELS, (CE_NOTE,
					    "Successfully recevied a FARP "
					    "response"));
					mutex_enter(&fptr->fcip_mutex);
					fptr->fcip_farp_rsp_flag = 1;
					cv_signal(&fptr->fcip_farp_cv);
					mutex_exit(&fptr->fcip_mutex);
					rval = FC_SUCCESS;
					goto els_cb_done;
				} else {
					FCIP_DEBUG(FCIP_DEBUG_ELS, (CE_WARN,
					    "Unable to handle a FARP response "
					    "receive"));
					rval = FC_UNCLAIMED;
					goto els_cb_done;
				}
			}
		}
		break;
	default:
		break;
	}
els_cb_done:
	mutex_enter(&fptr->fcip_mutex);
	fptr->fcip_flags &= ~(FCIP_IN_ELS_CB);
	mutex_exit(&fptr->fcip_mutex);
	return (rval);
}


/*
 * Handle inbound FARP requests
 */
static int
fcip_handle_farp_request(struct fcip *fptr, la_els_farp_t *fcmd)
{
	fcip_pkt_t		*fcip_pkt;
	fc_packet_t		*fc_pkt;
	fcip_port_info_t	*fport = fptr->fcip_port_info;
	int			rval = FC_FAILURE;
	opaque_t		fca_dev;
	fc_portmap_t 		map;
	struct fcip_routing_table *frp;
	struct fcip_dest *fdestp;

	/*
	 * Add an entry for the remote port into our routing and destination
	 * tables.
	 */
	map.map_did = fcmd->req_id;
	map.map_hard_addr.hard_addr = fcmd->req_id.port_id;
	map.map_state = PORT_DEVICE_VALID;
	map.map_type = PORT_DEVICE_NEW;
	map.map_flags = 0;
	map.map_pd = NULL;
	bcopy((void *)&fcmd->req_pwwn, (void *)&map.map_pwwn,
	    sizeof (la_wwn_t));
	bcopy((void *)&fcmd->req_nwwn, (void *)&map.map_nwwn,
	    sizeof (la_wwn_t));
	fcip_rt_update(fptr, &map, 1);
	mutex_enter(&fptr->fcip_rt_mutex);
	frp = fcip_lookup_rtable(fptr, &fcmd->req_pwwn, FCIP_COMPARE_NWWN);
	mutex_exit(&fptr->fcip_rt_mutex);

	fdestp = fcip_add_dest(fptr, frp);

	fcip_pkt = fcip_ipkt_alloc(fptr, sizeof (la_els_farp_t),
	    sizeof (la_els_farp_t), NULL, KM_SLEEP);
	if (fcip_pkt == NULL) {
		rval = FC_FAILURE;
		goto farp_done;
	}
	/*
	 * Fill in our port's PWWN and NWWN
	 */
	fcmd->resp_pwwn = fport->fcipp_pwwn;
	fcmd->resp_nwwn = fport->fcipp_nwwn;

	fcip_init_unicast_pkt(fcip_pkt, fport->fcipp_sid,
	    fcmd->req_id, NULL);

	fca_dev =
	    fc_ulp_get_fca_device(fport->fcipp_handle, fcmd->req_id);
	fc_pkt = FCIP_PKT_TO_FC_PKT(fcip_pkt);
	fc_pkt->pkt_cmd_fhdr.r_ctl = R_CTL_ELS_RSP;
	fc_pkt->pkt_fca_device = fca_dev;
	fcip_pkt->fcip_pkt_dest = fdestp;

	/*
	 * Attempt a PLOGI again
	 */
	if (fcmd->resp_flags & FARP_INIT_P_LOGI) {
		if (fcip_do_plogi(fptr, frp) != FC_SUCCESS) {
			/*
			 * Login to the remote port failed. There is no
			 * point continuing with the FARP request further
			 * so bail out here.
			 */
			frp->fcipr_state = PORT_DEVICE_INVALID;
			rval = FC_FAILURE;
			goto farp_done;
		}
	}

	FCIP_CP_OUT(fcmd, fc_pkt->pkt_cmd, fc_pkt->pkt_cmd_acc,
	    sizeof (la_els_farp_t));

	rval = fc_ulp_issue_els(fport->fcipp_handle, fc_pkt);
	if (rval != FC_SUCCESS) {
		FCIP_TNF_PROBE_2((fcip_handle_farp_request, "fcip io",
		    /* CSTYLED */, tnf_string, msg,
		    "fcip_transport of farp reply failed",
		    tnf_uint, rval, rval));
		FCIP_DEBUG(FCIP_DEBUG_ELS, (CE_WARN,
		    "fcip_transport of farp reply failed 0x%x", rval));
	}

farp_done:
	return (rval);
}


/*
 * Handle FARP responses to our FARP requests. When we receive a FARP
 * reply, we need to add the entry for the Port that replied into our
 * routing and destination hash tables. It is possible that the remote
 * port did not login into us (FARP responses can be received without
 * a PLOGI)
 */
static int
fcip_handle_farp_response(struct fcip *fptr, la_els_farp_t *fcmd)
{
	int			rval = FC_FAILURE;
	fc_portmap_t 		map;
	struct fcip_routing_table *frp;
	struct fcip_dest *fdestp;

	/*
	 * Add an entry for the remote port into our routing and destination
	 * tables.
	 */
	map.map_did = fcmd->dest_id;
	map.map_hard_addr.hard_addr = fcmd->dest_id.port_id;
	map.map_state = PORT_DEVICE_VALID;
	map.map_type = PORT_DEVICE_NEW;
	map.map_flags = 0;
	map.map_pd = NULL;
	bcopy((void *)&fcmd->resp_pwwn, (void *)&map.map_pwwn,
	    sizeof (la_wwn_t));
	bcopy((void *)&fcmd->resp_nwwn, (void *)&map.map_nwwn,
	    sizeof (la_wwn_t));
	fcip_rt_update(fptr, &map, 1);
	mutex_enter(&fptr->fcip_rt_mutex);
	frp = fcip_lookup_rtable(fptr, &fcmd->resp_pwwn, FCIP_COMPARE_NWWN);
	mutex_exit(&fptr->fcip_rt_mutex);

	fdestp = fcip_add_dest(fptr, frp);

	if (fdestp != NULL) {
		rval = FC_SUCCESS;
	}
	return (rval);
}


#define	FCIP_HDRS_LENGTH	\
	sizeof (fcph_network_hdr_t)+sizeof (llc_snap_hdr_t)+sizeof (ipha_t)

/*
 * fcip_data_cb is the heart of most IP operations. This routine is called
 * by the transport when any unsolicited IP data arrives at a port (which
 * is almost all IP data). This routine then strips off the Network header
 * from the payload (after authenticating the received payload ofcourse),
 * creates a message blk and sends the data upstream. You will see ugly
 * #defines because of problems with using esballoc() as opposed to
 * allocb to prevent an extra copy of data. We should probably move to
 * esballoc entirely when the MTU eventually will be larger than 1500 bytes
 * since copies will get more expensive then. At 1500 byte MTUs, there is
 * no noticable difference between using allocb and esballoc. The other
 * caveat is that the qlc firmware still cannot tell us accurately the
 * no. of valid bytes in the unsol buffer it DMA'ed so we have to resort
 * to looking into the IP header and hoping that the no. of bytes speficified
 * in the header was actually received.
 */
/* ARGSUSED */
static int
fcip_data_cb(opaque_t ulp_handle, opaque_t phandle,
    fc_unsol_buf_t *buf, uint32_t claimed)
{
	fcip_port_info_t		*fport;
	struct fcip 			*fptr;
	fcph_network_hdr_t		*nhdr;
	llc_snap_hdr_t			*snaphdr;
	mblk_t				*bp;
	uint32_t 			len;
	uint32_t			hdrlen;
	ushort_t			type;
	ipha_t				*iphdr;
	int				rval;

#ifdef FCIP_ESBALLOC
	frtn_t				*free_ubuf;
	struct fcip_esballoc_arg	*fesb_argp;
#endif /* FCIP_ESBALLOC */

	fport = fcip_get_port(phandle);
	if (fport == NULL) {
		return (FC_UNCLAIMED);
	}

	fptr = fport->fcipp_fcip;
	ASSERT(fptr != NULL);

	if (fptr == NULL) {
		return (FC_UNCLAIMED);
	}

	mutex_enter(&fptr->fcip_mutex);
	if ((fptr->fcip_flags & (FCIP_DETACHING | FCIP_DETACHED)) ||
	    (fptr->fcip_flags & (FCIP_SUSPENDED | FCIP_POWER_DOWN))) {
		mutex_exit(&fptr->fcip_mutex);
		rval = FC_UNCLAIMED;
		goto data_cb_done;
	}

	/*
	 * set fcip flags to indicate we are in the middle of a
	 * data callback so we can wait till the statechange
	 * is handled before succeeding/failing the SUSPEND/POWER DOWN.
	 */
	fptr->fcip_flags |= FCIP_IN_DATA_CB;
	mutex_exit(&fptr->fcip_mutex);

	FCIP_TNF_PROBE_2((fcip_data_cb, "fcip io", /* CSTYLED */,
		tnf_string, msg, "data callback",
		tnf_int, instance, ddi_get_instance(fport->fcipp_dip)));
	FCIP_DEBUG(FCIP_DEBUG_UPSTREAM,
	    (CE_NOTE, "fcip%d, data callback",
	    ddi_get_instance(fport->fcipp_dip)));

	/*
	 * get to the network and snap headers in the payload
	 */
	nhdr = (fcph_network_hdr_t *)buf->ub_buffer;
	snaphdr = (llc_snap_hdr_t *)(buf->ub_buffer +
	    sizeof (fcph_network_hdr_t));

	hdrlen = sizeof (fcph_network_hdr_t) + sizeof (llc_snap_hdr_t);

	/*
	 * get the IP header to obtain the no. of bytes we need to read
	 * off from the unsol buffer. This obviously is because not all
	 * data fills up the unsol buffer completely and the firmware
	 * doesn't tell us how many valid bytes are in there as well
	 */
	iphdr = (ipha_t *)(buf->ub_buffer + hdrlen);
	snaphdr->pid = BE_16(snaphdr->pid);
	type = snaphdr->pid;

	FCIP_DEBUG(FCIP_DEBUG_UPSTREAM,
	    (CE_CONT, "SNAPHDR: dsap %x, ssap %x, ctrl %x\n",
	    snaphdr->dsap, snaphdr->ssap, snaphdr->ctrl));

	FCIP_DEBUG(FCIP_DEBUG_UPSTREAM,
	    (CE_CONT, "oui[0] 0x%x oui[1] 0x%x oui[2] 0x%x pid 0x%x\n",
	    snaphdr->oui[0], snaphdr->oui[1], snaphdr->oui[2], snaphdr->pid));

	/* Authneticate, Authenticate */
	if (type == ETHERTYPE_IP) {
		len = hdrlen + BE_16(iphdr->ipha_length);
	} else if (type == ETHERTYPE_ARP) {
		len = hdrlen + 28;
	} else {
		len = buf->ub_bufsize;
	}

	FCIP_DEBUG(FCIP_DEBUG_UPSTREAM,
	    (CE_CONT, "effective packet length is %d bytes.\n", len));

	if (len < hdrlen || len > FCIP_UB_SIZE) {
		FCIP_DEBUG(FCIP_DEBUG_UPSTREAM,
		    (CE_NOTE, "Incorrect buffer size %d bytes", len));
		rval = FC_UNCLAIMED;
		goto data_cb_done;
	}

	if (buf->ub_frame.type != FC_TYPE_IS8802_SNAP) {
		FCIP_DEBUG(FCIP_DEBUG_UPSTREAM, (CE_NOTE, "Not IP/ARP data"));
		rval = FC_UNCLAIMED;
		goto data_cb_done;
	}

	FCIP_DEBUG(FCIP_DEBUG_UPSTREAM, (CE_NOTE, "checking wwn"));

	if ((fcip_wwn_compare(&nhdr->net_dest_addr, &fport->fcipp_pwwn,
	    FCIP_COMPARE_NWWN) != 0) &&
	    (!IS_BROADCAST_ADDR(&nhdr->net_dest_addr))) {
		rval = FC_UNCLAIMED;
		goto data_cb_done;
	} else if (fcip_cache_on_arp_broadcast &&
	    IS_BROADCAST_ADDR(&nhdr->net_dest_addr)) {
		fcip_cache_arp_broadcast(fptr, buf);
	}

	FCIP_DEBUG(FCIP_DEBUG_UPSTREAM, (CE_NOTE, "Allocate streams block"));

	/*
	 * Using esballoc instead of allocb should be faster, atleast at
	 * larger MTUs than 1500 bytes. Someday we'll get there :)
	 */
#if defined(FCIP_ESBALLOC)
	/*
	 * allocate memory for the frtn function arg. The Function
	 * (fcip_ubfree) arg is a struct fcip_esballoc_arg type
	 * which contains pointers to the unsol buffer and the
	 * opaque port handle for releasing the unsol buffer back to
	 * the FCA for reuse
	 */
	fesb_argp = (struct fcip_esballoc_arg *)
	    kmem_zalloc(sizeof (struct fcip_esballoc_arg), KM_NOSLEEP);

	if (fesb_argp == NULL) {
		FCIP_DEBUG(FCIP_DEBUG_UPSTREAM,
		    (CE_WARN, "esballoc of mblk failed in data_cb"));
		rval = FC_UNCLAIMED;
		goto data_cb_done;
	}
	/*
	 * Check with KM_NOSLEEP
	 */
	free_ubuf = (frtn_t *)kmem_zalloc(sizeof (frtn_t), KM_NOSLEEP);
	if (free_ubuf == NULL) {
		kmem_free(fesb_argp, sizeof (struct fcip_esballoc_arg));
		FCIP_DEBUG(FCIP_DEBUG_UPSTREAM,
		    (CE_WARN, "esballoc of mblk failed in data_cb"));
		rval = FC_UNCLAIMED;
		goto data_cb_done;
	}

	fesb_argp->frtnp = free_ubuf;
	fesb_argp->buf = buf;
	fesb_argp->phandle = phandle;
	free_ubuf->free_func = fcip_ubfree;
	free_ubuf->free_arg = (char *)fesb_argp;
	if ((bp = (mblk_t *)esballoc((unsigned char *)buf->ub_buffer,
	    len, BPRI_MED, free_ubuf)) == NULL) {
		kmem_free(fesb_argp, sizeof (struct fcip_esballoc_arg));
		kmem_free(free_ubuf, sizeof (frtn_t));
		FCIP_DEBUG(FCIP_DEBUG_UPSTREAM,
		    (CE_WARN, "esballoc of mblk failed in data_cb"));
		rval = FC_UNCLAIMED;
		goto data_cb_done;
	}
#elif !defined(FCIP_ESBALLOC)
	/*
	 * allocate streams mblk and copy the contents of the
	 * unsolicited buffer into this newly alloc'ed mblk
	 */
	if ((bp = (mblk_t *)fcip_allocb((size_t)len, BPRI_LO)) == NULL) {
		FCIP_DEBUG(FCIP_DEBUG_UPSTREAM,
		    (CE_WARN, "alloc of mblk failed in data_cb"));
		rval = FC_UNCLAIMED;
		goto data_cb_done;
	}

	/*
	 * Unsolicited buffers handed up to us from the FCA must be
	 * endian clean so just bcopy the data into our mblk. Else
	 * we may have to either copy the data byte by byte or
	 * use the ddi_rep_get* routines to do the copy for us.
	 */
	bcopy(buf->ub_buffer, bp->b_rptr, len);

	/*
	 * for esballoc'ed mblks - free the UB in the frtn function
	 * along with the memory allocated for the function arg.
	 * for allocb'ed mblk - release the unsolicited buffer here
	 */
	(void) fc_ulp_ubrelease(phandle, 1, &buf->ub_token);

#endif	/* FCIP_ESBALLOC */

	bp->b_wptr = bp->b_rptr + len;
	fptr->fcip_ipackets++;

	if (type == ETHERTYPE_IP) {
		mutex_enter(&fptr->fcip_mutex);
		fptr->fcip_ub_upstream++;
		mutex_exit(&fptr->fcip_mutex);
		bp->b_rptr += hdrlen;

		/*
		 * Check if ipq is valid in the sendup thread
		 */
		if (fcip_sendup_alloc_enque(fptr, bp, NULL) != FC_SUCCESS) {
			freemsg(bp);
		}
	} else {
		/*
		 * We won't get ethernet 802.3 packets in FCIP but we may get
		 * types other than ETHERTYPE_IP, such as ETHERTYPE_ARP. Let
		 * fcip_sendup() do the matching.
		 */
		mutex_enter(&fptr->fcip_mutex);
		fptr->fcip_ub_upstream++;
		mutex_exit(&fptr->fcip_mutex);
		if (fcip_sendup_alloc_enque(fptr, bp,
		    fcip_accept) != FC_SUCCESS) {
			freemsg(bp);
		}
	}

	rval = FC_SUCCESS;

	/*
	 * Unset fcip_flags to indicate we are out of callback and return
	 */
data_cb_done:
	mutex_enter(&fptr->fcip_mutex);
	fptr->fcip_flags &= ~(FCIP_IN_DATA_CB);
	mutex_exit(&fptr->fcip_mutex);
	return (rval);
}

#if !defined(FCIP_ESBALLOC)
/*
 * Allocate a message block for the inbound data to be sent upstream.
 */
static void *
fcip_allocb(size_t size, uint_t pri)
{
	mblk_t	*mp;

	if ((mp = allocb(size, pri)) == NULL) {
		return (NULL);
	}
	return (mp);
}

#endif

/*
 * This helper routine kmem cache alloc's a sendup element for enquing
 * into the sendup list for callbacks upstream from the dedicated sendup
 * thread. We enque the msg buf into the sendup list and cv_signal the
 * sendup thread to finish the callback for us.
 */
static int
fcip_sendup_alloc_enque(struct fcip *fptr, mblk_t *mp, struct fcipstr *(*f)())
{
	struct fcip_sendup_elem 	*msg_elem;
	int				rval = FC_FAILURE;

	FCIP_TNF_PROBE_1((fcip_sendup_alloc_enque, "fcip io", /* CSTYLED */,
		tnf_string, msg, "sendup msg enque"));
	msg_elem = kmem_cache_alloc(fptr->fcip_sendup_cache, KM_NOSLEEP);
	if (msg_elem == NULL) {
		/* drop pkt to floor - update stats */
		rval = FC_FAILURE;
		goto sendup_alloc_done;
	}
	msg_elem->fcipsu_mp = mp;
	msg_elem->fcipsu_func = f;

	mutex_enter(&fptr->fcip_sendup_mutex);
	if (fptr->fcip_sendup_head == NULL) {
		fptr->fcip_sendup_head = fptr->fcip_sendup_tail = msg_elem;
	} else {
		fptr->fcip_sendup_tail->fcipsu_next = msg_elem;
		fptr->fcip_sendup_tail = msg_elem;
	}
	fptr->fcip_sendup_cnt++;
	cv_signal(&fptr->fcip_sendup_cv);
	mutex_exit(&fptr->fcip_sendup_mutex);
	rval = FC_SUCCESS;

sendup_alloc_done:
	return (rval);
}

/*
 * One of the ways of performing the WWN to D_ID mapping required for
 * IPFC data is to cache the unsolicited ARP broadcast messages received
 * and update the routing table to add entry for the destination port
 * if we are the intended recipient of the ARP broadcast message. This is
 * one of the methods recommended in the rfc to obtain the WWN to D_ID mapping
 * but is not typically used unless enabled. The driver prefers to use the
 * nameserver/lilp map to obtain this mapping.
 */
static void
fcip_cache_arp_broadcast(struct fcip *fptr, fc_unsol_buf_t *buf)
{
	fcip_port_info_t		*fport;
	fcph_network_hdr_t		*nhdr;
	struct fcip_routing_table	*frp;
	fc_portmap_t			map;

	fport = fptr->fcip_port_info;
	if (fport == NULL) {
		return;
	}
	ASSERT(fport != NULL);

	nhdr = (fcph_network_hdr_t *)buf->ub_buffer;

	mutex_enter(&fptr->fcip_rt_mutex);
	frp = fcip_lookup_rtable(fptr, &nhdr->net_src_addr, FCIP_COMPARE_NWWN);
	mutex_exit(&fptr->fcip_rt_mutex);
	if (frp == NULL) {
		map.map_did.port_id = buf->ub_frame.s_id;
		map.map_hard_addr.hard_addr = buf->ub_frame.s_id;
		map.map_state = PORT_DEVICE_VALID;
		map.map_type = PORT_DEVICE_NEW;
		map.map_flags = 0;
		map.map_pd = NULL;
		bcopy((void *)&nhdr->net_src_addr, (void *)&map.map_pwwn,
		    sizeof (la_wwn_t));
		bcopy((void *)&nhdr->net_src_addr, (void *)&map.map_nwwn,
		    sizeof (la_wwn_t));
		fcip_rt_update(fptr, &map, 1);
		mutex_enter(&fptr->fcip_rt_mutex);
		frp = fcip_lookup_rtable(fptr, &nhdr->net_src_addr,
		    FCIP_COMPARE_NWWN);
		mutex_exit(&fptr->fcip_rt_mutex);

		(void) fcip_add_dest(fptr, frp);
	}

}

/*
 * This is a dedicated thread to do callbacks from fcip's data callback
 * routines into the modules upstream. The reason for this thread is
 * the data callback function can be called from an interrupt context and
 * the upstream modules *can* make calls downstream in the same thread
 * context. If the call is to a fabric port which is not yet in our
 * routing tables, we may have to query the nameserver/fabric for the
 * MAC addr to Port_ID mapping which may be blocking calls.
 */
static void
fcip_sendup_thr(void *arg)
{
	struct fcip		*fptr = (struct fcip *)arg;
	struct fcip_sendup_elem	*msg_elem;
	queue_t			*ip4q = NULL;

	CALLB_CPR_INIT(&fptr->fcip_cpr_info, &fptr->fcip_sendup_mutex,
	    callb_generic_cpr, "fcip_sendup_thr");

	mutex_enter(&fptr->fcip_sendup_mutex);
	for (;;) {

		while (fptr->fcip_sendup_thr_initted &&
		    fptr->fcip_sendup_head == NULL) {
			CALLB_CPR_SAFE_BEGIN(&fptr->fcip_cpr_info);
			cv_wait(&fptr->fcip_sendup_cv,
			    &fptr->fcip_sendup_mutex);
			CALLB_CPR_SAFE_END(&fptr->fcip_cpr_info,
			    &fptr->fcip_sendup_mutex);
		}

		if (fptr->fcip_sendup_thr_initted == 0) {
			break;
		}

		FCIP_TNF_PROBE_1((fcip_sendup_thr, "fcip io", /* CSTYLED */,
		    tnf_string, msg, "fcip sendup thr - new msg"));

		msg_elem = fptr->fcip_sendup_head;
		fptr->fcip_sendup_head = msg_elem->fcipsu_next;
		msg_elem->fcipsu_next = NULL;
		mutex_exit(&fptr->fcip_sendup_mutex);

		if (msg_elem->fcipsu_func == NULL) {
			/*
			 * Message for ipq. Check to see if the ipq is
			 * is still valid. Since the thread is asynchronous,
			 * there could have been a close on the stream
			 */
			mutex_enter(&fptr->fcip_mutex);
			if (fptr->fcip_ipq && canputnext(fptr->fcip_ipq)) {
				ip4q = fptr->fcip_ipq;
				mutex_exit(&fptr->fcip_mutex);
				putnext(ip4q, msg_elem->fcipsu_mp);
			} else {
				mutex_exit(&fptr->fcip_mutex);
				freemsg(msg_elem->fcipsu_mp);
			}
		} else {
			fcip_sendup(fptr, msg_elem->fcipsu_mp,
			    msg_elem->fcipsu_func);
		}

#if !defined(FCIP_ESBALLOC)
		/*
		 * for allocb'ed mblk - decrement upstream count here
		 */
		mutex_enter(&fptr->fcip_mutex);
		ASSERT(fptr->fcip_ub_upstream > 0);
		fptr->fcip_ub_upstream--;
		mutex_exit(&fptr->fcip_mutex);
#endif /* FCIP_ESBALLOC */

		kmem_cache_free(fptr->fcip_sendup_cache, (void *)msg_elem);
		mutex_enter(&fptr->fcip_sendup_mutex);
		fptr->fcip_sendup_cnt--;
	}


#ifndef	__lock_lint
	CALLB_CPR_EXIT(&fptr->fcip_cpr_info);
#else
	mutex_exit(&fptr->fcip_sendup_mutex);
#endif /* __lock_lint */

	/* Wake up fcip detach thread by the end */
	cv_signal(&fptr->fcip_sendup_cv);

	thread_exit();
}

#ifdef FCIP_ESBALLOC

/*
 * called from the stream head when it is done using an unsolicited buffer.
 * We release this buffer then to the FCA for reuse.
 */
static void
fcip_ubfree(char *arg)
{
	struct fcip_esballoc_arg *fesb_argp = (struct fcip_esballoc_arg *)arg;
	fc_unsol_buf_t	*ubuf;
	frtn_t		*frtnp;
	fcip_port_info_t		*fport;
	struct fcip 			*fptr;


	fport = fcip_get_port(fesb_argp->phandle);
	fptr = fport->fcipp_fcip;

	ASSERT(fesb_argp != NULL);
	ubuf = fesb_argp->buf;
	frtnp = fesb_argp->frtnp;


	FCIP_DEBUG(FCIP_DEBUG_UPSTREAM,
	    (CE_WARN, "freeing ubuf after esballoc in fcip_ubfree"));
	(void) fc_ulp_ubrelease(fesb_argp->phandle, 1, &ubuf->ub_token);

	mutex_enter(&fptr->fcip_mutex);
	ASSERT(fptr->fcip_ub_upstream > 0);
	fptr->fcip_ub_upstream--;
	cv_signal(&fptr->fcip_ub_cv);
	mutex_exit(&fptr->fcip_mutex);

	kmem_free(frtnp, sizeof (frtn_t));
	kmem_free(fesb_argp, sizeof (struct fcip_esballoc_arg));
}

#endif /* FCIP_ESBALLOC */

/*
 * handle data other than that of type ETHERTYPE_IP and send it on its
 * way upstream to the right streams module to handle
 */
static void
fcip_sendup(struct fcip *fptr, mblk_t *mp, struct fcipstr *(*acceptfunc)())
{
	struct fcipstr	*slp, *nslp;
	la_wwn_t	*dhostp;
	mblk_t		*nmp;
	uint32_t 	isgroupaddr;
	int 		type;
	uint32_t	hdrlen;
	fcph_network_hdr_t	*nhdr;
	llc_snap_hdr_t		*snaphdr;

	FCIP_TNF_PROBE_1((fcip_sendup, "fcip io", /* CSTYLED */,
		tnf_string, msg, "fcip sendup"));
	nhdr = (fcph_network_hdr_t *)mp->b_rptr;
	snaphdr =
	    (llc_snap_hdr_t *)(mp->b_rptr + sizeof (fcph_network_hdr_t));
	dhostp = &nhdr->net_dest_addr;
	type = snaphdr->pid;
	hdrlen = sizeof (fcph_network_hdr_t) + sizeof (llc_snap_hdr_t);

	/* No group address with fibre channel */
	isgroupaddr = 0;

	/*
	 * While holding a reader lock on the linked list of streams structures,
	 * attempt to match the address criteria for each stream
	 * and pass up the raw M_DATA ("fastpath") or a DL_UNITDATA_IND.
	 */

	rw_enter(&fcipstruplock, RW_READER);

	if ((slp = (*acceptfunc)(fcipstrup, fptr, type, dhostp)) == NULL) {
		rw_exit(&fcipstruplock);
		FCIP_TNF_PROBE_1((fcip_sendup, "fcip io", /* CSTYLED */,
		    tnf_string, msg, "fcip sendup - no slp"));
		freemsg(mp);
		return;
	}

	/*
	 * Loop on matching open streams until (*acceptfunc)() returns NULL.
	 */
	for (; nslp = (*acceptfunc)(slp->sl_nextp, fptr, type, dhostp);
	    slp = nslp) {
		if (canputnext(slp->sl_rq)) {
			if (nmp = dupmsg(mp)) {
				if ((slp->sl_flags & FCIP_SLFAST) &&
							!isgroupaddr) {
					nmp->b_rptr += hdrlen;
					putnext(slp->sl_rq, nmp);
				} else if (slp->sl_flags & FCIP_SLRAW) {
					/* No headers when FCIP_SLRAW is set */
					putnext(slp->sl_rq, nmp);
				} else if ((nmp = fcip_addudind(fptr, nmp,
				    nhdr, type))) {
					putnext(slp->sl_rq, nmp);
				}
			}
		}
	}

	/*
	 * Do the last one.
	 */
	if (canputnext(slp->sl_rq)) {
		if (slp->sl_flags & FCIP_SLFAST) {
			mp->b_rptr += hdrlen;
			putnext(slp->sl_rq, mp);
		} else if (slp->sl_flags & FCIP_SLRAW) {
			putnext(slp->sl_rq, mp);
		} else if ((mp = fcip_addudind(fptr, mp, nhdr, type))) {
			putnext(slp->sl_rq, mp);
		}
	} else {
		freemsg(mp);
	}
	FCIP_TNF_PROBE_1((fcip_sendup, "fcip io", /* CSTYLED */,
	    tnf_string, msg, "fcip sendup done"));

	rw_exit(&fcipstruplock);
}

/*
 * Match the stream based on type and wwn if necessary.
 * Destination wwn dhostp is passed to this routine is reserved
 * for future usage. We don't need to use it right now since port
 * to fcip instance mapping is unique and wwn is already validated when
 * packet comes to fcip.
 */
/* ARGSUSED */
static struct fcipstr *
fcip_accept(struct fcipstr *slp, struct fcip *fptr, int type, la_wwn_t *dhostp)
{
	t_uscalar_t 	sap;

	FCIP_TNF_PROBE_1((fcip_accept, "fcip io", /* CSTYLED */,
	    tnf_string, msg, "fcip accept"));

	for (; slp; slp = slp->sl_nextp) {
		sap = slp->sl_sap;
		FCIP_DEBUG(FCIP_DEBUG_UPSTREAM, (CE_CONT,
		    "fcip_accept: checking next sap = %x, type = %x",
		    sap, type));

		if ((slp->sl_fcip == fptr) && (type == sap)) {
			return (slp);
		}
	}
	return (NULL);
}

/*
 * Handle DL_UNITDATA_IND messages
 */
static mblk_t *
fcip_addudind(struct fcip *fptr, mblk_t *mp, fcph_network_hdr_t *nhdr,
    int type)
{
	dl_unitdata_ind_t	*dludindp;
	struct	fcipdladdr	*dlap;
	mblk_t	*nmp;
	int	size;
	uint32_t hdrlen;
	struct ether_addr	src_addr;
	struct ether_addr	dest_addr;


	hdrlen = (sizeof (llc_snap_hdr_t) + sizeof (fcph_network_hdr_t));
	mp->b_rptr += hdrlen;

	FCIP_TNF_PROBE_1((fcip_addudind, "fcip io", /* CSTYLED */,
	    tnf_string, msg, "fcip addudind"));

	/*
	 * Allocate an M_PROTO mblk for the DL_UNITDATA_IND.
	 */
	size = sizeof (dl_unitdata_ind_t) + FCIPADDRL + FCIPADDRL;
	if ((nmp = allocb(size, BPRI_LO)) == NULL) {
		fptr->fcip_allocbfail++;
		freemsg(mp);
		return (NULL);
	}
	DB_TYPE(nmp) = M_PROTO;
	nmp->b_wptr = nmp->b_datap->db_lim;
	nmp->b_rptr = nmp->b_wptr - size;

	/*
	 * Construct a DL_UNITDATA_IND primitive.
	 */
	dludindp = (dl_unitdata_ind_t *)nmp->b_rptr;
	dludindp->dl_primitive = DL_UNITDATA_IND;
	dludindp->dl_dest_addr_length = FCIPADDRL;
	dludindp->dl_dest_addr_offset = sizeof (dl_unitdata_ind_t);
	dludindp->dl_src_addr_length = FCIPADDRL;
	dludindp->dl_src_addr_offset = sizeof (dl_unitdata_ind_t) + FCIPADDRL;
	dludindp->dl_group_address = 0;		/* not DL_MULTI */

	dlap = (struct fcipdladdr *)(nmp->b_rptr + sizeof (dl_unitdata_ind_t));
	wwn_to_ether(&nhdr->net_dest_addr, &dest_addr);
	ether_bcopy(&dest_addr, &dlap->dl_phys);
	dlap->dl_sap = (uint16_t)type;

	dlap = (struct fcipdladdr *)(nmp->b_rptr + sizeof (dl_unitdata_ind_t)
		+ FCIPADDRL);
	wwn_to_ether(&nhdr->net_src_addr, &src_addr);
	ether_bcopy(&src_addr, &dlap->dl_phys);
	dlap->dl_sap = (uint16_t)type;

	/*
	 * Link the M_PROTO and M_DATA together.
	 */
	nmp->b_cont = mp;
	return (nmp);
}


/*
 * The open routine. For clone opens, we return the next available minor
 * no. for the stream to use
 */
/* ARGSUSED */
static int
fcip_open(queue_t *rq, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	struct fcipstr	*slp;
	struct fcipstr	**prevslp;
	minor_t	minor;

	FCIP_DEBUG(FCIP_DEBUG_DOWNSTREAM, (CE_NOTE, "in fcip_open"));
	FCIP_TNF_PROBE_1((fcip_open, "fcip io", /* CSTYLED */,
		tnf_string, msg, "enter"));
	/*
	 * We need to ensure that the port driver is loaded before
	 * we proceed
	 */
	if (ddi_hold_installed_driver(ddi_name_to_major(PORT_DRIVER)) == NULL) {
		/* no port driver instances found */
		FCIP_DEBUG(FCIP_DEBUG_STARTUP, (CE_WARN,
		    "!ddi_hold_installed_driver of fp failed\n"));
		return (ENXIO);
	}
	/* serialize opens */
	rw_enter(&fcipstruplock, RW_WRITER);

	prevslp = &fcipstrup;
	if (sflag == CLONEOPEN) {
		minor = 0;
		for (; (slp = *prevslp) != NULL; prevslp = &slp->sl_nextp) {
			if (minor < slp->sl_minor) {
				break;
			}
			minor ++;
		}
		FCIP_DEBUG(FCIP_DEBUG_DOWNSTREAM, (CE_NOTE,
		    "getmajor returns 0x%x", getmajor(*devp)));
		*devp = makedevice(getmajor(*devp), minor);
	} else {
		minor = getminor(*devp);
	}

	/*
	 * check if our qp's private area is already initialized. If yes
	 * the stream is already open - just return
	 */
	if (rq->q_ptr) {
		goto done;
	}

	slp = GETSTRUCT(struct fcipstr, 1);
	slp->sl_minor = minor;
	slp->sl_rq = rq;
	slp->sl_sap = 0;
	slp->sl_flags = 0;
	slp->sl_state = DL_UNATTACHED;
	slp->sl_fcip = NULL;

	mutex_init(&slp->sl_lock, NULL, MUTEX_DRIVER, NULL);

	/*
	 * link this new stream entry into list of active streams
	 */
	slp->sl_nextp = *prevslp;
	*prevslp = slp;

	rq->q_ptr = WR(rq)->q_ptr = (char *)slp;

	/*
	 * Disable automatic enabling of our write service procedures
	 * we need to control this explicitly. This will prevent
	 * anyone scheduling of our write service procedures.
	 */
	noenable(WR(rq));

done:
	rw_exit(&fcipstruplock);
	/*
	 * enable our put and service routines on the read side
	 */
	qprocson(rq);

	/*
	 * There is only one instance of fcip (instance = 0)
	 * for multiple instances of hardware
	 */
	(void) qassociate(rq, 0);	/* don't allow drcompat to be pushed */
	return (0);
}

/*
 * close an opened stream. The minor no. will then be available for
 * future opens.
 */
/* ARGSUSED */
static int
fcip_close(queue_t *rq, int flag, int otyp, cred_t *credp)
{
	struct fcipstr *slp;
	struct fcipstr **prevslp;

	FCIP_DEBUG(FCIP_DEBUG_DOWNSTREAM, (CE_NOTE, "in fcip_close"));
	FCIP_TNF_PROBE_1((fcip_close, "fcip io", /* CSTYLED */,
		tnf_string, msg, "enter"));
	ASSERT(rq);
	/* we should also have the active stream pointer in q_ptr */
	ASSERT(rq->q_ptr);

	ddi_rele_driver(ddi_name_to_major(PORT_DRIVER));
	/*
	 * disable our put and service procedures. We had enabled them
	 * on open
	 */
	qprocsoff(rq);
	slp = (struct fcipstr *)rq->q_ptr;

	/*
	 * Implicitly detach stream  a stream from an interface.
	 */
	if (slp->sl_fcip) {
		fcip_dodetach(slp);
	}

	(void) qassociate(rq, -1);	/* undo association in open */

	rw_enter(&fcipstruplock, RW_WRITER);

	/*
	 * unlink this stream from the active stream list and free it
	 */
	for (prevslp = &fcipstrup; (slp = *prevslp) != NULL;
	    prevslp = &slp->sl_nextp) {
		if (slp == (struct fcipstr *)rq->q_ptr) {
			break;
		}
	}

	/* we should have found slp */
	ASSERT(slp);

	*prevslp = slp->sl_nextp;
	mutex_destroy(&slp->sl_lock);
	kmem_free(slp, sizeof (struct fcipstr));
	rq->q_ptr = WR(rq)->q_ptr = NULL;

	rw_exit(&fcipstruplock);
	return (0);
}

/*
 * This is not an extension of the DDI_DETACH request. This routine
 * only detaches a stream from an interface
 */
static void
fcip_dodetach(struct fcipstr *slp)
{
	struct fcipstr	*tslp;
	struct fcip	*fptr;

	FCIP_DEBUG(FCIP_DEBUG_DETACH, (CE_NOTE, "in fcip_dodetach"));
	FCIP_TNF_PROBE_1((fcip_dodetach, "fcip io", /* CSTYLED */,
		tnf_string, msg, "enter"));
	ASSERT(slp->sl_fcip != NULL);

	fptr = slp->sl_fcip;
	slp->sl_fcip = NULL;

	/*
	 * we don't support promiscuous mode currently but check
	 * for and disable any promiscuous mode operation
	 */
	if (slp->sl_flags & SLALLPHYS) {
		slp->sl_flags &= ~SLALLPHYS;
	}

	/*
	 * disable ALLMULTI mode if all mulitcast addr are ON
	 */
	if (slp->sl_flags & SLALLMULTI) {
		slp->sl_flags &= ~SLALLMULTI;
	}

	/*
	 * we are most likely going to perform multicast by
	 * broadcasting to the well known addr (D_ID) 0xFFFFFF or
	 * ALPA 0x00 in case of public loops
	 */


	/*
	 * detach unit from device structure.
	 */
	for (tslp = fcipstrup; tslp != NULL; tslp = tslp->sl_nextp) {
		if (tslp->sl_fcip == fptr) {
			break;
		}
	}
	if (tslp == NULL) {
		FCIP_DEBUG(FCIP_DEBUG_DETACH, (CE_WARN,
		"fcip_dodeatch - active stream struct not found"));

		/* unregister with Fabric nameserver?? */
	}
	slp->sl_state = DL_UNATTACHED;

	fcip_setipq(fptr);
}


/*
 * Set or clear device ipq pointer.
 * Walk thru all the streams on this device, if a ETHERTYPE_IP
 * stream is found, assign device ipq to its sl_rq.
 */
static void
fcip_setipq(struct fcip *fptr)
{
	struct fcipstr	*slp;
	int		ok = 1;
	queue_t		*ipq = NULL;

	FCIP_DEBUG(FCIP_DEBUG_INIT, (CE_NOTE, "entered fcip_setipq"));

	rw_enter(&fcipstruplock, RW_READER);

	for (slp = fcipstrup; slp != NULL; slp = slp->sl_nextp) {
		if (slp->sl_fcip == fptr) {
			if (slp->sl_flags & (SLALLPHYS|SLALLSAP)) {
				ok = 0;
			}
			if (slp->sl_sap == ETHERTYPE_IP) {
				if (ipq == NULL) {
					ipq = slp->sl_rq;
				} else {
					ok = 0;
				}
			}
		}
	}

	rw_exit(&fcipstruplock);

	if (fcip_check_port_exists(fptr)) {
		/* fptr passed to us is stale */
		return;
	}

	mutex_enter(&fptr->fcip_mutex);
	if (ok) {
		fptr->fcip_ipq = ipq;
	} else {
		fptr->fcip_ipq = NULL;
	}
	mutex_exit(&fptr->fcip_mutex);
}


/* ARGSUSED */
static void
fcip_ioctl(queue_t *wq, mblk_t *mp)
{
	struct iocblk		*iocp = (struct iocblk *)mp->b_rptr;
	struct fcipstr		*slp = (struct fcipstr *)wq->q_ptr;

	FCIP_DEBUG(FCIP_DEBUG_DOWNSTREAM,
	    (CE_NOTE, "in fcip ioctl : %d", iocp->ioc_cmd));
	FCIP_TNF_PROBE_1((fcip_ioctl, "fcip io", /* CSTYLED */,
		tnf_string, msg, "enter"));

	switch (iocp->ioc_cmd) {
	case DLIOCRAW:
		slp->sl_flags |= FCIP_SLRAW;
		miocack(wq, mp, 0, 0);
		break;

	case DL_IOC_HDR_INFO:
		fcip_dl_ioc_hdr_info(wq, mp);
		break;

	default:
		miocnak(wq, mp, 0, EINVAL);
		break;
	}
}

/*
 * The streams 'Put' routine.
 */
/* ARGSUSED */
static int
fcip_wput(queue_t *wq, mblk_t *mp)
{
	struct fcipstr *slp = (struct fcipstr *)wq->q_ptr;
	struct fcip *fptr;
	struct fcip_dest *fdestp;
	fcph_network_hdr_t *headerp;

	FCIP_DEBUG(FCIP_DEBUG_DOWNSTREAM,
	    (CE_NOTE, "in fcip_wput :: type:%x", DB_TYPE(mp)));

	switch (DB_TYPE(mp)) {
	case M_DATA: {

		fptr = slp->sl_fcip;

		if (((slp->sl_flags & (FCIP_SLFAST|FCIP_SLRAW)) == 0) ||
		    (slp->sl_state != DL_IDLE) ||
		    (fptr == NULL)) {
			/*
			 * set error in the message block and send a reply
			 * back upstream. Sun's merror routine does this
			 * for us more cleanly.
			 */
			merror(wq, mp, EPROTO);
			break;
		}

		/*
		 * if any messages are already enqueued or if the interface
		 * is in promiscuous mode, causing the packets to loop back
		 * up, then enqueue the message. Otherwise just transmit
		 * the message. putq() puts the message on fcip's
		 * write queue and qenable() puts the queue (wq) on
		 * the list of queues to be called by the streams scheduler.
		 */
		if (wq->q_first) {
			(void) putq(wq, mp);
			fptr->fcip_wantw = 1;
			qenable(wq);
		} else if (fptr->fcip_flags & FCIP_PROMISC) {
			/*
			 * Promiscous mode not supported but add this code in
			 * case it will be supported in future.
			 */
			(void) putq(wq, mp);
			qenable(wq);
		} else {

			headerp = (fcph_network_hdr_t *)mp->b_rptr;
			fdestp = fcip_get_dest(fptr, &headerp->net_dest_addr);

			if (fdestp == NULL) {
				merror(wq, mp, EPROTO);
				break;
			}

			ASSERT(fdestp != NULL);

			(void) fcip_start(wq, mp, fptr, fdestp, KM_SLEEP);
		}
		break;
	}
	case M_PROTO:
	case M_PCPROTO:
		/*
		 * to prevent recursive calls into fcip_proto
		 * (PROTO and PCPROTO messages are handled by fcip_proto)
		 * let the service procedure handle these messages by
		 * calling putq here.
		 */
		(void) putq(wq, mp);
		qenable(wq);
		break;

	case M_IOCTL:
		fcip_ioctl(wq, mp);
		break;

	case M_FLUSH:
		if (*mp->b_rptr & FLUSHW) {
			flushq(wq, FLUSHALL);
			*mp->b_rptr &= ~FLUSHW;
		}
		/*
		 * we have both FLUSHW and FLUSHR set with FLUSHRW
		 */
		if (*mp->b_rptr & FLUSHR) {
			/*
			 * send msg back upstream. qreply() takes care
			 * of using the RD(wq) queue on its reply
			 */
			qreply(wq, mp);
		} else {
			freemsg(mp);
		}
		break;

	default:
		FCIP_DEBUG(FCIP_DEBUG_DOWNSTREAM,
		    (CE_NOTE, "default msg type: %x", DB_TYPE(mp)));
		freemsg(mp);
		break;
	}
	return (0);
}


/*
 * Handle M_PROTO and M_PCPROTO messages
 */
/* ARGSUSED */
static void
fcip_proto(queue_t *wq, mblk_t *mp)
{
	union DL_primitives	*dlp;
	struct fcipstr		*slp;
	t_uscalar_t		prim;

	slp = (struct fcipstr *)wq->q_ptr;
	dlp = (union DL_primitives *)mp->b_rptr;
	prim = dlp->dl_primitive;		/* the DLPI command */

	FCIP_TNF_PROBE_5((fcip_proto, "fcip io", /* CSTYLED */,
		tnf_string, msg, "enter",
		tnf_opaque, wq, wq,
		tnf_opaque, mp, mp,
		tnf_opaque, MP_DB_TYPE, DB_TYPE(mp),
		tnf_opaque, dl_primitive, dlp->dl_primitive));

	FCIP_DEBUG(FCIP_DEBUG_INIT, (CE_NOTE, "dl_primitve : %x", prim));

	mutex_enter(&slp->sl_lock);

	switch (prim) {
	case DL_UNITDATA_REQ:
		FCIP_TNF_PROBE_1((fcip_proto, "fcip io", /* CSTYLED */,
			tnf_string, msg, "unit data request"));
		FCIP_DEBUG(FCIP_DEBUG_DLPI, (CE_NOTE, "unit data request"));
		fcip_udreq(wq, mp);
		break;

	case DL_ATTACH_REQ:
		FCIP_TNF_PROBE_1((fcip_proto, "fcip io", /* CSTYLED */,
			tnf_string, msg, "Attach request"));
		FCIP_DEBUG(FCIP_DEBUG_DLPI, (CE_NOTE, "Attach request"));
		fcip_areq(wq, mp);
		break;

	case DL_DETACH_REQ:
		FCIP_TNF_PROBE_1((fcip_proto, "fcip io", /* CSTYLED */,
			tnf_string, msg, "Detach request"));
		FCIP_DEBUG(FCIP_DEBUG_DLPI, (CE_NOTE, "Detach request"));
		fcip_dreq(wq, mp);
		break;

	case DL_BIND_REQ:
		FCIP_DEBUG(FCIP_DEBUG_DLPI, (CE_NOTE, "Bind request"));
		FCIP_TNF_PROBE_1((fcip_proto, "fcip io", /* CSTYLED */,
			tnf_string, msg, "Bind request"));
		fcip_breq(wq, mp);
		break;

	case DL_UNBIND_REQ:
		FCIP_TNF_PROBE_1((fcip_proto, "fcip io", /* CSTYLED */,
			tnf_string, msg, "unbind request"));
		FCIP_DEBUG(FCIP_DEBUG_DLPI, (CE_NOTE, "unbind request"));
		fcip_ubreq(wq, mp);
		break;

	case DL_INFO_REQ:
		FCIP_TNF_PROBE_1((fcip_proto, "fcip io", /* CSTYLED */,
			tnf_string, msg, "Info request"));
		FCIP_DEBUG(FCIP_DEBUG_DLPI, (CE_NOTE, "Info request"));
		fcip_ireq(wq, mp);
		break;

	case DL_SET_PHYS_ADDR_REQ:
		FCIP_TNF_PROBE_1((fcip_proto, "fcip io", /* CSTYLED */,
			tnf_string, msg, "set phy addr request"));
		FCIP_DEBUG(FCIP_DEBUG_DLPI,
		    (CE_NOTE, "set phy addr request"));
		fcip_spareq(wq, mp);
		break;

	case DL_PHYS_ADDR_REQ:
		FCIP_TNF_PROBE_1((fcip_proto, "fcip io", /* CSTYLED */,
			tnf_string, msg, "phy addr request"));
		FCIP_DEBUG(FCIP_DEBUG_DLPI, (CE_NOTE, "phy addr request"));
		fcip_pareq(wq, mp);
		break;

	case DL_ENABMULTI_REQ:
		FCIP_TNF_PROBE_1((fcip_proto, "fcip io", /* CSTYLED */,
			tnf_string, msg, "Enable Multicast request"));
		FCIP_DEBUG(FCIP_DEBUG_DLPI,
		    (CE_NOTE, "Enable Multicast request"));
		dlerrorack(wq, mp, prim, DL_UNSUPPORTED, 0);
		break;

	case DL_DISABMULTI_REQ:
		FCIP_TNF_PROBE_1((fcip_proto, "fcip io", /* CSTYLED */,
			tnf_string, msg, "Disable Multicast request"));
		FCIP_DEBUG(FCIP_DEBUG_DLPI,
		    (CE_NOTE, "Disable Multicast request"));
		dlerrorack(wq, mp, prim, DL_UNSUPPORTED, 0);
		break;

	case DL_PROMISCON_REQ:
		FCIP_TNF_PROBE_1((fcip_proto, "fcip io", /* CSTYLED */,
			tnf_string, msg, "Promiscuous mode ON request"));
		FCIP_DEBUG(FCIP_DEBUG_DLPI,
		    (CE_NOTE, "Promiscuous mode ON request"));
		dlerrorack(wq, mp, prim, DL_UNSUPPORTED, 0);
		break;

	case DL_PROMISCOFF_REQ:
		FCIP_TNF_PROBE_1((fcip_proto, "fcip io", /* CSTYLED */,
			tnf_string, msg, "Promiscuous mode OFF request"));
		FCIP_DEBUG(FCIP_DEBUG_DLPI,
		    (CE_NOTE, "Promiscuous mode OFF request"));
		dlerrorack(wq, mp, prim, DL_UNSUPPORTED, 0);
		break;

	default:
		FCIP_TNF_PROBE_1((fcip_proto, "fcip io", /* CSTYLED */,
			tnf_string, msg, "Unsupported request"));
		dlerrorack(wq, mp, prim, DL_UNSUPPORTED, 0);
		break;
	}
	mutex_exit(&slp->sl_lock);
}

/*
 * Always enqueue M_PROTO and M_PCPROTO messages pn the wq and M_DATA
 * messages sometimes. Processing of M_PROTO and M_PCPROTO messages
 * require us to hold fcip's internal locks across (upstream) putnext
 * calls. Specifically fcip_intr could hold fcip_intrlock and fcipstruplock
 * when it calls putnext(). That thread could loop back around to call
 * fcip_wput and eventually fcip_init() to cause a recursive mutex panic
 *
 * M_DATA messages are enqueued only if we are out of xmit resources. Once
 * the transmit resources are available the service procedure is enabled
 * and an attempt is made to xmit all messages on the wq.
 */
/* ARGSUSED */
static int
fcip_wsrv(queue_t *wq)
{
	mblk_t		*mp;
	struct fcipstr	*slp;
	struct fcip	*fptr;
	struct fcip_dest *fdestp;
	fcph_network_hdr_t *headerp;

	slp = (struct fcipstr *)wq->q_ptr;
	fptr = slp->sl_fcip;

	FCIP_TNF_PROBE_2((fcip_wsrv, "fcip io", /* CSTYLED */,
		tnf_string, msg, "enter",
		tnf_opaque, wq, wq));
	FCIP_DEBUG(FCIP_DEBUG_DOWNSTREAM, (CE_NOTE, "fcip wsrv"));

	while (mp = getq(wq)) {
		switch (DB_TYPE(mp)) {
		case M_DATA:
			if (fptr && mp) {
				headerp = (fcph_network_hdr_t *)mp->b_rptr;
				fdestp = fcip_get_dest(fptr,
				    &headerp->net_dest_addr);
				if (fdestp == NULL) {
					freemsg(mp);
					goto done;
				}
				if (fcip_start(wq, mp, fptr, fdestp,
				    KM_SLEEP)) {
					goto done;
				}
			} else {
				freemsg(mp);
			}
			break;

		case M_PROTO:
		case M_PCPROTO:
			FCIP_DEBUG(FCIP_DEBUG_DOWNSTREAM,
			    (CE_NOTE, "PROT msg in wsrv"));
			fcip_proto(wq, mp);
			break;
		default:
			break;
		}
	}
done:
	return (0);
}


/*
 * This routine is called from fcip_wsrv to send a message downstream
 * on the fibre towards its destination. This routine performs the
 * actual WWN to D_ID mapping by looking up the routing and destination
 * tables.
 */
/* ARGSUSED */
static int
fcip_start(queue_t *wq, mblk_t *mp, struct fcip *fptr,
    struct fcip_dest *fdestp, int flags)
{
	int			rval;
	int			free;
	fcip_pkt_t		*fcip_pkt;
	fc_packet_t		*fc_pkt;
	fcip_port_info_t	*fport = fptr->fcip_port_info;
	size_t			datalen;

	FCIP_TNF_PROBE_4((fcip_start, "fcip io", /* CSTYLED */,
	    tnf_string, msg, "enter", tnf_opaque, wq, wq,
	    tnf_opaque, mp, mp,
	    tnf_opaque, MP_DB_TYPE, DB_TYPE(mp)));
	FCIP_DEBUG(FCIP_DEBUG_DOWNSTREAM, (CE_NOTE, "in fcipstart"));

	ASSERT(fdestp != NULL);

	/*
	 * Only return if port has gone offline and not come back online
	 * in a while
	 */
	if (fptr->fcip_flags & FCIP_LINK_DOWN) {
		freemsg(mp);
		return (0);
	}

	/*
	 * The message block coming in here already has the network and
	 * llc_snap hdr stuffed in
	 */
	/*
	 * Traditionally ethernet drivers at sun handle 3 cases here -
	 * 1. messages with one mblk
	 * 2. messages with 2 mblks
	 * 3. messages with >2 mblks
	 * For now lets handle all the 3 cases in a single case where we
	 * put them together in one mblk that has all the data
	 */

	if (mp->b_cont != NULL) {
		if (!pullupmsg(mp, -1)) {
			FCIP_DEBUG(FCIP_DEBUG_DOWNSTREAM,
			    (CE_WARN, "failed to concat message"));
			freemsg(mp);
			return (1);
		}
	}

	datalen = msgsize(mp);

	FCIP_DEBUG(FCIP_DEBUG_DOWNSTREAM, (CE_NOTE,
	    "msgsize with nhdr & llcsnap hdr in fcip_pkt_alloc 0x%lx",
	    datalen));

	/*
	 * We cannot have requests larger than FCIPMTU+Headers
	 */
	if (datalen > (FCIPMTU + sizeof (llc_snap_hdr_t) +
		sizeof (fcph_network_hdr_t))) {
		freemsg(mp);
		FCIP_DEBUG(FCIP_DEBUG_DOWNSTREAM, (CE_NOTE,
		    "fcip_pkt_alloc: datalen is larger than "
		    "max possible size."));
		return (1);
	}

	fcip_pkt = fcip_pkt_alloc(fptr, mp, flags, datalen);
	if (fcip_pkt == NULL) {
		(void) putbq(wq, mp);
		return (1);
	}

	fcip_pkt->fcip_pkt_mp = mp;
	fcip_pkt->fcip_pkt_wq = wq;
	fc_pkt = FCIP_PKT_TO_FC_PKT(fcip_pkt);

	mutex_enter(&fdestp->fcipd_mutex);
	/*
	 * If the device dynamically disappeared, just fail the request.
	 */
	if (fdestp->fcipd_rtable == NULL) {
		mutex_exit(&fdestp->fcipd_mutex);
		fcip_pkt_free(fcip_pkt, 1);
		return (1);
	}

	/*
	 * Now that we've assigned pkt_pd, we can call fc_ulp_init_packet
	 */

	fc_pkt->pkt_pd = fdestp->fcipd_pd;

	if (fc_ulp_init_packet((opaque_t)fport->fcipp_handle,
	    fc_pkt, flags) != FC_SUCCESS) {
		mutex_exit(&fdestp->fcipd_mutex);
		fcip_pkt_free(fcip_pkt, 1);
		return (1);
	}

	fcip_fdestp_enqueue_pkt(fdestp, fcip_pkt);
	fcip_pkt->fcip_pkt_dest = fdestp;
	fc_pkt->pkt_fca_device = fdestp->fcipd_fca_dev;

	FCIP_DEBUG(FCIP_DEBUG_DOWNSTREAM, (CE_NOTE,
	    "setting cmdlen to 0x%x: rsp 0x%x : data 0x%x",
	    fc_pkt->pkt_cmdlen, fc_pkt->pkt_rsplen, fc_pkt->pkt_datalen));

	fcip_init_unicast_pkt(fcip_pkt, fport->fcipp_sid,
	    fdestp->fcipd_did, fcip_pkt_callback);

	fdestp->fcipd_ncmds++;

	mutex_exit(&fdestp->fcipd_mutex);
	if ((rval = fcip_transport(fcip_pkt)) == FC_SUCCESS) {
		fptr->fcip_opackets++;
		return (0);
	}

	free = (rval == FC_STATEC_BUSY || rval == FC_OFFLINE ||
	    rval == FC_TRAN_BUSY) ? 0 : 1;

	mutex_enter(&fdestp->fcipd_mutex);
	rval = fcip_fdestp_dequeue_pkt(fdestp, fcip_pkt);

	if (!rval) {
		fcip_pkt = NULL;
	} else {
		fdestp->fcipd_ncmds--;
	}
	mutex_exit(&fdestp->fcipd_mutex);

	if (fcip_pkt != NULL) {
		fcip_pkt_free(fcip_pkt, free);
	}

	if (!free) {
		(void) putbq(wq, mp);
	}

	return (1);
}


/*
 * This routine enqueus a packet marked to be issued to the
 * transport in the dest structure. This enables us to timeout any
 * request stuck with the FCA/transport for long periods of time
 * without a response. fcip_pkt_timeout will attempt to clean up
 * any packets hung in this state of limbo.
 */
static void
fcip_fdestp_enqueue_pkt(struct fcip_dest *fdestp, fcip_pkt_t *fcip_pkt)
{
	ASSERT(mutex_owned(&fdestp->fcipd_mutex));
	FCIP_TNF_PROBE_1((fcip_fdestp_enqueue_pkt, "fcip io", /* CSTYLED */,
		tnf_string, msg, "destp enq pkt"));

	/*
	 * Just hang it off the head of packet list
	 */
	fcip_pkt->fcip_pkt_next = fdestp->fcipd_head;
	fcip_pkt->fcip_pkt_prev = NULL;
	fcip_pkt->fcip_pkt_flags |= FCIP_PKT_IN_LIST;

	if (fdestp->fcipd_head != NULL) {
		ASSERT(fdestp->fcipd_head->fcip_pkt_prev == NULL);
		fdestp->fcipd_head->fcip_pkt_prev = fcip_pkt;
	}

	fdestp->fcipd_head = fcip_pkt;
}


/*
 * dequeues any packets after the transport/FCA tells us it has
 * been successfully sent on its way. Ofcourse it doesn't mean that
 * the packet will actually reach its destination but its atleast
 * a step closer in that direction
 */
static int
fcip_fdestp_dequeue_pkt(struct fcip_dest *fdestp, fcip_pkt_t *fcip_pkt)
{
	fcip_pkt_t	*fcipd_pkt;

	ASSERT(mutex_owned(&fdestp->fcipd_mutex));
	if (fcip_pkt->fcip_pkt_flags & FCIP_PKT_IN_TIMEOUT) {
		fcipd_pkt = fdestp->fcipd_head;
		while (fcipd_pkt) {
			if (fcipd_pkt == fcip_pkt) {
				fcip_pkt_t	*pptr = NULL;

				if (fcipd_pkt == fdestp->fcipd_head) {
					ASSERT(fcipd_pkt->fcip_pkt_prev ==
					    NULL);
					fdestp->fcipd_head =
					    fcipd_pkt->fcip_pkt_next;
				} else {
					pptr = fcipd_pkt->fcip_pkt_prev;
					ASSERT(pptr != NULL);
					pptr->fcip_pkt_next =
					    fcipd_pkt->fcip_pkt_next;
				}
				if (fcipd_pkt->fcip_pkt_next) {
					pptr = fcipd_pkt->fcip_pkt_next;
					pptr->fcip_pkt_prev =
					    fcipd_pkt->fcip_pkt_prev;
				}
				fcip_pkt->fcip_pkt_flags &= ~FCIP_PKT_IN_LIST;
				break;
			}
			fcipd_pkt = fcipd_pkt->fcip_pkt_next;
		}
	} else {
		if (fcip_pkt->fcip_pkt_prev == NULL) {
			ASSERT(fdestp->fcipd_head == fcip_pkt);
			fdestp->fcipd_head = fcip_pkt->fcip_pkt_next;
		} else {
			fcip_pkt->fcip_pkt_prev->fcip_pkt_next =
			    fcip_pkt->fcip_pkt_next;
		}

		if (fcip_pkt->fcip_pkt_next) {
			fcip_pkt->fcip_pkt_next->fcip_pkt_prev =
			    fcip_pkt->fcip_pkt_prev;
		}

		fcipd_pkt = fcip_pkt;
		fcip_pkt->fcip_pkt_flags &= ~FCIP_PKT_IN_LIST;
	}

	return (fcipd_pkt == fcip_pkt);
}

/*
 * The transport routine - this is the routine that actually calls
 * into the FCA driver (through the transport ofcourse) to transmit a
 * datagram on the fibre. The dest struct assoicated with the port to
 * which the data is intended is already bound to the packet, this routine
 * only takes care of marking the packet a broadcast packet if it is
 * intended to be a broadcast request. This permits the transport to send
 * the packet down on the wire even if it doesn't have an entry for the
 * D_ID in its d_id hash tables.
 */
static int
fcip_transport(fcip_pkt_t *fcip_pkt)
{
	struct fcip		*fptr;
	fc_packet_t		*fc_pkt;
	fcip_port_info_t	*fport;
	struct fcip_dest	*fdestp;
	uint32_t		did;
	int			rval = FC_FAILURE;
	struct fcip_routing_table *frp = NULL;

	FCIP_TNF_PROBE_1((fcip_transport, "fcip io", /* CSTYLED */,
		tnf_string, msg, "enter"));

	fptr = fcip_pkt->fcip_pkt_fptr;
	fport = fptr->fcip_port_info;
	fc_pkt = FCIP_PKT_TO_FC_PKT(fcip_pkt);
	fdestp = fcip_pkt->fcip_pkt_dest;
	FCIP_DEBUG(FCIP_DEBUG_DOWNSTREAM, (CE_WARN, "fcip_transport called"));

	did = fptr->fcip_broadcast_did;
	if (fc_pkt->pkt_cmd_fhdr.d_id == did &&
	    fc_pkt->pkt_tran_type != FC_PKT_BROADCAST) {
		FCIP_DEBUG(FCIP_DEBUG_DOWNSTREAM,
		    (CE_NOTE, "trantype set to BROADCAST"));
		fc_pkt->pkt_tran_type = FC_PKT_BROADCAST;
	}

	mutex_enter(&fptr->fcip_mutex);
	if ((fc_pkt->pkt_tran_type != FC_PKT_BROADCAST) &&
	    (fc_pkt->pkt_pd == NULL)) {
		mutex_exit(&fptr->fcip_mutex);
		FCIP_TNF_PROBE_1((fcip_transport, "fcip io", /* CSTYLED */,
		    tnf_string, msg, "fcip transport no pd"));
		return (rval);
	} else if (fptr->fcip_port_state == FCIP_PORT_OFFLINE) {
		mutex_exit(&fptr->fcip_mutex);
		FCIP_TNF_PROBE_1((fcip_transport, "fcip io", /* CSTYLED */,
		    tnf_string, msg, "fcip transport port offline"));
		return (FC_TRAN_BUSY);
	}
	mutex_exit(&fptr->fcip_mutex);

	if (fdestp) {
		struct fcip_routing_table 	*frp;

		frp = fdestp->fcipd_rtable;
		mutex_enter(&fptr->fcip_rt_mutex);
		mutex_enter(&fdestp->fcipd_mutex);
		if (fc_pkt->pkt_pd != NULL) {
			if ((frp == NULL) ||
			    (frp && FCIP_RTE_UNAVAIL(frp->fcipr_state))) {
				mutex_exit(&fdestp->fcipd_mutex);
				mutex_exit(&fptr->fcip_rt_mutex);
				if (frp &&
				    (frp->fcipr_state == FCIP_RT_INVALID)) {
					FCIP_TNF_PROBE_1((fcip_transport,
					    "fcip io", /* CSTYLED */,
					    tnf_string, msg,
					    "fcip transport - TRANBUSY"));
					return (FC_TRAN_BUSY);
				} else {
					FCIP_TNF_PROBE_1((fcip_transport,
					    "fcip io", /* CSTYLED */,
					    tnf_string, msg,
					    "fcip transport: frp unavailable"));
					return (rval);
				}
			}
		}
		mutex_exit(&fdestp->fcipd_mutex);
		mutex_exit(&fptr->fcip_rt_mutex);
		ASSERT(fcip_pkt->fcip_pkt_flags & FCIP_PKT_IN_LIST);
	}

	/* Explicitly invalidate this field till fcip decides to use it */
	fc_pkt->pkt_ulp_rscn_infop = NULL;

	rval = fc_ulp_transport(fport->fcipp_handle, fc_pkt);
	if (rval == FC_STATEC_BUSY || rval == FC_OFFLINE) {
		/*
		 * Need to queue up the command for retry
		 */
		FCIP_DEBUG(FCIP_DEBUG_DOWNSTREAM,
		    (CE_WARN, "ulp_transport failed: 0x%x", rval));
	} else if (rval == FC_LOGINREQ && (frp != NULL)) {
		(void) fcip_do_plogi(fptr, frp);
	} else if (rval == FC_BADPACKET && (frp != NULL)) {
		/*
		 * There is a distinct possiblity in our scheme of things
		 * that we have a routing table entry with a NULL pd struct.
		 * Mark the routing table entry for removal if it is not a
		 * broadcast entry
		 */
		if ((frp->fcipr_d_id.port_id != 0x0) &&
		    (frp->fcipr_d_id.port_id != 0xffffff)) {
			mutex_enter(&fptr->fcip_rt_mutex);
			frp->fcipr_pd = NULL;
			frp->fcipr_state = PORT_DEVICE_INVALID;
			mutex_exit(&fptr->fcip_rt_mutex);
		}
	}

	FCIP_TNF_PROBE_1((fcip_transport, "fcip io", /* CSTYLED */,
	    tnf_string, msg, "fcip transport done"));
	return (rval);
}

/*
 * Call back routine. Called by the FCA/transport when the messages
 * has been put onto the wire towards its intended destination. We can
 * now free the fc_packet associated with the message
 */
static void
fcip_pkt_callback(fc_packet_t *fc_pkt)
{
	int			rval;
	fcip_pkt_t		*fcip_pkt;
	struct fcip_dest	*fdestp;

	fcip_pkt = (fcip_pkt_t *)fc_pkt->pkt_ulp_private;
	fdestp = fcip_pkt->fcip_pkt_dest;

	/*
	 * take the lock early so that we don't have a race condition
	 * with fcip_timeout
	 *
	 * fdestp->fcipd_mutex isn't really intended to lock per
	 * packet struct - see bug 5105592 for permanent solution
	 */
	mutex_enter(&fdestp->fcipd_mutex);

	fcip_pkt->fcip_pkt_flags |= FCIP_PKT_RETURNED;
	fcip_pkt->fcip_pkt_flags &= ~FCIP_PKT_IN_ABORT;
	if (fcip_pkt->fcip_pkt_flags & FCIP_PKT_IN_TIMEOUT) {
		mutex_exit(&fdestp->fcipd_mutex);
		return;
	}

	FCIP_DEBUG(FCIP_DEBUG_DOWNSTREAM, (CE_NOTE, "pkt callback"));

	ASSERT(fdestp->fcipd_rtable != NULL);
	ASSERT(fcip_pkt->fcip_pkt_flags & FCIP_PKT_IN_LIST);
	rval = fcip_fdestp_dequeue_pkt(fdestp, fcip_pkt);
	fdestp->fcipd_ncmds--;
	mutex_exit(&fdestp->fcipd_mutex);

	if (rval) {
		fcip_pkt_free(fcip_pkt, 1);
	}

	FCIP_TNF_PROBE_1((fcip_pkt_callback, "fcip io", /* CSTYLED */,
		tnf_string, msg, "pkt callback done"));
	FCIP_DEBUG(FCIP_DEBUG_DOWNSTREAM, (CE_NOTE, "pkt callback done"));
}

/*
 * Return 1 if the topology is supported, else return 0.
 * Topology support is consistent with what the whole
 * stack supports together.
 */
static int
fcip_is_supported_fc_topology(int fc_topology)
{
	switch (fc_topology) {

	case FC_TOP_PRIVATE_LOOP :
	case FC_TOP_PUBLIC_LOOP :
	case FC_TOP_FABRIC :
	case FC_TOP_NO_NS :
		return (1);
	default :
		return (0);
	}
}

/*
 * handle any topology specific initializations here
 * this routine must be called while holding fcip_mutex
 */
/* ARGSUSED */
static void
fcip_handle_topology(struct fcip *fptr)
{

	fcip_port_info_t	*fport = fptr->fcip_port_info;

	ASSERT(mutex_owned(&fptr->fcip_mutex));

	/*
	 * Since we know the port's topology - handle topology
	 * specific details here. In Point to Point and Private Loop
	 * topologies - we would probably not have a name server
	 */

	FCIP_TNF_PROBE_3((fcip_handle_topology, "fcip io", /* CSTYLED */,
		tnf_string, msg, "enter",
		tnf_uint, port_state, fport->fcipp_pstate,
		tnf_uint, topology, fport->fcipp_topology));
	FCIP_DEBUG(FCIP_DEBUG_INIT, (CE_NOTE, "port state: %x, topology %x",
		fport->fcipp_pstate, fport->fcipp_topology));

	fptr->fcip_broadcast_did = fcip_get_broadcast_did(fptr);
	mutex_exit(&fptr->fcip_mutex);
	(void) fcip_dest_add_broadcast_entry(fptr, 0);
	mutex_enter(&fptr->fcip_mutex);

	if (!fcip_is_supported_fc_topology(fport->fcipp_topology)) {
		FCIP_DEBUG(FCIP_DEBUG_INIT,
		    (CE_WARN, "fcip(0x%x): Unsupported port topology (0x%x)",
		    fptr->fcip_instance, fport->fcipp_topology));
		return;
	}

	switch (fport->fcipp_topology) {
	case FC_TOP_PRIVATE_LOOP: {

		fc_portmap_t		*port_map;
		uint32_t		listlen, alloclen;
		/*
		 * we may have to maintain routing. Get a list of
		 * all devices on this port that the transport layer is
		 * aware of. Check if any of them is a IS8802 type port,
		 * if yes get its WWN and DID mapping and cache it in
		 * the purport routing table. Since there is no
		 * State Change notification for private loop/point_point
		 * topologies - this table may not be accurate. The static
		 * routing table is updated on a state change callback.
		 */
		FCIP_DEBUG(FCIP_DEBUG_INIT, (CE_WARN, "port state valid!!"));
		fptr->fcip_port_state = FCIP_PORT_ONLINE;
		listlen = alloclen = FCIP_MAX_PORTS;
		port_map = (fc_portmap_t *)
		    kmem_zalloc((FCIP_MAX_PORTS * sizeof (fc_portmap_t)),
		    KM_SLEEP);
		if (fc_ulp_getportmap(fport->fcipp_handle, &port_map,
		    &listlen, FC_ULP_PLOGI_PRESERVE) == FC_SUCCESS) {
			mutex_exit(&fptr->fcip_mutex);
			fcip_rt_update(fptr, port_map, listlen);
			mutex_enter(&fptr->fcip_mutex);
		}
		if (listlen > alloclen) {
			alloclen = listlen;
		}
		kmem_free(port_map, (alloclen * sizeof (fc_portmap_t)));
		/*
		 * Now fall through and register with the transport
		 * that this port is IP capable
		 */
	}
	/* FALLTHROUGH */
	case FC_TOP_NO_NS:
		/*
		 * If we don't have a nameserver, lets wait until we
		 * have to send out a packet to a remote port and then
		 * try and discover the port using ARP/FARP.
		 */
	/* FALLTHROUGH */
	case FC_TOP_PUBLIC_LOOP:
	case FC_TOP_FABRIC: {
		fc_portmap_t	*port_map;
		uint32_t	listlen, alloclen;

		/* FC_TYPE of 0x05 goes to word 0, LSB */
		fptr->fcip_port_state = FCIP_PORT_ONLINE;

		if (!(fptr->fcip_flags & FCIP_REG_INPROGRESS)) {
			fptr->fcip_flags |= FCIP_REG_INPROGRESS;
			if (taskq_dispatch(fptr->fcip_tq, fcip_port_ns,
			    fptr, KM_NOSLEEP) == 0) {
				fptr->fcip_flags &= ~FCIP_REG_INPROGRESS;
			}
		}

		/*
		 * If fcip_create_nodes_on_demand is overridden to force
		 * discovery of all nodes in Fabric/Public loop topologies
		 * we need to query for and obtain all nodes and log into
		 * them as with private loop devices
		 */
		if (!fcip_create_nodes_on_demand) {
			fptr->fcip_port_state = FCIP_PORT_ONLINE;
			listlen = alloclen = FCIP_MAX_PORTS;
			port_map = (fc_portmap_t *)
			    kmem_zalloc((FCIP_MAX_PORTS *
			    sizeof (fc_portmap_t)), KM_SLEEP);
			if (fc_ulp_getportmap(fport->fcipp_handle, &port_map,
			    &listlen, FC_ULP_PLOGI_PRESERVE) == FC_SUCCESS) {
				mutex_exit(&fptr->fcip_mutex);
				fcip_rt_update(fptr, port_map, listlen);
				mutex_enter(&fptr->fcip_mutex);
			}
			if (listlen > alloclen) {
				alloclen = listlen;
			}
			kmem_free(port_map,
			    (alloclen * sizeof (fc_portmap_t)));
		}
		break;
	}

	default:
		break;
	}
}

static void
fcip_port_ns(void *arg)
{
	struct	fcip		*fptr = (struct fcip *)arg;
	fcip_port_info_t	*fport = fptr->fcip_port_info;
	fc_ns_cmd_t		ns_cmd;
	uint32_t		types[8];
	ns_rfc_type_t		rfc;

	mutex_enter(&fptr->fcip_mutex);
	if ((fptr->fcip_flags & (FCIP_DETACHING | FCIP_DETACHED)) ||
	    (fptr->fcip_flags & (FCIP_SUSPENDED | FCIP_POWER_DOWN))) {
		fptr->fcip_flags &= ~FCIP_REG_INPROGRESS;
		mutex_exit(&fptr->fcip_mutex);
		return;
	}
	mutex_exit(&fptr->fcip_mutex);

	/*
	 * Prepare the Name server structure to
	 * register with the transport in case of
	 * Fabric configuration.
	 */
	bzero(&rfc, sizeof (rfc));
	bzero(types, sizeof (types));

	types[FC4_TYPE_WORD_POS(FC_TYPE_IS8802_SNAP)] = (1 <<
	    FC4_TYPE_BIT_POS(FC_TYPE_IS8802_SNAP));

	rfc.rfc_port_id.port_id = fport->fcipp_sid.port_id;
	bcopy(types, rfc.rfc_types, sizeof (types));

	ns_cmd.ns_flags = 0;
	ns_cmd.ns_cmd = NS_RFT_ID;
	ns_cmd.ns_req_len = sizeof (rfc);
	ns_cmd.ns_req_payload = (caddr_t)&rfc;
	ns_cmd.ns_resp_len = 0;
	ns_cmd.ns_resp_payload = NULL;

	/*
	 * Perform the Name Server Registration for FC IS8802_SNAP Type.
	 * We don't expect a reply for registering port type
	 */
	(void) fc_ulp_port_ns(fptr->fcip_port_info->fcipp_handle,
		(opaque_t)0, &ns_cmd);

	mutex_enter(&fptr->fcip_mutex);
	fptr->fcip_flags &= ~FCIP_REG_INPROGRESS;
	mutex_exit(&fptr->fcip_mutex);
}

/*
 * setup this instance of fcip. This routine inits kstats, allocates
 * unsolicited buffers, determines' this port's siblings and handles
 * topology specific details which includes registering with the name
 * server and also setting up the routing table for this port for
 * private loops and point to point topologies
 */
static int
fcip_init_port(struct fcip *fptr)
{
	int rval = FC_SUCCESS;
	fcip_port_info_t	*fport = fptr->fcip_port_info;
	static char buf[64];
	size_t	tok_buf_size;

	ASSERT(fport != NULL);

	FCIP_TNF_PROBE_1((fcip_init_port, "fcip io", /* CSTYLED */,
		tnf_string, msg, "enter"));
	mutex_enter(&fptr->fcip_mutex);

	/*
	 * setup mac address for this port. Don't be too worried if
	 * the WWN is zero, there is probably nothing attached to
	 * to the port. There is no point allocating unsolicited buffers
	 * for an unused port so return success if we don't have a MAC
	 * address. Do the port init on a state change notification.
	 */
	if (fcip_setup_mac_addr(fptr) == FCIP_INVALID_WWN) {
		fptr->fcip_port_state = FCIP_PORT_OFFLINE;
		rval = FC_SUCCESS;
		goto done;
	}

	/*
	 * clear routing table hash list for this port
	 */
	fcip_rt_flush(fptr);

	/*
	 * init kstats for this instance
	 */
	fcip_kstat_init(fptr);

	/*
	 * Allocate unsolicited buffers
	 */
	fptr->fcip_ub_nbufs = fcip_ub_nbufs;
	tok_buf_size = sizeof (*fptr->fcip_ub_tokens) * fcip_ub_nbufs;

	FCIP_TNF_PROBE_2((fcip_init_port, "fcip io", /* CSTYLED */,
		tnf_string, msg, "debug",
		tnf_int, tokBufsize, tok_buf_size));

	FCIP_DEBUG(FCIP_DEBUG_INIT,
	    (CE_WARN, "tokBufsize: 0x%lx", tok_buf_size));

	fptr->fcip_ub_tokens = kmem_zalloc(tok_buf_size, KM_SLEEP);

	if (fptr->fcip_ub_tokens == NULL) {
		rval = FC_FAILURE;
		FCIP_DEBUG(FCIP_DEBUG_INIT,
		    (CE_WARN, "fcip(%d): failed to allocate unsol buf",
		    fptr->fcip_instance));
		goto done;
	}
	rval = fc_ulp_uballoc(fport->fcipp_handle, &fptr->fcip_ub_nbufs,
		fcip_ub_size, FC_TYPE_IS8802_SNAP, fptr->fcip_ub_tokens);

	if (rval != FC_SUCCESS) {
		FCIP_DEBUG(FCIP_DEBUG_INIT,
		    (CE_WARN, "fcip(%d): fc_ulp_uballoc failed with 0x%x!!",
		    fptr->fcip_instance, rval));
	}

	switch (rval) {
	case FC_SUCCESS:
		break;

	case FC_OFFLINE:
		fptr->fcip_port_state = FCIP_PORT_OFFLINE;
		rval = FC_FAILURE;
		goto done;

	case FC_UB_ERROR:
		FCIP_TNF_PROBE_1((fcip_init_port, "fcip io", /* CSTYLED */,
			tnf_string, msg, "invalid ub alloc request"));
		FCIP_DEBUG(FCIP_DEBUG_INIT,
		    (CE_WARN, "invalid ub alloc request !!"));
		rval = FC_FAILURE;
		goto done;

	case FC_FAILURE:
		/*
		 * requested bytes could not be alloced
		 */
		if (fptr->fcip_ub_nbufs != fcip_ub_nbufs) {
			cmn_err(CE_WARN,
			    "!fcip(0x%x): Failed to alloc unsolicited bufs",
			    ddi_get_instance(fport->fcipp_dip));
			rval = FC_FAILURE;
			goto done;
		}
		break;

	default:
		rval = FC_FAILURE;
		break;
	}

	/*
	 * Preallocate a Cache of fcip packets for transmit and receive
	 * We don't want to be holding on to unsolicited buffers while
	 * we transmit the message upstream
	 */
	FCIP_DEBUG(FCIP_DEBUG_INIT, (CE_NOTE, "allocating fcip_pkt cache"));

	(void) sprintf(buf, "fcip%d_cache", fptr->fcip_instance);
	fptr->fcip_xmit_cache = kmem_cache_create(buf,
		(fport->fcipp_fca_pkt_size + sizeof (fcip_pkt_t)),
		8, fcip_cache_constructor, fcip_cache_destructor,
		NULL, (void *)fport, NULL, 0);

	(void) sprintf(buf, "fcip%d_sendup_cache", fptr->fcip_instance);
	fptr->fcip_sendup_cache = kmem_cache_create(buf,
		sizeof (struct fcip_sendup_elem),
		8, fcip_sendup_constructor, NULL, NULL, (void *)fport, NULL, 0);

	if (fptr->fcip_xmit_cache == NULL) {
		FCIP_TNF_PROBE_2((fcip_init_port, "fcip io", /* CSTYLED */,
			tnf_string, msg, "unable to allocate xmit cache",
			tnf_int, instance, fptr->fcip_instance));
		FCIP_DEBUG(FCIP_DEBUG_INIT,
		    (CE_WARN, "fcip%d unable to allocate xmit cache",
		    fptr->fcip_instance));
		rval = FC_FAILURE;
		goto done;
	}

	/*
	 * We may need to handle routing tables for point to point and
	 * fcal topologies and register with NameServer for Fabric
	 * topologies.
	 */
	fcip_handle_topology(fptr);
	mutex_exit(&fptr->fcip_mutex);
	if (fcip_dest_add_broadcast_entry(fptr, 1) != FC_SUCCESS) {
		FCIP_DEBUG(FCIP_DEBUG_INIT,
		    (CE_WARN, "fcip(0x%x):add broadcast entry failed!!",
		    fptr->fcip_instance));
		mutex_enter(&fptr->fcip_mutex);
		rval = FC_FAILURE;
		goto done;
	}

	rval = FC_SUCCESS;
	return (rval);

done:
	/*
	 * we don't always come here from port_attach - so cleanup
	 * anything done in the init_port routine
	 */
	if (fptr->fcip_kstatp) {
		kstat_delete(fptr->fcip_kstatp);
		fptr->fcip_kstatp = NULL;
	}

	if (fptr->fcip_xmit_cache) {
		kmem_cache_destroy(fptr->fcip_xmit_cache);
		fptr->fcip_xmit_cache = NULL;
	}

	if (fptr->fcip_sendup_cache) {
		kmem_cache_destroy(fptr->fcip_sendup_cache);
		fptr->fcip_sendup_cache = NULL;
	}

	/* release unsolicited buffers */
	if (fptr->fcip_ub_tokens) {
		uint64_t	*tokens = fptr->fcip_ub_tokens;
		fptr->fcip_ub_tokens = NULL;

		mutex_exit(&fptr->fcip_mutex);
		(void) fc_ulp_ubfree(fport->fcipp_handle, fptr->fcip_ub_nbufs,
			tokens);
		kmem_free(tokens, tok_buf_size);

	} else {
		mutex_exit(&fptr->fcip_mutex);
	}

	return (rval);
}

/*
 * Sets up a port's MAC address from its WWN
 */
static int
fcip_setup_mac_addr(struct fcip *fptr)
{
	fcip_port_info_t	*fport = fptr->fcip_port_info;

	ASSERT(mutex_owned(&fptr->fcip_mutex));

	fptr->fcip_addrflags = 0;

	/*
	 * we cannot choose a MAC address for our interface - we have
	 * to live with whatever node WWN we get (minus the top two
	 * MSbytes for the MAC address) from the transport layer. We will
	 * treat the WWN as our factory MAC address.
	 */

	if ((fport->fcipp_nwwn.w.wwn_hi != 0) ||
	    (fport->fcipp_nwwn.w.wwn_lo != 0)) {
		char		etherstr[ETHERSTRL];

		wwn_to_ether(&fport->fcipp_nwwn, &fptr->fcip_macaddr);
		fcip_ether_to_str(&fptr->fcip_macaddr, etherstr);
		FCIP_DEBUG(FCIP_DEBUG_INIT,
		    (CE_NOTE, "setupmacaddr ouraddr %s", etherstr));

		fptr->fcip_addrflags = (FCIP_FACTADDR_PRESENT |
						FCIP_FACTADDR_USE);
	} else {
		/*
		 * No WWN - just return failure - there's not much
		 * we can do since we cannot set the WWN.
		 */
		FCIP_DEBUG(FCIP_DEBUG_INIT,
		    (CE_WARN, "Port does not have a valid WWN"));
		return (FCIP_INVALID_WWN);
	}
	return (FC_SUCCESS);
}


/*
 * flush routing table entries
 */
static void
fcip_rt_flush(struct fcip *fptr)
{
	int index;

	mutex_enter(&fptr->fcip_rt_mutex);
	for (index = 0; index < FCIP_RT_HASH_ELEMS; index++) {
		struct fcip_routing_table 	*frtp, *frtp_next;
		frtp = fptr->fcip_rtable[index];
		while (frtp) {
			frtp_next = frtp->fcipr_next;
			kmem_free(frtp, sizeof (struct fcip_routing_table));
			frtp = frtp_next;
		}
		fptr->fcip_rtable[index] = NULL;
	}
	mutex_exit(&fptr->fcip_rt_mutex);
}

/*
 * Free up the fcip softstate and all allocated resources for the
 * fcip instance assoicated with a given port driver instance
 *
 * Given that the list of structures pointed to by fcip_port_head,
 * this function is called from multiple sources, and the
 * fcip_global_mutex that protects fcip_port_head must be dropped,
 * our best solution is to return a value that indicates the next
 * port in the list.  This way the caller doesn't need to worry
 * about the race condition where it saves off a pointer to the
 * next structure in the list and by the time this routine returns,
 * that next structure has already been freed.
 */
static fcip_port_info_t *
fcip_softstate_free(fcip_port_info_t *fport)
{
	struct fcip		*fptr = NULL;
	int 			instance;
	timeout_id_t		tid;
	opaque_t		phandle = NULL;
	fcip_port_info_t	*prev_fport, *cur_fport, *next_fport = NULL;

	ASSERT(MUTEX_HELD(&fcip_global_mutex));

	if (fport) {
		phandle = fport->fcipp_handle;
		fptr = fport->fcipp_fcip;
	} else {
		return (next_fport);
	}

	if (fptr) {
		mutex_enter(&fptr->fcip_mutex);
		instance = ddi_get_instance(fptr->fcip_dip);

		/*
		 * dismantle timeout thread for this instance of fcip
		 */
		tid = fptr->fcip_timeout_id;
		fptr->fcip_timeout_id = NULL;

		mutex_exit(&fptr->fcip_mutex);
		(void) untimeout(tid);
		mutex_enter(&fptr->fcip_mutex);

		ASSERT(fcip_num_instances >= 0);
		fcip_num_instances--;

		/*
		 * stop sendup thread
		 */
		mutex_enter(&fptr->fcip_sendup_mutex);
		if (fptr->fcip_sendup_thr_initted) {
			fptr->fcip_sendup_thr_initted = 0;
			cv_signal(&fptr->fcip_sendup_cv);
			cv_wait(&fptr->fcip_sendup_cv,
			    &fptr->fcip_sendup_mutex);
		}
		ASSERT(fptr->fcip_sendup_head == NULL);
		fptr->fcip_sendup_head = fptr->fcip_sendup_tail = NULL;
		mutex_exit(&fptr->fcip_sendup_mutex);

		/*
		 * dismantle taskq
		 */
		if (fptr->fcip_tq) {
			taskq_t	*tq = fptr->fcip_tq;

			fptr->fcip_tq = NULL;

			mutex_exit(&fptr->fcip_mutex);
			taskq_destroy(tq);
			mutex_enter(&fptr->fcip_mutex);
		}

		if (fptr->fcip_kstatp) {
			kstat_delete(fptr->fcip_kstatp);
			fptr->fcip_kstatp = NULL;
		}

		/* flush the routing table entries */
		fcip_rt_flush(fptr);

		if (fptr->fcip_xmit_cache) {
			kmem_cache_destroy(fptr->fcip_xmit_cache);
			fptr->fcip_xmit_cache = NULL;
		}

		if (fptr->fcip_sendup_cache) {
			kmem_cache_destroy(fptr->fcip_sendup_cache);
			fptr->fcip_sendup_cache = NULL;
		}

		fcip_cleanup_dest(fptr);

		/* release unsolicited buffers */
		if (fptr->fcip_ub_tokens) {
			uint64_t	*tokens = fptr->fcip_ub_tokens;

			fptr->fcip_ub_tokens = NULL;
			mutex_exit(&fptr->fcip_mutex);
			if (phandle) {
				/*
				 * release the global mutex here to
				 * permit any data pending callbacks to
				 * complete. Else we will deadlock in the
				 * FCA waiting for all unsol buffers to be
				 * returned.
				 */
				mutex_exit(&fcip_global_mutex);
				(void) fc_ulp_ubfree(phandle,
				    fptr->fcip_ub_nbufs, tokens);
				mutex_enter(&fcip_global_mutex);
			}
			kmem_free(tokens, (sizeof (*tokens) * fcip_ub_nbufs));
		} else {
			mutex_exit(&fptr->fcip_mutex);
		}

		mutex_destroy(&fptr->fcip_mutex);
		mutex_destroy(&fptr->fcip_ub_mutex);
		mutex_destroy(&fptr->fcip_rt_mutex);
		mutex_destroy(&fptr->fcip_dest_mutex);
		mutex_destroy(&fptr->fcip_sendup_mutex);
		cv_destroy(&fptr->fcip_farp_cv);
		cv_destroy(&fptr->fcip_sendup_cv);
		cv_destroy(&fptr->fcip_ub_cv);

		ddi_soft_state_free(fcip_softp, instance);
	}

	/*
	 * Now dequeue the fcip_port_info from the port list
	 */
	cur_fport = fcip_port_head;
	prev_fport = NULL;
	while (cur_fport != NULL) {
		if (cur_fport == fport) {
			break;
		}
		prev_fport = cur_fport;
		cur_fport = cur_fport->fcipp_next;
	}

	/*
	 * Assert that we found a port in our port list
	 */
	ASSERT(cur_fport == fport);

	if (prev_fport) {
		/*
		 * Not the first port in the port list
		 */
		prev_fport->fcipp_next = fport->fcipp_next;
	} else {
		/*
		 * first port
		 */
		fcip_port_head = fport->fcipp_next;
	}
	next_fport = fport->fcipp_next;
	kmem_free(fport, sizeof (fcip_port_info_t));

	return (next_fport);
}


/*
 * This is called by transport for any ioctl operations performed
 * on the devctl or other transport minor nodes. It is currently
 * unused for fcip
 */
/* ARGSUSED */
static int
fcip_port_ioctl(opaque_t ulp_handle,  opaque_t port_handle, dev_t dev,
	int cmd, intptr_t data, int mode, cred_t *credp, int *rval,
	uint32_t claimed)
{
	return (FC_UNCLAIMED);
}

/*
 * DL_INFO_REQ - returns information about the DLPI stream to the DLS user
 * requesting information about this interface
 */
static void
fcip_ireq(queue_t *wq, mblk_t *mp)
{
	struct fcipstr		*slp;
	struct fcip		*fptr;
	dl_info_ack_t		*dlip;
	struct fcipdladdr	*dlap;
	la_wwn_t		*ep;
	int 			size;
	char			etherstr[ETHERSTRL];

	slp = (struct fcipstr *)wq->q_ptr;

	fptr = slp->sl_fcip;

	FCIP_DEBUG(FCIP_DEBUG_DLPI,
	    (CE_NOTE, "fcip_ireq: info request req rcvd"));

	FCIP_TNF_PROBE_1((fcip_ireq, "fcip io", /* CSTYLED */,
	    tnf_string, msg, "fcip ireq entered"));

	if (MBLKL(mp) < DL_INFO_REQ_SIZE) {
		dlerrorack(wq, mp, DL_INFO_REQ, DL_BADPRIM, 0);
		return;
	}

	/*
	 * Exchange current message for a DL_INFO_ACK
	 */
	size = sizeof (dl_info_ack_t) + FCIPADDRL + ETHERADDRL;
	if ((mp = mexchange(wq, mp, size, M_PCPROTO, DL_INFO_ACK)) == NULL) {
		return;
	}

	/*
	 * FILL in the DL_INFO_ACK fields and reply
	 */
	dlip = (dl_info_ack_t *)mp->b_rptr;
	*dlip = fcip_infoack;
	dlip->dl_current_state = slp->sl_state;
	dlap = (struct fcipdladdr *)(mp->b_rptr + dlip->dl_addr_offset);
	dlap->dl_sap = slp->sl_sap;


	if (fptr) {
		fcip_ether_to_str(&fptr->fcip_macaddr, etherstr);
		FCIP_DEBUG(FCIP_DEBUG_DLPI,
		    (CE_NOTE, "ireq - our mac: %s", etherstr));
		ether_bcopy(&fptr->fcip_macaddr, &dlap->dl_phys);
	} else {
		bzero((caddr_t)&dlap->dl_phys, ETHERADDRL);
	}

	ep = (la_wwn_t *)(mp->b_rptr + dlip->dl_brdcst_addr_offset);
	ether_bcopy(&fcip_arpbroadcast_addr, ep);

	FCIP_DEBUG(FCIP_DEBUG_DLPI, (CE_NOTE, "sending back info req.."));
	qreply(wq, mp);
}


/*
 * To handle DL_UNITDATA_REQ requests.
 */

static void
fcip_udreq(queue_t *wq, mblk_t *mp)
{
	struct fcipstr		*slp;
	struct fcip		*fptr;
	fcip_port_info_t	*fport;
	dl_unitdata_req_t	*dludp;
	mblk_t			*nmp;
	struct fcipdladdr	*dlap;
	fcph_network_hdr_t 	*headerp;
	llc_snap_hdr_t		*lsnap;
	t_uscalar_t		off, len;
	struct fcip_dest	*fdestp;
	la_wwn_t		wwn;
	int			hdr_size;

	FCIP_DEBUG(FCIP_DEBUG_DLPI, (CE_NOTE, "inside fcip_udreq"));

	FCIP_TNF_PROBE_1((fcip_udreq, "fcip io", /* CSTYLED */,
	    tnf_string, msg, "fcip udreq entered"));

	slp = (struct fcipstr *)wq->q_ptr;

	if (slp->sl_state != DL_IDLE) {
		dlerrorack(wq, mp, DL_UNITDATA_REQ, DL_OUTSTATE, 0);
		return;
	}

	fptr = slp->sl_fcip;

	if (fptr == NULL) {
		dlerrorack(wq, mp, DL_UNITDATA_REQ, DL_OUTSTATE, 0);
		return;
	}

	fport = fptr->fcip_port_info;

	dludp = (dl_unitdata_req_t *)mp->b_rptr;
	off = dludp->dl_dest_addr_offset;
	len = dludp->dl_dest_addr_length;

	/*
	 * Validate destination address format
	 */
	if (!MBLKIN(mp, off, len) || (len != FCIPADDRL)) {
		dluderrorind(wq, mp, (mp->b_rptr + off), len, DL_BADADDR, 0);
		return;
	}

	/*
	 * Error if no M_DATA follows
	 */
	nmp = mp->b_cont;
	if (nmp == NULL) {
		dluderrorind(wq, mp, (mp->b_rptr + off), len, DL_BADDATA, 0);
		return;
	}
	dlap = (struct fcipdladdr *)(mp->b_rptr + off);

	/*
	 * Now get the destination structure for the remote NPORT
	 */
	ether_to_wwn(&dlap->dl_phys, &wwn);
	fdestp = fcip_get_dest(fptr, &wwn);

	if (fdestp == NULL) {
		FCIP_DEBUG(FCIP_DEBUG_DLPI, (CE_NOTE,
		    "udreq - couldn't find dest struct for remote port");
		dluderrorind(wq, mp, (mp->b_rptr + off), len, DL_BADDATA, 0));
		return;
	}

	/*
	 * Network header + SAP
	 */
	hdr_size = sizeof (fcph_network_hdr_t) + sizeof (llc_snap_hdr_t);

	/* DB_REF gives the no. of msgs pointing to this block */
	if ((DB_REF(nmp) == 1) &&
	    (MBLKHEAD(nmp) >= hdr_size) &&
	    (((uintptr_t)mp->b_rptr & 0x1) == 0)) {
		la_wwn_t wwn;
		nmp->b_rptr -= hdr_size;

		/* first put the network header */
		headerp = (fcph_network_hdr_t *)nmp->b_rptr;
		if (ether_cmp(&dlap->dl_phys, &fcip_arpbroadcast_addr) == 0) {
			ether_to_wwn(&fcipnhbroadcastaddr, &wwn);
		} else {
			ether_to_wwn(&dlap->dl_phys, &wwn);
		}
		bcopy(&wwn, &headerp->net_dest_addr, sizeof (la_wwn_t));
		ether_to_wwn(&fptr->fcip_macaddr, &wwn);
		bcopy(&wwn, &headerp->net_src_addr, sizeof (la_wwn_t));

		/* Now the snap header */
		lsnap = (llc_snap_hdr_t *)(nmp->b_rptr +
		    sizeof (fcph_network_hdr_t));
		lsnap->dsap = 0xAA;
		lsnap->ssap = 0xAA;
		lsnap->ctrl = 0x03;
		lsnap->oui[0] = 0x00;
		lsnap->oui[1] = 0x00; 	/* 80 */
		lsnap->oui[2] = 0x00;	/* C2 */
		lsnap->pid = BE_16((dlap->dl_sap));

		freeb(mp);
		mp = nmp;

	} else {
		la_wwn_t wwn;

		DB_TYPE(mp) = M_DATA;
		headerp = (fcph_network_hdr_t *)mp->b_rptr;

		/*
		 * Only fill in the low 48bits of WWN for now - we can
		 * fill in the NAA_ID after we find the port in the
		 * routing tables
		 */
		if (ether_cmp(&dlap->dl_phys, &fcip_arpbroadcast_addr) == 0) {
			ether_to_wwn(&fcipnhbroadcastaddr, &wwn);
		} else {
			ether_to_wwn(&dlap->dl_phys, &wwn);
		}
		bcopy(&wwn, &headerp->net_dest_addr, sizeof (la_wwn_t));
		/* need to send our PWWN */
		bcopy(&fport->fcipp_pwwn, &headerp->net_src_addr,
		    sizeof (la_wwn_t));

		lsnap = (llc_snap_hdr_t *)(nmp->b_rptr +
		    sizeof (fcph_network_hdr_t));
		lsnap->dsap = 0xAA;
		lsnap->ssap = 0xAA;
		lsnap->ctrl = 0x03;
		lsnap->oui[0] = 0x00;
		lsnap->oui[1] = 0x00;
		lsnap->oui[2] = 0x00;
		lsnap->pid = BE_16(dlap->dl_sap);

		mp->b_wptr = mp->b_rptr + hdr_size;
	}

	/*
	 * Ethernet drivers have a lot of gunk here to put the Type
	 * information (for Ethernet encapsulation (RFC 894) or the
	 * Length (for 802.2/802.3) - I guess we'll just ignore that
	 * here.
	 */

	/*
	 * Start the I/O on this port. If fcip_start failed for some reason
	 * we call putbq in fcip_start so we don't need to check the
	 * return value from fcip_start
	 */
	(void) fcip_start(wq, mp, fptr, fdestp, KM_SLEEP);
}

/*
 * DL_ATTACH_REQ: attaches a PPA with a stream. ATTACH requets are needed
 * for style 2 DLS providers to identify the physical medium through which
 * the streams communication will happen
 */
static void
fcip_areq(queue_t *wq, mblk_t *mp)
{
	struct fcipstr		*slp;
	union DL_primitives	*dlp;
	fcip_port_info_t	*fport;
	struct fcip		*fptr;
	int			ppa;

	slp = (struct fcipstr *)wq->q_ptr;
	dlp = (union DL_primitives *)mp->b_rptr;

	if (MBLKL(mp) < DL_ATTACH_REQ_SIZE) {
		dlerrorack(wq, mp, DL_ATTACH_REQ, DL_BADPRIM, 0);
		return;
	}

	if (slp->sl_state != DL_UNATTACHED) {
		dlerrorack(wq, mp, DL_ATTACH_REQ, DL_OUTSTATE, 0);
		return;
	}

	ppa = dlp->attach_req.dl_ppa;
	FCIP_DEBUG(FCIP_DEBUG_DLPI, (CE_NOTE, "attach req: ppa %x", ppa));

	/*
	 * check if the PPA is valid
	 */

	mutex_enter(&fcip_global_mutex);

	for (fport = fcip_port_head; fport; fport = fport->fcipp_next) {
		if ((fptr = fport->fcipp_fcip) == NULL) {
			continue;
		}
		FCIP_DEBUG(FCIP_DEBUG_DLPI, (CE_NOTE, "ppa %x, inst %x", ppa,
		    ddi_get_instance(fptr->fcip_dip)));

		if (ppa == ddi_get_instance(fptr->fcip_dip)) {
			FCIP_DEBUG(FCIP_DEBUG_DLPI,
			    (CE_NOTE, "ppa found %x", ppa));
			break;
		}
	}

	if (fport == NULL) {
		FCIP_DEBUG(FCIP_DEBUG_DLPI,
		    (CE_NOTE, "dlerrorack coz fport==NULL"));

		mutex_exit(&fcip_global_mutex);

		if (fc_ulp_get_port_handle(ppa) == NULL) {
			dlerrorack(wq, mp, DL_ATTACH_REQ, DL_BADPPA, 0);
			return;
		}

		/*
		 * Wait for Port attach callback to trigger.  If port_detach
		 * got in while we were waiting, then ddi_get_soft_state
		 * will return NULL, and we'll return error.
		 */

		delay(drv_usectohz(FCIP_INIT_DELAY));
		mutex_enter(&fcip_global_mutex);

		fptr = ddi_get_soft_state(fcip_softp, ppa);
		if (fptr == NULL) {
			mutex_exit(&fcip_global_mutex);
			dlerrorack(wq, mp, DL_ATTACH_REQ, DL_BADPPA, 0);
			return;
		}
	}

	/*
	 * set link to device and update our state
	 */
	slp->sl_fcip = fptr;
	slp->sl_state = DL_UNBOUND;

	mutex_exit(&fcip_global_mutex);

#ifdef DEBUG
	mutex_enter(&fptr->fcip_mutex);
	if (fptr->fcip_flags & FCIP_LINK_DOWN) {
		FCIP_DEBUG(FCIP_DEBUG_DLPI, (CE_WARN, "port not online yet"));
	}
	mutex_exit(&fptr->fcip_mutex);
#endif

	dlokack(wq, mp, DL_ATTACH_REQ);
}


/*
 * DL_DETACH request - detaches a PPA from a stream
 */
static void
fcip_dreq(queue_t *wq, mblk_t *mp)
{
	struct fcipstr		*slp;

	slp = (struct fcipstr *)wq->q_ptr;

	if (MBLKL(mp) < DL_DETACH_REQ_SIZE) {
		dlerrorack(wq, mp, DL_DETACH_REQ, DL_BADPRIM, 0);
		return;
	}

	if (slp->sl_state != DL_UNBOUND) {
		dlerrorack(wq, mp, DL_DETACH_REQ, DL_OUTSTATE, 0);
		return;
	}

	fcip_dodetach(slp);
	dlokack(wq, mp, DL_DETACH_REQ);
}

/*
 * DL_BIND request: requests a DLS provider to bind a DLSAP to the stream.
 * DLS users communicate with a physical interface through DLSAPs. Multiple
 * DLSAPs can be bound to the same stream (PPA)
 */
static void
fcip_breq(queue_t *wq, mblk_t *mp)
{
	struct fcipstr		*slp;
	union DL_primitives	*dlp;
	struct fcip		*fptr;
	struct fcipdladdr	fcipaddr;
	t_uscalar_t		sap;
	int			xidtest;

	slp = (struct fcipstr *)wq->q_ptr;

	if (MBLKL(mp) < DL_BIND_REQ_SIZE) {
		dlerrorack(wq, mp, DL_BIND_REQ, DL_BADPRIM, 0);
		return;
	}

	if (slp->sl_state != DL_UNBOUND) {
		dlerrorack(wq, mp, DL_BIND_REQ, DL_OUTSTATE, 0);
		return;
	}

	dlp = (union DL_primitives *)mp->b_rptr;
	fptr = slp->sl_fcip;

	if (fptr == NULL) {
		dlerrorack(wq, mp, DL_BIND_REQ, DL_OUTSTATE, 0);
		return;
	}

	sap = dlp->bind_req.dl_sap;
	FCIP_DEBUG(FCIP_DEBUG_DLPI, (CE_NOTE, "fcip_breq - sap: %x", sap));
	xidtest = dlp->bind_req.dl_xidtest_flg;

	if (xidtest) {
		dlerrorack(wq, mp, DL_BIND_REQ, DL_NOAUTO, 0);
		return;
	}

	FCIP_DEBUG(FCIP_DEBUG_DLPI, (CE_NOTE, "DLBIND: sap : %x", sap));

	if (sap > ETHERTYPE_MAX) {
		dlerrorack(wq, mp, dlp->dl_primitive, DL_BADSAP, 0);
		return;
	}
	/*
	 * save SAP for this stream and change the link state
	 */
	slp->sl_sap = sap;
	slp->sl_state = DL_IDLE;

	fcipaddr.dl_sap = sap;
	ether_bcopy(&fptr->fcip_macaddr, &fcipaddr.dl_phys);
	dlbindack(wq, mp, sap, &fcipaddr, FCIPADDRL, 0, 0);

	fcip_setipq(fptr);
}

/*
 * DL_UNBIND request to unbind a previously bound DLSAP, from this stream
 */
static void
fcip_ubreq(queue_t *wq, mblk_t *mp)
{
	struct fcipstr	*slp;

	slp = (struct fcipstr *)wq->q_ptr;

	if (MBLKL(mp) < DL_UNBIND_REQ_SIZE) {
		dlerrorack(wq, mp, DL_UNBIND_REQ, DL_BADPRIM, 0);
		return;
	}

	if (slp->sl_state != DL_IDLE) {
		dlerrorack(wq, mp, DL_UNBIND_REQ, DL_OUTSTATE, 0);
		return;
	}

	slp->sl_state = DL_UNBOUND;
	slp->sl_sap = 0;

	(void) putnextctl1(RD(wq), M_FLUSH, FLUSHRW);
	dlokack(wq, mp, DL_UNBIND_REQ);

	fcip_setipq(slp->sl_fcip);
}

/*
 * Return our physical address
 */
static void
fcip_pareq(queue_t *wq, mblk_t *mp)
{
	struct fcipstr 		*slp;
	union DL_primitives	*dlp;
	int			type;
	struct fcip		*fptr;
	fcip_port_info_t	*fport;
	struct ether_addr	addr;

	slp = (struct fcipstr *)wq->q_ptr;

	if (MBLKL(mp) < DL_PHYS_ADDR_REQ_SIZE) {
		dlerrorack(wq, mp, DL_PHYS_ADDR_REQ, DL_BADPRIM, 0);
		return;
	}

	dlp = (union DL_primitives *)mp->b_rptr;
	type = dlp->physaddr_req.dl_addr_type;
	fptr = slp->sl_fcip;

	if (fptr == NULL) {
		dlerrorack(wq, mp, DL_PHYS_ADDR_REQ, DL_OUTSTATE, 0);
		return;
	}

	fport = fptr->fcip_port_info;

	switch (type) {
	case DL_FACT_PHYS_ADDR:
		FCIP_DEBUG(FCIP_DEBUG_DLPI,
		    (CE_NOTE, "returning factory phys addr"));
		wwn_to_ether(&fport->fcipp_pwwn, &addr);
		break;

	case DL_CURR_PHYS_ADDR:
		FCIP_DEBUG(FCIP_DEBUG_DLPI,
		    (CE_NOTE, "returning current phys addr"));
		ether_bcopy(&fptr->fcip_macaddr, &addr);
		break;

	default:
		FCIP_DEBUG(FCIP_DEBUG_DLPI,
		    (CE_NOTE, "Not known cmd type in phys addr"));
		dlerrorack(wq, mp, DL_PHYS_ADDR_REQ, DL_NOTSUPPORTED, 0);
		return;
	}
	dlphysaddrack(wq, mp, &addr, ETHERADDRL);
}

/*
 * Set physical address DLPI request
 */
static void
fcip_spareq(queue_t *wq, mblk_t *mp)
{
	struct fcipstr		*slp;
	union DL_primitives	*dlp;
	t_uscalar_t		off, len;
	struct ether_addr	*addrp;
	la_wwn_t		wwn;
	struct fcip		*fptr;
	fc_ns_cmd_t		fcip_ns_cmd;

	slp = (struct fcipstr *)wq->q_ptr;

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
	 * If the length of physical address is not correct or address
	 * specified is a broadcast address or multicast addr -
	 * return an error.
	 */
	if ((len != ETHERADDRL) ||
	    ((addrp->ether_addr_octet[0] & 01) == 1) ||
	    (ether_cmp(addrp, &fcip_arpbroadcast_addr) == 0)) {
		dlerrorack(wq, mp, DL_SET_PHYS_ADDR_REQ, DL_BADADDR, 0);
		return;
	}

	/*
	 * check if a stream is attached to this device. Else return an error
	 */
	if ((fptr = slp->sl_fcip) == NULL) {
		dlerrorack(wq, mp, DL_SET_PHYS_ADDR_REQ, DL_OUTSTATE, 0);
		return;
	}

	/*
	 * set the new interface local address. We request the transport
	 * layer to change the Port WWN for this device - return an error
	 * if we don't succeed.
	 */

	ether_to_wwn(addrp, &wwn);
	if (fcip_set_wwn(&wwn) == FC_SUCCESS) {
		FCIP_DEBUG(FCIP_DEBUG_DLPI,
		    (CE_WARN, "WWN changed in spareq"));
	} else {
		dlerrorack(wq, mp, DL_SET_PHYS_ADDR_REQ, DL_BADADDR, 0);
	}

	/*
	 * register The new Port WWN and Node WWN with the transport
	 * and Nameserver. Hope the transport ensures all current I/O
	 * has stopped before actually attempting to register a new
	 * port and Node WWN else we are hosed. Maybe a Link reset
	 * will get everyone's attention.
	 */
	fcip_ns_cmd.ns_flags = 0;
	fcip_ns_cmd.ns_cmd = NS_RPN_ID;
	fcip_ns_cmd.ns_req_len = sizeof (la_wwn_t);
	fcip_ns_cmd.ns_req_payload = (caddr_t)&wwn.raw_wwn[0];
	fcip_ns_cmd.ns_resp_len = 0;
	fcip_ns_cmd.ns_resp_payload = (caddr_t)0;
	if (fc_ulp_port_ns(fptr->fcip_port_info->fcipp_handle,
	    (opaque_t)0, &fcip_ns_cmd) != FC_SUCCESS) {
		FCIP_DEBUG(FCIP_DEBUG_DLPI,
		    (CE_WARN, "setting Port WWN failed"));
		dlerrorack(wq, mp, DL_SET_PHYS_ADDR_REQ, DL_BADPRIM, 0);
		return;
	}

	dlokack(wq, mp, DL_SET_PHYS_ADDR_REQ);
}

/*
 * change our port's WWN if permitted by hardware
 */
/* ARGSUSED */
static int
fcip_set_wwn(la_wwn_t *pwwn)
{
	/*
	 * We're usually not allowed to change the WWN of adapters
	 * but some adapters do permit us to change the WWN - don't
	 * permit setting of WWNs (yet?) - This behavior could be
	 * modified if needed
	 */
	return (FC_FAILURE);
}


/*
 * This routine fills in the header for fastpath data requests. What this
 * does in simple terms is, instead of sending all data through the Unitdata
 * request dlpi code paths (which will then append the protocol specific
 * header - network and snap headers in our case), the upper layers issue
 * a M_IOCTL with a DL_IOC_HDR_INFO request and ask the streams endpoint
 * driver to give the header it needs appended and the upper layer
 * allocates and fills in the header and calls our put routine
 */
static void
fcip_dl_ioc_hdr_info(queue_t *wq, mblk_t *mp)
{
	mblk_t			*nmp;
	struct fcipstr		*slp;
	struct fcipdladdr	*dlap;
	dl_unitdata_req_t	*dlup;
	fcph_network_hdr_t	*headerp;
	la_wwn_t		wwn;
	llc_snap_hdr_t		*lsnap;
	struct fcip		*fptr;
	fcip_port_info_t	*fport;
	t_uscalar_t		off, len;
	size_t			hdrlen;
	int 			error;

	slp = (struct fcipstr *)wq->q_ptr;
	fptr = slp->sl_fcip;
	if (fptr == NULL) {
		FCIP_DEBUG(FCIP_DEBUG_DOWNSTREAM,
		    (CE_NOTE, "dliochdr : returns EINVAL1"));
		miocnak(wq, mp, 0, EINVAL);
		return;
	}

	error = miocpullup(mp, sizeof (dl_unitdata_req_t) + FCIPADDRL);
	if (error != 0) {
		FCIP_DEBUG(FCIP_DEBUG_DOWNSTREAM,
		    (CE_NOTE, "dliochdr : returns %d", error));
		miocnak(wq, mp, 0, error);
		return;
	}

	fport = fptr->fcip_port_info;

	/*
	 * check if the DL_UNITDATA_REQ destination addr has valid offset
	 * and length values
	 */
	dlup = (dl_unitdata_req_t *)mp->b_cont->b_rptr;
	off = dlup->dl_dest_addr_offset;
	len = dlup->dl_dest_addr_length;
	if (dlup->dl_primitive != DL_UNITDATA_REQ ||
	    !MBLKIN(mp->b_cont, off, len) || (len != FCIPADDRL)) {
		FCIP_DEBUG(FCIP_DEBUG_DOWNSTREAM,
		    (CE_NOTE, "dliochdr : returns EINVAL2"));
		miocnak(wq, mp, 0, EINVAL);
		return;
	}

	dlap = (struct fcipdladdr *)(mp->b_cont->b_rptr + off);

	/*
	 * Allocate a new mblk to hold the ether header
	 */

	/*
	 * setup space for network header
	 */
	hdrlen = (sizeof (llc_snap_hdr_t) + sizeof (fcph_network_hdr_t));
	if ((nmp = allocb(hdrlen, BPRI_MED)) == NULL) {
		FCIP_DEBUG(FCIP_DEBUG_DOWNSTREAM,
		    (CE_NOTE, "dliochdr : returns ENOMEM"));
		miocnak(wq, mp, 0, ENOMEM);
		return;
	}
	nmp->b_wptr += hdrlen;

	/*
	 * Fill in the Network Hdr and LLC SNAP header;
	 */
	headerp = (fcph_network_hdr_t *)nmp->b_rptr;
	/*
	 * just fill in the Node WWN here - we can fill in the NAA_ID when
	 * we search the routing table
	 */
	if (ether_cmp(&dlap->dl_phys, &fcip_arpbroadcast_addr) == 0) {
		ether_to_wwn(&fcipnhbroadcastaddr, &wwn);
	} else {
		ether_to_wwn(&dlap->dl_phys, &wwn);
	}
	bcopy(&wwn, &headerp->net_dest_addr, sizeof (la_wwn_t));
	bcopy(&fport->fcipp_pwwn, &headerp->net_src_addr, sizeof (la_wwn_t));
	lsnap = (llc_snap_hdr_t *)(nmp->b_rptr + sizeof (fcph_network_hdr_t));
	lsnap->dsap = 0xAA;
	lsnap->ssap = 0xAA;
	lsnap->ctrl = 0x03;
	lsnap->oui[0] = 0x00;
	lsnap->oui[1] = 0x00;
	lsnap->oui[2] = 0x00;
	lsnap->pid = BE_16(dlap->dl_sap);

	/*
	 * Link new mblk in after the "request" mblks.
	 */
	linkb(mp, nmp);

	slp->sl_flags |= FCIP_SLFAST;

	FCIP_DEBUG(FCIP_DEBUG_DOWNSTREAM,
	    (CE_NOTE, "dliochdr : returns success "));
	miocack(wq, mp, msgsize(mp->b_cont), 0);
}


/*
 * Establish a kmem cache for fcip packets
 */
static int
fcip_cache_constructor(void *buf, void *arg, int flags)
{
	fcip_pkt_t		*fcip_pkt = buf;
	fc_packet_t		*fc_pkt;
	fcip_port_info_t	*fport = (fcip_port_info_t *)arg;
	int			(*cb) (caddr_t);
	struct fcip		*fptr;

	cb = (flags == KM_SLEEP) ? DDI_DMA_SLEEP : DDI_DMA_DONTWAIT;

	ASSERT(fport != NULL);

	fptr = fport->fcipp_fcip;

	/*
	 * we allocated space for our private area at the end of the
	 * fc packet. Make sure we point to it correctly. Ideally we
	 * should just push fc_packet_private to the beginning or end
	 * of the fc_packet structure
	 */
	fcip_pkt->fcip_pkt_next = NULL;
	fcip_pkt->fcip_pkt_prev = NULL;
	fcip_pkt->fcip_pkt_dest = NULL;
	fcip_pkt->fcip_pkt_state = 0;
	fcip_pkt->fcip_pkt_reason = 0;
	fcip_pkt->fcip_pkt_flags = 0;
	fcip_pkt->fcip_pkt_fptr = fptr;
	fcip_pkt->fcip_pkt_dma_flags = 0;

	fc_pkt = FCIP_PKT_TO_FC_PKT(fcip_pkt);
	fc_pkt->pkt_ulp_rscn_infop = NULL;

	/*
	 * We use pkt_cmd_dma for OUTBOUND requests. We don't expect
	 * any responses for outbound IP data so no need to setup
	 * response or data dma handles.
	 */
	if (ddi_dma_alloc_handle(fport->fcipp_dip,
	    &fport->fcipp_cmd_dma_attr, cb, NULL,
	    &fc_pkt->pkt_cmd_dma) != DDI_SUCCESS) {
		return (FCIP_FAILURE);
	}

	fc_pkt->pkt_cmd_acc = fc_pkt->pkt_resp_acc = NULL;
	fc_pkt->pkt_fca_private = (opaque_t)((caddr_t)buf +
	    sizeof (fcip_pkt_t));
	fc_pkt->pkt_ulp_private = (opaque_t)fcip_pkt;

	fc_pkt->pkt_cmd_cookie_cnt = fc_pkt->pkt_resp_cookie_cnt =
	    fc_pkt->pkt_data_cookie_cnt = 0;
	fc_pkt->pkt_cmd_cookie = fc_pkt->pkt_resp_cookie =
	    fc_pkt->pkt_data_cookie = NULL;

	return (FCIP_SUCCESS);
}

/*
 * destroy the fcip kmem cache
 */
static void
fcip_cache_destructor(void *buf, void *arg)
{
	fcip_pkt_t		*fcip_pkt = (fcip_pkt_t *)buf;
	fc_packet_t		*fc_pkt;
	fcip_port_info_t	*fport = (fcip_port_info_t *)arg;
	struct fcip		*fptr;

	ASSERT(fport != NULL);

	fptr = fport->fcipp_fcip;

	ASSERT(fptr == fcip_pkt->fcip_pkt_fptr);
	fc_pkt = FCIP_PKT_TO_FC_PKT(fcip_pkt);

	if (fc_pkt->pkt_cmd_dma) {
		ddi_dma_free_handle(&fc_pkt->pkt_cmd_dma);
	}
}

/*
 * the fcip destination structure is hashed on Node WWN assuming
 * a  NAA_ID of 0x1 (IEEE)
 */
static struct fcip_dest *
fcip_get_dest(struct fcip *fptr, la_wwn_t *pwwn)
{
	struct fcip_dest	*fdestp = NULL;
	fcip_port_info_t	*fport;
	int			hash_bucket;
	opaque_t		pd;
	int			rval;
	struct fcip_routing_table *frp;
	la_wwn_t		twwn;
	uint32_t		*twwnp = (uint32_t *)&twwn;

	hash_bucket = FCIP_DEST_HASH(pwwn->raw_wwn);
	FCIP_DEBUG(FCIP_DEBUG_DOWNSTREAM,
	    (CE_NOTE, "get dest hashbucket : 0x%x", hash_bucket));
	FCIP_DEBUG(FCIP_DEBUG_DOWNSTREAM,
	    (CE_NOTE, "0x%x 0x%x 0x%x 0x%x 0x%x 0x%x",
	    pwwn->raw_wwn[2], pwwn->raw_wwn[3], pwwn->raw_wwn[4],
	    pwwn->raw_wwn[5], pwwn->raw_wwn[6], pwwn->raw_wwn[7]));

	ASSERT(hash_bucket < FCIP_DEST_HASH_ELEMS);

	if (fcip_check_port_exists(fptr)) {
		/* fptr is stale, return fdestp */
		return (fdestp);
	}
	fport = fptr->fcip_port_info;

	/*
	 * First check if we have active I/Os going on with the
	 * destination port (an entry would exist in fcip_dest hash table)
	 */
	mutex_enter(&fptr->fcip_dest_mutex);
	fdestp = fptr->fcip_dest[hash_bucket];
	while (fdestp != NULL) {
		mutex_enter(&fdestp->fcipd_mutex);
		if (fdestp->fcipd_rtable) {
			if (fcip_wwn_compare(pwwn, &fdestp->fcipd_pwwn,
			    FCIP_COMPARE_NWWN) == 0) {
				FCIP_DEBUG(FCIP_DEBUG_DOWNSTREAM,
				    (CE_NOTE, "found fdestp"));
				mutex_exit(&fdestp->fcipd_mutex);
				mutex_exit(&fptr->fcip_dest_mutex);
				return (fdestp);
			}
		}
		mutex_exit(&fdestp->fcipd_mutex);
		fdestp = fdestp->fcipd_next;
	}
	mutex_exit(&fptr->fcip_dest_mutex);

	/*
	 * We did not find the destination port information in our
	 * active port list so search for an entry in our routing
	 * table.
	 */
	mutex_enter(&fptr->fcip_rt_mutex);
	frp = fcip_lookup_rtable(fptr, pwwn, FCIP_COMPARE_NWWN);
	mutex_exit(&fptr->fcip_rt_mutex);

	if (frp == NULL || (frp && (!FCIP_RTE_UNAVAIL(frp->fcipr_state)) &&
	    frp->fcipr_state != PORT_DEVICE_LOGGED_IN) ||
	    (frp && frp->fcipr_pd == NULL)) {
		/*
		 * No entry for the destination port in our routing
		 * table too. First query the transport to see if it
		 * already has structures for the destination port in
		 * its hash tables. This must be done for all topologies
		 * since we could have retired entries in the hash tables
		 * which may have to be re-added without a statechange
		 * callback happening. Its better to try and get an entry
		 * for the destination port rather than simply failing a
		 * request though it may be an overkill in private loop
		 * topologies.
		 * If a entry for the remote port exists in the transport's
		 * hash tables, we are fine and can add the entry to our
		 * routing and dest hash lists, Else for fabric configs we
		 * query the nameserver if one exists or issue FARP ELS.
		 */

		/*
		 * We need to do a PortName based Nameserver
		 * query operation. So get the right PortWWN
		 * for the adapter.
		 */
		bcopy(pwwn, &twwn, sizeof (la_wwn_t));

		/*
		 * Try IEEE Name (Format 1) first, this is the default and
		 * Emulex uses this format.
		 */
		pd = fc_ulp_get_remote_port(fport->fcipp_handle,
					    &twwn, &rval, 1);

		if (rval != FC_SUCCESS) {
			/*
			 * If IEEE Name (Format 1) query failed, try IEEE
			 * Extended Name (Format 2) which Qlogic uses.
			 * And try port 1 on Qlogic FC-HBA first.
			 * Note: On x86, we need to byte swap the 32-bit
			 * word first, after the modification, swap it back.
			 */
			*twwnp = BE_32(*twwnp);
			twwn.w.nport_id = QLC_PORT_1_ID_BITS;
			twwn.w.naa_id = QLC_PORT_NAA;
			*twwnp = BE_32(*twwnp);
			pd = fc_ulp_get_remote_port(fport->fcipp_handle,
						    &twwn, &rval, 1);
		}

		if (rval != FC_SUCCESS) {
			/* If still failed, try port 2 on Qlogic FC-HBA. */
			*twwnp = BE_32(*twwnp);
			twwn.w.nport_id = QLC_PORT_2_ID_BITS;
			*twwnp = BE_32(*twwnp);
			pd = fc_ulp_get_remote_port(fport->fcipp_handle,
						    &twwn, &rval, 1);
		}

		if (rval == FC_SUCCESS) {
			fc_portmap_t	map;
			/*
			 * Add the newly found destination structure
			 * to our routing table. Create a map with
			 * the device we found. We could ask the
			 * transport to give us the list of all
			 * devices connected to our port but we
			 * probably don't need to know all the devices
			 * so let us just constuct a list with only
			 * one device instead.
			 */

			fc_ulp_copy_portmap(&map, pd);
			fcip_rt_update(fptr, &map, 1);

			mutex_enter(&fptr->fcip_rt_mutex);
			frp = fcip_lookup_rtable(fptr, pwwn,
			    FCIP_COMPARE_NWWN);
			mutex_exit(&fptr->fcip_rt_mutex);

			fdestp = fcip_add_dest(fptr, frp);
		} else if (fcip_farp_supported &&
			(FC_TOP_EXTERNAL(fport->fcipp_topology) ||
			(fport->fcipp_topology == FC_TOP_PT_PT))) {
			/*
			 * The Name server request failed so
			 * issue an FARP
			 */
			fdestp = fcip_do_farp(fptr, pwwn, NULL,
				0, 0);
		} else {
		    fdestp = NULL;
		}
	} else if (frp && frp->fcipr_state == PORT_DEVICE_LOGGED_IN) {
		/*
		 * Prepare a dest structure to return to caller
		 */
		fdestp = fcip_add_dest(fptr, frp);
		FCIP_DEBUG(FCIP_DEBUG_DOWNSTREAM,
		    (CE_NOTE, "in fcip get dest non fabric"));
	}
	return (fdestp);
}


/*
 * Endian clean WWN compare.
 * Returns 0 if they compare OK, else return non zero value.
 * flag can be bitwise OR of FCIP_COMPARE_NWWN, FCIP_COMPARE_PWWN,
 * FCIP_COMPARE_BROADCAST.
 */
static int
fcip_wwn_compare(la_wwn_t *wwn1, la_wwn_t *wwn2, int flag)
{
	int rval = 0;
	if ((wwn1->raw_wwn[2] != wwn2->raw_wwn[2]) ||
	    (wwn1->raw_wwn[3] != wwn2->raw_wwn[3]) ||
	    (wwn1->raw_wwn[4] != wwn2->raw_wwn[4]) ||
	    (wwn1->raw_wwn[5] != wwn2->raw_wwn[5]) ||
	    (wwn1->raw_wwn[6] != wwn2->raw_wwn[6]) ||
	    (wwn1->raw_wwn[7] != wwn2->raw_wwn[7])) {
		rval = 1;
	} else if ((flag == FCIP_COMPARE_PWWN) &&
	    (((wwn1->raw_wwn[0] & 0xf0) != (wwn2->raw_wwn[0] & 0xf0)) ||
	    (wwn1->raw_wwn[1] != wwn2->raw_wwn[1]))) {
		rval = 1;
	}
	return (rval);
}


/*
 * Add an entry for a remote port in the dest hash table. Dest hash table
 * has entries for ports in the routing hash table with which we decide
 * to establish IP communication with. The no. of entries in the dest hash
 * table must always be less than or equal to the entries in the routing
 * hash table. Every entry in the dest hash table ofcourse must have a
 * corresponding entry in the routing hash table
 */
static struct fcip_dest *
fcip_add_dest(struct fcip *fptr, struct fcip_routing_table *frp)
{
	struct fcip_dest *fdestp = NULL;
	la_wwn_t	*pwwn;
	int hash_bucket;
	struct fcip_dest *fdest_new;

	if (frp == NULL) {
		return (fdestp);
	}

	pwwn = &frp->fcipr_pwwn;
	mutex_enter(&fptr->fcip_dest_mutex);
	hash_bucket = FCIP_DEST_HASH(pwwn->raw_wwn);
	FCIP_DEBUG(FCIP_DEBUG_DOWNSTREAM,
	    (CE_NOTE, "add dest hash_bucket: 0x%x", hash_bucket));

	ASSERT(hash_bucket < FCIP_DEST_HASH_ELEMS);

	fdestp = fptr->fcip_dest[hash_bucket];
	while (fdestp != NULL) {
		mutex_enter(&fdestp->fcipd_mutex);
		if (fdestp->fcipd_rtable) {
			if (fcip_wwn_compare(pwwn, &fdestp->fcipd_pwwn,
			    FCIP_COMPARE_PWWN) == 0) {
				mutex_exit(&fdestp->fcipd_mutex);
				mutex_exit(&fptr->fcip_dest_mutex);
				return (fdestp);
			}
		}
		mutex_exit(&fdestp->fcipd_mutex);
		fdestp = fdestp->fcipd_next;
	}

	ASSERT(fdestp == NULL);

	fdest_new = (struct fcip_dest *)
			kmem_zalloc(sizeof (struct fcip_dest), KM_SLEEP);

	mutex_init(&fdest_new->fcipd_mutex, NULL, MUTEX_DRIVER, NULL);
	fdest_new->fcipd_next = fptr->fcip_dest[hash_bucket];
	fdest_new->fcipd_refcnt = 0;
	fdest_new->fcipd_rtable = frp;
	fdest_new->fcipd_ncmds = 0;
	fptr->fcip_dest[hash_bucket] = fdest_new;
	fdest_new->fcipd_flags = FCIP_PORT_NOTLOGGED;

	mutex_exit(&fptr->fcip_dest_mutex);
	return (fdest_new);
}

/*
 * Cleanup the dest hash table and remove all entries
 */
static void
fcip_cleanup_dest(struct fcip *fptr)
{
	struct fcip_dest *fdestp = NULL;
	struct fcip_dest *fdest_delp = NULL;
	int i;

	mutex_enter(&fptr->fcip_dest_mutex);

	for (i = 0; i < FCIP_DEST_HASH_ELEMS; i++) {
		fdestp = fptr->fcip_dest[i];
		while (fdestp != NULL) {
			mutex_destroy(&fdestp->fcipd_mutex);
			fdest_delp = fdestp;
			fdestp = fdestp->fcipd_next;
			kmem_free(fdest_delp, sizeof (struct fcip_dest));
			fptr->fcip_dest[i] = NULL;
		}
	}
	mutex_exit(&fptr->fcip_dest_mutex);
}


/*
 * Send FARP requests for Fabric ports when we don't have the port
 * we wish to talk to in our routing hash table. FARP is specially required
 * to talk to FC switches for inband switch management. Most FC switches
 * today have a switch FC IP address for IP over FC inband switch management
 * but the WWN and Port_ID for this traffic is not available through the
 * Nameservers since the switch themeselves are transparent.
 */
/* ARGSUSED */
static struct fcip_dest *
fcip_do_farp(struct fcip *fptr, la_wwn_t *pwwn, char *ip_addr,
    size_t ip_addr_len, int flags)
{
	fcip_pkt_t		*fcip_pkt;
	fc_packet_t		*fc_pkt;
	fcip_port_info_t	*fport = fptr->fcip_port_info;
	la_els_farp_t		farp_cmd;
	la_els_farp_t		*fcmd;
	struct fcip_dest	*fdestp = NULL;
	int			rval;
	clock_t			farp_lbolt;
	la_wwn_t		broadcast_wwn;
	struct fcip_dest	*bdestp;
	struct fcip_routing_table 	*frp;

	bdestp = fcip_get_dest(fptr, &broadcast_wwn);

	if (bdestp == NULL) {
		return (fdestp);
	}

	fcip_pkt = fcip_ipkt_alloc(fptr, sizeof (la_els_farp_t),
	    sizeof (la_els_farp_t), bdestp->fcipd_pd, KM_SLEEP);

	if (fcip_pkt == NULL) {
		return (fdestp);
	}

	fc_pkt = FCIP_PKT_TO_FC_PKT(fcip_pkt);
	ether_to_wwn(&fcip_arpbroadcast_addr, &broadcast_wwn);

	mutex_enter(&bdestp->fcipd_mutex);
	if (bdestp->fcipd_rtable == NULL) {
		mutex_exit(&bdestp->fcipd_mutex);
		fcip_ipkt_free(fcip_pkt);
		return (fdestp);
	}

	fcip_pkt->fcip_pkt_dest = bdestp;
	fc_pkt->pkt_fca_device = bdestp->fcipd_fca_dev;

	bdestp->fcipd_ncmds++;
	mutex_exit(&bdestp->fcipd_mutex);

	fcip_init_broadcast_pkt(fcip_pkt, NULL, 1);
	fcip_pkt->fcip_pkt_flags |= FCIP_PKT_IN_LIST;

	/*
	 * Now initialize the FARP payload itself
	 */
	fcmd = &farp_cmd;
	fcmd->ls_code.ls_code = LA_ELS_FARP_REQ;
	fcmd->ls_code.mbz = 0;
	/*
	 * for now just match the Port WWN since the other match addr
	 * code points are optional. We can explore matching the IP address
	 * if needed
	 */
	if (ip_addr) {
		fcmd->match_addr = FARP_MATCH_WW_PN_IPv4;
	} else {
		fcmd->match_addr = FARP_MATCH_WW_PN;
	}

	/*
	 * Request the responder port to log into us - that way
	 * the Transport is aware of the remote port when we create
	 * an entry for it in our tables
	 */
	fcmd->resp_flags = FARP_INIT_REPLY | FARP_INIT_P_LOGI;
	fcmd->req_id = fport->fcipp_sid;
	fcmd->dest_id.port_id = fc_pkt->pkt_cmd_fhdr.d_id;
	bcopy(&fport->fcipp_pwwn, &fcmd->req_pwwn, sizeof (la_wwn_t));
	bcopy(&fport->fcipp_nwwn, &fcmd->req_nwwn, sizeof (la_wwn_t));
	bcopy(pwwn, &fcmd->resp_pwwn, sizeof (la_wwn_t));
	/*
	 * copy in source IP address if we get to know it
	 */
	if (ip_addr) {
		bcopy(ip_addr, fcmd->resp_ip, ip_addr_len);
	}

	fc_pkt->pkt_cmdlen = sizeof (la_els_farp_t);
	fc_pkt->pkt_rsplen = sizeof (la_els_farp_t);
	fc_pkt->pkt_tran_type = FC_PKT_EXCHANGE;
	fc_pkt->pkt_ulp_private = (opaque_t)fcip_pkt;

	/*
	 * Endian safe copy
	 */
	FCIP_CP_OUT(fcmd, fc_pkt->pkt_cmd, fc_pkt->pkt_cmd_acc,
	    sizeof (la_els_farp_t));

	/*
	 * send the packet in polled mode.
	 */
	rval = fc_ulp_issue_els(fport->fcipp_handle, fc_pkt);
	if (rval != FC_SUCCESS) {
		FCIP_DEBUG(FCIP_DEBUG_DOWNSTREAM, (CE_WARN,
		    "fcip_transport of farp pkt failed 0x%x", rval));
		fcip_pkt->fcip_pkt_flags &= ~FCIP_PKT_IN_LIST;
		fcip_ipkt_free(fcip_pkt);

		mutex_enter(&bdestp->fcipd_mutex);
		bdestp->fcipd_ncmds--;
		mutex_exit(&bdestp->fcipd_mutex);

		return (fdestp);
	}

	farp_lbolt = ddi_get_lbolt();
	farp_lbolt += drv_usectohz(FCIP_FARP_TIMEOUT);

	mutex_enter(&fptr->fcip_mutex);
	fptr->fcip_farp_rsp_flag = 0;
	while (!fptr->fcip_farp_rsp_flag) {
		if (cv_timedwait(&fptr->fcip_farp_cv, &fptr->fcip_mutex,
		    farp_lbolt) == -1) {
			/*
			 * No FARP response from any destination port
			 * so bail out.
			 */
			fptr->fcip_farp_rsp_flag = 1;
		} else {
			/*
			 * We received a FARP response - check to see if the
			 * response was in reply to our FARP request.
			 */

			mutex_enter(&fptr->fcip_rt_mutex);
			frp = fcip_lookup_rtable(fptr, pwwn, FCIP_COMPARE_NWWN);
			mutex_exit(&fptr->fcip_rt_mutex);

			if ((frp != NULL) &&
			    !FCIP_RTE_UNAVAIL(frp->fcipr_state)) {
				fdestp = fcip_get_dest(fptr, pwwn);
			} else {
				/*
				 * Not our FARP response so go back and wait
				 * again till FARP_TIMEOUT expires
				 */
				fptr->fcip_farp_rsp_flag = 0;
			}
		}
	}
	mutex_exit(&fptr->fcip_mutex);

	fcip_pkt->fcip_pkt_flags |= FCIP_PKT_IN_LIST;
	fcip_ipkt_free(fcip_pkt);
	mutex_enter(&bdestp->fcipd_mutex);
	bdestp->fcipd_ncmds--;
	mutex_exit(&bdestp->fcipd_mutex);
	return (fdestp);
}



/*
 * Helper routine to PLOGI to a remote port we wish to talk to.
 * This may not be required since the port driver does logins anyway,
 * but this can be required in fabric cases since FARP requests/responses
 * don't require you to be logged in?
 */

/* ARGSUSED */
static int
fcip_do_plogi(struct fcip *fptr, struct fcip_routing_table *frp)
{
	fcip_pkt_t		*fcip_pkt;
	fc_packet_t		*fc_pkt;
	fcip_port_info_t	*fport = fptr->fcip_port_info;
	la_els_logi_t		logi;
	int			rval;
	fc_frame_hdr_t		*fr_hdr;

	/*
	 * Don't bother to login for broadcast RTE entries
	 */
	if ((frp->fcipr_d_id.port_id == 0x0) ||
	    (frp->fcipr_d_id.port_id == 0xffffff)) {
		return (FC_FAILURE);
	}

	/*
	 * We shouldn't pound in too many logins here
	 *
	 */
	if (frp->fcipr_state == FCIP_RT_LOGIN_PROGRESS ||
	    frp->fcipr_state == PORT_DEVICE_LOGGED_IN) {
		return (FC_SUCCESS);
	}

	fcip_pkt = fcip_ipkt_alloc(fptr, sizeof (la_els_logi_t),
	    sizeof (la_els_logi_t), frp->fcipr_pd, KM_SLEEP);

	if (fcip_pkt == NULL) {
		return (FC_FAILURE);
	}

	/*
	 * Update back pointer for login state update
	 */
	fcip_pkt->fcip_pkt_frp = frp;
	frp->fcipr_state = FCIP_RT_LOGIN_PROGRESS;

	fc_pkt = FCIP_PKT_TO_FC_PKT(fcip_pkt);

	/*
	 * Initialize frame header for ELS
	 */
	fr_hdr = &fc_pkt->pkt_cmd_fhdr;
	fr_hdr->r_ctl = R_CTL_ELS_REQ;
	fr_hdr->type = FC_TYPE_EXTENDED_LS;
	fr_hdr->f_ctl = F_CTL_SEQ_INITIATIVE | F_CTL_FIRST_SEQ;
	fr_hdr->df_ctl = 0;
	fr_hdr->s_id = fport->fcipp_sid.port_id;
	fr_hdr->d_id = frp->fcipr_d_id.port_id;
	fr_hdr->seq_cnt = 0;
	fr_hdr->ox_id = 0xffff;
	fr_hdr->rx_id = 0xffff;
	fr_hdr->ro = 0;

	fc_pkt->pkt_rsplen = sizeof (la_els_logi_t);
	fc_pkt->pkt_comp = fcip_ipkt_callback;
	fc_pkt->pkt_tran_type = FC_PKT_EXCHANGE;
	fc_pkt->pkt_timeout = 10;	/* 10 seconds */
	fcip_pkt->fcip_pkt_ttl = fptr->fcip_timeout_ticks + fc_pkt->pkt_timeout;
	fc_pkt->pkt_ulp_private = (opaque_t)fcip_pkt;

	/*
	 * Everybody does class 3, so let's just set it.  If the transport
	 * knows better, it will deal with the class appropriately.
	 */

	fc_pkt->pkt_tran_flags = FC_TRAN_INTR | FC_TRAN_CLASS3;

	/*
	 * we need only fill in the ls_code and the cmd frame header
	 */
	bzero((void *)&logi, sizeof (la_els_logi_t));
	logi.ls_code.ls_code = LA_ELS_PLOGI;
	logi.ls_code.mbz = 0;

	FCIP_CP_OUT((uint8_t *)&logi, fc_pkt->pkt_cmd, fc_pkt->pkt_cmd_acc,
	    sizeof (la_els_logi_t));

	rval = fc_ulp_login(fport->fcipp_handle, &fc_pkt, 1);
	if (rval != FC_SUCCESS) {
		cmn_err(CE_WARN,
		    "!fc_ulp_login failed for d_id: 0x%x, rval: 0x%x",
		    frp->fcipr_d_id.port_id, rval);
		fcip_ipkt_free(fcip_pkt);
	}
	return (rval);
}

/*
 * The packet callback routine - called from the transport/FCA after
 * it is done DMA'ing/sending out the packet contents on the wire so
 * that the alloc'ed packet can be freed
 */
static void
fcip_ipkt_callback(fc_packet_t *fc_pkt)
{
	ls_code_t			logi_req;
	ls_code_t			logi_resp;
	fcip_pkt_t			*fcip_pkt;
	fc_frame_hdr_t			*fr_hdr;
	struct fcip 			*fptr;
	fcip_port_info_t		*fport;
	struct fcip_routing_table	*frp;

	fr_hdr = &fc_pkt->pkt_cmd_fhdr;

	FCIP_CP_IN(fc_pkt->pkt_resp, (uint8_t *)&logi_resp,
	    fc_pkt->pkt_resp_acc, sizeof (logi_resp));

	FCIP_CP_IN(fc_pkt->pkt_cmd, (uint8_t *)&logi_req, fc_pkt->pkt_cmd_acc,
	    sizeof (logi_req));

	fcip_pkt = (fcip_pkt_t *)fc_pkt->pkt_ulp_private;
	frp = fcip_pkt->fcip_pkt_frp;
	fptr = fcip_pkt->fcip_pkt_fptr;
	fport = fptr->fcip_port_info;

	ASSERT(logi_req.ls_code == LA_ELS_PLOGI);

	if (fc_pkt->pkt_state != FC_PKT_SUCCESS ||
	    logi_resp.ls_code != LA_ELS_ACC) {
		/* EMPTY */

		FCIP_DEBUG(FCIP_DEBUG_DOWNSTREAM, (CE_WARN,
		    "opcode : 0x%x to d_id: 0x%x failed",
		    logi_req.ls_code, fr_hdr->d_id));

		mutex_enter(&fptr->fcip_rt_mutex);
		frp->fcipr_state = PORT_DEVICE_INVALID;
		frp->fcipr_invalid_timeout = fptr->fcip_timeout_ticks +
		    (FCIP_RTE_TIMEOUT / 2);
		mutex_exit(&fptr->fcip_rt_mutex);
	} else {
		fc_portid_t	d_id;

		d_id.port_id = fr_hdr->d_id;
		d_id.priv_lilp_posit = 0;

		/*
		 * Update PLOGI results; FCA Handle, and Port device handles
		 */
		mutex_enter(&fptr->fcip_rt_mutex);
		frp->fcipr_pd = fc_pkt->pkt_pd;
		frp->fcipr_fca_dev =
		    fc_ulp_get_fca_device(fport->fcipp_handle, d_id);
		frp->fcipr_state = PORT_DEVICE_LOGGED_IN;
		mutex_exit(&fptr->fcip_rt_mutex);
	}

	fcip_ipkt_free(fcip_pkt);
}


/*
 * pkt_alloc routine for outbound IP datagrams. The cache constructor
 * Only initializes the pkt_cmd_dma (which is where the outbound datagram
 * is stuffed) since we don't expect response
 */
static fcip_pkt_t *
fcip_pkt_alloc(struct fcip *fptr, mblk_t *bp, int flags, int datalen)
{
	fcip_pkt_t 	*fcip_pkt;
	fc_packet_t	*fc_pkt;
	ddi_dma_cookie_t	pkt_cookie;
	ddi_dma_cookie_t	*cp;
	uint32_t		cnt;
	fcip_port_info_t	*fport = fptr->fcip_port_info;

	fcip_pkt = kmem_cache_alloc(fptr->fcip_xmit_cache, flags);
	if (fcip_pkt == NULL) {
		FCIP_DEBUG(FCIP_DEBUG_DOWNSTREAM, (CE_WARN,
		    "fcip_pkt_alloc: kmem_cache_alloc failed"));
		return (NULL);
	}

	fc_pkt = FCIP_PKT_TO_FC_PKT(fcip_pkt);
	fcip_pkt->fcip_pkt_fcpktp = fc_pkt;
	fc_pkt->pkt_tran_flags = 0;
	fcip_pkt->fcip_pkt_dma_flags = 0;

	/*
	 * the cache constructor has allocated the dma handle
	 */
	fc_pkt->pkt_cmd = (caddr_t)bp->b_rptr;
	if (ddi_dma_addr_bind_handle(fc_pkt->pkt_cmd_dma, NULL,
	    (caddr_t)bp->b_rptr, datalen, DDI_DMA_WRITE | DDI_DMA_CONSISTENT,
	    DDI_DMA_DONTWAIT, NULL, &pkt_cookie,
	    &fc_pkt->pkt_cmd_cookie_cnt) != DDI_DMA_MAPPED) {
			goto fail;
	}

	fcip_pkt->fcip_pkt_dma_flags |= FCIP_CMD_DMA_BOUND;

	if (fc_pkt->pkt_cmd_cookie_cnt >
	    fport->fcipp_cmd_dma_attr.dma_attr_sgllen) {
		goto fail;
	}

	ASSERT(fc_pkt->pkt_cmd_cookie_cnt != 0);

	cp = fc_pkt->pkt_cmd_cookie = (ddi_dma_cookie_t *)kmem_alloc(
	    fc_pkt->pkt_cmd_cookie_cnt * sizeof (pkt_cookie),
	    KM_NOSLEEP);

	if (cp == NULL) {
		goto fail;
	}

	*cp = pkt_cookie;
	cp++;
	for (cnt = 1; cnt < fc_pkt->pkt_cmd_cookie_cnt; cnt++, cp++) {
		ddi_dma_nextcookie(fc_pkt->pkt_cmd_dma, &pkt_cookie);
		*cp = pkt_cookie;
	}

	fc_pkt->pkt_cmdlen = datalen;

	fcip_pkt->fcip_pkt_mp = NULL;
	fcip_pkt->fcip_pkt_wq = NULL;
	fcip_pkt->fcip_pkt_dest = NULL;
	fcip_pkt->fcip_pkt_next = NULL;
	fcip_pkt->fcip_pkt_prev = NULL;
	fcip_pkt->fcip_pkt_state = 0;
	fcip_pkt->fcip_pkt_reason = 0;
	fcip_pkt->fcip_pkt_flags = 0;
	fcip_pkt->fcip_pkt_frp = NULL;

	return (fcip_pkt);
fail:
	if (fcip_pkt) {
		fcip_pkt_free(fcip_pkt, 0);
	}
	return ((fcip_pkt_t *)0);
}

/*
 * Free a packet and all its associated resources
 */
static void
fcip_pkt_free(struct fcip_pkt *fcip_pkt, int free_mblk)
{
	fc_packet_t	*fc_pkt = FCIP_PKT_TO_FC_PKT(fcip_pkt);
	struct fcip *fptr = fcip_pkt->fcip_pkt_fptr;

	if (fc_pkt->pkt_cmd_cookie != NULL) {
		kmem_free(fc_pkt->pkt_cmd_cookie, fc_pkt->pkt_cmd_cookie_cnt *
		    sizeof (ddi_dma_cookie_t));
		fc_pkt->pkt_cmd_cookie = NULL;
	}

	fcip_free_pkt_dma(fcip_pkt);
	if (free_mblk && fcip_pkt->fcip_pkt_mp) {
		freemsg(fcip_pkt->fcip_pkt_mp);
		fcip_pkt->fcip_pkt_mp = NULL;
	}

	(void) fc_ulp_uninit_packet(fptr->fcip_port_info->fcipp_handle, fc_pkt);

	kmem_cache_free(fptr->fcip_xmit_cache, (void *)fcip_pkt);
}

/*
 * Allocate a Packet for internal driver use. This is for requests
 * that originate from within the driver
 */
static fcip_pkt_t *
fcip_ipkt_alloc(struct fcip *fptr, int cmdlen, int resplen,
    opaque_t pd, int flags)
{
	fcip_pkt_t 		*fcip_pkt;
	fc_packet_t		*fc_pkt;
	int			(*cb)(caddr_t);
	fcip_port_info_t	*fport = fptr->fcip_port_info;
	size_t			real_len;
	uint_t			held_here = 0;
	ddi_dma_cookie_t	pkt_cookie;
	ddi_dma_cookie_t	*cp;
	uint32_t		cnt;

	cb = (flags == KM_SLEEP) ? DDI_DMA_SLEEP : DDI_DMA_DONTWAIT;

	fcip_pkt = kmem_zalloc((sizeof (fcip_pkt_t) +
	    fport->fcipp_fca_pkt_size), flags);

	if (fcip_pkt == NULL) {
		FCIP_DEBUG(FCIP_DEBUG_DOWNSTREAM,
		    (CE_WARN, "pkt alloc of ineternal pkt failed"));
		goto fail;
	}

	fcip_pkt->fcip_pkt_flags = FCIP_PKT_INTERNAL;
	fcip_pkt->fcip_pkt_fptr = fptr;
	fc_pkt = FCIP_PKT_TO_FC_PKT(fcip_pkt);
	fcip_pkt->fcip_pkt_fcpktp = fc_pkt;
	fc_pkt->pkt_tran_flags = 0;
	fc_pkt->pkt_cmdlen = 0;
	fc_pkt->pkt_rsplen = 0;
	fc_pkt->pkt_datalen = 0;
	fc_pkt->pkt_fca_private = (opaque_t)((caddr_t)fcip_pkt +
	    sizeof (fcip_pkt_t));
	fc_pkt->pkt_ulp_private = (opaque_t)fcip_pkt;

	if (cmdlen) {
		if (ddi_dma_alloc_handle(fptr->fcip_dip,
		    &fport->fcipp_cmd_dma_attr, cb, NULL,
		    &fc_pkt->pkt_cmd_dma) != DDI_SUCCESS) {
			goto fail;
		}

		if (ddi_dma_mem_alloc(fc_pkt->pkt_cmd_dma, cmdlen,
		    &fport->fcipp_fca_acc_attr, DDI_DMA_CONSISTENT,
		    cb, NULL, (caddr_t *)&fc_pkt->pkt_cmd,
		    &real_len, &fc_pkt->pkt_cmd_acc) != DDI_SUCCESS) {
			goto fail;
		}

		fcip_pkt->fcip_pkt_dma_flags |= FCIP_CMD_DMA_MEM;
		fc_pkt->pkt_cmdlen = cmdlen;

		if (real_len < cmdlen) {
			goto fail;
		}

		if (ddi_dma_addr_bind_handle(fc_pkt->pkt_cmd_dma, NULL,
		    (caddr_t)fc_pkt->pkt_cmd, real_len,
		    DDI_DMA_WRITE | DDI_DMA_CONSISTENT, cb, NULL,
		    &pkt_cookie, &fc_pkt->pkt_cmd_cookie_cnt) !=
		    DDI_DMA_MAPPED) {
			goto fail;
		}

		fcip_pkt->fcip_pkt_dma_flags |= FCIP_CMD_DMA_BOUND;

		if (fc_pkt->pkt_cmd_cookie_cnt >
		    fport->fcipp_cmd_dma_attr.dma_attr_sgllen) {
			goto fail;
		}

		ASSERT(fc_pkt->pkt_cmd_cookie_cnt != 0);

		cp = fc_pkt->pkt_cmd_cookie = (ddi_dma_cookie_t *)kmem_alloc(
		    fc_pkt->pkt_cmd_cookie_cnt * sizeof (pkt_cookie),
		    KM_NOSLEEP);

		if (cp == NULL) {
			goto fail;
		}

		*cp = pkt_cookie;
		cp++;
		for (cnt = 1; cnt < fc_pkt->pkt_cmd_cookie_cnt; cnt++, cp++) {
			ddi_dma_nextcookie(fc_pkt->pkt_cmd_dma, &pkt_cookie);
			*cp = pkt_cookie;
		}
	}

	if (resplen) {
		if (ddi_dma_alloc_handle(fptr->fcip_dip,
		    &fport->fcipp_resp_dma_attr, cb, NULL,
		    &fc_pkt->pkt_resp_dma) != DDI_SUCCESS) {
			goto fail;
		}

		if (ddi_dma_mem_alloc(fc_pkt->pkt_resp_dma, resplen,
		    &fport->fcipp_fca_acc_attr, DDI_DMA_CONSISTENT,
		    cb, NULL, (caddr_t *)&fc_pkt->pkt_resp,
		    &real_len, &fc_pkt->pkt_resp_acc) != DDI_SUCCESS) {
			goto fail;
		}

		fcip_pkt->fcip_pkt_dma_flags |= FCIP_RESP_DMA_MEM;

		if (real_len < resplen) {
			goto fail;
		}

		if (ddi_dma_addr_bind_handle(fc_pkt->pkt_resp_dma, NULL,
		    (caddr_t)fc_pkt->pkt_resp, real_len,
		    DDI_DMA_WRITE | DDI_DMA_CONSISTENT, cb, NULL,
		    &pkt_cookie, &fc_pkt->pkt_resp_cookie_cnt) !=
		    DDI_DMA_MAPPED) {
			goto fail;
		}

		fcip_pkt->fcip_pkt_dma_flags |= FCIP_RESP_DMA_BOUND;
		fc_pkt->pkt_rsplen = resplen;

		if (fc_pkt->pkt_resp_cookie_cnt >
		    fport->fcipp_resp_dma_attr.dma_attr_sgllen) {
			goto fail;
		}

		ASSERT(fc_pkt->pkt_resp_cookie_cnt != 0);

		cp = fc_pkt->pkt_resp_cookie = (ddi_dma_cookie_t *)kmem_alloc(
		    fc_pkt->pkt_resp_cookie_cnt * sizeof (pkt_cookie),
		    KM_NOSLEEP);

		if (cp == NULL) {
			goto fail;
		}

		*cp = pkt_cookie;
		cp++;
		for (cnt = 1; cnt < fc_pkt->pkt_resp_cookie_cnt; cnt++, cp++) {
			ddi_dma_nextcookie(fc_pkt->pkt_resp_dma, &pkt_cookie);
			*cp = pkt_cookie;
		}
	}

	/*
	 * Initialize pkt_pd prior to calling fc_ulp_init_packet
	 */

	fc_pkt->pkt_pd = pd;

	/*
	 * Ask the FCA to bless the internal packet
	 */
	if (fc_ulp_init_packet((opaque_t)fport->fcipp_handle,
	    fc_pkt, flags) != FC_SUCCESS) {
		goto fail;
	}

	/*
	 * Keep track of # of ipkts alloc-ed
	 * This function can get called with mutex either held or not. So, we'll
	 * grab mutex if it is not already held by this thread.
	 * This has to be cleaned up someday.
	 */
	if (!MUTEX_HELD(&fptr->fcip_mutex)) {
		held_here = 1;
		mutex_enter(&fptr->fcip_mutex);
	}

	fptr->fcip_num_ipkts_pending++;

	if (held_here)
		mutex_exit(&fptr->fcip_mutex);

	return (fcip_pkt);
fail:
	if (fcip_pkt) {
		fcip_ipkt_free(fcip_pkt);
	}

	return (NULL);
}

/*
 * free up an internal IP packet (like a FARP pkt etc)
 */
static void
fcip_ipkt_free(fcip_pkt_t *fcip_pkt)
{
	fc_packet_t		*fc_pkt;
	struct fcip		*fptr = fcip_pkt->fcip_pkt_fptr;
	fcip_port_info_t	*fport = fptr->fcip_port_info;

	ASSERT(fptr != NULL);
	ASSERT(!mutex_owned(&fptr->fcip_mutex));

	/* One less ipkt to wait for */
	mutex_enter(&fptr->fcip_mutex);
	if (fptr->fcip_num_ipkts_pending)	/* Safety check */
		fptr->fcip_num_ipkts_pending--;
	mutex_exit(&fptr->fcip_mutex);

	fc_pkt = FCIP_PKT_TO_FC_PKT(fcip_pkt);

	if (fc_pkt->pkt_cmd_cookie != NULL) {
		kmem_free(fc_pkt->pkt_cmd_cookie, fc_pkt->pkt_cmd_cookie_cnt *
		    sizeof (ddi_dma_cookie_t));
		fc_pkt->pkt_cmd_cookie = NULL;
	}

	if (fc_pkt->pkt_resp_cookie != NULL) {
		kmem_free(fc_pkt->pkt_resp_cookie, fc_pkt->pkt_resp_cookie_cnt *
		    sizeof (ddi_dma_cookie_t));
		fc_pkt->pkt_resp_cookie = NULL;
	}

	if (fc_ulp_uninit_packet(fport->fcipp_handle, fc_pkt) != FC_SUCCESS) {
		FCIP_DEBUG(FCIP_DEBUG_ELS, (CE_WARN,
		    "fc_ulp_uninit_pkt failed for internal fc pkt 0x%p",
		    (void *)fc_pkt));
	}
	fcip_free_pkt_dma(fcip_pkt);
	kmem_free(fcip_pkt, (sizeof (fcip_pkt_t) + fport->fcipp_fca_pkt_size));
}

/*
 * initialize a unicast request. This is a misnomer because even the
 * broadcast requests are initialized with this routine
 */
static void
fcip_init_unicast_pkt(fcip_pkt_t *fcip_pkt, fc_portid_t sid, fc_portid_t did,
    void (*comp) ())
{
	fc_packet_t		*fc_pkt;
	fc_frame_hdr_t		*fr_hdr;
	struct fcip		*fptr = fcip_pkt->fcip_pkt_fptr;

	fc_pkt = FCIP_PKT_TO_FC_PKT(fcip_pkt);
	fr_hdr = &fc_pkt->pkt_cmd_fhdr;

	fr_hdr->r_ctl = R_CTL_DEVICE_DATA | R_CTL_UNSOL_DATA;
	fr_hdr->s_id = sid.port_id;
	fr_hdr->d_id = did.port_id;
	fr_hdr->type = FC_TYPE_IS8802_SNAP;
	fr_hdr->f_ctl = F_CTL_FIRST_SEQ | F_CTL_LAST_SEQ;
	fr_hdr->df_ctl = DF_CTL_NET_HDR;
	fr_hdr->seq_cnt = 0;
	fr_hdr->ox_id = 0xffff;
	fr_hdr->rx_id = 0xffff;
	fr_hdr->ro = 0;
	/*
	 * reset all the length fields
	 */
	fc_pkt->pkt_rsplen = 0;
	fc_pkt->pkt_datalen = 0;
	fc_pkt->pkt_comp = comp;
	if (comp) {
		fc_pkt->pkt_tran_flags |= FC_TRAN_INTR;
	} else {
		fc_pkt->pkt_tran_flags |= FC_TRAN_NO_INTR;
	}
	fc_pkt->pkt_tran_type = FC_PKT_OUTBOUND | FC_PKT_IP_WRITE;
	fc_pkt->pkt_timeout = fcip_pkt_ttl_ticks;
	fcip_pkt->fcip_pkt_ttl = fptr->fcip_timeout_ticks + fc_pkt->pkt_timeout;
}


/*
 * Initialize a fcip_packet for broadcast data transfers
 */
static void
fcip_init_broadcast_pkt(fcip_pkt_t *fcip_pkt, void (*comp) (), int is_els)
{
	fc_packet_t		*fc_pkt;
	fc_frame_hdr_t		*fr_hdr;
	struct fcip		*fptr = fcip_pkt->fcip_pkt_fptr;
	fcip_port_info_t	*fport = fptr->fcip_port_info;
	uint32_t		sid;
	uint32_t		did;

	FCIP_TNF_PROBE_1((fcip_init_broadcast_pkt, "fcip io", /* CSTYLED */,
		tnf_string, msg, "enter"));
	fc_pkt = FCIP_PKT_TO_FC_PKT(fcip_pkt);
	fr_hdr = &fc_pkt->pkt_cmd_fhdr;
	sid = fport->fcipp_sid.port_id;

	if (is_els) {
		fr_hdr->r_ctl = R_CTL_ELS_REQ;
	} else {
		fr_hdr->r_ctl = R_CTL_DEVICE_DATA | R_CTL_UNSOL_DATA;
	}
	fr_hdr->s_id = sid;
	/*
	 * The destination broadcast address depends on the topology
	 * of the underlying port
	 */
	did = fptr->fcip_broadcast_did;
	/*
	 * mark pkt a broadcast pkt
	 */
	fc_pkt->pkt_tran_type = FC_PKT_BROADCAST;

	fr_hdr->d_id = did;
	fr_hdr->type = FC_TYPE_IS8802_SNAP;
	fr_hdr->f_ctl = F_CTL_FIRST_SEQ | F_CTL_LAST_SEQ | F_CTL_END_SEQ;
	fr_hdr->f_ctl &= ~(F_CTL_SEQ_INITIATIVE);
	fr_hdr->df_ctl = DF_CTL_NET_HDR;
	fr_hdr->seq_cnt = 0;
	fr_hdr->ox_id = 0xffff;
	fr_hdr->rx_id = 0xffff;
	fr_hdr->ro = 0;
	fc_pkt->pkt_comp = comp;

	if (comp) {
		fc_pkt->pkt_tran_flags |= FC_TRAN_INTR;
	} else {
		fc_pkt->pkt_tran_flags |= FC_TRAN_NO_INTR;
	}

	fc_pkt->pkt_tran_type = FC_PKT_BROADCAST;
	fc_pkt->pkt_timeout = fcip_pkt_ttl_ticks;
	fcip_pkt->fcip_pkt_ttl = fptr->fcip_timeout_ticks + fc_pkt->pkt_timeout;
}



/*
 * Free up all DMA resources associated with an allocated packet
 */
static void
fcip_free_pkt_dma(fcip_pkt_t *fcip_pkt)
{
	fc_packet_t	*fc_pkt;

	fc_pkt = FCIP_PKT_TO_FC_PKT(fcip_pkt);

	FCIP_DEBUG(FCIP_DEBUG_DOWNSTREAM,
	    (CE_NOTE, "in freepktdma : flags 0x%x",
	    fcip_pkt->fcip_pkt_dma_flags));

	if (fcip_pkt->fcip_pkt_dma_flags & FCIP_CMD_DMA_BOUND) {
		(void) ddi_dma_unbind_handle(fc_pkt->pkt_cmd_dma);
	}
	if (fcip_pkt->fcip_pkt_dma_flags & FCIP_CMD_DMA_MEM) {
		ddi_dma_mem_free(&fc_pkt->pkt_cmd_acc);
	}

	if (fcip_pkt->fcip_pkt_dma_flags & FCIP_RESP_DMA_BOUND) {
		(void) ddi_dma_unbind_handle(fc_pkt->pkt_resp_dma);
	}
	if (fcip_pkt->fcip_pkt_dma_flags & FCIP_RESP_DMA_MEM) {
		ddi_dma_mem_free(&fc_pkt->pkt_resp_acc);
	}
	/*
	 * for internal commands, we need to free up the dma handles too.
	 * This is done in the cache destructor for non internal cmds
	 */
	if (fcip_pkt->fcip_pkt_flags & FCIP_PKT_INTERNAL) {
		if (fc_pkt->pkt_cmd_dma) {
			ddi_dma_free_handle(&fc_pkt->pkt_cmd_dma);
		}
		if (fc_pkt->pkt_resp_dma) {
			ddi_dma_free_handle(&fc_pkt->pkt_resp_dma);
		}
	}
}


/*
 * helper routine to generate a string, given an ether addr
 */
static void
fcip_ether_to_str(struct ether_addr *e, caddr_t s)
{
	int i;

	for (i = 0; i < sizeof (struct ether_addr); i++, s += 2) {
		FCIP_DEBUG(FCIP_DEBUG_MISC,
		    (CE_CONT, "0x%02X:", e->ether_addr_octet[i]));
		(void) sprintf(s, "%02X", e->ether_addr_octet[i]);
	}

	*s = '\0';
}

/*
 * When a broadcast request comes from the upper streams modules, it
 * is ugly to look into every datagram to figure out if it is a broadcast
 * datagram or a unicast packet. Instead just add the broadcast entries
 * into our routing and dest tables and the standard hash table look ups
 * will find the entries. It is a lot cleaner this way. Also Solaris ifconfig
 * seems to be very ethernet specific and it requires broadcasts to the
 * ether broadcast addr of 0xffffffffff to succeed even though we specified
 * in the dl_info request that our broadcast MAC addr is 0x0000000000
 * (can't figure out why RFC2625 did this though). So add broadcast entries
 * for both MAC address
 */
static int
fcip_dest_add_broadcast_entry(struct fcip *fptr, int new_flag)
{
	fc_portmap_t 		map;
	struct fcip_routing_table *frp;
	uint32_t		did;
	la_wwn_t		broadcast_wwn;

	/*
	 * get port_id of destination for broadcast - this is topology
	 * dependent
	 */
	did = fptr->fcip_broadcast_did;

	ether_to_wwn(&fcip_arpbroadcast_addr, &broadcast_wwn);
	bcopy((void *)&broadcast_wwn, (void *)&map.map_pwwn, sizeof (la_wwn_t));
	bcopy((void *)&broadcast_wwn, (void *)&map.map_nwwn, sizeof (la_wwn_t));

	map.map_did.port_id = did;
	map.map_hard_addr.hard_addr = did;
	map.map_state = PORT_DEVICE_VALID;
	if (new_flag) {
		map.map_type = PORT_DEVICE_NEW;
	} else {
		map.map_type = PORT_DEVICE_CHANGED;
	}
	map.map_flags = 0;
	map.map_pd = NULL;
	bzero(&map.map_fc4_types, sizeof (map.map_fc4_types));
	fcip_rt_update(fptr, &map, 1);
	mutex_enter(&fptr->fcip_rt_mutex);
	frp = fcip_lookup_rtable(fptr, &broadcast_wwn, FCIP_COMPARE_NWWN);
	mutex_exit(&fptr->fcip_rt_mutex);
	if (frp == NULL) {
		return (FC_FAILURE);
	}
	(void) fcip_add_dest(fptr, frp);
	/*
	 * The Upper IP layers expect the traditional broadcast MAC addr
	 * of 0xff ff ff ff ff ff to work too if we want to plumb the fcip
	 * stream through the /etc/hostname.fcipXX file. Instead of checking
	 * each phys addr for a match with fcip's ARP header broadcast
	 * addr (0x00 00 00 00 00 00), its simply easier to add another
	 * broadcast entry for 0xff ff ff ff ff ff.
	 */
	ether_to_wwn(&fcipnhbroadcastaddr, &broadcast_wwn);
	bcopy((void *)&broadcast_wwn, (void *)&map.map_pwwn, sizeof (la_wwn_t));
	bcopy((void *)&broadcast_wwn, (void *)&map.map_nwwn, sizeof (la_wwn_t));
	fcip_rt_update(fptr, &map, 1);
	mutex_enter(&fptr->fcip_rt_mutex);
	frp = fcip_lookup_rtable(fptr, &broadcast_wwn, FCIP_COMPARE_NWWN);
	mutex_exit(&fptr->fcip_rt_mutex);
	if (frp == NULL) {
		return (FC_FAILURE);
	}
	(void) fcip_add_dest(fptr, frp);
	return (FC_SUCCESS);
}

/*
 * We need to obtain the D_ID of the broadcast port for transmitting all
 * our broadcast (and multicast) requests. The broadcast D_ID as we know
 * is dependent on the link topology
 */
static uint32_t
fcip_get_broadcast_did(struct fcip *fptr)
{
	fcip_port_info_t	*fport = fptr->fcip_port_info;
	uint32_t		did = 0;
	uint32_t		sid;

	FCIP_TNF_PROBE_2((fcip_get_broadcast_did, "fcip io", /* CSTYLED */,
		tnf_string, msg, "enter",
		tnf_opaque, fptr, fptr));

	sid = fport->fcipp_sid.port_id;

	switch (fport->fcipp_topology) {

	case FC_TOP_PT_PT: {
		fc_portmap_t	*port_map = NULL;
		uint32_t	listlen = 0;

		if (fc_ulp_getportmap(fport->fcipp_handle, &port_map,
		    &listlen, FC_ULP_PLOGI_DONTCARE) == FC_SUCCESS) {
			FCIP_DEBUG(FCIP_DEBUG_INIT, (CE_NOTE,
			    "fcip_gpmap: listlen :  0x%x", listlen));
			if (listlen == 1) {
				did = port_map->map_did.port_id;
			}
		}
		if (port_map) {
			kmem_free(port_map, listlen * sizeof (fc_portmap_t));
		}
		if (listlen != 1) {
			/* Dummy return value */
			return (0x00FFFFFF);
		}
		break;
	}

	case FC_TOP_NO_NS:
	/* FALLTHROUGH */
	case FC_TOP_FABRIC:
		/*
		 * The broadcast address is the same whether or not
		 * the switch/fabric contains a Name service.
		 */
		did = 0x00FFFFFF;
		break;

	case FC_TOP_PUBLIC_LOOP:
		/*
		 * The open replicate primitive must not be used. The
		 * broadcast sequence is simply sent to ALPA 0x00. The
		 * fabric controller then propagates the broadcast to all
		 * other ports. The fabric propagates the broadcast by
		 * using the OPNfr primitive.
		 */
		did = 0x00;
		break;

	case FC_TOP_PRIVATE_LOOP:
		/*
		 * The source port for broadcast in private loop mode
		 * must send an OPN(fr) signal forcing all ports in the
		 * loop to replicate the frames that they receive.
		 */
		did = 0x00FFFFFF;
		break;

	case FC_TOP_UNKNOWN:
	/* FALLTHROUGH */
	default:
		did = sid;
		FCIP_DEBUG(FCIP_DEBUG_INIT, (CE_WARN,
		    "fcip(0x%x):unknown topology in init_broadcast_pkt",
		    fptr->fcip_instance));
		break;
	}
	FCIP_TNF_PROBE_2((fcip_get_broadcast_did, "fcip io", /* CSTYLED */,
		tnf_string, msg, "return",
		tnf_opaque, did, did));

	return (did);
}


/*
 * fcip timeout performs 2 operations:
 * 1. timeout any packets sent to the FCA for which a callback hasn't
 *    happened. If you are wondering why we need a callback since all
 *    traffic in FCIP is unidirectional, hence all exchanges are unidirectional
 *    but wait, we can only free up the resources after we know the FCA has
 *    DMA'ed out the data. pretty obvious eh :)
 *
 * 2. Retire and routing table entries we marked up for retiring. This is
 *    to give the link a chance to recover instead of marking a port down
 *    when we have lost all communication with it after a link transition
 */
static void
fcip_timeout(void *arg)
{
	struct fcip 			*fptr = (struct fcip *)arg;
	int				i;
	fcip_pkt_t			*fcip_pkt;
	struct fcip_dest		*fdestp;
	int 				index;
	struct fcip_routing_table 	*frtp;
	int				dispatch_rte_removal = 0;

	mutex_enter(&fptr->fcip_mutex);

	fptr->fcip_flags |= FCIP_IN_TIMEOUT;
	fptr->fcip_timeout_ticks += fcip_tick_incr;

	if (fptr->fcip_flags & (FCIP_DETACHED | FCIP_DETACHING | \
	    FCIP_SUSPENDED | FCIP_POWER_DOWN)) {
		fptr->fcip_flags &= ~(FCIP_IN_TIMEOUT);
		mutex_exit(&fptr->fcip_mutex);
		return;
	}

	if (fptr->fcip_port_state == FCIP_PORT_OFFLINE) {
		if (fptr->fcip_timeout_ticks > fptr->fcip_mark_offline) {
			fptr->fcip_flags |= FCIP_LINK_DOWN;
		}
	}
	if (!fptr->fcip_flags & FCIP_RTE_REMOVING) {
		dispatch_rte_removal = 1;
	}
	mutex_exit(&fptr->fcip_mutex);

	/*
	 * Check if we have any Invalid routing table entries in our
	 * hashtable we have marked off for deferred removal. If any,
	 * we can spawn a taskq thread to do the cleanup for us. We
	 * need to avoid cleanup in the timeout thread since we may
	 * have to wait for outstanding commands to complete before
	 * we retire a routing table entry. Also dispatch the taskq
	 * thread only if we are already do not have a taskq thread
	 * dispatched.
	 */
	if (dispatch_rte_removal) {
		mutex_enter(&fptr->fcip_rt_mutex);
		for (index = 0; index < FCIP_RT_HASH_ELEMS; index++) {
			frtp = fptr->fcip_rtable[index];
			while (frtp) {
				if ((frtp->fcipr_state == FCIP_RT_INVALID) &&
				    (fptr->fcip_timeout_ticks >
				    frtp->fcipr_invalid_timeout)) {
					/*
					 * If we cannot schedule a task thread
					 * let us attempt again on the next
					 * tick rather than call
					 * fcip_rte_remove_deferred() from here
					 * directly since the routine can sleep.
					 */
					frtp->fcipr_state = FCIP_RT_RETIRED;

					mutex_enter(&fptr->fcip_mutex);
					fptr->fcip_flags |= FCIP_RTE_REMOVING;
					mutex_exit(&fptr->fcip_mutex);

					if (taskq_dispatch(fptr->fcip_tq,
					    fcip_rte_remove_deferred, fptr,
					    KM_NOSLEEP) == 0) {
						/*
						 * failed - so mark the entry
						 * as invalid again.
						 */
						frtp->fcipr_state =
						    FCIP_RT_INVALID;

						mutex_enter(&fptr->fcip_mutex);
						fptr->fcip_flags &=
						    ~FCIP_RTE_REMOVING;
						mutex_exit(&fptr->fcip_mutex);
					}
				}
				frtp = frtp->fcipr_next;
			}
		}
		mutex_exit(&fptr->fcip_rt_mutex);
	}

	mutex_enter(&fptr->fcip_dest_mutex);

	/*
	 * Now timeout any packets stuck with the transport/FCA for too long
	 */
	for (i = 0; i < FCIP_DEST_HASH_ELEMS; i++) {
		fdestp = fptr->fcip_dest[i];
		while (fdestp != NULL) {
			mutex_enter(&fdestp->fcipd_mutex);
			for (fcip_pkt = fdestp->fcipd_head; fcip_pkt != NULL;
			    fcip_pkt = fcip_pkt->fcip_pkt_next) {
				if (fcip_pkt->fcip_pkt_flags &
				    (FCIP_PKT_RETURNED | FCIP_PKT_IN_TIMEOUT |
				    FCIP_PKT_IN_ABORT)) {
					continue;
				}
				if (fptr->fcip_timeout_ticks >
				    fcip_pkt->fcip_pkt_ttl) {
					fcip_pkt->fcip_pkt_flags |=
					    FCIP_PKT_IN_TIMEOUT;

					mutex_exit(&fdestp->fcipd_mutex);
					if (taskq_dispatch(fptr->fcip_tq,
					    fcip_pkt_timeout, fcip_pkt,
					    KM_NOSLEEP) == 0) {
						/*
						 * timeout immediately
						 */
						fcip_pkt_timeout(fcip_pkt);
					}
					mutex_enter(&fdestp->fcipd_mutex);
					/*
					 * The linked list is altered because
					 * of one of the following reasons:
					 *	a. Timeout code dequeued a pkt
					 *	b. Pkt completion happened
					 *
					 * So restart the spin starting at
					 * the head again; This is a bit
					 * excessive, but okay since
					 * fcip_timeout_ticks isn't incremented
					 * for this spin, we will skip the
					 * not-to-be-timedout packets quickly
					 */
					fcip_pkt = fdestp->fcipd_head;
					if (fcip_pkt == NULL) {
						break;
					}
				}
			}
			mutex_exit(&fdestp->fcipd_mutex);
			fdestp = fdestp->fcipd_next;
		}
	}
	mutex_exit(&fptr->fcip_dest_mutex);

	/*
	 * reschedule the timeout thread
	 */
	mutex_enter(&fptr->fcip_mutex);

	fptr->fcip_timeout_id = timeout(fcip_timeout, fptr,
	    drv_usectohz(1000000));
	fptr->fcip_flags &= ~(FCIP_IN_TIMEOUT);
	mutex_exit(&fptr->fcip_mutex);
}


/*
 * This routine is either called from taskq or directly from fcip_timeout
 * does the actual job of aborting the packet
 */
static void
fcip_pkt_timeout(void *arg)
{
	fcip_pkt_t		*fcip_pkt = (fcip_pkt_t *)arg;
	struct fcip_dest	*fdestp;
	struct fcip		*fptr;
	fc_packet_t		*fc_pkt;
	fcip_port_info_t	*fport;
	int			rval;

	fdestp = fcip_pkt->fcip_pkt_dest;
	fptr = fcip_pkt->fcip_pkt_fptr;
	fport = fptr->fcip_port_info;
	fc_pkt = FCIP_PKT_TO_FC_PKT(fcip_pkt);

	/*
	 * try to abort the pkt
	 */
	fcip_pkt->fcip_pkt_flags |= FCIP_PKT_IN_ABORT;
	rval = fc_ulp_abort(fport->fcipp_handle, fc_pkt, KM_NOSLEEP);

	FCIP_DEBUG(FCIP_DEBUG_DOWNSTREAM,
	    (CE_NOTE, "fc_ulp_abort returns: 0x%x", rval));

	if (rval == FC_SUCCESS) {
		ASSERT(fdestp != NULL);

		/*
		 * dequeue the pkt from the dest structure pkt list
		 */
		fcip_pkt->fcip_pkt_flags &= ~FCIP_PKT_IN_ABORT;
		mutex_enter(&fdestp->fcipd_mutex);
		rval = fcip_fdestp_dequeue_pkt(fdestp, fcip_pkt);
		ASSERT(rval == 1);
		mutex_exit(&fdestp->fcipd_mutex);

		/*
		 * Now cleanup the pkt and free the mblk
		 */
		fcip_pkt_free(fcip_pkt, 1);
	} else {
		/*
		 * abort failed - just mark the pkt as done and
		 * wait for it to complete in fcip_pkt_callback since
		 * the pkt has already been xmitted by the FCA
		 */
		fcip_pkt->fcip_pkt_flags &= ~FCIP_PKT_IN_TIMEOUT;
		if (fcip_pkt->fcip_pkt_flags & FCIP_PKT_RETURNED) {
			fcip_pkt->fcip_pkt_flags &= ~FCIP_PKT_IN_ABORT;
			mutex_enter(&fdestp->fcipd_mutex);
			rval = fcip_fdestp_dequeue_pkt(fdestp, fcip_pkt);
			ASSERT(rval == 1);
			mutex_exit(&fdestp->fcipd_mutex);

			fcip_pkt_free(fcip_pkt, 1);
		}
		return;
	}
}


/*
 * Remove  a routing table entry marked for deferred removal. This routine
 * unlike fcip_pkt_timeout, is always called from a taskq context
 */
static void
fcip_rte_remove_deferred(void *arg)
{
	struct fcip 			*fptr = (struct fcip *)arg;
	int				hash_bucket;
	struct fcip_dest 		*fdestp;
	la_wwn_t			*pwwn;
	int 				index;
	struct fcip_routing_table 	*frtp, *frtp_next, *frtp_prev;


	mutex_enter(&fptr->fcip_rt_mutex);
	for (index = 0; index < FCIP_RT_HASH_ELEMS; index++) {
		frtp = fptr->fcip_rtable[index];
		frtp_prev = NULL;
		while (frtp) {
			frtp_next = frtp->fcipr_next;

			if (frtp->fcipr_state == FCIP_RT_RETIRED) {

				pwwn = &frtp->fcipr_pwwn;
				/*
				 * Get hold of destination pointer
				 */
				mutex_enter(&fptr->fcip_dest_mutex);

				hash_bucket = FCIP_DEST_HASH(pwwn->raw_wwn);
				ASSERT(hash_bucket < FCIP_DEST_HASH_ELEMS);

				fdestp = fptr->fcip_dest[hash_bucket];
				while (fdestp != NULL) {
					mutex_enter(&fdestp->fcipd_mutex);
					if (fdestp->fcipd_rtable) {
						if (fcip_wwn_compare(pwwn,
						    &fdestp->fcipd_pwwn,
						    FCIP_COMPARE_PWWN) == 0) {
							mutex_exit(
							&fdestp->fcipd_mutex);
							break;
						}
					}
					mutex_exit(&fdestp->fcipd_mutex);
					fdestp = fdestp->fcipd_next;
				}

				mutex_exit(&fptr->fcip_dest_mutex);
				if (fdestp == NULL) {
					frtp_prev = frtp;
					frtp = frtp_next;
					continue;
				}

				mutex_enter(&fdestp->fcipd_mutex);
				if (fdestp->fcipd_ncmds) {
					/*
					 * Instead of waiting to drain commands
					 * let us revisit this RT entry in
					 * the next pass.
					 */
					mutex_exit(&fdestp->fcipd_mutex);
					frtp_prev = frtp;
					frtp = frtp_next;
					continue;
				}

				/*
				 * We are clean, so remove the RTE
				 */
				fdestp->fcipd_rtable = NULL;
				mutex_exit(&fdestp->fcipd_mutex);

				FCIP_TNF_PROBE_2((fcip_rte_remove_deferred,
					"fcip io", /* CSTYLED */,
					tnf_string, msg,
					"remove retired routing entry",
					tnf_int, index, index));

				if (frtp_prev == NULL) {
					/* first element */
					fptr->fcip_rtable[index] =
					    frtp->fcipr_next;
				} else {
					frtp_prev->fcipr_next =
					    frtp->fcipr_next;
				}
				kmem_free(frtp,
				    sizeof (struct fcip_routing_table));

				frtp = frtp_next;
			} else {
				frtp_prev = frtp;
				frtp = frtp_next;
			}
		}
	}
	mutex_exit(&fptr->fcip_rt_mutex);
	/*
	 * Clear the RTE_REMOVING flag
	 */
	mutex_enter(&fptr->fcip_mutex);
	fptr->fcip_flags &= ~FCIP_RTE_REMOVING;
	mutex_exit(&fptr->fcip_mutex);
}

/*
 * Walk through all the dest hash table entries and count up the total
 * no. of packets outstanding against a given port
 */
static int
fcip_port_get_num_pkts(struct fcip *fptr)
{
	int 			num_cmds = 0;
	int 			i;
	struct fcip_dest	*fdestp;

	ASSERT(mutex_owned(&fptr->fcip_dest_mutex));

	for (i = 0; i < FCIP_DEST_HASH_ELEMS; i++) {
		fdestp = fptr->fcip_dest[i];
		while (fdestp != NULL) {
			mutex_enter(&fdestp->fcipd_mutex);

			ASSERT(fdestp->fcipd_ncmds >= 0);

			if (fdestp->fcipd_ncmds > 0) {
				num_cmds += fdestp->fcipd_ncmds;
			}
			mutex_exit(&fdestp->fcipd_mutex);
			fdestp = fdestp->fcipd_next;
		}
	}

	return (num_cmds);
}


/*
 * Walk through the routing table for this state instance and see if there is a
 * PLOGI in progress for any of the entries. Return success even if we find one.
 */
static int
fcip_plogi_in_progress(struct fcip *fptr)
{
	int				i;
	struct fcip_routing_table	*frp;

	ASSERT(mutex_owned(&fptr->fcip_rt_mutex));

	for (i = 0; i < FCIP_RT_HASH_ELEMS; i++) {
		frp = fptr->fcip_rtable[i];
		while (frp) {
			if (frp->fcipr_state == FCIP_RT_LOGIN_PROGRESS) {
				/* Found an entry where PLOGI is in progress */
				return (1);
			}
			frp = frp->fcipr_next;
		}
	}

	return (0);
}

/*
 * Walk through the fcip port global list and check if the given port exists in
 * the list. Returns "0" if port exists and "1" if otherwise.
 */
static int
fcip_check_port_exists(struct fcip *fptr)
{
	fcip_port_info_t	*cur_fport;
	fcip_port_info_t	*fport;

	mutex_enter(&fcip_global_mutex);
	fport = fptr->fcip_port_info;
	cur_fport = fcip_port_head;
	while (cur_fport != NULL) {
		if (cur_fport == fport) {
			/* Found */
			mutex_exit(&fcip_global_mutex);
			return (0);
		} else {
			cur_fport = cur_fport->fcipp_next;
		}
	}
	mutex_exit(&fcip_global_mutex);

	return (1);
}

/*
 * Constructor to initialize the sendup elements for callback into
 * modules upstream
 */

/* ARGSUSED */
static int
fcip_sendup_constructor(void *buf, void *arg, int flags)
{
	struct fcip_sendup_elem	*msg_elem = (struct fcip_sendup_elem *)buf;
	fcip_port_info_t	*fport = (fcip_port_info_t *)arg;

	ASSERT(fport != NULL);

	msg_elem->fcipsu_mp = NULL;
	msg_elem->fcipsu_func = NULL;
	msg_elem->fcipsu_next = NULL;

	return (FCIP_SUCCESS);
}
