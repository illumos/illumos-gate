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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/stream.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/ksynch.h>
#include <sys/stat.h>
#include <sys/modctl.h>
#include <sys/debug.h>
#include <sys/ethernet.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/strsun.h>
#include <sys/note.h>
#include <sys/mac.h>
#include <sys/mac_ether.h>
#include <sys/ldc.h>
#include <sys/mach_descrip.h>
#include <sys/mdeg.h>
#include <sys/vio_mailbox.h>
#include <sys/vio_common.h>
#include <sys/vnet_common.h>
#include <sys/vnet_mailbox.h>
#include <sys/vio_util.h>
#include <sys/vnet_gen.h>

/*
 * Implementation of the mac functionality for vnet using the
 * generic(default) transport layer of sun4v Logical Domain Channels(LDC).
 */

/*
 * Function prototypes.
 */
/* vgen proxy entry points */
int vgen_init(void *vnetp, dev_info_t *vnetdip, const uint8_t *macaddr,
	mac_register_t **vgenmacp);
int vgen_uninit(void *arg);
static int vgen_start(void *arg);
static void vgen_stop(void *arg);
static mblk_t *vgen_tx(void *arg, mblk_t *mp);
static int vgen_multicst(void *arg, boolean_t add,
	const uint8_t *mca);
static int vgen_promisc(void *arg, boolean_t on);
static int vgen_unicst(void *arg, const uint8_t *mca);
static int vgen_stat(void *arg, uint_t stat, uint64_t *val);
static void vgen_ioctl(void *arg, queue_t *wq, mblk_t *mp);

/* externs - functions provided by vnet to add/remove/modify entries in fdb */
void vnet_add_fdb(void *arg, uint8_t *macaddr, mac_tx_t m_tx, void *txarg);
void vnet_del_fdb(void *arg, uint8_t *macaddr);
void vnet_modify_fdb(void *arg, uint8_t *macaddr, mac_tx_t m_tx, void *txarg);
void vnet_add_def_rte(void *arg, mac_tx_t m_tx, void *txarg);
void vnet_del_def_rte(void *arg);
void vnet_rx(void *arg, mac_resource_handle_t mrh, mblk_t *mp);
void vnet_tx_update(void *arg);

/* vgen internal functions */
static void vgen_detach_ports(vgen_t *vgenp);
static void vgen_port_detach(vgen_port_t *portp);
static void vgen_port_list_insert(vgen_port_t *portp);
static void vgen_port_list_remove(vgen_port_t *portp);
static vgen_port_t *vgen_port_lookup(vgen_portlist_t *plistp,
	int port_num);
static int vgen_mdeg_reg(vgen_t *vgenp);
static void vgen_mdeg_unreg(vgen_t *vgenp);
static int vgen_mdeg_cb(void *cb_argp, mdeg_result_t *resp);
static int vgen_add_port(vgen_t *vgenp, md_t *mdp, mde_cookie_t mdex);
static int vgen_remove_port(vgen_t *vgenp, md_t *mdp, mde_cookie_t mdex);
static int vgen_port_attach_mdeg(vgen_t *vgenp, int port_num, uint64_t *ldcids,
	int num_ids, struct ether_addr *macaddr, boolean_t vsw_port);
static void vgen_port_detach_mdeg(vgen_port_t *portp);
static int vgen_update_port(vgen_t *vgenp, md_t *curr_mdp,
	mde_cookie_t curr_mdex, md_t *prev_mdp, mde_cookie_t prev_mdex);
static uint64_t	vgen_port_stat(vgen_port_t *portp, uint_t stat);

static int vgen_ldc_attach(vgen_port_t *portp, uint64_t ldc_id);
static void vgen_ldc_detach(vgen_ldc_t *ldcp);
static int vgen_alloc_tx_ring(vgen_ldc_t *ldcp);
static void vgen_free_tx_ring(vgen_ldc_t *ldcp);
static void vgen_init_ports(vgen_t *vgenp);
static void vgen_port_init(vgen_port_t *portp);
static void vgen_uninit_ports(vgen_t *vgenp);
static void vgen_port_uninit(vgen_port_t *portp);
static void vgen_init_ldcs(vgen_port_t *portp);
static void vgen_uninit_ldcs(vgen_port_t *portp);
static int vgen_ldc_init(vgen_ldc_t *ldcp);
static void vgen_ldc_uninit(vgen_ldc_t *ldcp);
static int vgen_init_tbufs(vgen_ldc_t *ldcp);
static void vgen_uninit_tbufs(vgen_ldc_t *ldcp);
static void vgen_clobber_tbufs(vgen_ldc_t *ldcp);
static void vgen_clobber_rxds(vgen_ldc_t *ldcp);
static uint64_t	vgen_ldc_stat(vgen_ldc_t *ldcp, uint_t stat);
static uint_t vgen_ldc_cb(uint64_t event, caddr_t arg);
static int vgen_portsend(vgen_port_t *portp, mblk_t *mp);
static int vgen_ldcsend(vgen_ldc_t *ldcp, mblk_t *mp);
static void vgen_reclaim(vgen_ldc_t *ldcp);
static void vgen_reclaim_dring(vgen_ldc_t *ldcp);
static int vgen_num_txpending(vgen_ldc_t *ldcp);
static int vgen_tx_dring_full(vgen_ldc_t *ldcp);
static int vgen_ldc_txtimeout(vgen_ldc_t *ldcp);
static void vgen_ldc_watchdog(void *arg);
static int vgen_setup_kstats(vgen_ldc_t *ldcp);
static void vgen_destroy_kstats(vgen_ldc_t *ldcp);
static int vgen_kstat_update(kstat_t *ksp, int rw);

/* vgen handshake functions */
static vgen_ldc_t *vh_nextphase(vgen_ldc_t *ldcp);
static int vgen_supported_version(vgen_ldc_t *ldcp, uint16_t ver_major,
	uint16_t ver_minor);
static int vgen_next_version(vgen_ldc_t *ldcp, vgen_ver_t *verp);
static int vgen_sendmsg(vgen_ldc_t *ldcp, caddr_t msg,  size_t msglen,
	boolean_t caller_holds_lock);
static int vgen_send_version_negotiate(vgen_ldc_t *ldcp);
static int vgen_send_attr_info(vgen_ldc_t *ldcp);
static int vgen_send_dring_reg(vgen_ldc_t *ldcp);
static int vgen_send_rdx_info(vgen_ldc_t *ldcp);
static int vgen_send_dring_data(vgen_ldc_t *ldcp, uint32_t start, int32_t end);
static int vgen_send_mcast_info(vgen_ldc_t *ldcp);
static int vgen_handshake_phase2(vgen_ldc_t *ldcp);
static void vgen_handshake_reset(vgen_ldc_t *ldcp);
static void vgen_reset_hphase(vgen_ldc_t *ldcp);
static void vgen_handshake(vgen_ldc_t *ldcp);
static int vgen_handshake_done(vgen_ldc_t *ldcp);
static void vgen_handshake_retry(vgen_ldc_t *ldcp);
static void vgen_handle_version_negotiate(vgen_ldc_t *ldcp,
	vio_msg_tag_t *tagp);
static void vgen_handle_attr_info(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp);
static void vgen_handle_dring_reg(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp);
static void vgen_handle_rdx_info(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp);
static void vgen_handle_mcast_info(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp);
static void vgen_handle_ctrlmsg(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp);
static void vgen_handle_dring_data(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp,
	mblk_t **headp, mblk_t **tailp);
static void vgen_send_dring_ack(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp,
	uint32_t start, int32_t end, uint8_t pstate);
static void vgen_handle_datamsg(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp,
	mblk_t **headp, mblk_t **tailp);
static void vgen_handle_errmsg(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp);
static int vgen_check_sid(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp);
static uint64_t	vgen_macaddr_strtoul(const uint8_t *macaddr);
static int vgen_macaddr_ultostr(uint64_t value, uint8_t *macaddr);
static caddr_t vgen_print_ethaddr(uint8_t *a, char *ebuf);
static void vgen_hwatchdog(void *arg);
static void vgen_print_attr_info(vgen_ldc_t *ldcp, int endpoint);
static void vgen_print_hparams(vgen_hparams_t *hp);
static void vgen_print_ldcinfo(vgen_ldc_t *ldcp);

/*
 * The handshake process consists of 5 phases defined below, with VH_PHASE0
 * being the pre-handshake phase and VH_DONE is the phase to indicate
 * successful completion of all phases.
 * Each phase may have one to several handshake states which are required
 * to complete successfully to move to the next phase.
 * Refer to the functions vgen_handshake() and vgen_handshake_done() for
 * more details.
 */
/* handshake phases */
enum {	VH_PHASE0, VH_PHASE1, VH_PHASE2, VH_PHASE3, VH_DONE = 0x80 };

/* handshake states */
enum {

	VER_INFO_SENT	=	0x1,
	VER_ACK_RCVD	=	0x2,
	VER_INFO_RCVD	=	0x4,
	VER_ACK_SENT	=	0x8,
	VER_NEGOTIATED	=	(VER_ACK_RCVD | VER_ACK_SENT),

	ATTR_INFO_SENT	=	0x10,
	ATTR_ACK_RCVD	=	0x20,
	ATTR_INFO_RCVD	=	0x40,
	ATTR_ACK_SENT	=	0x80,
	ATTR_INFO_EXCHANGED	=	(ATTR_ACK_RCVD | ATTR_ACK_SENT),

	DRING_INFO_SENT	=	0x100,
	DRING_ACK_RCVD	=	0x200,
	DRING_INFO_RCVD	=	0x400,
	DRING_ACK_SENT	=	0x800,
	DRING_INFO_EXCHANGED	=	(DRING_ACK_RCVD | DRING_ACK_SENT),

	RDX_INFO_SENT	=	0x1000,
	RDX_ACK_RCVD	=	0x2000,
	RDX_INFO_RCVD	=	0x4000,
	RDX_ACK_SENT	=	0x8000,
	RDX_EXCHANGED	=	(RDX_ACK_RCVD | RDX_ACK_SENT)

};

#define	LDC_LOCK(ldcp)	\
				mutex_enter(&((ldcp)->cblock));\
				mutex_enter(&((ldcp)->txlock));\
				mutex_enter(&((ldcp)->tclock));
#define	LDC_UNLOCK(ldcp)	\
				mutex_exit(&((ldcp)->tclock));\
				mutex_exit(&((ldcp)->txlock));\
				mutex_exit(&((ldcp)->cblock));

static struct ether_addr etherbroadcastaddr = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};
/*
 * MIB II broadcast/multicast packets
 */
#define	IS_BROADCAST(ehp) \
		(ether_cmp(&ehp->ether_dhost, &etherbroadcastaddr) == 0)
#define	IS_MULTICAST(ehp) \
		((ehp->ether_dhost.ether_addr_octet[0] & 01) == 1)

/*
 * Property names
 */
static char macaddr_propname[] = "mac-address";
static char rmacaddr_propname[] = "remote-mac-address";
static char channel_propname[] = "channel-endpoint";
static char reg_propname[] = "reg";
static char port_propname[] = "port";
static char swport_propname[] = "switch-port";
static char id_propname[] = "id";

/* versions supported - in decreasing order */
static vgen_ver_t vgen_versions[VGEN_NUM_VER] = { {1, 0} };

/* Tunables */
uint32_t vgen_hwd_interval = 1000;	/* handshake watchdog freq in msec */
uint32_t vgen_max_hretries = 1;		/* max # of handshake retries */
uint32_t vgen_ldcwr_retries = 10;	/* max # of ldc_write() retries */
uint32_t vgen_ldcup_retries = 5;	/* max # of ldc_up() retries */
uint32_t vgen_recv_delay = 1;		/* delay when rx descr not ready */
uint32_t vgen_recv_retries = 10;	/* retry when rx descr not ready */

#ifdef DEBUG
/* flags to simulate error conditions for debugging */
int vgen_trigger_txtimeout = 0;
int vgen_trigger_rxlost = 0;
#endif

/* MD update matching structure */
static md_prop_match_t	vport_prop_match[] = {
	{ MDET_PROP_VAL,	"id" },
	{ MDET_LIST_END,	NULL }
};

static mdeg_node_match_t vport_match = { "virtual-device-port",
					vport_prop_match };

/* template for matching a particular vnet instance */
static mdeg_prop_spec_t vgen_prop_template[] = {
	{ MDET_PROP_STR,	"name",		"network" },
	{ MDET_PROP_VAL,	"cfg-handle",	NULL },
	{ MDET_LIST_END,	NULL,		NULL }
};

#define	VGEN_SET_MDEG_PROP_INST(specp, val)	(specp)[1].ps_val = (val)

static int vgen_mdeg_cb(void *cb_argp, mdeg_result_t *resp);

static mac_callbacks_t vgen_m_callbacks = {
	0,
	vgen_stat,
	vgen_start,
	vgen_stop,
	vgen_promisc,
	vgen_multicst,
	vgen_unicst,
	vgen_tx,
	NULL,
	NULL,
	NULL
};

/* externs */
extern uint32_t vnet_ntxds;
extern uint32_t vnet_reclaim_lowat;
extern uint32_t vnet_reclaim_hiwat;
extern uint32_t vnet_ldcwd_interval;
extern uint32_t vnet_ldcwd_txtimeout;
extern uint32_t vnet_ldc_mtu;
extern uint32_t vnet_nrbufs;
extern int _vnet_dbglevel;
extern void _vnetdebug_printf(void *vnetp, const char *fmt, ...);

#ifdef DEBUG

/*
 * XXX: definitions below need to be in sync with those in vnet.c
 */

/*
 * debug levels:
 * DBG_LEVEL1:	Function entry/exit tracing
 * DBG_LEVEL2:	Info messages
 * DBG_LEVEL3:	Warning messages
 * DBG_LEVEL4:	Error messages
 */

enum	{ DBG_LEVEL1 = 0x01, DBG_LEVEL2 = 0x02, DBG_LEVEL3 = 0x04,
	    DBG_LEVEL4 = 0x08 };

#define	DBG1(_s)	do {						\
			    if ((_vnet_dbglevel & DBG_LEVEL1) != 0) {	\
					_vnetdebug_printf _s;		\
			    }					\
			_NOTE(CONSTCOND) } while (0)

#define	DBG2(_s)	do {						\
			    if ((_vnet_dbglevel & DBG_LEVEL2) != 0) {	\
					_vnetdebug_printf _s;		\
			    }					\
			_NOTE(CONSTCOND) } while (0)

#define	DWARN(_s)	do {						\
			    if ((_vnet_dbglevel & DBG_LEVEL3) != 0) {	\
					_vnetdebug_printf _s;		\
			    }					\
			_NOTE(CONSTCOND) } while (0)

#define	DERR(_s)	do {						\
			    if ((_vnet_dbglevel & DBG_LEVEL4) != 0) {	\
					_vnetdebug_printf _s;		\
			    }					\
			_NOTE(CONSTCOND) } while (0)

#else

#define	DBG1(_s)	if (0)	_vnetdebug_printf _s
#define	DBG2(_s)	if (0)	_vnetdebug_printf _s
#define	DWARN(_s)	if (0)	_vnetdebug_printf _s
#define	DERR(_s)	if (0)	_vnetdebug_printf _s

#endif

#ifdef DEBUG

/* simulate handshake error conditions for debug */
uint32_t vgen_hdbg;
#define	HDBG_VERSION	0x1
#define	HDBG_TIMEOUT	0x2
#define	HDBG_BAD_SID	0x4
#define	HDBG_OUT_STATE	0x8

#endif



/*
 * vgen_init() is called by an instance of vnet driver to initialize the
 * corresponding generic proxy transport layer. The arguments passed by vnet
 * are - an opaque pointer to the vnet instance, pointers to dev_info_t and
 * the mac address of the vnet device, and a pointer to mac_register_t of
 * the generic transport is returned in the last argument.
 */
int
vgen_init(void *vnetp, dev_info_t *vnetdip, const uint8_t *macaddr,
    mac_register_t **vgenmacp)
{
	vgen_t *vgenp;
	mac_register_t *macp;
	int instance;

	if ((vnetp == NULL) || (vnetdip == NULL))
		return (DDI_FAILURE);

	instance = ddi_get_instance(vnetdip);

	DBG1((vnetp, "vgen_init: enter vnet_instance(%d)\n", instance));

	vgenp = kmem_zalloc(sizeof (vgen_t), KM_SLEEP);

	vgenp->vnetp = vnetp;
	vgenp->vnetdip = vnetdip;
	bcopy(macaddr, &(vgenp->macaddr), ETHERADDRL);

	if ((macp = mac_alloc(MAC_VERSION)) == NULL) {
		KMEM_FREE(vgenp);
		return (DDI_FAILURE);
	}
	macp->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	macp->m_driver = vgenp;
	macp->m_dip = vnetdip;
	macp->m_src_addr = (uint8_t *)&(vgenp->macaddr);
	macp->m_callbacks = &vgen_m_callbacks;
	macp->m_min_sdu = 0;
	macp->m_max_sdu = ETHERMTU;
	vgenp->macp = macp;

	/* allocate multicast table */
	vgenp->mctab = kmem_zalloc(VGEN_INIT_MCTAB_SIZE *
	    sizeof (struct ether_addr), KM_SLEEP);
	vgenp->mccount = 0;
	vgenp->mcsize = VGEN_INIT_MCTAB_SIZE;

	mutex_init(&vgenp->lock, NULL, MUTEX_DRIVER, NULL);

	/* register with MD event generator */
	if (vgen_mdeg_reg(vgenp) != DDI_SUCCESS) {
		mutex_destroy(&vgenp->lock);
		kmem_free(vgenp->mctab, VGEN_INIT_MCTAB_SIZE *
		    sizeof (struct ether_addr));
		mac_free(vgenp->macp);
		KMEM_FREE(vgenp);
		return (DDI_FAILURE);
	}

	/* register macp of this vgen_t with vnet */
	*vgenmacp = vgenp->macp;

	DBG1((vnetp, "vgen_init: exit vnet_instance(%d)\n", instance));
	return (DDI_SUCCESS);
}

/*
 * Called by vnet to undo the initializations done by vgen_init().
 * The handle provided by generic transport during vgen_init() is the argument.
 */
int
vgen_uninit(void *arg)
{
	vgen_t	*vgenp = (vgen_t *)arg;
	void	*vnetp;
	int instance;
	vio_mblk_pool_t *rp, *nrp;

	if (vgenp == NULL) {
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(vgenp->vnetdip);
	vnetp = vgenp->vnetp;

	DBG1((vnetp, "vgen_uninit: enter vnet_instance(%d)\n", instance));

	/* unregister with MD event generator */
	vgen_mdeg_unreg(vgenp);

	mutex_enter(&vgenp->lock);

	/* detach all ports from the device */
	vgen_detach_ports(vgenp);

	/*
	 * free any pending rx mblk pools,
	 * that couldn't be freed previously during channel detach.
	 */
	rp = vgenp->rmp;
	while (rp != NULL) {
		nrp = vgenp->rmp = rp->nextp;
		if (vio_destroy_mblks(rp)) {
			vgenp->rmp = rp;
			mutex_exit(&vgenp->lock);
			return (DDI_FAILURE);
		}
		rp = nrp;
	}

	/* free multicast table */
	kmem_free(vgenp->mctab, vgenp->mcsize * sizeof (struct ether_addr));

	mac_free(vgenp->macp);

	mutex_exit(&vgenp->lock);

	mutex_destroy(&vgenp->lock);

	KMEM_FREE(vgenp);

	DBG1((vnetp, "vgen_uninit: exit vnet_instance(%d)\n", instance));

	return (DDI_SUCCESS);
}

/* enable transmit/receive for the device */
int
vgen_start(void *arg)
{
	vgen_t		*vgenp = (vgen_t *)arg;

	DBG1((vgenp->vnetp, "vgen_start: enter\n"));

	mutex_enter(&vgenp->lock);
	vgen_init_ports(vgenp);
	vgenp->flags |= VGEN_STARTED;
	mutex_exit(&vgenp->lock);

	DBG1((vgenp->vnetp, "vgen_start: exit\n"));
	return (DDI_SUCCESS);
}

/* stop transmit/receive */
void
vgen_stop(void *arg)
{
	vgen_t		*vgenp = (vgen_t *)arg;

	DBG1((vgenp->vnetp, "vgen_stop: enter\n"));

	mutex_enter(&vgenp->lock);
	vgen_uninit_ports(vgenp);
	vgenp->flags &= ~(VGEN_STARTED);
	mutex_exit(&vgenp->lock);

	DBG1((vgenp->vnetp, "vgen_stop: exit\n"));
}

/* vgen transmit function */
static mblk_t *
vgen_tx(void *arg, mblk_t *mp)
{
	vgen_port_t *portp;
	int status;

	portp = (vgen_port_t *)arg;
	status = vgen_portsend(portp, mp);
	if (status != VGEN_SUCCESS) {
		/* failure */
		return (mp);
	}
	/* success */
	return (NULL);
}

/* transmit packets over the given port */
static int
vgen_portsend(vgen_port_t *portp, mblk_t *mp)
{
	vgen_ldclist_t	*ldclp;
	vgen_ldc_t *ldcp;
	int status;

	ldclp = &portp->ldclist;
	READ_ENTER(&ldclp->rwlock);
	/*
	 * NOTE: for now, we will assume we have a single channel.
	 */
	if (ldclp->headp == NULL) {
		RW_EXIT(&ldclp->rwlock);
		return (VGEN_FAILURE);
	}
	ldcp = ldclp->headp;

	if (ldcp->need_resched) {
		/* out of tx resources, see vgen_ldcsend() for details. */
		mutex_enter(&ldcp->txlock);
		ldcp->statsp->tx_no_desc++;
		mutex_exit(&ldcp->txlock);

		RW_EXIT(&ldclp->rwlock);
		return (VGEN_FAILURE);
	}

	status  = vgen_ldcsend(ldcp, mp);
	RW_EXIT(&ldclp->rwlock);

	if (status != VGEN_TX_SUCCESS)
		return (VGEN_FAILURE);

	return (VGEN_SUCCESS);
}

/* channel transmit function */
static int
vgen_ldcsend(vgen_ldc_t *ldcp, mblk_t *mp)
{
	void		*vnetp;
	size_t		size;
	int		rv;
	uint64_t	tbuf_ix;
	vgen_private_desc_t	*tbufp;
	vgen_private_desc_t	*ntbufp;
	vnet_public_desc_t	*txdp;
	vio_dring_entry_hdr_t		*hdrp;
	vgen_stats_t		*statsp;
	struct ether_header	*ehp;
	boolean_t	is_bcast = B_FALSE;
	boolean_t	is_mcast = B_FALSE;
	boolean_t	need_intr = B_FALSE;
	size_t		mblksz;
	caddr_t		dst;
	mblk_t		*bp;

	vnetp = LDC_TO_VNET(ldcp);
	statsp = ldcp->statsp;
	size = msgsize(mp);

	DBG1((vnetp, "vgen_ldcsend: enter ldcid(%lx)\n", ldcp->ldc_id));

	mutex_enter(&ldcp->txlock);

	/* drop the packet if ldc is not up or handshake is not done */
	if (ldcp->ldc_status != LDC_UP) {
		DWARN((vnetp,
		    "vgen_ldcsend: id(%lx) status(%d), dropping packet\n",
		    ldcp->ldc_id, ldcp->ldc_status));
		/* retry ldc_up() if needed */
		if (ldcp->flags & CHANNEL_STARTED)
			(void) ldc_up(ldcp->ldc_handle);
		goto vgen_tx_exit;
	}

	if (ldcp->hphase != VH_DONE) {
		DWARN((vnetp,
		    "vgen_ldcsend: id(%lx) hphase(%x), dropping packet\n",
		    ldcp->ldc_id, ldcp->hphase));
		goto vgen_tx_exit;
	}

	if (size > (size_t)ETHERMAX) {
		DWARN((vnetp, "vgen_ldcsend: id(%lx) invalid size(%d)\n",
		    ldcp->ldc_id, size));
		goto vgen_tx_exit;
	}

	/*
	 * allocate a descriptor
	 */
	tbufp = ldcp->next_tbufp;
	ntbufp = NEXTTBUF(ldcp, tbufp);
	if (ntbufp == ldcp->cur_tbufp) { /* out of tbufs/txds */

		mutex_enter(&ldcp->tclock);
		if (ntbufp == ldcp->cur_tbufp) {
			ldcp->need_resched = B_TRUE;
			mutex_exit(&ldcp->tclock);

			statsp->tx_no_desc++;
			mutex_exit(&ldcp->txlock);

			return (VGEN_TX_NORESOURCES);
		}
		mutex_exit(&ldcp->tclock);
	}

	if (size < ETHERMIN)
		size = ETHERMIN;

	/* copy data into pre-allocated transmit buffer */
	dst = tbufp->datap + VNET_IPALIGN;
	for (bp = mp; bp != NULL; bp = bp->b_cont) {
		mblksz = MBLKL(bp);
		bcopy(bp->b_rptr, dst, mblksz);
		dst += mblksz;
	}

	tbuf_ix = tbufp - ldcp->tbufp;

	ehp = (struct ether_header *)tbufp->datap;
	is_bcast = IS_BROADCAST(ehp);
	is_mcast = IS_MULTICAST(ehp);

	tbufp->flags = VGEN_PRIV_DESC_BUSY;
	tbufp->datalen = size;

	/* initialize the corresponding public descriptor (txd) */
	txdp = tbufp->descp;
	hdrp = &txdp->hdr;
	if (need_intr)
		hdrp->ack = B_TRUE;
	txdp->nbytes = size;
	txdp->ncookies = tbufp->ncookies;
	bcopy((tbufp->memcookie), (txdp->memcookie),
		tbufp->ncookies * sizeof (ldc_mem_cookie_t));
	hdrp->dstate = VIO_DESC_READY;

	/* send dring datamsg to the peer */
	if (ldcp->resched_peer) {
		rv = vgen_send_dring_data(ldcp, (uint32_t)tbuf_ix, -1);
		if (rv != 0) {
			/* vgen_send_dring_data() error: drop the packet */
			DWARN((vnetp,
			    "vgen_ldcsend: vgen_send_dring_data():  failed: "
			    "id(%lx) rv(%d) len (%d)\n",
			    ldcp->ldc_id, rv, size));
			tbufp->flags = VGEN_PRIV_DESC_FREE;	/* free tbuf */
			hdrp->dstate = VIO_DESC_FREE;	/* free txd */
			hdrp->ack = B_FALSE;
			statsp->oerrors++;
			goto vgen_tx_exit;
		}
		ldcp->resched_peer = B_FALSE;
	}

	/* update next available tbuf in the ring */
	ldcp->next_tbufp = ntbufp;

	/* update tx index */
	INCR_TXI(ldcp->next_txi, ldcp);

	/* update stats */
	statsp->opackets++;
	statsp->obytes += size;
	if (is_bcast)
		statsp->brdcstxmt++;
	else if (is_mcast)
		statsp->multixmt++;

vgen_tx_exit:
	mutex_exit(&ldcp->txlock);

	DBG1((vnetp, "vgen_ldcsend: exit: ldcid (%lx)\n", ldcp->ldc_id));

	freemsg(mp);
	return (VGEN_TX_SUCCESS);
}

/* enable/disable a multicast address */
int
vgen_multicst(void *arg, boolean_t add, const uint8_t *mca)
{
	vgen_t			*vgenp;
	vnet_mcast_msg_t	mcastmsg;
	vio_msg_tag_t		*tagp;
	vgen_port_t		*portp;
	vgen_portlist_t		*plistp;
	vgen_ldc_t		*ldcp;
	vgen_ldclist_t		*ldclp;
	void			*vnetp;
	struct ether_addr	*addrp;
	int			rv;
	uint32_t		i;

	vgenp = (vgen_t *)arg;
	vnetp = vgenp->vnetp;
	addrp = (struct ether_addr *)mca;
	tagp = &mcastmsg.tag;
	bzero(&mcastmsg, sizeof (mcastmsg));

	mutex_enter(&vgenp->lock);

	plistp = &(vgenp->vgenports);

	READ_ENTER(&plistp->rwlock);

	portp = vgenp->vsw_portp;
	if (portp == NULL) {
		RW_EXIT(&plistp->rwlock);
		goto vgen_mcast_exit;
	}
	ldclp = &portp->ldclist;

	READ_ENTER(&ldclp->rwlock);

	ldcp = ldclp->headp;
	if (ldcp == NULL) {
		RW_EXIT(&ldclp->rwlock);
		RW_EXIT(&plistp->rwlock);
		goto vgen_mcast_exit;
	}

	mutex_enter(&ldcp->cblock);

	if (ldcp->hphase == VH_DONE) {
		/*
		 * If handshake is done, send a msg to vsw to add/remove
		 * the multicast address.
		 */
		tagp->vio_msgtype = VIO_TYPE_CTRL;
		tagp->vio_subtype = VIO_SUBTYPE_INFO;
		tagp->vio_subtype_env = VNET_MCAST_INFO;
		tagp->vio_sid = ldcp->local_sid;
		bcopy(mca, &(mcastmsg.mca), ETHERADDRL);
		mcastmsg.set = add;
		mcastmsg.count = 1;
		rv = vgen_sendmsg(ldcp, (caddr_t)tagp, sizeof (mcastmsg),
		    B_FALSE);
		if (rv != VGEN_SUCCESS) {
			DWARN((vnetp, "vgen_mutlicst: vgen_sendmsg failed"
			    "id (%lx)\n", ldcp->ldc_id));
		}
	} else {
		/* set the flag to send a msg to vsw after handshake is done */
		ldcp->need_mcast_sync = B_TRUE;
	}

	mutex_exit(&ldcp->cblock);

	if (add) {

		/* expand multicast table if necessary */
		if (vgenp->mccount >= vgenp->mcsize) {
			struct ether_addr	*newtab;
			uint32_t		newsize;


			newsize = vgenp->mcsize * 2;

			newtab = kmem_zalloc(newsize *
			    sizeof (struct ether_addr), KM_NOSLEEP);

			bcopy(vgenp->mctab, newtab, vgenp->mcsize *
			    sizeof (struct ether_addr));
			kmem_free(vgenp->mctab,
			    vgenp->mcsize * sizeof (struct ether_addr));

			vgenp->mctab = newtab;
			vgenp->mcsize = newsize;
		}

		/* add address to the table */
		vgenp->mctab[vgenp->mccount++] = *addrp;

	} else {

		/* delete address from the table */
		for (i = 0; i < vgenp->mccount; i++) {
			if (ether_cmp(addrp, &(vgenp->mctab[i])) == 0) {

				/*
				 * If there's more than one address in this
				 * table, delete the unwanted one by moving
				 * the last one in the list over top of it;
				 * otherwise, just remove it.
				 */
				if (vgenp->mccount > 1) {
					vgenp->mctab[i] =
						vgenp->mctab[vgenp->mccount-1];
				}
				vgenp->mccount--;
				break;
			}
		}
	}

	RW_EXIT(&ldclp->rwlock);
	RW_EXIT(&plistp->rwlock);

vgen_mcast_exit:
	mutex_exit(&vgenp->lock);
	return (DDI_SUCCESS);
}

/* set or clear promiscuous mode on the device */
static int
vgen_promisc(void *arg, boolean_t on)
{
	_NOTE(ARGUNUSED(arg, on))
	return (DDI_SUCCESS);
}

/* set the unicast mac address of the device */
static int
vgen_unicst(void *arg, const uint8_t *mca)
{
	_NOTE(ARGUNUSED(arg, mca))
	return (DDI_SUCCESS);
}

/* get device statistics */
int
vgen_stat(void *arg, uint_t stat, uint64_t *val)
{
	vgen_t		*vgenp = (vgen_t *)arg;
	vgen_port_t	*portp;
	vgen_portlist_t	*plistp;

	*val = 0;

	plistp = &(vgenp->vgenports);
	READ_ENTER(&plistp->rwlock);

	for (portp = plistp->headp; portp != NULL; portp = portp->nextp) {
		*val += vgen_port_stat(portp, stat);
	}

	RW_EXIT(&plistp->rwlock);

	return (0);
}

static void
vgen_ioctl(void *arg, queue_t *wq, mblk_t *mp)
{
	 _NOTE(ARGUNUSED(arg, wq, mp))
}

/* vgen internal functions */
/* detach all ports from the device */
static void
vgen_detach_ports(vgen_t *vgenp)
{
	vgen_port_t	*portp;
	vgen_portlist_t	*plistp;

	plistp = &(vgenp->vgenports);
	WRITE_ENTER(&plistp->rwlock);

	while ((portp = plistp->headp) != NULL) {
		vgen_port_detach(portp);
	}

	RW_EXIT(&plistp->rwlock);
}

/*
 * detach the given port.
 */
static void
vgen_port_detach(vgen_port_t *portp)
{
	vgen_t		*vgenp;
	vgen_ldclist_t	*ldclp;
	int		port_num;

	vgenp = portp->vgenp;
	port_num = portp->port_num;

	DBG1((vgenp->vnetp,
	    "vgen_port_detach: enter: port_num(%d)\n", port_num));

	/* remove it from port list */
	vgen_port_list_remove(portp);

	/* detach channels from this port */
	ldclp = &portp->ldclist;
	WRITE_ENTER(&ldclp->rwlock);
	while (ldclp->headp) {
		vgen_ldc_detach(ldclp->headp);
	}
	RW_EXIT(&ldclp->rwlock);

	if (vgenp->vsw_portp == portp) {
		vgenp->vsw_portp = NULL;
	}
	KMEM_FREE(portp);

	DBG1((vgenp->vnetp,
	    "vgen_port_detach: exit: port_num(%d)\n", port_num));
}

/* add a port to port list */
static void
vgen_port_list_insert(vgen_port_t *portp)
{
	vgen_portlist_t *plistp;
	vgen_t *vgenp;

	vgenp = portp->vgenp;
	plistp = &(vgenp->vgenports);

	if (plistp->headp == NULL) {
		plistp->headp = portp;
	} else {
		plistp->tailp->nextp = portp;
	}
	plistp->tailp = portp;
	portp->nextp = NULL;
}

/* remove a port from port list */
static void
vgen_port_list_remove(vgen_port_t *portp)
{
	vgen_port_t *prevp;
	vgen_port_t *nextp;
	vgen_portlist_t *plistp;
	vgen_t *vgenp;

	vgenp = portp->vgenp;

	plistp = &(vgenp->vgenports);

	if (plistp->headp == NULL)
		return;

	if (portp == plistp->headp) {
		plistp->headp = portp->nextp;
		if (portp == plistp->tailp)
			plistp->tailp = plistp->headp;
	} else {
		for (prevp = plistp->headp; ((nextp = prevp->nextp) != NULL) &&
		    (nextp != portp); prevp = nextp);
		if (nextp == portp) {
			prevp->nextp = portp->nextp;
		}
		if (portp == plistp->tailp)
			plistp->tailp = prevp;
	}
}

/* lookup a port in the list based on port_num */
static vgen_port_t *
vgen_port_lookup(vgen_portlist_t *plistp, int port_num)
{
	vgen_port_t *portp = NULL;

	for (portp = plistp->headp; portp != NULL; portp = portp->nextp) {
		if (portp->port_num == port_num) {
			break;
		}
	}

	return (portp);
}

/* enable ports for transmit/receive */
static void
vgen_init_ports(vgen_t *vgenp)
{
	vgen_port_t	*portp;
	vgen_portlist_t	*plistp;

	plistp = &(vgenp->vgenports);
	READ_ENTER(&plistp->rwlock);

	for (portp = plistp->headp; portp != NULL; portp = portp->nextp) {
		vgen_port_init(portp);
	}

	RW_EXIT(&plistp->rwlock);
}

static void
vgen_port_init(vgen_port_t *portp)
{
	vgen_t *vgenp;

	vgenp = portp->vgenp;
	/*
	 * Create fdb entry in vnet, corresponding to the mac
	 * address of this port. Note that the port specified
	 * is vsw-port. This is done so that vsw-port acts
	 * as the route to reach this macaddr, until the
	 * channel for this port comes up (LDC_UP) and
	 * handshake is done successfully.
	 * eg, if the peer is OBP-vnet, it may not bring the
	 * channel up for this port and may communicate via
	 * vsw to reach this port.
	 * Later, when Solaris-vnet comes up at the other end
	 * of the channel for this port and brings up the channel,
	 * it is an indication that peer vnet is capable of
	 * distributed switching, so the direct route through this
	 * port is specified in fdb, using vnet_modify_fdb(macaddr);
	 */
	vnet_add_fdb(vgenp->vnetp, (uint8_t *)&portp->macaddr,
	    vgen_tx, vgenp->vsw_portp);

	if (portp == vgenp->vsw_portp) {
		/*
		 * create the default route entry in vnet's fdb.
		 * This is the entry used by vnet to reach
		 * unknown destinations, which basically goes
		 * through vsw on domain0 and out through the
		 * physical device bound to vsw.
		 */
		vnet_add_def_rte(vgenp->vnetp, vgen_tx, portp);
	}

	/* Bring up the channels of this port */
	vgen_init_ldcs(portp);
}

/* disable transmit/receive on ports */
static void
vgen_uninit_ports(vgen_t *vgenp)
{
	vgen_port_t	*portp;
	vgen_portlist_t	*plistp;

	plistp = &(vgenp->vgenports);
	READ_ENTER(&plistp->rwlock);

	for (portp = plistp->headp; portp != NULL; portp = portp->nextp) {
		vgen_port_uninit(portp);
	}

	RW_EXIT(&plistp->rwlock);
}

static void
vgen_port_uninit(vgen_port_t *portp)
{
	vgen_t *vgenp;

	vgenp = portp->vgenp;

	vgen_uninit_ldcs(portp);
	/* delete the entry in vnet's fdb for this port */
	vnet_del_fdb(vgenp->vnetp, (uint8_t *)&portp->macaddr);
	if (portp == vgenp->vsw_portp) {
		/*
		 * if this is vsw-port, then delete the default
		 * route entry in vnet's fdb.
		 */
		vnet_del_def_rte(vgenp->vnetp);
	}
}

/* register with MD event generator */
static int
vgen_mdeg_reg(vgen_t *vgenp)
{
	mdeg_prop_spec_t	*pspecp;
	mdeg_node_spec_t	*parentp;
	uint_t			templatesz;
	int			rv;
	mdeg_handle_t		hdl;
	int			i;
	void			*vnetp = vgenp->vnetp;

	i = ddi_prop_get_int(DDI_DEV_T_ANY, vgenp->vnetdip,
			DDI_PROP_DONTPASS, reg_propname, -1);
	if (i == -1) {
		return (DDI_FAILURE);
	}
	templatesz = sizeof (vgen_prop_template);
	pspecp = kmem_zalloc(templatesz, KM_NOSLEEP);
	if (pspecp == NULL) {
		return (DDI_FAILURE);
	}
	parentp = kmem_zalloc(sizeof (mdeg_node_spec_t), KM_NOSLEEP);
	if (parentp == NULL) {
		kmem_free(pspecp, templatesz);
		return (DDI_FAILURE);
	}

	bcopy(vgen_prop_template, pspecp, templatesz);

	/*
	 * NOTE: The instance here refers to the value of "reg" property and
	 * not the dev_info instance (ddi_get_instance()) of vnet.
	 */
	VGEN_SET_MDEG_PROP_INST(pspecp, i);

	parentp->namep = "virtual-device";
	parentp->specp = pspecp;

	/* save parentp in vgen_t */
	vgenp->mdeg_parentp = parentp;

	rv = mdeg_register(parentp, &vport_match, vgen_mdeg_cb, vgenp, &hdl);
	if (rv != MDEG_SUCCESS) {
		DERR((vnetp, "vgen_mdeg_reg: mdeg_register failed\n"));
		KMEM_FREE(parentp);
		kmem_free(pspecp, templatesz);
		vgenp->mdeg_parentp = NULL;
		return (DDI_FAILURE);
	}

	/* save mdeg handle in vgen_t */
	vgenp->mdeg_hdl = hdl;

	return (DDI_SUCCESS);
}

/* unregister with MD event generator */
static void
vgen_mdeg_unreg(vgen_t *vgenp)
{
	(void) mdeg_unregister(vgenp->mdeg_hdl);
	KMEM_FREE(vgenp->mdeg_parentp);
	vgenp->mdeg_parentp = NULL;
	vgenp->mdeg_hdl = NULL;
}

/* callback function registered with MD event generator */
static int
vgen_mdeg_cb(void *cb_argp, mdeg_result_t *resp)
{
	int idx;
	int vsw_idx = -1;
	uint64_t val;
	vgen_t *vgenp;

	if ((resp == NULL) || (cb_argp == NULL)) {
		return (MDEG_FAILURE);
	}

	vgenp = (vgen_t *)cb_argp;
	DBG1((vgenp->vnetp, "vgen_mdeg_cb: enter\n"));

	mutex_enter(&vgenp->lock);

	DBG1((vgenp->vnetp,
	    "vgen_mdeg_cb: ports: removed(%x), added(%x), updated(%x)\n",
	    resp->removed.nelem, resp->added.nelem, resp->match_curr.nelem));

	for (idx = 0; idx < resp->removed.nelem; idx++) {
		(void) vgen_remove_port(vgenp, resp->removed.mdp,
		    resp->removed.mdep[idx]);
	}

	if (vgenp->vsw_portp == NULL) {
		/*
		 * find vsw_port and add it first, because other ports need
		 * this when adding fdb entry (see vgen_port_init()).
		 */
		for (idx = 0; idx < resp->added.nelem; idx++) {
			if (!(md_get_prop_val(resp->added.mdp,
			    resp->added.mdep[idx], swport_propname, &val))) {
				if (val == 0) {
					/*
					 * This port is connected to the
					 * vsw on dom0.
					 */
					vsw_idx = idx;
					(void) vgen_add_port(vgenp,
					    resp->added.mdp,
					    resp->added.mdep[idx]);
					break;
				}
			}
		}
		if (vsw_idx == -1) {
			DWARN((vgenp->vnetp, "vgen_mdeg_cb: "
			    "can't find vsw_port\n"));
			return (MDEG_FAILURE);
		}
	}

	for (idx = 0; idx < resp->added.nelem; idx++) {
		if ((vsw_idx != -1) && (vsw_idx == idx)) /* skip vsw_port */
			continue;
		(void) vgen_add_port(vgenp, resp->added.mdp,
		    resp->added.mdep[idx]);
	}

	for (idx = 0; idx < resp->match_curr.nelem; idx++) {
		(void) vgen_update_port(vgenp, resp->match_curr.mdp,
		    resp->match_curr.mdep[idx],
		    resp->match_prev.mdp,
		    resp->match_prev.mdep[idx]);
	}

	mutex_exit(&vgenp->lock);
	DBG1((vgenp->vnetp, "vgen_mdeg_cb: exit\n"));
	return (MDEG_SUCCESS);
}

/* add a new port to the device */
static int
vgen_add_port(vgen_t *vgenp, md_t *mdp, mde_cookie_t mdex)
{
	uint64_t	port_num;
	uint64_t	*ldc_ids;
	uint64_t	macaddr;
	uint64_t	val;
	int		num_ldcs;
	int		vsw_port = B_FALSE;
	int		i;
	int		addrsz;
	int		num_nodes = 0;
	int		listsz = 0;
	mde_cookie_t	*listp = NULL;
	uint8_t		*addrp;
	struct ether_addr	ea;

	/* read "id" property to get the port number */
	if (md_get_prop_val(mdp, mdex, id_propname, &port_num)) {
		DWARN((vgenp->vnetp,
		    "vgen_add_port: prop(%s) not found\n", id_propname));
		return (DDI_FAILURE);
	}

	/*
	 * Find the channel endpoint node(s) under this port node.
	 */
	if ((num_nodes = md_node_count(mdp)) <= 0) {
		DWARN((vgenp->vnetp,
		    "vgen_add_port: invalid number of nodes found (%d)",
		    num_nodes));
		return (DDI_FAILURE);
	}

	/* allocate space for node list */
	listsz = num_nodes * sizeof (mde_cookie_t);
	listp = kmem_zalloc(listsz, KM_NOSLEEP);
	if (listp == NULL)
		return (DDI_FAILURE);

	num_ldcs = md_scan_dag(mdp, mdex,
		md_find_name(mdp, channel_propname),
		md_find_name(mdp, "fwd"), listp);

	if (num_ldcs <= 0) {
		DWARN((vgenp->vnetp,
		    "vgen_add_port: can't find %s nodes", channel_propname));
		kmem_free(listp, listsz);
		return (DDI_FAILURE);
	}

	DBG2((vgenp->vnetp, "vgen_add_port: num_ldcs %d", num_ldcs));

	ldc_ids = kmem_zalloc(num_ldcs * sizeof (uint64_t), KM_NOSLEEP);
	if (ldc_ids == NULL) {
		kmem_free(listp, listsz);
		return (DDI_FAILURE);
	}

	for (i = 0; i < num_ldcs; i++) {
		/* read channel ids */
		if (md_get_prop_val(mdp, listp[i], id_propname, &ldc_ids[i])) {
			DWARN((vgenp->vnetp,
			    "vgen_add_port: prop(%s) not found\n",
			    id_propname));
			kmem_free(listp, listsz);
			kmem_free(ldc_ids, num_ldcs * sizeof (uint64_t));
			return (DDI_FAILURE);
		}
		DBG2((vgenp->vnetp, "vgen_add_port: ldc_id 0x%llx",
		    ldc_ids[i]));
	}

	kmem_free(listp, listsz);

	if (md_get_prop_data(mdp, mdex, rmacaddr_propname, &addrp,
	    &addrsz)) {
		DWARN((vgenp->vnetp,
		    "vgen_add_port: prop(%s) not found\n", rmacaddr_propname));
		kmem_free(ldc_ids, num_ldcs * sizeof (uint64_t));
		return (DDI_FAILURE);
	}

	if (addrsz < ETHERADDRL) {
		DWARN((vgenp->vnetp,
		    "vgen_add_port: invalid address size (%d)\n", addrsz));
		kmem_free(ldc_ids, num_ldcs * sizeof (uint64_t));
		return (DDI_FAILURE);
	}

	macaddr = *((uint64_t *)addrp);

	DBG2((vgenp->vnetp, "vgen_add_port: remote mac address 0x%llx\n",
	    macaddr));

	for (i = ETHERADDRL - 1; i >= 0; i--) {
		ea.ether_addr_octet[i] = macaddr & 0xFF;
		macaddr >>= 8;
	}

	if (vgenp->vsw_portp == NULL) {
		if (!(md_get_prop_val(mdp, mdex, swport_propname, &val))) {
			if (val == 0) {
				/* This port is connected to the vsw on dom0 */
				vsw_port = B_TRUE;
			}
		}
	}
	(void) vgen_port_attach_mdeg(vgenp, (int)port_num, ldc_ids, num_ldcs,
	    &ea, vsw_port);

	kmem_free(ldc_ids, num_ldcs * sizeof (uint64_t));

	return (DDI_SUCCESS);
}

/* remove a port from the device */
static int
vgen_remove_port(vgen_t *vgenp, md_t *mdp, mde_cookie_t mdex)
{
	uint64_t	port_num;
	vgen_port_t	*portp;
	vgen_portlist_t	*plistp;

	/* read "id" property to get the port number */
	if (md_get_prop_val(mdp, mdex, id_propname, &port_num)) {
		DWARN((vgenp->vnetp,
		    "vgen_remove_port: prop(%s) not found\n", id_propname));
		return (DDI_FAILURE);
	}

	plistp = &(vgenp->vgenports);

	WRITE_ENTER(&plistp->rwlock);
	portp = vgen_port_lookup(plistp, (int)port_num);
	if (portp == NULL) {
		DWARN((vgenp->vnetp, "vgen_remove_port: can't find port(%lx)\n",
		    port_num));
		RW_EXIT(&plistp->rwlock);
		return (DDI_FAILURE);
	}

	vgen_port_detach_mdeg(portp);
	RW_EXIT(&plistp->rwlock);

	return (DDI_SUCCESS);
}

/* attach a port to the device based on mdeg data */
static int
vgen_port_attach_mdeg(vgen_t *vgenp, int port_num, uint64_t *ldcids,
	int num_ids, struct ether_addr *macaddr, boolean_t vsw_port)
{
	vgen_port_t		*portp;
	vgen_portlist_t		*plistp;
	int			i;

	portp = kmem_zalloc(sizeof (vgen_port_t), KM_NOSLEEP);
	if (portp == NULL) {
		return (DDI_FAILURE);
	}
	portp->vgenp = vgenp;
	portp->port_num = port_num;

	DBG1((vgenp->vnetp,
	    "vgen_port_attach_mdeg: port_num(%d)\n", portp->port_num));

	portp->ldclist.num_ldcs = 0;
	portp->ldclist.headp = NULL;
	rw_init(&portp->ldclist.rwlock, NULL, RW_DRIVER, NULL);

	ether_copy(macaddr, &portp->macaddr);
	for (i = 0; i < num_ids; i++) {
		DBG2((vgenp->vnetp, "vgen_port_attach_mdeg: ldcid (%lx)\n",
		    ldcids[i]));
		(void) vgen_ldc_attach(portp, ldcids[i]);
	}

	/* link it into the list of ports */
	plistp = &(vgenp->vgenports);
	WRITE_ENTER(&plistp->rwlock);
	vgen_port_list_insert(portp);
	RW_EXIT(&plistp->rwlock);

	/* This port is connected to the vsw on domain0 */
	if (vsw_port)
		vgenp->vsw_portp = portp;

	if (vgenp->flags & VGEN_STARTED) {	/* interface is configured */
		vgen_port_init(portp);
	}

	DBG1((vgenp->vnetp,
	    "vgen_port_attach_mdeg: exit: port_num(%d)\n", portp->port_num));
	return (DDI_SUCCESS);
}

/* detach a port from the device based on mdeg data */
static void
vgen_port_detach_mdeg(vgen_port_t *portp)
{
	vgen_t *vgenp = portp->vgenp;

	DBG1((vgenp->vnetp,
	    "vgen_port_detach_mdeg: enter: port_num(%d)\n", portp->port_num));
	/* stop the port if needed */
	if (vgenp->flags & VGEN_STARTED) {
		vgen_port_uninit(portp);
	}
	vgen_port_detach(portp);

	DBG1((vgenp->vnetp,
	    "vgen_port_detach_mdeg: exit: port_num(%d)\n", portp->port_num));
}

static int
vgen_update_port(vgen_t *vgenp, md_t *curr_mdp, mde_cookie_t curr_mdex,
	md_t *prev_mdp, mde_cookie_t prev_mdex)
{
	 _NOTE(ARGUNUSED(vgenp, curr_mdp, curr_mdex, prev_mdp, prev_mdex))

	/* XXX: TBD */
	return (DDI_SUCCESS);
}

static uint64_t
vgen_port_stat(vgen_port_t *portp, uint_t stat)
{
	vgen_ldclist_t	*ldclp;
	vgen_ldc_t *ldcp;
	uint64_t	val;

	val = 0;
	ldclp = &portp->ldclist;

	READ_ENTER(&ldclp->rwlock);
	for (ldcp = ldclp->headp; ldcp != NULL; ldcp = ldcp->nextp) {
		val += vgen_ldc_stat(ldcp, stat);
	}
	RW_EXIT(&ldclp->rwlock);

	return (val);
}

/* attach the channel corresponding to the given ldc_id to the port */
static int
vgen_ldc_attach(vgen_port_t *portp, uint64_t ldc_id)
{
	vgen_t 		*vgenp;
	vgen_ldclist_t	*ldclp;
	vgen_ldc_t 	*ldcp, **prev_ldcp;
	ldc_attr_t 	attr;
	int 		status;
	ldc_status_t	istatus;
	enum		{AST_init = 0x0, AST_ldc_alloc = 0x1,
			AST_mutex_init = 0x2, AST_ldc_init = 0x4,
			AST_ldc_reg_cb = 0x8, AST_alloc_tx_ring = 0x10,
			AST_create_rxmblks = 0x20}
			attach_state;

	attach_state = AST_init;
	vgenp = portp->vgenp;
	ldclp = &portp->ldclist;

	ldcp = kmem_zalloc(sizeof (vgen_ldc_t), KM_NOSLEEP);
	if (ldcp == NULL) {
		goto ldc_attach_failed;
	}
	ldcp->ldc_id = ldc_id;
	ldcp->portp = portp;
	ldcp->reclaim_lowat = vnet_reclaim_lowat;
	ldcp->reclaim_hiwat = vnet_reclaim_hiwat;

	attach_state |= AST_ldc_alloc;

	mutex_init(&ldcp->txlock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ldcp->cblock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ldcp->tclock, NULL, MUTEX_DRIVER, NULL);

	attach_state |= AST_mutex_init;

	attr.devclass = LDC_DEV_NT;
	attr.instance = ddi_get_instance(vgenp->vnetdip);
	attr.mode = LDC_MODE_UNRELIABLE;
	attr.mtu = vnet_ldc_mtu;
	status = ldc_init(ldc_id, &attr, &ldcp->ldc_handle);
	if (status != 0) {
		DWARN((vgenp->vnetp, "ldc_init failed, id (%lx) rv (%d)\n",
		    ldc_id, status));
		goto ldc_attach_failed;
	}
	attach_state |= AST_ldc_init;

	status = ldc_reg_callback(ldcp->ldc_handle, vgen_ldc_cb, (caddr_t)ldcp);
	if (status != 0) {
		DWARN((vgenp->vnetp,
		    "ldc_reg_callback failed, id (%lx) rv (%d)\n",
		    ldc_id, status));
		goto ldc_attach_failed;
	}
	attach_state |= AST_ldc_reg_cb;

	(void) ldc_status(ldcp->ldc_handle, &istatus);
	ASSERT(istatus == LDC_INIT);
	ldcp->ldc_status = istatus;

	/* allocate transmit resources */
	status = vgen_alloc_tx_ring(ldcp);
	if (status != 0) {
		goto ldc_attach_failed;
	}
	attach_state |= AST_alloc_tx_ring;

	/* allocate receive resources */
	ldcp->num_rbufs = vnet_nrbufs;
	ldcp->rmp = NULL;
	status = vio_create_mblks(ldcp->num_rbufs, VGEN_DBLK_SZ,
		&(ldcp->rmp));
	if (status != 0) {
		goto ldc_attach_failed;
	}
	attach_state |= AST_create_rxmblks;

	/* Setup kstats for the channel */
	status = vgen_setup_kstats(ldcp);
	if (status != VGEN_SUCCESS) {
		goto ldc_attach_failed;
	}

	/* initialize vgen_versions supported */
	bcopy(vgen_versions, ldcp->vgen_versions, sizeof (ldcp->vgen_versions));

	/* link it into the list of channels for this port */
	WRITE_ENTER(&ldclp->rwlock);
	prev_ldcp = (vgen_ldc_t **)(&ldclp->headp);
	ldcp->nextp = *prev_ldcp;
	*prev_ldcp = ldcp;
	ldclp->num_ldcs++;
	RW_EXIT(&ldclp->rwlock);

	ldcp->flags |= CHANNEL_ATTACHED;
	return (DDI_SUCCESS);

ldc_attach_failed:
	if (attach_state & AST_create_rxmblks) {
		(void) vio_destroy_mblks(ldcp->rmp);
	}
	if (attach_state & AST_alloc_tx_ring) {
		vgen_free_tx_ring(ldcp);
	}
	if (attach_state & AST_ldc_reg_cb) {
		(void) ldc_unreg_callback(ldcp->ldc_handle);
	}
	if (attach_state & AST_ldc_init) {
		(void) ldc_fini(ldcp->ldc_handle);
	}
	if (attach_state & AST_mutex_init) {
		mutex_destroy(&ldcp->tclock);
		mutex_destroy(&ldcp->txlock);
		mutex_destroy(&ldcp->cblock);
	}
	if (attach_state & AST_ldc_alloc) {
		KMEM_FREE(ldcp);
	}
	return (DDI_FAILURE);
}

/* detach a channel from the port */
static void
vgen_ldc_detach(vgen_ldc_t *ldcp)
{
	vgen_port_t	*portp;
	vgen_t 		*vgenp;
	vgen_ldc_t 	*pldcp;
	vgen_ldc_t	**prev_ldcp;
	vgen_ldclist_t	*ldclp;

	portp = ldcp->portp;
	vgenp = portp->vgenp;
	ldclp = &portp->ldclist;

	prev_ldcp =  (vgen_ldc_t **)&ldclp->headp;
	for (; (pldcp = *prev_ldcp) != NULL; prev_ldcp = &pldcp->nextp) {
		if (pldcp == ldcp) {
			break;
		}
	}

	if (pldcp == NULL) {
		/* invalid ldcp? */
		return;
	}

	if (ldcp->ldc_status != LDC_INIT) {
		DWARN((vgenp->vnetp,
		    "vgen_ldc_detach: ldc_status is not INIT id(%lx)\n",
			    ldcp->ldc_id));
	}

	if (ldcp->flags & CHANNEL_ATTACHED) {
		ldcp->flags &= ~(CHANNEL_ATTACHED);

		vgen_destroy_kstats(ldcp);

		/* free receive resources */
		if (vio_destroy_mblks(ldcp->rmp)) {
			/*
			 * if we cannot reclaim all mblks, put this
			 * on the list of pools to be reclaimed when the
			 * device gets detached (see vgen_uninit()).
			 */
			ldcp->rmp->nextp =  vgenp->rmp;
			vgenp->rmp = ldcp->rmp;
		}

		/* free transmit resources */
		vgen_free_tx_ring(ldcp);

		(void) ldc_unreg_callback(ldcp->ldc_handle);
		(void) ldc_fini(ldcp->ldc_handle);
		mutex_destroy(&ldcp->tclock);
		mutex_destroy(&ldcp->txlock);
		mutex_destroy(&ldcp->cblock);

		/* unlink it from the list */
		*prev_ldcp = ldcp->nextp;
		ldclp->num_ldcs--;
		KMEM_FREE(ldcp);
	}
}

/*
 * This function allocates transmit resources for the channel.
 * The resources consist of a transmit descriptor ring and an associated
 * transmit buffer ring.
 */
static int
vgen_alloc_tx_ring(vgen_ldc_t *ldcp)
{
	void *tbufp;
	ldc_mem_info_t minfo;
	uint32_t txdsize;
	uint32_t tbufsize;
	int status;
	void *vnetp = LDC_TO_VNET(ldcp);

	ldcp->num_txds = vnet_ntxds;
	txdsize = sizeof (vnet_public_desc_t);
	tbufsize = sizeof (vgen_private_desc_t);

	/* allocate transmit buffer ring */
	tbufp = kmem_zalloc(ldcp->num_txds * tbufsize, KM_NOSLEEP);
	if (tbufp == NULL) {
		return (DDI_FAILURE);
	}

	/* create transmit descriptor ring */
	status = ldc_mem_dring_create(ldcp->num_txds, txdsize,
	    &ldcp->tx_dhandle);
	if (status) {
		DWARN((vnetp, "vgen_alloc_tx_ring: ldc_mem_dring_create() "
		    "failed, id(%lx)\n", ldcp->ldc_id));
		kmem_free(tbufp, ldcp->num_txds * tbufsize);
		return (DDI_FAILURE);
	}

	/* get the addr of descripror ring */
	status = ldc_mem_dring_info(ldcp->tx_dhandle, &minfo);
	if (status) {
		DWARN((vnetp, "vgen_alloc_tx_ring: ldc_mem_dring_info() "
		    "failed, id(%lx)\n", ldcp->ldc_id));
		kmem_free(tbufp, ldcp->num_txds * tbufsize);
		(void) ldc_mem_dring_destroy(ldcp->tx_dhandle);
		ldcp->tbufp = NULL;
		return (DDI_FAILURE);
	}
	ldcp->txdp = (vnet_public_desc_t *)(minfo.vaddr);
	ldcp->tbufp = tbufp;

	ldcp->txdendp = &((ldcp->txdp)[ldcp->num_txds]);
	ldcp->tbufendp = &((ldcp->tbufp)[ldcp->num_txds]);

	return (DDI_SUCCESS);
}

/* Free transmit resources for the channel */
static void
vgen_free_tx_ring(vgen_ldc_t *ldcp)
{
	int tbufsize = sizeof (vgen_private_desc_t);

	/* free transmit descriptor ring */
	(void) ldc_mem_dring_destroy(ldcp->tx_dhandle);

	/* free transmit buffer ring */
	kmem_free(ldcp->tbufp, ldcp->num_txds * tbufsize);
	ldcp->txdp = ldcp->txdendp = NULL;
	ldcp->tbufp = ldcp->tbufendp = NULL;
}

/* enable transmit/receive on the channels for the port */
static void
vgen_init_ldcs(vgen_port_t *portp)
{
	vgen_ldclist_t	*ldclp = &portp->ldclist;
	vgen_ldc_t	*ldcp;

	READ_ENTER(&ldclp->rwlock);
	ldcp =  ldclp->headp;
	for (; ldcp  != NULL; ldcp = ldcp->nextp) {
		(void) vgen_ldc_init(ldcp);
	}
	RW_EXIT(&ldclp->rwlock);
}

/* stop transmit/receive on the channels for the port */
static void
vgen_uninit_ldcs(vgen_port_t *portp)
{
	vgen_ldclist_t	*ldclp = &portp->ldclist;
	vgen_ldc_t	*ldcp;

	READ_ENTER(&ldclp->rwlock);
	ldcp =  ldclp->headp;
	for (; ldcp  != NULL; ldcp = ldcp->nextp) {
		vgen_ldc_uninit(ldcp);
	}
	RW_EXIT(&ldclp->rwlock);
}

/* enable transmit/receive on the channel */
static int
vgen_ldc_init(vgen_ldc_t *ldcp)
{
	void *vnetp = LDC_TO_VNET(ldcp);
	ldc_status_t	istatus;
	int		rv;
	enum		{ ST_init = 0x0, ST_init_tbufs = 0x1,
			    ST_ldc_open = 0x2, ST_dring_bind = 0x4,
			    ST_cb_enable = 0x8
			    }
			init_state;
	uint32_t	ncookies = 0;
	uint32_t	retries = 0;

	init_state = ST_init;

	LDC_LOCK(ldcp);

	rv = ldc_open(ldcp->ldc_handle);
	if (rv != 0) {
		DWARN((vnetp,
		    "vgen_ldcinit: ldc_open failed: id<%lx> rv(%d)\n",
		    ldcp->ldc_id, rv));
		goto ldcinit_failed;
	}
	init_state |= ST_ldc_open;

	(void) ldc_status(ldcp->ldc_handle, &istatus);
	if (istatus != LDC_OPEN && istatus != LDC_READY) {
		DWARN((vnetp,
		    "vgen_ldcinit: id (%lx) status(%d) is not OPEN/READY\n",
		    ldcp->ldc_id, istatus));
		goto ldcinit_failed;
	}
	ldcp->ldc_status = istatus;

	rv = vgen_init_tbufs(ldcp);
	if (rv != 0) {
		DWARN((vnetp,
		    "vgen_ldcinit: vgen_init_tbufs() failed: id(%lx)\n",
		    ldcp->ldc_id));
		goto ldcinit_failed;
	}
	init_state |= ST_init_tbufs;

	/* Bind descriptor ring to the channel */
	rv = ldc_mem_dring_bind(ldcp->ldc_handle, ldcp->tx_dhandle,
	    LDC_SHADOW_MAP, LDC_MEM_RW, &ldcp->tx_dcookie, &ncookies);
	if (rv != 0) {
		DWARN((vnetp, "vgen_ldcinit: id (%lx) "
		    "ldc_mem_dring_bind failed rv(%x)\n", ldcp->ldc_id, rv));
		goto ldcinit_failed;
	}

	ASSERT(ncookies == 1);
	ldcp->num_txdcookies = ncookies;

	init_state |= ST_dring_bind;

	rv = ldc_set_cb_mode(ldcp->ldc_handle, LDC_CB_ENABLE);
	if (rv != 0) {
		DWARN((vnetp, "vgen_ldc_init: id (%lx) "
		    "ldc_set_cb_mode failed\n", ldcp->ldc_id));
		goto ldcinit_failed;
	}

	init_state |= ST_cb_enable;

	do {
		rv = ldc_up(ldcp->ldc_handle);
		if ((rv != 0) && (rv == EWOULDBLOCK)) {
			DBG2((vnetp,
			    "vgen_ldcinit: ldc_up err id(%lx) rv(%d)\n",
			    ldcp->ldc_id, rv));
			drv_usecwait(VGEN_LDC_UP_DELAY);
		}
		if (retries++ >= vgen_ldcup_retries)
			break;
	} while (rv == EWOULDBLOCK);

	(void) ldc_status(ldcp->ldc_handle, &istatus);
	if (istatus != LDC_UP) {
		DBG2((vnetp, "vgen_ldcinit: id(%lx) status(%d) is not UP\n",
		    ldcp->ldc_id, istatus));
	}
	ldcp->ldc_status = istatus;

	/* initialize transmit watchdog timeout */
	ldcp->wd_tid = timeout(vgen_ldc_watchdog, (caddr_t)ldcp,
	    drv_usectohz(vnet_ldcwd_interval * 1000));

	ldcp->flags |= CHANNEL_STARTED;

	LDC_UNLOCK(ldcp);
	return (DDI_SUCCESS);

ldcinit_failed:
	if (init_state & ST_cb_enable) {
		(void) ldc_set_cb_mode(ldcp->ldc_handle, LDC_CB_DISABLE);
	}
	if (init_state & ST_dring_bind) {
		(void) ldc_mem_dring_unbind(ldcp->tx_dhandle);
	}
	if (init_state & ST_init_tbufs) {
		vgen_uninit_tbufs(ldcp);
	}
	if (init_state & ST_ldc_open) {
		(void) ldc_close(ldcp->ldc_handle);
	}
	LDC_UNLOCK(ldcp);
	return (DDI_FAILURE);
}

/* stop transmit/receive on the channel */
static void
vgen_ldc_uninit(vgen_ldc_t *ldcp)
{
	void *vnetp = LDC_TO_VNET(ldcp);
	int	rv;

	DBG1((vnetp, "vgen_ldc_uninit: enter: id(%lx)\n", ldcp->ldc_id));
	LDC_LOCK(ldcp);

	if ((ldcp->flags & CHANNEL_STARTED) == 0) {
		LDC_UNLOCK(ldcp);
		DWARN((vnetp, "vgen_ldc_uninit: id(%lx) CHANNEL_STARTED"
		    " flag is not set\n", ldcp->ldc_id));
		return;
	}

	/* disable further callbacks */
	rv = ldc_set_cb_mode(ldcp->ldc_handle, LDC_CB_DISABLE);
	if (rv != 0) {
		DWARN((vnetp, "vgen_ldc_uninit: id (%lx) "
		    "ldc_set_cb_mode failed\n", ldcp->ldc_id));
	}

	rv = ldc_down(ldcp->ldc_handle);
	if (rv != 0) {
		DWARN((vnetp, "vgen_ldc_uninit: id (%lx) "
		    "ldc_down failed\n", ldcp->ldc_id));
	}

	/* clear handshake done bit and wait for pending tx and cb to finish */
	ldcp->hphase &= ~(VH_DONE);
	LDC_UNLOCK(ldcp);
	drv_usecwait(1000);
	LDC_LOCK(ldcp);

	vgen_reset_hphase(ldcp);

	/* reset transmit watchdog timeout */
	if (ldcp->wd_tid) {
		(void) untimeout(ldcp->wd_tid);
		ldcp->wd_tid = 0;
	}

	/* unbind tx descriptor ring from the channel */
	rv = ldc_mem_dring_unbind(ldcp->tx_dhandle);
	if (rv != 0) {
		DWARN((vnetp, "vgen_ldcuninit: ldc_mem_dring_unbind "
		    "failed id(%lx)\n", ldcp->ldc_id));
	}

	vgen_uninit_tbufs(ldcp);

	rv = ldc_close(ldcp->ldc_handle);
	if (rv != 0) {
		DWARN((vnetp, "vgen_ldcuninit: ldc_close err id(%lx)\n",
		    ldcp->ldc_id));
	}
	ldcp->ldc_status = LDC_INIT;
	ldcp->flags &= ~(CHANNEL_STARTED);

	LDC_UNLOCK(ldcp);

	DBG1((vnetp, "vgen_ldc_uninit: exit: id(%lx)\n", ldcp->ldc_id));
}

/* Initialize the transmit buffer ring for the channel */
static int
vgen_init_tbufs(vgen_ldc_t *ldcp)
{
	vgen_private_desc_t	*tbufp;
	vnet_public_desc_t	*txdp;
	vio_dring_entry_hdr_t		*hdrp;
	int 			i;
	int 			rv;
	caddr_t			datap = NULL;
	int			ci;
	uint32_t		ncookies;

	bzero(ldcp->tbufp, sizeof (*tbufp) * (ldcp->num_txds));
	bzero(ldcp->txdp, sizeof (*txdp) * (ldcp->num_txds));

	datap = kmem_zalloc(ldcp->num_txds * VGEN_DBLK_SZ, KM_SLEEP);
	ldcp->tx_datap = datap;

	/*
	 * for each private descriptor, allocate a ldc mem_handle which is
	 * required to map the data during transmit, set the flags
	 * to free (available for use by transmit routine).
	 */

	for (i = 0; i < ldcp->num_txds; i++) {

		tbufp = &(ldcp->tbufp[i]);
		rv = ldc_mem_alloc_handle(ldcp->ldc_handle,
			&(tbufp->memhandle));
		if (rv) {
			tbufp->memhandle = 0;
			goto init_tbufs_failed;
		}

		/*
		 * bind ldc memhandle to the corresponding transmit buffer.
		 */
		ci = ncookies = 0;
		rv = ldc_mem_bind_handle(tbufp->memhandle,
		    (caddr_t)datap, VGEN_DBLK_SZ, LDC_SHADOW_MAP,
		    LDC_MEM_R, &(tbufp->memcookie[ci]), &ncookies);
		if (rv != 0) {
			goto init_tbufs_failed;
		}

		/*
		 * successful in binding the handle to tx data buffer.
		 * set datap in the private descr to this buffer.
		 */
		tbufp->datap = datap;

		if ((ncookies == 0) ||
			(ncookies > MAX_COOKIES)) {
			goto init_tbufs_failed;
		}

		for (ci = 1; ci < ncookies; ci++) {
			rv = ldc_mem_nextcookie(tbufp->memhandle,
				&(tbufp->memcookie[ci]));
			if (rv != 0) {
				goto init_tbufs_failed;
			}
		}

		tbufp->ncookies = ncookies;
		datap += VGEN_DBLK_SZ;

		tbufp->flags = VGEN_PRIV_DESC_FREE;
		txdp = &(ldcp->txdp[i]);
		hdrp = &txdp->hdr;
		hdrp->dstate = VIO_DESC_FREE;
		hdrp->ack = B_FALSE;
		tbufp->descp = txdp;

	}

	/* reset tbuf walking pointers */
	ldcp->next_tbufp = ldcp->tbufp;
	ldcp->cur_tbufp = ldcp->tbufp;

	/* initialize tx seqnum and index */
	ldcp->next_txseq = VNET_ISS;
	ldcp->next_txi = 0;

	ldcp->resched_peer = B_TRUE;

	return (DDI_SUCCESS);

init_tbufs_failed:;
	vgen_uninit_tbufs(ldcp);
	return (DDI_FAILURE);
}

/* Uninitialize transmit buffer ring for the channel */
static void
vgen_uninit_tbufs(vgen_ldc_t *ldcp)
{
	vgen_private_desc_t	*tbufp = ldcp->tbufp;
	int 			i;

	/* for each tbuf (priv_desc), free ldc mem_handle */
	for (i = 0; i < ldcp->num_txds; i++) {

		tbufp = &(ldcp->tbufp[i]);

		if (tbufp->datap) { /* if bound to a ldc memhandle */
			(void) ldc_mem_unbind_handle(tbufp->memhandle);
			tbufp->datap = NULL;
		}
		if (tbufp->memhandle) {
			(void) ldc_mem_free_handle(tbufp->memhandle);
			tbufp->memhandle = 0;
		}
	}

	if (ldcp->tx_datap) {
		/* prealloc'd tx data buffer */
		kmem_free(ldcp->tx_datap, ldcp->num_txds * VGEN_DBLK_SZ);
		ldcp->tx_datap = NULL;
	}

	bzero(ldcp->tbufp, sizeof (vgen_private_desc_t) * (ldcp->num_txds));
	bzero(ldcp->txdp, sizeof (vnet_public_desc_t) * (ldcp->num_txds));
}

/* clobber tx descriptor ring */
static void
vgen_clobber_tbufs(vgen_ldc_t *ldcp)
{
	vnet_public_desc_t	*txdp;
	vgen_private_desc_t	*tbufp;
	vio_dring_entry_hdr_t		*hdrp;
	void *vnetp = LDC_TO_VNET(ldcp);
	int i;
#ifdef DEBUG
	int ndone = 0;
#endif

	for (i = 0; i < ldcp->num_txds; i++) {

		tbufp = &(ldcp->tbufp[i]);
		txdp = tbufp->descp;
		hdrp = &txdp->hdr;

		if (tbufp->flags & VGEN_PRIV_DESC_BUSY) {
			tbufp->flags = VGEN_PRIV_DESC_FREE;
#ifdef DEBUG
			if (hdrp->dstate == VIO_DESC_DONE)
				ndone++;
#endif
			hdrp->dstate = VIO_DESC_FREE;
			hdrp->ack = B_FALSE;
		}
	}
	/* reset tbuf walking pointers */
	ldcp->next_tbufp = ldcp->tbufp;
	ldcp->cur_tbufp = ldcp->tbufp;

	/* reset tx seqnum and index */
	ldcp->next_txseq = VNET_ISS;
	ldcp->next_txi = 0;

	ldcp->resched_peer = B_TRUE;

#ifdef DEBUG
	DBG2((vnetp,
	    "vgen_clobber_tbufs: id(0x%lx) num descrs done (%d)\n",
	    ldcp->ldc_id, ndone));
#endif
}

/* clobber receive descriptor ring */
static void
vgen_clobber_rxds(vgen_ldc_t *ldcp)
{
	ldcp->rx_dhandle = 0;
	bzero(&ldcp->rx_dcookie, sizeof (ldcp->rx_dcookie));
	ldcp->rxdp = NULL;
	ldcp->next_rxi = 0;
	ldcp->num_rxds = 0;
	ldcp->next_rxseq = VNET_ISS;
}

/* initialize receive descriptor ring */
static int
vgen_init_rxds(vgen_ldc_t *ldcp, uint32_t num_desc, uint32_t desc_size,
	ldc_mem_cookie_t *dcookie, uint32_t ncookies)
{
	int rv;
	ldc_mem_info_t minfo;

	rv = ldc_mem_dring_map(ldcp->ldc_handle, dcookie, ncookies, num_desc,
	    desc_size, LDC_SHADOW_MAP, &(ldcp->rx_dhandle));
	if (rv != 0) {
		return (DDI_FAILURE);
	}

	/*
	 * sucessfully mapped, now try to
	 * get info about the mapped dring
	 */
	rv = ldc_mem_dring_info(ldcp->rx_dhandle, &minfo);
	if (rv != 0) {
		(void) ldc_mem_dring_unmap(ldcp->rx_dhandle);
		return (DDI_FAILURE);
	}

	/*
	 * save ring address, number of descriptors.
	 */
	ldcp->rxdp = (vnet_public_desc_t *)(minfo.vaddr);
	bcopy(dcookie, &(ldcp->rx_dcookie), sizeof (*dcookie));
	ldcp->num_rxdcookies = ncookies;
	ldcp->num_rxds = num_desc;
	ldcp->next_rxi = 0;
	ldcp->next_rxseq = VNET_ISS;

	return (DDI_SUCCESS);
}

/* get channel statistics */
static uint64_t
vgen_ldc_stat(vgen_ldc_t *ldcp, uint_t stat)
{
	vgen_stats_t *statsp;
	uint64_t val;

	val = 0;
	statsp = ldcp->statsp;
	switch (stat) {

	case MAC_STAT_MULTIRCV:
		val = statsp->multircv;
		break;

	case MAC_STAT_BRDCSTRCV:
		val = statsp->brdcstrcv;
		break;

	case MAC_STAT_MULTIXMT:
		val = statsp->multixmt;
		break;

	case MAC_STAT_BRDCSTXMT:
		val = statsp->brdcstxmt;
		break;

	case MAC_STAT_NORCVBUF:
		val = statsp->norcvbuf;
		break;

	case MAC_STAT_IERRORS:
		val = statsp->ierrors;
		break;

	case MAC_STAT_NOXMTBUF:
		val = statsp->noxmtbuf;
		break;

	case MAC_STAT_OERRORS:
		val = statsp->oerrors;
		break;

	case MAC_STAT_COLLISIONS:
		break;

	case MAC_STAT_RBYTES:
		val = statsp->rbytes;
		break;

	case MAC_STAT_IPACKETS:
		val = statsp->ipackets;
		break;

	case MAC_STAT_OBYTES:
		val = statsp->obytes;
		break;

	case MAC_STAT_OPACKETS:
		val = statsp->opackets;
		break;

	/* stats not relevant to ldc, return 0 */
	case MAC_STAT_IFSPEED:
	case ETHER_STAT_ALIGN_ERRORS:
	case ETHER_STAT_FCS_ERRORS:
	case ETHER_STAT_FIRST_COLLISIONS:
	case ETHER_STAT_MULTI_COLLISIONS:
	case ETHER_STAT_DEFER_XMTS:
	case ETHER_STAT_TX_LATE_COLLISIONS:
	case ETHER_STAT_EX_COLLISIONS:
	case ETHER_STAT_MACXMT_ERRORS:
	case ETHER_STAT_CARRIER_ERRORS:
	case ETHER_STAT_TOOLONG_ERRORS:
	case ETHER_STAT_XCVR_ADDR:
	case ETHER_STAT_XCVR_ID:
	case ETHER_STAT_XCVR_INUSE:
	case ETHER_STAT_CAP_1000FDX:
	case ETHER_STAT_CAP_1000HDX:
	case ETHER_STAT_CAP_100FDX:
	case ETHER_STAT_CAP_100HDX:
	case ETHER_STAT_CAP_10FDX:
	case ETHER_STAT_CAP_10HDX:
	case ETHER_STAT_CAP_ASMPAUSE:
	case ETHER_STAT_CAP_PAUSE:
	case ETHER_STAT_CAP_AUTONEG:
	case ETHER_STAT_ADV_CAP_1000FDX:
	case ETHER_STAT_ADV_CAP_1000HDX:
	case ETHER_STAT_ADV_CAP_100FDX:
	case ETHER_STAT_ADV_CAP_100HDX:
	case ETHER_STAT_ADV_CAP_10FDX:
	case ETHER_STAT_ADV_CAP_10HDX:
	case ETHER_STAT_ADV_CAP_ASMPAUSE:
	case ETHER_STAT_ADV_CAP_PAUSE:
	case ETHER_STAT_ADV_CAP_AUTONEG:
	case ETHER_STAT_LP_CAP_1000FDX:
	case ETHER_STAT_LP_CAP_1000HDX:
	case ETHER_STAT_LP_CAP_100FDX:
	case ETHER_STAT_LP_CAP_100HDX:
	case ETHER_STAT_LP_CAP_10FDX:
	case ETHER_STAT_LP_CAP_10HDX:
	case ETHER_STAT_LP_CAP_ASMPAUSE:
	case ETHER_STAT_LP_CAP_PAUSE:
	case ETHER_STAT_LP_CAP_AUTONEG:
	case ETHER_STAT_LINK_ASMPAUSE:
	case ETHER_STAT_LINK_PAUSE:
	case ETHER_STAT_LINK_AUTONEG:
	case ETHER_STAT_LINK_DUPLEX:
	default:
		val = 0;
		break;

	}
	return (val);
}

/* Interrupt handler for the channel */
static uint_t
vgen_ldc_cb(uint64_t event, caddr_t arg)
{
	_NOTE(ARGUNUSED(event))
	vgen_ldc_t	*ldcp;
	void 		*vnetp;
	vgen_t		*vgenp;
	size_t		msglen;
	ldc_status_t 	istatus;
	uint64_t	ldcmsg[7];
	int 		rv;
	vio_msg_tag_t	*tagp;
	mblk_t		*mp = NULL;
	mblk_t		*bp = NULL;
	mblk_t		*bpt = NULL;
	mblk_t		*headp = NULL;
	mblk_t		*tailp = NULL;
	vgen_stats_t	*statsp;

	ldcp = (vgen_ldc_t *)arg;
	vgenp = LDC_TO_VGEN(ldcp);
	vnetp = LDC_TO_VNET(ldcp);
	statsp = ldcp->statsp;

	DBG1((vnetp, "vgen_ldc_cb enter: ldcid (%lx)\n", ldcp->ldc_id));

	mutex_enter(&ldcp->cblock);
	statsp->callbacks++;
	if ((ldcp->ldc_status == LDC_INIT) || (ldcp->ldc_handle == NULL)) {
		DWARN((vnetp, "vgen_ldc_cb: id(%lx), status(%d) is LDC_INIT\n",
		    ldcp->ldc_id, ldcp->ldc_status));
		mutex_exit(&ldcp->cblock);
		return (LDC_SUCCESS);
	}

	/* check ldc status change events first */
	(void) ldc_status(ldcp->ldc_handle, &istatus);

	if (istatus != ldcp->ldc_status) {
		switch (istatus) {
		case LDC_UP:
			ldcp->ldc_status = istatus;
			DBG1((vnetp,
			    "vgen_ldc_cb: id(%lx) status(%d) is LDC_UP\n",
			    ldcp->ldc_id, ldcp->ldc_status));

			if (ldcp->portp != vgenp->vsw_portp) {
				/*
				 * modify fdb entry to use this port as the
				 * channel is up, instead of going through the
				 * vsw-port (see comments in vgen_port_init())
				 */
				vnet_modify_fdb(vnetp,
				    (uint8_t *)&ldcp->portp->macaddr,
				    vgen_tx, ldcp->portp);
			}
			/* Initialize local session id */
			ldcp->local_sid = ddi_get_lbolt();
			/* clear peer session id */
			ldcp->peer_sid = 0;
			ldcp->hretries = 0;
			/* Initiate Handshake process with peer ldc endpoint */
			vgen_handshake_reset(ldcp);
			vgen_handshake(vh_nextphase(ldcp));
			break;

		case LDC_OPEN:
		case LDC_READY:
			ldcp->ldc_status = istatus;
			if ((ldcp->portp != vgenp->vsw_portp) &&
				(vgenp->vsw_portp != NULL)) {
				/*
				 * modify fdb entry to use vsw-port  as the
				 * channel is reset and we don't have a direct
				 * link to the destination (see comments
				 * in vgen_port_init()).
				 */
				vnet_modify_fdb(vnetp,
				    (uint8_t *)&ldcp->portp->macaddr,
				    vgen_tx, vgenp->vsw_portp);
			}
			/* clear sids */
			ldcp->local_sid = 0;
			ldcp->peer_sid = 0;
			if (ldcp->hphase != VH_PHASE0) {
				vgen_handshake_reset(ldcp);
			}
			DBG1((vnetp,
			    "vgen_ldc_cb: id(%lx) status is (%d)\n",
			    ldcp->ldc_id, ldcp->ldc_status));
			break;

		default:
			DWARN((vnetp,
			    "vgen_ldc_cb: id(%lx) istatus=(%d) status(%d) is"
			    " *UNKNOWN*\n",
			    ldcp->ldc_id, istatus, ldcp->ldc_status));
			break;
		}
	}

	if (istatus != LDC_UP) {
		DBG1((vnetp, "vgen_ldc_cb: id(%lx) status(%d) is NOT LDC_UP\n",
			    ldcp->ldc_id, ldcp->ldc_status));
		mutex_exit(&ldcp->cblock);
		return (LDC_SUCCESS);
	}

	/* if ldc_status is UP, receive all packets */
	do {
		msglen = sizeof (ldcmsg);
		rv = ldc_read(ldcp->ldc_handle, (caddr_t)&ldcmsg, &msglen);

		if (rv != 0) {
			DWARN((vnetp,
			    "vgen_ldc_cb:ldc_read err id(%lx) rv(%d) "
			    "len(%d)\n", ldcp->ldc_id, rv, msglen));
			break;
		}
		if (msglen == 0) {
			DBG2((vnetp, "vgen_ldc_cb: ldc_read id(%lx) NODATA",
			ldcp->ldc_id));
			break;
		}
		DBG2((vnetp, "vgen_ldc_cb: ldc_read id(%lx): msglen(%d)",
		    ldcp->ldc_id, msglen));

		tagp = (vio_msg_tag_t *)ldcmsg;

		if (ldcp->peer_sid) {
			/*
			 * check sid only after we have received peer's sid
			 * in the version negotiate msg.
			 */
#ifdef DEBUG
			if (vgen_hdbg & HDBG_BAD_SID) {
				/* simulate bad sid condition */
				tagp->vio_sid = 0;
				vgen_hdbg &= ~(HDBG_BAD_SID);
			}
#endif
			if (vgen_check_sid(ldcp, tagp) == VGEN_FAILURE) {
				/*
				 * If sid mismatch is detected,
				 * reset the channel.
				 */
				ldcp->need_ldc_reset = B_TRUE;
				vgen_handshake_reset(ldcp);
				mutex_exit(&ldcp->cblock);
				return (LDC_SUCCESS);
			}
		}

		switch (tagp->vio_msgtype) {
		case VIO_TYPE_CTRL:
			vgen_handle_ctrlmsg(ldcp, tagp);
			break;

		case VIO_TYPE_DATA:
			headp = tailp = NULL;
			vgen_handle_datamsg(ldcp, tagp, &headp, &tailp);
			/* build a chain of received packets */
			if (headp != NULL) {
				if (bp == NULL) {
					bp = headp;
					bpt = tailp;
				} else {
					bpt->b_next = headp;
					bpt = tailp;
				}
			}
			break;

		case VIO_TYPE_ERR:
			vgen_handle_errmsg(ldcp, tagp);
			break;

		default:
			DWARN((vnetp,
			    "vgen_ldc_cb: Unknown VIO_TYPE(%x)\n",
			    tagp->vio_msgtype));
			break;
		}

	} while (msglen);

	mutex_exit(&ldcp->cblock);
	/* send up the received packets to MAC layer */
	while (bp != NULL) {
		mp = bp;
		bp = bp->b_next;
		mp->b_next = mp->b_prev = NULL;
		DBG2((vnetp, "vgen_ldc_cb: id(%lx) rx pkt len (%lx)\n",
		    ldcp->ldc_id, MBLKL(mp)));
		vnet_rx(vgenp->vnetp, NULL, mp);
	}
	DBG1((vnetp, "vgen_ldc_cb exit: ldcid (%lx)\n", ldcp->ldc_id));

	return (LDC_SUCCESS);
}

/* vgen handshake functions */

/* change the hphase for the channel to the next phase */
static vgen_ldc_t *
vh_nextphase(vgen_ldc_t *ldcp)
{
	if (ldcp->hphase == VH_PHASE3) {
		ldcp->hphase = VH_DONE;
	} else {
		ldcp->hphase++;
	}
	return (ldcp);
}

/*
 * Check whether the given version is supported or not and
 * return VGEN_SUCCESS if supported.
 */
static int
vgen_supported_version(vgen_ldc_t *ldcp, uint16_t ver_major,
uint16_t ver_minor)
{
	vgen_ver_t	*versions = ldcp->vgen_versions;
	int		i = 0;

	while (i < VGEN_NUM_VER) {
		if ((versions[i].ver_major == 0) &&
		    (versions[i].ver_minor == 0)) {
			break;
		}
		if ((versions[i].ver_major == ver_major) &&
			(versions[i].ver_minor == ver_minor)) {
			return (VGEN_SUCCESS);
		}
		i++;
	}
	return (VGEN_FAILURE);
}

/*
 * Given a version, return VGEN_SUCCESS if a lower version is supported.
 */
static int
vgen_next_version(vgen_ldc_t *ldcp, vgen_ver_t *verp)
{
	vgen_ver_t	*versions = ldcp->vgen_versions;
	int		i = 0;

	while (i < VGEN_NUM_VER) {
		if ((versions[i].ver_major == 0) &&
		    (versions[i].ver_minor == 0)) {
			break;
		}
		/*
		 * if we support a lower minor version within the same major
		 * version, or if we support a lower major version,
		 * update the verp parameter with this lower version and
		 * return success.
		 */
		if (((versions[i].ver_major == verp->ver_major) &&
			(versions[i].ver_minor < verp->ver_minor)) ||
			(versions[i].ver_major < verp->ver_major)) {
				verp->ver_major = versions[i].ver_major;
				verp->ver_minor = versions[i].ver_minor;
				return (VGEN_SUCCESS);
		}
		i++;
	}

	return (VGEN_FAILURE);
}

/*
 * wrapper routine to send the given message over ldc using ldc_write().
 */
static int
vgen_sendmsg(vgen_ldc_t *ldcp, caddr_t msg,  size_t msglen,
    boolean_t caller_holds_lock)
{
	int	rv;
	size_t	len;
	void *vnetp = LDC_TO_VNET(ldcp);
	uint32_t retries = 0;

	len = msglen;
	if ((len == 0) || (msg == NULL))
		return (VGEN_FAILURE);

	if (!caller_holds_lock) {
		mutex_enter(&ldcp->txlock);
	}

	do {
		len = msglen;
		rv = ldc_write(ldcp->ldc_handle, (caddr_t)msg, &len);
		if (retries++ >= vgen_ldcwr_retries)
			break;
	} while (rv == EWOULDBLOCK);

	if (!caller_holds_lock) {
		mutex_exit(&ldcp->txlock);
	}

	if ((rv != 0) || (len != msglen)) {
		DWARN((vnetp,
		    "vgen_sendmsg: ldc_write failed: id(%lx) rv(%d)"
		    " msglen (%d)\n", ldcp->ldc_id, rv, msglen));
		return (VGEN_FAILURE);
	}
	return (VGEN_SUCCESS);
}

/* send version negotiate message to the peer over ldc */
static int
vgen_send_version_negotiate(vgen_ldc_t *ldcp)
{
	vio_ver_msg_t	vermsg;
	vio_msg_tag_t	*tagp = &vermsg.tag;
	void		*vnetp = LDC_TO_VNET(ldcp);
	int		rv;

	bzero(&vermsg, sizeof (vermsg));

	tagp->vio_msgtype = VIO_TYPE_CTRL;
	tagp->vio_subtype = VIO_SUBTYPE_INFO;
	tagp->vio_subtype_env = VIO_VER_INFO;
	tagp->vio_sid = ldcp->local_sid;

	/* get version msg payload from ldcp->local */
	vermsg.ver_major = ldcp->local_hparams.ver_major;
	vermsg.ver_minor = ldcp->local_hparams.ver_minor;
	vermsg.dev_class = ldcp->local_hparams.dev_class;

	rv = vgen_sendmsg(ldcp, (caddr_t)tagp, sizeof (vermsg), B_FALSE);
	if (rv != VGEN_SUCCESS) {
		DWARN((vnetp, "vgen_send_version_negotiate: vgen_sendmsg failed"
		    "id (%lx)\n", ldcp->ldc_id));
		return (VGEN_FAILURE);
	}

	ldcp->hstate |= VER_INFO_SENT;
	DBG2((vnetp,
	    "vgen_send_version_negotiate: VER_INFO_SENT id (%lx) ver(%d,%d)\n",
	    ldcp->ldc_id, vermsg.ver_major, vermsg.ver_minor));

	return (VGEN_SUCCESS);
}

/* send attr info message to the peer over ldc */
static int
vgen_send_attr_info(vgen_ldc_t *ldcp)
{
	vnet_attr_msg_t	attrmsg;
	vio_msg_tag_t	*tagp = &attrmsg.tag;
	void		*vnetp = LDC_TO_VNET(ldcp);
	int		rv;

	bzero(&attrmsg, sizeof (attrmsg));

	tagp->vio_msgtype = VIO_TYPE_CTRL;
	tagp->vio_subtype = VIO_SUBTYPE_INFO;
	tagp->vio_subtype_env = VIO_ATTR_INFO;
	tagp->vio_sid = ldcp->local_sid;

	/* get attr msg payload from ldcp->local */
	attrmsg.mtu = ldcp->local_hparams.mtu;
	attrmsg.addr = ldcp->local_hparams.addr;
	attrmsg.addr_type = ldcp->local_hparams.addr_type;
	attrmsg.xfer_mode = ldcp->local_hparams.xfer_mode;
	attrmsg.ack_freq = ldcp->local_hparams.ack_freq;

	rv = vgen_sendmsg(ldcp, (caddr_t)tagp, sizeof (attrmsg), B_FALSE);
	if (rv != VGEN_SUCCESS) {
		DWARN((vnetp, "vgen_send_attr_info: vgen_sendmsg failed"
		    "id (%lx)\n", ldcp->ldc_id));
		return (VGEN_FAILURE);
	}

	ldcp->hstate |= ATTR_INFO_SENT;
	DBG2((vnetp, "vgen_send_attr_info: ATTR_INFO_SENT id (%lx)\n",
	    ldcp->ldc_id));

	return (VGEN_SUCCESS);
}

/* send descriptor ring register message to the peer over ldc */
static int
vgen_send_dring_reg(vgen_ldc_t *ldcp)
{
	vio_dring_reg_msg_t	msg;
	vio_msg_tag_t		*tagp = &msg.tag;
	void		*vnetp = LDC_TO_VNET(ldcp);
	int		rv;

	bzero(&msg, sizeof (msg));

	tagp->vio_msgtype = VIO_TYPE_CTRL;
	tagp->vio_subtype = VIO_SUBTYPE_INFO;
	tagp->vio_subtype_env = VIO_DRING_REG;
	tagp->vio_sid = ldcp->local_sid;

	/* get dring info msg payload from ldcp->local */
	bcopy(&(ldcp->local_hparams.dring_cookie), (msg.cookie),
		sizeof (ldc_mem_cookie_t));
	msg.ncookies = ldcp->local_hparams.num_dcookies;
	msg.num_descriptors = ldcp->local_hparams.num_desc;
	msg.descriptor_size = ldcp->local_hparams.desc_size;

	/*
	 * dring_ident is set to 0. After mapping the dring, peer sets this
	 * value and sends it in the ack, which is saved in
	 * vgen_handle_dring_reg().
	 */
	msg.dring_ident = 0;

	rv = vgen_sendmsg(ldcp, (caddr_t)tagp, sizeof (msg), B_FALSE);
	if (rv != VGEN_SUCCESS) {
		DWARN((vnetp, "vgen_send_dring_reg: vgen_sendmsg failed"
		    "id (%lx)\n", ldcp->ldc_id));
		return (VGEN_FAILURE);
	}

	ldcp->hstate |= DRING_INFO_SENT;
	DBG2((vnetp, "vgen_send_dring_reg: DRING_INFO_SENT id (%lx)\n",
	    ldcp->ldc_id));

	return (VGEN_SUCCESS);
}

static int
vgen_send_rdx_info(vgen_ldc_t *ldcp)
{
	vio_rdx_msg_t	rdxmsg;
	vio_msg_tag_t	*tagp = &rdxmsg.tag;
	void		*vnetp = LDC_TO_VNET(ldcp);
	int		rv;

	bzero(&rdxmsg, sizeof (rdxmsg));

	tagp->vio_msgtype = VIO_TYPE_CTRL;
	tagp->vio_subtype = VIO_SUBTYPE_INFO;
	tagp->vio_subtype_env = VIO_RDX;
	tagp->vio_sid = ldcp->local_sid;

	rv = vgen_sendmsg(ldcp, (caddr_t)tagp, sizeof (rdxmsg), B_FALSE);
	if (rv != VGEN_SUCCESS) {
		DWARN((vnetp, "vgen_send_rdx_info: vgen_sendmsg failed"
		    "id (%lx)\n", ldcp->ldc_id));
		return (VGEN_FAILURE);
	}

	ldcp->hstate |= RDX_INFO_SENT;
	DBG2((vnetp, "vgen_send_rdx_info: RDX_INFO_SENT id (%lx)\n",
	    ldcp->ldc_id));

	return (VGEN_SUCCESS);
}

/* send descriptor ring data message to the peer over ldc */
static int
vgen_send_dring_data(vgen_ldc_t *ldcp, uint32_t start, int32_t end)
{
	vio_dring_msg_t	dringmsg, *msgp = &dringmsg;
	vio_msg_tag_t	*tagp = &msgp->tag;
	void		*vnetp = LDC_TO_VNET(ldcp);
	int		rv;

	bzero(msgp, sizeof (*msgp));

	tagp->vio_msgtype = VIO_TYPE_DATA;
	tagp->vio_subtype = VIO_SUBTYPE_INFO;
	tagp->vio_subtype_env = VIO_DRING_DATA;
	tagp->vio_sid = ldcp->local_sid;

	msgp->seq_num = ldcp->next_txseq;
	msgp->dring_ident = ldcp->local_hparams.dring_ident;
	msgp->start_idx = start;
	msgp->end_idx = end;

	rv = vgen_sendmsg(ldcp, (caddr_t)tagp, sizeof (dringmsg), B_TRUE);
	if (rv != VGEN_SUCCESS) {
		DWARN((vnetp, "vgen_send_dring_data: vgen_sendmsg failed"
		    "id (%lx)\n", ldcp->ldc_id));
		return (VGEN_FAILURE);
	}

	ldcp->next_txseq++;
	ldcp->statsp->dring_data_msgs++;

	DBG2((vnetp, "vgen_send_dring_data: DRING_DATA_SENT id (%lx)\n",
	    ldcp->ldc_id));

	return (VGEN_SUCCESS);
}

/* send multicast addr info message to vsw */
static int
vgen_send_mcast_info(vgen_ldc_t *ldcp)
{
	vnet_mcast_msg_t	mcastmsg;
	vnet_mcast_msg_t	*msgp;
	vio_msg_tag_t		*tagp;
	vgen_t			*vgenp;
	void			*vnetp;
	struct ether_addr	*mca;
	int			rv;
	int			i;
	uint32_t		size;
	uint32_t		mccount;
	uint32_t		n;

	msgp = &mcastmsg;
	tagp = &msgp->tag;
	vgenp = LDC_TO_VGEN(ldcp);
	vnetp = LDC_TO_VNET(ldcp);

	mccount = vgenp->mccount;
	i = 0;

	do {
		tagp->vio_msgtype = VIO_TYPE_CTRL;
		tagp->vio_subtype = VIO_SUBTYPE_INFO;
		tagp->vio_subtype_env = VNET_MCAST_INFO;
		tagp->vio_sid = ldcp->local_sid;

		n = ((mccount >= VNET_NUM_MCAST) ? VNET_NUM_MCAST : mccount);
		size = n * sizeof (struct ether_addr);

		mca = &(vgenp->mctab[i]);
		bcopy(mca, (msgp->mca), size);
		msgp->set = B_TRUE;
		msgp->count = n;

		rv = vgen_sendmsg(ldcp, (caddr_t)tagp, sizeof (*msgp),
		    B_FALSE);
		if (rv != VGEN_SUCCESS) {
			DWARN((vnetp, "vgen_send_mcast_info: vgen_sendmsg err"
			    "id (%lx)\n", ldcp->ldc_id));
			return (VGEN_FAILURE);
		}

		mccount -= n;
		i += n;

	} while (mccount);

	return (VGEN_SUCCESS);
}

/* Initiate Phase 2 of handshake */
static int
vgen_handshake_phase2(vgen_ldc_t *ldcp)
{
	int rv;
#ifdef DEBUG
	if (vgen_hdbg & HDBG_OUT_STATE) {
		/* simulate out of state condition */
		vgen_hdbg &= ~(HDBG_OUT_STATE);
		rv = vgen_send_rdx_info(ldcp);
		return (rv);
	}
	if (vgen_hdbg & HDBG_TIMEOUT) {
		/* simulate timeout condition */
		vgen_hdbg &= ~(HDBG_TIMEOUT);
		return (VGEN_SUCCESS);
	}
#endif
	if ((rv = vgen_send_attr_info(ldcp)) != VGEN_SUCCESS) {
		return (rv);
	}
	if ((rv = vgen_send_dring_reg(ldcp)) != VGEN_SUCCESS) {
		return (rv);
	}

	return (VGEN_SUCCESS);
}

/*
 * This function resets the handshake phase to VH_PHASE0(pre-handshake phase).
 * This can happen after a channel comes up (status: LDC_UP) or
 * when handshake gets terminated due to various conditions.
 */
static void
vgen_reset_hphase(vgen_ldc_t *ldcp)
{
	vgen_t	*vgenp = LDC_TO_VGEN(ldcp);
	void	*vnetp = LDC_TO_VNET(ldcp);
	ldc_status_t istatus;

	DBG2((vnetp, "vgen_reset_hphase: id(0x%lx)\n", ldcp->ldc_id));
	/* reset hstate and hphase */
	ldcp->hstate = 0;
	ldcp->hphase = VH_PHASE0;

	/* reset handshake watchdog timeout */
	if (ldcp->htid) {
		(void) untimeout(ldcp->htid);
		ldcp->htid = 0;
	}

	/*
	 * Unmap drings, if dring_ready is set.
	 */
	if (ldcp->local_hparams.dring_ready) {
		ldcp->local_hparams.dring_ready = B_FALSE;
		/* do not unbind our dring */
	}

	if (ldcp->peer_hparams.dring_ready) {
		ldcp->peer_hparams.dring_ready = B_FALSE;
		/* Unmap peer's dring */
		(void) ldc_mem_dring_unmap(ldcp->rx_dhandle);
		vgen_clobber_rxds(ldcp);
	}

	vgen_clobber_tbufs(ldcp);

	/*
	 * clear local handshake params and initialize.
	 */
	bzero(&(ldcp->local_hparams), sizeof (ldcp->local_hparams));

	/* set version to the highest version supported */
	ldcp->local_hparams.ver_major =
			ldcp->vgen_versions[0].ver_major;
	ldcp->local_hparams.ver_minor =
			ldcp->vgen_versions[0].ver_minor;
	ldcp->local_hparams.dev_class = VDEV_NETWORK;

	/* set attr_info params */
	ldcp->local_hparams.mtu = ETHERMAX;
	ldcp->local_hparams.addr =
		vgen_macaddr_strtoul(vgenp->macaddr);
	ldcp->local_hparams.addr_type = ADDR_TYPE_MAC;
	ldcp->local_hparams.xfer_mode = VIO_DRING_MODE;
	ldcp->local_hparams.ack_freq = 0;	/* don't need acks */

	/*
	 * set dring_info params.
	 * Note: dring is already created and bound.
	 */
	bcopy(&(ldcp->tx_dcookie), &(ldcp->local_hparams.dring_cookie),
		sizeof (ldc_mem_cookie_t));
	ldcp->local_hparams.num_dcookies = ldcp->num_txdcookies;
	ldcp->local_hparams.num_desc = ldcp->num_txds;
	ldcp->local_hparams.desc_size = sizeof (vnet_public_desc_t);

	/*
	 * dring_ident is set to 0. After mapping the dring, peer sets this
	 * value and sends it in the ack, which is saved in
	 * vgen_handle_dring_reg().
	 */
	ldcp->local_hparams.dring_ident = 0;

	/* clear peer_hparams */
	bzero(&(ldcp->peer_hparams), sizeof (ldcp->peer_hparams));

	/* reset the channel if required */
	if (ldcp->need_ldc_reset) {
		DWARN((vnetp,
		    "vgen_reset_hphase: id (%lx), Doing Channel Reset...\n",
		    ldcp->ldc_id));
		ldcp->need_ldc_reset = B_FALSE;
		(void) ldc_down(ldcp->ldc_handle);
		(void) ldc_status(ldcp->ldc_handle, &istatus);
		DBG2((vnetp,
		    "vgen_reset_hphase: id (%lx), RESET Done,ldc_status(%x)\n",
		    ldcp->ldc_id, istatus));
		ldcp->ldc_status = istatus;
		/* clear sids */
		ldcp->local_sid = 0;
		ldcp->peer_sid = 0;
		(void) ldc_up(ldcp->ldc_handle);
	}
}

/* wrapper function for vgen_reset_hphase */
static void
vgen_handshake_reset(vgen_ldc_t *ldcp)
{
	ASSERT(MUTEX_HELD(&ldcp->cblock));
	mutex_enter(&ldcp->txlock);
	mutex_enter(&ldcp->tclock);

	vgen_reset_hphase(ldcp);

	mutex_exit(&ldcp->tclock);
	mutex_exit(&ldcp->txlock);
}

/*
 * Initiate handshake with the peer by sending various messages
 * based on the handshake-phase that the channel is currently in.
 */
static void
vgen_handshake(vgen_ldc_t *ldcp)
{
	uint32_t hphase = ldcp->hphase;
	void	*vnetp = LDC_TO_VNET(ldcp);
	vgen_t	*vgenp = LDC_TO_VGEN(ldcp);

	switch (hphase) {

	case VH_PHASE1:

		/*
		 * start timer, for entire handshake process, turn this timer
		 * off if all phases of handshake complete successfully and
		 * hphase goes to VH_DONE(below) or
		 * vgen_reset_hphase() gets called or
		 * channel is reset due to errors or
		 * vgen_ldc_uninit() is invoked(vgen_stop).
		 */
		ldcp->htid = timeout(vgen_hwatchdog, (caddr_t)ldcp,
		    drv_usectohz(vgen_hwd_interval * 1000));

		/* Phase 1 involves negotiating the version */
		if (vgen_send_version_negotiate(ldcp) != VGEN_SUCCESS) {
			vgen_handshake_reset(ldcp);
		}
		break;

	case VH_PHASE2:
		if (vgen_handshake_phase2(ldcp) != VGEN_SUCCESS) {
			vgen_handshake_reset(ldcp);
		}
		break;

	case VH_PHASE3:
		if (vgen_send_rdx_info(ldcp) != VGEN_SUCCESS) {
			vgen_handshake_reset(ldcp);
		}
		break;

	case VH_DONE:
		/* reset handshake watchdog timeout */
		if (ldcp->htid) {
			(void) untimeout(ldcp->htid);
			ldcp->htid = 0;
		}
		ldcp->hretries = 0;
#if 0
		vgen_print_ldcinfo(ldcp);
#endif
		DBG1((vnetp, "vgen_handshake: id(0x%lx) Handshake Done\n",
		    ldcp->ldc_id));

		if (ldcp->need_mcast_sync) {
			/* need to sync multicast table with vsw */

			ldcp->need_mcast_sync = B_FALSE;
			mutex_exit(&ldcp->cblock);

			mutex_enter(&vgenp->lock);
			(void) vgen_send_mcast_info(ldcp);
			mutex_exit(&vgenp->lock);

			mutex_enter(&ldcp->cblock);

		}
		break;

	default:
		break;
	}
}

/*
 * Check if the current handshake phase has completed successfully and
 * return the status.
 */
static int
vgen_handshake_done(vgen_ldc_t *ldcp)
{
	uint32_t	hphase = ldcp->hphase;
	int 		status = 0;
	void		*vnetp = LDC_TO_VNET(ldcp);

	switch (hphase) {

	case VH_PHASE1:
		/*
		 * Phase1 is done, if version negotiation
		 * completed successfully.
		 */
		status = ((ldcp->hstate & VER_NEGOTIATED) ==
			VER_NEGOTIATED);
		break;

	case VH_PHASE2:
		/*
		 * Phase 2 is done, if attr info and dring info
		 * have been exchanged successfully.
		 */
		status = (((ldcp->hstate & ATTR_INFO_EXCHANGED) ==
			    ATTR_INFO_EXCHANGED) &&
			    ((ldcp->hstate & DRING_INFO_EXCHANGED) ==
			    DRING_INFO_EXCHANGED));
		break;

	case VH_PHASE3:
		/* Phase 3 is done, if rdx msg has been exchanged */
		status = ((ldcp->hstate & RDX_EXCHANGED) ==
			RDX_EXCHANGED);
		break;

	default:
		break;
	}

	if (status == 0) {
		return (VGEN_FAILURE);
	}
	DBG2((vnetp, "VNET_HANDSHAKE_DONE: PHASE(%d)\n", hphase));
	return (VGEN_SUCCESS);
}

/* retry handshake on failure */
static void
vgen_handshake_retry(vgen_ldc_t *ldcp)
{
	/* reset handshake phase */
	vgen_handshake_reset(ldcp);
	if (vgen_max_hretries) {	/* handshake retry is specified */
		if (ldcp->hretries++ < vgen_max_hretries)
			vgen_handshake(vh_nextphase(ldcp));
	}
}

/*
 * Handle a version info msg from the peer or an ACK/NACK from the peer
 * to a version info msg that we sent.
 */
static void
vgen_handle_version_negotiate(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp)
{
	vio_ver_msg_t	*vermsg = (vio_ver_msg_t *)tagp;
	int		ack = 0;
	int		failed = 0;
	void		*vnetp = LDC_TO_VNET(ldcp);
	int		idx;
	vgen_ver_t	*versions = ldcp->vgen_versions;

	DBG1((vnetp, "vgen_handle_version_negotiate: enter\n"));
	switch (tagp->vio_subtype) {
	case VIO_SUBTYPE_INFO:

		/*  Cache sid of peer if this is the first time */
		if (ldcp->peer_sid == 0) {
			DBG2((vnetp,
			    "vgen_handle_version_negotiate: id (%lx) Caching"
			    " peer_sid(%x)\n", ldcp->ldc_id, tagp->vio_sid));
			ldcp->peer_sid = tagp->vio_sid;
		}

		if (ldcp->hphase != VH_PHASE1) {
			/*
			 * If we are not already in VH_PHASE1, reset to
			 * pre-handshake state, and initiate handshake
			 * to the peer too.
			 */
			vgen_handshake_reset(ldcp);
			vgen_handshake(vh_nextphase(ldcp));
		}
		ldcp->hstate |= VER_INFO_RCVD;

		/* save peer's requested values */
		ldcp->peer_hparams.ver_major = vermsg->ver_major;
		ldcp->peer_hparams.ver_minor = vermsg->ver_minor;
		ldcp->peer_hparams.dev_class = vermsg->dev_class;

		if ((vermsg->dev_class != VDEV_NETWORK) &&
		    (vermsg->dev_class != VDEV_NETWORK_SWITCH)) {
			/* unsupported dev_class, send NACK */

			tagp->vio_subtype = VIO_SUBTYPE_NACK;
			tagp->vio_sid = ldcp->local_sid;
			/* send reply msg back to peer */
			(void) vgen_sendmsg(ldcp, (caddr_t)tagp,
			    sizeof (*vermsg), B_FALSE);
			DWARN((vnetp,
			    "vgen_handle_version_negotiate: Version"
			    " Negotiation Failed id (%lx)\n", ldcp->ldc_id));
			vgen_handshake_reset(ldcp);
			return;
		}

		DBG2((vnetp, "vgen_handle_version_negotiate: VER_INFO_RCVD,"
		    " id (%lx), ver(%d,%d)\n", ldcp->ldc_id,
		    vermsg->ver_major,  vermsg->ver_minor));

		idx = 0;

		for (;;) {

			if (vermsg->ver_major > versions[idx].ver_major) {

				/* nack with next lower version */
				tagp->vio_subtype = VIO_SUBTYPE_NACK;
				vermsg->ver_major = versions[idx].ver_major;
				vermsg->ver_minor = versions[idx].ver_minor;
				break;
			}

			if (vermsg->ver_major == versions[idx].ver_major) {

				/* major version match - ACK version */
				tagp->vio_subtype = VIO_SUBTYPE_ACK;
				ack = 1;

				/*
				 * lower minor version to the one this endpt
				 * supports, if necessary
				 */
				if (vermsg->ver_minor >
				    versions[idx].ver_minor) {
					vermsg->ver_minor =
						versions[idx].ver_minor;
					ldcp->peer_hparams.ver_minor =
						versions[idx].ver_minor;
				}
				break;
			}

			idx++;

			if (idx == VGEN_NUM_VER) {

				/* no version match - send NACK */
				tagp->vio_subtype = VIO_SUBTYPE_NACK;
				vermsg->ver_major = 0;
				vermsg->ver_minor = 0;
				failed = 1;
				break;
			}

		}

		tagp->vio_sid = ldcp->local_sid;

		/* send reply msg back to peer */
		if (vgen_sendmsg(ldcp, (caddr_t)tagp, sizeof (*vermsg),
		    B_FALSE) != VGEN_SUCCESS) {
			vgen_handshake_reset(ldcp);
			return;
		}

		if (ack) {
			ldcp->hstate |= VER_ACK_SENT;
			DBG2((vnetp, "vgen_handle_version_negotiate:"
			    " VER_ACK_SENT, id (%lx) ver(%d,%d) \n",
			    ldcp->ldc_id, vermsg->ver_major,
			    vermsg->ver_minor));
		}
		if (failed) {
			DWARN((vnetp, "vgen_handle_version_negotiate:"
			    " Version Negotiation Failed id (%lx)\n",
			    ldcp->ldc_id));
			vgen_handshake_reset(ldcp);
			return;
		}
		if (vgen_handshake_done(ldcp) == VGEN_SUCCESS) {

			/*  VER_ACK_SENT and VER_ACK_RCVD */

			/* local and peer versions match? */
			ASSERT((ldcp->local_hparams.ver_major ==
				ldcp->peer_hparams.ver_major) &&
				(ldcp->local_hparams.ver_minor ==
				ldcp->peer_hparams.ver_minor));

			/* move to the next phase */
			vgen_handshake(vh_nextphase(ldcp));
		}

		break;

	case VIO_SUBTYPE_ACK:

		if (ldcp->hphase != VH_PHASE1) {
			/*  This should not happen. */
			DWARN((vnetp,
			    "vgen_handle_version_negotiate:"
			    " VER_ACK_RCVD id (%lx) Invalid Phase(%u)\n",
			    ldcp->ldc_id, ldcp->hphase));
			vgen_handshake_reset(ldcp);
			return;
		}

		/* SUCCESS - we have agreed on a version */
		ldcp->local_hparams.ver_major = vermsg->ver_major;
		ldcp->local_hparams.ver_minor = vermsg->ver_minor;
		ldcp->hstate |= VER_ACK_RCVD;

		DBG2((vnetp, "vgen_handle_version_negotiate:"
		    " VER_ACK_RCVD, id (%lx) ver(%d,%d) \n",
		    ldcp->ldc_id, vermsg->ver_major,  vermsg->ver_minor));

		if (vgen_handshake_done(ldcp) == VGEN_SUCCESS) {

			/*  VER_ACK_SENT and VER_ACK_RCVD */

			/* local and peer versions match? */
			ASSERT((ldcp->local_hparams.ver_major ==
				ldcp->peer_hparams.ver_major) &&
				(ldcp->local_hparams.ver_minor ==
				ldcp->peer_hparams.ver_minor));

			/* move to the next phase */
			vgen_handshake(vh_nextphase(ldcp));
		}
		break;

	case VIO_SUBTYPE_NACK:

		if (ldcp->hphase != VH_PHASE1) {
			/*  This should not happen.  */
			DWARN((vnetp,
			    "vgen_handle_version_negotiate:"
			    " VER_NACK_RCVD id (%lx) Invalid Phase(%u)\n",
			    ldcp->ldc_id, ldcp->hphase));
			vgen_handshake_reset(ldcp);
			return;
		}

		DBG2((vnetp, "vgen_handle_version_negotiate:"
		    " VER_NACK_RCVD id(%lx) next ver(%d,%d)\n",
		    ldcp->ldc_id, vermsg->ver_major, vermsg->ver_minor));

		/* check if version in NACK is zero */
		if (vermsg->ver_major == 0 && vermsg->ver_minor == 0) {
			/*
			 * Version Negotiation has failed.
			 */
			DWARN((vnetp, "vgen_handle_version_negotiate:"
			    " Version Negotiation Failed id (%lx)\n",
			    ldcp->ldc_id));
			vgen_handshake_reset(ldcp);
			return;
		}

		idx = 0;

		for (;;) {

			if (vermsg->ver_major > versions[idx].ver_major) {
				/* select next lower version */

				ldcp->local_hparams.ver_major =
					versions[idx].ver_major;
				ldcp->local_hparams.ver_minor =
					versions[idx].ver_minor;
				break;
			}

			if (vermsg->ver_major == versions[idx].ver_major) {
				/* major version match */

				ldcp->local_hparams.ver_major =
					versions[idx].ver_major;

				ldcp->local_hparams.ver_minor =
					versions[idx].ver_minor;
				break;
			}

			idx++;

			if (idx == VGEN_NUM_VER) {
				/*
				 * no version match.
				 * Version Negotiation has failed.
				 */
				DWARN((vnetp, "vgen_handle_version_negotiate:"
				    " Version Negotiation Failed id (%lx)\n",
				    ldcp->ldc_id));
				vgen_handshake_reset(ldcp);
				return;
			}

		}

		if (vgen_send_version_negotiate(ldcp) != VGEN_SUCCESS) {
			vgen_handshake_reset(ldcp);
			return;
		}

		break;
	}
	DBG1((vnetp, "vgen_handle_version_negotiate: exit\n"));
}

/* Check if the attributes are supported */
static int
vgen_check_attr_info(vgen_ldc_t *ldcp, vnet_attr_msg_t *msg)
{
	_NOTE(ARGUNUSED(ldcp))

#if 0
	uint64_t port_macaddr;
	port_macaddr = vgen_macaddr_strtoul((uint8_t *)
				&(ldcp->portp->macaddr));
#endif
	/*
	 * currently, we support these attr values:
	 * mtu of ethernet, addr_type of mac, xfer_mode of
	 * ldc shared memory, ack_freq of 0 (data is acked if
	 * the ack bit is set in the descriptor) and the address should
	 * match the address in the port node.
	 */
	if ((msg->mtu != ETHERMAX) ||
	    (msg->addr_type != ADDR_TYPE_MAC) ||
	    (msg->xfer_mode != VIO_DRING_MODE) ||
	    (msg->ack_freq > 64)) {
#if 0
	    (msg->addr != port_macaddr))
cmn_err(CE_CONT, "vgen_check_attr_info: msg->addr(%lx), port_macaddr(%lx)\n",
	msg->addr, port_macaddr);
#endif
		return (VGEN_FAILURE);
	}

	return (VGEN_SUCCESS);
}

/*
 * Handle an attribute info msg from the peer or an ACK/NACK from the peer
 * to an attr info msg that we sent.
 */
static void
vgen_handle_attr_info(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp)
{
	vnet_attr_msg_t *attrmsg = (vnet_attr_msg_t *)tagp;
	void		*vnetp = LDC_TO_VNET(ldcp);
	int		ack = 0;

	DBG1((vnetp, "vgen_handle_attr_info: enter\n"));
	if (ldcp->hphase != VH_PHASE2) {
		DWARN((vnetp,
		    "vgen_handle_attr_info: Rcvd ATTR_INFO id(%lx)"
		    " subtype (%d), Invalid Phase(%u)\n", ldcp->ldc_id,
		    tagp->vio_subtype, ldcp->hphase));
		vgen_handshake_reset(ldcp);
		return;
	}
	switch (tagp->vio_subtype) {
	case VIO_SUBTYPE_INFO:

		DBG2((vnetp, "vgen_handle_attr_info: ATTR_INFO_RCVD id(%lx)\n",
		    ldcp->ldc_id));
		ldcp->hstate |= ATTR_INFO_RCVD;

		/* save peer's values */
		ldcp->peer_hparams.mtu = attrmsg->mtu;
		ldcp->peer_hparams.addr = attrmsg->addr;
		ldcp->peer_hparams.addr_type = attrmsg->addr_type;
		ldcp->peer_hparams.xfer_mode = attrmsg->xfer_mode;
		ldcp->peer_hparams.ack_freq = attrmsg->ack_freq;

		if (vgen_check_attr_info(ldcp, attrmsg) == VGEN_FAILURE) {
			/* unsupported attr, send NACK */
			tagp->vio_subtype = VIO_SUBTYPE_NACK;
		} else {
			ack = 1;
			tagp->vio_subtype = VIO_SUBTYPE_ACK;
		}
		tagp->vio_sid = ldcp->local_sid;

		/* send reply msg back to peer */
		if (vgen_sendmsg(ldcp, (caddr_t)tagp, sizeof (*attrmsg),
		    B_FALSE) != VGEN_SUCCESS) {
			vgen_handshake_reset(ldcp);
			return;
		}

		if (ack) {
			ldcp->hstate |= ATTR_ACK_SENT;
			DBG2((vnetp, "vgen_handle_attr_info:"
			    " ATTR_ACK_SENT id(%lx)\n", ldcp->ldc_id));
		} else {
			/* failed */
			DWARN((vnetp, "vgen_handle_attr_info:"
			    " ATTR_NACK_SENT id(%lx)\n", ldcp->ldc_id));
			vgen_handshake_reset(ldcp);
			return;
		}

		if (vgen_handshake_done(ldcp) == VGEN_SUCCESS) {
			vgen_handshake(vh_nextphase(ldcp));
		}

		break;

	case VIO_SUBTYPE_ACK:

		ldcp->hstate |= ATTR_ACK_RCVD;

		DBG2((vnetp, "vgen_handle_attr_info: ATTR_ACK_RCVD id(%lx)\n",
		    ldcp->ldc_id));

		if (vgen_handshake_done(ldcp) == VGEN_SUCCESS) {
			vgen_handshake(vh_nextphase(ldcp));
		}
		break;

	case VIO_SUBTYPE_NACK:

		DBG2((vnetp, "vgen_handle_attr_info: ATTR_NACK_RCVD id(%lx)\n",
		    ldcp->ldc_id));
		vgen_handshake_reset(ldcp);
		break;
	}
	DBG1((vnetp, "vgen_handle_attr_info: exit\n"));
}

/* Check if the dring info msg is ok */
static int
vgen_check_dring_reg(vio_dring_reg_msg_t *msg)
{
	/* check if msg contents are ok */
	if ((msg->num_descriptors < 128) || (msg->descriptor_size <
	    sizeof (vnet_public_desc_t))) {
		return (VGEN_FAILURE);
	}
	return (VGEN_SUCCESS);
}

/*
 * Handle a descriptor ring register msg from the peer or an ACK/NACK from
 * the peer to a dring register msg that we sent.
 */
static void
vgen_handle_dring_reg(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp)
{
	vio_dring_reg_msg_t *msg = (vio_dring_reg_msg_t *)tagp;
	void *vnetp = LDC_TO_VNET(ldcp);
	ldc_mem_cookie_t dcookie;
	int ack = 0;
	int rv = 0;

	DBG1((vnetp, "vgen_handle_dring_reg: enter\n"));
	if (ldcp->hphase < VH_PHASE2) {
		/* dring_info can be rcvd in any of the phases after Phase1 */
		DWARN((vnetp,
		    "vgen_handle_dring_reg: Rcvd DRING_INFO, id (%lx)"
		    " Subtype (%d), Invalid Phase(%u)\n", ldcp->ldc_id,
		    tagp->vio_subtype, ldcp->hphase));
		vgen_handshake_reset(ldcp);
		return;
	}
	switch (tagp->vio_subtype) {
	case VIO_SUBTYPE_INFO:

		DBG2((vnetp, "vgen_handle_dring_reg: DRING_INFO_RCVD id(%lx)\n",
		    ldcp->ldc_id));
		ldcp->hstate |= DRING_INFO_RCVD;
		bcopy((msg->cookie), &dcookie, sizeof (dcookie));

		ASSERT(msg->ncookies == 1);

		if (vgen_check_dring_reg(msg) == VGEN_SUCCESS) {
			/*
			 * verified dring info msg to be ok,
			 * now try to map the remote dring.
			 */
			rv = vgen_init_rxds(ldcp, msg->num_descriptors,
			    msg->descriptor_size, &dcookie,
			    msg->ncookies);
			if (rv == DDI_SUCCESS) {
				/* now we can ack the peer */
				ack = 1;
			}
		}
		if (ack == 0) {
			/* failed, send NACK */
			tagp->vio_subtype = VIO_SUBTYPE_NACK;
		} else {
			if (!(ldcp->peer_hparams.dring_ready)) {

				/* save peer's dring_info values */
				bcopy(&dcookie,
				    &(ldcp->peer_hparams.dring_cookie),
				    sizeof (dcookie));
				ldcp->peer_hparams.num_desc =
						msg->num_descriptors;
				ldcp->peer_hparams.desc_size =
						msg->descriptor_size;
				ldcp->peer_hparams.num_dcookies =
						msg->ncookies;

				/* set dring_ident for the peer */
				ldcp->peer_hparams.dring_ident =
							(uint64_t)ldcp->rxdp;
				/* return the dring_ident in ack msg */
				msg->dring_ident =
							(uint64_t)ldcp->rxdp;

				ldcp->peer_hparams.dring_ready = B_TRUE;
			}
			tagp->vio_subtype = VIO_SUBTYPE_ACK;
		}
		tagp->vio_sid = ldcp->local_sid;
		/* send reply msg back to peer */
		if (vgen_sendmsg(ldcp, (caddr_t)tagp, sizeof (*msg),
		    B_FALSE) != VGEN_SUCCESS) {
			vgen_handshake_reset(ldcp);
			return;
		}

		if (ack) {
			ldcp->hstate |= DRING_ACK_SENT;
			DBG2((vnetp, "vgen_handle_dring_reg: DRING_ACK_SENT"
			    " id (%lx)\n", ldcp->ldc_id));
		} else {
			DWARN((vnetp, "vgen_handle_dring_reg: DRING_NACK_SENT"
			    " id (%lx)\n", ldcp->ldc_id));
			vgen_handshake_reset(ldcp);
			return;
		}

		if (vgen_handshake_done(ldcp) == VGEN_SUCCESS) {
			vgen_handshake(vh_nextphase(ldcp));
		}

		break;

	case VIO_SUBTYPE_ACK:

		ldcp->hstate |= DRING_ACK_RCVD;

		DBG2((vnetp, "vgen_handle_dring_reg: DRING_ACK_RCVD"
		    " id (%lx)\n", ldcp->ldc_id));

		if (!(ldcp->local_hparams.dring_ready)) {
			/* local dring is now ready */
			ldcp->local_hparams.dring_ready = B_TRUE;

			/* save dring_ident acked by peer */
			ldcp->local_hparams.dring_ident =
				msg->dring_ident;
		}

		if (vgen_handshake_done(ldcp) == VGEN_SUCCESS) {
			vgen_handshake(vh_nextphase(ldcp));
		}

		break;

	case VIO_SUBTYPE_NACK:

		DBG2((vnetp, "vgen_handle_dring_reg: DRING_NACK_RCVD"
		    " id (%lx)\n", ldcp->ldc_id));
		vgen_handshake_reset(ldcp);
		break;
	}
	DBG1((vnetp, "vgen_handle_dring_reg: exit\n"));
}

/*
 * Handle a rdx info msg from the peer or an ACK/NACK
 * from the peer to a rdx info msg that we sent.
 */
static void
vgen_handle_rdx_info(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp)
{
	void *vnetp = LDC_TO_VNET(ldcp);

	DBG1((vnetp, "vgen_handle_rdx_info: enter\n"));
	if (ldcp->hphase != VH_PHASE3) {
		DWARN((vnetp,
		    "vgen_handle_rdx_info: Rcvd RDX_INFO, id (%lx)"
		    "  Subtype (%d), Invalid Phase(%u)\n", ldcp->ldc_id,
		    tagp->vio_subtype, ldcp->hphase));
		vgen_handshake_reset(ldcp);
		return;
	}
	switch (tagp->vio_subtype) {
	case VIO_SUBTYPE_INFO:

		DBG2((vnetp, "vgen_handle_rdx_info: RDX_INFO_RCVD id (%lx)\n",
		    ldcp->ldc_id));
		ldcp->hstate |= RDX_INFO_RCVD;

		tagp->vio_subtype = VIO_SUBTYPE_ACK;
		tagp->vio_sid = ldcp->local_sid;
		/* send reply msg back to peer */
		if (vgen_sendmsg(ldcp, (caddr_t)tagp,
		    sizeof (vio_rdx_msg_t), B_FALSE) != VGEN_SUCCESS) {
			vgen_handshake_reset(ldcp);
			return;
		}

		ldcp->hstate |= RDX_ACK_SENT;
		DBG2((vnetp, "vgen_handle_rdx_info: RDX_ACK_SENT id (%lx)\n",
		    ldcp->ldc_id));

		if (vgen_handshake_done(ldcp) == VGEN_SUCCESS) {
			vgen_handshake(vh_nextphase(ldcp));
		}

		break;

	case VIO_SUBTYPE_ACK:

		ldcp->hstate |= RDX_ACK_RCVD;

		DBG2((vnetp, "vgen_handle_rdx_info: RDX_ACK_RCVD id (%lx)\n",
		    ldcp->ldc_id));

		if (vgen_handshake_done(ldcp) == VGEN_SUCCESS) {
			vgen_handshake(vh_nextphase(ldcp));
		}
		break;

	case VIO_SUBTYPE_NACK:

		DBG2((vnetp, "vgen_handle_rdx_info: RDX_NACK_RCVD id (%lx)\n",
		    ldcp->ldc_id));
		vgen_handshake_reset(ldcp);
		break;
	}
	DBG1((vnetp, "vgen_handle_rdx_info: exit\n"));
}

/* Handle ACK/NACK from vsw to a set multicast msg that we sent */
static void
vgen_handle_mcast_info(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp)
{
	void *vnetp = LDC_TO_VNET(ldcp);
	vgen_t *vgenp = LDC_TO_VGEN(ldcp);
	vnet_mcast_msg_t *msgp = (vnet_mcast_msg_t *)tagp;
	struct ether_addr *addrp;
	int count;
	int i;

	DBG1((vnetp, "vgen_handle_mcast_info: enter\n"));
	switch (tagp->vio_subtype) {

	case VIO_SUBTYPE_INFO:

		/* vnet shouldn't recv set mcast msg, only vsw handles it */
		DWARN((vnetp,
		    "vgen_handle_mcast_info: rcvd SET_MCAST_INFO id (%lx)\n",
		    ldcp->ldc_id));
		break;

	case VIO_SUBTYPE_ACK:

		/* success adding/removing multicast addr */
		DBG2((vnetp,
		    "vgen_handle_mcast_info: rcvd SET_MCAST_ACK id (%lx)\n",
		    ldcp->ldc_id));
		break;

	case VIO_SUBTYPE_NACK:

		DWARN((vnetp,
		    "vgen_handle_mcast_info: rcvd SET_MCAST_NACK id (%lx)\n",
		    ldcp->ldc_id));
		if (!(msgp->set)) {
			/* multicast remove request failed */
			break;
		}

		/* multicast add request failed */
		for (count = 0; count < msgp->count; count++) {
			addrp = &(msgp->mca[count]);

			/* delete address from the table */
			for (i = 0; i < vgenp->mccount; i++) {
				if (ether_cmp(addrp,
				    &(vgenp->mctab[i])) == 0) {
					if (vgenp->mccount > 1) {
						vgenp->mctab[i] =
						vgenp->mctab[vgenp->mccount-1];
					}
					vgenp->mccount--;
					break;
				}
			}
		}
		break;

	}
	DBG1((vnetp, "vgen_handle_mcast_info: exit\n"));
}

/* handler for control messages received from the peer ldc end-point */
static void
vgen_handle_ctrlmsg(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp)
{
	void *vnetp = LDC_TO_VNET(ldcp);

	DBG1((vnetp, "vgen_handle_ctrlmsg: enter\n"));
	switch (tagp->vio_subtype_env) {

	case VIO_VER_INFO:
		vgen_handle_version_negotiate(ldcp, tagp);
		break;

	case VIO_ATTR_INFO:
		vgen_handle_attr_info(ldcp, tagp);
		break;

	case VIO_DRING_REG:
		vgen_handle_dring_reg(ldcp, tagp);
		break;

	case VIO_RDX:
		vgen_handle_rdx_info(ldcp, tagp);
		break;

	case VNET_MCAST_INFO:
		vgen_handle_mcast_info(ldcp, tagp);
		break;

	}
	DBG1((vnetp, "vgen_handle_ctrlmsg: exit\n"));
}

/* handler for data messages received from the peer ldc end-point */
static void
vgen_handle_datamsg(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp,
	mblk_t **headp, mblk_t **tailp)
{
	void *vnetp = LDC_TO_VNET(ldcp);

	DBG1((vnetp, "vgen_handle_datamsg: enter\n"));

	if (ldcp->hphase != VH_DONE)
		return;
	switch (tagp->vio_subtype_env) {
	case VIO_DRING_DATA:
		vgen_handle_dring_data(ldcp, tagp, headp, tailp);
		break;
	default:
		break;
	}

	DBG1((vnetp, "vgen_handle_datamsg: exit\n"));
}

static void
vgen_send_dring_ack(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp, uint32_t start,
    int32_t end, uint8_t pstate)
{
	vio_dring_msg_t *msgp = (vio_dring_msg_t *)tagp;
	void *vnetp = LDC_TO_VNET(ldcp);

	tagp->vio_subtype = VIO_SUBTYPE_ACK;
	tagp->vio_sid = ldcp->local_sid;
	msgp->start_idx = start;
	msgp->end_idx = end;
	msgp->dring_process_state = pstate;
	if (vgen_sendmsg(ldcp, (caddr_t)tagp, sizeof (*msgp), B_FALSE)) {
		DWARN((vnetp, "vgen_send_dring_ack: id(%lx) vgen_sendmsg "
		    "failed\n", (ldcp)->ldc_id));
	}
}

static void
vgen_handle_dring_data(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp,
	mblk_t **headp, mblk_t **tailp)
{
	vio_dring_msg_t *dringmsg;
	vnet_public_desc_t *rxdp;
	vnet_public_desc_t *txdp;
	vio_dring_entry_hdr_t *hdrp;
	vgen_stats_t *statsp;
	struct ether_header *ehp;
	mblk_t *mp = NULL;
	mblk_t *bp = NULL;
	mblk_t *bpt = NULL;
	size_t nbytes;
	size_t nread;
	uint64_t off = 0;
	uint32_t start;
	int32_t end;
	uint32_t datalen;
	uint32_t ncookies;
	uint32_t ack_start;
	uint32_t ack_end;
	uint32_t rxi;
	uint32_t txi;
	int rv;
	boolean_t rxd_err = B_FALSE;
	boolean_t set_ack_start = B_FALSE;
	vgen_private_desc_t *tbufp;
	uint32_t next_rxi;
	boolean_t ready_txd = B_FALSE;
	uint32_t retries = 0;
#ifdef VGEN_HANDLE_LOST_PKTS
	int n;
#endif
#ifdef VGEN_REXMIT
	uint64_t seqnum;
#endif
	void *vnetp = LDC_TO_VNET(ldcp);

	dringmsg = (vio_dring_msg_t *)tagp;
	start = dringmsg->start_idx;
	end = dringmsg->end_idx;
	statsp = ldcp->statsp;

	DBG1((vnetp, "vgen_handle_dring_data: enter\n"));
	switch (tagp->vio_subtype) {

	case VIO_SUBTYPE_INFO:
		/*
		 * received a data msg, which contains the start and end
		 * indeces of the descriptors within the rx ring holding data,
		 * the seq_num of data packet corresponding to the start index,
		 * and the dring_ident.
		 * We can now read the contents of each of these descriptors
		 * and gather data from it.
		 */
		DBG2((vnetp,
		    "vgen_handle_dring_data: INFO: start(%d), end(%d)\n",
		    start, end));

		/* validate rx start and end indeces */
		if (!(CHECK_RXI(start, ldcp)) || ((end != -1) &&
		    !(CHECK_RXI(end, ldcp)))) {
			/* drop the message if invalid index */
			break;
		}

		/* validate dring_ident */
		if (dringmsg->dring_ident != ldcp->peer_hparams.dring_ident) {
			/* invalid dring_ident, drop the msg */
			break;
		}
#ifdef DEBUG
		if (vgen_trigger_rxlost) {
			/* drop this msg to simulate lost pkts for debugging */
			vgen_trigger_rxlost = 0;
			break;
		}
#endif

#ifdef	VGEN_HANDLE_LOST_PKTS

		/* receive start index doesn't match expected index */
		if (ldcp->next_rxi != start) {

			DWARN((vnetp, "vgen_handle_dring_data: id(%lx) "
			    "next_rxi(%d) != start(%d)\n",
			    ldcp->ldc_id, ldcp->next_rxi, start));

			/* calculate the number of pkts lost */
			if (start >= ldcp->next_rxi) {
				n = start - ldcp->next_rxi;
			} else  {
				n = ldcp->num_rxds - (ldcp->next_rxi - start);
			}

			/*
			 * sequence number of dring data message
			 * is less than the next sequence number that
			 * is expected:
			 *
			 * drop the message and the corresponding packets.
			 */
			if (ldcp->next_rxseq > dringmsg->seq_num) {
				DWARN((vnetp, "vgen_handle_dring_data: id(%lx) "
				    "dropping pkts, expected rxseq(0x%lx) "
				    "> recvd(0x%lx)\n",
				    ldcp->ldc_id, ldcp->next_rxseq,
				    dringmsg->seq_num));
				/*
				 * duplicate/multiple retransmissions from
				 * sender?? drop this msg.
				 */
				break;
			}

			/*
			 * sequence number of dring data message
			 * is greater than the next expected sequence number
			 *
			 * send a NACK back to the peer to indicate lost
			 * packets.
			 */
			if (dringmsg->seq_num > ldcp->next_rxseq) {
				statsp->rx_lost_pkts += n;
				tagp->vio_subtype = VIO_SUBTYPE_NACK;
				tagp->vio_sid = ldcp->local_sid;
				/* indicate the range of lost descriptors */
				dringmsg->start_idx = ldcp->next_rxi;
				rxi = start;
				DECR_RXI(rxi, ldcp);
				dringmsg->end_idx = rxi;
				/* dring ident is left unchanged */
				if (vgen_sendmsg(ldcp, (caddr_t)tagp,
				    sizeof (*dringmsg), B_FALSE)) {
					DWARN((vnetp,
					    "vgen_handle_dring_data: id(%lx) "
					    "vgen_sendmsg failed, "
					    "stype: NACK\n", ldcp->ldc_id));
				}
#ifdef VGEN_REXMIT
				/*
				 * stop further processing until peer
				 * retransmits with the right index.
				 * update next_rxseq expected.
				 */
				ldcp->next_rxseq += 1;
				break;
#else	/* VGEN_REXMIT */
				/*
				 * treat this range of descrs/pkts as dropped
				 * and set the new expected values for next_rxi
				 * and next_rxseq. continue(below) to process
				 * from the new start index.
				 */
				ldcp->next_rxi = start;
				ldcp->next_rxseq += 1;
#endif	/* VGEN_REXMIT */

			} else if (dringmsg->seq_num == ldcp->next_rxseq) {
				/*
				 * expected and received seqnums match, but
				 * the descriptor indeces don't?
				 *
				 * restart handshake with peer.
				 */
				DWARN((vnetp,
				    "vgen_handle_dring_data: id(%lx) "
				    "next_rxseq(0x%lx) == seq_num(0x%lx)\n",
				    ldcp->ldc_id, ldcp->next_rxseq,
				    dringmsg->seq_num));

			}

		} else {
			/* expected and start dring indeces match */

			if (dringmsg->seq_num != ldcp->next_rxseq) {

				/* seqnums don't match */

				DWARN((vnetp,
				    "vgen_handle_dring_data: id(%lx) "
				    "next_rxseq(0x%lx) != seq_num(0x%lx)\n",
				    ldcp->ldc_id, ldcp->next_rxseq,
				    dringmsg->seq_num));
			}
		}

#endif	/* VGEN_HANDLE_LOST_PKTS */

		/*
		 * start processing the descriptors from the specified
		 * start index, up to the index a descriptor is not ready
		 * to be processed or we process the entire descriptor ring
		 * and wrap around upto the start index.
		 */

		/* need to set the start index of descriptors to be ack'd */
		set_ack_start = B_TRUE;

		/* index upto which we have ack'd */
		ack_end = start;
		DECR_RXI(ack_end, ldcp);

		next_rxi = rxi =  start;
		do {

vgen_recv_retry:	if (ldc_mem_dring_acquire(ldcp->rx_dhandle,
			    rxi, rxi)) {
				DWARN((vnetp, "vgen_handle_dring_data: "
				    "id(%lx), ldc_mem_dring_acquire() failed\n",
				    ldcp->ldc_id));
				statsp->ierrors++;
				break;
			}

			rxdp = &(ldcp->rxdp[rxi]);
			hdrp = &rxdp->hdr;

			if (hdrp->dstate != VIO_DESC_READY) {
				/*
				 * descriptor is not ready.
				 * retry descriptor acquire, stop processing
				 * after max # retries.
				 */
				if (retries == vgen_recv_retries)
					break;
				retries++;
				drv_usecwait(vgen_recv_delay);
				goto vgen_recv_retry;
			}
			retries = 0;

			if (set_ack_start) {
				/*
				 * initialize the start index of the range
				 * of descriptors to be ack'd.
				 */
				ack_start = rxi;
				set_ack_start = B_FALSE;
			}

			datalen = rxdp->nbytes;
			ncookies = rxdp->ncookies;
			if ((datalen < ETHERMIN) ||
			    (ncookies == 0) ||
			    (ncookies > MAX_COOKIES)) {
				rxd_err = B_TRUE;
			} else {
				/*
				 * Try to allocate an mblk from the free pool
				 * of recv mblks for the channel.
				 * If this fails, use allocb().
				 */
				mp = vio_allocb(ldcp->rmp);
				if (!mp) {
					/*
					 * The data buffer returned by
					 * allocb(9F) is 8byte aligned. We
					 * allocate extra 8 bytes to ensure
					 * size is multiple of 8 bytes for
					 * ldc_mem_copy().
					 */
					statsp->rx_vio_allocb_fail++;
					mp = allocb(VNET_IPALIGN + datalen + 8,
					    BPRI_MED);
				}
				nbytes = (VNET_IPALIGN + datalen + 7) & ~7;
			}
			if ((rxd_err) || (mp == NULL)) {
				/*
				 * rxd_err or allocb() failure,
				 * drop this packet, get next.
				 */
				if (rxd_err) {
					statsp->ierrors++;
					rxd_err = B_FALSE;
				} else {
					statsp->rx_allocb_fail++;
				}

				/* set descriptor done bit */
				hdrp->dstate = VIO_DESC_DONE;

				(void) ldc_mem_dring_release(ldcp->rx_dhandle,
				    rxi, rxi);

				if (hdrp->ack) {
					/*
					 * sender needs ack for this packet,
					 * ack pkts upto this index.
					 */
					ack_end = rxi;

					vgen_send_dring_ack(ldcp, tagp,
					    ack_start, ack_end,
					    VIO_DP_ACTIVE);

					/* need to set new ack start index */
					set_ack_start = B_TRUE;
				}
				goto vgen_next_rxi;
			}

			nread = nbytes;
			rv = ldc_mem_copy(ldcp->ldc_handle,
			    (caddr_t)mp->b_rptr, off, &nread,
			    rxdp->memcookie, ncookies, LDC_COPY_IN);

			/* set done bit irrespective of rv of ldc_mem_copy() */
			hdrp->dstate = VIO_DESC_DONE;

			(void) ldc_mem_dring_release(ldcp->rx_dhandle,
			    rxi, rxi);

			mp->b_rptr += VNET_IPALIGN;

			if (hdrp->ack) {
				/*
				 * sender needs ack for this packet,
				 * ack pkts upto this index.
				 */
				ack_end = rxi;

				vgen_send_dring_ack(ldcp, tagp,
				    ack_start, ack_end, VIO_DP_ACTIVE);

				/* need to set new ack start index */
				set_ack_start = B_TRUE;
			}

			/* if ldc_mem_copy() failed */
			if (rv) {
				DWARN((vnetp,
				    "vgen_handle_dring_data: id(%lx) "
				    "ldc_mem_copy failed\n", ldcp->ldc_id));
				statsp->ierrors++;
				freemsg(mp);
				goto vgen_next_rxi;
			}
			if (nread != nbytes) {
				DWARN((vnetp,
				    "vgen_handle_dring_data: id(%lx) "
				    "ldc_mem_copy nread(%lx), nbytes(%lx)\n",
				    ldcp->ldc_id, nread, nbytes));
				statsp->ierrors++;
				freemsg(mp);
				goto vgen_next_rxi;
			}

			/* point to the actual end of data */
			mp->b_wptr = mp->b_rptr + datalen;

			/* update stats */
			statsp->ipackets++;
			statsp->rbytes += datalen;
			ehp = (struct ether_header *)mp->b_rptr;
			if (IS_BROADCAST(ehp))
				statsp->brdcstrcv++;
			else if (IS_MULTICAST(ehp))
				statsp->multircv++;

			/* build a chain of received packets */
			if (bp == NULL) {
				/* first pkt */
				bp = mp;
				bpt = bp;
				bpt->b_next = NULL;
			} else {
				mp->b_next = NULL;
				bpt->b_next = mp;
				bpt = mp;
			}


vgen_next_rxi:
			/* update end index of range of descrs to be ack'd */
			ack_end = rxi;

			/* update the next index to be processed */
			INCR_RXI(next_rxi, ldcp);
			if (next_rxi == start) {
				/*
				 * processed the entire descriptor ring upto
				 * the index at which we started.
				 */
				break;
			}

			rxi = next_rxi;

		_NOTE(CONSTCOND)
		} while (1);

		/*
		 * send an ack message to peer indicating that we have stopped
		 * processing descriptors.
		 */
		if (set_ack_start) {
			/*
			 * We have ack'd upto some index and we have not
			 * processed any descriptors beyond that index.
			 * Use the last ack'd index as both the start and
			 * end of range of descrs being ack'd.
			 * Note: This results in acking the last index twice
			 * and should be harmless.
			 */
			ack_start = ack_end;
		}

		vgen_send_dring_ack(ldcp, tagp, ack_start, ack_end,
		    VIO_DP_STOPPED);

		/* save new recv index and expected seqnum of next dring msg */
		ldcp->next_rxi = next_rxi;
		ldcp->next_rxseq += 1;

		break;

	case VIO_SUBTYPE_ACK:
		/*
		 * received an ack corresponding to a specific descriptor for
		 * which we had set the ACK bit in the descriptor (during
		 * transmit). This enables us to reclaim descriptors.
		 */

		DBG2((vnetp,
		    "vgen_handle_dring_data: ACK:  start(%d), end(%d)\n",
		    start, end));

		/* validate start and end indeces in the tx ack msg */
		if (!(CHECK_TXI(start, ldcp)) || !(CHECK_TXI(end, ldcp))) {
			/* drop the message if invalid index */
			break;
		}
		/* validate dring_ident */
		if (dringmsg->dring_ident != ldcp->local_hparams.dring_ident) {
			/* invalid dring_ident, drop the msg */
			break;
		}
		statsp->dring_data_acks++;

		/* reclaim descriptors that are done */
		vgen_reclaim(ldcp);

		if (dringmsg->dring_process_state != VIO_DP_STOPPED) {
			/*
			 * receiver continued processing descriptors after
			 * sending us the ack.
			 */
			break;
		}

		statsp->dring_stopped_acks++;

		/* receiver stopped processing descriptors */
		mutex_enter(&ldcp->txlock);
		mutex_enter(&ldcp->tclock);

		/*
		 * determine if there are any pending tx descriptors
		 * ready to be processed by the receiver(peer) and if so,
		 * send a message to the peer to restart receiving.
		 */
		ready_txd = B_FALSE;

		/*
		 * using the end index of the descriptor range for which
		 * we received the ack, check if the next descriptor is
		 * ready.
		 */
		txi = end;
		INCR_TXI(txi, ldcp);
		tbufp = &ldcp->tbufp[txi];
		txdp = tbufp->descp;
		hdrp = &txdp->hdr;
		if (hdrp->dstate == VIO_DESC_READY) {
			ready_txd = B_TRUE;
		} else {
			/*
			 * descr next to the end of ack'd descr range is not
			 * ready.
			 * starting from the current reclaim index, check
			 * if any descriptor is ready.
			 */

			txi = ldcp->cur_tbufp - ldcp->tbufp;
			tbufp = &ldcp->tbufp[txi];

			while (tbufp != ldcp->next_tbufp) {

				txdp = tbufp->descp;
				hdrp = &txdp->hdr;
				if (hdrp->dstate == VIO_DESC_READY) {
					break;
				}

				INCR_TXI(txi, ldcp);
				tbufp = &ldcp->tbufp[txi];

			}

			if (tbufp != ldcp->next_tbufp)
				ready_txd = B_TRUE;
		}

		if (ready_txd) {
			/*
			 * we have tx descriptor(s) ready to be
			 * processed by the receiver.
			 * send a message to the peer with the start index
			 * of ready descriptors.
			 */
			rv = vgen_send_dring_data(ldcp, txi, -1);
			if (rv != 0) {
				ldcp->resched_peer = B_TRUE;
			}
		} else {
			/*
			 * no ready tx descriptors. set the flag to send a
			 * message to peer when tx descriptors are ready in
			 * transmit routine.
			 */
			ldcp->resched_peer = B_TRUE;
		}

		mutex_exit(&ldcp->tclock);
		mutex_exit(&ldcp->txlock);

		break;

	case VIO_SUBTYPE_NACK:
		/*
		 * peer sent a NACK msg to indicate lost packets.
		 * The start and end correspond to the range of descriptors
		 * for which the peer didn't receive a dring data msg and so
		 * didn't receive the corresponding data.
		 */
		DWARN((vnetp,
		    "vgen_handle_dring_data: NACK:  start(%d), end(%d)\n",
		    start, end));

		/* validate start and end indeces in the tx nack msg */
		if (!(CHECK_TXI(start, ldcp)) || !(CHECK_TXI(end, ldcp))) {
			/* drop the message if invalid index */
			break;
		}
		/* validate dring_ident */
		if (dringmsg->dring_ident != ldcp->local_hparams.dring_ident) {
			/* invalid dring_ident, drop the msg */
			break;
		}
		mutex_enter(&ldcp->txlock);
		mutex_enter(&ldcp->tclock);

		if (ldcp->next_tbufp == ldcp->cur_tbufp) {
			/* no busy descriptors, bogus nack ? */
			mutex_exit(&ldcp->tclock);
			mutex_exit(&ldcp->txlock);
			break;
		}

#ifdef VGEN_REXMIT
		/* send a new dring data msg including the lost descrs */
		end = ldcp->next_tbufp - ldcp->tbufp;
		DECR_TXI(end, ldcp);
		rv = vgen_send_dring_data(ldcp, start, end);
		if (rv != 0) {
			/*
			 * vgen_send_dring_data() error: drop all packets
			 * in this descr range
			 */
			DWARN((vnetp,
			    "vgen_handle_dring_data: "
			    "vgen_send_dring_data failed :"
			    "id(%lx) rv(%d)\n", ldcp->ldc_id, rv));
			for (txi = start; txi <= end; ) {
				tbufp = &(ldcp->tbufp[txi]);
				txdp = tbufp->descp;
				hdrp = &txdp->hdr;
				tbufp->flags = VGEN_PRIV_DESC_FREE;
				hdrp->dstate = VIO_DESC_FREE;
				hdrp->ack = B_FALSE;
				statsp->oerrors++;
			}

			/* update next pointer */
			ldcp->next_tbufp = &(ldcp->tbufp[start]);
			ldcp->next_txi = start;
		}
		DBG2((vnetp,
		    "vgen_handle_dring_data: rexmit: start(%d) end(%d)\n",
		    start, end));
#else	/* VGEN_REXMIT */
		/* we just mark the descrs as done so they can be reclaimed */
		for (txi = start; txi <= end; ) {
			txdp = &(ldcp->txdp[txi]);
			hdrp = &txdp->hdr;
			if (hdrp->dstate == VIO_DESC_READY)
				hdrp->dstate = VIO_DESC_DONE;
			INCR_TXI(txi, ldcp);
		}
#endif	/* VGEN_REXMIT */
		mutex_exit(&ldcp->tclock);
		mutex_exit(&ldcp->txlock);

		break;
	}

	DBG1((vnetp, "vgen_handle_dring_data: exit\n"));
	*headp = bp;
	*tailp = bpt;

}

static void
vgen_reclaim(vgen_ldc_t *ldcp)
{
	mutex_enter(&ldcp->tclock);

	vgen_reclaim_dring(ldcp);
	ldcp->reclaim_lbolt = ddi_get_lbolt();

	mutex_exit(&ldcp->tclock);
}

/*
 * transmit reclaim function. starting from the current reclaim index
 * look for descriptors marked DONE and reclaim the descriptor and the
 * corresponding buffers (tbuf).
 */
static void
vgen_reclaim_dring(vgen_ldc_t *ldcp)
{
	vnet_public_desc_t *txdp;
	vgen_private_desc_t *tbufp;
	vio_dring_entry_hdr_t	*hdrp;
	vgen_t	*vgenp = LDC_TO_VGEN(ldcp);

#ifdef DEBUG
	if (vgen_trigger_txtimeout)
		return;
#endif

	tbufp = ldcp->cur_tbufp;
	txdp = tbufp->descp;
	hdrp = &txdp->hdr;

	while ((hdrp->dstate == VIO_DESC_DONE) &&
	    (tbufp != ldcp->next_tbufp)) {
		tbufp->flags = VGEN_PRIV_DESC_FREE;
		hdrp->dstate = VIO_DESC_FREE;
		hdrp->ack = B_FALSE;

		tbufp = NEXTTBUF(ldcp, tbufp);
		txdp = tbufp->descp;
		hdrp = &txdp->hdr;
	}

	ldcp->cur_tbufp = tbufp;

	/*
	 * Check if mac layer should be notified to restart transmissions
	 */
	if (ldcp->need_resched) {
		ldcp->need_resched = B_FALSE;
		vnet_tx_update(vgenp->vnetp);
	}
}

/* return the number of pending transmits for the channel */
static int
vgen_num_txpending(vgen_ldc_t *ldcp)
{
	int n;

	if (ldcp->next_tbufp >= ldcp->cur_tbufp) {
		n = ldcp->next_tbufp - ldcp->cur_tbufp;
	} else  {
		/* cur_tbufp > next_tbufp */
		n = ldcp->num_txds - (ldcp->cur_tbufp - ldcp->next_tbufp);
	}

	return (n);
}

/* determine if the transmit descriptor ring is full */
static int
vgen_tx_dring_full(vgen_ldc_t *ldcp)
{
	vgen_private_desc_t	*tbufp;
	vgen_private_desc_t	*ntbufp;

	tbufp = ldcp->next_tbufp;
	ntbufp = NEXTTBUF(ldcp, tbufp);
	if (ntbufp == ldcp->cur_tbufp) { /* out of tbufs/txds */
		return (VGEN_SUCCESS);
	}
	return (VGEN_FAILURE);
}

/* determine if timeout condition has occured */
static int
vgen_ldc_txtimeout(vgen_ldc_t *ldcp)
{
	if (((ddi_get_lbolt() - ldcp->reclaim_lbolt) >
	    drv_usectohz(vnet_ldcwd_txtimeout * 1000)) &&
	    (vnet_ldcwd_txtimeout) &&
	    (vgen_tx_dring_full(ldcp) == VGEN_SUCCESS)) {
		return (VGEN_SUCCESS);
	} else {
		return (VGEN_FAILURE);
	}
}

/* transmit watchdog timeout handler */
static void
vgen_ldc_watchdog(void *arg)
{
	vgen_ldc_t *ldcp;
	vgen_t *vgenp;
	void *vnetp;
	int rv;

	ldcp = (vgen_ldc_t *)arg;
	vgenp = LDC_TO_VGEN(ldcp);
	vnetp = LDC_TO_VNET(ldcp);

	rv = vgen_ldc_txtimeout(ldcp);
	if (rv == VGEN_SUCCESS) {
		DWARN((vnetp,
		    "vgen_ldc_watchdog: transmit timeout ldcid(%lx)\n",
		    ldcp->ldc_id));
#ifdef DEBUG
		if (vgen_trigger_txtimeout) {
			/* tx timeout triggered for debugging */
			vgen_trigger_txtimeout = 0;
		}
#endif
		mutex_enter(&ldcp->cblock);
		vgen_handshake_retry(ldcp);
		mutex_exit(&ldcp->cblock);
		if (ldcp->need_resched) {
			ldcp->need_resched = B_FALSE;
			vnet_tx_update(vgenp->vnetp);
		}
	}

	ldcp->wd_tid = timeout(vgen_ldc_watchdog, (caddr_t)ldcp,
	    drv_usectohz(vnet_ldcwd_interval * 1000));
}

static int
vgen_setup_kstats(vgen_ldc_t *ldcp)
{
	vgen_t *vgenp;
	struct kstat *ksp;
	vgen_stats_t *statsp;
	vgen_kstats_t *ldckp;
	int instance;
	size_t size;
	char name[MAXNAMELEN];

	vgenp = LDC_TO_VGEN(ldcp);
	instance = ddi_get_instance(vgenp->vnetdip);
	(void) sprintf(name, "vnetldc0x%lx", ldcp->ldc_id);
	statsp = kmem_zalloc(sizeof (vgen_stats_t), KM_SLEEP);
	if (statsp == NULL) {
		return (VGEN_FAILURE);
	}
	size = sizeof (vgen_kstats_t) / sizeof (kstat_named_t);
	ksp = kstat_create("vnet", instance, name, "net", KSTAT_TYPE_NAMED,
		size, 0);
	if (ksp == NULL) {
		KMEM_FREE(statsp);
		return (VGEN_FAILURE);
	}

	ldckp = (vgen_kstats_t *)ksp->ks_data;
	kstat_named_init(&ldckp->ipackets,		"ipackets",
		KSTAT_DATA_ULONG);
	kstat_named_init(&ldckp->ipackets64,		"ipackets64",
		KSTAT_DATA_ULONGLONG);
	kstat_named_init(&ldckp->ierrors,		"ierrors",
		KSTAT_DATA_ULONG);
	kstat_named_init(&ldckp->opackets,		"opackets",
		KSTAT_DATA_ULONG);
	kstat_named_init(&ldckp->opackets64,		"opackets64",
		KSTAT_DATA_ULONGLONG);
	kstat_named_init(&ldckp->oerrors,		"oerrors",
		KSTAT_DATA_ULONG);


	/* MIB II kstat variables */
	kstat_named_init(&ldckp->rbytes,		"rbytes",
		KSTAT_DATA_ULONG);
	kstat_named_init(&ldckp->rbytes64,		"rbytes64",
		KSTAT_DATA_ULONGLONG);
	kstat_named_init(&ldckp->obytes,		"obytes",
		KSTAT_DATA_ULONG);
	kstat_named_init(&ldckp->obytes64,		"obytes64",
		KSTAT_DATA_ULONGLONG);
	kstat_named_init(&ldckp->multircv,		"multircv",
		KSTAT_DATA_ULONG);
	kstat_named_init(&ldckp->multixmt,		"multixmt",
		KSTAT_DATA_ULONG);
	kstat_named_init(&ldckp->brdcstrcv,		"brdcstrcv",
		KSTAT_DATA_ULONG);
	kstat_named_init(&ldckp->brdcstxmt,		"brdcstxmt",
		KSTAT_DATA_ULONG);
	kstat_named_init(&ldckp->norcvbuf,		"norcvbuf",
		KSTAT_DATA_ULONG);
	kstat_named_init(&ldckp->noxmtbuf,		"noxmtbuf",
		KSTAT_DATA_ULONG);

	/* Tx stats */
	kstat_named_init(&ldckp->tx_no_desc,		"tx_no_desc",
		KSTAT_DATA_ULONG);

	/* Rx stats */
	kstat_named_init(&ldckp->rx_allocb_fail,	"rx_allocb_fail",
		KSTAT_DATA_ULONG);
	kstat_named_init(&ldckp->rx_vio_allocb_fail,	"rx_vio_allocb_fail",
		KSTAT_DATA_ULONG);
	kstat_named_init(&ldckp->rx_lost_pkts,		"rx_lost_pkts",
		KSTAT_DATA_ULONG);

	/* Interrupt stats */
	kstat_named_init(&ldckp->callbacks,		"callbacks",
		KSTAT_DATA_ULONG);
	kstat_named_init(&ldckp->dring_data_acks,	"dring_data_acks",
		KSTAT_DATA_ULONG);
	kstat_named_init(&ldckp->dring_stopped_acks,	"dring_stopped_acks",
		KSTAT_DATA_ULONG);
	kstat_named_init(&ldckp->dring_data_msgs,	"dring_data_msgs",
		KSTAT_DATA_ULONG);

	ksp->ks_update = vgen_kstat_update;
	ksp->ks_private = (void *)ldcp;
	kstat_install(ksp);

	ldcp->ksp = ksp;
	ldcp->statsp = statsp;
	return (VGEN_SUCCESS);
}

static void
vgen_destroy_kstats(vgen_ldc_t *ldcp)
{
	if (ldcp->ksp)
		kstat_delete(ldcp->ksp);
	KMEM_FREE(ldcp->statsp);
}

static int
vgen_kstat_update(kstat_t *ksp, int rw)
{
	vgen_ldc_t *ldcp;
	vgen_stats_t *statsp;
	vgen_kstats_t *ldckp;

	ldcp = (vgen_ldc_t *)ksp->ks_private;
	statsp = ldcp->statsp;
	ldckp = (vgen_kstats_t *)ksp->ks_data;

	if (rw == KSTAT_READ) {
		ldckp->ipackets.value.ul	= (uint32_t)statsp->ipackets;
		ldckp->ipackets64.value.ull	= statsp->ipackets;
		ldckp->ierrors.value.ul		= statsp->ierrors;
		ldckp->opackets.value.ul	= (uint32_t)statsp->opackets;
		ldckp->opackets64.value.ull	= statsp->opackets;
		ldckp->oerrors.value.ul		= statsp->oerrors;

		/*
		 * MIB II kstat variables
		 */
		ldckp->rbytes.value.ul		= (uint32_t)statsp->rbytes;
		ldckp->rbytes64.value.ull	= statsp->rbytes;
		ldckp->obytes.value.ul		= (uint32_t)statsp->obytes;
		ldckp->obytes64.value.ull	= statsp->obytes;
		ldckp->multircv.value.ul	= statsp->multircv;
		ldckp->multixmt.value.ul	= statsp->multixmt;
		ldckp->brdcstrcv.value.ul	= statsp->brdcstrcv;
		ldckp->brdcstxmt.value.ul	= statsp->brdcstxmt;
		ldckp->norcvbuf.value.ul	= statsp->norcvbuf;
		ldckp->noxmtbuf.value.ul	= statsp->noxmtbuf;

		ldckp->tx_no_desc.value.ul	= statsp->tx_no_desc;

		ldckp->rx_allocb_fail.value.ul	= statsp->rx_allocb_fail;
		ldckp->rx_vio_allocb_fail.value.ul = statsp->rx_vio_allocb_fail;
		ldckp->rx_lost_pkts.value.ul	= statsp->rx_lost_pkts;

		ldckp->callbacks.value.ul	= statsp->callbacks;
		ldckp->dring_data_acks.value.ul	= statsp->dring_data_acks;
		ldckp->dring_stopped_acks.value.ul = statsp->dring_stopped_acks;
		ldckp->dring_data_msgs.value.ul	= statsp->dring_data_msgs;
	} else {
		statsp->ipackets	= ldckp->ipackets64.value.ull;
		statsp->ierrors		= ldckp->ierrors.value.ul;
		statsp->opackets	= ldckp->opackets64.value.ull;
		statsp->oerrors		= ldckp->oerrors.value.ul;

		/*
		 * MIB II kstat variables
		 */
		statsp->rbytes		= ldckp->rbytes64.value.ull;
		statsp->obytes		= ldckp->obytes64.value.ull;
		statsp->multircv	= ldckp->multircv.value.ul;
		statsp->multixmt	= ldckp->multixmt.value.ul;
		statsp->brdcstrcv	= ldckp->brdcstrcv.value.ul;
		statsp->brdcstxmt	= ldckp->brdcstxmt.value.ul;
		statsp->norcvbuf	= ldckp->norcvbuf.value.ul;
		statsp->noxmtbuf	= ldckp->noxmtbuf.value.ul;

		statsp->tx_no_desc	= ldckp->tx_no_desc.value.ul;

		statsp->rx_allocb_fail	= ldckp->rx_allocb_fail.value.ul;
		statsp->rx_vio_allocb_fail = ldckp->rx_vio_allocb_fail.value.ul;
		statsp->rx_lost_pkts	= ldckp->rx_lost_pkts.value.ul;

		statsp->callbacks	= ldckp->callbacks.value.ul;
		statsp->dring_data_acks	= ldckp->dring_data_acks.value.ul;
		statsp->dring_stopped_acks = ldckp->dring_stopped_acks.value.ul;
		statsp->dring_data_msgs	= ldckp->dring_data_msgs.value.ul;
	}

	return (VGEN_SUCCESS);
}

/* handler for error messages received from the peer ldc end-point */
static void
vgen_handle_errmsg(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp)
{
	_NOTE(ARGUNUSED(ldcp, tagp))
}

/* Check if the session id in the received message is valid */
static int
vgen_check_sid(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp)
{
	if (tagp->vio_sid != ldcp->peer_sid) {
		void *vnetp = LDC_TO_VNET(ldcp);
		DWARN((vnetp,
		    "sid mismatch: expected(%x), rcvd(%x)\n",
		    ldcp->peer_sid, tagp->vio_sid));
		return (VGEN_FAILURE);
	}
	else
		return (VGEN_SUCCESS);
}

/* convert mac address from string to uint64_t */
static uint64_t
vgen_macaddr_strtoul(const uint8_t *macaddr)
{
	uint64_t val = 0;
	int i;

	for (i = 0; i < ETHERADDRL; i++) {
		val <<= 8;
		val |= macaddr[i];
	}

	return (val);
}

/* convert mac address from uint64_t to string */
static int
vgen_macaddr_ultostr(uint64_t val, uint8_t *macaddr)
{
	int i;
	uint64_t value;

	value = val;
	for (i = ETHERADDRL - 1; i >= 0; i--) {
		macaddr[i] = value & 0xFF;
		value >>= 8;
	}
	return (VGEN_SUCCESS);
}

static caddr_t
vgen_print_ethaddr(uint8_t *a, char *ebuf)
{
	(void) sprintf(ebuf,
		"%x:%x:%x:%x:%x:%x", a[0], a[1], a[2], a[3], a[4], a[5]);
	return (ebuf);
}

/* Handshake watchdog timeout handler */
static void
vgen_hwatchdog(void *arg)
{
	vgen_ldc_t *ldcp = (vgen_ldc_t *)arg;
	void *vnetp = LDC_TO_VNET(ldcp);

	DWARN((vnetp,
	    "vgen_hwatchdog: handshake timeout ldc(%lx) phase(%x) state(%x)\n",
	    ldcp->ldc_id, ldcp->hphase, ldcp->hstate));

	mutex_enter(&ldcp->cblock);
	ldcp->htid = 0;
	vgen_handshake_retry(ldcp);
	mutex_exit(&ldcp->cblock);
}

static void
vgen_print_hparams(vgen_hparams_t *hp)
{
	uint8_t	addr[6];
	char	ea[6];
	ldc_mem_cookie_t *dc;

	cmn_err(CE_CONT, "version_info:\n");
	cmn_err(CE_CONT,
	    "\tver_major: %d, ver_minor: %d, dev_class: %d\n",
	    hp->ver_major, hp->ver_minor, hp->dev_class);

	(void) vgen_macaddr_ultostr(hp->addr, addr);
	cmn_err(CE_CONT, "attr_info:\n");
	cmn_err(CE_CONT, "\tMTU: %lx, addr: %s\n", hp->mtu,
	    vgen_print_ethaddr(addr, ea));
	cmn_err(CE_CONT,
	    "\taddr_type: %x, xfer_mode: %x, ack_freq: %x\n",
	    hp->addr_type, hp->xfer_mode, hp->ack_freq);

	dc = &hp->dring_cookie;
	cmn_err(CE_CONT, "dring_info:\n");
	cmn_err(CE_CONT,
	    "\tlength: %d, dsize: %d\n", hp->num_desc, hp->desc_size);
	cmn_err(CE_CONT,
	    "\tldc_addr: 0x%lx, ldc_size: %ld\n",
	    dc->addr, dc->size);
	cmn_err(CE_CONT, "\tdring_ident: 0x%lx\n", hp->dring_ident);
}

static void
vgen_print_ldcinfo(vgen_ldc_t *ldcp)
{
	vgen_hparams_t *hp;

	cmn_err(CE_CONT, "Channel Information:\n");
	cmn_err(CE_CONT,
	    "\tldc_id: 0x%lx, ldc_status: 0x%x\n",
	    ldcp->ldc_id, ldcp->ldc_status);
	cmn_err(CE_CONT,
	    "\tlocal_sid: 0x%x, peer_sid: 0x%x\n",
	    ldcp->local_sid, ldcp->peer_sid);
	cmn_err(CE_CONT,
	    "\thphase: 0x%x, hstate: 0x%x\n",
	    ldcp->hphase, ldcp->hstate);

	cmn_err(CE_CONT, "Local handshake params:\n");
	hp = &ldcp->local_hparams;
	vgen_print_hparams(hp);

	cmn_err(CE_CONT, "Peer handshake params:\n");
	hp = &ldcp->peer_hparams;
	vgen_print_hparams(hp);
}
