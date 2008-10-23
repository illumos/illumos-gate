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
 */

/*
 * Copyright (c) 2007, The Ohio State University. All rights reserved.
 *
 * Portions of this source code is developed by the team members of
 * The Ohio State University's Network-Based Computing Laboratory (NBCL),
 * headed by Professor Dhabaleswar K. (DK) Panda.
 *
 * Acknowledgements to contributions from developors:
 *   Ranjit Noronha: noronha@cse.ohio-state.edu
 *   Lei Chai      : chail@cse.ohio-state.edu
 *   Weikuan Yu    : yuw@cse.ohio-state.edu
 *
 */

/*
 * The rpcib plugin. Implements the interface for RDMATF's
 * interaction with IBTF.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/stropts.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/systm.h>
#include <sys/pathname.h>
#include <sys/kstat.h>
#include <sys/t_lock.h>
#include <sys/ddi.h>
#include <sys/cmn_err.h>
#include <sys/time.h>
#include <sys/isa_defs.h>
#include <sys/callb.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/sunldi.h>
#include <sys/sdt.h>
#include <sys/dlpi.h>
#include <sys/ib/ibtl/ibti.h>
#include <rpc/rpc.h>
#include <rpc/ib.h>

#include <sys/modctl.h>

#include <sys/pathname.h>
#include <sys/kstr.h>
#include <sys/sockio.h>
#include <sys/vnode.h>
#include <sys/tiuser.h>
#include <net/if.h>
#include <sys/cred.h>
#include <rpc/rpc_rdma.h>

#include <nfs/nfs.h>
#include <sys/kstat.h>
#include <sys/atomic.h>

#define	NFS_RDMA_PORT	2050

extern char *inet_ntop(int, const void *, char *, int);


/*
 * Prototype declarations for driver ops
 */

static int	rpcib_attach(dev_info_t *, ddi_attach_cmd_t);
static int	rpcib_getinfo(dev_info_t *, ddi_info_cmd_t,
				void *, void **);
static int	rpcib_detach(dev_info_t *, ddi_detach_cmd_t);
static int	rpcib_is_ib_interface(char *);
static int	rpcib_dl_info(ldi_handle_t, dl_info_ack_t *);
static int	rpcib_do_ip_ioctl(int, int, caddr_t);
static boolean_t	rpcib_get_ib_addresses(struct sockaddr_in *,
			struct sockaddr_in6 *, uint_t *, uint_t *);
static	uint_t rpcib_get_number_interfaces(void);
static int rpcib_cache_kstat_update(kstat_t *, int);
static void rib_force_cleanup(void *);

struct {
	kstat_named_t cache_limit;
	kstat_named_t cache_allocation;
	kstat_named_t cache_hits;
	kstat_named_t cache_misses;
	kstat_named_t cache_misses_above_the_limit;
} rpcib_kstat = {
	{"cache_limit",			KSTAT_DATA_UINT64 },
	{"cache_allocation",		KSTAT_DATA_UINT64 },
	{"cache_hits",			KSTAT_DATA_UINT64 },
	{"cache_misses",		KSTAT_DATA_UINT64 },
	{"cache_misses_above_the_limit", KSTAT_DATA_UINT64 },
};

/* rpcib cb_ops */
static struct cb_ops rpcib_cbops = {
	nulldev,		/* open */
	nulldev,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	nodev,			/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* prop_op */
	NULL,			/* stream */
	D_MP,			/* cb_flag */
	CB_REV,			/* rev */
	nodev,			/* int (*cb_aread)() */
	nodev			/* int (*cb_awrite)() */
};




/*
 * Device options
 */
static struct dev_ops rpcib_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	rpcib_getinfo,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	rpcib_attach,		/* attach */
	rpcib_detach,		/* detach */
	nodev,			/* reset */
	&rpcib_cbops,		    /* driver ops - devctl interfaces */
	NULL,			/* bus operations */
	NULL,			/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

/*
 * Module linkage information.
 */

static struct modldrv rib_modldrv = {
	&mod_driverops,		/* Driver module */
	"RPCIB plugin driver",	/* Driver name and version */
	&rpcib_ops,		/* Driver ops */
};

static struct modlinkage rib_modlinkage = {
	MODREV_1,
	(void *)&rib_modldrv,
	NULL
};

typedef struct rib_lrc_entry {
	struct rib_lrc_entry *forw;
	struct rib_lrc_entry *back;
	char *lrc_buf;

	uint32_t lrc_len;
	void  *avl_node;
	bool_t registered;

	struct mrc lrc_mhandle;
	bool_t lrc_on_freed_list;
} rib_lrc_entry_t;

typedef	struct cache_struct	{
	rib_lrc_entry_t		r;
	uint32_t		len;
	uint32_t		elements;
	kmutex_t		node_lock;
	avl_node_t		avl_link;
} cache_avl_struct_t;


static uint64_t 	rib_total_buffers = 0;
uint64_t	cache_limit = 100 * 1024 * 1024;
static volatile uint64_t	cache_allocation = 0;
static uint64_t	cache_watermark = 80 * 1024 * 1024;
static uint64_t	cache_hits = 0;
static uint64_t	cache_misses = 0;
static uint64_t	cache_cold_misses = 0;
static uint64_t	cache_hot_misses = 0;
static uint64_t	cache_misses_above_the_limit = 0;
static bool_t	stats_enabled = FALSE;

static uint64_t max_unsignaled_rws = 5;

/*
 * rib_stat: private data pointer used when registering
 *	with the IBTF.  It is returned to the consumer
 *	in all callbacks.
 */
static rpcib_state_t *rib_stat = NULL;

#define	RNR_RETRIES	IBT_RNR_RETRY_1
#define	MAX_PORTS	2

int preposted_rbufs = RDMA_BUFS_GRANT;
int send_threshold = 1;

/*
 * State of the plugin.
 * ACCEPT = accepting new connections and requests.
 * NO_ACCEPT = not accepting new connection and requests.
 * This should eventually move to rpcib_state_t structure, since this
 * will tell in which state the plugin is for a particular type of service
 * like NFS, NLM or v4 Callback deamon. The plugin might be in accept
 * state for one and in no_accept state for the other.
 */
int		plugin_state;
kmutex_t	plugin_state_lock;

ldi_ident_t rpcib_li;

/*
 * RPCIB RDMATF operations
 */
#if defined(MEASURE_POOL_DEPTH)
static void rib_posted_rbufs(uint32_t x) { return; }
#endif
static rdma_stat rib_reachable(int addr_type, struct netbuf *, void **handle);
static rdma_stat rib_disconnect(CONN *conn);
static void rib_listen(struct rdma_svc_data *rd);
static void rib_listen_stop(struct rdma_svc_data *rd);
static rdma_stat rib_registermem(CONN *conn, caddr_t  adsp, caddr_t buf,
	uint_t buflen, struct mrc *buf_handle);
static rdma_stat rib_deregistermem(CONN *conn, caddr_t buf,
	struct mrc buf_handle);
static rdma_stat rib_registermem_via_hca(rib_hca_t *hca, caddr_t adsp,
		caddr_t buf, uint_t buflen, struct mrc *buf_handle);
static rdma_stat rib_deregistermem_via_hca(rib_hca_t *hca, caddr_t buf,
		struct mrc buf_handle);
static rdma_stat rib_registermemsync(CONN *conn,  caddr_t adsp, caddr_t buf,
	uint_t buflen, struct mrc *buf_handle, RIB_SYNCMEM_HANDLE *sync_handle,
	void *lrc);
static rdma_stat rib_deregistermemsync(CONN *conn, caddr_t buf,
	struct mrc buf_handle, RIB_SYNCMEM_HANDLE sync_handle, void *);
static rdma_stat rib_syncmem(CONN *conn, RIB_SYNCMEM_HANDLE shandle,
	caddr_t buf, int len, int cpu);

static rdma_stat rib_reg_buf_alloc(CONN *conn, rdma_buf_t *rdbuf);

static void rib_reg_buf_free(CONN *conn, rdma_buf_t *rdbuf);
static void *rib_rbuf_alloc(CONN *, rdma_buf_t *);

static void rib_rbuf_free(CONN *conn, int ptype, void *buf);

static rdma_stat rib_send(CONN *conn, struct clist *cl, uint32_t msgid);
static rdma_stat rib_send_resp(CONN *conn, struct clist *cl, uint32_t msgid);
static rdma_stat rib_post_resp(CONN *conn, struct clist *cl, uint32_t msgid);
static rdma_stat rib_post_resp_remove(CONN *conn, uint32_t msgid);
static rdma_stat rib_post_recv(CONN *conn, struct clist *cl);
static rdma_stat rib_recv(CONN *conn, struct clist **clp, uint32_t msgid);
static rdma_stat rib_read(CONN *conn, struct clist *cl, int wait);
static rdma_stat rib_write(CONN *conn, struct clist *cl, int wait);
static rdma_stat rib_ping_srv(int addr_type, struct netbuf *, rib_hca_t **);
static rdma_stat rib_conn_get(struct netbuf *, int addr_type, void *, CONN **);
static rdma_stat rib_conn_release(CONN *conn);
static rdma_stat rib_getinfo(rdma_info_t *info);

static rib_lrc_entry_t *rib_get_cache_buf(CONN *conn, uint32_t len);
static void rib_free_cache_buf(CONN *conn, rib_lrc_entry_t *buf);
static void rib_destroy_cache(rib_hca_t *hca);
static	void	rib_server_side_cache_reclaim(void *argp);
static int avl_compare(const void *t1, const void *t2);

static void rib_stop_services(rib_hca_t *);
static void rib_close_channels(rib_conn_list_t *);

/*
 * RPCIB addressing operations
 */

/*
 * RDMA operations the RPCIB module exports
 */
static rdmaops_t rib_ops = {
	rib_reachable,
	rib_conn_get,
	rib_conn_release,
	rib_listen,
	rib_listen_stop,
	rib_registermem,
	rib_deregistermem,
	rib_registermemsync,
	rib_deregistermemsync,
	rib_syncmem,
	rib_reg_buf_alloc,
	rib_reg_buf_free,
	rib_send,
	rib_send_resp,
	rib_post_resp,
	rib_post_resp_remove,
	rib_post_recv,
	rib_recv,
	rib_read,
	rib_write,
	rib_getinfo,
};

/*
 * RDMATF RPCIB plugin details
 */
static rdma_mod_t rib_mod = {
	"ibtf",		/* api name */
	RDMATF_VERS_1,
	0,
	&rib_ops,	/* rdma op vector for ibtf */
};

static rdma_stat open_hcas(rpcib_state_t *);
static rdma_stat rib_qp_init(rib_qp_t *, int);
static void rib_svc_scq_handler(ibt_cq_hdl_t, void *);
static void rib_clnt_scq_handler(ibt_cq_hdl_t, void *);
static void rib_clnt_rcq_handler(ibt_cq_hdl_t, void *);
static void rib_svc_rcq_handler(ibt_cq_hdl_t, void *);
static rib_bufpool_t *rib_rbufpool_create(rib_hca_t *hca, int ptype, int num);
static rdma_stat rib_reg_mem(rib_hca_t *, caddr_t adsp, caddr_t, uint_t,
	ibt_mr_flags_t, ibt_mr_hdl_t *, ibt_mr_desc_t *);
static rdma_stat rib_reg_mem_user(rib_hca_t *, caddr_t, uint_t, ibt_mr_flags_t,
	ibt_mr_hdl_t *, ibt_mr_desc_t *, caddr_t);
static rdma_stat rib_conn_to_srv(rib_hca_t *, rib_qp_t *, ibt_path_info_t *,
	ibt_ip_addr_t *, ibt_ip_addr_t *);
static rdma_stat rib_clnt_create_chan(rib_hca_t *, struct netbuf *,
	rib_qp_t **);
static rdma_stat rib_svc_create_chan(rib_hca_t *, caddr_t, uint8_t,
	rib_qp_t **);
static rdma_stat rib_sendwait(rib_qp_t *, struct send_wid *);
static struct send_wid *rib_init_sendwait(uint32_t, int, rib_qp_t *);
static int rib_free_sendwait(struct send_wid *);
static struct rdma_done_list *rdma_done_add(rib_qp_t *qp, uint32_t xid);
static void rdma_done_rm(rib_qp_t *qp, struct rdma_done_list *rd);
static void rdma_done_rem_list(rib_qp_t *);
static void rdma_done_notify(rib_qp_t *qp, uint32_t xid);

static void rib_async_handler(void *,
	ibt_hca_hdl_t, ibt_async_code_t, ibt_async_event_t *);
static rdma_stat rib_rem_rep(rib_qp_t *, struct reply *);
static struct svc_recv *rib_init_svc_recv(rib_qp_t *, ibt_wr_ds_t *);
static int rib_free_svc_recv(struct svc_recv *);
static struct recv_wid *rib_create_wid(rib_qp_t *, ibt_wr_ds_t *, uint32_t);
static void rib_free_wid(struct recv_wid *);
static rdma_stat rib_disconnect_channel(CONN *, rib_conn_list_t *);
static void rib_detach_hca(rib_hca_t *);
static rdma_stat rib_chk_srv_ibaddr(struct netbuf *, int,
	ibt_path_info_t *, ibt_ip_addr_t *, ibt_ip_addr_t *);

/*
 * Registration with IBTF as a consumer
 */
static struct ibt_clnt_modinfo_s rib_modinfo = {
	IBTI_V2,
	IBT_GENERIC,
	rib_async_handler,	/* async event handler */
	NULL,			/* Memory Region Handler */
	"nfs/ib"
};

/*
 * Global strucuture
 */

typedef struct rpcib_s {
	dev_info_t	*rpcib_dip;
	kmutex_t	rpcib_mutex;
} rpcib_t;

rpcib_t rpcib;

/*
 * /etc/system controlled variable to control
 * debugging in rpcib kernel module.
 * Set it to values greater that 1 to control
 * the amount of debugging messages required.
 */
int rib_debug = 0;


int
_init(void)
{
	int		error;
	int ret;

	error = mod_install((struct modlinkage *)&rib_modlinkage);
	if (error != 0) {
		/*
		 * Could not load module
		 */
		return (error);
	}
	ret = ldi_ident_from_mod(&rib_modlinkage, &rpcib_li);
	if (ret != 0)
		rpcib_li = NULL;
	mutex_init(&plugin_state_lock, NULL, MUTEX_DRIVER, NULL);

	return (0);
}

int
_fini()
{
	int status;

	if ((status = rdma_unregister_mod(&rib_mod)) != RDMA_SUCCESS) {
		return (EBUSY);
	}

	/*
	 * Remove module
	 */
	if ((status = mod_remove(&rib_modlinkage)) != 0) {
		(void) rdma_register_mod(&rib_mod);
		return (status);
	}
	mutex_destroy(&plugin_state_lock);
	ldi_ident_release(rpcib_li);
	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&rib_modlinkage, modinfop));
}


/*
 * rpcib_getinfo()
 * Given the device number, return the devinfo pointer or the
 * instance number.
 * Note: always succeed DDI_INFO_DEVT2INSTANCE, even before attach.
 */

/*ARGSUSED*/
static int
rpcib_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	int ret = DDI_SUCCESS;

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (rpcib.rpcib_dip != NULL)
			*result = rpcib.rpcib_dip;
		else {
			*result = NULL;
			ret = DDI_FAILURE;
		}
		break;

	case DDI_INFO_DEVT2INSTANCE:
		*result = NULL;
		break;

	default:
		ret = DDI_FAILURE;
	}
	return (ret);
}

static int
rpcib_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	ibt_status_t	ibt_status;
	rdma_stat	r_status;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	mutex_init(&rpcib.rpcib_mutex, NULL, MUTEX_DRIVER, NULL);

	mutex_enter(&rpcib.rpcib_mutex);
	if (rpcib.rpcib_dip != NULL) {
		mutex_exit(&rpcib.rpcib_mutex);
		return (DDI_FAILURE);
	}
	rpcib.rpcib_dip = dip;
	mutex_exit(&rpcib.rpcib_mutex);
	/*
	 * Create the "rpcib" minor-node.
	 */
	if (ddi_create_minor_node(dip,
	    "rpcib", S_IFCHR, 0, DDI_PSEUDO, 0) != DDI_SUCCESS) {
		/* Error message, no cmn_err as they print on console */
		return (DDI_FAILURE);
	}

	if (rib_stat == NULL) {
		rib_stat = kmem_zalloc(sizeof (*rib_stat), KM_SLEEP);
		mutex_init(&rib_stat->open_hca_lock, NULL, MUTEX_DRIVER, NULL);
	}

	rib_stat->hca_count = ibt_get_hca_list(&rib_stat->hca_guids);
	if (rib_stat->hca_count < 1) {
		mutex_destroy(&rib_stat->open_hca_lock);
		kmem_free(rib_stat, sizeof (*rib_stat));
		rib_stat = NULL;
		return (DDI_FAILURE);
	}

	ibt_status = ibt_attach(&rib_modinfo, dip,
	    (void *)rib_stat, &rib_stat->ibt_clnt_hdl);

	if (ibt_status != IBT_SUCCESS) {
		ibt_free_hca_list(rib_stat->hca_guids, rib_stat->hca_count);
		mutex_destroy(&rib_stat->open_hca_lock);
		kmem_free(rib_stat, sizeof (*rib_stat));
		rib_stat = NULL;
		return (DDI_FAILURE);
	}

	mutex_enter(&rib_stat->open_hca_lock);
	if (open_hcas(rib_stat) != RDMA_SUCCESS) {
		ibt_free_hca_list(rib_stat->hca_guids, rib_stat->hca_count);
		(void) ibt_detach(rib_stat->ibt_clnt_hdl);
		mutex_exit(&rib_stat->open_hca_lock);
		mutex_destroy(&rib_stat->open_hca_lock);
		kmem_free(rib_stat, sizeof (*rib_stat));
		rib_stat = NULL;
		return (DDI_FAILURE);
	}
	mutex_exit(&rib_stat->open_hca_lock);

	/*
	 * Register with rdmatf
	 */
	rib_mod.rdma_count = rib_stat->hca_count;
	r_status = rdma_register_mod(&rib_mod);
	if (r_status != RDMA_SUCCESS && r_status != RDMA_REG_EXIST) {
		rib_detach_hca(rib_stat->hca);
		ibt_free_hca_list(rib_stat->hca_guids, rib_stat->hca_count);
		(void) ibt_detach(rib_stat->ibt_clnt_hdl);
		mutex_destroy(&rib_stat->open_hca_lock);
		kmem_free(rib_stat, sizeof (*rib_stat));
		rib_stat = NULL;
		return (DDI_FAILURE);
	}


	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
rpcib_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {

	case DDI_DETACH:
		break;

	case DDI_SUSPEND:
	default:
		return (DDI_FAILURE);
	}

	/*
	 * Detach the hca and free resources
	 */
	mutex_enter(&plugin_state_lock);
	plugin_state = NO_ACCEPT;
	mutex_exit(&plugin_state_lock);
	rib_detach_hca(rib_stat->hca);
	ibt_free_hca_list(rib_stat->hca_guids, rib_stat->hca_count);
	(void) ibt_detach(rib_stat->ibt_clnt_hdl);

	mutex_enter(&rpcib.rpcib_mutex);
	rpcib.rpcib_dip = NULL;
	mutex_exit(&rpcib.rpcib_mutex);

	mutex_destroy(&rpcib.rpcib_mutex);
	return (DDI_SUCCESS);
}


static void rib_rbufpool_free(rib_hca_t *, int);
static void rib_rbufpool_deregister(rib_hca_t *, int);
static void rib_rbufpool_destroy(rib_hca_t *hca, int ptype);
static struct reply *rib_addreplylist(rib_qp_t *, uint32_t);
static rdma_stat rib_rem_replylist(rib_qp_t *);
static int rib_remreply(rib_qp_t *, struct reply *);
static rdma_stat rib_add_connlist(CONN *, rib_conn_list_t *);
static rdma_stat rib_rm_conn(CONN *, rib_conn_list_t *);


/*
 * One CQ pair per HCA
 */
static rdma_stat
rib_create_cq(rib_hca_t *hca, uint32_t cq_size, ibt_cq_handler_t cq_handler,
	rib_cq_t **cqp, rpcib_state_t *ribstat)
{
	rib_cq_t	*cq;
	ibt_cq_attr_t	cq_attr;
	uint32_t	real_size;
	ibt_status_t	status;
	rdma_stat	error = RDMA_SUCCESS;

	cq = kmem_zalloc(sizeof (rib_cq_t), KM_SLEEP);
	cq->rib_hca = hca;
	cq_attr.cq_size = cq_size;
	cq_attr.cq_flags = IBT_CQ_NO_FLAGS;
	status = ibt_alloc_cq(hca->hca_hdl, &cq_attr, &cq->rib_cq_hdl,
	    &real_size);
	if (status != IBT_SUCCESS) {
		cmn_err(CE_WARN, "rib_create_cq: ibt_alloc_cq() failed,"
		    " status=%d", status);
		error = RDMA_FAILED;
		goto fail;
	}
	ibt_set_cq_handler(cq->rib_cq_hdl, cq_handler, ribstat);

	/*
	 * Enable CQ callbacks. CQ Callbacks are single shot
	 * (e.g. you have to call ibt_enable_cq_notify()
	 * after each callback to get another one).
	 */
	status = ibt_enable_cq_notify(cq->rib_cq_hdl, IBT_NEXT_COMPLETION);
	if (status != IBT_SUCCESS) {
		cmn_err(CE_WARN, "rib_create_cq: "
		    "enable_cq_notify failed, status %d", status);
		error = RDMA_FAILED;
		goto fail;
	}
	*cqp = cq;

	return (error);
fail:
	if (cq->rib_cq_hdl)
		(void) ibt_free_cq(cq->rib_cq_hdl);
	if (cq)
		kmem_free(cq, sizeof (rib_cq_t));
	return (error);
}

static rdma_stat
open_hcas(rpcib_state_t *ribstat)
{
	rib_hca_t		*hca;
	ibt_status_t		ibt_status;
	rdma_stat		status;
	ibt_hca_portinfo_t	*pinfop;
	ibt_pd_flags_t		pd_flags = IBT_PD_NO_FLAGS;
	uint_t			size, cq_size;
	int			i;
	kstat_t *ksp;
	cache_avl_struct_t example_avl_node;
	char rssc_name[32];

	ASSERT(MUTEX_HELD(&ribstat->open_hca_lock));

	if (ribstat->hcas == NULL)
		ribstat->hcas = kmem_zalloc(ribstat->hca_count *
		    sizeof (rib_hca_t), KM_SLEEP);

	/*
	 * Open a hca and setup for RDMA
	 */
	for (i = 0; i < ribstat->hca_count; i++) {
		ibt_status = ibt_open_hca(ribstat->ibt_clnt_hdl,
		    ribstat->hca_guids[i],
		    &ribstat->hcas[i].hca_hdl);
		if (ibt_status != IBT_SUCCESS) {
			continue;
		}
		ribstat->hcas[i].hca_guid = ribstat->hca_guids[i];
		hca = &(ribstat->hcas[i]);
		hca->ibt_clnt_hdl = ribstat->ibt_clnt_hdl;
		hca->state = HCA_INITED;

		/*
		 * query HCA info
		 */
		ibt_status = ibt_query_hca(hca->hca_hdl, &hca->hca_attrs);
		if (ibt_status != IBT_SUCCESS) {
			goto fail1;
		}

		/*
		 * One PD (Protection Domain) per HCA.
		 * A qp is allowed to access a memory region
		 * only when it's in the same PD as that of
		 * the memory region.
		 */
		ibt_status = ibt_alloc_pd(hca->hca_hdl, pd_flags, &hca->pd_hdl);
		if (ibt_status != IBT_SUCCESS) {
			goto fail1;
		}

		/*
		 * query HCA ports
		 */
		ibt_status = ibt_query_hca_ports(hca->hca_hdl,
		    0, &pinfop, &hca->hca_nports, &size);
		if (ibt_status != IBT_SUCCESS) {
			goto fail2;
		}
		hca->hca_ports = pinfop;
		hca->hca_pinfosz = size;
		pinfop = NULL;

		cq_size = DEF_CQ_SIZE; /* default cq size */
		/*
		 * Create 2 pairs of cq's (1 pair for client
		 * and the other pair for server) on this hca.
		 * If number of qp's gets too large, then several
		 * cq's will be needed.
		 */
		status = rib_create_cq(hca, cq_size, rib_svc_rcq_handler,
		    &hca->svc_rcq, ribstat);
		if (status != RDMA_SUCCESS) {
			goto fail3;
		}

		status = rib_create_cq(hca, cq_size, rib_svc_scq_handler,
		    &hca->svc_scq, ribstat);
		if (status != RDMA_SUCCESS) {
			goto fail3;
		}

		status = rib_create_cq(hca, cq_size, rib_clnt_rcq_handler,
		    &hca->clnt_rcq, ribstat);
		if (status != RDMA_SUCCESS) {
			goto fail3;
		}

		status = rib_create_cq(hca, cq_size, rib_clnt_scq_handler,
		    &hca->clnt_scq, ribstat);
		if (status != RDMA_SUCCESS) {
			goto fail3;
		}

		/*
		 * Create buffer pools.
		 * Note rib_rbuf_create also allocates memory windows.
		 */
		hca->recv_pool = rib_rbufpool_create(hca,
		    RECV_BUFFER, MAX_BUFS);
		if (hca->recv_pool == NULL) {
			goto fail3;
		}

		hca->send_pool = rib_rbufpool_create(hca,
		    SEND_BUFFER, MAX_BUFS);
		if (hca->send_pool == NULL) {
			rib_rbufpool_destroy(hca, RECV_BUFFER);
			goto fail3;
		}

		if (hca->server_side_cache == NULL) {
			(void) sprintf(rssc_name,
			    "rib_server_side_cache_%04d", i);
			hca->server_side_cache = kmem_cache_create(
			    rssc_name,
			    sizeof (cache_avl_struct_t), 0,
			    NULL,
			    NULL,
			    rib_server_side_cache_reclaim,
			    hca, NULL, 0);
		}

		avl_create(&hca->avl_tree,
		    avl_compare,
		    sizeof (cache_avl_struct_t),
		    (uint_t)(uintptr_t)&example_avl_node.avl_link-
		    (uint_t)(uintptr_t)&example_avl_node);

		rw_init(&hca->avl_rw_lock,
		    NULL, RW_DRIVER, hca->iblock);
		mutex_init(&hca->cache_allocation,
		    NULL, MUTEX_DRIVER, NULL);
		hca->avl_init = TRUE;

		/* Create kstats for the cache */
		ASSERT(INGLOBALZONE(curproc));

		if (!stats_enabled) {
			ksp = kstat_create_zone("unix", 0, "rpcib_cache", "rpc",
			    KSTAT_TYPE_NAMED,
			    sizeof (rpcib_kstat) / sizeof (kstat_named_t),
			    KSTAT_FLAG_VIRTUAL | KSTAT_FLAG_WRITABLE,
			    GLOBAL_ZONEID);
			if (ksp) {
				ksp->ks_data = (void *) &rpcib_kstat;
				ksp->ks_update = rpcib_cache_kstat_update;
				kstat_install(ksp);
				stats_enabled = TRUE;
			}
		}
		if (NULL == hca->reg_cache_clean_up) {
			hca->reg_cache_clean_up = ddi_taskq_create(NULL,
			    "REG_CACHE_CLEANUP", 1, TASKQ_DEFAULTPRI, 0);
		}

		/*
		 * Initialize the registered service list and
		 * the lock
		 */
		hca->service_list = NULL;
		rw_init(&hca->service_list_lock, NULL, RW_DRIVER, hca->iblock);

		mutex_init(&hca->cb_lock, NULL, MUTEX_DRIVER, hca->iblock);
		cv_init(&hca->cb_cv, NULL, CV_DRIVER, NULL);
		rw_init(&hca->cl_conn_list.conn_lock, NULL, RW_DRIVER,
		    hca->iblock);
		rw_init(&hca->srv_conn_list.conn_lock, NULL, RW_DRIVER,
		    hca->iblock);
		rw_init(&hca->state_lock, NULL, RW_DRIVER, hca->iblock);
		mutex_init(&hca->inuse_lock, NULL, MUTEX_DRIVER, hca->iblock);
		hca->inuse = TRUE;
		/*
		 * XXX One hca only. Add multi-hca functionality if needed
		 * later.
		 */
		ribstat->hca = hca;
		ribstat->nhca_inited++;
		ibt_free_portinfo(hca->hca_ports, hca->hca_pinfosz);
		break;

fail3:
		ibt_free_portinfo(hca->hca_ports, hca->hca_pinfosz);
fail2:
		(void) ibt_free_pd(hca->hca_hdl, hca->pd_hdl);
fail1:
		(void) ibt_close_hca(hca->hca_hdl);

	}
	if (ribstat->hca != NULL)
		return (RDMA_SUCCESS);
	else
		return (RDMA_FAILED);
}

/*
 * Callback routines
 */

/*
 * SCQ handlers
 */
/* ARGSUSED */
static void
rib_clnt_scq_handler(ibt_cq_hdl_t cq_hdl, void *arg)
{
	ibt_status_t	ibt_status;
	ibt_wc_t	wc;
	int		i;

	/*
	 * Re-enable cq notify here to avoid missing any
	 * completion queue notification.
	 */
	(void) ibt_enable_cq_notify(cq_hdl, IBT_NEXT_COMPLETION);

	ibt_status = IBT_SUCCESS;
	while (ibt_status != IBT_CQ_EMPTY) {
	bzero(&wc, sizeof (wc));
	ibt_status = ibt_poll_cq(cq_hdl, &wc, 1, NULL);
	if (ibt_status != IBT_SUCCESS)
		return;

	/*
	 * Got a send completion
	 */
	if (wc.wc_id != NULL) {	/* XXX can it be otherwise ???? */
		struct send_wid *wd = (struct send_wid *)(uintptr_t)wc.wc_id;
		CONN	*conn = qptoc(wd->qp);

		mutex_enter(&wd->sendwait_lock);
		switch (wc.wc_status) {
		case IBT_WC_SUCCESS:
			wd->status = RDMA_SUCCESS;
			break;
		case IBT_WC_WR_FLUSHED_ERR:
			wd->status = RDMA_FAILED;
			break;
		default:
/*
 *    RC Send Q Error Code		Local state     Remote State
 *    ==================== 		===========     ============
 *    IBT_WC_BAD_RESPONSE_ERR             ERROR           None
 *    IBT_WC_LOCAL_LEN_ERR                ERROR           None
 *    IBT_WC_LOCAL_CHAN_OP_ERR            ERROR           None
 *    IBT_WC_LOCAL_PROTECT_ERR            ERROR           None
 *    IBT_WC_MEM_WIN_BIND_ERR             ERROR           None
 *    IBT_WC_REMOTE_INVALID_REQ_ERR       ERROR           ERROR
 *    IBT_WC_REMOTE_ACCESS_ERR            ERROR           ERROR
 *    IBT_WC_REMOTE_OP_ERR                ERROR           ERROR
 *    IBT_WC_RNR_NAK_TIMEOUT_ERR          ERROR           None
 *    IBT_WC_TRANS_TIMEOUT_ERR            ERROR           None
 *    IBT_WC_WR_FLUSHED_ERR               None            None
 */
			/*
			 * Channel in error state. Set connection to
			 * ERROR and cleanup will happen either from
			 * conn_release  or from rib_conn_get
			 */
			wd->status = RDMA_FAILED;
			mutex_enter(&conn->c_lock);
			if (conn->c_state != C_DISCONN_PEND)
				conn->c_state = C_ERROR_CONN;
			mutex_exit(&conn->c_lock);
			break;
		}

		if (wd->cv_sig == 1) {
			/*
			 * Notify poster
			 */
			cv_signal(&wd->wait_cv);
			mutex_exit(&wd->sendwait_lock);
		} else {
			/*
			 * Poster not waiting for notification.
			 * Free the send buffers and send_wid
			 */
			for (i = 0; i < wd->nsbufs; i++) {
				rib_rbuf_free(qptoc(wd->qp), SEND_BUFFER,
				    (void *)(uintptr_t)wd->sbufaddr[i]);
				}
			mutex_exit(&wd->sendwait_lock);
			(void) rib_free_sendwait(wd);
			}
		}
	}
}

/* ARGSUSED */
static void
rib_svc_scq_handler(ibt_cq_hdl_t cq_hdl, void *arg)
{
	ibt_status_t	ibt_status;
	ibt_wc_t	wc;
	int		i;

	/*
	 * Re-enable cq notify here to avoid missing any
	 * completion queue notification.
	 */
	(void) ibt_enable_cq_notify(cq_hdl, IBT_NEXT_COMPLETION);

	ibt_status = IBT_SUCCESS;
	while (ibt_status != IBT_CQ_EMPTY) {
		bzero(&wc, sizeof (wc));
		ibt_status = ibt_poll_cq(cq_hdl, &wc, 1, NULL);
		if (ibt_status != IBT_SUCCESS)
			return;

		/*
		 * Got a send completion
		 */
		if (wc.wc_id != NULL) { /* XXX NULL possible ???? */
			struct send_wid *wd =
			    (struct send_wid *)(uintptr_t)wc.wc_id;
			mutex_enter(&wd->sendwait_lock);
			if (wd->cv_sig == 1) {
				/*
				 * Update completion status and notify poster
				 */
				if (wc.wc_status == IBT_WC_SUCCESS)
					wd->status = RDMA_SUCCESS;
				else
					wd->status = RDMA_FAILED;
				cv_signal(&wd->wait_cv);
				mutex_exit(&wd->sendwait_lock);
			} else {
				/*
				 * Poster not waiting for notification.
				 * Free the send buffers and send_wid
				 */
				for (i = 0; i < wd->nsbufs; i++) {
					rib_rbuf_free(qptoc(wd->qp),
					    SEND_BUFFER,
					    (void *)(uintptr_t)wd->sbufaddr[i]);
				}
				mutex_exit(&wd->sendwait_lock);
				(void) rib_free_sendwait(wd);
			}
		}
	}
}

/*
 * RCQ handler
 */
/* ARGSUSED */
static void
rib_clnt_rcq_handler(ibt_cq_hdl_t cq_hdl, void *arg)
{
	rib_qp_t	*qp;
	ibt_status_t	ibt_status;
	ibt_wc_t	wc;
	struct recv_wid	*rwid;

	/*
	 * Re-enable cq notify here to avoid missing any
	 * completion queue notification.
	 */
	(void) ibt_enable_cq_notify(cq_hdl, IBT_NEXT_COMPLETION);

	ibt_status = IBT_SUCCESS;
	while (ibt_status != IBT_CQ_EMPTY) {
		bzero(&wc, sizeof (wc));
		ibt_status = ibt_poll_cq(cq_hdl, &wc, 1, NULL);
		if (ibt_status != IBT_SUCCESS)
			return;

		rwid = (struct recv_wid *)(uintptr_t)wc.wc_id;
		qp = rwid->qp;
		if (wc.wc_status == IBT_WC_SUCCESS) {
			XDR	inxdrs, *xdrs;
			uint_t	xid, vers, op, find_xid = 0;
			struct reply	*r;
			CONN *conn = qptoc(qp);
			uint32_t rdma_credit = 0;

			xdrs = &inxdrs;
			xdrmem_create(xdrs, (caddr_t)(uintptr_t)rwid->addr,
			    wc.wc_bytes_xfer, XDR_DECODE);
			/*
			 * Treat xid as opaque (xid is the first entity
			 * in the rpc rdma message).
			 */
			xid = *(uint32_t *)(uintptr_t)rwid->addr;

			/* Skip xid and set the xdr position accordingly. */
			XDR_SETPOS(xdrs, sizeof (uint32_t));
			(void) xdr_u_int(xdrs, &vers);
			(void) xdr_u_int(xdrs, &rdma_credit);
			(void) xdr_u_int(xdrs, &op);
			XDR_DESTROY(xdrs);

			if (vers != RPCRDMA_VERS) {
				/*
				 * Invalid RPC/RDMA version. Cannot
				 * interoperate.  Set connection to
				 * ERROR state and bail out.
				 */
				mutex_enter(&conn->c_lock);
				if (conn->c_state != C_DISCONN_PEND)
					conn->c_state = C_ERROR_CONN;
				mutex_exit(&conn->c_lock);
				rib_rbuf_free(conn, RECV_BUFFER,
				    (void *)(uintptr_t)rwid->addr);
				rib_free_wid(rwid);
				continue;
			}

			mutex_enter(&qp->replylist_lock);
			for (r = qp->replylist; r != NULL; r = r->next) {
				if (r->xid == xid) {
					find_xid = 1;
					switch (op) {
					case RDMA_MSG:
					case RDMA_NOMSG:
					case RDMA_MSGP:
						r->status = RDMA_SUCCESS;
						r->vaddr_cq = rwid->addr;
						r->bytes_xfer =
						    wc.wc_bytes_xfer;
						cv_signal(&r->wait_cv);
						break;
					default:
						rib_rbuf_free(qptoc(qp),
						    RECV_BUFFER,
						    (void *)(uintptr_t)
						    rwid->addr);
						break;
					}
					break;
				}
			}
			mutex_exit(&qp->replylist_lock);
			if (find_xid == 0) {
				/* RPC caller not waiting for reply */

				DTRACE_PROBE1(rpcib__i__nomatchxid1,
				    int, xid);

				rib_rbuf_free(qptoc(qp), RECV_BUFFER,
				    (void *)(uintptr_t)rwid->addr);
			}
		} else if (wc.wc_status == IBT_WC_WR_FLUSHED_ERR) {
			CONN *conn = qptoc(qp);

			/*
			 * Connection being flushed. Just free
			 * the posted buffer
			 */
			rib_rbuf_free(conn, RECV_BUFFER,
			    (void *)(uintptr_t)rwid->addr);
		} else {
			CONN *conn = qptoc(qp);
/*
 *  RC Recv Q Error Code		Local state     Remote State
 *  ====================		===========     ============
 *  IBT_WC_LOCAL_ACCESS_ERR             ERROR           ERROR when NAK recvd
 *  IBT_WC_LOCAL_LEN_ERR                ERROR           ERROR when NAK recvd
 *  IBT_WC_LOCAL_PROTECT_ERR            ERROR           ERROR when NAK recvd
 *  IBT_WC_LOCAL_CHAN_OP_ERR            ERROR           ERROR when NAK recvd
 *  IBT_WC_REMOTE_INVALID_REQ_ERR       ERROR           ERROR when NAK recvd
 *  IBT_WC_WR_FLUSHED_ERR               None            None
 */
			/*
			 * Channel in error state. Set connection
			 * in ERROR state.
			 */
			mutex_enter(&conn->c_lock);
			if (conn->c_state != C_DISCONN_PEND)
				conn->c_state = C_ERROR_CONN;
			mutex_exit(&conn->c_lock);
			rib_rbuf_free(conn, RECV_BUFFER,
			    (void *)(uintptr_t)rwid->addr);
		}
		rib_free_wid(rwid);
	}
}

/* Server side */
/* ARGSUSED */
static void
rib_svc_rcq_handler(ibt_cq_hdl_t cq_hdl, void *arg)
{
	rdma_recv_data_t *rdp;
	rib_qp_t	*qp;
	ibt_status_t	ibt_status;
	ibt_wc_t	wc;
	struct svc_recv	*s_recvp;
	CONN		*conn;
	mblk_t		*mp;

	/*
	 * Re-enable cq notify here to avoid missing any
	 * completion queue notification.
	 */
	(void) ibt_enable_cq_notify(cq_hdl, IBT_NEXT_COMPLETION);

	ibt_status = IBT_SUCCESS;
	while (ibt_status != IBT_CQ_EMPTY) {
		bzero(&wc, sizeof (wc));
		ibt_status = ibt_poll_cq(cq_hdl, &wc, 1, NULL);
		if (ibt_status != IBT_SUCCESS)
			return;

		s_recvp = (struct svc_recv *)(uintptr_t)wc.wc_id;
		qp = s_recvp->qp;
		conn = qptoc(qp);
		mutex_enter(&qp->posted_rbufs_lock);
		qp->n_posted_rbufs--;
#if defined(MEASURE_POOL_DEPTH)
		rib_posted_rbufs(preposted_rbufs -  qp->n_posted_rbufs);
#endif
		if (qp->n_posted_rbufs == 0)
			cv_signal(&qp->posted_rbufs_cv);
		mutex_exit(&qp->posted_rbufs_lock);

		if (wc.wc_status == IBT_WC_SUCCESS) {
			XDR	inxdrs, *xdrs;
			uint_t	xid, vers, op;
			uint32_t rdma_credit;

			xdrs = &inxdrs;
			/* s_recvp->vaddr stores data */
			xdrmem_create(xdrs, (caddr_t)(uintptr_t)s_recvp->vaddr,
			    wc.wc_bytes_xfer, XDR_DECODE);

			/*
			 * Treat xid as opaque (xid is the first entity
			 * in the rpc rdma message).
			 */
			xid = *(uint32_t *)(uintptr_t)s_recvp->vaddr;
			/* Skip xid and set the xdr position accordingly. */
			XDR_SETPOS(xdrs, sizeof (uint32_t));
			if (!xdr_u_int(xdrs, &vers) ||
			    !xdr_u_int(xdrs, &rdma_credit) ||
			    !xdr_u_int(xdrs, &op)) {
				rib_rbuf_free(conn, RECV_BUFFER,
				    (void *)(uintptr_t)s_recvp->vaddr);
				XDR_DESTROY(xdrs);
				(void) rib_free_svc_recv(s_recvp);
				continue;
			}
			XDR_DESTROY(xdrs);

			if (vers != RPCRDMA_VERS) {
				/*
				 * Invalid RPC/RDMA version.
				 * Drop rpc rdma message.
				 */
				rib_rbuf_free(conn, RECV_BUFFER,
				    (void *)(uintptr_t)s_recvp->vaddr);
				(void) rib_free_svc_recv(s_recvp);
				continue;
			}
			/*
			 * Is this for RDMA_DONE?
			 */
			if (op == RDMA_DONE) {
				rib_rbuf_free(conn, RECV_BUFFER,
				    (void *)(uintptr_t)s_recvp->vaddr);
				/*
				 * Wake up the thread waiting on
				 * a RDMA_DONE for xid
				 */
				mutex_enter(&qp->rdlist_lock);
				rdma_done_notify(qp, xid);
				mutex_exit(&qp->rdlist_lock);
				(void) rib_free_svc_recv(s_recvp);
				continue;
			}

			mutex_enter(&plugin_state_lock);
			if (plugin_state == ACCEPT) {
				while ((mp = allocb(sizeof (*rdp), BPRI_LO))
				    == NULL)
					(void) strwaitbuf(
					    sizeof (*rdp), BPRI_LO);
				/*
				 * Plugin is in accept state, hence the master
				 * transport queue for this is still accepting
				 * requests. Hence we can call svc_queuereq to
				 * queue this recieved msg.
				 */
				rdp = (rdma_recv_data_t *)mp->b_rptr;
				rdp->conn = conn;
				rdp->rpcmsg.addr =
				    (caddr_t)(uintptr_t)s_recvp->vaddr;
				rdp->rpcmsg.type = RECV_BUFFER;
				rdp->rpcmsg.len = wc.wc_bytes_xfer;
				rdp->status = wc.wc_status;
				mutex_enter(&conn->c_lock);
				conn->c_ref++;
				mutex_exit(&conn->c_lock);
				mp->b_wptr += sizeof (*rdp);
				svc_queuereq((queue_t *)rib_stat->q, mp);
				mutex_exit(&plugin_state_lock);
			} else {
				/*
				 * The master transport for this is going
				 * away and the queue is not accepting anymore
				 * requests for krpc, so don't do anything, just
				 * free the msg.
				 */
				mutex_exit(&plugin_state_lock);
				rib_rbuf_free(conn, RECV_BUFFER,
				    (void *)(uintptr_t)s_recvp->vaddr);
			}
		} else {
			rib_rbuf_free(conn, RECV_BUFFER,
			    (void *)(uintptr_t)s_recvp->vaddr);
		}
		(void) rib_free_svc_recv(s_recvp);
	}
}

/*
 * Handles DR event of IBT_HCA_DETACH_EVENT.
 */
/* ARGSUSED */
static void
rib_async_handler(void *clnt_private, ibt_hca_hdl_t hca_hdl,
	ibt_async_code_t code, ibt_async_event_t *event)
{

	switch (code) {
	case IBT_HCA_ATTACH_EVENT:
		/* ignore */
		break;
	case IBT_HCA_DETACH_EVENT:
	{
		ASSERT(rib_stat->hca->hca_hdl == hca_hdl);
		rib_detach_hca(rib_stat->hca);
#ifdef DEBUG
		cmn_err(CE_NOTE, "rib_async_handler(): HCA being detached!\n");
#endif
		break;
	}
#ifdef DEBUG
	case IBT_EVENT_PATH_MIGRATED:
		cmn_err(CE_NOTE, "rib_async_handler(): "
		    "IBT_EVENT_PATH_MIGRATED\n");
		break;
	case IBT_EVENT_SQD:
		cmn_err(CE_NOTE, "rib_async_handler(): IBT_EVENT_SQD\n");
		break;
	case IBT_EVENT_COM_EST:
		cmn_err(CE_NOTE, "rib_async_handler(): IBT_EVENT_COM_EST\n");
		break;
	case IBT_ERROR_CATASTROPHIC_CHAN:
		cmn_err(CE_NOTE, "rib_async_handler(): "
		    "IBT_ERROR_CATASTROPHIC_CHAN\n");
		break;
	case IBT_ERROR_INVALID_REQUEST_CHAN:
		cmn_err(CE_NOTE, "rib_async_handler(): "
		    "IBT_ERROR_INVALID_REQUEST_CHAN\n");
		break;
	case IBT_ERROR_ACCESS_VIOLATION_CHAN:
		cmn_err(CE_NOTE, "rib_async_handler(): "
		    "IBT_ERROR_ACCESS_VIOLATION_CHAN\n");
		break;
	case IBT_ERROR_PATH_MIGRATE_REQ:
		cmn_err(CE_NOTE, "rib_async_handler(): "
		    "IBT_ERROR_PATH_MIGRATE_REQ\n");
		break;
	case IBT_ERROR_CQ:
		cmn_err(CE_NOTE, "rib_async_handler(): IBT_ERROR_CQ\n");
		break;
	case IBT_ERROR_PORT_DOWN:
		cmn_err(CE_NOTE, "rib_async_handler(): IBT_ERROR_PORT_DOWN\n");
		break;
	case IBT_EVENT_PORT_UP:
		cmn_err(CE_NOTE, "rib_async_handler(): IBT_EVENT_PORT_UP\n");
		break;
	case IBT_ASYNC_OPAQUE1:
		cmn_err(CE_NOTE, "rib_async_handler(): IBT_ASYNC_OPAQUE1\n");
		break;
	case IBT_ASYNC_OPAQUE2:
		cmn_err(CE_NOTE, "rib_async_handler(): IBT_ASYNC_OPAQUE2\n");
		break;
	case IBT_ASYNC_OPAQUE3:
		cmn_err(CE_NOTE, "rib_async_handler(): IBT_ASYNC_OPAQUE3\n");
		break;
	case IBT_ASYNC_OPAQUE4:
		cmn_err(CE_NOTE, "rib_async_handler(): IBT_ASYNC_OPAQUE4\n");
		break;
#endif
	default:
		break;
	}
}

/*
 * Client's reachable function.
 */
static rdma_stat
rib_reachable(int addr_type, struct netbuf *raddr, void **handle)
{
	rib_hca_t	*hca;
	rdma_stat	status;

	/*
	 * First check if a hca is still attached
	 */
	*handle = NULL;
	rw_enter(&rib_stat->hca->state_lock, RW_READER);
	if (rib_stat->hca->state != HCA_INITED) {
		rw_exit(&rib_stat->hca->state_lock);
		return (RDMA_FAILED);
	}
	status = rib_ping_srv(addr_type, raddr, &hca);
	rw_exit(&rib_stat->hca->state_lock);

	if (status == RDMA_SUCCESS) {
		*handle = (void *)hca;
		return (RDMA_SUCCESS);
	} else {
		*handle = NULL;
		DTRACE_PROBE(rpcib__i__pingfailed);
		return (RDMA_FAILED);
	}
}

/* Client side qp creation */
static rdma_stat
rib_clnt_create_chan(rib_hca_t *hca, struct netbuf *raddr, rib_qp_t **qp)
{
	rib_qp_t	*kqp = NULL;
	CONN		*conn;
	rdma_clnt_cred_ctrl_t *cc_info;

	ASSERT(qp != NULL);
	*qp = NULL;

	kqp = kmem_zalloc(sizeof (rib_qp_t), KM_SLEEP);
	conn = qptoc(kqp);
	kqp->hca = hca;
	kqp->rdmaconn.c_rdmamod = &rib_mod;
	kqp->rdmaconn.c_private = (caddr_t)kqp;

	kqp->mode = RIB_CLIENT;
	kqp->chan_flags = IBT_BLOCKING;
	conn->c_raddr.buf = kmem_alloc(raddr->len, KM_SLEEP);
	bcopy(raddr->buf, conn->c_raddr.buf, raddr->len);
	conn->c_raddr.len = conn->c_raddr.maxlen = raddr->len;
	/*
	 * Initialize
	 */
	cv_init(&kqp->cb_conn_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&kqp->posted_rbufs_cv, NULL, CV_DEFAULT, NULL);
	mutex_init(&kqp->posted_rbufs_lock, NULL, MUTEX_DRIVER, hca->iblock);
	mutex_init(&kqp->replylist_lock, NULL, MUTEX_DRIVER, hca->iblock);
	mutex_init(&kqp->rdlist_lock, NULL, MUTEX_DEFAULT, hca->iblock);
	mutex_init(&kqp->cb_lock, NULL, MUTEX_DRIVER, hca->iblock);
	cv_init(&kqp->rdmaconn.c_cv, NULL, CV_DEFAULT, NULL);
	mutex_init(&kqp->rdmaconn.c_lock, NULL, MUTEX_DRIVER, hca->iblock);
	/*
	 * Initialize the client credit control
	 * portion of the rdmaconn struct.
	 */
	kqp->rdmaconn.c_cc_type = RDMA_CC_CLNT;
	cc_info = &kqp->rdmaconn.rdma_conn_cred_ctrl_u.c_clnt_cc;
	cc_info->clnt_cc_granted_ops = 0;
	cc_info->clnt_cc_in_flight_ops = 0;
	cv_init(&cc_info->clnt_cc_cv, NULL, CV_DEFAULT, NULL);

	*qp = kqp;
	return (RDMA_SUCCESS);
}

/* Server side qp creation */
static rdma_stat
rib_svc_create_chan(rib_hca_t *hca, caddr_t q, uint8_t port, rib_qp_t **qp)
{
	rib_qp_t	*kqp = NULL;
	ibt_chan_sizes_t	chan_sizes;
	ibt_rc_chan_alloc_args_t	qp_attr;
	ibt_status_t		ibt_status;
	rdma_srv_cred_ctrl_t *cc_info;

	*qp = NULL;

	kqp = kmem_zalloc(sizeof (rib_qp_t), KM_SLEEP);
	kqp->hca = hca;
	kqp->port_num = port;
	kqp->rdmaconn.c_rdmamod = &rib_mod;
	kqp->rdmaconn.c_private = (caddr_t)kqp;

	/*
	 * Create the qp handle
	 */
	bzero(&qp_attr, sizeof (ibt_rc_chan_alloc_args_t));
	qp_attr.rc_scq = hca->svc_scq->rib_cq_hdl;
	qp_attr.rc_rcq = hca->svc_rcq->rib_cq_hdl;
	qp_attr.rc_pd = hca->pd_hdl;
	qp_attr.rc_hca_port_num = port;
	qp_attr.rc_sizes.cs_sq_sgl = DSEG_MAX;
	qp_attr.rc_sizes.cs_rq_sgl = RQ_DSEG_MAX;
	qp_attr.rc_sizes.cs_sq = DEF_SQ_SIZE;
	qp_attr.rc_sizes.cs_rq = DEF_RQ_SIZE;
	qp_attr.rc_clone_chan = NULL;
	qp_attr.rc_control = IBT_CEP_RDMA_RD | IBT_CEP_RDMA_WR;
	qp_attr.rc_flags = IBT_WR_SIGNALED;

	rw_enter(&hca->state_lock, RW_READER);
	if (hca->state != HCA_DETACHED) {
		ibt_status = ibt_alloc_rc_channel(hca->hca_hdl,
		    IBT_ACHAN_NO_FLAGS, &qp_attr, &kqp->qp_hdl,
		    &chan_sizes);
	} else {
		rw_exit(&hca->state_lock);
		goto fail;
	}
	rw_exit(&hca->state_lock);

	if (ibt_status != IBT_SUCCESS) {
		DTRACE_PROBE1(rpcib__i_svccreatechanfail,
		    int, ibt_status);
		goto fail;
	}

	kqp->mode = RIB_SERVER;
	kqp->chan_flags = IBT_BLOCKING;
	kqp->q = q;	/* server ONLY */

	cv_init(&kqp->cb_conn_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&kqp->posted_rbufs_cv, NULL, CV_DEFAULT, NULL);
	mutex_init(&kqp->replylist_lock, NULL, MUTEX_DEFAULT, hca->iblock);
	mutex_init(&kqp->posted_rbufs_lock, NULL, MUTEX_DRIVER, hca->iblock);
	mutex_init(&kqp->rdlist_lock, NULL, MUTEX_DEFAULT, hca->iblock);
	mutex_init(&kqp->cb_lock, NULL, MUTEX_DRIVER, hca->iblock);
	cv_init(&kqp->rdmaconn.c_cv, NULL, CV_DEFAULT, NULL);
	mutex_init(&kqp->rdmaconn.c_lock, NULL, MUTEX_DRIVER, hca->iblock);
	/*
	 * Set the private data area to qp to be used in callbacks
	 */
	ibt_set_chan_private(kqp->qp_hdl, (void *)kqp);
	kqp->rdmaconn.c_state = C_CONNECTED;

	/*
	 * Initialize the server credit control
	 * portion of the rdmaconn struct.
	 */
	kqp->rdmaconn.c_cc_type = RDMA_CC_SRV;
	cc_info = &kqp->rdmaconn.rdma_conn_cred_ctrl_u.c_srv_cc;
	cc_info->srv_cc_buffers_granted = preposted_rbufs;
	cc_info->srv_cc_cur_buffers_used = 0;
	cc_info->srv_cc_posted = preposted_rbufs;

	*qp = kqp;

	return (RDMA_SUCCESS);
fail:
	if (kqp)
		kmem_free(kqp, sizeof (rib_qp_t));

	return (RDMA_FAILED);
}

/* ARGSUSED */
ibt_cm_status_t
rib_clnt_cm_handler(void *clnt_hdl, ibt_cm_event_t *event,
    ibt_cm_return_args_t *ret_args, void *priv_data,
    ibt_priv_data_len_t len)
{
	rpcib_state_t   *ribstat;
	rib_hca_t	*hca;

	ribstat = (rpcib_state_t *)clnt_hdl;
	hca = (rib_hca_t *)ribstat->hca;

	switch (event->cm_type) {

	/* got a connection close event */
	case IBT_CM_EVENT_CONN_CLOSED:
	{
		CONN	*conn;
		rib_qp_t *qp;

		/* check reason why connection was closed */
		switch (event->cm_event.closed) {
		case IBT_CM_CLOSED_DREP_RCVD:
		case IBT_CM_CLOSED_DREQ_TIMEOUT:
		case IBT_CM_CLOSED_DUP:
		case IBT_CM_CLOSED_ABORT:
		case IBT_CM_CLOSED_ALREADY:
			/*
			 * These cases indicate the local end initiated
			 * the closing of the channel. Nothing to do here.
			 */
			break;
		default:
			/*
			 * Reason for CONN_CLOSED event must be one of
			 * IBT_CM_CLOSED_DREQ_RCVD or IBT_CM_CLOSED_REJ_RCVD
			 * or IBT_CM_CLOSED_STALE. These indicate cases were
			 * the remote end is closing the channel. In these
			 * cases free the channel and transition to error
			 * state
			 */
			qp = ibt_get_chan_private(event->cm_channel);
			conn = qptoc(qp);
			mutex_enter(&conn->c_lock);
			if (conn->c_state == C_DISCONN_PEND) {
				mutex_exit(&conn->c_lock);
				break;
			}

			conn->c_state = C_ERROR_CONN;

			/*
			 * Free the rc_channel. Channel has already
			 * transitioned to ERROR state and WRs have been
			 * FLUSHED_ERR already.
			 */
			(void) ibt_free_channel(qp->qp_hdl);
			qp->qp_hdl = NULL;

			/*
			 * Free the conn if c_ref is down to 0 already
			 */
			if (conn->c_ref == 0) {
				/*
				 * Remove from list and free conn
				 */
				conn->c_state = C_DISCONN_PEND;
				mutex_exit(&conn->c_lock);
				(void) rib_disconnect_channel(conn,
				    &hca->cl_conn_list);
			} else {
				mutex_exit(&conn->c_lock);
			}
#ifdef DEBUG
			if (rib_debug)
				cmn_err(CE_NOTE, "rib_clnt_cm_handler: "
				    "(CONN_CLOSED) channel disconnected");
#endif
			break;
		}
		break;
	}
	default:
		break;
	}
	return (IBT_CM_ACCEPT);
}

/* Check server ib address */
rdma_stat
rib_chk_srv_ibaddr(struct netbuf *raddr,
	int addr_type, ibt_path_info_t *path, ibt_ip_addr_t *s_ip,
	ibt_ip_addr_t *d_ip)
{
	struct sockaddr_in	*sin4;
	struct sockaddr_in6	*sin6;
	ibt_status_t		ibt_status;
	ibt_ip_path_attr_t	ipattr;
	uint8_t npaths = 0;
	ibt_path_ip_src_t	srcip;

	ASSERT(raddr->buf != NULL);

	(void) bzero(path, sizeof (ibt_path_info_t));

	switch (addr_type) {
	case AF_INET:
		sin4 = (struct sockaddr_in *)raddr->buf;
		d_ip->family = AF_INET;
		d_ip->un.ip4addr = sin4->sin_addr.s_addr;
		break;

	case AF_INET6:
		sin6 = (struct sockaddr_in6 *)raddr->buf;
		d_ip->family = AF_INET6;
		d_ip->un.ip6addr = sin6->sin6_addr;
		break;

	default:
		return (RDMA_INVAL);
	}

	bzero(&ipattr, sizeof (ibt_ip_path_attr_t));
	bzero(&srcip, sizeof (ibt_path_ip_src_t));

	ipattr.ipa_dst_ip 	= d_ip;
	ipattr.ipa_hca_guid 	= rib_stat->hca->hca_guid;
	ipattr.ipa_ndst		= 1;
	ipattr.ipa_max_paths	= 1;
	npaths = 0;

	ibt_status = ibt_get_ip_paths(rib_stat->ibt_clnt_hdl,
	    IBT_PATH_NO_FLAGS,
	    &ipattr,
	    path,
	    &npaths,
	    &srcip);

	if (ibt_status != IBT_SUCCESS ||
	    npaths < 1 ||
	    path->pi_hca_guid != rib_stat->hca->hca_guid) {

		bzero(s_ip, sizeof (ibt_path_ip_src_t));
		return (RDMA_FAILED);
	}

	if (srcip.ip_primary.family == AF_INET) {
		s_ip->family = AF_INET;
		s_ip->un.ip4addr = srcip.ip_primary.un.ip4addr;
	} else {
		s_ip->family = AF_INET6;
		s_ip->un.ip6addr = srcip.ip_primary.un.ip6addr;
	}

	return (RDMA_SUCCESS);
}


/*
 * Connect to the server.
 */
rdma_stat
rib_conn_to_srv(rib_hca_t *hca, rib_qp_t *qp, ibt_path_info_t *path,
		ibt_ip_addr_t *s_ip, ibt_ip_addr_t *d_ip)
{
	ibt_chan_open_args_t	chan_args;	/* channel args */
	ibt_chan_sizes_t	chan_sizes;
	ibt_rc_chan_alloc_args_t	qp_attr;
	ibt_status_t		ibt_status;
	ibt_rc_returns_t	ret_args;   	/* conn reject info */
	int refresh = REFRESH_ATTEMPTS;	/* refresh if IBT_CM_CONN_STALE */
	ibt_ip_cm_info_t	ipcm_info;
	uint8_t cmp_ip_pvt[IBT_IP_HDR_PRIV_DATA_SZ];


	(void) bzero(&chan_args, sizeof (chan_args));
	(void) bzero(&qp_attr, sizeof (ibt_rc_chan_alloc_args_t));
	(void) bzero(&ipcm_info, sizeof (ibt_ip_cm_info_t));

	switch (ipcm_info.src_addr.family = s_ip->family) {
	case AF_INET:
		ipcm_info.src_addr.un.ip4addr = s_ip->un.ip4addr;
		break;
	case AF_INET6:
		ipcm_info.src_addr.un.ip6addr = s_ip->un.ip6addr;
		break;
	}

	switch (ipcm_info.dst_addr.family = d_ip->family) {
	case AF_INET:
		ipcm_info.dst_addr.un.ip4addr = d_ip->un.ip4addr;
		break;
	case AF_INET6:
		ipcm_info.dst_addr.un.ip6addr = d_ip->un.ip6addr;
		break;
	}

	ipcm_info.src_port = NFS_RDMA_PORT;

	ibt_status = ibt_format_ip_private_data(&ipcm_info,
	    IBT_IP_HDR_PRIV_DATA_SZ, cmp_ip_pvt);

	if (ibt_status != IBT_SUCCESS) {
		cmn_err(CE_WARN, "ibt_format_ip_private_data failed\n");
		return (-1);
	}

	qp_attr.rc_hca_port_num = path->pi_prim_cep_path.cep_hca_port_num;
	/* Alloc a RC channel */
	qp_attr.rc_scq = hca->clnt_scq->rib_cq_hdl;
	qp_attr.rc_rcq = hca->clnt_rcq->rib_cq_hdl;
	qp_attr.rc_pd = hca->pd_hdl;
	qp_attr.rc_sizes.cs_sq_sgl = DSEG_MAX;
	qp_attr.rc_sizes.cs_rq_sgl = RQ_DSEG_MAX;
	qp_attr.rc_sizes.cs_sq = DEF_SQ_SIZE;
	qp_attr.rc_sizes.cs_rq = DEF_RQ_SIZE;
	qp_attr.rc_clone_chan = NULL;
	qp_attr.rc_control = IBT_CEP_RDMA_RD | IBT_CEP_RDMA_WR;
	qp_attr.rc_flags = IBT_WR_SIGNALED;

	path->pi_sid = ibt_get_ip_sid(IPPROTO_TCP, NFS_RDMA_PORT);
	chan_args.oc_path = path;
	chan_args.oc_cm_handler = rib_clnt_cm_handler;
	chan_args.oc_cm_clnt_private = (void *)rib_stat;
	chan_args.oc_rdma_ra_out = 4;
	chan_args.oc_rdma_ra_in = 4;
	chan_args.oc_path_retry_cnt = 2;
	chan_args.oc_path_rnr_retry_cnt = RNR_RETRIES;
	chan_args.oc_priv_data = cmp_ip_pvt;
	chan_args.oc_priv_data_len = IBT_IP_HDR_PRIV_DATA_SZ;

refresh:
	rw_enter(&hca->state_lock, RW_READER);
	if (hca->state != HCA_DETACHED) {
		ibt_status = ibt_alloc_rc_channel(hca->hca_hdl,
		    IBT_ACHAN_NO_FLAGS,
		    &qp_attr, &qp->qp_hdl,
		    &chan_sizes);
	} else {
		rw_exit(&hca->state_lock);
		return (RDMA_FAILED);
	}
	rw_exit(&hca->state_lock);

	if (ibt_status != IBT_SUCCESS) {
		DTRACE_PROBE1(rpcib__i_conntosrv,
		    int, ibt_status);
		return (RDMA_FAILED);
	}

	/* Connect to the Server */
	(void) bzero(&ret_args, sizeof (ret_args));
	mutex_enter(&qp->cb_lock);
	ibt_status = ibt_open_rc_channel(qp->qp_hdl, IBT_OCHAN_NO_FLAGS,
	    IBT_BLOCKING, &chan_args, &ret_args);
	if (ibt_status != IBT_SUCCESS) {
		DTRACE_PROBE2(rpcib__i_openrctosrv,
		    int, ibt_status, int, ret_args.rc_status);

		(void) ibt_free_channel(qp->qp_hdl);
		qp->qp_hdl = NULL;
		mutex_exit(&qp->cb_lock);
		if (refresh-- && ibt_status == IBT_CM_FAILURE &&
		    ret_args.rc_status == IBT_CM_CONN_STALE) {
			/*
			 * Got IBT_CM_CONN_STALE probably because of stale
			 * data on the passive end of a channel that existed
			 * prior to reboot. Retry establishing a channel
			 * REFRESH_ATTEMPTS times, during which time the
			 * stale conditions on the server might clear up.
			 */
			goto refresh;
		}
		return (RDMA_FAILED);
	}
	mutex_exit(&qp->cb_lock);
	/*
	 * Set the private data area to qp to be used in callbacks
	 */
	ibt_set_chan_private(qp->qp_hdl, (void *)qp);
	return (RDMA_SUCCESS);
}

rdma_stat
rib_ping_srv(int addr_type, struct netbuf *raddr, rib_hca_t **hca)
{
	struct sockaddr_in	*sin4, *sin4arr;
	struct sockaddr_in6	*sin6, *sin6arr;
	uint_t			nif, nif4, nif6, i;
	ibt_path_info_t		path;
	ibt_status_t		ibt_status;
	uint8_t			num_paths_p;
	ibt_ip_path_attr_t	ipattr;
	ibt_ip_addr_t		dstip;
	ibt_path_ip_src_t	srcip;


	*hca = NULL;

	ASSERT(raddr->buf != NULL);

	bzero(&path, sizeof (ibt_path_info_t));
	bzero(&ipattr, sizeof (ibt_ip_path_attr_t));
	bzero(&srcip, sizeof (ibt_path_ip_src_t));

	/* Obtain the source IP addresses for the system */
	nif = rpcib_get_number_interfaces();
	sin4arr = (struct sockaddr_in *)
	    kmem_zalloc(sizeof (struct sockaddr_in) * nif, KM_SLEEP);
	sin6arr = (struct sockaddr_in6 *)
	    kmem_zalloc(sizeof (struct sockaddr_in6) * nif, KM_SLEEP);

	(void) rpcib_get_ib_addresses(sin4arr, sin6arr, &nif4, &nif6);

	/* Are there really any IB interfaces available */
	if (nif4 == 0 && nif6 == 0) {
		kmem_free(sin4arr, sizeof (struct sockaddr_in) * nif);
		kmem_free(sin6arr, sizeof (struct sockaddr_in6) * nif);
		return (RDMA_FAILED);
	}

	/* Prep the destination address */
	switch (addr_type) {
	case AF_INET:
		sin4 = (struct sockaddr_in *)raddr->buf;
		dstip.family = AF_INET;
		dstip.un.ip4addr = sin4->sin_addr.s_addr;

		for (i = 0; i < nif4; i++) {
			num_paths_p = 0;
			ipattr.ipa_dst_ip 	= &dstip;
			ipattr.ipa_hca_guid	= rib_stat->hca->hca_guid;
			ipattr.ipa_ndst		= 1;
			ipattr.ipa_max_paths	= 1;
			ipattr.ipa_src_ip.family = dstip.family;
			ipattr.ipa_src_ip.un.ip4addr =
			    sin4arr[i].sin_addr.s_addr;

			ibt_status = ibt_get_ip_paths(rib_stat->ibt_clnt_hdl,
			    IBT_PATH_NO_FLAGS,
			    &ipattr,
			    &path,
			    &num_paths_p,
			    &srcip);
			if (ibt_status == IBT_SUCCESS &&
			    num_paths_p != 0 &&
			    path.pi_hca_guid == rib_stat->hca->hca_guid) {
				*hca = rib_stat->hca;

				kmem_free(sin4arr,
				    sizeof (struct sockaddr_in) * nif);
				kmem_free(sin6arr,
				    sizeof (struct sockaddr_in6) * nif);

				return (RDMA_SUCCESS);
			}
		}
		break;

	case AF_INET6:
		sin6 = (struct sockaddr_in6 *)raddr->buf;
		dstip.family = AF_INET6;
		dstip.un.ip6addr = sin6->sin6_addr;

		for (i = 0; i < nif6; i++) {
			num_paths_p = 0;
			ipattr.ipa_dst_ip 	= &dstip;
			ipattr.ipa_hca_guid	= rib_stat->hca->hca_guid;
			ipattr.ipa_ndst		= 1;
			ipattr.ipa_max_paths	= 1;
			ipattr.ipa_src_ip.family = dstip.family;
			ipattr.ipa_src_ip.un.ip6addr = sin6arr[i].sin6_addr;

			ibt_status = ibt_get_ip_paths(rib_stat->ibt_clnt_hdl,
			    IBT_PATH_NO_FLAGS,
			    &ipattr,
			    &path,
			    &num_paths_p,
			    &srcip);
			if (ibt_status == IBT_SUCCESS &&
			    num_paths_p != 0 &&
			    path.pi_hca_guid == rib_stat->hca->hca_guid) {
				*hca = rib_stat->hca;

				kmem_free(sin4arr,
				    sizeof (struct sockaddr_in) * nif);
				kmem_free(sin6arr,
				    sizeof (struct sockaddr_in6) * nif);

				return (RDMA_SUCCESS);
			}
		}

		break;

	default:
		kmem_free(sin4arr, sizeof (struct sockaddr_in) * nif);
		kmem_free(sin6arr, sizeof (struct sockaddr_in6) * nif);
		return (RDMA_INVAL);
	}

	kmem_free(sin4arr, sizeof (struct sockaddr_in) * nif);
	kmem_free(sin6arr, sizeof (struct sockaddr_in6) * nif);
	return (RDMA_FAILED);
}

/*
 * Close channel, remove from connection list and
 * free up resources allocated for that channel.
 */
rdma_stat
rib_disconnect_channel(CONN *conn, rib_conn_list_t *conn_list)
{
	rib_qp_t	*qp = ctoqp(conn);
	rib_hca_t	*hca;

	/*
	 * c_ref == 0 and connection is in C_DISCONN_PEND
	 */
	hca = qp->hca;
	if (conn_list != NULL)
		(void) rib_rm_conn(conn, conn_list);

	if (qp->qp_hdl != NULL) {
		/*
		 * If the channel has not been establised,
		 * ibt_flush_channel is called to flush outstanding WRs
		 * on the Qs.  Otherwise, ibt_close_rc_channel() is
		 * called.  The channel is then freed.
		 */
		if (conn_list != NULL)
			(void) ibt_close_rc_channel(qp->qp_hdl,
			    IBT_BLOCKING, NULL, 0, NULL, NULL, 0);
		else
			(void) ibt_flush_channel(qp->qp_hdl);

		mutex_enter(&qp->posted_rbufs_lock);
		while (qp->n_posted_rbufs)
			cv_wait(&qp->posted_rbufs_cv, &qp->posted_rbufs_lock);
		mutex_exit(&qp->posted_rbufs_lock);
		(void) ibt_free_channel(qp->qp_hdl);
		qp->qp_hdl = NULL;
	}

	ASSERT(qp->rdlist == NULL);

	if (qp->replylist != NULL) {
		(void) rib_rem_replylist(qp);
	}

	cv_destroy(&qp->cb_conn_cv);
	cv_destroy(&qp->posted_rbufs_cv);
	mutex_destroy(&qp->cb_lock);

	mutex_destroy(&qp->replylist_lock);
	mutex_destroy(&qp->posted_rbufs_lock);
	mutex_destroy(&qp->rdlist_lock);

	cv_destroy(&conn->c_cv);
	mutex_destroy(&conn->c_lock);

	if (conn->c_raddr.buf != NULL) {
		kmem_free(conn->c_raddr.buf, conn->c_raddr.len);
	}
	if (conn->c_laddr.buf != NULL) {
		kmem_free(conn->c_laddr.buf, conn->c_laddr.len);
	}

	/*
	 * Credit control cleanup.
	 */
	if (qp->rdmaconn.c_cc_type == RDMA_CC_CLNT) {
		rdma_clnt_cred_ctrl_t *cc_info;
		cc_info = &qp->rdmaconn.rdma_conn_cred_ctrl_u.c_clnt_cc;
		cv_destroy(&cc_info->clnt_cc_cv);
	}

	kmem_free(qp, sizeof (rib_qp_t));

	/*
	 * If HCA has been DETACHED and the srv/clnt_conn_list is NULL,
	 * then the hca is no longer being used.
	 */
	if (conn_list != NULL) {
		rw_enter(&hca->state_lock, RW_READER);
		if (hca->state == HCA_DETACHED) {
			rw_enter(&hca->srv_conn_list.conn_lock, RW_READER);
			if (hca->srv_conn_list.conn_hd == NULL) {
				rw_enter(&hca->cl_conn_list.conn_lock,
				    RW_READER);

				if (hca->cl_conn_list.conn_hd == NULL) {
					mutex_enter(&hca->inuse_lock);
					hca->inuse = FALSE;
					cv_signal(&hca->cb_cv);
					mutex_exit(&hca->inuse_lock);
				}
				rw_exit(&hca->cl_conn_list.conn_lock);
			}
			rw_exit(&hca->srv_conn_list.conn_lock);
		}
		rw_exit(&hca->state_lock);
	}

	return (RDMA_SUCCESS);
}

/*
 * Wait for send completion notification. Only on receiving a
 * notification be it a successful or error completion, free the
 * send_wid.
 */
static rdma_stat
rib_sendwait(rib_qp_t *qp, struct send_wid *wd)
{
	clock_t timout, cv_wait_ret;
	rdma_stat error = RDMA_SUCCESS;
	int	i;

	/*
	 * Wait for send to complete
	 */
	ASSERT(wd != NULL);
	mutex_enter(&wd->sendwait_lock);
	if (wd->status == (uint_t)SEND_WAIT) {
		timout = drv_usectohz(SEND_WAIT_TIME * 1000000) +
		    ddi_get_lbolt();

		if (qp->mode == RIB_SERVER) {
			while ((cv_wait_ret = cv_timedwait(&wd->wait_cv,
			    &wd->sendwait_lock, timout)) > 0 &&
			    wd->status == (uint_t)SEND_WAIT)
				;
			switch (cv_wait_ret) {
			case -1:	/* timeout */
				DTRACE_PROBE(rpcib__i__srvsendwait__timeout);

				wd->cv_sig = 0;		/* no signal needed */
				error = RDMA_TIMEDOUT;
				break;
			default:	/* got send completion */
				break;
			}
		} else {
			while ((cv_wait_ret = cv_timedwait_sig(&wd->wait_cv,
			    &wd->sendwait_lock, timout)) > 0 &&
			    wd->status == (uint_t)SEND_WAIT)
				;
			switch (cv_wait_ret) {
			case -1:	/* timeout */
				DTRACE_PROBE(rpcib__i__clntsendwait__timeout);

				wd->cv_sig = 0;		/* no signal needed */
				error = RDMA_TIMEDOUT;
				break;
			case 0:		/* interrupted */
				DTRACE_PROBE(rpcib__i__clntsendwait__intr);

				wd->cv_sig = 0;		/* no signal needed */
				error = RDMA_INTR;
				break;
			default:	/* got send completion */
				break;
			}
		}
	}

	if (wd->status != (uint_t)SEND_WAIT) {
		/* got send completion */
		if (wd->status != RDMA_SUCCESS) {
			error = wd->status;
		if (wd->status != RDMA_CONNLOST)
			error = RDMA_FAILED;
		}
		for (i = 0; i < wd->nsbufs; i++) {
			rib_rbuf_free(qptoc(qp), SEND_BUFFER,
			    (void *)(uintptr_t)wd->sbufaddr[i]);
		}
		mutex_exit(&wd->sendwait_lock);
		(void) rib_free_sendwait(wd);
	} else {
		mutex_exit(&wd->sendwait_lock);
	}
	return (error);
}

static struct send_wid *
rib_init_sendwait(uint32_t xid, int cv_sig, rib_qp_t *qp)
{
	struct send_wid	*wd;

	wd = kmem_zalloc(sizeof (struct send_wid), KM_SLEEP);
	wd->xid = xid;
	wd->cv_sig = cv_sig;
	wd->qp = qp;
	cv_init(&wd->wait_cv, NULL, CV_DEFAULT, NULL);
	mutex_init(&wd->sendwait_lock, NULL, MUTEX_DRIVER, NULL);
	wd->status = (uint_t)SEND_WAIT;

	return (wd);
}

static int
rib_free_sendwait(struct send_wid *wdesc)
{
	cv_destroy(&wdesc->wait_cv);
	mutex_destroy(&wdesc->sendwait_lock);
	kmem_free(wdesc, sizeof (*wdesc));

	return (0);
}

static rdma_stat
rib_rem_rep(rib_qp_t *qp, struct reply *rep)
{
	mutex_enter(&qp->replylist_lock);
	if (rep != NULL) {
		(void) rib_remreply(qp, rep);
		mutex_exit(&qp->replylist_lock);
		return (RDMA_SUCCESS);
	}
	mutex_exit(&qp->replylist_lock);
	return (RDMA_FAILED);
}

/*
 * Send buffers are freed here only in case of error in posting
 * on QP. If the post succeeded, the send buffers are freed upon
 * send completion in rib_sendwait() or in the scq_handler.
 */
rdma_stat
rib_send_and_wait(CONN *conn, struct clist *cl, uint32_t msgid,
	int send_sig, int cv_sig, caddr_t *swid)
{
	struct send_wid	*wdesc;
	struct clist	*clp;
	ibt_status_t	ibt_status = IBT_SUCCESS;
	rdma_stat	ret = RDMA_SUCCESS;
	ibt_send_wr_t	tx_wr;
	int		i, nds;
	ibt_wr_ds_t	sgl[DSEG_MAX];
	uint_t		total_msg_size;
	rib_qp_t	*qp;

	qp = ctoqp(conn);

	ASSERT(cl != NULL);

	bzero(&tx_wr, sizeof (ibt_send_wr_t));

	nds = 0;
	total_msg_size = 0;
	clp = cl;
	while (clp != NULL) {
		if (nds >= DSEG_MAX) {
			DTRACE_PROBE(rpcib__i__sendandwait_dsegmax_exceeded);
			return (RDMA_FAILED);
		}
		sgl[nds].ds_va = clp->w.c_saddr;
		sgl[nds].ds_key = clp->c_smemhandle.mrc_lmr; /* lkey */
		sgl[nds].ds_len = clp->c_len;
		total_msg_size += clp->c_len;
		clp = clp->c_next;
		nds++;
	}

	if (send_sig) {
		/* Set SEND_SIGNAL flag. */
		tx_wr.wr_flags = IBT_WR_SEND_SIGNAL;
		wdesc = rib_init_sendwait(msgid, cv_sig, qp);
		*swid = (caddr_t)wdesc;
	} else {
		tx_wr.wr_flags = IBT_WR_NO_FLAGS;
		wdesc = rib_init_sendwait(msgid, 0, qp);
		*swid = (caddr_t)wdesc;
	}
	wdesc->nsbufs = nds;
	for (i = 0; i < nds; i++) {
		wdesc->sbufaddr[i] = sgl[i].ds_va;
	}

	tx_wr.wr_id = (ibt_wrid_t)(uintptr_t)wdesc;
	tx_wr.wr_opcode = IBT_WRC_SEND;
	tx_wr.wr_trans = IBT_RC_SRV;
	tx_wr.wr_nds = nds;
	tx_wr.wr_sgl = sgl;

	mutex_enter(&conn->c_lock);
	if (conn->c_state == C_CONNECTED) {
		ibt_status = ibt_post_send(qp->qp_hdl, &tx_wr, 1, NULL);
	}
	if (conn->c_state != C_CONNECTED ||
	    ibt_status != IBT_SUCCESS) {
		if (conn->c_state != C_DISCONN_PEND)
			conn->c_state = C_ERROR_CONN;
		mutex_exit(&conn->c_lock);
		for (i = 0; i < nds; i++) {
			rib_rbuf_free(conn, SEND_BUFFER,
			    (void *)(uintptr_t)wdesc->sbufaddr[i]);
		}

		(void) rib_free_sendwait(wdesc);

		return (RDMA_CONNLOST);
	}
	mutex_exit(&conn->c_lock);

	if (send_sig) {
		if (cv_sig) {
			/*
			 * cv_wait for send to complete.
			 * We can fail due to a timeout or signal or
			 * unsuccessful send.
			 */
			ret = rib_sendwait(qp, wdesc);

			return (ret);
		}
	}

	return (RDMA_SUCCESS);
}


rdma_stat
rib_send(CONN *conn, struct clist *cl, uint32_t msgid)
{
	rdma_stat	ret;
	caddr_t		wd;

	/* send-wait & cv_signal */
	ret = rib_send_and_wait(conn, cl, msgid, 1, 1, &wd);
	return (ret);
}

/*
 * Server interface (svc_rdma_ksend).
 * Send RPC reply and wait for RDMA_DONE.
 */
rdma_stat
rib_send_resp(CONN *conn, struct clist *cl, uint32_t msgid)
{
	rdma_stat ret = RDMA_SUCCESS;
	struct rdma_done_list *rd;
	clock_t timout, cv_wait_ret;
	caddr_t *wid = NULL;
	rib_qp_t *qp = ctoqp(conn);

	mutex_enter(&qp->rdlist_lock);
	rd = rdma_done_add(qp, msgid);

	/* No cv_signal (whether send-wait or no-send-wait) */
	ret = rib_send_and_wait(conn, cl, msgid, 1, 0, wid);

	if (ret != RDMA_SUCCESS) {
		rdma_done_rm(qp, rd);
	} else {
		/*
		 * Wait for RDMA_DONE from remote end
		 */
		timout =
		    drv_usectohz(REPLY_WAIT_TIME * 1000000) + ddi_get_lbolt();
		cv_wait_ret = cv_timedwait(&rd->rdma_done_cv,
		    &qp->rdlist_lock,
		    timout);

		rdma_done_rm(qp, rd);

		if (cv_wait_ret < 0) {
			ret = RDMA_TIMEDOUT;
		}
	}

	mutex_exit(&qp->rdlist_lock);
	return (ret);
}

static struct recv_wid *
rib_create_wid(rib_qp_t *qp, ibt_wr_ds_t *sgl, uint32_t msgid)
{
	struct recv_wid	*rwid;

	rwid = kmem_zalloc(sizeof (struct recv_wid), KM_SLEEP);
	rwid->xid = msgid;
	rwid->addr = sgl->ds_va;
	rwid->qp = qp;

	return (rwid);
}

static void
rib_free_wid(struct recv_wid *rwid)
{
	kmem_free(rwid, sizeof (struct recv_wid));
}

rdma_stat
rib_clnt_post(CONN* conn, struct clist *cl, uint32_t msgid)
{
	rib_qp_t	*qp = ctoqp(conn);
	struct clist	*clp = cl;
	struct reply	*rep;
	struct recv_wid	*rwid;
	int		nds;
	ibt_wr_ds_t	sgl[DSEG_MAX];
	ibt_recv_wr_t	recv_wr;
	rdma_stat	ret;
	ibt_status_t	ibt_status;

	/*
	 * rdma_clnt_postrecv uses RECV_BUFFER.
	 */

	nds = 0;
	while (cl != NULL) {
		if (nds >= DSEG_MAX) {
			ret = RDMA_FAILED;
			goto done;
		}
		sgl[nds].ds_va = cl->w.c_saddr;
		sgl[nds].ds_key = cl->c_smemhandle.mrc_lmr; /* lkey */
		sgl[nds].ds_len = cl->c_len;
		cl = cl->c_next;
		nds++;
	}

	if (nds != 1) {
		ret = RDMA_FAILED;
		goto done;
	}

	bzero(&recv_wr, sizeof (ibt_recv_wr_t));
	recv_wr.wr_nds = nds;
	recv_wr.wr_sgl = sgl;

	rwid = rib_create_wid(qp, &sgl[0], msgid);
	if (rwid) {
		recv_wr.wr_id = (ibt_wrid_t)(uintptr_t)rwid;
	} else {
		ret = RDMA_NORESOURCE;
		goto done;
	}
	rep = rib_addreplylist(qp, msgid);
	if (!rep) {
		rib_free_wid(rwid);
		ret = RDMA_NORESOURCE;
		goto done;
	}

	mutex_enter(&conn->c_lock);

	if (conn->c_state == C_CONNECTED) {
		ibt_status = ibt_post_recv(qp->qp_hdl, &recv_wr, 1, NULL);
	}

	if (conn->c_state != C_CONNECTED ||
	    ibt_status != IBT_SUCCESS) {
		if (conn->c_state != C_DISCONN_PEND)
			conn->c_state = C_ERROR_CONN;
		mutex_exit(&conn->c_lock);
		rib_free_wid(rwid);
		(void) rib_rem_rep(qp, rep);
		ret = RDMA_CONNLOST;
		goto done;
	}
	mutex_exit(&conn->c_lock);
	return (RDMA_SUCCESS);

done:
	while (clp != NULL) {
		rib_rbuf_free(conn, RECV_BUFFER,
		    (void *)(uintptr_t)clp->w.c_saddr3);
		clp = clp->c_next;
	}
	return (ret);
}

rdma_stat
rib_svc_post(CONN* conn, struct clist *cl)
{
	rib_qp_t	*qp = ctoqp(conn);
	struct svc_recv	*s_recvp;
	int		nds;
	ibt_wr_ds_t	sgl[DSEG_MAX];
	ibt_recv_wr_t	recv_wr;
	ibt_status_t	ibt_status;

	nds = 0;
	while (cl != NULL) {
		if (nds >= DSEG_MAX) {
			return (RDMA_FAILED);
		}
		sgl[nds].ds_va = cl->w.c_saddr;
		sgl[nds].ds_key = cl->c_smemhandle.mrc_lmr; /* lkey */
		sgl[nds].ds_len = cl->c_len;
		cl = cl->c_next;
		nds++;
	}

	if (nds != 1) {
		rib_rbuf_free(conn, RECV_BUFFER,
		    (caddr_t)(uintptr_t)sgl[0].ds_va);

		return (RDMA_FAILED);
	}

	bzero(&recv_wr, sizeof (ibt_recv_wr_t));
	recv_wr.wr_nds = nds;
	recv_wr.wr_sgl = sgl;

	s_recvp = rib_init_svc_recv(qp, &sgl[0]);
	/* Use s_recvp's addr as wr id */
	recv_wr.wr_id = (ibt_wrid_t)(uintptr_t)s_recvp;
	mutex_enter(&conn->c_lock);
	if (conn->c_state == C_CONNECTED) {
		ibt_status = ibt_post_recv(qp->qp_hdl, &recv_wr, 1, NULL);
	}
	if (conn->c_state != C_CONNECTED ||
	    ibt_status != IBT_SUCCESS) {
		if (conn->c_state != C_DISCONN_PEND)
			conn->c_state = C_ERROR_CONN;
		mutex_exit(&conn->c_lock);
		rib_rbuf_free(conn, RECV_BUFFER,
		    (caddr_t)(uintptr_t)sgl[0].ds_va);
		(void) rib_free_svc_recv(s_recvp);

		return (RDMA_CONNLOST);
	}
	mutex_exit(&conn->c_lock);

	return (RDMA_SUCCESS);
}

/* Client */
rdma_stat
rib_post_resp(CONN* conn, struct clist *cl, uint32_t msgid)
{

	return (rib_clnt_post(conn, cl, msgid));
}

/* Client */
rdma_stat
rib_post_resp_remove(CONN* conn, uint32_t msgid)
{
	rib_qp_t	*qp = ctoqp(conn);
	struct reply	*rep;

	mutex_enter(&qp->replylist_lock);
	for (rep = qp->replylist; rep != NULL; rep = rep->next) {
		if (rep->xid == msgid) {
			if (rep->vaddr_cq) {
				rib_rbuf_free(conn, RECV_BUFFER,
				    (caddr_t)(uintptr_t)rep->vaddr_cq);
			}
			(void) rib_remreply(qp, rep);
			break;
		}
	}
	mutex_exit(&qp->replylist_lock);

	return (RDMA_SUCCESS);
}

/* Server */
rdma_stat
rib_post_recv(CONN *conn, struct clist *cl)
{
	rib_qp_t	*qp = ctoqp(conn);

	if (rib_svc_post(conn, cl) == RDMA_SUCCESS) {
		mutex_enter(&qp->posted_rbufs_lock);
		qp->n_posted_rbufs++;
		mutex_exit(&qp->posted_rbufs_lock);
		return (RDMA_SUCCESS);
	}
	return (RDMA_FAILED);
}

/*
 * Client side only interface to "recv" the rpc reply buf
 * posted earlier by rib_post_resp(conn, cl, msgid).
 */
rdma_stat
rib_recv(CONN *conn, struct clist **clp, uint32_t msgid)
{
	struct reply *rep = NULL;
	clock_t timout, cv_wait_ret;
	rdma_stat ret = RDMA_SUCCESS;
	rib_qp_t *qp = ctoqp(conn);

	/*
	 * Find the reply structure for this msgid
	 */
	mutex_enter(&qp->replylist_lock);

	for (rep = qp->replylist; rep != NULL; rep = rep->next) {
		if (rep->xid == msgid)
			break;
	}

	if (rep != NULL) {
		/*
		 * If message not yet received, wait.
		 */
		if (rep->status == (uint_t)REPLY_WAIT) {
			timout = ddi_get_lbolt() +
			    drv_usectohz(REPLY_WAIT_TIME * 1000000);

			while ((cv_wait_ret = cv_timedwait_sig(&rep->wait_cv,
			    &qp->replylist_lock, timout)) > 0 &&
			    rep->status == (uint_t)REPLY_WAIT)
				;

			switch (cv_wait_ret) {
			case -1:	/* timeout */
				ret = RDMA_TIMEDOUT;
				break;
			case 0:
				ret = RDMA_INTR;
				break;
			default:
				break;
			}
		}

		if (rep->status == RDMA_SUCCESS) {
			struct clist *cl = NULL;

			/*
			 * Got message successfully
			 */
			clist_add(&cl, 0, rep->bytes_xfer, NULL,
			    (caddr_t)(uintptr_t)rep->vaddr_cq, NULL, NULL);
			*clp = cl;
		} else {
			if (rep->status != (uint_t)REPLY_WAIT) {
				/*
				 * Got error in reply message. Free
				 * recv buffer here.
				 */
				ret = rep->status;
				rib_rbuf_free(conn, RECV_BUFFER,
				    (caddr_t)(uintptr_t)rep->vaddr_cq);
			}
		}
		(void) rib_remreply(qp, rep);
	} else {
		/*
		 * No matching reply structure found for given msgid on the
		 * reply wait list.
		 */
		ret = RDMA_INVAL;
		DTRACE_PROBE(rpcib__i__nomatchxid2);
	}

	/*
	 * Done.
	 */
	mutex_exit(&qp->replylist_lock);
	return (ret);
}

/*
 * RDMA write a buffer to the remote address.
 */
rdma_stat
rib_write(CONN *conn, struct clist *cl, int wait)
{
	ibt_send_wr_t	tx_wr;
	int		cv_sig;
	int		i;
	ibt_wr_ds_t	sgl[DSEG_MAX];
	struct send_wid	*wdesc;
	ibt_status_t	ibt_status;
	rdma_stat	ret = RDMA_SUCCESS;
	rib_qp_t	*qp = ctoqp(conn);
	uint64_t	n_writes = 0;
	bool_t		force_wait = FALSE;

	if (cl == NULL) {
		return (RDMA_FAILED);
	}


	while ((cl != NULL)) {
		if (cl->c_len > 0) {
			bzero(&tx_wr, sizeof (ibt_send_wr_t));
			tx_wr.wr.rc.rcwr.rdma.rdma_raddr = cl->u.c_daddr;
			tx_wr.wr.rc.rcwr.rdma.rdma_rkey =
			    cl->c_dmemhandle.mrc_rmr; /* rkey */
			sgl[0].ds_va = cl->w.c_saddr;
			sgl[0].ds_key = cl->c_smemhandle.mrc_lmr; /* lkey */
			sgl[0].ds_len = cl->c_len;

			if (wait) {
				tx_wr.wr_flags = IBT_WR_SEND_SIGNAL;
				cv_sig = 1;
			} else {
				if (n_writes > max_unsignaled_rws) {
					n_writes = 0;
					force_wait = TRUE;
					tx_wr.wr_flags = IBT_WR_SEND_SIGNAL;
					cv_sig = 1;
				} else {
					tx_wr.wr_flags = IBT_WR_NO_FLAGS;
					cv_sig = 0;
				}
			}

			wdesc = rib_init_sendwait(0, cv_sig, qp);
			tx_wr.wr_id = (ibt_wrid_t)(uintptr_t)wdesc;
			tx_wr.wr_opcode = IBT_WRC_RDMAW;
			tx_wr.wr_trans = IBT_RC_SRV;
			tx_wr.wr_nds = 1;
			tx_wr.wr_sgl = sgl;

			mutex_enter(&conn->c_lock);
			if (conn->c_state == C_CONNECTED) {
				ibt_status =
				    ibt_post_send(qp->qp_hdl, &tx_wr, 1, NULL);
			}
			if (conn->c_state != C_CONNECTED ||
			    ibt_status != IBT_SUCCESS) {
				if (conn->c_state != C_DISCONN_PEND)
					conn->c_state = C_ERROR_CONN;
				mutex_exit(&conn->c_lock);
				(void) rib_free_sendwait(wdesc);
				return (RDMA_CONNLOST);
			}
			mutex_exit(&conn->c_lock);

			/*
			 * Wait for send to complete
			 */
			if (wait || force_wait) {
				force_wait = FALSE;
				ret = rib_sendwait(qp, wdesc);
				if (ret != 0) {
					return (ret);
				}
			} else {
				mutex_enter(&wdesc->sendwait_lock);
				for (i = 0; i < wdesc->nsbufs; i++) {
					rib_rbuf_free(qptoc(qp), SEND_BUFFER,
					    (void *)(uintptr_t)
					    wdesc->sbufaddr[i]);
				}
				mutex_exit(&wdesc->sendwait_lock);
				(void) rib_free_sendwait(wdesc);
			}
			n_writes ++;
		}
		cl = cl->c_next;
	}
	return (RDMA_SUCCESS);
}

/*
 * RDMA Read a buffer from the remote address.
 */
rdma_stat
rib_read(CONN *conn, struct clist *cl, int wait)
{
	ibt_send_wr_t	rx_wr;
	int		cv_sig;
	int		i;
	ibt_wr_ds_t	sgl;
	struct send_wid	*wdesc;
	ibt_status_t	ibt_status = IBT_SUCCESS;
	rdma_stat	ret = RDMA_SUCCESS;
	rib_qp_t	*qp = ctoqp(conn);

	if (cl == NULL) {
		return (RDMA_FAILED);
	}

	while (cl != NULL) {
		bzero(&rx_wr, sizeof (ibt_send_wr_t));
		/*
		 * Remote address is at the head chunk item in list.
		 */
		rx_wr.wr.rc.rcwr.rdma.rdma_raddr = cl->w.c_saddr;
		rx_wr.wr.rc.rcwr.rdma.rdma_rkey = cl->c_smemhandle.mrc_rmr;

		sgl.ds_va = cl->u.c_daddr;
		sgl.ds_key = cl->c_dmemhandle.mrc_lmr; /* lkey */
		sgl.ds_len = cl->c_len;

		if (wait) {
			rx_wr.wr_flags = IBT_WR_SEND_SIGNAL;
			cv_sig = 1;
		} else {
			rx_wr.wr_flags = IBT_WR_NO_FLAGS;
			cv_sig = 0;
		}

		wdesc = rib_init_sendwait(0, cv_sig, qp);
		rx_wr.wr_id = (ibt_wrid_t)(uintptr_t)wdesc;
		rx_wr.wr_opcode = IBT_WRC_RDMAR;
		rx_wr.wr_trans = IBT_RC_SRV;
		rx_wr.wr_nds = 1;
		rx_wr.wr_sgl = &sgl;

		mutex_enter(&conn->c_lock);
		if (conn->c_state == C_CONNECTED) {
			ibt_status = ibt_post_send(qp->qp_hdl, &rx_wr, 1, NULL);
		}
		if (conn->c_state != C_CONNECTED ||
		    ibt_status != IBT_SUCCESS) {
			if (conn->c_state != C_DISCONN_PEND)
				conn->c_state = C_ERROR_CONN;
			mutex_exit(&conn->c_lock);
			(void) rib_free_sendwait(wdesc);
			return (RDMA_CONNLOST);
		}
		mutex_exit(&conn->c_lock);

		/*
		 * Wait for send to complete if this is the
		 * last item in the list.
		 */
		if (wait && cl->c_next == NULL) {
			ret = rib_sendwait(qp, wdesc);
			if (ret != 0) {
				return (ret);
			}
		} else {
			mutex_enter(&wdesc->sendwait_lock);
			for (i = 0; i < wdesc->nsbufs; i++) {
				rib_rbuf_free(qptoc(qp), SEND_BUFFER,
				    (void *)(uintptr_t)wdesc->sbufaddr[i]);
			}
			mutex_exit(&wdesc->sendwait_lock);
			(void) rib_free_sendwait(wdesc);
		}
		cl = cl->c_next;
	}
	return (RDMA_SUCCESS);
}

/*
 * rib_srv_cm_handler()
 *    Connection Manager callback to handle RC connection requests.
 */
/* ARGSUSED */
static ibt_cm_status_t
rib_srv_cm_handler(void *any, ibt_cm_event_t *event,
	ibt_cm_return_args_t *ret_args, void *priv_data,
	ibt_priv_data_len_t len)
{
	queue_t		*q;
	rib_qp_t	*qp;
	rpcib_state_t	*ribstat;
	rib_hca_t	*hca;
	rdma_stat	status = RDMA_SUCCESS;
	int		i;
	struct clist	cl;
	rdma_buf_t	rdbuf = {0};
	void		*buf = NULL;
	CONN		*conn;
	ibt_ip_cm_info_t	ipinfo;
	struct sockaddr_in *s;
	struct sockaddr_in6 *s6;
	int sin_size = sizeof (struct sockaddr_in);
	int in_size = sizeof (struct in_addr);
	int sin6_size = sizeof (struct sockaddr_in6);

	ASSERT(any != NULL);
	ASSERT(event != NULL);

	ribstat = (rpcib_state_t *)any;
	hca = (rib_hca_t *)ribstat->hca;
	ASSERT(hca != NULL);

	/* got a connection request */
	switch (event->cm_type) {
	case IBT_CM_EVENT_REQ_RCV:
		/*
		 * If the plugin is in the NO_ACCEPT state, bail out.
		 */
		mutex_enter(&plugin_state_lock);
		if (plugin_state == NO_ACCEPT) {
			mutex_exit(&plugin_state_lock);
			return (IBT_CM_REJECT);
		}
		mutex_exit(&plugin_state_lock);

		/*
		 * Need to send a MRA MAD to CM so that it does not
		 * timeout on us.
		 */
		(void) ibt_cm_delay(IBT_CM_DELAY_REQ, event->cm_session_id,
		    event->cm_event.req.req_timeout * 8, NULL, 0);

		mutex_enter(&rib_stat->open_hca_lock);
		q = rib_stat->q;
		mutex_exit(&rib_stat->open_hca_lock);

		status = rib_svc_create_chan(hca, (caddr_t)q,
		    event->cm_event.req.req_prim_hca_port, &qp);

		if (status) {
			return (IBT_CM_REJECT);
		}

		ret_args->cm_ret.rep.cm_channel = qp->qp_hdl;
		ret_args->cm_ret.rep.cm_rdma_ra_out = 4;
		ret_args->cm_ret.rep.cm_rdma_ra_in = 4;
		ret_args->cm_ret.rep.cm_rnr_retry_cnt = RNR_RETRIES;

		/*
		 * Pre-posts RECV buffers
		 */
		conn = qptoc(qp);
		for (i = 0; i < preposted_rbufs; i++) {
			bzero(&rdbuf, sizeof (rdbuf));
			rdbuf.type = RECV_BUFFER;
			buf = rib_rbuf_alloc(conn, &rdbuf);
			if (buf == NULL) {
				(void) rib_disconnect_channel(conn, NULL);
				return (IBT_CM_REJECT);
			}

			bzero(&cl, sizeof (cl));
			cl.w.c_saddr3 = (caddr_t)rdbuf.addr;
			cl.c_len = rdbuf.len;
			cl.c_smemhandle.mrc_lmr =
			    rdbuf.handle.mrc_lmr; /* lkey */
			cl.c_next = NULL;
			status = rib_post_recv(conn, &cl);
			if (status != RDMA_SUCCESS) {
				(void) rib_disconnect_channel(conn, NULL);
				return (IBT_CM_REJECT);
			}
		}
		(void) rib_add_connlist(conn, &hca->srv_conn_list);

		/*
		 * Get the address translation
		 */
		rw_enter(&hca->state_lock, RW_READER);
		if (hca->state == HCA_DETACHED) {
			rw_exit(&hca->state_lock);
			return (IBT_CM_REJECT);
		}
		rw_exit(&hca->state_lock);

		bzero(&ipinfo, sizeof (ibt_ip_cm_info_t));

		if (ibt_get_ip_data(event->cm_priv_data_len,
		    event->cm_priv_data,
		    &ipinfo) != IBT_SUCCESS) {

			return (IBT_CM_REJECT);
		}

		switch (ipinfo.src_addr.family) {
		case AF_INET:

			conn->c_raddr.maxlen =
			    conn->c_raddr.len = sin_size;
			conn->c_raddr.buf = kmem_zalloc(sin_size, KM_SLEEP);

			s = (struct sockaddr_in *)conn->c_raddr.buf;
			s->sin_family = AF_INET;

			bcopy((void *)&ipinfo.src_addr.un.ip4addr,
			    &s->sin_addr, in_size);

			break;

		case AF_INET6:

			conn->c_raddr.maxlen =
			    conn->c_raddr.len = sin6_size;
			conn->c_raddr.buf = kmem_zalloc(sin6_size, KM_SLEEP);

			s6 = (struct sockaddr_in6 *)conn->c_raddr.buf;
			s6->sin6_family = AF_INET6;
			bcopy((void *)&ipinfo.src_addr.un.ip6addr,
			    &s6->sin6_addr,
			    sizeof (struct in6_addr));

			break;

		default:
			return (IBT_CM_REJECT);
		}

		break;

	case IBT_CM_EVENT_CONN_CLOSED:
	{
		CONN		*conn;
		rib_qp_t	*qp;

		switch (event->cm_event.closed) {
		case IBT_CM_CLOSED_DREP_RCVD:
		case IBT_CM_CLOSED_DREQ_TIMEOUT:
		case IBT_CM_CLOSED_DUP:
		case IBT_CM_CLOSED_ABORT:
		case IBT_CM_CLOSED_ALREADY:
			/*
			 * These cases indicate the local end initiated
			 * the closing of the channel. Nothing to do here.
			 */
			break;
		default:
			/*
			 * Reason for CONN_CLOSED event must be one of
			 * IBT_CM_CLOSED_DREQ_RCVD or IBT_CM_CLOSED_REJ_RCVD
			 * or IBT_CM_CLOSED_STALE. These indicate cases were
			 * the remote end is closing the channel. In these
			 * cases free the channel and transition to error
			 * state
			 */
			qp = ibt_get_chan_private(event->cm_channel);
			conn = qptoc(qp);
			mutex_enter(&conn->c_lock);
			if (conn->c_state == C_DISCONN_PEND) {
				mutex_exit(&conn->c_lock);
				break;
			}
			conn->c_state = C_ERROR_CONN;

			/*
			 * Free the rc_channel. Channel has already
			 * transitioned to ERROR state and WRs have been
			 * FLUSHED_ERR already.
			 */
			(void) ibt_free_channel(qp->qp_hdl);
			qp->qp_hdl = NULL;

			/*
			 * Free the conn if c_ref goes down to 0
			 */
			if (conn->c_ref == 0) {
				/*
				 * Remove from list and free conn
				 */
				conn->c_state = C_DISCONN_PEND;
				mutex_exit(&conn->c_lock);
				(void) rib_disconnect_channel(conn,
				    &hca->srv_conn_list);
			} else {
				mutex_exit(&conn->c_lock);
			}
			DTRACE_PROBE(rpcib__i__srvcm_chandisconnect);
			break;
		}
		break;
	}
	case IBT_CM_EVENT_CONN_EST:
		/*
		 * RTU received, hence connection established.
		 */
		if (rib_debug > 1)
			cmn_err(CE_NOTE, "rib_srv_cm_handler: "
			    "(CONN_EST) channel established");
		break;

	default:
		if (rib_debug > 2) {
			/* Let CM handle the following events. */
			if (event->cm_type == IBT_CM_EVENT_REP_RCV) {
				cmn_err(CE_NOTE, "rib_srv_cm_handler: "
				    "server recv'ed IBT_CM_EVENT_REP_RCV\n");
			} else if (event->cm_type == IBT_CM_EVENT_LAP_RCV) {
				cmn_err(CE_NOTE, "rib_srv_cm_handler: "
				    "server recv'ed IBT_CM_EVENT_LAP_RCV\n");
			} else if (event->cm_type == IBT_CM_EVENT_MRA_RCV) {
				cmn_err(CE_NOTE, "rib_srv_cm_handler: "
				    "server recv'ed IBT_CM_EVENT_MRA_RCV\n");
			} else if (event->cm_type == IBT_CM_EVENT_APR_RCV) {
				cmn_err(CE_NOTE, "rib_srv_cm_handler: "
				    "server recv'ed IBT_CM_EVENT_APR_RCV\n");
			} else if (event->cm_type == IBT_CM_EVENT_FAILURE) {
				cmn_err(CE_NOTE, "rib_srv_cm_handler: "
				    "server recv'ed IBT_CM_EVENT_FAILURE\n");
			}
		}
		return (IBT_CM_DEFAULT);
	}

	/* accept all other CM messages (i.e. let the CM handle them) */
	return (IBT_CM_ACCEPT);
}

static rdma_stat
rib_register_service(rib_hca_t *hca, int service_type)
{
	ibt_srv_desc_t		sdesc;
	ibt_hca_portinfo_t	*port_infop;
	ib_svc_id_t		srv_id;
	ibt_srv_hdl_t		srv_hdl;
	uint_t			port_size;
	uint_t			pki, i, num_ports, nbinds;
	ibt_status_t		ibt_status;
	rib_service_t		*new_service;
	ib_pkey_t		pkey;

	/*
	 * Query all ports for the given HCA
	 */
	rw_enter(&hca->state_lock, RW_READER);
	if (hca->state != HCA_DETACHED) {
		ibt_status = ibt_query_hca_ports(hca->hca_hdl, 0, &port_infop,
		    &num_ports, &port_size);
		rw_exit(&hca->state_lock);
	} else {
		rw_exit(&hca->state_lock);
		return (RDMA_FAILED);
	}
	if (ibt_status != IBT_SUCCESS) {
		return (RDMA_FAILED);
	}

	DTRACE_PROBE1(rpcib__i__regservice_numports,
	    int, num_ports);

	for (i = 0; i < num_ports; i++) {
		if (port_infop[i].p_linkstate != IBT_PORT_ACTIVE) {
			DTRACE_PROBE1(rpcib__i__regservice__portinactive,
			    int, i+1);
		} else if (port_infop[i].p_linkstate == IBT_PORT_ACTIVE) {
			DTRACE_PROBE1(rpcib__i__regservice__portactive,
			    int, i+1);
		}
	}

	/*
	 * Get all the IP addresses on this system to register the
	 * given "service type" on all DNS recognized IP addrs.
	 * Each service type such as NFS will have all the systems
	 * IP addresses as its different names. For now the only
	 * type of service we support in RPCIB is NFS.
	 */
	rw_enter(&hca->service_list_lock, RW_WRITER);
	/*
	 * Start registering and binding service to active
	 * on active ports on this HCA.
	 */
	nbinds = 0;
	new_service = NULL;

	/*
	 * We use IP addresses as the service names for
	 * service registration.  Register each of them
	 * with CM to obtain a svc_id and svc_hdl.  We do not
	 * register the service with machine's loopback address.
	 */
	(void) bzero(&srv_id, sizeof (ib_svc_id_t));
	(void) bzero(&srv_hdl, sizeof (ibt_srv_hdl_t));
	(void) bzero(&sdesc, sizeof (ibt_srv_desc_t));

	sdesc.sd_handler = rib_srv_cm_handler;
	sdesc.sd_flags = 0;
	ibt_status = ibt_register_service(hca->ibt_clnt_hdl,
	    &sdesc, ibt_get_ip_sid(IPPROTO_TCP, NFS_RDMA_PORT),
	    1, &srv_hdl, &srv_id);

	for (i = 0; i < num_ports; i++) {
		if (port_infop[i].p_linkstate != IBT_PORT_ACTIVE)
			continue;

		for (pki = 0; pki < port_infop[i].p_pkey_tbl_sz; pki++) {
			pkey = port_infop[i].p_pkey_tbl[pki];
			if ((pkey & IBSRM_HB) &&
			    (pkey != IB_PKEY_INVALID_FULL)) {

				/*
				 * Allocate and prepare a service entry
				 */
				new_service =
				    kmem_zalloc(1 * sizeof (rib_service_t),
				    KM_SLEEP);

				new_service->srv_type = service_type;
				new_service->srv_hdl = srv_hdl;
				new_service->srv_next = NULL;

				ibt_status = ibt_bind_service(srv_hdl,
				    port_infop[i].p_sgid_tbl[0],
				    NULL, rib_stat, NULL);

				DTRACE_PROBE1(rpcib__i__regservice__bindres,
				    int, ibt_status);

				if (ibt_status != IBT_SUCCESS) {
					kmem_free(new_service,
					    sizeof (rib_service_t));
					new_service = NULL;
					continue;
				}

				/*
				 * Add to the service list for this HCA
				 */
				new_service->srv_next = hca->service_list;
				hca->service_list = new_service;
				new_service = NULL;
				nbinds++;
			}
		}
	}
	rw_exit(&hca->service_list_lock);

	ibt_free_portinfo(port_infop, port_size);

	if (nbinds == 0) {
		return (RDMA_FAILED);
	} else {
		/*
		 * Put this plugin into accept state, since atleast
		 * one registration was successful.
		 */
		mutex_enter(&plugin_state_lock);
		plugin_state = ACCEPT;
		mutex_exit(&plugin_state_lock);
		return (RDMA_SUCCESS);
	}
}

void
rib_listen(struct rdma_svc_data *rd)
{
	rdma_stat status = RDMA_SUCCESS;

	rd->active = 0;
	rd->err_code = RDMA_FAILED;

	/*
	 * First check if a hca is still attached
	 */
	rw_enter(&rib_stat->hca->state_lock, RW_READER);
	if (rib_stat->hca->state != HCA_INITED) {
		rw_exit(&rib_stat->hca->state_lock);
		return;
	}
	rw_exit(&rib_stat->hca->state_lock);

	rib_stat->q = &rd->q;
	/*
	 * Right now the only service type is NFS. Hence force feed this
	 * value. Ideally to communicate the service type it should be
	 * passed down in rdma_svc_data.
	 */
	rib_stat->service_type = NFS;
	status = rib_register_service(rib_stat->hca, NFS);
	if (status != RDMA_SUCCESS) {
		rd->err_code = status;
		return;
	}
	/*
	 * Service active on an HCA, check rd->err_code for more
	 * explainable errors.
	 */
	rd->active = 1;
	rd->err_code = status;
}

/* XXXX */
/* ARGSUSED */
static void
rib_listen_stop(struct rdma_svc_data *svcdata)
{
	rib_hca_t		*hca;

	/*
	 * KRPC called the RDMATF to stop the listeners, this means
	 * stop sending incomming or recieved requests to KRPC master
	 * transport handle for RDMA-IB. This is also means that the
	 * master transport handle, responsible for us, is going away.
	 */
	mutex_enter(&plugin_state_lock);
	plugin_state = NO_ACCEPT;
	if (svcdata != NULL)
		svcdata->active = 0;
	mutex_exit(&plugin_state_lock);

	/*
	 * First check if a hca is still attached
	 */
	hca = rib_stat->hca;
	rw_enter(&hca->state_lock, RW_READER);
	if (hca->state != HCA_INITED) {
		rw_exit(&hca->state_lock);
		return;
	}
	rib_close_channels(&hca->srv_conn_list);
	rib_stop_services(hca);
	rw_exit(&hca->state_lock);
}

/*
 * Traverse the HCA's service list to unbind and deregister services.
 * Instead of unbinding the service for a service handle by
 * calling ibt_unbind_service() for each port/pkey, we unbind
 * all the services for the service handle by making only one
 * call to ibt_unbind_all_services().  Then, we deregister the
 * service for the service handle.
 *
 * When traversing the entries in service_list, we compare the
 * srv_hdl of the current entry with that of the next.  If they
 * are different or if the next entry is NULL, the current entry
 * marks the last binding of the service handle.  In this case,
 * call ibt_unbind_all_services() and deregister the service for
 * the service handle.  If they are the same, the current and the
 * next entries are bound to the same service handle.  In this
 * case, move on to the next entry.
 */
static void
rib_stop_services(rib_hca_t *hca)
{
	rib_service_t		*srv_list, *to_remove;

	/*
	 * unbind and deregister the services for this service type.
	 * Right now there is only one service type. In future it will
	 * be passed down to this function.
	 */
	rw_enter(&hca->service_list_lock, RW_WRITER);
	srv_list = hca->service_list;
	while (srv_list != NULL) {
		to_remove = srv_list;
		srv_list = to_remove->srv_next;
		if (srv_list == NULL || bcmp(to_remove->srv_hdl,
		    srv_list->srv_hdl, sizeof (ibt_srv_hdl_t))) {

			(void) ibt_unbind_all_services(to_remove->srv_hdl);
			(void) ibt_deregister_service(hca->ibt_clnt_hdl,
			    to_remove->srv_hdl);
		}

		kmem_free(to_remove, sizeof (rib_service_t));
	}
	hca->service_list = NULL;
	rw_exit(&hca->service_list_lock);
}

static struct svc_recv *
rib_init_svc_recv(rib_qp_t *qp, ibt_wr_ds_t *sgl)
{
	struct svc_recv	*recvp;

	recvp = kmem_zalloc(sizeof (struct svc_recv), KM_SLEEP);
	recvp->vaddr = sgl->ds_va;
	recvp->qp = qp;
	recvp->bytes_xfer = 0;
	return (recvp);
}

static int
rib_free_svc_recv(struct svc_recv *recvp)
{
	kmem_free(recvp, sizeof (*recvp));

	return (0);
}

static struct reply *
rib_addreplylist(rib_qp_t *qp, uint32_t msgid)
{
	struct reply	*rep;


	rep = kmem_zalloc(sizeof (struct reply), KM_NOSLEEP);
	if (rep == NULL) {
		DTRACE_PROBE(rpcib__i__addrreply__nomem);
		return (NULL);
	}
	rep->xid = msgid;
	rep->vaddr_cq = NULL;
	rep->bytes_xfer = 0;
	rep->status = (uint_t)REPLY_WAIT;
	rep->prev = NULL;
	cv_init(&rep->wait_cv, NULL, CV_DEFAULT, NULL);

	mutex_enter(&qp->replylist_lock);
	if (qp->replylist) {
		rep->next = qp->replylist;
		qp->replylist->prev = rep;
	}
	qp->rep_list_size++;

	DTRACE_PROBE1(rpcib__i__addrreply__listsize,
	    int, qp->rep_list_size);

	qp->replylist = rep;
	mutex_exit(&qp->replylist_lock);

	return (rep);
}

static rdma_stat
rib_rem_replylist(rib_qp_t *qp)
{
	struct reply	*r, *n;

	mutex_enter(&qp->replylist_lock);
	for (r = qp->replylist; r != NULL; r = n) {
		n = r->next;
		(void) rib_remreply(qp, r);
	}
	mutex_exit(&qp->replylist_lock);

	return (RDMA_SUCCESS);
}

static int
rib_remreply(rib_qp_t *qp, struct reply *rep)
{

	ASSERT(MUTEX_HELD(&qp->replylist_lock));
	if (rep->prev) {
		rep->prev->next = rep->next;
	}
	if (rep->next) {
		rep->next->prev = rep->prev;
	}
	if (qp->replylist == rep)
		qp->replylist = rep->next;

	cv_destroy(&rep->wait_cv);
	qp->rep_list_size--;

	DTRACE_PROBE1(rpcib__i__remreply__listsize,
	    int, qp->rep_list_size);

	kmem_free(rep, sizeof (*rep));

	return (0);
}

rdma_stat
rib_registermem(CONN *conn,  caddr_t adsp, caddr_t buf, uint_t buflen,
	struct mrc *buf_handle)
{
	ibt_mr_hdl_t	mr_hdl = NULL;	/* memory region handle */
	ibt_mr_desc_t	mr_desc;	/* vaddr, lkey, rkey */
	rdma_stat	status;
	rib_hca_t	*hca = (ctoqp(conn))->hca;

	/*
	 * Note: ALL buffer pools use the same memory type RDMARW.
	 */
	status = rib_reg_mem(hca, adsp, buf, buflen, 0, &mr_hdl, &mr_desc);
	if (status == RDMA_SUCCESS) {
		buf_handle->mrc_linfo = (uintptr_t)mr_hdl;
		buf_handle->mrc_lmr = (uint32_t)mr_desc.md_lkey;
		buf_handle->mrc_rmr = (uint32_t)mr_desc.md_rkey;
	} else {
		buf_handle->mrc_linfo = NULL;
		buf_handle->mrc_lmr = 0;
		buf_handle->mrc_rmr = 0;
	}
	return (status);
}

static rdma_stat
rib_reg_mem(rib_hca_t *hca, caddr_t adsp, caddr_t buf, uint_t size,
	ibt_mr_flags_t spec,
	ibt_mr_hdl_t *mr_hdlp, ibt_mr_desc_t *mr_descp)
{
	ibt_mr_attr_t	mem_attr;
	ibt_status_t	ibt_status;
	mem_attr.mr_vaddr = (uintptr_t)buf;
	mem_attr.mr_len = (ib_msglen_t)size;
	mem_attr.mr_as = (struct as *)(caddr_t)adsp;
	mem_attr.mr_flags = IBT_MR_SLEEP | IBT_MR_ENABLE_LOCAL_WRITE |
	    IBT_MR_ENABLE_REMOTE_READ | IBT_MR_ENABLE_REMOTE_WRITE |
	    IBT_MR_ENABLE_WINDOW_BIND | spec;

	rw_enter(&hca->state_lock, RW_READER);
	if (hca->state == HCA_INITED) {
		ibt_status = ibt_register_mr(hca->hca_hdl, hca->pd_hdl,
		    &mem_attr, mr_hdlp, mr_descp);
		rw_exit(&hca->state_lock);
	} else {
		rw_exit(&hca->state_lock);
		return (RDMA_FAILED);
	}

	if (ibt_status != IBT_SUCCESS) {
		return (RDMA_FAILED);
	}
	return (RDMA_SUCCESS);
}

rdma_stat
rib_registermemsync(CONN *conn,  caddr_t adsp, caddr_t buf, uint_t buflen,
	struct mrc *buf_handle, RIB_SYNCMEM_HANDLE *sync_handle, void *lrc)
{
	ibt_mr_hdl_t	mr_hdl = NULL;	/* memory region handle */
	rib_lrc_entry_t *l;
	ibt_mr_desc_t	mr_desc;	/* vaddr, lkey, rkey */
	rdma_stat	status;
	rib_hca_t	*hca = (ctoqp(conn))->hca;

	/*
	 * Non-coherent memory registration.
	 */
	l = (rib_lrc_entry_t *)lrc;
	if (l) {
		if (l->registered) {
			buf_handle->mrc_linfo =
			    (uintptr_t)l->lrc_mhandle.mrc_linfo;
			buf_handle->mrc_lmr =
			    (uint32_t)l->lrc_mhandle.mrc_lmr;
			buf_handle->mrc_rmr =
			    (uint32_t)l->lrc_mhandle.mrc_rmr;
			*sync_handle = (RIB_SYNCMEM_HANDLE)
			    (uintptr_t)l->lrc_mhandle.mrc_linfo;
			return (RDMA_SUCCESS);
		} else {
			/* Always register the whole buffer */
			buf = (caddr_t)l->lrc_buf;
			buflen = l->lrc_len;
		}
	}
	status = rib_reg_mem(hca, adsp, buf, buflen, 0, &mr_hdl, &mr_desc);

	if (status == RDMA_SUCCESS) {
		if (l) {
			l->lrc_mhandle.mrc_linfo = (uintptr_t)mr_hdl;
			l->lrc_mhandle.mrc_lmr   = (uint32_t)mr_desc.md_lkey;
			l->lrc_mhandle.mrc_rmr   = (uint32_t)mr_desc.md_rkey;
			l->registered		 = TRUE;
		}
		buf_handle->mrc_linfo = (uintptr_t)mr_hdl;
		buf_handle->mrc_lmr = (uint32_t)mr_desc.md_lkey;
		buf_handle->mrc_rmr = (uint32_t)mr_desc.md_rkey;
		*sync_handle = (RIB_SYNCMEM_HANDLE)mr_hdl;
	} else {
		buf_handle->mrc_linfo = NULL;
		buf_handle->mrc_lmr = 0;
		buf_handle->mrc_rmr = 0;
	}
	return (status);
}

/* ARGSUSED */
rdma_stat
rib_deregistermem(CONN *conn, caddr_t buf, struct mrc buf_handle)
{
	rib_hca_t *hca = (ctoqp(conn))->hca;
	/*
	 * Allow memory deregistration even if HCA is
	 * getting detached. Need all outstanding
	 * memory registrations to be deregistered
	 * before HCA_DETACH_EVENT can be accepted.
	 */
	(void) ibt_deregister_mr(hca->hca_hdl,
	    (ibt_mr_hdl_t)(uintptr_t)buf_handle.mrc_linfo);
	return (RDMA_SUCCESS);
}

/* ARGSUSED */
rdma_stat
rib_deregistermemsync(CONN *conn, caddr_t buf, struct mrc buf_handle,
		RIB_SYNCMEM_HANDLE sync_handle, void *lrc)
{
	rib_lrc_entry_t *l;
	l = (rib_lrc_entry_t *)lrc;
	if (l)
		if (l->registered)
			return (RDMA_SUCCESS);

	(void) rib_deregistermem(conn, buf, buf_handle);

	return (RDMA_SUCCESS);
}

/* ARGSUSED */
rdma_stat
rib_syncmem(CONN *conn, RIB_SYNCMEM_HANDLE shandle, caddr_t buf,
		int len, int cpu)
{
	ibt_status_t	status;
	rib_hca_t *hca = (ctoqp(conn))->hca;
	ibt_mr_sync_t	mr_segment;

	mr_segment.ms_handle = (ibt_mr_hdl_t)shandle;
	mr_segment.ms_vaddr = (ib_vaddr_t)(uintptr_t)buf;
	mr_segment.ms_len = (ib_memlen_t)len;
	if (cpu) {
		/* make incoming data visible to memory */
		mr_segment.ms_flags = IBT_SYNC_WRITE;
	} else {
		/* make memory changes visible to IO */
		mr_segment.ms_flags = IBT_SYNC_READ;
	}
	rw_enter(&hca->state_lock, RW_READER);
	if (hca->state == HCA_INITED) {
		status = ibt_sync_mr(hca->hca_hdl, &mr_segment, 1);
		rw_exit(&hca->state_lock);
	} else {
		rw_exit(&hca->state_lock);
		return (RDMA_FAILED);
	}

	if (status == IBT_SUCCESS)
		return (RDMA_SUCCESS);
	else {
		return (RDMA_FAILED);
	}
}

/*
 * XXXX	????
 */
static rdma_stat
rib_getinfo(rdma_info_t *info)
{
	/*
	 * XXXX	Hack!
	 */
	info->addrlen = 16;
	info->mts = 1000000;
	info->mtu = 1000000;

	return (RDMA_SUCCESS);
}

rib_bufpool_t *
rib_rbufpool_create(rib_hca_t *hca, int ptype, int num)
{
	rib_bufpool_t	*rbp = NULL;
	bufpool_t	*bp = NULL;
	caddr_t		buf;
	ibt_mr_attr_t	mem_attr;
	ibt_status_t	ibt_status;
	int		i, j;

	rbp = (rib_bufpool_t *)kmem_zalloc(sizeof (rib_bufpool_t), KM_SLEEP);

	bp = (bufpool_t *)kmem_zalloc(sizeof (bufpool_t) +
	    num * sizeof (void *), KM_SLEEP);

	mutex_init(&bp->buflock, NULL, MUTEX_DRIVER, hca->iblock);
	bp->numelems = num;


	switch (ptype) {
	case SEND_BUFFER:
		mem_attr.mr_flags = IBT_MR_SLEEP | IBT_MR_ENABLE_LOCAL_WRITE;
		bp->rsize = RPC_MSG_SZ;
		break;
	case RECV_BUFFER:
		mem_attr.mr_flags = IBT_MR_SLEEP | IBT_MR_ENABLE_LOCAL_WRITE;
		bp->rsize = RPC_BUF_SIZE;
		break;
	default:
		goto fail;
	}

	/*
	 * Register the pool.
	 */
	bp->bufsize = num * bp->rsize;
	bp->buf = kmem_zalloc(bp->bufsize, KM_SLEEP);
	rbp->mr_hdl = (ibt_mr_hdl_t *)kmem_zalloc(num *
	    sizeof (ibt_mr_hdl_t), KM_SLEEP);
	rbp->mr_desc = (ibt_mr_desc_t *)kmem_zalloc(num *
	    sizeof (ibt_mr_desc_t), KM_SLEEP);
	rw_enter(&hca->state_lock, RW_READER);

	if (hca->state != HCA_INITED) {
		rw_exit(&hca->state_lock);
		goto fail;
	}

	for (i = 0, buf = bp->buf; i < num; i++, buf += bp->rsize) {
		bzero(&rbp->mr_desc[i], sizeof (ibt_mr_desc_t));
		mem_attr.mr_vaddr = (uintptr_t)buf;
		mem_attr.mr_len = (ib_msglen_t)bp->rsize;
		mem_attr.mr_as = NULL;
		ibt_status = ibt_register_mr(hca->hca_hdl,
		    hca->pd_hdl, &mem_attr,
		    &rbp->mr_hdl[i],
		    &rbp->mr_desc[i]);
		if (ibt_status != IBT_SUCCESS) {
			for (j = 0; j < i; j++) {
				(void) ibt_deregister_mr(hca->hca_hdl,
				    rbp->mr_hdl[j]);
			}
			rw_exit(&hca->state_lock);
			goto fail;
		}
	}
	rw_exit(&hca->state_lock);
	buf = (caddr_t)bp->buf;
	for (i = 0; i < num; i++, buf += bp->rsize) {
		bp->buflist[i] = (void *)buf;
	}
	bp->buffree = num - 1;	/* no. of free buffers */
	rbp->bpool = bp;

	return (rbp);
fail:
	if (bp) {
		if (bp->buf)
			kmem_free(bp->buf, bp->bufsize);
		kmem_free(bp, sizeof (bufpool_t) + num*sizeof (void *));
	}
	if (rbp) {
		if (rbp->mr_hdl)
			kmem_free(rbp->mr_hdl, num*sizeof (ibt_mr_hdl_t));
		if (rbp->mr_desc)
			kmem_free(rbp->mr_desc, num*sizeof (ibt_mr_desc_t));
		kmem_free(rbp, sizeof (rib_bufpool_t));
	}
	return (NULL);
}

static void
rib_rbufpool_deregister(rib_hca_t *hca, int ptype)
{
	int i;
	rib_bufpool_t *rbp = NULL;
	bufpool_t *bp;

	/*
	 * Obtain pool address based on type of pool
	 */
	switch (ptype) {
		case SEND_BUFFER:
			rbp = hca->send_pool;
			break;
		case RECV_BUFFER:
			rbp = hca->recv_pool;
			break;
		default:
			return;
	}
	if (rbp == NULL)
		return;

	bp = rbp->bpool;

	/*
	 * Deregister the pool memory and free it.
	 */
	for (i = 0; i < bp->numelems; i++) {
		(void) ibt_deregister_mr(hca->hca_hdl, rbp->mr_hdl[i]);
	}
}

static void
rib_rbufpool_free(rib_hca_t *hca, int ptype)
{

	rib_bufpool_t *rbp = NULL;
	bufpool_t *bp;

	/*
	 * Obtain pool address based on type of pool
	 */
	switch (ptype) {
		case SEND_BUFFER:
			rbp = hca->send_pool;
			break;
		case RECV_BUFFER:
			rbp = hca->recv_pool;
			break;
		default:
			return;
	}
	if (rbp == NULL)
		return;

	bp = rbp->bpool;

	/*
	 * Free the pool memory.
	 */
	if (rbp->mr_hdl)
		kmem_free(rbp->mr_hdl, bp->numelems*sizeof (ibt_mr_hdl_t));

	if (rbp->mr_desc)
		kmem_free(rbp->mr_desc, bp->numelems*sizeof (ibt_mr_desc_t));
	if (bp->buf)
		kmem_free(bp->buf, bp->bufsize);
	mutex_destroy(&bp->buflock);
	kmem_free(bp, sizeof (bufpool_t) + bp->numelems*sizeof (void *));
	kmem_free(rbp, sizeof (rib_bufpool_t));
}

void
rib_rbufpool_destroy(rib_hca_t *hca, int ptype)
{
	/*
	 * Deregister the pool memory and free it.
	 */
	rib_rbufpool_deregister(hca, ptype);
	rib_rbufpool_free(hca, ptype);
}

/*
 * Fetch a buffer from the pool of type specified in rdbuf->type.
 */
static rdma_stat
rib_reg_buf_alloc(CONN *conn, rdma_buf_t *rdbuf)
{
	rib_lrc_entry_t *rlep;

	if (rdbuf->type ==  RDMA_LONG_BUFFER) {
		rlep = rib_get_cache_buf(conn, rdbuf->len);
		rdbuf->rb_private =  (caddr_t)rlep;
		rdbuf->addr = rlep->lrc_buf;
		rdbuf->handle = rlep->lrc_mhandle;
		return (RDMA_SUCCESS);
	}

	rdbuf->addr = rib_rbuf_alloc(conn, rdbuf);
	if (rdbuf->addr) {
		switch (rdbuf->type) {
		case SEND_BUFFER:
			rdbuf->len = RPC_MSG_SZ;	/* 1K */
			break;
		case RECV_BUFFER:
			rdbuf->len = RPC_BUF_SIZE; /* 2K */
			break;
		default:
			rdbuf->len = 0;
		}
		return (RDMA_SUCCESS);
	} else
		return (RDMA_FAILED);
}

#if defined(MEASURE_POOL_DEPTH)
static void rib_recv_bufs(uint32_t x) {

}

static void rib_send_bufs(uint32_t x) {

}
#endif

/*
 * Fetch a buffer of specified type.
 * Note that rdbuf->handle is mw's rkey.
 */
static void *
rib_rbuf_alloc(CONN *conn, rdma_buf_t *rdbuf)
{
	rib_qp_t	*qp = ctoqp(conn);
	rib_hca_t	*hca = qp->hca;
	rdma_btype	ptype = rdbuf->type;
	void		*buf;
	rib_bufpool_t	*rbp = NULL;
	bufpool_t	*bp;
	int		i;

	/*
	 * Obtain pool address based on type of pool
	 */
	switch (ptype) {
	case SEND_BUFFER:
		rbp = hca->send_pool;
		break;
	case RECV_BUFFER:
		rbp = hca->recv_pool;
		break;
	default:
		return (NULL);
	}
	if (rbp == NULL)
		return (NULL);

	bp = rbp->bpool;

	mutex_enter(&bp->buflock);
	if (bp->buffree < 0) {
		mutex_exit(&bp->buflock);
		return (NULL);
	}

	/* XXXX put buf, rdbuf->handle.mrc_rmr, ... in one place. */
	buf = bp->buflist[bp->buffree];
	rdbuf->addr = buf;
	rdbuf->len = bp->rsize;
	for (i = bp->numelems - 1; i >= 0; i--) {
		if ((ib_vaddr_t)(uintptr_t)buf == rbp->mr_desc[i].md_vaddr) {
			rdbuf->handle.mrc_rmr =
			    (uint32_t)rbp->mr_desc[i].md_rkey;
			rdbuf->handle.mrc_linfo =
			    (uintptr_t)rbp->mr_hdl[i];
			rdbuf->handle.mrc_lmr =
			    (uint32_t)rbp->mr_desc[i].md_lkey;
#if defined(MEASURE_POOL_DEPTH)
			if (ptype == SEND_BUFFER)
				rib_send_bufs(MAX_BUFS - (bp->buffree+1));
			if (ptype == RECV_BUFFER)
				rib_recv_bufs(MAX_BUFS - (bp->buffree+1));
#endif
			bp->buffree--;

			mutex_exit(&bp->buflock);

			return (buf);
		}
	}

	mutex_exit(&bp->buflock);

	return (NULL);
}

static void
rib_reg_buf_free(CONN *conn, rdma_buf_t *rdbuf)
{

	if (rdbuf->type == RDMA_LONG_BUFFER) {
		rib_free_cache_buf(conn, (rib_lrc_entry_t *)rdbuf->rb_private);
		rdbuf->rb_private = NULL;
		return;
	}
	rib_rbuf_free(conn, rdbuf->type, rdbuf->addr);
}

static void
rib_rbuf_free(CONN *conn, int ptype, void *buf)
{
	rib_qp_t *qp = ctoqp(conn);
	rib_hca_t *hca = qp->hca;
	rib_bufpool_t *rbp = NULL;
	bufpool_t *bp;

	/*
	 * Obtain pool address based on type of pool
	 */
	switch (ptype) {
	case SEND_BUFFER:
		rbp = hca->send_pool;
		break;
	case RECV_BUFFER:
		rbp = hca->recv_pool;
		break;
	default:
		return;
	}
	if (rbp == NULL)
		return;

	bp = rbp->bpool;

	mutex_enter(&bp->buflock);
	if (++bp->buffree >= bp->numelems) {
		/*
		 * Should never happen
		 */
		bp->buffree--;
	} else {
		bp->buflist[bp->buffree] = buf;
	}
	mutex_exit(&bp->buflock);
}

static rdma_stat
rib_add_connlist(CONN *cn, rib_conn_list_t *connlist)
{
	rw_enter(&connlist->conn_lock, RW_WRITER);
	if (connlist->conn_hd) {
		cn->c_next = connlist->conn_hd;
		connlist->conn_hd->c_prev = cn;
	}
	connlist->conn_hd = cn;
	rw_exit(&connlist->conn_lock);

	return (RDMA_SUCCESS);
}

static rdma_stat
rib_rm_conn(CONN *cn, rib_conn_list_t *connlist)
{
	rw_enter(&connlist->conn_lock, RW_WRITER);
	if (cn->c_prev) {
		cn->c_prev->c_next = cn->c_next;
	}
	if (cn->c_next) {
		cn->c_next->c_prev = cn->c_prev;
	}
	if (connlist->conn_hd == cn)
		connlist->conn_hd = cn->c_next;
	rw_exit(&connlist->conn_lock);

	return (RDMA_SUCCESS);
}

/*
 * Connection management.
 * IBTF does not support recycling of channels. So connections are only
 * in four states - C_CONN_PEND, or C_CONNECTED, or C_ERROR_CONN or
 * C_DISCONN_PEND state. No C_IDLE state.
 * C_CONN_PEND state: Connection establishment in progress to the server.
 * C_CONNECTED state: A connection when created is in C_CONNECTED state.
 * It has an RC channel associated with it. ibt_post_send/recv are allowed
 * only in this state.
 * C_ERROR_CONN state: A connection transitions to this state when WRs on the
 * channel are completed in error or an IBT_CM_EVENT_CONN_CLOSED event
 * happens on the channel or a IBT_HCA_DETACH_EVENT occurs on the HCA.
 * C_DISCONN_PEND state: When a connection is in C_ERROR_CONN state and when
 * c_ref drops to 0 (this indicates that RPC has no more references to this
 * connection), the connection should be destroyed. A connection transitions
 * into this state when it is being destroyed.
 */
static rdma_stat
rib_conn_get(struct netbuf *svcaddr, int addr_type, void *handle, CONN **conn)
{
	CONN *cn;
	int status = RDMA_SUCCESS;
	rib_hca_t *hca = (rib_hca_t *)handle;
	rib_qp_t *qp;
	clock_t cv_stat, timout;
	ibt_path_info_t path;
	ibt_ip_addr_t s_ip, d_ip;

again:
	rw_enter(&hca->cl_conn_list.conn_lock, RW_READER);
	cn = hca->cl_conn_list.conn_hd;
	while (cn != NULL) {
		/*
		 * First, clear up any connection in the ERROR state
		 */
		mutex_enter(&cn->c_lock);
		if (cn->c_state == C_ERROR_CONN) {
			if (cn->c_ref == 0) {
				/*
				 * Remove connection from list and destroy it.
				 */
				cn->c_state = C_DISCONN_PEND;
				mutex_exit(&cn->c_lock);
				rw_exit(&hca->cl_conn_list.conn_lock);
				(void) rib_disconnect_channel(cn,
				    &hca->cl_conn_list);
				goto again;
			}
			mutex_exit(&cn->c_lock);
			cn = cn->c_next;
			continue;
		}
		if (cn->c_state == C_DISCONN_PEND) {
			mutex_exit(&cn->c_lock);
			cn = cn->c_next;
			continue;
		}
		if ((cn->c_raddr.len == svcaddr->len) &&
		    bcmp(svcaddr->buf, cn->c_raddr.buf, svcaddr->len) == 0) {
			/*
			 * Our connection. Give up conn list lock
			 * as we are done traversing the list.
			 */
			rw_exit(&hca->cl_conn_list.conn_lock);
			if (cn->c_state == C_CONNECTED) {
				cn->c_ref++;	/* sharing a conn */
				mutex_exit(&cn->c_lock);
				*conn = cn;
				return (status);
			}
			if (cn->c_state == C_CONN_PEND) {
				/*
				 * Hold a reference to this conn before
				 * we give up the lock.
				 */
				cn->c_ref++;
				timout =  ddi_get_lbolt() +
				    drv_usectohz(CONN_WAIT_TIME * 1000000);
				while ((cv_stat = cv_timedwait_sig(&cn->c_cv,
				    &cn->c_lock, timout)) > 0 &&
				    cn->c_state == C_CONN_PEND)
					;
				if (cv_stat == 0) {
					cn->c_ref--;
					mutex_exit(&cn->c_lock);
					return (RDMA_INTR);
				}
				if (cv_stat < 0) {
					cn->c_ref--;
					mutex_exit(&cn->c_lock);
					return (RDMA_TIMEDOUT);
				}
				if (cn->c_state == C_CONNECTED) {
					*conn = cn;
					mutex_exit(&cn->c_lock);
					return (status);
				} else {
					cn->c_ref--;
					mutex_exit(&cn->c_lock);
					return (RDMA_TIMEDOUT);
				}
			}
		}
		mutex_exit(&cn->c_lock);
		cn = cn->c_next;
	}
	rw_exit(&hca->cl_conn_list.conn_lock);

	bzero(&path, sizeof (ibt_path_info_t));
	bzero(&s_ip, sizeof (ibt_ip_addr_t));
	bzero(&d_ip, sizeof (ibt_ip_addr_t));

	status = rib_chk_srv_ibaddr(svcaddr, addr_type, &path, &s_ip, &d_ip);
	if (status != RDMA_SUCCESS) {
		return (RDMA_FAILED);
	}

	/*
	 * Channel to server doesn't exist yet, create one.
	 */
	if (rib_clnt_create_chan(hca, svcaddr, &qp) != RDMA_SUCCESS) {
		return (RDMA_FAILED);
	}
	cn = qptoc(qp);
	cn->c_state = C_CONN_PEND;
	cn->c_ref = 1;

	/*
	 * Add to conn list.
	 * We had given up the READER lock. In the time since then,
	 * another thread might have created the connection we are
	 * trying here. But for now, that is quiet alright - there
	 * might be two connections between a pair of hosts instead
	 * of one. If we really want to close that window,
	 * then need to check the list after acquiring the
	 * WRITER lock.
	 */
	(void) rib_add_connlist(cn, &hca->cl_conn_list);
	status = rib_conn_to_srv(hca, qp, &path, &s_ip, &d_ip);
	mutex_enter(&cn->c_lock);
	if (status == RDMA_SUCCESS) {
		cn->c_state = C_CONNECTED;
		*conn = cn;
	} else {
		cn->c_state = C_ERROR_CONN;
		cn->c_ref--;
	}
	cv_broadcast(&cn->c_cv);
	mutex_exit(&cn->c_lock);
	return (status);
}

static rdma_stat
rib_conn_release(CONN *conn)
{
	rib_qp_t	*qp = ctoqp(conn);

	mutex_enter(&conn->c_lock);
	conn->c_ref--;

	/*
	 * If a conn is C_ERROR_CONN, close the channel.
	 * If it's CONNECTED, keep it that way.
	 */
	if (conn->c_ref == 0 && conn->c_state == C_ERROR_CONN) {
		conn->c_state = C_DISCONN_PEND;
		mutex_exit(&conn->c_lock);
		if (qp->mode == RIB_SERVER)
			(void) rib_disconnect_channel(conn,
			    &qp->hca->srv_conn_list);
		else
			(void) rib_disconnect_channel(conn,
			    &qp->hca->cl_conn_list);
		return (RDMA_SUCCESS);
	}
	mutex_exit(&conn->c_lock);
	return (RDMA_SUCCESS);
}

/*
 * Add at front of list
 */
static struct rdma_done_list *
rdma_done_add(rib_qp_t *qp, uint32_t xid)
{
	struct rdma_done_list *rd;

	ASSERT(MUTEX_HELD(&qp->rdlist_lock));

	rd = kmem_alloc(sizeof (*rd), KM_SLEEP);
	rd->xid = xid;
	cv_init(&rd->rdma_done_cv, NULL, CV_DEFAULT, NULL);

	rd->prev = NULL;
	rd->next = qp->rdlist;
	if (qp->rdlist != NULL)
		qp->rdlist->prev = rd;
	qp->rdlist = rd;

	return (rd);
}

static void
rdma_done_rm(rib_qp_t *qp, struct rdma_done_list *rd)
{
	struct rdma_done_list *r;

	ASSERT(MUTEX_HELD(&qp->rdlist_lock));

	r = rd->next;
	if (r != NULL) {
		r->prev = rd->prev;
	}

	r = rd->prev;
	if (r != NULL) {
		r->next = rd->next;
	} else {
		qp->rdlist = rd->next;
	}

	cv_destroy(&rd->rdma_done_cv);
	kmem_free(rd, sizeof (*rd));
}

static void
rdma_done_rem_list(rib_qp_t *qp)
{
	struct rdma_done_list	*r, *n;

	mutex_enter(&qp->rdlist_lock);
	for (r = qp->rdlist; r != NULL; r = n) {
		n = r->next;
		rdma_done_rm(qp, r);
	}
	mutex_exit(&qp->rdlist_lock);
}

static void
rdma_done_notify(rib_qp_t *qp, uint32_t xid)
{
	struct rdma_done_list *r = qp->rdlist;

	ASSERT(MUTEX_HELD(&qp->rdlist_lock));

	while (r) {
		if (r->xid == xid) {
			cv_signal(&r->rdma_done_cv);
			return;
		} else {
			r = r->next;
		}
	}
	DTRACE_PROBE1(rpcib__i__donenotify__nomatchxid,
	    int, xid);
}


/*
 * Goes through all connections and closes the channel
 * This will cause all the WRs on those channels to be
 * flushed.
 */
static void
rib_close_channels(rib_conn_list_t *connlist)
{
	CONN 		*conn;
	rib_qp_t	*qp;

	rw_enter(&connlist->conn_lock, RW_READER);
	conn = connlist->conn_hd;
	while (conn != NULL) {
		mutex_enter(&conn->c_lock);
		qp = ctoqp(conn);
		if (conn->c_state == C_CONNECTED) {
			/*
			 * Live connection in CONNECTED state.
			 * Call ibt_close_rc_channel in nonblocking mode
			 * with no callbacks.
			 */
			conn->c_state = C_ERROR_CONN;
			(void) ibt_close_rc_channel(qp->qp_hdl,
			    IBT_NOCALLBACKS, NULL, 0, NULL, NULL, 0);
			(void) ibt_free_channel(qp->qp_hdl);
			qp->qp_hdl = NULL;
		} else {
			if (conn->c_state == C_ERROR_CONN &&
			    qp->qp_hdl != NULL) {
				/*
				 * Connection in ERROR state but
				 * channel is not yet freed.
				 */
				(void) ibt_close_rc_channel(qp->qp_hdl,
				    IBT_NOCALLBACKS, NULL, 0, NULL,
				    NULL, 0);
				(void) ibt_free_channel(qp->qp_hdl);
				qp->qp_hdl = NULL;
			}
		}
		mutex_exit(&conn->c_lock);
		conn = conn->c_next;
	}
	rw_exit(&connlist->conn_lock);
}

/*
 * Frees up all connections that are no longer being referenced
 */
static void
rib_purge_connlist(rib_conn_list_t *connlist)
{
	CONN 		*conn;

top:
	rw_enter(&connlist->conn_lock, RW_READER);
	conn = connlist->conn_hd;
	while (conn != NULL) {
		mutex_enter(&conn->c_lock);

		/*
		 * At this point connection is either in ERROR
		 * or DISCONN_PEND state. If in DISCONN_PEND state
		 * then some other thread is culling that connection.
		 * If not and if c_ref is 0, then destroy the connection.
		 */
		if (conn->c_ref == 0 &&
		    conn->c_state != C_DISCONN_PEND) {
			/*
			 * Cull the connection
			 */
			conn->c_state = C_DISCONN_PEND;
			mutex_exit(&conn->c_lock);
			rw_exit(&connlist->conn_lock);
			(void) rib_disconnect_channel(conn, connlist);
			goto top;
		} else {
			/*
			 * conn disconnect already scheduled or will
			 * happen from conn_release when c_ref drops to 0.
			 */
			mutex_exit(&conn->c_lock);
		}
		conn = conn->c_next;
	}
	rw_exit(&connlist->conn_lock);

	/*
	 * At this point, only connections with c_ref != 0 are on the list
	 */
}

/*
 * Cleans and closes up all uses of the HCA
 */
static void
rib_detach_hca(rib_hca_t *hca)
{

	/*
	 * Stop all services on the HCA
	 * Go through cl_conn_list and close all rc_channels
	 * Go through svr_conn_list and close all rc_channels
	 * Free connections whose c_ref has dropped to 0
	 * Destroy all CQs
	 * Deregister and released all buffer pool memory after all
	 * connections are destroyed
	 * Free the protection domain
	 * ibt_close_hca()
	 */
	rw_enter(&hca->state_lock, RW_WRITER);
	if (hca->state == HCA_DETACHED) {
		rw_exit(&hca->state_lock);
		return;
	}

	hca->state = HCA_DETACHED;
	rib_stat->nhca_inited--;

	rib_stop_services(hca);
	rib_close_channels(&hca->cl_conn_list);
	rib_close_channels(&hca->srv_conn_list);
	rw_exit(&hca->state_lock);

	rib_purge_connlist(&hca->cl_conn_list);
	rib_purge_connlist(&hca->srv_conn_list);

	(void) ibt_free_cq(hca->clnt_rcq->rib_cq_hdl);
	(void) ibt_free_cq(hca->clnt_scq->rib_cq_hdl);
	(void) ibt_free_cq(hca->svc_rcq->rib_cq_hdl);
	(void) ibt_free_cq(hca->svc_scq->rib_cq_hdl);
	kmem_free(hca->clnt_rcq, sizeof (rib_cq_t));
	kmem_free(hca->clnt_scq, sizeof (rib_cq_t));
	kmem_free(hca->svc_rcq, sizeof (rib_cq_t));
	kmem_free(hca->svc_scq, sizeof (rib_cq_t));

	rw_enter(&hca->srv_conn_list.conn_lock, RW_READER);
	rw_enter(&hca->cl_conn_list.conn_lock, RW_READER);
	if (hca->srv_conn_list.conn_hd == NULL &&
	    hca->cl_conn_list.conn_hd == NULL) {
		/*
		 * conn_lists are NULL, so destroy
		 * buffers, close hca and be done.
		 */
		rib_rbufpool_destroy(hca, RECV_BUFFER);
		rib_rbufpool_destroy(hca, SEND_BUFFER);
		rib_destroy_cache(hca);
		(void) ibt_free_pd(hca->hca_hdl, hca->pd_hdl);
		(void) ibt_close_hca(hca->hca_hdl);
		hca->hca_hdl = NULL;
	}
	rw_exit(&hca->cl_conn_list.conn_lock);
	rw_exit(&hca->srv_conn_list.conn_lock);

	if (hca->hca_hdl != NULL) {
		mutex_enter(&hca->inuse_lock);
		while (hca->inuse)
			cv_wait(&hca->cb_cv, &hca->inuse_lock);
		mutex_exit(&hca->inuse_lock);
		/*
		 * conn_lists are now NULL, so destroy
		 * buffers, close hca and be done.
		 */
		rib_rbufpool_destroy(hca, RECV_BUFFER);
		rib_rbufpool_destroy(hca, SEND_BUFFER);
		(void) ibt_free_pd(hca->hca_hdl, hca->pd_hdl);
		(void) ibt_close_hca(hca->hca_hdl);
		hca->hca_hdl = NULL;
	}
}

static void
rib_server_side_cache_reclaim(void *argp)
{
	cache_avl_struct_t    *rcas;
	rib_lrc_entry_t		*rb;
	rib_hca_t *hca = (rib_hca_t *)argp;

	rw_enter(&hca->avl_rw_lock, RW_WRITER);
	rcas = avl_first(&hca->avl_tree);
	if (rcas != NULL)
		avl_remove(&hca->avl_tree, rcas);

	while (rcas != NULL) {
		while (rcas->r.forw != &rcas->r) {
			rcas->elements--;
			rib_total_buffers --;
			rb = rcas->r.forw;
			remque(rb);
			if (rb->registered)
				(void) rib_deregistermem_via_hca(hca,
				    rb->lrc_buf, rb->lrc_mhandle);
			cache_allocation -= rb->lrc_len;
			kmem_free(rb->lrc_buf, rb->lrc_len);
			kmem_free(rb, sizeof (rib_lrc_entry_t));
		}
		mutex_destroy(&rcas->node_lock);
		kmem_cache_free(hca->server_side_cache, rcas);
		rcas = avl_first(&hca->avl_tree);
		if (rcas != NULL)
			avl_remove(&hca->avl_tree, rcas);
	}
	rw_exit(&hca->avl_rw_lock);
}

static void
rib_server_side_cache_cleanup(void *argp)
{
	cache_avl_struct_t    *rcas;
	rib_lrc_entry_t		*rb;
	rib_hca_t *hca = (rib_hca_t *)argp;

	rw_enter(&hca->avl_rw_lock, RW_READER);
	if (cache_allocation < cache_limit) {
		rw_exit(&hca->avl_rw_lock);
		return;
	}
	rw_exit(&hca->avl_rw_lock);

	rw_enter(&hca->avl_rw_lock, RW_WRITER);
	rcas = avl_last(&hca->avl_tree);
	if (rcas != NULL)
		avl_remove(&hca->avl_tree, rcas);

	while (rcas != NULL) {
		while (rcas->r.forw != &rcas->r) {
			rcas->elements--;
			rib_total_buffers --;
			rb = rcas->r.forw;
			remque(rb);
			if (rb->registered)
				(void) rib_deregistermem_via_hca(hca,
				    rb->lrc_buf, rb->lrc_mhandle);
			cache_allocation -= rb->lrc_len;
			kmem_free(rb->lrc_buf, rb->lrc_len);
			kmem_free(rb, sizeof (rib_lrc_entry_t));
		}
		mutex_destroy(&rcas->node_lock);
		kmem_cache_free(hca->server_side_cache, rcas);
		if ((cache_allocation) < cache_limit) {
			rw_exit(&hca->avl_rw_lock);
			return;
		}

		rcas = avl_last(&hca->avl_tree);
		if (rcas != NULL)
			avl_remove(&hca->avl_tree, rcas);
	}
	rw_exit(&hca->avl_rw_lock);
}

static int
avl_compare(const void *t1, const void *t2)
{
	if (((cache_avl_struct_t *)t1)->len == ((cache_avl_struct_t *)t2)->len)
		return (0);

	if (((cache_avl_struct_t *)t1)->len < ((cache_avl_struct_t *)t2)->len)
		return (-1);

	return (1);
}

static void
rib_destroy_cache(rib_hca_t *hca)
{
	if (hca->reg_cache_clean_up != NULL) {
		ddi_taskq_destroy(hca->reg_cache_clean_up);
		hca->reg_cache_clean_up = NULL;
	}
	if (!hca->avl_init) {
		kmem_cache_destroy(hca->server_side_cache);
		avl_destroy(&hca->avl_tree);
		mutex_destroy(&hca->cache_allocation);
		rw_destroy(&hca->avl_rw_lock);
	}
	hca->avl_init = FALSE;
}

static void
rib_force_cleanup(void *hca)
{
	if (((rib_hca_t *)hca)->reg_cache_clean_up != NULL)
		(void) ddi_taskq_dispatch(
		    ((rib_hca_t *)hca)->reg_cache_clean_up,
		    rib_server_side_cache_cleanup,
		    (void *)hca, DDI_NOSLEEP);
}

static rib_lrc_entry_t *
rib_get_cache_buf(CONN *conn, uint32_t len)
{
	cache_avl_struct_t	cas, *rcas;
	rib_hca_t	*hca = (ctoqp(conn))->hca;
	rib_lrc_entry_t *reply_buf;
	avl_index_t where = NULL;
	uint64_t c_alloc = 0;

	if (!hca->avl_init)
		goto  error_alloc;

	cas.len = len;

	rw_enter(&hca->avl_rw_lock, RW_READER);

	mutex_enter(&hca->cache_allocation);
	c_alloc = cache_allocation;
	mutex_exit(&hca->cache_allocation);

	if ((rcas = (cache_avl_struct_t *)avl_find(&hca->avl_tree, &cas,
	    &where)) == NULL) {
		/* Am I above the cache limit */
		if ((c_alloc + len) >= cache_limit) {
			rib_force_cleanup((void *)hca);
			rw_exit(&hca->avl_rw_lock);
			cache_misses_above_the_limit ++;

			/* Allocate and register the buffer directly */
			goto error_alloc;
		}

		rw_exit(&hca->avl_rw_lock);
		rw_enter(&hca->avl_rw_lock, RW_WRITER);

		/* Recheck to make sure no other thread added the entry in */
		if ((rcas = (cache_avl_struct_t *)avl_find(&hca->avl_tree,
		    &cas, &where)) == NULL) {
			/* Allocate an avl tree entry */
			rcas = (cache_avl_struct_t *)
			    kmem_cache_alloc(hca->server_side_cache, KM_SLEEP);

			bzero(rcas, sizeof (cache_avl_struct_t));
			rcas->elements = 0;
			rcas->r.forw = &rcas->r;
			rcas->r.back = &rcas->r;
			rcas->len = len;
			mutex_init(&rcas->node_lock, NULL, MUTEX_DEFAULT, NULL);
			avl_insert(&hca->avl_tree, rcas, where);
		}
	}

	mutex_enter(&rcas->node_lock);

	if (rcas->r.forw != &rcas->r && rcas->elements > 0) {
		rib_total_buffers--;
		cache_hits++;
		reply_buf = rcas->r.forw;
		remque(reply_buf);
		rcas->elements--;
		mutex_exit(&rcas->node_lock);
		rw_exit(&hca->avl_rw_lock);
		mutex_enter(&hca->cache_allocation);
		cache_allocation -= len;
		mutex_exit(&hca->cache_allocation);
	} else {
		/* Am I above the cache limit */
		mutex_exit(&rcas->node_lock);
		if ((c_alloc + len) >= cache_limit) {
			rib_force_cleanup((void *)hca);
			rw_exit(&hca->avl_rw_lock);
			cache_misses_above_the_limit ++;
			/* Allocate and register the buffer directly */
			goto error_alloc;
		}
		rw_exit(&hca->avl_rw_lock);
		cache_misses ++;
		/* Allocate a reply_buf entry */
		reply_buf = (rib_lrc_entry_t *)
		    kmem_zalloc(sizeof (rib_lrc_entry_t), KM_SLEEP);
		bzero(reply_buf, sizeof (rib_lrc_entry_t));
		reply_buf->lrc_buf  = kmem_alloc(len, KM_SLEEP);
		reply_buf->lrc_len  = len;
		reply_buf->registered = FALSE;
		reply_buf->avl_node = (void *)rcas;
	}

	return (reply_buf);

error_alloc:
	reply_buf = (rib_lrc_entry_t *)
	    kmem_zalloc(sizeof (rib_lrc_entry_t), KM_SLEEP);
	bzero(reply_buf, sizeof (rib_lrc_entry_t));
	reply_buf->lrc_buf = kmem_alloc(len, KM_SLEEP);
	reply_buf->lrc_len = len;
	reply_buf->registered = FALSE;
	reply_buf->avl_node = NULL;

	return (reply_buf);
}

/*
 * Return a pre-registered back to the cache (without
 * unregistering the buffer)..
 */

static void
rib_free_cache_buf(CONN *conn, rib_lrc_entry_t *reg_buf)
{
	cache_avl_struct_t    cas, *rcas;
	avl_index_t where = NULL;
	rib_hca_t	*hca = (ctoqp(conn))->hca;

	if (!hca->avl_init)
		goto  error_free;

	cas.len = reg_buf->lrc_len;
	rw_enter(&hca->avl_rw_lock, RW_READER);
	if ((rcas = (cache_avl_struct_t *)
	    avl_find(&hca->avl_tree, &cas, &where)) == NULL) {
		rw_exit(&hca->avl_rw_lock);
		goto error_free;
	} else {
		rib_total_buffers ++;
		cas.len = reg_buf->lrc_len;
		mutex_enter(&rcas->node_lock);
		insque(reg_buf, &rcas->r);
		rcas->elements ++;
		mutex_exit(&rcas->node_lock);
		rw_exit(&hca->avl_rw_lock);
		mutex_enter(&hca->cache_allocation);
		cache_allocation += cas.len;
		mutex_exit(&hca->cache_allocation);
	}

	return;

error_free:

	if (reg_buf->registered)
		(void) rib_deregistermem_via_hca(hca,
		    reg_buf->lrc_buf, reg_buf->lrc_mhandle);
	kmem_free(reg_buf->lrc_buf, reg_buf->lrc_len);
	kmem_free(reg_buf, sizeof (rib_lrc_entry_t));
}

static rdma_stat
rib_registermem_via_hca(rib_hca_t *hca, caddr_t adsp, caddr_t buf,
	uint_t buflen, struct mrc *buf_handle)
{
	ibt_mr_hdl_t	mr_hdl = NULL;	/* memory region handle */
	ibt_mr_desc_t	mr_desc;	/* vaddr, lkey, rkey */
	rdma_stat	status;


	/*
	 * Note: ALL buffer pools use the same memory type RDMARW.
	 */
	status = rib_reg_mem(hca, adsp, buf, buflen, 0, &mr_hdl, &mr_desc);
	if (status == RDMA_SUCCESS) {
		buf_handle->mrc_linfo = (uint64_t)(uintptr_t)mr_hdl;
		buf_handle->mrc_lmr = (uint32_t)mr_desc.md_lkey;
		buf_handle->mrc_rmr = (uint32_t)mr_desc.md_rkey;
	} else {
		buf_handle->mrc_linfo = NULL;
		buf_handle->mrc_lmr = 0;
		buf_handle->mrc_rmr = 0;
	}
	return (status);
}

/* ARGSUSED */
static rdma_stat
rib_deregistermemsync_via_hca(rib_hca_t *hca, caddr_t buf,
    struct mrc buf_handle, RIB_SYNCMEM_HANDLE sync_handle)
{

	(void) rib_deregistermem_via_hca(hca, buf, buf_handle);
	return (RDMA_SUCCESS);
}

/* ARGSUSED */
static rdma_stat
rib_deregistermem_via_hca(rib_hca_t *hca, caddr_t buf, struct mrc buf_handle)
{

	(void) ibt_deregister_mr(hca->hca_hdl,
	    (ibt_mr_hdl_t)(uintptr_t)buf_handle.mrc_linfo);
	return (RDMA_SUCCESS);
}


/*
 * Return 0 if the interface is IB.
 * Return error (>0) if any error is encountered during processing.
 * Return -1 if the interface is not IB and no error.
 */
#define	isalpha(ch)	(((ch) >= 'a' && (ch) <= 'z') || \
			((ch) >= 'A' && (ch) <= 'Z'))
static int
rpcib_is_ib_interface(char *name)
{

	char	dev_path[MAXPATHLEN];
	char	devname[MAXNAMELEN];
	ldi_handle_t	lh;
	dl_info_ack_t	info;
	int	ret = 0;
	int	i;

	/*
	 * ibd devices are only style 2 devices
	 * so we will open only style 2 devices
	 * by ignoring the ppa
	 */

	i = strlen(name) - 1;
	while ((i >= 0) && (!isalpha(name[i]))) i--;

	if (i < 0) {
		/* Invalid interface name, no alphabet */
		return (-1);
	}

	(void) strncpy(devname, name, i + 1);
	devname[i + 1] = '\0';

	if (strcmp("lo", devname) == 0) {
		/*
		 * loopback interface  not rpc/rdma capable
		 */
		return (-1);
	}

	(void) strncpy(dev_path, "/dev/", MAXPATHLEN);
	if (strlcat(dev_path, devname, MAXPATHLEN) >= MAXPATHLEN) {
		/* string overflow */
		return (-1);
	}

	ret = ldi_open_by_name(dev_path, FREAD|FWRITE, kcred, &lh, rpcib_li);
	if (ret != 0) {
		return (ret);
	}
	ret = rpcib_dl_info(lh, &info);
	(void) ldi_close(lh, FREAD|FWRITE, kcred);
	if (ret != 0) {
		return (ret);
	}

	if (info.dl_mac_type != DL_IB) {
		return (-1);
	}

	return (0);
}

static int
rpcib_dl_info(ldi_handle_t lh, dl_info_ack_t *info)
{
	dl_info_req_t *info_req;
	union DL_primitives *dl_prim;
	mblk_t *mp;
	k_sigset_t smask;
	int error;

	if ((mp = allocb(sizeof (dl_info_req_t), BPRI_MED)) == NULL) {
		return (ENOMEM);
	}

	mp->b_datap->db_type = M_PROTO;

	info_req = (dl_info_req_t *)(uintptr_t)mp->b_wptr;
	mp->b_wptr += sizeof (dl_info_req_t);
	info_req->dl_primitive = DL_INFO_REQ;

	sigintr(&smask, 0);
	if ((error = ldi_putmsg(lh, mp)) != 0) {
		sigunintr(&smask);
		return (error);
	}
	if ((error = ldi_getmsg(lh, &mp, (timestruc_t *)NULL)) != 0) {
		sigunintr(&smask);
		return (error);
	}
	sigunintr(&smask);

	dl_prim = (union DL_primitives *)(uintptr_t)mp->b_rptr;
	switch (dl_prim->dl_primitive) {
		case DL_INFO_ACK:
			if (((uintptr_t)mp->b_wptr - (uintptr_t)mp->b_rptr) <
			    sizeof (dl_info_ack_t)) {
			error = -1;
			} else {
				*info = *(dl_info_ack_t *)(uintptr_t)mp->b_rptr;
				error = 0;
			}
			break;
		default:
			error = -1;
			break;
	}

	freemsg(mp);
	return (error);
}
static int
rpcib_do_ip_ioctl(int cmd, int len, caddr_t arg)
{
	vnode_t *kvp, *vp;
	TIUSER  *tiptr;
	struct  strioctl iocb;
	k_sigset_t smask;
	int	err = 0;

	if (lookupname("/dev/udp", UIO_SYSSPACE, FOLLOW, NULLVPP,
	    &kvp) == 0) {
		if (t_kopen((file_t *)NULL, kvp->v_rdev, FREAD|FWRITE,
		    &tiptr, CRED()) == 0) {
		vp = tiptr->fp->f_vnode;
	} else {
		VN_RELE(kvp);
		return (EPROTO);
		}
	} else {
			return (EPROTO);
	}

	iocb.ic_cmd = cmd;
	iocb.ic_timout = 0;
	iocb.ic_len = len;
	iocb.ic_dp = arg;
	sigintr(&smask, 0);
	err = kstr_ioctl(vp, I_STR, (intptr_t)&iocb);
	sigunintr(&smask);
	(void) t_kclose(tiptr, 0);
	VN_RELE(kvp);
	return (err);
}

static uint_t rpcib_get_number_interfaces(void) {
uint_t	numifs;
	if (rpcib_do_ip_ioctl(SIOCGIFNUM, sizeof (uint_t), (caddr_t)&numifs)) {
		return (0);
	}
	return (numifs);
}

static boolean_t
rpcib_get_ib_addresses(
	struct sockaddr_in *saddr4,
	struct sockaddr_in6 *saddr6,
	uint_t *number4,
	uint_t *number6)
{
	int	numifs;
	struct	ifconf	kifc;
	struct  ifreq *ifr;
	boolean_t ret = B_FALSE;

	*number4 = 0;
	*number6 = 0;

	if (rpcib_do_ip_ioctl(SIOCGIFNUM, sizeof (int), (caddr_t)&numifs)) {
		return (ret);
	}

	kifc.ifc_len = numifs * sizeof (struct ifreq);
	kifc.ifc_buf = kmem_zalloc(kifc.ifc_len, KM_SLEEP);

	if (rpcib_do_ip_ioctl(SIOCGIFCONF, sizeof (struct ifconf),
	    (caddr_t)&kifc)) {
		goto done;
	}

	ifr = kifc.ifc_req;
	for (numifs = kifc.ifc_len / sizeof (struct ifreq);
	    numifs > 0; numifs--, ifr++) {
		struct sockaddr_in *sin4;
		struct sockaddr_in6 *sin6;

		if ((rpcib_is_ib_interface(ifr->ifr_name) == 0)) {
			sin4 = (struct sockaddr_in *)(uintptr_t)&ifr->ifr_addr;
			sin6 = (struct sockaddr_in6 *)(uintptr_t)&ifr->ifr_addr;
			if (sin4->sin_family == AF_INET) {
				saddr4[*number4] = *(struct sockaddr_in *)
				    (uintptr_t)&ifr->ifr_addr;
				*number4 = *number4 + 1;
			} else if (sin6->sin6_family == AF_INET6) {
				saddr6[*number6] = *(struct sockaddr_in6 *)
				    (uintptr_t)&ifr->ifr_addr;
				*number6 = *number6 + 1;
			}
		}
	}
	ret = B_TRUE;
done:
	kmem_free(kifc.ifc_buf, kifc.ifc_len);
	return (ret);
}

/* ARGSUSED */
static int rpcib_cache_kstat_update(kstat_t *ksp, int rw) {

	if (KSTAT_WRITE == rw) {
		return (EACCES);
	}
	rpcib_kstat.cache_limit.value.ui64 =
	    (uint64_t)cache_limit;
	rpcib_kstat.cache_allocation.value.ui64 =
	    (uint64_t)cache_allocation;
	rpcib_kstat.cache_hits.value.ui64 =
	    (uint64_t)cache_hits;
	rpcib_kstat.cache_misses.value.ui64 =
	    (uint64_t)cache_misses;
	rpcib_kstat.cache_misses_above_the_limit.value.ui64 =
	    (uint64_t)cache_misses_above_the_limit;
	return (0);
}
