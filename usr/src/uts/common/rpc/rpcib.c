/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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


extern char *inet_ntop(int, const void *, char *, int);


/*
 * Prototype declarations for driver ops
 */

static int	rpcib_attach(dev_info_t *, ddi_attach_cmd_t);
static int	rpcib_getinfo(dev_info_t *, ddi_info_cmd_t,
			    void *, void **);
static int	rpcib_detach(dev_info_t *, ddi_detach_cmd_t);


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
	NULL			/* power */
};

/*
 * Module linkage information.
 */

static struct modldrv rib_modldrv = {
	&mod_driverops,			    /* Driver module */
	"RPCIB plugin driver, ver %I%", /* Driver name and version */
	&rpcib_ops,		    /* Driver ops */
};

static struct modlinkage rib_modlinkage = {
	MODREV_1,
	(void *)&rib_modldrv,
	NULL
};

/*
 * rib_stat: private data pointer used when registering
 *	with the IBTF.  It is returned to the consumer
 *	in all callbacks.
 */
static rpcib_state_t *rib_stat = NULL;

#define	RNR_RETRIES	2
#define	MAX_PORTS	2

int preposted_rbufs = 16;
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


/*
 * RPCIB RDMATF operations
 */
static rdma_stat rib_reachable(int addr_type, struct netbuf *, void **handle);
static rdma_stat rib_disconnect(CONN *conn);
static void rib_listen(struct rdma_svc_data *rd);
static void rib_listen_stop(struct rdma_svc_data *rd);
static rdma_stat rib_registermem(CONN *conn, caddr_t buf, uint_t buflen,
	struct mrc *buf_handle);
static rdma_stat rib_deregistermem(CONN *conn, caddr_t buf,
	struct mrc buf_handle);
static rdma_stat rib_registermemsync(CONN *conn, caddr_t buf, uint_t buflen,
	struct mrc *buf_handle, RIB_SYNCMEM_HANDLE *sync_handle);
static rdma_stat rib_deregistermemsync(CONN *conn, caddr_t buf,
	struct mrc buf_handle, RIB_SYNCMEM_HANDLE sync_handle);
static rdma_stat rib_syncmem(CONN *conn, RIB_SYNCMEM_HANDLE shandle,
	caddr_t buf, int len, int cpu);

static rdma_stat rib_reg_buf_alloc(CONN *conn, rdma_buf_t *rdbuf);

static void rib_reg_buf_free(CONN *conn, rdma_buf_t *rdbuf);
static void *rib_rbuf_alloc(CONN *, rdma_buf_t *);

static void rib_rbuf_free(CONN *conn, int ptype, void *buf);

static rdma_stat rib_send(CONN *conn, struct clist *cl, uint32_t msgid);
static rdma_stat rib_send_resp(CONN *conn, struct clist *cl, uint32_t msgid);
static rdma_stat rib_post_resp(CONN *conn, struct clist *cl, uint32_t msgid);
static rdma_stat rib_post_recv(CONN *conn, struct clist *cl);
static rdma_stat rib_recv(CONN *conn, struct clist **clp, uint32_t msgid);
static rdma_stat rib_read(CONN *conn, struct clist *cl, int wait);
static rdma_stat rib_write(CONN *conn, struct clist *cl, int wait);
static rdma_stat rib_ping_srv(int addr_type, struct netbuf *, rib_hca_t **);
static rdma_stat rib_conn_get(struct netbuf *, int addr_type, void *, CONN **);
static rdma_stat rib_conn_release(CONN *conn);
static rdma_stat rib_getinfo(rdma_info_t *info);
static rdma_stat rib_register_ats(rib_hca_t *);
static void rib_deregister_ats();
static void rib_stop_services(rib_hca_t *);

/*
 * RPCIB addressing operations
 */
char ** get_ip_addrs(int *count);
int get_interfaces(TIUSER *tiptr, int *num);
int find_addrs(TIUSER *tiptr, char **addrs, int num_ifs);
int get_ibd_ipaddr(rpcib_ibd_insts_t *);
rpcib_ats_t *get_ibd_entry(ib_gid_t *, ib_pkey_t, rpcib_ibd_insts_t *);
void rib_get_ibd_insts(rpcib_ibd_insts_t *);


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
	rib_post_recv,
	rib_recv,
	rib_read,
	rib_write,
	rib_getinfo
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
static rdma_stat rib_reg_mem(rib_hca_t *, caddr_t, uint_t, ibt_mr_flags_t,
	ibt_mr_hdl_t *, ibt_mr_desc_t *);
static rdma_stat rib_conn_to_srv(rib_hca_t *, rib_qp_t *, ibt_path_info_t *);
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
static rdma_stat rib_chk_srv_ats(rib_hca_t *, struct netbuf *, int,
	ibt_path_info_t *);

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

static int ats_running = 0;
int
_init(void)
{
	int		error;

	error = mod_install((struct modlinkage *)&rib_modlinkage);
	if (error != 0) {
		/*
		 * Could not load module
		 */
		return (error);
	}
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

	rib_deregister_ats();

	/*
	 * Remove module
	 */
	if ((status = mod_remove(&rib_modlinkage)) != 0) {
		(void) rdma_register_mod(&rib_mod);
		return (status);
	}
	mutex_destroy(&plugin_state_lock);
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


static void
rib_deregister_ats()
{
	rib_hca_t		*hca;
	rib_service_t		*srv_list, *to_remove;
	ibt_status_t   		ibt_status;

	/*
	 * deregister the Address Translation Service.
	 */
	hca = rib_stat->hca;
	rw_enter(&hca->service_list_lock, RW_WRITER);
	srv_list = hca->ats_list;
	while (srv_list != NULL) {
		to_remove = srv_list;
		srv_list = to_remove->srv_next;

		ibt_status = ibt_deregister_ar(hca->ibt_clnt_hdl,
				&to_remove->srv_ar);
		if (ibt_status != IBT_SUCCESS) {
#ifdef DEBUG
		    if (rib_debug) {
			cmn_err(CE_WARN, "_fini: "
			    "ibt_deregister_ar FAILED"
				" status: %d", ibt_status);
		    }
#endif
		} else {
		    mutex_enter(&rib_stat->open_hca_lock);
		    ats_running = 0;
		    mutex_exit(&rib_stat->open_hca_lock);
#ifdef DEBUG
		    if (rib_debug) {

			cmn_err(CE_NOTE, "_fini: "
			    "Successfully unregistered"
			    " ATS service: %s",
			    to_remove->srv_name);
		    }
#endif
		}
		kmem_free(to_remove, sizeof (rib_service_t));
	}
	hca->ats_list = NULL;
	rw_exit(&hca->service_list_lock);
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
			cmn_err(CE_WARN, "open_hcas: ibt_open_hca (%d) "
				"returned %d", i, ibt_status);
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
			cmn_err(CE_WARN, "open_hcas: ibt_query_hca "
			    "returned %d (hca_guid 0x%llx)",
			    ibt_status, (longlong_t)ribstat->hca_guids[i]);
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
			cmn_err(CE_WARN, "open_hcas: ibt_alloc_pd "
				"returned %d (hca_guid 0x%llx)",
				ibt_status, (longlong_t)ribstat->hca_guids[i]);
			goto fail1;
		}

		/*
		 * query HCA ports
		 */
		ibt_status = ibt_query_hca_ports(hca->hca_hdl,
				0, &pinfop, &hca->hca_nports, &size);
		if (ibt_status != IBT_SUCCESS) {
			cmn_err(CE_WARN, "open_hcas: "
				"ibt_query_hca_ports returned %d "
				"(hca_guid 0x%llx)",
				ibt_status, (longlong_t)hca->hca_guid);
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
			cmn_err(CE_WARN, "open_hcas: recv buf pool failed\n");
			goto fail3;
		}

		hca->send_pool = rib_rbufpool_create(hca,
					SEND_BUFFER, MAX_BUFS);
		if (hca->send_pool == NULL) {
			cmn_err(CE_WARN, "open_hcas: send buf pool failed\n");
			rib_rbufpool_destroy(hca, RECV_BUFFER);
			goto fail3;
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
#ifdef DEBUG
	if (rib_debug > 1) {
	    if (wc.wc_status != IBT_WC_SUCCESS) {
		    cmn_err(CE_NOTE, "rib_clnt_scq_handler: "
			"WR completed in error, wc.wc_status:%d, "
			"wc_id:%llx\n", wc.wc_status, (longlong_t)wc.wc_id);
	    }
	}
#endif
			/*
			 * Channel in error state. Set connection to
			 * ERROR and cleanup will happen either from
			 * conn_release  or from rib_conn_get
			 */
			wd->status = RDMA_FAILED;
			mutex_enter(&conn->c_lock);
			if (conn->c_state != C_DISCONN_PEND)
				conn->c_state = C_ERROR;
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
#ifdef DEBUG
	    if (rib_debug > 1 && wc.wc_status != IBT_WC_SUCCESS) {
		cmn_err(CE_NOTE, "rib_svc_scq_handler: WR completed in error "
			"wc.wc_status:%d, wc_id:%llX",
			wc.wc_status, (longlong_t)wc.wc_id);
	    }
#endif
	    if (wc.wc_id != NULL) { /* XXX NULL possible ???? */
		struct send_wid *wd = (struct send_wid *)(uintptr_t)wc.wc_id;

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
				rib_rbuf_free(qptoc(wd->qp), SEND_BUFFER,
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
		    XDR			inxdrs, *xdrs;
		    uint_t		xid, vers, op, find_xid = 0;
		    struct reply	*r;
		    CONN *conn = qptoc(qp);

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
		    (void) xdr_u_int(xdrs, &op);
		    XDR_DESTROY(xdrs);
		    if (vers != RPCRDMA_VERS) {
			/*
			 * Invalid RPC/RDMA version. Cannot interoperate.
			 * Set connection to ERROR state and bail out.
			 */
			mutex_enter(&conn->c_lock);
			if (conn->c_state != C_DISCONN_PEND)
				conn->c_state = C_ERROR;
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
				r->bytes_xfer = wc.wc_bytes_xfer;
				cv_signal(&r->wait_cv);
				break;
			    default:
				rib_rbuf_free(qptoc(qp), RECV_BUFFER,
						(void *)(uintptr_t)rwid->addr);
				break;
			    }
			    break;
			}
		    }
		    mutex_exit(&qp->replylist_lock);
		    if (find_xid == 0) {
			/* RPC caller not waiting for reply */
#ifdef DEBUG
			    if (rib_debug) {
			cmn_err(CE_NOTE, "rib_clnt_rcq_handler: "
			    "NO matching xid %u!\n", xid);
			    }
#endif
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
				conn->c_state = C_ERROR;
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
	struct recv_data *rd;
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
		if (qp->n_posted_rbufs == 0)
			cv_signal(&qp->posted_rbufs_cv);
		mutex_exit(&qp->posted_rbufs_lock);

		if (wc.wc_status == IBT_WC_SUCCESS) {
		    XDR		inxdrs, *xdrs;
		    uint_t	xid, vers, op;

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
			!xdr_u_int(xdrs, &op)) {
			rib_rbuf_free(conn, RECV_BUFFER,
				(void *)(uintptr_t)s_recvp->vaddr);
			XDR_DESTROY(xdrs);
#ifdef DEBUG
			cmn_err(CE_NOTE, "rib_svc_rcq_handler: "
			    "xdr_u_int failed for qp %p, wc_id=%llx",
			    (void *)qp, (longlong_t)wc.wc_id);
#endif
			(void) rib_free_svc_recv(s_recvp);
			continue;
		    }
		    XDR_DESTROY(xdrs);

		    if (vers != RPCRDMA_VERS) {
			/*
			 * Invalid RPC/RDMA version. Drop rpc rdma message.
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
			while ((mp = allocb(sizeof (*rd), BPRI_LO)) == NULL)
			    (void) strwaitbuf(sizeof (*rd), BPRI_LO);
			/*
			 * Plugin is in accept state, hence the master
			 * transport queue for this is still accepting
			 * requests. Hence we can call svc_queuereq to
			 * queue this recieved msg.
			 */
			rd = (struct recv_data *)mp->b_rptr;
			rd->conn = conn;
			rd->rpcmsg.addr = (caddr_t)(uintptr_t)s_recvp->vaddr;
			rd->rpcmsg.type = RECV_BUFFER;
			rd->rpcmsg.len = wc.wc_bytes_xfer;
			rd->status = wc.wc_status;
			mutex_enter(&conn->c_lock);
			conn->c_ref++;
			mutex_exit(&conn->c_lock);
			mp->b_wptr += sizeof (*rd);
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
	cmn_err(CE_NOTE, "rib_async_handler(): IBT_EVENT_PATH_MIGRATED\n");
		break;
	case IBT_EVENT_SQD:
	cmn_err(CE_NOTE, "rib_async_handler(): IBT_EVENT_SQD\n");
		break;
	case IBT_EVENT_COM_EST:
	cmn_err(CE_NOTE, "rib_async_handler(): IBT_EVENT_COM_EST\n");
		break;
	case IBT_ERROR_CATASTROPHIC_CHAN:
	cmn_err(CE_NOTE, "rib_async_handler(): IBT_ERROR_CATASTROPHIC_CHAN\n");
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
	cmn_err(CE_NOTE, "rib_async_handler(): IBT_ERROR_PATH_MIGRATE_REQ\n");
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
		/*
		 * Register the Address translation service
		 */
		mutex_enter(&rib_stat->open_hca_lock);
		if (ats_running == 0) {
			if (rib_register_ats(rib_stat->hca)
			    == RDMA_SUCCESS) {
				ats_running = 1;
				mutex_exit(&rib_stat->open_hca_lock);
				return (RDMA_SUCCESS);
			} else {
				mutex_exit(&rib_stat->open_hca_lock);
				return (RDMA_FAILED);
			}
		} else {
			mutex_exit(&rib_stat->open_hca_lock);
			return (RDMA_SUCCESS);
		}
	} else {
		*handle = NULL;
		if (rib_debug > 2)
		    cmn_err(CE_WARN, "rib_reachable(): ping_srv failed.\n");
		return (RDMA_FAILED);
	}
}

/* Client side qp creation */
static rdma_stat
rib_clnt_create_chan(rib_hca_t *hca, struct netbuf *raddr, rib_qp_t **qp)
{
	rib_qp_t	*kqp = NULL;
	CONN		*conn;

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

	ASSERT(qp != NULL);
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
		cmn_err(CE_WARN, "rib_svc_create_chan: "
			"ibt_alloc_rc_channel failed, ibt_status=%d.",
			ibt_status);
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
	*qp = kqp;
	return (RDMA_SUCCESS);
fail:
	if (kqp)
		kmem_free(kqp, sizeof (rib_qp_t));

	return (RDMA_FAILED);
}

void
rib_dump_pathrec(ibt_path_info_t *path_rec)
{
	ib_pkey_t	pkey;

	if (rib_debug > 1) {
	    cmn_err(CE_NOTE, "Path Record:\n");

	    cmn_err(CE_NOTE, "Source HCA GUID = %llx\n",
		(longlong_t)path_rec->pi_hca_guid);
	    cmn_err(CE_NOTE, "Dest Service ID = %llx\n",
		(longlong_t)path_rec->pi_sid);
	    cmn_err(CE_NOTE, "Port Num        = %02d\n",
		path_rec->pi_prim_cep_path.cep_hca_port_num);
	    cmn_err(CE_NOTE, "P_Key Index     = %04d\n",
		path_rec->pi_prim_cep_path.cep_pkey_ix);

	    (void) ibt_index2pkey_byguid(path_rec->pi_hca_guid,
			path_rec->pi_prim_cep_path.cep_hca_port_num,
			path_rec->pi_prim_cep_path.cep_pkey_ix, &pkey);
	    cmn_err(CE_NOTE, "P_Key		= 0x%x\n", pkey);


	    cmn_err(CE_NOTE, "SGID:           = %llx:%llx\n",
		(longlong_t)
		path_rec->pi_prim_cep_path.cep_adds_vect.av_sgid.gid_prefix,
		(longlong_t)
		path_rec->pi_prim_cep_path.cep_adds_vect.av_sgid.gid_guid);

	    cmn_err(CE_NOTE, "DGID:           = %llx:%llx\n",
		(longlong_t)
		path_rec->pi_prim_cep_path.cep_adds_vect.av_dgid.gid_prefix,
		(longlong_t)
		path_rec->pi_prim_cep_path.cep_adds_vect.av_dgid.gid_guid);

	    cmn_err(CE_NOTE, "Path Rate       = %02x\n",
		path_rec->pi_prim_cep_path.cep_adds_vect.av_srate);
	    cmn_err(CE_NOTE, "SL              = %02x\n",
		path_rec->pi_prim_cep_path.cep_adds_vect.av_srvl);
	    cmn_err(CE_NOTE, "Prim Packet LT  = %02x\n",
		path_rec->pi_prim_pkt_lt);
	    cmn_err(CE_NOTE, "Path MTU        = %02x\n",
		path_rec->pi_path_mtu);
	}
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

			conn->c_state = C_ERROR;

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


/* Check if server has done ATS registration */
rdma_stat
rib_chk_srv_ats(rib_hca_t *hca, struct netbuf *raddr,
	int addr_type, ibt_path_info_t *path)
{
	struct sockaddr_in	*sin4;
	struct sockaddr_in6	*sin6;
	ibt_path_attr_t		path_attr;
	ibt_status_t		ibt_status;
	ib_pkey_t		pkey;
	ibt_ar_t		ar_query, ar_result;
	rib_service_t		*ats;
	ib_gid_t		sgid;
	ibt_path_info_t		paths[MAX_PORTS];
	uint8_t			npaths, i;

	(void) bzero(&path_attr, sizeof (ibt_path_attr_t));
	(void) bzero(path, sizeof (ibt_path_info_t));

	/*
	 * Construct svc name
	 */
	path_attr.pa_sname = kmem_zalloc(IB_SVC_NAME_LEN, KM_SLEEP);
	switch (addr_type) {
	case AF_INET:
		sin4 = (struct sockaddr_in *)raddr->buf;
		(void) inet_ntop(AF_INET, &sin4->sin_addr, path_attr.pa_sname,
		    IB_SVC_NAME_LEN);
		break;

	case AF_INET6:
		sin6 = (struct sockaddr_in6 *)raddr->buf;
		(void) inet_ntop(AF_INET6, &sin6->sin6_addr,
		    path_attr.pa_sname, IB_SVC_NAME_LEN);
		break;

	default:
		kmem_free(path_attr.pa_sname, IB_SVC_NAME_LEN);
		return (RDMA_INVAL);
	}
	(void) strlcat(path_attr.pa_sname, "::NFS", IB_SVC_NAME_LEN);

	/*
	 * Attempt a path to the server on an ATS-registered port.
	 * Try all ATS-registered ports until one succeeds.
	 * The first one that succeeds will be used to connect
	 * to the server.  If none of them succeed, return RDMA_FAILED.
	 */
	rw_enter(&hca->state_lock, RW_READER);
	if (hca->state != HCA_DETACHED) {
	    rw_enter(&hca->service_list_lock, RW_READER);
	    for (ats = hca->ats_list; ats != NULL; ats = ats->srv_next) {
		path_attr.pa_hca_guid = hca->hca_guid;
		path_attr.pa_hca_port_num = ats->srv_port;
		ibt_status = ibt_get_paths(hca->ibt_clnt_hdl,
			IBT_PATH_MULTI_SVC_DEST, &path_attr, 2, paths, &npaths);
		if (ibt_status == IBT_SUCCESS ||
			ibt_status == IBT_INSUFF_DATA) {
		    for (i = 0; i < npaths; i++) {
			if (paths[i].pi_hca_guid) {
			/*
			 * do ibt_query_ar()
			 */
			    sgid =
				paths[i].pi_prim_cep_path.cep_adds_vect.av_sgid;

			    (void) ibt_index2pkey_byguid(paths[i].pi_hca_guid,
				paths[i].pi_prim_cep_path.cep_hca_port_num,
				paths[i].pi_prim_cep_path.cep_pkey_ix, &pkey);

			    bzero(&ar_query, sizeof (ar_query));
			    bzero(&ar_result, sizeof (ar_result));
			    ar_query.ar_gid =
				paths[i].pi_prim_cep_path.cep_adds_vect.av_dgid;
			    ar_query.ar_pkey = pkey;
			    ibt_status = ibt_query_ar(&sgid, &ar_query,
					&ar_result);
			    if (ibt_status == IBT_SUCCESS) {
#ifdef DEBUG
				if (rib_debug > 1)
				    rib_dump_pathrec(&paths[i]);
#endif
				bcopy(&paths[i], path,
					sizeof (ibt_path_info_t));
				rw_exit(&hca->service_list_lock);
				kmem_free(path_attr.pa_sname, IB_SVC_NAME_LEN);
				rw_exit(&hca->state_lock);
				return (RDMA_SUCCESS);
			    }
#ifdef DEBUG
			    if (rib_debug) {
				cmn_err(CE_NOTE, "rib_chk_srv_ats: "
				    "ibt_query_ar FAILED, return\n");
			    }
#endif
			}
		    }
		}
	    }
	    rw_exit(&hca->service_list_lock);
	}
	kmem_free(path_attr.pa_sname, IB_SVC_NAME_LEN);
	rw_exit(&hca->state_lock);
	return (RDMA_FAILED);
}


/*
 * Connect to the server.
 */
rdma_stat
rib_conn_to_srv(rib_hca_t *hca, rib_qp_t *qp, ibt_path_info_t *path)
{
	ibt_chan_open_args_t	chan_args;	/* channel args */
	ibt_chan_sizes_t	chan_sizes;
	ibt_rc_chan_alloc_args_t	qp_attr;
	ibt_status_t		ibt_status;
	ibt_rc_returns_t	ret_args;   	/* conn reject info */
	int refresh = REFRESH_ATTEMPTS;	/* refresh if IBT_CM_CONN_STALE */

	(void) bzero(&chan_args, sizeof (chan_args));
	(void) bzero(&qp_attr, sizeof (ibt_rc_chan_alloc_args_t));

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

	chan_args.oc_path = path;
	chan_args.oc_cm_handler = rib_clnt_cm_handler;
	chan_args.oc_cm_clnt_private = (void *)rib_stat;
	chan_args.oc_rdma_ra_out = 1;
	chan_args.oc_rdma_ra_in = 1;
	chan_args.oc_path_retry_cnt = 2;
	chan_args.oc_path_rnr_retry_cnt = RNR_RETRIES;

refresh:
	rw_enter(&hca->state_lock, RW_READER);
	if (hca->state != HCA_DETACHED) {
		ibt_status = ibt_alloc_rc_channel(hca->hca_hdl,
			IBT_ACHAN_NO_FLAGS, &qp_attr, &qp->qp_hdl,
			&chan_sizes);
	} else {
		rw_exit(&hca->state_lock);
		return (RDMA_FAILED);
	}
	rw_exit(&hca->state_lock);

	if (ibt_status != IBT_SUCCESS) {
#ifdef DEBUG
		cmn_err(CE_WARN, "rib_conn_to_srv: alloc_rc_channel "
		"failed, ibt_status=%d.", ibt_status);
#endif
		return (RDMA_FAILED);
	}

	/* Connect to the Server */
	(void) bzero(&ret_args, sizeof (ret_args));
	mutex_enter(&qp->cb_lock);
	ibt_status = ibt_open_rc_channel(qp->qp_hdl, IBT_OCHAN_NO_FLAGS,
			IBT_BLOCKING, &chan_args, &ret_args);
	if (ibt_status != IBT_SUCCESS) {
#ifdef DEBUG
		if (rib_debug)
			cmn_err(CE_WARN, "rib_conn_to_srv: open_rc_channel"
				" failed for qp %p, status=%d, "
				"ret_args.rc_status=%d\n",
				(void *)qp, ibt_status, ret_args.rc_status);
#endif
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
	struct sockaddr_in	*sin4;
	struct sockaddr_in6	*sin6;
	ibt_path_attr_t		path_attr;
	ibt_path_info_t		path;
	ibt_status_t		ibt_status;

	ASSERT(raddr->buf != NULL);

	bzero(&path_attr, sizeof (ibt_path_attr_t));
	bzero(&path, sizeof (ibt_path_info_t));

	/*
	 * Conctruct svc name
	 */
	path_attr.pa_sname = kmem_zalloc(IB_SVC_NAME_LEN, KM_SLEEP);
	switch (addr_type) {
	case AF_INET:
		sin4 = (struct sockaddr_in *)raddr->buf;
		(void) inet_ntop(AF_INET, &sin4->sin_addr, path_attr.pa_sname,
		    IB_SVC_NAME_LEN);
		break;

	case AF_INET6:
		sin6 = (struct sockaddr_in6 *)raddr->buf;
		(void) inet_ntop(AF_INET6, &sin6->sin6_addr,
		    path_attr.pa_sname, IB_SVC_NAME_LEN);
		break;

	default:
#ifdef	DEBUG
	    if (rib_debug) {
		cmn_err(CE_WARN, "rib_ping_srv: Address not recognized\n");
	    }
#endif
		kmem_free(path_attr.pa_sname, IB_SVC_NAME_LEN);
		return (RDMA_INVAL);
	}
	(void) strlcat(path_attr.pa_sname, "::NFS", IB_SVC_NAME_LEN);

	ibt_status = ibt_get_paths(rib_stat->ibt_clnt_hdl,
		IBT_PATH_NO_FLAGS, &path_attr, 1, &path, NULL);
	kmem_free(path_attr.pa_sname, IB_SVC_NAME_LEN);
	if (ibt_status != IBT_SUCCESS) {
	    if (rib_debug > 1) {
		cmn_err(CE_WARN, "rib_ping_srv: ibt_get_paths FAILED!"
			" status=%d\n", ibt_status);
	    }
	} else if (path.pi_hca_guid) {
		ASSERT(path.pi_hca_guid == rib_stat->hca->hca_guid);
		*hca = rib_stat->hca;
		return (RDMA_SUCCESS);
	}
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
#ifdef DEBUG
				if (rib_debug > 2)
					cmn_err(CE_WARN, "rib_sendwait: "
					    "timed out qp %p\n", (void *)qp);
#endif
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
#ifdef DEBUG
				if (rib_debug > 2)
					cmn_err(CE_WARN, "rib_sendwait: "
					    "timed out qp %p\n", (void *)qp);
#endif
				wd->cv_sig = 0;		/* no signal needed */
				error = RDMA_TIMEDOUT;
				break;
			case 0:		/* interrupted */
#ifdef DEBUG
				if (rib_debug > 2)
					cmn_err(CE_NOTE, "rib_sendwait:"
					    " interrupted on qp %p\n",
					    (void *)qp);
#endif
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
	int send_sig, int cv_sig)
{
	struct send_wid	*wdesc;
	struct clist	*clp;
	ibt_status_t	ibt_status = IBT_SUCCESS;
	rdma_stat	ret = RDMA_SUCCESS;
	ibt_send_wr_t	tx_wr;
	int		i, nds;
	ibt_wr_ds_t	sgl[DSEG_MAX];
	uint_t		total_msg_size;
	rib_qp_t	*qp = ctoqp(conn);

	ASSERT(cl != NULL);

	bzero(&tx_wr, sizeof (ibt_send_wr_t));

	nds = 0;
	total_msg_size = 0;
	clp = cl;
	while (clp != NULL) {
		if (nds >= DSEG_MAX) {
			cmn_err(CE_WARN, "rib_send_and_wait: DSEG_MAX"
			    " too small!");
			return (RDMA_FAILED);
		}
		sgl[nds].ds_va = clp->c_saddr;
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
	} else {
		tx_wr.wr_flags = IBT_WR_NO_FLAGS;
		wdesc = rib_init_sendwait(msgid, 0, qp);
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
	if (conn->c_state & C_CONNECTED) {
		ibt_status = ibt_post_send(qp->qp_hdl, &tx_wr, 1, NULL);
	}
	if (((conn->c_state & C_CONNECTED) == 0) ||
		ibt_status != IBT_SUCCESS) {
		mutex_exit(&conn->c_lock);
		for (i = 0; i < nds; i++) {
			rib_rbuf_free(conn, SEND_BUFFER,
				(void *)(uintptr_t)wdesc->sbufaddr[i]);
		}
		(void) rib_free_sendwait(wdesc);
#ifdef DEBUG
		if (rib_debug && ibt_status != IBT_SUCCESS)
			cmn_err(CE_WARN, "rib_send_and_wait: ibt_post_send "
				"failed! wr_id %llx on qpn %p, status=%d!",
				(longlong_t)tx_wr.wr_id, (void *)qp,
				ibt_status);
#endif
		return (RDMA_FAILED);
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
#ifdef DEBUG
	    if (rib_debug > 2)
		if (ret != 0) {
		    cmn_err(CE_WARN, "rib_send_and_wait: rib_sendwait "
			"FAILED, rdma stat=%d, wr_id %llx, qp %p!",
			ret, (longlong_t)tx_wr.wr_id, (void *)qp);
		}
#endif
		return (ret);
	    }
	}

	return (RDMA_SUCCESS);
}

rdma_stat
rib_send(CONN *conn, struct clist *cl, uint32_t msgid)
{
	rdma_stat	ret;

	/* send-wait & cv_signal */
	ret = rib_send_and_wait(conn, cl, msgid, 1, 1);

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
	rib_qp_t *qp = ctoqp(conn);

	mutex_enter(&qp->rdlist_lock);
	rd = rdma_done_add(qp, msgid);

	/* No cv_signal (whether send-wait or no-send-wait) */
	ret = rib_send_and_wait(conn, cl, msgid, 1, 0);
	if (ret != RDMA_SUCCESS) {
#ifdef DEBUG
	    cmn_err(CE_WARN, "rib_send_resp: send_and_wait "
		"failed, msgid %u, qp %p", msgid, (void *)qp);
#endif
	    rdma_done_rm(qp, rd);
	    goto done;
	}

	/*
	 * Wait for RDMA_DONE from remote end
	 */
	timout = drv_usectohz(REPLY_WAIT_TIME * 1000000) + ddi_get_lbolt();
	cv_wait_ret = cv_timedwait(&rd->rdma_done_cv, &qp->rdlist_lock,
	    timout);
	rdma_done_rm(qp, rd);
	if (cv_wait_ret < 0) {
#ifdef DEBUG
		if (rib_debug > 1) {
			cmn_err(CE_WARN, "rib_send_resp: RDMA_DONE not"
			    " recv'd for qp %p, xid:%u\n",
			    (void *)qp, msgid);
		}
#endif
		ret = RDMA_TIMEDOUT;
		goto done;
	}

done:
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
		    cmn_err(CE_WARN, "rib_clnt_post: DSEG_MAX too small!");
		    ret = RDMA_FAILED;
		    goto done;
		}
		sgl[nds].ds_va = cl->c_saddr;
		sgl[nds].ds_key = cl->c_smemhandle.mrc_lmr; /* lkey */
		sgl[nds].ds_len = cl->c_len;
		cl = cl->c_next;
		nds++;
	}

	if (nds != 1) {
	    cmn_err(CE_WARN, "rib_clnt_post: nds!=1\n");
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
		cmn_err(CE_WARN, "rib_clnt_post: out of memory");
		ret = RDMA_NORESOURCE;
		goto done;
	}
	rep = rib_addreplylist(qp, msgid);
	if (!rep) {
		cmn_err(CE_WARN, "rib_clnt_post: out of memory");
		rib_free_wid(rwid);
		ret = RDMA_NORESOURCE;
		goto done;
	}

	mutex_enter(&conn->c_lock);
	if (conn->c_state & C_CONNECTED) {
		ibt_status = ibt_post_recv(qp->qp_hdl, &recv_wr, 1, NULL);
	}
	if (((conn->c_state & C_CONNECTED) == 0) ||
		ibt_status != IBT_SUCCESS) {
		mutex_exit(&conn->c_lock);
#ifdef DEBUG
		cmn_err(CE_WARN, "rib_clnt_post: QPN %p failed in "
		    "ibt_post_recv(), msgid=%d, status=%d",
		    (void *)qp,  msgid, ibt_status);
#endif
		rib_free_wid(rwid);
		(void) rib_rem_rep(qp, rep);
		ret = RDMA_FAILED;
		goto done;
	}
	mutex_exit(&conn->c_lock);
	return (RDMA_SUCCESS);

done:
	while (clp != NULL) {
	    rib_rbuf_free(conn, RECV_BUFFER, (void *)(uintptr_t)clp->c_saddr);
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
		    cmn_err(CE_WARN, "rib_svc_post: DSEG_MAX too small!");
		    return (RDMA_FAILED);
		}
		sgl[nds].ds_va = cl->c_saddr;
		sgl[nds].ds_key = cl->c_smemhandle.mrc_lmr; /* lkey */
		sgl[nds].ds_len = cl->c_len;
		cl = cl->c_next;
		nds++;
	}

	if (nds != 1) {
	    cmn_err(CE_WARN, "rib_svc_post: nds!=1\n");
	    rib_rbuf_free(conn, RECV_BUFFER, (caddr_t)(uintptr_t)sgl[0].ds_va);
	    return (RDMA_FAILED);
	}
	bzero(&recv_wr, sizeof (ibt_recv_wr_t));
	recv_wr.wr_nds = nds;
	recv_wr.wr_sgl = sgl;

	s_recvp = rib_init_svc_recv(qp, &sgl[0]);
	/* Use s_recvp's addr as wr id */
	recv_wr.wr_id = (ibt_wrid_t)(uintptr_t)s_recvp;
	mutex_enter(&conn->c_lock);
	if (conn->c_state & C_CONNECTED) {
		ibt_status = ibt_post_recv(qp->qp_hdl, &recv_wr, 1, NULL);
	}
	if (((conn->c_state & C_CONNECTED) == 0) ||
		ibt_status != IBT_SUCCESS) {
		mutex_exit(&conn->c_lock);
#ifdef DEBUG
		cmn_err(CE_WARN, "rib_svc_post: QP %p failed in "
		    "ibt_post_recv(), status=%d",
		    (void *)qp, ibt_status);
#endif
		rib_rbuf_free(conn, RECV_BUFFER,
			(caddr_t)(uintptr_t)sgl[0].ds_va);
		(void) rib_free_svc_recv(s_recvp);
		return (RDMA_FAILED);
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
			    rep->status == (uint_t)REPLY_WAIT);

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
#ifdef DEBUG
		cmn_err(CE_WARN, "rib_recv: no matching reply for "
		    "xid %u, qp %p\n", msgid, (void *)qp);
#endif
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
	int		nds;
	int		cv_sig;
	ibt_wr_ds_t	sgl[DSEG_MAX];
	struct send_wid	*wdesc;
	ibt_status_t	ibt_status;
	rdma_stat	ret = RDMA_SUCCESS;
	rib_qp_t	*qp = ctoqp(conn);

	if (cl == NULL) {
		cmn_err(CE_WARN, "rib_write: NULL clist\n");
		return (RDMA_FAILED);
	}

	bzero(&tx_wr, sizeof (ibt_send_wr_t));
	/*
	 * Remote address is at the head chunk item in list.
	 */
	tx_wr.wr.rc.rcwr.rdma.rdma_raddr = cl->c_daddr;
	tx_wr.wr.rc.rcwr.rdma.rdma_rkey = cl->c_dmemhandle.mrc_rmr; /* rkey */

	nds = 0;
	while (cl != NULL) {
		if (nds >= DSEG_MAX) {
			cmn_err(CE_WARN, "rib_write: DSEG_MAX too small!");
			return (RDMA_FAILED);
		}
		sgl[nds].ds_va = cl->c_saddr;
		sgl[nds].ds_key = cl->c_smemhandle.mrc_lmr; /* lkey */
		sgl[nds].ds_len = cl->c_len;
		cl = cl->c_next;
		nds++;
	}

	if (wait) {
		tx_wr.wr_flags = IBT_WR_SEND_SIGNAL;
		cv_sig = 1;
	} else {
		tx_wr.wr_flags = IBT_WR_NO_FLAGS;
		cv_sig = 0;
	}

	wdesc = rib_init_sendwait(0, cv_sig, qp);
	tx_wr.wr_id = (ibt_wrid_t)(uintptr_t)wdesc;
	tx_wr.wr_opcode = IBT_WRC_RDMAW;
	tx_wr.wr_trans = IBT_RC_SRV;
	tx_wr.wr_nds = nds;
	tx_wr.wr_sgl = sgl;

	mutex_enter(&conn->c_lock);
	if (conn->c_state & C_CONNECTED) {
		ibt_status = ibt_post_send(qp->qp_hdl, &tx_wr, 1, NULL);
	}
	if (((conn->c_state & C_CONNECTED) == 0) ||
		ibt_status != IBT_SUCCESS) {
		mutex_exit(&conn->c_lock);
		(void) rib_free_sendwait(wdesc);
		return (RDMA_FAILED);
	}
	mutex_exit(&conn->c_lock);

	/*
	 * Wait for send to complete
	 */
	if (wait) {
		ret = rib_sendwait(qp, wdesc);
		if (ret != 0) {
			return (ret);
		}
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
	int		nds;
	int		cv_sig;
	ibt_wr_ds_t	sgl[DSEG_MAX];	/* is 2 sufficient? */
	struct send_wid	*wdesc;
	ibt_status_t	ibt_status = IBT_SUCCESS;
	rdma_stat	ret = RDMA_SUCCESS;
	rib_qp_t	*qp = ctoqp(conn);

	if (cl == NULL) {
		cmn_err(CE_WARN, "rib_read: NULL clist\n");
		return (RDMA_FAILED);
	}

	bzero(&rx_wr, sizeof (ibt_send_wr_t));
	/*
	 * Remote address is at the head chunk item in list.
	 */
	rx_wr.wr.rc.rcwr.rdma.rdma_raddr = cl->c_saddr;
	rx_wr.wr.rc.rcwr.rdma.rdma_rkey = cl->c_smemhandle.mrc_rmr; /* rkey */

	nds = 0;
	while (cl != NULL) {
		if (nds >= DSEG_MAX) {
			cmn_err(CE_WARN, "rib_read: DSEG_MAX too small!");
			return (RDMA_FAILED);
		}
		sgl[nds].ds_va = cl->c_daddr;
		sgl[nds].ds_key = cl->c_dmemhandle.mrc_lmr; /* lkey */
		sgl[nds].ds_len = cl->c_len;
		cl = cl->c_next;
		nds++;
	}

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
	rx_wr.wr_nds = nds;
	rx_wr.wr_sgl = sgl;

	mutex_enter(&conn->c_lock);
	if (conn->c_state & C_CONNECTED) {
		ibt_status = ibt_post_send(qp->qp_hdl, &rx_wr, 1, NULL);
	}
	if (((conn->c_state & C_CONNECTED) == 0) ||
		ibt_status != IBT_SUCCESS) {
		mutex_exit(&conn->c_lock);
#ifdef DEBUG
		if (rib_debug && ibt_status != IBT_SUCCESS)
			cmn_err(CE_WARN, "rib_read: FAILED post_sending RDMAR"
				" wr_id %llx on qp %p, status=%d",
				(longlong_t)rx_wr.wr_id, (void *)qp,
				ibt_status);
#endif
		(void) rib_free_sendwait(wdesc);
		return (RDMA_FAILED);
	}
	mutex_exit(&conn->c_lock);

	/*
	 * Wait for send to complete
	 */
	if (wait) {
		ret = rib_sendwait(qp, wdesc);
		if (ret != 0) {
			return (ret);
		}
	}

	return (RDMA_SUCCESS);
}

int
is_for_ipv4(ibt_ar_t *result)
{
	int	i, size = sizeof (struct in_addr);
	uint8_t	zero = 0;

	for (i = 0; i < (ATS_AR_DATA_LEN - size); i++)
		zero |= result->ar_data[i];
	return (zero == 0);
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
	rdma_buf_t	rdbuf;
	void		*buf = NULL;
	ibt_cm_req_rcv_t	cm_req_rcv;
	CONN		*conn;
	ibt_status_t ibt_status;
	ibt_ar_t	ar_query, ar_result;
	ib_gid_t	sgid;


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
#ifdef DEBUG
			cmn_err(CE_WARN, "rib_srv_cm_handler: "
			    "create_channel failed %d", status);
#endif
			return (IBT_CM_REJECT);
		}
		cm_req_rcv = event->cm_event.req;

#ifdef DEBUG
		if (rib_debug > 2) {
		    cmn_err(CE_NOTE, "rib_srv_cm_handler: "
			"server recv'ed IBT_CM_EVENT_REQ_RCV\n");
		    cmn_err(CE_NOTE, "\t\t SID:%llx\n",
				(longlong_t)cm_req_rcv.req_service_id);
		    cmn_err(CE_NOTE, "\t\t Local Port:%d\n",
				cm_req_rcv.req_prim_hca_port);
		    cmn_err(CE_NOTE,
			"\t\t Remote GID:(prefix:%llx,guid:%llx)\n",
			(longlong_t)cm_req_rcv.req_prim_addr.av_dgid.gid_prefix,
			(longlong_t)cm_req_rcv.req_prim_addr.av_dgid.gid_guid);
		    cmn_err(CE_NOTE, "\t\t Local GID:(prefix:%llx,guid:%llx)\n",
			(longlong_t)cm_req_rcv.req_prim_addr.av_sgid.gid_prefix,
			(longlong_t)cm_req_rcv.req_prim_addr.av_sgid.gid_guid);
		    cmn_err(CE_NOTE, "\t\t Remote QPN:%u\n",
			cm_req_rcv.req_remote_qpn);
		    cmn_err(CE_NOTE, "\t\t Remote Q_Key:%x\n",
			cm_req_rcv.req_remote_qkey);
		    cmn_err(CE_NOTE, "\t\t Local QP %p (qp_hdl=%p)\n",
			(void *)qp, (void *)qp->qp_hdl);
		}

		if (rib_debug > 2) {
		    ibt_rc_chan_query_attr_t	chan_attrs;

		    if (ibt_query_rc_channel(qp->qp_hdl, &chan_attrs)
			== IBT_SUCCESS) {
			cmn_err(CE_NOTE, "rib_svc_cm_handler: qp %p in "
			    "CEP state %d\n", (void *)qp, chan_attrs.rc_state);
		    }
		}
#endif

		ret_args->cm_ret.rep.cm_channel = qp->qp_hdl;
		ret_args->cm_ret.rep.cm_rdma_ra_out = 1;
		ret_args->cm_ret.rep.cm_rdma_ra_in = 1;
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
			cmn_err(CE_WARN, "rib_svc_cm_handler: "
			    "No RECV_BUFFER buf!\n");
			(void) rib_disconnect_channel(conn, NULL);
			return (IBT_CM_REJECT);
		    }

		    bzero(&cl, sizeof (cl));
		    cl.c_saddr = (uintptr_t)rdbuf.addr;
		    cl.c_len = rdbuf.len;
		    cl.c_smemhandle.mrc_lmr = rdbuf.handle.mrc_lmr; /* lkey */
		    cl.c_next = NULL;
		    status = rib_post_recv(conn, &cl);
		    if (status != RDMA_SUCCESS) {
			cmn_err(CE_WARN, "rib_srv_cm_handler: failed "
			    "posting RPC_REQ buf to qp %p!", (void *)qp);
			(void) rib_disconnect_channel(conn, NULL);
			return (IBT_CM_REJECT);
		    }
		}
		(void) rib_add_connlist(conn, &hca->srv_conn_list);

		/*
		 * Get the address translation service record from ATS
		 */
		rw_enter(&hca->state_lock, RW_READER);
		if (hca->state == HCA_DETACHED) {
		    rw_exit(&hca->state_lock);
		    return (IBT_CM_REJECT);
		}
		rw_exit(&hca->state_lock);

		for (i = 0; i < hca->hca_nports; i++) {
		    ibt_status = ibt_get_port_state(hca->hca_hdl, i+1,
					&sgid, NULL);
		    if (ibt_status != IBT_SUCCESS) {
			if (rib_debug) {
			    cmn_err(CE_WARN, "rib_srv_cm_handler: "
				"ibt_get_port_state FAILED!"
				"status = %d\n", ibt_status);
			}
		    } else {
			/*
			 * do ibt_query_ar()
			 */
			bzero(&ar_query, sizeof (ar_query));
			bzero(&ar_result, sizeof (ar_result));
			ar_query.ar_gid = cm_req_rcv.req_prim_addr.av_dgid;
			ar_query.ar_pkey = event->cm_event.req.req_pkey;
			ibt_status = ibt_query_ar(&sgid, &ar_query,
							&ar_result);
			if (ibt_status != IBT_SUCCESS) {
			    if (rib_debug) {
				cmn_err(CE_WARN, "rib_srv_cm_handler: "
				    "ibt_query_ar FAILED!"
				    "status = %d\n", ibt_status);
			    }
			} else {
			    conn = qptoc(qp);

			    if (is_for_ipv4(&ar_result)) {
				struct sockaddr_in *s;
				int sin_size = sizeof (struct sockaddr_in);
				int in_size = sizeof (struct in_addr);
				uint8_t	*start_pos;

				conn->c_raddr.maxlen =
					conn->c_raddr.len = sin_size;
				conn->c_raddr.buf = kmem_zalloc(sin_size,
						KM_SLEEP);
				s = (struct sockaddr_in *)conn->c_raddr.buf;
				s->sin_family = AF_INET;
				/*
				 * For IPv4,  the IP addr is stored in
				 * the last four bytes of ar_data.
				 */
				start_pos = ar_result.ar_data +
					ATS_AR_DATA_LEN - in_size;
				bcopy(start_pos, &s->sin_addr, in_size);
				if (rib_debug > 1) {
				    char print_addr[INET_ADDRSTRLEN];

				    bzero(print_addr, INET_ADDRSTRLEN);
				    (void) inet_ntop(AF_INET, &s->sin_addr,
						print_addr, INET_ADDRSTRLEN);
				    cmn_err(CE_NOTE, "rib_srv_cm_handler: "
					"remote clnt_addr: %s\n", print_addr);
				}
			    } else {
				struct sockaddr_in6 *s6;
				int sin6_size = sizeof (struct sockaddr_in6);

				conn->c_raddr.maxlen =
					conn->c_raddr.len = sin6_size;
				conn->c_raddr.buf = kmem_zalloc(sin6_size,
					KM_SLEEP);

				s6 = (struct sockaddr_in6 *)conn->c_raddr.buf;
				s6->sin6_family = AF_INET6;
				/* sin6_addr is stored in ar_data */
				bcopy(ar_result.ar_data, &s6->sin6_addr,
					sizeof (struct in6_addr));
				if (rib_debug > 1) {
				    char print_addr[INET6_ADDRSTRLEN];

				    bzero(print_addr, INET6_ADDRSTRLEN);
				    (void) inet_ntop(AF_INET6, &s6->sin6_addr,
						print_addr, INET6_ADDRSTRLEN);
				    cmn_err(CE_NOTE, "rib_srv_cm_handler: "
					"remote clnt_addr: %s\n", print_addr);
				}
			    }
			    return (IBT_CM_ACCEPT);
			}
		    }
		}
		if (rib_debug > 1) {
		    cmn_err(CE_WARN, "rib_srv_cm_handler: "
				"address record query failed!");
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
			conn->c_state = C_ERROR;

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
#ifdef DEBUG
			if (rib_debug)
				cmn_err(CE_NOTE, "rib_srv_cm_handler: "
					" (CONN_CLOSED) channel disconnected");
#endif
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
	    return (IBT_CM_REJECT);
	}

	/* accept all other CM messages (i.e. let the CM handle them) */
	return (IBT_CM_ACCEPT);
}

static rdma_stat
rib_register_ats(rib_hca_t *hca)
{
	ibt_hca_portinfo_t	*port_infop;
	uint_t			port_size;
	uint_t			pki, i, num_ports, nbinds;
	ibt_status_t		ibt_status;
	rib_service_t		*new_service, *temp_srv;
	rpcib_ats_t		*atsp;
	rpcib_ibd_insts_t	ibds;
	ib_pkey_t		pkey;
	ibt_ar_t		ar;	/* address record */

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
#ifdef DEBUG
	    if (rib_debug) {
		cmn_err(CE_NOTE, "rib_register_ats: FAILED in "
		    "ibt_query_hca_ports, status = %d\n", ibt_status);
	    }
#endif
		return (RDMA_FAILED);
	}

#ifdef	DEBUG
	if (rib_debug > 1) {
		cmn_err(CE_NOTE, "rib_register_ats: Ports detected "
		    "%d\n", num_ports);

		for (i = 0; i < num_ports; i++) {
			if (port_infop[i].p_linkstate != IBT_PORT_ACTIVE) {
				cmn_err(CE_WARN, "rib_register_ats "
				    "Port #: %d INACTIVE\n", i+1);
			} else if (port_infop[i].p_linkstate ==
			    IBT_PORT_ACTIVE) {
				cmn_err(CE_NOTE, "rib_register_ats "
				    "Port #: %d ACTIVE\n", i+1);
			}
		}
	}
#endif

	ibds.rib_ibd_alloc = N_IBD_INSTANCES;
	ibds.rib_ibd_cnt = 0;
	ibds.rib_ats = (rpcib_ats_t *)kmem_zalloc(ibds.rib_ibd_alloc *
			sizeof (rpcib_ats_t), KM_SLEEP);
	rib_get_ibd_insts(&ibds);

	if (ibds.rib_ibd_cnt == 0) {
	    kmem_free(ibds.rib_ats, ibds.rib_ibd_alloc *
				sizeof (rpcib_ats_t));
	    ibt_free_portinfo(port_infop, port_size);
	    return (RDMA_FAILED);
	}

	/*
	 * Get the IP addresses of active ports and
	 * register them with ATS.  IPv4 addresses
	 * have precedence over IPv6 addresses.
	 */
	if (get_ibd_ipaddr(&ibds) != 0) {
#ifdef	DEBUG
	    if (rib_debug > 1) {
		cmn_err(CE_WARN, "rib_register_ats: "
		    "get_ibd_ipaddr failed");
	    }
#endif
	    kmem_free(ibds.rib_ats, ibds.rib_ibd_alloc *
				sizeof (rpcib_ats_t));
	    ibt_free_portinfo(port_infop, port_size);
	    return (RDMA_FAILED);
	}

	/*
	 * Start ATS registration for active ports on this HCA.
	 */
	rw_enter(&hca->service_list_lock, RW_WRITER);
	nbinds = 0;
	new_service = NULL;
	for (i = 0; i < num_ports; i++) {
		if (port_infop[i].p_linkstate != IBT_PORT_ACTIVE)
			continue;

	    for (pki = 0; pki < port_infop[i].p_pkey_tbl_sz; pki++) {
		pkey = port_infop[i].p_pkey_tbl[pki];
		if ((pkey & IBSRM_HB) && (pkey != IB_PKEY_INVALID_FULL)) {
		    ar.ar_gid = port_infop[i].p_sgid_tbl[0];
		    ar.ar_pkey = pkey;
		    atsp = get_ibd_entry(&ar.ar_gid, pkey, &ibds);
		    if (atsp == NULL)
			continue;
		/*
		 * store the sin[6]_addr in ar_data
		 */
		    (void) bzero(ar.ar_data, ATS_AR_DATA_LEN);
		    if (atsp->ras_inet_type == AF_INET) {
			uint8_t *start_pos;

			/*
			 * The ipv4 addr goes into the last
			 * four bytes of ar_data.
			 */
			start_pos = ar.ar_data + ATS_AR_DATA_LEN -
				sizeof (struct in_addr);
			bcopy(&atsp->ras_sin.sin_addr, start_pos,
				sizeof (struct in_addr));
		    } else if (atsp->ras_inet_type == AF_INET6) {
			bcopy(&atsp->ras_sin6.sin6_addr, ar.ar_data,
				sizeof (struct in6_addr));
		    } else
			continue;

		    ibt_status = ibt_register_ar(hca->ibt_clnt_hdl, &ar);
		    if (ibt_status == IBT_SUCCESS) {
#ifdef	DEBUG
			if (rib_debug > 1) {
				cmn_err(CE_WARN, "rib_register_ats: "
				    "ibt_register_ar OK on port %d", i+1);
			}
#endif
			/*
			 * Allocate and prepare a service entry
			 */
			new_service = kmem_zalloc(sizeof (rib_service_t),
				KM_SLEEP);
			new_service->srv_port = i + 1;
			new_service->srv_ar = ar;
			new_service->srv_next = NULL;

			/*
			 * Add to the service list for this HCA
			 */
			new_service->srv_next = hca->ats_list;
			hca->ats_list = new_service;
			new_service = NULL;
			nbinds ++;
		    } else {
#ifdef	DEBUG
			if (rib_debug > 1) {
			    cmn_err(CE_WARN, "rib_register_ats: "
			    "ibt_register_ar FAILED on port %d", i+1);
			}
#endif
		    }
		}
	    }
	}

#ifdef	DEBUG
	if (rib_debug > 1) {
		for (temp_srv = hca->ats_list; temp_srv != NULL;
			temp_srv = temp_srv->srv_next) {
				cmn_err(CE_NOTE, "Service: ATS, active on"
					" port: %d\n", temp_srv->srv_port);
		}
	}
#endif

	rw_exit(&hca->service_list_lock);
	kmem_free(ibds.rib_ats, ibds.rib_ibd_alloc * sizeof (rpcib_ats_t));
	ibt_free_portinfo(port_infop, port_size);

	if (nbinds == 0) {
#ifdef	DEBUG
	if (rib_debug > 1) {
		cmn_err(CE_WARN, "rib_register_ats FAILED!\n");
	}
#endif
		return (RDMA_FAILED);
	}
	return (RDMA_SUCCESS);
}

static rdma_stat
rib_register_service(rib_hca_t *hca, int service_type)
{
	ibt_srv_desc_t		sdesc;
	ibt_srv_bind_t		sbind;
	ibt_hca_portinfo_t	*port_infop;
	ib_svc_id_t		srv_id;
	ibt_srv_hdl_t		srv_hdl;
	uint_t			port_size;
	uint_t			pki, i, j, num_ports, nbinds;
	ibt_status_t		ibt_status;
	char			**addrs;
	int			addr_count;
	rib_service_t		*new_service, *temp_srv;
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
#ifdef DEBUG
		cmn_err(CE_NOTE, "rib_register_service: FAILED in "
		    "ibt_query_hca_ports, status = %d\n", ibt_status);
#endif
		return (RDMA_FAILED);
	}

#ifdef	DEBUG
	if (rib_debug > 1) {
		cmn_err(CE_NOTE, "rib_register_service: Ports detected "
		    "%d\n", num_ports);

		for (i = 0; i < num_ports; i++) {
			if (port_infop[i].p_linkstate != IBT_PORT_ACTIVE) {
				cmn_err(CE_WARN, "rib_register_service "
				    "Port #: %d INACTIVE\n", i+1);
			} else if (port_infop[i].p_linkstate ==
			    IBT_PORT_ACTIVE) {
				cmn_err(CE_NOTE, "rib_register_service "
				    "Port #: %d ACTIVE\n", i+1);
			}
		}
	}
#endif
	/*
	 * Get all the IP addresses on this system to register the
	 * given "service type" on all DNS recognized IP addrs.
	 * Each service type such as NFS will have all the systems
	 * IP addresses as its different names. For now the only
	 * type of service we support in RPCIB is NFS.
	 */
	addrs = get_ip_addrs(&addr_count);
	if (addrs == NULL) {
#ifdef DEBUG
		if (rib_debug) {
		    cmn_err(CE_WARN, "rib_register_service: "
			"get_ip_addrs failed\n");
		}
#endif
		ibt_free_portinfo(port_infop, port_size);
		return (RDMA_FAILED);
	}

#ifdef	DEBUG
	if (rib_debug > 1) {
		for (i = 0; i < addr_count; i++)
			cmn_err(CE_NOTE, "addr %d: %s\n", i, addrs[i]);
	}
#endif

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
	for (j = 1; j < addr_count; j++) {
	    (void) bzero(&srv_id, sizeof (ib_svc_id_t));
	    (void) bzero(&srv_hdl, sizeof (ibt_srv_hdl_t));
	    (void) bzero(&sdesc, sizeof (ibt_srv_desc_t));

	    sdesc.sd_handler = rib_srv_cm_handler;
	    sdesc.sd_flags = 0;

	    ibt_status = ibt_register_service(hca->ibt_clnt_hdl,
			    &sdesc, 0, 1, &srv_hdl, &srv_id);
	    if (ibt_status != IBT_SUCCESS) {
#ifdef DEBUG
		if (rib_debug) {
		    cmn_err(CE_WARN, "rib_register_service: "
			"ibt_register_service FAILED, status "
			"= %d\n", ibt_status);
		}
#endif
		/*
		 * No need to go on, since we failed to obtain
		 * a srv_id and srv_hdl. Move on to the next
		 * IP addr as a service name.
		 */
		continue;
	    }
	    for (i = 0; i < num_ports; i++) {
		if (port_infop[i].p_linkstate != IBT_PORT_ACTIVE)
			continue;

		for (pki = 0; pki < port_infop[i].p_pkey_tbl_sz; pki++) {
		    pkey = port_infop[i].p_pkey_tbl[pki];
		    if ((pkey & IBSRM_HB) && (pkey != IB_PKEY_INVALID_FULL)) {

			/*
			 * Allocate and prepare a service entry
			 */
			new_service = kmem_zalloc(1 * sizeof (rib_service_t),
			    KM_SLEEP);
			new_service->srv_type = service_type;
			new_service->srv_port = i + 1;
			new_service->srv_id = srv_id;
			new_service->srv_hdl = srv_hdl;
			new_service->srv_sbind_hdl = kmem_zalloc(1 *
			    sizeof (ibt_sbind_hdl_t), KM_SLEEP);

			new_service->srv_name = kmem_zalloc(IB_SVC_NAME_LEN,
			    KM_SLEEP);
			(void) bcopy(addrs[j], new_service->srv_name,
			    IB_SVC_NAME_LEN);
			(void) strlcat(new_service->srv_name, "::NFS",
				IB_SVC_NAME_LEN);
			new_service->srv_next = NULL;

			/*
			 * Bind the service, specified by the IP address,
			 * to the port/pkey using the srv_hdl returned
			 * from ibt_register_service().
			 */
			(void) bzero(&sbind, sizeof (ibt_srv_bind_t));
			sbind.sb_pkey = pkey;
			sbind.sb_lease = 0xFFFFFFFF;
			sbind.sb_key[0] = NFS_SEC_KEY0;
			sbind.sb_key[1] = NFS_SEC_KEY1;
			sbind.sb_name = new_service->srv_name;

#ifdef	DEBUG
			if (rib_debug > 1) {
				cmn_err(CE_NOTE, "rib_register_service: "
				    "binding service using name: %s\n",
				    sbind.sb_name);
			}
#endif
			ibt_status = ibt_bind_service(srv_hdl,
			    port_infop[i].p_sgid_tbl[0], &sbind, rib_stat,
			    new_service->srv_sbind_hdl);
			if (ibt_status != IBT_SUCCESS) {
#ifdef	DEBUG
			    if (rib_debug) {
				cmn_err(CE_WARN, "rib_register_service: FAILED"
				    " in ibt_bind_service, status = %d\n",
				    ibt_status);
			    }
#endif
				kmem_free(new_service->srv_sbind_hdl,
				    sizeof (ibt_sbind_hdl_t));
				kmem_free(new_service->srv_name,
				    IB_SVC_NAME_LEN);
				kmem_free(new_service,
				    sizeof (rib_service_t));
				new_service = NULL;
				continue;
			}
#ifdef	DEBUG
			if (rib_debug > 1) {
				if (ibt_status == IBT_SUCCESS)
					cmn_err(CE_NOTE, "rib_regstr_service: "
					    "Serv: %s REGISTERED on port: %d",
					    sbind.sb_name, i+1);
			}
#endif
			/*
			 * Add to the service list for this HCA
			 */
			new_service->srv_next = hca->service_list;
			hca->service_list = new_service;
			new_service = NULL;
			nbinds ++;
		    }
		}
	    }
	}
	rw_exit(&hca->service_list_lock);

#ifdef	DEBUG
	if (rib_debug > 1) {
		/*
		 * Change this print to a more generic one, as rpcib
		 * is supposed to handle multiple service types.
		 */
		for (temp_srv = hca->service_list; temp_srv != NULL;
			temp_srv = temp_srv->srv_next) {
				cmn_err(CE_NOTE, "NFS-IB, active on port:"
					" %d\n"
					"Using name: %s", temp_srv->srv_port,
					temp_srv->srv_name);
		}
	}
#endif

	ibt_free_portinfo(port_infop, port_size);
	for (i = 0; i < addr_count; i++) {
		if (addrs[i])
			kmem_free(addrs[i], IB_SVC_NAME_LEN);
	}
	kmem_free(addrs, addr_count * sizeof (char *));

	if (nbinds == 0) {
#ifdef	DEBUG
	    if (rib_debug) {
		cmn_err(CE_WARN, "rib_register_service: "
		    "bind_service FAILED!\n");
	    }
#endif
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
	 * Register the Address translation service
	 */
	mutex_enter(&rib_stat->open_hca_lock);
	if (ats_running == 0) {
		if (rib_register_ats(rib_stat->hca) != RDMA_SUCCESS) {
#ifdef	DEBUG
		    if (rib_debug) {
			cmn_err(CE_WARN,
			    "rib_listen(): ats registration failed!");
		    }
#endif
		    mutex_exit(&rib_stat->open_hca_lock);
		    return;
		} else {
			ats_running = 1;
		}
	}
	mutex_exit(&rib_stat->open_hca_lock);

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
	ibt_status_t   		ibt_status;

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

		    ibt_status = ibt_unbind_all_services(to_remove->srv_hdl);
		    if (ibt_status != IBT_SUCCESS) {
			cmn_err(CE_WARN, "rib_listen_stop: "
			    "ibt_unbind_all_services FAILED"
				" status: %d\n", ibt_status);
		    }

		    ibt_status =
			ibt_deregister_service(hca->ibt_clnt_hdl,
				to_remove->srv_hdl);
		    if (ibt_status != IBT_SUCCESS) {
			cmn_err(CE_WARN, "rib_listen_stop: "
			    "ibt_deregister_service FAILED"
				" status: %d\n", ibt_status);
		    }

#ifdef	DEBUG
		    if (rib_debug > 1) {
			if (ibt_status == IBT_SUCCESS)
				cmn_err(CE_NOTE, "rib_listen_stop: "
				    "Successfully stopped and"
				    " UNREGISTERED service: %s\n",
				    to_remove->srv_name);
		    }
#endif
		}
		kmem_free(to_remove->srv_name, IB_SVC_NAME_LEN);
		kmem_free(to_remove->srv_sbind_hdl,
			sizeof (ibt_sbind_hdl_t));

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
		mutex_exit(&qp->replylist_lock);
		cmn_err(CE_WARN, "rib_addreplylist: no memory\n");
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
	if (rib_debug > 1)
	    cmn_err(CE_NOTE, "rib_addreplylist: qp:%p, rep_list_size:%d\n",
		(void *)qp, qp->rep_list_size);
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
	if (rib_debug > 1)
	    cmn_err(CE_NOTE, "rib_remreply: qp:%p, rep_list_size:%d\n",
		(void *)qp, qp->rep_list_size);

	kmem_free(rep, sizeof (*rep));

	return (0);
}

rdma_stat
rib_registermem(CONN *conn, caddr_t buf, uint_t buflen,
	struct mrc *buf_handle)
{
	ibt_mr_hdl_t	mr_hdl = NULL;	/* memory region handle */
	ibt_mr_desc_t	mr_desc;	/* vaddr, lkey, rkey */
	rdma_stat	status;
	rib_hca_t	*hca = (ctoqp(conn))->hca;

	/*
	 * Note: ALL buffer pools use the same memory type RDMARW.
	 */
	status = rib_reg_mem(hca, buf, buflen, 0, &mr_hdl, &mr_desc);
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
rib_reg_mem(rib_hca_t *hca, caddr_t buf, uint_t size, ibt_mr_flags_t spec,
	ibt_mr_hdl_t *mr_hdlp, ibt_mr_desc_t *mr_descp)
{
	ibt_mr_attr_t	mem_attr;
	ibt_status_t	ibt_status;

	mem_attr.mr_vaddr = (uintptr_t)buf;
	mem_attr.mr_len = (ib_msglen_t)size;
	mem_attr.mr_as = NULL;
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
		cmn_err(CE_WARN, "rib_reg_mem: ibt_register_mr "
			"(spec:%d) failed for addr %llX, status %d",
			spec, (longlong_t)mem_attr.mr_vaddr, ibt_status);
		return (RDMA_FAILED);
	}
	return (RDMA_SUCCESS);
}

rdma_stat
rib_registermemsync(CONN *conn, caddr_t buf, uint_t buflen,
	struct mrc *buf_handle, RIB_SYNCMEM_HANDLE *sync_handle)
{
	ibt_mr_hdl_t	mr_hdl = NULL;	/* memory region handle */
	ibt_mr_desc_t	mr_desc;	/* vaddr, lkey, rkey */
	rdma_stat	status;
	rib_hca_t	*hca = (ctoqp(conn))->hca;

	/*
	 * Non-coherent memory registration.
	 */
	status = rib_reg_mem(hca, buf, buflen, IBT_MR_NONCOHERENT, &mr_hdl,
			&mr_desc);
	if (status == RDMA_SUCCESS) {
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
		RIB_SYNCMEM_HANDLE sync_handle)
{
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
#ifdef DEBUG
		cmn_err(CE_WARN, "rib_syncmem: ibt_sync_mr failed with %d\n",
			status);
#endif
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
		/* mem_attr.mr_flags |= IBT_MR_ENABLE_WINDOW_BIND; */
		bp->rsize = RPC_MSG_SZ;
		break;
	    case RECV_BUFFER:
		mem_attr.mr_flags = IBT_MR_SLEEP | IBT_MR_ENABLE_LOCAL_WRITE;
		/* mem_attr.mr_flags |= IBT_MR_ENABLE_WINDOW_BIND; */
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
			hca->pd_hdl, &mem_attr, &rbp->mr_hdl[i],
			&rbp->mr_desc[i]);
		if (ibt_status != IBT_SUCCESS) {
		    for (j = 0; j < i; j++) {
			(void) ibt_deregister_mr(hca->hca_hdl, rbp->mr_hdl[j]);
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
		cmn_err(CE_WARN, "rib_rbuf_alloc: No free buffers!");
		mutex_exit(&bp->buflock);
		return (NULL);
	}

	/* XXXX put buf, rdbuf->handle.mrc_rmr, ... in one place. */
	buf = bp->buflist[bp->buffree];
	rdbuf->addr = buf;
	rdbuf->len = bp->rsize;
	for (i = bp->numelems - 1; i >= 0; i--) {
	    if ((ib_vaddr_t)(uintptr_t)buf == rbp->mr_desc[i].md_vaddr) {
		rdbuf->handle.mrc_rmr = (uint32_t)rbp->mr_desc[i].md_rkey;
		rdbuf->handle.mrc_linfo = (uintptr_t)rbp->mr_hdl[i];
		rdbuf->handle.mrc_lmr = (uint32_t)rbp->mr_desc[i].md_lkey;
		bp->buffree--;
		if (rib_debug > 1)
		    cmn_err(CE_NOTE, "rib_rbuf_alloc: %d free bufs "
			"(type %d)\n", bp->buffree+1, ptype);

		mutex_exit(&bp->buflock);

		return (buf);
	    }
	}
	cmn_err(CE_WARN, "rib_rbuf_alloc: NO matching buf %p of "
		"type %d found!", buf, ptype);
	mutex_exit(&bp->buflock);

	return (NULL);
}

static void
rib_reg_buf_free(CONN *conn, rdma_buf_t *rdbuf)
{

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
		cmn_err(CE_WARN, "rib_rbuf_free: One (type %d) "
			"too many frees!", ptype);
		bp->buffree--;
	} else {
		bp->buflist[bp->buffree] = buf;
		if (rib_debug > 1)
		    cmn_err(CE_NOTE, "rib_rbuf_free: %d free bufs "
			"(type %d)\n", bp->buffree+1, ptype);
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
 * in four states - C_CONN_PEND, or C_CONNECTED, or C_ERROR or
 * C_DISCONN_PEND state. No C_IDLE state.
 * C_CONN_PEND state: Connection establishment in progress to the server.
 * C_CONNECTED state: A connection when created is in C_CONNECTED state.
 * It has an RC channel associated with it. ibt_post_send/recv are allowed
 * only in this state.
 * C_ERROR state: A connection transitions to this state when WRs on the
 * channel are completed in error or an IBT_CM_EVENT_CONN_CLOSED event
 * happens on the channel or a IBT_HCA_DETACH_EVENT occurs on the HCA.
 * C_DISCONN_PEND state: When a connection is in C_ERROR state and when
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

again:
	rw_enter(&hca->cl_conn_list.conn_lock, RW_READER);
	cn = hca->cl_conn_list.conn_hd;
	while (cn != NULL) {
		/*
		 * First, clear up any connection in the ERROR state
		 */
		mutex_enter(&cn->c_lock);
		if (cn->c_state == C_ERROR) {
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
		} else if (cn->c_state == C_DISCONN_PEND) {
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

	status = rib_chk_srv_ats(hca, svcaddr, addr_type, &path);
	if (status != RDMA_SUCCESS) {
#ifdef DEBUG
		if (rib_debug) {
			cmn_err(CE_WARN, "rib_conn_get: "
				"No server ATS record!");
		}
#endif
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
	status = rib_conn_to_srv(hca, qp, &path);
	mutex_enter(&cn->c_lock);
	if (status == RDMA_SUCCESS) {
		cn->c_state = C_CONNECTED;
		*conn = cn;
	} else {
		cn->c_state = C_ERROR;
		cn->c_ref--;
#ifdef DEBUG
		if (rib_debug) {
			cmn_err(CE_WARN, "rib_conn_get: FAILED creating"
			    " a channel!");
		}
#endif
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
	 * If a conn is C_ERROR, close the channel.
	 * If it's CONNECTED, keep it that way.
	 */
	if (conn->c_ref == 0 && (conn->c_state &  C_ERROR)) {
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
	if (rib_debug > 1) {
	    cmn_err(CE_WARN, "rdma_done_notify: "
		"No matching xid for %u, qp %p\n", xid, (void *)qp);
	}
}

rpcib_ats_t *
get_ibd_entry(ib_gid_t *gid, ib_pkey_t pkey, rpcib_ibd_insts_t *ibds)
{
	rpcib_ats_t		*atsp;
	int			i;

	for (i = 0, atsp = ibds->rib_ats; i < ibds->rib_ibd_cnt; i++, atsp++) {
		if (atsp->ras_port_gid.gid_prefix == gid->gid_prefix &&
		    atsp->ras_port_gid.gid_guid == gid->gid_guid &&
		    atsp->ras_pkey == pkey) {
			return (atsp);
		}
	}
	return (NULL);
}

int
rib_get_ibd_insts_cb(dev_info_t *dip, void *arg)
{
	rpcib_ibd_insts_t *ibds = (rpcib_ibd_insts_t *)arg;
	rpcib_ats_t	*atsp;
	ib_pkey_t	pkey;
	uint8_t		port;
	ib_guid_t	hca_guid;
	ib_gid_t	port_gid;

	if (i_ddi_devi_attached(dip) &&
	    (strcmp(ddi_node_name(dip), "ibport") == 0) &&
	    (strstr(ddi_get_name_addr(dip), "ipib") != NULL)) {

		if (ibds->rib_ibd_cnt >= ibds->rib_ibd_alloc) {
		    rpcib_ats_t	*tmp;

		    tmp = (rpcib_ats_t *)kmem_zalloc((ibds->rib_ibd_alloc +
			N_IBD_INSTANCES) * sizeof (rpcib_ats_t), KM_SLEEP);
		    bcopy(ibds->rib_ats, tmp,
			ibds->rib_ibd_alloc * sizeof (rpcib_ats_t));
		    kmem_free(ibds->rib_ats,
			ibds->rib_ibd_alloc * sizeof (rpcib_ats_t));
		    ibds->rib_ats = tmp;
		    ibds->rib_ibd_alloc += N_IBD_INSTANCES;
		}
		if (((hca_guid = ddi_prop_get_int64(DDI_DEV_T_ANY,
			dip, 0, "hca-guid", 0)) == 0) ||
		    ((port = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
			0, "port-number", 0)) == 0) ||
		    (ibt_get_port_state_byguid(hca_guid, port,
			&port_gid, NULL) != IBT_SUCCESS) ||
		    ((pkey = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
			"port-pkey", IB_PKEY_INVALID_LIMITED)) <=
			IB_PKEY_INVALID_FULL)) {
		    return (DDI_WALK_CONTINUE);
		}
		atsp = &ibds->rib_ats[ibds->rib_ibd_cnt];
		atsp->ras_inst = ddi_get_instance(dip);
		atsp->ras_pkey = pkey;
		atsp->ras_port_gid = port_gid;
		ibds->rib_ibd_cnt++;
	}
	return (DDI_WALK_CONTINUE);
}

void
rib_get_ibd_insts(rpcib_ibd_insts_t *ibds)
{
	ddi_walk_devs(ddi_root_node(), rib_get_ibd_insts_cb, ibds);
}

/*
 * Return ibd interfaces and ibd instances.
 */
int
get_ibd_ipaddr(rpcib_ibd_insts_t *ibds)
{
	TIUSER			*tiptr, *tiptr6;
	vnode_t			*kvp, *kvp6;
	vnode_t			*vp = NULL, *vp6 = NULL;
	struct strioctl		iocb;
	struct lifreq		lif_req;
	int			k, ip_cnt;
	rpcib_ats_t		*atsp;

	if (lookupname("/dev/udp", UIO_SYSSPACE, FOLLOW, NULLVPP,
		&kvp) == 0) {
	    if (t_kopen((file_t *)NULL, kvp->v_rdev, FREAD|FWRITE,
		&tiptr, CRED()) == 0) {
		vp = tiptr->fp->f_vnode;
	    } else {
		VN_RELE(kvp);
	    }
	}

	if (lookupname("/dev/udp6", UIO_SYSSPACE, FOLLOW, NULLVPP,
		&kvp6) == 0) {
	    if (t_kopen((file_t *)NULL, kvp6->v_rdev, FREAD|FWRITE,
		&tiptr6, CRED()) == 0) {
		vp6 = tiptr6->fp->f_vnode;
	    } else {
		VN_RELE(kvp6);
	    }
	}

	if (vp == NULL && vp6 == NULL)
		return (-1);

	/* Get ibd ip's */
	ip_cnt = 0;
	for (k = 0, atsp = ibds->rib_ats; k < ibds->rib_ibd_cnt; k++, atsp++) {
		/* IPv4 */
	    if (vp != NULL) {
		(void) bzero((void *)&lif_req, sizeof (struct lifreq));
		(void) snprintf(lif_req.lifr_name,
			sizeof (lif_req.lifr_name), "%s%d",
			IBD_NAME, atsp->ras_inst);

		(void) bzero((void *)&iocb, sizeof (struct strioctl));
		iocb.ic_cmd = SIOCGLIFADDR;
		iocb.ic_timout = 0;
		iocb.ic_len = sizeof (struct lifreq);
		iocb.ic_dp = (caddr_t)&lif_req;
		if (kstr_ioctl(vp, I_STR, (intptr_t)&iocb) == 0) {
		    atsp->ras_inet_type = AF_INET;
		    bcopy(&lif_req.lifr_addr, &atsp->ras_sin,
			sizeof (struct sockaddr_in));
		    ip_cnt++;
		    continue;
		}
	    }
		/* Try IPv6 */
	    if (vp6 != NULL) {
		(void) bzero((void *)&lif_req, sizeof (struct lifreq));
		(void) snprintf(lif_req.lifr_name,
			sizeof (lif_req.lifr_name), "%s%d",
			IBD_NAME, atsp->ras_inst);

		(void) bzero((void *)&iocb, sizeof (struct strioctl));
		iocb.ic_cmd = SIOCGLIFADDR;
		iocb.ic_timout = 0;
		iocb.ic_len = sizeof (struct lifreq);
		iocb.ic_dp = (caddr_t)&lif_req;
		if (kstr_ioctl(vp6, I_STR, (intptr_t)&iocb) == 0) {

		    atsp->ras_inet_type = AF_INET6;
		    bcopy(&lif_req.lifr_addr, &atsp->ras_sin6,
			    sizeof (struct sockaddr_in6));
		    ip_cnt++;
		}
	    }
	}

	if (vp6 != NULL) {
	    (void) t_kclose(tiptr6, 0);
	    VN_RELE(kvp6);
	}
	if (vp != NULL) {
	    (void) t_kclose(tiptr, 0);
	    VN_RELE(kvp);
	}

	if (ip_cnt == 0)
	    return (-1);
	else
	    return (0);
}

char **
get_ip_addrs(int *count)
{
	TIUSER			*tiptr;
	vnode_t			*kvp;
	int			num_of_ifs;
	char			**addresses;
	int			return_code;

	/*
	 * Open a device for doing down stream kernel ioctls
	 */
	return_code = lookupname("/dev/udp", UIO_SYSSPACE, FOLLOW,
	    NULLVPP, &kvp);
	if (return_code != 0) {
		cmn_err(CE_NOTE, "get_Ip_addrs: lookupname failed\n");
		*count = -1;
		return (NULL);
	}

	return_code = t_kopen((file_t *)NULL, kvp->v_rdev, FREAD|FWRITE,
	    &tiptr, CRED());
	if (return_code != 0) {
		cmn_err(CE_NOTE, "get_Ip_addrs: t_kopen failed\n");
		VN_RELE(kvp);
		*count = -1;
		return (NULL);
	}

	/*
	 * Perform the first ioctl to get the number of interfaces
	 */
	return_code = get_interfaces(tiptr, &num_of_ifs);
	if (return_code != 0 || num_of_ifs == 0) {
		cmn_err(CE_NOTE, "get_Ip_addrs: get_interfaces failed\n");
		(void) t_kclose(tiptr, 0);
		VN_RELE(kvp);
		*count = -1;
		return (NULL);
	}

	/*
	 * Perform the second ioctl to get the address on each interface
	 * found.
	 */
	addresses = kmem_zalloc(num_of_ifs * sizeof (char *), KM_SLEEP);
	return_code = find_addrs(tiptr, addresses, num_of_ifs);
	if (return_code <= 0) {
		cmn_err(CE_NOTE, "get_Ip_addrs: find_addrs failed\n");
		(void) t_kclose(tiptr, 0);
		kmem_free(addresses, num_of_ifs * sizeof (char *));
		VN_RELE(kvp);
		*count = -1;
		return (NULL);
	}

	*count = return_code;
	VN_RELE(kvp);
	(void) t_kclose(tiptr, 0);
	return (addresses);
}

int
get_interfaces(TIUSER *tiptr, int *num)
{
	struct lifnum		if_buf;
	struct strioctl		iocb;
	vnode_t			*vp;
	int			return_code;

	/*
	 * Prep the number of interfaces request buffer for ioctl
	 */
	(void) bzero((void *)&if_buf, sizeof (struct lifnum));
	if_buf.lifn_family = AF_UNSPEC;
	if_buf.lifn_flags = 0;

	/*
	 * Prep the kernel ioctl buffer and send it down stream
	 */
	(void) bzero((void *)&iocb, sizeof (struct strioctl));
	iocb.ic_cmd = SIOCGLIFNUM;
	iocb.ic_timout = 0;
	iocb.ic_len = sizeof (if_buf);
	iocb.ic_dp = (caddr_t)&if_buf;

	vp = tiptr->fp->f_vnode;
	return_code = kstr_ioctl(vp, I_STR, (intptr_t)&iocb);
	if (return_code != 0) {
		cmn_err(CE_NOTE, "get_interfaces: kstr_ioctl failed\n");
		*num = -1;
		return (-1);
	}

	*num = if_buf.lifn_count;
#ifdef	DEBUG
	if (rib_debug > 1)
		cmn_err(CE_NOTE, "Number of interfaces detected: %d\n",
		    if_buf.lifn_count);
#endif
	return (0);
}

int
find_addrs(TIUSER *tiptr, char **addrs, int num_ifs)
{
	struct lifconf		lifc;
	struct lifreq		*if_data_buf;
	struct strioctl		iocb;
	caddr_t			request_buffer;
	struct sockaddr_in	*sin4;
	struct sockaddr_in6	*sin6;
	vnode_t			*vp;
	int			i, count, return_code;

	/*
	 * Prep the buffer for requesting all interface's info
	 */
	(void) bzero((void *)&lifc, sizeof (struct lifconf));
	lifc.lifc_family = AF_UNSPEC;
	lifc.lifc_flags = 0;
	lifc.lifc_len = num_ifs * sizeof (struct lifreq);

	request_buffer = kmem_zalloc(num_ifs * sizeof (struct lifreq),
	    KM_SLEEP);

	lifc.lifc_buf = request_buffer;

	/*
	 * Prep the kernel ioctl buffer and send it down stream
	 */
	(void) bzero((void *)&iocb, sizeof (struct strioctl));
	iocb.ic_cmd = SIOCGLIFCONF;
	iocb.ic_timout = 0;
	iocb.ic_len = sizeof (struct lifconf);
	iocb.ic_dp = (caddr_t)&lifc;

	vp = tiptr->fp->f_vnode;
	return_code = kstr_ioctl(vp, I_STR, (intptr_t)&iocb);
	if (return_code != 0) {
		cmn_err(CE_NOTE, "find_addrs: kstr_ioctl failed\n");
		kmem_free(request_buffer, num_ifs * sizeof (struct lifreq));
		return (-1);
	}

	/*
	 * Extract addresses and fill them in the requested array
	 * IB_SVC_NAME_LEN is defined to be 64 so it  covers both IPv4 &
	 * IPv6. Here count is the number of IP addresses collected.
	 */
	if_data_buf = lifc.lifc_req;
	count = 0;
	for (i = lifc.lifc_len / sizeof (struct lifreq); i > 0; i--,
	if_data_buf++) {
		if (if_data_buf->lifr_addr.ss_family == AF_INET) {
			sin4 = (struct sockaddr_in *)&if_data_buf->lifr_addr;
			addrs[count] = kmem_zalloc(IB_SVC_NAME_LEN, KM_SLEEP);
			(void) inet_ntop(AF_INET, &sin4->sin_addr,
			    addrs[count], IB_SVC_NAME_LEN);
			count ++;
		}

		if (if_data_buf->lifr_addr.ss_family == AF_INET6) {
			sin6 = (struct sockaddr_in6 *)&if_data_buf->lifr_addr;
			addrs[count] = kmem_zalloc(IB_SVC_NAME_LEN, KM_SLEEP);
			(void) inet_ntop(AF_INET6, &sin6->sin6_addr,
			    addrs[count], IB_SVC_NAME_LEN);
			count ++;
		}
	}

	kmem_free(request_buffer, num_ifs * sizeof (struct lifreq));
	return (count);
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
		if (conn->c_state & C_CONNECTED) {
			/*
			 * Live connection in CONNECTED state.
			 * Call ibt_close_rc_channel in nonblocking mode
			 * with no callbacks.
			 */
			conn->c_state = C_ERROR;
			(void) ibt_close_rc_channel(qp->qp_hdl,
				IBT_NOCALLBACKS, NULL, 0, NULL, NULL, 0);
			(void) ibt_free_channel(qp->qp_hdl);
			qp->qp_hdl = NULL;
		} else {
			if (conn->c_state == C_ERROR &&
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
	rib_deregister_ats();
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
