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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * sol_cma is a part of sol_ofs misc module. This file
 * provides interfaces for supporting the communication
 * management API defined in "rdma_cm.h". In-Kernel
 * consumers of the "rdma_cm.h" API should link sol_ofs
 * misc module using :
 *	-N misc/sol_ofs
 * Solaris uCMA (sol_ucma) driver is the current consumer for
 * sol_cma.
 */

/* Standard driver includes */
#include <sys/types.h>
#include <sys/modctl.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>

#include <sys/ib/clients/of/ofed_kernel.h>
#include <sys/ib/clients/of/rdma/ib_addr.h>

#include <sys/ib/clients/of/sol_ofs/sol_cma.h>
#include <sys/ib/clients/of/sol_ofs/sol_kverb_impl.h>

/* Modload support */
static struct modlmisc sol_ofs_modmisc	= {
	&mod_miscops,
	"Solaris OFS Misc module"
};

struct modlinkage sol_ofs_modlinkage = {
	MODREV_1,
	(void *)&sol_ofs_modmisc,
	NULL
};

static ib_client_t	*sol_cma_ib_client;
sol_cma_glbl_listen_t	sol_cma_glbl_listen;
avl_tree_t		sol_cma_glbl_listen_tree;

static void		sol_cma_add_dev(struct ib_device *);
static void		sol_cma_rem_dev(struct ib_device *);

static llist_head_t	sol_cma_dev_list = LLIST_HEAD_INIT(sol_cma_dev_list);
kmutex_t		sol_cma_dev_mutex;
kmutex_t		sol_cma_glob_mutex;

char	*sol_rdmacm_dbg_str = "sol_rdmacm";
char	*sol_ofs_dbg_str = "sol_ofs_mod";

/*
 * Local functions defines.
 */
int sol_cma_req_cmid_cmp(const void *p1, const void *p2);
int sol_cma_cmid_cmp(const void *p1, const void *p2);
int sol_cma_svc_cmp(const void *, const void *);

static struct rdma_cm_id *cma_alloc_chan(rdma_cm_event_handler,
    void *, enum rdma_port_space);
static void cma_set_chan_state(sol_cma_chan_t *, cma_chan_state_t);
static int cma_cas_chan_state(sol_cma_chan_t *, cma_chan_state_t,
    cma_chan_state_t);
static void cma_free_listen_list(struct rdma_cm_id *);
static void cma_destroy_id(struct rdma_cm_id *);
static void cma_handle_nomore_events(sol_cma_chan_t *);

extern void sol_ofs_dprintf_init();
extern void sol_ofs_dprintf_fini();

cma_chan_state_t cma_get_chan_state(sol_cma_chan_t *);
extern int ibcma_init_root_chan(sol_cma_chan_t *, sol_cma_glbl_listen_t *);
extern int ibcma_fini_root_chan(sol_cma_chan_t *);
extern void ibcma_copy_srv_hdl(sol_cma_chan_t *, sol_cma_glbl_listen_t *);
extern int ibcma_fini_ep_chan(sol_cma_chan_t *);
extern uint64_t ibcma_init_root_sid(sol_cma_chan_t *);
extern void rdma_ib_destroy_id(struct rdma_cm_id *);
extern int rdma_ib_bind_addr(struct rdma_cm_id *, struct sockaddr *);
extern int rdma_ib_resolve_addr(struct rdma_cm_id *, struct sockaddr *,
    struct sockaddr *, int);
extern int rdma_ib_resolve_route(struct rdma_cm_id *, int);
extern int rdma_ib_init_qp_attr(struct rdma_cm_id *, struct ib_qp_attr *,
    int *);
extern int rdma_ib_connect(struct rdma_cm_id *, struct rdma_conn_param *);
extern int rdma_ib_listen(struct rdma_cm_id *, int);
extern int rdma_ib_accept(struct rdma_cm_id *, struct rdma_conn_param *);
extern int rdma_ib_reject(struct rdma_cm_id *, const void *, uint8_t);
extern int rdma_ib_disconnect(struct rdma_cm_id *);
extern int rdma_ib_join_multicast(struct rdma_cm_id *, struct sockaddr *,
    void *);
extern void rdma_ib_leave_multicast(struct rdma_cm_id *, struct sockaddr *);

int
_init(void)
{
	int		err;

	sol_ofs_dprintf_init();
	SOL_OFS_DPRINTF_L5(sol_ofs_dbg_str, "_init()");

	mutex_init(&sol_cma_glob_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&sol_cma_dev_mutex, NULL, MUTEX_DRIVER, NULL);
	avl_create(&sol_cma_glbl_listen_tree,
	    sol_cma_svc_cmp, sizeof (sol_cma_glbl_listen_t),
	    offsetof(sol_cma_glbl_listen_t, cma_listen_node));

	sol_cma_ib_client = kmem_zalloc(sizeof (ib_client_t), KM_NOSLEEP);
	if (!sol_cma_ib_client) {
		SOL_OFS_DPRINTF_L2(sol_ofs_dbg_str,
		    "_init() - mem alloc failed");
		avl_destroy(&sol_cma_glbl_listen_tree);
		mutex_destroy(&sol_cma_dev_mutex);
		mutex_destroy(&sol_cma_glob_mutex);
		sol_ofs_dprintf_fini();
		return (ENOMEM);
	}

	sol_cma_ib_client->name = "sol_ofs";
	sol_cma_ib_client->add = sol_cma_add_dev;
	sol_cma_ib_client->remove = sol_cma_rem_dev;
	sol_cma_ib_client->dip = NULL;

	if ((err = ib_register_client(sol_cma_ib_client)) != 0) {
		SOL_OFS_DPRINTF_L2(sol_ofs_dbg_str,
		    "_init() ib_register_client() failed with err %d",
		    err);
		kmem_free(sol_cma_ib_client, sizeof (ib_client_t));
		avl_destroy(&sol_cma_glbl_listen_tree);
		mutex_destroy(&sol_cma_dev_mutex);
		mutex_destroy(&sol_cma_glob_mutex);
		sol_ofs_dprintf_fini();
		return (err);
	}

	if ((err = mod_install(&sol_ofs_modlinkage)) != 0) {
		SOL_OFS_DPRINTF_L2(sol_ofs_dbg_str,
		    "_init() - mod_install() failed");
		ib_unregister_client(sol_cma_ib_client);
		kmem_free(sol_cma_ib_client, sizeof (ib_client_t));
		avl_destroy(&sol_cma_glbl_listen_tree);
		mutex_destroy(&sol_cma_dev_mutex);
		mutex_destroy(&sol_cma_glob_mutex);
		sol_ofs_dprintf_fini();
		return (err);
	}

	SOL_OFS_DPRINTF_L5(sol_ofs_dbg_str, "_init() - ret");
	return (err);
}

int
_fini(void)
{
	int		err;

	SOL_OFS_DPRINTF_L5(sol_ofs_dbg_str, "_fini()");

	if (avl_numnodes(&sol_cma_glbl_listen_tree)) {
		SOL_OFS_DPRINTF_L2(sol_ofs_dbg_str, "_fini - "
		    "listen CMIDs still active");
		return (EBUSY);
	}
	if ((err = mod_remove(&sol_ofs_modlinkage)) != 0) {
		SOL_OFS_DPRINTF_L3(sol_ofs_dbg_str,
		    "_fini: mod_remove failed");
		return (err);
	}

	ib_unregister_client(sol_cma_ib_client);
	kmem_free(sol_cma_ib_client, sizeof (ib_client_t));
	avl_destroy(&sol_cma_glbl_listen_tree);
	mutex_destroy(&sol_cma_dev_mutex);
	mutex_destroy(&sol_cma_glob_mutex);
	SOL_OFS_DPRINTF_L5(sol_ofs_dbg_str, "_fini() - ret");
	sol_ofs_dprintf_fini();
	return (err);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&sol_ofs_modlinkage, modinfop));
}

typedef struct cma_device {
	kmutex_t		cma_mutex;
	/* Ptr in the global sol_cma_dev_list */
	llist_head_t		cma_list;
	/* List of listeners for this device */
	genlist_t		cma_epchan_list;
	struct ib_device	*cma_device;
	uint_t			cma_ref_count;
	enum {
		SOL_CMA_DEV_ADDED,
		SOL_CMA_DEV_REM_IN_PROGRESS
	} cma_dev_state;
} cma_device_t;

static void
sol_cma_add_dev(struct ib_device *dev)
{
	cma_device_t	*new_device;

	new_device = kmem_zalloc(sizeof (cma_device_t), KM_NOSLEEP);
	if (!new_device) {
		SOL_OFS_DPRINTF_L2(sol_ofs_dbg_str, "sol_cma_add_dev() "
		    "alloc failed!!");
		return;
	}
	mutex_init(&new_device->cma_mutex, NULL, MUTEX_DRIVER, NULL);
	llist_head_init(&new_device->cma_list, new_device);
	init_genlist(&new_device->cma_epchan_list);
	new_device->cma_device = dev;

	ib_set_client_data(dev, sol_cma_ib_client, new_device);

	mutex_enter(&sol_cma_dev_mutex);
	llist_add_tail(&new_device->cma_list, &sol_cma_dev_list);
	mutex_exit(&sol_cma_dev_mutex);
}

static void
sol_cma_rem_dev(struct ib_device *dev)
{
	cma_device_t	*rem_device;
	genlist_entry_t	*entry;

	SOL_OFS_DPRINTF_L5(sol_ofs_dbg_str, "sol_rem_dev(%p)", dev);

	rem_device = (cma_device_t *)ib_get_client_data(dev, sol_cma_ib_client);
	if (!rem_device) {
		SOL_OFS_DPRINTF_L2(sol_ofs_dbg_str, "sol_cma_rem_dev() "
		    "NULL cma_dev!!");
		return;
	}

	mutex_enter(&rem_device->cma_mutex);
	rem_device->cma_dev_state = SOL_CMA_DEV_REM_IN_PROGRESS;
	if (rem_device->cma_ref_count) {
		mutex_exit(&rem_device->cma_mutex);
		SOL_OFS_DPRINTF_L3(sol_ofs_dbg_str, "sol_cma_rem_dev() "
		    "BUSY cma_dev!!");
		return;
	}
	entry = remove_genlist_head(&rem_device->cma_epchan_list);
	while (entry) {
		sol_cma_chan_t	*ep_chanp;

		ep_chanp = (sol_cma_chan_t *)entry->data;
		if (ibcma_fini_ep_chan(ep_chanp) == 0) {
			genlist_entry_t	*entry1;
			sol_cma_chan_t	*root_chanp;

			ASSERT(ep_chanp->chan_listenp);
			entry1 = ep_chanp->chan_listenp->listen_ep_root_entry;
			root_chanp = (sol_cma_chan_t *)ep_chanp->listen_root;
			root_chanp->chan_listenp->listen_eps--;
			delete_genlist(&root_chanp->chan_listenp->listen_list,
			    entry1);

			kmem_free(ep_chanp, sizeof (sol_cma_chan_t));
			kmem_free(entry, sizeof (genlist_entry_t));
		}

		entry = remove_genlist_head(&rem_device->cma_epchan_list);
	}
	mutex_exit(&rem_device->cma_mutex);

	mutex_enter(&sol_cma_dev_mutex);
	llist_del(&rem_device->cma_list);
	mutex_exit(&sol_cma_dev_mutex);

	kmem_free(rem_device, sizeof (cma_device_t));
}

struct ib_device *
sol_cma_acquire_device(ib_guid_t hca_guid)
{
	llist_head_t	*entry;
	cma_device_t	*cma_devp;

	mutex_enter(&sol_cma_dev_mutex);
	list_for_each(entry, &sol_cma_dev_list) {
		cma_devp = (cma_device_t *)entry->ptr;

		if (cma_devp->cma_device->node_guid != hca_guid)
			continue;

		mutex_enter(&cma_devp->cma_mutex);
		if (cma_devp->cma_dev_state == SOL_CMA_DEV_REM_IN_PROGRESS) {
			SOL_OFS_DPRINTF_L3(sol_ofs_dbg_str,
			    "sol_cma_acquire_dev() - Device getting removed!!");
			mutex_exit(&cma_devp->cma_mutex);
			mutex_exit(&sol_cma_dev_mutex);
			return (NULL);
		}
		cma_devp->cma_ref_count++;
		mutex_exit(&cma_devp->cma_mutex);
		mutex_exit(&sol_cma_dev_mutex);
		return (cma_devp->cma_device);

	}
	mutex_exit(&sol_cma_dev_mutex);
	return (NULL);
}

static void
sol_cma_release_device(struct rdma_cm_id *id)
{
	ib_device_t	*device = id->device;
	llist_head_t	*entry;
	cma_device_t	*cma_devp;

	mutex_enter(&sol_cma_dev_mutex);
	list_for_each(entry, &sol_cma_dev_list) {
		cma_devp = (cma_device_t *)entry->ptr;

		if (cma_devp->cma_device != device)
			continue;

		mutex_enter(&cma_devp->cma_mutex);
		cma_devp->cma_ref_count--;
		if (cma_devp->cma_dev_state == SOL_CMA_DEV_REM_IN_PROGRESS &&
		    cma_devp->cma_ref_count == 0) {
			SOL_OFS_DPRINTF_L3(sol_ofs_dbg_str,
			    "sol_cma_release_dev() - Device free removed!!");
			mutex_exit(&cma_devp->cma_mutex);
			llist_del(&cma_devp->cma_list);
			kmem_free(cma_devp, sizeof (cma_device_t));
			mutex_exit(&sol_cma_dev_mutex);
			return;
		}
		mutex_exit(&cma_devp->cma_mutex);
	}
	mutex_exit(&sol_cma_dev_mutex);
}

void
sol_cma_add_hca_list(sol_cma_chan_t *ep_chanp, ib_guid_t hca_guid)
{
	llist_head_t	*entry;
	cma_device_t	*cma_devp;

	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "add_hca_list(%p, %llx)",
	    ep_chanp, hca_guid);
	mutex_enter(&sol_cma_dev_mutex);
	list_for_each(entry, &sol_cma_dev_list) {
		cma_devp = (cma_device_t *)entry->ptr;

		if ((cma_devp->cma_device)->node_guid != hca_guid)
			continue;

		mutex_enter(&cma_devp->cma_mutex);
		ep_chanp->chan_listenp->listen_ep_dev_entry =
		    add_genlist(&cma_devp->cma_epchan_list,
		    (uintptr_t)ep_chanp, NULL);
		ep_chanp->chan_listenp->listen_ep_device = cma_devp->cma_device;
		mutex_exit(&cma_devp->cma_mutex);
		mutex_exit(&sol_cma_dev_mutex);
		return;
	}
	mutex_exit(&sol_cma_dev_mutex);
	SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str, "add_hca_list(%p, %llx): "
	    "No matching HCA in list!!", ep_chanp, hca_guid);
}

/*
 * rdma_cm.h API functions.
 */
struct rdma_cm_id *
rdma_create_id(rdma_cm_event_handler evt_hdlr, void *context,
    enum rdma_port_space ps)
{
	struct rdma_cm_id 	*rdma_idp;

	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "rdma_create_id(%p, %p, %x)",
	    evt_hdlr, context, ps);

	if (ps != RDMA_PS_TCP && ps != RDMA_PS_UDP && ps != RDMA_PS_IPOIB) {
		SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
		    "rdma_create_id: unsupported protocol %x", ps);
		return (NULL);
	}

	rdma_idp = cma_alloc_chan(evt_hdlr, context, ps);
	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str,
	    "rdma_create_id : ret %p", rdma_idp);

	return (rdma_idp);
}

void
rdma_map_id2clnthdl(struct rdma_cm_id *rdma_idp, void *ib_client_hdl,
    void *iw_client_hdl)
{
	sol_cma_chan_t	*chanp = (sol_cma_chan_t *)rdma_idp;

	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str,
	    "rdma_map_id2clnthdl(%p, %p, %p)",
	    rdma_idp, ib_client_hdl, iw_client_hdl);
	ASSERT(ib_client_hdl != NULL || iw_client_hdl != NULL);
	chanp->chan_ib_client_hdl = ib_client_hdl;
	chanp->chan_iw_client_hdl = iw_client_hdl;
}

void
rdma_map_id2qphdl(struct rdma_cm_id *rdma_idp, void *qp_hdl)
{
	sol_cma_chan_t	*chanp = (sol_cma_chan_t *)rdma_idp;

	ASSERT(rdma_idp);
	ASSERT(qp_hdl);
	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "rdma_mapid2qphdl(%p, %p)",
	    rdma_idp, qp_hdl);
	chanp->chan_qp_hdl = qp_hdl;
}


void
rdma_destroy_id(struct rdma_cm_id *rdma_idp)
{
	sol_cma_chan_t		*chanp, *root_chanp;
	cma_chan_state_t	state;
	int			rc, is_root_cmid, do_wait, is_passive;

	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "rdma_destroy_id(%p)", rdma_idp);

	if (!rdma_idp)
		return;

	is_root_cmid = do_wait = is_passive = 0;

	chanp = (sol_cma_chan_t *)rdma_idp;
	root_chanp = (sol_cma_chan_t *)chanp->listen_root;
	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "rdma_destroy_id(%p), %p",
	    rdma_idp, root_chanp);

	mutex_enter(&chanp->chan_mutex);
	chanp->chan_cmid_destroy_state |= SOL_CMA_CALLER_CMID_DESTROYED;

	/*
	 * Wait in destroy of CMID when rdma_resolve_addr() / rdma_listen()
	 * rdma_resolve_route() API is in progress.
	 */
	while (chanp->chan_cmid_destroy_state & SOL_CMA_CALLER_API_PROGRESS)
		cv_wait(&chanp->chan_destroy_cv, &chanp->chan_mutex);

	/* Wait if Event is been notified to consumer */
	while (chanp->chan_cmid_destroy_state & SOL_CMA_CALLER_EVENT_PROGRESS)
		cv_wait(&chanp->chan_destroy_cv, &chanp->chan_mutex);

	if (rdma_idp->device)
		sol_cma_release_device(rdma_idp);

	if (chanp->chan_listenp && chanp->chan_listenp->listen_is_root)
		is_root_cmid = 1;
	if (root_chanp == NULL && is_root_cmid == 0)
		is_passive = 1;

	/*
	 * Skip Active side handling for passive CMIDs and listen CMID
	 * for which REQ CMIDs have not been created.
	 */
	if (is_passive || (is_root_cmid && chanp->chan_req_state !=
	    REQ_CMID_QUEUED)) {
		SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "rdma_destroy_id: "
		    "Skipping passive %p, %x, %x", chanp->chan_listenp,
		    is_root_cmid, chanp->chan_req_state);
		goto skip_passive_handling;
	}

	/*
	 * destroy_id() called for listening CMID and there are REQ
	 * CMIDs not yet notified. Reject such CMIDs and decrement
	 * the count.
	 */
	if (is_root_cmid && chanp->chan_req_cnt) {
		sol_cma_chan_t	*req_cmid_chan, *next_chan;

		SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "rdma_destroy_id: "
		    "not notified handling");
		for (req_cmid_chan = (sol_cma_chan_t *)avl_first(
		    &chanp->chan_req_avl_tree); req_cmid_chan &&
		    chanp->chan_req_cnt; req_cmid_chan = next_chan) {
			next_chan = AVL_NEXT(
			    &chanp->chan_req_avl_tree, req_cmid_chan);
			if (req_cmid_chan->chan_req_state ==
			    REQ_CMID_NOTIFIED) {
				avl_remove(&chanp->chan_req_avl_tree,
				    req_cmid_chan);
				chanp->chan_req_cnt--;
				chanp->chan_req_total_cnt--;
				mutex_exit(&chanp->chan_mutex);
				mutex_enter(&req_cmid_chan->chan_mutex);
				req_cmid_chan->chan_req_state =
				    REQ_CMID_SERVER_NONE;
				if (rdma_idp->ps == RDMA_PS_TCP)
					cma_set_chan_state(req_cmid_chan,
					    SOL_CMA_CHAN_DESTROY_PENDING);
				mutex_exit(&req_cmid_chan->chan_mutex);
				(void) rdma_disconnect(
				    (struct rdma_cm_id *)req_cmid_chan);
				mutex_enter(&chanp->chan_mutex);
				if (rdma_idp->ps == RDMA_PS_TCP) {
					mutex_enter(
					    &req_cmid_chan->chan_mutex);
					req_cmid_chan->listen_root =
					    rdma_idp;
					mutex_exit(
					    &req_cmid_chan->chan_mutex);
				} else {
					mutex_destroy(
					    &req_cmid_chan->chan_mutex);
					cv_destroy(
					    &req_cmid_chan->chan_destroy_cv);
					kmem_free(req_cmid_chan,
					    sizeof (sol_cma_chan_t));
				}
			}
		}
	}

	/*
	 * destroy_id() called for :
	 * 	listening CMID and all REQ CMIDs destroy_id() called
	 *	REQ CMID and 1 more REQ CMID not yet destroyed.
	 * wait till the CMID is completly destroyed.
	 */
	if (is_root_cmid && chanp->chan_req_total_cnt == 0) {
		SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "rdma_destroy_id: "
		    "root idp waiting");
		cma_set_chan_state(chanp, SOL_CMA_CHAN_DESTROY_WAIT);
		cv_wait(&chanp->chan_destroy_cv, &chanp->chan_mutex);
	}
	mutex_exit(&chanp->chan_mutex);

	if (root_chanp)
		mutex_enter(&root_chanp->chan_mutex);
	mutex_enter(&chanp->chan_mutex);
#ifdef	DEBUG
	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "rdma_destroy_id: "
	    "root_idp %p, cnt %x, state %x", root_chanp,
	    root_chanp ? root_chanp->chan_req_total_cnt : 0,
	    root_chanp ? cma_get_chan_state(root_chanp) : 0);
#endif

	if (root_chanp && root_chanp->chan_req_total_cnt == 1 &&
	    cma_get_chan_state(root_chanp) == SOL_CMA_CHAN_DESTROY_PENDING)
		do_wait = 1;
	if (root_chanp)
		mutex_exit(&root_chanp->chan_mutex);

skip_passive_handling :
	state = cma_get_chan_state(chanp);
	if (is_root_cmid == 0 && state != SOL_CMA_CHAN_DISCONNECT &&
	    SOL_CMAID_CONNECTED(chanp)) {
		/*
		 * A connected CM ID has not been disconnected.
		 * Call rdma_disconnect() to disconnect it.
		 */
		mutex_exit(&chanp->chan_mutex);
		rc = rdma_disconnect(rdma_idp);
		if (rc) {
			SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
			    "rdma_destroy_id(%p)- disconnect failed!!",
			    rdma_idp);
			return;
		}
		mutex_enter(&chanp->chan_mutex);
		if (root_chanp && chanp->listen_root == NULL)
			chanp->listen_root = (struct rdma_cm_id *)root_chanp;
		SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str,
		    "rdma_destroy_id(chanp %p, connect %x, ps %x)",
		    chanp, chanp->chan_connect_flag, rdma_idp->ps);
		if (SOL_CMAID_CONNECTED(chanp)) {
			if (do_wait) {
				cma_set_chan_state(chanp,
				    SOL_CMA_CHAN_DESTROY_WAIT);
				cv_wait(&chanp->chan_destroy_cv,
				    &chanp->chan_mutex);
				mutex_exit(&chanp->chan_mutex);
				cma_destroy_id(rdma_idp);
			} else {
				cma_set_chan_state(chanp,
				    SOL_CMA_CHAN_DESTROY_PENDING);
				mutex_exit(&chanp->chan_mutex);
			}
		} else {
			/*
			 * No more callbacks are expected for this CMID.
			 * Free this CMID.
			 */
			mutex_exit(&chanp->chan_mutex);
			cma_destroy_id(rdma_idp);
		}
	} else if (is_root_cmid == 0 && state ==
	    SOL_CMA_CHAN_DISCONNECT && SOL_CMAID_CONNECTED(chanp)) {
		/*
		 * CM ID was connected and disconnect is process.
		 * Free of this CM ID is done for the DISCONNECT
		 * notification for this CMID.
		 */
		cma_set_chan_state(chanp, SOL_CMA_CHAN_DESTROY_PENDING);
		mutex_exit(&chanp->chan_mutex);
	} else if (state != SOL_CMA_CHAN_DESTROY_PENDING) {
		/* CM ID, not connected, just free it. */
		mutex_exit(&chanp->chan_mutex);
		cma_destroy_id(rdma_idp);
	} else
		mutex_exit(&chanp->chan_mutex);

	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "rdma_destroy_id: ret");
}

/*
 * State transitions for Address resolution :
 *	Active Side (Client) :
 *	1. CREATE_ID-->BIND_ADDR-->RESOLVE_ADDR-->RESOLVE_ROUTE
 *
 *	Passive Side (Server) :
 *	2. CREATE_ID-->RESOLVE_ADDR-->RESOLVE_ROUTE
 *	IF_ADDR_ANY can be passed as local address in RESOLVE_ADDR
 */
int
rdma_bind_addr(struct rdma_cm_id *idp, struct sockaddr *addr)
{
	sol_cma_chan_t		*chanp;
	struct rdma_addr	*addrp;
	int			ret;

	ASSERT(idp);
	ASSERT(addr);
	chanp = (sol_cma_chan_t *)idp;
	addrp = &(idp->route.addr);
	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "rdma_bind_addr(%p, %p)",
	    idp, addr);

	mutex_enter(&chanp->chan_mutex);
	ret = cma_cas_chan_state(chanp, SOL_CMA_CHAN_IDLE, SOL_CMA_CHAN_BOUND);
	if (ret) {
		mutex_exit(&chanp->chan_mutex);
		return (ret);
	}
	/* Copy the local address to rdma_id structure */
	bcopy((void *)addr, (void *)&(addrp->src_addr),
	    sizeof (struct sockaddr));
	mutex_exit(&chanp->chan_mutex);

	/*
	 * First call rdma_ib_bind_addr() to bind this address.
	 * Next call rdma_iw_bind_addr() to bind this address.
	 * For IF_ADDR_ANY, IB address is given priority over
	 * iWARP.
	 */
	if (chanp->chan_ib_client_hdl == NULL) {
		ofs_client_t	*ofs_clnt;

		ofs_clnt = (ofs_client_t *)sol_cma_ib_client->clnt_hdl;
		chanp->chan_ib_client_hdl = ofs_clnt->ibt_hdl;
	}
	if (chanp->chan_ib_client_hdl && rdma_ib_bind_addr(idp, addr) == 0) {
		SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str,
		    "rdma_bind_addr: ret IB @");
		return (0);
#ifdef	IWARP_SUPPORT
	} else if (chanp->chan_iw_client_hdl && rdma_iw_bind_addr(idp, addr)
	    == 0) {
		SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str,
		    "rdma_bind_addr: ret iWARP @");
		return (0);
#endif	/* IWARP_SUPPORT */
	}

	mutex_enter(&chanp->chan_mutex);
	cma_set_chan_state(chanp, SOL_CMA_CHAN_IDLE);
	mutex_exit(&chanp->chan_mutex);
	SOL_OFS_DPRINTF_L4(sol_rdmacm_dbg_str, "rdma_bind_addr: ret failure!");
	return (EINVAL);
}

int
rdma_resolve_addr(struct rdma_cm_id *idp, struct sockaddr *src_addr,
    struct sockaddr *dst_addr, int timeout_ms)
{
	sol_cma_chan_t		*chanp;
	struct rdma_addr	*addrp;
	cma_chan_state_t	state;

	ASSERT(idp);
	chanp = (sol_cma_chan_t *)idp;
	addrp = &(idp->route.addr);
	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "rdma_resolve_addr(%p, %p, "
	    "%p, %x)", idp, src_addr, dst_addr, timeout_ms);

	mutex_enter(&chanp->chan_mutex);
	state = cma_get_chan_state(chanp);
	if (state != SOL_CMA_CHAN_IDLE && state != SOL_CMA_CHAN_BOUND) {
		SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
		    "rdma_resolve_addr : invalid chan state %x", state);
		mutex_exit(&chanp->chan_mutex);
		return (EINVAL);
	}
	if (chanp->chan_cmid_destroy_state &
	    SOL_CMA_CALLER_CMID_DESTROYED) {
		SOL_OFS_DPRINTF_L3(sol_rdmacm_dbg_str,
		    "rdma_resolve_addr : CMID %p, destroy called", chanp);
		mutex_exit(&chanp->chan_mutex);
		return (EINVAL);
	}
	chanp->chan_cmid_destroy_state |= SOL_CMA_CALLER_API_PROGRESS;

	if (chanp->chan_xport_type == SOL_CMA_XPORT_NONE) {
		bcopy((void *)src_addr, (void *)&(addrp->src_addr),
		    sizeof (struct sockaddr));
	}
	bcopy((void *)dst_addr, (void *)&(addrp->dst_addr),
	    sizeof (struct sockaddr));
	mutex_exit(&chanp->chan_mutex);

	/*
	 * First resolve this as an @ corresponding to IB fabric
	 * if this fails, resolve this as an @ corresponding to iWARP
	 */
	if (chanp->chan_ib_client_hdl == NULL) {
		ofs_client_t	*ofs_clnt;

		ofs_clnt = (ofs_client_t *)sol_cma_ib_client->clnt_hdl;
		chanp->chan_ib_client_hdl = ofs_clnt->ibt_hdl;
	}
	if (chanp->chan_ib_client_hdl && rdma_ib_resolve_addr(idp, src_addr,
	    dst_addr, timeout_ms) == 0) {
		SOL_OFS_DPRINTF_L4(sol_rdmacm_dbg_str,
		    "rdma_resolve_addr: ret IB @");
#ifdef IWARP_SUPPORT
	} else if (chanp->chan_iw_client_hdl && rdma_iw_resolve_addr(idp,
	    src_addr, dst_addr, timeout_ms) == 0) {
		SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
		    "rdma_resolve_addr: ret iWARP @");
#endif	/* IWARP_SUPPORT */
	} else {
		SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
		    "rdma_resolve_addr: Invalid @");
		return (EINVAL);
	}
	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "rdma_resolve_addr: ret 0");
	return (0);
}

static void cma_generate_event_sync(struct rdma_cm_id *,
    enum rdma_cm_event_type, int, struct rdma_conn_param *,
    struct rdma_ud_param *);

void
cma_resolve_addr_callback(sol_cma_chan_t *chanp, int rc)
{
	enum rdma_cm_event_type	event;

	mutex_enter(&chanp->chan_mutex);
	if (chanp->chan_cmid_destroy_state &
	    SOL_CMA_CALLER_CMID_DESTROYED) {
		SOL_OFS_DPRINTF_L3(sol_rdmacm_dbg_str,
		    "cma_resolve_addr : CMID %p, destroy called", chanp);
		chanp->chan_cmid_destroy_state &=
		    ~SOL_CMA_CALLER_API_PROGRESS;
		cv_broadcast(&chanp->chan_destroy_cv);
		mutex_exit(&chanp->chan_mutex);
		return;
	}
	if (rc == 0) {
		cma_set_chan_state(chanp, SOL_CMA_CHAN_ADDR_RESLVD);
		event = RDMA_CM_EVENT_ADDR_RESOLVED;
	} else
		event = RDMA_CM_EVENT_ADDR_ERROR;

	/*
	 * Generate RDMA_CM_EVENT_ADDR_RESOLVED event
	 * This will result in RDMA_USER_CM_CMD_RESOLVE_ROUTE in
	 * userland.
	 */
	chanp->chan_cmid_destroy_state |= SOL_CMA_CALLER_EVENT_PROGRESS;
	mutex_exit(&chanp->chan_mutex);
	cma_generate_event_sync((struct rdma_cm_id *)chanp, event, 0,
	    NULL, NULL);

	mutex_enter(&chanp->chan_mutex);
	chanp->chan_cmid_destroy_state &= ~SOL_CMA_CALLER_API_PROGRESS;
	if (chanp->chan_cmid_destroy_state & SOL_CMA_CALLER_CMID_DESTROYED)
		cv_broadcast(&chanp->chan_destroy_cv);
	mutex_exit(&chanp->chan_mutex);
}

int
rdma_resolve_route(struct rdma_cm_id *idp, int timeout_ms)
{
	sol_cma_chan_t		*chanp;

	ASSERT(idp);
	chanp = (sol_cma_chan_t *)idp;
	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "resolve_route(%p, %x)", idp,
	    timeout_ms);

	mutex_enter(&chanp->chan_mutex);
	if (cma_cas_chan_state(chanp, SOL_CMA_CHAN_ADDR_RESLVD,
	    SOL_CMA_CHAN_ROUTE_RESLVD) != 0) {
		mutex_exit(&chanp->chan_mutex);
		SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
		    "resolve_route: Invalid state");
		return (EINVAL);
	}
	if (chanp->chan_cmid_destroy_state &
	    SOL_CMA_CALLER_CMID_DESTROYED) {
		SOL_OFS_DPRINTF_L3(sol_rdmacm_dbg_str,
		    "rdma_resolve_route : CMID %p, destroy called", chanp);
		mutex_exit(&chanp->chan_mutex);
		return (EINVAL);
	}
	chanp->chan_cmid_destroy_state |= SOL_CMA_CALLER_API_PROGRESS;
	mutex_exit(&chanp->chan_mutex);

	/*
	 * Generate RDMA_CM_EVENT_ROUTE_RESOLVED event
	 * This will result in RDMA_USER_CM_CMD_RESOLVE_ROUTE in
	 * userland
	 */
	cma_generate_event(idp, RDMA_CM_EVENT_ROUTE_RESOLVED, 0,
	    NULL, NULL);

	mutex_enter(&chanp->chan_mutex);
	chanp->chan_cmid_destroy_state &= ~SOL_CMA_CALLER_API_PROGRESS;
	if (chanp->chan_cmid_destroy_state & SOL_CMA_CALLER_CMID_DESTROYED)
		cv_broadcast(&chanp->chan_destroy_cv);
	mutex_exit(&chanp->chan_mutex);

	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "resolve_route: ret 0");
	return (0);
}

/*
 * Connect or Listen request should be send after Route is resolved
 *
 *	Active Side (Client) :
 *	1. (State ROUTE_RESOLVED)-->CONNECT-->ACCEPT/REJECT-->DISCONNECT
 *	       -->DESTROY_ID-->close(9E)
 *	2. Same as (1), DESTROY_ID without DISCONNECT
 *	3. Same as (1), close(9e) without DESTROY_ID.
 *
 *	Passive Side (Server) :
 *	4. (State ROUTE_RESOLVED)-->LISTEN->DISCONNECT
 *		-->DESTROY_ID-->close(9E)
 *	5. Same as (4), DESTROY_ID without DISCONNECT
 *	6. Same as (4), close(9e) without DESTROY_ID.
 */
int
rdma_connect(struct rdma_cm_id *idp, struct rdma_conn_param *conn_param)
{
	sol_cma_chan_t		*chanp;
	int			ret = EINVAL;

	ASSERT(idp);
	chanp = (sol_cma_chan_t *)idp;
	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "rdma_connect(%p, %p)", idp,
	    conn_param);

	mutex_enter(&chanp->chan_mutex);
	if (chanp->chan_xport_type == SOL_CMA_XPORT_NONE) {
		mutex_exit(&chanp->chan_mutex);
		SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
		    "rdma_connect, Invalid Xport");
		return (EINVAL);
	}
	if (cma_cas_chan_state(chanp, SOL_CMA_CHAN_ROUTE_RESLVD,
	    SOL_CMA_CHAN_CONNECT)) {
		mutex_exit(&chanp->chan_mutex);
		SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
		    "rdma_connect, Invalid state");
		return (EINVAL);
	}

	if (chanp->chan_xport_type == SOL_CMA_XPORT_IB) {
		ret = rdma_ib_connect(idp, conn_param);
#ifdef	IWARP_SUPPORT
	} else if (chanp->chan_xport_type == SOL_CMA_XPORT_IWARP) {
		ret = rdma_iw_connect(idp, conn_param);
#endif	/* IWARP_SUPPORT */
	}
	mutex_exit(&chanp->chan_mutex);

	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "rdma_connect: ret %x", ret);
	return (ret);
}

static int cma_init_listen_root(sol_cma_chan_t *);
static void cma_fini_listen_root(sol_cma_chan_t *);

int
rdma_listen(struct rdma_cm_id *idp, int bklog)
{
	sol_cma_chan_t		*chanp;
	int			ret = 0;
	genlist_entry_t		*entry;
	cma_chan_state_t	state;

	ASSERT(idp);
	chanp = (sol_cma_chan_t *)idp;
	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "rdma_listen(%p, %x)",
	    idp, bklog);

	mutex_enter(&chanp->chan_mutex);
	state = cma_get_chan_state(chanp);
	if (state == SOL_CMA_CHAN_IDLE) {
		mutex_exit(&chanp->chan_mutex);
		return (EINVAL);
	}
	cma_set_chan_state(chanp, SOL_CMA_CHAN_LISTEN);

	if (chanp->chan_cmid_destroy_state &
	    SOL_CMA_CALLER_CMID_DESTROYED) {
		SOL_OFS_DPRINTF_L3(sol_rdmacm_dbg_str,
		    "rdma_listen : CMID %p, destroy called", chanp);
		mutex_exit(&chanp->chan_mutex);
		return (EINVAL);
	}
	chanp->chan_cmid_destroy_state |= SOL_CMA_CALLER_API_PROGRESS;

	ASSERT(chanp->chan_listenp == NULL);

	chanp->chan_listenp = kmem_zalloc(sizeof (sol_cma_listen_info_t),
	    KM_SLEEP);
	init_genlist(&(CHAN_LISTEN_LIST(chanp)));
	(chanp->chan_listenp)->listen_is_root = 1;
	ret = cma_init_listen_root(chanp);
	if (ret) {
		chanp->chan_listenp = NULL;
		mutex_exit(&chanp->chan_mutex);
		SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str, "rdma_listen: "
		    "cma_init_listen_root: failed");
		kmem_free(chanp->chan_listenp,
		    sizeof (sol_cma_listen_info_t));
		return (EINVAL);
	}

	if (chanp->chan_xport_type == SOL_CMA_XPORT_NONE) {
		ibcma_append_listen_list(idp);
#ifdef IWARP_SUPPORT
		iwcma_append_listen_list(idp);
#endif
	} else if (chanp->chan_xport_type == SOL_CMA_XPORT_IB) {
		ibcma_append_listen_list(idp);
#ifdef	IWARP_SUPPORT
	} else if (chanp->chan_xport_type == SOL_CMA_XPORT_IWARP) {
		iwcma_append_listen_list(idp);
#endif	/* IWARP_SUPPORT */
	}

	if (genlist_empty(&(CHAN_LISTEN_LIST(chanp)))) {
		cma_fini_listen_root(chanp);
		kmem_free((void *)chanp->chan_listenp,
		    sizeof (sol_cma_listen_info_t));
		chanp->chan_listenp = NULL;
		SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str, "rdma_listen: "
		    "No listeners");
		mutex_exit(&chanp->chan_mutex);
		return (0);
	}

	if (chanp->chan_cmid_destroy_state & SOL_CMA_CALLER_CMID_DESTROYED) {
		chanp->chan_cmid_destroy_state &=
		    ~SOL_CMA_CALLER_API_PROGRESS;
		cv_broadcast(&chanp->chan_destroy_cv);
	}

	genlist_for_each(entry, &(CHAN_LISTEN_LIST(chanp))) {
		struct rdma_cm_id	*ep_idp;
		sol_cma_chan_t		*ep_chanp;

		ep_idp = (struct rdma_cm_id *)entry->data;
		ep_chanp = (sol_cma_chan_t *)ep_idp;
		if (ep_chanp->chan_xport_type == SOL_CMA_XPORT_IB)
			ret = rdma_ib_listen(ep_idp, bklog);
#ifdef IWARP_SUPPORT
		if (ep_chanp->chan_xport_type == SOL_CMA_XPORT_IWARP)
			ret = rdma_iw_listen(ep_idp, bklog);
#endif
		if (ret)
			break;
	}

	chanp->chan_cmid_destroy_state &= ~SOL_CMA_CALLER_API_PROGRESS;
	if (chanp->chan_cmid_destroy_state & SOL_CMA_CALLER_CMID_DESTROYED)
		cv_broadcast(&chanp->chan_destroy_cv);
	mutex_exit(&chanp->chan_mutex);

	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "rdma_listen: ret %x", ret);
	return (ret);
}

int
rdma_accept(struct rdma_cm_id *idp, struct rdma_conn_param *conn_param)
{
	struct rdma_cm_id	*root_idp;
	sol_cma_chan_t		*root_chanp, *chanp;
	int			ret = EINVAL;

	ASSERT(idp);
	chanp = (sol_cma_chan_t *)idp;
	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "rdma_accept(%p, %p)",
	    idp, conn_param);

	mutex_enter(&chanp->chan_mutex);
	if (cma_cas_chan_state(chanp, SOL_CMA_CHAN_LISTEN,
	    SOL_CMA_CHAN_ACCEPT) && cma_cas_chan_state(chanp,
	    SOL_CMA_CHAN_CONNECT, SOL_CMA_CHAN_ACCEPT)) {
		SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
		    "rdma_accept, Invalid state");
		mutex_exit(&chanp->chan_mutex);
		return (EINVAL);
	}
	mutex_exit(&chanp->chan_mutex);

	root_idp = CHAN_LISTEN_ROOT(chanp);
	root_chanp = (sol_cma_chan_t *)root_idp;
	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "accept: root_idp %p",
	    root_idp);

	/* For TCP, delete from REQ AVL & insert to ACPT AVL */
	if (root_idp && root_idp->ps == RDMA_PS_TCP) {
		void		*find_ret;
		avl_index_t	where;

		SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "accept: root_idp %p"
		    "REQ AVL remove %p", root_chanp, idp);
		mutex_enter(&root_chanp->chan_mutex);
		mutex_enter(&chanp->chan_mutex);

		/*
		 * This CMID has been deleted, maybe because of timeout.
		 * Return EINVAL.
		 */
		if (chanp->chan_req_state != REQ_CMID_NOTIFIED) {
			mutex_exit(&chanp->chan_mutex);
			mutex_exit(&root_chanp->chan_mutex);
			SOL_OFS_DPRINTF_L3(sol_rdmacm_dbg_str,
			    "accept: root_idp %p chanp %p, not in REQ "
			    "AVL tree",  root_chanp, chanp);
			return (EINVAL);
		}
		ASSERT(cma_get_req_idp(root_idp, chanp->chan_session_id));
		avl_remove(&root_chanp->chan_req_avl_tree, idp);


		SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str,
		    "Add to ACPT AVL of %p IDP, idp %p, qp_hdl %p",
		    root_idp, idp, chanp->chan_qp_hdl);
		find_ret = avl_find(&root_chanp->chan_acpt_avl_tree,
		    (void *)chanp->chan_qp_hdl, &where);
		if (find_ret) {
			chanp->chan_req_state = REQ_CMID_SERVER_NONE;
			mutex_exit(&chanp->chan_mutex);
			mutex_exit(&root_chanp->chan_mutex);
			SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
			    "DUPLICATE ENTRY in ACPT AVL : root %p, "
			    "idp %p, qp_hdl %p",
			    root_idp, idp, chanp->chan_qp_hdl);
			return (EINVAL);
		}
		avl_insert(&root_chanp->chan_acpt_avl_tree,
		    (void *)idp, where);
		chanp->chan_req_state = REQ_CMID_ACCEPTED;
		mutex_exit(&chanp->chan_mutex);
		mutex_exit(&root_chanp->chan_mutex);
	}

	if (root_idp && IS_UDP_CMID(root_idp)) {
		cma_chan_state_t	chan_state;

		/*
		 * Accepting the connect request, no more events for this
		 * connection.
		 */
		cma_handle_nomore_events(chanp);
		mutex_enter(&chanp->chan_mutex);
		chan_state = cma_get_chan_state(chanp);
		mutex_exit(&chanp->chan_mutex);
		/* If rdma_destroy_id() was called, destroy CMID */
		if (chan_state == SOL_CMA_CHAN_DESTROY_PENDING) {
			cma_destroy_id((struct rdma_cm_id *)chanp);
			return (EINVAL);
		}
	}

	if (chanp->chan_xport_type == SOL_CMA_XPORT_IB)
		ret = rdma_ib_accept(idp, conn_param);
#ifdef	IWARP_SUPPORT
	if (chanp->chan_xport_type == SOL_CMA_XPORT_IWARP)
		ret = rdma_iw_accept(idp, conn_param);
#endif	/* IWARP_SUPPORT */

	if (ret && root_idp && idp->ps == RDMA_PS_TCP) {
		void		*find_ret;
		avl_index_t	where;

		SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str,
		    "Delete from REQ AVL of %p IDP, idp %p",
		    root_idp, idp);
		mutex_enter(&root_chanp->chan_mutex);
		mutex_enter(&chanp->chan_mutex);
		if (chanp->chan_req_state == REQ_CMID_ACCEPTED) {
			ASSERT(cma_get_acpt_idp(root_idp,
			    chanp->chan_qp_hdl));
			avl_remove(&root_chanp->chan_acpt_avl_tree,
			    idp);
			find_ret = avl_find(&root_chanp->chan_req_avl_tree,
			    (void *)chanp->chan_qp_hdl, &where);
			if (find_ret) {
				chanp->chan_req_state = REQ_CMID_SERVER_NONE;
				mutex_exit(&chanp->chan_mutex);
				mutex_exit(&root_chanp->chan_mutex);
				SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
				    "DUPLICATE ENTRY in REQ AVL : root %p, "
				    "idp %p, session_id %p",
				    root_idp, idp, chanp->chan_session_id);
				return (EINVAL);
			}
			avl_insert(&root_chanp->chan_req_avl_tree, idp, where);
			chanp->chan_req_state = REQ_CMID_NOTIFIED;
		}
		mutex_exit(&chanp->chan_mutex);
		mutex_exit(&root_chanp->chan_mutex);
	}

	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "rdma_accept: ret %x", ret);
	return (ret);
}

int
rdma_notify(struct rdma_cm_id *idp, enum ib_event_type evt)
{
	sol_cma_chan_t		*chanp;

	ASSERT(idp);
	chanp = (sol_cma_chan_t *)idp;
	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "rdma_notify(%p, %x)", idp, evt);

	mutex_enter(&chanp->chan_mutex);
	if (cma_cas_chan_state(chanp, SOL_CMA_CHAN_ROUTE_RESLVD,
	    SOL_CMA_CHAN_EVENT_NOTIFIED)) {
		SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
		    "rdma_notify, Invalid state");
		mutex_exit(&chanp->chan_mutex);
		return (EINVAL);
	}
	mutex_exit(&chanp->chan_mutex);

	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "rdma_notify: ret 0");
	return (0);
}

int
rdma_reject(struct rdma_cm_id *idp, const void *priv_data,
    uint8_t priv_data_len)
{
	struct rdma_cm_id	*root_idp;
	sol_cma_chan_t		*root_chanp, *chanp;
	int			ret = EINVAL;

	ASSERT(idp);
	chanp = (sol_cma_chan_t *)idp;
	root_idp = CHAN_LISTEN_ROOT(chanp);
	root_chanp = (sol_cma_chan_t *)root_idp;
	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "rdma_reject(%p, %p)", idp,
	    priv_data, priv_data_len);

	mutex_enter(&chanp->chan_mutex);
	if (cma_cas_chan_state(chanp, SOL_CMA_CHAN_LISTEN,
	    SOL_CMA_CHAN_REJECT)) {
		SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
		    "rdma_accept, Invalid state");
		mutex_exit(&chanp->chan_mutex);
		return (EINVAL);
	}
	mutex_exit(&chanp->chan_mutex);

	if (root_idp) {
		SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "reject: root_idp %p"
		    "REQ AVL remove %p", root_chanp, idp);

		/*
		 * Remove from REQ AVL tree. If this CMID has been deleted,
		 * it maybe because of timeout. Return EINVAL.
		 */
		mutex_enter(&root_chanp->chan_mutex);
		mutex_enter(&chanp->chan_mutex);
		if (chanp->chan_req_state != REQ_CMID_NOTIFIED &&
		    chanp->chan_req_state != REQ_CMID_QUEUED) {
			mutex_exit(&chanp->chan_mutex);
			mutex_exit(&root_chanp->chan_mutex);
			SOL_OFS_DPRINTF_L3(sol_rdmacm_dbg_str,
			    "reject: root_idp %p chanp %p, not in REQ "
			    "AVL tree",  root_chanp, chanp);
			return (EINVAL);
		}
		ASSERT(cma_get_req_idp(root_idp, chanp->chan_session_id));
		avl_remove(&root_chanp->chan_req_avl_tree, idp);
		chanp->chan_req_state = REQ_CMID_SERVER_NONE;
		mutex_exit(&chanp->chan_mutex);
		mutex_exit(&root_chanp->chan_mutex);
	}

	if (chanp->chan_xport_type == SOL_CMA_XPORT_IB)
		ret = rdma_ib_reject(idp, priv_data, priv_data_len);
#ifdef	IWARP_SUPPORT
	if (chanp->chan_xport_type == SOL_CMA_XPORT_IWARP)
		ret = rdma_iw_reject(idp, priv_data, priv_data_len);
#endif	/* IWARP_SUPPORT */


	if (!ret && root_idp) {
		cma_chan_state_t	chan_state;

		/*
		 * Rejecting connect request, no more events for this
		 * connection.
		 */
		cma_handle_nomore_events(chanp);
		mutex_enter(&chanp->chan_mutex);
		chan_state = cma_get_chan_state(chanp);
		mutex_exit(&chanp->chan_mutex);
		/* If rdma_destroy_id() was called, destroy CMID */
		if (chan_state == SOL_CMA_CHAN_DESTROY_PENDING)
			cma_destroy_id((struct rdma_cm_id *)chanp);
	} else if (ret && root_idp) {
		avl_index_t	where;

		SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str,
		    "reject fail: Add to Req AVL of %p IDP, idp %p,"
		    "session_id %p", root_idp, idp,
		    chanp->chan_session_id);
		mutex_enter(&root_chanp->chan_mutex);
		mutex_enter(&chanp->chan_mutex);
		if (chanp->chan_req_state == REQ_CMID_SERVER_NONE) {
			if (avl_find(&root_chanp->chan_req_avl_tree,
			    (void *)chanp->chan_session_id, &where)) {
				mutex_exit(&chanp->chan_mutex);
				mutex_exit(&root_chanp->chan_mutex);
				SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
				    "DUPLICATE ENTRY in REQ AVL : root %p, "
				    "idp %p, session_id %p",
				    root_idp, idp, chanp->chan_session_id);
				return (EINVAL);
			}
			avl_insert(&root_chanp->chan_req_avl_tree,
			    (void *)idp, where);
			chanp->chan_req_state = REQ_CMID_NOTIFIED;
		}
		mutex_exit(&chanp->chan_mutex);
		mutex_exit(&root_chanp->chan_mutex);
	}

	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "rdma_reject: ret %x", ret);
	return (ret);
}

int
rdma_disconnect(struct rdma_cm_id *idp)
{
	sol_cma_chan_t		*chanp;
	int			ret = EINVAL;
	cma_chan_state_t	state;

	chanp = (sol_cma_chan_t *)idp;
	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "rdma_disconnect(%p)", idp);

	if (!idp)
		return (0);

	mutex_enter(&chanp->chan_mutex);
	if (!(SOL_CMAID_CONNECTED(chanp))) {
		SOL_OFS_DPRINTF_L3(sol_rdmacm_dbg_str,
		    "rdma_disconnect(%p) - Not connected!!", idp);
		mutex_exit(&chanp->chan_mutex);
		return (EINVAL);
	}
	state = cma_get_chan_state(chanp);
	cma_set_chan_state(chanp, SOL_CMA_CHAN_DISCONNECT);
	mutex_exit(&chanp->chan_mutex);

	if (chanp->chan_xport_type == SOL_CMA_XPORT_IB) {
		ret = rdma_ib_disconnect(idp);
#ifdef	IWARP_SUPPORT
	} else if (chanp->chan_xport_type == SOL_CMA_XPORT_IWARP) {
		ret = rdma_iw_disconnect(idp);
#endif	/* IWARP_SUPPORT */
	}

	if (ret) {
		mutex_enter(&chanp->chan_mutex);
		cma_set_chan_state(chanp, state);
		mutex_exit(&chanp->chan_mutex);
		return (ret);
	}

	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "rdma_disconnect: ret %x", ret);
	return (ret);
}

int
rdma_init_qp_attr(struct rdma_cm_id *idp, struct ib_qp_attr *qpattr,
    int *qp_attr_mask)
{
	sol_cma_chan_t		*chanp;
	int			ret = EINVAL;

	ASSERT(idp);
	chanp = (sol_cma_chan_t *)idp;
	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "rdma_init_qp_attr(%p, %p, %p)",
	    idp, qpattr, qp_attr_mask);

	if (chanp->chan_xport_type == SOL_CMA_XPORT_IB) {
		ret = rdma_ib_init_qp_attr(idp, qpattr, qp_attr_mask);
#ifdef	IWARP_SUPPORT
	} else if (chanp->chan_xport_type == SOL_CMA_XPORT_IWARP)
		ret = rdma_iw_init_qp_attr(idp, qpattr, qp_attr_mask);
#endif	/* IWARP_SUPPORT */
	} else {
		ret = EINVAL;
	}

	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str,
	    "rdma_init_qp_attr: ret %x", ret);

	return (ret);
}

int
rdma_join_multicast(struct rdma_cm_id *idp, struct sockaddr *addr,
    void *context)
{
	sol_cma_chan_t		*chanp;
	int			ret = ENODEV;
	cma_chan_state_t	state;

	ASSERT(idp);
	chanp = (sol_cma_chan_t *)idp;
	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str,
	    "rdma_join_multicast(%p, %p, %p)",
	    idp, addr, context);

	mutex_enter(&chanp->chan_mutex);
	state = cma_get_chan_state(chanp);
	if (state != SOL_CMA_CHAN_BOUND &&
	    state != SOL_CMA_CHAN_ROUTE_RESLVD &&
	    state != SOL_CMA_CHAN_ADDR_RESLVD) {
		SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
		    "rdma_join_multicast, Invalid state");
		mutex_exit(&chanp->chan_mutex);
		return (EINVAL);
	}

	if (chanp->chan_xport_type == SOL_CMA_XPORT_IB)
		ret = rdma_ib_join_multicast(idp, addr, context);
#ifdef	IWARP_SUPPORT
	/* No support for Multicast on iWARP */
	else if (chanp->chan_xport_type == SOL_CMA_XPORT_IWARP)
		ret = ENOTSUP;
#endif	/* IWARP_SUPPORT */
	mutex_exit(&chanp->chan_mutex);

	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str,
	    "rdma_join_multicast: ret %x", ret);
	return (ret);
}

void
rdma_leave_multicast(struct rdma_cm_id *idp, struct sockaddr *addr)
{
	sol_cma_chan_t		*chanp;
	cma_chan_state_t	state;

	ASSERT(idp);
	chanp = (sol_cma_chan_t *)idp;
	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "rdma_leave_multicast(%p, %p)",
	    idp, addr);

	mutex_enter(&chanp->chan_mutex);
	state = cma_get_chan_state(chanp);
	if (state != SOL_CMA_CHAN_BOUND &&
	    state != SOL_CMA_CHAN_ROUTE_RESLVD &&
	    state != SOL_CMA_CHAN_ADDR_RESLVD) {
		SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
		    "rdma_leave_multicast, Invalid state");
		mutex_exit(&chanp->chan_mutex);
		return;
	}

	if (chanp->chan_xport_type == SOL_CMA_XPORT_IB)
		rdma_ib_leave_multicast(idp, addr);
#ifdef	IWARP_SUPPORT
	/* No support for Multicast on iWARP */
	else if (chanp->chan_xport_type == SOL_CMA_XPORT_IWARP)
		SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
		    "rdma_leave_multicast, iWARP");
#endif	/* IWARP_SUPPORT */
	mutex_exit(&chanp->chan_mutex);

	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "rdma_join_multicast: ret");
}

/*
 * Functions to compare to rdma_cm_id *, used by AVL tree
 * routines.
 */
int
sol_cma_req_cmid_cmp(const void *p1, const void *p2)
{
	sol_cma_chan_t		*chanp;

	chanp = (sol_cma_chan_t *)p2;
	if (chanp->chan_session_id > p1)
		return (+1);
	else if (chanp->chan_session_id < p1)
		return (-1);
	else
		return (0);
}

int
sol_cma_cmid_cmp(const void *p1, const void *p2)
{
	sol_cma_chan_t		*chanp;

	chanp = (sol_cma_chan_t *)p2;
	if (chanp->chan_qp_hdl > p1)
		return (+1);
	else if (chanp->chan_qp_hdl < p1)
		return (-1);
	else
		return (0);
}

/*
 * Function to compare two sol_cma_glbl_listen_t *, used by
 * AVL tree routines.
 */
int
sol_cma_svc_cmp(const void *p1, const void *p2)
{
	sol_cma_glbl_listen_t	*listenp;
	uint64_t		sid;

	sid = *(uint64_t *)p1;
	listenp = (sol_cma_glbl_listen_t *)p2;
	if (listenp->cma_listen_chan_sid > sid)
		return (+1);
	else if (listenp->cma_listen_chan_sid < sid)
		return (-1);
	else
		return (0);
}

static int
cma_init_listen_root(sol_cma_chan_t *chanp)
{
	sol_cma_glbl_listen_t	*cma_listenp;
	sol_cma_listen_info_t	*chan_listenp;
	int			rc = 0;
	avl_index_t		where = 0;
	uint64_t		listen_sid;

	ASSERT(chanp);
	ASSERT(chanp->chan_listenp);
	chan_listenp = chanp->chan_listenp;

	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str,
	    "cma_init_listen_root(%p)", chanp);

	/*
	 * First search for matching global listen_info for this SID.
	 * If found with the same client handle, reuse the service
	 * handle, if matching SID is found with different client
	 * handle, return EINVAL.
	 */
	listen_sid = ibcma_init_root_sid(chanp);
	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str,
	    "cma_init_listen_root: search SID 0x%llx",
	    listen_sid);

	mutex_enter(&sol_cma_glob_mutex);
	cma_listenp = avl_find(&sol_cma_glbl_listen_tree,
	    (void *) &listen_sid, &where);
	if (cma_listenp && cma_listenp->cma_listen_clnt_hdl ==
	    chanp->chan_ib_client_hdl) {
		SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str,
		    "cma_init_listen_root: matching listenp %p SID 0x%llx",
		    cma_listenp, listen_sid);
		chan_listenp->listen_entry = add_genlist(
		    &cma_listenp->cma_listen_chan_list,
		    (uintptr_t)chanp, NULL);
		chan_listenp->chan_glbl_listen_info = cma_listenp;
		ibcma_copy_srv_hdl(chanp, cma_listenp);
		mutex_exit(&sol_cma_glob_mutex);
		return (0);
	} else if (cma_listenp) {
		SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
		    "cma_init_listen_root: listenp %p, SID 0x%llx match, "
		    "client hdl prev %p, new %p mismatch",
		    cma_listenp, listen_sid,
		    cma_listenp->cma_listen_clnt_hdl,
		    chanp->chan_ib_client_hdl);
		mutex_exit(&sol_cma_glob_mutex);
		return (EINVAL);
	}

	cma_listenp = kmem_zalloc(sizeof (sol_cma_glbl_listen_t), KM_SLEEP);
	init_genlist(&cma_listenp->cma_listen_chan_list);
	chan_listenp->listen_entry = add_genlist(
	    &cma_listenp->cma_listen_chan_list, (uintptr_t)chanp, NULL);
	chan_listenp->chan_glbl_listen_info = cma_listenp;
	cma_listenp->cma_listen_clnt_hdl = chanp->chan_ib_client_hdl;
	cma_listenp->cma_listen_chan_sid = listen_sid;

	rc = ibcma_init_root_chan(chanp, cma_listenp);
	if (rc) {
		mutex_exit(&sol_cma_glob_mutex);
		SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
		    "cma_init_listen_root: ibcma_init_root_chan failed!!");
		delete_genlist(&cma_listenp->cma_listen_chan_list,
		    chan_listenp->listen_entry);
		kmem_free(cma_listenp, sizeof (sol_cma_glbl_listen_t));
		return (rc);
	}
	avl_insert(&sol_cma_glbl_listen_tree, cma_listenp, where);
	mutex_exit(&sol_cma_glob_mutex);
	return (0);
}

static void
cma_fini_listen_root(sol_cma_chan_t *chanp)
{
	sol_cma_glbl_listen_t	*cma_listenp;
	sol_cma_listen_info_t	*chan_listenp;

	ASSERT(chanp);
	ASSERT(chanp->chan_listenp);
	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "cma_fini_listen_root(%p)",
	    chanp);
	chan_listenp = chanp->chan_listenp;
	cma_listenp = chan_listenp->chan_glbl_listen_info;
	ASSERT(cma_listenp);
	mutex_enter(&sol_cma_glob_mutex);
	delete_genlist(&cma_listenp->cma_listen_chan_list,
	    chan_listenp->listen_entry);
	if (genlist_empty(&cma_listenp->cma_listen_chan_list)) {
		if (ibcma_fini_root_chan(chanp) == 0) {
			avl_remove(&sol_cma_glbl_listen_tree,
			    cma_listenp);
			kmem_free(cma_listenp,
			    sizeof (sol_cma_glbl_listen_t));
		} else
			SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
			    "cma_fini_listen_root: "
			    "ibcma_fini_root_chan failed");
	}

	mutex_exit(&sol_cma_glob_mutex);
}

typedef struct cma_event_async_arg {
	struct rdma_cm_id	*idp;
	enum rdma_cm_event_type	event;
	int			status;
	union {
		struct rdma_conn_param	conn;
		struct rdma_ud_param	param;
	} un;
	struct rdma_conn_param	*conn_param;
	struct rdma_ud_param	*ud_paramp;
} cma_event_async_arg_t;

static void cma_generate_event_sync(struct rdma_cm_id *,
    enum rdma_cm_event_type, int, struct rdma_conn_param *,
    struct rdma_ud_param *);

void
cma_generate_event_thr(void *arg)
{
	cma_event_async_arg_t	*event_arg = (cma_event_async_arg_t *)arg;

	cma_generate_event_sync(event_arg->idp, event_arg->event,
	    event_arg->status, event_arg->conn_param,
	    event_arg->ud_paramp);

	if (event_arg->conn_param && event_arg->conn_param->private_data_len)
		kmem_free((void *)event_arg->conn_param->private_data,
		    event_arg->conn_param->private_data_len);
	if (event_arg->ud_paramp && event_arg->ud_paramp->private_data_len)
		kmem_free((void *)event_arg->ud_paramp->private_data,
		    event_arg->ud_paramp->private_data_len);
	kmem_free(arg, sizeof (cma_event_async_arg_t));
}

void
cma_generate_event(struct rdma_cm_id *idp, enum rdma_cm_event_type event,
    int status, struct rdma_conn_param *conn_param,
    struct rdma_ud_param *ud_paramp)
{
	cma_event_async_arg_t	*event_arg;
	sol_cma_chan_t		*chanp = (sol_cma_chan_t *)idp;

	/*
	 * Set SOL_CMA_CALLER_EVENT_PROGRESS to indicate event
	 * notification is in progress, so that races between
	 * rdma_destroy_id() and event notification is taken care.
	 *
	 * If rdma_destroy_id() has been called for this CMID, call
	 * cma_generate_event_sync() which skips notification to the
	 * consumer and handles the event.
	 */
	mutex_enter(&chanp->chan_mutex);
	chanp->chan_cmid_destroy_state |= SOL_CMA_CALLER_EVENT_PROGRESS;
	if (chanp->chan_cmid_destroy_state & SOL_CMA_CALLER_CMID_DESTROYED) {
		mutex_exit(&chanp->chan_mutex);
		cma_generate_event_sync(idp, event, status, conn_param,
		    ud_paramp);
		return;
	}
	mutex_exit(&chanp->chan_mutex);

	event_arg = kmem_zalloc(sizeof (cma_event_async_arg_t), KM_SLEEP);
	event_arg->idp = idp;
	event_arg->event = event;
	event_arg->status = status;
	event_arg->conn_param = NULL;
	event_arg->ud_paramp = NULL;
	if (conn_param && conn_param->private_data_len) {
		bcopy(conn_param, &(event_arg->un.conn),
		    sizeof (struct rdma_conn_param));
		event_arg->conn_param = &(event_arg->un.conn);
		event_arg->conn_param->private_data = kmem_zalloc(
		    conn_param->private_data_len, KM_SLEEP);
		bcopy(conn_param->private_data,
		    (void *)event_arg->conn_param->private_data,
		    conn_param->private_data_len);
	} else if (conn_param && conn_param->private_data_len == 0) {
		bcopy(conn_param, &(event_arg->un.conn),
		    sizeof (struct rdma_conn_param));
	} else if (ud_paramp) {
		bcopy(ud_paramp, &(event_arg->un.param),
		    sizeof (struct rdma_ud_param));
		event_arg->ud_paramp = &(event_arg->un.param);
		if (ud_paramp->private_data_len) {
			event_arg->ud_paramp->private_data = kmem_zalloc(
			    ud_paramp->private_data_len, KM_SLEEP);
			bcopy(ud_paramp->private_data,
			    (void *)event_arg->ud_paramp->private_data,
			    ud_paramp->private_data_len);
		} else if (ud_paramp->private_data) {
			event_arg->ud_paramp->private_data =
			    ud_paramp->private_data;
		}
	}

	if (taskq_dispatch(system_taskq, cma_generate_event_thr,
	    (void *)event_arg, TQ_SLEEP) == TASKQID_INVALID) {
		SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
		    "generate_event_async: taskq_dispatch() failed!!");
		mutex_enter(&chanp->chan_mutex);
		chanp->chan_cmid_destroy_state &=
		    ~SOL_CMA_CALLER_EVENT_PROGRESS;
		if (chanp->chan_cmid_destroy_state &
		    SOL_CMA_CALLER_CMID_DESTROYED)
			cv_broadcast(&chanp->chan_destroy_cv);
		mutex_exit(&chanp->chan_mutex);
	}
}

static void
cma_generate_event_sync(struct rdma_cm_id *idp, enum rdma_cm_event_type event,
    int status, struct rdma_conn_param *conn_param,
    struct rdma_ud_param *ud_paramp)
{
	struct rdma_cm_event	cm_event;
	sol_cma_chan_t		*chanp = (sol_cma_chan_t *)idp;
	struct rdma_cm_id	*root_idp = NULL;
	sol_cma_chan_t		*root_chanp;
	int			ret;
	cma_chan_state_t	chan_state;

	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "generate_event_sync(%p, %x, "
	    "%x, %p, %p", idp, event, status, conn_param, ud_paramp);

	bzero(&cm_event, sizeof (cm_event));
	cm_event.event = event;
	cm_event.status = status;
	if (conn_param)
		bcopy((void *)conn_param, (void *)(&(cm_event.param.conn)),
		    sizeof (struct rdma_conn_param));
	else if (ud_paramp)
		bcopy((void *)ud_paramp, (void *)(&(cm_event.param.ud)),
		    sizeof (struct rdma_ud_param));

	/*
	 * If the consumer has destroyed the context for this CMID -
	 * do not notify, skip to handling the sol_ofs specific
	 * handling of the event.
	 */
	mutex_enter(&chanp->chan_mutex);
	if (chanp->chan_cmid_destroy_state & SOL_CMA_CALLER_CMID_DESTROYED) {
		mutex_exit(&chanp->chan_mutex);
		goto ofs_consume_event;
	}
	mutex_exit(&chanp->chan_mutex);

	root_idp = CHAN_LISTEN_ROOT(chanp);
	root_chanp = (sol_cma_chan_t *)root_idp;
	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "gen_event: root_idp %p",
	    root_idp);

	if (event == RDMA_CM_EVENT_CONNECT_REQUEST) {
		/*
		 * Update chan_req_state for the REQ CMID. Decrement
		 * count of REQ CMIDs not notifed to consumer.
		 */
		ASSERT(root_idp);
		mutex_enter(&root_chanp->chan_mutex);
		root_chanp->chan_req_cnt--;
#ifdef	DEBUG
		SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str,
		    "Dec req_cnt of %p IDP, idp %p, req_cnt %x",
		    root_idp, idp, root_chanp->chan_req_cnt);
#endif
		mutex_exit(&root_chanp->chan_mutex);
	}

	/* Pass the event to the client */
	ret = (idp->event_handler) (idp, &cm_event);

	if (ret) {
		/*
		 * If the consumer returned failure :
		 * 	CONNECT_REQUEST :
		 * 	1. rdma_disconnect() to disconnect connection.
		 * 	2. wakeup destroy, if destroy has been called
		 * 		for this CMID
		 * 	3. Destroy CMID if rdma_destroy has not been
		 * 		called.
		 * 	DISCONNECTED :
		 * 	1. call cma_handle_nomore_events() to cleanup
		 * 	Other Events :
		 * 	1. Client is expected to destroy the CMID.
		 */
		if (event == RDMA_CM_EVENT_CONNECT_REQUEST) {
			SOL_OFS_DPRINTF_L4(sol_rdmacm_dbg_str,
			    "cma_generate_event_async: consumer failed %d "
			    "event", event);
			if (rdma_disconnect(idp)) {
				SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
				    "generate_event_async: rdma_disconnect "
				    "failed");
			}
			mutex_enter(&chanp->chan_mutex);
			ASSERT(SOL_IS_SERVER_CMID(chanp));
			chanp->chan_req_state = REQ_CMID_SERVER_NONE;
			chanp->chan_cmid_destroy_state &=
			    ~SOL_CMA_CALLER_EVENT_PROGRESS;
			if (chanp->chan_cmid_destroy_state &
			    SOL_CMA_CALLER_CMID_DESTROYED) {
				cv_broadcast(&chanp->chan_destroy_cv);
				mutex_exit(&chanp->chan_mutex);
			} else {
				mutex_exit(&chanp->chan_mutex);
				rdma_destroy_id(idp);
			}
		} else if (event == RDMA_CM_EVENT_DISCONNECTED) {
			SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
			    "generate_event_async: consumer failed %d event",
			    event);
			cma_handle_nomore_events(chanp);
			mutex_enter(&chanp->chan_mutex);
			chan_state = cma_get_chan_state(chanp);
			chanp->chan_cmid_destroy_state &=
			    ~SOL_CMA_CALLER_EVENT_PROGRESS;
			if (chanp->chan_cmid_destroy_state &
			    SOL_CMA_CALLER_CMID_DESTROYED) {
				cv_broadcast(&chanp->chan_destroy_cv);
				mutex_exit(&chanp->chan_mutex);
			} else if (chan_state == SOL_CMA_CHAN_DESTROY_PENDING) {
				/* rdma_destroy_id() called: destroy CMID */
				mutex_exit(&chanp->chan_mutex);
				cma_destroy_id((struct rdma_cm_id *)chanp);
			} else
				mutex_exit(&chanp->chan_mutex);
		} else {
			SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
			    "generate_event_async: consumer failed %d event",
			    event);
		}

		return;
	}
ofs_consume_event:
	if (event == RDMA_CM_EVENT_DISCONNECTED) {
		cma_chan_state_t	chan_state;

		cma_handle_nomore_events(chanp);
		mutex_enter(&chanp->chan_mutex);
		chan_state = cma_get_chan_state(chanp);
		chanp->chan_cmid_destroy_state &=
		    ~SOL_CMA_CALLER_EVENT_PROGRESS;
		if (chanp->chan_cmid_destroy_state &
		    SOL_CMA_CALLER_CMID_DESTROYED) {
			cv_broadcast(&chanp->chan_destroy_cv);
			mutex_exit(&chanp->chan_mutex);
		} else if (chan_state == SOL_CMA_CHAN_DESTROY_PENDING) {
			/* If rdma_destroy_id() was called, destroy CMID */
			mutex_exit(&chanp->chan_mutex);
			cma_destroy_id((struct rdma_cm_id *)chanp);
		} else
			mutex_exit(&chanp->chan_mutex);
		return;
	} else if (IS_UDP_CMID(idp) && event == RDMA_CM_EVENT_UNREACHABLE) {
		/*
		 * If rdma_destroy_id() was called, destroy CMID
		 * If not chan_connect_flag/ chan_req_state has already been
		 * set to indicate that it can be deleted.
		 */
		mutex_enter(&chanp->chan_mutex);
		chan_state = cma_get_chan_state(chanp);
		chanp->chan_cmid_destroy_state &=
		    ~SOL_CMA_CALLER_EVENT_PROGRESS;
		if (chanp->chan_cmid_destroy_state &
		    SOL_CMA_CALLER_CMID_DESTROYED) {
			cv_broadcast(&chanp->chan_destroy_cv);
			mutex_exit(&chanp->chan_mutex);
		} else if (chan_state == SOL_CMA_CHAN_DESTROY_PENDING) {
			mutex_exit(&chanp->chan_mutex);
			cma_destroy_id(idp);
		} else
			mutex_exit(&chanp->chan_mutex);
		return;
	}

	mutex_enter(&chanp->chan_mutex);
	chanp->chan_cmid_destroy_state &= ~SOL_CMA_CALLER_EVENT_PROGRESS;
	if (chanp->chan_cmid_destroy_state & SOL_CMA_CALLER_CMID_DESTROYED)
		cv_broadcast(&chanp->chan_destroy_cv);
	mutex_exit(&chanp->chan_mutex);
}

/* Local Static functions */
static struct rdma_cm_id *
cma_alloc_chan(rdma_cm_event_handler evt_hdlr, void *context,
    enum rdma_port_space ps)
{
	struct rdma_cm_id	*rdma_idp;
	sol_cma_chan_t		*chanp;

	chanp = kmem_zalloc(sizeof (sol_cma_chan_t), KM_SLEEP);
	mutex_init(&chanp->chan_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&chanp->chan_destroy_cv, NULL, CV_DRIVER, NULL);
	rdma_idp = &(chanp->chan_rdma_cm);
	rdma_idp->context = context;
	rdma_idp->ps = ps;
	rdma_idp->event_handler = evt_hdlr;
	mutex_enter(&chanp->chan_mutex);
	cma_set_chan_state(chanp, SOL_CMA_CHAN_IDLE);
	avl_create(&chanp->chan_req_avl_tree, sol_cma_req_cmid_cmp,
	    sizeof (sol_cma_chan_t),
	    offsetof(sol_cma_chan_t, chan_req_avl_node));
	avl_create(&chanp->chan_acpt_avl_tree, sol_cma_cmid_cmp,
	    sizeof (sol_cma_chan_t),
	    offsetof(sol_cma_chan_t, chan_acpt_avl_node));
	mutex_exit(&chanp->chan_mutex);

	return (rdma_idp);
}

/* Change the state of sol_cma_chan_t */
static void
cma_set_chan_state(sol_cma_chan_t *chanp, cma_chan_state_t newstate)
{
	ASSERT(MUTEX_HELD(&chanp->chan_mutex));
	chanp->chan_state = newstate;
}

cma_chan_state_t
cma_get_chan_state(sol_cma_chan_t *chanp)
{
	ASSERT(MUTEX_HELD(&chanp->chan_mutex));
	return (chanp->chan_state);
}

/* Check & Swap the state of sol_ucma_chan_t */
static int
cma_cas_chan_state(sol_cma_chan_t *chanp, cma_chan_state_t prevstate,
    cma_chan_state_t newstate)
{
	int	ret = 0;

	ASSERT(MUTEX_HELD(&chanp->chan_mutex));
	if (chanp->chan_state != prevstate)
		ret = -1;
	else
		chanp->chan_state = newstate;

	return (ret);
}

static void
cma_free_listen_list(struct rdma_cm_id *idp)
{
	genlist_entry_t	*entry;
	sol_cma_chan_t	*chanp = (sol_cma_chan_t *)idp;

	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "cma_free_listen_list(%p)", idp);
	mutex_enter(&chanp->chan_mutex);
	entry = remove_genlist_head(&(CHAN_LISTEN_LIST(chanp)));
	mutex_exit(&chanp->chan_mutex);
	while (entry) {
		sol_cma_chan_t	*ep_chanp;

		ep_chanp = (sol_cma_chan_t *)entry->data;
		SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "fini_ep_chan: %p",
		    ep_chanp);
		if (ibcma_fini_ep_chan(ep_chanp) == 0) {
			genlist_entry_t		*entry1;
			struct ib_device	*device;
			cma_device_t		*cma_device;

			ASSERT(ep_chanp->chan_listenp);
			mutex_enter(&ep_chanp->chan_mutex);
			entry1 = ep_chanp->chan_listenp->listen_ep_dev_entry;
			device = ep_chanp->chan_listenp->listen_ep_device;
			ASSERT(device);
			cma_device = device->data;
			delete_genlist(&cma_device->cma_epchan_list,
			    entry1);
			sol_cma_release_device(
			    (struct rdma_cm_id *)ep_chanp);
			mutex_exit(&ep_chanp->chan_mutex);
			if (ep_chanp->chan_listenp)
				kmem_free(ep_chanp->chan_listenp,
				    sizeof (sol_cma_listen_info_t));

			mutex_destroy(&ep_chanp->chan_mutex);
			cv_destroy(&ep_chanp->chan_destroy_cv);
			kmem_free(ep_chanp, sizeof (sol_cma_chan_t));
			kmem_free(entry, sizeof (genlist_entry_t));
		}

		mutex_enter(&chanp->chan_mutex);
		entry = remove_genlist_head(&(CHAN_LISTEN_LIST(chanp)));
		mutex_exit(&chanp->chan_mutex);
	}
}

/*
 * Destroy a listening CMID when :
 *	a. All CONNECTION REQUEST recieved have been rejected
 *	   or closed.
 *	b. No CONNECTION REQUEST recieved.
 * Do not destroy a listening CMID when :
 *	a. CONNECTION REQUEST has been recieved and not been
 *	   accepted from the passive / server side.
 *	b. CONNECTION REQUEST has been recieved and has been
 *	   accepted from the passive server side.
 *	Mark the listening CMID as destroy pending.
 *
 * For CMIDs created for rdma_connect() or created for a
 * CONNECT request, destroy the CMID only when :
 *       CONNECTION has been closed or rejected.
 *
 *       Mark the CMID as destroy pending.
 *
 * When a connection is rejected or closed :
 *	Check if flag indicates - destroy pending,
 *	cma_destroy_id() is called, this also does
 *
 *	If there is a listening CMID assosiated with it,
 *	   call cma_destroy_if(listen_cmid);
 */
void
cma_destroy_id(struct rdma_cm_id *idp)
{
	sol_cma_chan_t		*chanp = (sol_cma_chan_t *)idp;
	cma_chan_state_t	state;
	ulong_t			acpt_nodes, req_nodes;

	mutex_enter(&chanp->chan_mutex);
	acpt_nodes = avl_numnodes(&chanp->chan_acpt_avl_tree);
	req_nodes = avl_numnodes(&chanp->chan_req_avl_tree);
	state = cma_get_chan_state(chanp);
	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "cma_destroy_id(%p)- "
	    "est CMIDs %ld, req CMID %ld, listen_root %p, state %x, %x",
	    idp, acpt_nodes, req_nodes, chanp->listen_root,
	    state, chanp->chan_req_state);

	/*
	 * If there are either REQ recieved or Established CMIDs just return.
	 * rdma_destroy() for these CMIDs can be called by client later.
	 */
	if (acpt_nodes || req_nodes) {
		cma_set_chan_state(chanp, SOL_CMA_CHAN_DESTROY_PENDING);
		mutex_exit(&chanp->chan_mutex);
		return;
	}
	cma_set_chan_state(chanp, SOL_CMA_CHAN_DESTROYING);
	avl_destroy(&chanp->chan_req_avl_tree);
	avl_destroy(&chanp->chan_acpt_avl_tree);

	mutex_exit(&chanp->chan_mutex);
	if (idp->route.path_rec) {
		kmem_free(idp->route.path_rec,
		    sizeof (struct ib_sa_path_rec) * idp->route.num_paths);
		idp->route.path_rec = NULL;
	}

	switch (chanp->chan_xport_type) {
	case SOL_CMA_XPORT_NONE :
		break;
	case SOL_CMA_XPORT_IB :
		rdma_ib_destroy_id(idp);
		break;
#ifdef	IWARP_SUPPORT
	case SOL_CMA_XPORT_IWARP :
		rdma_iw_destroy_id(idp);
		break;
#endif	/* IWARP_SUPPORT */
	default :
		SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
		    "cma_destroy_id: Unsupported xport type %x",
		    chanp->chan_xport_type);
		break;
	}

	/*
	 * Flush out & Free all listeners wrt to this ID
	 * No locking is required as this code is executed
	 * all REQ CMIDs have been destroyed. listen_list
	 * will therefore not be modified during this loop.
	 */
	if (chanp->chan_listenp) {
		cma_free_listen_list(idp);
		cma_fini_listen_root(chanp);
		kmem_free((void *)chanp->chan_listenp,
		    sizeof (sol_cma_listen_info_t));
		chanp->chan_listenp = NULL;
	}

	if (chanp->listen_root) {
		struct rdma_cm_id	*root_idp;
		sol_cma_chan_t		*root_chanp;

		root_idp = chanp->listen_root;
		root_chanp = (sol_cma_chan_t *)root_idp;
		mutex_enter(&root_chanp->chan_mutex);
		state = cma_get_chan_state(root_chanp);
		acpt_nodes = avl_numnodes(&root_chanp->chan_acpt_avl_tree);
		req_nodes = avl_numnodes(&root_chanp->chan_req_avl_tree);
		mutex_exit(&root_chanp->chan_mutex);
		SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "cma_destroy_id(%p)-"
		    " root idp %p, state %x, acpt_nodes %ld, req_nodes %ld",
		    idp, root_idp, state, acpt_nodes, req_nodes);

		if (state == SOL_CMA_CHAN_DESTROY_PENDING &&
		    req_nodes == 0UL && acpt_nodes == 0UL) {
			mutex_enter(&root_chanp->chan_mutex);
			root_chanp->chan_req_state = REQ_CMID_SERVER_NONE;
			mutex_exit(&root_chanp->chan_mutex);
			cma_destroy_id(root_idp);
		} else if (state == SOL_CMA_CHAN_DESTROY_WAIT &&
		    req_nodes == 0UL && acpt_nodes == 0UL) {
			mutex_enter(&root_chanp->chan_mutex);
			cma_set_chan_state(root_chanp,
			    SOL_CMA_CHAN_DESTROY_PENDING);
			root_chanp->chan_req_state = REQ_CMID_SERVER_NONE;
			cv_broadcast(&root_chanp->chan_destroy_cv);
			mutex_exit(&root_chanp->chan_mutex);
		}
	}

	mutex_destroy(&chanp->chan_mutex);
	cv_destroy(&chanp->chan_destroy_cv);
	kmem_free(chanp, sizeof (sol_cma_chan_t));
}

/*
 * Server TCP disconnect for an established channel.
 *	If destroy_id() has been called for the listening
 *	CMID and there are no more CMIDs with pending
 *	events corresponding to the listening CMID, free
 *	the listening CMID.
 *
 */
static void
cma_handle_nomore_events(sol_cma_chan_t *chanp)
{
	struct rdma_cm_id	*idp, *root_idp;
	sol_cma_chan_t		*root_chanp;
	cma_chan_state_t	state;
	ulong_t			req_nodes, acpt_nodes;

	idp = (struct rdma_cm_id *)chanp;
	root_idp = CHAN_LISTEN_ROOT(chanp);
	root_chanp = (sol_cma_chan_t *)root_idp;
	if (!root_chanp)
		return;

	mutex_enter(&root_chanp->chan_mutex);
	mutex_enter(&chanp->chan_mutex);
	CHAN_LISTEN_ROOT(chanp) = NULL;
	root_chanp->chan_req_total_cnt--;

	/*
	 * Removal of CMID from the AVL trees should already have been done
	 * by now. Below code mainly as a  safety net.
	 */
	if (chanp->chan_req_state == REQ_CMID_ACCEPTED) {
		ASSERT(chanp->chan_qp_hdl);
		ASSERT(cma_get_acpt_idp(root_idp,
		    chanp->chan_qp_hdl));
		avl_remove(&root_chanp->chan_acpt_avl_tree, idp);
		chanp->chan_req_state = REQ_CMID_SERVER_NONE;
	}
	if (REQ_CMID_IN_REQ_AVL_TREE(chanp)) {
		ASSERT(chanp->chan_session_id);
		ASSERT(cma_get_req_idp(root_idp,
		    chanp->chan_session_id));
		avl_remove(&root_chanp->chan_req_avl_tree, idp);
		chanp->chan_req_state = REQ_CMID_SERVER_NONE;
	}

	state = cma_get_chan_state(root_chanp);
	req_nodes = avl_numnodes(&root_chanp->chan_req_avl_tree);
	acpt_nodes = avl_numnodes(&root_chanp->chan_acpt_avl_tree);
	mutex_exit(&chanp->chan_mutex);
	mutex_exit(&root_chanp->chan_mutex);
	if (state == SOL_CMA_CHAN_DESTROY_PENDING && req_nodes == 0UL &&
	    acpt_nodes == 0UL)
		cma_destroy_id(root_idp);
}

extern int ib_modify_qp(struct ib_qp *, struct ib_qp_attr *, int);
extern int rdma_init_qp_attr(struct rdma_cm_id *, struct ib_qp_attr *,
    int *);

static int
cma_init_ud_qp(sol_cma_chan_t *chanp, struct ib_qp *qp)
{
	struct ib_qp_attr qp_attr;
	int qp_attr_mask, ret;

	qp_attr.qp_state = IB_QPS_INIT;
	ret = rdma_init_qp_attr(&chanp->chan_rdma_cm, &qp_attr, &qp_attr_mask);
	if (ret)
		return (ret);

	ret = ib_modify_qp(qp, &qp_attr, qp_attr_mask);
	if (ret)
		return (ret);

	qp_attr.qp_state = IB_QPS_RTR;
	ret = ib_modify_qp(qp, &qp_attr, IB_QP_STATE);
	if (ret)
		return (ret);

	qp_attr.qp_state = IB_QPS_RTS;
	qp_attr.sq_psn = 0;
	ret = ib_modify_qp(qp, &qp_attr, IB_QP_STATE | IB_QP_SQ_PSN);

	return (ret);
}

static int
cma_init_conn_qp(sol_cma_chan_t *chanp, struct ib_qp *qp)
{
	struct ib_qp_attr qp_attr;
	int qp_attr_mask, ret;

	qp_attr.qp_state = IB_QPS_INIT;
	ret = rdma_init_qp_attr(&chanp->chan_rdma_cm, &qp_attr, &qp_attr_mask);
	if (ret)
		return (ret);

	return (ib_modify_qp(qp, &qp_attr, qp_attr_mask));
}

static inline int
cma_is_ud_ps(enum rdma_port_space ps)
{
	return (ps == RDMA_PS_UDP || ps == RDMA_PS_IPOIB);
}

int
rdma_create_qp(struct rdma_cm_id *idp, struct ib_pd *pd,
    struct ib_qp_init_attr *qp_init_attr)
{
	sol_cma_chan_t	*chanp;
	struct ib_qp	*qp;
	int		ret;
	ofs_client_t	*dev_ofs_client;

	ASSERT(idp);
	chanp = (sol_cma_chan_t *)idp;
	if (idp->device->node_guid != pd->device->node_guid)
		return (-EINVAL);

	dev_ofs_client = (ofs_client_t *)pd->device->clnt_hdl;
	rdma_map_id2clnthdl(idp, dev_ofs_client->ibt_hdl, NULL);

	qp = ib_create_qp(pd, qp_init_attr);
	if ((uintptr_t)qp >= (uintptr_t)-0xFFF) {
		return ((intptr_t)qp);
	}
	rdma_map_id2qphdl(idp, (void *)qp->ibt_qp);

	if (cma_is_ud_ps(idp->ps)) {
		ret = cma_init_ud_qp(chanp, qp);
	} else {
		ret = cma_init_conn_qp(chanp, qp);
	}

	if (ret) {
		goto err;
	}

	idp->qp = qp;
	chanp->chan_qp_num = qp->qp_num;
	chanp->chan_is_srq = (qp->srq != NULL);
	return (0);
err:
	(void) ib_destroy_qp(qp);
	return (ret);
}

void
rdma_destroy_qp(struct rdma_cm_id *idp)
{
	ASSERT(idp);
	(void) ib_destroy_qp(idp->qp);
	idp->qp = NULL;
}
