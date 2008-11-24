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

#include <sys/cpuvar.h>
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>

#include <sys/socket.h>
#include <sys/strsubr.h>
#include <sys/sysmacros.h>

#include <sys/socketvar.h>
#include <netinet/in.h>

#include <sys/idm/idm.h>
#include <sys/idm/idm_so.h>

#define	IDM_NAME_VERSION	"iSCSI Data Mover"

extern struct mod_ops mod_miscops;
extern struct mod_ops mod_miscops;

static struct modlmisc modlmisc = {
	&mod_miscops,	/* Type of module */
	IDM_NAME_VERSION
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

extern int idm_task_compare(const void *t1, const void *t2);
extern void idm_wd_thread(void *arg);

static int _idm_init(void);
static int _idm_fini(void);
static void idm_buf_bind_in_locked(idm_task_t *idt, idm_buf_t *buf);
static void idm_buf_bind_out_locked(idm_task_t *idt, idm_buf_t *buf);
static void idm_buf_unbind_in_locked(idm_task_t *idt, idm_buf_t *buf);
static void idm_buf_unbind_out_locked(idm_task_t *idt, idm_buf_t *buf);
static void idm_task_abort_one(idm_conn_t *ic, idm_task_t *idt,
    idm_abort_type_t abort_type);
static void idm_task_aborted(idm_task_t *idt, idm_status_t status);

boolean_t idm_conn_logging = 0;
boolean_t idm_svc_logging = 0;

/*
 * Potential tuneable for the maximum number of tasks.  Default to
 * IDM_TASKIDS_MAX
 */

uint32_t	idm_max_taskids = IDM_TASKIDS_MAX;

/*
 * Global list of transport handles
 *   These are listed in preferential order, so we can simply take the
 *   first "it_conn_is_capable" hit. Note also that the order maps to
 *   the order of the idm_transport_type_t list.
 */
idm_transport_t idm_transport_list[] = {

	/* iSER on InfiniBand transport handle */
	{IDM_TRANSPORT_TYPE_ISER,	/* type */
	"/devices/ib/iser@0:iser",	/* device path */
	NULL,				/* LDI handle */
	NULL,				/* transport ops */
	NULL},				/* transport caps */

	/* IDM native sockets transport handle */
	{IDM_TRANSPORT_TYPE_SOCKETS,	/* type */
	NULL,				/* device path */
	NULL,				/* LDI handle */
	NULL,				/* transport ops */
	NULL}				/* transport caps */

};

int
_init(void)
{
	int rc;

	if ((rc = _idm_init()) != 0) {
		return (rc);
	}

	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	int rc;

	if ((rc = _idm_fini()) != 0) {
		return (rc);
	}

	if ((rc = mod_remove(&modlinkage)) != 0) {
		return (rc);
	}

	return (rc);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * idm_transport_register()
 *
 * Provides a mechanism for an IDM transport driver to register its
 * transport ops and caps with the IDM kernel module. Invoked during
 * a transport driver's attach routine.
 */
idm_status_t
idm_transport_register(idm_transport_attr_t *attr)
{
	ASSERT(attr->it_ops != NULL);
	ASSERT(attr->it_caps != NULL);

	switch (attr->type) {
	/* All known non-native transports here; for now, iSER */
	case IDM_TRANSPORT_TYPE_ISER:
		idm_transport_list[attr->type].it_ops	= attr->it_ops;
		idm_transport_list[attr->type].it_caps	= attr->it_caps;
		return (IDM_STATUS_SUCCESS);

	default:
		cmn_err(CE_NOTE, "idm: unknown transport type (0x%x) in "
		    "idm_transport_register", attr->type);
		return (IDM_STATUS_SUCCESS);
	}
}

/*
 * idm_ini_conn_create
 *
 * This function is invoked by the iSCSI layer to create a connection context.
 * This does not actually establish the socket connection.
 *
 * cr - Connection request parameters
 * new_con - Output parameter that contains the new request if successful
 *
 */
idm_status_t
idm_ini_conn_create(idm_conn_req_t *cr, idm_conn_t **new_con)
{
	idm_transport_t		*it;
	idm_conn_t		*ic;
	int			rc;

	it = idm_transport_lookup(cr);

retry:
	ic = idm_conn_create_common(CONN_TYPE_INI, it->it_type,
	    &cr->icr_conn_ops);

	bcopy(&cr->cr_ini_dst_addr, &ic->ic_ini_dst_addr,
	    sizeof (cr->cr_ini_dst_addr));

	/* create the transport-specific connection components */
	rc = it->it_ops->it_ini_conn_create(cr, ic);
	if (rc != IDM_STATUS_SUCCESS) {
		/* cleanup the failed connection */
		idm_conn_destroy_common(ic);
		kmem_free(ic, sizeof (idm_conn_t));

		/*
		 * It is possible for an IB client to connect to
		 * an ethernet-only client via an IB-eth gateway.
		 * Therefore, if we are attempting to use iSER and
		 * fail, retry with sockets before ultimately
		 * failing the connection.
		 */
		if (it->it_type == IDM_TRANSPORT_TYPE_ISER) {
			it = &idm_transport_list[IDM_TRANSPORT_TYPE_SOCKETS];
			goto retry;
		}

		return (IDM_STATUS_FAIL);
	}

	*new_con = ic;

	mutex_enter(&idm.idm_global_mutex);
	list_insert_tail(&idm.idm_ini_conn_list, ic);
	mutex_exit(&idm.idm_global_mutex);

	return (IDM_STATUS_SUCCESS);
}

/*
 * idm_ini_conn_destroy
 *
 * Releases any resources associated with the connection.  This is the
 * complement to idm_ini_conn_create.
 * ic - idm_conn_t structure representing the relevant connection
 *
 */
void
idm_ini_conn_destroy(idm_conn_t *ic)
{
	mutex_enter(&idm.idm_global_mutex);
	list_remove(&idm.idm_ini_conn_list, ic);
	mutex_exit(&idm.idm_global_mutex);

	ic->ic_transport_ops->it_ini_conn_destroy(ic);
	idm_conn_destroy_common(ic);
}

/*
 * idm_ini_conn_connect
 *
 * Establish connection to the remote system identified in idm_conn_t.
 * The connection parameters including the remote IP address were established
 * in the call to idm_ini_conn_create.
 *
 * ic - idm_conn_t structure representing the relevant connection
 *
 * Returns success if the connection was established, otherwise some kind
 * of meaningful error code.
 *
 * Upon return the initiator can send a "login" request when it is ready.
 */
idm_status_t
idm_ini_conn_connect(idm_conn_t *ic)
{
	idm_status_t	rc;

	rc = idm_conn_sm_init(ic);
	if (rc != IDM_STATUS_SUCCESS) {
		return (ic->ic_conn_sm_status);
	}
	/* Kick state machine */
	idm_conn_event(ic, CE_CONNECT_REQ, NULL);

	/* Wait for login flag */
	mutex_enter(&ic->ic_state_mutex);
	while (!(ic->ic_state_flags & CF_LOGIN_READY) &&
	    !(ic->ic_state_flags & CF_ERROR)) {
		cv_wait(&ic->ic_state_cv, &ic->ic_state_mutex);
	}
	mutex_exit(&ic->ic_state_mutex);

	if (ic->ic_state_flags & CF_ERROR) {
		/* ic->ic_conn_sm_status will contains failure status */
		return (ic->ic_conn_sm_status);
	}

	/* Ready to login */
	ASSERT(ic->ic_state_flags & CF_LOGIN_READY);
	(void) idm_notify_client(ic, CN_READY_FOR_LOGIN, NULL);

	return (IDM_STATUS_SUCCESS);
}

/*
 * idm_ini_conn_sm_fini_task()
 *
 * Dispatch a thread on the global taskq to tear down an initiator connection's
 * state machine. Note: We cannot do this from the disconnect thread as we will
 * end up in a situation wherein the thread is running on a taskq that it then
 * attempts to destroy.
 */
static void
idm_ini_conn_sm_fini_task(void *ic_void)
{
	idm_conn_sm_fini((idm_conn_t *)ic_void);
}

/*
 * idm_ini_conn_disconnect
 *
 * Forces a connection (previously established using idm_ini_conn_connect)
 * to perform a controlled shutdown, cleaning up any outstanding requests.
 *
 * ic - idm_conn_t structure representing the relevant connection
 *
 * This is synchronous and it will return when the connection has been
 * properly shutdown.
 */
/* ARGSUSED */
void
idm_ini_conn_disconnect(idm_conn_t *ic)
{
	mutex_enter(&ic->ic_state_mutex);

	if (ic->ic_state_flags == 0) {
		/* already disconnected */
		mutex_exit(&ic->ic_state_mutex);
		return;
	}
	ic->ic_state_flags = 0;
	ic->ic_conn_sm_status = 0;
	mutex_exit(&ic->ic_state_mutex);

	/* invoke the transport-specific conn_destroy */
	(void) ic->ic_transport_ops->it_ini_conn_disconnect(ic);

	/* teardown the connection sm */
	(void) taskq_dispatch(idm.idm_global_taskq, &idm_ini_conn_sm_fini_task,
	    (void *)ic, TQ_SLEEP);
}

/*
 * idm_tgt_svc_create
 *
 * The target calls this service to obtain a service context for each available
 * transport, starting a service of each type related to the IP address and port
 * passed. The idm_svc_req_t contains the service parameters.
 */
idm_status_t
idm_tgt_svc_create(idm_svc_req_t *sr, idm_svc_t **new_svc)
{
	idm_transport_type_t	type;
	idm_transport_t		*it;
	idm_svc_t		*is;
	int			rc;

	*new_svc = NULL;
	is = kmem_zalloc(sizeof (idm_svc_t), KM_SLEEP);

	/* Initialize transport-agnostic components of the service handle */
	is->is_svc_req = *sr;
	mutex_init(&is->is_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&is->is_cv, NULL, CV_DEFAULT, NULL);
	mutex_init(&is->is_count_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&is->is_count_cv, NULL, CV_DEFAULT, NULL);
	idm_refcnt_init(&is->is_refcnt, is);

	/*
	 * Make sure all available transports are setup.  We call this now
	 * instead of at initialization time in case IB has become available
	 * since we started (hotplug, etc).
	 */
	idm_transport_setup(sr->sr_li);

	/*
	 * Loop through the transports, configuring the transport-specific
	 * components of each one.
	 */
	for (type = 0; type < IDM_TRANSPORT_NUM_TYPES; type++) {

		it = &idm_transport_list[type];
		/*
		 * If it_ops is NULL then the transport is unconfigured
		 * and we shouldn't try to start the service.
		 */
		if (it->it_ops == NULL) {
			continue;
		}

		rc = it->it_ops->it_tgt_svc_create(sr, is);
		if (rc != IDM_STATUS_SUCCESS) {
			/* Teardown any configured services */
			while (type--) {
				it = &idm_transport_list[type];
				if (it->it_ops == NULL) {
					continue;
				}
				it->it_ops->it_tgt_svc_destroy(is);
			}
			/* Free the svc context and return */
			kmem_free(is, sizeof (idm_svc_t));
			return (rc);
		}
	}

	*new_svc = is;

	mutex_enter(&idm.idm_global_mutex);
	list_insert_tail(&idm.idm_tgt_svc_list, is);
	mutex_exit(&idm.idm_global_mutex);

	return (IDM_STATUS_SUCCESS);
}

/*
 * idm_tgt_svc_destroy
 *
 * is - idm_svc_t returned by the call to idm_tgt_svc_create
 *
 * Cleanup any resources associated with the idm_svc_t.
 */
void
idm_tgt_svc_destroy(idm_svc_t *is)
{
	idm_transport_type_t	type;
	idm_transport_t		*it;

	mutex_enter(&idm.idm_global_mutex);
	/* remove this service from the global list */
	list_remove(&idm.idm_tgt_svc_list, is);
	/* wakeup any waiters for service change */
	cv_broadcast(&idm.idm_tgt_svc_cv);
	mutex_exit(&idm.idm_global_mutex);

	/* tear down the svc resources */
	idm_refcnt_destroy(&is->is_refcnt);
	cv_destroy(&is->is_count_cv);
	mutex_destroy(&is->is_count_mutex);
	cv_destroy(&is->is_cv);
	mutex_destroy(&is->is_mutex);

	/* teardown each transport-specific service */
	for (type = 0; type < IDM_TRANSPORT_NUM_TYPES; type++) {
		it = &idm_transport_list[type];
		if (it->it_ops == NULL) {
			continue;
		}

		it->it_ops->it_tgt_svc_destroy(is);
	}

	/* free the svc handle */
	kmem_free(is, sizeof (idm_svc_t));
}

void
idm_tgt_svc_hold(idm_svc_t *is)
{
	idm_refcnt_hold(&is->is_refcnt);
}

void
idm_tgt_svc_rele_and_destroy(idm_svc_t *is)
{
	idm_refcnt_rele_and_destroy(&is->is_refcnt,
	    (idm_refcnt_cb_t *)&idm_tgt_svc_destroy);
}

/*
 * idm_tgt_svc_online
 *
 * is - idm_svc_t returned by the call to idm_tgt_svc_create
 *
 * Online each transport service, as we want this target to be accessible
 * via any configured transport.
 *
 * When the initiator establishes a new connection to the target, IDM will
 * call the "new connect" callback defined in the idm_svc_req_t structure
 * and it will pass an idm_conn_t structure representing that new connection.
 */
idm_status_t
idm_tgt_svc_online(idm_svc_t *is)
{

	idm_transport_type_t	type;
	idm_transport_t		*it;
	int			rc;
	int			svc_found;

	mutex_enter(&is->is_mutex);
	/* Walk through each of the transports and online them */
	if (is->is_online == 0) {
		svc_found = 0;
		for (type = 0; type < IDM_TRANSPORT_NUM_TYPES; type++) {
			it = &idm_transport_list[type];
			if (it->it_ops == NULL) {
				/* transport is not registered */
				continue;
			}

			mutex_exit(&is->is_mutex);
			rc = it->it_ops->it_tgt_svc_online(is);
			mutex_enter(&is->is_mutex);
			if (rc == IDM_STATUS_SUCCESS) {
				/* We have at least one service running. */
				svc_found = 1;
			}
		}
	} else {
		svc_found = 1;
	}
	if (svc_found)
		is->is_online++;
	mutex_exit(&is->is_mutex);

	return (svc_found ? IDM_STATUS_SUCCESS : IDM_STATUS_FAIL);
}

/*
 * idm_tgt_svc_offline
 *
 * is - idm_svc_t returned by the call to idm_tgt_svc_create
 *
 * Shutdown any online target services.
 */
void
idm_tgt_svc_offline(idm_svc_t *is)
{
	idm_transport_type_t	type;
	idm_transport_t		*it;

	mutex_enter(&is->is_mutex);
	is->is_online--;
	if (is->is_online == 0) {
		/* Walk through each of the transports and offline them */
		for (type = 0; type < IDM_TRANSPORT_NUM_TYPES; type++) {
			it = &idm_transport_list[type];
			if (it->it_ops == NULL) {
				/* transport is not registered */
				continue;
			}

			mutex_exit(&is->is_mutex);
			it->it_ops->it_tgt_svc_offline(is);
			mutex_enter(&is->is_mutex);
		}
	}
	mutex_exit(&is->is_mutex);
}

/*
 * idm_tgt_svc_lookup
 *
 * Lookup a service instance listening on the specified port
 */

idm_svc_t *
idm_tgt_svc_lookup(uint16_t port)
{
	idm_svc_t *result;

retry:
	mutex_enter(&idm.idm_global_mutex);
	for (result = list_head(&idm.idm_tgt_svc_list);
	    result != NULL;
	    result = list_next(&idm.idm_tgt_svc_list, result)) {
		if (result->is_svc_req.sr_port == port) {
			if (result->is_online == 0) {
				/*
				 * A service exists on this port, but it
				 * is going away, wait for it to cleanup.
				 */
				cv_wait(&idm.idm_tgt_svc_cv,
				    &idm.idm_global_mutex);
				mutex_exit(&idm.idm_global_mutex);
				goto retry;
			}
			idm_tgt_svc_hold(result);
			mutex_exit(&idm.idm_global_mutex);
			return (result);
		}
	}
	mutex_exit(&idm.idm_global_mutex);

	return (NULL);
}

/*
 * idm_negotiate_key_values()
 * Give IDM level a chance to negotiate any login parameters it should own.
 *  -- leave unhandled parameters alone on request_nvl
 *  -- move all handled parameters to response_nvl with an appropriate response
 *  -- also add an entry to negotiated_nvl for any accepted parameters
 */
kv_status_t
idm_negotiate_key_values(idm_conn_t *ic, nvlist_t *request_nvl,
    nvlist_t *response_nvl, nvlist_t *negotiated_nvl)
{
	ASSERT(ic->ic_transport_ops != NULL);
	return (ic->ic_transport_ops->it_negotiate_key_values(ic,
	    request_nvl, response_nvl, negotiated_nvl));
}

/*
 * idm_notice_key_values()
 * Activate at the IDM level any parameters that have been negotiated.
 * Passes the set of key value pairs to the transport for activation.
 * This will be invoked as the connection is entering full-feature mode.
 */
idm_status_t
idm_notice_key_values(idm_conn_t *ic, nvlist_t *negotiated_nvl)
{
	ASSERT(ic->ic_transport_ops != NULL);
	return (ic->ic_transport_ops->it_notice_key_values(ic,
	    negotiated_nvl));
}

/*
 * idm_buf_tx_to_ini
 *
 * This is IDM's implementation of the 'Put_Data' operational primitive.
 *
 * This function is invoked by a target iSCSI layer to request its local
 * Datamover layer to transmit the Data-In PDU to the peer iSCSI layer
 * on the remote iSCSI node. The I/O buffer represented by 'idb' is
 * transferred to the initiator associated with task 'idt'. The connection
 * info, contents of the Data-In PDU header, the DataDescriptorIn, BHS,
 * and the callback (idb->idb_buf_cb) at transfer completion are
 * provided as input.
 *
 * This data transfer takes place transparently to the remote iSCSI layer,
 * i.e. without its participation.
 *
 * Using sockets, IDM implements the data transfer by segmenting the data
 * buffer into appropriately sized iSCSI PDUs and transmitting them to the
 * initiator. iSER performs the transfer using RDMA write.
 *
 */
idm_status_t
idm_buf_tx_to_ini(idm_task_t *idt, idm_buf_t *idb,
    uint32_t offset, uint32_t xfer_len,
    idm_buf_cb_t idb_buf_cb, void *cb_arg)
{
	idm_status_t rc;

	idb->idb_bufoffset = offset;
	idb->idb_xfer_len = xfer_len;
	idb->idb_buf_cb = idb_buf_cb;
	idb->idb_cb_arg = cb_arg;

	mutex_enter(&idt->idt_mutex);
	switch (idt->idt_state) {
	case TASK_ACTIVE:
		idt->idt_tx_to_ini_start++;
		idm_task_hold(idt);
		idm_buf_bind_in_locked(idt, idb);
		idb->idb_in_transport = B_TRUE;
		rc = (*idt->idt_ic->ic_transport_ops->it_buf_tx_to_ini)
		    (idt, idb);
		return (rc);

	case TASK_SUSPENDING:
	case TASK_SUSPENDED:
		/*
		 * Bind buffer but don't start a transfer since the task
		 * is suspended
		 */
		idm_buf_bind_in_locked(idt, idb);
		mutex_exit(&idt->idt_mutex);
		return (IDM_STATUS_SUCCESS);

	case TASK_ABORTING:
	case TASK_ABORTED:
		/*
		 * Once the task is aborted, any buffers added to the
		 * idt_inbufv will never get cleaned up, so just return
		 * SUCCESS.  The buffer should get cleaned up by the
		 * client or framework once task_aborted has completed.
		 */
		mutex_exit(&idt->idt_mutex);
		return (IDM_STATUS_SUCCESS);

	default:
		ASSERT(0);
		break;
	}
	mutex_exit(&idt->idt_mutex);

	return (IDM_STATUS_FAIL);
}

/*
 * idm_buf_rx_from_ini
 *
 * This is IDM's implementation of the 'Get_Data' operational primitive.
 *
 * This function is invoked by a target iSCSI layer to request its local
 * Datamover layer to retrieve certain data identified by the R2T PDU from the
 * peer iSCSI layer on the remote node. The retrieved Data-Out PDU will be
 * mapped to the respective buffer by the task tags (ITT & TTT).
 * The connection information, contents of an R2T PDU, DataDescriptor, BHS, and
 * the callback (idb->idb_buf_cb) notification for data transfer completion are
 * are provided as input.
 *
 * When an iSCSI node sends an R2T PDU to its local Datamover layer, the local
 * Datamover layer, the local and remote Datamover layers transparently bring
 * about the data transfer requested by the R2T PDU, without the participation
 * of the iSCSI layers.
 *
 * Using sockets, IDM transmits an R2T PDU for each buffer and the rx_data_out()
 * assembles the Data-Out PDUs into the buffer. iSER uses RDMA read.
 *
 */
idm_status_t
idm_buf_rx_from_ini(idm_task_t *idt, idm_buf_t *idb,
    uint32_t offset, uint32_t xfer_len,
    idm_buf_cb_t idb_buf_cb, void *cb_arg)
{
	idm_status_t rc;

	idb->idb_bufoffset = offset;
	idb->idb_xfer_len = xfer_len;
	idb->idb_buf_cb = idb_buf_cb;
	idb->idb_cb_arg = cb_arg;

	/*
	 * "In" buf list is for "Data In" PDU's, "Out" buf list is for
	 * "Data Out" PDU's
	 */
	mutex_enter(&idt->idt_mutex);
	switch (idt->idt_state) {
	case TASK_ACTIVE:
		idt->idt_rx_from_ini_start++;
		idm_task_hold(idt);
		idm_buf_bind_out_locked(idt, idb);
		idb->idb_in_transport = B_TRUE;
		rc = (*idt->idt_ic->ic_transport_ops->it_buf_rx_from_ini)
		    (idt, idb);
		return (rc);
	case TASK_SUSPENDING:
	case TASK_SUSPENDED:
	case TASK_ABORTING:
	case TASK_ABORTED:
		/*
		 * Bind buffer but don't start a transfer since the task
		 * is suspended
		 */
		idm_buf_bind_out_locked(idt, idb);
		mutex_exit(&idt->idt_mutex);
		return (IDM_STATUS_SUCCESS);
	default:
		ASSERT(0);
		break;
	}
	mutex_exit(&idt->idt_mutex);

	return (IDM_STATUS_FAIL);
}

/*
 * idm_buf_tx_to_ini_done
 *
 * The transport calls this after it has completed a transfer requested by
 * a call to transport_buf_tx_to_ini
 *
 * Caller holds idt->idt_mutex, idt->idt_mutex is released before returning.
 * idt may be freed after the call to idb->idb_buf_cb.
 */
void
idm_buf_tx_to_ini_done(idm_task_t *idt, idm_buf_t *idb, idm_status_t status)
{
	ASSERT(mutex_owned(&idt->idt_mutex));
	idb->idb_in_transport = B_FALSE;
	idb->idb_tx_thread = B_FALSE;
	idt->idt_tx_to_ini_done++;

	/*
	 * idm_refcnt_rele may cause TASK_SUSPENDING --> TASK_SUSPENDED or
	 * TASK_ABORTING --> TASK_ABORTED transistion if the refcount goes
	 * to 0.
	 */
	idm_task_rele(idt);
	idb->idb_status = status;

	switch (idt->idt_state) {
	case TASK_ACTIVE:
		idm_buf_unbind_in_locked(idt, idb);
		mutex_exit(&idt->idt_mutex);
		(*idb->idb_buf_cb)(idb, status);
		return;
	case TASK_SUSPENDING:
	case TASK_SUSPENDED:
	case TASK_ABORTING:
	case TASK_ABORTED:
		/*
		 * To keep things simple we will ignore the case where the
		 * transfer was successful and leave all buffers bound to the
		 * task.  This allows us to also ignore the case where we've
		 * been asked to abort a task but the last transfer of the
		 * task has completed.  IDM has no idea whether this was, in
		 * fact, the last transfer of the task so it would be difficult
		 * to handle this case.  Everything should get sorted out again
		 * after task reassignment is complete.
		 *
		 * In the case of TASK_ABORTING we could conceivably call the
		 * buffer callback here but the timing of when the client's
		 * client_task_aborted callback is invoked vs. when the client's
		 * buffer callback gets invoked gets sticky.  We don't want
		 * the client to here from us again after the call to
		 * client_task_aborted() but we don't want to give it a bunch
		 * of failed buffer transfers until we've called
		 * client_task_aborted().  Instead we'll just leave all the
		 * buffers bound and allow the client to cleanup.
		 */
		break;
	default:
		ASSERT(0);
	}
	mutex_exit(&idt->idt_mutex);
}

/*
 * idm_buf_rx_from_ini_done
 *
 * The transport calls this after it has completed a transfer requested by
 * a call totransport_buf_tx_to_ini
 *
 * Caller holds idt->idt_mutex, idt->idt_mutex is released before returning.
 * idt may be freed after the call to idb->idb_buf_cb.
 */
void
idm_buf_rx_from_ini_done(idm_task_t *idt, idm_buf_t *idb, idm_status_t status)
{
	ASSERT(mutex_owned(&idt->idt_mutex));
	idb->idb_in_transport = B_FALSE;
	idt->idt_rx_from_ini_done++;

	/*
	 * idm_refcnt_rele may cause TASK_SUSPENDING --> TASK_SUSPENDED or
	 * TASK_ABORTING --> TASK_ABORTED transistion if the refcount goes
	 * to 0.
	 */
	idm_task_rele(idt);
	idb->idb_status = status;

	switch (idt->idt_state) {
	case TASK_ACTIVE:
		idm_buf_unbind_out_locked(idt, idb);
		mutex_exit(&idt->idt_mutex);
		(*idb->idb_buf_cb)(idb, status);
		return;
	case TASK_SUSPENDING:
	case TASK_SUSPENDED:
	case TASK_ABORTING:
	case TASK_ABORTED:
		/*
		 * To keep things simple we will ignore the case where the
		 * transfer was successful and leave all buffers bound to the
		 * task.  This allows us to also ignore the case where we've
		 * been asked to abort a task but the last transfer of the
		 * task has completed.  IDM has no idea whether this was, in
		 * fact, the last transfer of the task so it would be difficult
		 * to handle this case.  Everything should get sorted out again
		 * after task reassignment is complete.
		 *
		 * In the case of TASK_ABORTING we could conceivably call the
		 * buffer callback here but the timing of when the client's
		 * client_task_aborted callback is invoked vs. when the client's
		 * buffer callback gets invoked gets sticky.  We don't want
		 * the client to here from us again after the call to
		 * client_task_aborted() but we don't want to give it a bunch
		 * of failed buffer transfers until we've called
		 * client_task_aborted().  Instead we'll just leave all the
		 * buffers bound and allow the client to cleanup.
		 */
		break;
	default:
		ASSERT(0);
	}
	mutex_exit(&idt->idt_mutex);
}

/*
 * idm_buf_alloc
 *
 * Allocates a buffer handle and registers it for use with the transport
 * layer. If a buffer is not passed on bufptr, the buffer will be allocated
 * as well as the handle.
 *
 * ic		- connection on which the buffer will be transferred
 * bufptr	- allocate memory for buffer if NULL, else assign to buffer
 * buflen	- length of buffer
 *
 * Returns idm_buf_t handle if successful, otherwise NULL
 */
idm_buf_t *
idm_buf_alloc(idm_conn_t *ic, void *bufptr, uint64_t buflen)
{
	idm_buf_t	*buf = NULL;
	int		rc;

	ASSERT(ic != NULL);
	ASSERT(idm.idm_buf_cache != NULL);
	ASSERT(buflen > 0);

	/* Don't allocate new buffers if we are not in FFP */
	mutex_enter(&ic->ic_state_mutex);
	if (!ic->ic_ffp) {
		mutex_exit(&ic->ic_state_mutex);
		return (NULL);
	}


	idm_conn_hold(ic);
	mutex_exit(&ic->ic_state_mutex);

	buf = kmem_cache_alloc(idm.idm_buf_cache, KM_NOSLEEP);
	if (buf == NULL) {
		idm_conn_rele(ic);
		return (NULL);
	}

	buf->idb_ic		= ic;
	buf->idb_buflen		= buflen;
	buf->idb_exp_offset	= 0;
	buf->idb_bufoffset	= 0;
	buf->idb_xfer_len 	= 0;
	buf->idb_magic		= IDM_BUF_MAGIC;

	/*
	 * If bufptr is NULL, we have an implicit request to allocate
	 * memory for this IDM buffer handle and register it for use
	 * with the transport. To simplify this, and to give more freedom
	 * to the transport layer for it's own buffer management, both of
	 * these actions will take place in the transport layer.
	 * If bufptr is set, then the caller has allocated memory (or more
	 * likely it's been passed from an upper layer), and we need only
	 * register the buffer for use with the transport layer.
	 */
	if (bufptr == NULL) {
		/*
		 * Allocate a buffer from the transport layer (which
		 * will also register the buffer for use).
		 */
		rc = ic->ic_transport_ops->it_buf_alloc(buf, buflen);
		if (rc != 0) {
			idm_conn_rele(ic);
			kmem_cache_free(idm.idm_buf_cache, buf);
			return (NULL);
		}
		/* Set the bufalloc'd flag */
		buf->idb_bufalloc = B_TRUE;
	} else {
		/*
		 * Set the passed bufptr into the buf handle, and
		 * register the handle with the transport layer.
		 */
		buf->idb_buf = bufptr;

		rc = ic->ic_transport_ops->it_buf_setup(buf);
		if (rc != 0) {
			idm_conn_rele(ic);
			kmem_cache_free(idm.idm_buf_cache, buf);
			return (NULL);
		}
		/* Ensure bufalloc'd flag is unset */
		buf->idb_bufalloc = B_FALSE;
	}

	return (buf);

}

/*
 * idm_buf_free
 *
 * Release a buffer handle along with the associated buffer that was allocated
 * or assigned with idm_buf_alloc
 */
void
idm_buf_free(idm_buf_t *buf)
{
	idm_conn_t *ic = buf->idb_ic;


	buf->idb_task_binding	= NULL;

	if (buf->idb_bufalloc) {
		ic->ic_transport_ops->it_buf_free(buf);
	} else {
		ic->ic_transport_ops->it_buf_teardown(buf);
	}
	kmem_cache_free(idm.idm_buf_cache, buf);
	idm_conn_rele(ic);
}

/*
 * idm_buf_bind_in
 *
 * This function associates a buffer with a task. This is only for use by the
 * iSCSI initiator that will have only one buffer per transfer direction
 *
 */
void
idm_buf_bind_in(idm_task_t *idt, idm_buf_t *buf)
{
	mutex_enter(&idt->idt_mutex);
	idm_buf_bind_in_locked(idt, buf);
	mutex_exit(&idt->idt_mutex);
}

static void
idm_buf_bind_in_locked(idm_task_t *idt, idm_buf_t *buf)
{
	buf->idb_task_binding = idt;
	buf->idb_ic = idt->idt_ic;
	idm_listbuf_insert(&idt->idt_inbufv, buf);
}

void
idm_buf_bind_out(idm_task_t *idt, idm_buf_t *buf)
{
	mutex_enter(&idt->idt_mutex);
	idm_buf_bind_out_locked(idt, buf);
	mutex_exit(&idt->idt_mutex);
}

static void
idm_buf_bind_out_locked(idm_task_t *idt, idm_buf_t *buf)
{
	buf->idb_task_binding = idt;
	buf->idb_ic = idt->idt_ic;
	idm_listbuf_insert(&idt->idt_outbufv, buf);
}

void
idm_buf_unbind_in(idm_task_t *idt, idm_buf_t *buf)
{
	mutex_enter(&idt->idt_mutex);
	idm_buf_unbind_in_locked(idt, buf);
	mutex_exit(&idt->idt_mutex);
}

static void
idm_buf_unbind_in_locked(idm_task_t *idt, idm_buf_t *buf)
{
	list_remove(&idt->idt_inbufv, buf);
}

void
idm_buf_unbind_out(idm_task_t *idt, idm_buf_t *buf)
{
	mutex_enter(&idt->idt_mutex);
	idm_buf_unbind_out_locked(idt, buf);
	mutex_exit(&idt->idt_mutex);
}

static void
idm_buf_unbind_out_locked(idm_task_t *idt, idm_buf_t *buf)
{
	list_remove(&idt->idt_outbufv, buf);
}

/*
 * idm_buf_find() will lookup the idm_buf_t based on the relative offset in the
 * iSCSI PDU
 */
idm_buf_t *
idm_buf_find(void *lbuf, size_t data_offset)
{
	idm_buf_t	*idb;
	list_t		*lst = (list_t *)lbuf;

	/* iterate through the list to find the buffer */
	for (idb = list_head(lst); idb != NULL; idb = list_next(lst, idb)) {

		ASSERT((idb->idb_ic->ic_conn_type == CONN_TYPE_TGT) ||
		    (idb->idb_bufoffset == 0));

		if ((data_offset >= idb->idb_bufoffset) &&
		    (data_offset < (idb->idb_bufoffset + idb->idb_buflen))) {

			return (idb);
		}
	}

	return (NULL);
}

/*
 * idm_task_alloc
 *
 * This function will allocate a idm_task_t structure. A task tag is also
 * generated and saved in idt_tt. The task is not active.
 */
idm_task_t *
idm_task_alloc(idm_conn_t *ic)
{
	idm_task_t	*idt;

	ASSERT(ic != NULL);

	/* Don't allocate new tasks if we are not in FFP */
	mutex_enter(&ic->ic_state_mutex);
	if (!ic->ic_ffp) {
		mutex_exit(&ic->ic_state_mutex);
		return (NULL);
	}
	idt = kmem_cache_alloc(idm.idm_task_cache, KM_NOSLEEP);
	if (idt == NULL) {
		mutex_exit(&ic->ic_state_mutex);
		return (NULL);
	}

	ASSERT(list_is_empty(&idt->idt_inbufv));
	ASSERT(list_is_empty(&idt->idt_outbufv));

	idm_conn_hold(ic);
	mutex_exit(&ic->ic_state_mutex);

	idt->idt_state		= TASK_IDLE;
	idt->idt_ic		= ic;
	idt->idt_private 	= NULL;
	idt->idt_exp_datasn	= 0;
	idt->idt_exp_rttsn	= 0;

	return (idt);
}

/*
 * idm_task_start
 *
 * Add the task to an AVL tree to notify IDM about a new task. The caller
 * sets up the idm_task_t structure with a prior call to idm_task_alloc().
 * The task service does not function as a task/work engine, it is the
 * responsibility of the initiator to start the data transfer and free the
 * resources.
 */
void
idm_task_start(idm_task_t *idt, uintptr_t handle)
{
	ASSERT(idt != NULL);

	/* mark the task as ACTIVE */
	idt->idt_state = TASK_ACTIVE;
	idt->idt_client_handle = handle;
	idt->idt_tx_to_ini_start = idt->idt_tx_to_ini_done =
	    idt->idt_rx_from_ini_start = idt->idt_rx_from_ini_done = 0;
}

/*
 * idm_task_done
 *
 * This function will remove the task from the AVL tree indicating that the
 * task is no longer active.
 */
void
idm_task_done(idm_task_t *idt)
{
	ASSERT(idt != NULL);
	ASSERT(idt->idt_refcnt.ir_refcnt == 0);

	idt->idt_state = TASK_IDLE;
	idm_refcnt_reset(&idt->idt_refcnt);
}

/*
 * idm_task_free
 *
 * This function will free the Task Tag and the memory allocated for the task
 * idm_task_done should be called prior to this call
 */
void
idm_task_free(idm_task_t *idt)
{
	idm_conn_t *ic = idt->idt_ic;

	ASSERT(idt != NULL);
	ASSERT(idt->idt_state == TASK_IDLE);

	/*
	 * It's possible for items to still be in the idt_inbufv list if
	 * they were added after idm_task_cleanup was called.  We rely on
	 * STMF to free all buffers associated with the task however STMF
	 * doesn't know that we have this reference to the buffers.
	 * Use list_create so that we don't end up with stale references
	 * to these buffers.
	 */
	list_create(&idt->idt_inbufv, sizeof (idm_buf_t),
	    offsetof(idm_buf_t, idb_buflink));
	list_create(&idt->idt_outbufv, sizeof (idm_buf_t),
	    offsetof(idm_buf_t, idb_buflink));

	kmem_cache_free(idm.idm_task_cache, idt);

	idm_conn_rele(ic);
}

/*
 * idm_task_find
 *
 * This function looks up a task by task tag
 */
/*ARGSUSED*/
idm_task_t *
idm_task_find(idm_conn_t *ic, uint32_t itt, uint32_t ttt)
{
	uint32_t	tt, client_handle;
	idm_task_t	*idt;

	/*
	 * Must match both itt and ttt.  The table is indexed by itt
	 * for initiator connections and ttt for target connections.
	 */
	if (IDM_CONN_ISTGT(ic)) {
		tt = ttt;
		client_handle = itt;
	} else {
		tt = itt;
		client_handle = ttt;
	}

	rw_enter(&idm.idm_taskid_table_lock, RW_READER);
	if (tt >= idm.idm_taskid_max) {
		rw_exit(&idm.idm_taskid_table_lock);
		return (NULL);
	}

	idt = idm.idm_taskid_table[tt];

	if (idt != NULL) {
		mutex_enter(&idt->idt_mutex);
		if ((idt->idt_state != TASK_ACTIVE) ||
		    (IDM_CONN_ISTGT(ic) &&
		    (idt->idt_client_handle != client_handle))) {
			/*
			 * Task is aborting, we don't want any more references.
			 */
			mutex_exit(&idt->idt_mutex);
			rw_exit(&idm.idm_taskid_table_lock);
			return (NULL);
		}
		idm_task_hold(idt);
		mutex_exit(&idt->idt_mutex);
	}
	rw_exit(&idm.idm_taskid_table_lock);

	return (idt);
}

/*
 * idm_task_find_by_handle
 *
 * This function looks up a task by the client-private idt_client_handle.
 *
 * This function should NEVER be called in the performance path.  It is
 * intended strictly for error recovery/task management.
 */
/*ARGSUSED*/
void *
idm_task_find_by_handle(idm_conn_t *ic, uintptr_t handle)
{
	idm_task_t	*idt = NULL;
	int		idx = 0;

	rw_enter(&idm.idm_taskid_table_lock, RW_READER);

	for (idx = 0; idx < idm.idm_taskid_max; idx++) {
		idt = idm.idm_taskid_table[idx];

		if (idt == NULL)
			continue;

		mutex_enter(&idt->idt_mutex);

		if (idt->idt_state != TASK_ACTIVE) {
			/*
			 * Task is either in suspend, abort, or already
			 * complete.
			 */
			mutex_exit(&idt->idt_mutex);
			continue;
		}

		if (idt->idt_client_handle == handle) {
			idm_task_hold(idt);
			mutex_exit(&idt->idt_mutex);
			break;
		}

		mutex_exit(&idt->idt_mutex);
	}

	rw_exit(&idm.idm_taskid_table_lock);

	if ((idt == NULL) || (idx == idm.idm_taskid_max))
		return (NULL);

	return (idt->idt_private);
}

void
idm_task_hold(idm_task_t *idt)
{
	idm_refcnt_hold(&idt->idt_refcnt);
}

void
idm_task_rele(idm_task_t *idt)
{
	idm_refcnt_rele(&idt->idt_refcnt);
}

void
idm_task_abort(idm_conn_t *ic, idm_task_t *idt, idm_abort_type_t abort_type)
{
	idm_task_t	*task;
	int		idx;

	/*
	 * Passing NULL as the task indicates that all tasks
	 * for this connection should be aborted.
	 */
	if (idt == NULL) {
		/*
		 * Only the connection state machine should ask for
		 * all tasks to abort and this should never happen in FFP.
		 */
		ASSERT(!ic->ic_ffp);
		rw_enter(&idm.idm_taskid_table_lock, RW_READER);
		for (idx = 0; idx < idm.idm_taskid_max; idx++) {
			task = idm.idm_taskid_table[idx];
			if (task && (task->idt_state != TASK_IDLE) &&
			    (task->idt_ic == ic)) {
				rw_exit(&idm.idm_taskid_table_lock);
				idm_task_abort_one(ic, task, abort_type);
				rw_enter(&idm.idm_taskid_table_lock, RW_READER);
			}
		}
		rw_exit(&idm.idm_taskid_table_lock);
	} else {
		idm_task_abort_one(ic, idt, abort_type);
	}
}

static void
idm_task_abort_unref_cb(void *ref)
{
	idm_task_t *idt = ref;

	mutex_enter(&idt->idt_mutex);
	switch (idt->idt_state) {
	case TASK_SUSPENDING:
		idt->idt_state = TASK_SUSPENDED;
		mutex_exit(&idt->idt_mutex);
		idm_task_aborted(idt, IDM_STATUS_SUSPENDED);
		return;
	case TASK_ABORTING:
		idt->idt_state = TASK_ABORTED;
		mutex_exit(&idt->idt_mutex);
		idm_task_aborted(idt, IDM_STATUS_ABORTED);
		return;
	default:
		mutex_exit(&idt->idt_mutex);
		ASSERT(0);
		break;
	}
}

static void
idm_task_abort_one(idm_conn_t *ic, idm_task_t *idt, idm_abort_type_t abort_type)
{
	/* Caller must hold connection mutex */
	mutex_enter(&idt->idt_mutex);
	switch (idt->idt_state) {
	case TASK_ACTIVE:
		switch (abort_type) {
		case AT_INTERNAL_SUSPEND:
			/* Call transport to release any resources */
			idt->idt_state = TASK_SUSPENDING;
			mutex_exit(&idt->idt_mutex);
			ic->ic_transport_ops->it_free_task_rsrc(idt);

			/*
			 * Wait for outstanding references.  When all
			 * references are released the callback will call
			 * idm_task_aborted().
			 */
			idm_refcnt_async_wait_ref(&idt->idt_refcnt,
			    &idm_task_abort_unref_cb);
			return;
		case AT_INTERNAL_ABORT:
		case AT_TASK_MGMT_ABORT:
			idt->idt_state = TASK_ABORTING;
			mutex_exit(&idt->idt_mutex);
			ic->ic_transport_ops->it_free_task_rsrc(idt);

			/*
			 * Wait for outstanding references.  When all
			 * references are released the callback will call
			 * idm_task_aborted().
			 */
			idm_refcnt_async_wait_ref(&idt->idt_refcnt,
			    &idm_task_abort_unref_cb);
			return;
		default:
			ASSERT(0);
		}
		break;
	case TASK_SUSPENDING:
		/* Already called transport_free_task_rsrc(); */
		switch (abort_type) {
		case AT_INTERNAL_SUSPEND:
			/* Already doing it */
			break;
		case AT_INTERNAL_ABORT:
		case AT_TASK_MGMT_ABORT:
			idt->idt_state = TASK_ABORTING;
			break;
		default:
			ASSERT(0);
		}
		break;
	case TASK_SUSPENDED:
		/* Already called transport_free_task_rsrc(); */
		switch (abort_type) {
		case AT_INTERNAL_SUSPEND:
			/* Already doing it */
			break;
		case AT_INTERNAL_ABORT:
		case AT_TASK_MGMT_ABORT:
			idt->idt_state = TASK_ABORTING;
			mutex_exit(&idt->idt_mutex);

			/*
			 * We could probably call idm_task_aborted directly
			 * here but we may be holding the conn lock. It's
			 * easier to just switch contexts.  Even though
			 * we shouldn't really have any references we'll
			 * set the state to TASK_ABORTING instead of
			 * TASK_ABORTED so we can use the same code path.
			 */
			idm_refcnt_async_wait_ref(&idt->idt_refcnt,
			    &idm_task_abort_unref_cb);
			return;
		default:
			ASSERT(0);
		}
		break;
	case TASK_ABORTING:
	case TASK_ABORTED:
		switch (abort_type) {
		case AT_INTERNAL_SUSPEND:
			/* We're already past this point... */
		case AT_INTERNAL_ABORT:
		case AT_TASK_MGMT_ABORT:
			/* Already doing it */
			break;
		default:
			ASSERT(0);
		}
		break;
	case TASK_COMPLETE:
		/*
		 * In this case, let it go.  The status has already been
		 * sent (which may or may not get successfully transmitted)
		 * and we don't want to end up in a race between completing
		 * the status PDU and marking the task suspended.
		 */
		break;
	default:
		ASSERT(0);
	}
	mutex_exit(&idt->idt_mutex);
}

static void
idm_task_aborted(idm_task_t *idt, idm_status_t status)
{
	(*idt->idt_ic->ic_conn_ops.icb_task_aborted)(idt, status);
}

void
idm_task_cleanup(idm_task_t *idt)
{
	idm_buf_t *idb, *next_idb;
	list_t		tmp_buflist;
	ASSERT((idt->idt_state == TASK_SUSPENDED) ||
	    (idt->idt_state == TASK_ABORTED));

	list_create(&tmp_buflist, sizeof (idm_buf_t),
	    offsetof(idm_buf_t, idb_buflink));

	/*
	 * Remove all the buffers from the task and add them to a
	 * temporary local list -- we do this so that we can hold
	 * the task lock and prevent the task from going away if
	 * the client decides to call idm_task_done/idm_task_free.
	 * This could happen during abort in iscsit.
	 */
	mutex_enter(&idt->idt_mutex);
	for (idb = list_head(&idt->idt_inbufv);
	    idb != NULL;
	    idb = next_idb) {
		next_idb = list_next(&idt->idt_inbufv, idb);
		idm_buf_unbind_in_locked(idt, idb);
		list_insert_tail(&tmp_buflist, idb);
	}

	for (idb = list_head(&idt->idt_outbufv);
	    idb != NULL;
	    idb = next_idb) {
		next_idb = list_next(&idt->idt_outbufv, idb);
		idm_buf_unbind_out_locked(idt, idb);
		list_insert_tail(&tmp_buflist, idb);
	}
	mutex_exit(&idt->idt_mutex);

	for (idb = list_head(&tmp_buflist); idb != NULL; idb = next_idb) {
		next_idb = list_next(&tmp_buflist, idb);
		list_remove(&tmp_buflist, idb);
		(*idb->idb_buf_cb)(idb, IDM_STATUS_ABORTED);
	}
	list_destroy(&tmp_buflist);
}


/*
 * idm_pdu_tx
 *
 * This is IDM's implementation of the 'Send_Control' operational primitive.
 * This function is invoked by an initiator iSCSI layer requesting the transfer
 * of a iSCSI command PDU or a target iSCSI layer requesting the transfer of a
 * iSCSI response PDU. The PDU will be transmitted as-is by the local Datamover
 * layer to the peer iSCSI layer in the remote iSCSI node. The connection info
 * and iSCSI PDU-specific qualifiers namely BHS, AHS, DataDescriptor and Size
 * are provided as input.
 *
 */
void
idm_pdu_tx(idm_pdu_t *pdu)
{
	idm_conn_t		*ic = pdu->isp_ic;
	iscsi_async_evt_hdr_t	*async_evt;

	/*
	 * If we are in full-featured mode then route SCSI-related
	 * commands to the appropriate function vector without checking
	 * the connection state.  We will only be in full-feature mode
	 * when we are in an acceptable state for SCSI PDU's.
	 *
	 * We also need to ensure that there are no PDU events outstanding
	 * on the state machine.  Any non-SCSI PDU's received in full-feature
	 * mode will result in PDU events and until these have been handled
	 * we need to route all PDU's through the state machine as PDU
	 * events to maintain ordering.
	 *
	 * Note that IDM cannot enter FFP mode until it processes in
	 * its state machine the last xmit of the login process.
	 * Hence, checking the IDM_PDU_LOGIN_TX flag here would be
	 * superfluous.
	 */
	mutex_enter(&ic->ic_state_mutex);
	if (ic->ic_ffp && (ic->ic_pdu_events == 0)) {
		mutex_exit(&ic->ic_state_mutex);
		switch (IDM_PDU_OPCODE(pdu)) {
		case ISCSI_OP_SCSI_RSP:
			/* Target only */
			idm_pdu_tx_forward(ic, pdu);
			return;
		case ISCSI_OP_SCSI_TASK_MGT_RSP:
			/* Target only */
			idm_pdu_tx_forward(ic, pdu);
			return;
		case ISCSI_OP_SCSI_DATA_RSP:
			/* Target only */
			idm_pdu_tx_forward(ic, pdu);
			return;
		case ISCSI_OP_RTT_RSP:
			/* Target only */
			idm_pdu_tx_forward(ic, pdu);
			return;
		case ISCSI_OP_NOOP_IN:
			/* Target only */
			idm_pdu_tx_forward(ic, pdu);
			return;
		case ISCSI_OP_TEXT_RSP:
			/* Target only */
			idm_pdu_tx_forward(ic, pdu);
			return;
		case ISCSI_OP_TEXT_CMD:
		case ISCSI_OP_NOOP_OUT:
		case ISCSI_OP_SCSI_CMD:
		case ISCSI_OP_SCSI_DATA:
		case ISCSI_OP_SCSI_TASK_MGT_MSG:
			/* Initiator only */
			idm_pdu_tx_forward(ic, pdu);
			return;
		default:
			break;
		}

		mutex_enter(&ic->ic_state_mutex);
	}

	/*
	 * Any PDU's processed outside of full-feature mode and non-SCSI
	 * PDU's in full-feature mode are handled by generating an
	 * event to the connection state machine.  The state machine
	 * will validate the PDU against the current state and either
	 * transmit the PDU if the opcode is allowed or handle an
	 * error if the PDU is not allowed.
	 *
	 * This code-path will also generate any events that are implied
	 * by the PDU opcode.  For example a "login response" with success
	 * status generates a CE_LOGOUT_SUCCESS_SND event.
	 */
	switch (IDM_PDU_OPCODE(pdu)) {
	case ISCSI_OP_LOGIN_CMD:
		idm_conn_tx_pdu_event(ic, CE_LOGIN_SND, (uintptr_t)pdu);
		break;
	case ISCSI_OP_LOGIN_RSP:
		idm_parse_login_rsp(ic, pdu, /* Is RX */ B_FALSE);
		break;
	case ISCSI_OP_LOGOUT_CMD:
		idm_parse_logout_req(ic, pdu, /* Is RX */ B_FALSE);
		break;
	case ISCSI_OP_LOGOUT_RSP:
		idm_parse_logout_rsp(ic, pdu, /* Is RX */ B_FALSE);
		break;
	case ISCSI_OP_ASYNC_EVENT:
		async_evt = (iscsi_async_evt_hdr_t *)pdu->isp_hdr;
		switch (async_evt->async_event) {
		case ISCSI_ASYNC_EVENT_REQUEST_LOGOUT:
			idm_conn_tx_pdu_event(ic, CE_ASYNC_LOGOUT_SND,
			    (uintptr_t)pdu);
			break;
		case ISCSI_ASYNC_EVENT_DROPPING_CONNECTION:
			idm_conn_tx_pdu_event(ic, CE_ASYNC_DROP_CONN_SND,
			    (uintptr_t)pdu);
			break;
		case ISCSI_ASYNC_EVENT_DROPPING_ALL_CONNECTIONS:
			idm_conn_tx_pdu_event(ic, CE_ASYNC_DROP_ALL_CONN_SND,
			    (uintptr_t)pdu);
			break;
		case ISCSI_ASYNC_EVENT_SCSI_EVENT:
		case ISCSI_ASYNC_EVENT_PARAM_NEGOTIATION:
		default:
			idm_conn_tx_pdu_event(ic, CE_MISC_TX,
			    (uintptr_t)pdu);
			break;
		}
		break;
	case ISCSI_OP_SCSI_RSP:
		/* Target only */
		idm_conn_tx_pdu_event(ic, CE_MISC_TX, (uintptr_t)pdu);
		break;
	case ISCSI_OP_SCSI_TASK_MGT_RSP:
		/* Target only */
		idm_conn_tx_pdu_event(ic, CE_MISC_TX, (uintptr_t)pdu);
		break;
	case ISCSI_OP_SCSI_DATA_RSP:
		/* Target only */
		idm_conn_tx_pdu_event(ic, CE_MISC_TX, (uintptr_t)pdu);
		break;
	case ISCSI_OP_RTT_RSP:
		/* Target only */
		idm_conn_tx_pdu_event(ic, CE_MISC_TX, (uintptr_t)pdu);
		break;
	case ISCSI_OP_NOOP_IN:
		/* Target only */
		idm_conn_tx_pdu_event(ic, CE_MISC_TX, (uintptr_t)pdu);
		break;
	case ISCSI_OP_TEXT_RSP:
		/* Target only */
		idm_conn_tx_pdu_event(ic, CE_MISC_TX, (uintptr_t)pdu);
		break;
		/* Initiator only */
	case ISCSI_OP_SCSI_CMD:
	case ISCSI_OP_SCSI_TASK_MGT_MSG:
	case ISCSI_OP_SCSI_DATA:
	case ISCSI_OP_NOOP_OUT:
	case ISCSI_OP_TEXT_CMD:
	case ISCSI_OP_SNACK_CMD:
	case ISCSI_OP_REJECT_MSG:
	default:
		/*
		 * Connection state machine will validate these PDU's against
		 * the current state.  A PDU not allowed in the current
		 * state will cause a protocol error.
		 */
		idm_conn_tx_pdu_event(ic, CE_MISC_TX, (uintptr_t)pdu);
		break;
	}
	mutex_exit(&ic->ic_state_mutex);
}

/*
 * Allocates a PDU along with memory for header and data.
 */

idm_pdu_t *
idm_pdu_alloc(uint_t hdrlen, uint_t datalen)
{
	idm_pdu_t *result;

	/*
	 * IDM clients should cache these structures for performance
	 * critical paths.  We can't cache effectively in IDM because we
	 * don't know the correct header and data size.
	 *
	 * Valid header length is assumed to be hdrlen and valid data
	 * length is assumed to be datalen.  isp_hdrlen and isp_datalen
	 * can be adjusted after the PDU is returned if necessary.
	 */
	result = kmem_zalloc(sizeof (idm_pdu_t) + hdrlen + datalen, KM_SLEEP);
	result->isp_flags |= IDM_PDU_ALLOC; /* For idm_pdu_free sanity check */
	result->isp_hdr = (iscsi_hdr_t *)(result + 1); /* Ptr. Arithmetic */
	result->isp_hdrlen = hdrlen;
	result->isp_hdrbuflen = hdrlen;
	result->isp_transport_hdrlen = 0;
	result->isp_data = (uint8_t *)result->isp_hdr + hdrlen;
	result->isp_datalen = datalen;
	result->isp_databuflen = datalen;
	result->isp_magic = IDM_PDU_MAGIC;

	return (result);
}

/*
 * Free a PDU previously allocated with idm_pdu_alloc() including any
 * header and data space allocated as part of the original request.
 * Additional memory regions referenced by subsequent modification of
 * the isp_hdr and/or isp_data fields will not be freed.
 */
void
idm_pdu_free(idm_pdu_t *pdu)
{
	/* Make sure the structure was allocated using idm_pdu_alloc() */
	ASSERT(pdu->isp_flags & IDM_PDU_ALLOC);
	kmem_free(pdu,
	    sizeof (idm_pdu_t) + pdu->isp_hdrbuflen + pdu->isp_databuflen);
}

/*
 * Initialize the connection, private and callback fields in a PDU.
 */
void
idm_pdu_init(idm_pdu_t *pdu, idm_conn_t *ic, void *private, idm_pdu_cb_t *cb)
{
	/*
	 * idm_pdu_complete() will call idm_pdu_free if the callback is
	 * NULL.  This will only work if the PDU was originally allocated
	 * with idm_pdu_alloc().
	 */
	ASSERT((pdu->isp_flags & IDM_PDU_ALLOC) ||
	    (cb != NULL));
	pdu->isp_magic = IDM_PDU_MAGIC;
	pdu->isp_ic = ic;
	pdu->isp_private = private;
	pdu->isp_callback = cb;
}

/*
 * Initialize the header and header length field.  This function should
 * not be used to adjust the header length in a buffer allocated via
 * pdu_pdu_alloc since it overwrites the existing header pointer.
 */
void
idm_pdu_init_hdr(idm_pdu_t *pdu, uint8_t *hdr, uint_t hdrlen)
{
	pdu->isp_hdr = (iscsi_hdr_t *)((void *)hdr);
	pdu->isp_hdrlen = hdrlen;
}

/*
 * Initialize the data and data length fields.  This function should
 * not be used to adjust the data length of a buffer allocated via
 * idm_pdu_alloc since it overwrites the existing data pointer.
 */
void
idm_pdu_init_data(idm_pdu_t *pdu, uint8_t *data, uint_t datalen)
{
	pdu->isp_data = data;
	pdu->isp_datalen = datalen;
}

void
idm_pdu_complete(idm_pdu_t *pdu, idm_status_t status)
{
	if (pdu->isp_callback) {
		pdu->isp_status = status;
		(*pdu->isp_callback)(pdu, status);
	} else {
		idm_pdu_free(pdu);
	}
}

/*
 * State machine auditing
 */

void
idm_sm_audit_init(sm_audit_buf_t *audit_buf)
{
	bzero(audit_buf, sizeof (sm_audit_buf_t));
	audit_buf->sab_max_index = SM_AUDIT_BUF_MAX_REC - 1;
}

static
sm_audit_record_t *
idm_sm_audit_common(sm_audit_buf_t *audit_buf, sm_audit_record_type_t r_type,
    sm_audit_sm_type_t sm_type,
    int current_state)
{
	sm_audit_record_t *sar;

	sar = audit_buf->sab_records;
	sar += audit_buf->sab_index;
	audit_buf->sab_index++;
	audit_buf->sab_index &= audit_buf->sab_max_index;

	sar->sar_type = r_type;
	gethrestime(&sar->sar_timestamp);
	sar->sar_sm_type = sm_type;
	sar->sar_state = current_state;

	return (sar);
}

void
idm_sm_audit_event(sm_audit_buf_t *audit_buf,
    sm_audit_sm_type_t sm_type, int current_state,
    int event, uintptr_t event_info)
{
	sm_audit_record_t *sar;

	sar = idm_sm_audit_common(audit_buf, SAR_STATE_EVENT,
	    sm_type, current_state);
	sar->sar_event = event;
	sar->sar_event_info = event_info;
}

void
idm_sm_audit_state_change(sm_audit_buf_t *audit_buf,
    sm_audit_sm_type_t sm_type, int current_state, int new_state)
{
	sm_audit_record_t *sar;

	sar = idm_sm_audit_common(audit_buf, SAR_STATE_CHANGE,
	    sm_type, current_state);
	sar->sar_new_state = new_state;
}


/*
 * Object reference tracking
 */

void
idm_refcnt_init(idm_refcnt_t *refcnt, void *referenced_obj)
{
	bzero(refcnt, sizeof (*refcnt));
	idm_refcnt_reset(refcnt);
	refcnt->ir_referenced_obj = referenced_obj;
	bzero(&refcnt->ir_audit_buf, sizeof (refcnt_audit_buf_t));
	refcnt->ir_audit_buf.anb_max_index = REFCNT_AUDIT_BUF_MAX_REC - 1;
	mutex_init(&refcnt->ir_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&refcnt->ir_cv, NULL, CV_DEFAULT, NULL);
}

void
idm_refcnt_destroy(idm_refcnt_t *refcnt)
{
	ASSERT(refcnt->ir_refcnt == 0);
	cv_destroy(&refcnt->ir_cv);
	mutex_destroy(&refcnt->ir_mutex);
}

void
idm_refcnt_reset(idm_refcnt_t *refcnt)
{
	refcnt->ir_waiting = REF_NOWAIT;
	refcnt->ir_refcnt = 0;
}

void
idm_refcnt_hold(idm_refcnt_t *refcnt)
{
	/*
	 * Nothing should take a hold on an object after a call to
	 * idm_refcnt_wait_ref or idm_refcnd_async_wait_ref
	 */
	ASSERT(refcnt->ir_waiting == REF_NOWAIT);

	mutex_enter(&refcnt->ir_mutex);
	refcnt->ir_refcnt++;
	REFCNT_AUDIT(refcnt);
	mutex_exit(&refcnt->ir_mutex);
}

static void
idm_refcnt_unref_task(void *refcnt_void)
{
	idm_refcnt_t *refcnt = refcnt_void;

	REFCNT_AUDIT(refcnt);
	(*refcnt->ir_cb)(refcnt->ir_referenced_obj);
}

void
idm_refcnt_rele(idm_refcnt_t *refcnt)
{
	mutex_enter(&refcnt->ir_mutex);
	ASSERT(refcnt->ir_refcnt > 0);
	refcnt->ir_refcnt--;
	REFCNT_AUDIT(refcnt);
	if (refcnt->ir_waiting == REF_NOWAIT) {
		/* No one is waiting on this object */
		mutex_exit(&refcnt->ir_mutex);
		return;
	}

	/*
	 * Someone is waiting for this object to go idle so check if
	 * refcnt is 0.  Waiting on an object then later grabbing another
	 * reference is not allowed so we don't need to handle that case.
	 */
	if (refcnt->ir_refcnt == 0) {
		if (refcnt->ir_waiting == REF_WAIT_ASYNC) {
			if (taskq_dispatch(idm.idm_global_taskq,
			    &idm_refcnt_unref_task, refcnt, TQ_SLEEP) == NULL) {
				cmn_err(CE_WARN,
				    "idm_refcnt_rele: Couldn't dispatch task");
			}
		} else if (refcnt->ir_waiting == REF_WAIT_SYNC) {
			cv_signal(&refcnt->ir_cv);
		}
	}
	mutex_exit(&refcnt->ir_mutex);
}

void
idm_refcnt_rele_and_destroy(idm_refcnt_t *refcnt, idm_refcnt_cb_t *cb_func)
{
	mutex_enter(&refcnt->ir_mutex);
	ASSERT(refcnt->ir_refcnt > 0);
	refcnt->ir_refcnt--;
	REFCNT_AUDIT(refcnt);

	/*
	 * Someone is waiting for this object to go idle so check if
	 * refcnt is 0.  Waiting on an object then later grabbing another
	 * reference is not allowed so we don't need to handle that case.
	 */
	if (refcnt->ir_refcnt == 0) {
		refcnt->ir_cb = cb_func;
		refcnt->ir_waiting = REF_WAIT_ASYNC;
		if (taskq_dispatch(idm.idm_global_taskq,
		    &idm_refcnt_unref_task, refcnt, TQ_SLEEP) == NULL) {
			cmn_err(CE_WARN,
			    "idm_refcnt_rele: Couldn't dispatch task");
		}
	}
	mutex_exit(&refcnt->ir_mutex);
}

void
idm_refcnt_wait_ref(idm_refcnt_t *refcnt)
{
	mutex_enter(&refcnt->ir_mutex);
	refcnt->ir_waiting = REF_WAIT_SYNC;
	REFCNT_AUDIT(refcnt);
	while (refcnt->ir_refcnt != 0)
		cv_wait(&refcnt->ir_cv, &refcnt->ir_mutex);
	mutex_exit(&refcnt->ir_mutex);
}

void
idm_refcnt_async_wait_ref(idm_refcnt_t *refcnt, idm_refcnt_cb_t *cb_func)
{
	mutex_enter(&refcnt->ir_mutex);
	refcnt->ir_waiting = REF_WAIT_ASYNC;
	refcnt->ir_cb = cb_func;
	REFCNT_AUDIT(refcnt);
	/*
	 * It's possible we don't have any references.  To make things easier
	 * on the caller use a taskq to call the callback instead of
	 * calling it synchronously
	 */
	if (refcnt->ir_refcnt == 0) {
		if (taskq_dispatch(idm.idm_global_taskq,
		    &idm_refcnt_unref_task, refcnt, TQ_SLEEP) == NULL) {
			cmn_err(CE_WARN,
			    "idm_refcnt_async_wait_ref: "
			    "Couldn't dispatch task");
		}
	}
	mutex_exit(&refcnt->ir_mutex);
}

void
idm_refcnt_destroy_unref_obj(idm_refcnt_t *refcnt,
    idm_refcnt_cb_t *cb_func)
{
	mutex_enter(&refcnt->ir_mutex);
	if (refcnt->ir_refcnt == 0) {
		mutex_exit(&refcnt->ir_mutex);
		(*cb_func)(refcnt->ir_referenced_obj);
		return;
	}
	mutex_exit(&refcnt->ir_mutex);
}

void
idm_conn_hold(idm_conn_t *ic)
{
	idm_refcnt_hold(&ic->ic_refcnt);
}

void
idm_conn_rele(idm_conn_t *ic)
{
	idm_refcnt_rele(&ic->ic_refcnt);
}


static int
_idm_init(void)
{
	/* Initialize the rwlock for the taskid table */
	rw_init(&idm.idm_taskid_table_lock, NULL, RW_DRIVER, NULL);

	/* Initialize the global mutex and taskq */
	mutex_init(&idm.idm_global_mutex, NULL, MUTEX_DEFAULT, NULL);

	cv_init(&idm.idm_tgt_svc_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&idm.idm_wd_cv, NULL, CV_DEFAULT, NULL);

	idm.idm_global_taskq = taskq_create("idm_global_taskq", 1, minclsyspri,
	    4, 4, TASKQ_PREPOPULATE);
	if (idm.idm_global_taskq == NULL) {
		cv_destroy(&idm.idm_wd_cv);
		cv_destroy(&idm.idm_tgt_svc_cv);
		mutex_destroy(&idm.idm_global_mutex);
		rw_destroy(&idm.idm_taskid_table_lock);
		return (ENOMEM);
	}

	/* Start watchdog thread */
	idm.idm_wd_thread = thread_create(NULL, 0,
	    idm_wd_thread, NULL, 0, &p0, TS_RUN, minclsyspri);
	if (idm.idm_wd_thread == NULL) {
		/* Couldn't create the watchdog thread */
		taskq_destroy(idm.idm_global_taskq);
		cv_destroy(&idm.idm_wd_cv);
		cv_destroy(&idm.idm_tgt_svc_cv);
		mutex_destroy(&idm.idm_global_mutex);
		rw_destroy(&idm.idm_taskid_table_lock);
		return (ENOMEM);
	}

	/* Pause until the watchdog thread is running */
	mutex_enter(&idm.idm_global_mutex);
	while (!idm.idm_wd_thread_running)
		cv_wait(&idm.idm_wd_cv, &idm.idm_global_mutex);
	mutex_exit(&idm.idm_global_mutex);

	/*
	 * Allocate the task ID table and set "next" to 0.
	 */

	idm.idm_taskid_max = idm_max_taskids;
	idm.idm_taskid_table = (idm_task_t **)
	    kmem_zalloc(idm.idm_taskid_max * sizeof (idm_task_t *), KM_SLEEP);
	idm.idm_taskid_next = 0;

	/* Create the global buffer and task kmem caches */
	idm.idm_buf_cache = kmem_cache_create("idm_buf_cache",
	    sizeof (idm_buf_t), 8, NULL, NULL, NULL, NULL, NULL, KM_SLEEP);

	/*
	 * Note, we're explicitly allocating an additional iSER header-
	 * sized chunk for each of these elements. See idm_task_constructor().
	 */
	idm.idm_task_cache = kmem_cache_create("idm_task_cache",
	    sizeof (idm_task_t) + IDM_TRANSPORT_HEADER_LENGTH, 8,
	    &idm_task_constructor, &idm_task_destructor,
	    NULL, NULL, NULL, KM_SLEEP);

	/* Create the service and connection context lists */
	list_create(&idm.idm_tgt_svc_list, sizeof (idm_svc_t),
	    offsetof(idm_svc_t, is_list_node));
	list_create(&idm.idm_tgt_conn_list, sizeof (idm_conn_t),
	    offsetof(idm_conn_t, ic_list_node));
	list_create(&idm.idm_ini_conn_list, sizeof (idm_conn_t),
	    offsetof(idm_conn_t, ic_list_node));

	/* Initialize the native sockets transport */
	idm_so_init(&idm_transport_list[IDM_TRANSPORT_TYPE_SOCKETS]);

	/* Create connection ID pool */
	(void) idm_idpool_create(&idm.idm_conn_id_pool);

	return (DDI_SUCCESS);
}

static int
_idm_fini(void)
{
	if (!list_is_empty(&idm.idm_ini_conn_list) ||
	    !list_is_empty(&idm.idm_tgt_conn_list) ||
	    !list_is_empty(&idm.idm_tgt_svc_list)) {
		return (EBUSY);
	}

	mutex_enter(&idm.idm_global_mutex);
	idm.idm_wd_thread_running = B_FALSE;
	cv_signal(&idm.idm_wd_cv);
	mutex_exit(&idm.idm_global_mutex);

	thread_join(idm.idm_wd_thread_did);

	idm_idpool_destroy(&idm.idm_conn_id_pool);
	idm_so_fini();
	list_destroy(&idm.idm_ini_conn_list);
	list_destroy(&idm.idm_tgt_conn_list);
	list_destroy(&idm.idm_tgt_svc_list);
	kmem_cache_destroy(idm.idm_task_cache);
	kmem_cache_destroy(idm.idm_buf_cache);
	kmem_free(idm.idm_taskid_table,
	    idm.idm_taskid_max * sizeof (idm_task_t *));
	mutex_destroy(&idm.idm_global_mutex);
	cv_destroy(&idm.idm_wd_cv);
	cv_destroy(&idm.idm_tgt_svc_cv);
	rw_destroy(&idm.idm_taskid_table_lock);

	return (0);
}
