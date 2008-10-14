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
 *
 * iSNS Client
 */

#include "iscsi.h"		/* For ISCSI_MAX_IOVEC */
#include "isns_protocol.h"
#include "isns_client.h"
#include "persistent.h"

#ifdef _KERNEL
#include <sys/sunddi.h>
#else
#include <stdlib.h>
#endif
#include <netinet/tcp.h>
#include <sys/types.h>

/* For local use */
#define	ISNS_MAX_IOVEC		5
#define	MAX_XID			(2^16)
#define	MAX_RCV_RSP_COUNT	10	/* Maximum number of unmatched xid */
#define	ISNS_RCV_TIMEOUT	5
#define	ISNS_RCV_RETRY_MAX	2
#define	IPV4_RSVD_BYTES		10

typedef struct isns_reg_arg {
	iscsi_addr_t *isns_server_addr;
	uint8_t *node_name;
	size_t node_name_len;
	uint8_t *node_alias;
	size_t node_alias_len;
	uint32_t node_type;
	uint8_t *lhba_handle;
} isns_reg_arg_t;

typedef struct isns_async_thread_arg {
	uint8_t *lhba_handle;
	void *listening_so;
} isns_async_thread_arg_t;

/* One global queue to serve all LHBA instances. */
static ddi_taskq_t *reg_query_taskq;
static kmutex_t reg_query_taskq_mutex;

/* One global queue to serve all LHBA instances. */
static ddi_taskq_t *scn_taskq;
static kmutex_t scn_taskq_mutex;

/* One globally maintained transaction ID. */
static uint16_t xid = 0;

/*
 * One SCN callback registration per LHBA instance. For now, since we
 * support only one instance, we create one place holder for the
 * callback.
 */
void (*scn_callback_p)(void *);

/*
 * One thread, port, local address, and listening socket per LHBA instance.
 * For now, since we support only one instance, we create one set of place
 * holder for these data.
 */
static boolean_t esi_scn_thr_to_shutdown = B_FALSE;
static iscsi_thread_t *esi_scn_thr_id = NULL;
static iscsi_addr_t *local_addr = NULL;
static void *instance_listening_so = NULL;
/*
 * This mutex protects all the per LHBA instance variables, i.e.,
 * esi_scn_thr_to_shutdown, esi_scn_thr_id, local_addr, and
 * instance_listening_so.
 */
static kmutex_t esi_scn_thr_mutex;

/* iSNS related helpers */
/* Return status */
#define	ISNS_OK				0
#define	ISNS_BAD_SVR_ADDR		1
#define	ISNS_INTERNAL_ERR		2
#define	ISNS_CANNOT_FIND_LOCAL_ADDR	3
static int discover_isns_server(uint8_t *lhba_handle,
    iscsi_addr_list_t **isns_server_addrs);
static int create_esi_scn_thr(uint8_t *lhba_handle,
    iscsi_addr_t *isns_server_addr);
static void esi_scn_thr_cleanup(void);
static void register_isns_client(void *arg);
static isns_status_t do_isns_dev_attr_reg(iscsi_addr_t *isns_server_addr,
    uint8_t *node_name, uint8_t *node_alias, uint32_t node_type);
static isns_status_t do_isns_dev_dereg(iscsi_addr_t *isns_server_addr,
    uint8_t *node_name);

/*
 * Make query to all iSNS servers visible to the specified LHBA.
 * The query could be made for all target nodes or for a specific target
 * node.
 */
static isns_status_t do_isns_query(boolean_t is_query_all_nodes_b,
    uint8_t *lhba_handle, uint8_t *target_node_name,
    uint8_t *source_node_name, uint8_t *source_node_alias,
    uint32_t source_node_type, isns_portal_group_list_t **pg_list);

/*
 * Create DevAttrQuery message requesting portal group information for all
 * target nodes. Send it to the specified iSNS server. Parse the
 * DevAttrQueryRsp PDU and translate the results into a portal group list
 * object.
 */
static isns_status_t do_isns_dev_attr_query_all_nodes(
    iscsi_addr_t *isns_server_addr, uint8_t *node_name,
    uint8_t *node_alias, isns_portal_group_list_t **pg_list);

/*
 * Create DevAttrQuery message requesting portal group information for the
 * specified target node. Send it to the specified iSNS server. Parse the
 * DevAttrQueryRsp PDU and translate the results into a portal group list
 * object.
 */
static isns_status_t do_isns_dev_attr_query_one_node(
    iscsi_addr_t *isns_server_addr, uint8_t *target_node_name,
    uint8_t *source_node_name, uint8_t *source_node_alias,
    uint32_t source_node_type, isns_portal_group_list_t **pg_list);

static void isns_service_esi_scn(iscsi_thread_t *thread, void* arg);
static void (*scn_callback_lookup(uint8_t *lhba_handle))(void *);

/* Transport related helpers */
static void *isns_open(iscsi_addr_t *isns_server_addr);
static ssize_t isns_send_pdu(void *socket, isns_pdu_t *pdu);
static size_t isns_rcv_pdu(void *so, isns_pdu_t **pdu, size_t *pdu_size);
static boolean_t find_local_portal(iscsi_addr_t *isns_server_addr,
    iscsi_addr_t **local_addr, void **listening_so);

/* iSNS protocol related helpers */
static size_t isns_create_pdu_header(uint16_t func_id,
    uint16_t flags, isns_pdu_t **pdu);
static int isns_add_attr(isns_pdu_t *pdu,
    size_t max_pdu_size, uint32_t attr_id, uint32_t attr_len,
    void *attr_data, uint32_t attr_numeric_data);
static uint16_t create_xid(void);
static size_t isns_create_dev_attr_reg_pdu(
    uint8_t *node_name, uint8_t *node_alias, uint32_t node_type,
    uint16_t *xid, isns_pdu_t **out_pdu);
static size_t isns_create_dev_dereg_pdu(uint8_t *node_name,
    uint16_t *xid_p, isns_pdu_t **out_pdu);
static size_t isns_create_dev_attr_qry_target_nodes_pdu(
    uint8_t *node_name, uint8_t *node_alias, uint16_t *xid,
    isns_pdu_t **out_pdu);
static size_t isns_create_dev_attr_qry_one_pg_pdu(
    uint8_t *target_node_name, uint8_t *source_node_name,
    uint16_t *xid, isns_pdu_t **out_pdu);
static size_t isns_create_esi_rsp_pdu(uint32_t rsp_status_code,
    isns_pdu_t *pdu, uint16_t *xid, isns_pdu_t **out_pdu);
static size_t isns_create_scn_reg_pdu(uint8_t *node_name,
    uint8_t *node_alias, uint16_t *xid, isns_pdu_t **out_pdu);
static size_t isns_create_scn_dereg_pdu(uint8_t *node_name,
    uint16_t *xid_p, isns_pdu_t **out_pdu);
static size_t isns_create_scn_rsp_pdu(uint32_t rsp_status_code,
    isns_pdu_t *pdu, uint16_t *xid, isns_pdu_t **out_pdu);
static uint32_t isns_process_dev_attr_reg_rsp(isns_pdu_t *resp_pdu_p);
static uint32_t isns_process_dev_attr_dereg_rsp(isns_pdu_t *resp_pdu_p);

/*
 * Process and parse a DevAttrQryRsp message. The routine creates a list
 * of Portal Group objects if the message is parasable without any issue.
 * If the parsing is not successful, the pg_list will be set to NULL.
 */
static uint32_t isns_process_dev_attr_qry_target_nodes_pdu(
    iscsi_addr_t *isns_server_addr, uint16_t payload_funcId,
    isns_resp_t *resp_p, size_t resp_len,
    isns_portal_group_list_t **pg_list);
static uint32_t isns_process_scn_reg_rsp(isns_pdu_t *resp_pdu_p);
static uint32_t isns_process_scn_dereg_rsp(isns_pdu_t *resp_pdu_p);
static uint32_t isns_process_esi(isns_pdu_t *esi_pdu_p);
static uint32_t isns_process_scn(isns_pdu_t *scn_pdu_p, uint8_t *lhba_handle);

void
isns_client_init()
{
	mutex_init(&reg_query_taskq_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_enter(&reg_query_taskq_mutex);
	reg_query_taskq = ddi_taskq_create(NULL, "isns_reg_query_taskq",
	    1, TASKQ_DEFAULTPRI, 0);
	mutex_exit(&reg_query_taskq_mutex);

	mutex_init(&scn_taskq_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_enter(&scn_taskq_mutex);
	scn_taskq = ddi_taskq_create(NULL, "isns_scn_taskq",
	    1, TASKQ_DEFAULTPRI, 0);
	mutex_exit(&scn_taskq_mutex);

	mutex_init(&esi_scn_thr_mutex, NULL, MUTEX_DRIVER, NULL);

	/* MISC initializations. */
	scn_callback_p = NULL;
	esi_scn_thr_id = NULL;
	local_addr = NULL;
	instance_listening_so = NULL;
	esi_scn_thr_to_shutdown = B_FALSE;
	xid = 0;
}

void
isns_client_cleanup()
{
	ddi_taskq_t *tmp_taskq_p;

	mutex_enter(&scn_taskq_mutex);
	tmp_taskq_p = scn_taskq;
	scn_taskq = NULL;
	mutex_exit(&scn_taskq_mutex);
	ddi_taskq_destroy(tmp_taskq_p);

	mutex_enter(&reg_query_taskq_mutex);
	tmp_taskq_p = reg_query_taskq;
	reg_query_taskq = NULL;
	mutex_exit(&reg_query_taskq_mutex);
	ddi_taskq_destroy(tmp_taskq_p);

	mutex_destroy(&reg_query_taskq_mutex);
	mutex_destroy(&scn_taskq_mutex);

	esi_scn_thr_cleanup();

	mutex_destroy(&esi_scn_thr_mutex);
}

isns_status_t
isns_reg(uint8_t *lhba_handle,
	uint8_t *node_name,
	size_t node_name_len,
	uint8_t *node_alias,
	size_t node_alias_len,
	uint32_t node_type,
	void (*scn_callback)(void *))
{
	int i;
	int list_space;
	iscsi_addr_list_t *isns_server_addr_list;
	isns_reg_arg_t *reg_args_p;

	/* Look up the iSNS Server address(es) based on the specified ISID */
	if (discover_isns_server(lhba_handle, &isns_server_addr_list) !=
	    ISNS_OK) {
		return (isns_no_svr_found);
	}

	/* No iSNS server discovered - no registration needed. */
	if (isns_server_addr_list->al_out_cnt == 0) {
		list_space = sizeof (iscsi_addr_list_t);
		kmem_free(isns_server_addr_list, list_space);
		isns_server_addr_list = NULL;
		return (isns_no_svr_found);
	}

	/* Check and create ESI/SCN threads and populate local address */
	for (i = 0; i < isns_server_addr_list->al_out_cnt; i++) {
		if (create_esi_scn_thr(lhba_handle,
		    &(isns_server_addr_list->al_addrs[i])) == ISNS_OK) {
			break;
		}
	}
	if (i == isns_server_addr_list->al_out_cnt) {
		/*
		 * Problem creating ESI/SCN thread
		 * Free the server list
		 */
		list_space = sizeof (iscsi_addr_list_t);
		if (isns_server_addr_list->al_out_cnt > 0) {
			list_space += (sizeof (iscsi_addr_t) *
			    (isns_server_addr_list->al_out_cnt - 1));
		}
		kmem_free(isns_server_addr_list, list_space);
		isns_server_addr_list = NULL;
		return (isns_internal_err);
	}

	/* Register against all iSNS servers discovered. */
	for (i = 0; i < isns_server_addr_list->al_out_cnt; i++) {
		reg_args_p = kmem_zalloc(sizeof (isns_reg_arg_t), KM_SLEEP);
		reg_args_p->isns_server_addr =
		    kmem_zalloc(sizeof (iscsi_addr_t), KM_SLEEP);
		bcopy(&isns_server_addr_list->al_addrs[i],
		    reg_args_p->isns_server_addr, sizeof (iscsi_addr_t));
		reg_args_p->node_name = kmem_zalloc(node_name_len, KM_SLEEP);
		bcopy(node_name, reg_args_p->node_name, node_name_len);
		reg_args_p->node_name_len = node_name_len;
		reg_args_p->node_alias = kmem_zalloc(node_alias_len, KM_SLEEP);
		bcopy(node_alias, reg_args_p->node_alias, node_alias_len);
		reg_args_p->node_alias_len = node_alias_len;
		reg_args_p->node_type = node_type;

		/* Dispatch the registration request */
		register_isns_client(reg_args_p);
	}

	/* Free the server list */
	list_space = sizeof (iscsi_addr_list_t);
	if (isns_server_addr_list->al_out_cnt > 0) {
		list_space += (sizeof (iscsi_addr_t) *
		    (isns_server_addr_list->al_out_cnt - 1));
	}
	kmem_free(isns_server_addr_list, list_space);
	isns_server_addr_list = NULL;

	/* Register the scn_callback. */
	scn_callback_p = scn_callback;

	return (isns_ok);
}

isns_status_t
isns_reg_one_server(entry_t *isns_server,
	uint8_t *lhba_handle,
	uint8_t *node_name,
	size_t node_name_len,
	uint8_t *node_alias,
	size_t node_alias_len,
	uint32_t node_type,
	void (*scn_callback)(void *))
{
	int status;
	iscsi_addr_t *ap;
	isns_reg_arg_t *reg_args_p;

	ap = (iscsi_addr_t *)kmem_zalloc(sizeof (iscsi_addr_t), KM_SLEEP);
	ap->a_port = isns_server->e_port;
	ap->a_addr.i_insize = isns_server->e_insize;
	if (isns_server->e_insize == sizeof (struct in_addr)) {
		ap->a_addr.i_addr.in4.s_addr = (isns_server->e_u.u_in4.s_addr);
	} else if (isns_server->e_insize == sizeof (struct in6_addr)) {
		bcopy(&(isns_server->e_u.u_in6.s6_addr),
		    ap->a_addr.i_addr.in6.s6_addr,
		    sizeof (struct in6_addr));
	} else {
		kmem_free(ap, sizeof (iscsi_addr_t));
		return (isns_op_failed);
	}

	/* Check and create ESI/SCN threads and populate local address */
	if ((status = create_esi_scn_thr(lhba_handle, ap))
	    != ISNS_OK) {
		/* Problem creating ESI/SCN thread */
		DTRACE_PROBE1(isns_reg_one_server_create_esi_scn_thr,
		    int, status);
		kmem_free(ap, sizeof (iscsi_addr_t));
		return (isns_internal_err);
	}

	reg_args_p = kmem_zalloc(sizeof (isns_reg_arg_t), KM_SLEEP);
	reg_args_p->isns_server_addr =
	    kmem_zalloc(sizeof (iscsi_addr_t), KM_SLEEP);
	bcopy(ap, reg_args_p->isns_server_addr, sizeof (iscsi_addr_t));
	reg_args_p->node_name = kmem_zalloc(node_name_len, KM_SLEEP);
	bcopy(node_name, reg_args_p->node_name, node_name_len);
	reg_args_p->node_name_len = node_name_len;
	reg_args_p->node_alias = kmem_zalloc(node_alias_len, KM_SLEEP);
	bcopy(node_alias, reg_args_p->node_alias, node_alias_len);
	reg_args_p->node_alias_len = node_alias_len;
	reg_args_p->node_type = node_type;

	/* Dispatch the registration request */
	register_isns_client(reg_args_p);

	/* Register the scn_callback. */
	scn_callback_p = scn_callback;

	kmem_free(ap, sizeof (iscsi_addr_t));
	return (isns_ok);
}

isns_status_t
isns_dereg(uint8_t *lhba_handle,
	uint8_t *node_name)
{
	int i;
	int isns_svr_lst_sz;
	int list_space;
	iscsi_addr_list_t *isns_server_addr_list = NULL;
	isns_status_t dereg_stat, combined_dereg_stat;

	/* Look up the iSNS Server address(es) based on the specified ISID */
	if (discover_isns_server(lhba_handle, &isns_server_addr_list) !=
	    ISNS_OK) {
		return (isns_no_svr_found);
	}
	ASSERT(isns_server_addr_list != NULL);
	if (isns_server_addr_list->al_out_cnt == 0) {
		isns_svr_lst_sz = sizeof (iscsi_addr_list_t);
		kmem_free(isns_server_addr_list, isns_svr_lst_sz);
		isns_server_addr_list = NULL;
		return (isns_no_svr_found);
	}

	combined_dereg_stat = isns_ok;
	for (i = 0; i < isns_server_addr_list->al_out_cnt; i++) {
		dereg_stat = do_isns_dev_dereg(
		    &isns_server_addr_list->al_addrs[i],
		    node_name);
		if (dereg_stat == isns_ok) {
			if (combined_dereg_stat != isns_ok) {
				combined_dereg_stat = isns_op_partially_failed;
			}
		} else {
			if (combined_dereg_stat == isns_ok) {
				combined_dereg_stat = isns_op_partially_failed;
			}
		}
	}

	/* Free the server list. */
	list_space = sizeof (iscsi_addr_list_t);
	if (isns_server_addr_list->al_out_cnt > 0) {
		list_space += (sizeof (iscsi_addr_t) *
		    (isns_server_addr_list->al_out_cnt - 1));
	}
	kmem_free(isns_server_addr_list, list_space);
	isns_server_addr_list = NULL;

	/* Cleanup ESI/SCN thread. */
	esi_scn_thr_cleanup();

	return (combined_dereg_stat);
}

isns_status_t
isns_dereg_one_server(entry_t *isns_server,
	uint8_t *node_name,
	boolean_t is_last_isns_server_b)
{
	iscsi_addr_t *ap;
	isns_status_t dereg_stat;

	ap = (iscsi_addr_t *)kmem_zalloc(sizeof (iscsi_addr_t), KM_SLEEP);
	ap->a_port = isns_server->e_port;
	ap->a_addr.i_insize = isns_server->e_insize;
	if (isns_server->e_insize == sizeof (struct in_addr)) {
		ap->a_addr.i_addr.in4.s_addr = (isns_server->e_u.u_in4.s_addr);
	} else if (isns_server->e_insize == sizeof (struct in6_addr)) {
		bcopy(&(isns_server->e_u.u_in6.s6_addr),
		    ap->a_addr.i_addr.in6.s6_addr,
		    sizeof (struct in6_addr));
	} else {
		kmem_free(ap, sizeof (iscsi_addr_t));
		return (isns_op_failed);
	}

	dereg_stat = do_isns_dev_dereg(ap, node_name);

	kmem_free(ap, sizeof (iscsi_addr_t));

	if (is_last_isns_server_b == B_TRUE) {
		/*
		 * Clean up ESI/SCN thread resource if it is the
		 * last known iSNS server.
		 */
		esi_scn_thr_cleanup();
	}

	return (dereg_stat);
}

isns_status_t
isns_query(uint8_t *lhba_handle,
	uint8_t *node_name,
	uint8_t *node_alias,
	uint32_t node_type,
	isns_portal_group_list_t **pg_list)
{
	return (do_isns_query(B_TRUE,
	    lhba_handle,
	    (uint8_t *)"",
	    node_name,
	    node_alias,
	    node_type,
	    pg_list));
}

/* ARGSUSED */
isns_status_t
isns_query_one_server(iscsi_addr_t *isns_server_addr,
	uint8_t *lhba_handle,
	uint8_t *node_name,
	uint8_t *node_alias,
	uint32_t node_type,
	isns_portal_group_list_t **pg_list)
{
	return (do_isns_dev_attr_query_all_nodes(isns_server_addr,
	    node_name,
	    node_alias,
	    pg_list));
}

isns_status_t
isns_query_one_node(uint8_t *target_node_name,
	uint8_t *lhba_handle,
	uint8_t *source_node_name,
	uint8_t *source_node_alias,
	uint32_t source_node_type,
	isns_portal_group_list_t **pg_list)
{
	return (do_isns_query(B_FALSE,
	    lhba_handle,
	    target_node_name,
	    source_node_name,
	    source_node_alias,
	    source_node_type,
	    pg_list));
}

/* ARGSUSED */
isns_status_t
isns_query_one_server_one_node(iscsi_addr_t *isns_server_addr,
	uint8_t *target_node_name,
	uint8_t *lhba_handle,
	uint8_t *source_node_name,
	uint8_t *source_node_alias,
	uint32_t source_node_type,
	isns_portal_group_list_t **pg_list) {
	/* Not supported yet. */
	*pg_list = NULL;
	return (isns_op_failed);
}

/* ARGSUSED */
static
int
discover_isns_server(uint8_t *lhba_handle,
	iscsi_addr_list_t **isns_server_addrs)
{
	entry_t e;
	int i;
	int isns_server_count = 1;
	int list_space;
	void *void_p;

	/*
	 * Use supported iSNS server discovery method to find out all the
	 * iSNS servers. For now, only static configuration method is
	 * supported.
	 */
	isns_server_count = 0;
	void_p = NULL;
	persistent_isns_addr_lock();
	while (persistent_isns_addr_next(&void_p, &e) == B_TRUE) {
		isns_server_count++;
	}
	persistent_isns_addr_unlock();

	list_space = sizeof (iscsi_addr_list_t);
	if (isns_server_count > 0) {
		list_space += (sizeof (iscsi_addr_t) * (isns_server_count - 1));
	}
	*isns_server_addrs = (iscsi_addr_list_t *)kmem_zalloc(list_space,
	    KM_SLEEP);
	(*isns_server_addrs)->al_out_cnt = isns_server_count;

	persistent_isns_addr_lock();
	i = 0;
	void_p = NULL;
	while (persistent_isns_addr_next(&void_p, &e) == B_TRUE) {
		iscsi_addr_t *ap;

		ap = &((*isns_server_addrs)->al_addrs[i]);
		ap->a_port = e.e_port;
		ap->a_addr.i_insize = e.e_insize;
		if (e.e_insize == sizeof (struct in_addr)) {
			ap->a_addr.i_addr.in4.s_addr = (e.e_u.u_in4.s_addr);
		} else if (e.e_insize == sizeof (struct in6_addr)) {
			bcopy(&e.e_u.u_in6.s6_addr,
			    ap->a_addr.i_addr.in6.s6_addr,
			    sizeof (struct in6_addr));
		} else {
			kmem_free(*isns_server_addrs, list_space);
			*isns_server_addrs = NULL;
			(*isns_server_addrs)->al_out_cnt = 0;
			return (ISNS_BAD_SVR_ADDR);
		}
		i++;
	}
	persistent_isns_addr_unlock();

	return (ISNS_OK);
}

static
int
create_esi_scn_thr(uint8_t *lhba_handle, iscsi_addr_t *isns_server_address)
{
	iscsi_addr_t *tmp_local_addr;
	void *listening_so = NULL;

	ASSERT(lhba_handle != NULL);
	ASSERT(isns_server_address != NULL);

	/* Determine local port and address. */
	mutex_enter(&esi_scn_thr_mutex);
	if (local_addr == NULL) {
		boolean_t rval;
		rval = find_local_portal(isns_server_address,
		    &tmp_local_addr, &listening_so);
		if (rval == B_FALSE) {
			local_addr = NULL;
			mutex_exit(&esi_scn_thr_mutex);
			if (listening_so != NULL) {
				iscsi_net->close(listening_so);
			}
			return (ISNS_CANNOT_FIND_LOCAL_ADDR);
		}
		local_addr = tmp_local_addr;
	}
	mutex_exit(&esi_scn_thr_mutex);

	/*
	 * Bringing up of the thread should happen regardless of the
	 * subsequent registration status. That means, do not destroy the
	 * ESI/SCN thread already created.
	 */
	/* Check and create ESI/SCN thread. */
	mutex_enter(&esi_scn_thr_mutex);
	if (esi_scn_thr_id == NULL) {
		char thr_name[ISCSI_TH_MAX_NAME_LEN];
		int rval;
		isns_async_thread_arg_t *larg;

		/* Assume the LHBA handle has a length of 4 */
		if (snprintf(thr_name, sizeof (thr_name) - 1,
		    "isns_client_esi_%x%x%x%x",
		    lhba_handle[0],
		    lhba_handle[1],
		    lhba_handle[2],
		    lhba_handle[3]) >=
		    sizeof (thr_name)) {
			esi_scn_thr_id = NULL;
			if (local_addr != NULL) {
				kmem_free(local_addr, sizeof (iscsi_addr_t));
				local_addr = NULL;
			}
			if (listening_so != NULL) {
				iscsi_net->close(listening_so);
				listening_so = NULL;
			}
			mutex_exit(&esi_scn_thr_mutex);
			return (ISNS_INTERNAL_ERR);
		}

		larg = kmem_zalloc(sizeof (isns_async_thread_arg_t), KM_SLEEP);
		larg->lhba_handle = lhba_handle;
		larg->listening_so = listening_so;
		instance_listening_so = listening_so;
		esi_scn_thr_to_shutdown = B_FALSE;
		esi_scn_thr_id = iscsi_thread_create(NULL,
		    thr_name, isns_service_esi_scn, (void *)larg);
		if (esi_scn_thr_id == NULL) {
			if (local_addr != NULL) {
				kmem_free(local_addr, sizeof (iscsi_addr_t));
				local_addr = NULL;
			}
			if (listening_so != NULL) {
				iscsi_net->close(listening_so);
				listening_so = NULL;
				instance_listening_so = NULL;
			}
			mutex_exit(&esi_scn_thr_mutex);
			return (ISNS_INTERNAL_ERR);
		}

		rval = iscsi_thread_start(esi_scn_thr_id);
		if (rval == B_FALSE) {
			iscsi_thread_destroy(esi_scn_thr_id);
			esi_scn_thr_id = NULL;
			if (local_addr != NULL) {
				kmem_free(local_addr, sizeof (iscsi_addr_t));
				local_addr = NULL;
			}
			if (listening_so != NULL) {
				iscsi_net->close(listening_so);
				listening_so = NULL;
				instance_listening_so = NULL;
			}
			mutex_exit(&esi_scn_thr_mutex);
			return (ISNS_INTERNAL_ERR);
		}
		iscsi_thread_send_wakeup(esi_scn_thr_id);
	}
	mutex_exit(&esi_scn_thr_mutex);

	return (ISNS_OK);
}

static
void
register_isns_client(void *arg)
{
	isns_reg_arg_t *reg_args;
	isns_status_t status;

	reg_args = (isns_reg_arg_t *)arg;

	/* Deregister stale registration (if any). */
	status = do_isns_dev_dereg(reg_args->isns_server_addr,
	    reg_args->node_name);

	if (status == isns_open_conn_err) {
		/* Cannot open connection to the server. Stop proceeding. */
		kmem_free(reg_args->isns_server_addr, sizeof (iscsi_addr_t));
		reg_args->isns_server_addr = NULL;
		kmem_free(reg_args->node_name, reg_args->node_name_len);
		reg_args->node_name = NULL;
		kmem_free(reg_args->node_alias, reg_args->node_alias_len);
		reg_args->node_alias = NULL;
		kmem_free(reg_args, sizeof (isns_reg_arg_t));
		return;
	}

	DTRACE_PROBE1(register_isns_client_dereg, isns_status_t, status);

	/* New registration. */
	status =  do_isns_dev_attr_reg(reg_args->isns_server_addr,
	    reg_args->node_name, reg_args->node_alias, reg_args->node_type);

	DTRACE_PROBE1(register_isns_client_reg, isns_status_t, status);

	/* Cleanup */
	kmem_free(reg_args->isns_server_addr, sizeof (iscsi_addr_t));
	reg_args->isns_server_addr = NULL;
	kmem_free(reg_args->node_name, reg_args->node_name_len);
	reg_args->node_name = NULL;
	kmem_free(reg_args->node_alias, reg_args->node_alias_len);
	reg_args->node_alias = NULL;
	kmem_free(reg_args, sizeof (isns_reg_arg_t));
}

static
isns_status_t
do_isns_dev_attr_reg(iscsi_addr_t *isns_server_addr,
	uint8_t *node_name, uint8_t *node_alias, uint32_t node_type)
{
	int rcv_rsp_cnt = 0;
	int rsp_status;
	isns_pdu_t *in_pdu, *out_pdu;
	isns_status_t rval;
	size_t bytes_received, in_pdu_size = 0, out_pdu_size = 0;
	uint16_t xid;
	void *so = NULL;

	out_pdu_size = isns_create_dev_attr_reg_pdu(
	    node_name,
	    node_alias,
	    node_type,
	    &xid, &out_pdu);
	if (out_pdu_size == 0) {
		return (isns_create_msg_err);
	}

	ASSERT(out_pdu != NULL);
	ASSERT(out_pdu_size > 0);

	so = isns_open(isns_server_addr);
	if (so == NULL) {
		/* Log a message and return */
		kmem_free(out_pdu, out_pdu_size);
		out_pdu = NULL;
		return (isns_open_conn_err);
	}

	if (isns_send_pdu(so, out_pdu) != 0) {
		iscsi_net->close(so);
		kmem_free(out_pdu, out_pdu_size);
		out_pdu = NULL;
		return (isns_send_msg_err);
	}

	/* Done with the out PDU - free it */
	kmem_free(out_pdu, out_pdu_size);
	out_pdu = NULL;

	rcv_rsp_cnt = 0;
	rval = isns_ok;
	for (;;) {
		bytes_received = isns_rcv_pdu(so, &in_pdu, &in_pdu_size);
		ASSERT(bytes_received >= (size_t)0);
		if (bytes_received == 0) {
			ASSERT(in_pdu == NULL);
			ASSERT(in_pdu_size == 0);
			rval = isns_rcv_msg_err;
			break;
		}

		ASSERT(in_pdu != NULL);
		ASSERT(in_pdu_size > 0);

		if (ntohs(in_pdu->xid) != xid) {
			rcv_rsp_cnt++;
			if (rcv_rsp_cnt < MAX_RCV_RSP_COUNT) {
				continue;
			} else {
				/* Exceed maximum receive count. */
				kmem_free(in_pdu, in_pdu_size);
				in_pdu = NULL;
				rval = isns_no_rsp_rcvd;
				break;
			}
		}

		rsp_status = isns_process_dev_attr_reg_rsp(in_pdu);
		if (rsp_status != ISNS_RSP_SUCCESSFUL) {
			if (rsp_status == ISNS_RSP_SRC_UNAUTHORIZED) {
				rval = isns_op_partially_failed;
			} else {
				rval = isns_op_failed;
			}
		}
		kmem_free(in_pdu, in_pdu_size);
		in_pdu = NULL;
		break;
	}

	if (rval != isns_ok) {
		iscsi_net->close(so);
		return (rval);
	}

	/* Always register SCN */
	out_pdu_size = isns_create_scn_reg_pdu(
	    node_name, node_alias,
	    &xid, &out_pdu);
	if (out_pdu_size == 0) {
		iscsi_net->close(so);
		return (isns_create_msg_err);
	}

	ASSERT(out_pdu != NULL);
	ASSERT(out_pdu_size > 0);

	if (isns_send_pdu(so, out_pdu) != 0) {
		iscsi_net->close(so);
		kmem_free(out_pdu, out_pdu_size);
		out_pdu = NULL;
		return (isns_send_msg_err);
	}

	/* Done with the out PDU - free it */
	kmem_free(out_pdu, out_pdu_size);
	out_pdu = NULL;

	rcv_rsp_cnt = 0;
	for (;;) {
		bytes_received = isns_rcv_pdu(so, &in_pdu, &in_pdu_size);
		ASSERT(bytes_received >= (size_t)0);
		if (bytes_received == 0) {
			ASSERT(in_pdu == NULL);
			ASSERT(in_pdu_size == 0);
			rval = isns_rcv_msg_err;
			break;
		}

		ASSERT(in_pdu != NULL);
		ASSERT(in_pdu_size > 0);

		if (ntohs(in_pdu->xid) != xid) {
			rcv_rsp_cnt++;
			if (rcv_rsp_cnt < MAX_RCV_RSP_COUNT) {
				continue;
			} else {
				/* Exceed maximum receive count. */
				kmem_free(in_pdu, in_pdu_size);
				in_pdu = NULL;
				rval = isns_no_rsp_rcvd;
				break;
			}
		}

		rsp_status = isns_process_scn_reg_rsp(in_pdu);
		if (rsp_status != ISNS_RSP_SUCCESSFUL) {
			rval = isns_op_failed;
		}
		kmem_free(in_pdu, in_pdu_size);
		in_pdu = NULL;
		break;
	}

	iscsi_net->close(so);

	return (rval);
}

static
isns_status_t
do_isns_dev_dereg(iscsi_addr_t *isns_server_addr,
	uint8_t *node_name)
{
	int rcv_rsp_cnt = 0;
	int rsp_status;
	isns_pdu_t *in_pdu, *out_pdu;
	isns_status_t rval;
	size_t bytes_received, in_pdu_size = 0, out_pdu_size = 0;
	uint16_t xid;
	void *so = NULL;

	out_pdu_size = isns_create_dev_dereg_pdu(
	    node_name,
	    &xid, &out_pdu);
	if (out_pdu_size == 0) {
		return (isns_create_msg_err);
	}

	ASSERT(out_pdu != NULL);
	ASSERT(out_pdu_size > 0);

	so = isns_open(isns_server_addr);
	if (so == NULL) {
		/* Log a message and return */
		kmem_free(out_pdu, out_pdu_size);
		out_pdu = NULL;
		return (isns_open_conn_err);
	}

	if (isns_send_pdu(so, out_pdu) != 0) {
		iscsi_net->close(so);
		kmem_free(out_pdu, out_pdu_size);
		out_pdu = NULL;
		return (isns_send_msg_err);
	}

	/* Done with the out PDU - free it */
	kmem_free(out_pdu, out_pdu_size);
	out_pdu = NULL;

	rcv_rsp_cnt = 0;
	rval = isns_ok;
	for (;;) {
		bytes_received = isns_rcv_pdu(so, &in_pdu, &in_pdu_size);
		ASSERT(bytes_received >= (size_t)0);
		if (bytes_received == 0) {
			ASSERT(in_pdu == NULL);
			ASSERT(in_pdu_size == 0);
			rval = isns_rcv_msg_err;
			break;
		}

		ASSERT(in_pdu != NULL);
		ASSERT(in_pdu_size > 0);

		if (ntohs(in_pdu->xid) != xid) {
			rcv_rsp_cnt++;
			if (rcv_rsp_cnt < MAX_RCV_RSP_COUNT) {
				continue;
			} else {
				/* Exceed maximum receive count. */
				kmem_free(in_pdu, in_pdu_size);
				in_pdu = NULL;
				rval = isns_no_rsp_rcvd;
				break;
			}
		}

		rsp_status = isns_process_dev_attr_dereg_rsp(in_pdu);
		if (rsp_status != ISNS_RSP_SUCCESSFUL) {
			rval = isns_op_failed;
		}
		kmem_free(in_pdu, in_pdu_size);
		in_pdu = NULL;
		break;
	}

	if (rval != isns_ok) {
		iscsi_net->close(so);
		return (rval);
	}

	/* Always deregister SCN */
	out_pdu_size = isns_create_scn_dereg_pdu(
	    node_name,
	    &xid, &out_pdu);
	if (out_pdu_size == 0) {
		iscsi_net->close(so);
		return (isns_create_msg_err);
	}

	ASSERT(out_pdu != NULL);
	ASSERT(out_pdu_size > 0);

	if (isns_send_pdu(so, out_pdu) != 0) {
		iscsi_net->close(so);
		kmem_free(out_pdu, out_pdu_size);
		out_pdu = NULL;
		return (isns_send_msg_err);
	}

	/* Done with the out PDU - free it */
	kmem_free(out_pdu, out_pdu_size);
	out_pdu = NULL;

	rcv_rsp_cnt = 0;
	for (;;) {
		bytes_received = isns_rcv_pdu(so, &in_pdu, &in_pdu_size);
		ASSERT(bytes_received >= (size_t)0);
		if (bytes_received == 0) {
			ASSERT(in_pdu == NULL);
			ASSERT(in_pdu_size == 0);
			rval = isns_rcv_msg_err;
			break;
		}

		ASSERT(in_pdu != NULL);
		ASSERT(in_pdu_size > 0);

		if (ntohs(in_pdu->xid) != xid) {
			rcv_rsp_cnt++;
			if (rcv_rsp_cnt < MAX_RCV_RSP_COUNT) {
				continue;
			} else {
				/* Exceed maximum receive count. */
				kmem_free(in_pdu, in_pdu_size);
				in_pdu = NULL;
				rval = isns_no_rsp_rcvd;
				break;
			}
		}

		rsp_status = isns_process_scn_dereg_rsp(in_pdu);
		if (rsp_status != ISNS_RSP_SUCCESSFUL) {
			rval = isns_op_failed;
		}
		kmem_free(in_pdu, in_pdu_size);
		in_pdu = NULL;
		break;
	}

	iscsi_net->close(so);

	return (rval);
}

static
isns_status_t
do_isns_query(boolean_t is_query_all_nodes_b,
	uint8_t *lhba_handle,
	uint8_t *target_node_name,
	uint8_t *source_node_name,
	uint8_t *source_node_alias,
	uint32_t source_node_type,
	isns_portal_group_list_t **pg_list)
{
	int i, j, k;
	int combined_num_of_pgs, combined_pg_lst_sz,
	    isns_svr_lst_sz,
	    tmp_pg_list_sz,
	    tmp_pg_lists_sz;
	iscsi_addr_list_t *isns_server_addr_list = NULL;
	isns_portal_group_t *pg;
	isns_portal_group_list_t *combined_pg_list,
	    *tmp_pg_list, **tmp_pg_lists;
	isns_status_t qry_stat, combined_qry_stat;

	/* Look up the iSNS Server address(es) based on the specified ISID */
	if (discover_isns_server(lhba_handle, &isns_server_addr_list) !=
	    ISNS_OK) {
		*pg_list = NULL;
		return (isns_no_svr_found);
	}
	if (isns_server_addr_list->al_out_cnt == 0) {
		isns_svr_lst_sz = sizeof (iscsi_addr_list_t);
		kmem_free(isns_server_addr_list, isns_svr_lst_sz);
		isns_server_addr_list = NULL;
		*pg_list = NULL;
		return (isns_no_svr_found);
	}

	/*
	 * isns_server_addr_list->al_out_cnt should not be zero by the
	 * time it comes to this point.
	 */
	tmp_pg_lists_sz = isns_server_addr_list->al_out_cnt *
	    sizeof (isns_portal_group_list_t *);
	tmp_pg_lists = (isns_portal_group_list_t **)kmem_zalloc(
	    tmp_pg_lists_sz, KM_SLEEP);
	combined_num_of_pgs = 0;
	combined_qry_stat = isns_ok;
	for (i = 0; i < isns_server_addr_list->al_out_cnt; i++) {
		if (is_query_all_nodes_b) {
			qry_stat = do_isns_dev_attr_query_all_nodes(
			    &isns_server_addr_list->al_addrs[i],
			    source_node_name,
			    source_node_alias,
			    &tmp_pg_list);
		} else {
			qry_stat = do_isns_dev_attr_query_one_node(
			    &isns_server_addr_list->al_addrs[i],
			    target_node_name,
			    source_node_name,
			    source_node_alias,
			    source_node_type,
			    &tmp_pg_list);
		}

		/* Record the portal group list retrieved from this server. */
		tmp_pg_lists[i] = tmp_pg_list;
		if (tmp_pg_list != NULL) {
			combined_num_of_pgs += tmp_pg_list->pg_out_cnt;
		}

		if (qry_stat == isns_ok) {
			if (combined_qry_stat != isns_ok) {
				combined_qry_stat = isns_op_partially_failed;
			}
		} else {
			if (combined_qry_stat != isns_op_partially_failed) {
				if (combined_qry_stat == isns_ok && i > 0) {
					combined_qry_stat =
					    isns_op_partially_failed;
				} else {
					combined_qry_stat = qry_stat;
				}
			}
		}

		if (is_query_all_nodes_b == B_FALSE) {
			if (qry_stat == isns_ok) {
				/*
				 * Break out of the loop if we already got
				 * the node information for one node.
				 */
				break;
			}
		}
	}

	/* Merge the retrieved portal lists */
	combined_pg_lst_sz = sizeof (isns_portal_group_list_t);
	if (combined_num_of_pgs > 0) {
		combined_pg_lst_sz += (combined_num_of_pgs - 1) *
		    sizeof (isns_portal_group_t);
	}
	combined_pg_list = (isns_portal_group_list_t *)kmem_zalloc(
	    combined_pg_lst_sz, KM_SLEEP);

	combined_pg_list->pg_out_cnt = combined_num_of_pgs;
	k = 0;
	for (i = 0; i < isns_server_addr_list->al_out_cnt; i++) {
		if (tmp_pg_lists[i] == NULL) {
			continue;
		}
		for (j = 0; j < tmp_pg_lists[i]->pg_out_cnt; j++) {
			pg = &(combined_pg_list->pg_list[k]);
			bcopy(&(tmp_pg_lists[i]->pg_list[j]),
			    pg, sizeof (isns_portal_group_t));
			k++;
		}
		tmp_pg_list_sz = sizeof (isns_portal_group_list_t);
		if (tmp_pg_lists[i]->pg_out_cnt > 0) {
			tmp_pg_list_sz += (tmp_pg_lists[i]->pg_out_cnt - 1) *
			    sizeof (isns_portal_group_t);
		}
		kmem_free(tmp_pg_lists[i], tmp_pg_list_sz);
		tmp_pg_lists[i] = NULL;
	}
	kmem_free(tmp_pg_lists, tmp_pg_lists_sz);
	tmp_pg_lists = NULL;

	isns_svr_lst_sz = sizeof (iscsi_addr_list_t);
	if (isns_server_addr_list->al_out_cnt > 0) {
		isns_svr_lst_sz += (sizeof (iscsi_addr_t) *
		    (isns_server_addr_list->al_out_cnt - 1));
	}
	kmem_free(isns_server_addr_list, isns_svr_lst_sz);
	isns_server_addr_list = NULL;

	DTRACE_PROBE1(list, isns_portal_group_list_t *, combined_pg_list);

	*pg_list = combined_pg_list;
	return (combined_qry_stat);
}

static
isns_status_t
do_isns_dev_attr_query_all_nodes(iscsi_addr_t *isns_server_addr,
	uint8_t *node_name,
	uint8_t *node_alias,
	isns_portal_group_list_t **pg_list)
{
	int bytes_received;
	int rcv_rsp_cnt = 0;
	int rsp_status;
	uint16_t xid, seq_id = 0, func_id;
	isns_pdu_t *in_pdu, *out_pdu;
	isns_pdu_mult_payload_t *combined_pdu = NULL, *old_combined_pdu = NULL;
	isns_status_t qry_stat;
	size_t out_pdu_size = 0, in_pdu_size = 0;
	size_t old_combined_pdu_size = 0, combined_pdu_size = 0;
	void *so = NULL;
	uint8_t *payload_ptr;

	/* Initialize */
	*pg_list = NULL;

	so = isns_open(isns_server_addr);
	if (so == NULL) {
		/* Log a message and return */
		return (isns_open_conn_err);
	}

	/*
	 * Then, ask for all PG attributes. Filter the non-target nodes.
	 */
	out_pdu_size = isns_create_dev_attr_qry_target_nodes_pdu(
	    node_name, node_alias, &xid, &out_pdu);
	if (out_pdu_size == 0) {
		iscsi_net->close(so);
		return (isns_create_msg_err);
	}

	ASSERT(out_pdu != NULL);
	ASSERT(out_pdu_size > 0);

	if (isns_send_pdu(so, out_pdu) != 0) {
		iscsi_net->close(so);
		kmem_free(out_pdu, out_pdu_size);
		out_pdu = NULL;
		return (isns_send_msg_err);
	}

	/* Done with the out PDU - free it */
	kmem_free(out_pdu, out_pdu_size);
	out_pdu = NULL;

	rcv_rsp_cnt = 0;
	qry_stat = isns_ok;
	for (;;) {
		uint16_t flags;

		bytes_received = isns_rcv_pdu(so, &in_pdu, &in_pdu_size);
		ASSERT(bytes_received >= 0);
		if (bytes_received == 0) {
			ASSERT(in_pdu == NULL);
			ASSERT(in_pdu_size == 0);
			qry_stat = isns_rcv_msg_err;
			break;
		}

		ASSERT(in_pdu != NULL);
		ASSERT(in_pdu_size > 0);

		/*
		 * make sure we are processing the right transaction id
		 */
		if (ntohs(in_pdu->xid) != xid) {
			rcv_rsp_cnt++;
			if (rcv_rsp_cnt < MAX_RCV_RSP_COUNT) {
				kmem_free(in_pdu, in_pdu_size);
				in_pdu = NULL;
				continue;
			} else {
				/* Exceed maximum receive count. */
				kmem_free(in_pdu, in_pdu_size);
				in_pdu = NULL;
				qry_stat = isns_no_rsp_rcvd;
				break;
			}
		}

		/*
		 * check to see if FIRST and LAST PDU flag is set
		 * if they are both set, then this response only has one
		 * pdu and we can process the pdu
		 */
		flags = in_pdu->flags;
		if (((flags & ISNS_FLAG_FIRST_PDU) == ISNS_FLAG_FIRST_PDU) &&
		    ((flags & ISNS_FLAG_LAST_PDU) == ISNS_FLAG_LAST_PDU)) {
			rsp_status =
			    isns_process_dev_attr_qry_target_nodes_pdu(
			    isns_server_addr,
			    in_pdu->func_id,
			    (isns_resp_t *)in_pdu->payload,
			    (size_t)in_pdu->payload_len,
			    pg_list);
			kmem_free(in_pdu, in_pdu_size);
			in_pdu = NULL;
			break;
		}
		/*
		 * this pdu is part of a multi-pdu response.  save off the
		 * the payload of this pdu and continue processing
		 */
		if ((flags & ISNS_FLAG_FIRST_PDU) == ISNS_FLAG_FIRST_PDU) {
			/* This is the first pdu, make sure sequence ID is 0 */
			if (in_pdu->seq != 0) {
				cmn_err(CE_NOTE, "isns query response invalid: "
				    "first pdu is not sequence ID 0");
				kmem_free(in_pdu, in_pdu_size);
				in_pdu = NULL;
				return (isns_op_failed);
			}
			seq_id = 0;

			/* create new pdu and copy in data from old pdu */
			combined_pdu_size = ISNSP_MULT_PAYLOAD_HEADER_SIZE +
			    in_pdu->payload_len;
			combined_pdu = (isns_pdu_mult_payload_t *)kmem_zalloc(
			    combined_pdu_size, KM_SLEEP);
			func_id = in_pdu->func_id;
			combined_pdu->payload_len = in_pdu->payload_len;
			bcopy(in_pdu->payload, combined_pdu->payload,
			    in_pdu->payload_len);

			/* done with in_pdu, free it */
			kmem_free(in_pdu, in_pdu_size);
			in_pdu = NULL;
		} else {
			seq_id++;
			if (in_pdu->seq != seq_id) {
				cmn_err(CE_NOTE, "isns query response invalid: "
				    "Missing sequence ID %d from isns query "
				    "response.", seq_id);
				kmem_free(in_pdu, in_pdu_size);
				in_pdu = NULL;
				if (combined_pdu != NULL) {
					kmem_free(combined_pdu,
					    combined_pdu_size);
					combined_pdu = NULL;
				}
				return (isns_op_failed);
			}
			/*
			 * if conbined_pdu_size is still zero, then we never
			 * processed the first pdu
			 */
			if (combined_pdu_size == 0) {
				cmn_err(CE_NOTE, "isns query response invalid: "
				    "Did not receive first pdu.\n");
				kmem_free(in_pdu, in_pdu_size);
				in_pdu = NULL;
				return (isns_op_failed);
			}
			/* save off the old combined pdu */
			old_combined_pdu_size = combined_pdu_size;
			old_combined_pdu = combined_pdu;

			/*
			 * alloc a new pdu big enough to also hold the new
			 * pdu payload
			 */
			combined_pdu_size += in_pdu->payload_len;
			combined_pdu = (isns_pdu_mult_payload_t *)kmem_zalloc(
			    combined_pdu_size, KM_SLEEP);

			/*
			 * copy the old pdu into the new allocated pdu buffer
			 * and append on the new pdu payload that we just
			 * received
			 */
			bcopy(old_combined_pdu, combined_pdu,
			    old_combined_pdu_size);

			payload_ptr = combined_pdu->payload +
			    combined_pdu->payload_len;
			combined_pdu->payload_len += in_pdu->payload_len;
			bcopy(in_pdu->payload, payload_ptr,
			    in_pdu->payload_len);

			/* free in_pdu and old_combined_pdu */
			kmem_free(in_pdu, in_pdu_size);
			kmem_free(old_combined_pdu, old_combined_pdu_size);
			in_pdu = NULL;
			old_combined_pdu = NULL;
		}
		/*
		 * check to see if this is the LAST pdu.
		 * if it is, we can process it and move on
		 * otherwise continue to wait for the next pdu
		 */
		if ((flags & ISNS_FLAG_LAST_PDU) == ISNS_FLAG_LAST_PDU) {
			rsp_status =
			    isns_process_dev_attr_qry_target_nodes_pdu(
			    isns_server_addr,
			    func_id,
			    (isns_resp_t *)combined_pdu->payload,
			    combined_pdu->payload_len,
			    pg_list);
			kmem_free(combined_pdu, combined_pdu_size);
			combined_pdu = NULL;
			break;
		}
	}
	if (rsp_status != ISNS_RSP_SUCCESSFUL) {
		qry_stat = isns_op_failed;
	}

	iscsi_net->close(so);

	return (qry_stat);
}

/* ARGSUSED */
static
isns_status_t
do_isns_dev_attr_query_one_node(iscsi_addr_t *isns_server_addr,
	uint8_t *target_node_name,
	uint8_t *source_node_name,
	uint8_t *source_node_alias,
	uint32_t source_node_type,
	isns_portal_group_list_t **pg_list)
{
	int bytes_received;
	int rcv_rsp_cnt;
	int rsp_status;
	isns_pdu_t *in_pdu, *out_pdu;
	isns_status_t rval;
	size_t out_pdu_size = 0, in_pdu_size = 0;
	uint16_t xid;
	void *so = NULL;

	/* Obtain the list of target type storage nodes first */
	out_pdu_size = isns_create_dev_attr_qry_one_pg_pdu(
	    target_node_name, source_node_name, &xid, &out_pdu);
	if (out_pdu_size == 0) {
		return (isns_create_msg_err);
	}

	ASSERT(out_pdu != NULL);
	ASSERT(out_pdu_size > 0);

	so = isns_open(isns_server_addr);
	if (so == NULL) {
		/* Log a message and return */
		kmem_free(out_pdu, out_pdu_size);
		out_pdu = NULL;
		return (isns_open_conn_err);
	}

	if (isns_send_pdu(so, out_pdu) != 0) {
		iscsi_net->close(so);
		kmem_free(out_pdu, out_pdu_size);
		out_pdu = NULL;
		return (isns_send_msg_err);
	}

	/* Done with the out PDU - free it */
	kmem_free(out_pdu, out_pdu_size);
	out_pdu = NULL;

	rcv_rsp_cnt = 0;
	rval = isns_ok;
	for (;;) {
		bytes_received = isns_rcv_pdu(so, &in_pdu, &in_pdu_size);
		ASSERT(bytes_received >= 0);
		if (bytes_received == 0) {
			ASSERT(in_pdu == NULL);
			ASSERT(in_pdu_size == 0);
			rval = isns_rcv_msg_err;
			break;
		}

		ASSERT(in_pdu != NULL);
		ASSERT(in_pdu_size > 0);

		if (ntohs(in_pdu->xid) != xid) {
			rcv_rsp_cnt++;
			if (rcv_rsp_cnt < MAX_RCV_RSP_COUNT) {
				continue;
			} else {
				/* Exceed maximum receive count. */
				kmem_free(in_pdu, in_pdu_size);
				in_pdu = NULL;
				rval = isns_no_rsp_rcvd;
				break;
			}
		}

		rsp_status = isns_process_dev_attr_qry_target_nodes_pdu(
		    isns_server_addr, in_pdu->func_id,
		    (isns_resp_t *)in_pdu->payload, (size_t)in_pdu->payload_len,
		    pg_list);
		if (rsp_status != ISNS_RSP_SUCCESSFUL) {
			rval = isns_op_failed;
		}
		kmem_free(in_pdu, in_pdu_size);
		in_pdu = NULL;
		break;
	}

	iscsi_net->close(so);

	return (rval);
}

static
void
*isns_open(iscsi_addr_t *isns_server_addr)
{
	int rval = 0;
	union {
		struct sockaddr sin;
		struct sockaddr_in s_in4;
		struct sockaddr_in6 s_in6;
	} sa_rsvr = { 0 };
	void *so;

	if (isns_server_addr->a_addr.i_insize == sizeof (struct in_addr)) {
		/* IPv4 */
		sa_rsvr.s_in4.sin_family = AF_INET;
		sa_rsvr.s_in4.sin_port = htons(isns_server_addr->a_port);
		sa_rsvr.s_in4.sin_addr.s_addr =
		    isns_server_addr->a_addr.i_addr.in4.s_addr;

		/* Create socket */
		so = iscsi_net->socket(AF_INET, SOCK_STREAM, 0);
	} else {
		/* IPv6 */
		sa_rsvr.s_in6.sin6_family = AF_INET6;
		bcopy(&(isns_server_addr->a_addr.i_addr.in6),
		    sa_rsvr.s_in6.sin6_addr.s6_addr,
		    sizeof (struct in6_addr));
		sa_rsvr.s_in6.sin6_port = htons(isns_server_addr->a_port);
		/* Create socket */
		so = iscsi_net->socket(AF_INET6, SOCK_STREAM, 0);
	}

	if (so == NULL) {
		return (NULL);
	}

	rval = iscsi_net->connect(so, &sa_rsvr.sin,
	    (isns_server_addr->a_addr.i_insize == sizeof (struct in_addr)) ?
	    sizeof (struct sockaddr_in) :
	    sizeof (struct sockaddr_in6), 0, 0);

	if (rval != 0) {
		/* Flag value 2 indicates both cantsend and cantrecv */
		iscsi_net->shutdown(so, 2);
		iscsi_net->close(so);
		return (NULL);
	}

	(void) iscsi_net->getsockname(so);

	return (so);
}

static ssize_t
isns_send_pdu(void *socket, isns_pdu_t *pdu)
{
	int		iovlen = 0;
	iovec_t		iovec[ISNS_MAX_IOVEC];
	struct msghdr	msg;
	size_t		send_len;
	size_t		total_len = 0;

	ASSERT(iovlen < ISNS_MAX_IOVEC);
	iovec[iovlen].iov_base = (void *)pdu;
	iovec[iovlen].iov_len = (ISNSP_HEADER_SIZE);
	total_len += (ISNSP_HEADER_SIZE);
	iovlen++;

	ASSERT(iovlen < ISNS_MAX_IOVEC);
	iovec[iovlen].iov_base = (void *)pdu->payload;
	iovec[iovlen].iov_len = ntohs(pdu->payload_len);
	total_len += ntohs(pdu->payload_len);
	iovlen++;

	/* Initialization of the message header. */
	bzero(&msg, sizeof (msg));
	msg.msg_iov = &iovec[0];
	msg.msg_flags   = MSG_WAITALL;
	msg.msg_iovlen  = iovlen;

	send_len = iscsi_net->sendmsg(socket, &msg);
	return (send_len == total_len ? 0 : -1);
}

static
size_t
isns_rcv_pdu(void *socket, isns_pdu_t **pdu, size_t *pdu_size)
{
	int poll_cnt;
	iovec_t iovec[ISNS_MAX_IOVEC];
	isns_pdu_t *tmp_pdu_hdr;
	size_t bytes_received, total_bytes_received = 0, payload_len = 0;
	struct msghdr msg;
	uint8_t *tmp_pdu_data;

	/* Receive the header first */
	tmp_pdu_hdr = (isns_pdu_t *)kmem_zalloc(ISNSP_HEADER_SIZE, KM_SLEEP);
	(void) memset((char *)&iovec[0], 0, sizeof (iovec_t));
	iovec[0].iov_base = (void *)tmp_pdu_hdr;
	iovec[0].iov_len = ISNSP_HEADER_SIZE;

	/* Initialization of the message header. */
	bzero(&msg, sizeof (msg));
	msg.msg_iov = &iovec[0];
	msg.msg_flags = MSG_WAITALL;
	msg.msg_iovlen = 1;

	/* Poll and receive the packets. */
	poll_cnt = 0;
	do {
		bytes_received = iscsi_net->recvmsg(socket, &msg,
		    ISNS_RCV_TIMEOUT);
		if (bytes_received == 0) {
			/* Not yet. Increase poll count and try again. */
			poll_cnt++;
			continue;
		} else {
			/* OK data received. */
			break;
		}
	} while (poll_cnt < ISNS_RCV_RETRY_MAX);

	DTRACE_PROBE2(isns_rcv_pdu_hdr_summary,
	    int, poll_cnt, int, bytes_received);
	if (poll_cnt >= ISNS_RCV_RETRY_MAX) {
		kmem_free(tmp_pdu_hdr, ISNSP_HEADER_SIZE);
		*pdu = NULL;
		*pdu_size = 0;
		return (0);
	}
	if (bytes_received == 0 || bytes_received != ISNSP_HEADER_SIZE) {
		kmem_free(tmp_pdu_hdr, ISNSP_HEADER_SIZE);
		*pdu = NULL;
		*pdu_size = 0;
		return (0);
	}
	total_bytes_received += bytes_received;

	payload_len = ntohs(tmp_pdu_hdr->payload_len);
	DTRACE_PROBE1(isns_rcv_pdu_probe1, int, payload_len);
	/* Verify the received payload len is within limit */
	if (payload_len > ISNSP_MAX_PAYLOAD_SIZE) {
		kmem_free(tmp_pdu_hdr, ISNSP_HEADER_SIZE);
		*pdu = NULL;
		*pdu_size = 0;
		return (0);
	}

	/* Proceed to receive additional data. */
	tmp_pdu_data = kmem_zalloc(payload_len, KM_SLEEP);
	(void) memset((char *)&iovec[0], 0, sizeof (iovec_t));
	iovec[0].iov_base = (void *)tmp_pdu_data;
	iovec[0].iov_len = payload_len;

	/* Initialization of the message header. */
	bzero(&msg, sizeof (msg));
	msg.msg_iov = &iovec[0];
	msg.msg_flags   = MSG_WAITALL;
	msg.msg_iovlen  = 1;

	/* Poll and receive the rest of the PDU. */
	poll_cnt = 0;
	do {
		bytes_received = iscsi_net->recvmsg(socket, &msg,
		    ISNS_RCV_TIMEOUT);
		if (bytes_received == 0) {
			/* Not yet. Increase poll count and try again. */
			poll_cnt++;
			continue;
		} else {
			/* OK data received. */
			break;
		}
	} while (poll_cnt < ISNS_RCV_RETRY_MAX);

	DTRACE_PROBE2(isns_rcv_pdu_data_summary,
	    int, poll_cnt, int, bytes_received);

	if (poll_cnt >= ISNS_RCV_RETRY_MAX) {
		kmem_free(tmp_pdu_data, payload_len);
		kmem_free(tmp_pdu_hdr, ISNSP_HEADER_SIZE);
		*pdu = NULL;
		*pdu_size = 0;
		return (0);
	}
	if (bytes_received == 0 || bytes_received != payload_len) {
		kmem_free(tmp_pdu_data, payload_len);
		kmem_free(tmp_pdu_hdr, ISNSP_HEADER_SIZE);
		*pdu = NULL;
		*pdu_size = 0;
		return (0);
	}
	total_bytes_received += bytes_received;

	*pdu_size = ISNSP_HEADER_SIZE + payload_len;
	(*pdu) = (isns_pdu_t *)kmem_zalloc((*pdu_size), KM_SLEEP);
	(*pdu)->version = ntohs(tmp_pdu_hdr->version);
	(*pdu)->func_id = ntohs(tmp_pdu_hdr->func_id);
	(*pdu)->payload_len = payload_len;
	(*pdu)->flags = ntohs(tmp_pdu_hdr->flags);
	(*pdu)->xid = ntohs(tmp_pdu_hdr->xid);
	(*pdu)->seq = ntohs(tmp_pdu_hdr->seq);
	bcopy(tmp_pdu_data, &((*pdu)->payload), payload_len);

	kmem_free(tmp_pdu_data, payload_len);
	tmp_pdu_data = NULL;
	kmem_free(tmp_pdu_hdr, ISNSP_HEADER_SIZE);
	tmp_pdu_hdr = NULL;

	return (total_bytes_received);
}


/*
 * isns_create_dev_attr_reg_pdu - isns client registration pdu
 */
static size_t
isns_create_dev_attr_reg_pdu(
	uint8_t *node_name,
	uint8_t *node_alias,
	uint32_t node_type,
	uint16_t *xid_p,
	isns_pdu_t **out_pdu)
{
	in_port_t local_port;
	isns_pdu_t *pdu;
	size_t pdu_size, node_name_len, node_alias_len;
	uint16_t flags;

	ASSERT(node_name != NULL);
	ASSERT(node_alias != NULL);
	ASSERT(local_addr != NULL);

	/* RFC 4171 section 6.1 - NULLs included in the length. */
	node_name_len = strlen((char *)node_name) + 1;
	node_alias_len = strlen((char *)node_alias) + 1;

	if (node_name_len == 1) {
		*out_pdu = NULL;
		return (0);
	}

	/*
	 * Create DevAttrReg Message
	 *
	 * Enable the replace bit so that we can update
	 * existing registration
	 */
	flags = ISNS_FLAG_FIRST_PDU |
	    ISNS_FLAG_LAST_PDU |
	    ISNS_FLAG_REPLACE_REG;
	pdu_size = isns_create_pdu_header(ISNS_DEV_ATTR_REG, flags, &pdu);
	*xid_p = pdu->xid;

	/* Source attribute */
	if (isns_add_attr(pdu, pdu_size, ISNS_ISCSI_NAME_ATTR_ID,
	    node_name_len, node_name, 0) != 0) {
		kmem_free(pdu, pdu_size);
		*out_pdu = NULL;
		return (0);
	}

	/*
	 * Message Key Attributes
	 *
	 * EID attribute - Section 6.2.1
	 * This is required for re-registrations or Replace
	 * Bit is ignored - Section 5.6.5.1
	 */
	if (isns_add_attr(pdu, pdu_size, ISNS_EID_ATTR_ID,
	    node_name_len, node_name, 0) != 0) {
		kmem_free(pdu, pdu_size);
		*out_pdu = NULL;
		return (0);
	}

	/* Delimiter */
	if (isns_add_attr(pdu, pdu_size, ISNS_DELIMITER_ATTR_ID, 0, 0, 0)
	    != 0) {
		kmem_free(pdu, pdu_size);
		*out_pdu = NULL;
		return (0);
	}

	/* EID attribute - Section 6.2.1 */
	if (isns_add_attr(pdu, pdu_size, ISNS_EID_ATTR_ID,
	    node_name_len, node_name, 0) != 0) {
		kmem_free(pdu, pdu_size);
		*out_pdu = NULL;
		return (0);
	}

	/* ENTITY Protocol - Section 6.2.2 */
	if (isns_add_attr(pdu, pdu_size, ISNS_ENTITY_PROTOCOL_ATTR_ID, 4,
	    0, ISNS_ENTITY_PROTOCOL_ISCSI) != 0) {
		kmem_free(pdu, pdu_size);
		*out_pdu = NULL;
		return (0);
	}

	/* iSCSI Name - Section 6.4.1 */
	if (isns_add_attr(pdu, pdu_size, ISNS_ISCSI_NAME_ATTR_ID,
	    node_name_len, node_name, 0) != 0) {
		kmem_free(pdu, pdu_size);
		*out_pdu = NULL;
		return (0);
	}

	/* iSCSI Alias - Section 6.4.3 Optional */
	if (node_alias_len > 1) {
		if (isns_add_attr(pdu, pdu_size, ISNS_ISCSI_ALIAS_ATTR_ID,
		    node_alias_len, node_alias, 0) != 0) {
			kmem_free(pdu, pdu_size);
			*out_pdu = NULL;
			return (0);
		}
	}

	/* iSCSI Node Type - Section 6.4.2 */
	if (isns_add_attr(pdu, pdu_size, ISNS_ISCSI_NODE_TYPE_ATTR_ID, 4,
	    0, node_type) != 0) {
		kmem_free(pdu, pdu_size);
		*out_pdu = NULL;
		return (0);
	}

	mutex_enter(&esi_scn_thr_mutex);
	local_port = local_addr->a_port;
	mutex_exit(&esi_scn_thr_mutex);

	mutex_enter(&esi_scn_thr_mutex);
	/* Portal IP Address - Section 6.5.2 */
	if (isns_add_attr(pdu, pdu_size, ISNS_PORTAL_IP_ADDR_ATTR_ID, 16,
	    &(local_addr->a_addr.i_addr.in4),
	    local_addr->a_addr.i_insize) != 0) {
		kmem_free(pdu, pdu_size);
		*out_pdu = NULL;
		mutex_exit(&esi_scn_thr_mutex);
		return (0);
	}
	mutex_exit(&esi_scn_thr_mutex);

	/* Portal Port  - Section 6.5.3 */
	if (isns_add_attr(pdu, pdu_size, ISNS_PORTAL_PORT_ATTR_ID, 4, 0,
	    local_port) != 0) {
		kmem_free(pdu, pdu_size);
		*out_pdu = NULL;
		return (0);
	}

	/* SCN Port  - Section 6.3.7 */
	if (isns_add_attr(pdu, pdu_size, ISNS_SCN_PORT_ATTR_ID, 4, 0,
	    local_port) != 0) {
		kmem_free(pdu, pdu_size);
		*out_pdu = NULL;
		return (0);
	}

	/* ESI Port - Section 6.3.5 */
	if (isns_add_attr(pdu, pdu_size, ISNS_ESI_PORT_ATTR_ID, 4, 0,
	    local_port) != 0) {
		kmem_free(pdu, pdu_size);
		*out_pdu = NULL;
		return (0);
	}

	*out_pdu = pdu;
	return (pdu_size);
}

/*
 * isns_create_dev_dereg_pdu - Create an iSNS PDU for deregistration.
 */
static size_t
isns_create_dev_dereg_pdu(
	uint8_t *node_name,
	uint16_t *xid_p,
	isns_pdu_t **out_pdu)
{
	isns_pdu_t *pdu;
	size_t pdu_size, node_name_len;
	uint16_t flags;

	ASSERT(node_name != NULL);

	/* RFC 4171 section 6.1 - NULLs included in the length. */
	node_name_len = strlen((char *)node_name) + 1;

	if (node_name_len == 1) {
		*out_pdu = NULL;
		return (0);
	}

	/*
	 * Create DevDeReg Message
	 */
	flags = ISNS_FLAG_FIRST_PDU |
	    ISNS_FLAG_LAST_PDU;
	pdu_size = isns_create_pdu_header(ISNS_DEV_DEREG, flags, &pdu);
	*xid_p = pdu->xid;

	/* Source attribute */
	if (isns_add_attr(pdu, pdu_size, ISNS_ISCSI_NAME_ATTR_ID,
	    node_name_len, node_name, 0) != 0) {
		kmem_free(pdu, pdu_size);
		*out_pdu = NULL;
		return (0);
	}

	/* Delimiter */
	if (isns_add_attr(pdu, pdu_size, ISNS_DELIMITER_ATTR_ID, 0, 0, 0)
	    != 0) {
		kmem_free(pdu, pdu_size);
		*out_pdu = NULL;
		return (0);
	}

	/* Entity Identifier */
	if (isns_add_attr(pdu, pdu_size, ISNS_EID_ATTR_ID,
	    node_name_len, node_name, 0) != 0) {
		kmem_free(pdu, pdu_size);
		*out_pdu = NULL;
		return (0);
	}

	*out_pdu = pdu;
	return (pdu_size);
}

/*
 * isns_create_dev_attr_target_nodes_pdu - get all accessible targets
 *
 * Querys for a list of all accessible target nodes for this
 * initiator.  Requests all required login information (name,
 * ip, port, tpgt).
 */
static size_t
isns_create_dev_attr_qry_target_nodes_pdu(
	uint8_t *node_name,
	uint8_t *node_alias,
	uint16_t *xid_p, isns_pdu_t **out_pdu)
{
	isns_pdu_t *pdu_p;
	uint16_t flags;
	size_t pdu_size, node_name_len;

	ASSERT(node_name != NULL);
	ASSERT(node_alias != NULL);

	/* RFC 4171 section 6.1 - NULLs included in the length. */
	node_name_len = strlen((char *)node_name) + 1;

	if (node_name_len == 1) {
		*out_pdu = NULL;
		return (0);
	}

	/* Create DevAttrQry Message */
	flags = ISNS_FLAG_FIRST_PDU |
	    ISNS_FLAG_LAST_PDU;
	pdu_size = isns_create_pdu_header(ISNS_DEV_ATTR_QRY, flags, &pdu_p);
	*xid_p = pdu_p->xid;

	/* Source attribute */
	if (isns_add_attr(pdu_p, pdu_size, ISNS_ISCSI_NAME_ATTR_ID,
	    node_name_len, node_name, 0) != 0) {
		kmem_free(pdu_p, pdu_size);
		*out_pdu = NULL;
		return (0);
	}

	/*
	 * Message Key Attribute
	 *
	 * iSCSI Node Type
	 * Query target nodes only
	 */
	if (isns_add_attr(pdu_p, pdu_size, ISNS_ISCSI_NODE_TYPE_ATTR_ID,
	    4, 0, ISNS_TARGET_NODE_TYPE) != 0) {
		kmem_free(pdu_p, pdu_size);
		*out_pdu = NULL;
		return (0);
	}

	/* Delimiter */
	if (isns_add_attr(pdu_p, pdu_size,
	    ISNS_DELIMITER_ATTR_ID, 0, 0, 0) != 0) {
		kmem_free(pdu_p, pdu_size);
		*out_pdu = NULL;
		return (0);
	}

	/* PG iSCSI Name - Zero length TLV */
	if (isns_add_attr(pdu_p, pdu_size, ISNS_PG_ISCSI_NAME_ATTR_ID,
	    0, 0, 0) != 0) {
		kmem_free(pdu_p, pdu_size);
		*out_pdu = NULL;
		return (0);
	}

	/* PG Portal IP Address - Zero length TLV */
	if (isns_add_attr(pdu_p, pdu_size, ISNS_PG_PORTAL_IP_ADDR_ATTR_ID,
	    0, 0, 0) != 0) {
		kmem_free(pdu_p, pdu_size);
		*out_pdu = NULL;
		return (0);
	}

	/* PG Portal Port - Zero length TLV */
	if (isns_add_attr(pdu_p, pdu_size, ISNS_PG_PORTAL_PORT_ATTR_ID,
	    0, 0, 0) != 0) {
		kmem_free(pdu_p, pdu_size);
		*out_pdu = NULL;
		return (0);
	}

	/* PG Portal Group Tag - Zero length TLV */
	if (isns_add_attr(pdu_p, pdu_size,
	    ISNS_PG_TAG_ATTR_ID, 0, 0, 0) != 0) {
		kmem_free(pdu_p, pdu_size);
		*out_pdu = NULL;
		return (0);
	}

	*out_pdu = pdu_p;
	return (pdu_size);
}

static
size_t
isns_create_dev_attr_qry_one_pg_pdu(
	uint8_t *target_node_name,
	uint8_t *source_node_name,
	uint16_t *xid_p,
	isns_pdu_t **out_pdu)
{
	isns_pdu_t *pdu_p;
	uint16_t flags;
	size_t pdu_size, source_node_name_len, target_node_name_len;

	ASSERT(target_node_name != NULL);
	ASSERT(source_node_name != NULL);

	/* RFC 4171 section 6.1 - NULLs included in the length. */
	source_node_name_len = strlen((char *)source_node_name) + 1;
	target_node_name_len = strlen((char *)target_node_name) + 1;

	if (source_node_name_len == 1) {
		*out_pdu = NULL;
		return (0);
	}

	/* Create DevAttrQry message scoped to target_node_name */
	flags = ISNS_FLAG_FIRST_PDU |
	    ISNS_FLAG_LAST_PDU;
	pdu_size = isns_create_pdu_header(ISNS_DEV_ATTR_QRY, flags, &pdu_p);
	*xid_p = pdu_p->xid;

	/* Source attribute */
	if (isns_add_attr(pdu_p, pdu_size, ISNS_ISCSI_NAME_ATTR_ID,
	    source_node_name_len, source_node_name, 0) != 0) {
		kmem_free(pdu_p, pdu_size);
		*out_pdu = NULL;
		return (0);
	}

	/* Message key attribute */
	/* iSCSI Node Name */
	if (isns_add_attr(pdu_p, pdu_size, ISNS_ISCSI_NAME_ATTR_ID,
	    target_node_name_len,
	    target_node_name, 0) != 0) {
		kmem_free(pdu_p, pdu_size);
		*out_pdu = NULL;
		return (0);
	}

	/* Delimiter */
	if (isns_add_attr(pdu_p, pdu_size,
	    ISNS_DELIMITER_ATTR_ID, 0, 0, 0) != 0) {
		kmem_free(pdu_p, pdu_size);
		*out_pdu = NULL;
		return (0);
	}

	/* PG iSCSI Name - Zero length TLV */
	if (isns_add_attr(pdu_p, pdu_size, ISNS_PG_ISCSI_NAME_ATTR_ID,
	    0, 0, 0) != 0) {
		kmem_free(pdu_p, pdu_size);
		*out_pdu = NULL;
		return (0);
	}

	/* PG Portal IP Address - Zero length TLV */
	if (isns_add_attr(pdu_p, pdu_size, ISNS_PG_PORTAL_IP_ADDR_ATTR_ID,
	    0, 0, 0) != 0) {
		kmem_free(pdu_p, pdu_size);
		*out_pdu = NULL;
		return (0);
	}

	/* PG Portal Port - Zero length TLV */
	if (isns_add_attr(pdu_p, pdu_size, ISNS_PG_PORTAL_PORT_ATTR_ID,
	    0, 0, 0) != 0) {
		kmem_free(pdu_p, pdu_size);
		*out_pdu = NULL;
		return (0);
	}

	/* PG Portal Group Tag - Zero length TLV */
	if (isns_add_attr(pdu_p, pdu_size,
	    ISNS_PG_TAG_ATTR_ID, 0, 0, 0) != 0) {
		kmem_free(pdu_p, pdu_size);
		*out_pdu = NULL;
		return (0);
	}

	*out_pdu = pdu_p;
	return (pdu_size);
}

static
size_t
isns_create_scn_reg_pdu(
	uint8_t *node_name,
	uint8_t *node_alias,
	uint16_t *xid_p,
	isns_pdu_t **out_pdu)
{
	isns_pdu_t *pdu;
	size_t pdu_size, node_name_len;
	uint16_t flags;

	ASSERT(node_name != NULL);
	ASSERT(node_alias != NULL);

	/* RFC 4171 section 6.1 - NULLs included in the length. */
	node_name_len = strlen((char *)node_name) + 1;

	if (node_name_len == 1) {
		*out_pdu = NULL;
		return (0);
	}

	/* Create SCNReg Message */
	flags = ISNS_FLAG_FIRST_PDU |
	    ISNS_FLAG_LAST_PDU;
	pdu_size = isns_create_pdu_header(ISNS_SCN_REG, flags, &pdu);
	*xid_p = pdu->xid;

	/* Source attribute */
	if (isns_add_attr(pdu, pdu_size, ISNS_ISCSI_NAME_ATTR_ID,
	    node_name_len, node_name, 0) != 0) {
		kmem_free(pdu, pdu_size);
		*out_pdu = NULL;
		return (0);
	}

	/* Message attribute */
	if (isns_add_attr(pdu, pdu_size, ISNS_ISCSI_NAME_ATTR_ID,
	    node_name_len, node_name, 0) != 0) {
		kmem_free(pdu, pdu_size);
		*out_pdu = NULL;
		return (0);
	}

	/* Delimiter */
	if (isns_add_attr(pdu, pdu_size, ISNS_DELIMITER_ATTR_ID, 0, 0, 0)
	    != 0) {
		kmem_free(pdu, pdu_size);
		*out_pdu = NULL;
		return (0);
	}

	/* Operating attribute */
	if (isns_add_attr(pdu, pdu_size, ISNS_ISCSI_SCN_BITMAP_ATTR_ID,
	    4,
	    0,
	/*
	 * Microsoft seems to not differentiate between init and
	 * target. Hence, it makes no difference to turn on/off
	 * the initiator/target bit.
	 */
	    ISNS_TARGET_SELF_INFO_ONLY |
	    ISNS_OBJ_REMOVED |
	    ISNS_OBJ_ADDED |
	    ISNS_OBJ_UPDATED) != 0) {
		kmem_free(pdu, pdu_size);
		*out_pdu = NULL;
		return (0);
	}

	*out_pdu = pdu;
	return (pdu_size);
}

static
size_t
isns_create_scn_dereg_pdu(
	uint8_t *node_name,
	uint16_t *xid_p,
	isns_pdu_t **out_pdu)
{
	isns_pdu_t *pdu;
	size_t pdu_size, node_name_len;
	uint16_t flags;

	ASSERT(node_name != NULL);

	/* RFC 4171 section 6.1 - NULLs included in the length. */
	node_name_len = strlen((char *)node_name) + 1;

	if (node_name_len == 1) {
		*out_pdu = NULL;
		return (0);
	}

	/* Create SCNReg Message */
	flags = ISNS_FLAG_FIRST_PDU |
	    ISNS_FLAG_LAST_PDU;
	pdu_size = isns_create_pdu_header(ISNS_SCN_DEREG, flags, &pdu);
	*xid_p = pdu->xid;

	/* Source attribute */
	if (isns_add_attr(pdu, pdu_size, ISNS_ISCSI_NAME_ATTR_ID,
	    node_name_len, node_name, 0) != 0) {
		kmem_free(pdu, pdu_size);
		*out_pdu = NULL;
		return (0);
	}

	/* Message attribute */
	if (isns_add_attr(pdu, pdu_size, ISNS_ISCSI_NAME_ATTR_ID,
	    node_name_len, node_name, 0) != 0) {
		kmem_free(pdu, pdu_size);
		*out_pdu = NULL;
		return (0);
	}

	/* Delimiter */
	if (isns_add_attr(pdu, pdu_size, ISNS_DELIMITER_ATTR_ID, 0, 0, 0)
	    != 0) {
		kmem_free(pdu, pdu_size);
		*out_pdu = NULL;
		return (0);
	}

	/* No operating attribute */

	*out_pdu = pdu;
	return (pdu_size);
}

static
size_t
isns_create_esi_rsp_pdu(uint32_t rsp_status_code,
	isns_pdu_t *esi_pdu,
	uint16_t *xid_p,
	isns_pdu_t **out_pdu)
{
	isns_pdu_t *pdu_p;
	uint16_t flags;
	uint8_t *payload_ptr;
	uint32_t swapped_status_code = htonl(rsp_status_code);
	size_t pdu_size, payload_len = 0;

	/* Create ESIRsp Message */
	flags = ISNS_FLAG_FIRST_PDU |
	    ISNS_FLAG_LAST_PDU;
	pdu_size = isns_create_pdu_header(ISNS_ESI_RSP, flags, &pdu_p);
	*xid_p = pdu_p->xid;

	payload_len = ntohs(pdu_p->payload_len);

	/* Status Code */
	payload_ptr = pdu_p->payload + payload_len;
	bcopy(&swapped_status_code, payload_ptr, 4);
	payload_len += 4;

	payload_ptr = pdu_p->payload + payload_len;
	if ((esi_pdu->payload_len) < ISNSP_MAX_PAYLOAD_SIZE) {
		bcopy(esi_pdu->payload, payload_ptr,
		    (esi_pdu->payload_len));
		payload_len += (esi_pdu->payload_len);
	} else {
		bcopy(esi_pdu->payload, payload_ptr, ISNSP_MAX_PAYLOAD_SIZE);
		payload_len += ISNSP_MAX_PAYLOAD_SIZE;
	}
	pdu_p->payload_len = htons(payload_len);

	/* Delimiter */
	if (isns_add_attr(pdu_p, pdu_size, ISNS_DELIMITER_ATTR_ID, 0, 0, 0)
	    != 0) {
		kmem_free(pdu_p, pdu_size);
		*out_pdu = NULL;
		return (0);
	}

	*out_pdu = pdu_p;
	return (pdu_size);
}

static
size_t
isns_create_scn_rsp_pdu(uint32_t rsp_status_code,
	isns_pdu_t *scn_pdu,
	uint16_t *xid_p,
	isns_pdu_t **out_pdu)
{
	isns_pdu_t *pdu_p;
	uint16_t flags;
	uint8_t *payload_ptr;
	uint32_t swapped_status_code = htonl(rsp_status_code);
	size_t pdu_size, payload_len = 0;

	/* Create SCNRsp Message */
	flags = ISNS_FLAG_FIRST_PDU |
	    ISNS_FLAG_LAST_PDU;
	pdu_size = isns_create_pdu_header(ISNS_SCN_RSP, flags, &pdu_p);
	*xid_p = pdu_p->xid;

	payload_len = ntohs(pdu_p->payload_len);

	/* Status Code */
	payload_ptr = pdu_p->payload + payload_len;
	bcopy(&swapped_status_code, payload_ptr, 4);
	payload_len += 4;

	payload_ptr = pdu_p->payload + payload_len;
	if ((scn_pdu->payload_len) < ISNSP_MAX_PAYLOAD_SIZE) {
		bcopy(scn_pdu->payload, payload_ptr,
		    (scn_pdu->payload_len));
		payload_len += (scn_pdu->payload_len);
	} else {
		bcopy(scn_pdu->payload, payload_ptr, ISNSP_MAX_PAYLOAD_SIZE);
		payload_len += ISNSP_MAX_PAYLOAD_SIZE;
	}
	pdu_p->payload_len = htons(payload_len);

	/* Delimiter */
	if (isns_add_attr(pdu_p, pdu_size, ISNS_DELIMITER_ATTR_ID, 0, 0, 0)
	    != 0) {
		kmem_free(pdu_p, pdu_size);
		*out_pdu = NULL;
		return (0);
	}

	*out_pdu = pdu_p;
	return (pdu_size);
}

static
uint32_t
isns_process_dev_attr_reg_rsp(isns_pdu_t *resp_pdu_p)
{
	isns_resp_t *resp_p;

	if (resp_pdu_p->func_id != ISNS_DEV_ATTR_REG_RSP) {
		/* If this happens the iSNS server may have a problem. */
		return (ISNS_RSP_MSG_FORMAT_ERROR);
	}

	/* Check response's status code */
	resp_p = (isns_resp_t *)resp_pdu_p->payload;
	if (ntohl(resp_p->status) != ISNS_RSP_SUCCESSFUL) {
		return (ntohl(resp_p->status));
	}

	return (ISNS_RSP_SUCCESSFUL);
}

static
uint32_t
isns_process_dev_attr_dereg_rsp(isns_pdu_t *resp_pdu_p)
{
	isns_resp_t *resp_p;

	if (resp_pdu_p->func_id != ISNS_DEV_DEREG_RSP) {
		/* If this happens the iSNS server may have a problem. */
		return (ISNS_RSP_MSG_FORMAT_ERROR);
	}

	/* Check response's status code */
	resp_p = (isns_resp_t *)resp_pdu_p->payload;
	if (ntohl(resp_p->status) != ISNS_RSP_SUCCESSFUL) {
		return (ntohl(resp_p->status));
	}

	return (ISNS_RSP_SUCCESSFUL);
}

static
uint32_t
isns_process_scn_reg_rsp(isns_pdu_t *resp_pdu_p)
{
	isns_resp_t *resp_p;

	ASSERT(resp_pdu_p != NULL);
	if (resp_pdu_p->func_id != ISNS_SCN_REG_RSP) {
		/* If this happens the iSNS server may have a problem. */
		return (ISNS_RSP_MSG_FORMAT_ERROR);
	}

	/* Check response's status code */
	resp_p = (isns_resp_t *)resp_pdu_p->payload;
	if (ntohl(resp_p->status) != ISNS_RSP_SUCCESSFUL) {
		return (ntohl(resp_p->status));
	}
	return (ISNS_RSP_SUCCESSFUL);
}

static
uint32_t
isns_process_scn_dereg_rsp(isns_pdu_t *resp_pdu_p)
{
	isns_resp_t *resp_p;

	ASSERT(resp_pdu_p != NULL);
	if (resp_pdu_p->func_id != ISNS_SCN_DEREG_RSP) {
		/* If this happens the iSNS server may have a problem. */
		return (ISNS_RSP_MSG_FORMAT_ERROR);
	}

	/* Check response's status code */
	resp_p = (isns_resp_t *)resp_pdu_p->payload;
	if (ntohl(resp_p->status) != ISNS_RSP_SUCCESSFUL) {
		return (ntohl(resp_p->status));
	}
	return (ISNS_RSP_SUCCESSFUL);
}

static
uint32_t
isns_process_dev_attr_qry_target_nodes_pdu(
	iscsi_addr_t *isns_server_addr, uint16_t payload_funcId,
	isns_resp_t *resp_p, size_t resp_len,
	isns_portal_group_list_t **pg_list)
{
	boolean_t done_b, found_delimiter_b, target_node_type_b;
	int num_of_pgs = 0, pg_sz, idx;
	isns_tlv_t *attr_tlv_p;
	uint8_t *data_p;
	uint32_t len, total_payload_len = 0;
	isns_portal_group_t *pg;
	uint8_t	junk[IPV4_RSVD_BYTES];

	*pg_list = NULL;
	bzero(junk, IPV4_RSVD_BYTES);

	if (payload_funcId != ISNS_DEV_ATTR_QRY_RSP) {
		/* If this happens the iSNS server may have a problem. */
		return (ISNS_RSP_MSG_FORMAT_ERROR);
	}

	if (ntohl(resp_p->status) != ISNS_RSP_SUCCESSFUL) {
		return (ntohl(resp_p->status));
	}

	/*
	 * If payload is smaller than the length of even 1 attribute
	 * there is something wrong with the PDU.
	 */
	if (resp_len < (ISNS_TLV_ATTR_ID_LEN +
	    ISNS_TLV_ATTR_LEN_LEN)) {
		return (ISNS_RSP_MSG_FORMAT_ERROR);
	}

	/*
	 * Expected DevAttrQryRsp message format:
	 *
	 * Status Code
	 * iSCSI Node Type
	 * Delimiter
	 * PG iSCSI Name		[Optional]
	 * PG Portal IP Address		[Optional]
	 * PG Portal Port		[Optional]
	 * PG Tag			[Optional]
	 * PG iSCSI Name		[Optional]
	 * PG Portal IP Address		[Optional]
	 * PG Portal Port		[Optional]
	 * PG Tag			[Optional]
	 * .
	 * .
	 * .
	 */
	data_p = resp_p->data;
	done_b = B_FALSE;
	found_delimiter_b = B_FALSE;
	num_of_pgs = 0;
	total_payload_len = sizeof (resp_p->status);
	/* Find out the number of entries retrieved */
	while (!done_b) {
		attr_tlv_p = (isns_tlv_t *)data_p;
		if (ntohl(attr_tlv_p->attr_id) == ISNS_DELIMITER_ATTR_ID) {
			if (found_delimiter_b) {
				done_b = B_TRUE;
			} else {
				found_delimiter_b = B_TRUE;
			}
		} else if (ntohl(attr_tlv_p->attr_id) ==
		    ISNS_PG_TAG_ATTR_ID) {
			num_of_pgs++;
		}
		len = ntohl(attr_tlv_p->attr_len);

		total_payload_len += (ISNS_TLV_ATTR_ID_LEN +
		    ISNS_TLV_ATTR_LEN_LEN + len);
		if (total_payload_len >= resp_len) {
			done_b = B_TRUE;
		} else {
			data_p += (ISNS_TLV_ATTR_ID_LEN +
			    ISNS_TLV_ATTR_LEN_LEN + len);
		}
	}

	pg_sz = sizeof (isns_portal_group_list_t);
	if (num_of_pgs > 0) {
		pg_sz += (num_of_pgs - 1) * sizeof (isns_portal_group_t);
	}
	DTRACE_PROBE1(isns_process_dev_attr_qry_target_nodes_pdu_pg_size,
	    int, pg_sz);
	/*
	 * Once we passed this point, if for any reason we need to return
	 * because of a failure, we need to free the memory allocated for
	 * the pg_list and nullify it.
	 */
	*pg_list = (isns_portal_group_list_t *)kmem_zalloc(pg_sz, KM_SLEEP);
	(*pg_list)->pg_out_cnt = 0;

	/* Assign the isns_server information to all portal groups */
	for (idx = 0; idx < num_of_pgs; idx++) {
		pg = &((*pg_list)->pg_list[idx]);
		bcopy(&isns_server_addr->a_addr, &pg->isns_server_ip,
		    sizeof (iscsi_ipaddr_t));
		pg->isns_server_port = isns_server_addr->a_port;
	}

	data_p = resp_p->data;
	done_b = B_FALSE;
	found_delimiter_b = B_FALSE;
	total_payload_len = sizeof (resp_p->status);
	while (!done_b) {
		attr_tlv_p = (isns_tlv_t *)data_p;
		pg = &((*pg_list)->pg_list[(*pg_list)->pg_out_cnt]);
		switch (ntohl(attr_tlv_p->attr_id)) {
			case ISNS_DELIMITER_ATTR_ID:
				if (found_delimiter_b) {
					done_b = B_TRUE;
				} else {
					found_delimiter_b = B_TRUE;
				}
				break;

			case ISNS_PG_ISCSI_NAME_ATTR_ID:
				target_node_type_b = B_TRUE;
				bcopy(attr_tlv_p->attr_value,
				    (char *)pg->pg_iscsi_name,
				    ntohl(attr_tlv_p->attr_len) <
				    ISCSI_MAX_NAME_LEN ?
				    ntohl(attr_tlv_p->attr_len) :
				    ISCSI_MAX_NAME_LEN);

				DTRACE_PROBE1(isns_dev_attr_qry_process1,
				    char *, (char *)pg->pg_iscsi_name);
				break;

			case ISNS_PG_PORTAL_IP_ADDR_ATTR_ID:
				if (target_node_type_b) {
					/*
					 * Section 6.3.1 - The Portal IP Address
					 * is a 16-byte field that may contain
					 * an IPv4 or IPv6 address. When this
					 * field contains an IPv4 address, it
					 * is stored as an IPv4-mapped IPv6
					 * address
					 */
					if (ntohl(attr_tlv_p->attr_len) != 16) {
#define	STRING_AALR "address attribute length received "
#define	STRING_FISE16 "from iSNS server, Expected = 16, "
						cmn_err(CE_NOTE, "Wrong IP "
						    STRING_AALR
						    STRING_FISE16
						    "Received = %d",
						    ntohl(
						    attr_tlv_p->attr_len));
						return (
						    ISNS_RSP_MSG_FORMAT_ERROR);
#undef STRING_AALR
#undef STRING_FISE16
					}

					/*
					 * Section 6.3.1 and RFC 2373 state
					 * that an IPv4 address will be denoted
					 * by the 10 top bytes as all zero
					 * followed by either 2 bytes of
					 * 0x0000 or 0xFFFF The 0x0000 states
					 * that the address is is IPv6 capable
					 * and 0xFFFF states its not capable.
					 */
					if ((bcmp(attr_tlv_p->attr_value, junk,
					    IPV4_RSVD_BYTES) == 0) &&
					    (((attr_tlv_p->attr_value[10] ==
					    0x00) &&
					    (attr_tlv_p->attr_value[11] ==
					    0x00)) ||
					    ((attr_tlv_p->attr_value[10] ==
					    0xFF) &&
					    (attr_tlv_p->attr_value[11] ==
					    0xFF)))) {

						/* IPv4 */
						bcopy(attr_tlv_p->attr_value +
						    12, &pg->pg_ip_addr.u_ip4,
						    sizeof (struct in_addr));
						pg->insize =
						    sizeof (struct in_addr);
					} else {
						/* IPv6 */
						bcopy(attr_tlv_p->attr_value,
						    &pg->pg_ip_addr.u_ip6,
						    sizeof (struct in6_addr));
						pg->insize =
						    sizeof (struct in6_addr);
					}
				}
				break;

			case ISNS_PG_PORTAL_PORT_ATTR_ID:
				if (target_node_type_b) {
					pg->pg_port =
					    ntohl(*(uint32_t *)
					    (*attr_tlv_p).
					    attr_value);
				}

				break;

			case ISNS_PG_TAG_ATTR_ID:
				if (target_node_type_b) {
					pg->pg_tag =
					    ntohl(*(uint32_t *)
					    (*attr_tlv_p).
					    attr_value);
				}
				(*pg_list)->pg_out_cnt++;
				target_node_type_b = B_FALSE;
				break;

			default:
				break;
		}

		len = ntohl(attr_tlv_p->attr_len);
		total_payload_len += (ISNS_TLV_ATTR_ID_LEN +
		    ISNS_TLV_ATTR_LEN_LEN + len);
		if ((total_payload_len >= resp_len) ||
		    ((*pg_list)->pg_out_cnt == num_of_pgs)) {
			done_b = B_TRUE;
		} else {
			data_p += (ISNS_TLV_ATTR_ID_LEN +
			    ISNS_TLV_ATTR_LEN_LEN + len);
		}
	}

	return (ISNS_RSP_SUCCESSFUL);
}

/* ARGSUSED */
static
uint32_t
isns_process_esi(isns_pdu_t *esi_pdu_p)
{
	/* There's nothing particular to process for ESI. */
	return (ISNS_RSP_SUCCESSFUL);
}

static
uint32_t
isns_process_scn(isns_pdu_t *scn_pdu_p, uint8_t *lhba_handle)
{
	boolean_t dest_attr_found_b;
	boolean_t done_b;
	boolean_t scn_type_found_b;
	isns_scn_callback_arg_t *scn_args_p;
	isns_tlv_t *attr_tlv_p;
	uint8_t *data_p;
	uint8_t *src_attr;
	uint32_t attr_eff_len, normalized_attr_len;
	uint32_t scn_type;
	uint32_t total_payload_len;
	void (*scn_callback_to_use)(void *);

	/* get the lhba_handle to use for the call back */
	scn_callback_to_use = scn_callback_lookup(lhba_handle);
	if (scn_callback_to_use == NULL) {
		return (ISNS_RSP_INTERNAL_ERROR);
	}

	dest_attr_found_b = B_FALSE;
	scn_type = 0;
	scn_type_found_b = B_FALSE;
	data_p = scn_pdu_p->payload;
	done_b = B_FALSE;
	total_payload_len = 0;
	src_attr = (uint8_t *)kmem_zalloc(ISCSI_MAX_NAME_LEN, KM_SLEEP);
	/*
	 * Section 5.6.5.8 states an SCN can have more than one
	 * source attribute.  Process all attributes until we
	 * each process all the data or encounter the delimiter.
	 */
	while (!done_b) {
		attr_tlv_p = (isns_tlv_t *)data_p;

		switch (ntohl(attr_tlv_p->attr_id)) {
		/* ISNS_ISCSI_NAME_ATTR_ID - attribute name */
		case ISNS_ISCSI_NAME_ATTR_ID:
			attr_eff_len = strlen(
			    (char *)attr_tlv_p->attr_value) + 1;
			/*
			 * The attribute length must be 4-byte aligned.
			 * Section 5.1.3, RFC 4171.
			 */
			normalized_attr_len = (attr_eff_len % 4) == 0 ?
			    (attr_eff_len) :
			    (attr_eff_len + (4 - (attr_eff_len % 4)));
			if (normalized_attr_len !=
			    ntohl(attr_tlv_p->attr_len)) {
				/* This SCN is bad. */
				kmem_free(src_attr, ISCSI_MAX_NAME_LEN);
				return (ISNS_RSP_MSG_FORMAT_ERROR);
			}

			/* Check if this was the Destination Attribute */
			if ((dest_attr_found_b == B_TRUE) &&
			    (scn_type_found_b == B_TRUE)) {
				bzero(src_attr, ISCSI_MAX_NAME_LEN);
				bcopy(attr_tlv_p->attr_value,
				    (char *)src_attr,
				    ntohl(attr_tlv_p->attr_len) <
				    ISCSI_MAX_NAME_LEN ?
				    ntohl(attr_tlv_p->attr_len) :
				    ISCSI_MAX_NAME_LEN);

				/* allocate new callback structure */
				scn_args_p =
				    (isns_scn_callback_arg_t *)kmem_zalloc(
				    sizeof (isns_scn_callback_arg_t),
				    KM_SLEEP);
				scn_args_p->scn_type = ntohl(scn_type);
				bcopy(src_attr, scn_args_p->source_key_attr,
				    sizeof (scn_args_p->source_key_attr));

				/* Dispatch the callback to process the SCN */
				mutex_enter(&scn_taskq_mutex);
				if (scn_taskq != NULL) {
					(void) ddi_taskq_dispatch(scn_taskq,
					    scn_callback_to_use,
					    scn_args_p, DDI_SLEEP);
				}
				mutex_exit(&scn_taskq_mutex);
			} else {
				/* Skip Destination Attribute */
				dest_attr_found_b = B_TRUE;
			}
			break;

		/* ISNS_ISCSI_SCN_BITMAP_ATTR_ID - change type */
		case ISNS_ISCSI_SCN_BITMAP_ATTR_ID:
			/*
			 * Determine the type of action to take for this SCN.
			 */
			scn_type_found_b = B_TRUE;
			bcopy(&(attr_tlv_p->attr_value), &scn_type, 4);
			break;

		/* ISNS_DELIMITER_ATTR_ID - end of the payload of a message */
		case ISNS_DELIMITER_ATTR_ID:
			done_b = B_TRUE;
			break;
		}

		if (done_b == B_FALSE) {
			total_payload_len += ntohl(attr_tlv_p->attr_len) +
			    ISNS_TLV_ATTR_ID_LEN + ISNS_TLV_ATTR_LEN_LEN;
			if ((total_payload_len >= scn_pdu_p->payload_len) ||
			    (total_payload_len > ISNSP_MAX_PAYLOAD_SIZE)) {
				/* No more Attributes to process */
				done_b = B_TRUE;
			} else {
				if (scn_pdu_p->payload_len -
				    total_payload_len <=
				    ISNS_TLV_ATTR_ID_LEN +
				    ISNS_TLV_ATTR_LEN_LEN) {
					/*
					 * The rest of the data in the PDU
					 * is less than the size of a valid
					 * iSNS TLV. This next attribute
					 * probably spans across the PDU
					 * boundary. For now, do not
					 * process it further.
					 */
					done_b = B_TRUE;
				} else {
					/* Advance to the next Attribute */
					data_p += (ISNS_TLV_ATTR_ID_LEN +
					    ISNS_TLV_ATTR_LEN_LEN +
					    ntohl(attr_tlv_p->attr_len));
				}
			}
		}
	}

	kmem_free(src_attr, ISCSI_MAX_NAME_LEN);
	return (ISNS_RSP_SUCCESSFUL);
}

static
size_t
isns_create_pdu_header(uint16_t func_id, uint16_t flags, isns_pdu_t **pdu)
{
	/*
	 * It should be ok to assume ISNSP_MAX_PDU_SIZE is large enough
	 * since we are creating our own PDU which is fully under our control.
	 */
	size_t pdu_size = ISNSP_MAX_PDU_SIZE;

	*pdu = (isns_pdu_t *)kmem_zalloc(pdu_size, KM_SLEEP);
	(void) memset((*pdu), 0, pdu_size);
	(*pdu)->version = htons((uint16_t)ISNSP_VERSION);
	(*pdu)->func_id = htons((uint16_t)func_id);
	(*pdu)->payload_len = htons(0);
	(*pdu)->flags = htons((uint16_t)(flags | ISNS_FLAG_CLIENT));
	(*pdu)->xid = htons(create_xid());
	(*pdu)->seq = htons(0);

	return (pdu_size);
}

static
int
isns_add_attr(isns_pdu_t *pdu,
	size_t max_pdu_size,
	uint32_t attr_id,
	uint32_t attr_len,
	void *attr_data,
	uint32_t attr_numeric_data)
{
	isns_tlv_t *attr_tlv;
	uint8_t *payload_ptr;
	uint16_t payload_len;
	uint32_t normalized_attr_len;
	uint64_t attr_tlv_len;

	/* The attribute length must be 4-byte aligned. Section 5.1.3. */
	normalized_attr_len = (attr_len % 4) == 0 ? (attr_len) :
	    (attr_len + (4 - (attr_len % 4)));
	attr_tlv_len = ISNS_TLV_ATTR_ID_LEN
	    + ISNS_TLV_ATTR_LEN_LEN
	    + normalized_attr_len;
	/* Check if we are going to exceed the maximum PDU length. */
	payload_len = ntohs(pdu->payload_len);
	if ((payload_len + attr_tlv_len) > max_pdu_size) {
		return (1);
	}

	attr_tlv = (isns_tlv_t *)kmem_zalloc(attr_tlv_len, KM_SLEEP);

	attr_tlv->attr_id = htonl(attr_id);

	switch (attr_id) {
		case ISNS_DELIMITER_ATTR_ID:
		break;

		case ISNS_PORTAL_IP_ADDR_ATTR_ID:
		case ISNS_PG_PORTAL_IP_ADDR_ATTR_ID:
			if (attr_numeric_data == sizeof (in_addr_t)) {
				/* IPv4 */
				attr_tlv->attr_value[10] = 0xFF;
				attr_tlv->attr_value[11] = 0xFF;
				bcopy(attr_data, ((attr_tlv->attr_value) + 12),
				    sizeof (in_addr_t));
			} else if (attr_numeric_data == sizeof (in6_addr_t)) {
				/* IPv6 */
				bcopy(attr_data, attr_tlv->attr_value,
				    sizeof (in6_addr_t));
			} else if (attr_numeric_data == 0) {
				/* EMPTY */
				/* Do nothing */
			} else {
				kmem_free(attr_tlv, attr_tlv_len);
				attr_tlv = NULL;
				return (1);
			}
		break;

		case ISNS_EID_ATTR_ID:
		case ISNS_ISCSI_NAME_ATTR_ID:
		case ISNS_ISCSI_ALIAS_ATTR_ID:
		case ISNS_PG_ISCSI_NAME_ATTR_ID:
			bcopy((char *)attr_data,
			    attr_tlv->attr_value,
			    attr_len);
		break;

		default:
			switch (normalized_attr_len) {
				case 0:
				break;

				case 4:
					*(uint32_t *)attr_tlv->attr_value =
					    htonl(attr_numeric_data);
				break;

				case 8:
					*(uint64_t *)attr_tlv->attr_value =
					    BE_64((uint64_t)
					    attr_numeric_data);
				break;
			}
	}

	attr_tlv->attr_len = htonl(normalized_attr_len);
	/*
	 * Convert the network byte ordered payload length to host byte
	 * ordered for local address calculation.
	 */
	payload_len = ntohs(pdu->payload_len);
	payload_ptr = pdu->payload + payload_len;
	bcopy(attr_tlv, payload_ptr, attr_tlv_len);
	payload_len += attr_tlv_len;

	/*
	 * Convert the host byte ordered payload length back to network
	 * byte ordered - it's now ready to be sent on the wire.
	 */
	pdu->payload_len = htons(payload_len);

	kmem_free(attr_tlv, attr_tlv_len);
	attr_tlv = NULL;

	return (0);
}

/* ARGSUSED */
static
void
isns_service_esi_scn(iscsi_thread_t *thread, void *arg)
{
	int clnt_len;
	isns_async_thread_arg_t *larg;
	isns_pdu_t *in_pdu;
	size_t bytes_received, in_pdu_size = 0;
	uint8_t *lhba_handle;
	union {
		struct sockaddr sin;
		struct sockaddr_in s_in4;
		struct sockaddr_in6 s_in6;
	} clnt_addr = { 0 };
	union {
		struct sockaddr_in	soa4;
		struct sockaddr_in6	soa6;
	} local_conn_prop;
	void *listening_so, *connecting_so;

	larg = (isns_async_thread_arg_t *)arg;
	listening_so = larg->listening_so;
	lhba_handle = larg->lhba_handle;

	/* Done using the argument - free it */
	kmem_free(larg, sizeof (*larg));

	if (((struct sonode *)listening_so)->so_laddr.soa_len <=
	    sizeof (local_conn_prop)) {
		bcopy(((struct sonode *)listening_so)->so_laddr.soa_sa,
		    &local_conn_prop,
		    ((struct sonode *)listening_so)->so_laddr.soa_len);
	}

	if (iscsi_net->listen(listening_so, 5) < 0) {
		iscsi_net->close(listening_so);
	}

	for (;;) {
		int rval;
		isns_pdu_t *out_pdu;
		size_t out_pdu_size;

		clnt_len = sizeof (clnt_addr);

		/* Blocking call */
		connecting_so = iscsi_net->accept(
		    (struct sonode *)listening_so,
		    &clnt_addr.sin, &clnt_len);

		mutex_enter(&esi_scn_thr_mutex);
		if (esi_scn_thr_to_shutdown == B_TRUE) {
			/* Terminate the thread if instructed to do so. */
			mutex_exit(&esi_scn_thr_mutex);
			return;
		}
		mutex_exit(&esi_scn_thr_mutex);

		if (connecting_so == NULL) {
			iscsi_net->close(listening_so);
			continue;
		}

		bytes_received = isns_rcv_pdu(connecting_so, &in_pdu,
		    &in_pdu_size);
		if (in_pdu == NULL) {
			continue;
		}
		if (bytes_received == 0) {
			continue;
		}

		switch (in_pdu->func_id) {
		case ISNS_ESI:
		case ISNS_SCN:
			if (in_pdu->func_id == ISNS_ESI) {
				rval = isns_process_esi(in_pdu);
				out_pdu_size = isns_create_esi_rsp_pdu(
				    rval,
				    in_pdu,
				    &xid,
				    &out_pdu);
			} else if (in_pdu->func_id == ISNS_SCN) {
				rval = isns_process_scn(in_pdu,
				    lhba_handle);
				out_pdu_size = isns_create_scn_rsp_pdu(
				    rval,
				    in_pdu,
				    &xid,
				    &out_pdu);
			} else {
				/*
				 * Ignore all traffics other than
				 * ESI and SCN.
				 */
				kmem_free(in_pdu, in_pdu_size);
				in_pdu = NULL;
				continue;
			}

			if (out_pdu_size == 0) {
				kmem_free(in_pdu, in_pdu_size);
				in_pdu = NULL;
				continue;
			}

			(void) isns_send_pdu(connecting_so, out_pdu);

			kmem_free(out_pdu, out_pdu_size);
			out_pdu = NULL;
			kmem_free(in_pdu, in_pdu_size);
			in_pdu = NULL;

			iscsi_net->close(connecting_so);
			break;

		default:
			kmem_free(in_pdu, in_pdu_size);
			in_pdu = NULL;
			continue;
		}
	}
}

static
boolean_t
find_local_portal(iscsi_addr_t *isns_server_addr,
    iscsi_addr_t **local_addr, void **listening_so)
{
	char local_addr_str[256];
	union {
		struct sockaddr_in	soa4;
		struct sockaddr_in6	soa6;
	} local_conn_prop = { 0 };
	union {
		struct sockaddr sin;
		struct sockaddr_in s_in4;
		struct sockaddr_in6 s_in6;
	} serv_addr = { 0 };
	void *so;

	*local_addr = NULL;
	*listening_so = NULL;

	/*
	 * Determine the local IP address.
	 */
	so = isns_open(isns_server_addr);
	if (so == NULL) {
		return (B_FALSE);
	}

	if (((struct sonode *)so)->so_laddr.soa_len >
	    sizeof (local_conn_prop)) {
		iscsi_net->close(so);
		return (B_FALSE);
	}

	bcopy(((struct sonode *)so)->so_laddr.soa_sa,
	    &local_conn_prop,
	    ((struct sonode *)so)->so_laddr.soa_len);

	if (local_conn_prop.soa4.sin_family == AF_INET) {
		*local_addr = (iscsi_addr_t *)kmem_zalloc(sizeof (iscsi_addr_t),
		    KM_SLEEP);
		(*local_addr)->a_addr.i_addr.in4.s_addr =
		    local_conn_prop.soa4.sin_addr.s_addr;
		(*local_addr)->a_addr.i_insize = sizeof (in_addr_t);
	} else if (local_conn_prop.soa4.sin_family == AF_INET6) {
		/* EMPTY */
	} else {
		iscsi_net->close(so);
		return (B_FALSE);
	}

	iscsi_net->close(so);

	/*
	 * Determine the local IP address. (End)
	 */

	serv_addr.s_in4.sin_family = AF_INET;
	/*
	 * Use INADDR_ANY to accept connections from any of the connected
	 * networks.
	 */
	serv_addr.s_in4.sin_addr.s_addr = htonl(INADDR_ANY);
	/*
	 * Use port number 0 to allow the system to assign a unique unused
	 * port.
	 */
	serv_addr.s_in4.sin_port = htons(0);

	so = iscsi_net->socket(AF_INET, SOCK_STREAM, 0);
	if (so == NULL) {
		kmem_free((*local_addr), sizeof (iscsi_addr_t));
		*local_addr = NULL;
		return (B_FALSE);
	}

	if (iscsi_net->bind(so, &serv_addr.sin,
		sizeof (struct sockaddr), 0, 0) < 0) {
		kmem_free((*local_addr), sizeof (iscsi_addr_t));
		*local_addr = NULL;
		iscsi_net->close(so);
		return (B_FALSE);
	}

	if (((struct sonode *)so)->so_laddr.soa_len <=
	    sizeof (local_conn_prop)) {
		bcopy(((struct sonode *)so)->so_laddr.soa_sa,
		    &local_conn_prop,
		    ((struct sonode *)so)->so_laddr.soa_len);
		(*local_addr)->a_port = ntohs(local_conn_prop.soa4.sin_port);
	} else {
		(*local_addr)->a_port = ISNS_DEFAULT_ESI_SCN_PORT;
	}

	*listening_so = so;

	(void) inet_ntop(AF_INET, (void *)&((*local_addr)->a_addr.i_addr.in4),
	    local_addr_str, 256);

	return (B_TRUE);
}

/* ARGSUSED */
static
void
(*scn_callback_lookup(uint8_t *lhba_handle))(void *)
{
	/*
	 * When we support multiple HBA instance we will use lhba_handle
	 * to look up the associated SCN callback. For now, we only support
	 * one HBA instance therefore we always return the same SCN callback.
	 */
	return (scn_callback_p);
}

static
uint16_t
create_xid()
{
	return (xid++ % MAX_XID);
}

static
void
esi_scn_thr_cleanup()
{
	boolean_t clear_esi_scn_thr_id_b = B_FALSE;
	boolean_t clear_instance_listening_so_b = B_FALSE;
	boolean_t clear_local_addr_b = B_FALSE;
	iscsi_thread_t *tmp_esi_scn_thr_id = NULL;

	mutex_enter(&esi_scn_thr_mutex);
	tmp_esi_scn_thr_id = esi_scn_thr_id;
	mutex_exit(&esi_scn_thr_mutex);
	if (tmp_esi_scn_thr_id != NULL) {
		boolean_t unblock_esi_scn_thr_b = B_TRUE;

		/* Instruct the ESI/SCN to shut itself down. */
		mutex_enter(&esi_scn_thr_mutex);
		esi_scn_thr_to_shutdown = B_TRUE;
		if (instance_listening_so != NULL &&
		    local_addr != NULL) {
			isns_pdu_t *out_pdu;
			size_t out_pdu_size;
			void *connecting_so;

			/*
			 * Open a connection to the local address and send
			 * a dummy header to unblock the accept call so that
			 * the ESI/SCN thread has a chance to terminate
			 * itself.
			 */
			connecting_so = isns_open(local_addr);
			if (connecting_so == NULL) {
				unblock_esi_scn_thr_b = B_FALSE;
				mutex_exit(&esi_scn_thr_mutex);
			} else {
				out_pdu_size = isns_create_pdu_header(0,
				    ISNS_FLAG_FIRST_PDU |
				    ISNS_FLAG_LAST_PDU,
				    &out_pdu);
				if (isns_send_pdu(connecting_so,
				    out_pdu) != 0) {
					unblock_esi_scn_thr_b = B_FALSE;
				} else {
					unblock_esi_scn_thr_b = B_TRUE;
				}
				iscsi_net->close(connecting_so);
				kmem_free(out_pdu, out_pdu_size);
				out_pdu = NULL;
				mutex_exit(&esi_scn_thr_mutex);
			}
		} else {
			mutex_exit(&esi_scn_thr_mutex);
		}

		if (unblock_esi_scn_thr_b == B_TRUE) {
			clear_instance_listening_so_b = B_TRUE;
			clear_esi_scn_thr_id_b = B_TRUE;
			clear_local_addr_b = B_TRUE;
		}
	}

	if (clear_instance_listening_so_b &&
	    clear_esi_scn_thr_id_b &&
	    clear_local_addr_b) {
		(void) iscsi_thread_stop(esi_scn_thr_id);
		iscsi_thread_destroy(esi_scn_thr_id);

		mutex_enter(&esi_scn_thr_mutex);
		esi_scn_thr_id = NULL;

		/*
		 * Shutdown and close the listening socket.
		 */
		iscsi_net->shutdown(instance_listening_so, 2);
		iscsi_net->close(instance_listening_so);
		instance_listening_so = NULL;

		if (local_addr != NULL) {
			kmem_free(local_addr, sizeof (iscsi_addr_t));
			local_addr = NULL;
		}
		mutex_exit(&esi_scn_thr_mutex);
	}
}
