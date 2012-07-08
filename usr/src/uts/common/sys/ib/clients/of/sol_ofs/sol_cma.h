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

#ifndef _SYS_IB_CLIENTS_OF_SOL_OFS_SOL_CMA_H
#define	_SYS_IB_CLIENTS_OF_SOL_OFS_SOL_CMA_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/sysmacros.h>

#include <sys/ib/clients/of/sol_ofs/sol_ofs_common.h>
#include <sys/ib/clients/of/rdma/rdma_cm.h>
#include <sys/ib/clients/of/sol_ofs/sol_ib_cma.h> /* Transport Specific */


#define	IS_UDP_CMID(idp)	((idp)->ps == RDMA_PS_UDP || \
	(idp)->ps == RDMA_PS_IPOIB)
#define	IS_VALID_SOCKADDR(sockaddrp) \
	((sockaddrp)->sa_family == AF_INET || \
	(sockaddrp)->sa_family == AF_INET6)

/*
 * Global structure which contains information about all
 * CMIDs, which have called rdma_listen().
 */
typedef struct sol_cma_glbl_listen_s {
	avl_node_t	cma_listen_node;

	uint64_t	cma_listen_chan_sid;
	void		*cma_listen_clnt_hdl;
	void		*cma_listen_svc_hdl;
	genlist_t	cma_listen_chan_list;
} sol_cma_glbl_listen_t;

/* State of the RDMA-CM ID */
typedef enum {
	SOL_CMA_CHAN_IDLE,
	SOL_CMA_CHAN_BOUND,
	SOL_CMA_CHAN_ADDR_QUERY,
	SOL_CMA_CHAN_ADDR_BOUND,
	SOL_CMA_CHAN_ADDR_RESLVD,
	SOL_CMA_CHAN_ROUTE_QUERY,
	SOL_CMA_CHAN_ROUTE_RESLVD,

	SOL_CMA_CHAN_EVENT_NOTIFIED,

	SOL_CMA_CHAN_CONNECT,
	SOL_CMA_CHAN_LISTEN,
	SOL_CMA_CHAN_DISCONNECT,
	SOL_CMA_CHAN_ACCEPT,
	SOL_CMA_CHAN_REJECT,

	SOL_CMA_CHAN_DESTROYING,
	SOL_CMA_CHAN_DESTROY_PENDING,
	SOL_CMA_CHAN_DESTROY_WAIT,

	SOL_CMA_CHAN_HCA_DOWN,
	SOL_CMA_CHAN_PORT_DOWN
} cma_chan_state_t;

typedef struct listen_info_s {
	uint8_t			listen_is_root;

	/* For Root CMIDs, pointer to global listen info */
	genlist_entry_t		*listen_entry;
	sol_cma_glbl_listen_t	*chan_glbl_listen_info;

	/*
	 * For EP CMIDs, pointer to ib_device and root CMID
	 * for HCA DR
	 */
	genlist_entry_t		*listen_ep_dev_entry;
	genlist_entry_t		*listen_ep_root_entry;
	struct ib_device	*listen_ep_device;

	/*
	 * Count & list of EPs for this listen_info.
	 * This is 0, if listen_is_root is 0.
	 */
	uint32_t		listen_eps;
	genlist_t		listen_list;

	/* Transport Specific */
	union {
		/* For Root CMID */
		ibt_srv_hdl_t	_listen_srv_hdl;

		/* For Endpoint CMID */
		ibt_sbind_hdl_t	_listen_sbind_hdl;
	} un_listen;
#define	listen_ib_srv_hdl	un_listen._listen_srv_hdl
#define	listen_ib_sbind_hdl	un_listen._listen_sbind_hdl
} sol_cma_listen_info_t;

typedef enum {
	SOL_CMA_XPORT_NONE = 0,
	SOL_CMA_XPORT_IB,
	SOL_CMA_XPORT_IWARP
} sol_cma_xport_type_t;

/*
 * This is used to track the state of a client side CMID.
 * 	CONNECT_NONE	Server side CMID, or CMID for which
 * 			rdma_connect() has not been called.
 *
 * 	CLIENT_NONE	Client side CMID for which connection
 * 			has been torn down.
 *
 * 			For UDP it also represents connection
 * 			established (no more IBTF CM events
 * 			expected).
 *
 * 	INITIATED	rdma_connect() has been called not yet
 * 			established.
 *
 * 	ESTABLISHED	Client CMID has connection established.
 */
typedef enum {
	SOL_CMA_CONNECT_NONE = 0,
	SOL_CMA_CONNECT_CLIENT_NONE,
	SOL_CMA_CONNECT_INITIATED,
	SOL_CMA_CONNECT_ESTABLISHED,
} sol_cma_connect_flag_t;

/*
 * This is used to track the state of CMIDs created for Connection
 * Requests and listening CMID.
 *
 * 	NONE		Client CMID, listen CMID with no REQs yet.
 *
 * 	SERVER_DONE	REQ CMID connection done, no more events.
 *
 * 			For listening CMID all REQ CMIDs have events
 * 			completed.
 *
 * 	CREATED		listening CMID with > 1 REQ CMID with events
 * 			pending.
 *
 * 	QUEUED		REQ CMID in REQ AVL tree of listening CMID
 *
 * 	ACCEPTED	REQ CMID accepted and in ACPT AVL tree of the
 * 			listening CMID.
 */
typedef enum {
	REQ_CMID_NONE = 0,
	REQ_CMID_SERVER_NONE,
	REQ_CMID_CREATED,
	REQ_CMID_QUEUED,
	REQ_CMID_NOTIFIED,
	REQ_CMID_ACCEPTED,
} cma_req_cmid_state_t;

#define	SOL_IS_SERVER_CMID(chanp)	\
	((chanp)->chan_req_state != REQ_CMID_NONE)
#define	SOL_IS_CLIENT_CMID(chanp)	\
	((chanp)->chan_connect_flag != SOL_CMA_CONNECT_NONE)

#define	REQ_CMID_IN_REQ_AVL_TREE(chanp)	\
	((chanp)->chan_req_state == REQ_CMID_QUEUED ||	\
	(chanp)->chan_req_state == REQ_CMID_NOTIFIED)
#define	SOL_CMID_CLOSE_REQUIRED(chanp)		\
	((chanp)->chan_connect_flag == SOL_CMA_CONNECT_INITIATED ||	\
	(chanp)->chan_connect_flag == SOL_CMA_CONNECT_ESTABLISHED || \
	(chanp)->chan_req_state == REQ_CMID_ACCEPTED)
#define	SOL_CMAID_CONNECTED(chanp)	\
	(SOL_CMID_CLOSE_REQUIRED(chanp) ||	\
	(chanp)->chan_req_state  ==  REQ_CMID_NOTIFIED)

/*
 * CMID_DESTROYED	- Flag to indicate rdma_destroy_id has been
 * 			called for this CMID
 *
 * EVENT_PROGRESS	- RDMACM Event for this CMID been passed to
 * 			the sol_ofs client.
 *
 * API_PROGRESS		- rdma_resolve_addr() / rdma_resolve_route() /
 *			rdma_listen() is in progress.
 */
#define	SOL_CMA_CALLER_CMID_DESTROYED		0x01
#define	SOL_CMA_CALLER_EVENT_PROGRESS		0x02
#define	SOL_CMA_CALLER_API_PROGRESS		0x04

typedef struct {
	struct rdma_cm_id	chan_rdma_cm;

	/*
	 * Below are all CMA Channel specific fields required in Solaris,
	 * apart from rdma_cm_id.
	 */

	/* AVL Tree for REQs and EST CMIDs */
	avl_node_t		chan_req_avl_node;
	avl_node_t		chan_acpt_avl_node;
	avl_tree_t		chan_req_avl_tree;
	avl_tree_t		chan_acpt_avl_tree;

	/*
	 * chan_req_cnt -
	 *	REQ CMIDs created not yet notified to client
	 * chan_total_req_cnt -
	 *	REQ CMIDs created not destroy_id(0 not called.
	 */
	uint64_t		chan_req_cnt;
	uint64_t		chan_req_total_cnt;


	/* State for Server side and client side CMIDs */
	cma_req_cmid_state_t	chan_req_state;
	sol_cma_connect_flag_t	chan_connect_flag;

	kmutex_t		chan_mutex;
	kcondvar_t		chan_destroy_cv;
	cma_chan_state_t	chan_state;
	uint8_t			chan_cmid_destroy_state;

	/*
	 * Transport type for the rdma_id, IB or IWARP. This is set to
	 * NONE, when the transport type is not yet determined.
	 */
	sol_cma_xport_type_t	chan_xport_type;

	/*
	 * Passed from sol_ofs consumer, using the rdma_map_id2clnthdl
	 * and rdma_map_id2qphdl
	 */
	void			*chan_ib_client_hdl;
	void			*chan_iw_client_hdl;
	void			*chan_qp_hdl;

	/* Data for root / endpoint CM ID. */
	sol_cma_listen_info_t	*chan_listenp;

	/* Ptr to the root CMID for Endpoint & Req CMID */
	struct rdma_cm_id	*listen_root;
#define	CHAN_LISTEN_LIST(chanp)	(((chanp)->chan_listenp)->listen_list)
#define	CHAN_LISTEN_ROOT(chanp)	((chanp)->listen_root)

	struct rdma_conn_param	chan_param;

	/* Session ID for completion */
	void			*chan_session_id;

	uint32_t		chan_qp_num;
	uint8_t			chan_is_srq;

	union {
		ibcma_chan_t	chan_ib_xport;
	} un_xport;	/* Transport specific fields */
#define	chan_ib			un_xport.chan_ib_xport
} sol_cma_chan_t;

void ibcma_append_listen_list(struct rdma_cm_id *);
#ifdef	IWARP_SUPPORT
void iwcma_append_listen_list(struct rdma_cm_id *);
#endif


extern void cma_generate_event(struct rdma_cm_id *, enum rdma_cm_event_type,
    int, struct rdma_conn_param *, struct rdma_ud_param *);
extern struct ib_device *sol_cma_acquire_device(ib_guid_t);

static inline int
sol_cma_any_addr(struct sockaddr *addr)
{
	ASSERT(addr);
	if (addr->sa_family == AF_INET) {
		struct sockaddr_in	*in_addr;
		in_addr = (struct sockaddr_in *)addr;

		return (in_addr->sin_addr.s_addr == INADDR_ANY);
	} else if (addr->sa_family == AF_INET6) {
		struct sockaddr_in6	*in6_addr;
		in6_addr = (struct sockaddr_in6 *)addr;

		return (IN6_IS_ADDR_UNSPECIFIED(&(in6_addr->sin6_addr)));
	}
	return (0);
}

static inline struct rdma_cm_id *
cma_create_new_id(struct rdma_cm_id *srcid)
{
	struct	rdma_cm_id	*newid;
	sol_cma_chan_t		*new_chanp, *src_chanp;

	newid = rdma_create_id(srcid->event_handler, srcid->context,
	    srcid->ps);
	if (newid == NULL)
		return (newid);

	if (srcid->device) {
		newid->device =
		    sol_cma_acquire_device(srcid->device->node_guid);
	}
	bcopy(&((srcid->route).addr), &((newid->route).addr),
	    sizeof (struct rdma_addr));
	if ((srcid->route).num_paths) {
		int	num_paths;

		num_paths = (newid->route).num_paths =
		    (srcid->route).num_paths;
		(newid->route).path_rec = kmem_zalloc(num_paths *
		    sizeof (struct ib_sa_path_rec), KM_SLEEP);
		bcopy(&((srcid->route).path_rec),
		    &((newid->route).path_rec),
		    num_paths * sizeof (struct ib_sa_path_rec));
	}
	newid->port_num = srcid->port_num;

	new_chanp = (sol_cma_chan_t *)newid;
	src_chanp = (sol_cma_chan_t *)srcid;
	new_chanp->chan_state = src_chanp->chan_state;
	new_chanp->chan_xport_type = src_chanp->chan_xport_type;
	if (CHAN_LISTEN_ROOT(src_chanp))
		CHAN_LISTEN_ROOT(new_chanp) =  CHAN_LISTEN_ROOT(src_chanp);
	else
		CHAN_LISTEN_ROOT(new_chanp) = srcid;
	return (newid);
}


static inline struct rdma_cm_id *
cma_get_req_idp(struct rdma_cm_id *root_idp, void *qp_hdl)
{
	struct rdma_cm_id	*req_idp;
	sol_cma_chan_t		*root_chanp;

	root_chanp = (sol_cma_chan_t *)root_idp;
	ASSERT(MUTEX_HELD(&root_chanp->chan_mutex));
	req_idp = (struct rdma_cm_id *)avl_find(
	    &root_chanp->chan_req_avl_tree, (void *)qp_hdl, NULL);
	return (req_idp);
}

static inline struct rdma_cm_id *
cma_get_acpt_idp(struct rdma_cm_id *root_idp, void *qp_hdl)
{
	struct rdma_cm_id	*acpt_idp;
	sol_cma_chan_t		*root_chanp;

	root_chanp = (sol_cma_chan_t *)root_idp;
	ASSERT(MUTEX_HELD(&root_chanp->chan_mutex));
	acpt_idp = (struct rdma_cm_id *)avl_find(
	    &root_chanp->chan_acpt_avl_tree, (void *)qp_hdl, NULL);
	return (acpt_idp);
}
#ifdef __cplusplus
}
#endif

#endif	/* _SYS_IB_CLIENTS_OF_SOL_OFS_SOL_CMA_H */
