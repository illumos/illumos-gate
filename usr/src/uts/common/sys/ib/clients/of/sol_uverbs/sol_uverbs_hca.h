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

#ifndef _SYS_IB_CLIENTS_OF_SOL_UVERBS_SOL_UVERBS_HCA_H
#define	_SYS_IB_CLIENTS_OF_SOL_UVERBS_SOL_UVERBS_HCA_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 *
 * NAME: sol_uverbs_hca.h
 *
 * DESC: Solaris OFED hca management utility.
 *
 *	This file implements a very thin layer that provides the OFA user kernel
 *	agents the ability to operate in the same IBT/HCA domain.  That is all
 *	of the OFA user space kernel agents share the same IBT client handle,
 *	opened by the sol_uverbs driver.
 *
 */

#include <sys/ib/ibtl/ibvti.h>

/*
 * Definitions
 */

/*
 * Structures
 */

/*
 * HCA Info.
 *
 * Each IBT HCA the sol_uverbs driver knows about is maintained in a
 * a list that points to IBT handles and the client event handler
 * callbacks.
 */
typedef struct sol_uverbs_hca {
	llist_head_t		list;
	llist_head_t		event_handler_list;
	kmutex_t		event_handler_lock;
	llist_head_t		client_data_list;
	kmutex_t		client_data_lock;
	ibt_clnt_hdl_t		clnt_hdl;
	ib_guid_t		guid;
	ibt_hca_hdl_t		hdl;
	ibt_hca_attr_t		attr;
	uint32_t		nports;
	ibt_hca_portinfo_t	*ports;
	size_t			pinfosz;
} sol_uverbs_hca_t;

/*
 * Client structure passed to Solaris User Verbs to provide addtion and
 * removal callbacks.  The "add" function will be invoked for each
 * IBT hca in the system when it is available, the "remove" will be
 * invoked when an IBT hca is no longer available.
 */
typedef struct sol_uverbs_ib_client {
	llist_head_t	list;
	char		*name;
	void		(*add)(sol_uverbs_hca_t *);
	void		(*remove)(sol_uverbs_hca_t *);
} sol_uverbs_ib_client_t;

/*
 * Event handler structure passed to Solaris User Verbs hca management
 * to register an asynchronous event handler for an IBT hca.
 */
typedef struct sol_uverbs_ib_event_handler {
	llist_head_t		list;
	sol_uverbs_hca_t	*hca;
	void			(*handler)(struct sol_uverbs_ib_event_handler *,
				ibt_hca_hdl_t hca,
				ibt_async_code_t code,
				ibt_async_event_t *event);
} sol_uverbs_ib_event_handler_t;

#define	SOL_UVERBS_INIT_IB_EVENT_HANDLER(_struct_ptr,  _hca_ptr, _func_ptr) \
	do {							\
		(_struct_ptr)->hca	= _hca_ptr;		\
		(_struct_ptr)->handler	= _func_ptr;		\
		llist_head_init(&(_struct_ptr)->list, 0);	\
	} while (0)

/*
 * Control structures for managmenet of common HCA list.
 */
extern kmutex_t		sol_uverbs_hca_lock;
extern llist_head_t	sol_uverbs_hca_list;
extern llist_head_t	sol_uverbs_client_list;

/*
 * Functions
 */
/*
 * sol_uverbs HCA list management and helper sol_uverbs nternal functions.
 */
int  sol_uverbs_common_hca_init();
void sol_uverbs_common_hca_fini();
sol_uverbs_hca_t *sol_uverbs_ibt_hdl_to_hca(ibt_hca_hdl_t hdl);

/*
 * COMMON HCA CLIENT API - See sol_uverbs_hca.c for complete
 * function description.
 */

/*
 * Register for client notifications.  The "add" function pointer
 * in the client structure will be invoked for each hca in the system, the
 * "remove" function pointer will be invoked as hca's are no longer
 * available.
 */
int  sol_uverbs_ib_register_client(sol_uverbs_ib_client_t *client);

/*
 * Unregister for client notifications.
 */
void sol_uverbs_ib_unregister_client(sol_uverbs_ib_client_t *client);

/*
 * Mechanism for client to associate private data with each IBT hca.
 */
void *sol_uverbs_ib_get_client_data(sol_uverbs_hca_t *hca,
					sol_uverbs_ib_client_t *client);

void sol_uverbs_ib_set_client_data(sol_uverbs_hca_t *hca,
	sol_uverbs_ib_client_t *client, void *data);

/*
 * Mechanism for client to register/unregister for asynchronous event callbacks.
 */
int
sol_uverbs_ib_register_event_handler(sol_uverbs_ib_event_handler_t *handler);

int
sol_uverbs_ib_unregister_event_handler(sol_uverbs_ib_event_handler_t *handler);

/*
 * HELPER API provided by sol_uverbs, see sol_uverbs_qp.c for complete
 * descriptions.
 */

/*
 * Map a user QP id to an IBT QP Handle.
 */
ibt_qp_hdl_t sol_uverbs_uqpid_to_ibt_handle(uint32_t u_qpid);

/*
 * Inform sol_uverbs to igonore requested modify QP calls for the
 * specific QP.
 */
int sol_uverbs_disable_user_qp_modify(uint32_t u_qpid);
int sol_uverbs_enable_user_qp_modify(uint32_t u_qpid);

#ifdef __cplusplus
}
#endif
#endif /* _SYS_IB_CLIENTS_OF_SOL_UVERBS_SOL_UVERBS_HCA_H */
