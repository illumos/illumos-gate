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
 * sol_uverbs_hca.c
 *
 * Provides the Solaris OFED User Verbs thin common hca interface for
 * sharing of IBT client handle, device list, and asynchronous event
 * delivery.
 */
#include <sys/vfs.h>
#ifdef VFS_OPS
#include <sys/vfs_opreg.h>
#include <sys/vnode.h>
#endif
#include <sys/errno.h>
#include <sys/cred.h>
#include <sys/uio.h>
#include <sys/semaphore.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/ib/ibtl/ibvti.h>
#include <sys/ib/clients/of/ofa_solaris.h>
#include <sys/ib/clients/of/sol_ofs/sol_ofs_common.h>
#include <sys/ib/clients/of/sol_uverbs/sol_uverbs_hca.h>
#include <sys/ib/clients/of/sol_uverbs/sol_uverbs.h>

extern char	*sol_uverbs_dbg_str;

/*
 * Globals for managing the list of HCA's and the registered clients.
 */
kmutex_t	sol_uverbs_hca_lock;
llist_head_t	sol_uverbs_hca_list;
llist_head_t	sol_uverbs_client_list;
static uint32_t	sol_uverbs_common_hca_initialized = 0;

typedef struct sol_uverbs_hca_client_data {
	llist_head_t		list;
	sol_uverbs_ib_client_t	*client;
	void			*data;
} sol_uverbs_hca_client_data_t;

static
int sol_uverbs_hca_add_client_context(sol_uverbs_hca_t *hca,
	sol_uverbs_ib_client_t *client);

/*
 * Function:
 *	sol_uverbs_ib_register_client
 * Input:
 *	client  	- Pointer to the client structure
 * Output:
 *	None
 * Returns:
 *	Zero on success, else error code.
 * Description:
 *	The Solaris User Verbs kernel agent provides a single
 *	common view of the IBTF devices.  This function allows
 *	Solaris OFA kernel implementations to share this view
 *	by registerng a client callback for notification of HCA
 *	addtion and removal.  Note that when this function is
 *	called, the client will	get an "add" callback for all
 *	existing devices.
 */
int
sol_uverbs_ib_register_client(sol_uverbs_ib_client_t *client)
{
	llist_head_t		*entry;
	sol_uverbs_hca_t	*hca;

	ASSERT(client != NULL);
	mutex_enter(&sol_uverbs_hca_lock);
	llist_head_init(&client->list, client);
	llist_add_tail(&client->list, &sol_uverbs_client_list);
	list_for_each(entry, &sol_uverbs_hca_list) {
		hca = (sol_uverbs_hca_t *)entry->ptr;

		if (client->add &&
		    !sol_uverbs_hca_add_client_context(hca, client)) {
			client->add(hca);
		}
	}
	mutex_exit(&sol_uverbs_hca_lock);

	return (0);
}

/*
 * Function:
 *	sol_uverbs_ib_unregister_client
 * Input:
 *	client  - Pointer to the client structure
 * Output:
 *	None
 * Returns:
 *	None
 * Description:
 *	Removes a client registration previously created with
 *	the sol_uverbs_ib_register_client() call.
 */
void
sol_uverbs_ib_unregister_client(sol_uverbs_ib_client_t *client)
{
	llist_head_t			*entry, *centry, *tmp;
	sol_uverbs_hca_t		*hca;
	sol_uverbs_hca_client_data_t	*context;

	ASSERT(client != NULL);
	mutex_enter(&sol_uverbs_hca_lock);

	list_for_each(entry, &sol_uverbs_hca_list) {
		hca = (sol_uverbs_hca_t *)entry->ptr;

		ASSERT(hca != NULL);

		if (client->remove) {
			client->remove(hca);
		}
		mutex_enter(&hca->client_data_lock);
		centry = hca->client_data_list.nxt;
		tmp = centry->nxt;

		while (centry != &hca->client_data_list) {
			ASSERT(centry);
			context = (sol_uverbs_hca_client_data_t *)centry->ptr;
			ASSERT(context != NULL);

			if (context->client == client) {
				llist_del(centry);
				kmem_free(context, sizeof (*context));
			}
			centry = tmp;
			tmp = centry->nxt;
		}
		mutex_exit(&hca->client_data_lock);
	}
	llist_del(&client->list);
	mutex_exit(&sol_uverbs_hca_lock);
}

/*
 * Function:
 *	sol_uverbs_ib_get_client_data
 * Input:
 *	hca    	- Pointer to HCA struct passed in the client
 *                add function callback.
 *     client   - A pointer to the client structure.
 * Output:
 *	None
 * Returns:
 *	The client data, or NULL on error.
 * Description:
 *	Returns the client data associated with the given
 *      HCA. The data is set/specified via the
 *	sol_uverbs_ib_set_client_data() function.
 */
void *
sol_uverbs_ib_get_client_data(sol_uverbs_hca_t *hca,
					sol_uverbs_ib_client_t *client)
{
	llist_head_t			*entry;
	sol_uverbs_hca_client_data_t	*context;
	void				*data = NULL;

	ASSERT(hca != NULL);
	ASSERT(client != NULL);

	mutex_enter(&hca->client_data_lock);

	list_for_each(entry, &hca->client_data_list) {
		context = (sol_uverbs_hca_client_data_t *)entry->ptr;

		ASSERT(context != NULL);

		if (context->client == client) {
			data = context->data;
			break;
		}
	}
	mutex_exit(&hca->client_data_lock);
	return (data);
}

/*
 * Function:
 *	sol_uverbs_ib_set_client_data
 * Input:
 *	hca    	- Pointer to HCA struct passed in the client
 *                add function.
 *     client   - A pointer to the client structure.
 *     data     - The client data to associate with the HCA.
 * Output:
 *	None
 * Returns:
 *	None
 * Description:
 *	Sets the client data associated with the given
 *      HCA.
 */
void
sol_uverbs_ib_set_client_data(sol_uverbs_hca_t *hca,
	sol_uverbs_ib_client_t *client, void *data)
{
	llist_head_t			*entry;
	sol_uverbs_hca_client_data_t	*context;

	ASSERT(hca != NULL);
	ASSERT(client != NULL);

	mutex_enter(&hca->client_data_lock);

	list_for_each(entry, &hca->client_data_list) {
		context = (sol_uverbs_hca_client_data_t *)entry->ptr;

		ASSERT(context != NULL);

		if (context->client == client) {
			context->data = data;
			goto out;
		}
	}
	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
	    "HCA SET CLIENT DATA: No client found for %s\n",
	    client->name != NULL ? client->name : "NULL Client Name");

out:
	mutex_exit(&hca->client_data_lock);
}

/*
 * Function:
 *	sol_uverbs_ib_register_event_handler
 * Input:
 *	handler  - Pointer to handler structure
 * Output:
 *	None
 * Returns:
 *	Zero
 * Description:
 *	Register to receive ansynchronous notifications
 *	for the HCA defined in the handler struct.  The notifications
 *	are delivered via the callback function defined in the handler
 *	struct.
 */
int
sol_uverbs_ib_register_event_handler(sol_uverbs_ib_event_handler_t *handler)
{
	ASSERT(handler != NULL);
	ASSERT(handler->hca != NULL);

	mutex_enter(&handler->hca->event_handler_lock);
	llist_head_init(&handler->list, handler);
	llist_add_tail(&handler->list, &handler->hca->event_handler_list);
	mutex_exit(&handler->hca->event_handler_lock);
	return (0);
}

/*
 * Function:
 *	sol_uverbs_ib_unregister_event_handler
 * Input:
 *	handler  - Pointer to handler structure
 * Output:
 *	None
 * Returns:
 *	Zero
 * Description:
 *	Unregister a ansynchronous notification handler previously
 *	registered via the osl_uverbs_ib_register_event_handler() call.
 */
int
sol_uverbs_ib_unregister_event_handler(sol_uverbs_ib_event_handler_t *handler)
{
	ASSERT(handler != NULL);
	ASSERT(handler->hca != NULL);

	mutex_enter(&handler->hca->event_handler_lock);
	llist_del(&handler->list);
	mutex_exit(&handler->hca->event_handler_lock);
	return (0);
}

/*
 * Function:
 *	sol_uverbs_common_hca_init
 * Input:
 *	None
 * Output:
 *	None
 * Returns:
 *	Zero
 * Description:
 *	Perform initialization required by the common hca client API.
 */
int
sol_uverbs_common_hca_init()
{
	llist_head_init(&sol_uverbs_hca_list, NULL);
	llist_head_init(&sol_uverbs_client_list, NULL);
	mutex_init(&sol_uverbs_hca_lock, NULL, MUTEX_DRIVER, NULL);
	sol_uverbs_common_hca_initialized = 1;
	return (0);
}

/*
 * Function:
 *	sol_uverbs_common_hca_fini
 * Input:
 *	None
 * Output:
 *	None
 * Returns:
 *	None
 * Description:
 *	Perform cleanup required by the common hca client API.
 */
void
sol_uverbs_common_hca_fini()
{
	ASSERT(llist_empty(&sol_uverbs_client_list));
	sol_uverbs_common_hca_initialized = 0;
	mutex_destroy(&sol_uverbs_hca_lock);
}

/*
 * Helpers for internal use only
 */
/*
 * Function:
 *	sol_uverbs_hca_add_client_context
 * Input:
 *	hca	- Pointer to the hca struct to add a client context.
 *	client  - Pointer to the client.
 * Output:
 *	None
 * Returns:
 *	0 on success, else the error.
 * Description:
 *	Create a context for the specified client and attach it to
 *	the specified hca.
 */
static
int sol_uverbs_hca_add_client_context(sol_uverbs_hca_t *hca,
    sol_uverbs_ib_client_t *client)
{
	sol_uverbs_hca_client_data_t   *context;

	context = kmem_zalloc(sizeof (*context), KM_NOSLEEP);

	if (!context) {
		SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
		    "HCA: Couldn't allocate client context for %s",
		    client->name ? client->name : "Name is NULL");
		return (ENOMEM);
	}

	context->client = client;
	context->data   = NULL;
	llist_head_init(&context->list, context);

	mutex_enter(&hca->client_data_lock);
	llist_add(&context->list, &hca->client_data_list);
	mutex_exit(&hca->client_data_lock);
	return (0);
}

/*
 * Function:
 *	sol_uverbs_ibt_hdl_to_hca
 * Input:
 *	hca_hdl - IBT handle to an HCA.
 * Output:
 *	None
 * Returns:
 *	A pointer to the sol_uverbs HCA structure associated with the handle,
 *	or NULL if no associated HCA is found.
 * Description:
 *	Given an IBT hca handle, return the user verbs HCA structure associated
 *	with that handle.
 */
sol_uverbs_hca_t *
sol_uverbs_ibt_hdl_to_hca(ibt_hca_hdl_t hca_hdl)
{
	llist_head_t		*entry;
	sol_uverbs_hca_t	*hca;
	sol_uverbs_hca_t	*ret = NULL;

	mutex_enter(&sol_uverbs_hca_lock);
	list_for_each(entry, &sol_uverbs_hca_list) {
		hca = (sol_uverbs_hca_t *)entry->ptr;

		if (hca->hdl == hca_hdl) {
			ret = hca;
			break;
		}
	}
	mutex_exit(&sol_uverbs_hca_lock);

	return (ret);
}
