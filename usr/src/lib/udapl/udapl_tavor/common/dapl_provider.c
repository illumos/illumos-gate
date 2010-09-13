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
 * Copyright (c) 2002-2003, Network Appliance, Inc. All rights reserved.
 */

/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *
 * MODULE: dapl_provider.c
 *
 * PURPOSE: Provider function table
 * Description: DAT Interfaces to this provider
 *
 * $Id: dapl_provider.c,v 1.7 2003/08/08 19:42:54 sjs2 Exp $
 */

#include "dapl_provider.h"


/*
 *
 * Global Data
 *
 */

DAPL_PROVIDER_LIST 		g_dapl_provider_list;


/*
 * the function table for this provider
 */

DAT_PROVIDER g_dapl_provider_template =
{
	NULL,
	0,
	&dapl_ia_open,
	&dapl_ia_query,
	&dapl_ia_close,

	&dapl_set_consumer_context,
	&dapl_get_consumer_context,
	&dapl_get_handle_type,

	&dapl_cno_create,
	&dapl_cno_modify_agent,
	&dapl_cno_query,
	&dapl_cno_free,
	&dapl_cno_wait,

	&dapl_cr_query,
	&dapl_cr_accept,
	&dapl_cr_reject,
	&dapl_cr_handoff,

	&dapl_evd_create,
	&dapl_evd_query,
	&dapl_evd_modify_cno,
	&dapl_evd_enable,
	&dapl_evd_disable,
	&dapl_evd_wait,
	&dapl_evd_resize,
	&dapl_evd_post_se,
	&dapl_evd_dequeue,
	&dapl_evd_free,

	&dapl_ep_create,
	&dapl_ep_query,
	&dapl_ep_modify,
	&dapl_ep_connect,
	&dapl_ep_dup_connect,
	&dapl_ep_disconnect,
	&dapl_ep_post_send,
	&dapl_ep_post_recv,
	&dapl_ep_post_rdma_read,
	&dapl_ep_post_rdma_write,
	&dapl_ep_get_status,
	&dapl_ep_free,

	&dapl_lmr_create,
	&dapl_lmr_query,
	&dapl_lmr_free,

	&dapl_rmr_create,
	&dapl_rmr_query,
	&dapl_rmr_bind,
	&dapl_rmr_free,

	&dapl_psp_create,
	&dapl_psp_query,
	&dapl_psp_free,

	&dapl_rsp_create,
	&dapl_rsp_query,
	&dapl_rsp_free,

	&dapl_pz_create,
	&dapl_pz_query,
	&dapl_pz_free,

	&dapl_psp_create_any,
	&dapl_ep_reset,
	&dapl_evd_set_unwaitable,
	&dapl_evd_clear_unwaitable,

	&dapl_lmr_sync_rdma_read,
	&dapl_lmr_sync_rdma_write,

	&dapl_ep_create_with_srq,
	&dapl_ep_recv_query,
	&dapl_ep_set_watermark,

	&dapl_srq_create,
	&dapl_srq_free,
	&dapl_srq_post_recv,
	&dapl_srq_query,
	&dapl_srq_resize,
	&dapl_srq_set_lw
};



/*
 *
 * Function Prototypes
 *
 */

static DAT_BOOLEAN
dapl_provider_list_key_cmp(
    const char *name_a,
    const char *name_b);


/*
 *
 * Function Definitions
 *
 */

DAT_RETURN
dapl_provider_list_create(void)
{
	DAT_RETURN status;

	status = DAT_SUCCESS;

	/* create the head node */
	g_dapl_provider_list.head = dapl_os_alloc(
	    sizeof (DAPL_PROVIDER_LIST_NODE));
	if (NULL == g_dapl_provider_list.head) {
		status = DAT_ERROR(DAT_INSUFFICIENT_RESOURCES,
		    DAT_RESOURCE_MEMORY);
		goto bail;
	}

	(void) dapl_os_memzero(g_dapl_provider_list.head,
	    sizeof (DAPL_PROVIDER_LIST_NODE));

	/* create the tail node */
	g_dapl_provider_list.tail = dapl_os_alloc(
	    sizeof (DAPL_PROVIDER_LIST_NODE));
	if (NULL == g_dapl_provider_list.tail) {
		status = DAT_ERROR(DAT_INSUFFICIENT_RESOURCES,
		    DAT_RESOURCE_MEMORY);
		goto bail;
	}

	(void) dapl_os_memzero(g_dapl_provider_list.tail,
	    sizeof (DAPL_PROVIDER_LIST_NODE));

	g_dapl_provider_list.head->next = g_dapl_provider_list.tail;
	g_dapl_provider_list.tail->prev = g_dapl_provider_list.head;
	g_dapl_provider_list.size = 0;

bail:
	if (DAT_SUCCESS != status) {
		if (NULL != g_dapl_provider_list.head) {
			dapl_os_free(g_dapl_provider_list.head,
			    sizeof (DAPL_PROVIDER_LIST_NODE));
		}

		if (NULL != g_dapl_provider_list.tail) {
			dapl_os_free(g_dapl_provider_list.tail,
			    sizeof (DAPL_PROVIDER_LIST_NODE));
		}
	}

	return (status);
}


DAT_RETURN
dapl_provider_list_destroy(void)
{
	DAPL_PROVIDER_LIST_NODE *cur_node;

	while (NULL != g_dapl_provider_list.head) {
		cur_node = g_dapl_provider_list.head;
		g_dapl_provider_list.head = cur_node->next;

		dapl_os_free(cur_node, sizeof (DAPL_PROVIDER_LIST_NODE));
	}

	return (DAT_SUCCESS);
}


DAT_COUNT
dapl_provider_list_size(void)
{
	return (g_dapl_provider_list.size);
}


DAT_RETURN
dapl_provider_list_insert(
    IN  const char *name,
    IN  DAT_PROVIDER **p_data)
{
	DAPL_PROVIDER_LIST_NODE *cur_node, *prev_node, *next_node;
	DAT_RETURN status;
	unsigned int len;

	status = DAT_SUCCESS;
	*p_data = NULL;

	cur_node = dapl_os_alloc(sizeof (DAPL_PROVIDER_LIST_NODE));

	if (NULL == cur_node) {
		status = DAT_ERROR(DAT_INSUFFICIENT_RESOURCES,
		    DAT_RESOURCE_MEMORY);
		goto bail;
	}

	len = dapl_os_strlen(name);

	if (DAT_NAME_MAX_LENGTH <= len) {
		status = DAT_ERROR(DAT_INSUFFICIENT_RESOURCES,
		    DAT_RESOURCE_MEMORY);
		goto bail;
	}

	/* insert node at end of list to preserve registration order */
	prev_node = g_dapl_provider_list.tail->prev;
	next_node = g_dapl_provider_list.tail;

	(void) dapl_os_memcpy(cur_node->name, name, len);
	cur_node->name[len] = '\0';
	cur_node->data = g_dapl_provider_template;
	cur_node->data.device_name = cur_node->name;
	cur_node->next = next_node;
	cur_node->prev = prev_node;

	prev_node->next = cur_node;
	next_node->prev = cur_node;

	g_dapl_provider_list.size++;

	if (NULL != p_data) {
		*p_data = &cur_node->data;
	}

bail:
	if (DAT_SUCCESS != status) {
		if (NULL != cur_node) {
			dapl_os_free(cur_node,
			    sizeof (DAPL_PROVIDER_LIST_NODE));
		}
	}

	return (status);
}


DAT_RETURN
dapl_provider_list_search(
    IN  const char *name,
    OUT DAT_PROVIDER **p_data)
{
	DAPL_PROVIDER_LIST_NODE *cur_node;
	DAT_RETURN		status;

	status = DAT_ERROR(DAT_NAME_NOT_FOUND, 0);

	for (cur_node = g_dapl_provider_list.head->next;
	    g_dapl_provider_list.tail != cur_node;
	    cur_node = cur_node->next) {
		if (dapl_provider_list_key_cmp(cur_node->name, name)) {
			if (NULL != p_data) {
				*p_data = &cur_node->data;
			}

			status = DAT_SUCCESS;
			goto bail;
		}
	}

bail:
	return (status);
}


DAT_RETURN
dapl_provider_list_remove(
    IN  const char *name)
{
	DAPL_PROVIDER_LIST_NODE *cur_node, *prev_node, *next_node;
	DAT_RETURN status;

	status = DAT_ERROR(DAT_NAME_NOT_FOUND, 0);

	for (cur_node = g_dapl_provider_list.head->next;
	    g_dapl_provider_list.tail != cur_node;
	    cur_node = cur_node->next) {
		if (dapl_provider_list_key_cmp(cur_node->name, name)) {
			prev_node = cur_node->prev;
			next_node = cur_node->next;

			prev_node->next = next_node;
			next_node->prev = prev_node;

			dapl_os_free(cur_node,
			    sizeof (DAPL_PROVIDER_LIST_NODE));

			g_dapl_provider_list.size--;

			status = DAT_SUCCESS;
			goto bail;
		}
	}

bail:
	return (status);
}


DAT_BOOLEAN
dapl_provider_list_key_cmp(
    const char *name_a,
    const char *name_b)
{
	unsigned int len;

	len = dapl_os_strlen(name_a);

	if (dapl_os_strlen(name_b) != len) {
		return (DAT_FALSE);
	} else if (dapl_os_memcmp(name_a, name_b, len)) {
		return (DAT_FALSE);
	} else {
		return (DAT_TRUE);
	}
}
