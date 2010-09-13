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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <strings.h>

#include "sip_parse_uri.h"
#include "sip_msg.h"
#include "sip_miscdefs.h"
#include "sip_xaction.h"
#include "sip_hash.h"

#define	RFC_3261_BRANCH "z9hG4bK"

/*
 * The transaction hash table
 */
sip_hash_t	sip_xaction_hash[SIP_HASH_SZ];

int (*sip_xaction_ulp_trans_err)(sip_transaction_t, int, void *) = NULL;
void (*sip_xaction_ulp_state_cb)(sip_transaction_t, sip_msg_t, int, int) = NULL;

int sip_xaction_add(sip_xaction_t *, char *, _sip_msg_t *, sip_method_t);
static boolean_t sip_is_conn_obj_cache(sip_conn_object_t, void *);

/*
 * Get the md5 hash of the required fields
 */
int
sip_find_md5_digest(char *bid, _sip_msg_t *msg, uint16_t *hindex,
    sip_method_t method)
{
	boolean_t	is_2543;

	is_2543 = (bid == NULL ||
	    strncmp(bid, RFC_3261_BRANCH, strlen(RFC_3261_BRANCH)) != 0);

	if (is_2543 && msg == NULL)
		return (EINVAL);
	if (is_2543) {
		_sip_header_t	*from = NULL;
		_sip_header_t	*cid = NULL;
		_sip_header_t	*via = NULL;
		const sip_str_t	*to_uri = NULL;
		int		cseq;
		int		error = 0;

		/*
		 * Since the response might contain parameters not in the
		 * request, just use the to URI.
		 */
		to_uri = sip_get_to_uri_str((sip_msg_t)msg, &error);
		if (to_uri == NULL || error != 0)
			return (EINVAL);
		cseq = sip_get_callseq_num((sip_msg_t)msg, &error);
		if (cseq < 0 || error != 0)
			return (EINVAL);
		(void) pthread_mutex_lock(&msg->sip_msg_mutex);
		via = sip_search_for_header(msg, SIP_VIA, NULL);
		from = sip_search_for_header(msg, SIP_FROM, NULL);
		cid = sip_search_for_header(msg, SIP_CALL_ID, NULL);
		(void) pthread_mutex_unlock(&msg->sip_msg_mutex);
		if (via == NULL || from == NULL || cid == NULL)
			return (EINVAL);
		sip_md5_hash(via->sip_hdr_start,
		    via->sip_hdr_end - via->sip_hdr_start,
		    cid->sip_hdr_start,
		    cid->sip_hdr_end - cid->sip_hdr_start,
		    from->sip_hdr_start,
		    from->sip_hdr_end - from->sip_hdr_start,
		    (char *)&cseq, sizeof (int),
		    (char *)&method, sizeof (sip_method_t),
		    to_uri->sip_str_ptr, to_uri->sip_str_len,
		    (uchar_t *)hindex);
	} else {
		sip_md5_hash(bid, strlen(bid), (char *)&method,
		    sizeof (sip_method_t), NULL, 0, NULL, 0, NULL, 0, NULL, 0,
		    (uchar_t *)hindex);
	}
	return (0);
}

/*
 * Add object to the connection cache object. Not checking for duplicates!!
 */
int
sip_add_conn_obj_cache(sip_conn_object_t obj, void *cobj)
{
	void			**obj_val;
	sip_conn_obj_pvt_t	*pvt_data;
	sip_conn_cache_t	*xaction_list;
	sip_xaction_t		*sip_trans = (sip_xaction_t *)cobj;

	/*
	 * Is already cached
	 */
	if (sip_trans->sip_xaction_conn_obj != NULL) {
		if (sip_is_conn_obj_cache(sip_trans->sip_xaction_conn_obj,
		    (void *)sip_trans)) {
			return (0);
		}
		/*
		 * Transaction has cached a different conn_obj, release it
		 */
		sip_del_conn_obj_cache(sip_trans->sip_xaction_conn_obj,
		    (void *)sip_trans);
	}

	xaction_list = malloc(sizeof (sip_conn_cache_t));
	if (xaction_list == NULL)
		return (ENOMEM);
	xaction_list->obj = cobj;
	xaction_list->next = xaction_list->prev = NULL;

	obj_val = (void *)obj;
	pvt_data = (sip_conn_obj_pvt_t *)*obj_val;
	if (pvt_data == NULL) {
		free(xaction_list);
		return (EINVAL);
	}
	(void) pthread_mutex_lock(&pvt_data->sip_conn_obj_cache_lock);

	if (pvt_data->sip_conn_obj_cache == NULL) {
		pvt_data->sip_conn_obj_cache = xaction_list;
	} else {
		xaction_list->next =  pvt_data->sip_conn_obj_cache;
		pvt_data->sip_conn_obj_cache->prev = xaction_list;
		pvt_data->sip_conn_obj_cache = xaction_list;
	}
	sip_refhold_conn(obj);
	sip_trans->sip_xaction_conn_obj = obj;
	(void) pthread_mutex_unlock(&pvt_data->sip_conn_obj_cache_lock);
	return (0);
}

/*
 * Walk thru the list of transactions that have cached this obj and
 * and return true if 'cobj' is one of them.
 */
static boolean_t
sip_is_conn_obj_cache(sip_conn_object_t obj, void *cobj)
{
	void			**obj_val;
	sip_conn_obj_pvt_t	*pvt_data;
	sip_conn_cache_t	*xaction_list;
	sip_xaction_t		*trans;
	sip_xaction_t		*ctrans = (sip_xaction_t *)cobj;

	obj_val = (void *)obj;
	pvt_data = (sip_conn_obj_pvt_t *)*obj_val;
	if (pvt_data == NULL)
		return (B_FALSE);
	(void) pthread_mutex_lock(&pvt_data->sip_conn_obj_cache_lock);
	xaction_list = pvt_data->sip_conn_obj_cache;
	while (xaction_list != NULL) {
		trans = (sip_xaction_t *)xaction_list->obj;
		if (ctrans != trans) {
			xaction_list = xaction_list->next;
			continue;
		}
		(void) pthread_mutex_unlock(&pvt_data->sip_conn_obj_cache_lock);
		return (B_TRUE);
	}
	(void) pthread_mutex_unlock(&pvt_data->sip_conn_obj_cache_lock);
	return (B_FALSE);
}


/*
 * Walk thru the list of transactions that have cached this obj and
 * refrele the objs.
 */
void
sip_del_conn_obj_cache(sip_conn_object_t obj, void *cobj)
{
	void			**obj_val;
	sip_conn_obj_pvt_t	*pvt_data;
	sip_conn_cache_t	*xaction_list;
	sip_conn_cache_t	*tmp_list;
	sip_xaction_t		*trans;
	sip_xaction_t		*ctrans = NULL;

	if (cobj != NULL)
		ctrans = (sip_xaction_t *)cobj;

	obj_val = (void *)obj;
	pvt_data = (sip_conn_obj_pvt_t *)*obj_val;
	if (pvt_data == NULL) {	/* ASSERT FALSE if ctrans != NULL?? */
		if (ctrans != NULL) {
			sip_refrele_conn(obj);
			ctrans->sip_xaction_conn_obj = NULL;
		}
		return;
	}
	(void) pthread_mutex_lock(&pvt_data->sip_conn_obj_cache_lock);
	xaction_list = pvt_data->sip_conn_obj_cache;
	while (xaction_list != NULL) {
		tmp_list = xaction_list;
		trans = (sip_xaction_t *)xaction_list->obj;
		assert(trans != NULL);
		if (ctrans != NULL && ctrans != trans) {
			xaction_list = xaction_list->next;
			continue;
		}
		if (ctrans == NULL)
			(void) pthread_mutex_lock(&trans->sip_xaction_mutex);
		assert(trans->sip_xaction_conn_obj == obj);
		sip_refrele_conn(obj);
		trans->sip_xaction_conn_obj = NULL;
		if (ctrans == NULL)
			(void) pthread_mutex_unlock(&trans->sip_xaction_mutex);
		xaction_list = xaction_list->next;

		/*
		 * Take the obj out of the list
		 */
		if (tmp_list == pvt_data->sip_conn_obj_cache) {
			if (xaction_list == NULL) {
				pvt_data->sip_conn_obj_cache = NULL;
			} else {
				xaction_list->prev = NULL;
				pvt_data->sip_conn_obj_cache = xaction_list;
			}
		} else if (xaction_list == NULL) {
			assert(tmp_list->prev != NULL);
			tmp_list->prev->next = NULL;
		} else {
			assert(tmp_list->prev != NULL);
			tmp_list->prev->next = xaction_list;
			xaction_list->prev = tmp_list->prev;
		}
		tmp_list->prev = NULL;
		tmp_list->next = NULL;
		tmp_list->obj = NULL;

		free(tmp_list);
	}
	(void) pthread_mutex_unlock(&pvt_data->sip_conn_obj_cache_lock);
}

/*
 * Check for a transaction match. Passed to sip_hash_find().
 */
boolean_t
sip_xaction_match(void *obj, void *hindex)
{
	sip_xaction_t	*tmp = (sip_xaction_t *)obj;

	tmp = (sip_xaction_t *)obj;

	if (SIP_IS_XACTION_TERMINATED(tmp->sip_xaction_state))
		return (B_FALSE);
	if (bcmp(tmp->sip_xaction_hash_digest, hindex,
	    sizeof (tmp->sip_xaction_hash_digest)) == 0) {
		SIP_XACTION_REFCNT_INCR(tmp);
		return (B_TRUE);
	}
	return (B_FALSE);
}


/*
 * Find a transaction
 */
static sip_xaction_t *
sip_xaction_find(char *branchid, _sip_msg_t *msg, int which)
{
	sip_xaction_t		*tmp;
	uint16_t		hash_index[8];
	int			hindex;
	sip_method_t		method;
	int			error;
	sip_message_type_t	*sip_msg_info;

	sip_msg_info = msg->sip_msg_req_res;
	method = sip_get_callseq_method((sip_msg_t)msg, &error);
	if (error != 0)
		return (NULL);

	/*
	 * If we are getting a ACK/CANCEL we need to match with the
	 * corresponding INVITE, if any.
	 */
	if (sip_msg_info->is_request && which == SIP_SERVER_TRANSACTION &&
	    (method == ACK || method == CANCEL)) {
		method = INVITE;
	}
	if (sip_find_md5_digest(branchid, msg, hash_index, method) != 0)
		return (NULL);
	hindex = SIP_DIGEST_TO_HASH(hash_index);
	tmp = (sip_xaction_t *)sip_hash_find(sip_xaction_hash,
	    (void *)hash_index, hindex, sip_xaction_match);
	return (tmp);
}

/*
 * create a transaction.
 */
static sip_xaction_t *
sip_xaction_create(sip_conn_object_t obj, _sip_msg_t *msg, char *branchid,
    int *error)
{
	sip_xaction_t		*trans;
	sip_message_type_t	*sip_msg_info;
	int			state = 0;
	int			prev_state = 0;
	sip_method_t		method;
	int			ret;
	int			timer1 = sip_timer_T1;
	int			timer4 = sip_timer_T4;
	int			timerd = sip_timer_TD;

	if (error != NULL)
		*error = 0;
	/*
	 * Make sure we are not creating a transaction for
	 * an ACK request.
	 */
	trans = (sip_xaction_t *)malloc(sizeof (sip_xaction_t));
	if (trans == NULL) {
		if (error != NULL)
			*error = ENOMEM;
		return (NULL);
	}
	bzero(trans, sizeof (sip_xaction_t));
	if (branchid == NULL) {
		trans->sip_xaction_branch_id = (char *)sip_branchid(NULL);
		if (trans->sip_xaction_branch_id == NULL) {
			free(trans);
			if (error != NULL)
				*error = ENOMEM;
			return (NULL);
		}
	} else {
		trans->sip_xaction_branch_id = (char *)malloc(strlen(branchid)
		    + 1);
		if (trans->sip_xaction_branch_id == NULL) {
			free(trans);
			if (error != NULL)
				*error = ENOMEM;
			return (NULL);
		}
		(void) strncpy(trans->sip_xaction_branch_id, branchid,
		    strlen(branchid));
		trans->sip_xaction_branch_id[strlen(branchid)] = '\0';
	}
	(void) pthread_mutex_init(&trans->sip_xaction_mutex, NULL);
	SIP_MSG_REFCNT_INCR(msg);
	trans->sip_xaction_orig_msg = msg;
	assert(msg->sip_msg_req_res != NULL);
	sip_msg_info = msg->sip_msg_req_res;
	if (sip_msg_info->is_request) {
		method = sip_msg_info->sip_req_method;
	} else {
		method = sip_get_callseq_method((sip_msg_t)msg, &ret);
		if (ret != 0) {
			free(trans->sip_xaction_branch_id);
			free(trans);
			if (error != NULL)
				*error = ret;
			return (NULL);
		}
		if (method == INVITE)
			state = SIP_SRV_INV_PROCEEDING;
		else
			state = SIP_SRV_TRYING;
	}
	trans->sip_xaction_method = method;
	trans->sip_xaction_state = state;

	/*
	 * Get connection object specific timeouts, if present
	 */
	if (sip_conn_timer1 != NULL)
		timer1 = sip_conn_timer1(obj);
	if (sip_conn_timer4 != NULL)
		timer4 = sip_conn_timer4(obj);
	if (sip_conn_timerd != NULL)
		timerd = sip_conn_timerd(obj);

	SIP_INIT_TIMER(trans->sip_xaction_TA, 2 * timer1);
	SIP_INIT_TIMER(trans->sip_xaction_TB, 64 * timer1)
	SIP_INIT_TIMER(trans->sip_xaction_TD,  timerd);
	SIP_INIT_TIMER(trans->sip_xaction_TE, timer1);
	SIP_INIT_TIMER(trans->sip_xaction_TF, 64 * timer1);
	SIP_INIT_TIMER(trans->sip_xaction_TG, 2 * timer1);
	SIP_INIT_TIMER(trans->sip_xaction_TH, 64 * timer1);
	SIP_INIT_TIMER(trans->sip_xaction_TI, timer4);
	SIP_INIT_TIMER(trans->sip_xaction_TJ, 64 * timer1);
	SIP_INIT_TIMER(trans->sip_xaction_TK, timer4);

	if ((ret = sip_xaction_add(trans, branchid, msg, method)) != 0) {
		(void) pthread_mutex_destroy(&trans->sip_xaction_mutex);
		free(trans->sip_xaction_branch_id);
		free(trans);
		if (error != NULL)
			*error = ret;
		return (NULL);
	}
	if (sip_xaction_ulp_state_cb != NULL &&
	    prev_state != trans->sip_xaction_state) {
		sip_xaction_ulp_state_cb((sip_transaction_t)trans,
		    (sip_msg_t)msg, prev_state, trans->sip_xaction_state);
	}
	return (trans);
}

/*
 * Find a transaction, create if asked for
 */
sip_xaction_t *
sip_xaction_get(sip_conn_object_t obj, sip_msg_t msg, boolean_t create,
    int which, int *error)
{
	char			*branchid;
	sip_xaction_t		*sip_trans;
	_sip_msg_t		*_msg;
	sip_message_type_t	*sip_msg_info;

	if (error != NULL)
		*error = 0;

	_msg = (_sip_msg_t *)msg;
	sip_msg_info = ((_sip_msg_t *)msg)->sip_msg_req_res;

	branchid = sip_get_branchid(msg, NULL);
	sip_trans = sip_xaction_find(branchid, _msg, which);
	if (sip_trans == NULL && create) {
		/*
		 * If we are sending a request, must be conformant to RFC 3261.
		 */
		if (sip_msg_info->is_request &&
		    (branchid == NULL || strncmp(branchid,
		    RFC_3261_BRANCH, strlen(RFC_3261_BRANCH) != 0))) {
			if (error != NULL)
				*error = EINVAL;
			if (branchid != NULL)
				free(branchid);
			return (NULL);
		}
		sip_trans = sip_xaction_create(obj, _msg, branchid, error);
		if (sip_trans != NULL)
			SIP_XACTION_REFCNT_INCR(sip_trans);
	}
	if (branchid != NULL)
		free(branchid);
	return (sip_trans);
}


/*
 * Delete a transaction if the reference count is 0. Passed to
 * sip_hash_delete().
 */
boolean_t
sip_xaction_remove(void *obj, void *hindex, int *found)
{
	sip_xaction_t	*tmp = (sip_xaction_t *)obj;
	int		count = 0;
	sip_msg_chain_t	*msg_chain;
	sip_msg_chain_t	*nmsg_chain;

	*found = 0;
	tmp = (sip_xaction_t *)obj;
	(void) pthread_mutex_lock(&tmp->sip_xaction_mutex);
	if (bcmp(tmp->sip_xaction_hash_digest, hindex,
	    sizeof (tmp->sip_xaction_hash_digest)) == 0) {
		*found = 1;
		if (tmp->sip_xaction_ref_cnt != 0) {
			(void) pthread_mutex_unlock(&tmp->sip_xaction_mutex);
			return (B_FALSE);
		}
		(void) pthread_mutex_destroy(&tmp->sip_xaction_mutex);
		SIP_CANCEL_TIMER(tmp->sip_xaction_TA);
		SIP_CANCEL_TIMER(tmp->sip_xaction_TB);
		SIP_CANCEL_TIMER(tmp->sip_xaction_TD);
		SIP_CANCEL_TIMER(tmp->sip_xaction_TE);
		SIP_CANCEL_TIMER(tmp->sip_xaction_TF);
		SIP_CANCEL_TIMER(tmp->sip_xaction_TG);
		SIP_CANCEL_TIMER(tmp->sip_xaction_TH);
		SIP_CANCEL_TIMER(tmp->sip_xaction_TI);
		SIP_CANCEL_TIMER(tmp->sip_xaction_TJ);
		SIP_CANCEL_TIMER(tmp->sip_xaction_TK);
		sip_write_to_log((void *)tmp, SIP_TRANSACTION_LOG, NULL, 0);
		free(tmp->sip_xaction_branch_id);
		if (tmp->sip_xaction_last_msg != NULL) {
			SIP_MSG_REFCNT_DECR(tmp->sip_xaction_last_msg);
			tmp->sip_xaction_last_msg = NULL;
		}
		if (tmp->sip_xaction_orig_msg != NULL) {
			SIP_MSG_REFCNT_DECR(tmp->sip_xaction_orig_msg);
			tmp->sip_xaction_orig_msg = NULL;
		}
		if (tmp->sip_xaction_conn_obj != NULL) {
			sip_del_conn_obj_cache(tmp->sip_xaction_conn_obj,
			    (void *)tmp);
		}
		/*
		 * If the transaction logging is disabled before we could
		 * write the captured messages into the transaction log, then
		 * we need to free those captured messsages
		 */
		for (count = 0; count <= SIP_SRV_NONINV_TERMINATED; count++) {
			msg_chain = tmp->sip_xaction_log[count].sip_msgs;
			while (msg_chain != NULL) {
				nmsg_chain = msg_chain->next;
				if (msg_chain->sip_msg != NULL)
					free(msg_chain->sip_msg);
				free(msg_chain);
				msg_chain = nmsg_chain;
			}
		}
		free(tmp);
		return (B_TRUE);
	}
	(void) pthread_mutex_unlock(&tmp->sip_xaction_mutex);
	return (B_FALSE);
}

/*
 * Delete a SIP transaction
 */
void
sip_xaction_delete(sip_xaction_t *trans)
{
	int	hindex;

	(void) pthread_mutex_lock(&trans->sip_xaction_mutex);
	hindex = SIP_DIGEST_TO_HASH(trans->sip_xaction_hash_digest);
	if (trans->sip_xaction_ref_cnt != 0) {
		(void) pthread_mutex_unlock(&trans->sip_xaction_mutex);
		return;
	}
	(void) pthread_mutex_unlock(&trans->sip_xaction_mutex);
	sip_hash_delete(sip_xaction_hash, trans->sip_xaction_hash_digest,
	    hindex, sip_xaction_remove);
}

/*
 * Add a SIP transaction into the hash list.
 */
int
sip_xaction_add(sip_xaction_t *trans, char *branchid, _sip_msg_t *msg,
    sip_method_t method)
{
	uint16_t	hash_index[8];

	if (sip_find_md5_digest(branchid, msg, hash_index, method) != 0)
		return (EINVAL);

	/*
	 * trans is not in the list as yet, so no need to hold the lock
	 */
	bcopy(hash_index, trans->sip_xaction_hash_digest, sizeof (hash_index));

	if (sip_hash_add(sip_xaction_hash, (void *)trans,
	    SIP_DIGEST_TO_HASH(hash_index)) != 0) {
		return (ENOMEM);
	}
	return (0);
}


/*
 * Given a state, return the  string - This is mostly for debug purposes
 */
char *
sip_get_xaction_state(int state)
{
	switch (state) {
		case SIP_NEW_TRANSACTION:
			return ("SIP_NEW_TRANSACTION");
		case SIP_CLNT_CALLING:
			return ("SIP_CLNT_CALLING");
		case SIP_CLNT_INV_PROCEEDING:
			return ("SIP_CLNT_INV_PROCEEDING");
		case SIP_CLNT_INV_TERMINATED:
			return ("SIP_CLNT_INV_TERMINATED");
		case SIP_CLNT_INV_COMPLETED:
			return ("SIP_CLNT_INV_COMPLETED");
		case SIP_CLNT_TRYING:
			return ("SIP_CLNT_TRYING");
		case SIP_CLNT_NONINV_PROCEEDING:
			return ("SIP_CLNT_NONINV_PROCEEDING");
		case SIP_CLNT_NONINV_TERMINATED:
			return ("SIP_CLNT_NONINV_TERMINATED");
		case SIP_CLNT_NONINV_COMPLETED:
			return ("SIP_CLNT_NONINV_COMPLETED");
		case SIP_SRV_INV_PROCEEDING:
			return ("SIP_SRV_INV_PROCEEDING");
		case SIP_SRV_INV_COMPLETED:
			return ("SIP_SRV_INV_COMPLETED");
		case SIP_SRV_CONFIRMED:
			return ("SIP_SRV_CONFIRMED");
		case SIP_SRV_INV_TERMINATED:
			return ("SIP_SRV_INV_TERMINATED");
		case SIP_SRV_TRYING:
			return ("SIP_SRV_TRYING");
		case SIP_SRV_NONINV_PROCEEDING:
			return ("SIP_SRV_NONINV_PROCEEDING");
		case SIP_SRV_NONINV_COMPLETED:
			return ("SIP_SRV_NONINV_COMPLETED");
		case SIP_SRV_NONINV_TERMINATED:
			return ("SIP_SRV_NONINV_TERMINATED");
		default :
			return ("UNKNOWN");
	}
}

/*
 * Initialize the hash table etc.
 */
void
sip_xaction_init(int (*ulp_trans_err)(sip_transaction_t, int, void *),
    void (*ulp_state_cb)(sip_transaction_t, sip_msg_t, int, int))
{
	int	cnt;

	for (cnt = 0; cnt < SIP_HASH_SZ; cnt++) {
		sip_xaction_hash[cnt].hash_count = 0;
		sip_xaction_hash[cnt].hash_head = NULL;
		sip_xaction_hash[cnt].hash_tail = NULL;
		(void) pthread_mutex_init(
		    &sip_xaction_hash[cnt].sip_hash_mutex, NULL);
	}
	if (ulp_trans_err != NULL)
		sip_xaction_ulp_trans_err = ulp_trans_err;
	if (ulp_state_cb != NULL)
		sip_xaction_ulp_state_cb = ulp_state_cb;
}
