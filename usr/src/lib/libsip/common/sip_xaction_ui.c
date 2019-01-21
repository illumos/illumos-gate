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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <strings.h>
#include <pthread.h>
#include <sip.h>

#include "sip_msg.h"
#include "sip_miscdefs.h"
#include "sip_xaction.h"

/*
 * Hold transaction
 */
void
sip_hold_trans(sip_transaction_t sip_trans)
{
	sip_xaction_t	*_trans;

	if (sip_trans == NULL)
		return;
	_trans = (sip_xaction_t *)sip_trans;
	(void) pthread_mutex_lock(&((_trans)->sip_xaction_mutex));
	SIP_XACTION_REFCNT_INCR(_trans);
	(void) pthread_mutex_unlock(&((_trans)->sip_xaction_mutex));
}

/*
 * Release transaction
 */
void
sip_release_trans(sip_transaction_t sip_trans)
{
	sip_xaction_t	*_trans;

	if (sip_trans == NULL)
		return;
	_trans = (sip_xaction_t *)sip_trans;
	SIP_XACTION_REFCNT_DECR(_trans);
}

/*
 * Given a message get the client/server transaction. The caller is
 * responsible for doing a sip_release_trans().
 */
const struct sip_xaction *
sip_get_trans(sip_msg_t sip_msg, int which, int *error)
{
	if (error != NULL)
		*error = 0;
	if (sip_msg == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	return ((sip_transaction_t)sip_xaction_get(NULL, sip_msg, B_FALSE,
	    which, NULL));
}

/*
 * Get the last response sent for this transaction
 */
const struct sip_message *
sip_get_trans_resp_msg(sip_transaction_t sip_trans, int *error)
{
	sip_xaction_t	*_trans;

	if (error != NULL)
		*error = 0;
	if (sip_trans == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	_trans = (sip_xaction_t *)sip_trans;
	if ((_trans->sip_xaction_last_msg != NULL) &&
	    !sip_msg_is_request((sip_msg_t)_trans->sip_xaction_last_msg,
	    error)) {
		return (_trans->sip_xaction_last_msg);
	} else if (!sip_msg_is_request((sip_msg_t)
	    _trans->sip_xaction_orig_msg, error)) {
		return (_trans->sip_xaction_orig_msg);
	}
	return (NULL);
}

/*
 * Get the SIP message that created this transaction
 */
const struct sip_message *
sip_get_trans_orig_msg(sip_transaction_t sip_trans, int *error)
{
	if (error != NULL)
		*error = 0;
	if (sip_trans == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	return (((sip_xaction_t *)sip_trans)->sip_xaction_orig_msg);
}

/*
 * Get the connection object that was used to send the last message for this
 * transaction.
 */
const struct sip_conn_object *
sip_get_trans_conn_obj(sip_transaction_t sip_trans, int *error)
{
	if (error != NULL)
		*error = 0;
	if (sip_trans == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	return (((sip_xaction_t *)sip_trans)->sip_xaction_conn_obj);
}

/*
 * Get the transaction method
 */
sip_method_t
sip_get_trans_method(sip_transaction_t sip_trans, int *error)
{
	if (error != NULL)
		*error = 0;

	if (sip_trans == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (-1);
	}
	return (((sip_xaction_t *)sip_trans)->sip_xaction_method);
}

/*
 * Get the transaction id. Caller frees string
 */
char *
sip_get_trans_branchid(sip_transaction_t trans, int *error)
{
	sip_xaction_t	*xaction = (sip_xaction_t *)trans;
	char		*bid;

	if (error != NULL)
		*error = 0;
	if (xaction == NULL || xaction->sip_xaction_branch_id == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	bid = malloc(strlen(xaction->sip_xaction_branch_id) + 1);
	if (bid == NULL) {
		if (error != NULL)
			*error = ENOMEM;
		return (NULL);
	}
	(void) strncpy(bid, xaction->sip_xaction_branch_id,
	    strlen(xaction->sip_xaction_branch_id));
	bid[strlen(xaction->sip_xaction_branch_id)] = '\0';
	return (bid);
}

/*
 * Get the transaction state
 */
int
sip_get_trans_state(sip_transaction_t trans, int *error)
{
	sip_xaction_t	*xaction = (sip_xaction_t *)trans;

	if (error != NULL)
		*error = 0;
	if (xaction == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (0);
	}
	return (xaction->sip_xaction_state);
}
