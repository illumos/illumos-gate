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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <sip.h>

#include "sip_msg.h"
#include "sip_miscdefs.h"
#include "sip_parse_uri.h"
#include "sip_dialog.h"

/*
 * Create a request using the state maintained in the dialog.
 */
sip_msg_t
sip_create_dialog_req(sip_method_t method, sip_dialog_t dialog,
    char *transport, char *sent_by, int sent_by_port, char *via_param,
    uint32_t maxforward, int cseq)
{
	_sip_dialog_t	*_dialog;
	sip_msg_t	sip_msg;
	char		*uri;
	int		oldseq = 0;

	if (!sip_manage_dialog || dialog == NULL || transport == NULL ||
	    sent_by == NULL) {
		return (NULL);
	}
	if ((sip_msg = sip_new_msg()) == NULL)
		return (NULL);
	_dialog = (_sip_dialog_t *)dialog;
	(void) pthread_mutex_lock(&_dialog->sip_dlg_mutex);
	/*
	 * Depending on the route set, if any, the request URI could either
	 * be the contact URI or the 1st URI from the route set.
	 */
	uri = (char *)sip_dialog_req_uri(_dialog);
	if (uri == NULL)
		goto err_ret;
	if (sip_add_request_line(sip_msg, method, uri) != 0) {
		free(uri);
		goto err_ret;
	}
	free(uri);
	if (sip_copy_header(sip_msg, _dialog->sip_dlg_local_uri_tag, NULL) != 0)
		goto err_ret;
	if (sip_copy_header(sip_msg, _dialog->sip_dlg_remote_uri_tag, NULL) !=
	    0) {
		goto err_ret;
	}
	if (sip_copy_header(sip_msg, _dialog->sip_dlg_local_contact, NULL) != 0)
		goto err_ret;
	if (sip_add_via(sip_msg, transport, sent_by, sent_by_port, via_param) !=
	    0) {
		goto err_ret;
	}
	if (sip_add_maxforward(sip_msg, maxforward) != 0)
		goto err_ret;
	if (sip_copy_header(sip_msg, _dialog->sip_dlg_call_id, NULL) != 0)
		goto err_ret;
	if (cseq < 0) {
		if (_dialog->sip_dlg_local_cseq == 0)
			_dialog->sip_dlg_local_cseq = 1;
		oldseq = _dialog->sip_dlg_local_cseq;
		cseq = ++_dialog->sip_dlg_local_cseq;
	}
	if (sip_add_cseq(sip_msg, method, cseq) != 0) {
		_dialog->sip_dlg_local_cseq = oldseq;
		goto err_ret;
	}
	/*
	 * The route set, even if empty, overrides any pre-existing route set.
	 * If the route set is empty, the UAC MUST NOT add a Route header
	 * field to the request.
	 */
	(void) sip_delete_header_by_name(sip_msg, SIP_ROUTE);

	if (_dialog->sip_dlg_route_set != NULL) {
		if (sip_copy_header(sip_msg, _dialog->sip_dlg_route_set,
		    NULL) != 0) {
			_dialog->sip_dlg_local_cseq = oldseq;
			goto err_ret;
		}
	}
	(void) pthread_mutex_unlock(&_dialog->sip_dlg_mutex);
	return (sip_msg);
err_ret:
	(void) pthread_mutex_unlock(&_dialog->sip_dlg_mutex);
	sip_free_msg(sip_msg);
	return (NULL);
}

/*
 * Create a request using the state maintained in the dialog. The request will
 * not have Contact header.
 */
sip_msg_t
sip_create_dialog_req_nocontact(sip_method_t method, sip_dialog_t dialog,
    char *transport, char *sent_by, int sent_by_port, char *via_param,
    uint32_t maxforward, int cseq)
{
	sip_msg_t	sip_msg;

	sip_msg = sip_create_dialog_req(method, dialog, transport, sent_by,
	    sent_by_port, via_param, maxforward, cseq);
	if (sip_msg != NULL) {
		if (sip_delete_header_by_name(sip_msg, SIP_CONTACT) != 0) {
			sip_free_msg(sip_msg);
			return (NULL);
		}
	}

	return (sip_msg);
}

/*
 * Get the Dialog method
 */
int
sip_get_dialog_method(sip_dialog_t dialog, int *error)
{
	_sip_dialog_t	*_dialog;

	if (error != NULL)
		*error = 0;
	if (!sip_manage_dialog) {
		if (error != NULL)
			*error = EINVAL;
		return (0);
	}
	if (dialog == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (0);
	}
	_dialog = (_sip_dialog_t *)dialog;
	return (_dialog->sip_dlg_method);
}

/*
 * Get the Dialog state
 */
int
sip_get_dialog_state(sip_dialog_t dialog, int *error)
{
	_sip_dialog_t	*_dialog;

	if (error != NULL)
		*error = 0;
	if (!sip_manage_dialog) {
		if (error != NULL)
			*error = EINVAL;
		return (0);
	}
	if (dialog == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (0);
	}
	_dialog = (_sip_dialog_t *)dialog;
	return (_dialog->sip_dlg_state);
}

/*
 * Return the dialog callid
 */
const sip_str_t *
sip_get_dialog_callid(sip_dialog_t dialog, int *error)
{
	_sip_dialog_t		*_dialog;
	const struct sip_value	*val;
	const sip_str_t		*callid = NULL;

	if (error != NULL)
		*error = 0;
	if (!sip_manage_dialog || dialog == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	_dialog = (_sip_dialog_t *)dialog;
	(void) pthread_mutex_lock(&_dialog->sip_dlg_mutex);
	if (dialog->sip_dlg_call_id != NULL) {
		val = sip_get_header_value(_dialog->sip_dlg_call_id, error);
		if (val == NULL) {
			(void) pthread_mutex_unlock(&_dialog->sip_dlg_mutex);
			return (NULL);
		}
		callid = &((sip_hdr_value_t *)val)->str_val;
	}
	(void) pthread_mutex_unlock(&_dialog->sip_dlg_mutex);
	return (callid);
}

/*
 * Return the dialog localtag.
 */
const sip_str_t *
sip_get_dialog_local_tag(sip_dialog_t dialog, int *error)
{
	_sip_dialog_t		*_dialog;
	const sip_str_t		*ltag = NULL;
	const struct sip_value	*val;

	if (error != NULL)
		*error = 0;
	if (!sip_manage_dialog || dialog == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	_dialog = (_sip_dialog_t *)dialog;
	(void) pthread_mutex_lock(&_dialog->sip_dlg_mutex);
	if (dialog->sip_dlg_local_uri_tag != NULL) {
		val = sip_get_header_value(_dialog->sip_dlg_local_uri_tag,
		    error);
		if (val == NULL) {
			(void) pthread_mutex_unlock(&_dialog->sip_dlg_mutex);
			return (NULL);
		}
		ltag = sip_get_param_value((sip_header_value_t)val, "tag",
		    error);
	}
	(void) pthread_mutex_unlock(&_dialog->sip_dlg_mutex);
	return (ltag);
}

/*
 * Return the dialog remotetag
 */
const sip_str_t *
sip_get_dialog_remote_tag(sip_dialog_t dialog, int *error)
{
	_sip_dialog_t		*_dialog;
	const sip_str_t		*ttag = NULL;
	const struct sip_value	*val;

	if (error != NULL)
		*error = 0;
	if (!sip_manage_dialog || dialog == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	_dialog = (_sip_dialog_t *)dialog;
	(void) pthread_mutex_lock(&_dialog->sip_dlg_mutex);
	if (dialog->sip_dlg_remote_uri_tag != NULL) {
		val = sip_get_header_value(_dialog->sip_dlg_remote_uri_tag,
		    error);
		if (val == NULL) {
			(void) pthread_mutex_unlock(&_dialog->sip_dlg_mutex);
			return (NULL);
		}
		ttag = sip_get_param_value((sip_header_value_t)val, "tag",
		    error);
	}
	(void) pthread_mutex_unlock(&_dialog->sip_dlg_mutex);

	return (ttag);
}

/*
 * Return the dialog localuri.
 */
const struct sip_uri *
sip_get_dialog_local_uri(sip_dialog_t dialog, int *error)
{
	_sip_dialog_t		*_dialog;
	const _sip_uri_t	*luri = NULL;
	const struct sip_value	*val;

	if (error != NULL)
		*error = 0;
	if (!sip_manage_dialog || dialog == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	_dialog = (_sip_dialog_t *)dialog;
	(void) pthread_mutex_lock(&_dialog->sip_dlg_mutex);
	if (dialog->sip_dlg_local_uri_tag != NULL) {
		val = sip_get_header_value(_dialog->sip_dlg_local_uri_tag,
		    error);
		if (val == NULL) {
			(void) pthread_mutex_unlock(&_dialog->sip_dlg_mutex);
			return (NULL);
		}
		luri = val->sip_value_parse_uri;
	}
	(void) pthread_mutex_unlock(&_dialog->sip_dlg_mutex);

	return ((sip_uri_t)luri);
}

/*
 * Return the dialog remoteuri.
 */
const struct sip_uri *
sip_get_dialog_remote_uri(sip_dialog_t dialog, int *error)
{
	_sip_dialog_t		*_dialog;
	const _sip_uri_t	*ruri = NULL;
	const struct sip_value	*val;

	if (error != NULL)
		*error = 0;
	if (!sip_manage_dialog || dialog == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	_dialog = (_sip_dialog_t *)dialog;
	(void) pthread_mutex_lock(&_dialog->sip_dlg_mutex);
	if (dialog->sip_dlg_remote_uri_tag != NULL) {
		val = sip_get_header_value(dialog->sip_dlg_remote_uri_tag,
		    error);
		if (val == NULL) {
			(void) pthread_mutex_unlock(&_dialog->sip_dlg_mutex);
			return (NULL);
		}
		ruri = val->sip_value_parse_uri;
	}
	(void) pthread_mutex_unlock(&_dialog->sip_dlg_mutex);
	return ((sip_uri_t)ruri);
}

/*
 * Return the dialog remotetarg.
 */
const struct sip_uri *
sip_get_dialog_remote_target_uri(sip_dialog_t dialog, int *error)
{
	_sip_dialog_t		*_dialog;
	const struct sip_uri	*rtarg = NULL;
	const struct sip_value	*val;

	if (error != NULL)
		*error = 0;
	if (!sip_manage_dialog || dialog == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	_dialog = (_sip_dialog_t *)dialog;
	(void) pthread_mutex_lock(&_dialog->sip_dlg_mutex);
	if (dialog->sip_dlg_remote_target != NULL) {
		val = sip_get_header_value(_dialog->sip_dlg_remote_target,
		    error);
		if (val == NULL) {
			(void) pthread_mutex_unlock(&_dialog->sip_dlg_mutex);
			return (NULL);
		}
		rtarg = val->sip_value_parse_uri;
	}
	(void) pthread_mutex_unlock(&_dialog->sip_dlg_mutex);

	return ((sip_uri_t)rtarg);
}

/*
 * Return the dialog local contact uri.
 */
const struct sip_uri *
sip_get_dialog_local_contact_uri(sip_dialog_t dialog, int *error)
{
	_sip_dialog_t		*_dialog;
	const struct sip_uri	*lcuri = NULL;
	const struct sip_value	*val;

	if (error != NULL)
		*error = 0;
	if (!sip_manage_dialog || dialog == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	_dialog = (_sip_dialog_t *)dialog;
	(void) pthread_mutex_lock(&_dialog->sip_dlg_mutex);
	if (dialog->sip_dlg_local_contact != NULL) {
		val = sip_get_header_value(_dialog->sip_dlg_local_contact,
		    error);
		if (val == NULL) {
			(void) pthread_mutex_unlock(&_dialog->sip_dlg_mutex);
			return (NULL);
		}
		lcuri = val->sip_value_parse_uri;
	}
	(void) pthread_mutex_unlock(&_dialog->sip_dlg_mutex);

	return ((sip_uri_t)lcuri);
}

/*
 * Return the dialog route set
 */
const sip_str_t *
sip_get_dialog_route_set(sip_dialog_t dialog, int *error)
{
	_sip_dialog_t		*_dialog;

	if (error != NULL)
		*error = 0;
	if (!sip_manage_dialog || dialog == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	_dialog = (_sip_dialog_t *)dialog;
	if (_dialog->sip_dlg_rset.sip_str_len > 0)
		return (&_dialog->sip_dlg_rset);
	return (NULL);
}

/*
 * Return the dialog secure
 */
boolean_t
sip_is_dialog_secure(sip_dialog_t dialog, int *error)
{
	_sip_dialog_t	*_dialog;
	boolean_t	issecure;

	if (error != NULL)
		*error = 0;
	if (!sip_manage_dialog || dialog == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (B_FALSE);
	}
	_dialog = (_sip_dialog_t *)dialog;
	(void) pthread_mutex_lock(&_dialog->sip_dlg_mutex);
	issecure = _dialog->sip_dlg_secure;
	(void) pthread_mutex_unlock(&_dialog->sip_dlg_mutex);
	return (issecure);
}

/*
 * Return the dialog local cseq
 */
uint32_t
sip_get_dialog_local_cseq(sip_dialog_t dialog, int *error)
{
	_sip_dialog_t	*_dialog;
	uint32_t	cseq;

	if (error != NULL)
		*error = 0;
	if (!sip_manage_dialog || dialog == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (0);
	}
	_dialog = (_sip_dialog_t *)dialog;
	(void) pthread_mutex_lock(&_dialog->sip_dlg_mutex);
	cseq = _dialog->sip_dlg_local_cseq;
	(void) pthread_mutex_unlock(&_dialog->sip_dlg_mutex);
	return (cseq);
}

/*
 * Return the dialog remote cseq
 */
uint32_t
sip_get_dialog_remote_cseq(sip_dialog_t dialog, int *error)
{
	_sip_dialog_t	*_dialog;
	uint32_t	cseq;

	if (error != NULL)
		*error = 0;
	if (!sip_manage_dialog || dialog == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (0);
	}
	_dialog = (_sip_dialog_t *)dialog;
	(void) pthread_mutex_lock(&_dialog->sip_dlg_mutex);
	cseq = _dialog->sip_dlg_remote_cseq;
	(void) pthread_mutex_unlock(&_dialog->sip_dlg_mutex);
	return (cseq);
}

/*
 * Return the dialog type
 */
int
sip_get_dialog_type(sip_dialog_t dialog, int *error)
{
	_sip_dialog_t	*_dialog;
	int		type;

	if (error != NULL)
		*error = 0;
	if (!sip_manage_dialog || dialog == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (-1);
	}
	_dialog = (_sip_dialog_t *)dialog;
	(void) pthread_mutex_lock(&_dialog->sip_dlg_mutex);
	type = _dialog->sip_dlg_type;
	(void) pthread_mutex_unlock(&_dialog->sip_dlg_mutex);
	return (type);
}


/*
 * Partial dialog ?
 */
boolean_t
sip_incomplete_dialog(sip_dialog_t dialog)
{
	_sip_dialog_t	*_dialog;
	boolean_t	isnew;

	if (!sip_manage_dialog || dialog == NULL)
		return (B_FALSE);
	_dialog = (_sip_dialog_t *)dialog;
	(void) pthread_mutex_lock(&_dialog->sip_dlg_mutex);
	isnew = _dialog->sip_dlg_state == SIP_DLG_NEW;
	(void) pthread_mutex_unlock(&_dialog->sip_dlg_mutex);
	return (isnew);
}

/*
 * Hold dialog
 */
void
sip_hold_dialog(sip_dialog_t dialog)
{
	_sip_dialog_t	*_dialog;

	if (!sip_manage_dialog || dialog == NULL)
		return;
	_dialog = (_sip_dialog_t *)dialog;
	(void) pthread_mutex_lock(&_dialog->sip_dlg_mutex);
	SIP_DLG_REFCNT_INCR(_dialog);
	(void) pthread_mutex_unlock(&_dialog->sip_dlg_mutex);
}

/*
 * Release dialog
 */
void
sip_release_dialog(sip_dialog_t dialog)
{
	_sip_dialog_t	*_dialog;

	if (!sip_manage_dialog || dialog == NULL)
		return;
	_dialog = (_sip_dialog_t *)dialog;
	SIP_DLG_REFCNT_DECR(_dialog);
}

/*
 * Delete a dialog
 */
void
sip_delete_dialog(sip_dialog_t dialog)
{
	if (!sip_manage_dialog || dialog == NULL)
		return;
	sip_dialog_terminate(dialog, NULL);
}
