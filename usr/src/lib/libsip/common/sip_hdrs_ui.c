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

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <errno.h>
#include <pthread.h>
#include <sip.h>

#include "sip_msg.h"

/*
 * Generic function to get int or string value from a header
 */
static void *
sip_get_val_from_hdr(sip_hdr_value_t *val, int val_type, boolean_t stype,
    int *error)
{
	if (error != NULL)
		*error = 0;

	if (val == NULL || val->sip_value_state == SIP_VALUE_DELETED) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}

	if (val->sip_value_state == SIP_VALUE_BAD)
		*error = EPROTO;

	switch (val_type) {
		case (SIP_INT_VAL):
			return (&(val->int_val));
		case (SIP_STR_VAL):
			return (&(val->str_val));
		case (SIP_STRS_VAL):
			if (stype == B_TRUE) {
				if (val->strs_val.s1.sip_str_ptr != NULL)
					return (&(val->strs_val.s1));
				return (NULL);
			}
			if (val->strs_val.s2.sip_str_ptr != NULL)
				return (&(val->strs_val.s2));
			return (NULL);
		case (SIP_INTSTR_VAL):
			if (stype == B_TRUE) {
				if (val->intstr_str.sip_str_ptr != NULL)
					return (&(val->intstr_str));
				else
					return (NULL);
			}
			return (&(val->intstr_int));
		case (SIP_AUTH_VAL):
			return (&(val->auth_val));
	}
	if (error != NULL && *error == 0)
		*error = EINVAL;
	return (NULL);
}

/*
 * Generic function to get value from a header given the value type and
 * the string info (for multi-string values).
 */
static void *
sip_get_val_from_msg(sip_msg_t msg, char *hdr_name, int val_type,
    boolean_t stype, boolean_t empty_val, int *error)
{
	const _sip_header_t	*header;
	sip_hdr_value_t		*value;

	if (error != NULL)
		*error = 0;
	if (msg == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}

	header = sip_get_header(msg, hdr_name, NULL, error);
	if (header == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}

	value = (sip_hdr_value_t *)sip_get_header_value(header, error);
	if (value == NULL) {
		if (error != NULL && empty_val == B_FALSE)
			*error = EPROTO;
		return (NULL);
	}
	return (sip_get_val_from_hdr(value, val_type, stype, error));
}

/*
 * Get the URI from the value
 */
const sip_str_t *
sip_get_cftruri_from_val(sip_header_value_t value, int *error)
{
	sip_hdr_value_t	*cftrvalue;

	if (error != NULL)
		*error = 0;

	if (value == NULL || value->value_state == SIP_VALUE_DELETED) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	cftrvalue = (sip_hdr_value_t *)value;
	/*
	 * If the value is BAD, update error to reflect it.
	 */
	if (error != NULL && value->value_state == SIP_VALUE_BAD)
		*error = EPROTO;
	return (&cftrvalue->cftr_uri);
}

/*
 * Get display name from the value
 */
const sip_str_t *
sip_get_cftrname_from_val(sip_header_value_t value, int *error)
{
	sip_hdr_value_t *cftrvalue;

	if (error != NULL)
		*error = 0;
	if (value == NULL || value->value_state == SIP_VALUE_DELETED) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	cftrvalue = (sip_hdr_value_t *)value;
	/*
	 * If the value is BAD, update error to reflect it.
	 */
	if (error != NULL && value->value_state == SIP_VALUE_BAD)
		*error = EPROTO;
	return (cftrvalue->cftr_name);
}

/*
 * Contact header can have more than one value
 * so we require a value to be passed in to get a value.
 */
const sip_str_t *
sip_get_contact_uri_str(sip_header_value_t value, int *error)
{
	return (sip_get_cftruri_from_val(value, error));
}

/*
 * Contact header can have more than one value
 * so we require a value to be passed in to get a value.
 */
const sip_str_t *
sip_get_contact_display_name(sip_header_value_t value, int *error)
{
	return (sip_get_cftrname_from_val(value, error));
}

/*
 * Route header can have more than one value
 * so we require a value to be passed in to get a value.
 */
const sip_str_t *
sip_get_route_uri_str(sip_header_value_t value, int *error)
{
	return (sip_get_cftruri_from_val(value, error));
}

/*
 * Route header can have more than one value
 * so we require a value to be passed in to get a value.
 */
const sip_str_t *
sip_get_route_display_name(sip_header_value_t value, int *error)
{
	return (sip_get_cftrname_from_val(value, error));
}

/*
 * Get URI from the SIP message
 */
const sip_str_t *
sip_get_cftruri_from_msg(sip_msg_t sip_msg, int *error, char *hdrname)
{
	const sip_hdr_value_t	*value;
	const struct sip_header	*header;

	if (error != NULL)
		*error = 0;
	if (sip_msg == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}

	header = sip_get_header(sip_msg, hdrname, NULL, error);
	if (header == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}

	value = (sip_hdr_value_t *)sip_get_header_value(header, error);
	if (value == NULL) {
		if (error != NULL)
			*error = EPROTO;
		return (NULL);
	}
	/*
	 * If the value is BAD, update error to reflect it.
	 */
	if (error != NULL && value->sip_value_state == SIP_VALUE_BAD)
		*error = EPROTO;
	return (&value->cftr_uri);
}

/*
 * Get display name from the SIP message
 */
const sip_str_t *
sip_get_cftrname_from_msg(sip_msg_t sip_msg, int *error, char *hdrname)
{
	const sip_hdr_value_t		*value;
	const struct  sip_header	*header;

	if (error != NULL)
		*error = 0;
	if (sip_msg == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	header = sip_get_header(sip_msg, hdrname, NULL, error);
	if (header == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}

	value = (sip_hdr_value_t *)sip_get_header_value(header, error);
	if (value == NULL) {
		if (error != NULL)
			*error = EPROTO;
		return (NULL);
	}
	/*
	 * If the value is BAD, update error to reflect it.
	 */
	if (error != NULL && value->sip_value_state == SIP_VALUE_BAD)
		*error = EPROTO;
	return (value->cftr_name);
}

/*
 * Get FROM URI
 */
const sip_str_t *
sip_get_from_uri_str(sip_msg_t sip_msg, int *error)
{
	return (sip_get_cftruri_from_msg(sip_msg, error, SIP_FROM));
}

/*
 * Get FROM display name
 */
const sip_str_t *
sip_get_from_display_name(sip_msg_t sip_msg, int *error)
{
	return (sip_get_cftrname_from_msg(sip_msg, error, SIP_FROM));
}

/*
 * Return the FROM tag
 */
const sip_str_t *
sip_get_from_tag(sip_msg_t sip_msg, int *error)
{
	const sip_hdr_value_t	*value;
	const struct sip_header	*header;

	if (error != NULL)
		*error = 0;
	if (sip_msg == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	header = sip_get_header(sip_msg, SIP_FROM, NULL, error);
	if (header == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}

	value = (sip_hdr_value_t *)sip_get_header_value(header, error);
	if (value == NULL) {
		if (error != NULL)
			*error = EPROTO;
		return (NULL);
	}
	/*
	 * If the value is BAD, update error to reflect it.
	 */
	if (error != NULL && value->sip_value_state == SIP_VALUE_BAD)
		*error = EPROTO;
	return (sip_get_param_value((sip_header_value_t)value, "tag", error));
}

/*
 * Get TO URI
 */
const sip_str_t *
sip_get_to_uri_str(sip_msg_t sip_msg, int *error)
{
	return (sip_get_cftruri_from_msg(sip_msg, error, SIP_TO));
}

/*
 * Get TO display name
 */
const sip_str_t *
sip_get_to_display_name(sip_msg_t sip_msg, int *error)
{
	return (sip_get_cftrname_from_msg(sip_msg, error, SIP_TO));
}

/*
 * Get TO tag
 */
const sip_str_t *
sip_get_to_tag(sip_msg_t sip_msg, int *error)
{
	const sip_hdr_value_t	*value;
	const struct sip_header	*header;

	if (error != NULL)
		*error = 0;
	if (sip_msg == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	header = sip_get_header(sip_msg, SIP_TO, NULL, error);
	if (header == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}

	value = (sip_hdr_value_t *)sip_get_header_value(header, error);
	if (value == NULL) {
		if (error != NULL)
			*error = EPROTO;
		return (NULL);
	}
	/*
	 * If the value is BAD, update error to reflect it.
	 */
	if (error != NULL && value->sip_value_state == SIP_VALUE_BAD)
		*error = EPROTO;
	return (sip_get_param_value((sip_header_value_t)value, "tag", error));
}

/*
 * Return the Call-Id
 */
const sip_str_t *
sip_get_callid(sip_msg_t sip_msg, int *error)
{
	sip_str_t	*r;

	r = (sip_str_t *)sip_get_val_from_msg(sip_msg, SIP_CALL_ID, SIP_STR_VAL,
	    B_FALSE, B_TRUE, error);
	return (r);
}

#define	SIP_CSEQ_NUM	1
#define	SIP_CSEQ_METHOD	2

/*
 * Get number/method from the CSEQ header
 */
static void *
sip_get_cseq_val(sip_msg_t msg, int type, int *error)
{
	const _sip_header_t	*header;
	sip_hdr_value_t		*val;

	if (error != NULL)
		*error = 0;

	if (msg == NULL)  {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	header = sip_get_header(msg, SIP_CSEQ, NULL, error);
	if (header == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	val = (sip_hdr_value_t *)sip_get_header_value(header, error);
	if (val == NULL) {
		if (error != NULL)
			*error = EPROTO;
		return (NULL);
	}
	if (error != NULL && val->sip_value.value_state == SIP_VALUE_BAD)
		*error = EPROTO;

	switch (type) {
		case SIP_CSEQ_NUM:
			return (&(val->cseq_num));
		case SIP_CSEQ_METHOD:
			return (&(val->cseq_method));
	}
	if (error != NULL)
		*error = EINVAL;
	return (NULL);
}

/*
 * Get CSEQ number
 */
int
sip_get_callseq_num(sip_msg_t sip_msg, int *error)
{
	int	*r;

	r = (int *)sip_get_cseq_val(sip_msg, SIP_CSEQ_NUM, error);
	return (r == NULL ? -1 : *r);
}

/*
 * Get CSEQ method
 */
sip_method_t
sip_get_callseq_method(sip_msg_t sip_msg, int *error)
{
	sip_method_t	*r;

	r = (sip_method_t *)sip_get_cseq_val(sip_msg, SIP_CSEQ_METHOD, error);
	return (r == NULL ? -1 : *r);
}

/*
 * Via header can have more than one value
 * so we require a value to be passed in.
 */
const sip_str_t *
sip_get_via_sent_by_host(sip_header_value_t value, int *error)
{
	sip_hdr_value_t	*via_value;

	if (error != NULL)
		*error = 0;
	if (value == NULL || value->value_state == SIP_VALUE_DELETED) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	via_value = (sip_hdr_value_t *)value;
	if (via_value->sip_value_state == SIP_VALUE_BAD && error != NULL)
		*error = EPROTO;
	return (&via_value->via_sent_by_host);
}

/*
 * Via header can have more than one value
 * so we require a value to be passed in.
 */
int
sip_get_via_sent_by_port(sip_header_value_t value, int *error)
{
	sip_hdr_value_t	*via_value;

	if (error != NULL)
		*error = 0;
	if (value == NULL || value->value_state == SIP_VALUE_DELETED) {
		if (error != NULL)
			*error = EINVAL;
		return (-1);
	}
	via_value = (sip_hdr_value_t *)value;
	if (via_value->sip_value_state == SIP_VALUE_BAD && error != NULL)
		*error = EPROTO;
	return (via_value->via_sent_by_port);
}

/*
 * Return the protocol version from the VIA value
 */
const sip_str_t *
sip_get_via_sent_protocol_version(sip_header_value_t value, int *error)
{
	sip_hdr_value_t *via_value;

	if (value == NULL || value->value_state == SIP_VALUE_DELETED) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	via_value = (sip_hdr_value_t *)value;
	if (via_value->sip_value_state == SIP_VALUE_BAD && error != NULL)
		*error = EPROTO;
	return (&via_value->via_protocol_vers);
}

/*
 * Return the protocol name
 */
const sip_str_t *
sip_get_via_sent_protocol_name(sip_header_value_t value, int *error)
{
	sip_hdr_value_t	*via_value;

	if (error != NULL)
		*error = 0;
	if (value == NULL || value->value_state == SIP_VALUE_DELETED) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	via_value = (sip_hdr_value_t *)value;
	if (via_value->sip_value_state == SIP_VALUE_BAD && error != NULL)
		*error = EPROTO;
	return (&via_value->via_protocol_name);
}

/*
 * Return the transport from the VIA value
 */
const sip_str_t *
sip_get_via_sent_transport(sip_header_value_t value, int *error)
{
	sip_hdr_value_t	*via_value;

	if (error != NULL)
		*error = 0;
	if (value == NULL || value->value_state == SIP_VALUE_DELETED) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	via_value = (sip_hdr_value_t *)value;
	if (via_value->sip_value_state == SIP_VALUE_BAD && error != NULL)
		*error = EPROTO;
	return (&via_value->via_protocol_transport);
}

/*
 * get the branch id from the topmost VIA header
 */
char *
sip_get_branchid(sip_msg_t sip_msg, int *error)
{
	_sip_header_t		*header;
	sip_parsed_header_t	*parsed_header;
	sip_hdr_value_t		*via_value;
	const sip_str_t		*param_value;
	char			*bid;
	_sip_msg_t		*_sip_msg;

	if (error != NULL)
		*error = 0;

	if (sip_msg == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}

	_sip_msg = (_sip_msg_t *)sip_msg;

	(void) pthread_mutex_lock(&_sip_msg->sip_msg_mutex);
	header = sip_search_for_header(_sip_msg, SIP_VIA, NULL);
	if (header == NULL) {
		if (error != NULL)
			*error = EINVAL;
		(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
		return (NULL);
	}
	if (sip_parse_via_header(header, &parsed_header) != 0) {
		if (error != NULL)
			*error = EPROTO;
		(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
		return (NULL);
	}
	if (parsed_header == NULL) {
		if (error != NULL)
			*error = EPROTO;
		(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
		return (NULL);
	}
	via_value = (sip_hdr_value_t *)parsed_header->value;
	if (via_value == NULL || via_value->sip_value_state == SIP_VALUE_BAD) {
		if (error != NULL)
			*error = EPROTO;
		(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
		return (NULL);
	}
	param_value = sip_get_param_value((sip_header_value_t)via_value,
	    "branch", error);

	if (param_value == NULL) {
		if (error != NULL)
			*error = EINVAL;
		(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
		return (NULL);
	}

	bid = (char *)malloc(param_value->sip_str_len + 1);
	if (bid == NULL) {
		if (error != NULL)
			*error = ENOMEM;
		(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
		return (NULL);
	}
	(void) strncpy(bid, param_value->sip_str_ptr,
	    param_value->sip_str_len);
	bid[param_value->sip_str_len] = '\0';
	(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
	return (bid);
}

/*
 * adds branchid to the topmost VIA header, if a branchid already exists,
 * returns error.
 */
int
sip_add_branchid_to_via(sip_msg_t sip_msg, char *branchid)
{
	int		err = 0;
	char		*param;
	int		plen;
	sip_header_t	via_hdr;
	_sip_msg_t	*_sip_msg;

	if (sip_msg == NULL)
		return (EINVAL);
	/*
	 * If there is already a branchid param, error?
	 */
	if (sip_get_branchid(sip_msg, NULL) != NULL)
		return (EINVAL);
	_sip_msg = (_sip_msg_t *)sip_msg;
	(void) pthread_mutex_lock(&_sip_msg->sip_msg_mutex);
	via_hdr = (sip_header_t)sip_search_for_header(_sip_msg, SIP_VIA, NULL);
	(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
	if (via_hdr == NULL)
		return (EINVAL);
	plen = strlen(branchid) + strlen("branch=") + 1;
	param = malloc(plen);
	if (param == NULL)
		return (ENOMEM);
	(void) snprintf(param, plen, "branch=%s", branchid);

	(void) sip_add_param(via_hdr, param, &err);
	free(param);

	return (err);
}

/*
 * returns the number of VIA headers in the SIP message
 */
int
sip_get_num_via(sip_msg_t sip_msg, int *error)
{
	_sip_msg_t	*_sip_msg;
	sip_header_t	hdr;
	int		via_cnt = 0;

	if (error != NULL)
		*error = 0;
	if (sip_msg == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (via_cnt);
	}
	_sip_msg = (_sip_msg_t *)sip_msg;
	(void) pthread_mutex_lock(&_sip_msg->sip_msg_mutex);
	hdr = (sip_header_t)sip_search_for_header(_sip_msg, SIP_VIA, NULL);
	while (hdr != NULL) {
		via_cnt++;
		hdr = (sip_header_t)sip_search_for_header(_sip_msg, SIP_VIA,
		    hdr);
	}
	(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
	return (via_cnt);
}

/*
 * Return Max-Forward value
 */
int
sip_get_maxforward(sip_msg_t sip_msg, int *error)
{
	int	*r;

	r = (int *)sip_get_val_from_msg(sip_msg, SIP_MAX_FORWARDS, SIP_INT_VAL,
	    B_FALSE, B_FALSE, error);
	if (r == NULL)
		return (-1);
	return (*r);
}

/*
 * Get the content type
 */
const sip_str_t *
sip_get_content_type(sip_msg_t sip_msg, int *error)
{
	sip_str_t	*r;

	r = (sip_str_t *)sip_get_val_from_msg(sip_msg, SIP_CONTENT_TYPE,
	    SIP_STRS_VAL, B_TRUE, B_FALSE, error);
	return (r);
}

/*
 * Get the content sub-type
 */
const sip_str_t *
sip_get_content_sub_type(sip_msg_t sip_msg, int *error)
{
	sip_str_t	*r;

	r = (sip_str_t *)sip_get_val_from_msg(sip_msg, SIP_CONTENT_TYPE,
	    SIP_STRS_VAL, B_FALSE, B_FALSE, error);
	return (r);
}

/*
 * Return the content-length value
 */
int
sip_get_content_length(sip_msg_t sip_msg, int *error)
{
	int	*r;

	r = (int *)sip_get_val_from_msg(sip_msg, SIP_CONTENT_LENGTH,
	    SIP_INT_VAL, B_FALSE, B_FALSE, error);
	if (r == NULL)
		return (-1);
	return (*r);
}

/*
 * get allow-events
 */
const sip_str_t *
sip_get_allow_events(sip_header_value_t value, int *error)
{
	sip_str_t	*r;
	sip_hdr_value_t	*val = (sip_hdr_value_t *)value;

	r = (sip_str_t *)sip_get_val_from_hdr(val, SIP_STR_VAL, B_TRUE, error);
	return (r);
}

/*
 * get event
 */
const sip_str_t *
sip_get_event(sip_msg_t sip_msg, int *error)
{
	sip_str_t	*r;

	r = (sip_str_t *)sip_get_val_from_msg(sip_msg, SIP_EVENT, SIP_STR_VAL,
	    B_FALSE, B_FALSE, error);
	return (r);
}

/*
 * get subscription state
 */
const sip_str_t *
sip_get_substate(sip_msg_t sip_msg, int *error)
{
	sip_str_t	*r;

	r = (sip_str_t *)sip_get_val_from_msg(sip_msg, SIP_SUBSCRIPTION_STATE,
	    SIP_STR_VAL, B_FALSE, B_FALSE, error);
	return (r);
}

/*
 * get accept type
 */
const sip_str_t *
sip_get_accept_type(sip_header_value_t value, int *error)
{
	sip_str_t	*r;
	sip_hdr_value_t	*val = (sip_hdr_value_t *)value;

	r = (sip_str_t *)sip_get_val_from_hdr(val, SIP_STRS_VAL, B_TRUE, error);
	return (r);
}

/*
 * get accept subtype
 */
const sip_str_t *
sip_get_accept_sub_type(sip_header_value_t value, int *error)
{
	sip_str_t	*r;
	sip_hdr_value_t	*val = (sip_hdr_value_t *)value;

	r = (sip_str_t *)sip_get_val_from_hdr(val, SIP_STRS_VAL, B_FALSE,
	    error);
	return (r);
}

/*
 * accept-encode can have more than one value
 */
const sip_str_t *
sip_get_accept_enc(sip_header_value_t value, int *error)
{
	sip_str_t	*r;
	sip_hdr_value_t	*val = (sip_hdr_value_t *)value;

	r = (sip_str_t *)sip_get_val_from_hdr(val, SIP_STR_VAL, B_FALSE, error);
	return (r);
}

/*
 * accept-language can have more than one value
 */
const sip_str_t *
sip_get_accept_lang(sip_header_value_t value, int *error)
{
	sip_str_t	*r;
	sip_hdr_value_t	*val = (sip_hdr_value_t *)value;

	r = (sip_str_t *)sip_get_val_from_hdr(val, SIP_STR_VAL, B_FALSE, error);
	return (r);
}

/*
 * get URI from the alert-info header
 */
const sip_str_t *
sip_get_alert_info_uri(sip_header_value_t value, int *error)
{
	sip_str_t	*r;
	sip_hdr_value_t	*val = (sip_hdr_value_t *)value;

	r = (sip_str_t *)sip_get_val_from_hdr(val, SIP_STR_VAL, B_FALSE, error);
	return (r);
}

/*
 * get method from allow header
 */
sip_method_t
sip_get_allow_method(sip_header_value_t value, int *error)
{
	int		*r;
	sip_hdr_value_t	*val = (sip_hdr_value_t *)value;

	r = (int *)sip_get_val_from_hdr(val, SIP_INT_VAL, B_FALSE, error);
	return (r == NULL ? -1 : (sip_method_t)*r);
}

/*
 * get URI from call-info header
 */
const sip_str_t *
sip_get_call_info_uri(sip_header_value_t value, int *error)
{
	sip_str_t	*r;
	sip_hdr_value_t	*val = (sip_hdr_value_t *)value;

	r = (sip_str_t *)sip_get_val_from_hdr(val, SIP_STR_VAL, B_FALSE, error);
	return (r);
}

/*
 * get content-disposition value
 */
const sip_str_t *
sip_get_content_disp(sip_msg_t sip_msg, int *error)
{
	sip_str_t	*r;

	r = (sip_str_t *)sip_get_val_from_msg(sip_msg, SIP_CONTENT_DIS,
	    SIP_STR_VAL, B_FALSE, B_FALSE, error);
	return (r);
}

/*
 * get content-encoding value
 */
const sip_str_t *
sip_get_content_enc(sip_header_value_t value, int *error)
{
	sip_str_t	*r;
	sip_hdr_value_t	*val = (sip_hdr_value_t *)value;

	r = (sip_str_t *)sip_get_val_from_hdr(val, SIP_STR_VAL, B_FALSE, error);
	return (r);
}

/*
 * get content-language value
 */
const sip_str_t *
sip_get_content_lang(sip_header_value_t value, int *error)
{
	sip_str_t	*r;
	sip_hdr_value_t	*val = (sip_hdr_value_t *)value;

	r = (sip_str_t *)sip_get_val_from_hdr(val, SIP_STR_VAL, B_FALSE, error);
	return (r);
}

/*
 * sip_get_date_time, day, wkday, month, year
 */
#define	D_TIME		0x01
#define	D_DAY		0x02
#define	D_MONTH		0x03
#define	D_YEAR		0x04
#define	D_WKDAY		0x05
#define	D_TIMEZONE	0x06

/*
 * get date information
 */
static void *
sip_get_date_val(sip_msg_t msg, int type, int *error)
{
	const _sip_header_t	*header;
	sip_hdr_value_t		*val;

	if (error != NULL)
		*error = 0;
	if (msg == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	header = sip_get_header(msg, SIP_DATE, NULL, error);
	if (header == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}

	val = (sip_hdr_value_t *)sip_get_header_value(header, error);
	if (val == NULL) {
		if (error != NULL)
			*error = EPROTO;
		return (NULL);
	}
	if (error != NULL && val->sip_value.value_state == SIP_VALUE_BAD)
		*error = EPROTO;
	switch (type) {
		case (D_TIME):
			return (&(val->date_t));
		case (D_DAY):
			return (&(val->date_d));
		case (D_MONTH):
			return (&(val->date_m));
		case (D_YEAR):
			return (&(val->date_y));
		case (D_WKDAY):
			return (&(val->date_wd));
		case (D_TIMEZONE):
			return (&(val->date_tz));
	}
	if (error != NULL)
		*error = EINVAL;
	return (NULL);
}

/*
 * get time value
 */
const sip_str_t *
sip_get_date_time(sip_msg_t sip_msg, int *error)
{
	sip_str_t	*r;

	r = (sip_str_t *)sip_get_date_val(sip_msg, D_TIME, error);
	return (r);
}

/*
 * get day
 */
int
sip_get_date_day(sip_msg_t sip_msg, int *error)
{
	int	*r = NULL;

	r = sip_get_date_val(sip_msg, D_DAY, error);
	return (r == NULL ? -1 : *(int *)r);
}

/*
 * get month
 */
const sip_str_t *
sip_get_date_month(sip_msg_t sip_msg, int *error)
{
	sip_str_t	*r;

	r = (sip_str_t *)sip_get_date_val(sip_msg, D_MONTH, error);
	return (r);
}

/*
 * get year
 */
int
sip_get_date_year(sip_msg_t sip_msg, int *error)
{
	int	*r;

	r = (int *)sip_get_date_val(sip_msg, D_YEAR, error);
	return (r == NULL ? -1 : *r);
}

/*
 * get day of the week
 */
const sip_str_t *
sip_get_date_wkday(sip_msg_t sip_msg, int *error)
{
	sip_str_t	*r;

	r = (sip_str_t *)sip_get_date_val(sip_msg, D_WKDAY, error);
	return (r);
}

/*
 * get the timezone
 */
const sip_str_t *
sip_get_date_timezone(sip_msg_t sip_msg, int *error)
{
	sip_str_t	*r;

	r = (sip_str_t *)sip_get_date_val(sip_msg, D_TIMEZONE, error);
	return (r);
}

/*
 * get error-info URI
 */
const sip_str_t *
sip_get_error_info_uri(sip_header_value_t value, int *error)
{
	sip_str_t	*r;
	sip_hdr_value_t	*val = (sip_hdr_value_t *)value;

	r = (sip_str_t *)sip_get_val_from_hdr(val, SIP_STR_VAL, B_FALSE, error);
	return (r);
}

/*
 * get priv-value from privacy
 */
const sip_str_t *
sip_get_priv_value(sip_header_value_t value, int *error)
{
	sip_str_t	*r;
	sip_hdr_value_t	*val = (sip_hdr_value_t *)value;

	r = (sip_str_t *)sip_get_val_from_hdr(val, SIP_STR_VAL, B_FALSE, error);
	return (r);
}

/*
 * return expires value
 */
int
sip_get_expires(sip_msg_t sip_msg, int *error)
{
	int	*r;

	r = (int *)sip_get_val_from_msg(sip_msg, SIP_EXPIRE, SIP_INT_VAL,
	    B_FALSE, B_FALSE, error);
	if (r == NULL)
		return (-1);
	return (*r);
}

/*
 * get reply-to value
 */
const sip_str_t *
sip_get_in_reply_to(sip_header_value_t value, int *error)
{
	sip_str_t	*r;
	sip_hdr_value_t	*val = (sip_hdr_value_t *)value;

	r = (sip_str_t *)sip_get_val_from_hdr(val, SIP_STR_VAL, B_FALSE, error);
	return (r);
}

/*
 * get min-expires value
 */
int
sip_get_min_expires(sip_msg_t sip_msg, int *error)
{
	int	*r;

	r = (int *)sip_get_val_from_msg(sip_msg, SIP_MIN_EXPIRE, SIP_INT_VAL,
	    B_FALSE, B_FALSE, error);
	if (r == NULL)
		return (-1);
	return (*r);
}

/*
 * get mime-version
 */
const sip_str_t *
sip_get_mime_version(sip_msg_t sip_msg, int *error)
{
	sip_str_t	*r;

	r = (sip_str_t *)sip_get_val_from_msg(sip_msg, SIP_MIME_VERSION,
	    SIP_STR_VAL, B_FALSE, B_FALSE, error);
	return (r);
}

/*
 * get organization value
 */
const sip_str_t *
sip_get_org(sip_msg_t sip_msg, int *error)
{
	sip_str_t	*r;

	r = (sip_str_t *)sip_get_val_from_msg(sip_msg, SIP_ORGANIZATION,
	    SIP_STR_VAL, B_FALSE, B_TRUE, error);
	return (r);
}

/*
 * get priority value
 */
const sip_str_t *
sip_get_priority(sip_msg_t sip_msg, int *error)
{
	sip_str_t	*r;

	r = (sip_str_t *)sip_get_val_from_msg(sip_msg, SIP_PRIORITY,
	    SIP_STR_VAL, B_FALSE, B_FALSE, error);
	return (r);
}

/*
 * get display name
 */
const sip_str_t *
sip_get_pidentity_display_name(sip_header_value_t value, int *error)
{
	sip_str_t	*r;
	sip_hdr_value_t	*val = (sip_hdr_value_t *)value;

	r = (sip_str_t *)sip_get_val_from_hdr(val, SIP_STRS_VAL, B_TRUE, error);

	return (r);
}

/*
 * get URI
 */
const sip_str_t *
sip_get_pidenty_uri_str(sip_header_value_t value, int *error)
{
	sip_str_t	*r;
	sip_hdr_value_t	*val = (sip_hdr_value_t *)value;

	r = (sip_str_t *)sip_get_val_from_hdr(val, SIP_STRS_VAL, B_FALSE,
	    error);

	return (r);
}

/*
 * get display name from passerted-identity header
 */
const sip_str_t *
sip_get_passertedid_display_name(sip_header_value_t value, int *error)
{
	return (sip_get_pidentity_display_name(value, error));
}

/*
 * get URI from passerted-identity header
 */
const sip_str_t *
sip_get_passertedid_uri_str(sip_header_value_t value, int *error)
{
	return (sip_get_pidenty_uri_str(value, error));
}

/*
 * get display name from ppreferred-identity header
 */
const sip_str_t *
sip_get_ppreferredid_display_name(sip_header_value_t value, int *error)
{
	return (sip_get_pidentity_display_name(value, error));
}

/*
 * get URI from ppreferred-identity header
 */
const sip_str_t *
sip_get_ppreferredid_uri_str(sip_header_value_t value, int *error)
{
	return (sip_get_pidenty_uri_str(value, error));
}

#define	SIP_RACK_RESP_NUM	1
#define	SIP_RACK_CSEQ_NUM	2
#define	SIP_RACK_METHOD		3

/*
 * Get rack information
 */
static void *
sip_get_rack_val(sip_msg_t msg, int type, int *error)
{
	const _sip_header_t	*header;
	sip_hdr_value_t		*val;

	if (error != NULL)
		*error = 0;

	if (msg == NULL)  {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	header = sip_get_header(msg, SIP_RACK, NULL, error);
	if (header == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	val = (sip_hdr_value_t *)sip_get_header_value(header, error);
	if (val == NULL) {
		if (error != NULL)
			*error = EPROTO;
		return (NULL);
	}
	if (error != NULL && val->sip_value.value_state == SIP_VALUE_BAD)
		*error = EPROTO;

	switch (type) {
		case SIP_RACK_RESP_NUM:
			return (&(val->rack_resp));
		case SIP_RACK_CSEQ_NUM:
			return (&(val->rack_cseq));
		case SIP_RACK_METHOD:
			return (&(val->rack_method));
	}
	if (error != NULL)
		*error = EINVAL;
	return (NULL);
}

/*
 * get response number for rack
 */
int
sip_get_rack_resp_num(sip_msg_t sip_msg, int *error)
{
	int	*r;

	r = (int *)sip_get_rack_val(sip_msg, SIP_RACK_RESP_NUM, error);

	return (r == NULL ? -1 : *r);
}

/*
 * get sequence number for rack
 */
int
sip_get_rack_cseq_num(sip_msg_t sip_msg, int *error)
{
	int	*r;

	r = (int *)sip_get_rack_val(sip_msg, SIP_RACK_CSEQ_NUM, error);

	return (r == NULL ? -1 : *r);
}

/*
 * get method for rack
 */
sip_method_t
sip_get_rack_method(sip_msg_t sip_msg, int *error)
{
	sip_method_t	*r;

	r = (sip_method_t *)sip_get_rack_val(sip_msg, SIP_RACK_METHOD, error);

	return (r == NULL ? -1 : *r);
}

/*
 * get response number from rseq
 */
int
sip_get_rseq_resp_num(sip_msg_t sip_msg, int *error)
{
	int	*r;

	r = (int *)sip_get_val_from_msg(sip_msg, SIP_RSEQ, SIP_INT_VAL,
	    B_FALSE, B_FALSE, error);

	return (r == NULL ? -1 : *r);
}

/*
 * get reply-to display name
 */
const sip_str_t *
sip_get_replyto_display_name(sip_msg_t sip_msg, int *error)
{
	sip_str_t	*r;

	r = (sip_str_t *)sip_get_val_from_msg(sip_msg, SIP_REPLYTO,
	    SIP_STRS_VAL, B_TRUE, B_FALSE, error);
	return (r);
}

/*
 * get reply-to URI
 */
const sip_str_t *
sip_get_replyto_uri_str(sip_msg_t sip_msg, int *error)
{
	sip_str_t	*r;

	r = (sip_str_t *)sip_get_val_from_msg(sip_msg, SIP_REPLYTO,
	    SIP_STRS_VAL, B_FALSE, B_FALSE, error);

	return (r);
}

/*
 * get require value
 */
const sip_str_t *
sip_get_require(sip_header_value_t value, int *error)
{
	sip_str_t	*r;
	sip_hdr_value_t	*val = (sip_hdr_value_t *)value;

	r = (sip_str_t *)sip_get_val_from_hdr(val, SIP_STR_VAL, B_FALSE, error);
	return (r);
}

/*
 * get retry-after time
 */
int
sip_get_retry_after_time(sip_msg_t sip_msg, int *error)
{
	int	*t;

	t = (int *)sip_get_val_from_msg(sip_msg, SIP_RETRY_AFTER,
	    SIP_INTSTR_VAL, B_FALSE, B_FALSE, error);
	if (t == NULL)
		return (-1);
	return (*t);
}

/*
 * get retry-after comments
 */
const sip_str_t *
sip_get_retry_after_cmts(sip_msg_t sip_msg, int *error)
{
	sip_str_t	*r;

	r = (sip_str_t *)sip_get_val_from_msg(sip_msg, SIP_RETRY_AFTER,
	    SIP_INTSTR_VAL, B_TRUE, B_FALSE, error);
	return (r);
}

/*
 * get subject
 */
const sip_str_t *
sip_get_subject(sip_msg_t sip_msg, int *error)
{
	sip_str_t	*r;

	r = (sip_str_t *)sip_get_val_from_msg(sip_msg, SIP_SUBJECT, SIP_STR_VAL,
	    B_FALSE, B_TRUE, error);
	return (r);
}

/*
 * get supported
 */
const sip_str_t *
sip_get_supported(sip_header_value_t value, int *error)
{
	sip_str_t	*r;
	sip_hdr_value_t	*val = (sip_hdr_value_t *)value;

	r = (sip_str_t *)sip_get_val_from_hdr(val, SIP_STR_VAL, B_FALSE, error);
	return (r);
}

/*
 * get timestamp delay
 */
const sip_str_t *
sip_get_tstamp_delay(sip_msg_t sip_msg, int *error)
{
	sip_str_t	*t;

	t = sip_get_val_from_msg(sip_msg, SIP_TIMESTAMP, SIP_STRS_VAL, B_FALSE,
	    B_FALSE, error);
	return (t);
}

/*
 * get timestamp
 */
const sip_str_t *
sip_get_tstamp_value(sip_msg_t sip_msg, int *error)
{
	sip_str_t	*t;

	t = sip_get_val_from_msg(sip_msg, SIP_TIMESTAMP, SIP_STRS_VAL, B_TRUE,
	    B_FALSE, error);
	return (t);
}

/*
 * get unsupported value
 */
const sip_str_t *
sip_get_unsupported(sip_header_value_t value, int *error)
{
	sip_str_t	*r;
	sip_hdr_value_t	*val = (sip_hdr_value_t *)value;

	r = (sip_str_t *)sip_get_val_from_hdr(val, SIP_STR_VAL, B_FALSE, error);
	return (r);
}

/*
 * get server value from message
 */
const sip_str_t *
sip_get_server(sip_msg_t sip_msg, int *error)
{
	sip_str_t	*r;

	r = (sip_str_t *)sip_get_val_from_msg(sip_msg, SIP_SERVER, SIP_STR_VAL,
	    B_FALSE, B_FALSE, error);
	return (r);
}

/*
 * get user-agent value
 */
const sip_str_t *
sip_get_user_agent(sip_msg_t sip_msg, int *error)
{
	sip_str_t	*r;

	r = sip_get_val_from_msg(sip_msg, SIP_USER_AGENT, SIP_STR_VAL, B_FALSE,
	    B_FALSE, error);
	return (r);
}

#define	W_CODE	0x05
#define	W_AGENT	0x06
#define	W_TEXT	0x07

/*
 * get warning info
 */
static void *
sip_get_warninfo(sip_header_value_t value, int info, int *error)
{
	sip_hdr_value_t	*val = (sip_hdr_value_t *)value;

	if (error != NULL)
		*error = 0;

	if (val == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}

	if (val->sip_value_state == SIP_VALUE_BAD) {
		*error = EPROTO;
		return (NULL);
	}

	switch (info) {
		case (W_CODE):
			return (&(val->warn_code));
		case (W_AGENT):
			return (&(val->warn_agt));
		case (W_TEXT):
			return (&(val->warn_text));
	}
	if (error != NULL)
		*error = EINVAL;
	return (NULL);
}

/*
 * get warning code
 */
int
sip_get_warning_code(sip_header_value_t value, int *error)
{
	int	*c;

	if (error != NULL)
		*error = 0;

	if (value == NULL || value->value_state == SIP_VALUE_DELETED) {
		if (error != NULL)
			*error = EINVAL;
		return (-1);
	}
	c = (int *)sip_get_warninfo(value, W_CODE, error);
	if (c == NULL)
		return (-1);
	return (*c);
}

/*
 * get warning agent
 */
const sip_str_t *
sip_get_warning_agent(sip_header_value_t value, int *error)
{
	sip_str_t	*r;

	if (value == NULL || value->value_state == SIP_VALUE_DELETED) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	r = (sip_str_t *)sip_get_warninfo(value, W_AGENT, error);
	return (r);
}

/*
 * get warning text
 */
const sip_str_t *
sip_get_warning_text(sip_header_value_t value, int *error)
{
	sip_str_t	*r;

	if (value == NULL || value->value_state == SIP_VALUE_DELETED) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	r = (sip_str_t *)sip_get_warninfo(value, W_TEXT, error);
	return (r);
}

/*
 * get authorization scheme
 */
const sip_str_t *
sip_get_author_scheme(sip_msg_t sip_msg, int *error)
{
	sip_str_t	*r;

	r = sip_get_val_from_msg(sip_msg, SIP_AUTHOR, SIP_AUTH_VAL, B_FALSE,
	    B_FALSE, error);
	return (r);
}

/*
 * get authentication parameter
 */
static const sip_str_t *
sip_get_auth_param(sip_msg_t msg, char *hdr_name, char *pname, int *error)
{
	const _sip_header_t	*header;
	sip_hdr_value_t		*value;
	sip_param_t		*param;

	if (error != NULL)
		*error = 0;

	if (msg == NULL || pname == NULL || hdr_name == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}

	header = sip_get_header(msg, hdr_name, NULL, error);
	if (header == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}

	value = (sip_hdr_value_t *)sip_get_header_value(header, error);
	if (value == NULL) {
		if (error != NULL)
			*error = EPROTO;
		return (NULL);
	}

	param = sip_get_param_from_list(value->auth_param, pname);
	if (param != NULL)
		return (&param->param_value);
	return (NULL);
}

/*
 * get authentication parameter
 */
const sip_str_t *
sip_get_author_param(sip_msg_t sip_msg, char *name, int *error)
{
	const sip_str_t	*r;

	r = sip_get_auth_param(sip_msg, SIP_AUTHOR, name, error);
	return (r);
}

/*
 * get authentication info
 */
const sip_str_t *
sip_get_authen_info(sip_header_value_t value, int *error)
{
	sip_str_t	*r;
	sip_hdr_value_t	*val = (sip_hdr_value_t *)value;

	if (error != NULL)
		*error = 0;
	if (value == NULL || value->value_state == SIP_VALUE_DELETED) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	r = sip_get_val_from_hdr(val, SIP_STR_VAL, B_FALSE, error);
	return (r);
}

/*
 * get proxy-authentication scheme
 */
const sip_str_t *
sip_get_proxy_authen_scheme(sip_msg_t msg, int *error)
{
	sip_str_t	*r;

	r = sip_get_val_from_msg(msg, SIP_PROXY_AUTHEN, SIP_AUTH_VAL, B_FALSE,
	    B_FALSE, error);
	return (r);
}

/*
 * get proxy authentication parameter
 */
const sip_str_t *
sip_get_proxy_authen_param(sip_msg_t sip_msg, char *name, int *error)
{
	const sip_str_t	*r;

	r = sip_get_auth_param(sip_msg, SIP_PROXY_AUTHEN, name, error);
	return (r);
}

/*
 * get proxy-authorization scheme
 */
const sip_str_t *
sip_get_proxy_author_scheme(sip_msg_t msg, int *error)
{
	sip_str_t	*r;

	r = sip_get_val_from_msg(msg, SIP_PROXY_AUTHOR, SIP_AUTH_VAL, B_FALSE,
	    B_FALSE, error);
	return (r);
}

/*
 * get proxy-authorization parameter
 */
const sip_str_t *
sip_get_proxy_author_param(sip_msg_t sip_msg, char *name, int *error)
{
	const sip_str_t	*r;

	r = sip_get_auth_param(sip_msg, SIP_PROXY_AUTHOR, name, error);
	return (r);
}

/*
 * get proxy-require
 */
const sip_str_t *
sip_get_proxy_require(sip_header_value_t value, int *error)
{
	sip_str_t	*r;
	sip_hdr_value_t	*val = (sip_hdr_value_t *)value;

	if (error != NULL)
		*error = 0;
	if (value == NULL || value->value_state == SIP_VALUE_DELETED) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	r = sip_get_val_from_hdr(val, SIP_STR_VAL, B_FALSE, error);
	return (r);
}

/*
 * get www-authentication scheme
 */
const sip_str_t *
sip_get_www_authen_scheme(sip_msg_t msg, int *error)
{
	sip_str_t	*r;

	r = sip_get_val_from_msg(msg, SIP_WWW_AUTHEN, SIP_AUTH_VAL, B_FALSE,
	    B_FALSE, error);
	return (r);
}

/*
 * get www-authentication parameter
 */
const sip_str_t *
sip_get_www_authen_param(sip_msg_t sip_msg, char *name, int *error)
{
	const sip_str_t	*r;

	r = sip_get_auth_param(sip_msg, SIP_WWW_AUTHEN, name, error);
	return (r);
}
