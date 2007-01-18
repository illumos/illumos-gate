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
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <strings.h>
#include <pthread.h>
#include <sip.h>

#include "sip_msg.h"
#include "sip_miscdefs.h"
#include "sip_parse_uri.h"
#include "sip_xaction.h"

#define	SIP_BUF_SIZE	128

/*
 * Find the header named header, consecutive calls with old_header
 * passed in will return next header of the same type.
 * If no name is passed the first header is returned. consectutive calls
 * with no name but an old header will return the next header.
 */
const struct sip_header *
sip_get_header(sip_msg_t sip_msg, char *header_name, sip_header_t old_header,
    int *error)
{
	_sip_msg_t		*_sip_msg;
	const struct sip_header	*sip_hdr;

	if (error != NULL)
		*error = 0;
	if (sip_msg == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	_sip_msg = (_sip_msg_t *)sip_msg;
	(void) pthread_mutex_lock(&_sip_msg->sip_msg_mutex);
	sip_hdr = (sip_header_t)sip_search_for_header((_sip_msg_t *)sip_msg,
	    header_name, (_sip_header_t *)old_header);
	(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
	if (sip_hdr == NULL && error != NULL)
		*error = EINVAL;
	return (sip_hdr);
}

/*
 * Return the request line as a string. Caller releases the returned string.
 */
char *
sip_reqline_to_str(sip_msg_t sip_msg, int *error)
{
	char	*reqstr;

	if (error != NULL)
		*error = 0;
	if (sip_msg == NULL || !sip_msg_is_request(sip_msg, error)) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	reqstr = _sip_startline_to_str((_sip_msg_t *)sip_msg, error);
	return (reqstr);
}

/*
 * Return the response line as a string. Caller releases the returned string.
 */
char *
sip_respline_to_str(sip_msg_t sip_msg, int *error)
{
	char	*respstr;

	if (error != NULL)
		*error = 0;
	if (sip_msg == NULL || sip_msg_is_request(sip_msg, error)) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	respstr = _sip_startline_to_str((_sip_msg_t *)sip_msg, error);
	return (respstr);
}

/*
 * return the first value of the header
 */
const struct sip_value *
sip_get_header_value(const struct sip_header *sip_header, int *error)
{
	_sip_header_t		*_sip_header;
	sip_parsed_header_t	*sip_parsed_header;
	int			ret = 0;
	const struct sip_value	*value;

	if (error != NULL)
		*error = 0;
	if (sip_header == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	_sip_header = (_sip_header_t *)sip_header;
	if (_sip_header->sip_hdr_sipmsg != NULL) {
		(void) pthread_mutex_lock(
		    &_sip_header->sip_hdr_sipmsg->sip_msg_mutex);
	}
	if (_sip_header->sip_header_state == SIP_HEADER_DELETED) {
		if (_sip_header->sip_hdr_sipmsg != NULL) {
			(void) pthread_mutex_unlock(
			    &_sip_header->sip_hdr_sipmsg->sip_msg_mutex);
		}
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	ret = _sip_header->sip_header_functions->header_parse_func(
	    _sip_header, &sip_parsed_header);
	if (_sip_header->sip_hdr_sipmsg != NULL) {
		(void) pthread_mutex_unlock
		    (&_sip_header->sip_hdr_sipmsg->sip_msg_mutex);
	}
	if (error != NULL)
		*error = ret;

	if (ret != 0)
		return (NULL);
	value = (sip_header_value_t)sip_parsed_header->value;
	while (value != NULL && value->value_state == SIP_VALUE_DELETED)
		value = value->next;
	if (value != NULL && value->value_state == SIP_VALUE_BAD &&
	    error != NULL) {
		*error = EPROTO;
	}
	return ((sip_header_value_t)value);
}

/*
 * Return the next value of the header.
 */
const struct sip_value *
sip_get_next_value(sip_header_value_t old_value, int *error)
{
	const struct sip_value *value;

	if (error != NULL)
		*error = 0;
	if (old_value == NULL || old_value->next == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	/*
	 * We never free the deleted values so no need to hold a lock.
	 */
	value = (sip_header_value_t)old_value->next;
	while (value != NULL && value->value_state == SIP_VALUE_DELETED)
		value = value->next;
	if (value != NULL && value->value_state == SIP_VALUE_BAD &&
	    error != NULL) {
		*error = EPROTO;
	}
	return ((sip_header_value_t)value);
}

/*
 * Given a SIP message, delete the header "header_name".
 */
int
sip_delete_header_by_name(sip_msg_t msg, char *header_name)
{
	_sip_msg_t	*_msg = (_sip_msg_t *)msg;
	sip_header_t	sip_hdr;
	_sip_header_t	*_sip_hdr;

	if (_msg == NULL || header_name == NULL)
		return (EINVAL);
	(void) pthread_mutex_lock(&_msg->sip_msg_mutex);
	if (_msg->sip_msg_cannot_be_modified) {
		(void) pthread_mutex_unlock(&_msg->sip_msg_mutex);
		return (EPERM);
	}
	sip_hdr = (sip_header_t)sip_search_for_header(_msg, header_name, NULL);
	if (sip_hdr == NULL) {
		(void) pthread_mutex_unlock(&_msg->sip_msg_mutex);
		return (EINVAL);
	}
	_sip_hdr = (_sip_header_t *)sip_hdr;
	_sip_hdr->sip_header_state = SIP_HEADER_DELETED;
	_sip_hdr->sip_hdr_sipmsg->sip_msg_len -= _sip_hdr->sip_hdr_end -
	    _sip_hdr->sip_hdr_start;
	assert(_sip_hdr->sip_hdr_sipmsg->sip_msg_len >= 0);
	if (_msg->sip_msg_buf != NULL)
		_msg->sip_msg_modified = B_TRUE;
	(void) pthread_mutex_unlock(&_msg->sip_msg_mutex);

	return (0);
}

/*
 * Mark the header as deleted.
 */
int
sip_delete_header(sip_header_t sip_header)
{
	_sip_header_t	*_sip_header;

	if (sip_header == NULL)
		return (EINVAL);
	_sip_header = (_sip_header_t *)sip_header;
	(void) pthread_mutex_lock(&_sip_header->sip_hdr_sipmsg->sip_msg_mutex);
	if (_sip_header->sip_hdr_sipmsg->sip_msg_cannot_be_modified) {
		(void) pthread_mutex_unlock
		    (&_sip_header->sip_hdr_sipmsg->sip_msg_mutex);
		return (EPERM);
	}
	if (_sip_header->sip_header_state == SIP_HEADER_DELETED) {
		(void) pthread_mutex_unlock(
		    &_sip_header->sip_hdr_sipmsg->sip_msg_mutex);
		return (EINVAL);
	}
	_sip_header->sip_header_state = SIP_HEADER_DELETED;
	_sip_header->sip_hdr_sipmsg->sip_msg_len -= _sip_header->sip_hdr_end -
	    _sip_header->sip_hdr_start;
	assert(_sip_header->sip_hdr_sipmsg->sip_msg_len >= 0);
	if (_sip_header->sip_hdr_sipmsg->sip_msg_buf != NULL)
		_sip_header->sip_hdr_sipmsg->sip_msg_modified = B_TRUE;
	(void) pthread_mutex_unlock
	    (&_sip_header->sip_hdr_sipmsg->sip_msg_mutex);
	return (0);
}

/*
 * Mark the value as deleted.
 */
int
sip_delete_value(sip_header_t sip_header, sip_header_value_t sip_header_value)
{
	_sip_header_t	*_sip_header;
	sip_value_t	*_sip_header_value;
	int		vlen;
	char		*c;

	if (sip_header == NULL || sip_header_value == NULL)
		return (EINVAL);
	_sip_header = (_sip_header_t *)sip_header;
	(void) pthread_mutex_lock(&_sip_header->sip_hdr_sipmsg->sip_msg_mutex);
	if (_sip_header->sip_hdr_sipmsg->sip_msg_cannot_be_modified) {
		(void) pthread_mutex_unlock(&_sip_header->
		    sip_hdr_sipmsg->sip_msg_mutex);
		return (EPERM);
	}
	if (_sip_header->sip_header_state == SIP_HEADER_DELETED) {
		(void) pthread_mutex_unlock(
		    &_sip_header->sip_hdr_sipmsg->sip_msg_mutex);
		return (EINVAL);
	}
	_sip_header_value = (sip_value_t *)sip_header_value;
	if (_sip_header_value->value_state == SIP_VALUE_DELETED) {
		(void) pthread_mutex_unlock(
		    &_sip_header->sip_hdr_sipmsg->sip_msg_mutex);
		return (EINVAL);
	}
	_sip_header->sip_header_state = SIP_HEADER_DELETED_VAL;
	_sip_header_value->value_state = SIP_VALUE_DELETED;
	vlen = _sip_header_value->value_end - _sip_header_value->value_start;
	if (_sip_header->sip_hdr_parsed->value == _sip_header_value) {
		c = _sip_header_value->value_start;
		while (*c-- != SIP_HCOLON)
			vlen++;
	} else {
		c = _sip_header_value->value_start;
		while (*c-- != SIP_COMMA)
			vlen++;
	}
	if (_sip_header_value->next == NULL) {
		sip_value_t	*value = _sip_header->sip_hdr_parsed->value;
		boolean_t	crlf_present =  B_FALSE;
		char		*s;

		while (value != NULL && value != _sip_header_value) {
			crlf_present = B_FALSE;

			if (value->value_state == SIP_VALUE_DELETED) {
				value = value->next;
				continue;
			}
			s = value->value_end;
			while (s != value->value_start) {
				if (*s == '\r' && strncmp(s, SIP_CRLF,
				    strlen(SIP_CRLF)) == 0) {
					crlf_present = B_TRUE;
					break;
				}
				s--;
			}
			value = value->next;
		}
		if (!crlf_present) {
			c = _sip_header_value->value_end;
			while (*c-- != '\r')
				vlen--;
			assert(vlen > 0);
		}
	}
	_sip_header->sip_hdr_sipmsg->sip_msg_len -= vlen;
	if (_sip_header->sip_hdr_sipmsg->sip_msg_buf != NULL)
		_sip_header->sip_hdr_sipmsg->sip_msg_modified = B_TRUE;
	(void) pthread_mutex_unlock
	    (&_sip_header->sip_hdr_sipmsg->sip_msg_mutex);
	return (0);
}

/*
 * Given a param list, check if a param name exists.
 */
boolean_t
sip_is_param_present(const sip_param_t *param_list, char *param_name,
    int param_len)
{
	const sip_param_t	*param = param_list;

	while (param != NULL) {
		if (param->param_name.sip_str_len == param_len &&
		    strncasecmp(param->param_name.sip_str_ptr, param_name,
			param_len) == 0) {
			return (B_TRUE);
		}
		param = param->param_next;
	}
	return (B_FALSE);
}


/*
 * Given a value header return the value of the named param.
 */
const sip_str_t *
sip_get_param_value(sip_header_value_t header_value, char *param_name,
    int *error)
{
	sip_value_t	*_sip_header_value;
	sip_param_t	*sip_param;

	if (error != NULL)
		*error = 0;
	if (header_value == NULL || param_name == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	_sip_header_value = (sip_value_t *)header_value;
	if (_sip_header_value->value_state == SIP_VALUE_DELETED) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	if (_sip_header_value->param_list == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	sip_param = sip_get_param_from_list(_sip_header_value->param_list,
	    param_name);
	if (sip_param != NULL)
		return (&sip_param->param_value);
	return (NULL);
}

/*
 * Return the list of params in the header
 */
const sip_param_t *
sip_get_params(sip_header_value_t header_value, int *error)
{
	sip_value_t	*sip_header_value;

	if (error != NULL)
		*error = 0;
	if (header_value == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	sip_header_value = (sip_value_t *)header_value;
	if (sip_header_value->value_state == SIP_VALUE_DELETED) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	return (sip_header_value->param_list);
}

/*
 * Return true if this is a SIP request
 */
boolean_t
sip_msg_is_request(sip_msg_t sip_msg, int *error)
{
	_sip_msg_t		*_sip_msg;
	sip_message_type_t	*sip_msg_info;
	boolean_t		ret;

	if (error != NULL)
		*error = 0;
	if (sip_msg == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (B_FALSE);
	}
	_sip_msg = (_sip_msg_t *)sip_msg;
	(void) pthread_mutex_lock(&_sip_msg->sip_msg_mutex);
	if (_sip_msg->sip_msg_req_res == NULL) {
		(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
		if (error != NULL)
			*error = EINVAL;
		return (B_FALSE);
	}
	sip_msg_info = _sip_msg->sip_msg_req_res;
	ret = sip_msg_info->is_request;
	(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
	return (ret);
}

/*
 * Return true if this is a SIP response
 */
boolean_t
sip_msg_is_response(sip_msg_t sip_msg, int *error)
{
	boolean_t		is_resp;
	_sip_msg_t		*_sip_msg;
	sip_message_type_t	*sip_msg_info;

	if (error != NULL)
		*error = 0;
	if (sip_msg == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (B_FALSE);
	}
	_sip_msg = (_sip_msg_t *)sip_msg;
	(void) pthread_mutex_lock(&_sip_msg->sip_msg_mutex);
	if (_sip_msg->sip_msg_req_res == NULL) {
		(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
		if (error != NULL)
			*error = EINVAL;
		return (B_FALSE);
	}
	sip_msg_info = _sip_msg->sip_msg_req_res;
	is_resp = !sip_msg_info->is_request;
	(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
	return (is_resp);
}

/*
 * Return the method in the request line
 */
sip_method_t
sip_get_request_method(sip_msg_t sip_msg, int *error)
{
	_sip_msg_t		*_sip_msg;
	sip_message_type_t	*sip_msg_info;
	sip_method_t 		ret = -1;

	if (error != NULL)
		*error = 0;
	if (sip_msg == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (ret);
	}
	_sip_msg = (_sip_msg_t *)sip_msg;
	(void) pthread_mutex_lock(&_sip_msg->sip_msg_mutex);
	sip_msg_info = _sip_msg->sip_msg_req_res;
	if (_sip_msg->sip_msg_req_res == NULL) {
		(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
		if (error != NULL)
			*error = EINVAL;
		return (ret);
	}
	if (sip_msg_info->is_request)
		ret = sip_msg_info->sip_req_method;
	else if (error != NULL)
		*error = EINVAL;
	(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
	return (ret);
}

/*
 * Return the URI from the request line
 */
const sip_str_t *
sip_get_request_uri_str(sip_msg_t sip_msg, int *error)
{
	_sip_msg_t		*_sip_msg;
	sip_message_type_t	*sip_msg_info;
	sip_str_t 		*ret = NULL;
	struct sip_uri		*parsed_uri;

	if (error != NULL)
		*error = 0;
	if (sip_msg == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	_sip_msg = (_sip_msg_t *)sip_msg;
	(void) pthread_mutex_lock(&_sip_msg->sip_msg_mutex);
	if (_sip_msg->sip_msg_req_res == NULL) {
		(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	sip_msg_info = _sip_msg->sip_msg_req_res;
	if (sip_msg_info->is_request)
		ret = &sip_msg_info->sip_req_uri;
	(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);

	/*
	 * If the error is required, check the validity of the URI via
	 * sip_uri_parse().
	 */
	if (error != NULL) {
		parsed_uri = sip_parse_uri(ret, error);
		if (parsed_uri != NULL)
			sip_free_parsed_uri((sip_uri_t)parsed_uri);
	}
	return (ret);
}

/*
 * Return the response code
 */
int
sip_get_response_code(sip_msg_t sip_msg, int *error)
{
	_sip_msg_t		*_sip_msg;
	sip_message_type_t	*sip_msg_info;
	int 			ret = -1;

	if (error != NULL)
		*error = 0;
	if (sip_msg == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (ret);
	}
	_sip_msg = (_sip_msg_t *)sip_msg;
	(void) pthread_mutex_lock(&_sip_msg->sip_msg_mutex);
	if (_sip_msg->sip_msg_req_res == NULL) {
		(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
		if (error != NULL)
			*error = EINVAL;
		return (ret);
	}
	sip_msg_info = _sip_msg->sip_msg_req_res;
	if (!sip_msg_info->is_request)
		ret = sip_msg_info->sip_resp_code;
	else if (error != NULL)
		*error = EINVAL;
	(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
	return (ret);
}

/*
 * Get the response phrase
 */
const sip_str_t *
sip_get_response_phrase(sip_msg_t sip_msg, int *error)
{
	_sip_msg_t		*_sip_msg;
	sip_message_type_t	*sip_msg_info;
	sip_str_t 		*ret = NULL;

	if (error != NULL)
		*error = 0;
	if (sip_msg == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (ret);
	}
	_sip_msg = (_sip_msg_t *)sip_msg;
	(void) pthread_mutex_lock(&_sip_msg->sip_msg_mutex);
	if (_sip_msg->sip_msg_req_res == NULL) {
		(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
		if (error != NULL)
			*error = EINVAL;
		return (ret);
	}
	sip_msg_info = _sip_msg->sip_msg_req_res;
	(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
	if (!sip_msg_info->is_request) {
		if (sip_msg_info->sip_resp_phrase_len == 0)
			ret = NULL;
		else
			ret = &sip_msg_info->sip_resp_phrase;
	} else if (error != NULL) {
		*error = EINVAL;
	}
	return (ret);
}

/*
 * Get the SIP version string
 */
const sip_str_t *
sip_get_sip_version(sip_msg_t sip_msg, int *error)
{
	_sip_msg_t		*_sip_msg;
	sip_message_type_t	*sip_msg_info;
	sip_str_t		*ret = NULL;

	if (error != NULL)
		*error = 0;
	if (sip_msg == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (ret);
	}
	_sip_msg = (_sip_msg_t *)sip_msg;
	(void) pthread_mutex_lock(&_sip_msg->sip_msg_mutex);
	if (_sip_msg->sip_msg_req_res == NULL) {
		(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
		if (error != NULL)
			*error = EINVAL;
		return (ret);
	}
	sip_msg_info = _sip_msg->sip_msg_req_res;
	(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
	ret = &sip_msg_info->sip_proto_version.version;
	return (ret);
}

/*
 * Return the length of the SIP message
 */
int
sip_get_msg_len(sip_msg_t sip_msg, int *error)
{
	_sip_msg_t	*_sip_msg;

	if (error != NULL)
		*error = 0;
	if (sip_msg == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (-1);
	}
	_sip_msg = (_sip_msg_t *)sip_msg;

	return (_sip_msg->sip_msg_len);
}

/*
 * Get content as a string. Caller frees the string
 */
char *
sip_get_content(sip_msg_t sip_msg, int *error)
{
	_sip_msg_t	*_sip_msg;
	sip_content_t	*sip_content;
	char		*content;
	int		len;
	char		*p;

	if (error != NULL)
		*error = 0;

	if (sip_msg == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	_sip_msg = (_sip_msg_t *)sip_msg;
	(void) pthread_mutex_lock(&_sip_msg->sip_msg_mutex);
	if (_sip_msg->sip_msg_content == NULL) {
		(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	content = malloc(_sip_msg->sip_msg_content_len + 1);
	if (content == NULL) {
		(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
		if (error != NULL)
			*error = ENOMEM;
		return (NULL);
	}
	p = content;
	sip_content = _sip_msg->sip_msg_content;
	while (sip_content != NULL) {
		len =  sip_content->sip_content_end -
		    sip_content->sip_content_start;
		(void) strncpy(p, sip_content->sip_content_start, len);
		p += len;
		sip_content = sip_content->sip_content_next;
	}
	content[_sip_msg->sip_msg_content_len] = '\0';
	(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
	return (content);
}

/*
 * copy sip_header with param, if any, to sip_msg
 */
int
sip_copy_header(sip_msg_t sip_msg, sip_header_t sip_header, char *param)
{
	_sip_msg_t	*_sip_msg;
	_sip_header_t	*_sip_header;
	int		ret;

	if (sip_msg == NULL || sip_header == NULL)
		return (EINVAL);
	_sip_msg = (_sip_msg_t *)sip_msg;
	_sip_header = (_sip_header_t *)sip_header;
	(void) pthread_mutex_lock(&_sip_msg->sip_msg_mutex);
	if (_sip_msg->sip_msg_cannot_be_modified) {
		(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
		return (EPERM);
	}
	if (_sip_header->sip_header_state == SIP_HEADER_DELETED) {
		(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
		return (EINVAL);
	}

	ret = _sip_copy_header(_sip_msg, _sip_header, param, B_TRUE);
	if (_sip_msg->sip_msg_buf != NULL)
		_sip_msg->sip_msg_modified = B_TRUE;
	(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
	return (ret);
}

/*
 * copy the header specified by header_name, with param, if any
 */
int
sip_copy_header_by_name(sip_msg_t old_msg, sip_msg_t new_msg,
    char *header_name, char *param)
{
	int		ret;
	_sip_msg_t	*_old_msg = (_sip_msg_t *)old_msg;
	_sip_msg_t	*_new_msg = (_sip_msg_t *)new_msg;

	if (_old_msg == NULL || _new_msg == NULL || header_name == NULL ||
	    _old_msg == _new_msg) {
		return (EINVAL);
	}
	(void) pthread_mutex_lock(&_new_msg->sip_msg_mutex);
	if (_new_msg->sip_msg_cannot_be_modified) {
		(void) pthread_mutex_unlock(&_new_msg->sip_msg_mutex);
		return (EPERM);
	}

	(void) pthread_mutex_lock(&_old_msg->sip_msg_mutex);
	ret = _sip_find_and_copy_header(_old_msg, _new_msg, header_name, param,
	    B_FALSE);
	(void) pthread_mutex_unlock(&_old_msg->sip_msg_mutex);
	if (_new_msg->sip_msg_buf != NULL)
		_new_msg->sip_msg_modified = B_TRUE;
	(void) pthread_mutex_unlock(&_new_msg->sip_msg_mutex);
	return (ret);
}

/*
 * add the given header to sip_message
 */
int
sip_add_header(sip_msg_t sip_msg, char *header_string)
{
	int		header_size;
	_sip_header_t	*new_header;
	_sip_msg_t	*_sip_msg;

	if (sip_msg == NULL || header_string == NULL)
		return (EINVAL);
	_sip_msg = (_sip_msg_t *)sip_msg;
	(void) pthread_mutex_lock(&_sip_msg->sip_msg_mutex);
	if (_sip_msg->sip_msg_cannot_be_modified) {
		(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
		return (EPERM);
	}
	header_size = strlen(header_string) + strlen(SIP_CRLF);
	new_header = sip_new_header(header_size);
	if (new_header == NULL) {
		(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
		return (ENOMEM);
	}

	(void) snprintf(new_header->sip_hdr_start, header_size + 1, "%s%s",
	    header_string, SIP_CRLF);
	_sip_add_header(_sip_msg, new_header, B_TRUE, B_FALSE, NULL);
	if (_sip_msg->sip_msg_buf != NULL)
		_sip_msg->sip_msg_modified = B_TRUE;
	(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
	return (0);
}

/*
 * add the given param to the sip_header. create a new header with the param
 * and mark the old header as deleted.
 */
sip_header_t
sip_add_param(sip_header_t sip_header, char *param, int *error)
{
	_sip_header_t	*_sip_header;
	_sip_header_t	*new_header;
	int		hdrlen;
	_sip_msg_t	*_sip_msg;
	int		param_len;
	char		*tmp_ptr;

	if (error != NULL)
		*error = 0;

	if (param == NULL || sip_header == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}

	_sip_header = (_sip_header_t *)sip_header;

	(void) pthread_mutex_lock(&_sip_header->sip_hdr_sipmsg->sip_msg_mutex);
	if (_sip_header->sip_hdr_sipmsg->sip_msg_cannot_be_modified) {
		if (error != NULL)
			*error = EPERM;
		(void) pthread_mutex_unlock(
		    &_sip_header->sip_hdr_sipmsg->sip_msg_mutex);
		return (NULL);
	}
	if (_sip_header->sip_header_state == SIP_HEADER_DELETED) {
		if (error != NULL)
			*error = EINVAL;
		(void) pthread_mutex_unlock(
		    &_sip_header->sip_hdr_sipmsg->sip_msg_mutex);
		return (NULL);
	}

	param_len = SIP_SPACE_LEN + sizeof (char) + SIP_SPACE_LEN +
	    strlen(param);
	hdrlen = _sip_header->sip_hdr_end - _sip_header->sip_hdr_start;
	new_header = sip_new_header(hdrlen + param_len);
	if (new_header == NULL) {
		if (error != NULL)
			*error = ENOMEM;
		(void) pthread_mutex_unlock(
		    &_sip_header->sip_hdr_sipmsg->sip_msg_mutex);
		return (NULL);
	}
	(void) memcpy(new_header->sip_hdr_start, _sip_header->sip_hdr_start,
	    hdrlen);
	new_header->sip_hdr_end = new_header->sip_hdr_start + hdrlen;
	hdrlen = param_len + 1;
	/*
	 * Find CRLF
	 */
	tmp_ptr = new_header->sip_hdr_end;
	while (*tmp_ptr-- != '\n') {
		hdrlen++;
		if (tmp_ptr == new_header->sip_hdr_start) {
			sip_free_header(new_header);
			if (error != NULL)
				*error = EINVAL;
			(void) pthread_mutex_unlock(
			    &_sip_header->sip_hdr_sipmsg->sip_msg_mutex);
			return (NULL);
		}
	}
	(void) snprintf(tmp_ptr, hdrlen + 1,
	    " %c %s%s", SIP_SEMI, param, SIP_CRLF);
	new_header->sip_hdr_end += param_len;
	new_header->sip_header_functions = _sip_header->sip_header_functions;
	_sip_msg = _sip_header->sip_hdr_sipmsg;
	_sip_add_header(_sip_msg, new_header, B_TRUE, B_FALSE, NULL);
	if (_sip_header->sip_hdr_sipmsg->sip_msg_buf != NULL)
		_sip_header->sip_hdr_sipmsg->sip_msg_modified = B_TRUE;
	(void) pthread_mutex_unlock(&new_header->sip_hdr_sipmsg->sip_msg_mutex);
	(void) sip_delete_header(sip_header);
	return ((sip_header_t)new_header);
}

/*
 * Get Request URI
 */
const struct sip_uri *
sip_get_request_uri(sip_msg_t sip_msg, int *error)
{
	_sip_msg_t		*_sip_msg;
	sip_message_type_t	*sip_msg_info;
	const struct sip_uri	*ret = NULL;

	if (error != NULL)
		*error = 0;

	if (sip_msg == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	_sip_msg = (_sip_msg_t *)sip_msg;
	(void) pthread_mutex_lock(&_sip_msg->sip_msg_mutex);
	sip_msg_info = _sip_msg->sip_msg_req_res;
	if (sip_msg_info != NULL && sip_msg_info->is_request) {
		ret = sip_msg_info->sip_req_parse_uri;
	} else {
		if (error != NULL)
			*error = EINVAL;
	}
	(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);

	if (ret != NULL) {
		if (ret->sip_uri_scheme.sip_str_len == 0 ||
		    ret->sip_uri_scheme.sip_str_ptr == NULL) {
			ret = NULL;
			if (error != NULL)
				*error = EINVAL;
		} else if (ret->sip_uri_errflags != 0 && error != NULL) {
			*error = EINVAL;
		}
	}
	return ((sip_uri_t)ret);
}

/*
 * returns a comma separated string of all the sent-by values registered by
 * the UA.
 */
char *
sip_sent_by_to_str(int *error)
{
	sent_by_list_t	*sb;
	int		sb_len = 0;
	int		slen;
	char		*sb_str;
	char		*p;
	int		count = 0;
	int		cnt = 0;

	if (error != NULL)
		*error = 0;

	(void) pthread_mutex_lock(&sip_sent_by_lock);
	if (sip_sent_by == NULL) {
		(void) pthread_mutex_unlock(&sip_sent_by_lock);
		return (NULL);
	}
	sb = sip_sent_by;
	for (cnt = 0; cnt < sip_sent_by_count; cnt++) {
		sb_len += strlen(sb->sb_val);
		sb = sb->sb_next;
	}
	/*
	 * for the commas
	 */
	sb_len += sip_sent_by_count - 1;
	sb_str = malloc(sb_len + 1);
	if (sb_str == NULL) {
		if (error != NULL)
			*error = ENOMEM;
		(void) pthread_mutex_unlock(&sip_sent_by_lock);
		return (NULL);
	}
	sb = sip_sent_by;
	p = sb_str;
	slen = sb_len + 1;
	for (cnt = 0; cnt < sip_sent_by_count; cnt++) {
		if (cnt == 0) {
			count = snprintf(p, slen, "%s", sb->sb_val);
		} else {
			count = snprintf(p, slen, "%c%s", SIP_COMMA,
			    sb->sb_val);
		}
		p += count;
		slen -= count;
		sb = sb->sb_next;
	}
	sb_str[sb_len] = '\0';
	(void) pthread_mutex_unlock(&sip_sent_by_lock);
	return (sb_str);
}

/*
 * A comma separated list of sent-by values.
 */
int
sip_register_sent_by(char *val)
{
	sent_by_list_t	*sb = NULL;
	sent_by_list_t	*sb_tail = NULL;
	char		*str;
	int		count = 0;

	if (val == NULL)
		return (EINVAL);
	str = strtok(val, ",");
	while (str != NULL) {
		int	slen;
		char	*start = str;
		char	*end = str + strlen(str) - 1;

		while (isspace(*start))
			start++;
		while (isspace(*end))
			end--;
		if (end <= start)
			goto err_ret;
		slen = end - start + 1;
		sb_tail = (sent_by_list_t *)malloc(sizeof (*sb_tail));
		if (sb_tail == NULL)
			goto err_ret;
		sb_tail->sb_next = sb_tail->sb_prev = NULL;
		if ((sb_tail->sb_val = (char *)malloc(slen + 1)) == NULL) {
			free(sb_tail);
			goto err_ret;
		}
		(void) strncpy(sb_tail->sb_val, start, slen);
		sb_tail->sb_val[slen] = '\0';
		if (sb == NULL) {
			sb = sb_tail;
		} else {
			sb_tail->sb_next = sb;
			sb->sb_prev = sb_tail;
			sb = sb_tail;
		}
		count++;
		str = strtok(NULL, ",");
	}
	sb_tail = sb;
	while (sb_tail->sb_next != NULL)
		sb_tail = sb_tail->sb_next;
	(void) pthread_mutex_lock(&sip_sent_by_lock);
	if (sip_sent_by != NULL) {
		sb_tail->sb_next = sip_sent_by;
		sip_sent_by->sb_prev = sb_tail;
	}
	sip_sent_by = sb;
	sip_sent_by_count += count;
	(void) pthread_mutex_unlock(&sip_sent_by_lock);
	return (0);
err_ret:
	sb_tail = sb;
	for (; count > 0; count--) {
		sb = sb_tail->sb_next;
		free(sb_tail->sb_val);
		sb_tail->sb_next = NULL;
		sb_tail->sb_prev = NULL;
		free(sb_tail);
		sb_tail = sb;
	}
	return (EINVAL);
}

/*
 * Un-register sent-by values; 'val' contains a comma separated list
 */
void
sip_unregister_sent_by(char *val)
{
	sent_by_list_t	*sb;
	char		*str;
	int		count = 0;

	(void) pthread_mutex_lock(&sip_sent_by_lock);
	str = strtok(val, ",");
	while (str != NULL) {
		sb = sip_sent_by;
		for (count = 0; count < sip_sent_by_count; count++) {
			if (strncmp(sb->sb_val, str, strlen(str)) == 0) {
				if (sb == sip_sent_by) {
					if (sb->sb_next != NULL)
						sip_sent_by = sb->sb_next;
					else
						sip_sent_by = NULL;
				} else if (sb->sb_next == NULL) {
					sb->sb_prev->sb_next = NULL;
				} else {
					sb->sb_prev->sb_next = sb->sb_next;
					sb->sb_next->sb_prev = sb->sb_prev;
				}
				sip_sent_by_count--;
				sb->sb_next = NULL;
				sb->sb_prev = NULL;
				free(sb->sb_val);
				free(sb);
				break;
			}
			sb = sb->sb_next;
		}
		str = strtok(NULL, ",");
	}
	(void) pthread_mutex_unlock(&sip_sent_by_lock);
}

/*
 * Un-register all the sent-by values
 */
void
sip_unregister_all_sent_by()
{
	sent_by_list_t	*sb;
	int		count;

	(void) pthread_mutex_lock(&sip_sent_by_lock);
	sb = sip_sent_by;
	for (count = 0; count < sip_sent_by_count; count++) {
		sip_sent_by = sb->sb_next;
		free(sb->sb_val);
		sb->sb_next = NULL;
		sb->sb_prev = NULL;
		free(sb);
		sb = sip_sent_by;
	}
	sip_sent_by = NULL;
	sip_sent_by_count = 0;
	(void) pthread_mutex_unlock(&sip_sent_by_lock);
}

/*
 * Given a response code, return the corresponding phrase
 */
char *
sip_get_resp_desc(int resp_code)
{
	switch (resp_code) {
	case SIP_TRYING:
		return ("TRYING");
	case SIP_RINGING:
		return ("RINGING");
	case SIP_CALL_IS_BEING_FORWARDED:
		return ("CALL_IS_BEING_FORWARDED");
	case SIP_QUEUED:
		return ("QUEUED");
	case SIP_SESSION_PROGRESS:
		return ("SESSION_PROGRESS");
	case SIP_OK:
		return ("OK");
	case SIP_ACCEPTED:
		return ("ACCEPTED");
	case SIP_MULTIPLE_CHOICES:
		return ("MULTIPLE_CHOICES");
	case SIP_MOVED_PERMANENTLY:
		return ("MOVED_PERMANENTLY");
	case SIP_MOVED_TEMPORARILY:
		return ("MOVED_TEMPORARILY");
	case SIP_USE_PROXY:
		return ("USE_PROXY");
	case SIP_ALTERNATIVE_SERVICE:
		return ("ALTERNATIVE_SERVICE");
	case SIP_BAD_REQUEST:
		return ("BAD_REQUEST");
	case SIP_UNAUTHORIZED:
		return ("UNAUTHORIZED");
	case SIP_PAYMENT_REQUIRED:
		return ("PAYMENT_REQUIRED");
	case SIP_FORBIDDEN:
		return ("FORBIDDEN");
	case SIP_NOT_FOUND:
		return ("NOT_FOUND");
	case SIP_METHOD_NOT_ALLOWED:
		return ("METHOD_NOT_ALLOWED");
	case SIP_NOT_ACCEPTABLE:
		return ("NOT_ACCEPTABLE");
	case SIP_PROXY_AUTH_REQUIRED:
		return ("PROXY_AUTH_REQUIRED");
	case SIP_REQUEST_TIMEOUT:
		return ("REQUEST_TIMEOUT");
	case SIP_GONE:
		return ("GONE");
	case SIP_REQUEST_ENTITY_2_LARGE:
		return ("REQUEST_ENTITY_2_LARGE");
	case SIP_REQUEST_URI_2_LONG:
		return ("REQUEST_URI_2_LONG");
	case SIP_UNSUPPORTED_MEDIA_TYPE:
		return ("UNSUPPORTED_MEDIA_TYPE");
	case SIP_UNSUPPORTED_URI_SCHEME:
		return ("UNSUPPORTED_URI_SCHEME");
	case SIP_BAD_EXTENSION:
		return ("BAD_EXTENSION");
	case SIP_EXTENSION_REQUIRED:
		return ("EXTENSION_REQUIRED");
	case SIP_INTERVAL_2_BRIEF:
		return ("INTERVAL_2_BRIEF");
	case SIP_TEMPORARILY_UNAVAIL:
		return ("TEMPORARILY_UNAVAIL");
	case SIP_CALL_NON_EXISTANT:
		return ("CALL_NON_EXISTANT");
	case SIP_LOOP_DETECTED:
		return ("LOOP_DETECTED");
	case SIP_TOO_MANY_HOOPS:
		return ("TOO_MANY_HOOPS");
	case SIP_ADDRESS_INCOMPLETE:
		return ("ADDRESS_INCOMPLETE");
	case SIP_AMBIGUOUS:
		return ("AMBIGUOUS");
	case SIP_BUSY_HERE:
		return ("BUSY_HERE");
	case SIP_REQUEST_TERMINATED:
		return ("REQUEST_TERMINATED");
	case SIP_NOT_ACCEPTABLE_HERE:
		return ("NOT_ACCEPTABLE_HERE");
	case SIP_BAD_EVENT:
		return ("BAD_EVENT");
	case SIP_REQUEST_PENDING:
		return ("REQUEST_PENDING");
	case SIP_UNDECIPHERABLE:
		return ("UNDECIPHERABLE");
	case SIP_SERVER_INTERNAL_ERROR:
		return ("SERVER_INTERNAL_ERROR");
	case SIP_NOT_IMPLEMENTED:
		return ("NOT_IMPLEMENTED");
	case SIP_BAD_GATEWAY:
		return ("BAD_GATEWAY");
	case SIP_SERVICE_UNAVAILABLE:
		return ("SERVICE_UNAVAILABLE");
	case SIP_SERVER_TIMEOUT:
		return ("SERVER_TIMEOUT");
	case SIP_VERSION_NOT_SUPPORTED:
		return ("VERSION_NOT_SUPPORTED");
	case SIP_MESSAGE_2_LARGE:
		return ("MESSAGE_2_LARGE");
	case SIP_BUSY_EVERYWHERE:
		return ("BUSY_EVERYWHERE");
	case SIP_DECLINE:
		return ("DECLINE");
	case SIP_DOES_NOT_EXIST_ANYWHERE:
		return ("DOES_NOT_EXIST_ANYWHERE");
	case SIP_NOT_ACCEPTABLE_ANYWHERE:
		return ("NOT_ACCEPTABLE_ANYWHERE");
	default:
		return ("UNKNOWN");
	}
}

/*
 * The following three fns initialize and destroy the private library
 * data in sip_conn_object_t. The assumption is that the 1st member
 * of sip_conn_object_t is reserved for library use. The private data
 * is used only for byte-stream protocols such as TCP to accumulate
 * a complete SIP message, based on the CONTENT-LENGTH value, before
 * processing it.
 */
int
sip_init_conn_object(sip_conn_object_t obj)
{
	void			**obj_val;
	sip_conn_obj_pvt_t	*pvt_data;

	if (obj == NULL)
		return (EINVAL);
	pvt_data =  malloc(sizeof (sip_conn_obj_pvt_t));
	if (pvt_data == NULL)
		return (ENOMEM);
	pvt_data->sip_conn_obj_cache = NULL;
	pvt_data->sip_conn_obj_reass = malloc(sizeof (sip_reass_entry_t));
	if (pvt_data->sip_conn_obj_reass == NULL) {
		free(pvt_data);
		return (ENOMEM);
	}
	bzero(pvt_data->sip_conn_obj_reass, sizeof (sip_reass_entry_t));
	(void) pthread_mutex_init(&pvt_data->sip_conn_obj_reass_lock, NULL);
	(void) pthread_mutex_init(&pvt_data->sip_conn_obj_cache_lock, NULL);
	sip_refhold_conn(obj);
	obj_val = (void *)obj;
	*obj_val = (void *)pvt_data;

	return (0);
}

/*
 * Clear private date, if any
 */
void
sip_clear_stale_data(sip_conn_object_t obj)
{
	void			**obj_val;
	sip_conn_obj_pvt_t	*pvt_data;
	sip_reass_entry_t	*reass;

	if (obj == NULL)
		return;
	obj_val = (void *)obj;
	pvt_data = (sip_conn_obj_pvt_t *)*obj_val;
	(void) pthread_mutex_lock(&pvt_data->sip_conn_obj_reass_lock);
	reass = pvt_data->sip_conn_obj_reass;
	if (reass->sip_reass_msg != NULL) {
		assert(reass->sip_reass_msglen > 0);
		free(reass->sip_reass_msg);
		reass->sip_reass_msglen = 0;
	}
	assert(reass->sip_reass_msglen == 0);
	(void) pthread_mutex_unlock(&pvt_data->sip_conn_obj_reass_lock);
}

/*
 * Walk through all the transactions, remove if this obj has been cached
 * by any.
 */
void
sip_conn_destroyed(sip_conn_object_t obj)
{
	void			**obj_val;
	sip_conn_obj_pvt_t	*pvt_data;

	if (obj == NULL)
		return;
	obj_val = (void *)obj;
	pvt_data = (sip_conn_obj_pvt_t *)*obj_val;

	sip_clear_stale_data(obj);
	free(pvt_data->sip_conn_obj_reass);
	pvt_data->sip_conn_obj_reass = NULL;
	(void) pthread_mutex_destroy(&pvt_data->sip_conn_obj_reass_lock);

	sip_del_conn_obj_cache(obj, NULL);
	(void) pthread_mutex_destroy(&pvt_data->sip_conn_obj_cache_lock);

	free(pvt_data);
	*obj_val = NULL;
	sip_refrele_conn(obj);
}
