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

#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sip.h>

#include "sip_msg.h"
#include "sip_miscdefs.h"
#include "sip_parse_generic.h"

sip_methods_t sip_methods[MAX_SIP_METHODS] = {
	{"UNKNOWN", 7},
	{"INVITE", 6},
	{"ACK", 3},
	{"OPTIONS", 7},
	{"BYE", 3},
	{"CANCEL", 6},
	{"REGISTER", 8},
	{"REFER", 5},
	{"INFO", 4},
	{"SUBSCRIBE", 9},
	{"NOTIFY", 6},
	{"PRACK", 5}
};

/*
 * Built-In Header function table
 */
sip_header_function_t sip_header_function_table[] = {
	{"Unknown", NULL, sip_parse_unknown_header, NULL, NULL, NULL},
	{"CONTACT", "m", sip_parse_cftr_header, NULL, NULL,
	sip_free_cftr_header},
	{"FROM", "F", sip_parse_cftr_header, NULL, NULL, sip_free_cftr_header},
	{"TO", "T", sip_parse_cftr_header, NULL, NULL, sip_free_cftr_header},
	{"CONTENT-LENGTH", "l", sip_parse_clen_header, NULL, NULL,
	sip_free_phdr},
	{"CONTENT-TYPE", "c", sip_parse_ctype_header, NULL, NULL,
	sip_free_phdr},
	{"CALL-ID", "i", sip_parse_cid_header, NULL, NULL, sip_free_phdr},
	{"CSEQ", NULL, sip_parse_cseq_header, NULL, NULL, sip_free_phdr},
	{"VIA", "v", sip_parse_via_header, NULL, NULL, sip_free_phdr},
	{"Max-Forwards", NULL, sip_parse_maxf_header, NULL, NULL,
	sip_free_phdr},
	{"RECORD-ROUTE", NULL, sip_parse_cftr_header, NULL, NULL,
	sip_free_cftr_header},
	{"ROUTE", NULL, sip_parse_cftr_header, NULL, NULL,
	sip_free_cftr_header},
	{"ACCEPT", NULL, sip_parse_acpt_header, NULL, NULL, sip_free_phdr},
	{"ACCEPT-ENCODING", NULL, sip_parse_acpt_encode_header, NULL, NULL,
	sip_free_phdr},
	{"ACCEPT-LANGUAGE", NULL, sip_parse_acpt_lang_header, NULL, NULL,
	sip_free_phdr},
	{"ALERT-INFO", NULL, sip_parse_alert_header, NULL, NULL, sip_free_phdr},
	{"ALLOW", NULL, sip_parse_allow_header, NULL, NULL, sip_free_phdr},
	{"CALL-INFO", NULL, sip_parse_callinfo_header, NULL, NULL,
	sip_free_phdr},
	{"CONTENT-DISPOSITION", NULL, sip_parse_contentdis_header, NULL, NULL,
	sip_free_phdr},
	{"CONTENT-ENCODING", "e", sip_parse_contentencode_header, NULL, NULL,
	sip_free_phdr},
	{"CONTENT-LANGUAGE", NULL, sip_parse_contentlang_header, NULL, NULL,
	sip_free_phdr},
	{"DATE", NULL, sip_parse_date_header, NULL, NULL, sip_free_phdr},
	{"ERROR-INFO", NULL, sip_parse_errorinfo_header, NULL, NULL,
	sip_free_phdr},
	{"EXPIRES", NULL, sip_parse_expire_header, NULL, NULL, sip_free_phdr},
	{"IN-REPLY-TO", NULL, sip_parse_inreplyto_header, NULL, NULL,
	sip_free_phdr},
	{"MIN-EXPIRES", NULL, sip_parse_minexpire_header, NULL, NULL,
	sip_free_phdr},
	{"MIME-VERSION", NULL, sip_parse_mimeversion_header, NULL, NULL,
	sip_free_phdr},
	{"ORGANIZATION", NULL, sip_parse_org_header, NULL, NULL, sip_free_phdr},
	{"PRIORITY", NULL, sip_parse_priority_header, NULL, NULL,
	sip_free_phdr},
	{"REQUIRE", NULL, sip_parse_require_header, NULL, NULL, sip_free_phdr},
	{"REPLY-TO", NULL, sip_parse_replyto_header, NULL, NULL, sip_free_phdr},
	{"RETRY-AFTER", NULL, sip_parse_retryaft_header, NULL, NULL,
	sip_free_phdr},
	{"SERVER", NULL, sip_parse_server_header, NULL, NULL, sip_free_phdr},
	{"SUBJECT", "s", sip_parse_subject_header, NULL, NULL, sip_free_phdr},
	{"TIMESTAMP", NULL, sip_parse_timestamp_header, NULL, NULL,
	sip_free_phdr},
	{"UNSUPPORTED", NULL, sip_parse_usupport_header, NULL, NULL,
	sip_free_phdr},
	{"SUPPORTED", "k", sip_parse_support_header, NULL, NULL, sip_free_phdr},
	{"USER-AGENT", NULL, sip_parse_useragt_header, NULL, NULL,
	sip_free_phdr},
	{"WARNING", NULL, sip_parse_warn_header, NULL, NULL, sip_free_phdr},
	{"ALLOW-EVENTS", "u", sip_parse_allow_events_header, NULL, NULL,
	sip_free_phdr},
	{"EVENT", "o", sip_parse_event_header, NULL, NULL, sip_free_phdr},
	{"SUBSCRIPTION-STATE", NULL, sip_parse_substate_header, NULL, NULL,
	sip_free_phdr},
	{"AUTHORIZATION", NULL, sip_parse_author_header, NULL, NULL,
	sip_free_phdr},
	{"AUTHENTICATION-INFO", NULL, sip_parse_ainfo_header, NULL, NULL,
	sip_free_phdr},
	{"PROXY-AUTHORIZATION", NULL, sip_parse_pauthor_header, NULL, NULL,
	sip_free_phdr},
	{"PROXY-AUTHENTICATE", NULL, sip_parse_pauthen_header, NULL, NULL,
	sip_free_phdr},
	{"PROXY-REQUIRE", NULL, sip_parse_preq_header, NULL, NULL,
	sip_free_phdr},
	{"WWW-AUTHENTICATE", NULL, sip_parse_wauthen_header, NULL, NULL,
	sip_free_phdr},
	{"RSEQ", NULL, sip_parse_rseq, NULL, NULL, sip_free_phdr},
	{"RACK", NULL, sip_parse_rack, NULL, NULL, sip_free_phdr},
	{"P-ASSERTED-IDENTITY", NULL, sip_parse_passertedid, NULL, NULL,
	sip_free_phdr},
	{"P-PREFERRED-IDENTITY", NULL, sip_parse_ppreferredid, NULL, NULL,
	sip_free_phdr},
	{"PRIVACY", NULL, sip_parse_privacy_header, NULL, NULL, sip_free_phdr},
	{NULL, NULL, NULL, NULL, NULL, NULL},
};

#define	MAX_SIP_HEADERS	\
	sizeof (sip_header_function_table) / sizeof (sip_header_function_t)

/*
 * External/application provided function table
 */
sip_header_function_t *sip_header_function_table_external = NULL;

/*
 * Free parameter list
 */
static void
sip_free_params(sip_param_t *param_list)
{
	sip_param_t *param, *next_param;

	param = param_list;

	while (param != NULL) {
		next_param = param->param_next;
		free(param);
		param = next_param;
	}
}

/*
 * Common header free routine
 */
void
sip_free_phdr(sip_parsed_header_t *header)
{
	sip_hdr_value_t	*value;
	sip_hdr_value_t	*next_value;

	if (header == NULL)
		return;
	value = (sip_hdr_value_t *)header->value;
	while (value != NULL) {
		sip_free_params(value->sip_param_list);
		next_value = value->sip_next_value;
		free(value);
		value = next_value;
	}
	free(header);
}

/*
 * Free Contact/From/To header
 */
void
sip_free_cftr_header(sip_parsed_header_t *header)
{
	sip_hdr_value_t	*value;
	sip_hdr_value_t	*next_value;

	if (header == NULL)
		return;
	value = (sip_hdr_value_t *)header->value;
	while (value != NULL) {
		next_value = value->sip_next_value;
		sip_free_params(value->sip_param_list);
		if (value->cftr_name != NULL)
			free(value->cftr_name);
		if (value->sip_value_parsed_uri != NULL) {
			sip_free_parsed_uri(value->sip_value_parsed_uri);
			value->sip_value_parsed_uri = NULL;
		}
		free(value);
		value = next_value;
	}
	free(header);
}

/*
 * Return new header
 */
_sip_header_t *
sip_new_header(int header_size)
{
	_sip_header_t *new_header;

	new_header = calloc(1, sizeof (_sip_header_t));
	if (new_header == NULL)
		return (NULL);

	/*
	 * We are using snprintf which adds a null character
	 * so allocate an extra byte which is not part of
	 * the message header
	 */
	new_header->sip_hdr_start = calloc(1, header_size + 1);
	if (new_header->sip_hdr_start == NULL) {
		free(new_header);
		return (NULL);
	}
	new_header->sip_hdr_end = new_header->sip_hdr_start + header_size;
	new_header->sip_hdr_current = new_header->sip_hdr_start;
	new_header->sip_hdr_allocated = B_TRUE;
	return (new_header);
}

/*
 * Free the given header
 */
void
sip_free_header(_sip_header_t *sip_header)
{
	if (sip_header->sip_hdr_allocated) {
		assert(sip_header->sip_hdr_start != NULL);
		free(sip_header->sip_hdr_start);
	}
	if (sip_header->sip_hdr_parsed != NULL) {
		assert(sip_header->sip_header_functions != NULL);
		if (sip_header->sip_header_functions->header_free != NULL) {
			sip_header->sip_header_functions->header_free(
			    sip_header->sip_hdr_parsed);
		}
	}
	free(sip_header);
}

/*
 * Return a copy of the header passed in.
 */
_sip_header_t *
sip_dup_header(_sip_header_t *from)
{
	size_t		hdr_size;
	_sip_header_t	*to;

	hdr_size = from->sip_hdr_end - from->sip_hdr_start;
	to = sip_new_header(hdr_size);
	if (to == NULL)
		return (NULL);
	if (from->sip_header_state == SIP_HEADER_DELETED_VAL) {
		to->sip_hdr_end = to->sip_hdr_start +
		    sip_copy_values(to->sip_hdr_start, from);
	} else {
		(void) memcpy(to->sip_hdr_start, from->sip_hdr_start, hdr_size);
		to->sip_hdr_end = to->sip_hdr_start + hdr_size;
	}
	to->sip_header_functions = from->sip_header_functions;
	return (to);
}

/*
 * Copy header with extra_param, if any, to sip_msg
 */
int
_sip_copy_header(_sip_msg_t *sip_msg, _sip_header_t *header, char *extra_param,
    boolean_t skip_crlf)
{
	_sip_header_t	*new_header;
	int		hdrlen;
	int		extra_len = 0;
	int		ncrlf = 0;
	char		*p;

#ifdef	__solaris__
	assert(mutex_held(&sip_msg->sip_msg_mutex));
#endif
	if (extra_param != NULL) {
		extra_len = SIP_SPACE_LEN + sizeof (char) + SIP_SPACE_LEN +
		    strlen(extra_param);
	}
	/*
	 * Just take one if there are more, i.e. if this is the last header
	 * before the content.
	 */
	if (skip_crlf) {
		if (header->sip_hdr_end - strlen(SIP_CRLF) <=
		    header->sip_hdr_start) {
			goto proceed;
		}
		p = header->sip_hdr_end - strlen(SIP_CRLF);
		while (strncmp(SIP_CRLF, p, strlen(SIP_CRLF)) == 0) {
			ncrlf++;
			if (p - strlen(SIP_CRLF) < header->sip_hdr_start)
				break;
			p -= strlen(SIP_CRLF);
		}
		/*
		 * Take one CRLF.
		 */
		ncrlf = (ncrlf - 1) * strlen(SIP_CRLF);
	}
proceed:
	hdrlen = header->sip_hdr_end - header->sip_hdr_start - ncrlf;
	new_header = sip_new_header(hdrlen + extra_len);
	if (new_header == NULL)
		return (ENOMEM);
	if (header->sip_header_state == SIP_HEADER_DELETED_VAL) {
		int	len;

		len = sip_copy_values(new_header->sip_hdr_start, header);
		new_header->sip_hdr_end = new_header->sip_hdr_start + len;
		hdrlen = hdrlen - len + extra_len;
	} else {
		(void) memcpy(new_header->sip_hdr_start, header->sip_hdr_start,
		    hdrlen);
		new_header->sip_hdr_end = new_header->sip_hdr_start + hdrlen;
		hdrlen = extra_len;
	}
	if (extra_param != NULL) {
		/*
		 * Find CR
		 */
		if (sip_find_cr(new_header) != 0) {
			sip_free_header(new_header);
			return (EINVAL);
		}
		hdrlen += new_header->sip_hdr_end - new_header->sip_hdr_current;
		(void) snprintf(new_header->sip_hdr_current, hdrlen + 1,
		    " %c %s%s", SIP_SEMI, extra_param, SIP_CRLF);
	}

	new_header->sip_hdr_end += extra_len;
	new_header->sip_header_functions = header->sip_header_functions;
	_sip_add_header(sip_msg, new_header, B_TRUE, B_FALSE, NULL);
	return (0);
}

/*
 * Copy all "header_name" headers from _old_msg to _new_msg
 */
int
_sip_find_and_copy_all_header(_sip_msg_t *_old_msg, _sip_msg_t *_new_msg,
    char *header_name)
{
	_sip_header_t	*header;
	int		ret = 0;

	if (_old_msg == NULL || _new_msg == NULL)
		return (EINVAL);
#ifdef	__solaris__
	assert(mutex_held(&_old_msg->sip_msg_mutex));
#endif
	if (_old_msg != _new_msg)
		(void) pthread_mutex_lock(&_new_msg->sip_msg_mutex);
	header = sip_search_for_header(_old_msg, header_name, NULL);
	while (header != NULL) {
		ret = _sip_copy_header(_new_msg, header, NULL, B_TRUE);
		if (ret != 0)
			break;
		header = sip_search_for_header(_old_msg, header_name, header);
	}
	if (_old_msg != _new_msg)
		(void) pthread_mutex_unlock(&_new_msg->sip_msg_mutex);
	return (ret);
}

/*
 * Copy header_name from _old_msg to _new_msg with extra_parm.
 */
int
_sip_find_and_copy_header(sip_msg_t _old_msg, sip_msg_t _new_msg,
    char *header_name, char *extra_param, boolean_t lock_newmsg)
{
	_sip_header_t	*header;
	int		ret;

	if (_old_msg == NULL || _new_msg == NULL)
		return (EINVAL);
#ifdef	__solaris__
	assert(mutex_held(&_old_msg->sip_msg_mutex));
#endif
	header = sip_search_for_header(_old_msg, header_name, NULL);
	if (header == NULL)
		return (EINVAL);
	if (lock_newmsg)
		(void) pthread_mutex_lock(&_new_msg->sip_msg_mutex);
	ret = _sip_copy_header(_new_msg, header, extra_param, B_TRUE);
	if (lock_newmsg)
		(void) pthread_mutex_unlock(&_new_msg->sip_msg_mutex);
	return (ret);
}

/*
 * Copy all headers from old_msg to new_msg
 */
int
sip_copy_all_headers(sip_msg_t old_msg, sip_msg_t new_msg)
{
	_sip_header_t	*header;
	_sip_msg_t	*_old_msg;
	_sip_msg_t	*_new_msg;
	int		ret = 0;

	if (old_msg == NULL || new_msg == NULL)
		return (EINVAL);
	_old_msg = (_sip_msg_t *)old_msg;
	_new_msg = (_sip_msg_t *)new_msg;

	(void) pthread_mutex_lock(&_old_msg->sip_msg_mutex);
	(void) pthread_mutex_lock(&_new_msg->sip_msg_mutex);
	header = sip_search_for_header(_old_msg, NULL, NULL);
	while (header != NULL) {
		ret = _sip_copy_header(_new_msg, header, NULL, B_FALSE);
		if (ret != 0)
			goto done;
		header = sip_search_for_header(_old_msg, NULL, header);
	}
done:
	(void) pthread_mutex_unlock(&_new_msg->sip_msg_mutex);
	(void) pthread_mutex_unlock(&_old_msg->sip_msg_mutex);
	return (ret);
}

/*
 * Copy start line from msg to sip_msg
 */
int
sip_copy_start_line(sip_msg_t msg, sip_msg_t sip_msg)
{
	int		len;
	_sip_header_t	*new_header;
	_sip_msg_t	*_old_msg;
	_sip_msg_t	*_sip_msg;

	if (msg == NULL || sip_msg == NULL)
		return (EINVAL);
	_old_msg = (_sip_msg_t *)msg;
	_sip_msg = (_sip_msg_t *)sip_msg;

	(void) pthread_mutex_lock(&_old_msg->sip_msg_mutex);
	if (_old_msg->sip_msg_start_line == NULL) {
		(void) pthread_mutex_unlock(&_old_msg->sip_msg_mutex);
		return (EINVAL);
	}
	len = _old_msg->sip_msg_start_line->sip_hdr_end -
	    _old_msg->sip_msg_start_line->sip_hdr_start;
	new_header = sip_new_header(len);
	if (new_header == NULL) {
		(void) pthread_mutex_unlock(&_old_msg->sip_msg_mutex);
		return (ENOMEM);
	}
	new_header->sip_hdr_sipmsg = _sip_msg;
	(void) pthread_mutex_lock(&sip_msg->sip_msg_mutex);
	_sip_msg->sip_msg_start_line = new_header;
	_sip_msg->sip_msg_len = len;
	(void) strncpy(_sip_msg->sip_msg_start_line->sip_hdr_start,
	    _old_msg->sip_msg_start_line->sip_hdr_start, len);
	(void) sip_parse_first_line(_sip_msg->sip_msg_start_line,
	    &_sip_msg->sip_msg_req_res);
	(void) pthread_mutex_unlock(&_old_msg->sip_msg_mutex);
	(void) pthread_mutex_unlock(&sip_msg->sip_msg_mutex);
	return (0);
}

/*
 * Delete start line from sip_msg
 */
int
sip_delete_start_line_locked(_sip_msg_t *_sip_msg)
{
	_sip_header_t	*header;
	_sip_header_t	*next_header;

	if (_sip_msg->sip_msg_start_line == NULL)
		return (EINVAL);

	header = _sip_msg->sip_msg_start_line;
	while (header != NULL) {
		next_header = header->sip_hdr_next;
		_sip_msg->sip_msg_len -= (header->sip_hdr_end -
		    header->sip_hdr_start);
		sip_free_header(header);
		header = next_header;
	}
	_sip_msg->sip_msg_start_line = NULL;

	/*
	 * Also delete the sip_msg_req_res info since we don't have a start
	 * line.
	 */
	while (_sip_msg->sip_msg_req_res != NULL) {
		sip_message_type_t	*sip_msg_type_ptr;

		sip_msg_type_ptr = _sip_msg->sip_msg_req_res->sip_next;
		if (_sip_msg->sip_msg_req_res->is_request) {
			sip_request_t	*reqline;

			reqline = &_sip_msg->sip_msg_req_res->U.sip_request;
			if (reqline->sip_parse_uri != NULL) {
				sip_free_parsed_uri(reqline->sip_parse_uri);
				reqline->sip_parse_uri = NULL;
			}
		}
		free(_sip_msg->sip_msg_req_res);
		_sip_msg->sip_msg_req_res = sip_msg_type_ptr;
	}
	return (0);
}


/*
 * Delete start line from sip_msg
 */
int
sip_delete_start_line(sip_msg_t sip_msg)
{
	_sip_msg_t	*_sip_msg;
	int		ret;

	if (sip_msg == NULL)
		return (EINVAL);

	_sip_msg = (_sip_msg_t *)sip_msg;
	(void) pthread_mutex_lock(&_sip_msg->sip_msg_mutex);
	ret = sip_delete_start_line_locked(_sip_msg);
	(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);

	return (ret);
}

/*
 * Delete all headers from _sip_msg
 */
void
sip_delete_all_headers(_sip_msg_t *_sip_msg)
{
	_sip_header_t *header;

#ifdef	__solaris__
	assert(mutex_held(&_sip_msg->sip_msg_mutex));
#endif

	header = _sip_msg->sip_msg_headers_start;
	while (header != NULL) {
		_sip_header_t *next_header;
		next_header = header->sip_hdr_next;
		sip_free_header(header);
		header = next_header;
	}
	_sip_msg->sip_msg_headers_start = NULL;
	_sip_msg->sip_msg_headers_end = NULL;
}

/*
 * Delete and free the named header. If header_name is null
 * free all headers.
 */
void
sip_delete_headers(sip_msg_t sip_msg, char *header_name)
{
	_sip_header_t *header;
	_sip_msg_t *_sip_msg;

	_sip_msg = (_sip_msg_t *)sip_msg;
#ifdef	__solaris__
	assert(mutex_held(&_sip_msg->sip_msg_mutex));
#endif
	header = sip_search_for_header(_sip_msg, header_name, NULL);
	if (header == NULL)
		return;
	while (header != NULL) {
		if (_sip_msg->sip_msg_headers_start == header) {
			_sip_msg->sip_msg_headers_start = header->sip_hdr_next;
		} else {
			header->sip_hdr_prev->sip_hdr_next =
			    header->sip_hdr_next;
		}
		if (_sip_msg->sip_msg_headers_end == header) {
			_sip_msg->sip_msg_headers_end = header->sip_hdr_prev;
		} else {
			header->sip_hdr_next->sip_hdr_prev =
			    header->sip_hdr_prev;
		}
		sip_free_header(header);
		if (header_name != NULL)
			return;
		else
			header = sip_search_for_header(_sip_msg, NULL, NULL);
	}
}

/*
 * Add a header to sip_msg. If header_name is provided then the new header
 * is added before that header, if first is set, or after. If append is
 * set, then the header is added to the end of the header list.
 */
void
_sip_add_header(_sip_msg_t *sip_msg, _sip_header_t *new_header,
    boolean_t append, boolean_t first, char *header_name)
{
	_sip_header_t	*header = NULL;

	if (sip_msg == NULL || new_header == NULL)
		return;
#ifdef	__solaris__
	assert(mutex_held(&sip_msg->sip_msg_mutex));
#endif
	new_header->sip_hdr_sipmsg = sip_msg;
	if (header_name != NULL) {
		_sip_header_t	*header_tmp;

		header = sip_search_for_header(sip_msg, header_name, NULL);
		header_tmp = header;
		if (!first) {
			while (header != NULL) {
				header_tmp = header;
				header = sip_search_for_header(sip_msg,
				    header_name, header);
			}
		}
		header = header_tmp;
		if (header == NULL)
			append =  B_TRUE;
	}

	if (header != NULL) {
		if (append) {
			new_header->sip_hdr_prev = header;
			if (sip_msg->sip_msg_headers_end == header) {
				sip_msg->sip_msg_headers_end = new_header;
				new_header->sip_hdr_next = NULL;
			} else {
				header->sip_hdr_next->sip_hdr_prev = new_header;
				new_header->sip_hdr_next = header->sip_hdr_next;
			}
			header->sip_hdr_next = new_header;
		} else {
			new_header->sip_hdr_next = header;
			if (sip_msg->sip_msg_headers_start == header) {
				sip_msg->sip_msg_headers_start = new_header;
				new_header->sip_hdr_prev = NULL;
			} else {
				header->sip_hdr_prev->sip_hdr_next = new_header;
				new_header->sip_hdr_prev = header->sip_hdr_prev;
			}
			header->sip_hdr_prev = new_header;
		}
	} else {
		if (append) {
			if (sip_msg->sip_msg_headers_end != NULL) {
				sip_msg->sip_msg_headers_end->sip_hdr_next =
				    new_header;
			} else {
				sip_msg->sip_msg_headers_start = new_header;
			}
			new_header->sip_hdr_prev =
			    sip_msg->sip_msg_headers_end;
			new_header->sip_hdr_next = NULL;
			sip_msg->sip_msg_headers_end = new_header;
		} else {
			if (sip_msg->sip_msg_headers_start != NULL) {
				sip_msg->sip_msg_headers_start->sip_hdr_prev =
				    new_header;
			} else {
				sip_msg->sip_msg_headers_end = new_header;
			}
			new_header->sip_hdr_next =
			    sip_msg->sip_msg_headers_start;
			new_header->sip_hdr_prev = NULL;
			sip_msg->sip_msg_headers_start = new_header;
		}
	}
	sip_msg->sip_msg_len += new_header->sip_hdr_end -
	    new_header->sip_hdr_start;
}

/*
 * Scan through the function table and return the entry for the given header
 * type.
 */
sip_header_function_t *
_sip_get_header_functions(sip_header_function_t *sip_header_function_table,
    _sip_header_t *sip_header, char *header_name)
{
	int	len;
	int	i = 0;

	if (sip_header == NULL && header_name == NULL)
		return (NULL);

	/*
	 * If header_name is NULL we first have to locate the name
	 */
	if (header_name == NULL) {
		if (sip_skip_white_space(sip_header) != 0) {
			return (NULL);
		}
		header_name = sip_header->sip_hdr_current;
		if (sip_find_separator(sip_header, SIP_HCOLON, 0,
		    0, B_FALSE) != 0) {
			return (NULL);
		}
		len = sip_header->sip_hdr_current - header_name;
	} else {
		len = strlen(header_name);
	}

	if (len > 0) {
		while (sip_header_function_table[i].header_name != NULL ||
		    sip_header_function_table[i].header_short_name != NULL) {
			if (sip_header_function_table[i].header_name != NULL &&
			    len ==
			    strlen(sip_header_function_table[i].header_name)) {
				if (strncasecmp(header_name,
				    sip_header_function_table[i].
				    header_name, len) == 0) {
					break;
				}
			} else if (sip_header_function_table[i].
			    header_short_name != NULL && len ==
			    strlen(sip_header_function_table[i].
			    header_short_name)) {
				if (strncasecmp(header_name,
				    sip_header_function_table[i].
				    header_short_name, len) == 0) {
					break;
				}
			}
			i++;
		}
	}

	if (sip_header != NULL)
		sip_header->sip_hdr_current = sip_header->sip_hdr_start;
	if (sip_header_function_table[i].header_name == NULL)
		return (NULL);
	return (&sip_header_function_table[i]);
}

/*
 * Return the entry from the function table for the given header
 */
sip_header_function_t *
sip_get_header_functions(_sip_header_t *sip_header, char *header_name)
{
	sip_header_function_t	*func;
	sip_header_function_t	*header_f_table = NULL;

	if (sip_header_function_table_external != NULL) {
		header_f_table = _sip_get_header_functions(
		    sip_header_function_table_external,
		    sip_header, header_name);
		if (header_f_table != NULL)
			return (header_f_table);
	}
	func = _sip_get_header_functions(sip_header_function_table, sip_header,
	    header_name);
	return (func);
}

/*
 * Search for the header name passed in.
 */
_sip_header_t *
sip_search_for_header(_sip_msg_t *sip_msg, char *header_name,
    _sip_header_t *old_header)
{
	int			len = 0;
	int			full_len = 0;
	int			compact_len = 0;
	_sip_header_t		*header = NULL;
	char			*compact_name = NULL;
	char			*full_name = NULL;
	sip_header_function_t	*header_f_table = NULL;

	if (sip_msg == NULL)
		return (NULL);
#ifdef	__solaris__
	assert(mutex_held(&sip_msg->sip_msg_mutex));
#endif

	if (header_name != NULL) {
		header_f_table = sip_get_header_functions(NULL, header_name);
		if (header_f_table != NULL) {
			full_name = header_f_table->header_name;
			compact_name = header_f_table->header_short_name;
			if (full_name != NULL)
				full_len = strlen(full_name);
			if (compact_name != NULL)
				compact_len = strlen(compact_name);
		} else {
			header_f_table = &sip_header_function_table[0];
			full_name = header_name;
			full_len  = strlen(full_name);
		}
	}

	if (old_header != NULL)
		header = old_header->sip_hdr_next;
	else
		header = sip_msg->sip_msg_headers_start;

	while (header != NULL) {

		if (header->sip_header_state == SIP_HEADER_DELETED) {
			header = header->sip_hdr_next;
			continue;
		}

		if (compact_len == 0 && full_len == 0)
			break;

		header->sip_hdr_current = header->sip_hdr_start;

		if (sip_skip_white_space(header)) {
			header = header->sip_hdr_next;
			continue;
		}

		len = header->sip_hdr_end - header->sip_hdr_current;

		if (full_name != NULL && (full_len <= len) &&
		    strncasecmp(header->sip_hdr_current, full_name,
		    full_len) == 0) {
			header->sip_hdr_current += full_len;
			if (sip_skip_white_space(header)) {
				header = header->sip_hdr_next;
				continue;
			}

			if (*header->sip_hdr_current == SIP_HCOLON) {
				header_name = full_name;
				break;
			}
		}

		if (compact_name != NULL && (compact_len <= len) &&
		    strncasecmp(header->sip_hdr_current, compact_name,
		    compact_len) == 0) {
			header->sip_hdr_current += compact_len;
			if (sip_skip_white_space(header)) {
				header = header->sip_hdr_next;
				continue;
			}
			if (*header->sip_hdr_current == SIP_HCOLON) {
				header_name = compact_name;
				break;
			}
		}
		header = header->sip_hdr_next;
	}

	if (header != NULL) {
		header->sip_hdr_current = header->sip_hdr_start;
		if (header_f_table == NULL) {
			header_f_table =
			    sip_get_header_functions(header, header_name);
			if (header_f_table == NULL)
				header_f_table = &sip_header_function_table[0];
		}

		header->sip_header_functions = header_f_table;
	}
	return (header);
}

/*
 * Return the start line as a string. Caller frees string
 */
char *
_sip_startline_to_str(_sip_msg_t *sip_msg, int *error)
{
	char		*slstr;
	int		len;

	if (error != NULL)
		*error = 0;

	if (sip_msg == NULL || sip_msg->sip_msg_start_line == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	(void) pthread_mutex_lock(&sip_msg->sip_msg_mutex);
	len = sip_msg->sip_msg_start_line->sip_hdr_end -
	    sip_msg->sip_msg_start_line->sip_hdr_start - 2;
	if ((slstr = malloc(len + 1)) == NULL) {
		(void) pthread_mutex_unlock(&sip_msg->sip_msg_mutex);
		if (error != NULL)
			*error = ENOMEM;
		return (NULL);
	}
	(void) strncpy(slstr, sip_msg->sip_msg_start_line->sip_hdr_start, len);
	(void) pthread_mutex_unlock(&sip_msg->sip_msg_mutex);
	slstr[len] = '\0';
	return (slstr);
}

/*
 * Return the given header as a string. Caller frees string
 */
char *
sip_hdr_to_str(sip_header_t sip_header, int *error)
{
	char		*hdrstr;
	char		*tmpptr;
	_sip_header_t	*_sip_header;
	int		len;

	if (error != NULL)
		*error = 0;

	if (sip_header == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	_sip_header = (_sip_header_t *)sip_header;
	if (_sip_header->sip_header_state == SIP_HEADER_DELETED) {
		if (_sip_header->sip_hdr_sipmsg != NULL) {
			(void) pthread_mutex_unlock(
			    &_sip_header->sip_hdr_sipmsg->sip_msg_mutex);
		}
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	if (_sip_header->sip_hdr_sipmsg != NULL) {
		(void) pthread_mutex_lock(
		    &_sip_header->sip_hdr_sipmsg->sip_msg_mutex);
	}
	len = _sip_header->sip_hdr_end - _sip_header->sip_hdr_start;
	hdrstr = malloc(len);
	if (hdrstr == NULL) {
		if (_sip_header->sip_hdr_sipmsg != NULL) {
			(void) pthread_mutex_unlock(
			    &_sip_header->sip_hdr_sipmsg->sip_msg_mutex);
		}
		if (error != NULL)
			*error = ENOMEM;
		return (NULL);
	}
	if (_sip_header->sip_header_state == SIP_HEADER_DELETED_VAL) {
		len = sip_copy_values(hdrstr, _sip_header);
	} else {
		(void) strncpy(hdrstr, _sip_header->sip_hdr_start, len);
	}
	if (_sip_header->sip_hdr_sipmsg != NULL) {
		(void) pthread_mutex_unlock(
		    &_sip_header->sip_hdr_sipmsg->sip_msg_mutex);
	}
	tmpptr = hdrstr + len;
	while (*tmpptr-- != '\n') {
		if (tmpptr == _sip_header->sip_hdr_start) {
			free(hdrstr);
			if (error != NULL)
				*error = EINVAL;
			return (NULL);
		}
	}
	*tmpptr = '\0';
	return (hdrstr);
}

/*
 * Given a param list find the named parameter.
 * Returns a pointer to the value or NULL.
 */
sip_param_t *
sip_get_param_from_list(sip_param_t *param_list, char *param_name)
{
	while (param_list != NULL) {
		if (param_list->param_name.sip_str_len == strlen(param_name) &&
		    strncasecmp(param_list->param_name.sip_str_ptr, param_name,
		    strlen(param_name)) == 0) {
			return (param_list);
		}
		param_list = param_list->param_next;
	}
	return (NULL);
}
