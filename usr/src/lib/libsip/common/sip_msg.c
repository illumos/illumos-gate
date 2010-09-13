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
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sip.h>

#include "sip_msg.h"
#include "sip_miscdefs.h"
#include "sip_parse_generic.h"

/*
 * Response consists of SIP version, response code, response phrase and CRLF.
 */
#define	SIP_RESPONSE	"%s %d %s%s"

void sip_free_content(_sip_msg_t *);

/*
 * Allocate a new sip msg struct.
 */
sip_msg_t
sip_new_msg()
{
	_sip_msg_t *sip_msg;

	sip_msg = calloc(1, sizeof (_sip_msg_t));
	if (sip_msg != NULL) {
		sip_msg->sip_msg_ref_cnt = 1;
		(void) pthread_mutex_init(&sip_msg->sip_msg_mutex, NULL);
	}
	return ((sip_msg_t)sip_msg);
}

/*
 * Free all resources. The lock is taken by SIP_MSG_REFCNT_DECR. The
 * thread that decrements the last refcount should take care that
 * the message is not accessible to other threads before doing so.
 * Else, if the message is still accessible to others, it is
 * possible that the other thread could be waiting to take the
 * lock when we proceed to destroy it.
 */
void
sip_destroy_msg(_sip_msg_t *_sip_msg)
{
#ifdef	__solaris__
	assert(mutex_held(&_sip_msg->sip_msg_mutex));
#endif
	(void) sip_delete_start_line_locked(_sip_msg);
	assert(_sip_msg->sip_msg_ref_cnt == 0);
	sip_delete_all_headers((sip_msg_t)_sip_msg);
	sip_free_content(_sip_msg);
	if (_sip_msg->sip_msg_buf != NULL)
		free(_sip_msg->sip_msg_buf);

	if (_sip_msg->sip_msg_old_buf != NULL)
		free(_sip_msg->sip_msg_old_buf);

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
	(void) pthread_mutex_destroy(&_sip_msg->sip_msg_mutex);
	free(_sip_msg);
}

/*
 * Free a sip msg struct.
 */
void
sip_free_msg(sip_msg_t sip_msg)
{
	if (sip_msg == NULL)
		return;

	SIP_MSG_REFCNT_DECR((_sip_msg_t *)sip_msg);
}

/*
 * Hold a sip msg struct.
 */
void
sip_hold_msg(sip_msg_t sip_msg)
{

	if (sip_msg == NULL)
		return;

	SIP_MSG_REFCNT_INCR((_sip_msg_t *)sip_msg);
}

/*
 * Clone a message
 */
sip_msg_t
sip_clone_msg(sip_msg_t sip_msg)
{
	_sip_msg_t	*new_msg;
	_sip_msg_t	*_sip_msg;
	sip_content_t	*sip_content;
	sip_content_t	*msg_content;
	sip_content_t	*new_content = NULL;
	int		len;

	if (sip_msg == NULL)
		return (NULL);
	new_msg = (_sip_msg_t *)sip_new_msg();
	if (new_msg == NULL)
		return (NULL);
	_sip_msg = (_sip_msg_t *)sip_msg;
	/*
	 * Get start line
	 */
	if (sip_copy_start_line(_sip_msg, new_msg) != 0) {
		sip_free_msg((sip_msg_t)new_msg);
		return (NULL);
	}
	if (sip_copy_all_headers(_sip_msg, new_msg) != 0) {
		sip_free_msg((sip_msg_t)new_msg);
		return (NULL);
	}
	(void) pthread_mutex_lock(&_sip_msg->sip_msg_mutex);
	sip_content = _sip_msg->sip_msg_content;
	while (sip_content != NULL) {
		msg_content = calloc(1, sizeof (sip_content_t));
		if (msg_content == NULL) {
			sip_free_msg((sip_msg_t)new_msg);
			(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
			return (NULL);
		}
		len = sip_content->sip_content_end -
		    sip_content->sip_content_start;
		msg_content->sip_content_start = malloc(len + 1);
		if (msg_content->sip_content_start == NULL) {
			sip_free_msg((sip_msg_t)new_msg);
			(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
			return (NULL);
		}
		(void) strncpy(msg_content->sip_content_start,
		    sip_content->sip_content_start, len);
		msg_content->sip_content_start[len] = '\0';
		msg_content->sip_content_current =
		    msg_content->sip_content_start;
		msg_content->sip_content_end =  msg_content->sip_content_start +
		    len;
		msg_content->sip_content_allocated = B_TRUE;
		new_msg->sip_msg_content_len += len;
		new_msg->sip_msg_len += len;
		if (new_msg->sip_msg_content == NULL)
			new_msg->sip_msg_content = msg_content;
		else
			new_content->sip_content_next = msg_content;
		new_content = msg_content;
		sip_content = sip_content->sip_content_next;
	}
	(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
	/*
	 * Since this is a new message, no threads should be referring
	 * to this, so it is not necessary to take the lock, however,
	 * since sip_msg_to_msgbuf() expects the lock to be held, we'll
	 * take it here.
	 */
	(void) pthread_mutex_lock(&new_msg->sip_msg_mutex);
	new_msg->sip_msg_buf = sip_msg_to_msgbuf((sip_msg_t)new_msg, NULL);
	if (new_msg->sip_msg_buf == NULL) {
		(void) pthread_mutex_unlock(&new_msg->sip_msg_mutex);
		sip_free_msg((sip_msg_t)new_msg);
		return (NULL);
	}
	new_msg->sip_msg_cannot_be_modified = B_TRUE;
	(void) pthread_mutex_unlock(&new_msg->sip_msg_mutex);

	return ((sip_msg_t)new_msg);
}

/*
 * Return the SIP message as a string. Caller frees the string
 */
char *
sip_msg_to_str(sip_msg_t sip_msg, int *error)
{
	_sip_msg_t	*msg;
	char		*msgstr;

	if (sip_msg == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	msg = (_sip_msg_t *)sip_msg;
	(void) pthread_mutex_lock(&msg->sip_msg_mutex);
	msgstr = sip_msg_to_msgbuf(msg, error);
	(void) pthread_mutex_unlock(&msg->sip_msg_mutex);
	return (msgstr);
}

/*
 * Given a message generate a string that includes all the headers and the
 * content.
 */
char *
sip_msg_to_msgbuf(_sip_msg_t *msg, int *error)
{
	_sip_header_t	*header;
	int		len = 0;
	char		*p;
	char		*e;
	sip_content_t	*sip_content;
#ifdef	_DEBUG
	int		tlen = 0;
	int		clen = 0;
#endif

	if (error != NULL)
		*error = 0;

	if (msg == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
#ifdef	__solaris__
	assert(mutex_held(&msg->sip_msg_mutex));
#endif

	p = (char *)malloc(msg->sip_msg_len + 1);
	if (p == NULL) {
		if (error != 0)
			*error = ENOMEM;
		return (NULL);
	}
	e = p;

	/*
	 * Get the start line
	 */
	if (msg->sip_msg_start_line != NULL) {
		len = msg->sip_msg_start_line->sip_hdr_end -
		    msg->sip_msg_start_line->sip_hdr_start;
		(void) strncpy(e, msg->sip_msg_start_line->sip_hdr_start, len);
		e += len;
#ifdef	_DEBUG
		tlen += len;
#endif
	}
	header = sip_search_for_header(msg, NULL, NULL);
	while (header != NULL) {
		if (header->sip_header_state != SIP_HEADER_DELETED) {
			if (header->sip_header_state ==
			    SIP_HEADER_DELETED_VAL) {
				len = sip_copy_values(e, header);
			} else {
				len = header->sip_hdr_end -
				    header->sip_hdr_start;
				(void) strncpy(e, header->sip_hdr_start, len);
			}
#ifdef	_DEBUG
			tlen += len;
			assert(tlen <= msg->sip_msg_len);
#endif
		}
		header = sip_search_for_header(msg, NULL, header);
		e += len;
	}
	sip_content = msg->sip_msg_content;
	while (sip_content != NULL) {
		len = sip_content->sip_content_end -
		    sip_content->sip_content_start;
#ifdef	_DEBUG
		clen += len;
		assert(clen <= msg->sip_msg_content_len);
		tlen += len;
		assert(tlen <= msg->sip_msg_len);
#endif
		(void) strncpy(e, sip_content->sip_content_start, len);
		e += len;
		sip_content = sip_content->sip_content_next;
	}
	p[msg->sip_msg_len] = '\0';
	return (p);
}

/*
 * This is called just before sending the message to the transport. It
 * creates the sip_msg_buf from the SIP headers.
 */
int
sip_adjust_msgbuf(_sip_msg_t *msg)
{
	_sip_header_t	*header;
	int		ret;
#ifdef	_DEBUG
	int		tlen = 0;
	int		clen = 0;
#endif

	if (msg == NULL)
		return (EINVAL);

	(void) pthread_mutex_lock(&msg->sip_msg_mutex);
	if ((msg->sip_msg_buf != NULL) && (!msg->sip_msg_modified)) {
		/*
		 * We could just be forwarding the message we
		 * received.
		 */
		(void) pthread_mutex_unlock(&msg->sip_msg_mutex);
		return (0);
	}

	/*
	 * We are sending a new message or a message that we received
	 * but have modified it. We keep the old
	 * msgbuf till the message is freed as some
	 * headers still point to it.
	 */

	assert(msg->sip_msg_old_buf == NULL);
	msg->sip_msg_old_buf = msg->sip_msg_buf;
	/*
	 * We add the content-length header here, if it has not
	 * already been added.
	 */
	header = sip_search_for_header(msg, SIP_CONTENT_LENGTH, NULL);
	if (header != NULL) {
		/*
		 * Mark the previous header as deleted.
		 */
		header->sip_header_state = SIP_HEADER_DELETED;
		header->sip_hdr_sipmsg->sip_msg_len -= header->sip_hdr_end -
		    header->sip_hdr_start;
	}
	(void) pthread_mutex_unlock(&msg->sip_msg_mutex);
	ret = sip_add_content_length(msg, msg->sip_msg_content_len);
	if (ret != 0) {
		(void) pthread_mutex_unlock(&msg->sip_msg_mutex);
		return (ret);
	}
	(void) pthread_mutex_lock(&msg->sip_msg_mutex);
	msg->sip_msg_modified = B_FALSE;

	msg->sip_msg_buf = sip_msg_to_msgbuf((sip_msg_t)msg, &ret);
	if (msg->sip_msg_buf == NULL) {
		(void) pthread_mutex_unlock(&msg->sip_msg_mutex);
		return (ret);
	}
	/*
	 * Once the message has been sent it can not be modified
	 * any furthur as we keep a pointer to it for retransmission
	 */
	msg->sip_msg_cannot_be_modified = B_TRUE;

	(void) pthread_mutex_unlock(&msg->sip_msg_mutex);
	return (0);
}

/*
 * Copy header values into ptr
 */
int
sip_copy_values(char *ptr, _sip_header_t *header)
{
	sip_header_value_t	value;
	int			tlen = 0;
	int			len = 0;
	boolean_t		first = B_TRUE;
	char			*p = ptr;
	char			*s;
	boolean_t		crlf_present = B_FALSE;

	if (sip_parse_goto_values(header) != 0)
		return (0);

	len = header->sip_hdr_current - header->sip_hdr_start;
	(void) strncpy(p, header->sip_hdr_start, len);
	tlen += len;
	p += len;
	value = header->sip_hdr_parsed->value;
	while (value != NULL) {
		if (value->value_state != SIP_VALUE_DELETED) {
			crlf_present = B_FALSE;
			len = value->value_end - value->value_start;
			if (first) {
				(void) strncpy(p, value->value_start, len);
				first = B_FALSE;
			} else {
				s = value->value_start;
				while (*s != SIP_COMMA)
					s--;
				len += value->value_start - s;
				(void) strncpy(p, s, len);
			}
			tlen += len;
			p += len;
			s = value->value_end;
			while (s != value->value_start) {
				if (*s == '\r' && strncmp(s, SIP_CRLF,
				    strlen(SIP_CRLF)) == 0) {
					crlf_present = B_TRUE;
					break;
				}
				s--;
			}
		} else {
			if (value->next == NULL && !first && !crlf_present) {
				s = value->value_end;
				while (*s != '\r')
					s--;
				len = value->value_end - s;
				(void) strncpy(p, s, len);
				tlen += len;
				p += len;
			}
		}
		value = value->next;
	}
	return (tlen);
}


/*
 * Add content (message body) to sip_msg
 */
int
sip_add_content(sip_msg_t sip_msg, char *content)
{
	size_t		len;
	sip_content_t	**loc;
	sip_content_t	*msg_content;
	_sip_msg_t	*_sip_msg;

	if (sip_msg == NULL || content == NULL || strlen(content) == 0)
		return (EINVAL);
	len = strlen(content);
	_sip_msg = (_sip_msg_t *)sip_msg;
	(void) pthread_mutex_lock(&_sip_msg->sip_msg_mutex);

	if (_sip_msg->sip_msg_cannot_be_modified) {
		(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
		return (ENOTSUP);
	}

	msg_content = calloc(1, sizeof (sip_content_t));
	if (msg_content == NULL) {
		(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
		return (ENOMEM);
	}
	msg_content->sip_content_start = malloc(strlen(content) + 1);
	if (msg_content->sip_content_start == NULL) {
		(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
		free(msg_content);
		return (ENOMEM);
	}
	(void) strncpy(msg_content->sip_content_start, content,
	    strlen(content));
	msg_content->sip_content_start[strlen(content)] = '\0';
	msg_content->sip_content_current = msg_content->sip_content_start;
	msg_content->sip_content_end = msg_content->sip_content_start +
	    strlen(msg_content->sip_content_start);
	msg_content->sip_content_allocated = B_TRUE;

	loc = &_sip_msg->sip_msg_content;
	while (*loc != NULL)
		loc = &((*loc)->sip_content_next);
	*loc = msg_content;

	_sip_msg->sip_msg_content_len += len;
	_sip_msg->sip_msg_len += len;
	if (_sip_msg->sip_msg_buf != NULL)
		_sip_msg->sip_msg_modified = B_TRUE;
	(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
	return (0);
}

/*
 * Free the message content
 */
void
sip_free_content(_sip_msg_t *sip_msg)
{
	sip_content_t *content;

	if (sip_msg == NULL)
		return;
	content = sip_msg->sip_msg_content;
	while (content != NULL) {
		sip_content_t *content_tmp;

		content_tmp = content;
		content = content->sip_content_next;
		if (content_tmp->sip_content_allocated)
			free(content_tmp->sip_content_start);
		free(content_tmp);
	}
	sip_msg->sip_msg_content = NULL;
}


/*
 * Add a response line to sip_response
 */
int
sip_add_response_line(sip_msg_t sip_response, int response, char *response_code)
{
	_sip_header_t	*new_header;
	int		header_size;
	_sip_msg_t	*_sip_response;
	int		ret;

	if (sip_response == NULL || response < 0 || response_code == NULL)
		return (EINVAL);
	_sip_response = (_sip_msg_t *)sip_response;
	(void) pthread_mutex_lock(&_sip_response->sip_msg_mutex);
	if (_sip_response->sip_msg_cannot_be_modified) {
		(void) pthread_mutex_unlock(&_sip_response->sip_msg_mutex);
		return (ENOTSUP);
	}
	header_size = strlen(SIP_VERSION) + SIP_SPACE_LEN +
	    SIP_SIZE_OF_STATUS_CODE + SIP_SPACE_LEN + strlen(response_code) +
	    strlen(SIP_CRLF);

	new_header = sip_new_header(header_size);
	if (new_header == NULL) {
		(void) pthread_mutex_unlock(&_sip_response->sip_msg_mutex);
		return (ENOMEM);
	}
	new_header->sip_hdr_sipmsg = _sip_response;

	(void) snprintf(new_header->sip_hdr_start, header_size + 1,
	    SIP_RESPONSE, SIP_VERSION, response, response_code, SIP_CRLF);

	new_header->sip_hdr_next = _sip_response->sip_msg_start_line;
	_sip_response->sip_msg_start_line = new_header;
	_sip_response->sip_msg_len += header_size;
	ret = sip_parse_first_line(_sip_response->sip_msg_start_line,
	    &_sip_response->sip_msg_req_res);
	if (_sip_response->sip_msg_buf != NULL)
		_sip_response->sip_msg_modified = B_TRUE;
	(void) pthread_mutex_unlock(&_sip_response->sip_msg_mutex);
	return (ret);
}

/*
 * create a response based on the sip_request.
 * Copies Call-ID, CSeq, From, To and Via headers from the request.
 */
sip_msg_t
sip_create_response(sip_msg_t sip_request, int response, char *response_code,
    char *totag, char *mycontact)
{
	_sip_msg_t	*new_msg;
	_sip_msg_t	*_sip_request;
	boolean_t	ttag_present;

	if (sip_request == NULL || response_code == NULL)
		return (NULL);

	ttag_present =  sip_get_to_tag(sip_request, NULL) != NULL;

	new_msg = (_sip_msg_t *)sip_new_msg();
	if (new_msg == NULL)
		return (NULL);
	_sip_request = (_sip_msg_t *)sip_request;

	(void) pthread_mutex_lock(&_sip_request->sip_msg_mutex);

	/*
	 * Add response line.
	 */
	if (sip_add_response_line(new_msg, response, response_code) != 0)
		goto error;

	/*
	 * Copy Via headers
	 */
	if (_sip_find_and_copy_all_header(_sip_request, new_msg, SIP_VIA) != 0)
		goto error;

	/*
	 * Copy From header.
	 */
	if (_sip_find_and_copy_header(_sip_request, new_msg, SIP_FROM,
	    NULL, B_FALSE)) {
		goto error;
	}
	/*
	 * Copy To header. If To tag is present, copy it, if not then
	 * add one if the repsonse is not provisional.
	 */
	if (ttag_present || (totag == NULL && response == SIP_TRYING)) {
		if (_sip_find_and_copy_header(_sip_request, new_msg, SIP_TO,
		    NULL, B_FALSE)) {
			goto error;
		}
	} else {
		char		*xtra_param;
		boolean_t	tag_alloc = B_FALSE;
		int		taglen;

		if (totag == NULL) {
			totag = sip_guid();
			if (totag == NULL)
				goto error;
			tag_alloc = B_TRUE;
		}
		taglen = strlen(SIP_TAG) + strlen(totag) + 1;
		xtra_param = (char *)malloc(taglen);
		if (xtra_param == NULL) {
			if (tag_alloc)
				free(totag);
			goto error;
		}
		(void) snprintf(xtra_param, taglen, "%s%s", SIP_TAG, totag);
		if (tag_alloc)
			free(totag);
		if (_sip_find_and_copy_header(_sip_request, new_msg,
		    SIP_TO, xtra_param, B_FALSE)) {
			free(xtra_param);
			goto error;
		}
		free(xtra_param);
	}

	/*
	 * Copy Call-ID header.
	 */
	if (_sip_find_and_copy_header(_sip_request, new_msg, SIP_CALL_ID, NULL,
	    B_FALSE)) {
		goto error;
	}
	/*
	 * Copy CSEQ header
	 */
	if (_sip_find_and_copy_header(_sip_request, new_msg, SIP_CSEQ, NULL,
	    B_FALSE)) {
		goto error;
	}
	/*
	 * Copy RECORD-ROUTE header, if present.
	 */
	if (sip_search_for_header(_sip_request, SIP_RECORD_ROUTE, NULL) !=
	    NULL) {
		if (_sip_find_and_copy_all_header(_sip_request, new_msg,
		    SIP_RECORD_ROUTE) != 0) {
			goto error;
		}
	}
	if (mycontact != NULL) {
		if (sip_add_contact(new_msg, NULL, mycontact, B_FALSE,
		    NULL) != 0) {
			goto error;
		}
	}
	(void) pthread_mutex_unlock(&_sip_request->sip_msg_mutex);
	return ((sip_msg_t)new_msg);
error:
	sip_free_msg((sip_msg_t)new_msg);
	(void) pthread_mutex_unlock(&_sip_request->sip_msg_mutex);
	return (NULL);
}

/*
 * NON OK ACK : MUST contain values for the Call-ID, From, and Request-URI
 * that are equal to the values of those header fields in the orig request
 * passed to the transport. The To header field in the ACK MUST equal the To
 * header field in the response being acknowledged. The ACK MUST contain the
 * top Via header field of the original request.  The CSeq header field in
 * the ACK MUST contain the same value for the sequence number as was
 * present in the original request, but the method parameter MUST be equal
 * to "ACK".
 */
int
sip_create_nonOKack(sip_msg_t request, sip_msg_t response, sip_msg_t ack_msg)
{
	int		seqno;
	char		*uri;
	_sip_msg_t	*_request;
	_sip_msg_t	*_response;
	_sip_msg_t	*_ack_msg;
	int		ret;

	if (request == NULL || response == NULL || ack_msg == NULL ||
	    request == ack_msg) {
		return (EINVAL);
	}
	_request = (_sip_msg_t *)request;
	_response = (_sip_msg_t *)response;
	_ack_msg = (_sip_msg_t *)ack_msg;

	(void) pthread_mutex_lock(&_request->sip_msg_mutex);
	if (_request->sip_msg_req_res == NULL) {
		if ((ret = sip_parse_first_line(_request->sip_msg_start_line,
		    &_request->sip_msg_req_res)) != 0) {
			(void) pthread_mutex_unlock(&_request->sip_msg_mutex);
			return (ret);
		}
	}
	if (_request->sip_msg_req_res->U.sip_request.sip_request_uri.
	    sip_str_ptr == NULL) {
		(void) pthread_mutex_unlock(&_request->sip_msg_mutex);
		return (EINVAL);
	}
	uri = (char *)malloc(_request->sip_msg_req_res->U.sip_request.
	    sip_request_uri.sip_str_len + 1);
	if (uri == NULL) {
		(void) pthread_mutex_unlock(&_request->sip_msg_mutex);
		return (EINVAL);
	}
	(void) strncpy(uri,
	    _request->sip_msg_req_res->U.sip_request.sip_request_uri.
	    sip_str_ptr, _request->sip_msg_req_res->U.sip_request.
	    sip_request_uri.sip_str_len);
	uri[_request->sip_msg_req_res->U.sip_request.
	    sip_request_uri.sip_str_len] = '\0';
	if ((ret = sip_add_request_line(_ack_msg, ACK, uri)) != 0) {
		(void) pthread_mutex_unlock(&_request->sip_msg_mutex);
		return (ret);
	}
	free(uri);
	if ((ret = _sip_find_and_copy_header(_request, _ack_msg, SIP_VIA,
	    NULL, B_TRUE)) != 0) {
		(void) pthread_mutex_unlock(&_request->sip_msg_mutex);
		return (ret);
	}
	(void) _sip_find_and_copy_header(_request, _ack_msg,
	    SIP_MAX_FORWARDS, NULL, B_TRUE);

	(void) pthread_mutex_lock(&_response->sip_msg_mutex);
	if ((ret = _sip_find_and_copy_header(_response, _ack_msg, SIP_TO,
	    NULL, B_TRUE)) != 0) {
		(void) pthread_mutex_unlock(&_response->sip_msg_mutex);
		return (ret);
	}
	(void) pthread_mutex_unlock(&_response->sip_msg_mutex);
	if ((ret = _sip_find_and_copy_header(_request, _ack_msg, SIP_FROM,
	    NULL, B_TRUE)) != 0) {
		(void) pthread_mutex_unlock(&_request->sip_msg_mutex);
		return (ret);
	}
	if ((ret = _sip_find_and_copy_header(_request, _ack_msg, SIP_CALL_ID,
	    NULL, B_TRUE)) != 0) {
		(void) pthread_mutex_unlock(&_request->sip_msg_mutex);
		return (ret);
	}
	(void) pthread_mutex_unlock(&_request->sip_msg_mutex);
	seqno = sip_get_callseq_num(_request, &ret);
	if (ret != 0)
		return (ret);
	if ((ret = sip_add_cseq(_ack_msg, ACK, seqno)) != 0)
		return (ret);
	if ((ret = sip_adjust_msgbuf(_ack_msg)) != 0)
		return (ret);
	return (0);
}

/*
 * This is a 2XX ACK, for others ACK is constructed differently,
 * esp. the branch id is retained.
 */
int
sip_create_OKack(sip_msg_t response, sip_msg_t ack_msg, char *transport,
    char *sent_by, int sent_by_port, char *via_params)
{
	int			seqno;
	char			*uri;
	sip_parsed_header_t	*parsed_header;
	sip_hdr_value_t		*contact_value;
	_sip_header_t		*header;
	_sip_msg_t		*_response;
	_sip_msg_t		*_ack_msg;
	int			ret;

	if (response == NULL || response == NULL || transport == NULL)
		return (EINVAL);
	_response = (_sip_msg_t *)response;
	_ack_msg = (_sip_msg_t *)ack_msg;

	/*
	 * Get URI from the response, Contact field
	 */
	(void) pthread_mutex_lock(&_response->sip_msg_mutex);
	if ((header = sip_search_for_header(_response, SIP_CONTACT,
	    NULL)) == NULL) {
		(void) pthread_mutex_unlock(&_response->sip_msg_mutex);
		return (EINVAL);
	}
	if ((ret = sip_parse_cftr_header(header, (void *)&parsed_header)) !=
	    0) {
		(void) pthread_mutex_unlock(&_response->sip_msg_mutex);
		return (ret);
	}
	contact_value = (sip_hdr_value_t *)parsed_header->value;
	if (contact_value->cftr_uri.sip_str_ptr == NULL) {
		(void) pthread_mutex_unlock(&_response->sip_msg_mutex);
		return (EINVAL);
	}
	uri = (char *)malloc(contact_value->cftr_uri.sip_str_len + 1);
	if (uri == NULL) {
		(void) pthread_mutex_unlock(&_response->sip_msg_mutex);
		return (ENOMEM);
	}
	(void) strncpy(uri, contact_value->cftr_uri.sip_str_ptr,
	    contact_value->cftr_uri.sip_str_len);
	uri[contact_value->cftr_uri.sip_str_len] = '\0';
	if ((ret = sip_add_request_line(_ack_msg, ACK, uri)) != 0) {
		(void) pthread_mutex_unlock(&_response->sip_msg_mutex);
		return (ret);
	}
	free(uri);
	if ((ret = sip_add_via(_ack_msg, transport, sent_by, sent_by_port,
	    via_params)) != 0) {
		(void) pthread_mutex_unlock(&_response->sip_msg_mutex);
		return (ret);
	}

	if ((ret = _sip_find_and_copy_header(_response, _ack_msg, SIP_TO,
	    NULL, B_TRUE)) != 0) {
		(void) pthread_mutex_unlock(&_response->sip_msg_mutex);
		return (ret);
	}
	if ((ret = _sip_find_and_copy_header(_response, _ack_msg, SIP_FROM,
	    NULL, B_TRUE)) != 0) {
		(void) pthread_mutex_unlock(&_response->sip_msg_mutex);
		return (ret);
	}
	if ((ret = _sip_find_and_copy_header(_response, _ack_msg, SIP_CALL_ID,
	    NULL, B_TRUE)) != 0) {
		(void) pthread_mutex_unlock(&_response->sip_msg_mutex);
		return (ret);
	}
	/*
	 * Copy Max-Forward if present
	 */
	if (sip_search_for_header(_response, SIP_MAX_FORWARDS, NULL) != NULL) {
		if ((ret = _sip_find_and_copy_header(_response, _ack_msg,
		    SIP_MAX_FORWARDS, NULL, B_TRUE)) != 0) {
			(void) pthread_mutex_unlock(&_response->sip_msg_mutex);
			return (ret);
		}
	}
	(void) pthread_mutex_unlock(&_response->sip_msg_mutex);
	seqno = sip_get_callseq_num(_response, &ret);
	if (ret != 0)
		return (ret);
	if ((ret = sip_add_cseq(_ack_msg, ACK, seqno)) != 0)
		return (ret);

	return (0);
}

/*
 * Request-Line   =  Method SP Request-URI SP SIP-Version CRLF
 */
int
sip_add_request_line(sip_msg_t sip_request, sip_method_t method,
    char *request_uri)
{
	_sip_header_t	*new_header;
	int		 header_size;
	_sip_msg_t	*_sip_request;

	if (method < INVITE || method >= MAX_SIP_METHODS ||
	    request_uri == NULL || sip_request == NULL) {
		return (EINVAL);
	}

	_sip_request = (_sip_msg_t *)sip_request;
	(void) pthread_mutex_lock(&_sip_request->sip_msg_mutex);
	if (_sip_request->sip_msg_cannot_be_modified) {
		(void) pthread_mutex_unlock(&_sip_request->sip_msg_mutex);
		return (ENOTSUP);
	}

	header_size = strlen(sip_methods[method].name) + SIP_SPACE_LEN +
	    strlen(request_uri) + SIP_SPACE_LEN + strlen(SIP_VERSION) +
	    strlen(SIP_CRLF);

	new_header = sip_new_header(header_size);
	if (new_header == NULL) {
		(void) pthread_mutex_unlock(&_sip_request->sip_msg_mutex);
		return (ENOMEM);
	}
	new_header->sip_hdr_sipmsg = _sip_request;

	(void) snprintf(new_header->sip_hdr_start, header_size + 1,
	    "%s %s %s%s", sip_methods[method].name, request_uri,
	    SIP_VERSION, SIP_CRLF);

	new_header->sip_hdr_next = _sip_request->sip_msg_start_line;
	_sip_request->sip_msg_start_line = new_header;
	_sip_request->sip_msg_len += header_size;
	(void) sip_parse_first_line(_sip_request->sip_msg_start_line,
	    &_sip_request->sip_msg_req_res);
	if (_sip_request->sip_msg_buf != NULL)
		_sip_request->sip_msg_modified = B_TRUE;
	(void) pthread_mutex_unlock(&_sip_request->sip_msg_mutex);
	return (0);
}
