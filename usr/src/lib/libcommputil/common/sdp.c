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

/*
 * Contains implementation of various interfaces exported by library
 */

#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sdp.h>

#include "sdp_parse.h"
#include "commp_util.h"

#define	FIELD_EQUALS_CRLF_LEN		4  /* first two characters and CRLF */

#define	SDP_ATTR_TO_STR(m_attr) {					\
	while ((m_attr) != NULL) {					\
		if ((m_attr)->a_value != NULL) {			\
			wrote = snprintf(buf, len, "a=%s%c%s%s",	\
			    (m_attr)->a_name, COMMP_COLON, (m_attr)->  	\
			    a_value, COMMP_CRLF);			\
		} else {						\
			wrote = snprintf(buf, len, "a=%s%s", (m_attr)-> \
			    a_name, COMMP_CRLF);			\
		}							\
		len = len - wrote;					\
		buf = buf + wrote;					\
		(m_attr) = (m_attr)->a_next;				\
	}								\
}

#define	SDP_KEY_TO_STR(m_key) {						\
	if ((m_key) != NULL) {						\
		if ((m_key)->k_enckey != NULL) {			\
			wrote = snprintf(buf, len, "k=%s%c%s%s",	\
			    (m_key)->k_method, COMMP_COLON, (m_key)->	\
			    k_enckey, COMMP_CRLF);			\
		} else {						\
			wrote = snprintf(buf, len, "k=%s%s", (m_key)->	\
			    k_method, COMMP_CRLF);			\
		}							\
		len = len - wrote;					\
		buf = buf + wrote;					\
	}								\
}

#define	SDP_BANDWIDTH_TO_STR(m_bw) {					\
	while ((m_bw) != NULL) {					\
		wrote = snprintf(buf, len, "b=%s%c%llu%s", (m_bw)->	\
		    b_type, COMMP_COLON, (m_bw)->b_value, COMMP_CRLF);	\
		len = len - wrote;					\
		buf = buf + wrote;					\
		(m_bw) = (m_bw)->b_next;				\
	}								\
}

#define	SDP_INFORMATION_TO_STR(m_info) {				       \
	if ((m_info) != NULL) {						       \
		wrote = snprintf(buf, len, "i=%s%s", (m_info), COMMP_CRLF);    \
		len = len - wrote;					       \
		buf = buf + wrote;					       \
	}								       \
}

#define	SDP_CONNECTION_TO_STR(m_conn) {					       \
	while ((m_conn) != NULL) {					       \
		if (strcasecmp((m_conn)->c_addrtype,			       \
		    COMMP_ADDRTYPE_IP4) == 0) {				       \
			if ((m_conn)->c_addrcount > 1) {		       \
				wrote = snprintf(buf, len, "c=%s %s %s/%d/%d"  \
				    "%s", (m_conn)->c_nettype, (m_conn)->      \
				    c_addrtype, (m_conn)->c_address, (m_conn)->\
				    c_ttl, (m_conn)->c_addrcount, COMMP_CRLF); \
			} else if ((m_conn)->c_addrcount == 1) {	       \
				wrote = snprintf(buf, len, "c=%s %s %s/%d%s",  \
				    (m_conn)->c_nettype, (m_conn)->c_addrtype, \
				    (m_conn)->c_address, (m_conn)->c_ttl,      \
				    COMMP_CRLF);			       \
			} else {					       \
				wrote = snprintf(buf, len, "c=%s %s %s%s",     \
				    (m_conn)->c_nettype, (m_conn)->c_addrtype, \
				    (m_conn)->c_address, COMMP_CRLF);	       \
			}						       \
		} else if (strcasecmp((m_conn)->c_addrtype,		       \
		    COMMP_ADDRTYPE_IP6) == 0) {                                \
			if ((m_conn)->c_addrcount <= 1) {		       \
				wrote = snprintf(buf, len, "c=%s %s %s%s",     \
				    (m_conn)->c_nettype, (m_conn)->c_addrtype, \
				    (m_conn)->c_address, COMMP_CRLF);	       \
			} else {					       \
				wrote = snprintf(buf, len, "c=%s %s %s/%d%s",  \
				    (m_conn)->c_nettype, (m_conn)->c_addrtype, \
				    (m_conn)->c_address, (m_conn)->c_addrcount,\
				    COMMP_CRLF);			       \
			}						       \
		} else {						       \
			wrote = snprintf(buf, len, "c=%s %s %s%s", (m_conn)->  \
			    c_nettype, (m_conn)->c_addrtype, (m_conn)->        \
			    c_address, COMMP_CRLF);			       \
		}							       \
		len = len - wrote;					       \
		buf = buf + wrote;					       \
		(m_conn) = (m_conn)->c_next;				       \
	}								       \
}

#define	SDP_ADD_KEY(d_key, s_key) {					\
	if ((s_key) != NULL) {						\
		if (sdp_add_key(&(d_key), (s_key)->k_method,		\
		    (s_key)->k_enckey) != 0) {				\
			sdp_free_session(new_sess);			\
			return (NULL);					\
		}							\
	}								\
}

#define	SDP_ADD_ATTRIBUTE(d_attr, s_attr) {				\
	while ((s_attr) != NULL) {					\
		if (sdp_add_attribute(&(d_attr), (s_attr)->a_name,	\
		    (s_attr)->a_value) != 0) {		 		\
			sdp_free_session(new_sess);			\
			return (NULL);					\
		}							\
		(s_attr) = (s_attr)->a_next;				\
	}								\
}

#define	SDP_ADD_BANDWIDTH(d_bw, s_bw) {					\
	while ((s_bw) != NULL) {					\
		if (sdp_add_bandwidth(&(d_bw), (s_bw)->b_type,		\
		    (s_bw)->b_value) != 0) {				\
			sdp_free_session(new_sess);			\
			return (NULL);					\
		}							\
		(s_bw) = (s_bw)->b_next;				\
	}								\
}

#define	SDP_ADD_CONNECTION(d_conn, s_conn) {				\
	while ((s_conn) != NULL) {					\
		if (sdp_add_connection(&(d_conn), (s_conn)->c_nettype,	\
		    (s_conn)->c_addrtype, (s_conn)->c_address,		\
		    (s_conn)->c_ttl, (s_conn)->c_addrcount) != 0) {	\
			sdp_free_session(new_sess);			\
			return (NULL);					\
		}							\
		(s_conn) = (s_conn)->c_next;				\
	}								\
}

#define	SDP_LEN_CONNECTION(m_conn) {					  \
	while ((m_conn) != NULL) {					  \
		len += FIELD_EQUALS_CRLF_LEN;				  \
		len += strlen((m_conn)->c_nettype);			  \
		len += strlen((m_conn)->c_addrtype) + 1;		  \
		len += strlen((m_conn)->c_address) + 1;			  \
		len += snprintf(buf, 1, "%u", (m_conn)->c_ttl) + 1;	  \
		len += snprintf(buf, 1, "%d", (m_conn)->c_addrcount) + 1; \
		(m_conn) = (m_conn)->c_next;				  \
	}								  \
}

#define	SDP_LEN_BANDWIDTH(m_bw) {					\
	while ((m_bw) != NULL) {					\
		len += FIELD_EQUALS_CRLF_LEN;				\
		len += strlen((m_bw)->b_type);				\
		len += snprintf(buf, 1, "%llu", (m_bw)->b_value) + 1;	\
		(m_bw) = (m_bw)->b_next;				\
	}								\
}

#define	SDP_LEN_KEY(m_key) {						\
	if ((m_key) != NULL) {						\
		len += FIELD_EQUALS_CRLF_LEN;				\
		len += strlen((m_key)->k_method);			\
		if ((m_key)->k_enckey != NULL)				\
			len += strlen((m_key)->k_enckey) + 1;		\
	}								\
}

#define	SDP_LEN_ATTRIBUTE(m_attr) {					\
	while ((m_attr) != NULL) {					\
		len += FIELD_EQUALS_CRLF_LEN;				\
		len += strlen((m_attr)->a_name);			\
		if ((m_attr)->a_value != NULL)				\
			len += strlen((m_attr)->a_value) + 1;		\
		(m_attr) = (m_attr)->a_next;				\
	}								\
}

/*
 * Given a media list and media name ("audio", "video", et al), it searches
 * the list for that media. Returns NULL if media not present.
 */
sdp_media_t *
sdp_find_media(sdp_media_t *media, const char *name)
{
	if (media == NULL || name == NULL || (strlen(name) == 0)) {
		return (NULL);
	}
	while (media != NULL) {
		if (media->m_name != NULL) {
			if (strcasecmp(name, media->m_name) == 0)
				return (media);
		}
		media = media->m_next;
	}
	return (media);
}

/*
 * Given a attribute list and name of the attribute ("rtpmap", "fmtp", et al),
 * this API searches the list for that attribute. Returns NULL if not found.
 */
sdp_attr_t *
sdp_find_attribute(sdp_attr_t *attr, const char *name)
{
	if (attr == NULL || name == NULL || (strlen(name) == 0)) {
		return (NULL);
	}
	while (attr != NULL) {
		if (attr->a_name != NULL) {
			if (strcasecmp(attr->a_name, name) == 0)
				return (attr);
		}
		attr = attr->a_next;
	}
	return (attr);
}

/*
 * Given a media list and a format number, this API will return the rtpmap
 * attribute matching the format number.
 */
sdp_attr_t *
sdp_find_media_rtpmap(sdp_media_t *media, const char *format)
{
	sdp_attr_t		*attr = NULL;
	char			*tmp = NULL;

	if (media == NULL || format == NULL || (strlen(format) == 0)) {
		return (NULL);
	}
	attr = media->m_attr;
	while (attr != NULL) {
		if (attr->a_name != NULL && (strcasecmp(attr->a_name,
		    SDP_RTPMAP) == 0)) {
			if (attr->a_value != NULL) {
				tmp = attr->a_value;
				while (isspace(*tmp))
					++tmp;
				if (strncasecmp(tmp, format,
				    strlen(format)) == 0) {
					return (attr);
				}
			}
		}
		attr = attr->a_next;
	}
	return (attr);
}

/*
 * Adds origin field to the session.
 * o=<username> <sess-id> <sess-version> <nettype> <addrtype> <unicast-address>
 */
int
sdp_add_origin(sdp_session_t *session, const char *name, uint64_t id,
    uint64_t ver, const char *nettype, const char *addrtype,
    const char *address)
{
	sdp_origin_t		*origin;
	int			ret = 0;

	if (session == NULL || name == NULL || nettype == NULL ||
	    addrtype == NULL || address == NULL) {
		return (EINVAL);
	}
	if (session->s_origin != NULL)
		return (EPROTO);
	origin = calloc(1, sizeof (sdp_origin_t));
	if (origin == NULL)
		return (ENOMEM);
	origin->o_id = id;
	origin->o_version = ver;
	if ((ret = commp_add_str(&origin->o_username, name, strlen(name))) != 0)
		goto err_ret;
	if ((ret = commp_add_str(&origin->o_nettype, nettype,
	    strlen(nettype))) != 0) {
		goto err_ret;
	}
	if ((ret = commp_add_str(&origin->o_addrtype, addrtype,
	    strlen(addrtype))) != 0) {
		goto err_ret;
	}
	if ((ret = commp_add_str(&origin->o_address, address,
	    strlen(address))) != 0) {
		goto err_ret;
	}
	session->s_origin = origin;
	return (ret);
err_ret:
	sdp_free_origin(origin);
	return (ret);
}

/*
 * Adds session name field to the session.
 * s=<session name>
 */
int
sdp_add_name(sdp_session_t *session, const char *name)
{
	if (session == NULL || name == NULL)
		return (EINVAL);
	if (session->s_name != NULL)
		return (EPROTO);
	return (commp_add_str(&session->s_name, name, strlen(name)));
}

/*
 * Adds session information field to the session or media section of SDP.
 * i=<session description>
 */
int
sdp_add_information(char **information, const char *value)
{
	if (information == NULL || value == NULL)
		return (EINVAL);
	if (*information != NULL)
		return (EPROTO);
	return (commp_add_str(information, value, strlen(value)));
}

/*
 * Adds uri field to the session.
 * u=<uri>
 */
int
sdp_add_uri(sdp_session_t *session, const char *uri)
{
	if (session == NULL || uri == NULL)
		return (EINVAL);
	if (session->s_uri != NULL)
		return (EPROTO);
	return (commp_add_str(&session->s_uri, uri, strlen(uri)));
}

/*
 * Adds email address field to the session.
 * e=<email-address>
 */
int
sdp_add_email(sdp_session_t *session, const char *email)
{
	if (session == NULL || email == NULL || (strlen(email) == 0))
		return (EINVAL);
	return (add_value_to_list(&session->s_email, email, strlen(email),
	    B_TRUE));
}

/*
 * Adds phone number field to the session.
 * p=<phone-number>
 */
int
sdp_add_phone(sdp_session_t *session, const char *phone)
{
	if (session == NULL || phone == NULL || (strlen(phone) == 0))
		return (EINVAL);
	return (add_value_to_list(&session->s_phone, phone, strlen(phone),
	    B_TRUE));
}

/*
 * Adds connection field to the session or media section of SDP
 * c=<nettype> <addrtype> <connection-address>[/ttl]/<number of addresses>
 */
int
sdp_add_connection(sdp_conn_t **conn, const char *nettype, const char *addrtype,
    const char *address, uint8_t ttl, int addrcount)
{
	sdp_conn_t		*tmp;
	sdp_conn_t		*new_conn;
	int			ret = 0;

	if (conn == NULL || nettype == NULL || addrtype == NULL ||
	    address == NULL) {
		return (EINVAL);
	}
	new_conn = calloc(1, sizeof (sdp_conn_t));
	if (new_conn == NULL)
		return (ENOMEM);
	new_conn->c_ttl = ttl;
	new_conn->c_addrcount = addrcount;
	if ((ret = commp_add_str(&new_conn->c_nettype, nettype,
	    strlen(nettype))) != 0) {
		goto err_ret;
	}
	if ((ret = commp_add_str(&new_conn->c_addrtype, addrtype,
	    strlen(addrtype))) != 0) {
		goto err_ret;
	}
	if ((ret = commp_add_str(&new_conn->c_address, address,
	    strlen(address))) != 0) {
		goto err_ret;
	}
	if (*conn == NULL) {
		*conn = new_conn;
	} else {
		tmp = *conn;
		while (tmp->c_next != NULL)
			tmp = tmp->c_next;
		tmp->c_next = new_conn;
	}
	return (ret);
err_ret:
	sdp_free_connection(new_conn);
	return (ret);
}

/*
 * Adds bandwidth field to the session or media section of SDP.
 * b=<bwtype>:<bandwidth>
 */
int
sdp_add_bandwidth(sdp_bandwidth_t **bw, const char *type, uint64_t value)
{
	sdp_bandwidth_t		*new_bw;
	sdp_bandwidth_t		*tmp;
	int			ret = 0;

	if (bw == NULL || type == NULL)
		return (EINVAL);
	new_bw = calloc(1, sizeof (sdp_bandwidth_t));
	if (new_bw == NULL)
		return (ENOMEM);
	new_bw->b_value = value;
	if ((ret = commp_add_str(&new_bw->b_type, type, strlen(type))) != 0) {
		free(new_bw);
		return (ret);
	}
	if (*bw == NULL) {
		*bw = new_bw;
	} else {
		tmp = *bw;
		while (tmp->b_next != NULL)
			tmp = tmp->b_next;
		tmp->b_next = new_bw;
	}
	return (ret);
}

/*
 * Adds time field to the session
 * t=<start-time> <stop-time>
 */
int
sdp_add_time(sdp_session_t *session, uint64_t starttime, uint64_t stoptime,
    sdp_time_t **time)
{
	sdp_time_t		*new_time;
	sdp_time_t		*tmp;

	if (time != NULL)
		*time = NULL;
	if (session == NULL) {
		return (EINVAL);
	}
	new_time = calloc(1, sizeof (sdp_time_t));
	if (new_time == NULL) {
		return (ENOMEM);
	}
	new_time->t_start = starttime;
	new_time->t_stop = stoptime;
	tmp = session->s_time;
	if (tmp == NULL)
		session->s_time = new_time;
	else {
		while (tmp->t_next != NULL)
			tmp = tmp->t_next;
		tmp->t_next = new_time;
	}
	if (time != NULL)
		*time = new_time;
	return (0);
}

/*
 * Adds repeat field to the time structure of session
 * r=<repeat interval> <active duration> <offsets from start-time>
 */
int
sdp_add_repeat(sdp_time_t *time, uint64_t interval, uint64_t duration,
    const char *offset)
{
	sdp_repeat_t		*tmp;
	sdp_repeat_t		*new_repeat;
	int			ret = 0;

	if (time == NULL || offset == NULL)
		return (EINVAL);
	new_repeat = calloc(1, sizeof (sdp_repeat_t));
	if (new_repeat == NULL)
		return (ENOMEM);
	new_repeat->r_interval = interval;
	new_repeat->r_duration = duration;
	if ((ret = sdp_str_to_list(&new_repeat->r_offset, offset,
	    strlen(offset), B_FALSE)) != 0) {
		goto err_ret;
	}
	tmp = time->t_repeat;
	if (tmp == NULL) {
		time->t_repeat = new_repeat;
	} else {
		while (tmp->r_next != NULL)
			tmp = tmp->r_next;
		tmp->r_next = new_repeat;
	}
	return (ret);
err_ret:
	sdp_free_repeat(new_repeat);
	return (ret);
}

/*
 * Adds time zone field to the session
 * z=<adjustment time> <offset> <adjustment time> <offset> ....
 */
int
sdp_add_zone(sdp_session_t *session, uint64_t time, const char *offset)
{
	sdp_zone_t		*new_zone;
	sdp_zone_t		*tmp;
	int			ret = 0;

	if (session == NULL || offset == NULL)
		return (EINVAL);
	new_zone = calloc(1, sizeof (sdp_zone_t));
	if (new_zone == NULL)
		return (ENOMEM);
	new_zone->z_time = time;
	if ((ret = commp_add_str(&new_zone->z_offset, offset,
	    strlen(offset))) != 0) {
		free(new_zone);
		return (ret);
	}
	tmp = session->s_zone;
	if (tmp == NULL) {
		session->s_zone = new_zone;
	} else {
		while (tmp->z_next != NULL) {
			tmp = tmp->z_next;
		}
		tmp->z_next = new_zone;
	}
	return (ret);
}

/*
 * Adds key field to session or media section of SDP.
 * k=<method>
 * k=<method>:<encryption key>
 */
int
sdp_add_key(sdp_key_t **key, const char *method, const char *enckey)
{
	int			ret = 0;

	if (key == NULL || method == NULL)
		return (EINVAL);
	if (*key != NULL)
		return (EPROTO);
	*key = calloc(1, sizeof (sdp_key_t));
	if (*key == NULL)
		return (ENOMEM);
	if ((ret = commp_add_str(&((*key)->k_method), method,
	    strlen(method))) != 0) {
		goto err_ret;
	}
	if (enckey != NULL) {
		if ((ret = commp_add_str(&((*key)->k_enckey), enckey,
		    strlen(enckey))) != 0) {
			goto err_ret;
		}
	}
	return (ret);
err_ret:
	sdp_free_key(*key);
	*key = NULL;
	return (ret);
}

/*
 * Adds attribute field to session or media section of SDP.
 * a=<attribute>
 * a=<attribute>:<value>
 */
int
sdp_add_attribute(sdp_attr_t **attr, const char *name, const char *value)
{
	sdp_attr_t		*tmp;
	sdp_attr_t		*new_attr;
	int			ret = 0;

	if (attr == NULL || name == NULL)
		return (EINVAL);
	new_attr = calloc(1, sizeof (sdp_attr_t));
	if (new_attr == NULL)
		return (ENOMEM);
	if ((ret = commp_add_str(&new_attr->a_name, name, strlen(name))) != 0)
		goto err_ret;
	if (value != NULL) {
		if ((ret = commp_add_str(&new_attr->a_value, value,
		    strlen(value))) != 0) {
			goto err_ret;
		}
	}
	tmp = *attr;
	if (tmp == NULL) {
		*attr = new_attr;
	} else {
		while (tmp->a_next != NULL)
			tmp = tmp->a_next;
		tmp->a_next = new_attr;
	}
	return (ret);
err_ret:
	sdp_free_attribute(new_attr);
	return (ret);
}

/*
 * Adds media field to the session.
 * m=<media> <port>[/portcount] <proto> <fmt> ...
 */
int
sdp_add_media(sdp_session_t *session, const char *name, uint_t port,
    int portcount, const char *protocol, const char *fmt, sdp_media_t **media)
{
	sdp_media_t		*tmp;
	sdp_media_t		*new_media;
	int			ret = 0;

	if (media != NULL)
		*media = NULL;
	if (session == NULL || name == NULL || protocol == NULL ||
	    portcount <= 0 || fmt == NULL) {
		return (EINVAL);
	}
	new_media = calloc(1, sizeof (sdp_media_t));
	if (new_media == NULL) {
		return (ENOMEM);
	}
	new_media->m_session = session;
	new_media->m_port = port;
	new_media->m_portcount = portcount;
	if ((ret = commp_add_str(&new_media->m_name, name, strlen(name))) != 0)
		goto err_ret;
	if ((ret = commp_add_str(&new_media->m_proto, protocol,
	    strlen(protocol))) != 0) {
		goto err_ret;
	}
	if ((ret = sdp_str_to_list(&new_media->m_format, fmt,
	    strlen(fmt), B_TRUE)) != 0) {
		goto err_ret;
	}
	tmp = session->s_media;
	if (tmp == NULL) {
		session->s_media = new_media;
	} else {
		while (tmp->m_next != NULL)
			tmp = tmp->m_next;
		tmp->m_next = new_media;
	}
	if (media != NULL)
		*media = new_media;
	return (0);
err_ret:
	sdp_free_media(new_media);
	return (ret);
}

/*
 * This internal API is required by sdp_session_to_str(). It determines the
 * length of buffer that is required to hold the session. Since the RFC does
 * not limit the size of various sub-fields in the field. We need to scan
 * through the structure to determine the length.
 */
int
sdp_get_length(const sdp_session_t *session)
{
	int			len = 0;
	char			buf[1];
	sdp_list_t		*list;
	sdp_conn_t		*conn;
	sdp_bandwidth_t		*bw;
	sdp_zone_t		*zone;
	sdp_time_t		*time;
	sdp_repeat_t		*repeat;
	sdp_attr_t		*attr;
	sdp_media_t		*media;

	len += FIELD_EQUALS_CRLF_LEN;
	len += snprintf(buf, 1, "%d", session->s_version);
	if (session->s_origin != NULL) {
		len += FIELD_EQUALS_CRLF_LEN;
		len += strlen(session->s_origin->o_username);
		len += snprintf(buf, 1, "%llu", session->s_origin->o_id) + 1;
		len += snprintf(buf, 1, "%llu", session->s_origin->o_version)
		    + 1;
		len += strlen(session->s_origin->o_nettype) + 1;
		len += strlen(session->s_origin->o_addrtype) + 1;
		len += strlen(session->s_origin->o_address) + 1;
	}
	if (session->s_name != NULL)
		len += strlen(session->s_name) + FIELD_EQUALS_CRLF_LEN;
	if (session->s_info != NULL)
		len += strlen(session->s_info) + FIELD_EQUALS_CRLF_LEN;
	if (session->s_uri != NULL)
		len += strlen(session->s_uri) + FIELD_EQUALS_CRLF_LEN;
	list = session->s_email;
	while (list != NULL) {
		len += strlen((char *)list->value) + FIELD_EQUALS_CRLF_LEN;
		list = list->next;
	}
	list = session->s_phone;
	while (list != NULL) {
		len += strlen((char *)list->value) + FIELD_EQUALS_CRLF_LEN;
		list = list->next;
	}
	conn = session->s_conn;
	SDP_LEN_CONNECTION(conn);
	bw = session->s_bw;
	SDP_LEN_BANDWIDTH(bw);
	time = session->s_time;
	while (time != NULL) {
		len += FIELD_EQUALS_CRLF_LEN;
		len += snprintf(buf, 1, "%llu", time->t_start);
		len += snprintf(buf, 1, "%llu", time->t_stop) + 1;
		repeat = time->t_repeat;
		while (repeat != NULL) {
			len += FIELD_EQUALS_CRLF_LEN;
			len += snprintf(buf, 1, "%llu", repeat->r_interval);
			len += snprintf(buf, 1, "%llu", repeat->r_duration) + 1;
			list = repeat->r_offset;
			while (list != NULL) {
				len += snprintf(buf, 1, "%llu",
				    *(uint64_t *)list->value) + 1;
				list = list->next;
			}
			repeat = repeat->r_next;
		}
		time = time->t_next;
	}
	if (session->s_zone != NULL)
		len += FIELD_EQUALS_CRLF_LEN;
	zone = session->s_zone;
	while (zone != NULL) {
		len += snprintf(buf, 1, "%llu", zone->z_time) + 1;
		len += strlen(zone->z_offset) + 1;
		zone = zone->z_next;
	}
	SDP_LEN_KEY(session->s_key);
	attr = session->s_attr;
	SDP_LEN_ATTRIBUTE(attr);
	media = session->s_media;
	while (media != NULL) {
		len += FIELD_EQUALS_CRLF_LEN;
		len += strlen(media->m_name);
		len += snprintf(buf, 1, "%u", media->m_port) + 1;
		len += snprintf(buf, 1, "%d", media->m_portcount) + 1;
		len += strlen(media->m_proto) + 1;
		list = media->m_format;
		while (list != NULL) {
			len += strlen((char *)list->value) + 1;
			list = list->next;
		}
		if (media->m_info != NULL)
			len += strlen(media->m_info) + FIELD_EQUALS_CRLF_LEN;
		conn = media->m_conn;
		SDP_LEN_CONNECTION(conn);
		bw = media->m_bw;
		SDP_LEN_BANDWIDTH(bw);
		SDP_LEN_KEY(media->m_key);
		attr = media->m_attr;
		SDP_LEN_ATTRIBUTE(attr);
		media = media->m_next;
	}
	return (len);
}

/*
 * Given a session structure it clones (deep copy) and returns the cloned copy
 */
sdp_session_t *
sdp_clone_session(const sdp_session_t *session)
{
	sdp_session_t		*new_sess;
	sdp_origin_t		*origin;
	sdp_list_t		*list;
	sdp_time_t		*time;
	sdp_time_t		*new_time;
	sdp_repeat_t		*repeat;
	sdp_media_t		*media;
	sdp_media_t		*new_media;
	sdp_conn_t		*conn;
	sdp_bandwidth_t		*bw;
	sdp_attr_t		*attr;
	sdp_zone_t		*zone;
	char			*offset = NULL;
	char			*format = NULL;

	if (session == NULL)
		return (NULL);
	new_sess = calloc(1, sizeof (sdp_session_t));
	if (new_sess == NULL)
		return (NULL);
	new_sess->sdp_session_version = session->sdp_session_version;
	new_sess->s_version = session->s_version;
	origin = session->s_origin;
	if (origin != NULL && (sdp_add_origin(new_sess, origin->o_username,
	    origin->o_id, origin->o_version, origin->o_nettype, origin->
	    o_addrtype, origin->o_address) != 0)) {
		goto err_ret;
	}
	if (session->s_name != NULL && sdp_add_name(new_sess, session->
	    s_name) != 0) {
		goto err_ret;
	}
	if (session->s_info != NULL && sdp_add_information(&new_sess->
	    s_info, session->s_info) != 0) {
		goto err_ret;
	}
	if (session->s_uri != NULL && sdp_add_uri(new_sess, session->
	    s_uri) != 0) {
		goto err_ret;
	}
	list = session->s_email;
	while (list != NULL) {
		if (sdp_add_email(new_sess, (char *)list->value) != 0)
			goto err_ret;
		list = list->next;
	}
	list = session->s_phone;
	while (list != NULL) {
		if (sdp_add_phone(new_sess, (char *)list->value) != 0)
			goto err_ret;
		list = list->next;
	}
	conn = session->s_conn;
	SDP_ADD_CONNECTION(new_sess->s_conn, conn);
	bw = session->s_bw;
	SDP_ADD_BANDWIDTH(new_sess->s_bw, bw);
	time = session->s_time;
	while (time != NULL) {
		if (sdp_add_time(new_sess, time->t_start, time->t_stop,
		    &new_time) != 0) {
			goto err_ret;
		}
		repeat = time->t_repeat;
		while (repeat != NULL) {
			if (sdp_list_to_str(repeat->r_offset, &offset,
			    B_FALSE) != 0) {
				goto err_ret;
			}
			if (sdp_add_repeat(new_time, repeat->r_interval,
			    repeat->r_duration, offset) != 0) {
				free(offset);
				goto err_ret;
			}
			free(offset);
			repeat = repeat->r_next;
		}
		time = time->t_next;
	}
	zone = session->s_zone;
	while (zone != NULL) {
		if (sdp_add_zone(new_sess, zone->z_time, zone->z_offset) != 0)
			goto err_ret;
		zone = zone->z_next;
	}
	SDP_ADD_KEY(new_sess->s_key, session->s_key);
	attr = session->s_attr;
	SDP_ADD_ATTRIBUTE(new_sess->s_attr, attr);
	media = session->s_media;
	while (media != NULL) {
		if (sdp_list_to_str(media->m_format, &format, B_TRUE) != 0)
			goto err_ret;
		if (sdp_add_media(new_sess, media->m_name,
		    media->m_port, media->m_portcount, media->m_proto,
		    format, &new_media) != 0) {
			free(format);
			goto err_ret;
		}
		free(format);
		if (media->m_info != NULL) {
			if (sdp_add_information(&new_media->m_info,
			    media->m_info) != 0) {
				goto err_ret;
			}
		}
		conn = media->m_conn;
		SDP_ADD_CONNECTION(new_media->m_conn, conn);
		bw = media->m_bw;
		SDP_ADD_BANDWIDTH(new_media->m_bw, bw);
		SDP_ADD_KEY(new_media->m_key, media->m_key);
		attr = media->m_attr;
		SDP_ADD_ATTRIBUTE(new_media->m_attr, attr);
		new_media->m_session = new_sess;
		media = media->m_next;
	}
	return (new_sess);
err_ret:
	sdp_free_session(new_sess);
	return (NULL);
}

/*
 * should i check if individual members are NULL, if not snprintf
 * will core dump.
 */
/*
 * Given a session structure, this API converts it into character
 * buffer, which will be used as a payload later on.
 */
char *
sdp_session_to_str(const sdp_session_t *session, int *error)
{
	char			*ret = NULL;
	char			*buf = NULL;
	int			len = 0;
	int			s_len = 0;
	int			wrote = 0;
	sdp_origin_t		*origin;
	sdp_list_t		*list;
	sdp_conn_t		*conn;
	sdp_attr_t		*attr;
	sdp_bandwidth_t		*bw;
	sdp_time_t		*time;
	sdp_repeat_t		*repeat;
	sdp_zone_t		*zone;
	sdp_media_t		*media;

	if (error != NULL)
		*error = 0;
	if (session == NULL) {
		if (error != NULL)
			*error = EINVAL;
		return (NULL);
	}
	s_len = sdp_get_length(session);
	ret = malloc(s_len + 1);
	if (ret == NULL) {
		if (error != NULL)
			*error = ENOMEM;
		return (NULL);
	}
	buf = ret;
	len = s_len + 1;
	wrote = snprintf(buf, len, "v=%d%s", session->s_version, COMMP_CRLF);
	len = len - wrote;
	buf = buf + wrote;
	origin = session->s_origin;
	if (origin != NULL) {
		wrote = snprintf(buf, len, "o=%s %llu %llu %s %s %s%s",
		    origin->o_username, origin->o_id, origin->o_version,
		    origin->o_nettype, origin->o_addrtype, origin->o_address,
		    COMMP_CRLF);
		len = len - wrote;
		buf = buf + wrote;
	}
	if (session->s_name != NULL) {
		wrote = snprintf(buf, len, "s=%s%s", session->s_name,
		    COMMP_CRLF);
		len = len - wrote;
		buf = buf + wrote;
	}
	SDP_INFORMATION_TO_STR(session->s_info);
	if (session->s_uri != NULL) {
		wrote = snprintf(buf, len, "u=%s%s", session->s_uri,
		    COMMP_CRLF);
		len = len - wrote;
		buf = buf + wrote;
	}
	list = session->s_email;
	while (list != NULL) {
		wrote = snprintf(buf, len, "e=%s%s", (char *)list->value,
		    COMMP_CRLF);
		len = len - wrote;
		buf = buf + wrote;
		list = list->next;
	}
	list = session->s_phone;
	while (list != NULL) {
		wrote = snprintf(buf, len, "p=%s%s", (char *)list->value,
		    COMMP_CRLF);
		len = len - wrote;
		buf = buf + wrote;
		list = list->next;
	}
	conn = session->s_conn;
	SDP_CONNECTION_TO_STR(conn);
	bw = session->s_bw;
	SDP_BANDWIDTH_TO_STR(bw);
	time = session->s_time;
	while (time != NULL) {
		wrote = snprintf(buf, len, "t=%llu %llu%s", time->t_start,
		    time->t_stop, COMMP_CRLF);
		len = len - wrote;
		buf = buf + wrote;
		repeat = time->t_repeat;
		while (repeat != NULL) {
			wrote = snprintf(buf, len, "r=%llu %llu", repeat->
			    r_interval, repeat->r_duration);
			len = len - wrote;
			buf = buf + wrote;
			list = repeat->r_offset;
			while (list != NULL) {
				wrote = snprintf(buf, len, " %llu",
				    *(uint64_t *)list->value);
				len = len - wrote;
				buf = buf + wrote;
				list = list->next;
			}
			wrote = snprintf(buf, len, "%s", COMMP_CRLF);
			len = len - wrote;
			buf = buf + wrote;
			repeat = repeat->r_next;
		}
		time = time->t_next;
	}
	zone = session->s_zone;
	if (zone != NULL) {
		wrote = snprintf(buf, len, "z=%llu %s", zone->z_time,
		    zone->z_offset);
		len = len - wrote;
		buf = buf + wrote;
		zone = zone->z_next;
		while (zone != NULL) {
			wrote = snprintf(buf, len, " %llu %s", zone->z_time,
			    zone->z_offset);
			len = len - wrote;
			buf = buf + wrote;
			zone = zone->z_next;
		}
		wrote = snprintf(buf, len, "%s", COMMP_CRLF);
		len = len - wrote;
		buf = buf + wrote;
	}
	SDP_KEY_TO_STR(session->s_key);
	attr = session->s_attr;
	SDP_ATTR_TO_STR(attr);
	media = session->s_media;
	while (media != NULL) {
		if (media->m_portcount == 1) {
			wrote = snprintf(buf, len, "m=%s %d %s", media->m_name,
			    media->m_port, media->m_proto);
		} else {
			wrote = snprintf(buf, len, "m=%s %d/%d %s", media->
			    m_name, media->m_port, media->m_portcount, media->
			    m_proto);
		}
		len = len - wrote;
		buf = buf + wrote;
		list = media->m_format;
		while (list != NULL) {
			wrote = snprintf(buf, len, " %s", (char *)list->value);
			len = len - wrote;
			buf = buf + wrote;
			list = list->next;
		}
		wrote = snprintf(buf, len, "%s", COMMP_CRLF);
		len = len - wrote;
		buf = buf + wrote;
		SDP_INFORMATION_TO_STR(media->m_info);
		conn = media->m_conn;
		SDP_CONNECTION_TO_STR(conn);
		bw = media->m_bw;
		SDP_BANDWIDTH_TO_STR(bw);
		SDP_KEY_TO_STR(media->m_key);
		attr = media->m_attr;
		SDP_ATTR_TO_STR(attr);
		media = media->m_next;
	}
	assert(len >= 1);
	*buf = '\0';
	return (ret);
}

/*
 * Given a session structure and the field ('v', 'o', 's', et al), this API
 * deletes the corresponding structure element. It frees the memory and sets the
 * pointer to NULL
 */
int
sdp_delete_all_field(sdp_session_t *session, const char field)
{
	if (session == NULL)
		return (EINVAL);
	switch (field) {
		case SDP_ORIGIN_FIELD:
			sdp_free_origin(session->s_origin);
			session->s_origin = NULL;
			break;
		case SDP_NAME_FIELD:
			free(session->s_name);
			session->s_name = NULL;
			break;
		case SDP_INFO_FIELD:
			free(session->s_info);
			session->s_info = NULL;
			break;
		case SDP_URI_FIELD:
			free(session->s_uri);
			session->s_uri = NULL;
			break;
		case SDP_EMAIL_FIELD:
			sdp_free_list(session->s_email);
			session->s_email = NULL;
			break;
		case SDP_PHONE_FIELD:
			sdp_free_list(session->s_phone);
			session->s_phone = NULL;
			break;
		case SDP_CONNECTION_FIELD:
			sdp_free_connection(session->s_conn);
			session->s_conn = NULL;
			break;
		case SDP_BANDWIDTH_FIELD:
			sdp_free_bandwidth(session->s_bw);
			session->s_bw = NULL;
			break;
		case SDP_TIME_FIELD:
			sdp_free_time(session->s_time);
			session->s_time = NULL;
			break;
		case SDP_ZONE_FIELD:
			sdp_free_zone(session->s_zone);
			session->s_zone = NULL;
			break;
		case SDP_KEY_FIELD:
			sdp_free_key(session->s_key);
			session->s_key = NULL;
			break;
		case SDP_ATTRIBUTE_FIELD:
			sdp_free_attribute(session->s_attr);
			session->s_attr = NULL;
			break;
		case SDP_MEDIA_FIELD:
			sdp_free_media(session->s_media);
			session->s_media = NULL;
			break;
		default:
			return (EINVAL);
	}
	return (0);
}

/*
 * Given a media structure and the field ('i', 'b', 'c', et al), this API
 * deletes the corresponding structure element. It frees the memory and sets
 * the pointer to NULL.
 */
int
sdp_delete_all_media_field(sdp_media_t *media, const char field)
{
	if (media == NULL)
		return (EINVAL);
	switch (field) {
		case SDP_INFO_FIELD:
			free(media->m_info);
			media->m_info = NULL;
			break;
		case SDP_CONNECTION_FIELD:
			sdp_free_connection(media->m_conn);
			media->m_conn = NULL;
			break;
		case SDP_BANDWIDTH_FIELD:
			sdp_free_bandwidth(media->m_bw);
			media->m_bw = NULL;
			break;
		case SDP_KEY_FIELD:
			sdp_free_key(media->m_key);
			media->m_key = NULL;
			break;
		case SDP_ATTRIBUTE_FIELD:
			sdp_free_attribute(media->m_attr);
			media->m_attr = NULL;
			break;
		default:
			return (EINVAL);
	}
	return (0);
}

/*
 * Given a media list and the media, this API deletes that media from the
 * list. It frees the memory corresponding to that media.
 */
int
sdp_delete_media(sdp_media_t **l_media, sdp_media_t *media)
{
	sdp_media_t		*cur;
	sdp_media_t		*prev;

	if (l_media == NULL || *l_media == NULL || media == NULL)
		return (EINVAL);
	cur = *l_media;
	prev = NULL;
	while (cur != NULL && cur != media) {
		prev = cur;
		cur = cur->m_next;
	}
	if (cur == NULL)
		return (EINVAL);
	if (cur == *l_media)
		*l_media = cur->m_next;
	else
		prev->m_next = cur->m_next;
	cur->m_next = NULL;
	sdp_free_media(cur);
	return (0);
}

/*
 * Given an attribute list and an attribute, this API deletes that attribue
 * from the list. It frees the memory corresponding to that attribute.
 */
int
sdp_delete_attribute(sdp_attr_t **l_attr, sdp_attr_t *attr)
{
	sdp_attr_t		*cur;
	sdp_attr_t		*prev;

	if (l_attr == NULL || *l_attr == NULL || attr == NULL)
		return (EINVAL);
	cur = *l_attr;
	prev = NULL;
	while (cur != NULL && cur != attr) {
		prev = cur;
		cur = cur->a_next;
	}
	if (cur == NULL)
		return (EINVAL);
	if (cur == *l_attr)
		*l_attr = cur->a_next;
	else
		prev->a_next = cur->a_next;
	cur->a_next = NULL;
	sdp_free_attribute(cur);
	return (0);
}

/*
 * Allocates a new sdp session structure and assigns a version number to it.
 * Currently one version is defined and it is 1. This will be useful in future
 * in the unlikely need to change the structure.
 */
sdp_session_t *
sdp_new_session()
{
	sdp_session_t	*session = NULL;

	session = calloc(1, sizeof (sdp_session_t));
	if (session != NULL)
		session->sdp_session_version = SDP_SESSION_VERSION_1;
	return (session);
}
