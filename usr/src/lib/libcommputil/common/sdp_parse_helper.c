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
 * Helper functions to skip white spaces, find tokens, find separators and free
 * memory.
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

void
sdp_free_origin(sdp_origin_t *origin)
{
	if (origin != NULL) {
		if (origin->o_username != NULL)
			free(origin->o_username);
		if (origin->o_nettype != NULL)
			free(origin->o_nettype);
		if (origin->o_addrtype != NULL)
			free(origin->o_addrtype);
		if (origin->o_address != NULL)
			free(origin->o_address);
		free(origin);
	}
}

void
sdp_free_key(sdp_key_t *key)
{
	if (key != NULL) {
		if (key->k_method != NULL)
			free(key->k_method);
		if (key->k_enckey != NULL)
			free(key->k_enckey);
		free(key);
	}
}

void
sdp_free_zone(sdp_zone_t *zone)
{
	sdp_zone_t	*next_zone;

	while (zone != NULL) {
		next_zone = zone->z_next;
		if (zone->z_offset != NULL)
			free(zone->z_offset);
		free(zone);
		zone = next_zone;
	}
}

void
sdp_free_list(sdp_list_t *list)
{
	sdp_list_t	*next_list;

	while (list != NULL) {
		next_list = list->next;
		if (list->value != NULL)
			free(list->value);
		free(list);
		list = next_list;
	}
}

void
sdp_free_media(sdp_media_t *media)
{
	sdp_media_t	*next_media;

	while (media != NULL) {
		next_media = media->m_next;
		if (media->m_name != NULL)
			free(media->m_name);
		if (media->m_proto != NULL)
			free(media->m_proto);
		if (media->m_format != NULL)
			sdp_free_list(media->m_format);
		if (media->m_info != NULL)
			free(media->m_info);
		if (media->m_conn != NULL)
			sdp_free_connection(media->m_conn);
		if (media->m_bw != NULL)
			sdp_free_bandwidth(media->m_bw);
		if (media->m_key != NULL)
			sdp_free_key(media->m_key);
		if (media->m_attr != NULL)
			sdp_free_attribute(media->m_attr);
		free(media);
		media = next_media;
	}
}

void
sdp_free_attribute(sdp_attr_t *attr)
{
	sdp_attr_t	*next_attr;

	while (attr != NULL) {
		next_attr = attr->a_next;
		if (attr->a_name != NULL)
			free(attr->a_name);
		if (attr->a_value != NULL)
			free(attr->a_value);
		free(attr);
		attr = next_attr;
	}
}

void
sdp_free_connection(sdp_conn_t *conn)
{
	sdp_conn_t	*next_conn;

	while (conn != NULL) {
		next_conn = conn->c_next;
		if (conn->c_nettype != NULL)
			free(conn->c_nettype);
		if (conn->c_addrtype != NULL)
			free(conn->c_addrtype);
		if (conn->c_address != NULL)
			free(conn->c_address);
		free(conn);
		conn = next_conn;
	}
}

void
sdp_free_bandwidth(sdp_bandwidth_t *bw)
{
	sdp_bandwidth_t		*next_bw;

	while (bw != NULL) {
		next_bw = bw->b_next;
		if (bw->b_type != NULL)
			free(bw->b_type);
		free(bw);
		bw = next_bw;
	}
}

void
sdp_free_repeat(sdp_repeat_t *repeat)
{
	sdp_repeat_t	*next_repeat;

	while (repeat != NULL) {
		next_repeat = repeat->r_next;
		sdp_free_list(repeat->r_offset);
		free(repeat);
		repeat = next_repeat;
	}
}

void
sdp_free_time(sdp_time_t *time)
{
	sdp_time_t	*next_time;

	while (time != NULL) {
		next_time = time->t_next;
		sdp_free_repeat(time->t_repeat);
		free(time);
		time = next_time;
	}
}

void
sdp_free_session(sdp_session_t *session)
{
	if (session == NULL)
		return;
	if (session->s_origin != NULL)
		sdp_free_origin(session->s_origin);
	if (session->s_name != NULL)
		free(session->s_name);
	if (session->s_info != NULL)
		free(session->s_info);
	if (session->s_uri != NULL)
		free(session->s_uri);
	if (session->s_email != NULL)
		sdp_free_list(session->s_email);
	if (session->s_phone != NULL)
		sdp_free_list(session->s_phone);
	if (session->s_conn != NULL)
		sdp_free_connection(session->s_conn);
	if (session->s_bw != NULL)
		sdp_free_bandwidth(session->s_bw);
	if (session->s_time != NULL)
		sdp_free_time(session->s_time);
	if (session->s_zone != NULL)
		sdp_free_zone(session->s_zone);
	if (session->s_key != NULL)
		sdp_free_key(session->s_key);
	if (session->s_attr != NULL)
		sdp_free_attribute(session->s_attr);
	if (session->s_media != NULL)
		sdp_free_media(session->s_media);
	free(session);
}

/*
 * Adds text of a given length to a linked list. If the list is NULL to
 * start with it builds the new list
 */
int
add_value_to_list(sdp_list_t **list, const char *value, int len, boolean_t text)
{
	sdp_list_t	*new = NULL;
	sdp_list_t	*tmp = NULL;

	new = malloc(sizeof (sdp_list_t));
	if (new == NULL)
		return (ENOMEM);
	new->next = NULL;
	if (text)
		new->value = (char *)calloc(1, len + 1);
	else
		new->value = (uint64_t *)calloc(1, sizeof (uint64_t));
	if (new->value == NULL) {
		free(new);
		return (ENOMEM);
	}
	if (text) {
		(void) strncpy(new->value, value, len);
	} else {
		if (commp_time_to_secs((char *)value, (char *)(value +
		    len), new->value) != 0) {
			sdp_free_list(new);
			return (EINVAL);
		}
	}
	if (*list == NULL) {
		*list = new;
	} else {
		tmp = *list;
		while (tmp->next != NULL)
			tmp = tmp->next;
		tmp->next = new;
	}
	return (0);
}

/*
 * Given a linked list converts it to space separated string.
 */
int
sdp_list_to_str(sdp_list_t *list, char **buf, boolean_t text)
{
	int 		size = 0;
	int 		wrote = 0;
	sdp_list_t	*tmp;
	char		*ret;
	char		c[1];

	if (list == NULL) {
		*buf = NULL;
		return (EINVAL);
	}
	tmp = list;
	while (list != NULL) {
		if (text)
			size += strlen((char *)list->value);
		else
			size += snprintf(c, 1, "%lld",
			    *(uint64_t *)list->value);
		size++;
		list = list->next;
	}
	list = tmp;
	if (size > 0) {
		*buf = calloc(1, size + 1);
		if (*buf == NULL)
			return (ENOMEM);
		ret = *buf;
		while (list != NULL) {
			if (text) {
				wrote = snprintf(ret, size, "%s ",
				    (char *)list->value);
			} else {
				wrote = snprintf(ret, size, "%lld ",
				    *(uint64_t *)list->value);
			}
			ret = ret + wrote;
			size = size - wrote;
			list = list->next;
		}
	} else {
		return (EINVAL);
	}
	return (0);
}

/*
 * Given a space separated string, converts it into linked list. SDP field
 * repeat and media can have undefined number of offsets or formats
 * respectively. We need to capture it in a linked list.
 */
int
sdp_str_to_list(sdp_list_t **list, const char *buf, int len, boolean_t text)
{
	const char	*begin;
	const char	*current;
	const char	*end;
	int		ret = 0;

	if (len == 0)
		return (EINVAL);
	current = buf;
	end = current + len;
	/* takes care of strings with just spaces */
	if (commp_skip_white_space(&current, end) != 0)
		return (EINVAL);
	while (current < end) {
		(void) commp_skip_white_space(&current, end);
		begin = current;
		while (current < end) {
			if (isspace(*current))
				break;
			++current;
		}
		if (current != begin) {
			if ((ret = add_value_to_list(list, begin,
			    current - begin, text)) != 0) {
				sdp_free_list(*list);
				*list = NULL;
				return (ret);
			}
		}
	}
	return (0);
}
