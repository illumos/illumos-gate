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
 * Parses the SDP description as per the SDP grammar defined in Section 9 of
 * RFC 4566
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sdp.h>

#include "sdp_parse.h"
#include "commp_util.h"

/*
 * proto-version-field (v=)
 * %x76 "=" 1*DIGIT CRLF
 */
static void
sdp_parse_version(int *version, const char *begin, const char *end,
    uint_t *p_error)
{
	if (*begin++ != COMMP_EQUALS || commp_atoi(begin, end, version) != 0)
		*p_error |= SDP_VERSION_ERROR;
}

/*
 * session-name-field (s=)
 * %x73 "=" text CRLF
 * text = byte-string
 * byte-string = 1*(%x01-09/%x0B-0C/%x0E-FF)
 *               ;any byte except NUL, CR, or LF
 */
static void
sdp_parse_name(char **name, const char *begin, const char *end,
    uint_t *p_error)
{
	int	len;

	if (*begin++ != COMMP_EQUALS) {
		*p_error |= SDP_NAME_ERROR;
		return;
	}
	/* there can be only one name field */
	if (*name != NULL)
		return;
	len = end - begin;
	if (len < 1) {
		*p_error |= SDP_NAME_ERROR;
	} else {
		COMMP_COPY_STR(*name, begin, len);
		if (*name == NULL) {
			*p_error |= SDP_MEMORY_ERROR;
			return;
		}
	}
}

/*
 * information-field (i=)
 * [%x69 "=" text CRLF]
 * text = byte-string
 * byte-string = 1*(%x01-09/%x0B-0C/%x0E-FF)
 *			any byte except NUL, CR, or LF
 */
static void
sdp_parse_info(char **info, const char *begin, const char *end,
    uint_t *p_error)
{
	int 	len;

	if (*begin++ != COMMP_EQUALS) {
		*p_error |= SDP_INFO_ERROR;
		return;
	}
	/* There can be only one info field */
	if (*info != NULL)
		return;
	len = end - begin;
	if (len < 1) {
		*p_error |= SDP_INFO_ERROR;
	} else {
		COMMP_COPY_STR(*info, begin, len);
		if (*info == NULL) {
			*p_error |= SDP_MEMORY_ERROR;
			return;
		}
	}
}

/*
 * uri-field (u=)
 * [%x75 "=" uri CRLF]
 * anything between "=" and "CRLF" is considered to be URI.
 */
static void
sdp_parse_uri(char **uri, const char *begin, const char *end, uint_t *p_error)
{
	int 	len;

	if (*begin++ != COMMP_EQUALS) {
		*p_error |= SDP_URI_ERROR;
		return;
	}
	/* There can be only one uri field */
	if (*uri != NULL)
		return;
	len = end - begin;
	if (len < 1 || isspace(*begin) || isspace (*(end - 1))) {
		*p_error |= SDP_URI_ERROR;
	} else {
		COMMP_COPY_STR(*uri, begin, len);
		if (*uri == NULL) {
			*p_error |= SDP_MEMORY_ERROR;
			return;
		}
	}
}

/*
 * phone-fields (p=)
 * *(%x70 "=" phone-number CRLF)
 * anything between "=" and "CRLF" is considered to be phone-number
 */
static void
sdp_parse_phone(sdp_list_t **phone, const char *begin, const char *end,
    uint_t *p_error)
{
	int 		len;
	sdp_list_t	*new_phone = NULL;
	sdp_list_t	*tmp = NULL;

	if (*begin++ != COMMP_EQUALS) {
		*p_error |= SDP_PHONE_ERROR;
		return;
	}
	len = end - begin;
	if (len < 1 || isspace(*begin) || isspace(*(end - 1))) {
		*p_error |= SDP_PHONE_ERROR;
	} else {
		new_phone = calloc(1, sizeof (sdp_list_t));
		if (new_phone == NULL) {
			*p_error |= SDP_MEMORY_ERROR;
			return;
		}
		COMMP_COPY_STR(new_phone->value, begin, len);
		if (new_phone->value == NULL) {
			free(new_phone);
			*p_error |= SDP_MEMORY_ERROR;
			return;
		}
		if (*phone == NULL) {
			*phone = new_phone;
		} else {
			tmp = *phone;
			while (tmp->next != NULL)
				tmp = tmp->next;
			tmp->next = new_phone;
		}
	}
}

/*
 * email-fields (e=)
 * *(%x65 "=" email-address CRLF)
 * anything between "=" and "CRLF" is considered to be email-address
 */
static void
sdp_parse_email(sdp_list_t **email, const char *begin, const char *end,
    uint_t *p_error)
{
	int 		len;
	sdp_list_t	*new_email = NULL;
	sdp_list_t	*tmp = NULL;

	if (*begin++ != COMMP_EQUALS) {
		*p_error |= SDP_EMAIL_ERROR;
		return;
	}
	len = end - begin;
	if (len < 1 || isspace(*begin) || isspace(*(end - 1))) {
		*p_error |= SDP_EMAIL_ERROR;
	} else {
		new_email = calloc(1, sizeof (sdp_list_t));
		if (new_email == NULL) {
			*p_error |= SDP_MEMORY_ERROR;
			return;
		}
		COMMP_COPY_STR(new_email->value, begin, len);
		if (new_email->value == NULL) {
			free(new_email);
			*p_error |= SDP_MEMORY_ERROR;
			return;
		}
		if (*email == NULL) {
			*email = new_email;
		} else {
			tmp = *email;
			while (tmp->next != NULL)
				tmp = tmp->next;
			tmp->next = new_email;
		}
	}
}

/*
 * origin-field (o=)
 * %x6f "=" username SP sess-id SP sess-version SP nettype SP addrtype SP
 * unicast-address CRLF
 *
 * username = non-ws-string
 * sess-id = 1*DIGIT
 * sess-version = 1*DIGIT
 * nettype = token
 * addrtype = token
 * token = 1*(token-char)
 * token-char = %x21 / %x23-27 / %x2A-2B / %x2D-2E / %x30-39 / %x41-5A / %x5E-7E
 * i.e. no space in token-char
 */
static void
sdp_parse_origin(sdp_origin_t **origin, const char *begin, const char *end,
    uint_t *p_error)
{
	const char	*current = NULL;
	sdp_origin_t	*new_origin = NULL;

	if (*begin++ != COMMP_EQUALS) {
		*p_error |= SDP_ORIGIN_ERROR;
		return;
	}
	/* There can be only one origin field */
	if (*origin != NULL)
		return;
	new_origin = calloc(1, sizeof (sdp_origin_t));
	if (new_origin == NULL) {
		*p_error |= SDP_MEMORY_ERROR;
		return;
	}
	/* Get username */
	current = begin;
	if (commp_find_token(&begin, &current, end, COMMP_SP, B_FALSE) != 0) {
		goto err_ret;
	} else {
		COMMP_COPY_STR(new_origin->o_username, begin, current - begin);
		if (new_origin->o_username == NULL) {
			sdp_free_origin(new_origin);
			*p_error |= SDP_MEMORY_ERROR;
			return;
		}
	}
	/* Get Session-ID */
	begin = ++current;
	if (commp_find_token(&begin, &current, end, COMMP_SP, B_FALSE) != 0)
		goto err_ret;
	if (commp_strtoull(begin, current, &new_origin->o_id) != 0)
		goto err_ret;
	/* Get Version */
	begin = ++current;
	if (commp_find_token(&begin, &current, end, COMMP_SP, B_FALSE) != 0)
		goto err_ret;
	if (commp_strtoull(begin, current, &new_origin->o_version) != 0)
		goto err_ret;
	/* Get nettype */
	begin = ++current;
	if (commp_find_token(&begin, &current, end, COMMP_SP, B_FALSE) != 0) {
		goto err_ret;
	} else {
		COMMP_COPY_STR(new_origin->o_nettype, begin, current - begin);
		if (new_origin->o_nettype == NULL) {
			sdp_free_origin(new_origin);
			*p_error |= SDP_MEMORY_ERROR;
			return;
		}
	}
	/* Get addrtype */
	begin = ++current;
	if (commp_find_token(&begin, &current, end, COMMP_SP, B_FALSE) != 0) {
		goto err_ret;
	} else {
		COMMP_COPY_STR(new_origin->o_addrtype, begin, current - begin);
		if (new_origin->o_addrtype == NULL) {
			sdp_free_origin(new_origin);
			*p_error |= SDP_MEMORY_ERROR;
			return;
		}
	}
	/* Get address. Its the last sub-field */
	begin = ++current;
	if (commp_find_token(&begin, &current, end, COMMP_SP, B_TRUE) != 0)
		goto err_ret;
	COMMP_COPY_STR(new_origin->o_address, begin, current - begin);
	if (new_origin->o_address == NULL) {
		sdp_free_origin(new_origin);
		*p_error |= SDP_MEMORY_ERROR;
		return;
	}
	*origin = new_origin;
	return;
err_ret:
	*p_error |= SDP_ORIGIN_ERROR;
	sdp_free_origin(new_origin);
}

/*
 * time-fields (t=)
 * 1*( %x74 "=" start-time SP stop-time CRLF)
 * start-time = time / "0"
 * stop-time = time / "0"
 * time = POS-DIGIT 9*DIGIT
 * POS-DIGIT = %x31-39 ; 1 - 9
 */
static sdp_time_t *
sdp_parse_time(sdp_time_t **time, const char *begin, const char *end,
    uint_t *p_error)
{
	const char	*current;
	sdp_time_t	*new_time;
	sdp_time_t	*tmp;

	if (*begin++ != COMMP_EQUALS) {
		*p_error |= SDP_TIME_ERROR;
		return (NULL);
	}
	new_time = calloc(1, sizeof (sdp_time_t));
	if (new_time == NULL) {
		*p_error |= SDP_MEMORY_ERROR;
		return (NULL);
	}
	/* Get start-time */
	current = begin;
	if (commp_find_token(&begin, &current, end, COMMP_SP, B_FALSE) != 0)
		goto err_ret;
	if (commp_strtoull(begin, current, &new_time->t_start) != 0)
		goto err_ret;
	/* Get stop-time */
	begin = ++current;
	if (commp_find_token(&begin, &current, end, COMMP_SP, B_TRUE) != 0)
		goto err_ret;
	if (commp_strtoull(begin, current, &new_time->t_stop) != 0)
		goto err_ret;
	/* Now assign time to session structure */
	if (*time == NULL) {
		*time = new_time;
	} else {
		tmp = *time;
		while (tmp->t_next != NULL)
			tmp = tmp->t_next;
		tmp->t_next = new_time;
	}
	return (new_time);
err_ret:
	*p_error |= SDP_TIME_ERROR;
	sdp_free_time(new_time);
	return (NULL);
}

/*
 * connection-field (c=)
 * [%x63 "=" nettype SP addrtype SP connection-address CRLF]
 * nettype = token
 * addrtype = token
 * connection-address =  multicast-address / unicast-address
 * here, connection-address is parsed as a string.
 */
static void
sdp_parse_connection(sdp_conn_t **conn, const char *begin, const char *end,
    uint_t *p_error)
{
	const char	*current;
	const char	*t_begin;
	const char	*t_current;
	sdp_conn_t	*new_conn;
	sdp_conn_t	*tmp;
	boolean_t	is_IP4 = B_FALSE;
	boolean_t	is_IP6 = B_FALSE;

	if (*begin++ != COMMP_EQUALS) {
		*p_error |= SDP_CONNECTION_ERROR;
		return;
	}
	new_conn = calloc(1, sizeof (sdp_conn_t));
	if (new_conn == NULL) {
		*p_error |= SDP_MEMORY_ERROR;
		return;
	}
	/* Get NetworkType */
	current = begin;
	if (commp_find_token(&begin, &current, end, COMMP_SP, B_FALSE) != 0) {
		goto err_ret;
	} else {
		COMMP_COPY_STR(new_conn->c_nettype, begin, current - begin);
		if (new_conn->c_nettype == NULL) {
			sdp_free_connection(new_conn);
			*p_error |= SDP_MEMORY_ERROR;
			return;
		}
	}
	/* Get AddressType */
	begin = ++current;
	if (commp_find_token(&begin, &current, end, COMMP_SP, B_FALSE) != 0) {
		goto err_ret;
	} else {
		COMMP_COPY_STR(new_conn->c_addrtype, begin, current - begin);
		if (new_conn->c_addrtype == NULL) {
			sdp_free_connection(new_conn);
			*p_error |= SDP_MEMORY_ERROR;
			return;
		}
	}
	if ((strlen(COMMP_ADDRTYPE_IP4) == strlen(new_conn->c_addrtype)) &&
	    (strncasecmp(new_conn->c_addrtype, COMMP_ADDRTYPE_IP4,
	    strlen(COMMP_ADDRTYPE_IP4)) == 0)) {
		is_IP4 = B_TRUE;
	} else if ((strlen(COMMP_ADDRTYPE_IP6) == strlen(new_conn->
	    c_addrtype)) && (strncasecmp(new_conn->c_addrtype,
	    COMMP_ADDRTYPE_IP6, strlen(COMMP_ADDRTYPE_IP6)) == 0)) {
		is_IP6 = B_TRUE;
	}
	/* Get Address. Parsing depends if its IP4,IP6 or something else */
	begin = ++current;
	if (!is_IP4 && !is_IP6) {
		if (commp_find_token(&begin, &current, end, COMMP_SP,
		    B_TRUE) != 0) {
			goto err_ret;
		}
	} else {
		if (commp_find_token(&begin, &current, end, COMMP_SLASH,
		    B_FALSE) != 0) {
			goto err_ret;
		}
		if (current != end) {
			/* SLASH is present. Needs further parsing */
			t_current = current;
			t_begin = ++t_current;
			if (commp_find_token(&t_begin, &t_current, end,
			    COMMP_SLASH, B_FALSE) != 0) {
				goto err_ret;
			}
			if (t_current != end) {
				/*
				 * Another SLASH present. If is_IP4 true then
				 * this is Address count. If is_IP6 true then
				 * incorrect field as per RFC.
				 */
				if (is_IP6) {
					goto err_ret;
				} else {
					if (commp_atoi((t_current + 1), end,
					    &new_conn->c_addrcount) != 0) {
						goto err_ret;
					}
				}
			}
			if (is_IP6) {
				if (commp_atoi((current + 1), t_current,
				    &new_conn->c_addrcount) != 0) {
					goto err_ret;
				}
			} else {
				if (commp_strtoub((current + 1), t_current,
				    &new_conn->c_ttl) != 0) {
					goto err_ret;
				}
				if (new_conn->c_addrcount == 0)
					new_conn->c_addrcount = 1;
			}
		}
	}
	COMMP_COPY_STR(new_conn->c_address, begin, current - begin);
	if (new_conn->c_address == NULL) {
		sdp_free_connection(new_conn);
		*p_error |= SDP_MEMORY_ERROR;
		return;
	}
	if (*conn == NULL) {
		*conn = new_conn;
	} else {
		tmp = *conn;
		while (tmp->c_next != NULL)
			tmp = tmp->c_next;
		tmp->c_next = new_conn;
	}
	return;
err_ret:
	*p_error |= SDP_CONNECTION_ERROR;
	sdp_free_connection(new_conn);
}

/*
 * bandwidth-fields (b=)
 * *(%x62 "=" bwtype ":" bandwidth CRLF)
 * bwtype = token
 * bandwidth = 1*DIGIT
 */
static void
sdp_parse_bandwidth(sdp_bandwidth_t **bw, const char *begin, const char *end,
    uint_t *p_error)
{
	const char		*current;
	sdp_bandwidth_t		*new_bw = NULL;
	sdp_bandwidth_t		*tmp = NULL;

	if (*begin++ != COMMP_EQUALS) {
		*p_error |= SDP_BANDWIDTH_ERROR;
		return;
	}
	new_bw = calloc(1, sizeof (sdp_bandwidth_t));
	if (new_bw == NULL) {
		*p_error |= SDP_MEMORY_ERROR;
		return;
	}
	current = begin;
	if (commp_find_token(&begin, &current, end, COMMP_COLON,
	    B_FALSE) != 0) {
		goto err_ret;
	} else {
		COMMP_COPY_STR(new_bw->b_type, begin, current - begin);
		if (new_bw->b_type == NULL) {
			sdp_free_bandwidth(new_bw);
			*p_error |= SDP_MEMORY_ERROR;
			return;
		}
	}
	if (current == end)
		goto err_ret;
	begin = ++current;
	if (commp_find_token(&begin, &current, end, COMMP_SP, B_TRUE) != 0)
		goto err_ret;
	if (commp_strtoull(begin, current, &new_bw->b_value) != 0)
		goto err_ret;
	if (*bw == NULL) {
		*bw = new_bw;
	} else {
		tmp = *bw;
		while (tmp->b_next != NULL)
			tmp = tmp->b_next;
		tmp->b_next = new_bw;
	}
	return;
err_ret:
	*p_error |= SDP_BANDWIDTH_ERROR;
	sdp_free_bandwidth(new_bw);
}

/*
 * repeat-fields (r=)
 * Not stand-alone. One or more repeat field appear after time field.
 * %x72 "=" repeat-interval SP typed-time 1*(SP typed-time)
 * repeat-interval = POS-DIGIT *DIGIT [fixed-len-time-unit]
 * typed-time = 1*DIGIT [fixed-len-time-unit]
 * fixed-len-time-unit = %x64 / %x68 / %x6d / %x73
 */
static void
sdp_parse_repeat(sdp_time_t *time, const char *begin, const char *end,
    uint_t *p_error)
{
	const char	*current;
	sdp_repeat_t	*repeat;
	sdp_repeat_t	*new_repeat;
	int		ret;

	if (*begin++ != COMMP_EQUALS) {
		*p_error |= SDP_REPEAT_TIME_ERROR;
		return;
	}
	/*
	 * A time field should be present before this field can occur, if
	 * time is NULL then repeat field has occured before time field and
	 * hence fields are out of order.
	 */
	if (time == NULL)
		return;
	/*
	 * Get the latest time field and associate this repeat field
	 * with it.
	 */
	while (time->t_next != NULL)
		time = time->t_next;
	new_repeat = calloc(1, sizeof (sdp_repeat_t));
	if (new_repeat == NULL) {
		*p_error |= SDP_MEMORY_ERROR;
		return;
	}
	/*
	 * for a given time field, there could be several repeat fields
	 * add the new repeat field at the end of it.
	 */
	repeat = time->t_repeat;
	if (repeat == NULL) {
		time->t_repeat = new_repeat;
	} else {
		while (repeat->r_next != NULL)
			repeat = repeat->r_next;
		repeat->r_next = new_repeat;
	}
	/*
	 * Populate the elements of sdp_repeat.
	 * Get time-interval
	 */
	current = begin;
	if (commp_find_token(&begin, &current, end, COMMP_SP, B_FALSE) != 0)
		goto err_ret;
	if (commp_time_to_secs(begin, current, &new_repeat->r_interval) != 0)
		goto err_ret;
	/* Get duration. It could be the last sub-field */
	begin = ++current;
	if (commp_find_token(&begin, &current, end, COMMP_SP, B_FALSE) != 0)
		goto err_ret;
	if (commp_time_to_secs(begin, current, &new_repeat->r_duration) != 0)
		goto err_ret;
	++current;
	/* Get offsets into sdp_list */
	if (current >= end)
		goto err_ret;
	while (current < end) {
		begin = current;
		if (commp_find_token(&begin, &current, end, COMMP_SP,
		    B_FALSE) != 0) {
			goto err_ret;
		}
		if ((ret = add_value_to_list(&new_repeat->r_offset, begin,
		    current - begin, B_FALSE)) != 0) {
			if (ret == ENOMEM) {
				*p_error |= SDP_MEMORY_ERROR;
				return;
			} else {
				goto err_ret;
			}
		}
		++current;
	}
	/* check for trailing white space character. */
	if (isspace(*(end - 1)))
		goto err_ret;
	return;
err_ret:
	*p_error |= SDP_REPEAT_TIME_ERROR;
	if (repeat != NULL)
		repeat->r_next = NULL;
	else
		time->t_repeat = NULL;
	sdp_free_repeat(new_repeat);
}

/*
 * zone-adjustments (z=)
 * %x7a "=" time SP ["-"] typed-time *(SP time SP ["-"] typed-time)
 */
static void
sdp_parse_zone(sdp_zone_t **zone, const char *begin, const char *end,
    uint_t *p_error)
{
	const char	*current;
	sdp_zone_t	*new_zone = NULL;
	sdp_zone_t	*tmp = NULL;

	if (*begin++ != COMMP_EQUALS) {
		*p_error |= SDP_ZONE_ERROR;
		return;
	}
	/* There can be atmost one zone field. */
	if (*zone != NULL)
		return;
	/* Get time and offset */
	current = begin;
	while (current < end) {
		new_zone = calloc(1, sizeof (sdp_zone_t));
		if (new_zone == NULL) {
			*p_error |= SDP_MEMORY_ERROR;
			return;
		}
		if (*zone == NULL) {
			*zone = new_zone;
			tmp = *zone;
		} else {
			tmp->z_next = new_zone;
			tmp = new_zone;
		}
		begin = current;
		if (commp_find_token(&begin, &current, end, COMMP_SP,
		    B_FALSE) != 0) {
			goto err_ret;
		}
		if (commp_strtoull(begin, current, &new_zone->z_time) != 0)
			goto err_ret;
		begin = ++current;
		if (commp_find_token(&begin, &current, end, COMMP_SP,
		    B_FALSE) != 0) {
			goto err_ret;
		} else {
			COMMP_COPY_STR(new_zone->z_offset, begin, current -
			    begin);
			if (new_zone->z_offset == NULL) {
				*p_error |= SDP_MEMORY_ERROR;
				return;
			}

		}
		++current;
	}
	if (isspace(*(end - 1)))
		goto err_ret;
	return;
err_ret:
	*p_error |= SDP_ZONE_ERROR;
	sdp_free_zone(*zone);
	*zone = NULL;
}

/*
 * key-field (k=)
 * [%x6b "=" key-type CRLF]
 * key-type = %x70 %x72 %x6f %x6d %x70 %x74 /     ; "prompt"
 *            %x63 %x6c %x65 %x61 %x72 ":" text / ; "clear:"
 *            %x62 %x61 %x73 %x65 "64:" base64 /  ; "base64:"
 *            %x75 %x72 %x69 ":" uri              ; "uri:"
 */
static void
sdp_parse_key(sdp_key_t **key, const char *begin, const char *end,
    uint_t *p_error)
{
	const char	*current;
	sdp_key_t	*new_key;

	if (*begin++ != COMMP_EQUALS) {
		*p_error |= SDP_KEY_ERROR;
		return;
	}
	/* There can be only one key field */
	if (*key != NULL)
		return;
	new_key = calloc(1, sizeof (sdp_key_t));
	if (new_key == NULL) {
		*p_error |= SDP_MEMORY_ERROR;
		return;
	}
	/* Get Method name */
	current = begin;
	if (commp_find_token(&begin, &current, end, COMMP_COLON,
	    B_FALSE) != 0) {
		goto err_ret;
	} else {
		COMMP_COPY_STR(new_key->k_method, begin, current - begin);
		if (new_key->k_method == NULL) {
			sdp_free_key(new_key);
			*p_error |= SDP_MEMORY_ERROR;
			return;
		}
	}
	/* Get key, if exists. */
	if (*current == COMMP_COLON) {
		++current;
		if (current == end)
			goto err_ret;
		COMMP_COPY_STR(new_key->k_enckey, current, end - current);
		if (new_key->k_enckey == NULL) {
			sdp_free_key(new_key);
			*p_error |= SDP_MEMORY_ERROR;
			return;
		}
	}
	*key = new_key;
	return;
err_ret:
	*p_error |= SDP_KEY_ERROR;
	sdp_free_key(new_key);
}

/*
 * attribute-fields (a=)
 * *(%x61 "=" attribute CRLF)
 * attribute = (att-field ":" att-value) / att-field
 * att-field = token
 * att-value = byte-string
 */
static void
sdp_parse_attribute(sdp_attr_t **attr, const char *begin, const char *end,
    uint_t *p_error)
{
	const char	*current;
	sdp_attr_t	*new_attr;
	sdp_attr_t	*tmp;

	if (*begin++ != COMMP_EQUALS) {
		*p_error |= SDP_ATTRIBUTE_ERROR;
		return;
	}
	new_attr = calloc(1, sizeof (sdp_attr_t));
	if (new_attr == NULL) {
		*p_error |= SDP_MEMORY_ERROR;
		return;
	}
	/* Get Attribute Name */
	current = begin;
	if (commp_find_token(&begin, &current, end, COMMP_COLON,
	    B_FALSE) != 0) {
		goto err_ret;
	} else {
		COMMP_COPY_STR(new_attr->a_name, begin, current - begin);
		if (new_attr->a_name == NULL) {
			sdp_free_attribute(new_attr);
			*p_error |= SDP_MEMORY_ERROR;
			return;
		}
	}
	/* Get Attribute Value */
	if (*current == COMMP_COLON) {
		++current;
		if (current == end)
			goto err_ret;
		COMMP_COPY_STR(new_attr->a_value, current, end - current);
		if (new_attr->a_value == NULL) {
			sdp_free_attribute(new_attr);
			*p_error |= SDP_MEMORY_ERROR;
			return;
		}
	}
	if (*attr == NULL) {
		*attr = new_attr;
	} else {
		tmp = *attr;
		while (tmp->a_next != NULL)
			tmp = tmp->a_next;
		tmp->a_next = new_attr;
	}
	return;
err_ret:
	*p_error |= SDP_ATTRIBUTE_ERROR;
	sdp_free_attribute(new_attr);
}

/*
 * media-field (m=)
 * %x6d "=" media SP port ["/" integer] SP proto 1*(SP fmt) CRLF
 */
static sdp_media_t *
sdp_parse_media(sdp_session_t *session, const char *begin, const char *end,
    uint_t *p_error)
{
	const char	*current;
	const char	*fake_end;
	sdp_media_t	*new_media;
	sdp_media_t	*tmp;

	if (*begin++ != COMMP_EQUALS) {
		*p_error |= SDP_MEDIA_ERROR;
		return (NULL);
	}

	new_media = calloc(1, sizeof (sdp_media_t));
	if (new_media == NULL) {
		*p_error |= SDP_MEMORY_ERROR;
		return (NULL);
	}
	new_media->m_session = session;
	/* Get media name */
	current = begin;
	if (commp_find_token(&begin, &current, end, COMMP_SP, B_FALSE) != 0) {
		goto err_ret;
	} else {
		COMMP_COPY_STR(new_media->m_name, begin, current - begin);
		if (new_media->m_name == NULL) {
			sdp_free_media(new_media);
			*p_error |= SDP_MEMORY_ERROR;
			return (NULL);
		}
	}
	/* Get port */
	begin = ++current;
	if (commp_find_token(&begin, &current, end, COMMP_SP, B_FALSE) != 0)
		goto err_ret;
	fake_end = current;
	current = begin;
	if (commp_find_token(&begin, &current, fake_end, COMMP_SLASH,
	    B_FALSE) != 0) {
		goto err_ret;
	}
	if (commp_atoui(begin, current, &new_media->m_port) != 0)
		goto err_ret;
	/* Get portcount */
	if (*current == COMMP_SLASH) {
		begin = ++current;
		if (commp_find_token(&begin, &current, fake_end, COMMP_SP,
		    B_FALSE) != 0) {
			goto err_ret;
		}
		if (commp_atoi(begin, current, &new_media->m_portcount) != 0)
			goto err_ret;
	} else {
		new_media->m_portcount = 1;
	}
	/* Get Protocol */
	begin = ++current;
	if (commp_find_token(&begin, &current, end, COMMP_SP, B_FALSE) != 0) {
		goto err_ret;
	} else {
		COMMP_COPY_STR(new_media->m_proto, begin, current - begin);
		if (new_media->m_proto == NULL) {
			sdp_free_media(new_media);
			*p_error |= SDP_MEMORY_ERROR;
			return (NULL);
		}
	}
	++current;
	/* Get format list */
	if (current >= end)
		goto err_ret;
	while (current < end) {
		begin = current;
		if (commp_find_token(&begin, &current, end, COMMP_SP,
		    B_FALSE) != 0) {
			goto err_ret;
		}
		if (add_value_to_list(&new_media->m_format, begin,
		    current - begin, B_TRUE) != 0) {
			sdp_free_media(new_media);
			*p_error |= SDP_MEMORY_ERROR;
			return (NULL);
		}
		++current;
	}
	/* check for trailing white space character. */
	if (isspace(*(end - 1)))
		goto err_ret;
	/* Assign new media to the media list */
	tmp = session->s_media;
	if (tmp == NULL) {
		session->s_media = new_media;
	} else {
		while (tmp->m_next != NULL)
			tmp = tmp->m_next;
		tmp->m_next = new_media;
	}
	return (new_media);
err_ret:
	*p_error |= SDP_MEDIA_ERROR;
	sdp_free_media(new_media);
	return (NULL);
}

/*
 * This function ensures that a field is in the right order in SDP descripton.
 * It also identifies cases where a field ('v', 'o, 'i', et al) that must occur
 * once but occurs several times in SDP description. error cannot be NULL.
 */
static void
sdp_check_order(char prev, char *order, int *error)
{
	*error = 0;
	while (*order != '\0') {
		if (*order++ == prev)
			return;
	}
	*error = 1;
}

/*
 * This function determines the SDP field and calls the appropriate parse
 * function. It also ensures that the SDP fields are in strict order.
 */
static void
sdp_handle_fields(sdp_description_t *description, sdp_session_t *_session,
    const char *begin, const char *end)
{
	boolean_t	u_field = B_FALSE;
	int		error = 0;			/* fields order error */
	char		prev = description->d_prev;
	char		m_prev = description->d_mprev;

	switch (*begin) {
		case SDP_VERSION_FIELD:
			sdp_check_order(prev, SDP_VERSION_ORDER, &error);
			description->d_version = B_TRUE;
			sdp_parse_version(&_session->s_version, begin + 1, end,
			    &description->d_perror);
			break;
		case SDP_ORIGIN_FIELD:
			sdp_check_order(prev, SDP_ORIGIN_ORDER, &error);
			description->d_origin = B_TRUE;
			sdp_parse_origin(&_session->s_origin, begin + 1, end,
			    &description->d_perror);
			break;
		case SDP_NAME_FIELD:
			sdp_check_order(prev, SDP_NAME_ORDER, &error);
			description->d_name = B_TRUE;
			sdp_parse_name(&_session->s_name, begin + 1, end,
			    &description->d_perror);
			break;
		case SDP_INFO_FIELD:
			if (description->d_mparsed) {
				sdp_check_order(m_prev, SDP_M_INFO_ORDER,
				    &error);
				if (description->d_lmedia == NULL)
					break;
				sdp_parse_info(&(description->d_lmedia->
				    m_info), begin + 1, end, &description->
				    d_perror);
			} else {
				sdp_check_order(prev, SDP_INFO_ORDER, &error);
				sdp_parse_info(&_session->s_info, begin + 1,
				    end, &description->d_perror);
			}
			break;
		case SDP_URI_FIELD:
			sdp_check_order(prev, SDP_URI_ORDER, &error);
			sdp_parse_uri(&_session->s_uri, begin + 1, end,
			    &description->d_perror);
			break;
		case SDP_EMAIL_FIELD:
			sdp_check_order(prev, SDP_EMAIL_ORDER, &error);
			sdp_parse_email(&_session->s_email, begin + 1, end,
			    &description->d_perror);
			break;
		case SDP_PHONE_FIELD:
			sdp_check_order(prev, SDP_PHONE_ORDER, &error);
			sdp_parse_phone(&_session->s_phone, begin + 1, end,
			    &description->d_perror);
			break;
		case SDP_CONNECTION_FIELD:
			if (description->d_mparsed) {
				sdp_check_order(m_prev, SDP_M_CONN_ORDER,
				    &error);
				--description->d_mccount;
				if (description->d_lmedia == NULL)
					break;
				sdp_parse_connection(&(description->d_lmedia->
				    m_conn), begin + 1, end,
				    &description->d_perror);
			} else {
				/*
				 * RFC - 4566 says that session section  should
				 * have only one connection field, while media
				 * section can have many
				 */
				sdp_check_order(prev, SDP_CONN_ORDER, &error);
				description->d_conn = B_TRUE;
				if (_session->s_conn != NULL)
					break;
				sdp_parse_connection(&_session->s_conn,
				    begin + 1, end, &description->d_perror);
			}
			break;
		case SDP_BANDWIDTH_FIELD:
			if (description->d_mparsed) {
				sdp_check_order(m_prev, SDP_M_BW_ORDER, &error);
				if (description->d_lmedia == NULL)
					break;
				sdp_parse_bandwidth(&(description->d_lmedia->
				    m_bw), begin + 1, end,
				    &description->d_perror);
			} else {
				sdp_check_order(prev, SDP_BW_ORDER, &error);
				sdp_parse_bandwidth(&_session->s_bw,
				    begin + 1, end, &description->d_perror);
			}
			break;
		case SDP_TIME_FIELD:
			if (!description->d_tparsed || description->d_prev !=
			    SDP_REPEAT_FIELD) {
				sdp_check_order(prev, SDP_TIME_ORDER, &error);
			}
			description->d_tparsed = B_TRUE;
			description->d_ltime = sdp_parse_time(&_session->
			    s_time, begin + 1, end, &description->d_perror);
			break;
		case SDP_REPEAT_FIELD:
			sdp_check_order(prev, SDP_REPEAT_ORDER, &error);
			if (description->d_ltime == NULL)
				break;
			/* we pass time, as repeat is associated with time */
			sdp_parse_repeat(description->d_ltime, begin + 1, end,
			    &description->d_perror);
			break;
		case SDP_ZONE_FIELD:
			sdp_check_order(prev, SDP_ZONE_ORDER, &error);
			sdp_parse_zone(&_session->s_zone, begin + 1, end,
			    &description->d_perror);
			break;
		case SDP_KEY_FIELD:
			if (description->d_mparsed) {
				sdp_check_order(m_prev, SDP_M_KEY_ORDER,
				    &error);
				if (description->d_lmedia == NULL)
					break;
				sdp_parse_key(&(description->d_lmedia->m_key),
				    begin + 1, end, &description->d_perror);
			} else {
				sdp_check_order(prev, SDP_KEY_ORDER, &error);
				sdp_parse_key(&_session->s_key, begin + 1, end,
				    &description->d_perror);
			}
			break;
		case SDP_ATTRIBUTE_FIELD:
			if (description->d_mparsed) {
				sdp_check_order(m_prev, SDP_M_ATTR_ORDER,
				    &error);
				if (description->d_lmedia == NULL)
					break;
				sdp_parse_attribute(&(description->d_lmedia->
				    m_attr), begin + 1, end,
				    &description->d_perror);
			} else {
				sdp_check_order(prev, SDP_ATTR_ORDER, &error);
				sdp_parse_attribute(&_session->s_attr,
				    begin + 1, end, &description->d_perror);
			}
			break;
		case SDP_MEDIA_FIELD:
			if (!description->d_mparsed) {
				sdp_check_order(prev, SDP_MEDIA_ORDER, &error);
				description->d_mccount = 1;
			} else {
				if (description->d_mccount == 1)
					description->d_mconn = B_FALSE;
				description->d_mccount = 1;
			}
			description->d_mparsed = B_TRUE;
			description->d_lmedia = sdp_parse_media(_session,
			    begin + 1, end, &description->d_perror);
			break;
		default:
			/* Unknown field type. Ignore it */
			u_field = B_TRUE;
			break;
	}
	if (error)
		description->d_perror |= SDP_FIELDS_ORDER_ERROR;
	if (!u_field) {
		if (!description->d_mparsed)
			description->d_prev = *begin;
		else
			description->d_mprev = *begin;
	}
}

/*
 * Parses the SDP info
 */
int
sdp_parse(const char *sdp_info, int len, int flags, sdp_session_t **session,
    uint_t *p_error)
{

	const char		*f_begin;
	const char		*f_end;
	sdp_description_t	*description;
	const char		*start;
	const char		*end;
	const char		*current;

	if (sdp_info == NULL || len == 0 || p_error == NULL || flags != 0 ||
	    session == NULL) {
		if (session != NULL)
			*session = NULL;
		return (EINVAL);
	}
	*session = NULL;
	*p_error = 0;
	description = calloc(1, sizeof (sdp_description_t));
	if (description == NULL) {
		return (ENOMEM);
	}
	/* Needed later to check for mandatory fields */
	description->d_prev = COMMP_SP;
	description->d_mconn = B_TRUE;
	*session = sdp_new_session();
	if (*session == NULL) {
		free(description);
		return (ENOMEM);
	}
	start = sdp_info;
	end = start + len;
	if (commp_skip_white_space(&start, end) != 0) {
		free(description);
		free(*session);
		*session = NULL;
		return (EINVAL);
	}
	current = start;
	f_begin = current;
	while ((current < end) && !(description->d_perror &
	    SDP_MEMORY_ERROR)) {
		/*
		 * RFC says parser SHOULD be tolerant to records ending
		 * with a single newline character too.
		 */
		if (strncmp(COMMP_CRLF, current, strlen(COMMP_CRLF)) == 0) {
			f_end = current;
			sdp_handle_fields(description, *session, f_begin,
			    f_end);
			COMMP_SKIP_CRLF(current);
			(void) commp_skip_white_space(&current, end);
			f_begin = current;
		} else if (strncmp(COMMP_LF, current, strlen(COMMP_LF)) == 0) {
			f_end = current;
			sdp_handle_fields(description, *session, f_begin,
			    f_end);
			COMMP_SKIP_LF(current);
			(void) commp_skip_white_space(&current, end);
			f_begin = current;
		} else {
			current++;
		}
	}
	if (description->d_perror & SDP_MEMORY_ERROR) {
		free(description);
		sdp_free_session(*session);
		*session = NULL;
		return (ENOMEM);
	}
	/*
	 * Check for mandatory fields v, o, s, t fields. For connection field,
	 * RFC says; a connection field must be present in every media
	 * description or at the session-level
	 */
	if (description->d_mccount == 1)
		description->d_mconn = B_FALSE;
	if (!(description->d_version && description->d_origin &&
	    description->d_name && description->d_tparsed &&
	    (description->d_conn || (description->d_mparsed &&
	    description->d_mconn)))) {
		description->d_perror |= SDP_MISSING_FIELDS;
	}
	*p_error = description->d_perror;
	free(description);
	return (0);
}
