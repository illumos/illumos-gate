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

#ifndef _SDP_H
#define	_SDP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

#define	SDP_VERSION_FIELD	'v'
#define	SDP_ORIGIN_FIELD	'o'
#define	SDP_NAME_FIELD		's'
#define	SDP_INFO_FIELD		'i'
#define	SDP_URI_FIELD		'u'
#define	SDP_EMAIL_FIELD		'e'
#define	SDP_PHONE_FIELD		'p'
#define	SDP_CONNECTION_FIELD	'c'
#define	SDP_BANDWIDTH_FIELD	'b'
#define	SDP_TIME_FIELD		't'
#define	SDP_REPEAT_FIELD	'r'
#define	SDP_ZONE_FIELD		'z'
#define	SDP_KEY_FIELD		'k'
#define	SDP_ATTRIBUTE_FIELD	'a'
#define	SDP_MEDIA_FIELD		'm'

/* SDP Parse errors */
#define	SDP_VERSION_ERROR	0x00000001
#define	SDP_ORIGIN_ERROR	0x00000002
#define	SDP_NAME_ERROR		0x00000004
#define	SDP_INFO_ERROR		0x00000008
#define	SDP_URI_ERROR		0x00000010
#define	SDP_EMAIL_ERROR		0x00000020
#define	SDP_PHONE_ERROR		0x00000040
#define	SDP_CONNECTION_ERROR	0x00000080
#define	SDP_BANDWIDTH_ERROR	0x00000100
#define	SDP_TIME_ERROR		0x00000200
#define	SDP_REPEAT_TIME_ERROR	0x00000400
#define	SDP_ZONE_ERROR		0x00000800
#define	SDP_KEY_ERROR		0x00001000
#define	SDP_ATTRIBUTE_ERROR	0x00002000
#define	SDP_MEDIA_ERROR		0x00004000
#define	SDP_FIELDS_ORDER_ERROR	0x00008000
#define	SDP_MISSING_FIELDS	0x00010000

#define	SDP_AUDIO		"audio"
#define	SDP_VIDEO		"video"
#define	SDP_TEXT		"text"
#define	SDP_APPLICATION		"application"
#define	SDP_MESSAGE		"message"
#define	SDP_RTPMAP		"rtpmap"

#define	SDP_SESSION_VERSION_1	1

typedef struct sdp_list {
	void			*value;
	struct sdp_list		*next;
} sdp_list_t;

/*
 * SDP origin field.
 * o=<username> <sess-id> <sess-version> <nettype> <addrtype> <unicast-address>
 */
typedef struct sdp_origin {
	char			*o_username;
	uint64_t 		o_id;
	uint64_t 		o_version;
	char			*o_nettype;
	char			*o_addrtype;
	char			*o_address;
} sdp_origin_t;

/*
 * SDP connection field.
 * c=<nettype> <addrtype> <connection-address>[/ttl]/<number of addresses>
 */
typedef struct sdp_conn {
	char			*c_nettype;
	char			*c_addrtype;
	char			*c_address;
	int 			c_addrcount;
	struct sdp_conn		*c_next;
	uint8_t			c_ttl;
} sdp_conn_t;

/*
 * SDP repeat field. Always found in time structure.
 * r=<repeat interval> <active duration> <offsets from start-time>
 */
typedef struct sdp_repeat {
	uint64_t		r_interval;
	uint64_t		r_duration;
	sdp_list_t 		*r_offset;
	struct sdp_repeat	*r_next;
} sdp_repeat_t;

/*
 * SDP time field.
 * t=<start-time> <stop-time>
 */
typedef struct sdp_time {
	uint64_t 		t_start;
	uint64_t 		t_stop;
	sdp_repeat_t 		*t_repeat;
	struct sdp_time		*t_next;
} sdp_time_t;

/*
 * SDP time zone field.
 * z=<adjustment time> <offset> <adjustment time> <offset> ....
 */
typedef struct sdp_zone {
	uint64_t 		z_time;
	char			*z_offset;
	struct sdp_zone		*z_next;
} sdp_zone_t;

/*
 * SDP attribute field.
 * a=<attribute> or a=<attribute>:<value>
 */
typedef struct sdp_attr {
	char			*a_name;
	char			*a_value;
	struct sdp_attr		*a_next;
} sdp_attr_t;

/*
 * SDP bandwidth field.
 * b=<bwtype>:<bandwidth>
 */
typedef struct sdp_bandwidth {
	char			*b_type;
	uint64_t 		b_value;
	struct sdp_bandwidth	*b_next;
} sdp_bandwidth_t;

/*
 * SDP key field to session or media section of SDP.
 * k=<method> or k=<method>:<encryption key>
 */
typedef struct sdp_key {
	char			*k_method;
	char			*k_enckey;
} sdp_key_t;

typedef struct sdp_session	sdp_session_t;

/*
 * SDP media section, contains media fields and other fields within
 * media section.
 * m=<media> <port>[/portcount] <proto> <fmt> ...
 */
typedef struct sdp_media {
	char			*m_name;
	uint_t			m_port;
	int			m_portcount;
	char			*m_proto;
	sdp_list_t 		*m_format;
	char			*m_info;
	sdp_conn_t 		*m_conn;
	sdp_bandwidth_t 	*m_bw;
	sdp_key_t 		*m_key;
	sdp_attr_t 		*m_attr;
	struct sdp_media 	*m_next;
	sdp_session_t		*m_session;
} sdp_media_t;

struct sdp_session {
	int			sdp_session_version;
	int 			s_version;
	sdp_origin_t 		*s_origin;
	char			*s_name;
	char			*s_info;
	char			*s_uri;
	sdp_list_t 		*s_email;
	sdp_list_t 		*s_phone;
	sdp_conn_t 		*s_conn;
	sdp_bandwidth_t 	*s_bw;
	sdp_time_t 		*s_time;
	sdp_zone_t 		*s_zone;
	sdp_key_t 		*s_key;
	sdp_attr_t 		*s_attr;
	sdp_media_t 		*s_media;
};

extern int		sdp_parse(const char *, int, int, sdp_session_t **,
			    uint_t *);
extern sdp_media_t	*sdp_find_media(sdp_media_t *, const char *);
extern sdp_attr_t	*sdp_find_attribute(sdp_attr_t *, const char *);
extern sdp_attr_t	*sdp_find_media_rtpmap(sdp_media_t *, const char *);
extern sdp_session_t	*sdp_clone_session(const sdp_session_t *);
extern sdp_session_t	*sdp_new_session();
extern int		sdp_add_origin(sdp_session_t *, const char *, uint64_t,
			    uint64_t, const char *, const char *, const char *);
extern int		sdp_add_name(sdp_session_t *, const char *);
extern int		sdp_add_information(char **, const char *);
extern int		sdp_add_uri(sdp_session_t *, const char *);
extern int		sdp_add_email(sdp_session_t *, const char *);
extern int		sdp_add_phone(sdp_session_t *, const char *);
extern int		sdp_add_connection(sdp_conn_t **, const char *,
			    const char *, const char *, uint8_t, int);
extern int		sdp_add_bandwidth(sdp_bandwidth_t **, const char *,
			    uint64_t);
extern int		sdp_add_repeat(sdp_time_t *, uint64_t, uint64_t,
			    const char *);
extern int		sdp_add_time(sdp_session_t *, uint64_t, uint64_t,
			    sdp_time_t **);
extern int		sdp_add_zone(sdp_session_t *, uint64_t, const char *);
extern int		sdp_add_key(sdp_key_t **, const char *, const char *);
extern int		sdp_add_attribute(sdp_attr_t **, const char *,
			    const char *);
extern int		sdp_add_media(sdp_session_t *, const char *, uint_t,
			    int, const char *, const char *, sdp_media_t **);
extern int		sdp_delete_all_field(sdp_session_t *, const char);
extern int		sdp_delete_all_media_field(sdp_media_t *, const char);
extern int		sdp_delete_media(sdp_media_t **, sdp_media_t *);
extern int		sdp_delete_attribute(sdp_attr_t **, sdp_attr_t *);
extern void		sdp_free_session(sdp_session_t *);
extern char		*sdp_session_to_str(const sdp_session_t *, int *);


#ifdef __cplusplus
}
#endif

#endif /* _SDP_H */
