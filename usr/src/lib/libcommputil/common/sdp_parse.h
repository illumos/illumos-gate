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

#ifndef _SDP_PARSE_H
#define	_SDP_PARSE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sdp.h>
#include <sys/types.h>

#define	SDP_MEMORY_ERROR		0x10000000

#define	SDP_VERSION_ORDER		" "
#define	SDP_ORIGIN_ORDER		"v"
#define	SDP_NAME_ORDER			"o"
#define	SDP_INFO_ORDER			"s"
#define	SDP_URI_ORDER			"is"
#define	SDP_EMAIL_ORDER			"euis"
#define	SDP_PHONE_ORDER			"peuis"
#define	SDP_CONN_ORDER			"peuis"
#define	SDP_BW_ORDER			"bcpeuis"
#define	SDP_TIME_ORDER			"tbcpeuis"
#define	SDP_REPEAT_ORDER		"rt"
#define	SDP_ZONE_ORDER			"rt"
#define	SDP_KEY_ORDER			"zrt"
#define	SDP_ATTR_ORDER			"akzrt"
#define	SDP_MEDIA_ORDER			"makzrt"
#define	SDP_M_INFO_ORDER		"m"
#define	SDP_M_CONN_ORDER		"cim"
#define	SDP_M_BW_ORDER			"bcim"
#define	SDP_M_KEY_ORDER			"bcim"
#define	SDP_M_ATTR_ORDER		"akbcim"

typedef struct sdp_description {
	/*
	 * Following boolean fields are used to
	 * check for presence of mandatory fields
	 * in session structure
	 */
	boolean_t	d_version;	/* Version field */
	boolean_t	d_origin;	/* Origin field */
	boolean_t	d_name;		/* Name field */
	boolean_t	d_conn;		/* Connection field */
	boolean_t	d_mconn;	/* Media connection field */
	boolean_t	d_mparsed;	/* Media parsed */
	boolean_t	d_tparsed;	/* Time parsed */
	/*
	 * keeps count of connection fields within
	 * media section
	 */
	int		d_mccount;
	sdp_media_t	*d_lmedia;	/* Last media field */
	sdp_time_t	*d_ltime;	/* Last time field */
	uint_t		d_perror;	/* Parse error */
	char		d_prev;		/* previous field */
	char		d_mprev;	/* previous field in media section */
} sdp_description_t;

extern int		add_value_to_list(sdp_list_t **, const char *, int,
			    boolean_t);
extern int		sdp_list_to_str(sdp_list_t *, char **, boolean_t);
extern int		sdp_str_to_list(sdp_list_t **, const char *, int,
			    boolean_t);
extern void		sdp_free_repeat(sdp_repeat_t *);
extern void		sdp_free_origin(sdp_origin_t *);
extern void		sdp_free_list(sdp_list_t *);
extern void		sdp_free_connection(sdp_conn_t *);
extern void		sdp_free_bandwidth(sdp_bandwidth_t *);
extern void		sdp_free_time(sdp_time_t *);
extern void		sdp_free_zone(sdp_zone_t *);
extern void		sdp_free_attribute(sdp_attr_t *);
extern void		sdp_free_key(sdp_key_t *);
extern void		sdp_free_media(sdp_media_t *);

#ifdef __cplusplus
}
#endif

#endif /* _SDP_PARSE_H */
