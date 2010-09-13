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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SIP_PARSE_URI_H
#define	_SIP_PARSE_URI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sip.h>

#define	SIP_URI_BUF_SIZE	128

#define	SIP_SCHEME		"sip"
#define	SIPS_SCHEME		"sips"

#define	SIP_SCHEME_LEN		3
#define	SIPS_SCHEME_LEN		4

/*
 * SIP-URI = "sip:" [ userinfo ] hostport
 *           uri-parameters [ headers ]
 * SIPS-URI =  "sips:" [ userinfo ] hostport
 *           uri-parameters [ headers ]
 * uri-parameters = *( ";" uri-parameter)
 * uri-parameter = transport-param / user-param / method-param
 *                 / ttl-param / maddr-param / lr-param / other-param
 * transport-param   =  "transport="
 *                      "udp" / "tcp" / "sctp" / "tls"/ other-transport)
 * other-transport   =  token
 * headers  =  "?" header *( "&" header )
 */
typedef struct sip_uri_sip_s {
	sip_param_t 	*sip_params;
	sip_str_t 	sip_headers;
} sip_uri_sip_t;

/*
 * opaque	uri opaque part
 * query	uri query
 * path		uri path
 * regname	uri reg-name
 */
typedef struct sip_uri_abs_s {
	sip_str_t	sip_uri_opaque;
	sip_str_t 	sip_uri_query;
	sip_str_t 	sip_uri_path;
	sip_str_t 	sip_uri_regname;
} sip_uri_abs_t;

/*
 * structure for a parsed URI
 *   sip_uri_scheme		URI scheme
 *   sip_uri_user		user name
 *   sip_uri_password		password for the user
 *   sip_uri_host		host name
 *   sip_uri_port		port number for the host (0 = none specified)
 *   sip_uri_errflags		error flags
 *   sip_uri_issip		is this a SIP  URI.
 *   sip_uri_isteluser		user is a telephone-subscriber
 */
typedef struct sip_uri {
	sip_str_t	sip_uri_scheme;
	sip_str_t 	sip_uri_user;
	sip_str_t	sip_uri_password;
	sip_str_t	sip_uri_host;
	uint_t		sip_uri_port;
	uint_t		sip_uri_errflags;
	boolean_t	sip_uri_issip;
	boolean_t	sip_uri_isteluser;
	union {
		sip_uri_sip_t	sip_sipuri;	/* SIP URI */
		sip_uri_abs_t	sip_absuri;	/* Absolute URI */
	} specific;
}_sip_uri_t;

#define	sip_uri_params		specific.sip_sipuri.sip_params
#define	sip_uri_headers		specific.sip_sipuri.sip_headers
#define	sip_uri_opaque		specific.sip_absuri.sip_uri_opaque
#define	sip_uri_query		specific.sip_absuri.sip_uri_query
#define	sip_uri_path		specific.sip_absuri.sip_uri_path
#define	sip_uri_regname		specific.sip_absuri.sip_uri_regname

extern void	sip_uri_parse_it(_sip_uri_t *, sip_str_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SIP_PARSE_URI_H */
