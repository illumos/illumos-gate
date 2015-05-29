/*
 * CDDL HEADER START
 *
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2015, 2016 by Delphix. All rights reserved.
 */

#ifndef	_CONNSTAT_H
#define	_CONNSTAT_H

#include <sys/types.h>
#include <sys/socket.h>
#include <ofmt.h>
#include <sys/stropts.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct connstat_conn_attr_s {
	struct sockaddr_storage	ca_laddr;
	struct sockaddr_storage	ca_raddr;
	int			ca_lport;
	int			ca_rport;
	int			ca_state;
} connstat_conn_attr_t;

typedef struct conn_walk_state_s {
	ofmt_handle_t		cws_ofmt;
	uint_t			cws_flags;
	connstat_conn_attr_t	cws_filter;
} conn_walk_state_t;

/* cws_flags */
#define	CS_LOOPBACK	0x0001	/* Include loopback connections */
#define	CS_IPV4		0x0002	/* Show only IPv4 connections */
#define	CS_IPV6		0x0004	/* Show only IPv6 connections */
#define	CS_LADDR	0x0008	/* Filter by laddr in cws_filter */
#define	CS_RADDR	0x0010	/* Filter by raddr in cws_filter */
#define	CS_LPORT	0x0020	/* Filter by lport in cws_filter */
#define	CS_RPORT	0x0040	/* Filter by rport in cws_filter */
#define	CS_STATE	0x0080	/* Filter by state in cws_filter */
#define	CS_PARSABLE	0x0100	/* Parsable output */

typedef ofmt_field_t *connstat_getfieldsfunc_t(void);
typedef void connstat_walkfunc_t(struct strbuf *, conn_walk_state_t *);

typedef struct connstat_proto_s {
	char	*csp_proto;
	char	*csp_default_fields;
	int	csp_miblevel;
	int	csp_mibv4name;
	int	csp_mibv6name;
	connstat_getfieldsfunc_t *csp_getfields;
	connstat_walkfunc_t *csp_v4walk;
	connstat_walkfunc_t *csp_v6walk;
} connstat_proto_t;

boolean_t print_string(ofmt_arg_t *, char *, uint_t);
boolean_t print_uint16(ofmt_arg_t *, char *, uint_t);
boolean_t print_uint32(ofmt_arg_t *, char *, uint_t);
boolean_t print_uint64(ofmt_arg_t *, char *, uint_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _CONNSTAT_H */
