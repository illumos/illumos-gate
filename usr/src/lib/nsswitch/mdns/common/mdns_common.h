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

#ifndef _MDNS_COMMON_H
#define	_MDNS_COMMON_H

#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <strings.h>
#include <syslog.h>
#include <sys/time.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <nsswitch.h>
#include <nss_common.h>
#include <nss_dbdefs.h>
#include <stdlib.h>
#include <signal.h>
#include <libscf.h>
#include <dns_sd.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	NSSMDNS_MAXQRYTMO	1
#define	NSSMDNS_MAXSRCHDMNS	6
#define	NSSMDNS_MAXVALIDDMNS	10

#define	SMF_MDNS_FMRI "svc:/network/dns/multicast:default"
#define	SMF_NSSMDNSCFG_PROPGRP "nss_mdns_config"
#define	SMF_NSSMDNSCFG_SRCHPROP "search"
#define	SMF_NSSMDNSCFG_DMNPROP "domain"

typedef struct mdns_backend *mdns_backend_ptr_t;
typedef nss_status_t (*mdns_backend_op_t)(mdns_backend_ptr_t, void *);

struct mdns_backend {
	mdns_backend_op_t	*ops;
	nss_dbop_t		n_ops;
	char *dmnsrchlist[NSSMDNS_MAXSRCHDMNS];
	char *validdmnlist[NSSMDNS_MAXVALIDDMNS];
	struct timeval conftimestamp;
};

struct mdns_querydata {
	nss_XbyY_args_t *argp;
	char *buffer;
	int buflen;
	int ttl;
	boolean_t qrydone;
	int status;
	int af;
	char paddrbuf[INET6_ADDRSTRLEN + 1];
	int withttlbsize;
	char *withttlbuffer;
};

nss_backend_t *_nss_mdns_constr(mdns_backend_op_t *, int);
void _nss_mdns_destr(mdns_backend_ptr_t);
int _nss_mdns_querybyname(mdns_backend_ptr_t, char *name,
		int af, struct mdns_querydata *data);
int _nss_mdns_querybyaddr(mdns_backend_ptr_t, char *name,
		int af, struct mdns_querydata *data);
void _nss_mdns_updatecfg(mdns_backend_ptr_t);

nss_status_t _nss_mdns_gethost_withttl(void *buf, size_t bufsize, int ipnode);
nss_status_t _nss_get_mdns_hosts_name(mdns_backend_ptr_t *be,
		void **bufp, size_t *sizep);
nss_status_t _nss_get_mdns_ipnodes_name(mdns_backend_ptr_t *be,
		void **bufp, size_t *sizep);

#ifdef	__cplusplus
}
#endif

#endif /* _MDNS_COMMON_H */
