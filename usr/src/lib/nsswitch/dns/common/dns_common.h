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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Common code and structures used by name-service-switch "dns" backends.
 */

#ifndef _DNS_COMMON_H
#define	_DNS_COMMON_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <strings.h>
#include <thread.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <syslog.h>
#include <nsswitch.h>
#include <nss_common.h>
#include <nss_dbdefs.h>
#include <stdlib.h>
#include <signal.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct dns_backend *dns_backend_ptr_t;
typedef nss_status_t (*dns_backend_op_t)(dns_backend_ptr_t, void *);

struct dns_backend {
	dns_backend_op_t	*ops;
	nss_dbop_t		n_ops;
};

/* multithreaded libresolv2 related functions and variables */
extern void	(*set_no_hosts_fallback)(void);
extern void	(*unset_no_hosts_fallback)(void);
extern struct __res_state	*(*set_res_retry)();
extern int	(*enable_mt)();
extern int	(*disable_mt)();
extern int	*(*get_h_errno)();
extern int	(*override_retry)(int);
extern void	switch_resolver_setup(int *, sigset_t *, int *);
extern void	switch_resolver_reset(int, sigset_t, int);
extern mutex_t	one_lane;

extern int ent2result(struct hostent *, nss_XbyY_args_t *, int);
extern int ent2str(struct hostent *, nss_XbyY_args_t *, int);

nss_backend_t *_nss_dns_constr(dns_backend_op_t *, int);
extern	nss_status_t _herrno2nss(int);

nss_status_t _nss_dns_gethost_withttl(void *buf, size_t bufsize, int ipnode);
nss_status_t _nss_get_dns_hosts_name(dns_backend_ptr_t *, void **, size_t *);
nss_status_t _nss_get_dns_ipnodes_name(dns_backend_ptr_t *, void **, size_t *);

#ifdef	__cplusplus
}
#endif

#endif /* _DNS_COMMON_H */
