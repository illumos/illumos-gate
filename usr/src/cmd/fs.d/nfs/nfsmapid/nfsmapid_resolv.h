/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_NFSMAPID_RESOLV_H
#define	_NFSMAPID_RESOLV_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <rpc/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>
#include <errno.h>
#include <ctype.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <assert.h>
#include <synch.h>
#include <syslog.h>
#include <locale.h>
#include <thread.h>
#include <sys/sdt.h>

#ifndef	DEBUG
#define	IDMAP_DBG(txt, arg1, arg2)
#else
#define	IDMAP_DBG(txt, arg1, arg2)					\
	if (nfsmapid_debug) {						\
		if (arg1 != NULL && arg2 != NULL)			\
			syslog(LOG_ERR, gettext(txt), arg1, arg2);	\
		else if (arg1 != NULL && arg2 == NULL)			\
			syslog(LOG_ERR, gettext(txt), arg1);		\
		else if (arg1 == NULL && arg2 != NULL)			\
			syslog(LOG_ERR, gettext(txt), arg2);		\
	}
#endif	/* DEBUG */

#ifdef	__NFSMAPID_RES_IMPL
/*
 * Error Messages
 */
#define	EMSG_NETDB_INTERNAL	\
	gettext("Internal Resolver Error: %s")

#define	EMSG_TRY_AGAIN		\
	gettext("\"%s\" DNS nameserver(s) not responding...\tRetrying")

#define	EMSG_NO_RECOVERY	\
	gettext("Unrecoverable Resolver Error: %s")

#define	EMSG_HOST_NOT_FOUND	\
	gettext("Authoritative nameserver unresponsive to queries " \
		"for domain \"%s\"")

#define	EMSG_NO_DATA		\
	gettext("\"%s\" DNS TXT record not found: Defaulting to \"%s\"")

#define	EMSG_DNS_THREAD_ERROR  \
	gettext("Unable to create DNS query thread")

#define	EMSG_DNS_DISABLE \
	gettext("%s: Further DNS queries disabled !")

#define	EMSG_DNS_RR_INVAL \
	gettext("\"%s\" Invalid DNS TXT record: Defaulting to \"%s\"")

/*
 * DNS related info
 */
#define	NFSMAPID_DNS_RR			"_nfsv4idmapdomain"
#define	NFSMAPID_DNS_TOUT_SECS		(30LL)
#define	NFSMAPID_SLOG_RATE		20	/* ~10 mins */

#define	DNAMEMAX			(NS_MAXCDNAME + 1)
#define	NS_ERRS				6	/* netdb.h */

typedef union {
	HEADER	hdr;
	uchar_t	buf[PACKETSZ];
} ans_t;

/*
 * NOTE: All s_ prefixed variables are only to be used by the DNS
 *       feature implementation (nfsmapid_resolv.c). The exported
 *       globals (ie. seen by nfsmapid.c/nfsmapid_server.c) are the
 *       dns_ prefixed variables along with sysdns_domain.
 */
static ans_t			 s_ans;
static int			 s_anslen;
static char			 s_dname[DNAMEMAX] = {0};
static char			 s_txt_rr[DNAMEMAX] = {0};

static rwlock_t			 s_dns_impl_lock = DEFAULTRWLOCK;
static mutex_t			 s_res_lock = ERRORCHECKMUTEX;
static uint32_t			 s_dns_tout = 0;
static thread_t			 s_dns_qthread;
static bool_t			 s_dns_qthr_created = FALSE;
static bool_t			 s_dns_disabled = FALSE;
static struct __res_state	 s_res = {0};

static void			 resolv_decode(void);
static int			 resolv_error(void);
static void			 resolv_get_txt_data(void);
static void			 resolv_txt_reset(void);
static void			 resolve_process_txt(uchar_t *, int);
static int			 resolv_search(void);
static uchar_t			*resolv_skip_rr(uchar_t *, uchar_t *);

#ifdef	DEBUG
bool_t				 nfsmapid_debug = FALSE;
#endif	/* DEBUG */

uint32_t			 dns_txt_domain_len = 0;
char				 dns_txt_domain[DNAMEMAX] = {0};
char				 sysdns_domain[DNAMEMAX] = {0};
rwlock_t			 dns_data_lock = DEFAULTRWLOCK;
int				 dns_txt_cached = 0;

extern uint32_t			 cur_domain_len;
extern char			 cur_domain[];
extern rwlock_t			 domain_cfg_lock;
extern void			 idmap_kcall(int);
extern int			 standard_domain_str(const char *);
extern void			 update_diag_file(char *);

#else	/* __NFSMAPID_RES_IMPL */

/*
 * exported interfaces + data
 */
extern int			resolv_init(void);
extern void			get_dns_txt_domain(int);

#ifdef	DEBUG
extern bool_t			nfsmapid_debug;
#endif	/* DEBUG */

extern uint32_t			dns_txt_domain_len;
extern char			dns_txt_domain[];
extern rwlock_t			dns_data_lock;
extern char			sysdns_domain[];

#endif	/* __NFSMAPID_RES_IMPL */

#ifdef	__cplusplus
}
#endif

#endif	/* _NFSMAPID_RESOLV_H */
