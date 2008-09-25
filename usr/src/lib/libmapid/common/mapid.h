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

#ifndef	_MAPID_H
#define	_MAPID_H

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
#include <deflt.h>
#include <nfs/nfs4.h>

#define	DNAMEMAX			(NS_MAXCDNAME + 1)

typedef struct {
	void	*(*fcn)(void *);
	int	 signal;
} cb_t;

#ifdef	__LIBMAPID_IMPL

/*
 * Error Messages
 */
#define	EMSG_NETDB_INTERNAL	"Internal Resolver Error: %s"

#define	EMSG_TRY_AGAIN		"\"%s\" DNS nameserver(s) not responding" \
				"...\tRetrying"

#define	EMSG_NO_RECOVERY	"Unrecoverable Resolver Error: %s"

#define	EMSG_HOST_NOT_FOUND	"Authoritative nameserver unresponsive " \
				"to queries for domain \"%s\""

#define	EMSG_NO_DATA		"\"%s\" DNS TXT record not found: "\
				"Defaulting to \"%s\""

#define	EMSG_DNS_THREAD_ERROR	"Unable to create DNS query thread"

#define	EMSG_DNS_DISABLE	"%s: Further DNS queries disabled !"

#define	EMSG_DNS_RR_INVAL	"\"%s\" Invalid DNS TXT record: "\
				"Defaulting to \"%s\""

/*
 * DNS related info
 */
#define	NFSMAPID_DNS_RR			"_nfsv4idmapdomain"
#define	NFSMAPID_DNS_TOUT_SECS		(30LL)
#define	NFSMAPID_SLOG_RATE		20	/* ~10 mins */

#define	NS_ERRS				6	/* netdb.h */

typedef union {
	HEADER	hdr;
	uchar_t	buf[PACKETSZ];
} ans_t;

/*
 * NOTE: All s_ prefixed variables are only to be used by the DNS
 *       feature implementation (mapid.c). The exported globals
 *	 (ie. seen by nfsmapid.c/nfsmapid_server.c) are the
 *       dns_ prefixed variables along with sysdns_domain.
 */
static ans_t			 s_ans;
static int			 s_anslen;
static char			 s_dname[DNAMEMAX] = {0};
static char			 s_txt_rr[DNAMEMAX] = {0};

static rwlock_t			 s_dns_data_lock = DEFAULTRWLOCK;
static rwlock_t			 s_dns_impl_lock = DEFAULTRWLOCK;
static mutex_t			 s_res_lock = ERRORCHECKMUTEX;
static uint32_t			 s_dns_tout = 0;
static thread_t			 s_dns_qthread;
static bool_t			 s_dns_qthr_created = FALSE;
static bool_t			 s_dns_disabled = FALSE;
static struct __res_state	 s_res = {0};
static thread_key_t		 s_thr_key;
int				 lib_init_done = 0;

static int			 resolv_init(void);
static void			 resolv_decode(void);
static int			 resolv_error(void);
static void			 resolv_get_txt_data(void);
static void			 resolv_txt_reset(void);
static void			 resolve_process_txt(uchar_t *, int);
static int			 resolv_search(void);
static void			 resolv_destroy(void);
static uchar_t			*resolv_skip_rr(uchar_t *, uchar_t *);
static void			 domain_sync(cb_t *, char *);
static int			 get_mtime(const char *, timestruc_t *);
static void			 get_nfs_domain(void);
static void			 get_dns_domain(void);
static void			 get_dns_txt_domain(cb_t *);
void				 _lib_init(void);

#ifdef	DEBUG
bool_t				 nfsmapid_debug = FALSE;
#endif	/* DEBUG */

/*
 * mapid_domain_lock:	rwlock used to serialize access/changes
 *			to the library's mapid_domain global var.
 *
 * mapid_domain:	Library variable used to store the current
 *			domain configured for use in decoding/encoding
 *			outbound and inbound attr strings, accordingly.
 *
 * nfs_domain:		If /etc/default/nfs NFSMAPID_DOMAIN var
 *			has been set, nfs_domain will hold this
 *			value for the duration of the instance;
 *			If the value ever changes, the change is
 *			detected via the use of nfs_mtime and
 *			nfs_domain is updated accordingly.
 *
 * dns_domain:		If the system's resolver (/etc/resolv.conf)
 *			has been configured, dns_domain will hold
 *			the configured DNS domain as reported by the
 *			res_ninit() resolver interface. If the system's
 *			/etc/resolv.conf file is updated, the change
 *			is detected via the use of dns_mtime and
 *			dns_domain is updated accordingly.
 */
rwlock_t			mapid_domain_lock = DEFAULTRWLOCK;
uint32_t			mapid_domain_len = 0;
char				mapid_domain[DNAMEMAX] = {0};

timestruc_t			nfs_mtime = {0};
uint32_t			nfs_domain_len = 0;
char				nfs_domain[DNAMEMAX] = {0};

timestruc_t			dns_mtime = {0};
uint32_t			dns_domain_len = 0;
char				dns_domain[DNAMEMAX] = {0};

int				dns_txt_cached = 0;
uint32_t			dns_txt_domain_len = 0;
char				dns_txt_domain[DNAMEMAX] = {0};
char				sysdns_domain[DNAMEMAX] = {0};

timestruc_t			zapped_mtime = {0};

#define	ZAP_DOMAIN(which)			\
	{					\
		bzero(which##_domain, DNAMEMAX);\
		which##_domain_len = 0;		\
		which##_mtime = zapped_mtime;	\
	}

#define	TIMESTRUC_EQ(a, b)			\
		(((a).tv_sec == (b).tv_sec) &&	\
		((a).tv_nsec == (b).tv_nsec))



#endif	/* __LIBMAPID_IMPL */

/*
 * PSARC 2005/487 Consolidation Private Interfaces
 * mapid_reeval_domain(), mapid_get_domain()
 * Changes must be reviewed by Solaris File Sharing
 */
extern void			 mapid_reeval_domain(cb_t *);
extern char			*mapid_get_domain(void);

/*
 * PSARC 2005/487 Contracted Sun Private Interface
 * mapid_derive_domain(), mapid_stdchk_domain()
 * Changes must be reviewed by Solaris File Sharing
 * Changes must be communicated to contract-2005-487-01@sun.com
 */
extern int			 mapid_stdchk_domain(const char *);
extern char			*mapid_derive_domain(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _MAPID_H */
