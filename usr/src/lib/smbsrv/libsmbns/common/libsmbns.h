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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef	_LIBSMBNS_H
#define	_LIBSMBNS_H

#include <ldap.h>
#include <smbsrv/libsmb.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* ADS typedef/data structures and functions */


typedef struct smb_ads_handle {
	char *domain;		/* ADS domain (in lower case) */
	char *domain_dn;	/* domain in Distinquish Name format */
	char *ip_addr;		/* ip addr in string format */
	char *hostname;		/* fully qualified hostname */
	char *site;		/* local ADS site */
	LDAP *ld;		/* LDAP handle */
} smb_ads_handle_t;

typedef struct smb_ads_host_info {
	char name[MAXHOSTNAMELEN];  /* fully qualified hostname */
	int port;		/* ldap port */
	int priority;		/* DNS SRV record priority */
	int weight;		/* DNS SRV record weight */
	smb_inaddr_t ipaddr;	/* network byte order */
} smb_ads_host_info_t;

/*
 * The possible return status of the adjoin routine.
 */
typedef enum smb_adjoin_status {
	SMB_ADJOIN_SUCCESS = 0,
	SMB_ADJOIN_ERR_GET_HANDLE,
	SMB_ADJOIN_ERR_GEN_PWD,
	SMB_ADJOIN_ERR_GET_DCLEVEL,
	SMB_ADJOIN_ERR_ADD_TRUST_ACCT,
	SMB_ADJOIN_ERR_MOD_TRUST_ACCT,
	SMB_ADJOIN_ERR_DUP_TRUST_ACCT,
	SMB_ADJOIN_ERR_TRUST_ACCT,
	SMB_ADJOIN_ERR_INIT_KRB_CTX,
	SMB_ADJOIN_ERR_GET_SPNS,
	SMB_ADJOIN_ERR_KSETPWD,
	SMB_ADJOIN_ERR_UPDATE_CNTRL_ATTR,
	SMB_ADJOIN_ERR_WRITE_KEYTAB,
	SMB_ADJOIN_ERR_IDMAP_SET_DOMAIN,
	SMB_ADJOIN_ERR_IDMAP_REFRESH,
	SMB_ADJOIN_ERR_COMMIT_KEYTAB
} smb_adjoin_status_t;

/* ADS functions */
extern void smb_ads_init(void);
extern void smb_ads_fini(void);
extern void smb_ads_refresh(void);
extern smb_ads_handle_t *smb_ads_open(void);
extern void smb_ads_close(smb_ads_handle_t *);
extern int smb_ads_publish_share(smb_ads_handle_t *, const char *, const char *,
    const char *, const char *);
extern int smb_ads_remove_share(smb_ads_handle_t *, const char *, const char *,
    const char *, const char *);
extern int smb_ads_build_unc_name(char *, int, const char *, const char *);
extern int smb_ads_lookup_share(smb_ads_handle_t *, const char *, const char *,
    char *);
extern int smb_ads_add_share(smb_ads_handle_t *, const char *, const char *,
    const char *);
extern smb_adjoin_status_t smb_ads_join(char *, char *, char *, char *);
extern void smb_ads_join_errmsg(smb_adjoin_status_t);
extern boolean_t smb_ads_lookup_msdcs(char *, char *, char *, uint32_t);
extern smb_ads_host_info_t *smb_ads_find_host(char *, char *);

/* DYNDNS functions */
extern void *dyndns_publisher(void *);
extern void dyndns_start(void);
extern void dyndns_stop(void);
extern int dyndns_update(char *);
extern void dyndns_update_zones(void);
extern void dyndns_clear_zones(void);

/* Kerberos cache management function */
extern int smb_ccache_init(char *, char *);
extern void smb_ccache_remove(char *);

/* NETBIOS Functions */
extern int smb_netbios_start(void);
extern void smb_netbios_stop(void);
extern void smb_netbios_name_reconfig(void);

/* Browser Functions */
extern void smb_browser_reconfig(void);
extern boolean_t smb_browser_netlogon(char *, char *, uint32_t);


#ifdef	__cplusplus
}
#endif

#endif	/* _LIBSMBNS_H */
