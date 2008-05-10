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

#ifndef	_LIBSMBNS_H
#define	_LIBSMBNS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <ldap.h>
#include <smbsrv/libsmb.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* ADS typedef/data structures and functions */
#define	ADS_MAXBUFLEN 100

typedef struct ads_handle_s {
	char *user;		/* admin user to create share in ADS */
	char *pwd;		/* user password */
	char *domain;		/* ADS domain */
	char *domain_dn;	/* domain in Distinquish Name format */
	char *ip_addr;		/* ip addr in string format */
	char *hostname;		/* fully qualified hostname */
	char *site;		/* local ADS site */
	LDAP *ld;		/* LDAP handle */
} ADS_HANDLE;

/*
 * The possible return status of the adjoin routine.
 */
typedef enum adjoin_status {
	ADJOIN_SUCCESS = 0,
	ADJOIN_ERR_GET_HANDLE,
	ADJOIN_ERR_GEN_PASSWD,
	ADJOIN_ERR_ADD_TRUST_ACCT,
	ADJOIN_ERR_MOD_TRUST_ACCT,
	ADJOIN_ERR_GET_ENCTYPES,
	ADJOIN_ERR_INIT_KRB_CTX,
	ADJOIN_ERR_GET_SPNS,
	ADJOIN_ERR_KSETPWD,
	ADJOIN_ERR_UPDATE_CNTRL_ATTR,
	ADJOIN_ERR_WRITE_KEYTAB,
	ADJOIN_ERR_IDMAP_SET_DOMAIN,
	ADJOIN_ERR_IDMAP_REFRESH,
	ADJOIN_NUM_STATUS
} adjoin_status_t;

/* ADS functions */
extern void ads_init(void);
extern void ads_refresh(void);
extern ADS_HANDLE *ads_open(void);
extern void ads_close(ADS_HANDLE *);
extern int ads_publish_share(ADS_HANDLE *, const char *, const char *,
    const char *, const char *);
extern int ads_remove_share(ADS_HANDLE *, const char *, const char *,
    const char *, const char *);
extern int ads_build_unc_name(char *, int, const char *, const char *);
extern int ads_lookup_share(ADS_HANDLE *, const char *, const char *, char *);
extern int ads_add_share(ADS_HANDLE *, const char *, const char *,
    const char *);
extern adjoin_status_t ads_join(char *, char *, char *, char *, int);
extern char *adjoin_report_err(adjoin_status_t);
extern int ads_domain_change_cleanup(char *);
extern int ads_update_attrs(void);

/* DYNDNS functions */
extern int dns_msgid_init(void);
extern int dyndns_update(char *);
extern int dyndns_update_core(char *);
extern int dyndns_clear_rev_zone(char *);

/* Kerberos initialization function */
extern int smb_kinit(char *, char *);
extern int smb_ccache_init(char *, char *);
extern void smb_ccache_remove(char *);

/* NETBIOS Functions */
extern int msdcs_lookup_ads(char *, char *);
extern int smb_netbios_start(void);
extern void smb_netbios_shutdown(void);
extern void smb_netbios_name_reconfig(void);

/* Browser Functions */
extern void smb_browser_reconfig(void);
extern void smb_browser_netlogon(char *);


#ifdef	__cplusplus
}
#endif

#endif	/* _LIBSMBNS_H */
