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

#ifndef	_LIBSMBNS_H
#define	_LIBSMBNS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <ldap.h>
#include <net/if.h>

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
	ADJOIN_ERR_GET_HOST_PRINC,
	ADJOIN_ERR_INIT_KRB_CTX,
	ADJOIN_ERR_GET_KRB_PRINC,
	ADJOIN_ERR_KSETPWD,
	ADJOIN_ERR_UPDATE_CNTRL_ATTR,
	ADJOIN_ERR_WRITE_KEYTAB,
	ADJOIN_ERR_IDMAP_SET_DOMAIN,
	ADJOIN_ERR_IDMAP_REFRESH,
	ADJOIN_ERR_SMB_REFRESH,
	ADJOIN_NUM_STATUS
} adjoin_status_t;

/* ADS functions */
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
extern int ads_domain_change_notify_handler(char *);
extern adjoin_status_t ads_join(char *, char *, char *, int);
extern char *adjoin_report_err(adjoin_status_t status);

/* DYNDNS functions */
extern int dyndns_update(void);
extern int dyndns_clear_rev_zone(void);

/* Kerberos initialization function */
extern int smb_kinit(char *user, char *passwd);


/* NETBIOS Functions */
extern int msdcs_lookup_ads(void);
extern void smb_netbios_start(void);
extern void smb_netbios_shutdown(void);
extern void smb_netbios_name_reconfig(void);

/* Browser Configure */
extern void smb_browser_config(void);

extern void smb_netlogon_request(int, int, char *);

/*
 * NIC listing and config
 */
#define	MAXIFS	256
#define	SIZE_IP	17

typedef struct {
	char		ifname[LIFNAMSIZ];
	uint32_t	ip;
	uint32_t	mask;
	uint32_t	broadcast;
	boolean_t	exclude;
	uint64_t	flags;
	char		groupname[LIFGRNAMSIZ];
	char		**aliases;
	int		naliases;
} net_cfg_t;
typedef struct {
	net_cfg_t	*net_cfg_list;
	int		net_cfg_cnt;
} net_cfg_list_t;

struct if_list {
	char		name[IFNAMSIZ+1];
	struct if_list	*next;
};

struct ip_alias {
	char		name[SIZE_IP];
	struct ip_alias	*next;
};

#define	GATEWAY_FILE	"/etc/defaultrouter"

/* NIC Config functions */
extern void smb_resolver_init(void);
extern void smb_resolver_close(void);
extern int smb_get_nameservers(struct in_addr *, int);
extern uint16_t smb_get_next_resid(void);
extern void smb_nic_lock(void);
extern void smb_nic_unlock(void);
extern int smb_nic_init(void);
extern void smb_nic_build_info(void);
extern net_cfg_t *smb_nic_get_byind(int, net_cfg_t *);
extern net_cfg_t *smb_nic_get_bysubnet(uint32_t, net_cfg_t *);
extern net_cfg_t *smb_nic_get_byip(uint32_t, net_cfg_t *);
extern int smb_nic_get_num(void);
extern int smb_nic_get_IP(char *, uint32_t *uip);
extern int smb_nic_get_broadcast(char *, uint32_t *uip);
extern int smb_nic_get_netmask(char *, uint32_t *uip);
extern int smb_nic_get_IP_aliases(char *, struct ip_alias **);
extern int smb_nic_get_number(void);
extern int smb_nic_get_num_physical(void);
extern int smb_nic_get_num_logical(void);
extern int smb_nic_get_num_aliases(char *);
extern int smb_nic_get_default_gateway(char *, unsigned int);
extern int smb_nic_flags(char *, uint64_t *);
extern int smb_nic_build_if_name(char ***);
extern int smb_nic_build_network_structures(net_cfg_t **, int *);
extern char *smb_nic_get_ifnames(int, int);
extern int smb_nic_validate_ip_address(char *);
extern int smb_nic_status(char *, uint64_t);
extern int smb_nic_get_group(char *lifname, char *grname);
extern int smb_nic_set_group(char *lifname, char *grname);
extern int smb_nic_clear_niclist(net_cfg_t *, int);
extern int smb_nic_clear_name_list(char **, int);
extern int smb_nic_clear_ip_alias(struct ip_alias *);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBSMBNS_H */
