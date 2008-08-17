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

#pragma ident	"@(#)smbns_ads.c	1.12	08/08/06 SMI"

#include <sys/param.h>
#include <ldap.h>
#include <stdlib.h>
#include <gssapi/gssapi.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <netdb.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <sys/synch.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <smbsrv/libsmbns.h>
#include <smbns_ads.h>
#include <smbns_dyndns.h>
#include <smbns_krb.h>

#define	SMB_ADS_DN_MAX	300
#define	SMB_ADS_MAXMSGLEN 512
#define	SMB_ADS_COMPUTERS_CN "Computers"
#define	SMB_ADS_COMPUTER_NUM_ATTR 8
#define	SMB_ADS_SHARE_NUM_ATTR 3
#define	SMB_ADS_SITE_MAX MAXHOSTNAMELEN

#define	SMB_ADS_MSDCS_SRV_DC_RR		"_ldap._tcp.dc._msdcs"
#define	SMB_ADS_MSDCS_SRV_SITE_RR	"_ldap._tcp.%s._sites.dc._msdcs"

/*
 * domainControllerFunctionality
 *
 * This rootDSE attribute indicates the functional level of the DC.
 */
#define	SMB_ADS_ATTR_DCLEVEL	"domainControllerFunctionality"
#define	SMB_ADS_DCLEVEL_W2K	0
#define	SMB_ADS_DCLEVEL_W2K3	2
#define	SMB_ADS_DCLEVEL_W2K8	3

/*
 * msDs-supportedEncryptionTypes (Windows Server 2008 only)
 *
 * This attribute defines the encryption types supported by the system.
 * Encryption Types:
 *  - DES cbc mode with CRC-32
 *  - DES cbc mode with RSA-MD5
 *  - ArcFour with HMAC/md5
 *  - AES-128
 *  - AES-256
 */
#define	SMB_ADS_ATTR_ENCTYPES	"msDs-supportedEncryptionTypes"
#define	SMB_ADS_ENC_DES_CRC	1
#define	SMB_ADS_ENC_DES_MD5	2
#define	SMB_ADS_ENC_RC4		4
#define	SMB_ADS_ENC_AES128	8
#define	SMB_ADS_ENC_AES256	16

#define	SMB_ADS_ATTR_SAMACCT	"sAMAccountName"
#define	SMB_ADS_ATTR_UPN	"userPrincipalName"
#define	SMB_ADS_ATTR_SPN	"servicePrincipalName"
#define	SMB_ADS_ATTR_CTL	"userAccountControl"
#define	SMB_ADS_ATTR_DNSHOST	"dNSHostName"
#define	SMB_ADS_ATTR_KVNO	"msDS-KeyVersionNumber"
#define	SMB_ADS_ATTR_DN		"distinguishedName"

/* current ADS server to communicate with */
static smb_ads_host_info_t *ads_host_info = NULL;
static mutex_t ads_host_mtx;
static char ads_site[SMB_ADS_SITE_MAX];
static mutex_t ads_site_mtx;

/*
 * adjoin_errmsg
 *
 * Use the adjoin return status defined in adjoin_status_t as the index
 * to this table.
 */
static char *adjoin_errmsg[] = {
	"ADJOIN succeeded.",
	"ADJOIN failed to get handle.",
	"ADJOIN failed to generate machine password.",
	"ADJOIN failed to add workstation trust account.",
	"ADJOIN failed to modify workstation trust account.",
	"ADJOIN failed to get list of encryption types.",
	"ADJOIN failed to initialize kerberos context.",
	"ADJOIN failed to get Kerberos principal.",
	"ADJOIN failed to set machine account password on AD.",
	"ADJOIN failed to modify CONTROL attribute of the account.",
	"ADJOIN failed to write Kerberos keytab file.",
	"ADJOIN failed to configure domain_name property for idmapd.",
	"ADJOIN failed to refresh idmap service."
};

static smb_ads_handle_t *smb_ads_open_main(char *, char *, char *);
static int smb_ads_bind(smb_ads_handle_t *);
static int smb_ads_add_computer(smb_ads_handle_t *, int, char *);
static int smb_ads_modify_computer(smb_ads_handle_t *, int, char *);
static int smb_ads_computer_op(smb_ads_handle_t *, int, int, char *);
static int smb_ads_lookup_computer_n_attr(smb_ads_handle_t *, char *, char **,
    int, char *);
static int smb_ads_update_computer_cntrl_attr(smb_ads_handle_t *, int, char *);
static krb5_kvno smb_ads_lookup_computer_attr_kvno(smb_ads_handle_t *, char *);
static int smb_ads_gen_machine_passwd(char *, int);
static smb_ads_host_info_t *smb_ads_get_host_info(void);
static void smb_ads_set_host_info(smb_ads_host_info_t *);
static void smb_ads_free_host_info(void);
static int smb_ads_get_spnset(char *, char **);
static void smb_ads_free_spnset(char **);
static int smb_ads_alloc_attr(LDAPMod **, int);
static void smb_ads_free_attr(LDAPMod **);
static int smb_ads_get_dc_level(smb_ads_handle_t *);
static smb_ads_host_info_t *smb_ads_select_dc(smb_ads_host_list_t *);

/*
 * smb_ads_init
 *
 * Initializes the ads_site global variable.
 */
void
smb_ads_init(void)
{
	(void) mutex_lock(&ads_site_mtx);
	(void) smb_config_getstr(SMB_CI_ADS_SITE, ads_site, sizeof (ads_site));
	(void) mutex_unlock(&ads_site_mtx);
}

/*
 * smb_ads_refresh
 *
 * If the ads_site has changed, clear the ads_host_info cache.
 */
void
smb_ads_refresh(void)
{
	char new_site[SMB_ADS_SITE_MAX];

	(void) smb_config_getstr(SMB_CI_ADS_SITE, new_site, sizeof (new_site));
	(void) mutex_lock(&ads_site_mtx);
	if (strcasecmp(ads_site, new_site)) {
		(void) strlcpy(ads_site, new_site, sizeof (ads_site));
		smb_ads_free_host_info();
	}
	(void) mutex_unlock(&ads_site_mtx);
}

/*
 * smb_ads_build_unc_name
 *
 * Construct the UNC name of the share object in the format of
 * \\hostname.domain\shareUNC
 *
 * Returns 0 on success, -1 on error.
 */
int
smb_ads_build_unc_name(char *unc_name, int maxlen,
    const char *hostname, const char *shareUNC)
{
	char my_domain[MAXHOSTNAMELEN];

	if (smb_getfqdomainname(my_domain, sizeof (my_domain)) != 0)
		return (-1);

	(void) snprintf(unc_name, maxlen, "\\\\%s.%s\\%s",
	    hostname, my_domain, shareUNC);
	return (0);
}

/*
 * smb_ads_ldap_ping
 *
 * This is used to bind to an ADS server to see
 * if it is still alive.
 *
 * Returns:
 *   -1: error
 *    0: successful
 */
/*ARGSUSED*/
static int
smb_ads_ldap_ping(smb_ads_host_info_t *ads_host)
{
	struct in_addr addr;
	int ldversion = LDAP_VERSION3, status, timeoutms = 5 * 1000;
	LDAP *ld = NULL;

	addr.s_addr = ads_host->ip_addr;

	ld = ldap_init((char *)inet_ntoa(addr), ads_host->port);
	if (ld == NULL)
		return (-1);

	ldversion = LDAP_VERSION3;
	(void) ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &ldversion);
	/* setup TCP/IP connect timeout */
	(void) ldap_set_option(ld, LDAP_X_OPT_CONNECT_TIMEOUT, &timeoutms);

	status = ldap_bind_s(ld, "", NULL, LDAP_AUTH_SIMPLE);

	if (status != LDAP_SUCCESS) {
		(void) ldap_unbind(ld);
		return (-1);
	}

	(void) ldap_unbind(ld);

	return (0);
}

/*
 * smb_ads_set_host_info
 * Cache the result of the ADS discovery if the cache is empty.
 */
static void
smb_ads_set_host_info(smb_ads_host_info_t *host)
{
	(void) mutex_lock(&ads_host_mtx);
	if (!ads_host_info)
		ads_host_info = host;
	(void) mutex_unlock(&ads_host_mtx);
}

/*
 * smb_ads_get_host_info
 * Get the cached ADS host info.
 */
static smb_ads_host_info_t *
smb_ads_get_host_info(void)
{
	smb_ads_host_info_t *host;

	(void) mutex_lock(&ads_host_mtx);
	host = ads_host_info;
	(void) mutex_unlock(&ads_host_mtx);
	return (host);
}

/*
 * smb_ads_skip_ques_sec
 * Skips the question section.
 */
static int
smb_ads_skip_ques_sec(int qcnt, uchar_t **ptr, uchar_t *eom)
{
	int i, len;

	for (i = 0; i < qcnt; i++) {
		if ((len = dn_skipname(*ptr, eom)) < 0) {
			syslog(LOG_ERR, "DNS query invalid message format");
			return (-1);
		}
		*ptr += len + QFIXEDSZ;
	}

	return (0);
}

/*
 * smb_ads_decode_host_ans_sec
 * Decodes ADS hosts, priority, weight and port number from the answer
 * section based on the current buffer pointer.
 */
static int
smb_ads_decode_host_ans_sec(int ans_cnt, uchar_t **ptr, uchar_t *eom,
    uchar_t *buf, smb_ads_host_info_t *ads_host_list)
{
	int i, len;
	smb_ads_host_info_t *ads_host;

	for (i = 0; i < ans_cnt; i++) {
		ads_host = &ads_host_list[i];

		if ((len = dn_skipname(*ptr, eom)) < 0) {
			syslog(LOG_ERR, "DNS query invalid message format");
			return (-1);
		}

		*ptr += len;

		/* skip type, class, ttl */
		*ptr += 8;
		/* data size */
		*ptr += 2;

		/* Get priority, weight */
		/* LINTED: E_CONSTANT_CONDITION */
		NS_GET16(ads_host->priority, *ptr);
		/* LINTED: E_CONSTANT_CONDITION */
		NS_GET16(ads_host->weight, *ptr);

		/* port */
		/* LINTED: E_CONSTANT_CONDITION */
		NS_GET16(ads_host->port, *ptr);
		/* domain name */
		len = dn_expand(buf, eom, *ptr, ads_host->name, MAXHOSTNAMELEN);
		if (len < 0) {
			syslog(LOG_ERR, "DNS query invalid SRV record");
			return (-1);
		}
		*ptr += len;
	}

	return (0);
}

/*
 * smb_ads_skip_auth_sec
 * Skips the authority section.
 */
static int
smb_ads_skip_auth_sec(int ns_cnt, uchar_t **ptr, uchar_t *eom)
{
	int i, len;
	uint16_t size;

	for (i = 0; i < ns_cnt; i++) {
		if ((len = dn_skipname(*ptr, eom)) < 0) {
			syslog(LOG_ERR, "DNS query invalid message format");
			return (-1);
		}
		*ptr += len;
		/* skip type, class, ttl */
		*ptr += 8;
		/* get len of data */
		/* LINTED: E_CONSTANT_CONDITION */
		NS_GET16(size, *ptr);
		if ((*ptr + size) > eom) {
			syslog(LOG_ERR, "DNS query invalid message format");
			return (-1);
		}

		*ptr += size;
	}

	return (0);
}

/*
 * smb_ads_decode_host_addi_sec
 * Decodes ADS hosts and IP Addresses from the additional section based
 * on the current buffer pointer.
 */
static int
smb_ads_decode_host_addi_sec(int addit_cnt, uchar_t **ptr, uchar_t *eom,
    uchar_t *buf, smb_ads_host_info_t *ads_host_list)
{
	int i, len;
	in_addr_t ipaddr;
	smb_ads_host_info_t *ads_host;

	for (i = 0; i < addit_cnt; i++) {
		ads_host = &ads_host_list[i];

		/* domain name */
		len = dn_expand(buf, eom, *ptr, ads_host->name, MAXHOSTNAMELEN);
		if (len < 0) {
			syslog(LOG_ERR, "DNS query invalid SRV record");
			return (-1);
		}
		*ptr += len;

		/* skip type, class, TTL, data len */
		*ptr += 10;

		/* LINTED: E_CONSTANT_CONDITION */
		NS_GET32(ipaddr, *ptr);

		ads_host->ip_addr = htonl(ipaddr);
	}

	return (0);
}

static void
smb_ads_init_host_info(smb_ads_host_info_t *ads_host,
    char *name, in_addr_t ipaddr, int priority, int weight, int port)
{
	(void) strlcpy(ads_host->name, name, MAXHOSTNAMELEN);
	ads_host->ip_addr = ipaddr;
	ads_host->priority = priority;
	ads_host->weight = weight;
	ads_host->port = port;
}

/*
 * smb_ads_hlist_alloc
 */
smb_ads_host_list_t *
smb_ads_hlist_alloc(int count)
{
	int size;
	smb_ads_host_list_t *hlist;

	size = sizeof (smb_ads_host_info_t) * count;
	hlist = (smb_ads_host_list_t *)malloc(sizeof (smb_ads_host_list_t));
	if (hlist == NULL)
		return (NULL);

	hlist->ah_cnt = count;
	hlist->ah_list = (smb_ads_host_info_t *)malloc(size);
	if (hlist->ah_list == NULL) {
		free(hlist);
		return (NULL);
	}

	bzero(hlist->ah_list, size);
	return (hlist);
}

/*
 * smb_ads_hlist_free
 */
static void
smb_ads_hlist_free(smb_ads_host_list_t *host_list)
{
	if (host_list == NULL)
		return;

	free(host_list->ah_list);
	free(host_list);
}

/*
 * smb_ads_find_host
 *
 * This routine sends a DNS service location (SRV) query message to the
 * DNS server via TCP to query it for a list of ADS server(s).  Once a reply
 * is received, the reply message is parsed to get the hostname.  A host
 * lookup by name is done to get the IP address if the additional section of
 * the reply packet does not contain any IP addresses.  If there are IP
 * addresses populated in the additional section then the additional section
 * is parsed to obtain the IP addresses.
 *
 * The service location of _ldap._tcp.dc.msdcs.<ADS domain> is used to
 * guarantee that Microsoft domain controllers are returned.  Microsoft domain
 * controllers are also ADS servers.
 *
 * The ADS hostnames are stored in the answer section of the DNS reply message.
 * The IP addresses are stored in the additional section.
 *
 * The DNS reply message may be in compress formed.  The compression is done
 * on repeating domain name label in the message.  i.e hostname.
 *
 * An ADS host is returned from the list of ADS servers.
 *
 * Parameters:
 *   domain: domain of ADS host.
 *   sought: the ADS host to be sought. It can be set to empty string to find
 *           any ADS hosts in that domain.
 *
 * Returns:
 *   ADS host: fully qualified hostname, ip address, ldap port.
 *   port    : LDAP port of ADS host.
 *
 */
/*ARGSUSED*/
smb_ads_host_info_t *
smb_ads_find_host(char *domain, char *sought, int *port)
{
	int i, error;
	struct hostent *h;
	struct in_addr addr;
	smb_ads_host_list_t *ans_hlist, *adt_hlist, *res_hlist;
	smb_ads_host_info_t *ads_host = NULL, *res_host = NULL;
	smb_ads_host_info_t *ans_hep;	/* Pointer to answer host entry */
	smb_ads_host_info_t *adt_hep;	/* Pointer to additional host entry */
	char *curdom = NULL;
	boolean_t same_domain, istrunc = B_FALSE;
	int len, qcnt, ans_cnt, ns_cnt, addit_cnt;
	uchar_t *ptr, *eom;
	struct __res_state res_state;
	union {
		HEADER hdr;
		uchar_t buf[NS_MAXMSG];
	} msg;
	char site_service[MAXHOSTNAMELEN];
	char *svc_name[2] = {site_service, SMB_ADS_MSDCS_SRV_DC_RR};
	int hlist_cnt = 0;

	/*
	 * If we have already found an ADS server in the given domain, return
	 * the cached ADS host if either the sought host is not specified or
	 * the cached ADS host matches the sought host.
	 */
	res_host = smb_ads_get_host_info();
	if (res_host) {
		curdom = strchr(res_host->name, '.');
		same_domain = (curdom && !strcasecmp(++curdom, domain));
		if (same_domain && (!sought ||
		    (sought && !strncasecmp(res_host->name, sought,
		    strlen(sought))))) {
			if (smb_ads_ldap_ping(res_host) == 0)
				return (res_host);
		}

		smb_ads_free_host_info();
	}

	bzero(&res_state, sizeof (struct __res_state));
	if (res_ninit(&res_state) < 0)
		return (NULL);

	/* use TCP */
	res_state.options |= RES_USEVC;

	(void) mutex_lock(&ads_site_mtx);
	if (*ads_site == '\0')
		*site_service = '\0';
	else
		(void) snprintf(site_service, sizeof (site_service),
		    SMB_ADS_MSDCS_SRV_SITE_RR, ads_site);
	(void) mutex_unlock(&ads_site_mtx);

	/*
	 * First look for ADS hosts in ADS site if configured.  Then try
	 * without ADS site info.
	 */
	for (i = 0; i < 2; i++) {
		if (*svc_name[i] == '\0')
			continue;

		len = res_nquerydomain(&res_state, svc_name[i], domain,
		    C_IN, T_SRV, msg.buf, sizeof (msg.buf));

		smb_tracef("Querying DNS for SRV RRs named '%s'", svc_name[i]);

		if (len < 0) {
			smb_tracef("DNS query for '%s' failed (%s)",
			    svc_name[i], hstrerror(res_state.res_h_errno));
			continue;
		}
		if (len > sizeof (msg.buf)) {
			syslog(LOG_ERR, "DNS query %ib message doesn't fit"
			    " into %ib buffer",
			    len, sizeof (msg.buf));
			continue;
		}

		/* 2. parse the reply, skip header and question sections */

		ptr = msg.buf + sizeof (msg.hdr);
		eom = msg.buf + len;

		/* check truncated message bit */
		if (msg.hdr.tc)
			istrunc = B_TRUE;

		qcnt = ntohs(msg.hdr.qdcount);
		ans_cnt = ntohs(msg.hdr.ancount);
		ns_cnt = ntohs(msg.hdr.nscount);
		addit_cnt = ntohs(msg.hdr.arcount);

		if (smb_ads_skip_ques_sec(qcnt, &ptr, eom) != 0) {
			res_ndestroy(&res_state);
			return (NULL);
		}

		ans_hlist = smb_ads_hlist_alloc(ans_cnt);
		if (ans_hlist == NULL) {
			res_ndestroy(&res_state);
			return (NULL);
		}

		ans_hep = ans_hlist->ah_list;

		/* 3. walk through the answer section */

		if (smb_ads_decode_host_ans_sec(ans_cnt, &ptr, eom, msg.buf,
		    ans_hep) != 0) {
			smb_ads_hlist_free(ans_hlist);
			res_ndestroy(&res_state);
			return (NULL);
		}

		/* check authority section */
		if (ns_cnt > 0) {
			if (smb_ads_skip_auth_sec(ns_cnt, &ptr, eom) != 0) {
				smb_ads_hlist_free(ans_hlist);
				res_ndestroy(&res_state);
				return (NULL);
			}
		}

		/*
		 * Check additional section to get IP address of ADS host.
		 * If additional section contains no IP address(es) then
		 * do a host lookup by hostname to get the IP address.
		 */
		if (addit_cnt > 0) {
			int j;

			adt_hlist = smb_ads_hlist_alloc(addit_cnt);
			if (adt_hlist == NULL) {
				smb_ads_hlist_free(ans_hlist);
				res_ndestroy(&res_state);
				return (NULL);
			}
			adt_hep = adt_hlist->ah_list;

			if (smb_ads_decode_host_addi_sec(addit_cnt, &ptr, eom,
			    msg.buf, adt_hep) != 0) {
				smb_ads_hlist_free(ans_hlist);
				smb_ads_hlist_free(adt_hlist);
				res_ndestroy(&res_state);
				return (NULL);
			}

			res_hlist = smb_ads_hlist_alloc(addit_cnt);
			if (res_hlist == NULL) {
				smb_ads_hlist_free(ans_hlist);
				smb_ads_hlist_free(adt_hlist);
				res_ndestroy(&res_state);
				return (NULL);
			}
			ads_host = res_hlist->ah_list;

			/* pick a host that is up */
			for (i = 0; i < addit_cnt; i++) {
				if ((sought) &&
				    (strncasecmp(sought,
				    adt_hep[i].name,
				    strlen(sought)) != 0))
					continue;
				/*
				 * find the host in the list of hosts from
				 * the answer section to get the port number.
				 */
				for (j = 0; j < ans_cnt; j++)
					if (strcmp(adt_hep[i].name,
					    ans_hep[j].name) == 0)
						break;

				if (j == ans_cnt) {
					smb_ads_hlist_free(ans_hlist);
					smb_ads_hlist_free(adt_hlist);
					smb_ads_hlist_free(res_hlist);
					res_ndestroy(&res_state);
					return (NULL);
				}

				smb_ads_init_host_info(ads_host,
				    adt_hep[i].name, adt_hep[i].ip_addr,
				    ans_hep[j].priority, ans_hep[j].weight,
				    ans_hep[j].port);

				*port = ads_host->port;
				addr.s_addr = ads_host->ip_addr;
				smb_tracef("smb_ads: Found ADS server: "
				    "%s (%s) [%d][%d]", ads_host->name,
				    inet_ntoa(addr), ads_host->priority,
				    ads_host->weight);
				hlist_cnt++;
				ads_host++;
			}
			smb_ads_hlist_free(ans_hlist);
			smb_ads_hlist_free(adt_hlist);
			res_ndestroy(&res_state);

			if (hlist_cnt != 0) {
				res_hlist->ah_cnt = hlist_cnt;
				res_host = smb_ads_select_dc(res_hlist);
				smb_ads_set_host_info(res_host);
			}
			smb_ads_hlist_free(res_hlist);
			return (res_host);
		} else {
			res_hlist = smb_ads_hlist_alloc(ans_cnt);
			if (res_hlist == NULL) {
				smb_ads_hlist_free(ans_hlist);
				res_ndestroy(&res_state);
				return (NULL);
			}
			ads_host = res_hlist->ah_list;

			/*
			 * Shouldn't get here unless entries exist in DNS but
			 * DNS server did not put them in additional section of
			 * DNS reply packet.
			 */
			for (i = 0; i < ans_cnt; i++) {
				if ((sought) &&
				    (strncasecmp(sought, ans_hep[i].name,
				    strlen(sought)) != 0))
					continue;

				h = getipnodebyname(ans_hep[i].name,
				    AF_INET, 0, &error);

				if (h == NULL || h->h_addr == NULL)
					continue;

				(void) memcpy(&ans_hep[i].ip_addr,
				    h->h_addr, sizeof (addr.s_addr));

				freehostent(h);

				smb_ads_init_host_info(ads_host,
				    ans_hep[i].name, ans_hep[i].ip_addr,
				    ans_hep[i].priority, ans_hep[i].weight,
				    ans_hep[i].port);

				*port = ads_host->port;
				addr.s_addr = ads_host->ip_addr;
				smb_tracef("smb_ads: Found ADS server: "
				    "%s (%s) [%d][%d]", ads_host->name,
				    inet_ntoa(addr), ads_host->priority,
				    ads_host->weight);
				hlist_cnt++;
				ads_host++;
			}
			smb_ads_hlist_free(ans_hlist);
			res_ndestroy(&res_state);

			if (hlist_cnt != 0) {
				res_hlist->ah_cnt = hlist_cnt;
				res_host = smb_ads_select_dc(res_hlist);
				smb_ads_set_host_info(res_host);
			}
			smb_ads_hlist_free(res_hlist);
			return (res_host);
		}
	}
	res_ndestroy(&res_state);
	syslog(LOG_ERR, "smb_ads: ADS server is either not found or offline.");

	if (istrunc && sought && *sought != 0)
		syslog(LOG_WARNING, "smb_ads: Truncated TCP reply message is "
		    "detected for DNS query (SRV) of ADS hosts.\n");

	return (NULL);
}

/*
 * smb_ads_convert_domain
 * Converts a domain string into its distinguished name i.e. a unique
 * name for an entry in the Directory Service.
 * Memory is allocated
 * for the new string.
 * i.e. procom.com -> dc=procom,dc=com
 * Parameters:
 *   s: fully qualified DNS domain string
 * Returns:
 *   NULL if error
 *   DNS domain in LDAP DN string format
 */
static char *
smb_ads_convert_domain(char *s)
{
	char *t, *s2, *t2;
	int len, cnt;

	if (s == NULL || *s == 0)
		return (NULL);

	cnt = 0;
	t = s;
	while (*t) {
		if (*t++ == '.') {
			cnt++;
		}
	}

	len = 3 + strlen(s) + cnt*3 + 1;

	s2 = (char *)malloc(len);
	if (s2 == NULL)
		return (NULL);

	bzero(s2, len);

	t = s2;
	(void) strncpy(t, "dc=", 3);
	t += 3;
	t2 = s;
	while (*s) {
		if (*s == '.') {
			if (t + 3 >= s2 + len - 1) {
				syslog(LOG_ERR, "[smb_ads_convert_domain] "
				    "buffer overrun for string "
				    "conversion of %s: tot buf "
				    "sz alloc: %d, last "
				    "written buf offset: %d\n",
				    t2, len, t+3-s2);
				free(s2);
				return (NULL);
			}
			(void) strncpy(t, ",dc=", 4);
			t += 4;
			s++;
		} else {
			if (t >= s2 + len - 1) {
				syslog(LOG_ERR, "[smb_ads_convert_domain] "
				    "buffer overrun for string "
				    "conversion of %s: tot buf "
				    "sz alloc: %d, last "
				    "written buf offset: %d\n",
				    t2, len, t-s2);
				free(s2);
				return (NULL);
			}
			*t++ = *s++;
		}
	}
	*t = '\0';
	return (s2);
}

/*
 * smb_ads_free_host_info
 * Free the memory use by the global ads_host_info and set it to NULL.
 */
static void
smb_ads_free_host_info(void)
{
	(void) mutex_lock(&ads_host_mtx);
	if (ads_host_info) {
		free(ads_host_info);
		ads_host_info = NULL;
	}
	(void) mutex_unlock(&ads_host_mtx);
}

/*
 * smb_ads_open
 * Open a LDAP connection to an ADS server if the system is in domain mode.
 * Acquire both Kerberos TGT and LDAP service tickets for the host principal.
 *
 * This function should only be called after the system is successfully joined
 * to a domain.
 */
smb_ads_handle_t *
smb_ads_open(void)
{
	char domain[MAXHOSTNAMELEN];

	if (smb_config_get_secmode() != SMB_SECMODE_DOMAIN)
		return (NULL);

	if (smb_getfqdomainname(domain, MAXHOSTNAMELEN) != 0)
		return (NULL);

	return (smb_ads_open_main(domain, NULL, NULL));
}

/*
 * smb_ads_open_main
 * Open a LDAP connection to an ADS server.
 * If ADS is enabled and the administrative username, password, and
 * ADS domain are defined then query DNS to find an ADS server if this is the
 * very first call to this routine.  After an ADS server is found then this
 * server will be used everytime this routine is called until the system is
 * rebooted or the ADS server becomes unavailable then an ADS server will
 * be queried again.  After the connection is made then an ADS handle
 * is created to be returned.
 *
 * After the LDAP connection, the LDAP version will be set to 3 using
 * ldap_set_option().
 *
 * The smb_ads_bind() routine is also called before the ADS handle is returned.
 * Parameters:
 *   domain - fully-qualified domain name
 *   user   - the user account for whom the Kerberos TGT ticket and ADS
 *            service tickets are acquired.
 *   password - password of the specified user
 *
 * Returns:
 *   NULL              : can't connect to ADS server or other errors
 *   smb_ads_handle_t* : handle to ADS server
 */
static smb_ads_handle_t *
smb_ads_open_main(char *domain, char *user, char *password)
{
	smb_ads_handle_t *ah;
	LDAP *ld;
	int version = 3, ads_port;
	smb_ads_host_info_t *ads_host = NULL;
	struct in_addr addr;

	ads_host = smb_ads_get_host_info();
	if (!ads_host) {
		ads_host = smb_ads_find_host(domain, NULL, &ads_port);
		if (ads_host == NULL) {
			syslog(LOG_ERR, "smb_ads: No ADS host found from "
			    "configured nameservers");
			return (NULL);
		}
	}

	ah = (smb_ads_handle_t *)malloc(sizeof (smb_ads_handle_t));
	if (ah == NULL)
		return (NULL);
	(void) memset(ah, 0, sizeof (smb_ads_handle_t));

	addr.s_addr = ads_host->ip_addr;
	if ((ld = ldap_init((char *)inet_ntoa(addr), ads_host->port)) == NULL) {
		syslog(LOG_ERR, "smb_ads: Could not open connection "
		    "to host: %s\n", ads_host->name);
		smb_ads_free_host_info();
		free(ah);
		return (NULL);
	}

	if (ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version)
	    != LDAP_SUCCESS) {
		syslog(LOG_ERR, "smb_ads: Could not set "
		    "LDAP_OPT_PROTOCOL_VERSION %d\n", version);
		smb_ads_free_host_info();
		free(ah);
		(void) ldap_unbind(ld);
		return (NULL);
	}

	(void) ldap_set_option(ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
	ah->ld = ld;
	ah->user = (user) ? strdup(user) : NULL;
	ah->pwd = (password) ? strdup(password) : NULL;
	ah->domain = strdup(domain);

	if (ah->domain == NULL) {
		smb_ads_close(ah);
		return (NULL);
	}

	ah->domain_dn = smb_ads_convert_domain(domain);
	if (ah->domain_dn == NULL) {
		smb_ads_close(ah);
		return (NULL);
	}

	ah->hostname = strdup(ads_host->name);
	if (ah->hostname == NULL) {
		smb_ads_close(ah);
		return (NULL);
	}
	(void) mutex_lock(&ads_site_mtx);
	if (*ads_site != '\0') {
		if ((ah->site = strdup(ads_site)) == NULL) {
			smb_ads_close(ah);
			(void) mutex_unlock(&ads_site_mtx);
			return (NULL);
		}
	} else {
		ah->site = NULL;
	}
	(void) mutex_unlock(&ads_site_mtx);

	if (smb_ads_bind(ah) == -1) {
		smb_ads_close(ah);
		return (NULL);
	}

	return (ah);
}

/*
 * smb_ads_close
 * Close connection to ADS server and free memory allocated for ADS handle.
 * LDAP unbind is called here.
 * Parameters:
 *   ah: handle to ADS server
 * Returns:
 *   void
 */
void
smb_ads_close(smb_ads_handle_t *ah)
{
	int len;

	if (ah == NULL)
		return;
	/* close and free connection resources */
	if (ah->ld)
		(void) ldap_unbind(ah->ld);

	free(ah->user);
	if (ah->pwd) {
		len = strlen(ah->pwd);
		/* zero out the memory that contains user's password */
		if (len > 0)
			bzero(ah->pwd, len);
		free(ah->pwd);
	}
	free(ah->domain);
	free(ah->domain_dn);
	free(ah->hostname);
	free(ah->site);
	free(ah);
}

/*
 * smb_ads_display_stat
 * Display error message for GSS-API routines.
 * Parameters:
 *   maj:  GSS major status
 *   min:  GSS minor status
 * Returns:
 *   None
 */
static void
smb_ads_display_stat(OM_uint32 maj, OM_uint32 min)
{
	gss_buffer_desc msg;
	OM_uint32 msg_ctx = 0;
	OM_uint32 min2;
	(void) gss_display_status(&min2, maj, GSS_C_GSS_CODE, GSS_C_NULL_OID,
	    &msg_ctx, &msg);
	syslog(LOG_ERR, "smb_ads: major status error: %s\n", (char *)msg.value);
	(void) gss_display_status(&min2, min, GSS_C_MECH_CODE, GSS_C_NULL_OID,
	    &msg_ctx, &msg);
	syslog(LOG_ERR, "smb_ads: minor status error: %s\n", (char *)msg.value);
}

/*
 * smb_ads_alloc_attr
 *
 * Since the attrs is a null-terminated array, all elements
 * in the array (except the last one) will point to allocated
 * memory.
 */
static int
smb_ads_alloc_attr(LDAPMod *attrs[], int num)
{
	int i;

	bzero(attrs, num * sizeof (LDAPMod *));
	for (i = 0; i < (num - 1); i++) {
		attrs[i] = (LDAPMod *)malloc(sizeof (LDAPMod));
		if (attrs[i] == NULL) {
			smb_ads_free_attr(attrs);
			return (-1);
		}
	}

	return (0);
}

/*
 * smb_ads_free_attr
 * Free memory allocated when publishing a share.
 * Parameters:
 *   attrs: an array of LDAPMod pointers
 * Returns:
 *   None
 */
static void
smb_ads_free_attr(LDAPMod *attrs[])
{
	int i;
	for (i = 0; attrs[i]; i++) {
		free(attrs[i]);
	}
}

/*
 * smb_ads_get_spnset
 *
 * Derives the core set of SPNs based on the FQHN.
 * The spn_set is a null-terminated array of char pointers.
 *
 * Returns 0 upon success. Otherwise, returns -1.
 */
static int
smb_ads_get_spnset(char *fqhost, char **spn_set)
{
	int i;

	bzero(spn_set, (SMBKRB5_SPN_IDX_MAX + 1) * sizeof (char *));
	for (i = 0; i < SMBKRB5_SPN_IDX_MAX; i++) {
		if ((spn_set[i] = smb_krb5_get_spn(i, fqhost)) == NULL) {
			smb_ads_free_spnset(spn_set);
			return (-1);
		}
	}

	return (0);
}

/*
 * smb_ads_free_spnset
 *
 * Free the memory allocated for the set of SPNs.
 */
static void
smb_ads_free_spnset(char **spn_set)
{
	int i;
	for (i = 0; spn_set[i]; i++)
		free(spn_set[i]);
}

/*
 * smb_ads_acquire_cred
 * Called by smb_ads_bind() to get a handle to administrative user's credential
 * stored locally on the system.  The credential is the TGT.  If the attempt at
 * getting handle fails then a second attempt will be made after getting a
 * new TGT.
 * Please look at smb_ads_bind() for more information.
 *
 * Paramters:
 *   ah         : handle to ADS server
 *   kinit_retry: if 0 then a second attempt will be made to get handle to the
 *                credential if the first attempt fails
 * Returns:
 *   cred_handle: handle to the administrative user's credential (TGT)
 *   oid        : contains Kerberos 5 object identifier
 *   kinit_retry: A 1 indicates that a second attempt has been made to get
 *                handle to the credential and no further attempts can be made
 *   -1         : error
 *    0         : success
 */
static int
smb_ads_acquire_cred(smb_ads_handle_t *ah, gss_cred_id_t *cred_handle,
    gss_OID *oid, int *kinit_retry)
{
	return (krb5_acquire_cred_kinit(ah->user, ah->pwd, cred_handle, oid,
	    kinit_retry, "ads"));
}

/*
 * smb_ads_establish_sec_context
 * Called by smb_ads_bind() to establish a security context to an LDAP service
 * on an ADS server. If the attempt at establishing the security context fails
 * then a second attempt will be made by smb_ads_bind() if a new TGT has not
 * been already obtained in ads_acquire_cred.  The second attempt, if allowed,
 * will obtained a new TGT here and a new handle to the credential will also be
 * obtained in ads_acquire_cred.  LDAP SASL bind is used to send and receive
 * the GSS tokens to and from the ADS server.
 * Please look at ads_bind for more information.
 * Paramters:
 *   ah             : handle to ADS server
 *   cred_handle    : handle to administrative user's credential (TGT)
 *   oid            : Kerberos 5 object identifier
 *   kinit_retry    : if 0 then a second attempt can be made to establish a
 *                    security context with ADS server if first attempt fails
 * Returns:
 *   gss_context    : security context to ADS server
 *   sercred        : encrypted ADS server's supported security layers
 *   do_acquire_cred: if 1 then a second attempt will be made to establish a
 *                    security context with ADS server after getting a new
 *                    handle to the user's credential
 *   kinit_retry    : if 1 then a second attempt will be made to establish a
 *                    a security context and no further attempts can be made
 *   -1             : error
 *    0             : success
 */
static int
smb_ads_establish_sec_context(smb_ads_handle_t *ah, gss_ctx_id_t *gss_context,
    gss_cred_id_t cred_handle, gss_OID oid, struct berval **sercred,
    int *kinit_retry, int *do_acquire_cred)
{
	OM_uint32 maj, min, time_rec;
	char service_name[SMB_ADS_MAXBUFLEN];
	gss_buffer_desc send_tok, service_buf;
	gss_name_t target_name;
	gss_buffer_desc input;
	gss_buffer_desc *inputptr;
	struct berval cred;
	OM_uint32 ret_flags;
	int stat;
	int gss_flags;

	(void) snprintf(service_name, SMB_ADS_MAXBUFLEN, "ldap@%s",
	    ah->hostname);
	service_buf.value = service_name;
	service_buf.length = strlen(service_name)+1;
	if ((maj = gss_import_name(&min, &service_buf,
	    (gss_OID) gss_nt_service_name,
	    &target_name)) != GSS_S_COMPLETE) {
		smb_ads_display_stat(maj, min);
		if (oid != GSS_C_NO_OID)
			(void) gss_release_oid(&min, &oid);
		return (-1);
	}

	*gss_context = GSS_C_NO_CONTEXT;
	*sercred = NULL;
	inputptr = GSS_C_NO_BUFFER;
	gss_flags = GSS_C_MUTUAL_FLAG;
	do {
		if (krb5_establish_sec_ctx_kinit(ah->user, ah->pwd,
		    cred_handle, gss_context, target_name, oid,
		    gss_flags, inputptr, &send_tok,
		    &ret_flags, &time_rec, kinit_retry,
		    do_acquire_cred, &maj, "ads") == -1) {
			if (oid != GSS_C_NO_OID)
				(void) gss_release_oid(&min, &oid);
			(void) gss_release_name(&min, &target_name);
			return (-1);
		}

		cred.bv_val = send_tok.value;
		cred.bv_len = send_tok.length;
		if (*sercred) {
			ber_bvfree(*sercred);
			*sercred = NULL;
		}
		stat = ldap_sasl_bind_s(ah->ld, NULL, "GSSAPI",
		    &cred, NULL, NULL, sercred);
		if (stat != LDAP_SUCCESS &&
		    stat != LDAP_SASL_BIND_IN_PROGRESS) {
			/* LINTED - E_SEC_PRINTF_VAR_FMT */
			syslog(LOG_ERR, ldap_err2string(stat));
			if (oid != GSS_C_NO_OID)
				(void) gss_release_oid(&min, &oid);
			(void) gss_release_name(&min, &target_name);
			(void) gss_release_buffer(&min, &send_tok);
			return (-1);
		}
		input.value = (*sercred)->bv_val;
		input.length = (*sercred)->bv_len;
		inputptr = &input;
		if (send_tok.length > 0)
			(void) gss_release_buffer(&min, &send_tok);
	} while (maj != GSS_S_COMPLETE);

	if (oid != GSS_C_NO_OID)
		(void) gss_release_oid(&min, &oid);
	(void) gss_release_name(&min, &target_name);

	return (0);
}

/*
 * smb_ads_negotiate_sec_layer
 * Call by smb_ads_bind() to negotiate additional security layer for further
 * communication after security context establishment.  No additional security
 * is needed so a "no security layer" is negotiated.  The security layer is
 * described in the SASL RFC 2478 and this step is needed for secure LDAP
 * binding.  LDAP SASL bind is used to send and receive the GSS tokens to and
 * from the ADS server.
 * Please look at smb_ads_bind for more information.
 *
 * Paramters:
 *   ah         : handle to ADS server
 *   gss_context: security context to ADS server
 *   sercred    : encrypted ADS server's supported security layers
 * Returns:
 *   -1         : error
 *    0         : success
 */
static int
smb_ads_negotiate_sec_layer(smb_ads_handle_t *ah, gss_ctx_id_t gss_context,
    struct berval *sercred)
{
	OM_uint32 maj, min;
	gss_buffer_desc unwrap_inbuf, unwrap_outbuf;
	gss_buffer_desc wrap_inbuf, wrap_outbuf;
	int conf_state, sec_layer;
	char auth_id[5];
	struct berval cred;
	int stat;
	gss_qop_t qt;

	/* check for server supported security layer */
	unwrap_inbuf.value = sercred->bv_val;
	unwrap_inbuf.length = sercred->bv_len;
	if ((maj = gss_unwrap(&min, gss_context,
	    &unwrap_inbuf, &unwrap_outbuf,
	    &conf_state, &qt)) != GSS_S_COMPLETE) {
		smb_ads_display_stat(maj, min);
		if (sercred)
			ber_bvfree(sercred);
		return (-1);
	}
	sec_layer = *((char *)unwrap_outbuf.value);
	(void) gss_release_buffer(&min, &unwrap_outbuf);
	if (!(sec_layer & 1)) {
		syslog(LOG_ERR, "smb_ads: ADS server does not support "
		    "no security layer!\n");
		if (sercred) ber_bvfree(sercred);
		return (-1);
	}
	if (sercred) ber_bvfree(sercred);

	/* no security layer needed after successful binding */
	auth_id[0] = 0x01;

	/* byte 2-4: max client recv size in network byte order */
	auth_id[1] = 0x00;
	auth_id[2] = 0x40;
	auth_id[3] = 0x00;
	wrap_inbuf.value = auth_id;
	wrap_inbuf.length = 4;
	conf_state = 0;
	if ((maj = gss_wrap(&min, gss_context, conf_state, 0, &wrap_inbuf,
	    &conf_state, &wrap_outbuf)) != GSS_S_COMPLETE) {
		smb_ads_display_stat(maj, min);
		return (-1);
	}

	cred.bv_val = wrap_outbuf.value;
	cred.bv_len = wrap_outbuf.length;
	sercred = NULL;
	stat = ldap_sasl_bind_s(ah->ld, NULL, "GSSAPI", &cred, NULL, NULL,
	    &sercred);
	if (stat != LDAP_SUCCESS && stat != LDAP_SASL_BIND_IN_PROGRESS) {
		/* LINTED - E_SEC_PRINTF_VAR_FMT */
		syslog(LOG_ERR, ldap_err2string(stat));
		(void) gss_release_buffer(&min, &wrap_outbuf);
		return (-1);
	}

	(void) gss_release_buffer(&min, &wrap_outbuf);
	if (sercred)
		ber_bvfree(sercred);

	return (0);
}

/*
 * smb_ads_bind
 * Use secure binding to bind to ADS server.
 * Use GSS-API with Kerberos 5 as the security mechanism and LDAP SASL with
 * Kerberos 5 as the security mechanisn to authenticate, obtain a security
 * context, and securely bind an administrative user so that other LDAP
 * commands can be used, i.e. add and delete.
 *
 * To obtain the security context, a Kerberos ticket-granting ticket (TGT)
 * for the user is needed to obtain a ticket for the LDAP service.  To get
 * a TGT for the user, the username and password is needed.  Once a TGT is
 * obtained then it will be stored locally and used until it is expired.
 * This routine will automatically obtained a TGT for the first time or when
 * it expired.  LDAP SASL bind is then finally used to send GSS tokens to
 * obtain a security context for the LDAP service on the ADS server.  If
 * there is any problem getting the security context then a new TGT will be
 * obtain to try getting the security context once more.
 *
 * After the security context is obtain and established, the LDAP SASL bind
 * is used to negotiate an additional security layer.  No further security is
 * needed so a "no security layer" is negotiated.  After this the security
 * context can be deleted and further LDAP commands can be sent to the ADS
 * server until a LDAP unbind command is issued to the ADS server.
 * Paramaters:
 *   ah: handle to ADS server
 * Returns:
 *  -1: error
 *   0: success
 */
static int
smb_ads_bind(smb_ads_handle_t *ah)
{
	OM_uint32 min;
	gss_cred_id_t cred_handle;
	gss_ctx_id_t gss_context;
	gss_OID oid;
	struct berval *sercred;
	int kinit_retry, do_acquire_cred;
	int rc = 0;

	kinit_retry = 0;
	do_acquire_cred = 0;

acquire_cred:

	if (smb_ads_acquire_cred(ah, &cred_handle, &oid, &kinit_retry))
		return (-1);

	if (smb_ads_establish_sec_context(ah, &gss_context, cred_handle,
	    oid, &sercred, &kinit_retry, &do_acquire_cred)) {
		(void) gss_release_cred(&min, &cred_handle);
		if (do_acquire_cred) {
			do_acquire_cred = 0;
			goto acquire_cred;
		}
		return (-1);
	}
	rc = smb_ads_negotiate_sec_layer(ah, gss_context, sercred);

	if (cred_handle != GSS_C_NO_CREDENTIAL)
		(void) gss_release_cred(&min, &cred_handle);
	(void) gss_delete_sec_context(&min, &gss_context, NULL);

	return ((rc) ? -1 : 0);
}

/*
 * smb_ads_add_share
 * Call by smb_ads_publish_share to create share object in ADS.
 * This routine specifies the attributes of an ADS LDAP share object. The first
 * attribute and values define the type of ADS object, the share object.  The
 * second attribute and value define the UNC of the share data for the share
 * object. The LDAP synchronous add command is used to add the object into ADS.
 * The container location to add the object needs to specified.
 * Parameters:
 *   ah          : handle to ADS server
 *   adsShareName: name of share object to be created in ADS
 *   shareUNC    : share name on NetForce
 *   adsContainer: location in ADS to create share object
 *
 * Returns:
 *   -1          : error
 *    0          : success
 */
int
smb_ads_add_share(smb_ads_handle_t *ah, const char *adsShareName,
    const char *unc_name, const char *adsContainer)
{
	LDAPMod *attrs[SMB_ADS_SHARE_NUM_ATTR];
	char *tmp1[5], *tmp2[5];
	int j = 0;
	char *share_dn;
	char buf[SMB_ADS_MAXMSGLEN];
	int len, ret;

	len = 5 + strlen(adsShareName) + strlen(adsContainer) +
	    strlen(ah->domain_dn) + 1;

	share_dn = (char *)malloc(len);
	if (share_dn == NULL)
		return (-1);

	(void) snprintf(share_dn, len, "cn=%s,%s,%s", adsShareName,
	    adsContainer, ah->domain_dn);

	if (smb_ads_alloc_attr(attrs, SMB_ADS_SHARE_NUM_ATTR) != 0) {
		free(share_dn);
		return (-1);
	}

	attrs[j]->mod_op = LDAP_MOD_ADD;
	attrs[j]->mod_type = "objectClass";
	tmp1[0] = "top";
	tmp1[1] = "leaf";
	tmp1[2] = "connectionPoint";
	tmp1[3] = "volume";
	tmp1[4] = 0;
	attrs[j]->mod_values = tmp1;

	attrs[++j]->mod_op = LDAP_MOD_ADD;
	attrs[j]->mod_type = "uNCName";
	tmp2[0] = (char *)unc_name;
	tmp2[1] = 0;
	attrs[j]->mod_values = tmp2;

	if ((ret = ldap_add_s(ah->ld, share_dn, attrs)) != LDAP_SUCCESS) {
		(void) snprintf(buf, SMB_ADS_MAXMSGLEN,
		    "smb_ads_add_share: %s:", share_dn);
		/* LINTED - E_SEC_PRINTF_VAR_FMT */
		syslog(LOG_ERR, ldap_err2string(ret));
		smb_ads_free_attr(attrs);
		free(share_dn);
		return (ret);
	}
	free(share_dn);
	smb_ads_free_attr(attrs);

	(void) snprintf(buf, SMB_ADS_MAXMSGLEN,
	    "Share %s has been added to ADS container: %s.\n", adsShareName,
	    adsContainer);
	smb_tracef("smb_ads: %s", buf);

	return (0);
}

/*
 * smb_ads_del_share
 * Call by smb_ads_remove_share to remove share object from ADS.  The container
 * location to remove the object needs to specified.  The LDAP synchronous
 * delete command is used.
 * Parameters:
 *   ah          : handle to ADS server
 *   adsShareName: name of share object in ADS to be removed
 *   adsContainer: location of share object in ADS
 * Returns:
 *   -1          : error
 *    0          : success
 */
static int
smb_ads_del_share(smb_ads_handle_t *ah, const char *adsShareName,
    const char *adsContainer)
{
	char *share_dn, buf[SMB_ADS_MAXMSGLEN];
	int len, ret;

	len = 5 + strlen(adsShareName) + strlen(adsContainer) +
	    strlen(ah->domain_dn) + 1;

	share_dn = (char *)malloc(len);
	if (share_dn == NULL)
		return (-1);

	(void) snprintf(share_dn, len, "cn=%s,%s,%s", adsShareName,
	    adsContainer, ah->domain_dn);
	if ((ret = ldap_delete_s(ah->ld, share_dn)) != LDAP_SUCCESS) {
		/* LINTED - E_SEC_PRINTF_VAR_FMT */
		syslog(LOG_ERR, ldap_err2string(ret));
		free(share_dn);
		return (-1);
	}
	free(share_dn);

	(void) snprintf(buf, SMB_ADS_MAXMSGLEN,
	    "Share %s has been removed from ADS container: %s.\n",
	    adsShareName, adsContainer);
	smb_tracef("smb_ads: %s", buf);

	return (0);
}


/*
 * smb_ads_escape_search_filter_chars
 *
 * This routine will escape the special characters found in a string
 * that will later be passed to the ldap search filter.
 *
 * RFC 1960 - A String Representation of LDAP Search Filters
 * 3.  String Search Filter Definition
 * If a value must contain one of the characters '*' OR '(' OR ')',
 * these characters
 * should be escaped by preceding them with the backslash '\' character.
 *
 * RFC 2252 - LDAP Attribute Syntax Definitions
 * a backslash quoting mechanism is used to escape
 * the following separator symbol character (such as "'", "$" or "#") if
 * it should occur in that string.
 */
static int
smb_ads_escape_search_filter_chars(const char *src, char *dst)
{
	int avail = SMB_ADS_MAXBUFLEN - 1; /* reserve a space for NULL char */

	if (src == NULL || dst == NULL)
		return (-1);

	while (*src) {
		if (!avail) {
			*dst = 0;
			return (-1);
		}

		switch (*src) {
		case '\\':
		case '\'':
		case '$':
		case '#':
		case '*':
		case '(':
		case ')':
			*dst++ = '\\';
			avail--;
			/* fall through */

		default:
			*dst++ = *src++;
			avail--;
		}
	}

	*dst = 0;

	return (0);
}

/*
 * smb_ads_lookup_share
 * The search filter is set to search for a specific share name in the
 * specified ADS container.  The LDSAP synchronous search command is used.
 * Parameters:
 *   ah          : handle to ADS server
 *   adsShareName: name of share object in ADS to be searched
 *   adsContainer: location of share object in ADS
 * Returns:
 *   -1          : error
 *    0          : not found
 *    1          : found
 */
int
smb_ads_lookup_share(smb_ads_handle_t *ah, const char *adsShareName,
    const char *adsContainer, char *unc_name)
{
	char *attrs[4], filter[SMB_ADS_MAXBUFLEN];
	char *share_dn;
	int len, ret;
	LDAPMessage *res;
	char tmpbuf[SMB_ADS_MAXBUFLEN];

	if (adsShareName == NULL || adsContainer == NULL)
		return (-1);

	len = 5 + strlen(adsShareName) + strlen(adsContainer) +
	    strlen(ah->domain_dn) + 1;

	share_dn = (char *)malloc(len);
	if (share_dn == NULL)
		return (-1);

	(void) snprintf(share_dn, len, "cn=%s,%s,%s", adsShareName,
	    adsContainer, ah->domain_dn);

	res = NULL;
	attrs[0] = "cn";
	attrs[1] = "objectClass";
	attrs[2] = "uNCName";
	attrs[3] = NULL;

	if (smb_ads_escape_search_filter_chars(unc_name, tmpbuf) != 0) {
		free(share_dn);
		return (-1);
	}

	(void) snprintf(filter, sizeof (filter),
	    "(&(objectClass=volume)(uNCName=%s))", tmpbuf);

	if ((ret = ldap_search_s(ah->ld, share_dn,
	    LDAP_SCOPE_BASE, filter, attrs, 0, &res)) != LDAP_SUCCESS) {
		if (ret != LDAP_NO_SUCH_OBJECT) {
			syslog(LOG_ERR, "ldap[%s]: %s", share_dn,
			    ldap_err2string(ret));
		}
		(void) ldap_msgfree(res);
		free(share_dn);
		return (0);
	}

	(void) free(share_dn);

	/* no match is found */
	if (ldap_count_entries(ah->ld, res) == 0) {
		(void) ldap_msgfree(res);
		return (0);
	}

	/* free the search results */
	(void) ldap_msgfree(res);

	return (1);
}

/*
 * smb_ads_convert_directory
 * Convert relative share directory to UNC to be appended to hostname.
 * i.e. cvol/a/b -> cvol\a\b
 */
char *
smb_ads_convert_directory(char *rel_dir)
{
	char *t, *s2;
	int len;

	if (rel_dir == NULL)
		return (NULL);

	len = strlen(rel_dir) + 1;
	s2 = (char *)malloc(len);
	if (s2 == NULL)
		return (NULL);

	t = s2;
	while (*rel_dir) {
		if (*rel_dir == '/') {
			*t++ = '\\';
			rel_dir++;
		} else {
			*t++ = *rel_dir++;
		}
	}
	*t = '\0';
	return (s2);
}

/*
 * smb_ads_publish_share
 * Publish share into ADS.  If a share name already exist in ADS in the same
 * container then the existing share object is removed before adding the new
 * share object.
 * Parameters:
 *   ah          : handle return from smb_ads_open
 *   adsShareName: name of share to be added to ADS directory
 *   shareUNC    : name of share on client, can be NULL to use the same name
 *                 as adsShareName
 *   adsContainer: location for share to be added in ADS directory, ie
 *                   ou=share_folder
 *   uncType     : use UNC_HOSTNAME to use hostname for UNC, use UNC_HOSTADDR
 *                   to use host ip addr for UNC.
 * Returns:
 *   -1          : error
 *    0          : success
 */
int
smb_ads_publish_share(smb_ads_handle_t *ah, const char *adsShareName,
    const char *shareUNC, const char *adsContainer, const char *hostname)
{
	int ret;
	char unc_name[SMB_ADS_MAXBUFLEN];

	if (adsShareName == NULL || adsContainer == NULL)
		return (-1);

	if (shareUNC == 0 || *shareUNC == 0)
		shareUNC = adsShareName;

	if (smb_ads_build_unc_name(unc_name, sizeof (unc_name),
	    hostname, shareUNC) < 0) {
		smb_tracef("smb_ads: Cannot publish share '%s' "
		    "[missing UNC name]", shareUNC);
		return (-1);
	}

	ret = smb_ads_lookup_share(ah, adsShareName, adsContainer, unc_name);

	switch (ret) {
	case 1:
		(void) smb_ads_del_share(ah, adsShareName, adsContainer);
		ret = smb_ads_add_share(ah, adsShareName, unc_name,
		    adsContainer);
		break;

	case 0:
		ret = smb_ads_add_share(ah, adsShareName, unc_name,
		    adsContainer);
		if (ret == LDAP_ALREADY_EXISTS) {
			smb_tracef("smb_ads: Cannot publish share '%s' "
			    "[name is already in use]", adsShareName);
			ret = -1;
		}
		break;

	case -1:
	default:
		/* return with error code */
		ret = -1;
	}

	return (ret);
}

/*
 * smb_ads_remove_share
 * Remove share from ADS.  A search is done first before explicitly removing
 * the share.
 * Parameters:
 *   ah          : handle return from smb_ads_open
 *   adsShareName: name of share to be removed from ADS directory
 *   adsContainer: location for share to be removed from ADS directory, ie
 *                   ou=share_folder
 * Returns:
 *   -1          : error
 *    0          : success
 */
int
smb_ads_remove_share(smb_ads_handle_t *ah, const char *adsShareName,
    const char *shareUNC, const char *adsContainer, const char *hostname)
{
	int ret;
	char unc_name[SMB_ADS_MAXBUFLEN];

	if (adsShareName == NULL || adsContainer == NULL)
		return (-1);
	if (shareUNC == 0 || *shareUNC == 0)
		shareUNC = adsShareName;

	if (smb_ads_build_unc_name(unc_name, sizeof (unc_name),
	    hostname, shareUNC) < 0) {
		smb_tracef("smb_ads: Unable to remove share '%s' from "
		    "ADS [missing UNC name]", shareUNC);
		return (-1);
	}

	ret = smb_ads_lookup_share(ah, adsShareName, adsContainer, unc_name);
	if (ret == 0)
		return (0);
	if (ret == -1)
		return (-1);

	return (smb_ads_del_share(ah, adsShareName, adsContainer));
}

/*
 * smb_ads_get_computer_dn
 *
 * Build the distinguish name for this system.
 */
static void
smb_ads_get_computer_dn(smb_ads_handle_t *ah, char *buf, size_t buflen)
{
	char hostname[MAXHOSTNAMELEN];

	(void) smb_gethostname(hostname, MAXHOSTNAMELEN, 0);
	(void) snprintf(buf, buflen, "cn=%s,cn=%s,%s",
	    hostname, SMB_ADS_COMPUTERS_CN, ah->domain_dn);
}

/*
 * smb_ads_add_computer
 *
 * Returns 0 upon success. Otherwise, returns -1.
 */
static int
smb_ads_add_computer(smb_ads_handle_t *ah, int dclevel, char *dn)
{
	return (smb_ads_computer_op(ah, LDAP_MOD_ADD, dclevel, dn));
}

/*
 * smb_ads_modify_computer
 *
 * Returns 0 upon success. Otherwise, returns -1.
 */
static int
smb_ads_modify_computer(smb_ads_handle_t *ah, int dclevel, char *dn)
{
	return (smb_ads_computer_op(ah, LDAP_MOD_REPLACE, dclevel, dn));
}

/*
 * smb_ads_get_dc_level
 *
 * Returns the functional level of the DC upon success.
 * Otherwise, -1 is returned.
 */
static int
smb_ads_get_dc_level(smb_ads_handle_t *ah)
{
	LDAPMessage *res, *entry;
	char *attr[2];
	char **vals;
	int rc = -1;

	res = NULL;
	attr[0] = SMB_ADS_ATTR_DCLEVEL;
	attr[1] = NULL;
	if (ldap_search_s(ah->ld, "", LDAP_SCOPE_BASE, NULL, attr,
	    0, &res) != LDAP_SUCCESS) {
		(void) ldap_msgfree(res);
		return (-1);
	}

	/* no match for the specified attribute is found */
	if (ldap_count_entries(ah->ld, res) == 0) {
		(void) ldap_msgfree(res);
		return (-1);
	}

	entry = ldap_first_entry(ah->ld, res);
	if (entry) {
		if ((vals = ldap_get_values(ah->ld, entry,
		    SMB_ADS_ATTR_DCLEVEL)) == NULL) {
			/*
			 * Observed the values aren't populated
			 * by the Windows 2000 server.
			 */
			(void) ldap_msgfree(res);
			return (SMB_ADS_DCLEVEL_W2K);
		}

		if (vals[0] != NULL)
			rc = atoi(vals[0]);

		ldap_value_free(vals);
	}

	(void) ldap_msgfree(res);
	return (rc);
}

static int
smb_ads_computer_op(smb_ads_handle_t *ah, int op, int dclevel, char *dn)
{
	LDAPMod *attrs[SMB_ADS_COMPUTER_NUM_ATTR];
	char *oc_vals[6], *sam_val[2], *usr_val[2];
	char *spn_set[SMBKRB5_SPN_IDX_MAX + 1], *ctl_val[2], *fqh_val[2];
	char *encrypt_val[2];
	int j = -1;
	int ret, usrctl_flags = 0;
	char sam_acct[MAXHOSTNAMELEN + 1];
	char fqhost[MAXHOSTNAMELEN];
	char *user_principal;
	char usrctl_buf[16];
	char encrypt_buf[16];
	int max;

	if (smb_gethostname(fqhost, MAXHOSTNAMELEN, 0) != 0)
		return (-1);

	(void) strlcpy(sam_acct, fqhost, MAXHOSTNAMELEN + 1);
	(void) strlcat(sam_acct, "$", MAXHOSTNAMELEN + 1);
	(void) snprintf(fqhost, MAXHOSTNAMELEN, "%s.%s", fqhost,
	    ah->domain);

	if (smb_ads_get_spnset(fqhost, spn_set) != 0)
		return (-1);

	/*
	 * Windows 2008 DC expects the UPN attribute to be host/fqhn while
	 * both Windows 2000 & 2003 expect it to be host/fqhn@realm.
	 */
	if (dclevel == SMB_ADS_DCLEVEL_W2K8)
		user_principal = smb_krb5_get_spn(SMBKRB5_SPN_IDX_HOST, fqhost);
	else
		user_principal = smb_krb5_get_upn(spn_set[SMBKRB5_SPN_IDX_HOST],
		    ah->domain);

	if (user_principal == NULL) {
		smb_ads_free_spnset(spn_set);
		return (-1);
	}

	max = (SMB_ADS_COMPUTER_NUM_ATTR - ((op != LDAP_MOD_ADD) ? 1 : 0))
	    - (dclevel == SMB_ADS_DCLEVEL_W2K8 ?  0 : 1);

	if (smb_ads_alloc_attr(attrs, max) != 0) {
		free(user_principal);
		smb_ads_free_spnset(spn_set);
		return (-1);
	}

	/* objectClass attribute is not modifiable. */
	if (op == LDAP_MOD_ADD) {
		attrs[++j]->mod_op = op;
		attrs[j]->mod_type = "objectClass";
		oc_vals[0] = "top";
		oc_vals[1] = "person";
		oc_vals[2] = "organizationalPerson";
		oc_vals[3] = "user";
		oc_vals[4] = "computer";
		oc_vals[5] = 0;
		attrs[j]->mod_values = oc_vals;
	}

	attrs[++j]->mod_op = op;
	attrs[j]->mod_type = SMB_ADS_ATTR_SAMACCT;
	sam_val[0] = sam_acct;
	sam_val[1] = 0;
	attrs[j]->mod_values = sam_val;

	attrs[++j]->mod_op = op;
	attrs[j]->mod_type = SMB_ADS_ATTR_UPN;
	usr_val[0] = user_principal;
	usr_val[1] = 0;
	attrs[j]->mod_values = usr_val;

	attrs[++j]->mod_op = op;
	attrs[j]->mod_type = SMB_ADS_ATTR_SPN;
	attrs[j]->mod_values = spn_set;

	attrs[++j]->mod_op = op;
	attrs[j]->mod_type = SMB_ADS_ATTR_CTL;
	usrctl_flags |= (SMB_ADS_USER_ACCT_CTL_WKSTATION_TRUST_ACCT |
	    SMB_ADS_USER_ACCT_CTL_PASSWD_NOTREQD |
	    SMB_ADS_USER_ACCT_CTL_ACCOUNTDISABLE);
	(void) snprintf(usrctl_buf, sizeof (usrctl_buf), "%d", usrctl_flags);
	ctl_val[0] = usrctl_buf;
	ctl_val[1] = 0;
	attrs[j]->mod_values = ctl_val;

	attrs[++j]->mod_op = op;
	attrs[j]->mod_type = SMB_ADS_ATTR_DNSHOST;
	fqh_val[0] = fqhost;
	fqh_val[1] = 0;
	attrs[j]->mod_values = fqh_val;

	/* enctypes support starting in Windows Server 2008 */
	if (dclevel > SMB_ADS_DCLEVEL_W2K3) {
		attrs[++j]->mod_op = op;
		attrs[j]->mod_type = SMB_ADS_ATTR_ENCTYPES;
		(void) snprintf(encrypt_buf, sizeof (encrypt_buf), "%d",
		    SMB_ADS_ENC_AES256 + SMB_ADS_ENC_AES128 + SMB_ADS_ENC_RC4 +
		    SMB_ADS_ENC_DES_MD5 + SMB_ADS_ENC_DES_CRC);
		encrypt_val[0] = encrypt_buf;
		encrypt_val[1] = 0;
		attrs[j]->mod_values = encrypt_val;
	}

	switch (op) {
	case LDAP_MOD_ADD:
		if ((ret = ldap_add_s(ah->ld, dn, attrs)) != LDAP_SUCCESS) {
			syslog(LOG_ERR, "smb_ads_add_computer: %s",
			    ldap_err2string(ret));
			ret = -1;
		}
		break;

	case LDAP_MOD_REPLACE:
		if ((ret = ldap_modify_s(ah->ld, dn, attrs)) != LDAP_SUCCESS) {
			syslog(LOG_ERR, "smb_ads_modify_computer: %s",
			    ldap_err2string(ret));
			ret = -1;
		}
		break;

	default:
		ret = -1;

	}

	smb_ads_free_attr(attrs);
	free(user_principal);
	smb_ads_free_spnset(spn_set);

	return (ret);
}

/*
 * Delete an ADS computer account.
 */
static void
smb_ads_del_computer(smb_ads_handle_t *ah, char *dn)
{
	int rc;

	if ((rc = ldap_delete_s(ah->ld, dn)) != LDAP_SUCCESS)
		smb_tracef("smb_ads_del_computer: %s", ldap_err2string(rc));
}

/*
 * smb_ads_lookup_computer_n_attr
 *
 * Lookup the value of the specified attribute on the computer
 * object. If the specified attribute can be found, its value is returned
 * via 'val' parameter.
 *
 * 'attr' parameter can be set to NULL if you only attempt to
 * see whether the computer object exists on AD or not.
 *
 * Return:
 *  1 if both the computer and the specified attribute is found.
 *  0 if either the computer or the specified attribute is not found.
 * -1 on error.
 */
static int
smb_ads_lookup_computer_n_attr(smb_ads_handle_t *ah, char *attr, char **val,
    int scope, char *dn)
{
	char *attrs[2], filter[SMB_ADS_MAXBUFLEN];
	LDAPMessage *res, *entry;
	char **vals;
	char tmpbuf[SMB_ADS_MAXBUFLEN];
	char my_hostname[MAXHOSTNAMELEN];

	if (smb_gethostname(my_hostname, MAXHOSTNAMELEN, 0) != 0)
		return (-1);

	res = NULL;
	attrs[0] = attr;
	attrs[1] = NULL;

	if (smb_ads_escape_search_filter_chars(my_hostname, tmpbuf) != 0)
		return (-1);

	(void) snprintf(filter, sizeof (filter),
	    "(&(objectClass=computer)(cn=%s))", tmpbuf);

	if (ldap_search_s(ah->ld, dn, scope, filter, attrs, 0,
	    &res) != LDAP_SUCCESS) {
		(void) ldap_msgfree(res);
		return (0);
	}

	if (attr) {
		/* no match for the specified attribute is found */
		if (ldap_count_entries(ah->ld, res) == 0) {
			if (val)
				*val = NULL;

			(void) ldap_msgfree(res);
			return (0);
		}

		entry = ldap_first_entry(ah->ld, res);
		if (entry) {
			vals = ldap_get_values(ah->ld, entry, attr);
			if (!vals && val) {
				*val = NULL;
				(void) ldap_msgfree(res);
				return (0);
			}

			if (vals[0] != NULL && val)
				*val = strdup(vals[0]);

			ldap_value_free(vals);
		}
	}

	/* free the search results */
	(void) ldap_msgfree(res);
	return (1);
}

/*
 * smb_ads_find_computer
 *
 * Starts by searching for the system's AD computer object in the default
 * container (i.e. cn=Computers).  If not found, searches the entire directory.
 *
 * If found, B_TRUE is returned and 'dn' will be set to the
 * distinguishedName of the system's AD computer object.  Otherwise, returns
 * B_FALSE.
 */
static boolean_t
smb_ads_find_computer(smb_ads_handle_t *ah, char *dn)
{
	boolean_t found;
	char *val = NULL;

	smb_ads_get_computer_dn(ah, dn, SMB_ADS_DN_MAX);
	found = (smb_ads_lookup_computer_n_attr(ah, NULL, NULL, LDAP_SCOPE_BASE,
	    dn) == 1);

	if (!found) {
		(void) strlcpy(dn, ah->domain_dn, SMB_ADS_DN_MAX);
		found = (smb_ads_lookup_computer_n_attr(ah, SMB_ADS_ATTR_DN,
		    &val, LDAP_SCOPE_SUBTREE, dn) == 1);

		if (found && val)
			(void) strlcpy(dn, val, SMB_ADS_DN_MAX);
		else
			found = B_FALSE;
	}

	return (found);
}

/*
 * smb_ads_update_computer_cntrl_attr
 *
 * Modify the user account control attribute of an existing computer
 * object on AD.
 *
 * Returns 0 on success. Otherwise, returns -1.
 */
static int
smb_ads_update_computer_cntrl_attr(smb_ads_handle_t *ah, int des_only, char *dn)
{
	LDAPMod *attrs[2];
	char *ctl_val[2];
	int ret, usrctl_flags = 0;
	char usrctl_buf[16];

	if (smb_ads_alloc_attr(attrs, sizeof (attrs) / sizeof (LDAPMod *)) != 0)
		return (-1);

	attrs[0]->mod_op = LDAP_MOD_REPLACE;
	attrs[0]->mod_type = SMB_ADS_ATTR_CTL;

	usrctl_flags |= (SMB_ADS_USER_ACCT_CTL_WKSTATION_TRUST_ACCT |
	    SMB_ADS_USER_ACCT_CTL_TRUSTED_FOR_DELEGATION |
	    SMB_ADS_USER_ACCT_CTL_DONT_EXPIRE_PASSWD);

	if (des_only)
		usrctl_flags |= SMB_ADS_USER_ACCT_CTL_USE_DES_KEY_ONLY;

	(void) snprintf(usrctl_buf, sizeof (usrctl_buf), "%d", usrctl_flags);
	ctl_val[0] = usrctl_buf;
	ctl_val[1] = 0;
	attrs[0]->mod_values = ctl_val;

	if ((ret = ldap_modify_s(ah->ld, dn, attrs)) != LDAP_SUCCESS) {
		syslog(LOG_ERR, "smb_ads_modify_computer: %s",
		    ldap_err2string(ret));
		ret = -1;
	}

	smb_ads_free_attr(attrs);
	return (ret);
}

/*
 * smb_ads_update_attrs
 *
 * Updates the servicePrincipalName and dNSHostName attributes of the
 * system's AD computer object.
 */
int
smb_ads_update_attrs(void)
{
	smb_ads_handle_t *ah;
	LDAPMod *attrs[3];
	char *fqh_val[2];
	int i = 0;
	int ret;
	char fqhost[MAXHOSTNAMELEN];
	char dn[SMB_ADS_DN_MAX];
	char *spn_set[SMBKRB5_SPN_IDX_MAX + 1];

	if ((ah = smb_ads_open()) == NULL)
		return (-1);

	if (!smb_ads_find_computer(ah, dn)) {
		smb_ads_close(ah);
		return (-1);
	}

	if (smb_getfqhostname(fqhost, MAXHOSTNAMELEN) != 0) {
		smb_ads_close(ah);
		return (-1);
	}

	if (smb_ads_get_spnset(fqhost, spn_set) != 0) {
		smb_ads_close(ah);
		return (-1);
	}

	if (smb_ads_alloc_attr(attrs, sizeof (attrs) / sizeof (LDAPMod *))
	    != 0) {
		smb_ads_free_spnset(spn_set);
		smb_ads_close(ah);
		return (-1);
	}

	attrs[i]->mod_op = LDAP_MOD_REPLACE;
	attrs[i]->mod_type = SMB_ADS_ATTR_SPN;
	attrs[i]->mod_values = spn_set;

	attrs[++i]->mod_op = LDAP_MOD_REPLACE;
	attrs[i]->mod_type = SMB_ADS_ATTR_DNSHOST;
	fqh_val[0] = fqhost;
	fqh_val[1] = 0;
	attrs[i]->mod_values = fqh_val;

	if ((ret = ldap_modify_s(ah->ld, dn, attrs)) != LDAP_SUCCESS) {
		syslog(LOG_ERR, "smb_ads_update_attrs: %s",
		    ldap_err2string(ret));
		ret = -1;
	}

	smb_ads_free_attr(attrs);
	smb_ads_free_spnset(spn_set);
	smb_ads_close(ah);

	return (ret);

}

/*
 * smb_ads_lookup_computer_attr_kvno
 *
 * Lookup the value of the Kerberos version number attribute of the computer
 * account.
 */
static krb5_kvno
smb_ads_lookup_computer_attr_kvno(smb_ads_handle_t *ah, char *dn)
{
	char *val = NULL;
	int kvno = 1;

	if (smb_ads_lookup_computer_n_attr(ah, SMB_ADS_ATTR_KVNO, &val,
	    LDAP_SCOPE_BASE, dn) == 1) {
		if (val) {
			kvno = atoi(val);
			free(val);
		}
	}

	return (kvno);
}

/*
 * smb_ads_gen_machine_passwd
 *
 * Returned a null-terminated machine password generated randomly
 * from [0-9a-zA-Z] character set. In order to pass the password
 * quality check (three character classes), an uppercase letter is
 * used as the first character of the machine password.
 */
static int
smb_ads_gen_machine_passwd(char *machine_passwd, int bufsz)
{
	char *data = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJK"
	    "LMNOPQRSTUVWXYZ";
	int datalen = strlen(data);
	int i, data_idx;

	if (!machine_passwd || bufsz == 0)
		return (-1);

	/*
	 * The decimal value of upper case 'A' is 65. Randomly pick
	 * an upper-case letter from the ascii table.
	 */
	machine_passwd[0] = (random() % 26) + 65;
	for (i = 1; i < bufsz - 1; i++) {
		data_idx = random() % datalen;
		machine_passwd[i] = data[data_idx];
	}

	machine_passwd[bufsz - 1] = 0;
	return (0);
}

/*
 * smb_ads_domain_change_cleanup
 *
 * If we're attempting to join the system to a new domain, the keys for
 * the host principal regarding the old domain should be removed from
 * Kerberos keytab. Also, the ads_host_info cache should be cleared.
 *
 * newdom is fully-qualified domain name.  It can be set to empty string
 * if user attempts to switch to workgroup mode.
 */
int
smb_ads_domain_change_cleanup(char *newdom)
{
	char origdom[MAXHOSTNAMELEN];
	krb5_context ctx = NULL;
	krb5_principal krb5princs[SMBKRB5_SPN_IDX_MAX];
	int rc;

	if (smb_getfqdomainname(origdom, MAXHOSTNAMELEN)) {
		if (smb_getdomainname(origdom, MAXHOSTNAMELEN) == 0)
			if (strncasecmp(origdom, newdom, strlen(origdom)))
				smb_ads_free_host_info();

		return (0);
	}

	if (strcasecmp(origdom, newdom) == 0)
		return (0);

	smb_ads_free_host_info();

	if (smb_krb5_ctx_init(&ctx) != 0)
		return (-1);

	if (smb_krb5_get_principals(origdom, ctx, krb5princs) != 0) {
		smb_krb5_ctx_fini(ctx);
		return (-1);

	}

	rc = smb_krb5_remove_keytab_entries(ctx, krb5princs,
	    SMBNS_KRB5_KEYTAB);

	smb_krb5_free_principals(ctx, krb5princs, SMBKRB5_SPN_IDX_MAX);
	smb_krb5_ctx_fini(ctx);

	return (rc);
}



/*
 * smb_ads_join
 *
 * Besides the NT-4 style domain join (using MS-RPC), CIFS server also
 * provides the domain join using Kerberos Authentication, Keberos
 * Change & Set password, and LDAP protocols. Basically, AD join
 * operation would require the following tickets to be acquired for the
 * the user account that is provided for the domain join.
 *
 * 1) a Keberos TGT ticket,
 * 2) a ldap service ticket, and
 * 3) kadmin/changpw service ticket
 *
 * The ADS client first sends a ldap search request to find out whether
 * or not the workstation trust account already exists in the Active Directory.
 * The existing computer object for this workstation will be removed and
 * a new one will be added. The machine account password is randomly
 * generated and set for the newly created computer object using KPASSWD
 * protocol (See RFC 3244). Once the password is set, our ADS client
 * finalizes the machine account by modifying the user acount control
 * attribute of the computer object. Kerberos keys derived from the machine
 * account password will be stored locally in /etc/krb5/krb5.keytab file.
 * That would be needed while acquiring Kerberos TGT ticket for the host
 * principal after the domain join operation.
 */
smb_adjoin_status_t
smb_ads_join(char *domain, char *user, char *usr_passwd, char *machine_passwd,
    int len)
{
	smb_ads_handle_t *ah = NULL;
	krb5_context ctx = NULL;
	krb5_principal krb5princs[SMBKRB5_SPN_IDX_MAX];
	krb5_kvno kvno;
	boolean_t des_only, delete = B_TRUE;
	smb_adjoin_status_t rc = SMB_ADJOIN_SUCCESS;
	boolean_t new_acct;
	int dclevel, num;
	char dn[SMB_ADS_DN_MAX];

	/*
	 * Call library functions that can be used to get
	 * the list of encryption algorithms available on the system.
	 * (similar to what 'encrypt -l' CLI does). For now,
	 * unless someone has modified the configuration of the
	 * cryptographic framework (very unlikely), the following is the
	 * list of algorithms available on any system running Nevada
	 * by default.
	 */
	krb5_enctype w2k8enctypes[] = {ENCTYPE_AES256_CTS_HMAC_SHA1_96,
	    ENCTYPE_AES128_CTS_HMAC_SHA1_96, ENCTYPE_ARCFOUR_HMAC,
	    ENCTYPE_DES_CBC_CRC, ENCTYPE_DES_CBC_MD5,
	};

	krb5_enctype pre_w2k8enctypes[] = {ENCTYPE_ARCFOUR_HMAC,
	    ENCTYPE_DES_CBC_CRC, ENCTYPE_DES_CBC_MD5,
	};

	krb5_enctype *encptr;

	if ((ah = smb_ads_open_main(domain, user, usr_passwd)) == NULL) {
		smb_ccache_remove(SMB_CCACHE_PATH);
		return (SMB_ADJOIN_ERR_GET_HANDLE);
	}

	if (smb_ads_gen_machine_passwd(machine_passwd, len) != 0) {
		smb_ads_close(ah);
		smb_ccache_remove(SMB_CCACHE_PATH);
		return (SMB_ADJOIN_ERR_GEN_PASSWD);
	}

	if ((dclevel = smb_ads_get_dc_level(ah)) == -1) {
		smb_ads_close(ah);
		smb_ccache_remove(SMB_CCACHE_PATH);
		return (SMB_ADJOIN_ERR_GET_DCLEVEL);
	}

	if (smb_ads_find_computer(ah, dn)) {
		new_acct = B_FALSE;
		if (smb_ads_modify_computer(ah, dclevel, dn) != 0) {
			smb_ads_close(ah);
			smb_ccache_remove(SMB_CCACHE_PATH);
			return (SMB_ADJOIN_ERR_MOD_TRUST_ACCT);
		}
	} else {
		new_acct = B_TRUE;
		smb_ads_get_computer_dn(ah, dn, SMB_ADS_DN_MAX);
		if (smb_ads_add_computer(ah, dclevel, dn) != 0) {
			smb_ads_close(ah);
			smb_ccache_remove(SMB_CCACHE_PATH);
			return (SMB_ADJOIN_ERR_ADD_TRUST_ACCT);
		}
	}

	des_only = B_FALSE;

	if (smb_krb5_ctx_init(&ctx) != 0) {
		rc = SMB_ADJOIN_ERR_INIT_KRB_CTX;
		goto adjoin_cleanup;
	}

	if (smb_krb5_get_principals(ah->domain, ctx, krb5princs) != 0) {
		rc = SMB_ADJOIN_ERR_GET_SPNS;
		goto adjoin_cleanup;
	}

	if (smb_krb5_setpwd(ctx, krb5princs[SMBKRB5_SPN_IDX_HOST],
	    machine_passwd) != 0) {
		rc = SMB_ADJOIN_ERR_KSETPWD;
		goto adjoin_cleanup;
	}

	kvno = smb_ads_lookup_computer_attr_kvno(ah, dn);

	if (smb_ads_update_computer_cntrl_attr(ah, des_only, dn)
	    != 0) {
		rc = SMB_ADJOIN_ERR_UPDATE_CNTRL_ATTR;
		goto adjoin_cleanup;
	}

	if (dclevel == SMB_ADS_DCLEVEL_W2K8) {
		num = sizeof (w2k8enctypes) / sizeof (krb5_enctype);
		encptr = w2k8enctypes;
	} else {
		num = sizeof (pre_w2k8enctypes) / sizeof (krb5_enctype);
		encptr = pre_w2k8enctypes;
	}

	if (smb_krb5_update_keytab_entries(ctx, krb5princs, SMBNS_KRB5_KEYTAB,
	    kvno, machine_passwd, encptr, num) != 0) {
		rc = SMB_ADJOIN_ERR_WRITE_KEYTAB;
		goto adjoin_cleanup;
	}

	/* Set IDMAP config */
	if (smb_config_set_idmap_domain(ah->domain) != 0) {
		rc = SMB_ADJOIN_ERR_IDMAP_SET_DOMAIN;
		goto adjoin_cleanup;
	}

	/* Refresh IDMAP service */
	if (smb_config_refresh_idmap() != 0) {
		rc = SMB_ADJOIN_ERR_IDMAP_REFRESH;
		goto adjoin_cleanup;
	}

	delete = B_FALSE;
adjoin_cleanup:
	if (new_acct && delete)
		smb_ads_del_computer(ah, dn);

	if (rc != SMB_ADJOIN_ERR_INIT_KRB_CTX) {
		if (rc != SMB_ADJOIN_ERR_GET_SPNS)
			smb_krb5_free_principals(ctx, krb5princs,
			    SMBKRB5_SPN_IDX_MAX);
		smb_krb5_ctx_fini(ctx);
	}

	smb_ads_close(ah);
	smb_ccache_remove(SMB_CCACHE_PATH);
	return (rc);
}

/*
 * smb_adjoin_report_err
 *
 * Display error message for the specific adjoin error code.
 */
char *
smb_adjoin_report_err(smb_adjoin_status_t status)
{
	if (status < 0 || status >= SMB_ADJOIN_NUM_STATUS)
		return ("ADJOIN: unknown status");

	return (adjoin_errmsg[status]);
}

/*
 * smb_ads_get_pdc_ip
 *
 * Check to see if there is any configured PDC.
 * If there is then converts the string IP to
 * integer format and returns it.
 */
static uint32_t
smb_ads_get_pdc_ip(void)
{
	char p[INET_ADDRSTRLEN];
	uint32_t ipaddr = 0;
	int rc;

	rc = smb_config_getstr(SMB_CI_DOMAIN_SRV, p, sizeof (p));
	if (rc == SMBD_SMF_OK) {
		rc = inet_pton(AF_INET, p, &ipaddr);
		if (rc == 0)
			ipaddr = 0;
	}

	return (ipaddr);
}

/*
 * smb_ads_dc_compare
 *
 * Comparision function for sorting host entries (SRV records of DC) via qsort.
 */
static int
smb_ads_dc_compare(const void *p, const void *q)
{
	smb_ads_host_info_t *h1 = (smb_ads_host_info_t *)p;
	smb_ads_host_info_t *h2 = (smb_ads_host_info_t *)q;

	if (h1->priority < h2->priority)
		return (-1);
	if (h1->priority > h2->priority)
		return (1);

	/* Priorities are equal */
	if (h1->weight < h2->weight)
		return (1);
	if (h1->weight > h2->weight)
		return (-1);

	return (0);
}

/*
 * smb_ads_dc_recommend
 *
 * RFC 2052/2782 are taken as reference, while implementing this algorithm.
 *
 * Domain Controllers(DCs) with lowest priority in their SRV DNS records
 * are selected first. If they have equal priorities, then DC with highest
 * weight in its SRV DNS record is selected. If the priority and weight are
 * both equal, then the DC at the top of the list is selected.
 *
 * Returns NULL if no DC found or if the found DC is not responding to
 * smb_ads_ldap_ping.
 */
static smb_ads_host_info_t *
smb_ads_dc_recommend(smb_ads_host_list_t *hlist)
{
	smb_ads_host_info_t *hinfo = NULL;
	int i;

	if (hlist->ah_cnt == 1) {
		hinfo = hlist->ah_list;
		return (hinfo);
	}

	qsort(hlist->ah_list, hlist->ah_cnt,
	    sizeof (smb_ads_host_info_t), smb_ads_dc_compare);

	/* We have the sorted list. Return the first DC that is up. */
	for (i = 0; i < hlist->ah_cnt; i++) {
		hinfo = &hlist->ah_list[i];
		if (smb_ads_ldap_ping(hinfo) == 0) {
			smb_tracef("smb_ads_dc_recommend: "
			    "Selected DC %s(pri=%d wt=%d)",
			    hinfo->name, hinfo->priority, hinfo->weight);
			return (hinfo);
		}
	}
	return (NULL);
}

/*
 * smb_ads_select_pdc
 *
 * This method selects a Preferred DC (PDC) from the passed list of DCs (hlist),
 * if the configured PDC property is set and the selected PDC responds to
 * ldap_ping.
 *
 * The passed hinfo structure contains a pointer to the selected DC.
 * Returns true if the PDC is found, false otherwise.
 */
static boolean_t
smb_ads_select_pdc(smb_ads_host_info_t *hinfo, smb_ads_host_list_t *hlist)
{
	uint32_t ip;
	smb_ads_host_info_t *thinfo = NULL;
	int r;

	if (ip = smb_ads_get_pdc_ip()) {
		for (r = 0; r < hlist->ah_cnt; r++) {
			if (hlist->ah_list[r].ip_addr == ip) {
				thinfo = &hlist->ah_list[r];
				if (smb_ads_ldap_ping(thinfo) == 0) {
					smb_ads_init_host_info(hinfo,
					    thinfo->name, thinfo->ip_addr,
					    thinfo->priority, thinfo->weight,
					    thinfo->port);
					return (B_TRUE);
				} else
					smb_tracef("PDC not responding.");
			}
		}
	}
	return (B_FALSE);
}

/*
 * smb_ads_select_dcfromsubnet
 *
 * This method builds a list of DC's in the same subnet and sorts the list
 * according to the priority and weight of the DC entry.
 * Returns the DC from the top of the sorted list, that responds to ldap ping.
 *
 * The passed hinfo structure contains a pointer to the selected DC.
 * mem_err argument is set, if there are memory allocation issues.
 * Returns true if DC is found in the same subnet, false otherwise.
 */
static boolean_t
smb_ads_select_dcfromsubnet(smb_ads_host_info_t *hinfo,
    smb_ads_host_list_t *hlist, int *mem_err)
{
	smb_ads_host_list_t *snet_hlist = NULL;
	smb_ads_host_info_t *snet_hinfo = NULL, *thinfo = NULL;
	smb_nic_t *lnic;
	int r, snet_count = 0;
	smb_niciter_t ni;

	snet_hlist = smb_ads_hlist_alloc(hlist->ah_cnt);
	if (snet_hlist == NULL) {
		*mem_err = 1;
		return (B_FALSE);
	}
	snet_hinfo = snet_hlist->ah_list;
	for (r = 0; r < hlist->ah_cnt; r++) {
		thinfo = &hlist->ah_list[r];
		if (smb_nic_getfirst(&ni) != 0)
			break;
		do {
			lnic = &ni.ni_nic;

			if ((thinfo->ip_addr & lnic->nic_mask) ==
			    (lnic->nic_ip & lnic->nic_mask)) {
				snet_count++;
				smb_ads_init_host_info(snet_hinfo, thinfo->name,
				    thinfo->ip_addr, thinfo->priority,
				    thinfo->weight, thinfo->port);
				snet_hinfo++;
			}
		} while (smb_nic_getnext(&ni) == 0);
	}
	snet_hlist->ah_cnt = snet_count;

	if (snet_hlist->ah_cnt > 0) {
		thinfo = smb_ads_dc_recommend(snet_hlist);
		if (thinfo) {
			smb_ads_init_host_info(hinfo, thinfo->name,
			    thinfo->ip_addr, thinfo->priority, thinfo->weight,
			    thinfo->port);
			smb_ads_hlist_free(snet_hlist);
			return (B_TRUE);
		}
	}
	smb_ads_hlist_free(snet_hlist);
	return (B_FALSE);
}

/*
 * smb_ads_select_dcfromlist
 *
 * This method sorts the list of DCs by priority and weight and
 * returns the first DC that responds to ldap ping.
 *
 * The passed hinfo structure contains a pointer to the selected DC.
 * Returns true if DC is found, false otherwise.
 */
static boolean_t
smb_ads_select_dcfromlist(smb_ads_host_info_t *hinfo,
    smb_ads_host_list_t *hlist)
{
	smb_ads_host_info_t *thinfo = NULL;

	thinfo = smb_ads_dc_recommend(hlist);
	if (thinfo) {
		smb_ads_init_host_info(hinfo,
		    thinfo->name, thinfo->ip_addr,
		    thinfo->priority, thinfo->weight,
		    thinfo->port);
		return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * smb_ads_select_dc
 *
 * Given the list of DCs returned by ADS lookup, this routine returns
 * a DC according to the following.
 *
 *  - If there is a configured PDC and it's in the ADS list,
 *    then return the DC, if it responds to ldap ping.
 *  - Build a list of DC's in the same subnet. Sort the list
 *    according to priority and weight of the DC entry.
 *    Return the DC from the top of the list, that responds to ldap ping.
 *  - Else, sort DC list by priority & weight and return first DC that responds
 *    to ldap ping.
 *
 * Returns NULL on error.
 */
static smb_ads_host_info_t *
smb_ads_select_dc(smb_ads_host_list_t *hlist)
{
	smb_ads_host_info_t *hinfo = NULL;
	int mem_err = 0;

	hinfo = (smb_ads_host_info_t *)malloc(sizeof (smb_ads_host_info_t));
	if (hinfo == NULL)
		return (NULL);

	/* 1. Check PDC. */
	if (smb_ads_select_pdc(hinfo, hlist))
		return (hinfo);

	/* 2. Check subnet. */
	if (smb_ads_select_dcfromsubnet(hinfo, hlist, &mem_err))
		return (hinfo);

	if (mem_err) {
		free(hinfo);
		return (NULL);
	}

	/*
	 * 3. Sort DC list by priority & weight and return first DC that
	 *    responds to LDAP ping.
	 */
	if (smb_ads_select_dcfromlist(hinfo, hlist))
		return (hinfo);

	free(hinfo);
	return (NULL);
}
