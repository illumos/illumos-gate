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
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/param.h>
#include <ldap.h>
#include <stdlib.h>
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
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>
#include <sasl/sasl.h>
#include <note.h>
#include <errno.h>
#include <cryptoutil.h>

#include <smbsrv/libsmbns.h>
#include <smbns_dyndns.h>
#include <smbns_krb.h>

#define	SMB_ADS_AF_UNKNOWN(x)	(((x)->ipaddr.a_family != AF_INET) && \
	((x)->ipaddr.a_family != AF_INET6))

#define	SMB_ADS_MAXBUFLEN 100
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
#define	SMB_ADS_DCLEVEL_W2K8_R2 4

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

static krb5_enctype w2k8enctypes[] = {
    ENCTYPE_AES256_CTS_HMAC_SHA1_96,
    ENCTYPE_AES128_CTS_HMAC_SHA1_96,
    ENCTYPE_ARCFOUR_HMAC,
    ENCTYPE_DES_CBC_CRC,
    ENCTYPE_DES_CBC_MD5,
};

static krb5_enctype pre_w2k8enctypes[] = {
    ENCTYPE_ARCFOUR_HMAC,
    ENCTYPE_DES_CBC_CRC,
    ENCTYPE_DES_CBC_MD5,
};

#define	SMB_ADS_ATTR_SAMACCT	"sAMAccountName"
#define	SMB_ADS_ATTR_UPN	"userPrincipalName"
#define	SMB_ADS_ATTR_SPN	"servicePrincipalName"
#define	SMB_ADS_ATTR_CTL	"userAccountControl"
#define	SMB_ADS_ATTR_DNSHOST	"dNSHostName"
#define	SMB_ADS_ATTR_KVNO	"msDS-KeyVersionNumber"
#define	SMB_ADS_ATTR_DN		"distinguishedName"

/*
 * UserAccountControl flags: manipulate user account properties.
 *
 * The hexadecimal value of the following property flags are based on MSDN
 * article # 305144.
 */
#define	SMB_ADS_USER_ACCT_CTL_SCRIPT				0x00000001
#define	SMB_ADS_USER_ACCT_CTL_ACCOUNTDISABLE			0x00000002
#define	SMB_ADS_USER_ACCT_CTL_HOMEDIR_REQUIRED			0x00000008
#define	SMB_ADS_USER_ACCT_CTL_LOCKOUT				0x00000010
#define	SMB_ADS_USER_ACCT_CTL_PASSWD_NOTREQD			0x00000020
#define	SMB_ADS_USER_ACCT_CTL_PASSWD_CANT_CHANGE		0x00000040
#define	SMB_ADS_USER_ACCT_CTL_ENCRYPTED_TEXT_PWD_ALLOWED	0x00000080
#define	SMB_ADS_USER_ACCT_CTL_TMP_DUP_ACCT			0x00000100
#define	SMB_ADS_USER_ACCT_CTL_NORMAL_ACCT			0x00000200
#define	SMB_ADS_USER_ACCT_CTL_INTERDOMAIN_TRUST_ACCT		0x00000800
#define	SMB_ADS_USER_ACCT_CTL_WKSTATION_TRUST_ACCT		0x00001000
#define	SMB_ADS_USER_ACCT_CTL_SRV_TRUST_ACCT			0x00002000
#define	SMB_ADS_USER_ACCT_CTL_DONT_EXPIRE_PASSWD		0x00010000
#define	SMB_ADS_USER_ACCT_CTL_MNS_LOGON_ACCT			0x00020000
#define	SMB_ADS_USER_ACCT_CTL_SMARTCARD_REQUIRED		0x00040000
#define	SMB_ADS_USER_ACCT_CTL_TRUSTED_FOR_DELEGATION		0x00080000
#define	SMB_ADS_USER_ACCT_CTL_NOT_DELEGATED			0x00100000
#define	SMB_ADS_USER_ACCT_CTL_USE_DES_KEY_ONLY			0x00200000
#define	SMB_ADS_USER_ACCT_CTL_DONT_REQ_PREAUTH			0x00400000
#define	SMB_ADS_USER_ACCT_CTL_PASSWD_EXPIRED			0x00800000
#define	SMB_ADS_USER_ACCT_CTL_TRUSTED_TO_AUTH_FOR_DELEGATION	0x01000000

/*
 * Length of "dc=" prefix.
 */
#define	SMB_ADS_DN_PREFIX_LEN	3

static char *smb_ads_computer_objcls[] = {
	"top", "person", "organizationalPerson",
	"user", "computer", NULL
};

static char *smb_ads_share_objcls[] = {
	"top", "leaf", "connectionPoint", "volume", NULL
};

/* Cached ADS server to communicate with */
static smb_ads_host_info_t *smb_ads_cached_host_info = NULL;
static mutex_t smb_ads_cached_host_mtx;

/*
 * SMB ADS config cache is maintained to facilitate the detection of
 * changes in configuration that is relevant to AD selection.
 */
typedef struct smb_ads_config {
	char c_site[SMB_ADS_SITE_MAX];
	smb_inaddr_t c_pdc;
	mutex_t c_mtx;
} smb_ads_config_t;

static smb_ads_config_t smb_ads_cfg;


/* attribute/value pair */
typedef struct smb_ads_avpair {
	char *avp_attr;
	char *avp_val;
} smb_ads_avpair_t;

/* query status */
typedef enum smb_ads_qstat {
	SMB_ADS_STAT_ERR = -2,
	SMB_ADS_STAT_DUP,
	SMB_ADS_STAT_NOT_FOUND,
	SMB_ADS_STAT_FOUND
} smb_ads_qstat_t;

typedef struct smb_ads_host_list {
	int ah_cnt;
	smb_ads_host_info_t *ah_list;
} smb_ads_host_list_t;

static smb_ads_handle_t *smb_ads_open_main(char *, char *, char *);
static int smb_ads_add_computer(smb_ads_handle_t *, int, char *);
static int smb_ads_modify_computer(smb_ads_handle_t *, int, char *);
static int smb_ads_computer_op(smb_ads_handle_t *, int, int, char *);
static smb_ads_qstat_t smb_ads_lookup_computer_n_attr(smb_ads_handle_t *,
    smb_ads_avpair_t *, int, char *);
static int smb_ads_update_computer_cntrl_attr(smb_ads_handle_t *, int, char *);
static krb5_kvno smb_ads_lookup_computer_attr_kvno(smb_ads_handle_t *, char *);
static void smb_ads_free_cached_host(void);
static int smb_ads_alloc_attr(LDAPMod **, int);
static void smb_ads_free_attr(LDAPMod **);
static int smb_ads_get_dc_level(smb_ads_handle_t *);
static smb_ads_host_info_t *smb_ads_select_dc(smb_ads_host_list_t *);
static smb_ads_qstat_t smb_ads_find_computer(smb_ads_handle_t *, char *);
static smb_ads_qstat_t smb_ads_getattr(LDAP *, LDAPMessage *,
    smb_ads_avpair_t *);
static smb_ads_qstat_t smb_ads_get_qstat(smb_ads_handle_t *, LDAPMessage *,
    smb_ads_avpair_t *);
static boolean_t smb_ads_match_pdc(smb_ads_host_info_t *);
static boolean_t smb_ads_is_sought_host(smb_ads_host_info_t *, char *);
static boolean_t smb_ads_is_same_domain(char *, char *);
static boolean_t smb_ads_is_pdc_configured(void);
static smb_ads_host_info_t *smb_ads_dup_host_info(smb_ads_host_info_t *);
static char *smb_ads_get_sharedn(const char *, const char *, const char *);
static krb5_enctype *smb_ads_get_enctypes(int, int *);

/*
 * smb_ads_init
 *
 * Initializes the ADS config cache.
 */
void
smb_ads_init(void)
{
	(void) mutex_lock(&smb_ads_cfg.c_mtx);
	(void) smb_config_getstr(SMB_CI_ADS_SITE,
	    smb_ads_cfg.c_site, SMB_ADS_SITE_MAX);
	(void) smb_config_getip(SMB_CI_DOMAIN_SRV, &smb_ads_cfg.c_pdc);
	(void) mutex_unlock(&smb_ads_cfg.c_mtx);
}

void
smb_ads_fini(void)
{
	smb_ads_free_cached_host();
}

/*
 * smb_ads_refresh
 *
 * This function will be called when smb/server SMF service is refreshed.
 * Clearing the smb_ads_cached_host_info would allow the next DC
 * discovery process to pick up an AD based on the new AD configuration.
 */
void
smb_ads_refresh(void)
{
	char new_site[SMB_ADS_SITE_MAX];
	smb_inaddr_t new_pdc;
	boolean_t purge = B_FALSE;

	(void) smb_config_getstr(SMB_CI_ADS_SITE, new_site, SMB_ADS_SITE_MAX);
	(void) smb_config_getip(SMB_CI_DOMAIN_SRV, &new_pdc);
	(void) mutex_lock(&smb_ads_cfg.c_mtx);
	if (smb_strcasecmp(smb_ads_cfg.c_site, new_site, 0)) {
		(void) strlcpy(smb_ads_cfg.c_site, new_site, SMB_ADS_SITE_MAX);
		purge = B_TRUE;
	}

	smb_ads_cfg.c_pdc = new_pdc;
	(void) mutex_unlock(&smb_ads_cfg.c_mtx);

	(void) mutex_lock(&smb_ads_cached_host_mtx);
	if (smb_ads_cached_host_info &&
	    smb_ads_is_pdc_configured() &&
	    !smb_ads_match_pdc(smb_ads_cached_host_info))
		purge = B_TRUE;
	(void) mutex_unlock(&smb_ads_cached_host_mtx);

	if (purge)
		smb_ads_free_cached_host();
}



static boolean_t
smb_ads_is_pdc_configured(void)
{
	boolean_t configured;

	(void) mutex_lock(&smb_ads_cfg.c_mtx);
	configured = !smb_inet_iszero(&smb_ads_cfg.c_pdc);
	(void) mutex_unlock(&smb_ads_cfg.c_mtx);

	return (configured);
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
	int ldversion = LDAP_VERSION3, status, timeoutms = 5 * 1000;
	LDAP *ld = NULL;

	ld = ldap_init(ads_host->name, ads_host->port);
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
 * The cached ADS host is no longer valid if one of the following criteria
 * is satisfied:
 *
 * 1) not in the specified domain
 * 2) not the sought host (if specified)
 * 3) not reachable
 *
 * The caller is responsible for acquiring the smb_ads_cached_host_mtx lock
 * prior to calling this function.
 *
 * Return B_TRUE if the cache host is still valid. Otherwise, return B_FALSE.
 */
static boolean_t
smb_ads_validate_cache_host(char *domain, char *srv)
{
	if (!smb_ads_cached_host_info)
		return (B_FALSE);

	if (!smb_ads_is_same_domain(smb_ads_cached_host_info->name, domain))
		return (B_FALSE);

	if (smb_ads_ldap_ping(smb_ads_cached_host_info) == 0) {
		if (!srv)
			return (B_TRUE);

		if (smb_ads_is_sought_host(smb_ads_cached_host_info, srv))
			return (B_TRUE);
	}

	return (B_FALSE);
}

/*
 * smb_ads_is_sought_host
 *
 * Returns true, if the sought host name matches the input host (host) name.
 * The sought host is expected to be in Fully Qualified Domain Name (FQDN)
 * format.
 */
static boolean_t
smb_ads_is_sought_host(smb_ads_host_info_t *host, char *sought_host_name)
{
	if ((host == NULL) || (sought_host_name == NULL))
		return (B_FALSE);

	if (smb_strcasecmp(host->name, sought_host_name, 0))
		return (B_FALSE);

	return (B_TRUE);
}

/*
 * smb_ads_match_hosts_same_domain
 *
 * Returns true, if the cached ADS host is in the same domain as the
 * current (given) domain.
 */
static boolean_t
smb_ads_is_same_domain(char *cached_host_name, char *current_domain)
{
	char *cached_host_domain;

	if ((cached_host_name == NULL) || (current_domain == NULL))
		return (B_FALSE);

	cached_host_domain = strchr(cached_host_name, '.');
	if (cached_host_domain == NULL)
		return (B_FALSE);

	++cached_host_domain;
	if (smb_strcasecmp(cached_host_domain, current_domain, 0))
		return (B_FALSE);

	return (B_TRUE);
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
		if ((len = dn_skipname(*ptr, eom)) < 0)
			return (-1);

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

		if ((len = dn_skipname(*ptr, eom)) < 0)
			return (-1);


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
		if (len < 0)
			return (-1);

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
		if ((len = dn_skipname(*ptr, eom)) < 0)
			return (-1);

		*ptr += len;
		/* skip type, class, ttl */
		*ptr += 8;
		/* get len of data */
		/* LINTED: E_CONSTANT_CONDITION */
		NS_GET16(size, *ptr);
		if ((*ptr + size) > eom)
			return (-1);

		*ptr += size;
	}

	return (0);
}

/*
 * smb_ads_decode_host_ip
 *
 * Decodes ADS hosts and IP Addresses from the additional section based
 * on the current buffer pointer.
 */
static int
smb_ads_decode_host_ip(int addit_cnt, int ans_cnt, uchar_t **ptr,
    uchar_t *eom, uchar_t *buf, smb_ads_host_info_t *ads_host_list)
{
	int i, j, len;
	smb_inaddr_t ipaddr;
	char hostname[MAXHOSTNAMELEN];
	char *name;
	uint16_t size = 0;

	for (i = 0; i < addit_cnt; i++) {

		/* domain name */
		len = dn_expand(buf, eom, *ptr, hostname, MAXHOSTNAMELEN);
		if (len < 0)
			return (-1);

		*ptr += len;

		/* skip type, class, TTL, data len */
		*ptr += 8;
		/* LINTED: E_CONSTANT_CONDITION */
		NS_GET16(size, *ptr);

		if (size == INADDRSZ) {
			/* LINTED: E_CONSTANT_CONDITION */
			NS_GET32(ipaddr.a_ipv4, *ptr);
			ipaddr.a_ipv4 = htonl(ipaddr.a_ipv4);
			ipaddr.a_family = AF_INET;
		} else if (size == IN6ADDRSZ) {
#ifdef BIG_ENDIAN
			bcopy(*ptr, &ipaddr.a_ipv6, IN6ADDRSZ);
#else
			for (i = 0; i < IN6ADDRSZ; i++)
				(uint8_t *)(ipaddr.a_ipv6)
				    [IN6ADDRSZ-1-i] = *(*ptr+i);
#endif
			ipaddr.a_family = AF_INET6;
			*ptr += size;
		}

		/*
		 * find the host in the list of DC records from
		 * the answer section, that matches the host in the
		 * additional section, and set its IP address.
		 */
		for (j = 0; j < ans_cnt; j++) {
			if ((name = ads_host_list[j].name) == NULL)
				continue;
			if (smb_strcasecmp(name, hostname, 0) == 0) {
				ads_host_list[j].ipaddr = ipaddr;
			}
		}
	}
	return (0);
}

/*
 * smb_ads_dup_host_info
 *
 * Duplicates the passed smb_ads_host_info_t structure.
 * Caller must free memory allocated by this method.
 *
 * Returns a reference to the duplicated smb_ads_host_info_t structure.
 * Returns NULL on error.
 */
static smb_ads_host_info_t *
smb_ads_dup_host_info(smb_ads_host_info_t *ads_host)
{
	smb_ads_host_info_t *dup_host;

	if (ads_host == NULL)
		return (NULL);

	dup_host = malloc(sizeof (smb_ads_host_info_t));

	if (dup_host != NULL)
		bcopy(ads_host, dup_host, sizeof (smb_ads_host_info_t));

	return (dup_host);
}

/*
 * smb_ads_hlist_alloc
 */
static smb_ads_host_list_t *
smb_ads_hlist_alloc(int count)
{
	int size;
	smb_ads_host_list_t *hlist;

	if (count == 0)
		return (NULL);

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
 * smb_ads_query_dns_server
 *
 * This routine sends a DNS service location (SRV) query message to the
 * DNS server via TCP to query it for a list of ADS server(s). Once a reply
 * is received, the reply message is parsed to get the hostname. If there are IP
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
 * Upon successful completion, host list of ADS server(s) is returned.
 */
static smb_ads_host_list_t *
smb_ads_query_dns_server(char *domain, char *msdcs_svc_name)
{
	smb_ads_host_list_t *hlist = NULL;
	int len, qcnt, ans_cnt, ns_cnt, addit_cnt;
	uchar_t *ptr, *eom;
	struct __res_state res_state;
	union {
		HEADER hdr;
		uchar_t buf[NS_MAXMSG];
	} msg;

	bzero(&res_state, sizeof (struct __res_state));
	if (res_ninit(&res_state) < 0)
		return (NULL);

	/* use TCP */
	res_state.options |= RES_USEVC;

	len = res_nquerydomain(&res_state, msdcs_svc_name, domain,
	    C_IN, T_SRV, msg.buf, sizeof (msg.buf));

	if (len < 0) {
		syslog(LOG_NOTICE, "DNS query for %s failed: %s",
		    msdcs_svc_name, hstrerror(res_state.res_h_errno));
		res_ndestroy(&res_state);
		return (NULL);
	}

	if (len > sizeof (msg.buf)) {
		syslog(LOG_NOTICE,
		    "DNS query for %s failed: too big", msdcs_svc_name);
		res_ndestroy(&res_state);
		return (NULL);
	}

	/* parse the reply, skip header and question sections */
	ptr = msg.buf + sizeof (msg.hdr);
	eom = msg.buf + len;

	/* check truncated message bit */
	if (msg.hdr.tc)
		syslog(LOG_NOTICE,
		    "DNS query for %s failed: truncated", msdcs_svc_name);

	qcnt = ntohs(msg.hdr.qdcount);
	ans_cnt = ntohs(msg.hdr.ancount);
	ns_cnt = ntohs(msg.hdr.nscount);
	addit_cnt = ntohs(msg.hdr.arcount);

	if (smb_ads_skip_ques_sec(qcnt, &ptr, eom) != 0) {
		res_ndestroy(&res_state);
		return (NULL);
	}

	hlist = smb_ads_hlist_alloc(ans_cnt);
	if (hlist == NULL) {
		res_ndestroy(&res_state);
		return (NULL);
	}

	/* walk through the answer section */
	if (smb_ads_decode_host_ans_sec(ans_cnt, &ptr, eom, msg.buf,
	    hlist->ah_list) != 0) {
		smb_ads_hlist_free(hlist);
		res_ndestroy(&res_state);
		return (NULL);
	}

	/* check authority section */
	if (ns_cnt > 0) {
		if (smb_ads_skip_auth_sec(ns_cnt, &ptr, eom) != 0) {
			smb_ads_hlist_free(hlist);
			res_ndestroy(&res_state);
			return (NULL);
		}
	}

	/*
	 * Check additional section to get IP address of ADS host.
	 */
	if (addit_cnt > 0) {
		if (smb_ads_decode_host_ip(addit_cnt, ans_cnt,
		    &ptr, eom, msg.buf, hlist->ah_list) != 0) {
			smb_ads_hlist_free(hlist);
			res_ndestroy(&res_state);
			return (NULL);
		}
	}

	res_ndestroy(&res_state);
	return (hlist);
}

/*
 * smb_ads_get_site_service
 *
 * Gets the msdcs SRV RR for the specified site.
 */
static void
smb_ads_get_site_service(char *site_service, size_t len)
{
	(void) mutex_lock(&smb_ads_cfg.c_mtx);
	if (*smb_ads_cfg.c_site == '\0')
		*site_service = '\0';
	else
		(void) snprintf(site_service, len,
		    SMB_ADS_MSDCS_SRV_SITE_RR, smb_ads_cfg.c_site);

	(void) mutex_unlock(&smb_ads_cfg.c_mtx);
}

/*
 * smb_ads_getipnodebyname
 *
 * This method gets the IP address by doing a host name lookup.
 */
static int
smb_ads_getipnodebyname(smb_ads_host_info_t *hentry)
{
	struct hostent *h;
	int error;

	switch (hentry->ipaddr.a_family) {
	case AF_INET6:
		h = getipnodebyname(hentry->name, hentry->ipaddr.a_family,
		    AI_DEFAULT, &error);
		if (h == NULL || h->h_length != IPV6_ADDR_LEN)
			return (-1);
		break;

	case AF_INET:
		h = getipnodebyname(hentry->name, hentry->ipaddr.a_family,
		    0, &error);
		if (h == NULL || h->h_length != INADDRSZ)
			return (-1);
		break;

	default:
		return (-1);
	}
	bcopy(*(h->h_addr_list), &hentry->ipaddr.a_ip, h->h_length);
	freehostent(h);
	return (0);
}

/*
 *  Checks the IP address to see if it is zero.  If so, then do a host
 *  lookup by hostname to get the IP address based on the IP family.
 *
 *  If the family is unknown then do a lookup by hostame based on the
 *  setting of the SMB_CI_IPV6_ENABLE property.
 */
static int
smb_ads_set_ipaddr(smb_ads_host_info_t *hentry)
{
	if (smb_inet_iszero(&hentry->ipaddr)) {
		if (smb_ads_getipnodebyname(hentry) < 0)
			return (-1);
	} else if (SMB_ADS_AF_UNKNOWN(hentry)) {
		hentry->ipaddr.a_family =
		    smb_config_getbool(SMB_CI_IPV6_ENABLE) ? AF_INET6 : AF_INET;

		if (smb_ads_getipnodebyname(hentry) < 0) {
			hentry->ipaddr.a_family = 0;
			return (-1);
		}
	}

	return (0);
}

/*
 * smb_ads_find_host
 *
 * Finds an ADS host in a given domain.
 *
 * If the cached host is valid, it will be used. Otherwise, a DC will
 * be selected based on the following criteria:
 *
 * 1) pdc (aka preferred DC) configuration
 * 2) AD site configuration - the scope of the DNS lookup will be
 * restricted to the specified site.
 * 3) DC on the same subnet
 * 4) DC with the lowest priority/highest weight
 *
 * The above items are listed in decreasing preference order. The selected
 * DC must be online.
 *
 * If this function is called during domain join, the specified kpasswd server
 * takes precedence over preferred DC, AD site, and so on.
 *
 * Parameters:
 *   domain: fully-qualified domain name.
 *   kpasswd_srv: fully-quailifed hostname of the kpasswd server.
 *
 * Returns:
 *   A copy of the cached host info is returned. The caller is responsible
 *   for deallocating the memory returned by this function.
 */
/*ARGSUSED*/
smb_ads_host_info_t *
smb_ads_find_host(char *domain, char *kpasswd_srv)
{
	int i;
	char site_service[MAXHOSTNAMELEN];
	smb_ads_host_list_t *hlist, *hlist2;
	smb_ads_host_info_t *hlistp = NULL, *host = NULL;
	smb_ads_host_info_t *found_kpasswd_srv = NULL;
	smb_ads_host_info_t *found_pdc = NULL;

	if ((kpasswd_srv) && (*kpasswd_srv == '\0'))
		kpasswd_srv = NULL;

	(void) mutex_lock(&smb_ads_cached_host_mtx);
	if (smb_ads_validate_cache_host(domain, kpasswd_srv)) {
		host = smb_ads_dup_host_info(smb_ads_cached_host_info);
		(void) mutex_unlock(&smb_ads_cached_host_mtx);
		return (host);
	}

	(void) mutex_unlock(&smb_ads_cached_host_mtx);
	smb_ads_free_cached_host();

	/*
	 * First look for ADS hosts in ADS site if configured.  Then try
	 * without ADS site info.
	 */
	hlist = NULL;
	smb_ads_get_site_service(site_service, MAXHOSTNAMELEN);

	/*
	 * If we're given an AD, the DNS SRV RR lookup should not be restricted
	 * to the specified site since there is no guarantee that the specified
	 * AD is in the specified site.
	 */
	if (*site_service != '\0' && !kpasswd_srv &&
	    !smb_ads_is_pdc_configured())
		hlist = smb_ads_query_dns_server(domain, site_service);

	if (!hlist)
		hlist = smb_ads_query_dns_server(domain,
		    SMB_ADS_MSDCS_SRV_DC_RR);

	if ((hlist == NULL) || (hlist->ah_list == NULL) || (hlist->ah_cnt == 0))
		return (NULL);

	for (i = 0, hlistp = hlist->ah_list; i < hlist->ah_cnt; i++) {
		if (smb_ads_set_ipaddr(&hlistp[i]) < 0)
			continue;

		if (smb_ads_is_sought_host(&hlistp[i], kpasswd_srv))
			found_kpasswd_srv = &hlistp[i];

		if (smb_ads_match_pdc(&hlistp[i]))
			found_pdc = &hlistp[i];
	}

	if (found_kpasswd_srv && smb_ads_ldap_ping(found_kpasswd_srv) == 0) {
		host = found_kpasswd_srv;
		goto update_cache;
	}

	if (found_pdc && smb_ads_ldap_ping(found_pdc) == 0) {
		host = found_pdc;
		goto update_cache;
	}

	/*
	 * If the specified DC (kpasswd_srv or pdc) is not found, fallback
	 * to find a DC in the specified AD site.
	 */
	if (*site_service != '\0' &&
	    (kpasswd_srv || smb_ads_is_pdc_configured())) {
		hlist2 = smb_ads_query_dns_server(domain, site_service);
		if (hlist2 && hlist2->ah_list && hlist2->ah_cnt != 0) {
			smb_ads_hlist_free(hlist);
			hlist = hlist2;
			hlistp = hlist->ah_list;

			for (i = 0; i < hlist->ah_cnt; i++)
				(void) smb_ads_set_ipaddr(&hlistp[i]);
		}
	}

	/* Select DC from DC list */
	host = smb_ads_select_dc(hlist);

update_cache:
	if (host) {
		(void) mutex_lock(&smb_ads_cached_host_mtx);
		if (!smb_ads_cached_host_info)
			smb_ads_cached_host_info = smb_ads_dup_host_info(host);
		host = smb_ads_dup_host_info(smb_ads_cached_host_info);
		(void) mutex_unlock(&smb_ads_cached_host_mtx);
	}

	smb_ads_hlist_free(hlist);
	return (host);
}

/*
 * Return the number of dots in a string.
 */
static int
smb_ads_count_dots(const char *s)
{
	int ndots = 0;

	while (*s) {
		if (*s++ == '.')
			ndots++;
	}

	return (ndots);
}

/*
 * Convert a domain name in dot notation to distinguished name format,
 * for example: sun.com -> dc=sun,dc=com.
 *
 * Returns a pointer to an allocated buffer containing the distinguished
 * name.
 */
static char *
smb_ads_convert_domain(const char *domain_name)
{
	const char *s;
	char *dn_name;
	char buf[2];
	int ndots;
	int len;

	if (domain_name == NULL || *domain_name == 0)
		return (NULL);

	ndots = smb_ads_count_dots(domain_name);
	++ndots;
	len = strlen(domain_name) + (ndots * SMB_ADS_DN_PREFIX_LEN) + 1;

	if ((dn_name = malloc(len)) == NULL)
		return (NULL);

	bzero(dn_name, len);
	(void) strlcpy(dn_name, "dc=", len);

	buf[1] = '\0';
	s = domain_name;

	while (*s) {
		if (*s == '.') {
			(void) strlcat(dn_name, ",dc=", len);
		} else {
			buf[0] = *s;
			(void) strlcat(dn_name, buf, len);
		}
		++s;
	}

	return (dn_name);
}

/*
 * smb_ads_free_cached_host
 *
 * Free the memory use by the global smb_ads_cached_host_info & set it to NULL.
 */
static void
smb_ads_free_cached_host(void)
{
	(void) mutex_lock(&smb_ads_cached_host_mtx);
	if (smb_ads_cached_host_info) {
		free(smb_ads_cached_host_info);
		smb_ads_cached_host_info = NULL;
	}
	(void) mutex_unlock(&smb_ads_cached_host_mtx);
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

static int
smb_ads_saslcallback(LDAP *ld, unsigned flags, void *defaults, void *prompts)
{
	NOTE(ARGUNUSED(ld, defaults));
	sasl_interact_t *interact;

	if (prompts == NULL || flags != LDAP_SASL_INTERACTIVE)
		return (LDAP_PARAM_ERROR);

	/* There should be no extra arguemnts for SASL/GSSAPI authentication */
	for (interact = prompts; interact->id != SASL_CB_LIST_END;
	    interact++) {
		interact->result = NULL;
		interact->len = 0;
	}
	return (LDAP_SUCCESS);
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
 * The LDAP connection is bound before the ADS handle is returned.
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
	int version = 3;
	smb_ads_host_info_t *ads_host = NULL;
	int rc;

	if (user != NULL) {
		if (smb_kinit(user, password) == 0)
			return (NULL);
		user = NULL;
		password = NULL;
	}

	ads_host = smb_ads_find_host(domain, NULL);
	if (ads_host == NULL)
		return (NULL);

	ah = (smb_ads_handle_t *)malloc(sizeof (smb_ads_handle_t));
	if (ah == NULL) {
		free(ads_host);
		return (NULL);
	}

	(void) memset(ah, 0, sizeof (smb_ads_handle_t));

	if ((ld = ldap_init(ads_host->name, ads_host->port)) == NULL) {
		smb_ads_free_cached_host();
		free(ah);
		free(ads_host);
		return (NULL);
	}

	if (ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version)
	    != LDAP_SUCCESS) {
		smb_ads_free_cached_host();
		free(ah);
		free(ads_host);
		(void) ldap_unbind(ld);
		return (NULL);
	}

	(void) ldap_set_option(ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
	ah->ld = ld;
	ah->domain = strdup(domain);

	if (ah->domain == NULL) {
		smb_ads_close(ah);
		free(ads_host);
		return (NULL);
	}

	/*
	 * ah->domain is often used for generating service principal name.
	 * Convert it to lower case for RFC 4120 section 6.2.1 conformance.
	 */
	(void) smb_strlwr(ah->domain);
	ah->domain_dn = smb_ads_convert_domain(domain);
	if (ah->domain_dn == NULL) {
		smb_ads_close(ah);
		free(ads_host);
		return (NULL);
	}

	ah->hostname = strdup(ads_host->name);
	if (ah->hostname == NULL) {
		smb_ads_close(ah);
		free(ads_host);
		return (NULL);
	}
	(void) mutex_lock(&smb_ads_cfg.c_mtx);
	if (*smb_ads_cfg.c_site != '\0') {
		if ((ah->site = strdup(smb_ads_cfg.c_site)) == NULL) {
			smb_ads_close(ah);
			(void) mutex_unlock(&smb_ads_cfg.c_mtx);
			free(ads_host);
			return (NULL);
		}
	} else {
		ah->site = NULL;
	}
	(void) mutex_unlock(&smb_ads_cfg.c_mtx);

	rc = ldap_sasl_interactive_bind_s(ah->ld, "", "GSSAPI", NULL, NULL,
	    LDAP_SASL_INTERACTIVE, &smb_ads_saslcallback, NULL);
	if (rc != LDAP_SUCCESS) {
		syslog(LOG_ERR, "ldal_sasl_interactive_bind_s failed (%s)",
		    ldap_err2string(rc));
		smb_ads_close(ah);
		free(ads_host);
		return (NULL);
	}

	free(ads_host);
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
	if (ah == NULL)
		return;
	/* close and free connection resources */
	if (ah->ld)
		(void) ldap_unbind(ah->ld);

	free(ah->domain);
	free(ah->domain_dn);
	free(ah->hostname);
	free(ah->site);
	free(ah);
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
 * Returns share DN in an allocated buffer.  The format of the DN is
 * cn=<sharename>,<container RDNs>,<domain DN>
 *
 * If the domain DN is not included in the container parameter,
 * then it will be appended to create the share DN.
 *
 * The caller must free the allocated buffer.
 */
static char *
smb_ads_get_sharedn(const char *sharename, const char *container,
    const char *domain_dn)
{
	char *share_dn;
	int rc, offset, container_len, domain_len;
	boolean_t append_domain = B_TRUE;

	container_len = strlen(container);
	domain_len = strlen(domain_dn);

	if (container_len >= domain_len) {

		/* offset to last domain_len characters */
		offset = container_len - domain_len;

		if (smb_strcasecmp(container + offset,
		    domain_dn, domain_len) == 0)
			append_domain = B_FALSE;
	}

	if (append_domain)
		rc = asprintf(&share_dn, "cn=%s,%s,%s", sharename,
		    container, domain_dn);
	else
		rc = asprintf(&share_dn, "cn=%s,%s", sharename,
		    container);

	return ((rc == -1) ? NULL : share_dn);
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
	int j = 0;
	char *share_dn;
	int ret;
	char *unc_names[] = {(char *)unc_name, NULL};

	if ((share_dn = smb_ads_get_sharedn(adsShareName, adsContainer,
	    ah->domain_dn)) == NULL)
		return (-1);

	if (smb_ads_alloc_attr(attrs, SMB_ADS_SHARE_NUM_ATTR) != 0) {
		free(share_dn);
		return (-1);
	}

	attrs[j]->mod_op = LDAP_MOD_ADD;
	attrs[j]->mod_type = "objectClass";
	attrs[j]->mod_values = smb_ads_share_objcls;

	attrs[++j]->mod_op = LDAP_MOD_ADD;
	attrs[j]->mod_type = "uNCName";
	attrs[j]->mod_values = unc_names;

	if ((ret = ldap_add_s(ah->ld, share_dn, attrs)) != LDAP_SUCCESS) {
		if (ret == LDAP_NO_SUCH_OBJECT) {
			syslog(LOG_ERR, "Failed to publish share %s in" \
			    " AD.  Container does not exist: %s.\n",
			    adsShareName, share_dn);

		} else {
			syslog(LOG_ERR, "Failed to publish share %s in" \
			    " AD: %s (%s).\n", adsShareName, share_dn,
			    ldap_err2string(ret));
		}
		smb_ads_free_attr(attrs);
		free(share_dn);
		return (ret);
	}
	free(share_dn);
	smb_ads_free_attr(attrs);

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
	char *share_dn;
	int ret;

	if ((share_dn = smb_ads_get_sharedn(adsShareName, adsContainer,
	    ah->domain_dn)) == NULL)
		return (-1);

	if ((ret = ldap_delete_s(ah->ld, share_dn)) != LDAP_SUCCESS) {
		smb_tracef("ldap_delete: %s", ldap_err2string(ret));
		free(share_dn);
		return (-1);
	}
	free(share_dn);

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
	int ret;
	LDAPMessage *res;
	char tmpbuf[SMB_ADS_MAXBUFLEN];

	if (adsShareName == NULL || adsContainer == NULL)
		return (-1);

	if ((share_dn = smb_ads_get_sharedn(adsShareName, adsContainer,
	    ah->domain_dn)) == NULL)
		return (-1);

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
		if (ret != LDAP_NO_SUCH_OBJECT)
			smb_tracef("%s: ldap_search: %s", share_dn,
			    ldap_err2string(ret));

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
	    hostname, shareUNC) < 0)
		return (-1);

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
		if (ret == LDAP_ALREADY_EXISTS)
			ret = -1;

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
	    hostname, shareUNC) < 0)
		return (-1);

	ret = smb_ads_lookup_share(ah, adsShareName, adsContainer, unc_name);
	if (ret == 0)
		return (0);
	if (ret == -1)
		return (-1);

	return (smb_ads_del_share(ah, adsShareName, adsContainer));
}

/*
 * smb_ads_get_default_comp_container_dn
 *
 * Build the distinguished name for the default computer conatiner (i.e. the
 * pre-defined Computers container).
 */
static void
smb_ads_get_default_comp_container_dn(smb_ads_handle_t *ah, char *buf,
    size_t buflen)
{
	(void) snprintf(buf, buflen, "cn=%s,%s", SMB_ADS_COMPUTERS_CN,
	    ah->domain_dn);
}

/*
 * smb_ads_get_default_comp_dn
 *
 * Build the distinguished name for this system.
 */
static void
smb_ads_get_default_comp_dn(smb_ads_handle_t *ah, char *buf, size_t buflen)
{
	char nbname[NETBIOS_NAME_SZ];
	char container_dn[SMB_ADS_DN_MAX];

	(void) smb_getnetbiosname(nbname, sizeof (nbname));
	smb_ads_get_default_comp_container_dn(ah, container_dn, SMB_ADS_DN_MAX);
	(void) snprintf(buf, buflen, "cn=%s,%s", nbname, container_dn);
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

/*
 * The fully-qualified hostname returned by this function is often used for
 * constructing service principal name.  Return the fully-qualified hostname
 * in lower case for RFC 4120 section 6.2.1 conformance.
 */
static int
smb_ads_getfqhostname(smb_ads_handle_t *ah, char *fqhost, int len)
{
	if (smb_gethostname(fqhost, len, SMB_CASE_LOWER) != 0)
		return (-1);

	(void) snprintf(fqhost, len, "%s.%s", fqhost,
	    ah->domain);

	return (0);
}

static int
smb_ads_computer_op(smb_ads_handle_t *ah, int op, int dclevel, char *dn)
{
	LDAPMod *attrs[SMB_ADS_COMPUTER_NUM_ATTR];
	char *sam_val[2];
	char *ctl_val[2], *fqh_val[2];
	char *encrypt_val[2];
	int j = -1;
	int ret, usrctl_flags = 0;
	char sam_acct[SMB_SAMACCT_MAXLEN];
	char fqhost[MAXHOSTNAMELEN];
	char usrctl_buf[16];
	char encrypt_buf[16];
	int max;
	smb_krb5_pn_set_t spn, upn;

	if (smb_getsamaccount(sam_acct, sizeof (sam_acct)) != 0)
		return (-1);

	if (smb_ads_getfqhostname(ah, fqhost, MAXHOSTNAMELEN))
		return (-1);

	/* The SPN attribute is multi-valued and must be 1 or greater */
	if (smb_krb5_get_pn_set(&spn, SMB_PN_SPN_ATTR, ah->domain) == 0)
		return (-1);

	/* The UPN attribute is single-valued and cannot be zero */
	if (smb_krb5_get_pn_set(&upn, SMB_PN_UPN_ATTR, ah->domain) != 1) {
		smb_krb5_free_pn_set(&spn);
		smb_krb5_free_pn_set(&upn);
		return (-1);
	}

	max = (SMB_ADS_COMPUTER_NUM_ATTR - ((op != LDAP_MOD_ADD) ? 1 : 0))
	    - (dclevel >= SMB_ADS_DCLEVEL_W2K8 ?  0 : 1);

	if (smb_ads_alloc_attr(attrs, max) != 0) {
		smb_krb5_free_pn_set(&spn);
		smb_krb5_free_pn_set(&upn);
		return (-1);
	}

	/* objectClass attribute is not modifiable. */
	if (op == LDAP_MOD_ADD) {
		attrs[++j]->mod_op = op;
		attrs[j]->mod_type = "objectClass";
		attrs[j]->mod_values = smb_ads_computer_objcls;
	}

	attrs[++j]->mod_op = op;
	attrs[j]->mod_type = SMB_ADS_ATTR_SAMACCT;
	sam_val[0] = sam_acct;
	sam_val[1] = 0;
	attrs[j]->mod_values = sam_val;

	attrs[++j]->mod_op = op;
	attrs[j]->mod_type = SMB_ADS_ATTR_UPN;
	attrs[j]->mod_values = upn.s_pns;

	attrs[++j]->mod_op = op;
	attrs[j]->mod_type = SMB_ADS_ATTR_SPN;
	attrs[j]->mod_values =  spn.s_pns;

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
			syslog(LOG_NOTICE, "ldap_add: %s",
			    ldap_err2string(ret));
			ret = -1;
		}
		break;

	case LDAP_MOD_REPLACE:
		if ((ret = ldap_modify_s(ah->ld, dn, attrs)) != LDAP_SUCCESS) {
			syslog(LOG_NOTICE, "ldap_modify: %s",
			    ldap_err2string(ret));
			ret = -1;
		}
		break;

	default:
		ret = -1;

	}

	smb_ads_free_attr(attrs);
	smb_krb5_free_pn_set(&spn);
	smb_krb5_free_pn_set(&upn);

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
		smb_tracef("ldap_delete: %s", ldap_err2string(rc));
}

/*
 * Gets the value of the given attribute.
 */
static smb_ads_qstat_t
smb_ads_getattr(LDAP *ld, LDAPMessage *entry, smb_ads_avpair_t *avpair)
{
	char **vals;
	smb_ads_qstat_t rc = SMB_ADS_STAT_FOUND;

	assert(avpair);
	avpair->avp_val = NULL;
	vals = ldap_get_values(ld, entry, avpair->avp_attr);
	if (!vals)
		return (SMB_ADS_STAT_NOT_FOUND);

	if (!vals[0]) {
		ldap_value_free(vals);
		return (SMB_ADS_STAT_NOT_FOUND);
	}

	avpair->avp_val = strdup(vals[0]);
	if (!avpair->avp_val)
		rc = SMB_ADS_STAT_ERR;

	ldap_value_free(vals);
	return (rc);
}

/*
 * Process query's result.
 */
static smb_ads_qstat_t
smb_ads_get_qstat(smb_ads_handle_t *ah, LDAPMessage *res,
    smb_ads_avpair_t *avpair)
{
	char fqhost[MAXHOSTNAMELEN];
	smb_ads_avpair_t dnshost_avp;
	smb_ads_qstat_t rc = SMB_ADS_STAT_FOUND;
	LDAPMessage *entry;

	if (smb_ads_getfqhostname(ah, fqhost, MAXHOSTNAMELEN))
		return (SMB_ADS_STAT_ERR);

	if (ldap_count_entries(ah->ld, res) == 0)
		return (SMB_ADS_STAT_NOT_FOUND);

	if ((entry = ldap_first_entry(ah->ld, res)) == NULL)
		return (SMB_ADS_STAT_ERR);

	dnshost_avp.avp_attr = SMB_ADS_ATTR_DNSHOST;
	rc = smb_ads_getattr(ah->ld, entry, &dnshost_avp);

	switch (rc) {
	case SMB_ADS_STAT_FOUND:
		/*
		 * Returns SMB_ADS_STAT_DUP to avoid overwriting
		 * the computer account of another system whose
		 * NetBIOS name collides with that of the current
		 * system.
		 */
		if (strcasecmp(dnshost_avp.avp_val, fqhost))
			rc = SMB_ADS_STAT_DUP;

		free(dnshost_avp.avp_val);
		break;

	case SMB_ADS_STAT_NOT_FOUND:
		/*
		 * Pre-created computer account doesn't have
		 * the dNSHostname attribute. It's been observed
		 * that the dNSHostname attribute is only set after
		 * a successful domain join.
		 * Returns SMB_ADS_STAT_FOUND as the account is
		 * pre-created for the current system.
		 */
		rc = SMB_ADS_STAT_FOUND;
		break;

	default:
		break;
	}

	if (rc != SMB_ADS_STAT_FOUND)
		return (rc);

	if (avpair)
		rc = smb_ads_getattr(ah->ld, entry, avpair);

	return (rc);

}

/*
 * smb_ads_lookup_computer_n_attr
 *
 * If avpair is NULL, checks the status of the specified computer account.
 * Otherwise, looks up the value of the specified computer account's attribute.
 * If found, the value field of the avpair will be allocated and set. The
 * caller should free the allocated buffer.
 *
 * Return:
 *  SMB_ADS_STAT_FOUND  - if both the computer and the specified attribute is
 *                        found.
 *  SMB_ADS_STAT_NOT_FOUND - if either the computer or the specified attribute
 *                           is not found.
 *  SMB_ADS_STAT_DUP - if the computer account is already used by other systems
 *                     in the AD. This could happen if the hostname of multiple
 *                     systems resolved to the same NetBIOS name.
 *  SMB_ADS_STAT_ERR - any failure.
 */
static smb_ads_qstat_t
smb_ads_lookup_computer_n_attr(smb_ads_handle_t *ah, smb_ads_avpair_t *avpair,
    int scope, char *dn)
{
	char *attrs[3], filter[SMB_ADS_MAXBUFLEN];
	LDAPMessage *res;
	char sam_acct[SMB_SAMACCT_MAXLEN], sam_acct2[SMB_SAMACCT_MAXLEN];
	smb_ads_qstat_t rc;

	if (smb_getsamaccount(sam_acct, sizeof (sam_acct)) != 0)
		return (SMB_ADS_STAT_ERR);

	res = NULL;
	attrs[0] = SMB_ADS_ATTR_DNSHOST;
	attrs[1] = NULL;
	attrs[2] = NULL;

	if (avpair) {
		if (!avpair->avp_attr)
			return (SMB_ADS_STAT_ERR);

		attrs[1] = avpair->avp_attr;
	}

	if (smb_ads_escape_search_filter_chars(sam_acct, sam_acct2) != 0)
		return (SMB_ADS_STAT_ERR);

	(void) snprintf(filter, sizeof (filter),
	    "(&(objectClass=computer)(%s=%s))", SMB_ADS_ATTR_SAMACCT,
	    sam_acct2);

	if (ldap_search_s(ah->ld, dn, scope, filter, attrs, 0,
	    &res) != LDAP_SUCCESS) {
		(void) ldap_msgfree(res);
		return (SMB_ADS_STAT_NOT_FOUND);
	}

	rc = smb_ads_get_qstat(ah, res, avpair);
	/* free the search results */
	(void) ldap_msgfree(res);
	return (rc);
}

/*
 * smb_ads_find_computer
 *
 * Starts by searching for the system's AD computer object in the default
 * container (i.e. cn=Computers).  If not found, searches the entire directory.
 * If found, 'dn' will be set to the distinguished name of the system's AD
 * computer object.
 */
static smb_ads_qstat_t
smb_ads_find_computer(smb_ads_handle_t *ah, char *dn)
{
	smb_ads_qstat_t stat;
	smb_ads_avpair_t avpair;

	avpair.avp_attr = SMB_ADS_ATTR_DN;
	smb_ads_get_default_comp_container_dn(ah, dn, SMB_ADS_DN_MAX);
	stat = smb_ads_lookup_computer_n_attr(ah, &avpair, LDAP_SCOPE_ONELEVEL,
	    dn);

	if (stat == SMB_ADS_STAT_NOT_FOUND) {
		(void) strlcpy(dn, ah->domain_dn, SMB_ADS_DN_MAX);
		stat = smb_ads_lookup_computer_n_attr(ah, &avpair,
		    LDAP_SCOPE_SUBTREE, dn);
	}

	if (stat == SMB_ADS_STAT_FOUND) {
		(void) strlcpy(dn, avpair.avp_val, SMB_ADS_DN_MAX);
		free(avpair.avp_val);
	}

	return (stat);
}

/*
 * smb_ads_update_computer_cntrl_attr
 *
 * Modify the user account control attribute of an existing computer
 * object on AD.
 *
 * Returns LDAP error code.
 */
static int
smb_ads_update_computer_cntrl_attr(smb_ads_handle_t *ah, int flags, char *dn)
{
	LDAPMod *attrs[2];
	char *ctl_val[2];
	int ret = 0;
	char usrctl_buf[16];

	if (smb_ads_alloc_attr(attrs, sizeof (attrs) / sizeof (LDAPMod *)) != 0)
		return (LDAP_NO_MEMORY);

	attrs[0]->mod_op = LDAP_MOD_REPLACE;
	attrs[0]->mod_type = SMB_ADS_ATTR_CTL;

	(void) snprintf(usrctl_buf, sizeof (usrctl_buf), "%d", flags);
	ctl_val[0] = usrctl_buf;
	ctl_val[1] = 0;
	attrs[0]->mod_values = ctl_val;
	if ((ret = ldap_modify_s(ah->ld, dn, attrs)) != LDAP_SUCCESS) {
		syslog(LOG_NOTICE, "ldap_modify: %s", ldap_err2string(ret));
	}

	smb_ads_free_attr(attrs);
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
	smb_ads_avpair_t avpair;
	int kvno = 1;

	avpair.avp_attr = SMB_ADS_ATTR_KVNO;
	if (smb_ads_lookup_computer_n_attr(ah, &avpair,
	    LDAP_SCOPE_BASE, dn) == SMB_ADS_STAT_FOUND) {
		kvno = atoi(avpair.avp_val);
		free(avpair.avp_val);
	}

	return (kvno);
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
smb_ads_join(char *domain, char *user, char *usr_passwd, char *machine_passwd)
{
	smb_ads_handle_t *ah = NULL;
	krb5_context ctx = NULL;
	krb5_principal *krb5princs = NULL;
	krb5_kvno kvno;
	boolean_t des_only, delete = B_TRUE;
	smb_adjoin_status_t rc = SMB_ADJOIN_SUCCESS;
	boolean_t new_acct;
	int dclevel, num, usrctl_flags = 0;
	smb_ads_qstat_t qstat;
	char dn[SMB_ADS_DN_MAX];
	char tmpfile[] = SMBNS_KRB5_KEYTAB_TMP;
	int cnt;
	smb_krb5_pn_set_t spns;

	krb5_enctype *encptr;

	if ((ah = smb_ads_open_main(domain, user, usr_passwd)) == NULL) {
		smb_ccache_remove(SMB_CCACHE_PATH);
		return (SMB_ADJOIN_ERR_GET_HANDLE);
	}

	if ((dclevel = smb_ads_get_dc_level(ah)) == -1) {
		smb_ads_close(ah);
		smb_ccache_remove(SMB_CCACHE_PATH);
		return (SMB_ADJOIN_ERR_GET_DCLEVEL);
	}

	qstat = smb_ads_find_computer(ah, dn);
	switch (qstat) {
	case SMB_ADS_STAT_FOUND:
		new_acct = B_FALSE;
		if (smb_ads_modify_computer(ah, dclevel, dn) != 0) {
			smb_ads_close(ah);
			smb_ccache_remove(SMB_CCACHE_PATH);
			return (SMB_ADJOIN_ERR_MOD_TRUST_ACCT);
		}
		break;

	case SMB_ADS_STAT_NOT_FOUND:
		new_acct = B_TRUE;
		smb_ads_get_default_comp_dn(ah, dn, SMB_ADS_DN_MAX);
		if (smb_ads_add_computer(ah, dclevel, dn) != 0) {
			smb_ads_close(ah);
			smb_ccache_remove(SMB_CCACHE_PATH);
			return (SMB_ADJOIN_ERR_ADD_TRUST_ACCT);
		}
		break;

	default:
		if (qstat == SMB_ADS_STAT_DUP)
			rc = SMB_ADJOIN_ERR_DUP_TRUST_ACCT;
		else
			rc = SMB_ADJOIN_ERR_TRUST_ACCT;
		smb_ads_close(ah);
		smb_ccache_remove(SMB_CCACHE_PATH);
		return (rc);
	}

	des_only = B_FALSE;

	if (smb_krb5_ctx_init(&ctx) != 0) {
		rc = SMB_ADJOIN_ERR_INIT_KRB_CTX;
		goto adjoin_cleanup;
	}

	if (smb_krb5_get_pn_set(&spns, SMB_PN_KEYTAB_ENTRY, ah->domain) == 0) {
		rc = SMB_ADJOIN_ERR_GET_SPNS;
		goto adjoin_cleanup;
	}

	if (smb_krb5_get_kprincs(ctx, spns.s_pns, spns.s_cnt, &krb5princs)
	    != 0) {
		smb_krb5_free_pn_set(&spns);
		rc = SMB_ADJOIN_ERR_GET_SPNS;
		goto adjoin_cleanup;
	}

	cnt = spns.s_cnt;
	smb_krb5_free_pn_set(&spns);

	/* New machine_passwd was filled in by our caller. */
	if (smb_krb5_setpwd(ctx, ah->domain, machine_passwd) != 0) {
		rc = SMB_ADJOIN_ERR_KSETPWD;
		goto adjoin_cleanup;
	}

	kvno = smb_ads_lookup_computer_attr_kvno(ah, dn);

	/*
	 * Only members of Domain Admins and Enterprise Admins can set
	 * the TRUSTED_FOR_DELEGATION userAccountControl flag.
	 */
	if (smb_ads_update_computer_cntrl_attr(ah,
	    SMB_ADS_USER_ACCT_CTL_WKSTATION_TRUST_ACCT |
	    SMB_ADS_USER_ACCT_CTL_TRUSTED_FOR_DELEGATION, dn)
	    == LDAP_INSUFFICIENT_ACCESS) {
		usrctl_flags |= (SMB_ADS_USER_ACCT_CTL_WKSTATION_TRUST_ACCT |
		    SMB_ADS_USER_ACCT_CTL_DONT_EXPIRE_PASSWD);

		syslog(LOG_NOTICE, "Unable to set the "
		    "TRUSTED_FOR_DELEGATION userAccountControl flag on "
		    "the machine account in Active Directory.  Please refer "
		    "to the Troubleshooting guide for more information.");

	} else {
		usrctl_flags |= (SMB_ADS_USER_ACCT_CTL_WKSTATION_TRUST_ACCT |
		    SMB_ADS_USER_ACCT_CTL_TRUSTED_FOR_DELEGATION |
		    SMB_ADS_USER_ACCT_CTL_DONT_EXPIRE_PASSWD);
	}

	if (des_only)
		usrctl_flags |= SMB_ADS_USER_ACCT_CTL_USE_DES_KEY_ONLY;

	if (smb_ads_update_computer_cntrl_attr(ah, usrctl_flags, dn)
	    != 0) {
		rc = SMB_ADJOIN_ERR_UPDATE_CNTRL_ATTR;
		goto adjoin_cleanup;
	}

	if (mktemp(tmpfile) == NULL) {
		rc = SMB_ADJOIN_ERR_WRITE_KEYTAB;
		goto adjoin_cleanup;
	}

	encptr = smb_ads_get_enctypes(dclevel, &num);
	if (smb_krb5_kt_populate(ctx, ah->domain, krb5princs, cnt,
	    tmpfile, kvno, machine_passwd, encptr, num) != 0) {
		rc = SMB_ADJOIN_ERR_WRITE_KEYTAB;
		goto adjoin_cleanup;
	}

	delete = B_FALSE;
adjoin_cleanup:
	if (new_acct && delete)
		smb_ads_del_computer(ah, dn);

	if (rc != SMB_ADJOIN_ERR_INIT_KRB_CTX) {
		if (rc != SMB_ADJOIN_ERR_GET_SPNS)
			smb_krb5_free_kprincs(ctx, krb5princs, cnt);
		smb_krb5_ctx_fini(ctx);
	}

	/* commit keytab file */
	if (rc == SMB_ADJOIN_SUCCESS) {
		if (rename(tmpfile, SMBNS_KRB5_KEYTAB) != 0) {
			(void) unlink(tmpfile);
			rc = SMB_ADJOIN_ERR_COMMIT_KEYTAB;
		}
	} else {
		(void) unlink(tmpfile);
	}

	smb_ads_close(ah);
	smb_ccache_remove(SMB_CCACHE_PATH);
	return (rc);
}

/*
 * smb_ads_join_errmsg
 *
 * Display error message for the specific adjoin error code.
 */
void
smb_ads_join_errmsg(smb_adjoin_status_t status)
{
	int i;
	struct xlate_table {
		smb_adjoin_status_t status;
		char *msg;
	} adjoin_table[] = {
		{ SMB_ADJOIN_ERR_GET_HANDLE, "Failed to connect to an "
		    "Active Directory server." },
		{ SMB_ADJOIN_ERR_GEN_PWD, "Failed to generate machine "
		    "password." },
		{ SMB_ADJOIN_ERR_GET_DCLEVEL, "Unknown functional level of "
		    "the domain controller. The rootDSE attribute named "
		    "\"domainControllerFunctionality\" is missing from the "
		    "Active Directory." },
		{ SMB_ADJOIN_ERR_ADD_TRUST_ACCT, "Failed to create the "
		    "workstation trust account." },
		{ SMB_ADJOIN_ERR_MOD_TRUST_ACCT, "Failed to modify the "
		    "workstation trust account." },
		{ SMB_ADJOIN_ERR_DUP_TRUST_ACCT, "Failed to create the "
		    "workstation trust account because its name is already "
		    "in use." },
		{ SMB_ADJOIN_ERR_TRUST_ACCT, "Error in querying the "
		    "workstation trust account" },
		{ SMB_ADJOIN_ERR_INIT_KRB_CTX, "Failed to initialize Kerberos "
		    "context." },
		{ SMB_ADJOIN_ERR_GET_SPNS, "Failed to get Kerberos "
		    "principals." },
		{ SMB_ADJOIN_ERR_KSETPWD, "Failed to set machine password." },
		{ SMB_ADJOIN_ERR_UPDATE_CNTRL_ATTR,  "Failed to modify "
		    "userAccountControl attribute of the workstation trust "
		    "account." },
		{ SMB_ADJOIN_ERR_WRITE_KEYTAB, "Error in writing to local "
		    "keytab file (i.e /etc/krb5/krb5.keytab)." },
		{ SMB_ADJOIN_ERR_IDMAP_SET_DOMAIN, "Failed to update idmap "
		    "configuration." },
		{ SMB_ADJOIN_ERR_IDMAP_REFRESH, "Failed to refresh idmap "
		    "service." },
		{ SMB_ADJOIN_ERR_COMMIT_KEYTAB, "Failed to commit changes to "
		    "local keytab file (i.e. /etc/krb5/krb5.keytab)." }
	};

	for (i = 0; i < sizeof (adjoin_table) / sizeof (adjoin_table[0]); i++) {
		if (adjoin_table[i].status == status)
			syslog(LOG_NOTICE, "%s", adjoin_table[i].msg);
	}
}

/*
 * smb_ads_match_pdc
 *
 * Returns B_TRUE if the given host's IP address matches the preferred DC's
 * IP address. Otherwise, returns B_FALSE.
 */
static boolean_t
smb_ads_match_pdc(smb_ads_host_info_t *host)
{
	boolean_t match = B_FALSE;

	if (!host)
		return (match);

	(void) mutex_lock(&smb_ads_cfg.c_mtx);
	if (smb_inet_equal(&host->ipaddr, &smb_ads_cfg.c_pdc))
		match = B_TRUE;
	(void) mutex_unlock(&smb_ads_cfg.c_mtx);

	return (match);
}

/*
 * smb_ads_select_dcfromsubnet
 *
 * This method walks the list of DCs and returns the first DC record that
 * responds to ldap ping and is in the same subnet as the host.
 *
 * Returns a pointer to the found DC record.
 * Returns NULL, on error or if no DC record is found.
 */
static smb_ads_host_info_t *
smb_ads_select_dcfromsubnet(smb_ads_host_list_t *hlist)
{
	smb_ads_host_info_t *hentry;
	smb_nic_t *lnic;
	smb_niciter_t ni;
	size_t cnt;
	int i;

	if (smb_nic_getfirst(&ni) != SMB_NIC_SUCCESS)
		return (NULL);
	do {
		lnic = &ni.ni_nic;
		cnt = hlist->ah_cnt;

		for (i = 0; i < cnt; i++) {
			hentry = &hlist->ah_list[i];
			if ((hentry->ipaddr.a_family == AF_INET) &&
			    (lnic->nic_ip.a_family == AF_INET)) {
				if ((hentry->ipaddr.a_ipv4 &
				    lnic->nic_mask) ==
				    (lnic->nic_ip.a_ipv4 &
				    lnic->nic_mask))
					if (smb_ads_ldap_ping(hentry) == 0)
						return (hentry);
			}
		}
	} while (smb_nic_getnext(&ni) == SMB_NIC_SUCCESS);

	return (NULL);
}

/*
 * smb_ads_select_dcfromlist
 *
 * This method walks the list of DCs and returns the first DC that
 * responds to ldap ping.
 *
 * Returns a pointer to the found DC record.
 * Returns NULL if no DC record is found.
 */
static smb_ads_host_info_t *
smb_ads_select_dcfromlist(smb_ads_host_list_t *hlist)
{
	smb_ads_host_info_t *hentry;
	size_t cnt;
	int i;

	cnt = hlist->ah_cnt;
	for (i = 0; i < cnt; i++) {
		hentry = &hlist->ah_list[i];
		if (smb_ads_ldap_ping(hentry) == 0)
			return (hentry);
	}

	return (NULL);
}

/*
 * smb_ads_dc_compare
 *
 * Comparision function for sorting host entries (SRV records of DC) via qsort.
 * RFC 2052/2782 are taken as reference, while implementing this algorithm.
 *
 * Domain Controllers(DCs) with lowest priority in their SRV DNS records
 * are selected first. If they have equal priorities, then DC with highest
 * weight in its SRV DNS record is selected. If the priority and weight are
 * both equal, then the DC at the top of the list is selected.
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
 * smb_ads_select_dc
 *
 * The list of ADS hosts returned by ADS lookup, is sorted by lowest priority
 * and highest weight. On this sorted list, following additional rules are
 * applied, to select a DC.
 *
 *  - If there is a DC in the same subnet, then return the DC,
 *    if it responds to ldap ping.
 *  - Else, return first DC that responds to ldap ping.
 *
 * A reference to the host entry from input host list is returned.
 *
 * Returns NULL on error.
 */
static smb_ads_host_info_t *
smb_ads_select_dc(smb_ads_host_list_t *hlist)
{
	smb_ads_host_info_t *hentry = NULL;

	if (hlist->ah_cnt == 0)
		return (NULL);

	if (hlist->ah_cnt == 1) {
		hentry = hlist->ah_list;
		if (smb_ads_ldap_ping(hentry) == 0)
			return (hentry);
	}

	/* Sort the list by priority and weight */
	qsort(hlist->ah_list, hlist->ah_cnt,
	    sizeof (smb_ads_host_info_t), smb_ads_dc_compare);

	if ((hentry = smb_ads_select_dcfromsubnet(hlist)) != NULL)
		return (hentry);

	if ((hentry = smb_ads_select_dcfromlist(hlist)) != NULL)
		return (hentry);

	return (NULL);
}

/*
 * smb_ads_lookup_msdcs
 *
 * If server argument is set, try to locate the specified DC.
 * If it is set to empty string, locate any DCs in the specified domain.
 * Returns the discovered DC via buf.
 *
 * fqdn	  - fully-qualified domain name
 * server - fully-qualifed hostname of a DC
 * buf    - the hostname of the discovered DC
 */
boolean_t
smb_ads_lookup_msdcs(char *fqdn, char *server, char *buf, uint32_t buflen)
{
	smb_ads_host_info_t *hinfo = NULL;
	char *p;
	char *sought_host;
	char ipstr[INET6_ADDRSTRLEN];

	if (!fqdn || !buf)
		return (B_FALSE);

	ipstr[0] = '\0';
	*buf = '\0';
	sought_host = (*server == 0 ? NULL : server);
	if ((hinfo = smb_ads_find_host(fqdn, sought_host)) == NULL)
		return (B_FALSE);

	(void) smb_inet_ntop(&hinfo->ipaddr, ipstr,
	    SMB_IPSTRLEN(hinfo->ipaddr.a_family));
	smb_tracef("msdcsLookupADS: %s [%s]", hinfo->name, ipstr);

	(void) strlcpy(buf, hinfo->name, buflen);
	/*
	 * Remove the domain extension
	 */
	if ((p = strchr(buf, '.')) != 0)
		*p = '\0';

	free(hinfo);
	return (B_TRUE);
}

static krb5_enctype *
smb_ads_get_enctypes(int dclevel, int *num)
{
	krb5_enctype *encptr;

	if (dclevel >= SMB_ADS_DCLEVEL_W2K8) {
		*num = sizeof (w2k8enctypes) / sizeof (krb5_enctype);
		encptr = w2k8enctypes;
	} else {
		*num = sizeof (pre_w2k8enctypes) / sizeof (krb5_enctype);
		encptr = pre_w2k8enctypes;
	}

	return (encptr);
}
