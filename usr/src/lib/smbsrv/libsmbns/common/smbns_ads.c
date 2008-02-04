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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

#define	ADS_DN_MAX	300
#define	ADS_MAXMSGLEN 512
#define	ADS_HOST_PREFIX "host/"
#define	ADS_COMPUTERS_CN "Computers"
#define	ADS_COMPUTER_NUM_ATTR 7
#define	ADS_SHARE_NUM_ATTR 3
#define	ADS_SITE_MAX MAXHOSTNAMELEN

/* current ADS server to communicate with */
ADS_HOST_INFO *ads_host_info = NULL;
mutex_t ads_host_mtx;
char ads_site[ADS_SITE_MAX];
mutex_t ads_site_mtx;


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
	"ADJOIN failed to get host principal.",
	"ADJOIN failed to initialize kerberos context.",
	"ADJOIN failed to get Kerberos principal.",
	"ADJOIN failed to set machine account password on AD.",
	"ADJOIN failed to modify CONTROL attribute of the account.",
	"ADJOIN failed to write Kerberos keytab file.",
	"ADJOIN failed to configure domain_name property for idmapd.",
	"ADJOIN failed to refresh idmap service."
	"ADJOIN failed to refresh SMB service."
};

static ADS_HANDLE *ads_open_main(char *domain, char *user, char *password);
static int ads_bind(ADS_HANDLE *);
static void ads_get_computer_dn(ADS_HANDLE *, char *, size_t);
static char *ads_get_host_principal(char *fqhost);
static char *ads_get_host_principal_w_realm(char *princ, char *domain);
static int ads_get_host_principals(char *fqhost, char *domain,
    char **princ, char **princ_r);
static int ads_add_computer(ADS_HANDLE *ah);
static int ads_modify_computer(ADS_HANDLE *ah);
static void ads_del_computer(ADS_HANDLE *ah);
static int ads_computer_op(ADS_HANDLE *ah, int op);
static int ads_lookup_computer_n_attr(ADS_HANDLE *ah, char *attr, char **val);
static int ads_update_computer_cntrl_attr(ADS_HANDLE *ah, int des_only);
static krb5_kvno ads_lookup_computer_attr_kvno(ADS_HANDLE *ah);
static int ads_gen_machine_passwd(char *machine_passwd, int bufsz);
static ADS_HOST_INFO *ads_get_host_info(void);
static void ads_set_host_info(ADS_HOST_INFO *host);
static void ads_free_host_info(void);

/*
 * ads_init
 *
 * Initializes the ads_site global variable.
 */
void
ads_init(void)
{
	(void) mutex_lock(&ads_site_mtx);
	(void) smb_config_getstr(SMB_CI_ADS_SITE, ads_site, sizeof (ads_site));
	(void) mutex_unlock(&ads_site_mtx);
}

/*
 * ads_refresh
 *
 * If the ads_site has changed, clear the ads_host_info cache.
 */
void
ads_refresh(void)
{
	char new_site[ADS_SITE_MAX];

	(void) smb_config_getstr(SMB_CI_ADS_SITE, new_site, sizeof (new_site));
	(void) mutex_lock(&ads_site_mtx);
	if (strcasecmp(ads_site, new_site)) {
		(void) strlcpy(ads_site, new_site, sizeof (ads_site));
		ads_free_host_info();
	}
	(void) mutex_unlock(&ads_site_mtx);
}

/*
 * ads_build_unc_name
 *
 * Construct the UNC name of the share object in the format of
 * \\hostname.domain\shareUNC
 *
 * Returns 0 on success, -1 on error.
 */
int
ads_build_unc_name(char *unc_name, int maxlen,
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
 * ads_skip_domain_name
 * Skip domain name format in DNS message.  The format is a sequence of
 * ascii labels with each label having a length byte at the beginning.
 * The domain name is terminated with a NULL character.
 * i.e. 3sun3com0
 * Parameters:
 *   bufptr: address of pointer of buffer that contains domain name
 * Returns:
 *   bufptr: points to the data after the domain name label
 */
static void
ads_skip_domain_name(char **bufptr)
{
	int i = 0;
	unsigned char c, d;

	c = (*bufptr)[i++];
	d = c & 0xC0;
	while (c != 0 && (d != 0xC0)) {	/* do nothing */
		c = (*bufptr)[i++];
		d = c & 0xC0;
	}

	if (d == 0xC0)
		/* skip 2nd byte in 2 byte ptr info */
		i++;
	*bufptr += i;
}

static int
ads_is_ptr(char *buf, int len, char *offset_ptr, char **new_loc)
{
	uint16_t offset;
	unsigned char c;

	c = len & 0xC0;
	if (c == 0xC0) {
		offset_ptr = dyndns_get_nshort(offset_ptr, &offset);
		offset &= 0x3FFF;
		if (offset > NS_PACKETSZ) {
			return (-1);
		}
		*new_loc = buf + offset;
		return (1);
	}
	return (0);
}

/*
 * ads_get_domain_name
 * Converts the domain name format in DNS message back to string format.
 * The format is a sequence of ascii labels with each label having a length
 * byte at the beginning.  The domain name is terminated with a NULL
 * character.
 * i.e. 6procom3com0 -> procom.com
 * Parameters:
 *   bufptr   : address of pointer to buffer that contains domain name
 *   dname_len: length of domain name in label format
 * Returns:
 *   NULL       : error
 *   domain name: in string format using allocated memory
 *   bufptr     : points to the data after the domain name label
 */
static char *
ads_get_domain_name(char *buf, char **bufptr)
{
	char str[256], *ptr, *new_loc;
	int i, j, k, len, ret;
	int skip = 0;
	i = 0;
	k = 0;
	ptr = *bufptr;

	/* get len of first label */
	len = ptr[i++];
	if ((ret = ads_is_ptr(buf, len, &ptr[i-1], &new_loc)) == 1) {
		if (skip == 0) {
			/* skip up to first ptr */
			skip = i;
		}

		i = 0;
		ptr = new_loc;

		/* get len of first label */
		len = ptr[i++];
	} else {
		if (ret == -1) {
			return (NULL);
		}
	}

	while (len) {
		if ((len > 63) || (k >= 255))
			return (NULL);

		for (j = 0; j < len; j++)
			str[k++] = ptr[i++];

		/* get len of next label */
		len = ptr[i++];
		if ((ret = ads_is_ptr(buf, len, &ptr[i-1], &new_loc)) == 1) {
			if (skip == 0) {
				/* skip up to first ptr */
				skip = i;
			}
			i = 0;
			ptr = new_loc;

			/* get len of first label */
			len = ptr[i++];
		} else if (ret == -1) {
			return (NULL);
		}

		if (len) {
			/* replace label len or ptr with '.' */
			str[k++] = '.';
		}
	}

	str[k] = 0;

	if (skip) {
		/* skip name with ptr or just ptr */
		*bufptr += skip + 1;
	} else {
		/* skip name */
		*bufptr += i;
	}

	return (strdup(str));
}

/*
 * ads_ping
 * Ping IP without displaying log.  This is used to ping an ADS server to see
 * if it is still alive before connecting to it with TCP.
 * Taken from os/service/ping.c
 * Parameters:
 *   hostinetaddr: 4 bytes IP address in network byte order
 * Returns:
 *   -1: error
 *    0: successful
 */
/*ARGSUSED*/
static int
ads_ping(unsigned long hostinetaddr)
{
	return (0);
}

/*
 * ads_free_host_list
 */
static void
ads_free_host_list(ADS_HOST_INFO *host_list, int count)
{
	int i;
	for (i = 0; i < count; i++) {
		free(host_list[i].name);
	}
	free(host_list);
}

/*
 * ads_set_host_info
 * Cache the result of the ADS discovery if the cache is empty.
 */
static void
ads_set_host_info(ADS_HOST_INFO *host)
{
	(void) mutex_lock(&ads_host_mtx);
	if (!ads_host_info)
		ads_host_info = host;
	(void) mutex_unlock(&ads_host_mtx);
}

/*
 * ads_get_host_info
 * Get the cached ADS host info.
 */
static ADS_HOST_INFO *
ads_get_host_info(void)
{
	ADS_HOST_INFO *host;

	(void) mutex_lock(&ads_host_mtx);
	host = ads_host_info;
	(void) mutex_unlock(&ads_host_mtx);
	return (host);
}
/*
 * ads_find_host
 * This routine builds a DNS service location message and sends it to the
 * DNS server via UDP to query it for a list of ADS server(s).  Once a reply
 * is received, the reply message is parsed to get the hostname and IP
 * addresses of the ADS server(s).  One ADS server will be selected from the
 * list.  A ping is sent to each host at a time and the one that respond will
 * be selected.
 *
 * The service location of _ldap._tcp.dc.msdcs.<ADS domain> is used to
 * guarantee that Microsoft domain controllers are returned.  Microsoft domain
 * controllers are also ADS servers.
 *
 * The ADS hostnames are stored in the answer section of the DNS reply message.
 * The IP addresses are stored in the additional section.  If the additional
 * section does not contain any IP addresses then a DNS query by hostname is
 * sent to get the IP address of the hostname.  This is very unlikely.
 *
 * The DNS reply message may be in compress formed.  The compression is done
 * on repeating domain name label in the message.  i.e hostname.
 * Parameters:
 *   ns: Nameserver to use to find the ADS host
 *   domain: domain of ADS host.
 * Returns:
 *   ADS host: fully qualified hostname, ip address, ldap port
 *   port    : LDAP port of ADS host
 */
/*ARGSUSED*/
ADS_HOST_INFO *
ads_find_host(char *ns, char *domain, int *port, char *service, int *go_next)
{
	int s;
	uint16_t id, rid, data_len, eport;
	int ipaddr;
	char buf[NS_PACKETSZ], buf2[NS_PACKETSZ];
	char *bufptr, *str;
	int i, ret;
	int queryReq;
	uint16_t query_cnt, ans_cnt, namser_cnt, addit_cnt;
	int quest_type, quest_class;
	int dns_ip;
	struct in_addr addr;
	uint16_t flags = 0;
	int force_recurs = 0;
	ADS_HOST_INFO *ads_hosts_list = NULL, *ads_host;
	ADS_HOST_INFO *ads_hosts_list2 = NULL;

	*go_next = 0;

	/*
	 * If we have already found an ADS server, skip the ads_find_host
	 * process. Returns the ADS host from the cache.
	 */
	ads_host = ads_get_host_info();
	if (ads_host)
		return (ads_host);

	if (ns == NULL || *ns == 0) {
		return (NULL);
	}
	dns_ip = inet_addr(ns);

	if ((s = dyndns_open_init_socket(SOCK_DGRAM, dns_ip, 53)) < 0)
		return (NULL);

retry:
	/* build query request */
	queryReq = REQ_QUERY;
	query_cnt = 1;
	ans_cnt = 0;
	namser_cnt = 0;
	addit_cnt = 0;

	(void) memset(buf, 0, NS_PACKETSZ);
	bufptr = buf;
	id = dns_get_msgid();
	if (dyndns_build_header(&bufptr, BUFLEN_UDP(bufptr, buf), id, queryReq,
	    query_cnt, ans_cnt, namser_cnt, addit_cnt, flags) == -1) {
		(void) close(s);
		return (NULL);
	}

	quest_type = ns_t_srv;
	quest_class = ns_c_in;

	if (dyndns_build_quest_zone(&bufptr, BUFLEN_UDP(bufptr, buf), service,
	    quest_type, quest_class) == -1) {
		(void) close(s);
		return (NULL);
	}

	if (dyndns_udp_send_recv(s, buf, bufptr - buf, buf2) == -1) {
		(void) close(s);
		syslog(LOG_ERR, "smb_ads: send/receive error");
		*go_next = 1;
		return (NULL);
	}
	(void) close(s);

	(void) dyndns_get_nshort(buf2, &rid);
	if (id != rid)
		return (NULL);

	/*
	 * check if query is successful by checking error
	 * field in UDP
	 */
	ret = buf2[3] & 0xf;
	if (ret != NOERROR) {
		syslog(LOG_ERR, "smb_ads: DNS query for ADS host error: %d: ",
		    ret);
		dyndns_msg_err(ret);
		*go_next = 1;
		return (NULL);
	}

	bufptr = buf2;
	bufptr += 2;		/* Skip ID section */
	bufptr = dyndns_get_nshort(bufptr, &flags);
	bufptr = dyndns_get_nshort(bufptr, &query_cnt);
	bufptr = dyndns_get_nshort(bufptr, &ans_cnt);
	bufptr = dyndns_get_nshort(bufptr, &namser_cnt);
	bufptr = dyndns_get_nshort(bufptr, &addit_cnt);

	if (ans_cnt == 0) {
		/* Check if the server supports recursive queries */
		if (force_recurs++ == 0 && (flags & DNSF_RECUR_SUPP) != 0) {
			flags = DNSF_RECUR_QRY;
			goto retry;
		}

		syslog(LOG_DEBUG, "smb_ads: No ADS host found: "
		    "No answer section\n");
		return (NULL);
	}

	/* skip question section */
	if (query_cnt == 1) {
		ads_skip_domain_name(&bufptr);
		bufptr += 4;
	} else {
		syslog(LOG_ERR, "smb_ads: No ADS host found, malformed "
		    "question section, query_cnt: %d???\n", query_cnt);
		return (NULL);
	}

	ads_hosts_list = (ADS_HOST_INFO *)
	    malloc(sizeof (ADS_HOST_INFO)*ans_cnt);
	if (ads_hosts_list == NULL)
		return (NULL);

	bzero(ads_hosts_list, sizeof (ADS_HOST_INFO) * ans_cnt);

	/* check answer section */
	for (i = 0; i < ans_cnt; i++) {
		ads_skip_domain_name(&bufptr);

		/* skip type, class, ttl */
		bufptr += 8;

		/* len of data after this point */
		bufptr = dyndns_get_nshort(bufptr, &data_len);

		/* skip priority, weight */
		bufptr += 4;
		bufptr = dyndns_get_nshort(bufptr, &eport);
		ads_hosts_list[i].port = eport;

		if ((str = ads_get_domain_name(buf2, &bufptr)) == NULL) {
			syslog(LOG_ERR, "smb_ads: No ADS host found, "
			    "error decoding DNS answer section\n");
			ads_free_host_list(ads_hosts_list, ans_cnt);
			return (NULL);
		}
		ads_hosts_list[i].name = str;
	}

	/* check authority section */
	for (i = 0; i < namser_cnt; i++) {
		ads_skip_domain_name(&bufptr);

		/* skip type, class, ttl */
		bufptr += 8;

		/* get len of data */
		bufptr = dyndns_get_nshort(bufptr, &data_len);

		/* skip data */
		bufptr += data_len;
	}

	/* check additional section to get IP address of ads host */
	if (addit_cnt > 0) {
		int j;

		ads_hosts_list2 = (ADS_HOST_INFO *)
		    malloc(sizeof (ADS_HOST_INFO) * addit_cnt);
		if (ads_hosts_list2 == NULL) {
			ads_free_host_list(ads_hosts_list, ans_cnt);
			return (NULL);
		}

		bzero(ads_hosts_list2, sizeof (ADS_HOST_INFO) * addit_cnt);

		for (i = 0; i < addit_cnt; i++) {

			if ((str = ads_get_domain_name(buf2,
			    &bufptr)) == NULL) {
				syslog(LOG_ERR, "smb_ads: No ADS host found, "
				    "error decoding DNS additional section\n");
				ads_free_host_list(ads_hosts_list, ans_cnt);
				ads_free_host_list(ads_hosts_list2, addit_cnt);
				return (NULL);
			}

			ads_hosts_list2[i].name = str;
			bufptr += 10;
			bufptr = dyndns_get_int(bufptr, &ipaddr);
			ads_hosts_list2[i].ip_addr = ipaddr;
		}

		/* pick a host that is up */
		for (i = 0; i < addit_cnt; i++) {
			if (ads_ping(ads_hosts_list2[i].ip_addr) != 0) {
				continue;
			}
			for (j = 0; j < ans_cnt; j++)
				if (strcmp(ads_hosts_list2[i].name,
				    ads_hosts_list[j].name) == 0)
					break;
			if (j == ans_cnt) {
				ads_free_host_list(ads_hosts_list, ans_cnt);
				ads_free_host_list(ads_hosts_list2, addit_cnt);
				return (NULL);
			}
			ads_host = (ADS_HOST_INFO *)
			    malloc(sizeof (ADS_HOST_INFO));
			if (ads_host == NULL) {
				ads_free_host_list(ads_hosts_list, ans_cnt);
				ads_free_host_list(ads_hosts_list2, addit_cnt);
				return (NULL);
			}
			bzero(ads_host, sizeof (ADS_HOST_INFO));
			ads_host->name = strdup(ads_hosts_list[j].name);
			if (ads_host->name == NULL) {
				ads_free_host_list(ads_hosts_list, ans_cnt);
				ads_free_host_list(ads_hosts_list2, addit_cnt);
				return (NULL);
			}
			ads_host->ip_addr = ads_hosts_list2[i].ip_addr;
			ads_host->port = ads_hosts_list[j].port;
			*port = ads_host->port;
			addr.s_addr = ads_host->ip_addr;
			syslog(LOG_DEBUG, "smb_ads: Found ADS server: %s (%s)"
			    " from %s\n", ads_host->name, inet_ntoa(addr), ns);
			ads_free_host_list(ads_hosts_list, ans_cnt);
			ads_free_host_list(ads_hosts_list2, addit_cnt);
			ads_set_host_info(ads_host);
			return (ads_host);
		}
		ads_free_host_list(ads_hosts_list2, addit_cnt);
	}

	syslog(LOG_ERR, "smb_ads: Can't get IP for "
	    "ADS host or ADS host is down.\n");
	ads_free_host_list(ads_hosts_list, ans_cnt);

	*go_next = 1;
	return (NULL);
}

/*
 * ads_convert_domain
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
ads_convert_domain(char *s)
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
				syslog(LOG_ERR, "[ads_convert_domain] "
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
				syslog(LOG_ERR, "[ads_convert_domain] "
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
 * ads_free_host_info
 * Free the memory use by the global ads_host_info and set it to NULL.
 */
static void
ads_free_host_info(void)
{
	(void) mutex_lock(&ads_host_mtx);
	if (ads_host_info) {
		free(ads_host_info->name);
		free(ads_host_info);
		ads_host_info = NULL;
	}
	(void) mutex_unlock(&ads_host_mtx);
}

/*
 * ads_open
 * Open a LDAP connection to an ADS server if the system is in domain mode.
 * Acquire both Kerberos TGT and LDAP service tickets for the host principal.
 *
 * This function should only be called after the system is successfully joined
 * to a domain.
 */
ADS_HANDLE *
ads_open(void)
{
	char domain[MAXHOSTNAMELEN];

	if (smb_config_get_secmode() != SMB_SECMODE_DOMAIN)
		return (NULL);

	if (smb_getfqdomainname(domain, MAXHOSTNAMELEN) != 0)
		return (NULL);

	return (ads_open_main(domain, NULL, NULL));
}

/*
 * ads_open_main
 * Open a LDAP connection to an ADS server.
 * If ADS is enabled and the administrative username, password, and
 * ADS domain are defined then query DNS to find an ADS server if this is the
 * very first call to this routine.  After an ADS server is found then this
 * server will be used everytime this routine is called until the system is
 * rebooted or the ADS server becomes unavailable then an ADS server will
 * be queried again.  The ADS server is always ping before an LDAP connection
 * is made to it.  If the pings fail then DNS is used once more to find an
 * available ADS server.  If the ping is successful then an LDAP connection
 * is made to the ADS server.  After the connection is made then an ADS handle
 * is created to be returned.
 *
 * After the LDAP connection, the LDAP version will be set to 3 using
 * ldap_set_option().
 *
 * The ads_bind() routine is also called before the ADS handle is returned.
 * Parameters:
 *   domain - fully-qualified domain name
 *   user   - the user account for whom the Kerberos TGT ticket and ADS
 *            service tickets are acquired.
 *   password - password of the specified user
 *
 * Returns:
 *   NULL        : can't connect to ADS server or other errors
 *   ADS_HANDLE* : handle to ADS server
 */
static ADS_HANDLE *
ads_open_main(char *domain, char *user, char *password)
{
	ADS_HANDLE *ah;
	LDAP *ld;
	int version = 3, ads_port, find_ads_retry;
	ADS_HOST_INFO *ads_host = NULL;
	struct in_addr addr;
	char site[ADS_SITE_MAX];
	char service[MAXHOSTNAMELEN];
	char site_service[MAXHOSTNAMELEN];
	struct in_addr ns_list[MAXNS];
	int i, cnt, go_next;


	(void) mutex_lock(&ads_site_mtx);
	(void) strlcpy(site, ads_site, sizeof (site));
	(void) mutex_unlock(&ads_site_mtx);

	find_ads_retry = 0;
find_ads_host:

	ads_host = ads_get_host_info();
	if (!ads_host) {
		if (*site != '\0') {
			(void) snprintf(site_service, sizeof (site_service),
			    "_ldap._tcp.%s._sites.dc._msdcs.%s", site, domain);
		} else {
			*site_service = '\0';
		}
		(void) snprintf(service, sizeof (service),
		    "_ldap._tcp.dc._msdcs.%s", domain);

		cnt = smb_get_nameservers(ns_list, MAXNS);

		ads_host = NULL;
		go_next = 0;
		for (i = 0; i < cnt; i++) {
			if (*site_service != '\0') {
				ads_host = ads_find_host(inet_ntoa(ns_list[i]),
				    domain, &ads_port, site_service, &go_next);
			}
			if (ads_host == NULL) {
				ads_host = ads_find_host(inet_ntoa(ns_list[i]),
				    domain, &ads_port, service, &go_next);
			}
			if (ads_host != NULL)
				break;
			if (go_next == 0)
				break;
		}
	}

	if (ads_host == NULL) {
		syslog(LOG_ERR, "smb_ads: No ADS host found from "
		    "configured nameservers");
		return (NULL);
	}

	if (ads_ping(ads_host->ip_addr) != 0) {
		ads_free_host_info();
		ads_host = NULL;
		if (find_ads_retry == 0) {
			find_ads_retry = 1;
			goto find_ads_host;
		}
		return (NULL);
	}

	ah = (ADS_HANDLE *)malloc(sizeof (ADS_HANDLE));
	if (ah == NULL) {
		return (NULL);
	}
	(void) memset(ah, 0, sizeof (ADS_HANDLE));

	addr.s_addr = ads_host->ip_addr;
	if ((ld = ldap_init((char *)inet_ntoa(addr), ads_host->port)) == NULL) {
		syslog(LOG_ERR, "smb_ads: Could not open connection "
		    "to host: %s\n", ads_host->name);
		ads_free_host_info();
		ads_host = NULL;
		free(ah);
		if (find_ads_retry == 0) {
			find_ads_retry = 1;
			goto find_ads_host;
		}
		return (NULL);
	}

	if (ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version)
	    != LDAP_SUCCESS) {
		syslog(LOG_ERR, "smb_ads: Could not set "
		    "LDAP_OPT_PROTOCOL_VERSION %d\n", version);
		ads_free_host_info();
		free(ah);
		(void) ldap_unbind(ld);
		return (NULL);
	}

	ah->ld = ld;
	ah->user = (user) ? strdup(user) : NULL;
	ah->pwd = (password) ? strdup(password) : NULL;
	ah->domain = strdup(domain);

	if (ah->domain == NULL) {
		ads_close(ah);
		return (NULL);
	}

	ah->domain_dn = ads_convert_domain(domain);
	if (ah->domain_dn == NULL) {
		ads_close(ah);
		return (NULL);
	}

	ah->hostname = strdup(ads_host->name);
	if (ah->hostname == NULL) {
		ads_close(ah);
		return (NULL);
	}
	if (site) {
		ah->site = strdup(site);
		if (ah->site == NULL) {
			ads_close(ah);
			return (NULL);
		}
	} else {
		ah->site = NULL;
	}

	if (ads_bind(ah) == -1) {
		ads_close(ah);
		return (NULL);
	}

	return (ah);
}

/*
 * ads_close
 * Close connection to ADS server and free memory allocated for ADS handle.
 * LDAP unbind is called here.
 * Parameters:
 *   ah: handle to ADS server
 * Returns:
 *   void
 */
void
ads_close(ADS_HANDLE *ah)
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
 * ads_display_stat
 * Display error message for GSS-API routines.
 * Parameters:
 *   maj:  GSS major status
 *   min:  GSS minor status
 * Returns:
 *   None
 */
static void
ads_display_stat(OM_uint32 maj, OM_uint32 min)
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
 * free_attr
 * Free memory allocated when publishing a share.
 * Parameters:
 *   attrs: an array of LDAPMod pointers
 * Returns:
 *   None
 */
static void
free_attr(LDAPMod *attrs[])
{
	int i;
	for (i = 0; attrs[i]; i++) {
		free(attrs[i]);
	}
}

/*
 * ads_acquire_cred
 * Called by ads_bind() to get a handle to administrative user's credential
 * stored locally on the system.  The credential is the TGT.  If the attempt at
 * getting handle fails then a second attempt will be made after getting a
 * new TGT.
 * Please look at ads_bind() for more information.
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
ads_acquire_cred(ADS_HANDLE *ah, gss_cred_id_t *cred_handle, gss_OID *oid,
	int *kinit_retry)
{
	return (krb5_acquire_cred_kinit(ah->user, ah->pwd, cred_handle, oid,
	    kinit_retry, "ads"));
}

/*
 * ads_establish_sec_context
 * Called by ads_bind() to establish a security context to an LDAP service on
 * an ADS server. If the attempt at establishing the security context fails
 * then a second attempt will be made by ads_bind() if a new TGT has not been
 * already obtained in ads_acquire_cred.  The second attempt, if allowed, will
 * obtained a new TGT here and a new handle to the credential will also be
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
ads_establish_sec_context(ADS_HANDLE *ah, gss_ctx_id_t *gss_context,
    gss_cred_id_t cred_handle, gss_OID oid, struct berval **sercred,
    int *kinit_retry, int *do_acquire_cred)
{
	OM_uint32 maj, min, time_rec;
	char service_name[ADS_MAXBUFLEN];
	gss_buffer_desc send_tok, service_buf;
	gss_name_t target_name;
	gss_buffer_desc input;
	gss_buffer_desc *inputptr;
	struct berval cred;
	OM_uint32 ret_flags;
	int stat;
	int gss_flags;

	(void) snprintf(service_name, ADS_MAXBUFLEN, "ldap@%s", ah->hostname);
	service_buf.value = service_name;
	service_buf.length = strlen(service_name)+1;
	if ((maj = gss_import_name(&min, &service_buf,
	    (gss_OID) gss_nt_service_name,
	    &target_name)) != GSS_S_COMPLETE) {
		ads_display_stat(maj, min);
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
 * ads_negotiate_sec_layer
 * Call by ads_bind() to negotiate additional security layer for further
 * communication after security context establishment.  No additional security
 * is needed so a "no security layer" is negotiated.  The security layer is
 * described in the SASL RFC 2478 and this step is needed for secure LDAP
 * binding.  LDAP SASL bind is used to send and receive the GSS tokens to and
 * from the ADS server.
 * Please look at ads_bind for more information.
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
ads_negotiate_sec_layer(ADS_HANDLE *ah, gss_ctx_id_t gss_context,
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
		ads_display_stat(maj, min);
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
		ads_display_stat(maj, min);
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
 * ads_bind
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
ads_bind(ADS_HANDLE *ah)
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

	if (ads_acquire_cred(ah, &cred_handle, &oid, &kinit_retry))
		return (-1);

	if (ads_establish_sec_context(ah, &gss_context, cred_handle,
	    oid, &sercred, &kinit_retry, &do_acquire_cred)) {
		(void) gss_release_cred(&min, &cred_handle);
		if (do_acquire_cred) {
			do_acquire_cred = 0;
			goto acquire_cred;
		}
		return (-1);
	}
	rc = ads_negotiate_sec_layer(ah, gss_context, sercred);

	if (cred_handle != GSS_C_NO_CREDENTIAL)
		(void) gss_release_cred(&min, &cred_handle);
	(void) gss_delete_sec_context(&min, &gss_context, NULL);

	return ((rc) ? -1 : 0);
}

/*
 * ads_add_share
 * Call by ads_publish_share to create share object in ADS.
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
ads_add_share(ADS_HANDLE *ah, const char *adsShareName,
    const char *unc_name, const char *adsContainer)
{
	LDAPMod *attrs[ADS_SHARE_NUM_ATTR];
	char *tmp1[5], *tmp2[5];
	int j = 0;
	char *share_dn;
	char buf[ADS_MAXMSGLEN];
	int len, ret;

	len = 5 + strlen(adsShareName) + strlen(adsContainer) +
	    strlen(ah->domain_dn) + 1;

	share_dn = (char *)malloc(len);
	if (share_dn == NULL)
		return (-1);

	(void) snprintf(share_dn, len, "cn=%s,%s,%s", adsShareName,
	    adsContainer, ah->domain_dn);

	for (j = 0; j < (ADS_SHARE_NUM_ATTR - 1); j++) {
		attrs[j] = (LDAPMod *)malloc(sizeof (LDAPMod));
		if (attrs[j] == NULL) {
			free_attr(attrs);
			free(share_dn);
			return (-1);
		}
	}

	j = 0;
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

	attrs[++j] = 0;

	if ((ret = ldap_add_s(ah->ld, share_dn, attrs)) != LDAP_SUCCESS) {
		(void) snprintf(buf, ADS_MAXMSGLEN,
		    "ads_add_share: %s:", share_dn);
		/* LINTED - E_SEC_PRINTF_VAR_FMT */
		syslog(LOG_ERR, ldap_err2string(ret));
		free_attr(attrs);
		free(share_dn);
		return (ret);
	}
	free(share_dn);
	free_attr(attrs);

	(void) snprintf(buf, ADS_MAXMSGLEN,
	    "Share %s has been added to ADS container: %s.\n", adsShareName,
	    adsContainer);
	syslog(LOG_DEBUG, "smb_ads: %s", buf);

	return (0);
}

/*
 * ads_del_share
 * Call by ads_remove_share to remove share object from ADS.  The container
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
ads_del_share(ADS_HANDLE *ah, const char *adsShareName,
    const char *adsContainer)
{
	char *share_dn, buf[ADS_MAXMSGLEN];
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

	(void) snprintf(buf, ADS_MAXMSGLEN,
	    "Share %s has been removed from ADS container: %s.\n",
	    adsShareName, adsContainer);
	syslog(LOG_DEBUG, "smb_ads: %s", buf);

	return (0);
}


/*
 * ads_escape_search_filter_chars
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
ads_escape_search_filter_chars(const char *src, char *dst)
{
	int avail = ADS_MAXBUFLEN - 1; /* reserve a space for NULL char */

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
 * ads_lookup_share
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
ads_lookup_share(ADS_HANDLE *ah, const char *adsShareName,
    const char *adsContainer, char *unc_name)
{
	char *attrs[4], filter[ADS_MAXBUFLEN];
	char *share_dn;
	int len, ret;
	LDAPMessage *res;
	char tmpbuf[ADS_MAXBUFLEN];

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

	if (ads_escape_search_filter_chars(unc_name, tmpbuf) != 0) {
		free(share_dn);
		return (-1);
	}

	(void) snprintf(filter, sizeof (filter),
	    "(&(objectClass=volume)(uNCName=%s))", tmpbuf);

	if ((ret = ldap_search_s(ah->ld, share_dn,
	    LDAP_SCOPE_BASE, filter, attrs, 0, &res)) != LDAP_SUCCESS) {
		/* LINTED - E_SEC_PRINTF_VAR_FMT */
		syslog(LOG_ERR, ldap_err2string(ret));
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
 * ads_convert_directory
 * Convert relative share directory to UNC to be appended to hostname.
 * i.e. cvol/a/b -> cvol\a\b
 */
char *
ads_convert_directory(char *rel_dir)
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
 * ads_publish_share
 * Publish share into ADS.  If a share name already exist in ADS in the same
 * container then the existing share object is removed before adding the new
 * share object.
 * Parameters:
 *   ah          : handle return from ads_open
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
ads_publish_share(ADS_HANDLE *ah, const char *adsShareName,
    const char *shareUNC, const char *adsContainer, const char *hostname)
{
	int ret;
	char unc_name[ADS_MAXBUFLEN];

	if (adsShareName == NULL || adsContainer == NULL)
		return (-1);

	if (shareUNC == 0 || *shareUNC == 0)
		shareUNC = adsShareName;

	if (ads_build_unc_name(unc_name, sizeof (unc_name),
	    hostname, shareUNC) < 0) {
		syslog(LOG_DEBUG, "smb_ads: Cannot publish share '%s' "
		    "[missing UNC name]", shareUNC);
		return (-1);
	}

	ret = ads_lookup_share(ah, adsShareName, adsContainer, unc_name);

	switch (ret) {
	case 1:
		(void) ads_del_share(ah, adsShareName, adsContainer);
		ret = ads_add_share(ah, adsShareName, unc_name, adsContainer);
		break;

	case 0:
		ret = ads_add_share(ah, adsShareName, unc_name, adsContainer);
		if (ret == LDAP_ALREADY_EXISTS) {
			syslog(LOG_DEBUG, "smb_ads: Cannot publish share '%s' "
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
 * ads_remove_share
 * Remove share from ADS.  A search is done first before explicitly removing
 * the share.
 * Parameters:
 *   ah          : handle return from ads_open
 *   adsShareName: name of share to be removed from ADS directory
 *   adsContainer: location for share to be removed from ADS directory, ie
 *                   ou=share_folder
 * Returns:
 *   -1          : error
 *    0          : success
 */
int
ads_remove_share(ADS_HANDLE *ah, const char *adsShareName, const char *shareUNC,
    const char *adsContainer, const char *hostname)
{
	int ret;
	char unc_name[ADS_MAXBUFLEN];

	if (adsShareName == NULL || adsContainer == NULL)
		return (-1);
	if (shareUNC == 0 || *shareUNC == 0)
		shareUNC = adsShareName;

	if (ads_build_unc_name(unc_name, sizeof (unc_name),
	    hostname, shareUNC) < 0) {
		syslog(LOG_DEBUG, "smb_ads: Unable to remove share '%s' from "
		    "ADS [missing UNC name]", shareUNC);
		return (-1);
	}

	ret = ads_lookup_share(ah, adsShareName, adsContainer, unc_name);
	if (ret == 0)
		return (0);
	if (ret == -1)
		return (-1);

	return (ads_del_share(ah, adsShareName, adsContainer));
}

/*
 * ads_get_computer_dn
 *
 * Build the distinguish name for this system.
 */
static void
ads_get_computer_dn(ADS_HANDLE *ah, char *buf, size_t buflen)
{
	char hostname[MAXHOSTNAMELEN];

	(void) smb_gethostname(hostname, MAXHOSTNAMELEN, 0);
	(void) snprintf(buf, buflen, "cn=%s,cn=%s,%s",
	    hostname, ADS_COMPUTERS_CN, ah->domain_dn);
}

static char *
ads_get_host_principal(char *fqhost)
{
	int len;
	char *princ;

	if (!fqhost)
		return (NULL);

	len = strlen(ADS_HOST_PREFIX) + strlen(fqhost) + 1;
	princ = (char *)malloc(len);

	if (!princ) {
		syslog(LOG_ERR, "ads_get_host_principal: resource shortage");
		return (NULL);
	}
	(void) snprintf(princ, len, "%s%s", ADS_HOST_PREFIX,
	    fqhost);

	return (princ);
}

static char *
ads_get_host_principal_w_realm(char *princ, char *domain)
{
	int len;
	char *realm;
	char *princ_r;

	if (!princ || !domain)
		return (NULL);

	realm = strdup(domain);
	if (!realm)
		return (NULL);

	(void) utf8_strupr(realm);

	len = strlen(princ) + 1 + strlen(realm) + 1;
	princ_r = (char *)malloc(len);
	if (!princ_r) {
		syslog(LOG_ERR, "ads_get_host_principal_w_realm: resource"
		    " shortage");
		free(realm);
		return (NULL);
	}

	(void) snprintf(princ_r, len, "%s@%s", princ, realm);
	free(realm);

	return (princ_r);
}

/*
 * ads_get_host_principals
 *
 * If fqhost is NULL, this function will attempt to obtain fully qualified
 * hostname prior to generating the host principals. If caller is not
 * interested in getting the principal name without the Kerberos realm
 * info, princ can be set to NULL.
 */
static int
ads_get_host_principals(char *fqhost, char *domain, char **princ,
    char **princ_r)
{
	char hostname[MAXHOSTNAMELEN];
	char *p;

	if (princ != NULL)
		*princ = NULL;

	*princ_r = NULL;

	if (fqhost) {
		(void) strlcpy(hostname, fqhost, MAXHOSTNAMELEN);
	} else {
		if (smb_gethostname(hostname, MAXHOSTNAMELEN, 0) != 0)
			return (-1);

		(void) snprintf(hostname, MAXHOSTNAMELEN, "%s.%s", hostname,
		    domain);
	}

	if ((p = ads_get_host_principal(hostname)) == NULL) {
		return (-1);
	}

	*princ_r = ads_get_host_principal_w_realm(p, domain);
	if (*princ_r == NULL) {
		free(p);
		return (-1);
	}

	if (princ != NULL)
		*princ = p;
	else
		free(p);

	return (0);
}

/*
 * ads_add_computer
 *
 * Returns 0 upon success. Otherwise, returns -1.
 */
static int
ads_add_computer(ADS_HANDLE *ah)
{
	return (ads_computer_op(ah, LDAP_MOD_ADD));
}

/*
 * ads_modify_computer
 *
 * Returns 0 upon success. Otherwise, returns -1.
 */
static int
ads_modify_computer(ADS_HANDLE *ah)
{
	return (ads_computer_op(ah, LDAP_MOD_REPLACE));
}

static int
ads_computer_op(ADS_HANDLE *ah, int op)
{
	LDAPMod *attrs[ADS_COMPUTER_NUM_ATTR];
	char *oc_vals[6], *sam_val[2], *usr_val[2];
	char *svc_val[2], *ctl_val[2], *fqh_val[2];
	int j = 0;
	int ret, usrctl_flags = 0;
	char sam_acct[MAXHOSTNAMELEN + 1];
	char fqhost[MAXHOSTNAMELEN];
	char dn[ADS_DN_MAX];
	char *user_principal, *svc_principal;
	char usrctl_buf[16];
	int max;

	if (smb_gethostname(fqhost, MAXHOSTNAMELEN, 0) != 0)
		return (-1);

	(void) strlcpy(sam_acct, fqhost, MAXHOSTNAMELEN + 1);
	(void) strlcat(sam_acct, "$", MAXHOSTNAMELEN + 1);
	(void) snprintf(fqhost, MAXHOSTNAMELEN, "%s.%s", fqhost,
	    ah->domain);

	if (ads_get_host_principals(fqhost, ah->domain, &svc_principal,
	    &user_principal) == -1) {
		syslog(LOG_ERR,
		    "ads_computer_op: unable to get host principal");
		return (-1);
	}

	ads_get_computer_dn(ah, dn, ADS_DN_MAX);

	max = (ADS_COMPUTER_NUM_ATTR - ((op != LDAP_MOD_ADD) ? 1 : 0));
	for (j = 0; j < (max - 1); j++) {
		attrs[j] = (LDAPMod *)malloc(sizeof (LDAPMod));
		if (attrs[j] == NULL) {
			free_attr(attrs);
			free(user_principal);
			free(svc_principal);
			return (-1);
		}
	}

	j = -1;
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
	attrs[j]->mod_type = "sAMAccountName";
	sam_val[0] = sam_acct;
	sam_val[1] = 0;
	attrs[j]->mod_values = sam_val;

	attrs[++j]->mod_op = op;
	attrs[j]->mod_type = "userPrincipalName";
	usr_val[0] = user_principal;
	usr_val[1] = 0;
	attrs[j]->mod_values = usr_val;

	attrs[++j]->mod_op = op;
	attrs[j]->mod_type = "servicePrincipalName";
	svc_val[0] = svc_principal;
	svc_val[1] = 0;
	attrs[j]->mod_values = svc_val;

	attrs[++j]->mod_op = op;
	attrs[j]->mod_type = "userAccountControl";
	usrctl_flags |= (ADS_USER_ACCT_CTL_WKSTATION_TRUST_ACCT |
	    ADS_USER_ACCT_CTL_PASSWD_NOTREQD |
	    ADS_USER_ACCT_CTL_ACCOUNTDISABLE);
	(void) snprintf(usrctl_buf, sizeof (usrctl_buf), "%d", usrctl_flags);
	ctl_val[0] = usrctl_buf;
	ctl_val[1] = 0;
	attrs[j]->mod_values = ctl_val;

	attrs[++j]->mod_op = op;
	attrs[j]->mod_type = "dNSHostName";
	fqh_val[0] = fqhost;
	fqh_val[1] = 0;
	attrs[j]->mod_values = fqh_val;

	attrs[++j] = 0;

	switch (op) {
	case LDAP_MOD_ADD:
		if ((ret = ldap_add_s(ah->ld, dn, attrs)) != LDAP_SUCCESS) {
			syslog(LOG_ERR, "ads_add_computer: %s",
			    ldap_err2string(ret));
			ret = -1;
		}
		break;

	case LDAP_MOD_REPLACE:
		if ((ret = ldap_modify_s(ah->ld, dn, attrs)) != LDAP_SUCCESS) {
			syslog(LOG_ERR, "ads_modify_computer: %s",
			    ldap_err2string(ret));
			ret = -1;
		}
		break;

	default:
		ret = -1;

	}

	free_attr(attrs);
	free(user_principal);
	free(svc_principal);

	return (ret);
}

/*
 * Delete an ADS computer account.
 */
static void
ads_del_computer(ADS_HANDLE *ah)
{
	char dn[ADS_DN_MAX];
	int rc;

	ads_get_computer_dn(ah, dn, ADS_DN_MAX);

	if ((rc = ldap_delete_s(ah->ld, dn)) != LDAP_SUCCESS) {
		syslog(LOG_DEBUG, "ads_del_computer: %s",
		    ldap_err2string(rc));
	}
}

/*
 * ads_lookup_computer_n_attr
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
ads_lookup_computer_n_attr(ADS_HANDLE *ah, char *attr, char **val)
{
	char *attrs[2], filter[ADS_MAXBUFLEN];
	LDAPMessage *res, *entry;
	char **vals;
	char tmpbuf[ADS_MAXBUFLEN];
	char my_hostname[MAXHOSTNAMELEN], sam_acct[MAXHOSTNAMELEN + 1];
	char dn[ADS_DN_MAX];

	if (smb_gethostname(my_hostname, MAXHOSTNAMELEN, 0) != 0)
		return (-1);

	(void) snprintf(sam_acct, sizeof (sam_acct), "%s$", my_hostname);
	ads_get_computer_dn(ah, dn, ADS_DN_MAX);

	res = NULL;
	attrs[0] = attr;
	attrs[1] = NULL;

	if (ads_escape_search_filter_chars(sam_acct, tmpbuf) != 0) {
		return (-1);
	}

	(void) snprintf(filter, sizeof (filter), "objectClass=computer",
	    tmpbuf);

	if (ldap_search_s(ah->ld, dn, LDAP_SCOPE_BASE, filter, attrs, 0,
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
 * ads_find_computer
 *
 * Return:
 *  1 if found.
 *  0 if not found or encounters error.
 */
static int
ads_find_computer(ADS_HANDLE *ah)
{
	return (ads_lookup_computer_n_attr(ah, NULL, NULL) == 1);
}

/*
 * ads_update_computer_cntrl_attr
 *
 * Modify the user account control attribute of an existing computer
 * object on AD.
 *
 * Returns 0 on success. Otherwise, returns -1.
 */
static int
ads_update_computer_cntrl_attr(ADS_HANDLE *ah, int des_only)
{
	LDAPMod *attrs[6];
	char *ctl_val[2];
	int j = -1;
	int ret, usrctl_flags = 0;
	char dn[ADS_DN_MAX];
	char usrctl_buf[16];

	ads_get_computer_dn(ah, dn, ADS_DN_MAX);

	attrs[++j] = (LDAPMod *) malloc(sizeof (LDAPMod));
	attrs[j]->mod_op = LDAP_MOD_REPLACE;
	attrs[j]->mod_type = "userAccountControl";

	usrctl_flags |= (ADS_USER_ACCT_CTL_WKSTATION_TRUST_ACCT |
	    ADS_USER_ACCT_CTL_TRUSTED_FOR_DELEGATION |
	    ADS_USER_ACCT_CTL_DONT_EXPIRE_PASSWD);

	if (des_only)
		usrctl_flags |= ADS_USER_ACCT_CTL_USE_DES_KEY_ONLY;

	(void) snprintf(usrctl_buf, sizeof (usrctl_buf), "%d", usrctl_flags);
	ctl_val[0] = usrctl_buf;
	ctl_val[1] = 0;
	attrs[j]->mod_values = ctl_val;

	attrs[++j] = 0;

	if ((ret = ldap_modify_s(ah->ld, dn, attrs)) != LDAP_SUCCESS) {
		syslog(LOG_ERR, "ads_modify_computer: %s",
		    ldap_err2string(ret));
		ret = -1;
	}

	free_attr(attrs);
	return (ret);
}

/*
 * ads_lookup_computer_attr_kvno
 *
 * Lookup the value of the Kerberos version number attribute of the computer
 * account.
 */
static krb5_kvno
ads_lookup_computer_attr_kvno(ADS_HANDLE *ah)
{
	char *val = NULL;
	int kvno = 1;

	if (ads_lookup_computer_n_attr(ah, "msDS-KeyVersionNumber",
	    &val) == 1) {
		if (val) {
			kvno = atoi(val);
			free(val);
		}
	}

	return (kvno);
}

/*
 * ads_gen_machine_passwd
 *
 * Returned a null-terminated machine password generated randomly
 * from [0-9a-zA-Z] character set. In order to pass the password
 * quality check (three character classes), an uppercase letter is
 * used as the first character of the machine password.
 */
static int
ads_gen_machine_passwd(char *machine_passwd, int bufsz)
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
 * ads_domain_change_cleanup
 *
 * If we're attempting to join the system to a new domain, the keys for
 * the host principal regarding the old domain should be removed from
 * Kerberos keytab. Also, the ads_host_info cache should be cleared.
 *
 * newdom is fully-qualified domain name.  It can be set to empty string
 * if user attempts to switch to workgroup mode.
 */
int
ads_domain_change_cleanup(char *newdom)
{
	char origdom[MAXHOSTNAMELEN];
	char *princ_r;
	krb5_context ctx = NULL;
	krb5_principal krb5princ;
	int rc;

	if (smb_getfqdomainname(origdom, MAXHOSTNAMELEN))
		return (0);

	if (strcasecmp(origdom, newdom) == 0)
		return (0);

	ads_free_host_info();
	if (ads_get_host_principals(NULL, origdom, NULL, &princ_r) == -1)
		return (-1);

	if (smb_krb5_ctx_init(&ctx) != 0) {
		free(princ_r);
		return (-1);
	}

	if (smb_krb5_get_principal(ctx, princ_r, &krb5princ) != 0) {
		free(princ_r);
		smb_krb5_ctx_fini(ctx);
		return (-1);

	}

	rc = smb_krb5_remove_keytab_entries(ctx, krb5princ, SMBNS_KRB5_KEYTAB);
	free(princ_r);
	smb_krb5_ctx_fini(ctx);

	return (rc);
}

/*
 * ads_join
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
 * generated and set for the newly created computer object using KPASSD
 * protocol (See RFC 3244). Once the password is set, our ADS client
 * finalizes the machine account by modifying the user acount control
 * attribute of the computer object. Kerberos keys derived from the machine
 * account password will be stored locally in /etc/krb5/krb5.keytab file.
 * That would be needed while acquiring Kerberos TGT ticket for the host
 * principal after the domain join operation.
 */
adjoin_status_t
ads_join(char *domain, char *user, char *usr_passwd, char *machine_passwd,
    int len)
{
	ADS_HANDLE *ah = NULL;
	krb5_context ctx = NULL;
	krb5_principal krb5princ;
	krb5_kvno kvno;
	char *princ_r;
	boolean_t des_only, delete = B_TRUE;
	adjoin_status_t rc = ADJOIN_SUCCESS;
	boolean_t new_acct;
	/*
	 * Call library functions that can be used to get
	 * the list of encryption algorithms available on the system.
	 * (similar to what 'encrypt -l' CLI does). For now,
	 * unless someone has modified the configuration of the
	 * cryptographic framework (very unlikely), the following is the
	 * list of algorithms available on any system running Nevada
	 * by default.
	 */
	krb5_enctype enctypes[] = {ENCTYPE_DES_CBC_CRC, ENCTYPE_DES_CBC_MD5,
	    ENCTYPE_ARCFOUR_HMAC, ENCTYPE_AES128_CTS_HMAC_SHA1_96};

	if ((ah = ads_open_main(domain, user, usr_passwd)) == NULL) {
		(void) smb_config_refresh();
		return (ADJOIN_ERR_GET_HANDLE);
	}

	if (ads_gen_machine_passwd(machine_passwd, len) != 0) {
		ads_close(ah);
		(void) smb_config_refresh();
		return (ADJOIN_ERR_GEN_PASSWD);
	}

	if (ads_find_computer(ah)) {
		new_acct = B_FALSE;
		if (ads_modify_computer(ah) != 0) {
			ads_close(ah);
			(void) smb_config_refresh();
			return (ADJOIN_ERR_MOD_TRUST_ACCT);
		}
	} else {
		new_acct = B_TRUE;
		if (ads_add_computer(ah) != 0) {
			ads_close(ah);
			(void) smb_config_refresh();
			return (ADJOIN_ERR_ADD_TRUST_ACCT);
		}
	}

	des_only = B_FALSE;

	/*
	 * If we are talking to a Longhorn server, we need to set up
	 * the msDS-SupportedEncryptionTypes attribute of the computer
	 * object accordingly
	 *
	 * The code to modify the msDS-SupportedEncryptionTypes can be
	 * added once we figure out why the Longhorn server rejects the
	 * SmbSessionSetup request sent by SMB redirector.
	 */

	if (ads_get_host_principals(NULL, ah->domain, NULL, &princ_r) == -1) {
		if (new_acct)
			ads_del_computer(ah);
		ads_close(ah);
		(void) smb_config_refresh();
		return (ADJOIN_ERR_GET_HOST_PRINC);
	}

	if (smb_krb5_ctx_init(&ctx) != 0) {
		rc = ADJOIN_ERR_INIT_KRB_CTX;
		goto adjoin_cleanup;
	}

	if (smb_krb5_get_principal(ctx, princ_r, &krb5princ) != 0) {
		rc = ADJOIN_ERR_GET_KRB_PRINC;
		goto adjoin_cleanup;
	}

	if (smb_krb5_setpwd(ctx, krb5princ, machine_passwd) != 0) {
		rc = ADJOIN_ERR_KSETPWD;
		goto adjoin_cleanup;
	}

	kvno = ads_lookup_computer_attr_kvno(ah);

	if (ads_update_computer_cntrl_attr(ah, des_only) != 0) {
		rc = ADJOIN_ERR_UPDATE_CNTRL_ATTR;
		goto adjoin_cleanup;
	}

	if (smb_krb5_update_keytab_entries(ctx, krb5princ, SMBNS_KRB5_KEYTAB,
	    kvno, machine_passwd, enctypes,
	    (sizeof (enctypes) / sizeof (krb5_enctype))) != 0) {
		rc = ADJOIN_ERR_WRITE_KEYTAB;
		goto adjoin_cleanup;
	}

	/* Set IDMAP config */
	if (smb_config_set_idmap_domain(ah->domain) != 0) {
		rc = ADJOIN_ERR_IDMAP_SET_DOMAIN;
		goto adjoin_cleanup;
	}

	/* Refresh IDMAP service */
	if (smb_config_refresh_idmap() != 0) {
		rc = ADJOIN_ERR_IDMAP_REFRESH;
		goto adjoin_cleanup;
	}

	delete = B_FALSE;
adjoin_cleanup:
	if (new_acct && delete)
		ads_del_computer(ah);

	if (rc != ADJOIN_ERR_INIT_KRB_CTX) {
		if (rc != ADJOIN_ERR_GET_KRB_PRINC)
			krb5_free_principal(ctx, krb5princ);
		smb_krb5_ctx_fini(ctx);
	}

	ads_close(ah);
	free(princ_r);

	/*
	 * Don't mask other failure.  Only reports SMF refresh
	 * failure if no other domain join failure.
	 */
	if ((smb_config_refresh() != 0) && (rc == ADJOIN_SUCCESS))
		rc = ADJOIN_ERR_SMB_REFRESH;

	return (rc);
}

/*
 * adjoin_report_err
 *
 * Display error message for the specific adjoin error code.
 */
char *
adjoin_report_err(adjoin_status_t status)
{
	if (status < 0 || status >= ADJOIN_NUM_STATUS)
		return ("ADJOIN: unknown status");

	return (adjoin_errmsg[status]);
}
