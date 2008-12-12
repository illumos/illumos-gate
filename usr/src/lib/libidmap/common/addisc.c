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
 * Active Directory Auto-Discovery.
 *
 * This [project private] API allows the caller to provide whatever
 * details it knows a priori (i.e., provided via configuration so as to
 * override auto-discovery) and in any order.  Then the caller can ask
 * for any of the auto-discoverable parameters in any order.
 *
 * But there is an actual order in which discovery must be done.  Given
 * the discovery mechanism implemented here, that order is:
 *
 *  - the domain name joined must be discovered first
 *  - then the domain controllers
 *  - then the forest name and site name
 *  - then the global catalog servers, and site-specific domain
 *    controllers and global catalog servers.
 *
 * The API does not require it be called in the same order because there
 * may be other discovery mechanisms in the future, and exposing
 * ordering requirements of the current mechanism now can create trouble
 * down the line.  Also, this makes the API easier to use now, which
 * means less work to do some day when we make this a public API.
 *
 * Domain discovery is done by res_nsearch() of the DNS SRV RR name for
 * domain controllers.  As long as the joined domain appears in the DNS
 * resolver's search list then we'll find it.
 *
 * Domain controller discovery is a matter of formatting the DNS SRV RR
 * FQDN for domain controllers and doing a lookup for them.  Knowledge
 * of the domain name is not fundamentally required, but we separate the
 * two processes, which in practice can lead to one more DNS lookup than
 * is strictly required.
 *
 * Forest and site name discovery require an LDAP search of the AD
 * "configuration partition" at a domain controller for the joined
 * domain.  Forest and site name discovery depend on knowing the joined
 * domain name and domain controllers for that domain.
 *
 * Global catalog server discovery requires knowledge of the forest
 * name in order to format the DNS SRV RR FQDN to lookup.  Site-specific
 * domain controller discovery depends on knowing the site name (and,
 * therefore, joined domain, ...).  Site-specific global catalog server
 * discovery depends on knowledge of the forest and site names, which
 * depend on...
 *
 * All the work of discovering particular items is done by functions
 * named validate_<item>().  Each such function calls validate_<item>()
 * for any items that it depends on.
 *
 * This API is not thread-safe.
 */


#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <net/if.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <netinet/in.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>
#include <ctype.h>
#include <errno.h>
#include <ldap.h>
#include <sasl/sasl.h>
#include <sys/u8_textprep.h>
#include "addisc.h"


enum ad_item_state {
		AD_STATE_INVALID = 0,	/* The value is not valid */
		AD_STATE_FIXED,		/* The value was fixed by caller */
		AD_STATE_AUTO		/* The value is auto discovered */
		};

enum ad_data_type {
		AD_STRING = 123,
		AD_DIRECTORY,
		AD_DOMAINS_IN_FOREST,
		AD_TRUSTED_DOMAINS
		};


typedef struct ad_subnet {
	char subnet[24];
} ad_subnet_t;


typedef struct ad_item {
	enum ad_item_state	state;
	enum ad_data_type	type;
	void 			*value;
	time_t 			ttl;
	unsigned int 		version;	/* Version is only changed */
						/* if the value changes */
#define	PARAM1		0
#define	PARAM2		1
	int 		param_version[2];
					/* These holds the version of */
					/* dependents so that a dependent */
					/* change can be detected */
} ad_item_t;

typedef struct ad_disc {
	struct __res_state res_state;
	int		res_ninitted;
	ad_subnet_t	*subnets;
	int		subnets_changed;
	time_t		subnets_last_check;
	ad_item_t	domain_name;		/* DNS hostname string */
	ad_item_t	domain_controller;	/* Directory hostname and */
						/* port array */
	ad_item_t	site_name;		/* String */
	ad_item_t	forest_name;		/* DNS forestname string */
	ad_item_t	global_catalog;		/* Directory hostname and */
						/* port array */
	ad_item_t	domains_in_forest;	/* DNS domainname and SID */
						/* array */
	ad_item_t	trusted_domains;	/* DNS domainname and trust */
						/* direction array */
	/* Site specfic versions */
	ad_item_t	site_domain_controller;	/* Directory hostname and */
						/* port array */
	ad_item_t	site_global_catalog;	/* Directory hostname and */
						/* port array */
} ad_disc;


#define	DNS_MAX_NAME	NS_MAXDNAME


/* SRV RR names for various queries */
#define	LDAP_SRV_HEAD		"_ldap._tcp."
#define	SITE_SRV_MIDDLE		"%s._sites."
#define	GC_SRV_TAIL		"gc._msdcs"
#define	DC_SRV_TAIL		"dc._msdcs"
#define	ALL_GC_SRV_TAIL		"_gc._tcp"
#define	PDC_SRV			 "_ldap._tcp.pdc._msdcs.%s"

/* A RR name for all GCs -- last resort this works */
#define	GC_ALL_A_NAME_FSTR "gc._msdcs.%s."


/*
 * We try res_ninit() whenever we don't have one.  res_ninit() fails if
 * idmapd is running before the network is up!
 */
#define	DO_RES_NINIT(ctx)   if (!(ctx)->res_ninitted) \
		(ctx)->res_ninitted = (res_ninit(&ctx->res_state) != -1)

#define	is_fixed(item)					\
	((item)->state == AD_STATE_FIXED)

#define	is_changed(item, num, param) 			\
	((item)->param_version[num] != (param)->version)

/*LINTLIBRARY*/

/*
 * Function definitions
 */
static ad_item_t *
validate_SiteName(ad_disc_t ctx);



static void
update_version(ad_item_t *item, int  num, ad_item_t *param)
{
	item->param_version[num] = param->version;
}



static int
is_valid(ad_item_t *item)
{
	if (item->value != NULL) {
		if (item->state == AD_STATE_FIXED)
			return (TRUE);
		if (item->state == AD_STATE_AUTO &&
		    (item->ttl == 0 || item->ttl > time(NULL)))
			return (TRUE);
	}
	return (FALSE);
}


static void
update_item(ad_item_t *item, void *value, enum ad_item_state state,
		uint32_t ttl)
{
	if (item->value != NULL && value != NULL) {
		if ((item->type == AD_STRING &&
		    strcmp(item->value, value) != 0) ||
		    (item->type == AD_DIRECTORY &&
		    ad_disc_compare_ds(item->value, value) != 0)||
		    (item->type == AD_DOMAINS_IN_FOREST &&
		    ad_disc_compare_domainsinforest(item->value, value) != 0) ||
		    (item->type == AD_TRUSTED_DOMAINS &&
		    ad_disc_compare_trusteddomains(item->value, value) != 0))
			item->version++;
	} else if (item->value != value)
		item->version++;

	if (item->value != NULL)
		free(item->value);

	item->value = value;
	item->state = state;

	if (ttl == 0)
		item->ttl = 0;
	else
		item->ttl = time(NULL) + ttl;
}


/* Compare DS lists */
int
ad_disc_compare_ds(idmap_ad_disc_ds_t *ds1, idmap_ad_disc_ds_t *ds2)
{
	int	i, j;
	int	num_ds1;
	int	num_ds2;
	int	match;

	for (i = 0; ds1[i].host[0] != '\0'; i++)
		continue;
	num_ds1 = i;
	for (j = 0; ds2[j].host[0] != '\0'; j++)
		continue;
	num_ds2 = j;
	if (num_ds1 != num_ds2)
		return (1);

	for (i = 0; i < num_ds1; i++) {
		match = FALSE;
		for (j = 0; j < num_ds2; j++) {
			if (strcmp(ds1[i].host, ds2[i].host) == 0 &&
			    ds1[i].port == ds2[i].port) {
				match = TRUE;
				break;
			}
		}
		if (!match)
			return (1);
	}
	return (0);
}


/* Copy a list of DSs */
static idmap_ad_disc_ds_t *
ds_dup(const idmap_ad_disc_ds_t *srv)
{
	int	i;
	int	size;
	idmap_ad_disc_ds_t *new = NULL;

	for (i = 0; srv[i].host[0] != '\0'; i++)
		continue;

	size = (i + 1) * sizeof (idmap_ad_disc_ds_t);
	new = malloc(size);
	if (new != NULL)
		memcpy(new, srv, size);
	return (new);
}


int
ad_disc_compare_trusteddomains(ad_disc_trusteddomains_t *td1,
			ad_disc_trusteddomains_t *td2)
{
	int	i, j;
	int	num_td1;
	int	num_td2;
	int	match;
	int 	err;

	for (i = 0; td1[i].domain[0] != '\0'; i++)
		continue;
	num_td1 = i;

	for (j = 0; td2[j].domain[0] != '\0'; j++)
		continue;
	num_td2 = j;

	if (num_td1 != num_td2)
		return (1);

	for (i = 0; i < num_td1; i++) {
		match = FALSE;
		for (j = 0; j < num_td2; j++) {
			if (u8_strcmp(td1[i].domain, td2[i].domain, 0,
			    U8_STRCMP_CI_LOWER, U8_UNICODE_LATEST, &err) == 0 &&
			    err == 0) {
				match = TRUE;
				break;
			}
		}
		if (!match)
			return (1);
	}
	return (0);
}



/* Copy a list of Trusted Domains */
static ad_disc_trusteddomains_t *
td_dup(const ad_disc_trusteddomains_t *td)
{
	int	i;
	int	size;
	ad_disc_trusteddomains_t *new = NULL;

	for (i = 0; td[i].domain[0] != '\0'; i++)
		continue;

	size = (i + 1) * sizeof (ad_disc_trusteddomains_t);
	new = malloc(size);
	if (new != NULL)
		memcpy(new, td, size);
	return (new);
}



int
ad_disc_compare_domainsinforest(ad_disc_domainsinforest_t *df1,
			ad_disc_domainsinforest_t *df2)
{
	int	i, j;
	int	num_df1;
	int	num_df2;
	int	match;
	int	err;

	for (i = 0; df1[i].domain[0] != '\0'; i++)
		continue;
	num_df1 = i;

	for (j = 0; df2[j].domain[0] != '\0'; j++)
		continue;
	num_df2 = j;

	if (num_df1 != num_df2)
		return (1);

	for (i = 0; i < num_df1; i++) {
		match = FALSE;
		for (j = 0; j < num_df2; j++) {
			if (u8_strcmp(df1[i].domain, df2[i].domain, 0,
			    U8_STRCMP_CI_LOWER, U8_UNICODE_LATEST, &err) == 0 &&
			    err == 0 &&
			    strcmp(df1[i].sid, df2[i].sid) == 0) {
				match = TRUE;
				break;
			}
		}
		if (!match)
			return (1);
	}
	return (0);
}



/* Copy a list of Trusted Domains */
static ad_disc_domainsinforest_t *
df_dup(const ad_disc_domainsinforest_t *df)
{
	int	i;
	int	size;
	ad_disc_domainsinforest_t *new = NULL;

	for (i = 0; df[i].domain[0] != '\0'; i++)
		continue;

	size = (i + 1) * sizeof (ad_disc_domainsinforest_t);
	new = malloc(size);
	if (new != NULL)
		memcpy(new, df, size);
	return (new);
}





/*
 * Returns an array of IPv4 address/prefix length
 * The last subnet is NULL
 */
static ad_subnet_t *
find_subnets()
{
	int		sock, n, i;
	struct lifconf	lifc;
	struct lifreq	lifr, *lifrp;
	struct lifnum	lifn;
	uint32_t	prefix_len;
	char		*s;
	ad_subnet_t	*results;

	lifrp = &lifr;

	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		idmapdlog(LOG_ERR, "Failed to open IPv4 socket for "
		    "listing network interfaces (%s)", strerror(errno));
		return (NULL);
	}

	lifn.lifn_family = AF_INET;
	lifn.lifn_flags = 0;
	if (ioctl(sock, SIOCGLIFNUM, (char *)&lifn) < 0) {
		idmapdlog(LOG_ERR,
		    "Failed to find the number of network interfaces (%s)",
		    strerror(errno));
		close(sock);
		return (NULL);
	}

	if (lifn.lifn_count < 1) {
		idmapdlog(LOG_ERR, "No IPv4 network interfaces found");
		close(sock);
		return (NULL);
	}

	lifc.lifc_family = AF_INET;
	lifc.lifc_flags = 0;
	lifc.lifc_len = lifn.lifn_count * sizeof (struct lifreq);
	lifc.lifc_buf = malloc(lifc.lifc_len);

	if (lifc.lifc_buf == NULL) {
		idmapdlog(LOG_ERR, "Out of memory");
		close(sock);
		return (NULL);
	}

	if (ioctl(sock, SIOCGLIFCONF, (char *)&lifc) < 0) {
		idmapdlog(LOG_ERR, "Failed to list network interfaces (%s)",
		    strerror(errno));
		free(lifc.lifc_buf);
		close(sock);
		return (NULL);
	}

	n = lifc.lifc_len / (int)sizeof (struct lifreq);

	if ((results = calloc(n + 1, sizeof (ad_subnet_t))) == NULL) {
		free(lifc.lifc_buf);
		close(sock);
		return (NULL);
	}

	for (i = 0, lifrp = lifc.lifc_req; i < n; i++, lifrp++) {
		if (ioctl(sock, SIOCGLIFFLAGS, lifrp) < 0)
			continue;

		if ((lifrp->lifr_flags & IFF_UP) == 0)
			continue;

		if (ioctl(sock, SIOCGLIFSUBNET, lifrp) < 0)
			continue;

		prefix_len = lifrp->lifr_addrlen;

		s = inet_ntoa(((struct sockaddr_in *)
		    &lifrp->lifr_addr)->sin_addr);

		(void) snprintf(results[i].subnet, sizeof (ad_subnet_t),
		    "%s/%d", s, prefix_len);
	}

	free(lifc.lifc_buf);
	close(sock);

	return (results);
}

static int
cmpsubnets(ad_subnet_t *subnets1, ad_subnet_t *subnets2)
{
	int num_subnets1;
	int num_subnets2;
	int matched;
	int i, j;

	for (i = 0; subnets1[i].subnet[0] != '\0'; i++)
		continue;
	num_subnets1 = i;

	for (i = 0; subnets2[i].subnet[0] != '\0'; i++)
		continue;
	num_subnets2 = i;

	if (num_subnets1 != num_subnets2)
		return (1);

	for (i = 0;  i < num_subnets1; i++) {
		matched = FALSE;
		for (j = 0; j < num_subnets2; j++) {
			if (strcmp(subnets1[i].subnet,
			    subnets2[j].subnet) == 0) {
				matched = TRUE;
				break;
			}
		}
		if (!matched)
			return (1);
	}
	return (0);
}




/* Convert a DN's DC components into a DNS domainname */
static char *
DN_to_DNS(const char *dn_name)
{
	char	dns[DNS_MAX_NAME];
	char	*dns_name;
	int	i, j;
	int	num = 0;

	j = 0;
	i = 0;

	if (dn_name == NULL)
		return (NULL);
	/*
	 * Find all DC=<value> and form DNS name of the
	 * form <value1>.<value2>...
	 */
	while (dn_name[i] != '\0') {
		if (strncasecmp(&dn_name[i], "DC=", 3) == 0) {
			i += 3;
			if (dn_name[i] != '\0' && num > 0)
				dns[j++] = '.';
			while (dn_name[i] != '\0' &&
			    dn_name[i] != ',' && dn_name[i] != '+')
				dns[j++] = dn_name[i++];
			num++;
		} else {
			/* Skip attr=value as it is not DC= */
			while (dn_name[i] != '\0' &&
			    dn_name[i] != ',' && dn_name[i] != '+')
				i++;
		}
		/* Skip over separator ','  or '+' */
		if (dn_name[i] != '\0') i++;
	}
	dns[j] = '\0';
	dns_name = malloc(j + 1);
	if (dns_name != NULL)
		(void) strlcpy(dns_name, dns, j + 1);
	return (dns_name);
}


/* Format the DN of an AD LDAP subnet object for some subnet */
static char *
subnet_to_DN(const char *subnet, const char *baseDN)
{
	char *result;
	int len;

	len = snprintf(NULL, 0,
	    "CN=%s,CN=Subnets,CN=Sites,%s",
	    subnet, baseDN) + 1;

	result = malloc(len);
	if (result != NULL)
		(void) snprintf(result, len,
		    "CN=%s,CN=Subnets,CN=Sites,%s",
		    subnet, baseDN);
	return (result);
}


/* Make a list of subnet object DNs from a list of subnets */
static char **
subnets_to_DNs(ad_subnet_t *subnets, const char *base_dn)
{
	char **results;
	int i, j;

	for (i = 0; subnets[i].subnet[0] != '\0'; i++)
		continue;

	results = calloc(i + 1, sizeof (char *));
	if (results == NULL)
		return (NULL);

	for (i = 0; subnets[i].subnet[0] != '\0'; i++) {
		if ((results[i] = subnet_to_DN(subnets[i].subnet, base_dn))
		    == NULL) {
			for (j = 0; j < i; j++)
				free(results[j]);
			free(results);
			return (NULL);
		}
	}

	return (results);
}


/* Compare SRC RRs; used with qsort() */
static int
srvcmp(idmap_ad_disc_ds_t *s1, idmap_ad_disc_ds_t *s2)
{
	if (s1->priority < s2->priority)
		return (1);
	else if (s1->priority > s2->priority)
		return (-1);

	if (s1->weight < s2->weight)
		return (1);
	else if (s1->weight > s2->weight)
		return (-1);

	return (0);
}


/*
 * Query or search the SRV RRs for a given name.
 *
 * If name == NULL then search (as in res_nsearch(3RESOLV), honoring any
 * search list/option), else query (as in res_nquery(3RESOLV)).
 *
 * The output TTL will be the one of the SRV RR with the lowest TTL.
 */
idmap_ad_disc_ds_t *
srv_query(res_state state, const char *svc_name, const char *dname,
		char **rrname, uint32_t *ttl)
{
	idmap_ad_disc_ds_t *srv;
	idmap_ad_disc_ds_t *srv_res;
	union {
		HEADER hdr;
		uchar_t buf[NS_MAXMSG];
	} msg;
	int len, cnt, qdcount, ancount;
	uchar_t *ptr, *eom;
	uchar_t *end;
	uint16_t type;
	/* LINTED  E_FUNC_SET_NOT_USED */
	uint16_t class;
	uint32_t rttl;
	uint16_t size;
	char *query_type;
	char namebuf[NS_MAXDNAME];

	if (state == NULL)
		return (NULL);

	/* Set negative result TTL */
	*ttl = 5 * 60;

	/* 1. query necessary resource records */

	/* Search, querydomain or query */
	if (rrname != NULL) {
		query_type = "search";
		*rrname = NULL;
		len = res_nsearch(state, svc_name, C_IN, T_SRV,
		    msg.buf, sizeof (msg.buf));
	} else if (dname != NULL) {
		query_type = "query";
		len = res_nquerydomain(state, svc_name, dname, C_IN, T_SRV,
		    msg.buf, sizeof (msg.buf));
	}

	idmapdlog(LOG_DEBUG, "%sing DNS for SRV RRs named '%s'",
	    query_type, svc_name);

	if (len < 0) {
		idmapdlog(LOG_DEBUG, "DNS %s for '%s' failed (%s)",
		    query_type, svc_name, hstrerror(state->res_h_errno));
		return (NULL);
	}
	if (len > sizeof (msg.buf)) {
		idmapdlog(LOG_ERR, "DNS query %ib message doesn't fit"
		    " into %ib buffer",
		    len, sizeof (msg.buf));
		return (NULL);
	}

	/* 2. parse the reply, skip header and question sections */

	ptr = msg.buf + sizeof (msg.hdr);
	eom = msg.buf + len;
	qdcount = ntohs(msg.hdr.qdcount);
	ancount = ntohs(msg.hdr.ancount);

	for (cnt = qdcount; cnt > 0; --cnt) {
		if ((len = dn_skipname(ptr, eom)) < 0) {
			idmapdlog(LOG_ERR, "DNS query invalid message format");
			return (NULL);
		}
		ptr += len + QFIXEDSZ;
	}

	/* 3. walk through the answer section */

	srv_res = calloc(ancount + 1, sizeof (idmap_ad_disc_ds_t));
	*ttl = (uint32_t)-1;

	for (srv = srv_res, cnt = ancount;
	    cnt > 0; --cnt, srv++) {

		len = dn_expand(msg.buf, eom, ptr, namebuf,
		    sizeof (namebuf));
		if (len < 0) {
			idmapdlog(LOG_ERR, "DNS query invalid message format");
			return (NULL);
		}
		if (rrname != NULL && *rrname == NULL)
			*rrname = strdup(namebuf);
		ptr += len;
		NS_GET16(type, ptr);
		NS_GET16(class, ptr);
		NS_GET32(rttl, ptr);
		NS_GET16(size, ptr);
		if ((end = ptr + size) > eom) {
			idmapdlog(LOG_ERR, "DNS query invalid message format");
			return (NULL);
		}

		if (type != T_SRV) {
			ptr = end;
			continue;
		}

		NS_GET16(srv->priority, ptr);
		NS_GET16(srv->weight, ptr);
		NS_GET16(srv->port, ptr);
		len = dn_expand(msg.buf, eom, ptr, srv->host,
		    sizeof (srv->host));
		if (len < 0) {
			idmapdlog(LOG_ERR, "DNS query invalid SRV record");
			return (NULL);
		}

		if (rttl < *ttl)
			*ttl = rttl;

		idmapdlog(LOG_DEBUG, "Found %s %d IN SRV [%d][%d] %s:%d",
		    namebuf, rttl, srv->priority, srv->weight, srv->host,
		    srv->port);

		/* 3. move ptr to the end of current record */

		ptr = end;
	}

	if (ancount > 1)
		qsort(srv_res, ancount, sizeof (*srv_res),
		    (int (*)(const void *, const void *))srvcmp);

	return (srv_res);
}


static int
/* ARGSUSED */
saslcallback(LDAP *ld, unsigned flags, void *defaults, void *prompts)
{
	sasl_interact_t *interact;

	if (prompts == NULL || flags != LDAP_SASL_INTERACTIVE)
		return (LDAP_PARAM_ERROR);

	/* There should be no extra arguemnts for SASL/GSSAPI authentication */
	for (interact = prompts; interact->id != SASL_CB_LIST_END; interact++) {
		interact->result = NULL;
		interact->len = 0;
	}
	return (LDAP_SUCCESS);
}

/*
 * A utility function to bind to a Directory server
 */

static LDAP*
ldap_lookup_init(idmap_ad_disc_ds_t *ds)
{
	int 	i;
	int	rc, ldversion;
	int	zero = 0;
	int 	timeoutms = 5 * 1000;
	char 	*saslmech = "GSSAPI";
	uint32_t saslflags = LDAP_SASL_INTERACTIVE;
	LDAP 	*ld = NULL;

	for (i = 0; ds[i].host[0] != '\0'; i++) {
		ld = ldap_init(ds[i].host, ds[i].port);
		if (ld == NULL) {
			idmapdlog(LOG_DEBUG, "Couldn't connect to "
			    "AD DC %s:%d (%s)",
			    ds[i].host, ds[i].port,
			    strerror(errno));
			continue;
		}

		ldversion = LDAP_VERSION3;
		(void) ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION,
		    &ldversion);

		(void) ldap_set_option(ld, LDAP_OPT_REFERRALS,
		    LDAP_OPT_OFF);
		(void) ldap_set_option(ld, LDAP_OPT_TIMELIMIT, &zero);
		(void) ldap_set_option(ld, LDAP_OPT_SIZELIMIT, &zero);
		/* setup TCP/IP connect timeout */
		(void) ldap_set_option(ld, LDAP_X_OPT_CONNECT_TIMEOUT,
		    &timeoutms);
		(void) ldap_set_option(ld, LDAP_OPT_RESTART,
		    LDAP_OPT_ON);

		rc = ldap_sasl_interactive_bind_s(ld, "" /* binddn */,
		    saslmech, NULL, NULL, saslflags, &saslcallback,
		    NULL /* defaults */);
		if (rc == LDAP_SUCCESS)
			break;

		idmapdlog(LOG_INFO, "LDAP SASL bind to %s:%d failed (%s)",
		    ds[i].host, ds[i].port, ldap_err2string(rc));
		(void) ldap_unbind(ld);
		ld = NULL;
	}
	return (ld);
}


/*
 * A utility function to get the value of some attribute of one of one
 * or more AD LDAP objects named by the dn_list; first found one wins.
 */
static char *
ldap_lookup_entry_attr(LDAP **ld, idmap_ad_disc_ds_t *domainControllers,
			char **dn_list, char *attr)
{
	int 	i;
	int	rc;
	int	scope = LDAP_SCOPE_BASE;
	char	*attrs[2];
	LDAPMessage *results = NULL;
	LDAPMessage *entry;
	char	**values = NULL;
	char	*val = NULL;

	attrs[0] = attr;
	attrs[1] = NULL;

	if (*ld == NULL)
		*ld = ldap_lookup_init(domainControllers);

	if (*ld == NULL)
		return (NULL);

	for (i = 0; dn_list[i] != NULL; i++) {
		rc = ldap_search_s(*ld, dn_list[i], scope,
		    "(objectclass=*)", attrs, 0, &results);
		if (rc == LDAP_SUCCESS) {
			for (entry = ldap_first_entry(*ld, results);
			    entry != NULL && values == NULL;
			    entry = ldap_next_entry(*ld, entry)) {
				values = ldap_get_values(
				    *ld, entry, attr);
			}

			if (values != NULL) {
				(void) ldap_msgfree(results);
				val = strdup(values[0]);
				ldap_value_free(values);
				return (val);
			}
		}
		if (results != NULL) {
			(void) ldap_msgfree(results);
			results = NULL;
		}
	}

	return (NULL);
}


/*
 * Lookup the trusted domains in the global catalog.
 *
 * Returns:
 *	array of trusted domains which is terminated by
 *		an empty trusted domain.
 *	NULL an error occured
 */
ad_disc_trusteddomains_t *
ldap_lookup_trusted_domains(LDAP **ld, idmap_ad_disc_ds_t *globalCatalog,
			char *base_dn)
{
	int		scope = LDAP_SCOPE_SUBTREE;
	char		*attrs[3];
	int		rc;
	LDAPMessage	*results = NULL;
	LDAPMessage	*entry;
	char		*filter;
	char		**partner = NULL;
	char		**direction = NULL;
	int		num = 0;
	ad_disc_trusteddomains_t *trusted_domains = NULL;


	if (*ld == NULL)
		*ld = ldap_lookup_init(globalCatalog);

	if (*ld == NULL)
		return (NULL);

	attrs[0] = "trustPartner";
	attrs[1] = "trustDirection";
	attrs[2] = NULL;

	/* trustDirection values - inbound = 1 and bidirectional = 3 */
	filter = "(&(objectclass=trustedDomain)"
	    "(|(trustDirection=3)(trustDirection=1)))";

	rc = ldap_search_s(*ld, base_dn, scope, filter, attrs, 0, &results);
	if (rc == LDAP_SUCCESS) {
		for (entry = ldap_first_entry(*ld, results);
		    entry != NULL; entry = ldap_next_entry(*ld, entry)) {
			partner = ldap_get_values(*ld, entry, "trustPartner");
			direction = ldap_get_values(
			    *ld, entry, "trustDirection");

			if (partner != NULL && direction != NULL) {
				num++;
				trusted_domains = realloc(trusted_domains,
				    (num + 1) *
				    sizeof (ad_disc_trusteddomains_t));
				if (trusted_domains == NULL) {
					ldap_value_free(partner);
					ldap_value_free(direction);
					ldap_msgfree(results);
					return (NULL);
				}
				/* Last element should be zero */
				memset(&trusted_domains[num], 0,
				    sizeof (ad_disc_trusteddomains_t));
				strcpy(trusted_domains[num - 1].domain,
				    partner[0]);
				trusted_domains[num - 1].direction =
				    atoi(direction[0]);
			}
			if (partner != NULL)
				ldap_value_free(partner);
			if (direction != NULL)
				ldap_value_free(direction);
		}
	} else if (rc == LDAP_NO_RESULTS_RETURNED) {
		/* This is not an error - return empty trusted domain */
		trusted_domains = calloc(1, sizeof (ad_disc_trusteddomains_t));
	}
	if (results != NULL)
		ldap_msgfree(results);

	return (trusted_domains);
}

static int
decode_sid(BerValue *bval, char *sid_txt)
{
	int		i, j;
	uchar_t		*v;
	uint32_t	a;
	struct sid {
		uchar_t		version;
		uchar_t		sub_authority_count;
		uint64_t	authority;  /* really, 48-bits */
		uint32_t	sub_authorities[16];
	} sid;
	char *ptr;
	int len;
	int rlen;


	/*
	 * The binary format of a SID is as follows:
	 *
	 * byte #0: version, always 0x01
	 * byte #1: RID count, always <= 0x0f
	 * bytes #2-#7: SID authority, big-endian 48-bit unsigned int
	 *
	 * followed by RID count RIDs, each a little-endian, unsigned
	 * 32-bit int.
	 */
	/*
	 * Sanity checks: must have at least one RID, version must be
	 * 0x01, and the length must be 8 + rid count * 4
	 */
	if (bval->bv_len > 8 && bval->bv_val[0] == 0x01 &&
	    bval->bv_len == 1 + 1 + 6 + bval->bv_val[1] * 4) {
		v = (uchar_t *)bval->bv_val;
		sid.version = v[0];
		sid.sub_authority_count = v[1];
		sid.authority =
		    /* big endian -- so start from the left */
		    ((u_longlong_t)v[2] << 40) |
		    ((u_longlong_t)v[3] << 32) |
		    ((u_longlong_t)v[4] << 24) |
		    ((u_longlong_t)v[5] << 16) |
		    ((u_longlong_t)v[6] << 8) |
		    (u_longlong_t)v[7];
		for (i = 0; i < sid.sub_authority_count; i++) {
			j = 8 + (i * 4);
			/* little endian -- so start from the right */
			a = (v[j + 3] << 24) | (v[j + 2] << 16) |
			    (v[j + 1] << 8) | (v[j]);
			sid.sub_authorities[i] = a;
		}

		ptr = sid_txt;
		len = AD_DISC_MAXSID;
		rlen = snprintf(ptr, len, "S-1-%llu", sid.authority);

		ptr += rlen;
		len -= rlen;

		for (i = 0; i < sid.sub_authority_count; i++) {
			assert(len > 0);
			rlen = snprintf(
			    ptr, len, "-%u", sid.sub_authorities[i]);
			ptr += rlen;
			len -= rlen;
		}
		assert(len > 0);
		return (0);
	}
	return (-1);
}

/*
 * This functions finds all the domains in a forest.
 * It first finds all the naming contexts by finding the
 * root DSE attribute namingContext. For each naming context
 * it performes an entry search looking for Domain object class
 * returning the attribute objectSid.
 */
ad_disc_domainsinforest_t *
ldap_lookup_domains_in_forest(LDAP **ld, idmap_ad_disc_ds_t *globalCatalogs)
{
	int		scope = LDAP_SCOPE_BASE;
	char		*attrs[2];
	char		*root_attrs[2];
	int		rc;
	LDAPMessage	*result = NULL;
	LDAPMessage	*entry;
	char		*filter;
	char		**nc = NULL;
	struct berval	**sid_ber;
	int		num = 0;
	ad_disc_domainsinforest_t *domains = NULL;
	int		i;
	char 		*name;


	if (*ld == NULL)
		*ld = ldap_lookup_init(globalCatalogs);

	if (*ld == NULL) {
		idmapdlog(LOG_NOTICE, "Couldn't open and SASL bind LDAP "
		    "connections to any domain controllers; discovery of "
		    "some items will fail");
		return (NULL);
	}

	root_attrs[0] = "namingContexts";
	root_attrs[1] = NULL;

	attrs[0] = "objectSid";
	attrs[1] = NULL;

	filter = "(objectclass=Domain)";

	/* Find naming contexts */
	rc = ldap_search_s(*ld, LDAP_ROOT_DSE, scope, "(objectClass=*)",
	    root_attrs, 0, &result);
	if (rc == LDAP_SUCCESS) {
		entry = ldap_first_entry(*ld, result);
		if (entry != NULL) {
			nc = ldap_get_values(*ld, entry, "namingContexts");
		}
	}
	if (result != NULL)
		ldap_msgfree(result);
	if (nc == NULL)
		return (NULL);

	/* Find domains */
	for (i = 0; nc[i] != NULL; i++) {
		rc = ldap_search_s(*ld, nc[i], scope, filter, attrs, 0,
		    &result);
		if (rc == LDAP_SUCCESS) {
			entry = ldap_first_entry(*ld, result);
			if (entry != NULL) {
				sid_ber = ldap_get_values_len(*ld, entry,
				    "objectSid");
				if (sid_ber != NULL) {
					num++;
					domains = realloc(domains,
					    (num + 1) *
					    sizeof (ad_disc_domainsinforest_t));
					if (domains == NULL) {
						ldap_value_free_len(sid_ber);
						ldap_msgfree(result);
						ldap_value_free(nc);
						return (NULL);
					}
					memset(&domains[num], 0,
					    sizeof (ad_disc_domainsinforest_t));
					if (decode_sid(sid_ber[0],
					    domains[num - 1].sid) < 0) {
						ldap_value_free_len(sid_ber);
						ldap_msgfree(result);
						ldap_value_free(nc);
						return (NULL);
					}
					ldap_value_free_len(sid_ber);

					name = DN_to_DNS(nc[i]);
					if (name == NULL) {
						free(domains);
						ldap_msgfree(result);
						ldap_value_free(nc);
						return (NULL);
					}
					strcpy(domains[num - 1].domain, name);
					free(name);
				}
			}
		}
		if (result != NULL)
			ldap_msgfree(result);
	}
	ldap_value_free(nc);

	return (domains);
}


ad_disc_t
ad_disc_init(void)
{
	struct ad_disc *ctx;
	ctx = calloc(1, sizeof (struct ad_disc));
	if (ctx != NULL)
		DO_RES_NINIT(ctx);

	ctx->domain_name.type = AD_STRING;
	ctx->domain_controller.type = AD_DIRECTORY;
	ctx->site_name.type = AD_STRING;
	ctx->forest_name.type = AD_STRING;
	ctx->global_catalog.type = AD_DIRECTORY;
	ctx->domains_in_forest.type = AD_DOMAINS_IN_FOREST;
	ctx->trusted_domains.type = AD_TRUSTED_DOMAINS;
	/* Site specific versions */
	ctx->site_domain_controller.type = AD_DIRECTORY;
	ctx->site_global_catalog.type = AD_DIRECTORY;
	return (ctx);
}


void
ad_disc_fini(ad_disc_t ctx)
{
	if (ctx == NULL)
		return;

	if (ctx->res_ninitted)
		res_ndestroy(&ctx->res_state);

	if (ctx->subnets != NULL)
		free(ctx->subnets);

	if (ctx->domain_name.value != NULL)
		free(ctx->domain_name.value);

	if (ctx->domain_controller.value != NULL)
		free(ctx->domain_controller.value);

	if (ctx->site_name.value != NULL)
		free(ctx->site_name.value);

	if (ctx->forest_name.value != NULL)
		free(ctx->forest_name.value);

	if (ctx->global_catalog.value != NULL)
		free(ctx->global_catalog.value);

	if (ctx->domains_in_forest.value != NULL)
		free(ctx->domains_in_forest.value);

	if (ctx->trusted_domains.value != NULL)
		free(ctx->trusted_domains.value);

	/* Site specific versions */
	if (ctx->site_domain_controller.value != NULL)
		free(ctx->site_domain_controller.value);

	if (ctx->site_global_catalog.value != NULL)
		free(ctx->site_global_catalog.value);

	free(ctx);
}

void
ad_disc_refresh(ad_disc_t ctx)
{
	if (ctx->res_ninitted)
		res_ndestroy(&ctx->res_state);
	(void) memset(&ctx->res_state, 0, sizeof (ctx->res_state));
	ctx->res_ninitted = res_ninit(&ctx->res_state) != -1;

	if (ctx->domain_name.state == AD_STATE_AUTO)
		ctx->domain_name.state = AD_STATE_INVALID;

	if (ctx->domain_controller.state == AD_STATE_AUTO)
		ctx->domain_controller.state  = AD_STATE_INVALID;

	if (ctx->site_name.state == AD_STATE_AUTO)
		ctx->site_name.state = AD_STATE_INVALID;

	if (ctx->forest_name.state == AD_STATE_AUTO)
		ctx->forest_name.state = AD_STATE_INVALID;

	if (ctx->global_catalog.state == AD_STATE_AUTO)
		ctx->global_catalog.state = AD_STATE_INVALID;

	if (ctx->domains_in_forest.state == AD_STATE_AUTO)
		ctx->domains_in_forest.state  = AD_STATE_INVALID;

	if (ctx->trusted_domains.state == AD_STATE_AUTO)
		ctx->trusted_domains.state  = AD_STATE_INVALID;

	if (ctx->site_domain_controller.state == AD_STATE_AUTO)
		ctx->site_domain_controller.state  = AD_STATE_INVALID;

	if (ctx->site_global_catalog.state == AD_STATE_AUTO)
		ctx->site_global_catalog.state = AD_STATE_INVALID;
}



/* Discover joined Active Directory domainName */
static ad_item_t *
validate_DomainName(ad_disc_t ctx)
{
	idmap_ad_disc_ds_t *domain_controller = NULL;
	char *dname, *srvname;
	uint32_t ttl = 0;

	if (is_valid(&ctx->domain_name))
		return (&ctx->domain_name);


	/* Try to find our domain by searching for DCs for it */
	DO_RES_NINIT(ctx);
	domain_controller = srv_query(&ctx->res_state, LDAP_SRV_HEAD
	    DC_SRV_TAIL, ctx->domain_name.value, &srvname, &ttl);

	/*
	 * If we can't find DCs by via res_nsearch() then there's no
	 * point in trying anything else to discover the AD domain name.
	 */
	if (domain_controller == NULL)
		return (NULL);

	free(domain_controller);
	/*
	 * We have the FQDN of the SRV RR name, so now we extract the
	 * domainname suffix from it.
	 */
	dname = strdup(srvname + strlen(LDAP_SRV_HEAD DC_SRV_TAIL) +
	    1 /* for the dot between RR name and domainname */);

	free(srvname);

	if (dname == NULL) {
		idmapdlog(LOG_ERR, "Out of memory");
		return (NULL);
	}

	/* Eat any trailing dot */
	if (*(dname + strlen(dname)) == '.')
		*(dname + strlen(dname)) = '\0';

	update_item(&ctx->domain_name, dname, AD_STATE_AUTO, ttl);

	return (&ctx->domain_name);
}


char *
ad_disc_get_DomainName(ad_disc_t ctx, int *auto_discovered)
{
	char *domain_name = NULL;
	ad_item_t *domain_name_item;

	domain_name_item = validate_DomainName(ctx);

	if (domain_name_item) {
		domain_name = strdup(domain_name_item->value);
		if (auto_discovered != NULL)
			*auto_discovered =
			    (domain_name_item->state == AD_STATE_AUTO);
	} else if (auto_discovered != NULL)
		*auto_discovered = FALSE;

	return (domain_name);
}


/* Discover domain controllers */
static ad_item_t *
validate_DomainController(ad_disc_t ctx, enum ad_disc_req req)
{
	uint32_t ttl = 0;
	idmap_ad_disc_ds_t *domain_controller = NULL;
	int validate_global = FALSE;
	int validate_site = FALSE;
	ad_item_t *domain_name_item;
	ad_item_t *site_name_item = NULL;

	/* If the values is fixed there will not be a site specific version */
	if (is_fixed(&ctx->domain_controller))
		return (&ctx->domain_controller);

	domain_name_item = validate_DomainName(ctx);
	if (domain_name_item == NULL)
		return (NULL);

	if (req == AD_DISC_GLOBAL)
		validate_global = TRUE;
	else {
		site_name_item = validate_SiteName(ctx);
		if (site_name_item != NULL)
			validate_site = TRUE;
		else if (req == AD_DISC_PREFER_SITE)
			validate_global = TRUE;
	}

	if (validate_global) {
		if (!is_valid(&ctx->domain_controller) ||
		    is_changed(&ctx->domain_controller, PARAM1,
		    domain_name_item)) {
			/*
			 * Lookup DNS SRV RR named
			 * _ldap._tcp.dc._msdcs.<DomainName>
			 */
			DO_RES_NINIT(ctx);
			domain_controller = srv_query(&ctx->res_state,
			    LDAP_SRV_HEAD DC_SRV_TAIL,
			    domain_name_item->value, NULL, &ttl);

			if (domain_controller == NULL)
				return (NULL);

			update_item(&ctx->domain_controller, domain_controller,
			    AD_STATE_AUTO, ttl);
			update_version(&ctx->domain_controller, PARAM1,
			    domain_name_item);
		}
		return (&ctx->domain_controller);
	}

	if (validate_site) {
		if (!is_valid(&ctx->site_domain_controller) ||
		    is_changed(&ctx->site_domain_controller, PARAM1,
		    domain_name_item) ||
		    is_changed(&ctx->site_domain_controller, PARAM2,
		    site_name_item)) {
			char rr_name[DNS_MAX_NAME];
			/*
			 * Lookup DNS SRV RR named
			 * _ldap._tcp.<SiteName>._sites.dc._msdcs.<DomainName>
			 */
			(void) snprintf(rr_name, sizeof (rr_name),
			    LDAP_SRV_HEAD SITE_SRV_MIDDLE DC_SRV_TAIL,
			    site_name_item->value);
			DO_RES_NINIT(ctx);
			domain_controller = srv_query(&ctx->res_state, rr_name,
			    domain_name_item->value, NULL, &ttl);
			if (domain_controller == NULL)
				return (NULL);

			update_item(&ctx->site_domain_controller,
			    domain_controller, AD_STATE_AUTO, ttl);
			update_version(&ctx->site_domain_controller, PARAM1,
			    domain_name_item);
			update_version(&ctx->site_domain_controller, PARAM2,
			    site_name_item);
		}
		return (&ctx->site_domain_controller);
	}
	return (NULL);
}

idmap_ad_disc_ds_t *
ad_disc_get_DomainController(ad_disc_t ctx, enum ad_disc_req req,
			int *auto_discovered)
{
	ad_item_t *domain_controller_item;
	idmap_ad_disc_ds_t *domain_controller = NULL;

	domain_controller_item = validate_DomainController(ctx, req);

	if (domain_controller_item != NULL) {
		domain_controller = ds_dup(domain_controller_item->value);
		if (auto_discovered != NULL)
			*auto_discovered =
			    (domain_controller_item->state == AD_STATE_AUTO);
	} else if (auto_discovered != NULL)
		*auto_discovered = FALSE;

	return (domain_controller);
}


/* Discover site name (for multi-homed systems the first one found wins) */
static ad_item_t *
validate_SiteName(ad_disc_t ctx)
{
	LDAP *ld = NULL;
	ad_subnet_t *subnets = NULL;
	char **dn_subnets = NULL;
	char *dn_root[2];
	char *config_naming_context = NULL;
	char *site_object = NULL;
	char *site_name = NULL;
	char *forest_name;
	int len;
	int i;
	int update_required = FALSE;
	ad_item_t *domain_controller_item;

	if (is_fixed(&ctx->site_name))
		return (&ctx->site_name);

	/* Can't rely on site-specific DCs */
	domain_controller_item = validate_DomainController(ctx, AD_DISC_GLOBAL);
	if (domain_controller_item == NULL)
		return (NULL);

	if (!is_valid(&ctx->site_name) ||
	    is_changed(&ctx->site_name, PARAM1, &ctx->domain_controller) ||
	    ctx->subnets == NULL || ctx->subnets_changed) {
		subnets = find_subnets();
		ctx->subnets_last_check = time(NULL);
		update_required = TRUE;
	} else if (ctx->subnets_last_check + 60 < time(NULL)) {
		subnets = find_subnets();
		ctx->subnets_last_check = time(NULL);
		if (cmpsubnets(ctx->subnets, subnets) != 0)
			update_required = TRUE;
	}

	if (!update_required) {
		free(subnets);
		return (&ctx->site_name);
	}

	if (subnets == NULL)
		return (NULL);

	dn_root[0] = "";
	dn_root[1] = NULL;

	config_naming_context = ldap_lookup_entry_attr(
	    &ld, ctx->domain_controller.value,
	    dn_root, "configurationNamingContext");
	if (config_naming_context == NULL)
		goto out;
	/*
	 * configurationNamingContext also provides the Forest
	 * Name.
	 */
	if (!is_fixed(&ctx->forest_name)) {
		/*
		 * The configurationNamingContext should be of
		 * form:
		 * CN=Configuration,<DNforestName>
		 * Remove the first part and convert to DNS form
		 * (replace ",DC=" with ".")
		 */
		char *str = "CN=Configuration,";
		int len = strlen(str);
		if (strncasecmp(config_naming_context, str, len) == 0) {
			forest_name = DN_to_DNS(config_naming_context + len);
			update_item(&ctx->forest_name, forest_name,
			    AD_STATE_AUTO, 0);
		}
	}

	dn_subnets = subnets_to_DNs(subnets, config_naming_context);
	if (dn_subnets == NULL)
		goto out;

	site_object = ldap_lookup_entry_attr(
	    &ld, domain_controller_item->value,
	    dn_subnets, "siteobject");
	if (site_object != NULL) {
		/*
		 * The site object should be of the form
		 * CN=<site>,CN=Sites,CN=Configuration,
		 *		<DN Domain>
		 */
		if (strncasecmp(site_object, "CN=", 3) == 0) {
			for (len = 0; site_object[len + 3] != ','; len++)
					;
			site_name = malloc(len + 1);
			(void) strncpy(site_name, &site_object[3], len);
			site_name[len] = '\0';
			update_item(&ctx->site_name, site_name,
			    AD_STATE_AUTO, 0);
		}
	}

	if (ctx->subnets != NULL) {
		free(ctx->subnets);
		ctx->subnets = NULL;
	}
	ctx->subnets = subnets;
	subnets = NULL;
	ctx->subnets_changed = FALSE;

out:
	if (ld != NULL)
		(void) ldap_unbind(ld);

	if (dn_subnets != NULL) {
		for (i = 0; dn_subnets[i] != NULL; i++)
			free(dn_subnets[i]);
		free(dn_subnets);
	}
	if (config_naming_context != NULL)
		free(config_naming_context);
	if (site_object != NULL)
		free(site_object);

	free(subnets);
	if (site_name == NULL)
		return (NULL);
	return (&ctx->site_name);

}


char *
ad_disc_get_SiteName(ad_disc_t ctx, int *auto_discovered)
{
	ad_item_t *site_name_item;
	char	*site_name = NULL;

	site_name_item = validate_SiteName(ctx);
	if (site_name_item != NULL) {
		site_name = strdup(site_name_item->value);
		if (auto_discovered != NULL)
			*auto_discovered =
			    (site_name_item->state == AD_STATE_AUTO);
	} else if (auto_discovered != NULL)
		*auto_discovered = FALSE;

	return (site_name);
}



/* Discover forest name */
static ad_item_t *
validate_ForestName(ad_disc_t ctx)
{
	LDAP	*ld = NULL;
	char	*config_naming_context;
	char	*forest_name = NULL;
	char	*dn_list[2];
	ad_item_t *domain_controller_item;

	if (is_fixed(&ctx->forest_name))
		return (&ctx->forest_name);
	/*
	 * We may not have a site name yet, so we won't rely on
	 * site-specific DCs.  (But maybe we could replace
	 * validate_ForestName() with validate_siteName()?)
	 */
	domain_controller_item = validate_DomainController(ctx, AD_DISC_GLOBAL);
	if (domain_controller_item == NULL)
		return (NULL);

	if (!is_valid(&ctx->forest_name) ||
	    is_changed(&ctx->forest_name, PARAM1, domain_controller_item)) {

		dn_list[0] = "";
		dn_list[1] = NULL;
		config_naming_context = ldap_lookup_entry_attr(
		    &ld, ctx->domain_controller.value,
		    dn_list, "configurationNamingContext");
		if (config_naming_context != NULL) {
			/*
			 * The configurationNamingContext should be of
			 * form:
			 * CN=Configuration,<DNforestName>
			 * Remove the first part and convert to DNS form
			 * (replace ",DC=" with ".")
			 */
			char *str = "CN=Configuration,";
			int len = strlen(str);
			if (strncasecmp(config_naming_context, str, len) == 0) {
				forest_name = DN_to_DNS(
				    config_naming_context + len);
			}
			free(config_naming_context);
		}
		if (ld != NULL)
			(void) ldap_unbind(ld);

		if (forest_name == NULL)
			return (NULL);

		update_item(&ctx->forest_name, forest_name, AD_STATE_AUTO, 0);
		update_version(&ctx->forest_name, PARAM1,
		    domain_controller_item);
	}
	return (&ctx->forest_name);
}


char *
ad_disc_get_ForestName(ad_disc_t ctx, int *auto_discovered)
{
	ad_item_t *forest_name_item;
	char	*forest_name = NULL;

	forest_name_item = validate_ForestName(ctx);

	if (forest_name_item != NULL) {
		forest_name = strdup(forest_name_item->value);
		if (auto_discovered != NULL)
			*auto_discovered =
			    (forest_name_item->state == AD_STATE_AUTO);
	} else if (auto_discovered != NULL)
		*auto_discovered = FALSE;

	return (forest_name);
}


/* Discover global catalog servers */
static ad_item_t *
validate_GlobalCatalog(ad_disc_t ctx, enum ad_disc_req req)
{
	idmap_ad_disc_ds_t *global_catalog = NULL;
	uint32_t ttl = 0;
	int	validate_global = FALSE;
	int	validate_site = FALSE;
	ad_item_t *forest_name_item;
	ad_item_t *site_name_item;

	/* If the values is fixed there will not be a site specific version */
	if (is_fixed(&ctx->global_catalog))
		return (&ctx->global_catalog);

	forest_name_item = validate_ForestName(ctx);
	if (forest_name_item == NULL)
		return (NULL);

	if (req == AD_DISC_GLOBAL)
		validate_global = TRUE;
	else {
		site_name_item = validate_SiteName(ctx);
		if (site_name_item != NULL)
			validate_site = TRUE;
		else if (req == AD_DISC_PREFER_SITE)
			validate_global = TRUE;
	}

	if (validate_global) {
		if (!is_valid(&ctx->global_catalog) ||
		    is_changed(&ctx->global_catalog, PARAM1,
		    forest_name_item)) {
			/*
			 * Lookup DNS SRV RR named
			 * _ldap._tcp.gc._msdcs.<ForestName>
			 */
			DO_RES_NINIT(ctx);
			global_catalog =
			    srv_query(&ctx->res_state,
			    LDAP_SRV_HEAD GC_SRV_TAIL,
			    ctx->forest_name.value, NULL, &ttl);

			if (global_catalog == NULL)
				return (NULL);

			update_item(&ctx->global_catalog, global_catalog,
			    AD_STATE_AUTO, ttl);
			update_version(&ctx->global_catalog, PARAM1,
			    forest_name_item);
		}
		return (&ctx->global_catalog);
	}

	if (validate_site) {
		if (!is_valid(&ctx->site_global_catalog) ||
		    is_changed(&ctx->site_global_catalog, PARAM1,
		    forest_name_item) ||
		    is_changed(&ctx->site_global_catalog, PARAM2,
		    site_name_item)) {
			char 	rr_name[DNS_MAX_NAME];

			/*
			 * Lookup DNS SRV RR named:
			 * _ldap._tcp.<siteName>._sites.gc.
			 *	_msdcs.<ForestName>
			 */
			(void) snprintf(rr_name,
			    sizeof (rr_name),
			    LDAP_SRV_HEAD SITE_SRV_MIDDLE GC_SRV_TAIL,
			    ctx->site_name.value);
			DO_RES_NINIT(ctx);
			global_catalog = srv_query(&ctx->res_state, rr_name,
			    ctx->forest_name.value, NULL, &ttl);

			if (global_catalog == NULL)
				return (NULL);
			update_item(&ctx->site_global_catalog, global_catalog,
			    AD_STATE_AUTO, ttl);
			update_version(&ctx->site_global_catalog, PARAM1,
			    forest_name_item);
			update_version(&ctx->site_global_catalog, PARAM2,
			    site_name_item);
		}
		return (&ctx->site_global_catalog);
	}
	return (NULL);
}


idmap_ad_disc_ds_t *
ad_disc_get_GlobalCatalog(ad_disc_t ctx, enum ad_disc_req req,
			int *auto_discovered)
{
	idmap_ad_disc_ds_t *global_catalog = NULL;
	ad_item_t *global_catalog_item;

	global_catalog_item = validate_GlobalCatalog(ctx, req);

	if (global_catalog_item != NULL) {
		global_catalog = ds_dup(global_catalog_item->value);
		if (auto_discovered != NULL)
			*auto_discovered =
			    (global_catalog_item->state == AD_STATE_AUTO);
	} else if (auto_discovered != NULL)
		*auto_discovered = FALSE;

	return (global_catalog);
}


static ad_item_t *
validate_TrustedDomains(ad_disc_t ctx)
{
	LDAP *ld = NULL;
	ad_item_t *global_catalog_item;
	ad_item_t *forest_name_item;
	ad_disc_trusteddomains_t *trusted_domains;
	char *dn = NULL;
	char *forest_name_dn;
	int len;
	int num_parts;

	if (is_fixed(&ctx->trusted_domains))
		return (&ctx->trusted_domains);

	global_catalog_item = validate_GlobalCatalog(ctx, AD_DISC_GLOBAL);
	if (global_catalog_item == NULL)
		return (NULL);

	forest_name_item = validate_ForestName(ctx);
	if (forest_name_item == NULL)
		return (NULL);

	if (!is_valid(&ctx->trusted_domains) ||
	    is_changed(&ctx->trusted_domains, PARAM1, global_catalog_item) ||
	    is_changed(&ctx->trusted_domains, PARAM2, forest_name_item)) {

		forest_name_dn = ldap_dns_to_dn(forest_name_item->value,
		    &num_parts);
		if (forest_name_dn == NULL)
			return (NULL);

		len = snprintf(NULL, 0, "CN=System,%s", forest_name_dn) + 1;
		dn = malloc(len);
		if (dn == NULL)  {
			free(forest_name_dn);
			return (NULL);
		}
		(void) snprintf(dn, len, "CN=System,%s", forest_name_dn);
		free(forest_name_dn);

		trusted_domains = ldap_lookup_trusted_domains(
		    &ld, global_catalog_item->value, dn);

		if (ld != NULL)
			(void) ldap_unbind(ld);
		free(dn);

		if (trusted_domains == NULL)
			return (NULL);

		update_item(&ctx->trusted_domains, trusted_domains,
		    AD_STATE_AUTO, 0);
		update_version(&ctx->trusted_domains, PARAM1,
		    global_catalog_item);
		update_version(&ctx->trusted_domains, PARAM2,
		    forest_name_item);
	}

	return (&ctx->trusted_domains);
}


ad_disc_trusteddomains_t *
ad_disc_get_TrustedDomains(ad_disc_t ctx, int *auto_discovered)
{
	ad_disc_trusteddomains_t *trusted_domains = NULL;
	ad_item_t *trusted_domains_item;

	trusted_domains_item = validate_TrustedDomains(ctx);

	if (trusted_domains_item != NULL) {
		trusted_domains = td_dup(trusted_domains_item->value);
		if (auto_discovered != NULL)
			*auto_discovered =
			    (trusted_domains_item->state == AD_STATE_AUTO);
	} else if (auto_discovered != NULL)
		*auto_discovered = FALSE;

	return (trusted_domains);
}


static ad_item_t *
validate_DomainsInForest(ad_disc_t ctx)
{
	ad_item_t *global_catalog_item;
	LDAP *ld = NULL;
	ad_disc_domainsinforest_t *domains_in_forest;

	if (is_fixed(&ctx->domains_in_forest))
		return (&ctx->domains_in_forest);

	global_catalog_item = validate_GlobalCatalog(ctx, AD_DISC_GLOBAL);
	if (global_catalog_item == NULL)
		return (NULL);

	if (!is_valid(&ctx->domains_in_forest) ||
	    is_changed(&ctx->domains_in_forest, PARAM1, global_catalog_item)) {

		domains_in_forest = ldap_lookup_domains_in_forest(
		    &ld, global_catalog_item->value);

		if (ld != NULL)
			(void) ldap_unbind(ld);

		if (domains_in_forest == NULL)
			return (NULL);

		update_item(&ctx->domains_in_forest, domains_in_forest,
		    AD_STATE_AUTO, 0);
		update_version(&ctx->domains_in_forest, PARAM1,
		    global_catalog_item);
	}
	return (&ctx->domains_in_forest);
}


ad_disc_domainsinforest_t *
ad_disc_get_DomainsInForest(ad_disc_t ctx, int *auto_discovered)
{
	ad_disc_domainsinforest_t *domains_in_forest = NULL;
	ad_item_t *domains_in_forest_item;

	domains_in_forest_item = validate_DomainsInForest(ctx);

	if (domains_in_forest_item != NULL) {
		domains_in_forest = df_dup(domains_in_forest_item->value);
		if (auto_discovered != NULL)
			*auto_discovered =
			    (domains_in_forest_item->state == AD_STATE_AUTO);
	} else if (auto_discovered != NULL)
		*auto_discovered = FALSE;

	return (domains_in_forest);
}




int
ad_disc_set_DomainName(ad_disc_t ctx, const char *domainName)
{
	char *domain_name = NULL;
	if (domainName != NULL) {
		domain_name = strdup(domainName);
		if (domain_name == NULL)
			return (-1);
		update_item(&ctx->domain_name, domain_name,
		    AD_STATE_FIXED, 0);
	} else if (ctx->domain_name.state == AD_STATE_FIXED)
		ctx->domain_name.state = AD_STATE_INVALID;
	return (0);
}


int
ad_disc_set_DomainController(ad_disc_t ctx,
				const idmap_ad_disc_ds_t *domainController)
{
	idmap_ad_disc_ds_t *domain_controller = NULL;
	if (domainController != NULL) {
		domain_controller = ds_dup(domainController);
		if (domain_controller == NULL)
			return (-1);
		update_item(&ctx->domain_controller, domain_controller,
		    AD_STATE_FIXED, 0);
	} else if (ctx->domain_controller.state == AD_STATE_FIXED)
		ctx->domain_controller.state = AD_STATE_INVALID;
	return (0);
}


int
ad_disc_set_SiteName(ad_disc_t ctx, const char *siteName)
{
	char *site_name = NULL;
	if (siteName != NULL) {
		site_name = strdup(siteName);
		if (site_name == NULL)
			return (-1);
		update_item(&ctx->site_name, site_name, AD_STATE_FIXED, 0);
	} else if (ctx->site_name.state == AD_STATE_FIXED)
		ctx->site_name.state = AD_STATE_INVALID;
	return (0);
}

int
ad_disc_set_ForestName(ad_disc_t ctx, const char *forestName)
{
	char *forest_name = NULL;
	if (forestName != NULL) {
		forest_name = strdup(forestName);
		if (forest_name == NULL)
			return (-1);
		update_item(&ctx->forest_name, forest_name,
		    AD_STATE_FIXED, 0);
	} else if (ctx->forest_name.state == AD_STATE_FIXED)
		ctx->forest_name.state = AD_STATE_INVALID;
	return (0);
}

int
ad_disc_set_GlobalCatalog(ad_disc_t ctx,
    const idmap_ad_disc_ds_t *globalCatalog)
{
	idmap_ad_disc_ds_t *global_catalog = NULL;
	if (globalCatalog != NULL) {
		global_catalog = ds_dup(globalCatalog);
		if (global_catalog == NULL)
			return (-1);
		update_item(&ctx->global_catalog, global_catalog,
		    AD_STATE_FIXED, 0);
	} else if (ctx->global_catalog.state == AD_STATE_FIXED)
		ctx->global_catalog.state = AD_STATE_INVALID;
	return (0);
}


int
ad_disc_unset(ad_disc_t ctx)
{
	if (ctx->domain_name.state == AD_STATE_FIXED)
		ctx->domain_name.state =  AD_STATE_INVALID;

	if (ctx->domain_controller.state == AD_STATE_FIXED)
		ctx->domain_controller.state =  AD_STATE_INVALID;

	if (ctx->site_name.state == AD_STATE_FIXED)
		ctx->site_name.state =  AD_STATE_INVALID;

	if (ctx->forest_name.state == AD_STATE_FIXED)
		ctx->forest_name.state =  AD_STATE_INVALID;

	if (ctx->global_catalog.state == AD_STATE_FIXED)
		ctx->global_catalog.state =  AD_STATE_INVALID;

	return (0);
}

/*
 * ad_disc_get_TTL
 *
 * This routines the time to live for AD
 * auto discovered items.
 *
 *	Returns:
 *		-1 if there are no TTL items
 *		0  if there are expired items
 *		else the number of seconds
 *
 * The MIN_GT_ZERO(x, y) macro return the lesser of x and y, provided it
 * is positive -- min() greater than zero.
 */
#define	MIN_GT_ZERO(x, y) (((x) <= 0) ? (((y) <= 0) ? \
		(-1) : (y)) : (((y) <= 0) ? (x) : (((x) > (y)) ? (y) : (x))))
int
ad_disc_get_TTL(ad_disc_t ctx)
{
	int ttl;

	ttl = MIN_GT_ZERO(ctx->domain_controller.ttl, ctx->global_catalog.ttl);
	ttl = MIN_GT_ZERO(ttl, ctx->site_domain_controller.ttl);
	ttl = MIN_GT_ZERO(ttl, ctx->site_global_catalog.ttl);

	if (ttl == -1)
		return (-1);
	ttl -= time(NULL);
	if (ttl < 0)
		return (0);
	return (ttl);
}

int
ad_disc_SubnetChanged(ad_disc_t ctx)
{
	ad_subnet_t *subnets;

	if (ctx->subnets_changed || ctx->subnets == NULL)
		return (TRUE);

	if ((subnets = find_subnets()) != NULL) {
		if (cmpsubnets(subnets, ctx->subnets) != 0)
			ctx->subnets_changed = TRUE;
		free(subnets);
	}

	return (ctx->subnets_changed);
}
