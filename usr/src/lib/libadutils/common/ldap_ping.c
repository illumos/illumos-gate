/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
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
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>
#include <ctype.h>
#include <errno.h>
#include <ldap.h>
#include <lber.h>
#include <syslog.h>
#include "adutils_impl.h"
#include "addisc_impl.h"

#define	LDAP_PORT	389

#define	NETLOGON_ATTR_NAME			"NetLogon"
#define	NETLOGON_NT_VERSION_1			0x00000001
#define	NETLOGON_NT_VERSION_5			0x00000002
#define	NETLOGON_NT_VERSION_5EX			0x00000004
#define	NETLOGON_NT_VERSION_5EX_WITH_IP		0x00000008
#define	NETLOGON_NT_VERSION_WITH_CLOSEST_SITE	0x00000010
#define	NETLOGON_NT_VERSION_AVOID_NT4EMUL	0x01000000

typedef enum {
	OPCODE = 0,
	SBZ,
	FLAGS,
	DOMAIN_GUID,
	FOREST_NAME,
	DNS_DOMAIN_NAME,
	DNS_HOST_NAME,
	NET_DOMAIN_NAME,
	NET_COMP_NAME,
	USER_NAME,
	DC_SITE_NAME,
	CLIENT_SITE_NAME,
	SOCKADDR_SIZE,
	SOCKADDR,
	NEXT_CLOSEST_SITE_NAME,
	NTVER,
	LM_NT_TOKEN,
	LM_20_TOKEN
} field_5ex_t;

struct _berelement {
	char	*ber_buf;
	char	*ber_ptr;
	char	*ber_end;
};

extern int ldap_put_filter(BerElement *ber, char *);
static void send_to_cds(ad_disc_cds_t *, char *, size_t, int);
static ad_disc_cds_t *find_cds_by_addr(ad_disc_cds_t *, struct sockaddr_in6 *);
static boolean_t addrmatch(struct addrinfo *, struct sockaddr_in6 *);
static void save_ai(ad_disc_cds_t *, struct addrinfo *);

static void
cldap_escape_le64(char *buf, uint64_t val, int bytes)
{
	char *p = buf;

	while (bytes != 0) {
		p += sprintf(p, "\\%.2x", (uint8_t)(val & 0xff));
		val >>= 8;
		bytes--;
	}
	*p = '\0';
}

/*
 * Construct CLDAPMessage PDU for NetLogon search request.
 *
 *  CLDAPMessage ::= SEQUENCE {
 *      messageID       MessageID,
 *      protocolOp      searchRequest   SearchRequest;
 *  }
 *
 *  SearchRequest ::=
 *      [APPLICATION 3] SEQUENCE {
 *          baseObject    LDAPDN,
 *          scope         ENUMERATED {
 *                             baseObject            (0),
 *                             singleLevel           (1),
 *                             wholeSubtree          (2)
 *                        },
 *          derefAliases  ENUMERATED {
 *                                     neverDerefAliases     (0),
 *                                     derefInSearching      (1),
 *                                     derefFindingBaseObj   (2),
 *                                     derefAlways           (3)
 *                                },
 *          sizeLimit     INTEGER (0 .. MaxInt),
 *          timeLimit     INTEGER (0 .. MaxInt),
 *          attrsOnly     BOOLEAN,
 *          filter        Filter,
 *          attributes    SEQUENCE OF AttributeType
 *  }
 */
BerElement *
cldap_build_request(const char *dname,
	const char *host, uint32_t ntver, uint16_t msgid)
{
	BerElement 	*ber;
	int		len = 0;
	char		*basedn = "";
	int scope = LDAP_SCOPE_BASE, deref = LDAP_DEREF_NEVER,
	    sizelimit = 0, timelimit = 0, attrsonly = 0;
	char		filter[512];
	char		ntver_esc[13];
	char		*p, *pend;

	/*
	 * Construct search filter in LDAP format.
	 */
	p = filter;
	pend = p + sizeof (filter);

	len = snprintf(p, pend - p, "(&(DnsDomain=%s)", dname);
	if (len >= (pend - p))
		goto fail;
	p += len;

	if (host != NULL) {
		len = snprintf(p, (pend - p), "(Host=%s)", host);
		if (len >= (pend - p))
			goto fail;
		p += len;
	}

	if (ntver != 0) {
		/*
		 * Format NtVer as little-endian with LDAPv3 escapes.
		 */
		cldap_escape_le64(ntver_esc, ntver, sizeof (ntver));
		len = snprintf(p, (pend - p), "(NtVer=%s)", ntver_esc);
		if (len >= (pend - p))
			goto fail;
		p += len;
	}

	len = snprintf(p, pend - p, ")");
	if (len >= (pend - p))
		goto fail;
	p += len;

	/*
	 * Encode CLDAPMessage and beginning of SearchRequest sequence.
	 */

	if ((ber = ber_alloc()) == NULL)
		goto fail;

	if (ber_printf(ber, "{it{seeiib", msgid,
	    LDAP_REQ_SEARCH, basedn, scope, deref,
	    sizelimit, timelimit, attrsonly) < 0)
		goto fail;

	/*
	 * Encode Filter sequence.
	 */
	if (ldap_put_filter(ber, filter) < 0)
		goto fail;
	/*
	 * Encode attribute and close Filter and SearchRequest sequences.
	 */
	if (ber_printf(ber, "{s}}}", NETLOGON_ATTR_NAME) < 0)
		goto fail;

	/*
	 * Success
	 */
	return (ber);

fail:
	if (ber != NULL)
		ber_free(ber, 1);
	return (NULL);
}

/*
 * Parse incoming search responses and attribute to correct hosts.
 *
 *  CLDAPMessage ::= SEQUENCE {
 *     messageID       MessageID,
 *                     searchResponse  SEQUENCE OF
 *                                         SearchResponse;
 *  }
 *
 *  SearchResponse ::=
 *    CHOICE {
 *         entry          [APPLICATION 4] SEQUENCE {
 *                             objectName     LDAPDN,
 *                             attributes     SEQUENCE OF SEQUENCE {
 *                                              AttributeType,
 *                                              SET OF
 *                                                AttributeValue
 *                                            }
 *                        },
 *         resultCode     [APPLICATION 5] LDAPResult
 *    }
 */

static int
decode_name(uchar_t *base, uchar_t *cp, char *str)
{
	uchar_t *tmp = NULL, *st = cp;
	uint8_t len;

	/*
	 * there should probably be some boundary checks on str && cp
	 * maybe pass in strlen && msglen ?
	 */
	while (*cp != 0) {
		if (*cp == 0xc0) {
			if (tmp == NULL)
				tmp = cp + 2;
			cp = base + *(cp + 1);
		}
		for (len = *cp++; len > 0; len--)
			*str++ = *cp++;
		*str++ = '.';
	}
	if (cp != st)
		*(str-1) = '\0';
	else
		*str = '\0';

	return ((tmp == NULL ? cp + 1 : tmp) - st);
}

static int
cldap_parse(ad_disc_t ctx, ad_disc_cds_t *cds, BerElement *ber)
{
	ad_disc_ds_t *dc = &cds->cds_ds;
	uchar_t *base = NULL, *cp = NULL;
	char val[512]; /* how big should val be? */
	int l, msgid, rc = 0;
	uint16_t opcode;
	field_5ex_t f = OPCODE;

	/*
	 * Later, compare msgid's/some validation?
	 */

	if (ber_scanf(ber, "{i{x{{x[la", &msgid, &l, &cp) == LBER_ERROR) {
		rc = 1;
		goto out;
	}

	for (base = cp; ((cp - base) < l) && (f <= LM_20_TOKEN); f++) {
		val[0] = '\0';
		switch (f) {
		case OPCODE:
			/* opcode = *(uint16_t *)cp; */
			/* cp +=2; */
			opcode = *cp++;
			opcode |= (*cp++ << 8);
			break;
		case SBZ:
			cp += 2;
			break;
		case FLAGS:
			/* dci->Flags = *(uint32_t *)cp; */
			/* cp +=4; */
			dc->flags = *cp++;
			dc->flags |= (*cp++ << 8);
			dc->flags |= (*cp++ << 16);
			dc->flags |= (*cp++ << 26);
			break;
		case DOMAIN_GUID:
			if (ctx != NULL)
				auto_set_DomainGUID(ctx, cp);
			cp += 16;
			break;
		case FOREST_NAME:
			cp += decode_name(base, cp, val);
			if (ctx != NULL)
				auto_set_ForestName(ctx, val);
			break;
		case DNS_DOMAIN_NAME:
			/*
			 * We always have this already.
			 * (Could validate it here.)
			 */
			cp += decode_name(base, cp, val);
			break;
		case DNS_HOST_NAME:
			cp += decode_name(base, cp, val);
			if (0 != strcasecmp(val, dc->host)) {
				logger(LOG_ERR, "DC name %s != %s?",
				    val, dc->host);
			}
			break;
		case NET_DOMAIN_NAME:
			/*
			 * This is the "Flat" domain name.
			 * (i.e. the NetBIOS name)
			 * ignore for now.
			 */
			cp += decode_name(base, cp, val);
			break;
		case NET_COMP_NAME:
			/* not needed */
			cp += decode_name(base, cp, val);
			break;
		case USER_NAME:
			/* not needed */
			cp += decode_name(base, cp, val);
			break;
		case DC_SITE_NAME:
			cp += decode_name(base, cp, val);
			(void) strlcpy(dc->site, val, sizeof (dc->site));
			break;
		case CLIENT_SITE_NAME:
			cp += decode_name(base, cp, val);
			if (ctx != NULL)
				auto_set_SiteName(ctx, val);
			break;
		/*
		 * These are all possible, but we don't really care about them.
		 * Sockaddr_size && sockaddr might be useful at some point
		 */
		case SOCKADDR_SIZE:
		case SOCKADDR:
		case NEXT_CLOSEST_SITE_NAME:
		case NTVER:
		case LM_NT_TOKEN:
		case LM_20_TOKEN:
			break;
		default:
			rc = 3;
			goto out;
		}
	}

out:
	if (base)
		free(base);
	else if (cp)
		free(cp);
	return (rc);
}


/*
 * Filter out unresponsive servers, and save the domain info
 * returned by the "LDAP ping" in the returned object.
 * If ctx != NULL, this is a query for a DC, in which case we
 * also save the Domain GUID, Site name, and Forest name as
 * "auto" (discovered) values in the ctx.
 *
 * Only return the "winner".  (We only want one DC/GC)
 */
ad_disc_ds_t *
ldap_ping(ad_disc_t ctx, ad_disc_cds_t *dclist, char *dname, int reqflags)
{
	struct sockaddr_in6 addr6;
	socklen_t addrlen;
	struct pollfd pingchk;
	ad_disc_cds_t *send_ds;
	ad_disc_cds_t *recv_ds = NULL;
	ad_disc_ds_t *ret_ds = NULL;
	BerElement *req = NULL;
	BerElement *res = NULL;
	struct _berelement *be, *rbe;
	size_t be_len, rbe_len;
	int fd = -1;
	int tries = 3;
	int waitsec;
	int r;
	uint16_t msgid;

	/* One plus a null entry. */
	ret_ds = calloc(2, sizeof (ad_disc_ds_t));
	if (ret_ds == NULL)
		goto fail;

	if ((fd = socket(PF_INET6, SOCK_DGRAM, 0)) < 0)
		goto fail;

	(void) memset(&addr6, 0, sizeof (addr6));
	addr6.sin6_family = AF_INET6;
	addr6.sin6_addr = in6addr_any;
	if (bind(fd, (struct sockaddr *)&addr6, sizeof (addr6)) < 0)
		goto fail;

	/*
	 * semi-unique msgid...
	 */
	msgid = gethrtime() & 0xffff;

	/*
	 * Is ntver right? It certainly works on w2k8... If others are needed,
	 * that might require changes to cldap_parse
	 */
	req = cldap_build_request(dname, NULL,
	    NETLOGON_NT_VERSION_5EX, msgid);
	if (req == NULL)
		goto fail;
	be = (struct _berelement *)req;
	be_len = be->ber_end - be->ber_buf;

	if ((res = ber_alloc()) == NULL)
		goto fail;
	rbe = (struct _berelement *)res;
	rbe_len = rbe->ber_end - rbe->ber_buf;

	pingchk.fd = fd;
	pingchk.events = POLLIN;
	pingchk.revents = 0;

try_again:
	send_ds = dclist;
	waitsec = 5;
	while (recv_ds == NULL && waitsec > 0) {

		/*
		 * If there is another candidate, send to it.
		 */
		if (send_ds->cds_ds.host[0] != '\0') {
			send_to_cds(send_ds, be->ber_buf, be_len, fd);
			send_ds++;

			/*
			 * Wait 1/10 sec. before the next send.
			 */
			r = poll(&pingchk, 1, 100);
#if 0 /* DEBUG */
			/* Drop all responses 1st pass. */
			if (waitsec == 5)
				r = 0;
#endif
		} else {
			/*
			 * No more candidates to "ping", so
			 * just wait a sec for responses.
			 */
			r = poll(&pingchk, 1, 1000);
			if (r == 0)
				--waitsec;
		}

		if (r > 0) {
			/*
			 * Got a response.
			 */
			(void) memset(&addr6, 0, addrlen = sizeof (addr6));
			r = recvfrom(fd, rbe->ber_buf, rbe_len, 0,
			    (struct sockaddr *)&addr6, &addrlen);

			recv_ds = find_cds_by_addr(dclist, &addr6);
			if (recv_ds == NULL)
				continue;

			(void) cldap_parse(ctx, recv_ds, res);
			if ((recv_ds->cds_ds.flags & reqflags) != reqflags) {
				logger(LOG_ERR, "Skip %s"
				    "due to flags 0x%X",
				    recv_ds->cds_ds.host,
				    recv_ds->cds_ds.flags);
				recv_ds = NULL;
			}
		}
	}

	if (recv_ds == NULL) {
		if (--tries <= 0)
			goto fail;
		goto try_again;
	}

	(void) memcpy(ret_ds, recv_ds, sizeof (*ret_ds));

	ber_free(res, 1);
	ber_free(req, 1);
	(void) close(fd);
	return (ret_ds);

fail:
	ber_free(res, 1);
	ber_free(req, 1);
	(void) close(fd);
	free(ret_ds);
	return (NULL);
}

/*
 * Attempt a send of the LDAP request to all known addresses
 * for this candidate server.
 */
static void
send_to_cds(ad_disc_cds_t *send_cds, char *ber_buf, size_t be_len, int fd)
{
	struct sockaddr_in6 addr6;
	struct addrinfo *ai;
	int err;

	if (DBG(DISC, 2)) {
		logger(LOG_DEBUG, "send to: %s", send_cds->cds_ds.host);
	}

	for (ai = send_cds->cds_ai; ai != NULL; ai = ai->ai_next) {

		/*
		 * Build the "to" address.
		 */
		(void) memset(&addr6, 0, sizeof (addr6));
		if (ai->ai_family == AF_INET6) {
			(void) memcpy(&addr6, ai->ai_addr, sizeof (addr6));
		} else if (ai->ai_family == AF_INET) {
			struct sockaddr_in *sin =
			    (void *)ai->ai_addr;
			addr6.sin6_family = AF_INET6;
			IN6_INADDR_TO_V4MAPPED(&sin->sin_addr,
			    &addr6.sin6_addr);
		} else {
			continue;
		}
		addr6.sin6_port = htons(LDAP_PORT);

		/*
		 * Send the "ping" to this address.
		 */
		err = sendto(fd, ber_buf, be_len, 0,
		    (struct sockaddr *)&addr6, sizeof (addr6));
		err = (err < 0) ? errno : 0;

		if (DBG(DISC, 2)) {
			char abuf[INET6_ADDRSTRLEN];
			const char *pa;

			pa = inet_ntop(AF_INET6,
			    &addr6.sin6_addr,
			    abuf, sizeof (abuf));
			logger(LOG_ERR, "  > %s rc=%d",
			    pa ? pa : "?", err);
		}
	}
}

/*
 * We have a response from some address.  Find the candidate with
 * this address.  In case a candidate had multiple addresses, we
 * keep track of which the response came from.
 */
static ad_disc_cds_t *
find_cds_by_addr(ad_disc_cds_t *dclist, struct sockaddr_in6 *sin6from)
{
	char abuf[INET6_ADDRSTRLEN];
	ad_disc_cds_t *ds;
	struct addrinfo *ai;
	int eai;

	if (DBG(DISC, 1)) {
		eai = getnameinfo((void *)sin6from, sizeof (*sin6from),
		    abuf, sizeof (abuf), NULL, 0, NI_NUMERICHOST);
		if (eai != 0)
			(void) strlcpy(abuf, "?", sizeof (abuf));
		logger(LOG_DEBUG, "LDAP ping resp: addr=%s", abuf);
	}

	/*
	 * Find the DS this response came from.
	 * (don't accept unexpected responses)
	 */
	for (ds = dclist; ds->cds_ds.host[0] != '\0'; ds++) {
		ai = ds->cds_ai;
		while (ai != NULL) {
			if (addrmatch(ai, sin6from))
				goto found;
			ai = ai->ai_next;
		}
	}
	if (DBG(DISC, 1)) {
		logger(LOG_DEBUG, "  (unexpected)");
	}
	return (NULL);

found:
	if (DBG(DISC, 2)) {
		logger(LOG_DEBUG, "  from %s", ds->cds_ds.host);
	}
	save_ai(ds, ai);
	return (ds);
}

static boolean_t
addrmatch(struct addrinfo *ai, struct sockaddr_in6 *sin6from)
{

	/*
	 * Note: on a GC query, the ds->addr port numbers are
	 * the GC port, and our from addr has the LDAP port.
	 * Just compare the IP addresses.
	 */

	if (ai->ai_family == AF_INET6) {
		struct sockaddr_in6 *sin6p = (void *)ai->ai_addr;

		if (!memcmp(&sin6from->sin6_addr, &sin6p->sin6_addr,
		    sizeof (struct in6_addr)))
			return (B_TRUE);
	}

	if (ai->ai_family == AF_INET) {
		struct in6_addr in6;
		struct sockaddr_in *sin4p = (void *)ai->ai_addr;

		IN6_INADDR_TO_V4MAPPED(&sin4p->sin_addr, &in6);
		if (!memcmp(&sin6from->sin6_addr, &in6,
		    sizeof (struct in6_addr)))
			return (B_TRUE);
	}

	return (B_FALSE);
}

static void
save_ai(ad_disc_cds_t *cds, struct addrinfo *ai)
{
	ad_disc_ds_t *ds = &cds->cds_ds;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;

	/*
	 * If this DS already saw a response, keep the first
	 * address from which we received a response.
	 */
	if (ds->addr.ss_family != 0) {
		if (DBG(DISC, 2))
			logger(LOG_DEBUG, "already have an address");
		return;
	}

	switch (ai->ai_family) {
	case AF_INET:
		sin = (void *)&ds->addr;
		(void) memcpy(sin, ai->ai_addr, sizeof (*sin));
		sin->sin_port = htons(ds->port);
		break;

	case AF_INET6:
		sin6 = (void *)&ds->addr;
		(void) memcpy(sin6, ai->ai_addr, sizeof (*sin6));
		sin6->sin6_port = htons(ds->port);
		break;

	default:
		logger(LOG_ERR, "bad AF %d", ai->ai_family);
	}
}
