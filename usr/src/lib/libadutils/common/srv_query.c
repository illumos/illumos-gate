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
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * DNS query helper functions for addisc.c
 */

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
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
#include <sasl/sasl.h>
#include <sys/u8_textprep.h>
#include <syslog.h>
#include <uuid/uuid.h>
#include <ads/dsgetdc.h>
#include "adutils_impl.h"
#include "addisc_impl.h"

static void save_addr(ad_disc_cds_t *, sa_family_t, uchar_t *, size_t);
static struct addrinfo *make_addrinfo(sa_family_t, uchar_t *, size_t);

static void do_getaddrinfo(ad_disc_cds_t *);
static ad_disc_cds_t *srv_parse(uchar_t *, int, int *, int *);
static void add_preferred(ad_disc_cds_t *, ad_disc_ds_t *, int *, int);
static void get_addresses(ad_disc_cds_t *, int);

/*
 * Simplified version of srv_query() for domain auto-discovery.
 */
int
srv_getdom(res_state state, const char *svc_name, char **rrname)
{
	union {
		HEADER hdr;
		uchar_t buf[NS_MAXMSG];
	} msg;
	int len, qdcount, ancount;
	uchar_t *ptr, *eom;
	char namebuf[NS_MAXDNAME];

	/* query necessary resource records */

	*rrname = NULL;
	if (DBG(DNS, 1))  {
		logger(LOG_DEBUG, "Looking for SRV RRs '%s.*'", svc_name);
	}
	len = res_nsearch(state, svc_name, C_IN, T_SRV,
	    msg.buf, sizeof (msg.buf));
	if (len < 0) {
		if (DBG(DNS, 0)) {
			logger(LOG_DEBUG,
			    "DNS search for '%s' failed (%s)",
			    svc_name, hstrerror(state->res_h_errno));
		}
		return (-1);
	}

	if (len > sizeof (msg.buf)) {
		logger(LOG_WARNING,
		    "DNS query %ib message doesn't fit into %ib buffer",
		    len, sizeof (msg.buf));
		len = sizeof (msg.buf);
	}

	/* parse the reply header */

	ptr = msg.buf + sizeof (msg.hdr);
	eom = msg.buf + len;
	qdcount = ntohs(msg.hdr.qdcount);
	ancount = ntohs(msg.hdr.ancount);

	/* skip the question section */

	len = ns_skiprr(ptr, eom, ns_s_qd, qdcount);
	if (len < 0) {
		logger(LOG_ERR, "DNS query invalid message format");
		return (-1);
	}
	ptr += len;

	/* parse the answer section */
	if (ancount < 1) {
		logger(LOG_ERR, "DNS query - no answers");
		return (-1);
	}

	len = dn_expand(msg.buf, eom, ptr, namebuf, sizeof (namebuf));
	if (len < 0) {
		logger(LOG_ERR, "DNS query invalid message format");
		return (-1);
	}
	*rrname = strdup(namebuf);
	if (*rrname == NULL) {
		logger(LOG_ERR, "Out of memory");
		return (-1);
	}

	return (0);
}


/*
 * Compare SRC RRs; used with qsort().  Sort order:
 * "Earliest" (lowest number) priority first,
 * then weight highest to lowest.
 */
static int
srvcmp(ad_disc_ds_t *s1, ad_disc_ds_t *s2)
{
	if (s1->priority < s2->priority)
		return (-1);
	else if (s1->priority > s2->priority)
		return (1);

	if (s1->weight < s2->weight)
		return (1);
	else if (s1->weight > s2->weight)
		return (-1);

	return (0);
}

/*
 * Query or search the SRV RRs for a given name.
 *
 * If dname == NULL then search (as in res_nsearch(3RESOLV), honoring any
 * search list/option), else query (as in res_nquery(3RESOLV)).
 *
 * The output TTL will be the one of the SRV RR with the lowest TTL.
 */
ad_disc_cds_t *
srv_query(res_state state, const char *svc_name, const char *dname,
    ad_disc_ds_t *prefer)
{
	ad_disc_cds_t *cds_res = NULL;
	uchar_t *msg = NULL;
	int len, scnt, maxcnt;

	msg = malloc(NS_MAXMSG);
	if (msg == NULL) {
		logger(LOG_ERR, "Out of memory");
		return (NULL);
	}

	/* query necessary resource records */

	/* Search, querydomain or query */
	if (dname == NULL) {
		dname = "*";
		if (DBG(DNS, 1))  {
			logger(LOG_DEBUG, "Looking for SRV RRs '%s.*'",
			    svc_name);
		}
		len = res_nsearch(state, svc_name, C_IN, T_SRV,
		    msg, NS_MAXMSG);
		if (len < 0) {
			if (DBG(DNS, 0)) {
				logger(LOG_DEBUG,
				    "DNS search for '%s' failed (%s)",
				    svc_name, hstrerror(state->res_h_errno));
			}
			goto errout;
		}
	} else { /* dname != NULL */
		if (DBG(DNS, 1)) {
			logger(LOG_DEBUG, "Looking for SRV RRs '%s.%s' ",
			    svc_name, dname);
		}

		len = res_nquerydomain(state, svc_name, dname, C_IN, T_SRV,
		    msg, NS_MAXMSG);

		if (len < 0) {
			if (DBG(DNS, 0)) {
				logger(LOG_DEBUG, "DNS: %s.%s: %s",
				    svc_name, dname,
				    hstrerror(state->res_h_errno));
			}
			goto errout;
		}
	}

	if (len > NS_MAXMSG) {
		logger(LOG_WARNING,
		    "DNS query %ib message doesn't fit into %ib buffer",
		    len, NS_MAXMSG);
		len = NS_MAXMSG;
	}


	/* parse the reply header */

	cds_res = srv_parse(msg, len, &scnt, &maxcnt);
	if (cds_res == NULL)
		goto errout;

	if (prefer != NULL)
		add_preferred(cds_res, prefer, &scnt, maxcnt);

	get_addresses(cds_res, scnt);

	/* sort list of candidates */
	if (scnt > 1)
		qsort(cds_res, scnt, sizeof (*cds_res),
		    (int (*)(const void *, const void *))srvcmp);

	free(msg);
	return (cds_res);

errout:
	free(msg);
	return (NULL);
}

static ad_disc_cds_t *
srv_parse(uchar_t *msg, int len, int *scnt, int *maxcnt)
{
	ad_disc_cds_t *cds;
	ad_disc_cds_t *cds_res = NULL;
	HEADER *hdr;
	int i, qdcount, ancount, nscount, arcount;
	uchar_t *ptr, *eom;
	uchar_t *end;
	uint16_t type;
	/* LINTED  E_FUNC_SET_NOT_USED */
	uint16_t class;
	uint32_t rttl;
	uint16_t size;
	char namebuf[NS_MAXDNAME];

	eom = msg + len;
	hdr = (void *)msg;
	ptr = msg + sizeof (HEADER);

	qdcount = ntohs(hdr->qdcount);
	ancount = ntohs(hdr->ancount);
	nscount = ntohs(hdr->nscount);
	arcount = ntohs(hdr->arcount);

	/* skip the question section */

	len = ns_skiprr(ptr, eom, ns_s_qd, qdcount);
	if (len < 0) {
		logger(LOG_ERR, "DNS query invalid message format");
		return (NULL);
	}
	ptr += len;

	/*
	 * Walk through the answer section, building the result array.
	 * The array size is +2 because we (possibly) add the preferred
	 * DC if it was not there, and an empty one (null termination).
	 */

	*maxcnt = ancount + 2;
	cds_res = calloc(*maxcnt, sizeof (*cds_res));
	if (cds_res == NULL) {
		logger(LOG_ERR, "Out of memory");
		return (NULL);
	}

	cds = cds_res;
	for (i = 0; i < ancount; i++) {

		len = dn_expand(msg, eom, ptr, namebuf,
		    sizeof (namebuf));
		if (len < 0) {
			logger(LOG_ERR, "DNS query invalid message format");
			goto err;
		}
		ptr += len;
		NS_GET16(type, ptr);
		NS_GET16(class, ptr);
		NS_GET32(rttl, ptr);
		NS_GET16(size, ptr);
		if ((end = ptr + size) > eom) {
			logger(LOG_ERR, "DNS query invalid message format");
			goto err;
		}

		if (type != T_SRV) {
			ptr = end;
			continue;
		}

		NS_GET16(cds->cds_ds.priority, ptr);
		NS_GET16(cds->cds_ds.weight, ptr);
		NS_GET16(cds->cds_ds.port, ptr);
		len = dn_expand(msg, eom, ptr, cds->cds_ds.host,
		    sizeof (cds->cds_ds.host));
		if (len < 0) {
			logger(LOG_ERR, "DNS query invalid SRV record");
			goto err;
		}

		cds->cds_ds.ttl = rttl;

		if (DBG(DNS, 2)) {
			logger(LOG_DEBUG, "    %s", namebuf);
			logger(LOG_DEBUG,
			    "        ttl=%d pri=%d weight=%d %s:%d",
			    rttl, cds->cds_ds.priority, cds->cds_ds.weight,
			    cds->cds_ds.host, cds->cds_ds.port);
		}
		cds++;

		/* move ptr to the end of current record */
		ptr = end;
	}
	*scnt = (cds - cds_res);

	/* skip the nameservers section (if any) */

	len = ns_skiprr(ptr, eom, ns_s_ns, nscount);
	if (len < 0) {
		logger(LOG_ERR, "DNS query invalid message format");
		goto err;
	}
	ptr += len;

	/* walk through the additional records */
	for (i = 0; i < arcount; i++) {
		sa_family_t af;

		len = dn_expand(msg, eom, ptr, namebuf,
		    sizeof (namebuf));
		if (len < 0) {
			logger(LOG_ERR, "DNS query invalid message format");
			goto err;
		}
		ptr += len;
		NS_GET16(type, ptr);
		NS_GET16(class, ptr);
		NS_GET32(rttl, ptr);
		NS_GET16(size, ptr);
		if ((end = ptr + size) > eom) {
			logger(LOG_ERR, "DNS query invalid message format");
			goto err;
		}
		switch (type) {
		case ns_t_a:
			af = AF_INET;
			break;
		case ns_t_aaaa:
			af = AF_INET6;
			break;
		default:
			continue;
		}

		if (DBG(DNS, 2)) {
			char abuf[INET6_ADDRSTRLEN];
			const char *ap;

			ap = inet_ntop(af, ptr, abuf, sizeof (abuf));
			logger(LOG_DEBUG, "    %s    %s    %s",
			    (af == AF_INET) ? "A   " : "AAAA",
			    (ap) ? ap : "?", namebuf);
		}

		/* Find the server, add to its address list. */
		for (cds = cds_res; cds->cds_ds.host[0] != '\0'; cds++)
			if (0 == strcmp(namebuf, cds->cds_ds.host))
				save_addr(cds, af, ptr, size);

		/* move ptr to the end of current record */
		ptr = end;
	}

	return (cds_res);

err:
	free(cds_res);
	return (NULL);
}

/*
 * Save this address on the server, if not already there.
 */
static void
save_addr(ad_disc_cds_t *cds, sa_family_t af, uchar_t *addr, size_t alen)
{
	struct addrinfo *ai, *new_ai, *last_ai;

	new_ai = make_addrinfo(af, addr, alen);
	if (new_ai == NULL)
		return;

	last_ai = NULL;
	for (ai = cds->cds_ai; ai != NULL; ai = ai->ai_next) {
		last_ai = ai;

		if (new_ai->ai_family == ai->ai_family &&
		    new_ai->ai_addrlen == ai->ai_addrlen &&
		    0 == memcmp(new_ai->ai_addr, ai->ai_addr,
		    ai->ai_addrlen)) {
			/* it's already there */
			freeaddrinfo(new_ai);
			return;
		}
	}

	/* Not found.  Append. */
	if (last_ai != NULL) {
		last_ai->ai_next = new_ai;
	} else {
		cds->cds_ai = new_ai;
	}
}

static struct addrinfo *
make_addrinfo(sa_family_t af, uchar_t *addr, size_t alen)
{
	struct addrinfo *ai;
	struct sockaddr *sa;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	int slen;

	ai = calloc(1, sizeof (*ai));
	sa = calloc(1, sizeof (struct sockaddr_in6));

	if (ai == NULL || sa == NULL) {
		logger(LOG_ERR, "Out of memory");
		goto errout;
	}

	switch (af) {
	case AF_INET:
		sin = (void *)sa;
		if (alen < sizeof (in_addr_t)) {
			logger(LOG_ERR, "bad IPv4 addr len");
			goto errout;
		}
		alen = sizeof (in_addr_t);
		sin->sin_family = af;
		(void) memcpy(&sin->sin_addr, addr, alen);
		slen = sizeof (*sin);
		break;

	case AF_INET6:
		sin6 = (void *)sa;
		if (alen < sizeof (in6_addr_t)) {
			logger(LOG_ERR, "bad IPv6 addr len");
			goto errout;
		}
		alen = sizeof (in6_addr_t);
		sin6->sin6_family = af;
		(void) memcpy(&sin6->sin6_addr, addr, alen);
		slen = sizeof (*sin6);
		break;

	default:
		goto errout;
	}

	ai->ai_family = af;
	ai->ai_addrlen = slen;
	ai->ai_addr = sa;
	sa->sa_family = af;
	return (ai);

errout:
	free(ai);
	free(sa);
	return (NULL);
}

/*
 * Set a preferred candidate, which may already be in the list,
 * in which case we just bump its priority, or else add it.
 */
static void
add_preferred(ad_disc_cds_t *cds, ad_disc_ds_t *prefer, int *nds, int maxds)
{
	ad_disc_ds_t *ds;
	int i;

	assert(*nds < maxds);
	for (i = 0; i < *nds; i++) {
		ds = &cds[i].cds_ds;

		if (strcasecmp(ds->host, prefer->host) == 0) {
			/* Force this element to be sorted first. */
			ds->priority = 0;
			ds->weight = 200;
			return;
		}
	}

	/*
	 * The preferred DC was not found in this DNS response,
	 * so add it.  Again arrange for it to be sorted first.
	 * Address info. is added later.
	 */
	ds = &cds[i].cds_ds;
	(void) memcpy(ds, prefer, sizeof (*ds));
	ds->priority = 0;
	ds->weight = 200;
	*nds = i + 1;
}

/*
 * Do another pass over the array to check for missing addresses and
 * try resolving the names.  Normally, the DNS response from AD will
 * have supplied additional address records for all the SRV records.
 */
static void
get_addresses(ad_disc_cds_t *cds, int cnt)
{
	int i;

	for (i = 0; i < cnt; i++) {
		if (cds[i].cds_ai == NULL) {
			do_getaddrinfo(&cds[i]);
		}
	}
}

static void
do_getaddrinfo(ad_disc_cds_t *cds)
{
	struct addrinfo hints;
	struct addrinfo *ai;
	ad_disc_ds_t *ds;
	time_t t0, t1;
	int err;

	(void) memset(&hints, 0, sizeof (hints));
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_socktype = SOCK_STREAM;
	ds = &cds->cds_ds;

	/*
	 * This getaddrinfo call may take a LONG time, i.e. if our
	 * DNS servers are misconfigured or not responding.
	 * We need something like getaddrinfo_a(), with a timeout.
	 * For now, just log when this happens so we'll know
	 * if these calls are taking a long time.
	 */
	if (DBG(DNS, 2))
		logger(LOG_DEBUG, "getaddrinfo %s ...", ds->host);
	t0 = time(NULL);
	err = getaddrinfo(cds->cds_ds.host, NULL, &hints, &ai);
	t1 = time(NULL);
	if (DBG(DNS, 2))
		logger(LOG_DEBUG, "getaddrinfo %s rc=%d", ds->host, err);
	if (t1 > (t0 + 5)) {
		logger(LOG_WARNING, "Lookup host (%s) took %u sec. "
		    "(Check DNS settings)", ds->host, (int)(t1 - t0));
	}
	if (err != 0) {
		logger(LOG_ERR, "No address for host: %s (%s)",
		    ds->host, gai_strerror(err));
		/* Make this sort at the end. */
		ds->priority = 1 << 16;
		return;
	}

	cds->cds_ai = ai;
}

void
srv_free(ad_disc_cds_t *cds_vec)
{
	ad_disc_cds_t *cds;

	for (cds = cds_vec; cds->cds_ds.host[0] != '\0'; cds++) {
		if (cds->cds_ai != NULL) {
			freeaddrinfo(cds->cds_ai);
		}
	}
	free(cds_vec);
}
