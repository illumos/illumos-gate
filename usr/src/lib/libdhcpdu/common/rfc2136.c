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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<thread.h>
#include	<stdlib.h>
#include	<netdb.h>
#include	<strings.h>
#include	<alloca.h>
#include	<sys/socket.h>
#include	<netinet/in.h>
#include	<arpa/inet.h>
#include	<arpa/nameser.h>
#include	"res_update.h"
#include	<stdio.h>
#include	<errno.h>
#include	<resolv.h>
#include	<assert.h>
#include	<stdarg.h>
#include	<libnvpair.h>

#define	MAX_RETRIES	5	/* times to loop on TRY_AGAIN errors */
#define	LEASEMIN	3600	/* minimum lease time allowed by RFC 1531 */

static boolean_t	getNS(char *, struct in_addr *);
static void		cacheNS(char *, struct in_addr *, int);
static boolean_t	lookupNS(char *, struct in_addr *);
static boolean_t	send_update(struct hostent *, struct in_addr *);
static unsigned short	parse_ushort(const char **);
static unsigned int	parse_uint(const char **);
static void		freeupdrecs(ns_updque);
static void		freehost(struct hostent *);
static boolean_t	delA(struct __res_state *, char *);
static boolean_t	delPTR(struct __res_state *, char *, char *);
static boolean_t	addA(struct __res_state *, char *, struct in_addr);
static boolean_t	addPTR(struct __res_state *, char *, char *);
static boolean_t	retry_update(struct __res_state *, ns_updrec *);

extern char		*inet_ntoa_r(struct in_addr, char *);

/*
 *	The parent (calling) thread and the child thread it spawns to do an
 *	update use this structure to rendezvous.  The child thread sets the
 *	``done'' variable to B_TRUE when it's completed its work.  The nusers
 *	variable lets us arbitrate to see who has to clean up (via the
 *	provided childstat_cleanup() function) the dynamically-allocated
 *	structure - last one to wake up loses, and has to do the work.
 */
struct	childstat {
	mutex_t		m;
	cond_t		cv;
	struct hostent	*hp;
	boolean_t	synchflag;
	boolean_t	done;
	int		ret;
	int		nusers;
};
static void	childstat_cleanup(struct childstat *);

static void	update_thread(void *);

/*
 *	The given environment variable, if present, will contain the name
 *	of a file (or the distinguished values "stdout" and "stderr") into
 *	which we should place the debugging output from this shared object.
 *
 *	The debugging output is basically free-form but uses the dprint()
 *	function to ensure that each message is tagged with its thread ID,
 *	so we have some hope of sorting out later what actually happened.
 */
static char	env_filetoken[] = "DHCP_DNS_OUTPUT";
static void	dprint(char *, ...);
static FILE	*debug_fp;

static boolean_t	dns_config_ok;		/* did res_ninit() work? */

static nvlist_t	*nvl;

/* CSTYLED */
#pragma init	(init)

/*
 *	This is the shared object startup function, called once when we
 *	are dlopen()ed.
 */
static void
init(void)
{
	char *cp;
	struct __res_state res;

	if (cp = getenv(env_filetoken)) {
		if (strcmp(cp, "stdout") == 0)
			debug_fp = stdout;
		else if (strcmp(cp, "stderr") == 0)
			debug_fp = stderr;
		else {
			debug_fp = fopen(cp, "a");
		}
		if (debug_fp)
			(void) setvbuf(debug_fp, NULL, _IOLBF, BUFSIZ);
	}

	/*
	 *	Use res_ninit(3RESOLV) to see whether DNS has been configured
	 *	on the host running this code.  In practice, life must be very
	 *	bad for res_ninit() to fail.
	 */
	(void) memset(&res, 0, sizeof (res));
	if (res_ninit(&res) == -1) {
		dprint("res_ninit() failed - dns_config_ok FALSE\n");
		dns_config_ok = B_FALSE;
	} else {
		dprint("res_ninit() succeeded\n");
		dns_config_ok = B_TRUE;
	}
	res_ndestroy(&res);
}

/*
 *	This is the interface exported to the outside world.  Control over
 *	the hostent structure is assumed to pass to dns_puthostent();  it will
 *	free the associated space when done.
 */
int
dns_puthostent(struct hostent *hp, time_t timeout)
{
	struct childstat *sp;
	timestruc_t t;
	int ret;
	thread_t tid;


	/*
	 *	Check the consistency of the hostent structure:
	 *	both the name and address fields should be valid,
	 *	h_addrtype must be AF_INET, and h_length must be
	 *	sizeof (struct in_addr);
	 */
	if (hp == NULL) {
		dprint("hp is NULL - return -1\n");
		return (-1);
	}
	if (hp->h_addr_list == NULL) {
		dprint("h_addr_list is NULL - return -1\n");
		freehost(hp);
		return (-1);
	}
	if (hp->h_addr_list[0] == NULL) {
		dprint("h_addr_list is zero-length - return -1\n");
		freehost(hp);
		return (-1);
	}
	if (hp->h_name == NULL) {
		dprint("h_name is NULL - return -1\n");
		freehost(hp);
		return (-1);
	}
	if (hp->h_name[0] == '\0') {
		dprint("h_name[0] is NUL - return -1\n");
		freehost(hp);
		return (-1);
	}
	if (hp->h_addrtype != AF_INET) {
		dprint("h_addrtype (%d) != AF_INET - return -1\n",
		    hp->h_addrtype);
		freehost(hp);
		return (-1);
	}
	if (hp->h_length != sizeof (struct in_addr)) {
		dprint("h_length (%d) != sizeof (struct in_addr) - return -1\n",
		    hp->h_length);
		freehost(hp);
		return (-1);
	}

	dprint("dns_puthostent(%s, %d)\n", hp->h_name, (int)timeout);

	if (dns_config_ok == B_FALSE) {
		dprint("dns_config_ok FALSE - return -1\n");
		freehost(hp);
		return (-1);
	}

	if ((sp = malloc(sizeof (struct childstat))) == NULL) {
		dprint("malloc (sizeof struct childstat) failed\n");
		freehost(hp);
		return (-1);
	}

	/*
	 *	From this point on, both hp and sp are cleaned up and freed via
	 *	childstat_cleanup(), with bookkeeping done to see whether the
	 *	parent thread or the child one should be the one in charge of
	 *	cleaning up.
	 */
	sp->hp = hp;

	if (timeout > 0)
		sp->synchflag = B_TRUE;
	else
		sp->synchflag = B_FALSE;
	sp->done = B_FALSE;
	sp->ret = 0;
	sp->nusers = 1;
	(void) mutex_init(&sp->m, USYNC_THREAD, 0);
	(void) cond_init(&sp->cv, USYNC_THREAD, 0);
	(void) time(&t.tv_sec);
	t.tv_sec += timeout;
	t.tv_nsec = 0;

	if (thr_create(NULL, NULL, (void *(*)(void *))update_thread,
	    (void *) sp, THR_DAEMON|THR_DETACHED, &tid)) {
		dprint("thr_create failed (errno %d) - return -1\n", errno);
		childstat_cleanup(sp);
		return (-1);
	}
	else
		dprint("thread %u created\n", tid);

	if (!sp->done) {	/* we might already have finished */
		(void) mutex_lock(&sp->m);

		/* if asynchronous, and child still working, just return; */
		if ((!sp->done) && (timeout == 0)) {
			sp->nusers--;
			(void) mutex_unlock(&sp->m);
			dprint("done 0, timeout 0\n");
			return (0);
		}

		/* otherwise, wait for child to finish or time to expire */
		while (!sp->done)
			if (cond_timedwait(&sp->cv, &sp->m, &t) == ETIME) {
				/*
				 *	Child thread did not return before the
				 *	timeout.  One might think we could
				 *		assert(sp->nusers > 1);
				 *	here, but we can't:  we must protect
				 *	against this sequence of events:
				 *		cond_timedwait() times out
				 *
				 *		child finishes, grabs mutex,
				 *		decrements nusers, sets done,
				 *	    and exits.
				 *
				 *		cond_timedwait() reacquires the
				 *		mutex and returns ETIME
				 *
				 *	If this happens, nusers will now be 1,
				 *	even though cond_timedwait() returned
				 *	ETIME.
				 */
				if (sp->nusers == 1)
					/* child must have also set done */
					break;
				else
					/* child thread has not returned */
					sp->nusers--;
				(void) mutex_unlock(&sp->m);
				dprint("update for %s timed out\n", hp->h_name);
				return (0);
			}
		assert(sp->done);
		ret = sp->ret;
	}

	childstat_cleanup(sp);
	return (ret);
}

/*
 *	This worker thread, spawned by dns_puthostent(), is responsible for
 *	seeing that the update work gets done and cleaning up afterward
 *	if necessary.
 */
static void
update_thread(void *arg)
{
	char *p;
	int num_updated = 0;
	struct in_addr ia;
	struct hostent *hp;
	struct childstat *sp;

	dprint("update_thread running\n");

	sp = (struct childstat *)arg;

	(void) mutex_lock(&sp->m);
	/*
	 *	Paranoia:  if nusers was 0 and we were asked to do a
	 *	synchronous update, our parent must have incremented
	 *	it, called cond_timedwait(), timed out, and decremented it,
	 *	all before we got this far.  In this case, we do nothing
	 *	except clean up and exit.
	 */
	if ((++sp->nusers == 1) && sp->synchflag) {
		childstat_cleanup(sp);
		thr_exit(0);
	}

	(void) mutex_unlock(&sp->m);

	hp = sp->hp;

	/*
	 *	h_name should be full-qualified;  find the name servers for
	 *	its domain ...
	 */
	for (p = hp->h_name; *p != NULL; p++)
		if (*p == '.') {
			if (getNS(++p, &ia)) {
				char ntoab[INET_ADDRSTRLEN];

				(void) inet_ntoa_r(ia, ntoab);
				dprint("update for %s goes to %s\n",
				    hp->h_name, ntoab);
				/* ... and send the update to one of them. */
				if (send_update(hp, &ia)) {
					dprint("send_update succeeded\n");
					num_updated = 1;
				} else {
					dprint("send_update failed\n");
					num_updated = 0;
				}
			} else {
				dprint("getNS failed\n");
				num_updated = -1;
			}
			break;
		}
	dprint("update for %s returning %d\n", hp->h_name, num_updated);

	(void) mutex_lock(&sp->m);
	if (--sp->nusers == 0) {
		/* parent timed out and abandoned us - our turn to clean up */
		childstat_cleanup(sp);
	} else {
		sp->done = B_TRUE;
		sp->ret = num_updated;
		(void) cond_signal(&sp->cv);
		(void) mutex_unlock(&sp->m);
	}

	thr_exit(0);
}

/*
 *	Find a name server for the supplied domain and return its IP address.
 *	Sadly, in order to do this we have to parse the actual DNS reply
 *	packet - no functions are provided for doing this work for us.
 */
static boolean_t
getNS(char *domain, struct in_addr *iap)
{
	HEADER *hp;
	union {
		HEADER	h;
		char	buf[NS_PACKETSZ];
	} abuf;
	int alen;
	int count;
	int retries;
	unsigned char   name[MAXDNAME];
	int qdcount, ancount, nscount, arcount;
	unsigned char *data;
	unsigned char *m_bound;
	int type, class, ttl, dlen;
	struct hostent *ep;
	unsigned char *NS_data;
	boolean_t found_NS = B_FALSE;
	struct __res_state res;
	extern struct hostent *res_gethostbyname(const char *);

	if (lookupNS(domain, iap)) {
		dprint("getNS:  found cached IP address for domain %s\n",
		    domain);
		return (B_TRUE);
	}
	(void) memset(&res, 0, sizeof (res));
	if (res_ninit(&res) == -1) {
		dprint("getNS(\"%s\"):  res_ninit failed\n", domain);
		return (B_FALSE);
	}
	for (retries = 0; retries < MAX_RETRIES; retries++) {
		alen = res_nquery(&res, domain, C_IN, T_NS, (uchar_t *)&abuf,
		    sizeof (abuf));

		if (alen <= 0) {
			/*
			 * Look for indicators from libresolv:res_nsend()
			 * that we should retry a request.
			 */
			if ((errno == ECONNREFUSED) ||
			    ((h_errno == TRY_AGAIN) && (errno == ETIMEDOUT))) {
				dprint("getNS retry:  errno %d, h_errno %d\n",
				    errno, h_errno);
				continue;
			} else {
				dprint("getNS(\"%s\"):  res_nquery failed "
				    "(h_errno %d)\n", domain, h_errno);
				res_ndestroy(&res);
				return (B_FALSE);
			}
		}
	}
	if (alen <= 0) {
		dprint("getNS(\"%s\"):  res_nquery failed " "(h_errno %d)\n",
		    domain, h_errno);
		res_ndestroy(&res);
		return (B_FALSE);
	}

	m_bound = ((unsigned char *)&abuf) + alen;

	hp = (HEADER *)&abuf;
	data = (unsigned char *)&hp[1];	/* a DNS paradigm - actually abuf.buf */

	qdcount = ntohs(hp->qdcount);
	ancount = ntohs(hp->ancount);
	nscount = ntohs(hp->nscount);
	arcount = ntohs(hp->arcount);

	dprint("getNS(\"%s\"):\n", domain);
	dprint("\tqdcount %d\n", qdcount);
	dprint("\tancount %d\n", ancount);
	dprint("\tnscount %d\n", nscount);
	dprint("\tarcount %d\n", arcount);

	while (--qdcount >= 0) {
		dlen = dn_skipname(data, m_bound);
		if (dlen < 0) {
			dprint("dn_skipname returned < 0\n");
			res_ndestroy(&res);
			return (B_FALSE);
		}
		data += dlen + QFIXEDSZ;
	}

	count = ancount;
	count += arcount;
	while (--count >= 0 && data < m_bound) {
		if ((dlen = dn_expand((unsigned char *) &abuf, m_bound,
				data, (char *)name, sizeof (name))) < 0) {
			dprint("dn_expand() dom failed\n");
			res_ndestroy(&res);
			return (B_FALSE);
		}
		data += dlen;
		type = parse_ushort((const char **)&data);
		class = parse_ushort((const char **)&data);
		ttl = parse_uint((const char **)&data);
		dlen = parse_ushort((const char **)&data);

		switch (type) {
			case T_NS:
				dprint("\ttype T_NS\n");
				break;
			case T_CNAME:
				dprint("\ttype T_CNAME\n");
				break;
			case T_A:
				dprint("\ttype T_A\n");
				break;
			case T_SOA:
				dprint("\ttype T_SOA\n");
				break;
			case T_MX:
				dprint("\ttype T_MX\n");
				break;
			case T_TXT:
				dprint("\ttype T_TXT\n");
				break;
			default:
				dprint("\ttype %d\n", type);
			}
			if (class == C_IN)
				dprint("\tclass C_IN\n");
			else
				dprint("\tclass %d\n", class);
			dprint("\tttl %d secs\n", ttl);
			dprint("\tlen %d bytes\n", dlen);

		switch (type) {
		case T_A:
			(void) memcpy(iap, data, sizeof (struct in_addr));
			cacheNS(domain, iap, ttl);
			res_ndestroy(&res);
			return (B_TRUE);

		case T_NS:
			found_NS = B_TRUE;
			NS_data = data;	/* we may need this name below */
			if (dn_expand((unsigned char *) &abuf, m_bound, data,
			    (char *)name, sizeof (name)) < 0) {
				dprint("\tdn_expand() T_NS failed\n");
				res_ndestroy(&res);
				return (B_FALSE);
			}
			dprint("\tname %s\n", name);
			break;
		}
		data += dlen;
	}
	dprint("getNS:  fell through res_nquery results - no A records\n");

	/*
	 *	The reply contained NS records, but no A records.  Use
	 *	res_gethostbyname() to get the name server's address
	 *	via DNS.
	 */
	if (found_NS) {
		if (dn_expand((unsigned char *) &abuf, m_bound, NS_data,
		    (char *)name, sizeof (name)) < 0) {
			dprint("\tdn_expand() T_NS failed\n");
			res_ndestroy(&res);
			return (B_FALSE);
		}

		if (ep = res_gethostbyname((const char *)name)) {
			(void) memcpy(iap, ep->h_addr, sizeof (struct in_addr));
			cacheNS(domain, iap, ttl);
			res_ndestroy(&res);
			return (B_TRUE);
		} else
			dprint("getNS:  res_gethostbyname(%s) failed\n", name);
	} else {
		dprint("getNS:  reply contained no NS records\n");
	}

	res_ndestroy(&res);
	return (B_FALSE);
}

/*
 *	Cache the <domain, IP address> tuple (which is assumed to not already
 *	be cached) for ttl seconds.
 */
static void
cacheNS(char *domain, struct in_addr *iap, int ttl)
{
	if (ttl > 0) {
		time_t now;

		if (nvl == NULL &&
		    nvlist_alloc(&nvl, NV_UNIQUE_NAME_TYPE, 0) != 0) {
			dprint("cacheNS:  nvlist_alloc failed\n");
			return;
		}

		(void) time(&now);
		now += ttl;
		if ((nvlist_add_int32(nvl, domain, iap->s_addr) != 0) ||
		    (nvlist_add_byte_array(nvl, domain, (uchar_t *)&now,
			sizeof (now)) != 0)) {
			dprint("cacheNS:  nvlist_add failed\n");
			nvlist_free(nvl);
			nvl = NULL;
		}
	} else
		dprint("cacheNS:  ttl 0 - nothing to cache\n");
}

/*
 *	See whether the <domain, IP address> tuple has been cached.
 */
static boolean_t
lookupNS(char *domain, struct in_addr *iap)
{
	int32_t i;

	if (nvlist_lookup_int32(nvl, domain, &i) == 0) {
		time_t *ttlptr;
		uint_t nelem = sizeof (*ttlptr);

		if (nvlist_lookup_byte_array(nvl, domain, (uchar_t **)&ttlptr,
		    &nelem) != 0)
			return (B_FALSE);

		if (*ttlptr >= time(0)) {	/* still OK to use */
			iap->s_addr = i;
			return (B_TRUE);
		} else {
			(void) nvlist_remove_all(nvl, domain);
		}
	}

	return (B_FALSE);
}

/*
 *	Do the work of updating DNS to have the <hp->h_name <-> hp->h_addr>
 *	pairing.
 */
static boolean_t
send_update(struct hostent *hp, struct in_addr *to_server)
{
	char *forfqhost;
	struct __res_state res;
	struct in_addr netaddr;
	char revnamebuf[MAXDNAME];

	(void) memset(&res, 0, sizeof (res));
	if (res_ninit(&res) == -1) {
		dprint("send_updated res_ninit failed!");
		return (B_FALSE);
	}
	res.nscount = 1;
	res.nsaddr.sin_family = AF_INET;
	res.nsaddr.sin_port = htons(NAMESERVER_PORT);
	res.nsaddr.sin_addr.s_addr = to_server->s_addr;

	/* If debugging output desired, then ask resolver to do it, too */
	if (debug_fp != NULL)
		res.options |= RES_DEBUG;

	if (strchr(hp->h_name, '.') == NULL) {
		dprint("send_update handed non-FQDN:  %s\n", hp->h_name);
		res_ndestroy(&res);
		return (B_FALSE);
	}
	forfqhost = hp->h_name;

	/* Construct the fully-qualified name for PTR record updates */
	/* LINTED - alignment */
	netaddr.s_addr = ((struct in_addr *)hp->h_addr)->s_addr;
	(void) snprintf(revnamebuf, sizeof (revnamebuf),
	    "%u.%u.%u.%u.in-addr.ARPA",
	    netaddr.S_un.S_un_b.s_b4, netaddr.S_un.S_un_b.s_b3,
	    netaddr.S_un.S_un_b.s_b2, netaddr.S_un.S_un_b.s_b1);
	dprint("send_update %s:  revname %s\n", hp->h_name, revnamebuf);

	/*
	 *	The steps in doing an update:
	 *		-  delete any A records
	 *		-  delete any PTR records
	 *		-  add an A record
	 *		-  add a PTR record
	 */

	if (!delA(&res, forfqhost) ||
	    !delPTR(&res, forfqhost, revnamebuf) ||
	    !addA(&res, forfqhost, netaddr) ||
	    !addPTR(&res, forfqhost, revnamebuf)) {
		res_ndestroy(&res);
		return (B_FALSE);
	}
	res_ndestroy(&res);
	return (B_TRUE);
}

/* delete A records for this fully-qualified name */
static boolean_t
delA(struct __res_state *resp, char *fqdn)
{
	ns_updque q;
	ns_updrec *updreqp;

	INIT_LIST(q);
	updreqp = res_mkupdrec(S_UPDATE, fqdn, C_IN, T_A, 0);
	if (updreqp == NULL) {
		dprint("res_mkupdrec (del A) failed\n");
		return (B_FALSE);
	}
	updreqp->r_opcode = DELETE;
	updreqp->r_data = NULL;
	updreqp->r_size = 0;
	APPEND(q, updreqp, r_link);
	if (retry_update(resp, HEAD(q)) != 1) {
		dprint("res_nupdate (del A) failed - errno %d, h_errno %d\n",
		    errno, h_errno);
		freeupdrecs(q);
		return (B_FALSE);
	}
	freeupdrecs(q);
	return (B_TRUE);
}

/* delete PTR records for this address */
static boolean_t
delPTR(struct __res_state *resp, char *fqdn, char *revname)
{
	ns_updque q;
	ns_updrec *updreqp;

	INIT_LIST(q);
	updreqp = res_mkupdrec(S_UPDATE, revname, C_IN, T_PTR, 0);
	if (updreqp == NULL) {
		dprint("res_mkupdrec (del PTR) failed\n");
		return (B_FALSE);
	}
	updreqp->r_opcode = DELETE;
	updreqp->r_data = (unsigned char *)fqdn;
	updreqp->r_size = strlen(fqdn);
	APPEND(q, updreqp, r_link);
	if (retry_update(resp, HEAD(q)) != 1) {
		dprint("res_nupdate (del PTR) failed - errno %d, h_errno %d\n",
		    errno, h_errno);
		freeupdrecs(q);
		return (B_FALSE);
	}
	freeupdrecs(q);
	return (B_TRUE);
}

/* add an A record for this fqdn <-> addr pair */
static boolean_t
addA(struct __res_state *resp, char *fqdn, struct in_addr na)
{
	ns_updque q;
	ns_updrec *prereqp, *updreqp;
	int ttl = LEASEMIN;
	char ntoab[INET_ADDRSTRLEN];

	INIT_LIST(q);
	prereqp = res_mkupdrec(S_PREREQ, fqdn, C_IN, T_A, 0);
	if (prereqp == NULL) {
		dprint("res_mkupdrec (add A PREREQ) failed\n");
		return (B_FALSE);
	}
	prereqp->r_opcode = NXRRSET;
	prereqp->r_data = NULL;
	prereqp->r_size = 0;
	APPEND(q, prereqp, r_link);
	updreqp = res_mkupdrec(S_UPDATE, fqdn, C_IN, T_A, ttl);
	if (updreqp == NULL) {
		dprint("res_mkupdrec (add A UPDATE) failed\n");
		freeupdrecs(q);
		return (B_FALSE);
	}

	(void) inet_ntoa_r(na, ntoab);
	updreqp->r_opcode = ADD;
	updreqp->r_data = (unsigned char *)ntoab;
	updreqp->r_size = strlen(ntoab);
	APPEND(q, updreqp, r_link);
	if (retry_update(resp, HEAD(q)) != 1) {
		dprint("res_nupdate (ADD A) failed - errno %d, h_errno %d\n",
		    errno, h_errno);
		freeupdrecs(q);
		return (B_FALSE);
	}
	freeupdrecs(q);
	return (B_TRUE);
}

/* add a PTR record for this fqdn <-> address pair */
static boolean_t
addPTR(struct __res_state *resp, char *fqdn, char *revname)
{
	ns_updque q;
	ns_updrec *prereqp, *updreqp;
	int ttl = LEASEMIN;

	INIT_LIST(q);
	prereqp = res_mkupdrec(S_UPDATE, revname, C_IN, T_PTR, 0);
	if (prereqp == NULL) {
		dprint("res_mkupdrec (add PTR DELETE) failed\n");
		return (B_FALSE);
	}
	prereqp->r_opcode = DELETE;
	prereqp->r_data = NULL;
	prereqp->r_size = 0;
	APPEND(q, prereqp, r_link);
	updreqp = res_mkupdrec(S_UPDATE, revname, C_IN, T_PTR, ttl);
	if (updreqp == NULL) {
		dprint("res_mkupdrec (add PTR ADD) failed\n");
		freeupdrecs(q);
		return (B_FALSE);
	}
	updreqp->r_opcode = ADD;
	updreqp->r_data = (unsigned char *)fqdn;
	updreqp->r_size = strlen(fqdn);
	APPEND(q, updreqp, r_link);
	if (retry_update(resp, HEAD(q)) != 1) {
		dprint("res_nupdate (ADD PTR) failed - errno %d, h_errno %d\n",
		    errno, h_errno);
		freeupdrecs(q);
		return (B_FALSE);
	}
	freeupdrecs(q);

	return (B_TRUE);
}

/* retry an update request when appropriate */
static boolean_t
retry_update(struct __res_state *resp, ns_updrec *h)
{
	int retries;

	for (retries = 0; retries < MAX_RETRIES; retries++)
		if (res_nupdate(resp, h, NULL) == 1) {
			return (B_TRUE);
		} else {
			/*
			 * Look for indicators from libresolv:res_nsend()
			 * that we should retry a request.
			 */
			if ((errno == ECONNREFUSED) ||
			    ((h_errno == TRY_AGAIN) && (errno == ETIMEDOUT))) {
				dprint("retry_update - errno %d, h_errno %d\n",
				    errno, h_errno);
				continue;
			} else
				return (B_FALSE);
		}

	return (B_FALSE);
}

static void
freeupdrecs(ns_updque q)
{
	while (!EMPTY(q)) {
		ns_updrec *tmp;

		tmp = HEAD(q);
		UNLINK(q, tmp, r_link);
		res_freeupdrec(tmp);
	}
}

/*
 *	Parse a 16-bit quantity from a DNS reply packet.
 */
static unsigned short
parse_ushort(const char **pp)
{
	const uchar_t	*p = (const uchar_t *)*pp;
	unsigned short  val;

	val = (p[0] << 8) | p[1];
	*pp += 2;
	return (val);
}


/*
 *	Parse a 32-bit quantity from a DNS reply packet.
 */
static unsigned int
parse_uint(const char **pp)
{
	const uchar_t	*p = (const uchar_t *)*pp;
	unsigned int   val;

	val =  ((uint_t)p[0] << 24) | ((uint_t)p[1] << 16) |
	    ((uint_t)p[2] << 8) | (uint_t)p[3];
	*pp += 4;
	return (val);
}

/*
 *	Clean up a childstat structure's synchronization variables and free
 *	the allocated memory.
 */
static void
childstat_cleanup(struct childstat *sp)
{
	(void) cond_destroy(&sp->cv);
	(void) mutex_destroy(&sp->m);
	freehost(sp->hp);
	free(sp);
}

/*
 *	Format and print a debug message, prepending the thread ID of the
 *	thread logging the message.
 */
/* PRINTFLIKE1 */
static void
dprint(char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	if (debug_fp) {
		(void) fprintf(debug_fp, "%u:  ", thr_self());
		(void) vfprintf(debug_fp, format, ap);
		va_end(ap);
	}
}

static void
freehost(struct hostent *hp)
{
	free(hp->h_addr);
	free(hp->h_addr_list);
	free(hp->h_name);
	free(hp);
}
