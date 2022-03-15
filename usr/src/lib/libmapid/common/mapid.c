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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * PSARC/2004/154 nfsmapid DNS enhancements implementation.
 *
 * As per RFC 7530, file owner and group attributes in version 4 of the
 * NFS protocol are no longer exchanged between client and server as 32
 * bit integral values. Instead, owner and group file attributes are
 * exchanged between client and server as UTF8 strings of form
 *
 *      'user@domain'		(ie. "joeblow@central.sun.com")
 *      'group@domain'		(ie. "staff@central.sun.com")
 *
 * This NFSv4 feature is far beyond anything NFSv2/v3 ever provided, as
 * being able to describe a user with a unique string identifier provides
 * a much more powerful and administrative friendly way of dealing with
 * overlaps in the uid/gid number spaces. That notwithstanding, dealing
 * with issues of correctly mapping user and group ownership in a cross-
 * domain environment has proven a difficult problem to solve, since
 * dealing with different permutations of client naming configurations
 * (ie. NIS only, LDAP only, etc.) have bloated the problem. Thus, users
 * utilizing clients and servers that have the 'domain' portion of the
 * UTF8 attribute string configured differently than its peer server and
 * client accordingly, will experience watching their files owned by the
 * 'nobody' user and group. This is due to the fact that the 'domain's
 * don't match and the nfsmapid daemon treats the attribute strings as
 * unknown user(s) or group(s) (even though the actual uid/gid's may exist
 * in the executing daemon's system). Please refer to PSARC/2004/154 for
 * further background and motivation for these enhancements.
 *
 * The latest implementation of the nfsmapid daemon relies on a DNS TXT
 * record. The behavior of nfsmapid is to first use the NFSMAPID_DOMAIN
 * configuration option in /etc/default/nfs. If the option has not been
 * set, then the nfsmapid daemon queries the configured DNS domain server
 * for the _nfsv4idmapdomain TXT record. If the record exists, then the
 * record's value is used as the 'domain' portion of the UTF8 attribute
 * strings. If the TXT record has not been configured in the DNS server,
 * then the daemon falls back to using the DNS domain name itself as the
 * 'domain' portion of the attribute strings. Lastly, if the configured
 * DNS server is unresponsive, the nfsmapid daemon falls back to using
 * the DNS domain name as the 'domain' portion of the attribute strings,
 * and fires up a query thread to keep contacting the DNS server until
 * it responds with either a TXT record, or a lack thereof, in which
 * case, nfsmapid just continues to utilize the DNS domain name.
 */
#define	__LIBMAPID_IMPL
#include <nfs/mapid.h>
#include <libshare.h>
#include <libscf.h>
#include <limits.h>
#include <rpcsvc/daemon_utils.h>
#include "smfcfg.h"

#pragma	init(_lib_init)
#pragma	fini(_lib_fini)

/*
 * DEBUG Only
 * Decode any resolver errors and print out message to log
 */
static int
resolv_error(void)
{
#ifndef	DEBUG

	return (h_errno);

#else	/* DEBUG */

	static uint64_t	 msg_done[NS_ERRS] = {0};

	switch (h_errno) {
	case NETDB_INTERNAL:
		syslog(LOG_ERR, EMSG_NETDB_INTERNAL, strerror(errno));
		break;

	case HOST_NOT_FOUND:
		(void) rw_rdlock(&s_dns_impl_lock);
		msg_done[h_errno]++;
		if (!(msg_done[h_errno] % NFSMAPID_SLOG_RATE))
			syslog(LOG_ERR, EMSG_HOST_NOT_FOUND, s_dname);
		(void) rw_unlock(&s_dns_impl_lock);
		break;

	case TRY_AGAIN:
		/*
		 * Nameserver is not responding.
		 * Try again after a given timeout.
		 */
		(void) rw_rdlock(&s_dns_impl_lock);
		msg_done[h_errno]++;
		if (!(msg_done[h_errno] % NFSMAPID_SLOG_RATE))
			syslog(LOG_ERR, EMSG_TRY_AGAIN, s_dname);
		(void) rw_unlock(&s_dns_impl_lock);
		break;

	case NO_RECOVERY:
		/*
		 * This msg only really happens once, due
		 * to s_dns_disabled flag (see below)
		 */
		syslog(LOG_ERR, EMSG_NO_RECOVERY, hstrerror(h_errno));
		break;

	case NO_DATA:
		/*
		 * No entries in the nameserver for
		 * the specific record or record type.
		 */
		(void) rw_rdlock(&s_dns_impl_lock);
		msg_done[h_errno]++;
		if (!(msg_done[h_errno] % NFSMAPID_SLOG_RATE))
			syslog(LOG_ERR, EMSG_NO_DATA, NFSMAPID_DNS_RR, s_dname);
		(void) rw_unlock(&s_dns_impl_lock);
		break;

	case NETDB_SUCCESS:
	default:
		break;
	}
	return (h_errno);

#endif	/* DEBUG */
}

/*
 * Reset the global state variables used for the TXT record.
 * Having these values reset to zero helps nfsmapid confirm
 * that a valid DNS TXT record was not found; in which case,
 * it would fall back to using the configured DNS domain name.
 *
 * If a valid DNS TXT record _was_ found, but subsequent contact
 * to the DNS server is somehow hindered, the previous DNS TXT
 * RR value continues to be used. Thus, in such instances, we
 * forego clearing the global config variables so nfsmapid can
 * continue to use a valid DNS TXT RR while contact to the DNS
 * server is reestablished.
 */
static void
resolv_txt_reset(void)
{
	(void) rw_wrlock(&s_dns_impl_lock);
	bzero(s_txt_rr, sizeof (s_txt_rr));
	(void) rw_unlock(&s_dns_impl_lock);

	(void) rw_wrlock(&s_dns_data_lock);
	if (!dns_txt_cached) {
		dns_txt_domain_len = 0;
		bzero(dns_txt_domain, DNAMEMAX);
	}
	(void) rw_unlock(&s_dns_data_lock);
}

/*
 * Initialize resolver and populate &s_res struct
 *
 * DNS Domain is saved off sysdns_domain in case we
 * need to fall back to using the DNS domain name as
 * the v4 attribute string domain.
 */
static int
resolv_init(void)
{
	size_t			len;
	int			n;
	struct __res_state	res;

	(void) mutex_lock(&s_res_lock);
	bzero(&s_res, sizeof (struct __res_state));
	n = h_errno = errno = 0;
	if ((n = res_ninit(&s_res)) < 0) {
		(void) mutex_unlock(&s_res_lock);
		(void) resolv_error();
		return (n);
	}
	res = s_res;
	(void) mutex_unlock(&s_res_lock);

	len = strlen(res.defdname) + 1;
	(void) rw_wrlock(&s_dns_impl_lock);
	bzero(s_dname, sizeof (s_dname));
	(void) snprintf(s_dname, len, "%s", res.defdname);
	(void) rw_unlock(&s_dns_impl_lock);

	(void) rw_wrlock(&s_dns_data_lock);
	(void) snprintf(sysdns_domain, len, "%s", res.defdname);
	(void) rw_unlock(&s_dns_data_lock);

	return (0);
}

/*
 * Search criteria assumptions:
 *
 * The onus will fall on the sysadmins to correctly configure the TXT
 * record in the DNS domain where the box currently resides in order
 * for the record to be found. However, if they sysadmin chooses to
 * add the 'search' key to /etc/resolv.conf, then resolv_search()
 * _will_ traverse up the DNS tree as specified in the 'search' key.
 * Otherwise, we'll default the domain to the DNS domain itself.
 */
static int
resolv_search(void)
{
	int			len;
	ans_t			ans = {0};
	struct __res_state	res;
	int			type = T_TXT;
	int			class = C_IN;

	(void) mutex_lock(&s_res_lock);
	res = s_res;
	(void) mutex_unlock(&s_res_lock);

	/*
	 * Avoid holding locks across the res_nsearch() call to
	 * prevent stalling threads during network partitions.
	 */
	len = h_errno = errno = 0;
	if ((len = res_nsearch(&res, NFSMAPID_DNS_RR, class, type,
	    ans.buf, sizeof (ans))) < 0)
		return (resolv_error());

	(void) rw_wrlock(&s_dns_impl_lock);
	s_ans = ans;
	s_anslen = len;
	(void) rw_unlock(&s_dns_impl_lock);

	return (NETDB_SUCCESS);
}

/*
 * Free all resolver state information stored in s_res
 */
static void
resolv_destroy(void)
{
	(void) mutex_lock(&s_res_lock);
	res_ndestroy(&s_res);
	(void) mutex_unlock(&s_res_lock);
}

/*
 * Skip one DNS record
 */
static uchar_t  *
resolv_skip_rr(uchar_t *p, uchar_t *eom)
{
	int	t;
	int	dlen;

	/*
	 * Skip compressed name
	 */
	errno = 0;
	if ((t = dn_skipname(p, eom)) < 0) {
#ifdef	DEBUG
		syslog(LOG_ERR, "%s", strerror(errno));
#endif
		return (NULL);
	}

	/*
	 * Advance pointer and make sure
	 * we're still within the message
	 */
	p += t;
	if ((p + RRFIXEDSZ) > eom)
		return (NULL);

	/*
	 * Now, just skip over the rr fields
	 */
	p += INT16SZ;	/* type */
	p += INT16SZ;	/* class */
	p += INT32SZ;	/* ttl */
	dlen = ns_get16(p);
	p += INT16SZ;
	p += dlen;	/* dlen */
	if (p > eom)
		return (NULL);

	return (p);
}

/*
 * Process one TXT record.
 *
 * nfsmapid queries the DNS server for the specific _nfsv4idmapdomain
 * TXT record. Thus, if the TXT record exists, the answer section of
 * the DNS response carries the TXT record's value. Thus, we check that
 * the value is indeed a valid domain and set the modular s_txt_rr
 * global to the domain value.
 */
static void
resolve_process_txt(uchar_t *p, int dlen)
{
	char		*rr_base = (char *)(p + 1);
	char		*rr_end = (char *)(p + dlen);
	size_t		 len = rr_end - rr_base;
#ifdef	DEBUG
	static uint64_t	 msg_done = 0;
#endif
	char		 tmp_txt_rr[DNAMEMAX];

	if (len >= DNAMEMAX)
		return;		/* process next TXT RR */

	/*
	 * make sure we have a clean buf since
	 * we may've processed several TXT rr's
	 */
	(void) rw_wrlock(&s_dns_impl_lock);
	bzero(s_txt_rr, sizeof (s_txt_rr));
	(void) rw_unlock(&s_dns_impl_lock);

	(void) strncpy(tmp_txt_rr, rr_base, len);
	tmp_txt_rr[len] = '\0';

	/*
	 * If there is a record and it's a valid domain, we're done.
	 */
	if (rr_base[0] != '\0' && mapid_stdchk_domain(tmp_txt_rr) > 0) {
		(void) rw_wrlock(&s_dns_impl_lock);
		(void) strncpy(s_txt_rr, rr_base, len);
		(void) rw_unlock(&s_dns_impl_lock);
#ifdef	DEBUG
		syslog(LOG_ERR, "TXT (Rec):\t%s", s_txt_rr);

	} else if (!(msg_done++ % NFSMAPID_SLOG_RATE)) {
		/*
		 * Otherwise, log the error
		 */
		(void) rw_rdlock(&s_dns_impl_lock);
		syslog(LOG_ERR, EMSG_DNS_RR_INVAL, NFSMAPID_DNS_RR, s_dname);
		(void) rw_unlock(&s_dns_impl_lock);
#endif
	}
}

/*
 * Decode any answer received from the DNS server. This interface is
 * capable of much more than just decoding TXT records. We maintain
 * focus on TXT rr's for now, but this will probably change once we
 * get the IETF approved application specific DNS RR.
 *
 * Here's an example of the TXT record we're decoding (as would appear
 * in the DNS zone file):
 *
 *            _nfsv4idmapdomain    IN    TXT    "sun.com"
 *
 * Once the IETF application specific DNS RR is granted, we should only
 * be changing the record flavor, but all should pretty much stay the
 * same.
 */
static void
resolv_decode(void)
{
	uchar_t		*buf;
	HEADER		*hp;
	uchar_t		 name[DNAMEMAX];
	uchar_t		*eom;
	uchar_t		*p;
	int		 n;
	uint_t		 qd_cnt;
	uint_t		 an_cnt;
	uint_t		 ns_cnt;
	uint_t		 ar_cnt;
	uint_t		 cnt;
	uint_t		 type;
	int		 dlen;
	ans_t		 answer = {0};
	int		 answer_len = 0;

	/*
	 * Check the HEADER for any signs of errors
	 * and extract the answer counts for later.
	 */
	(void) rw_rdlock(&s_dns_impl_lock);
	answer = s_ans;
	answer_len = s_anslen;
	(void) rw_unlock(&s_dns_impl_lock);

	buf = (uchar_t *)&answer.buf;
	hp = (HEADER *)&answer.hdr;
	eom = (uchar_t *)(buf + answer_len);
	if (hp->rcode !=  NOERROR) {
#ifdef	DEBUG
		syslog(LOG_ERR, "errno: %s", strerror(errno));
		syslog(LOG_ERR, "h_errno: %s", hstrerror(h_errno));
#endif
		return;
	}
	qd_cnt = ntohs(hp->qdcount);
	an_cnt = ntohs(hp->ancount);
	ns_cnt = ntohs(hp->nscount);
	ar_cnt = ntohs(hp->arcount);

	/*
	 * skip query entries
	 */
	p = (uchar_t *)(buf + HFIXEDSZ);
	errno = 0;
	while (qd_cnt-- > 0) {
		n = dn_skipname(p, eom);
		if (n < 0) {
#ifdef	DEBUG
			syslog(LOG_ERR, "%s", strerror(errno));
#endif
			return;
		}
		p += n;
		p += INT16SZ;	/* type */
		p += INT16SZ;	/* class */
	}

#ifdef	DEBUG
	/*
	 * If debugging... print query only once.
	 * NOTE: Don't advance pointer... this is done
	 *	 in while() loop on a per record basis !
	 */
	n = h_errno = errno = 0;
	n = dn_expand(buf, eom, p, (char *)name, sizeof (name));
	if (n < 0) {
		(void) resolv_error();
		return;
	}
	syslog(LOG_ERR, "Query:\t\t%-30s", name);
#endif

	/*
	 * Process actual answer(s).
	 */
	cnt = an_cnt;
	while (cnt-- > 0 && p < eom) {
		/* skip the name field */
		n = dn_expand(buf, eom, p, (char *)name, sizeof (name));
		if (n < 0) {
			(void) resolv_error();
			return;
		}
		p += n;

		if ((p + 3 * INT16SZ + INT32SZ) > eom)
			return;

		type = ns_get16(p);
		p += INT16SZ;
		p += INT16SZ + INT32SZ;	/* skip class & ttl */
		dlen = ns_get16(p);
		p += INT16SZ;

		if ((p + dlen) > eom)
			return;

		switch (type) {
			case T_TXT:
				resolve_process_txt(p, dlen);
				break;

			default:
				/*
				 * Advance to next answer record for any
				 * other record types. Again, this will
				 * probably change (see block comment).
				 */
				p += dlen;
				break;
		}
	}

	/*
	 * Skip name server and additional records for now.
	 */
	cnt = ns_cnt + ar_cnt;
	if (cnt > 0) {
		while (--cnt != 0 && p < eom) {
			p = resolv_skip_rr(p, eom);
			if (p == NULL)
				return;
		}
	}
}

/*
 * If a valid TXT record entry exists, s_txt_rr contains the domain
 * value (as set in resolv_process_txt) and we extract the value into
 * dns_txt_domain (the exported global). If there was _no_ valid TXT
 * entry, we simply return and check_domain() will default to the
 * DNS domain since we did resolv_txt_reset() first.
 */
static void
resolv_get_txt_data()
{
	(void) rw_rdlock(&s_dns_impl_lock);
	if (s_txt_rr[0] != '\0') {
		(void) rw_wrlock(&s_dns_data_lock);
		(void) snprintf(dns_txt_domain, strlen(s_txt_rr) + 1, "%s",
		    s_txt_rr);
		dns_txt_domain_len = strlen(dns_txt_domain);
		dns_txt_cached = 1;
		(void) rw_unlock(&s_dns_data_lock);
	}
	(void) rw_unlock(&s_dns_impl_lock);
}

static void
domain_sync(cb_t *argp, char *dname)
{
	int	dlen = 0;
	void	*(*fcn)(void *) = NULL;
	int	sighup = 0;
	int	domchg = 0;

	/*
	 * Make sure values passed are sane and initialize accordingly.
	 */
	if (dname != NULL)
		dlen = strlen(dname);
	if (argp) {
		if (argp->fcn)
			fcn = argp->fcn;
		if (argp->signal)
			sighup = argp->signal;
	}

	/*
	 * Update the library's mapid_domain variable if 'dname' is different.
	 */
	if (dlen != 0 && strncasecmp(dname, mapid_domain, NS_MAXCDNAME)) {
		(void) rw_wrlock(&mapid_domain_lock);
		(void) strncpy(mapid_domain, dname, NS_MAXCDNAME);
		mapid_domain_len = dlen;
		(void) rw_unlock(&mapid_domain_lock);
		domchg++;
	}

	/*
	 * If the caller gave us a valid callback routine, we
	 * instantiate it to announce the domain change, but
	 * only if either the domain changed _or_ the caller
	 * was issued a SIGHUP.
	 */
	if (fcn != NULL && (sighup || domchg))
		(void) fcn((void *)mapid_domain);
}

/*
 * Thread to keep pinging  DNS  server for  TXT  record if nfsmapid's
 * initial attempt at contact with server failed. We could potentially
 * have a substantial number of NFSv4 clients and having all of them
 * hammering on an already unresponsive DNS server would not help
 * things. So, we limit the number of live query threads to at most
 * 1 at any one time to keep things from getting out of hand.
 */
/* ARGSUSED */
static void *
resolv_query_thread(void *arg)
{
	unsigned int	 nap_time;

#ifdef	DEBUG
	char		*whoami = "query_thread";

	syslog(LOG_ERR, "%s active !", whoami);
#endif
	(void) rw_rdlock(&s_dns_impl_lock);
	nap_time = s_dns_tout;
	(void) rw_unlock(&s_dns_impl_lock);

	for (;;) {
		(void) sleep(nap_time);

		resolv_txt_reset();
		if (resolv_init() < 0) {
			/*
			 * Failed to initialize resolver. Do not
			 * query DNS server.
			 */
			goto thr_reset;
		}
		switch (resolv_search()) {
		case NETDB_SUCCESS:
			resolv_decode();
			resolv_get_txt_data();

			/*
			 * This is a bit different than what we
			 * do in get_dns_txt_domain(), where we
			 * simply return and let the caller
			 * access dns_txt_domain directly.
			 *
			 * Here we invoke the callback routine
			 * provided by the caller to the
			 * mapid_reeval_domain() interface via
			 * the cb_t's fcn param.
			 */
			domain_sync((cb_t *)arg, dns_txt_domain);
			goto thr_okay;

		case NO_DATA:
			/*
			 * DNS is up now, but does not have
			 * the NFSV4IDMAPDOMAIN TXT record.
			 */
#ifdef	DEBUG
			syslog(LOG_ERR, "%s: DNS has no TXT Record", whoami);
#endif
			goto thr_reset;

		case NO_RECOVERY:
			/*
			 * Non-Recoverable error occurred. No sense
			 * in keep pinging the DNS server at this
			 * point, so we disable any further contact.
			 */
#ifdef	DEBUG
			syslog(LOG_ERR, EMSG_DNS_DISABLE, whoami);
#endif
			(void) rw_wrlock(&s_dns_impl_lock);
			s_dns_disabled = TRUE;
			(void) rw_unlock(&s_dns_impl_lock);
			goto thr_reset;

		case HOST_NOT_FOUND:
			/*
			 * Authoritative NS not responding...
			 * keep trying for non-authoritative reply
			 */
			/*FALLTHROUGH*/

		case TRY_AGAIN:
			/* keep trying */
#ifdef	DEBUG
			syslog(LOG_ERR, "%s: retrying...", whoami);
#endif
			break;

		case NETDB_INTERNAL:
		default:
#ifdef	DEBUG
			syslog(LOG_ERR, "%s: Internal resolver error: %s",
			    whoami, strerror(errno));
#endif
			goto thr_reset;
		}

		resolv_destroy();
	}
thr_reset:
	(void) rw_wrlock(&s_dns_data_lock);
	dns_txt_cached = 0;
	(void) rw_unlock(&s_dns_data_lock);
	resolv_txt_reset();

thr_okay:
	resolv_destroy();
	/* mark thread as done */
	(void) rw_wrlock(&s_dns_impl_lock);
	s_dns_qthr_created = FALSE;
	(void) rw_unlock(&s_dns_impl_lock);

	(void) thr_exit(NULL);
	/*NOTREACHED*/
	return (NULL);
}

/*
 * nfsmapid's interface into the resolver for getting the TXT record.
 *
 * Key concepts:
 *
 * o If the DNS server is available and the TXT record is found, we
 *   simply decode the output and fill the exported dns_txt_domain
 *   global, so our caller can configure the daemon appropriately.
 *
 * o If the TXT record is not found, then having done resolv_txt_reset()
 *   first will allow our caller to recognize that the exported globals
 *   are empty and thus configure nfsmapid to use the default DNS domain.
 *
 * o Having no /etc/resolv.conf file is pretty much a show stopper, since
 *   there is no name server address information. We return since we've
 *   already have reset the TXT global state.
 *
 * o If a previous call to the DNS server resulted in an unrecoverable
 *   error, then we disable further contact to the DNS server and return.
 *   Having the TXT global state already reset guarantees that our caller
 *   will fall back to the right configuration.
 *
 * o Query thread creation is throttled by s_dns_qthr_created. We mitigate
 *   the problem of an already unresponsive DNS server by allowing at most
 *   1 outstanding query thread since we could potentially have a substantial
 *   amount of clients hammering on the same DNS server attempting to get
 *   the TXT record.
 */
static void
get_dns_txt_domain(cb_t *argp)
{
	int		err;
#ifdef	DEBUG
	static uint64_t	msg_done = 0;
	char		*whoami = "get_dns_txt_domain";
#endif
	long		thr_flags = THR_DETACHED;
	struct stat	st;

	/*
	 * We reset TXT variables first in case /etc/resolv.conf
	 * is missing or we've had unrecoverable resolver errors,
	 * we'll default to get_dns_domain(). If a previous DNS
	 * TXT RR was found, don't clear it until we're certain
	 * that contact can be made to the DNS server (see block
	 * comment atop resolv_txt_reset). If we're responding to
	 * a SIGHUP signal, force a reset of the cached copy.
	 */
	if (argp && argp->signal) {
		(void) rw_wrlock(&s_dns_data_lock);
		dns_txt_cached = 0;
		(void) rw_unlock(&s_dns_data_lock);
	}
	resolv_txt_reset();

	errno = 0;
	if (stat(_PATH_RESCONF, &st) < 0 && errno == ENOENT) {
		/*
		 * If /etc/resolv.conf is not there, then we'll
		 * get the domain from domainname(8). No real
		 * reason to query DNS or fire a thread since we
		 * have no nameserver addresses.
		 */
		(void) rw_wrlock(&s_dns_data_lock);
		dns_txt_cached = 0;
		(void) rw_unlock(&s_dns_data_lock);
		resolv_txt_reset();
		return;
	}

	(void) rw_rdlock(&s_dns_impl_lock);
	if (s_dns_disabled) {
		/*
		 * If there were non-recoverable problems with DNS,
		 * we have stopped querying DNS entirely. See
		 * NO_RECOVERY clause below.
		 */
#ifdef	DEBUG
		syslog(LOG_ERR, "%s: DNS queries disabled", whoami);
#endif
		(void) rw_unlock(&s_dns_impl_lock);
		return;
	}
	(void) rw_unlock(&s_dns_impl_lock);

	if (resolv_init() < 0) {
		/*
		 * Failed to initialize resolver. Do not
		 * query DNS server.
		 */
		(void) rw_wrlock(&s_dns_data_lock);
		dns_txt_cached = 0;
		(void) rw_unlock(&s_dns_data_lock);
		resolv_txt_reset();
		return;
	}
	switch (resolv_search()) {
	case NETDB_SUCCESS:
		/*
		 * If there _is_ a TXT record, we let
		 * our caller set the global state.
		 */
		resolv_decode();
		resolv_get_txt_data();
		break;

	case TRY_AGAIN:
		if (argp == NULL || argp->fcn == NULL)
			/*
			 * If no valid argument was passed or
			 * callback defined, don't fire thread
			 */
			break;

		(void) rw_wrlock(&s_dns_impl_lock);
		if (s_dns_qthr_created) {
			/*
			 * We may have lots of clients, so we don't
			 * want to bog down the DNS server with tons
			 * of requests... lest it becomes even more
			 * unresponsive, so limit 1 thread to query
			 * DNS at a time.
			 */
#ifdef	DEBUG
			syslog(LOG_ERR, "%s: query thread already active",
			    whoami);
#endif
			(void) rw_unlock(&s_dns_impl_lock);
			break;
		}

		/*
		 * DNS did not respond ! Set timeout and kick off
		 * thread to try op again after s_dns_tout seconds.
		 * We've made sure that we don't have an already
		 * running thread above.
		 */
		s_dns_tout = NFSMAPID_DNS_TOUT_SECS;
		err = thr_create(NULL, 0, resolv_query_thread, (void *)argp,
		    thr_flags, &s_dns_qthread);
		if (!err) {
			s_dns_qthr_created = TRUE;
		}
#ifdef DEBUG
		else {
			msg_done++;
			if (!(msg_done % NFSMAPID_SLOG_RATE))
				syslog(LOG_ERR, EMSG_DNS_THREAD_ERROR);
		}
#endif
		(void) rw_unlock(&s_dns_impl_lock);
		break;

	case NO_RECOVERY:
#ifdef	DEBUG
		syslog(LOG_ERR, EMSG_DNS_DISABLE, whoami);
#endif
		(void) rw_wrlock(&s_dns_impl_lock);
		s_dns_disabled = TRUE;
		(void) rw_unlock(&s_dns_impl_lock);

		/*FALLTHROUGH*/

	default:
		/*
		 * For any other errors... DNS is responding, but
		 * either it has no data, or some other problem is
		 * occuring. At any rate, the TXT domain should not
		 * be used, so we default to the DNS domain.
		 */
		(void) rw_wrlock(&s_dns_data_lock);
		dns_txt_cached = 0;
		(void) rw_unlock(&s_dns_data_lock);
		resolv_txt_reset();
		break;
	}

	resolv_destroy();
}

static int
get_mtime(const char *fname, timestruc_t *mtim)
{
	struct stat st;
	int err;

	if ((err = stat(fname, &st)) != 0)
		return (err);

	*mtim = st.st_mtim;
	return (0);
}


/*
 * trim_wspace is a destructive interface; it is up to
 * the caller to save off an original copy if needed.
 */
static char *
trim_wspace(char *dp)
{
	char	*r;
	char	*ndp;

	/*
	 * Any empty domain is not valid
	 */
	if (dp == NULL)
		return (NULL);

	/*
	 * Skip leading blanks
	 */
	for (ndp = dp; *ndp != '\0'; ndp++) {
		if (!isspace(*ndp))
			break;
	}

	/*
	 * If we reached the end of the string w/o
	 * finding a non-blank char, return error
	 */
	if (*ndp == '\0')
		return (NULL);

	/*
	 * Find next blank in string
	 */
	for (r = ndp; *r != '\0'; r++) {
		if (isspace(*r))
			break;
	}

	/*
	 * No more blanks found, we are done
	 */
	if (*r == '\0')
		return (ndp);

	/*
	 * Terminate string at blank
	 */
	*r++ = '\0';

	/*
	 * Skip any trailing spaces
	 */
	while (*r != '\0') {
		/*
		 * If a non-blank is found, it is an
		 * illegal domain (embedded blanks).
		 */
		if (!isspace(*r))
			return (NULL);
		r++;
	}
	return (ndp);
}

static void
get_nfs_domain(void)
{
	char value[NS_MAXCDNAME];
	int	ret, bufsz = NS_MAXCDNAME;

	/*
	 * Get NFSMAPID_DOMAIN property value from SMF.
	 */
	bzero(value, NS_MAXCDNAME);
	ret = nfs_smf_get_prop("nfsmapid_domain", value, DEFAULT_INSTANCE,
	    SCF_TYPE_ASTRING, NFSMAPID, &bufsz);
	if (ret == SA_OK && *value != '\0') {
		char *dp = NULL;
#ifdef DEBUG
		char    *whoami = "get_nfs_domain";
		char	orig[NS_MAXCDNAME] = {0};
		(void) strncpy(orig, value, NS_MAXCDNAME);
#endif
		/*
		 * NFSMAPID_DOMAIN was set, so it's time for validation. If
		 * it's okay, then update NFS domain and return. If not,
		 * bail (syslog in DEBUG). We make nfsmapid more a bit
		 * more forgiving of trailing and leading white space.
		 */
		if ((dp = trim_wspace(value)) != NULL) {
			if (mapid_stdchk_domain(dp) > 0) {
				nfs_domain_len = strlen(dp);
				(void) strncpy(nfs_domain, dp, NS_MAXCDNAME);
				nfs_domain[NS_MAXCDNAME] = '\0';
				return;
			}
		}
#ifdef	DEBUG
		if (orig[0] != '\0') {
			syslog(LOG_ERR, gettext("%s: Invalid domain name \"%s\""
			    " found in SMF."), whoami, orig);
		}
#endif
	}
	/*
	 * So the NFS SMF parameter nfsmapid_domain cannot be obtained or
	 * there is an invalid nfsmapid_domain property value.
	 * Time to zap current NFS domain info.
	 */
	ZAP_DOMAIN(nfs);
}

static void
get_dns_domain(void)
{
	timestruc_t	 ntime = {0};

	/*
	 * If we can't get stats for the config file, then
	 * zap the DNS domain info.  If mtime hasn't changed,
	 * then there's no work to do, so just return.
	 */
	errno = 0;
	if (get_mtime(_PATH_RESCONF, &ntime) != 0) {
		switch (errno) {
			case ENOENT:
				/*
				 * The resolver defaults to obtaining the
				 * domain off of the NIS domainname(8) if
				 * /etc/resolv.conf does not exist, so we
				 * move forward.
				 */
				break;

			default:
				ZAP_DOMAIN(dns);
				return;
		}
	} else if (TIMESTRUC_EQ(ntime, dns_mtime))
		return;

	/*
	 * Re-initialize resolver to zap DNS domain from previous
	 * resolv_init() calls.
	 */
	(void) resolv_init();

	/*
	 * Update cached DNS domain.  No need for validation since
	 * domain comes from resolver.  If resolver doesn't return the
	 * domain, then zap the DNS domain.  This shouldn't ever happen,
	 * and if it does, the machine has bigger problems (so no need
	 * to generate a message that says DNS appears to be broken).
	 */
	(void) rw_rdlock(&s_dns_data_lock);
	if (sysdns_domain[0] != '\0') {
		(void) strncpy(dns_domain, sysdns_domain, NS_MAXCDNAME);
		dns_domain_len = strlen(sysdns_domain);
		(void) rw_unlock(&s_dns_data_lock);
		dns_mtime = ntime;
		resolv_destroy();
		return;
	}
	(void) rw_unlock(&s_dns_data_lock);

	ZAP_DOMAIN(dns);

	resolv_destroy();

}

/*
 * PSARC 2005/487 Contracted Sun Private Interface
 * mapid_stdchk_domain()
 * Changes must be reviewed by Solaris File Sharing
 * Changes must be communicated to contract-2005-487-01@sun.com
 *
 * Based on the recommendations from RFC1033 and RFC1035, check
 * if a given domain name string is valid. Return values are:
 *
 *       1 = valid domain name
 *       0 = invalid domain name (or invalid embedded character)
 *      -1 = domain length > NS_MAXCDNAME
 */
int
mapid_stdchk_domain(const char *ds)
{
	int	i;
	size_t	len;

	if (ds[0] == '\0')
		return (0);
	else
		len = strlen(ds) - 1;

	/*
	 * 1st _AND_ last char _must_ be alphanumeric.
	 * We check for other valid chars below.
	 */
	if ((!isalpha(ds[0]) && !isdigit(ds[0])) ||
	    (!isalpha(ds[len]) && !isdigit(ds[len])))
		return (0);

	for (i = 0; *ds && i <= NS_MAXCDNAME; i++, ds++) {
		if (!isalpha(*ds) && !isdigit(*ds) &&
		    (*ds != '.') && (*ds != '-') && (*ds != '_'))
			return (0);
	}
	return (i == (NS_MAXCDNAME + 1) ? -1 : 1);
}

/*
 * PSARC 2005/487 Consolidation Private
 * mapid_reeval_domain()
 * Changes must be reviewed by Solaris File Sharing
 */
void
mapid_reeval_domain(cb_t *arg)
{
	char	*domain = NULL;

	get_nfs_domain();
	if (nfs_domain_len != 0) {
		domain = nfs_domain;
		goto dsync;
	}

	get_dns_txt_domain(arg);
	if (dns_txt_domain_len != 0)
		domain = dns_txt_domain;
	else {
		/*
		 * We're either here because:
		 *
		 *  . NFSMAPID_DOMAIN was not set in /etc/default/nfs
		 *  . No suitable DNS TXT resource record exists
		 *  . DNS server is not responding to requests
		 *
		 * in either case, we want to default to using the
		 * system configured DNS domain. If this fails, then
		 * dns_domain will be empty and dns_domain_len will
		 * be 0.
		 */
		get_dns_domain();
		domain = dns_domain;
	}

dsync:
	domain_sync(arg, domain);
}

/*
 * PSARC 2005/487 Consolidation Private
 * mapid_get_domain()
 * Changes must be reviewed by Solaris File Sharing
 *
 * The use of TSD in mapid_get_domain() diverges slightly from the typical
 * TSD use, since here, the benefit of doing TSD is mostly to allocate
 * a per-thread buffer that will be utilized by other up-calls to the
 * daemon.
 *
 * In doors, the thread used for the upcall never really exits, hence
 * the typical destructor function defined via thr_keycreate() will
 * never be called. Thus, we only use TSD to allocate the per-thread
 * buffer and fill it up w/the configured 'mapid_domain' on each call.
 * This still alleviates the problem of having the caller free any
 * malloc'd space.
 */
char *
mapid_get_domain(void)
{
	void	*tsd = NULL;

	(void) thr_getspecific(s_thr_key, &tsd);
	if (tsd == NULL) {
		tsd = malloc(NS_MAXCDNAME+1);
		if (tsd != NULL) {
			(void) rw_rdlock(&mapid_domain_lock);
			(void) strncpy((char *)tsd, mapid_domain, NS_MAXCDNAME);
			(void) rw_unlock(&mapid_domain_lock);
			(void) thr_setspecific(s_thr_key, tsd);
		}
	} else {
		(void) rw_rdlock(&mapid_domain_lock);
		(void) strncpy((char *)tsd, mapid_domain, NS_MAXCDNAME);
		(void) rw_unlock(&mapid_domain_lock);
	}
	return ((char *)tsd);
}

/*
 * PSARC 2005/487 Contracted Sun Private Interface
 * mapid_derive_domain()
 * Changes must be reviewed by Solaris File Sharing
 * Changes must be communicated to contract-2005-487-01@sun.com
 *
 * This interface is called solely via sysidnfs4 iff no
 * NFSMAPID_DOMAIN was found. So, there is no ill effect
 * of having the reeval function call get_nfs_domain().
 */
char *
mapid_derive_domain(void)
{
	cb_t	cb = {0};

	_lib_init();
	mapid_reeval_domain(&cb);
	return (mapid_get_domain());
}

void
_lib_init(void)
{
	(void) resolv_init(); /* May fail! */
	(void) rwlock_init(&mapid_domain_lock, USYNC_THREAD, NULL);
	(void) thr_keycreate(&s_thr_key, NULL);
	lib_init_done++;
	resolv_destroy();
}

void
_lib_fini(void)
{
	resolv_destroy();
}
