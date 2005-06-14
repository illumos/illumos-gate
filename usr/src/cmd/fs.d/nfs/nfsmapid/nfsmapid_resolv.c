/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * PSARC/2004/154 nfsmapid DNS enhancements implementation.
 *
 * As per RFC 3050, file owner and group attributes in version 4 of the
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
#define	__NFSMAPID_RES_IMPL
#include "nfsmapid_resolv.h"

/*
 * DEBUG Only
 * Decode any resolver errors and print out message to log
 */
static int
resolv_error(void)
{
	static uint64_t	 msg_done[NS_ERRS] = {0};

	switch (h_errno) {
		case NETDB_INTERNAL:
			IDMAP_DBG(EMSG_NETDB_INTERNAL, strerror(errno), NULL);
			break;

		case HOST_NOT_FOUND:
			(void) rw_rdlock(&s_dns_impl_lock);
			msg_done[h_errno]++;
#ifdef DEBUG
			if (!(msg_done[h_errno] % NFSMAPID_SLOG_RATE))
				IDMAP_DBG(EMSG_HOST_NOT_FOUND, s_dname, NULL);
#endif
			(void) rw_unlock(&s_dns_impl_lock);
			break;

		case TRY_AGAIN:
			/*
			 * Nameserver is not responding.
			 * Try again after a given timeout.
			 */
			(void) rw_rdlock(&s_dns_impl_lock);
			msg_done[h_errno]++;
#ifdef DEBUG
			if (!(msg_done[h_errno] % NFSMAPID_SLOG_RATE))
				IDMAP_DBG(EMSG_TRY_AGAIN, s_dname, NULL);
#endif
			(void) rw_unlock(&s_dns_impl_lock);
			break;

		case NO_RECOVERY:
			/*
			 * This msg only really happens once, due
			 * to s_dns_disabled flag (see below)
			 */
			IDMAP_DBG(EMSG_NO_RECOVERY, hstrerror(h_errno), NULL);
			break;

		case NO_DATA:
			/*
			 * No entries in the nameserver for
			 * the specific record or record type.
			 */
			(void) rw_rdlock(&s_dns_impl_lock);
			msg_done[h_errno]++;
#ifdef DEBUG
			if (!(msg_done[h_errno] % NFSMAPID_SLOG_RATE))
				IDMAP_DBG(EMSG_NO_DATA, NFSMAPID_DNS_RR,
				    s_dname);
#endif
			(void) rw_unlock(&s_dns_impl_lock);
			break;

		case NETDB_SUCCESS:
		default:
			break;
	}
	return (h_errno);
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

	(void) rw_wrlock(&dns_data_lock);
	if (!dns_txt_cached) {
		dns_txt_domain_len = 0;
		bzero(dns_txt_domain, DNAMEMAX);
	}
	(void) rw_unlock(&dns_data_lock);
}

/*
 * Initialize resolver and populate &s_res struct
 *
 * DNS Domain is saved off sysdns_domain in case we
 * need to fall back to using the DNS domain name as
 * the v4 attribute string domain.
 */
int
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

	(void) rw_wrlock(&dns_data_lock);
	(void) snprintf(sysdns_domain, len, "%s", res.defdname);
	(void) rw_unlock(&dns_data_lock);

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
		IDMAP_DBG("%s", strerror(errno), NULL);
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
	NS_GET16(dlen, p);
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
	static uint64_t	 msg_done = 0;
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
	if (rr_base[0] != '\0' && standard_domain_str(tmp_txt_rr)) {
		(void) rw_wrlock(&s_dns_impl_lock);
		(void) strncpy(s_txt_rr, rr_base, len);
		(void) rw_unlock(&s_dns_impl_lock);
		IDMAP_DBG("TXT (Rec):\t%s", s_txt_rr, NULL);

	} else if (!(msg_done++ % NFSMAPID_SLOG_RATE)) {
		/*
		 * Otherwise, log the error
		 */
		(void) rw_rdlock(&s_dns_impl_lock);
		IDMAP_DBG(EMSG_DNS_RR_INVAL, NFSMAPID_DNS_RR, s_dname);
		(void) rw_unlock(&s_dns_impl_lock);
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
	uint_t		 class;
	int		 dlen;
	ulong_t		 ttl;
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
		IDMAP_DBG("errno: %s", strerror(errno), NULL);
		IDMAP_DBG("h_errno: %s", hstrerror(h_errno), NULL);
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
			IDMAP_DBG("%s", strerror(errno), NULL);
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
	IDMAP_DBG("Query:\t\t%-30s", name, NULL);
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

		NS_GET16(type, p);
		NS_GET16(class, p);
		NS_GET32(ttl, p);
		NS_GET16(dlen, p);

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
		(void) rw_wrlock(&dns_data_lock);
		(void) snprintf(dns_txt_domain, strlen(s_txt_rr) + 1, "%s",
								s_txt_rr);
		dns_txt_domain_len = strlen(dns_txt_domain);
		dns_txt_cached = 1;
		(void) rw_unlock(&dns_data_lock);
	}
	(void) rw_unlock(&s_dns_impl_lock);
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
void *
resolv_query_thread(void *arg)
{
#ifdef DEBUG
	char		*whoami = "query_thread";
#endif
	uint32_t	 nap_time;

	IDMAP_DBG("query_thread active !", NULL, NULL);
	(void) rw_rdlock(&s_dns_impl_lock);
	nap_time = s_dns_tout;
	(void) rw_unlock(&s_dns_impl_lock);

	for (;;) {
		(void) sleep(nap_time);

		resolv_txt_reset();
		(void) resolv_init();
		switch (resolv_search()) {
			case NETDB_SUCCESS:
				IDMAP_DBG("%s: DNS replied", whoami, NULL);
				resolv_decode();
				resolv_get_txt_data();

				/*
				 * This is a bit different than what we
				 * do in get_dns_txt_domain(). Here, the
				 * thread _must_ update the global state
				 * if a new TXT record was found.
				 */
				(void) rw_rdlock(&dns_data_lock);
				if (dns_txt_domain_len != 0) {
					/*
					 * Update global state and only
					 * flush the cache if there were
					 * any updates to cur_domain
					 */
					(void) rw_wrlock(&domain_cfg_lock);
					(void) strncpy(cur_domain,
							dns_txt_domain,
							DNAMEMAX-1);
					cur_domain_len = dns_txt_domain_len;
					update_diag_file(cur_domain);
					DTRACE_PROBE1(nfsmapid, thread__domain,
					    cur_domain);
					(void) rw_unlock(&domain_cfg_lock);
					idmap_kcall(-1);
				}
				(void) rw_unlock(&dns_data_lock);
				goto thr_okay;

			case NO_DATA:
				/*
				 * DNS is up now, but does not have
				 * the NFSV4IDMAPDOMAIN TXT record.
				 */
				IDMAP_DBG("%s: DNS has no TXT Record", whoami,
				    NULL);
				goto thr_reset;

			case NO_RECOVERY:
				/*
				 * Non-Recoverable error occurred. No sense
				 * in keep pinging the DNS server at this
				 * point, so we disable any further contact.
				 */
				IDMAP_DBG(EMSG_DNS_DISABLE, whoami, NULL);
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
				IDMAP_DBG("%s: retrying...", whoami, NULL);
				break;

			case NETDB_INTERNAL:
			default:
				IDMAP_DBG("%s: Internal resolver error: %s",
				    whoami, strerror(errno));
				goto thr_reset;
		}
	}
thr_reset:
	(void) rw_wrlock(&dns_data_lock);
	dns_txt_cached = 0;
	(void) rw_unlock(&dns_data_lock);
	resolv_txt_reset();

thr_okay:
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
void
get_dns_txt_domain(int sighup)
{
	int		err;
#ifdef DEBUG
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
	if (sighup) {
		(void) rw_wrlock(&dns_data_lock);
		dns_txt_cached = 0;
		(void) rw_unlock(&dns_data_lock);
	}
	resolv_txt_reset();

	errno = 0;
	if (stat(_PATH_RESCONF, &st) < 0 && errno == ENOENT) {
		/*
		 * If /etc/resolv.conf is not there, then we'll
		 * get the domain from domainname(1M). No real
		 * reason to query DNS or fire a thread since we
		 * have no nameserver addresses.
		 */
		goto txtclear;
	}

	(void) rw_rdlock(&s_dns_impl_lock);
	if (s_dns_disabled) {
		/*
		 * If there were non-recoverable problems with DNS,
		 * we have stopped querying DNS entirely. See
		 * NO_RECOVERY clause below.
		 */
		IDMAP_DBG("%s: DNS queries disabled", whoami, NULL);
		(void) rw_unlock(&s_dns_impl_lock);
		return;
	}
	(void) rw_unlock(&s_dns_impl_lock);

	(void) resolv_init();
	switch (resolv_search()) {
		case NETDB_SUCCESS:
			/*
			 * If there _is_ a TXT record, we let
			 * our caller set the global state.
			 */
			resolv_decode();
			resolv_get_txt_data();
			return;

		case TRY_AGAIN:
			(void) rw_wrlock(&s_dns_impl_lock);
			if (s_dns_qthr_created) {
				/*
				 * We may have lots of clients, so we don't
				 * want to bog down the DNS server with tons
				 * of requests... lest it becomes even more
				 * unresponsive, so limit 1 thread to query
				 * DNS at a time.
				 */
				IDMAP_DBG("%s: query thread already active",
				    whoami, NULL);
				(void) rw_unlock(&s_dns_impl_lock);
				return;
			}

			/*
			 * DNS did not respond ! Set timeout and kick off
			 * thread to try op again after s_dns_tout seconds.
			 * We've made sure that we don't have an already
			 * running thread above.
			 */
			s_dns_tout = NFSMAPID_DNS_TOUT_SECS;
			err = thr_create(NULL, 0, resolv_query_thread, NULL,
			    thr_flags, &s_dns_qthread);
			if (!err) {
				s_dns_qthr_created = TRUE;
			}
#ifdef DEBUG
			else {
				msg_done++;
				if (!(msg_done % NFSMAPID_SLOG_RATE))
					IDMAP_DBG(EMSG_DNS_THREAD_ERROR, NULL,
					    NULL);
			}
#endif
			(void) rw_unlock(&s_dns_impl_lock);
			return;

		case NO_RECOVERY:
			IDMAP_DBG(EMSG_DNS_DISABLE, whoami, NULL);
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
			break;
	}

txtclear:
	(void) rw_wrlock(&dns_data_lock);
	dns_txt_cached = 0;
	(void) rw_unlock(&dns_data_lock);
	resolv_txt_reset();
}
