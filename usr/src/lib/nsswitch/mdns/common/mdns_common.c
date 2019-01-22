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

#include "mdns_common.h"

static int _nss_mdns_queryrecord(const char *rrname, int rrclass, int rrtype,
		DNSServiceQueryRecordReply callback,
		struct mdns_querydata *data);
static void _nss_mdns_get_svcstatetimestamp(struct timeval *);
static void _nss_mdns_loadsmfcfg(mdns_backend_ptr_t);
static void _nss_mdns_freesmfcfg(mdns_backend_ptr_t);
static boolean_t cmpdmn(char *, char **, int);
static char *RDataToName(char *data, char *buffer, int datalen, int buflen);
static int searchdomain(mdns_backend_ptr_t, char *, int, char **);
static boolean_t validdomain(mdns_backend_ptr_t, char *, int);

/*
 * This file includes the functions to query for host name
 * information via Multicast DNS (mDNS). The function
 * _nss_mdns_queryrecord queries for the host information via
 * Multicast DNS. _nss_mdns_querybyname and _nss_mdns_querybyaddr
 * query for host IP address and hostname by querying for A/AAAA
 * and PTR DNS resource records respectively. DNSServiceQueryRecord
 * in libdns_sd sends a request to the mDNS daemon (mdnsd) to place
 * the DNS query via multicast and return the results.
 * mdnsd is managed by SMF (FMRI: svc:/network/dns/multicast:default).
 *
 * gethostent.c and gethostent6.c implement the nsswitch 'hosts'
 * backend module getXbyY functions: getbyname and getbyaddr.
 * getby* functions in gethostent.c  supports only IPv4 and
 * getby* functions in gethostent6.c returns both IPv4 and
 * IPv6 results. Functions in gethostent.c and gethostent6.c
 * call the _nss_mdns_queryby* functions in mdns_common.c to
 * query for host information via mDNS.
 *
 * Configuration for mdns is stored in SMF and is accessed using
 * the FMRI: svc:/network/dns/multicast:default. Configuration
 * includes the list of valid DNS domains checked before querying host
 * information via mDNS and the search list to use for host lookup via
 * mDNS. The default valid domain list in the mDNS service supports host
 * lookups for hostnames in the ".local" domain and hostname queries
 * for link-local IPv4 and IPv6 addresses. _nss_mdns_loadsmfcfg
 * loads the nss_mdns configuration from SMF and the function
 * _nss_mdns_updatecfg checks for any updates in nss_mdns configuration.
 */

static int
_nss_mdns_queryrecord(const char *rrname, int rrclass, int rrtype,
		DNSServiceQueryRecordReply callback,
		struct mdns_querydata *data)
{
	int sockfd;
	int flags = kDNSServiceFlagsForceMulticast;  /* Multicast only */
	int opinterface = kDNSServiceInterfaceIndexAny;
	DNSServiceErrorType err;
	DNSServiceRef ref = NULL;
	int ret;
	struct fd_set readfds;
	struct timeval tv;

	data->status = NSS_NOTFOUND;
#ifdef DEBUG
	syslog(LOG_DEBUG, "nss_mdns: query called rrname:%s rrtype:%d",
	    rrname, rrtype);
#endif
	err = DNSServiceQueryRecord(&ref, flags, opinterface,
	    rrname, rrtype, rrclass, callback, data);
	if (err != kDNSServiceErr_NoError || ref == NULL ||
	    (sockfd = DNSServiceRefSockFD(ref)) == 0) {
		DNSServiceRefDeallocate(ref);
		data->status = NSS_UNAVAIL;
		return (NSS_UNAVAIL);
	}

	do {
		FD_ZERO(&readfds);
		FD_SET(sockfd, &readfds);
		tv.tv_sec = NSSMDNS_MAXQRYTMO;
		tv.tv_usec = 0;

		/* Wait until response received from mDNS daemon */
		ret = select(sockfd + 1, &readfds, NULL, NULL, &tv);
		if (!((ret > 0) && FD_ISSET(sockfd, &readfds) &&
		    (DNSServiceProcessResult(ref) == kDNSServiceErr_NoError))) {
			data->status = NSS_NOTFOUND;
			if (errno != EINTR)
				data->qrydone = B_TRUE;
		}
	} while (data->qrydone != B_TRUE);

	if (data->status == NSS_SUCCESS && (data->withttlbuffer == NULL)) {
		nss_XbyY_args_t *argp = data->argp;
		if (argp->buf.result != NULL) {
			int stat;

			if (data->buffer == NULL) {
				data->status = NSS_NOTFOUND;
				DNSServiceRefDeallocate(ref);
				return (data->status);
			}
			stat = (*argp->str2ent)(data->buffer,
			    strlen(data->buffer),
			    argp->buf.result, argp->buf.buffer,
			    argp->buf.buflen);
			if (stat == NSS_STR_PARSE_SUCCESS) {
				argp->returnval = argp->buf.result;
				argp->returnlen = 1;
			} else {
				data->status = NSS_NOTFOUND;
				if (stat == NSS_STR_PARSE_ERANGE)
					argp->erange = 1;
			}
			free(data->buffer);
		} else {
			argp->returnval = argp->buf.buffer;
			argp->returnlen = strlen(argp->buf.buffer);
		}
		data->buffer = NULL;
		data->buflen = 0;
	}

	if (data->status != NSS_SUCCESS)
		data->argp->h_errno = HOST_NOT_FOUND;

	DNSServiceRefDeallocate(ref);
	return (data->status);
}

static void
/* LINTED E_FUNC_ARG_UNUSED */
_nss_mdns_querynamereply(DNSServiceRef sdRef, const DNSServiceFlags flags,
		/* LINTED E_FUNC_ARG_UNUSED */
		uint32_t ifIndex, DNSServiceErrorType errorCode,
		const char *fullname, uint16_t rrtype, uint16_t rrclass,
		/* LINTED E_FUNC_ARG_UNUSED */
		uint16_t rdlen, const void *rdata, uint32_t ttl,
		void *context)
{
	struct mdns_querydata *qdata;
	nss_XbyY_args_t *argp;
	int firstent = 0;
	int af;
	char addrstore[INET6_ADDRSTRLEN];
	char *buffer;
	int len;
	int remlen;

	qdata = (struct mdns_querydata *)context;
	argp = qdata->argp;

	if (errorCode != kDNSServiceErr_NoError) {
		qdata->qrydone = B_TRUE;
		return;
	}
	if ((flags & kDNSServiceFlagsMoreComing))
		qdata->qrydone = B_FALSE;
	else
		qdata->qrydone = B_TRUE;
	if (!(flags & kDNSServiceFlagsAdd))
		return;
	if (rrclass != kDNSServiceClass_IN)
		return;

	if (rrtype == kDNSServiceType_A)
		af = AF_INET;
	else if (rrtype == kDNSServiceType_AAAA)
		af = AF_INET6;
	else
		return;

	if (qdata->buffer == NULL) {
		if (qdata->withttlbsize > 0) {
			remlen = qdata->buflen =
			    qdata->withttlbsize;
			buffer = qdata->buffer =
			    qdata->withttlbuffer;
			(void) memset(qdata->buffer, 0, remlen);
		} else {
			remlen = qdata->buflen =
			    argp->buf.buflen;
			if (argp->buf.result != NULL) {
				buffer = qdata->buffer =
				    calloc(1, remlen);
			} else {
				/* Return in file format */
				(void) memset(argp->buf.buffer,
				    0, remlen);
				buffer = qdata->buffer = argp->buf.buffer;
			}
		}
		firstent = 1;
	} else {
		buffer = qdata->buffer + strlen(qdata->buffer);
		remlen = qdata->buflen - strlen(qdata->buffer);
	}

#ifdef DEBUG
	syslog(LOG_DEBUG, "nss_mdns: querynamereply remlen:%d", remlen);
#endif
	if (inet_ntop(af, rdata, addrstore, INET6_ADDRSTRLEN) != NULL) {
		if (firstent)
			len = snprintf(buffer, remlen, "%s %s",
			    addrstore, fullname);
		else
			len = snprintf(buffer, remlen, "\n%s %s",
			    addrstore, fullname);
		if (len >= remlen || len < 0) {
			qdata->status = NSS_NOTFOUND;
			qdata->argp->erange = 1;
			qdata->argp->h_errno = HOST_NOT_FOUND;
			return;
		}
		qdata->ttl	= ttl;
		qdata->status	= NSS_SUCCESS;
#ifdef DEBUG
		syslog(LOG_DEBUG, "nss_mdns: querynamereply buffer:%s", buffer);
#endif
	} else {
		qdata->status = NSS_NOTFOUND;
		qdata->argp->h_errno = HOST_NOT_FOUND;
	}
}

int
_nss_mdns_querybyname(mdns_backend_ptr_t be, char *qname,
		int af, struct mdns_querydata *data)
{
	int rrtype;
	int rrclass;
	int srchidx = 0;
	int rc;
	char hname[MAXDNAME];
	char *name;
	char *sname;

	rrclass = kDNSServiceClass_IN;
	if (af == AF_INET6)
		rrtype = kDNSServiceType_ANY;
	else if (af == AF_INET)
		rrtype = kDNSServiceType_A;
	else
		return (NSS_NOTFOUND);

	name = strdup(qname);
	if (name == NULL)
		return (NSS_UNAVAIL);

	while ((srchidx = searchdomain(be, name, srchidx, &sname)) != -1) {
		if (sname != NULL)
			(void) snprintf(hname, sizeof (hname), "%s.%s",
			    name, sname);
		else
			(void) strlcpy(hname, name, sizeof (hname));
#ifdef DEBUG
	syslog(LOG_DEBUG, "nss_mdns: querybyname called" \
	    " srchidx:%d af:%d hname:%s", srchidx, af, qname);
#endif
		rc = _nss_mdns_queryrecord(hname, rrclass, rrtype,
		    _nss_mdns_querynamereply, data);
		if ((rc == NSS_UNAVAIL) || (rc == NSS_SUCCESS)) {
			free(name);
			return (rc);
		}
	}
	free(name);
	return (NSS_NOTFOUND);
}

static void
/* LINTED E_FUNC_ARG_UNUSED */
_nss_mdns_queryaddrreply(DNSServiceRef sdRef, const DNSServiceFlags flags,
		/* LINTED E_FUNC_ARG_UNUSED */
		uint32_t ifIndex, DNSServiceErrorType errorCode,
		/* LINTED E_FUNC_ARG_UNUSED */
		const char *fullname, uint16_t rrtype, uint16_t rrclass,
		uint16_t rdlen, const void *rdata, uint32_t ttl,
		void *context)
{
	struct mdns_querydata *qdata;
	nss_XbyY_args_t *argp;
	char hostname[NI_MAXHOST];
	int firstent = 0;
	char *buffer;
	int len;
	int remlen;

	qdata = (struct mdns_querydata *)context;
	argp = qdata->argp;

	if (errorCode != kDNSServiceErr_NoError) {
		qdata->qrydone = B_TRUE;
		return;
	}
	if ((flags & kDNSServiceFlagsMoreComing))
		qdata->qrydone = B_FALSE;
	else
		qdata->qrydone = B_TRUE;
	if (!(flags & kDNSServiceFlagsAdd))
		return;
	if (rrclass != kDNSServiceClass_IN)
		return;
	if (rrtype != kDNSServiceType_PTR)
		return;

	if (qdata->buffer == NULL) {
		remlen = qdata->buflen = argp->buf.buflen;
		if (argp->buf.result != NULL) {
			buffer = qdata->buffer = calloc(1, remlen);
		} else {
			/* Return in file format */
			(void) memset(argp->buf.buffer, 0, remlen);
			buffer = qdata->buffer = argp->buf.buffer;
		}
		firstent = 1;
	} else {
		buffer = qdata->buffer + strlen(qdata->buffer);
		remlen = qdata->buflen - strlen(qdata->buffer);
	}

	if (RDataToName((char *)rdata, hostname, rdlen, NI_MAXHOST) == NULL) {
		qdata->status = NSS_NOTFOUND;
		qdata->argp->h_errno = HOST_NOT_FOUND;
		return;
	}

#ifdef DEBUG
	syslog(LOG_DEBUG, "nss_mdns: querynamereply remlen:%d", remlen);
#endif
	if (firstent)
		len = snprintf(buffer, remlen, "%s %s",
		    qdata->paddrbuf, hostname);
	else
		len = snprintf(buffer, remlen, "\n%s %s",
		    qdata->paddrbuf, hostname);
	if (len >= remlen || len < 0) {
		qdata->status = NSS_NOTFOUND;
		qdata->argp->erange = 1;
		qdata->argp->h_errno = HOST_NOT_FOUND;
		return;
	}
	qdata->status	= NSS_SUCCESS;
	qdata->ttl	= ttl;
}

int
/* LINTED E_FUNC_ARG_UNUSED */
_nss_mdns_querybyaddr(mdns_backend_ptr_t be, char *name, int af,
		struct mdns_querydata *data)
{
	int rrtype;
	int rrclass;

#ifdef DEBUG
	syslog(LOG_DEBUG, "nss_mdns: querybyaddr called" \
	    " af:%d addr:%s", af, name);
#endif
	rrclass = kDNSServiceClass_IN;
	rrtype = kDNSServiceType_PTR;

	if (validdomain(be, name, 0) == B_FALSE) {
		data->status = NSS_NOTFOUND;
		return (NSS_NOTFOUND);
	}
	return (_nss_mdns_queryrecord(name, rrclass, rrtype,
	    _nss_mdns_queryaddrreply, data));
}

/*
 * Converts the encoded name in RData returned
 * by mDNS query to name in file format
 */
static char *
RDataToName(char *data, char *buffer, int datalen, int buflen)
{
	char *src = data;
	char *srcend = data + datalen;
	char *ptr = buffer;
	char *end;
	char *bend = buffer + buflen - 1; /* terminal '\0' */
	int domainlen = 0;

	while ((src < srcend) && (*src != 0)) {

		/* first byte is len */
		domainlen = *src++;
		end = src + domainlen;

		while ((src < end) && (ptr < bend)) {
			uint8_t ch = *src++;
			if (ch == '.' || ch == '\\') {
				*ptr++ = '\\';
			}
			*ptr++ = ch;
		}

		/*
		 * Check if we copied entire domain str. and
		 * if space is still remaining for '.' seperator
		 */
		if ((src != end) || (ptr == bend))
			return (NULL);
		*ptr++ = '.';
	}
	*ptr = '\0';
	return (ptr);
}

nss_backend_t *
_nss_mdns_constr(mdns_backend_op_t ops[], int n_ops)
{
	mdns_backend_ptr_t	be;

	if ((be = (mdns_backend_ptr_t)calloc(1, sizeof (*be))) == NULL)
		return (NULL);
	be->ops = ops;
	be->n_ops = n_ops;
	_nss_mdns_updatecfg(be);
	return ((nss_backend_t *)be);
}

void
_nss_mdns_destr(mdns_backend_ptr_t be)
{
	if (be != NULL) {
		_nss_mdns_freesmfcfg(be);
		free(be);
	}
}

static int
searchdomain(mdns_backend_ptr_t be, char *name, int srchidx, char **sname)
{
	int trailing_dot = 0;
	char *ch;
	*sname = NULL;

	ch = name + strlen(name) - 1;
	if ((*ch) == '.')
		trailing_dot++;

	if (trailing_dot && srchidx > 0)
		/*
		 * If there is a trailing dot in the query
		 * name, do not perform any additional queries
		 * with search domains.
		 */
		return (-1);

	if (srchidx == 0) {
		/*
		 * If there is a trailing dot in the query
		 * or atleast one dot in the query name then
		 * perform a query as-is once first.
		 */
		++srchidx;
		if ((trailing_dot || (strchr(name, '.') != NULL))) {
			if (validdomain(be, name, 1) == B_TRUE)
				return (srchidx);
			else if (trailing_dot)
				return (-1);
		}
	}

	if ((srchidx > NSSMDNS_MAXSRCHDMNS) ||
	    (be->dmnsrchlist[srchidx-1] == NULL))
		return (-1);

	*sname = be->dmnsrchlist[srchidx-1];
	return (++srchidx);
}

/*
 * This function determines if the domain name in the query
 * matches any of the valid & search domains in the nss_mdns
 * configuration.
 */
static boolean_t
validdomain(mdns_backend_ptr_t be, char *name, int chksrchdmns)
{
	char *nameptr;

	/* Remove any trailing and leading dots in the name  */
	nameptr = name + strlen(name) - 1;
	while (*nameptr && (nameptr != name) && (*nameptr == '.'))
		nameptr--;
	*(++nameptr) = '\0';
	nameptr = name;
	while (*nameptr && (*nameptr == '.'))
		nameptr++;
	if (*nameptr == '\0')
		return (B_FALSE);

	/* Compare with search domains */
	if (chksrchdmns && (cmpdmn(nameptr, be->dmnsrchlist,
	    NSSMDNS_MAXSRCHDMNS) == B_TRUE))
		return (B_TRUE);

	/* Compare with valid domains */
	return (cmpdmn(nameptr, be->validdmnlist, NSSMDNS_MAXVALIDDMNS));
}

static boolean_t
cmpdmn(char *name, char **dmnlist, int maxdmns)
{
	char *vptr;
	int vdlen;
	char *cptr;
	int nlen;
	int i;

	nlen = strlen(name);
	for (i = 0; (i < maxdmns) &&
	    ((vptr = dmnlist[i]) != NULL); i++) {
		vdlen = strlen(vptr);
		if (vdlen > nlen)
			continue;
		cptr = name + nlen - vdlen;
		if (strncasecmp(cptr, vptr, vdlen) == 0)
			return (B_TRUE);
	}
	return (B_FALSE);
}

static void
_nss_mdns_get_svcstatetimestamp(struct timeval *ptv)
{
	scf_handle_t *h;
	scf_simple_prop_t *sprop;
	int32_t nsec;

	(void) memset(ptv, 0, sizeof (struct timeval));

	h = scf_handle_create(SCF_VERSION);
	if (h == NULL)
		return;

	if (scf_handle_bind(h) == -1) {
		scf_handle_destroy(h);
		return;
	}

	if ((sprop = scf_simple_prop_get(h, SMF_MDNS_FMRI,
	    SCF_PG_RESTARTER, SCF_PROPERTY_STATE_TIMESTAMP)) != NULL) {
		ptv->tv_sec = *(time_t *)(scf_simple_prop_next_time(sprop,
		    &nsec));
		ptv->tv_usec = nsec / 1000;
		scf_simple_prop_free(sprop);
	}

	if (h != NULL)
		scf_handle_destroy(h);
}

void
_nss_mdns_updatecfg(mdns_backend_ptr_t be)
{
	struct timeval statetimestamp;

	/*
	 * Update configuration if current svc state timestamp
	 * is different from last known svc state timestamp
	 */
	_nss_mdns_get_svcstatetimestamp(&statetimestamp);
	if ((statetimestamp.tv_sec == 0) && (statetimestamp.tv_usec == 0)) {
		syslog(LOG_ERR, "nss_mdns: error checking " \
		    "svc:/network/dns/multicast:default" \
		    " service timestamp");
	} else if ((be->conftimestamp.tv_sec == statetimestamp.tv_sec) &&
	    (be->conftimestamp.tv_usec == statetimestamp.tv_usec)) {
		return;
	}

	_nss_mdns_freesmfcfg(be);
	_nss_mdns_loadsmfcfg(be);
	be->conftimestamp.tv_sec = statetimestamp.tv_sec;
	be->conftimestamp.tv_usec = statetimestamp.tv_usec;
}

static void
load_mdns_domaincfg(scf_handle_t *h, char **storelist,
			const char *scfprop, int maxprops)
{
	scf_simple_prop_t *sprop;
	char *tchr;
	char *pchr;
	int tlen;
	int cnt = 0;

	if ((sprop = scf_simple_prop_get(h, SMF_MDNS_FMRI,
	    SMF_NSSMDNSCFG_PROPGRP, scfprop)) == NULL)
			return;

	while ((cnt < maxprops) &&
	    (tchr = scf_simple_prop_next_astring(sprop)) != NULL) {

		/* Remove beginning & trailing '.' chars */
		while (*tchr && (*tchr == '.'))
			tchr++;

		if (*tchr && ((tlen = strlen(tchr)) < MAXDNAME)) {
			pchr = &tchr[tlen-1];
			while ((pchr != tchr) && (*pchr == '.'))
				pchr--;
			*(++pchr) = '\0';
			storelist[cnt] = strdup(tchr);
			cnt++;
		}
	}
	scf_simple_prop_free(sprop);
}

static void
_nss_mdns_loadsmfcfg(mdns_backend_ptr_t be)
{
	scf_handle_t *h;

	h = scf_handle_create(SCF_VERSION);
	if (h == NULL)
		return;

	if (scf_handle_bind(h) == -1) {
		scf_handle_destroy(h);
		return;
	}

	load_mdns_domaincfg(h, &(be->dmnsrchlist[0]),
	    SMF_NSSMDNSCFG_SRCHPROP, NSSMDNS_MAXSRCHDMNS);

	load_mdns_domaincfg(h, &(be->validdmnlist[0]),
	    SMF_NSSMDNSCFG_DMNPROP, NSSMDNS_MAXVALIDDMNS);

	if (h != NULL)
		scf_handle_destroy(h);
}

static void
_nss_mdns_freesmfcfg(mdns_backend_ptr_t be)
{
	int idx;
	if (be == NULL)
		return;
	for (idx = 0; idx < NSSMDNS_MAXSRCHDMNS; idx++) {
		if (be->dmnsrchlist[idx] != NULL) {
			free(be->dmnsrchlist[idx]);
			be->dmnsrchlist[idx] = NULL;
		}
	}
	for (idx = 0; idx < NSSMDNS_MAXVALIDDMNS; idx++) {
		if (be->validdmnlist[idx] != NULL) {
			free(be->validdmnlist[idx]);
			be->validdmnlist[idx] = NULL;
		}
	}
}

/*
 * Performs lookup for IP address by hostname via mDNS and returns
 * results along with the TTL value from the mDNS resource records.
 * Called by nscd wth a ptr to packed bufer and packed buffer size.
 */
nss_status_t
_nss_mdns_gethost_withttl(void *buffer, size_t bufsize, int ipnode)
{
	nss_pheader_t *pbuf = (nss_pheader_t *)buffer;
	nss_XbyY_args_t arg;
	int dbop;
	int af;
	int len;
	int blen;
	char *dbname;
	nss_status_t sret;
	char *hname;
	struct mdns_querydata qdata;
	nssuint_t *pttl;
	mdns_backend_ptr_t be = NULL;

	(void) memset(&qdata, 0, sizeof (struct mdns_querydata));

	qdata.argp = &arg;

	/*
	 * Retrieve withttl buffer and size from the passed packed buffer.
	 * Results are returned along with ttl in this buffer.
	 */
	qdata.withttlbsize = pbuf->data_len - sizeof (nssuint_t);
	qdata.withttlbuffer = (char *)buffer + pbuf->data_off;

	sret = nss_packed_getkey(buffer, bufsize, &dbname, &dbop, &arg);
	if (sret != NSS_SUCCESS)
		return (NSS_ERROR);

	if (ipnode) {
		if (arg.key.ipnode.flags != 0)
			return (NSS_ERROR);
		hname = (char *)arg.key.ipnode.name;
		af = arg.key.ipnode.af_family;
	} else {
		af = AF_INET;
		hname = (char *)arg.key.name;
	}

	if ((be = (mdns_backend_ptr_t)calloc(1, sizeof (*be))) == NULL)
		return (NSS_ERROR);
	_nss_mdns_updatecfg(be);

	/* Zero out the withttl buffer prior to use */
	(void) memset(qdata.withttlbuffer, 0, qdata.withttlbsize);

#ifdef DEBUG
	syslog(LOG_DEBUG, "nss_mdns: querybyname withttl called" \
	    " af:%d hname:%s", af, hname);
#endif
	if (_nss_mdns_querybyname(be, hname, af, &qdata) == NSS_SUCCESS) {
		blen = strlen(qdata.buffer);
		len = ROUND_UP(blen, sizeof (nssuint_t));

		if (len + sizeof (nssuint_t) > pbuf->data_len) {
			_nss_mdns_freesmfcfg(be);
			free(be);
			return (NSS_ERROR);
		}

		pbuf->ext_off = pbuf->data_off + len;
		pbuf->ext_len = sizeof (nssuint_t);
		pbuf->data_len = blen;

		/* Return ttl in the packed buffer at ext_off */
		pttl = (nssuint_t *)((void *)((char *)pbuf + pbuf->ext_off));
		*pttl = qdata.ttl;

		_nss_mdns_freesmfcfg(be);
		free(be);
		return (NSS_SUCCESS);
	}
	_nss_mdns_freesmfcfg(be);
	free(be);
	return (NSS_ERROR);
}
