/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * lib/krb5/os/dnsglue.c
 *
 * Copyright 2004 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 */
#include "autoconf.h"
#ifdef KRB5_DNS_LOOKUP

#include "dnsglue.h"

/*
 * Only use res_ninit() if there's also a res_ndestroy(), to avoid
 * memory leaks (Linux & Solaris) and outright corruption (AIX 4.x,
 * 5.x).  While we're at it, make sure res_nsearch() is there too.
 *
 * In any case, it is probable that platforms having broken
 * res_ninit() will have thread safety hacks for res_init() and _res.
 */
#if HAVE_RES_NINIT && HAVE_RES_NDESTROY && HAVE_RES_NSEARCH
#define USE_RES_NINIT 1
#endif

/*
 * Opaque handle
 */
struct krb5int_dns_state {
    int nclass;
    int ntype;
    void *ansp;
    int anslen;
    int ansmax;
#if HAVE_NS_INITPARSE
    int cur_ans;
    ns_msg msg;
#else
    unsigned char *ptr;
    unsigned short nanswers;
#endif
};

#if !HAVE_NS_INITPARSE
static int initparse(struct krb5int_dns_state *);
#endif

/*
 * krb5int_dns_init()
 *
 * Initialize an opaque handle.  Do name lookup and initial parsing of
 * reply, skipping question section.  Prepare to iterate over answer
 * section.  Returns -1 on error, 0 on success.
 */
int
krb5int_dns_init(struct krb5int_dns_state **dsp,
		 char *host, int nclass, int ntype)
{
#if USE_RES_NINIT
    struct __res_state statbuf;
#endif
    struct krb5int_dns_state *ds;
    int len, ret;
    size_t nextincr, maxincr;
    unsigned char *p;

    *dsp = ds = malloc(sizeof(*ds));
    if (ds == NULL)
	return -1;

    ret = -1;
    ds->nclass = nclass;
    ds->ntype = ntype;
    ds->ansp = NULL;
    ds->anslen = 0;
    ds->ansmax = 0;
    nextincr = 2048;
    maxincr = INT_MAX;

#if HAVE_NS_INITPARSE
    ds->cur_ans = 0;
#endif

#if USE_RES_NINIT
    memset(&statbuf, 0, sizeof(statbuf));
    ret = res_ninit(&statbuf);
#else
    ret = res_init();
#endif
    if (ret < 0)
	return -1;

    do {
	p = (ds->ansp == NULL)
	    ? malloc(nextincr) : realloc(ds->ansp, nextincr);

	if (p == NULL && ds->ansp != NULL) {
	    ret = -1;
	    goto errout;
	}
	ds->ansp = p;
	ds->ansmax = nextincr;

#if USE_RES_NINIT
	len = res_nsearch(&statbuf, host, ds->nclass, ds->ntype,
			  ds->ansp, ds->ansmax);
#else
	len = res_search(host, ds->nclass, ds->ntype,
			 ds->ansp, ds->ansmax);
#endif
	if (len > maxincr) {
	    ret = -1;
	    goto errout;
	}
	while (nextincr < len)
	    nextincr *= 2;
	if (len < 0 || nextincr > maxincr) {
	    ret = -1;
	    goto errout;
	}
    } while (len > ds->ansmax);

    ds->anslen = len;
#if HAVE_NS_INITPARSE
    ret = ns_initparse(ds->ansp, ds->anslen, &ds->msg);
#else
    ret = initparse(ds);
#endif
    if (ret < 0)
	goto errout;

    ret = 0;

errout:
#if USE_RES_NINIT
    res_ndestroy(&statbuf);
#endif
    if (ret < 0) {
	if (ds->ansp != NULL) {
	    free(ds->ansp);
	    ds->ansp = NULL;
	}
    }

    return ret;
}

#if HAVE_NS_INITPARSE
/*
 * krb5int_dns_nextans - get next matching answer record
 *
 * Sets pp to NULL if no more records.  Returns -1 on error, 0 on
 * success.
 */
int
krb5int_dns_nextans(struct krb5int_dns_state *ds,
		    const unsigned char **pp, int *lenp)
{
    int len;
    ns_rr rr;

    *pp = NULL;
    *lenp = 0;
    while (ds->cur_ans < ns_msg_count(ds->msg, ns_s_an)) {
	len = ns_parserr(&ds->msg, ns_s_an, ds->cur_ans, &rr);
	if (len < 0)
	    return -1;
	ds->cur_ans++;
	if (ds->nclass == ns_rr_class(rr)
	    && ds->ntype == ns_rr_type(rr)) {
	    *pp = ns_rr_rdata(rr);
	    *lenp = ns_rr_rdlen(rr);
	    return 0;
	}
    }
    return 0;
}
#endif

/*
 * krb5int_dns_expand - wrapper for dn_expand()
 */
int krb5int_dns_expand(struct krb5int_dns_state *ds,
		       const unsigned char *p,
		       char *buf, int len)
{

#if HAVE_NS_NAME_UNCOMPRESS
    return ns_name_uncompress(ds->ansp,
			      (unsigned char *)ds->ansp + ds->anslen,
			      p, buf, (size_t)len);
#else
    return dn_expand(ds->ansp,
		     (unsigned char *)ds->ansp + ds->anslen,
		     p, buf, len);
#endif
}

/*
 * Free stuff.
 */
void
krb5int_dns_fini(struct krb5int_dns_state *ds)
{
    if (ds == NULL)
	return;
    if (ds->ansp != NULL)
	free(ds->ansp);
    free(ds);
}

/*
 * Compat routines for BIND 4
 */
#if !HAVE_NS_INITPARSE

/*
 * initparse
 *
 * Skip header and question section of reply.  Set a pointer to the
 * beginning of the answer section, and prepare to iterate over
 * answer records.
 */
static int
initparse(struct krb5int_dns_state *ds)
{
    HEADER *hdr;
    unsigned char *p;
    unsigned short nqueries, nanswers;
    int len;
#if !HAVE_DN_SKIPNAME
    char host[MAXDNAME];
#endif

    if (ds->anslen < sizeof(HEADER))
	return -1;

    hdr = (HEADER *)ds->ansp;
    p = ds->ansp;
    nqueries = ntohs((unsigned short)hdr->qdcount);
    nanswers = ntohs((unsigned short)hdr->ancount);
    p += sizeof(HEADER);

    /*
     * Skip query records.
     */
    while (nqueries--) {
#if HAVE_DN_SKIPNAME
	len = dn_skipname(p, (unsigned char *)ds->ansp + ds->anslen);
#else
	len = dn_expand(ds->ansp, (unsigned char *)ds->ansp + ds->anslen,
			p, host, sizeof(host));
#endif
	if (len < 0 || !INCR_OK(ds->ansp, ds->anslen, p, len + 4))
	    return -1;
	p += len + 4;
    }
    ds->ptr = p;
    ds->nanswers = nanswers;
    return 0;
}

/*
 * krb5int_dns_nextans() - get next answer record
 *
 * Sets pp to NULL if no more records.
 */
int
krb5int_dns_nextans(struct krb5int_dns_state *ds,
		    const unsigned char **pp, int *lenp)
{
    int len;
    unsigned char *p;
    unsigned short ntype, nclass, rdlen;
#if !HAVE_DN_SKIPNAME
    char host[MAXDNAME];
#endif

    *pp = NULL;
    *lenp = 0;
    p = ds->ptr;

    while (ds->nanswers--) {
#if HAVE_DN_SKIPNAME
	len = dn_skipname(p, (unsigned char *)ds->ansp + ds->anslen);
#else
	len = dn_expand(ds->ansp, (unsigned char *)ds->ansp + ds->anslen,
			p, host, sizeof(host));
#endif
	if (len < 0 || !INCR_OK(ds->ansp, ds->anslen, p, len))
	    return -1;
	p += len;
	SAFE_GETUINT16(ds->ansp, ds->anslen, p, 2, ntype, out);
	/* Also skip 4 bytes of TTL */
	SAFE_GETUINT16(ds->ansp, ds->anslen, p, 6, nclass, out);
	SAFE_GETUINT16(ds->ansp, ds->anslen, p, 2, rdlen, out);

	if (!INCR_OK(ds->ansp, ds->anslen, p, rdlen))
	    return -1;
/* Solaris Kerberos - resync */
#if 0
	if (rdlen > INT_MAX)
	    return -1;
#endif
	if (nclass == ds->nclass && ntype == ds->ntype) {
	    *pp = p;
	    *lenp = rdlen;
	    ds->ptr = p + rdlen;
	    return 0;
	}
	p += rdlen;
    }
    return 0;
out:
    return -1;
}

#endif

#endif /* KRB5_DNS_LOOKUP */
