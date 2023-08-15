/*
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright (c) 1994,2003,2005 by the Massachusetts Institute of Technology.
 * Copyright (c) 1994 CyberSAFE Corporation
 * Copyright (c) 1993 Open Computing Security Group
 * Copyright (c) 1990,1991 by the Massachusetts Institute of Technology.
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
 * Neither M.I.T., the Open Computing Security Group, nor
 * CyberSAFE Corporation make any representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * krb5_get_cred_from_kdc() and related functions:
 *
 * Get credentials from some KDC somewhere, possibly accumulating TGTs
 * along the way.
 */

#include "k5-int.h"
#include <stdio.h>
#include "int-proto.h"
#include <locale.h>

struct tr_state;

/*
 * Ring buffer abstraction for TGTs returned from a ccache; avoids
 * lots of excess copying.
 */

#define NCC_TGTS 2
struct cc_tgts {
    krb5_creds cred[NCC_TGTS];
    int dirty[NCC_TGTS];
    unsigned int cur, nxt;
};

/* NOTE: This only checks if NXT_TGT is CUR_CC_TGT. */
#define NXT_TGT_IS_CACHED(ts)			\
	((ts)->nxt_tgt == (ts)->cur_cc_tgt)

#define MARK_CUR_CC_TGT_CLEAN(ts)			\
do {							\
	(ts)->cc_tgts.dirty[(ts)->cc_tgts.cur] = 0;	\
} while (0)

static void init_cc_tgts(struct tr_state *);
static void shift_cc_tgts(struct tr_state *);
static void clean_cc_tgts(struct tr_state *);

/*
 * State struct for do_traversal() and helpers.
 *
 * CUR_TGT and NXT_TGT can each point either into CC_TGTS or into
 * KDC_TGTS.
 *
 * CUR_TGT is the "working" TGT, which will be used to obtain new
 * TGTs.  NXT_TGT will be CUR_TGT for the next iteration of the loop.
 *
 * Part of the baroqueness of this setup is to deal with annoying
 * differences between krb5_cc_retrieve_cred() and
 * krb5_get_cred_via_tkt(); krb5_cc_retrieve_cred() fills in a
 * caller-allocated krb5_creds, while krb5_get_cred_via_tkt()
 * allocates a krb5_creds for return.
 */
struct tr_state {
    krb5_context ctx;
    krb5_ccache ccache;
    krb5_principal *kdc_list;
    unsigned int nkdcs;
    krb5_principal *cur_kdc;
    krb5_principal *nxt_kdc;
    krb5_principal *lst_kdc;
    krb5_creds *cur_tgt;
    krb5_creds *nxt_tgt;
    krb5_creds **kdc_tgts;
    struct cc_tgts cc_tgts;
    krb5_creds *cur_cc_tgt;
    krb5_creds *nxt_cc_tgt;
    unsigned int ntgts;
};

/*
 * Debug support
 */
#ifdef DEBUG_GC_FRM_KDC

#define TR_DBG(ts, prog) tr_dbg(ts, prog)
#define TR_DBG_RET(ts, prog, ret) tr_dbg_ret(ts, prog, ret)
#define TR_DBG_RTREE(ts, prog, princ) tr_dbg_rtree(ts, prog, princ)

static void tr_dbg(struct tr_state *, const char *);
static void tr_dbg_ret(struct tr_state *, const char *, krb5_error_code);
static void tr_dbg_rtree(struct tr_state *, const char *, krb5_principal);

#else

#define TR_DBG(ts, prog)
#define TR_DBG_RET(ts, prog, ret)
#define TR_DBG_RTREE(ts, prog, princ)

#endif /* !DEBUG_GC_FRM_KDC */

#ifdef DEBUG_REFERRALS

#define DPRINTF(x) printf x
#define DFPRINTF(x) fprintf x
#define DUMP_PRINC(x, y) krb5int_dbgref_dump_principal((x), (y))

#else

#define DPRINTF(x)
#define DFPRINTF(x)
#define DUMP_PRINC(x, y)

#endif

/* Convert ticket flags to necessary KDC options */
#define FLAGS2OPTS(flags) (flags & KDC_TKT_COMMON_MASK)

/*
 * Certain krb5_cc_retrieve_cred() errors are soft errors when looking
 * for a cross-realm TGT.
 */
#define HARD_CC_ERR(r) ((r) && (r) != KRB5_CC_NOTFOUND &&	\
	(r) != KRB5_CC_NOT_KTYPE)


/*
 * Flags for ccache lookups of cross-realm TGTs.
 *
 * A cross-realm TGT may be issued by some other intermediate realm's
 * KDC, so we use KRB5_TC_MATCH_SRV_NAMEONLY.
 */
/*
 * Solaris Kerberos:
 * Include KRB5_TC_MATCH_TIMES so as to ensure that the retrieved ticket
 * isn't stale.
 */
#define RETR_FLAGS (KRB5_TC_MATCH_SRV_NAMEONLY | \
					KRB5_TC_SUPPORTED_KTYPES |   \
					KRB5_TC_MATCH_TIMES)

/*
 * Prototypes of helper functions
 */
static krb5_error_code tgt_mcred(krb5_context, krb5_principal,
    krb5_principal, krb5_principal, krb5_creds *);
static krb5_error_code retr_local_tgt(struct tr_state *, krb5_principal);
static krb5_error_code try_ccache(struct tr_state *, krb5_creds *);
static krb5_error_code find_nxt_kdc(struct tr_state *);
static krb5_error_code try_kdc(struct tr_state *, krb5_creds *);
static krb5_error_code kdc_mcred(struct tr_state *, krb5_principal,
    krb5_creds *mcreds);
static krb5_error_code next_closest_tgt(struct tr_state *, krb5_principal);
static krb5_error_code init_rtree(struct tr_state *,
    krb5_principal, krb5_principal);
static krb5_error_code do_traversal(krb5_context ctx, krb5_ccache,
    krb5_principal client, krb5_principal server,
    krb5_creds *out_cc_tgt, krb5_creds **out_tgt,
    krb5_creds ***out_kdc_tgts);
static krb5_error_code krb5_get_cred_from_kdc_opt(krb5_context, krb5_ccache,
    krb5_creds *, krb5_creds **, krb5_creds ***, int);

/*
 * init_cc_tgts()
 *
 * Initialize indices for cached-TGT ring buffer.  Caller must zero
 * CC_TGTS, CC_TGT_DIRTY arrays prior to calling.
 */
static void
init_cc_tgts(struct tr_state *ts)
{

    ts->cc_tgts.cur = 0;
    ts->cc_tgts.nxt = 1;
    ts->cur_cc_tgt = &ts->cc_tgts.cred[0];
    ts->nxt_cc_tgt = &ts->cc_tgts.cred[1];
}

/*
 * shift_cc_tgts()
 *
 * Given a fresh assignment to NXT_CC_TGT, mark NXT_CC_TGT as dirty,
 * and shift indices so old NXT_CC_TGT becomes new CUR_CC_TGT.  Clean
 * the new NXT_CC_TGT.
 */
static void
shift_cc_tgts(struct tr_state *ts)
{
    unsigned int i;
    struct cc_tgts *rb;

    rb = &ts->cc_tgts;
    i = rb->cur = rb->nxt;
    rb->dirty[i] = 1;
    ts->cur_cc_tgt = ts->nxt_cc_tgt;

    i = (i + 1) % NCC_TGTS;

    rb->nxt = i;
    ts->nxt_cc_tgt = &rb->cred[i];
    if (rb->dirty[i]) {
	krb5_free_cred_contents(ts->ctx, &rb->cred[i]);
	rb->dirty[i] = 0;
    }
}

/*
 * clean_cc_tgts()
 *
 * Free CC_TGTS which were dirty, then mark them clean.
 */
static void
clean_cc_tgts(struct tr_state *ts)
{
    unsigned int i;
    struct cc_tgts *rb;

    rb = &ts->cc_tgts;
    for (i = 0; i < NCC_TGTS; i++) {
	if (rb->dirty[i]) {
	    krb5_free_cred_contents(ts->ctx, &rb->cred[i]);
	    rb->dirty[i] = 0;
	}
    }
}

/*
 * Debug support
 */
#ifdef DEBUG_GC_FRM_KDC
static void
tr_dbg(struct tr_state *ts, const char *prog)
{
    krb5_error_code retval;
    char *cur_tgt_str, *cur_kdc_str, *nxt_kdc_str;

    cur_tgt_str = cur_kdc_str = nxt_kdc_str = NULL;
    retval = krb5_unparse_name(ts->ctx, ts->cur_tgt->server, &cur_tgt_str);
    if (retval) goto cleanup;
    retval = krb5_unparse_name(ts->ctx, *ts->cur_kdc, &cur_kdc_str);
    if (retval) goto cleanup;
    retval = krb5_unparse_name(ts->ctx, *ts->nxt_kdc, &nxt_kdc_str);
    if (retval) goto cleanup;
    fprintf(stderr, "%s: cur_tgt %s\n", prog, cur_tgt_str);
    fprintf(stderr, "%s: cur_kdc %s\n", prog, cur_kdc_str);
    fprintf(stderr, "%s: nxt_kdc %s\n", prog, nxt_kdc_str);
cleanup:
    if (cur_tgt_str)
	krb5_free_unparsed_name(ts->ctx, cur_tgt_str);
    if (cur_kdc_str)
	krb5_free_unparsed_name(ts->ctx, cur_kdc_str);
    if (nxt_kdc_str)
	krb5_free_unparsed_name(ts->ctx, nxt_kdc_str);
}

static void
tr_dbg_ret(struct tr_state *ts, const char *prog, krb5_error_code ret)
{
    fprintf(stderr, "%s: return %d (%s)\n", prog, (int)ret,
	    error_message(ret));
}

static void
tr_dbg_rtree(struct tr_state *ts, const char *prog, krb5_principal princ)
{
    char *str;

    if (krb5_unparse_name(ts->ctx, princ, &str))
	return;
    fprintf(stderr, "%s: %s\n", prog, str);
    krb5_free_unparsed_name(ts->ctx, str);
}
#endif /* DEBUG_GC_FRM_KDC */

/*
 * tgt_mcred()
 *
 * Return MCREDS for use as a match criterion.
 *
 * Resulting credential has CLIENT as the client principal, and
 * krbtgt/realm_of(DST)@realm_of(SRC) as the server principal.  Zeroes
 * MCREDS first, does not allocate MCREDS, and cleans MCREDS on
 * failure.  The peculiar ordering of DST and SRC args is for
 * consistency with krb5_tgtname().
 */
static krb5_error_code
tgt_mcred(krb5_context ctx, krb5_principal client,
	  krb5_principal dst, krb5_principal src,
	  krb5_creds *mcreds)
{
    krb5_error_code retval;

    retval = 0;
    memset(mcreds, 0, sizeof(*mcreds));

    retval = krb5_copy_principal(ctx, client, &mcreds->client);
    if (retval)
	goto cleanup;

    retval = krb5_tgtname(ctx, krb5_princ_realm(ctx, dst),
			  krb5_princ_realm(ctx, src), &mcreds->server);
    if (retval)
	goto cleanup;

cleanup:
    if (retval)
	krb5_free_cred_contents(ctx, mcreds);

    return retval;
}

/*
 * init_rtree()
 *
 * Populate KDC_LIST with the output of krb5_walk_realm_tree().
 */
static krb5_error_code
init_rtree(struct tr_state *ts,
	   krb5_principal client, krb5_principal server)
{
    krb5_error_code retval;

    ts->kdc_list = NULL;
    retval = krb5_walk_realm_tree(ts->ctx, krb5_princ_realm(ts->ctx, client),
				  krb5_princ_realm(ts->ctx, server),
				  &ts->kdc_list, KRB5_REALM_BRANCH_CHAR);
    if (retval)
	return retval;

    for (ts->nkdcs = 0; ts->kdc_list[ts->nkdcs]; ts->nkdcs++) {
	assert(krb5_princ_size(ts->ctx, ts->kdc_list[ts->nkdcs]) == 2);
	TR_DBG_RTREE(ts, "init_rtree", ts->kdc_list[ts->nkdcs]);
    }
    assert(ts->nkdcs > 1);
    ts->lst_kdc = ts->kdc_list + ts->nkdcs - 1;

    ts->kdc_tgts = calloc(ts->nkdcs + 1, sizeof(krb5_creds));
    if (ts->kdc_tgts == NULL)
	return ENOMEM;

    return 0;
}

/*
 * retr_local_tgt()
 *
 * Prime CUR_TGT with the cached TGT of the client's local realm.
 */
static krb5_error_code
retr_local_tgt(struct tr_state *ts, krb5_principal client)
{
    krb5_error_code retval;
    krb5_creds tgtq;

    memset(&tgtq, 0, sizeof(tgtq));
    retval = tgt_mcred(ts->ctx, client, client, client, &tgtq);
    if (retval)
	return retval;

    /* Match realm, unlike other ccache retrievals here. */
    retval = krb5_cc_retrieve_cred(ts->ctx, ts->ccache,
				   KRB5_TC_SUPPORTED_KTYPES,
				   &tgtq, ts->nxt_cc_tgt);
    krb5_free_cred_contents(ts->ctx, &tgtq);
    if (!retval) {
	shift_cc_tgts(ts);
	ts->nxt_tgt = ts->cur_tgt = ts->cur_cc_tgt;
    }
    return retval;
}

/*
 * try_ccache()
 *
 * Attempt to retrieve desired NXT_TGT from ccache.  Point NXT_TGT to
 * it if successful.
 */
static krb5_error_code
try_ccache(struct tr_state *ts, krb5_creds *tgtq)
{
    krb5_error_code retval;
    krb5_timestamp saved_endtime;

    TR_DBG(ts, "try_ccache");
    /*
     * Solaris Kerberos:
     * Ensure the retrieved cred isn't stale.
     * Set endtime to now so krb5_cc_retrieve_cred won't return an expired ticket.
     */
    saved_endtime = tgtq->times.endtime;
    if ((retval = krb5_timeofday(ts->ctx, &(tgtq->times.endtime))) != 0) {
    	tgtq->times.endtime = saved_endtime;
    	return retval;
    }
    retval = krb5_cc_retrieve_cred(ts->ctx, ts->ccache, RETR_FLAGS,
				   tgtq, ts->nxt_cc_tgt);
    if (!retval) {
	shift_cc_tgts(ts);
	ts->nxt_tgt = ts->cur_cc_tgt;
    }
    /*
     * Solaris Kerberos:
     * Ensure that tgtq->times.endtime is reset back to its original value so
     * that if tgtq is used to request a ticket from the KDC it doesn't request
     * a ticket with an endtime set to "now".
     */
    tgtq->times.endtime = saved_endtime;
    TR_DBG_RET(ts, "try_ccache", retval);
    return retval;
}

/*
 * find_nxt_kdc()
 *
 * A NXT_TGT gotten from an intermediate KDC might actually be a
 * referral.  Search KDC_LIST forward starting from CUR_KDC, looking
 * for the KDC with the same remote realm as NXT_TGT.  If we don't
 * find it, the intermediate KDC is leading us off the transit path.
 *
 * Match on CUR_KDC's remote realm, not local realm, because, among
 * other reasons, we can get a referral to the final realm; e.g.,
 * given
 *
 *     KDC_LIST == { krbtgt/R1@R1, krbtgt/R2@R1, krbtgt/R3@R2,
 *                   krbtgt/R4@R3, NULL }
 *     CUR_TGT->SERVER == krbtgt/R2@R1
 *     NXT_TGT->SERVER == krbtgt/R4@R2
 *
 * i.e., we got a ticket issued by R2 with remote realm R4, we want to
 * find krbtgt/R4@R3, not krbtgt/R3@R2, even though we have no TGT
 * with R3 as its local realm.
 *
 * Set up for next iteration of do_traversal() loop by pointing
 * NXT_KDC to one entry forward of the match.
 */
static krb5_error_code
find_nxt_kdc(struct tr_state *ts)
{
    krb5_data *r1, *r2;
    krb5_principal *kdcptr;

    TR_DBG(ts, "find_nxt_kdc");
  /*
   * Solaris Kerberos:
   * The following assertion is not be true for the case when
   * ts->nxt points to a cached ticket and not to a freshly
   * fetched TGT in ts->kdc_tgts. See changes in try_kdc()
   */
  /*  assert(ts->nxt_tgt == ts->kdc_tgts[ts->ntgts-1]); */
    if (krb5_princ_size(ts->ctx, ts->nxt_tgt->server) != 2) {
	/* Solaris Kerberos */
	char *s_name = NULL;
	int err = krb5_unparse_name(ts->ctx, ts->nxt_tgt->server, &s_name);
	if (!err) {
	    krb5_set_error_message(ts->ctx, KRB5_KDCREP_MODIFIED,
				dgettext(TEXT_DOMAIN,
					"KDC reply did not match expectations: server '%s' principal size should be 2"),
				s_name);
	    krb5_free_unparsed_name(ts->ctx, s_name);
	} else
	    krb5_set_error_message(ts->ctx, KRB5_KDCREP_MODIFIED,
				dgettext(TEXT_DOMAIN,
					"KDC reply did not match expectations: server principal size should be 2"));
	return KRB5_KDCREP_MODIFIED;
    }
    r1 = krb5_princ_component(ts->ctx, ts->nxt_tgt->server, 1);

    for (kdcptr = ts->cur_kdc + 1; *kdcptr != NULL; kdcptr++) {

	r2 = krb5_princ_component(ts->ctx, *kdcptr, 1);

	if (r1 != NULL && r2 != NULL &&
	    r1->length == r2->length &&
	    !memcmp(r1->data, r2->data, r1->length)) {
	    break;
	}
    }
    if (*kdcptr == NULL) {
	/*
	 * Not found; we probably got an unexpected realm referral.
	 * Don't touch NXT_KDC, thus allowing next_closest_tgt() to
	 * continue looping backwards.
	 */
	/*
	 * Solaris Kerberos:
	 * Only free the allocated creds if they are in kdc_tgts. If they
	 * are in cc_tgts no freeing is necessary.
	 */
	if (ts->ntgts > 0 && ts->nxt_tgt == ts->kdc_tgts[ts->ntgts-1]) {
	    /* Punt NXT_TGT from KDC_TGTS if bogus. */
	    krb5_free_creds(ts->ctx, ts->kdc_tgts[--ts->ntgts]);
	    ts->kdc_tgts[ts->ntgts] = NULL;
	}
	TR_DBG_RET(ts, "find_nxt_kdc", KRB5_KDCREP_MODIFIED);
	krb5_set_error_message(ts->ctx, KRB5_KDCREP_MODIFIED,
			    dgettext(TEXT_DOMAIN,
				    "KDC reply did not match expectation: KDC not found.  Probably got an unexpected realm referral"));
	return KRB5_KDCREP_MODIFIED;
    }
    ts->nxt_kdc = kdcptr;
    TR_DBG_RET(ts, "find_nxt_kdc", 0);
    return 0;
}

/*
 * try_kdc()
 *
 * Using CUR_TGT, attempt to get desired NXT_TGT.  Update NXT_KDC if
 * successful.
 */
static krb5_error_code
try_kdc(struct tr_state *ts, krb5_creds *tgtq)
{
    krb5_error_code retval;
    krb5_creds ltgtq;
    krb5_creds *tmp_out_cred;

    TR_DBG(ts, "try_kdc");
    /* This check should probably be in gc_via_tkt. */
    if (!krb5_c_valid_enctype(ts->cur_tgt->keyblock.enctype))
	return KRB5_PROG_ETYPE_NOSUPP;

    ltgtq = *tgtq;
    ltgtq.is_skey = FALSE;
    ltgtq.ticket_flags = ts->cur_tgt->ticket_flags;
    /*
     * Solaris Kerberos:
     * Store credential in a temporary ticket as we may not
     * want to add it to ts->kdc_tgts if it is already in
     * the cache.
     */
    retval = krb5_get_cred_via_tkt(ts->ctx, ts->cur_tgt,
				   FLAGS2OPTS(ltgtq.ticket_flags),
				   ts->cur_tgt->addresses,
				   &ltgtq, &tmp_out_cred);
    if (retval) {
	ts->ntgts--;
	ts->nxt_tgt = ts->cur_tgt;
	TR_DBG_RET(ts, "try_kdc", retval);
	return retval;
    }

    /*
     * Solaris Kerberos:
     * See if the returned creds are different to the requested creds.
     * This can happen when the server returns a TGT "closer" to the
     * desired realm.
     */
    if (!(krb5_principal_compare(ts->ctx, tgtq->server, tmp_out_cred->server))) {
	    /* Not equal, ticket may already be in the cache */
	    retval = try_ccache(ts, tmp_out_cred);
	    if (!retval) {
	        krb5_free_creds(ts->ctx, tmp_out_cred);
	        retval = find_nxt_kdc(ts);
	        return retval;
	    }
	}

    ts->kdc_tgts[ts->ntgts++] = tmp_out_cred;
    ts->nxt_tgt = ts->kdc_tgts[ts->ntgts-1];
    retval = find_nxt_kdc(ts);
    TR_DBG_RET(ts, "try_kdc", retval);
    return retval;
}

/*
 * kdc_mcred()
 *
 * Return MCREDS for use as a match criterion.
 *
 * Resulting credential has CLIENT as the client principal, and
 * krbtgt/remote_realm(NXT_KDC)@local_realm(CUR_KDC) as the server
 * principal.  Zeroes MCREDS first, does not allocate MCREDS, and
 * cleans MCREDS on failure.
 */
static krb5_error_code
kdc_mcred(struct tr_state *ts, krb5_principal client, krb5_creds *mcreds)
{
    krb5_error_code retval;
    krb5_data *rdst, *rsrc;

    retval = 0;
    memset(mcreds, 0, sizeof(*mcreds));

    rdst = krb5_princ_component(ts->ctx, *ts->nxt_kdc, 1);
    rsrc = krb5_princ_component(ts->ctx, *ts->cur_kdc, 1);
    retval = krb5_copy_principal(ts->ctx, client, &mcreds->client);
    if (retval)
	goto cleanup;

    retval = krb5_tgtname(ts->ctx, rdst, rsrc, &mcreds->server);
    if (retval)
	goto cleanup;

cleanup:
    if (retval)
	krb5_free_cred_contents(ts->ctx, mcreds);

    return retval;
}

/*
 * next_closest_tgt()
 *
 * Using CUR_TGT, attempt to get the cross-realm TGT having its remote
 * realm closest to the target principal's.  Update NXT_TGT, NXT_KDC
 * accordingly.
 */
static krb5_error_code
next_closest_tgt(struct tr_state *ts, krb5_principal client)
{
    krb5_error_code retval;
    krb5_creds tgtq;

    retval = 0;
    memset(&tgtq, 0, sizeof(tgtq));

    for (ts->nxt_kdc = ts->lst_kdc;
	 ts->nxt_kdc > ts->cur_kdc;
	 ts->nxt_kdc--) {

	krb5_free_cred_contents(ts->ctx, &tgtq);
	retval = kdc_mcred(ts, client, &tgtq);
	if (retval)
	    goto cleanup;
	/* Don't waste time retrying ccache for direct path. */
	if (ts->cur_kdc != ts->kdc_list || ts->nxt_kdc != ts->lst_kdc) {
	    retval = try_ccache(ts, &tgtq);
	    if (!retval)
		break;
	    if (HARD_CC_ERR(retval))
		goto cleanup;
	}
	/* Not in the ccache, so talk to a KDC. */
	retval = try_kdc(ts, &tgtq);
	if (!retval) {
	    break;
	}
	/*
	 * Because try_kdc() validates referral TGTs, it can return an
	 * error indicating a bogus referral.  The loop continues when
	 * it gets a bogus referral, which is arguably the right
	 * thing.  (Previous implementation unconditionally failed.)
	 */
    }
    /*
     * If we have a non-zero retval, we either have a hard error or we
     * failed to find a closer TGT.
     */
cleanup:
    krb5_free_cred_contents(ts->ctx, &tgtq);
    return retval;
}

/*
 * do_traversal()
 *
 * Find final TGT needed to get CLIENT a ticket for SERVER.  Point
 * OUT_TGT at the desired TGT, which may be an existing cached TGT
 * (copied into OUT_CC_TGT) or one of the newly obtained TGTs
 * (collected in OUT_KDC_TGTS).
 *
 * Get comfortable; this is somewhat complicated.
 *
 * Nomenclature: Cross-realm TGS principal names have the form:
 *
 *     krbtgt/REMOTE@LOCAL
 *
 * krb5_walk_realm_tree() returns a list like:
 *
 *     krbtgt/R1@R1, krbtgt/R2@R1, krbtgt/R3@R2, ...
 *
 * These are prinicpal names, not realm names.  We only really use the
 * remote parts of the TGT principal names.
 *
 * The do_traversal loop calls next_closest_tgt() to find the next
 * closest TGT to the destination realm.  next_closest_tgt() updates
 * NXT_KDC for the following iteration of the do_traversal() loop.
 *
 * At the beginning of any given iteration of the do_traversal() loop,
 * CUR_KDC's remote realm is the remote realm of CUR_TGT->SERVER.  The
 * local realms of CUR_KDC and CUR_TGT->SERVER may not match due to
 * short-circuit paths provided by intermediate KDCs, e.g., CUR_KDC
 * might be krbtgt/D@C, while CUR_TGT->SERVER is krbtgt/D@B.
 *
 * For example, given KDC_LIST of
 *
 * krbtgt/R1@R1, krbtgt/R2@R1, krbtgt/R3@R2, krbtgt/R4@R3,
 * krbtgt/R5@R4
 *
 * The next_closest_tgt() loop moves NXT_KDC to the left starting from
 * R5, stopping before it reaches CUR_KDC.  When next_closest_tgt()
 * returns, the do_traversal() loop updates CUR_KDC to be NXT_KDC, and
 * calls next_closest_tgt() again.
 *
 * next_closest_tgt() at start of its loop:
 *
 *      CUR                 NXT
 *       |                   |
 *       V                   V
 *     +----+----+----+----+----+
 *     | R1 | R2 | R3 | R4 | R5 |
 *     +----+----+----+----+----+
 *
 * next_closest_tgt() returns after finding a ticket for krbtgt/R3@R1:
 *
 *      CUR       NXT
 *       |         |
 *       V         V
 *     +----+----+----+----+----+
 *     | R1 | R2 | R3 | R4 | R5 |
 *     +----+----+----+----+----+
 *
 * do_traversal() updates CUR_KDC:
 *
 *                NXT
 *                CUR
 *                 |
 *                 V
 *     +----+----+----+----+----+
 *     | R1 | R2 | R3 | R4 | R5 |
 *     +----+----+----+----+----+
 *
 * next_closest_tgt() at start of its loop:
 *
 *                CUR       NXT
 *                 |         |
 *                 V         V
 *     +----+----+----+----+----+
 *     | R1 | R2 | R3 | R4 | R5 |
 *     +----+----+----+----+----+
 *
 * etc.
 *
 * The algorithm executes in n*(n-1)/2 (the sum of integers from 1 to
 * n-1) attempts in the worst case, i.e., each KDC only has a
 * cross-realm ticket for the immediately following KDC in the transit
 * path.  Typically, short-circuit paths will cause execution occur
 * faster than this worst-case scenario.
 *
 * When next_closest_tgt() updates NXT_KDC, it may not perform a
 * simple increment from CUR_KDC, in part because some KDC may
 * short-circuit pieces of the transit path.
 */
static krb5_error_code
do_traversal(krb5_context ctx,
	     krb5_ccache ccache,
	     krb5_principal client,
	     krb5_principal server,
	     krb5_creds *out_cc_tgt,
	     krb5_creds **out_tgt,
	     krb5_creds ***out_kdc_tgts)
{
    krb5_error_code retval;
    struct tr_state state, *ts;

    *out_tgt = NULL;
    *out_kdc_tgts = NULL;
    ts = &state;
    memset(ts, 0, sizeof(*ts));
    ts->ctx = ctx;
    ts->ccache = ccache;
    init_cc_tgts(ts);

    retval = init_rtree(ts, client, server);
    if (retval)
	goto cleanup;

    retval = retr_local_tgt(ts, client);
    if (retval)
	goto cleanup;

    for (ts->cur_kdc = ts->kdc_list, ts->nxt_kdc = NULL;
	 ts->cur_kdc != NULL && ts->cur_kdc < ts->lst_kdc;
	 ts->cur_kdc = ts->nxt_kdc, ts->cur_tgt = ts->nxt_tgt) {

	retval = next_closest_tgt(ts, client);
	if (retval)
	    goto cleanup;
	assert(ts->cur_kdc != ts->nxt_kdc);
    }

    if (NXT_TGT_IS_CACHED(ts)) {
	*out_cc_tgt = *ts->cur_cc_tgt;
	*out_tgt = out_cc_tgt;
	MARK_CUR_CC_TGT_CLEAN(ts);
    } else {
	/* CUR_TGT is somewhere in KDC_TGTS; no need to copy. */
	*out_tgt = ts->nxt_tgt;
    }

cleanup:
    clean_cc_tgts(ts);
    if (ts->kdc_list != NULL)
	krb5_free_realm_tree(ctx, ts->kdc_list);
    if (ts->ntgts == 0) {
	*out_kdc_tgts = NULL;
	if (ts->kdc_tgts != NULL)
	    free(ts->kdc_tgts);
    } else
	*out_kdc_tgts = ts->kdc_tgts;
    return retval;
}

/*
 * krb5_get_cred_from_kdc_opt()
 * krb5_get_cred_from_kdc()
 * krb5_get_cred_from_kdc_validate()
 * krb5_get_cred_from_kdc_renew()
 *
 * Retrieve credentials for client IN_CRED->CLIENT, server
 * IN_CRED->SERVER, ticket flags IN_CRED->TICKET_FLAGS, possibly
 * second_ticket if needed.
 *
 * Request credentials from the KDC for the server's realm.  Point
 * TGTS to an allocated array of pointers to krb5_creds, containing
 * any intermediate credentials obtained in the process of contacting
 * the server's KDC; if no intermediate credentials were obtained,
 * TGTS is a null pointer.  Return intermediate credentials if
 * intermediate KDCs provided credentials, even if no useful end
 * ticket results.
 *
 * Caller must free TGTS, regardless of whether this function returns
 * success.
 *
 * This function does NOT cache the intermediate TGTs.
 *
 * Do not call this routine if desired credentials are already cached.
 *
 * On success, OUT_CRED contains the desired credentials; the caller
 * must free them.
 *
 * Beware memory management issues if you have modifications in mind.
 * With the addition of referral support, it is now the case that *tgts,
 * referral_tgts, tgtptr, referral_tgts, and *out_creds all may point to
 * the same credential at different times.
 *
 * Returns errors, system errors.
 */

static krb5_error_code
krb5_get_cred_from_kdc_opt(krb5_context context, krb5_ccache ccache,
			   krb5_creds *in_cred, krb5_creds **out_cred,
			   krb5_creds ***tgts, int kdcopt)
{
    krb5_error_code retval, subretval;
    krb5_principal client, server, supplied_server, out_supplied_server;
    krb5_creds tgtq, cc_tgt, *tgtptr, *referral_tgts[KRB5_REFERRAL_MAXHOPS];
    krb5_boolean old_use_conf_ktypes;
    char **hrealms;
    int referral_count, i;

    /*
     * Set up client and server pointers.  Make a fresh and modifyable
     * copy of the in_cred server and save the supplied version.
     */
    client = in_cred->client;
    if ((retval=krb5_copy_principal(context, in_cred->server, &server)))
        return retval;
    /* We need a second copy for the output creds. */
    if ((retval = krb5_copy_principal(context, server,
				      &out_supplied_server)) != 0 ) {
	krb5_free_principal(context, server);
	return retval;
    }
    supplied_server = in_cred->server;
    in_cred->server=server;

    DUMP_PRINC("gc_from_kdc initial client", client);
    DUMP_PRINC("gc_from_kdc initial server", server);
    memset(&cc_tgt, 0, sizeof(cc_tgt));
    memset(&tgtq, 0, sizeof(tgtq));
    memset(&referral_tgts, 0, sizeof(referral_tgts));

    tgtptr = NULL;
    *tgts = NULL;
    *out_cred=NULL;
    old_use_conf_ktypes = context->use_conf_ktypes;

    /* Copy client realm to server if no hint. */
    if (krb5_is_referral_realm(&server->realm)) {
        /* Use the client realm. */
        DPRINTF(("gc_from_kdc: no server realm supplied, "
		 "using client realm.\n"));
	krb5_free_data_contents(context, &server->realm);
	if (!( server->realm.data = (char *)malloc(client->realm.length+1)))
	    return ENOMEM;
	memcpy(server->realm.data, client->realm.data, client->realm.length);
	server->realm.length = client->realm.length;
	server->realm.data[server->realm.length] = 0;
    }
    /*
     * Retreive initial TGT to match the specified server, either for the
     * local realm in the default (referral) case or for the remote
     * realm if we're starting someplace non-local.
     */
    retval = tgt_mcred(context, client, server, client, &tgtq);
    if (retval)
	goto cleanup;

    /* Fast path: Is it in the ccache? */
    context->use_conf_ktypes = 1;

    /*
     * Solaris Kerberos:
     * Ensure the retrieved cred isn't stale.
     * Set endtime to now so krb5_cc_retrieve_cred won't return an expired ticket.
     */
    if ((retval = krb5_timeofday(context, &(tgtq.times.endtime))) != 0) {
    	goto cleanup;
    }
    retval = krb5_cc_retrieve_cred(context, ccache, RETR_FLAGS,
				   &tgtq, &cc_tgt);
    if (!retval) {
	tgtptr = &cc_tgt;
    } else if (!HARD_CC_ERR(retval)) {
        DPRINTF(("gc_from_kdc: starting do_traversal to find "
		 "initial TGT for referral\n"));
	retval = do_traversal(context, ccache, client, server,
			      &cc_tgt, &tgtptr, tgts);
    }
    if (retval) {
        DPRINTF(("gc_from_kdc: failed to find initial TGT for referral\n"));
        goto cleanup;
    }

    DUMP_PRINC("gc_from_kdc: server as requested", supplied_server);

    /*
     * Try requesting a service ticket from our local KDC with referrals
     * turned on.  If the first referral succeeds, follow a referral-only
     * path, otherwise fall back to old-style assumptions.
     */

    for (referral_count = 0;
	 referral_count < KRB5_REFERRAL_MAXHOPS;
	 referral_count++) {
#if 0
        DUMP_PRINC("gc_from_kdc: referral loop: tgt in use", tgtptr->server);
        DUMP_PRINC("gc_from_kdc: referral loop: request is for", server);
#endif
        retval = krb5_get_cred_via_tkt(context, tgtptr,
				       KDC_OPT_CANONICALIZE |
				       FLAGS2OPTS(tgtptr->ticket_flags) |
				       kdcopt |
				       (in_cred->second_ticket.length ?
					KDC_OPT_ENC_TKT_IN_SKEY : 0),
				       tgtptr->addresses, in_cred, out_cred);
	if (retval) {
	    DPRINTF(("gc_from_kdc: referral TGS-REQ request failed: <%s>\n",
		     error_message(retval)));
	    /* If we haven't gone anywhere yet, fail through to the
	       non-referral case. */
	    if (referral_count==0) {
	        DPRINTF(("gc_from_kdc: initial referral failed; "
			 "punting to fallback.\n"));
	        break;
	    }
	    /* Otherwise, try the same query without canonicalization
	       set, and fail hard if that doesn't work. */
	    DPRINTF(("gc_from_kdc: referral #%d failed; "
		     "retrying without option.\n", referral_count + 1));
	    retval = krb5_get_cred_via_tkt(context, tgtptr,
					   FLAGS2OPTS(tgtptr->ticket_flags) |
					   kdcopt |
					   (in_cred->second_ticket.length ?
					    KDC_OPT_ENC_TKT_IN_SKEY : 0),
					   tgtptr->addresses,
					   in_cred, out_cred);
	    /* Whether or not that succeeded, we're done. */
	    goto cleanup;
	}
	    /* Referral request succeeded; let's see what it is. */
	    if (krb5_principal_compare(context, in_cred->server,
				       (*out_cred)->server)) {
		DPRINTF(("gc_from_kdc: request generated ticket "
			 "for requested server principal\n"));
		DUMP_PRINC("gc_from_kdc final referred reply",
			   in_cred->server);

	    /*
	     * Check if the return enctype is one that we requested if
	     * needed.
	     */
	    if (old_use_conf_ktypes || context->tgs_ktype_count == 0)
		goto cleanup;
	    for (i = 0; i < context->tgs_ktype_count; i++) {
		if ((*out_cred)->keyblock.enctype == context->tgs_ktypes[i]) {
		    /* Found an allowable etype, so we're done */
		    goto cleanup;
		}
	    }
	    /*
	     *  We need to try again, but this time use the
	     *  tgs_ktypes in the context. At this point we should
	     *  have all the tgts to succeed.
	     */

	    /* Free "wrong" credential */
	    krb5_free_creds(context, *out_cred);
	    *out_cred = NULL;
	    /* Re-establish tgs etypes */
	    context->use_conf_ktypes = old_use_conf_ktypes;
	    retval = krb5_get_cred_via_tkt(context, tgtptr,
					   KDC_OPT_CANONICALIZE |
					   FLAGS2OPTS(tgtptr->ticket_flags) |
					   kdcopt |
					   (in_cred->second_ticket.length ?
					    KDC_OPT_ENC_TKT_IN_SKEY : 0),
					   tgtptr->addresses,
					   in_cred, out_cred);
		goto cleanup;
	    }
	    else if (IS_TGS_PRINC(context, (*out_cred)->server)) {
		krb5_data *r1, *r2;

		DPRINTF(("gc_from_kdc: request generated referral tgt\n"));
		DUMP_PRINC("gc_from_kdc credential received",
			   (*out_cred)->server);

		if (referral_count == 0)
		    r1 = &tgtptr->server->data[1];
		else
		    r1 = &referral_tgts[referral_count-1]->server->data[1];

		r2 = &(*out_cred)->server->data[1];
		if (r1->length == r2->length &&
		    !memcmp(r1->data, r2->data, r1->length)) {
		    DPRINTF(("gc_from_kdc: referred back to "
			     "previous realm; fall back\n"));
		    krb5_free_creds(context, *out_cred);
		    *out_cred = NULL;
		    break;
		}
		/* Check for referral routing loop. */
		for (i=0;i<referral_count;i++) {
#if 0
		    DUMP_PRINC("gc_from_kdc: loop compare #1",
			       (*out_cred)->server);
		    DUMP_PRINC("gc_from_kdc: loop compare #2",
			       referral_tgts[i]->server);
#endif
		    if (krb5_principal_compare(context,
					       (*out_cred)->server,
					       referral_tgts[i]->server)) {
			DFPRINTF((stderr,
				  "krb5_get_cred_from_kdc_opt: "
				  "referral routing loop - "
				  "got referral back to hop #%d\n", i));
			retval=KRB5_KDC_UNREACH;
			goto cleanup;
		    }
		}
		/* Point current tgt pointer at newly-received TGT. */
		if (tgtptr == &cc_tgt)
		    krb5_free_cred_contents(context, tgtptr);
		tgtptr=*out_cred;
		/* Save pointer to tgt in referral_tgts. */
		referral_tgts[referral_count]=*out_cred;
		/* Copy krbtgt realm to server principal. */
		krb5_free_data_contents(context, &server->realm);
		retval = krb5int_copy_data_contents(context,
						    &tgtptr->server->data[1],
						    &server->realm);
		if (retval)
		    return retval;
		/*
		 * Future work: rewrite server principal per any
		 * supplied padata.
		 */
	    } else {
		/* Not a TGT; punt to fallback. */
		krb5_free_creds(context, *out_cred);
		*out_cred = NULL;
		break;
	}
    }

    DUMP_PRINC("gc_from_kdc client at fallback", client);
    DUMP_PRINC("gc_from_kdc server at fallback", server);

    /*
     * At this point referrals have been tried and have failed.  Go
     * back to the server principal as originally issued and try the
     * conventional path.
     */

    /*
     * Referrals have failed.  Look up fallback realm if not
     * originally provided.
     */
    if (krb5_is_referral_realm(&supplied_server->realm)) {
        if (server->length >= 2) {
	    retval=krb5_get_fallback_host_realm(context, &server->data[1],
						&hrealms);
	    if (retval) goto cleanup;
#if 0
	    DPRINTF(("gc_from_kdc: using fallback realm of %s\n",
		     hrealms[0]));
#endif
	    krb5_free_data_contents(context,&in_cred->server->realm);
	    server->realm.data=hrealms[0];
	    server->realm.length=strlen(hrealms[0]);
	    free(hrealms);
	}
	else {
	    /*
	     * Problem case: Realm tagged for referral but apparently not
	     * in a <type>/<host> format that
	     * krb5_get_fallback_host_realm can deal with.
	     */
	    /* Solaris Kerberos */
	    char *s_name = NULL;
	    char *c_name = NULL;
	    krb5_error_code s_err, c_err;
	    s_err = krb5_unparse_name(context, server, &s_name);
	    c_err = krb5_unparse_name(context, client, &c_name);
	    krb5_set_error_message(context, KRB5_ERR_HOST_REALM_UNKNOWN,
				dgettext(TEXT_DOMAIN,
					"Cannot determine realm for host: Referral specified but no fallback realm available. Client is '%s' and Server is '%s'"),
				c_err ? "unknown" : c_name,
				s_err ? "unknown" : s_name);
	    if (s_name)
		krb5_free_unparsed_name(context, s_name);
	    if (c_name)
		krb5_free_unparsed_name(context, c_name);

	    DPRINTF(("gc_from_kdc: referral specified "
		     "but no fallback realm avaiable!\n"));
	    return KRB5_ERR_HOST_REALM_UNKNOWN;
	}
    }

    DUMP_PRINC("gc_from_kdc server at fallback after fallback rewrite",
	       server);

    /*
     * Get a TGT for the target realm.
     */

    krb5_free_cred_contents(context, &tgtq);
    retval = tgt_mcred(context, client, server, client, &tgtq);
    if (retval)
	goto cleanup;

    /* Fast path: Is it in the ccache? */
    /* Free tgtptr data if reused from above. */
    if (tgtptr == &cc_tgt)
	krb5_free_cred_contents(context, tgtptr);
    /* Free TGTS if previously filled by do_traversal() */
    if (*tgts != NULL) {
	for (i = 0; (*tgts)[i] != NULL; i++) {
	    krb5_free_creds(context, (*tgts)[i]);
	}
	free(*tgts);
	*tgts = NULL;
    }
    context->use_conf_ktypes = 1;
    /*
     * Solaris Kerberos:
     * Ensure the retrieved cred isn't stale.
     * Set endtime to now so krb5_cc_retrieve_cred won't return an expired ticket.
     */
    if ((retval = krb5_timeofday(context, &(tgtq.times.endtime))) != 0) {
    	goto cleanup;
    }
    retval = krb5_cc_retrieve_cred(context, ccache, RETR_FLAGS,
				   &tgtq, &cc_tgt);
    if (!retval) {
	tgtptr = &cc_tgt;
    } else if (!HARD_CC_ERR(retval)) {
	retval = do_traversal(context, ccache, client, server,
			      &cc_tgt, &tgtptr, tgts);
    }
    if (retval)
	goto cleanup;

    /*
     * Finally have TGT for target realm!  Try using it to get creds.
     */

    if (!krb5_c_valid_enctype(tgtptr->keyblock.enctype)) {
	retval = KRB5_PROG_ETYPE_NOSUPP;
	goto cleanup;
    }

    context->use_conf_ktypes = old_use_conf_ktypes;
    retval = krb5_get_cred_via_tkt(context, tgtptr,
				   FLAGS2OPTS(tgtptr->ticket_flags) |
				   kdcopt |
				   (in_cred->second_ticket.length ?
				    KDC_OPT_ENC_TKT_IN_SKEY : 0),
				   tgtptr->addresses, in_cred, out_cred);

cleanup:
    krb5_free_cred_contents(context, &tgtq);
    if (tgtptr == &cc_tgt)
	krb5_free_cred_contents(context, tgtptr);
    context->use_conf_ktypes = old_use_conf_ktypes;
    /* Drop the original principal back into in_cred so that it's cached
       in the expected format. */
    DUMP_PRINC("gc_from_kdc: final hacked server principal at cleanup",
	       server);
    krb5_free_principal(context, server);
    in_cred->server = supplied_server;
    if (*out_cred && !retval) {
        /* Success: free server, swap supplied server back in. */
        krb5_free_principal (context, (*out_cred)->server);
	(*out_cred)->server= out_supplied_server;
    }
    else {
        /*
	 * Failure: free out_supplied_server.  Don't free out_cred here
	 * since it's either null or a referral TGT that we free below,
	 * and we may need it to return.
	 */
        krb5_free_principal (context, out_supplied_server);
    }
    DUMP_PRINC("gc_from_kdc: final server after reversion", in_cred->server);
    /*
     * Deal with ccache TGT management: If tgts has been set from
     * initial non-referral TGT discovery, leave it alone.  Otherwise, if
     * referral_tgts[0] exists return it as the only entry in tgts.
     * (Further referrals are never cached, only the referral from the
     * local KDC.)  This is part of cleanup because useful received TGTs
     * should be cached even if the main request resulted in failure.
     */

    if (*tgts == NULL) {
        if (referral_tgts[0]) {
#if 0
  	    /*
	     * This should possibly be a check on the candidate return
	     * credential against the cache, in the circumstance where we
	     * don't want to clutter the cache with near-duplicate
	     * credentials on subsequent iterations.  For now, it is
	     * disabled.
	     */
	    subretval=...?;
	    if (subretval) {
#endif
	        /* Allocate returnable TGT list. */
	        if (!(*tgts=calloc(sizeof (krb5_creds *), 2)))
		    return ENOMEM;
		subretval=krb5_copy_creds(context, referral_tgts[0], &((*tgts)[0]));
		if(subretval)
		    return subretval;
		(*tgts)[1]=NULL;
		DUMP_PRINC("gc_from_kdc: returning referral TGT for ccache",
			   (*tgts)[0]->server);
#if 0
	    }
#endif
	}
    }

    /* Free referral TGTs list. */
    for (i=0;i<KRB5_REFERRAL_MAXHOPS;i++) {
        if(referral_tgts[i]) {
	    krb5_free_creds(context, referral_tgts[i]);
	}
    }
    DPRINTF(("gc_from_kdc finishing with %s\n",
	     retval ? error_message(retval) : "no error"));
    return retval;
}

krb5_error_code
krb5_get_cred_from_kdc(krb5_context context, krb5_ccache ccache,
		       krb5_creds *in_cred, krb5_creds **out_cred,
		       krb5_creds ***tgts)
{
    return krb5_get_cred_from_kdc_opt(context, ccache, in_cred, out_cred, tgts,
				      0);
}

krb5_error_code
krb5_get_cred_from_kdc_validate(krb5_context context, krb5_ccache ccache,
				krb5_creds *in_cred, krb5_creds **out_cred,
				krb5_creds ***tgts)
{
    return krb5_get_cred_from_kdc_opt(context, ccache, in_cred, out_cred, tgts,
				      KDC_OPT_VALIDATE);
}

krb5_error_code
krb5_get_cred_from_kdc_renew(krb5_context context, krb5_ccache ccache,
			     krb5_creds *in_cred, krb5_creds **out_cred,
			     krb5_creds ***tgts)
{
    return krb5_get_cred_from_kdc_opt(context, ccache, in_cred, out_cred, tgts,
				      KDC_OPT_RENEW);
}
