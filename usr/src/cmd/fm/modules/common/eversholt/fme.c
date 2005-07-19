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
 *
 * fme.c -- fault management exercise module
 *
 * this module provides the simulated fault management exercise.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <alloca.h>
#include <libnvpair.h>
#include <sys/fm/protocol.h>
#include <fm/fmd_api.h>
#include "alloc.h"
#include "out.h"
#include "stats.h"
#include "stable.h"
#include "literals.h"
#include "lut.h"
#include "tree.h"
#include "ptree.h"
#include "itree.h"
#include "ipath.h"
#include "fme.h"
#include "evnv.h"
#include "eval.h"
#include "config.h"
#include "platform.h"

/* imported from eft.c... */
extern int Autoconvict;
extern char *Autoclose;
extern hrtime_t Hesitate;
extern nv_alloc_t Eft_nv_hdl;

/* fme under construction is global so we can free it on module abort */
static struct fme *Nfmep;

static const char *Undiag_reason;

static int Nextid = 0;

/* list of fault management exercises underway */
static struct fme {
	struct fme *next;		/* next exercise */
	unsigned long long ull;		/* time when fme was created */
	int id;				/* FME id */
	struct cfgdata *cfgdata;	/* full configuration data */
	struct lut *eventtree;		/* propagation tree for this FME */
	/*
	 * The initial error report that created this FME is kept in
	 * two forms.  e0 points to the instance tree node and is used
	 * by fme_eval() as the starting point for the inference
	 * algorithm.  e0r is the event handle FMD passed to us when
	 * the ereport first arrived and is used when setting timers,
	 * which are always relative to the time of this initial
	 * report.
	 */
	struct event *e0;
	fmd_event_t *e0r;

	id_t    timer;			/* for setting an fmd time-out */
	id_t	htid;			/* for setting hesitation timer */

	struct event *ecurrent;		/* ereport under consideration */
	struct event *suspects;		/* current suspect list */
	struct event *psuspects;	/* previous suspect list */
	int nsuspects;			/* count of suspects */
	int nonfault;			/* zero if all suspects T_FAULT */
	int posted_suspects;		/* true if we've posted a diagnosis */
	int hesitated;			/* true if we hesitated */
	int uniqobs;			/* number of unique events observed */
	int peek;			/* just peeking, don't track suspects */
	enum fme_state {
		FME_NOTHING = 5000,	/* not evaluated yet */
		FME_WAIT,		/* need to wait for more info */
		FME_CREDIBLE,		/* suspect list is credible */
		FME_DISPROVED		/* no valid suspects found */
	} state;

	unsigned long long pull;	/* time passed since created */
	unsigned long long wull;	/* wait until this time for re-eval */
	struct event *observations;	/* observation list */
	struct lut *globals;		/* values of global variables */
	/* fmd interfacing */
	fmd_hdl_t *hdl;			/* handle for talking with fmd */
	fmd_case_t *fmcase;		/* what fmd 'case' we associate with */
	/* stats */
	struct stats *Rcount;
	struct stats *Hcallcount;
	struct stats *Rcallcount;
	struct stats *Ccallcount;
	struct stats *Ecallcount;
	struct stats *Tcallcount;
	struct stats *Marrowcount;
	struct stats *diags;
} *FMElist, *EFMElist, *ClosedFMEs;

static struct case_list {
	fmd_case_t *fmcase;
	struct case_list *next;
} *Undiagablecaselist;

static void fme_eval(struct fme *fmep, fmd_event_t *ffep);
static enum fme_state hypothesise(struct fme *fmep, struct event *ep,
	unsigned long long at_latest_by, unsigned long long *pdelay,
	struct arrow *arrowp);
static struct node *eventprop_lookup(struct event *ep, const char *propname);
static struct node *pathstring2epnamenp(char *path);
static void publish_undiagnosable(fmd_hdl_t *hdl, fmd_event_t *ffep);
static void restore_suspects(struct fme *fmep);
static void save_suspects(struct fme *fmep);
static void destroy_fme(struct fme *f);
static void fme_receive_report(fmd_hdl_t *hdl, fmd_event_t *ffep,
    const char *eventstring, const struct ipath *ipp, nvlist_t *nvl);

static struct fme *
alloc_fme(void)
{
	struct fme *fmep;

	fmep = MALLOC(sizeof (*fmep));
	bzero(fmep, sizeof (*fmep));
	return (fmep);
}

/*
 * fme_ready -- called when all initialization of the FME (except for
 *	stats) has completed successfully.  Adds the fme to global lists
 *	and establishes its stats.
 */
static struct fme *
fme_ready(struct fme *fmep)
{
	char nbuf[100];

	Nfmep = NULL;	/* don't need to free this on module abort now */

	if (EFMElist) {
		EFMElist->next = fmep;
		EFMElist = fmep;
	} else
		FMElist = EFMElist = fmep;

	(void) sprintf(nbuf, "fme%d.Rcount", fmep->id);
	fmep->Rcount = stats_new_counter(nbuf, "ereports received", 0);
	(void) sprintf(nbuf, "fme%d.Hcall", fmep->id);
	fmep->Hcallcount = stats_new_counter(nbuf, "calls to hypothesise()", 1);
	(void) sprintf(nbuf, "fme%d.Rcall", fmep->id);
	fmep->Rcallcount = stats_new_counter(nbuf,
	    "calls to requirements_test()", 1);
	(void) sprintf(nbuf, "fme%d.Ccall", fmep->id);
	fmep->Ccallcount = stats_new_counter(nbuf, "calls to causes_test()", 1);
	(void) sprintf(nbuf, "fme%d.Ecall", fmep->id);
	fmep->Ecallcount =
	    stats_new_counter(nbuf, "calls to effects_test()", 1);
	(void) sprintf(nbuf, "fme%d.Tcall", fmep->id);
	fmep->Tcallcount = stats_new_counter(nbuf, "calls to triggered()", 1);
	(void) sprintf(nbuf, "fme%d.Marrow", fmep->id);
	fmep->Marrowcount = stats_new_counter(nbuf,
	    "arrows marked by mark_arrows()", 1);
	(void) sprintf(nbuf, "fme%d.diags", fmep->id);
	fmep->diags = stats_new_counter(nbuf, "suspect lists diagnosed", 0);

	out(O_ALTFP|O_VERB2, "newfme: config snapshot contains...");
	config_print(O_ALTFP|O_VERB2, fmep->cfgdata->cooked);

	return (fmep);
}

static struct fme *
newfme(const char *e0class, const struct ipath *e0ipp)
{
	struct cfgdata *cfgdata;

	if ((cfgdata = config_snapshot()) == NULL) {
		out(O_ALTFP, "newfme: NULL configuration");
		Undiag_reason = UD_NOCONF;
		return (NULL);
	}

	Nfmep = alloc_fme();

	Nfmep->id = Nextid++;
	Nfmep->cfgdata = cfgdata;
	Nfmep->posted_suspects = 0;
	Nfmep->uniqobs = 0;
	Nfmep->state = FME_NOTHING;
	Nfmep->pull = 0ULL;

	Nfmep->fmcase = NULL;
	Nfmep->hdl = NULL;

	if ((Nfmep->eventtree = itree_create(cfgdata->cooked)) == NULL) {
		out(O_ALTFP, "newfme: NULL instance tree");
		Undiag_reason = UD_INSTFAIL;
		config_free(cfgdata);
		FREE(Nfmep);
		Nfmep = NULL;
		return (NULL);
	}

	itree_ptree(O_ALTFP|O_VERB2, Nfmep->eventtree);

	if ((Nfmep->e0 =
	    itree_lookup(Nfmep->eventtree, e0class, e0ipp)) == NULL) {
		out(O_ALTFP, "newfme: e0 not in instance tree");
		Undiag_reason = UD_BADEVENTI;
		itree_free(Nfmep->eventtree);
		config_free(cfgdata);
		FREE(Nfmep);
		Nfmep = NULL;
		return (NULL);
	}

	return (fme_ready(Nfmep));
}

void
fme_fini(void)
{
	struct fme *sfp, *fp;
	struct case_list *ucasep, *nextcasep;

	ucasep = Undiagablecaselist;
	while (ucasep != NULL) {
		nextcasep = ucasep->next;
		FREE(ucasep);
		ucasep = nextcasep;
	}
	Undiagablecaselist = NULL;

	/* clean up closed fmes */
	fp = ClosedFMEs;
	while (fp != NULL) {
		sfp = fp->next;
		destroy_fme(fp);
		fp = sfp;
	}
	ClosedFMEs = NULL;

	fp = FMElist;
	while (fp != NULL) {
		sfp = fp->next;
		destroy_fme(fp);
		fp = sfp;
	}
	FMElist = EFMElist = NULL;

	/* if we were in the middle of creating an fme, free it now */
	if (Nfmep) {
		destroy_fme(Nfmep);
		Nfmep = NULL;
	}
}

/*
 * Allocated space for a buffer name.  20 bytes allows for
 * a ridiculous 9,999,999 unique observations.
 */
#define	OBBUFNMSZ 20

/*
 *  serialize_observation
 *
 *  Create a recoverable version of the current observation
 *  (f->ecurrent).  We keep a serialized version of each unique
 *  observation in order that we may resume correctly the fme in the
 *  correct state if eft or fmd crashes and we're restarted.
 */
static void
serialize_observation(struct fme *fp, const char *cls, const struct ipath *ipp)
{
	size_t pkdlen;
	char tmpbuf[OBBUFNMSZ];
	char *pkd = NULL;
	char *estr;

	(void) snprintf(tmpbuf, OBBUFNMSZ, "observed%d", fp->uniqobs);
	estr = ipath2str(cls, ipp);
	fmd_buf_create(fp->hdl, fp->fmcase, tmpbuf, strlen(estr) + 1);
	fmd_buf_write(fp->hdl, fp->fmcase, tmpbuf, (void *)estr,
	    strlen(estr) + 1);
	FREE(estr);

	if (fp->ecurrent != NULL && fp->ecurrent->nvp != NULL) {
		(void) snprintf(tmpbuf,
		    OBBUFNMSZ, "observed%d.nvp", fp->uniqobs);
		if (nvlist_xpack(fp->ecurrent->nvp,
		    &pkd, &pkdlen, NV_ENCODE_XDR, &Eft_nv_hdl) != 0)
			out(O_DIE|O_SYS, "pack of observed nvl failed");
		fmd_buf_create(fp->hdl, fp->fmcase, tmpbuf, pkdlen);
		fmd_buf_write(fp->hdl, fp->fmcase, tmpbuf, (void *)pkd, pkdlen);
		FREE(pkd);
	}

	fp->uniqobs++;
	fmd_buf_write(fp->hdl, fp->fmcase, WOBUF_NOBS, (void *)&fp->uniqobs,
	    sizeof (fp->uniqobs));
}

/*
 *  init_fme_bufs -- We keep several bits of state about an fme for
 *	use if eft or fmd crashes and we're restarted.
 */
static void
init_fme_bufs(struct fme *fp)
{
	size_t cfglen = fp->cfgdata->nextfree - fp->cfgdata->begin;

	fmd_buf_create(fp->hdl, fp->fmcase, WOBUF_CFGLEN, sizeof (cfglen));
	fmd_buf_write(fp->hdl, fp->fmcase, WOBUF_CFGLEN, (void *)&cfglen,
	    sizeof (cfglen));
	if (cfglen != 0) {
		fmd_buf_create(fp->hdl, fp->fmcase, WOBUF_CFG, cfglen);
		fmd_buf_write(fp->hdl, fp->fmcase, WOBUF_CFG,
		    fp->cfgdata->begin, cfglen);
	}

	fmd_buf_create(fp->hdl, fp->fmcase, WOBUF_PULL, sizeof (fp->pull));
	fmd_buf_write(fp->hdl, fp->fmcase, WOBUF_PULL, (void *)&fp->pull,
	    sizeof (fp->pull));

	fmd_buf_create(fp->hdl, fp->fmcase, WOBUF_ID, sizeof (fp->id));
	fmd_buf_write(fp->hdl, fp->fmcase, WOBUF_ID, (void *)&fp->id,
	    sizeof (fp->id));

	fmd_buf_create(fp->hdl, fp->fmcase, WOBUF_NOBS, sizeof (fp->uniqobs));
	fmd_buf_write(fp->hdl, fp->fmcase, WOBUF_NOBS, (void *)&fp->uniqobs,
	    sizeof (fp->uniqobs));

	fmd_buf_create(fp->hdl, fp->fmcase, WOBUF_POSTD,
	    sizeof (fp->posted_suspects));
	fmd_buf_write(fp->hdl, fp->fmcase, WOBUF_POSTD,
	    (void *)&fp->posted_suspects, sizeof (fp->posted_suspects));
}

static void
destroy_fme_bufs(struct fme *fp)
{
	char tmpbuf[OBBUFNMSZ];
	int o;

	fmd_buf_destroy(fp->hdl, fp->fmcase, WOBUF_CFGLEN);
	fmd_buf_destroy(fp->hdl, fp->fmcase, WOBUF_CFG);
	fmd_buf_destroy(fp->hdl, fp->fmcase, WOBUF_PULL);
	fmd_buf_destroy(fp->hdl, fp->fmcase, WOBUF_ID);
	fmd_buf_destroy(fp->hdl, fp->fmcase, WOBUF_POSTD);
	fmd_buf_destroy(fp->hdl, fp->fmcase, WOBUF_NOBS);

	for (o = 0; o < fp->uniqobs; o++) {
		(void) snprintf(tmpbuf, OBBUFNMSZ, "observed%d", o);
		fmd_buf_destroy(fp->hdl, fp->fmcase, tmpbuf);
		(void) snprintf(tmpbuf, OBBUFNMSZ, "observed%d.nvp", o);
		fmd_buf_destroy(fp->hdl, fp->fmcase, tmpbuf);
	}
}

/*
 * reconstitute_observations -- convert a case's serialized observations
 *	back into struct events.  Returns zero if all observations are
 *	successfully reconstituted.
 */
static int
reconstitute_observations(struct fme *fmep)
{
	struct event *ep;
	struct node *epnamenp = NULL;
	size_t pkdlen;
	char *pkd = NULL;
	char *tmpbuf = alloca(OBBUFNMSZ);
	char *sepptr;
	char *estr;
	int ocnt;
	int elen;

	for (ocnt = 0; ocnt < fmep->uniqobs; ocnt++) {
		(void) snprintf(tmpbuf, OBBUFNMSZ, "observed%d", ocnt);
		elen = fmd_buf_size(fmep->hdl, fmep->fmcase, tmpbuf);
		if (elen == 0) {
			out(O_ALTFP,
			    "reconstitute_observation: no %s buffer found.",
			    tmpbuf);
			Undiag_reason = UD_MISSINGOBS;
			break;
		}

		estr = MALLOC(elen);
		fmd_buf_read(fmep->hdl, fmep->fmcase, tmpbuf, estr, elen);
		sepptr = strchr(estr, '@');
		if (sepptr == NULL) {
			out(O_ALTFP,
			    "reconstitute_observation: %s: "
			    "missing @ separator in %s.",
			    tmpbuf, estr);
			Undiag_reason = UD_MISSINGPATH;
			FREE(estr);
			break;
		}

		*sepptr = '\0';
		if ((epnamenp = pathstring2epnamenp(sepptr + 1)) == NULL) {
			out(O_ALTFP,
			    "reconstitute_observation: %s: "
			    "trouble converting path string \"%s\" "
			    "to internal representation.",
			    tmpbuf, sepptr + 1);
			Undiag_reason = UD_MISSINGPATH;
			FREE(estr);
			break;
		}

		/* construct the event */
		ep = itree_lookup(fmep->eventtree,
		    stable(estr), ipath(epnamenp));
		if (ep == NULL) {
			out(O_ALTFP,
			    "reconstitute_observation: %s: "
			    "lookup of  \"%s\" in itree failed.",
			    tmpbuf, ipath2str(estr, ipath(epnamenp)));
			Undiag_reason = UD_BADOBS;
			tree_free(epnamenp);
			FREE(estr);
			break;
		}
		tree_free(epnamenp);

		/*
		 * We may or may not have a saved nvlist for the observation
		 */
		(void) snprintf(tmpbuf, OBBUFNMSZ, "observed%d.nvp", ocnt);
		pkdlen = fmd_buf_size(fmep->hdl, fmep->fmcase, tmpbuf);
		if (pkdlen != 0) {
			pkd = MALLOC(pkdlen);
			fmd_buf_read(fmep->hdl,
			    fmep->fmcase, tmpbuf, pkd, pkdlen);
			if (nvlist_xunpack(pkd,
			    pkdlen, &ep->nvp, &Eft_nv_hdl) != 0)
				out(O_DIE|O_SYS, "pack of observed nvl failed");
			FREE(pkd);
		}

		if (ocnt == 0)
			fmep->e0 = ep;

		FREE(estr);
		fmep->ecurrent = ep;
		ep->count++;

		/* link it into list of observations seen */
		ep->observations = fmep->observations;
		fmep->observations = ep;
	}

	if (ocnt == fmep->uniqobs) {
		(void) fme_ready(fmep);
		return (0);
	}

	return (1);
}

/*
 * restart_fme -- called during eft initialization.  Reconstitutes
 *	an in-progress fme.
 */
void
fme_restart(fmd_hdl_t *hdl, fmd_case_t *inprogress)
{
	nvlist_t *defect;
	struct case_list *bad;
	struct fme *fmep;
	struct cfgdata *cfgdata = NULL;
	size_t rawsz;

	fmep = alloc_fme();
	fmep->fmcase = inprogress;
	fmep->hdl = hdl;

	if (fmd_buf_size(hdl, inprogress, WOBUF_CFGLEN) != sizeof (size_t)) {
		out(O_ALTFP, "restart_fme: No config data");
		Undiag_reason = UD_MISSINGINFO;
		goto badcase;
	}
	fmd_buf_read(hdl, inprogress, WOBUF_CFGLEN, (void *)&rawsz,
	    sizeof (size_t));

	if ((fmep->e0r = fmd_case_getprincipal(hdl, inprogress)) == NULL) {
		out(O_ALTFP, "restart_fme: No event zero");
		Undiag_reason = UD_MISSINGZERO;
		goto badcase;
	}

	cfgdata = MALLOC(sizeof (struct cfgdata));
	cfgdata->cooked = NULL;
	cfgdata->devcache = NULL;
	cfgdata->cpucache = NULL;
	cfgdata->refcnt = 1;

	if (rawsz > 0) {
		if (fmd_buf_size(hdl, inprogress, WOBUF_CFG) != rawsz) {
			out(O_ALTFP, "restart_fme: Config data size mismatch");
			Undiag_reason = UD_CFGMISMATCH;
			goto badcase;
		}
		cfgdata->begin = MALLOC(rawsz);
		cfgdata->end = cfgdata->nextfree = cfgdata->begin + rawsz;
		fmd_buf_read(hdl,
		    inprogress, WOBUF_CFG, cfgdata->begin, rawsz);
	} else {
		cfgdata->begin = cfgdata->end = cfgdata->nextfree = NULL;
	}
	fmep->cfgdata = cfgdata;

	config_cook(cfgdata);
	if ((fmep->eventtree = itree_create(cfgdata->cooked)) == NULL) {
		/* case not properly saved or irretrievable */
		out(O_ALTFP, "restart_fme: NULL instance tree");
		Undiag_reason = UD_INSTFAIL;
		goto badcase;
	}

	itree_ptree(O_ALTFP|O_VERB2, fmep->eventtree);

	if (fmd_buf_size(hdl, inprogress, WOBUF_PULL) == 0) {
		out(O_ALTFP, "restart_fme: no saved wait time");
		Undiag_reason = UD_MISSINGINFO;
		goto badcase;
	} else {
		fmd_buf_read(hdl, inprogress, WOBUF_PULL, (void *)&fmep->pull,
		    sizeof (fmep->pull));
	}

	if (fmd_buf_size(hdl, inprogress, WOBUF_POSTD) == 0) {
		out(O_ALTFP, "restart_fme: no saved posted status");
		Undiag_reason = UD_MISSINGINFO;
		goto badcase;
	} else {
		fmd_buf_read(hdl, inprogress, WOBUF_POSTD,
		    (void *)&fmep->posted_suspects,
		    sizeof (fmep->posted_suspects));
	}

	if (fmd_buf_size(hdl, inprogress, WOBUF_ID) == 0) {
		out(O_ALTFP, "restart_fme: no saved id");
		Undiag_reason = UD_MISSINGINFO;
		goto badcase;
	} else {
		fmd_buf_read(hdl, inprogress, WOBUF_ID, (void *)&fmep->id,
		    sizeof (fmep->id));
	}
	if (Nextid <= fmep->id)
		Nextid = fmep->id + 1;

	if (fmd_buf_size(hdl, inprogress, WOBUF_NOBS) == 0) {
		out(O_ALTFP, "restart_fme: no count of observations");
		Undiag_reason = UD_MISSINGINFO;
		goto badcase;
	} else {
		fmd_buf_read(hdl, inprogress, WOBUF_NOBS,
		    (void *)&fmep->uniqobs, sizeof (fmep->uniqobs));
	}

	if (reconstitute_observations(fmep) != 0)
		goto badcase;

	/* give the diagnosis algorithm a shot at the new FME state */
	fme_eval(fmep, NULL);
	return;

badcase:
	if (fmep->eventtree != NULL)
		itree_free(fmep->eventtree);
	config_free(cfgdata);
	destroy_fme_bufs(fmep);
	FREE(fmep);

	/*
	 * Since we're unable to restart the case, add it to the undiagable
	 * list and solve and close it as appropriate.
	 */
	bad = MALLOC(sizeof (struct case_list));
	bad->next = NULL;

	if (Undiagablecaselist != NULL)
		bad->next = Undiagablecaselist;
	Undiagablecaselist = bad;
	bad->fmcase = inprogress;

	out(O_ALTFP, "[case %s (unable to restart), ",
	    fmd_case_uuid(hdl, bad->fmcase));

	if (fmd_case_solved(hdl, bad->fmcase)) {
		out(O_ALTFP, "already solved, ");
	} else {
		out(O_ALTFP, "solving, ");
		defect = fmd_nvl_create_fault(hdl, UNDIAGNOSABLE_DEFECT, 100,
		    NULL, NULL, NULL);
		if (Undiag_reason != NULL)
			(void) nvlist_add_string(defect,
			    UNDIAG_REASON, Undiag_reason);
		fmd_case_add_suspect(hdl, bad->fmcase, defect);
		fmd_case_solve(hdl, bad->fmcase);
	}

	if (fmd_case_closed(hdl, bad->fmcase)) {
		out(O_ALTFP, "already closed ]");
	} else {
		out(O_ALTFP, "closing ]");
		fmd_case_close(hdl, bad->fmcase);
	}
}

void
destroy_fme(struct fme *f)
{
	stats_delete(f->Rcount);
	stats_delete(f->Hcallcount);
	stats_delete(f->Rcallcount);
	stats_delete(f->Ccallcount);
	stats_delete(f->Ecallcount);
	stats_delete(f->Tcallcount);
	stats_delete(f->Marrowcount);
	stats_delete(f->diags);

	itree_free(f->eventtree);
	config_free(f->cfgdata);
	FREE(f);
}

static const char *
fme_state2str(enum fme_state s)
{
	switch (s) {
	case FME_NOTHING:	return ("NOTHING");
	case FME_WAIT:		return ("WAIT");
	case FME_CREDIBLE:	return ("CREDIBLE");
	case FME_DISPROVED:	return ("DISPROVED");
	default:		return ("UNKNOWN");
	}
}

static int
is_problem(enum nametype t)
{
	return (t == N_FAULT || t == N_DEFECT || t == N_UPSET);
}

static int
is_fault(enum nametype t)
{
	return (t == N_FAULT);
}

static int
is_defect(enum nametype t)
{
	return (t == N_DEFECT);
}

static int
is_upset(enum nametype t)
{
	return (t == N_UPSET);
}

/*ARGSUSED*/
static void
clear_causes_tested(struct event *lhs, struct event *ep, void *arg)
{
	struct bubble *bp;
	struct arrowlist *ap;

	for (bp = itree_next_bubble(ep, NULL); bp;
	    bp = itree_next_bubble(ep, bp)) {
		if (bp->t != B_FROM)
			continue;
		for (ap = itree_next_arrow(bp, NULL); ap;
		    ap = itree_next_arrow(bp, ap))
			ap->arrowp->causes_tested = 0;
	}
}

/*
 * call this function with initcode set to 0 to initialize cycle tracking
 */
static void
initialize_cycles(struct fme *fmep)
{
	lut_walk(fmep->eventtree, (lut_cb)clear_causes_tested, NULL);
}

static void
fme_print(int flags, struct fme *fmep)
{
	struct event *ep;

	out(flags, "Fault Management Exercise %d", fmep->id);
	out(flags, "\t       State: %s", fme_state2str(fmep->state));
	out(flags|O_NONL, "\t  Start time: ");
	ptree_timeval(flags|O_NONL, &fmep->ull);
	out(flags, NULL);
	if (fmep->wull) {
		out(flags|O_NONL, "\t   Wait time: ");
		ptree_timeval(flags|O_NONL, &fmep->wull);
		out(flags, NULL);
	}
	out(flags|O_NONL, "\t          E0: ");
	if (fmep->e0)
		itree_pevent_brief(flags|O_NONL, fmep->e0);
	else
		out(flags|O_NONL, "NULL");
	out(flags, NULL);
	out(flags|O_NONL, "\tObservations:");
	for (ep = fmep->observations; ep; ep = ep->observations) {
		out(flags|O_NONL, " ");
		itree_pevent_brief(flags|O_NONL, ep);
	}
	out(flags, NULL);
	out(flags|O_NONL, "\tSuspect list:");
	for (ep = fmep->suspects; ep; ep = ep->suspects) {
		out(flags|O_NONL, " ");
		itree_pevent_brief(flags|O_NONL, ep);
	}
	out(flags, NULL);
	out(flags|O_VERB2, "\t        Tree:");
	itree_ptree(flags|O_VERB2, fmep->eventtree);
}

static struct node *
pathstring2epnamenp(char *path)
{
	char *sep = "/";
	struct node *ret;
	char *ptr;

	if ((ptr = strtok(path, sep)) == NULL)
		out(O_DIE, "pathstring2epnamenp: invalid empty class");

	ret = tree_iname(stable(ptr), NULL, 0);

	while ((ptr = strtok(NULL, sep)) != NULL)
		ret = tree_name_append(ret,
		    tree_iname(stable(ptr), NULL, 0));

	return (ret);
}

/*
 * for a given upset sp, increment the corresponding SERD engine.  if the
 * SERD engine trips, return the ename and ipp of the resulting ereport.
 * returns true if engine tripped and *enamep and *ippp were filled in.
 */
static int
serd_eval(fmd_hdl_t *hdl, fmd_event_t *ffep, fmd_case_t *fmcase,
	struct event *sp, const char **enamep, const struct ipath **ippp)
{
	struct node *serdinst;
	char *serdname;

	ASSERT(sp->t == N_UPSET);
	ASSERT(ffep != NULL);

	/*
	 * obtain instanced SERD engine from the upset sp.  from this
	 * derive serdname, the string used to identify the SERD engine.
	 */
	serdinst = eventprop_lookup(sp, L_engine);

	if (serdinst == NULL)
		return (NULL);

	serdname = ipath2str(serdinst->u.stmt.np->u.event.ename->u.name.s,
	    ipath(serdinst->u.stmt.np->u.event.epname));

	if (!fmd_serd_exists(hdl, serdname)) {
		struct node *nN, *nT;

		/* no SERD engine yet, so create it */
		nN = lut_lookup(serdinst->u.stmt.lutp, (void *)L_N, NULL);
		nT = lut_lookup(serdinst->u.stmt.lutp, (void *)L_T, NULL);

		ASSERT(nN->t == T_NUM);
		ASSERT(nT->t == T_TIMEVAL);

		fmd_serd_create(hdl, serdname, (uint_t)nN->u.ull,
		    (hrtime_t)nT->u.ull);
	}


	/*
	 * increment SERD engine.  if engine fires, reset serd
	 * engine and return trip_strcode
	 */
	if (fmd_serd_record(hdl, serdname, ffep)) {
		struct node *tripinst = lut_lookup(serdinst->u.stmt.lutp,
		    (void *)L_trip, NULL);

		ASSERT(tripinst != NULL);

		*enamep = tripinst->u.event.ename->u.name.s;
		*ippp = ipath(tripinst->u.event.epname);

		fmd_case_add_serd(hdl, fmcase, serdname);
		fmd_serd_reset(hdl, serdname);
		out(O_ALTFP|O_NONL, "[engine fired: %s, sending: ", serdname);
		ipath_print(O_ALTFP|O_NONL, *enamep, *ippp);
		out(O_ALTFP, "]");

		FREE(serdname);
		return (1);
	}

	FREE(serdname);
	return (0);
}

/*
 * search a suspect list for upsets.  feed each upset to serd_eval() and
 * build up tripped[], an array of ereports produced by the firing of
 * any SERD engines.  then feed each ereport back into
 * fme_receive_report().
 *
 * returns ntrip, the number of these ereports produced.
 */
static int
upsets_eval(struct fme *fmep, fmd_event_t *ffep)
{
	/* we build an array of tripped ereports that we send ourselves */
	struct {
		const char *ename;
		const struct ipath *ipp;
	} *tripped;
	struct event *sp;
	int ntrip, nupset, i;

	/*
	 * we avoid recursion by calling fme_receive_report() at the end of
	 * this function with a NULL ffep
	 */
	if (ffep == NULL)
		return (0);

	/*
	 * count the number of upsets to determine the upper limit on
	 * expected trip ereport strings.  remember that one upset can
	 * lead to at most one ereport.
	 */
	nupset = 0;
	for (sp = fmep->suspects; sp; sp = sp->suspects) {
		if (sp->t == N_UPSET)
			nupset++;
	}

	if (nupset == 0)
		return (0);

	/*
	 * get to this point if we have upsets and expect some trip
	 * ereports
	 */
	tripped = alloca(sizeof (*tripped) * nupset);
	bzero((void *)tripped, sizeof (*tripped) * nupset);

	ntrip = 0;
	for (sp = fmep->suspects; sp; sp = sp->suspects)
		if (sp->t == N_UPSET &&
		    serd_eval(fmep->hdl, ffep, fmep->fmcase, sp,
			    &tripped[ntrip].ename, &tripped[ntrip].ipp))
			ntrip++;

	for (i = 0; i < ntrip; i++)
		fme_receive_report(fmep->hdl, NULL,
		    tripped[i].ename, tripped[i].ipp, NULL);

	return (ntrip);
}

/*
 * fme_receive_external_report -- call when an external ereport comes in
 *
 * this routine just converts the relevant information from the ereport
 * into a format used internally and passes it on to fme_receive_report().
 */
void
fme_receive_external_report(fmd_hdl_t *hdl, fmd_event_t *ffep, nvlist_t *nvl,
    const char *eventstring)
{
	struct node *epnamenp = platform_getpath(nvl);
	const struct ipath *ipp;

	/*
	 * XFILE: If we ended up without a path, it's an X-file.
	 * For now, use our undiagnosable interface.
	 */
	if (epnamenp == NULL) {
		out(O_ALTFP, "XFILE: Unable to get path from ereport");
		Undiag_reason = UD_NOPATH;
		publish_undiagnosable(hdl, ffep);
		return;
	}

	ipp = ipath(epnamenp);
	tree_free(epnamenp);
	fme_receive_report(hdl, ffep, stable(eventstring), ipp, nvl);
}

static void
fme_receive_report(fmd_hdl_t *hdl, fmd_event_t *ffep,
    const char *eventstring, const struct ipath *ipp, nvlist_t *nvl)
{
	struct event *ep;
	struct fme *fmep = NULL;
	struct fme *ofmep, *svfmep;
	int matched = 0;

	out(O_ALTFP|O_NONL, "fme_receive_report: ");
	ipath_print(O_ALTFP|O_NONL, eventstring, ipp);
	out(O_ALTFP|O_STAMP, NULL);

	/* decide which FME it goes to */
	for (fmep = FMElist; fmep; fmep = fmep->next) {
		int prev_verbose;
		unsigned long long my_delay = TIMEVAL_EVENTUALLY;
		enum fme_state state;

		/* look up event in event tree for this FME */
		if ((ep = itree_lookup(fmep->eventtree,
		    eventstring, ipp)) == NULL)
			continue;

		/* note observation */
		fmep->ecurrent = ep;
		if (ep->count++ == 0) {
			/* link it into list of observations seen */
			ep->observations = fmep->observations;
			fmep->observations = ep;
			ep->nvp = evnv_dupnvl(nvl);
		}

		/* tell hypothesise() not to mess with suspect list */
		fmep->peek = 1;

		/* don't want this to be verbose (unless Debug is set) */
		prev_verbose = Verbose;
		if (Debug == 0)
			Verbose = 0;

		initialize_cycles(fmep);
		state = hypothesise(fmep, fmep->e0, fmep->ull, &my_delay, NULL);

		fmep->peek = 0;

		/* put verbose flag back */
		Verbose = prev_verbose;

		if (state != FME_DISPROVED) {
			/* found an FME that explains the ereport */
			matched++;
			out(O_ALTFP|O_NONL, "[");
			ipath_print(O_ALTFP|O_NONL, eventstring, ipp);
			out(O_ALTFP, " explained by FME%d]", fmep->id);

			if (ep->count == 1)
				serialize_observation(fmep, eventstring, ipp);

			if (ffep)
				fmd_case_add_ereport(hdl, fmep->fmcase, ffep);

			stats_counter_bump(fmep->Rcount);

			/* re-eval FME */
			fme_eval(fmep, ffep);
		} else {

			/* not a match, undo noting of observation */
			fmep->ecurrent = NULL;
			if (--ep->count == 0) {
				/* unlink it from observations */
				fmep->observations = ep->observations;
				ep->observations = NULL;
				nvlist_free(ep->nvp);
				ep->nvp = NULL;
			}
		}
	}

	if (matched)
		return;	/* explained by at least one existing FME */

	/* clean up closed fmes */
	ofmep = ClosedFMEs;
	while (ofmep != NULL) {
		svfmep = ofmep->next;
		destroy_fme(ofmep);
		ofmep = svfmep;
	}
	ClosedFMEs = NULL;

	/* start a new FME */
	if ((fmep = newfme(eventstring, ipp)) == NULL) {
		out(O_ALTFP|O_NONL, "[");
		ipath_print(O_ALTFP|O_NONL, eventstring, ipp);
		out(O_ALTFP, " CANNOT DIAGNOSE]");
		publish_undiagnosable(hdl, ffep);
		return;
	}

	/* open a case */
	fmep->fmcase = fmd_case_open(hdl, NULL);
	fmep->hdl = hdl;
	init_fme_bufs(fmep);

	out(O_ALTFP|O_NONL, "[");
	ipath_print(O_ALTFP|O_NONL, eventstring, ipp);
	out(O_ALTFP, " created FME%d, case %s]", fmep->id,
	    fmd_case_uuid(hdl, fmep->fmcase));

	ep = fmep->e0;
	ASSERT(ep != NULL);

	/* note observation */
	fmep->ecurrent = ep;
	if (ep->count++ == 0) {
		/* link it into list of observations seen */
		ep->observations = fmep->observations;
		fmep->observations = ep;
		ep->nvp = evnv_dupnvl(nvl);
		serialize_observation(fmep, eventstring, ipp);
	}

	stats_counter_bump(fmep->Rcount);

	if (ffep) {
		fmd_case_add_ereport(hdl, fmep->fmcase, ffep);
		fmd_case_setprincipal(hdl, fmep->fmcase, ffep);
		fmep->e0r = ffep;
	}

	/* give the diagnosis algorithm a shot at the new FME state */
	fme_eval(fmep, ffep);
}

void
fme_status(int flags)
{
	struct fme *fmep;

	if (FMElist == NULL) {
		out(flags, "No fault management exercises underway.");
		return;
	}

	for (fmep = FMElist; fmep; fmep = fmep->next)
		fme_print(flags, fmep);
}

/*
 * "indent" routines used mostly for nicely formatted debug output, but also
 * for sanity checking for infinite recursion bugs.
 */

#define	MAX_INDENT 1024
static const char *indent_s[MAX_INDENT];
static int current_indent;

static void
indent_push(const char *s)
{
	if (current_indent < MAX_INDENT)
		indent_s[current_indent++] = s;
	else
		out(O_DIE, "unexpected recursion depth (%d)", current_indent);
}

static void
indent_set(const char *s)
{
	current_indent = 0;
	indent_push(s);
}

static void
indent_pop(void)
{
	if (current_indent > 0)
		current_indent--;
	else
		out(O_DIE, "recursion underflow");
}

static void
indent(void)
{
	int i;
	if (!Verbose)
		return;
	for (i = 0; i < current_indent; i++)
		out(O_ALTFP|O_VERB|O_NONL, indent_s[i]);
}

static int
suspects_changed(struct fme *fmep)
{
	struct event *suspects = fmep->suspects;
	struct event *psuspects = fmep->psuspects;

	while (suspects != NULL && psuspects != NULL) {
		if (suspects != psuspects)
			return (1);
		suspects = suspects->suspects;
		psuspects = psuspects->psuspects;
	}

	return (suspects != psuspects);
}

#define	SLNEW		1
#define	SLCHANGED	2
#define	SLWAIT		3
#define	SLDISPROVED	4

static void
print_suspects(int circumstance, struct fme *fmep)
{
	struct event *ep;

	out(O_ALTFP|O_NONL, "[");
	if (circumstance == SLCHANGED) {
		out(O_ALTFP|O_NONL, "FME%d diagnosis changed. state: %s, "
		    "suspect list:", fmep->id, fme_state2str(fmep->state));
	} else if (circumstance == SLWAIT) {
		out(O_ALTFP|O_NONL, "FME%d set wait timer ", fmep->id);
		ptree_timeval(O_ALTFP|O_NONL, &fmep->wull);
	} else if (circumstance == SLDISPROVED) {
		out(O_ALTFP|O_NONL, "FME%d DIAGNOSIS UNKNOWN", fmep->id);
	} else {
		out(O_ALTFP|O_NONL, "FME%d DIAGNOSIS PRODUCED:", fmep->id);
	}

	if (circumstance == SLWAIT || circumstance == SLDISPROVED) {
		out(O_ALTFP, "]");
		return;
	}

	for (ep = fmep->suspects; ep; ep = ep->suspects) {
		out(O_ALTFP|O_NONL, " ");
		itree_pevent_brief(O_ALTFP|O_NONL, ep);
	}
	out(O_ALTFP, "]");
}

static struct node *
eventprop_lookup(struct event *ep, const char *propname)
{
	return (lut_lookup(ep->props, (void *)propname, NULL));
}

#define	MAXDIGITIDX	23
static char numbuf[MAXDIGITIDX + 1];

static int
node2uint(struct node *n, uint_t *valp)
{
	struct evalue value;
	struct lut *globals = NULL;

	if (n == NULL)
		return (1);

	/*
	 * check value.v since we are being asked to convert an unsigned
	 * long long int to an unsigned int
	 */
	if (! eval_expr(n, NULL, NULL, &globals, NULL, NULL, 0, &value) ||
	    value.t != UINT64 || value.v > (1ULL << 32))
		return (1);

	*valp = (uint_t)value.v;

	return (0);
}

static nvlist_t *
node2fmri(struct node *n)
{
	nvlist_t **pa, *f, *p;
	struct node *nc;
	uint_t depth = 0;
	char *numstr, *nullbyte;
	char *failure;
	int err, i;

	/* XXX do we need to be able to handle a non-T_NAME node? */
	if (n == NULL || n->t != T_NAME)
		return (NULL);

	for (nc = n; nc != NULL; nc = nc->u.name.next) {
		if (nc->u.name.child == NULL || nc->u.name.child->t != T_NUM)
			break;
		depth++;
	}

	if (nc != NULL) {
		/* We bailed early, something went wrong */
		return (NULL);
	}

	if ((err = nvlist_xalloc(&f, NV_UNIQUE_NAME, &Eft_nv_hdl)) != 0)
		out(O_DIE|O_SYS, "alloc of fmri nvl failed");
	pa = alloca(depth * sizeof (nvlist_t *));
	for (i = 0; i < depth; i++)
		pa[i] = NULL;

	err = nvlist_add_string(f, FM_FMRI_SCHEME, FM_FMRI_SCHEME_HC);
	err |= nvlist_add_uint8(f, FM_VERSION, FM_HC_SCHEME_VERSION);
	err |= nvlist_add_string(f, FM_FMRI_HC_ROOT, "");
	err |= nvlist_add_uint32(f, FM_FMRI_HC_LIST_SZ, depth);
	if (err != 0) {
		failure = "basic construction of FMRI failed";
		goto boom;
	}

	numbuf[MAXDIGITIDX] = '\0';
	nullbyte = &numbuf[MAXDIGITIDX];
	i = 0;

	for (nc = n; nc != NULL; nc = nc->u.name.next) {
		err = nvlist_xalloc(&p, NV_UNIQUE_NAME, &Eft_nv_hdl);
		if (err != 0) {
			failure = "alloc of an hc-pair failed";
			goto boom;
		}
		err = nvlist_add_string(p, FM_FMRI_HC_NAME, nc->u.name.s);
		numstr = ulltostr(nc->u.name.child->u.ull, nullbyte);
		err |= nvlist_add_string(p, FM_FMRI_HC_ID, numstr);
		if (err != 0) {
			failure = "construction of an hc-pair failed";
			goto boom;
		}
		pa[i++] = p;
	}

	err = nvlist_add_nvlist_array(f, FM_FMRI_HC_LIST, pa, depth);
	if (err == 0) {
		for (i = 0; i < depth; i++)
			if (pa[i] != NULL)
				nvlist_free(pa[i]);
		return (f);
	}
	failure = "addition of hc-pair array to FMRI failed";

boom:
	for (i = 0; i < depth; i++)
		if (pa[i] != NULL)
			nvlist_free(pa[i]);
	nvlist_free(f);
	out(O_DIE, "%s", failure);
	/*NOTREACHED*/
}

static uint_t
avg(uint_t sum, uint_t cnt)
{
	unsigned long long s = sum * 10;

	return ((s / cnt / 10) + (((s / cnt % 10) >= 5) ? 1 : 0));
}

static uint8_t
percentof(uint_t part, uint_t whole)
{
	unsigned long long p = part * 1000;

	return ((p / whole / 10) + (((p / whole % 10) >= 5) ? 1 : 0));
}

static struct rsl {
	struct event *suspect;
	nvlist_t *asru;
	nvlist_t *fru;
	nvlist_t *rsrc;
};

/*
 *  rslfree -- free internal members of struct rsl not expected to be
 *	freed elsewhere.
 */
static void
rslfree(struct rsl *freeme)
{
	if (freeme->asru != NULL)
		nvlist_free(freeme->asru);
	if (freeme->fru != NULL)
		nvlist_free(freeme->fru);
	if (freeme->rsrc != NULL && freeme->rsrc != freeme->asru)
		nvlist_free(freeme->rsrc);
}

/*
 *  rslcmp -- compare two rsl structures.  Use the following
 *	comparisons to establish cardinality:
 *
 *	1. Name of the suspect's class. (simple strcmp)
 *	2. Name of the suspect's ASRU. (trickier, since nvlist)
 *
 */
static int
rslcmp(const void *a, const void *b)
{
	struct rsl *r1 = (struct rsl *)a;
	struct rsl *r2 = (struct rsl *)b;
	int rv;

	rv = strcmp(r1->suspect->enode->u.event.ename->u.name.s,
	    r2->suspect->enode->u.event.ename->u.name.s);
	if (rv != 0)
		return (rv);

	if (r1->asru == NULL && r2->asru == NULL)
		return (0);
	if (r1->asru == NULL)
		return (-1);
	if (r2->asru == NULL)
		return (1);
	return (evnv_cmpnvl(r1->asru, r2->asru, 0));
}

/*
 *  rsluniq -- given an array of rsl structures, seek out and "remove"
 *	any duplicates.  Dups are "remove"d by NULLing the suspect pointer
 *	of the array element.  Removal also means updating the number of
 *	problems and the number of problems which are not faults.  User
 *	provides the first and last element pointers.
 */
static void
rsluniq(struct rsl *first, struct rsl *last, int *nprobs, int *nnonf)
{
	struct rsl *cr;

	if (*nprobs == 1)
		return;

	/*
	 *  At this point, we only expect duplicate defects.
	 *  Eversholt's diagnosis algorithm prevents duplicate
	 *  suspects, but we rewrite defects in the platform code after
	 *  the diagnosis is made, and that can introduce new
	 *  duplicates.
	 */
	while (first <= last) {
		if (first->suspect == NULL || !is_defect(first->suspect->t)) {
			first++;
			continue;
		}
		cr = first + 1;
		while (cr <= last) {
			if (is_defect(first->suspect->t)) {
				if (rslcmp(first, cr) == 0) {
					cr->suspect = NULL;
					rslfree(cr);
					(*nprobs)--;
					(*nnonf)--;
				}
			}
			/*
			 * assume all defects are in order after our
			 * sort and short circuit here with "else break" ?
			 */
			cr++;
		}
		first++;
	}
}

/*
 * get_resources -- for a given suspect, determine what ASRU, FRU and
 *     RSRC nvlists should be advertised in the final suspect list.
 */
void
get_resources(struct event *sp, struct rsl *rsrcs, struct config *croot)
{
	struct node *asrudef, *frudef;
	nvlist_t *asru, *fru;
	nvlist_t *rsrc = NULL;
	char *pathstr;

	/*
	 * First find any ASRU and/or FRU defined in the
	 * initial fault tree.
	 */
	asrudef = eventprop_lookup(sp, L_ASRU);
	frudef = eventprop_lookup(sp, L_FRU);

	/*
	 * Create FMRIs based on those definitions
	 */
	asru = node2fmri(asrudef);
	fru = node2fmri(frudef);
	pathstr = ipath2str(NULL, sp->ipp);

	/*
	 * Allow for platform translations of the FMRIs
	 */
	platform_units_translate(is_defect(sp->t), croot, &asru, &fru, &rsrc,
	    pathstr);

	FREE(pathstr);
	rsrcs->suspect = sp;
	rsrcs->asru = asru;
	rsrcs->fru = fru;
	rsrcs->rsrc = rsrc;
}

/*
 * trim_suspects -- prior to publishing, we may need to remove some
 *    suspects from the list.  If we're auto-closing upsets, we don't
 *    want any of those in the published list.  If the ASRUs for multiple
 *    defects resolve to the same ASRU (driver) we only want to publish
 *    that as a single suspect.
 */
static void
trim_suspects(struct fme *fmep, boolean_t no_upsets, struct rsl **begin,
    struct rsl **end)
{
	struct event *ep;
	struct rsl *rp;
	int rpcnt;

	/*
	 * First save the suspects in the psuspects, then copy back
	 * only the ones we wish to retain.  This resets nsuspects to
	 * zero.
	 */
	rpcnt = fmep->nsuspects;
	save_suspects(fmep);

	/*
	 * allocate an array of resource pointers for the suspects.
	 * We may end up using less than the full allocation, but this
	 * is a very short-lived array.  publish_suspects() will free
	 * this array when it's done using it.
	 */
	rp = *begin = MALLOC(rpcnt * sizeof (struct rsl));
	bzero(rp, rpcnt * sizeof (struct rsl));

	/* first pass, remove any unwanted upsets and populate our array */
	for (ep = fmep->psuspects; ep; ep = ep->psuspects) {
		if (no_upsets && is_upset(ep->t))
			continue;
		get_resources(ep, rp, fmep->cfgdata->cooked);
		rp++;
		fmep->nsuspects++;
		if (!is_fault(ep->t))
			fmep->nonfault++;
	}

	/* if all we had was unwanted upsets, we're done */
	if (fmep->nsuspects == 0)
		return;

	*end = rp - 1;

	/* sort the array */
	qsort(*begin, fmep->nsuspects, sizeof (struct rsl), rslcmp);
	rsluniq(*begin, *end, &fmep->nsuspects, &fmep->nonfault);
}

static void
publish_suspects(struct fme *fmep)
{
	struct event *ep;
	struct rsl *srl = NULL;
	struct rsl *erl;
	struct rsl *rp;
	nvlist_t *fault;
	uint8_t cert;
	uint_t *frs;
	uint_t fravg, frsum, fr;
	int frcnt, fridx;
	boolean_t no_upsets = B_FALSE;

	stats_counter_bump(fmep->diags);

	/*
	 * The current fmd interfaces don't allow us to solve a case
	 * that's already solved.  If we make a new case, what of the
	 * ereports?  We don't appear to have an interface that allows
	 * us to access the ereports attached to a case (if we wanted
	 * to copy the original case's ereport attachments to the new
	 * case) and it's also a bit unclear if there would be any
	 * problems with having ereports attached to multiple cases
	 * and/or attaching DIAGNOSED ereports to a case.  For now,
	 * we'll just output a message.
	 */
	if (fmep->posted_suspects ||
	    fmd_case_solved(fmep->hdl, fmep->fmcase)) {
		out(O_ALTFP|O_NONL, "Revised diagnosis for case %s: ",
		    fmd_case_uuid(fmep->hdl, fmep->fmcase));
		for (ep = fmep->suspects; ep; ep = ep->suspects) {
			out(O_ALTFP|O_NONL, " ");
			itree_pevent_brief(O_ALTFP|O_NONL, ep);
		}
		out(O_ALTFP, NULL);
		return;
	}

	/*
	 * If we're auto-closing upsets, we don't want to include them
	 * in any produced suspect lists or certainty accounting.
	 */
	if (Autoclose != NULL)
		if (strcmp(Autoclose, "true") == 0 ||
		    strcmp(Autoclose, "all") == 0 ||
		    strcmp(Autoclose, "upsets") == 0)
			no_upsets = B_TRUE;

	trim_suspects(fmep, no_upsets, &srl, &erl);

	/*
	 * If the resulting suspect list has no members, we're
	 * done.  Returning here will simply close the case.
	 */
	if (fmep->nsuspects == 0) {
		out(O_ALTFP,
		    "[FME%d, case %s (all suspects are upsets)]",
		    fmep->id, fmd_case_uuid(fmep->hdl, fmep->fmcase));
		FREE(srl);
		restore_suspects(fmep);
		return;
	}

	/*
	 * If the suspect list is all faults, then for a given fault,
	 * say X of N, X's certainty is computed via:
	 *
	 * fitrate(X) / (fitrate(1) + ... + fitrate(N)) * 100
	 *
	 * If none of the suspects are faults, and there are N suspects,
	 * the certainty of a given suspect is 100/N.
	 *
	 * If there are are a mixture of faults and other problems in
	 * the suspect list, we take an average of the faults'
	 * FITrates and treat this average as the FITrate for any
	 * non-faults.  The fitrate of any given suspect is then
	 * computed per the first formula above.
	 */
	if (fmep->nonfault == fmep->nsuspects) {
		/* NO faults in the suspect list */
		cert = percentof(1, fmep->nsuspects);
	} else {
		/* sum the fitrates */
		frs = alloca(fmep->nsuspects * sizeof (uint_t));
		fridx = frcnt = frsum = 0;

		for (rp = srl; rp <= erl; rp++) {
			struct node *n;

			if (rp->suspect == NULL)
				continue;
			if (!is_fault(rp->suspect->t)) {
				frs[fridx++] = 0;
				continue;
			}
			n = eventprop_lookup(rp->suspect, L_FITrate);
			if (node2uint(n, &fr) != 0) {
				out(O_DEBUG|O_NONL, "event ");
				ipath_print(O_DEBUG|O_NONL,
				    ep->enode->u.event.ename->u.name.s,
				    ep->ipp);
				out(O_DEBUG, " has no FITrate (using 1)");
				fr = 1;
			} else if (fr == 0) {
				out(O_DEBUG|O_NONL, "event ");
				ipath_print(O_DEBUG|O_NONL,
				    ep->enode->u.event.ename->u.name.s,
				    ep->ipp);
				out(O_DEBUG, " has zero FITrate (using 1)");
				fr = 1;
			}

			frs[fridx++] = fr;
			frsum += fr;
			frcnt++;
		}
		fravg = avg(frsum, frcnt);
		for (fridx = 0; fridx < fmep->nsuspects; fridx++)
			if (frs[fridx] == 0) {
				frs[fridx] = fravg;
				frsum += fravg;
			}
	}

	/* Add them in reverse order of our sort, as fmd reverses order */
	for (rp = erl; rp >= srl; rp--) {
		if (rp->suspect == NULL)
			continue;
		if (fmep->nonfault != fmep->nsuspects)
			cert = percentof(frs[--fridx], frsum);
		fault = fmd_nvl_create_fault(fmep->hdl,
		    rp->suspect->enode->u.event.ename->u.name.s,
		    cert,
		    rp->asru,
		    rp->fru,
		    rp->rsrc);
		if (fault == NULL)
			out(O_DIE, "fault creation failed");
		fmd_case_add_suspect(fmep->hdl, fmep->fmcase, fault);
		rp->suspect->fault = fault;
		rslfree(rp);
	}
	fmd_case_solve(fmep->hdl, fmep->fmcase);
	out(O_ALTFP, "[solving FME%d, case %s]", fmep->id,
	    fmd_case_uuid(fmep->hdl, fmep->fmcase));

	if (Autoconvict) {
		for (rp = srl; rp <= erl; rp++) {
			if (rp->suspect == NULL)
				continue;
			fmd_case_convict(fmep->hdl,
			    fmep->fmcase, rp->suspect->fault);
		}
		out(O_ALTFP, "[convicting FME%d, case %s]", fmep->id,
		    fmd_case_uuid(fmep->hdl, fmep->fmcase));
	}

	/*
	 * revert to the original suspect list
	 */
	FREE(srl);
	restore_suspects(fmep);
}

static void
publish_undiagnosable(fmd_hdl_t *hdl, fmd_event_t *ffep)
{
	struct case_list *newcase;
	nvlist_t *defect;

	out(O_ALTFP,
	    "[undiagnosable ereport received, "
	    "creating and closing a new case (%s)]",
	    Undiag_reason ? Undiag_reason : "reason not provided");

	newcase = MALLOC(sizeof (struct case_list));
	newcase->next = NULL;

	newcase->fmcase = fmd_case_open(hdl, NULL);
	if (Undiagablecaselist != NULL)
		newcase->next = Undiagablecaselist;
	Undiagablecaselist = newcase;

	if (ffep != NULL)
		fmd_case_add_ereport(hdl, newcase->fmcase, ffep);

	defect = fmd_nvl_create_fault(hdl, UNDIAGNOSABLE_DEFECT, 100,
	    NULL, NULL, NULL);
	if (Undiag_reason != NULL)
		(void) nvlist_add_string(defect, UNDIAG_REASON, Undiag_reason);
	fmd_case_add_suspect(hdl, newcase->fmcase, defect);

	fmd_case_solve(hdl, newcase->fmcase);
	fmd_case_close(hdl, newcase->fmcase);
}

static void
fme_undiagnosable(struct fme *f)
{
	nvlist_t *defect;

	out(O_ALTFP, "[solving/closing FME%d, case %s (%s)]",
	    f->id, fmd_case_uuid(f->hdl, f->fmcase),
	    Undiag_reason ? Undiag_reason : "undiagnosable");

	defect = fmd_nvl_create_fault(f->hdl, UNDIAGNOSABLE_DEFECT, 100,
	    NULL, NULL, NULL);
	if (Undiag_reason != NULL)
		(void) nvlist_add_string(defect, UNDIAG_REASON, Undiag_reason);
	fmd_case_add_suspect(f->hdl, f->fmcase, defect);
	fmd_case_solve(f->hdl, f->fmcase);
	destroy_fme_bufs(f);
	fmd_case_close(f->hdl, f->fmcase);
}

/*
 * fme_close_case
 *
 *	Find the requested case amongst our fmes and close it.  Free up
 *	the related fme.
 */
void
fme_close_case(fmd_hdl_t *hdl, fmd_case_t *fmcase)
{
	struct case_list *ucasep, *prevcasep = NULL;
	struct fme *prev = NULL;
	struct fme *fmep;

	for (ucasep = Undiagablecaselist; ucasep; ucasep = ucasep->next) {
		if (fmcase != ucasep->fmcase) {
			prevcasep = ucasep;
			continue;
		}

		if (prevcasep == NULL)
			Undiagablecaselist = Undiagablecaselist->next;
		else
			prevcasep->next = ucasep->next;

		FREE(ucasep);
		return;
	}

	for (fmep = FMElist; fmep; fmep = fmep->next) {
		if (fmep->hdl == hdl && fmep->fmcase == fmcase)
			break;
		prev = fmep;
	}

	if (fmep == NULL) {
		out(O_WARN, "Eft asked to close unrecognized case [%s].",
		    fmd_case_uuid(hdl, fmcase));
		return;
	}

	if (EFMElist == fmep)
		EFMElist = prev;

	if (prev == NULL)
		FMElist = FMElist->next;
	else
		prev->next = fmep->next;

	fmep->next = NULL;

	/* Get rid of any timer this fme has set */
	if (fmep->wull != 0)
		fmd_timer_remove(fmep->hdl, fmep->timer);

	if (ClosedFMEs == NULL) {
		ClosedFMEs = fmep;
	} else {
		fmep->next = ClosedFMEs;
		ClosedFMEs = fmep;
	}
}

/*
 * fme_set_timer()
 *	If the time we need to wait for the given FME is less than the
 *	current timer, kick that old timer out and establish a new one.
 */
static void
fme_set_timer(struct fme *fmep, unsigned long long wull)
{
	out(O_ALTFP|O_VERB|O_NONL, " fme_set_timer: request to wait ");
	ptree_timeval(O_ALTFP|O_VERB, &wull);

	if (wull <= fmep->pull) {
		out(O_ALTFP|O_VERB|O_NONL, "already have waited at least ");
		ptree_timeval(O_ALTFP|O_VERB, &fmep->pull);
		out(O_ALTFP|O_VERB, NULL);
		/* we've waited at least wull already, don't need timer */
		return;
	}

	out(O_ALTFP|O_VERB|O_NONL, " currently ");
	if (fmep->wull != 0) {
		out(O_ALTFP|O_VERB|O_NONL, "waiting ");
		ptree_timeval(O_ALTFP|O_VERB, &fmep->wull);
		out(O_ALTFP|O_VERB, NULL);
	} else {
		out(O_ALTFP|O_VERB|O_NONL, "not waiting");
		out(O_ALTFP|O_VERB, NULL);
	}

	if (fmep->wull != 0)
		if (wull >= fmep->wull)
			/* New timer would fire later than established timer */
			return;

	if (fmep->wull != 0)
		fmd_timer_remove(fmep->hdl, fmep->timer);

	fmep->timer = fmd_timer_install(fmep->hdl, (void *)fmep,
	    fmep->e0r, wull);
	out(O_ALTFP|O_VERB, "timer set, id is %ld", fmep->timer);
	fmep->wull = wull;
}

void
fme_timer_fired(struct fme *fmep, id_t tid)
{
	struct fme *ffmep = NULL;

	for (ffmep = FMElist; ffmep; ffmep = ffmep->next)
		if (ffmep == fmep)
			break;

	if (ffmep == NULL) {
		out(O_WARN, "Timer fired for an FME (%p) not in FMEs list.",
		    (void *)fmep);
		return;
	}

	if (tid != fmep->htid) {
		/*
		 * normal timer (not the hesitation timer
		 */
		fmep->pull = fmep->wull;
		fmep->wull = 0;
		fmd_buf_write(fmep->hdl, fmep->fmcase,
		    WOBUF_PULL, (void *)&fmep->pull, sizeof (fmep->pull));
	} else {
		fmep->hesitated = 1;
	}
	fme_eval(fmep, NULL);
}

/*
 * Preserve the fme's suspect list in its psuspects list, NULLing the
 * suspects list in the meantime.
 */
static void
save_suspects(struct fme *fmep)
{
	struct event *ep;
	struct event *nextep;

	/* zero out the previous suspect list */
	for (ep = fmep->psuspects; ep; ep = nextep) {
		nextep = ep->psuspects;
		ep->psuspects = NULL;
	}
	fmep->psuspects = NULL;

	/* zero out the suspect list, copying it to previous suspect list */
	fmep->psuspects = fmep->suspects;
	for (ep = fmep->suspects; ep; ep = nextep) {
		nextep = ep->suspects;
		ep->psuspects = ep->suspects;
		ep->suspects = NULL;
		ep->is_suspect = 0;
	}
	fmep->suspects = NULL;
	fmep->nsuspects = 0;
	fmep->nonfault = 0;
}

/*
 * Retrieve the fme's suspect list from its psuspects list.
 */
static void
restore_suspects(struct fme *fmep)
{
	struct event *ep;
	struct event *nextep;

	fmep->nsuspects = fmep->nonfault = 0;
	fmep->suspects = fmep->psuspects;
	for (ep = fmep->psuspects; ep; ep = nextep) {
		fmep->nsuspects++;
		if (!is_fault(ep->t))
			fmep->nonfault++;
		nextep = ep->psuspects;
		ep->suspects = ep->psuspects;
	}
}

/*
 * this is what we use to call the Emrys prototype code instead of main()
 */
static void
fme_eval(struct fme *fmep, fmd_event_t *ffep)
{
	struct event *ep;
	unsigned long long my_delay = TIMEVAL_EVENTUALLY;

	save_suspects(fmep);

	out(O_ALTFP|O_VERB, "Evaluate FME %d", fmep->id);
	indent_set("  ");

	initialize_cycles(fmep);
	fmep->state = hypothesise(fmep, fmep->e0, fmep->ull, &my_delay, NULL);

	out(O_ALTFP|O_VERB|O_NONL, "FME%d state: %s, suspect list:", fmep->id,
	    fme_state2str(fmep->state));
	for (ep = fmep->suspects; ep; ep = ep->suspects) {
		out(O_ALTFP|O_VERB|O_NONL, " ");
		itree_pevent_brief(O_ALTFP|O_VERB|O_NONL, ep);
	}
	out(O_ALTFP|O_VERB, NULL);

	if (fmep->posted_suspects) {
		/*
		 * this FME has already posted a diagnosis, so see if
		 * the event changed the diagnosis and print a warning
		 * if it did.
		 *
		 */
		if (suspects_changed(fmep)) {
			print_suspects(SLCHANGED, fmep);
			publish_suspects(fmep);
		}
	} else {
		switch (fmep->state) {
		case FME_CREDIBLE:
			/*
			 * if the suspect list contains any upsets, we
			 * turn off the hesitation logic (by setting
			 * the hesitate flag which normally indicates
			 * we've already done the hesitate logic).
			 * this is done because hesitating with upsets
			 * causes us to explain away additional soft errors
			 * while the upset FME stays open.
			 */
			if (fmep->hesitated == 0) {
				struct event *s;

				for (s = fmep->suspects; s; s = s->suspects) {
					if (s->t == N_UPSET) {
						fmep->hesitated = 1;
						break;
					}
				}
			}

			if (Hesitate &&
			    fmep->suspects != NULL &&
			    fmep->suspects->suspects != NULL &&
			    fmep->hesitated == 0) {
				/*
				 * about to publish multi-entry suspect list,
				 * set the hesitation timer if not already set.
				 */
				if (fmep->htid == 0) {
					out(O_ALTFP|O_NONL,
					    "[hesitate FME%d, case %s ",
					    fmep->id,
					    fmd_case_uuid(fmep->hdl,
					    fmep->fmcase));
					ptree_timeval(O_ALTFP|O_NONL,
					    (unsigned long long *)&Hesitate);
					out(O_ALTFP, "]");
					fme_set_timer(fmep, my_delay);
					fmep->htid =
					    fmd_timer_install(fmep->hdl,
					    (void *)fmep, NULL, Hesitate);
				} else {
					out(O_ALTFP,
					    "[still hesitating FME%d, case %s]",
					    fmep->id,
					    fmd_case_uuid(fmep->hdl,
					    fmep->fmcase));
				}
			} else {
				print_suspects(SLNEW, fmep);
				(void) upsets_eval(fmep, ffep);
				publish_suspects(fmep);
				fmep->posted_suspects = 1;
				fmd_buf_write(fmep->hdl, fmep->fmcase,
				    WOBUF_POSTD,
				    (void *)&fmep->posted_suspects,
				    sizeof (fmep->posted_suspects));
			}
			break;

		case FME_WAIT:
			/*
			 * singleton suspect list implies
			 * no point in waiting
			 */
			if (fmep->suspects &&
			    fmep->suspects->suspects == NULL) {
				print_suspects(SLNEW, fmep);
				(void) upsets_eval(fmep, ffep);
				publish_suspects(fmep);
				fmep->posted_suspects = 1;
				fmd_buf_write(fmep->hdl, fmep->fmcase,
				    WOBUF_POSTD,
				    (void *)&fmep->posted_suspects,
				    sizeof (fmep->posted_suspects));
				fmep->state = FME_CREDIBLE;
			} else {
				ASSERT(my_delay > fmep->ull);
				fme_set_timer(fmep, my_delay);
				print_suspects(SLWAIT, fmep);
			}
			break;

		case FME_DISPROVED:
			print_suspects(SLDISPROVED, fmep);
			Undiag_reason = UD_UNSOLVD;
			fme_undiagnosable(fmep);
			break;
		}
	}

	if (fmep->posted_suspects == 1 && Autoclose != NULL) {
		int doclose = 0;

		if (strcmp(Autoclose, "true") == 0 ||
		    strcmp(Autoclose, "all") == 0)
			doclose = 1;

		if (strcmp(Autoclose, "upsets") == 0) {
			doclose = 1;
			for (ep = fmep->suspects; ep; ep = ep->suspects) {
				if (ep->t != N_UPSET) {
					doclose = 0;
					break;
				}
			}
		}

		if (doclose) {
			out(O_ALTFP, "[closing FME%d, case %s (autoclose)]",
			    fmep->id, fmd_case_uuid(fmep->hdl, fmep->fmcase));

			destroy_fme_bufs(fmep);
			fmd_case_close(fmep->hdl, fmep->fmcase);
		}
	}
}

/*
 * below here is the code derived from the Emrys prototype
 */

static void indent(void);
static int triggered(struct fme *fmep, struct event *ep, int mark);
static void mark_arrows(struct fme *fmep, struct event *ep, int mark);
static enum fme_state effects_test(struct fme *fmep,
    struct event *fault_event);
static enum fme_state requirements_test(struct fme *fmep, struct event *ep,
    unsigned long long at_latest_by, unsigned long long *pdelay,
    struct arrow *arrowp);
static enum fme_state causes_test(struct fme *fmep, struct event *ep,
    unsigned long long at_latest_by, unsigned long long *pdelay);

static int
triggered(struct fme *fmep, struct event *ep, int mark)
{
	struct bubble *bp;
	struct arrowlist *ap;
	int count = 0;

	stats_counter_bump(fmep->Tcallcount);
	for (bp = itree_next_bubble(ep, NULL); bp;
	    bp = itree_next_bubble(ep, bp)) {
		if (bp->t != B_TO)
			continue;
		for (ap = itree_next_arrow(bp, NULL); ap;
		    ap = itree_next_arrow(bp, ap)) {
			/* check count of marks against K in the bubble */
			if (ap->arrowp->tail->mark == mark &&
			    ++count >= bp->nork)
				return (1);
		}
	}
	return (0);
}

static void
mark_arrows(struct fme *fmep, struct event *ep, int mark)
{
	struct bubble *bp;
	struct arrowlist *ap;

	for (bp = itree_next_bubble(ep, NULL); bp;
	    bp = itree_next_bubble(ep, bp)) {
		if (bp->t != B_FROM)
			continue;
		if (bp->mark != mark) {
			stats_counter_bump(fmep->Marrowcount);
			bp->mark = mark;
			for (ap = itree_next_arrow(bp, NULL); ap;
			    ap = itree_next_arrow(bp, ap)) {
				struct constraintlist *ctp;
				struct evalue value;
				int do_not_follow = 0;
				/*
				 * see if false constraint prevents us
				 * from traversing this arrow, but don't
				 * bother if the event is an ereport we
				 * haven't seen
				 */
				if (ap->arrowp->head->myevent->t != N_EREPORT ||
				    ap->arrowp->head->myevent->count != 0) {
					platform_set_payloadnvp(
					    ap->arrowp->head->myevent->nvp);
					for (ctp = ap->arrowp->constraints;
					    ctp != NULL; ctp = ctp->next) {
						if (eval_expr(ctp->cnode,
						    NULL, NULL,
						    &fmep->globals,
						    fmep->cfgdata->cooked,
						    ap->arrowp, 0,
						    &value) == 0 ||
						    value.t == UNDEFINED ||
						    value.v == 0) {
							do_not_follow = 1;
							break;
						}
					}
					platform_set_payloadnvp(NULL);
				}

				if (do_not_follow) {
					indent();
					out(O_ALTFP|O_VERB|O_NONL,
					    "  False arrow to ");
					itree_pevent_brief(
					    O_ALTFP|O_VERB|O_NONL,
					    ap->arrowp->head->myevent);
					out(O_ALTFP|O_VERB|O_NONL, " ");
					ptree(O_ALTFP|O_VERB|O_NONL,
					    ctp->cnode, 1, 0);
					out(O_ALTFP|O_VERB, NULL);
					continue;
				}

				if (triggered(fmep, ap->arrowp->head->myevent,
				    mark))
					mark_arrows(fmep,
					    ap->arrowp->head->myevent, mark);
			}
		}
	}
}

static enum fme_state
effects_test(struct fme *fmep, struct event *fault_event)
{
	struct event *error_event;
	enum fme_state return_value = FME_CREDIBLE;

	stats_counter_bump(fmep->Ecallcount);
	indent_push("  E");
	indent();
	out(O_ALTFP|O_VERB|O_NONL, "->");
	itree_pevent_brief(O_ALTFP|O_VERB|O_NONL, fault_event);
	out(O_ALTFP|O_VERB, NULL);

	mark_arrows(fmep, fault_event, 1);
	for (error_event = fmep->observations;
	    error_event; error_event = error_event->observations) {
		indent();
		out(O_ALTFP|O_VERB|O_NONL, " ");
		itree_pevent_brief(O_ALTFP|O_VERB|O_NONL, error_event);
		if (!triggered(fmep, error_event, 1)) {
			return_value = FME_DISPROVED;
			out(O_ALTFP|O_VERB, " NOT triggered");
			break;
		} else {
			out(O_ALTFP|O_VERB, " triggered");
		}
	}
	mark_arrows(fmep, fault_event, 0);

	indent();
	out(O_ALTFP|O_VERB|O_NONL, "<-%s ", fme_state2str(return_value));
	itree_pevent_brief(O_ALTFP|O_VERB|O_NONL, fault_event);
	out(O_ALTFP|O_VERB, NULL);
	indent_pop();
	return (return_value);
}

static enum fme_state
requirements_test(struct fme *fmep, struct event *ep,
    unsigned long long at_latest_by, unsigned long long *pdelay,
    struct arrow *arrowp)
{
	int waiting_events;
	int credible_events;
	enum fme_state return_value = FME_CREDIBLE;
	unsigned long long overall_delay = TIMEVAL_EVENTUALLY;
	unsigned long long arrow_delay;
	unsigned long long my_delay;
	struct event *ep2;
	struct bubble *bp;
	struct arrowlist *ap;

	stats_counter_bump(fmep->Rcallcount);
	indent_push("  R");
	indent();
	out(O_ALTFP|O_VERB|O_NONL, "->");
	itree_pevent_brief(O_ALTFP|O_VERB|O_NONL, ep);
	out(O_ALTFP|O_VERB|O_NONL, ", at latest by: ");
	ptree_timeval(O_ALTFP|O_VERB|O_NONL, &at_latest_by);
	out(O_ALTFP|O_VERB, NULL);

	if (ep->t == N_EREPORT) {
		if (ep->count == 0) {
			if (fmep->pull >= at_latest_by) {
				return_value = FME_DISPROVED;
			} else {
				*pdelay = at_latest_by;
				return_value = FME_WAIT;
			}
		} else if (arrowp != NULL) {
			/*
			 * evaluate constraints only for current observation
			 */
			struct constraintlist *ctp;
			struct evalue value;

			platform_set_payloadnvp(ep->nvp);
			for (ctp = arrowp->constraints; ctp != NULL;
				ctp = ctp->next) {
				if (eval_expr(ctp->cnode, NULL, NULL,
				    &fmep->globals, fmep->cfgdata->cooked,
				    arrowp, 0, &value) == 0 ||
				    value.t == UNDEFINED || value.v == 0) {
					indent();
					out(O_ALTFP|O_VERB|O_NONL,
					    "  False constraint ");
					out(O_ALTFP|O_VERB|O_NONL, " ");
					ptree(O_ALTFP|O_VERB|O_NONL,
					    ctp->cnode, 1, 0);
					out(O_ALTFP|O_VERB, NULL);
					return_value = FME_DISPROVED;
					break;
				}
			}
			platform_set_payloadnvp(NULL);
		}

		indent();
		switch (return_value) {
		case FME_CREDIBLE:
			out(O_ALTFP|O_VERB|O_NONL, "<-CREDIBLE ");
			itree_pevent_brief(O_ALTFP|O_VERB|O_NONL, ep);
			break;
		case FME_DISPROVED:
			out(O_ALTFP|O_VERB|O_NONL, "<-DISPROVED ");
			itree_pevent_brief(O_ALTFP|O_VERB|O_NONL, ep);
			break;
		case FME_WAIT:
			out(O_ALTFP|O_VERB|O_NONL, "<-WAIT ");
			itree_pevent_brief(O_ALTFP|O_VERB|O_NONL, ep);
			out(O_ALTFP|O_VERB|O_NONL, " to ");
			ptree_timeval(O_ALTFP|O_VERB|O_NONL, &at_latest_by);
			break;
		default:
			out(O_DIE, "requirements_test: unexpected fme_state");
			break;
		}
		out(O_ALTFP|O_VERB, NULL);
		indent_pop();

		return (return_value);
	}

	/* this event is not a report, descend the tree */
	for (bp = itree_next_bubble(ep, NULL); bp;
	    bp = itree_next_bubble(ep, bp)) {
		if (bp->t != B_FROM)
			continue;
		if (bp->mark == 0) {
			int n = bp->nork;

			bp->mark = 1;
			credible_events = 0;
			waiting_events = 0;
			arrow_delay = TIMEVAL_EVENTUALLY;
			/*
			 * n is -1 for 'A' so adjust it.
			 * XXX just count up the arrows for now.
			 */
			if (n < 0) {
				n = 0;
				for (ap = itree_next_arrow(bp, NULL); ap;
				    ap = itree_next_arrow(bp, ap))
					n++;
				indent();
				out(O_ALTFP|O_VERB, " Bubble Counted N=%d", n);
			} else {
				indent();
				out(O_ALTFP|O_VERB, " Bubble N=%d", n);
			}

			for (ap = itree_next_arrow(bp, NULL); ap;
			    ap = itree_next_arrow(bp, ap)) {
				ep2 = ap->arrowp->head->myevent;
				if (n <= credible_events)
					break;

				if (triggered(fmep, ep2, 1))
					/* XXX adding max timevals! */
					switch (requirements_test(fmep, ep2,
					    at_latest_by + ap->arrowp->maxdelay,
					    &my_delay, ap->arrowp)) {
					case FME_CREDIBLE:
						credible_events++;
						break;
					case FME_DISPROVED:
						break;
					case FME_WAIT:
						if (my_delay < arrow_delay)
							arrow_delay = my_delay;
						waiting_events++;
						break;
					default:
						out(O_DIE,
						"Bug in requirements_test.");
					}
				else
					credible_events++;
			}
			indent();
			out(O_ALTFP|O_VERB, " Credible: %d Waiting %d",
			    credible_events, waiting_events);
			if (credible_events + waiting_events < n) {
				/* Can never meet requirements */
				indent();
				out(O_ALTFP|O_VERB|O_NONL, "<-DISPROVED ");
				itree_pevent_brief(O_ALTFP|O_VERB|O_NONL, ep);
				out(O_ALTFP|O_VERB, NULL);
				indent_pop();
				return (FME_DISPROVED);
			}
			if (credible_events < n) { /* will have to wait */
				/* wait time is shortest known */
				if (arrow_delay < overall_delay)
					overall_delay = arrow_delay;
				return_value = FME_WAIT;
			}
		} else {
			indent();
			out(O_ALTFP|O_VERB|O_NONL, " Mark was set: ");
			itree_pevent_brief(O_ALTFP|O_VERB|O_NONL, ep);
			out(O_ALTFP|O_VERB|O_NONL, " to");
			for (ap = itree_next_arrow(bp, NULL); ap;
			    ap = itree_next_arrow(bp, ap)) {
				out(O_ALTFP|O_VERB|O_NONL, " ");
				itree_pevent_brief(O_ALTFP|O_VERB|O_NONL,
				    ap->arrowp->head->myevent);
			}
			out(O_ALTFP|O_VERB, NULL);
		}
	}

	/*
	 * evaluate constraints for ctlist, which is the list of
	 * constraints for the arrow pointing into this node of the tree
	 */
	if (return_value == FME_CREDIBLE && arrowp != NULL) {
		struct constraintlist *ctp;
		struct evalue value;

		platform_set_payloadnvp(ep->nvp);
		for (ctp = arrowp->constraints; ctp != NULL;
			ctp = ctp->next) {
			if (eval_expr(ctp->cnode, NULL,	NULL, &fmep->globals,
			    fmep->cfgdata->cooked, arrowp, 0, &value) == 0 ||
			    value.t == UNDEFINED || value.v == 0) {
				indent();
				out(O_ALTFP|O_VERB|O_NONL,
				    "  False constraint ");
				out(O_ALTFP|O_VERB|O_NONL, " ");
				ptree(O_ALTFP|O_VERB|O_NONL,
				    ctp->cnode, 1, 0);
				out(O_ALTFP|O_VERB, NULL);
				return_value = FME_DISPROVED;
				break;
			}
		}
		platform_set_payloadnvp(NULL);
	}

	if (return_value == FME_WAIT)
		*pdelay = overall_delay;
	indent();
	out(O_ALTFP|O_VERB|O_NONL, "<-%s ", fme_state2str(return_value));
	itree_pevent_brief(O_ALTFP|O_VERB|O_NONL, ep);
	out(O_ALTFP|O_VERB, NULL);
	indent_pop();
	return (return_value);
}

static enum fme_state
causes_test(struct fme *fmep, struct event *ep,
    unsigned long long at_latest_by, unsigned long long *pdelay)
{
	unsigned long long overall_delay = TIMEVAL_EVENTUALLY;
	unsigned long long my_delay;
	int credible_results = 0;
	int waiting_results = 0;
	enum fme_state fstate;
	struct event *tail_event;
	struct bubble *bp;
	struct arrowlist *ap;
	int k = 1;

	stats_counter_bump(fmep->Ccallcount);
	indent_push("  C");
	indent();
	out(O_ALTFP|O_VERB|O_NONL, "->");
	itree_pevent_brief(O_ALTFP|O_VERB|O_NONL, ep);
	out(O_ALTFP|O_VERB, NULL);

	for (bp = itree_next_bubble(ep, NULL); bp;
	    bp = itree_next_bubble(ep, bp)) {
		if (bp->t != B_TO)
			continue;
		k = bp->nork;	/* remember the K value */
		for (ap = itree_next_arrow(bp, NULL); ap;
		    ap = itree_next_arrow(bp, ap)) {
			struct constraintlist *ctp;
			struct evalue value;
			int do_not_follow = 0;
			/*
			 * see if false constraint prevents us
			 * from traversing this arrow
			 */
			platform_set_payloadnvp(ep->nvp);
			for (ctp = ap->arrowp->constraints;
			    ctp != NULL; ctp = ctp->next) {
				if (eval_expr(ctp->cnode, NULL, NULL,
				    &fmep->globals,
				    fmep->cfgdata->cooked,
				    ap->arrowp, 0,
				    &value) == 0 ||
				    value.t == UNDEFINED ||
				    value.v == 0) {
					do_not_follow = 1;
					break;
				}
			}
			platform_set_payloadnvp(NULL);
			if (do_not_follow) {
				indent();
				out(O_ALTFP|O_VERB|O_NONL,
				    "  False arrow from ");
				itree_pevent_brief(O_ALTFP|O_VERB|O_NONL,
				    ap->arrowp->tail->myevent);
				out(O_ALTFP|O_VERB|O_NONL, " ");
				ptree(O_ALTFP|O_VERB|O_NONL, ctp->cnode, 1, 0);
				out(O_ALTFP|O_VERB, NULL);
				continue;
			}

			if (ap->arrowp->causes_tested++ > 0) {
				/*
				 * get to this point if this is not the
				 * first time we're going through this
				 * arrow in the causes test.  consider this
				 * branch to be credible and let the
				 * credible/noncredible outcome depend on
				 * the other branches in this cycle.
				 */
				fstate = FME_CREDIBLE;
			} else {
				/*
				 * get to this point if this is the first
				 * time we're going through this arrow.
				 */
				tail_event = ap->arrowp->tail->myevent;
				fstate = hypothesise(fmep, tail_event,
						    at_latest_by,
						    &my_delay, ap->arrowp);
			}

			switch (fstate) {
			case FME_WAIT:
				if (my_delay < overall_delay)
					overall_delay = my_delay;
				waiting_results++;
				break;
			case FME_CREDIBLE:
				credible_results++;
				break;
			case FME_DISPROVED:
				break;
			default:
				out(O_DIE, "Bug in causes_test");
			}

			ap->arrowp->causes_tested--;
			ASSERT(ap->arrowp->causes_tested >= 0);
		}
	}
	/* compare against K */
	if (credible_results + waiting_results < k) {
		indent();
		out(O_ALTFP|O_VERB|O_NONL, "<-DISPROVED ");
		itree_pevent_brief(O_ALTFP|O_VERB|O_NONL, ep);
		out(O_ALTFP|O_VERB, NULL);
		indent_pop();
		return (FME_DISPROVED);
	}
	if (waiting_results != 0) {
		*pdelay = overall_delay;
		indent();
		out(O_ALTFP|O_VERB|O_NONL, "<-WAIT ");
		itree_pevent_brief(O_ALTFP|O_VERB|O_NONL, ep);
		out(O_ALTFP|O_VERB|O_NONL, " to ");
		ptree_timeval(O_ALTFP|O_VERB|O_NONL, &at_latest_by);
		out(O_ALTFP|O_VERB, NULL);
		indent_pop();
		return (FME_WAIT);
	}
	indent();
	out(O_ALTFP|O_VERB|O_NONL, "<-CREDIBLE ");
	itree_pevent_brief(O_ALTFP|O_VERB|O_NONL, ep);
	out(O_ALTFP|O_VERB, NULL);
	indent_pop();
	return (FME_CREDIBLE);
}

static enum fme_state
hypothesise(struct fme *fmep, struct event *ep,
	unsigned long long at_latest_by, unsigned long long *pdelay,
	struct arrow *arrowp)
{
	enum fme_state rtr, otr;
	unsigned long long my_delay;
	unsigned long long overall_delay = TIMEVAL_EVENTUALLY;

	stats_counter_bump(fmep->Hcallcount);
	indent_push("  H");
	indent();
	out(O_ALTFP|O_VERB|O_NONL, "->");
	itree_pevent_brief(O_ALTFP|O_VERB|O_NONL, ep);
	out(O_ALTFP|O_VERB|O_NONL, ", at latest by: ");
	ptree_timeval(O_ALTFP|O_VERB|O_NONL, &at_latest_by);
	out(O_ALTFP|O_VERB, NULL);

	rtr = requirements_test(fmep, ep, at_latest_by, &my_delay, arrowp);
	mark_arrows(fmep, ep, 0); /* clean up after requirements test */
	if ((rtr == FME_WAIT) && (my_delay < overall_delay))
		overall_delay = my_delay;
	if (rtr != FME_DISPROVED) {
		if (is_problem(ep->t)) {
			otr = effects_test(fmep, ep);
			if (otr != FME_DISPROVED) {
				if (fmep->peek == 0 && ep->is_suspect++ == 0) {
					ep->suspects = fmep->suspects;
					fmep->suspects = ep;
					fmep->nsuspects++;
					if (!is_fault(ep->t))
						fmep->nonfault++;
				}
			}
		} else
			otr = causes_test(fmep, ep, at_latest_by, &my_delay);
		if ((otr == FME_WAIT) && (my_delay < overall_delay))
			overall_delay = my_delay;
		if ((otr != FME_DISPROVED) &&
		    ((rtr == FME_WAIT) || (otr == FME_WAIT)))
			*pdelay = overall_delay;
	}
	if (rtr == FME_DISPROVED) {
		indent();
		out(O_ALTFP|O_VERB|O_NONL, "<-DISPROVED ");
		itree_pevent_brief(O_ALTFP|O_VERB|O_NONL, ep);
		out(O_ALTFP|O_VERB, " (doesn't meet requirements)");
		indent_pop();
		return (FME_DISPROVED);
	}
	if ((otr == FME_DISPROVED) && is_problem(ep->t)) {
		indent();
		out(O_ALTFP|O_VERB|O_NONL, "<-DISPROVED ");
		itree_pevent_brief(O_ALTFP|O_VERB|O_NONL, ep);
		out(O_ALTFP|O_VERB, " (doesn't explain all reports)");
		indent_pop();
		return (FME_DISPROVED);
	}
	if (otr == FME_DISPROVED) {
		indent();
		out(O_ALTFP|O_VERB|O_NONL, "<-DISPROVED ");
		itree_pevent_brief(O_ALTFP|O_VERB|O_NONL, ep);
		out(O_ALTFP|O_VERB, " (causes are not credible)");
		indent_pop();
		return (FME_DISPROVED);
	}
	if ((rtr == FME_WAIT) || (otr == FME_WAIT)) {
		indent();
		out(O_ALTFP|O_VERB|O_NONL, "<-WAIT ");
		itree_pevent_brief(O_ALTFP|O_VERB|O_NONL, ep);
		out(O_ALTFP|O_VERB|O_NONL, " to ");
		ptree_timeval(O_ALTFP|O_VERB|O_NONL, &overall_delay);
		out(O_ALTFP|O_VERB, NULL);
		indent_pop();
		return (FME_WAIT);
	}
	indent();
	out(O_ALTFP|O_VERB|O_NONL, "<-CREDIBLE ");
	itree_pevent_brief(O_ALTFP|O_VERB|O_NONL, ep);
	out(O_ALTFP|O_VERB, NULL);
	indent_pop();
	return (FME_CREDIBLE);
}
