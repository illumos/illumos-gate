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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Milan Jurik. All rights reserved.
 * Copyright (c) 2018, Joyent, Inc.
 *
 * fme.c -- fault management exercise module
 *
 * this module provides the simulated fault management exercise.
 */

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
#include "esclex.h"

/* imported from eft.c... */
extern hrtime_t Hesitate;
extern char *Serd_Override;
extern nv_alloc_t Eft_nv_hdl;
extern int Max_fme;
extern fmd_hdl_t *Hdl;

static int Istat_need_save;
static int Serd_need_save;
void istat_save(void);
void serd_save(void);

/* fme under construction is global so we can free it on module abort */
static struct fme *Nfmep;

static int Undiag_reason = UD_VAL_UNKNOWN;

static int Nextid = 0;

static int Open_fme_count = 0;	/* Count of open FMEs */

/* list of fault management exercises underway */
static struct fme {
	struct fme *next;		/* next exercise */
	unsigned long long ull;		/* time when fme was created */
	int id;				/* FME id */
	struct config *config;		/* cooked configuration data */
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

	struct event *ecurrent;		/* ereport under consideration */
	struct event *suspects;		/* current suspect list */
	struct event *psuspects;	/* previous suspect list */
	int nsuspects;			/* count of suspects */
	int posted_suspects;		/* true if we've posted a diagnosis */
	int uniqobs;			/* number of unique events observed */
	int peek;			/* just peeking, don't track suspects */
	int overflow;			/* true if overflow FME */
	enum fme_state {
		FME_NOTHING = 5000,	/* not evaluated yet */
		FME_WAIT,		/* need to wait for more info */
		FME_CREDIBLE,		/* suspect list is credible */
		FME_DISPROVED,		/* no valid suspects found */
		FME_DEFERRED		/* don't know yet (k-count not met) */
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
	unsigned long long at_latest_by, unsigned long long *pdelay);
static struct node *eventprop_lookup(struct event *ep, const char *propname);
static struct node *pathstring2epnamenp(char *path);
static void publish_undiagnosable(fmd_hdl_t *hdl, fmd_event_t *ffep,
	fmd_case_t *fmcase, nvlist_t *detector, char *arg);
static char *undiag_2reason_str(int ud, char *arg);
static const char *undiag_2defect_str(int ud);
static void restore_suspects(struct fme *fmep);
static void save_suspects(struct fme *fmep);
static void destroy_fme(struct fme *f);
static void fme_receive_report(fmd_hdl_t *hdl, fmd_event_t *ffep,
    const char *eventstring, const struct ipath *ipp, nvlist_t *nvl);
static void istat_counter_reset_cb(struct istat_entry *entp,
    struct stats *statp, const struct ipath *ipp);
static void istat_counter_topo_chg_cb(struct istat_entry *entp,
    struct stats *statp, void *unused);
static void serd_reset_cb(struct serd_entry *entp, void *unused,
    const struct ipath *ipp);
static void serd_topo_chg_cb(struct serd_entry *entp, void *unused,
    void *unused2);
static void destroy_fme_bufs(struct fme *fp);

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
	config_print(O_ALTFP|O_VERB2, fmep->config);

	return (fmep);
}

extern void ipath_dummy_lut(struct arrow *);
extern struct lut *itree_create_dummy(const char *, const struct ipath *);

/* ARGSUSED */
static void
set_needed_arrows(struct event *ep, struct event *ep2, struct fme *fmep)
{
	struct bubble *bp;
	struct arrowlist *ap;

	for (bp = itree_next_bubble(ep, NULL); bp;
	    bp = itree_next_bubble(ep, bp)) {
		if (bp->t != B_FROM)
			continue;
		for (ap = itree_next_arrow(bp, NULL); ap;
		    ap = itree_next_arrow(bp, ap)) {
			ap->arrowp->pnode->u.arrow.needed = 1;
			ipath_dummy_lut(ap->arrowp);
		}
	}
}

/* ARGSUSED */
static void
unset_needed_arrows(struct event *ep, struct event *ep2, struct fme *fmep)
{
	struct bubble *bp;
	struct arrowlist *ap;

	for (bp = itree_next_bubble(ep, NULL); bp;
	    bp = itree_next_bubble(ep, bp)) {
		if (bp->t != B_FROM)
			continue;
		for (ap = itree_next_arrow(bp, NULL); ap;
		    ap = itree_next_arrow(bp, ap))
			ap->arrowp->pnode->u.arrow.needed = 0;
	}
}

static void globals_destructor(void *left, void *right, void *arg);
static void clear_arrows(struct event *ep, struct event *ep2, struct fme *fmep);

static boolean_t
prune_propagations(const char *e0class, const struct ipath *e0ipp)
{
	char nbuf[100];
	unsigned long long my_delay = TIMEVAL_EVENTUALLY;
	extern struct lut *Usednames;

	Nfmep = alloc_fme();
	Nfmep->id = Nextid;
	Nfmep->state = FME_NOTHING;
	Nfmep->eventtree = itree_create_dummy(e0class, e0ipp);
	if ((Nfmep->e0 =
	    itree_lookup(Nfmep->eventtree, e0class, e0ipp)) == NULL) {
		itree_free(Nfmep->eventtree);
		FREE(Nfmep);
		Nfmep = NULL;
		return (B_FALSE);
	}
	Nfmep->ecurrent = Nfmep->observations = Nfmep->e0;
	Nfmep->e0->count++;

	(void) sprintf(nbuf, "fme%d.Rcount", Nfmep->id);
	Nfmep->Rcount = stats_new_counter(nbuf, "ereports received", 0);
	(void) sprintf(nbuf, "fme%d.Hcall", Nfmep->id);
	Nfmep->Hcallcount =
	    stats_new_counter(nbuf, "calls to hypothesise()", 1);
	(void) sprintf(nbuf, "fme%d.Rcall", Nfmep->id);
	Nfmep->Rcallcount = stats_new_counter(nbuf,
	    "calls to requirements_test()", 1);
	(void) sprintf(nbuf, "fme%d.Ccall", Nfmep->id);
	Nfmep->Ccallcount =
	    stats_new_counter(nbuf, "calls to causes_test()", 1);
	(void) sprintf(nbuf, "fme%d.Ecall", Nfmep->id);
	Nfmep->Ecallcount =
	    stats_new_counter(nbuf, "calls to effects_test()", 1);
	(void) sprintf(nbuf, "fme%d.Tcall", Nfmep->id);
	Nfmep->Tcallcount = stats_new_counter(nbuf, "calls to triggered()", 1);
	(void) sprintf(nbuf, "fme%d.Marrow", Nfmep->id);
	Nfmep->Marrowcount = stats_new_counter(nbuf,
	    "arrows marked by mark_arrows()", 1);
	(void) sprintf(nbuf, "fme%d.diags", Nfmep->id);
	Nfmep->diags = stats_new_counter(nbuf, "suspect lists diagnosed", 0);

	Nfmep->peek = 1;
	lut_walk(Nfmep->eventtree, (lut_cb)unset_needed_arrows, (void *)Nfmep);
	lut_free(Usednames, NULL, NULL);
	Usednames = NULL;
	lut_walk(Nfmep->eventtree, (lut_cb)clear_arrows, (void *)Nfmep);
	(void) hypothesise(Nfmep, Nfmep->e0, Nfmep->ull, &my_delay);
	itree_prune(Nfmep->eventtree);
	lut_walk(Nfmep->eventtree, (lut_cb)set_needed_arrows, (void *)Nfmep);

	stats_delete(Nfmep->Rcount);
	stats_delete(Nfmep->Hcallcount);
	stats_delete(Nfmep->Rcallcount);
	stats_delete(Nfmep->Ccallcount);
	stats_delete(Nfmep->Ecallcount);
	stats_delete(Nfmep->Tcallcount);
	stats_delete(Nfmep->Marrowcount);
	stats_delete(Nfmep->diags);
	itree_free(Nfmep->eventtree);
	lut_free(Nfmep->globals, globals_destructor, NULL);
	FREE(Nfmep);
	return (B_TRUE);
}

static struct fme *
newfme(const char *e0class, const struct ipath *e0ipp, fmd_hdl_t *hdl,
    fmd_case_t *fmcase, fmd_event_t *ffep, nvlist_t *nvl)
{
	struct cfgdata *cfgdata;
	int init_size;
	extern int alloc_total();
	nvlist_t *detector = NULL;
	char *pathstr;
	char *arg;

	/*
	 * First check if e0ipp is actually in the topology so we can give a
	 * more useful error message.
	 */
	ipathlastcomp(e0ipp);
	pathstr = ipath2str(NULL, e0ipp);
	cfgdata = config_snapshot();
	platform_units_translate(0, cfgdata->cooked, NULL, NULL,
	    &detector, pathstr);
	FREE(pathstr);
	structconfig_free(cfgdata->cooked);
	config_free(cfgdata);
	if (detector == NULL) {
		/* See if class permits silent discard on unknown component. */
		if (lut_lookup(Ereportenames_discard, (void *)e0class, NULL)) {
			out(O_ALTFP|O_VERB2, "Unable to map \"%s\" ereport "
			    "to component path, but silent discard allowed.",
			    e0class);
			fmd_case_close(hdl, fmcase);
		} else {
			Undiag_reason = UD_VAL_BADEVENTPATH;
			(void) nvlist_lookup_nvlist(nvl, FM_EREPORT_DETECTOR,
			    &detector);
			arg = ipath2str(e0class, e0ipp);
			publish_undiagnosable(hdl, ffep, fmcase, detector, arg);
			FREE(arg);
		}
		return (NULL);
	}

	/*
	 * Next run a quick first pass of the rules with a dummy config. This
	 * allows us to prune those rules which can't possibly cause this
	 * ereport.
	 */
	if (!prune_propagations(e0class, e0ipp)) {
		/*
		 * The fault class must have been in the rules or we would
		 * not have registered for it (and got a "nosub"), and the
		 * pathname must be in the topology or we would have failed the
		 * previous test. So to get here means the combination of
		 * class and pathname in the ereport must be invalid.
		 */
		Undiag_reason = UD_VAL_BADEVENTCLASS;
		arg = ipath2str(e0class, e0ipp);
		publish_undiagnosable(hdl, ffep, fmcase, detector, arg);
		nvlist_free(detector);
		FREE(arg);
		return (NULL);
	}

	/*
	 * Now go ahead and create the real fme using the pruned rules.
	 */
	init_size = alloc_total();
	out(O_ALTFP|O_STAMP, "start config_snapshot using %d bytes", init_size);
	nvlist_free(detector);
	pathstr = ipath2str(NULL, e0ipp);
	cfgdata = config_snapshot();
	platform_units_translate(0, cfgdata->cooked, NULL, NULL,
	    &detector, pathstr);
	FREE(pathstr);
	platform_save_config(hdl, fmcase);
	out(O_ALTFP|O_STAMP, "config_snapshot added %d bytes",
	    alloc_total() - init_size);

	Nfmep = alloc_fme();

	Nfmep->id = Nextid++;
	Nfmep->config = cfgdata->cooked;
	config_free(cfgdata);
	Nfmep->posted_suspects = 0;
	Nfmep->uniqobs = 0;
	Nfmep->state = FME_NOTHING;
	Nfmep->pull = 0ULL;
	Nfmep->overflow = 0;

	Nfmep->fmcase = fmcase;
	Nfmep->hdl = hdl;

	if ((Nfmep->eventtree = itree_create(Nfmep->config)) == NULL) {
		Undiag_reason = UD_VAL_INSTFAIL;
		arg = ipath2str(e0class, e0ipp);
		publish_undiagnosable(hdl, ffep, fmcase, detector, arg);
		nvlist_free(detector);
		FREE(arg);
		structconfig_free(Nfmep->config);
		destroy_fme_bufs(Nfmep);
		FREE(Nfmep);
		Nfmep = NULL;
		return (NULL);
	}

	itree_ptree(O_ALTFP|O_VERB2, Nfmep->eventtree);

	if ((Nfmep->e0 =
	    itree_lookup(Nfmep->eventtree, e0class, e0ipp)) == NULL) {
		Undiag_reason = UD_VAL_BADEVENTI;
		arg = ipath2str(e0class, e0ipp);
		publish_undiagnosable(hdl, ffep, fmcase, detector, arg);
		nvlist_free(detector);
		FREE(arg);
		itree_free(Nfmep->eventtree);
		structconfig_free(Nfmep->config);
		destroy_fme_bufs(Nfmep);
		FREE(Nfmep);
		Nfmep = NULL;
		return (NULL);
	}

	nvlist_free(detector);
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

	platform_restore_config(fp->hdl, fp->fmcase);
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
			Undiag_reason = UD_VAL_MISSINGOBS;
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
			Undiag_reason = UD_VAL_MISSINGPATH;
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
			Undiag_reason = UD_VAL_MISSINGPATH;
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
			Undiag_reason = UD_VAL_BADOBS;
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
			ASSERT(ep->nvp == NULL);
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
	struct cfgdata *cfgdata;
	size_t rawsz;
	struct event *ep;
	char *tmpbuf = alloca(OBBUFNMSZ);
	char *sepptr;
	char *estr;
	int elen;
	struct node *epnamenp = NULL;
	int init_size;
	extern int alloc_total();
	char *reason;

	/*
	 * ignore solved or closed cases
	 */
	if (fmd_case_solved(hdl, inprogress) ||
	    fmd_case_closed(hdl, inprogress))
		return;

	fmep = alloc_fme();
	fmep->fmcase = inprogress;
	fmep->hdl = hdl;

	if (fmd_buf_size(hdl, inprogress, WOBUF_POSTD) == 0) {
		out(O_ALTFP, "restart_fme: no saved posted status");
		Undiag_reason = UD_VAL_MISSINGINFO;
		goto badcase;
	} else {
		fmd_buf_read(hdl, inprogress, WOBUF_POSTD,
		    (void *)&fmep->posted_suspects,
		    sizeof (fmep->posted_suspects));
	}

	if (fmd_buf_size(hdl, inprogress, WOBUF_ID) == 0) {
		out(O_ALTFP, "restart_fme: no saved id");
		Undiag_reason = UD_VAL_MISSINGINFO;
		goto badcase;
	} else {
		fmd_buf_read(hdl, inprogress, WOBUF_ID, (void *)&fmep->id,
		    sizeof (fmep->id));
	}
	if (Nextid <= fmep->id)
		Nextid = fmep->id + 1;

	out(O_ALTFP, "Replay FME %d", fmep->id);

	if (fmd_buf_size(hdl, inprogress, WOBUF_CFGLEN) != sizeof (size_t)) {
		out(O_ALTFP, "restart_fme: No config data");
		Undiag_reason = UD_VAL_MISSINGINFO;
		goto badcase;
	}
	fmd_buf_read(hdl, inprogress, WOBUF_CFGLEN, (void *)&rawsz,
	    sizeof (size_t));

	if ((fmep->e0r = fmd_case_getprincipal(hdl, inprogress)) == NULL) {
		out(O_ALTFP, "restart_fme: No event zero");
		Undiag_reason = UD_VAL_MISSINGZERO;
		goto badcase;
	}

	if (fmd_buf_size(hdl, inprogress, WOBUF_PULL) == 0) {
		out(O_ALTFP, "restart_fme: no saved wait time");
		Undiag_reason = UD_VAL_MISSINGINFO;
		goto badcase;
	} else {
		fmd_buf_read(hdl, inprogress, WOBUF_PULL, (void *)&fmep->pull,
		    sizeof (fmep->pull));
	}

	if (fmd_buf_size(hdl, inprogress, WOBUF_NOBS) == 0) {
		out(O_ALTFP, "restart_fme: no count of observations");
		Undiag_reason = UD_VAL_MISSINGINFO;
		goto badcase;
	} else {
		fmd_buf_read(hdl, inprogress, WOBUF_NOBS,
		    (void *)&fmep->uniqobs, sizeof (fmep->uniqobs));
	}

	(void) snprintf(tmpbuf, OBBUFNMSZ, "observed0");
	elen = fmd_buf_size(fmep->hdl, fmep->fmcase, tmpbuf);
	if (elen == 0) {
		out(O_ALTFP, "reconstitute_observation: no %s buffer found.",
		    tmpbuf);
		Undiag_reason = UD_VAL_MISSINGOBS;
		goto badcase;
	}
	estr = MALLOC(elen);
	fmd_buf_read(fmep->hdl, fmep->fmcase, tmpbuf, estr, elen);
	sepptr = strchr(estr, '@');
	if (sepptr == NULL) {
		out(O_ALTFP, "reconstitute_observation: %s: "
		    "missing @ separator in %s.",
		    tmpbuf, estr);
		Undiag_reason = UD_VAL_MISSINGPATH;
		FREE(estr);
		goto badcase;
	}
	*sepptr = '\0';
	if ((epnamenp = pathstring2epnamenp(sepptr + 1)) == NULL) {
		out(O_ALTFP, "reconstitute_observation: %s: "
		    "trouble converting path string \"%s\" "
		    "to internal representation.", tmpbuf, sepptr + 1);
		Undiag_reason = UD_VAL_MISSINGPATH;
		FREE(estr);
		goto badcase;
	}
	(void) prune_propagations(stable(estr), ipath(epnamenp));
	tree_free(epnamenp);
	FREE(estr);

	init_size = alloc_total();
	out(O_ALTFP|O_STAMP, "start config_restore using %d bytes", init_size);
	cfgdata = MALLOC(sizeof (struct cfgdata));
	cfgdata->cooked = NULL;
	cfgdata->devcache = NULL;
	cfgdata->devidcache = NULL;
	cfgdata->tpcache = NULL;
	cfgdata->cpucache = NULL;
	cfgdata->raw_refcnt = 1;

	if (rawsz > 0) {
		if (fmd_buf_size(hdl, inprogress, WOBUF_CFG) != rawsz) {
			out(O_ALTFP, "restart_fme: Config data size mismatch");
			Undiag_reason = UD_VAL_CFGMISMATCH;
			goto badcase;
		}
		cfgdata->begin = MALLOC(rawsz);
		cfgdata->end = cfgdata->nextfree = cfgdata->begin + rawsz;
		fmd_buf_read(hdl,
		    inprogress, WOBUF_CFG, cfgdata->begin, rawsz);
	} else {
		cfgdata->begin = cfgdata->end = cfgdata->nextfree = NULL;
	}

	config_cook(cfgdata);
	fmep->config = cfgdata->cooked;
	config_free(cfgdata);
	out(O_ALTFP|O_STAMP, "config_restore added %d bytes",
	    alloc_total() - init_size);

	if ((fmep->eventtree = itree_create(fmep->config)) == NULL) {
		/* case not properly saved or irretrievable */
		out(O_ALTFP, "restart_fme: NULL instance tree");
		Undiag_reason = UD_VAL_INSTFAIL;
		goto badcase;
	}

	itree_ptree(O_ALTFP|O_VERB2, fmep->eventtree);

	if (reconstitute_observations(fmep) != 0)
		goto badcase;

	out(O_ALTFP|O_NONL, "FME %d replay observations: ", fmep->id);
	for (ep = fmep->observations; ep; ep = ep->observations) {
		out(O_ALTFP|O_NONL, " ");
		itree_pevent_brief(O_ALTFP|O_NONL, ep);
	}
	out(O_ALTFP, NULL);

	Open_fme_count++;

	/* give the diagnosis algorithm a shot at the new FME state */
	fme_eval(fmep, fmep->e0r);
	return;

badcase:
	if (fmep->eventtree != NULL)
		itree_free(fmep->eventtree);
	if (fmep->config)
		structconfig_free(fmep->config);
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

	out(O_ALTFP|O_NONL, "[case %s (unable to restart), ",
	    fmd_case_uuid(hdl, bad->fmcase));

	if (fmd_case_solved(hdl, bad->fmcase)) {
		out(O_ALTFP|O_NONL, "already solved, ");
	} else {
		out(O_ALTFP|O_NONL, "solving, ");
		defect = fmd_nvl_create_fault(hdl,
		    undiag_2defect_str(Undiag_reason), 100, NULL, NULL, NULL);
		reason = undiag_2reason_str(Undiag_reason, NULL);
		(void) nvlist_add_string(defect, UNDIAG_REASON, reason);
		FREE(reason);
		fmd_case_add_suspect(hdl, bad->fmcase, defect);
		fmd_case_solve(hdl, bad->fmcase);
		Undiag_reason = UD_VAL_UNKNOWN;
	}

	if (fmd_case_closed(hdl, bad->fmcase)) {
		out(O_ALTFP, "already closed ]");
	} else {
		out(O_ALTFP, "closing ]");
		fmd_case_close(hdl, bad->fmcase);
	}
}

/*ARGSUSED*/
static void
globals_destructor(void *left, void *right, void *arg)
{
	struct evalue *evp = (struct evalue *)right;
	if (evp->t == NODEPTR)
		tree_free((struct node *)(uintptr_t)evp->v);
	evp->v = (uintptr_t)NULL;
	FREE(evp);
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

	if (f->eventtree != NULL)
		itree_free(f->eventtree);
	if (f->config)
		structconfig_free(f->config);
	lut_free(f->globals, globals_destructor, NULL);
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
	case FME_DEFERRED:	return ("DEFERRED");
	default:		return ("UNKNOWN");
	}
}

static int
is_problem(enum nametype t)
{
	return (t == N_FAULT || t == N_DEFECT || t == N_UPSET);
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
	if (fmep->eventtree != NULL) {
		out(flags|O_VERB2, "\t        Tree:");
		itree_ptree(flags|O_VERB2, fmep->eventtree);
	}
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
serd_eval(struct fme *fmep, fmd_hdl_t *hdl, fmd_event_t *ffep,
    fmd_case_t *fmcase, struct event *sp, const char **enamep,
    const struct ipath **ippp)
{
	struct node *serdinst;
	char *serdname;
	char *serdresource;
	char *serdclass;
	struct node *nid;
	struct serd_entry *newentp;
	int i, serdn = -1, serdincrement = 1, len = 0;
	char *serdsuffix = NULL, *serdt = NULL;
	struct evalue *ep;

	ASSERT(sp->t == N_UPSET);
	ASSERT(ffep != NULL);

	if ((ep = (struct evalue *)lut_lookup(sp->serdprops,
	    (void *)"n", (lut_cmp)strcmp)) != NULL) {
		ASSERT(ep->t == UINT64);
		serdn = (int)ep->v;
	}
	if ((ep = (struct evalue *)lut_lookup(sp->serdprops,
	    (void *)"t", (lut_cmp)strcmp)) != NULL) {
		ASSERT(ep->t == STRING);
		serdt = (char *)(uintptr_t)ep->v;
	}
	if ((ep = (struct evalue *)lut_lookup(sp->serdprops,
	    (void *)"suffix", (lut_cmp)strcmp)) != NULL) {
		ASSERT(ep->t == STRING);
		serdsuffix = (char *)(uintptr_t)ep->v;
	}
	if ((ep = (struct evalue *)lut_lookup(sp->serdprops,
	    (void *)"increment", (lut_cmp)strcmp)) != NULL) {
		ASSERT(ep->t == UINT64);
		serdincrement = (int)ep->v;
	}

	/*
	 * obtain instanced SERD engine from the upset sp.  from this
	 * derive serdname, the string used to identify the SERD engine.
	 */
	serdinst = eventprop_lookup(sp, L_engine);

	if (serdinst == NULL)
		return (-1);

	len = strlen(serdinst->u.stmt.np->u.event.ename->u.name.s) + 1;
	if (serdsuffix != NULL)
		len += strlen(serdsuffix);
	serdclass = MALLOC(len);
	if (serdsuffix != NULL)
		(void) snprintf(serdclass, len, "%s%s",
		    serdinst->u.stmt.np->u.event.ename->u.name.s, serdsuffix);
	else
		(void) snprintf(serdclass, len, "%s",
		    serdinst->u.stmt.np->u.event.ename->u.name.s);
	serdresource = ipath2str(NULL,
	    ipath(serdinst->u.stmt.np->u.event.epname));
	len += strlen(serdresource) + 1;
	serdname = MALLOC(len);
	(void) snprintf(serdname, len, "%s@%s", serdclass, serdresource);
	FREE(serdresource);

	/* handle serd engine "id" property, if there is one */
	if ((nid =
	    lut_lookup(serdinst->u.stmt.lutp, (void *)L_id, NULL)) != NULL) {
		struct evalue *gval;
		char suffixbuf[200];
		char *suffix;
		char *nserdname;
		size_t nname;

		out(O_ALTFP|O_NONL, "serd \"%s\" id: ", serdname);
		ptree_name_iter(O_ALTFP|O_NONL, nid);

		ASSERTinfo(nid->t == T_GLOBID, ptree_nodetype2str(nid->t));

		if ((gval = lut_lookup(fmep->globals,
		    (void *)nid->u.globid.s, NULL)) == NULL) {
			out(O_ALTFP, " undefined");
		} else if (gval->t == UINT64) {
			out(O_ALTFP, " %llu", gval->v);
			(void) sprintf(suffixbuf, "%llu", gval->v);
			suffix = suffixbuf;
		} else {
			out(O_ALTFP, " \"%s\"", (char *)(uintptr_t)gval->v);
			suffix = (char *)(uintptr_t)gval->v;
		}

		nname = strlen(serdname) + strlen(suffix) + 2;
		nserdname = MALLOC(nname);
		(void) snprintf(nserdname, nname, "%s:%s", serdname, suffix);
		FREE(serdname);
		serdname = nserdname;
	}

	/*
	 * if the engine is empty, and we have an override for n/t then
	 * destroy and recreate it.
	 */
	if ((serdn != -1 || serdt != NULL) && fmd_serd_exists(hdl, serdname) &&
	    fmd_serd_empty(hdl, serdname))
		fmd_serd_destroy(hdl, serdname);

	if (!fmd_serd_exists(hdl, serdname)) {
		struct node *nN, *nT;
		const char *s;
		struct node *nodep;
		struct config *cp;
		char *path;
		uint_t nval;
		hrtime_t tval;
		int i;
		char *ptr;
		int got_n_override = 0, got_t_override = 0;

		/* no SERD engine yet, so create it */
		nodep = serdinst->u.stmt.np->u.event.epname;
		path = ipath2str(NULL, ipath(nodep));
		cp = config_lookup(fmep->config, path, 0);
		FREE((void *)path);

		/*
		 * We allow serd paramaters to be overridden, either from
		 * eft.conf file values (if Serd_Override is set) or from
		 * driver properties (for "serd.io.device" engines).
		 */
		if (Serd_Override != NULL) {
			char *save_ptr, *ptr1, *ptr2, *ptr3;
			ptr3 = save_ptr = STRDUP(Serd_Override);
			while (*ptr3 != '\0') {
				ptr1 = strchr(ptr3, ',');
				*ptr1 = '\0';
				if (strcmp(ptr3, serdclass) == 0) {
					ptr2 =  strchr(ptr1 + 1, ',');
					*ptr2 = '\0';
					nval = atoi(ptr1 + 1);
					out(O_ALTFP, "serd override %s_n %d",
					    serdclass, nval);
					ptr3 =  strchr(ptr2 + 1, ' ');
					if (ptr3)
						*ptr3 = '\0';
					ptr = STRDUP(ptr2 + 1);
					out(O_ALTFP, "serd override %s_t %s",
					    serdclass, ptr);
					got_n_override = 1;
					got_t_override = 1;
					break;
				} else {
					ptr2 =  strchr(ptr1 + 1, ',');
					ptr3 =  strchr(ptr2 + 1, ' ');
					if (ptr3 == NULL)
						break;
				}
				ptr3++;
			}
			FREE(save_ptr);
		}

		if (cp && got_n_override == 0) {
			/*
			 * convert serd engine class into property name
			 */
			char *prop_name = MALLOC(strlen(serdclass) + 3);
			for (i = 0; i < strlen(serdclass); i++) {
				if (serdclass[i] == '.')
					prop_name[i] = '_';
				else
					prop_name[i] = serdclass[i];
			}
			prop_name[i++] = '_';
			prop_name[i++] = 'n';
			prop_name[i] = '\0';
			if (s = config_getprop(cp, prop_name)) {
				nval = atoi(s);
				out(O_ALTFP, "serd override %s_n %s",
				    serdclass, s);
				got_n_override = 1;
			}
			prop_name[i - 1] = 't';
			if (s = config_getprop(cp, prop_name)) {
				ptr = STRDUP(s);
				out(O_ALTFP, "serd override %s_t %s",
				    serdclass, s);
				got_t_override = 1;
			}
			FREE(prop_name);
		}

		if (serdn != -1 && got_n_override == 0) {
			nval = serdn;
			out(O_ALTFP, "serd override %s_n %d", serdclass, serdn);
			got_n_override = 1;
		}
		if (serdt != NULL && got_t_override == 0) {
			ptr = STRDUP(serdt);
			out(O_ALTFP, "serd override %s_t %s", serdclass, serdt);
			got_t_override = 1;
		}

		if (!got_n_override) {
			nN = lut_lookup(serdinst->u.stmt.lutp, (void *)L_N,
			    NULL);
			ASSERT(nN->t == T_NUM);
			nval = (uint_t)nN->u.ull;
		}
		if (!got_t_override) {
			nT = lut_lookup(serdinst->u.stmt.lutp, (void *)L_T,
			    NULL);
			ASSERT(nT->t == T_TIMEVAL);
			tval = (hrtime_t)nT->u.ull;
		} else {
			const unsigned long long *ullp;
			const char *suffix;
			int len;

			len = strspn(ptr, "0123456789");
			suffix = stable(&ptr[len]);
			ullp = (unsigned long long *)lut_lookup(Timesuffixlut,
			    (void *)suffix, NULL);
			ptr[len] = '\0';
			tval = strtoull(ptr, NULL, 0) * (ullp ? *ullp : 1ll);
			FREE(ptr);
		}
		fmd_serd_create(hdl, serdname, nval, tval);
	}

	newentp = MALLOC(sizeof (*newentp));
	newentp->ename = stable(serdclass);
	FREE(serdclass);
	newentp->ipath = ipath(serdinst->u.stmt.np->u.event.epname);
	newentp->hdl = hdl;
	if (lut_lookup(SerdEngines, newentp, (lut_cmp)serd_cmp) == NULL) {
		SerdEngines = lut_add(SerdEngines, (void *)newentp,
		    (void *)newentp, (lut_cmp)serd_cmp);
		Serd_need_save = 1;
		serd_save();
	} else {
		FREE(newentp);
	}


	/*
	 * increment SERD engine.  if engine fires, reset serd
	 * engine and return trip_strcode if required.
	 */
	for (i = 0; i < serdincrement; i++) {
		if (fmd_serd_record(hdl, serdname, ffep)) {
			fmd_case_add_serd(hdl, fmcase, serdname);
			fmd_serd_reset(hdl, serdname);

			if (ippp) {
				struct node *tripinst =
				    lut_lookup(serdinst->u.stmt.lutp,
				    (void *)L_trip, NULL);
				ASSERT(tripinst != NULL);
				*enamep = tripinst->u.event.ename->u.name.s;
				*ippp = ipath(tripinst->u.event.epname);
				out(O_ALTFP|O_NONL,
				    "[engine fired: %s, sending: ", serdname);
				ipath_print(O_ALTFP|O_NONL, *enamep, *ippp);
				out(O_ALTFP, "]");
			} else {
				out(O_ALTFP, "[engine fired: %s, no trip]",
				    serdname);
			}
			FREE(serdname);
			return (1);
		}
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
		    serd_eval(fmep, fmep->hdl, ffep, fmep->fmcase, sp,
		    &tripped[ntrip].ename, &tripped[ntrip].ipp) == 1)
			ntrip++;

	for (i = 0; i < ntrip; i++) {
		struct event *ep, *nep;
		struct fme *nfmep;
		fmd_case_t *fmcase;
		const struct ipath *ipp;
		const char *eventstring;
		int prev_verbose;
		unsigned long long my_delay = TIMEVAL_EVENTUALLY;
		enum fme_state state;

		/*
		 * First try and evaluate a case with the trip ereport plus
		 * all the other ereports that cause the trip. If that fails
		 * to evaluate then try again with just this ereport on its own.
		 */
		out(O_ALTFP|O_NONL, "fme_receive_report_serd: ");
		ipath_print(O_ALTFP|O_NONL, tripped[i].ename, tripped[i].ipp);
		out(O_ALTFP|O_STAMP, NULL);
		ep = fmep->e0;
		eventstring = ep->enode->u.event.ename->u.name.s;
		ipp = ep->ipp;

		/*
		 * create a duplicate fme and case
		 */
		fmcase = fmd_case_open(fmep->hdl, NULL);
		out(O_ALTFP|O_NONL, "duplicate fme for event [");
		ipath_print(O_ALTFP|O_NONL, eventstring, ipp);
		out(O_ALTFP, " ]");

		if ((nfmep = newfme(eventstring, ipp, fmep->hdl,
		    fmcase, ffep, ep->nvp)) == NULL) {
			out(O_ALTFP|O_NONL, "[");
			ipath_print(O_ALTFP|O_NONL, eventstring, ipp);
			out(O_ALTFP, " CANNOT DIAGNOSE]");
			continue;
		}

		Open_fme_count++;
		nfmep->pull = fmep->pull;
		init_fme_bufs(nfmep);
		out(O_ALTFP|O_NONL, "[");
		ipath_print(O_ALTFP|O_NONL, eventstring, ipp);
		out(O_ALTFP, " created FME%d, case %s]", nfmep->id,
		    fmd_case_uuid(nfmep->hdl, nfmep->fmcase));
		if (ffep) {
			fmd_case_setprincipal(nfmep->hdl, nfmep->fmcase, ffep);
			fmd_case_add_ereport(nfmep->hdl, nfmep->fmcase, ffep);
			nfmep->e0r = ffep;
		}

		/*
		 * add the original ereports
		 */
		for (ep = fmep->observations; ep; ep = ep->observations) {
			eventstring = ep->enode->u.event.ename->u.name.s;
			ipp = ep->ipp;
			out(O_ALTFP|O_NONL, "adding event [");
			ipath_print(O_ALTFP|O_NONL, eventstring, ipp);
			out(O_ALTFP, " ]");
			nep = itree_lookup(nfmep->eventtree, eventstring, ipp);
			if (nep->count++ == 0) {
				nep->observations = nfmep->observations;
				nfmep->observations = nep;
				serialize_observation(nfmep, eventstring, ipp);
				nep->nvp = evnv_dupnvl(ep->nvp);
			}
			if (ep->ffep && ep->ffep != ffep)
				fmd_case_add_ereport(nfmep->hdl, nfmep->fmcase,
				    ep->ffep);
			stats_counter_bump(nfmep->Rcount);
		}

		/*
		 * add the serd trigger ereport
		 */
		if ((ep = itree_lookup(nfmep->eventtree, tripped[i].ename,
		    tripped[i].ipp)) == NULL) {
			/*
			 * The trigger ereport is not in the instance tree. It
			 * was presumably removed by prune_propagations() as
			 * this combination of events is not present in the
			 * rules.
			 */
			out(O_ALTFP, "upsets_eval: e0 not in instance tree");
			Undiag_reason = UD_VAL_BADEVENTI;
			goto retry_lone_ereport;
		}
		out(O_ALTFP|O_NONL, "adding event [");
		ipath_print(O_ALTFP|O_NONL, tripped[i].ename, tripped[i].ipp);
		out(O_ALTFP, " ]");
		nfmep->ecurrent = ep;
		ep->nvp = NULL;
		ep->count = 1;
		ep->observations = nfmep->observations;
		nfmep->observations = ep;

		/*
		 * just peek first.
		 */
		nfmep->peek = 1;
		prev_verbose = Verbose;
		if (Debug == 0)
			Verbose = 0;
		lut_walk(nfmep->eventtree, (lut_cb)clear_arrows, (void *)nfmep);
		state = hypothesise(nfmep, nfmep->e0, nfmep->ull, &my_delay);
		nfmep->peek = 0;
		Verbose = prev_verbose;
		if (state == FME_DISPROVED) {
			out(O_ALTFP, "upsets_eval: hypothesis disproved");
			Undiag_reason = UD_VAL_UNSOLVD;
retry_lone_ereport:
			/*
			 * However the trigger ereport on its own might be
			 * diagnosable, so check for that. Undo the new fme
			 * and case we just created and call fme_receive_report.
			 */
			out(O_ALTFP|O_NONL, "[");
			ipath_print(O_ALTFP|O_NONL, tripped[i].ename,
			    tripped[i].ipp);
			out(O_ALTFP, " retrying with just trigger ereport]");
			itree_free(nfmep->eventtree);
			nfmep->eventtree = NULL;
			structconfig_free(nfmep->config);
			nfmep->config = NULL;
			destroy_fme_bufs(nfmep);
			fmd_case_close(nfmep->hdl, nfmep->fmcase);
			fme_receive_report(fmep->hdl, ffep,
			    tripped[i].ename, tripped[i].ipp, NULL);
			continue;
		}

		/*
		 * and evaluate
		 */
		serialize_observation(nfmep, tripped[i].ename, tripped[i].ipp);
		fme_eval(nfmep, ffep);
	}

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
    const char *class)
{
	struct node		*epnamenp;
	fmd_case_t		*fmcase;
	const struct ipath	*ipp;
	nvlist_t		*detector = NULL;

	class = stable(class);

	/* Get the component path from the ereport */
	epnamenp = platform_getpath(nvl);

	/* See if we ended up without a path. */
	if (epnamenp == NULL) {
		/* See if class permits silent discard on unknown component. */
		if (lut_lookup(Ereportenames_discard, (void *)class, NULL)) {
			out(O_ALTFP|O_VERB2, "Unable to map \"%s\" ereport "
			    "to component path, but silent discard allowed.",
			    class);
		} else {
			/*
			 * XFILE: Failure to find a component is bad unless
			 * 'discard_if_config_unknown=1' was specified in the
			 * ereport definition. Indicate undiagnosable.
			 */
			Undiag_reason = UD_VAL_NOPATH;
			fmcase = fmd_case_open(hdl, NULL);

			/*
			 * We don't have a component path here (which means that
			 * the detector was not in hc-scheme and couldn't be
			 * converted to hc-scheme. Report the raw detector as
			 * the suspect resource if there is one.
			 */
			(void) nvlist_lookup_nvlist(nvl, FM_EREPORT_DETECTOR,
			    &detector);
			publish_undiagnosable(hdl, ffep, fmcase, detector,
			    (char *)class);
		}
		return;
	}

	ipp = ipath(epnamenp);
	tree_free(epnamenp);
	fme_receive_report(hdl, ffep, class, ipp, nvl);
}

/*ARGSUSED*/
void
fme_receive_repair_list(fmd_hdl_t *hdl, fmd_event_t *ffep, nvlist_t *nvl,
    const char *eventstring)
{
	char *uuid;
	nvlist_t **nva;
	uint_t nvc;
	const struct ipath *ipp;

	if (nvlist_lookup_string(nvl, FM_SUSPECT_UUID, &uuid) != 0 ||
	    nvlist_lookup_nvlist_array(nvl, FM_SUSPECT_FAULT_LIST,
	    &nva, &nvc) != 0) {
		out(O_ALTFP, "No uuid or fault list for list.repaired event");
		return;
	}

	out(O_ALTFP, "Processing list.repaired from case %s", uuid);

	while (nvc-- != 0) {
		/*
		 * Reset any istat or serd engine associated with this path.
		 */
		char *path;

		if ((ipp = platform_fault2ipath(*nva++)) == NULL)
			continue;

		path = ipath2str(NULL, ipp);
		out(O_ALTFP, "fme_receive_repair_list: resetting state for %s",
		    path);
		FREE(path);

		lut_walk(Istats, (lut_cb)istat_counter_reset_cb, (void *)ipp);
		istat_save();

		lut_walk(SerdEngines, (lut_cb)serd_reset_cb, (void *)ipp);
		serd_save();
	}
}

/*ARGSUSED*/
void
fme_receive_topology_change(void)
{
	lut_walk(Istats, (lut_cb)istat_counter_topo_chg_cb, NULL);
	istat_save();

	lut_walk(SerdEngines, (lut_cb)serd_topo_chg_cb, NULL);
	serd_save();
}

static int mark_arrows(struct fme *fmep, struct event *ep, int mark,
    unsigned long long at_latest_by, unsigned long long *pdelay, int keep);

/* ARGSUSED */
static void
clear_arrows(struct event *ep, struct event *ep2, struct fme *fmep)
{
	struct bubble *bp;
	struct arrowlist *ap;

	ep->cached_state = 0;
	ep->keep_in_tree = 0;
	for (bp = itree_next_bubble(ep, NULL); bp;
	    bp = itree_next_bubble(ep, bp)) {
		if (bp->t != B_FROM)
			continue;
		bp->mark = 0;
		for (ap = itree_next_arrow(bp, NULL); ap;
		    ap = itree_next_arrow(bp, ap))
			ap->arrowp->mark = 0;
	}
}

static void
fme_receive_report(fmd_hdl_t *hdl, fmd_event_t *ffep,
    const char *eventstring, const struct ipath *ipp, nvlist_t *nvl)
{
	struct event *ep;
	struct fme *fmep = NULL;
	struct fme *ofmep = NULL;
	struct fme *cfmep, *svfmep;
	int matched = 0;
	nvlist_t *defect;
	fmd_case_t *fmcase;
	char *reason;

	out(O_ALTFP|O_NONL, "fme_receive_report: ");
	ipath_print(O_ALTFP|O_NONL, eventstring, ipp);
	out(O_ALTFP|O_STAMP, NULL);

	/* decide which FME it goes to */
	for (fmep = FMElist; fmep; fmep = fmep->next) {
		int prev_verbose;
		unsigned long long my_delay = TIMEVAL_EVENTUALLY;
		enum fme_state state;
		nvlist_t *pre_peek_nvp = NULL;

		if (fmep->overflow) {
			if (!(fmd_case_closed(fmep->hdl, fmep->fmcase)))
				ofmep = fmep;

			continue;
		}

		/*
		 * ignore solved or closed cases
		 */
		if (fmep->posted_suspects ||
		    fmd_case_solved(fmep->hdl, fmep->fmcase) ||
		    fmd_case_closed(fmep->hdl, fmep->fmcase))
			continue;

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
		} else {
			/* use new payload values for peek */
			pre_peek_nvp = ep->nvp;
			ep->nvp = evnv_dupnvl(nvl);
		}

		/* tell hypothesise() not to mess with suspect list */
		fmep->peek = 1;

		/* don't want this to be verbose (unless Debug is set) */
		prev_verbose = Verbose;
		if (Debug == 0)
			Verbose = 0;

		lut_walk(fmep->eventtree, (lut_cb)clear_arrows, (void *)fmep);
		state = hypothesise(fmep, fmep->e0, fmep->ull, &my_delay);

		fmep->peek = 0;

		/* put verbose flag back */
		Verbose = prev_verbose;

		if (state != FME_DISPROVED) {
			/* found an FME that explains the ereport */
			matched++;
			out(O_ALTFP|O_NONL, "[");
			ipath_print(O_ALTFP|O_NONL, eventstring, ipp);
			out(O_ALTFP, " explained by FME%d]", fmep->id);

			nvlist_free(pre_peek_nvp);

			if (ep->count == 1)
				serialize_observation(fmep, eventstring, ipp);

			if (ffep) {
				fmd_case_add_ereport(hdl, fmep->fmcase, ffep);
				ep->ffep = ffep;
			}

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
			} else {
				nvlist_free(ep->nvp);
				ep->nvp = pre_peek_nvp;
			}
		}
	}

	if (matched)
		return;	/* explained by at least one existing FME */

	/* clean up closed fmes */
	cfmep = ClosedFMEs;
	while (cfmep != NULL) {
		svfmep = cfmep->next;
		destroy_fme(cfmep);
		cfmep = svfmep;
	}
	ClosedFMEs = NULL;

	if (ofmep) {
		out(O_ALTFP|O_NONL, "[");
		ipath_print(O_ALTFP|O_NONL, eventstring, ipp);
		out(O_ALTFP, " ADDING TO OVERFLOW FME]");
		if (ffep)
			fmd_case_add_ereport(hdl, ofmep->fmcase, ffep);

		return;

	} else if (Max_fme && (Open_fme_count >= Max_fme)) {
		out(O_ALTFP|O_NONL, "[");
		ipath_print(O_ALTFP|O_NONL, eventstring, ipp);
		out(O_ALTFP, " MAX OPEN FME REACHED]");

		fmcase = fmd_case_open(hdl, NULL);

		/* Create overflow fme */
		if ((fmep = newfme(eventstring, ipp, hdl, fmcase, ffep,
		    nvl)) == NULL) {
			out(O_ALTFP|O_NONL, "[");
			ipath_print(O_ALTFP|O_NONL, eventstring, ipp);
			out(O_ALTFP, " CANNOT OPEN OVERFLOW FME]");
			return;
		}

		Open_fme_count++;

		init_fme_bufs(fmep);
		fmep->overflow = B_TRUE;

		if (ffep)
			fmd_case_add_ereport(hdl, fmep->fmcase, ffep);

		Undiag_reason = UD_VAL_MAXFME;
		defect = fmd_nvl_create_fault(hdl,
		    undiag_2defect_str(Undiag_reason), 100, NULL, NULL, NULL);
		reason = undiag_2reason_str(Undiag_reason, NULL);
		(void) nvlist_add_string(defect, UNDIAG_REASON, reason);
		FREE(reason);
		fmd_case_add_suspect(hdl, fmep->fmcase, defect);
		fmd_case_solve(hdl, fmep->fmcase);
		Undiag_reason = UD_VAL_UNKNOWN;
		return;
	}

	/* open a case */
	fmcase = fmd_case_open(hdl, NULL);

	/* start a new FME */
	if ((fmep = newfme(eventstring, ipp, hdl, fmcase, ffep, nvl)) == NULL) {
		out(O_ALTFP|O_NONL, "[");
		ipath_print(O_ALTFP|O_NONL, eventstring, ipp);
		out(O_ALTFP, " CANNOT DIAGNOSE]");
		return;
	}

	Open_fme_count++;

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
	} else {
		/* new payload overrides any previous */
		nvlist_free(ep->nvp);
		ep->nvp = evnv_dupnvl(nvl);
	}

	stats_counter_bump(fmep->Rcount);

	if (ffep) {
		fmd_case_add_ereport(hdl, fmep->fmcase, ffep);
		fmd_case_setprincipal(hdl, fmep->fmcase, ffep);
		fmep->e0r = ffep;
		ep->ffep = ffep;
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
		out(O_ALTFP|O_NONL, "FME%d set wait timer %ld ", fmep->id,
		    fmep->timer);
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
			nvlist_free(pa[i]);
		return (f);
	}
	failure = "addition of hc-pair array to FMRI failed";

boom:
	for (i = 0; i < depth; i++)
		nvlist_free(pa[i]);
	nvlist_free(f);
	out(O_DIE, "%s", failure);
	/*NOTREACHED*/
	return (NULL);
}

/* an ipath cache entry is an array of these, with s==NULL at the end */
struct ipath {
	const char *s;	/* component name (in stable) */
	int i;		/* instance number */
};

static nvlist_t *
ipath2fmri(struct ipath *ipath)
{
	nvlist_t **pa, *f, *p;
	uint_t depth = 0;
	char *numstr, *nullbyte;
	char *failure;
	int err, i;
	struct ipath *ipp;

	for (ipp = ipath; ipp->s != NULL; ipp++)
		depth++;

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

	for (ipp = ipath; ipp->s != NULL; ipp++) {
		err = nvlist_xalloc(&p, NV_UNIQUE_NAME, &Eft_nv_hdl);
		if (err != 0) {
			failure = "alloc of an hc-pair failed";
			goto boom;
		}
		err = nvlist_add_string(p, FM_FMRI_HC_NAME, ipp->s);
		numstr = ulltostr(ipp->i, nullbyte);
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
			nvlist_free(pa[i]);
		return (f);
	}
	failure = "addition of hc-pair array to FMRI failed";

boom:
	for (i = 0; i < depth; i++)
		nvlist_free(pa[i]);
	nvlist_free(f);
	out(O_DIE, "%s", failure);
	/*NOTREACHED*/
	return (NULL);
}

static uint8_t
percentof(uint_t part, uint_t whole)
{
	unsigned long long p = part * 1000;

	return ((p / whole / 10) + (((p / whole % 10) >= 5) ? 1 : 0));
}

struct rsl {
	struct event *suspect;
	nvlist_t *asru;
	nvlist_t *fru;
	nvlist_t *rsrc;
};

static void publish_suspects(struct fme *fmep, struct rsl *srl);

/*
 *  rslfree -- free internal members of struct rsl not expected to be
 *	freed elsewhere.
 */
static void
rslfree(struct rsl *freeme)
{
	nvlist_free(freeme->asru);
	nvlist_free(freeme->fru);
	if (freeme->rsrc != freeme->asru)
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

	if (r1->rsrc == NULL && r2->rsrc == NULL)
		return (0);
	if (r1->rsrc == NULL)
		return (-1);
	if (r2->rsrc == NULL)
		return (1);
	return (evnv_cmpnvl(r1->rsrc, r2->rsrc, 0));
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
	 *  Allow for platform translations of the FMRIs
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
static int
trim_suspects(struct fme *fmep, struct rsl *begin, struct rsl *begin2,
    fmd_event_t *ffep)
{
	struct event *ep;
	struct rsl *rp = begin;
	struct rsl *rp2 = begin2;
	int mess_zero_count = 0;
	int serd_rval;
	uint_t messval;

	/* remove any unwanted upsets and populate our array */
	for (ep = fmep->psuspects; ep; ep = ep->psuspects) {
		if (is_upset(ep->t))
			continue;
		serd_rval = serd_eval(fmep, fmep->hdl, ffep, fmep->fmcase, ep,
		    NULL, NULL);
		if (serd_rval == 0)
			continue;
		if (node2uint(eventprop_lookup(ep, L_message),
		    &messval) == 0 && messval == 0) {
			get_resources(ep, rp2, fmep->config);
			rp2++;
			mess_zero_count++;
		} else {
			get_resources(ep, rp, fmep->config);
			rp++;
			fmep->nsuspects++;
		}
	}
	return (mess_zero_count);
}

/*
 * addpayloadprop -- add a payload prop to a problem
 */
static void
addpayloadprop(const char *lhs, struct evalue *rhs, nvlist_t *fault)
{
	nvlist_t *rsrc, *hcs;

	ASSERT(fault != NULL);
	ASSERT(lhs != NULL);
	ASSERT(rhs != NULL);

	if (nvlist_lookup_nvlist(fault, FM_FAULT_RESOURCE, &rsrc) != 0)
		out(O_DIE, "cannot add payloadprop \"%s\" to fault", lhs);

	if (nvlist_lookup_nvlist(rsrc, FM_FMRI_HC_SPECIFIC, &hcs) != 0) {
		out(O_ALTFP|O_VERB2, "addpayloadprop: create hc_specific");
		if (nvlist_xalloc(&hcs, NV_UNIQUE_NAME, &Eft_nv_hdl) != 0)
			out(O_DIE,
			    "cannot add payloadprop \"%s\" to fault", lhs);
		if (nvlist_add_nvlist(rsrc, FM_FMRI_HC_SPECIFIC, hcs) != 0)
			out(O_DIE,
			    "cannot add payloadprop \"%s\" to fault", lhs);
		nvlist_free(hcs);
		if (nvlist_lookup_nvlist(rsrc, FM_FMRI_HC_SPECIFIC, &hcs) != 0)
			out(O_DIE,
			    "cannot add payloadprop \"%s\" to fault", lhs);
	} else
		out(O_ALTFP|O_VERB2, "addpayloadprop: reuse hc_specific");

	if (rhs->t == UINT64) {
		out(O_ALTFP|O_VERB2, "addpayloadprop: %s=%llu", lhs, rhs->v);

		if (nvlist_add_uint64(hcs, lhs, rhs->v) != 0)
			out(O_DIE,
			    "cannot add payloadprop \"%s\" to fault", lhs);
	} else {
		out(O_ALTFP|O_VERB2, "addpayloadprop: %s=\"%s\"",
		    lhs, (char *)(uintptr_t)rhs->v);

		if (nvlist_add_string(hcs, lhs, (char *)(uintptr_t)rhs->v) != 0)
			out(O_DIE,
			    "cannot add payloadprop \"%s\" to fault", lhs);
	}
}

static char *Istatbuf;
static char *Istatbufptr;
static int Istatsz;

/*
 * istataddsize -- calculate size of istat and add it to Istatsz
 */
/*ARGSUSED2*/
static void
istataddsize(const struct istat_entry *lhs, struct stats *rhs, void *arg)
{
	int val;

	ASSERT(lhs != NULL);
	ASSERT(rhs != NULL);

	if ((val = stats_counter_value(rhs)) == 0)
		return;	/* skip zero-valued stats */

	/* count up the size of the stat name */
	Istatsz += ipath2strlen(lhs->ename, lhs->ipath);
	Istatsz++;	/* for the trailing NULL byte */

	/* count up the size of the stat value */
	Istatsz += snprintf(NULL, 0, "%d", val);
	Istatsz++;	/* for the trailing NULL byte */
}

/*
 * istat2str -- serialize an istat, writing result to *Istatbufptr
 */
/*ARGSUSED2*/
static void
istat2str(const struct istat_entry *lhs, struct stats *rhs, void *arg)
{
	char *str;
	int len;
	int val;

	ASSERT(lhs != NULL);
	ASSERT(rhs != NULL);

	if ((val = stats_counter_value(rhs)) == 0)
		return;	/* skip zero-valued stats */

	/* serialize the stat name */
	str = ipath2str(lhs->ename, lhs->ipath);
	len = strlen(str);

	ASSERT(Istatbufptr + len + 1 < &Istatbuf[Istatsz]);
	(void) strlcpy(Istatbufptr, str, &Istatbuf[Istatsz] - Istatbufptr);
	Istatbufptr += len;
	FREE(str);
	*Istatbufptr++ = '\0';

	/* serialize the stat value */
	Istatbufptr += snprintf(Istatbufptr, &Istatbuf[Istatsz] - Istatbufptr,
	    "%d", val);
	*Istatbufptr++ = '\0';

	ASSERT(Istatbufptr <= &Istatbuf[Istatsz]);
}

void
istat_save()
{
	if (Istat_need_save == 0)
		return;

	/* figure out how big the serialzed info is */
	Istatsz = 0;
	lut_walk(Istats, (lut_cb)istataddsize, NULL);

	if (Istatsz == 0) {
		/* no stats to save */
		fmd_buf_destroy(Hdl, NULL, WOBUF_ISTATS);
		return;
	}

	/* create the serialized buffer */
	Istatbufptr = Istatbuf = MALLOC(Istatsz);
	lut_walk(Istats, (lut_cb)istat2str, NULL);

	/* clear out current saved stats */
	fmd_buf_destroy(Hdl, NULL, WOBUF_ISTATS);

	/* write out the new version */
	fmd_buf_write(Hdl, NULL, WOBUF_ISTATS, Istatbuf, Istatsz);
	FREE(Istatbuf);

	Istat_need_save = 0;
}

int
istat_cmp(struct istat_entry *ent1, struct istat_entry *ent2)
{
	if (ent1->ename != ent2->ename)
		return (ent2->ename - ent1->ename);
	if (ent1->ipath != ent2->ipath)
		return ((char *)ent2->ipath - (char *)ent1->ipath);

	return (0);
}

/*
 * istat-verify -- verify the component associated with a stat still exists
 *
 * if the component no longer exists, this routine resets the stat and
 * returns 0.  if the component still exists, it returns 1.
 */
static int
istat_verify(struct node *snp, struct istat_entry *entp)
{
	struct stats *statp;
	nvlist_t *fmri;

	fmri = node2fmri(snp->u.event.epname);
	if (platform_path_exists(fmri)) {
		nvlist_free(fmri);
		return (1);
	}
	nvlist_free(fmri);

	/* component no longer in system.  zero out the associated stats */
	if ((statp = (struct stats *)
	    lut_lookup(Istats, entp, (lut_cmp)istat_cmp)) == NULL ||
	    stats_counter_value(statp) == 0)
		return (0);	/* stat is already reset */

	Istat_need_save = 1;
	stats_counter_reset(statp);
	return (0);
}

static void
istat_bump(struct node *snp, int n)
{
	struct stats *statp;
	struct istat_entry ent;

	ASSERT(snp != NULL);
	ASSERTinfo(snp->t == T_EVENT, ptree_nodetype2str(snp->t));
	ASSERT(snp->u.event.epname != NULL);

	/* class name should be hoisted into a single stable entry */
	ASSERT(snp->u.event.ename->u.name.next == NULL);
	ent.ename = snp->u.event.ename->u.name.s;
	ent.ipath = ipath(snp->u.event.epname);

	if (!istat_verify(snp, &ent)) {
		/* component no longer exists in system, nothing to do */
		return;
	}

	if ((statp = (struct stats *)
	    lut_lookup(Istats, &ent, (lut_cmp)istat_cmp)) == NULL) {
		/* need to create the counter */
		int cnt = 0;
		struct node *np;
		char *sname;
		char *snamep;
		struct istat_entry *newentp;

		/* count up the size of the stat name */
		np = snp->u.event.ename;
		while (np != NULL) {
			cnt += strlen(np->u.name.s);
			cnt++;	/* for the '.' or '@' */
			np = np->u.name.next;
		}
		np = snp->u.event.epname;
		while (np != NULL) {
			cnt += snprintf(NULL, 0, "%s%llu",
			    np->u.name.s, np->u.name.child->u.ull);
			cnt++;	/* for the '/' or trailing NULL byte */
			np = np->u.name.next;
		}

		/* build the stat name */
		snamep = sname = alloca(cnt);
		np = snp->u.event.ename;
		while (np != NULL) {
			snamep += snprintf(snamep, &sname[cnt] - snamep,
			    "%s", np->u.name.s);
			np = np->u.name.next;
			if (np)
				*snamep++ = '.';
		}
		*snamep++ = '@';
		np = snp->u.event.epname;
		while (np != NULL) {
			snamep += snprintf(snamep, &sname[cnt] - snamep,
			    "%s%llu", np->u.name.s, np->u.name.child->u.ull);
			np = np->u.name.next;
			if (np)
				*snamep++ = '/';
		}
		*snamep++ = '\0';

		/* create the new stat & add it to our list */
		newentp = MALLOC(sizeof (*newentp));
		*newentp = ent;
		statp = stats_new_counter(NULL, sname, 0);
		Istats = lut_add(Istats, (void *)newentp, (void *)statp,
		    (lut_cmp)istat_cmp);
	}

	/* if n is non-zero, set that value instead of bumping */
	if (n) {
		stats_counter_reset(statp);
		stats_counter_add(statp, n);
	} else
		stats_counter_bump(statp);
	Istat_need_save = 1;

	ipath_print(O_ALTFP|O_VERB2, ent.ename, ent.ipath);
	out(O_ALTFP|O_VERB2, " %s to value %d", n ? "set" : "incremented",
	    stats_counter_value(statp));
}

/*ARGSUSED*/
static void
istat_destructor(void *left, void *right, void *arg)
{
	struct istat_entry *entp = (struct istat_entry *)left;
	struct stats *statp = (struct stats *)right;
	FREE(entp);
	stats_delete(statp);
}

/*
 * Callback used in a walk of the Istats to reset matching stat counters.
 */
static void
istat_counter_reset_cb(struct istat_entry *entp, struct stats *statp,
    const struct ipath *ipp)
{
	char *path;

	if (entp->ipath == ipp) {
		path = ipath2str(entp->ename, ipp);
		out(O_ALTFP, "istat_counter_reset_cb: resetting %s", path);
		FREE(path);
		stats_counter_reset(statp);
		Istat_need_save = 1;
	}
}

/*ARGSUSED*/
static void
istat_counter_topo_chg_cb(struct istat_entry *entp, struct stats *statp,
    void *unused)
{
	char *path;
	nvlist_t *fmri;

	fmri = ipath2fmri((struct ipath *)(entp->ipath));
	if (!platform_path_exists(fmri)) {
		path = ipath2str(entp->ename, entp->ipath);
		out(O_ALTFP, "istat_counter_topo_chg_cb: not present %s", path);
		FREE(path);
		stats_counter_reset(statp);
		Istat_need_save = 1;
	}
	nvlist_free(fmri);
}

void
istat_fini(void)
{
	lut_free(Istats, istat_destructor, NULL);
}

static char *Serdbuf;
static char *Serdbufptr;
static int Serdsz;

/*
 * serdaddsize -- calculate size of serd and add it to Serdsz
 */
/*ARGSUSED*/
static void
serdaddsize(const struct serd_entry *lhs, struct stats *rhs, void *arg)
{
	ASSERT(lhs != NULL);

	/* count up the size of the stat name */
	Serdsz += ipath2strlen(lhs->ename, lhs->ipath);
	Serdsz++;	/* for the trailing NULL byte */
}

/*
 * serd2str -- serialize a serd engine, writing result to *Serdbufptr
 */
/*ARGSUSED*/
static void
serd2str(const struct serd_entry *lhs, struct stats *rhs, void *arg)
{
	char *str;
	int len;

	ASSERT(lhs != NULL);

	/* serialize the serd engine name */
	str = ipath2str(lhs->ename, lhs->ipath);
	len = strlen(str);

	ASSERT(Serdbufptr + len + 1 <= &Serdbuf[Serdsz]);
	(void) strlcpy(Serdbufptr, str, &Serdbuf[Serdsz] - Serdbufptr);
	Serdbufptr += len;
	FREE(str);
	*Serdbufptr++ = '\0';
	ASSERT(Serdbufptr <= &Serdbuf[Serdsz]);
}

void
serd_save()
{
	if (Serd_need_save == 0)
		return;

	/* figure out how big the serialzed info is */
	Serdsz = 0;
	lut_walk(SerdEngines, (lut_cb)serdaddsize, NULL);

	if (Serdsz == 0) {
		/* no serd engines to save */
		fmd_buf_destroy(Hdl, NULL, WOBUF_SERDS);
		return;
	}

	/* create the serialized buffer */
	Serdbufptr = Serdbuf = MALLOC(Serdsz);
	lut_walk(SerdEngines, (lut_cb)serd2str, NULL);

	/* clear out current saved stats */
	fmd_buf_destroy(Hdl, NULL, WOBUF_SERDS);

	/* write out the new version */
	fmd_buf_write(Hdl, NULL, WOBUF_SERDS, Serdbuf, Serdsz);
	FREE(Serdbuf);
	Serd_need_save = 0;
}

int
serd_cmp(struct serd_entry *ent1, struct serd_entry *ent2)
{
	if (ent1->ename != ent2->ename)
		return (ent2->ename - ent1->ename);
	if (ent1->ipath != ent2->ipath)
		return ((char *)ent2->ipath - (char *)ent1->ipath);

	return (0);
}

void
fme_serd_load(fmd_hdl_t *hdl)
{
	int sz;
	char *sbuf;
	char *sepptr;
	char *ptr;
	struct serd_entry *newentp;
	struct node *epname;
	nvlist_t *fmri;
	char *namestring;

	if ((sz = fmd_buf_size(hdl, NULL, WOBUF_SERDS)) == 0)
		return;
	sbuf = alloca(sz);
	fmd_buf_read(hdl, NULL, WOBUF_SERDS, sbuf, sz);
	ptr = sbuf;
	while (ptr < &sbuf[sz]) {
		sepptr = strchr(ptr, '@');
		*sepptr = '\0';
		namestring = ptr;
		sepptr++;
		ptr = sepptr;
		ptr += strlen(ptr);
		ptr++;	/* move past the '\0' separating paths */
		epname = pathstring2epnamenp(sepptr);
		fmri = node2fmri(epname);
		if (platform_path_exists(fmri)) {
			newentp = MALLOC(sizeof (*newentp));
			newentp->hdl = hdl;
			newentp->ipath = ipath(epname);
			newentp->ename = stable(namestring);
			SerdEngines = lut_add(SerdEngines, (void *)newentp,
			    (void *)newentp, (lut_cmp)serd_cmp);
		} else
			Serd_need_save = 1;
		tree_free(epname);
		nvlist_free(fmri);
	}
	/* save it back again in case some of the paths no longer exist */
	serd_save();
}

/*ARGSUSED*/
static void
serd_destructor(void *left, void *right, void *arg)
{
	struct serd_entry *entp = (struct serd_entry *)left;
	FREE(entp);
}

/*
 * Callback used in a walk of the SerdEngines to reset matching serd engines.
 */
/*ARGSUSED*/
static void
serd_reset_cb(struct serd_entry *entp, void *unused, const struct ipath *ipp)
{
	char *path;

	if (entp->ipath == ipp) {
		path = ipath2str(entp->ename, ipp);
		out(O_ALTFP, "serd_reset_cb: resetting %s", path);
		fmd_serd_reset(entp->hdl, path);
		FREE(path);
		Serd_need_save = 1;
	}
}

/*ARGSUSED*/
static void
serd_topo_chg_cb(struct serd_entry *entp, void *unused, void *unused2)
{
	char *path;
	nvlist_t *fmri;

	fmri = ipath2fmri((struct ipath *)(entp->ipath));
	if (!platform_path_exists(fmri)) {
		path = ipath2str(entp->ename, entp->ipath);
		out(O_ALTFP, "serd_topo_chg_cb: not present %s", path);
		fmd_serd_reset(entp->hdl, path);
		FREE(path);
		Serd_need_save = 1;
	}
	nvlist_free(fmri);
}

void
serd_fini(void)
{
	lut_free(SerdEngines, serd_destructor, NULL);
}

static void
publish_suspects(struct fme *fmep, struct rsl *srl)
{
	struct rsl *rp;
	nvlist_t *fault;
	uint8_t cert;
	uint_t *frs;
	uint_t frsum, fr;
	uint_t messval;
	uint_t retireval;
	uint_t responseval;
	struct node *snp;
	int frcnt, fridx;
	boolean_t allfaulty = B_TRUE;
	struct rsl *erl = srl + fmep->nsuspects - 1;

	/*
	 * sort the array
	 */
	qsort(srl, fmep->nsuspects, sizeof (struct rsl), rslcmp);

	/* sum the fitrates */
	frs = alloca(fmep->nsuspects * sizeof (uint_t));
	fridx = frcnt = frsum = 0;

	for (rp = srl; rp <= erl; rp++) {
		struct node *n;

		n = eventprop_lookup(rp->suspect, L_FITrate);
		if (node2uint(n, &fr) != 0) {
			out(O_DEBUG|O_NONL, "event ");
			ipath_print(O_DEBUG|O_NONL,
			    rp->suspect->enode->u.event.ename->u.name.s,
			    rp->suspect->ipp);
			out(O_VERB, " has no FITrate (using 1)");
			fr = 1;
		} else if (fr == 0) {
			out(O_DEBUG|O_NONL, "event ");
			ipath_print(O_DEBUG|O_NONL,
			    rp->suspect->enode->u.event.ename->u.name.s,
			    rp->suspect->ipp);
			out(O_VERB, " has zero FITrate (using 1)");
			fr = 1;
		}

		frs[fridx++] = fr;
		frsum += fr;
		frcnt++;
	}

	/* Add them in reverse order of our sort, as fmd reverses order */
	for (rp = erl; rp >= srl; rp--) {
		cert = percentof(frs[--fridx], frsum);
		fault = fmd_nvl_create_fault(fmep->hdl,
		    rp->suspect->enode->u.event.ename->u.name.s,
		    cert,
		    rp->asru,
		    rp->fru,
		    rp->rsrc);
		if (fault == NULL)
			out(O_DIE, "fault creation failed");
		/* if "message" property exists, add it to the fault */
		if (node2uint(eventprop_lookup(rp->suspect, L_message),
		    &messval) == 0) {

			out(O_ALTFP,
			    "[FME%d, %s adds message=%d to suspect list]",
			    fmep->id,
			    rp->suspect->enode->u.event.ename->u.name.s,
			    messval);
			if (nvlist_add_boolean_value(fault,
			    FM_SUSPECT_MESSAGE,
			    (messval) ? B_TRUE : B_FALSE) != 0) {
				out(O_DIE, "cannot add no-message to fault");
			}
		}

		/* if "retire" property exists, add it to the fault */
		if (node2uint(eventprop_lookup(rp->suspect, L_retire),
		    &retireval) == 0) {

			out(O_ALTFP,
			    "[FME%d, %s adds retire=%d to suspect list]",
			    fmep->id,
			    rp->suspect->enode->u.event.ename->u.name.s,
			    retireval);
			if (nvlist_add_boolean_value(fault,
			    FM_SUSPECT_RETIRE,
			    (retireval) ? B_TRUE : B_FALSE) != 0) {
				out(O_DIE, "cannot add no-retire to fault");
			}
		}

		/* if "response" property exists, add it to the fault */
		if (node2uint(eventprop_lookup(rp->suspect, L_response),
		    &responseval) == 0) {

			out(O_ALTFP,
			    "[FME%d, %s adds response=%d to suspect list]",
			    fmep->id,
			    rp->suspect->enode->u.event.ename->u.name.s,
			    responseval);
			if (nvlist_add_boolean_value(fault,
			    FM_SUSPECT_RESPONSE,
			    (responseval) ? B_TRUE : B_FALSE) != 0) {
				out(O_DIE, "cannot add no-response to fault");
			}
		}

		/* add any payload properties */
		lut_walk(rp->suspect->payloadprops,
		    (lut_cb)addpayloadprop, (void *)fault);
		rslfree(rp);

		/*
		 * If "action" property exists, evaluate it;  this must be done
		 * before the allfaulty check below since some actions may
		 * modify the asru to be used in fmd_nvl_fmri_has_fault.  This
		 * needs to be restructured if any new actions are introduced
		 * that have effects that we do not want to be visible if
		 * we decide not to publish in the dupclose check below.
		 */
		if ((snp = eventprop_lookup(rp->suspect, L_action)) != NULL) {
			struct evalue evalue;

			out(O_ALTFP|O_NONL,
			    "[FME%d, %s action ", fmep->id,
			    rp->suspect->enode->u.event.ename->u.name.s);
			ptree_name_iter(O_ALTFP|O_NONL, snp);
			out(O_ALTFP, "]");
			Action_nvl = fault;
			(void) eval_expr(snp, NULL, NULL, NULL, NULL,
			    NULL, 0, &evalue);
		}

		fmd_case_add_suspect(fmep->hdl, fmep->fmcase, fault);

		/*
		 * check if the asru is already marked as "faulty".
		 */
		if (allfaulty) {
			nvlist_t *asru;

			out(O_ALTFP|O_VERB, "FME%d dup check ", fmep->id);
			itree_pevent_brief(O_ALTFP|O_VERB|O_NONL, rp->suspect);
			out(O_ALTFP|O_VERB|O_NONL, " ");
			if (nvlist_lookup_nvlist(fault,
			    FM_FAULT_ASRU, &asru) != 0) {
				out(O_ALTFP|O_VERB, "NULL asru");
				allfaulty = B_FALSE;
			} else if (fmd_nvl_fmri_has_fault(fmep->hdl, asru,
			    FMD_HAS_FAULT_ASRU, NULL)) {
				out(O_ALTFP|O_VERB, "faulty");
			} else {
				out(O_ALTFP|O_VERB, "not faulty");
				allfaulty = B_FALSE;
			}
		}

	}

	if (!allfaulty) {
		/*
		 * don't update the count stat if all asrus are already
		 * present and unrepaired in the asru cache
		 */
		for (rp = erl; rp >= srl; rp--) {
			struct event *suspect = rp->suspect;

			if (suspect == NULL)
				continue;

			/* if "count" exists, increment the appropriate stat */
			if ((snp = eventprop_lookup(suspect,
			    L_count)) != NULL) {
				out(O_ALTFP|O_NONL,
				    "[FME%d, %s count ", fmep->id,
				    suspect->enode->u.event.ename->u.name.s);
				ptree_name_iter(O_ALTFP|O_NONL, snp);
				out(O_ALTFP, "]");
				istat_bump(snp, 0);

			}
		}
		istat_save();	/* write out any istat changes */
	}
}

static const char *
undiag_2defect_str(int ud)
{
	switch (ud) {
	case UD_VAL_MISSINGINFO:
	case UD_VAL_MISSINGOBS:
	case UD_VAL_MISSINGPATH:
	case UD_VAL_MISSINGZERO:
	case UD_VAL_BADOBS:
	case UD_VAL_CFGMISMATCH:
		return (UNDIAG_DEFECT_CHKPT);

	case UD_VAL_BADEVENTI:
	case UD_VAL_BADEVENTPATH:
	case UD_VAL_BADEVENTCLASS:
	case UD_VAL_INSTFAIL:
	case UD_VAL_NOPATH:
	case UD_VAL_UNSOLVD:
		return (UNDIAG_DEFECT_FME);

	case UD_VAL_MAXFME:
		return (UNDIAG_DEFECT_LIMIT);

	case UD_VAL_UNKNOWN:
	default:
		return (UNDIAG_DEFECT_UNKNOWN);
	}
}

static const char *
undiag_2fault_str(int ud)
{
	switch (ud) {
	case UD_VAL_BADEVENTI:
	case UD_VAL_BADEVENTPATH:
	case UD_VAL_BADEVENTCLASS:
	case UD_VAL_INSTFAIL:
	case UD_VAL_NOPATH:
	case UD_VAL_UNSOLVD:
		return (UNDIAG_FAULT_FME);
	default:
		return (NULL);
	}
}

static char *
undiag_2reason_str(int ud, char *arg)
{
	const char *ptr;
	char *buf;
	int with_arg = 0;

	switch (ud) {
	case UD_VAL_BADEVENTPATH:
		ptr = UD_STR_BADEVENTPATH;
		with_arg = 1;
		break;
	case UD_VAL_BADEVENTCLASS:
		ptr = UD_STR_BADEVENTCLASS;
		with_arg = 1;
		break;
	case UD_VAL_BADEVENTI:
		ptr = UD_STR_BADEVENTI;
		with_arg = 1;
		break;
	case UD_VAL_BADOBS:
		ptr = UD_STR_BADOBS;
		break;
	case UD_VAL_CFGMISMATCH:
		ptr = UD_STR_CFGMISMATCH;
		break;
	case UD_VAL_INSTFAIL:
		ptr = UD_STR_INSTFAIL;
		with_arg = 1;
		break;
	case UD_VAL_MAXFME:
		ptr = UD_STR_MAXFME;
		break;
	case UD_VAL_MISSINGINFO:
		ptr = UD_STR_MISSINGINFO;
		break;
	case UD_VAL_MISSINGOBS:
		ptr = UD_STR_MISSINGOBS;
		break;
	case UD_VAL_MISSINGPATH:
		ptr = UD_STR_MISSINGPATH;
		break;
	case UD_VAL_MISSINGZERO:
		ptr = UD_STR_MISSINGZERO;
		break;
	case UD_VAL_NOPATH:
		ptr = UD_STR_NOPATH;
		with_arg = 1;
		break;
	case UD_VAL_UNSOLVD:
		ptr = UD_STR_UNSOLVD;
		break;
	case UD_VAL_UNKNOWN:
	default:
		ptr = UD_STR_UNKNOWN;
		break;
	}
	if (with_arg) {
		buf = MALLOC(strlen(ptr) + strlen(arg) - 1);
		(void) sprintf(buf, ptr, arg);
	} else {
		buf = MALLOC(strlen(ptr) + 1);
		(void) sprintf(buf, ptr);
	}
	return (buf);
}

static void
publish_undiagnosable(fmd_hdl_t *hdl, fmd_event_t *ffep, fmd_case_t *fmcase,
    nvlist_t *detector, char *arg)
{
	struct case_list *newcase;
	nvlist_t *defect, *fault;
	const char *faultstr;
	char *reason = undiag_2reason_str(Undiag_reason, arg);

	out(O_ALTFP,
	    "[undiagnosable ereport received, "
	    "creating and closing a new case (%s)]", reason);

	newcase = MALLOC(sizeof (struct case_list));
	newcase->next = NULL;
	newcase->fmcase = fmcase;
	if (Undiagablecaselist != NULL)
		newcase->next = Undiagablecaselist;
	Undiagablecaselist = newcase;

	if (ffep != NULL)
		fmd_case_add_ereport(hdl, newcase->fmcase, ffep);

	/* add defect */
	defect = fmd_nvl_create_fault(hdl,
	    undiag_2defect_str(Undiag_reason), 50, NULL, NULL, detector);
	(void) nvlist_add_string(defect, UNDIAG_REASON, reason);
	(void) nvlist_add_boolean_value(defect, FM_SUSPECT_RETIRE, B_FALSE);
	(void) nvlist_add_boolean_value(defect, FM_SUSPECT_RESPONSE, B_FALSE);
	fmd_case_add_suspect(hdl, newcase->fmcase, defect);

	/* add fault if appropriate */
	faultstr = undiag_2fault_str(Undiag_reason);
	if (faultstr != NULL) {
		fault = fmd_nvl_create_fault(hdl, faultstr, 50, NULL, NULL,
		    detector);
		(void) nvlist_add_string(fault, UNDIAG_REASON, reason);
		(void) nvlist_add_boolean_value(fault, FM_SUSPECT_RETIRE,
		    B_FALSE);
		(void) nvlist_add_boolean_value(fault, FM_SUSPECT_RESPONSE,
		    B_FALSE);
		fmd_case_add_suspect(hdl, newcase->fmcase, fault);
	}
	FREE(reason);

	/* solve and close case */
	fmd_case_solve(hdl, newcase->fmcase);
	fmd_case_close(hdl, newcase->fmcase);
	Undiag_reason = UD_VAL_UNKNOWN;
}

static void
fme_undiagnosable(struct fme *f)
{
	nvlist_t *defect, *fault, *detector = NULL;
	struct event *ep;
	char *pathstr;
	const char *faultstr;
	char *reason = undiag_2reason_str(Undiag_reason, NULL);

	out(O_ALTFP, "[solving/closing FME%d, case %s (%s)]",
	    f->id, fmd_case_uuid(f->hdl, f->fmcase), reason);

	for (ep = f->observations; ep; ep = ep->observations) {

		if (ep->ffep != f->e0r)
			fmd_case_add_ereport(f->hdl, f->fmcase, ep->ffep);

		pathstr = ipath2str(NULL, ipath(platform_getpath(ep->nvp)));
		platform_units_translate(0, f->config, NULL, NULL, &detector,
		    pathstr);
		FREE(pathstr);

		/* add defect */
		defect = fmd_nvl_create_fault(f->hdl,
		    undiag_2defect_str(Undiag_reason), 50 / f->uniqobs,
		    NULL, NULL, detector);
		(void) nvlist_add_string(defect, UNDIAG_REASON, reason);
		(void) nvlist_add_boolean_value(defect, FM_SUSPECT_RETIRE,
		    B_FALSE);
		(void) nvlist_add_boolean_value(defect, FM_SUSPECT_RESPONSE,
		    B_FALSE);
		fmd_case_add_suspect(f->hdl, f->fmcase, defect);

		/* add fault if appropriate */
		faultstr = undiag_2fault_str(Undiag_reason);
		if (faultstr == NULL)
			continue;
		fault = fmd_nvl_create_fault(f->hdl, faultstr, 50 / f->uniqobs,
		    NULL, NULL, detector);
		(void) nvlist_add_string(fault, UNDIAG_REASON, reason);
		(void) nvlist_add_boolean_value(fault, FM_SUSPECT_RETIRE,
		    B_FALSE);
		(void) nvlist_add_boolean_value(fault, FM_SUSPECT_RESPONSE,
		    B_FALSE);
		fmd_case_add_suspect(f->hdl, f->fmcase, fault);
		nvlist_free(detector);
	}
	FREE(reason);
	fmd_case_solve(f->hdl, f->fmcase);
	fmd_case_close(f->hdl, f->fmcase);
	Undiag_reason = UD_VAL_UNKNOWN;
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

	Open_fme_count--;

	/* See if we can close the overflow FME */
	if (Open_fme_count <= Max_fme) {
		for (fmep = FMElist; fmep; fmep = fmep->next) {
			if (fmep->overflow && !(fmd_case_closed(fmep->hdl,
			    fmep->fmcase)))
				break;
		}

		if (fmep != NULL)
			fmd_case_close(fmep->hdl, fmep->fmcase);
	}
}

/*
 * fme_set_timer()
 *	If the time we need to wait for the given FME is less than the
 *	current timer, kick that old timer out and establish a new one.
 */
static int
fme_set_timer(struct fme *fmep, unsigned long long wull)
{
	out(O_ALTFP|O_VERB|O_NONL, " fme_set_timer: request to wait ");
	ptree_timeval(O_ALTFP|O_VERB, &wull);

	if (wull <= fmep->pull) {
		out(O_ALTFP|O_VERB|O_NONL, "already have waited at least ");
		ptree_timeval(O_ALTFP|O_VERB, &fmep->pull);
		out(O_ALTFP|O_VERB, NULL);
		/* we've waited at least wull already, don't need timer */
		return (0);
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
			return (0);

	if (fmep->wull != 0) {
		fmd_timer_remove(fmep->hdl, fmep->timer);
	}

	fmep->timer = fmd_timer_install(fmep->hdl, (void *)fmep,
	    fmep->e0r, wull);
	out(O_ALTFP|O_VERB, "timer set, id is %ld", fmep->timer);
	fmep->wull = wull;
	return (1);
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

	out(O_ALTFP|O_VERB, "Timer fired %lx", tid);
	fmep->pull = fmep->wull;
	fmep->wull = 0;
	fmd_buf_write(fmep->hdl, fmep->fmcase,
	    WOBUF_PULL, (void *)&fmep->pull, sizeof (fmep->pull));

	fme_eval(fmep, fmep->e0r);
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
}

/*
 * Retrieve the fme's suspect list from its psuspects list.
 */
static void
restore_suspects(struct fme *fmep)
{
	struct event *ep;
	struct event *nextep;

	fmep->nsuspects = 0;
	fmep->suspects = fmep->psuspects;
	for (ep = fmep->psuspects; ep; ep = nextep) {
		fmep->nsuspects++;
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
	struct rsl *srl = NULL;
	struct rsl *srl2 = NULL;
	int mess_zero_count;
	int rpcnt;

	save_suspects(fmep);

	out(O_ALTFP, "Evaluate FME %d", fmep->id);
	indent_set("  ");

	lut_walk(fmep->eventtree, (lut_cb)clear_arrows, (void *)fmep);
	fmep->state = hypothesise(fmep, fmep->e0, fmep->ull, &my_delay);

	out(O_ALTFP|O_NONL, "FME%d state: %s, suspect list:", fmep->id,
	    fme_state2str(fmep->state));
	for (ep = fmep->suspects; ep; ep = ep->suspects) {
		out(O_ALTFP|O_NONL, " ");
		itree_pevent_brief(O_ALTFP|O_NONL, ep);
	}
	out(O_ALTFP, NULL);

	switch (fmep->state) {
	case FME_CREDIBLE:
		print_suspects(SLNEW, fmep);
		(void) upsets_eval(fmep, ffep);

		/*
		 * we may have already posted suspects in upsets_eval() which
		 * can recurse into fme_eval() again. If so then just return.
		 */
		if (fmep->posted_suspects)
			return;

		stats_counter_bump(fmep->diags);
		rpcnt = fmep->nsuspects;
		save_suspects(fmep);

		/*
		 * create two lists, one for "message=1" faults and one for
		 * "message=0" faults. If we have a mixture we will generate
		 * two separate suspect lists.
		 */
		srl = MALLOC(rpcnt * sizeof (struct rsl));
		bzero(srl, rpcnt * sizeof (struct rsl));
		srl2 = MALLOC(rpcnt * sizeof (struct rsl));
		bzero(srl2, rpcnt * sizeof (struct rsl));
		mess_zero_count = trim_suspects(fmep, srl, srl2, ffep);

		/*
		 * If the resulting suspect list has no members, we're
		 * done so simply close the case. Otherwise sort and publish.
		 */
		if (fmep->nsuspects == 0 && mess_zero_count == 0) {
			out(O_ALTFP,
			    "[FME%d, case %s (all suspects are upsets)]",
			    fmep->id, fmd_case_uuid(fmep->hdl, fmep->fmcase));
			fmd_case_close(fmep->hdl, fmep->fmcase);
		} else if (fmep->nsuspects != 0 && mess_zero_count == 0) {
			publish_suspects(fmep, srl);
			out(O_ALTFP, "[solving FME%d, case %s]", fmep->id,
			    fmd_case_uuid(fmep->hdl, fmep->fmcase));
			fmd_case_solve(fmep->hdl, fmep->fmcase);
		} else if (fmep->nsuspects == 0 && mess_zero_count != 0) {
			fmep->nsuspects = mess_zero_count;
			publish_suspects(fmep, srl2);
			out(O_ALTFP, "[solving FME%d, case %s]", fmep->id,
			    fmd_case_uuid(fmep->hdl, fmep->fmcase));
			fmd_case_solve(fmep->hdl, fmep->fmcase);
		} else {
			struct event *obsp;
			struct fme *nfmep;

			publish_suspects(fmep, srl);
			out(O_ALTFP, "[solving FME%d, case %s]", fmep->id,
			    fmd_case_uuid(fmep->hdl, fmep->fmcase));
			fmd_case_solve(fmep->hdl, fmep->fmcase);

			/*
			 * Got both message=0 and message=1 so create a
			 * duplicate case. Also need a temporary duplicate fme
			 * structure for use by publish_suspects().
			 */
			nfmep = alloc_fme();
			nfmep->id =  Nextid++;
			nfmep->hdl = fmep->hdl;
			nfmep->nsuspects = mess_zero_count;
			nfmep->fmcase = fmd_case_open(fmep->hdl, NULL);
			out(O_ALTFP|O_STAMP,
			    "[creating parallel FME%d, case %s]", nfmep->id,
			    fmd_case_uuid(nfmep->hdl, nfmep->fmcase));
			Open_fme_count++;
			if (ffep) {
				fmd_case_setprincipal(nfmep->hdl,
				    nfmep->fmcase, ffep);
				fmd_case_add_ereport(nfmep->hdl,
				    nfmep->fmcase, ffep);
			}
			for (obsp = fmep->observations; obsp;
			    obsp = obsp->observations)
				if (obsp->ffep && obsp->ffep != ffep)
					fmd_case_add_ereport(nfmep->hdl,
					    nfmep->fmcase, obsp->ffep);

			publish_suspects(nfmep, srl2);
			out(O_ALTFP, "[solving FME%d, case %s]", nfmep->id,
			    fmd_case_uuid(nfmep->hdl, nfmep->fmcase));
			fmd_case_solve(nfmep->hdl, nfmep->fmcase);
			FREE(nfmep);
		}
		FREE(srl);
		FREE(srl2);
		restore_suspects(fmep);

		fmep->posted_suspects = 1;
		fmd_buf_write(fmep->hdl, fmep->fmcase,
		    WOBUF_POSTD,
		    (void *)&fmep->posted_suspects,
		    sizeof (fmep->posted_suspects));

		/*
		 * Now the suspects have been posted, we can clear up
		 * the instance tree as we won't be looking at it again.
		 * Also cancel the timer as the case is now solved.
		 */
		if (fmep->wull != 0) {
			fmd_timer_remove(fmep->hdl, fmep->timer);
			fmep->wull = 0;
		}
		break;

	case FME_WAIT:
		ASSERT(my_delay > fmep->ull);
		(void) fme_set_timer(fmep, my_delay);
		print_suspects(SLWAIT, fmep);
		itree_prune(fmep->eventtree);
		return;

	case FME_DISPROVED:
		print_suspects(SLDISPROVED, fmep);
		Undiag_reason = UD_VAL_UNSOLVD;
		fme_undiagnosable(fmep);
		break;
	}

	itree_free(fmep->eventtree);
	fmep->eventtree = NULL;
	structconfig_free(fmep->config);
	fmep->config = NULL;
	destroy_fme_bufs(fmep);
}

static void indent(void);
static int triggered(struct fme *fmep, struct event *ep, int mark);
static enum fme_state effects_test(struct fme *fmep,
    struct event *fault_event, unsigned long long at_latest_by,
    unsigned long long *pdelay);
static enum fme_state requirements_test(struct fme *fmep, struct event *ep,
    unsigned long long at_latest_by, unsigned long long *pdelay);
static enum fme_state causes_test(struct fme *fmep, struct event *ep,
    unsigned long long at_latest_by, unsigned long long *pdelay);

static int
checkconstraints(struct fme *fmep, struct arrow *arrowp)
{
	struct constraintlist *ctp;
	struct evalue value;
	char *sep = "";

	if (arrowp->forever_false) {
		indent();
		out(O_ALTFP|O_VERB|O_NONL, "  Forever false constraint: ");
		for (ctp = arrowp->constraints; ctp != NULL; ctp = ctp->next) {
			out(O_ALTFP|O_VERB|O_NONL, sep);
			ptree(O_ALTFP|O_VERB|O_NONL, ctp->cnode, 1, 0);
			sep = ", ";
		}
		out(O_ALTFP|O_VERB, NULL);
		return (0);
	}
	if (arrowp->forever_true) {
		indent();
		out(O_ALTFP|O_VERB|O_NONL, "  Forever true constraint: ");
		for (ctp = arrowp->constraints; ctp != NULL; ctp = ctp->next) {
			out(O_ALTFP|O_VERB|O_NONL, sep);
			ptree(O_ALTFP|O_VERB|O_NONL, ctp->cnode, 1, 0);
			sep = ", ";
		}
		out(O_ALTFP|O_VERB, NULL);
		return (1);
	}

	for (ctp = arrowp->constraints; ctp != NULL; ctp = ctp->next) {
		if (eval_expr(ctp->cnode, NULL, NULL,
		    &fmep->globals, fmep->config,
		    arrowp, 0, &value)) {
			/* evaluation successful */
			if (value.t == UNDEFINED || value.v == 0) {
				/* known false */
				arrowp->forever_false = 1;
				indent();
				out(O_ALTFP|O_VERB|O_NONL,
				    "  False constraint: ");
				ptree(O_ALTFP|O_VERB|O_NONL, ctp->cnode, 1, 0);
				out(O_ALTFP|O_VERB, NULL);
				return (0);
			}
		} else {
			/* evaluation unsuccessful -- unknown value */
			indent();
			out(O_ALTFP|O_VERB|O_NONL,
			    "  Deferred constraint: ");
			ptree(O_ALTFP|O_VERB|O_NONL, ctp->cnode, 1, 0);
			out(O_ALTFP|O_VERB, NULL);
			return (1);
		}
	}
	/* known true */
	arrowp->forever_true = 1;
	indent();
	out(O_ALTFP|O_VERB|O_NONL, "  True constraint: ");
	for (ctp = arrowp->constraints; ctp != NULL; ctp = ctp->next) {
		out(O_ALTFP|O_VERB|O_NONL, sep);
		ptree(O_ALTFP|O_VERB|O_NONL, ctp->cnode, 1, 0);
		sep = ", ";
	}
	out(O_ALTFP|O_VERB, NULL);
	return (1);
}

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
			if ((ap->arrowp->mark & mark) &&
			    ++count >= bp->nork)
				return (1);
		}
	}
	return (0);
}

static int
mark_arrows(struct fme *fmep, struct event *ep, int mark,
    unsigned long long at_latest_by, unsigned long long *pdelay, int keep)
{
	struct bubble *bp;
	struct arrowlist *ap;
	unsigned long long overall_delay = TIMEVAL_EVENTUALLY;
	unsigned long long my_delay;
	enum fme_state result;
	int retval = 0;

	for (bp = itree_next_bubble(ep, NULL); bp;
	    bp = itree_next_bubble(ep, bp)) {
		if (bp->t != B_FROM)
			continue;
		stats_counter_bump(fmep->Marrowcount);
		for (ap = itree_next_arrow(bp, NULL); ap;
		    ap = itree_next_arrow(bp, ap)) {
			struct event *ep2 = ap->arrowp->head->myevent;
			/*
			 * if we're clearing marks, we can avoid doing
			 * all that work evaluating constraints.
			 */
			if (mark == 0) {
				if (ap->arrowp->arrow_marked == 0)
					continue;
				ap->arrowp->arrow_marked = 0;
				ap->arrowp->mark &= ~EFFECTS_COUNTER;
				if (keep && (ep2->cached_state &
				    (WAIT_EFFECT|CREDIBLE_EFFECT|PARENT_WAIT)))
					ep2->keep_in_tree = 1;
				ep2->cached_state &=
				    ~(WAIT_EFFECT|CREDIBLE_EFFECT|PARENT_WAIT);
				(void) mark_arrows(fmep, ep2, mark, 0, NULL,
				    keep);
				continue;
			}
			ap->arrowp->arrow_marked = 1;
			if (ep2->cached_state & REQMNTS_DISPROVED) {
				indent();
				out(O_ALTFP|O_VERB|O_NONL,
				    "  ALREADY DISPROVED ");
				itree_pevent_brief(O_ALTFP|O_VERB|O_NONL, ep2);
				out(O_ALTFP|O_VERB, NULL);
				continue;
			}
			if (ep2->cached_state & WAIT_EFFECT) {
				indent();
				out(O_ALTFP|O_VERB|O_NONL,
				    "  ALREADY EFFECTS WAIT ");
				itree_pevent_brief(O_ALTFP|O_VERB|O_NONL, ep2);
				out(O_ALTFP|O_VERB, NULL);
				continue;
			}
			if (ep2->cached_state & CREDIBLE_EFFECT) {
				indent();
				out(O_ALTFP|O_VERB|O_NONL,
				    "  ALREADY EFFECTS CREDIBLE ");
				itree_pevent_brief(O_ALTFP|O_VERB|O_NONL, ep2);
				out(O_ALTFP|O_VERB, NULL);
				continue;
			}
			if ((ep2->cached_state & PARENT_WAIT) &&
			    (mark & PARENT_WAIT)) {
				indent();
				out(O_ALTFP|O_VERB|O_NONL,
				    "  ALREADY PARENT EFFECTS WAIT ");
				itree_pevent_brief(O_ALTFP|O_VERB|O_NONL, ep2);
				out(O_ALTFP|O_VERB, NULL);
				continue;
			}
			platform_set_payloadnvp(ep2->nvp);
			if (checkconstraints(fmep, ap->arrowp) == 0) {
				platform_set_payloadnvp(NULL);
				indent();
				out(O_ALTFP|O_VERB|O_NONL,
				    "  CONSTRAINTS FAIL ");
				itree_pevent_brief(O_ALTFP|O_VERB|O_NONL, ep2);
				out(O_ALTFP|O_VERB, NULL);
				continue;
			}
			platform_set_payloadnvp(NULL);
			ap->arrowp->mark |= EFFECTS_COUNTER;
			if (!triggered(fmep, ep2, EFFECTS_COUNTER)) {
				indent();
				out(O_ALTFP|O_VERB|O_NONL,
				    "  K-COUNT NOT YET MET ");
				itree_pevent_brief(O_ALTFP|O_VERB|O_NONL, ep2);
				out(O_ALTFP|O_VERB, NULL);
				continue;
			}
			ep2->cached_state &= ~PARENT_WAIT;
			/*
			 * if we've reached an ereport and no propagation time
			 * is specified, use the Hesitate value
			 */
			if (ep2->t == N_EREPORT && at_latest_by == 0ULL &&
			    ap->arrowp->maxdelay == 0ULL) {
				out(O_ALTFP|O_VERB|O_NONL, "  default wait ");
				itree_pevent_brief(O_ALTFP|O_VERB|O_NONL, ep2);
				out(O_ALTFP|O_VERB, NULL);
				result = requirements_test(fmep, ep2, Hesitate,
				    &my_delay);
			} else {
				result = requirements_test(fmep, ep2,
				    at_latest_by + ap->arrowp->maxdelay,
				    &my_delay);
			}
			if (result == FME_WAIT) {
				retval = WAIT_EFFECT;
				if (overall_delay > my_delay)
					overall_delay = my_delay;
				ep2->cached_state |= WAIT_EFFECT;
				indent();
				out(O_ALTFP|O_VERB|O_NONL, "  EFFECTS WAIT ");
				itree_pevent_brief(O_ALTFP|O_VERB|O_NONL, ep2);
				out(O_ALTFP|O_VERB, NULL);
				indent_push("  E");
				if (mark_arrows(fmep, ep2, PARENT_WAIT,
				    at_latest_by, &my_delay, 0) ==
				    WAIT_EFFECT) {
					retval = WAIT_EFFECT;
					if (overall_delay > my_delay)
						overall_delay = my_delay;
				}
				indent_pop();
			} else if (result == FME_DISPROVED) {
				indent();
				out(O_ALTFP|O_VERB|O_NONL,
				    "  EFFECTS DISPROVED ");
				itree_pevent_brief(O_ALTFP|O_VERB|O_NONL, ep2);
				out(O_ALTFP|O_VERB, NULL);
			} else {
				ep2->cached_state |= mark;
				indent();
				if (mark == CREDIBLE_EFFECT)
					out(O_ALTFP|O_VERB|O_NONL,
					    "  EFFECTS CREDIBLE ");
				else
					out(O_ALTFP|O_VERB|O_NONL,
					    "  PARENT EFFECTS WAIT ");
				itree_pevent_brief(O_ALTFP|O_VERB|O_NONL, ep2);
				out(O_ALTFP|O_VERB, NULL);
				indent_push("  E");
				if (mark_arrows(fmep, ep2, mark, at_latest_by,
				    &my_delay, 0) == WAIT_EFFECT) {
					retval = WAIT_EFFECT;
					if (overall_delay > my_delay)
						overall_delay = my_delay;
				}
				indent_pop();
			}
		}
	}
	if (retval == WAIT_EFFECT)
		*pdelay = overall_delay;
	return (retval);
}

static enum fme_state
effects_test(struct fme *fmep, struct event *fault_event,
    unsigned long long at_latest_by, unsigned long long *pdelay)
{
	struct event *error_event;
	enum fme_state return_value = FME_CREDIBLE;
	unsigned long long overall_delay = TIMEVAL_EVENTUALLY;
	unsigned long long my_delay;

	stats_counter_bump(fmep->Ecallcount);
	indent_push("  E");
	indent();
	out(O_ALTFP|O_VERB|O_NONL, "->");
	itree_pevent_brief(O_ALTFP|O_VERB|O_NONL, fault_event);
	out(O_ALTFP|O_VERB, NULL);

	if (mark_arrows(fmep, fault_event, CREDIBLE_EFFECT, at_latest_by,
	    &my_delay, 0) == WAIT_EFFECT) {
		return_value = FME_WAIT;
		if (overall_delay > my_delay)
			overall_delay = my_delay;
	}
	for (error_event = fmep->observations;
	    error_event; error_event = error_event->observations) {
		indent();
		out(O_ALTFP|O_VERB|O_NONL, " ");
		itree_pevent_brief(O_ALTFP|O_VERB|O_NONL, error_event);
		if (!(error_event->cached_state & CREDIBLE_EFFECT)) {
			if (error_event->cached_state &
			    (PARENT_WAIT|WAIT_EFFECT)) {
				out(O_ALTFP|O_VERB, " NOT YET triggered");
				continue;
			}
			return_value = FME_DISPROVED;
			out(O_ALTFP|O_VERB, " NOT triggered");
			break;
		} else {
			out(O_ALTFP|O_VERB, " triggered");
		}
	}
	if (return_value == FME_DISPROVED) {
		(void) mark_arrows(fmep, fault_event, 0, 0, NULL, 0);
	} else {
		fault_event->keep_in_tree = 1;
		(void) mark_arrows(fmep, fault_event, 0, 0, NULL, 1);
	}

	indent();
	out(O_ALTFP|O_VERB|O_NONL, "<-EFFECTS %s ",
	    fme_state2str(return_value));
	itree_pevent_brief(O_ALTFP|O_VERB|O_NONL, fault_event);
	out(O_ALTFP|O_VERB, NULL);
	indent_pop();
	if (return_value == FME_WAIT)
		*pdelay = overall_delay;
	return (return_value);
}

static enum fme_state
requirements_test(struct fme *fmep, struct event *ep,
    unsigned long long at_latest_by, unsigned long long *pdelay)
{
	int waiting_events;
	int credible_events;
	int deferred_events;
	enum fme_state return_value = FME_CREDIBLE;
	unsigned long long overall_delay = TIMEVAL_EVENTUALLY;
	unsigned long long arrow_delay;
	unsigned long long my_delay;
	struct event *ep2;
	struct bubble *bp;
	struct arrowlist *ap;

	if (ep->cached_state & REQMNTS_CREDIBLE) {
		indent();
		out(O_ALTFP|O_VERB|O_NONL, "  REQMNTS ALREADY CREDIBLE ");
		itree_pevent_brief(O_ALTFP|O_VERB|O_NONL, ep);
		out(O_ALTFP|O_VERB, NULL);
		return (FME_CREDIBLE);
	}
	if (ep->cached_state & REQMNTS_DISPROVED) {
		indent();
		out(O_ALTFP|O_VERB|O_NONL, "  REQMNTS ALREADY DISPROVED ");
		itree_pevent_brief(O_ALTFP|O_VERB|O_NONL, ep);
		out(O_ALTFP|O_VERB, NULL);
		return (FME_DISPROVED);
	}
	if (ep->cached_state & REQMNTS_WAIT) {
		indent();
		*pdelay = ep->cached_delay;
		out(O_ALTFP|O_VERB|O_NONL, "  REQMNTS ALREADY WAIT ");
		itree_pevent_brief(O_ALTFP|O_VERB|O_NONL, ep);
		out(O_ALTFP|O_VERB|O_NONL, ", wait for: ");
		ptree_timeval(O_ALTFP|O_VERB|O_NONL, &at_latest_by);
		out(O_ALTFP|O_VERB, NULL);
		return (FME_WAIT);
	}
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
				ep->cached_delay = *pdelay = at_latest_by;
				return_value = FME_WAIT;
			}
		}

		indent();
		switch (return_value) {
		case FME_CREDIBLE:
			ep->cached_state |= REQMNTS_CREDIBLE;
			out(O_ALTFP|O_VERB|O_NONL, "<-REQMNTS CREDIBLE ");
			itree_pevent_brief(O_ALTFP|O_VERB|O_NONL, ep);
			break;
		case FME_DISPROVED:
			ep->cached_state |= REQMNTS_DISPROVED;
			out(O_ALTFP|O_VERB|O_NONL, "<-REQMNTS DISPROVED ");
			itree_pevent_brief(O_ALTFP|O_VERB|O_NONL, ep);
			break;
		case FME_WAIT:
			ep->cached_state |= REQMNTS_WAIT;
			out(O_ALTFP|O_VERB|O_NONL, "<-REQMNTS WAIT ");
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
		int n;

		if (bp->t != B_FROM)
			continue;

		n = bp->nork;

		credible_events = 0;
		waiting_events = 0;
		deferred_events = 0;
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

		if (n == 0)
			continue;
		if (!(bp->mark & (BUBBLE_ELIDED|BUBBLE_OK))) {
			for (ap = itree_next_arrow(bp, NULL); ap;
			    ap = itree_next_arrow(bp, ap)) {
				ep2 = ap->arrowp->head->myevent;
				platform_set_payloadnvp(ep2->nvp);
				(void) checkconstraints(fmep, ap->arrowp);
				if (!ap->arrowp->forever_false) {
					/*
					 * if all arrows are invalidated by the
					 * constraints, then we should elide the
					 * whole bubble to be consistant with
					 * the tree creation time behaviour
					 */
					bp->mark |= BUBBLE_OK;
					platform_set_payloadnvp(NULL);
					break;
				}
				platform_set_payloadnvp(NULL);
			}
		}
		for (ap = itree_next_arrow(bp, NULL); ap;
		    ap = itree_next_arrow(bp, ap)) {
			ep2 = ap->arrowp->head->myevent;
			if (n <= credible_events)
				break;

			ap->arrowp->mark |= REQMNTS_COUNTER;
			if (triggered(fmep, ep2, REQMNTS_COUNTER))
				/* XXX adding max timevals! */
				switch (requirements_test(fmep, ep2,
				    at_latest_by + ap->arrowp->maxdelay,
				    &my_delay)) {
				case FME_DEFERRED:
					deferred_events++;
					break;
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
				deferred_events++;
		}
		if (!(bp->mark & BUBBLE_OK) && waiting_events == 0) {
			bp->mark |= BUBBLE_ELIDED;
			continue;
		}
		indent();
		out(O_ALTFP|O_VERB, " Credible: %d Waiting %d",
		    credible_events + deferred_events, waiting_events);
		if (credible_events + deferred_events + waiting_events < n) {
			/* Can never meet requirements */
			ep->cached_state |= REQMNTS_DISPROVED;
			indent();
			out(O_ALTFP|O_VERB|O_NONL, "<-REQMNTS DISPROVED ");
			itree_pevent_brief(O_ALTFP|O_VERB|O_NONL, ep);
			out(O_ALTFP|O_VERB, NULL);
			indent_pop();
			return (FME_DISPROVED);
		}
		if (credible_events + deferred_events < n) {
			/* will have to wait */
			/* wait time is shortest known */
			if (arrow_delay < overall_delay)
				overall_delay = arrow_delay;
			return_value = FME_WAIT;
		} else if (credible_events < n) {
			if (return_value != FME_WAIT)
				return_value = FME_DEFERRED;
		}
	}

	/*
	 * don't mark as FME_DEFERRED. If this event isn't reached by another
	 * path, then this will be considered FME_CREDIBLE. But if it is
	 * reached by a different path so the K-count is met, then might
	 * get overridden by FME_WAIT or FME_DISPROVED.
	 */
	if (return_value == FME_WAIT) {
		ep->cached_state |= REQMNTS_WAIT;
		ep->cached_delay = *pdelay = overall_delay;
	} else if (return_value == FME_CREDIBLE) {
		ep->cached_state |= REQMNTS_CREDIBLE;
	}
	indent();
	out(O_ALTFP|O_VERB|O_NONL, "<-REQMNTS %s ",
	    fme_state2str(return_value));
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
			int do_not_follow = 0;

			/*
			 * if we get to the same event multiple times
			 * only worry about the first one.
			 */
			if (ap->arrowp->tail->myevent->cached_state &
			    CAUSES_TESTED) {
				indent();
				out(O_ALTFP|O_VERB|O_NONL,
				    "  causes test already run for ");
				itree_pevent_brief(O_ALTFP|O_VERB|O_NONL,
				    ap->arrowp->tail->myevent);
				out(O_ALTFP|O_VERB, NULL);
				continue;
			}

			/*
			 * see if false constraint prevents us
			 * from traversing this arrow
			 */
			platform_set_payloadnvp(ep->nvp);
			if (checkconstraints(fmep, ap->arrowp) == 0)
				do_not_follow = 1;
			platform_set_payloadnvp(NULL);
			if (do_not_follow) {
				indent();
				out(O_ALTFP|O_VERB|O_NONL,
				    "  False arrow from ");
				itree_pevent_brief(O_ALTFP|O_VERB|O_NONL,
				    ap->arrowp->tail->myevent);
				out(O_ALTFP|O_VERB, NULL);
				continue;
			}

			ap->arrowp->tail->myevent->cached_state |=
			    CAUSES_TESTED;
			tail_event = ap->arrowp->tail->myevent;
			fstate = hypothesise(fmep, tail_event, at_latest_by,
			    &my_delay);

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
		}
	}
	/* compare against K */
	if (credible_results + waiting_results < k) {
		indent();
		out(O_ALTFP|O_VERB|O_NONL, "<-CAUSES DISPROVED ");
		itree_pevent_brief(O_ALTFP|O_VERB|O_NONL, ep);
		out(O_ALTFP|O_VERB, NULL);
		indent_pop();
		return (FME_DISPROVED);
	}
	if (waiting_results != 0) {
		*pdelay = overall_delay;
		indent();
		out(O_ALTFP|O_VERB|O_NONL, "<-CAUSES WAIT ");
		itree_pevent_brief(O_ALTFP|O_VERB|O_NONL, ep);
		out(O_ALTFP|O_VERB|O_NONL, " to ");
		ptree_timeval(O_ALTFP|O_VERB|O_NONL, &at_latest_by);
		out(O_ALTFP|O_VERB, NULL);
		indent_pop();
		return (FME_WAIT);
	}
	indent();
	out(O_ALTFP|O_VERB|O_NONL, "<-CAUSES CREDIBLE ");
	itree_pevent_brief(O_ALTFP|O_VERB|O_NONL, ep);
	out(O_ALTFP|O_VERB, NULL);
	indent_pop();
	return (FME_CREDIBLE);
}

static enum fme_state
hypothesise(struct fme *fmep, struct event *ep,
    unsigned long long at_latest_by, unsigned long long *pdelay)
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

	rtr = requirements_test(fmep, ep, at_latest_by, &my_delay);
	if ((rtr == FME_WAIT) && (my_delay < overall_delay))
		overall_delay = my_delay;
	if (rtr != FME_DISPROVED) {
		if (is_problem(ep->t)) {
			otr = effects_test(fmep, ep, at_latest_by, &my_delay);
			if (otr != FME_DISPROVED) {
				if (fmep->peek == 0 && ep->is_suspect == 0) {
					ep->suspects = fmep->suspects;
					ep->is_suspect = 1;
					fmep->suspects = ep;
					fmep->nsuspects++;
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

/*
 * fme_istat_load -- reconstitute any persistent istats
 */
void
fme_istat_load(fmd_hdl_t *hdl)
{
	int sz;
	char *sbuf;
	char *ptr;

	if ((sz = fmd_buf_size(hdl, NULL, WOBUF_ISTATS)) == 0) {
		out(O_ALTFP, "fme_istat_load: No stats");
		return;
	}

	sbuf = alloca(sz);

	fmd_buf_read(hdl, NULL, WOBUF_ISTATS, sbuf, sz);

	/*
	 * pick apart the serialized stats
	 *
	 * format is:
	 *	<class-name>, '@', <path>, '\0', <value>, '\0'
	 * for example:
	 *	"stat.first@stat0/path0\02\0stat.second@stat0/path1\023\0"
	 *
	 * since this is parsing our own serialized data, any parsing issues
	 * are fatal, so we check for them all with ASSERT() below.
	 */
	ptr = sbuf;
	while (ptr < &sbuf[sz]) {
		char *sepptr;
		struct node *np;
		int val;

		sepptr = strchr(ptr, '@');
		ASSERT(sepptr != NULL);
		*sepptr = '\0';

		/* construct the event */
		np = newnode(T_EVENT, NULL, 0);
		np->u.event.ename = newnode(T_NAME, NULL, 0);
		np->u.event.ename->u.name.t = N_STAT;
		np->u.event.ename->u.name.s = stable(ptr);
		np->u.event.ename->u.name.it = IT_ENAME;
		np->u.event.ename->u.name.last = np->u.event.ename;

		ptr = sepptr + 1;
		ASSERT(ptr < &sbuf[sz]);
		ptr += strlen(ptr);
		ptr++;	/* move past the '\0' separating path from value */
		ASSERT(ptr < &sbuf[sz]);
		ASSERT(isdigit(*ptr));
		val = atoi(ptr);
		ASSERT(val > 0);
		ptr += strlen(ptr);
		ptr++;	/* move past the final '\0' for this entry */

		np->u.event.epname = pathstring2epnamenp(sepptr + 1);
		ASSERT(np->u.event.epname != NULL);

		istat_bump(np, val);
		tree_free(np);
	}

	istat_save();
}
