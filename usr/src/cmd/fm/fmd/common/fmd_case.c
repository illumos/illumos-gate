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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * FMD Case Subsystem
 *
 * Diagnosis engines are expected to group telemetry events related to the
 * diagnosis of a particular problem on the system into a set of cases.  The
 * diagnosis engine may have any number of cases open at a given point in time.
 * Some cases may eventually be *solved* by associating a suspect list of one
 * or more problems with the case, at which point fmd publishes a list.suspect
 * event for the case and it becomes visible to administrators and agents.
 *
 * Every case is named using a UUID, and is globally visible in the case hash.
 * Cases are reference-counted, except for the reference from the case hash
 * itself.  Consumers of case references include modules, which store active
 * cases on the mod_cases list, ASRUs in the resource cache, and the RPC code.
 *
 * Cases obey the following state machine.  In states UNSOLVED, SOLVED, and
 * CLOSE_WAIT, a case's module refers to the owning module (a diagnosis engine
 * or transport) and the case is referenced by the mod_cases list.  Once the
 * case reaches the CLOSED or REPAIRED states, a case's module changes to refer
 * to the root module (fmd.d_rmod) and is deleted from the owner's mod_cases.
 *
 *			+------------+
 *	     +----------|  UNSOLVED  |
 *	     |		+------------+
 *	   1 |	             4 |
 *           |                 |
 *	+----v---+ /-2->+------v-----+	  3	+--------+
 *      | SOLVED |<     | CLOSE_WAIT |--------->| CLOSED |
 *	+--------+ \-5->+------------+		+--------+
 *	                       |                    |
 *                           6 |                    | 7
 *      		+------v-----+              |
 *	                |  REPAIRED  |<-------------+
 *			+------------+
 *
 * The state machine changes are triggered by calls to fmd_case_transition()
 * from various locations inside of fmd, as described below:
 *
 * [1] Called by: fmd_case_solve()
 *       Actions: FMD_CF_SOLVED flag is set in ci_flags
 *                conviction policy is applied to suspect list
 *                suspects convicted are marked faulty (F) in R$
 *                list.suspect event logged and dispatched
 *
 * [2] Called by: fmd_case_close(), fmd_case_uuclose(), fmd_xprt_event_uuclose()
 *       Actions: FMD_CF_ISOLATED flag is set in ci_flags
 *                suspects convicted (F) are marked unusable (U) in R$
 *                diagnosis engine fmdo_close() entry point scheduled
 *                case transitions to CLOSED [3] upon exit from CLOSE_WAIT
 *
 * [3] Called by: fmd_case_delete() (after fmdo_close() entry point returns)
 *       Actions: list.isolated event dispatched
 *                case deleted from module's list of open cases
 *
 * [4] Called by: fmd_case_close(), fmd_case_uuclose()
 *       Actions: diagnosis engine fmdo_close() entry point scheduled
 *                case is subsequently discarded by fmd_case_delete()
 *
 * [5] Called by: fmd_case_repair(), fmd_case_update()
 *       Actions: FMD_CF_REPAIR flag is set in ci_flags
 *                diagnosis engine fmdo_close() entry point scheduled
 *                case transitions to REPAIRED [6] upon exit from CLOSE_WAIT
 *
 * [6] Called by: fmd_case_repair(), fmd_case_update()
 *       Actions: FMD_CF_REPAIR flag is set in ci_flags
 *                suspects convicted are marked non faulty (!F) in R$
 *                list.repaired event dispatched
 *
 * [7] Called by: fmd_case_repair(), fmd_case_update()
 *       Actions: FMD_CF_REPAIR flag is set in ci_flags
 *                suspects convicted are marked non faulty (!F) in R$
 *                list.repaired event dispatched
 */

#include <sys/fm/protocol.h>
#include <uuid/uuid.h>
#include <alloca.h>

#include <fmd_alloc.h>
#include <fmd_module.h>
#include <fmd_error.h>
#include <fmd_conf.h>
#include <fmd_case.h>
#include <fmd_string.h>
#include <fmd_subr.h>
#include <fmd_protocol.h>
#include <fmd_event.h>
#include <fmd_eventq.h>
#include <fmd_dispq.h>
#include <fmd_buf.h>
#include <fmd_log.h>
#include <fmd_asru.h>
#include <fmd_fmri.h>
#include <fmd_xprt.h>

#include <fmd.h>

static const char *const _fmd_case_snames[] = {
	"UNSOLVED",	/* FMD_CASE_UNSOLVED */
	"SOLVED",	/* FMD_CASE_SOLVED */
	"CLOSE_WAIT",	/* FMD_CASE_CLOSE_WAIT */
	"CLOSED",	/* FMD_CASE_CLOSED */
	"REPAIRED"	/* FMD_CASE_REPAIRED */
};

extern volatile uint32_t fmd_asru_fake_not_present;

static fmd_case_impl_t *fmd_case_tryhold(fmd_case_impl_t *);

fmd_case_hash_t *
fmd_case_hash_create(void)
{
	fmd_case_hash_t *chp = fmd_alloc(sizeof (fmd_case_hash_t), FMD_SLEEP);

	(void) pthread_rwlock_init(&chp->ch_lock, NULL);
	chp->ch_hashlen = fmd.d_str_buckets;
	chp->ch_hash = fmd_zalloc(sizeof (void *) * chp->ch_hashlen, FMD_SLEEP);
	chp->ch_code_hash = fmd_zalloc(sizeof (void *) * chp->ch_hashlen,
	    FMD_SLEEP);
	chp->ch_count = 0;

	return (chp);
}

/*
 * Destroy the case hash.  Unlike most of our hash tables, no active references
 * are kept by the case hash itself; all references come from other subsystems.
 * The hash must be destroyed after all modules are unloaded; if anything was
 * present in the hash it would be by definition a reference count leak.
 */
void
fmd_case_hash_destroy(fmd_case_hash_t *chp)
{
	fmd_free(chp->ch_hash, sizeof (void *) * chp->ch_hashlen);
	fmd_free(chp->ch_code_hash, sizeof (void *) * chp->ch_hashlen);
	fmd_free(chp, sizeof (fmd_case_hash_t));
}

/*
 * Take a snapshot of the case hash by placing an additional hold on each
 * member in an auxiliary array, and then call 'func' for each case.
 */
void
fmd_case_hash_apply(fmd_case_hash_t *chp,
    void (*func)(fmd_case_t *, void *), void *arg)
{
	fmd_case_impl_t *cp, **cps, **cpp;
	uint_t cpc, i;

	(void) pthread_rwlock_rdlock(&chp->ch_lock);

	cps = cpp = fmd_alloc(chp->ch_count * sizeof (fmd_case_t *), FMD_SLEEP);
	cpc = chp->ch_count;

	for (i = 0; i < chp->ch_hashlen; i++) {
		for (cp = chp->ch_hash[i]; cp != NULL; cp = cp->ci_next) {
			fmd_case_hold((fmd_case_t *)cp);
			*cpp++ = cp;
		}
	}

	ASSERT(cpp == cps + cpc);
	(void) pthread_rwlock_unlock(&chp->ch_lock);

	for (i = 0; i < cpc; i++) {
		func((fmd_case_t *)cps[i], arg);
		fmd_case_rele((fmd_case_t *)cps[i]);
	}

	fmd_free(cps, cpc * sizeof (fmd_case_t *));
}

static void
fmd_case_code_hash_insert(fmd_case_hash_t *chp, fmd_case_impl_t *cip)
{
	uint_t h = fmd_strhash(cip->ci_code) % chp->ch_hashlen;

	cip->ci_code_next = chp->ch_code_hash[h];
	chp->ch_code_hash[h] = cip;
}

static void
fmd_case_code_hash_delete(fmd_case_hash_t *chp, fmd_case_impl_t *cip)
{
	fmd_case_impl_t **pp, *cp;

	if (cip->ci_code) {
		uint_t h = fmd_strhash(cip->ci_code) % chp->ch_hashlen;

		pp = &chp->ch_code_hash[h];
		for (cp = *pp; cp != NULL; cp = cp->ci_code_next) {
			if (cp != cip)
				pp = &cp->ci_code_next;
			else
				break;
		}
		if (cp != NULL) {
			*pp = cp->ci_code_next;
			cp->ci_code_next = NULL;
		}
	}
}

/*
 * Look up the diagcode for this case and cache it in ci_code.  If no suspects
 * were defined for this case or if the lookup fails, the event dictionary or
 * module code is broken, and we set the event code to a precomputed default.
 */
static const char *
fmd_case_mkcode(fmd_case_t *cp)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;
	fmd_case_susp_t *cis;
	fmd_case_hash_t *chp = fmd.d_cases;

	char **keys, **keyp;
	const char *s;

	ASSERT(MUTEX_HELD(&cip->ci_lock));
	ASSERT(cip->ci_state >= FMD_CASE_SOLVED);

	/*
	 * delete any existing entry from code hash if it is on it
	 */
	fmd_case_code_hash_delete(chp, cip);

	fmd_free(cip->ci_code, cip->ci_codelen);
	cip->ci_codelen = cip->ci_mod->mod_codelen;
	cip->ci_code = fmd_zalloc(cip->ci_codelen, FMD_SLEEP);
	keys = keyp = alloca(sizeof (char *) * (cip->ci_nsuspects + 1));

	for (cis = cip->ci_suspects; cis != NULL; cis = cis->cis_next) {
		if (nvlist_lookup_string(cis->cis_nvl, FM_CLASS, keyp) == 0)
			keyp++;
	}

	*keyp = NULL; /* mark end of keys[] array for libdiagcode */

	if (cip->ci_nsuspects == 0 || fmd_module_dc_key2code(
	    cip->ci_mod, keys, cip->ci_code, cip->ci_codelen) != 0) {
		(void) fmd_conf_getprop(fmd.d_conf, "nodiagcode", &s);
		fmd_free(cip->ci_code, cip->ci_codelen);
		cip->ci_codelen = strlen(s) + 1;
		cip->ci_code = fmd_zalloc(cip->ci_codelen, FMD_SLEEP);
		(void) strcpy(cip->ci_code, s);
	}

	/*
	 * add into hash of solved cases
	 */
	fmd_case_code_hash_insert(chp, cip);

	return (cip->ci_code);
}

typedef struct {
	int	*fcl_countp;
	uint8_t *fcl_ba;
	nvlist_t **fcl_nva;
	int	*fcl_msgp;
} fmd_case_lst_t;

static void
fmd_case_set_lst(fmd_asru_link_t *alp, void *arg)
{
	fmd_case_lst_t *entryp = (fmd_case_lst_t *)arg;
	boolean_t b;
	int state;

	if (nvlist_lookup_boolean_value(alp->al_event, FM_SUSPECT_MESSAGE,
	    &b) == 0 && b == B_FALSE)
		*entryp->fcl_msgp = B_FALSE;
	entryp->fcl_ba[*entryp->fcl_countp] = 0;
	state = fmd_asru_al_getstate(alp);
	if (state & FMD_ASRU_UNUSABLE)
		entryp->fcl_ba[*entryp->fcl_countp] |= FM_SUSPECT_UNUSABLE;
	if (state & FMD_ASRU_FAULTY)
		entryp->fcl_ba[*entryp->fcl_countp] |= FM_SUSPECT_FAULTY;
	if (!(state & FMD_ASRU_PRESENT))
		entryp->fcl_ba[*entryp->fcl_countp] |= FM_SUSPECT_NOT_PRESENT;
	entryp->fcl_nva[*entryp->fcl_countp] = alp->al_event;
	(*entryp->fcl_countp)++;
}

static void
fmd_case_faulty(fmd_asru_link_t *alp, void *arg)
{
	int *faultyp = (int *)arg;

	*faultyp |= (alp->al_flags & FMD_ASRU_FAULTY);
}

static void
fmd_case_usable(fmd_asru_link_t *alp, void *arg)
{
	int *usablep = (int *)arg;

	*usablep |= !(fmd_asru_al_getstate(alp) & FMD_ASRU_UNUSABLE);
}

nvlist_t *
fmd_case_mkevent(fmd_case_t *cp, const char *class)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;
	nvlist_t **nva, *nvl;
	uint8_t *ba;
	int msg = B_TRUE;
	const char *code;
	fmd_case_lst_t fcl;
	int count = 0;

	(void) pthread_mutex_lock(&cip->ci_lock);
	ASSERT(cip->ci_state >= FMD_CASE_SOLVED);

	nva = alloca(sizeof (nvlist_t *) * cip->ci_nsuspects);
	ba = alloca(sizeof (uint8_t) * cip->ci_nsuspects);

	/*
	 * For each suspect associated with the case, store its fault event
	 * nvlist in 'nva'.  We also look to see if any of the suspect faults
	 * have asked not to be messaged.  If any of them have made such a
	 * request, propagate that attribute to the composite list.* event.
	 * Finally, store each suspect's faulty status into the bitmap 'ba'.
	 */
	fcl.fcl_countp = &count;
	fcl.fcl_msgp = &msg;
	fcl.fcl_ba = ba;
	fcl.fcl_nva = nva;
	fmd_asru_hash_apply_by_case(fmd.d_asrus, cp, fmd_case_set_lst, &fcl);

	if (cip->ci_code == NULL)
		(void) fmd_case_mkcode(cp);
	/*
	 * For repair event, we lookup diagcode from dict using key
	 * "list.repaired".
	 */
	if (strcmp(class, FM_LIST_REPAIRED_CLASS) == 0)
		(void) fmd_conf_getprop(fmd.d_conf, "repaircode", &code);
	else
		code = cip->ci_code;

	if (msg == B_FALSE)
		cip->ci_flags |= FMD_CF_INVISIBLE;

	nvl = fmd_protocol_list(class, cip->ci_mod->mod_fmri, cip->ci_uuid,
	    code, count, nva, ba, msg, &cip->ci_tv);

	(void) pthread_mutex_unlock(&cip->ci_lock);
	return (nvl);
}

static boolean_t
fmd_case_compare_elem(nvlist_t *nvl, nvlist_t *xnvl, const char *elem)
{
	nvlist_t *new_rsrc;
	nvlist_t *rsrc;
	char *new_name = NULL;
	char *name = NULL;
	ssize_t new_namelen;
	ssize_t namelen;
	int fmri_present = 1;
	int new_fmri_present = 1;
	int match = B_FALSE;
	fmd_topo_t *ftp = fmd_topo_hold();

	if (nvlist_lookup_nvlist(xnvl, elem, &rsrc) != 0)
		fmri_present = 0;
	else {
		if ((namelen = fmd_fmri_nvl2str(rsrc, NULL, 0)) == -1)
			goto done;
		name = fmd_alloc(namelen + 1, FMD_SLEEP);
		if (fmd_fmri_nvl2str(rsrc, name, namelen + 1) == -1)
			goto done;
	}
	if (nvlist_lookup_nvlist(nvl, elem, &new_rsrc) != 0)
		new_fmri_present = 0;
	else {
		if ((new_namelen = fmd_fmri_nvl2str(new_rsrc, NULL, 0)) == -1)
			goto done;
		new_name = fmd_alloc(new_namelen + 1, FMD_SLEEP);
		if (fmd_fmri_nvl2str(new_rsrc, new_name, new_namelen + 1) == -1)
			goto done;
	}
	match = (fmri_present == new_fmri_present &&
	    (fmri_present == 0 ||
	    topo_fmri_strcmp(ftp->ft_hdl, name, new_name)));
done:
	if (name != NULL)
		fmd_free(name, namelen + 1);
	if (new_name != NULL)
		fmd_free(new_name, new_namelen + 1);
	fmd_topo_rele(ftp);
	return (match);
}

static int
fmd_case_match_suspect(fmd_case_susp_t *cis, fmd_case_susp_t *xcis)
{
	char *class, *new_class;

	if (!fmd_case_compare_elem(cis->cis_nvl, xcis->cis_nvl, FM_FAULT_ASRU))
		return (0);
	if (!fmd_case_compare_elem(cis->cis_nvl, xcis->cis_nvl,
	    FM_FAULT_RESOURCE))
		return (0);
	if (!fmd_case_compare_elem(cis->cis_nvl, xcis->cis_nvl, FM_FAULT_FRU))
		return (0);
	(void) nvlist_lookup_string(xcis->cis_nvl, FM_CLASS, &class);
	(void) nvlist_lookup_string(cis->cis_nvl, FM_CLASS, &new_class);
	return (strcmp(class, new_class) == 0);
}

/*
 * see if an identical suspect list already exists in the cache
 */
static int
fmd_case_check_for_dups(fmd_case_t *cp)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp, *xcip;
	fmd_case_hash_t *chp = fmd.d_cases;
	fmd_case_susp_t *xcis, *cis;
	int match = 0, match_susp;
	uint_t h;

	(void) pthread_rwlock_rdlock(&chp->ch_lock);

	/*
	 * Find all cases with this code
	 */
	h = fmd_strhash(cip->ci_code) % chp->ch_hashlen;
	for (xcip = chp->ch_code_hash[h]; xcip != NULL;
	    xcip = xcip->ci_code_next) {
		/*
		 * only look for any cases (apart from this one)
		 * whose code and number of suspects match
		 */
		if (xcip == cip || strcmp(xcip->ci_code, cip->ci_code) != 0 ||
		    xcip->ci_nsuspects != cip->ci_nsuspects)
			continue;

		/*
		 * For each suspect in one list, check if there
		 * is an identical suspect in the other list
		 */
		match = 1;
		fmd_case_hold((fmd_case_t *)xcip);
		for (xcis = xcip->ci_suspects; xcis != NULL;
		    xcis = xcis->cis_next) {
			match_susp = 0;
			for (cis = cip->ci_suspects; cis != NULL;
			    cis = cis->cis_next) {
				if (fmd_case_match_suspect(cis, xcis) == 1) {
					match_susp = 1;
					break;
				}
			}
			if (match_susp == 0) {
				match = 0;
				break;
			}
		}
		fmd_case_rele((fmd_case_t *)xcip);
		if (match) {
			(void) pthread_rwlock_unlock(&chp->ch_lock);
			return (1);
		}
	}
	(void) pthread_rwlock_unlock(&chp->ch_lock);
	return (0);
}

/*
 * Convict suspects in a case by applying a conviction policy and updating the
 * resource cache prior to emitting the list.suspect event for the given case.
 * At present, our policy is very simple: convict every suspect in the case.
 * In the future, this policy can be extended and made configurable to permit:
 *
 * - convicting the suspect with the highest FIT rate
 * - convicting the suspect with the cheapest FRU
 * - convicting the suspect with the FRU that is in a depot's inventory
 * - convicting the suspect with the longest lifetime
 *
 * and so forth.  A word to the wise: this problem is significantly harder that
 * it seems at first glance.  Future work should heed the following advice:
 *
 * Hacking the policy into C code here is a very bad idea.  The policy needs to
 * be decided upon very carefully and fundamentally encodes knowledge of what
 * suspect list combinations can be emitted by what diagnosis engines.  As such
 * fmd's code is the wrong location, because that would require fmd itself to
 * be updated for every diagnosis engine change, defeating the entire design.
 * The FMA Event Registry knows the suspect list combinations: policy inputs
 * can be derived from it and used to produce per-module policy configuration.
 *
 * If the policy needs to be dynamic and not statically fixed at either fmd
 * startup or module load time, any implementation of dynamic policy retrieval
 * must employ some kind of caching mechanism or be part of a built-in module.
 * The fmd_case_convict() function is called with locks held inside of fmd and
 * is not a place where unbounded blocking on some inter-process or inter-
 * system communication to another service (e.g. another daemon) can occur.
 */
static int
fmd_case_convict(fmd_case_t *cp)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;
	fmd_asru_hash_t *ahp = fmd.d_asrus;

	fmd_case_susp_t *cis;
	fmd_asru_link_t *alp;

	(void) pthread_mutex_lock(&cip->ci_lock);
	(void) fmd_case_mkcode(cp);
	if (fmd_case_check_for_dups(cp) == 1) {
		(void) pthread_mutex_unlock(&cip->ci_lock);
		return (1);
	}

	/*
	 * no suspect list already exists  - allocate new cache entries
	 */
	for (cis = cip->ci_suspects; cis != NULL; cis = cis->cis_next) {
		if ((alp = fmd_asru_hash_create_entry(ahp,
		    cp, cis->cis_nvl)) == NULL) {
			fmd_error(EFMD_CASE_EVENT, "cannot convict suspect in "
			    "%s: %s\n", cip->ci_uuid, fmd_strerror(errno));
			continue;
		}
		(void) fmd_asru_clrflags(alp, FMD_ASRU_UNUSABLE);
		(void) fmd_asru_setflags(alp, FMD_ASRU_FAULTY);
	}

	(void) pthread_mutex_unlock(&cip->ci_lock);
	return (0);
}

void
fmd_case_publish(fmd_case_t *cp, uint_t state)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;
	fmd_event_t *e;
	nvlist_t *nvl;
	char *class;

	if (state == FMD_CASE_CURRENT)
		state = cip->ci_state; /* use current state */

	switch (state) {
	case FMD_CASE_SOLVED:
		(void) pthread_mutex_lock(&cip->ci_lock);
		if (cip->ci_tv_valid == 0) {
			fmd_time_gettimeofday(&cip->ci_tv);
			cip->ci_tv_valid = 1;
		}
		(void) pthread_mutex_unlock(&cip->ci_lock);

		if (fmd_case_convict(cp) == 1) { /* dupclose */
			cip->ci_flags &= ~FMD_CF_SOLVED;
			fmd_case_transition(cp, FMD_CASE_CLOSE_WAIT, 0);
			break;
		}
		nvl = fmd_case_mkevent(cp, FM_LIST_SUSPECT_CLASS);
		(void) nvlist_lookup_string(nvl, FM_CLASS, &class);

		e = fmd_event_create(FMD_EVT_PROTOCOL, FMD_HRT_NOW, nvl, class);
		(void) pthread_rwlock_rdlock(&fmd.d_log_lock);
		fmd_log_append(fmd.d_fltlog, e, cp);
		(void) pthread_rwlock_unlock(&fmd.d_log_lock);
		fmd_dispq_dispatch(fmd.d_disp, e, class);

		(void) pthread_mutex_lock(&cip->ci_mod->mod_stats_lock);
		cip->ci_mod->mod_stats->ms_casesolved.fmds_value.ui64++;
		(void) pthread_mutex_unlock(&cip->ci_mod->mod_stats_lock);

		break;

	case FMD_CASE_CLOSE_WAIT:
		fmd_case_hold(cp);
		e = fmd_event_create(FMD_EVT_CLOSE, FMD_HRT_NOW, NULL, cp);
		fmd_eventq_insert_at_head(cip->ci_mod->mod_queue, e);

		(void) pthread_mutex_lock(&cip->ci_mod->mod_stats_lock);
		cip->ci_mod->mod_stats->ms_caseclosed.fmds_value.ui64++;
		(void) pthread_mutex_unlock(&cip->ci_mod->mod_stats_lock);

		break;

	case FMD_CASE_CLOSED:
		nvl = fmd_case_mkevent(cp, FM_LIST_ISOLATED_CLASS);
		(void) nvlist_lookup_string(nvl, FM_CLASS, &class);
		e = fmd_event_create(FMD_EVT_PROTOCOL, FMD_HRT_NOW, nvl, class);
		fmd_dispq_dispatch(fmd.d_disp, e, class);
		break;

	case FMD_CASE_REPAIRED:
		nvl = fmd_case_mkevent(cp, FM_LIST_REPAIRED_CLASS);
		(void) nvlist_lookup_string(nvl, FM_CLASS, &class);
		e = fmd_event_create(FMD_EVT_PROTOCOL, FMD_HRT_NOW, nvl, class);
		(void) pthread_rwlock_rdlock(&fmd.d_log_lock);
		fmd_log_append(fmd.d_fltlog, e, cp);
		(void) pthread_rwlock_unlock(&fmd.d_log_lock);
		fmd_dispq_dispatch(fmd.d_disp, e, class);
		break;
	}
}

fmd_case_t *
fmd_case_hash_lookup(fmd_case_hash_t *chp, const char *uuid)
{
	fmd_case_impl_t *cip;
	uint_t h;

	(void) pthread_rwlock_rdlock(&chp->ch_lock);
	h = fmd_strhash(uuid) % chp->ch_hashlen;

	for (cip = chp->ch_hash[h]; cip != NULL; cip = cip->ci_next) {
		if (strcmp(cip->ci_uuid, uuid) == 0)
			break;
	}

	/*
	 * If deleting bit is set, treat the case as if it doesn't exist.
	 */
	if (cip != NULL)
		cip = fmd_case_tryhold(cip);

	if (cip == NULL)
		(void) fmd_set_errno(EFMD_CASE_INVAL);

	(void) pthread_rwlock_unlock(&chp->ch_lock);
	return ((fmd_case_t *)cip);
}

static fmd_case_impl_t *
fmd_case_hash_insert(fmd_case_hash_t *chp, fmd_case_impl_t *cip)
{
	fmd_case_impl_t *eip;
	uint_t h;

	(void) pthread_rwlock_wrlock(&chp->ch_lock);
	h = fmd_strhash(cip->ci_uuid) % chp->ch_hashlen;

	for (eip = chp->ch_hash[h]; eip != NULL; eip = eip->ci_next) {
		if (strcmp(cip->ci_uuid, eip->ci_uuid) == 0 &&
		    fmd_case_tryhold(eip) != NULL) {
			(void) pthread_rwlock_unlock(&chp->ch_lock);
			return (eip); /* uuid already present */
		}
	}

	cip->ci_next = chp->ch_hash[h];
	chp->ch_hash[h] = cip;

	chp->ch_count++;
	ASSERT(chp->ch_count != 0);

	(void) pthread_rwlock_unlock(&chp->ch_lock);
	return (cip);
}

static void
fmd_case_hash_delete(fmd_case_hash_t *chp, fmd_case_impl_t *cip)
{
	fmd_case_impl_t *cp, **pp;
	uint_t h;

	ASSERT(MUTEX_HELD(&cip->ci_lock));

	cip->ci_flags |= FMD_CF_DELETING;
	(void) pthread_mutex_unlock(&cip->ci_lock);

	(void) pthread_rwlock_wrlock(&chp->ch_lock);

	h = fmd_strhash(cip->ci_uuid) % chp->ch_hashlen;
	pp = &chp->ch_hash[h];

	for (cp = *pp; cp != NULL; cp = cp->ci_next) {
		if (cp != cip)
			pp = &cp->ci_next;
		else
			break;
	}

	if (cp == NULL) {
		fmd_panic("case %p (%s) not found on hash chain %u\n",
		    (void *)cip, cip->ci_uuid, h);
	}

	*pp = cp->ci_next;
	cp->ci_next = NULL;

	/*
	 * delete from code hash if it is on it
	 */
	fmd_case_code_hash_delete(chp, cip);

	ASSERT(chp->ch_count != 0);
	chp->ch_count--;

	(void) pthread_rwlock_unlock(&chp->ch_lock);

	(void) pthread_mutex_lock(&cip->ci_lock);
	ASSERT(cip->ci_flags & FMD_CF_DELETING);
}

fmd_case_t *
fmd_case_create(fmd_module_t *mp, void *data)
{
	fmd_case_impl_t *cip = fmd_zalloc(sizeof (fmd_case_impl_t), FMD_SLEEP);
	fmd_case_impl_t *eip = NULL;
	uuid_t uuid;

	(void) pthread_mutex_init(&cip->ci_lock, NULL);
	fmd_buf_hash_create(&cip->ci_bufs);

	fmd_module_hold(mp);
	cip->ci_mod = mp;
	cip->ci_refs = 1;
	cip->ci_state = FMD_CASE_UNSOLVED;
	cip->ci_flags = FMD_CF_DIRTY;
	cip->ci_data = data;

	/*
	 * Calling libuuid: get a clue.  The library interfaces cleverly do not
	 * define any constant for the length of an unparse string, and do not
	 * permit the caller to specify a buffer length for safety.  The spec
	 * says it will be 36 bytes, but we make it tunable just in case.
	 */
	(void) fmd_conf_getprop(fmd.d_conf, "uuidlen", &cip->ci_uuidlen);
	cip->ci_uuid = fmd_zalloc(cip->ci_uuidlen + 1, FMD_SLEEP);

	/*
	 * We expect this loop to execute only once, but code it defensively
	 * against the possibility of libuuid bugs.  Keep generating uuids and
	 * attempting to do a hash insert until we get a unique one.
	 */
	do {
		if (eip != NULL)
			fmd_case_rele((fmd_case_t *)eip);
		uuid_generate(uuid);
		uuid_unparse(uuid, cip->ci_uuid);
	} while ((eip = fmd_case_hash_insert(fmd.d_cases, cip)) != cip);

	ASSERT(fmd_module_locked(mp));
	fmd_list_append(&mp->mod_cases, cip);
	fmd_module_setcdirty(mp);

	(void) pthread_mutex_lock(&cip->ci_mod->mod_stats_lock);
	cip->ci_mod->mod_stats->ms_caseopen.fmds_value.ui64++;
	(void) pthread_mutex_unlock(&cip->ci_mod->mod_stats_lock);

	return ((fmd_case_t *)cip);
}

static void
fmd_case_destroy_suspects(fmd_case_impl_t *cip)
{
	fmd_case_susp_t *cis, *ncis;

	ASSERT(MUTEX_HELD(&cip->ci_lock));

	for (cis = cip->ci_suspects; cis != NULL; cis = ncis) {
		ncis = cis->cis_next;
		nvlist_free(cis->cis_nvl);
		fmd_free(cis, sizeof (fmd_case_susp_t));
	}

	cip->ci_suspects = NULL;
	cip->ci_nsuspects = 0;
}

fmd_case_t *
fmd_case_recreate(fmd_module_t *mp, fmd_xprt_t *xp,
    uint_t state, const char *uuid, const char *code)
{
	fmd_case_impl_t *cip = fmd_zalloc(sizeof (fmd_case_impl_t), FMD_SLEEP);
	fmd_case_impl_t *eip;

	ASSERT(state < FMD_CASE_REPAIRED);

	(void) pthread_mutex_init(&cip->ci_lock, NULL);
	fmd_buf_hash_create(&cip->ci_bufs);

	fmd_module_hold(mp);
	cip->ci_mod = mp;
	cip->ci_xprt = xp;
	cip->ci_refs = 1;
	cip->ci_state = state;
	cip->ci_uuid = fmd_strdup(uuid, FMD_SLEEP);
	cip->ci_uuidlen = strlen(cip->ci_uuid);
	cip->ci_code = fmd_strdup(code, FMD_SLEEP);
	cip->ci_codelen = cip->ci_code ? strlen(cip->ci_code) + 1 : 0;

	if (state > FMD_CASE_CLOSE_WAIT)
		cip->ci_flags |= FMD_CF_SOLVED;

	/*
	 * Insert the case into the global case hash.  If the specified UUID is
	 * already present, check to see if it is an orphan: if so, reclaim it;
	 * otherwise if it is owned by a different module then return NULL.
	 */
	if ((eip = fmd_case_hash_insert(fmd.d_cases, cip)) != cip) {
		(void) pthread_mutex_lock(&cip->ci_lock);
		cip->ci_refs--; /* decrement to zero */
		fmd_case_destroy((fmd_case_t *)cip, B_FALSE);

		cip = eip; /* switch 'cip' to the existing case */
		(void) pthread_mutex_lock(&cip->ci_lock);

		/*
		 * If the ASRU cache is trying to recreate an orphan, then just
		 * return the existing case that we found without changing it.
		 */
		if (mp == fmd.d_rmod) {
			(void) pthread_mutex_unlock(&cip->ci_lock);
			fmd_case_rele((fmd_case_t *)cip);
			return ((fmd_case_t *)cip);
		}

		/*
		 * If the existing case isn't an orphan or is being proxied,
		 * then we have a UUID conflict: return failure to the caller.
		 */
		if (cip->ci_mod != fmd.d_rmod || xp != NULL) {
			(void) pthread_mutex_unlock(&cip->ci_lock);
			fmd_case_rele((fmd_case_t *)cip);
			return (NULL);
		}

		/*
		 * If the new module is reclaiming an orphaned case, remove
		 * the case from the root module, switch ci_mod, and then fall
		 * through to adding the case to the new owner module 'mp'.
		 */
		fmd_module_lock(cip->ci_mod);
		fmd_list_delete(&cip->ci_mod->mod_cases, cip);
		fmd_module_unlock(cip->ci_mod);

		fmd_module_rele(cip->ci_mod);
		cip->ci_mod = mp;
		fmd_module_hold(mp);

		fmd_case_destroy_suspects(cip);
		cip->ci_state = state;

		(void) pthread_mutex_unlock(&cip->ci_lock);
		fmd_case_rele((fmd_case_t *)cip);
	} else {
		/*
		 * add into hash of solved cases
		 */
		if (cip->ci_code)
			fmd_case_code_hash_insert(fmd.d_cases, cip);
	}

	ASSERT(fmd_module_locked(mp));
	fmd_list_append(&mp->mod_cases, cip);

	(void) pthread_mutex_lock(&cip->ci_mod->mod_stats_lock);
	cip->ci_mod->mod_stats->ms_caseopen.fmds_value.ui64++;
	(void) pthread_mutex_unlock(&cip->ci_mod->mod_stats_lock);

	return ((fmd_case_t *)cip);
}

void
fmd_case_destroy(fmd_case_t *cp, int visible)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;
	fmd_case_item_t *cit, *ncit;

	ASSERT(MUTEX_HELD(&cip->ci_lock));
	ASSERT(cip->ci_refs == 0);

	if (visible) {
		TRACE((FMD_DBG_CASE, "deleting case %s", cip->ci_uuid));
		fmd_case_hash_delete(fmd.d_cases, cip);
	}

	for (cit = cip->ci_items; cit != NULL; cit = ncit) {
		ncit = cit->cit_next;
		fmd_event_rele(cit->cit_event);
		fmd_free(cit, sizeof (fmd_case_item_t));
	}

	fmd_case_destroy_suspects(cip);

	if (cip->ci_principal != NULL)
		fmd_event_rele(cip->ci_principal);

	fmd_free(cip->ci_uuid, cip->ci_uuidlen + 1);
	fmd_free(cip->ci_code, cip->ci_codelen);
	(void) fmd_buf_hash_destroy(&cip->ci_bufs);

	fmd_module_rele(cip->ci_mod);
	fmd_free(cip, sizeof (fmd_case_impl_t));
}

void
fmd_case_hold(fmd_case_t *cp)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;

	(void) pthread_mutex_lock(&cip->ci_lock);
	fmd_case_hold_locked(cp);
	(void) pthread_mutex_unlock(&cip->ci_lock);
}

void
fmd_case_hold_locked(fmd_case_t *cp)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;

	ASSERT(MUTEX_HELD(&cip->ci_lock));
	if (cip->ci_flags & FMD_CF_DELETING)
		fmd_panic("attempt to hold a deleting case %p (%s)\n",
		    (void *)cip, cip->ci_uuid);
	cip->ci_refs++;
	ASSERT(cip->ci_refs != 0);
}

static fmd_case_impl_t *
fmd_case_tryhold(fmd_case_impl_t *cip)
{
	/*
	 * If the case's "deleting" bit is unset, hold and return case,
	 * otherwise, return NULL.
	 */
	(void) pthread_mutex_lock(&cip->ci_lock);
	if (cip->ci_flags & FMD_CF_DELETING) {
		(void) pthread_mutex_unlock(&cip->ci_lock);
		cip = NULL;
	} else {
		fmd_case_hold_locked((fmd_case_t *)cip);
		(void) pthread_mutex_unlock(&cip->ci_lock);
	}
	return (cip);
}

void
fmd_case_rele(fmd_case_t *cp)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;

	(void) pthread_mutex_lock(&cip->ci_lock);
	ASSERT(cip->ci_refs != 0);

	if (--cip->ci_refs == 0)
		fmd_case_destroy((fmd_case_t *)cip, B_TRUE);
	else
		(void) pthread_mutex_unlock(&cip->ci_lock);
}

void
fmd_case_rele_locked(fmd_case_t *cp)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;

	ASSERT(MUTEX_HELD(&cip->ci_lock));
	--cip->ci_refs;
	ASSERT(cip->ci_refs != 0);
}

int
fmd_case_insert_principal(fmd_case_t *cp, fmd_event_t *ep)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;
	fmd_case_item_t *cit;
	fmd_event_t *oep;
	uint_t state;
	int new;

	fmd_event_hold(ep);
	(void) pthread_mutex_lock(&cip->ci_lock);

	if (cip->ci_flags & FMD_CF_SOLVED)
		state = FMD_EVS_DIAGNOSED;
	else
		state = FMD_EVS_ACCEPTED;

	oep = cip->ci_principal;
	cip->ci_principal = ep;

	for (cit = cip->ci_items; cit != NULL; cit = cit->cit_next) {
		if (cit->cit_event == ep)
			break;
	}

	cip->ci_flags |= FMD_CF_DIRTY;
	new = cit == NULL && ep != oep;

	(void) pthread_mutex_unlock(&cip->ci_lock);

	fmd_module_setcdirty(cip->ci_mod);
	fmd_event_transition(ep, state);

	if (oep != NULL)
		fmd_event_rele(oep);

	return (new);
}

int
fmd_case_insert_event(fmd_case_t *cp, fmd_event_t *ep)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;
	fmd_case_item_t *cit;
	uint_t state;
	int new;

	(void) pthread_mutex_lock(&cip->ci_lock);

	if (cip->ci_flags & FMD_CF_SOLVED)
		state = FMD_EVS_DIAGNOSED;
	else
		state = FMD_EVS_ACCEPTED;

	for (cit = cip->ci_items; cit != NULL; cit = cit->cit_next) {
		if (cit->cit_event == ep)
			break;
	}

	new = cit == NULL && ep != cip->ci_principal;

	/*
	 * If the event is already in the case or the case is already solved,
	 * there is no reason to save it: just transition it appropriately.
	 */
	if (cit != NULL || (cip->ci_flags & FMD_CF_SOLVED)) {
		(void) pthread_mutex_unlock(&cip->ci_lock);
		fmd_event_transition(ep, state);
		return (new);
	}

	cit = fmd_alloc(sizeof (fmd_case_item_t), FMD_SLEEP);
	fmd_event_hold(ep);

	cit->cit_next = cip->ci_items;
	cit->cit_event = ep;

	cip->ci_items = cit;
	cip->ci_nitems++;

	cip->ci_flags |= FMD_CF_DIRTY;
	(void) pthread_mutex_unlock(&cip->ci_lock);

	fmd_module_setcdirty(cip->ci_mod);
	fmd_event_transition(ep, state);

	return (new);
}

void
fmd_case_insert_suspect(fmd_case_t *cp, nvlist_t *nvl)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;
	fmd_case_susp_t *cis = fmd_alloc(sizeof (fmd_case_susp_t), FMD_SLEEP);

	(void) pthread_mutex_lock(&cip->ci_lock);
	ASSERT(cip->ci_state < FMD_CASE_CLOSE_WAIT);
	cip->ci_flags |= FMD_CF_DIRTY;

	cis->cis_next = cip->ci_suspects;
	cis->cis_nvl = nvl;

	cip->ci_suspects = cis;
	cip->ci_nsuspects++;

	(void) pthread_mutex_unlock(&cip->ci_lock);
	fmd_module_setcdirty(cip->ci_mod);
}

void
fmd_case_recreate_suspect(fmd_case_t *cp, nvlist_t *nvl)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;
	fmd_case_susp_t *cis = fmd_alloc(sizeof (fmd_case_susp_t), FMD_SLEEP);
	boolean_t b;

	(void) pthread_mutex_lock(&cip->ci_lock);
	ASSERT(cip->ci_state == FMD_CASE_CLOSED);
	ASSERT(cip->ci_mod == fmd.d_rmod);

	cis->cis_next = cip->ci_suspects;
	cis->cis_nvl = nvl;

	if (nvlist_lookup_boolean_value(nvl,
	    FM_SUSPECT_MESSAGE, &b) == 0 && b == B_FALSE)
		cip->ci_flags |= FMD_CF_INVISIBLE;

	cip->ci_suspects = cis;
	cip->ci_nsuspects++;

	(void) pthread_mutex_unlock(&cip->ci_lock);
}

void
fmd_case_reset_suspects(fmd_case_t *cp)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;

	(void) pthread_mutex_lock(&cip->ci_lock);
	ASSERT(cip->ci_state < FMD_CASE_SOLVED);

	fmd_case_destroy_suspects(cip);
	cip->ci_flags |= FMD_CF_DIRTY;

	(void) pthread_mutex_unlock(&cip->ci_lock);
	fmd_module_setcdirty(cip->ci_mod);
}

/*ARGSUSED*/
static void
fmd_case_unusable(fmd_asru_link_t *alp, void *arg)
{
	(void) fmd_asru_setflags(alp, FMD_ASRU_UNUSABLE);
}

/*
 * Grab ci_lock and update the case state and set the dirty bit.  Then perform
 * whatever actions and emit whatever events are appropriate for the state.
 * Refer to the topmost block comment explaining the state machine for details.
 */
void
fmd_case_transition(fmd_case_t *cp, uint_t state, uint_t flags)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;
	fmd_case_item_t *cit;
	fmd_event_t *e;

	ASSERT(state <= FMD_CASE_REPAIRED);
	(void) pthread_mutex_lock(&cip->ci_lock);

	if (!(cip->ci_flags & FMD_CF_SOLVED) && !(flags & FMD_CF_SOLVED))
		flags &= ~(FMD_CF_ISOLATED | FMD_CF_REPAIRED);

	cip->ci_flags |= flags;

	if (cip->ci_state >= state) {
		(void) pthread_mutex_unlock(&cip->ci_lock);
		return; /* already in specified state */
	}

	TRACE((FMD_DBG_CASE, "case %s %s->%s", cip->ci_uuid,
	    _fmd_case_snames[cip->ci_state], _fmd_case_snames[state]));

	cip->ci_state = state;
	cip->ci_flags |= FMD_CF_DIRTY;

	if (cip->ci_xprt == NULL && cip->ci_mod != fmd.d_rmod)
		fmd_module_setcdirty(cip->ci_mod);

	switch (state) {
	case FMD_CASE_SOLVED:
		for (cit = cip->ci_items; cit != NULL; cit = cit->cit_next)
			fmd_event_transition(cit->cit_event, FMD_EVS_DIAGNOSED);

		if (cip->ci_principal != NULL) {
			fmd_event_transition(cip->ci_principal,
			    FMD_EVS_DIAGNOSED);
		}
		break;

	case FMD_CASE_CLOSE_WAIT:
		/*
		 * If the case was never solved, do not change ASRUs.
		 * If the case was never fmd_case_closed, do not change ASRUs.
		 * If the case was repaired, do not change ASRUs.
		 */
		if ((cip->ci_flags & (FMD_CF_SOLVED | FMD_CF_ISOLATED |
		    FMD_CF_REPAIRED)) == (FMD_CF_SOLVED | FMD_CF_ISOLATED))
			fmd_asru_hash_apply_by_case(fmd.d_asrus, cp,
			    fmd_case_unusable, NULL);

		/*
		 * If an orphaned case transitions to CLOSE_WAIT, the owning
		 * module is no longer loaded: continue on to CASE_CLOSED.
		 */
		if (fmd_case_orphaned(cp))
			state = cip->ci_state = FMD_CASE_CLOSED;
		break;

	case FMD_CASE_REPAIRED:
		ASSERT(fmd_case_orphaned(cp));
		fmd_module_lock(cip->ci_mod);
		fmd_list_delete(&cip->ci_mod->mod_cases, cip);
		fmd_module_unlock(cip->ci_mod);
		break;
	}

	(void) pthread_mutex_unlock(&cip->ci_lock);

	/*
	 * If the module has initialized, then publish the appropriate event
	 * for the new case state.  If not, we are being called from the
	 * checkpoint code during module load, in which case the module's
	 * _fmd_init() routine hasn't finished yet, and our event dictionaries
	 * may not be open yet, which will prevent us from computing the event
	 * code.  Defer the call to fmd_case_publish() by enqueuing a PUBLISH
	 * event in our queue: this won't be processed until _fmd_init is done.
	 */
	if (cip->ci_mod->mod_flags & FMD_MOD_INIT)
		fmd_case_publish(cp, state);
	else {
		fmd_case_hold(cp);
		e = fmd_event_create(FMD_EVT_PUBLISH, FMD_HRT_NOW, NULL, cp);
		fmd_eventq_insert_at_head(cip->ci_mod->mod_queue, e);
	}

	/*
	 * If we transitioned to REPAIRED, adjust the reference count to
	 * reflect our removal from fmd.d_rmod->mod_cases.  If the caller has
	 * not placed an additional hold on the case, it will now be freed.
	 */
	if (state == FMD_CASE_REPAIRED) {
		(void) pthread_mutex_lock(&cip->ci_lock);
		fmd_asru_hash_delete_case(fmd.d_asrus, cp);
		(void) pthread_mutex_unlock(&cip->ci_lock);
		fmd_case_rele(cp);
	}
}

/*
 * Transition the specified case to *at least* the specified state by first
 * re-validating the suspect list using the resource cache.  This function is
 * employed by the checkpoint code when restoring a saved, solved case to see
 * if the state of the case has effectively changed while fmd was not running
 * or the module was not loaded.  If none of the suspects are present anymore,
 * advance the state to REPAIRED.  If none are usable, advance to CLOSE_WAIT.
 */
void
fmd_case_transition_update(fmd_case_t *cp, uint_t state, uint_t flags)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;

	int faulty = 0;		/* are any suspects faulty? */
	int usable = 0;		/* are any suspects usable? */

	ASSERT(state >= FMD_CASE_SOLVED);
	(void) pthread_mutex_lock(&cip->ci_lock);

	fmd_asru_hash_apply_by_case(fmd.d_asrus, cp, fmd_case_faulty, &faulty);
	fmd_asru_hash_apply_by_case(fmd.d_asrus, cp, fmd_case_usable, &usable);

	(void) pthread_mutex_unlock(&cip->ci_lock);

	/*
	 * If none of the suspects were faulty, it implies they were either
	 * repaired already or not present and the rsrc.age time has expired.
	 * We can move the state on to repaired.
	 */
	if (!faulty) {
		state = MAX(state, FMD_CASE_CLOSE_WAIT);
		flags |= FMD_CF_REPAIRED;
	} else if (!usable) {
		state = MAX(state, FMD_CASE_CLOSE_WAIT);
		flags |= FMD_CF_ISOLATED;
	}

	fmd_case_transition(cp, state, flags);
}

void
fmd_case_setdirty(fmd_case_t *cp)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;

	(void) pthread_mutex_lock(&cip->ci_lock);
	cip->ci_flags |= FMD_CF_DIRTY;
	(void) pthread_mutex_unlock(&cip->ci_lock);

	fmd_module_setcdirty(cip->ci_mod);
}

void
fmd_case_clrdirty(fmd_case_t *cp)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;

	(void) pthread_mutex_lock(&cip->ci_lock);
	cip->ci_flags &= ~FMD_CF_DIRTY;
	(void) pthread_mutex_unlock(&cip->ci_lock);
}

void
fmd_case_commit(fmd_case_t *cp)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;
	fmd_case_item_t *cit;

	(void) pthread_mutex_lock(&cip->ci_lock);

	if (cip->ci_flags & FMD_CF_DIRTY) {
		for (cit = cip->ci_items; cit != NULL; cit = cit->cit_next)
			fmd_event_commit(cit->cit_event);

		if (cip->ci_principal != NULL)
			fmd_event_commit(cip->ci_principal);

		fmd_buf_hash_commit(&cip->ci_bufs);
		cip->ci_flags &= ~FMD_CF_DIRTY;
	}

	(void) pthread_mutex_unlock(&cip->ci_lock);
}

/*
 * Indicate that the case may need to change state because one or more of the
 * ASRUs named as a suspect has changed state.  We examine all the suspects
 * and if none are still faulty, we initiate a case close transition.
 */
void
fmd_case_update(fmd_case_t *cp)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;
	uint_t cstate;
	int faulty = 0;

	(void) pthread_mutex_lock(&cip->ci_lock);
	cstate = cip->ci_state;

	if (cip->ci_xprt != NULL || cip->ci_state < FMD_CASE_SOLVED) {
		(void) pthread_mutex_unlock(&cip->ci_lock);
		return; /* update is not appropriate */
	}

	if (cip->ci_flags & FMD_CF_REPAIRED) {
		(void) pthread_mutex_unlock(&cip->ci_lock);
		return; /* already repaired */
	}

	fmd_asru_hash_apply_by_case(fmd.d_asrus, cp, fmd_case_faulty, &faulty);
	(void) pthread_mutex_unlock(&cip->ci_lock);

	if (faulty)
		return; /* one or more suspects are still marked faulty */

	if (cstate == FMD_CASE_CLOSED)
		fmd_case_transition(cp, FMD_CASE_REPAIRED, FMD_CF_REPAIRED);
	else
		fmd_case_transition(cp, FMD_CASE_CLOSE_WAIT, FMD_CF_REPAIRED);
}

/*
 * Delete a closed case from the module's case list once the fmdo_close() entry
 * point has run to completion.  If the case is owned by a transport module,
 * tell the transport to proxy a case close on the other end of the transport.
 * If not, transition to the appropriate next state based on ci_flags.  This
 * function represents the end of CLOSE_WAIT and transitions the case to either
 * CLOSED or REPAIRED or discards it entirely because it was never solved;
 * refer to the topmost block comment explaining the state machine for details.
 */
void
fmd_case_delete(fmd_case_t *cp)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;
	fmd_modstat_t *msp;
	size_t buftotal;

	ASSERT(fmd_module_locked(cip->ci_mod));
	fmd_list_delete(&cip->ci_mod->mod_cases, cip);
	buftotal = fmd_buf_hash_destroy(&cip->ci_bufs);

	(void) pthread_mutex_lock(&cip->ci_mod->mod_stats_lock);
	msp = cip->ci_mod->mod_stats;

	ASSERT(msp->ms_caseopen.fmds_value.ui64 != 0);
	msp->ms_caseopen.fmds_value.ui64--;

	ASSERT(msp->ms_buftotal.fmds_value.ui64 >= buftotal);
	msp->ms_buftotal.fmds_value.ui64 -= buftotal;

	(void) pthread_mutex_unlock(&cip->ci_mod->mod_stats_lock);

	if (cip->ci_xprt == NULL)
		fmd_module_setcdirty(cip->ci_mod);

	fmd_module_rele(cip->ci_mod);
	cip->ci_mod = fmd.d_rmod;
	fmd_module_hold(cip->ci_mod);

	/*
	 * If the case is not proxied and it has been solved, then retain it
	 * on the root module's case list at least until we're transitioned.
	 * Otherwise free the case with our final fmd_case_rele() below.
	 */
	if (cip->ci_xprt == NULL && (cip->ci_flags & FMD_CF_SOLVED)) {
		fmd_module_lock(cip->ci_mod);
		fmd_list_append(&cip->ci_mod->mod_cases, cip);
		fmd_module_unlock(cip->ci_mod);
		fmd_case_hold(cp);
	}

	/*
	 * If a proxied case finishes CLOSE_WAIT, then it can be discarded
	 * rather than orphaned because by definition it can have no entries
	 * in the resource cache of the current fault manager.
	 */
	if (cip->ci_xprt != NULL)
		fmd_xprt_uuclose(cip->ci_xprt, cip->ci_uuid);
	else if (cip->ci_flags & FMD_CF_REPAIRED)
		fmd_case_transition(cp, FMD_CASE_REPAIRED, 0);
	else if (cip->ci_flags & FMD_CF_ISOLATED)
		fmd_case_transition(cp, FMD_CASE_CLOSED, 0);

	fmd_case_rele(cp);
}

void
fmd_case_discard(fmd_case_t *cp)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;

	(void) pthread_mutex_lock(&cip->ci_mod->mod_stats_lock);
	cip->ci_mod->mod_stats->ms_caseopen.fmds_value.ui64--;
	(void) pthread_mutex_unlock(&cip->ci_mod->mod_stats_lock);

	ASSERT(fmd_module_locked(cip->ci_mod));
	fmd_list_delete(&cip->ci_mod->mod_cases, cip);
	fmd_case_rele(cp);
}

/*
 * Indicate that the problem corresponding to a case has been repaired by
 * clearing the faulty bit on each ASRU named as a suspect.  If the case hasn't
 * already been closed, this function initiates the transition to CLOSE_WAIT.
 * The caller must have the case held from fmd_case_hash_lookup(), so we can
 * grab and drop ci_lock without the case being able to be freed in between.
 */
int
fmd_case_repair(fmd_case_t *cp)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;
	uint_t cstate;

	(void) pthread_mutex_lock(&cip->ci_lock);
	cstate = cip->ci_state;

	if (cip->ci_xprt != NULL) {
		(void) pthread_mutex_unlock(&cip->ci_lock);
		return (fmd_set_errno(EFMD_CASE_OWNER));
	}

	if (cstate < FMD_CASE_SOLVED) {
		(void) pthread_mutex_unlock(&cip->ci_lock);
		return (fmd_set_errno(EFMD_CASE_STATE));
	}

	if (cip->ci_flags & FMD_CF_REPAIRED) {
		(void) pthread_mutex_unlock(&cip->ci_lock);
		return (0); /* already repaired */
	}

	fmd_asru_hash_apply_by_case(fmd.d_asrus, cp, fmd_asru_repair, NULL);
	(void) pthread_mutex_unlock(&cip->ci_lock);

	if (cstate == FMD_CASE_CLOSED)
		fmd_case_transition(cp, FMD_CASE_REPAIRED, FMD_CF_REPAIRED);
	else
		fmd_case_transition(cp, FMD_CASE_CLOSE_WAIT, FMD_CF_REPAIRED);

	return (0);
}

int
fmd_case_contains(fmd_case_t *cp, fmd_event_t *ep)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;
	fmd_case_item_t *cit;
	uint_t state;
	int rv = 0;

	(void) pthread_mutex_lock(&cip->ci_lock);

	if (cip->ci_state >= FMD_CASE_SOLVED)
		state = FMD_EVS_DIAGNOSED;
	else
		state = FMD_EVS_ACCEPTED;

	for (cit = cip->ci_items; cit != NULL; cit = cit->cit_next) {
		if ((rv = fmd_event_equal(ep, cit->cit_event)) != 0)
			break;
	}

	if (rv == 0 && cip->ci_principal != NULL)
		rv = fmd_event_equal(ep, cip->ci_principal);

	(void) pthread_mutex_unlock(&cip->ci_lock);

	if (rv != 0)
		fmd_event_transition(ep, state);

	return (rv);
}

int
fmd_case_orphaned(fmd_case_t *cp)
{
	return (((fmd_case_impl_t *)cp)->ci_mod == fmd.d_rmod);
}

void
fmd_case_settime(fmd_case_t *cp, time_t tv_sec, suseconds_t tv_usec)
{
	((fmd_case_impl_t *)cp)->ci_tv.tv_sec = tv_sec;
	((fmd_case_impl_t *)cp)->ci_tv.tv_usec = tv_usec;
	((fmd_case_impl_t *)cp)->ci_tv_valid = 1;
}
