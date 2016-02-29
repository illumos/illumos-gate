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
 *	     |		      1 |
 *	     |			|
 *	     |		+-------v----+
 *	   2 |		|    SOLVED  |
 *	     |		+------------+
 *	     |		    3 |  5 |
 *	     +------------+   |    |
 *			  |   |    |
 *			+-v---v----v-+
 *			| CLOSE_WAIT |
 *			+------------+
 *			  |   |    |
 *	      +-----------+   |    +------------+
 *	      |		    4 |			|
 *	      v		+-----v------+		|
 *	   discard      |   CLOSED   |	      6	|
 *			+------------+		|
 *			      |			|
 *			      |	   +------------+
 *			    7 |	   |
 *			+-----v----v-+
 *			|  REPAIRED  |
 *			+------------+
 *			      |
 *			    8 |
 *			+-----v------+
 *			|  RESOLVED  |
 *			+------------+
 *			      |
 *			      v
 *			   discard
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
 * [2] Called by: fmd_case_close(), fmd_case_uuclose()
 *       Actions: diagnosis engine fmdo_close() entry point scheduled
 *                case discarded upon exit from CLOSE_WAIT
 *
 * [3] Called by: fmd_case_close(), fmd_case_uuclose(), fmd_xprt_event_uuclose()
 *       Actions: FMD_CF_ISOLATED flag is set in ci_flags
 *                suspects convicted (F) are marked unusable (U) in R$
 *                diagnosis engine fmdo_close() entry point scheduled
 *                case transitions to CLOSED [4] upon exit from CLOSE_WAIT
 *
 * [4] Called by: fmd_case_delete() (after fmdo_close() entry point returns)
 *       Actions: list.isolated event dispatched
 *                case deleted from module's list of open cases
 *
 * [5] Called by: fmd_case_repair(), fmd_case_update()
 *       Actions: FMD_CF_REPAIR flag is set in ci_flags
 *                diagnosis engine fmdo_close() entry point scheduled
 *                case transitions to REPAIRED [6] upon exit from CLOSE_WAIT
 *
 * [6] Called by: fmd_case_delete() (after fmdo_close() entry point returns)
 *       Actions: suspects convicted are marked non faulty (!F) in R$
 *                list.repaired or list.updated event dispatched
 *
 * [7] Called by: fmd_case_repair(), fmd_case_update()
 *       Actions: FMD_CF_REPAIR flag is set in ci_flags
 *                suspects convicted are marked non faulty (!F) in R$
 *                list.repaired or list.updated event dispatched
 *
 * [8] Called by: fmd_case_uuresolve()
 *       Actions: list.resolved event dispatched
 *		  case is discarded
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
	"REPAIRED",	/* FMD_CASE_REPAIRED */
	"RESOLVED"	/* FMD_CASE_RESOLVED */
};

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
		for (cp = chp->ch_hash[i]; cp != NULL; cp = cp->ci_next)
			*cpp++ = fmd_case_tryhold(cp);
	}

	ASSERT(cpp == cps + cpc);
	(void) pthread_rwlock_unlock(&chp->ch_lock);

	for (i = 0; i < cpc; i++) {
		if (cps[i] != NULL) {
			func((fmd_case_t *)cps[i], arg);
			fmd_case_rele((fmd_case_t *)cps[i]);
		}
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
	int	fcl_maxcount;
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

	if (*entryp->fcl_countp >= entryp->fcl_maxcount)
		return;
	if (nvlist_lookup_boolean_value(alp->al_event, FM_SUSPECT_MESSAGE,
	    &b) == 0 && b == B_FALSE)
		*entryp->fcl_msgp = B_FALSE;
	entryp->fcl_ba[*entryp->fcl_countp] = 0;
	state = fmd_asru_al_getstate(alp);
	if (state & FMD_ASRU_DEGRADED)
		entryp->fcl_ba[*entryp->fcl_countp] |= FM_SUSPECT_DEGRADED;
	if (state & FMD_ASRU_UNUSABLE)
		entryp->fcl_ba[*entryp->fcl_countp] |= FM_SUSPECT_UNUSABLE;
	if (state & FMD_ASRU_FAULTY)
		entryp->fcl_ba[*entryp->fcl_countp] |= FM_SUSPECT_FAULTY;
	if (!(state & FMD_ASRU_PRESENT))
		entryp->fcl_ba[*entryp->fcl_countp] |= FM_SUSPECT_NOT_PRESENT;
	if (alp->al_reason == FMD_ASRU_REPAIRED)
		entryp->fcl_ba[*entryp->fcl_countp] |= FM_SUSPECT_REPAIRED;
	else if (alp->al_reason == FMD_ASRU_REPLACED)
		entryp->fcl_ba[*entryp->fcl_countp] |= FM_SUSPECT_REPLACED;
	else if (alp->al_reason == FMD_ASRU_ACQUITTED)
		entryp->fcl_ba[*entryp->fcl_countp] |= FM_SUSPECT_ACQUITTED;
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

static void
fmd_case_not_faulty(fmd_asru_link_t *alp, void *arg)
{
	int *not_faultyp = (int *)arg;

	*not_faultyp |= !(alp->al_flags & FMD_ASRU_FAULTY);
}

/*
 * Have we got any suspects with an asru that are still unusable and present?
 */
static void
fmd_case_unusable_and_present(fmd_asru_link_t *alp, void *arg)
{
	int *rvalp = (int *)arg;
	int state;
	nvlist_t *asru;

	/*
	 * if this a proxy case and this suspect doesn't have an local asru
	 * then state is unknown so we must assume it may still be unusable.
	 */
	if ((alp->al_flags & FMD_ASRU_PROXY) &&
	    !(alp->al_flags & FMD_ASRU_PROXY_WITH_ASRU)) {
		*rvalp |= B_TRUE;
		return;
	}

	state = fmd_asru_al_getstate(alp);
	if (nvlist_lookup_nvlist(alp->al_event, FM_FAULT_ASRU, &asru) != 0)
		return;
	*rvalp |= ((state & FMD_ASRU_UNUSABLE) && (state & FMD_ASRU_PRESENT));
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
	fcl.fcl_maxcount = cip->ci_nsuspects;
	fcl.fcl_msgp = &msg;
	fcl.fcl_ba = ba;
	fcl.fcl_nva = nva;
	fmd_asru_hash_apply_by_case(fmd.d_asrus, cp, fmd_case_set_lst, &fcl);

	if (cip->ci_code == NULL)
		(void) fmd_case_mkcode(cp);
	/*
	 * For repair and updated event, we lookup diagcode from dict using key
	 * "list.repaired" or "list.updated" or "list.resolved".
	 */
	if (strcmp(class, FM_LIST_REPAIRED_CLASS) == 0)
		(void) fmd_conf_getprop(fmd.d_conf, "repaircode", &code);
	else if (strcmp(class, FM_LIST_RESOLVED_CLASS) == 0)
		(void) fmd_conf_getprop(fmd.d_conf, "resolvecode", &code);
	else if (strcmp(class, FM_LIST_UPDATED_CLASS) == 0)
		(void) fmd_conf_getprop(fmd.d_conf, "updatecode", &code);
	else
		code = cip->ci_code;

	if (msg == B_FALSE)
		cip->ci_flags |= FMD_CF_INVISIBLE;

	/*
	 * Use the ci_diag_de if one has been saved (eg for an injected fault).
	 * Otherwise use the authority for the current module.
	 */
	nvl = fmd_protocol_list(class, cip->ci_diag_de == NULL ?
	    cip->ci_mod->mod_fmri : cip->ci_diag_de, cip->ci_uuid, code, count,
	    nva, ba, msg, &cip->ci_tv, cip->ci_injected);

	(void) pthread_mutex_unlock(&cip->ci_lock);
	return (nvl);
}

static int fmd_case_match_on_faulty_overlap = 1;
static int fmd_case_match_on_acquit_overlap = 1;
static int fmd_case_auto_acquit_isolated = 1;
static int fmd_case_auto_acquit_non_acquitted = 1;
static int fmd_case_too_recent = 10; /* time in seconds */

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
fmd_case_match_suspect(nvlist_t *nvl1, nvlist_t *nvl2)
{
	char *class, *new_class;

	if (!fmd_case_compare_elem(nvl1, nvl2, FM_FAULT_ASRU))
		return (0);
	if (!fmd_case_compare_elem(nvl1, nvl2, FM_FAULT_RESOURCE))
		return (0);
	if (!fmd_case_compare_elem(nvl1, nvl2, FM_FAULT_FRU))
		return (0);
	(void) nvlist_lookup_string(nvl2, FM_CLASS, &class);
	(void) nvlist_lookup_string(nvl1, FM_CLASS, &new_class);
	return (strcmp(class, new_class) == 0);
}

typedef struct {
	int	*fcms_countp;
	int	fcms_maxcount;
	fmd_case_impl_t *fcms_cip;
	uint8_t *fcms_new_susp_state;
	uint8_t *fcms_old_susp_state;
	uint8_t *fcms_old_match_state;
} fcms_t;
#define	SUSPECT_STATE_FAULTY				0x1
#define	SUSPECT_STATE_ISOLATED				0x2
#define	SUSPECT_STATE_REMOVED				0x4
#define	SUSPECT_STATE_ACQUITED				0x8
#define	SUSPECT_STATE_REPAIRED				0x10
#define	SUSPECT_STATE_REPLACED				0x20
#define	SUSPECT_STATE_NO_MATCH				0x1

/*
 * This is called for each suspect in the old case. Compare it against each
 * suspect in the new case, setting fcms_old_susp_state and fcms_new_susp_state
 * as appropriate. fcms_new_susp_state will left as 0 if the suspect is not
 * found in the old case.
 */
static void
fmd_case_match_suspects(fmd_asru_link_t *alp, void *arg)
{
	fcms_t *fcmsp = (fcms_t *)arg;
	fmd_case_impl_t *cip = fcmsp->fcms_cip;
	fmd_case_susp_t *cis;
	int i = 0;
	int state = fmd_asru_al_getstate(alp);

	if (*fcmsp->fcms_countp >= fcmsp->fcms_maxcount)
		return;

	if (!(state & FMD_ASRU_PRESENT) || (!(state & FMD_ASRU_FAULTY) &&
	    alp->al_reason == FMD_ASRU_REMOVED))
		fcmsp->fcms_old_susp_state[*fcmsp->fcms_countp] =
		    SUSPECT_STATE_REMOVED;
	else if ((state & FMD_ASRU_UNUSABLE) && (state & FMD_ASRU_FAULTY))
		fcmsp->fcms_old_susp_state[*fcmsp->fcms_countp] =
		    SUSPECT_STATE_ISOLATED;
	else if (state & FMD_ASRU_FAULTY)
		fcmsp->fcms_old_susp_state[*fcmsp->fcms_countp] =
		    SUSPECT_STATE_FAULTY;
	else if (alp->al_reason == FMD_ASRU_REPLACED)
		fcmsp->fcms_old_susp_state[*fcmsp->fcms_countp] =
		    SUSPECT_STATE_REPLACED;
	else if (alp->al_reason == FMD_ASRU_ACQUITTED)
		fcmsp->fcms_old_susp_state[*fcmsp->fcms_countp] =
		    SUSPECT_STATE_ACQUITED;
	else
		fcmsp->fcms_old_susp_state[*fcmsp->fcms_countp] =
		    SUSPECT_STATE_REPAIRED;

	for (cis = cip->ci_suspects; cis != NULL; cis = cis->cis_next, i++)
		if (fmd_case_match_suspect(cis->cis_nvl, alp->al_event) == 1)
			break;
	if (cis != NULL)
		fcmsp->fcms_new_susp_state[i] =
		    fcmsp->fcms_old_susp_state[*fcmsp->fcms_countp];
	else
		fcmsp->fcms_old_match_state[*fcmsp->fcms_countp] |=
		    SUSPECT_STATE_NO_MATCH;
	(*fcmsp->fcms_countp)++;
}

typedef struct {
	int	*fca_do_update;
	fmd_case_impl_t *fca_cip;
} fca_t;

/*
 * Re-fault all acquitted suspects that are still present in the new list.
 */
static void
fmd_case_fault_acquitted_matching(fmd_asru_link_t *alp, void *arg)
{
	fca_t *fcap = (fca_t *)arg;
	fmd_case_impl_t *cip = fcap->fca_cip;
	fmd_case_susp_t *cis;
	int state = fmd_asru_al_getstate(alp);

	if (!(state & FMD_ASRU_FAULTY) &&
	    alp->al_reason == FMD_ASRU_ACQUITTED) {
		for (cis = cip->ci_suspects; cis != NULL; cis = cis->cis_next)
			if (fmd_case_match_suspect(cis->cis_nvl,
			    alp->al_event) == 1)
				break;
		if (cis != NULL) {
			(void) fmd_asru_setflags(alp, FMD_ASRU_FAULTY);
			*fcap->fca_do_update = 1;
		}
	}
}

/*
 * Re-fault all suspects that are still present in the new list.
 */
static void
fmd_case_fault_all_matching(fmd_asru_link_t *alp, void *arg)
{
	fca_t *fcap = (fca_t *)arg;
	fmd_case_impl_t *cip = fcap->fca_cip;
	fmd_case_susp_t *cis;
	int state = fmd_asru_al_getstate(alp);

	if (!(state & FMD_ASRU_FAULTY)) {
		for (cis = cip->ci_suspects; cis != NULL; cis = cis->cis_next)
			if (fmd_case_match_suspect(cis->cis_nvl,
			    alp->al_event) == 1)
				break;
		if (cis != NULL) {
			(void) fmd_asru_setflags(alp, FMD_ASRU_FAULTY);
			*fcap->fca_do_update = 1;
		}
	}
}

/*
 * Acquit all suspects that are no longer present in the new list.
 */
static void
fmd_case_acquit_no_match(fmd_asru_link_t *alp, void *arg)
{
	fca_t *fcap = (fca_t *)arg;
	fmd_case_impl_t *cip = fcap->fca_cip;
	fmd_case_susp_t *cis;
	int state = fmd_asru_al_getstate(alp);

	if (state & FMD_ASRU_FAULTY) {
		for (cis = cip->ci_suspects; cis != NULL; cis = cis->cis_next)
			if (fmd_case_match_suspect(cis->cis_nvl,
			    alp->al_event) == 1)
				break;
		if (cis == NULL) {
			(void) fmd_asru_clrflags(alp, FMD_ASRU_FAULTY,
			    FMD_ASRU_ACQUITTED);
			*fcap->fca_do_update = 1;
		}
	}
}

/*
 * Acquit all isolated suspects.
 */
static void
fmd_case_acquit_isolated(fmd_asru_link_t *alp, void *arg)
{
	int *do_update = (int *)arg;
	int state = fmd_asru_al_getstate(alp);

	if ((state & FMD_ASRU_PRESENT) && (state & FMD_ASRU_UNUSABLE) &&
	    (state & FMD_ASRU_FAULTY)) {
		(void) fmd_asru_clrflags(alp, FMD_ASRU_FAULTY,
		    FMD_ASRU_ACQUITTED);
		*do_update = 1;
	}
}

/*
 * Acquit suspect which matches specified nvlist
 */
static void
fmd_case_acquit_suspect(fmd_asru_link_t *alp, void *arg)
{
	nvlist_t *nvl = (nvlist_t *)arg;
	int state = fmd_asru_al_getstate(alp);

	if ((state & FMD_ASRU_FAULTY) &&
	    fmd_case_match_suspect(nvl, alp->al_event) == 1)
		(void) fmd_asru_clrflags(alp, FMD_ASRU_FAULTY,
		    FMD_ASRU_ACQUITTED);
}

typedef struct {
	fmd_case_impl_t *fccd_cip;
	uint8_t *fccd_new_susp_state;
	uint8_t *fccd_new_match_state;
	int *fccd_discard_new;
	int *fccd_adjust_new;
} fccd_t;

/*
 * see if a matching suspect list already exists in the cache
 */
static void
fmd_case_check_for_dups(fmd_case_t *old_cp, void *arg)
{
	fccd_t *fccdp = (fccd_t *)arg;
	fmd_case_impl_t *new_cip = fccdp->fccd_cip;
	fmd_case_impl_t *old_cip = (fmd_case_impl_t *)old_cp;
	int i, count = 0, do_update = 0, got_isolated_overlap = 0;
	int got_faulty_overlap = 0;
	int got_acquit_overlap = 0;
	boolean_t too_recent;
	uint64_t most_recent = 0;
	fcms_t fcms;
	fca_t fca;
	uint8_t *new_susp_state;
	uint8_t *old_susp_state;
	uint8_t *old_match_state;

	new_susp_state = alloca(new_cip->ci_nsuspects * sizeof (uint8_t));
	for (i = 0; i < new_cip->ci_nsuspects; i++)
		new_susp_state[i] = 0;
	old_susp_state = alloca(old_cip->ci_nsuspects * sizeof (uint8_t));
	for (i = 0; i < old_cip->ci_nsuspects; i++)
		old_susp_state[i] = 0;
	old_match_state = alloca(old_cip->ci_nsuspects * sizeof (uint8_t));
	for (i = 0; i < old_cip->ci_nsuspects; i++)
		old_match_state[i] = 0;

	/*
	 * Compare with each suspect in the existing case.
	 */
	fcms.fcms_countp = &count;
	fcms.fcms_maxcount = old_cip->ci_nsuspects;
	fcms.fcms_cip = new_cip;
	fcms.fcms_new_susp_state = new_susp_state;
	fcms.fcms_old_susp_state = old_susp_state;
	fcms.fcms_old_match_state = old_match_state;
	fmd_asru_hash_apply_by_case(fmd.d_asrus, (fmd_case_t *)old_cip,
	    fmd_case_match_suspects, &fcms);

	/*
	 * If we have some faulty, non-isolated suspects that overlap, then most
	 * likely it is the suspects that overlap in the suspect lists that are
	 * to blame. So we can consider this to be a match.
	 */
	for (i = 0; i < new_cip->ci_nsuspects; i++)
		if (new_susp_state[i] == SUSPECT_STATE_FAULTY)
			got_faulty_overlap = 1;
	if (got_faulty_overlap && fmd_case_match_on_faulty_overlap)
		goto got_match;

	/*
	 * If we have no faulty, non-isolated suspects in the old case, but we
	 * do have some acquitted suspects that overlap, then most likely it is
	 * the acquitted suspects that overlap in the suspect lists that are
	 * to blame. So we can consider this to be a match.
	 */
	for (i = 0; i < new_cip->ci_nsuspects; i++)
		if (new_susp_state[i] == SUSPECT_STATE_ACQUITED)
			got_acquit_overlap = 1;
	for (i = 0; i < old_cip->ci_nsuspects; i++)
		if (old_susp_state[i] == SUSPECT_STATE_FAULTY)
			got_acquit_overlap = 0;
	if (got_acquit_overlap && fmd_case_match_on_acquit_overlap)
		goto got_match;

	/*
	 * Check that all suspects in the new list are present in the old list.
	 * Return if we find one that isn't.
	 */
	for (i = 0; i < new_cip->ci_nsuspects; i++)
		if (new_susp_state[i] == 0)
			return;

	/*
	 * Check that all suspects in the old list are present in the new list
	 * *or* they are isolated or removed/replaced (which would explain why
	 * they are not present in the new list). Return if we find one that is
	 * faulty and unisolated or repaired or acquitted, and that is not
	 * present in the new case.
	 */
	for (i = 0; i < old_cip->ci_nsuspects; i++)
		if (old_match_state[i] == SUSPECT_STATE_NO_MATCH &&
		    (old_susp_state[i] == SUSPECT_STATE_FAULTY ||
		    old_susp_state[i] == SUSPECT_STATE_ACQUITED ||
		    old_susp_state[i] == SUSPECT_STATE_REPAIRED))
			return;

got_match:
	/*
	 * If the old case is already in repaired/resolved state, we can't
	 * do anything more with it, so keep the new case, but acquit some
	 * of the suspects if appropriate.
	 */
	if (old_cip->ci_state >= FMD_CASE_REPAIRED) {
		if (fmd_case_auto_acquit_non_acquitted) {
			*fccdp->fccd_adjust_new = 1;
			for (i = 0; i < new_cip->ci_nsuspects; i++) {
				fccdp->fccd_new_susp_state[i] |=
				    new_susp_state[i];
				if (new_susp_state[i] == 0)
					fccdp->fccd_new_susp_state[i] =
					    SUSPECT_STATE_NO_MATCH;
			}
		}
		return;
	}

	/*
	 * Otherwise discard the new case and keep the old, again updating the
	 * state of the suspects as appropriate
	 */
	*fccdp->fccd_discard_new = 1;
	fca.fca_cip = new_cip;
	fca.fca_do_update = &do_update;

	/*
	 * See if new case occurred within fmd_case_too_recent seconds of the
	 * most recent modification to the old case and if so don't do
	 * auto-acquit. This avoids problems if a flood of ereports come in and
	 * they don't all get diagnosed before the first case causes some of
	 * the devices to be isolated making it appear that an isolated device
	 * was in the suspect list.
	 */
	fmd_asru_hash_apply_by_case(fmd.d_asrus, old_cp,
	    fmd_asru_most_recent, &most_recent);
	too_recent = (new_cip->ci_tv.tv_sec - most_recent <
	    fmd_case_too_recent);

	if (got_faulty_overlap) {
		/*
		 * Acquit any suspects not present in the new list, plus
		 * any that are are present but are isolated.
		 */
		fmd_asru_hash_apply_by_case(fmd.d_asrus, old_cp,
		    fmd_case_acquit_no_match, &fca);
		if (fmd_case_auto_acquit_isolated && !too_recent)
			fmd_asru_hash_apply_by_case(fmd.d_asrus, old_cp,
			    fmd_case_acquit_isolated, &do_update);
	} else if (got_acquit_overlap) {
		/*
		 * Re-fault the acquitted matching suspects and acquit all
		 * isolated suspects.
		 */
		if (fmd_case_auto_acquit_isolated && !too_recent) {
			fmd_asru_hash_apply_by_case(fmd.d_asrus, old_cp,
			    fmd_case_fault_acquitted_matching, &fca);
			fmd_asru_hash_apply_by_case(fmd.d_asrus, old_cp,
			    fmd_case_acquit_isolated, &do_update);
		}
	} else if (fmd_case_auto_acquit_isolated) {
		/*
		 * To get here, there must be no faulty or acquitted suspects,
		 * but there must be at least one isolated suspect. Just acquit
		 * non-matching isolated suspects. If there are no matching
		 * isolated suspects, then re-fault all matching suspects.
		 */
		for (i = 0; i < new_cip->ci_nsuspects; i++)
			if (new_susp_state[i] == SUSPECT_STATE_ISOLATED)
				got_isolated_overlap = 1;
		if (!got_isolated_overlap)
			fmd_asru_hash_apply_by_case(fmd.d_asrus, old_cp,
			    fmd_case_fault_all_matching, &fca);
		fmd_asru_hash_apply_by_case(fmd.d_asrus, old_cp,
		    fmd_case_acquit_no_match, &fca);
	}

	/*
	 * If we've updated anything in the old case, call fmd_case_update()
	 */
	if (do_update)
		fmd_case_update(old_cp);
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
	int discard_new = 0, i;
	fmd_case_susp_t *cis;
	fmd_asru_link_t *alp;
	uint8_t *new_susp_state;
	uint8_t *new_match_state;
	int adjust_new = 0;
	fccd_t fccd;
	fmd_case_impl_t *ncp, **cps, **cpp;
	uint_t cpc;
	fmd_case_hash_t *chp;

	/*
	 * First we must see if any matching cases already exist.
	 */
	new_susp_state = alloca(cip->ci_nsuspects * sizeof (uint8_t));
	for (i = 0; i < cip->ci_nsuspects; i++)
		new_susp_state[i] = 0;
	new_match_state = alloca(cip->ci_nsuspects * sizeof (uint8_t));
	for (i = 0; i < cip->ci_nsuspects; i++)
		new_match_state[i] = 0;
	fccd.fccd_cip = cip;
	fccd.fccd_adjust_new = &adjust_new;
	fccd.fccd_new_susp_state = new_susp_state;
	fccd.fccd_new_match_state = new_match_state;
	fccd.fccd_discard_new = &discard_new;

	/*
	 * Hold all cases
	 */
	chp = fmd.d_cases;
	(void) pthread_rwlock_rdlock(&chp->ch_lock);
	cps = cpp = fmd_alloc(chp->ch_count * sizeof (fmd_case_t *), FMD_SLEEP);
	cpc = chp->ch_count;
	for (i = 0; i < chp->ch_hashlen; i++)
		for (ncp = chp->ch_hash[i]; ncp != NULL; ncp = ncp->ci_next)
			*cpp++ = fmd_case_tryhold(ncp);
	ASSERT(cpp == cps + cpc);
	(void) pthread_rwlock_unlock(&chp->ch_lock);

	/*
	 * Run fmd_case_check_for_dups() on all cases except the current one.
	 */
	for (i = 0; i < cpc; i++) {
		if (cps[i] != NULL) {
			if (cps[i] != (fmd_case_impl_t *)cp)
				fmd_case_check_for_dups((fmd_case_t *)cps[i],
				    &fccd);
			fmd_case_rele((fmd_case_t *)cps[i]);
		}
	}
	fmd_free(cps, cpc * sizeof (fmd_case_t *));

	(void) pthread_mutex_lock(&cip->ci_lock);
	if (cip->ci_code == NULL)
		(void) fmd_case_mkcode(cp);
	else if (cip->ci_precanned)
		fmd_case_code_hash_insert(fmd.d_cases, cip);

	if (discard_new) {
		/*
		 * We've found an existing case that is a match and it is not
		 * already in repaired or resolved state. So we can close this
		 * one as a duplicate.
		 */
		(void) pthread_mutex_unlock(&cip->ci_lock);
		return (1);
	}

	/*
	 * Allocate new cache entries
	 */
	for (cis = cip->ci_suspects; cis != NULL; cis = cis->cis_next) {
		if ((alp = fmd_asru_hash_create_entry(ahp,
		    cp, cis->cis_nvl)) == NULL) {
			fmd_error(EFMD_CASE_EVENT, "cannot convict suspect in "
			    "%s: %s\n", cip->ci_uuid, fmd_strerror(errno));
			continue;
		}
		alp->al_flags |= FMD_ASRU_PRESENT;
		alp->al_asru->asru_flags |= FMD_ASRU_PRESENT;
		(void) fmd_asru_clrflags(alp, FMD_ASRU_UNUSABLE, 0);
		(void) fmd_asru_setflags(alp, FMD_ASRU_FAULTY);
	}

	if (adjust_new) {
		int some_suspect = 0, some_not_suspect = 0;

		/*
		 * There is one or more matching case but they are already in
		 * repaired or resolved state. So we need to keep the new
		 * case, but we can adjust it. Repaired/removed/replaced
		 * suspects are unlikely to be to blame (unless there are
		 * actually two separate faults). So if we have a combination of
		 * repaired/replaced/removed suspects and acquitted suspects in
		 * the old lists, then we should acquit in the new list those
		 * that were repaired/replaced/removed in the old.
		 */
		for (i = 0; i < cip->ci_nsuspects; i++) {
			if ((new_susp_state[i] & SUSPECT_STATE_REPLACED) ||
			    (new_susp_state[i] & SUSPECT_STATE_REPAIRED) ||
			    (new_susp_state[i] & SUSPECT_STATE_REMOVED) ||
			    (new_match_state[i] & SUSPECT_STATE_NO_MATCH))
				some_not_suspect = 1;
			else
				some_suspect = 1;
		}
		if (some_suspect && some_not_suspect) {
			for (cis = cip->ci_suspects, i = 0; cis != NULL;
			    cis = cis->cis_next, i++)
				if ((new_susp_state[i] &
				    SUSPECT_STATE_REPLACED) ||
				    (new_susp_state[i] &
				    SUSPECT_STATE_REPAIRED) ||
				    (new_susp_state[i] &
				    SUSPECT_STATE_REMOVED) ||
				    (new_match_state[i] &
				    SUSPECT_STATE_NO_MATCH))
					fmd_asru_hash_apply_by_case(fmd.d_asrus,
					    cp, fmd_case_acquit_suspect,
					    cis->cis_nvl);
		}
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

		/*
		 * If we already have a code, then case is already solved.
		 */
		if (cip->ci_precanned == 0 && cip->ci_xprt == NULL &&
		    cip->ci_code != NULL) {
			(void) pthread_mutex_unlock(&cip->ci_lock);
			break;
		}

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
		if (cip->ci_xprt != NULL) {
			/*
			 * For proxy, save some information about the transport
			 * in the resource cache.
			 */
			int count = 0;
			fmd_asru_set_on_proxy_t fasp;
			fmd_xprt_impl_t *xip = (fmd_xprt_impl_t *)cip->ci_xprt;

			fasp.fasp_countp = &count;
			fasp.fasp_maxcount = cip->ci_nsuspects;
			fasp.fasp_proxy_asru = cip->ci_proxy_asru;
			fasp.fasp_proxy_external = xip->xi_flags &
			    FMD_XPRT_EXTERNAL;
			fasp.fasp_proxy_rdonly = ((xip->xi_flags &
			    FMD_XPRT_RDWR) == FMD_XPRT_RDONLY);
			fmd_asru_hash_apply_by_case(fmd.d_asrus, cp,
			    fmd_asru_set_on_proxy, &fasp);
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

	case FMD_CASE_RESOLVED:
		nvl = fmd_case_mkevent(cp, FM_LIST_RESOLVED_CLASS);
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
fmd_case_create(fmd_module_t *mp, const char *uuidstr, void *data)
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

	if (uuidstr == NULL) {
		/*
		 * We expect this loop to execute only once, but code it
		 * defensively against the possibility of libuuid bugs.
		 * Keep generating uuids and attempting to do a hash insert
		 * until we get a unique one.
		 */
		do {
			if (eip != NULL)
				fmd_case_rele((fmd_case_t *)eip);
			uuid_generate(uuid);
			uuid_unparse(uuid, cip->ci_uuid);
		} while ((eip = fmd_case_hash_insert(fmd.d_cases, cip)) != cip);
	} else {
		/*
		 * If a uuid was specified we must succeed with that uuid,
		 * or return NULL indicating a case with that uuid already
		 * exists.
		 */
		(void) strncpy(cip->ci_uuid, uuidstr, cip->ci_uuidlen + 1);
		if (fmd_case_hash_insert(fmd.d_cases, cip) != cip) {
			fmd_free(cip->ci_uuid, cip->ci_uuidlen + 1);
			(void) fmd_buf_hash_destroy(&cip->ci_bufs);
			fmd_module_rele(mp);
			pthread_mutex_destroy(&cip->ci_lock);
			fmd_free(cip, sizeof (*cip));
			return (NULL);
		}
	}

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

	if (cip->ci_proxy_asru)
		fmd_free(cip->ci_proxy_asru, sizeof (uint8_t) *
		    cip->ci_nsuspects);
	nvlist_free(cip->ci_diag_de);
	if (cip->ci_diag_asru)
		fmd_free(cip->ci_diag_asru, sizeof (uint8_t) *
		    cip->ci_nsuspects);

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
			/*
			 * In case the case has already been created from
			 * a checkpoint file we need to set up code now.
			 */
			if (cip->ci_state < FMD_CASE_CLOSED) {
				if (code != NULL && cip->ci_code == NULL) {
					cip->ci_code = fmd_strdup(code,
					    FMD_SLEEP);
					cip->ci_codelen = cip->ci_code ?
					    strlen(cip->ci_code) + 1 : 0;
					fmd_case_code_hash_insert(fmd.d_cases,
					    cip);
				}
			}

			/*
			 * When recreating an orphan case, state passed in may
			 * be CLOSED (faulty) or REPAIRED/RESOLVED (!faulty). If
			 * any suspects are still CLOSED (faulty) then the
			 * overall state needs to be CLOSED.
			 */
			if ((cip->ci_state == FMD_CASE_REPAIRED ||
			    cip->ci_state == FMD_CASE_RESOLVED) &&
			    state == FMD_CASE_CLOSED)
				cip->ci_state = FMD_CASE_CLOSED;
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

		/*
		 * It's possible that fmd crashed or was restarted during a
		 * previous solve operation between the asru cache being created
		 * and the ckpt file being updated to SOLVED. Thus when the DE
		 * recreates the case here from the checkpoint file, the state
		 * will be UNSOLVED and yet we are having to reclaim because
		 * the case was in the asru cache. If this happens, revert the
		 * case back to the UNSOLVED state and let the DE solve it again
		 */
		if (state == FMD_CASE_UNSOLVED) {
			fmd_asru_hash_delete_case(fmd.d_asrus,
			    (fmd_case_t *)cip);
			fmd_case_destroy_suspects(cip);
			fmd_case_code_hash_delete(fmd.d_cases, cip);
			fmd_free(cip->ci_code, cip->ci_codelen);
			cip->ci_code = NULL;
			cip->ci_codelen = 0;
			cip->ci_tv_valid = 0;
		}

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
	boolean_t injected;

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

	if (nvlist_lookup_boolean_value(((fmd_event_impl_t *)ep)->ev_nvl,
	    "__injected", &injected) == 0 && injected)
		fmd_case_set_injected(cp);

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
	if (cip->ci_xprt == NULL)
		fmd_module_setcdirty(cip->ci_mod);
}

void
fmd_case_recreate_suspect(fmd_case_t *cp, nvlist_t *nvl)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;
	fmd_case_susp_t *cis = fmd_alloc(sizeof (fmd_case_susp_t), FMD_SLEEP);
	boolean_t b;

	(void) pthread_mutex_lock(&cip->ci_lock);

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
	int resolved = 0;
	int any_unusable_and_present = 0;

	ASSERT(state <= FMD_CASE_RESOLVED);
	(void) pthread_mutex_lock(&cip->ci_lock);

	if (!(cip->ci_flags & FMD_CF_SOLVED) && !(flags & FMD_CF_SOLVED))
		flags &= ~(FMD_CF_ISOLATED | FMD_CF_REPAIRED | FMD_CF_RESOLVED);

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
		 * module is no longer loaded: continue on to CASE_CLOSED or
		 * CASE_REPAIRED as appropriate.
		 */
		if (fmd_case_orphaned(cp)) {
			if (cip->ci_flags & FMD_CF_REPAIRED) {
				state = cip->ci_state = FMD_CASE_REPAIRED;
				TRACE((FMD_DBG_CASE, "case %s %s->%s",
				    cip->ci_uuid,
				    _fmd_case_snames[FMD_CASE_CLOSE_WAIT],
				    _fmd_case_snames[FMD_CASE_REPAIRED]));
				goto do_repair;
			} else {
				state = cip->ci_state = FMD_CASE_CLOSED;
				TRACE((FMD_DBG_CASE, "case %s %s->%s",
				    cip->ci_uuid,
				    _fmd_case_snames[FMD_CASE_CLOSE_WAIT],
				    _fmd_case_snames[FMD_CASE_CLOSED]));
			}
		}
		break;

	case FMD_CASE_REPAIRED:
do_repair:
		ASSERT(cip->ci_xprt != NULL || fmd_case_orphaned(cp));

		/*
		 * If we've been requested to transition straight on to the
		 * RESOLVED state (which can happen with fault proxying where a
		 * list.resolved or a uuresolved is received from the other
		 * side), or if all suspects are already either usable or not
		 * present then transition straight to RESOLVED state,
		 * publishing both the list.repaired and list.resolved. For a
		 * proxy, if we discover here that all suspects are already
		 * either usable or not present, notify the diag side instead
		 * using fmd_xprt_uuresolved().
		 */
		if (flags & FMD_CF_RESOLVED) {
			if (cip->ci_xprt != NULL)
				fmd_list_delete(&cip->ci_mod->mod_cases, cip);
		} else {
			fmd_asru_hash_apply_by_case(fmd.d_asrus, cp,
			    fmd_case_unusable_and_present,
			    &any_unusable_and_present);
			if (any_unusable_and_present)
				break;
			if (cip->ci_xprt != NULL) {
				fmd_xprt_uuresolved(cip->ci_xprt, cip->ci_uuid);
				break;
			}
		}

		cip->ci_state = FMD_CASE_RESOLVED;
		(void) pthread_mutex_unlock(&cip->ci_lock);
		fmd_case_publish(cp, state);
		TRACE((FMD_DBG_CASE, "case %s %s->%s", cip->ci_uuid,
		    _fmd_case_snames[FMD_CASE_REPAIRED],
		    _fmd_case_snames[FMD_CASE_RESOLVED]));
		state = FMD_CASE_RESOLVED;
		resolved = 1;
		(void) pthread_mutex_lock(&cip->ci_lock);
		break;

	case FMD_CASE_RESOLVED:
		/*
		 * For a proxy, no need to check that all suspects are already
		 * either usable or not present - this request has come from
		 * the diagnosing side which makes the final decision on this.
		 */
		if (cip->ci_xprt != NULL) {
			fmd_list_delete(&cip->ci_mod->mod_cases, cip);
			resolved = 1;
			break;
		}

		ASSERT(fmd_case_orphaned(cp));

		/*
		 * If all suspects are already either usable or not present then
		 * carry on, publish list.resolved and discard the case.
		 */
		fmd_asru_hash_apply_by_case(fmd.d_asrus, cp,
		    fmd_case_unusable_and_present, &any_unusable_and_present);
		if (any_unusable_and_present) {
			(void) pthread_mutex_unlock(&cip->ci_lock);
			return;
		}

		resolved = 1;
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

	if (resolved) {
		if (cip->ci_xprt != NULL) {
			/*
			 * If we transitioned to RESOLVED, adjust the reference
			 * count to reflect our removal from
			 * fmd.d_rmod->mod_cases above.  If the caller has not
			 * placed an additional hold on the case, it will now
			 * be freed.
			 */
			(void) pthread_mutex_lock(&cip->ci_lock);
			fmd_asru_hash_delete_case(fmd.d_asrus, cp);
			(void) pthread_mutex_unlock(&cip->ci_lock);
			fmd_case_rele(cp);
		} else {
			fmd_asru_hash_apply_by_case(fmd.d_asrus, cp,
			    fmd_asru_log_resolved, NULL);
			(void) pthread_mutex_lock(&cip->ci_lock);
			/* mark as "ready to be discarded */
			cip->ci_flags |= FMD_CF_RES_CMPL;
			(void) pthread_mutex_unlock(&cip->ci_lock);
		}
	}
}

/*
 * Discard any case if it is in RESOLVED state (and if check_if_aged argument
 * is set if all suspects have passed the rsrc.aged time).
 */
void
fmd_case_discard_resolved(fmd_case_t *cp, void *arg)
{
	int check_if_aged = *(int *)arg;
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;

	/*
	 * First check if case has completed transition to resolved.
	 */
	(void) pthread_mutex_lock(&cip->ci_lock);
	if (!(cip->ci_flags & FMD_CF_RES_CMPL)) {
		(void) pthread_mutex_unlock(&cip->ci_lock);
		return;
	}

	/*
	 * Now if check_is_aged is set, see if all suspects have aged.
	 */
	if (check_if_aged) {
		int aged = 1;

		fmd_asru_hash_apply_by_case(fmd.d_asrus, cp,
		    fmd_asru_check_if_aged, &aged);
		if (!aged) {
			(void) pthread_mutex_unlock(&cip->ci_lock);
			return;
		}
	}

	/*
	 * Finally discard the case, clearing FMD_CF_RES_CMPL so we don't
	 * do it twice.
	 */
	fmd_module_lock(cip->ci_mod);
	fmd_list_delete(&cip->ci_mod->mod_cases, cip);
	fmd_module_unlock(cip->ci_mod);
	fmd_asru_hash_delete_case(fmd.d_asrus, cp);
	cip->ci_flags &= ~FMD_CF_RES_CMPL;
	(void) pthread_mutex_unlock(&cip->ci_lock);
	fmd_case_rele(cp);
}

/*
 * Transition the specified case to *at least* the specified state by first
 * re-validating the suspect list using the resource cache.  This function is
 * employed by the checkpoint code when restoring a saved, solved case to see
 * if the state of the case has effectively changed while fmd was not running
 * or the module was not loaded.
 */
void
fmd_case_transition_update(fmd_case_t *cp, uint_t state, uint_t flags)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;

	int usable = 0;		/* are any suspects usable? */

	ASSERT(state >= FMD_CASE_SOLVED);
	(void) pthread_mutex_lock(&cip->ci_lock);

	fmd_asru_hash_apply_by_case(fmd.d_asrus, cp, fmd_case_usable, &usable);

	(void) pthread_mutex_unlock(&cip->ci_lock);

	if (!usable) {
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
 * On proxy side, send back repair/acquit/etc request to diagnosing side
 */
void
fmd_case_xprt_updated(fmd_case_t *cp)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;
	nvlist_t **nva;
	uint8_t *ba;
	int msg = B_TRUE;
	int count = 0;
	fmd_case_lst_t fcl;

	ASSERT(cip->ci_xprt != NULL);
	(void) pthread_mutex_lock(&cip->ci_lock);
	ba = alloca(sizeof (uint8_t) * cip->ci_nsuspects);
	nva = alloca(sizeof (nvlist_t *) * cip->ci_nsuspects);
	fcl.fcl_countp = &count;
	fcl.fcl_maxcount = cip->ci_nsuspects;
	fcl.fcl_msgp = &msg;
	fcl.fcl_ba = ba;
	fcl.fcl_nva = nva;
	fmd_asru_hash_apply_by_case(fmd.d_asrus, cp, fmd_case_set_lst, &fcl);
	(void) pthread_mutex_unlock(&cip->ci_lock);
	fmd_xprt_updated(cip->ci_xprt, cip->ci_uuid, ba, cip->ci_proxy_asru,
	    count);
}

/*
 * fmd_case_update_status() can be called on either the proxy side when a
 * list.suspect is received, or on the diagnosing side when an update request
 * is received from the proxy. It updates the status in the resource cache.
 */
void
fmd_case_update_status(fmd_case_t *cp, uint8_t *statusp, uint8_t *proxy_asrup,
    uint8_t *diag_asrup)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;
	int count = 0;
	fmd_asru_update_status_t faus;

	/*
	 * update status of resource cache entries
	 */
	faus.faus_countp = &count;
	faus.faus_maxcount = cip->ci_nsuspects;
	faus.faus_ba = statusp;
	faus.faus_proxy_asru = proxy_asrup;
	faus.faus_diag_asru = diag_asrup;
	faus.faus_is_proxy = (cip->ci_xprt != NULL);
	(void) pthread_mutex_lock(&cip->ci_lock);
	fmd_asru_hash_apply_by_case(fmd.d_asrus, cp, fmd_asru_update_status,
	    &faus);
	(void) pthread_mutex_unlock(&cip->ci_lock);
}

/*
 * Called on either the proxy side or the diag side when a repair has taken
 * place on the other side but this side may know the asru "contains"
 * relationships.
 */
void
fmd_case_update_containees(fmd_case_t *cp)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;

	(void) pthread_mutex_lock(&cip->ci_lock);
	fmd_asru_hash_apply_by_case(fmd.d_asrus, cp,
	    fmd_asru_update_containees, NULL);
	(void) pthread_mutex_unlock(&cip->ci_lock);
}

/*
 * fmd_case_close_status() is called on diagnosing side when proxy side
 * has had a uuclose. It updates the status in the resource cache.
 */
void
fmd_case_close_status(fmd_case_t *cp)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;
	int count = 0;
	fmd_asru_close_status_t facs;

	/*
	 * update status of resource cache entries
	 */
	facs.facs_countp = &count;
	facs.facs_maxcount = cip->ci_nsuspects;
	(void) pthread_mutex_lock(&cip->ci_lock);
	fmd_asru_hash_apply_by_case(fmd.d_asrus, cp, fmd_asru_close_status,
	    &facs);
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

	if (cip->ci_state < FMD_CASE_SOLVED) {
		(void) pthread_mutex_unlock(&cip->ci_lock);
		return; /* update is not appropriate */
	}

	if (cip->ci_flags & FMD_CF_REPAIRED) {
		(void) pthread_mutex_unlock(&cip->ci_lock);
		return; /* already repaired */
	}

	TRACE((FMD_DBG_CASE, "case update %s", cip->ci_uuid));
	fmd_asru_hash_apply_by_case(fmd.d_asrus, cp, fmd_case_faulty, &faulty);
	(void) pthread_mutex_unlock(&cip->ci_lock);

	if (faulty) {
		nvlist_t *nvl;
		fmd_event_t *e;
		char *class;

		TRACE((FMD_DBG_CASE, "sending list.updated %s", cip->ci_uuid));
		nvl = fmd_case_mkevent(cp, FM_LIST_UPDATED_CLASS);
		(void) nvlist_lookup_string(nvl, FM_CLASS, &class);
		e = fmd_event_create(FMD_EVT_PROTOCOL, FMD_HRT_NOW, nvl, class);
		(void) pthread_rwlock_rdlock(&fmd.d_log_lock);
		fmd_log_append(fmd.d_fltlog, e, cp);
		(void) pthread_rwlock_unlock(&fmd.d_log_lock);
		fmd_dispq_dispatch(fmd.d_disp, e, class);
		return; /* one or more suspects are still marked faulty */
	}

	if (cstate == FMD_CASE_CLOSED)
		fmd_case_transition(cp, FMD_CASE_REPAIRED, FMD_CF_REPAIRED);
	else
		fmd_case_transition(cp, FMD_CASE_CLOSE_WAIT, FMD_CF_REPAIRED);
}

/*
 * Delete a closed case from the module's case list once the fmdo_close() entry
 * point has run to completion.  If the case is owned by a transport module,
 * tell the transport to proxy a case close on the other end of the transport.
 * Transition to the appropriate next state based on ci_flags.  This
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

	TRACE((FMD_DBG_CASE, "case delete %s", cip->ci_uuid));
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
	 * If the case has been solved, then retain it
	 * on the root module's case list at least until we're transitioned.
	 * Otherwise free the case with our final fmd_case_rele() below.
	 */
	if (cip->ci_flags & FMD_CF_SOLVED) {
		fmd_module_lock(cip->ci_mod);
		fmd_list_append(&cip->ci_mod->mod_cases, cip);
		fmd_module_unlock(cip->ci_mod);
		fmd_case_hold(cp);
	}

	/*
	 * Transition onwards to REPAIRED or CLOSED as originally requested.
	 * Note that for proxy case if we're transitioning to CLOSED it means
	 * the case was isolated locally, so call fmd_xprt_uuclose() to notify
	 * the diagnosing side. No need to notify the diagnosing side if we are
	 * transitioning to REPAIRED as we only do this when requested to do
	 * so by the diagnosing side anyway.
	 */
	if (cip->ci_flags & FMD_CF_REPAIRED)
		fmd_case_transition(cp, FMD_CASE_REPAIRED, 0);
	else if (cip->ci_flags & FMD_CF_ISOLATED) {
		fmd_case_transition(cp, FMD_CASE_CLOSED, 0);
		if (cip->ci_xprt != NULL)
			fmd_xprt_uuclose(cip->ci_xprt, cip->ci_uuid);
	}

	fmd_case_rele(cp);
}

void
fmd_case_discard(fmd_case_t *cp, boolean_t delete_from_asru_cache)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;

	(void) pthread_mutex_lock(&cip->ci_mod->mod_stats_lock);
	cip->ci_mod->mod_stats->ms_caseopen.fmds_value.ui64--;
	(void) pthread_mutex_unlock(&cip->ci_mod->mod_stats_lock);

	ASSERT(fmd_module_locked(cip->ci_mod));
	fmd_list_delete(&cip->ci_mod->mod_cases, cip);
	if (delete_from_asru_cache) {
		(void) pthread_mutex_lock(&cip->ci_lock);
		fmd_asru_hash_delete_case(fmd.d_asrus, cp);
		(void) pthread_mutex_unlock(&cip->ci_lock);
	}
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
	fmd_asru_rep_arg_t fara;

	(void) pthread_mutex_lock(&cip->ci_lock);
	cstate = cip->ci_state;

	if (cstate < FMD_CASE_SOLVED) {
		(void) pthread_mutex_unlock(&cip->ci_lock);
		return (fmd_set_errno(EFMD_CASE_STATE));
	}

	if (cip->ci_flags & FMD_CF_REPAIRED) {
		(void) pthread_mutex_unlock(&cip->ci_lock);
		return (0); /* already repaired */
	}

	TRACE((FMD_DBG_CASE, "case repair %s", cip->ci_uuid));
	fara.fara_reason = FMD_ASRU_REPAIRED;
	fara.fara_bywhat = FARA_BY_CASE;
	fara.fara_rval = NULL;
	fmd_asru_hash_apply_by_case(fmd.d_asrus, cp, fmd_asru_repaired, &fara);
	(void) pthread_mutex_unlock(&cip->ci_lock);

	/*
	 * if this is a proxied case, send the repair across the transport.
	 * The remote side will then do the repair and send a list.repaired back
	 * again such that we can finally repair the case on this side.
	 */
	if (cip->ci_xprt != NULL) {
		fmd_case_xprt_updated(cp);
		return (0);
	}

	if (cstate == FMD_CASE_CLOSED)
		fmd_case_transition(cp, FMD_CASE_REPAIRED, FMD_CF_REPAIRED);
	else
		fmd_case_transition(cp, FMD_CASE_CLOSE_WAIT, FMD_CF_REPAIRED);

	return (0);
}

int
fmd_case_acquit(fmd_case_t *cp)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;
	uint_t cstate;
	fmd_asru_rep_arg_t fara;

	(void) pthread_mutex_lock(&cip->ci_lock);
	cstate = cip->ci_state;

	if (cstate < FMD_CASE_SOLVED) {
		(void) pthread_mutex_unlock(&cip->ci_lock);
		return (fmd_set_errno(EFMD_CASE_STATE));
	}

	if (cip->ci_flags & FMD_CF_REPAIRED) {
		(void) pthread_mutex_unlock(&cip->ci_lock);
		return (0); /* already repaired */
	}

	TRACE((FMD_DBG_CASE, "case acquit %s", cip->ci_uuid));
	fara.fara_reason = FMD_ASRU_ACQUITTED;
	fara.fara_bywhat = FARA_BY_CASE;
	fara.fara_rval = NULL;
	fmd_asru_hash_apply_by_case(fmd.d_asrus, cp, fmd_asru_repaired, &fara);
	(void) pthread_mutex_unlock(&cip->ci_lock);

	/*
	 * if this is a proxied case, send the repair across the transport.
	 * The remote side will then do the repair and send a list.repaired back
	 * again such that we can finally repair the case on this side.
	 */
	if (cip->ci_xprt != NULL) {
		fmd_case_xprt_updated(cp);
		return (0);
	}

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

void
fmd_case_set_injected(fmd_case_t *cp)
{
	((fmd_case_impl_t *)cp)->ci_injected = 1;
}

void
fmd_case_set_de_fmri(fmd_case_t *cp, nvlist_t *nvl)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;

	nvlist_free(cip->ci_diag_de);
	cip->ci_diag_de = nvl;
}

void
fmd_case_setcode(fmd_case_t *cp, char *code)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;

	cip->ci_code = fmd_strdup(code, FMD_SLEEP);
	cip->ci_codelen = cip->ci_code ? strlen(cip->ci_code) + 1 : 0;
}

/*ARGSUSED*/
static void
fmd_case_repair_replay_case(fmd_case_t *cp, void *arg)
{
	int not_faulty = 0;
	int faulty = 0;
	nvlist_t *nvl;
	fmd_event_t *e;
	char *class;
	int any_unusable_and_present = 0;
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;

	if (cip->ci_state < FMD_CASE_SOLVED || cip->ci_xprt != NULL)
		return;

	if (cip->ci_state == FMD_CASE_RESOLVED) {
		cip->ci_flags |= FMD_CF_RES_CMPL;
		return;
	}

	fmd_asru_hash_apply_by_case(fmd.d_asrus, cp, fmd_case_faulty, &faulty);
	fmd_asru_hash_apply_by_case(fmd.d_asrus, cp, fmd_case_not_faulty,
	    &not_faulty);

	if (cip->ci_state >= FMD_CASE_REPAIRED && !faulty) {
		/*
		 * If none of the suspects is faulty, replay the list.repaired.
		 * If all suspects are already either usable or not present then
		 * also transition straight to RESOLVED state.
		 */
		fmd_asru_hash_apply_by_case(fmd.d_asrus, cp,
		    fmd_case_unusable_and_present, &any_unusable_and_present);
		if (!any_unusable_and_present) {
			cip->ci_state = FMD_CASE_RESOLVED;

			TRACE((FMD_DBG_CASE, "replay sending list.repaired %s",
			    cip->ci_uuid));
			nvl = fmd_case_mkevent(cp, FM_LIST_REPAIRED_CLASS);
			(void) nvlist_lookup_string(nvl, FM_CLASS, &class);
			e = fmd_event_create(FMD_EVT_PROTOCOL, FMD_HRT_NOW, nvl,
			    class);
			fmd_dispq_dispatch(fmd.d_disp, e, class);

			TRACE((FMD_DBG_CASE, "replay sending list.resolved %s",
			    cip->ci_uuid));
			fmd_case_publish(cp, FMD_CASE_RESOLVED);
			fmd_asru_hash_apply_by_case(fmd.d_asrus, cp,
			    fmd_asru_log_resolved, NULL);
			cip->ci_flags |= FMD_CF_RES_CMPL;
		} else {
			TRACE((FMD_DBG_CASE, "replay sending list.repaired %s",
			    cip->ci_uuid));
			nvl = fmd_case_mkevent(cp, FM_LIST_REPAIRED_CLASS);
			(void) nvlist_lookup_string(nvl, FM_CLASS, &class);
			e = fmd_event_create(FMD_EVT_PROTOCOL, FMD_HRT_NOW, nvl,
			    class);
			fmd_dispq_dispatch(fmd.d_disp, e, class);
		}
	} else if (faulty && not_faulty) {
		/*
		 * if some but not all of the suspects are not faulty, replay
		 * the list.updated.
		 */
		TRACE((FMD_DBG_CASE, "replay sending list.updated %s",
		    cip->ci_uuid));
		nvl = fmd_case_mkevent(cp, FM_LIST_UPDATED_CLASS);
		(void) nvlist_lookup_string(nvl, FM_CLASS, &class);
		e = fmd_event_create(FMD_EVT_PROTOCOL, FMD_HRT_NOW, nvl, class);
		fmd_dispq_dispatch(fmd.d_disp, e, class);
	}
}

void
fmd_case_repair_replay()
{
	fmd_case_hash_apply(fmd.d_cases, fmd_case_repair_replay_case, NULL);
}
