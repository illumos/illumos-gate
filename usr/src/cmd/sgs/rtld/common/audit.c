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
 * Copyright (c) 1996, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2012, Joyent, Inc. All rights reserved.
 *
 * Audit interfaces.  Auditing can be enabled in two ways:
 *
 *  -	Using the LD_AUDIT environment variable
 *
 *  -	From individual objects containing a DT_DEPAUDIT entry
 *		(see ld(1) -P/-p options).
 *
 * The former establishes a global set of audit libraries which can inspect all
 * objects from a given process.  The latter establishes a local set of audit
 * libraries which can inspect the immediate dependencies of the caller.
 *
 * Audit library capabilities are indicated by flags within the link-map list
 * header (for global auditing), see LML_TFLG_AUD_* flags, or by the same flags
 * within the individual link-map (for local auditing).  Although both sets of
 * flags can occur in different data items they are defined as one to simplify
 * audit interface requirements.  The basic test for all audit interfaces is:
 *
 *    if ((lml->lm_tflags | AFLAGS(lmp)) & LML_TFLG_AUD_MASK)
 *
 * Note.  Auditors themselves are identified with the LML_TFLG_NOAUDIT link-map
 * list flag, and no LML_TFLG_AUD_MASK flags.  These flags get propagated from
 * a callers link-map list to any new link-map lists created.  Thus, standard
 * link-maps lists have the LML_TFLG_AUD_MASK flags propagated, and should a
 * new link-map list be created by an auditor, that list gets tagged as
 * LML_TFLG_NOAUDIT.
 *
 * The latter link-map list equivalence test insures that auditors themselves
 * (invoked through DT_DEPAUDIT) are not audited.
 *
 * The history of version changes:
 *
 * LAV_VERSION1 (Solaris 2.6)
 *	Auditing implementation added.
 *
 * LAV_VERSION2 (Solaris 2.6)
 *	LA_SYMB_ALTVALUE support added.
 *
 * LAV_VERSION3 (Solaris 9 update 7)
 *	ld_objfilter() added.
 *
 * LAV_VERSION4 (Solaris 10 update 5)
 *	Correction of activity calls for local auditors, and introduction of
 *	-z globalaudit concept.
 *
 * LAV_VERSION5 (Solaris 11)
 *	Under this version, preinit and activity events are enabled from local
 *	auditors.  The la_preinit and la_activity interfaces require a cookie
 *	that represents the head of the link-map list being audited.  If a
 *	local preinit or activity interface is detected, the local auditors
 *	la_objopen() routine is called with a cookie that represents the object
 *	that heads the link-map list of the object being audited.
 *
 *	A local auditor is loaded through adding a new dependency that requests
 *	auditing, and therefore an la_activity(ADD) event is already in effect.
 *	Regardless, the local auditors la_activity() routine is called with the
 *	cookie that represents the object that heads the link-map list of the
 *	object being audited.
 *
 *	A local auditor can be loaded prior to the preinit event.  In this case,
 *	the local auditors la_preinit() routine is called with the cookie that
 *	represents the object that heads the link-map list of the object being
 *	audited.  After the preinit event, any la_preinit() routine within a
 *	local auditor will not be called.
 *
 *	These events are intended to follow the expected sequence of events
 *	received by global auditors, ie:
 *
 *	  -	la_objopen(main)
 *	  -	la_activity(ADD)
 *	  -	la_objopen(dependency)
 *	  -	la_activity(CONSISTENT)
 *	  -	la_preinit(main)
 */

#include	<stdio.h>
#include	<sys/types.h>
#include	<sys/lwp.h>
#include	<stdio.h>
#include	<stdarg.h>
#include	<dlfcn.h>
#include	<string.h>
#include	<debug.h>
#include	"_rtld.h"
#include	"_audit.h"
#include	"_elf.h"
#include	"msg.h"

uint_t	audit_flags = 0;		/* Copy of specific audit flags to */
					/* simplify boot_elf.s access. */

/*
 * Obtain a head link-map cookie.  Local auditors can provide la_preinit() and
 * la_activity() routines, and these routines require a cookie that represents
 * the object that heads the link-map of the object being audited.  A list of
 * these cookies is maintained on the link-map list.  This list allows multiple
 * local objects to specify the same auditor, and to obtain the same cookie
 * for the link-map that heads the link-map list.
 *
 * The initial cookie is created by _audit_create_head_client() which is called
 * from _audit_add_head().  This cookies address is then passed to the local
 * auditors ld_objopen() and la_activity() routines.  Subsequent preinit and
 * activity events use _audit_get_head_client() to dynamically retrieve the
 * cookies address.
 */
static Audit_client *
_audit_get_head_client(Rt_map *hlmp, Rt_map *almp)
{
	Audit_client	*acp;
	Aliste		idx;
	Lm_list		*hlml = LIST(hlmp);

	for (ALIST_TRAVERSE(hlml->lm_aud_cookies, idx, acp)) {
		if (acp->ac_lmp == almp)
			return (acp);
	}
	return (NULL);
}

static Audit_client *
_audit_create_head_client(Rt_map *hlmp, Rt_map *almp)
{
	Audit_client	ac, *acp;
	Lm_list		*hlml = LIST(hlmp);

	ac.ac_lmp = almp;
	ac.ac_cookie = (uintptr_t)hlmp;
	ac.ac_flags = 0;

	if ((acp = alist_append(&(hlml->lm_aud_cookies), &ac,
	    sizeof (Audit_client), AL_CNT_COOKIES)) == NULL)
		return (NULL);

	return (acp);
}

/*
 * Determine the appropriate client.  Each client structure identifies the
 * link-map of the auditor it is associated with.  From the client structure,
 * the address of the associated cookie, that represents the object being
 * audited, is retrieved so that the address can be passed to any audit call.
 *
 * Note, objects that are being locally audited, can provide la_preinit() and
 * la_activity() routines.  These routines must be passed cookies that represent
 * the object that heads the link-map list of the object being audited.  These
 * cookies are not maintained on this objects Audit_client structure, but are
 * obtained from the associated link-map lists lm_cookies alist.
 */
static Audit_client *
_audit_client(Audit_info *aip, Rt_map *almp)
{
	int	ndx;

	if (aip == NULL)
		return (NULL);

	for (ndx = 0; ndx < aip->ai_cnt; ndx++) {
		if (aip->ai_clients[ndx].ac_lmp == almp)
			return (&(aip->ai_clients[ndx]));
	}
	return (NULL);
}

/*
 * la_filter() caller.  Traverse through all audit libraries and call any
 * la_filter() entry points found.  A zero return from an auditor indicates
 * that the filtee should be ignored.
 */
static int
_audit_objfilter(APlist *list, Rt_map *frlmp, const char *ref, Rt_map *felmp,
    uint_t flags)
{
	Audit_list	*alp;
	Aliste		idx;
	Lm_list		*frlml = LIST(frlmp);

	for (APLIST_TRAVERSE(list, idx, alp)) {
		Audit_client	*fracp, *feacp;
		Rt_map		*almp = alp->al_lmp;
		Lm_list		*alml = LIST(almp);
		int		ret;

		if (alp->al_objfilter == NULL)
			continue;
		if ((fracp = _audit_client(AUDINFO(frlmp), almp)) == NULL)
			continue;
		if ((feacp = _audit_client(AUDINFO(felmp), almp)) == NULL)
			continue;

		DBG_CALL(Dbg_audit_objfilter(frlml, DBG_AUD_CALL,
		    alp->al_libname, NAME(frlmp), NAME(felmp), ref));

		leave(alml, thr_flg_reenter);
		ret = (*alp->al_objfilter)(&(fracp->ac_cookie), ref,
		    &(feacp->ac_cookie), flags);
		(void) enter(thr_flg_reenter);

		if (ret == 0) {
			DBG_CALL(Dbg_audit_objfilter(frlml, DBG_AUD_RET,
			    alp->al_libname, NAME(frlmp), NULL, NULL));
			return (0);
		}
	}
	return (1);
}

int
audit_objfilter(Rt_map *frlmp, const char *ref, Rt_map *felmp, uint_t flags)
{
	uint_t	rtldflags;
	int	respond = 1;

	if (rt_critical())
		return (respond);

	APPLICATION_ENTER(rtldflags);

	if (auditors && (auditors->ad_flags & LML_TFLG_AUD_OBJFILTER))
		respond = _audit_objfilter(auditors->ad_list, frlmp,
		    ref, felmp, flags);
	if (respond && AUDITORS(frlmp) &&
	    (AUDITORS(frlmp)->ad_flags & LML_TFLG_AUD_OBJFILTER))
		respond = _audit_objfilter(AUDITORS(frlmp)->ad_list, frlmp,
		    ref, felmp, flags);

	APPLICATION_RETURN(rtldflags);

	return (respond);
}

/*
 * la_objsearch() caller.  Traverse through all audit libraries and call any
 * la_objsearch() entry points found.
 *
 * Effectively any audit library can change the name we're working with, so we
 * continue to propagate the new name to each audit library.  Any 0 return
 * terminates the search.
 */
static char *
_audit_objsearch(APlist *list, char *oname, Rt_map *clmp, uint_t flags)
{
	Audit_list	*alp;
	Aliste		idx;
	Lm_list		*clml = LIST(clmp);

	for (APLIST_TRAVERSE(list, idx, alp)) {
		Audit_client	*acp;
		Rt_map		*almp = alp->al_lmp;
		Lm_list		*alml = LIST(almp);
		char		*nname = oname;

		if (alp->al_objsearch == NULL)
			continue;
		if ((acp = _audit_client(AUDINFO(clmp), almp)) == NULL)
			continue;

		DBG_CALL(Dbg_audit_objsearch(clml, DBG_AUD_CALL,
		    alp->al_libname, nname, flags, NULL));

		leave(alml, thr_flg_reenter);
		nname = (*alp->al_objsearch)(nname, &(acp->ac_cookie), flags);
		(void) enter(thr_flg_reenter);

		/*
		 * Diagnose any return name that differs from the original name
		 * passed to the auditor.
		 */
		if (nname && (nname[0] == '\0'))
			nname = NULL;
		if ((nname != oname) || strcmp(nname, oname))
			DBG_CALL(Dbg_audit_objsearch(clml, DBG_AUD_RET,
			    alp->al_libname, oname, flags, nname));

		if ((oname = nname) == NULL)
			break;

	}
	return (oname);
}

char *
audit_objsearch(Rt_map *clmp, const char *name, uint_t flags)
{
	char	*nname = (char *)name;
	uint_t	rtldflags;

	if (rt_critical())
		return (nname);

	APPLICATION_ENTER(rtldflags);

	if (auditors && (auditors->ad_flags & LML_TFLG_AUD_OBJSEARCH))
		nname = _audit_objsearch(auditors->ad_list, nname,
		    clmp, flags);
	if (nname && AUDITORS(clmp) &&
	    (AUDITORS(clmp)->ad_flags & LML_TFLG_AUD_OBJSEARCH))
		nname = _audit_objsearch(AUDITORS(clmp)->ad_list, nname,
		    clmp, flags);

	APPLICATION_RETURN(rtldflags);

	DBG_CALL(Dbg_libs_audit(LIST(clmp), name, nname));
	return (nname);
}

/*
 * la_activity() caller.  Traverse through all audit libraries and call any
 * la_activity() entry points found.
 */
static void
_audit_activity(APlist *list, Rt_map *clmp, uint_t flags, Boolean client)
{
	Audit_list	*alp;
	Aliste		idx;
	Lm_list		*clml = LIST(clmp);

	for (APLIST_TRAVERSE(list, idx, alp)) {
		Audit_client	*acp;
		Rt_map		*almp = alp->al_lmp;
		Lm_list		*alml = LIST(almp);
		uintptr_t	*cookie;

		if (alp->al_activity == 0)
			continue;

		/*
		 * Determine what cookie is required.  Any auditing that
		 * originates from the object that heads the link-map list has
		 * its own cookie.  Local auditors must obtain the cookie that
		 * represents the object that heads the link-map list.
		 */
		if (client)
			acp = _audit_client(AUDINFO(clmp), almp);
		else
			acp = _audit_get_head_client(clml->lm_head, almp);

		if (acp == NULL)
			continue;
		cookie = &(acp->ac_cookie);

		/*
		 * Make sure the audit library only sees one addition/deletion
		 * at a time.  This ensures the library doesn't see numerous
		 * events from lazy loading a series of libraries.  Keep track
		 * of this caller having called an auditor, so that the
		 * appropriate "consistent" event can be supplied on leaving
		 * ld.so.1.
		 */
		if ((flags == LA_ACT_ADD) || (flags == LA_ACT_DELETE)) {
			if (alml->lm_flags & LML_FLG_AUDITNOTIFY)
				continue;

			alml->lm_flags |= LML_FLG_AUDITNOTIFY;
			clml->lm_flags |= LML_FLG_ACTAUDIT;
		} else {
			if ((alml->lm_flags & LML_FLG_AUDITNOTIFY) == 0)
				continue;

			alml->lm_flags &= ~LML_FLG_AUDITNOTIFY;
		}

		DBG_CALL(Dbg_audit_activity(clml, alp->al_libname,
		    NAME(clml->lm_head), flags));

		leave(alml, thr_flg_reenter);
		(*alp->al_activity)(cookie, flags);
		(void) enter(thr_flg_reenter);
	}
}

void
audit_activity(Rt_map *clmp, uint_t flags)
{
	Rt_map	*lmp;
	Aliste	idx;
	uint_t	rtldflags;

	if (rt_critical())
		return;

	APPLICATION_ENTER(rtldflags);

	if (auditors && (auditors->ad_flags & LML_TFLG_AUD_ACTIVITY))
		_audit_activity(auditors->ad_list, clmp, flags, TRUE);
	if (AUDITORS(clmp) &&
	    (AUDITORS(clmp)->ad_flags & LML_TFLG_AUD_ACTIVITY))
		_audit_activity(AUDITORS(clmp)->ad_list, clmp, flags, TRUE);

	for (APLIST_TRAVERSE(aud_activity, idx, lmp)) {
		if ((clmp != lmp) && AUDITORS(lmp) &&
		    (AUDITORS(lmp)->ad_flags & LML_TFLG_AUD_ACTIVITY)) {
			_audit_activity(AUDITORS(lmp)->ad_list, lmp, flags,
			    FALSE);
		}
	}

	APPLICATION_RETURN(rtldflags);
}

/*
 * Determine whether an auditor is in use by the head link-map object.
 */
static int
_audit_used_by_head(Rt_map *hlmp, Rt_map *almp)
{
	Audit_list	*alp;
	Aliste		idx;

	for (APLIST_TRAVERSE(AUDITORS(hlmp)->ad_list, idx, alp)) {
		if (alp->al_lmp == almp)
			return (1);
	}
	return (0);
}

/*
 * la_objopen() caller for the head link-map.  Global auditors, or an auditor
 * started from the object that heads a link-map list (typically the dynamic
 * executable), are passed to la_objopen().  However, local auditors can
 * provide activity and preinit events, and for these events, a cookie
 * representing the head link-map list object is expected.  This routine obtains
 * these cookies from the link-map list lm_cookies element.  This element
 * ensures all clients of the same auditor use the same cookie.
 *
 * Although a local auditor will get an la_objopen() call for the object that
 * heads the link-map list of the object being audited, the auditor is not
 * permitted to request binding information for this head object.  The head
 * object has already been in existence, and bindings may have been resolved
 * with it.  This local auditor is coming into existence too late, and thus we
 * don't allow any bindings to be caught at all.
 */
static int
_audit_add_head(Rt_map *clmp, Rt_map *hlmp, int preinit, int activity)
{
	Lm_list		*clml = LIST(clmp);
	Lmid_t		lmid = get_linkmap_id(clml);
	Audit_list	*alp;
	Aliste		idx;
	int		save = 0;

	for (APLIST_TRAVERSE(AUDITORS(clmp)->ad_list, idx, alp)) {
		Audit_client	*acp;
		Rt_map		*almp = alp->al_lmp;
		Lm_list		*alml = LIST(almp);
		uintptr_t	*cookie;
		uint_t		rtldflags;

		/*
		 * Ensure this local auditor isn't already in existence as an
		 * auditor for the head of the link-map list.  If it is, then
		 * this auditor will have already receive preinit and activity
		 * events.
		 */
		if (AUDITORS(hlmp) && _audit_used_by_head(hlmp, almp))
			continue;

		/*
		 * Create a cookie that represents the object that heads the
		 * link-map list.  If the cookie already exists, then this
		 * auditor has already been established for another objects
		 * local auditing.  In this case, do not issue a la_objopen()
		 * or la_activity() event, as these will have already occurred.
		 */
		if ((acp = _audit_get_head_client(clml->lm_head, almp)) != NULL)
			continue;
		if ((acp =
		    _audit_create_head_client(clml->lm_head, almp)) == NULL)
			return (0);

		cookie = &(acp->ac_cookie);
		save++;

		/*
		 * Call the la_objopen() if available.
		 */
		if (alp->al_objopen) {
			uint_t	flags;

			DBG_CALL(Dbg_audit_objopen(clml, DBG_AUD_CALL,
			    alp->al_libname, NAME(hlmp), 0, FALSE));

			APPLICATION_ENTER(rtldflags);
			leave(alml, thr_flg_reenter);
			flags = (*alp->al_objopen)((Link_map *)hlmp, lmid,
			    cookie);
			(void) enter(thr_flg_reenter);
			APPLICATION_RETURN(rtldflags);

			if (flags) {
				DBG_CALL(Dbg_audit_objopen(clml, DBG_AUD_RET,
				    alp->al_libname, NAME(hlmp), flags, TRUE));
			}
		}

		/*
		 * Call the la_activity() if available.
		 */
		if (alp->al_activity) {
			alml->lm_flags |= LML_FLG_AUDITNOTIFY;
			clml->lm_flags |= LML_FLG_ACTAUDIT;

			DBG_CALL(Dbg_audit_activity(clml, alp->al_libname,
			    NAME(clml->lm_head), LA_ACT_ADD));

			APPLICATION_ENTER(rtldflags);
			leave(alml, thr_flg_reenter);
			(*alp->al_activity)(cookie, LA_ACT_ADD);
			(void) enter(thr_flg_reenter);
			APPLICATION_RETURN(rtldflags);
		}
	}

	/*
	 * If new head link-map cookies have been generated, then maintain
	 * any preinit and/or activity requirements.
	 */
	if (save) {
		if (preinit && (aplist_append(&aud_preinit, clmp,
		    AL_CNT_AUDITORS) == NULL))
			return (0);
		if (activity && (aplist_append(&aud_activity, clmp,
		    AL_CNT_AUDITORS) == NULL))
			return (0);
	}
	return (1);
}

/*
 * la_objopen() caller.  Create an audit information structure for the indicated
 * link-map, regardless of an la_objopen() entry point.  This structure is used
 * to supply information to various audit interfaces (see LML_MSK_AUDINFO).
 * Traverse through all audit libraries and call any la_objopen() entry points
 * found.
 */
static int
_audit_objopen(APlist *list, Rt_map *nlmp, Lmid_t lmid, Audit_info *aip,
    int *ndx)
{
	Lm_list		*nlml = LIST(nlmp);
	Audit_list	*alp;
	Aliste		idx;

	for (APLIST_TRAVERSE(list, idx, alp)) {
		uint_t		flags;
		Audit_client	*acp;
		Rt_map		*almp = alp->al_lmp;
		Lm_list		*alml = LIST(almp);

		/*
		 * Associate a cookie with the audit library, and assign the
		 * initial cookie as the present link-map.
		 */
		acp = &aip->ai_clients[(*ndx)++];
		acp->ac_lmp = alp->al_lmp;
		acp->ac_cookie = (uintptr_t)nlmp;

		if (alp->al_objopen == NULL)
			continue;

		DBG_CALL(Dbg_audit_objopen(nlml, DBG_AUD_CALL, alp->al_libname,
		    NAME(nlmp), 0, FALSE));

		leave(alml, thr_flg_reenter);
		flags = (*alp->al_objopen)((Link_map *)nlmp, lmid,
		    &(acp->ac_cookie));
		(void) enter(thr_flg_reenter);

		/*
		 * Diagnose any flags returned by the auditor.
		 */
		if (flags) {
			DBG_CALL(Dbg_audit_objopen(nlml, DBG_AUD_RET,
			    alp->al_libname, NAME(nlmp), flags, FALSE));
		}

		if (flags & LA_FLG_BINDTO)
			acp->ac_flags |= FLG_AC_BINDTO;

		if (flags & LA_FLG_BINDFROM) {
			ulong_t		pltcnt;

			acp->ac_flags |= FLG_AC_BINDFROM;

			/*
			 * We only need dynamic plt's if a pltenter and/or a
			 * pltexit() entry point exist in one of our auditing
			 * libraries.
			 */
			if (aip->ai_dynplts || (JMPREL(nlmp) == 0) ||
			    ((audit_flags & (AF_PLTENTER | AF_PLTEXIT)) == 0))
				continue;

			/*
			 * Create one dynplt for every 'PLT' that exists in the
			 * object.
			 */
			pltcnt = PLTRELSZ(nlmp) / RELENT(nlmp);
			if ((aip->ai_dynplts = calloc(pltcnt,
			    dyn_plt_ent_size)) == NULL)
				return (0);
		}
	}
	return (1);
}

int
audit_objopen(Rt_map *clmp, Rt_map *nlmp)
{
	Lmid_t		lmid = get_linkmap_id(LIST(nlmp));
	int		respond = 1, ndx = 0;
	uint_t		rtldflags;
	uint_t		clients = 0;
	Audit_info	*aip;

	if (rt_critical())
		return (respond);

	/*
	 * Determine the number of auditors that can receive information
	 * regarding this object.  This provides the number of client
	 * structures required for this object.
	 */
	if (auditors)
		clients = auditors->ad_cnt;
	if (AUDITORS(clmp))
		clients += AUDITORS(clmp)->ad_cnt;
	if ((nlmp != clmp) && AUDITORS(nlmp))
		clients += AUDITORS(nlmp)->ad_cnt;

	/*
	 * Allocate an audit information structure.  Each audited object
	 * maintains a AUDINFO() structure.  As this structure can only be
	 * created once all auditors are loaded, a client count can now be
	 * computed.
	 *
	 * The allocation of the audit information structure includes an array
	 * of audit clients, 1 per audit library that has been loaded.
	 *
	 *			 ---------------
	 *			| ai_cnt	|
	 * 	Audit_info	| ai_clients	|-------
	 *			| ai_dynplts	|	|
	 *			|---------------|	|
	 * 	Audit_client    |	1	|<------
	 *			|---------------|
	 *			|	2	|
	 *			    .........
	 */
	if ((AUDINFO(nlmp) = aip = calloc(1, sizeof (Audit_info) +
	    (sizeof (Audit_client) * clients))) == NULL)
		return (0);

	aip->ai_cnt = clients;
	aip->ai_clients = (Audit_client *)((uintptr_t)aip +
	    sizeof (Audit_info));

	APPLICATION_ENTER(rtldflags);

	if (auditors)
		respond = _audit_objopen(auditors->ad_list, nlmp,
		    lmid, aip, &ndx);
	if (respond && AUDITORS(clmp))
		respond = _audit_objopen(AUDITORS(clmp)->ad_list, nlmp,
		    lmid, aip, &ndx);
	if (respond && (nlmp != clmp) && AUDITORS(nlmp))
		respond = _audit_objopen(AUDITORS(nlmp)->ad_list, nlmp,
		    lmid, aip, &ndx);

	APPLICATION_RETURN(rtldflags);

	return (respond);
}

/*
 * la_objclose() caller.  Traverse through all audit libraries and call any
 * la_objclose() entry points found.
 */
void
_audit_objclose(APlist *list, Rt_map *lmp)
{
	Audit_list	*alp;
	Aliste		idx;
	Lm_list		*lml = LIST(lmp);

	for (APLIST_TRAVERSE(list, idx, alp)) {
		Audit_client	*acp;
		Rt_map		*almp = alp->al_lmp;
		Lm_list		*alml = LIST(almp);

		if (alp->al_objclose == NULL)
			continue;
		if ((acp = _audit_client(AUDINFO(lmp), almp)) == NULL)
			continue;

		DBG_CALL(Dbg_audit_objclose(lml, alp->al_libname, NAME(lmp)));

		leave(alml, thr_flg_reenter);
		(*alp->al_objclose)(&(acp->ac_cookie));
		(void) enter(thr_flg_reenter);
	}
}

/*
 * Determine any la_objclose() requirements.  An object that is about to be
 * deleted needs to trigger an la_objclose() event to any associated auditors.
 * In the case of local auditing, a deleted object may have a number of callers,
 * and each of these callers may have their own auditing requirements.  To
 * ensure only one la_objclose() event is sent to each auditor, collect the
 * auditors from any callers and make sure there's no duplication.
 */
inline static void
add_objclose_list(Rt_map *lmp, APlist **alpp)
{
	if (AFLAGS(lmp) & LML_TFLG_AUD_OBJCLOSE) {
		Audit_list	*alp;
		Aliste		idx;

		for (APLIST_TRAVERSE(AUDITORS(lmp)->ad_list, idx, alp)) {
			if (aplist_test(alpp, alp, AL_CNT_AUDITORS) == 0)
				return;
		}
	}
}

void
audit_objclose(Rt_map *lmp, Rt_map *clmp)
{
	APlist		*alp = NULL;
	uint_t		rtldflags;

	if (rt_critical())
		return;

	APPLICATION_ENTER(rtldflags);

	if (auditors && (auditors->ad_flags & LML_TFLG_AUD_OBJCLOSE))
		_audit_objclose(auditors->ad_list, lmp);

	/*
	 * If this link-map list contains local auditors, determine if this
	 * object, or any of this objects CALLERS have instantiated auditors
	 * that need to know of la_objclose() events.
	 */
	if (LIST(lmp)->lm_flags & LML_FLG_LOCAUDIT) {
		Bnd_desc	*bdp;
		Aliste		idx;

		add_objclose_list(lmp, &alp);

		for (APLIST_TRAVERSE(CALLERS(lmp), idx, bdp))
			add_objclose_list(bdp->b_caller, &alp);
	}

	/*
	 * If this close originated from dlclose(), determine whether the caller
	 * requires a la_objclose() event.
	 */
	if (clmp)
		add_objclose_list(clmp, &alp);

	if (alp) {
		_audit_objclose(alp, lmp);
		free((void *)alp);
	}

	APPLICATION_RETURN(rtldflags);
}

/*
 * la_pltenter() caller.  Traverse through all audit libraries and call any
 * la_pltenter() entry points found.  NOTE: this routine is called via the
 * glue code established in elf_plt_trace_write(), the symbol descriptor is
 * created as part of the glue and for 32bit environments the st_name is a
 * pointer to the real symbol name (ie. it's already been adjusted with the
 * objects base offset).  For 64bit environments the st_name remains the
 * original symbol offset and in this case it is used to compute the real name
 * pointer and pass as a separate argument to the auditor.
 */
static void
_audit_pltenter(APlist *list, Rt_map *rlmp, Rt_map *dlmp, Sym *sym,
    uint_t ndx, void *regs, uint_t *flags)
{
	Audit_list	*alp;
	Aliste		idx;
	Lm_list		*rlml = LIST(rlmp);
#if	defined(_ELF64)
	const char	*name = (const char *)(sym->st_name + STRTAB(dlmp));
#else
	const char	*name = (const char *)(sym->st_name);
#endif

	for (APLIST_TRAVERSE(list, idx, alp)) {
		Audit_client	*racp, *dacp;
		Rt_map		*almp = alp->al_lmp;
		Lm_list		*alml = LIST(almp);
		Addr		ovalue = sym->st_value;

		if (alp->al_pltenter == 0)
			continue;
		if ((racp = _audit_client(AUDINFO(rlmp), almp)) == NULL)
			continue;
		if ((dacp = _audit_client(AUDINFO(dlmp), almp)) == NULL)
			continue;
		if (((racp->ac_flags & FLG_AC_BINDFROM) == 0) ||
		    ((dacp->ac_flags & FLG_AC_BINDTO) == 0))
			continue;

		DBG_CALL(Dbg_audit_pltenter(rlml, DBG_AUD_CALL,
		    alp->al_libname, name, ovalue));

		leave(alml, thr_flg_reenter);
		sym->st_value = (Addr)(*alp->al_pltenter)(sym, ndx,
		    &(racp->ac_cookie), &(dacp->ac_cookie), regs,
		/* BEGIN CSTYLED */
#if	defined(_ELF64)
		    flags, name);
#else
		    flags);
#endif
		/* END CSTYLED */
		(void) enter(thr_flg_reenter);

		if (ovalue != sym->st_value) {
			DBG_CALL(Dbg_audit_pltenter(rlml, DBG_AUD_RET,
			    alp->al_libname, name, sym->st_value));
		}
	}
}

Addr
audit_pltenter(Rt_map *rlmp, Rt_map *dlmp, Sym *sym, uint_t ndx,
    void *regs, uint_t *flags)
{
	Sym	nsym = *sym;
	uint_t	rtldflags;

	if (rt_critical())
		return (nsym.st_value);

	/*
	 * We're effectively entering ld.so.1 from user (glue) code.
	 */
	(void) enter(0);
	APPLICATION_ENTER(rtldflags);

	if (auditors && (auditors->ad_flags & LML_TFLG_AUD_PLTENTER))
		_audit_pltenter(auditors->ad_list, rlmp, dlmp, &nsym,
		    ndx, regs, flags);
	if (AUDITORS(rlmp) &&
	    (AUDITORS(rlmp)->ad_flags & LML_TFLG_AUD_PLTENTER))
		_audit_pltenter(AUDITORS(rlmp)->ad_list, rlmp, dlmp, &nsym,
		    ndx, regs, flags);

	APPLICATION_RETURN(rtldflags);
	leave(LIST(rlmp), 0);

	return (nsym.st_value);
}

/*
 * la_pltexit() caller.  Traverse through all audit libraries and call any
 * la_pltexit() entry points found.  See notes above (_audit_pltenter) for
 * discussion on st_name.
 */
static Addr
_audit_pltexit(APlist *list, uintptr_t retval, Rt_map *rlmp, Rt_map *dlmp,
    Sym *sym, uint_t ndx)
{
	Audit_list	*alp;
	Aliste		idx;
#if	defined(_ELF64)
	const char	*name = (const char *)(sym->st_name + STRTAB(dlmp));
#else
	const char	*name = (const char *)(sym->st_name);
#endif
	Lm_list		*rlml = LIST(rlmp);

	for (APLIST_TRAVERSE(list, idx, alp)) {
		Audit_client	*racp, *dacp;
		Rt_map		*almp = alp->al_lmp;
		Lm_list		*alml = LIST(almp);

		if (alp->al_pltexit == 0)
			continue;
		if ((racp = _audit_client(AUDINFO(rlmp), almp)) == NULL)
			continue;
		if ((dacp = _audit_client(AUDINFO(dlmp), almp)) == NULL)
			continue;
		if (((racp->ac_flags & FLG_AC_BINDFROM) == 0) ||
		    ((dacp->ac_flags & FLG_AC_BINDTO) == 0))
			continue;

		DBG_CALL(Dbg_audit_pltexit(rlml, alp->al_libname, name));

		leave(alml, thr_flg_reenter);
		retval = (*alp->al_pltexit)(sym, ndx,
		    &(racp->ac_cookie), &(dacp->ac_cookie),
		/* BEGIN CSTYLED */
#if	defined(_ELF64)
		    retval, name);
#else
		    retval);
#endif
		/* END CSTYLED */
		(void) enter(thr_flg_reenter);
	}
	return (retval);
}

Addr
audit_pltexit(uintptr_t retval, Rt_map *rlmp, Rt_map *dlmp, Sym *sym,
    uint_t ndx)
{
	uintptr_t	_retval = retval;
	uint_t		rtldflags;

	if (rt_critical())
		return (_retval);

	/*
	 * We're effectively entering ld.so.1 from user (glue) code.
	 */
	(void) enter(0);
	APPLICATION_ENTER(rtldflags);

	if (auditors && (auditors->ad_flags & LML_TFLG_AUD_PLTEXIT))
		_retval = _audit_pltexit(auditors->ad_list, _retval,
		    rlmp, dlmp, sym, ndx);
	if (AUDITORS(rlmp) && (AUDITORS(rlmp)->ad_flags & LML_TFLG_AUD_PLTEXIT))
		_retval = _audit_pltexit(AUDITORS(rlmp)->ad_list, _retval,
		    rlmp, dlmp, sym, ndx);

	APPLICATION_RETURN(rtldflags);
	leave(LIST(rlmp), 0);

	return (_retval);
}


/*
 * la_symbind() caller.  Traverse through all audit libraries and call any
 * la_symbind() entry points found.
 */
static Addr
_audit_symbind(APlist *list, Rt_map *rlmp, Rt_map *dlmp, Sym *sym, uint_t ndx,
    uint_t *flags, int *called)
{
	Audit_list	*alp;
	Aliste		idx;
	Lm_list		*rlml = LIST(rlmp);
#if	defined(_ELF64)
	const char	*name = (const char *)(sym->st_name + STRTAB(dlmp));
#else
	const char	*name = (const char *)(sym->st_name);
#endif

	for (APLIST_TRAVERSE(list, idx, alp)) {
		Audit_client	*racp, *dacp;
		Rt_map		*almp = alp->al_lmp;
		Lm_list		*alml = LIST(almp);
		Addr		ovalue = sym->st_value;
		uint_t		lflags, oflags = *flags;

		if (alp->al_symbind == 0)
			continue;

		if ((racp = _audit_client(AUDINFO(rlmp), almp)) != NULL &&
		    (racp->ac_flags & FLG_AC_BINDFROM) == 0)
			continue;

		if ((dacp = _audit_client(AUDINFO(dlmp), almp)) == NULL)
			continue;

		if ((dacp->ac_flags & FLG_AC_BINDTO) == 0)
			continue;

		/*
		 * The la_symbind interface is only called when the destination
		 * object has been identified as BINDTO and either the
		 * destination object is being locally audited or the calling
		 * object has been identified as BINDFROM.  Use a local version
		 * of the flags, so that any user update can be collected.
		 */
		(*called)++;
		lflags = (oflags & ~(LA_SYMB_NOPLTENTER | LA_SYMB_NOPLTEXIT));

		DBG_CALL(Dbg_audit_symbind(rlml, DBG_AUD_CALL,
		    alp->al_libname, name, ovalue, oflags));

		leave(alml, thr_flg_reenter);
		sym->st_value = (*alp->al_symbind)(sym, ndx, racp == NULL ?
		    NULL : &(racp->ac_cookie), &(dacp->ac_cookie),
		/* BEGIN CSTYLED */
#if	defined(_ELF64)
		    &lflags, name);
#else
		    &lflags);
#endif
		/* END CSTYLED */
		(void) enter(thr_flg_reenter);

		/*
		 * If the auditor indicated that they did not want to process
		 * pltenter, or pltexit audits for this symbol, retain this
		 * information.  Also retain whether an alternative symbol value
		 * has been supplied.
		 */
		*flags |= (lflags & (LA_SYMB_NOPLTENTER | LA_SYMB_NOPLTEXIT));
		if ((ovalue != sym->st_value) &&
		    (alp->al_vernum >= LAV_VERSION2))
			*flags |= LA_SYMB_ALTVALUE;

		if ((ovalue != sym->st_value) || (oflags != *flags)) {
			DBG_CALL(Dbg_audit_symbind(rlml, DBG_AUD_RET,
			    alp->al_libname, name, sym->st_value, *flags));
		}
	}
	return (sym->st_value);
}

Addr
audit_symbind(Rt_map *rlmp, Rt_map *dlmp, Sym *sym, uint_t ndx, Addr value,
    uint_t *flags)
{
	Sym	nsym;
	int	called = 0;
	uint_t	rtldflags;

	/*
	 * Construct a new symbol from that supplied but with the real address.
	 * In the 64-bit world the st_name field is only 32-bits which isn't
	 * big enough to hold a character pointer. We pass this pointer as a
	 * separate parameter for 64-bit audit libraries.
	 */
	nsym = *sym;
	nsym.st_value = value;

	if (rt_critical())
		return (nsym.st_value);

#if	!defined(_ELF64)
	nsym.st_name += (Word)STRTAB(dlmp);
#endif
	APPLICATION_ENTER(rtldflags);

	if (auditors && (auditors->ad_flags & LML_TFLG_AUD_SYMBIND))
		nsym.st_value = _audit_symbind(auditors->ad_list,
		    rlmp, dlmp, &nsym, ndx, flags, &called);

	if (AUDITORS(rlmp) && (AUDITORS(rlmp)->ad_flags & LML_TFLG_AUD_SYMBIND))
		nsym.st_value = _audit_symbind(AUDITORS(rlmp)->ad_list,
		    rlmp, dlmp, &nsym, ndx, flags, &called);

	if (dlmp != rlmp && AUDITORS(dlmp) &&
	    (AUDITORS(dlmp)->ad_flags & LML_TFLG_AUD_SYMBIND)) {
		nsym.st_value = _audit_symbind(AUDITORS(dlmp)->ad_list,
		    rlmp, dlmp, &nsym, ndx, flags, &called);
	}

	/*
	 * If no la_symbind() was called for this interface, fabricate that no
	 * la_pltenter, or la_pltexit is required.  This helps reduce the glue
	 * code created for further auditing.
	 */
	if (called == 0)
		*flags |= (LA_SYMB_NOPLTENTER | LA_SYMB_NOPLTEXIT);

	APPLICATION_RETURN(rtldflags);

	return (nsym.st_value);
}

/*
 * la_preinit() caller.  Traverse through all audit libraries and call any
 * la_preinit() entry points found.
 */
static void
_audit_preinit(APlist *list, Rt_map *clmp, Boolean client)
{
	Audit_list	*alp;
	Aliste		idx;
	Lm_list		*clml = LIST(clmp);

	for (APLIST_TRAVERSE(list, idx, alp)) {
		Audit_client	*acp;
		Rt_map		*almp = alp->al_lmp;
		Lm_list		*alml = LIST(almp);
		uintptr_t	*cookie;

		if (alp->al_preinit == 0)
			continue;

		/*
		 * Determine what cookie is required.  Any auditing that
		 * originates from the object that heads the link-map list has
		 * its own cookie.  Local auditors must obtain the cookie that
		 * represents the object that heads the link-map list.
		 */
		if (client)
			acp = _audit_client(AUDINFO(clmp), almp);
		else
			acp = _audit_get_head_client(clml->lm_head, almp);

		if (acp == NULL)
			continue;
		cookie = &(acp->ac_cookie);

		DBG_CALL(Dbg_audit_preinit(clml, alp->al_libname,
		    NAME(clml->lm_head)));

		leave(alml, thr_flg_reenter);
		(*alp->al_preinit)(cookie);
		(void) enter(thr_flg_reenter);
	}
}

void
audit_preinit(Rt_map *mlmp)
{
	Rt_map	*clmp;
	Aliste	idx;
	uint_t	rtldflags;

	if (rt_critical())
		return;

	APPLICATION_ENTER(rtldflags);

	if (auditors && (auditors->ad_flags & LML_TFLG_AUD_PREINIT))
		_audit_preinit(auditors->ad_list, mlmp, TRUE);

	if (AUDITORS(mlmp) && (AUDITORS(mlmp)->ad_flags & LML_TFLG_AUD_PREINIT))
		_audit_preinit(AUDITORS(mlmp)->ad_list, mlmp, TRUE);

	for (APLIST_TRAVERSE(aud_preinit, idx, clmp)) {
		if (AUDITORS(clmp) &&
		    (AUDITORS(clmp)->ad_flags & LML_TFLG_AUD_PREINIT))
			_audit_preinit(AUDITORS(clmp)->ad_list, clmp, FALSE);
	}

	APPLICATION_RETURN(rtldflags);
}

/*
 * Clean up (free) an audit descriptor.  First, gather a list of all handles,
 * and then close each one down.  This is done rather than using the handles
 * directly from the auditors, as the audit list can be torn down as a result
 * of the dlclose.  In other words, what you're pointing at can be removed
 * while you're still pointing at it.
 */
void
audit_desc_cleanup(Rt_map *clmp)
{
	Audit_desc	*adp = AUDITORS(clmp);
	Audit_list	*alp;
	Aliste		idx;
	APlist		*ghalp = NULL;

	if (adp == NULL)
		return;
	if (adp->ad_name)
		free(adp->ad_name);

	for (APLIST_TRAVERSE(adp->ad_list, idx, alp))
		(void) aplist_append(&ghalp, alp->al_ghp, AL_CNT_GROUPS);

	free(adp->ad_list);
	adp->ad_list = NULL;

	free(adp);

	/*
	 * Indicate that the caller is no longer being audited.
	 */
	AUDITORS(clmp) = NULL;
	AFLAGS(clmp) &= ~LML_TFLG_AUD_MASK;

	if (ghalp) {
		Grp_hdl		*ghp;
		Aliste		idx;

		for (APLIST_TRAVERSE(ghalp, idx, ghp)) {
			(void) dlclose_intn(ghp, clmp);
		}
		free(ghalp);
	}
}

/*
 * Objects that establish local auditors may have been added to preinit or
 * activity lists.  Remove the object from this list if it is present.
 */
static void
remove_auditor(APlist *alp, Rt_map *clmp)
{
	Rt_map	*lmp;
	Aliste	idx;

	for (APLIST_TRAVERSE(alp, idx, lmp)) {
		if (lmp == clmp) {
			aplist_delete(alp, &idx);
			return;
		}
	}
}

/*
 * Clean up (free) an audit information structure.
 */
void
audit_info_cleanup(Rt_map *clmp)
{
	Audit_info	*aip = AUDINFO(clmp);

	if (aip == NULL)
		return;

	if (aip->ai_dynplts)
		free(aip->ai_dynplts);

	if (aud_preinit)
		remove_auditor(aud_preinit, clmp);
	if (aud_activity)
		remove_auditor(aud_activity, clmp);

	free(aip);
}

/*
 * Create a data structure of symbol lookup names and associated flags to help
 * simplify audit_symget() use.
 */
typedef struct {
	Msg	sname;
	uint_t	alflag;
	uint_t	auflag;
} Aud_info;

static const Aud_info aud_info[] = {
	{ MSG_SYM_LAVERSION, 0, 0 },	/* MSG_ORIG(MSG_SYM_LAVERSION) */
	{ MSG_SYM_LAPREINIT,		/* MSG_ORIG(MSG_SYM_LAPREINIT) */
	    LML_TFLG_AUD_PREINIT, 0 },
	{ MSG_SYM_LAOBJSEARCH,		/* MSG_ORIG(MSG_SYM_LAOBJSEARCH) */
	    LML_TFLG_AUD_OBJSEARCH, 0 },
	{ MSG_SYM_LAOBJOPEN,		/* MSG_ORIG(MSG_SYM_LAOBJOPEN) */
	    LML_TFLG_AUD_OBJOPEN, 0 },
	{ MSG_SYM_LAOBJFILTER,		/* MSG_ORIG(MSG_SYM_LAOBJFILTER */
	    LML_TFLG_AUD_OBJFILTER, 0 },
	{ MSG_SYM_LAOBJCLOSE,		/* MSG_ORIG(MSG_SYM_LAOBJCLOSE) */
	    LML_TFLG_AUD_OBJCLOSE, 0 },
	{ MSG_SYM_LAACTIVITY,		/* MSG_ORIG(MSG_SYM_LAACTIVITY) */
	    LML_TFLG_AUD_ACTIVITY, 0 },

#if	defined(_ELF64)
	{ MSG_SYM_LASYMBIND_64,		/* MSG_ORIG(MSG_SYM_LASYMBIND_64) */
#else
	{ MSG_SYM_LASYMBIND,		/* MSG_ORIG(MSG_SYM_LASYMBIND) */
#endif
	    LML_TFLG_AUD_SYMBIND, 0 },

#if	defined(__sparcv9)
	{ MSG_SYM_LAV9PLTENTER,		/* MSG_ORIG(MSG_SYM_LAV9PLTENTER) */
#elif   defined(__sparc)
	{ MSG_SYM_LAV8PLTENTER,		/* MSG_ORIG(MSG_SYM_LAV8PLTENTER) */
#elif	defined(__amd64)
	{ MSG_SYM_LAAMD64PLTENTER, /* MSG_ORIG(MSG_SYM_LAAMD64PLTENTER) */
#elif	defined(__i386)
	{ MSG_SYM_LAX86PLTENTER,	/* MSG_ORIG(MSG_SYM_LAX86PLTENTER) */
#else
#error platform not defined!
#endif
	    LML_TFLG_AUD_PLTENTER, AF_PLTENTER },

#if	defined(_ELF64)
	{ MSG_SYM_LAPLTEXIT_64,		/* MSG_ORIG(MSG_SYM_LAPLTEXIT_64) */
#else
	{ MSG_SYM_LAPLTEXIT,		/* MSG_ORIG(MSG_SYM_LAPLTEXIT) */
#endif
	    LML_TFLG_AUD_PLTEXIT, AF_PLTEXIT }
};

#define	AI_LAVERSION	0
#define	AI_LAPREINIT	1
#define	AI_LAOBJSEARCH	2
#define	AI_LAOBJOPEN	3
#define	AI_LAOBJFILTER	4
#define	AI_LAOBJCLOSE	5
#define	AI_LAACTIVITY	6
#define	AI_LASYMBIND	7
#define	AI_LAPLTENTER	8
#define	AI_LAPLTEXIT	9

static Addr
audit_symget(Audit_list *alp, int info, int *in_nfavl)
{
	Rt_map		*lmp = alp->al_lmp;
	const char	*sname = MSG_ORIG(aud_info[info].sname);
	uint_t		alflag = aud_info[info].alflag;
	uint_t		auflag = aud_info[info].auflag;
	uint_t		binfo;
	Slookup		sl;
	Sresult		sr;

	/*
	 * Initialize the symbol lookup, and symbol result, data structures.
	 */
	SLOOKUP_INIT(sl, sname, lml_rtld.lm_head, lmp, ld_entry_cnt,
	    0, 0, 0, 0, (LKUP_FIRST | LKUP_DLSYM));
	SRESULT_INIT(sr, sname);

	if (LM_LOOKUP_SYM(lmp)(&sl, &sr, &binfo, in_nfavl)) {
		Addr	addr = sr.sr_sym->st_value;

		if (!(FLAGS(lmp) & FLG_RT_FIXED))
			addr += ADDR(lmp);

		if (alflag)
			alp->al_flags |= alflag;
		if (auflag)
			audit_flags |= auflag;

		/*
		 * Note, unlike most other diagnostics, where we wish to
		 * identify the lmid of the caller, here we use the lmid of
		 * the auditor itself to show the association of the auditor
		 * and the interfaces it provides.
		 */
		DBG_CALL(Dbg_audit_interface(LIST(alp->al_lmp),
		    alp->al_libname, sr.sr_name));
		return (addr);
	}
	return (0);
}

/*
 * Centralize cleanup routines.
 */
static int
audit_disable(char *name, Rt_map *clmp, Grp_hdl *ghp, Audit_list *alp)
{
	eprintf(LIST(clmp), ERR_FATAL, MSG_INTL(MSG_AUD_DISABLED), name);
	if (ghp)
		(void) dlclose_intn(ghp, clmp);
	if (alp)
		free(alp);

	return (0);
}

/*
 * Given a list of one or more audit libraries, open each one and establish a
 * a descriptor representing the entry points it provides.
 */
int
audit_setup(Rt_map *clmp, Audit_desc *adp, uint_t orig, int *in_nfavl)
{
	char		*ptr, *next;
	Lm_list		*clml = LIST(clmp);
	Rt_map		*hlmp;
	int		error = 1, activity = 0, preinit = 0;
	uint_t		rtldflags;

	/*
	 * Determine the type of auditing for diagnostics.
	 */
	if (DBG_ENABLED) {
		int	type;

		if (orig & PD_FLG_EXTLOAD)
			type = DBG_AUD_PRELOAD;
		else if (FLAGS1(clmp) & FL1_RT_GLOBAUD)
			type = DBG_AUD_GLOBAL;
		else
			type = DBG_AUD_LOCAL;

		DBG_CALL(Dbg_audit_lib(clmp, adp->ad_name, type));
	}

	/*
	 * Mark that we have at least one auditing link map
	 */
	rtld_flags2 |= RT_FL2_HASAUDIT;

	/*
	 * The audit definitions may be a list (which will already have been
	 * dupped) so split it into individual tokens.
	 */
	for (ptr = strtok_r(adp->ad_name, MSG_ORIG(MSG_STR_DELIMIT), &next);
	    ptr; ptr = strtok_r(NULL,  MSG_ORIG(MSG_STR_DELIMIT), &next)) {
		Grp_hdl		*ghp;
		Rt_map		*lmp;
		Lm_list		*lml;
		Rt_map		**tobj;
		Audit_list	*alp;

		DBG_CALL(Dbg_util_nl(clml, DBG_NL_STD));

		/*
		 * Open the audit library on its own link-map.
		 */
		if ((ghp = dlmopen_intn((Lm_list *)LM_ID_NEWLM, ptr,
		    (RTLD_FIRST | RTLD_GLOBAL | RTLD_WORLD), clmp,
		    FLG_RT_AUDIT, orig)) == NULL) {
			error = audit_disable(ptr, clmp, 0, 0);
			continue;
		}
		lmp = ghp->gh_ownlmp;
		lml = LIST(lmp);

		/*
		 * If this auditor has already been loaded, reuse it.
		 */
		if ((alp = lml->lm_alp) != NULL) {
			if (aplist_append(&(adp->ad_list), alp,
			    AL_CNT_AUDITORS) == NULL)
				return (audit_disable(ptr, clmp, ghp, alp));

			adp->ad_cnt++;
			adp->ad_flags |= alp->al_flags;

			/*
			 * If this existing auditor provides preinit or
			 * activity routines, track their existence.  The
			 * instantiation of a local auditor requires a cookie
			 * be created that represents the object that heads
			 * the link-map list of the object being audited.
			 */
			if (alp->al_preinit)
				preinit++;
			if (alp->al_activity)
				activity++;

			continue;
		}

		/*
		 * Prior to the Unified Process Model (UPM) environment, an
		 * rtld lock had to be held upon leave().  However, even within
		 * a UPM environment, an old auditor, that has a lazy dependency
		 * on libc, is still a possibility.  As libc isn't loaded, we
		 * don't know the process model, and will determine this later.
		 * Refer to external.c:get_lcinterface().
		 */
		if ((rtld_flags2 & RT_FL2_UNIFPROC) == 0)
			lml->lm_flags |= LML_FLG_HOLDLOCK;

		/*
		 * Allocate an audit list descriptor for this object and
		 * search for all known entry points.
		 */
		if ((alp = calloc(1, sizeof (Audit_list))) == NULL)
			return (audit_disable(ptr, clmp, ghp, 0));

		alp->al_libname = NAME(lmp);
		alp->al_lmp = lmp;
		alp->al_ghp = ghp;

		/*
		 * All audit libraries must handshake through la_version().
		 * Determine that the symbol exists, finish initializing the
		 * object, and then call the function.
		 */
		if ((alp->al_version = (uint_t(*)())audit_symget(alp,
		    AI_LAVERSION, in_nfavl)) == 0) {
			eprintf(lml, ERR_FATAL, MSG_INTL(MSG_GEN_NOSYM),
			    MSG_ORIG(MSG_SYM_LAVERSION));
			error = audit_disable(ptr, clmp, ghp, alp);
			continue;
		}

		if ((tobj = tsort(lmp, lml->lm_init, RT_SORT_REV)) ==
		    (Rt_map **)S_ERROR)
			return (audit_disable(ptr, clmp, ghp, alp));

		if (tobj)
			call_init(tobj, DBG_INIT_SORT);

		APPLICATION_ENTER(rtldflags);
		leave(lml, thr_flg_reenter);
		alp->al_vernum = (*alp->al_version)(LAV_CURRENT);
		(void) enter(thr_flg_reenter);
		APPLICATION_RETURN(rtldflags);

		DBG_CALL(Dbg_audit_version(clml, alp->al_libname,
		    LAV_CURRENT, alp->al_vernum));

		if ((alp->al_vernum < LAV_VERSION1) ||
		    (alp->al_vernum > LAV_CURRENT)) {
			eprintf(lml, ERR_FATAL, MSG_INTL(MSG_AUD_BADVERS),
			    LAV_CURRENT, alp->al_vernum);
			error = audit_disable(ptr, clmp, ghp, alp);
			continue;
		}

		if (aplist_append(&(adp->ad_list), alp,
		    AL_CNT_AUDITORS) == NULL)
			return (audit_disable(ptr, clmp, ghp, alp));

		adp->ad_cnt++;

		/*
		 * Collect any remaining entry points.
		 */
		alp->al_objsearch = (char *(*)())audit_symget(alp,
		    AI_LAOBJSEARCH, in_nfavl);
		alp->al_objopen = (uint_t(*)())audit_symget(alp,
		    AI_LAOBJOPEN, in_nfavl);
		alp->al_objfilter = (int(*)())audit_symget(alp,
		    AI_LAOBJFILTER, in_nfavl);
		alp->al_objclose = (uint_t(*)())audit_symget(alp,
		    AI_LAOBJCLOSE, in_nfavl);
		alp->al_symbind = (uintptr_t(*)())audit_symget(alp,
		    AI_LASYMBIND, in_nfavl);
		alp->al_pltenter = (uintptr_t(*)())audit_symget(alp,
		    AI_LAPLTENTER, in_nfavl);
		alp->al_pltexit = (uintptr_t(*)())audit_symget(alp,
		    AI_LAPLTEXIT, in_nfavl);

		if ((alp->al_preinit = (void(*)())audit_symget(alp,
		    AI_LAPREINIT, in_nfavl)) != NULL)
			preinit++;
		if ((alp->al_activity = (void(*)())audit_symget(alp,
		    AI_LAACTIVITY, in_nfavl)) != NULL)
			activity++;

		/*
		 * Collect the individual object flags, and assign this audit
		 * list descriptor to its associated link-map list.
		 */
		adp->ad_flags |= alp->al_flags;
		lml->lm_alp = alp;
	}

	/*
	 * If the caller isn't the head of its own link-map list, then any
	 * preinit or activity entry points need to be tracked separately.
	 * These "events" are not associated with a particular link-map, and
	 * thus a traversal of any existing preinit and activity clients is
	 * required.
	 *
	 * If either of these events are required, establish a cookie for the
	 * object at the head of the link-map list, and make an initial ADD
	 * activity for these local auditors.
	 */
	if ((preinit || activity) && ((hlmp = clml->lm_head) != clmp) &&
	    (_audit_add_head(clmp, hlmp, preinit, activity) == 0))
		return (0);

	/*
	 * Free the original audit string, as this descriptor may be used again
	 * to add additional auditing.
	 */
	free(adp->ad_name);
	adp->ad_name = NULL;

	return (error);
}
