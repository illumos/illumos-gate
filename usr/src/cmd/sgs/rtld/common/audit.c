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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Audit interfaces.  Auditing can be enabled in two ways:
 *
 *	o	Using the LD_AUDIT environment variable
 *
 *	o	From individual objects containing a DT_DEPAUDIT entry
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
 *    if (((lml->lm_tflags | AFLAGS(lmp)) & LML_TFLG_AUD_MASK) &&
 *	(lml == LIST(lmp)))
 *
 * The latter link-map list equivalence test insures that auditors themselves
 * (invoked through DT_DEPAUDIT) are not audited.
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

static Audit_client *
_audit_client(Audit_info *aip, Rt_map *almp)
{
	int	ndx;

	if (aip == 0)
		return (0);

	for (ndx = 0; ndx < aip->ai_cnt; ndx++) {
		if (aip->ai_clients[ndx].ac_lmp == almp)
			return (&(aip->ai_clients[ndx]));
	}
	return (0);
}

/*
 * la_filter() caller.  Traverse through all audit libraries and call any
 * la_filter() entry points found.  A zero return from an auditor indicates
 * that the filtee should be ignored.
 */
static int
_audit_objfilter(List *list, Rt_map *frlmp, const char *ref, Rt_map *felmp,
    uint_t flags)
{
	Audit_list	*alp;
	Listnode	*lnp;

	for (LIST_TRAVERSE(list, lnp, alp)) {
		Audit_client	*fracp, *feacp;

		if (alp->al_objfilter == 0)
			continue;
		if ((fracp = _audit_client(AUDINFO(frlmp), alp->al_lmp)) == 0)
			continue;
		if ((feacp = _audit_client(AUDINFO(felmp), alp->al_lmp)) == 0)
			continue;

		leave(LIST(alp->al_lmp), thr_flg_reenter);
		if ((*alp->al_objfilter)(&(fracp->ac_cookie), ref,
		    &(feacp->ac_cookie), flags) == 0)
			return (0);
		(void) enter(thr_flg_reenter);
	}
	return (1);
}

int
audit_objfilter(Rt_map *frlmp, const char *ref, Rt_map *felmp, uint_t flags)
{
	int	appl = 0, respond = 1;

	if ((rtld_flags & RT_FL_APPLIC) == 0)
		appl = rtld_flags |= RT_FL_APPLIC;

	if (auditors && (auditors->ad_flags & LML_TFLG_AUD_OBJFILTER))
		respond = _audit_objfilter(&(auditors->ad_list), frlmp,
		    ref, felmp, flags);
	if (respond && AUDITORS(frlmp) &&
	    (AUDITORS(frlmp)->ad_flags & LML_TFLG_AUD_OBJFILTER))
		respond = _audit_objfilter(&(AUDITORS(frlmp)->ad_list), frlmp,
		    ref, felmp, flags);

	if (appl)
		rtld_flags &= ~RT_FL_APPLIC;

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
_audit_objsearch(List *list, char *name, Rt_map *clmp, uint_t flags)
{
	Audit_list	*alp;
	Listnode	*lnp;
	char		*nname = (char *)name;

	for (LIST_TRAVERSE(list, lnp, alp)) {
		Audit_client	*acp;

		if (alp->al_objsearch == 0)
			continue;
		if ((acp = _audit_client(AUDINFO(clmp), alp->al_lmp)) == 0)
			continue;

		leave(LIST(alp->al_lmp), thr_flg_reenter);
		nname = (*alp->al_objsearch)(nname, &(acp->ac_cookie), flags);
		(void) enter(thr_flg_reenter);
		if (nname == 0)
			break;
	}
	return (nname);
}

char *
audit_objsearch(Rt_map *clmp, const char *name, uint_t flags)
{
	char	*nname = (char *)name;
	int	appl = 0;

	if ((rtld_flags & RT_FL_APPLIC) == 0)
		appl = rtld_flags |= RT_FL_APPLIC;

	if (auditors && (auditors->ad_flags & LML_TFLG_AUD_OBJSEARCH))
		nname = _audit_objsearch(&(auditors->ad_list), nname,
		    clmp, flags);
	if (nname && AUDITORS(clmp) &&
	    (AUDITORS(clmp)->ad_flags & LML_TFLG_AUD_OBJSEARCH))
		nname = _audit_objsearch(&(AUDITORS(clmp)->ad_list), nname,
		    clmp, flags);

	if (appl)
		rtld_flags &= ~RT_FL_APPLIC;

	DBG_CALL(Dbg_libs_audit(LIST(clmp), name, nname));
	return (nname);
}

/*
 * la_activity() caller.  Traverse through all audit libraries and call any
 * la_activity() entry points found.
 */
static void
_audit_activity(List *list, Rt_map *clmp, uint_t flags)
{
	Audit_list	*alp;
	Listnode	*lnp;
	Lm_list		*clml = LIST(clmp);

	for (LIST_TRAVERSE(list, lnp, alp)) {
		Audit_client	*acp;
		Rt_map		*almp = alp->al_lmp;
		Lm_list		*alml = LIST(almp);

		if (alp->al_activity == 0)
			continue;
		if ((acp = _audit_client(AUDINFO(clmp), alp->al_lmp)) == 0)
			continue;

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

			if (aplist_append(&clml->lm_actaudit, clmp,
			    AL_CNT_ACTAUDIT) == NULL)
				return;

			alml->lm_flags |= LML_FLG_AUDITNOTIFY;

		} else {
			if ((alml->lm_flags & LML_FLG_AUDITNOTIFY) == 0)
				continue;

			alml->lm_flags &= ~LML_FLG_AUDITNOTIFY;
		}

		leave(LIST(alp->al_lmp), thr_flg_reenter);
		(*alp->al_activity)(&(acp->ac_cookie), flags);
		(void) enter(thr_flg_reenter);
	}
}

void
audit_activity(Rt_map *clmp, uint_t flags)
{
	int	appl = 0;

	if ((rtld_flags & RT_FL_APPLIC) == 0)
		appl = rtld_flags |= RT_FL_APPLIC;

	if (auditors && (auditors->ad_flags & LML_TFLG_AUD_ACTIVITY))
		_audit_activity(&(auditors->ad_list), clmp, flags);
	if (AUDITORS(clmp) &&
	    (AUDITORS(clmp)->ad_flags & LML_TFLG_AUD_ACTIVITY))
		_audit_activity(&(AUDITORS(clmp)->ad_list), clmp, flags);

	if (appl)
		rtld_flags &= ~RT_FL_APPLIC;
}

/*
 * la_objopen() caller.  Create an audit information structure for the indicated
 * link-map, regardless of an la_objopen() entry point.  This structure is used
 * to supply information to various audit interfaces (see LML_MSK_AUDINFO).
 * Traverse through all audit library and call any la_objopen() entry points
 * found.
 */
static int
_audit_objopen(List *list, Rt_map *nlmp, Lmid_t lmid, Audit_info *aip,
    int *ndx)
{
	Audit_list	*alp;
	Listnode	*lnp;

	for (LIST_TRAVERSE(list, lnp, alp)) {
		uint_t		flags;
		Audit_client	*acp;

		/*
		 * Associate a cookie with the audit library, and assign the
		 * initial cookie as the present link-map.
		 */
		acp = &aip->ai_clients[(*ndx)++];
		acp->ac_lmp = alp->al_lmp;
		acp->ac_cookie = (uintptr_t)nlmp;

		if (alp->al_objopen == 0)
			continue;

		DBG_CALL(Dbg_audit_object(LIST(alp->al_lmp), alp->al_libname,
		    NAME(nlmp)));

		leave(LIST(alp->al_lmp), thr_flg_reenter);
		flags = (*alp->al_objopen)((Link_map *)nlmp, lmid,
		    &(acp->ac_cookie));
		(void) enter(thr_flg_reenter);

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
	int		appl = 0, respond = 1, ndx = 0;
	uint_t		clients = 0;
	Audit_info	*aip;

	/*
	 * Determine the total number of audit libraries in use.  This provides
	 * the number of client structures required for this object.
	 */
	if (auditors)
		clients = auditors->ad_cnt;
	if (AUDITORS(clmp))
		clients += AUDITORS(clmp)->ad_cnt;
	if ((nlmp != clmp) && AUDITORS(nlmp))
		clients += AUDITORS(nlmp)->ad_cnt;

	/*
	 * The initial allocation of the audit information structure includes
	 * an array of audit clients, 1 per audit library presently available.
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

	if ((rtld_flags & RT_FL_APPLIC) == 0)
		appl = rtld_flags |= RT_FL_APPLIC;

	if (auditors)
		respond = _audit_objopen(&(auditors->ad_list), nlmp,
		    lmid, aip, &ndx);
	if (respond && AUDITORS(clmp))
		respond = _audit_objopen(&(AUDITORS(clmp)->ad_list), nlmp,
		    lmid, aip, &ndx);
	if (respond && (nlmp != clmp) && AUDITORS(nlmp))
		respond = _audit_objopen(&(AUDITORS(nlmp)->ad_list), nlmp,
		    lmid, aip, &ndx);

	if (appl)
		rtld_flags &= ~RT_FL_APPLIC;

	return (respond);
}

/*
 * la_objclose() caller.  Traverse through all audit library and call any
 * la_objclose() entry points found.
 */
void
_audit_objclose(List *list, Rt_map *lmp)
{
	Audit_list	*alp;
	Listnode	*lnp;

	for (LIST_TRAVERSE(list, lnp, alp)) {
		Audit_client	*acp;

		if (alp->al_objclose == 0)
			continue;
		if ((acp = _audit_client(AUDINFO(lmp), alp->al_lmp)) == 0)
			continue;

		leave(LIST(alp->al_lmp), thr_flg_reenter);
		(*alp->al_objclose)(&(acp->ac_cookie));
		(void) enter(thr_flg_reenter);
	}
}

void
audit_objclose(Rt_map *clmp, Rt_map *lmp)
{
	int	appl = 0;

	if ((rtld_flags & RT_FL_APPLIC) == 0)
		appl = rtld_flags |= RT_FL_APPLIC;

	if (auditors && (auditors->ad_flags & LML_TFLG_AUD_OBJCLOSE))
		_audit_objclose(&(auditors->ad_list), lmp);
	if (AUDITORS(clmp) &&
	    (AUDITORS(clmp)->ad_flags & LML_TFLG_AUD_OBJCLOSE))
		_audit_objclose(&(AUDITORS(clmp)->ad_list), lmp);

	if (appl)
		rtld_flags &= ~RT_FL_APPLIC;
}

/*
 * la_pltenter() caller.  Traverse through all audit library and call any
 * la_pltenter() entry points found.  NOTE: this routine is called via the
 * glue code established in elf_plt_trace_write(), the symbol descriptor is
 * created as part of the glue and for 32bit environments the st_name is a
 * pointer to the real symbol name (ie. it's already been adjusted with the
 * objects base offset).  For 64bit environments the st_name remains the
 * original symbol offset and in this case it is used to compute the real name
 * pointer and pass as a separate argument to the auditor.
 */
static void
_audit_pltenter(List *list, Rt_map *rlmp, Rt_map *dlmp, Sym *sym,
    uint_t ndx, void *regs, uint_t *flags)
{
	Audit_list	*alp;
	Listnode	*lnp;
#if	defined(_ELF64)
	const char	*name = (const char *)(sym->st_name + STRTAB(dlmp));
#else
	const char	*name = (const char *)(sym->st_name);
#endif

	for (LIST_TRAVERSE(list, lnp, alp)) {
		Audit_client	*racp, *dacp;
		Addr		prev = sym->st_value;

		if (alp->al_pltenter == 0)
			continue;
		if ((racp = _audit_client(AUDINFO(rlmp), alp->al_lmp)) == 0)
			continue;
		if ((dacp = _audit_client(AUDINFO(dlmp), alp->al_lmp)) == 0)
			continue;
		if (((racp->ac_flags & FLG_AC_BINDFROM) == 0) ||
		    ((dacp->ac_flags & FLG_AC_BINDTO) == 0))
			continue;

		leave(LIST(alp->al_lmp), thr_flg_reenter);
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

		DBG_CALL(Dbg_audit_symval(LIST(alp->al_lmp), alp->al_libname,
		    MSG_ORIG(MSG_AUD_PLTENTER), name, prev, sym->st_name));
	}
}

Addr
audit_pltenter(Rt_map *rlmp, Rt_map *dlmp, Sym *sym, uint_t ndx,
    void *regs, uint_t *flags)
{
	Sym	_sym = *sym;
	int	_appl = 0;

	/*
	 * We're effectively entering ld.so.1 from user (glue) code.
	 */
	(void) enter(0);
	if ((rtld_flags & RT_FL_APPLIC) == 0)
		_appl = rtld_flags |= RT_FL_APPLIC;

	if (auditors && (auditors->ad_flags & LML_TFLG_AUD_PLTENTER))
		_audit_pltenter(&(auditors->ad_list), rlmp, dlmp, &_sym,
		    ndx, regs, flags);
	if (AUDITORS(rlmp) &&
	    (AUDITORS(rlmp)->ad_flags & LML_TFLG_AUD_PLTENTER))
		_audit_pltenter(&(AUDITORS(rlmp)->ad_list), rlmp, dlmp, &_sym,
		    ndx, regs, flags);

	if (_appl)
		rtld_flags &= ~RT_FL_APPLIC;
	leave(LIST(rlmp), 0);

	return (_sym.st_value);
}

/*
 * la_pltexit() caller.  Traverse through all audit library and call any
 * la_pltexit() entry points found.  See notes above (_audit_pltenter) for
 * discussion on st_name.
 */
static Addr
_audit_pltexit(List *list, uintptr_t retval, Rt_map *rlmp, Rt_map *dlmp,
    Sym *sym, uint_t ndx)
{
	Audit_list	*alp;
	Listnode	*lnp;
#if	defined(_ELF64)
	const char	*name = (const char *)(sym->st_name + STRTAB(dlmp));
#endif

	for (LIST_TRAVERSE(list, lnp, alp)) {
		Audit_client	*racp, *dacp;

		if (alp->al_pltexit == 0)
			continue;
		if ((racp = _audit_client(AUDINFO(rlmp), alp->al_lmp)) == 0)
			continue;
		if ((dacp = _audit_client(AUDINFO(dlmp), alp->al_lmp)) == 0)
			continue;
		if (((racp->ac_flags & FLG_AC_BINDFROM) == 0) ||
		    ((dacp->ac_flags & FLG_AC_BINDTO) == 0))
			continue;

		leave(LIST(alp->al_lmp), thr_flg_reenter);
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
	int		_appl = 0;

	/*
	 * We're effectively entering ld.so.1 from user (glue) code.
	 */
	(void) enter(0);
	if ((rtld_flags & RT_FL_APPLIC) == 0)
		_appl = rtld_flags |= RT_FL_APPLIC;

	if (auditors && (auditors->ad_flags & LML_TFLG_AUD_PLTEXIT))
		_retval = _audit_pltexit(&(auditors->ad_list), _retval,
		    rlmp, dlmp, sym, ndx);
	if (AUDITORS(rlmp) && (AUDITORS(rlmp)->ad_flags & LML_TFLG_AUD_PLTEXIT))
		_retval = _audit_pltexit(&(AUDITORS(rlmp)->ad_list), _retval,
		    rlmp, dlmp, sym, ndx);

	if (_appl)
		rtld_flags &= ~RT_FL_APPLIC;
	leave(LIST(rlmp), 0);

	return (_retval);
}


/*
 * la_symbind() caller.  Traverse through all audit library and call any
 * la_symbind() entry points found.
 */
static Addr
_audit_symbind(List *list, Rt_map *rlmp, Rt_map *dlmp, Sym *sym, uint_t ndx,
    uint_t *flags, int *called)
{
	Audit_list	*alp;
	Listnode	*lnp;
#if	defined(_ELF64)
	const char	*name = (const char *)(sym->st_name + STRTAB(dlmp));
#else
	const char	*name = (const char *)(sym->st_name);
#endif

	for (LIST_TRAVERSE(list, lnp, alp)) {
		Audit_client	*racp, *dacp;
		Addr		prev = sym->st_value;
		uint_t		lflags;

		if (alp->al_symbind == 0)
			continue;
		if ((racp = _audit_client(AUDINFO(rlmp), alp->al_lmp)) == 0)
			continue;
		if ((dacp = _audit_client(AUDINFO(dlmp), alp->al_lmp)) == 0)
			continue;
		if (((racp->ac_flags & FLG_AC_BINDFROM) == 0) ||
		    ((dacp->ac_flags & FLG_AC_BINDTO) == 0))
			continue;

		/*
		 * The la_symbind interface is only called when the calling
		 * object has been identified as BINDFROM, and the destination
		 * object has been identified as BINDTO.  Use a local version of
		 * the flags, so that any user update can be collected.
		 */
		called++;
		lflags = (*flags & ~(LA_SYMB_NOPLTENTER | LA_SYMB_NOPLTEXIT));

		leave(LIST(alp->al_lmp), thr_flg_reenter);
		sym->st_value = (*alp->al_symbind)(sym, ndx,
		    &(racp->ac_cookie), &(dacp->ac_cookie),
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
		if ((prev != sym->st_value) && (alp->al_vernum >= LAV_VERSION2))
			*flags |= LA_SYMB_ALTVALUE;

		DBG_CALL(Dbg_audit_symval(LIST(alp->al_lmp), alp->al_libname,
		    MSG_ORIG(MSG_AUD_SYMBIND), name, prev, sym->st_value));
	}
	return (sym->st_value);
}

Addr
audit_symbind(Rt_map *rlmp, Rt_map *dlmp, Sym *sym, uint_t ndx, Addr value,
    uint_t *flags)
{
	Sym	_sym;
	int	_appl = 0, called = 0;

	/*
	 * Construct a new symbol from that supplied but with the real address.
	 * In the 64-bit world the st_name field is only 32-bits which isn't
	 * big enough to hold a character pointer. We pass this pointer as a
	 * separate parameter for 64-bit audit libraries.
	 */
	_sym = *sym;
	_sym.st_value = value;

#if	!defined(_ELF64)
	_sym.st_name += (Word)STRTAB(dlmp);
#endif
	if ((rtld_flags & RT_FL_APPLIC) == 0)
		_appl = rtld_flags |= RT_FL_APPLIC;

	if (auditors && (auditors->ad_flags & LML_TFLG_AUD_SYMBIND))
		_sym.st_value = _audit_symbind(&(auditors->ad_list),
		    rlmp, dlmp, &_sym, ndx, flags, &called);
	if (AUDITORS(rlmp) && (AUDITORS(rlmp)->ad_flags & LML_TFLG_AUD_SYMBIND))
		_sym.st_value = _audit_symbind(&(AUDITORS(rlmp)->ad_list),
		    rlmp, dlmp, &_sym, ndx, flags, &called);

	/*
	 * If no la_symbind() was called for this interface, fabricate that no
	 * la_pltenter, or la_pltexit is required.  This helps reduce the glue
	 * code created for further auditing.
	 */
	if (caller == 0)
		*flags |= (LA_SYMB_NOPLTENTER | LA_SYMB_NOPLTEXIT);

	if (_appl)
		rtld_flags &= ~RT_FL_APPLIC;

	return (_sym.st_value);
}

/*
 * la_preinit() caller.  Traverse through all audit libraries and call any
 * la_preinit() entry points found.
 */
static void
_audit_preinit(List *list, Rt_map *clmp)
{
	Audit_list	*alp;
	Listnode	*lnp;

	for (LIST_TRAVERSE(list, lnp, alp)) {
		Audit_client	*acp;

		if (alp->al_preinit == 0)
			continue;
		if ((acp = _audit_client(AUDINFO(clmp), alp->al_lmp)) == 0)
			continue;

		leave(LIST(alp->al_lmp), thr_flg_reenter);
		(*alp->al_preinit)(&(acp->ac_cookie));
		(void) enter(thr_flg_reenter);
	}
}

void
audit_preinit(Rt_map *clmp)
{
	int	appl = 0;

	if ((rtld_flags & RT_FL_APPLIC) == 0)
		appl = rtld_flags |= RT_FL_APPLIC;

	if (auditors && (auditors->ad_flags & LML_TFLG_AUD_PREINIT))
		_audit_preinit(&(auditors->ad_list), clmp);
	if (AUDITORS(clmp) && (AUDITORS(clmp)->ad_flags & LML_TFLG_AUD_PREINIT))
		_audit_preinit(&(AUDITORS(clmp)->ad_list), clmp);

	if (appl)
		rtld_flags &= ~RT_FL_APPLIC;
}

/*
 * Clean up (free) an audit descriptor.  First, gather a list of all handles,
 * and then close each one down.  This is done rather than using the handles
 * directly from the auditors, as the audit list can be torn down as a result
 * of the dlclose.  In other words, what you're pointing at can be removed
 * while your still pointing at it.
 */
void
audit_desc_cleanup(Rt_map *clmp)
{
	Audit_desc	*adp = AUDITORS(clmp);
	Audit_list	*alp;
	Listnode	*lnp, *olnp;
	APlist		*ghalp = NULL;

	if (adp == 0)
		return;
	if (adp->ad_name)
		free(adp->ad_name);

	olnp = 0;
	for (LIST_TRAVERSE(&(adp->ad_list), lnp, alp)) {
		(void) aplist_append(&ghalp, alp->al_ghp, AL_CNT_GROUPS);

		if (olnp)
			free(olnp);
		olnp = lnp;
	}
	if (olnp)
		free(olnp);

	free(adp);
	AUDITORS(clmp) = 0;

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
 * Clean up (free) an audit information structure.
 */
void
audit_info_cleanup(Rt_map *clmp)
{
	Audit_info	*aip = AUDINFO(clmp);

	if (aip == 0)
		return;

	if (aip->ai_dynplts)
		free(aip->ai_dynplts);
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
	{ MSG_SYM_LAVERSION,	0 },	/* MSG_ORIG(MSG_SYM_LAVERSION) */
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
	Rt_map		*_lmp, *lmp = alp->al_lmp;
	const char	*sname = MSG_ORIG(aud_info[info].sname);
	uint_t		alflag = aud_info[info].alflag;
	uint_t		auflag = aud_info[info].auflag;
	uint_t		binfo;
	Sym		*sym;
	Slookup		sl;

	/*
	 * Initialize the symbol lookup data structure.
	 */
	SLOOKUP_INIT(sl, sname, lml_rtld.lm_head, lmp, ld_entry_cnt,
	    0, 0, 0, 0, LKUP_FIRST);

	if (sym = LM_LOOKUP_SYM(lmp)(&sl, &_lmp, &binfo, in_nfavl)) {
		Addr	addr = sym->st_value;

		if (!(FLAGS(lmp) & FLG_RT_FIXED))
			addr += ADDR(lmp);

		if (alflag)
			alp->al_flags |= alflag;
		if (auflag)
			audit_flags |= auflag;

		DBG_CALL(Dbg_audit_interface(LIST(alp->al_lmp),
		    alp->al_libname, sname));
		return (addr);
	} else
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
	char	*ptr, *next;
	Lm_list	*clml = LIST(clmp);
	int	error = 1;

	DBG_CALL(Dbg_audit_lib(clml, adp->ad_name));

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
		Rt_map		**tobj;
		Audit_list	*alp;

		/*
		 * Open the audit library on its own link-map.
		 */
		if ((ghp = dlmopen_intn((Lm_list *)LM_ID_NEWLM, ptr,
		    (RTLD_FIRST | RTLD_GLOBAL | RTLD_WORLD), clmp,
		    FLG_RT_AUDIT, orig)) == 0) {
			error = audit_disable(ptr, clmp, 0, 0);
			continue;
		}
		lmp = ghp->gh_ownlmp;

		/*
		 * If this auditor has already been loaded, reuse it.
		 */
		if ((alp = LIST(lmp)->lm_alp) != 0) {
			if (list_append(&(adp->ad_list), alp) == 0)
				return (audit_disable(ptr, clmp, ghp, alp));

			adp->ad_cnt++;
			DBG_CALL(Dbg_audit_version(clml, alp->al_libname,
			    alp->al_vernum));
			adp->ad_flags |= alp->al_flags;
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
			LIST(lmp)->lm_flags |= LML_FLG_HOLDLOCK;

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
			eprintf(LIST(lmp), ERR_FATAL, MSG_INTL(MSG_GEN_NOSYM),
			    MSG_ORIG(MSG_SYM_LAVERSION));
			error = audit_disable(ptr, clmp, ghp, alp);
			continue;
		}

		if ((tobj = tsort(lmp, LIST(lmp)->lm_init, RT_SORT_REV)) ==
		    (Rt_map **)S_ERROR)
			return (audit_disable(ptr, clmp, ghp, alp));

		rtld_flags |= RT_FL_APPLIC;
		if (tobj != (Rt_map **)NULL)
			call_init(tobj, DBG_INIT_SORT);

		alp->al_vernum = alp->al_version(LAV_CURRENT);
		rtld_flags &= ~RT_FL_APPLIC;

		if ((alp->al_vernum < LAV_VERSION1) ||
		    (alp->al_vernum > LAV_CURRENT)) {
			eprintf(LIST(lmp), ERR_FATAL, MSG_INTL(MSG_AUD_BADVERS),
			    LAV_CURRENT, alp->al_vernum);
			error = audit_disable(ptr, clmp, ghp, alp);
			continue;
		}

		if (list_append(&(adp->ad_list), alp) == 0)
			return (audit_disable(ptr, clmp, ghp, alp));

		adp->ad_cnt++;
		DBG_CALL(Dbg_audit_version(clml, alp->al_libname,
		    alp->al_vernum));

		/*
		 * Collect any remaining entry points.
		 */
		alp->al_preinit = (void(*)())audit_symget(alp,
		    AI_LAPREINIT, in_nfavl);
		alp->al_objsearch = (char *(*)())audit_symget(alp,
		    AI_LAOBJSEARCH, in_nfavl);
		alp->al_objopen = (uint_t(*)())audit_symget(alp,
		    AI_LAOBJOPEN, in_nfavl);
		alp->al_objfilter = (int(*)())audit_symget(alp,
		    AI_LAOBJFILTER, in_nfavl);
		alp->al_objclose = (uint_t(*)())audit_symget(alp,
		    AI_LAOBJCLOSE, in_nfavl);
		alp->al_activity = (void (*)())audit_symget(alp,
		    AI_LAACTIVITY, in_nfavl);
		alp->al_symbind = (uintptr_t(*)())audit_symget(alp,
		    AI_LASYMBIND, in_nfavl);
		alp->al_pltenter = (uintptr_t(*)())audit_symget(alp,
		    AI_LAPLTENTER, in_nfavl);
		alp->al_pltexit = (uintptr_t(*)())audit_symget(alp,
		    AI_LAPLTEXIT, in_nfavl);

		/*
		 * Collect the individual object flags, and assign this audit
		 * list descriptor to its associated link-map list.
		 */
		adp->ad_flags |= alp->al_flags;
		LIST(lmp)->lm_alp = alp;
	}

	/*
	 * Free the original audit string, as this descriptor may be used again
	 * to add additional auditing.
	 */
	free(adp->ad_name);
	adp->ad_name = 0;

	return (error);
}
