/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2015 Joyent, Inc.  All rights reserved.
 */

/*
 * The following ia a basic overview of how we diff types in containers (the
 * generally interesting part of diff, and what's used by merge). We maintain
 * two mapping tables, a table of forward mappings (src->dest), and a reverse
 * mapping (dest->src). Both are initialized to contain no mapping, and can also
 * be updated to contain a negative mapping.
 *
 * What we do first is iterate over each type in the src container, and compare
 * it with a type in the destination container. This may involve doing recursive
 * comparisons -- which can involve cycles. To deal with this, whenever we
 * encounter something which may be cyclic, we insert a guess. In other words,
 * we assume that it may be true. This is necessary for the classic case of the
 * following structure:
 *
 * struct foo {
 * 	struct foo *foo_next;
 * };
 *
 * If it turns out that we were wrong, we discard our guesses.
 *
 * If we find that a given type in src has no corresponding entry in dst, we
 * then mark its map as CTF_ERR (-1) to indicate that it has *no* match, as
 * opposed to the default value of 0, which indicates an unknown match.
 * Once we've done the first iteration through src, we know at that point in
 * time whether everything in dst is similar or not and can simply walk over it
 * and don't have to do any additional checks.
 */

#include <libctf.h>
#include <ctf_impl.h>
#include <sys/debug.h>

typedef struct ctf_diff_func {
	const char *cdf_name;
	ulong_t cdf_symidx;
	ulong_t cdf_matchidx;
} ctf_diff_func_t;

typedef struct ctf_diff_obj {
	const char *cdo_name;
	ulong_t cdo_symidx;
	ctf_id_t cdo_id;
	ulong_t cdo_matchidx;
} ctf_diff_obj_t;

typedef struct ctf_diff_guess {
	struct ctf_diff_guess *cdg_next;
	ctf_id_t cdg_iid;
	ctf_id_t cdg_oid;
} ctf_diff_guess_t;

/* typedef in libctf.h */
struct ctf_diff {
	uint_t cds_flags;
	boolean_t cds_tvalid;	/* types valid */
	ctf_file_t *cds_ifp;
	ctf_file_t *cds_ofp;
	ctf_id_t *cds_forward;
	ctf_id_t *cds_reverse;
	size_t cds_fsize;
	size_t cds_rsize;
	ctf_diff_type_f cds_func;
	ctf_diff_guess_t *cds_guess;
	void *cds_arg;
	uint_t cds_nifuncs;
	uint_t cds_nofuncs;
	uint_t cds_nextifunc;
	uint_t cds_nextofunc;
	ctf_diff_func_t *cds_ifuncs;
	ctf_diff_func_t *cds_ofuncs;
	boolean_t cds_ffillip;
	boolean_t cds_fvalid;
	uint_t cds_niobj;
	uint_t cds_noobj;
	uint_t cds_nextiobj;
	uint_t cds_nextoobj;
	ctf_diff_obj_t *cds_iobj;
	ctf_diff_obj_t *cds_oobj;
	boolean_t cds_ofillip;
	boolean_t cds_ovalid;
};

#define	TINDEX(tid) (tid - 1)

/*
 * Team Diff
 */
static int ctf_diff_type(ctf_diff_t *, ctf_file_t *, ctf_id_t, ctf_file_t *,
    ctf_id_t);

static int
ctf_diff_name(ctf_file_t *ifp, ctf_id_t iid, ctf_file_t *ofp, ctf_id_t oid)
{
	const char *iname, *oname;
	const ctf_type_t *itp, *otp;

	if ((itp = ctf_lookup_by_id(&ifp, iid)) == NULL)
		return (CTF_ERR);

	if ((otp = ctf_lookup_by_id(&ofp, oid)) == NULL)
		return (ctf_set_errno(ifp, iid));

	iname = ctf_strptr(ifp, itp->ctt_name);
	oname = ctf_strptr(ofp, otp->ctt_name);

	if ((iname == NULL || oname == NULL) && (iname != oname))
		return (B_TRUE);

	/* Two anonymous names are the same */
	if (iname == NULL && oname == NULL)
		return (B_FALSE);

	return (strcmp(iname, oname) == 0 ? B_FALSE: B_TRUE);
}

/*
 * For floats and ints
 */
static int
ctf_diff_number(ctf_file_t *ifp, ctf_id_t iid, ctf_file_t *ofp, ctf_id_t oid)
{
	ctf_encoding_t ien, den;

	if (ctf_type_encoding(ifp, iid, &ien) != 0)
		return (CTF_ERR);

	if (ctf_type_encoding(ofp, oid, &den) != 0)
		return (ctf_set_errno(ifp, iid));

	if (bcmp(&ien, &den, sizeof (ctf_encoding_t)) != 0)
		return (B_TRUE);

	return (B_FALSE);
}

/*
 * Two typedefs are equivalent, if after we resolve a chain of typedefs, they
 * point to equivalent types. This means that if a size_t is defined as follows:
 *
 * size_t -> ulong_t -> unsigned long
 * size_t -> unsigned long
 *
 * That we'll ultimately end up treating them the same.
 */
static int
ctf_diff_typedef(ctf_diff_t *cds, ctf_file_t *ifp, ctf_id_t iid,
    ctf_file_t *ofp, ctf_id_t oid)
{
	ctf_id_t iref = CTF_ERR, oref = CTF_ERR;

	while (ctf_type_kind(ifp, iid) == CTF_K_TYPEDEF) {
		iref = ctf_type_reference(ifp, iid);
		if (iref == CTF_ERR)
			return (CTF_ERR);
		iid = iref;
	}

	while (ctf_type_kind(ofp, oid) == CTF_K_TYPEDEF) {
		oref = ctf_type_reference(ofp, oid);
		if (oref == CTF_ERR)
			return (CTF_ERR);
		oid = oref;
	}

	VERIFY(iref != CTF_ERR && oref != CTF_ERR);
	return (ctf_diff_type(cds, ifp, iref, ofp, oref));
}

/*
 * Two qualifiers are equivalent iff they point to two equivalent types.
 */
static int
ctf_diff_qualifier(ctf_diff_t *cds, ctf_file_t *ifp, ctf_id_t iid,
    ctf_file_t *ofp, ctf_id_t oid)
{
	ctf_id_t iref, oref;

	iref = ctf_type_reference(ifp, iid);
	if (iref == CTF_ERR)
		return (CTF_ERR);

	oref = ctf_type_reference(ofp, oid);
	if (oref == CTF_ERR)
		return (ctf_set_errno(ifp, ctf_errno(ofp)));

	return (ctf_diff_type(cds, ifp, iref, ofp, oref));
}

/*
 * Two arrays are the same iff they have the same type for contents, the same
 * type for the index, and the same number of elements.
 */
static int
ctf_diff_array(ctf_diff_t *cds, ctf_file_t *ifp, ctf_id_t iid, ctf_file_t *ofp,
    ctf_id_t oid)
{
	int ret;
	ctf_arinfo_t iar, oar;

	if (ctf_array_info(ifp, iid, &iar) == CTF_ERR)
		return (CTF_ERR);

	if (ctf_array_info(ofp, oid, &oar) == CTF_ERR)
		return (ctf_set_errno(ifp, ctf_errno(ofp)));

	ret = ctf_diff_type(cds, ifp, iar.ctr_contents, ofp, oar.ctr_contents);
	if (ret != B_FALSE)
		return (ret);

	if (iar.ctr_nelems != oar.ctr_nelems)
		return (B_TRUE);

	/*
	 * If we're ignoring integer types names, then we're trying to do a bit
	 * of a logical diff and we don't really care about the fact that the
	 * index element might not be the same here, what we care about are the
	 * number of elements and that they're the same type.
	 */
	if ((cds->cds_flags & CTF_DIFF_F_IGNORE_INTNAMES) == 0) {
		ret = ctf_diff_type(cds, ifp, iar.ctr_index, ofp,
		    oar.ctr_index);
		if (ret != B_FALSE)
			return (ret);
	}

	return (B_FALSE);
}

/*
 * Two function pointers are the same if the following is all true:
 *
 *   o They have the same return type
 *   o They have the same number of arguments
 *   o The arguments are of the same type
 *   o They have the same flags
 */
static int
ctf_diff_fptr(ctf_diff_t *cds, ctf_file_t *ifp, ctf_id_t iid, ctf_file_t *ofp,
    ctf_id_t oid)
{
	int ret, i;
	ctf_funcinfo_t ifunc, ofunc;
	ctf_id_t *iids, *oids;

	if (ctf_func_info_by_id(ifp, iid, &ifunc) == CTF_ERR)
		return (CTF_ERR);

	if (ctf_func_info_by_id(ofp, oid, &ofunc) == CTF_ERR)
		return (ctf_set_errno(ifp, ctf_errno(ofp)));

	if (ifunc.ctc_argc != ofunc.ctc_argc)
		return (B_TRUE);

	if (ifunc.ctc_flags != ofunc.ctc_flags)
		return (B_TRUE);

	ret = ctf_diff_type(cds, ifp, ifunc.ctc_return, ofp, ofunc.ctc_return);
	if (ret != B_FALSE)
		return (ret);

	iids = ctf_alloc(sizeof (ctf_id_t) * ifunc.ctc_argc);
	if (iids == NULL)
		return (ctf_set_errno(ifp, ENOMEM));

	oids = ctf_alloc(sizeof (ctf_id_t) * ifunc.ctc_argc);
	if (oids == NULL) {
		ctf_free(iids, sizeof (ctf_id_t) * ifunc.ctc_argc);
		return (ctf_set_errno(ifp, ENOMEM));
	}

	if (ctf_func_args_by_id(ifp, iid, ifunc.ctc_argc, iids) == CTF_ERR) {
		ret = CTF_ERR;
		goto out;
	}

	if (ctf_func_args_by_id(ofp, oid, ofunc.ctc_argc, oids) == CTF_ERR) {
		ret = ctf_set_errno(ifp, ctf_errno(ofp));
		goto out;
	}

	ret = B_TRUE;
	for (i = 0; i < ifunc.ctc_argc; i++) {
		ret = ctf_diff_type(cds, ifp, iids[i], ofp, oids[i]);
		if (ret != B_FALSE)
			goto out;
	}
	ret = B_FALSE;

out:
	ctf_free(iids, sizeof (ctf_id_t) * ifunc.ctc_argc);
	ctf_free(oids, sizeof (ctf_id_t) * ofunc.ctc_argc);
	return (ret);
}

/*
 * Two structures are the same if every member is identical to its corresponding
 * type, at the same offset, and has the same name, as well as them having the
 * same overall size.
 */
static int
ctf_diff_struct(ctf_diff_t *cds, ctf_file_t *ifp, ctf_id_t iid, ctf_file_t *ofp,
    ctf_id_t oid)
{
	ctf_file_t *oifp;
	const ctf_type_t *itp, *otp;
	ssize_t isize, iincr, osize, oincr;
	const ctf_member_t *imp, *omp;
	const ctf_lmember_t *ilmp, *olmp;
	int n;
	ctf_diff_guess_t *cdg;

	oifp = ifp;

	if ((itp = ctf_lookup_by_id(&ifp, iid)) == NULL)
		return (CTF_ERR);

	if ((otp = ctf_lookup_by_id(&ofp, oid)) == NULL)
		return (ctf_set_errno(oifp, ctf_errno(ofp)));

	if (ctf_type_size(ifp, iid) != ctf_type_size(ofp, oid))
		return (B_TRUE);

	if (LCTF_INFO_VLEN(ifp, itp->ctt_info) !=
	    LCTF_INFO_VLEN(ofp, otp->ctt_info))
		return (B_TRUE);

	(void) ctf_get_ctt_size(ifp, itp, &isize, &iincr);
	(void) ctf_get_ctt_size(ofp, otp, &osize, &oincr);

	if (ifp->ctf_version == CTF_VERSION_1 || isize < CTF_LSTRUCT_THRESH) {
		imp = (const ctf_member_t *)((uintptr_t)itp + iincr);
		ilmp = NULL;
	} else {
		imp = NULL;
		ilmp = (const ctf_lmember_t *)((uintptr_t)itp + iincr);
	}

	if (ofp->ctf_version == CTF_VERSION_1 || osize < CTF_LSTRUCT_THRESH) {
		omp = (const ctf_member_t *)((uintptr_t)otp + oincr);
		olmp = NULL;
	} else {
		omp = NULL;
		olmp = (const ctf_lmember_t *)((uintptr_t)otp + oincr);
	}

	/*
	 * Insert our assumption that they're equal for the moment.
	 */
	cdg = ctf_alloc(sizeof (ctf_diff_guess_t));
	if (cdg == NULL)
		return (ctf_set_errno(ifp, ENOMEM));
	cdg->cdg_iid = iid;
	cdg->cdg_oid = oid;
	cdg->cdg_next = cds->cds_guess;
	cds->cds_guess = cdg;
	cds->cds_forward[TINDEX(iid)] = oid;
	cds->cds_reverse[TINDEX(oid)] = iid;

	for (n = LCTF_INFO_VLEN(ifp, itp->ctt_info); n != 0; n--) {
		const char *iname, *oname;
		ulong_t ioff, ooff;
		ctf_id_t itype, otype;
		int ret;

		if (imp != NULL) {
			iname = ctf_strptr(ifp, imp->ctm_name);
			ioff = imp->ctm_offset;
			itype = imp->ctm_type;
		} else {
			iname = ctf_strptr(ifp, ilmp->ctlm_name);
			ioff = CTF_LMEM_OFFSET(ilmp);
			itype = ilmp->ctlm_type;
		}

		if (omp != NULL) {
			oname = ctf_strptr(ofp, omp->ctm_name);
			ooff = omp->ctm_offset;
			otype = omp->ctm_type;
		} else {
			oname = ctf_strptr(ofp, olmp->ctlm_name);
			ooff = CTF_LMEM_OFFSET(olmp);
			otype = olmp->ctlm_type;
		}

		if (ioff != ooff) {
			return (B_TRUE);
		}
		if (strcmp(iname, oname) != 0) {
			return (B_TRUE);
		}
		ret = ctf_diff_type(cds, ifp, itype, ofp, otype);
		if (ret != B_FALSE) {
			return (ret);
		}

		/* Advance our pointers */
		if (imp != NULL)
			imp++;
		if (ilmp != NULL)
			ilmp++;
		if (omp != NULL)
			omp++;
		if (olmp != NULL)
			olmp++;
	}

	return (B_FALSE);
}

/*
 * Two unions are the same if they have the same set of members. This is similar
 * to, but slightly different from a struct. The offsets of members don't
 * matter. However, their is no guarantee of ordering so we have to fall back to
 * doing an O(N^2) scan.
 */
typedef struct ctf_diff_union_member {
	ctf_diff_t *cdum_cds;
	ctf_file_t *cdum_fp;
	ctf_file_t *cdum_iterfp;
	const char *cdum_name;
	ctf_id_t cdum_type;
	int cdum_ret;
} ctf_diff_union_member_t;

typedef struct ctf_diff_union_fp {
	ctf_diff_t *cduf_cds;
	ctf_file_t *cduf_curfp;
	ctf_file_t *cduf_altfp;
	ctf_id_t cduf_type;
	int cduf_ret;
} ctf_diff_union_fp_t;

/* ARGSUSED */
static int
ctf_diff_union_check_member(const char *name, ctf_id_t id, ulong_t off,
    void *arg)
{
	int ret;
	ctf_diff_union_member_t *cdump = arg;

	if (strcmp(name, cdump->cdum_name) != 0)
		return (0);

	ret = ctf_diff_type(cdump->cdum_cds, cdump->cdum_fp, cdump->cdum_type,
	    cdump->cdum_iterfp, id);
	if (ret == CTF_ERR) {
		cdump->cdum_ret = CTF_ERR;
		return (1);
	}

	if (ret == B_FALSE) {
		cdump->cdum_ret = B_FALSE;
		/* Return non-zero to stop iteration as we have a match */
		return (1);
	}

	return (0);
}

/* ARGSUSED */
static int
ctf_diff_union_check_fp(const char *name, ctf_id_t id, ulong_t off, void *arg)
{
	int ret;
	ctf_diff_union_member_t cdum;
	ctf_diff_union_fp_t *cdufp = arg;

	cdum.cdum_cds = cdufp->cduf_cds;
	cdum.cdum_fp = cdufp->cduf_curfp;
	cdum.cdum_iterfp = cdufp->cduf_altfp;
	cdum.cdum_name = name;
	cdum.cdum_type = id;
	cdum.cdum_ret = B_TRUE;

	ret = ctf_member_iter(cdum.cdum_iterfp, cdufp->cduf_type,
	    ctf_diff_union_check_member, &cdum);
	if (ret == 0 || cdum.cdum_ret == CTF_ERR) {
		/* No match found or error, terminate now */
		cdufp->cduf_ret = cdum.cdum_ret;
		return (1);
	} else if (ret == CTF_ERR) {
		(void) ctf_set_errno(cdum.cdum_fp, ctf_errno(cdum.cdum_iterfp));
		cdufp->cduf_ret = CTF_ERR;
		return (1);
	} else {
		ASSERT(cdum.cdum_ret == B_FALSE);
		cdufp->cduf_ret = cdum.cdum_ret;
		return (0);
	}
}

static int
ctf_diff_union(ctf_diff_t *cds, ctf_file_t *ifp, ctf_id_t iid, ctf_file_t *ofp,
    ctf_id_t oid)
{
	ctf_file_t *oifp;
	const ctf_type_t *itp, *otp;
	ctf_diff_union_fp_t cduf;
	ctf_diff_guess_t *cdg;
	int ret;

	oifp = ifp;
	if ((itp = ctf_lookup_by_id(&ifp, iid)) == NULL)
		return (CTF_ERR);
	if ((otp = ctf_lookup_by_id(&ofp, oid)) == NULL)
		return (ctf_set_errno(oifp, ctf_errno(ofp)));

	if (LCTF_INFO_VLEN(ifp, itp->ctt_info) !=
	    LCTF_INFO_VLEN(ofp, otp->ctt_info))
		return (B_TRUE);

	cdg = ctf_alloc(sizeof (ctf_diff_guess_t));
	if (cdg == NULL)
		return (ctf_set_errno(ifp, ENOMEM));
	cdg->cdg_iid = iid;
	cdg->cdg_oid = oid;
	cdg->cdg_next = cds->cds_guess;
	cds->cds_guess = cdg;
	cds->cds_forward[TINDEX(iid)] = oid;
	cds->cds_reverse[TINDEX(oid)] = iid;

	cduf.cduf_cds = cds;
	cduf.cduf_curfp = ifp;
	cduf.cduf_altfp = ofp;
	cduf.cduf_type = oid;
	cduf.cduf_ret = B_TRUE;
	ret = ctf_member_iter(ifp, iid, ctf_diff_union_check_fp, &cduf);
	if (ret != CTF_ERR)
		ret = cduf.cduf_ret;

	return (ret);
}

/*
 * Two enums are equivalent if they share the same underlying type and they have
 * the same set of members.
 */
static int
ctf_diff_enum(ctf_file_t *ifp, ctf_id_t iid, ctf_file_t *ofp, ctf_id_t oid)
{
	ctf_file_t *oifp;
	const ctf_type_t *itp, *otp;
	ssize_t iincr, oincr;
	const ctf_enum_t *iep, *oep;
	int n;

	oifp = ifp;
	if ((itp = ctf_lookup_by_id(&ifp, iid)) == NULL)
		return (CTF_ERR);
	if ((otp = ctf_lookup_by_id(&ofp, oid)) == NULL)
		return (ctf_set_errno(oifp, ctf_errno(ofp)));

	if (LCTF_INFO_VLEN(ifp, itp->ctt_info) !=
	    LCTF_INFO_VLEN(ofp, otp->ctt_info))
		return (B_TRUE);

	(void) ctf_get_ctt_size(ifp, itp, NULL, &iincr);
	(void) ctf_get_ctt_size(ofp, otp, NULL, &oincr);
	iep = (const ctf_enum_t *)((uintptr_t)itp + iincr);
	oep = (const ctf_enum_t *)((uintptr_t)otp + oincr);

	for (n = LCTF_INFO_VLEN(ifp, itp->ctt_info); n != 0;
	    n--, iep++, oep++) {
		if (strcmp(ctf_strptr(ifp, iep->cte_name),
		    ctf_strptr(ofp, oep->cte_name)) != 0)
			return (B_TRUE);

		if (iep->cte_value != oep->cte_value)
			return (B_TRUE);
	}

	return (B_FALSE);
}

/*
 * Two forwards are equivalent in one of two cases. If both are forwards, than
 * they are the same. Otherwise, they're equivalent if one is a struct or union
 * and the other is a forward.
 */
static int
ctf_diff_forward(ctf_file_t *ifp, ctf_id_t iid, ctf_file_t *ofp, ctf_id_t oid)
{
	int ikind, okind;

	ikind = ctf_type_kind(ifp, iid);
	okind = ctf_type_kind(ofp, oid);

	if (ikind == okind) {
		ASSERT(ikind == CTF_K_FORWARD);
		return (B_FALSE);
	} else if (ikind == CTF_K_FORWARD) {
		return (okind != CTF_K_UNION && okind != CTF_K_STRUCT);
	} else {
		return (ikind != CTF_K_UNION && ikind != CTF_K_STRUCT);
	}
}

/*
 * Are two types equivalent?
 */
int
ctf_diff_type(ctf_diff_t *cds, ctf_file_t *ifp, ctf_id_t iid, ctf_file_t *ofp,
    ctf_id_t oid)
{
	int ret, ikind, okind;

	/* Do a quick short circuit */
	if (ifp == ofp && iid == oid)
		return (B_FALSE);

	/*
	 * Check if it's something we've already encountered in a forward
	 * reference or forward negative table. Also double check the reverse
	 * table.
	 */
	if (cds->cds_forward[TINDEX(iid)] == oid)
		return (B_FALSE);
	if (cds->cds_forward[TINDEX(iid)] != 0)
		return (B_TRUE);
	if (cds->cds_reverse[TINDEX(oid)] == iid)
		return (B_FALSE);
	if ((cds->cds_flags & CTF_DIFF_F_IGNORE_INTNAMES) == 0 &&
	    cds->cds_reverse[TINDEX(oid)] != 0)
		return (B_TRUE);

	ikind = ctf_type_kind(ifp, iid);
	okind = ctf_type_kind(ofp, oid);

	if (ikind != okind &&
	    ikind != CTF_K_FORWARD && okind != CTF_K_FORWARD)
			return (B_TRUE);

	/* Check names */
	if ((ret = ctf_diff_name(ifp, iid, ofp, oid)) != B_FALSE) {
		if (ikind != okind || ikind != CTF_K_INTEGER ||
		    (cds->cds_flags & CTF_DIFF_F_IGNORE_INTNAMES) == 0)
			return (ret);
	}

	if (ikind == CTF_K_FORWARD || okind == CTF_K_FORWARD)
		return (ctf_diff_forward(ifp, iid, ofp, oid));

	switch (ikind) {
	case CTF_K_INTEGER:
	case CTF_K_FLOAT:
		ret = ctf_diff_number(ifp, iid, ofp, oid);
		break;
	case CTF_K_ARRAY:
		ret = ctf_diff_array(cds, ifp, iid, ofp, oid);
		break;
	case CTF_K_FUNCTION:
		ret = ctf_diff_fptr(cds, ifp, iid, ofp, oid);
		break;
	case CTF_K_STRUCT:
		ret = ctf_diff_struct(cds, ifp, iid, ofp, oid);
		break;
	case CTF_K_UNION:
		ret = ctf_diff_union(cds, ifp, iid, ofp, oid);
		break;
	case CTF_K_ENUM:
		ret = ctf_diff_enum(ifp, iid, ofp, oid);
		break;
	case CTF_K_FORWARD:
		ret = ctf_diff_forward(ifp, iid, ofp, oid);
		break;
	case CTF_K_TYPEDEF:
		ret = ctf_diff_typedef(cds, ifp, iid, ofp, oid);
		break;
	case CTF_K_POINTER:
	case CTF_K_VOLATILE:
	case CTF_K_CONST:
	case CTF_K_RESTRICT:
		ret = ctf_diff_qualifier(cds, ifp, iid, ofp, oid);
		break;
	case CTF_K_UNKNOWN:
		/*
		 * The current CTF tools use CTF_K_UNKNOWN as a padding type. We
		 * always declare two instances of CTF_K_UNKNOWN as different,
		 * even though this leads to additional diff noise.
		 */
		ret = B_TRUE;
		break;
	default:
		abort();
	}

	return (ret);
}

/*
 * Walk every type in the first container and try to find a match in the second.
 * If there is a match, then update both the forward and reverse mapping tables.
 *
 * The self variable tells us whether or not we should be comparing the input
 * ctf container with itself or not.
 */
static int
ctf_diff_pass1(ctf_diff_t *cds, boolean_t self)
{
	int i, j, diff;
	int istart, iend, jstart, jend;

	if (cds->cds_ifp->ctf_flags & LCTF_CHILD) {
		istart = 0x8001;
		iend = cds->cds_ifp->ctf_typemax + 0x8000;
	} else {
		istart = 1;
		iend = cds->cds_ifp->ctf_typemax;
	}

	if (cds->cds_ofp->ctf_flags & LCTF_CHILD) {
		jstart = 0x8001;
		jend = cds->cds_ofp->ctf_typemax + 0x8000;
	} else {
		jstart = 1;
		jend = cds->cds_ofp->ctf_typemax;
	}

	for (i = istart; i <= iend; i++) {
		diff = B_TRUE;

		/*
		 * If we're doing a self diff for dedup purposes, then we want
		 * to ensure that we compare a type i with every type in the
		 * range, [ 1, i ). Yes, this does mean that when i equals 1,
		 * we won't compare anything.
		 */
		if (self == B_TRUE) {
			jstart = istart;
			jend = i - 1;
		}
		for (j = jstart; j <= jend; j++) {
			ctf_diff_guess_t *cdg, *tofree;

			ASSERT(cds->cds_guess == NULL);
			diff = ctf_diff_type(cds, cds->cds_ifp, i,
			    cds->cds_ofp, j);
			if (diff == CTF_ERR)
				return (CTF_ERR);

			/* Clean up our guesses */
			cdg = cds->cds_guess;
			cds->cds_guess = NULL;
			while (cdg != NULL) {
				if (diff == B_TRUE) {
					cds->cds_forward[TINDEX(cdg->cdg_iid)] =
					    0;
					cds->cds_reverse[TINDEX(cdg->cdg_oid)] =
					    0;
				}
				tofree = cdg;
				cdg = cdg->cdg_next;
				ctf_free(tofree, sizeof (ctf_diff_guess_t));
			}

			/* Found a hit, update the tables */
			if (diff == B_FALSE) {
				cds->cds_forward[TINDEX(i)] = j;
				if (cds->cds_reverse[TINDEX(j)] == 0)
					cds->cds_reverse[TINDEX(j)] = i;
				break;
			}
		}

		/* Call the callback at this point */
		if (diff == B_TRUE) {
			cds->cds_forward[TINDEX(i)] = CTF_ERR;
			cds->cds_func(cds->cds_ifp, i, B_FALSE, NULL, CTF_ERR,
			    cds->cds_arg);
		} else {
			cds->cds_func(cds->cds_ifp, i, B_TRUE, cds->cds_ofp, j,
			    cds->cds_arg);
		}
	}

	return (0);
}

/*
 * Now we need to walk the second container and emit anything that we didn't
 * find as common in the first pass.
 */
static int
ctf_diff_pass2(ctf_diff_t *cds)
{
	int i, start, end;

	start = 0x1;
	end = cds->cds_ofp->ctf_typemax;
	if (cds->cds_ofp->ctf_flags & LCTF_CHILD) {
		start += 0x8000;
		end += 0x8000;
	}

	for (i = start; i <= end; i++) {
		if (cds->cds_reverse[TINDEX(i)] != 0)
			continue;
		cds->cds_func(cds->cds_ofp, i, B_FALSE, NULL, CTF_ERR,
		    cds->cds_arg);
	}

	return (0);
}

int
ctf_diff_init(ctf_file_t *ifp, ctf_file_t *ofp, ctf_diff_t **cdsp)
{
	ctf_diff_t *cds;
	size_t fsize, rsize;

	cds = ctf_alloc(sizeof (ctf_diff_t));
	if (cds == NULL)
		return (ctf_set_errno(ifp, ENOMEM));

	bzero(cds, sizeof (ctf_diff_t));
	cds->cds_ifp = ifp;
	cds->cds_ofp = ofp;

	fsize = sizeof (ctf_id_t) * ifp->ctf_typemax;
	rsize = sizeof (ctf_id_t) * ofp->ctf_typemax;
	if (ifp->ctf_flags & LCTF_CHILD)
		fsize += 0x8000 * sizeof (ctf_id_t);
	if (ofp->ctf_flags & LCTF_CHILD)
		rsize += 0x8000 * sizeof (ctf_id_t);

	cds->cds_forward = ctf_alloc(fsize);
	if (cds->cds_forward == NULL) {
		ctf_free(cds, sizeof (ctf_diff_t));
		return (ctf_set_errno(ifp, ENOMEM));
	}
	cds->cds_fsize = fsize;
	cds->cds_reverse = ctf_alloc(rsize);
	if (cds->cds_reverse == NULL) {
		ctf_free(cds->cds_forward, fsize);
		ctf_free(cds, sizeof (ctf_diff_t));
		return (ctf_set_errno(ifp, ENOMEM));
	}
	cds->cds_rsize = rsize;
	bzero(cds->cds_forward, fsize);
	bzero(cds->cds_reverse, rsize);

	cds->cds_ifp->ctf_refcnt++;
	cds->cds_ofp->ctf_refcnt++;
	*cdsp = cds;
	return (0);
}

int
ctf_diff_types(ctf_diff_t *cds, ctf_diff_type_f cb, void *arg)
{
	int ret;

	cds->cds_func = cb;
	cds->cds_arg = arg;

	ret = ctf_diff_pass1(cds, B_FALSE);
	if (ret == 0)
		ret = ctf_diff_pass2(cds);

	cds->cds_func = NULL;
	cds->cds_arg = NULL;
	cds->cds_tvalid = B_TRUE;
	return (ret);
}

/*
 * Do a diff where we're comparing a container with itself. In other words we'd
 * like to know what types are actually duplicates of existing types in the
 * container.
 *
 * Note this should remain private to libctf and not be exported in the public
 * mapfile for the time being.
 */
int
ctf_diff_self(ctf_diff_t *cds, ctf_diff_type_f cb, void *arg)
{
	if (cds->cds_ifp != cds->cds_ofp)
		return (EINVAL);

	cds->cds_func = cb;
	cds->cds_arg = arg;

	return (ctf_diff_pass1(cds, B_TRUE));
}


void
ctf_diff_fini(ctf_diff_t *cds)
{
	ctf_diff_guess_t *cdg;
	size_t fsize, rsize;

	if (cds == NULL)
		return;

	cds->cds_ifp->ctf_refcnt--;
	cds->cds_ofp->ctf_refcnt--;

	fsize = sizeof (ctf_id_t) * cds->cds_ifp->ctf_typemax;
	rsize = sizeof (ctf_id_t) * cds->cds_ofp->ctf_typemax;
	if (cds->cds_ifp->ctf_flags & LCTF_CHILD)
		fsize += 0x8000 * sizeof (ctf_id_t);
	if (cds->cds_ofp->ctf_flags & LCTF_CHILD)
		rsize += 0x8000 * sizeof (ctf_id_t);

	if (cds->cds_ifuncs != NULL)
		ctf_free(cds->cds_ifuncs,
		    sizeof (ctf_diff_func_t) * cds->cds_nifuncs);
	if (cds->cds_ofuncs != NULL)
		ctf_free(cds->cds_ofuncs,
		    sizeof (ctf_diff_func_t) * cds->cds_nofuncs);
	if (cds->cds_iobj != NULL)
		ctf_free(cds->cds_iobj,
		    sizeof (ctf_diff_obj_t) * cds->cds_niobj);
	if (cds->cds_oobj != NULL)
		ctf_free(cds->cds_oobj,
		    sizeof (ctf_diff_obj_t) * cds->cds_noobj);
	cdg = cds->cds_guess;
	while (cdg != NULL) {
		ctf_diff_guess_t *tofree = cdg;
		cdg = cdg->cdg_next;
		ctf_free(tofree, sizeof (ctf_diff_guess_t));
	}
	if (cds->cds_forward != NULL)
		ctf_free(cds->cds_forward, cds->cds_fsize);
	if (cds->cds_reverse != NULL)
		ctf_free(cds->cds_reverse, cds->cds_rsize);
	ctf_free(cds, sizeof (ctf_diff_t));
}

uint_t
ctf_diff_getflags(ctf_diff_t *cds)
{
	return (cds->cds_flags);
}

int
ctf_diff_setflags(ctf_diff_t *cds, uint_t flags)
{
	if ((flags & ~CTF_DIFF_F_IGNORE_INTNAMES) != 0)
		return (ctf_set_errno(cds->cds_ifp, EINVAL));

	cds->cds_flags = flags;
	return (0);
}

static boolean_t
ctf_diff_symid(ctf_diff_t *cds, ctf_id_t iid, ctf_id_t oid)
{
	ctf_file_t *ifp, *ofp;

	ifp = cds->cds_ifp;
	ofp = cds->cds_ofp;

	/*
	 * If we have parent containers on the scene here, we need to go through
	 * and do a full diff check because while a diff for types will not
	 * actually go through and check types in the parent container.
	 */
	if (iid == 0 || oid == 0)
		return (iid == oid ? B_FALSE: B_TRUE);

	if (!(ifp->ctf_flags & LCTF_CHILD) && !(ofp->ctf_flags & LCTF_CHILD)) {
		if (cds->cds_forward[TINDEX(iid)] != oid)
			return (B_TRUE);
		return (B_FALSE);
	}

	return (ctf_diff_type(cds, ifp, iid, ofp, oid));
}

/* ARGSUSED */
static void
ctf_diff_void_cb(ctf_file_t *ifp, ctf_id_t iid, boolean_t same, ctf_file_t *ofp,
    ctf_id_t oid, void *arg)
{
}

/* ARGSUSED */
static int
ctf_diff_func_count(const char *name, ulong_t symidx, ctf_funcinfo_t *fip,
    void *arg)
{
	uint32_t *ip = arg;

	*ip = *ip + 1;
	return (0);
}

/* ARGSUSED */
static int
ctf_diff_func_fill_cb(const char *name, ulong_t symidx, ctf_funcinfo_t *fip,
    void *arg)
{
	uint_t *next, max;
	ctf_diff_func_t *funcptr;
	ctf_diff_t *cds = arg;

	if (cds->cds_ffillip == B_TRUE) {
		max = cds->cds_nifuncs;
		next = &cds->cds_nextifunc;
		funcptr = cds->cds_ifuncs + *next;
	} else {
		max = cds->cds_nofuncs;
		next = &cds->cds_nextofunc;
		funcptr = cds->cds_ofuncs + *next;

	}

	VERIFY(*next < max);
	funcptr->cdf_name = name;
	funcptr->cdf_symidx = symidx;
	funcptr->cdf_matchidx = ULONG_MAX;
	*next = *next + 1;

	return (0);
}

int
ctf_diff_func_fill(ctf_diff_t *cds)
{
	int ret;
	uint32_t ifcount, ofcount, idcnt, cti;
	ulong_t i, j;
	ctf_id_t *iids, *oids;

	ifcount = 0;
	ofcount = 0;
	idcnt = 0;
	iids = NULL;
	oids = NULL;

	ret = ctf_function_iter(cds->cds_ifp, ctf_diff_func_count, &ifcount);
	if (ret != 0)
		return (ret);
	ret = ctf_function_iter(cds->cds_ofp, ctf_diff_func_count, &ofcount);
	if (ret != 0)
		return (ret);

	cds->cds_ifuncs = ctf_alloc(sizeof (ctf_diff_func_t) * ifcount);
	if (cds->cds_ifuncs == NULL)
		return (ctf_set_errno(cds->cds_ifp, ENOMEM));

	cds->cds_nifuncs = ifcount;
	cds->cds_nextifunc = 0;

	cds->cds_ofuncs = ctf_alloc(sizeof (ctf_diff_func_t) * ofcount);
	if (cds->cds_ofuncs == NULL)
		return (ctf_set_errno(cds->cds_ifp, ENOMEM));

	cds->cds_nofuncs = ofcount;
	cds->cds_nextofunc = 0;

	cds->cds_ffillip = B_TRUE;
	if ((ret = ctf_function_iter(cds->cds_ifp, ctf_diff_func_fill_cb,
	    cds)) != 0)
		return (ret);

	cds->cds_ffillip = B_FALSE;
	if ((ret = ctf_function_iter(cds->cds_ofp, ctf_diff_func_fill_cb,
	    cds)) != 0)
		return (ret);

	/*
	 * Everything is initialized to not match. This could probably be faster
	 * with something that used a hash. But this part of the diff isn't used
	 * by merge.
	 */
	for (i = 0; i < cds->cds_nifuncs; i++) {
		for (j = 0; j < cds->cds_nofuncs; j++) {
			ctf_diff_func_t *ifd, *ofd;
			ctf_funcinfo_t ifip, ofip;
			boolean_t match;

			ifd = &cds->cds_ifuncs[i];
			ofd = &cds->cds_ofuncs[j];
			if (strcmp(ifd->cdf_name, ofd->cdf_name) != 0)
				continue;

			ret = ctf_func_info(cds->cds_ifp, ifd->cdf_symidx,
			    &ifip);
			if (ret != 0)
				goto out;
			ret = ctf_func_info(cds->cds_ofp, ofd->cdf_symidx,
			    &ofip);
			if (ret != 0) {
				ret = ctf_set_errno(cds->cds_ifp,
				    ctf_errno(cds->cds_ofp));
				goto out;
			}

			if (ifip.ctc_argc != ofip.ctc_argc &&
			    ifip.ctc_flags != ofip.ctc_flags)
				continue;

			/* Validate return type and arguments are the same */
			if (ctf_diff_symid(cds, ifip.ctc_return,
			    ofip.ctc_return))
				continue;

			if (ifip.ctc_argc > idcnt) {
				if (iids != NULL)
					ctf_free(iids,
					    sizeof (ctf_id_t) * idcnt);
				if (oids != NULL)
					ctf_free(oids,
					    sizeof (ctf_id_t) * idcnt);
				iids = oids = NULL;
				idcnt = ifip.ctc_argc;
				iids = ctf_alloc(sizeof (ctf_id_t) * idcnt);
				if (iids == NULL) {
					ret = ctf_set_errno(cds->cds_ifp,
					    ENOMEM);
					goto out;
				}
				oids = ctf_alloc(sizeof (ctf_id_t) * idcnt);
				if (iids == NULL) {
					ret = ctf_set_errno(cds->cds_ifp,
					    ENOMEM);
					goto out;
				}
			}

			if ((ret = ctf_func_args(cds->cds_ifp, ifd->cdf_symidx,
			    ifip.ctc_argc, iids)) != 0)
				goto out;
			if ((ret = ctf_func_args(cds->cds_ofp, ofd->cdf_symidx,
			    ofip.ctc_argc, oids)) != 0)
				goto out;

			match = B_TRUE;
			for (cti = 0; cti < ifip.ctc_argc; cti++) {
				if (ctf_diff_symid(cds, iids[cti], oids[cti])) {
					match = B_FALSE;
					break;
				}
			}

			if (match == B_FALSE)
				continue;

			ifd->cdf_matchidx = j;
			ofd->cdf_matchidx = i;
			break;
		}
	}

	ret = 0;

out:
	if (iids != NULL)
		ctf_free(iids, sizeof (ctf_id_t) * idcnt);
	if (oids != NULL)
		ctf_free(oids, sizeof (ctf_id_t) * idcnt);

	return (ret);
}

/*
 * In general, two functions are the same, if they have the same name and their
 * arguments have the same types, including the return type. Like types, we
 * basically have to do this in two passes. In the first phase we walk every
 * type in the first container and try to find a match in the second.
 */
int
ctf_diff_functions(ctf_diff_t *cds, ctf_diff_func_f cb, void *arg)
{
	int ret;
	ulong_t i;

	if (cds->cds_tvalid == B_FALSE) {
		if ((ret = ctf_diff_types(cds, ctf_diff_void_cb, NULL)) != 0)
			return (ret);
	}

	if (cds->cds_fvalid == B_FALSE) {
		if ((ret = ctf_diff_func_fill(cds)) != 0)
			return (ret);
		cds->cds_fvalid = B_TRUE;
	}

	for (i = 0; i < cds->cds_nifuncs; i++) {
		if (cds->cds_ifuncs[i].cdf_matchidx == ULONG_MAX) {
			cb(cds->cds_ifp, cds->cds_ifuncs[i].cdf_symidx,
			    B_FALSE, NULL, ULONG_MAX, arg);
		} else {
			ulong_t idx = cds->cds_ifuncs[i].cdf_matchidx;
			cb(cds->cds_ifp, cds->cds_ifuncs[i].cdf_symidx, B_TRUE,
			    cds->cds_ofp, cds->cds_ofuncs[idx].cdf_symidx, arg);
		}
	}

	for (i = 0; i < cds->cds_nofuncs; i++) {
		if (cds->cds_ofuncs[i].cdf_matchidx != ULONG_MAX)
			continue;
		cb(cds->cds_ofp, cds->cds_ofuncs[i].cdf_symidx, B_FALSE,
		    NULL, ULONG_MAX, arg);
	}

	return (0);
}

static int
ctf_diff_obj_fill_cb(const char *name, ctf_id_t id, ulong_t symidx, void *arg)
{
	uint_t *next, max;
	ctf_diff_obj_t *objptr;
	ctf_diff_t *cds = arg;

	if (cds->cds_ofillip == B_TRUE) {
		max = cds->cds_niobj;
		next = &cds->cds_nextiobj;
		objptr = cds->cds_iobj + *next;
	} else {
		max = cds->cds_noobj;
		next = &cds->cds_nextoobj;
		objptr = cds->cds_oobj+ *next;

	}

	VERIFY(*next < max);
	objptr->cdo_name = name;
	objptr->cdo_symidx = symidx;
	objptr->cdo_id = id;
	objptr->cdo_matchidx = ULONG_MAX;
	*next = *next + 1;

	return (0);
}

/* ARGSUSED */
static int
ctf_diff_obj_count(const char *name, ctf_id_t id, ulong_t symidx, void *arg)
{
	uint32_t *count = arg;

	*count = *count + 1;

	return (0);
}


static int
ctf_diff_obj_fill(ctf_diff_t *cds)
{
	int ret;
	uint32_t iocount, oocount;
	ulong_t i, j;

	iocount = 0;
	oocount = 0;

	ret = ctf_object_iter(cds->cds_ifp, ctf_diff_obj_count, &iocount);
	if (ret != 0)
		return (ret);

	ret = ctf_object_iter(cds->cds_ofp, ctf_diff_obj_count, &oocount);
	if (ret != 0)
		return (ret);

	cds->cds_iobj = ctf_alloc(sizeof (ctf_diff_obj_t) * iocount);
	if (cds->cds_iobj == NULL)
		return (ctf_set_errno(cds->cds_ifp, ENOMEM));
	cds->cds_niobj = iocount;
	cds->cds_nextiobj = 0;

	cds->cds_oobj = ctf_alloc(sizeof (ctf_diff_obj_t) * oocount);
	if (cds->cds_oobj == NULL)
		return (ctf_set_errno(cds->cds_ifp, ENOMEM));
	cds->cds_noobj = oocount;
	cds->cds_nextoobj = 0;

	cds->cds_ofillip = B_TRUE;
	if ((ret = ctf_object_iter(cds->cds_ifp, ctf_diff_obj_fill_cb,
	    cds)) != 0)
		return (ret);

	cds->cds_ofillip = B_FALSE;
	if ((ret = ctf_object_iter(cds->cds_ofp, ctf_diff_obj_fill_cb,
	    cds)) != 0)
		return (ret);

	for (i = 0; i < cds->cds_niobj; i++) {
		for (j = 0; j < cds->cds_noobj; j++) {
			ctf_diff_obj_t *id, *od;

			id = &cds->cds_iobj[i];
			od = &cds->cds_oobj[j];

			if (id->cdo_name == NULL || od->cdo_name == NULL)
				continue;
			if (strcmp(id->cdo_name, od->cdo_name) != 0)
				continue;

			if (ctf_diff_symid(cds, id->cdo_id, od->cdo_id)) {
				continue;
			}

			id->cdo_matchidx = j;
			od->cdo_matchidx = i;
			break;
		}
	}

	return (0);
}

int
ctf_diff_objects(ctf_diff_t *cds, ctf_diff_obj_f cb, void *arg)
{
	int ret;
	ulong_t i;

	if (cds->cds_tvalid == B_FALSE) {
		if ((ret = ctf_diff_types(cds, ctf_diff_void_cb, NULL)) != 0)
			return (ret);
	}

	if (cds->cds_ovalid == B_FALSE) {
		if ((ret = ctf_diff_obj_fill(cds)) != 0)
			return (ret);
		cds->cds_ovalid = B_TRUE;
	}

	for (i = 0; i < cds->cds_niobj; i++) {
		ctf_diff_obj_t *o = &cds->cds_iobj[i];

		if (cds->cds_iobj[i].cdo_matchidx == ULONG_MAX) {
			cb(cds->cds_ifp, o->cdo_symidx, o->cdo_id, B_FALSE,
			    NULL, ULONG_MAX, CTF_ERR, arg);
		} else {
			ctf_diff_obj_t *alt = &cds->cds_oobj[o->cdo_matchidx];
			cb(cds->cds_ifp, o->cdo_symidx, o->cdo_id, B_TRUE,
			    cds->cds_ofp, alt->cdo_symidx, alt->cdo_id, arg);
		}
	}

	for (i = 0; i < cds->cds_noobj; i++) {
		ctf_diff_obj_t *o = &cds->cds_oobj[i];
		if (o->cdo_matchidx != ULONG_MAX)
			continue;
		cb(cds->cds_ofp, o->cdo_symidx, o->cdo_id, B_FALSE, NULL,
		    ULONG_MAX, CTF_ERR, arg);
	}

	return (0);
}
