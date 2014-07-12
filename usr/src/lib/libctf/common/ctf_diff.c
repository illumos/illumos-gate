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
 * Copyright (c) 2014 Joyent, Inc.  All rights reserved.
 */

#include <libctf.h>
#include <ctf_impl.h>
#include <sys/debug.h>

/* typedef in libctf.h */
struct ctf_diff {
	uint_t cds_flags;
	ctf_file_t *cds_ifp;
	ctf_file_t *cds_ofp;
	ctf_idhash_t cds_forward;
	ctf_idhash_t cds_reverse;
	ctf_idhash_t cds_fneg;
	ctf_idhash_t cds_f_visited;
	ctf_idhash_t cds_r_visited;
	ctf_diff_type_f cds_func;
	int cds_visitid;
	void *cds_arg;
};

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

	if (iar.ctr_nelems == oar.ctr_nelems)
		return (B_FALSE);

	ret = ctf_diff_type(cds, ifp, iar.ctr_index, ofp, oar.ctr_index);
	if (ret != B_FALSE)
		return (ret);

	return (B_TRUE);
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
ctf_diff_func(ctf_diff_t *cds, ctf_file_t *ifp, ctf_id_t iid, ctf_file_t *ofp,
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
 * type, at the same offset, and has the same name.
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

	oifp = ifp;

	if ((itp = ctf_lookup_by_id(&ifp, iid)) == NULL)
		return (CTF_ERR);

	if ((otp = ctf_lookup_by_id(&ofp, oid)) == NULL)
		return (ctf_set_errno(oifp, ctf_errno(ofp)));

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
		if (ret != B_FALSE)
			return (ret);

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
	int ret;

	oifp = ifp;
	if ((itp = ctf_lookup_by_id(&ifp, iid)) == NULL)
		return (CTF_ERR);
	if ((otp = ctf_lookup_by_id(&ofp, oid)) == NULL)
		return (ctf_set_errno(oifp, ctf_errno(ofp)));

	if (LCTF_INFO_VLEN(ifp, itp->ctt_info) !=
	    LCTF_INFO_VLEN(ofp, otp->ctt_info))
		return (B_TRUE);

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
	ctf_ihelem_t *lookup, *fv, *rv;

	/* Do a quick short circuit */
	if (ifp == ofp && iid == oid)
		return (B_FALSE);

	/*
	 * Check if it's something we've already encountered in a forward
	 * reference or forward negative table.
	 */
	if ((lookup = ctf_idhash_lookup(&cds->cds_forward, iid)) != NULL) {
		if (lookup->ih_value == oid)
			return (B_FALSE);
		else
			return (B_TRUE);
	}

	if (ctf_idhash_lookup(&cds->cds_forward, iid) != NULL) {
		return (B_TRUE);
	}

	fv = ctf_idhash_lookup(&cds->cds_f_visited, iid);
	rv = ctf_idhash_lookup(&cds->cds_r_visited, oid);
	if (fv != NULL && rv != NULL)
		return (fv->ih_value != rv->ih_value);
	else if (fv != NULL || rv != NULL)
		return (B_TRUE);

	ikind = ctf_type_kind(ifp, iid);
	okind = ctf_type_kind(ofp, oid);

	/* Check names */
	if ((ret = ctf_diff_name(ifp, iid, ofp, oid)) != B_FALSE) {
		if (ikind != okind || ikind != CTF_K_INTEGER ||
		    (cds->cds_flags & CTF_DIFF_F_IGNORE_INTNAMES) == 0)
			return (ret);
	}

	if (ikind != okind) {
		if (ikind == CTF_K_FORWARD || okind == CTF_K_FORWARD)
			return (ctf_diff_forward(ifp, iid, ofp, oid));
		else
			return (B_TRUE);
	}

	switch (ikind) {
	case CTF_K_INTEGER:
	case CTF_K_FLOAT:
		ret = ctf_diff_number(ifp, iid, ofp, oid);
		break;
	case CTF_K_ARRAY:
		ret = ctf_diff_array(cds, ifp, iid, ofp, oid);
		break;
	case CTF_K_FUNCTION:
		ret = ctf_diff_func(cds, ifp, iid, ofp, oid);
		break;
	case CTF_K_STRUCT:
		VERIFY(ctf_idhash_insert(&cds->cds_f_visited, iid,
		    cds->cds_visitid) == 0);
		VERIFY(ctf_idhash_insert(&cds->cds_r_visited, oid,
		    cds->cds_visitid) == 0);
		cds->cds_visitid++;
		ret = ctf_diff_struct(cds, ifp, iid, ofp, oid);
		break;
	case CTF_K_UNION:
		VERIFY(ctf_idhash_insert(&cds->cds_f_visited, iid,
		    cds->cds_visitid) == 0);
		VERIFY(ctf_idhash_insert(&cds->cds_r_visited, oid,
		    cds->cds_visitid) == 0);
		cds->cds_visitid++;
		ret = ctf_diff_union(cds, ifp, iid, ofp, oid);
		break;
	case CTF_K_ENUM:
		ret = ctf_diff_enum(ifp, iid, ofp, oid);
		break;
	case CTF_K_FORWARD:
		ret = ctf_diff_forward(ifp, iid, ofp, oid);
		break;
	case CTF_K_POINTER:
	case CTF_K_TYPEDEF:
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
 */
static int
ctf_diff_pass1(ctf_diff_t *cds)
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
		for (j = jstart; j <= jend; j++) {
			cds->cds_visitid = 1;
			ctf_idhash_clear(&cds->cds_f_visited);
			ctf_idhash_clear(&cds->cds_r_visited);

			diff = ctf_diff_type(cds, cds->cds_ifp, i,
			    cds->cds_ofp, j);
			if (diff == CTF_ERR)
				return (CTF_ERR);

			/* Found a hit, update the tables */
			if (diff == B_FALSE) {
				VERIFY(ctf_idhash_lookup(&cds->cds_forward,
				    i) == NULL);
				VERIFY(ctf_idhash_insert(&cds->cds_forward,
				    i, j) == 0);
				if (ctf_idhash_lookup(&cds->cds_reverse, j) ==
				    NULL) {
					VERIFY(ctf_idhash_lookup(
					    &cds->cds_reverse, j) == NULL);
					VERIFY(ctf_idhash_insert(
					    &cds->cds_reverse, j, i) == 0);
				}
				break;
			}
		}

		/* Call the callback at this point */
		if (diff == B_TRUE) {
			VERIFY(ctf_idhash_insert(&cds->cds_fneg, i, 1) == 0);
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
	int i;

	for (i = 1; i <= cds->cds_ofp->ctf_typemax; i++) {
		if (ctf_idhash_lookup(&cds->cds_reverse, i) != NULL)
			continue;
		cds->cds_func(cds->cds_ofp, i, B_FALSE, NULL, CTF_ERR,
		    cds->cds_arg);
	}

	return (0);
}

int
ctf_diff_init(ctf_file_t *ifp, ctf_file_t *ofp, ctf_diff_t **cdsp)
{
	int ret;
	ctf_diff_t *cds;

	cds = ctf_alloc(sizeof (ctf_diff_t));
	if (cds == NULL)
		return (ctf_set_errno(ifp, ENOMEM));

	bzero(cds, sizeof (ctf_diff_t));
	cds->cds_ifp = ifp;
	cds->cds_ofp = ofp;
	ret = ctf_idhash_create(&cds->cds_forward, ifp->ctf_typemax);
	if (ret != 0) {
		ctf_free(cds, sizeof (ctf_diff_t));
		return (ctf_set_errno(ifp, ret));
	}
	ret = ctf_idhash_create(&cds->cds_reverse, ofp->ctf_typemax);
	if (ret != 0) {
		ctf_idhash_destroy(&cds->cds_forward);
		ctf_free(cds, sizeof (ctf_diff_t));
		return (ctf_set_errno(ifp, ret));
	}
	ret = ctf_idhash_create(&cds->cds_f_visited, ifp->ctf_typemax);
	if (ret != 0) {
		ctf_idhash_destroy(&cds->cds_reverse);
		ctf_idhash_destroy(&cds->cds_forward);
		ctf_free(cds, sizeof (ctf_diff_t));
		return (ctf_set_errno(ifp, ret));
	}
	ret = ctf_idhash_create(&cds->cds_r_visited, ofp->ctf_typemax);
	if (ret != 0) {
		ctf_idhash_destroy(&cds->cds_f_visited);
		ctf_idhash_destroy(&cds->cds_reverse);
		ctf_idhash_destroy(&cds->cds_forward);
		ctf_free(cds, sizeof (ctf_diff_t));
		return (ctf_set_errno(ifp, ret));
	}
	ret = ctf_idhash_create(&cds->cds_fneg, ifp->ctf_typemax);
	if (ret != 0) {
		ctf_idhash_destroy(&cds->cds_r_visited);
		ctf_idhash_destroy(&cds->cds_f_visited);
		ctf_idhash_destroy(&cds->cds_reverse);
		ctf_idhash_destroy(&cds->cds_forward);
		ctf_free(cds, sizeof (ctf_diff_t));
		return (ctf_set_errno(ifp, ret));
	}

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

	/*
	 * For the moment clear all idhashes and rerun this phase. Ideally we
	 * should reuse this, but we can save that for when we add things like
	 * taking the diff of the objects and the like.
	 */
	ctf_idhash_clear(&cds->cds_forward);
	ctf_idhash_clear(&cds->cds_reverse);
	ctf_idhash_clear(&cds->cds_fneg);
	ctf_idhash_clear(&cds->cds_f_visited);
	ctf_idhash_clear(&cds->cds_r_visited);

	ret = ctf_diff_pass1(cds);
	if (ret == 0)
		ret = ctf_diff_pass2(cds);

	cds->cds_func = NULL;
	cds->cds_arg = NULL;
	return (ret);
}

void
ctf_diff_fini(ctf_diff_t *cds)
{
	cds->cds_ifp->ctf_refcnt--;
	cds->cds_ofp->ctf_refcnt--;

	ctf_idhash_destroy(&cds->cds_fneg);
	ctf_idhash_destroy(&cds->cds_r_visited);
	ctf_idhash_destroy(&cds->cds_f_visited);
	ctf_idhash_destroy(&cds->cds_reverse);
	ctf_idhash_destroy(&cds->cds_forward);
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
	if ((flags & ~CTF_DIFF_F_MASK) != 0)
		return (ctf_set_errno(cds->cds_ifp, EINVAL));

	cds->cds_flags = flags;
	return (0);
}
