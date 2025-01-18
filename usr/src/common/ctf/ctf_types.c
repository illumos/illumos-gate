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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2020 Joyent, Inc.
 * Copyright 2020 OmniOS Community Edition (OmniOSce) Association.
 * Copyright 2025 Oxide Computer Company
 */

#include <ctf_impl.h>
#include <sys/debug.h>

ssize_t
ctf_get_ctt_size(const ctf_file_t *fp, const ctf_type_t *tp, ssize_t *sizep,
    ssize_t *incrementp)
{
	ssize_t size, increment;

	if (fp->ctf_version > CTF_VERSION_1 &&
	    tp->ctt_size == CTF_LSIZE_SENT) {
		size = CTF_TYPE_LSIZE(tp);
		increment = sizeof (ctf_type_t);
	} else {
		size = tp->ctt_size;
		increment = sizeof (ctf_stype_t);
	}

	if (sizep)
		*sizep = size;
	if (incrementp)
		*incrementp = increment;

	return (size);
}

void
ctf_set_ctt_size(ctf_type_t *tp, ssize_t size)
{
	if (size > CTF_MAX_SIZE) {
		tp->ctt_size = CTF_LSIZE_SENT;
		tp->ctt_lsizehi = CTF_SIZE_TO_LSIZE_HI(size);
		tp->ctt_lsizelo = CTF_SIZE_TO_LSIZE_LO(size);
	} else {
		tp->ctt_size = (ushort_t)size;
	}
}

/*
 * Iterate over the members of a STRUCT or UNION.  We pass the name, member
 * type, and offset of each member to the specified callback function.
 */
int
ctf_member_iter(ctf_file_t *fp, ctf_id_t type, ctf_member_f *func, void *arg)
{
	ctf_file_t *ofp = fp;
	const ctf_type_t *tp;
	ssize_t size, increment;
	uint_t kind, n;
	int rc;

	if ((type = ctf_type_resolve(fp, type)) == CTF_ERR)
		return (CTF_ERR); /* errno is set for us */

	if ((tp = ctf_lookup_by_id(&fp, type)) == NULL)
		return (CTF_ERR); /* errno is set for us */

	(void) ctf_get_ctt_size(fp, tp, &size, &increment);
	kind = LCTF_INFO_KIND(fp, tp->ctt_info);

	if (kind != CTF_K_STRUCT && kind != CTF_K_UNION)
		return (ctf_set_errno(ofp, ECTF_NOTSOU));

	if (fp->ctf_version == CTF_VERSION_1 || size < CTF_LSTRUCT_THRESH) {
		const ctf_member_t *mp = (const ctf_member_t *)
		    ((uintptr_t)tp + increment);

		for (n = LCTF_INFO_VLEN(fp, tp->ctt_info); n != 0; n--, mp++) {
			const char *name = ctf_strptr(fp, mp->ctm_name);
			if ((rc = func(name, mp->ctm_type, mp->ctm_offset,
			    arg)) != 0)
				return (rc);
		}

	} else {
		const ctf_lmember_t *lmp = (const ctf_lmember_t *)
		    ((uintptr_t)tp + increment);

		for (n = LCTF_INFO_VLEN(fp, tp->ctt_info); n != 0; n--, lmp++) {
			const char *name = ctf_strptr(fp, lmp->ctlm_name);
			if ((rc = func(name, lmp->ctlm_type,
			    (ulong_t)CTF_LMEM_OFFSET(lmp), arg)) != 0)
				return (rc);
		}
	}

	return (0);
}

/*
 * Iterate over the members of an ENUM.  We pass the string name and associated
 * integer value of each enum element to the specified callback function.
 */
int
ctf_enum_iter(ctf_file_t *fp, ctf_id_t type, ctf_enum_f *func, void *arg)
{
	ctf_file_t *ofp = fp;
	const ctf_type_t *tp;
	const ctf_enum_t *ep;
	ssize_t increment;
	uint_t n;
	int rc;

	if ((type = ctf_type_resolve(fp, type)) == CTF_ERR)
		return (CTF_ERR); /* errno is set for us */

	if ((tp = ctf_lookup_by_id(&fp, type)) == NULL)
		return (CTF_ERR); /* errno is set for us */

	if (LCTF_INFO_KIND(fp, tp->ctt_info) != CTF_K_ENUM)
		return (ctf_set_errno(ofp, ECTF_NOTENUM));

	(void) ctf_get_ctt_size(fp, tp, NULL, &increment);

	ep = (const ctf_enum_t *)((uintptr_t)tp + increment);

	for (n = LCTF_INFO_VLEN(fp, tp->ctt_info); n != 0; n--, ep++) {
		const char *name = ctf_strptr(fp, ep->cte_name);
		if ((rc = func(name, ep->cte_value, arg)) != 0)
			return (rc);
	}

	return (0);
}

/*
 * Iterate over every type in the given CTF container. If the user doesn't ask
 * for all types, then we only give them the user visible, aka root, types.  We
 * pass the type ID of each type to the specified callback function.
 */
int
ctf_type_iter(ctf_file_t *fp, boolean_t nonroot, ctf_type_f *func, void *arg)
{
	ctf_id_t id, max = fp->ctf_typemax;
	int rc, child = (fp->ctf_flags & LCTF_CHILD);

	for (id = 1; id <= max; id++) {
		const ctf_type_t *tp = LCTF_INDEX_TO_TYPEPTR(fp, id);
		if ((nonroot || CTF_INFO_ISROOT(tp->ctt_info)) &&
		    (rc = func(CTF_INDEX_TO_TYPE(id, child),
		    CTF_INFO_ISROOT(tp->ctt_info),  arg)) != 0)
			return (rc);
	}

	return (0);
}

/*
 * Follow a given type through the graph for TYPEDEF, VOLATILE, CONST, and
 * RESTRICT nodes until we reach a "base" type node.  This is useful when
 * we want to follow a type ID to a node that has members or a size.  To guard
 * against infinite loops, we implement simplified cycle detection and check
 * each link against itself, the previous node, and the topmost node.
 */
ctf_id_t
ctf_type_resolve(ctf_file_t *fp, ctf_id_t type)
{
	ctf_id_t prev = type, otype = type;
	ctf_file_t *ofp = fp;
	const ctf_type_t *tp;

	while ((tp = ctf_lookup_by_id(&fp, type)) != NULL) {
		switch (LCTF_INFO_KIND(fp, tp->ctt_info)) {
		case CTF_K_TYPEDEF:
		case CTF_K_VOLATILE:
		case CTF_K_CONST:
		case CTF_K_RESTRICT:
			if (tp->ctt_type == type || tp->ctt_type == otype ||
			    tp->ctt_type == prev) {
				ctf_dprintf("type %ld cycle detected\n", otype);
				return (ctf_set_errno(ofp, ECTF_CORRUPT));
			}
			prev = type;
			type = tp->ctt_type;
			break;
		default:
			return (type);
		}
	}

	return (CTF_ERR); /* errno is set for us */
}

/*
 * Format an integer type; if a vname is specified, we need to insert it prior
 * to any bitfield ":24" suffix.  This works out far simpler than figuring it
 * out from scratch.
 */
static const char *
ctf_format_int(ctf_decl_t *cd, const char *vname, const char *qname,
    const char *name)
{
	const char *c;

	if (vname == NULL) {
		if (qname != NULL)
			ctf_decl_sprintf(cd, "%s`%s", qname, name);
		else
			ctf_decl_sprintf(cd, "%s", name);
		return (NULL);
	}

	if ((c = strchr(name, ':')) == NULL) {
		ctf_decl_sprintf(cd, "%s", name);
		return (vname);
	}

	/* "unsigned int mybits:23" */
	ctf_decl_sprintf(cd, "%.*s %s%s", c - name, name, vname, c);
	return (NULL);
}

static void
ctf_format_func(ctf_file_t *fp, ctf_decl_t *cd,
    const char *vname, ctf_id_t id, int want_func_args)
{
	ctf_funcinfo_t fi;
	/* We'll presume zone_create() is a bad example. */
	ctf_id_t args[20];

	ctf_decl_sprintf(cd, "%s(", vname == NULL ? "" : vname);

	if (!want_func_args)
		goto out;

	if (ctf_func_info_by_id(fp, id, &fi) != 0)
		goto out;

	if (fi.ctc_argc > ARRAY_SIZE(args))
		fi.ctc_argc = ARRAY_SIZE(args);

	if (fi.ctc_argc == 0) {
		ctf_decl_sprintf(cd, "void");
		goto out;
	}

	if (ctf_func_args_by_id(fp, id, fi.ctc_argc, args) != 0)
		goto out;

	for (size_t i = 0; i < fi.ctc_argc; i++) {
		char aname[512];

		if (ctf_type_name(fp, args[i], aname, sizeof (aname)) == NULL)
			(void) strlcpy(aname, "unknown_t", sizeof (aname));

		ctf_decl_sprintf(cd, "%s%s", aname,
		    i + 1 == fi.ctc_argc ? "" : ", ");
	}

	if (fi.ctc_flags & CTF_FUNC_VARARG)
		ctf_decl_sprintf(cd, "%s...", fi.ctc_argc == 0 ? "" : ", ");

out:
	ctf_decl_sprintf(cd, ")");
}

/*
 * Lookup the given type ID and print a string name for it into buf.  Return the
 * actual number of bytes (not including \0) needed to format the name.
 *
 * "vname" is an optional variable name or similar, so array suffix formatting,
 * bitfields, and functions are C-correct.  (This is not perfect, as can be seen
 * in kiconv_ops_t.)
 */
static ssize_t
ctf_type_qlname(ctf_file_t *fp, ctf_id_t type, char *buf, size_t len,
    const char *vname, const char *qname)
{
	int want_func_args = (vname != NULL);
	ctf_decl_t cd;
	ctf_decl_node_t *cdp;
	ctf_decl_prec_t prec, lp, rp;
	int ptr, arr;
	uint_t k;

	if (fp == NULL && type == CTF_ERR)
		return (-1); /* simplify caller code by permitting CTF_ERR */

	ctf_decl_init(&cd, buf, len);
	ctf_decl_push(&cd, fp, type);

	if (cd.cd_err != 0) {
		ctf_decl_fini(&cd);
		return (ctf_set_errno(fp, cd.cd_err));
	}

	/*
	 * If the type graph's order conflicts with lexical precedence order
	 * for pointers or arrays, then we need to surround the declarations at
	 * the corresponding lexical precedence with parentheses.  This can
	 * result in either a parenthesized pointer (*) as in int (*)() or
	 * int (*)[], or in a parenthesized pointer and array as in int (*[])().
	 */
	ptr = cd.cd_order[CTF_PREC_POINTER] > CTF_PREC_POINTER;
	arr = cd.cd_order[CTF_PREC_ARRAY] > CTF_PREC_ARRAY;

	rp = arr ? CTF_PREC_ARRAY : ptr ? CTF_PREC_POINTER : -1;
	lp = ptr ? CTF_PREC_POINTER : arr ? CTF_PREC_ARRAY : -1;

	k = CTF_K_POINTER; /* avoid leading whitespace (see below) */

	for (prec = CTF_PREC_BASE; prec < CTF_PREC_MAX; prec++) {
		for (cdp = ctf_list_next(&cd.cd_nodes[prec]);
		    cdp != NULL; cdp = ctf_list_next(cdp)) {

			ctf_file_t *rfp = fp;
			const ctf_type_t *tp =
			    ctf_lookup_by_id(&rfp, cdp->cd_type);
			const char *name = ctf_strptr(rfp, tp->ctt_name);

			if (k != CTF_K_POINTER && k != CTF_K_ARRAY)
				ctf_decl_sprintf(&cd, " ");

			if (lp == prec) {
				ctf_decl_sprintf(&cd, "(");
				lp = -1;
			}

			switch (cdp->cd_kind) {
			case CTF_K_INTEGER:
				vname = ctf_format_int(&cd, vname, qname, name);
				break;
			case CTF_K_FLOAT:
			case CTF_K_TYPEDEF:
				if (qname != NULL)
					ctf_decl_sprintf(&cd, "%s`", qname);
				ctf_decl_sprintf(&cd, "%s", name);
				break;
			case CTF_K_POINTER:
				ctf_decl_sprintf(&cd, "*");
				break;
			case CTF_K_ARRAY:
				ctf_decl_sprintf(&cd, "%s[%u]",
				    vname != NULL ? vname : "", cdp->cd_n);
				vname = NULL;
				break;
			case CTF_K_FUNCTION:
				ctf_format_func(fp, &cd, vname,
				    cdp->cd_type, want_func_args);
				vname = NULL;
				break;
			case CTF_K_FORWARD:
				switch (tp->ctt_type) {
				case CTF_K_UNION:
					ctf_decl_sprintf(&cd, "union ");
					break;
				case CTF_K_ENUM:
					ctf_decl_sprintf(&cd, "enum ");
					break;
				case CTF_K_STRUCT:
				default:
					ctf_decl_sprintf(&cd, "struct ");
					break;
				}
				if (qname != NULL)
					ctf_decl_sprintf(&cd, "%s`", qname);
				ctf_decl_sprintf(&cd, "%s", name);
				break;
			case CTF_K_STRUCT:
				ctf_decl_sprintf(&cd, "struct ");
				if (qname != NULL)
					ctf_decl_sprintf(&cd, "%s`", qname);
				ctf_decl_sprintf(&cd, "%s", name);
				break;
			case CTF_K_UNION:
				ctf_decl_sprintf(&cd, "union ");
				if (qname != NULL)
					ctf_decl_sprintf(&cd, "%s`", qname);
				ctf_decl_sprintf(&cd, "%s", name);
				break;
			case CTF_K_ENUM:
				ctf_decl_sprintf(&cd, "enum ");
				if (qname != NULL)
					ctf_decl_sprintf(&cd, "%s`", qname);
				ctf_decl_sprintf(&cd, "%s", name);
				break;
			case CTF_K_VOLATILE:
				ctf_decl_sprintf(&cd, "volatile");
				break;
			case CTF_K_CONST:
				ctf_decl_sprintf(&cd, "const");
				break;
			case CTF_K_RESTRICT:
				ctf_decl_sprintf(&cd, "restrict");
				break;
			}

			k = cdp->cd_kind;
		}

		if (rp == prec) {
			/*
			 * Peek ahead: if we're going to hit a function,
			 * we want to insert its name now before this closing
			 * bracket.
			 */
			if (vname != NULL && prec < CTF_PREC_FUNCTION) {
				cdp = ctf_list_next(
				    &cd.cd_nodes[CTF_PREC_FUNCTION]);

				if (cdp != NULL) {
					ctf_decl_sprintf(&cd, "%s", vname);
					vname = NULL;
				}
			}

			ctf_decl_sprintf(&cd, ")");
		}
	}

	if (vname != NULL)
		ctf_decl_sprintf(&cd, " %s", vname);

	if (cd.cd_len >= len)
		(void) ctf_set_errno(fp, ECTF_NAMELEN);

	ctf_decl_fini(&cd);
	return (cd.cd_len);
}

ssize_t
ctf_type_lname(ctf_file_t *fp, ctf_id_t type, char *buf, size_t len)
{
	return (ctf_type_qlname(fp, type, buf, len, NULL, NULL));
}

/*
 * Lookup the given type ID and print a string name for it into buf.  If buf
 * is too small, return NULL: the ECTF_NAMELEN error is set on 'fp' for us.
 */
char *
ctf_type_name(ctf_file_t *fp, ctf_id_t type, char *buf, size_t len)
{
	ssize_t rv = ctf_type_qlname(fp, type, buf, len, NULL, NULL);
	return (rv >= 0 && rv < len ? buf : NULL);
}

char *
ctf_type_qname(ctf_file_t *fp, ctf_id_t type, char *buf, size_t len,
    const char *qname)
{
	ssize_t rv = ctf_type_qlname(fp, type, buf, len, NULL, qname);
	return (rv >= 0 && rv < len ? buf : NULL);
}

char *
ctf_type_cname(ctf_file_t *fp, ctf_id_t type, char *buf, size_t len,
    const char *cname)
{
	ssize_t rv = ctf_type_qlname(fp, type, buf, len, cname, NULL);
	return (rv >= 0 && rv < len ? buf : NULL);
}

/*
 * Resolve the type down to a base type node, and then return the size
 * of the type storage in bytes.
 */
ssize_t
ctf_type_size(ctf_file_t *fp, ctf_id_t type)
{
	const ctf_type_t *tp;
	ssize_t size;
	ctf_arinfo_t ar;

	if ((type = ctf_type_resolve(fp, type)) == CTF_ERR)
		return (-1); /* errno is set for us */

	if ((tp = ctf_lookup_by_id(&fp, type)) == NULL)
		return (-1); /* errno is set for us */

	switch (LCTF_INFO_KIND(fp, tp->ctt_info)) {
	case CTF_K_POINTER:
		return (fp->ctf_dmodel->ctd_pointer);

	case CTF_K_FUNCTION:
		return (0); /* function size is only known by symtab */

	case CTF_K_FORWARD:
		return (0);

	case CTF_K_ENUM:
		return (ctf_get_ctt_size(fp, tp, NULL, NULL));

	case CTF_K_ARRAY:
		/*
		 * Array size is not directly returned by stabs data.  Instead,
		 * it defines the element type and requires the user to perform
		 * the multiplication.  If ctf_get_ctt_size() returns zero, the
		 * current version of ctfconvert does not compute member sizes
		 * and we compute the size here on its behalf.
		 */
		if ((size = ctf_get_ctt_size(fp, tp, NULL, NULL)) > 0)
			return (size);

		if (ctf_array_info(fp, type, &ar) == CTF_ERR ||
		    (size = ctf_type_size(fp, ar.ctr_contents)) == CTF_ERR)
			return (-1); /* errno is set for us */

		return (size * ar.ctr_nelems);
	case CTF_K_STRUCT:
	case CTF_K_UNION:
		/*
		 * If we have a zero size, we may be in the process of adding a
		 * structure or union but having not called ctf_update() to deal
		 * with the circular dependencies in such structures and unions.
		 * To handle that case, if we get a size of zero from the ctt,
		 * we look up the dtdef and use its size instead.
		 */
		size = ctf_get_ctt_size(fp, tp, NULL, NULL);
		if (size == 0) {
			ctf_dtdef_t *dtd = ctf_dtd_lookup(fp, type);
			if (dtd != NULL)
				return (dtd->dtd_data.ctt_size);
		}
		return (size);
	default:
		return (ctf_get_ctt_size(fp, tp, NULL, NULL));
	}
}

/*
 * Resolve the type down to a base type node, and then return the alignment
 * needed for the type storage in bytes.
 */
ssize_t
ctf_type_align(ctf_file_t *fp, ctf_id_t type)
{
	const ctf_type_t *tp;
	ctf_arinfo_t r;

	if ((type = ctf_type_resolve(fp, type)) == CTF_ERR)
		return (-1); /* errno is set for us */

	if ((tp = ctf_lookup_by_id(&fp, type)) == NULL)
		return (-1); /* errno is set for us */

	switch (LCTF_INFO_KIND(fp, tp->ctt_info)) {
	case CTF_K_POINTER:
	case CTF_K_FUNCTION:
		return (fp->ctf_dmodel->ctd_pointer);

	case CTF_K_ARRAY:
		if (ctf_array_info(fp, type, &r) == CTF_ERR)
			return (-1); /* errno is set for us */
		return (ctf_type_align(fp, r.ctr_contents));

	case CTF_K_STRUCT:
	case CTF_K_UNION: {
		uint_t n = LCTF_INFO_VLEN(fp, tp->ctt_info);
		ssize_t size, increment;
		size_t align = 0;
		const void *vmp;

		(void) ctf_get_ctt_size(fp, tp, &size, &increment);
		vmp = (uchar_t *)tp + increment;

		if (LCTF_INFO_KIND(fp, tp->ctt_info) == CTF_K_STRUCT)
			n = MIN(n, 1); /* only use first member for structs */

		if (fp->ctf_version == CTF_VERSION_1 ||
		    size < CTF_LSTRUCT_THRESH) {
			const ctf_member_t *mp = vmp;
			for (; n != 0; n--, mp++) {
				ssize_t am = ctf_type_align(fp, mp->ctm_type);
				align = MAX(align, am);
			}
		} else {
			const ctf_lmember_t *lmp = vmp;
			for (; n != 0; n--, lmp++) {
				ssize_t am = ctf_type_align(fp, lmp->ctlm_type);
				align = MAX(align, am);
			}
		}

		return (align);
	}

	case CTF_K_ENUM:
	default:
		return (ctf_get_ctt_size(fp, tp, NULL, NULL));
	}
}

/*
 * Return the kind (CTF_K_* constant) for the specified type ID.
 */
int
ctf_type_kind(ctf_file_t *fp, ctf_id_t type)
{
	const ctf_type_t *tp;

	if ((tp = ctf_lookup_by_id(&fp, type)) == NULL)
		return (CTF_ERR); /* errno is set for us */

	return (LCTF_INFO_KIND(fp, tp->ctt_info));
}

/*
 * If the type is one that directly references another type (such as POINTER),
 * then return the ID of the type to which it refers.
 */
ctf_id_t
ctf_type_reference(ctf_file_t *fp, ctf_id_t type)
{
	ctf_file_t *ofp = fp;
	const ctf_type_t *tp;

	if ((tp = ctf_lookup_by_id(&fp, type)) == NULL)
		return (CTF_ERR); /* errno is set for us */

	switch (LCTF_INFO_KIND(fp, tp->ctt_info)) {
	case CTF_K_POINTER:
	case CTF_K_TYPEDEF:
	case CTF_K_VOLATILE:
	case CTF_K_CONST:
	case CTF_K_RESTRICT:
		return (tp->ctt_type);
	default:
		return (ctf_set_errno(ofp, ECTF_NOTREF));
	}
}

/*
 * Find a pointer to type by looking in fp->ctf_ptrtab.  If we can't find a
 * pointer to the given type, see if we can compute a pointer to the type
 * resulting from resolving the type down to its base type and use that
 * instead.  This helps with cases where the CTF data includes "struct foo *"
 * but not "foo_t *" and the user accesses "foo_t *" in the debugger.
 */
ctf_id_t
ctf_type_pointer(ctf_file_t *fp, ctf_id_t type)
{
	ctf_file_t *ofp = fp;
	ctf_id_t ntype;

	if (ctf_lookup_by_id(&fp, type) == NULL)
		return (CTF_ERR); /* errno is set for us */

	if ((ntype = fp->ctf_ptrtab[CTF_TYPE_TO_INDEX(type)]) != 0)
		return (CTF_INDEX_TO_TYPE(ntype, (fp->ctf_flags & LCTF_CHILD)));

	if ((type = ctf_type_resolve(fp, type)) == CTF_ERR)
		return (ctf_set_errno(ofp, ECTF_NOTYPE));

	if (ctf_lookup_by_id(&fp, type) == NULL)
		return (ctf_set_errno(ofp, ECTF_NOTYPE));

	if ((ntype = fp->ctf_ptrtab[CTF_TYPE_TO_INDEX(type)]) != 0)
		return (CTF_INDEX_TO_TYPE(ntype, (fp->ctf_flags & LCTF_CHILD)));

	return (ctf_set_errno(ofp, ECTF_NOTYPE));
}

/*
 * Return the encoding for the specified INTEGER or FLOAT.
 */
int
ctf_type_encoding(ctf_file_t *fp, ctf_id_t type, ctf_encoding_t *ep)
{
	ctf_file_t *ofp = fp;
	const ctf_type_t *tp;
	ssize_t increment;
	uint_t data;

	if ((tp = ctf_lookup_by_id(&fp, type)) == NULL)
		return (CTF_ERR); /* errno is set for us */

	(void) ctf_get_ctt_size(fp, tp, NULL, &increment);

	switch (LCTF_INFO_KIND(fp, tp->ctt_info)) {
	case CTF_K_INTEGER:
		data = *(const uint_t *)((uintptr_t)tp + increment);
		ep->cte_format = CTF_INT_ENCODING(data);
		ep->cte_offset = CTF_INT_OFFSET(data);
		ep->cte_bits = CTF_INT_BITS(data);
		break;
	case CTF_K_FLOAT:
		data = *(const uint_t *)((uintptr_t)tp + increment);
		ep->cte_format = CTF_FP_ENCODING(data);
		ep->cte_offset = CTF_FP_OFFSET(data);
		ep->cte_bits = CTF_FP_BITS(data);
		break;
	default:
		return (ctf_set_errno(ofp, ECTF_NOTINTFP));
	}

	return (0);
}

int
ctf_type_cmp(ctf_file_t *lfp, ctf_id_t ltype, ctf_file_t *rfp, ctf_id_t rtype)
{
	int rval;

	if (ltype < rtype)
		rval = -1;
	else if (ltype > rtype)
		rval = 1;
	else
		rval = 0;

	if (lfp == rfp)
		return (rval);

	if (CTF_TYPE_ISPARENT(ltype) && lfp->ctf_parent != NULL)
		lfp = lfp->ctf_parent;

	if (CTF_TYPE_ISPARENT(rtype) && rfp->ctf_parent != NULL)
		rfp = rfp->ctf_parent;

	if (lfp < rfp)
		return (-1);

	if (lfp > rfp)
		return (1);

	return (rval);
}

/*
 * Return a boolean value indicating if two types are compatible integers or
 * floating-pointer values.  This function returns true if the two types are
 * the same, or if they have the same ASCII name and encoding properties.
 * This function could be extended to test for compatibility for other kinds.
 */
int
ctf_type_compat(ctf_file_t *lfp, ctf_id_t ltype,
    ctf_file_t *rfp, ctf_id_t rtype)
{
	const ctf_type_t *ltp, *rtp;
	ctf_encoding_t le, re;
	ctf_arinfo_t la, ra;
	uint_t lkind, rkind;

	if (ctf_type_cmp(lfp, ltype, rfp, rtype) == 0)
		return (1);

	ltype = ctf_type_resolve(lfp, ltype);
	lkind = ctf_type_kind(lfp, ltype);

	rtype = ctf_type_resolve(rfp, rtype);
	rkind = ctf_type_kind(rfp, rtype);

	if (lkind != rkind ||
	    (ltp = ctf_lookup_by_id(&lfp, ltype)) == NULL ||
	    (rtp = ctf_lookup_by_id(&rfp, rtype)) == NULL ||
	    strcmp(ctf_strptr(lfp, ltp->ctt_name),
	    ctf_strptr(rfp, rtp->ctt_name)) != 0)
		return (0);

	switch (lkind) {
	case CTF_K_INTEGER:
	case CTF_K_FLOAT:
		return (ctf_type_encoding(lfp, ltype, &le) == 0 &&
		    ctf_type_encoding(rfp, rtype, &re) == 0 &&
		    bcmp(&le, &re, sizeof (ctf_encoding_t)) == 0);
	case CTF_K_POINTER:
		return (ctf_type_compat(lfp, ctf_type_reference(lfp, ltype),
		    rfp, ctf_type_reference(rfp, rtype)));
	case CTF_K_ARRAY:
		return (ctf_array_info(lfp, ltype, &la) == 0 &&
		    ctf_array_info(rfp, rtype, &ra) == 0 &&
		    la.ctr_nelems == ra.ctr_nelems && ctf_type_compat(
		    lfp, la.ctr_contents, rfp, ra.ctr_contents) &&
		    ctf_type_compat(lfp, la.ctr_index, rfp, ra.ctr_index));
	case CTF_K_STRUCT:
	case CTF_K_UNION:
		return (ctf_type_size(lfp, ltype) == ctf_type_size(rfp, rtype));
	case CTF_K_ENUM:
	case CTF_K_FORWARD:
		return (1); /* no other checks required for these type kinds */
	default:
		return (0); /* should not get here since we did a resolve */
	}
}

typedef struct {
	ctf_file_t *cms_fp;
	const ctf_type_t *cms_tp;
	ulong_t cms_curoff;
} ctf_member_stack_t;

/*
 * Determine whether or not we should push this frame on. If we're at our depth,
 * then that's it. In particular for us to look at this we need to:
 *
 * 1) Have no name.
 * 2) Be a struct or union (implicitly that means we can look this up).
 * 3) Not exceed our internal depth.
 */
static void
ctf_member_info_push(ctf_member_stack_t *stack, size_t *depthp, size_t max,
    const ctf_member_stack_t *cur, ushort_t mtype, const char *mname,
    ulong_t moff)
{
	uint_t kind;
	ctf_member_stack_t *cms;

	if (*depthp == max)
		return;

	if (*mname != '\0')
		return;

	cms = &stack[*depthp];
	cms->cms_fp = cur->cms_fp;
	cms->cms_tp = ctf_lookup_by_id(&cms->cms_fp, mtype);
	if (cms->cms_tp == NULL)
		return;
	kind = LCTF_INFO_KIND(cms->cms_fp, cms->cms_tp->ctt_info);
	if (kind != CTF_K_STRUCT && kind != CTF_K_UNION)
		return;
	cms->cms_curoff = cur->cms_curoff + moff;
	*depthp = *depthp + 1;
}

/*
 * Return the type and offset for a given member of a STRUCT or UNION. C11
 * officially added anonymous structs and unions. These are members whose name
 * is the empty string. When looking for a member, we will search anonymous
 * structures and unions it. This can nest to an arbitrary depth; however, we
 * use a fixed bound to limit our overall stack usage. This will cause us to go
 * through and visit all of our current members before considering any anonymous
 * entries. Note, this is okay because there are no duplicate member names
 * allowed.
 */
int
ctf_member_info(ctf_file_t *ifp, ctf_id_t type, const char *name,
    ctf_membinfo_t *mip)
{
	uint_t kind;
	ctf_member_stack_t stack[128];
	size_t depth = 0;

	/*
	 * We only ever resolve the top-level type while searching.
	 */
	if ((type = ctf_type_resolve(ifp, type)) == CTF_ERR)
		return (CTF_ERR); /* errno is set for us */

	stack[depth].cms_fp = ifp;
	stack[depth].cms_curoff = 0;
	stack[depth].cms_tp = ctf_lookup_by_id(&stack[depth].cms_fp, type);
	if (stack[depth].cms_tp == NULL)
		return (CTF_ERR); /* errno is set for us */

	kind = LCTF_INFO_KIND(stack[depth].cms_fp,
	    stack[depth].cms_tp->ctt_info);

	if (kind != CTF_K_STRUCT && kind != CTF_K_UNION)
		return (ctf_set_errno(ifp, ECTF_NOTSOU));

	depth++;
	while (depth != 0) {
		ssize_t size, increment;
		ctf_member_stack_t cms;

		depth--;
		cms = stack[depth];

		(void) ctf_get_ctt_size(cms.cms_fp, cms.cms_tp, &size,
		    &increment);

		if (cms.cms_fp->ctf_version == CTF_VERSION_1 ||
		    size < CTF_LSTRUCT_THRESH) {
			const ctf_member_t *mp = (const ctf_member_t *)
			    ((uintptr_t)cms.cms_tp + increment);

			for (uint_t n = LCTF_INFO_VLEN(cms.cms_fp,
			    cms.cms_tp->ctt_info); n != 0; n--, mp++) {
				const char *mname = ctf_strptr(cms.cms_fp,
				    mp->ctm_name);

				if (strcmp(mname, name) == 0) {
					mip->ctm_type = mp->ctm_type;
					mip->ctm_offset = mp->ctm_offset +
					    cms.cms_curoff;
					return (0);
				}

				ctf_member_info_push(stack, &depth,
				    ARRAY_SIZE(stack), &cms, mp->ctm_type,
				    mname, mp->ctm_offset);
			}
		} else {
			const ctf_lmember_t *lmp = (const ctf_lmember_t *)
			    ((uintptr_t)cms.cms_tp + increment);

			for (uint_t n = LCTF_INFO_VLEN(cms.cms_fp,
			    cms.cms_tp->ctt_info); n != 0; n--, lmp++) {
				const char *mname = ctf_strptr(cms.cms_fp,
				    lmp->ctlm_name);
				ulong_t off = (ulong_t)CTF_LMEM_OFFSET(lmp);
				if (strcmp(mname, name) == 0) {
					mip->ctm_type = lmp->ctlm_type;
					mip->ctm_offset = cms.cms_curoff + off;
					return (0);
				}

				ctf_member_info_push(stack, &depth,
				    ARRAY_SIZE(stack), &cms, lmp->ctlm_type,
				    mname, off);
			}
		}

	}

	return (ctf_set_errno(ifp, ECTF_NOMEMBNAM));
}

/*
 * Return the array type, index, and size information for the specified ARRAY.
 */
int
ctf_array_info(ctf_file_t *fp, ctf_id_t type, ctf_arinfo_t *arp)
{
	ctf_file_t *ofp = fp;
	const ctf_type_t *tp;
	const ctf_array_t *ap;
	ssize_t increment;

	if ((tp = ctf_lookup_by_id(&fp, type)) == NULL)
		return (CTF_ERR); /* errno is set for us */

	if (LCTF_INFO_KIND(fp, tp->ctt_info) != CTF_K_ARRAY)
		return (ctf_set_errno(ofp, ECTF_NOTARRAY));

	(void) ctf_get_ctt_size(fp, tp, NULL, &increment);

	ap = (const ctf_array_t *)((uintptr_t)tp + increment);
	arp->ctr_contents = ap->cta_contents;
	arp->ctr_index = ap->cta_index;
	arp->ctr_nelems = ap->cta_nelems;

	return (0);
}

/*
 * Convert the specified value to the corresponding enum member name, if a
 * matching name can be found.  Otherwise NULL is returned.
 */
const char *
ctf_enum_name(ctf_file_t *fp, ctf_id_t type, int value)
{
	ctf_file_t *ofp = fp;
	const ctf_type_t *tp;
	const ctf_enum_t *ep;
	ssize_t increment;
	uint_t n;

	if ((type = ctf_type_resolve(fp, type)) == CTF_ERR)
		return (NULL); /* errno is set for us */

	if ((tp = ctf_lookup_by_id(&fp, type)) == NULL)
		return (NULL); /* errno is set for us */

	if (LCTF_INFO_KIND(fp, tp->ctt_info) != CTF_K_ENUM) {
		(void) ctf_set_errno(ofp, ECTF_NOTENUM);
		return (NULL);
	}

	(void) ctf_get_ctt_size(fp, tp, NULL, &increment);

	ep = (const ctf_enum_t *)((uintptr_t)tp + increment);

	for (n = LCTF_INFO_VLEN(fp, tp->ctt_info); n != 0; n--, ep++) {
		if (ep->cte_value == value)
			return (ctf_strptr(fp, ep->cte_name));
	}

	(void) ctf_set_errno(ofp, ECTF_NOENUMNAM);
	return (NULL);
}

/*
 * Convert the specified enum tag name to the corresponding value, if a
 * matching name can be found.  Otherwise CTF_ERR is returned.
 */
int
ctf_enum_value(ctf_file_t *fp, ctf_id_t type, const char *name, int *valp)
{
	ctf_file_t *ofp = fp;
	const ctf_type_t *tp;
	const ctf_enum_t *ep;
	ssize_t size, increment;
	uint_t n;

	if ((type = ctf_type_resolve(fp, type)) == CTF_ERR)
		return (CTF_ERR); /* errno is set for us */

	if ((tp = ctf_lookup_by_id(&fp, type)) == NULL)
		return (CTF_ERR); /* errno is set for us */

	if (LCTF_INFO_KIND(fp, tp->ctt_info) != CTF_K_ENUM) {
		(void) ctf_set_errno(ofp, ECTF_NOTENUM);
		return (CTF_ERR);
	}

	(void) ctf_get_ctt_size(fp, tp, &size, &increment);

	ep = (const ctf_enum_t *)((uintptr_t)tp + increment);

	for (n = LCTF_INFO_VLEN(fp, tp->ctt_info); n != 0; n--, ep++) {
		if (strcmp(ctf_strptr(fp, ep->cte_name), name) == 0) {
			if (valp != NULL)
				*valp = ep->cte_value;
			return (0);
		}
	}

	(void) ctf_set_errno(ofp, ECTF_NOENUMNAM);
	return (CTF_ERR);
}

/*
 * Recursively visit the members of any type.  This function is used as the
 * engine for ctf_type_visit, below.  We resolve the input type, recursively
 * invoke ourself for each type member if the type is a struct or union, and
 * then invoke the callback function on the current type.  If any callback
 * returns non-zero, we abort and percolate the error code back up to the top.
 */
static int
ctf_type_rvisit(ctf_file_t *fp, ctf_id_t type, ctf_visit_f *func, void *arg,
    const char *name, ulong_t offset, int depth)
{
	ctf_id_t otype = type;
	const ctf_type_t *tp;
	ssize_t size, increment;
	uint_t kind, n;
	int rc;

	if ((type = ctf_type_resolve(fp, type)) == CTF_ERR)
		return (CTF_ERR); /* errno is set for us */

	if ((tp = ctf_lookup_by_id(&fp, type)) == NULL)
		return (CTF_ERR); /* errno is set for us */

	if ((rc = func(name, otype, offset, depth, arg)) != 0)
		return (rc);

	kind = LCTF_INFO_KIND(fp, tp->ctt_info);

	if (kind != CTF_K_STRUCT && kind != CTF_K_UNION)
		return (0);

	(void) ctf_get_ctt_size(fp, tp, &size, &increment);

	if (fp->ctf_version == CTF_VERSION_1 || size < CTF_LSTRUCT_THRESH) {
		const ctf_member_t *mp = (const ctf_member_t *)
		    ((uintptr_t)tp + increment);

		for (n = LCTF_INFO_VLEN(fp, tp->ctt_info); n != 0; n--, mp++) {
			if ((rc = ctf_type_rvisit(fp, mp->ctm_type,
			    func, arg, ctf_strptr(fp, mp->ctm_name),
			    offset + mp->ctm_offset, depth + 1)) != 0)
				return (rc);
		}

	} else {
		const ctf_lmember_t *lmp = (const ctf_lmember_t *)
		    ((uintptr_t)tp + increment);

		for (n = LCTF_INFO_VLEN(fp, tp->ctt_info); n != 0; n--, lmp++) {
			if ((rc = ctf_type_rvisit(fp, lmp->ctlm_type,
			    func, arg, ctf_strptr(fp, lmp->ctlm_name),
			    offset + (ulong_t)CTF_LMEM_OFFSET(lmp),
			    depth + 1)) != 0)
				return (rc);
		}
	}

	return (0);
}

/*
 * Recursively visit the members of any type.  We pass the name, member
 * type, and offset of each member to the specified callback function.
 */
int
ctf_type_visit(ctf_file_t *fp, ctf_id_t type, ctf_visit_f *func, void *arg)
{
	return (ctf_type_rvisit(fp, type, func, arg, "", 0, 0));
}

int
ctf_func_info_by_id(ctf_file_t *fp, ctf_id_t type, ctf_funcinfo_t *fip)
{
	ctf_file_t *ofp = fp;
	const ctf_type_t *tp;
	const ushort_t *dp;
	int nargs;
	ssize_t increment;

	if ((tp = ctf_lookup_by_id(&fp, type)) == NULL)
		return (CTF_ERR); /* errno is set for us */

	if (LCTF_INFO_KIND(fp, tp->ctt_info) != CTF_K_FUNCTION)
		return (ctf_set_errno(ofp, ECTF_NOTFUNC));

	fip->ctc_return = tp->ctt_type;
	nargs = LCTF_INFO_VLEN(fp, tp->ctt_info);
	fip->ctc_argc = nargs;
	fip->ctc_flags = 0;

	/* dp should now point to the first argument */
	if (nargs != 0) {
		(void) ctf_get_ctt_size(fp, tp, NULL, &increment);
		dp = (ushort_t *)((uintptr_t)fp->ctf_buf +
		    fp->ctf_txlate[CTF_TYPE_TO_INDEX(type)] + increment);
		if (dp[nargs - 1] == 0) {
			fip->ctc_flags |= CTF_FUNC_VARARG;
			fip->ctc_argc--;
		}
	}

	return (0);
}

int
ctf_func_args_by_id(ctf_file_t *fp, ctf_id_t type, uint_t argc, ctf_id_t *argv)
{
	ctf_file_t *ofp = fp;
	const ctf_type_t *tp;
	const ushort_t *dp;
	int nargs;
	ssize_t increment;

	if ((tp = ctf_lookup_by_id(&fp, type)) == NULL)
		return (CTF_ERR); /* errno is set for us */

	if (LCTF_INFO_KIND(fp, tp->ctt_info) != CTF_K_FUNCTION)
		return (ctf_set_errno(ofp, ECTF_NOTFUNC));

	nargs = LCTF_INFO_VLEN(fp, tp->ctt_info);
	(void) ctf_get_ctt_size(fp, tp, NULL, &increment);
	dp = (ushort_t *)((uintptr_t)fp->ctf_buf +
	    fp->ctf_txlate[CTF_TYPE_TO_INDEX(type)] +
	    increment);
	if (nargs != 0 && dp[nargs - 1] == 0)
		nargs--;

	for (nargs = MIN(argc, nargs); nargs != 0; nargs--)
		*argv++ = *dp++;

	return (0);
}

int
ctf_object_iter(ctf_file_t *fp, ctf_object_f *func, void *arg)
{
	int i, ret;
	ctf_id_t id;
	uintptr_t symbase = (uintptr_t)fp->ctf_symtab.cts_data;
	uintptr_t strbase = (uintptr_t)fp->ctf_strtab.cts_data;

	if (fp->ctf_symtab.cts_data == NULL)
		return (ctf_set_errno(fp, ECTF_NOSYMTAB));

	for (i = 0; i < fp->ctf_nsyms; i++) {
		char *name;
		if (fp->ctf_sxlate[i] == -1u)
			continue;
		id = *(ushort_t *)((uintptr_t)fp->ctf_buf +
		    fp->ctf_sxlate[i]);

		/*
		 * Validate whether or not we're looking at a data object as
		 * oposed to a function.
		 */
		if (fp->ctf_symtab.cts_entsize == sizeof (Elf32_Sym)) {
			const Elf32_Sym *symp = (Elf32_Sym *)symbase + i;
			if (ELF32_ST_TYPE(symp->st_info) != STT_OBJECT)
				continue;
			if (fp->ctf_strtab.cts_data != NULL &&
			    symp->st_name != 0)
				name = (char *)(strbase + symp->st_name);
			else
				name = NULL;
		} else {
			const Elf64_Sym *symp = (Elf64_Sym *)symbase + i;
			if (ELF64_ST_TYPE(symp->st_info) != STT_OBJECT)
				continue;
			if (fp->ctf_strtab.cts_data != NULL &&
			    symp->st_name != 0)
				name = (char *)(strbase + symp->st_name);
			else
				name = NULL;
		}

		if ((ret = func(name, id, i, arg)) != 0)
			return (ret);
	}

	return (0);
}

int
ctf_function_iter(ctf_file_t *fp, ctf_function_f *func, void *arg)
{
	int i, ret;
	uintptr_t symbase = (uintptr_t)fp->ctf_symtab.cts_data;
	uintptr_t strbase = (uintptr_t)fp->ctf_strtab.cts_data;

	if (fp->ctf_symtab.cts_data == NULL)
		return (ctf_set_errno(fp, ECTF_NOSYMTAB));

	for (i = 0; i < fp->ctf_nsyms; i++) {
		char *name;
		ushort_t info, *dp;
		ctf_funcinfo_t fi;
		if (fp->ctf_sxlate[i] == -1u)
			continue;

		dp = (ushort_t *)((uintptr_t)fp->ctf_buf +
		    fp->ctf_sxlate[i]);
		info = *dp;
		if (info == 0)
			continue;

		/*
		 * This may be a function or it may be a data object. We have to
		 * consult the symbol table to be certain. Functions are encoded
		 * with their info, data objects with their actual type.
		 */
		if (fp->ctf_symtab.cts_entsize == sizeof (Elf32_Sym)) {
			const Elf32_Sym *symp = (Elf32_Sym *)symbase + i;
			if (ELF32_ST_TYPE(symp->st_info) != STT_FUNC)
				continue;
			if (fp->ctf_strtab.cts_data != NULL)
				name = (char *)(strbase + symp->st_name);
			else
				name = NULL;
		} else {
			const Elf64_Sym *symp = (Elf64_Sym *)symbase + i;
			if (ELF64_ST_TYPE(symp->st_info) != STT_FUNC)
				continue;
			if (fp->ctf_strtab.cts_data != NULL)
				name = (char *)(strbase + symp->st_name);
			else
				name = NULL;
		}

		if (LCTF_INFO_KIND(fp, info) != CTF_K_FUNCTION)
			continue;
		dp++;
		fi.ctc_return = *dp;
		dp++;
		fi.ctc_argc = LCTF_INFO_VLEN(fp, info);
		fi.ctc_flags = 0;

		if (fi.ctc_argc != 0 && dp[fi.ctc_argc - 1] == 0) {
			fi.ctc_flags |= CTF_FUNC_VARARG;
			fi.ctc_argc--;
		}

		if ((ret = func(name, i, &fi, arg)) != 0)
			return (ret);

	}

	return (0);
}

char *
ctf_symbol_name(ctf_file_t *fp, ulong_t idx, char *buf, size_t len)
{
	const char *name;
	uintptr_t symbase = (uintptr_t)fp->ctf_symtab.cts_data;
	uintptr_t strbase = (uintptr_t)fp->ctf_strtab.cts_data;

	if (fp->ctf_symtab.cts_data == NULL) {
		(void) ctf_set_errno(fp, ECTF_NOSYMTAB);
		return (NULL);
	}

	if (fp->ctf_strtab.cts_data == NULL) {
		(void) ctf_set_errno(fp, ECTF_STRTAB);
		return (NULL);
	}

	if (idx > fp->ctf_nsyms) {
		(void) ctf_set_errno(fp, ECTF_NOTDATA);
		return (NULL);
	}

	if (fp->ctf_symtab.cts_entsize == sizeof (Elf32_Sym)) {
		const Elf32_Sym *symp = (Elf32_Sym *)symbase + idx;
		if (ELF32_ST_TYPE(symp->st_info) != STT_OBJECT &&
		    ELF32_ST_TYPE(symp->st_info) != STT_FUNC) {
			(void) ctf_set_errno(fp, ECTF_NOTDATA);
			return (NULL);
		}
		if (symp->st_name == 0) {
			(void) ctf_set_errno(fp, ENOENT);
			return (NULL);
		}
		name = (const char *)(strbase + symp->st_name);
	} else {
		const Elf64_Sym *symp = (Elf64_Sym *)symbase + idx;
		if (ELF64_ST_TYPE(symp->st_info) != STT_FUNC &&
		    ELF64_ST_TYPE(symp->st_info) != STT_OBJECT) {
			(void) ctf_set_errno(fp, ECTF_NOTDATA);
			return (NULL);
		}
		if (symp->st_name == 0) {
			(void) ctf_set_errno(fp, ENOENT);
			return (NULL);
		}
		name = (const char *)(strbase + symp->st_name);
	}

	(void) strlcpy(buf, name, len);

	return (buf);
}

int
ctf_string_iter(ctf_file_t *fp, ctf_string_f *func, void *arg)
{
	int rc;
	const char *strp = fp->ctf_str[CTF_STRTAB_0].cts_strs;
	size_t strl = fp->ctf_str[CTF_STRTAB_0].cts_len;

	while (strl > 0) {
		size_t len;

		if ((rc = func(strp, arg)) != 0)
			return (rc);

		len = strlen(strp) + 1;
		strl -= len;
		strp += len;
	}

	return (0);
}

/*
 * fp isn't strictly necessary at the moment. However, if we ever rev the file
 * format, the valid values for kind will change.
 */
const char *
ctf_kind_name(ctf_file_t *fp, int kind)
{
	switch (kind) {
	case CTF_K_INTEGER:
		return ("integer");
	case CTF_K_FLOAT:
		return ("float");
	case CTF_K_POINTER:
		return ("pointer");
	case CTF_K_ARRAY:
		return ("array");
	case CTF_K_FUNCTION:
		return ("function");
	case CTF_K_STRUCT:
		return ("struct");
	case CTF_K_UNION:
		return ("union");
	case CTF_K_ENUM:
		return ("enum");
	case CTF_K_FORWARD:
		return ("forward");
	case CTF_K_TYPEDEF:
		return ("typedef");
	case CTF_K_VOLATILE:
		return ("volatile");
	case CTF_K_CONST:
		return ("const");
	case CTF_K_RESTRICT:
		return ("restrict");
	case CTF_K_UNKNOWN:
	default:
		return ("unknown");
	}
}

ctf_id_t
ctf_max_id(ctf_file_t *fp)
{
	int child = (fp->ctf_flags & LCTF_CHILD);
	return (fp->ctf_typemax + (child ? CTF_CHILD_START : 0));
}

ulong_t
ctf_nr_syms(ctf_file_t *fp)
{
	return (fp->ctf_nsyms);
}
