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
 * Copyright (c) 2015 Joyent, Inc.
 */

/*
 * To perform a merge of two CTF containers, we first diff the two containers
 * types. For every type that's in the src container, but not in the dst
 * container, we note it and add it to dst container. If there are any objects
 * or functions associated with src, we go through and update the types that
 * they refer to such that they all refer to types in the dst container.
 *
 * The bulk of the logic for the merge, after we've run the diff, occurs in
 * ctf_merge_common().
 *
 * In terms of exported APIs, we don't really export a simple merge two
 * containers, as the general way this is used, in something like ctfmerge(1),
 * is to add all the containers and then let us figure out the best way to merge
 * it.
 */

#include <libctf_impl.h>
#include <sys/debug.h>
#include <sys/list.h>
#include <stddef.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <mergeq.h>
#include <errno.h>

typedef struct ctf_merge_tinfo {
	uint16_t cmt_map;	/* Map to the type in out */
	boolean_t cmt_fixup;
	boolean_t cmt_forward;
	boolean_t cmt_missing;
} ctf_merge_tinfo_t;

/*
 * State required for doing an individual merge of two containers.
 */
typedef struct ctf_merge_types {
	ctf_file_t *cm_out;		/* Output CTF file */
	ctf_file_t *cm_src;		/* Input CTF file */
	ctf_merge_tinfo_t *cm_tmap;	/* Type state information */
	boolean_t cm_dedup;		/* Are we doing a dedup? */
	boolean_t cm_unique;		/* are we doing a uniquify? */
} ctf_merge_types_t;

typedef struct ctf_merge_objmap {
	list_node_t cmo_node;
	const char *cmo_name;		/* Symbol name */
	ulong_t cmo_idx;		/* Symbol ID */
	ctf_id_t cmo_tid;		/* Type ID */
} ctf_merge_objmap_t;

typedef struct ctf_merge_funcmap {
	list_node_t cmf_node;
	const char *cmf_name;		/* Symbol name */
	ulong_t cmf_idx;		/* Symbol ID */
	ctf_id_t cmf_rtid;		/* Type ID */
	uint_t cmf_flags;		/* ctf_funcinfo_t ctc_flags */
	uint_t cmf_argc;		/* Number of arguments */
	ctf_id_t cmf_args[];		/* Types of arguments */
} ctf_merge_funcmap_t;

typedef struct ctf_merge_input {
	list_node_t cmi_node;
	ctf_file_t *cmi_input;
	list_t cmi_omap;
	list_t cmi_fmap;
	boolean_t cmi_created;
} ctf_merge_input_t;

struct ctf_merge_handle {
	list_t cmh_inputs;		/* Input list */
	uint_t cmh_ninputs;		/* Number of inputs */
	uint_t cmh_nthreads;		/* Number of threads to use */
	ctf_file_t *cmh_unique;		/* ctf to uniquify against */
	boolean_t cmh_msyms;		/* Should we merge symbols/funcs? */
	int cmh_ofd;			/* FD for output file */
	int cmh_flags;			/* Flags that control merge behavior */
	char *cmh_label;		/* Optional label */
	char *cmh_pname;		/* Parent name */
};

static int ctf_merge_add_type(ctf_merge_types_t *, ctf_id_t);

static ctf_id_t
ctf_merge_gettype(ctf_merge_types_t *cmp, ctf_id_t id)
{
	if (cmp->cm_dedup == B_FALSE) {
		VERIFY(cmp->cm_tmap[id].cmt_map != 0);
		return (cmp->cm_tmap[id].cmt_map);
	}

	while (cmp->cm_tmap[id].cmt_missing == B_FALSE) {
		VERIFY(cmp->cm_tmap[id].cmt_map != 0);
		id = cmp->cm_tmap[id].cmt_map;
	}
	VERIFY(cmp->cm_tmap[id].cmt_map != 0);
	return (cmp->cm_tmap[id].cmt_map);
}

static void
ctf_merge_diffcb(ctf_file_t *ifp, ctf_id_t iid, boolean_t same, ctf_file_t *ofp,
    ctf_id_t oid, void *arg)
{
	ctf_merge_types_t *cmp = arg;
	ctf_merge_tinfo_t *cmt = cmp->cm_tmap;

	if (same == B_TRUE) {
		if (ctf_type_kind(ifp, iid) == CTF_K_FORWARD &&
		    ctf_type_kind(ofp, oid) != CTF_K_FORWARD) {
			VERIFY(cmt[oid].cmt_map == 0);

			/*
			 * If we're uniquifying types, it's possible for the
			 * container that we're uniquifying against to have a
			 * forward which exists in the container being reduced.
			 * For example, genunix has the machcpu structure as a
			 * forward which is actually in unix and we uniquify
			 * unix against genunix. In such cases, we explicitly do
			 * not do any mapping of the forward information, lest
			 * we risk losing the real definition. Instead, mark
			 * that it's missing.
			 */
			if (cmp->cm_unique == B_TRUE) {
				cmt[oid].cmt_missing = B_TRUE;
				return;
			}

			cmt[oid].cmt_map = iid;
			cmt[oid].cmt_forward = B_TRUE;
			ctf_dprintf("merge diff forward mapped %d->%d\n", oid,
			    iid);
			return;
		}

		/*
		 * We could have multiple things that a given type ends up
		 * matching in the world of forwards and pointers to forwards.
		 * For now just take the first one...
		 */
		if (cmt[oid].cmt_map != 0)
			return;
		cmt[oid].cmt_map = iid;
		ctf_dprintf("merge diff mapped %d->%d\n", oid, iid);
	} else if (ifp == cmp->cm_src) {
		VERIFY(cmt[iid].cmt_map == 0);
		cmt[iid].cmt_missing = B_TRUE;
		ctf_dprintf("merge diff said %d is missing\n", iid);
	}
}

static int
ctf_merge_add_number(ctf_merge_types_t *cmp, ctf_id_t id)
{
	int ret, flags;
	const ctf_type_t *tp;
	const char *name;
	ctf_encoding_t en;

	if (ctf_type_encoding(cmp->cm_src, id, &en) != 0)
		return (CTF_ERR);

	tp = LCTF_INDEX_TO_TYPEPTR(cmp->cm_src, id);
	name = ctf_strraw(cmp->cm_src, tp->ctt_name);
	if (CTF_INFO_ISROOT(tp->ctt_info) != 0)
		flags = CTF_ADD_ROOT;
	else
		flags = CTF_ADD_NONROOT;

	ret = ctf_add_encoded(cmp->cm_out, flags, name, &en,
	    ctf_type_kind(cmp->cm_src, id));

	if (ret == CTF_ERR)
		return (ret);

	VERIFY(cmp->cm_tmap[id].cmt_map == 0);
	cmp->cm_tmap[id].cmt_map = ret;
	return (0);
}

static int
ctf_merge_add_array(ctf_merge_types_t *cmp, ctf_id_t id)
{
	int ret, flags;
	const ctf_type_t *tp;
	ctf_arinfo_t ar;

	if (ctf_array_info(cmp->cm_src, id, &ar) == CTF_ERR)
		return (CTF_ERR);

	tp = LCTF_INDEX_TO_TYPEPTR(cmp->cm_src, id);
	if (CTF_INFO_ISROOT(tp->ctt_info) != 0)
		flags = CTF_ADD_ROOT;
	else
		flags = CTF_ADD_NONROOT;

	if (cmp->cm_tmap[ar.ctr_contents].cmt_map == 0) {
		ret = ctf_merge_add_type(cmp, ar.ctr_contents);
		if (ret != 0)
			return (ret);
		ASSERT(cmp->cm_tmap[ar.ctr_contents].cmt_map != 0);
	}
	ar.ctr_contents = ctf_merge_gettype(cmp, ar.ctr_contents);

	if (cmp->cm_tmap[ar.ctr_index].cmt_map == 0) {
		ret = ctf_merge_add_type(cmp, ar.ctr_index);
		if (ret != 0)
			return (ret);
		ASSERT(cmp->cm_tmap[ar.ctr_index].cmt_map != 0);
	}
	ar.ctr_index = ctf_merge_gettype(cmp, ar.ctr_index);

	ret = ctf_add_array(cmp->cm_out, flags, &ar);
	if (ret == CTF_ERR)
		return (ret);

	VERIFY(cmp->cm_tmap[id].cmt_map == 0);
	cmp->cm_tmap[id].cmt_map = ret;

	return (0);
}

static int
ctf_merge_add_reftype(ctf_merge_types_t *cmp, ctf_id_t id)
{
	int ret, flags;
	const ctf_type_t *tp;
	ctf_id_t reftype;
	const char *name;

	tp = LCTF_INDEX_TO_TYPEPTR(cmp->cm_src, id);
	name = ctf_strraw(cmp->cm_src, tp->ctt_name);
	if (CTF_INFO_ISROOT(tp->ctt_info) != 0)
		flags = CTF_ADD_ROOT;
	else
		flags = CTF_ADD_NONROOT;

	reftype = ctf_type_reference(cmp->cm_src, id);
	if (reftype == CTF_ERR)
		return (ctf_set_errno(cmp->cm_out, ctf_errno(cmp->cm_src)));

	if (cmp->cm_tmap[reftype].cmt_map == 0) {
		ret = ctf_merge_add_type(cmp, reftype);
		if (ret != 0)
			return (ret);
		ASSERT(cmp->cm_tmap[reftype].cmt_map != 0);
	}
	reftype = ctf_merge_gettype(cmp, reftype);

	ret = ctf_add_reftype(cmp->cm_out, flags, name, reftype,
	    ctf_type_kind(cmp->cm_src, id));
	if (ret == CTF_ERR)
		return (ret);

	VERIFY(cmp->cm_tmap[id].cmt_map == 0);
	cmp->cm_tmap[id].cmt_map = ret;
	return (0);
}

static int
ctf_merge_add_typedef(ctf_merge_types_t *cmp, ctf_id_t id)
{
	int ret, flags;
	const ctf_type_t *tp;
	const char *name;
	ctf_id_t reftype;

	tp = LCTF_INDEX_TO_TYPEPTR(cmp->cm_src, id);
	name = ctf_strraw(cmp->cm_src, tp->ctt_name);
	if (CTF_INFO_ISROOT(tp->ctt_info) != 0)
		flags = CTF_ADD_ROOT;
	else
		flags = CTF_ADD_NONROOT;

	reftype = ctf_type_reference(cmp->cm_src, id);
	if (reftype == CTF_ERR)
		return (ctf_set_errno(cmp->cm_out, ctf_errno(cmp->cm_src)));

	if (cmp->cm_tmap[reftype].cmt_map == 0) {
		ret = ctf_merge_add_type(cmp, reftype);
		if (ret != 0)
			return (ret);
		ASSERT(cmp->cm_tmap[reftype].cmt_map != 0);
	}
	reftype = ctf_merge_gettype(cmp, reftype);

	ret = ctf_add_typedef(cmp->cm_out, flags, name, reftype);
	if (ret == CTF_ERR)
		return (ret);

	VERIFY(cmp->cm_tmap[id].cmt_map == 0);
	cmp->cm_tmap[id].cmt_map = ret;
	return (0);
}

typedef struct ctf_merge_enum {
	ctf_file_t *cme_fp;
	ctf_id_t cme_id;
} ctf_merge_enum_t;

static int
ctf_merge_add_enumerator(const char *name, int value, void *arg)
{
	ctf_merge_enum_t *cmep = arg;

	return (ctf_add_enumerator(cmep->cme_fp, cmep->cme_id, name, value) ==
	    CTF_ERR);
}

static int
ctf_merge_add_enum(ctf_merge_types_t *cmp, ctf_id_t id)
{
	int flags;
	const ctf_type_t *tp;
	const char *name;
	ctf_id_t enumid;
	ctf_merge_enum_t cme;

	tp = LCTF_INDEX_TO_TYPEPTR(cmp->cm_src, id);
	name = ctf_strraw(cmp->cm_src, tp->ctt_name);
	if (CTF_INFO_ISROOT(tp->ctt_info) != 0)
		flags = CTF_ADD_ROOT;
	else
		flags = CTF_ADD_NONROOT;

	enumid = ctf_add_enum(cmp->cm_out, flags, name);
	if (enumid == CTF_ERR)
		return (enumid);

	cme.cme_fp = cmp->cm_out;
	cme.cme_id = enumid;
	if (ctf_enum_iter(cmp->cm_src, id, ctf_merge_add_enumerator,
	    &cme) != 0)
		return (CTF_ERR);

	VERIFY(cmp->cm_tmap[id].cmt_map == 0);
	cmp->cm_tmap[id].cmt_map = enumid;
	return (0);
}

static int
ctf_merge_add_func(ctf_merge_types_t *cmp, ctf_id_t id)
{
	int ret, flags, i;
	const ctf_type_t *tp;
	ctf_funcinfo_t ctc;
	ctf_id_t *argv;

	tp = LCTF_INDEX_TO_TYPEPTR(cmp->cm_src, id);
	if (CTF_INFO_ISROOT(tp->ctt_info) != 0)
		flags = CTF_ADD_ROOT;
	else
		flags = CTF_ADD_NONROOT;

	if (ctf_func_info_by_id(cmp->cm_src, id, &ctc) == CTF_ERR)
		return (ctf_set_errno(cmp->cm_out, ctf_errno(cmp->cm_src)));

	argv = ctf_alloc(sizeof (ctf_id_t) * ctc.ctc_argc);
	if (argv == NULL)
		return (ctf_set_errno(cmp->cm_out, ENOMEM));
	if (ctf_func_args_by_id(cmp->cm_src, id, ctc.ctc_argc, argv) ==
	    CTF_ERR) {
		ctf_free(argv, sizeof (ctf_id_t) * ctc.ctc_argc);
		return (ctf_set_errno(cmp->cm_out, ctf_errno(cmp->cm_src)));
	}

	if (cmp->cm_tmap[ctc.ctc_return].cmt_map == 0) {
		ret = ctf_merge_add_type(cmp, ctc.ctc_return);
		if (ret != 0)
			return (ret);
		ASSERT(cmp->cm_tmap[ctc.ctc_return].cmt_map != 0);
	}
	ctc.ctc_return = ctf_merge_gettype(cmp, ctc.ctc_return);

	for (i = 0; i < ctc.ctc_argc; i++) {
		if (cmp->cm_tmap[argv[i]].cmt_map == 0) {
			ret = ctf_merge_add_type(cmp, argv[i]);
			if (ret != 0)
				return (ret);
			ASSERT(cmp->cm_tmap[argv[i]].cmt_map != 0);
		}
		argv[i] = ctf_merge_gettype(cmp, argv[i]);
	}

	ret = ctf_add_funcptr(cmp->cm_out, flags, &ctc, argv);
	ctf_free(argv, sizeof (ctf_id_t) * ctc.ctc_argc);
	if (ret == CTF_ERR)
		return (ret);

	VERIFY(cmp->cm_tmap[id].cmt_map == 0);
	cmp->cm_tmap[id].cmt_map = ret;
	return (0);
}

static int
ctf_merge_add_forward(ctf_merge_types_t *cmp, ctf_id_t id)
{
	int ret, flags;
	const ctf_type_t *tp;
	const char *name;

	tp = LCTF_INDEX_TO_TYPEPTR(cmp->cm_src, id);
	name = ctf_strraw(cmp->cm_src, tp->ctt_name);
	if (CTF_INFO_ISROOT(tp->ctt_info) != 0)
		flags = CTF_ADD_ROOT;
	else
		flags = CTF_ADD_NONROOT;

	/*
	 * ctf_add_forward tries to check to see if a given forward already
	 * exists in one of its hash tables.  If we're here then we know that we
	 * have a forward in a container that isn't present in another.
	 * Therefore, we choose a token hash table to satisfy the API choice
	 * here.
	 */
	ret = ctf_add_forward(cmp->cm_out, flags, name, CTF_K_STRUCT);
	if (ret == CTF_ERR)
		return (CTF_ERR);

	VERIFY(cmp->cm_tmap[id].cmt_map == 0);
	cmp->cm_tmap[id].cmt_map = ret;
	return (0);
}

typedef struct ctf_merge_su {
	ctf_merge_types_t *cms_cm;
	ctf_id_t cms_id;
} ctf_merge_su_t;

static int
ctf_merge_add_member(const char *name, ctf_id_t type, ulong_t offset, void *arg)
{
	ctf_merge_su_t *cms = arg;

	VERIFY(cms->cms_cm->cm_tmap[type].cmt_map != 0);
	type = cms->cms_cm->cm_tmap[type].cmt_map;

	ctf_dprintf("Trying to add member %s to %d\n", name, cms->cms_id);
	return (ctf_add_member(cms->cms_cm->cm_out, cms->cms_id, name,
	    type, offset) == CTF_ERR);
}

/*
 * During the first pass, we always add the generic structure and union but none
 * of its members as they might not all have been mapped yet. Instead we just
 * mark all structures and unions as needing to be fixed up.
 */
static int
ctf_merge_add_sou(ctf_merge_types_t *cmp, ctf_id_t id, boolean_t forward)
{
	int flags, kind;
	const ctf_type_t *tp;
	const char *name;
	ctf_id_t suid;

	tp = LCTF_INDEX_TO_TYPEPTR(cmp->cm_src, id);
	name = ctf_strraw(cmp->cm_src, tp->ctt_name);
	if (CTF_INFO_ISROOT(tp->ctt_info) != 0)
		flags = CTF_ADD_ROOT;
	else
		flags = CTF_ADD_NONROOT;
	kind = ctf_type_kind(cmp->cm_src, id);

	if (kind == CTF_K_STRUCT)
		suid = ctf_add_struct(cmp->cm_out, flags, name);
	else
		suid = ctf_add_union(cmp->cm_out, flags, name);

	if (suid == CTF_ERR)
		return (suid);

	/*
	 * If this is a forward reference then its mapping should already
	 * exist.
	 */
	if (forward == B_FALSE) {
		VERIFY(cmp->cm_tmap[id].cmt_map == 0);
		cmp->cm_tmap[id].cmt_map = suid;
		ctf_dprintf("added sou \"%s\" as (%d) %d->%d\n", name, kind, id,
		    suid);
	} else {
		VERIFY(cmp->cm_tmap[id].cmt_map == suid);
	}
	cmp->cm_tmap[id].cmt_fixup = B_TRUE;

	return (0);
}

static int
ctf_merge_add_type(ctf_merge_types_t *cmp, ctf_id_t id)
{
	int kind, ret;

	/*
	 * We may end up evaluating a type more than once as we may deal with it
	 * as we recursively evaluate some kind of reference and then we may see
	 * it normally.
	 */
	if (cmp->cm_tmap[id].cmt_map != 0)
		return (0);

	kind = ctf_type_kind(cmp->cm_src, id);
	switch (kind) {
	case CTF_K_INTEGER:
	case CTF_K_FLOAT:
		ret = ctf_merge_add_number(cmp, id);
		break;
	case CTF_K_ARRAY:
		ret = ctf_merge_add_array(cmp, id);
		break;
	case CTF_K_POINTER:
	case CTF_K_VOLATILE:
	case CTF_K_CONST:
	case CTF_K_RESTRICT:
		ret = ctf_merge_add_reftype(cmp, id);
		break;
	case CTF_K_TYPEDEF:
		ret = ctf_merge_add_typedef(cmp, id);
		break;
	case CTF_K_ENUM:
		ret = ctf_merge_add_enum(cmp, id);
		break;
	case CTF_K_FUNCTION:
		ret = ctf_merge_add_func(cmp, id);
		break;
	case CTF_K_FORWARD:
		ret = ctf_merge_add_forward(cmp, id);
		break;
	case CTF_K_STRUCT:
	case CTF_K_UNION:
		ret = ctf_merge_add_sou(cmp, id, B_FALSE);
		break;
	case CTF_K_UNKNOWN:
		/*
		 * We don't add unknown types, and we later assert that nothing
		 * should reference them.
		 */
		return (0);
	default:
		abort();
	}

	return (ret);
}

static int
ctf_merge_fixup_sou(ctf_merge_types_t *cmp, ctf_id_t id)
{
	ctf_dtdef_t *dtd;
	ctf_merge_su_t cms;
	ctf_id_t mapid;
	ssize_t size;

	mapid = cmp->cm_tmap[id].cmt_map;
	VERIFY(mapid != 0);
	dtd = ctf_dtd_lookup(cmp->cm_out, mapid);
	VERIFY(dtd != NULL);

	ctf_dprintf("Trying to fix up sou %d\n", id);
	cms.cms_cm = cmp;
	cms.cms_id = mapid;
	if (ctf_member_iter(cmp->cm_src, id, ctf_merge_add_member, &cms) != 0)
		return (CTF_ERR);

	if ((size = ctf_type_size(cmp->cm_src, id)) == CTF_ERR)
		return (CTF_ERR);
	if (ctf_set_size(cmp->cm_out, mapid, size) == CTF_ERR)
		return (CTF_ERR);

	return (0);
}

static int
ctf_merge_fixup_type(ctf_merge_types_t *cmp, ctf_id_t id)
{
	int kind, ret;

	kind = ctf_type_kind(cmp->cm_src, id);
	switch (kind) {
	case CTF_K_STRUCT:
	case CTF_K_UNION:
		ret = ctf_merge_fixup_sou(cmp, id);
		break;
	default:
		VERIFY(0);
		ret = CTF_ERR;
	}

	return (ret);
}

/*
 * Now that we've successfully merged everything, we're going to clean
 * up the merge type table. Traditionally if we had just two different
 * files that we were working between, the types would be fully
 * resolved. However, because we were comparing with ourself every step
 * of the way and not our reduced self, we need to go through and update
 * every mapped entry to what it now points to in the deduped file.
 */
static void
ctf_merge_fixup_dedup_map(ctf_merge_types_t *cmp)
{
	int i;

	for (i = 1; i < cmp->cm_src->ctf_typemax + 1; i++) {
		ctf_id_t tid;

		/*
		 * Missing types always have their id updated to exactly what it
		 * should be.
		 */
		if (cmp->cm_tmap[i].cmt_missing == B_TRUE) {
			VERIFY(cmp->cm_tmap[i].cmt_map != 0);
			continue;
		}

		tid = i;
		while (cmp->cm_tmap[tid].cmt_missing == B_FALSE) {
			VERIFY(cmp->cm_tmap[tid].cmt_map != 0);
			tid = cmp->cm_tmap[tid].cmt_map;
		}
		VERIFY(cmp->cm_tmap[tid].cmt_map != 0);
		cmp->cm_tmap[i].cmt_map = cmp->cm_tmap[tid].cmt_map;
	}
}


/*
 * We're going to do three passes over the containers.
 *
 * Pass 1 checks for forward references in the output container that we know
 * exist in the source container.
 *
 * Pass 2 adds all the missing types from the source container. As part of this
 * we may be adding a type as a forward reference that doesn't exist yet.
 * Any types that we encounter in this form, we need to add to a third pass.
 *
 * Pass 3 is the fixup pass. Here we go through and find all the types that were
 * missing in the first.
 *
 * Importantly, we *must* call ctf_update between the second and third pass,
 * otherwise several of the libctf functions will not properly find the data in
 * the container. If we're doing a dedup we also fix up the type mapping.
 */
static int
ctf_merge_common(ctf_merge_types_t *cmp)
{
	int ret, i;

	ctf_phase_dump(cmp->cm_src, "merge-common-src");
	ctf_phase_dump(cmp->cm_out, "merge-common-dest");

	/* Pass 1 */
	for (i = 1; i <= cmp->cm_src->ctf_typemax; i++) {
		if (cmp->cm_tmap[i].cmt_forward == B_TRUE) {
			ret = ctf_merge_add_sou(cmp, i, B_TRUE);
			if (ret != 0) {
				return (ret);
			}
		}
	}

	/* Pass 2 */
	for (i = 1; i <= cmp->cm_src->ctf_typemax; i++) {
		if (cmp->cm_tmap[i].cmt_missing == B_TRUE) {
			ret = ctf_merge_add_type(cmp, i);
			if (ret != 0) {
				ctf_dprintf("Failed to merge type %d\n", i);
				return (ret);
			}
		}
	}

	ret = ctf_update(cmp->cm_out);
	if (ret != 0)
		return (ret);

	if (cmp->cm_dedup == B_TRUE) {
		ctf_merge_fixup_dedup_map(cmp);
	}

	ctf_dprintf("Beginning merge pass 3\n");
	/* Pass 3 */
	for (i = 1; i <= cmp->cm_src->ctf_typemax; i++) {
		if (cmp->cm_tmap[i].cmt_fixup == B_TRUE) {
			ret = ctf_merge_fixup_type(cmp, i);
			if (ret != 0)
				return (ret);
		}
	}

	if (cmp->cm_dedup == B_TRUE) {
		ctf_merge_fixup_dedup_map(cmp);
	}

	return (0);
}

/*
 * Uniquification is slightly different from a stock merge. For starters, we
 * don't need to replace any forward references in the output. In this case
 * though, the types that already exist are in a parent container to the empty
 * output container.
 */
static int
ctf_merge_uniquify_types(ctf_merge_types_t *cmp)
{
	int i, ret;

	for (i = 1; i <= cmp->cm_src->ctf_typemax; i++) {
		if (cmp->cm_tmap[i].cmt_missing == B_FALSE)
			continue;
		ret = ctf_merge_add_type(cmp, i);
		if (ret != 0)
			return (ret);
	}

	ret = ctf_update(cmp->cm_out);
	if (ret != 0)
		return (ret);

	for (i = 1; i <= cmp->cm_src->ctf_typemax; i++) {
		if (cmp->cm_tmap[i].cmt_fixup == B_FALSE)
			continue;
		ret = ctf_merge_fixup_type(cmp, i);
		if (ret != 0)
			return (ret);
	}

	return (0);
}

static int
ctf_merge_types_init(ctf_merge_types_t *cmp)
{
	cmp->cm_tmap = ctf_alloc(sizeof (ctf_merge_tinfo_t) *
	    (cmp->cm_src->ctf_typemax + 1));
	if (cmp->cm_tmap == NULL)
		return (ctf_set_errno(cmp->cm_out, ENOMEM));
	bzero(cmp->cm_tmap, sizeof (ctf_merge_tinfo_t) *
	    (cmp->cm_src->ctf_typemax + 1));
	return (0);
}

static void
ctf_merge_types_fini(ctf_merge_types_t *cmp)
{
	ctf_free(cmp->cm_tmap, sizeof (ctf_merge_tinfo_t) *
	    (cmp->cm_src->ctf_typemax + 1));
}

/*
 * Merge the types contained inside of two input files. The second input file is
 * always going to be the destination. We're guaranteed that it's always
 * writeable.
 */
static int
ctf_merge_types(void *arg, void *arg2, void **outp, void *unsued)
{
	int ret;
	ctf_merge_types_t cm;
	ctf_diff_t *cdp;
	ctf_merge_objmap_t *cmo;
	ctf_merge_funcmap_t *cmf;
	ctf_merge_input_t *scmi = arg;
	ctf_merge_input_t *dcmi = arg2;
	ctf_file_t *out = dcmi->cmi_input;
	ctf_file_t *source = scmi->cmi_input;

	ctf_dprintf("merging %p->%p\n", source, out);

	if (!(out->ctf_flags & LCTF_RDWR))
		return (ctf_set_errno(out, ECTF_RDONLY));

	if (ctf_getmodel(out) != ctf_getmodel(source))
		return (ctf_set_errno(out, ECTF_DMODEL));

	if ((ret = ctf_diff_init(out, source, &cdp)) != 0)
		return (ret);

	cm.cm_out = out;
	cm.cm_src = source;
	cm.cm_dedup = B_FALSE;
	cm.cm_unique = B_FALSE;
	ret = ctf_merge_types_init(&cm);
	if (ret != 0) {
		ctf_diff_fini(cdp);
		return (ctf_set_errno(out, ret));
	}

	ret = ctf_diff_types(cdp, ctf_merge_diffcb, &cm);
	if (ret != 0)
		goto cleanup;
	ret = ctf_merge_common(&cm);
	ctf_dprintf("merge common returned with %d\n", ret);
	if (ret == 0) {
		ret = ctf_update(out);
		ctf_dprintf("update returned with %d\n", ret);
	} else {
		goto cleanup;
	}

	/*
	 * Now we need to fix up the object and function maps.
	 */
	for (cmo = list_head(&scmi->cmi_omap); cmo != NULL;
	    cmo = list_next(&scmi->cmi_omap, cmo)) {
		if (cmo->cmo_tid == 0)
			continue;
		VERIFY(cm.cm_tmap[cmo->cmo_tid].cmt_map != 0);
		cmo->cmo_tid = cm.cm_tmap[cmo->cmo_tid].cmt_map;
	}

	for (cmf = list_head(&scmi->cmi_fmap); cmf != NULL;
	    cmf = list_next(&scmi->cmi_fmap, cmf)) {
		int i;

		VERIFY(cm.cm_tmap[cmf->cmf_rtid].cmt_map != 0);
		cmf->cmf_rtid = cm.cm_tmap[cmf->cmf_rtid].cmt_map;
		for (i = 0; i < cmf->cmf_argc; i++) {
			VERIFY(cm.cm_tmap[cmf->cmf_args[i]].cmt_map != 0);
			cmf->cmf_args[i] = cm.cm_tmap[cmf->cmf_args[i]].cmt_map;
		}
	}

	/*
	 * Now that we've fixed things up, we need to give our function and
	 * object maps to the destination, such that it can continue to update
	 * them going forward.
	 */
	list_move_tail(&dcmi->cmi_fmap, &scmi->cmi_fmap);
	list_move_tail(&dcmi->cmi_omap, &scmi->cmi_omap);

cleanup:
	if (ret == 0)
		*outp = dcmi;
	ctf_merge_types_fini(&cm);
	ctf_diff_fini(cdp);
	if (ret != 0)
		return (ctf_errno(out));
	return (0);
}

/*
 * After performing a pass, we need to go through the object and function type
 * maps and potentially fix them up based on the new maps that we haev.
 */
static void
ctf_merge_fixup_nontypes(ctf_merge_types_t *cmp, ctf_merge_input_t *cmi)
{
	ctf_merge_objmap_t *cmo;
	ctf_merge_funcmap_t *cmf;

	for (cmo = list_head(&cmi->cmi_omap); cmo != NULL;
	    cmo = list_next(&cmi->cmi_omap, cmo)) {
		if (cmo->cmo_tid == 0)
			continue;
		VERIFY(cmp->cm_tmap[cmo->cmo_tid].cmt_map != 0);
		cmo->cmo_tid = cmp->cm_tmap[cmo->cmo_tid].cmt_map;
	}

	for (cmf = list_head(&cmi->cmi_fmap); cmf != NULL;
	    cmf = list_next(&cmi->cmi_fmap, cmf)) {
		int i;

		VERIFY(cmp->cm_tmap[cmf->cmf_rtid].cmt_map != 0);
		cmf->cmf_rtid = cmp->cm_tmap[cmf->cmf_rtid].cmt_map;
		for (i = 0; i < cmf->cmf_argc; i++) {
			VERIFY(cmp->cm_tmap[cmf->cmf_args[i]].cmt_map !=
			    0);
			cmf->cmf_args[i] =
			    cmp->cm_tmap[cmf->cmf_args[i]].cmt_map;
		}
	}
}

static int
ctf_uniquify_types(ctf_merge_t *cmh, ctf_file_t *src, ctf_file_t **outp)
{
	int err, ret;
	ctf_file_t *out;
	ctf_merge_types_t cm;
	ctf_diff_t *cdp;
	ctf_merge_input_t *cmi;
	ctf_file_t *parent = cmh->cmh_unique;

	*outp = NULL;
	out = ctf_fdcreate(cmh->cmh_ofd, &err);
	if (out == NULL)
		return (ctf_set_errno(src, err));

	out->ctf_parname = cmh->cmh_pname;
	if (ctf_setmodel(out, ctf_getmodel(parent)) != 0) {
		(void) ctf_set_errno(src, ctf_errno(out));
		ctf_close(out);
		return (CTF_ERR);
	}

	if (ctf_import(out, parent) != 0) {
		(void) ctf_set_errno(src, ctf_errno(out));
		ctf_close(out);
		return (CTF_ERR);
	}

	if ((ret = ctf_diff_init(parent, src, &cdp)) != 0) {
		ctf_close(out);
		return (ctf_set_errno(src, ctf_errno(parent)));
	}

	cm.cm_out = parent;
	cm.cm_src = src;
	cm.cm_dedup = B_FALSE;
	cm.cm_unique = B_TRUE;
	ret = ctf_merge_types_init(&cm);
	if (ret != 0) {
		ctf_close(out);
		ctf_diff_fini(cdp);
		return (ctf_set_errno(src, ret));
	}

	ret = ctf_diff_types(cdp, ctf_merge_diffcb, &cm);
	if (ret == 0) {
		cm.cm_out = out;
		ret = ctf_merge_uniquify_types(&cm);
		if (ret == 0)
			ret = ctf_update(out);
	}

	if (ret != 0) {
		ctf_merge_types_fini(&cm);
		ctf_diff_fini(cdp);
		return (ctf_set_errno(src, ctf_errno(cm.cm_out)));
	}

	for (cmi = list_head(&cmh->cmh_inputs); cmi != NULL;
	    cmi = list_next(&cmh->cmh_inputs, cmi)) {
		ctf_merge_fixup_nontypes(&cm, cmi);
	}

	ctf_merge_types_fini(&cm);
	ctf_diff_fini(cdp);
	*outp = out;
	return (0);
}

static void
ctf_merge_fini_input(ctf_merge_input_t *cmi)
{
	ctf_merge_objmap_t *cmo;
	ctf_merge_funcmap_t *cmf;

	while ((cmo = list_remove_head(&cmi->cmi_omap)) != NULL)
		ctf_free(cmo, sizeof (ctf_merge_objmap_t));

	while ((cmf = list_remove_head(&cmi->cmi_fmap)) != NULL)
		ctf_free(cmf, sizeof (ctf_merge_funcmap_t) +
		    sizeof (ctf_id_t) * cmf->cmf_argc);

	if (cmi->cmi_created == B_TRUE && cmi->cmi_input != NULL)
		ctf_close(cmi->cmi_input);

	ctf_free(cmi, sizeof (ctf_merge_input_t));
}

void
ctf_merge_fini(ctf_merge_t *cmh)
{
	size_t len;
	ctf_merge_input_t *cmi;

	if (cmh->cmh_label != NULL) {
		len = strlen(cmh->cmh_label) + 1;
		ctf_free(cmh->cmh_label, len);
	}

	if (cmh->cmh_pname != NULL) {
		len = strlen(cmh->cmh_pname) + 1;
		ctf_free(cmh->cmh_pname, len);
	}

	while ((cmi = list_remove_head(&cmh->cmh_inputs)) != NULL)
		ctf_merge_fini_input(cmi);

	ctf_free(cmh, sizeof (ctf_merge_t));
}

ctf_merge_t *
ctf_merge_init(int fd, int *errp)
{
	int err;
	ctf_merge_t *out;
	struct stat st;

	if (errp == NULL)
		errp = &err;

	if (fd != -1 && fstat(fd, &st) != 0) {
		*errp = EINVAL;
		return (NULL);
	}

	out = ctf_alloc(sizeof (ctf_merge_t));
	if (out == NULL) {
		*errp = ENOMEM;
		return (NULL);
	}

	if (fd == -1) {
		out->cmh_msyms = B_FALSE;
	} else {
		out->cmh_msyms = B_TRUE;
	}

	list_create(&out->cmh_inputs, sizeof (ctf_merge_input_t),
	    offsetof(ctf_merge_input_t, cmi_node));
	out->cmh_ninputs = 0;
	out->cmh_nthreads = 1;
	out->cmh_unique = NULL;
	out->cmh_ofd = fd;
	out->cmh_flags = 0;
	out->cmh_label = NULL;
	out->cmh_pname = NULL;

	return (out);
}

int
ctf_merge_label(ctf_merge_t *cmh, const char *label)
{
	char *dup;

	if (label == NULL)
		return (EINVAL);

	dup = ctf_strdup(label);
	if (dup == NULL)
		return (EAGAIN);

	if (cmh->cmh_label != NULL) {
		size_t len = strlen(cmh->cmh_label) + 1;
		ctf_free(cmh->cmh_label, len);
	}

	cmh->cmh_label = dup;
	return (0);
}

static int
ctf_merge_add_funcs_cb(const char *name, ulong_t idx, ctf_funcinfo_t *fip,
    void *arg)
{
	ctf_merge_input_t *cmi = arg;
	ctf_merge_funcmap_t *fmap;

	fmap = ctf_alloc(sizeof (ctf_merge_funcmap_t) +
	    sizeof (ctf_id_t) * fip->ctc_argc);
	if (fmap == NULL)
		return (ENOMEM);

	fmap->cmf_idx = idx;
	fmap->cmf_rtid = fip->ctc_return;
	fmap->cmf_flags = fip->ctc_flags;
	fmap->cmf_argc = fip->ctc_argc;
	fmap->cmf_name = name;

	if (ctf_func_args(cmi->cmi_input, idx, fmap->cmf_argc,
	    fmap->cmf_args) != 0) {
		ctf_free(fmap, sizeof (ctf_merge_funcmap_t) +
		    sizeof (ctf_id_t) * fip->ctc_argc);
		return (ctf_errno(cmi->cmi_input));
	}

	list_insert_tail(&cmi->cmi_fmap, fmap);
	return (0);
}

static int
ctf_merge_add_objs_cb(const char *name, ctf_id_t id, ulong_t idx, void *arg)
{
	ctf_merge_input_t *cmi = arg;
	ctf_merge_objmap_t *cmo;

	cmo = ctf_alloc(sizeof (ctf_merge_objmap_t));
	if (cmo == NULL)
		return (ENOMEM);

	cmo->cmo_name = name;
	cmo->cmo_idx = idx;
	cmo->cmo_tid = id;
	list_insert_tail(&cmi->cmi_omap, cmo);
	return (0);
}

/*
 * Whenever we create an entry to merge, we then go and add a second empty
 * ctf_file_t which we use for the purposes of our merging. It's not the best,
 * but it's the best that we've got at the moment.
 */
int
ctf_merge_add(ctf_merge_t *cmh, ctf_file_t *input)
{
	int ret;
	ctf_merge_input_t *cmi;
	ctf_file_t *empty;

	if (input->ctf_flags & LCTF_CHILD)
		return (ECTF_MCHILD);

	cmi = ctf_alloc(sizeof (ctf_merge_input_t));
	if (cmi == NULL)
		return (ENOMEM);

	cmi->cmi_created = B_FALSE;
	cmi->cmi_input = input;
	list_create(&cmi->cmi_fmap, sizeof (ctf_merge_funcmap_t),
	    offsetof(ctf_merge_funcmap_t, cmf_node));
	list_create(&cmi->cmi_omap, sizeof (ctf_merge_funcmap_t),
	    offsetof(ctf_merge_objmap_t, cmo_node));

	if (cmh->cmh_msyms == B_TRUE) {
		if ((ret = ctf_function_iter(input, ctf_merge_add_funcs_cb,
		    cmi)) != 0) {
			ctf_merge_fini_input(cmi);
			return (ret);
		}

		if ((ret = ctf_object_iter(input, ctf_merge_add_objs_cb,
		    cmi)) != 0) {
			ctf_merge_fini_input(cmi);
			return (ret);
		}
	}

	list_insert_tail(&cmh->cmh_inputs, cmi);
	cmh->cmh_ninputs++;

	/* And now the empty one to merge into this */
	cmi = ctf_alloc(sizeof (ctf_merge_input_t));
	if (cmi == NULL)
		return (ENOMEM);
	list_create(&cmi->cmi_fmap, sizeof (ctf_merge_funcmap_t),
	    offsetof(ctf_merge_funcmap_t, cmf_node));
	list_create(&cmi->cmi_omap, sizeof (ctf_merge_funcmap_t),
	    offsetof(ctf_merge_objmap_t, cmo_node));

	empty = ctf_fdcreate(cmh->cmh_ofd, &ret);
	if (empty == NULL)
		return (ret);
	cmi->cmi_input = empty;
	cmi->cmi_created = B_TRUE;

	if (ctf_setmodel(empty, ctf_getmodel(input)) == CTF_ERR) {
		return (ctf_errno(empty));
	}

	list_insert_tail(&cmh->cmh_inputs, cmi);
	cmh->cmh_ninputs++;
	ctf_dprintf("added containers %p and %p\n", input, empty);
	return (0);
}

int
ctf_merge_uniquify(ctf_merge_t *cmh, ctf_file_t *u, const char *pname)
{
	char *dup;

	if (u->ctf_flags & LCTF_CHILD)
		return (ECTF_MCHILD);
	if (pname == NULL)
		return (EINVAL);
	dup = ctf_strdup(pname);
	if (dup == NULL)
		return (EINVAL);
	if (cmh->cmh_pname != NULL) {
		size_t len = strlen(cmh->cmh_pname) + 1;
		ctf_free(cmh->cmh_pname, len);
	}
	cmh->cmh_pname = dup;
	cmh->cmh_unique = u;
	return (0);
}

static int
ctf_merge_symbols(ctf_merge_t *cmh, ctf_file_t *fp)
{
	int err;
	ulong_t i;

	uintptr_t symbase = (uintptr_t)fp->ctf_symtab.cts_data;
	uintptr_t strbase = (uintptr_t)fp->ctf_strtab.cts_data;

	for (i = 0; i < fp->ctf_nsyms; i++) {
		const char *name;
		ctf_merge_input_t *cmi;
		ctf_merge_objmap_t *cmo;

		if (fp->ctf_symtab.cts_entsize == sizeof (Elf32_Sym)) {
			const Elf32_Sym *symp = (Elf32_Sym *)symbase + i;
			int type = ELF32_ST_TYPE(symp->st_info);
			if (type != STT_OBJECT)
				continue;
			if (ctf_sym_valid(strbase, type, symp->st_shndx,
			    symp->st_value, symp->st_name) == B_FALSE)
				continue;
			name = (char *)(strbase + symp->st_name);
		} else {
			const Elf64_Sym *symp = (Elf64_Sym *)symbase + i;
			int type = ELF64_ST_TYPE(symp->st_info);
			if (type != STT_OBJECT)
				continue;
			if (ctf_sym_valid(strbase, type, symp->st_shndx,
			    symp->st_value, symp->st_name) == B_FALSE)
				continue;
			name = (char *)(strbase + symp->st_name);
		}

		cmo = NULL;
		for (cmi = list_head(&cmh->cmh_inputs); cmi != NULL;
		    cmi = list_next(&cmh->cmh_inputs, cmi)) {
			for (cmo = list_head(&cmi->cmi_omap); cmo != NULL;
			    cmo = list_next(&cmi->cmi_omap, cmo)) {
				if (strcmp(cmo->cmo_name, name) == 0)
					goto found;
			}
		}
found:
		if (cmo != NULL) {
			if (cmo->cmo_tid == 0)
				continue;
			if ((err = ctf_add_object(fp, i, cmo->cmo_tid)) != 0) {
				ctf_dprintf("Failed to add symbol %s->%d: %s\n",
				    name, cmo->cmo_tid,
				    ctf_errmsg(ctf_errno(fp)));
				return (err);
			}
		}
	}

	return (0);
}

static int
ctf_merge_functions(ctf_merge_t *cmh, ctf_file_t *fp)
{
	int err;
	ulong_t i;
	ctf_funcinfo_t fi;

	uintptr_t symbase = (uintptr_t)fp->ctf_symtab.cts_data;
	uintptr_t strbase = (uintptr_t)fp->ctf_strtab.cts_data;

	for (i = 0; i < fp->ctf_nsyms; i++) {
		const char *name;
		ctf_merge_input_t *cmi;
		ctf_merge_funcmap_t *cmf;

		if (fp->ctf_symtab.cts_entsize == sizeof (Elf32_Sym)) {
			const Elf32_Sym *symp = (Elf32_Sym *)symbase + i;
			int type = ELF32_ST_TYPE(symp->st_info);
			if (ELF32_ST_TYPE(symp->st_info) != STT_FUNC)
				continue;
			if (ctf_sym_valid(strbase, type, symp->st_shndx,
			    symp->st_value, symp->st_name) == B_FALSE)
				continue;
			name = (char *)(strbase + symp->st_name);
		} else {
			const Elf64_Sym *symp = (Elf64_Sym *)symbase + i;
			int type = ELF64_ST_TYPE(symp->st_info);
			if (ELF64_ST_TYPE(symp->st_info) != STT_FUNC)
				continue;
			if (ctf_sym_valid(strbase, type, symp->st_shndx,
			    symp->st_value, symp->st_name) == B_FALSE)
				continue;
			name = (char *)(strbase + symp->st_name);
		}

		cmf = NULL;
		for (cmi = list_head(&cmh->cmh_inputs); cmi != NULL;
		    cmi = list_next(&cmh->cmh_inputs, cmi)) {
			for (cmf = list_head(&cmi->cmi_fmap); cmf != NULL;
			    cmf = list_next(&cmi->cmi_fmap, cmf)) {
				if (strcmp(cmf->cmf_name, name) == 0)
					goto found;
			}
		}
found:
		if (cmf != NULL) {
			fi.ctc_return = cmf->cmf_rtid;
			fi.ctc_argc = cmf->cmf_argc;
			fi.ctc_flags = cmf->cmf_flags;
			if ((err = ctf_add_function(fp, i, &fi,
			    cmf->cmf_args)) != 0)
				return (err);
		}
	}

	return (0);

}

int
ctf_merge_merge(ctf_merge_t *cmh, ctf_file_t **outp)
{
	int err, merr;
	ctf_merge_input_t *cmi;
	ctf_id_t ltype;
	mergeq_t *mqp;
	ctf_merge_input_t *final;
	ctf_file_t *out;

	if (cmh->cmh_label != NULL && cmh->cmh_unique != NULL) {
		const char *label = ctf_label_topmost(cmh->cmh_unique);
		if (label == NULL)
			return (ECTF_NOLABEL);
		if (strcmp(label, cmh->cmh_label) != 0)
			return (ECTF_LCONFLICT);
	}

	if (mergeq_init(&mqp, cmh->cmh_nthreads) == -1) {
		return (errno);
	}

	VERIFY(cmh->cmh_ninputs % 2 == 0);
	for (cmi = list_head(&cmh->cmh_inputs); cmi != NULL;
	    cmi = list_next(&cmh->cmh_inputs, cmi)) {
		if (mergeq_add(mqp, cmi) == -1) {
			err = errno;
			mergeq_fini(mqp);
		}
	}

	err = mergeq_merge(mqp, ctf_merge_types, NULL, (void **)&final, &merr);
	mergeq_fini(mqp);

	if (err == MERGEQ_ERROR) {
		return (errno);
	} else if (err == MERGEQ_UERROR) {
		return (merr);
	}

	/*
	 * Disassociate the generated ctf_file_t from the original input. That
	 * way when the input gets cleaned up, we don't accidentally kill the
	 * final reference to the ctf_file_t. If it gets uniquified then we'll
	 * kill it.
	 */
	VERIFY(final->cmi_input != NULL);
	out = final->cmi_input;
	final->cmi_input = NULL;

	ctf_dprintf("preparing to uniquify against: %p\n", cmh->cmh_unique);
	if (cmh->cmh_unique != NULL) {
		ctf_file_t *u;
		err = ctf_uniquify_types(cmh, out, &u);
		if (err != 0) {
			err = ctf_errno(out);
			ctf_close(out);
			return (err);
		}
		ctf_close(out);
		out = u;
	}

	ltype = out->ctf_typemax;
	if ((out->ctf_flags & LCTF_CHILD) && ltype != 0)
		ltype += CTF_CHILD_START;
	ctf_dprintf("trying to add the label\n");
	if (cmh->cmh_label != NULL &&
	    ctf_add_label(out, cmh->cmh_label, ltype, 0) != 0) {
		ctf_close(out);
		return (ctf_errno(out));
	}

	ctf_dprintf("merging symbols and the like\n");
	if (cmh->cmh_msyms == B_TRUE) {
		err = ctf_merge_symbols(cmh, out);
		if (err != 0) {
			ctf_close(out);
			return (ctf_errno(out));
		}

		err = ctf_merge_functions(cmh, out);
		if (err != 0) {
			ctf_close(out);
			return (ctf_errno(out));
		}
	}

	err = ctf_update(out);
	if (err != 0) {
		ctf_close(out);
		return (ctf_errno(out));
	}

	*outp = out;
	return (0);
}

/*
 * When we get told that something is unique, eg. same is B_FALSE, then that
 * tells us that we need to add it to the output. If same is B_TRUE, then we'll
 * want to record it in the mapping table so that we know how to redirect types
 * to the extant ones.
 */
static void
ctf_dedup_cb(ctf_file_t *ifp, ctf_id_t iid, boolean_t same, ctf_file_t *ofp,
    ctf_id_t oid, void *arg)
{
	ctf_merge_types_t *cmp = arg;
	ctf_merge_tinfo_t *cmt = cmp->cm_tmap;

	if (same == B_TRUE) {
		/*
		 * The output id here may itself map to something else.
		 * Therefore, we need to basically walk a chain and see what it
		 * points to until it itself points to a base type, eg. -1.
		 * Otherwise we'll dedup to something which no longer exists.
		 */
		while (cmt[oid].cmt_missing == B_FALSE)
			oid = cmt[oid].cmt_map;
		cmt[iid].cmt_map = oid;
		ctf_dprintf("%d->%d \n", iid, oid);
	} else {
		VERIFY(cmt[iid].cmt_map == 0);
		cmt[iid].cmt_missing = B_TRUE;
		ctf_dprintf("%d is missing\n", iid);
	}
}

/*
 * Dedup a CTF container.
 *
 * DWARF and other encoding formats that we use to create CTF data may create
 * multiple copies of a given type. However, after doing a conversion, and
 * before doing a merge, we'd prefer, if possible, to have every input container
 * to be unique.
 *
 * Doing a deduplication is like a normal merge. However, when we diff the types
 * in the container, rather than doing a normal diff, we instead want to diff
 * against any already processed types. eg, for a given type i in a container,
 * we want to diff it from 0 to i - 1.
 */
int
ctf_merge_dedup(ctf_merge_t *cmp, ctf_file_t **outp)
{
	int ret;
	ctf_diff_t *cdp = NULL;
	ctf_merge_input_t *cmi, *cmc;
	ctf_file_t *ifp, *ofp;
	ctf_merge_types_t cm;

	if (cmp == NULL || outp == NULL)
		return (EINVAL);

	ctf_dprintf("encountered %d inputs\n", cmp->cmh_ninputs);
	if (cmp->cmh_ninputs != 2)
		return (EINVAL);

	ctf_dprintf("passed argument sanity check\n");

	cmi = list_head(&cmp->cmh_inputs);
	VERIFY(cmi != NULL);
	cmc = list_next(&cmp->cmh_inputs, cmi);
	VERIFY(cmc != NULL);
	ifp = cmi->cmi_input;
	ofp = cmc->cmi_input;
	VERIFY(ifp != NULL);
	VERIFY(ofp != NULL);
	cm.cm_src = ifp;
	cm.cm_out = ofp;
	cm.cm_dedup = B_TRUE;
	cm.cm_unique = B_FALSE;

	if ((ret = ctf_merge_types_init(&cm)) != 0) {
		return (ret);
	}

	if ((ret = ctf_diff_init(ifp, ifp, &cdp)) != 0)
		goto err;

	ctf_dprintf("Successfully initialized dedup\n");
	if ((ret = ctf_diff_self(cdp, ctf_dedup_cb, &cm)) != 0)
		goto err;

	ctf_dprintf("Successfully diffed types\n");
	ret = ctf_merge_common(&cm);
	ctf_dprintf("deduping types result: %d\n", ret);
	if (ret == 0)
		ret = ctf_update(cm.cm_out);
	if (ret != 0)
		goto err;

	ctf_dprintf("Successfully deduped types\n");
	ctf_phase_dump(cm.cm_out, "dedup-pre-syms");

	/*
	 * Now we need to fix up the object and function maps.
	 */
	ctf_merge_fixup_nontypes(&cm, cmi);

	if (cmp->cmh_msyms == B_TRUE) {
		ret = ctf_merge_symbols(cmp, cm.cm_out);
		if (ret != 0) {
			ret = ctf_errno(cm.cm_out);
			ctf_dprintf("failed to dedup symbols: %s\n",
			    ctf_errmsg(ret));
			goto err;
		}

		ret = ctf_merge_functions(cmp, cm.cm_out);
		if (ret != 0) {
			ret = ctf_errno(cm.cm_out);
			ctf_dprintf("failed to dedup functions: %s\n",
			    ctf_errmsg(ret));
			goto err;
		}
	}

	ret = ctf_update(cm.cm_out);
	if (ret == 0) {
		cmc->cmi_input = NULL;
		*outp = cm.cm_out;
	}
err:
	ctf_merge_types_fini(&cm);
	ctf_diff_fini(cdp);
	return (ret);
}

int
ctf_merge_set_nthreads(ctf_merge_t *cmp, const uint_t nthrs)
{
	if (nthrs == 0)
		return (EINVAL);
	cmp->cmh_nthreads = nthrs;
	return (0);
}
