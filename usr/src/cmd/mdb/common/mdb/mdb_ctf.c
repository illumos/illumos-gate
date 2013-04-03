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
 */
/*
 * Copyright (c) 2013 by Delphix. All rights reserved.
 * Copyright (c) 2013, Joyent, Inc.  All rights reserved.
 */

#include <mdb/mdb_ctf.h>
#include <mdb/mdb_ctf_impl.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_string.h>
#include <mdb/mdb.h>
#include <mdb/mdb_debug.h>

#include <libctf.h>
#include <string.h>

typedef struct tnarg {
	mdb_tgt_t *tn_tgt;		/* target to use for lookup */
	const char *tn_name;		/* query string to lookup */
	ctf_file_t *tn_fp;		/* CTF container from match */
	ctf_id_t tn_id;			/* CTF type ID from match */
} tnarg_t;

typedef struct type_iter {
	mdb_ctf_type_f *ti_cb;
	void *ti_arg;
	ctf_file_t *ti_fp;
} type_iter_t;

typedef struct member_iter {
	mdb_ctf_member_f *mi_cb;
	void *mi_arg;
	ctf_file_t *mi_fp;
} member_iter_t;

typedef struct type_visit {
	mdb_ctf_visit_f	*tv_cb;
	void		*tv_arg;
	ctf_file_t	*tv_fp;
	ulong_t		tv_base_offset;	/* used when recursing from type_cb() */
	int		tv_base_depth;	/* used when recursing from type_cb() */
	int		tv_min_depth;
} type_visit_t;

typedef struct mbr_info {
	const char *mbr_member;
	ulong_t *mbr_offp;
	mdb_ctf_id_t *mbr_typep;
} mbr_info_t;

typedef struct synth_intrinsic {
	const char *syn_name;
	ctf_encoding_t syn_enc;
	uint_t syn_kind;
} synth_intrinsic_t;

typedef struct synth_typedef {
	const char *syt_src;
	const char *syt_targ;
} synth_typedef_t;

/*
 * As part of our support for synthetic types via ::typedef, we define a core
 * set of types.
 */
static const synth_intrinsic_t synth_builtins32[] = {
{ "void", { CTF_INT_SIGNED, 0, 0 }, CTF_K_INTEGER },
{ "signed", { CTF_INT_SIGNED, 0, 32 }, CTF_K_INTEGER },
{ "unsigned", { 0, 0, 32 }, CTF_K_INTEGER },
{ "char", { CTF_INT_SIGNED | CTF_INT_CHAR, 0, 8 }, CTF_K_INTEGER },
{ "short", { CTF_INT_SIGNED, 0, 16 }, CTF_K_INTEGER },
{ "int", { CTF_INT_SIGNED, 0, 32 }, CTF_K_INTEGER },
{ "long", { CTF_INT_SIGNED, 0, 32 }, CTF_K_INTEGER },
{ "long long", { CTF_INT_SIGNED, 0, 64 }, CTF_K_INTEGER },
{ "signed char", { CTF_INT_SIGNED | CTF_INT_CHAR, 0, 8 }, CTF_K_INTEGER },
{ "signed short", { CTF_INT_SIGNED, 0, 16 }, CTF_K_INTEGER },
{ "signed int", { CTF_INT_SIGNED, 0, 32 }, CTF_K_INTEGER },
{ "signed long", { CTF_INT_SIGNED, 0, 32 }, CTF_K_INTEGER },
{ "signed long long", { CTF_INT_SIGNED, 0, 64 }, CTF_K_INTEGER },
{ "unsigned char", { CTF_INT_CHAR, 0, 8 }, CTF_K_INTEGER },
{ "unsigned short", { 0, 0, 16 }, CTF_K_INTEGER },
{ "unsigned int", { 0, 0, 32 }, CTF_K_INTEGER },
{ "unsigned long", { 0, 0, 32 }, CTF_K_INTEGER },
{ "unsigned long long", { 0, 0, 64 }, CTF_K_INTEGER },
{ "_Bool", { CTF_INT_BOOL, 0, 8 }, CTF_K_INTEGER },
{ "float", { CTF_FP_SINGLE, 0, 32 }, CTF_K_FLOAT },
{ "double", { CTF_FP_DOUBLE, 0, 64 }, CTF_K_FLOAT },
{ "long double", { CTF_FP_LDOUBLE, 0, 128 }, CTF_K_FLOAT },
{ "float imaginary", { CTF_FP_IMAGRY, 0, 32 }, CTF_K_FLOAT },
{ "double imaginary", { CTF_FP_DIMAGRY, 0, 64 }, CTF_K_FLOAT },
{ "long double imaginary", { CTF_FP_LDIMAGRY, 0, 128 }, CTF_K_FLOAT },
{ "float complex", { CTF_FP_CPLX, 0, 64 }, CTF_K_FLOAT },
{ "double complex", { CTF_FP_DCPLX, 0, 128 }, CTF_K_FLOAT },
{ "long double complex", { CTF_FP_LDCPLX, 0, 256 }, CTF_K_FLOAT },
{ NULL, { 0, 0, 0}, 0 }
};

static const synth_intrinsic_t synth_builtins64[] = {
{ "void", { CTF_INT_SIGNED, 0, 0 }, CTF_K_INTEGER },
{ "signed", { CTF_INT_SIGNED, 0, 32 }, CTF_K_INTEGER },
{ "unsigned", { 0, 0, 32 }, CTF_K_INTEGER },
{ "char", { CTF_INT_SIGNED | CTF_INT_CHAR, 0, 8 }, CTF_K_INTEGER },
{ "short", { CTF_INT_SIGNED, 0, 16 }, CTF_K_INTEGER },
{ "int", { CTF_INT_SIGNED, 0, 32 }, CTF_K_INTEGER },
{ "long", { CTF_INT_SIGNED, 0, 64 }, CTF_K_INTEGER },
{ "long long", { CTF_INT_SIGNED, 0, 64 }, CTF_K_INTEGER },
{ "signed char", { CTF_INT_SIGNED | CTF_INT_CHAR, 0, 8 }, CTF_K_INTEGER },
{ "signed short", { CTF_INT_SIGNED, 0, 16 }, CTF_K_INTEGER },
{ "signed int", { CTF_INT_SIGNED, 0, 32 }, CTF_K_INTEGER },
{ "signed long", { CTF_INT_SIGNED, 0, 64 }, CTF_K_INTEGER },
{ "signed long long", { CTF_INT_SIGNED, 0, 64 }, CTF_K_INTEGER },
{ "unsigned char", { CTF_INT_CHAR, 0, 8 }, CTF_K_INTEGER },
{ "unsigned short", { 0, 0, 16 }, CTF_K_INTEGER },
{ "unsigned int", { 0, 0, 32 }, CTF_K_INTEGER },
{ "unsigned long", { 0, 0, 64 }, CTF_K_INTEGER },
{ "unsigned long long", { 0, 0, 64 }, CTF_K_INTEGER },
{ "_Bool", { CTF_INT_BOOL, 0, 8 }, CTF_K_INTEGER },
{ "float", { CTF_FP_SINGLE, 0, 32 }, CTF_K_FLOAT },
{ "double", { CTF_FP_DOUBLE, 0, 64 }, CTF_K_FLOAT },
{ "long double", { CTF_FP_LDOUBLE, 0, 128 }, CTF_K_FLOAT },
{ "float imaginary", { CTF_FP_IMAGRY, 0, 32 }, CTF_K_FLOAT },
{ "double imaginary", { CTF_FP_DIMAGRY, 0, 64 }, CTF_K_FLOAT },
{ "long double imaginary", { CTF_FP_LDIMAGRY, 0, 128 }, CTF_K_FLOAT },
{ "float complex", { CTF_FP_CPLX, 0, 64 }, CTF_K_FLOAT },
{ "double complex", { CTF_FP_DCPLX, 0, 128 }, CTF_K_FLOAT },
{ "long double complex", { CTF_FP_LDCPLX, 0, 256 }, CTF_K_FLOAT },
{ NULL, { 0, 0, 0 }, 0 }
};

static const synth_typedef_t synth_typedefs32[] = {
{ "char", "int8_t" },
{ "short", "int16_t" },
{ "int", "int32_t" },
{ "long long", "int64_t" },
{ "int", "intptr_t" },
{ "unsigned char", "uint8_t" },
{ "unsigned short", "uint16_t" },
{ "unsigned", "uint32_t" },
{ "unsigned long long", "uint64_t" },
{ "unsigned char", "uchar_t" },
{ "unsigned short", "ushort_t" },
{ "unsigned", "uint_t" },
{ "unsigned long", "ulong_t" },
{ "unsigned long long", "u_longlong_t" },
{ "int", "ptrdiff_t" },
{ "unsigned", "uintptr_t" },
{ NULL, NULL }
};

static const synth_typedef_t synth_typedefs64[] = {
{ "char", "int8_t" },
{ "short", "int16_t" },
{ "int", "int32_t" },
{ "long", "int64_t" },
{ "long", "intptr_t" },
{ "unsigned char", "uint8_t" },
{ "unsigned short", "uint16_t" },
{ "unsigned", "uint32_t" },
{ "unsigned long", "uint64_t" },
{ "unsigned char", "uchar_t" },
{ "unsigned short", "ushort_t" },
{ "unsigned", "uint_t" },
{ "unsigned long", "ulong_t" },
{ "unsigned long long", "u_longlong_t" },
{ "long", "ptrdiff_t" },
{ "unsigned long", "uintptr_t" },
{ NULL, NULL }
};

static void
set_ctf_id(mdb_ctf_id_t *p, ctf_file_t *fp, ctf_id_t id)
{
	mdb_ctf_impl_t *mcip = (mdb_ctf_impl_t *)p;

	mcip->mci_fp = fp;
	mcip->mci_id = id;
}

/*
 * Callback function for mdb_tgt_object_iter used from name_to_type, below,
 * to search the CTF namespace of each object file for a particular name.
 */
/*ARGSUSED*/
static int
obj_lookup(void *data, const mdb_map_t *mp, const char *name)
{
	tnarg_t *tnp = data;
	ctf_file_t *fp;
	ctf_id_t id;

	if ((fp = mdb_tgt_name_to_ctf(tnp->tn_tgt, name)) != NULL &&
	    (id = ctf_lookup_by_name(fp, tnp->tn_name)) != CTF_ERR) {
		tnp->tn_fp = fp;
		tnp->tn_id = id;

		/*
		 * We may have found a forward declaration.  If we did, we'll
		 * note the ID and file pointer, but we'll keep searching in
		 * an attempt to find the real thing.  If we found something
		 * real (i.e. not a forward), we stop the iteration.
		 */
		return (ctf_type_kind(fp, id) == CTF_K_FORWARD ? 0 : -1);
	}

	return (0);
}

/*
 * Convert a string type name with an optional leading object specifier into
 * the corresponding CTF file container and type ID.  If an error occurs, we
 * print an appropriate message and return NULL.
 */
static ctf_file_t *
name_to_type(mdb_tgt_t *t, const char *cname, ctf_id_t *idp)
{
	const char *object = MDB_TGT_OBJ_EXEC;
	ctf_file_t *fp = NULL;
	ctf_id_t id;
	tnarg_t arg;
	char *p, *s;
	char buf[MDB_SYM_NAMLEN];
	char *name = &buf[0];

	(void) mdb_snprintf(buf, sizeof (buf), "%s", cname);

	if ((p = strrsplit(name, '`')) != NULL) {
		/*
		 * We need to shuffle things around a little to support
		 * type names of the form "struct module`name".
		 */
		if ((s = strsplit(name, ' ')) != NULL) {
			bcopy(cname + (s - name), name, (p - s) - 1);
			name[(p - s) - 1] = '\0';
			bcopy(cname, name + (p - s), s - name);
			p = name + (p - s);
		}
		if (*name != '\0')
			object = name;
		name = p;
	}

	/*
	 * Attempt to look up the name in the primary object file.  If this
	 * fails and the name was unscoped, search all remaining object files.
	 * Finally, search the synthetic types.
	 */
	if (((fp = mdb_tgt_name_to_ctf(t, object)) == NULL ||
	    (id = ctf_lookup_by_name(fp, name)) == CTF_ERR ||
	    ctf_type_kind(fp, id) == CTF_K_FORWARD) &&
	    object == MDB_TGT_OBJ_EXEC) {

		arg.tn_tgt = t;
		arg.tn_name = name;
		arg.tn_fp = NULL;
		arg.tn_id = CTF_ERR;

		(void) mdb_tgt_object_iter(t, obj_lookup, &arg);

		if (arg.tn_id != CTF_ERR) {
			fp = arg.tn_fp;
			id = arg.tn_id;
		} else if (mdb.m_synth != NULL) {
			if ((id = ctf_lookup_by_name(mdb.m_synth,
			    name)) != CTF_ERR)
				fp = mdb.m_synth;
		}
	}

	if (fp == NULL)
		return (NULL); /* errno is set for us */

	if (id == CTF_ERR) {
		(void) set_errno(ctf_to_errno(ctf_errno(fp)));
		return (NULL);
	}

	*idp = id;
	return (fp);
}

/*
 * Check to see if there is ctf data in the given object. This is useful
 * so that we don't enter some loop where every call to lookup fails.
 */
int
mdb_ctf_enabled_by_object(const char *object)
{
	mdb_tgt_t *t = mdb.m_target;

	return (mdb_tgt_name_to_ctf(t, object) != NULL);
}

int
mdb_ctf_lookup_by_name(const char *name, mdb_ctf_id_t *p)
{
	ctf_file_t *fp = NULL;
	mdb_ctf_impl_t *mcip = (mdb_ctf_impl_t *)p;
	mdb_tgt_t *t = mdb.m_target;

	if (mcip == NULL)
		return (set_errno(EINVAL));

	if ((fp = name_to_type(t, name, &mcip->mci_id)) == NULL) {
		mdb_ctf_type_invalidate(p);
		return (-1); /* errno is set for us */
	}

	mcip->mci_fp = fp;

	return (0);
}

int
mdb_ctf_lookup_by_symbol(const GElf_Sym *symp, const mdb_syminfo_t *sip,
    mdb_ctf_id_t *p)
{
	ctf_file_t *fp = NULL;
	mdb_ctf_impl_t *mcip = (mdb_ctf_impl_t *)p;
	mdb_tgt_t *t = mdb.m_target;

	if (mcip == NULL)
		return (set_errno(EINVAL));

	if (symp == NULL || sip == NULL) {
		mdb_ctf_type_invalidate(p);
		return (set_errno(EINVAL));
	}

	if ((fp = mdb_tgt_addr_to_ctf(t, symp->st_value)) == NULL) {
		mdb_ctf_type_invalidate(p);
		return (-1); /* errno is set for us */
	}

	if ((mcip->mci_id = ctf_lookup_by_symbol(fp, sip->sym_id)) == CTF_ERR) {
		mdb_ctf_type_invalidate(p);
		return (set_errno(ctf_to_errno(ctf_errno(fp))));
	}

	mcip->mci_fp = fp;

	return (0);
}

int
mdb_ctf_lookup_by_addr(uintptr_t addr, mdb_ctf_id_t *p)
{
	GElf_Sym sym;
	mdb_syminfo_t si;
	char name[MDB_SYM_NAMLEN];
	const mdb_map_t *mp;
	mdb_tgt_t *t = mdb.m_target;
	const char *obj, *c;

	if (p == NULL)
		return (set_errno(EINVAL));

	if (mdb_tgt_lookup_by_addr(t, addr, MDB_TGT_SYM_EXACT, name,
	    sizeof (name), NULL, NULL) == -1) {
		mdb_ctf_type_invalidate(p);
		return (-1); /* errno is set for us */
	}

	if ((c = strrsplit(name, '`')) != NULL) {
		obj = name;
	} else {
		if ((mp = mdb_tgt_addr_to_map(t, addr)) == NULL) {
			mdb_ctf_type_invalidate(p);
			return (-1); /* errno is set for us */
		}

		obj = mp->map_name;
		c = name;
	}

	if (mdb_tgt_lookup_by_name(t, obj, c, &sym, &si) == -1) {
		mdb_ctf_type_invalidate(p);
		return (-1); /* errno is set for us */
	}

	return (mdb_ctf_lookup_by_symbol(&sym, &si, p));
}

int
mdb_ctf_module_lookup(const char *name, mdb_ctf_id_t *p)
{
	ctf_file_t *fp;
	ctf_id_t id;
	mdb_module_t *mod;

	if ((mod = mdb_get_module()) == NULL)
		return (set_errno(EMDB_CTX));

	if ((fp = mod->mod_ctfp) == NULL)
		return (set_errno(EMDB_NOCTF));

	if ((id = ctf_lookup_by_name(fp, name)) == CTF_ERR)
		return (set_errno(ctf_to_errno(ctf_errno(fp))));

	set_ctf_id(p, fp, id);

	return (0);
}

/*ARGSUSED*/
int
mdb_ctf_func_info(const GElf_Sym *symp, const mdb_syminfo_t *sip,
    mdb_ctf_funcinfo_t *mfp)
{
	ctf_file_t *fp = NULL;
	ctf_funcinfo_t f;
	mdb_tgt_t *t = mdb.m_target;
	char name[MDB_SYM_NAMLEN];
	const mdb_map_t *mp;
	mdb_syminfo_t si;
	int err;

	if (symp == NULL || mfp == NULL)
		return (set_errno(EINVAL));

	/*
	 * In case the input symbol came from a merged or private symbol table,
	 * re-lookup the address as a symbol, and then perform a fully scoped
	 * lookup of that symbol name to get the mdb_syminfo_t for its CTF.
	 */
	if ((fp = mdb_tgt_addr_to_ctf(t, symp->st_value)) == NULL ||
	    (mp = mdb_tgt_addr_to_map(t, symp->st_value)) == NULL ||
	    mdb_tgt_lookup_by_addr(t, symp->st_value, MDB_TGT_SYM_FUZZY,
	    name, sizeof (name), NULL, NULL) != 0)
		return (-1); /* errno is set for us */

	if (strchr(name, '`') != NULL)
		err = mdb_tgt_lookup_by_scope(t, name, NULL, &si);
	else
		err = mdb_tgt_lookup_by_name(t, mp->map_name, name, NULL, &si);

	if (err != 0)
		return (-1); /* errno is set for us */

	if (ctf_func_info(fp, si.sym_id, &f) == CTF_ERR)
		return (set_errno(ctf_to_errno(ctf_errno(fp))));

	set_ctf_id(&mfp->mtf_return, fp, f.ctc_return);
	mfp->mtf_argc = f.ctc_argc;
	mfp->mtf_flags = f.ctc_flags;
	mfp->mtf_symidx = si.sym_id;

	return (0);
}

int
mdb_ctf_func_args(const mdb_ctf_funcinfo_t *funcp, uint_t len,
    mdb_ctf_id_t *argv)
{
	ctf_file_t *fp;
	ctf_id_t cargv[32];
	int i;

	if (len > (sizeof (cargv) / sizeof (cargv[0])))
		return (set_errno(EINVAL));

	if (funcp == NULL || argv == NULL)
		return (set_errno(EINVAL));

	fp = mdb_ctf_type_file(funcp->mtf_return);

	if (ctf_func_args(fp, funcp->mtf_symidx, len, cargv) == CTF_ERR)
		return (set_errno(ctf_to_errno(ctf_errno(fp))));

	for (i = MIN(len, funcp->mtf_argc) - 1; i >= 0; i--) {
		set_ctf_id(&argv[i], fp, cargv[i]);
	}

	return (0);
}

void
mdb_ctf_type_invalidate(mdb_ctf_id_t *idp)
{
	set_ctf_id(idp, NULL, CTF_ERR);
}

int
mdb_ctf_type_valid(mdb_ctf_id_t id)
{
	return (((mdb_ctf_impl_t *)&id)->mci_id != CTF_ERR);
}

int
mdb_ctf_type_cmp(mdb_ctf_id_t aid, mdb_ctf_id_t bid)
{
	mdb_ctf_impl_t *aidp = (mdb_ctf_impl_t *)&aid;
	mdb_ctf_impl_t *bidp = (mdb_ctf_impl_t *)&bid;

	return (ctf_type_cmp(aidp->mci_fp, aidp->mci_id,
	    bidp->mci_fp, bidp->mci_id));
}

int
mdb_ctf_type_resolve(mdb_ctf_id_t mid, mdb_ctf_id_t *outp)
{
	ctf_id_t id;
	mdb_ctf_impl_t *idp = (mdb_ctf_impl_t *)&mid;

	if ((id = ctf_type_resolve(idp->mci_fp, idp->mci_id)) == CTF_ERR) {
		if (outp)
			mdb_ctf_type_invalidate(outp);
		return (set_errno(ctf_to_errno(ctf_errno(idp->mci_fp))));
	}

	if (ctf_type_kind(idp->mci_fp, id) == CTF_K_FORWARD) {
		char name[MDB_SYM_NAMLEN];
		mdb_ctf_id_t lookup_id;

		if (ctf_type_name(idp->mci_fp, id, name, sizeof (name)) !=
		    NULL &&
		    mdb_ctf_lookup_by_name(name, &lookup_id) == 0 &&
		    outp != NULL) {
			*outp = lookup_id;
			return (0);
		}
	}

	if (outp != NULL)
		set_ctf_id(outp, idp->mci_fp, id);

	return (0);
}

char *
mdb_ctf_type_name(mdb_ctf_id_t id, char *buf, size_t len)
{
	mdb_ctf_impl_t *idp = (mdb_ctf_impl_t *)&id;
	char *ret;

	if (!mdb_ctf_type_valid(id)) {
		(void) set_errno(EINVAL);
		return (NULL);
	}

	ret = ctf_type_name(idp->mci_fp, idp->mci_id, buf, len);
	if (ret == NULL)
		(void) set_errno(ctf_to_errno(ctf_errno(idp->mci_fp)));

	return (ret);
}

ssize_t
mdb_ctf_type_size(mdb_ctf_id_t id)
{
	mdb_ctf_impl_t *idp = (mdb_ctf_impl_t *)&id;
	ssize_t ret;

	/* resolve the type in case there's a forward declaration */
	if ((ret = mdb_ctf_type_resolve(id, &id)) != 0)
		return (ret);

	if ((ret = ctf_type_size(idp->mci_fp, idp->mci_id)) == CTF_ERR)
		return (set_errno(ctf_to_errno(ctf_errno(idp->mci_fp))));

	return (ret);
}

int
mdb_ctf_type_kind(mdb_ctf_id_t id)
{
	mdb_ctf_impl_t *idp = (mdb_ctf_impl_t *)&id;
	int ret;

	if ((ret = ctf_type_kind(idp->mci_fp, idp->mci_id)) == CTF_ERR)
		return (set_errno(ctf_to_errno(ctf_errno(idp->mci_fp))));

	return (ret);
}

int
mdb_ctf_type_reference(mdb_ctf_id_t mid, mdb_ctf_id_t *outp)
{
	mdb_ctf_impl_t *idp = (mdb_ctf_impl_t *)&mid;
	ctf_id_t id;

	if ((id = ctf_type_reference(idp->mci_fp, idp->mci_id)) == CTF_ERR) {
		if (outp)
			mdb_ctf_type_invalidate(outp);
		return (set_errno(ctf_to_errno(ctf_errno(idp->mci_fp))));
	}

	if (outp != NULL)
		set_ctf_id(outp, idp->mci_fp, id);

	return (0);
}


int
mdb_ctf_type_encoding(mdb_ctf_id_t id, ctf_encoding_t *ep)
{
	mdb_ctf_impl_t *idp = (mdb_ctf_impl_t *)&id;

	if (ctf_type_encoding(idp->mci_fp, idp->mci_id, ep) == CTF_ERR)
		return (set_errno(ctf_to_errno(ctf_errno(idp->mci_fp))));

	return (0);
}

/*
 * callback proxy for mdb_ctf_type_visit
 */
static int
type_cb(const char *name, ctf_id_t type, ulong_t off, int depth, void *arg)
{
	type_visit_t *tvp = arg;
	mdb_ctf_id_t id;
	mdb_ctf_id_t base;
	mdb_ctf_impl_t *basep = (mdb_ctf_impl_t *)&base;

	int ret;

	if (depth < tvp->tv_min_depth)
		return (0);

	off += tvp->tv_base_offset;
	depth += tvp->tv_base_depth;

	set_ctf_id(&id, tvp->tv_fp, type);

	(void) mdb_ctf_type_resolve(id, &base);
	if ((ret = tvp->tv_cb(name, id, base, off, depth, tvp->tv_arg)) != 0)
		return (ret);

	/*
	 * If the type resolves to a type in a different file, we must have
	 * followed a forward declaration.  We need to recurse into the
	 * new type.
	 */
	if (basep->mci_fp != tvp->tv_fp && mdb_ctf_type_valid(base)) {
		type_visit_t tv;

		tv.tv_cb = tvp->tv_cb;
		tv.tv_arg = tvp->tv_arg;
		tv.tv_fp = basep->mci_fp;

		tv.tv_base_offset = off;
		tv.tv_base_depth = depth;
		tv.tv_min_depth = 1;	/* depth = 0 has already been done */

		ret = ctf_type_visit(basep->mci_fp, basep->mci_id,
		    type_cb, &tv);
	}
	return (ret);
}

int
mdb_ctf_type_visit(mdb_ctf_id_t id, mdb_ctf_visit_f *func, void *arg)
{
	mdb_ctf_impl_t *idp = (mdb_ctf_impl_t *)&id;
	type_visit_t tv;
	int ret;

	tv.tv_cb = func;
	tv.tv_arg = arg;
	tv.tv_fp = idp->mci_fp;
	tv.tv_base_offset = 0;
	tv.tv_base_depth = 0;
	tv.tv_min_depth = 0;

	ret = ctf_type_visit(idp->mci_fp, idp->mci_id, type_cb, &tv);

	if (ret == CTF_ERR)
		return (set_errno(ctf_to_errno(ctf_errno(idp->mci_fp))));

	return (ret);
}

int
mdb_ctf_array_info(mdb_ctf_id_t id, mdb_ctf_arinfo_t *arp)
{
	mdb_ctf_impl_t *idp = (mdb_ctf_impl_t *)&id;
	ctf_arinfo_t car;

	if (ctf_array_info(idp->mci_fp, idp->mci_id, &car) == CTF_ERR)
		return (set_errno(ctf_to_errno(ctf_errno(idp->mci_fp))));

	set_ctf_id(&arp->mta_contents, idp->mci_fp, car.ctr_contents);
	set_ctf_id(&arp->mta_index, idp->mci_fp, car.ctr_index);

	arp->mta_nelems = car.ctr_nelems;

	return (0);
}

const char *
mdb_ctf_enum_name(mdb_ctf_id_t id, int value)
{
	mdb_ctf_impl_t *idp = (mdb_ctf_impl_t *)&id;
	const char *ret;

	/* resolve the type in case there's a forward declaration */
	if (mdb_ctf_type_resolve(id, &id) != 0)
		return (NULL);

	if ((ret = ctf_enum_name(idp->mci_fp, idp->mci_id, value)) == NULL)
		(void) set_errno(ctf_to_errno(ctf_errno(idp->mci_fp)));

	return (ret);
}

/*
 * callback proxy for mdb_ctf_member_iter
 */
static int
member_iter_cb(const char *name, ctf_id_t type, ulong_t off, void *data)
{
	member_iter_t *mip = data;
	mdb_ctf_id_t id;

	set_ctf_id(&id, mip->mi_fp, type);

	return (mip->mi_cb(name, id, off, mip->mi_arg));
}

int
mdb_ctf_member_iter(mdb_ctf_id_t id, mdb_ctf_member_f *cb, void *data)
{
	mdb_ctf_impl_t *idp = (mdb_ctf_impl_t *)&id;
	member_iter_t mi;
	int ret;

	/* resolve the type in case there's a forward declaration */
	if ((ret = mdb_ctf_type_resolve(id, &id)) != 0)
		return (ret);

	mi.mi_cb = cb;
	mi.mi_arg = data;
	mi.mi_fp = idp->mci_fp;

	ret = ctf_member_iter(idp->mci_fp, idp->mci_id, member_iter_cb, &mi);

	if (ret == CTF_ERR)
		return (set_errno(ctf_to_errno(ctf_errno(idp->mci_fp))));

	return (ret);
}

int
mdb_ctf_enum_iter(mdb_ctf_id_t id, mdb_ctf_enum_f *cb, void *data)
{
	mdb_ctf_impl_t *idp = (mdb_ctf_impl_t *)&id;
	int ret;

	/* resolve the type in case there's a forward declaration */
	if ((ret = mdb_ctf_type_resolve(id, &id)) != 0)
		return (ret);

	return (ctf_enum_iter(idp->mci_fp, idp->mci_id, cb, data));
}

/*
 * callback proxy for mdb_ctf_type_iter
 */
static int
type_iter_cb(ctf_id_t type, void *data)
{
	type_iter_t *tip = data;
	mdb_ctf_id_t id;

	set_ctf_id(&id, tip->ti_fp, type);

	return (tip->ti_cb(id, tip->ti_arg));
}

int
mdb_ctf_type_iter(const char *object, mdb_ctf_type_f *cb, void *data)
{
	ctf_file_t *fp;
	mdb_tgt_t *t = mdb.m_target;
	int ret;
	type_iter_t ti;

	if (object == MDB_CTF_SYNTHETIC_ITER)
		fp = mdb.m_synth;
	else
		fp = mdb_tgt_name_to_ctf(t, object);

	if (fp == NULL)
		return (-1);

	ti.ti_cb = cb;
	ti.ti_arg = data;
	ti.ti_fp = fp;

	if ((ret = ctf_type_iter(fp, type_iter_cb, &ti)) == CTF_ERR)
		return (set_errno(ctf_to_errno(ctf_errno(fp))));

	return (ret);
}

/* utility functions */

ctf_id_t
mdb_ctf_type_id(mdb_ctf_id_t id)
{
	return (((mdb_ctf_impl_t *)&id)->mci_id);
}

ctf_file_t *
mdb_ctf_type_file(mdb_ctf_id_t id)
{
	return (((mdb_ctf_impl_t *)&id)->mci_fp);
}

static int
member_info_cb(const char *name, mdb_ctf_id_t id, ulong_t off, void *data)
{
	mbr_info_t *mbrp = data;

	if (strcmp(name, mbrp->mbr_member) == 0) {
		if (mbrp->mbr_offp != NULL)
			*(mbrp->mbr_offp) = off;
		if (mbrp->mbr_typep != NULL)
			*(mbrp->mbr_typep) = id;

		return (1);
	}

	return (0);
}

int
mdb_ctf_member_info(mdb_ctf_id_t id, const char *member, ulong_t *offp,
    mdb_ctf_id_t *typep)
{
	mbr_info_t mbr;
	int rc;

	mbr.mbr_member = member;
	mbr.mbr_offp = offp;
	mbr.mbr_typep = typep;

	rc = mdb_ctf_member_iter(id, member_info_cb, &mbr);

	/* couldn't get member list */
	if (rc == -1)
		return (-1); /* errno is set for us */

	/* not a member */
	if (rc == 0)
		return (set_errno(EMDB_CTFNOMEMB));

	return (0);
}

/*
 * Returns offset in _bits_ in *retp.
 */
int
mdb_ctf_offsetof(mdb_ctf_id_t id, const char *member, ulong_t *retp)
{
	return (mdb_ctf_member_info(id, member, retp, NULL));
}

/*
 * Returns offset in _bytes_, or -1 on failure.
 */
int
mdb_ctf_offsetof_by_name(const char *type, const char *member)
{
	mdb_ctf_id_t id;
	ulong_t off;

	if (mdb_ctf_lookup_by_name(type, &id) == -1) {
		mdb_warn("couldn't find type %s", type);
		return (-1);
	}

	if (mdb_ctf_offsetof(id, member, &off) == -1) {
		mdb_warn("couldn't find member %s of type %s", member, type);
		return (-1);
	}
	if (off % 8 != 0) {
		mdb_warn("member %s of type %s is an unsupported bitfield\n",
		    member, type);
		return (-1);
	}
	off /= 8;

	return (off);
}


/*ARGSUSED*/
static int
num_members_cb(const char *name, mdb_ctf_id_t id, ulong_t off, void *data)
{
	int *count = data;
	*count = *count + 1;
	return (0);
}

int
mdb_ctf_num_members(mdb_ctf_id_t id)
{
	int count = 0;

	if (mdb_ctf_member_iter(id, num_members_cb, &count) != 0)
		return (-1); /* errno is set for us */

	return (count);
}

typedef struct mbr_contains {
	char **mbc_bufp;
	size_t *mbc_lenp;
	ulong_t *mbc_offp;
	mdb_ctf_id_t *mbc_idp;
	ssize_t mbc_total;
} mbr_contains_t;

static int
offset_to_name_cb(const char *name, mdb_ctf_id_t id, ulong_t off, void *data)
{
	mbr_contains_t *mbc = data;
	ulong_t size;
	ctf_encoding_t e;
	size_t n;

	if (*mbc->mbc_offp < off)
		return (0);

	if (mdb_ctf_type_encoding(id, &e) == -1)
		size = mdb_ctf_type_size(id) * NBBY;
	else
		size = e.cte_bits;

	if (off + size <= *mbc->mbc_offp)
		return (0);

	n = mdb_snprintf(*mbc->mbc_bufp, *mbc->mbc_lenp, "%s", name);
	mbc->mbc_total += n;
	if (n > *mbc->mbc_lenp)
		n = *mbc->mbc_lenp;

	*mbc->mbc_lenp -= n;
	*mbc->mbc_bufp += n;

	*mbc->mbc_offp -= off;
	*mbc->mbc_idp = id;

	return (1);
}

ssize_t
mdb_ctf_offset_to_name(mdb_ctf_id_t id, ulong_t off, char *buf, size_t len,
    int dot, mdb_ctf_id_t *midp, ulong_t *moffp)
{
	size_t size;
	size_t n;
	mbr_contains_t mbc;

	if (!mdb_ctf_type_valid(id))
		return (set_errno(EINVAL));

	/*
	 * Quick sanity check to make sure the given offset is within
	 * this scope of this type.
	 */
	if (mdb_ctf_type_size(id) * NBBY <= off)
		return (set_errno(EINVAL));

	mbc.mbc_bufp = &buf;
	mbc.mbc_lenp = &len;
	mbc.mbc_offp = &off;
	mbc.mbc_idp = &id;
	mbc.mbc_total = 0;

	*buf = '\0';

	for (;;) {
		/*
		 * Check for an exact match.
		 */
		if (off == 0)
			break;

		(void) mdb_ctf_type_resolve(id, &id);

		/*
		 * Find the member that contains this offset.
		 */
		switch (mdb_ctf_type_kind(id)) {
		case CTF_K_ARRAY: {
			mdb_ctf_arinfo_t ar;
			uint_t index;

			(void) mdb_ctf_array_info(id, &ar);
			size = mdb_ctf_type_size(ar.mta_contents) * NBBY;
			index = off / size;

			id = ar.mta_contents;
			off %= size;

			n = mdb_snprintf(buf, len, "[%u]", index);
			mbc.mbc_total += n;
			if (n > len)
				n = len;

			buf += n;
			len -= n;
			break;
		}

		case CTF_K_STRUCT: {
			int ret;

			/*
			 * Find the member that contains this offset
			 * and continue.
			 */

			if (dot) {
				mbc.mbc_total++;
				if (len != 0) {
					*buf++ = '.';
					*buf = '\0';
					len--;
				}
			}

			ret = mdb_ctf_member_iter(id, offset_to_name_cb, &mbc);
			if (ret == -1)
				return (-1); /* errno is set for us */

			/*
			 * If we did not find a member containing this offset
			 * (due to holes in the structure), return EINVAL.
			 */
			if (ret == 0)
				return (set_errno(EINVAL));

			break;
		}

		case CTF_K_UNION:
			/*
			 * Treat unions like atomic entities since we can't
			 * do more than guess which member of the union
			 * might be the intended one.
			 */
			goto done;

		case CTF_K_INTEGER:
		case CTF_K_FLOAT:
		case CTF_K_POINTER:
		case CTF_K_ENUM:
			goto done;

		default:
			return (set_errno(EINVAL));
		}

		dot = 1;
	}
done:
	if (midp != NULL)
		*midp = id;
	if (moffp != NULL)
		*moffp = off;

	return (mbc.mbc_total);
}

static void
mdb_ctf_warn(uint_t flags, const char *format, ...)
{
	va_list alist;

	if (flags & MDB_CTF_VREAD_QUIET)
		return;

	va_start(alist, format);
	vwarn(format, alist);
	va_end(alist);
}

/*
 * Check if two types are structurally the same rather than logically
 * the same. That is to say that two types are equal if they have the
 * same logical structure rather than having the same ids in CTF-land.
 */
static int type_equals(mdb_ctf_id_t, mdb_ctf_id_t);

static int
type_equals_cb(const char *name, mdb_ctf_id_t amem, ulong_t aoff, void *data)
{
	mdb_ctf_id_t b = *(mdb_ctf_id_t *)data;
	ulong_t boff;
	mdb_ctf_id_t bmem;

	/*
	 * Look up the corresponding member in the other composite type.
	 */
	if (mdb_ctf_member_info(b, name, &boff, &bmem) != 0)
		return (1);

	/*
	 * We don't allow members to be shuffled around.
	 */
	if (aoff != boff)
		return (1);

	return (type_equals(amem, bmem) ? 0 : 1);
}

static int
type_equals(mdb_ctf_id_t a, mdb_ctf_id_t b)
{
	size_t asz, bsz;
	int akind, bkind;
	mdb_ctf_arinfo_t aar, bar;

	/*
	 * Resolve both types down to their fundamental types, and make
	 * sure their sizes and kinds match.
	 */
	if (mdb_ctf_type_resolve(a, &a) != 0 ||
	    mdb_ctf_type_resolve(b, &b) != 0 ||
	    (asz = mdb_ctf_type_size(a)) == -1UL ||
	    (bsz = mdb_ctf_type_size(b)) == -1UL ||
	    (akind = mdb_ctf_type_kind(a)) == -1 ||
	    (bkind = mdb_ctf_type_kind(b)) == -1 ||
	    asz != bsz || akind != bkind) {
		return (0);
	}

	switch (akind) {
	case CTF_K_INTEGER:
	case CTF_K_FLOAT:
	case CTF_K_POINTER:
		/*
		 * For pointers we could be a little stricter and require
		 * both pointers to reference types which look vaguely
		 * similar (for example, we could insist that the two types
		 * have the same name). However, all we really care about
		 * here is that the structure of the two types are the same,
		 * and, in that regard, one pointer is as good as another.
		 */
		return (1);

	case CTF_K_UNION:
	case CTF_K_STRUCT:
		/*
		 * The test for the number of members is only strictly
		 * necessary for unions since we'll find other problems with
		 * structs. However, the extra check will do no harm.
		 */
		return (mdb_ctf_num_members(a) == mdb_ctf_num_members(b) &&
		    mdb_ctf_member_iter(a, type_equals_cb, &b) == 0);

	case CTF_K_ARRAY:
		return (mdb_ctf_array_info(a, &aar) == 0 &&
		    mdb_ctf_array_info(b, &bar) == 0 &&
		    aar.mta_nelems == bar.mta_nelems &&
		    type_equals(aar.mta_index, bar.mta_index) &&
		    type_equals(aar.mta_contents, bar.mta_contents));
	}

	return (0);
}


typedef struct member {
	char		*m_modbuf;
	char		*m_tgtbuf;
	const char	*m_tgtname;
	mdb_ctf_id_t	m_tgtid;
	uint_t		m_flags;
} member_t;

static int vread_helper(mdb_ctf_id_t, char *, mdb_ctf_id_t, char *,
    const char *, uint_t);

static int
member_cb(const char *name, mdb_ctf_id_t modmid, ulong_t modoff, void *data)
{
	member_t *mp = data;
	char *modbuf = mp->m_modbuf;
	mdb_ctf_id_t tgtmid;
	char *tgtbuf = mp->m_tgtbuf;
	ulong_t tgtoff;
	char tgtname[128];

	(void) mdb_snprintf(tgtname, sizeof (tgtname),
	    "member %s of type %s", name, mp->m_tgtname);

	if (mdb_ctf_member_info(mp->m_tgtid, name, &tgtoff, &tgtmid) != 0) {
		mdb_ctf_warn(mp->m_flags,
		    "could not find %s\n", tgtname);
		return (set_errno(EMDB_CTFNOMEMB));
	}

	return (vread_helper(modmid, modbuf + modoff / NBBY,
	    tgtmid, tgtbuf + tgtoff / NBBY, tgtname, mp->m_flags));
}

typedef struct enum_value {
	int		*ev_modbuf;
	const char	*ev_name;
} enum_value_t;

static int
enum_cb(const char *name, int value, void *data)
{
	enum_value_t *ev = data;

	if (strcmp(name, ev->ev_name) == 0) {
		*ev->ev_modbuf = value;
		return (1);
	}
	return (0);
}

static int
vread_helper(mdb_ctf_id_t modid, char *modbuf,
    mdb_ctf_id_t tgtid, char *tgtbuf, const char *tgtname, uint_t flags)
{
	size_t modsz, tgtsz;
	int modkind, tgtkind;
	member_t mbr;
	enum_value_t ev;
	int ret;
	mdb_ctf_arinfo_t tar, mar;
	int i;
	char typename[128];
	char mdbtypename[128];
	ctf_encoding_t tgt_encoding, mod_encoding;
	boolean_t signed_int = B_FALSE;

	if (mdb_ctf_type_name(tgtid, typename, sizeof (typename)) == NULL) {
		(void) mdb_snprintf(typename, sizeof (typename),
		    "#%ul", mdb_ctf_type_id(tgtid));
	}
	if (mdb_ctf_type_name(modid,
	    mdbtypename, sizeof (mdbtypename)) == NULL) {
		(void) mdb_snprintf(mdbtypename, sizeof (mdbtypename),
		    "#%ul", mdb_ctf_type_id(modid));
	}

	if (tgtname == NULL)
		tgtname = "";

	/*
	 * Resolve the types to their canonical form.
	 */
	(void) mdb_ctf_type_resolve(modid, &modid);
	(void) mdb_ctf_type_resolve(tgtid, &tgtid);

	if ((modkind = mdb_ctf_type_kind(modid)) == -1) {
		mdb_ctf_warn(flags,
		    "couldn't determine type kind of mdb module type %s\n",
		    mdbtypename);
		return (-1); /* errno is set for us */
	}
	if ((tgtkind = mdb_ctf_type_kind(tgtid)) == -1) {
		mdb_ctf_warn(flags,
		    "couldn't determine type kind of %s\n", typename);
		return (-1); /* errno is set for us */
	}

	if ((modsz = mdb_ctf_type_size(modid)) == -1UL) {
		mdb_ctf_warn(flags, "couldn't determine type size of "
		    "mdb module type %s\n", mdbtypename);
		return (-1); /* errno is set for us */
	}
	if ((tgtsz = mdb_ctf_type_size(tgtid)) == -1UL) {
		mdb_ctf_warn(flags, "couldn't determine size of %s (%s)\n",
		    typename, tgtname);
		return (-1); /* errno is set for us */
	}

	if (tgtkind == CTF_K_POINTER && modkind == CTF_K_INTEGER &&
	    strcmp(mdbtypename, "uintptr_t") == 0) {
		/* allow them to convert a pointer to a uintptr_t */
		ASSERT(modsz == tgtsz);
	} else if (tgtkind != modkind) {
		mdb_ctf_warn(flags, "unexpected kind for type %s (%s)\n",
		    typename, tgtname);
		return (set_errno(EMDB_INCOMPAT));
	}

	switch (tgtkind) {
	case CTF_K_INTEGER:
	case CTF_K_FLOAT:
		/*
		 * Must determine if the target and module types have the same
		 * encoding before we can copy them.
		 */
		if (mdb_ctf_type_encoding(tgtid, &tgt_encoding) != 0) {
			mdb_ctf_warn(flags,
			    "couldn't determine encoding of type %s (%s)\n",
			    typename, tgtname);
			return (-1); /* errno is set for us */
		}
		if (mdb_ctf_type_encoding(modid, &mod_encoding) != 0) {
			mdb_ctf_warn(flags, "couldn't determine encoding of "
			    "mdb module type %s\n", mdbtypename);
			return (-1); /* errno is set for us */
		}

		if (modkind == CTF_K_INTEGER) {
			if ((tgt_encoding.cte_format & CTF_INT_SIGNED) !=
			    (mod_encoding.cte_format & CTF_INT_SIGNED)) {
				mdb_ctf_warn(flags,
				    "signedness mismatch between type "
				    "%s (%s) and mdb module type %s\n",
				    typename, tgtname, mdbtypename);
				return (set_errno(EMDB_INCOMPAT));
			}
			signed_int =
			    ((tgt_encoding.cte_format & CTF_INT_SIGNED) != 0);
		} else if (tgt_encoding.cte_format != mod_encoding.cte_format) {
			mdb_ctf_warn(flags,
			    "encoding mismatch (%#x != %#x) between type "
			    "%s (%s) and mdb module type %s\n",
			    tgt_encoding.cte_format, mod_encoding.cte_format,
			    typename, tgtname, mdbtypename);
			return (set_errno(EMDB_INCOMPAT));
		}
		/* FALLTHROUGH */
	case CTF_K_POINTER:
		/*
		 * If the sizes don't match we need to be tricky to make
		 * sure that the caller gets the correct data.
		 */
		if (modsz < tgtsz) {
			mdb_ctf_warn(flags, "size of type %s (%s) is too "
			    "large for mdb module type %s\n",
			    typename, tgtname, mdbtypename);
			return (set_errno(EMDB_INCOMPAT));
		} else if (modsz > tgtsz) {
			/* BEGIN CSTYLED */
			/*
			 * Fill modbuf with 1's for sign extension if target
			 * buf is a signed integer and its value is negative.
			 *
			 *   S = sign bit (in most-significant byte)
			 *
			 *      BIG ENDIAN DATA
			 *    +--------+--------+--------+--------+
			 *    |S       |        |        |        |
			 *    +--------+--------+--------+--------+
			 *     0        1  ...            sz-1     sz
			 *
			 *      LITTLE ENDIAN DATA
			 *    +--------+--------+--------+--------+
			 *    |        |        |        |S       |
			 *    +--------+--------+--------+--------+
			 *     0        1  ...            sz-1     sz
			 */
			/* END CSTYLED */
#ifdef _BIG_ENDIAN
			if (signed_int && (tgtbuf[0] & 0x80) != 0)
#else
			if (signed_int && (tgtbuf[tgtsz - 1] & 0x80) != 0)
#endif
				(void) memset(modbuf, 0xFF, modsz);
			else
				bzero(modbuf, modsz);
#ifdef _BIG_ENDIAN
			bcopy(tgtbuf, modbuf + modsz - tgtsz, tgtsz);
#else
			bcopy(tgtbuf, modbuf, tgtsz);
#endif
		} else {
			bcopy(tgtbuf, modbuf, modsz);
		}

		return (0);

	case CTF_K_ENUM:
		if (modsz != tgtsz || modsz != sizeof (int)) {
			mdb_ctf_warn(flags, "unexpected size of type %s (%s)\n",
			    typename, tgtname);
			return (set_errno(EMDB_INCOMPAT));
		}

		/*
		 * Default to the same value as in the target.
		 */
		bcopy(tgtbuf, modbuf, sizeof (int));

		/* LINTED */
		i = *(int *)tgtbuf;

		/* LINTED */
		ev.ev_modbuf = (int *)modbuf;
		ev.ev_name = mdb_ctf_enum_name(tgtid, i);
		if (ev.ev_name == NULL) {
			mdb_ctf_warn(flags,
			    "unexpected value %u of enum type %s (%s)\n",
			    i, typename, tgtname);
			return (set_errno(EMDB_INCOMPAT));
		}

		ret = mdb_ctf_enum_iter(modid, enum_cb, &ev);
		if (ret == 0) {
			/* value not found */
			mdb_ctf_warn(flags,
			    "unexpected value %s (%u) of enum type %s (%s)\n",
			    ev.ev_name, i, typename, tgtname);
			return (set_errno(EMDB_INCOMPAT));
		} else if (ret == 1) {
			/* value found */
			return (0);
		} else if (ret == -1) {
			mdb_ctf_warn(flags, "could not iterate enum %s (%s)\n",
			    typename, tgtname);
		}
		return (ret);

	case CTF_K_STRUCT:
		mbr.m_modbuf = modbuf;
		mbr.m_tgtbuf = tgtbuf;
		mbr.m_tgtid = tgtid;
		mbr.m_flags = flags;
		mbr.m_tgtname = typename;

		return (mdb_ctf_member_iter(modid, member_cb, &mbr));

	case CTF_K_UNION:

		/*
		 * Unions are a little tricky. The only time it's truly
		 * safe to read in a union is if no part of the union or
		 * any of its component types have changed.  The correct
		 * use of this feature is to read the containing structure,
		 * figure out which component of the union is valid, compute
		 * the location of that in the target and then read in
		 * that part of the structure.
		 */

		if (!type_equals(modid, tgtid)) {
			mdb_ctf_warn(flags, "inexact match for union %s (%s)\n",
			    typename, tgtname);
			return (set_errno(EMDB_INCOMPAT));
		}

		ASSERT(modsz == tgtsz);

		bcopy(tgtbuf, modbuf, modsz);

		return (0);

	case CTF_K_ARRAY:
		if (mdb_ctf_array_info(tgtid, &tar) != 0) {
			mdb_ctf_warn(flags,
			    "couldn't get array info for %s (%s)\n",
			    typename, tgtname);
			return (-1); /* errno is set for us */
		}
		if (mdb_ctf_array_info(modid, &mar) != 0) {
			mdb_ctf_warn(flags,
			    "couldn't get array info for mdb module type %s\n",
			    mdbtypename);
			return (-1); /* errno is set for us */
		}

		if (tar.mta_nelems != mar.mta_nelems) {
			mdb_ctf_warn(flags,
			    "unexpected array size (%u) for type %s (%s)\n",
			    tar.mta_nelems, typename, tgtname);
			return (set_errno(EMDB_INCOMPAT));
		}

		if ((modsz = mdb_ctf_type_size(mar.mta_contents)) == -1UL) {
			mdb_ctf_warn(flags, "couldn't determine type size of "
			    "mdb module type %s\n", mdbtypename);
			return (-1); /* errno is set for us */
		}
		if ((tgtsz = mdb_ctf_type_size(tar.mta_contents)) == -1UL) {
			mdb_ctf_warn(flags,
			    "couldn't determine size of %s (%s)\n",
			    typename, tgtname);
			return (-1); /* errno is set for us */
		}

		for (i = 0; i < tar.mta_nelems; i++) {
			ret = vread_helper(mar.mta_contents, modbuf + i * modsz,
			    tar.mta_contents, tgtbuf + i * tgtsz,
			    tgtname, flags);

			if (ret != 0)
				return (ret);
		}

		return (0);
	}

	mdb_ctf_warn(flags, "unsupported kind %d for type %s (%s)\n",
	    modkind, typename, tgtname);
	return (set_errno(EMDB_INCOMPAT));
}

/*
 * Like mdb_vread(), mdb_ctf_vread() is used to read from the target's
 * virtual address space.  However, mdb_ctf_vread() can be used to safely
 * read a complex type (e.g. a struct) from the target, even if MDB was compiled
 * against a different definition of that type (e.g. when debugging a crash
 * dump from an older release).
 *
 * Callers can achieve this by defining their own type which corresponds to the
 * type in the target, but contains only the members that the caller requires.
 * Using the CTF type information embedded in the target, mdb_ctf_vread will
 * find the required members in the target and fill in the caller's structure.
 * The members are located by name, and their types are verified to be
 * compatible.
 *
 * By convention, the caller will declare a type with the name "mdb_<type>",
 * where <type> is the name of the type in the target (e.g. mdb_zio_t).  This
 * type will contain the members that the caller is interested in.  For example:
 *
 * typedef struct mdb_zio {
 *         enum zio_type io_type;
 *         void *io_waiter;
 *         struct {
 *                 struct {
 *                         void *list_next;
 *                 } list_head;
 *         } io_parent_list;
 *         int io_error;
 * } mdb_zio_t;
 *
 * mdb_zio_t zio;
 * error = mdb_ctf_vread(&zio, "zio_t", "mdb_zio_t", zio_target_addr, 0);
 *
 * If a given MDB module has different dcmds or walkers that need to read
 * different members from the same struct, then different "mdb_" types
 * should be declared for each caller.  By convention, these types should
 * be named "mdb_<dcmd or walker>_<type>", e.g. mdb_findstack_kthread_t
 * for ::findstack.  If the MDB module is compiled from several source files,
 * one must be especially careful to not define different types with the
 * same name in different source files, because the compiler can not detect
 * this error.
 *
 * Enums will also be translated by name, so the mdb module will receive
 * the enum value it expects even if the target has renumbered the enum.
 * Warning: it will therefore only work with enums are only used to store
 * legitimate enum values (not several values or-ed together).
 *
 * By default, if mdb_ctf_vread() can not find any members or enum values,
 * it will print a descriptive message (with mdb_warn()) and fail.
 * Passing MDB_CTF_VREAD_QUIET in 'flags' will suppress the warning message.
 * Additional flags can be used to ignore specific types of translation
 * failure, but should be used with caution, because they will silently leave
 * the caller's buffer uninitialized.
 */
int
mdb_ctf_vread(void *modbuf, const char *target_typename,
    const char *mdb_typename, uintptr_t addr, uint_t flags)
{
	ctf_file_t *mfp;
	ctf_id_t mid;
	void *tgtbuf;
	size_t size;
	mdb_ctf_id_t tgtid;
	mdb_ctf_id_t modid;
	mdb_module_t *mod;

	if ((mod = mdb_get_module()) == NULL || (mfp = mod->mod_ctfp) == NULL) {
		mdb_ctf_warn(flags, "no ctf data found for mdb module %s\n",
		    mod->mod_name);
		return (set_errno(EMDB_NOCTF));
	}

	if ((mid = ctf_lookup_by_name(mfp, mdb_typename)) == CTF_ERR) {
		mdb_ctf_warn(flags, "couldn't find ctf data for "
		    "type %s in mdb module %s\n",
		    mdb_typename, mod->mod_name);
		return (set_errno(ctf_to_errno(ctf_errno(mfp))));
	}

	set_ctf_id(&modid, mfp, mid);

	if (mdb_ctf_lookup_by_name(target_typename, &tgtid) != 0) {
		mdb_ctf_warn(flags,
		    "couldn't find type %s in target's ctf data\n",
		    target_typename);
		return (set_errno(EMDB_NOCTF));
	}

	/*
	 * Read the data out of the target's address space.
	 */
	if ((size = mdb_ctf_type_size(tgtid)) == -1UL) {
		mdb_ctf_warn(flags, "couldn't determine size of type %s\n",
		    target_typename);
		return (-1); /* errno is set for us */
	}

	tgtbuf = mdb_alloc(size, UM_SLEEP | UM_GC);

	if (mdb_vread(tgtbuf, size, addr) < 0) {
		mdb_ctf_warn(flags, "couldn't read %s from %p\n",
		    target_typename, addr);
		return (-1); /* errno is set for us */
	}

	return (vread_helper(modid, modbuf, tgtid, tgtbuf, NULL, flags));
}

/*
 * Note: mdb_ctf_readsym() doesn't take separate parameters for the name
 * of the target's type vs the mdb module's type.  Use with complicated
 * types (e.g. structs) may result in unnecessary failure if a member of
 * the struct has been changed in the target, but is not actually needed
 * by the mdb module.  Use mdb_lookup_by_name() + mdb_ctf_vread() to
 * avoid this problem.
 */
int
mdb_ctf_readsym(void *buf, const char *typename, const char *name, uint_t flags)
{
	GElf_Sym sym;

	if (mdb_lookup_by_obj(MDB_TGT_OBJ_EVERY, name, &sym) != 0) {
		mdb_ctf_warn(flags, "couldn't find symbol %s\n", name);
		return (-1); /* errno is set for us */
	}

	return (mdb_ctf_vread(buf, typename, typename, sym.st_value, flags));
}

ctf_file_t *
mdb_ctf_bufopen(const void *ctf_va, size_t ctf_size, const void *sym_va,
    Shdr *symhdr, const void *str_va, Shdr *strhdr, int *errp)
{
	ctf_sect_t ctdata, symtab, strtab;

	ctdata.cts_name = ".SUNW_ctf";
	ctdata.cts_type = SHT_PROGBITS;
	ctdata.cts_flags = 0;
	ctdata.cts_data = ctf_va;
	ctdata.cts_size = ctf_size;
	ctdata.cts_entsize = 1;
	ctdata.cts_offset = 0;

	symtab.cts_name = ".symtab";
	symtab.cts_type = symhdr->sh_type;
	symtab.cts_flags = symhdr->sh_flags;
	symtab.cts_data = sym_va;
	symtab.cts_size = symhdr->sh_size;
	symtab.cts_entsize = symhdr->sh_entsize;
	symtab.cts_offset = symhdr->sh_offset;

	strtab.cts_name = ".strtab";
	strtab.cts_type = strhdr->sh_type;
	strtab.cts_flags = strhdr->sh_flags;
	strtab.cts_data = str_va;
	strtab.cts_size = strhdr->sh_size;
	strtab.cts_entsize = strhdr->sh_entsize;
	strtab.cts_offset = strhdr->sh_offset;

	return (ctf_bufopen(&ctdata, &symtab, &strtab, errp));
}

int
mdb_ctf_synthetics_init(void)
{
	int err;

	if ((mdb.m_synth = ctf_create(&err)) == NULL)
		return (set_errno(ctf_to_errno(err)));

	return (0);
}

void
mdb_ctf_synthetics_fini(void)
{
	if (mdb.m_synth == NULL)
		return;

	ctf_close(mdb.m_synth);
	mdb.m_synth = NULL;
}

int
mdb_ctf_synthetics_create_base(int kind)
{
	const synth_intrinsic_t *synp;
	const synth_typedef_t *sytp;
	int err;
	ctf_id_t id;
	ctf_file_t *cp = mdb.m_synth;

	if (mdb.m_synth == NULL) {
		mdb_printf("synthetic types disabled: ctf create failed\n");
		return (1);
	}

	switch (kind) {
	case SYNTHETIC_ILP32:
		synp = synth_builtins32;
		sytp = synth_typedefs32;
		break;
	case SYNTHETIC_LP64:
		synp = synth_builtins64;
		sytp = synth_typedefs64;
		break;
	default:
		mdb_dprintf(MDB_DBG_CTF, "invalid type of intrinsic: %d\n",
		    kind);
		return (1);
	}

	err = 0;
	for (; synp->syn_name != NULL; synp++) {
		if (synp->syn_kind == CTF_K_INTEGER) {
			err = ctf_add_integer(cp, CTF_ADD_ROOT, synp->syn_name,
			    &synp->syn_enc);
		} else {
			err = ctf_add_float(cp, CTF_ADD_ROOT, synp->syn_name,
			    &synp->syn_enc);
		}

		if (err == CTF_ERR) {
			mdb_dprintf(MDB_DBG_CTF, "couldn't add synthetic "
			    "type: %s\n", synp->syn_name);
			goto discard;
		}
	}

	if (ctf_update(cp) == CTF_ERR) {
		mdb_dprintf(MDB_DBG_CTF, "failed to update synthetic types\n");
		goto discard;
	}

	for (; sytp->syt_src != NULL; sytp++) {
		id = ctf_lookup_by_name(cp, sytp->syt_src);
		if (id == CTF_ERR) {
			mdb_dprintf(MDB_DBG_CTF, "cailed to lookup %s: %s\n",
			    sytp->syt_src, ctf_errmsg(ctf_errno(cp)));
			goto discard;
		}
		if (ctf_add_typedef(cp, CTF_ADD_ROOT, sytp->syt_targ, id) ==
		    CTF_ERR) {
			mdb_dprintf(MDB_DBG_CTF, "couldn't add typedef %s "
			    "%s: %s\n", sytp->syt_targ, sytp->syt_src,
			    ctf_errmsg(ctf_errno(cp)));
			goto discard;
		}
	}

	if (ctf_update(cp) == CTF_ERR) {
		mdb_dprintf(MDB_DBG_CTF, "failed to update synthetic types\n");
		goto discard;
	}

	return (0);

discard:
	err = set_errno(ctf_to_errno(ctf_errno(cp)));
	(void) ctf_discard(cp);
	return (err);
}

int
mdb_ctf_synthetics_reset(void)
{
	mdb_ctf_synthetics_fini();
	return (mdb_ctf_synthetics_init());
}

int
mdb_ctf_add_typedef(const char *name, const mdb_ctf_id_t *p, mdb_ctf_id_t *new)
{
	ctf_id_t rid;
	mdb_ctf_id_t tid;
	mdb_ctf_impl_t *mcip = (mdb_ctf_impl_t *)p;

	if (mdb.m_synth == NULL) {
		mdb_printf("synthetic types disabled: ctf create failed\n");
		return (1);
	}

	if (mdb_ctf_lookup_by_name(name, &tid) == 0) {
		mdb_dprintf(MDB_DBG_CTF, "failed to add type %s: a type "
		    "with that name already exists\n", name);
		return (set_errno(EEXIST));
	}

	rid = ctf_add_type(mdb.m_synth, mcip->mci_fp, mcip->mci_id);
	if (rid == CTF_ERR) {
		mdb_dprintf(MDB_DBG_CTF, "failed to add reference type: %s\n",
		    ctf_errmsg(ctf_errno(mdb.m_synth)));
		return (set_errno(ctf_to_errno(ctf_errno(mdb.m_synth))));
	}
	rid = ctf_add_typedef(mdb.m_synth, CTF_ADD_ROOT, name, rid);
	if (rid == CTF_ERR) {
		mdb_dprintf(MDB_DBG_CTF, "failed to add typedef: %s",
		    ctf_errmsg(ctf_errno(mdb.m_synth)));
		return (set_errno(ctf_to_errno(ctf_errno(mdb.m_synth))));
	}

	if (ctf_update(mdb.m_synth) == CTF_ERR) {
		mdb_dprintf(MDB_DBG_CTF, "failed to update synthetic types: %s",
		    ctf_errmsg(ctf_errno(mdb.m_synth)));
		return (set_errno(ctf_to_errno(ctf_errno(mdb.m_synth))));
	}

	if (new != NULL)
		set_ctf_id(new, mdb.m_synth, rid);

	return (0);
}

int
mdb_ctf_add_struct(const char *name, mdb_ctf_id_t *rid)
{
	mdb_ctf_id_t tid;
	ctf_id_t id;

	if (mdb.m_synth == NULL) {
		mdb_printf("synthetic types disabled: ctf create failed\n");
		return (1);
	}

	if (name != NULL && mdb_ctf_lookup_by_name(name, &tid) == 0) {
		mdb_dprintf(MDB_DBG_CTF, "failed to add type %s: a type "
		    "with that name already exists\n", name);
		return (set_errno(EEXIST));
	}

	if ((id = ctf_add_struct(mdb.m_synth, CTF_ADD_ROOT, name)) ==
	    CTF_ERR) {
		mdb_dprintf(MDB_DBG_CTF, "failed to add struct: %s\n",
		    ctf_errmsg(ctf_errno(mdb.m_synth)));
		return (set_errno(ctf_to_errno(ctf_errno(mdb.m_synth))));
	}

	if (ctf_update(mdb.m_synth) == CTF_ERR) {
		mdb_dprintf(MDB_DBG_CTF, "failed to update synthetic types: %s",
		    ctf_errmsg(ctf_errno(mdb.m_synth)));
		return (set_errno(ctf_to_errno(ctf_errno(mdb.m_synth))));
	}

	if (rid != NULL)
		set_ctf_id(rid, mdb.m_synth, id);

	return (0);
}

int
mdb_ctf_add_union(const char *name, mdb_ctf_id_t *rid)
{
	mdb_ctf_id_t tid;
	ctf_id_t id;

	if (mdb.m_synth == NULL) {
		mdb_printf("synthetic types disabled: ctf create failed\n");
		return (1);
	}

	if (name != NULL && mdb_ctf_lookup_by_name(name, &tid) == 0) {
		mdb_dprintf(MDB_DBG_CTF, "failed to add type %s: a type "
		    "with that name already exists\n", name);
		return (set_errno(EEXIST));
	}

	if ((id = ctf_add_union(mdb.m_synth, CTF_ADD_ROOT, name)) ==
	    CTF_ERR) {
		mdb_dprintf(MDB_DBG_CTF, "failed to add union: %s\n",
		    ctf_errmsg(ctf_errno(mdb.m_synth)));
		return (set_errno(ctf_to_errno(ctf_errno(mdb.m_synth))));
	}

	if (ctf_update(mdb.m_synth) == CTF_ERR) {
		mdb_dprintf(MDB_DBG_CTF, "failed to update synthetic types: %s",
		    ctf_errmsg(ctf_errno(mdb.m_synth)));
		return (set_errno(ctf_to_errno(ctf_errno(mdb.m_synth))));
	}

	if (rid != NULL)
		set_ctf_id(rid, mdb.m_synth, id);

	return (0);
}

int
mdb_ctf_add_member(const mdb_ctf_id_t *p, const char *name,
    const mdb_ctf_id_t *mtype, mdb_ctf_id_t *rid)
{
	ctf_id_t id, mtid;
	mdb_ctf_impl_t *mcip = (mdb_ctf_impl_t *)p;
	mdb_ctf_impl_t *mcim = (mdb_ctf_impl_t *)mtype;

	if (mdb.m_synth == NULL) {
		mdb_printf("synthetic types disabled: ctf create failed\n");
		return (DCMD_ERR);
	}

	if (mcip->mci_fp != mdb.m_synth) {
		mdb_dprintf(MDB_DBG_CTF, "requested to add member to a type "
		    "that wasn't created from a synthetic\n");
		return (set_errno(EINVAL));
	}

	mtid = ctf_add_type(mdb.m_synth, mcim->mci_fp, mcim->mci_id);
	if (mtid == CTF_ERR) {
		mdb_dprintf(MDB_DBG_CTF, "failed to add member type: %s\n",
		    ctf_errmsg(ctf_errno(mdb.m_synth)));
		return (set_errno(ctf_to_errno(ctf_errno(mdb.m_synth))));
	}

	if (ctf_update(mdb.m_synth) == CTF_ERR) {
		mdb_dprintf(MDB_DBG_CTF, "failed to update synthetic types: %s",
		    ctf_errmsg(ctf_errno(mdb.m_synth)));
		return (set_errno(ctf_to_errno(ctf_errno(mdb.m_synth))));
	}

	id = ctf_add_member(mdb.m_synth, mcip->mci_id, name, mtid);
	if (id == CTF_ERR) {
		mdb_dprintf(MDB_DBG_CTF, "failed to add member %s: %s\n",
		    name, ctf_errmsg(ctf_errno(mdb.m_synth)));
		return (set_errno(ctf_to_errno(ctf_errno(mdb.m_synth))));
	}

	if (ctf_update(mdb.m_synth) == CTF_ERR) {
		mdb_dprintf(MDB_DBG_CTF, "failed to update synthetic types: %s",
		    ctf_errmsg(ctf_errno(mdb.m_synth)));
		return (set_errno(ctf_to_errno(ctf_errno(mdb.m_synth))));
	}

	if (rid != NULL)
		set_ctf_id(rid, mdb.m_synth, id);

	return (0);
}

int
mdb_ctf_add_array(const mdb_ctf_arinfo_t *marp, mdb_ctf_id_t *rid)
{
	mdb_ctf_impl_t *mcip;
	ctf_arinfo_t car;
	ctf_id_t id;

	if (mdb.m_synth == NULL) {
		mdb_printf("synthetic types disabled: ctf create failed\n");
		return (1);
	}

	car.ctr_nelems = marp->mta_nelems;

	mcip = (mdb_ctf_impl_t *)&marp->mta_contents;
	id = ctf_add_type(mdb.m_synth, mcip->mci_fp, mcip->mci_id);
	if (id == CTF_ERR) {
		mdb_dprintf(MDB_DBG_CTF, "failed to add member type: %s\n",
		    ctf_errmsg(ctf_errno(mdb.m_synth)));
		return (set_errno(ctf_to_errno(ctf_errno(mdb.m_synth))));
	}
	car.ctr_contents = id;

	mcip = (mdb_ctf_impl_t *)&marp->mta_index;
	id = ctf_add_type(mdb.m_synth, mcip->mci_fp, mcip->mci_id);
	if (id == CTF_ERR) {
		mdb_dprintf(MDB_DBG_CTF, "failed to add member type: %s\n",
		    ctf_errmsg(ctf_errno(mdb.m_synth)));
		return (set_errno(ctf_to_errno(ctf_errno(mdb.m_synth))));
	}
	car.ctr_index = id;

	if (ctf_update(mdb.m_synth) == CTF_ERR) {
		mdb_dprintf(MDB_DBG_CTF, "failed to update synthetic types: %s",
		    ctf_errmsg(ctf_errno(mdb.m_synth)));
		return (set_errno(ctf_to_errno(ctf_errno(mdb.m_synth))));
	}

	id = ctf_add_array(mdb.m_synth, CTF_ADD_ROOT, &car);
	if (id == CTF_ERR) {
		mdb_dprintf(MDB_DBG_CTF, "failed to update synthetic types: %s",
		    ctf_errmsg(ctf_errno(mdb.m_synth)));
		return (set_errno(ctf_to_errno(ctf_errno(mdb.m_synth))));
	}

	if (ctf_update(mdb.m_synth) == CTF_ERR) {
		mdb_dprintf(MDB_DBG_CTF, "failed to update synthetic types: %s",
		    ctf_errmsg(ctf_errno(mdb.m_synth)));
		return (set_errno(ctf_to_errno(ctf_errno(mdb.m_synth))));
	}

	if (rid != NULL)
		set_ctf_id(rid, mdb.m_synth, id);

	return (0);
}

int
mdb_ctf_add_pointer(const mdb_ctf_id_t *p, mdb_ctf_id_t *rid)
{
	ctf_id_t id;
	mdb_ctf_impl_t *mcip = (mdb_ctf_impl_t *)p;

	if (mdb.m_synth == NULL) {
		mdb_printf("synthetic types disabled: ctf create failed\n");
		return (1);
	}

	id = ctf_add_type(mdb.m_synth, mcip->mci_fp, mcip->mci_id);
	if (id == CTF_ERR) {
		mdb_dprintf(MDB_DBG_CTF, "failed to add pointer type: %s\n",
		    ctf_errmsg(ctf_errno(mdb.m_synth)));
		return (set_errno(ctf_to_errno(ctf_errno(mdb.m_synth))));
	}

	if (ctf_update(mdb.m_synth) == CTF_ERR) {
		mdb_dprintf(MDB_DBG_CTF, "failed to update synthetic types: %s",
		    ctf_errmsg(ctf_errno(mdb.m_synth)));
		return (set_errno(ctf_to_errno(ctf_errno(mdb.m_synth))));
	}


	id = ctf_add_pointer(mdb.m_synth, CTF_ADD_ROOT, id);
	if (id == CTF_ERR) {
		mdb_dprintf(MDB_DBG_CTF, "failed to add pointer: %s\n",
		    ctf_errmsg(ctf_errno(mdb.m_synth)));
		return (set_errno(ctf_to_errno(ctf_errno(mdb.m_synth))));
	}

	if (ctf_update(mdb.m_synth) == CTF_ERR) {
		mdb_dprintf(MDB_DBG_CTF, "failed to update synthetic types: %s",
		    ctf_errmsg(ctf_errno(mdb.m_synth)));
		return (set_errno(ctf_to_errno(ctf_errno(mdb.m_synth))));
	}


	if (rid != NULL)
		set_ctf_id(rid, mdb.m_synth, id);

	return (0);
}

int
mdb_ctf_type_delete(const mdb_ctf_id_t *id)
{
	int ret;

	mdb_ctf_impl_t *mcip = (mdb_ctf_impl_t *)id;

	if (mcip->mci_fp != mdb.m_synth) {
		mdb_warn("bad ctf_file_t, expected synth container\n");
		return (1);
	}

	ret = ctf_delete_type(mcip->mci_fp, mcip->mci_id);
	if (ret != 0) {
		mdb_dprintf(MDB_DBG_CTF, "failed to delete synthetic type: %s",
		    ctf_errmsg(ctf_errno(mdb.m_synth)));
		return (set_errno(ctf_to_errno(ctf_errno(mdb.m_synth))));
	}

	if (ctf_update(mdb.m_synth) == CTF_ERR) {
		mdb_dprintf(MDB_DBG_CTF, "failed to update synthetic types: %s",
		    ctf_errmsg(ctf_errno(mdb.m_synth)));
		return (set_errno(ctf_to_errno(ctf_errno(mdb.m_synth))));
	}

	return (0);
}

static int
mdb_ctf_synthetics_file_cb(mdb_ctf_id_t id, void *arg)
{
	ctf_file_t *targ = arg;
	mdb_ctf_impl_t *mcip = (mdb_ctf_impl_t *)&id;

	if (ctf_add_type(targ, mcip->mci_fp, mcip->mci_id) == CTF_ERR) {
		mdb_dprintf(MDB_DBG_CTF, "failed to add type %d: %s\n",
		    mcip->mci_id, ctf_errmsg(ctf_errno(mcip->mci_fp)));
		return (set_errno(ctf_to_errno(ctf_errno(mcip->mci_fp))));
	}

	return (0);
}

int
mdb_ctf_synthetics_from_file(const char *file)
{
	ctf_file_t *fp, *syn = mdb.m_synth;
	int ret;
	type_iter_t ti;

	if (syn == NULL) {
		mdb_warn("synthetic types disabled: ctf create failed\n");
		return (1);
	}

	if ((fp = mdb_ctf_open(file, &ret)) == NULL) {
		mdb_warn("failed to parse ctf data in %s", file);
		return (1);
	}

	ret = DCMD_OK;
	ti.ti_fp = fp;
	ti.ti_arg = syn;
	ti.ti_cb = mdb_ctf_synthetics_file_cb;
	if (ctf_type_iter(fp, type_iter_cb, &ti) == CTF_ERR) {
		ret = set_errno(ctf_to_errno(ctf_errno(fp)));
		mdb_warn("failed to add types");
		goto cleanup;
	}

	if (ctf_update(syn) == CTF_ERR) {
		mdb_dprintf(MDB_DBG_CTF, "failed to update synthetic types\n");
		ret = set_errno(ctf_to_errno(ctf_errno(fp)));
	}

cleanup:
	ctf_close(fp);
	if (ret != 0)
		(void) ctf_discard(syn);
	return (ret);
}
