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
 * Copyright (c) 2019, Joyent, Inc.
 */

/*
 * Collection of common utilities for CTF testing.
 */

#include <strings.h>
#include <libctf.h>
#include "check-common.h"

typedef struct ctftests_lookup_cb {
	ctf_file_t *clc_fp;
	ctf_id_t clc_id;
	const char *clc_name;
} ctftests_lookup_cb_t;

typedef struct ctftest_member_cb {
	ctf_file_t *cmc_fp;
	const check_member_t *cmc_members;
	const char *cmc_name;
} ctftest_member_cb_t;

static int
ctftest_lookup_type_cb(ctf_id_t id, boolean_t root, void *arg)
{
	char buf[2048];
	ctftests_lookup_cb_t *clc = arg;

	if (ctf_type_name(clc->clc_fp, id, buf, sizeof (buf)) == NULL)
		return (0);

	if (strcmp(buf, clc->clc_name) != 0)
		return (0);

	clc->clc_id = id;
	return (1);
}

/*
 * This is a variant on the classic ctf_lookup_by_name(). ctf_lookup_by_name()
 * skips qualifiers, which makes sense given what the consumers of it are trying
 * to do. However, that's not what we want here. So instead we basically have to
 * walk the type table.
 */
static ctf_id_t
ctftest_lookup_type(ctf_file_t *fp, const char *name)
{
	ctftests_lookup_cb_t clc;

	clc.clc_fp = fp;
	clc.clc_id = CTF_ERR;
	clc.clc_name = name;

	(void) ctf_type_iter(fp, B_TRUE, ctftest_lookup_type_cb, &clc);
	return (clc.clc_id);
}

static int
ctftest_lookup_object_cb(const char *obj, ctf_id_t type, ulong_t idx, void *arg)
{
	ctftests_lookup_cb_t *clc = arg;

	if (strcmp(obj, clc->clc_name) == 0) {
		clc->clc_id = type;
		return (1);
	}

	return (0);
}

static ctf_id_t
ctftest_lookup_symbol(ctf_file_t *fp, const char *name)
{
	ctftests_lookup_cb_t clc;

	clc.clc_fp = fp;
	clc.clc_id = CTF_ERR;
	clc.clc_name = name;

	(void) ctf_object_iter(fp, ctftest_lookup_object_cb, &clc);
	return (clc.clc_id);
}

typedef struct ctf_function_cb {
	const char *cfc_name;
	ulong_t *cfc_symp;
	ctf_funcinfo_t *cfc_fip;
} ctf_function_cb_t;

static int
ctftest_lookup_function_cb(const char *name, ulong_t symidx,
    ctf_funcinfo_t *fip, void *arg)
{
	ctf_function_cb_t *cfc = arg;
	if (strcmp(name, cfc->cfc_name) != 0)
		return (0);

	*cfc->cfc_symp = symidx;
	*cfc->cfc_fip = *fip;

	return (1);
}

/*
 * Note, this function finds the first one with a matching name. This must not
 * be used when performing searches where a given name may occur more than once.
 */
static boolean_t
ctftest_lookup_function(ctf_file_t *fp, const char *name, ulong_t *symp,
    ctf_funcinfo_t *fip)
{
	ctf_function_cb_t cfc;

	*symp = 0;
	cfc.cfc_name = name;
	cfc.cfc_symp = symp;
	cfc.cfc_fip = fip;
	(void) ctf_function_iter(fp, ctftest_lookup_function_cb, &cfc);
	return (*symp == 0 ? B_FALSE : B_TRUE);
}

boolean_t
ctftest_check_numbers(ctf_file_t *fp, const check_number_t *tests)
{
	uint_t i;
	boolean_t ret = B_TRUE;

	for (i = 0; tests[i].cn_tname != NULL; i++) {
		ctf_id_t id;
		ctf_encoding_t enc;

		id = ctftest_lookup_type(fp, tests[i].cn_tname);
		if (id == CTF_ERR) {
			warnx("failed to look up %s", tests[i].cn_tname);
			ret = B_FALSE;
			continue;
		}

		if (ctf_type_kind(fp, id) != tests[i].cn_kind) {
			warnx("type kind mismatch for %s: got %u, expected %u",
			    tests[i].cn_tname, ctf_type_kind(fp, id),
			    tests[i].cn_kind);
			ret = B_FALSE;
			continue;
		}

		if (ctf_type_encoding(fp, id, &enc) == CTF_ERR) {
			warnx("failed to get type encoding for %s: %s",
			    tests[i].cn_tname, ctf_errmsg(ctf_errno(fp)));
			ret = B_FALSE;
			continue;
		}

		if (enc.cte_format != tests[i].cn_flags) {
			warnx("encoding flags mismatch for %s: got 0x%x, "
			    "expected 0x%x", tests[i].cn_tname, enc.cte_format,
			    tests[i].cn_flags);
			ret = B_FALSE;
			continue;
		}

		if (enc.cte_offset != tests[i].cn_offset) {
			warnx("encoding offset mismatch for %s: got 0x%x, "
			    "expected 0x%x", tests[i].cn_tname, enc.cte_offset,
			    tests[i].cn_offset);
			ret = B_FALSE;
			continue;
		}

		if (enc.cte_bits != tests[i].cn_size) {
			warnx("encoding size mismatch for %s: got 0x%x, "
			    "expected 0x%x", tests[i].cn_tname, enc.cte_bits,
			    tests[i].cn_size);
			ret = B_FALSE;
			continue;
		}
	}

	return (ret);
}

typedef struct ctftests_symbol_cb {
	ctf_file_t	*csc_fp;
	boolean_t	csc_ret;
	const check_symbol_t *csc_tests;
} ctftest_symbol_cb_t;

static int
ctftest_check_symbol_cb(const char *obj, ctf_id_t type, ulong_t idx, void *arg)
{
	ctftest_symbol_cb_t *cb = arg;
	const check_symbol_t *tests = cb->csc_tests;
	ctf_file_t *fp = cb->csc_fp;
	uint_t i;

	for (i = 0; tests[i].cs_symbol != NULL; i++) {
		ctf_id_t id;

		if (strcmp(obj, tests[i].cs_symbol) != 0)
			continue;

		id = ctftest_lookup_type(fp, tests[i].cs_type);
		if (id == CTF_ERR) {
			warnx("failed to lookup type %s for symbol %s",
			    tests[i].cs_type, tests[i].cs_symbol);
			cb->csc_ret = B_FALSE;
			return (0);
		}

		if (id != type) {
			warnx("type mismatch for symbol %s, has type id %u, "
			    "but specified type %s has id %u",
			    tests[i].cs_symbol, type, tests[i].cs_type, id);
			cb->csc_ret = B_FALSE;
			return (0);
		}
	}

	return (0);
}

boolean_t
ctftest_check_symbols(ctf_file_t *fp, const check_symbol_t *tests)
{
	ctftest_symbol_cb_t cb;

	cb.csc_fp = fp;
	cb.csc_ret = B_TRUE;
	cb.csc_tests = tests;
	if (ctf_object_iter(fp, ctftest_check_symbol_cb, &cb) != 0)
		return (B_FALSE);
	return (cb.csc_ret);
}


boolean_t
ctftest_check_descent(const char *symbol, ctf_file_t *fp,
    const check_descent_t *tests)
{
	ctf_id_t base;
	uint_t layer = 0;

	/*
	 * First, find the initial type of the symbol.
	 */
	base = ctftest_lookup_symbol(fp, symbol);
	if (base == CTF_ERR) {
		warnx("failed to lookup type for symbol %s", symbol);
		return (B_FALSE);
	}

	while (tests->cd_tname != NULL) {
		ctf_id_t tid;
		int kind;
		ctf_arinfo_t ari;

		if (base == CTF_ERR) {
			warnx("encountered non-reference type at layer %u "
			    "while still expecting type %s for symbol %s",
			    layer, tests->cd_tname, symbol);
			return (B_FALSE);
		}

		tid = ctftest_lookup_type(fp, tests->cd_tname);
		if (tid == CTF_ERR) {
			warnx("failed to lookup type %s", tests->cd_tname);
			return (B_FALSE);
		}

		if (tid != base) {
			warnx("type mismatch at layer %u: found id %u, but "
			    "expecting type id %u for type %s, symbol %s",
			    layer, base, tid, tests->cd_tname, symbol);
			return (B_FALSE);
		}

		kind = ctf_type_kind(fp, base);
		if (kind != tests->cd_kind) {
			warnx("type kind mismatch at layer %u: found kind %u, "
			    "but expected kind %u for %s, symbol %s", layer,
			    kind, tests->cd_kind, tests->cd_tname, symbol);
			return (B_FALSE);
		}

		switch (kind) {
		case CTF_K_ARRAY:
			if (ctf_array_info(fp, base, &ari) == CTF_ERR) {
				warnx("failed to lookup array info at layer "
				    "%u for type %s, symbol %s: %s", base,
				    tests->cd_tname, symbol,
				    ctf_errmsg(ctf_errno(fp)));
				return (B_FALSE);
			}

			if (tests->cd_nents != ari.ctr_nelems) {
				warnx("array element mismatch at layer %u "
				    "for type %s, symbol %s: found %u, "
				    "expected %u", layer, tests->cd_tname,
				    symbol, ari.ctr_nelems, tests->cd_nents);
				return (B_FALSE);
			}

			tid = ctftest_lookup_type(fp, tests->cd_contents);
			if (tid == CTF_ERR) {
				warnx("failed to look up type %s",
				    tests->cd_contents);
				return (B_FALSE);
			}

			if (ari.ctr_contents != tid) {
				warnx("array contents mismatch at layer %u "
				    "for type %s, symbol %s: found %u, "
				    "expected %s/%u", layer, tests->cd_tname,
				    symbol, ari.ctr_contents,
				    tests->cd_contents, tid);

				return (B_FALSE);
			}
			base = ari.ctr_contents;
			break;
		default:
			base = ctf_type_reference(fp, base);
			break;
		}

		tests++;
		layer++;
	}

	if (base != CTF_ERR) {
		warnx("found additional type %u in chain, but expected no more",
		    base);
		return (B_FALSE);
	}

	return (B_TRUE);
}

int
ctftest_check_enum_count(const char *name, int value, void *arg)
{
	uint_t *u = arg;
	*u = *u + 1;
	return (0);
}

int
ctftest_check_enum_value(const char *name, int value, void *arg)
{
	uint_t i;
	const check_enum_t *enums = arg;

	for (i = 0; enums[i].ce_name != NULL; i++) {
		if (strcmp(enums[i].ce_name, name) != 0)
			continue;
		if (enums[i].ce_value == (int64_t)value)
			return (0);
		warnx("enum %s value mismatch: found %d, expected %" PRId64,
		    name, value, enums[i].ce_value);
		return (1);
	}

	warnx("found no matching entry for enum member %s", name);
	return (1);
}

boolean_t
ctftest_check_enum(const char *type, ctf_file_t *fp, const check_enum_t *enums)
{
	int ret;
	uint_t tcount, ecount;
	ctf_id_t base;

	if ((base = ctftest_lookup_type(fp, type)) == CTF_ERR) {
		warnx("Failed to look up type %s", type);
		return (B_FALSE);
	}

	if (ctf_type_kind(fp, base) != CTF_K_ENUM) {
		warnx("%s is not an enum", type);
		return (B_FALSE);
	}

	/*
	 * First count how many entries we have.
	 */
	tcount = 0;
	while (enums[tcount].ce_name != NULL) {
		tcount++;
	}

	ecount = 0;
	if (ctf_enum_iter(fp, base, ctftest_check_enum_count, &ecount) != 0) {
		warnx("failed to walk enum %s: %s", type,
		    ctf_errmsg(ctf_errno(fp)));
		return (B_FALSE);
	}

	if (tcount != ecount) {
		warnx("enum value mismatch: expected %u values, but found %u",
		    tcount, ecount);
		return (B_FALSE);
	}

	if ((ret = ctf_enum_iter(fp, base, ctftest_check_enum_value,
	    (void *)enums)) != 0) {
		if (ret == -1) {
			warnx("failed to walk enum %s: %s", type,
			    ctf_errmsg(ctf_errno(fp)));
		}
		return (B_FALSE);
	}

	return (B_TRUE);
}

int
ctftest_check_member_count(const char *mname, ctf_id_t mtype, ulong_t bitoff,
    void *arg)
{
	uint_t *countp = arg;
	*countp = *countp + 1;
	return (0);
}

int
ctftest_check_members_cb(const char *mname, ctf_id_t mtype, ulong_t bitoff,
    void *arg)
{
	uint_t i;
	const ctftest_member_cb_t *cmc = arg;
	const check_member_t *members = cmc->cmc_members;
	ctf_file_t *fp = cmc->cmc_fp;

	for (i = 0; members[i].cm_name != NULL; i++) {
		boolean_t bad = B_FALSE;
		char buf[2048];

		if (strcmp(mname, members[i].cm_name) != 0)
			continue;

		if (bitoff != members[i].cm_offset) {
			warnx("member %s of type %s has mismatched bit offset: "
			    "found %lu, expected %lu", mname, cmc->cmc_name,
			    bitoff, members[i].cm_offset);
			bad = B_TRUE;
		}

		if (ctf_type_name(fp, mtype, buf, sizeof (buf)) == NULL) {
			warnx("failed to obtain type name for member %s",
			    mname, ctf_errmsg(ctf_errno(fp)));
			bad = B_TRUE;
		} else if (strcmp(buf, members[i].cm_type) != 0) {
			warnx("member %s has bad type, found %s, expected %s",
			    mname, buf, members[i].cm_type);
			bad = B_TRUE;
		}

		return (bad ? 1 : 0);
	}

	warnx("found no matching entry for member %s of type %s", mname,
	    cmc->cmc_name);
	return (1);
}

boolean_t
ctftest_check_members(const char *type, ctf_file_t *fp, int kind,
    size_t size, const check_member_t *members)
{
	int ret;
	uint_t tcount, mcount;
	ctf_id_t base;
	ctftest_member_cb_t cmc;

	if ((base = ctftest_lookup_type(fp, type)) == CTF_ERR) {
		warnx("failed to look up type %s", type);
		return (B_FALSE);
	}

	if (ctf_type_kind(fp, base) != kind) {
		warnx("%s has kind %s, expected %s", type,
		    ctf_kind_name(fp, ctf_type_kind(fp, base)),
		    ctf_kind_name(fp, kind));
		return (B_FALSE);
	}

	if (size != ctf_type_size(fp, base)) {
		warnx("%s has bad size, expected %lu, found %lu",
		    type, size, ctf_type_size(fp, base));
		return (B_FALSE);
	}

	/*
	 * First count how many entries we have.
	 */
	tcount = 0;
	while (members[tcount].cm_name != NULL) {
		tcount++;
	}

	mcount = 0;
	if (ctf_member_iter(fp, base, ctftest_check_member_count, &mcount) !=
	    0) {
		warnx("failed to walk members of %s: %s", type,
		    ctf_errmsg(ctf_errno(fp)));
		return (B_FALSE);
	}

	if (tcount != mcount) {
		warnx("type member mismatch: expected %u values, but found %u",
		    tcount, mcount);
		return (B_FALSE);
	}

	cmc.cmc_fp = fp;
	cmc.cmc_members = members;
	cmc.cmc_name = type;
	if ((ret = ctf_member_iter(fp, base, ctftest_check_members_cb,
	    &cmc)) != 0) {
		if (ret == -1) {
			warnx("failed to walk type %s: %s", type,
			    ctf_errmsg(ctf_errno(fp)));
		}
		return (B_FALSE);
	}

	return (B_TRUE);
}

boolean_t
ctftest_check_function(const char *symbol, ctf_file_t *fp, const char *rtype,
    uint_t nargs, uint_t flags, const char **argv)
{
	ulong_t sym;
	ctf_funcinfo_t fi;
	uint_t i;
	boolean_t ret = B_TRUE;
	ctf_id_t *args;
	char buf[2048];


	if (!ctftest_lookup_function(fp, symbol, &sym, &fi)) {
		warnx("failed to look up function %s", symbol);
		return (B_FALSE);
	}

	if (ctf_type_name(fp, fi.ctc_return, buf, sizeof (buf)) == NULL) {
		warnx("failed to lookup return type name for function %s",
		    symbol);
		ret = B_FALSE;
	} else if (strcmp(rtype, buf) != 0) {
		warnx("return type has wrong type: found %s, expected %s",
		    buf, rtype);
		ret = B_FALSE;
	}

	if (nargs != fi.ctc_argc) {
		warnx("function argument mismatch: found %u, expected %u",
		    fi.ctc_argc, nargs);
		ret = B_FALSE;
	}

	if (flags != fi.ctc_flags) {
		warnx("function flags mismatch, found 0x%x, expected 0x%x",
		    fi.ctc_flags, flags);
		ret = B_FALSE;
	}

	if (!ret || fi.ctc_argc == 0) {
		return (ret);
	}

	if ((args = calloc(fi.ctc_argc, sizeof (ctf_id_t))) == NULL) {
		warnx("failed to allocate memory for function arguments");
		return (B_FALSE);
	}

	if (ctf_func_args(fp, sym, fi.ctc_argc, args) != 0) {
		warnx("failed to get function information: %s",
		    ctf_errmsg(ctf_errno(fp)));
		free(args);
		return (B_FALSE);
	}

	for (i = 0; i < fi.ctc_argc; i++) {
		if (ctf_type_name(fp, args[i], buf, sizeof (buf)) == NULL) {
			warnx("failed to obtain type name for argument %u",
			    i, ctf_errmsg(ctf_errno(fp)));
			ret = B_FALSE;
			break;
		}

		if (strcmp(buf, argv[i]) != 0) {
			warnx("argument %u has wrong type: found %s, "
			    "expected %s", i, buf, argv[i]);
			ret = B_FALSE;
			break;
		}
	}

	free(args);
	return (ret);
}

boolean_t
ctftest_check_fptr(const char *type, ctf_file_t *fp, const char *rtype,
    uint_t nargs, uint_t flags, const char **argv)
{
	ctf_id_t tid;
	ctf_funcinfo_t fi;
	uint_t i;
	boolean_t ret = B_TRUE;
	ctf_id_t *args;
	char buf[2048];


	if ((tid = ctf_lookup_by_name(fp, type)) == CTF_ERR) {
		warnx("failed to look up type %s: %s", type,
		    ctf_errmsg(ctf_errno(fp)));
		return (B_FALSE);
	}

	/*
	 * Perform two CTF type resolves, one for the function pointer and one
	 * for the typedef that gets passed in.
	 */
	if ((tid = ctf_type_resolve(fp, tid)) == CTF_ERR) {
		warnx("failed to convert type %s to base type: %s", type,
		    ctf_errmsg(ctf_errno(fp)));
		return (B_FALSE);
	}

	if (ctf_type_kind(fp, tid) == CTF_K_POINTER &&
	    (tid = ctf_type_reference(fp, tid)) == CTF_ERR) {
		warnx("failed to convert type %s to base type: %s", type,
		    ctf_errmsg(ctf_errno(fp)));
		return (B_FALSE);
	}

	if (ctf_func_info_by_id(fp, tid, &fi) != 0) {
		warnx("failed to get function information for type %s: %s",
		    type, ctf_errmsg(ctf_errno(fp)));
		return (B_FALSE);
	}

	if (ctf_type_name(fp, fi.ctc_return, buf, sizeof (buf)) == NULL) {
		warnx("failed to lookup return type name for function %s",
		    type);
		ret = B_FALSE;
	} else if (strcmp(rtype, buf) != 0) {
		warnx("return type has wrong type: found %s, expected %s",
		    buf, rtype);
		ret = B_FALSE;
	}

	if (nargs != fi.ctc_argc) {
		warnx("function argument mismatch: found %u, expected %u",
		    fi.ctc_argc, nargs);
		ret = B_FALSE;
	}

	if (flags != fi.ctc_flags) {
		warnx("function flags mismatch, found 0x%x, expected 0x%x",
		    fi.ctc_flags, flags);
		ret = B_FALSE;
	}

	if (!ret || fi.ctc_argc == 0) {
		return (ret);
	}

	if ((args = calloc(fi.ctc_argc, sizeof (ctf_id_t))) == NULL) {
		warnx("failed to allocate memory for function arguments");
		return (B_FALSE);
	}

	if (ctf_func_args_by_id(fp, tid, fi.ctc_argc, args) != 0) {
		warnx("failed to get function information: %s",
		    ctf_errmsg(ctf_errno(fp)));
		free(args);
		return (B_FALSE);
	}

	for (i = 0; i < fi.ctc_argc; i++) {
		if (ctf_type_name(fp, args[i], buf, sizeof (buf)) == NULL) {
			warnx("failed to obtain type name for argument %u",
			    i, ctf_errmsg(ctf_errno(fp)));
			ret = B_FALSE;
			break;
		}

		if (strcmp(buf, argv[i]) != 0) {
			warnx("argument %u has wrong type: found %s, "
			    "expected %s", i, buf, argv[i]);
			ret = B_FALSE;
			break;
		}
	}

	free(args);
	return (ret);
}

typedef struct ctftest_duplicates {
	ctf_file_t *ctd_fp;
	char **ctd_names;
	size_t ctd_len;
	size_t ctd_curent;
	boolean_t ctd_ret;
} ctftest_duplicates_t;

static int
ctftest_duplicates_cb(ctf_id_t id, boolean_t root, void *arg)
{
	char buf[2048];
	ctftest_duplicates_t *dup = arg;
	size_t i;

	if (ctf_type_name(dup->ctd_fp, id, buf, sizeof (buf)) == NULL) {
		warnx("failed to lookup name for id %ld", id);
		dup->ctd_ret = B_FALSE;
		return (1);
	}

	for (i = 0; i < dup->ctd_curent; i++) {
		if (strcmp(buf, dup->ctd_names[i]) == 0) {
			warnx("encountered duplicate type '%s'", buf);
			dup->ctd_ret = B_FALSE;
			/*
			 * Don't break out of the loop and keep going in case we
			 * find another duplicate.
			 */
			return (0);
		}
	}

	if (dup->ctd_curent == dup->ctd_len) {
		char **n;
		size_t newlen = dup->ctd_len * 2;

		n = recallocarray(dup->ctd_names, dup->ctd_len, newlen,
		    sizeof (char *));
		if (n == NULL) {
			warnx("failed to resize type name array");
			dup->ctd_ret = B_FALSE;
			return (1);
		}

		dup->ctd_names = n;
		dup->ctd_len = newlen;
	}

	dup->ctd_names[dup->ctd_curent] = strdup(buf);
	if (dup->ctd_names[dup->ctd_curent] == NULL) {
		warn("failed to duplicate type name");
		dup->ctd_ret = B_FALSE;
		return (1);
	}
	dup->ctd_curent++;

	return (0);
}

boolean_t
ctftest_duplicates(ctf_file_t *fp)
{
	size_t i;
	ctftest_duplicates_t d;

	bzero(&d, sizeof (d));
	d.ctd_fp = fp;
	d.ctd_len = 4;
	d.ctd_ret = B_TRUE;
	d.ctd_names = recallocarray(NULL, 0, d.ctd_len, sizeof (char *));
	if (d.ctd_names == NULL) {
		warnx("failed to allocate duplicate name storage");
		return (B_FALSE);
	}

	(void) ctf_type_iter(fp, B_TRUE, ctftest_duplicates_cb, &d);

	for (i = 0; i < d.ctd_curent; i++) {
		free(d.ctd_names[i]);
	}
	free(d.ctd_names);

	return (d.ctd_ret);
}
