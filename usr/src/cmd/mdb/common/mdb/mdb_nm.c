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

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <sys/elf.h>
#include <sys/elf_SPARC.h>

#include <libproc.h>
#include <libctf.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

#include <mdb/mdb_string.h>
#include <mdb/mdb_argvec.h>
#include <mdb/mdb_nv.h>
#include <mdb/mdb_fmt.h>
#include <mdb/mdb_target.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_conf.h>
#include <mdb/mdb_module.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_stdlib.h>
#include <mdb/mdb_lex.h>
#include <mdb/mdb_io_impl.h>
#include <mdb/mdb_help.h>
#include <mdb/mdb_disasm.h>
#include <mdb/mdb_frame.h>
#include <mdb/mdb_evset.h>
#include <mdb/mdb_print.h>
#include <mdb/mdb_nm.h>
#include <mdb/mdb_set.h>
#include <mdb/mdb_demangle.h>
#include <mdb/mdb.h>

enum {
	NM_FMT_INDEX	= 0x0001,			/* -f ndx */
	NM_FMT_VALUE	= 0x0002,			/* -f val */
	NM_FMT_SIZE	= 0x0004,			/* -f size */
	NM_FMT_TYPE	= 0x0008,			/* -f type */
	NM_FMT_BIND	= 0x0010,			/* -f bind */
	NM_FMT_OTHER	= 0x0020,			/* -f oth */
	NM_FMT_SHNDX	= 0x0040,			/* -f shndx */
	NM_FMT_NAME	= 0x0080,			/* -f name */
	NM_FMT_CTYPE	= 0x0100,			/* -f ctype */
	NM_FMT_OBJECT	= 0x0200,			/* -f obj */

	NM_FMT_CTFID	= 0x1000			/* -f ctfid */
};

enum {
	NM_TYPE_NOTY	= 1 << STT_NOTYPE,		/* -t noty */
	NM_TYPE_OBJT	= 1 << STT_OBJECT,		/* -t objt */
	NM_TYPE_FUNC	= 1 << STT_FUNC,		/* -t func */
	NM_TYPE_SECT	= 1 << STT_SECTION,		/* -t sect */
	NM_TYPE_FILE	= 1 << STT_FILE,		/* -t file */
	NM_TYPE_COMM	= 1 << STT_COMMON,		/* -t comm */
	NM_TYPE_TLS	= 1 << STT_TLS,			/* -t tls */
	NM_TYPE_REGI	= 1 << STT_SPARC_REGISTER	/* -t regi */
};

typedef struct {
	GElf_Sym nm_sym;
	const char *nm_name;
	mdb_syminfo_t nm_si;
	const char *nm_object;
	ctf_file_t *nm_fp;
} nm_sym_t;

typedef struct {
	ctf_file_t *nii_fp;

	uint_t nii_flags;
	uint_t nii_types;
	ulong_t nii_id;
	const char *nii_pfmt;
	const char *nii_ofmt;

	const GElf_Sym *nii_symp;

	nm_sym_t **nii_sympp;
} nm_iter_info_t;

typedef struct {
	mdb_tgt_sym_f *ngs_cb;
	void *ngs_arg;
	mdb_syminfo_t ngs_si;
	const char *ngs_object;
} nm_gelf_symtab_t;

typedef struct {
	uint_t noi_which;
	uint_t noi_type;
	mdb_tgt_sym_f *noi_cb;
	nm_iter_info_t *noi_niip;
} nm_object_iter_t;

static const char *
nm_type2str(uchar_t info)
{
	switch (GELF_ST_TYPE(info)) {
	case STT_NOTYPE:
		return ("NOTY");
	case STT_OBJECT:
		return ("OBJT");
	case STT_FUNC:
		return ("FUNC");
	case STT_SECTION:
		return ("SECT");
	case STT_FILE:
		return ("FILE");
	case STT_COMMON:
		return ("COMM");
	case STT_TLS:
		return ("TLS");
	case STT_SPARC_REGISTER:
		return ("REGI");
	default:
		return ("?");
	}
}

static const char *
nm_bind2str(uchar_t info)
{
	switch (GELF_ST_BIND(info)) {
	case STB_LOCAL:
		return ("LOCL");
	case STB_GLOBAL:
		return ("GLOB");
	case STB_WEAK:
		return ("WEAK");
	default:
		return ("?");
	}
}

static const char *
nm_sect2str(GElf_Half shndx)
{
	static char buf[16];

	switch (shndx) {
	case SHN_UNDEF:
		return ("UNDEF");
	case SHN_ABS:
		return ("ABS");
	case SHN_COMMON:
		return ("COMMON");
	default:
		(void) mdb_iob_snprintf(buf, sizeof (buf), "%hu", shndx);
		return (buf);
	}
}

static char *
nm_func_signature(ctf_file_t *fp, uint_t index, char *buf, size_t len)
{
	int n;
	ctf_funcinfo_t f;
	ctf_id_t argv[32];
	char arg[32];
	char *start = buf;
	char *sep = "";
	int i;

	if (ctf_func_info(fp, index, &f) == CTF_ERR)
		return (NULL);

	if (ctf_type_name(fp, f.ctc_return, arg, sizeof (arg)) != NULL)
		n = mdb_snprintf(buf, len, "%s (*)(", arg);
	else
		n = mdb_snprintf(buf, len, "<%ld> (*)(", f.ctc_return);

	if (len <= n)
		return (start);

	buf += n;
	len -= n;

	(void) ctf_func_args(fp, index, sizeof (argv) / sizeof (argv[0]), argv);

	for (i = 0; i < f.ctc_argc; i++) {
		if (ctf_type_name(fp, argv[i], arg, sizeof (arg)) != NULL)
			n = mdb_snprintf(buf, len, "%s%s", sep, arg);
		else
			n = mdb_snprintf(buf, len, "%s<%ld>", sep, argv[i]);

		if (len <= n)
			return (start);

		buf += n;
		len -= n;

		sep = ", ";
	}

	if (f.ctc_flags & CTF_FUNC_VARARG) {
		n = mdb_snprintf(buf, len, "%s...", sep);
		if (len <= n)
			return (start);
		buf += n;
		len -= n;
	} else if (f.ctc_argc == 0) {
		n = mdb_snprintf(buf, len, "void");
		if (len <= n)
			return (start);
		buf += n;
		len -= n;
	}

	(void) mdb_snprintf(buf, len, ")");

	return (start);
}

static void
nm_print_ctype(void *data)
{
	nm_iter_info_t *niip = data;
	char buf[256];
	ctf_id_t id;
	char *str = NULL;
	uint_t index = niip->nii_id;
	ctf_file_t *fp = niip->nii_fp;

	if (fp != NULL) {
		if (GELF_ST_TYPE(niip->nii_symp->st_info) == STT_FUNC)
			str = nm_func_signature(fp, index, buf, sizeof (buf));
		else if ((id = ctf_lookup_by_symbol(fp, index)) != CTF_ERR)
			str = ctf_type_name(fp, id, buf, sizeof (buf));
	}

	if (str == NULL)
		str = "<unknown type>";

	mdb_printf("%-50s", str);
}

static void
nm_print_ctfid(void *data)
{
	nm_iter_info_t *niip = data;
	ctf_id_t id;
	uint_t index = niip->nii_id;
	ctf_file_t *fp = niip->nii_fp;

	if (fp != NULL && (id = ctf_lookup_by_symbol(fp, index)) != CTF_ERR) {
		mdb_printf("%-9ld", id);
	} else {
		mdb_printf("%9s", "");
	}
}

static void
nm_print_obj(void *data)
{
	const char *obj = (const char *)data;

	if (obj == MDB_TGT_OBJ_EXEC)
		obj = "exec";
	else if (obj == MDB_TGT_OBJ_RTLD)
		obj = "rtld";
	else if (obj == MDB_TGT_OBJ_EVERY)
		obj = "";

	mdb_printf("%-15s", obj);
}

/*ARGSUSED*/
static int
nm_print(void *data, const GElf_Sym *sym, const char *name,
    const mdb_syminfo_t *sip, const char *obj)
{
	nm_iter_info_t *niip = data;

	if (!((1 << GELF_ST_TYPE(sym->st_info)) & niip->nii_types))
		return (0);

	niip->nii_id = sip->sym_id;
	niip->nii_symp = sym;

	mdb_table_print(niip->nii_flags, "|",
	    MDB_TBL_PRNT, NM_FMT_INDEX, "%5u", sip->sym_id,
	    MDB_TBL_FUNC, NM_FMT_OBJECT, nm_print_obj, obj,
	    MDB_TBL_PRNT, NM_FMT_VALUE, niip->nii_pfmt, sym->st_value,
	    MDB_TBL_PRNT, NM_FMT_SIZE, niip->nii_pfmt, sym->st_size,
	    MDB_TBL_PRNT, NM_FMT_TYPE, "%-5s", nm_type2str(sym->st_info),
	    MDB_TBL_PRNT, NM_FMT_BIND, "%-5s", nm_bind2str(sym->st_info),
	    MDB_TBL_PRNT, NM_FMT_OTHER, niip->nii_ofmt, sym->st_other,
	    MDB_TBL_PRNT, NM_FMT_SHNDX, "%-8s", nm_sect2str(sym->st_shndx),
	    MDB_TBL_FUNC, NM_FMT_CTFID, nm_print_ctfid, niip,
	    MDB_TBL_FUNC, NM_FMT_CTYPE, nm_print_ctype, niip,
	    MDB_TBL_PRNT, NM_FMT_NAME, "%s", name,
	    MDB_TBL_DONE);

	mdb_printf("\n");

	return (0);
}

/*ARGSUSED*/
static int
nm_any(void *data, const GElf_Sym *sym, const char *name,
    const mdb_syminfo_t *sip, const char *obj)
{
	return (nm_print(data, sym, name, sip, obj));
}

/*ARGSUSED*/
static int
nm_undef(void *data, const GElf_Sym *sym, const char *name,
    const mdb_syminfo_t *sip, const char *obj)
{
	if (sym->st_shndx == SHN_UNDEF)
		return (nm_print(data, sym, name, sip, obj));

	return (0);
}

/*ARGSUSED*/
static int
nm_asgn(void *data, const GElf_Sym *sym, const char *name,
    const mdb_syminfo_t *sip, const char *obj)
{
	const char *opts;

	switch (GELF_ST_TYPE(sym->st_info)) {
	case STT_FUNC:
		opts = "-f";
		break;
	case STT_OBJECT:
		opts = "-o";
		break;
	default:
		opts = "";
	}

	mdb_printf("%#llr::nmadd %s -s %#llr %s\n",
	    sym->st_value, opts, sym->st_size, name);

	return (0);
}

/*ARGSUSED*/
static int
nm_cnt_any(void *data, const GElf_Sym *sym, const char *name,
    const mdb_syminfo_t *sip, const char *obj)
{
	size_t *cntp = (size_t *)data;
	(*cntp)++;
	return (0);
}

/*ARGSUSED*/
static int
nm_cnt_undef(void *data, const GElf_Sym *sym, const char *name,
    const mdb_syminfo_t *sip, const char *obj)
{
	if (sym->st_shndx == SHN_UNDEF)
		return (nm_cnt_any(data, sym, name, sip, obj));

	return (0);
}

/*ARGSUSED*/
static int
nm_get_any(void *data, const GElf_Sym *sym, const char *name,
    const mdb_syminfo_t *sip, const char *obj)
{
	nm_iter_info_t *niip = data;
	nm_sym_t **sympp = niip->nii_sympp;

	(*sympp)->nm_sym = *sym;
	(*sympp)->nm_name = name;
	(*sympp)->nm_si = *sip;
	(*sympp)->nm_object = obj;
	(*sympp)->nm_fp = niip->nii_fp;
	(*sympp)++;

	return (0);
}

/*ARGSUSED*/
static int
nm_get_undef(void *data, const GElf_Sym *sym, const char *name,
    const mdb_syminfo_t *sip, const char *obj)
{
	if (sym->st_shndx == SHN_UNDEF)
		return (nm_get_any(data, sym, name, sip, obj));

	return (0);
}

static int
nm_compare_name(const void *lp, const void *rp)
{
	const nm_sym_t *lhs = (nm_sym_t *)lp;
	const nm_sym_t *rhs = (nm_sym_t *)rp;

	return (strcmp(lhs->nm_name, rhs->nm_name));
}

static int
nm_compare_val(const void *lp, const void *rp)
{
	const nm_sym_t *lhs = (nm_sym_t *)lp;
	const nm_sym_t *rhs = (nm_sym_t *)rp;

	return (lhs->nm_sym.st_value < rhs->nm_sym.st_value ? -1 :
	    (lhs->nm_sym.st_value > rhs->nm_sym.st_value ? 1 : 0));
}

static int
nm_gelf_symtab_cb(void *data, const GElf_Sym *symp, const char *name, uint_t id)
{
	nm_gelf_symtab_t *ngsp = data;

	ngsp->ngs_si.sym_id = id;

	return (ngsp->ngs_cb(ngsp->ngs_arg, symp, name, &ngsp->ngs_si,
	    ngsp->ngs_object));
}

static void
nm_gelf_symtab_iter(mdb_gelf_symtab_t *gst, const char *object, uint_t table,
    mdb_tgt_sym_f *cb, void *arg)
{
	nm_gelf_symtab_t ngs;

	ngs.ngs_cb = cb;
	ngs.ngs_arg = arg;

	ngs.ngs_si.sym_table = table;
	ngs.ngs_object = object;

	mdb_gelf_symtab_iter(gst, nm_gelf_symtab_cb, &ngs);
}

static int nm_symbol_iter(const char *, uint_t, uint_t, mdb_tgt_sym_f *,
    nm_iter_info_t *);

/*ARGSUSED*/
static int
nm_object_iter_cb(void *data, const mdb_map_t *mp, const char *name)
{
	nm_object_iter_t *noip = data;

	/*
	 * Since we're interating over all the objects in a target,
	 * don't return an error if we hit an object that we can't
	 * get symbol data for.
	 */
	if (nm_symbol_iter(name, noip->noi_which, noip->noi_type,
	    noip->noi_cb, noip->noi_niip) != 0)
		mdb_warn("unable to dump symbol data for: %s\n", name);
	return (0);
}

int
nm_symbol_iter(const char *object, uint_t which, uint_t type,
    mdb_tgt_sym_f *cb, nm_iter_info_t *niip)
{
	mdb_tgt_t *t = mdb.m_target;

	if (object == MDB_TGT_OBJ_EVERY) {
		nm_object_iter_t noi;

		noi.noi_which = which;
		noi.noi_type = type;
		noi.noi_cb = cb;
		noi.noi_niip = niip;

		return (mdb_tgt_object_iter(t, nm_object_iter_cb, &noi));
	}

	niip->nii_fp = mdb_tgt_name_to_ctf(t, object);

	return (mdb_tgt_symbol_iter(t, object, which, type, cb, niip));
}

/*ARGSUSED*/
int
cmd_nm(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	enum {
		NM_DYNSYM	= 0x0001,	/* -D (use dynsym) */
		NM_DEC		= 0x0002,	/* -d (decimal output) */
		NM_GLOBAL	= 0x0004,	/* -g (globals only) */
		NM_NOHDRS	= 0x0008,	/* -h (suppress header) */
		NM_OCT		= 0x0010,	/* -o (octal output) */
		NM_UNDEF	= 0x0020,	/* -u (undefs only) */
		NM_HEX		= 0x0040,	/* -x (hex output) */
		NM_SORT_NAME	= 0x0080,	/* -n (sort by name) */
		NM_SORT_VALUE	= 0x0100,	/* -v (sort by value) */
		NM_PRVSYM	= 0x0200,	/* -P (use private symtab) */
		NM_PRTASGN	= 0x0400	/* -p (print in asgn syntax) */
	};

	mdb_subopt_t opt_fmt_opts[] = {
		{ NM_FMT_INDEX, "ndx" },
		{ NM_FMT_VALUE, "val" },
		{ NM_FMT_SIZE, "sz" },
		{ NM_FMT_TYPE, "type" },
		{ NM_FMT_BIND, "bind" },
		{ NM_FMT_OTHER, "oth" },
		{ NM_FMT_SHNDX, "shndx" },
		{ NM_FMT_NAME, "name" },
		{ NM_FMT_CTYPE, "ctype" },
		{ NM_FMT_OBJECT, "obj" },
		{ NM_FMT_CTFID, "ctfid" },
		{ 0, NULL }
	};

	mdb_subopt_t opt_type_opts[] = {
		{ NM_TYPE_NOTY, "noty" },
		{ NM_TYPE_OBJT, "objt" },
		{ NM_TYPE_FUNC, "func" },
		{ NM_TYPE_SECT, "sect" },
		{ NM_TYPE_FILE, "file" },
		{ NM_TYPE_COMM, "comm" },
		{ NM_TYPE_TLS, "tls" },
		{ NM_TYPE_REGI, "regi" },
		{ 0, NULL }
	};

	uint_t optf = 0;
	uint_t opt_fmt;
	uint_t opt_types;
	int i;

	mdb_tgt_sym_f *callback;
	uint_t which, type;

	char *object = (char *)MDB_TGT_OBJ_EVERY;
	int hwidth;
	size_t nsyms = 0;

	nm_sym_t *syms, *symp;

	nm_iter_info_t nii;

	/* default output columns */
	opt_fmt = NM_FMT_VALUE | NM_FMT_SIZE | NM_FMT_TYPE | NM_FMT_BIND |
	    NM_FMT_OTHER | NM_FMT_SHNDX | NM_FMT_NAME;

	/* default output types */
	opt_types = NM_TYPE_NOTY | NM_TYPE_OBJT | NM_TYPE_FUNC | NM_TYPE_SECT |
	    NM_TYPE_FILE | NM_TYPE_COMM | NM_TYPE_TLS | NM_TYPE_REGI;

	i = mdb_getopts(argc, argv,
	    'D', MDB_OPT_SETBITS, NM_DYNSYM, &optf,
	    'P', MDB_OPT_SETBITS, NM_PRVSYM, &optf,
	    'd', MDB_OPT_SETBITS, NM_DEC, &optf,
	    'g', MDB_OPT_SETBITS, NM_GLOBAL, &optf,
	    'h', MDB_OPT_SETBITS, NM_NOHDRS, &optf,
	    'n', MDB_OPT_SETBITS, NM_SORT_NAME, &optf,
	    'o', MDB_OPT_SETBITS, NM_OCT, &optf,
	    'p', MDB_OPT_SETBITS, NM_PRTASGN | NM_NOHDRS, &optf,
	    'u', MDB_OPT_SETBITS, NM_UNDEF, &optf,
	    'v', MDB_OPT_SETBITS, NM_SORT_VALUE, &optf,
	    'x', MDB_OPT_SETBITS, NM_HEX, &optf,
	    'f', MDB_OPT_SUBOPTS, opt_fmt_opts, &opt_fmt,
	    't', MDB_OPT_SUBOPTS, opt_type_opts, &opt_types,
	    NULL);

	if (i != argc) {
		if (flags & DCMD_ADDRSPEC)
			return (DCMD_USAGE);

		if (argc != 0 && (argc - i) == 1) {
			if (argv[i].a_type != MDB_TYPE_STRING ||
			    argv[i].a_un.a_str[0] == '-')
				return (DCMD_USAGE);
			else
				object = (char *)argv[i].a_un.a_str;
		} else
			return (DCMD_USAGE);
	}

	if ((optf & (NM_DEC | NM_HEX | NM_OCT)) == 0) {
		switch (mdb.m_radix) {
		case 8:
			optf |= NM_OCT;
			break;
		case 10:
			optf |= NM_DEC;
			break;
		default:
			optf |= NM_HEX;
		}
	}

	switch (optf & (NM_DEC | NM_HEX | NM_OCT)) {
	case NM_DEC:
#ifdef _LP64
		nii.nii_pfmt = "%-20llu";
		nii.nii_ofmt = "%-5u";
		hwidth = 20;
#else
		nii.nii_pfmt = "%-10llu";
		nii.nii_ofmt = "%-5u";
		hwidth = 10;
#endif
		break;
	case NM_HEX:
#ifdef _LP64
		nii.nii_pfmt = "0x%016llx";
		nii.nii_ofmt = "0x%-3x";
		hwidth = 18;
#else
		nii.nii_pfmt = "0x%08llx";
		nii.nii_ofmt = "0x%-3x";
		hwidth = 10;
#endif
		break;
	case NM_OCT:
#ifdef _LP64
		nii.nii_pfmt = "%-22llo";
		nii.nii_ofmt = "%-5o";
		hwidth = 22;
#else
		nii.nii_pfmt = "%-11llo";
		nii.nii_ofmt = "%-5o";
		hwidth = 11;
#endif
		break;
	default:
		mdb_warn("-d/-o/-x options are mutually exclusive\n");
		return (DCMD_USAGE);
	}

	if (object != MDB_TGT_OBJ_EVERY && (optf & NM_PRVSYM)) {
		mdb_warn("-P/object options are mutually exclusive\n");
		return (DCMD_USAGE);
	}

	if ((flags & DCMD_ADDRSPEC) && (optf & NM_PRVSYM)) {
		mdb_warn("-P/address options are mutually exclusive\n");
		return (DCMD_USAGE);
	}

	if (!(optf & NM_NOHDRS)) {
		mdb_printf("%<u>");
		mdb_table_print(opt_fmt, " ",
		    MDB_TBL_PRNT, NM_FMT_INDEX, "Index",
		    MDB_TBL_PRNT, NM_FMT_OBJECT, "%-15s", "Object",
		    MDB_TBL_PRNT, NM_FMT_VALUE, "%-*s", hwidth, "Value",
		    MDB_TBL_PRNT, NM_FMT_SIZE, "%-*s", hwidth, "Size",
		    MDB_TBL_PRNT, NM_FMT_TYPE, "%-5s", "Type",
		    MDB_TBL_PRNT, NM_FMT_BIND, "%-5s", "Bind",
		    MDB_TBL_PRNT, NM_FMT_OTHER, "%-5s", "Other",
		    MDB_TBL_PRNT, NM_FMT_SHNDX, "%-8s", "Shndx",
		    MDB_TBL_PRNT, NM_FMT_CTFID, "%-9s", "CTF ID",
		    MDB_TBL_PRNT, NM_FMT_CTYPE, "%-50s", "C Type",
		    MDB_TBL_PRNT, NM_FMT_NAME, "%s", "Name",
		    MDB_TBL_DONE);

		mdb_printf("%</u>\n");
	}

	nii.nii_flags = opt_fmt;
	nii.nii_types = opt_types;

	if (optf & NM_DYNSYM)
		which = MDB_TGT_DYNSYM;
	else
		which = MDB_TGT_SYMTAB;

	if (optf & NM_GLOBAL)
		type = MDB_TGT_BIND_GLOBAL | MDB_TGT_TYPE_ANY;
	else
		type = MDB_TGT_BIND_ANY | MDB_TGT_TYPE_ANY;

	if (flags & DCMD_ADDRSPEC)
		optf |= NM_SORT_NAME; /* use sorting path if only one symbol */

	if (optf & (NM_SORT_NAME | NM_SORT_VALUE)) {
		char name[MDB_SYM_NAMLEN];
		GElf_Sym sym;
		mdb_syminfo_t si;

		if (optf & NM_UNDEF)
			callback = nm_cnt_undef;
		else
			callback = nm_cnt_any;

		if (flags & DCMD_ADDRSPEC) {
			const mdb_map_t *mp;
			/* gather relevant data for the specified addr */

			nii.nii_fp = mdb_tgt_addr_to_ctf(mdb.m_target, addr);

			if (mdb_tgt_lookup_by_addr(mdb.m_target, addr,
			    MDB_SYM_FUZZY, name, sizeof (name), &sym,
			    &si) == -1) {
				mdb_warn("%lr", addr);
				return (DCMD_ERR);
			}

			if ((mp = mdb_tgt_addr_to_map(mdb.m_target, addr))
			    != NULL) {
				object = mdb_alloc(strlen(mp->map_name) + 1,
				    UM_SLEEP | UM_GC);

				(void) strcpy(object, mp->map_name);

				/*
				 * Try to find a better match for the syminfo.
				 */
				(void) mdb_tgt_lookup_by_name(mdb.m_target,
				    object, name, &sym, &si);
			}

			(void) callback(&nsyms, &sym, name, &si, object);

		} else if (optf & NM_PRVSYM) {
			nsyms = mdb_gelf_symtab_size(mdb.m_prsym);
		} else {
			(void) mdb_tgt_symbol_iter(mdb.m_target, object,
			    which, type, callback, &nsyms);
		}

		if (nsyms == 0)
			return (DCMD_OK);

		syms = symp = mdb_alloc(sizeof (nm_sym_t) * nsyms,
		    UM_SLEEP | UM_GC);

		nii.nii_sympp = &symp;

		if (optf & NM_UNDEF)
			callback = nm_get_undef;
		else
			callback = nm_get_any;

		if (flags & DCMD_ADDRSPEC) {
			(void) callback(&nii, &sym, name, &si, object);
		} else if (optf & NM_PRVSYM) {
			nm_gelf_symtab_iter(mdb.m_prsym, object, MDB_TGT_PRVSYM,
			    callback, &nii);
		} else if (nm_symbol_iter(object, which, type, callback,
		    &nii) == -1) {
			mdb_warn("failed to iterate over symbols");
			return (DCMD_ERR);
		}

		if (optf & NM_SORT_NAME)
			qsort(syms, nsyms, sizeof (nm_sym_t), nm_compare_name);
		else
			qsort(syms, nsyms, sizeof (nm_sym_t), nm_compare_val);
	}

	if ((optf & (NM_PRVSYM | NM_PRTASGN)) == (NM_PRVSYM | NM_PRTASGN))
		callback = nm_asgn;
	else if (optf & NM_UNDEF)
		callback = nm_undef;
	else
		callback = nm_any;

	if (optf & (NM_SORT_NAME | NM_SORT_VALUE)) {
		for (symp = syms; nsyms-- != 0; symp++) {
			nii.nii_fp = symp->nm_fp;

			(void) callback(&nii, &symp->nm_sym, symp->nm_name,
			    &symp->nm_si, symp->nm_object);
		}

	} else {
		if (optf & NM_PRVSYM) {
			nm_gelf_symtab_iter(mdb.m_prsym, object, MDB_TGT_PRVSYM,
			    callback, &nii);

		} else if (nm_symbol_iter(object, which, type, callback, &nii)
		    == -1) {
			mdb_warn("failed to iterate over symbols");
			return (DCMD_ERR);
		}
	}

	return (DCMD_OK);
}

int
cmd_nmadd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uintptr_t opt_e = 0, opt_s = 0;
	uint_t opt_f = FALSE, opt_o = FALSE;

	GElf_Sym sym;
	int i;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	i = mdb_getopts(argc, argv,
	    'f', MDB_OPT_SETBITS, TRUE, &opt_f,
	    'o', MDB_OPT_SETBITS, TRUE, &opt_o,
	    'e', MDB_OPT_UINTPTR, &opt_e,
	    's', MDB_OPT_UINTPTR, &opt_s, NULL);

	if (i != (argc - 1) || argv[i].a_type != MDB_TYPE_STRING ||
	    argv[i].a_un.a_str[0] == '-' || argv[i].a_un.a_str[0] == '+')
		return (DCMD_USAGE);

	if (opt_e && opt_e < addr) {
		mdb_warn("end (%p) is less than start address (%p)\n",
		    (void *)opt_e, (void *)addr);
		return (DCMD_USAGE);
	}

	if (mdb_gelf_symtab_lookup_by_name(mdb.m_prsym,
	    argv[i].a_un.a_str, &sym, NULL) == -1) {
		bzero(&sym, sizeof (sym));
		sym.st_info = GELF_ST_INFO(STB_GLOBAL, STT_NOTYPE);
	}

	if (opt_f)
		sym.st_info = GELF_ST_INFO(STB_GLOBAL, STT_FUNC);
	if (opt_o)
		sym.st_info = GELF_ST_INFO(STB_GLOBAL, STT_OBJECT);
	if (opt_e)
		sym.st_size = (GElf_Xword)(opt_e - addr);
	if (opt_s)
		sym.st_size = (GElf_Xword)(opt_s);
	sym.st_value = (GElf_Addr)addr;

	mdb_gelf_symtab_insert(mdb.m_prsym, argv[i].a_un.a_str, &sym);

	mdb_iob_printf(mdb.m_out, "added %s, value=%llr size=%llr\n",
	    argv[i].a_un.a_str, sym.st_value, sym.st_size);

	return (DCMD_OK);
}

/*ARGSUSED*/
int
cmd_nmdel(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	const char *name;
	GElf_Sym sym;
	uint_t id;

	if (argc != 1 || argv->a_type != MDB_TYPE_STRING ||
	    argv->a_un.a_str[0] == '-' || (flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	name = argv->a_un.a_str;

	if (mdb_gelf_symtab_lookup_by_name(mdb.m_prsym, name, &sym, &id) == 0) {
		mdb_gelf_symtab_delete(mdb.m_prsym, name, &sym);
		mdb_printf("deleted %s, value=%llr size=%llr\n",
		    name, sym.st_value, sym.st_size);
		return (DCMD_OK);
	}

	mdb_warn("symbol '%s' not found in private symbol table\n", name);
	return (DCMD_ERR);
}

void
nm_help(void)
{
	mdb_printf("-D         print .dynsym instead of .symtab\n"
	    "-P         print private symbol table instead of .symtab\n"
	    "-d         print value and size in decimal\n"
	    "-g         only print global symbols\n"
	    "-h         suppress header line\n"
	    "-n         sort symbols by name\n"
	    "-o         print value and size in octal\n"
	    "-p         print symbols as a series of ::nmadd commands\n"
	    "-u         only print undefined symbols\n"
	    "-v         sort symbols by value\n"
	    "-x         print value and size in hexadecimal\n"
	    "-f format  use specified format\n"
	    "           ndx, val, sz, type, bind, oth, shndx, "
	    "name, ctype, obj\n"
	    "-t types   display symbols with the specified types\n"
	    "           noty, objt, func, sect, file, regi\n"
	    "obj        specify object whose symbol table should be used\n");
}

void
nmadd_help(void)
{
	mdb_printf("-f       set type of symbol to STT_FUNC\n"
	    "-o       set type of symbol to STT_OBJECT\n"
	    "-e end   set size of symbol to end - start address\n"
	    "-s size  set size of symbol to explicit value\n"
	    "name     specify symbol name to add\n");
}
