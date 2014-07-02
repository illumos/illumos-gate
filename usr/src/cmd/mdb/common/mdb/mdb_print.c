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
 * Copyright (c) 2012, 2014 by Delphix. All rights reserved.
 * Copyright (c) 2012 Joyent, Inc. All rights reserved.
 */

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_target.h>
#include <mdb/mdb_argvec.h>
#include <mdb/mdb_string.h>
#include <mdb/mdb_stdlib.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_fmt.h>
#include <mdb/mdb_ctf.h>
#include <mdb/mdb_ctf_impl.h>
#include <mdb/mdb.h>
#include <mdb/mdb_tab.h>

#include <sys/isa_defs.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <netinet/in.h>
#include <strings.h>
#include <libctf.h>
#include <ctype.h>

typedef struct holeinfo {
	ulong_t hi_offset;		/* expected offset */
	uchar_t hi_isunion;		/* represents a union */
} holeinfo_t;

typedef struct printarg {
	mdb_tgt_t *pa_tgt;		/* current target */
	mdb_tgt_t *pa_realtgt;		/* real target (for -i) */
	mdb_tgt_t *pa_immtgt;		/* immediate target (for -i) */
	mdb_tgt_as_t pa_as;		/* address space to use for i/o */
	mdb_tgt_addr_t pa_addr;		/* base address for i/o */
	ulong_t pa_armemlim;		/* limit on array elements to print */
	ulong_t pa_arstrlim;		/* limit on array chars to print */
	const char *pa_delim;		/* element delimiter string */
	const char *pa_prefix;		/* element prefix string */
	const char *pa_suffix;		/* element suffix string */
	holeinfo_t *pa_holes;		/* hole detection information */
	int pa_nholes;			/* size of holes array */
	int pa_flags;			/* formatting flags (see below) */
	int pa_depth;			/* previous depth */
	int pa_nest;			/* array nesting depth */
	int pa_tab;			/* tabstop width */
	uint_t pa_maxdepth;		/* Limit max depth */
	uint_t pa_nooutdepth;		/* don't print output past this depth */
} printarg_t;

#define	PA_SHOWTYPE	0x001		/* print type name */
#define	PA_SHOWBASETYPE	0x002		/* print base type name */
#define	PA_SHOWNAME	0x004		/* print member name */
#define	PA_SHOWADDR	0x008		/* print address */
#define	PA_SHOWVAL	0x010		/* print value */
#define	PA_SHOWHOLES	0x020		/* print holes in structs */
#define	PA_INTHEX	0x040		/* print integer values in hex */
#define	PA_INTDEC	0x080		/* print integer values in decimal */
#define	PA_NOSYMBOLIC	0x100		/* don't print ptrs as func+offset */

#define	IS_CHAR(e) \
	(((e).cte_format & (CTF_INT_CHAR | CTF_INT_SIGNED)) == \
	(CTF_INT_CHAR | CTF_INT_SIGNED) && (e).cte_bits == NBBY)

#define	COMPOSITE_MASK	((1 << CTF_K_STRUCT) | \
			(1 << CTF_K_UNION) | (1 << CTF_K_ARRAY))
#define	IS_COMPOSITE(k)	(((1 << k) & COMPOSITE_MASK) != 0)

#define	SOU_MASK	((1 << CTF_K_STRUCT) | (1 << CTF_K_UNION))
#define	IS_SOU(k)	(((1 << k) & SOU_MASK) != 0)

#define	MEMBER_DELIM_ERR	-1
#define	MEMBER_DELIM_DONE	0
#define	MEMBER_DELIM_PTR	1
#define	MEMBER_DELIM_DOT	2
#define	MEMBER_DELIM_LBR	3

typedef int printarg_f(const char *, const char *,
    mdb_ctf_id_t, mdb_ctf_id_t, ulong_t, printarg_t *);

static int elt_print(const char *, mdb_ctf_id_t, mdb_ctf_id_t, ulong_t, int,
    void *);
static void print_close_sou(printarg_t *, int);

/*
 * Given an address, look up the symbol ID of the specified symbol in its
 * containing module.  We only support lookups for exact matches.
 */
static const char *
addr_to_sym(mdb_tgt_t *t, uintptr_t addr, char *name, size_t namelen,
    GElf_Sym *symp, mdb_syminfo_t *sip)
{
	const mdb_map_t *mp;
	const char *p;

	if (mdb_tgt_lookup_by_addr(t, addr, MDB_TGT_SYM_EXACT, name,
	    namelen, NULL, NULL) == -1)
		return (NULL); /* address does not exactly match a symbol */

	if ((p = strrsplit(name, '`')) != NULL) {
		if (mdb_tgt_lookup_by_name(t, name, p, symp, sip) == -1)
			return (NULL);
		return (p);
	}

	if ((mp = mdb_tgt_addr_to_map(t, addr)) == NULL)
		return (NULL); /* address does not fall within a mapping */

	if (mdb_tgt_lookup_by_name(t, mp->map_name, name, symp, sip) == -1)
		return (NULL);

	return (name);
}

/*
 * This lets dcmds be a little fancy with their processing of type arguments
 * while still treating them more or less as a single argument.
 * For example, if a command is invokes like this:
 *
 *   ::<dcmd> proc_t ...
 *
 * this function will just copy "proc_t" into the provided buffer. If the
 * command is instead invoked like this:
 *
 *   ::<dcmd> struct proc ...
 *
 * this function will place the string "struct proc" into the provided buffer
 * and increment the caller's argv and argc. This allows the caller to still
 * treat the type argument logically as it would an other atomic argument.
 */
int
args_to_typename(int *argcp, const mdb_arg_t **argvp, char *buf, size_t len)
{
	int argc = *argcp;
	const mdb_arg_t *argv = *argvp;

	if (argc < 1 || argv->a_type != MDB_TYPE_STRING)
		return (DCMD_USAGE);

	if (strcmp(argv->a_un.a_str, "struct") == 0 ||
	    strcmp(argv->a_un.a_str, "enum") == 0 ||
	    strcmp(argv->a_un.a_str, "union") == 0) {
		if (argc <= 1) {
			mdb_warn("%s is not a valid type\n", argv->a_un.a_str);
			return (DCMD_ABORT);
		}

		if (argv[1].a_type != MDB_TYPE_STRING)
			return (DCMD_USAGE);

		(void) mdb_snprintf(buf, len, "%s %s",
		    argv[0].a_un.a_str, argv[1].a_un.a_str);

		*argcp = argc - 1;
		*argvp = argv + 1;
	} else {
		(void) mdb_snprintf(buf, len, "%s", argv[0].a_un.a_str);
	}

	return (0);
}

/*ARGSUSED*/
int
cmd_sizeof(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_ctf_id_t id;
	char tn[MDB_SYM_NAMLEN];
	int ret;

	if (flags & DCMD_ADDRSPEC)
		return (DCMD_USAGE);

	if ((ret = args_to_typename(&argc, &argv, tn, sizeof (tn))) != 0)
		return (ret);

	if (argc != 1)
		return (DCMD_USAGE);

	if (mdb_ctf_lookup_by_name(tn, &id) != 0) {
		mdb_warn("failed to look up type %s", tn);
		return (DCMD_ERR);
	}

	if (flags & DCMD_PIPE_OUT)
		mdb_printf("%#lr\n", mdb_ctf_type_size(id));
	else
		mdb_printf("sizeof (%s) = %#lr\n", tn, mdb_ctf_type_size(id));

	return (DCMD_OK);
}

int
cmd_sizeof_tab(mdb_tab_cookie_t *mcp, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	char tn[MDB_SYM_NAMLEN];
	int ret;

	if (argc == 0 && !(flags & DCMD_TAB_SPACE))
		return (0);

	if (argc == 0 && (flags & DCMD_TAB_SPACE))
		return (mdb_tab_complete_type(mcp, NULL, MDB_TABC_NOPOINT));

	if ((ret = mdb_tab_typename(&argc, &argv, tn, sizeof (tn))) < 0)
		return (ret);

	if (argc == 1)
		return (mdb_tab_complete_type(mcp, tn, MDB_TABC_NOPOINT));

	return (0);
}

/*ARGSUSED*/
int
cmd_offsetof(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	const char *member;
	mdb_ctf_id_t id;
	ulong_t off;
	char tn[MDB_SYM_NAMLEN];
	ssize_t sz;
	int ret;

	if (flags & DCMD_ADDRSPEC)
		return (DCMD_USAGE);

	if ((ret = args_to_typename(&argc, &argv, tn, sizeof (tn))) != 0)
		return (ret);

	if (argc != 2 || argv[1].a_type != MDB_TYPE_STRING)
		return (DCMD_USAGE);

	if (mdb_ctf_lookup_by_name(tn, &id) != 0) {
		mdb_warn("failed to look up type %s", tn);
		return (DCMD_ERR);
	}

	member = argv[1].a_un.a_str;

	if (mdb_ctf_member_info(id, member, &off, &id) != 0) {
		mdb_warn("failed to find member %s of type %s", member, tn);
		return (DCMD_ERR);
	}

	if (flags & DCMD_PIPE_OUT) {
		if (off % NBBY != 0) {
			mdb_warn("member %s of type %s is not byte-aligned\n",
			    member, tn);
			return (DCMD_ERR);
		}
		mdb_printf("%#lr", off / NBBY);
		return (DCMD_OK);
	}

	mdb_printf("offsetof (%s, %s) = %#lr",
	    tn, member, off / NBBY);
	if (off % NBBY != 0)
		mdb_printf(".%lr", off % NBBY);

	if ((sz = mdb_ctf_type_size(id)) > 0)
		mdb_printf(", sizeof (...->%s) = %#lr", member, sz);

	mdb_printf("\n");

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
enum_prefix_scan_cb(const char *name, int value, void *arg)
{
	char *str = arg;

	/*
	 * This function is called with every name in the enum.  We make
	 * "arg" be the common prefix, if any.
	 */
	if (str[0] == 0) {
		if (strlcpy(arg, name, MDB_SYM_NAMLEN) >= MDB_SYM_NAMLEN)
			return (1);
		return (0);
	}

	while (*name == *str) {
		if (*str == 0) {
			if (str != arg) {
				str--;	/* don't smother a name completely */
			}
			break;
		}
		name++;
		str++;
	}
	*str = 0;

	return (str == arg);	/* only continue if prefix is non-empty */
}

struct enum_p2_info {
	intmax_t e_value;	/* value we're processing */
	char	*e_buf;		/* buffer for holding names */
	size_t	e_size;		/* size of buffer */
	size_t	e_prefix;	/* length of initial prefix */
	uint_t	e_allprefix;	/* apply prefix to first guy, too */
	uint_t	e_bits;		/* bits seen */
	uint8_t	e_found;	/* have we seen anything? */
	uint8_t	e_first;	/* does buf contain the first one? */
	uint8_t	e_zero;		/* have we seen a zero value? */
};

static int
enum_p2_cb(const char *name, int bit_arg, void *arg)
{
	struct enum_p2_info *eiip = arg;
	uintmax_t bit = bit_arg;

	if (bit != 0 && !ISP2(bit))
		return (1);	/* non-power-of-2; abort processing */

	if ((bit == 0 && eiip->e_zero) ||
	    (bit != 0 && (eiip->e_bits & bit) != 0)) {
		return (0);	/* already seen this value */
	}

	if (bit == 0)
		eiip->e_zero = 1;
	else
		eiip->e_bits |= bit;

	if (eiip->e_buf != NULL && (eiip->e_value & bit) != 0) {
		char *buf = eiip->e_buf;
		size_t prefix = eiip->e_prefix;

		if (eiip->e_found) {
			(void) strlcat(buf, "|", eiip->e_size);

			if (eiip->e_first && !eiip->e_allprefix && prefix > 0) {
				char c1 = buf[prefix];
				char c2 = buf[prefix + 1];
				buf[prefix] = '{';
				buf[prefix + 1] = 0;
				mdb_printf("%s", buf);
				buf[prefix] = c1;
				buf[prefix + 1] = c2;
				mdb_printf("%s", buf + prefix);
			} else {
				mdb_printf("%s", buf);
			}

		}
		/* skip the common prefix as necessary */
		if ((eiip->e_found || eiip->e_allprefix) &&
		    strlen(name) > prefix)
			name += prefix;

		(void) strlcpy(eiip->e_buf, name, eiip->e_size);
		eiip->e_first = !eiip->e_found;
		eiip->e_found = 1;
	}
	return (0);
}

static int
enum_is_p2(mdb_ctf_id_t id)
{
	struct enum_p2_info eii;
	bzero(&eii, sizeof (eii));

	return (mdb_ctf_type_kind(id) == CTF_K_ENUM &&
	    mdb_ctf_enum_iter(id, enum_p2_cb, &eii) == 0 &&
	    eii.e_bits != 0);
}

static int
enum_value_print_p2(mdb_ctf_id_t id, intmax_t value, uint_t allprefix)
{
	struct enum_p2_info eii;
	char prefix[MDB_SYM_NAMLEN + 2];
	intmax_t missed;

	bzero(&eii, sizeof (eii));

	eii.e_value = value;
	eii.e_buf = prefix;
	eii.e_size = sizeof (prefix);
	eii.e_allprefix = allprefix;

	prefix[0] = 0;
	if (mdb_ctf_enum_iter(id, enum_prefix_scan_cb, prefix) == 0)
		eii.e_prefix = strlen(prefix);

	if (mdb_ctf_enum_iter(id, enum_p2_cb, &eii) != 0 || eii.e_bits == 0)
		return (-1);

	missed = (value & ~(intmax_t)eii.e_bits);

	if (eii.e_found) {
		/* push out any final value, with a | if we missed anything */
		if (!eii.e_first)
			(void) strlcat(prefix, "}", sizeof (prefix));
		if (missed != 0)
			(void) strlcat(prefix, "|", sizeof (prefix));

		mdb_printf("%s", prefix);
	}

	if (!eii.e_found || missed) {
		mdb_printf("%#llx", missed);
	}

	return (0);
}

struct enum_cbinfo {
	uint_t		e_flags;
	const char	*e_string;	/* NULL for value searches */
	size_t		e_prefix;
	intmax_t	e_value;
	uint_t		e_found;
	mdb_ctf_id_t	e_id;
};
#define	E_PRETTY		0x01
#define	E_HEX			0x02
#define	E_SEARCH_STRING		0x04
#define	E_SEARCH_VALUE		0x08
#define	E_ELIDE_PREFIX		0x10

static void
enum_print(struct enum_cbinfo *info, const char *name, int value)
{
	uint_t flags = info->e_flags;
	uint_t elide_prefix = (info->e_flags & E_ELIDE_PREFIX);

	if (name != NULL && info->e_prefix && strlen(name) > info->e_prefix)
		name += info->e_prefix;

	if (flags & E_PRETTY) {
		uint_t indent = 5 + ((flags & E_HEX) ? 8 : 11);

		mdb_printf((flags & E_HEX)? "%8x " : "%11d ", value);
		(void) mdb_inc_indent(indent);
		if (name != NULL) {
			mdb_iob_puts(mdb.m_out, name);
		} else {
			(void) enum_value_print_p2(info->e_id, value,
			    elide_prefix);
		}
		(void) mdb_dec_indent(indent);
		mdb_printf("\n");
	} else {
		mdb_printf("%#r\n", value);
	}
}

static int
enum_cb(const char *name, int value, void *arg)
{
	struct enum_cbinfo *info = arg;
	uint_t flags = info->e_flags;

	if (flags & E_SEARCH_STRING) {
		if (strcmp(name, info->e_string) != 0)
			return (0);

	} else if (flags & E_SEARCH_VALUE) {
		if (value != info->e_value)
			return (0);
	}

	enum_print(info, name, value);

	info->e_found = 1;
	return (0);
}

void
enum_help(void)
{
	mdb_printf("%s",
"Without an address and name, print all values for the enumeration \"enum\".\n"
"With an address, look up a particular value in \"enum\".  With a name, look\n"
"up a particular name in \"enum\".\n");

	(void) mdb_dec_indent(2);
	mdb_printf("\n%<b>OPTIONS%</b>\n");
	(void) mdb_inc_indent(2);

	mdb_printf("%s",
"   -e    remove common prefixes from enum names\n"
"   -x    report enum values in hexadecimal\n");
}

/*ARGSUSED*/
int
cmd_enum(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct enum_cbinfo info;

	char type[MDB_SYM_NAMLEN + sizeof ("enum ")];
	char tn2[MDB_SYM_NAMLEN + sizeof ("enum ")];
	char prefix[MDB_SYM_NAMLEN];
	mdb_ctf_id_t id;
	mdb_ctf_id_t idr;

	int i;
	intmax_t search;
	uint_t isp2;

	info.e_flags = (flags & DCMD_PIPE_OUT)? 0 : E_PRETTY;
	info.e_string = NULL;
	info.e_value = 0;
	info.e_found = 0;

	i = mdb_getopts(argc, argv,
	    'e', MDB_OPT_SETBITS, E_ELIDE_PREFIX, &info.e_flags,
	    'x', MDB_OPT_SETBITS, E_HEX, &info.e_flags,
	    NULL);

	argc -= i;
	argv += i;

	if ((i = args_to_typename(&argc, &argv, type, MDB_SYM_NAMLEN)) != 0)
		return (i);

	if (strchr(type, ' ') == NULL) {
		/*
		 * Check as an enumeration tag first, and fall back
		 * to checking for a typedef.  Yes, this means that
		 * anonymous enumerations whose typedefs conflict with
		 * an enum tag can't be accessed.  Don't do that.
		 */
		(void) mdb_snprintf(tn2, sizeof (tn2), "enum %s", type);

		if (mdb_ctf_lookup_by_name(tn2, &id) == 0) {
			(void) strcpy(type, tn2);
		} else if (mdb_ctf_lookup_by_name(type, &id) != 0) {
			mdb_warn("types '%s', '%s'", tn2, type);
			return (DCMD_ERR);
		}
	} else {
		if (mdb_ctf_lookup_by_name(type, &id) != 0) {
			mdb_warn("'%s'", type);
			return (DCMD_ERR);
		}
	}

	/* resolve it, and make sure we're looking at an enumeration */
	if (mdb_ctf_type_resolve(id, &idr) == -1) {
		mdb_warn("unable to resolve '%s'", type);
		return (DCMD_ERR);
	}
	if (mdb_ctf_type_kind(idr) != CTF_K_ENUM) {
		mdb_warn("'%s': not an enumeration\n", type);
		return (DCMD_ERR);
	}

	info.e_id = idr;

	if (argc > 2)
		return (DCMD_USAGE);

	if (argc == 2) {
		if (flags & DCMD_ADDRSPEC) {
			mdb_warn("may only specify one of: name, address\n");
			return (DCMD_USAGE);
		}

		if (argv[1].a_type == MDB_TYPE_STRING) {
			info.e_flags |= E_SEARCH_STRING;
			info.e_string = argv[1].a_un.a_str;
		} else if (argv[1].a_type == MDB_TYPE_IMMEDIATE) {
			info.e_flags |= E_SEARCH_VALUE;
			search = argv[1].a_un.a_val;
		} else {
			return (DCMD_USAGE);
		}
	}

	if (flags & DCMD_ADDRSPEC) {
		info.e_flags |= E_SEARCH_VALUE;
		search = mdb_get_dot();
	}

	if (info.e_flags & E_SEARCH_VALUE) {
		if ((int)search != search) {
			mdb_warn("value '%lld' out of enumeration range\n",
			    search);
		}
		info.e_value = search;
	}

	isp2 = enum_is_p2(idr);
	if (isp2)
		info.e_flags |= E_HEX;

	if (DCMD_HDRSPEC(flags) && (info.e_flags & E_PRETTY)) {
		if (info.e_flags & E_HEX)
			mdb_printf("%<u>%8s %-64s%</u>\n", "VALUE", "NAME");
		else
			mdb_printf("%<u>%11s %-64s%</u>\n", "VALUE", "NAME");
	}

	/* if the enum is a power-of-two one, process it that way */
	if ((info.e_flags & E_SEARCH_VALUE) && isp2) {
		enum_print(&info, NULL, info.e_value);
		return (DCMD_OK);
	}

	prefix[0] = 0;
	if ((info.e_flags & E_ELIDE_PREFIX) &&
	    mdb_ctf_enum_iter(id, enum_prefix_scan_cb, prefix) == 0)
		info.e_prefix = strlen(prefix);

	if (mdb_ctf_enum_iter(idr, enum_cb, &info) == -1) {
		mdb_warn("cannot walk '%s' as enum", type);
		return (DCMD_ERR);
	}

	if (info.e_found == 0 &&
	    (info.e_flags & (E_SEARCH_STRING | E_SEARCH_VALUE)) != 0) {
		if (info.e_flags & E_SEARCH_STRING)
			mdb_warn("name \"%s\" not in '%s'\n", info.e_string,
			    type);
		else
			mdb_warn("value %#lld not in '%s'\n", info.e_value,
			    type);

		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

static int
setup_vcb(const char *name, uintptr_t addr)
{
	const char *p;
	mdb_var_t *v;

	if ((v = mdb_nv_lookup(&mdb.m_nv, name)) == NULL) {
		if ((p = strbadid(name)) != NULL) {
			mdb_warn("'%c' may not be used in a variable "
			    "name\n", *p);
			return (DCMD_ABORT);
		}

		if ((v = mdb_nv_insert(&mdb.m_nv, name, NULL, addr, 0)) == NULL)
			return (DCMD_ERR);
	} else {
		if (v->v_flags & MDB_NV_RDONLY) {
			mdb_warn("variable %s is read-only\n", name);
			return (DCMD_ABORT);
		}
	}

	/*
	 * If there already exists a vcb for this variable, we may be
	 * calling the dcmd in a loop.  We only create a vcb for this
	 * variable on the first invocation.
	 */
	if (mdb_vcb_find(v, mdb.m_frame) == NULL)
		mdb_vcb_insert(mdb_vcb_create(v), mdb.m_frame);

	return (0);
}

/*ARGSUSED*/
int
cmd_list(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int offset;
	uintptr_t a, tmp;
	int ret;

	if (!(flags & DCMD_ADDRSPEC) || argc == 0)
		return (DCMD_USAGE);

	if (argv->a_type != MDB_TYPE_STRING) {
		/*
		 * We are being given a raw offset in lieu of a type and
		 * member; confirm the number of arguments and argument
		 * type.
		 */
		if (argc != 1 || argv->a_type != MDB_TYPE_IMMEDIATE)
			return (DCMD_USAGE);

		offset = argv->a_un.a_val;

		argv++;
		argc--;

		if (offset % sizeof (uintptr_t)) {
			mdb_warn("offset must fall on a word boundary\n");
			return (DCMD_ABORT);
		}
	} else {
		const char *member;
		char buf[MDB_SYM_NAMLEN];
		int ret;

		/*
		 * Check that we were provided 2 arguments: a type name
		 * and a member of that type.
		 */
		if (argc != 2)
			return (DCMD_USAGE);

		ret = args_to_typename(&argc, &argv, buf, sizeof (buf));
		if (ret != 0)
			return (ret);

		argv++;
		argc--;

		member = argv->a_un.a_str;
		offset = mdb_ctf_offsetof_by_name(buf, member);
		if (offset == -1)
			return (DCMD_ABORT);

		argv++;
		argc--;

		if (offset % (sizeof (uintptr_t)) != 0) {
			mdb_warn("%s is not a word-aligned member\n", member);
			return (DCMD_ABORT);
		}
	}

	/*
	 * If we have any unchewed arguments, a variable name must be present.
	 */
	if (argc == 1) {
		if (argv->a_type != MDB_TYPE_STRING)
			return (DCMD_USAGE);

		if ((ret = setup_vcb(argv->a_un.a_str, addr)) != 0)
			return (ret);

	} else if (argc != 0) {
		return (DCMD_USAGE);
	}

	a = addr;

	do {
		mdb_printf("%lr\n", a);

		if (mdb_vread(&tmp, sizeof (tmp), a + offset) == -1) {
			mdb_warn("failed to read next pointer from object %p",
			    a);
			return (DCMD_ERR);
		}

		a = tmp;
	} while (a != addr && a != NULL);

	return (DCMD_OK);
}

int
cmd_array(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_ctf_id_t id;
	ssize_t elemsize = 0;
	char tn[MDB_SYM_NAMLEN];
	int ret, nelem = -1;

	mdb_tgt_t *t = mdb.m_target;
	GElf_Sym sym;
	mdb_ctf_arinfo_t ar;
	mdb_syminfo_t s_info;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (argc >= 2) {
		ret = args_to_typename(&argc, &argv, tn, sizeof (tn));
		if (ret != 0)
			return (ret);

		if (argc == 1)	/* unquoted compound type without count */
			return (DCMD_USAGE);

		if (mdb_ctf_lookup_by_name(tn, &id) != 0) {
			mdb_warn("failed to look up type %s", tn);
			return (DCMD_ABORT);
		}

		if (argv[1].a_type == MDB_TYPE_IMMEDIATE)
			nelem = argv[1].a_un.a_val;
		else
			nelem = mdb_strtoull(argv[1].a_un.a_str);

		elemsize = mdb_ctf_type_size(id);
	} else if (addr_to_sym(t, addr, tn, sizeof (tn), &sym, &s_info)
	    != NULL && mdb_ctf_lookup_by_symbol(&sym, &s_info, &id)
	    == 0 && mdb_ctf_type_kind(id) == CTF_K_ARRAY &&
	    mdb_ctf_array_info(id, &ar) != -1) {
		elemsize = mdb_ctf_type_size(id) / ar.mta_nelems;
		nelem = ar.mta_nelems;
	} else {
		mdb_warn("no symbol information for %a", addr);
		return (DCMD_ERR);
	}

	if (argc == 3 || argc == 1) {
		if (argv[argc - 1].a_type != MDB_TYPE_STRING)
			return (DCMD_USAGE);

		if ((ret = setup_vcb(argv[argc - 1].a_un.a_str, addr)) != 0)
			return (ret);

	} else if (argc > 3) {
		return (DCMD_USAGE);
	}

	for (; nelem > 0; nelem--) {
		mdb_printf("%lr\n", addr);
		addr = addr + elemsize;
	}

	return (DCMD_OK);
}

/*
 * Print an integer bitfield in hexadecimal by reading the enclosing byte(s)
 * and then shifting and masking the data in the lower bits of a uint64_t.
 */
static int
print_bitfield(ulong_t off, printarg_t *pap, ctf_encoding_t *ep)
{
	mdb_tgt_addr_t addr = pap->pa_addr + off / NBBY;
	size_t size = (ep->cte_bits + (NBBY - 1)) / NBBY;
	uint64_t mask = (1ULL << ep->cte_bits) - 1;
	uint64_t value = 0;
	uint8_t *buf = (uint8_t *)&value;
	uint8_t shift;

	const char *format;

	if (!(pap->pa_flags & PA_SHOWVAL))
		return (0);

	if (ep->cte_bits > sizeof (value) * NBBY - 1) {
		mdb_printf("??? (invalid bitfield size %u)", ep->cte_bits);
		return (0);
	}

	/*
	 * On big-endian machines, we need to adjust the buf pointer to refer
	 * to the lowest 'size' bytes in 'value', and we need shift based on
	 * the offset from the end of the data, not the offset of the start.
	 */
#ifdef _BIG_ENDIAN
	buf += sizeof (value) - size;
	off += ep->cte_bits;
#endif
	if (mdb_tgt_aread(pap->pa_tgt, pap->pa_as, buf, size, addr) != size) {
		mdb_warn("failed to read %lu bytes at %llx",
		    (ulong_t)size, addr);
		return (1);
	}

	shift = off % NBBY;

	/*
	 * Offsets are counted from opposite ends on little- and
	 * big-endian machines.
	 */
#ifdef _BIG_ENDIAN
	shift = NBBY - shift;
#endif

	/*
	 * If the bits we want do not begin on a byte boundary, shift the data
	 * right so that the value is in the lowest 'cte_bits' of 'value'.
	 */
	if (off % NBBY != 0)
		value >>= shift;
	value &= mask;

	/*
	 * We default to printing signed bitfields as decimals,
	 * and unsigned bitfields in hexadecimal.  If they specify
	 * hexadecimal, we treat the field as unsigned.
	 */
	if ((pap->pa_flags & PA_INTHEX) ||
	    !(ep->cte_format & CTF_INT_SIGNED)) {
		format = (pap->pa_flags & PA_INTDEC)? "%#llu" : "%#llx";
	} else {
		int sshift = sizeof (value) * NBBY - ep->cte_bits;

		/* sign-extend value, and print as a signed decimal */
		value = ((int64_t)value << sshift) >> sshift;
		format = "%#lld";
	}
	mdb_printf(format, value);

	return (0);
}

/*
 * Print out a character or integer value.  We use some simple heuristics,
 * described below, to determine the appropriate radix to use for output.
 */
static int
print_int_val(const char *type, ctf_encoding_t *ep, ulong_t off,
    printarg_t *pap)
{
	static const char *const sformat[] = { "%#d", "%#d", "%#d", "%#lld" };
	static const char *const uformat[] = { "%#u", "%#u", "%#u", "%#llu" };
	static const char *const xformat[] = { "%#x", "%#x", "%#x", "%#llx" };

	mdb_tgt_addr_t addr = pap->pa_addr + off / NBBY;
	const char *const *fsp;
	size_t size;

	union {
		uint64_t i8;
		uint32_t i4;
		uint16_t i2;
		uint8_t i1;
		time_t t;
		ipaddr_t I;
	} u;

	if (!(pap->pa_flags & PA_SHOWVAL))
		return (0);

	if (ep->cte_format & CTF_INT_VARARGS) {
		mdb_printf("...\n");
		return (0);
	}

	/*
	 * If the size is not a power-of-two number of bytes in the range 1-8
	 * then we assume it is a bitfield and print it as such.
	 */
	size = ep->cte_bits / NBBY;
	if (size > 8 || (ep->cte_bits % NBBY) != 0 || (size & (size - 1)) != 0)
		return (print_bitfield(off, pap, ep));

	if (IS_CHAR(*ep)) {
		mdb_printf("'");
		if (mdb_fmt_print(pap->pa_tgt, pap->pa_as,
		    addr, 1, 'C') == addr)
			return (1);
		mdb_printf("'");
		return (0);
	}

	if (mdb_tgt_aread(pap->pa_tgt, pap->pa_as, &u.i8, size, addr) != size) {
		mdb_warn("failed to read %lu bytes at %llx",
		    (ulong_t)size, addr);
		return (1);
	}

	/*
	 * We pretty-print some integer based types.  time_t values are
	 * printed as a calendar date and time, and IPv4 addresses as human
	 * readable dotted quads.
	 */
	if (!(pap->pa_flags & (PA_INTHEX | PA_INTDEC))) {
		if (strcmp(type, "time_t") == 0 && u.t != 0) {
			mdb_printf("%Y", u.t);
			return (0);
		}
		if (strcmp(type, "ipaddr_t") == 0 ||
		    strcmp(type, "in_addr_t") == 0) {
			mdb_printf("%I", u.I);
			return (0);
		}
	}

	/*
	 * The default format is hexadecimal.
	 */
	if (!(pap->pa_flags & PA_INTDEC))
		fsp = xformat;
	else if (ep->cte_format & CTF_INT_SIGNED)
		fsp = sformat;
	else
		fsp = uformat;

	switch (size) {
	case sizeof (uint8_t):
		mdb_printf(fsp[0], u.i1);
		break;
	case sizeof (uint16_t):
		mdb_printf(fsp[1], u.i2);
		break;
	case sizeof (uint32_t):
		mdb_printf(fsp[2], u.i4);
		break;
	case sizeof (uint64_t):
		mdb_printf(fsp[3], u.i8);
		break;
	}
	return (0);
}

/*ARGSUSED*/
static int
print_int(const char *type, const char *name, mdb_ctf_id_t id,
    mdb_ctf_id_t base, ulong_t off, printarg_t *pap)
{
	ctf_encoding_t e;

	if (!(pap->pa_flags & PA_SHOWVAL))
		return (0);

	if (mdb_ctf_type_encoding(base, &e) != 0) {
		mdb_printf("??? (%s)", mdb_strerror(errno));
		return (0);
	}

	return (print_int_val(type, &e, off, pap));
}

/*
 * Print out a floating point value.  We only provide support for floats in
 * the ANSI-C float, double, and long double formats.
 */
/*ARGSUSED*/
static int
print_float(const char *type, const char *name, mdb_ctf_id_t id,
    mdb_ctf_id_t base, ulong_t off, printarg_t *pap)
{
#ifndef _KMDB
	mdb_tgt_addr_t addr = pap->pa_addr + off / NBBY;
	ctf_encoding_t e;

	union {
		float f;
		double d;
		long double ld;
	} u;

	if (!(pap->pa_flags & PA_SHOWVAL))
		return (0);

	if (mdb_ctf_type_encoding(base, &e) == 0) {
		if (e.cte_format == CTF_FP_SINGLE &&
		    e.cte_bits == sizeof (float) * NBBY) {
			if (mdb_tgt_aread(pap->pa_tgt, pap->pa_as, &u.f,
			    sizeof (u.f), addr) != sizeof (u.f)) {
				mdb_warn("failed to read float at %llx", addr);
				return (1);
			}
			mdb_printf("%s", doubletos(u.f, 7, 'e'));

		} else if (e.cte_format == CTF_FP_DOUBLE &&
		    e.cte_bits == sizeof (double) * NBBY) {
			if (mdb_tgt_aread(pap->pa_tgt, pap->pa_as, &u.d,
			    sizeof (u.d), addr) != sizeof (u.d)) {
				mdb_warn("failed to read float at %llx", addr);
				return (1);
			}
			mdb_printf("%s", doubletos(u.d, 7, 'e'));

		} else if (e.cte_format == CTF_FP_LDOUBLE &&
		    e.cte_bits == sizeof (long double) * NBBY) {
			if (mdb_tgt_aread(pap->pa_tgt, pap->pa_as, &u.ld,
			    sizeof (u.ld), addr) != sizeof (u.ld)) {
				mdb_warn("failed to read float at %llx", addr);
				return (1);
			}
			mdb_printf("%s", longdoubletos(&u.ld, 16, 'e'));

		} else {
			mdb_printf("??? (unsupported FP format %u / %u bits\n",
			    e.cte_format, e.cte_bits);
		}
	} else
		mdb_printf("??? (%s)", mdb_strerror(errno));
#else
	mdb_printf("<FLOAT>");
#endif
	return (0);
}


/*
 * Print out a pointer value as a symbol name + offset or a hexadecimal value.
 * If the pointer itself is a char *, we attempt to read a bit of the data
 * referenced by the pointer and display it if it is a printable ASCII string.
 */
/*ARGSUSED*/
static int
print_ptr(const char *type, const char *name, mdb_ctf_id_t id,
    mdb_ctf_id_t base, ulong_t off, printarg_t *pap)
{
	mdb_tgt_addr_t addr = pap->pa_addr + off / NBBY;
	ctf_encoding_t e;
	uintptr_t value;
	char buf[256];
	ssize_t len;

	if (!(pap->pa_flags & PA_SHOWVAL))
		return (0);

	if (mdb_tgt_aread(pap->pa_tgt, pap->pa_as,
	    &value, sizeof (value), addr) != sizeof (value)) {
		mdb_warn("failed to read %s pointer at %llx", name, addr);
		return (1);
	}

	if (pap->pa_flags & PA_NOSYMBOLIC) {
		mdb_printf("%#lx", value);
		return (0);
	}

	mdb_printf("%a", value);

	if (value == NULL || strcmp(type, "caddr_t") == 0)
		return (0);

	if (mdb_ctf_type_kind(base) == CTF_K_POINTER &&
	    mdb_ctf_type_reference(base, &base) != -1 &&
	    mdb_ctf_type_resolve(base, &base) != -1 &&
	    mdb_ctf_type_encoding(base, &e) == 0 && IS_CHAR(e)) {
		if ((len = mdb_tgt_readstr(pap->pa_realtgt, pap->pa_as,
		    buf, sizeof (buf), value)) >= 0 && strisprint(buf)) {
			if (len == sizeof (buf))
				(void) strabbr(buf, sizeof (buf));
			mdb_printf(" \"%s\"", buf);
		}
	}

	return (0);
}


/*
 * Print out a fixed-size array.  We special-case arrays of characters
 * and attempt to print them out as ASCII strings if possible.  For other
 * arrays, we iterate over a maximum of pa_armemlim members and call
 * mdb_ctf_type_visit() again on each element to print its value.
 */
/*ARGSUSED*/
static int
print_array(const char *type, const char *name, mdb_ctf_id_t id,
    mdb_ctf_id_t base, ulong_t off, printarg_t *pap)
{
	mdb_tgt_addr_t addr = pap->pa_addr + off / NBBY;
	printarg_t pa = *pap;
	ssize_t eltsize;
	mdb_ctf_arinfo_t r;
	ctf_encoding_t e;
	uint_t i, kind, limit;
	int d, sou;
	char buf[8];
	char *str;

	if (!(pap->pa_flags & PA_SHOWVAL))
		return (0);

	if (pap->pa_depth == pap->pa_maxdepth) {
		mdb_printf("[ ... ]");
		return (0);
	}

	/*
	 * Determine the base type and size of the array's content.  If this
	 * fails, we cannot print anything and just give up.
	 */
	if (mdb_ctf_array_info(base, &r) == -1 ||
	    mdb_ctf_type_resolve(r.mta_contents, &base) == -1 ||
	    (eltsize = mdb_ctf_type_size(base)) == -1) {
		mdb_printf("[ ??? ] (%s)", mdb_strerror(errno));
		return (0);
	}

	/*
	 * Read a few bytes and determine if the content appears to be
	 * printable ASCII characters.  If so, read the entire array and
	 * attempt to display it as a string if it is printable.
	 */
	if ((pap->pa_arstrlim == MDB_ARR_NOLIMIT ||
	    r.mta_nelems <= pap->pa_arstrlim) &&
	    mdb_ctf_type_encoding(base, &e) == 0 && IS_CHAR(e) &&
	    mdb_tgt_readstr(pap->pa_tgt, pap->pa_as, buf,
	    MIN(sizeof (buf), r.mta_nelems), addr) > 0 && strisprint(buf)) {

		str = mdb_alloc(r.mta_nelems + 1, UM_SLEEP | UM_GC);
		str[r.mta_nelems] = '\0';

		if (mdb_tgt_aread(pap->pa_tgt, pap->pa_as, str,
		    r.mta_nelems, addr) != r.mta_nelems) {
			mdb_warn("failed to read char array at %llx", addr);
			return (1);
		}

		if (strisprint(str)) {
			mdb_printf("[ \"%s\" ]", str);
			return (0);
		}
	}

	if (pap->pa_armemlim != MDB_ARR_NOLIMIT)
		limit = MIN(r.mta_nelems, pap->pa_armemlim);
	else
		limit = r.mta_nelems;

	if (limit == 0) {
		mdb_printf("[ ... ]");
		return (0);
	}

	kind = mdb_ctf_type_kind(base);
	sou = IS_COMPOSITE(kind);

	pa.pa_addr = addr;		/* set base address to start of array */
	pa.pa_maxdepth = pa.pa_maxdepth - pa.pa_depth - 1;
	pa.pa_nest += pa.pa_depth + 1;	/* nesting level is current depth + 1 */
	pa.pa_depth = 0;		/* reset depth to 0 for new scope */
	pa.pa_prefix = NULL;

	if (sou) {
		pa.pa_delim = "\n";
		mdb_printf("[\n");
	} else {
		pa.pa_flags &= ~(PA_SHOWTYPE | PA_SHOWNAME | PA_SHOWADDR);
		pa.pa_delim = ", ";
		mdb_printf("[ ");
	}

	for (i = 0; i < limit; i++, pa.pa_addr += eltsize) {
		if (i == limit - 1 && !sou) {
			if (limit < r.mta_nelems)
				pa.pa_delim = ", ... ]";
			else
				pa.pa_delim = " ]";
		}

		if (mdb_ctf_type_visit(r.mta_contents, elt_print, &pa) == -1) {
			mdb_warn("failed to print array data");
			return (1);
		}
	}

	if (sou) {
		for (d = pa.pa_depth - 1; d >= 0; d--)
			print_close_sou(&pa, d);

		if (limit < r.mta_nelems) {
			mdb_printf("%*s... ]",
			    (pap->pa_depth + pap->pa_nest) * pap->pa_tab, "");
		} else {
			mdb_printf("%*s]",
			    (pap->pa_depth + pap->pa_nest) * pap->pa_tab, "");
		}
	}

	/* copy the hole array info, since it may have been grown */
	pap->pa_holes = pa.pa_holes;
	pap->pa_nholes = pa.pa_nholes;

	return (0);
}

/*
 * Print out a struct or union header.  We need only print the open brace
 * because mdb_ctf_type_visit() itself will automatically recurse through
 * all members of the given struct or union.
 */
/*ARGSUSED*/
static int
print_sou(const char *type, const char *name, mdb_ctf_id_t id,
    mdb_ctf_id_t base, ulong_t off, printarg_t *pap)
{
	mdb_tgt_addr_t addr = pap->pa_addr + off / NBBY;

	/*
	 * We have pretty-printing for some structures where displaying
	 * structure contents has no value.
	 */
	if (pap->pa_flags & PA_SHOWVAL) {
		if (strcmp(type, "in6_addr_t") == 0 ||
		    strcmp(type, "struct in6_addr") == 0) {
			in6_addr_t in6addr;

			if (mdb_tgt_aread(pap->pa_tgt, pap->pa_as, &in6addr,
			    sizeof (in6addr), addr) != sizeof (in6addr)) {
				mdb_warn("failed to read %s pointer at %llx",
				    name, addr);
				return (1);
			}
			mdb_printf("%N", &in6addr);
			/*
			 * Don't print anything further down in the
			 * structure.
			 */
			pap->pa_nooutdepth = pap->pa_depth;
			return (0);
		}
		if (strcmp(type, "struct in_addr") == 0) {
			in_addr_t inaddr;

			if (mdb_tgt_aread(pap->pa_tgt, pap->pa_as, &inaddr,
			    sizeof (inaddr), addr) != sizeof (inaddr)) {
				mdb_warn("failed to read %s pointer at %llx",
				    name, addr);
				return (1);
			}
			mdb_printf("%I", inaddr);
			pap->pa_nooutdepth = pap->pa_depth;
			return (0);
		}
	}

	if (pap->pa_depth == pap->pa_maxdepth)
		mdb_printf("{ ... }");
	else
		mdb_printf("{");
	pap->pa_delim = "\n";
	return (0);
}

/*
 * Print an enum value.  We attempt to convert the value to the corresponding
 * enum name and print that if possible.
 */
/*ARGSUSED*/
static int
print_enum(const char *type, const char *name, mdb_ctf_id_t id,
    mdb_ctf_id_t base, ulong_t off, printarg_t *pap)
{
	mdb_tgt_addr_t addr = pap->pa_addr + off / NBBY;
	const char *ename;
	int value;
	int isp2 = enum_is_p2(base);
	int flags = pap->pa_flags | (isp2 ? PA_INTHEX : 0);

	if (!(flags & PA_SHOWVAL))
		return (0);

	if (mdb_tgt_aread(pap->pa_tgt, pap->pa_as,
	    &value, sizeof (value), addr) != sizeof (value)) {
		mdb_warn("failed to read %s integer at %llx", name, addr);
		return (1);
	}

	if (flags & PA_INTHEX)
		mdb_printf("%#x", value);
	else
		mdb_printf("%#d", value);

	(void) mdb_inc_indent(8);
	mdb_printf(" (");

	if (!isp2 || enum_value_print_p2(base, value, 0) != 0) {
		ename = mdb_ctf_enum_name(base, value);
		if (ename == NULL) {
			ename = "???";
		}
		mdb_printf("%s", ename);
	}
	mdb_printf(")");
	(void) mdb_dec_indent(8);

	return (0);
}

/*
 * This will only get called if the structure isn't found in any available CTF
 * data.
 */
/*ARGSUSED*/
static int
print_tag(const char *type, const char *name, mdb_ctf_id_t id,
    mdb_ctf_id_t base, ulong_t off, printarg_t *pap)
{
	char basename[MDB_SYM_NAMLEN];

	if (pap->pa_flags & PA_SHOWVAL)
		mdb_printf("; ");

	if (mdb_ctf_type_name(base, basename, sizeof (basename)) != NULL)
		mdb_printf("<forward declaration of %s>", basename);
	else
		mdb_printf("<forward declaration of unknown type>");

	return (0);
}

static void
print_hole(printarg_t *pap, int depth, ulong_t off, ulong_t endoff)
{
	ulong_t bits = endoff - off;
	ulong_t size = bits / NBBY;
	ctf_encoding_t e;

	static const char *const name = "<<HOLE>>";
	char type[MDB_SYM_NAMLEN];

	int bitfield =
	    (off % NBBY != 0 ||
	    bits % NBBY != 0 ||
	    size > 8 ||
	    (size & (size - 1)) != 0);

	ASSERT(off < endoff);

	if (bits > NBBY * sizeof (uint64_t)) {
		ulong_t end;

		/*
		 * The hole is larger than the largest integer type.  To
		 * handle this, we split up the hole at 8-byte-aligned
		 * boundaries, recursing to print each subsection.  For
		 * normal C structures, we'll loop at most twice.
		 */
		for (; off < endoff; off = end) {
			end = P2END(off, NBBY * sizeof (uint64_t));
			if (end > endoff)
				end = endoff;

			ASSERT((end - off) <= NBBY * sizeof (uint64_t));
			print_hole(pap, depth, off, end);
		}
		ASSERT(end == endoff);

		return;
	}

	if (bitfield)
		(void) mdb_snprintf(type, sizeof (type), "unsigned");
	else
		(void) mdb_snprintf(type, sizeof (type), "uint%d_t", bits);

	if (pap->pa_flags & (PA_SHOWTYPE | PA_SHOWNAME | PA_SHOWADDR))
		mdb_printf("%*s", (depth + pap->pa_nest) * pap->pa_tab, "");

	if (pap->pa_flags & PA_SHOWADDR) {
		if (off % NBBY == 0)
			mdb_printf("%llx ", pap->pa_addr + off / NBBY);
		else
			mdb_printf("%llx.%lx ",
			    pap->pa_addr + off / NBBY, off % NBBY);
	}

	if (pap->pa_flags & PA_SHOWTYPE)
		mdb_printf("%s ", type);

	if (pap->pa_flags & PA_SHOWNAME)
		mdb_printf("%s", name);

	if (bitfield && (pap->pa_flags & PA_SHOWTYPE))
		mdb_printf(" :%d", bits);

	mdb_printf("%s ", (pap->pa_flags & PA_SHOWVAL)? " =" : "");

	/*
	 * We fake up a ctf_encoding_t, and use print_int_val() to print
	 * the value.  Holes are always processed as unsigned integers.
	 */
	bzero(&e, sizeof (e));
	e.cte_format = 0;
	e.cte_offset = 0;
	e.cte_bits = bits;

	if (print_int_val(type, &e, off, pap) != 0)
		mdb_iob_discard(mdb.m_out);
	else
		mdb_iob_puts(mdb.m_out, pap->pa_delim);
}

/*
 * The print_close_sou() function is called for each structure or union
 * which has been completed.  For structures, we detect and print any holes
 * before printing the closing brace.
 */
static void
print_close_sou(printarg_t *pap, int newdepth)
{
	int d = newdepth + pap->pa_nest;

	if ((pap->pa_flags & PA_SHOWHOLES) && !pap->pa_holes[d].hi_isunion) {
		ulong_t end = pap->pa_holes[d + 1].hi_offset;
		ulong_t expected = pap->pa_holes[d].hi_offset;

		if (end < expected)
			print_hole(pap, newdepth + 1, end, expected);
	}
	/* if the struct is an array element, print a comma after the } */
	mdb_printf("%*s}%s\n", d * pap->pa_tab, "",
	    (newdepth == 0 && pap->pa_nest > 0)? "," : "");
}

static printarg_f *const printfuncs[] = {
	print_int,	/* CTF_K_INTEGER */
	print_float,	/* CTF_K_FLOAT */
	print_ptr,	/* CTF_K_POINTER */
	print_array,	/* CTF_K_ARRAY */
	print_ptr,	/* CTF_K_FUNCTION */
	print_sou,	/* CTF_K_STRUCT */
	print_sou,	/* CTF_K_UNION */
	print_enum,	/* CTF_K_ENUM */
	print_tag	/* CTF_K_FORWARD */
};

/*
 * The elt_print function is used as the mdb_ctf_type_visit callback.  For
 * each element, we print an appropriate name prefix and then call the
 * print subroutine for this type class in the array above.
 */
static int
elt_print(const char *name, mdb_ctf_id_t id, mdb_ctf_id_t base,
    ulong_t off, int depth, void *data)
{
	char type[MDB_SYM_NAMLEN + sizeof (" <<12345678...>>")];
	int kind, rc, d;
	printarg_t *pap = data;

	for (d = pap->pa_depth - 1; d >= depth; d--) {
		if (d < pap->pa_nooutdepth)
			print_close_sou(pap, d);
	}

	/*
	 * Reset pa_nooutdepth if we've come back out of the structure we
	 * didn't want to print.
	 */
	if (depth <= pap->pa_nooutdepth)
		pap->pa_nooutdepth = (uint_t)-1;

	if (depth > pap->pa_maxdepth || depth > pap->pa_nooutdepth)
		return (0);

	if (!mdb_ctf_type_valid(base) ||
	    (kind = mdb_ctf_type_kind(base)) == -1)
		return (-1); /* errno is set for us */

	if (mdb_ctf_type_name(id, type, MDB_SYM_NAMLEN) == NULL)
		(void) strcpy(type, "(?)");

	if (pap->pa_flags & PA_SHOWBASETYPE) {
		/*
		 * If basetype is different and informative, concatenate
		 * <<basetype>> (or <<baset...>> if it doesn't fit)
		 *
		 * We just use the end of the buffer to store the type name, and
		 * only connect it up if that's necessary.
		 */

		char *type_end = type + strlen(type);
		char *basetype;
		size_t sz;

		(void) strlcat(type, " <<", sizeof (type));

		basetype = type + strlen(type);
		sz = sizeof (type) - (basetype - type);

		*type_end = '\0'; /* restore the end of type for strcmp() */

		if (mdb_ctf_type_name(base, basetype, sz) != NULL &&
		    strcmp(basetype, type) != 0 &&
		    strcmp(basetype, "struct ") != 0 &&
		    strcmp(basetype, "enum ") != 0 &&
		    strcmp(basetype, "union ") != 0) {
			type_end[0] = ' ';	/* reconnect */
			if (strlcat(type, ">>", sizeof (type)) >= sizeof (type))
				(void) strlcpy(
				    type + sizeof (type) - 6, "...>>", 6);
		}
	}

	if (pap->pa_flags & PA_SHOWHOLES) {
		ctf_encoding_t e;
		ssize_t nsize;
		ulong_t newoff;
		holeinfo_t *hole;
		int extra = IS_COMPOSITE(kind)? 1 : 0;

		/*
		 * grow the hole array, if necessary
		 */
		if (pap->pa_nest + depth + extra >= pap->pa_nholes) {
			int new = MAX(MAX(8, pap->pa_nholes * 2),
			    pap->pa_nest + depth + extra + 1);

			holeinfo_t *nhi = mdb_zalloc(
			    sizeof (*nhi) * new, UM_NOSLEEP | UM_GC);

			bcopy(pap->pa_holes, nhi,
			    pap->pa_nholes * sizeof (*nhi));

			pap->pa_holes = nhi;
			pap->pa_nholes = new;
		}

		hole = &pap->pa_holes[depth + pap->pa_nest];

		if (depth != 0 && off > hole->hi_offset)
			print_hole(pap, depth, hole->hi_offset, off);

		/* compute the next expected offset */
		if (kind == CTF_K_INTEGER &&
		    mdb_ctf_type_encoding(base, &e) == 0)
			newoff = off + e.cte_bits;
		else if ((nsize = mdb_ctf_type_size(base)) >= 0)
			newoff = off + nsize * NBBY;
		else {
			/* something bad happened, disable hole checking */
			newoff = -1UL;		/* ULONG_MAX */
		}

		hole->hi_offset = newoff;

		if (IS_COMPOSITE(kind)) {
			hole->hi_isunion = (kind == CTF_K_UNION);
			hole++;
			hole->hi_offset = off;
		}
	}

	if (pap->pa_flags & (PA_SHOWTYPE | PA_SHOWNAME | PA_SHOWADDR))
		mdb_printf("%*s", (depth + pap->pa_nest) * pap->pa_tab, "");

	if (pap->pa_flags & PA_SHOWADDR) {
		if (off % NBBY == 0)
			mdb_printf("%llx ", pap->pa_addr + off / NBBY);
		else
			mdb_printf("%llx.%lx ",
			    pap->pa_addr + off / NBBY, off % NBBY);
	}

	if ((pap->pa_flags & PA_SHOWTYPE)) {
		mdb_printf("%s", type);
		/*
		 * We want to avoid printing a trailing space when
		 * dealing with pointers in a structure, so we end
		 * up with:
		 *
		 *	label_t *t_onfault = 0
		 *
		 * If depth is zero, always print the trailing space unless
		 * we also have a prefix.
		 */
		if (type[strlen(type) - 1] != '*' ||
		    (depth == 0 && (!(pap->pa_flags & PA_SHOWNAME) ||
		    pap->pa_prefix == NULL)))
			mdb_printf(" ");
	}

	if (pap->pa_flags & PA_SHOWNAME) {
		if (pap->pa_prefix != NULL && depth <= 1)
			mdb_printf("%s%s", pap->pa_prefix,
			    (depth == 0) ? "" : pap->pa_suffix);
		mdb_printf("%s", name);
	}

	if ((pap->pa_flags & PA_SHOWTYPE) && kind == CTF_K_INTEGER) {
		ctf_encoding_t e;

		if (mdb_ctf_type_encoding(base, &e) == 0) {
			ulong_t bits = e.cte_bits;
			ulong_t size = bits / NBBY;

			if (bits % NBBY != 0 ||
			    off % NBBY != 0 ||
			    size > 8 ||
			    size != mdb_ctf_type_size(base))
				mdb_printf(" :%d", bits);
		}
	}

	if (depth != 0 ||
	    ((pap->pa_flags & PA_SHOWNAME) && pap->pa_prefix != NULL))
		mdb_printf("%s ", pap->pa_flags & PA_SHOWVAL ? " =" : "");

	if (depth == 0 && pap->pa_prefix != NULL)
		name = pap->pa_prefix;

	pap->pa_depth = depth;
	if (kind <= CTF_K_UNKNOWN || kind >= CTF_K_TYPEDEF) {
		mdb_warn("unknown ctf for %s type %s kind %d\n",
		    name, type, kind);
		return (-1);
	}
	rc = printfuncs[kind - 1](type, name, id, base, off, pap);

	if (rc != 0)
		mdb_iob_discard(mdb.m_out);
	else
		mdb_iob_puts(mdb.m_out, pap->pa_delim);

	return (rc);
}

/*
 * Special semantics for pipelines.
 */
static int
pipe_print(mdb_ctf_id_t id, ulong_t off, void *data)
{
	printarg_t *pap = data;
	ssize_t size;
	static const char *const fsp[] = { "%#r", "%#r", "%#r", "%#llr" };
	uintptr_t value;
	uintptr_t addr = pap->pa_addr + off / NBBY;
	mdb_ctf_id_t base;
	int enum_value;
	ctf_encoding_t e;

	union {
		uint64_t i8;
		uint32_t i4;
		uint16_t i2;
		uint8_t i1;
	} u;

	if (mdb_ctf_type_resolve(id, &base) == -1) {
		mdb_warn("could not resolve type");
		return (-1);
	}

	/*
	 * If the user gives -a, then always print out the address of the
	 * member.
	 */
	if ((pap->pa_flags & PA_SHOWADDR)) {
		mdb_printf("%#lr\n", addr);
		return (0);
	}

again:
	switch (mdb_ctf_type_kind(base)) {
	case CTF_K_POINTER:
		if (mdb_tgt_aread(pap->pa_tgt, pap->pa_as,
		    &value, sizeof (value), addr) != sizeof (value)) {
			mdb_warn("failed to read pointer at %p", addr);
			return (-1);
		}
		mdb_printf("%#lr\n", value);
		break;

	case CTF_K_ENUM:
		if (mdb_tgt_aread(pap->pa_tgt, pap->pa_as, &enum_value,
		    sizeof (enum_value), addr) != sizeof (enum_value)) {
			mdb_warn("failed to read enum at %llx", addr);
			return (-1);
		}
		mdb_printf("%#r\n", enum_value);
		break;

	case CTF_K_INTEGER:
		if (mdb_ctf_type_encoding(base, &e) != 0) {
			mdb_warn("could not get type encoding\n");
			return (-1);
		}

		/*
		 * For immediate values, we just print out the value.
		 */
		size = e.cte_bits / NBBY;
		if (size > 8 || (e.cte_bits % NBBY) != 0 ||
		    (size & (size - 1)) != 0) {
			return (print_bitfield(off, pap, &e));
		}

		if (mdb_tgt_aread(pap->pa_tgt, pap->pa_as, &u.i8, size,
		    addr) != size) {
			mdb_warn("failed to read %lu bytes at %p",
			    (ulong_t)size, pap->pa_addr);
			return (-1);
		}

		switch (size) {
		case sizeof (uint8_t):
			mdb_printf(fsp[0], u.i1);
			break;
		case sizeof (uint16_t):
			mdb_printf(fsp[1], u.i2);
			break;
		case sizeof (uint32_t):
			mdb_printf(fsp[2], u.i4);
			break;
		case sizeof (uint64_t):
			mdb_printf(fsp[3], u.i8);
			break;
		}
		mdb_printf("\n");
		break;

	case CTF_K_FUNCTION:
	case CTF_K_FLOAT:
	case CTF_K_ARRAY:
	case CTF_K_UNKNOWN:
	case CTF_K_STRUCT:
	case CTF_K_UNION:
	case CTF_K_FORWARD:
		/*
		 * For these types, always print the address of the member
		 */
		mdb_printf("%#lr\n", addr);
		break;

	default:
		mdb_warn("unknown type %d", mdb_ctf_type_kind(base));
		break;
	}

	return (0);
}

static int
parse_delimiter(char **strp)
{
	switch (**strp) {
	case '\0':
		return (MEMBER_DELIM_DONE);

	case '.':
		*strp = *strp + 1;
		return (MEMBER_DELIM_DOT);

	case '[':
		*strp = *strp + 1;
		return (MEMBER_DELIM_LBR);

	case '-':
		*strp = *strp + 1;
		if (**strp == '>') {
			*strp = *strp + 1;
			return (MEMBER_DELIM_PTR);
		}
		*strp = *strp - 1;
		/*FALLTHROUGH*/
	default:
		return (MEMBER_DELIM_ERR);
	}
}

static int
deref(printarg_t *pap, size_t size)
{
	uint32_t a32;
	mdb_tgt_as_t as = pap->pa_as;
	mdb_tgt_addr_t *ap = &pap->pa_addr;

	if (size == sizeof (mdb_tgt_addr_t)) {
		if (mdb_tgt_aread(mdb.m_target, as, ap, size, *ap) == -1) {
			mdb_warn("could not dereference pointer %llx\n", *ap);
			return (-1);
		}
	} else {
		if (mdb_tgt_aread(mdb.m_target, as, &a32, size, *ap) == -1) {
			mdb_warn("could not dereference pointer %x\n", *ap);
			return (-1);
		}

		*ap = (mdb_tgt_addr_t)a32;
	}

	/*
	 * We've dereferenced at least once, we must be on the real
	 * target. If we were in the immediate target, reset to the real
	 * target; it's reset as needed when we return to the print
	 * routines.
	 */
	if (pap->pa_tgt == pap->pa_immtgt)
		pap->pa_tgt = pap->pa_realtgt;

	return (0);
}

static int
parse_member(printarg_t *pap, const char *str, mdb_ctf_id_t id,
    mdb_ctf_id_t *idp, ulong_t *offp, int *last_deref)
{
	int delim;
	char member[64];
	char buf[128];
	uint_t index;
	char *start = (char *)str;
	char *end;
	ulong_t off = 0;
	mdb_ctf_arinfo_t ar;
	mdb_ctf_id_t rid;
	int kind;
	ssize_t size;
	int non_array = FALSE;

	/*
	 * id always has the unresolved type for printing error messages
	 * that include the type; rid always has the resolved type for
	 * use in mdb_ctf_* calls.  It is possible for this command to fail,
	 * however, if the resolved type is in the parent and it is currently
	 * unavailable.  Note that we also can't print out the name of the
	 * type, since that would also rely on looking up the resolved name.
	 */
	if (mdb_ctf_type_resolve(id, &rid) != 0) {
		mdb_warn("failed to resolve type");
		return (-1);
	}

	delim = parse_delimiter(&start);
	/*
	 * If the user fails to specify an initial delimiter, guess -> for
	 * pointer types and . for non-pointer types.
	 */
	if (delim == MEMBER_DELIM_ERR)
		delim = (mdb_ctf_type_kind(rid) == CTF_K_POINTER) ?
		    MEMBER_DELIM_PTR : MEMBER_DELIM_DOT;

	*last_deref = FALSE;

	while (delim != MEMBER_DELIM_DONE) {
		switch (delim) {
		case MEMBER_DELIM_PTR:
			kind = mdb_ctf_type_kind(rid);
			if (kind != CTF_K_POINTER) {
				mdb_warn("%s is not a pointer type\n",
				    mdb_ctf_type_name(id, buf, sizeof (buf)));
				return (-1);
			}

			size = mdb_ctf_type_size(id);
			if (deref(pap, size) != 0)
				return (-1);

			(void) mdb_ctf_type_reference(rid, &id);
			(void) mdb_ctf_type_resolve(id, &rid);

			off = 0;
			break;

		case MEMBER_DELIM_DOT:
			kind = mdb_ctf_type_kind(rid);
			if (kind != CTF_K_STRUCT && kind != CTF_K_UNION) {
				mdb_warn("%s is not a struct or union type\n",
				    mdb_ctf_type_name(id, buf, sizeof (buf)));
				return (-1);
			}
			break;

		case MEMBER_DELIM_LBR:
			end = strchr(start, ']');
			if (end == NULL) {
				mdb_warn("no trailing ']'\n");
				return (-1);
			}

			(void) mdb_snprintf(member, end - start + 1, "%s",
			    start);

			index = mdb_strtoull(member);

			switch (mdb_ctf_type_kind(rid)) {
			case CTF_K_POINTER:
				size = mdb_ctf_type_size(rid);

				if (deref(pap, size) != 0)
					return (-1);

				(void) mdb_ctf_type_reference(rid, &id);
				(void) mdb_ctf_type_resolve(id, &rid);

				size = mdb_ctf_type_size(id);
				if (size <= 0) {
					mdb_warn("cannot dereference void "
					    "type\n");
					return (-1);
				}

				pap->pa_addr += index * size;
				off = 0;

				if (index == 0 && non_array)
					*last_deref = TRUE;
				break;

			case CTF_K_ARRAY:
				(void) mdb_ctf_array_info(rid, &ar);

				if (index >= ar.mta_nelems) {
					mdb_warn("index %r is outside of "
					    "array bounds [0 .. %r]\n",
					    index, ar.mta_nelems - 1);
				}

				id = ar.mta_contents;
				(void) mdb_ctf_type_resolve(id, &rid);

				size = mdb_ctf_type_size(id);
				if (size <= 0) {
					mdb_warn("cannot dereference void "
					    "type\n");
					return (-1);
				}

				pap->pa_addr += index * size;
				off = 0;
				break;

			default:
				mdb_warn("cannot index into non-array, "
				    "non-pointer type\n");
				return (-1);
			}

			start = end + 1;
			delim = parse_delimiter(&start);
			continue;

		case MEMBER_DELIM_ERR:
		default:
			mdb_warn("'%c' is not a valid delimiter\n", *start);
			return (-1);
		}

		*last_deref = FALSE;
		non_array = TRUE;

		/*
		 * Find the end of the member name; assume that a member
		 * name is at least one character long.
		 */
		for (end = start + 1; isalnum(*end) || *end == '_'; end++)
			continue;

		(void) mdb_snprintf(member, end - start + 1, "%s", start);

		if (mdb_ctf_member_info(rid, member, &off, &id) != 0) {
			mdb_warn("failed to find member %s of %s", member,
			    mdb_ctf_type_name(id, buf, sizeof (buf)));
			return (-1);
		}
		(void) mdb_ctf_type_resolve(id, &rid);

		pap->pa_addr += off / NBBY;

		start = end;
		delim = parse_delimiter(&start);
	}

	*idp = id;
	*offp = off;

	return (0);
}

static int
cmd_print_tab_common(mdb_tab_cookie_t *mcp, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	char tn[MDB_SYM_NAMLEN];
	char member[64];
	int delim, kind;
	int ret = 0;
	mdb_ctf_id_t id, rid;
	mdb_ctf_arinfo_t ar;
	char *start, *end;
	ulong_t dul;

	if (argc == 0 && !(flags & DCMD_TAB_SPACE))
		return (0);

	if (argc == 0 && (flags & DCMD_TAB_SPACE))
		return (mdb_tab_complete_type(mcp, NULL, MDB_TABC_NOPOINT |
		    MDB_TABC_NOARRAY));

	if ((ret = mdb_tab_typename(&argc, &argv, tn, sizeof (tn))) < 0)
		return (ret);

	if (argc == 1 && (!(flags & DCMD_TAB_SPACE) || ret == 1))
		return (mdb_tab_complete_type(mcp, tn, MDB_TABC_NOPOINT |
		    MDB_TABC_NOARRAY));

	if (argc == 1 && (flags & DCMD_TAB_SPACE))
		return (mdb_tab_complete_member(mcp, tn, NULL));

	/*
	 * This is the reason that tab completion was created. We're going to go
	 * along and walk the delimiters until we find something a member that
	 * we don't recognize, at which point we'll try and tab complete it.
	 * Note that ::print takes multiple args, so this is going to operate on
	 * whatever the last arg that we have is.
	 */
	if (mdb_ctf_lookup_by_name(tn, &id) != 0)
		return (1);

	(void) mdb_ctf_type_resolve(id, &rid);
	start = (char *)argv[argc-1].a_un.a_str;
	delim = parse_delimiter(&start);

	/*
	 * If we hit the case where we actually have no delimiters, than we need
	 * to make sure that we properly set up the fields the loops would.
	 */
	if (delim == MEMBER_DELIM_DONE)
		(void) mdb_snprintf(member, sizeof (member), "%s", start);

	while (delim != MEMBER_DELIM_DONE) {
		switch (delim) {
		case MEMBER_DELIM_PTR:
			kind = mdb_ctf_type_kind(rid);
			if (kind != CTF_K_POINTER)
				return (1);

			(void) mdb_ctf_type_reference(rid, &id);
			(void) mdb_ctf_type_resolve(id, &rid);
			break;
		case MEMBER_DELIM_DOT:
			kind = mdb_ctf_type_kind(rid);
			if (kind != CTF_K_STRUCT && kind != CTF_K_UNION)
				return (1);
			break;
		case MEMBER_DELIM_LBR:
			end = strchr(start, ']');
			/*
			 * We're not going to try and tab complete the indexes
			 * here. So for now, punt on it. Also, we're not going
			 * to try and validate you're within the bounds, just
			 * that you get the type you asked for.
			 */
			if (end == NULL)
				return (1);

			switch (mdb_ctf_type_kind(rid)) {
			case CTF_K_POINTER:
				(void) mdb_ctf_type_reference(rid, &id);
				(void) mdb_ctf_type_resolve(id, &rid);
				break;
			case CTF_K_ARRAY:
				(void) mdb_ctf_array_info(rid, &ar);
				id = ar.mta_contents;
				(void) mdb_ctf_type_resolve(id, &rid);
				break;
			default:
				return (1);
			}

			start = end + 1;
			delim = parse_delimiter(&start);
			break;
		case MEMBER_DELIM_ERR:
		default:
			break;
		}

		for (end = start + 1; isalnum(*end) || *end == '_'; end++)
			continue;

		(void) mdb_snprintf(member, end - start + 1, start);

		/*
		 * We are going to try to resolve this name as a member. There
		 * are a few two different questions that we need to answer. The
		 * first is do we recognize this member. The second is are we at
		 * the end of the string. If we encounter a member that we don't
		 * recognize before the end, then we have to error out and can't
		 * complete it. But if there are no more delimiters then we can
		 * try and complete it.
		 */
		ret = mdb_ctf_member_info(rid, member, &dul, &id);
		start = end;
		delim = parse_delimiter(&start);
		if (ret != 0 && errno == EMDB_CTFNOMEMB) {
			if (delim != MEMBER_DELIM_DONE)
				return (1);
			continue;
		} else if (ret != 0)
			return (1);

		if (delim == MEMBER_DELIM_DONE)
			return (mdb_tab_complete_member_by_id(mcp, rid,
			    member));

		(void) mdb_ctf_type_resolve(id, &rid);
	}

	/*
	 * If we've reached here, then we need to try and tab complete the last
	 * field, which is currently member, based on the ctf type id that we
	 * already have in rid.
	 */
	return (mdb_tab_complete_member_by_id(mcp, rid, member));
}

int
cmd_print_tab(mdb_tab_cookie_t *mcp, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	int i, dummy;

	/*
	 * This getopts is only here to make the tab completion work better when
	 * including options in the ::print arguments. None of the values should
	 * be used. This should only be updated with additional arguments, if
	 * they are added to cmd_print.
	 */
	i = mdb_getopts(argc, argv,
	    'a', MDB_OPT_SETBITS, PA_SHOWADDR, &dummy,
	    'C', MDB_OPT_SETBITS, TRUE, &dummy,
	    'c', MDB_OPT_UINTPTR, &dummy,
	    'd', MDB_OPT_SETBITS, PA_INTDEC, &dummy,
	    'h', MDB_OPT_SETBITS, PA_SHOWHOLES, &dummy,
	    'i', MDB_OPT_SETBITS, TRUE, &dummy,
	    'L', MDB_OPT_SETBITS, TRUE, &dummy,
	    'l', MDB_OPT_UINTPTR, &dummy,
	    'n', MDB_OPT_SETBITS, PA_NOSYMBOLIC, &dummy,
	    'p', MDB_OPT_SETBITS, TRUE, &dummy,
	    's', MDB_OPT_UINTPTR, &dummy,
	    'T', MDB_OPT_SETBITS, PA_SHOWTYPE | PA_SHOWBASETYPE, &dummy,
	    't', MDB_OPT_SETBITS, PA_SHOWTYPE, &dummy,
	    'x', MDB_OPT_SETBITS, PA_INTHEX, &dummy,
	    NULL);

	argc -= i;
	argv += i;

	return (cmd_print_tab_common(mcp, flags, argc, argv));
}

/*
 * Recursively descend a print a given data structure.  We create a struct of
 * the relevant print arguments and then call mdb_ctf_type_visit() to do the
 * traversal, using elt_print() as the callback for each element.
 */
/*ARGSUSED*/
int
cmd_print(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uintptr_t opt_c = MDB_ARR_NOLIMIT, opt_l = MDB_ARR_NOLIMIT;
	uint_t opt_C = FALSE, opt_L = FALSE, opt_p = FALSE, opt_i = FALSE;
	uintptr_t opt_s = (uintptr_t)-1ul;
	int uflags = (flags & DCMD_ADDRSPEC) ? PA_SHOWVAL : 0;
	mdb_ctf_id_t id;
	int err = DCMD_OK;

	mdb_tgt_t *t = mdb.m_target;
	printarg_t pa;
	int d, i;

	char s_name[MDB_SYM_NAMLEN];
	mdb_syminfo_t s_info;
	GElf_Sym sym;

	/*
	 * If a new option is added, make sure the getopts above in
	 * cmd_print_tab is also updated.
	 */
	i = mdb_getopts(argc, argv,
	    'a', MDB_OPT_SETBITS, PA_SHOWADDR, &uflags,
	    'C', MDB_OPT_SETBITS, TRUE, &opt_C,
	    'c', MDB_OPT_UINTPTR, &opt_c,
	    'd', MDB_OPT_SETBITS, PA_INTDEC, &uflags,
	    'h', MDB_OPT_SETBITS, PA_SHOWHOLES, &uflags,
	    'i', MDB_OPT_SETBITS, TRUE, &opt_i,
	    'L', MDB_OPT_SETBITS, TRUE, &opt_L,
	    'l', MDB_OPT_UINTPTR, &opt_l,
	    'n', MDB_OPT_SETBITS, PA_NOSYMBOLIC, &uflags,
	    'p', MDB_OPT_SETBITS, TRUE, &opt_p,
	    's', MDB_OPT_UINTPTR, &opt_s,
	    'T', MDB_OPT_SETBITS, PA_SHOWTYPE | PA_SHOWBASETYPE, &uflags,
	    't', MDB_OPT_SETBITS, PA_SHOWTYPE, &uflags,
	    'x', MDB_OPT_SETBITS, PA_INTHEX, &uflags,
	    NULL);

	if (uflags & PA_INTHEX)
		uflags &= ~PA_INTDEC;	/* -x and -d are mutually exclusive */

	uflags |= PA_SHOWNAME;

	if (opt_p && opt_i) {
		mdb_warn("-p and -i options are incompatible\n");
		return (DCMD_ERR);
	}

	argc -= i;
	argv += i;

	if (argc != 0 && argv->a_type == MDB_TYPE_STRING) {
		const char *t_name = s_name;
		int ret;

		if (strchr("+-", argv->a_un.a_str[0]) != NULL)
			return (DCMD_USAGE);

		if ((ret = args_to_typename(&argc, &argv, s_name,
		    sizeof (s_name))) != 0)
			return (ret);

		if (mdb_ctf_lookup_by_name(t_name, &id) != 0) {
			if (!(flags & DCMD_ADDRSPEC) || opt_i ||
			    addr_to_sym(t, addr, s_name, sizeof (s_name),
			    &sym, &s_info) == NULL ||
			    mdb_ctf_lookup_by_symbol(&sym, &s_info, &id) != 0) {

				mdb_warn("failed to look up type %s", t_name);
				return (DCMD_ABORT);
			}
		} else {
			argc--;
			argv++;
		}

	} else if (!(flags & DCMD_ADDRSPEC) || opt_i) {
		return (DCMD_USAGE);

	} else if (addr_to_sym(t, addr, s_name, sizeof (s_name),
	    &sym, &s_info) == NULL) {
		mdb_warn("no symbol information for %a", addr);
		return (DCMD_ERR);

	} else if (mdb_ctf_lookup_by_symbol(&sym, &s_info, &id) != 0) {
		mdb_warn("no type data available for %a [%u]", addr,
		    s_info.sym_id);
		return (DCMD_ERR);
	}

	pa.pa_tgt = mdb.m_target;
	pa.pa_realtgt = pa.pa_tgt;
	pa.pa_immtgt = NULL;
	pa.pa_as = opt_p ? MDB_TGT_AS_PHYS : MDB_TGT_AS_VIRT;
	pa.pa_armemlim = mdb.m_armemlim;
	pa.pa_arstrlim = mdb.m_arstrlim;
	pa.pa_delim = "\n";
	pa.pa_flags = uflags;
	pa.pa_nest = 0;
	pa.pa_tab = 4;
	pa.pa_prefix = NULL;
	pa.pa_suffix = NULL;
	pa.pa_holes = NULL;
	pa.pa_nholes = 0;
	pa.pa_depth = 0;
	pa.pa_maxdepth = opt_s;
	pa.pa_nooutdepth = (uint_t)-1;

	if ((flags & DCMD_ADDRSPEC) && !opt_i)
		pa.pa_addr = opt_p ? mdb_get_dot() : addr;
	else
		pa.pa_addr = NULL;

	if (opt_i) {
		const char *vargv[2];
		uintmax_t dot = mdb_get_dot();
		size_t outsize = mdb_ctf_type_size(id);
		vargv[0] = (const char *)&dot;
		vargv[1] = (const char *)&outsize;
		pa.pa_immtgt = mdb_tgt_create(mdb_value_tgt_create,
		    0, 2, vargv);
		pa.pa_tgt = pa.pa_immtgt;
	}

	if (opt_c != MDB_ARR_NOLIMIT)
		pa.pa_arstrlim = opt_c;
	if (opt_C)
		pa.pa_arstrlim = MDB_ARR_NOLIMIT;
	if (opt_l != MDB_ARR_NOLIMIT)
		pa.pa_armemlim = opt_l;
	if (opt_L)
		pa.pa_armemlim = MDB_ARR_NOLIMIT;

	if (argc > 0) {
		for (i = 0; i < argc; i++) {
			mdb_ctf_id_t mid;
			int last_deref;
			ulong_t off;
			int kind;
			char buf[MDB_SYM_NAMLEN];

			mdb_tgt_t *oldtgt = pa.pa_tgt;
			mdb_tgt_as_t oldas = pa.pa_as;
			mdb_tgt_addr_t oldaddr = pa.pa_addr;

			if (argv->a_type == MDB_TYPE_STRING) {
				const char *member = argv[i].a_un.a_str;
				mdb_ctf_id_t rid;

				if (parse_member(&pa, member, id, &mid,
				    &off, &last_deref) != 0) {
					err = DCMD_ABORT;
					goto out;
				}

				/*
				 * If the member string ends with a "[0]"
				 * (last_deref * is true) and the type is a
				 * structure or union, * print "->" rather
				 * than "[0]." in elt_print.
				 */
				(void) mdb_ctf_type_resolve(mid, &rid);
				kind = mdb_ctf_type_kind(rid);
				if (last_deref && IS_SOU(kind)) {
					char *end;
					(void) mdb_snprintf(buf, sizeof (buf),
					    "%s", member);
					end = strrchr(buf, '[');
					*end = '\0';
					pa.pa_suffix = "->";
					member = &buf[0];
				} else if (IS_SOU(kind)) {
					pa.pa_suffix = ".";
				} else {
					pa.pa_suffix = "";
				}

				pa.pa_prefix = member;
			} else {
				ulong_t moff;

				moff = (ulong_t)argv[i].a_un.a_val;

				if (mdb_ctf_offset_to_name(id, moff * NBBY,
				    buf, sizeof (buf), 0, &mid, &off) == -1) {
					mdb_warn("invalid offset %lx\n", moff);
					err = DCMD_ABORT;
					goto out;
				}

				pa.pa_prefix = buf;
				pa.pa_addr += moff - off / NBBY;
				pa.pa_suffix = strlen(buf) == 0 ? "" : ".";
			}

			off %= NBBY;
			if (flags & DCMD_PIPE_OUT) {
				if (pipe_print(mid, off, &pa) != 0) {
					mdb_warn("failed to print type");
					err = DCMD_ERR;
					goto out;
				}
			} else if (off != 0) {
				mdb_ctf_id_t base;
				(void) mdb_ctf_type_resolve(mid, &base);

				if (elt_print("", mid, base, off, 0,
				    &pa) != 0) {
					mdb_warn("failed to print type");
					err = DCMD_ERR;
					goto out;
				}
			} else {
				if (mdb_ctf_type_visit(mid, elt_print,
				    &pa) == -1) {
					mdb_warn("failed to print type");
					err = DCMD_ERR;
					goto out;
				}

				for (d = pa.pa_depth - 1; d >= 0; d--)
					print_close_sou(&pa, d);
			}

			pa.pa_depth = 0;
			pa.pa_tgt = oldtgt;
			pa.pa_as = oldas;
			pa.pa_addr = oldaddr;
			pa.pa_delim = "\n";
		}

	} else if (flags & DCMD_PIPE_OUT) {
		if (pipe_print(id, 0, &pa) != 0) {
			mdb_warn("failed to print type");
			err = DCMD_ERR;
			goto out;
		}
	} else {
		if (mdb_ctf_type_visit(id, elt_print, &pa) == -1) {
			mdb_warn("failed to print type");
			err = DCMD_ERR;
			goto out;
		}

		for (d = pa.pa_depth - 1; d >= 0; d--)
			print_close_sou(&pa, d);
	}

	mdb_set_dot(addr + mdb_ctf_type_size(id));
	err = DCMD_OK;
out:
	if (pa.pa_immtgt)
		mdb_tgt_destroy(pa.pa_immtgt);
	return (err);
}

void
print_help(void)
{
	mdb_printf(
	    "-a         show address of object\n"
	    "-C         unlimit the length of character arrays\n"
	    "-c limit   limit the length of character arrays\n"
	    "-d         output values in decimal\n"
	    "-h         print holes in structures\n"
	    "-i         interpret address as data of the given type\n"
	    "-L         unlimit the length of standard arrays\n"
	    "-l limit   limit the length of standard arrays\n"
	    "-n         don't print pointers as symbol offsets\n"
	    "-p         interpret address as a physical memory address\n"
	    "-s depth   limit the recursion depth\n"
	    "-T         show type and <<base type>> of object\n"
	    "-t         show type of object\n"
	    "-x         output values in hexadecimal\n"
	    "\n"
	    "type may be omitted if the C type of addr can be inferred.\n"
	    "\n"
	    "Members may be specified with standard C syntax using the\n"
	    "array indexing operator \"[index]\", structure member\n"
	    "operator \".\", or structure pointer operator \"->\".\n"
	    "\n"
	    "Offsets must use the $[ expression ] syntax\n");
}

static int
printf_signed(mdb_ctf_id_t id, uintptr_t addr, ulong_t off, char *fmt,
    boolean_t sign)
{
	ssize_t size;
	mdb_ctf_id_t base;
	ctf_encoding_t e;

	union {
		uint64_t ui8;
		uint32_t ui4;
		uint16_t ui2;
		uint8_t ui1;
		int64_t i8;
		int32_t i4;
		int16_t i2;
		int8_t i1;
	} u;

	if (mdb_ctf_type_resolve(id, &base) == -1) {
		mdb_warn("could not resolve type");
		return (DCMD_ABORT);
	}

	if (mdb_ctf_type_kind(base) != CTF_K_INTEGER) {
		mdb_warn("expected integer type\n");
		return (DCMD_ABORT);
	}

	if (mdb_ctf_type_encoding(base, &e) != 0) {
		mdb_warn("could not get type encoding");
		return (DCMD_ABORT);
	}

	if (sign)
		sign = e.cte_format & CTF_INT_SIGNED;

	size = e.cte_bits / NBBY;

	/*
	 * Check to see if our life has been complicated by the presence of
	 * a bitfield.  If it has, we will print it using logic that is only
	 * slightly different than that found in print_bitfield(), above.  (In
	 * particular, see the comments there for an explanation of the
	 * endianness differences in this code.)
	 */
	if (size > 8 || (e.cte_bits % NBBY) != 0 ||
	    (size & (size - 1)) != 0) {
		uint64_t mask = (1ULL << e.cte_bits) - 1;
		uint64_t value = 0;
		uint8_t *buf = (uint8_t *)&value;
		uint8_t shift;

		/*
		 * Round our size up one byte.
		 */
		size = (e.cte_bits + (NBBY - 1)) / NBBY;

		if (e.cte_bits > sizeof (value) * NBBY - 1) {
			mdb_printf("invalid bitfield size %u", e.cte_bits);
			return (DCMD_ABORT);
		}

#ifdef _BIG_ENDIAN
		buf += sizeof (value) - size;
		off += e.cte_bits;
#endif

		if (mdb_vread(buf, size, addr) == -1) {
			mdb_warn("failed to read %lu bytes at %p", size, addr);
			return (DCMD_ERR);
		}

		shift = off % NBBY;
#ifdef _BIG_ENDIAN
		shift = NBBY - shift;
#endif

		/*
		 * If we have a bit offset within the byte, shift it down.
		 */
		if (off % NBBY != 0)
			value >>= shift;
		value &= mask;

		if (sign) {
			int sshift = sizeof (value) * NBBY - e.cte_bits;
			value = ((int64_t)value << sshift) >> sshift;
		}

		mdb_printf(fmt, value);
		return (0);
	}

	if (mdb_vread(&u.i8, size, addr) == -1) {
		mdb_warn("failed to read %lu bytes at %p", (ulong_t)size, addr);
		return (DCMD_ERR);
	}

	switch (size) {
	case sizeof (uint8_t):
		mdb_printf(fmt, (uint64_t)(sign ? u.i1 : u.ui1));
		break;
	case sizeof (uint16_t):
		mdb_printf(fmt, (uint64_t)(sign ? u.i2 : u.ui2));
		break;
	case sizeof (uint32_t):
		mdb_printf(fmt, (uint64_t)(sign ? u.i4 : u.ui4));
		break;
	case sizeof (uint64_t):
		mdb_printf(fmt, (uint64_t)(sign ? u.i8 : u.ui8));
		break;
	}

	return (0);
}

static int
printf_int(mdb_ctf_id_t id, uintptr_t addr, ulong_t off, char *fmt)
{
	return (printf_signed(id, addr, off, fmt, B_TRUE));
}

static int
printf_uint(mdb_ctf_id_t id, uintptr_t addr, ulong_t off, char *fmt)
{
	return (printf_signed(id, addr, off, fmt, B_FALSE));
}

/*ARGSUSED*/
static int
printf_uint32(mdb_ctf_id_t id, uintptr_t addr, ulong_t off, char *fmt)
{
	mdb_ctf_id_t base;
	ctf_encoding_t e;
	uint32_t value;

	if (mdb_ctf_type_resolve(id, &base) == -1) {
		mdb_warn("could not resolve type\n");
		return (DCMD_ABORT);
	}

	if (mdb_ctf_type_kind(base) != CTF_K_INTEGER ||
	    mdb_ctf_type_encoding(base, &e) != 0 ||
	    e.cte_bits / NBBY != sizeof (value)) {
		mdb_warn("expected 32-bit integer type\n");
		return (DCMD_ABORT);
	}

	if (mdb_vread(&value, sizeof (value), addr) == -1) {
		mdb_warn("failed to read 32-bit value at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf(fmt, value);

	return (0);
}

/*ARGSUSED*/
static int
printf_ptr(mdb_ctf_id_t id, uintptr_t addr, ulong_t off, char *fmt)
{
	uintptr_t value;
	mdb_ctf_id_t base;

	if (mdb_ctf_type_resolve(id, &base) == -1) {
		mdb_warn("could not resolve type\n");
		return (DCMD_ABORT);
	}

	if (mdb_ctf_type_kind(base) != CTF_K_POINTER) {
		mdb_warn("expected pointer type\n");
		return (DCMD_ABORT);
	}

	if (mdb_vread(&value, sizeof (value), addr) == -1) {
		mdb_warn("failed to read pointer at %llx", addr);
		return (DCMD_ERR);
	}

	mdb_printf(fmt, value);

	return (0);
}

/*ARGSUSED*/
static int
printf_string(mdb_ctf_id_t id, uintptr_t addr, ulong_t off, char *fmt)
{
	mdb_ctf_id_t base;
	mdb_ctf_arinfo_t r;
	char buf[1024];
	ssize_t size;

	if (mdb_ctf_type_resolve(id, &base) == -1) {
		mdb_warn("could not resolve type");
		return (DCMD_ABORT);
	}

	if (mdb_ctf_type_kind(base) == CTF_K_POINTER) {
		uintptr_t value;

		if (mdb_vread(&value, sizeof (value), addr) == -1) {
			mdb_warn("failed to read pointer at %llx", addr);
			return (DCMD_ERR);
		}

		if (mdb_readstr(buf, sizeof (buf) - 1, value) < 0) {
			mdb_warn("failed to read string at %llx", value);
			return (DCMD_ERR);
		}

		mdb_printf(fmt, buf);
		return (0);
	}

	if (mdb_ctf_type_kind(base) != CTF_K_ARRAY) {
		mdb_warn("exepected pointer or array type\n");
		return (DCMD_ABORT);
	}

	if (mdb_ctf_array_info(base, &r) == -1 ||
	    mdb_ctf_type_resolve(r.mta_contents, &base) == -1 ||
	    (size = mdb_ctf_type_size(base)) == -1) {
		mdb_warn("can't determine array type");
		return (DCMD_ABORT);
	}

	if (size != 1) {
		mdb_warn("string format specifier requires "
		    "an array of characters\n");
		return (DCMD_ABORT);
	}

	bzero(buf, sizeof (buf));

	if (mdb_vread(buf, MIN(r.mta_nelems, sizeof (buf) - 1), addr) == -1) {
		mdb_warn("failed to read array at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf(fmt, buf);

	return (0);
}

/*ARGSUSED*/
static int
printf_ipv6(mdb_ctf_id_t id, uintptr_t addr, ulong_t off, char *fmt)
{
	mdb_ctf_id_t base;
	mdb_ctf_id_t ipv6_type, ipv6_base;
	in6_addr_t ipv6;

	if (mdb_ctf_lookup_by_name("in6_addr_t", &ipv6_type) == -1) {
		mdb_warn("could not resolve in6_addr_t type\n");
		return (DCMD_ABORT);
	}

	if (mdb_ctf_type_resolve(id, &base) == -1) {
		mdb_warn("could not resolve type\n");
		return (DCMD_ABORT);
	}

	if (mdb_ctf_type_resolve(ipv6_type, &ipv6_base) == -1) {
		mdb_warn("could not resolve in6_addr_t type\n");
		return (DCMD_ABORT);
	}

	if (mdb_ctf_type_cmp(base, ipv6_base) != 0) {
		mdb_warn("requires argument of type in6_addr_t\n");
		return (DCMD_ABORT);
	}

	if (mdb_vread(&ipv6, sizeof (ipv6), addr) == -1) {
		mdb_warn("couldn't read in6_addr_t at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf(fmt, &ipv6);

	return (0);
}

/*
 * To validate the format string specified to ::printf, we run the format
 * string through a very simple state machine that restricts us to a subset
 * of mdb_printf() functionality.
 */
enum {
	PRINTF_NOFMT = 1,		/* no current format specifier */
	PRINTF_PERC,			/* processed '%' */
	PRINTF_FMT,			/* processing format specifier */
	PRINTF_LEFT,			/* processed '-', expecting width */
	PRINTF_WIDTH,			/* processing width */
	PRINTF_QUES			/* processed '?', expecting format */
};

int
cmd_printf_tab(mdb_tab_cookie_t *mcp, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	int ii;
	char *f;

	/*
	 * If argc doesn't have more than what should be the format string,
	 * ignore it.
	 */
	if (argc <= 1)
		return (0);

	/*
	 * Because we aren't leveraging the lex and yacc engine, we have to
	 * manually walk the arguments to find both the first and last
	 * open/close quote of the format string.
	 */
	f = strchr(argv[0].a_un.a_str, '"');
	if (f == NULL)
		return (0);

	f = strchr(f + 1, '"');
	if (f != NULL) {
		ii = 0;
	} else {
		for (ii = 1; ii < argc; ii++) {
			if (argv[ii].a_type != MDB_TYPE_STRING)
				continue;
			f = strchr(argv[ii].a_un.a_str, '"');
			if (f != NULL)
				break;
		}
		/* Never found */
		if (ii == argc)
			return (0);
	}

	ii++;
	argc -= ii;
	argv += ii;

	return (cmd_print_tab_common(mcp, flags, argc, argv));
}

int
cmd_printf(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	char type[MDB_SYM_NAMLEN];
	int i, nfmts = 0, ret;
	mdb_ctf_id_t id;
	const char *fmt, *member;
	char **fmts, *last, *dest, f;
	int (**funcs)(mdb_ctf_id_t, uintptr_t, ulong_t, char *);
	int state = PRINTF_NOFMT;
	printarg_t pa;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	bzero(&pa, sizeof (pa));
	pa.pa_as = MDB_TGT_AS_VIRT;
	pa.pa_realtgt = pa.pa_tgt = mdb.m_target;

	if (argc == 0 || argv[0].a_type != MDB_TYPE_STRING) {
		mdb_warn("expected a format string\n");
		return (DCMD_USAGE);
	}

	/*
	 * Our first argument is a format string; rip it apart and run it
	 * through our state machine to validate that our input is within the
	 * subset of mdb_printf() format strings that we allow.
	 */
	fmt = argv[0].a_un.a_str;
	/*
	 * 'dest' must be large enough to hold a copy of the format string,
	 * plus a NUL and up to 2 additional characters for each conversion
	 * in the format string.  This gives us a bloat factor of 5/2 ~= 3.
	 *   e.g. "%d" (strlen of 2) --> "%lld\0" (need 5 bytes)
	 */
	dest = mdb_zalloc(strlen(fmt) * 3, UM_SLEEP | UM_GC);
	fmts = mdb_zalloc(strlen(fmt) * sizeof (char *), UM_SLEEP | UM_GC);
	funcs = mdb_zalloc(strlen(fmt) * sizeof (void *), UM_SLEEP | UM_GC);
	last = dest;

	for (i = 0; fmt[i] != '\0'; i++) {
		*dest++ = f = fmt[i];

		switch (state) {
		case PRINTF_NOFMT:
			state = f == '%' ? PRINTF_PERC : PRINTF_NOFMT;
			break;

		case PRINTF_PERC:
			state = f == '-' ? PRINTF_LEFT :
			    f >= '0' && f <= '9' ? PRINTF_WIDTH :
			    f == '?' ? PRINTF_QUES :
			    f == '%' ? PRINTF_NOFMT : PRINTF_FMT;
			break;

		case PRINTF_LEFT:
			state = f >= '0' && f <= '9' ? PRINTF_WIDTH :
			    f == '?' ? PRINTF_QUES : PRINTF_FMT;
			break;

		case PRINTF_WIDTH:
			state = f >= '0' && f <= '9' ? PRINTF_WIDTH :
			    PRINTF_FMT;
			break;

		case PRINTF_QUES:
			state = PRINTF_FMT;
			break;
		}

		if (state != PRINTF_FMT)
			continue;

		dest--;

		/*
		 * Now check that we have one of our valid format characters.
		 */
		switch (f) {
		case 'a':
		case 'A':
		case 'p':
			funcs[nfmts] = printf_ptr;
			break;

		case 'd':
		case 'q':
		case 'R':
			funcs[nfmts] = printf_int;
			*dest++ = 'l';
			*dest++ = 'l';
			break;

		case 'I':
			funcs[nfmts] = printf_uint32;
			break;

		case 'N':
			funcs[nfmts] = printf_ipv6;
			break;

		case 'H':
		case 'o':
		case 'r':
		case 'u':
		case 'x':
		case 'X':
			funcs[nfmts] = printf_uint;
			*dest++ = 'l';
			*dest++ = 'l';
			break;

		case 's':
			funcs[nfmts] = printf_string;
			break;

		case 'Y':
			funcs[nfmts] = sizeof (time_t) == sizeof (int) ?
			    printf_uint32 : printf_uint;
			break;

		default:
			mdb_warn("illegal format string at or near "
			    "'%c' (position %d)\n", f, i + 1);
			return (DCMD_ABORT);
		}

		*dest++ = f;
		*dest++ = '\0';
		fmts[nfmts++] = last;
		last = dest;
		state = PRINTF_NOFMT;
	}

	argc--;
	argv++;

	/*
	 * Now we expect a type name.
	 */
	if ((ret = args_to_typename(&argc, &argv, type, sizeof (type))) != 0)
		return (ret);

	argv++;
	argc--;

	if (mdb_ctf_lookup_by_name(type, &id) != 0) {
		mdb_warn("failed to look up type %s", type);
		return (DCMD_ABORT);
	}

	if (argc == 0) {
		mdb_warn("at least one member must be specified\n");
		return (DCMD_USAGE);
	}

	if (argc != nfmts) {
		mdb_warn("%s format specifiers (found %d, expected %d)\n",
		    argc > nfmts ? "missing" : "extra", nfmts, argc);
		return (DCMD_ABORT);
	}

	for (i = 0; i < argc; i++) {
		mdb_ctf_id_t mid;
		ulong_t off;
		int ignored;

		if (argv[i].a_type != MDB_TYPE_STRING) {
			mdb_warn("expected only type member arguments\n");
			return (DCMD_ABORT);
		}

		if (strcmp((member = argv[i].a_un.a_str), ".") == 0) {
			/*
			 * We allow "." to be specified to denote the current
			 * value of dot.
			 */
			if (funcs[i] != printf_ptr && funcs[i] != printf_uint &&
			    funcs[i] != printf_int) {
				mdb_warn("expected integer or pointer format "
				    "specifier for '.'\n");
				return (DCMD_ABORT);
			}

			mdb_printf(fmts[i], mdb_get_dot());
			continue;
		}

		pa.pa_addr = addr;

		if (parse_member(&pa, member, id, &mid, &off, &ignored) != 0)
			return (DCMD_ABORT);

		if ((ret = funcs[i](mid, pa.pa_addr, off, fmts[i])) != 0) {
			mdb_warn("failed to print member '%s'\n", member);
			return (ret);
		}
	}

	mdb_printf("%s", last);

	return (DCMD_OK);
}

static char _mdb_printf_help[] =
"The format string argument is a printf(3C)-like format string that is a\n"
"subset of the format strings supported by mdb_printf().  The type argument\n"
"is the name of a type to be used to interpret the memory referenced by dot.\n"
"The member should either be a field in the specified structure, or the\n"
"special member '.', denoting the value of dot (and treated as a pointer).\n"
"The number of members must match the number of format specifiers in the\n"
"format string.\n"
"\n"
"The following format specifiers are recognized by ::printf:\n"
"\n"
"  %%    Prints the '%' symbol.\n"
"  %a    Prints the member in symbolic form.\n"
"  %d    Prints the member as a decimal integer.  If the member is a signed\n"
"        integer type, the output will be signed.\n"
"  %H    Prints the member as a human-readable size.\n"
"  %I    Prints the member as an IPv4 address (must be 32-bit integer type).\n"
"  %N    Prints the member as an IPv6 address (must be of type in6_addr_t).\n"
"  %o    Prints the member as an unsigned octal integer.\n"
"  %p    Prints the member as a pointer, in hexadecimal.\n"
"  %q    Prints the member in signed octal.  Honk if you ever use this!\n"
"  %r    Prints the member as an unsigned value in the current output radix.\n"
"  %R    Prints the member as a signed value in the current output radix.\n"
"  %s    Prints the member as a string (requires a pointer or an array of\n"
"        characters).\n"
"  %u    Prints the member as an unsigned decimal integer.\n"
"  %x    Prints the member in hexadecimal.\n"
"  %X    Prints the member in hexadecimal, using the characters A-F as the\n"
"        digits for the values 10-15.\n"
"  %Y    Prints the member as a time_t as the string "
	    "'year month day HH:MM:SS'.\n"
"\n"
"The following field width specifiers are recognized by ::printf:\n"
"\n"
"  %n    Field width is set to the specified decimal value.\n"
"  %?    Field width is set to the maximum width of a hexadecimal pointer\n"
"        value.  This is 8 in an ILP32 environment, and 16 in an LP64\n"
"        environment.\n"
"\n"
"The following flag specifers are recognized by ::printf:\n"
"\n"
"  %-    Left-justify the output within the specified field width.  If the\n"
"        width of the output is less than the specified field width, the\n"
"        output will be padded with blanks on the right-hand side.  Without\n"
"        %-, values are right-justified by default.\n"
"\n"
"  %0    Zero-fill the output field if the output is right-justified and the\n"
"        width of the output is less than the specified field width.  Without\n"
"        %0, right-justified values are prepended with blanks in order to\n"
"        fill the field.\n"
"\n"
"Examples: \n"
"\n"
"  ::walk proc | "
	"::printf \"%-6d %s\\n\" proc_t p_pidp->pid_id p_user.u_psargs\n"
"  ::walk thread | "
	"::printf \"%?p %3d %a\\n\" kthread_t . t_pri t_startpc\n"
"  ::walk zone | "
	"::printf \"%-40s %20s\\n\" zone_t zone_name zone_nodename\n"
"  ::walk ire | "
	"::printf \"%Y %I\\n\" ire_t ire_create_time ire_u.ire4_u.ire4_addr\n"
"\n";

void
printf_help(void)
{
	mdb_printf("%s", _mdb_printf_help);
}
