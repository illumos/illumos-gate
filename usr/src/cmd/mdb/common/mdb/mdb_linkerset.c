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
 * Copyright 2021 Joyent, Inc.
 */

#include <mdb/mdb_debug.h>
#include <mdb/mdb_errno.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_ctf.h>
#include <mdb/mdb_ctf_impl.h>
#include <mdb/mdb_target_impl.h>
#include <mdb/mdb.h>
#include <sys/errno.h>
#include <string.h>

/*
 * A linker set is an array of pointers. The start of the set will have a
 * weak symbol of the form START_PREFIX + name that will have the address
 * of the first element (pointer) and another weak symbol that points just
 * past the end of the final element. E.g. for a linker set 'foo', the
 * first element will have a symbol __start_set_foo, and all __stop_set_foo
 * will have the address just after the last element (e.g. &(last_element + 1))
 */
#define	START_PREFIX "__start_set_"
#define	STOP_PREFIX "__stop_set_"

/*
 * The pointers that comprise the linker set have names that follow
 * the pattern __set_<setname>_sym_<objname>.
 */
#define	SYM_PREFIX "__set_"
#define	SYM_DELIM "_sym_"

typedef struct ldset_info {
	char		ldsi_name[MDB_SYM_NAMLEN];
	uintptr_t	ldsi_addr;
	uintptr_t	ldsi_endaddr;
	size_t		ldsi_ptrsize;
	size_t		ldsi_nelem;
	ssize_t		ldsi_elsize;
} ldset_info_t;

/*
 * Similar to ldset_name_from_start(), except that it uses a linker set item
 * name (e.g. '__set_foo_set_sym_foo_item') and writes the set name ('foo_set')
 * into buf.
 */
static int
ldset_name_from_item(const char *item_name, char *buf, size_t buflen)
{
	const char *startp;
	const char *endp;
	size_t setname_len;

	/* The item name must start with '__sym_' */
	if (strncmp(item_name, SYM_PREFIX, sizeof (SYM_PREFIX) - 1) != 0) {
		return (set_errno(EINVAL));
	}
	startp = item_name + sizeof (SYM_PREFIX) - 1;

	/* The item name must have stuff after '__sym_' */
	if (*startp == '\0') {
		return (set_errno(EINVAL));
	}

	/* Find the start of '_sym_' after the prefix */
	endp = strstr(startp, SYM_DELIM);
	if (endp == NULL) {
		/* '_sym_' not in the name, not a valid item name */
		return (set_errno(EINVAL));
	}

	setname_len = (size_t)(endp - startp);
	if (setname_len + 1 > buflen) {
		return (set_errno(ENAMETOOLONG));
	}

	/*
	 * We've verified buf has enough room for the linker set name + NUL.
	 * For sanity, we guarantee any trailing bytes in buf are zero, and
	 * use strncpy() so we copy only the bytes from item_name that are
	 * a part of the linker set name. The result should always be NUL
	 * terminated as a result.
	 */
	(void) memset(buf, '\0', buflen);
	(void) strncpy(buf, item_name + sizeof (SYM_PREFIX) - 1, setname_len);

	return (0);
}

static int
ldset_get_sym(const char *prefix, const char *name, GElf_Sym *sym)
{
	char symname[MDB_SYM_NAMLEN] = { 0 };

	if (mdb_snprintf(symname, sizeof (symname), "%s%s", prefix, name) >
	    sizeof (symname) - 1) {
		return (set_errno(ENAMETOOLONG));
	}

	return (mdb_tgt_lookup_by_name(mdb.m_target, MDB_TGT_OBJ_EVERY, symname,
	    sym, NULL));
}

/*
 * Given the address of a pointer in a linker set, return the address of the
 * item in the set in *addrp.
 */
static int
ldset_get_entry(uintptr_t addr, uintptr_t *addrp, size_t ptrsize)
{
	union {
		uint64_t u64;
		uint32_t u32;
	} val;
	ssize_t n;

	switch (ptrsize) {
	case sizeof (uint32_t):
		n = mdb_vread(&val.u32, sizeof (uint32_t), addr);
		*addrp = (uintptr_t)val.u32;
		break;
	case sizeof (uint64_t):
		n = mdb_vread(&val.u64, sizeof (uint64_t), addr);
		*addrp = (uintptr_t)val.u64;
		break;
	default:
		return (set_errno(ENOTSUP));
	}

	if (n != ptrsize) {
		/* XXX: Better error value? */
		return (set_errno(ENODATA));
	}

	return (0);
}

static ssize_t
ldset_item_size(uintptr_t addr)
{
	mdb_ctf_id_t id;
	int ret;

	ret = mdb_ctf_lookup_by_addr(addr, &id);
	if (ret != 0) {
		return ((ssize_t)ret);
	}

	return (mdb_ctf_type_size(id));
}

static int
ldset_get_info(uintptr_t addr, ldset_info_t *ldsi)
{
	GElf_Sym start_sym = { 0 };
	GElf_Sym stop_sym = { 0 };
	char name[MDB_SYM_NAMLEN] = { 0 };
	uintptr_t item_addr;
	int ret;

	switch (mdb_tgt_dmodel(mdb.m_target)) {
	case MDB_TGT_MODEL_LP64:
		ldsi->ldsi_ptrsize = sizeof (uint64_t);
		break;
	case MDB_TGT_MODEL_ILP32:
		ldsi->ldsi_ptrsize = sizeof (uint32_t);
		break;
	default:
		return (set_errno(ENOTSUP));
	}

	ret = mdb_tgt_lookup_by_addr(mdb.m_target, addr, MDB_TGT_SYM_EXACT,
	    name, sizeof (name), &start_sym, NULL);
	if (ret != 0) {
		return (ret);
	}

	if (ldset_name_from_item(name, ldsi->ldsi_name,
	    sizeof (ldsi->ldsi_name)) != 0) {
		return (-1);
	}

	ret = ldset_get_sym(STOP_PREFIX, ldsi->ldsi_name, &stop_sym);
	if (ret != 0) {
		return (-1);
	}

	if (stop_sym.st_value < addr) {
		return (set_errno(EINVAL));
	}

	if (ldset_get_entry(addr, &item_addr, ldsi->ldsi_ptrsize) != 0) {
		return (-1);
	}

	ldsi->ldsi_addr = addr;
	ldsi->ldsi_endaddr = stop_sym.st_value;
	ldsi->ldsi_nelem = (stop_sym.st_value - addr) / ldsi->ldsi_ptrsize;
	ldsi->ldsi_elsize = ldset_item_size(item_addr);

	return (0);
}

static int
ldsets_init_cb(void *data, const GElf_Sym *sym, const char *name,
    const mdb_syminfo_t *sip, const char *obj)
{
	mdb_nv_t	*nv = data;
	const char	*ldset_name;
	GElf_Sym	stop_sym = { 0 };
	int		ret;

	if (strncmp(name, START_PREFIX, sizeof (START_PREFIX) - 1) != 0) {
		return (0);
	}

	/*
	 * The name of the linker set should follow START_PREFIX. If there's
	 * nothing there, then it's not a linker set, so skip this symbol.
	 */
	ldset_name = name + sizeof (START_PREFIX) - 1;
	if (*ldset_name == '\0') {
		return (0);
	}

	ret = ldset_get_sym(STOP_PREFIX, ldset_name, &stop_sym);
	if (ret != 0) {
		/* If there's no stop symbol, we just ignore */
		if (errno == ENOENT) {
			errno = 0;
			return (0);
		}
		return (-1);
	}

	/*
	 * The stop symbol should be at the same or higher address than
	 * the start symbol. If not, we ignore.
	 */
	if (stop_sym.st_value < sym->st_value) {
		return (0);
	}

	if (mdb_nv_insert(nv, ldset_name, NULL, sym->st_value,
	    MDB_NV_RDONLY) == NULL) {
		return (-1);
	}

	return (0);
}

/*
 * Initialize an mdb_nv_t with the name/addr of all the linkersets found in
 * the target.
 */
static int
ldsets_nv_init(mdb_nv_t *nv, uint_t flags)
{
	if (mdb_nv_create(nv, flags) == NULL)
		return (-1);

	return (mdb_tgt_symbol_iter(mdb.m_target, MDB_TGT_OBJ_EVERY,
	    MDB_TGT_SYMTAB, MDB_TGT_BIND_ANY | MDB_TGT_TYPE_NOTYPE,
	    ldsets_init_cb, nv));
}

int
ldsets_walk_init(mdb_walk_state_t *wsp)
{
	mdb_nv_t *nv;
	int ret;

	nv = mdb_zalloc(sizeof (*nv), UM_SLEEP | UM_GC);
	ret = ldsets_nv_init(nv, UM_SLEEP | UM_GC);
	if (ret != 0) {
		return (ret);
	}

	mdb_nv_rewind(nv);
	wsp->walk_data = nv;
	return (WALK_NEXT);
}

int
ldsets_walk_step(mdb_walk_state_t *wsp)
{
	mdb_nv_t *nv = wsp->walk_data;
	mdb_var_t *v = mdb_nv_advance(nv);
	int status;

	if (v == NULL) {
		return (WALK_DONE);
	}

	wsp->walk_addr = mdb_nv_get_value(v);
	status = wsp->walk_callback(wsp->walk_addr, NULL, wsp->walk_cbdata);
	return (status);
}

int
ldset_walk_init(mdb_walk_state_t *wsp)
{
	ldset_info_t *ldsi;
	int ret;

	ldsi = mdb_zalloc(sizeof (*ldsi), UM_SLEEP | UM_GC);

	ret = ldset_get_info(wsp->walk_addr, ldsi);
	if (ret != 0)
		return (WALK_ERR);

	wsp->walk_data = ldsi;
	return (WALK_NEXT);
}

int
ldset_walk_step(mdb_walk_state_t *wsp)
{
	ldset_info_t *ldsi = wsp->walk_data;
	uintptr_t addr;
	int ret;

	if (wsp->walk_addr >= ldsi->ldsi_endaddr) {
		return (WALK_DONE);
	}

	ret = ldset_get_entry(wsp->walk_addr, &addr, ldsi->ldsi_ptrsize);
	if (ret != 0) {
		return (WALK_ERR);
	}

	ret = wsp->walk_callback(addr, NULL, wsp->walk_cbdata);

	wsp->walk_addr += ldsi->ldsi_ptrsize;
	return (ret);
}

static int
linkerset_walk_cb(uintptr_t addr, const void *data, void *cbarg)
{
	mdb_printf("%lr\n", addr);
	return (0);
}

static int
linkersets_walk_cb(uintptr_t addr, const void *data, void *cbarg)
{
	ldset_info_t	info = { 0 };
	int		ret;
	char		buf[64]; /* big enough for element size in any radix */

	ret = ldset_get_info(addr, &info);
	if (ret != 0)
		return (WALK_ERR);

	if (info.ldsi_elsize > 0) {
		(void) mdb_snprintf(buf, sizeof (buf), "%#r",
		    info.ldsi_elsize);
	} else {
		(void) strlcpy(buf, "?", sizeof (buf));
	}

	mdb_printf("%-20s %8s %9u\n", info.ldsi_name, buf, info.ldsi_nelem);
	return (WALK_NEXT);
}

int
cmd_linkerset(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int ret;

	if (argc > 1) {
		return (DCMD_USAGE);
	}

	/* Walk a linkerset given by the first argument */
	if (argc == 1) {
		const char	*setname = argv->a_un.a_str;
		GElf_Sym	start_sym = { 0 };
		ldset_info_t	info = { 0 };

		if (argv->a_type != MDB_TYPE_STRING) {
			return (DCMD_USAGE);
		}

		ret = ldset_get_sym(START_PREFIX, setname, &start_sym);
		if (ret != 0) {
			mdb_warn("Failed to get address of linkerset");
			return (-1);
		}

		ret = ldset_get_info((uintptr_t)start_sym.st_value, &info);
		if (ret != 0) {
			mdb_warn("Failed to get information on linkerset");
			return (-1);
		}

		return (mdb_pwalk("linkerset", linkerset_walk_cb, NULL,
		    info.ldsi_addr));
	}

	/* Display all the known linkersets */
	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<b>%<u>%-20s %-8s %-9s%</u>%</b>\n",
		    "NAME", "ITEMSIZE", "ITEMCOUNT");
	}

	return (mdb_walk("linkersets", linkersets_walk_cb, NULL));
}

static int
ldset_complete(mdb_var_t *v, void *arg)
{
	mdb_tab_cookie_t *mcp = arg;

	mdb_tab_insert(mcp, mdb_nv_get_name(v));
	return (0);
}

static int
ldset_tab_complete(mdb_tab_cookie_t *mcp, const char *ldset)
{
	mdb_nv_t nv = { 0 };
	int ret;

	ret = ldsets_nv_init(&nv, UM_GC | UM_SLEEP);
	if (ret != 0) {
		return (ret);
	}

	if (ldset != NULL) {
		mdb_tab_setmbase(mcp, ldset);
	}

	mdb_nv_sort_iter(&nv, ldset_complete, mcp, UM_GC | UM_SLEEP);
	return (1);
}

int
cmd_linkerset_tab(mdb_tab_cookie_t *mcp, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	if (argc > 1)
		return (1);

	if (argc == 1) {
		ASSERT(argv[0].a_type == MDB_TYPE_STRING);
		return (ldset_tab_complete(mcp, argv[0].a_un.a_str));
	}

	if (argc == 0 && (flags & DCMD_TAB_SPACE) != 0) {
		return (ldset_tab_complete(mcp, NULL));
	}

	return (1);
}

void
linkerset_help(void)
{
	static const char ldset_desc[] =
"A linker set is an array of pointers to objects in a target that have been\n"
"collected by the linker. The start and end location of each linker set\n"
"is designated by weak symbols with well known strings prefixed to the\n"
"name of the linker set.\n"
"\n"
"When invoked without any arguments, the ::linkerset command will attempt to\n"
"enumerate all linker sets present in the target. For each linker set, the \n"
"name, number of objects in the set, as well as the size of each object (when\n"
"known) is displayed. The ::linkerset command uses the CTF information to\n"
"determine the size of each object. If the CTF data is unavailable for a\n"
"given linkerset, '?' will displayed instead of the size.\n"
"\n"
"The ::linkerset command can also be invoked with a single argument -- the\n"
"name of a specific linker set. In this invocation, the ::linkerset command\n"
"will display the addresses of each object in the set and can be used as\n"
"part of a command pipeline.\n";

	static const char ldset_examples[] =
"  ::linkerset\n"
"  ::linkerset sysinit_set | ::print 'struct sysinit'\n";

	mdb_printf("%s\n", ldset_desc);
	(void) mdb_dec_indent(2);
	mdb_printf("%<b>EXAMPLES%</b>\n");
	(void) mdb_inc_indent(2);
	mdb_printf("%s\n", ldset_examples);
}
