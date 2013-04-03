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
 * Copyright (c) 2013 by Delphix. All rights reserved.
 * Copyright (c) 2012 Joyent, Inc. All rights reserved.
 */
/*
 * This file contains all of the interfaces for mdb's tab completion engine.
 * Currently some interfaces are private to mdb and its internal implementation,
 * those are in mdb_tab.h. Other pieces are public interfaces. Those are in
 * mdb_modapi.h.
 *
 * Memory allocations in tab completion context have to be done very carefully.
 * We need to think of ourselves as the same as any other command that is being
 * executed by the user, which means we must use UM_GC to handle being
 * interrupted.
 */

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ctf.h>
#include <mdb/mdb_ctf_impl.h>
#include <mdb/mdb_string.h>
#include <mdb/mdb_module.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_print.h>
#include <mdb/mdb_nv.h>
#include <mdb/mdb_tab.h>
#include <mdb/mdb_target.h>
#include <mdb/mdb.h>

#include <ctype.h>

/*
 * There may be another way to do this, but this works well enough.
 */
#define	COMMAND_SEPARATOR "::"

/*
 * find_command_start --
 *
 * 	Given a buffer find the start of the last command.
 */
static char *
tab_find_command_start(char *buf)
{
	char *offset = strstr(buf, COMMAND_SEPARATOR);

	if (offset == NULL)
		return (NULL);

	for (;;) {
		char *next = strstr(offset + strlen(COMMAND_SEPARATOR),
		    COMMAND_SEPARATOR);

		if (next == NULL) {
			return (offset);
		}

		offset = next;
	}
}

/*
 * get_dcmd --
 *
 * 	Given a buffer containing a command and its argument return
 * 	the name of the command and the offset in the buffer where
 * 	the command arguments start.
 *
 * 	Note: This will modify the buffer.
 */
char *
tab_get_dcmd(char *buf, char **args, uint_t *flags)
{
	char *start = buf + strlen(COMMAND_SEPARATOR);
	char *separator = start;
	const char *end = buf + strlen(buf);
	uint_t space = 0;

	while (separator < end && !isspace(*separator))
		separator++;

	if (separator == end) {
		*args = NULL;
	} else {
		if (isspace(*separator))
			space = 1;

		*separator++ = '\0';
		*args = separator;
	}

	if (space)
		*flags |= DCMD_TAB_SPACE;

	return (start);
}

/*
 * count_args --
 *
 * 	Given a buffer containing dmcd arguments return the total number
 * 	of arguments.
 *
 * 	While parsing arguments we need to keep track of whether or not the last
 * 	arguments ends with a trailing space.
 */
static int
tab_count_args(const char *input, uint_t *flags)
{
	const char *index;
	int argc = 0;
	uint_t space = *flags & DCMD_TAB_SPACE;
	index = input;

	while (*index != '\0') {
		while (*index != '\0' && isspace(*index)) {
			index++;
			space = 1;
		}

		if (*index != '\0' && !isspace(*index)) {
			argc++;
			space = 0;
			while (*index != '\0' && !isspace (*index)) {
				index++;
			}
		}
	}

	if (space)
		*flags |= DCMD_TAB_SPACE;
	else
		*flags &= ~DCMD_TAB_SPACE;

	return (argc);
}

/*
 * copy_args --
 *
 * 	Given a buffer containing dcmd arguments and an array of mdb_arg_t's
 * 	initialize the string value of each mdb_arg_t.
 *
 * 	Note: This will modify the buffer.
 */
static int
tab_copy_args(char *input, int argc, mdb_arg_t *argv)
{
	int i = 0;
	char *index;

	index = input;

	while (*index) {
		while (*index && isspace(*index)) {
			index++;
		}

		if (*index && !isspace(*index)) {
			char *end = index;

			while (*end && !isspace(*end)) {
				end++;
			}

			if (*end) {
				*end++ = '\0';
			}

			argv[i].a_type = MDB_TYPE_STRING;
			argv[i].a_un.a_str = index;

			index = end;
			i++;
		}
	}

	if (i != argc)
		return (-1);

	return (0);
}

/*
 * parse-buf --
 *
 * 	Parse the given buffer and return the specified dcmd, the number
 * 	of arguments, and array of mdb_arg_t containing the argument
 * 	values.
 *
 * 	Note: this will modify the specified buffer. Caller is responisble
 * 	for freeing argvp.
 */
static int
tab_parse_buf(char *buf, char **dcmdp, int *argcp, mdb_arg_t **argvp,
    uint_t *flags)
{
	char *data = tab_find_command_start(buf);
	char *args_data = NULL;
	char *dcmd = NULL;
	int argc = 0;
	mdb_arg_t *argv = NULL;

	if (data == NULL) {
		return (-1);
	}

	dcmd = tab_get_dcmd(data, &args_data, flags);

	if (dcmd == NULL) {
		return (-1);
	}

	if (args_data != NULL) {
		argc = tab_count_args(args_data, flags);

		if (argc != 0) {
			argv = mdb_alloc(sizeof (mdb_arg_t) * argc,
			    UM_SLEEP | UM_GC);

			if (tab_copy_args(args_data, argc, argv) == -1)
				return (-1);
		}
	}

	*dcmdp = dcmd;
	*argcp = argc;
	*argvp = argv;

	return (0);
}

/*
 * tab_command --
 *
 * 	This function is executed anytime a tab is entered. It checks
 * 	the current buffer to determine if there is a valid dmcd,
 * 	if that dcmd has a tab completion handler it will invoke it.
 *
 *	This function returns the string (if any) that should be added to the
 *	existing buffer to complete it.
 */
int
mdb_tab_command(mdb_tab_cookie_t *mcp, const char *buf)
{
	char *data;
	char *dcmd = NULL;
	int argc = 0;
	mdb_arg_t *argv = NULL;
	int ret = 0;
	mdb_idcmd_t *cp;
	uint_t flags = 0;

	/*
	 * Parsing the command and arguments will modify the buffer
	 * (replacing spaces with \0), so make a copy of the specified
	 * buffer first.
	 */
	data = mdb_alloc(strlen(buf) + 1, UM_SLEEP | UM_GC);
	(void) strcpy(data, buf);

	/*
	 * Get the specified dcmd and arguments from the buffer.
	 */
	ret = tab_parse_buf(data, &dcmd, &argc, &argv, &flags);

	/*
	 * Match against global symbols if the input is not a dcmd
	 */
	if (ret != 0) {
		(void) mdb_tab_complete_global(mcp, buf);
		goto out;
	}

	/*
	 * Check to see if the buffer contains a valid dcmd
	 */
	cp = mdb_dcmd_lookup(dcmd);

	/*
	 * When argc is zero it indicates that we are trying to tab complete
	 * a dcmd or a global symbol. Note, that if there isn't the start of
	 * a dcmd, i.e. ::, then we will have already bailed in the call to
	 * tab_parse_buf.
	 */
	if (cp == NULL && argc != 0) {
		goto out;
	}

	/*
	 * Invoke the command specific tab completion handler or the built in
	 * dcmd one if there is no dcmd.
	 */
	if (cp == NULL)
		(void) mdb_tab_complete_dcmd(mcp, dcmd);
	else
		mdb_call_tab(cp, mcp, flags, argc, argv);

out:
	return (mdb_tab_size(mcp));
}

static int
tab_complete_dcmd(mdb_var_t *v, void *arg)
{
	mdb_idcmd_t *idcp = mdb_nv_get_cookie(mdb_nv_get_cookie(v));
	mdb_tab_cookie_t *mcp = (mdb_tab_cookie_t *)arg;

	/*
	 * The way that mdb is implemented, even commands like $C will show up
	 * here. As such, we don't want to match anything that doesn't start
	 * with an alpha or number. While nothing currently appears (via a
	 * cursory search with mdb -k) to start with a capital letter or a
	 * number, we'll support them anyways.
	 */
	if (!isalnum(idcp->idc_name[0]))
		return (0);

	mdb_tab_insert(mcp, idcp->idc_name);
	return (0);
}

int
mdb_tab_complete_dcmd(mdb_tab_cookie_t *mcp, const char *dcmd)
{
	mdb_tab_setmbase(mcp, dcmd);
	mdb_nv_sort_iter(&mdb.m_dcmds, tab_complete_dcmd, mcp,
	    UM_GC | UM_SLEEP);
	return (0);
}

static int
tab_complete_walker(mdb_var_t *v, void *arg)
{
	mdb_iwalker_t *iwp = mdb_nv_get_cookie(mdb_nv_get_cookie(v));
	mdb_tab_cookie_t *mcp = arg;

	mdb_tab_insert(mcp, iwp->iwlk_name);
	return (0);
}

int
mdb_tab_complete_walker(mdb_tab_cookie_t *mcp, const char *walker)
{
	if (walker != NULL)
		mdb_tab_setmbase(mcp, walker);
	mdb_nv_sort_iter(&mdb.m_walkers, tab_complete_walker, mcp,
	    UM_GC | UM_SLEEP);

	return (0);
}

mdb_tab_cookie_t *
mdb_tab_init(void)
{
	mdb_tab_cookie_t *mcp;

	mcp = mdb_zalloc(sizeof (mdb_tab_cookie_t), UM_SLEEP | UM_GC);
	(void) mdb_nv_create(&mcp->mtc_nv, UM_SLEEP | UM_GC);

	return (mcp);
}

size_t
mdb_tab_size(mdb_tab_cookie_t *mcp)
{
	return (mdb_nv_size(&mcp->mtc_nv));
}

/*
 * Determine whether the specified name is a valid tab completion for
 * the given command. If the name is a valid tab completion then
 * it will be saved in the mdb_tab_cookie_t.
 */
void
mdb_tab_insert(mdb_tab_cookie_t *mcp, const char *name)
{
	size_t len, matches, index;
	uint_t flags;
	mdb_var_t *v;
	char *n;
	const char *nvn;

	/*
	 * If we have a match set, then we want to verify that we actually match
	 * it.
	 */
	if (mcp->mtc_base != NULL &&
	    strncmp(name, mcp->mtc_base, strlen(mcp->mtc_base)) != 0)
		return;

	v = mdb_nv_lookup(&mcp->mtc_nv, name);
	if (v != NULL)
		return;

	/*
	 * Names that we get passed in may be longer than MDB_NV_NAMELEN which
	 * is currently 31 including the null terminator. If that is the case,
	 * then we're going to take care of allocating a string and holding it
	 * for our caller. Note that we don't need to free it, because we're
	 * allocating this with UM_GC.
	 */
	flags = 0;
	len = strlen(name);
	if (len > MDB_NV_NAMELEN - 1) {
		n = mdb_alloc(len + 1, UM_SLEEP | UM_GC);
		(void) strcpy(n, name);
		nvn = n;
		flags |= MDB_NV_EXTNAME;
	} else {
		nvn = name;
	}
	flags |= MDB_NV_RDONLY;

	(void) mdb_nv_insert(&mcp->mtc_nv, nvn, NULL, 0, flags);

	matches = mdb_tab_size(mcp);
	if (matches == 1) {
		(void) strlcpy(mcp->mtc_match, nvn, MDB_SYM_NAMLEN);
	} else {
		index = 0;
		while (mcp->mtc_match[index] &&
		    mcp->mtc_match[index] == nvn[index])
			index++;

		mcp->mtc_match[index] = '\0';
	}
}

/*ARGSUSED*/
static int
tab_print_cb(mdb_var_t *v, void *ignored)
{
	mdb_printf("%s\n", mdb_nv_get_name(v));
	return (0);
}

void
mdb_tab_print(mdb_tab_cookie_t *mcp)
{
	mdb_nv_sort_iter(&mcp->mtc_nv, tab_print_cb, NULL, UM_SLEEP | UM_GC);
}

const char *
mdb_tab_match(mdb_tab_cookie_t *mcp)
{
	size_t blen;

	if (mcp->mtc_base == NULL)
		blen = 0;
	else
		blen = strlen(mcp->mtc_base);
	return (mcp->mtc_match + blen);
}

void
mdb_tab_setmbase(mdb_tab_cookie_t *mcp, const char *base)
{
	(void) strlcpy(mcp->mtc_base, base, MDB_SYM_NAMLEN);
}

/*
 * This function is currently a no-op due to the fact that we have to GC because
 * we're in command context.
 */
/*ARGSUSED*/
void
mdb_tab_fini(mdb_tab_cookie_t *mcp)
{
}

/*ARGSUSED*/
static int
tab_complete_global(void *arg, const GElf_Sym *sym, const char *name,
    const mdb_syminfo_t *sip, const char *obj)
{
	mdb_tab_cookie_t *mcp = arg;
	mdb_tab_insert(mcp, name);
	return (0);
}

/*
 * This function tab completes against all loaded global symbols.
 */
int
mdb_tab_complete_global(mdb_tab_cookie_t *mcp, const char *name)
{
	mdb_tab_setmbase(mcp, name);
	(void) mdb_tgt_symbol_iter(mdb.m_target, MDB_TGT_OBJ_EVERY,
	    MDB_TGT_SYMTAB, MDB_TGT_BIND_ANY | MDB_TGT_TYPE_OBJECT |
	    MDB_TGT_TYPE_FUNC, tab_complete_global, mcp);
	return (0);
}

/*
 * This function takes a ctf id and determines whether or not the associated
 * type should be considered as a potential match for the given tab
 * completion command. We verify that the type itself is valid
 * for completion given the current context of the command, resolve
 * its actual name, and then pass it off to mdb_tab_insert to determine
 * if it's an actual match.
 */
static int
tab_complete_type(mdb_ctf_id_t id, void *arg)
{
	int rkind;
	char buf[MDB_SYM_NAMLEN];
	mdb_ctf_id_t rid;
	mdb_tab_cookie_t *mcp = arg;
	uint_t flags = (uint_t)(uintptr_t)mcp->mtc_cba;

	/*
	 * CTF data includes types that mdb commands don't understand. Before
	 * we resolve the actual type prune any entry that is a type we
	 * don't care about.
	 */
	switch (mdb_ctf_type_kind(id)) {
	case CTF_K_CONST:
	case CTF_K_RESTRICT:
	case CTF_K_VOLATILE:
		return (0);
	}

	if (mdb_ctf_type_resolve(id, &rid) != 0)
		return (1);

	rkind = mdb_ctf_type_kind(rid);

	if ((flags & MDB_TABC_MEMBERS) && rkind != CTF_K_STRUCT &&
	    rkind != CTF_K_UNION)
		return (0);

	if ((flags & MDB_TABC_NOPOINT) && rkind == CTF_K_POINTER)
		return (0);

	if ((flags & MDB_TABC_NOARRAY) && rkind == CTF_K_ARRAY)
		return (0);

	(void) mdb_ctf_type_name(id, buf, sizeof (buf));

	mdb_tab_insert(mcp, buf);
	return (0);
}

/*ARGSUSED*/
static int
mdb_tab_complete_module(void *data, const mdb_map_t *mp, const char *name)
{
	(void) mdb_ctf_type_iter(name, tab_complete_type, data);
	return (0);
}

int
mdb_tab_complete_type(mdb_tab_cookie_t *mcp, const char *name, uint_t flags)
{
	mdb_tgt_t *t = mdb.m_target;

	mcp->mtc_cba = (void *)(uintptr_t)flags;
	if (name != NULL)
		mdb_tab_setmbase(mcp, name);

	(void) mdb_tgt_object_iter(t, mdb_tab_complete_module, mcp);
	(void) mdb_ctf_type_iter(MDB_CTF_SYNTHETIC_ITER, tab_complete_type,
	    mcp);
	return (0);
}

/*ARGSUSED*/
static int
tab_complete_member(const char *name, mdb_ctf_id_t id, ulong_t off, void *arg)
{
	mdb_tab_cookie_t *mcp = arg;
	mdb_tab_insert(mcp, name);
	return (0);
}

int
mdb_tab_complete_member_by_id(mdb_tab_cookie_t *mcp, mdb_ctf_id_t id,
    const char *member)
{
	if (member != NULL)
		mdb_tab_setmbase(mcp, member);
	(void) mdb_ctf_member_iter(id, tab_complete_member, mcp);
	return (0);
}

int
mdb_tab_complete_member(mdb_tab_cookie_t *mcp, const char *type,
    const char *member)
{
	mdb_ctf_id_t id;

	if (mdb_ctf_lookup_by_name(type, &id) != 0)
		return (-1);

	return (mdb_tab_complete_member_by_id(mcp, id, member));
}

int
mdb_tab_complete_mt(mdb_tab_cookie_t *mcp, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	char tn[MDB_SYM_NAMLEN];
	int ret;

	if (argc == 0 && !(flags & DCMD_TAB_SPACE))
		return (0);

	if (argc == 0)
		return (mdb_tab_complete_type(mcp, NULL, MDB_TABC_MEMBERS));

	if ((ret = mdb_tab_typename(&argc, &argv, tn, sizeof (tn))) < 0)
		return (ret);

	if (argc == 1 && (!(flags & DCMD_TAB_SPACE) || ret == 1))
		return (mdb_tab_complete_type(mcp, tn, MDB_TABC_MEMBERS));

	if (argc == 1 && (flags & DCMD_TAB_SPACE))
		return (mdb_tab_complete_member(mcp, tn, NULL));

	if (argc == 2)
		return (mdb_tab_complete_member(mcp, tn, argv[1].a_un.a_str));

	return (0);
}

/*
 * This is similar to mdb_print.c's args_to_typename, but it has subtle
 * differences surrounding how the strings of one element are handled that have
 * 'struct', 'enum', or 'union' in them and instead works with them for tab
 * completion purposes.
 */
int
mdb_tab_typename(int *argcp, const mdb_arg_t **argvp, char *buf, size_t len)
{
	int argc = *argcp;
	const mdb_arg_t *argv = *argvp;

	if (argc < 1 || argv->a_type != MDB_TYPE_STRING)
		return (DCMD_USAGE);

	if (strcmp(argv->a_un.a_str, "struct") == 0 ||
	    strcmp(argv->a_un.a_str, "enum") == 0 ||
	    strcmp(argv->a_un.a_str, "union") == 0) {
		if (argc == 1) {
			(void) mdb_snprintf(buf, len, "%s ",
			    argv[0].a_un.a_str);
			return (1);
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
