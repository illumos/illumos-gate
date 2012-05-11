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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2012, Joyent, Inc.  All rights reserved.
 */

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_macalias.h>
#include <mdb/mdb_fmt.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_help.h>
#include <mdb/mdb.h>

const char _mdb_help[] =
"\nEach debugger command in %s is structured as follows:\n\n"
"      [ address [, count]] verb [ arguments ... ]\n"
"             ^       ^      ^      ^\n"
" the start --+       |      |      +-- arguments are strings which can be\n"
" address can be an   |      |          quoted using \"\" or '' or\n"
" expression          |      |          expressions enclosed in $[ ]\n"
"                     |      |\n"
" the repeat count  --+      +--------- the verb is a name which begins\n"
" is also an expression                 with either $, :, or ::.  it can also\n"
"                                       be a format specifier (/ \\ ? or =)\n\n"
"For information on debugger commands (dcmds) and walkers, type:\n\n"
"      ::help cmdname ... for more detailed information on a command\n"
"      ::dcmds        ... for a list of dcmds and their descriptions\n"
"      ::walkers      ... for a list of walkers and their descriptions\n"
"      ::dmods -l     ... for a list of modules and their dcmds and walkers\n"
"      ::formats      ... for a list of format characters for / \\ ? and =\n\n"
"For information on command-line options, type:\n\n"
"      $ %s -?      ... in your shell for a complete list of options\n\n";

/*ARGSUSED*/
static int
print_dcmd(mdb_var_t *v, void *ignored)
{
	const mdb_idcmd_t *idcp = mdb_nv_get_cookie(v);
	if (idcp->idc_descr != NULL)
		mdb_printf("  dcmd %-20s - %s\n",
		    idcp->idc_name, idcp->idc_descr);
	return (0);
}

/*ARGSUSED*/
static int
print_walk(mdb_var_t *v, void *ignored)
{
	const mdb_iwalker_t *iwp = mdb_nv_get_cookie(v);
	if (iwp->iwlk_descr != NULL)
		mdb_printf("  walk %-20s - %s\n",
		    iwp->iwlk_name, iwp->iwlk_descr);
	return (0);
}

/*ARGSUSED*/
static int
print_dmod_long(mdb_var_t *v, void *ignored)
{
	mdb_module_t *mod = mdb_nv_get_cookie(v);

	mdb_printf("\n%<u>%-70s%</u>\n", mod->mod_name);

	if (mod->mod_tgt_ctor != NULL) {
		mdb_printf("  ctor 0x%-18lx - target constructor\n",
		    (ulong_t)mod->mod_tgt_ctor);
	}

	if (mod->mod_dis_ctor != NULL) {
		mdb_printf("  ctor 0x%-18lx - disassembler constructor\n",
		    (ulong_t)mod->mod_dis_ctor);
	}

	mdb_nv_sort_iter(&mod->mod_dcmds, print_dcmd, NULL, UM_SLEEP | UM_GC);
	mdb_nv_sort_iter(&mod->mod_walkers, print_walk, NULL, UM_SLEEP | UM_GC);

	return (0);
}

/*ARGSUSED*/
static int
print_dmod_short(mdb_var_t *v, void *ignored)
{
	mdb_printf("%s\n", mdb_nv_get_name(v));
	return (0);
}

/*ARGSUSED*/
int
cmd_dmods(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int (*func)(mdb_var_t *, void *);
	uint_t opt_l = FALSE;
	mdb_var_t *v;
	int i;

	if (flags & DCMD_ADDRSPEC)
		return (DCMD_USAGE);

	i = mdb_getopts(argc, argv, 'l', MDB_OPT_SETBITS, TRUE, &opt_l, NULL);
	func = opt_l ? print_dmod_long : print_dmod_short;

	if (i != argc) {
		if (argc - i != 1 || argv[i].a_type != MDB_TYPE_STRING)
			return (DCMD_USAGE);

		v = mdb_nv_lookup(&mdb.m_modules, argv[i].a_un.a_str);

		if (v == NULL)
			mdb_warn("%s module not loaded\n", argv[i].a_un.a_str);
		else
			(void) func(v, NULL);

	} else
		mdb_nv_sort_iter(&mdb.m_modules, func, NULL, UM_SLEEP | UM_GC);

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
print_wdesc(mdb_var_t *v, void *ignored)
{
	mdb_iwalker_t *iwp = mdb_nv_get_cookie(mdb_nv_get_cookie(v));

	if (iwp->iwlk_descr != NULL)
		mdb_printf("%-24s - %s\n", mdb_nv_get_name(v), iwp->iwlk_descr);
	return (0);
}

/*ARGSUSED*/
int
cmd_walkers(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if ((flags & DCMD_ADDRSPEC) || argc != 0)
		return (DCMD_USAGE);

	mdb_nv_sort_iter(&mdb.m_walkers, print_wdesc, NULL, UM_SLEEP | UM_GC);
	return (DCMD_OK);
}

/*ARGSUSED*/
static int
print_ddesc(mdb_var_t *v, void *ignored)
{
	mdb_idcmd_t *idcp = mdb_nv_get_cookie(mdb_nv_get_cookie(v));

	if (idcp->idc_descr != NULL)
		mdb_printf("%-24s - %s\n", mdb_nv_get_name(v), idcp->idc_descr);
	return (0);
}

/*ARGSUSED*/
int
cmd_dcmds(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if ((flags & DCMD_ADDRSPEC) || argc != 0)
		return (DCMD_USAGE);

	mdb_nv_sort_iter(&mdb.m_dcmds, print_ddesc, NULL, UM_SLEEP | UM_GC);
	return (DCMD_OK);
}

/*ARGSUSED*/
int
cmd_help(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	const char *prefix, *usage;
	const mdb_idcmd_t *idcp;

	if ((flags & DCMD_ADDRSPEC) || argc > 1)
		return (DCMD_USAGE);

	if (argc == 0) {
		mdb_printf(_mdb_help, mdb.m_pname, mdb.m_pname);
		return (DCMD_OK);
	}

	if (argv->a_type != MDB_TYPE_STRING) {
		warn("expected string argument\n");
		return (DCMD_USAGE);
	}

	if (strncmp(argv->a_un.a_str, "::", 2) == 0)
		idcp = mdb_dcmd_lookup(argv->a_un.a_str + 2);
	else
		idcp = mdb_dcmd_lookup(argv->a_un.a_str);

	if (idcp == NULL) {
		mdb_warn("unknown command: %s\n", argv->a_un.a_str);
		return (DCMD_ERR);
	}

	prefix = strchr(":$=/\\?>", idcp->idc_name[0]) ? "" : "::";
	usage = idcp->idc_usage ? idcp->idc_usage : "";

	mdb_printf("\n%<b>NAME%</b>\n  %s - %s\n\n",
	    idcp->idc_name, idcp->idc_descr);

	mdb_printf("%<b>SYNOPSIS%</b>\n  ");
	if (usage[0] == '?') {
		mdb_printf("[ %<u>addr%</u> ] ");
		usage++;
	} else if (usage[0] == ':') {
		mdb_printf("%<u>addr%</u> ");
		usage++;
	}

	mdb_printf("%s%s %s\n\n", prefix, idcp->idc_name, usage);

	if (idcp->idc_help != NULL) {
		mdb_printf("%<b>DESCRIPTION%</b>\n");
		(void) mdb_inc_indent(2);
		idcp->idc_help();
		(void) mdb_dec_indent(2);
		mdb_printf("\n");
	}

	/*
	 * For now, modules that are built-in mark their interfaces Evolving
	 * (documented in mdb(1)) and modules that are loaded mark their
	 * interfaces Unstable.  In the future we could extend the dmod linkage
	 * to include the module's intended stability and then show it here.
	 */
	mdb_printf("%<b>ATTRIBUTES%</b>\n\n");
	mdb_printf("  Target: %s\n", mdb_tgt_name(mdb.m_target));
	mdb_printf("  Module: %s\n", idcp->idc_modp->mod_name);
	mdb_printf("  Interface Stability: %s\n\n",
	    (idcp->idc_descr != NULL && idcp->idc_modp->mod_hdl == NULL) ?
	    "Evolving" : "Unstable");

	return (DCMD_OK);
}

int
cmd_help_tab(mdb_tab_cookie_t *mcp, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	if (argc == 0 && !(flags & DCMD_TAB_SPACE))
		return (0);

	if (argc > 1)
		return (0);

	if (argc == 0)
		return (mdb_tab_complete_dcmd(mcp, NULL));
	else
		return (mdb_tab_complete_dcmd(mcp, argv[0].a_un.a_str));
}


static int
print_dcmd_def(mdb_var_t *v, void *private)
{
	mdb_idcmd_t *idcp = mdb_nv_get_cookie(mdb_nv_get_cookie(v));
	int *ip = private;

	mdb_printf("  [%d] %s`%s\n",
	    (*ip)++, idcp->idc_modp->mod_name, idcp->idc_name);

	return (0);
}

static int
print_walker_def(mdb_var_t *v, void *private)
{
	mdb_iwalker_t *iwp = mdb_nv_get_cookie(mdb_nv_get_cookie(v));
	int *ip = private;

	mdb_printf("  [%d] %s`%s\n",
	    (*ip)++, iwp->iwlk_modp->mod_name, iwp->iwlk_name);

	return (0);
}

/*ARGSUSED*/
int
cmd_which(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	const char defn_hdr[] = "   >  definition list:\n";
	uint_t opt_v = FALSE;
	int i;

	i = mdb_getopts(argc, argv, 'v', MDB_OPT_SETBITS, TRUE, &opt_v, NULL);

	for (; i < argc; i++) {
		const char *s = argv[i].a_un.a_str;
		int found = FALSE;
		mdb_iwalker_t *iwp;
		mdb_idcmd_t *idcp;
		const char *alias;

		if (argv->a_type != MDB_TYPE_STRING)
			continue;

		if (s[0] == '$' && s[1] == '<')
			s += 2;

		if ((idcp = mdb_dcmd_lookup(s)) != NULL) {
			mdb_var_t *v = idcp->idc_var;
			int i = 1;

			if (idcp->idc_modp != &mdb.m_rmod) {
				mdb_printf("%s is a dcmd from module %s\n",
				    s, idcp->idc_modp->mod_name);
			} else
				mdb_printf("%s is a built-in dcmd\n", s);

			if (opt_v) {
				mdb_printf(defn_hdr);
				mdb_nv_defn_iter(v, print_dcmd_def, &i);
			}
			found = TRUE;
		}

		if ((iwp = mdb_walker_lookup(s)) != NULL) {
			mdb_var_t *v = iwp->iwlk_var;
			int i = 1;

			if (iwp->iwlk_modp != &mdb.m_rmod) {
				mdb_printf("%s is a walker from module %s\n",
				    s, iwp->iwlk_modp->mod_name);
			} else
				mdb_printf("%s is a built-in walker\n", s);

			if (opt_v) {
				mdb_printf(defn_hdr);
				mdb_nv_defn_iter(v, print_walker_def, &i);
			}
			found = TRUE;
		}

		if ((alias = mdb_macalias_lookup(s)) != NULL) {
			mdb_printf("%s is a macro alias for '%s'\n", s, alias);
			found = TRUE;
		}

		if (!found)
			mdb_warn("%s not found\n", s);
	}

	return (DCMD_OK);
}
