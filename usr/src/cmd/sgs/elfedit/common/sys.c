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
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <strings.h>
#include <elfedit.h>
#include "_elfedit.h"
#include "msg.h"




/*
 * This file provides the builtin sys module. It is similar to the
 * other modules, but differs in several important ways:
 *
 *	- It is built as a static part of elfedit, and not
 *		as a sharable object.
 *	- It must be avaialble before the ELFCLASS of the object
 *		is known, so it is not ELFCLASS specific. We don't build
 *		it twice with <sys/machelf.h>, as we do for the loadable
 *		modules. This means that commands need to test for the type
 *		of their obj_state argument at runtime.
 *	- The init function signature is different. We build an entire
 *		module definition statically.
 */



/*
 * This function is supplied to elfedit through our elfedit_module_t
 * definition. It translates the opaque elfedit_i18nhdl_t handles
 * in our module interface into the actual strings for elfedit to
 * use.
 *
 * note:
 *	This module uses Msg codes for its i18n handle type.
 *	So the translation is simply to use MSG_INTL() to turn
 *	it into a string and return it.
 */
static const char *
mod_i18nhdl_to_str(elfedit_i18nhdl_t hdl)
{
	Msg msg = (Msg)hdl;

	return (MSG_INTL(msg));
}



/*
 * The sys_opt_t enum specifies a bit value for every optional argument
 * allowed by a command in this module.
 */
typedef enum {
	SYS_OPT_F_ALL =		1,	/* -a */
	SYS_OPT_F_FORCE =	2,	/* -f */
	SYS_OPT_F_SYNOPSIS =	4,	/* -s */
} dyn_opt_t;


/*
 * Given a generic (void *) pointer to an obj_state argument, determine
 * which type it is, and return the st_file, st_fd and st_elf fields.
 */
static void
get_obj_state_info(void *obj_state, const char **file, int *fd, Elf **elf)
{
	if (state.elf.elfclass == ELFCLASS32) {
		elfedit32_obj_state_t *s = (elfedit32_obj_state_t *)obj_state;

		*file = s->os_file;
		*fd = s->os_fd;
		*elf = s->os_elf;
	} else {
		elfedit64_obj_state_t *s = (elfedit64_obj_state_t *)obj_state;

		*file = s->os_file;
		*fd = s->os_fd;
		*elf = s->os_elf;
	}
}



/*
 * Helper for cmd_help(). Displays synopsis information for one command.
 */
static void
cmd_help_synopsis(elfeditGC_module_t *mod, elfeditGC_cmd_t *cmd)
{
	char		name_buf[128];
	const char	*name;
	const char	**cmd_name;

	if (cmd->cmd_name[1] == NULL) {   /* One name */
		name = *cmd->cmd_name;
	} else {
		const char *cname;
		int need_comma = 0;

		name = name_buf;
		(void) snprintf(name_buf, sizeof (name_buf),
		    MSG_ORIG(MSG_HLPFMT_MULTNAM), cmd->cmd_name[0]);
		for (cmd_name = cmd->cmd_name + 1;
		    *cmd_name; cmd_name++) {
			if (need_comma)
				(void) strlcat(name_buf,
				    MSG_ORIG(MSG_STR_COMMA_SP),
				    sizeof (name_buf));
			need_comma = 1;
			cname = (cmd_name[0][0] == '\0') ?
			    MSG_INTL(MSG_HLPFMT_MODDEFCMD) : *cmd_name;
			(void) strlcat(name_buf, cname,
			    sizeof (name_buf));
		}
		(void) strlcat(name_buf, MSG_ORIG(MSG_STR_CPAREN),
		    sizeof (name_buf));
	}
	elfedit_printf(MSG_ORIG(MSG_HLPFMT_NAMSUMHDR), name,
	    (* mod->mod_i18nhdl_to_str)(cmd->cmd_desc));
	elfedit_printf(MSG_INTL(MSG_HLPFMT_SUMSYNOPSIS),
	    elfedit_format_command_usage(mod, cmd,
	    MSG_ORIG(MSG_STR_HLPSUMINDENT),
	    strlen(MSG_ORIG(MSG_STR_HLPSUMINDENT))));
}


/*
 * Helper for cmd_help(). Displays synopsis information for one module.
 */
static void
cmd_help_showmod(elfeditGC_module_t *mod)
{
	elfeditGC_cmd_t	*cmd;

	elfedit_printf(MSG_ORIG(MSG_HLPFMT_NAMDSCHDR),
	    mod->mod_name, (* mod->mod_i18nhdl_to_str)(mod->mod_desc));
	for (cmd = mod->mod_cmds; cmd->cmd_func != NULL; cmd++) {
		if (cmd != mod->mod_cmds)
			elfedit_printf(MSG_ORIG(MSG_STR_NL));
		elfedit_printf(MSG_ORIG(MSG_STR_NL));
		cmd_help_synopsis(mod, cmd);
	}
}


/*
 * Given a string containing newline characters, break it into
 * individual lines, and output each line with the given
 * prefix string in front.
 */
static void
write_help_str(const char *str, const char *prefix)
{
	size_t i;

	if (str == NULL)
		return;
	while (*str) {
		i = strcspn(str, MSG_ORIG(MSG_STR_NL));
		if (*(str + i) != '\0')
			i++;
		elfedit_printf(prefix);
		elfedit_write(str, i);
		str += i;
	}
}


/*
 * Given a title, and a NULL terminated list of option/argument
 * descriptors, output the list contents.
 */
static void
write_optarg(elfeditGC_module_t *mod, const char *title,
    elfedit_cmd_optarg_t *optarg)
{
	int			cnt;
	int			len;
	const char		*help;
	elfedit_optarg_item_t	item;

	elfedit_printf(title);
	for (cnt = 0; optarg->oa_name != NULL; cnt++) {
		elfedit_next_optarg(&optarg, &item);

		/* Insert a blank line between items */
		if (cnt > 0)
			elfedit_printf(MSG_ORIG(MSG_STR_NL));

		/* Indentation */
		elfedit_printf(MSG_ORIG(MSG_STR_HLPINDENT));
		len = strlen(item.oai_name);
		help = elfedit_optarg_helpstr(mod, &item);
		if (item.oai_flags & ELFEDIT_CMDOA_F_VALUE) {
			len += 1 + strlen(item.oai_vname);
			elfedit_printf(MSG_ORIG(MSG_STR_HLPOPTARG2),
			    item.oai_name, item.oai_vname);
		} else {
			elfedit_printf(MSG_ORIG(MSG_STR_HLPOPTARG),
			    item.oai_name);
		}

		/*
		 * If name is too long, inject a newline to avoid
		 * crowding the help text.
		 */
		if (len > 3)
			elfedit_printf(MSG_ORIG(MSG_STR_NL));

		/* Output the help text with a tab prefix */
		write_help_str(help, MSG_ORIG(MSG_STR_TAB));
	}
}


/*
 * Implementation of sys:help
 */
/*ARGSUSED*/
static elfedit_cmdret_t
cmd_help(void *obj_state, int argc, const char *argv[])
{
#define	INITIAL_ITEM_ALLOC 4


	/*
	 * An array of this type is used to collect the data needed to
	 * generate help output.
	 */
	typedef struct {
		elfeditGC_cmd_t		*cmd;
		elfeditGC_module_t	*cmd_mod;	/* Used with cmd */
		elfeditGC_module_t	*mod;
	} ITEM;

	static ITEM	*item;
	static int	item_cnt;

	MODLIST_T		*modlist;
	int			dispcnt;
	size_t			i;
	elfeditGC_module_t	*mod;
	elfeditGC_cmd_t		*cmd;
	int			minus_s = 0;
	elfedit_getopt_state_t	getopt_state;
	ITEM			*cur_item;

	/*
	 * Process options. The only option accepted is -s, so we
	 * don't even have to check the idmask to know.
	 */
	elfedit_getopt_init(&getopt_state, &argc, &argv);
	while (elfedit_getopt(&getopt_state) != NULL)
		minus_s = 1;

	/*
	 * This command can produce an arbitrary amount of output, so
	 * run a pager.
	 */
	elfedit_pager_init();

	if (argc == 0) {
		if (minus_s) {
			/* Force all modules to load so we have data */
			elfedit_load_modpath();
			for (modlist = state.modlist; modlist;
			    modlist = modlist->ml_next) {
				cmd_help_showmod(modlist->ml_mod);
				if (modlist->ml_next != NULL) {
					elfedit_printf(MSG_ORIG(MSG_STR_NL));
					elfedit_printf(MSG_ORIG(MSG_STR_NL));
				}
			}
			return (ELFEDIT_CMDRET_NONE);
		}

		/*
		 * If no arguments are present, we display a simple
		 * "how to use help" tutorial, which will hopefully
		 * bootstrap the user into a position where they
		 * know how to run the help command, and then find
		 * what they're really after.
		 */
		elfedit_printf(MSG_INTL(MSG_SYS_HELP_HELP_NOARG));
		return (ELFEDIT_CMDRET_NONE);
	}


	/*
	 * As we process the arguments, we are willing to treat each
	 * one as either a module or a command:
	 *	1) An item without a colon can be a module,
	 *		or a command from the sys: module.
	 *	2) An item with a colon, and no command part is
	 *		a module, and it can also be the default
	 *		command for the module, if it has one. We choose
	 *		to only display the module info in this case, since
	 *		the use of "" to represent the default command is
	 *		an implementation detail, not a user-facing concept.
	 *	3) An item with a colon and a command part can only be
	 *		a command.
	 *
	 * Note that there are cases where one argument can have two
	 * valid interpretations. In this case, we display them both.
	 *
	 * Pass over the arguments and determine how many distinct
	 * "things" we need to display. At the same time, force any
	 * needed modules to load so that the debug load messages won't
	 * show up in between the displayed items, and save the command
	 * and module definitions we will need to generate the output.
	 */
	if (argc > item_cnt) {
		int n = (item_cnt == 0) ? INITIAL_ITEM_ALLOC : item_cnt;

		while (n < argc)
			n *= 2;

		item = elfedit_realloc(MSG_INTL(MSG_ALLOC_HELPITEM), item,
		    n * sizeof (*item));
		item_cnt = n;
	}

	dispcnt = 0;
	for (i = 0; i < argc; i++) {
		const char *colon = strchr(argv[i], ':');

		if (colon == NULL) {	/* No colon: sys: cmd or module */
			item[i].cmd =
			    elfedit_find_command(argv[i], 0, &item[i].cmd_mod);
			if (item[i].cmd != NULL)
				dispcnt++;

			/*
			 * Also try to load it as a module. If a command
			 * was found, then this need not succeed. Otherwise,
			 * it has to be a module, and we cause an error
			 * to be issued if not.
			 */
			item[i].mod = elfedit_load_module(argv[i],
			    item[i].cmd == NULL, 0);
			if (item[i].mod != NULL)
				dispcnt++;
		} else if (*(colon + 1) == '\0') {
			/* Just colon: Module (and maybe default command) */
			char buf[ELFEDIT_MAXMODNAM + 1];
			const char *str = argv[i];
			int len = colon - str;

			item[i].cmd = NULL;
			/* Strip off the colon */
			if (len < sizeof (buf)) {
				(void) strncpy(buf, str, len);
				buf[len] = '\0';
				str = buf;
			}
			item[i].mod = elfedit_load_module(str, 1, 0);
			dispcnt++;
		} else {	/* A command */
			item[i].cmd =
			    elfedit_find_command(argv[i], 1, &item[i].cmd_mod);
			dispcnt++;
			item[i].mod = NULL;
		}
	}

	/*
	 * Having validated the items, loop over them again and produce
	 * the required help output.
	 */
	for (cur_item = item; argc--; argv++, cur_item++) {


		/* Help for a module? */
		if (cur_item->mod != NULL) {
			if (dispcnt > 1)
				elfedit_printf(MSG_ORIG(MSG_HLPFMT_MULTIHDR),
				    *argv);
			cmd_help_showmod(cur_item->mod);
			if ((dispcnt > 1) && (argc > 0))
				elfedit_printf(MSG_INTL(MSG_HLPFMT_MULTIEND),
				    argv[0], argv[1]);
			/* An empty line after the last line of output */
			elfedit_printf(MSG_ORIG(MSG_STR_NL));
		}

		/* Help for a command? */
		if (cur_item->cmd == NULL)
			continue;
		cmd = cur_item->cmd;
		mod = cur_item->cmd_mod;
		if (dispcnt > 1)
			elfedit_printf(MSG_ORIG(MSG_HLPFMT_MULTIHDR), *argv);

		/* If -s, display quick synopsis rather than the whole thing */
		if (minus_s) {
			cmd_help_synopsis(mod, cmd);
			continue;
		}

		elfedit_printf(MSG_INTL(MSG_HLPFMT_MOD), mod->mod_name,
		    (* mod->mod_i18nhdl_to_str)(mod->mod_desc));
		elfedit_printf(MSG_INTL(MSG_HLPFMT_NAME),
		    *cmd->cmd_name,
		    (* mod->mod_i18nhdl_to_str)(cmd->cmd_desc));
		elfedit_printf(MSG_INTL(MSG_HLPFMT_SYNOPSIS),
		    elfedit_format_command_usage(mod, cmd,
		    MSG_ORIG(MSG_STR_HLPUSEINDENT),
		    strlen(MSG_ORIG(MSG_STR_HLPINDENT))));
		/* If there are alias names, show them */
		if (cmd->cmd_name[1] != NULL) {
			const char **alias = cmd->cmd_name + 1;

			elfedit_printf(MSG_INTL(MSG_HLPFMT_ALIASES));
			do {
				elfedit_printf(
				    MSG_ORIG(MSG_STR_HLPINDENT));
				elfedit_printf(
				    MSG_ORIG(MSG_FMT_MODCMD),
				    mod->mod_name, *alias);
				if (**alias == '\0')
					elfedit_printf(
					    MSG_INTL(MSG_HLPFMT_DEFCMD));
				elfedit_printf(MSG_ORIG(MSG_STR_NL));
				alias++;
			} while (*alias);
		}
		elfedit_printf(MSG_INTL(MSG_HLPFMT_DESC));
		write_help_str(
		    (* mod->mod_i18nhdl_to_str)(cmd->cmd_help),
		    MSG_ORIG(MSG_STR_HLPINDENT));
		if (cmd->cmd_args != NULL)
			write_optarg(mod, MSG_INTL(MSG_HLPFMT_ARGS),
			    cmd->cmd_args);
		if (cmd->cmd_opt != NULL)
			write_optarg(mod, MSG_INTL(MSG_HLPFMT_OPT),
			    cmd->cmd_opt);
		if ((dispcnt > 1) && (argc > 0))
			elfedit_printf(MSG_INTL(MSG_HLPFMT_MULTIEND),
			    argv[0], argv[1]);
		/* An empty line after the last line of output */
		elfedit_printf(MSG_ORIG(MSG_STR_NL));
	}

	return (ELFEDIT_CMDRET_NONE);

#undef	INITIAL_ITEM_ALLOC
}


/*
 * Command completion function for sys:help
 */
/*ARGSUSED*/
static void
cpl_help(void *obj_state, void *cpldata, int argc, const char *argv[],
    int num_opt)
{
	/*
	 * The arguments can be any module or command. Supplying the
	 * commands implicitly supplies the modules too.
	 */
	elfedit_cpl_command(cpldata);
}


/*
 * Implementation of sys:load
 */
/*ARGSUSED*/
static elfedit_cmdret_t
cmd_load(void *obj_state, int argc, const char *argv[])
{
	elfedit_getopt_state_t	getopt_state;
	elfedit_getopt_ret_t	*getopt_ret;
	struct stat		statbuf;

	elfedit_getopt_init(&getopt_state, &argc, &argv);
	while ((getopt_ret = elfedit_getopt(&getopt_state)) != NULL) {
		switch (getopt_ret->gor_idmask) {
		case SYS_OPT_F_ALL:
			elfedit_load_modpath();
			break;
		}
	}

	/* For each remaining argument, load them individually */
	for (; argc-- > 0; argv++) {
		/* Is it a directory? Load everything in it */
		if ((stat(*argv, &statbuf) == 0) &&
		    (statbuf.st_mode & S_IFDIR)) {
			elfedit_load_moddir(*argv, 1, 1);
		} else {	/* Not a directory. Normal load */
			(void) elfedit_load_module(*argv, 1, 1);
		}
	}

	return (0);
}


/*
 * Command completion function for sys:load
 */
/*ARGSUSED*/
static void
cpl_load(void *obj_state, void *cpldata, int argc, const char *argv[],
    int num_opt)
{
	/*
	 * Module names. Note that this causes elfedit to load all
	 * of the modules, which probably makes the current load
	 * operation unnecessary. This could be improved, but I don't
	 * see it as worth the complexity. Explicit load calls are
	 * rare, and the user will usually not use command completion.
	 */
	elfedit_cpl_module(cpldata, 1);
}


/*
 * Implementation of sys:quit
 */
/*ARGSUSED*/
static elfedit_cmdret_t
cmd_quit(void *obj_state, int argc, const char *argv[])
{
	elfedit_getopt_state_t	getopt_state;
	elfedit_getopt_ret_t	*getopt_ret;
	int			force = 0;
	const char		*file;
	int			fd;
	Elf			*elf;

	elfedit_getopt_init(&getopt_state, &argc, &argv);
	while ((getopt_ret = elfedit_getopt(&getopt_state)) != NULL) {
		switch (getopt_ret->gor_idmask) {
		case SYS_OPT_F_FORCE:
			force = 1;
			break;
		}
	}
	if (argc != 0)
		elfedit_command_usage();

	if (state.file.present) {
		/*
		 * If session is not READONLY, then refuse to quit if file
		 * needs flushing and -f option was not used.
		 */
		if (!(state.flags & ELFEDIT_F_READONLY) && state.file.dirty &&
		    !force)
			elfedit_msg(ELFEDIT_MSG_ERR,
			    MSG_INTL(MSG_ERR_NODIRTYQUIT));

		get_obj_state_info(obj_state, &file, &fd, &elf);
		(void) close(fd);
		(void) elf_end(elf);
		free(obj_state);
	}

	elfedit_exit(0);
	/*NOTREACHED*/
	return (0);
}


/*
 * Implementation of sys:status
 */
/*ARGSUSED*/
static elfedit_cmdret_t
cmd_status(void *obj_state, int argc, const char *argv[])
{
	MODLIST_T	*modlist;
	const char	*s;
	size_t		i;

	if (argc > 0)
		elfedit_command_usage();

	/*
	 * This command can produce an arbitrary amount of output, so
	 * run a pager.
	 */
	elfedit_pager_init();

	/* Files */
	if (state.file.present == 0) {
		elfedit_printf(MSG_INTL(MSG_HLPFMT_INFILENONE));
	} else if (state.flags & ELFEDIT_F_READONLY) {
		elfedit_printf(MSG_INTL(MSG_HLPFMT_INFILERO),
		    state.file.infile);
	} else {
		elfedit_printf(MSG_INTL(MSG_HLPFMT_INFILE), state.file.infile);
		elfedit_printf(MSG_INTL(MSG_HLPFMT_OUTFILE),
		    state.file.outfile);
	}
	if (state.file.dirty)
		elfedit_printf(MSG_INTL(MSG_HLPFMT_CNGPENDING));

	/* Option Variables */
	elfedit_printf(MSG_INTL(MSG_HLPFMT_VARHDR));
	elfedit_printf(MSG_INTL(MSG_HLPFMT_AFLG),
	    (state.flags & ELFEDIT_F_AUTOPRINT) ? MSG_ORIG(MSG_STR_ON) :
	    MSG_ORIG(MSG_STR_OFF));
	elfedit_printf(MSG_INTL(MSG_HLPFMT_DFLG),
	    (state.flags & ELFEDIT_F_DEBUG) ? MSG_ORIG(MSG_STR_ON) :
	    MSG_ORIG(MSG_STR_OFF));
	elfedit_printf(MSG_INTL(MSG_HLPFMT_OFLG),
	    elfedit_atoconst_value_to_str(ELFEDIT_CONST_OUTSTYLE,
	    state.outstyle, 1));

	/* Module Load Path */
	elfedit_printf(MSG_INTL(MSG_HLPFMT_PATHHDR));
	for (i = 0; i < state.modpath.n; i++)
		elfedit_printf(MSG_ORIG(MSG_HLPFMT_PATHELT),
		    state.modpath.seg[i]);

	/* Currently Loaded Modules */
	elfedit_printf(MSG_INTL(MSG_HLPFMT_MODHDR));
	for (modlist = state.modlist; modlist;
	    modlist = modlist->ml_next) {
		s = modlist->ml_path ? modlist->ml_path :
		    MSG_INTL(MSG_FMT_BUILTIN);
		elfedit_printf(MSG_ORIG(MSG_HLPFMT_NAMDSCCOL),
		    modlist->ml_mod->mod_name, s);
	}

	return (ELFEDIT_CMDRET_NONE);
}

/*
 * Implementation of sys:set
 */
/*ARGSUSED*/
static elfedit_cmdret_t
cmd_set(void *obj_state, int argc, const char *argv[])
{
	if ((argc != 2) || (strlen(argv[0]) > 1))
		elfedit_command_usage();

	switch (**argv) {
	case 'a':
	case 'A':
		if (elfedit_atobool(argv[1], MSG_INTL(MSG_SYSSET_A)))
			state.flags |= ELFEDIT_F_AUTOPRINT;
		else
			state.flags &= ~ELFEDIT_F_AUTOPRINT;
		break;

	case 'd':
	case 'D':
		if (elfedit_atobool(argv[1], MSG_INTL(MSG_SYSSET_D)))
			state.flags |= ELFEDIT_F_DEBUG;
		else
			state.flags &= ~ELFEDIT_F_DEBUG;
		break;

	case 'o':
	case 'O':
		if (elfedit_atooutstyle(argv[1], &state.outstyle) == 0)
			elfedit_msg(ELFEDIT_MSG_ERR,
			    MSG_INTL(MSG_ERR_BADOSTYLE), argv[1]);
		break;

	default:
		elfedit_command_usage();
	}

	return (0);
}


/*
 * Command completion function for sys:set
 */
/*ARGSUSED*/
static void
cpl_set(void *obj_state, void *cpldata, int argc, const char *argv[],
    int num_opt)
{
	const char *s;

	/*
	 * This command doesn't accept options, so num_opt should be
	 * 0. This is a defensive measure, in case that should change.
	 */
	argc -= num_opt;
	argv += num_opt;

	if ((argc < 1) || (argc > 2))
		return;

	if (argc == 1) {	/* The first argument is a variable letter */
		elfedit_cpl_match(cpldata, MSG_ORIG(MSG_STR_A), 1);
		elfedit_cpl_match(cpldata, MSG_ORIG(MSG_STR_D), 1);
		elfedit_cpl_match(cpldata, MSG_ORIG(MSG_STR_O), 1);
		elfedit_cpl_match(cpldata, MSG_ORIG(MSG_STR_W), 1);
		return;
	}

	/* We're dealing with the second argument, the value */
	s = argv[0];
	if (strlen(s) > 1)	/* One letter variables */
		return;
	switch (*s) {
	case 'a':		/* Booleans */
	case 'A':
	case 'd':
	case 'D':
	case 'w':
	case 'W':
		/* The second argument is a boolean */
		elfedit_cpl_atoconst(cpldata, ELFEDIT_CONST_BOOL);

		/* The numbers are not symbolic, but we want them in the list */
		elfedit_cpl_match(cpldata, MSG_ORIG(MSG_STR_0), 1);
		elfedit_cpl_match(cpldata, MSG_ORIG(MSG_STR_1), 1);
		break;

	case 'o':		/* Output style */
	case 'O':
		elfedit_cpl_atoconst(cpldata, ELFEDIT_CONST_OUTSTYLE);
		break;
	}
}


/*
 * Implementation of sys:unload
 */
/*ARGSUSED*/
static elfedit_cmdret_t
cmd_unload(void *obj_state, int argc, const char *argv[])
{
	elfedit_getopt_state_t	getopt_state;
	elfedit_getopt_ret_t	*getopt_ret;
	MODLIST_T		*moddef;
	int			do_all = 0;

	elfedit_getopt_init(&getopt_state, &argc, &argv);
	while ((getopt_ret = elfedit_getopt(&getopt_state)) != NULL) {
		switch (getopt_ret->gor_idmask) {
		case SYS_OPT_F_ALL:
			do_all = 1;
			break;
		}
	}

	/*
	 * If -a is specified, unload everything except builtins. Don't
	 * allow plain arguments in this case because there is nothing
	 * left to unload after -a.
	 */
	if (do_all) {
		if (argc > 0)
			elfedit_command_usage();
		/*
		 * Until we run out of non-builtin modules, take the first
		 * one from the list and unload it. Each removal alters
		 * the list, so we always start at the beginning, but this
		 * is efficient since we always remove the first available item
		 */
		while (state.modlist != NULL) {
			for (moddef = state.modlist; moddef != NULL;
			    moddef = moddef->ml_next)
				if (moddef->ml_dl_hdl != NULL) break;

			/* If we made it to the end, then the list is empty */
			if (moddef == NULL)
				break;

			elfedit_unload_module(moddef->ml_mod->mod_name);
		}
		return (0);
	}

	/* Unload each module individually */
	for (; argc-- > 0; argv++)
		elfedit_unload_module(*argv);

	return (0);
}


/*
 * Command completion function for sys:unload
 */
/*ARGSUSED*/
static void
cpl_unload(void *obj_state, void *cpldata, int argc, const char *argv[],
    int num_opt)
{
	/*
	 * Module names. Don't allow elfedit to load all the modules,
	 * as the only modules we want to unload are those already
	 * in memory.
	 */
	elfedit_cpl_module(cpldata, 0);
}


/*
 * Implementation of sys:write
 */
/*ARGSUSED2*/
static elfedit_cmdret_t
cmd_write(void *obj_state, int argc, const char *argv[])
{
	const char	*file;
	int		fd;
	Elf		*elf;

	if (argc != 0)
		elfedit_command_usage();

	if (state.file.present != 0) {
		if (state.flags & ELFEDIT_F_READONLY)
			elfedit_msg(ELFEDIT_MSG_ERR,
			    MSG_INTL(MSG_ERR_READONLY));

		get_obj_state_info(obj_state, &file, &fd, &elf);
		if (elf_update(elf, ELF_C_WRITE) == -1)
			elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_LIBELF),
			    file, MSG_ORIG(MSG_ELF_UPDATE),
			    elf_errmsg(elf_errno()));

		/*
		 * An update has succeeded for this file, so revoke the need
		 * to unlink it on exit.
		 */
		state.file.unlink_on_exit = 0;
	}

	return (ELFEDIT_CMDRET_FLUSH);
}





/*ARGSUSED*/
MODLIST_T *
elfedit_sys_init(elfedit_module_version_t version)
{
	/* sys:help */
	static const char *name_help[] = { MSG_ORIG(MSG_SYS_CMD_HELP),
	    MSG_ORIG(MSG_SYS_CMD_HELP_A1), MSG_ORIG(MSG_SYS_CMD_HELP_A2),
	    NULL };
	static elfedit_cmd_optarg_t opt_help[] = {
		{ MSG_ORIG(MSG_STR_MINUS_S),
		    /* MSG_INTL(MSG_SYS_OPTDESC_HELP_S) */
		    ELFEDIT_I18NHDL(MSG_SYS_OPTDESC_HELP_S), 0,
		    SYS_OPT_F_SYNOPSIS, 0 },
		{ NULL }
	};
	static elfedit_cmd_optarg_t arg_help[] = {
		{ MSG_ORIG(MSG_STR_ARG),
		    /* MSG_INTL(MSG_ARGDESC_HELP_ARG) */
		    ELFEDIT_I18NHDL(MSG_ARGDESC_HELP_ARG),
		    ELFEDIT_CMDOA_F_OPT | ELFEDIT_CMDOA_F_MULT },
		{ NULL }
	};

	/* sys:load */
	static const char *name_load[] = {
	    MSG_ORIG(MSG_SYS_CMD_LOAD), NULL };
	static elfedit_cmd_optarg_t opt_load[] = {
		{ MSG_ORIG(MSG_STR_MINUS_A),
		    /* MSG_INTL(MSG_SYS_OPTDESC_LOAD_A) */
		    ELFEDIT_I18NHDL(MSG_SYS_OPTDESC_LOAD_A), 0,
		    SYS_OPT_F_ALL, 0 },
		{ NULL }
	};
	static elfedit_cmd_optarg_t arg_load[] = {
		{ MSG_ORIG(MSG_STR_MODNAME),
		    /* MSG_INTL(MSG_ARGDESC_LOAD_MODNAME) */
		    ELFEDIT_I18NHDL(MSG_ARGDESC_LOAD_MODNAME),
		    ELFEDIT_CMDOA_F_OPT | ELFEDIT_CMDOA_F_MULT },
		{ NULL }
	};

	/* sys:quit */
	static const char *name_quit[] = { MSG_ORIG(MSG_SYS_CMD_QUIT),
	    MSG_ORIG(MSG_SYS_CMD_QUIT_A1), MSG_ORIG(MSG_SYS_CMD_QUIT_A2),
	    NULL };
	static elfedit_cmd_optarg_t opt_quit[] = {
		{ MSG_ORIG(MSG_STR_MINUS_F),
		    /* MSG_INTL(MSG_SYS_OPTDESC_QUIT_F) */
		    ELFEDIT_I18NHDL(MSG_SYS_OPTDESC_QUIT_F), 0,
		    SYS_OPT_F_FORCE, 0 },
		{ NULL }
	};

	/* sys:status */
	static const char *name_status[] = {
	    MSG_ORIG(MSG_SYS_CMD_STATUS), NULL };

	/* sys:set */
	static const char *name_set[] = {
	    MSG_ORIG(MSG_SYS_CMD_SET), NULL };
	static elfedit_cmd_optarg_t arg_set[] = {
		{ MSG_ORIG(MSG_STR_OPTION),
		    /* MSG_INTL(MSG_ARGDESC_SET_OPTION) */
		    ELFEDIT_I18NHDL(MSG_ARGDESC_SET_OPTION), 0 },
		{ MSG_ORIG(MSG_STR_VALUE),
		    /* MSG_INTL(MSG_ARGDESC_SET_VALUE) */
		    ELFEDIT_I18NHDL(MSG_ARGDESC_SET_VALUE), 0 },
		{ NULL }
	};

	/* sys:unload */
	static const char *name_unload[] = {
	    MSG_ORIG(MSG_SYS_CMD_UNLOAD), NULL };
	static elfedit_cmd_optarg_t opt_unload[] = {
		{ MSG_ORIG(MSG_STR_MINUS_A),
		    /* MSG_INTL(MSG_SYS_OPTDESC_UNLOAD_A) */
		    ELFEDIT_I18NHDL(MSG_SYS_OPTDESC_UNLOAD_A), 0,
		    SYS_OPT_F_ALL, 0},
		{ NULL }
	};
	static elfedit_cmd_optarg_t arg_unload[] = {
		{ MSG_ORIG(MSG_STR_MODNAME),
		    /* MSG_INTL(MSG_ARGDESC_UNLOAD_MODNAME) */
		    ELFEDIT_I18NHDL(MSG_ARGDESC_UNLOAD_MODNAME),
		    ELFEDIT_CMDOA_F_OPT | ELFEDIT_CMDOA_F_MULT },
		{ NULL }
	};

	/* sys:write */
	static const char *name_write[] = { MSG_ORIG(MSG_SYS_CMD_WRITE),
	    MSG_ORIG(MSG_SYS_CMD_WRITE_A1), MSG_ORIG(MSG_SYS_CMD_WRITE_A2),
	    NULL };

	static elfedit_cmd_t cmds[] = {
		/* sym:help */
		{ (elfedit_cmd_func_t *)cmd_help,
		    (elfedit_cmdcpl_func_t *)cpl_help, name_help,
		    /* MSG_INTL(MSG_SYS_DESC_HELP) */
		    ELFEDIT_I18NHDL(MSG_SYS_DESC_HELP),
		    /* MSG_INTL(MSG_SYS_HELP_HELP) */
		    ELFEDIT_I18NHDL(MSG_SYS_HELP_HELP),
		    opt_help, arg_help },

		/* sym:load */
		{ (elfedit_cmd_func_t *)cmd_load,
		    (elfedit_cmdcpl_func_t *)cpl_load, name_load,
		    /* MSG_INTL(MSG_SYS_DESC_LOAD) */
		    ELFEDIT_I18NHDL(MSG_SYS_DESC_LOAD),
		    /* MSG_INTL(MSG_SYS_HELP_LOAD) */
		    ELFEDIT_I18NHDL(MSG_SYS_HELP_LOAD),
		    opt_load, arg_load },

		/* sym:quit */
		{ (elfedit_cmd_func_t *)cmd_quit, NULL, name_quit,
		    /* MSG_INTL(MSG_SYS_DESC_QUIT) */
		    ELFEDIT_I18NHDL(MSG_SYS_DESC_QUIT),
		    /* MSG_INTL(MSG_SYS_HELP_QUIT) */
		    ELFEDIT_I18NHDL(MSG_SYS_HELP_QUIT),
		    opt_quit, NULL },

		/* sym:status */
		{ (elfedit_cmd_func_t *)cmd_status, NULL, name_status,
		    /* MSG_INTL(MSG_SYS_DESC_STATUS) */
		    ELFEDIT_I18NHDL(MSG_SYS_DESC_STATUS),
		    /* MSG_INTL(MSG_SYS_HELP_STATUS) */
		    ELFEDIT_I18NHDL(MSG_SYS_HELP_STATUS),
		    NULL, NULL },

		/* sym:set */
		{ (elfedit_cmd_func_t *)cmd_set,
		    (elfedit_cmdcpl_func_t *)cpl_set, name_set,
		    /* MSG_INTL(MSG_SYS_DESC_SET) */
		    ELFEDIT_I18NHDL(MSG_SYS_DESC_SET),
		    /* MSG_INTL(MSG_SYS_HELP_SET) */
		    ELFEDIT_I18NHDL(MSG_SYS_HELP_SET),
		    NULL, arg_set },

		/* sym:unload */
		{ (elfedit_cmd_func_t *)cmd_unload,
		    (elfedit_cmdcpl_func_t *)cpl_unload, name_unload,
		    /* MSG_INTL(MSG_SYS_DESC_UNLOAD) */
		    ELFEDIT_I18NHDL(MSG_SYS_DESC_UNLOAD),
		    /* MSG_INTL(MSG_SYS_HELP_UNLOAD) */
		    ELFEDIT_I18NHDL(MSG_SYS_HELP_UNLOAD),
		    opt_unload, arg_unload },

		/* sym:write */
		{ (elfedit_cmd_func_t *)cmd_write, NULL, name_write,
		    /* MSG_INTL(MSG_SYS_DESC_WRITE) */
		    ELFEDIT_I18NHDL(MSG_SYS_DESC_WRITE),
		    /* MSG_INTL(MSG_SYS_HELP_WRITE) */
		    ELFEDIT_I18NHDL(MSG_SYS_HELP_WRITE),
		    NULL, NULL},

		{ NULL }
	};

	static elfedit_module_t module = {
	    ELFEDIT_VER_CURRENT, MSG_ORIG(MSG_MOD_SYS),
	    /* MSG_INTL(MSG_MOD_SYS_DESC) */
	    ELFEDIT_I18NHDL(MSG_MOD_SYS_DESC),
	    cmds, mod_i18nhdl_to_str };

	static MODLIST_T moddef = {
		NULL,		/* next */
		(elfeditGC_module_t *)&module,	/* Module definition */
		NULL,		/* Didn't dlopen() it, so NULL handle */
		NULL		/* Didn't dlopen() it, so no file path */
	};

	return (&moddef);
}
