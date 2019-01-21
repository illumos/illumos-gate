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

#include	<stdio.h>
#include	<unistd.h>
#include	<elfedit.h>
#include	<strings.h>
#include	<debug.h>
#include	<conv.h>
#include	<syminfo_msg.h>



/*
 * This module uses shared code for several of the commands.
 * It is sometimes necessary to know which specific command
 * is active.
 */
typedef enum {
	SYMINFO_CMD_T_DUMP =		0,	/* syminfo:dump */

	SYMINFO_CMD_T_SI_BOUNDTO =	1,	/* syminfo:si_boundto */
	SYMINFO_CMD_T_SI_FLAGS =	2	/* syminfo:si_boundto */
} SYMINFO_CMD_T;



#ifndef _ELF64
/*
 * We supply this function for the msg module. Only one copy is needed.
 */
const char *
_syminfo_msg(Msg mid)
{
	return (gettext(MSG_ORIG(mid)));
}

#endif



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
 * The sym_opt_t enum specifies a bit value for every optional
 * argument allowed by a command in this module.
 */
typedef enum {
	SYMINFO_OPT_F_AND =	1,	/* -and: AND (&) values to dest */
	SYMINFO_OPT_F_CMP =	2,	/* -cmp: Complement (~) values */
	SYMINFO_OPT_F_NEEDED =	4,	/* -needed: arg is name of object to */
					/*	be referenced via DT_NEEDED */
					/*	dynamic entry */
	SYMINFO_OPT_F_OR =	8,	/* -or: OR (|) values to dest */
	SYMINFO_OPT_F_SYMNDX =	16	/* -symndx: Sym specified by index */
} syminfo_opt_t;


/*
 * A variable of type ARGSTATE is used by each command to maintain
 * information about the syminfo section being used, as and for any
 * auxiliary sections that are related to it. This helps us to ensure
 * that we only fetch each section a single time:
 *	- More efficient
 *	- Prevents multiple ELFEDIT_MSG_DEBUG messages from
 *	  being produced for a given section.
 */
typedef struct {
	elfedit_obj_state_t	*obj_state;
	syminfo_opt_t		optmask;	/* Mask of options used */
	int			argc;		/* # of plain arguments */
	const char		**argv;		/* Plain arguments */
	struct {				/* Syminfo */
		elfedit_section_t	*sec;
		Syminfo			*data;
		Word			n;
	} syminfo;
	struct {				/* Symbol table */
		elfedit_section_t	*sec;
		Sym			*data;
		Word			n;
	} sym;
	struct {				/* String table */
		elfedit_section_t	*sec;
	} str;
	struct {				/* Dynamic section */
		elfedit_section_t	*sec;
		Dyn			*data;
		Word			n;
	} dynamic;
} ARGSTATE;



/*
 * Standard argument processing for syminfo module
 *
 * entry
 *	obj_state, argc, argv - Standard command arguments
 *	optmask - Mask of allowed optional arguments.
 *	argstate - Address of ARGSTATE block to be initialized
 *
 * exit:
 *	On success, *argstate is initialized. On error,
 *	an error is issued and this routine does not return.
 *
 * note:
 *	Only the syminfo section is initially referenced by
 *	argstate. Use the argstate_add_XXX() routines below to
 *	access any other sections needed.
 */
static void
process_args(elfedit_obj_state_t *obj_state, int argc, const char *argv[],
    SYMINFO_CMD_T cmd, ARGSTATE *argstate)
{
	elfedit_getopt_state_t	getopt_state;
	elfedit_getopt_ret_t	*getopt_ret;

	bzero(argstate, sizeof (*argstate));
	argstate->obj_state = obj_state;

	elfedit_getopt_init(&getopt_state, &argc, &argv);

	/* Add each new option to the options mask */
	while ((getopt_ret = elfedit_getopt(&getopt_state)) != NULL)
		argstate->optmask |= getopt_ret->gor_idmask;

	/*
	 * Usage error if there are too many plain arguments.
	 *	- syminfo:dump accepts a single argument
	 *	- syminfo:si_boundto accepts 2 arguments
	 *	- syminfo:si_flags accepts an unbounded number
	 */
	if (((cmd == SYMINFO_CMD_T_DUMP) && (argc > 1)) ||
	    ((cmd == SYMINFO_CMD_T_SI_BOUNDTO) && (argc > 2)))
		elfedit_command_usage();

	/* If there may be an arbitrary amount of output, use a pager */
	if (argc == 0)
		elfedit_pager_init();

	/* Return the updated values of argc/argv */
	argstate->argc = argc;
	argstate->argv = argv;

	/* Locate the syminfo section */
	argstate->syminfo.sec = elfedit_sec_getsyminfo(obj_state,
	    &argstate->syminfo.data, &argstate->syminfo.n);
}



/*
 * We maintain the state of the current syminfo table in a ARGSTATE
 * structure. A syminfo is related to the dynamic symbol table, and
 * can reference the dynamic section of the object. We don't look those
 * things up unless we actually need them, both to be efficient, and
 * to prevent duplicate ELFEDIT_MSG_DEBUG messages from being issued
 * as they are located. Hence, process_args() is used to initialze the
 * state block with just the syminfo section, and then one of the
 * argstate_add_XXX() functions is used as needed to fetch the
 * additional sections.
 *
 * entry:
 *	argstate - State block for current symbol table.
 *
 * exit:
 *	If the needed auxiliary section is not found, an error is
 *	issued and the argstate_add_XXX() routine does not return.
 *	Otherwise, the fields in argstate have been filled in, ready
 *	for use.
 *
 */
static void
argstate_add_sym(ARGSTATE *argstate)
{
	if (argstate->sym.sec != NULL)
		return;

	argstate->sym.sec = elfedit_sec_getsymtab(argstate->obj_state,
	    1, argstate->syminfo.sec->sec_shdr->sh_link, NULL,
	    &argstate->sym.data, &argstate->sym.n, NULL);
}
static void
argstate_add_str(ARGSTATE *argstate)
{
	if (argstate->str.sec != NULL)
		return;

	argstate_add_sym(argstate);
	argstate->str.sec = elfedit_sec_getstr(argstate->obj_state,
	    argstate->sym.sec->sec_shdr->sh_link, 0);
}
static void
argstate_add_dynamic(ARGSTATE *argstate)
{
	if (argstate->dynamic.sec != NULL)
		return;

	argstate->dynamic.sec = elfedit_sec_getdyn(argstate->obj_state,
	    &argstate->dynamic.data, &argstate->dynamic.n);
}



/*
 * Display syminfo section entries in the style used by elfdump.
 *
 * entry:
 *	argstate - State block for current symbol table.
 *	ndx - Index of first symbol to display
 *	cnt - Number of symbols to display
 */
static void
dump_syminfo(ARGSTATE *argstate, Word ndx, Word cnt)
{
	Syminfo			*syminfo;
	Sym			*sym;
	Dyn			*dyn;

	syminfo = argstate->syminfo.data + ndx;

	argstate_add_sym(argstate);
	sym = argstate->sym.data + ndx;

	argstate_add_str(argstate);

	argstate_add_dynamic(argstate);
	dyn = argstate->dynamic.data;

	/*
	 * Loop through the syminfo entries.
	 */
	Elf_syminfo_title(0);

	for (; cnt-- > 0; ndx++, syminfo++, sym++) {
		const char	*needed = NULL, *name;

		name = elfedit_offset_to_str(argstate->str.sec,
		    sym->st_name, ELFEDIT_MSG_ERR, 0);

		if ((syminfo->si_boundto < SYMINFO_BT_LOWRESERVE) &&
		    (syminfo->si_boundto < argstate->dynamic.n) &&
		    ((dyn[syminfo->si_boundto].d_tag == DT_NEEDED) ||
		    (dyn[syminfo->si_boundto].d_tag == DT_USED)))
			needed = elfedit_offset_to_str(argstate->str.sec,
			    dyn[syminfo->si_boundto].d_un.d_val,
			    ELFEDIT_MSG_ERR, 0);
		else
			needed = MSG_ORIG(MSG_STR_EMPTY);

		Elf_syminfo_entry(0, ndx, syminfo, name, needed);
	}
}



/*
 * Print syminfo values, taking the calling command, and output style
 * into account.
 *
 * entry:
 *	cmd - SYMINFO_CMD_T_* value giving identify of caller
 *	autoprint - If True, output is only produced if the elfedit
 *		autoprint flag is set. If False, output is always produced.
 *	argstate - State block for current symbol table.
 *	ndx - Index of first symbol to display
 *	cnt - Number of symbols to display
 */
static void
print_syminfo(SYMINFO_CMD_T cmd, int autoprint, ARGSTATE *argstate,
    Word ndx, Word cnt)
{
	elfedit_outstyle_t	outstyle;
	Syminfo			*syminfo;

	if ((autoprint && ((elfedit_flags() & ELFEDIT_F_AUTOPRINT) == 0)) ||
	    (cnt == 0))
		return;

	/*
	 * Pick an output style. syminfo:dump is required to use the default
	 * style. The other commands use the current output style.
	 */
	outstyle = (cmd == SYMINFO_CMD_T_DUMP) ?
	    ELFEDIT_OUTSTYLE_DEFAULT : elfedit_outstyle();

	/*
	 * If doing default output, use elfdump style where we
	 * show all symbol attributes. In this case, the command
	 * that called us doesn't matter
	 */
	if (outstyle == ELFEDIT_OUTSTYLE_DEFAULT) {
		dump_syminfo(argstate, ndx, cnt);
		return;
	}

	syminfo = argstate->syminfo.data;

	switch (cmd) {
	case SYMINFO_CMD_T_SI_BOUNDTO:
		if (outstyle == ELFEDIT_OUTSTYLE_SIMPLE) {
			/* Find the dynamic section and string table */
			argstate_add_dynamic(argstate);
			argstate_add_str(argstate);
		}

		for (syminfo += ndx; cnt--; syminfo++) {
			Half bndto = syminfo->si_boundto;

			if (outstyle == ELFEDIT_OUTSTYLE_SIMPLE) {
				const char	*str = NULL;

				switch (bndto) {
				case SYMINFO_BT_SELF:
					str = elfedit_atoconst_value_to_str(
					    ELFEDIT_CONST_SYMINFO_BT,
					    SYMINFO_BT_SELF, 1);
					break;
				case SYMINFO_BT_PARENT:
					str = elfedit_atoconst_value_to_str(
					    ELFEDIT_CONST_SYMINFO_BT,
					    SYMINFO_BT_PARENT, 1);
					break;
				case SYMINFO_BT_NONE:
					str = elfedit_atoconst_value_to_str(
					    ELFEDIT_CONST_SYMINFO_BT,
					    SYMINFO_BT_NONE, 1);
					break;
				}
				if ((str == NULL) &&
				    (bndto < SYMINFO_BT_LOWRESERVE) &&
				    (argstate->dynamic.sec != NULL) &&
				    (bndto < argstate->dynamic.n) &&
				    (argstate->dynamic.data[bndto].d_tag ==
				    DT_NEEDED))
					str = elfedit_offset_to_str(
					    argstate->str.sec,
					    argstate->dynamic.data[bndto].
					    d_un.d_val, ELFEDIT_MSG_ERR, 0);

				if (str != NULL) {
					elfedit_printf(MSG_ORIG(MSG_FMT_STRNL),
					    str);
					continue;
				}
			}

			/*
			 * If we reach this point, we are either in numeric
			 * mode, or we were unable to find a string above.
			 * In either case, output as integer.
			 */
			elfedit_printf(MSG_ORIG(MSG_FMT_WORDVALNL),
			    EC_WORD(bndto));
		}
		break;

	case SYMINFO_CMD_T_SI_FLAGS:
		for (syminfo += ndx; cnt--; syminfo++) {
			if (outstyle == ELFEDIT_OUTSTYLE_SIMPLE) {
				Conv_syminfo_flags_buf_t buf;

				elfedit_printf(MSG_ORIG(MSG_FMT_STRNL),
				    conv_syminfo_flags(syminfo->si_flags,
				    CONV_FMT_NOBKT, &buf));
			} else {
				elfedit_printf(MSG_ORIG(MSG_FMT_HEXNUMNL),
				    EC_WORD(syminfo->si_flags));
			}
		}
		break;
	}
}


/*
 * Convert the given argument string into a symbol table index.
 *
 * entry:
 *	argstate - State block for current symbol table.
 *	arg - String containing symbol index argument.
 *
 * exit:
 *	On success, returns the symbol index. On failure, an error
 *	is issued and this routine does not return.
 */
static Word
arg_to_symndx(ARGSTATE *argstate, const char *arg)
{
	Word symndx;

	/*
	 * If the -symndx option was specified, arg is an index
	 * into the symbol table.
	 */
	if (argstate->optmask & SYMINFO_OPT_F_SYMNDX)
		return (elfedit_atoui_range(arg, MSG_ORIG(MSG_STR_SYM),
		    0, argstate->syminfo.n - 1, NULL));

	/*
	 * arg is a symbol name. Return the index of the first symbol
	 * that matches
	 */
	argstate_add_sym(argstate);
	argstate_add_str(argstate);

	(void) elfedit_name_to_symndx(argstate->sym.sec,
	    argstate->str.sec, arg, ELFEDIT_MSG_ERR, &symndx);

	return (symndx);
}


/*
 * Given a string argument representing an object, return the index of
 * the dynamic section that should be used for the si_boundto value.
 */
static Half
needed_to_boundto(ARGSTATE *argstate, const char *arg)
{
	Conv_inv_buf_t		inv_buf;
	elfedit_dyn_elt_t	strpad_elt;
	elfedit_dyn_elt_t	null_elt;
	elfedit_section_t	*dynsec;
	Word			null_cnt;
	Dyn			*dyn;
	Word			str_offset, ndx, numdyn;
	int			have_string;

	argstate_add_str(argstate);
	argstate_add_dynamic(argstate);
	dynsec = argstate->dynamic.sec;
	numdyn = argstate->dynamic.n;

	/* Locate DT_SUNW_STRPAD element if present and locate the DT_NULLs */
	elfedit_dyn_elt_init(&strpad_elt);
	elfedit_dyn_elt_init(&null_elt);
	null_cnt = 0;
	strpad_elt.dn_dyn.d_un.d_val = 0;
	dyn = argstate->dynamic.data;
	for (ndx = 0; ndx < numdyn; dyn++, ndx++) {
		switch (dyn->d_tag) {
		case DT_NULL:
			/* Count all the nulls, remember the first one */
			null_cnt++;
			if (!null_elt.dn_seen)
				elfedit_dyn_elt_save(&null_elt, ndx, dyn);
			break;

		case DT_SUNW_STRPAD:
			if (elfedit_test_osabi(argstate->obj_state,
			    ELFOSABI_SOLARIS, 0))
				elfedit_dyn_elt_save(&strpad_elt, ndx, dyn);
			break;
		}
	}

	/*
	 * Look up the string in the string table and get its offset. If
	 * this succeeds, then it is possible that there is a DT_NEEDED
	 * dynamic entry that references it.
	 */
	have_string = elfedit_sec_findstr(argstate->str.sec,
	    strpad_elt.dn_dyn.d_un.d_val, arg, &str_offset) != 0;
	if (have_string) {
		dyn = argstate->dynamic.data;
		for (ndx = 0; ndx < numdyn; dyn++, ndx++) {
			if (((dyn->d_tag == DT_NEEDED) ||
			    (dyn->d_tag == DT_USED)) &&
			    (dyn->d_un.d_val == str_offset))
				goto done;
		}
	}

	/*
	 * It doesn't already exist. We might be able to add a DT_NEEDED
	 * to the dynamic section if an extra DT_NULL is available.
	 * Otherwise, we have to fail here.
	 */
	if (null_cnt < 2)
		elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_NOEXTRANULL),
		    EC_WORD(dynsec->sec_shndx), dynsec->sec_name);

	/*
	 * If the string is not already in the string table, try to
	 * insert it. If it succeeds, we will convert the DT_NULL.
	 * Otherwise, an error will be issued and control will not
	 * return here.
	 */
	if (!have_string)
		str_offset = elfedit_dynstr_insert(dynsec,
		    argstate->str.sec, &strpad_elt, arg);

	/* Convert the extra DT_NULL */
	ndx = null_elt.dn_ndx;
	elfedit_msg(ELFEDIT_MSG_DEBUG, MSG_INTL(MSG_DEBUG_CONVNULL),
	    EC_WORD(dynsec->sec_shndx), dynsec->sec_name, EC_WORD(ndx),
	    conv_dyn_tag(DT_NEEDED,
	    argstate->obj_state->os_ehdr->e_ident[EI_OSABI],
	    argstate->obj_state->os_ehdr->e_machine,
	    0, &inv_buf));
	dyn = argstate->dynamic.data + ndx;
	dyn->d_tag = DT_NEEDED;
	dyn->d_un.d_val = str_offset;
	elfedit_modified_data(dynsec);

done:
	elfedit_msg(ELFEDIT_MSG_DEBUG, MSG_INTL(MSG_DEBUG_FNDNEEDED),
	    dynsec->sec_shndx, dynsec->sec_name, ndx, arg);
	return (ndx);
}

/*
 * Common body for the syminfo: module commands. These commands
 * share a large amount of common behavior, so it is convenient
 * to centralize things and use the cmd argument to handle the
 * small differences.
 *
 * entry:
 *	cmd - One of the SYMINFO_CMD_T_* constants listed above, specifying
 *		which command to implement.
 *	obj_state, argc, argv - Standard command arguments
 */
static elfedit_cmdret_t
cmd_body(SYMINFO_CMD_T cmd, elfedit_obj_state_t *obj_state,
    int argc, const char *argv[])
{
	ARGSTATE		argstate;
	Word			ndx;
	Syminfo			*syminfo;
	elfedit_cmdret_t	ret = ELFEDIT_CMDRET_NONE;

	process_args(obj_state, argc, argv, cmd, &argstate);

	/* If there are no arguments, dump the whole table and return */
	if (argstate.argc == 0) {
		print_syminfo(cmd, 0, &argstate, 0, argstate.syminfo.n);
		return (ELFEDIT_CMDRET_NONE);
	}

	/* The first argument is the symbol name/index */
	ndx = arg_to_symndx(&argstate, argstate.argv[0]);

	/* If there is a single argument, display that item and return */
	if (argstate.argc == 1) {
		print_syminfo(cmd, 0, &argstate, ndx, 1);
		return (ELFEDIT_CMDRET_NONE);
	}

	syminfo = &argstate.syminfo.data[ndx];

	/*
	 * Syminfo [0] holds the value SYMINFO_CURRENT, as a versioning
	 * technique. You're not supposed to mess with it.
	 */
	if (ndx == 0)
		elfedit_msg(ELFEDIT_MSG_DEBUG, MSG_INTL(MSG_DEBUG_CHGSYMINFO0),
		    EC_WORD(argstate.syminfo.sec->sec_shndx),
		    argstate.syminfo.sec->sec_name, EC_WORD(ndx));

	/* The second value supplies a new value for the item */
	switch (cmd) {
		/*
		 * SYMINFO_CMD_T_DUMP can't get here: It never has more than
		 * one argument, and is handled above.
		 */

	case SYMINFO_CMD_T_SI_BOUNDTO:
		{
			const char *name = MSG_ORIG(MSG_CMD_SI_BOUNDTO);
			Half boundto;

			if (argstate.optmask & SYMINFO_OPT_F_NEEDED)
				boundto = needed_to_boundto(&argstate,
				    argstate.argv[1]);
			else
				boundto = elfedit_atoconst_range(
				    argstate.argv[1], MSG_ORIG(MSG_STR_VALUE),
				    0, 0xffff, ELFEDIT_CONST_SYMINFO_BT);

			if (syminfo->si_boundto == boundto) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_X_OK),
				    argstate.syminfo.sec->sec_shndx,
				    argstate.syminfo.sec->sec_name, ndx, name,
				    syminfo->si_boundto);
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_X_CHG),
				    argstate.syminfo.sec->sec_shndx,
				    argstate.syminfo.sec->sec_name, ndx, name,
				    syminfo->si_boundto, boundto);
				ret = ELFEDIT_CMDRET_MOD;
				syminfo->si_boundto = boundto;
			}
		}
		break;

	case SYMINFO_CMD_T_SI_FLAGS:
		{
			Conv_syminfo_flags_buf_t flags_buf1, flags_buf2;
			const char *name = MSG_ORIG(MSG_CMD_SI_FLAGS);
			Half flags = 0;
			int i;

			/* Collect the arguments */
			for (i = 1; i < argstate.argc; i++)
				flags |= (Word)
				    elfedit_atoconst(argstate.argv[i],
				    ELFEDIT_CONST_SYMINFO_FLG);

			/* Complement the value? */
			if (argstate.optmask & SYMINFO_OPT_F_CMP)
				flags = ~flags;

			/* Perform any requested bit operations */
			if (argstate.optmask & SYMINFO_OPT_F_AND)
				flags &= syminfo->si_flags;
			else if (argstate.optmask & SYMINFO_OPT_F_OR)
				flags |= syminfo->si_flags;

			/* Set the value */
			if (syminfo->si_flags == flags) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_S_OK),
				    argstate.syminfo.sec->sec_shndx,
				    argstate.syminfo.sec->sec_name, ndx, name,
				    conv_syminfo_flags(syminfo->si_flags,
				    0, &flags_buf1));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_S_CHG),
				    argstate.syminfo.sec->sec_shndx,
				    argstate.syminfo.sec->sec_name, ndx, name,
				    conv_syminfo_flags(syminfo->si_flags,
				    0, &flags_buf1),
				    conv_syminfo_flags(flags, 0, &flags_buf2));
				ret = ELFEDIT_CMDRET_MOD;
				syminfo->si_flags = flags;
			}
		}
		break;
	}

	/*
	 * If we modified the syminfo section, tell libelf.
	 */
	if (ret == ELFEDIT_CMDRET_MOD)
		elfedit_modified_data(argstate.syminfo.sec);

	/* Do autoprint */
	print_syminfo(cmd, 1, &argstate, ndx, 1);

	return (ret);
}




/*
 * Command completion functions for the various commands
 */
/*ARGSUSED*/
static void
cpl_si_boundto(elfedit_obj_state_t *obj_state, void *cpldata, int argc,
    const char *argv[], int num_opt)
{
	int i;

	/*
	 * If -needed option is not present, the second argument can be
	 * an SYMINFO_BT_ value.
	 */
	if (argc != (num_opt + 2))
		return;

	/* Is -needed there? If so, no completion is possible so return */
	for (i = 0; i < num_opt; i++)
		if (strcmp(argv[i], MSG_ORIG(MSG_STR_MINUS_NEEDED)) == 0)
			return;

	elfedit_cpl_atoconst(cpldata, ELFEDIT_CONST_SYMINFO_BT);
}

/*ARGSUSED*/
static void
cpl_si_flags(elfedit_obj_state_t *obj_state, void *cpldata, int argc,
    const char *argv[], int num_opt)
{
	/* The second argument can be an SYMINFO_FLG_ value */
	if (argc == (num_opt + 2))
		elfedit_cpl_atoconst(cpldata, ELFEDIT_CONST_SYMINFO_FLG);
}



/*
 * Implementation functions for the commands
 */
static elfedit_cmdret_t
cmd_dump(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(SYMINFO_CMD_T_DUMP, obj_state, argc, argv));
}


static elfedit_cmdret_t
cmd_si_boundto(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(SYMINFO_CMD_T_SI_BOUNDTO, obj_state, argc, argv));
}


static elfedit_cmdret_t
cmd_si_flags(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(SYMINFO_CMD_T_SI_FLAGS, obj_state, argc, argv));
}




/*ARGSUSED*/
elfedit_module_t *
elfedit_init(elfedit_module_version_t version)
{
	/* sym:dump */
	static const char *name_dump[] = {
	    MSG_ORIG(MSG_CMD_DUMP),
	    MSG_ORIG(MSG_STR_EMPTY),	/* "" makes this the default command */
	    NULL
	};
	static elfedit_cmd_optarg_t opt_dump[] = {
		{ MSG_ORIG(MSG_STR_MINUS_SYMNDX),
		    /* MSG_INTL(MSG_OPTDESC_SYMNDX) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_SYMNDX), 0,
		    SYMINFO_OPT_F_SYMNDX, 0 },
		{ NULL }
	};
	static elfedit_cmd_optarg_t arg_dump[] = {
		{ MSG_ORIG(MSG_STR_SYM),
		    /* MSG_INTL(MSG_A1_SYM) */
		    ELFEDIT_I18NHDL(MSG_A1_SYM),
		    ELFEDIT_CMDOA_F_OPT },
		{ NULL }
	};

	/* sym:si_boundto */
	static const char *name_si_boundto[] = {
	    MSG_ORIG(MSG_CMD_SI_BOUNDTO), NULL };
	static elfedit_cmd_optarg_t opt_si_boundto[] = {
		{ MSG_ORIG(MSG_STR_MINUS_NEEDED),
		    /* MSG_INTL(MSG_OPTDESC_NEEDED) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_NEEDED), 0,
		    SYMINFO_OPT_F_NEEDED, 0 },
		{ ELFEDIT_STDOA_OPT_O, 0,
		    ELFEDIT_CMDOA_F_INHERIT, 0, 0 },
		{ MSG_ORIG(MSG_STR_MINUS_SYMNDX),
		    /* MSG_INTL(MSG_OPTDESC_SYMNDX) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_SYMNDX), 0,
		    SYMINFO_OPT_F_SYMNDX, 0 },
		{ NULL }
	};
	static elfedit_cmd_optarg_t arg_si_boundto[] = {
		{ MSG_ORIG(MSG_STR_SYM),
		    /* MSG_INTL(MSG_A1_SYM) */
		    ELFEDIT_I18NHDL(MSG_A1_SYM),
		    ELFEDIT_CMDOA_F_OPT },
		{ MSG_ORIG(MSG_STR_VALUE),
		    /* MSG_INTL(MSG_A2_DESC_SI_BOUNDTO) */
		    ELFEDIT_I18NHDL(MSG_A2_DESC_SI_BOUNDTO),
		    ELFEDIT_CMDOA_F_OPT },
		{ NULL }
	};

	/* sym:si_flags */
	static const char *name_si_flags[] = {
	    MSG_ORIG(MSG_CMD_SI_FLAGS), NULL };
	static elfedit_cmd_optarg_t opt_si_flags[] = {
		{ ELFEDIT_STDOA_OPT_AND, 0, ELFEDIT_CMDOA_F_INHERIT,
		    SYMINFO_OPT_F_AND, SYMINFO_OPT_F_OR },
		{ ELFEDIT_STDOA_OPT_CMP, 0,
		    ELFEDIT_CMDOA_F_INHERIT, SYMINFO_OPT_F_CMP, 0 },
		{ ELFEDIT_STDOA_OPT_O, 0,
		    ELFEDIT_CMDOA_F_INHERIT, 0, 0 },
		{ ELFEDIT_STDOA_OPT_OR, 0, ELFEDIT_CMDOA_F_INHERIT,
		    SYMINFO_OPT_F_OR, SYMINFO_OPT_F_AND },
		{ MSG_ORIG(MSG_STR_MINUS_SYMNDX),
		    /* MSG_INTL(MSG_OPTDESC_SYMNDX) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_SYMNDX), 0,
		    SYMINFO_OPT_F_SYMNDX, 0 },
		{ NULL }
	};
	static elfedit_cmd_optarg_t arg_si_flags[] = {
		{ MSG_ORIG(MSG_STR_SYM),
		    /* MSG_INTL(MSG_A1_SYM) */
		    ELFEDIT_I18NHDL(MSG_A1_SYM),
		    ELFEDIT_CMDOA_F_OPT },
		{ MSG_ORIG(MSG_STR_VALUE),
		    /* MSG_INTL(MSG_A2_DESC_SI_FLAGS) */
		    ELFEDIT_I18NHDL(MSG_A2_DESC_SI_FLAGS),
		    ELFEDIT_CMDOA_F_OPT | ELFEDIT_CMDOA_F_MULT },
		{ NULL }
	};

	static elfedit_cmd_t cmds[] = {
		/* sym:dump */
		{ cmd_dump, NULL, name_dump,
		    /* MSG_INTL(MSG_DESC_DUMP) */
		    ELFEDIT_I18NHDL(MSG_DESC_DUMP),
		    /* MSG_INTL(MSG_HELP_DUMP) */
		    ELFEDIT_I18NHDL(MSG_HELP_DUMP),
		    opt_dump, arg_dump },

		/* sym:si_boundto */
		{ cmd_si_boundto, cpl_si_boundto, name_si_boundto,
		    /* MSG_INTL(MSG_DESC_SI_BOUNDTO) */
		    ELFEDIT_I18NHDL(MSG_DESC_SI_BOUNDTO),
		    /* MSG_INTL(MSG_HELP_SI_BOUNDTO) */
		    ELFEDIT_I18NHDL(MSG_HELP_SI_BOUNDTO),
		    opt_si_boundto, arg_si_boundto },

		/* sym:si_flags */
		{ cmd_si_flags, cpl_si_flags, name_si_flags,
		    /* MSG_INTL(MSG_DESC_SI_FLAGS) */
		    ELFEDIT_I18NHDL(MSG_DESC_SI_FLAGS),
		    /* MSG_INTL(MSG_HELP_SI_FLAGS) */
		    ELFEDIT_I18NHDL(MSG_HELP_SI_FLAGS),
		    opt_si_flags, arg_si_flags },

		{ NULL }
	};

	static elfedit_module_t module = {
	    ELFEDIT_VER_CURRENT, MSG_ORIG(MSG_MOD_NAME),
	    /* MSG_INTL(MSG_MOD_DESC) */
	    ELFEDIT_I18NHDL(MSG_MOD_DESC),
	    cmds, mod_i18nhdl_to_str };

	return (&module);
}
