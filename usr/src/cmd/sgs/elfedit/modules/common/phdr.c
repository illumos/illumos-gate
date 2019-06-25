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

#include	<elfedit.h>
#include	<strings.h>
#include	<conv.h>
#include	<debug.h>
#include	<phdr_msg.h>


/*
 * Program headers
 */



/*
 * This module uses shared code for several of the commands.
 * It is sometimes necessary to know which specific command
 * is active.
 */
typedef enum {
	/* Dump command, used as module default to display dynamic section */
	PHDR_CMD_T_DUMP =	0,	/* phdr:dump */

	/* Commands that correspond directly to program header fields */
	PHDR_CMD_T_P_TYPE =	1,	/* phdr:p_type */
	PHDR_CMD_T_P_OFFSET =	2,	/* phdr:p_offset */
	PHDR_CMD_T_P_VADDR =	3,	/* phdr:p_vaddr */
	PHDR_CMD_T_P_PADDR =	4,	/* phdr:p_paddr */
	PHDR_CMD_T_P_FILESZ =	5,	/* phdr:p_filesz */
	PHDR_CMD_T_P_MEMSZ =	6,	/* phdr:p_memsz */
	PHDR_CMD_T_P_FLAGS =	7,	/* phdr:p_flags */
	PHDR_CMD_T_P_ALIGN =	8,	/* phdr:p_align */

	/* Commands that do not correspond directly to a specific phdr tag */
	PHDR_CMD_T_INTERP =	9,	/* phdr:interp */
	PHDR_CMD_T_DELETE =	10,	/* phdr:delete */
	PHDR_CMD_T_MOVE =	11	/* phdr:move */
} PHDR_CMD_T;



/*
 * The following type is ued by locate_interp() to return
 * information about the interpreter program header.
 */
typedef struct {
	Word			phndx;	/* Index of PT_INTERP header */
	Phdr			*phdr;		/* PT_INTERP header */
	elfedit_section_t	*sec;		/* Section containing string */
	Word			stroff;		/* Offset into string section */
	const char		*str;		/* Interpreter string */
} INTERP_STATE;


#ifndef _ELF64
/*
 * We supply this function for the msg module
 */
const char *
_phdr_msg(Msg mid)
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
 * The phdr_opt_t enum specifies a bit value for every optional
 * argument allowed by a command in this module.
 */
typedef enum {
	PHDR_OPT_F_AND =	1,	/* -and: AND (&) values to dest */
	PHDR_OPT_F_CMP =	2,	/* -cmp: Complement (~) values */
	PHDR_OPT_F_PHNDX =	4,	/* -phndx: Program header by index, */
					/*	not by name */
	PHDR_OPT_F_OR =		8	/* -or: OR (|) values to dest */
} phdr_opt_t;


/*
 * A variable of type ARGSTATE is used by each command to maintain
 * information about the section headers and related things. It is
 * initialized by process_args(), and used by the other routines.
 */
typedef struct {
	elfedit_obj_state_t	*obj_state;
	phdr_opt_t		optmask;	/* Mask of options used */
	int			argc;		/* # of plain arguments */
	const char		**argv;		/* Plain arguments */
	int			ndx_set;	/* True if ndx is valid */
	Word			ndx;		/* Index of header if cmd */
						/*	accepts it */
	int			print_req;	/* Call is a print request */
} ARGSTATE;


/*
 * Standard argument processing for phdr module
 *
 * entry
 *	obj_state, argc, argv - Standard command arguments
 *	optmask - Mask of allowed optional arguments.
 *	cmd - PHDR_CMD_T_* value giving identify of caller
 *	argstate - Address of ARGSTATE block to be initialized
 *
 * exit:
 *	On success, *argstate is initialized. On error,
 *	an error is issued and this routine does not return.
 */
static void
process_args(elfedit_obj_state_t *obj_state, int argc, const char *argv[],
    PHDR_CMD_T cmd, ARGSTATE *argstate)
{
	elfedit_getopt_state_t	getopt_state;
	elfedit_getopt_ret_t	*getopt_ret;

	bzero(argstate, sizeof (*argstate));
	argstate->obj_state = obj_state;

	elfedit_getopt_init(&getopt_state, &argc, &argv);

	/* Add each new option to the options mask */
	while ((getopt_ret = elfedit_getopt(&getopt_state)) != NULL)
		argstate->optmask |= getopt_ret->gor_idmask;

	/* Are the right number of plain arguments present? */
	switch (cmd) {
	case PHDR_CMD_T_DUMP:
		if (argc > 1)
			elfedit_command_usage();
		argstate->print_req = 1;
		break;
	case PHDR_CMD_T_P_FLAGS:
		/* phdr:sh_flags allows an arbitrary number of arguments */
		argstate->print_req = (argc < 2);
		break;
	case PHDR_CMD_T_INTERP:
		if (argc > 1)
			elfedit_command_usage();
		argstate->print_req = (argc == 0);
		break;
	case PHDR_CMD_T_DELETE:
		if ((argc < 1) || (argc > 2))
			elfedit_command_usage();
		argstate->print_req = 0;
		break;
	case PHDR_CMD_T_MOVE:
		if ((argc < 2) || (argc > 3))
			elfedit_command_usage();
		argstate->print_req = 0;
		break;

	default:
		/* The remaining commands accept 2 plain arguments */
		if (argc > 2)
			elfedit_command_usage();
		argstate->print_req = (argc < 2);
		break;
	}

	/* Return the updated values of argc/argv */
	argstate->argc = argc;
	argstate->argv = argv;

	argstate->ndx_set = 0;
	if ((argc > 0) && (cmd != PHDR_CMD_T_INTERP)) {
		/*
		 * If the -phndx option is present, the first argument is
		 * the index of the header to use. Otherwise, it is a
		 * name corresponding to its type, similar to the way
		 * elfdump works with its -N option.
		 */
		if (argstate->optmask & PHDR_OPT_F_PHNDX) {
			argstate->ndx = (Word) elfedit_atoui_range(
			    argstate->argv[0], MSG_ORIG(MSG_STR_ELEMENT), 0,
			    argstate->obj_state->os_phnum - 1, NULL);
			argstate->ndx_set = 1;
		} else {
			Conv_inv_buf_t inv_buf;
			Ehdr		*ehdr = obj_state->os_ehdr;
			Half		mach = ehdr->e_machine;
			uchar_t		osabi = ehdr->e_ident[EI_OSABI];
			Word		i;
			Phdr		*phdr;

			argstate->ndx = (Word) elfedit_atoconst(
			    argstate->argv[0], ELFEDIT_CONST_PT);
			phdr = obj_state->os_phdr;
			for (i = 0; i < obj_state->os_phnum; i++, phdr++) {
				if (phdr->p_type == argstate->ndx) {
					argstate->ndx = i;
					argstate->ndx_set = 1;
					elfedit_msg(ELFEDIT_MSG_DEBUG,
					    MSG_INTL(MSG_DEBUG_PHDR),
					    EC_WORD(i), conv_phdr_type(osabi,
					    mach, phdr->p_type, 0, &inv_buf));
					break;
				}
			}
			if (i == argstate->obj_state->os_phnum)
				elfedit_msg(ELFEDIT_MSG_ERR,
				    MSG_INTL(MSG_ERR_NOPHDR), conv_phdr_type(
				    osabi, mach, argstate->ndx, 0, &inv_buf));
		}
	}

	/* If there may be an arbitrary amount of output, use a pager */
	if (argc == 0)
		elfedit_pager_init();

}



/*
 * Locate the interpreter string for the object and related information
 *
 * entry:
 *	obj_state - Object state
 *	interp - NULL, or variable to be filled in with information
 *		about the interpteter string.
 */
static const char *
locate_interp(elfedit_obj_state_t *obj_state, INTERP_STATE *interp)
{
	INTERP_STATE		local_interp;
	elfedit_section_t	*strsec;	/* String table */
	size_t		phnum;		/* # of program headers */
	int		phndx;		/* Index of PT_INTERP program header */
	Phdr		*phdr;		/* Program header array */
	Word		i;

	if (interp == NULL)
		interp = &local_interp;

	/* Locate the PT_INTERP program header */
	phnum = obj_state->os_phnum;
	phdr = obj_state->os_phdr;

	for (phndx = 0; phndx < phnum; phndx++) {
		if (phdr[phndx].p_type  == PT_INTERP) {
			interp->phndx = phndx;
			interp->phdr = phdr + phndx;
			break;
		}
	}
	/* If no PT_INTERP program header found, we cannot proceed */
	if (phndx == phnum)
		elfedit_elferr(obj_state->os_file,
		    MSG_INTL(MSG_ERR_NOINTERPPHDR));

	/*
	 * Locate the section containing the interpteter string as well
	 * as the string itself.
	 *
	 * The program header contains a direct offset to the string, so
	 * we find the section by walking through the them looking for
	 * the one with a base and size that would contain the string.
	 * Note that this target section cannot be in a NOBITS section.
	 */
	for (i = 1; i < obj_state->os_shnum; i++) {
		strsec = &obj_state->os_secarr[i];

		if ((strsec->sec_shdr->sh_type != SHT_NOBITS) &&
		    (interp->phdr->p_offset >= strsec->sec_shdr->sh_offset) &&
		    ((interp->phdr->p_offset + interp->phdr->p_filesz) <=
		    (strsec->sec_shdr->sh_offset +
		    strsec->sec_shdr->sh_size))) {
			interp->sec = strsec;

			interp->stroff = interp->phdr->p_offset -
			    strsec->sec_shdr->sh_offset;
			interp->str = ((char *)strsec->sec_data->d_buf) +
			    interp->stroff;
			return (interp->str);
		}
	}

	/*
	 * We don't expect to get here: If there is a PT_INTERP header,
	 * we fully expect the string to exist.
	 */
	elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_NOINTERPSEC));
	/*NOTREACHED*/

	return (NULL);		/* For lint */
}

/*
 * Print program header values, taking the calling command, and output style
 * into account.
 *
 * entry:
 *	autoprint - If True, output is only produced if the elfedit
 *		autoprint flag is set. If False, output is always produced.
 *	cmd - PHDR_CMD_T_* value giving identify of caller
 *	argstate - State block for section header array. The following
 *		fields are examined in order to determine the form
 *		of output: ndx_set, ndx, print_req.
 */
static void
print_phdr(PHDR_CMD_T cmd, int autoprint, ARGSTATE *argstate)
{
	elfedit_outstyle_t	outstyle;
	Ehdr			*ehdr = argstate->obj_state->os_ehdr;
	uchar_t			osabi = ehdr->e_ident[EI_OSABI];
	Half			mach = ehdr->e_machine;
	Word			ndx, cnt, by_type, type;
	Phdr			*phdr;

	if (autoprint && ((elfedit_flags() & ELFEDIT_F_AUTOPRINT) == 0))
		return;

	/*
	 * Determine which indexes to display:
	 *
	 * -	If the user specified an index, the display starts
	 *	with that item. If it was a print_request, and the
	 *	index was specified by type, then all items of the
	 *	same type are shown. If not a print request, or the index
	 *	was given numerically, then just the single item is shown.
	 *
	 * -	If no index is specified, every program header is shown.
	 */
	by_type = 0;
	if (argstate->ndx_set) {
		ndx = argstate->ndx;
		if (argstate->print_req &&
		    ((argstate->optmask & PHDR_OPT_F_PHNDX) == 0)) {
			by_type = 1;
			type = argstate->obj_state->os_phdr[ndx].p_type;
			cnt = argstate->obj_state->os_phnum - ndx;
		} else {
			cnt = 1;
		}
	} else {
		ndx = 0;
		cnt = argstate->obj_state->os_phnum;
	}
	phdr = argstate->obj_state->os_phdr + ndx;

	/*
	 * Pick an output style. phdr:dump is required to use the default
	 * style. The other commands use the current output style.
	 */
	outstyle = (cmd == PHDR_CMD_T_DUMP) ?
	    ELFEDIT_OUTSTYLE_DEFAULT : elfedit_outstyle();

	/*
	 * If doing default output, use elfdump style where we
	 * show all program header attributes. In this case, the
	 * command that called us doesn't matter.
	 *
	 * Exclude PHDR_CMD_T_INTERP from this: It isn't per-phdr like
	 * the other commands.
	 */
	if ((outstyle == ELFEDIT_OUTSTYLE_DEFAULT) &&
	    (cmd != PHDR_CMD_T_INTERP)) {
		for (; cnt--; ndx++, phdr++) {
			if (by_type && (type != phdr->p_type))
				continue;

			elfedit_printf(MSG_ORIG(MSG_STR_NL));
			elfedit_printf(MSG_INTL(MSG_ELF_PHDR), EC_WORD(ndx));
			Elf_phdr(0, osabi, mach, phdr);
		}
		return;
	}

	if (cmd == PHDR_CMD_T_INTERP) {
		INTERP_STATE interp;

		(void) locate_interp(argstate->obj_state, &interp);
		switch (outstyle) {
		case ELFEDIT_OUTSTYLE_DEFAULT:
			elfedit_printf(MSG_INTL(MSG_FMT_ELF_INTERP),
			    interp.sec->sec_name, interp.str);
			break;
		case ELFEDIT_OUTSTYLE_SIMPLE:
			elfedit_printf(MSG_ORIG(MSG_FMT_STRNL), interp.str);
			break;
		case ELFEDIT_OUTSTYLE_NUM:
			elfedit_printf(MSG_ORIG(MSG_FMT_U_NL),
			    EC_WORD(interp.stroff));
			break;
		}
		return;
	}

	/* Handle the remaining commands */
	for (; cnt--; ndx++, phdr++) {
		if (by_type && (type != phdr->p_type))
			continue;

		switch (cmd) {
		case PHDR_CMD_T_P_TYPE:
			if (outstyle == ELFEDIT_OUTSTYLE_SIMPLE) {
				Conv_inv_buf_t inv_buf;

				elfedit_printf(MSG_ORIG(MSG_FMT_STRNL),
				    conv_phdr_type(osabi,
				    argstate->obj_state->os_ehdr->e_machine,
				    phdr->p_type, 0, &inv_buf));
			} else {
				elfedit_printf(MSG_ORIG(MSG_FMT_X_NL),
				    EC_WORD(phdr->p_type));
			}
			break;

		case PHDR_CMD_T_P_OFFSET:
			elfedit_printf(MSG_ORIG(MSG_FMT_LLX_NL),
			    EC_OFF(phdr->p_offset));
			break;

		case PHDR_CMD_T_P_VADDR:
			elfedit_printf(MSG_ORIG(MSG_FMT_LLX_NL),
			    EC_ADDR(phdr->p_vaddr));
			break;

		case PHDR_CMD_T_P_PADDR:
			elfedit_printf(MSG_ORIG(MSG_FMT_LLX_NL),
			    EC_ADDR(phdr->p_paddr));
			break;

		case PHDR_CMD_T_P_FILESZ:
			elfedit_printf(MSG_ORIG(MSG_FMT_LLX_NL),
			    EC_XWORD(phdr->p_filesz));
			break;

		case PHDR_CMD_T_P_MEMSZ:
			elfedit_printf(MSG_ORIG(MSG_FMT_LLX_NL),
			    EC_XWORD(phdr->p_memsz));
			break;

		case PHDR_CMD_T_P_FLAGS:
			if (outstyle == ELFEDIT_OUTSTYLE_SIMPLE) {
				Conv_phdr_flags_buf_t phdr_flags_buf;

				elfedit_printf(MSG_ORIG(MSG_FMT_STRNL),
				    conv_phdr_flags(osabi, phdr->p_flags,
				    CONV_FMT_NOBKT, &phdr_flags_buf));
			} else {
				elfedit_printf(MSG_ORIG(MSG_FMT_X_NL),
				    EC_WORD(phdr->p_flags));
			}
			break;

		case PHDR_CMD_T_P_ALIGN:
			elfedit_printf(MSG_ORIG(MSG_FMT_LLX_NL),
			    EC_XWORD(phdr->p_align));
			break;
		}
	}
}


/*
 * Called from cmd_body() in the case where a plain argument
 * is given to phdr:interp to change the interpreter.
 */
static elfedit_cmdret_t
cmd_body_set_interp(ARGSTATE *argstate)
{
	elfedit_obj_state_t	*obj_state = argstate->obj_state;
	elfedit_section_t	*strsec;	/* String table */
	INTERP_STATE	interp;
	Word		numdyn;		/* # of elements in dyn arr */
	size_t		phnum;		/* # of program headers */
	Phdr		*phdr;		/* Program header array */
	Word		i, j;
	Word		str_offset;	/* Offset in strsec to new interp str */
	int		str_found = 0;	 /* True when we have new interp str */
	Word		str_size;	/* Size of new interp string + NULL */

	phnum = obj_state->os_phnum;
	phdr = obj_state->os_phdr;

	/* Locate the PT_INTERP program header */
	(void) locate_interp(obj_state, &interp);
	strsec = interp.sec;
	str_offset = interp.stroff;

	/*
	 * If the given string is the same as the existing interpreter
	 * string, say so and return.
	 */
	if (strcmp(interp.str, argstate->argv[0]) == 0) {
		elfedit_msg(ELFEDIT_MSG_DEBUG, MSG_INTL(MSG_DEBUG_OLDINTERPOK),
		    EC_WORD(strsec->sec_shndx), strsec->sec_name,
		    EC_WORD(str_offset), interp.str);
		return (ELFEDIT_CMDRET_NONE);
	}

	/*
	 * An ELF PT_INTERP usually references its own special section
	 * instead of some other string table. The ELF ABI says that this
	 * section must be named ".interp". Hence, this is a rare case
	 * in which the name of a section can be taken as an indication
	 * of its contents. .interp is typically sized to just fit
	 * the original string, including its NULL termination. You can
	 * treat it as a string table with one string.
	 *
	 * Thanks to 'elfedit', it may be that we encounter a file where
	 * PT_INTERP does not reference the .interp section. This will happen
	 * if elfedit is used to change the interpreter to a string that is
	 * too big to fit in .interp, in which case we will use the
	 * .dynstr string table (That code is below, in this function).
	 *
	 * Given the above facts, our next step is to locate the .interp
	 * section and see if our new string will fit in it. Since we can't
	 * depend on PT_INTERP, we search the section headers to find a
	 * section whith the following characteristics:
	 *	- The name is ".interp".
	 *	- Section is allocable (SHF_ALLOC) and SHT_PROGBITS.
	 *	- It is not part of a writable segment.
	 * If we find such a section, and the new string fits, we will
	 * write it there.
	 */
	str_size = strlen(argstate->argv[0]) + 1;
	for (i = 1; i < obj_state->os_shnum; i++) {
		strsec = &obj_state->os_secarr[i];
		if ((strcmp(strsec->sec_name, MSG_ORIG(MSG_SEC_INTERP)) == 0) &&
		    (strsec->sec_shdr->sh_flags & SHF_ALLOC) &&
		    (strsec->sec_shdr->sh_type & SHT_PROGBITS)) {
			for (j = 0; j < phnum; j++) {
				Phdr *tphdr = &phdr[j];
				if ((strsec->sec_shdr->sh_offset >=
				    tphdr->p_offset) &&
				    ((strsec->sec_shdr->sh_offset +
				    strsec->sec_shdr->sh_size) <=
				    (tphdr->p_offset + tphdr->p_filesz)) &&
				    (tphdr->p_flags & PF_W)) {
					break;
				}
			}
			if ((j == phnum) &&
			    (str_size <= strsec->sec_shdr->sh_size)) {
				/* .interp section found, and has room */
				str_found = 1;
				str_offset = 0;
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_NEWISTR), EC_WORD(j),
				    strsec->sec_name, EC_WORD(str_offset),
				    argstate->argv[0]);
				/* Put new value in section */
				(void) strncpy((char *)strsec->sec_data->d_buf,
				    argstate->argv[0],
				    strsec->sec_shdr->sh_size);
				/* Set libelf dirty bit so change is flushed */
				elfedit_modified_data(strsec);
				break;
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_LNGISTR), EC_WORD(j),
				    strsec->sec_name, EC_WORD(str_offset),
				    EC_WORD(str_size),
				    EC_WORD(strsec->sec_shdr->sh_size),
				    argstate->argv[0]);
			}
		}
	}

	/*
	 * If the above did not find a string within the .interp section,
	 * then we have a second option. If this ELF object has a dynamic
	 * section, then we are willing to use strings from within the
	 * associated .dynstr string table. And if there is reserved space
	 * in .dynstr (as reported by the DT_SUNW_STRPAD dynamic entry),
	 * then we are even willing to add a new string to .dynstr.
	 */
	if (!str_found) {
		elfedit_section_t	*dynsec;
		Dyn			*dyn;

		dynsec = elfedit_sec_getdyn(obj_state, &dyn, &numdyn);
		strsec = elfedit_sec_getstr(obj_state,
		    dynsec->sec_shdr->sh_link, 0);

		/* Does string exist in the table already, or can we add it? */
		str_offset = elfedit_strtab_insert(obj_state, strsec,
		    dynsec, argstate->argv[0]);
	}


	/*
	 * If we are here, we know we have a replacement string, because
	 * the errors from checking .dynamic/.dynstr will not allow
	 * things to get here otherwise.
	 *
	 * The PT_INTERP program header references the string directly,
	 * so we add the section offset to the string offset.
	 */
	interp.phdr->p_offset = strsec->sec_shdr->sh_offset + str_offset;
	interp.phdr->p_filesz = str_size;
	elfedit_modified_phdr(obj_state);
	elfedit_msg(ELFEDIT_MSG_DEBUG, MSG_INTL(MSG_DEBUG_SETPHINTERP),
	    EC_WORD(interp.phndx), EC_XWORD(interp.phdr->p_offset),
	    EC_XWORD(interp.phdr->p_filesz));

	return (ELFEDIT_CMDRET_MOD);
}


/*
 * Common body for the phdr: module commands. These commands
 * share a large amount of common behavior, so it is convenient
 * to centralize things and use the cmd argument to handle the
 * small differences.
 *
 * entry:
 *	cmd - One of the PHDR_CMD_T_* constants listed above, specifying
 *		which command to implement.
 *	obj_state, argc, argv - Standard command arguments
 */
static elfedit_cmdret_t
cmd_body(PHDR_CMD_T cmd, elfedit_obj_state_t *obj_state,
    int argc, const char *argv[])
{
	ARGSTATE		argstate;
	Phdr			*phdr;
	elfedit_cmdret_t	ret = ELFEDIT_CMDRET_NONE;
	int			do_autoprint = 1;

	process_args(obj_state, argc, argv, cmd, &argstate);

	/* If this is a printing request, print and return */
	if (argstate.print_req) {
		print_phdr(cmd, 0, &argstate);
		return (ELFEDIT_CMDRET_NONE);
	}


	if (argstate.ndx_set)
		phdr = &argstate.obj_state->os_phdr[argstate.ndx];

	switch (cmd) {
		/*
		 * PHDR_CMD_T_DUMP can't get here: It never has more than
		 * one argument, and is handled above.
		 */

	case PHDR_CMD_T_P_TYPE:
		{
			Ehdr	*ehdr = obj_state->os_ehdr;
			uchar_t	osabi = ehdr->e_ident[EI_OSABI];
			Half	mach = ehdr->e_machine;
			Word p_type = elfedit_atoconst(argstate.argv[1],
			    ELFEDIT_CONST_PT);
			Conv_inv_buf_t inv_buf1, inv_buf2;

			if (phdr->p_type == p_type) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_S_OK),
				    argstate.ndx, MSG_ORIG(MSG_CMD_P_TYPE),
				    conv_phdr_type(osabi, mach, phdr->p_type,
				    0, &inv_buf1));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_S_CHG),
				    argstate.ndx, MSG_ORIG(MSG_CMD_P_TYPE),
				    conv_phdr_type(osabi, mach,
				    phdr->p_type, 0, &inv_buf1),
				    conv_phdr_type(osabi, mach,
				    p_type, 0, &inv_buf2));
				ret = ELFEDIT_CMDRET_MOD;
				phdr->p_type = p_type;
			}
		}
		break;

	case PHDR_CMD_T_P_OFFSET:
		{
			Off p_offset;

			p_offset = elfedit_atoui(argstate.argv[1], NULL);
			if (phdr->p_offset == p_offset) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_LLX_OK),
				    argstate.ndx, MSG_ORIG(MSG_CMD_P_OFFSET),
				    EC_XWORD(phdr->p_offset));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_LLX_CHG),
				    argstate.ndx, MSG_ORIG(MSG_CMD_P_OFFSET),
				    EC_XWORD(phdr->p_offset),
				    EC_XWORD(p_offset));
				ret = ELFEDIT_CMDRET_MOD;
				phdr->p_offset = p_offset;
			}
		}
		break;

	case PHDR_CMD_T_P_VADDR:
		{
			Addr p_vaddr = elfedit_atoui(argstate.argv[1], NULL);

			if (phdr->p_vaddr == p_vaddr) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_LLX_OK),
				    argstate.ndx, MSG_ORIG(MSG_CMD_P_VADDR),
				    EC_ADDR(phdr->p_vaddr));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_LLX_CHG),
				    argstate.ndx, MSG_ORIG(MSG_CMD_P_VADDR),
				    EC_ADDR(phdr->p_vaddr), EC_ADDR(p_vaddr));
				ret = ELFEDIT_CMDRET_MOD;
				phdr->p_vaddr = p_vaddr;
			}
		}
		break;

	case PHDR_CMD_T_P_PADDR:
		{
			Addr p_paddr = elfedit_atoui(argstate.argv[1], NULL);

			if (phdr->p_paddr == p_paddr) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_LLX_OK),
				    argstate.ndx, MSG_ORIG(MSG_CMD_P_PADDR),
				    EC_ADDR(phdr->p_paddr));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_LLX_CHG),
				    argstate.ndx, MSG_ORIG(MSG_CMD_P_PADDR),
				    EC_ADDR(phdr->p_paddr), EC_ADDR(p_paddr));
				ret = ELFEDIT_CMDRET_MOD;
				phdr->p_paddr = p_paddr;
			}
		}
		break;

	case PHDR_CMD_T_P_FILESZ:
		{
			Xword p_filesz = elfedit_atoui(argstate.argv[1], NULL);

			if (phdr->p_filesz == p_filesz) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_LLX_OK),
				    argstate.ndx, MSG_ORIG(MSG_CMD_P_FILESZ),
				    EC_XWORD(phdr->p_filesz));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_LLX_CHG),
				    argstate.ndx, MSG_ORIG(MSG_CMD_P_FILESZ),
				    EC_XWORD(phdr->p_filesz),
				    EC_XWORD(p_filesz));
				ret = ELFEDIT_CMDRET_MOD;
				phdr->p_filesz = p_filesz;
			}
		}
		break;

	case PHDR_CMD_T_P_MEMSZ:
		{
			Xword p_memsz = elfedit_atoui(argstate.argv[1], NULL);

			if (phdr->p_memsz == p_memsz) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_LLX_OK),
				    argstate.ndx, MSG_ORIG(MSG_CMD_P_MEMSZ),
				    EC_XWORD(phdr->p_memsz));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_LLX_CHG),
				    argstate.ndx, MSG_ORIG(MSG_CMD_P_MEMSZ),
				    EC_XWORD(phdr->p_memsz),
				    EC_XWORD(p_memsz));
				ret = ELFEDIT_CMDRET_MOD;
				phdr->p_memsz = p_memsz;
			}
		}
		break;

	case PHDR_CMD_T_P_FLAGS:
		{
			Ehdr	*ehdr = obj_state->os_ehdr;
			uchar_t	osabi = ehdr->e_ident[EI_OSABI];
			Conv_phdr_flags_buf_t buf1, buf2;
			Word	p_flags = 0;
			int	i;

						/* Collect the flag arguments */
			for (i = 1; i < argstate.argc; i++)
				p_flags |=
				    (Word) elfedit_atoconst(argstate.argv[i],
				    ELFEDIT_CONST_PF);

			/* Complement the value? */
			if (argstate.optmask & PHDR_OPT_F_CMP)
				p_flags = ~p_flags;

			/* Perform any requested bit operations */
			if (argstate.optmask & PHDR_OPT_F_AND)
				p_flags &= phdr->p_flags;
			else if (argstate.optmask & PHDR_OPT_F_OR)
				p_flags |= phdr->p_flags;

			/* Set the value */
			if (phdr->p_flags == p_flags) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_S_OK),
				    argstate.ndx, MSG_ORIG(MSG_CMD_P_FLAGS),
				    conv_phdr_flags(osabi, phdr->p_flags,
				    0, &buf1));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_S_CHG),
				    argstate.ndx, MSG_ORIG(MSG_CMD_P_FLAGS),
				    conv_phdr_flags(osabi, phdr->p_flags,
				    0, &buf1),
				    conv_phdr_flags(osabi, p_flags, 0, &buf2));
				ret = ELFEDIT_CMDRET_MOD;
				phdr->p_flags = p_flags;
			}
		}
		break;

	case PHDR_CMD_T_P_ALIGN:
		{
			Xword p_align = elfedit_atoui(argstate.argv[1], NULL);

			if (phdr->p_align == p_align) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_LLX_OK),
				    argstate.ndx, MSG_ORIG(MSG_CMD_P_ALIGN),
				    EC_XWORD(phdr->p_align));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_LLX_CHG),
				    argstate.ndx, MSG_ORIG(MSG_CMD_P_ALIGN),
				    EC_XWORD(phdr->p_align),
				    EC_XWORD(p_align));
				ret = ELFEDIT_CMDRET_MOD;
				phdr->p_align = p_align;
			}
		}
		break;

	case PHDR_CMD_T_INTERP:
		ret = cmd_body_set_interp(&argstate);
		break;

	case PHDR_CMD_T_DELETE:
		{
			Word cnt = (argstate.argc == 1) ? 1 :
			    (Word) elfedit_atoui_range(argstate.argv[1],
			    MSG_ORIG(MSG_STR_COUNT), 1,
			    obj_state->os_phnum - argstate.ndx, NULL);

			elfedit_array_elts_delete(MSG_ORIG(MSG_MOD_NAME),
			    obj_state->os_phdr, sizeof (Phdr),
			    obj_state->os_phnum, argstate.ndx, cnt);
			do_autoprint = 0;
			ret = ELFEDIT_CMDRET_MOD;
		}
		break;

	case PHDR_CMD_T_MOVE:
		{
			Phdr	save;
			Word	cnt;
			Word	dstndx;

			do_autoprint = 0;
			dstndx = (Word)
			    elfedit_atoui_range(argstate.argv[1],
			    MSG_ORIG(MSG_STR_DST_INDEX), 0,
			    obj_state->os_phnum - 1, NULL);
			if (argstate.argc == 2) {
				cnt = 1;
			} else {
				cnt = (Word) elfedit_atoui_range(
				    argstate.argv[2], MSG_ORIG(MSG_STR_COUNT),
				    1, obj_state->os_phnum, NULL);
			}
			elfedit_array_elts_move(MSG_ORIG(MSG_MOD_NAME),
			    obj_state->os_phdr, sizeof (save),
			    obj_state->os_phnum, argstate.ndx, dstndx,
			    cnt, &save);
			ret = ELFEDIT_CMDRET_MOD;
		}
		break;
	}

	/*
	 * If we modified the section header array, tell libelf.
	 */
	if (ret == ELFEDIT_CMDRET_MOD)
		elfedit_modified_phdr(obj_state);

	/* Do autoprint */
	if (do_autoprint)
		print_phdr(cmd, 1, &argstate);

	return (ret);
}



/*
 * Command completion functions for the various commands
 */

/*
 * A number of the commands accept a PT_ constant as their first
 * argument as long as the -phndx option is not used.
 */
/*ARGSUSED*/
static void
cpl_1starg_pt(elfedit_obj_state_t *obj_state, void *cpldata, int argc,
    const char *argv[], int num_opt)
{
	int i;

	for (i = 0; i < num_opt; i++)
		if (strcmp(MSG_ORIG(MSG_STR_MINUS_PHNDX), argv[i]) == 0)
			return;

	if (argc == (num_opt + 1))
		elfedit_cpl_atoconst(cpldata, ELFEDIT_CONST_PT);
}

/*ARGSUSED*/
static void
cpl_p_type(elfedit_obj_state_t *obj_state, void *cpldata, int argc,
    const char *argv[], int num_opt)
{
	/* The first argument follows the standard rules */
	cpl_1starg_pt(obj_state, cpldata, argc, argv, num_opt);

	/* The second argument can be a PT_ value */
	if (argc == (num_opt + 2))
		elfedit_cpl_atoconst(cpldata, ELFEDIT_CONST_PT);
}


/*ARGSUSED*/
static void
cpl_p_flags(elfedit_obj_state_t *obj_state, void *cpldata, int argc,
    const char *argv[], int num_opt)
{
	/* The first argument follows the standard rules */
	cpl_1starg_pt(obj_state, cpldata, argc, argv, num_opt);

	/* The second and following arguments can be an PF_ value */
	if (argc >= (num_opt + 2))
		elfedit_cpl_atoconst(cpldata, ELFEDIT_CONST_PF);
}



/*
 * Implementation functions for the commands
 */
static elfedit_cmdret_t
cmd_dump(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(PHDR_CMD_T_DUMP, obj_state, argc, argv));
}

static elfedit_cmdret_t
cmd_p_type(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(PHDR_CMD_T_P_TYPE, obj_state, argc, argv));
}

static elfedit_cmdret_t
cmd_p_offset(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(PHDR_CMD_T_P_OFFSET, obj_state, argc, argv));
}

static elfedit_cmdret_t
cmd_p_vaddr(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(PHDR_CMD_T_P_VADDR, obj_state, argc, argv));
}

static elfedit_cmdret_t
cmd_p_paddr(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(PHDR_CMD_T_P_PADDR, obj_state, argc, argv));
}

static elfedit_cmdret_t
cmd_p_filesz(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(PHDR_CMD_T_P_FILESZ, obj_state, argc, argv));
}

static elfedit_cmdret_t
cmd_p_memsz(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(PHDR_CMD_T_P_MEMSZ, obj_state, argc, argv));
}

static elfedit_cmdret_t
cmd_p_flags(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(PHDR_CMD_T_P_FLAGS, obj_state, argc, argv));
}

static elfedit_cmdret_t
cmd_p_align(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(PHDR_CMD_T_P_ALIGN, obj_state, argc, argv));
}

static elfedit_cmdret_t
cmd_interp(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(PHDR_CMD_T_INTERP, obj_state, argc, argv));
}

static elfedit_cmdret_t
cmd_delete(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(PHDR_CMD_T_DELETE, obj_state, argc, argv));
}

static elfedit_cmdret_t
cmd_move(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(PHDR_CMD_T_MOVE, obj_state, argc, argv));
}


/*ARGSUSED*/
elfedit_module_t *
elfedit_init(elfedit_module_version_t version)
{
	/* Multiple commands accept a standard set of options */
	static elfedit_cmd_optarg_t opt_std[] = {
		{ ELFEDIT_STDOA_OPT_O, 0,
		    ELFEDIT_CMDOA_F_INHERIT, 0, 0 },
		{ MSG_ORIG(MSG_STR_MINUS_PHNDX),
		    /* MSG_INTL(MSG_OPTDESC_PHNDX) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_PHNDX), 0,
		    PHDR_OPT_F_PHNDX, 0 },
		{ NULL }
	};

	/* For commands that only accept -phndx */
	static elfedit_cmd_optarg_t opt_minus_phndx[] = {
		{ MSG_ORIG(MSG_STR_MINUS_PHNDX),
		    /* MSG_INTL(MSG_OPTDESC_PHNDX) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_PHNDX), 0,
		    PHDR_OPT_F_PHNDX, 0 },
		{ NULL }
	};


	/* phdr:dump */
	static const char *name_dump[] = {
	    MSG_ORIG(MSG_CMD_DUMP),
	    MSG_ORIG(MSG_STR_EMPTY),	/* "" makes this the default command */
	    NULL
	};
	static elfedit_cmd_optarg_t arg_dump[] = {
		{ MSG_ORIG(MSG_STR_ELEMENT),
		    /* MSG_INTL(MSG_A1_ELEMENT) */
		    ELFEDIT_I18NHDL(MSG_A1_ELEMENT),
		    ELFEDIT_CMDOA_F_OPT },
		{ NULL }
	};

	/* phdr:p_type */
	static const char *name_p_type[] = { MSG_ORIG(MSG_CMD_P_TYPE), NULL };
	static elfedit_cmd_optarg_t arg_p_type[] = {
		{ MSG_ORIG(MSG_STR_ELEMENT),
		    /* MSG_INTL(MSG_A1_ELEMENT) */
		    ELFEDIT_I18NHDL(MSG_A1_ELEMENT),
		    ELFEDIT_CMDOA_F_OPT },
		{ MSG_ORIG(MSG_STR_TYPE),
		    /* MSG_INTL(MSG_A2_P_TYPE_TYPE) */
		    ELFEDIT_I18NHDL(MSG_A2_P_TYPE_TYPE),
		    ELFEDIT_CMDOA_F_OPT },
		{ NULL }
	};

	/* phdr:p_offset */
	static const char *name_p_offset[] = { MSG_ORIG(MSG_CMD_P_OFFSET),
	    NULL };
	static elfedit_cmd_optarg_t arg_p_offset[] = {
		{ MSG_ORIG(MSG_STR_ELEMENT),
		    /* MSG_INTL(MSG_A1_ELEMENT) */
		    ELFEDIT_I18NHDL(MSG_A1_ELEMENT),
		    ELFEDIT_CMDOA_F_OPT },
		{ MSG_ORIG(MSG_STR_VALUE),
		    /* MSG_INTL(MSG_A2_P_OFFSET_VALUE) */
		    ELFEDIT_I18NHDL(MSG_A2_P_OFFSET_VALUE),
		    ELFEDIT_CMDOA_F_OPT },
		{ NULL }
	};

	/* phdr:p_vaddr */
	static const char *name_p_vaddr[] = { MSG_ORIG(MSG_CMD_P_VADDR),
	    NULL };
	static elfedit_cmd_optarg_t arg_p_vaddr[] = {
		{ MSG_ORIG(MSG_STR_ELEMENT),
		    /* MSG_INTL(MSG_A1_ELEMENT) */
		    ELFEDIT_I18NHDL(MSG_A1_ELEMENT),
		    ELFEDIT_CMDOA_F_OPT },
		{ MSG_ORIG(MSG_STR_ADDR),
		    /* MSG_INTL(MSG_A2_P_VADDR_ADDR) */
		    ELFEDIT_I18NHDL(MSG_A2_P_VADDR_ADDR),
		    ELFEDIT_CMDOA_F_OPT },
		{ NULL }
	};

	/* phdr:p_paddr */
	static const char *name_p_paddr[] = { MSG_ORIG(MSG_CMD_P_PADDR),
	    NULL };
	static elfedit_cmd_optarg_t arg_p_paddr[] = {
		{ MSG_ORIG(MSG_STR_ELEMENT),
		    /* MSG_INTL(MSG_A1_ELEMENT) */
		    ELFEDIT_I18NHDL(MSG_A1_ELEMENT),
		    ELFEDIT_CMDOA_F_OPT },
		{ MSG_ORIG(MSG_STR_ADDR),
		    /* MSG_INTL(MSG_A2_P_PADDR_ADDR) */
		    ELFEDIT_I18NHDL(MSG_A2_P_PADDR_ADDR),
		    ELFEDIT_CMDOA_F_OPT },
		{ NULL }
	};

	/* phdr:p_filesz */
	static const char *name_p_filesz[] = { MSG_ORIG(MSG_CMD_P_FILESZ),
	    NULL };
	static elfedit_cmd_optarg_t arg_p_filesz[] = {
	    /* MSG_INTL(MSG_A1_ELEMENT) */
		{ MSG_ORIG(MSG_STR_ELEMENT), ELFEDIT_I18NHDL(MSG_A1_ELEMENT),
		    ELFEDIT_CMDOA_F_OPT },
		{ MSG_ORIG(MSG_STR_SIZE),
		    /* MSG_INTL(MSG_A2_P_FILESZ_SIZE) */
		    ELFEDIT_I18NHDL(MSG_A2_P_FILESZ_SIZE),
		    ELFEDIT_CMDOA_F_OPT },
		{ NULL }
	};

	/* phdr:p_memsz */
	static const char *name_p_memsz[] = { MSG_ORIG(MSG_CMD_P_MEMSZ),
	    NULL };
	static elfedit_cmd_optarg_t arg_p_memsz[] = {
		{ MSG_ORIG(MSG_STR_ELEMENT),
		    /* MSG_INTL(MSG_A1_ELEMENT) */
		    ELFEDIT_I18NHDL(MSG_A1_ELEMENT),
		    ELFEDIT_CMDOA_F_OPT },
		{ MSG_ORIG(MSG_STR_SIZE),
		    /* MSG_INTL(MSG_A2_P_MEMSZ_SIZE) */
		    ELFEDIT_I18NHDL(MSG_A2_P_MEMSZ_SIZE),
		    ELFEDIT_CMDOA_F_OPT },
		{ NULL }
	};

	/* shdr:p_flags */
	static const char *name_p_flags[] = {
	    MSG_ORIG(MSG_CMD_P_FLAGS), NULL };
	static elfedit_cmd_optarg_t opt_p_flags[] = {
		{ ELFEDIT_STDOA_OPT_AND, 0,
		    ELFEDIT_CMDOA_F_INHERIT, PHDR_OPT_F_AND, PHDR_OPT_F_OR },
		{ ELFEDIT_STDOA_OPT_CMP, 0,
		    ELFEDIT_CMDOA_F_INHERIT, PHDR_OPT_F_CMP, 0 },
		{ MSG_ORIG(MSG_STR_MINUS_PHNDX),
		    /* MSG_INTL(MSG_OPTDESC_PHNDX) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_PHNDX), 0,
		    PHDR_OPT_F_PHNDX, 0 },
		{ ELFEDIT_STDOA_OPT_O, 0,
		    ELFEDIT_CMDOA_F_INHERIT, 0, 0 },
		{ ELFEDIT_STDOA_OPT_OR, 0,
		    ELFEDIT_CMDOA_F_INHERIT, PHDR_OPT_F_OR, PHDR_OPT_F_AND },
		{ NULL }
	};
	static elfedit_cmd_optarg_t arg_p_flags[] = {
		{ MSG_ORIG(MSG_STR_ELEMENT),
		    /* MSG_INTL(MSG_A1_ELEMENT) */
		    ELFEDIT_I18NHDL(MSG_A1_ELEMENT),
		    ELFEDIT_CMDOA_F_OPT },
		{ MSG_ORIG(MSG_STR_VALUE),
		    /* MSG_INTL(MSG_A2_P_FLAGS_VALUE) */
		    ELFEDIT_I18NHDL(MSG_A2_P_FLAGS_VALUE),
		    ELFEDIT_CMDOA_F_OPT | ELFEDIT_CMDOA_F_MULT },
		{ NULL }
	};

	/* phdr:p_align */
	static const char *name_p_align[] = { MSG_ORIG(MSG_CMD_P_ALIGN),
	    NULL };
	static elfedit_cmd_optarg_t arg_p_align[] = {
		{ MSG_ORIG(MSG_STR_ELEMENT),
		    /* MSG_INTL(MSG_A1_ELEMENT) */
		    ELFEDIT_I18NHDL(MSG_A1_ELEMENT),
		    ELFEDIT_CMDOA_F_OPT },
		{ MSG_ORIG(MSG_STR_ALIGN),
		    /* MSG_INTL(MSG_A2_P_ALIGN_ALIGN) */
		    ELFEDIT_I18NHDL(MSG_A2_P_ALIGN_ALIGN),
		    ELFEDIT_CMDOA_F_OPT },
		{ NULL }
	};

	/* phdr:interp */
	static const char *name_interp[] = { MSG_ORIG(MSG_CMD_INTERP), NULL };
	static elfedit_cmd_optarg_t opt_interp[] = {
		{ ELFEDIT_STDOA_OPT_O, 0,
		    ELFEDIT_CMDOA_F_INHERIT, 0, 0 },
		{ NULL }
	};
	static elfedit_cmd_optarg_t arg_interp[] = {
		{ MSG_ORIG(MSG_STR_NEWPATH),
		    /* MSG_INTL(MSG_A1_INTERP_NEWPATH) */
		    ELFEDIT_I18NHDL(MSG_A1_INTERP_NEWPATH),
		    ELFEDIT_CMDOA_F_OPT },
		{ NULL }
	};

	/* phdr:delete */
	static const char *name_delete[] = { MSG_ORIG(MSG_CMD_DELETE), NULL };
	static elfedit_cmd_optarg_t arg_delete[] = {
		{ MSG_ORIG(MSG_STR_ELEMENT),
		    /* MSG_INTL(MSG_A1_ELEMENT) */
		    ELFEDIT_I18NHDL(MSG_A1_ELEMENT),
		    0 },
		{ MSG_ORIG(MSG_STR_COUNT),
		    /* MSG_INTL(MSG_A2_DELETE_COUNT) */
		    ELFEDIT_I18NHDL(MSG_A2_DELETE_COUNT),
		    ELFEDIT_CMDOA_F_OPT },
		{ NULL }
	};

	/* phdr:move */
	static const char *name_move[] = { MSG_ORIG(MSG_CMD_MOVE), NULL };
	static elfedit_cmd_optarg_t arg_move[] = {
		{ MSG_ORIG(MSG_STR_ELEMENT),
		    /* MSG_INTL(MSG_A1_ELEMENT) */
		    ELFEDIT_I18NHDL(MSG_A1_ELEMENT),
		    ELFEDIT_CMDOA_F_OPT },
		{ MSG_ORIG(MSG_STR_DST_INDEX),
		    /* MSG_INTL(MSG_A2_MOVE_DST_INDEX) */
		    ELFEDIT_I18NHDL(MSG_A2_MOVE_DST_INDEX),
		    0 },
		{ MSG_ORIG(MSG_STR_COUNT),
		    /* MSG_INTL(MSG_A3_MOVE_COUNT) */
		    ELFEDIT_I18NHDL(MSG_A3_MOVE_COUNT),
		    ELFEDIT_CMDOA_F_OPT },
		{ NULL }
	};

	static elfedit_cmd_t cmds[] = {
		/* phdr:dump */
		{ cmd_dump, cpl_1starg_pt, name_dump,
		    /* MSG_INTL(MSG_DESC_DUMP) */
		    ELFEDIT_I18NHDL(MSG_DESC_DUMP),
		    /* MSG_INTL(MSG_HELP_DUMP) */
		    ELFEDIT_I18NHDL(MSG_HELP_DUMP),
		    opt_minus_phndx, arg_dump },

		/* phdr:p_type */
		{ cmd_p_type, cpl_p_type, name_p_type,
		    /* MSG_INTL(MSG_DESC_P_TYPE) */
		    ELFEDIT_I18NHDL(MSG_DESC_P_TYPE),
		    /* MSG_INTL(MSG_HELP_P_TYPE) */
		    ELFEDIT_I18NHDL(MSG_HELP_P_TYPE),
		    opt_std, arg_p_type },

		/* phdr:p_offset */
		{ cmd_p_offset, cpl_1starg_pt, name_p_offset,
		    /* MSG_INTL(MSG_DESC_P_OFFSET) */
		    ELFEDIT_I18NHDL(MSG_DESC_P_OFFSET),
		    /* MSG_INTL(MSG_HELP_P_OFFSET) */
		    ELFEDIT_I18NHDL(MSG_HELP_P_OFFSET),
		    opt_std, arg_p_offset },

		/* phdr:p_vaddr */
		{ cmd_p_vaddr, cpl_1starg_pt, name_p_vaddr,
		    /* MSG_INTL(MSG_DESC_P_VADDR) */
		    ELFEDIT_I18NHDL(MSG_DESC_P_VADDR),
		    /* MSG_INTL(MSG_HELP_P_VADDR) */
		    ELFEDIT_I18NHDL(MSG_HELP_P_VADDR),
		    opt_std, arg_p_vaddr },

		/* phdr:p_paddr */
		{ cmd_p_paddr, cpl_1starg_pt, name_p_paddr,
		    /* MSG_INTL(MSG_DESC_P_PADDR) */
		    ELFEDIT_I18NHDL(MSG_DESC_P_PADDR),
		    /* MSG_INTL(MSG_HELP_P_PADDR) */
		    ELFEDIT_I18NHDL(MSG_HELP_P_PADDR),
		    opt_std, arg_p_paddr },

		/* phdr:p_filesz */
		{ cmd_p_filesz, cpl_1starg_pt, name_p_filesz,
		    /* MSG_INTL(MSG_DESC_P_FILESZ) */
		    ELFEDIT_I18NHDL(MSG_DESC_P_FILESZ),
		    /* MSG_INTL(MSG_HELP_P_FILESZ) */
		    ELFEDIT_I18NHDL(MSG_HELP_P_FILESZ),
		    opt_std, arg_p_filesz },

		/* phdr:p_memsz */
		{ cmd_p_memsz, cpl_1starg_pt, name_p_memsz,
		    /* MSG_INTL(MSG_DESC_P_MEMSZ) */
		    ELFEDIT_I18NHDL(MSG_DESC_P_MEMSZ),
		    /* MSG_INTL(MSG_HELP_P_MEMSZ) */
		    ELFEDIT_I18NHDL(MSG_HELP_P_MEMSZ),
		    opt_std, arg_p_memsz },

		/* phdr:p_flags */
		{ cmd_p_flags, cpl_p_flags, name_p_flags,
		    /* MSG_INTL(MSG_DESC_P_FLAGS) */
		    ELFEDIT_I18NHDL(MSG_DESC_P_FLAGS),
		    /* MSG_INTL(MSG_HELP_P_FLAGS) */
		    ELFEDIT_I18NHDL(MSG_HELP_P_FLAGS),
		    opt_p_flags, arg_p_flags },

		/* phdr:p_align */
		{ cmd_p_align, cpl_1starg_pt, name_p_align,
		    /* MSG_INTL(MSG_DESC_P_ALIGN) */
		    ELFEDIT_I18NHDL(MSG_DESC_P_ALIGN),
		    /* MSG_INTL(MSG_HELP_P_ALIGN) */
		    ELFEDIT_I18NHDL(MSG_HELP_P_ALIGN),
		    opt_std, arg_p_align },

		/* phdr:interp */
		{ cmd_interp, NULL, name_interp,
		    /* MSG_INTL(MSG_DESC_INTERP) */
		    ELFEDIT_I18NHDL(MSG_DESC_INTERP),
		    /* MSG_INTL(MSG_HELP_INTERP) */
		    ELFEDIT_I18NHDL(MSG_HELP_INTERP),
		    opt_interp, arg_interp },

		/* phdr:delete */
		{ cmd_delete, cpl_1starg_pt, name_delete,
		    /* MSG_INTL(MSG_DESC_DELETE) */
		    ELFEDIT_I18NHDL(MSG_DESC_DELETE),
		    /* MSG_INTL(MSG_HELP_DELETE) */
		    ELFEDIT_I18NHDL(MSG_HELP_DELETE),
		    opt_minus_phndx, arg_delete },

		/* phdr:move */
		{ cmd_move, cpl_1starg_pt, name_move,
		    /* MSG_INTL(MSG_DESC_MOVE) */
		    ELFEDIT_I18NHDL(MSG_DESC_MOVE),
		    /* MSG_INTL(MSG_HELP_MOVE) */
		    ELFEDIT_I18NHDL(MSG_HELP_MOVE),
		    opt_minus_phndx, arg_move },

		{ NULL }
	};

	static elfedit_module_t module = {
	    ELFEDIT_VER_CURRENT, MSG_ORIG(MSG_MOD_NAME),
	    /* MSG_INTL(MSG_MOD_DESC) */
	    ELFEDIT_I18NHDL(MSG_MOD_DESC),
	    cmds, mod_i18nhdl_to_str };

	return (&module);
}
