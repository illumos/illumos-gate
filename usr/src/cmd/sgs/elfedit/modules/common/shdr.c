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
#include	<sys/elf_SPARC.h>
#include	<sys/elf_amd64.h>
#include	<strings.h>
#include	<debug.h>
#include	<conv.h>
#include	<shdr_msg.h>




/*
 * This module uses shared code for several of the commands.
 * It is sometimes necessary to know which specific command
 * is active.
 */
typedef enum {
	SHDR_CMD_T_DUMP =		0,	/* shdr:dump */

	SHDR_CMD_T_SH_ADDR =		1,	/* shdr:sh_addr */
	SHDR_CMD_T_SH_ADDRALIGN =	2,	/* shdr:sh_addralign */
	SHDR_CMD_T_SH_ENTSIZE =		3,	/* shdr:sh_entsize */
	SHDR_CMD_T_SH_FLAGS =		4,	/* shdr:sh_flags */
	SHDR_CMD_T_SH_INFO =		5,	/* shdr:sh_info */
	SHDR_CMD_T_SH_LINK =		6,	/* shdr:sh_link */
	SHDR_CMD_T_SH_NAME =		7,	/* shdr:sh_name */
	SHDR_CMD_T_SH_OFFSET =		8,	/* shdr:sh_offset */
	SHDR_CMD_T_SH_SIZE =		9,	/* shdr:sh_size */
	SHDR_CMD_T_SH_TYPE =		10	/* shdr:sh_type */
} SHDR_CMD_T;



#ifndef _ELF64
/*
 * We supply this function for the msg module. Only one copy is needed.
 */
const char *
_shdr_msg(Msg mid)
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
 * The shdr_opt_t enum specifies a bit value for every optional
 * argument allowed by a command in this module.
 */
typedef enum {
	SHDR_OPT_F_AND =	1,	/* -and: AND (&) values to dest */
	SHDR_OPT_F_CMP =	2,	/* -cmp: Complement (~) values */
	SHDR_OPT_F_NAMOFFSET =	4,	/* -name_offset: Name arg is numeric */
					/*	 ofset rather than string */
	SHDR_OPT_F_OR =		8,	/* -or: OR (|) values to dest */
	SHDR_OPT_F_SHNDX =	16,	/* -shndx: Section by index, not name */
	SHDR_OPT_F_SHTYP =	32,	/* -shtyp: Section by type, not name */
	SHDR_OPT_F_VALUE_SHNAM = 64,	/* -value_shnam: Value of sh_info or */
					/*	sh_link given as section name */
	SHDR_OPT_F_VALUE_SHTYP = 128	/* -value_shtyp: Value of sh_info or */
					/*	sh_link given as section type */
} shdr_opt_t;


/*
 * A variable of type ARGSTATE is used by each command to maintain
 * information about the section headers and related things. It is
 * initialized by process_args(), and used by the other routines.
 */
typedef struct {
	elfedit_obj_state_t	*obj_state;
	shdr_opt_t		optmask;	/* Mask of options used */
	int			argc;		/* # of plain arguments */
	const char		**argv;		/* Plain arguments */
} ARGSTATE;




/*
 * Standard argument processing for shdr module
 *
 * entry
 *	obj_state, argc, argv - Standard command arguments
 *	optmask - Mask of allowed optional arguments.
 *	cmd - SHDR_CMD_T_* value giving identify of caller
 *	argstate - Address of ARGSTATE block to be initialized
 *
 * exit:
 *	On success, *argstate is initialized. On error,
 *	an error is issued and this routine does not return.
 */
static void
process_args(elfedit_obj_state_t *obj_state, int argc, const char *argv[],
    SHDR_CMD_T cmd, ARGSTATE *argstate)
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
	case SHDR_CMD_T_DUMP:
		if (argc > 1)
			elfedit_command_usage();
		break;
	case SHDR_CMD_T_SH_FLAGS:
		/* shdr:sh_flags allows an arbitrary number of arguments */
		break;
	default:
		/* The remaining commands accept 2 plain arguments */
		if (argc > 2)
			elfedit_command_usage();
		break;
	}

	/* If there may be an arbitrary amount of output, use a pager */
	if (argc == 0)
		elfedit_pager_init();

	/* Return the updated values of argc/argv */
	argstate->argc = argc;
	argstate->argv = argv;
}



/*
 * Options for deciding which items print_shdr() displays.
 */
typedef enum {
	PRINT_SHDR_ALL,		/* Print all shdr[ndx:ndx+cnt-1] */
	PRINT_SHDR_TYPE,	/* Print all shdr[ndx:ndx+cnt-1] with type */
				/*	 of shdr[ndx] */
	PRINT_SHDR_NAME,	/* Print all shdr[ndx:ndx+cnt-1] with name */
				/*	 of shdr[ndx] */
} PRINT_SHDR_T;

/*
 * Print section header values, taking the calling command, and output style
 * into account.
 *
 * entry:
 *	autoprint - If True, output is only produced if the elfedit
 *		autoprint flag is set. If False, output is always produced.
 *	cmd - SHDR_CMD_T_* value giving identify of caller
 *	argstate - State block for section header array
 *	ndx - Index of first section to display
 *	cnt - Number of sections to display
 *	print_type - Specifies which items are shown
 */
static void
print_shdr(SHDR_CMD_T cmd, int autoprint, ARGSTATE *argstate,
    Word ndx, Word cnt, PRINT_SHDR_T print_type)
{
	elfedit_outstyle_t	outstyle;
	Ehdr			*ehdr = argstate->obj_state->os_ehdr;
	uchar_t			osabi = ehdr->e_ident[EI_OSABI];
	Half			mach = ehdr->e_machine;
	elfedit_section_t	*ref_sec = &argstate->obj_state->os_secarr[ndx];


	if ((autoprint && ((elfedit_flags() & ELFEDIT_F_AUTOPRINT) == 0)) ||
	    (cnt == 0))
		return;

	/*
	 * Pick an output style. shdr:dump is required to use the default
	 * style. The other commands use the current output style.
	 */
	outstyle = (cmd == SHDR_CMD_T_DUMP) ?
	    ELFEDIT_OUTSTYLE_DEFAULT : elfedit_outstyle();

	for (; cnt--; ndx++) {
		elfedit_section_t *sec = &argstate->obj_state->os_secarr[ndx];
		Shdr *shdr = sec->sec_shdr;

		switch (print_type) {
		case PRINT_SHDR_TYPE:
			if (shdr->sh_type != ref_sec->sec_shdr->sh_type)
				continue;
			break;

		case PRINT_SHDR_NAME:
			if (strcmp(sec->sec_name, ref_sec->sec_name) != 0)
				continue;
			break;
		}

		/*
		 * If doing default output, use elfdump style where we
		 * show all section header attributes. In this case, the
		 * command that called us doesn't matter
		 */
		if (outstyle == ELFEDIT_OUTSTYLE_DEFAULT) {
			elfedit_printf(MSG_ORIG(MSG_STR_NL));
			elfedit_printf(MSG_INTL(MSG_ELF_SHDR), ndx,
			    sec->sec_name);
			Elf_shdr(NULL, osabi, mach, sec->sec_shdr);
			continue;
		}

		/* Non-default output is handled case by case */
		switch (cmd) {
		case SHDR_CMD_T_SH_ADDR:
			elfedit_printf(MSG_ORIG(MSG_FMT_XWORDHEXNL),
			    EC_XWORD(shdr->sh_addr));
			break;

		case SHDR_CMD_T_SH_ADDRALIGN:
			elfedit_printf(MSG_ORIG(MSG_FMT_XWORDHEXNL),
			    EC_XWORD(shdr->sh_addralign));
			break;

		case SHDR_CMD_T_SH_ENTSIZE:
			elfedit_printf(MSG_ORIG(MSG_FMT_XWORDHEXNL),
			    EC_XWORD(shdr->sh_entsize));
			break;

		case SHDR_CMD_T_SH_FLAGS:
			if (outstyle == ELFEDIT_OUTSTYLE_SIMPLE) {
				Conv_sec_flags_buf_t sec_flags_buf;

				elfedit_printf(MSG_ORIG(MSG_FMT_STRNL),
				    conv_sec_flags(osabi, mach, shdr->sh_flags,
				    CONV_FMT_NOBKT, &sec_flags_buf));
			} else {
				elfedit_printf(MSG_ORIG(MSG_FMT_XWORDHEXNL),
				    EC_XWORD(shdr->sh_flags));
			}
			break;

		case SHDR_CMD_T_SH_INFO:
			elfedit_printf(MSG_ORIG(MSG_FMT_WORDVALNL),
			    EC_WORD(shdr->sh_info));
			break;

		case SHDR_CMD_T_SH_LINK:
			elfedit_printf(MSG_ORIG(MSG_FMT_WORDVALNL),
			    EC_WORD(shdr->sh_link));
			break;

		case SHDR_CMD_T_SH_NAME:
			/*
			 * In simple output mode, we show the string. In
			 * numeric mode, we show the string table offset.
			 */
			if (outstyle == ELFEDIT_OUTSTYLE_SIMPLE) {
				elfedit_printf(MSG_ORIG(MSG_FMT_STRNL),
				    sec->sec_name);
			} else {
				elfedit_printf(MSG_ORIG(MSG_FMT_WORDVALNL),
				    EC_WORD(shdr->sh_name));
			}
			break;

		case SHDR_CMD_T_SH_OFFSET:
			elfedit_printf(MSG_ORIG(MSG_FMT_XWORDHEXNL),
			    EC_XWORD(shdr->sh_offset));
			break;

		case SHDR_CMD_T_SH_SIZE:
			elfedit_printf(MSG_ORIG(MSG_FMT_XWORDHEXNL),
			    EC_XWORD(shdr->sh_size));
			break;

		case SHDR_CMD_T_SH_TYPE:
			if (outstyle == ELFEDIT_OUTSTYLE_SIMPLE) {
				Conv_inv_buf_t inv_buf;

				elfedit_printf(MSG_ORIG(MSG_FMT_STRNL),
				    conv_sec_type(osabi, mach, shdr->sh_type, 0,
				    &inv_buf));
			} else {
				elfedit_printf(MSG_ORIG(MSG_FMT_WORDHEXNL),
				    EC_WORD(shdr->sh_type));
			}
			break;
		}
	}
}


/*
 * Common body for the shdr: module commands. These commands
 * share a large amount of common behavior, so it is convenient
 * to centralize things and use the cmd argument to handle the
 * small differences.
 *
 * entry:
 *	cmd - One of the SHDR_CMD_T_* constants listed above, specifying
 *		which command to implement.
 *	obj_state, argc, argv - Standard command arguments
 */
static elfedit_cmdret_t
cmd_body(SHDR_CMD_T cmd, elfedit_obj_state_t *obj_state,
    int argc, const char *argv[])
{
	Ehdr			*ehdr = obj_state->os_ehdr;
	uchar_t			osabi = ehdr->e_ident[EI_OSABI];
	Half			mach = ehdr->e_machine;
	ARGSTATE		argstate;
	Word			ndx;
	elfedit_section_t	*shdr_sec;
	Shdr			*shdr;
	elfedit_cmdret_t	ret = ELFEDIT_CMDRET_NONE;
	PRINT_SHDR_T		print_type;

	process_args(obj_state, argc, argv, cmd, &argstate);

	/* If there are no arguments, dump the whole table and return */
	if (argstate.argc == 0) {
		print_shdr(cmd, 0, &argstate, 0, obj_state->os_shnum,
		    PRINT_SHDR_ALL);
		return (ELFEDIT_CMDRET_NONE);
	}

	/*
	 * The first argument gives the section to use. This can be a
	 * name (default), section index, or section type, depending on
	 * the options used.
	 */
	if (argstate.optmask & SHDR_OPT_F_SHNDX) {
		ndx = elfedit_atoshndx(argstate.argv[0], obj_state->os_shnum);
		print_type = PRINT_SHDR_ALL;
	} else if (argstate.optmask & SHDR_OPT_F_SHTYP) {
		ndx = elfedit_type_to_shndx(obj_state,
		    elfedit_atoconst(argstate.argv[0], ELFEDIT_CONST_SHT));
		print_type = PRINT_SHDR_TYPE;
	} else {
		ndx = elfedit_name_to_shndx(obj_state, argstate.argv[0]);
		print_type = PRINT_SHDR_NAME;
	}

	/* If there is a single argument, display that item and return */
	if (argstate.argc == 1) {
		Word	cnt;

		cnt = (print_type == PRINT_SHDR_ALL) ?
		    1 : obj_state->os_shnum - ndx;
		print_shdr(cmd, 0, &argstate, ndx, cnt, print_type);
		return (ELFEDIT_CMDRET_NONE);
	}

	/*
	 * Section [0] is supposed to be all zero unless extended sections
	 * are in force. Rather than setting extended values directly,
	 * it is expected to be handled by libelf. So, a direct change here
	 * is probably not what was intended.
	 */
	if (ndx == 0)
		elfedit_msg(ELFEDIT_MSG_DEBUG, MSG_INTL(MSG_DEBUG_CHGSHDR0));

	/* The second value is an integer giving a new value */
	shdr_sec = &obj_state->os_secarr[ndx];
	shdr = shdr_sec->sec_shdr;
	switch (cmd) {
		/*
		 * SHDR_CMD_T_DUMP can't get here: It never has more than
		 * one argument, and is handled above.
		 */

	case SHDR_CMD_T_SH_ADDR:
		{
			Addr sh_addr = elfedit_atoui(argstate.argv[1], NULL);

			if (shdr->sh_addr == sh_addr) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_LLX_OK),
				    ndx, shdr_sec->sec_name,
				    MSG_ORIG(MSG_CMD_SH_ADDR),
				    EC_ADDR(shdr->sh_addr));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_LLX_CHG),
				    ndx, shdr_sec->sec_name,
				    MSG_ORIG(MSG_CMD_SH_ADDR),
				    EC_ADDR(shdr->sh_addr), EC_ADDR(sh_addr));
				ret = ELFEDIT_CMDRET_MOD;
				shdr->sh_addr = sh_addr;
			}
		}
		break;

	case SHDR_CMD_T_SH_ADDRALIGN:
		{
			Xword	sh_addralign;

			sh_addralign = elfedit_atoui(argstate.argv[1], NULL);
			if (elfedit_bits_set(sh_addralign,
			    sizeof (sh_addralign)) > 1)
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_ADDRALIGN),
				    argstate.argv[1]);
			if (shdr->sh_addralign == sh_addralign) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_LLX_OK),
				    ndx, shdr_sec->sec_name,
				    MSG_ORIG(MSG_CMD_SH_ADDRALIGN),
				    EC_XWORD(shdr->sh_addralign));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_LLX_CHG),
				    ndx, shdr_sec->sec_name,
				    MSG_ORIG(MSG_CMD_SH_ADDRALIGN),
				    EC_XWORD(shdr->sh_addralign),
				    EC_XWORD(sh_addralign));
				ret = ELFEDIT_CMDRET_MOD;
				shdr->sh_addralign = sh_addralign;
			}
		}
		break;

	case SHDR_CMD_T_SH_ENTSIZE:
		{
			Xword sh_entsize;

			sh_entsize = elfedit_atoui(argstate.argv[1], NULL);
			if (shdr->sh_entsize == sh_entsize) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_LLX_OK),
				    ndx, shdr_sec->sec_name,
				    MSG_ORIG(MSG_CMD_SH_ENTSIZE),
				    EC_XWORD(shdr->sh_entsize));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_LLX_CHG),
				    ndx, shdr_sec->sec_name,
				    MSG_ORIG(MSG_CMD_SH_ENTSIZE),
				    EC_XWORD(shdr->sh_entsize),
				    EC_XWORD(sh_entsize));
				ret = ELFEDIT_CMDRET_MOD;
				shdr->sh_entsize = sh_entsize;
			}
		}
		break;

	case SHDR_CMD_T_SH_FLAGS:
		{
			Conv_sec_flags_buf_t buf1, buf2;
			Word	sh_flags = 0;
			int	i;

						/* Collect the flag arguments */
			for (i = 1; i < argstate.argc; i++)
				sh_flags |=
				    (Word) elfedit_atoconst(argstate.argv[i],
				    ELFEDIT_CONST_SHF);

			/* Complement the value? */
			if (argstate.optmask & SHDR_OPT_F_CMP)
				sh_flags = ~sh_flags;

			/* Perform any requested bit operations */
			if (argstate.optmask & SHDR_OPT_F_AND)
				sh_flags &= shdr->sh_flags;
			else if (argstate.optmask & SHDR_OPT_F_OR)
				sh_flags |= shdr->sh_flags;

			/* Set the value */
			if (shdr->sh_flags == sh_flags) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_S_OK),
				    ndx, shdr_sec->sec_name,
				    MSG_ORIG(MSG_CMD_SH_FLAGS),
				    conv_sec_flags(osabi, mach,
				    shdr->sh_flags, 0, &buf1));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_S_CHG),
				    ndx, shdr_sec->sec_name,
				    MSG_ORIG(MSG_CMD_SH_FLAGS),
				    conv_sec_flags(osabi, mach,
				    shdr->sh_flags, 0, &buf1),
				    conv_sec_flags(osabi, mach,
				    sh_flags, 0, &buf2));
				ret = ELFEDIT_CMDRET_MOD;
				shdr->sh_flags = sh_flags;
			}
		}
		break;

	case SHDR_CMD_T_SH_INFO:
		{
			Word sh_info;

			if (argstate.optmask & SHDR_OPT_F_VALUE_SHNAM)
				sh_info = elfedit_name_to_shndx(obj_state,
				    argstate.argv[1]);
			else if (argstate.optmask & SHDR_OPT_F_VALUE_SHTYP)
				sh_info = elfedit_type_to_shndx(obj_state,
				    elfedit_atoconst(argstate.argv[1],
				    ELFEDIT_CONST_SHT));
			else
				sh_info = elfedit_atoui(argstate.argv[1], NULL);

			if (shdr->sh_info == sh_info) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_D_OK),
				    ndx, shdr_sec->sec_name,
				    MSG_ORIG(MSG_CMD_SH_INFO),
				    EC_WORD(shdr->sh_info));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_D_CHG),
				    ndx, shdr_sec->sec_name,
				    MSG_ORIG(MSG_CMD_SH_INFO),
				    EC_WORD(shdr->sh_info), EC_WORD(sh_info));
				ret = ELFEDIT_CMDRET_MOD;
				shdr->sh_info = sh_info;
			}
		}
		break;

	case SHDR_CMD_T_SH_LINK:
		{
			Word sh_link;

			if (argstate.optmask & SHDR_OPT_F_VALUE_SHNAM)
				sh_link = elfedit_name_to_shndx(obj_state,
				    argstate.argv[1]);
			else if (argstate.optmask & SHDR_OPT_F_VALUE_SHTYP)
				sh_link = elfedit_type_to_shndx(obj_state,
				    elfedit_atoconst(argstate.argv[1],
				    ELFEDIT_CONST_SHT));
			else
				sh_link = elfedit_atoui(argstate.argv[1], NULL);

			if (shdr->sh_link == sh_link) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_D_OK),
				    ndx, shdr_sec->sec_name,
				    MSG_ORIG(MSG_CMD_SH_LINK),
				    EC_WORD(shdr->sh_link));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_D_CHG),
				    ndx, shdr_sec->sec_name,
				    MSG_ORIG(MSG_CMD_SH_LINK),
				    EC_WORD(shdr->sh_link), EC_WORD(sh_link));
				ret = ELFEDIT_CMDRET_MOD;
				shdr->sh_link = sh_link;
			}
		}
		break;

	case SHDR_CMD_T_SH_NAME:
		{
			elfedit_section_t *shstr_sec =
			    &obj_state->os_secarr[obj_state->os_shstrndx];
			Word sh_name;

			/*
			 * If -name_offset was specified, this is an offset
			 * into the string table. Otherwise it is a string
			 * we need to turn into an offset.
			 */
			sh_name = (argstate.optmask & SHDR_OPT_F_NAMOFFSET) ?
			    elfedit_atoui(argstate.argv[1], NULL) :
			    elfedit_strtab_insert(obj_state,
			    shstr_sec, NULL, argstate.argv[1]);
			if (shdr->sh_name == sh_name) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_D_OK),
				    ndx, shdr_sec->sec_name,
				    MSG_ORIG(MSG_CMD_SH_NAME),
				    EC_WORD(shdr->sh_name));
			} else {
				/*
				 * The section name is cached, so we must
				 * also update that value. This call will
				 * warn if the offset is out of range, and
				 * will supply a safe string in that case.
				 */
				shdr_sec->sec_name =
				    elfedit_offset_to_str(shstr_sec,
				    sh_name, ELFEDIT_MSG_DEBUG, 1);

				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_D_CHG),
				    ndx, shdr_sec->sec_name,
				    MSG_ORIG(MSG_CMD_SH_NAME),
				    EC_WORD(shdr->sh_name), EC_WORD(sh_name));
				ret = ELFEDIT_CMDRET_MOD;
				shdr->sh_name = sh_name;
			}
		}
		break;

	case SHDR_CMD_T_SH_OFFSET:
		{
			Off sh_offset;

			sh_offset = elfedit_atoui(argstate.argv[1], NULL);
			if (shdr->sh_offset == sh_offset) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_LLX_OK),
				    ndx, shdr_sec->sec_name,
				    MSG_ORIG(MSG_CMD_SH_OFFSET),
				    EC_XWORD(shdr->sh_offset));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_LLX_CHG),
				    ndx, shdr_sec->sec_name,
				    MSG_ORIG(MSG_CMD_SH_OFFSET),
				    EC_XWORD(shdr->sh_offset),
				    EC_XWORD(sh_offset));
				ret = ELFEDIT_CMDRET_MOD;
				shdr->sh_offset = sh_offset;
			}
		}
		break;

	case SHDR_CMD_T_SH_SIZE:
		{
			Xword sh_size;

			sh_size = elfedit_atoui(argstate.argv[1], NULL);
			if (shdr->sh_size == sh_size) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_LLX_OK),
				    ndx, shdr_sec->sec_name,
				    MSG_ORIG(MSG_CMD_SH_SIZE),
				    EC_XWORD(shdr->sh_size));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_LLX_CHG),
				    ndx, shdr_sec->sec_name,
				    MSG_ORIG(MSG_CMD_SH_SIZE),
				    EC_XWORD(shdr->sh_size),
				    EC_XWORD(sh_size));
				ret = ELFEDIT_CMDRET_MOD;
				shdr->sh_size = sh_size;
			}
		}
		break;

	case SHDR_CMD_T_SH_TYPE:
		{
			Word sh_type = elfedit_atoconst(argstate.argv[1],
			    ELFEDIT_CONST_SHT);
			Conv_inv_buf_t inv_buf1, inv_buf2;

			if (shdr->sh_type == sh_type) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_S_OK),
				    ndx, shdr_sec->sec_name,
				    MSG_ORIG(MSG_CMD_SH_TYPE),
				    conv_sec_type(osabi, mach, shdr->sh_type,
				    0, &inv_buf1));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_S_CHG),
				    ndx, shdr_sec->sec_name,
				    MSG_ORIG(MSG_CMD_SH_TYPE),
				    conv_sec_type(osabi, mach, shdr->sh_type,
				    0, &inv_buf1),
				    conv_sec_type(osabi, mach, sh_type,
				    0, &inv_buf2));
				ret = ELFEDIT_CMDRET_MOD;
				shdr->sh_type = sh_type;
			}
		}
		break;
	}

	/*
	 * If we modified the section header array, tell libelf.
	 */
	if (ret == ELFEDIT_CMDRET_MOD)
		elfedit_modified_shdr(shdr_sec);

	/* Do autoprint */
	print_shdr(cmd, 1, &argstate, ndx, 1, PRINT_SHDR_ALL);

	return (ret);
}




/*
 * Command completion functions for the various commands
 */

/*
 * All of the commands accept the same first argument (sec) that
 * specifies the section. This argument can be a section name
 * (default), section index, or section type, depending on the
 * options used. This routine determines which case is current,
 * and then supplies completion for the first argument.
 */
static void
cpl_1starg_sec(elfedit_obj_state_t *obj_state, void *cpldata, int argc,
    const char *argv[], int num_opt)
{
	elfedit_section_t *sec;
	enum { NAME, INDEX, TYPE } op;
	Word ndx;

	if (argc != (num_opt + 1))
		return;

	op = NAME;
	for (ndx = 0; ndx < num_opt; ndx++) {
		if (strcmp(argv[ndx], MSG_ORIG(MSG_STR_MINUS_SHNDX)) == 0)
			op = INDEX;
		else if (strcmp(argv[ndx], MSG_ORIG(MSG_STR_MINUS_SHTYP)) == 0)
			op = TYPE;
	}

	switch (op) {
	case NAME:
		if (obj_state == NULL)
			break;
		sec = obj_state->os_secarr;
		for (ndx = 0; ndx < obj_state->os_shnum; ndx++, sec++)
			elfedit_cpl_match(cpldata, sec->sec_name, 0);
		break;

	case INDEX:
		elfedit_cpl_atoconst(cpldata, ELFEDIT_CONST_SHN);
		break;

	case TYPE:
		elfedit_cpl_atoconst(cpldata, ELFEDIT_CONST_SHT);
		break;
	}
}


/*ARGSUSED*/
static void
cpl_sh_flags(elfedit_obj_state_t *obj_state, void *cpldata, int argc,
    const char *argv[], int num_opt)
{
	/* Handle -shXXX options */
	cpl_1starg_sec(obj_state, cpldata, argc, argv, num_opt);

	/* The second and following arguments can be an SHF_ value */
	if (argc >= (num_opt + 2))
		elfedit_cpl_atoconst(cpldata, ELFEDIT_CONST_SHF);
}

/*
 * For shdr:sh_info and shdr:sh_link: The value argument can be an
 * integer, section name, or section type.
 */
/*ARGSUSED*/
static void
cpl_sh_infolink(elfedit_obj_state_t *obj_state, void *cpldata, int argc,
    const char *argv[], int num_opt)
{
	elfedit_section_t *sec;
	enum { NAME, INTVAL, TYPE } op;
	Word ndx;

	/* Handle -shXXX options */
	cpl_1starg_sec(obj_state, cpldata, argc, argv, num_opt);

	if (argc != (num_opt + 2))
		return;

	op = INTVAL;
	for (ndx = 0; ndx < num_opt; ndx++) {
		if (strcmp(argv[ndx], MSG_ORIG(MSG_STR_MINUS_VALUE_SHNAM)) == 0)
			op = NAME;
		else if (strcmp(argv[ndx],
		    MSG_ORIG(MSG_STR_MINUS_VALUE_SHTYP)) == 0)
			op = TYPE;
	}

	switch (op) {
	case NAME:
		if (obj_state == NULL)
			break;
		sec = obj_state->os_secarr;
		for (ndx = 0; ndx < obj_state->os_shnum; ndx++, sec++)
			elfedit_cpl_match(cpldata, sec->sec_name, 0);
		break;

	case TYPE:
		elfedit_cpl_atoconst(cpldata, ELFEDIT_CONST_SHT);
		break;
	}
}

/*ARGSUSED*/
static void
cpl_sh_type(elfedit_obj_state_t *obj_state, void *cpldata, int argc,
    const char *argv[], int num_opt)
{
	/* Handle -shXXX options */
	cpl_1starg_sec(obj_state, cpldata, argc, argv, num_opt);

	/* The second argument can be an SHT_ value */
	if (argc == (num_opt + 2))
		elfedit_cpl_atoconst(cpldata, ELFEDIT_CONST_SHT);
}



/*
 * Implementation functions for the commands
 */
static elfedit_cmdret_t
cmd_dump(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(SHDR_CMD_T_DUMP, obj_state, argc, argv));
}


static elfedit_cmdret_t
cmd_sh_addr(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(SHDR_CMD_T_SH_ADDR, obj_state, argc, argv));
}


static elfedit_cmdret_t
cmd_sh_addralign(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(SHDR_CMD_T_SH_ADDRALIGN, obj_state, argc, argv));
}


static elfedit_cmdret_t
cmd_sh_entsize(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(SHDR_CMD_T_SH_ENTSIZE, obj_state, argc, argv));
}

static elfedit_cmdret_t
cmd_sh_flags(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(SHDR_CMD_T_SH_FLAGS, obj_state, argc, argv));
}

static elfedit_cmdret_t
cmd_sh_info(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(SHDR_CMD_T_SH_INFO, obj_state, argc, argv));
}

static elfedit_cmdret_t
cmd_sh_link(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(SHDR_CMD_T_SH_LINK, obj_state, argc, argv));
}

static elfedit_cmdret_t
cmd_sh_name(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(SHDR_CMD_T_SH_NAME, obj_state, argc, argv));
}

static elfedit_cmdret_t
cmd_sh_offset(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(SHDR_CMD_T_SH_OFFSET, obj_state, argc, argv));
}

static elfedit_cmdret_t
cmd_sh_size(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(SHDR_CMD_T_SH_SIZE, obj_state, argc, argv));
}

static elfedit_cmdret_t
cmd_sh_type(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(SHDR_CMD_T_SH_TYPE, obj_state, argc, argv));
}



/*ARGSUSED*/
elfedit_module_t *
elfedit_init(elfedit_module_version_t version)
{
	/* Multiple commands accept only the standard set of options */
	static elfedit_cmd_optarg_t opt_std[] = {
		{ ELFEDIT_STDOA_OPT_O, 0,
		    ELFEDIT_CMDOA_F_INHERIT, 0, 0 },
		{ MSG_ORIG(MSG_STR_MINUS_SHNDX),
		    /* MSG_INTL(MSG_OPTDESC_SHNDX) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_SHNDX), 0,
		    SHDR_OPT_F_SHNDX, SHDR_OPT_F_SHTYP },
		{ MSG_ORIG(MSG_STR_MINUS_SHTYP),
		    /* MSG_INTL(MSG_OPTDESC_SHTYP) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_SHTYP), 0,
		    SHDR_OPT_F_SHTYP, SHDR_OPT_F_SHNDX },
		{ NULL }
	};

	/*
	 * sh_info and sh_link accept the standard options above,
	 * plus -value_shnam and -value_shtyp.
	 */
	static elfedit_cmd_optarg_t opt_infolink[] = {
		{ ELFEDIT_STDOA_OPT_O, 0,
		    ELFEDIT_CMDOA_F_INHERIT, 0, 0 },
		{ MSG_ORIG(MSG_STR_MINUS_SHNDX),
		    /* MSG_INTL(MSG_OPTDESC_SHNDX) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_SHNDX), 0,
		    SHDR_OPT_F_SHNDX, SHDR_OPT_F_SHTYP },
		{ MSG_ORIG(MSG_STR_MINUS_SHTYP),
		    /* MSG_INTL(MSG_OPTDESC_SHTYP) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_SHTYP), 0,
		    SHDR_OPT_F_SHTYP, SHDR_OPT_F_SHNDX },
		{ MSG_ORIG(MSG_STR_MINUS_VALUE_SHNAM),
		    /* MSG_INTL(MSG_OPTDESC_VALUE_SHNAM) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_VALUE_SHNAM), 0,
		    SHDR_OPT_F_VALUE_SHNAM, SHDR_OPT_F_VALUE_SHNAM },
		{ MSG_ORIG(MSG_STR_MINUS_VALUE_SHTYP),
		    /* MSG_INTL(MSG_OPTDESC_VALUE_SHTYP) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_VALUE_SHTYP), 0,
		    SHDR_OPT_F_VALUE_SHTYP, SHDR_OPT_F_VALUE_SHTYP },
		{ NULL }
	};

	/* shdr:sh_addr */
	static const char *name_sh_addr[] = {
	    MSG_ORIG(MSG_CMD_SH_ADDR), NULL };
	static elfedit_cmd_optarg_t arg_sh_addr[] = {
		{ MSG_ORIG(MSG_STR_SEC),
		    /* MSG_INTL(MSG_A1_SEC) */
		    ELFEDIT_I18NHDL(MSG_A1_SEC),
		    ELFEDIT_CMDOA_F_OPT },
		{ MSG_ORIG(MSG_STR_VALUE),
		    /* MSG_INTL(MSG_A2_DESC_SH_ADDR) */
		    ELFEDIT_I18NHDL(MSG_A2_DESC_SH_ADDR),
		    ELFEDIT_CMDOA_F_OPT },
		{ NULL }
	};

	/* shdr:dump */
	static const char *name_dump[] = {
	    MSG_ORIG(MSG_CMD_DUMP),
	    MSG_ORIG(MSG_STR_EMPTY),	/* "" makes this the default command */
	    NULL
	};
	static elfedit_cmd_optarg_t opt_dump[] = {
		{ MSG_ORIG(MSG_STR_MINUS_SHNDX),
		    /* MSG_INTL(MSG_OPTDESC_SHNDX) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_SHNDX), 0,
		    SHDR_OPT_F_SHNDX, SHDR_OPT_F_SHTYP },
		{ MSG_ORIG(MSG_STR_MINUS_SHTYP),
		    /* MSG_INTL(MSG_OPTDESC_SHTYP) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_SHTYP), 0,
		    SHDR_OPT_F_SHTYP, SHDR_OPT_F_SHNDX },
		{ NULL }
	};
	static elfedit_cmd_optarg_t arg_dump[] = {
		{ MSG_ORIG(MSG_STR_SEC),
		    /* MSG_INTL(MSG_A1_SEC) */
		    ELFEDIT_I18NHDL(MSG_A1_SEC),
		    ELFEDIT_CMDOA_F_OPT },
		{ NULL }
	};

	/* shdr:sh_addralign */
	static const char *name_sh_addralign[] = {
	    MSG_ORIG(MSG_CMD_SH_ADDRALIGN), NULL };
	static elfedit_cmd_optarg_t arg_sh_addralign[] = {
		{ MSG_ORIG(MSG_STR_SEC),
		    /* MSG_INTL(MSG_A1_SEC) */
		    ELFEDIT_I18NHDL(MSG_A1_SEC),
		    ELFEDIT_CMDOA_F_OPT },
		{ MSG_ORIG(MSG_STR_VALUE),
		    /* MSG_INTL(MSG_A2_DESC_SH_ADDRALIGN) */
		    ELFEDIT_I18NHDL(MSG_A2_DESC_SH_ADDRALIGN),
		    ELFEDIT_CMDOA_F_OPT },
		{ NULL }
	};

	/* shdr:sh_entsize */
	static const char *name_sh_entsize[] = {
	    MSG_ORIG(MSG_CMD_SH_ENTSIZE), NULL };
	static elfedit_cmd_optarg_t arg_sh_entsize[] = {
		{ MSG_ORIG(MSG_STR_SEC),
		    /* MSG_INTL(MSG_A1_SEC) */
		    ELFEDIT_I18NHDL(MSG_A1_SEC),
		    ELFEDIT_CMDOA_F_OPT },
		{ MSG_ORIG(MSG_STR_VALUE),
		    /* MSG_INTL(MSG_A2_DESC_SH_ENTSIZE) */
		    ELFEDIT_I18NHDL(MSG_A2_DESC_SH_ENTSIZE),
		    ELFEDIT_CMDOA_F_OPT },
		{ NULL }
	};

	/* shdr:sh_flags */
	static const char *name_sh_flags[] = {
	    MSG_ORIG(MSG_CMD_SH_FLAGS), NULL };
	static elfedit_cmd_optarg_t opt_sh_flags[] = {
		{ ELFEDIT_STDOA_OPT_AND, 0,
		    ELFEDIT_CMDOA_F_INHERIT, SHDR_OPT_F_AND, SHDR_OPT_F_OR },
		{ ELFEDIT_STDOA_OPT_CMP, 0,
		    ELFEDIT_CMDOA_F_INHERIT, SHDR_OPT_F_CMP, 0 },
		{ ELFEDIT_STDOA_OPT_O, 0,
		    ELFEDIT_CMDOA_F_INHERIT, 0, 0 },
		{ ELFEDIT_STDOA_OPT_OR, 0,
		    ELFEDIT_CMDOA_F_INHERIT, SHDR_OPT_F_OR, SHDR_OPT_F_AND },
		{ MSG_ORIG(MSG_STR_MINUS_SHNDX),
		    /* MSG_INTL(MSG_OPTDESC_SHNDX) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_SHNDX), 0,
		    SHDR_OPT_F_SHNDX, SHDR_OPT_F_SHTYP },
		{ MSG_ORIG(MSG_STR_MINUS_SHTYP),
		    /* MSG_INTL(MSG_OPTDESC_SHTYP) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_SHTYP), 0,
		    SHDR_OPT_F_SHTYP, SHDR_OPT_F_SHNDX },
		{ NULL }
	};
	static elfedit_cmd_optarg_t arg_sh_flags[] = {
		{ MSG_ORIG(MSG_STR_SEC),
		    /* MSG_INTL(MSG_A1_SEC) */
		    ELFEDIT_I18NHDL(MSG_A1_SEC),
		    ELFEDIT_CMDOA_F_OPT },
		{ MSG_ORIG(MSG_STR_VALUE),
		    /* MSG_INTL(MSG_A2_DESC_SH_FLAGS) */
		    ELFEDIT_I18NHDL(MSG_A2_DESC_SH_FLAGS),
		    ELFEDIT_CMDOA_F_OPT | ELFEDIT_CMDOA_F_MULT },
		{ NULL }
	};

	/* shdr:sh_info */
	static const char *name_sh_info[] = {
	    MSG_ORIG(MSG_CMD_SH_INFO), NULL };
	static elfedit_cmd_optarg_t arg_sh_info[] = {
		{ MSG_ORIG(MSG_STR_SEC),
		    /* MSG_INTL(MSG_A1_SEC) */
		    ELFEDIT_I18NHDL(MSG_A1_SEC),
		    ELFEDIT_CMDOA_F_OPT },
		{ MSG_ORIG(MSG_STR_VALUE),
		    /* MSG_INTL(MSG_A2_DESC_SH_INFO) */
		    ELFEDIT_I18NHDL(MSG_A2_DESC_SH_INFO),
		    ELFEDIT_CMDOA_F_OPT },
		{ NULL }
	};

	/* shdr:sh_link */
	static const char *name_sh_link[] = {
	    MSG_ORIG(MSG_CMD_SH_LINK), NULL };
	static elfedit_cmd_optarg_t arg_sh_link[] = {
		{ MSG_ORIG(MSG_STR_SEC),
		    /* MSG_INTL(MSG_A1_SEC) */
		    ELFEDIT_I18NHDL(MSG_A1_SEC),
		    ELFEDIT_CMDOA_F_OPT },
		{ MSG_ORIG(MSG_STR_VALUE),
		    /* MSG_INTL(MSG_A2_DESC_SH_LINK) */
		    ELFEDIT_I18NHDL(MSG_A2_DESC_SH_LINK),
		    ELFEDIT_CMDOA_F_OPT },
		{ NULL }
	};

	/* shdr:sh_name */
	static const char *name_sh_name[] = {
	    MSG_ORIG(MSG_CMD_SH_NAME), NULL };
	static elfedit_cmd_optarg_t opt_sh_name[] = {
		{ MSG_ORIG(MSG_STR_MINUS_NAME_OFFSET),
		    /* MSG_INTL(MSG_OPTDESC_NAME_OFFSET) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_NAME_OFFSET), 0,
		    SHDR_OPT_F_NAMOFFSET, 0 },
		{ ELFEDIT_STDOA_OPT_O, 0,
		    ELFEDIT_CMDOA_F_INHERIT, 0, 0 },
		{ MSG_ORIG(MSG_STR_MINUS_SHNDX),
		    /* MSG_INTL(MSG_OPTDESC_SHNDX) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_SHNDX), 0,
		    SHDR_OPT_F_SHNDX, SHDR_OPT_F_SHTYP },
		{ MSG_ORIG(MSG_STR_MINUS_SHTYP),
		    /* MSG_INTL(MSG_OPTDESC_SHTYP) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_SHTYP), 0,
		    SHDR_OPT_F_SHTYP, SHDR_OPT_F_SHNDX },
		{ NULL }
	};
	static elfedit_cmd_optarg_t arg_sh_name[] = {
		{ MSG_ORIG(MSG_STR_SEC),
		    /* MSG_INTL(MSG_A1_SEC) */
		    ELFEDIT_I18NHDL(MSG_A1_SEC),
		    ELFEDIT_CMDOA_F_OPT },
		{ MSG_ORIG(MSG_STR_NAME),
		    /* MSG_INTL(MSG_A2_DESC_SH_NAME) */
		    ELFEDIT_I18NHDL(MSG_A2_DESC_SH_NAME),
		    ELFEDIT_CMDOA_F_OPT },
		{ NULL }
	};

	/* shdr:sh_offset */
	static const char *name_sh_offset[] = {
	    MSG_ORIG(MSG_CMD_SH_OFFSET), NULL };
	static elfedit_cmd_optarg_t arg_sh_offset[] = {
		{ MSG_ORIG(MSG_STR_SEC),
		    /* MSG_INTL(MSG_A1_SEC) */
		    ELFEDIT_I18NHDL(MSG_A1_SEC),
		    ELFEDIT_CMDOA_F_OPT },
		{ MSG_ORIG(MSG_STR_VALUE),
		    /* MSG_INTL(MSG_A2_DESC_SH_OFFSET) */
		    ELFEDIT_I18NHDL(MSG_A2_DESC_SH_OFFSET),
		    ELFEDIT_CMDOA_F_OPT },
		{ NULL }
	};

	/* shdr:sh_size */
	static const char *name_sh_size[] = {
	    MSG_ORIG(MSG_CMD_SH_SIZE), NULL };
	static elfedit_cmd_optarg_t arg_sh_size[] = {
		{ MSG_ORIG(MSG_STR_SEC),
		    /* MSG_INTL(MSG_A1_SEC) */
		    ELFEDIT_I18NHDL(MSG_A1_SEC),
		    ELFEDIT_CMDOA_F_OPT },
		{ MSG_ORIG(MSG_STR_VALUE),
		    /* MSG_INTL(MSG_A2_DESC_SH_SIZE) */
		    ELFEDIT_I18NHDL(MSG_A2_DESC_SH_SIZE),
		    ELFEDIT_CMDOA_F_OPT },
		{ NULL }
	};

	/* shdr:sh_type */
	static const char *name_sh_type[] = {
	    MSG_ORIG(MSG_CMD_SH_TYPE), NULL };
	static elfedit_cmd_optarg_t arg_sh_type[] = {
		{ MSG_ORIG(MSG_STR_SEC),
		    /* MSG_INTL(MSG_A1_SEC) */
		    ELFEDIT_I18NHDL(MSG_A1_SEC),
		    ELFEDIT_CMDOA_F_OPT },
		{ MSG_ORIG(MSG_STR_VALUE),
		    /* MSG_INTL(MSG_A2_DESC_SH_TYPE) */
		    ELFEDIT_I18NHDL(MSG_A2_DESC_SH_TYPE),
		    ELFEDIT_CMDOA_F_OPT },
		{ NULL }
	};

	static elfedit_cmd_t cmds[] = {
		/* shdr:dump */
		{ cmd_dump, cpl_1starg_sec, name_dump,
		    /* MSG_INTL(MSG_DESC_DUMP) */
		    ELFEDIT_I18NHDL(MSG_DESC_DUMP),
		    /* MSG_INTL(MSG_HELP_DUMP) */
		    ELFEDIT_I18NHDL(MSG_HELP_DUMP),
		    opt_dump, arg_dump },

		/* shdr:sh_addr */
		{ cmd_sh_addr, cpl_1starg_sec, name_sh_addr,
		    /* MSG_INTL(MSG_DESC_SH_ADDR) */
		    ELFEDIT_I18NHDL(MSG_DESC_SH_ADDR),
		    /* MSG_INTL(MSG_HELP_SH_ADDR) */
		    ELFEDIT_I18NHDL(MSG_HELP_SH_ADDR),
		    opt_std, arg_sh_addr },

		/* shdr:sh_addralign */
		{ cmd_sh_addralign, cpl_1starg_sec, name_sh_addralign,
		    /* MSG_INTL(MSG_DESC_SH_ADDRALIGN) */
		    ELFEDIT_I18NHDL(MSG_DESC_SH_ADDRALIGN),
		    /* MSG_INTL(MSG_HELP_SH_ADDRALIGN) */
		    ELFEDIT_I18NHDL(MSG_HELP_SH_ADDRALIGN),
		    opt_std, arg_sh_addralign },

		/* shdr:sh_entsize */
		{ cmd_sh_entsize, cpl_1starg_sec, name_sh_entsize,
		    /* MSG_INTL(MSG_DESC_SH_ENTSIZE) */
		    ELFEDIT_I18NHDL(MSG_DESC_SH_ENTSIZE),
		    /* MSG_INTL(MSG_HELP_SH_ENTSIZE) */
		    ELFEDIT_I18NHDL(MSG_HELP_SH_ENTSIZE),
		    opt_std, arg_sh_entsize },

		/* shdr:sh_flags */
		{ cmd_sh_flags, cpl_sh_flags, name_sh_flags,
		    /* MSG_INTL(MSG_DESC_SH_FLAGS) */
		    ELFEDIT_I18NHDL(MSG_DESC_SH_FLAGS),
		    /* MSG_INTL(MSG_HELP_SH_FLAGS) */
		    ELFEDIT_I18NHDL(MSG_HELP_SH_FLAGS),
		    opt_sh_flags, arg_sh_flags },

		/* shdr:sh_info */
		{ cmd_sh_info, cpl_sh_infolink, name_sh_info,
		    /* MSG_INTL(MSG_DESC_SH_INFO) */
		    ELFEDIT_I18NHDL(MSG_DESC_SH_INFO),
		    /* MSG_INTL(MSG_HELP_SH_INFO) */
		    ELFEDIT_I18NHDL(MSG_HELP_SH_INFO),
		    opt_infolink, arg_sh_info },

		/* shdr:sh_link */
		{ cmd_sh_link, cpl_sh_infolink, name_sh_link,
		    /* MSG_INTL(MSG_DESC_SH_LINK) */
		    ELFEDIT_I18NHDL(MSG_DESC_SH_LINK),
		    /* MSG_INTL(MSG_HELP_SH_LINK) */
		    ELFEDIT_I18NHDL(MSG_HELP_SH_LINK),
		    opt_infolink, arg_sh_link },

		/* shdr:sh_name */
		{ cmd_sh_name, cpl_1starg_sec, name_sh_name,
		    /* MSG_INTL(MSG_DESC_SH_NAME) */
		    ELFEDIT_I18NHDL(MSG_DESC_SH_NAME),
		    /* MSG_INTL(MSG_HELP_SH_NAME) */
		    ELFEDIT_I18NHDL(MSG_HELP_SH_NAME),
		    opt_sh_name, arg_sh_name },

		/* shdr:sh_offset */
		{ cmd_sh_offset, cpl_1starg_sec, name_sh_offset,
		    /* MSG_INTL(MSG_DESC_SH_OFFSET) */
		    ELFEDIT_I18NHDL(MSG_DESC_SH_OFFSET),
		    /* MSG_INTL(MSG_HELP_SH_OFFSET) */
		    ELFEDIT_I18NHDL(MSG_HELP_SH_OFFSET),
		    opt_std, arg_sh_offset },

		/* shdr:sh_size */
		{ cmd_sh_size, cpl_1starg_sec, name_sh_size,
		    /* MSG_INTL(MSG_DESC_SH_SIZE) */
		    ELFEDIT_I18NHDL(MSG_DESC_SH_SIZE),
		    /* MSG_INTL(MSG_HELP_SH_SIZE) */
		    ELFEDIT_I18NHDL(MSG_HELP_SH_SIZE),
		    opt_std, arg_sh_size },

		/* shdr:sh_type */
		{ cmd_sh_type, cpl_sh_type, name_sh_type,
		    /* MSG_INTL(MSG_DESC_SH_TYPE) */
		    ELFEDIT_I18NHDL(MSG_DESC_SH_TYPE),
		    /* MSG_INTL(MSG_HELP_SH_TYPE) */
		    ELFEDIT_I18NHDL(MSG_HELP_SH_TYPE),
		    opt_std, arg_sh_type },

		{ NULL }
	};

	static elfedit_module_t module = {
	    ELFEDIT_VER_CURRENT, MSG_ORIG(MSG_MOD_NAME),
	    /* MSG_INTL(MSG_MOD_DESC) */
	    ELFEDIT_I18NHDL(MSG_MOD_DESC),
	    cmds, mod_i18nhdl_to_str };

	return (&module);
}
