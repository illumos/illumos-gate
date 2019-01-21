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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include	<ctype.h>
#include	<elfedit.h>
#include	<sys/elf_SPARC.h>
#include	<strings.h>
#include	<debug.h>
#include	<conv.h>
#include	<dyn_msg.h>


/*
 * Dynamic section
 */

/*
 * This module uses shared code for several of the commands.
 * It is sometimes necessary to know which specific command
 * is active.
 */
typedef enum {
	/* Dump command, used as module default to display dynamic section */
	DYN_CMD_T_DUMP =	0,	/* dyn:dump */

	/* Commands that do not correspond directly to a specific DT tag */
	DYN_CMD_T_TAG =		1,	/* dyn:tag */
	DYN_CMD_T_VALUE =	2,	/* dyn:value */
	DYN_CMD_T_DELETE =	3,	/* dyn:delete */
	DYN_CMD_T_MOVE =	4,	/* dyn:shift */

	/* Commands that embody tag specific knowledge */
	DYN_CMD_T_RUNPATH =	5,	/* dyn:runpath/rpath */
	DYN_CMD_T_POSFLAG1 =	6,	/* dyn:posflag1 */
	DYN_CMD_T_FLAGS =	7,	/* dyn:flags */
	DYN_CMD_T_FLAGS1 =	8,	/* dyn:flags1 */
	DYN_CMD_T_FEATURE1 =	9,	/* dyn:feature1 */
	DYN_CMD_T_CHECKSUM =	10,	/* dyn:checksum */
	DYN_CMD_T_SUNW_LDMACH =	11	/* dyn:sunw_ldmach */
} DYN_CMD_T;



#ifndef _ELF64
/*
 * We supply this function for the msg module
 */
const char *
_dyn_msg(Msg mid)
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
 * The dyn_opt_t enum specifies a bit value for every optional
 * argument allowed by a command in this module.
 */
typedef enum {
	DYN_OPT_F_ADD =		1,	/* -add: Add new elt rather than */
					/*	modifying an existing one */
	DYN_OPT_F_AND =		2,	/* -and: AND (&) values to dest */
	DYN_OPT_F_CMP =		4,	/* -cmp: Complement (~) values */
	DYN_OPT_F_DYNNDX_ELT =	8,	/* -dynndx: 1st plain arg is tag */
					/*	index, not name */
	DYN_OPT_F_DYNNDX_VAL =	16,	/* -dynndx ndx: Index is value to */
					/*	option rather than 1st plain */
					/*	arg. Used for dyn:posflag1 */
	DYN_OPT_F_NEEDED =	32,	/* -needed str: Locate DT_POSFLAG_1 */
					/*	relative to DT_NEEDED element */
	DYN_OPT_F_OR =		64,	/* -or: OR (|) values to dest */
	DYN_OPT_F_STRVAL =	128	/* -s: value is string, not integer */
} dyn_opt_t;


/*
 * A variable of type ARGSTATE is used by each command to maintain
 * information about the arguments and related things. It is
 * initialized by process_args(), and used by the other routines.
 */
typedef struct {
	elfedit_obj_state_t	*obj_state;
	elfedit_section_t	*strsec;	/* Dynamic string table ref */
	struct {
		elfedit_section_t *sec;		/* Dynamic section reference */
		Dyn	*data;			/* Start dynamic section data */
		Word	num;			/* # dynamic elts */
		Word	null_ndx;		/* Index of first DT_NULL */
		Word	num_null_ndx;		/* # of DT_NULL elements */
	} dyn;
	dyn_opt_t		optmask;	/* Mask of options used */
	int			argc;		/* # of plain arguments */
	const char		**argv;		/* Plain arguments */
	const char		*dyn_elt_str;	/* Value string for */
						/*	DYN_OPT_F_DYNNDX_VAL */
						/*	or DYN_OPT_F_NEEDED */
} ARGSTATE;



/*
 * Set argstate null_ndx field for current dynamic area
 */
static void
set_null_ndx(ARGSTATE *argstate)
{
	Word	num, null_ndx;

	num = argstate->dyn.num;
	argstate->dyn.num_null_ndx = 0;
	for (null_ndx = 0; null_ndx < num; null_ndx++)
		if (argstate->dyn.data[null_ndx].d_tag == DT_NULL) {
			argstate->dyn.num_null_ndx++;
			break;
		}
	argstate->dyn.null_ndx = null_ndx;

	/* Count the number of remaining DT_NULL items */
	for (; null_ndx < num; null_ndx++)
		if (argstate->dyn.data[null_ndx].d_tag == DT_NULL)
			argstate->dyn.num_null_ndx++;
}


/*
 * Convert the first available DT_NULL slot in the dynamic section
 * into something else.
 *
 * entry:
 *	argstate - Argument state block
 *	d_tag, d_val - Values to be set in new element
 *
 * exit:
 *	If an extra DT_NULL slot is available, a debug message is
 *	issued, the slot is converted to its new use, and the argstate
 *	block state related to DT_NULL slots is updated.
 *
 *	if no extra DT_NULL slot is present, an error is issued and
 *	this routine does not return to the caller.
 */
static Word
convert_dt_null(ARGSTATE *argstate, Xword d_tag, Xword d_val)
{
	Conv_inv_buf_t inv_buf;
	Word	ndx;
	Dyn	*dyn;
	Ehdr	*ehdr;

	/* If we lack an extra element, we can't continue */
	if (argstate->dyn.num_null_ndx <= 1)
		elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_NOEXTRANULL),
		    EC_WORD(argstate->dyn.sec->sec_shndx),
		    argstate->dyn.sec->sec_name);

	ehdr = argstate->obj_state->os_ehdr;
	elfedit_msg(ELFEDIT_MSG_DEBUG, MSG_INTL(MSG_DEBUG_CONVNULL),
	    EC_WORD(argstate->dyn.sec->sec_shndx), argstate->dyn.sec->sec_name,
	    EC_WORD(argstate->dyn.null_ndx), conv_dyn_tag(d_tag,
	    ehdr->e_ident[EI_OSABI], ehdr->e_machine, 0, &inv_buf));

	ndx = argstate->dyn.null_ndx;
	dyn = &argstate->dyn.data[ndx];
	dyn->d_tag = d_tag;
	dyn->d_un.d_val = d_val;

	/* Recompute the DT_NULL situation */
	set_null_ndx(argstate);

	return (ndx);
}


/*
 * Standard argument processing for dyn module
 *
 * entry
 *	obj_state, argc, argv - Standard command arguments
 *	argstate - Address of ARGSTATE block to be initialized
 *
 * exit:
 *	On success, *argstate is initialized. On error,
 *	an error is issued and this routine does not return.
 */
static void
process_args(elfedit_obj_state_t *obj_state, int argc, const char *argv[],
    ARGSTATE *argstate)
{
	elfedit_getopt_state_t	getopt_state;
	elfedit_getopt_ret_t	*getopt_ret;

	bzero(argstate, sizeof (*argstate));
	argstate->obj_state = obj_state;

	elfedit_getopt_init(&getopt_state, &argc, &argv);

	/* Add each new option to the options mask */
	while ((getopt_ret = elfedit_getopt(&getopt_state)) != NULL) {
		argstate->optmask |= getopt_ret->gor_idmask;
		switch (getopt_ret->gor_idmask) {
		case DYN_OPT_F_DYNNDX_VAL:
		case DYN_OPT_F_NEEDED:
			argstate->dyn_elt_str = getopt_ret->gor_value;
			break;
		}
	}

	/* If there may be an arbitrary amount of output, use a pager */
	if (argc == 0)
		elfedit_pager_init();

	/* Return the updated values of argc/argv */
	argstate->argc = argc;
	argstate->argv = argv;

	/* Locate the dynamic section, and the assocated string table */
	argstate->dyn.sec = elfedit_sec_getdyn(obj_state, &argstate->dyn.data,
	    &argstate->dyn.num);
	argstate->strsec = elfedit_sec_getstr(obj_state,
	    argstate->dyn.sec->sec_shdr->sh_link, 0);

	/* Index of first DT_NULL */
	set_null_ndx(argstate);
}

/*
 * Print ELF header values, taking the calling command, and output style
 * into account.
 *
 * entry:
 *	cmd - DYN_CMD_T_* value giving identify of caller
 *	autoprint - If True, output is only produced if the elfedit
 *		autoprint flag is set. If False, output is always produced.
 *	argstate - Argument state block
 *	print_type - Specifies which dynamic elements to display.
 *	arg - If print_type is PRINT_DYN_T_NDX, displays the index specified.
 *		Otherwise ignored.
 */
typedef enum {
	PRINT_DYN_T_ALL =	0,	/* Show all indexes */
	PRINT_DYN_T_NDX =	1,	/* Show dynamic[arg] only */
	PRINT_DYN_T_TAG =	2,	/* Show all elts with tag type */
					/*	given by arg */
	PRINT_DYN_T_RUNPATH =	3	/* Show all runpath/rpath elts */

} PRINT_DYN_T;

static void
print_dyn(DYN_CMD_T cmd, int autoprint, ARGSTATE *argstate,
    PRINT_DYN_T print_type, Word arg)
{
	elfedit_outstyle_t	outstyle;
	Conv_fmt_flags_t	flags_fmt_flags;
	Word	end_ndx, ndx, printed = 0;
	Dyn	*dyn;
	int	header_done = 0;
	Xword	last_d_val;
	int	one_shot;
	int	osabi_solaris;

	if (autoprint && ((elfedit_flags() & ELFEDIT_F_AUTOPRINT) == 0))
		return;

	osabi_solaris =
	    elfedit_test_osabi(argstate->obj_state, ELFOSABI_SOLARIS, 0);

	/*
	 * Pick an output style. dyn:dump is required to use the default
	 * style. The other commands use the current output style.
	 */
	outstyle = (cmd == DYN_CMD_T_DUMP) ?
	    ELFEDIT_OUTSTYLE_DEFAULT : elfedit_outstyle();

	/*
	 * When using the simple output style, omit the
	 * brackets from around the values.
	 */
	flags_fmt_flags = (outstyle == ELFEDIT_OUTSTYLE_SIMPLE) ?
	    CONV_FMT_NOBKT : 0;

	/* Starting index */
	if (print_type == PRINT_DYN_T_NDX) {
		if (arg >= argstate->dyn.num)
			return;		/* Out of range */
		ndx = arg;
	} else {
		ndx = 0;
	}

	/*
	 * one_shot is used by positional elements (e.g. DT_POSFLAG_1)
	 * to get the item following them to be shown even if they
	 * are not of the desired tag type or the count of elements
	 * to be displayed is only 1.
	 */
	one_shot = 0;

	dyn = &argstate->dyn.data[ndx];

	/*
	 * Loop predicate explanation:
	 * Normally, we want to iterate from the starting index
	 * to the end. However, in the case of PRINT_DYN_T_NDX, we
	 * only want to display one item (ndx == arg) and then quit,
	 * with the exception that if we've been through the loop
	 * and encountered a one_shot situation, we want to continue
	 * iterating until the one-shot situation is cleared.
	 */
	for (; (ndx < argstate->dyn.num) &&
	    ((print_type != PRINT_DYN_T_NDX) || ((ndx == arg) || one_shot));
	    dyn++, ndx++) {
		union {
			Conv_inv_buf_t		inv;
			Conv_dyn_flag_buf_t	flag;
			Conv_dyn_flag1_buf_t	flag1;
			Conv_dyn_posflag1_buf_t	posflag1;
			Conv_dyn_feature1_buf_t	feature1;
		} c_buf;
		const char	*name;

		if (one_shot) {
			one_shot = 0;
		} else {
			/*
			 * If we are only displaying certain tag types and
			 * this isn't one of those, move on to next element.
			 */
			switch (print_type) {
			case PRINT_DYN_T_TAG:
				if (dyn->d_tag != arg)
					continue;
				break;
			case PRINT_DYN_T_RUNPATH:
				if ((dyn->d_tag != DT_RPATH) &&
				    (dyn->d_tag != DT_RUNPATH))
					continue;
				break;
			}
		}

		/*
		 * Print the information numerically, and if possible
		 * as a string.
		 */
		name = NULL;
		switch (dyn->d_tag) {
		case DT_NULL:
			if (!((outstyle == ELFEDIT_OUTSTYLE_DEFAULT) &&
			    (print_type == PRINT_DYN_T_ALL) &&
			    (dyn->d_un.d_val == 0)))
				break;
			end_ndx = ndx;
			/*
			 * Special case: DT_NULLs can come in groups
			 * that we prefer to reduce to a single line.
			 */
			while ((end_ndx < (argstate->dyn.num - 1)) &&
			    ((dyn + 1)->d_tag == DT_NULL) &&
			    ((dyn + 1)->d_un.d_val == 0)) {
				dyn++;
				end_ndx++;
			}
			if (header_done == 0) {
				header_done = 1;
				Elf_dyn_title(0);
			}
			Elf_dyn_null_entry(0, dyn, ndx, end_ndx);
			ndx = end_ndx;
			printed = 1;
			last_d_val = dyn->d_un.d_val;
			continue;

		/*
		 * Print the information numerically, and if possible
		 * as a string.
		 */
		case DT_NEEDED:
		case DT_SONAME:
		case DT_FILTER:
		case DT_AUXILIARY:
		case DT_CONFIG:
		case DT_RPATH:
		case DT_RUNPATH:
		case DT_USED:
		case DT_DEPAUDIT:
		case DT_AUDIT:
			name = elfedit_offset_to_str(argstate->strsec,
			    dyn->d_un.d_val, ELFEDIT_MSG_DEBUG, 0);
			break;
		case DT_SUNW_AUXILIARY:
		case DT_SUNW_FILTER:
			if (osabi_solaris)
				name = elfedit_offset_to_str(argstate->strsec,
				    dyn->d_un.d_val, ELFEDIT_MSG_DEBUG, 0);
			break;

		case DT_FLAGS:
			name = conv_dyn_flag(dyn->d_un.d_val,
			    flags_fmt_flags, &c_buf.flag);
			break;
		case DT_FLAGS_1:
			name = conv_dyn_flag1(dyn->d_un.d_val,
			    flags_fmt_flags, &c_buf.flag1);
			break;
		case DT_POSFLAG_1:
			/*
			 * If this is dyn:posflag1, and the print_type
			 * is PRINT_DYN_T_TAG, and the -needed option is
			 * used, then don't show any DT_POSFLAG_1 elements
			 * that are not followed by a DT_NEEDED element
			 * that matches the -needed string.
			 */
			if ((cmd == DYN_CMD_T_POSFLAG1) &&
			    (print_type == PRINT_DYN_T_TAG) &&
			    ((argstate->optmask & DYN_OPT_F_NEEDED) != 0) &&
			    ((ndx + 1) < argstate->dyn.num)) {
				Dyn *dyn1 = &argstate->dyn.data[ndx + 1];

				if (dyn1->d_tag != DT_NEEDED)
					continue;
				name = elfedit_offset_to_str(argstate->strsec,
				    dyn1->d_un.d_val, ELFEDIT_MSG_DEBUG, 0);
				if (strncmp(name, argstate->dyn_elt_str,
				    strlen(argstate->dyn_elt_str)) != 0)
					continue;
			}

			name = conv_dyn_posflag1(dyn->d_un.d_val,
			    flags_fmt_flags, &c_buf.posflag1);
			/*
			 * DT_POSFLAG_1 is a positional element that affects
			 * the following item. If using the default output
			 * style, then show the following item as well.
			 */
			one_shot = (outstyle == ELFEDIT_OUTSTYLE_DEFAULT);
			break;
		case DT_FEATURE_1:
			name = conv_dyn_feature1(dyn->d_un.d_val,
			    flags_fmt_flags, &c_buf.feature1);
			break;
		case DT_DEPRECATED_SPARC_REGISTER:
			name = MSG_INTL(MSG_STR_DEPRECATED);
			break;
		case DT_SUNW_LDMACH:
			if (osabi_solaris)
				name = conv_ehdr_mach((Half)dyn->d_un.d_val, 0,
				    &c_buf.inv);
			break;
		}

		if (outstyle == ELFEDIT_OUTSTYLE_DEFAULT) {
			Ehdr	*ehdr;

			if (header_done == 0) {
				header_done = 1;
				Elf_dyn_title(0);
			}
			if (name == NULL)
				name = MSG_ORIG(MSG_STR_EMPTY);
			ehdr = argstate->obj_state->os_ehdr;
			Elf_dyn_entry(0, dyn, ndx, name,
			    ehdr->e_ident[EI_OSABI], ehdr->e_machine);
		} else {
			/*
			 * In simple or numeric mode under a print type
			 * that is based on tag type rather than on index,
			 * if there are more than one qualifying tag, we
			 * want to skip printing redundant information.
			 */
			switch (print_type) {
			case PRINT_DYN_T_TAG:
				switch (dyn->d_tag) {
				case DT_NEEDED:
					/* Multiple NEEDED entries are normal */
					break;
				case DT_POSFLAG_1:
					/*
					 * Positional flags don't count,
					 * because each one affects a different
					 * item. Don't skip those even if they
					 * have duplicate values.
					 */
					break;
				default:
					/*
					 * Anything else: If we've already
					 * printed this value, don't print
					 * it again.
					 */
					if (printed &&
					    (last_d_val == dyn->d_un.d_val))
						continue;
				}
				break;
			case PRINT_DYN_T_RUNPATH:
				/*
				 * If we've already printed this value,
				 * don't print it again. This commonly
				 * happens when both DT_RPATH and DT_RUNPATH
				 * are present with the same value.
				 */
				if (printed && (last_d_val == dyn->d_un.d_val))
					continue;
				break;
			}

			if ((name != NULL) &&
			    (outstyle == ELFEDIT_OUTSTYLE_SIMPLE)) {
				elfedit_printf(MSG_ORIG(MSG_FMT_STRNL), name);
			} else {
				elfedit_printf(MSG_ORIG(MSG_FMT_HEXXWORDNL),
				    EC_XWORD(dyn->d_un.d_val));
			}
		}
		printed = 1;
		last_d_val = dyn->d_un.d_val;
	}

	/*
	 * If nothing was output under the print types that are
	 * based on tag type, issue an error saying it doesn't exist.
	 */
	if (!printed) {
		if (print_type == PRINT_DYN_T_TAG) {
			Conv_inv_buf_t	inv_buf;
			Ehdr		*ehdr = argstate->obj_state->os_ehdr;

			elfedit_msg(ELFEDIT_MSG_ERR,
			    MSG_INTL(MSG_ERR_NODYNELT),
			    EC_WORD(argstate->dyn.sec->sec_shndx),
			    argstate->dyn.sec->sec_name, conv_dyn_tag(arg,
			    ehdr->e_ident[EI_OSABI], ehdr->e_machine,
			    0, &inv_buf));
		}

		if (print_type == PRINT_DYN_T_RUNPATH)
			elfedit_msg(ELFEDIT_MSG_ERR,
			    MSG_INTL(MSG_ERR_NORUNPATH),
			    EC_WORD(argstate->dyn.sec->sec_shndx),
			    argstate->dyn.sec->sec_name);
	}
}


/*
 * Determine the index(s) of the dynamic element(s) to be displayed and/or
 * manipulated.
 *
 * entry:
 *	argstate - Argument state block
 *	arg - If the command being called accepts a first plain argument
 *		named 'elt' which is used to specify the dynamic element,
 *		arg is the value of argv[0] for that command. If the
 *		command does not accept an 'elt' argument and instead
 *		implicitly assumes a tag type, arg is the constant string
 *		for that type (e.g. "DT_POSFLAG_1").
 *	print_request - True if the command is to print the current
 *		value(s) and return without changing anything.
 *	print_type - Address of variable containing PRINT_DYN_T_
 *		code specifying how the elements will be displayed.
 *
 * exit:
 *	If print_request is False: This routine always returns the index
 *	of a single dynamic element. *print_type is set to PRINT_DYN_T_NDX.
 *	The 'elt' argument as well as any modifier options (-dynndx, -needed)
 *	are examined to determine this index. If there are no modifier options,
 *	the dynamic section contains no element of the desired type, and there
 *	is an extra DT_NULL element in the section, then a new element of
 *	the desired type is created and its index returned. Otherwise an
 *	error is issued.
 *
 *	If print_request is True: If a modifier (-dynndx, -needed) was used,
 *	*print_type is set to PRINT_DYN_T_NDX and the index of the
 *	corresponding single dynamic element is returned. If no modifier
 *	was used, *print_type is set to PRINT_DYN_T_TAG, and the tag
 *	type code is returned.
 */
static Word
arg_to_index(ARGSTATE *argstate, const char *arg,
    int print_request, PRINT_DYN_T *print_type)
{
	Word	ndx;
	Xword	dt_value;
	Dyn	*dyn;


	/* Assume we are returning an index, alter as needed below */
	*print_type = PRINT_DYN_T_NDX;

	/*
	 * All the commands that accept the DYN_OPT_F_DYNNDX_ELT form
	 * of -dynndx require a plain argument named 'elt' as their first
	 * argument. -dynndx is a modifier that means that 'elt' is a
	 * simple numeric section index. Routines that accept this form
	 * of -dynndx are willing to handle any tag type, so all we need
	 * to check is that the value is in range.
	 */
	if ((argstate->optmask & DYN_OPT_F_DYNNDX_ELT) != 0)
		return ((Word) elfedit_atoui_range(arg, MSG_ORIG(MSG_STR_ELT),
		    0, argstate->dyn.num - 1, NULL));

	/* arg is a DT_ tag type, not a numeric index */
	dt_value = (Word) elfedit_atoconst(arg, ELFEDIT_CONST_DT);

	/*
	 * Commands that accept the DYN_OPT_F_DYNNDX_VAL form  of
	 * dynndx do not accept the 'elt' argument. The index is a
	 * value that follows the option, and was saved in argstate by
	 * process_args(). Routines that accept this form of -dynndx
	 * require the specified element to have a specific tag type,
	 * so we test for this as well as for the index being in range.
	 */
	if ((argstate->optmask & DYN_OPT_F_DYNNDX_VAL) != 0) {
		ndx = ((Word) elfedit_atoui_range(argstate->dyn_elt_str,
		    MSG_ORIG(MSG_STR_INDEX), 0, argstate->dyn.num - 1, NULL));
		if (argstate->dyn.data[ndx].d_tag != dt_value) {
			Ehdr	*ehdr = argstate->obj_state->os_ehdr;
			uchar_t	osabi = ehdr->e_ident[EI_OSABI];
			Half	mach = ehdr->e_machine;
			Conv_inv_buf_t	is, want;

			elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_WRONGTAG),
			    EC_WORD(argstate->dyn.sec->sec_shndx),
			    argstate->dyn.sec->sec_name, ndx,
			    conv_dyn_tag(dt_value, osabi, mach, 0, &want),
			    conv_dyn_tag(argstate->dyn.data[ndx].d_tag,
			    osabi, mach, 0, &is));
		}
		return (ndx);
	}

	/*
	 * If this is a printing request, then we let print_dyn() show
	 * all the items with this tag type.
	 */
	if (print_request) {
		*print_type = PRINT_DYN_T_TAG;
		return (dt_value);
	}

	/*
	 * Commands that accept -needed are looking for the dt_value element
	 * (usually DT_POSFLAG_1) that immediately preceeds the DT_NEEDED
	 * element with the string given by argstate->dyn_elt_str.
	 */
	if ((argstate->optmask & DYN_OPT_F_NEEDED) != 0) {
		Word	retndx = argstate->dyn.num;	/* Out of range value */
		const char	*name;
		size_t		len;

		len = strlen(argstate->dyn_elt_str);
		for (ndx = 0, dyn = argstate->dyn.data;
		    ndx < argstate->dyn.num; dyn++, ndx++) {
			/*
			 * If the immediately preceeding item has the
			 * tag type we're looking for, and the current item
			 * is a DT_NEEDED with a string that matches,
			 * then the preceeding item is the one we want.
			 */
			if ((dyn->d_tag == DT_NEEDED) &&
			    (ndx > 0) && (retndx == (ndx - 1))) {
				name = elfedit_offset_to_str(argstate->strsec,
				    dyn->d_un.d_val, ELFEDIT_MSG_DEBUG, 0);

				if (strncmp(name,
				    argstate->dyn_elt_str, len) == 0)
					return (retndx);
				continue;
			}

			/*
			 * If the current item has the tag type we're
			 * looking for, make it our current candidate.
			 * If the next item is a DT_NEEDED with the right
			 * string value, we'll use it then.
			 */
			if (dyn->d_tag == dt_value)
				retndx = ndx;
		}

		/* If we get here, no matching DT_NEEDED was found */
		elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_NEEDEDNOMATCH),
		    EC_WORD(argstate->dyn.sec->sec_shndx),
		    argstate->dyn.sec->sec_name, argstate->dyn_elt_str);
	}

	/* Locate the first entry with the given tag type */
	for (ndx = 0; ndx < argstate->dyn.num; ndx++) {
		if (argstate->dyn.data[ndx].d_tag == dt_value) {
			elfedit_msg(ELFEDIT_MSG_DEBUG,
			    MSG_INTL(MSG_DEBUG_DT2NDX),
			    EC_WORD(argstate->dyn.sec->sec_shndx),
			    argstate->dyn.sec->sec_name, EC_WORD(ndx), arg);
			return (ndx);
		}
	}

	/* Not found. Can we create one? */
	if (argstate->dyn.num_null_ndx > 1)
		return (convert_dt_null(argstate, dt_value, 0));

	/* No room to create one, so we're out of options and must fail */
	elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_NODTELT),
	    EC_WORD(argstate->dyn.sec->sec_shndx),
	    argstate->dyn.sec->sec_name, arg);

	/*NOTREACHED*/
	return (0);		/* For lint */
}


/*
 * Called by cmd_body() for dyn:value. Implements the core functionality
 * for that command.
 *
 * This routine expects that both the index and value arguments are
 * present.
 */
static elfedit_cmdret_t
cmd_body_value(ARGSTATE *argstate, Word *ret_ndx)
{
	elfedit_section_t	*dynsec = argstate->dyn.sec;
	elfedit_section_t	*strsec = argstate->strsec;
	elfedit_dyn_elt_t	strpad_elt;
	Word	i;
	Dyn	*dyn = argstate->dyn.data;
	Word	numdyn = argstate->dyn.num;
	int	minus_add, minus_s, minus_dynndx;
	Word	tmp_val;
	Xword	arg1, arg2;
	int	arg2_known = 1;

	minus_add = ((argstate->optmask & DYN_OPT_F_ADD) != 0);
	minus_s = ((argstate->optmask & DYN_OPT_F_STRVAL) != 0);
	minus_dynndx = ((argstate->optmask & DYN_OPT_F_DYNNDX_ELT) != 0);

	elfedit_dyn_elt_init(&strpad_elt);

	/*
	 * The first argument is an index if -dynndx is used, and is a
	 * tag value otherwise.
	 */
	arg1 = minus_dynndx ?
	    elfedit_atoui_range(argstate->argv[0], MSG_ORIG(MSG_STR_ELT),
	    0, numdyn - 1, NULL) :
	    elfedit_atoconst(argstate->argv[0], ELFEDIT_CONST_DT);

	if (minus_s) {
		/*
		 * Don't allow the user to specify -s when manipulating a
		 * DT_SUNW_STRPAD element. Since DT_SUNW_STRPAD is used to
		 * manage the extra space used for strings, this would break
		 * our ability to add the string.
		 */
		if ((!minus_dynndx && (arg1 == DT_SUNW_STRPAD)) ||
		    (minus_dynndx && (dyn[arg1].d_tag == DT_SUNW_STRPAD)))
			elfedit_msg(ELFEDIT_MSG_ERR,
			    MSG_INTL(MSG_ERR_STRPADSTRVAL),
			    EC_WORD(dynsec->sec_shndx), dynsec->sec_name);

		/* Locate DT_SUNW_STRPAD element if present */
		strpad_elt.dn_dyn.d_un.d_val = 0;
		(void) elfedit_dynstr_getpad(argstate->obj_state,
		    argstate->dyn.sec, &strpad_elt);

		/*
		 * Look up the string: If the user specified the -dynndx
		 * -option, then we will insert it if possible, and
		 * fail with an error if not. However, if they did not
		 * specify -dynndx, we want to look up the string if it is
		 * already there, but defer the insertion. The reason for
		 * this is that we may have to grab an unused DT_NULL element
		 * below, and if there are none available, we won't want
		 * to have modified the string table.
		 *
		 * This isn't a problem, because if the string isn't
		 * in the string table, it can't be used by a dynamic element.
		 * Hence, we don't need to insert it to know that there is
		 * no match.
		 */
		if (minus_dynndx == 0) {
			if (elfedit_sec_findstr(strsec,
			    strpad_elt.dn_dyn.d_un.d_val, argstate->argv[1],
			    &tmp_val) == 0) {
				arg2_known = 0;
			} else {
				arg2 = tmp_val;
			}
		} else {
			arg2 = elfedit_dynstr_insert(dynsec, strsec,
			    &strpad_elt, argstate->argv[1]);
		}
	} else {		/* Argument 2 is an integer */
		arg2 = elfedit_atoui(argstate->argv[1], NULL);
	}


	if (!minus_dynndx && !(minus_add && !arg2_known)) {
		/*
		 * Search the dynamic section and see if an item with the
		 * specified tag value already exists. We can reduce this
		 * to a simple update of an existing value if -add is not
		 * specified or the existing d_un value matches the new one.
		 *
		 * In either of these cases, we will change arg1 to be the
		 * index, and set minus_dynndx, causing the simple update to
		 * happen immediately below.
		 */
		for (i = 0; i < numdyn; i++) {
			if ((dyn[i].d_tag == arg1) &&
			    (!minus_add || (dyn[i].d_un.d_val == arg2))) {
				arg1 = i;
				minus_dynndx = 1;
				break;
			}
		}
	}

	/*
	 * If -dynndx is used, then this is a relatively simple
	 * operation, as we simply write over the specified index.
	 */
	if (minus_dynndx) {
		/*
		 * If we held back from inserting a new string into
		 * the dynstr above, we insert it now, because we
		 * have a slot in the dynamic section, and we need
		 * the string offset ot finish.
		 */
		if (!arg2_known)
			arg2 = elfedit_dynstr_insert(dynsec, strsec,
			    &strpad_elt, argstate->argv[1]);

		*ret_ndx = arg1;
		if (dyn[arg1].d_un.d_val == arg2) {
			elfedit_msg(ELFEDIT_MSG_DEBUG,
			    MSG_INTL(MSG_DEBUG_X_OK),
			    dynsec->sec_shndx, dynsec->sec_name,
			    EC_WORD(arg1), EC_XWORD(arg2));
			return (ELFEDIT_CMDRET_NONE);
		} else {
			/* Warn if setting DT_NULL value to non-zero */
			if ((dyn[arg1].d_tag == DT_NULL) && (arg2 != 0))
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_DTNULLVALUE),
				    dynsec->sec_shndx, dynsec->sec_name,
				    EC_WORD(arg1), EC_XWORD(arg2));

			elfedit_msg(ELFEDIT_MSG_DEBUG,
			    MSG_INTL(MSG_DEBUG_X_CHG),
			    dynsec->sec_shndx, dynsec->sec_name,
			    EC_WORD(arg1), EC_XWORD(dyn[arg1].d_un.d_val),
			    EC_XWORD(arg2));
			dyn[arg1].d_un.d_val = arg2;
			return (ELFEDIT_CMDRET_MOD);
		}
	}

	/*
	 * We need a new slot in the dynamic section. If we can't have
	 * one, then we fail.
	 */
	if (argstate->dyn.num_null_ndx <= 1)
		elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_NOEXTRANULL),
		    EC_WORD(dynsec->sec_shndx), dynsec->sec_name);

	/*
	 * If we still need to insert a new string into the dynstr,
	 * then it is safe now, because if we succeed, we know that
	 * there is an available slot to receive it. If we fail, we
	 * haven't claimed the extra slot yet, and it will be unharmed.
	 */
	if (!arg2_known)
		arg2 = elfedit_dynstr_insert(dynsec, strsec,
		    &strpad_elt, argstate->argv[1]);

	/* Use an extra DT_NULL slot and enter the new element */
	*ret_ndx = convert_dt_null(argstate, arg1, arg2);
	return (ELFEDIT_CMDRET_MOD);
}



/*
 * Called by cmd_body() for dyn:runpath. Implements the core functionality
 * for that command.
 *
 * History Lesson And Strategy:
 *
 * This routine handles both DT_RPATH and DT_RUNPATH entries, altering
 * either or both if they are present.
 *
 * The original SYSV ABI only had DT_RPATH, and the runtime loader used
 * it to search for things in the following order:
 *
 *	DT_RPATH, LD_LIBRARY_PATH, defaults
 *
 * Solaris did not follow this rule, an extremely rare deviation from
 * the ABI. Environment variables should supercede everything else,
 * otherwise they are not very useful. This decision was made at the
 * very beginning of the SunOS 5.x development, so we have always
 * deviated from the ABI and and instead search in the order
 *
 *	LD_LIBRARY_PATH, DT_RPATH, defaults
 *
 * Other Unix variants initially followed the ABI, but in recent years
 * have come to agree with the early Solaris folks that it was a mistake.
 * Hence, DT_RUNPATH was invented, with the search order:
 *
 *	LD_LIBRARY_PATH, DT_RUNPATH, defaults
 *
 * So for Solaris, DT_RPATH and DT_RUNPATH mean the same thing. If both
 * are present (which does happen), we set them both to the new
 * value. If either one is present, we set that one. If neither is
 * present, and we have a spare DT_NULL slot, we create a DT_RUNPATH, but
 * not a DT_RPATH, to conserve available slots for other uses.
 */
static elfedit_cmdret_t
cmd_body_runpath(ARGSTATE *argstate)
{
	elfedit_section_t	*dynsec = argstate->dyn.sec;
	elfedit_section_t	*strsec = argstate->strsec;
	elfedit_dyn_elt_t	rpath_elt;
	elfedit_dyn_elt_t	runpath_elt;
	elfedit_dyn_elt_t	strpad_elt;
	Word			i;
	Dyn			*dyn = argstate->dyn.data;
	Word			numdyn = argstate->dyn.num;

	/* Go through the tags and gather what we need */
	elfedit_dyn_elt_init(&rpath_elt);
	elfedit_dyn_elt_init(&runpath_elt);
	elfedit_dyn_elt_init(&strpad_elt);
	for (i = 0; i < numdyn; i++) {
		switch (dyn[i].d_tag) {
		case DT_RPATH:
			elfedit_dyn_elt_save(&rpath_elt, i, &dyn[i]);
			break;

		case DT_RUNPATH:
			elfedit_dyn_elt_save(&runpath_elt, i, &dyn[i]);
			break;

		case DT_SUNW_STRPAD:
			if (elfedit_test_osabi(argstate->obj_state,
			    ELFOSABI_SOLARIS, 0))
				elfedit_dyn_elt_save(&strpad_elt, i, &dyn[i]);
			break;
		}
	}

	/*  Do we have an available dynamic section entry to use? */
	if (rpath_elt.dn_seen || runpath_elt.dn_seen) {
		/*
		 * We have seen a DT_RPATH, or a DT_RUNPATH, or both.
		 * If all of these have the same string as the desired
		 * new value, then we don't need to alter anything and can
		 * simply return. Otherwise, we'll modify them all to have
		 * the new string (below).
		 */
		if ((!rpath_elt.dn_seen ||
		    (strcmp(elfedit_dyn_offset_to_str(strsec, &rpath_elt),
		    argstate->argv[0]) == 0)) &&
		    (!runpath_elt.dn_seen ||
		    (strcmp(elfedit_dyn_offset_to_str(strsec, &runpath_elt),
		    argstate->argv[0]) == 0))) {
			if (rpath_elt.dn_seen)
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_OLDRPATHOK),
				    EC_WORD(dynsec->sec_shndx),
				    dynsec->sec_name, EC_WORD(rpath_elt.dn_ndx),
				    elfedit_atoconst_value_to_str(
				    ELFEDIT_CONST_DT, DT_RPATH, 1));
			if (runpath_elt.dn_seen)
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_OLDRPATHOK),
				    EC_WORD(dynsec->sec_shndx),
				    dynsec->sec_name,
				    EC_WORD(runpath_elt.dn_ndx),
				    elfedit_atoconst_value_to_str(
				    ELFEDIT_CONST_DT, DT_RUNPATH, 1));
			return (ELFEDIT_CMDRET_NONE);
		}
	} else if (argstate->dyn.num_null_ndx <= 1) {
		/*
		 * There is no DT_RPATH or DT_RUNPATH in the dynamic array,
		 * and there are no extra DT_NULL entries that we can
		 * convert into one. We cannot proceed.
		 */
		elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_NOEXTRANULL),
		    EC_WORD(dynsec->sec_shndx), dynsec->sec_name);
	}

	/* Does the string exist in the table already, or can we add it? */
	rpath_elt.dn_dyn.d_un.d_val = runpath_elt.dn_dyn.d_un.d_val =
	    elfedit_dynstr_insert(dynsec, strsec, &strpad_elt,
	    argstate->argv[0]);

	/* Update DT_RPATH entry if present */
	if (rpath_elt.dn_seen) {
		elfedit_msg(ELFEDIT_MSG_DEBUG, MSG_INTL(MSG_DEBUG_PREVRPATH),
		    EC_WORD(dynsec->sec_shndx), dynsec->sec_name,
		    EC_WORD(rpath_elt.dn_ndx),
		    elfedit_atoconst_value_to_str(
		    ELFEDIT_CONST_DT, DT_RPATH, 1),
		    elfedit_dyn_offset_to_str(strsec, &rpath_elt));
		dyn[rpath_elt.dn_ndx] = rpath_elt.dn_dyn;
	}

	/*
	 * Update the DT_RUNPATH entry in the dynamic section, if present.
	 * If one is not present, and there is also no DT_RPATH, then
	 * we use a spare DT_NULL entry to create a new DT_RUNPATH.
	 */
	if (runpath_elt.dn_seen || !rpath_elt.dn_seen) {
		if (runpath_elt.dn_seen) {
			elfedit_msg(ELFEDIT_MSG_DEBUG,
			    MSG_INTL(MSG_DEBUG_PREVRPATH),
			    EC_WORD(dynsec->sec_shndx), dynsec->sec_name,
			    EC_WORD(runpath_elt.dn_ndx),
			    elfedit_atoconst_value_to_str(
			    ELFEDIT_CONST_DT, DT_RUNPATH, 1),
			    elfedit_dyn_offset_to_str(strsec, &runpath_elt));
			dyn[runpath_elt.dn_ndx] = runpath_elt.dn_dyn;
		} else {	/* Using a spare DT_NULL entry */
			(void) convert_dt_null(argstate, DT_RUNPATH,
			    runpath_elt.dn_dyn.d_un.d_val);
		}
	}

	return (ELFEDIT_CMDRET_MOD);
}



/*
 * Argument processing for the bitmask commands. Convert the arguments
 * to integer form, apply -and/-cmp/-or, and return the resulting value.
 *
 * entry:
 *	argstate - Argument state block
 *	orig - Value of original bitmask
 *	const_type - ELFEDIT_CONST_* value for type of constants
 */
static Word
flag_bitop(ARGSTATE *argstate, Word orig, elfedit_const_t const_type)
{
	Word flags = 0;
	int i;

	/* Collect the arguments */
	for (i = 0; i < argstate->argc; i++)
		flags |= (Word) elfedit_atoconst(argstate->argv[i], const_type);

	/* Complement the value? */
	if (argstate->optmask & DYN_OPT_F_CMP)
		flags = ~flags;

	/* Perform any requested bit operations */
	if (argstate->optmask & DYN_OPT_F_AND)
		flags &= orig;
	else if (argstate->optmask & DYN_OPT_F_OR)
		flags |= orig;

	return (flags);
}



/*
 * Common body for the dyn: module commands. These commands
 * share a large amount of common behavior, so it is convenient
 * to centralize things and use the cmd argument to handle the
 * small differences.
 *
 * entry:
 *	cmd - One of the DYN_CMD_T_* constants listed above, specifying
 *		which command to implement.
 *	obj_state, argc, argv - Standard command arguments
 */
static elfedit_cmdret_t
cmd_body(DYN_CMD_T cmd, elfedit_obj_state_t *obj_state,
    int argc, const char *argv[])
{
	ARGSTATE		argstate;
	Dyn			*dyn;
	const char		*dyn_name;
	Word			dyn_ndx, dyn_num, null_ndx;
	elfedit_cmdret_t	ret = ELFEDIT_CMDRET_NONE;
	PRINT_DYN_T		print_type = PRINT_DYN_T_ALL;
	Word			ndx;
	int			print_only = 0;
	int			do_autoprint = 1;

	/* Process the optional arguments */
	process_args(obj_state, argc, argv, &argstate);

	dyn = argstate.dyn.data;
	dyn_num = argstate.dyn.num;
	dyn_name = argstate.dyn.sec->sec_name;
	dyn_ndx = argstate.dyn.sec->sec_shndx;

	/* Check number of arguments, gather information */
	switch (cmd) {
	case DYN_CMD_T_DUMP:
		/* dyn:dump can accept an optional index argument */
		if (argstate.argc > 1)
			elfedit_command_usage();
		print_only = 1;
		if (argstate.argc == 1)
			ndx = arg_to_index(&argstate, argstate.argv[0],
			    print_only, &print_type);
		break;

	case DYN_CMD_T_TAG:
		print_only = (argstate.argc != 2);
		if (argstate.argc > 0) {
			if (argstate.argc > 2)
				elfedit_command_usage();
			ndx = arg_to_index(&argstate, argstate.argv[0],
			    print_only, &print_type);
		}
		break;

	case DYN_CMD_T_VALUE:
		print_only = (argstate.argc != 2);
		if (argstate.argc > 2)
			elfedit_command_usage();
		if (argstate.argc > 0) {
			if (print_only) {
				ndx = arg_to_index(&argstate, argstate.argv[0],
				    print_only, &print_type);
			} else {
				print_type = PRINT_DYN_T_NDX;
			}
		}
		break;

	case DYN_CMD_T_DELETE:
		if ((argstate.argc < 1) || (argstate.argc > 2))
			elfedit_command_usage();
		ndx = arg_to_index(&argstate, argstate.argv[0],
		    0, &print_type);
		do_autoprint = 0;
		break;

	case DYN_CMD_T_MOVE:
		if ((argstate.argc < 2) || (argstate.argc > 3))
			elfedit_command_usage();
		ndx = arg_to_index(&argstate, argstate.argv[0],
		    0, &print_type);
		do_autoprint = 0;
		break;

	case DYN_CMD_T_RUNPATH:
		if (argstate.argc > 1)
			elfedit_command_usage();
		/*
		 * dyn:runpath does not accept an explicit index
		 * argument, so we implicitly only show the DT_RPATH and
		 * DT_RUNPATH elements.
		 */
		print_type = PRINT_DYN_T_RUNPATH;
		print_only = (argstate.argc == 0);
		break;

	case DYN_CMD_T_POSFLAG1:
		print_only = (argstate.argc == 0);
		ndx = arg_to_index(&argstate, elfedit_atoconst_value_to_str(
		    ELFEDIT_CONST_DT, DT_POSFLAG_1, 1),
		    print_only, &print_type);
		break;

	case DYN_CMD_T_FLAGS:
		print_only = (argstate.argc == 0);
		ndx = arg_to_index(&argstate, elfedit_atoconst_value_to_str(
		    ELFEDIT_CONST_DT, DT_FLAGS, 1),
		    print_only, &print_type);
		break;

	case DYN_CMD_T_FLAGS1:
		print_only = (argstate.argc == 0);
		ndx = arg_to_index(&argstate, elfedit_atoconst_value_to_str(
		    ELFEDIT_CONST_DT, DT_FLAGS_1, 1),
		    print_only, &print_type);
		break;

	case DYN_CMD_T_FEATURE1:
		print_only = (argstate.argc == 0);
		ndx = arg_to_index(&argstate, elfedit_atoconst_value_to_str(
		    ELFEDIT_CONST_DT, DT_FEATURE_1, 1),
		    print_only, &print_type);
		break;

	case DYN_CMD_T_CHECKSUM:
		ndx = arg_to_index(&argstate, elfedit_atoconst_value_to_str(
		    ELFEDIT_CONST_DT, DT_CHECKSUM, 1),
		    print_only, &print_type);
		break;

	case DYN_CMD_T_SUNW_LDMACH:
		if (argstate.argc > 1)
			elfedit_command_usage();
		/* DT_SUNW_LDMACH is an ELFOSABI_SOLARIS feature */
		(void) elfedit_test_osabi(argstate.obj_state,
		    ELFOSABI_SOLARIS, 1);
		print_only = (argstate.argc == 0);
		ndx = arg_to_index(&argstate, elfedit_atoconst_value_to_str(
		    ELFEDIT_CONST_DT, DT_SUNW_LDMACH, 1),
		    print_only, &print_type);
		break;

	default:
		/* Note expected: All commands should have been caught above */
		elfedit_command_usage();
		break;
	}


	/* If this is a request to print current values, do it and return */
	if (print_only) {
		print_dyn(cmd, 0, &argstate, print_type, ndx);
		return (ELFEDIT_CMDRET_NONE);
	}


	switch (cmd) {
		/*
		 * DYN_CMD_T_DUMP can't get here: It is a print-only
		 * command.
		 */

	case DYN_CMD_T_TAG:
		{
			Ehdr		*ehdr = argstate.obj_state->os_ehdr;
			uchar_t		osabi = ehdr->e_ident[EI_OSABI];
			Half		mach = ehdr->e_machine;
			Conv_inv_buf_t	inv_buf1, inv_buf2;
			Xword d_tag = (Xword) elfedit_atoconst(argstate.argv[1],
			    ELFEDIT_CONST_DT);

			if (dyn[ndx].d_tag == d_tag) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_S_OK), dyn_ndx, dyn_name,
				    EC_WORD(ndx), conv_dyn_tag(d_tag, osabi,
				    mach, 0, &inv_buf1));
			} else {
				Xword orig_d_tag = dyn[ndx].d_tag;

				ret = ELFEDIT_CMDRET_MOD;
				dyn[ndx].d_tag = d_tag;

				/*
				 * Update null termination index. Warn if we
				 * just clobbered the only DT_NULL termination
				 * for the array.
				 */
				null_ndx = argstate.dyn.null_ndx;
				set_null_ndx(&argstate);
				if ((argstate.dyn.null_ndx >=
				    argstate.dyn.num) &&
				    (null_ndx != argstate.dyn.null_ndx))
					elfedit_msg(ELFEDIT_MSG_DEBUG,
					    MSG_INTL(MSG_DEBUG_NULLTERM),
					    dyn_ndx, dyn_name,
					    EC_WORD(ndx), conv_dyn_tag(d_tag,
					    osabi, mach, 0, &inv_buf1));

				/*
				 * Warning if
				 *	- Inserting a DT_NULL cuts off following
				 *		non-null elements.
				 *	- Inserting a non-DT_NULL after the
				 *		first null element, will be
				 *		ignored by rtld.
				 */
				if (d_tag == DT_NULL) {
					if ((ndx + 1) < null_ndx)
						elfedit_msg(ELFEDIT_MSG_DEBUG,
						    MSG_INTL(MSG_DEBUG_NULCLIP),
						    dyn_ndx, dyn_name,
						    EC_WORD(ndx),
						    conv_dyn_tag(d_tag, osabi,
						    mach, 0, &inv_buf1));
				} else {
					if ((ndx + 1) > argstate.dyn.null_ndx)
						elfedit_msg(ELFEDIT_MSG_DEBUG,
						    MSG_INTL(MSG_DEBUG_NULHIDE),
						    dyn_ndx, dyn_name,
						    EC_WORD(ndx),
						    conv_dyn_tag(d_tag, osabi,
						    mach, 0, &inv_buf1));
				}

				/* Debug message that we changed it */
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_S_CHG),
				    dyn_ndx, dyn_name, EC_WORD(ndx),
				    conv_dyn_tag(orig_d_tag, osabi, mach, 0,
				    &inv_buf1),
				    conv_dyn_tag(d_tag, osabi, mach, 0,
				    &inv_buf2));
			}
		}
		break;

	case DYN_CMD_T_VALUE:
		ret = cmd_body_value(&argstate, &ndx);
		break;

	case DYN_CMD_T_DELETE:
		{
			Word cnt = (argstate.argc == 1) ? 1 :
			    (Word) elfedit_atoui_range(argstate.argv[1],
			    MSG_ORIG(MSG_STR_COUNT), 1, dyn_num - ndx, NULL);
			const char *msg_prefix =
			    elfedit_sec_msgprefix(argstate.dyn.sec);

			elfedit_array_elts_delete(msg_prefix, argstate.dyn.data,
			    sizeof (Dyn), dyn_num, ndx, cnt);
			ret = ELFEDIT_CMDRET_MOD;
		}
		break;

	case DYN_CMD_T_MOVE:
		{
			Dyn	save;
			Word	cnt;
			Word	dstndx;
			const char *msg_prefix =
			    elfedit_sec_msgprefix(argstate.dyn.sec);

			dstndx = (Word)
			    elfedit_atoui_range(argstate.argv[1],
			    MSG_ORIG(MSG_STR_DST_INDEX), 0, dyn_num - 1,
			    NULL);
			if (argstate.argc == 2) {
				cnt = 1;
			} else {
				cnt = (Word) elfedit_atoui_range(
				    argstate.argv[2], MSG_ORIG(MSG_STR_COUNT),
				    1, dyn_num, NULL);
			}
			elfedit_array_elts_move(msg_prefix, argstate.dyn.data,
			    sizeof (save), dyn_num, ndx, dstndx, cnt, &save);
			ret = ELFEDIT_CMDRET_MOD;
		}
		break;


	case DYN_CMD_T_RUNPATH:
		ret = cmd_body_runpath(&argstate);
		break;

	case DYN_CMD_T_POSFLAG1:
		{
			Conv_dyn_posflag1_buf_t buf1, buf2;
			Word flags;

			flags = flag_bitop(&argstate, dyn[ndx].d_un.d_val,
			    ELFEDIT_CONST_DF_P1);

			/* Set the value */
			if (dyn[ndx].d_un.d_val == flags) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_S_OK), dyn_ndx,
				    dyn_name, EC_WORD(ndx),
				    conv_dyn_posflag1(dyn[ndx].d_un.d_val, 0,
				    &buf1));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_S_CHG),
				    dyn_ndx, dyn_name, EC_WORD(ndx),
				    conv_dyn_posflag1(dyn[ndx].d_un.d_val, 0,
				    &buf1),
				    conv_dyn_posflag1(flags, 0, &buf2));
				ret = ELFEDIT_CMDRET_MOD;
				dyn[ndx].d_un.d_val = flags;
			}
		}
		break;

	case DYN_CMD_T_FLAGS:
		{
			Conv_dyn_flag_buf_t buf1, buf2;
			Word flags;

			flags = flag_bitop(&argstate, dyn[ndx].d_un.d_val,
			    ELFEDIT_CONST_DF);

			/* Set the value */
			if (dyn[ndx].d_un.d_val == flags) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_S_OK), dyn_ndx,
				    dyn_name, EC_WORD(ndx),
				    conv_dyn_flag(dyn[ndx].d_un.d_val, 0,
				    &buf1));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_S_CHG),
				    dyn_ndx, dyn_name, EC_WORD(ndx),
				    conv_dyn_flag(dyn[ndx].d_un.d_val, 0,
				    &buf1),
				    conv_dyn_flag(flags, 0, &buf2));
				ret = ELFEDIT_CMDRET_MOD;
				dyn[ndx].d_un.d_val = flags;
			}
		}
		break;

	case DYN_CMD_T_FLAGS1:
		{
			Conv_dyn_flag1_buf_t buf1, buf2;
			Word flags1;

			flags1 = flag_bitop(&argstate, dyn[ndx].d_un.d_val,
			    ELFEDIT_CONST_DF_1);

			/* Set the value */
			if (dyn[ndx].d_un.d_val == flags1) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_S_OK), dyn_ndx,
				    dyn_name, EC_WORD(ndx),
				    conv_dyn_flag1(dyn[ndx].d_un.d_val,
				    0, &buf1));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_S_CHG),
				    dyn_ndx, dyn_name, EC_WORD(ndx),
				    conv_dyn_flag1(dyn[ndx].d_un.d_val,
				    0, &buf1),
				    conv_dyn_flag1(flags1, 0, &buf2));
				ret = ELFEDIT_CMDRET_MOD;
				dyn[ndx].d_un.d_val = flags1;
			}
		}
		break;

	case DYN_CMD_T_FEATURE1:
		{
			Conv_dyn_feature1_buf_t buf1, buf2;
			Word flags;

			flags = flag_bitop(&argstate, dyn[ndx].d_un.d_val,
			    ELFEDIT_CONST_DTF_1);

			/* Set the value */
			if (dyn[ndx].d_un.d_val == flags) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_S_OK), dyn_ndx,
				    dyn_name, EC_WORD(ndx),
				    conv_dyn_feature1(dyn[ndx].d_un.d_val, 0,
				    &buf1));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_S_CHG),
				    dyn_ndx, dyn_name, EC_WORD(ndx),
				    conv_dyn_feature1(dyn[ndx].d_un.d_val, 0,
				    &buf1),
				    conv_dyn_feature1(flags, 0, &buf2));
				ret = ELFEDIT_CMDRET_MOD;
				dyn[ndx].d_un.d_val = flags;
			}
		}
		break;

	case DYN_CMD_T_CHECKSUM:
		{
			long checksum = elf_checksum(obj_state->os_elf);

			/* Set the value */
			if (dyn[ndx].d_un.d_val == checksum) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_X_OK), dyn_ndx,
				    dyn_name, EC_WORD(ndx), EC_XWORD(checksum));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_X_CHG),
				    dyn_ndx, dyn_name, EC_WORD(ndx),
				    EC_XWORD(dyn[ndx].d_un.d_val),
				    EC_XWORD(checksum));
				ret = ELFEDIT_CMDRET_MOD;
				dyn[ndx].d_un.d_val = checksum;
			}

		}
		break;

	case DYN_CMD_T_SUNW_LDMACH:
		{
			Conv_inv_buf_t buf1, buf2;
			Half ldmach;

			ldmach = (Half) elfedit_atoconst(argstate.argv[0],
			    ELFEDIT_CONST_EM);

			/* Set the value */
			if (dyn[ndx].d_un.d_val == ldmach) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_S_OK), dyn_ndx,
				    dyn_name, EC_WORD(ndx),
				    conv_ehdr_mach(dyn[ndx].d_un.d_val, 0,
				    &buf1));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_S_CHG),
				    dyn_ndx, dyn_name, EC_WORD(ndx),
				    conv_ehdr_mach(dyn[ndx].d_un.d_val, 0,
				    &buf1),
				    conv_ehdr_mach(ldmach, 0, &buf2));
				ret = ELFEDIT_CMDRET_MOD;
				dyn[ndx].d_un.d_val = ldmach;
			}
		}
		break;

	}

	/*
	 * If we modified the dynamic section header, tell libelf.
	 */
	if (ret == ELFEDIT_CMDRET_MOD)
		elfedit_modified_data(argstate.dyn.sec);

	/* Do autoprint */
	if (do_autoprint)
		print_dyn(cmd, 1, &argstate, print_type, ndx);

	return (ret);
}



/*
 * Command completion functions for the commands
 */

/*
 * Command completion for the first argument, which specifies
 * the dynamic element to use. Examines the options to see if
 * -dynndx is present, and if not, supplies the completion
 * strings for argument 1.
 */
/*ARGSUSED*/
static void
cpl_eltarg(elfedit_obj_state_t *obj_state, void *cpldata, int argc,
    const char *argv[], int num_opt)
{
	elfedit_section_t	*cache;
	Dyn			*dyn;
	Word			i;
	const char		*s;
	char			*s2;
	char			buf[128];

	/* Make sure it's the first argument */
	if ((argc - num_opt) != 1)
		return;

	/* Is -dynndx present? If so, we don't complete tag types */
	for (i = 0; i < num_opt; i++)
		if (strcmp(argv[i], MSG_ORIG(MSG_STR_MINUS_DYNNDX)) == 0)
			return;

	/*
	 * If there is no object, or if there is no dynamic section,
	 * then supply all possible names.
	 */
	if ((obj_state == NULL) || (obj_state->os_dynndx == SHN_UNDEF)) {
		elfedit_cpl_atoconst(cpldata, ELFEDIT_CONST_DT);
		return;
	}

	/* Supply completions for the tags present in the dynamic section */
	cache = &obj_state->os_secarr[obj_state->os_dynndx];
	dyn = (Dyn *) cache->sec_data->d_buf;
	i = cache->sec_shdr->sh_size / cache->sec_shdr->sh_entsize;
	for (; i-- > 0; dyn++) {
		s = elfedit_atoconst_value_to_str(ELFEDIT_CONST_DT,
		    dyn->d_tag, 0);
		if (s == NULL)
			continue;
		elfedit_cpl_match(cpldata, s, 1);

		/*
		 * To get the informal tag names that are lowercase
		 * and lack the leading DT_, we copy the string we
		 * have into a buffer and process it.
		 */
		if (strlen(s) < 3)
			continue;
		(void) strlcpy(buf, s + 3, sizeof (buf));
		for (s2 = buf; *s2 != '\0'; s2++)
			if (isupper(*s2))
				*s2 = tolower(*s2);
		elfedit_cpl_match(cpldata, buf, 1);
	}
}


/*ARGSUSED*/
static void
cpl_tag(elfedit_obj_state_t *obj_state, void *cpldata, int argc,
    const char *argv[], int num_opt)
{
	/* First argument */
	if ((argc - num_opt) == 1) {
		cpl_eltarg(obj_state, cpldata, argc, argv, num_opt);
		return;
	}

	/* The second argument is always a tag value */
	if ((argc - num_opt) == 2)
		elfedit_cpl_atoconst(cpldata, ELFEDIT_CONST_DT);
}

/*ARGSUSED*/
static void
cpl_posflag1(elfedit_obj_state_t *obj_state, void *cpldata, int argc,
    const char *argv[], int num_opt)
{
	/*
	 * dyn:posflag1 accepts two mutually exclusive options that have
	 * a corresponding value argument: -dynndx and -needed. If we
	 * are being called to supply options for the value, handle that here.
	 */
	if ((num_opt > 1) && (argc == num_opt)) {
		elfedit_section_t	*dynsec, *strsec;
		const char		*opt = argv[num_opt - 2];
		dyn_opt_t		type;
		Dyn			*dyn;
		Word			i, num;

		/*
		 * If there is no object available, or if the object has no
		 * dynamic section, then there is nothing to report.
		 */
		if ((obj_state == NULL) || obj_state->os_dynndx == SHN_UNDEF)
			return;

		/*
		 * Determine which option it is, bail if it isn't one of
		 * the ones we are concerned with.
		 */
		if ((strcmp(opt, MSG_ORIG(MSG_STR_MINUS_NEEDED)) == 0))
			type = DYN_OPT_F_NEEDED;
		else if ((strcmp(opt, MSG_ORIG(MSG_STR_MINUS_DYNNDX)) == 0))
			type = DYN_OPT_F_DYNNDX_VAL;
		else
			return;

		dynsec = elfedit_sec_getdyn(obj_state, &dyn, &num);
		switch (type) {
		case DYN_OPT_F_NEEDED:
			strsec = elfedit_sec_getstr(obj_state,
			    dynsec->sec_shdr->sh_link, 0);
			for (; num-- > 0; dyn++)
				if (dyn->d_tag == DT_NEEDED)
					elfedit_cpl_match(cpldata,
					    elfedit_offset_to_str(strsec,
					    dyn->d_un.d_val, ELFEDIT_MSG_DEBUG,
					    0), 0);
			break;

		case DYN_OPT_F_DYNNDX_VAL:
			for (i = 0; i < num; i++, dyn++)
				if (dyn->d_tag == DT_POSFLAG_1)
					elfedit_cpl_ndx(cpldata, i);
			break;
		}
		return;
	}

	/* This routine allows multiple flags to be specified */
	elfedit_cpl_atoconst(cpldata, ELFEDIT_CONST_DF_P1);
}

/*ARGSUSED*/
static void
cpl_flags(elfedit_obj_state_t *obj_state, void *cpldata, int argc,
    const char *argv[], int num_opt)
{
	/* This routine allows multiple flags to be specified */
	elfedit_cpl_atoconst(cpldata, ELFEDIT_CONST_DF);
}

/*ARGSUSED*/
static void
cpl_flags1(elfedit_obj_state_t *obj_state, void *cpldata, int argc,
    const char *argv[], int num_opt)
{
	/* This routine allows multiple flags to be specified */
	elfedit_cpl_atoconst(cpldata, ELFEDIT_CONST_DF_1);
}

/*ARGSUSED*/
static void
cpl_feature1(elfedit_obj_state_t *obj_state, void *cpldata, int argc,
    const char *argv[], int num_opt)
{
	/* This routine allows multiple flags to be specified */
	elfedit_cpl_atoconst(cpldata, ELFEDIT_CONST_DTF_1);
}

/*ARGSUSED*/
static void
cpl_sunw_ldmach(elfedit_obj_state_t *obj_state, void *cpldata, int argc,
    const char *argv[], int num_opt)
{
	/*
	 * This command doesn't accept options, so num_opt should be
	 * 0. This is a defensive measure, in case that should change.
	 */
	argc -= num_opt;
	argv += num_opt;

	if (argc == 1)
		elfedit_cpl_atoconst(cpldata, ELFEDIT_CONST_EM);
}


/*
 * Implementation functions for the commands
 */
static elfedit_cmdret_t
cmd_dump(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(DYN_CMD_T_DUMP, obj_state, argc, argv));
}

static elfedit_cmdret_t
cmd_tag(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(DYN_CMD_T_TAG, obj_state, argc, argv));
}

static elfedit_cmdret_t
cmd_value(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(DYN_CMD_T_VALUE, obj_state, argc, argv));
}

static elfedit_cmdret_t
cmd_delete(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(DYN_CMD_T_DELETE, obj_state, argc, argv));
}

static elfedit_cmdret_t
cmd_move(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(DYN_CMD_T_MOVE, obj_state, argc, argv));
}

static elfedit_cmdret_t
cmd_runpath(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(DYN_CMD_T_RUNPATH, obj_state, argc, argv));
}

static elfedit_cmdret_t
cmd_posflag1(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(DYN_CMD_T_POSFLAG1, obj_state, argc, argv));
}

static elfedit_cmdret_t
cmd_flags(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(DYN_CMD_T_FLAGS, obj_state, argc, argv));
}

static elfedit_cmdret_t
cmd_flags1(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(DYN_CMD_T_FLAGS1, obj_state, argc, argv));
}

static elfedit_cmdret_t
cmd_feature1(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(DYN_CMD_T_FEATURE1, obj_state, argc, argv));
}

static elfedit_cmdret_t
cmd_checksum(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(DYN_CMD_T_CHECKSUM, obj_state, argc, argv));
}

static elfedit_cmdret_t
cmd_sunw_ldmach(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(DYN_CMD_T_SUNW_LDMACH, obj_state, argc, argv));
}



/*ARGSUSED*/
elfedit_module_t *
elfedit_init(elfedit_module_version_t version)
{
	/* For commands that only accept -o */
	static elfedit_cmd_optarg_t opt_ostyle[] = {
		{ ELFEDIT_STDOA_OPT_O, 0,
		    ELFEDIT_CMDOA_F_INHERIT, 0, 0 },
		{ NULL }
	};

	/* For commands that only accept -and, -cmp, -o, -or */
	static elfedit_cmd_optarg_t opt_ostyle_bitop[] = {
		{ ELFEDIT_STDOA_OPT_AND, 0,
		    ELFEDIT_CMDOA_F_INHERIT, DYN_OPT_F_AND, DYN_OPT_F_OR },
		{ ELFEDIT_STDOA_OPT_CMP, 0,
		    ELFEDIT_CMDOA_F_INHERIT, DYN_OPT_F_CMP, 0 },
		{ ELFEDIT_STDOA_OPT_O, 0,
		    ELFEDIT_CMDOA_F_INHERIT, 0, 0 },
		{ ELFEDIT_STDOA_OPT_OR, 0,
		    ELFEDIT_CMDOA_F_INHERIT, DYN_OPT_F_OR, DYN_OPT_F_AND },
		{ NULL }
	};

	/* For commands that only accept -dynndx */
	static elfedit_cmd_optarg_t opt_minus_dynndx[] = {
		{ MSG_ORIG(MSG_STR_MINUS_DYNNDX),
		    /* MSG_INTL(MSG_OPTDESC_DYNNDX_ELT) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_DYNNDX_ELT), 0,
		    DYN_OPT_F_DYNNDX_ELT, 0 },
		{ NULL }
	};

	/* dyn:dump */
	static const char *name_dump[] = {
	    MSG_ORIG(MSG_CMD_DUMP),
	    MSG_ORIG(MSG_STR_EMPTY),	/* "" makes this the default command */
	    NULL
	};
	static elfedit_cmd_optarg_t arg_dump[] = {
		{ MSG_ORIG(MSG_STR_ELT),
		    /* MSG_INTL(MSG_ARGDESC_ELT) */
		    ELFEDIT_I18NHDL(MSG_ARGDESC_ELT),
		    ELFEDIT_CMDOA_F_OPT },
		{ NULL }
	};


	/* dyn:tag */
	static const char *name_tag[] = { MSG_ORIG(MSG_CMD_TAG), NULL };
	static elfedit_cmd_optarg_t opt_tag[] = {
		{ MSG_ORIG(MSG_STR_MINUS_DYNNDX),
		    /* MSG_INTL(MSG_OPTDESC_DYNNDX_ELT) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_DYNNDX_ELT), 0,
		    DYN_OPT_F_DYNNDX_ELT, 0 },
		{ ELFEDIT_STDOA_OPT_O, 0,
		    ELFEDIT_CMDOA_F_INHERIT, 0, 0 },
		{ NULL }
	};
	static elfedit_cmd_optarg_t arg_tag[] = {
		{ MSG_ORIG(MSG_STR_ELT),
		    /* MSG_INTL(MSG_A1_TAG_ELT) */
		    ELFEDIT_I18NHDL(MSG_A1_TAG_ELT),
		    ELFEDIT_CMDOA_F_OPT },
		{ MSG_ORIG(MSG_STR_VALUE),
		    /* MSG_INTL(MSG_A2_TAG_VALUE) */
		    ELFEDIT_I18NHDL(MSG_A2_TAG_VALUE),
		    ELFEDIT_CMDOA_F_OPT },
		{ NULL }
	};


	/* dyn:value */
	static const char *name_value[] = { MSG_ORIG(MSG_CMD_VALUE), NULL };
	static elfedit_cmd_optarg_t opt_value[] = {
		{ MSG_ORIG(MSG_STR_MINUS_ADD),
		    /* MSG_INTL(MSG_OPTDESC_ADD) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_ADD), 0,
		    DYN_OPT_F_ADD, DYN_OPT_F_DYNNDX_ELT },
		{ MSG_ORIG(MSG_STR_MINUS_DYNNDX),
		    /* MSG_INTL(MSG_OPTDESC_DYNNDX_ELT) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_DYNNDX_ELT), 0,
		    DYN_OPT_F_DYNNDX_ELT, DYN_OPT_F_ADD },
		{ ELFEDIT_STDOA_OPT_O, 0,
		    ELFEDIT_CMDOA_F_INHERIT, 0, 0 },
		{ MSG_ORIG(MSG_STR_MINUS_S),
		    /* MSG_INTL(MSG_OPTDESC_S) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_S), 0,
		    DYN_OPT_F_STRVAL, 0 },
		{ NULL }
	};
	static elfedit_cmd_optarg_t arg_value[] = {
		{ MSG_ORIG(MSG_STR_ELT),
		    /* MSG_INTL(MSG_ARGDESC_ELT) */
		    ELFEDIT_I18NHDL(MSG_ARGDESC_ELT),
		    ELFEDIT_CMDOA_F_OPT },
		{ MSG_ORIG(MSG_STR_VALUE),
		    /* MSG_INTL(MSG_A2_VALUE_VALUE) */
		    ELFEDIT_I18NHDL(MSG_A2_VALUE_VALUE),
		    ELFEDIT_CMDOA_F_OPT },
		{ NULL }
	};

	/* dyn:delete */
	static const char *name_delete[] = { MSG_ORIG(MSG_CMD_DELETE), NULL };
	static elfedit_cmd_optarg_t arg_delete[] = {
		{ MSG_ORIG(MSG_STR_ELT),
		    /* MSG_INTL(MSG_ARGDESC_ELT) */
		    ELFEDIT_I18NHDL(MSG_ARGDESC_ELT),
		    0 },
		{ MSG_ORIG(MSG_STR_COUNT),
		    /* MSG_INTL(MSG_A2_DELETE_COUNT) */
		    ELFEDIT_I18NHDL(MSG_A2_DELETE_COUNT),
		    ELFEDIT_CMDOA_F_OPT },
		{ NULL }
	};

	/* dyn:move */
	static const char *name_move[] = { MSG_ORIG(MSG_CMD_MOVE), NULL };
	static elfedit_cmd_optarg_t arg_move[] = {
		{ MSG_ORIG(MSG_STR_ELT),
		    /* MSG_INTL(MSG_ARGDESC_ELT) */
		    ELFEDIT_I18NHDL(MSG_ARGDESC_ELT),
		    0 },
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

	/* dyn:runpath / dyn:rpath */
	static const char *name_runpath[] = { MSG_ORIG(MSG_CMD_RUNPATH),
	    MSG_ORIG(MSG_CMD_RUNPATH_A1), NULL };
	static elfedit_cmd_optarg_t arg_runpath[] = {
		{ MSG_ORIG(MSG_STR_NEWPATH),
		    /* MSG_INTL(MSG_A1_RUNPATH_NEWPATH) */
		    ELFEDIT_I18NHDL(MSG_A1_RUNPATH_NEWPATH),
		    ELFEDIT_CMDOA_F_OPT },
		{ NULL }
	};

	/* dyn:posflag1 */
	static const char *name_posflag1[] = { MSG_ORIG(MSG_CMD_POSFLAG1),
	    NULL };
	static elfedit_cmd_optarg_t opt_posflag1[] = {
		{ ELFEDIT_STDOA_OPT_AND, 0,
		    ELFEDIT_CMDOA_F_INHERIT, DYN_OPT_F_AND, DYN_OPT_F_OR },
		{ ELFEDIT_STDOA_OPT_CMP, 0,
		    ELFEDIT_CMDOA_F_INHERIT, DYN_OPT_F_CMP, 0 },
		{ MSG_ORIG(MSG_STR_MINUS_DYNNDX),
		    /* MSG_INTL(MSG_OPTDESC_DYNNDX_VAL) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_DYNNDX_VAL),
		    ELFEDIT_CMDOA_F_VALUE,
		    DYN_OPT_F_DYNNDX_VAL, DYN_OPT_F_NEEDED },
		{ MSG_ORIG(MSG_STR_INDEX), 0, 0, 0 },
		{ MSG_ORIG(MSG_STR_MINUS_NEEDED),
		    /* MSG_INTL(MSG_OPTDESC_NEEDED) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_NEEDED),
		    ELFEDIT_CMDOA_F_VALUE,
		    DYN_OPT_F_NEEDED, DYN_OPT_F_DYNNDX_VAL },
		{ MSG_ORIG(MSG_STR_PREFIX), 0, 0, 0 },
		{ ELFEDIT_STDOA_OPT_O, 0,
		    ELFEDIT_CMDOA_F_INHERIT, 0, 0 },
		{ ELFEDIT_STDOA_OPT_OR, 0,
		    ELFEDIT_CMDOA_F_INHERIT, DYN_OPT_F_OR, DYN_OPT_F_AND },
		{ NULL }
	};
	static elfedit_cmd_optarg_t arg_posflag1[] = {
		{ MSG_ORIG(MSG_STR_VALUE),
		    /* MSG_INTL(MSG_A1_POSFLAG1_VALUE) */
		    ELFEDIT_I18NHDL(MSG_A1_POSFLAG1_VALUE),
		    ELFEDIT_CMDOA_F_OPT | ELFEDIT_CMDOA_F_MULT },
		{ NULL }
	};

	/* dyn:flags */
	static const char *name_flags[] = { MSG_ORIG(MSG_CMD_FLAGS), NULL };
	static elfedit_cmd_optarg_t arg_flags[] = {
		{ MSG_ORIG(MSG_STR_VALUE),
		    /* MSG_INTL(MSG_A1_FLAGS_VALUE) */
		    ELFEDIT_I18NHDL(MSG_A1_FLAGS_VALUE),
		    ELFEDIT_CMDOA_F_OPT | ELFEDIT_CMDOA_F_MULT },
		{ NULL }
	};

	/* dyn:flags1 */
	static const char *name_flags1[] = { MSG_ORIG(MSG_CMD_FLAGS1), NULL };
	static elfedit_cmd_optarg_t arg_flags1[] = {
		{ MSG_ORIG(MSG_STR_VALUE),
		    /* MSG_INTL(MSG_A1_FLAGS1_VALUE) */
		    ELFEDIT_I18NHDL(MSG_A1_FLAGS1_VALUE),
		    ELFEDIT_CMDOA_F_OPT | ELFEDIT_CMDOA_F_MULT },
		{ NULL }
	};

	/* dyn:feature1 */
	static const char *name_feature1[] = { MSG_ORIG(MSG_CMD_FEATURE1),
	    NULL };
	static elfedit_cmd_optarg_t arg_feature1[] = {
		{ MSG_ORIG(MSG_STR_VALUE),
		    /* MSG_INTL(MSG_A1_FEATURE1_VALUE) */
		    ELFEDIT_I18NHDL(MSG_A1_FEATURE1_VALUE),
		    ELFEDIT_CMDOA_F_OPT | ELFEDIT_CMDOA_F_MULT },
		{ NULL }
	};

	/* dyn:checksum */
	static const char *name_checksum[] = { MSG_ORIG(MSG_CMD_CHECKSUM),
	    NULL };

	/* dyn:sunw_ldmach */
	static const char *name_sunw_ldmach[] = { MSG_ORIG(MSG_CMD_SUNW_LDMACH),
	    NULL };
	static elfedit_cmd_optarg_t arg_sunw_ldmach[] = {
		{ MSG_ORIG(MSG_STR_VALUE),
		    /* MSG_INTL(MSG_A1_SUNW_LDMACH_VALUE) */
		    ELFEDIT_I18NHDL(MSG_A1_SUNW_LDMACH_VALUE),
		    ELFEDIT_CMDOA_F_OPT },
		{ NULL }
	};



	static elfedit_cmd_t cmds[] = {
		/* dyn:dump */
		{ cmd_dump, cpl_eltarg, name_dump,
		    /* MSG_INTL(MSG_DESC_DUMP) */
		    ELFEDIT_I18NHDL(MSG_DESC_DUMP),
		    /* MSG_INTL(MSG_HELP_DUMP) */
		    ELFEDIT_I18NHDL(MSG_HELP_DUMP),
		    opt_minus_dynndx, arg_dump },

		/* dyn:tag */
		{ cmd_tag, cpl_tag, name_tag,
		    /* MSG_INTL(MSG_DESC_TAG) */
		    ELFEDIT_I18NHDL(MSG_DESC_TAG),
		    /* MSG_INTL(MSG_HELP_TAG) */
		    ELFEDIT_I18NHDL(MSG_HELP_TAG),
		    opt_tag, arg_tag },

		/* dyn:value */
		{ cmd_value, cpl_eltarg, name_value,
		    /* MSG_INTL(MSG_DESC_VALUE) */
		    ELFEDIT_I18NHDL(MSG_DESC_VALUE),
		    /* MSG_INTL(MSG_HELP_VALUE) */
		    ELFEDIT_I18NHDL(MSG_HELP_VALUE),
		    opt_value, arg_value },

		/* dyn:delete */
		{ cmd_delete, cpl_eltarg, name_delete,
		    /* MSG_INTL(MSG_DESC_DELETE) */
		    ELFEDIT_I18NHDL(MSG_DESC_DELETE),
		    /* MSG_INTL(MSG_HELP_DELETE) */
		    ELFEDIT_I18NHDL(MSG_HELP_DELETE),
		    opt_minus_dynndx, arg_delete },

		/* dyn:move */
		{ cmd_move, cpl_eltarg, name_move,
		    /* MSG_INTL(MSG_DESC_MOVE) */
		    ELFEDIT_I18NHDL(MSG_DESC_MOVE),
		    /* MSG_INTL(MSG_HELP_MOVE) */
		    ELFEDIT_I18NHDL(MSG_HELP_MOVE),
		    opt_minus_dynndx, arg_move },

		/* dyn:runpath */
		{ cmd_runpath, NULL, name_runpath,
		    /* MSG_INTL(MSG_DESC_RUNPATH) */
		    ELFEDIT_I18NHDL(MSG_DESC_RUNPATH),
		    /* MSG_INTL(MSG_HELP_RUNPATH) */
		    ELFEDIT_I18NHDL(MSG_HELP_RUNPATH),
		    opt_ostyle, arg_runpath },

		/* dyn:posflag1 */
		{ cmd_posflag1, cpl_posflag1, name_posflag1,
		    /* MSG_INTL(MSG_DESC_POSFLAG1) */
		    ELFEDIT_I18NHDL(MSG_DESC_POSFLAG1),
		    /* MSG_INTL(MSG_HELP_POSFLAG1) */
		    ELFEDIT_I18NHDL(MSG_HELP_POSFLAG1),
		    opt_posflag1, arg_posflag1 },

		/* dyn:flags */
		{ cmd_flags, cpl_flags, name_flags,
		    /* MSG_INTL(MSG_DESC_FLAGS) */
		    ELFEDIT_I18NHDL(MSG_DESC_FLAGS),
		    /* MSG_INTL(MSG_HELP_FLAGS) */
		    ELFEDIT_I18NHDL(MSG_HELP_FLAGS),
		    opt_ostyle_bitop, arg_flags },

		/* dyn:flags1 */
		{ cmd_flags1, cpl_flags1, name_flags1,
		    /* MSG_INTL(MSG_DESC_FLAGS1) */
		    ELFEDIT_I18NHDL(MSG_DESC_FLAGS1),
		    /* MSG_INTL(MSG_HELP_FLAGS1) */
		    ELFEDIT_I18NHDL(MSG_HELP_FLAGS1),
		    opt_ostyle_bitop, arg_flags1 },

		/* dyn:feature1 */
		{ cmd_feature1, cpl_feature1, name_feature1,
		    /* MSG_INTL(MSG_DESC_FEATURE1) */
		    ELFEDIT_I18NHDL(MSG_DESC_FEATURE1),
		    /* MSG_INTL(MSG_HELP_FEATURE1) */
		    ELFEDIT_I18NHDL(MSG_HELP_FEATURE1),
		    opt_ostyle_bitop, arg_feature1 },

		/* dyn:checksum */
		{ cmd_checksum, NULL, name_checksum,
		    /* MSG_INTL(MSG_DESC_CHECKSUM) */
		    ELFEDIT_I18NHDL(MSG_DESC_CHECKSUM),
		    /* MSG_INTL(MSG_HELP_CHECKSUM) */
		    ELFEDIT_I18NHDL(MSG_HELP_CHECKSUM),
		    NULL, NULL },

		/* dyn:sunw_ldmach */
		{ cmd_sunw_ldmach, cpl_sunw_ldmach, name_sunw_ldmach,
		    /* MSG_INTL(MSG_DESC_SUNW_LDMACH) */
		    ELFEDIT_I18NHDL(MSG_DESC_SUNW_LDMACH),
		    /* MSG_INTL(MSG_HELP_SUNW_LDMACH) */
		    ELFEDIT_I18NHDL(MSG_HELP_SUNW_LDMACH),
		    opt_ostyle, arg_sunw_ldmach },

		{ NULL }
	};

	static elfedit_module_t module = {
	    ELFEDIT_VER_CURRENT, MSG_ORIG(MSG_MOD_NAME),
	    /* MSG_INTL(MSG_MOD_DESC) */
	    ELFEDIT_I18NHDL(MSG_MOD_DESC), cmds, mod_i18nhdl_to_str };

	return (&module);
}
