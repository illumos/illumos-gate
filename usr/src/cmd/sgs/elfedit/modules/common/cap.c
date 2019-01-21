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
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

#include	<ctype.h>
#include	<elfedit.h>
#include	<sys/elf_SPARC.h>
#include	<strings.h>
#include	<debug.h>
#include	<conv.h>
#include	<cap_msg.h>


/*
 * Capabilities section
 */




/*
 * This module uses shared code for several of the commands.
 * It is sometimes necessary to know which specific command
 * is active.
 */
typedef enum {
	/* Dump command, used as module default to display dynamic section */
	CAP_CMD_T_DUMP =	0,	/* cap:dump */

	/* Commands that do not correspond directly to a specific DT tag */
	CAP_CMD_T_TAG =		1,	/* cap:tag */
	CAP_CMD_T_VALUE =	2,	/* cap:value */
	CAP_CMD_T_DELETE =	3,	/* cap:delete */
	CAP_CMD_T_MOVE =	4,	/* cap:shift */

	/* Commands that embody tag specific knowledge */
	CAP_CMD_T_HW1 =		5,	/* cap:hw1 */
	CAP_CMD_T_SF1 =		6,	/* cap:sf1 */
	CAP_CMD_T_HW2 =		7,	/* cap:hw2 */
} CAP_CMD_T;



#ifndef _ELF64
/*
 * We supply this function for the msg module
 */
const char *
_cap_msg(Msg mid)
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
 * The cap_opt_t enum specifies a bit value for every optional
 * argument allowed by a command in this module.
 */
typedef enum {
	CAP_OPT_F_AND =		1,	/* -and: AND (&) values to dest */
	CAP_OPT_F_CMP =		2,	/* -cmp: Complement (~) values */
	CAP_OPT_F_CAPID =	4,	/* -capid id: elt limited to given */
					/*	capabilities group */
	CAP_OPT_F_CAPNDX =	8,	/* -capndx: elt is tag index, */
					/*	not name */
	CAP_OPT_F_OR =		16,	/* -or: OR (|) values to dest */
	CAP_OPT_F_STRVAL =	32	/* -s: value is string, not integer */
} cap_opt_t;


/*
 * A variable of type ARGSTATE is used by each command to maintain
 * information about the arguments and related things. It is
 * initialized by process_args(), and used by the other routines.
 */
typedef struct {
	elfedit_obj_state_t	*obj_state;
	struct {
		elfedit_section_t *sec;	/* Capabilities section reference */
		Cap	*data;		/* Start of capabilities section data */
		Word	num;		/* # Capabilities elts */
		Boolean	grp_set;	/* TRUE when cap group is set */
		Word	grp_start_ndx;	/* capabilities group starting index */
		Word	grp_end_ndx;	/* capabilities group ending index */
	} cap;
	struct {			/* String table */
		elfedit_section_t *sec;
	} str;
	cap_opt_t	optmask;	/* Mask of options used */
	int		argc;		/* # of plain arguments */
	const char	**argv;		/* Plain arguments */
} ARGSTATE;



/*
 * Lookup the string table associated with the capabilities
 * section.
 *
 * entry:
 *	argstate - Argument state block
 *	required - If TRUE, failure to obtain a string table should be
 *		considered to be an error.
 *
 * exit:
 *	If a string table is found, argstate->str is updated to reference it.
 *	If no string table is found, and required is TRUE, an error is issued
 *	and this routine does not return to the caller. Otherwise, this
 *	routine returns quietly without modifying argstate->str.
 */
static void
argstate_add_str(ARGSTATE *argstate, Boolean required)
{
	/* String table already loaded? */
	if (argstate->str.sec != NULL)
		return;

	/*
	 * We can't proceed if the capabilities section does not have
	 * an associated string table.
	 */
	if (argstate->cap.sec->sec_shdr->sh_info == 0) {
		/* Error if the operation requires a string table */
		if (required)
			elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_NOSTRTAB),
			    EC_WORD(argstate->cap.sec->sec_shndx),
			    argstate->cap.sec->sec_name);
		return;
	}

	argstate->str.sec = elfedit_sec_getstr(argstate->obj_state,
	    argstate->cap.sec->sec_shdr->sh_info, 0);
}

/*
 * Given an index into the capabilities array, locate the index of the
 * initial element in its capabilities group, and the number of elements
 * in the group.
 */
static void
cap_group_extents(ARGSTATE *argstate, Word ndx, Word *ret_start_ndx,
    Word *ret_end_ndx)
{
	*ret_end_ndx = ndx;

	/*
	 * The group starts with a non-NULL tag that is either the
	 * first tag in the array, or is preceded by a NULL tag.
	 */
	while ((ndx > 0) && (argstate->cap.data[ndx].c_tag == CA_SUNW_NULL))
		ndx--;
	while ((ndx > 0) && (argstate->cap.data[ndx - 1].c_tag != CA_SUNW_NULL))
		ndx--;
	*ret_start_ndx = ndx;


	/*
	 * The group is terminated by a series of 1 or more NULL tags.
	 */
	ndx = *ret_end_ndx;
	while (((ndx + 1) < argstate->cap.num) &&
	    (argstate->cap.data[ndx].c_tag != CA_SUNW_NULL))
		ndx++;
	while (((ndx + 1) < argstate->cap.num) &&
	    (argstate->cap.data[ndx + 1].c_tag == CA_SUNW_NULL))
		ndx++;
	*ret_end_ndx = ndx;
}

/*
 * If a CA_SUNW_ID element exists within the current capabilities group
 * in the given argument state, return the string pointer to the name.
 * Otherwise return a pointer to a descriptive "noname" string.
 */
static const char *
cap_group_id(ARGSTATE *argstate)
{
	Word		ndx = argstate->cap.grp_start_ndx;
	Cap		*cap = argstate->cap.data + ndx;

	for (; ndx <= argstate->cap.grp_end_ndx; ndx++, cap++) {
		if (cap->c_tag == CA_SUNW_ID) {
			argstate_add_str(argstate, TRUE);
			return (elfedit_offset_to_str(argstate->str.sec,
			    cap->c_un.c_val, ELFEDIT_MSG_ERR, 0));
		}

		if (cap->c_tag == CA_SUNW_NULL)
			break;
	}

	return ((argstate->cap.grp_start_ndx == 0) ?
	    MSG_INTL(MSG_STR_OBJECT) : MSG_INTL(MSG_STR_NONAME));
}


/*
 * Given an index into the capabilities array, set the argstate cap.grp_*
 * fields to reflect the capabilities group containing the index.
 *
 * The group concept is used to limit operations to a related group
 * of capabilities, and prevent insert/delete/move operations from
 * spilling across groups.
 */
static void
argstate_cap_group(ARGSTATE *argstate, Word ndx)
{
	if (argstate->cap.grp_set == TRUE)
		return;

	cap_group_extents(argstate, ndx, &argstate->cap.grp_start_ndx,
	    &argstate->cap.grp_end_ndx);

	argstate->cap.grp_set = TRUE;
	elfedit_msg(ELFEDIT_MSG_DEBUG, MSG_INTL(MSG_DEBUG_CAPGRP),
	    EC_WORD(argstate->cap.sec->sec_shndx), argstate->cap.sec->sec_name,
	    EC_WORD(argstate->cap.grp_start_ndx),
	    EC_WORD(argstate->cap.grp_end_ndx), cap_group_id(argstate));
}

/*
 * Given an index into the capabilities array, issue a group title for
 * the capabilities group that contains it.
 */
static void
group_title(ARGSTATE *argstate, Word ndx)
{
	ARGSTATE	loc_argstate;

	loc_argstate = *argstate;
	cap_group_extents(argstate, ndx, &loc_argstate.cap.grp_start_ndx,
	    &loc_argstate.cap.grp_end_ndx);
	elfedit_printf(MSG_INTL(MSG_FMT_CAPGRP),
	    EC_WORD(loc_argstate.cap.grp_start_ndx),
	    EC_WORD(loc_argstate.cap.grp_end_ndx), cap_group_id(&loc_argstate));
}

/*
 * Standard argument processing for cap module
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
	const char		*capid = NULL;

	bzero(argstate, sizeof (*argstate));
	argstate->obj_state = obj_state;

	elfedit_getopt_init(&getopt_state, &argc, &argv);

	/* Add each new option to the options mask */
	while ((getopt_ret = elfedit_getopt(&getopt_state)) != NULL) {
		argstate->optmask |= getopt_ret->gor_idmask;

		if (getopt_ret->gor_idmask == CAP_OPT_F_CAPID)
			capid = getopt_ret->gor_value;
	}

	/* If there may be an arbitrary amount of output, use a pager */
	if (argc == 0)
		elfedit_pager_init();

	/* Return the updated values of argc/argv */
	argstate->argc = argc;
	argstate->argv = argv;

	/* Locate the capabilities section */
	argstate->cap.sec = elfedit_sec_getcap(obj_state, &argstate->cap.data,
	    &argstate->cap.num);

	/*
	 * If -capid was specified, locate the specified capabilities group,
	 * and narrow the section data to use only that group. Otherwise,
	 * use the whole array.
	 */
	if (capid != NULL) {
		Word	i;
		Cap	*cap = argstate->cap.data;

		/*
		 * -capid requires the capability section to have an
		 * associated string table.
		 */
		argstate_add_str(argstate, TRUE);

		for (i = 0; i < argstate->cap.num; i++, cap++)
			if ((cap->c_tag == CA_SUNW_ID) &&
			    (strcmp(capid, elfedit_offset_to_str(
			    argstate->str.sec, cap->c_un.c_val,
			    ELFEDIT_MSG_ERR, 0)) == 0))
				break;

		if (i == argstate->cap.num)
			elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_BADCAPID),
			    EC_WORD(argstate->cap.sec->sec_shndx),
			    argstate->cap.sec->sec_name, capid);
		argstate_cap_group(argstate, i);
	} else {
		argstate->cap.grp_start_ndx = 0;
		argstate->cap.grp_end_ndx = argstate->cap.num - 1;
	}
}



/*
 * Print ELF capabilities values, taking the calling command, and output style
 * into account.
 *
 * entry:
 *	cmd - CAP_CMD_T_* value giving identify of caller
 *	autoprint - If True, output is only produced if the elfedit
 *		autoprint flag is set. If False, output is always produced.
 *	argstate - Argument state block
 *	print_type - Specifies which capabilities elements to display.
 *	ndx = If print_type is PRINT_CAP_T_NDX, displays the index specified.
 *		Otherwise ignored.
 */
typedef enum {
	PRINT_CAP_T_ALL =	0,	/* Show all indexes */
	PRINT_CAP_T_NDX =	1,	/* Show capabilities[arg] only */
	PRINT_CAP_T_TAG =	2	/* Show all elts with tag type */
					/*	given by arg */
} PRINT_CAP_T;

static void
print_cap(CAP_CMD_T cmd, int autoprint, ARGSTATE *argstate,
    PRINT_CAP_T print_type, Word arg)
{
	elfedit_outstyle_t	outstyle;
	Word		cnt, ndx, printed = 0;
	Cap		*cap;
	Boolean		header_done = FALSE, null_seen = FALSE;
	const char	*str;
	size_t		str_size;

	if (autoprint && ((elfedit_flags() & ELFEDIT_F_AUTOPRINT) == 0))
		return;

	/*
	 * Pick an output style. cap:dump is required to use the default
	 * style. The other commands use the current output style.
	 */
	outstyle = (cmd == CAP_CMD_T_DUMP) ?
	    ELFEDIT_OUTSTYLE_DEFAULT : elfedit_outstyle();

	/* How many elements do we examine? */
	if (print_type == PRINT_CAP_T_NDX) {
		if (arg >= argstate->cap.num)
			return;		/* Out of range */
		ndx = arg;
		cnt = 1;
	} else {
		ndx = argstate->cap.grp_start_ndx;
		cnt = argstate->cap.grp_end_ndx - ndx + 1;
	}

	/* Load string table if there is one */
	argstate_add_str(argstate, FALSE);
	if (argstate->str.sec == NULL) {
		str = NULL;
		str_size = 0;
	} else {
		str = (const char *)argstate->str.sec->sec_data->d_buf;
		str_size = argstate->str.sec->sec_data->d_size;
	}

	cap = &argstate->cap.data[ndx];
	for (; cnt--; cap++, ndx++) {
		/*
		 * If we are only displaying certain tag types and
		 * this isn't one of those, move on to next element.
		 */
		if ((print_type == PRINT_CAP_T_TAG) && (cap->c_tag != arg)) {
			if (cap->c_tag == CA_SUNW_NULL)
				null_seen = TRUE;
			continue;
		}

		/*
		 * If capability type requires a string table, and we don't
		 * have one, force an error.
		 */
		switch (cap->c_tag) {
		case CA_SUNW_PLAT:
		case CA_SUNW_MACH:
		case CA_SUNW_ID:
			if (argstate->str.sec == NULL)
				argstate_add_str(argstate, TRUE);
			break;
		}

		if (outstyle == ELFEDIT_OUTSTYLE_DEFAULT) {
			if (null_seen && (cap->c_tag != CA_SUNW_NULL)) {
				null_seen = FALSE;
				if (header_done) {
					elfedit_printf(MSG_ORIG(MSG_FMT_STRNL),
					    MSG_ORIG(MSG_STR_EMPTY));
					header_done = FALSE;
				}
			}

			if (header_done == FALSE) {
				header_done = TRUE;
				group_title(argstate, ndx);
				Elf_cap_title(0);
			}
			Elf_cap_entry(NULL, cap, ndx, str, str_size,
			    argstate->obj_state->os_ehdr->e_machine);
		} else {
			/*
			 * If CAP_CMD_T_TAG, and not in default output
			 * style, display the tag rather than the value.
			 */
			if (cmd == CAP_CMD_T_TAG) {
				if (outstyle == ELFEDIT_OUTSTYLE_SIMPLE) {
					Conv_inv_buf_t	inv_buf;

					elfedit_printf(MSG_ORIG(MSG_FMT_STRNL),
					    conv_cap_tag(cap->c_tag, 0,
					    &inv_buf));
				} else {
					elfedit_printf(
					    MSG_ORIG(MSG_FMT_WORDVALNL),
					    EC_WORD(cap->c_tag));
				}
				printed = 1;
				continue;
			}

			/* Displaying the value in simple or numeric mode */
			if (outstyle == ELFEDIT_OUTSTYLE_SIMPLE) {
				Conv_cap_val_buf_t	cap_val_buf;

				if (print_type == PRINT_CAP_T_TAG) {
					elfedit_printf(MSG_ORIG(MSG_FMT_STRNL),
					    conv_cap_val_hw1(cap->c_un.c_val,
					    argstate->obj_state->os_ehdr->
					    e_machine, CONV_FMT_NOBKT,
					    &cap_val_buf.cap_val_hw1_buf));
					printed = 1;
					continue;
				}

				switch (cap->c_tag) {
				case CA_SUNW_HW_1:
					elfedit_printf(MSG_ORIG(MSG_FMT_STRNL),
					    conv_cap_val_hw1(cap->c_un.c_val,
					    argstate->obj_state->os_ehdr->
					    e_machine, CONV_FMT_NOBKT,
					    &cap_val_buf.cap_val_hw1_buf));
					printed = 1;
					continue;
				case CA_SUNW_SF_1:
					elfedit_printf(MSG_ORIG(MSG_FMT_STRNL),
					    conv_cap_val_sf1(cap->c_un.c_val,
					    argstate->obj_state->os_ehdr->
					    e_machine, CONV_FMT_NOBKT,
					    &cap_val_buf.cap_val_sf1_buf));
					printed = 1;
					continue;
				case CA_SUNW_HW_2:
					elfedit_printf(MSG_ORIG(MSG_FMT_STRNL),
					    conv_cap_val_hw2(cap->c_un.c_val,
					    argstate->obj_state->os_ehdr->
					    e_machine, CONV_FMT_NOBKT,
					    &cap_val_buf.cap_val_hw2_buf));
					printed = 1;
					continue;
				case CA_SUNW_PLAT:
				case CA_SUNW_MACH:
				case CA_SUNW_ID:
					elfedit_printf(MSG_ORIG(MSG_FMT_STRNL),
					    elfedit_offset_to_str(
					    argstate->str.sec, cap->c_un.c_val,
					    ELFEDIT_MSG_ERR, 0));
					printed = 1;
					continue;
				}
			}
			elfedit_printf(MSG_ORIG(MSG_FMT_HEXXWORDNL),
			    EC_XWORD(cap->c_un.c_val));
		}
		printed = 1;
		if (cap->c_tag == CA_SUNW_NULL)
			null_seen = TRUE;
	}

	/*
	 * If nothing was output under the print types that are
	 * based on tag type, issue an error saying it doesn't exist.
	 */
	if (!printed && (print_type == PRINT_CAP_T_TAG)) {
		Conv_inv_buf_t	inv_buf;

		elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_NOCAELT),
		    EC_WORD(argstate->cap.sec->sec_shndx),
		    argstate->cap.sec->sec_name, argstate->cap.grp_start_ndx,
		    argstate->cap.grp_end_ndx, cap_group_id(argstate),
		    conv_cap_tag(arg, 0, &inv_buf));
	}
}


/*
 * Process the elt argument: This will be a tag type if -capndx is
 * not present and this is a print request. It will be an index otherwise.
 *
 * entry:
 *	argstate - Argument state block
 *	arg - Argument string to be converted into an index
 *	argname - String giving the name by which the argument is
 *		referred in the online help for the command.
 *	print_request - True if the command is to print the current
 *		value(s) and return without changing anything.
 *	print_type - Address of variable containing PRINT_CAP_T_
 *		code specifying how the elements will be displayed.
 *
 * exit:
 *	If print_request is False: arg is converted into an integer value.
 *	If -capndx was used, we convert it into an integer. If it was not
 *	used, then arg is a tag name --- we find the first capabilities entry
 *	that matches. If no entry matches, and there is an extra CA_NULL,
 *	it is added. Otherwise an error is issued. *print_type is set
 *	to PRINT_CAP_T_NDX.
 *
 *	If print_request is True: If -capndx was used, arg is converted into
 *	an integer value, *print_type is set to PRINT_CAP_T_NDX, and
 *	the value is returned. If -capndx was not used, *print_type is set to
 *	PRINT_CAP_T_TAG, and the tag value is returned.
 */
static Word
arg_to_index(ARGSTATE *argstate, const char *arg, const char *argname,
    int print_request, PRINT_CAP_T *print_type)
{
	Word		ndx, ca_value;


	/* Assume we are returning an index, alter as needed below */
	*print_type = PRINT_CAP_T_NDX;

	/*
	 * If -capndx was used, this is a simple numeric index.
	 * Determine its capability group because some operations
	 * (move, delete) are limited to operate within it.
	 */
	if ((argstate->optmask & CAP_OPT_F_CAPNDX) != 0) {
		ndx = (Word) elfedit_atoui_range(arg, argname, 0,
		    argstate->cap.num - 1, NULL);
		argstate_cap_group(argstate, ndx);
		return (ndx);
	}

	/* The argument is a CA_ tag type, not a numeric index */
	ca_value = (Word) elfedit_atoconst(arg, ELFEDIT_CONST_CA);

	/*
	 * If this is a printing request, then we let print_cap() show
	 * all the items with this tag type.
	 */
	if (print_request) {
		*print_type = PRINT_CAP_T_TAG;
		return (ca_value);
	}

	/*
	 * If we haven't determined a capability group yet, either via
	 * -capid, or -capndx, then make it the initial group, which
	 * represent the object capabilities.
	 */
	if (!argstate->cap.grp_set)
		argstate_cap_group(argstate, 0);

	/*
	 * Locate the first entry with the given tag type within the
	 * capabilities group.
	 */
	for (ndx = argstate->cap.grp_start_ndx;
	    ndx <= argstate->cap.grp_end_ndx; ndx++) {
		if (argstate->cap.data[ndx].c_tag == ca_value) {
			elfedit_msg(ELFEDIT_MSG_DEBUG,
			    MSG_INTL(MSG_DEBUG_CA2NDX),
			    EC_WORD(argstate->cap.sec->sec_shndx),
			    argstate->cap.sec->sec_name, EC_WORD(ndx), arg);
			return (ndx);
		}

		/*
		 * If we hit a NULL, then only more NULLs can follow it and
		 * there's no need to look further. If there is more than
		 * one NULL, we can grab the first one and turn it into
		 * an element of the desired type.
		 */
		if (argstate->cap.data[ndx].c_tag == CA_SUNW_NULL) {
			if (ndx < argstate->cap.grp_end_ndx) {
				Conv_inv_buf_t	inv_buf;

				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_CONVNULL),
				    EC_WORD(argstate->cap.sec->sec_shndx),
				    argstate->cap.sec->sec_name, EC_WORD(ndx),
				    conv_cap_tag(ca_value, 0, &inv_buf));
				argstate->cap.data[ndx].c_tag = ca_value;
				bzero(&argstate->cap.data[ndx].c_un,
				    sizeof (argstate->cap.data[ndx].c_un));
				return (ndx);
			}
			break;
		}
	}

	/* No room to create one, so we're out of options and must fail */
	elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_NOCAELT),
	    EC_WORD(argstate->cap.sec->sec_shndx),
	    argstate->cap.sec->sec_name, argstate->cap.grp_start_ndx,
	    argstate->cap.grp_end_ndx, cap_group_id(argstate), arg);

	/*NOTREACHED*/
	return (0);		/* For lint */
}


/*
 * Argument processing for the bitmask commands. Convert the arguments
 * to integer form, apply -and/-cmp/-or, and return the resulting value.
 *
 * entry:
 *	argstate - Argument state block
 *	orig - Value of original bitmask
 *	const_sym - NULL, or array of name->integer mappings for
 *		applicable symbolic constant names.
 */
static Word
flag_bitop(ARGSTATE *argstate, Word orig, const elfedit_atoui_sym_t *const_sym)
{
	Word flags = 0;
	int i;

	/* Collect the arguments */
	for (i = 0; i < argstate->argc; i++)
		flags |= (Word) elfedit_atoui(argstate->argv[i], const_sym);

	/* Complement the value? */
	if (argstate->optmask & CAP_OPT_F_CMP)
		flags = ~flags;

	/* Perform any requested bit operations */
	if (argstate->optmask & CAP_OPT_F_AND)
		flags &= orig;
	else if (argstate->optmask & CAP_OPT_F_OR)
		flags |= orig;

	return (flags);
}

/*
 * Common processing for capabilities value setting.
 *
 * entry:
 *	argstate - Argument state block
 *	cap - capabilities data pointer
 *	ndx - capabilities data index
 *	cap_ndx - capabilities section index
 *	cap_name - capabilities section name
 *	cap_tag - capabilities tag
 *	const_type - data conversion type
 */
static elfedit_cmdret_t
cap_set(ARGSTATE *argstate, Cap *cap, Word ndx, Word cap_ndx,
    const char *cap_name, Xword cap_tag, elfedit_const_t const_type)
{
	Conv_cap_val_buf_t	buf1, buf2;
	Half			mach = argstate->obj_state->os_ehdr->e_machine;
	Xword			ncap, ocap;

	ncap = flag_bitop(argstate, cap[ndx].c_un.c_val,
	    elfedit_const_to_atoui(const_type));

	/* Set the value */
	if ((ocap = cap[ndx].c_un.c_val) == ncap) {
		elfedit_msg(ELFEDIT_MSG_DEBUG, MSG_INTL(MSG_DEBUG_BSB_OK),
		    cap_ndx, cap_name, EC_WORD(ndx),
		    conv_cap_val(cap_tag, ocap, mach, CONV_FMT_NOBKT, &buf1));

		return (ELFEDIT_CMDRET_NONE);
	} else {
		elfedit_msg(ELFEDIT_MSG_DEBUG, MSG_INTL(MSG_DEBUG_BSB_CHG),
		    cap_ndx, cap_name, EC_WORD(ndx),
		    conv_cap_val(cap_tag, ocap, mach, CONV_FMT_NOBKT, &buf1),
		    conv_cap_val(cap_tag, ncap, mach, CONV_FMT_NOBKT, &buf2));

		cap[ndx].c_un.c_val = ncap;
		return (ELFEDIT_CMDRET_MOD);
	}
}

/*
 * Common body for the cap: module commands. These commands
 * share a large amount of common behavior, so it is convenient
 * to centralize things and use the cmd argument to handle the
 * small differences.
 *
 * entry:
 *	cmd - One of the CAP_CMD_T_* constants listed above, specifying
 *		which command to implement.
 *	obj_state, argc, argv - Standard command arguments
 */
static elfedit_cmdret_t
cmd_body(CAP_CMD_T cmd, elfedit_obj_state_t *obj_state,
    int argc, const char *argv[])
{
	ARGSTATE		argstate;
	Cap			*cap;
	const char		*cap_name;
	Word			cap_ndx;
	elfedit_cmdret_t	ret = ELFEDIT_CMDRET_NONE;
	PRINT_CAP_T		print_type = PRINT_CAP_T_ALL;
	Word			ndx;
	int			print_only = 0;
	int			do_autoprint = 1;

	/* Process the optional arguments */
	process_args(obj_state, argc, argv, &argstate);

	cap = argstate.cap.data;
	cap_name = argstate.cap.sec->sec_name;
	cap_ndx = argstate.cap.sec->sec_shndx;

	/* Check number of arguments, gather information */
	switch (cmd) {
	case CAP_CMD_T_DUMP:
		/* cap:dump can accept an optional index argument */
		if (argstate.argc > 1)
			elfedit_command_usage();
		print_only = 1;
		if (argstate.argc == 1)
			ndx = arg_to_index(&argstate, argstate.argv[0],
			    MSG_ORIG(MSG_STR_ELT), print_only, &print_type);
		break;

	case CAP_CMD_T_TAG:
	case CAP_CMD_T_VALUE:
		print_only = (argstate.argc != 2);
		if (argstate.argc > 0) {
			if (argstate.argc > 2)
				elfedit_command_usage();
			ndx = arg_to_index(&argstate, argstate.argv[0],
			    MSG_ORIG(MSG_STR_ELT), print_only, &print_type);
		}
		break;

	case CAP_CMD_T_DELETE:
		if ((argstate.argc < 1) || (argstate.argc > 2))
			elfedit_command_usage();
		ndx = arg_to_index(&argstate, argstate.argv[0],
		    MSG_ORIG(MSG_STR_ELT),
		    0, &print_type);
		do_autoprint = 0;
		break;

	case CAP_CMD_T_MOVE:
		if ((argstate.argc < 2) || (argstate.argc > 3))
			elfedit_command_usage();
		ndx = arg_to_index(&argstate, argstate.argv[0],
		    MSG_ORIG(MSG_STR_ELT), 0, &print_type);
		do_autoprint = 0;
		break;

	case CAP_CMD_T_HW1:
		print_only = (argstate.argc == 0);
		ndx = arg_to_index(&argstate, elfedit_atoconst_value_to_str(
		    ELFEDIT_CONST_CA, CA_SUNW_HW_1, 1),
		    MSG_ORIG(MSG_STR_VALUE), print_only, &print_type);
		break;

	case CAP_CMD_T_SF1:
		print_only = (argstate.argc == 0);
		ndx = arg_to_index(&argstate, elfedit_atoconst_value_to_str(
		    ELFEDIT_CONST_CA, CA_SUNW_SF_1, 1),
		    MSG_ORIG(MSG_STR_VALUE), print_only, &print_type);
		break;

	case CAP_CMD_T_HW2:
		print_only = (argstate.argc == 0);
		ndx = arg_to_index(&argstate, elfedit_atoconst_value_to_str(
		    ELFEDIT_CONST_CA, CA_SUNW_HW_2, 1),
		    MSG_ORIG(MSG_STR_VALUE), print_only, &print_type);
		break;

	default:
		/* Note expected: All commands should have been caught above */
		elfedit_command_usage();
		break;
	}


	/* If this is a request to print current values, do it and return */
	if (print_only) {
		print_cap(cmd, 0, &argstate, print_type, ndx);
		return (ELFEDIT_CMDRET_NONE);
	}


	switch (cmd) {
		/*
		 * CAP_CMD_T_DUMP can't get here: It is a print-only
		 * command.
		 */

	case CAP_CMD_T_TAG:
		{
			Conv_inv_buf_t	inv_buf1, inv_buf2;
			Word c_tag = (Word) elfedit_atoconst(argstate.argv[1],
			    ELFEDIT_CONST_CA);

			if (cap[ndx].c_tag == c_tag) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_S_OK),
				    cap_ndx, cap_name, EC_WORD(ndx),
				    conv_cap_tag(c_tag, 0, &inv_buf1));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_S_CHG),
				    cap_ndx, cap_name, EC_WORD(ndx),
				    conv_cap_tag(cap[ndx].c_tag, 0, &inv_buf1),
				    conv_cap_tag(c_tag, 0, &inv_buf2));
				cap[ndx].c_tag = c_tag;
				ret = ELFEDIT_CMDRET_MOD;
			}
		}
		break;

	case CAP_CMD_T_VALUE:
		{
			Xword c_val;

			if (argstate.optmask & CAP_OPT_F_STRVAL) {
				argstate_add_str(&argstate, TRUE);
				c_val = elfedit_strtab_insert(obj_state,
				    argstate.str.sec, NULL, argstate.argv[1]);
			} else {
				c_val = (Xword)
				    elfedit_atoui(argstate.argv[1], NULL);
			}

			if (cap[ndx].c_un.c_val == c_val) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_X_OK),
				    argstate.cap.sec->sec_shndx,
				    argstate.cap.sec->sec_name,
				    EC_WORD(ndx), EC_XWORD(c_val));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_X_CHG),
				    argstate.cap.sec->sec_shndx,
				    argstate.cap.sec->sec_name,
				    EC_WORD(ndx), EC_XWORD(cap[ndx].c_un.c_val),
				    EC_XWORD(c_val));
				cap[ndx].c_un.c_val = c_val;
				ret = ELFEDIT_CMDRET_MOD;
			}
		}
		break;

	case CAP_CMD_T_DELETE:
		{
			Word cnt = (argstate.argc == 1) ? 1 :
			    (Word) elfedit_atoui_range(argstate.argv[1],
			    MSG_ORIG(MSG_STR_COUNT), 1,
			    argstate.cap.grp_end_ndx - ndx + 1, NULL);
			const char *msg_prefix =
			    elfedit_sec_msgprefix(argstate.cap.sec);

			/*
			 * We want to limit the deleted elements to be
			 * in the range of the current capabilities group,
			 * and for the resulting NULL elements to be inserted
			 * at the end of the group, rather than at the end
			 * of the section. To do this, we set the array length
			 * in the call to the delete function so that it thinks
			 * the array ends with the current group.
			 *
			 * The delete function will catch attempts to delete
			 * past this virtual end, but the error message will
			 * not make sense to the user. In order to prevent that,
			 * we check for the condition here and provide a more
			 * useful error.
			 */
			if ((ndx + cnt - 1) > argstate.cap.grp_end_ndx)
				elfedit_msg(ELFEDIT_MSG_ERR,
				    MSG_INTL(MSG_ERR_GRPARRBNDS), msg_prefix,
				    argstate.cap.grp_start_ndx,
				    argstate.cap.grp_end_ndx,
				    cap_group_id(&argstate));
			elfedit_array_elts_delete(msg_prefix, cap, sizeof (Cap),
			    argstate.cap.grp_end_ndx + 1, ndx, cnt);
			ret = ELFEDIT_CMDRET_MOD;
		}
		break;

	case CAP_CMD_T_MOVE:
		{
			Cap	save;
			Word	cnt;
			Word	dstndx;
			const char *msg_prefix =
			    elfedit_sec_msgprefix(argstate.cap.sec);

			dstndx = (Word)
			    elfedit_atoui_range(argstate.argv[1],
			    MSG_ORIG(MSG_STR_DST_INDEX),
			    argstate.cap.grp_start_ndx,
			    argstate.cap.grp_end_ndx, NULL);
			if (argstate.argc == 2) {
				cnt = 1;
			} else {
				Word max;

				max = argstate.cap.grp_end_ndx -
				    ((ndx > dstndx) ? ndx : dstndx) + 1;
				cnt = (Word) elfedit_atoui_range(
				    argstate.argv[2], MSG_ORIG(MSG_STR_COUNT),
				    1, max, NULL);
			}

			/*
			 * Moves are required to be self contained within
			 * the bounds of the selected capability group.
			 * The move utility function contains bounds checking,
			 * but is not sub-array aware. Hence, we bounds check
			 * check it here, and then hand of the validated
			 * operation to the move utility function to execute.
			 */
			if ((ndx < argstate.cap.grp_start_ndx) ||
			    ((ndx + cnt) > argstate.cap.grp_end_ndx) ||
			    (dstndx < argstate.cap.grp_start_ndx) ||
			    ((dstndx + cnt) > argstate.cap.grp_end_ndx))
				elfedit_msg(ELFEDIT_MSG_ERR,
				    MSG_INTL(MSG_ERR_GRPARRBNDS), msg_prefix,
				    argstate.cap.grp_start_ndx,
				    argstate.cap.grp_end_ndx,
				    cap_group_id(&argstate));
			elfedit_array_elts_move(msg_prefix, cap, sizeof (save),
			    argstate.cap.grp_end_ndx + 1, ndx, dstndx,
			    cnt, &save);
			ret = ELFEDIT_CMDRET_MOD;
		}
		break;


	case CAP_CMD_T_HW1:
		{
			ret = cap_set(&argstate, cap, ndx, cap_ndx, cap_name,
			    CA_SUNW_HW_1, ELFEDIT_CONST_HW1_SUNW);
		}
		break;

	case CAP_CMD_T_SF1:
		{
			ret = cap_set(&argstate, cap, ndx, cap_ndx, cap_name,
			    CA_SUNW_SF_1, ELFEDIT_CONST_SF1_SUNW);
		}
		break;

	case CAP_CMD_T_HW2:
		{
			ret = cap_set(&argstate, cap, ndx, cap_ndx, cap_name,
			    CA_SUNW_HW_2, ELFEDIT_CONST_HW2_SUNW);
		}
		break;
	}

	/*
	 * If we modified the capabilities section header, tell libelf.
	 */
	if (ret == ELFEDIT_CMDRET_MOD)
		elfedit_modified_data(argstate.cap.sec);

	/* Do autoprint */
	if (do_autoprint)
		print_cap(cmd, 1, &argstate, print_type, ndx);

	return (ret);
}



/*
 * Command completion functions for the commands
 */

/*
 * -capid command completion: Supply all CA_SUNW_ID names found in the object.
 */
static void
cpl_capid_opt(elfedit_obj_state_t *obj_state, void *cpldata, int argc,
    const char *argv[], int num_opt)
{
	elfedit_section_t	*cap_sec, *str_sec;
	Cap			*cap;
	Word			num;

	if (obj_state == NULL)	 /* No object available */
		return;

	if ((argc > num_opt) || (argc < 2) ||
	    (strcmp(argv[argc - 2], MSG_ORIG(MSG_STR_MINUS_CAPID)) != 0))
		return;

	cap_sec = elfedit_sec_getcap(obj_state, &cap, &num);

	/* If no associated string table, we have no strings to complete */
	if (cap_sec->sec_shdr->sh_info == 0)
		return;

	str_sec = elfedit_sec_getstr(obj_state, cap_sec->sec_shdr->sh_info, 0);

	for (; num--; cap++)
		if (cap->c_tag == CA_SUNW_ID)
			elfedit_cpl_match(cpldata, elfedit_offset_to_str(
			    str_sec, cap->c_un.c_val, ELFEDIT_MSG_ERR, 0), 0);
}

/*
 * Command completion for the first argument, which specifies
 * the capabilities element to use. Examines the options to see if
 * -capndx is present, and if not, supplies the completion
 * strings for argument 1.
 */
/*ARGSUSED*/
static void
cpl_eltarg(elfedit_obj_state_t *obj_state, void *cpldata, int argc,
    const char *argv[], int num_opt)
{
	Word	i;

	/* -capid id_name */
	if (argc <= num_opt) {
		cpl_capid_opt(obj_state, cpldata, argc, argv, num_opt);
		return;
	}

	/* Make sure it's the first argument */
	if ((argc - num_opt) != 1)
		return;

	/* Is -capndx present? If so, we don't complete tag types */
	for (i = 0; i < num_opt; i++)
		if (strcmp(argv[i], MSG_ORIG(MSG_STR_MINUS_CAPNDX)) == 0)
			return;

	/*
	 * Supply capability tag names. There are very few of these, so
	 * rather than worry about whether a given tag exists in the
	 * file or not, we simply serve up all the possibilities.
	 */
	elfedit_cpl_atoconst(cpldata, ELFEDIT_CONST_CA);
}

/*ARGSUSED*/
static void
cpl_tag(elfedit_obj_state_t *obj_state, void *cpldata, int argc,
    const char *argv[], int num_opt)
{
	/* -capid id_name */
	if (argc <= num_opt) {
		cpl_capid_opt(obj_state, cpldata, argc, argv, num_opt);
		return;
	}

	/* First plain argument */
	if ((argc - num_opt) == 1) {
		cpl_eltarg(obj_state, cpldata, argc, argv, num_opt);
		return;
	}

	/* The second argument is always a tag value */
	if ((argc - num_opt) == 2)
		elfedit_cpl_atoconst(cpldata, ELFEDIT_CONST_CA);
}

/*ARGSUSED*/
static void
cpl_hw1(elfedit_obj_state_t *obj_state, void *cpldata, int argc,
    const char *argv[], int num_opt)
{
	/* -capid id_name */
	if (argc <= num_opt) {
		cpl_capid_opt(obj_state, cpldata, argc, argv, num_opt);
		return;
	}

	/* This routine allows multiple flags to be specified */
	elfedit_cpl_atoconst(cpldata, ELFEDIT_CONST_HW1_SUNW);
}

/*ARGSUSED*/
static void
cpl_sf1(elfedit_obj_state_t *obj_state, void *cpldata, int argc,
    const char *argv[], int num_opt)
{
	/* -capid id_name */
	if (argc <= num_opt) {
		cpl_capid_opt(obj_state, cpldata, argc, argv, num_opt);
		return;
	}

	/* This routine allows multiple flags to be specified */
	elfedit_cpl_atoconst(cpldata, ELFEDIT_CONST_SF1_SUNW);
}

/*ARGSUSED*/
static void
cpl_hw2(elfedit_obj_state_t *obj_state, void *cpldata, int argc,
    const char *argv[], int num_opt)
{
	/* -capid id_name */
	if (argc <= num_opt) {
		cpl_capid_opt(obj_state, cpldata, argc, argv, num_opt);
		return;
	}

	/* This routine allows multiple flags to be specified */
	elfedit_cpl_atoconst(cpldata, ELFEDIT_CONST_HW2_SUNW);
}

/*
 * Implementation functions for the commands
 */
static elfedit_cmdret_t
cmd_dump(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(CAP_CMD_T_DUMP, obj_state, argc, argv));
}

static elfedit_cmdret_t
cmd_tag(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(CAP_CMD_T_TAG, obj_state, argc, argv));
}

static elfedit_cmdret_t
cmd_value(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(CAP_CMD_T_VALUE, obj_state, argc, argv));
}

static elfedit_cmdret_t
cmd_delete(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(CAP_CMD_T_DELETE, obj_state, argc, argv));
}

static elfedit_cmdret_t
cmd_move(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(CAP_CMD_T_MOVE, obj_state, argc, argv));
}

static elfedit_cmdret_t
cmd_hw1(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(CAP_CMD_T_HW1, obj_state, argc, argv));
}

static elfedit_cmdret_t
cmd_sf1(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(CAP_CMD_T_SF1, obj_state, argc, argv));
}

static elfedit_cmdret_t
cmd_hw2(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(CAP_CMD_T_HW2, obj_state, argc, argv));
}

/*ARGSUSED*/
elfedit_module_t *
elfedit_init(elfedit_module_version_t version)
{
	/* For commands that only accept -capid, -and, -cmp, -o, and -or */
	static elfedit_cmd_optarg_t opt_ostyle_capid_bitop[] = {
		{ ELFEDIT_STDOA_OPT_AND, 0,
		    ELFEDIT_CMDOA_F_INHERIT, CAP_OPT_F_AND, CAP_OPT_F_OR },
		{ MSG_ORIG(MSG_STR_MINUS_CAPID),
		    /* MSG_INTL(MSG_OPTDESC_CAPID) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_CAPID), ELFEDIT_CMDOA_F_VALUE,
		    CAP_OPT_F_CAPID, CAP_OPT_F_CAPNDX },
		{ MSG_ORIG(MSG_STR_IDNAME), 0, 0 },
		{ ELFEDIT_STDOA_OPT_CMP, 0,
		    ELFEDIT_CMDOA_F_INHERIT, CAP_OPT_F_CMP, 0 },
		{ ELFEDIT_STDOA_OPT_O, 0,
		    ELFEDIT_CMDOA_F_INHERIT, 0, 0 },
		{ ELFEDIT_STDOA_OPT_OR, 0,
		    ELFEDIT_CMDOA_F_INHERIT, CAP_OPT_F_OR, CAP_OPT_F_AND },
		{ NULL }
	};

	/* For commands that only accept -capid and -capndx */
	static elfedit_cmd_optarg_t opt_capid_capndx[] = {
		{ MSG_ORIG(MSG_STR_MINUS_CAPID),
		    /* MSG_INTL(MSG_OPTDESC_CAPID) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_CAPID), ELFEDIT_CMDOA_F_VALUE,
		    CAP_OPT_F_CAPID, CAP_OPT_F_CAPNDX },
		{ MSG_ORIG(MSG_STR_IDNAME), 0, 0 },
		{ MSG_ORIG(MSG_STR_MINUS_CAPNDX),
		    /* MSG_INTL(MSG_OPTDESC_CAPNDX) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_CAPNDX), 0,
		    CAP_OPT_F_CAPNDX, CAP_OPT_F_CAPID },
		{ NULL }
	};


	/* cap:dump */
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


	/* cap:tag */
	static const char *name_tag[] = { MSG_ORIG(MSG_CMD_TAG), NULL };
	static elfedit_cmd_optarg_t opt_tag[] = {
		{ MSG_ORIG(MSG_STR_MINUS_CAPID),
		    /* MSG_INTL(MSG_OPTDESC_CAPID) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_CAPID), ELFEDIT_CMDOA_F_VALUE,
		    CAP_OPT_F_CAPID, CAP_OPT_F_CAPNDX },
		{ MSG_ORIG(MSG_STR_IDNAME), 0, 0 },
		{ MSG_ORIG(MSG_STR_MINUS_CAPNDX),
		    /* MSG_INTL(MSG_OPTDESC_CAPNDX) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_CAPNDX), 0,
		    CAP_OPT_F_CAPNDX, 0 },
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


	/* cap:value */
	static const char *name_value[] = { MSG_ORIG(MSG_CMD_VALUE), NULL };
	static elfedit_cmd_optarg_t opt_value[] = {
		{ MSG_ORIG(MSG_STR_MINUS_CAPID),
		    /* MSG_INTL(MSG_OPTDESC_CAPID) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_CAPID), ELFEDIT_CMDOA_F_VALUE,
		    CAP_OPT_F_CAPID, CAP_OPT_F_CAPNDX },
		{ MSG_ORIG(MSG_STR_IDNAME), 0, 0 },
		{ MSG_ORIG(MSG_STR_MINUS_CAPNDX),
		    /* MSG_INTL(MSG_OPTDESC_CAPNDX) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_CAPNDX), 0,
		    CAP_OPT_F_CAPNDX, 0 },
		{ ELFEDIT_STDOA_OPT_O, 0,
		    ELFEDIT_CMDOA_F_INHERIT, 0, 0 },
		{ MSG_ORIG(MSG_STR_MINUS_S),
		    /* MSG_INTL(MSG_OPTDESC_S) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_S), 0,
		    CAP_OPT_F_STRVAL, 0 },
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

	/* cap:delete */
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

	/* cap:move */
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

	/* cap:hw1 */
	static const char *name_hw1[] = { MSG_ORIG(MSG_CMD_HW1), NULL };
	static elfedit_cmd_optarg_t arg_hw1[] = {
		{ MSG_ORIG(MSG_STR_VALUE),
		    /* MSG_INTL(MSG_A1_HW1_VALUE) */
		    ELFEDIT_I18NHDL(MSG_A1_HW1_VALUE),
		    ELFEDIT_CMDOA_F_OPT | ELFEDIT_CMDOA_F_MULT },
		{ NULL }
	};

	/* cap:sf1 */
	static const char *name_sf1[] = { MSG_ORIG(MSG_CMD_SF1), NULL };
	static elfedit_cmd_optarg_t arg_sf1[] = {
		{ MSG_ORIG(MSG_STR_VALUE),
		    /* MSG_INTL(MSG_A1_SF1_VALUE) */
		    ELFEDIT_I18NHDL(MSG_A1_SF1_VALUE),
		    ELFEDIT_CMDOA_F_OPT | ELFEDIT_CMDOA_F_MULT },
		{ NULL }
	};

	/* cap:hw2 */
	static const char *name_hw2[] = { MSG_ORIG(MSG_CMD_HW2), NULL };
	static elfedit_cmd_optarg_t arg_hw2[] = {
		{ MSG_ORIG(MSG_STR_VALUE),
		    /* MSG_INTL(MSG_A1_HW2_VALUE) */
		    ELFEDIT_I18NHDL(MSG_A1_HW2_VALUE),
		    ELFEDIT_CMDOA_F_OPT | ELFEDIT_CMDOA_F_MULT },
		{ NULL }
	};


	static elfedit_cmd_t cmds[] = {
		/* cap:dump */
		{ cmd_dump, cpl_eltarg, name_dump,
		    /* MSG_INTL(MSG_DESC_DUMP) */
		    ELFEDIT_I18NHDL(MSG_DESC_DUMP),
		    /* MSG_INTL(MSG_HELP_DUMP) */
		    ELFEDIT_I18NHDL(MSG_HELP_DUMP),
		    opt_capid_capndx, arg_dump },

		/* cap:tag */
		{ cmd_tag, cpl_tag, name_tag,
		    /* MSG_INTL(MSG_DESC_TAG) */
		    ELFEDIT_I18NHDL(MSG_DESC_TAG),
		    /* MSG_INTL(MSG_HELP_TAG) */
		    ELFEDIT_I18NHDL(MSG_HELP_TAG),
		    opt_tag, arg_tag },

		/* cap:value */
		{ cmd_value, cpl_eltarg, name_value,
		    /* MSG_INTL(MSG_DESC_VALUE) */
		    ELFEDIT_I18NHDL(MSG_DESC_VALUE),
		    /* MSG_INTL(MSG_HELP_VALUE) */
		    ELFEDIT_I18NHDL(MSG_HELP_VALUE),
		    opt_value, arg_value },

		/* cap:delete */
		{ cmd_delete, cpl_eltarg, name_delete,
		    /* MSG_INTL(MSG_DESC_DELETE) */
		    ELFEDIT_I18NHDL(MSG_DESC_DELETE),
		    /* MSG_INTL(MSG_HELP_DELETE) */
		    ELFEDIT_I18NHDL(MSG_HELP_DELETE),
		    opt_capid_capndx, arg_delete },

		/* cap:move */
		{ cmd_move, cpl_eltarg, name_move,
		    /* MSG_INTL(MSG_DESC_MOVE) */
		    ELFEDIT_I18NHDL(MSG_DESC_MOVE),
		    /* MSG_INTL(MSG_HELP_MOVE) */
		    ELFEDIT_I18NHDL(MSG_HELP_MOVE),
		    opt_capid_capndx, arg_move },

		/* cap:hw1 */
		{ cmd_hw1, cpl_hw1, name_hw1,
		    /* MSG_INTL(MSG_DESC_HW1) */
		    ELFEDIT_I18NHDL(MSG_DESC_HW1),
		    /* MSG_INTL(MSG_HELP_HW1) */
		    ELFEDIT_I18NHDL(MSG_HELP_HW1),
		    opt_ostyle_capid_bitop, arg_hw1 },

		/* cap:sf1 */
		{ cmd_sf1, cpl_sf1, name_sf1,
		    /* MSG_INTL(MSG_DESC_SF1) */
		    ELFEDIT_I18NHDL(MSG_DESC_SF1),
		    /* MSG_INTL(MSG_HELP_SF1) */
		    ELFEDIT_I18NHDL(MSG_HELP_SF1),
		    opt_ostyle_capid_bitop, arg_sf1 },

		/* cap:hw2 */
		{ cmd_hw2, cpl_hw2, name_hw2,
		    /* MSG_INTL(MSG_DESC_HW2) */
		    ELFEDIT_I18NHDL(MSG_DESC_HW2),
		    /* MSG_INTL(MSG_HELP_HW2) */
		    ELFEDIT_I18NHDL(MSG_HELP_HW2),
		    opt_ostyle_capid_bitop, arg_hw2 },

		{ NULL }
	};

	static elfedit_module_t module = {
	    ELFEDIT_VER_CURRENT, MSG_ORIG(MSG_MOD_NAME),
	    /* MSG_INTL(MSG_MOD_DESC) */
	    ELFEDIT_I18NHDL(MSG_MOD_DESC),
	    cmds, mod_i18nhdl_to_str };

	return (&module);
}
