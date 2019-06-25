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
#include	<ctype.h>
#include	<unistd.h>
#include	<elfedit.h>
#include	<strings.h>
#include	<debug.h>
#include	<conv.h>
#include	<str_msg.h>




#define	MAXNDXSIZE	10



/*
 * This module uses shared code for several of the commands.
 * It is sometimes necessary to know which specific command
 * is active.
 */
typedef enum {
	STR_CMD_T_DUMP =	0,	/* str:dump */
	STR_CMD_T_SET =		1,	/* str:set */
	STR_CMD_T_ADD =		2,	/* str:add */
	STR_CMD_T_ZERO =	3,	/* str:zero */
} STR_CMD_T;



#ifndef _ELF64
/*
 * We supply this function for the msg module. Only one copy is needed.
 */
const char *
_str_msg(Msg mid)
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
	STR_OPT_F_ANY =		1,	/* -any: treat any sec. as strtab */
	STR_OPT_F_END =		2,	/* -end: zero to end of strtab */
	STR_OPT_F_NOTERM =	4,	/* -noterm: str:set won't term string */
	STR_OPT_F_SHNAME =	8,	/* -shnam name: section spec. by name */
	STR_OPT_F_SHNDX =	16,	/* -shndx ndx: strtab spec. by index */
	STR_OPT_F_SHTYP =	32,	/* -shtyp type: section spec. by type */
	STR_OPT_F_STRNDX =	64,	/* -strndx: String specified by index */
} str_opt_t;


/*
 * A variable of type ARGSTATE is used by each command to maintain
 * information about the string table section being used, and for any
 * auxiliary sections that are related to it.
 */
typedef struct {
	elfedit_obj_state_t	*obj_state;
	str_opt_t		optmask;	/* Mask of options used */
	int			argc;		/* # of plain arguments */
	const char		**argv;		/* Plain arguments */

	struct {				/* String table */
		elfedit_section_t	*sec;
		Word			ndx;	/* Table offset if (argc > 0) */
	} str;
	struct {				/* Dynamic section */
		elfedit_section_t	*sec;
		Dyn			*data;
		Word			n;
		elfedit_dyn_elt_t	strpad;
	} dyn;
} ARGSTATE;



/*
 * Given an ELF SHT_ section type constant, shndx_to_strtab() returns
 * one of the following
 */

typedef enum {
	SHTOSTR_NONE = 0,		/* Type can't lead to a  string table */
	SHTOSTR_STRTAB = 1,		/* type is SHT_STRTAB */
	SHTOSTR_LINK_STRTAB = 2,	/* sh_link for type yields strtab */
	SHTOSTR_LINK_SYMTAB = 3,	/* sh_link for type yields symtab */
	SHTOSTR_SHF_STRINGS = 4,	/* Not strtab, but SHF_STRINGS set */
} SHTOSTR_T;

static SHTOSTR_T
shtype_to_strtab(Word sh_type, Word sh_flags)
{
	/*
	 * A string table section always leads to itself. A
	 * non-string table that has it's SHF_STRINGS section flag
	 * set trumps anything else.
	 */
	if (sh_type == SHT_STRTAB)
		return (SHTOSTR_STRTAB);
	if (sh_flags & SHF_STRINGS)
		return (SHTOSTR_SHF_STRINGS);

	/*
	 * Look at non-stringtable section types that can lead to
	 * string tables via sh_link.
	 */
	switch (sh_type) {
	/* These sections reference a string table via sh_link */
	case SHT_DYNAMIC:
	case SHT_SYMTAB:
	case SHT_DYNSYM:
	case SHT_SUNW_LDYNSYM:
	case SHT_SUNW_verdef:
	case SHT_SUNW_verneed:
		return (SHTOSTR_LINK_STRTAB);

	/*
	 * These sections reference a symbol table via sh_link.
	 * Symbol tables, in turn, reference a string table
	 * via their sh_link.
	 */
	case SHT_HASH:
	case SHT_REL:
	case SHT_RELA:
	case SHT_GROUP:
	case SHT_SYMTAB_SHNDX:
	case SHT_SUNW_move:
	case SHT_SUNW_syminfo:
	case SHT_SUNW_versym:
	case SHT_SUNW_symsort:
	case SHT_SUNW_tlssort:
		return (SHTOSTR_LINK_SYMTAB);
	}

	/* Types that lead to string tables were caught above */
	return (SHTOSTR_NONE);
}

/*
 * Given a section index, attempt to convert it into an index
 * to a string table section.
 */
static Word
shndx_to_strtab(elfedit_obj_state_t *obj_state, Word ndx)
{
	/*
	 * Locate and validate the string table. In the case where
	 * a non-string table section is given that references a string
	 * table, we will use the referenced table.
	 */
	if (ndx < obj_state->os_shnum) {
		Shdr *shdr = obj_state->os_secarr[ndx].sec_shdr;

		switch (shtype_to_strtab(shdr->sh_type, shdr->sh_flags)) {

		/* Sections that reference a string table via sh_link */
		case SHTOSTR_LINK_STRTAB:
			ndx = shdr->sh_link;
			break;

		/*
		 * Sections that reference a symbol tabel via sh_link,
		 * which in turn reference a string table via their sh_link.
		 */
		case SHTOSTR_LINK_SYMTAB:
			ndx = shdr->sh_link;
			if (ndx < obj_state->os_shnum)
				ndx =
				    obj_state->os_secarr[ndx].sec_shdr->sh_link;
			break;
		}
	}

	return (ndx);
}



/*
 * Standard argument processing for string table module
 *
 * entry
 *	obj_state, argc, argv - Standard command arguments
 *	optmask - Mask of allowed optional arguments.
 *	argstate - Address of ARGSTATE block to be initialized
 *
 * exit:
 *	On success, *argstate is initialized. On error,
 *	an error is issued and this routine does not return.
 */
static void
process_args(elfedit_obj_state_t *obj_state, int argc, const char *argv[],
    STR_CMD_T cmd, ARGSTATE *argstate, int *print_only)
{
	elfedit_getopt_state_t	getopt_state;
	elfedit_getopt_ret_t	*getopt_ret;
	Word			ndx;
	int			argc_ok;

	bzero(argstate, sizeof (*argstate));
	argstate->obj_state = obj_state;

	/*
	 * By default, we use the section name string table pointed at
	 * by the ELF header.
	 */
	ndx = obj_state->os_ehdr->e_shstrndx;

	elfedit_getopt_init(&getopt_state, &argc, &argv);

	/* Add each new option to the options mask */
	while ((getopt_ret = elfedit_getopt(&getopt_state)) != NULL) {
		argstate->optmask |= getopt_ret->gor_idmask;

		switch (getopt_ret->gor_idmask) {
		case STR_OPT_F_SHNAME:		/* -shnam name */
			ndx = elfedit_name_to_shndx(obj_state,
			    getopt_ret->gor_value);
			break;

		case STR_OPT_F_SHNDX:		/* -shndx index */
			ndx = elfedit_atoui(getopt_ret->gor_value, NULL);
			break;

		case STR_OPT_F_SHTYP:		/* -shtyp type */
			ndx = elfedit_type_to_shndx(obj_state,
			    elfedit_atoconst(getopt_ret->gor_value,
			    ELFEDIT_CONST_SHT));
			break;
		}
	}

	/*
	 * Usage error if there are the wrong number of plain arguments.
	 */
	switch (cmd) {
	case STR_CMD_T_DUMP:
		argc_ok = (argc == 0) || (argc == 1);
		*print_only = 1;
		break;
	case STR_CMD_T_SET:
		argc_ok = (argc == 1) || (argc == 2);
		*print_only = (argc == 1);
		break;
	case STR_CMD_T_ADD:
		argc_ok = (argc == 1);
		*print_only = 0;
		break;
	case STR_CMD_T_ZERO:
		/*
		 * The second argument (count) and the -end option are
		 * mutally exclusive.
		 */
		argc_ok = ((argc == 1) || (argc == 2)) &&
		    !((argc == 2) && (argstate->optmask & STR_OPT_F_END));
		*print_only = 0;
		break;
	default:
		argc_ok = 0;	/* Unknown command? */
		break;
	}
	if (!argc_ok)
		elfedit_command_usage();

	/* If there may be an arbitrary amount of output, use a pager */
	if (argc == 0)
		elfedit_pager_init();

	/* Return the updated values of argc/argv */
	argstate->argc = argc;
	argstate->argv = argv;

	if (argstate->optmask & STR_OPT_F_ANY) {
		/* Take the arbitrary section */
		argstate->str.sec = elfedit_sec_get(obj_state, ndx);

	} else {
		/*
		 * Locate and validate the string table. In the case where
		 * a non-string table section is given that references a string
		 * table, we will use the referenced table.
		 */
		ndx = shndx_to_strtab(obj_state, ndx);

		/*
		 * If ndx is a string table, the following will issue the
		 * proper debug messages. If it is out of range, or of any
		 * other type, an error is issued and it doesn't return.
		 */
		argstate->str.sec = elfedit_sec_getstr(obj_state, ndx, 1);
	}

	/*
	 * If there is a dynamic section, check its sh_link to the
	 * string table index. If these match, then we have the
	 * dynamic string table. In that case, fetch the dynamic
	 * section and locate the DT_SUNW_STRPAD entry, causing
	 * debug messages to be issued.
	 */
	argstate->dyn.sec = NULL;
	elfedit_dyn_elt_init(&argstate->dyn.strpad);
	if (obj_state->os_dynndx != SHN_UNDEF) {
		elfedit_section_t *dynsec =
		    &obj_state->os_secarr[obj_state->os_dynndx];

		if ((dynsec->sec_shdr->sh_type == SHT_DYNAMIC) &&
		    (argstate->str.sec->sec_shndx ==
		    dynsec->sec_shdr->sh_link)) {
			argstate->dyn.sec = elfedit_sec_getdyn(obj_state,
			    &argstate->dyn.data, &argstate->dyn.n);
			(void) elfedit_dynstr_getpad(obj_state, dynsec,
			    &argstate->dyn.strpad);

			/*
			 * Does the pad value make sense?
			 * Issue debug message and ignore it if not.
			 */
			if ((argstate->dyn.strpad.dn_seen != 0) &&
			    (argstate->dyn.strpad.dn_dyn.d_un.d_val >
			    argstate->str.sec->sec_data->d_size)) {
				argstate->dyn.strpad.dn_seen = 0;
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_BADSTRPAD),
				    EC_WORD(argstate->str.sec->sec_shndx),
				    argstate->str.sec->sec_name,
				    EC_XWORD(argstate->dyn.strpad.dn_dyn.
				    d_un.d_val),
				    EC_XWORD(argstate->str.sec->
				    sec_data->d_size));

			}
		}
	}

	/* Locate the string table offset if argument is present */
	if ((argc > 0) && (cmd != STR_CMD_T_ADD)) {
		/*
		 * If the -strndx option was specified, arg is an index
		 * into the string table. Otherwise it is a string
		 * to be looked up.
		 */
		if (argstate->optmask & STR_OPT_F_STRNDX) {
			argstate->str.ndx = (elfedit_atoui_range(argv[0],
			    MSG_ORIG(MSG_STR_STRING), 0,
			    argstate->str.sec->sec_data->d_size - 1, NULL));
		} else {
			if (elfedit_sec_findstr(argstate->str.sec, 0, argv[0],
			    &argstate->str.ndx) == 0)
				elfedit_msg(ELFEDIT_MSG_ERR,
				    MSG_INTL(MSG_ERR_STRNOTFND),
				    EC_WORD(argstate->str.sec->sec_shndx),
				    argstate->str.sec->sec_name, argv[0]);
		}
	} else {
		argstate->str.ndx = 0;
	}
}



/*
 * Print string table values, taking output style into account.
 *
 * entry:
 *	autoprint - If True, output is only produced if the elfedit
 *		autoprint flag is set. If False, output is always produced.
 *	argstate - State block for current symbol table.
 */
static void
print_strtab(int autoprint, ARGSTATE *argstate)
{
	char			index[(MAXNDXSIZE * 2) + 4];
	elfedit_outstyle_t	outstyle;
	const char		*str, *limit, *tbl_limit;
	Word			ndx;


	if (autoprint && ((elfedit_flags() & ELFEDIT_F_AUTOPRINT) == 0))
		return;

	outstyle = elfedit_outstyle();
	if (outstyle == ELFEDIT_OUTSTYLE_DEFAULT) {
		elfedit_printf(MSG_INTL(MSG_FMT_STRTAB),
		    argstate->str.sec->sec_name);
		if (argstate->dyn.strpad.dn_seen)
			elfedit_printf(MSG_INTL(MSG_FMT_DYNSTRPAD),
			    EC_WORD(argstate->str.sec->sec_data->d_size -
			    argstate->dyn.strpad.dn_dyn.d_un.d_val),
			    EC_WORD(argstate->str.sec->sec_data->d_size - 1),
			    EC_WORD(argstate->dyn.strpad.dn_dyn.d_un.d_val));
		elfedit_printf(MSG_INTL(MSG_FMT_DUMPTITLE));
	}

	str = argstate->str.sec->sec_data->d_buf;
	tbl_limit = str + argstate->str.sec->sec_data->d_size;
	ndx = argstate->str.ndx;
	if (argstate->argc > 0) {
		str += ndx;
		/*
		 * If first byte is NULL and this is the default output style,
		 * then we want to display the range of NULL bytes, and we
		 * push limit out to the last one in the sequence. Otherwise,
		 * just display the string.
		 */
		if ((*str == '\0') && (outstyle == ELFEDIT_OUTSTYLE_DEFAULT)) {
			limit = str;
			while (((limit + 1) < tbl_limit) &&
			    (*(limit + 1) == '\0'))
				limit++;
		} else {
			limit = str + strlen(str) + 1;
		}
	} else {
		/* Display the entire string table  */
		limit = tbl_limit;
	}


	while (str < limit) {
		Word	skip = strlen(str) + 1;
		Word	start_ndx;

		if (outstyle != ELFEDIT_OUTSTYLE_DEFAULT) {
			elfedit_printf(MSG_ORIG(MSG_FMT_STRNL), str);
			str += skip;
			ndx += skip;
			continue;
		}

		start_ndx = ndx;
		if (*str == '\0')
			while (((str + 1) < limit) && (*(str + 1) == '\0')) {
				ndx++;
				str++;
			}

		if (start_ndx != ndx) {
			(void) snprintf(index, sizeof (index),
			    MSG_ORIG(MSG_FMT_INDEXRANGE),
			    EC_XWORD(start_ndx), EC_XWORD(ndx));
		} else {
			(void) snprintf(index, sizeof (index),
			    MSG_ORIG(MSG_FMT_INDEX), EC_XWORD(ndx));
		}
		elfedit_printf(MSG_ORIG(MSG_FMT_DUMPENTRY), index);
		elfedit_write(MSG_ORIG(MSG_STR_DQUOTE), MSG_STR_DQUOTE_SIZE);
		if (start_ndx == ndx)
			elfedit_str_to_c_literal(str, elfedit_write);
		elfedit_write(MSG_ORIG(MSG_STR_DQUOTENL),
		    MSG_STR_DQUOTENL_SIZE);
		str += skip;
		ndx += skip;
	}
}


/*
 * Command body for str:set, handling the case where the 3rd
 * argument (new-str) is present.
 */
static elfedit_cmdret_t
cmd_body_set(ARGSTATE *argstate)
{
	elfedit_section_t	*strsec = argstate->str.sec;
	const char		*newstr = argstate->argv[1];
	Word	ndx = argstate->str.ndx;
	char	*oldstr;
	int	i, len, ncp;

	len = strlen(newstr);
	ncp = len;
	if (!(argstate->optmask & STR_OPT_F_NOTERM))
		ncp++;

	/* NULL string with no termination? Nothing to do */
	if (ncp == 0)
		return (ELFEDIT_CMDRET_NONE);

	/* Does it fit? */
	if ((ndx + ncp) > strsec->sec_data->d_size)
		elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_NOFIT),
		    EC_WORD(strsec->sec_shndx), strsec->sec_name,
		    EC_WORD(ndx), newstr);

	/* Does it clobber the final NULL termination? */
	if (((ndx + ncp) == strsec->sec_data->d_size) &&
	    (argstate->optmask & STR_OPT_F_NOTERM))
		elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_FINALNULL),
		    EC_WORD(strsec->sec_shndx), strsec->sec_name,
		    EC_WORD(ndx), newstr);

	/*
	 * strtab[0] is always supposed to contain a NULL byte. You're not
	 * supposed to mess with it. We will carry out this operation,
	 * but with a debug message indicating that it is unorthodox.
	 */
	if ((ndx == 0) && (*newstr != '\0'))
		elfedit_msg(ELFEDIT_MSG_DEBUG, MSG_INTL(MSG_DEBUG_CHGSTR0),
		    EC_WORD(strsec->sec_shndx), strsec->sec_name,
		    EC_WORD(ndx), newstr);

	/* Does it alter the existing value? */
	oldstr = ndx + (char *)strsec->sec_data->d_buf;
	for (i = 0; i < ncp; i++)
		if (newstr[i] != oldstr[i])
			break;
	if (i == ncp) {		/* No change */
		elfedit_msg(ELFEDIT_MSG_DEBUG, MSG_INTL(MSG_DEBUG_S_OK),
		    strsec->sec_shndx, strsec->sec_name, ndx, newstr);
		return (ELFEDIT_CMDRET_NONE);
	}

	/*
	 * If the new string is longer than the old one, then it will
	 * clobber the start of the following string. The resulting
	 * string table is perfectly legal, but issue a debug message
	 * letting the user know.
	 */
	i = strlen(oldstr);
	if (len > i)
		elfedit_msg(ELFEDIT_MSG_DEBUG, MSG_INTL(MSG_DEBUG_LONGSTR),
		    EC_WORD(strsec->sec_shndx), strsec->sec_name,
		    EC_WORD(ndx), len, i);

	/*
	 * If we have strayed into the reserved part of the dynstr, then
	 * update DT_SUNW_STRPAD.
	 */
	if (argstate->dyn.strpad.dn_seen) {
		elfedit_dyn_elt_t	*strpad = &argstate->dyn.strpad;
		Word	new_pad_ndx = ndx + len + 1;
		Word	pad_ndx = argstate->str.sec->sec_data->d_size -
		    strpad->dn_dyn.d_un.d_val;

		if (new_pad_ndx > pad_ndx) {
			elfedit_msg(ELFEDIT_MSG_DEBUG,
			    MSG_INTL(MSG_DEBUG_ADDDYNSTR),
			    EC_WORD(strsec->sec_shndx), strsec->sec_name,
			    EC_WORD(ndx), EC_WORD(new_pad_ndx - pad_ndx),
			    EC_WORD(strpad->dn_dyn.d_un.d_val),
			    newstr);

			strpad->dn_dyn.d_un.d_val =
			    argstate->dyn.data[strpad->dn_ndx].d_un.d_val =
			    (argstate->str.sec->sec_data->d_size - new_pad_ndx);
			elfedit_modified_data(argstate->dyn.sec);
		}
	}



	elfedit_msg(ELFEDIT_MSG_DEBUG, MSG_INTL(MSG_DEBUG_S_CHG),
	    strsec->sec_shndx, strsec->sec_name, ndx, len, oldstr, newstr);
	bcopy(newstr, oldstr, ncp);

	return (ELFEDIT_CMDRET_MOD);
}


/*
 * Command body for str:zero
 */
static elfedit_cmdret_t
cmd_body_zero(ARGSTATE *argstate)
{
	elfedit_section_t	*strsec = argstate->str.sec;
	Word	count;
	Word	ndx = argstate->str.ndx;
	char	*oldstr = ndx + (char *)strsec->sec_data->d_buf;
	Word	i;

	/* How many bytes to zero? */
	if (argstate->optmask & STR_OPT_F_END)
		count = strsec->sec_data->d_size - argstate->str.ndx;
	else if (argstate->argc == 2)
		count = elfedit_atoui_range(argstate->argv[1],
		    MSG_ORIG(MSG_STR_COUNT), 0,
		    argstate->str.sec->sec_data->d_size - argstate->str.ndx,
		    NULL);
	else
		count = strlen(oldstr);

	/* Does it alter the existing value? */
	for (i = 0; i < count; i++)
		if (oldstr[i] != '\0')
			break;
	if (i == count) {		/* No change */
		elfedit_msg(ELFEDIT_MSG_DEBUG, MSG_INTL(MSG_DEBUG_Z_OK),
		    strsec->sec_shndx, strsec->sec_name, ndx);
		return (ELFEDIT_CMDRET_NONE);
	}

	elfedit_msg(ELFEDIT_MSG_DEBUG, MSG_INTL(MSG_DEBUG_Z_CHG),
	    strsec->sec_shndx, strsec->sec_name, ndx, count);
	bzero(oldstr, count);

	return (ELFEDIT_CMDRET_MOD);
}


/*
 * Common body for the str: module commands.
 *
 * entry:
 *	cmd - One of the STR_CMD_T_* constants listed above, specifying
 *		which command to implement.
 *	obj_state, argc, argv - Standard command arguments
 */
static elfedit_cmdret_t
cmd_body(STR_CMD_T cmd, elfedit_obj_state_t *obj_state,
    int argc, const char *argv[])
{
	ARGSTATE		argstate;
	elfedit_cmdret_t	ret = ELFEDIT_CMDRET_NONE;
	int			print_only;

	process_args(obj_state, argc, argv, cmd, &argstate, &print_only);

	/*
	 * If this call call does not change data, display the current
	 * value(s) and return.
	 */
	if (print_only) {
		print_strtab(0, &argstate);
		return (ELFEDIT_CMDRET_NONE);
	}

	switch (cmd) {
	/* NOTE: STR_CMD_T_DUMP can't get here --- it's always print_only */

	case STR_CMD_T_SET:
		ret = cmd_body_set(&argstate);
		break;

	case STR_CMD_T_ADD:
		argstate.str.ndx = elfedit_strtab_insert(obj_state,
		    argstate.str.sec, argstate.dyn.sec, argstate.argv[0]);
		break;

	case STR_CMD_T_ZERO:
		ret = cmd_body_zero(&argstate);
		break;
	}

	/*
	 * If we modified the strtab section, tell libelf.
	 */
	if (ret == ELFEDIT_CMDRET_MOD)
		elfedit_modified_data(argstate.str.sec);

	/* Do autoprint */
	print_strtab(1, &argstate);

	return (ret);
}




/*
 * Command completion functions for the various commands
 */

static void
add_shtyp_match(Word sh_type, void *cpldata)
{
	char		buf[128];
	const char	*s;
	char		*s2;

	s = elfedit_atoconst_value_to_str(ELFEDIT_CONST_SHT, sh_type, 0);
	elfedit_cpl_match(cpldata, s, 1);

	/*
	 * To get the informal tag names that are lowercase
	 * and lack the leading SHT_, we copy the string we
	 * have into a buffer and process it.
	 */
	if (strlen(s) < 4)
		return;
	(void) strlcpy(buf, s + 4, sizeof (buf));
	for (s2 = buf; *s2 != '\0'; s2++)
		if (isupper(*s2))
			*s2 = tolower(*s2);
	elfedit_cpl_match(cpldata, buf, 1);
}

/*
 * Handle filling in the values for -shnam, -shndx, and -shtyp options.
 */
/*ARGSUSED*/
static void
cpl_sh_opt(elfedit_obj_state_t *obj_state, void *cpldata, int argc,
    const char *argv[], int num_opt)
{
	enum { NAME, INDEX, TYPE }	op;
	elfedit_section_t		*sec;
	Word	ndx;

	if ((argc != num_opt) || (argc < 2))
		return;

	if (strcmp(argv[argc - 2], MSG_ORIG(MSG_STR_MINUS_SHNAM)) == 0) {
		op = NAME;
	} else if (strcmp(argv[argc - 2], MSG_ORIG(MSG_STR_MINUS_SHNDX)) == 0) {
		op = INDEX;

	} else if (strcmp(argv[argc - 2], MSG_ORIG(MSG_STR_MINUS_SHTYP)) == 0) {
		op = TYPE;

		if (obj_state == NULL) {	 /* No object available */
			elfedit_atoui_sym_t *atoui_sym;

			atoui_sym = elfedit_const_to_atoui(ELFEDIT_CONST_SHT);
			for (; atoui_sym->sym_name != NULL; atoui_sym++)
				if (shtype_to_strtab(atoui_sym->sym_value, 0) !=
				    SHTOSTR_NONE)
					elfedit_cpl_match(cpldata,
					    atoui_sym->sym_name, 1);
		}
	} else {
		return;
	}

	if (obj_state == NULL)	 /* No object available */
		return;

	/*
	 * Loop over the section headers and supply command completion
	 * for the items in the file that can yield a string table.
	 */
	sec = obj_state->os_secarr;
	for (ndx = 0; ndx < obj_state->os_shnum; ndx++, sec++) {
		Shdr		*shdr = sec->sec_shdr;
		SHTOSTR_T	shtostr_type;

		shtostr_type = shtype_to_strtab(shdr->sh_type, shdr->sh_flags);
		if (shtostr_type == SHTOSTR_NONE)
			continue;

		switch (op) {
		case NAME:
			elfedit_cpl_match(cpldata, sec->sec_name, 0);
			break;
		case INDEX:
			elfedit_cpl_ndx(cpldata, sec->sec_shndx);
			break;
		case TYPE:
			if (shtostr_type != SHTOSTR_SHF_STRINGS)
				add_shtyp_match(shdr->sh_type, cpldata);
			break;
		}
	}
}


/*
 * Most of the commands accept an -shXXX option for the string table
 * and a string first argument. This routine examines which argument
 * is being processed, and supplies completion for these items.
 */
static void
cpl_sec_str(elfedit_obj_state_t *obj_state, void *cpldata, int argc,
    const char *argv[], int num_opt)
{
	const char		*str, *limit;
	elfedit_section_t	*sec;
	Word			strtab_ndx;
	Word			ndx;

	/* Handle -shXXX options */
	cpl_sh_opt(obj_state, cpldata, argc, argv, num_opt);

	/* Without object state, there's no data to work from */
	if (obj_state == NULL)
		return;

	/* If not first plain arg, return */
	if (argc != (num_opt + 1))
		return;

	/*
	 * Look at the options, looking for two things:
	 *	1) A -shXXX option specifying a section. If so, turn that
	 *		into a section index if possible.
	 *	2) Was -strndx used? If so, we are looking at an integer
	 *		value and have nothing to complete.
	 */
	strtab_ndx = obj_state->os_ehdr->e_shstrndx;
	for (ndx = 0; ndx < num_opt; ndx++) {
		if (strcmp(argv[ndx], MSG_ORIG(MSG_STR_MINUS_STRNDX)) == 0)
			return;

		if ((ndx+1) < num_opt) {
			if (strcmp(argv[ndx],
			    MSG_ORIG(MSG_STR_MINUS_SHNAM)) == 0) {
				Word		i;

				for (i = 1; i < obj_state->os_shnum; i++)
					if (strcmp(obj_state->os_secarr[i].
					    sec_name, argv[ndx+1]) == 0) {
						strtab_ndx = i;
						break;
					}
			} else if (strcmp(argv[ndx],
			    MSG_ORIG(MSG_STR_MINUS_SHNDX)) == 0) {
				elfedit_atoui_t val;

				if (elfedit_atoui2(argv[ndx+1], NULL,
				    &val) != 0)
					strtab_ndx = val;
			} else if (strcmp(argv[ndx],
			    MSG_ORIG(MSG_STR_MINUS_SHTYP)) == 0) {
				elfedit_atoui_t	sh_type;
				Word		i;

				if (elfedit_atoconst2(argv[ndx+1],
				    ELFEDIT_CONST_SHT, &sh_type) == 0)
					continue;
				for (i = 1; i < obj_state->os_shnum; i++)
					if (obj_state->os_secarr[i].sec_shdr->
					    sh_type == sh_type) {
						strtab_ndx = i;
						break;
					}
			}
		}
	}

	/*
	 * Locate and validate the string table. In the case where
	 * a non-string table section is given that references a string
	 * table, we will use the referenced table.
	 */
	strtab_ndx = shndx_to_strtab(obj_state, strtab_ndx);
	if ((strtab_ndx >= obj_state->os_shnum) ||
	    (obj_state->os_secarr[strtab_ndx].sec_shdr->sh_type != SHT_STRTAB))
		return;
	sec = &obj_state->os_secarr[strtab_ndx];

	str = sec->sec_data->d_buf;
	limit = str + sec->sec_data->d_size;
	while (str < limit) {
		if (*str != '\0')
			elfedit_cpl_match(cpldata, str, 0);
		str += strlen(str) + 1;
	}
}



/*
 * Implementation functions for the commands
 */
static elfedit_cmdret_t
cmd_dump(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(STR_CMD_T_DUMP, obj_state, argc, argv));
}

static elfedit_cmdret_t
cmd_set(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(STR_CMD_T_SET, obj_state, argc, argv));
}

static elfedit_cmdret_t
cmd_add(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(STR_CMD_T_ADD, obj_state, argc, argv));
}

static elfedit_cmdret_t
cmd_zero(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(STR_CMD_T_ZERO, obj_state, argc, argv));
}



/*ARGSUSED*/
elfedit_module_t *
elfedit_init(elfedit_module_version_t version)
{
	/* str:dump */
	static const char *name_dump[] = {
	    MSG_ORIG(MSG_CMD_DUMP),
	    MSG_ORIG(MSG_STR_EMPTY),	/* "" makes this the default command */
	    NULL
	};
	static elfedit_cmd_optarg_t opt_dump[] = {
		{ MSG_ORIG(MSG_STR_MINUS_ANY),
		    /* MSG_INTL(MSG_OPTDESC_ANY) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_ANY), 0,
		    STR_OPT_F_ANY, 0 },
		{ ELFEDIT_STDOA_OPT_O, 0,
		    ELFEDIT_CMDOA_F_INHERIT, 0, 0 },
		{ MSG_ORIG(MSG_STR_MINUS_SHNAM),
		    /* MSG_INTL(MSG_OPTDESC_SHNAM) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_SHNAM), ELFEDIT_CMDOA_F_VALUE,
		    STR_OPT_F_SHNAME, STR_OPT_F_SHNDX | STR_OPT_F_SHTYP },
		{ MSG_ORIG(MSG_STR_NAME), 0, 0 },
		{ MSG_ORIG(MSG_STR_MINUS_SHNDX),
		    /* MSG_INTL(MSG_OPTDESC_SHNDX) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_SHNDX), ELFEDIT_CMDOA_F_VALUE,
		    STR_OPT_F_SHNDX, STR_OPT_F_SHNAME | STR_OPT_F_SHTYP },
		{ MSG_ORIG(MSG_STR_INDEX), 0, 0 },
		{ MSG_ORIG(MSG_STR_MINUS_SHTYP),
		    /* MSG_INTL(MSG_OPTDESC_SHTYP) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_SHTYP), ELFEDIT_CMDOA_F_VALUE,
		    STR_OPT_F_SHTYP, STR_OPT_F_SHNAME | STR_OPT_F_SHNDX },
		{ MSG_ORIG(MSG_STR_TYPE), 0, 0 },
		{ MSG_ORIG(MSG_STR_MINUS_STRNDX),
		    /* MSG_INTL(MSG_OPTDESC_STRNDX) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_STRNDX), 0,
		    STR_OPT_F_STRNDX, 0 },
		{ NULL }
	};
	static elfedit_cmd_optarg_t arg_dump[] = {
		{ MSG_ORIG(MSG_STR_STRING),
		    /* MSG_INTL(MSG_A1_STRING) */
		    ELFEDIT_I18NHDL(MSG_A1_STRING),
		    ELFEDIT_CMDOA_F_OPT },
		{ NULL }
	};

	/* str:set */
	static const char *name_set[] = {
	    MSG_ORIG(MSG_CMD_SET), NULL };
	static elfedit_cmd_optarg_t opt_set[] = {
		{ MSG_ORIG(MSG_STR_MINUS_ANY),
		    /* MSG_INTL(MSG_OPTDESC_ANY) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_ANY), 0,
		    STR_OPT_F_ANY, 0 },
		{ ELFEDIT_STDOA_OPT_O, 0,
		    ELFEDIT_CMDOA_F_INHERIT, 0, 0 },
		{ MSG_ORIG(MSG_STR_MINUS_NOTERM),
		    /* MSG_INTL(MSG_OPTDESC_NOTERM) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_NOTERM), 0,
		    STR_OPT_F_NOTERM, 0 },
		{ MSG_ORIG(MSG_STR_MINUS_SHNAM),
		    /* MSG_INTL(MSG_OPTDESC_SHNAM) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_SHNAM), ELFEDIT_CMDOA_F_VALUE,
		    STR_OPT_F_SHNAME, STR_OPT_F_SHNDX | STR_OPT_F_SHTYP },
		{ MSG_ORIG(MSG_STR_NAME), 0, 0 },
		{ MSG_ORIG(MSG_STR_MINUS_SHNDX),
		    /* MSG_INTL(MSG_OPTDESC_SHNDX) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_SHNDX), ELFEDIT_CMDOA_F_VALUE,
		    STR_OPT_F_SHNDX, STR_OPT_F_SHNAME | STR_OPT_F_SHTYP },
		{ MSG_ORIG(MSG_STR_INDEX), 0, 0 },
		{ MSG_ORIG(MSG_STR_MINUS_SHTYP),
		    /* MSG_INTL(MSG_OPTDESC_SHTYP) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_SHTYP), ELFEDIT_CMDOA_F_VALUE,
		    STR_OPT_F_SHTYP, STR_OPT_F_SHNAME | STR_OPT_F_SHNDX },
		{ MSG_ORIG(MSG_STR_TYPE), 0, 0 },
		{ MSG_ORIG(MSG_STR_MINUS_STRNDX),
		    /* MSG_INTL(MSG_OPTDESC_STRNDX) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_STRNDX), 0,
		    STR_OPT_F_STRNDX, 0 },
		{ NULL }
	};
	static elfedit_cmd_optarg_t arg_set[] = {
		{ MSG_ORIG(MSG_STR_STRING),
		    /* MSG_INTL(MSG_A1_STRING) */
		    ELFEDIT_I18NHDL(MSG_A1_STRING),
		    0 },
		{ MSG_ORIG(MSG_STR_NEWSTRING),
		    /* MSG_INTL(MSG_A2_NEWSTRING) */
		    ELFEDIT_I18NHDL(MSG_A2_NEWSTRING),
		    ELFEDIT_CMDOA_F_OPT },
		{ NULL }
	};

	/* str:add */
	static const char *name_add[] = {
	    MSG_ORIG(MSG_CMD_ADD), NULL };
	static elfedit_cmd_optarg_t opt_add[] = {
		{ ELFEDIT_STDOA_OPT_O, 0,
		    ELFEDIT_CMDOA_F_INHERIT, 0, 0 },
		{ MSG_ORIG(MSG_STR_MINUS_SHNAM),
		    /* MSG_INTL(MSG_OPTDESC_SHNAM) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_SHNAM), ELFEDIT_CMDOA_F_VALUE,
		    STR_OPT_F_SHNAME, STR_OPT_F_SHNDX | STR_OPT_F_SHTYP },
		{ MSG_ORIG(MSG_STR_NAME), 0, 0 },
		{ MSG_ORIG(MSG_STR_MINUS_SHNDX),
		    /* MSG_INTL(MSG_OPTDESC_SHNDX) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_SHNDX), ELFEDIT_CMDOA_F_VALUE,
		    STR_OPT_F_SHNDX, STR_OPT_F_SHNAME | STR_OPT_F_SHTYP },
		{ MSG_ORIG(MSG_STR_INDEX), 0, 0 },
		{ MSG_ORIG(MSG_STR_MINUS_SHTYP),
		    /* MSG_INTL(MSG_OPTDESC_SHTYP) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_SHTYP), ELFEDIT_CMDOA_F_VALUE,
		    STR_OPT_F_SHTYP, STR_OPT_F_SHNAME | STR_OPT_F_SHNDX },
		{ MSG_ORIG(MSG_STR_TYPE), 0, 0 },
		{ NULL }
	};
	static elfedit_cmd_optarg_t arg_add[] = {
		{ MSG_ORIG(MSG_STR_NEWSTRING),
		    /* MSG_INTL(MSG_A1_NEWSTRING) */
		    ELFEDIT_I18NHDL(MSG_A1_NEWSTRING),
		    0 },
		{ NULL }
	};

	/* str:zero */
	static const char *name_zero[] = {
	    MSG_ORIG(MSG_CMD_ZERO), NULL };
	static elfedit_cmd_optarg_t opt_zero[] = {
		{ MSG_ORIG(MSG_STR_MINUS_ANY),
		    /* MSG_INTL(MSG_OPTDESC_ANY) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_ANY), 0,
		    STR_OPT_F_ANY, 0 },
		{ ELFEDIT_STDOA_OPT_O, 0,
		    ELFEDIT_CMDOA_F_INHERIT, 0, 0 },
		{ MSG_ORIG(MSG_STR_MINUS_SHNAM),
		    /* MSG_INTL(MSG_OPTDESC_SHNAM) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_SHNAM), ELFEDIT_CMDOA_F_VALUE,
		    STR_OPT_F_SHNAME, STR_OPT_F_SHNDX | STR_OPT_F_SHTYP },
		{ MSG_ORIG(MSG_STR_NAME), 0, 0 },
		{ MSG_ORIG(MSG_STR_MINUS_SHNDX),
		    /* MSG_INTL(MSG_OPTDESC_SHNDX) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_SHNDX), ELFEDIT_CMDOA_F_VALUE,
		    STR_OPT_F_SHNDX, STR_OPT_F_SHNAME | STR_OPT_F_SHTYP },
		{ MSG_ORIG(MSG_STR_INDEX), 0, 0 },
		{ MSG_ORIG(MSG_STR_MINUS_SHTYP),
		    /* MSG_INTL(MSG_OPTDESC_SHTYP) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_SHTYP), ELFEDIT_CMDOA_F_VALUE,
		    STR_OPT_F_SHTYP, STR_OPT_F_SHNAME | STR_OPT_F_SHNDX },
		{ MSG_ORIG(MSG_STR_TYPE), 0, 0 },
		{ MSG_ORIG(MSG_STR_MINUS_STRNDX),
		    /* MSG_INTL(MSG_OPTDESC_STRNDX) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_STRNDX), 0,
		    STR_OPT_F_STRNDX, 0 },
		{ MSG_ORIG(MSG_STR_MINUS_END),
		    /* MSG_INTL(MSG_OPTDESC_END) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_END), 0,
		    STR_OPT_F_END, 0 },
		{ NULL }
	};
	static elfedit_cmd_optarg_t arg_zero[] = {
		{ MSG_ORIG(MSG_STR_STRING),
		    /* MSG_INTL(MSG_A1_STRING) */
		    ELFEDIT_I18NHDL(MSG_A1_STRING),
		    0 },
		{ MSG_ORIG(MSG_STR_COUNT),
		    /* MSG_INTL(MSG_A2_COUNT) */
		    ELFEDIT_I18NHDL(MSG_A2_COUNT),
		    ELFEDIT_CMDOA_F_OPT },
		{ NULL }
	};


	static elfedit_cmd_t cmds[] = {
		/* str:dump */
		{ cmd_dump, cpl_sec_str, name_dump,
		    /* MSG_INTL(MSG_DESC_DUMP) */
		    ELFEDIT_I18NHDL(MSG_DESC_DUMP),
		    /* MSG_INTL(MSG_HELP_DUMP) */
		    ELFEDIT_I18NHDL(MSG_HELP_DUMP),
		    opt_dump, arg_dump },

		/* str:set */
		{ cmd_set, cpl_sec_str, name_set,
		    /* MSG_INTL(MSG_DESC_SET) */
		    ELFEDIT_I18NHDL(MSG_DESC_SET),
		    /* MSG_INTL(MSG_HELP_SET) */
		    ELFEDIT_I18NHDL(MSG_HELP_SET),
		    opt_set, arg_set },

		/* str:add */
		{ cmd_add, cpl_sh_opt, name_add,
		    /* MSG_INTL(MSG_DESC_ADD) */
		    ELFEDIT_I18NHDL(MSG_DESC_ADD),
		    /* MSG_INTL(MSG_HELP_ADD) */
		    ELFEDIT_I18NHDL(MSG_HELP_ADD),
		    opt_add, arg_add },

		/* str:zero */
		{ cmd_zero, cpl_sec_str, name_zero,
		    /* MSG_INTL(MSG_DESC_ZERO) */
		    ELFEDIT_I18NHDL(MSG_DESC_ZERO),
		    /* MSG_INTL(MSG_HELP_ZERO) */
		    ELFEDIT_I18NHDL(MSG_HELP_ZERO),
		    opt_zero, arg_zero },

		{ NULL }
	};

	static elfedit_module_t module = {
	    ELFEDIT_VER_CURRENT, MSG_ORIG(MSG_MOD_NAME),
	    /* MSG_INTL(MSG_MOD_DESC) */
	    ELFEDIT_I18NHDL(MSG_MOD_DESC),
	    cmds, mod_i18nhdl_to_str };

	return (&module);
}
