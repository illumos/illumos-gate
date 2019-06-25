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

#define	ELF_TARGET_AMD64	/* SHN_AMD64_LCOMMON */

#include	<stdio.h>
#include	<unistd.h>
#include	<elfedit.h>
#include	<strings.h>
#include	<debug.h>
#include	<conv.h>
#include	<sym_msg.h>




#define	MAXNDXSIZE	10



/*
 * This module uses shared code for several of the commands.
 * It is sometimes necessary to know which specific command
 * is active.
 */
typedef enum {
	SYM_CMD_T_DUMP =		0,	/* sym:dump */

	SYM_CMD_T_ST_BIND =		1,	/* sym:st_bind */
	SYM_CMD_T_ST_INFO =		2,	/* sym:st_info */
	SYM_CMD_T_ST_NAME =		3,	/* sym:st_name */
	SYM_CMD_T_ST_OTHER =		4,	/* sym:st_other */
	SYM_CMD_T_ST_SHNDX =		5,	/* sym:st_shndx */
	SYM_CMD_T_ST_SIZE =		6,	/* sym:st_size */
	SYM_CMD_T_ST_TYPE =		7,	/* sym:st_type */
	SYM_CMD_T_ST_VALUE =		8,	/* sym:st_value */
	SYM_CMD_T_ST_VISIBILITY =	9	/* sym:st_visibility */
} SYM_CMD_T;



/*
 * ELFCLASS-specific definitions
 */
#ifdef _ELF64

#define	MSG_FMT_XWORDVALNL MSG_FMT_XWORDVALNL_64

#else

#define	MSG_FMT_XWORDVALNL MSG_FMT_XWORDVALNL_32

/*
 * We supply this function for the msg module. Only one copy is needed.
 */
const char *
_sym_msg(Msg mid)
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
	SYM_OPT_F_XSHINDEX =	1,	/* -e: Force shndx update to extended */
					/*	 index section */
	SYM_OPT_F_NAMOFFSET =	2,	/* -name_offset: sym:st_name name arg */
					/*	is numeric offset */
					/*	rather than ASCII string */
	SYM_OPT_F_SECSHNDX =	4,	/* -secshndx: Section arg is */
					/*	section index, not name */
	SYM_OPT_F_SECSHTYP =	8,	/* -secshtyp: Section arg is */
					/*	section type, not name */
	SYM_OPT_F_SHNAME =	16,	/* -shnam name: section spec. by name */
	SYM_OPT_F_SHNDX =	32,	/* -shndx ndx: section spec. by index */
	SYM_OPT_F_SHTYP =	64,	/* -shtyp type: section spec. by type */
	SYM_OPT_F_SYMNDX =	128	/* -symndx: Sym specified by index */
} sym_opt_t;


/*
 * A variable of type ARGSTATE is used by each command to maintain
 * the overall state for a given set of arguments and the symbol tables
 * being managed.
 *
 * The state for each symbol table and the auxiliary sections that are
 * related to it are kept in a SYMSTATE sub-struct.
 *
 * One benefit of ARGSTATE is that it helps us to ensure that we only
 * fetch each section a single time:
 *	- More efficient
 *	- Prevents multiple ELFEDIT_MSG_DEBUG messages from
 *	  being produced for a given section.
 *
 * note: The symstate array in ARGSTATE is defined as having one
 *	element, but in reality, we allocate enough room for
 *	the number of elements defined in the numsymstate field.
 */
typedef struct {
	Word ndx;	/* If argstate.argc > 0, this is the table index */
	struct {				/* Symbol table */
		elfedit_section_t	*sec;
		Sym			*data;
		Word			n;
	} sym;
	struct {				/* String table */
		elfedit_section_t	*sec;
	} str;
	struct {				/* Versym */
		Word			shndx;
		elfedit_section_t	*sec;
		Versym			*data;
		Word			n;
	} versym;
	struct {				/* Extended section indices */
		Word			shndx;
		elfedit_section_t	*sec;
		Word			*data;
		Word			n;
	} xshndx;
} SYMSTATE;
typedef struct {
	elfedit_obj_state_t	*obj_state;
	sym_opt_t		optmask;	/* Mask of options used */
	int			argc;		/* # of plain arguments */
	const char		**argv;		/* Plain arguments */
	int			numsymstate;	/* # of items in symstate[] */
	SYMSTATE		symstate[1];	/* Symbol tables to process */
} ARGSTATE;


/*
 * We maintain the state of each symbol table and related associated
 * sections in a SYMSTATE structure . We don't look those auxiliary
 * things up unless we actually need them, both to be efficient,
 * and to prevent duplicate ELFEDIT_MSG_DEBUG messages from being
 * issued as they are located. Hence, process_args() is used to
 * initialize the state block with just the symbol table, and then one
 * of the argstate_add_XXX() functions is used as needed
 * to fetch the additional sections.
 *
 * entry:
 *	argstate - Overall state block
 *	symstate - State block for current symbol table.
 *
 * exit:
 *	If the needed auxiliary section is not found, an error is
 *	issued and the argstate_add_XXX() routine does not return.
 *	Otherwise, the fields in argstate have been filled in, ready
 *	for use.
 *
 */
static void
symstate_add_str(ARGSTATE *argstate, SYMSTATE *symstate)
{
	if (symstate->str.sec != NULL)
		return;

	symstate->str.sec = elfedit_sec_getstr(argstate->obj_state,
	    symstate->sym.sec->sec_shdr->sh_link, 0);
}
static void
symstate_add_versym(ARGSTATE *argstate, SYMSTATE *symstate)
{
	if (symstate->versym.sec != NULL)
		return;

	symstate->versym.sec = elfedit_sec_getversym(argstate->obj_state,
	    symstate->sym.sec, &symstate->versym.data, &symstate->versym.n);
}
static void
symstate_add_xshndx(ARGSTATE *argstate, SYMSTATE *symstate)
{
	if (symstate->xshndx.sec != NULL)
		return;

	symstate->xshndx.sec = elfedit_sec_getxshndx(argstate->obj_state,
	    symstate->sym.sec, &symstate->xshndx.data, &symstate->xshndx.n);
}



/*
 * Display symbol table entries in the style used by elfdump.
 *
 * entry:
 *	argstate - Overall state block
 *	symstate - State block for current symbol table.
 *	ndx - Index of first symbol to display
 *	cnt - Number of symbols to display
 */
static void
dump_symtab(ARGSTATE *argstate, SYMSTATE *symstate, Word ndx, Word cnt)
{
	char			index[MAXNDXSIZE];
	Word			shndx;
	const char		*shndx_name;
	elfedit_section_t	*symsec;
	elfedit_section_t	*strsec;
	Sym			*sym;
	elfedit_obj_state_t	*obj_state = argstate->obj_state;
	uchar_t			osabi = obj_state->os_ehdr->e_ident[EI_OSABI];
	Half			mach = obj_state->os_ehdr->e_machine;
	const char		*symname;
	Versym			versym;

	symsec = symstate->sym.sec;
	sym = symstate->sym.data + ndx;

	symstate_add_str(argstate, symstate);
	strsec = symstate->str.sec;

	/* If there is a versym index section, fetch it */
	if (symstate->versym.shndx != SHN_UNDEF)
		symstate_add_versym(argstate, symstate);

	/* If there is an extended index section, fetch it */
	if (symstate->xshndx.shndx != SHN_UNDEF)
		symstate_add_xshndx(argstate, symstate);

	elfedit_printf(MSG_INTL(MSG_FMT_SYMTAB), symsec->sec_name);
	Elf_syms_table_title(0, ELF_DBG_ELFDUMP);
	for (; cnt-- > 0; ndx++, sym++) {
		(void) snprintf(index, MAXNDXSIZE,
		    MSG_ORIG(MSG_FMT_INDEX), EC_XWORD(ndx));
		versym = (symstate->versym.sec == NULL) ? 0 :
		    symstate->versym.data[ndx];
		symname = elfedit_offset_to_str(strsec, sym->st_name,
		    ELFEDIT_MSG_DEBUG, 0);
		shndx = sym->st_shndx;
		if ((shndx == SHN_XINDEX) && (symstate->xshndx.sec != NULL))
			shndx = symstate->xshndx.data[ndx];
		shndx_name = elfedit_shndx_to_name(obj_state, shndx);
		Elf_syms_table_entry(NULL, ELF_DBG_ELFDUMP, index, osabi, mach,
		    sym, versym, 0, shndx_name, symname);
	}
}



/*
 * Called by print_sym() to determine if a given symbol has the same
 * display value for the current command in every symbol table.
 *
 * entry:
 *	cmd - SYM_CMD_T_* value giving identify of caller
 *	argstate - Overall state block
 *	outstyle - Output style to use
 */
static int
all_same(SYM_CMD_T cmd, ARGSTATE *argstate, elfedit_outstyle_t outstyle)
{
	Word			tblndx;
	SYMSTATE		*symstate1, *symstate2;
	Sym			*sym1, *sym2;

	symstate1 = argstate->symstate;
	for (tblndx = 0; tblndx < (argstate->numsymstate - 1);
	    tblndx++, symstate1++) {
		symstate2 = symstate1 + 1;
		sym1 = &symstate1->sym.data[symstate1->ndx];
		sym2 = &symstate2->sym.data[symstate2->ndx];

		switch (cmd) {
		case SYM_CMD_T_DUMP:
			/* sym:dump should always show everything */
			return (0);

		case SYM_CMD_T_ST_BIND:
			if (ELF_ST_BIND(sym1->st_info) !=
			    ELF_ST_BIND(sym2->st_info))
				return (0);
			break;

		case SYM_CMD_T_ST_INFO:
			if (sym1->st_info !=  sym2->st_info)
				return (0);
			break;

		case SYM_CMD_T_ST_NAME:
			/*
			 * In simple output mode, we show the string. In
			 * numeric mode, we show the string table offset.
			 */
			if (outstyle == ELFEDIT_OUTSTYLE_SIMPLE) {
				const char *n1, *n2;

				symstate_add_str(argstate, symstate1);
				symstate_add_str(argstate, symstate2);
				n1 = elfedit_offset_to_str(symstate1->str.sec,
				    sym1->st_name, ELFEDIT_MSG_DEBUG, 0);
				n2 = elfedit_offset_to_str(symstate2->str.sec,
				    sym2->st_name, ELFEDIT_MSG_DEBUG, 0);
				if (strcmp(n1, n2) != 0)
					return (0);
			} else {
				if (sym1->st_name !=  sym2->st_name)
					return (0);
			}
			break;

		case SYM_CMD_T_ST_OTHER:
			if (sym1->st_other !=  sym2->st_other)
				return (0);
			break;

		case SYM_CMD_T_ST_SHNDX:
			{
				Word	ndx1, ndx2;

				ndx1 = sym1->st_shndx;
				if ((ndx1 == SHN_XINDEX) &&
				    (symstate1->xshndx.shndx != SHN_UNDEF)) {
					symstate_add_xshndx(argstate,
					    symstate1);
					ndx1 = symstate1->xshndx.
					    data[symstate1->ndx];
				}
				ndx2 = sym2->st_shndx;
				if ((ndx2 == SHN_XINDEX) &&
				    (symstate2->xshndx.shndx != SHN_UNDEF)) {
					symstate_add_xshndx(argstate,
					    symstate2);
					ndx2 = symstate2->xshndx.
					    data[symstate2->ndx];
				}
				if (ndx1 !=  ndx2)
					return (0);
			}
			break;

		case SYM_CMD_T_ST_SIZE:
			if (sym1->st_size !=  sym2->st_size)
				return (0);
			break;

		case SYM_CMD_T_ST_TYPE:
			if (ELF_ST_TYPE(sym1->st_info) !=
			    ELF_ST_TYPE(sym2->st_info))
				return (0);
			break;

		case SYM_CMD_T_ST_VALUE:
			if (sym1->st_value !=  sym2->st_value)
				return (0);
			break;

		case SYM_CMD_T_ST_VISIBILITY:
			if (ELF_ST_VISIBILITY(sym1->st_info) !=
			    ELF_ST_VISIBILITY(sym2->st_info))
				return (0);
			break;
		}
	}

	/* If we got here, there are no differences (or maybe only 1 table */
	return (1);
}


/*
 * Called by print_sym() to display values for a single symbol table.
 *
 * entry:
 *	autoprint - If True, output is only produced if the elfedit
 *		autoprint flag is set. If False, output is always produced.
 *	cmd - SYM_CMD_T_* value giving identify of caller
 *	argstate - Overall state block
 *	symstate - State block for current symbol table.
 *	ndx - Index of first symbol to display
 *	cnt - Number of symbols to display
 */
static void
print_symstate(SYM_CMD_T cmd, ARGSTATE *argstate, SYMSTATE *symstate,
    elfedit_outstyle_t outstyle, Word ndx, Word cnt)
{
	Word	value;
	Sym	*sym;

	/*
	 * If doing default output, use elfdump style where we
	 * show all symbol attributes. In this case, the command
	 * that called us doesn't matter
	 */
	if (outstyle == ELFEDIT_OUTSTYLE_DEFAULT) {
		dump_symtab(argstate, symstate, ndx, cnt);
		return;
	}

	sym = symstate->sym.data;

	switch (cmd) {
	case SYM_CMD_T_ST_BIND:
		{
			Conv_inv_buf_t inv_buf;

			for (sym += ndx; cnt--; sym++) {
				value = ELF_ST_BIND(sym->st_info);
				if (outstyle == ELFEDIT_OUTSTYLE_SIMPLE) {
					elfedit_printf(MSG_ORIG(MSG_FMT_STRNL),
					    conv_sym_info_bind(value,
					    CONV_FMT_ALT_CF, &inv_buf));
				} else {
					elfedit_printf(
					    MSG_ORIG(MSG_FMT_WORDVALNL),
					    EC_WORD(value));
				}
			}
		}
		return;

	case SYM_CMD_T_ST_INFO:
		for (sym += ndx; cnt-- > 0; sym++)
			elfedit_printf(MSG_ORIG(MSG_FMT_WORDVALNL),
			    EC_WORD(sym->st_info));
		return;

	case SYM_CMD_T_ST_NAME:
		/*
		 * In simple output mode, we show the string. In numeric
		 * mode, we show the string table offset.
		 */
		if (outstyle == ELFEDIT_OUTSTYLE_SIMPLE) {
			symstate_add_str(argstate, symstate);
			for (sym += ndx; cnt--; sym++) {
				elfedit_printf(MSG_ORIG(MSG_FMT_STRNL),
				    elfedit_offset_to_str(symstate->str.sec,
				    sym->st_name, ELFEDIT_MSG_ERR, 0));
			}
		} else {
			for (; cnt--; sym++)
				elfedit_printf(MSG_ORIG(MSG_FMT_WORDVALNL),
				    EC_WORD(sym->st_name));
		}
		return;

	case SYM_CMD_T_ST_OTHER:
		for (sym += ndx; cnt-- > 0; sym++)
			elfedit_printf(MSG_ORIG(MSG_FMT_WORDVALNL),
			    EC_WORD(sym->st_other));
		return;

	case SYM_CMD_T_ST_SHNDX:
		/* If there is an extended index section, fetch it */
		if (symstate->xshndx.shndx != SHN_UNDEF)
			symstate_add_xshndx(argstate, symstate);

		for (; cnt--; ndx++) {
			value = sym[ndx].st_shndx;
			if ((value == SHN_XINDEX) &&
			    (symstate->xshndx.sec != NULL))
				value = symstate->xshndx.data[ndx];

			if (outstyle == ELFEDIT_OUTSTYLE_SIMPLE) {
				elfedit_printf(MSG_ORIG(MSG_FMT_STRNL),
				    elfedit_shndx_to_name(argstate->obj_state,
				    value));
			} else {
				elfedit_printf(MSG_ORIG(MSG_FMT_WORDVALNL),
				    EC_WORD(value));
			}
		}
		return;

	case SYM_CMD_T_ST_SIZE:
		/*
		 * machine word width integers displayed in fixed width
		 * 0-filled hex format.
		 */
		for (sym += ndx; cnt--; sym++)
			elfedit_printf(MSG_ORIG(MSG_FMT_XWORDVALNL),
			    sym->st_size);
		return;

	case SYM_CMD_T_ST_TYPE:
		{
			Half mach = argstate->obj_state->os_ehdr->e_machine;
			Conv_inv_buf_t inv_buf;

			for (sym += ndx; cnt--; sym++) {
				value = ELF_ST_TYPE(sym->st_info);
				if (outstyle == ELFEDIT_OUTSTYLE_SIMPLE) {
					elfedit_printf(MSG_ORIG(MSG_FMT_STRNL),
					    conv_sym_info_type(mach, value,
					    CONV_FMT_ALT_CF, &inv_buf));
				} else {
					elfedit_printf(
					    MSG_ORIG(MSG_FMT_WORDVALNL),
					    EC_WORD(value));
				}
			}
		}
		return;

	case SYM_CMD_T_ST_VALUE:
		/*
		 * machine word width integers displayed in fixed width
		 * 0-filled hex format.
		 */
		for (sym += ndx; cnt--; sym++)
			elfedit_printf(MSG_ORIG(MSG_FMT_XWORDVALNL),
			    sym->st_value);
		return;

	case SYM_CMD_T_ST_VISIBILITY:
		{
			Conv_inv_buf_t inv_buf;

			for (sym += ndx; cnt--; sym++) {
				value = ELF_ST_VISIBILITY(sym->st_other);
				if (outstyle == ELFEDIT_OUTSTYLE_SIMPLE) {
					elfedit_printf(MSG_ORIG(MSG_FMT_STRNL),
					    conv_sym_other_vis(value,
					    CONV_FMT_ALT_CF, &inv_buf));
				} else {
					elfedit_printf(
					    MSG_ORIG(MSG_FMT_WORDVALNL),
					    EC_WORD(value));
				}
			}
		}
		return;

	}
}


/*
 * Print symbol values, taking the calling command, and output style
 * into account.
 *
 * entry:
 *	autoprint - If True, output is only produced if the elfedit
 *		autoprint flag is set. If False, output is always produced.
 *	cmd - SYM_CMD_T_* value giving identify of caller
 *	argstate - Overall state block
 *	symstate - State block for current symbol table.
 *	ndx - Index of first symbol to display
 *	cnt - Number of symbols to display
 */
static void
print_sym(SYM_CMD_T cmd, int autoprint, ARGSTATE *argstate)
{
	Word			ndx, tblndx;
	Word			cnt;
	elfedit_outstyle_t	outstyle;
	SYMSTATE		*symstate;
	int			only_one;

	if ((autoprint && ((elfedit_flags() & ELFEDIT_F_AUTOPRINT) == 0)))
		return;

	/*
	 * Pick an output style. sym:dump is required to use the default
	 * style. The other commands use the current output style.
	 */
	outstyle = (cmd == SYM_CMD_T_DUMP) ?
	    ELFEDIT_OUTSTYLE_DEFAULT : elfedit_outstyle();

	/*
	 * This is a nicity: Force any needed auxiliary sections to be
	 * fetched here before any output is produced. This will put all
	 * of the debug messages right at the top in a single cluster.
	 */
	symstate = argstate->symstate;
	for (tblndx = 0; tblndx < argstate->numsymstate; tblndx++, symstate++) {
		if (outstyle == ELFEDIT_OUTSTYLE_DEFAULT) {
			symstate_add_str(argstate, symstate);
			if (symstate->versym.shndx != SHN_UNDEF)
				symstate_add_versym(argstate, symstate);
			if (symstate->xshndx.shndx != SHN_UNDEF)
				symstate_add_xshndx(argstate, symstate);
			continue;
		}

		if (outstyle == ELFEDIT_OUTSTYLE_SIMPLE) {
			switch (cmd) {
			case SYM_CMD_T_ST_NAME:
				symstate_add_str(argstate, symstate);
				break;

			case SYM_CMD_T_ST_SHNDX:
				if (symstate->xshndx.shndx != SHN_UNDEF)
					symstate_add_xshndx(argstate, symstate);
				break;
			}
		}
	}

	/*
	 * If there is more than one table, we are displaying a single
	 * item, we are not using the default "elfdump" style, and all
	 * the symbols have the same value for the thing we intend to
	 * display, then we only want to display it once.
	 */
	only_one = (argstate->numsymstate > 1) && (argstate->argc > 0) &&
	    (outstyle != ELFEDIT_OUTSTYLE_DEFAULT) &&
	    all_same(cmd, argstate, outstyle);

	/* Run through the tables and display from each one */
	symstate = argstate->symstate;
	for (tblndx = 0; tblndx < argstate->numsymstate; tblndx++, symstate++) {
		if (argstate->argc == 0) {
			ndx = 0;
			cnt = symstate->sym.n;
		} else {
			ndx = symstate->ndx;
			cnt = 1;
		}

		if ((tblndx > 0) && ((argstate->argc == 0) ||
		    (outstyle == ELFEDIT_OUTSTYLE_DEFAULT)))
			elfedit_printf(MSG_ORIG(MSG_STR_NL));

		print_symstate(cmd, argstate, symstate, outstyle, ndx, cnt);
		if (only_one)
			break;
	}
}


/*
 * The cmd_body_set_st_XXX() functions are for use by cmd_body().
 * They handle the case where the second plain argument is
 * a value to be stored in the symbol.
 *
 * entry:
 *	argstate - Overall state block
 *	symstate - State block for current symbol table.
 */
static elfedit_cmdret_t
cmd_body_set_st_bind(ARGSTATE *argstate, SYMSTATE *symstate)
{
	elfedit_cmdret_t	ret = ELFEDIT_CMDRET_NONE;
	Sym			*sym = &symstate->sym.data[symstate->ndx];
	Word			gbl_ndx;
	uchar_t			bind, type, old_bind;
	Word			symndx;
	Conv_inv_buf_t		inv_buf1, inv_buf2;

	/*
	 * Use the ELF_ST_BIND() macro to access the defined bits
	 * of the st_info field related to symbol binding.
	 * Accepts STB_ symbolic names as well as integers.
	 */
	bind = elfedit_atoconst_range(argstate->argv[1],
	    MSG_INTL(MSG_ARG_SYMBIND), 0, 15, ELFEDIT_CONST_STB);
	old_bind = ELF_ST_BIND(sym->st_info);
	type = ELF_ST_TYPE(sym->st_info);

	if (old_bind == bind) {
		elfedit_msg(ELFEDIT_MSG_DEBUG, MSG_INTL(MSG_DEBUG_S_OK),
		    symstate->sym.sec->sec_shndx, symstate->sym.sec->sec_name,
		    EC_WORD(symstate->ndx), MSG_ORIG(MSG_CMD_ST_BIND),
		    conv_sym_info_bind(bind, CONV_FMT_ALT_CF, &inv_buf1));
	} else {
		/*
		 * The sh_info field of the symbol table section header
		 * gives the index of the first non-local symbol in
		 * the table. Issue warnings if the binding we set
		 * contradicts this.
		 */
		gbl_ndx = symstate->sym.sec->sec_shdr->sh_info;
		symndx = symstate->sym.sec->sec_shndx;
		if ((bind == STB_LOCAL) && (symstate->ndx >= gbl_ndx))
			elfedit_msg(ELFEDIT_MSG_DEBUG,
			    MSG_INTL(MSG_DEBUG_LBINDGSYM),
			    EC_WORD(symndx), symstate->sym.sec->sec_name,
			    symstate->ndx, EC_WORD(symndx), gbl_ndx);
		if ((bind != STB_LOCAL) && (symstate->ndx < gbl_ndx))
			elfedit_msg(ELFEDIT_MSG_DEBUG,
			    MSG_INTL(MSG_DEBUG_GBINDLSYM),
			    EC_WORD(symndx), symstate->sym.sec->sec_name,
			    symstate->ndx, EC_WORD(symndx), gbl_ndx);

		elfedit_msg(ELFEDIT_MSG_DEBUG, MSG_INTL(MSG_DEBUG_S_CHG),
		    symstate->sym.sec->sec_shndx, symstate->sym.sec->sec_name,
		    EC_WORD(symstate->ndx), MSG_ORIG(MSG_CMD_ST_BIND),
		    conv_sym_info_bind(old_bind, CONV_FMT_ALT_CF,
		    &inv_buf1),
		    conv_sym_info_bind(bind, CONV_FMT_ALT_CF, &inv_buf2));
		ret = ELFEDIT_CMDRET_MOD;
		sym->st_info = ELF_ST_INFO(bind, type);
	}

	return (ret);
}

static elfedit_cmdret_t
cmd_body_set_st_name(ARGSTATE *argstate, SYMSTATE *symstate)
{
	elfedit_cmdret_t	ret = ELFEDIT_CMDRET_NONE;
	Sym			*sym = &symstate->sym.data[symstate->ndx];
	Word	str_offset;

	/*
	 * If -n was specified, this is an offset into the string
	 * table. Otherwise it is a string we need to turn into
	 * an offset
	 */
	symstate_add_str(argstate, symstate);
	if (argstate->optmask & SYM_OPT_F_NAMOFFSET) {
		str_offset = elfedit_atoui(argstate->argv[1], NULL);
		/* Warn if the offset is out of range */
		(void) elfedit_offset_to_str(symstate->str.sec,
		    str_offset, ELFEDIT_MSG_DEBUG, 1);
	} else {
		str_offset = elfedit_strtab_insert(argstate->obj_state,
		    symstate->str.sec, NULL, argstate->argv[1]);
	}

	if (sym->st_name == str_offset) {
		elfedit_msg(ELFEDIT_MSG_DEBUG, MSG_INTL(MSG_DEBUG_D_OK),
		    symstate->sym.sec->sec_shndx, symstate->sym.sec->sec_name,
		    EC_WORD(symstate->ndx), MSG_ORIG(MSG_CMD_ST_NAME),
		    EC_WORD(sym->st_name));
	} else {
		/*
		 * Warn the user: Changing the name of a symbol in the dynsym
		 * will break the hash table in this object.
		 */
		if (symstate->sym.sec->sec_shdr->sh_type == SHT_DYNSYM)
			elfedit_msg(ELFEDIT_MSG_DEBUG,
			    MSG_INTL(MSG_DEBUG_DYNSYMNAMCHG),
			    EC_WORD(symstate->sym.sec->sec_shndx),
			    symstate->sym.sec->sec_name,
			    EC_WORD(symstate->ndx));

		elfedit_msg(ELFEDIT_MSG_DEBUG, MSG_INTL(MSG_DEBUG_D_CHG),
		    symstate->sym.sec->sec_shndx, symstate->sym.sec->sec_name,
		    EC_WORD(symstate->ndx), MSG_ORIG(MSG_CMD_ST_NAME),
		    EC_WORD(sym->st_name),
		    EC_WORD(str_offset));
		ret = ELFEDIT_CMDRET_MOD;
		sym->st_name = str_offset;
	}

	return (ret);
}

static elfedit_cmdret_t
cmd_body_set_st_shndx(ARGSTATE *argstate, SYMSTATE *symstate)
{
	elfedit_cmdret_t	ret = ELFEDIT_CMDRET_NONE;
	Sym			*sym = &symstate->sym.data[symstate->ndx];
	Word	shndx, st_shndx, xshndx;
	int	use_xshndx;
	int	shndx_chg, xshndx_chg;


	/*
	 * By default, the sec argument is a section name. If -secshndx was
	 * specified, it is a section index, and if -secshtyp is specified,
	 * it is a section type.
	 */
	if (argstate->optmask & SYM_OPT_F_SECSHNDX)
		shndx = elfedit_atoshndx(argstate->argv[1],
		    argstate->obj_state->os_shnum);
	else if (argstate->optmask & SYM_OPT_F_SECSHTYP)
		shndx = elfedit_type_to_shndx(argstate->obj_state,
		    elfedit_atoconst(argstate->argv[1], ELFEDIT_CONST_SHT));
	else
		shndx = elfedit_name_to_shndx(argstate->obj_state,
		    argstate->argv[1]);

	/*
	 * We want to use an extended index section if the index is too
	 * large to be represented otherwise, or if the caller specified
	 * the -e option to make us do it anyway. However, we cannot
	 * do this if the index is in the special reserved range between
	 * SHN_LORESERVE and SHN_HIRESERVE.
	 */
	use_xshndx = (shndx > SHN_HIRESERVE) ||
	    ((shndx < SHN_LORESERVE) &&
	    (argstate->optmask & SYM_OPT_F_XSHINDEX));

	/*
	 * There are two cases where we have to touch the extended
	 * index section:
	 *
	 *	1) We have determined that we need to, as determined above.
	 *	2) We do not require it, but the file has an extended
	 *		index section, in which case we should set the slot
	 *		in that extended section to SHN_UNDEF (0).
	 *
	 * Fetch the extended section as required, and determine the values
	 * for st_shndx and the extended section slot.
	 */
	if (use_xshndx) {
		/* We must have an extended index section, or error out */
		symstate_add_xshndx(argstate, symstate);

		/* Set symbol to SHN_XINDEX, put index in the extended sec. */
		st_shndx = SHN_XINDEX;
		xshndx = shndx;
	} else {
		st_shndx = shndx;
		xshndx = SHN_UNDEF;
		if (symstate->xshndx.shndx != SHN_UNDEF)
			use_xshndx = 1;
	}
	if (use_xshndx)
		symstate_add_xshndx(argstate, symstate);
	shndx_chg = (sym->st_shndx != st_shndx);
	xshndx_chg = use_xshndx &&
	    (symstate->xshndx.data[symstate->ndx] != xshndx);


	/* If anything is going to change, issue appropiate warnings */
	if (shndx_chg || xshndx_chg) {
		/*
		 * Setting the first symbol to anything other than SHN_UNDEF
		 * produces a bad ELF file.
		 */
		if ((symstate->ndx == 0) && (shndx != SHN_UNDEF))
			elfedit_msg(ELFEDIT_MSG_DEBUG,
			    MSG_INTL(MSG_DEBUG_SHNDX_UNDEF0));

		/*
		 * Setting SHN_XINDEX directly, instead of providing
		 * an extended index and letting us decide to use
		 * SHN_XINDEX to implement it, is probably a mistake.
		 * Issue a warning, but go ahead and follow the directions
		 * we've been given.
		 */
		if (shndx == SHN_XINDEX)
			elfedit_msg(ELFEDIT_MSG_DEBUG,
			    MSG_INTL(MSG_DEBUG_SHNDX_XINDEX));

		/*
		 * If the section index can fit in the symbol, but
		 * -e is being used to force it into the extended
		 * index section, issue a warning.
		 */
		if (use_xshndx && (shndx < SHN_LORESERVE) &&
		    (st_shndx == SHN_XINDEX))
			elfedit_msg(ELFEDIT_MSG_DEBUG,
			    MSG_INTL(MSG_DEBUG_SHNDX_EFORCE),
			    EC_WORD(symstate->sym.sec->sec_shndx),
			    symstate->sym.sec->sec_name, EC_WORD(symstate->ndx),
			    EC_WORD(shndx));
	}

	if (shndx_chg) {
		elfedit_msg(ELFEDIT_MSG_DEBUG, MSG_INTL(MSG_DEBUG_S_CHG),
		    symstate->sym.sec->sec_shndx, symstate->sym.sec->sec_name,
		    EC_WORD(symstate->ndx), MSG_ORIG(MSG_CMD_ST_SHNDX),
		    elfedit_shndx_to_name(argstate->obj_state,
		    sym->st_shndx),
		    elfedit_shndx_to_name(argstate->obj_state, st_shndx));
		ret = ELFEDIT_CMDRET_MOD;
		sym->st_shndx = st_shndx;
	} else {
		elfedit_msg(ELFEDIT_MSG_DEBUG, MSG_INTL(MSG_DEBUG_S_OK),
		    symstate->sym.sec->sec_shndx, symstate->sym.sec->sec_name,
		    EC_WORD(symstate->ndx), MSG_ORIG(MSG_CMD_ST_SHNDX),
		    elfedit_shndx_to_name(argstate->obj_state, st_shndx));
	}

	if (use_xshndx) {
		if (xshndx_chg) {
			elfedit_msg(ELFEDIT_MSG_DEBUG,
			    MSG_INTL(MSG_DEBUG_EXT_S_CHG),
			    symstate->xshndx.sec->sec_shndx,
			    symstate->xshndx.sec->sec_name,
			    EC_WORD(symstate->ndx),
			    elfedit_shndx_to_name(argstate->obj_state,
			    symstate->xshndx.data[symstate->ndx]),
			    elfedit_shndx_to_name(argstate->obj_state, xshndx));
			ret = ELFEDIT_CMDRET_MOD;
			symstate->xshndx.data[symstate->ndx] = xshndx;
			elfedit_modified_data(symstate->xshndx.sec);
		} else {
			elfedit_msg(ELFEDIT_MSG_DEBUG,
			    MSG_INTL(MSG_DEBUG_EXT_S_OK),
			    symstate->xshndx.sec->sec_shndx,
			    symstate->xshndx.sec->sec_name,
			    EC_WORD(symstate->ndx),
			    elfedit_shndx_to_name(argstate->obj_state, xshndx));
		}
	}

	return (ret);
}

static elfedit_cmdret_t
cmd_body_set_st_type(ARGSTATE *argstate, SYMSTATE *symstate)
{
	elfedit_cmdret_t	ret = ELFEDIT_CMDRET_NONE;
	Conv_inv_buf_t	inv_buf1, inv_buf2;
	Half		mach = argstate->obj_state->os_ehdr->e_machine;
	Sym		*sym = &symstate->sym.data[symstate->ndx];
	uchar_t		bind, type, old_type;

	/*
	 * Use the ELF_ST_TYPE() macro to access the defined bits
	 * of the st_info field related to symbol type.
	 * Accepts STT_ symbolic names as well as integers.
	 */
	bind = ELF_ST_BIND(sym->st_info);
	type = elfedit_atoconst_range(argstate->argv[1],
	    MSG_INTL(MSG_ARG_SYMBIND), 0, 15, ELFEDIT_CONST_STT);
	old_type = ELF_ST_TYPE(sym->st_info);

	if (old_type == type) {
		elfedit_msg(ELFEDIT_MSG_DEBUG, MSG_INTL(MSG_DEBUG_S_OK),
		    symstate->sym.sec->sec_shndx, symstate->sym.sec->sec_name,
		    EC_WORD(symstate->ndx), MSG_ORIG(MSG_CMD_ST_TYPE),
		    conv_sym_info_type(mach, type, CONV_FMT_ALT_CF,
		    &inv_buf1));
	} else {
		elfedit_msg(ELFEDIT_MSG_DEBUG, MSG_INTL(MSG_DEBUG_S_CHG),
		    symstate->sym.sec->sec_shndx, symstate->sym.sec->sec_name,
		    EC_WORD(symstate->ndx), MSG_ORIG(MSG_CMD_ST_TYPE),
		    conv_sym_info_type(mach, old_type, CONV_FMT_ALT_CF,
		    &inv_buf1),
		    conv_sym_info_type(mach, type, CONV_FMT_ALT_CF,
		    &inv_buf2));
		ret = ELFEDIT_CMDRET_MOD;
		sym->st_info = ELF_ST_INFO(bind, type);
	}

	return (ret);
}

static elfedit_cmdret_t
cmd_body_set_st_visibility(ARGSTATE *argstate, SYMSTATE *symstate)
{
	elfedit_cmdret_t	ret = ELFEDIT_CMDRET_NONE;
	Conv_inv_buf_t	inv_buf1, inv_buf2;
	Sym		*sym = &symstate->sym.data[symstate->ndx];
	uchar_t		st_other = sym->st_other;
	uchar_t		vis, old_vis;

	/*
	 * Use the ELF_ST_VISIBILITY() macro to access the
	 * defined bits of the st_other field related to symbol
	 * visibility. Accepts STV_ symbolic names as well as integers.
	 */
	vis = elfedit_atoconst_range(argstate->argv[1],
	    MSG_INTL(MSG_ARG_SYMVIS), 0, STV_ELIMINATE, ELFEDIT_CONST_STV);
	old_vis = st_other & MSK_SYM_VISIBILITY;

	if (old_vis == vis) {
		elfedit_msg(ELFEDIT_MSG_DEBUG, MSG_INTL(MSG_DEBUG_S_OK),
		    symstate->sym.sec->sec_shndx, symstate->sym.sec->sec_name,
		    EC_WORD(symstate->ndx), MSG_ORIG(MSG_CMD_ST_VISIBILITY),
		    conv_sym_other_vis(old_vis, CONV_FMT_ALT_CF,
		    &inv_buf1));
	} else {
		elfedit_msg(ELFEDIT_MSG_DEBUG, MSG_INTL(MSG_DEBUG_S_CHG),
		    symstate->sym.sec->sec_shndx, symstate->sym.sec->sec_name,
		    EC_WORD(symstate->ndx), MSG_ORIG(MSG_CMD_ST_VISIBILITY),
		    conv_sym_other_vis(old_vis, CONV_FMT_ALT_CF,
		    &inv_buf1),
		    conv_sym_other_vis(vis, CONV_FMT_ALT_CF, &inv_buf2));
		ret = ELFEDIT_CMDRET_MOD;
		st_other = (st_other & ~MSK_SYM_VISIBILITY) |
		    ELF_ST_VISIBILITY(vis);
		sym->st_other = st_other;
	}

	return (ret);
}


/*
 * Standard argument processing for sym module
 *
 * entry
 *	obj_state, argc, argv - Standard command arguments
 *	optmask - Mask of allowed optional arguments.
 *	symstate - State block for current symbol table.
 *	argstate - Address of ARGSTATE block to be initialized
 *
 * exit:
 *	On success, *argstate is initialized. On error,
 *	an error is issued and this routine does not return.
 *
 * note:
 *	Only the basic symbol table is initially referenced by
 *	argstate. Use the argstate_add_XXX() routines below to
 *	access any auxiliary sections needed.
 */
static ARGSTATE *
process_args(elfedit_obj_state_t *obj_state, int argc, const char *argv[],
    SYM_CMD_T cmd)
{
	/*
	 * We reuse this same argstate, resizing it to the required
	 * number of symbol tables on the first call, and as necessary.
	 */
	static ARGSTATE *argstate;
	static int argstate_size = 0;

	elfedit_getopt_state_t	getopt_state;
	elfedit_getopt_ret_t	*getopt_ret;
	elfedit_symtab_t	*symtab;
	int		explicit = 0;
	int		got_sym = 0;
	Word		index;
	Word		tblndx;
	size_t		size;
	SYMSTATE	*symstate;

	/* If there are no symbol tables, we can't do a thing */
	if (obj_state->os_symtabnum == 0)
		elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_NOSYMTAB));

	/* Calulate required size of argstate and realloc as necessary */
	size = sizeof (ARGSTATE) +
	    ((obj_state->os_symtabnum - 1) * sizeof (SYMSTATE));
	if (argstate_size != size) {
		argstate = elfedit_realloc(MSG_INTL(MSG_ALLOC_ARGSTATE),
		    argstate, size);
		argstate_size = size;
	}
	bzero(argstate, argstate_size);
	argstate->obj_state = obj_state;

	elfedit_getopt_init(&getopt_state, &argc, &argv);
	while ((getopt_ret = elfedit_getopt(&getopt_state)) != NULL) {
		argstate->optmask |= getopt_ret->gor_idmask;
		switch (getopt_ret->gor_idmask) {
		case SYM_OPT_F_SHNAME:		/* -shnam name */
			index = elfedit_name_to_shndx(obj_state,
			    getopt_ret->gor_value);
			explicit = 1;
			break;

		case SYM_OPT_F_SHNDX:		/* -shndx index */
			index = elfedit_atoui_range(getopt_ret->gor_value,
			    MSG_INTL(MSG_ARG_SECNDX), 1,
			    obj_state->os_shnum - 1, NULL);
			explicit = 1;
			break;

		case SYM_OPT_F_SHTYP:		/* -shtyp type */
			index = elfedit_type_to_shndx(obj_state,
			    elfedit_atoconst(getopt_ret->gor_value,
			    ELFEDIT_CONST_SHT));
			explicit = 1;
			break;
		}
	}

	/*
	 * Usage error if there are too many plain arguments. sym:dump accepts
	 * a single argument, while the others accept 2.
	 */
	if (((cmd == SYM_CMD_T_DUMP) && (argc > 1)) || (argc > 2))
		elfedit_command_usage();

	/*
	 * If the -symndx option was specified, the sym arg is an index
	 * into the symbol table. In this case, the symbol table must be
	 * explicitly specified (-shnam, -shndx, or -shtype).
	 */
	if ((argstate->optmask & SYM_OPT_F_SYMNDX) && !explicit)
		elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_NEEDEXPSYMTAB));

	/*
	 * If a section was explicitly specified, it must be a symbol table.
	 */
	if (explicit)
		(void) elfedit_sec_issymtab(obj_state,
		    &obj_state->os_secarr[index], 1, NULL);

	/* If there may be an arbitrary amount of output, use a pager */
	if (argc == 0)
		elfedit_pager_init();

	/* Return the updated values of argc/argv */
	argstate->argc = argc;
	argstate->argv = argv;

	/*
	 * Decide which symbol table(s) to use. Set up the symstate
	 * array to contain them:
	 *	- If a symbol table was explicitly specified, we use
	 *		it, and only it.
	 *	- If no symbol table is explicitly specified, and the symbol
	 *		is given by name, we use all symbol tables that
	 *		contain a symbol with that name, throwing an error
	 *		if there isn't at least 1 such table.
	 *	- If no symbol table is specified, and no symbol is specified,
	 *		we use all the tables.
	 */
	symtab = obj_state->os_symtab;
	symstate = argstate->symstate;
	for (tblndx = 0; tblndx < obj_state->os_symtabnum;
	    tblndx++, symtab++) {
		/*
		 * If an explicit table is specified, only that table is
		 * considered.
		 *
		 * If no explicit table is specified, verify that table
		 * is considered to be a symbol table by the current osabi,
		 * and quietly skip it if not.
		 */
		if (explicit) {
			if (symtab->symt_shndx != index)
				continue;
		} else if (elfedit_sec_issymtab(obj_state,
		    &obj_state->os_secarr[symtab->symt_shndx], 0, NULL) == 0) {
			continue;
		}

		symstate->sym.sec = elfedit_sec_getsymtab(obj_state, 1,
		    symtab->symt_shndx, NULL, &symstate->sym.data,
		    &symstate->sym.n, &symtab);
		symstate->versym.shndx = symtab->symt_versym;
		symstate->xshndx.shndx = symtab->symt_xshndx;
		if (argc > 0) {
			if (argstate->optmask & SYM_OPT_F_SYMNDX) {
				symstate->ndx = elfedit_atoui_range(
				    argstate->argv[0], MSG_INTL(MSG_ARG_SYM), 0,
				    symstate->sym.n - 1, NULL);
			} else {
				/*
				 * arg is a symbol name. Use the index of
				 * the first symbol that matches
				 */

				/*
				 * We will use debug messages for failure up
				 * until we run out of symbol tables. If we
				 * don't find a table with the desired symbol
				 * before the last table, we switch to error
				 * messages. Hence, we will jump with an error
				 * if no table will work.
				 */
				int err_type = (!got_sym &&
				    ((tblndx + 1) == obj_state->os_symtabnum)) ?
				    ELFEDIT_MSG_ERR : ELFEDIT_MSG_DEBUG;

				symstate_add_str(argstate, symstate);

				/*
				 * If the symbol table doesn't have this
				 * symbol, then forget it.
				 */
				if (elfedit_name_to_symndx(symstate->sym.sec,
				    symstate->str.sec, argstate->argv[0],
				    err_type, &symstate->ndx) == 0) {
					bzero(symstate, sizeof (*symstate));
					continue;
				}
			}
		}
		argstate->numsymstate++;
		symstate++;
		/*
		 * If the symbol table was given explicitly, and
		 * we've just taken it, then there is no reason to
		 * continue searching.
		 */
		if (explicit)
			break;
	}

	return (argstate);
}



/*
 * Called by cmd_body() to handle the value change for a single
 * symbol table.
 *
 * entry:
 *	cmd - One of the SYM_CMD_T_* constants listed above, specifying
 *		which command to implement.
 *	argstate - Overall state block
 *	symstate - State block for current symbol table.
 */
static elfedit_cmdret_t
symstate_cmd_body(SYM_CMD_T cmd, ARGSTATE *argstate, SYMSTATE *symstate)
{
	elfedit_cmdret_t	ret = ELFEDIT_CMDRET_NONE;
	Sym			*sym = &symstate->sym.data[symstate->ndx];

	/* You're not supposed to change the value of symbol [0] */
	if (symstate->ndx == 0)
		elfedit_msg(ELFEDIT_MSG_DEBUG, MSG_INTL(MSG_DEBUG_CHGSYMELT0),
		    EC_WORD(symstate->sym.sec->sec_shndx),
		    symstate->sym.sec->sec_name, EC_WORD(symstate->ndx));

	/* The second value is an integer giving a new value */
	switch (cmd) {
		/*
		 * SYM_CMD_T_DUMP can't get here: It never has more than
		 * one argument, and is handled above.
		 */

	case SYM_CMD_T_ST_BIND:
		ret = cmd_body_set_st_bind(argstate, symstate);
		break;

	case SYM_CMD_T_ST_INFO:
		{
			/* Treat st_info as a raw integer field */
			uchar_t st_info =
			    elfedit_atoui(argstate->argv[1], NULL);

			if (sym->st_info == st_info) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_D_OK),
				    symstate->sym.sec->sec_shndx,
				    symstate->sym.sec->sec_name,
				    EC_WORD(symstate->ndx),
				    MSG_ORIG(MSG_CMD_ST_INFO),
				    EC_WORD(sym->st_info));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_D_CHG),
				    symstate->sym.sec->sec_shndx,
				    symstate->sym.sec->sec_name,
				    EC_WORD(symstate->ndx),
				    MSG_ORIG(MSG_CMD_ST_INFO),
				    EC_WORD(sym->st_info), EC_WORD(st_info));
				ret = ELFEDIT_CMDRET_MOD;
				sym->st_info = st_info;
			}
		}
	break;

	case SYM_CMD_T_ST_NAME:
		ret = cmd_body_set_st_name(argstate, symstate);
		break;

	case SYM_CMD_T_ST_OTHER:
		{
			/* Treat st_other as a raw integer field */
			uchar_t st_other =
			    elfedit_atoui(argstate->argv[1], NULL);

			if (sym->st_other == st_other) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_D_OK),
				    symstate->sym.sec->sec_shndx,
				    symstate->sym.sec->sec_name,
				    EC_WORD(symstate->ndx),
				    MSG_ORIG(MSG_CMD_ST_OTHER),
				    EC_WORD(sym->st_other));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_D_CHG),
				    symstate->sym.sec->sec_shndx,
				    symstate->sym.sec->sec_name,
				    EC_WORD(symstate->ndx),
				    MSG_ORIG(MSG_CMD_ST_OTHER),
				    EC_WORD(sym->st_other), EC_WORD(st_other));
				ret = ELFEDIT_CMDRET_MOD;
				sym->st_other = st_other;
			}
		}
		break;

	case SYM_CMD_T_ST_SHNDX:
		ret = cmd_body_set_st_shndx(argstate, symstate);
		break;

	case SYM_CMD_T_ST_SIZE:
		{
			Xword st_size = elfedit_atoui(argstate->argv[1], NULL);

			if (sym->st_size == st_size) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_LLX_OK),
				    symstate->sym.sec->sec_shndx,
				    symstate->sym.sec->sec_name,
				    EC_WORD(symstate->ndx),
				    MSG_ORIG(MSG_CMD_ST_SIZE),
				    EC_XWORD(sym->st_size));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_LLX_CHG),
				    symstate->sym.sec->sec_shndx,
				    symstate->sym.sec->sec_name,
				    EC_WORD(symstate->ndx),
				    MSG_ORIG(MSG_CMD_ST_SIZE),
				    EC_XWORD(sym->st_size), EC_XWORD(st_size));
				ret = ELFEDIT_CMDRET_MOD;
				sym->st_size = st_size;
			}
		}
		break;

	case SYM_CMD_T_ST_TYPE:
		ret = cmd_body_set_st_type(argstate, symstate);
		break;

	case SYM_CMD_T_ST_VALUE:
		{
			Addr st_value = elfedit_atoui(argstate->argv[1], NULL);

			if (sym->st_value == st_value) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_LLX_OK),
				    symstate->sym.sec->sec_shndx,
				    symstate->sym.sec->sec_name,
				    EC_WORD(symstate->ndx),
				    MSG_ORIG(MSG_CMD_ST_VALUE),
				    EC_ADDR(sym->st_value));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_LLX_CHG),
				    symstate->sym.sec->sec_shndx,
				    symstate->sym.sec->sec_name,
				    EC_WORD(symstate->ndx),
				    MSG_ORIG(MSG_CMD_ST_VALUE),
				    EC_ADDR(sym->st_value),
				    EC_ADDR(st_value));
				ret = ELFEDIT_CMDRET_MOD;
				ret = ELFEDIT_CMDRET_MOD;
				sym->st_value = st_value;
			}
		}
		break;

	case SYM_CMD_T_ST_VISIBILITY:
		ret = cmd_body_set_st_visibility(argstate, symstate);
		break;
	}

	/*
	 * If we modified the symbol table, tell libelf.
	 * Any other modified sections are the responsibility
	 * of the cmd_body_set_st_*() function that did it, but
	 * everyone modifies the table itself, so we handle that here.
	 */
	if (ret == ELFEDIT_CMDRET_MOD)
		elfedit_modified_data(symstate->sym.sec);

	return (ret);
}




/*
 * Common body for the sym: module commands. These commands
 * share a large amount of common behavior, so it is convenient
 * to centralize things and use the cmd argument to handle the
 * small differences.
 *
 * entry:
 *	cmd - One of the SYM_CMD_T_* constants listed above, specifying
 *		which command to implement.
 *	obj_state, argc, argv - Standard command arguments
 */
static elfedit_cmdret_t
cmd_body(SYM_CMD_T cmd, elfedit_obj_state_t *obj_state,
    int argc, const char *argv[])
{
	elfedit_cmdret_t	ret = ELFEDIT_CMDRET_NONE;
	ARGSTATE		*argstate;
	SYMSTATE		*symstate;
	Word			tblndx;

	argstate = process_args(obj_state, argc, argv, cmd);

	/*
	 * If there are not 2 arguments, then this is a display request.
	 * If no arguments are present, the full table (or tables) is
	 * dumped. If there is one argument, then the specified item is shown.
	 */
	if (argstate->argc < 2) {
		print_sym(cmd, 0, argstate);
		return (ELFEDIT_CMDRET_NONE);
	}

	/*
	 * When processing multiple symbol tables, it is important that
	 * any failure happen before anything is changed. Otherwise, you
	 * can end up in a situation where things are left in an inconsistent
	 * half done state. sym:st_name has that issue when the -name_offset
	 * option is used, because the string may be insertable into some
	 * (dynstr) string tables, but not all of them. So, do the tests
	 * up front, and refuse to continue if any string insertions would
	 * fail.
	 */
	if ((cmd == SYM_CMD_T_ST_NAME) && (argstate->numsymstate > 1) &&
	    ((argstate->optmask & SYM_OPT_F_NAMOFFSET) == 0)) {
		symstate = argstate->symstate;
		for (tblndx = 0; tblndx < argstate->numsymstate;
		    tblndx++, symstate++)
			elfedit_strtab_insert_test(obj_state, symstate->str.sec,
			    NULL, argstate->argv[1]);
	}


	/* Loop over the table(s) and make the specified value change */
	symstate = argstate->symstate;
	for (tblndx = 0; tblndx < argstate->numsymstate; tblndx++, symstate++)
		if (symstate_cmd_body(cmd, argstate, symstate) ==
		    ELFEDIT_CMDRET_MOD)
			ret = ELFEDIT_CMDRET_MOD;

	/* Do autoprint */
	print_sym(cmd, 1, argstate);

	return (ret);
}




/*
 * Command completion functions for the various commands
 */

/*
 * Handle filling in the values for -shnam, -shndx, and -shtyp options.
 */
/*ARGSUSED*/
static void
cpl_sh_opt(elfedit_obj_state_t *obj_state, void *cpldata, int argc,
    const char *argv[], int num_opt)
{
	enum { NAME, INDEX, TYPE }	op;
	elfedit_symtab_t		*symtab;
	Word	tblndx;

	if ((argc != num_opt) || (argc < 2))
		return;

	if (strcmp(argv[argc - 2], MSG_ORIG(MSG_STR_MINUS_SHNAM)) == 0) {
		op = NAME;
	} else if (strcmp(argv[argc - 2], MSG_ORIG(MSG_STR_MINUS_SHNDX)) == 0) {
		op = INDEX;

	} else if (strcmp(argv[argc - 2], MSG_ORIG(MSG_STR_MINUS_SHTYP)) == 0) {
		op = TYPE;
		if (obj_state == NULL)	 /* No object available */
			elfedit_cpl_atoconst(cpldata,
			    ELFEDIT_CONST_SHT_ALLSYMTAB);
	} else {
		return;
	}

	if (obj_state == NULL)	 /* No object available */
		return;

	/*
	 * Loop over the symbol tables and supply command completion
	 * for the items in the file.
	 */
	symtab = obj_state->os_symtab;
	for (tblndx = 0; tblndx < obj_state->os_symtabnum;
	    tblndx++, symtab++) {
		elfedit_section_t *sec =
		    &obj_state->os_secarr[symtab->symt_shndx];

		switch (op) {
		case NAME:
			elfedit_cpl_match(cpldata, sec->sec_name, 0);
			break;
		case INDEX:
			elfedit_cpl_ndx(cpldata, symtab->symt_shndx);
			break;
		case TYPE:
			{
				elfedit_atoui_sym_t *cpl_list;

				(void) elfedit_sec_issymtab(obj_state,
				    sec, 1, &cpl_list);
				elfedit_cpl_atoui(cpldata, cpl_list);
			}
			break;
		}
	}
}

/*ARGSUSED*/
static void
cpl_st_bind(elfedit_obj_state_t *obj_state, void *cpldata, int argc,
    const char *argv[], int num_opt)
{
	/* Handle -shXXX options */
	cpl_sh_opt(obj_state, cpldata, argc, argv, num_opt);

	/* The second argument can be an STB_ value */
	if (argc == (num_opt + 2))
		elfedit_cpl_atoconst(cpldata, ELFEDIT_CONST_STB);
}

/*ARGSUSED*/
static void
cpl_st_shndx(elfedit_obj_state_t *obj_state, void *cpldata, int argc,
    const char *argv[], int num_opt)
{
	elfedit_section_t *sec;
	enum { NAME, INDEX, TYPE } op;
	Word ndx;

	/* Handle -shXXX options */
	cpl_sh_opt(obj_state, cpldata, argc, argv, num_opt);

	/*
	 * The second argument can be a section name, a section
	 * index (-secshndx), or a section type (-secshtyp). We
	 * can do completions for each of these.
	 */
	if (argc != (num_opt + 2))
		return;

	op = NAME;
	for (ndx = 0; ndx < num_opt; ndx++) {
		if (strcmp(argv[ndx], MSG_ORIG(MSG_STR_MINUS_SECSHNDX)) == 0)
			op = INDEX;
		else if (strcmp(argv[ndx],
		    MSG_ORIG(MSG_STR_MINUS_SECSHTYP)) == 0)
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
cpl_st_type(elfedit_obj_state_t *obj_state, void *cpldata, int argc,
    const char *argv[], int num_opt)
{
	/* Handle -shXXX options */
	cpl_sh_opt(obj_state, cpldata, argc, argv, num_opt);

	/* The second argument can be an STT_ value */
	if (argc == (num_opt + 2))
		elfedit_cpl_atoconst(cpldata, ELFEDIT_CONST_STT);
}

/*ARGSUSED*/
static void
cpl_st_visibility(elfedit_obj_state_t *obj_state, void *cpldata, int argc,
    const char *argv[], int num_opt)
{
	/* Handle -shXXX options */
	cpl_sh_opt(obj_state, cpldata, argc, argv, num_opt);

	/* The second argument can be an STV_ value */
	if (argc == (num_opt + 2))
		elfedit_cpl_atoconst(cpldata, ELFEDIT_CONST_STV);
}



/*
 * Implementation functions for the commands
 */
static elfedit_cmdret_t
cmd_dump(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(SYM_CMD_T_DUMP, obj_state, argc, argv));
}


static elfedit_cmdret_t
cmd_st_bind(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(SYM_CMD_T_ST_BIND, obj_state, argc, argv));
}


static elfedit_cmdret_t
cmd_st_info(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(SYM_CMD_T_ST_INFO, obj_state, argc, argv));
}

static elfedit_cmdret_t
cmd_st_name(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(SYM_CMD_T_ST_NAME, obj_state, argc, argv));
}

static elfedit_cmdret_t
cmd_st_other(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(SYM_CMD_T_ST_OTHER, obj_state, argc, argv));
}

static elfedit_cmdret_t
cmd_st_shndx(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(SYM_CMD_T_ST_SHNDX, obj_state, argc, argv));
}

static elfedit_cmdret_t
cmd_st_size(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(SYM_CMD_T_ST_SIZE, obj_state, argc, argv));
}

static elfedit_cmdret_t
cmd_st_type(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(SYM_CMD_T_ST_TYPE, obj_state, argc, argv));
}

static elfedit_cmdret_t
cmd_st_value(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(SYM_CMD_T_ST_VALUE, obj_state, argc, argv));
}

static elfedit_cmdret_t
cmd_st_visibility(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(SYM_CMD_T_ST_VISIBILITY, obj_state, argc, argv));
}



/*ARGSUSED*/
elfedit_module_t *
elfedit_init(elfedit_module_version_t version)
{
	/* Multiple commands accept only the standard set of options */
	static elfedit_cmd_optarg_t opt_std[] = {
		{ MSG_ORIG(MSG_STR_MINUS_SHNAM),
		    /* MSG_INTL(MSG_OPTDESC_SHNAM) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_SHNAM), ELFEDIT_CMDOA_F_VALUE,
		    SYM_OPT_F_SHNAME, SYM_OPT_F_SHNDX | SYM_OPT_F_SHTYP },
		{ MSG_ORIG(MSG_STR_NAME), 0, 0 },
		{ MSG_ORIG(MSG_STR_MINUS_SHNDX),
		    /* MSG_INTL(MSG_OPTDESC_SHNDX) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_SHNDX), ELFEDIT_CMDOA_F_VALUE,
		    SYM_OPT_F_SHNDX, SYM_OPT_F_SHNAME | SYM_OPT_F_SHTYP },
		{ MSG_ORIG(MSG_STR_INDEX), 0, 0 },
		{ MSG_ORIG(MSG_STR_MINUS_SHTYP),
		    /* MSG_INTL(MSG_OPTDESC_SHTYP) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_SHTYP), ELFEDIT_CMDOA_F_VALUE,
		    SYM_OPT_F_SHTYP, SYM_OPT_F_SHNAME | SYM_OPT_F_SHNDX },
		{ MSG_ORIG(MSG_STR_TYPE), 0, 0 },
		{ MSG_ORIG(MSG_STR_MINUS_SYMNDX),
		    /* MSG_INTL(MSG_OPTDESC_SYMNDX) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_SYMNDX), 0, SYM_OPT_F_SYMNDX },
		{ ELFEDIT_STDOA_OPT_O, 0,
		    ELFEDIT_CMDOA_F_INHERIT, 0 },
		{ NULL }
	};

	/* sym:dump */
	static const char *name_dump[] = {
	    MSG_ORIG(MSG_CMD_DUMP),
	    MSG_ORIG(MSG_STR_EMPTY),	/* "" makes this the default command */
	    NULL
	};
	static elfedit_cmd_optarg_t opt_dump[] = {
		{ MSG_ORIG(MSG_STR_MINUS_SHNAM),
		    /* MSG_INTL(MSG_OPTDESC_SHNAM) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_SHNAM), ELFEDIT_CMDOA_F_VALUE,
		    SYM_OPT_F_SHNAME, SYM_OPT_F_SHNDX | SYM_OPT_F_SHTYP },
		{ MSG_ORIG(MSG_STR_NAME), 0, 0 },
		{ MSG_ORIG(MSG_STR_MINUS_SHNDX),
		    /* MSG_INTL(MSG_OPTDESC_SHNDX) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_SHNDX), ELFEDIT_CMDOA_F_VALUE,
		    SYM_OPT_F_SHNDX, SYM_OPT_F_SHNAME | SYM_OPT_F_SHTYP },
		{ MSG_ORIG(MSG_STR_INDEX), 0, 0 },
		{ MSG_ORIG(MSG_STR_MINUS_SHTYP),
		    /* MSG_INTL(MSG_OPTDESC_SHTYP) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_SHTYP), ELFEDIT_CMDOA_F_VALUE,
		    SYM_OPT_F_SHTYP, SYM_OPT_F_SHNAME | SYM_OPT_F_SHNDX },
		{ MSG_ORIG(MSG_STR_TYPE), 0, 0 },
		{ MSG_ORIG(MSG_STR_MINUS_SYMNDX),
		    /* MSG_INTL(MSG_OPTDESC_SYMNDX) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_SYMNDX), 0, SYM_OPT_F_SYMNDX },
		{ NULL }
	};
	static elfedit_cmd_optarg_t arg_dump[] = {
		{ MSG_ORIG(MSG_STR_SYM),
		    /* MSG_INTL(MSG_A1_SYM) */
		    ELFEDIT_I18NHDL(MSG_A1_SYM),
		    ELFEDIT_CMDOA_F_OPT },
		{ NULL }
	};

	/* sym:st_bind */
	static const char *name_st_bind[] = {
	    MSG_ORIG(MSG_CMD_ST_BIND), NULL };
	static elfedit_cmd_optarg_t arg_st_bind[] = {
		{ MSG_ORIG(MSG_STR_SYM),
		    /* MSG_INTL(MSG_A1_SYM) */
		    ELFEDIT_I18NHDL(MSG_A1_SYM),
		    ELFEDIT_CMDOA_F_OPT },
		{ MSG_ORIG(MSG_STR_VALUE),
		    /* MSG_INTL(MSG_A2_DESC_ST_BIND) */
		    ELFEDIT_I18NHDL(MSG_A2_DESC_ST_BIND),
		    ELFEDIT_CMDOA_F_OPT },
		{ NULL }
	};

	/* sym:st_info */
	static const char *name_st_info[] = {
	    MSG_ORIG(MSG_CMD_ST_INFO), NULL };
	static elfedit_cmd_optarg_t arg_st_info[] = {
		{ MSG_ORIG(MSG_STR_SYM),
		    /* MSG_INTL(MSG_A1_SYM) */
		    ELFEDIT_I18NHDL(MSG_A1_SYM),
		    ELFEDIT_CMDOA_F_OPT },
		{ MSG_ORIG(MSG_STR_VALUE),
		    /* MSG_INTL(MSG_A2_DESC_ST_INFO) */
		    ELFEDIT_I18NHDL(MSG_A2_DESC_ST_INFO),
		    ELFEDIT_CMDOA_F_OPT },
		{ NULL }
	};

	/* sym:st_name */
	static const char *name_st_name[] = {
	    MSG_ORIG(MSG_CMD_ST_NAME), NULL };
	static elfedit_cmd_optarg_t opt_st_name[] = {
		{ MSG_ORIG(MSG_STR_MINUS_SHNAM),
		    /* MSG_INTL(MSG_OPTDESC_SHNAM) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_SHNAM), ELFEDIT_CMDOA_F_VALUE,
		    SYM_OPT_F_SHNAME, SYM_OPT_F_SHNDX | SYM_OPT_F_SHTYP },
		{ MSG_ORIG(MSG_STR_NAME), 0, 0, 0 },
		{ MSG_ORIG(MSG_STR_MINUS_SHNDX),
		    /* MSG_INTL(MSG_OPTDESC_SHNDX) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_SHNDX), ELFEDIT_CMDOA_F_VALUE,
		    SYM_OPT_F_SHNDX, SYM_OPT_F_SHNAME | SYM_OPT_F_SHTYP },
		{ MSG_ORIG(MSG_STR_INDEX), 0, 0, 0 },
		{ MSG_ORIG(MSG_STR_MINUS_SHTYP),
		    /* MSG_INTL(MSG_OPTDESC_SHTYP) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_SHTYP), ELFEDIT_CMDOA_F_VALUE,
		    SYM_OPT_F_SHTYP, SYM_OPT_F_SHNAME | SYM_OPT_F_SHNDX },
		{ MSG_ORIG(MSG_STR_TYPE), 0, 0, 0 },
		{ MSG_ORIG(MSG_STR_MINUS_SYMNDX),
		    /* MSG_INTL(MSG_OPTDESC_SYMNDX) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_SYMNDX), 0,
		    SYM_OPT_F_SYMNDX, 0 },
		{ MSG_ORIG(MSG_STR_MINUS_NAME_OFFSET),
		    /* MSG_INTL(MSG_OPTDESC_NAME_OFFSET) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_NAME_OFFSET), 0,
		    SYM_OPT_F_NAMOFFSET, 0 },
		{ ELFEDIT_STDOA_OPT_O, 0,
		    ELFEDIT_CMDOA_F_INHERIT, 0, 0 },
		{ NULL }
	};
	static elfedit_cmd_optarg_t arg_st_name[] = {
		{ MSG_ORIG(MSG_STR_SYM),
		    /* MSG_INTL(MSG_A1_SYM) */
		    ELFEDIT_I18NHDL(MSG_A1_SYM),
		    ELFEDIT_CMDOA_F_OPT },
		{ MSG_ORIG(MSG_STR_NAME),
		    /* MSG_INTL(MSG_A2_DESC_ST_NAME) */
		    ELFEDIT_I18NHDL(MSG_A2_DESC_ST_NAME),
		    ELFEDIT_CMDOA_F_OPT },
		{ NULL }
	};

	/* sym:st_other */
	static const char *name_st_other[] = {
	    MSG_ORIG(MSG_CMD_ST_OTHER), NULL };
	static elfedit_cmd_optarg_t arg_st_other[] = {
		{ MSG_ORIG(MSG_STR_SYM),
		    /* MSG_INTL(MSG_A1_SYM) */
		    ELFEDIT_I18NHDL(MSG_A1_SYM),
		    ELFEDIT_CMDOA_F_OPT },
		{ MSG_ORIG(MSG_STR_VALUE),
		    /* MSG_INTL(MSG_A2_DESC_ST_OTHER) */
		    ELFEDIT_I18NHDL(MSG_A2_DESC_ST_OTHER),
		    ELFEDIT_CMDOA_F_OPT },
		{ NULL }
	};

	/* sym:st_shndx */
	static const char *name_st_shndx[] = {
	    MSG_ORIG(MSG_CMD_ST_SHNDX), NULL };
	static elfedit_cmd_optarg_t opt_st_shndx[] = {
		{ MSG_ORIG(MSG_STR_MINUS_E),
		    /* MSG_INTL(MSG_OPTDESC_E) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_E), 0, SYM_OPT_F_XSHINDEX, 0 },
		{ MSG_ORIG(MSG_STR_MINUS_SHNAM),
		    /* MSG_INTL(MSG_OPTDESC_SHNAM) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_SHNAM), ELFEDIT_CMDOA_F_VALUE,
		    SYM_OPT_F_SHNAME, SYM_OPT_F_SHNDX | SYM_OPT_F_SHTYP },
		{ MSG_ORIG(MSG_STR_NAME), 0, 0, 0 },
		{ MSG_ORIG(MSG_STR_MINUS_SHNDX),
		    /* MSG_INTL(MSG_OPTDESC_SHNDX) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_SHNDX), ELFEDIT_CMDOA_F_VALUE,
		    SYM_OPT_F_SHNDX, SYM_OPT_F_SHNAME | SYM_OPT_F_SHTYP },
		{ MSG_ORIG(MSG_STR_INDEX), 0, 0, 0 },
		{ MSG_ORIG(MSG_STR_MINUS_SHTYP),
		    /* MSG_INTL(MSG_OPTDESC_SHTYP) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_SHTYP), ELFEDIT_CMDOA_F_VALUE,
		    SYM_OPT_F_SHTYP, SYM_OPT_F_SHNAME | SYM_OPT_F_SHNDX },
		{ MSG_ORIG(MSG_STR_TYPE), 0, 0, 0 },
		{ MSG_ORIG(MSG_STR_MINUS_SYMNDX),
		    /* MSG_INTL(MSG_OPTDESC_SYMNDX) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_SYMNDX), 0,
		    SYM_OPT_F_SYMNDX, 0 },
		{ ELFEDIT_STDOA_OPT_O, 0,
		    ELFEDIT_CMDOA_F_INHERIT, 0, 0 },
		{ MSG_ORIG(MSG_STR_MINUS_SECSHNDX),
		    /* MSG_INTL(MSG_OPTDESC_SECSHNDX) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_SECSHNDX),
		    0, SYM_OPT_F_SECSHNDX, SYM_OPT_F_SECSHTYP },
		{ MSG_ORIG(MSG_STR_MINUS_SECSHTYP),
		    /* MSG_INTL(MSG_OPTDESC_SECSHTYP) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_SECSHTYP),
		    0, SYM_OPT_F_SECSHTYP, SYM_OPT_F_SECSHNDX },
		{ NULL }
	};
	static elfedit_cmd_optarg_t arg_st_shndx[] = {
		{ MSG_ORIG(MSG_STR_SYM),
		    /* MSG_INTL(MSG_A1_SYM) */
		    ELFEDIT_I18NHDL(MSG_A1_SYM),
		    ELFEDIT_CMDOA_F_OPT },
		{ MSG_ORIG(MSG_STR_SEC),
		    /* MSG_INTL(MSG_A2_DESC_ST_SEC) */
		    ELFEDIT_I18NHDL(MSG_A2_DESC_ST_SEC),
		    ELFEDIT_CMDOA_F_OPT },
		{ NULL }
	};

	/* sym:st_size */
	static const char *name_st_size[] = {
	    MSG_ORIG(MSG_CMD_ST_SIZE), NULL };
	static elfedit_cmd_optarg_t arg_st_size[] = {
		{ MSG_ORIG(MSG_STR_SYM),
		    /* MSG_INTL(MSG_A1_SYM) */
		    ELFEDIT_I18NHDL(MSG_A1_SYM),
		    ELFEDIT_CMDOA_F_OPT },
		{ MSG_ORIG(MSG_STR_VALUE),
		    /* MSG_INTL(MSG_A2_DESC_ST_SIZE) */
		    ELFEDIT_I18NHDL(MSG_A2_DESC_ST_SIZE),
		    ELFEDIT_CMDOA_F_OPT },
		{ NULL }
	};

	/* sym:st_type */
	static const char *name_st_type[] = {
	    MSG_ORIG(MSG_CMD_ST_TYPE), NULL };
	static elfedit_cmd_optarg_t arg_st_type[] = {
		{ MSG_ORIG(MSG_STR_SYM),
		    /* MSG_INTL(MSG_A1_SYM) */
		    ELFEDIT_I18NHDL(MSG_A1_SYM),
		    ELFEDIT_CMDOA_F_OPT },
		{ MSG_ORIG(MSG_STR_VALUE),
		    /* MSG_INTL(MSG_A2_DESC_ST_TYPE) */
		    ELFEDIT_I18NHDL(MSG_A2_DESC_ST_TYPE),
		    ELFEDIT_CMDOA_F_OPT },
		{ NULL }
	};

	/* sym:st_value */
	static const char *name_st_value[] = {
	    MSG_ORIG(MSG_CMD_ST_VALUE), NULL };
	static elfedit_cmd_optarg_t arg_st_value[] = {
		{ MSG_ORIG(MSG_STR_SYM),
		    /* MSG_INTL(MSG_A1_SYM) */
		    ELFEDIT_I18NHDL(MSG_A1_SYM),
		    ELFEDIT_CMDOA_F_OPT },
		{ MSG_ORIG(MSG_STR_VALUE),
		    /* MSG_INTL(MSG_A2_DESC_ST_VALUE) */
		    ELFEDIT_I18NHDL(MSG_A2_DESC_ST_VALUE),
		    ELFEDIT_CMDOA_F_OPT },
		{ NULL }
	};

	/* sym:st_visibility */
	static const char *name_st_visibility[] = {
	    MSG_ORIG(MSG_CMD_ST_VISIBILITY), NULL };
	static elfedit_cmd_optarg_t arg_st_visibility[] = {
		{ MSG_ORIG(MSG_STR_SYM),
		    /* MSG_INTL(MSG_A1_SYM) */
		    ELFEDIT_I18NHDL(MSG_A1_SYM),
		    ELFEDIT_CMDOA_F_OPT },
		{ MSG_ORIG(MSG_STR_VALUE),
		    /* MSG_INTL(MSG_A2_DESC_ST_VISIBILITY) */
		    ELFEDIT_I18NHDL(MSG_A2_DESC_ST_VISIBILITY),
		    ELFEDIT_CMDOA_F_OPT },
		{ NULL }
	};

	static elfedit_cmd_t cmds[] = {
		/* sym:dump */
		{ cmd_dump, cpl_sh_opt, name_dump,
		    /* MSG_INTL(MSG_DESC_DUMP) */
		    ELFEDIT_I18NHDL(MSG_DESC_DUMP),
		    /* MSG_INTL(MSG_HELP_DUMP) */
		    ELFEDIT_I18NHDL(MSG_HELP_DUMP),
		    opt_dump, arg_dump },

		/* sym:st_bind */
		{ cmd_st_bind, cpl_st_bind, name_st_bind,
		    /* MSG_INTL(MSG_DESC_ST_BIND) */
		    ELFEDIT_I18NHDL(MSG_DESC_ST_BIND),
		    /* MSG_INTL(MSG_HELP_ST_BIND) */
		    ELFEDIT_I18NHDL(MSG_HELP_ST_BIND),
		    opt_std, arg_st_bind },

		/* sym:st_info */
		{ cmd_st_info, cpl_sh_opt, name_st_info,
		    /* MSG_INTL(MSG_DESC_ST_INFO) */
		    ELFEDIT_I18NHDL(MSG_DESC_ST_INFO),
		    /* MSG_INTL(MSG_HELP_ST_INFO) */
		    ELFEDIT_I18NHDL(MSG_HELP_ST_INFO),
		    opt_std, arg_st_info },

		/* sym:st_name */
		{ cmd_st_name, cpl_sh_opt, name_st_name,
		    /* MSG_INTL(MSG_DESC_ST_NAME) */
		    ELFEDIT_I18NHDL(MSG_DESC_ST_NAME),
		    /* MSG_INTL(MSG_HELP_ST_NAME) */
		    ELFEDIT_I18NHDL(MSG_HELP_ST_NAME),
		    opt_st_name, arg_st_name },

		/* sym:st_other */
		{ cmd_st_other, cpl_sh_opt, name_st_other,
		    /* MSG_INTL(MSG_DESC_ST_OTHER) */
		    ELFEDIT_I18NHDL(MSG_DESC_ST_OTHER),
		    /* MSG_INTL(MSG_HELP_ST_OTHER) */
		    ELFEDIT_I18NHDL(MSG_HELP_ST_OTHER),
		    opt_std, arg_st_other },

		/* sym:st_shndx */
		{ cmd_st_shndx, cpl_st_shndx, name_st_shndx,
		    /* MSG_INTL(MSG_DESC_ST_SHNDX) */
		    ELFEDIT_I18NHDL(MSG_DESC_ST_SHNDX),
		    /* MSG_INTL(MSG_HELP_ST_SHNDX) */
		    ELFEDIT_I18NHDL(MSG_HELP_ST_SHNDX),
		    opt_st_shndx, arg_st_shndx },

		/* sym:st_size */
		{ cmd_st_size, cpl_sh_opt, name_st_size,
		    /* MSG_INTL(MSG_DESC_ST_SIZE) */
		    ELFEDIT_I18NHDL(MSG_DESC_ST_SIZE),
		    /* MSG_INTL(MSG_HELP_ST_SIZE) */
		    ELFEDIT_I18NHDL(MSG_HELP_ST_SIZE),
		    opt_std, arg_st_size },

		/* sym:st_type */
		{ cmd_st_type, cpl_st_type, name_st_type,
		    /* MSG_INTL(MSG_DESC_ST_TYPE) */
		    ELFEDIT_I18NHDL(MSG_DESC_ST_TYPE),
		    /* MSG_INTL(MSG_HELP_ST_TYPE) */
		    ELFEDIT_I18NHDL(MSG_HELP_ST_TYPE),
		    opt_std, arg_st_type },

		/* sym:st_value */
		{ cmd_st_value, cpl_sh_opt, name_st_value,
		    /* MSG_INTL(MSG_DESC_ST_VALUE) */
		    ELFEDIT_I18NHDL(MSG_DESC_ST_VALUE),
		    /* MSG_INTL(MSG_HELP_ST_VALUE) */
		    ELFEDIT_I18NHDL(MSG_HELP_ST_VALUE),
		    opt_std, arg_st_value },

		/* sym:st_visibility */
		{ cmd_st_visibility, cpl_st_visibility, name_st_visibility,
		    /* MSG_INTL(MSG_DESC_ST_VISIBILITY) */
		    ELFEDIT_I18NHDL(MSG_DESC_ST_VISIBILITY),
		    /* MSG_INTL(MSG_HELP_ST_VISIBILITY) */
		    ELFEDIT_I18NHDL(MSG_HELP_ST_VISIBILITY),
		    opt_std, arg_st_visibility },

		{ NULL }
	};

	static elfedit_module_t module = {
	    ELFEDIT_VER_CURRENT, MSG_ORIG(MSG_MOD_NAME),
	    /* MSG_INTL(MSG_MOD_DESC) */
	    ELFEDIT_I18NHDL(MSG_MOD_DESC),
	    cmds, mod_i18nhdl_to_str };

	return (&module);
}
