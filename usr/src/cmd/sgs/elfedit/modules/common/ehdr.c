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
#include	<elfedit.h>
#include	<sys/elf_SPARC.h>
#include	<sys/elf_amd64.h>
#include	<strings.h>
#include	<conv.h>
#include	<debug.h>
#include	<ehdr_msg.h>




/*
 * This module handles changes to the ELF header
 */



/*
 * This module uses shared code for several of the commands.
 * It is sometimes necessary to know which specific command
 * is active.
 */
typedef enum {
	/* Dump command, used as module default to display ELF header */
	EHDR_CMD_T_DUMP =		0,	/* ehdr:dump */

	/* Commands that correspond directly to ELF header fields */
	EHDR_CMD_T_E_IDENT =		1,	/* ehdr:e_ident */
	EHDR_CMD_T_E_TYPE =		2,	/* ehdr:e_type */
	EHDR_CMD_T_E_MACHINE =		3,	/* ehdr:e_machine */
	EHDR_CMD_T_E_VERSION =		4,	/* ehdr:e_version */
	EHDR_CMD_T_E_ENTRY =		5,	/* ehdr:e_entry */
	EHDR_CMD_T_E_PHOFF =		6,	/* ehdr:e_phoff */
	EHDR_CMD_T_E_SHOFF =		7,	/* ehdr:e_shoff */
	EHDR_CMD_T_E_FLAGS =		8,	/* ehdr:e_flags */
	EHDR_CMD_T_E_EHSIZE =		9,	/* ehdr:e_ehsize */
	EHDR_CMD_T_E_PHENTSIZE =	10,	/* ehdr:e_phentsize */
	EHDR_CMD_T_E_PHNUM =		11,	/* ehdr:e_phnum */
	EHDR_CMD_T_E_SHENTSIZE =	12,	/* ehdr:e_shentsize */
	EHDR_CMD_T_E_SHNUM =		13,	/* ehdr:e_shnum */
	EHDR_CMD_T_E_SHSTRNDX =		14,	/* ehdr:e_shstrndx */

	/* Commands that correspond to the e_ident[] array in ELF hdr */
	EHDR_CMD_T_EI_MAG0 =		15,	/* ehdr:ei_mag0 */
	EHDR_CMD_T_EI_MAG1 =		16,	/* ehdr:ei_mag1 */
	EHDR_CMD_T_EI_MAG2 =		17,	/* ehdr:ei_mag2 */
	EHDR_CMD_T_EI_MAG3 =		18,	/* ehdr:ei_mag3 */
	EHDR_CMD_T_EI_CLASS =		19,	/* ehdr:ei_class */
	EHDR_CMD_T_EI_DATA =		20,	/* ehdr:ei_data */
	EHDR_CMD_T_EI_VERSION =		21,	/* ehdr:ei_version */
	EHDR_CMD_T_EI_OSABI =		22,	/* ehdr:ei_osabi */
	EHDR_CMD_T_EI_ABIVERSION =	23	/* ehdr:ei_abiversion */
} EHDR_CMD_T;






#ifndef _ELF64
/*
 * We supply this function for the msg module
 */
const char *
_ehdr_msg(Msg mid)
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
 * The ehdr_opt_t enum specifies a bit value for every optional
 * argument allowed by a command in this module.
 */
typedef enum {
	EHDR_OPT_F_AND =	1,	/* -and: AND (&) values to dest */
	EHDR_OPT_F_CMP =	2,	/* -cmp: Complement (~) values */
	EHDR_OPT_F_OR =		4,	/* -or: OR (|) values to dest */
	EHDR_OPT_F_SHNDX =	8,	/* -shndx: sec argument is index of */
					/*	section, not name */
	EHDR_OPT_F_SHTYP =	16	/* -shtyp: sec argument is type of */
					/*	section, not name */
} ehdr_opt_t;


/*
 * A variable of type ARGSTATE is used by each command to maintain
 * information about the arguments and related things. It is
 * initialized by process_args(), and used by the other routines.
 */
typedef struct {
	elfedit_obj_state_t	*obj_state;
	ehdr_opt_t		optmask;	/* Mask of options used */
	int			argc;		/* # of plain arguments */
	const char		**argv;		/* Plain arguments */
} ARGSTATE;



/*
 * Standard argument processing for ehdr module
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
	while ((getopt_ret = elfedit_getopt(&getopt_state)) != NULL)
		argstate->optmask |= getopt_ret->gor_idmask;

	/* If there may be an arbitrary amount of output, use a pager */
	if (argc == 0)
		elfedit_pager_init();

	/* Return the updated values of argc/argv */
	argstate->argc = argc;
	argstate->argv = argv;
}






/*
 * Format the given magic number byte into a buffer
 *
 * entry:
 *	value - Value of the magic value byte given by
 *		ehdr->ei_ident[EI_MAG?]
 */
static const char *
conv_magic_value(int value)
{
	/*
	 * This routine can be called twice within a single C statement,
	 * so we use alternating buffers on each call to allow this
	 * without requiring the caller to supply a buffer (the size of
	 * which they don't know).
	 */
	static char buf1[20];
	static char buf2[20];
	static char *buf;

	/* Switch buffers */
	buf = (buf == buf1) ? buf2 : buf1;

	if (isprint(value))
		(void) snprintf(buf, sizeof (buf1),
		    MSG_ORIG(MSG_FMT_HEXNUM_QCHR), value, value);
	else
		(void) snprintf(buf, sizeof (buf1),
		    MSG_ORIG(MSG_FMT_HEXNUM), value);
	return (buf);
}



/*
 * Print ELF header values, taking the calling command, and output style
 * into account.
 *
 * entry:
 *	cmd - EHDR_CMD_T_* value giving identify of caller
 *	e_ident_ndx - Ignored unless cmd is EHDR_CMD_T_E_IDENT. In IDENT
 *		case, index of item in e_ident[] array to display, or
 *		-1 to display the entire array.
 *	autoprint - If True, output is only produced if the elfedit
 *		autoprint flag is set. If False, output is always produced.
 *	argstate - Argument state block
 */
static void
print_ehdr(EHDR_CMD_T cmd, int e_ident_ndx, int autoprint,
    ARGSTATE *argstate)
{
	elfedit_outstyle_t	outstyle;
	Conv_fmt_flags_t	flags_fmt_flags = 0;
	Ehdr		*ehdr;
	int		c;
	Conv_inv_buf_t	inv_buf;

	if (autoprint && ((elfedit_flags() & ELFEDIT_F_AUTOPRINT) == 0))
		return;

	/*
	 * Pick an output style. ehdr:dump is required to use the default
	 * style. The other commands use the current output style.
	 */
	if (cmd == EHDR_CMD_T_DUMP) {
		outstyle = ELFEDIT_OUTSTYLE_DEFAULT;
	} else {
		outstyle = elfedit_outstyle();

		/*
		 * When the caller specifies the simple output style,
		 * omit the brackets from around the values.
		 */
		if (outstyle == ELFEDIT_OUTSTYLE_SIMPLE)
			flags_fmt_flags = CONV_FMT_NOBKT;

		/*
		 * For things that show a single header item, switch
		 * from default to simple mode.
		 */
		if ((outstyle == ELFEDIT_OUTSTYLE_DEFAULT) &&
		    ((cmd != EHDR_CMD_T_E_IDENT) || (e_ident_ndx != -1)))
			outstyle = ELFEDIT_OUTSTYLE_SIMPLE;
	}

	ehdr = argstate->obj_state->os_ehdr;

	/*
	 * If doing default output, use elfdump style where we
	 * show the full ELF header. In this case, the command
	 * that called us doesn't matter. This can only happen
	 * from ehdr:dump or ehdr:e_ident/
	 */
	if (outstyle == ELFEDIT_OUTSTYLE_DEFAULT) {
		const char *ndx, *value;
		char ndx_buf[64], value_buf[20];
		int i;

		if (cmd == EHDR_CMD_T_DUMP) {
			Elf_ehdr(NULL, ehdr,
			    argstate->obj_state->os_secarr[0].sec_shdr);
			elfedit_printf(MSG_ORIG(MSG_STR_NL));
		}

		/*
		 * Elf_ehdr() does not display all of e_ident[], so we
		 * augment by displaying the entire array separately.
		 */
		elfedit_printf(MSG_ORIG(MSG_STR_EIDENT_HDR));

		for (i = 0; i < EI_NIDENT; i++) {
			ndx = value = NULL;

			switch (i) {
			case EI_MAG0:
			case EI_MAG1:
			case EI_MAG2:
			case EI_MAG3:
				ndx = elfedit_atoconst_value_to_str(
				    ELFEDIT_CONST_EI, i, 1);
				value = conv_magic_value(ehdr->e_ident[i]);
				break;
			case EI_CLASS:
				ndx = elfedit_atoconst_value_to_str(
				    ELFEDIT_CONST_EI, EI_CLASS, 1);
				value = conv_ehdr_class(ehdr->e_ident[EI_CLASS],
				    0, &inv_buf);
				break;
			case EI_DATA:
				ndx = elfedit_atoconst_value_to_str(
				    ELFEDIT_CONST_EI, EI_DATA, 1);
				value = conv_ehdr_data(ehdr->e_ident[EI_DATA],
				    0, &inv_buf);
				break;
			case EI_VERSION:
				ndx = elfedit_atoconst_value_to_str(
				    ELFEDIT_CONST_EI, EI_VERSION, 1);
				value = conv_ehdr_vers(
				    ehdr->e_ident[EI_VERSION], 0, &inv_buf);
				break;
			case EI_OSABI:
				ndx = elfedit_atoconst_value_to_str(
				    ELFEDIT_CONST_EI, EI_OSABI, 1);
				value = conv_ehdr_osabi(ehdr->e_ident[EI_OSABI],
				    0, &inv_buf);
				break;
			case EI_ABIVERSION:
				ndx = elfedit_atoconst_value_to_str(
				    ELFEDIT_CONST_EI, EI_ABIVERSION, 1);
				value = conv_ehdr_abivers(
				    ehdr->e_ident[EI_OSABI],
				    ehdr->e_ident[EI_ABIVERSION],
				    CONV_FMT_DECIMAL, &inv_buf);
				break;
			default:
				value = value_buf;
				(void) snprintf(value_buf, sizeof (value_buf),
				    MSG_ORIG(MSG_FMT_HEXNUM), ehdr->e_ident[i]);
				break;
			}

			if (ndx == NULL)
				(void) snprintf(ndx_buf, sizeof (ndx_buf),
				    MSG_ORIG(MSG_FMT_BKTINT), i);
			else
				(void) snprintf(ndx_buf, sizeof (ndx_buf),
				    MSG_ORIG(MSG_FMT_BKTSTR), ndx);
			elfedit_printf(MSG_ORIG(MSG_FMT_EI_ELT),
			    ndx_buf, value);
		}
		return;
	}


	switch (cmd) {
	case EHDR_CMD_T_E_IDENT:
		{
			int		i, cnt;

			/* Show one element, or the entire thing? */
			if (e_ident_ndx == -1) {
				i = 0;
				cnt = EI_NIDENT;
			} else {
				i = e_ident_ndx;
				cnt = 1;
			}

			for (; cnt-- > 0; i++) {
				/*
				 * If using numeric style, or there is
				 * no conversion routine for this item,
				 * print a simple hex value.
				 */
				if ((outstyle == ELFEDIT_OUTSTYLE_NUM) ||
				    (i > EI_ABIVERSION)) {
					elfedit_printf(
					    MSG_ORIG(MSG_FMT_HEXNUMNL),
					    ehdr->e_ident[i]);
					continue;
				}

				/* Handle special cases in simple mode */
				switch (i) {
				case EI_MAG0:
				case EI_MAG1:
				case EI_MAG2:
				case EI_MAG3:
					elfedit_printf(MSG_ORIG(MSG_FMT_STRNL),
					    conv_magic_value(ehdr->e_ident[i]));
					continue;
				case EI_CLASS:
					elfedit_printf(MSG_ORIG(MSG_FMT_STRNL),
					    conv_ehdr_class(
					    ehdr->e_ident[EI_CLASS], 0,
					    &inv_buf));
					continue;
				case EI_DATA:
					elfedit_printf(MSG_ORIG(MSG_FMT_STRNL),
					    conv_ehdr_data(
					    ehdr->e_ident[EI_DATA], 0,
					    &inv_buf));
					continue;
				case EI_VERSION:
					elfedit_printf(MSG_ORIG(MSG_FMT_STRNL),
					    conv_ehdr_vers(
					    ehdr->e_ident[EI_VERSION], 0,
					    &inv_buf));
					continue;
				case EI_OSABI:
					elfedit_printf(MSG_ORIG(MSG_FMT_STRNL),
					    conv_ehdr_osabi(
					    ehdr->e_ident[EI_OSABI], 0,
					    &inv_buf));
					continue;
				case EI_ABIVERSION:
					elfedit_printf(MSG_ORIG(MSG_FMT_STRNL),
					    conv_ehdr_abivers(
					    ehdr->e_ident[EI_OSABI],
					    ehdr->e_ident[EI_ABIVERSION],
					    CONV_FMT_DECIMAL, &inv_buf));
					continue;
				}
			}
		}
		return;

	case EHDR_CMD_T_E_TYPE:
		if (outstyle == ELFEDIT_OUTSTYLE_SIMPLE)
			elfedit_printf(MSG_ORIG(MSG_FMT_STRNL),
			    conv_ehdr_type(ehdr->e_ident[EI_OSABI],
			    ehdr->e_type, 0, &inv_buf));
		else
			elfedit_printf(MSG_ORIG(MSG_FMT_DECNUMNL),
			    ehdr->e_type);
		return;

	case EHDR_CMD_T_E_MACHINE:
		if (outstyle == ELFEDIT_OUTSTYLE_SIMPLE) {
			elfedit_printf(MSG_ORIG(MSG_FMT_STRNL),
			    conv_ehdr_mach(ehdr->e_machine, 0, &inv_buf));
		} else {
			elfedit_printf(MSG_ORIG(MSG_FMT_DECNUMNL),
			    EC_WORD(ehdr->e_machine));
		}
		return;

	case EHDR_CMD_T_E_VERSION:
		if (outstyle == ELFEDIT_OUTSTYLE_SIMPLE)
			elfedit_printf(MSG_ORIG(MSG_FMT_STRNL),
			    conv_ehdr_vers(ehdr->e_version, 0, &inv_buf));
		else
			elfedit_printf(MSG_ORIG(MSG_FMT_DECNUMNL),
			    ehdr->e_version);
		return;

	case EHDR_CMD_T_E_ENTRY:
		elfedit_printf(MSG_ORIG(MSG_FMT_HEXNUMNL),
		    EC_WORD(ehdr->e_entry));
		return;

	case EHDR_CMD_T_E_PHOFF:
		elfedit_printf(MSG_ORIG(MSG_FMT_HEXNUMNL),
		    EC_WORD(ehdr->e_phoff));
		return;

	case EHDR_CMD_T_E_SHOFF:
		elfedit_printf(MSG_ORIG(MSG_FMT_HEXNUMNL),
		    EC_WORD(ehdr->e_shoff));
		return;

	case EHDR_CMD_T_E_FLAGS:
		if (outstyle == ELFEDIT_OUTSTYLE_SIMPLE) {
			Conv_ehdr_flags_buf_t	flags_buf;

			elfedit_printf(MSG_ORIG(MSG_FMT_STRNL),
			    conv_ehdr_flags(ehdr->e_machine, ehdr->e_flags,
			    flags_fmt_flags, &flags_buf));
		} else {
			elfedit_printf(MSG_ORIG(MSG_FMT_HEXNUMNL),
			    ehdr->e_flags);
		}
		return;

	case EHDR_CMD_T_E_EHSIZE:
		elfedit_printf(MSG_ORIG(MSG_FMT_DECNUMNL),
		    EC_WORD(ehdr->e_ehsize));
		return;

	case EHDR_CMD_T_E_PHENTSIZE:
		elfedit_printf(MSG_ORIG(MSG_FMT_DECNUMNL),
		    EC_WORD(ehdr->e_phentsize));
		return;

	case EHDR_CMD_T_E_PHNUM:
		{
			Word num = ehdr->e_phnum;

			/*
			 * If using extended indexes, fetch the real
			 * value from shdr[0].sh_info
			 */
			if (num == PN_XNUM)
				num = argstate->obj_state->
				    os_secarr[0].sec_shdr->sh_info;

			elfedit_printf(MSG_ORIG(MSG_FMT_DECNUMNL),
			    EC_WORD(num));
		}
		return;

	case EHDR_CMD_T_E_SHENTSIZE:
		elfedit_printf(MSG_ORIG(MSG_FMT_DECNUMNL),
		    EC_WORD(ehdr->e_shentsize));
		return;

	case EHDR_CMD_T_E_SHNUM:
		{
			Word num = ehdr->e_shnum;

			/*
			 * If using extended indexes, fetch the real
			 * value from shdr[0].sh_size
			 */
			if (num == 0)
				num = argstate->obj_state->
				    os_secarr[0].sec_shdr->sh_size;

			elfedit_printf(MSG_ORIG(MSG_FMT_DECNUMNL),
			    EC_WORD(num));
		}
		return;

	case EHDR_CMD_T_E_SHSTRNDX:
		{
			Word num = ehdr->e_shstrndx;

			/*
			 * If using extended indexes, fetch the real
			 * value from shdr[0].sh_link
			 */
			if (num == SHN_XINDEX)
				num = argstate->obj_state->
				    os_secarr[0].sec_shdr->sh_link;

			elfedit_printf(MSG_ORIG(MSG_FMT_DECNUMNL),
			    EC_WORD(num));
		}
		return;

	case EHDR_CMD_T_EI_MAG0:
	case EHDR_CMD_T_EI_MAG1:
	case EHDR_CMD_T_EI_MAG2:
	case EHDR_CMD_T_EI_MAG3:
		/* This depends on EHDR_CMD_T_EI_MAG[0-3] being contiguous */
		c = ehdr->e_ident[cmd - EHDR_CMD_T_EI_MAG0];
		if (outstyle == ELFEDIT_OUTSTYLE_SIMPLE)
			elfedit_printf(MSG_ORIG(MSG_FMT_STRNL),
			    conv_magic_value(c));
		else
			elfedit_printf(MSG_ORIG(MSG_FMT_HEXNUMNL), c);
		return;

	case EHDR_CMD_T_EI_CLASS:
		c = ehdr->e_ident[EI_CLASS];
		if (outstyle == ELFEDIT_OUTSTYLE_SIMPLE)
			elfedit_printf(MSG_ORIG(MSG_FMT_STRNL),
			    conv_ehdr_class(c, 0, &inv_buf));
		else
			elfedit_printf(MSG_ORIG(MSG_FMT_HEXNUMNL), c);
		return;

	case EHDR_CMD_T_EI_DATA:
		c = ehdr->e_ident[EI_DATA];
		if (outstyle == ELFEDIT_OUTSTYLE_SIMPLE)
			elfedit_printf(MSG_ORIG(MSG_FMT_STRNL),
			    conv_ehdr_data(c, 0, &inv_buf));
		else
			elfedit_printf(MSG_ORIG(MSG_FMT_HEXNUMNL), c);
		return;

	case EHDR_CMD_T_EI_VERSION:
		c = ehdr->e_ident[EI_VERSION];
		if (outstyle == ELFEDIT_OUTSTYLE_SIMPLE)
			elfedit_printf(MSG_ORIG(MSG_FMT_STRNL),
			    conv_ehdr_vers(c, 0, &inv_buf));
		else
			elfedit_printf(MSG_ORIG(MSG_FMT_HEXNUMNL), c);
		return;

	case EHDR_CMD_T_EI_OSABI:
		c = ehdr->e_ident[EI_OSABI];
		if (outstyle == ELFEDIT_OUTSTYLE_SIMPLE) {
			elfedit_printf(MSG_ORIG(MSG_FMT_STRNL),
			    conv_ehdr_osabi(c, 0, &inv_buf));
		} else {
			elfedit_printf(MSG_ORIG(MSG_FMT_HEXNUMNL),
			    EC_WORD(c));
		}
		return;

	case EHDR_CMD_T_EI_ABIVERSION:
		c = ehdr->e_ident[EI_ABIVERSION];
		if (outstyle == ELFEDIT_OUTSTYLE_SIMPLE) {
			elfedit_printf(MSG_ORIG(MSG_FMT_STRNL),
			    conv_ehdr_abivers(ehdr->e_ident[EI_OSABI],
			    c, CONV_FMT_DECIMAL, &inv_buf));
		} else {
			elfedit_printf(MSG_ORIG(MSG_FMT_HEXNUMNL),
			    EC_WORD(c));
		}
		return;
	}
}


/*
 * Common body for the ehdr: module commands. These commands
 * share a large amount of common behavior, so it is convenient
 * to centralize things and use the cmd argument to handle the
 * small differences.
 *
 * entry:
 *	cmd - One of the EHDR_CMD_T_* constants listed above, specifying
 *		which command to implement.
 *	obj_state, argc, argv - Standard command arguments
 */
static elfedit_cmdret_t
cmd_body(EHDR_CMD_T cmd, elfedit_obj_state_t *obj_state,
    int argc, const char *argv[])
{
	/*
	 * When a call comes in for ehdr:e_ident[ndx], and the
	 * specified element is one that we have a special command
	 * for, then we revector to that special command instead
	 * of using the generic ehdr:e_ident processing. This array,
	 * which is indexed by the e_ident[] index value is used
	 * to decide if that is the case. If the resulting value
	 * is EHDR_CMD_T_E_IDENT, then the generic processing is
	 * used. Otherwise, we revector to the specified command.
	 */
	static const int e_ident_revector[16] = {
		EHDR_CMD_T_EI_MAG0,		/* 0: EI_MAG0 */
		EHDR_CMD_T_EI_MAG1,		/* 1: EI_MAG1 */
		EHDR_CMD_T_EI_MAG2,		/* 2: EI_MAG2 */
		EHDR_CMD_T_EI_MAG3,		/* 3: EI_MAG3 */
		EHDR_CMD_T_EI_CLASS,		/* 4: EI_CLASS */
		EHDR_CMD_T_EI_DATA,		/* 5: EI_DATA */
		EHDR_CMD_T_EI_VERSION,		/* 6: EI_VERSION */
		EHDR_CMD_T_EI_OSABI,		/* 7: EI_OSABI */
		EHDR_CMD_T_EI_ABIVERSION,	/* 8: EI_ABIVERSION */
		EHDR_CMD_T_E_IDENT,		/* 9: generic */
		EHDR_CMD_T_E_IDENT,		/* 10: generic */
		EHDR_CMD_T_E_IDENT,		/* 11: generic */
		EHDR_CMD_T_E_IDENT,		/* 12: generic */
		EHDR_CMD_T_E_IDENT,		/* 13: generic */
		EHDR_CMD_T_E_IDENT,		/* 14: generic */
		EHDR_CMD_T_E_IDENT,		/* 15: generic */
	};


	ARGSTATE		argstate;
	Ehdr			*ehdr;
	elfedit_cmdret_t	ret = ELFEDIT_CMDRET_NONE;
	int			e_ident_ndx = -1;
	Conv_inv_buf_t		inv_buf1, inv_buf2;

	/* Process the optional arguments */
	process_args(obj_state, argc, argv, &argstate);

	/* Check number of arguments */
	switch (cmd) {
	case EHDR_CMD_T_DUMP:
		/* ehdr:dump does not accept arguments */
		if (argstate.argc > 0)
			elfedit_command_usage();
		break;
	case EHDR_CMD_T_E_IDENT:
		/*
		 * ehdr:e_ident accepts 1 or 2 arguments, the first
		 * being the index into the array, and the second being
		 * the value. If there are arguments, then process the
		 * index, and remove it from the argument list.
		 */
		if (argstate.argc > 0) {
			if (argstate.argc > 2)
				elfedit_command_usage();
			e_ident_ndx = (int)
			    elfedit_atoconst_range(argstate.argv[0],
			    MSG_ORIG(MSG_STR_INDEX), 0, EI_NIDENT - 1,
			    ELFEDIT_CONST_EI);
			argstate.argc--;
			argstate.argv++;

			/*
			 * If the index is for one of the e_ident elements
			 * that we have a special command for, then switch
			 * to that command. e_ident_revector[] returns
			 * EHDR_CMD_T_E_IDENT in the cases where such a command
			 * does not exist, in which case we'll continue with the
			 * generic code.
			 */
			cmd = e_ident_revector[e_ident_ndx];
		}
		break;
	case EHDR_CMD_T_E_FLAGS:
		/* ehdr:e_flags accepts an arbitrary number of arguments */
		break;
	default:
		/* The remaining commands accept a single optional argument */
		if (argstate.argc > 1)
			elfedit_command_usage();
		break;
	}

	/* If there are no arguments, dump the ELF header and return */
	if (argstate.argc == 0) {
		print_ehdr(cmd, e_ident_ndx, 0, &argstate);
		return (ELFEDIT_CMDRET_NONE);
	}

	ehdr = obj_state->os_ehdr;
	switch (cmd) {
		/*
		 * EHDR_CMD_T_DUMP can't get here: It never has an
		 * argument, and is handled above.
		 */

	case EHDR_CMD_T_E_IDENT:
		{
			/*
			 * Only those e_ident[] elements for which we
			 * don't have a specialized command come here.
			 * The argument is a value to be set in
			 * e_ident[e_ident_ndx].
			 */
			uchar_t value = (uchar_t)
			    elfedit_atoui_range(argstate.argv[0],
			    MSG_ORIG(MSG_STR_VALUE), 0, 255, NULL);

			if (ehdr->e_ident[e_ident_ndx] == value) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_EI_D_X_OK),
				    e_ident_ndx, EC_WORD(value));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_EI_D_X_CHG),
				    e_ident_ndx, ehdr->e_ident[e_ident_ndx],
				    value);
				ret = ELFEDIT_CMDRET_MOD;
				ehdr->e_ident[e_ident_ndx] = value;
			}
		}
		break;

	case EHDR_CMD_T_E_TYPE:
		{
			/* The argument gives the object type */
			Half type = (Half) elfedit_atoconst(argstate.argv[0],
			    ELFEDIT_CONST_ET);
			const char *name = MSG_ORIG(MSG_CMD_E_TYPE);

			if (ehdr->e_type == type) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_E_S_OK), name,
				    conv_ehdr_type(ehdr->e_ident[EI_OSABI],
				    ehdr->e_type, 0, &inv_buf1));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_E_S_CHG), name,
				    conv_ehdr_type(ehdr->e_ident[EI_OSABI],
				    ehdr->e_type, 0, &inv_buf1),
				    conv_ehdr_type(ehdr->e_ident[EI_OSABI],
				    type, 0, &inv_buf2));
				ret = ELFEDIT_CMDRET_MOD;
				ehdr->e_type = type;
			}
		}
		break;

	case EHDR_CMD_T_E_MACHINE:
		{
			/* The argument gives the machine code */
			Half mach = (Half) elfedit_atoconst(argstate.argv[0],
			    ELFEDIT_CONST_EM);
			const char *name = MSG_ORIG(MSG_CMD_E_MACHINE);

			if (ehdr->e_machine == mach) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_E_S_OK), name,
				    conv_ehdr_mach(ehdr->e_machine, 0,
				    &inv_buf1));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_E_S_CHG), name,
				    conv_ehdr_mach(ehdr->e_machine, 0,
				    &inv_buf1),
				    conv_ehdr_mach(mach, 0, &inv_buf2));
				ret = ELFEDIT_CMDRET_MOD_OS_MACH;
				ehdr->e_machine = mach;

			}
		}
		break;

	case EHDR_CMD_T_E_VERSION:
		{
			/* The argument gives the version */
			Word ver = (Word) elfedit_atoconst(argstate.argv[0],
			    ELFEDIT_CONST_EV);
			const char *name = MSG_ORIG(MSG_CMD_E_VERSION);

			if (ehdr->e_version == ver) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_E_S_OK), name,
				    conv_ehdr_vers(ehdr->e_version, 0,
				    &inv_buf1));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_E_S_CHG), name,
				    conv_ehdr_vers(ehdr->e_version, 0,
				    &inv_buf1),
				    conv_ehdr_vers(ver, 0, &inv_buf2));
				ret = ELFEDIT_CMDRET_MOD;
				ehdr->e_version = ver;
			}
		}
		break;

	case EHDR_CMD_T_E_ENTRY:
		{
			/* The argument gives the entry address */
			Addr entry = (Addr)
			    elfedit_atoui(argstate.argv[0], NULL);
			const char *name = MSG_ORIG(MSG_CMD_E_ENTRY);

			if (ehdr->e_entry == entry) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_E_LLX_OK), name,
				    EC_ADDR(ehdr->e_entry));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_E_LLX_CHG), name,
				    EC_ADDR(ehdr->e_entry), EC_ADDR(entry));
				ret = ELFEDIT_CMDRET_MOD;
				ehdr->e_entry = entry;
			}
		}
		break;

	case EHDR_CMD_T_E_PHOFF:
		{
			/* The argument gives the program header offset */
			Off off = (Off) elfedit_atoui(argstate.argv[0],
			    NULL);
			const char *name = MSG_ORIG(MSG_CMD_E_PHOFF);

			if (ehdr->e_phoff == off) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_E_LLX_OK), name,
				    EC_OFF(ehdr->e_phoff));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_E_LLX_CHG), name,
				    EC_OFF(ehdr->e_phoff), EC_OFF(off));
				ret = ELFEDIT_CMDRET_MOD;
				ehdr->e_phoff = off;
			}
		}
		break;

	case EHDR_CMD_T_E_SHOFF:
		{
			/* The argument gives the section header offset */
			Off off = (Off) elfedit_atoui(argstate.argv[0],
			    NULL);
			const char *name = MSG_ORIG(MSG_CMD_E_SHOFF);

			if (ehdr->e_shoff == off) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_E_LLX_OK), name,
				    EC_OFF(ehdr->e_shoff));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_E_LLX_CHG), name,
				    EC_OFF(ehdr->e_shoff), EC_OFF(off));
				ret = ELFEDIT_CMDRET_MOD;
				ehdr->e_shoff = off;
			}
		}
		break;

	case EHDR_CMD_T_E_FLAGS:
		{
			Conv_ehdr_flags_buf_t flags_buf1, flags_buf2;
			const char *name = MSG_ORIG(MSG_CMD_E_FLAGS);
			Word flags = 0;
			int i;

			/* Collect the arguments */
			for (i = 0; i < argstate.argc; i++)
				flags |= (Word)
				    elfedit_atoconst(argstate.argv[i],
				    ELFEDIT_CONST_EF);

			/* Complement the value? */
			if (argstate.optmask & EHDR_OPT_F_CMP)
				flags = ~flags;

			/* Perform any requested bit operations */
			if (argstate.optmask & EHDR_OPT_F_AND)
				flags &= ehdr->e_flags;
			else if (argstate.optmask & EHDR_OPT_F_OR)
				flags |= ehdr->e_flags;

			/* Set the value */
			if (ehdr->e_flags == flags) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_E_S_OK), name,
				    conv_ehdr_flags(ehdr->e_machine,
				    ehdr->e_flags, 0, &flags_buf1));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_E_S_CHG), name,
				    conv_ehdr_flags(ehdr->e_machine,
				    ehdr->e_flags, 0, &flags_buf1),
				    conv_ehdr_flags(ehdr->e_machine,
				    flags, 0, &flags_buf2));
				ret = ELFEDIT_CMDRET_MOD;
				ehdr->e_flags = flags;
			}
		}
		break;

	case EHDR_CMD_T_E_EHSIZE:
		{
			/* The argument gives the ELF header size */
			Half ehsize = (Half) elfedit_atoui(argstate.argv[0],
			    NULL);
			const char *name = MSG_ORIG(MSG_CMD_E_EHSIZE);

			if (ehdr->e_ehsize == ehsize) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_E_D_OK), name,
				    EC_WORD(ehdr->e_ehsize));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_E_D_CHG), name,
				    EC_WORD(ehdr->e_ehsize), EC_WORD(ehsize));
				ret = ELFEDIT_CMDRET_MOD;
				ehdr->e_ehsize = ehsize;
			}
		}
		break;

	case EHDR_CMD_T_E_PHENTSIZE:
		{
			/*
			 * The argument gives the size of a program
			 * header element.
			 */
			Half phentsize = (Half) elfedit_atoui(argstate.argv[0],
			    NULL);
			const char *name = MSG_ORIG(MSG_CMD_E_PHENTSIZE);

			if (ehdr->e_phentsize == phentsize) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_E_D_OK), name,
				    EC_WORD(ehdr->e_phentsize));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_E_D_CHG), name,
				    EC_WORD(ehdr->e_phentsize),
				    EC_WORD(phentsize));
				ret = ELFEDIT_CMDRET_MOD;
				ehdr->e_phentsize = phentsize;
			}
		}
		break;

	case EHDR_CMD_T_E_PHNUM:
		{
			/* The argument gives the number of program headers */
			Word phnum = (Word) elfedit_atoui(argstate.argv[0],
			    NULL);
			const char *name = MSG_ORIG(MSG_CMD_E_PHNUM);
			elfedit_section_t *sec0 = &obj_state->os_secarr[0];
			Shdr *shdr0 = sec0->sec_shdr;
			Half e_phnum;
			Word sh_info;

			if (phnum >= PN_XNUM) {
				e_phnum = PN_XNUM;
				sh_info = phnum;
			} else {
				e_phnum = phnum;
				sh_info = 0;
			}

			if (ehdr->e_phnum == e_phnum) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_E_D_OK), name,
				    EC_WORD(ehdr->e_phnum));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_E_D_CHG), name,
				    EC_WORD(ehdr->e_phnum), e_phnum);
				ret = ELFEDIT_CMDRET_MOD;
				ehdr->e_phnum = e_phnum;
			}
			if (shdr0->sh_info == sh_info) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_SHDR0_D_OK),
				    MSG_ORIG(MSG_STR_SH_INFO),
				    EC_WORD(shdr0->sh_info));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_SHDR0_D_CHG),
				    MSG_ORIG(MSG_STR_SH_INFO),
				    EC_WORD(shdr0->sh_info), sh_info);
				ret = ELFEDIT_CMDRET_MOD;
				shdr0->sh_info = sh_info;
				elfedit_modified_shdr(sec0);
			}
		}
		break;

	case EHDR_CMD_T_E_SHENTSIZE:
		{
			/*
			 * The argument gives the size of a program
			 * header element.
			 */
			Half shentsize = (Half) elfedit_atoui(argstate.argv[0],
			    NULL);
			const char *name = MSG_ORIG(MSG_CMD_E_SHENTSIZE);

			if (ehdr->e_shentsize == shentsize) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_E_D_OK), name,
				    EC_WORD(ehdr->e_shentsize));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_E_D_CHG), name,
				    EC_WORD(ehdr->e_shentsize),
				    EC_WORD(shentsize));
				ret = ELFEDIT_CMDRET_MOD;
				ehdr->e_shentsize = shentsize;
			}
		}
		break;

	case EHDR_CMD_T_E_SHNUM:
		{
			/* The argument gives the number of section headers */
			Word shnum = (Word) elfedit_atoui(argstate.argv[0],
			    NULL);
			const char *name = MSG_ORIG(MSG_CMD_E_SHNUM);
			elfedit_section_t *sec0 = &obj_state->os_secarr[0];
			Shdr *shdr0 = sec0->sec_shdr;
			Half e_shnum;
			Word sh_size;

			if (shnum >= SHN_LORESERVE) {
				e_shnum = 0;
				sh_size = shnum;
			} else {
				e_shnum = shnum;
				sh_size = 0;
			}

			if (ehdr->e_shnum == e_shnum) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_E_D_OK), name,
				    EC_WORD(ehdr->e_shnum));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_E_D_CHG), name,
				    EC_WORD(ehdr->e_shnum), e_shnum);
				ret = ELFEDIT_CMDRET_MOD;
				ehdr->e_shnum = e_shnum;
			}
			if (shdr0->sh_size == sh_size) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_SHDR0_D_OK),
				    MSG_ORIG(MSG_STR_SH_SIZE),
				    EC_WORD(shdr0->sh_size));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_SHDR0_D_CHG),
				    MSG_ORIG(MSG_STR_SH_SIZE),
				    EC_WORD(shdr0->sh_size), sh_size);
				ret = ELFEDIT_CMDRET_MOD;
				shdr0->sh_size = sh_size;
				elfedit_modified_shdr(sec0);
			}
		}
		break;

	case EHDR_CMD_T_E_SHSTRNDX:
		{
			const char *name = MSG_ORIG(MSG_CMD_E_SHSTRNDX);
			Word shstrndx;
			elfedit_section_t *sec0 = &obj_state->os_secarr[0];
			Shdr *shdr0 = sec0->sec_shdr;
			Half e_shstrndx;
			Word sh_link;

			/*
			 * By default, sec argument is name of section.
			 * If -shndx is used, it is a numeric index, and
			 * if -shtyp is used, it is a section type.
			 */
			if (argstate.optmask & EHDR_OPT_F_SHNDX)
				shstrndx = elfedit_atoshndx(argstate.argv[0],
				    obj_state->os_shnum);
			else if (argstate.optmask & EHDR_OPT_F_SHTYP)
				shstrndx = elfedit_type_to_shndx(obj_state,
				    elfedit_atoconst(argstate.argv[0],
				    ELFEDIT_CONST_SHT));
			else
				shstrndx = elfedit_name_to_shndx(obj_state,
				    argstate.argv[0]);

			/* Warn if the section isn't a string table */
			if ((shstrndx >= obj_state->os_shnum) ||
			    ((shstrndx >= SHN_LORESERVE) &&
			    (shstrndx <= SHN_HIRESERVE)) ||
			    (obj_state->os_secarr[shstrndx].sec_shdr->sh_type !=
			    SHT_STRTAB))
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_NOTSTRTAB), name,
				    EC_WORD(shstrndx));

			if (shstrndx >= SHN_LORESERVE) {
				e_shstrndx = SHN_XINDEX;
				sh_link = shstrndx;
			} else {
				e_shstrndx = shstrndx;
				sh_link = 0;
			}

			if (ehdr->e_shstrndx == e_shstrndx) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_E_D_OK), name,
				    EC_WORD(ehdr->e_shstrndx));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_E_D_CHG), name,
				    EC_WORD(ehdr->e_shstrndx), e_shstrndx);
				ret = ELFEDIT_CMDRET_MOD;
				ehdr->e_shstrndx = e_shstrndx;
			}
			if (shdr0->sh_link == sh_link) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_SHDR0_D_OK),
				    MSG_ORIG(MSG_STR_SH_LINK),
				    EC_WORD(shdr0->sh_link));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_SHDR0_D_CHG),
				    MSG_ORIG(MSG_STR_SH_LINK),
				    EC_WORD(shdr0->sh_link), sh_link);
				ret = ELFEDIT_CMDRET_MOD;
				shdr0->sh_link = sh_link;
				elfedit_modified_shdr(sec0);
			}
		}
		break;

	case EHDR_CMD_T_EI_MAG0:
	case EHDR_CMD_T_EI_MAG1:
	case EHDR_CMD_T_EI_MAG2:
	case EHDR_CMD_T_EI_MAG3:
		{
			/*
			 * This depends on EHDR_CMD_T_EI_MAG[0-3]
			 * being contiguous
			 */
			int ei_ndx = (cmd - EHDR_CMD_T_EI_MAG0) + EI_MAG0;

			/* The argument gives the magic number byte */
			int mag = (int)elfedit_atoui_range(argstate.argv[0],
			    MSG_ORIG(MSG_STR_VALUE), 0, 255, NULL);

			if (ehdr->e_ident[ei_ndx] == mag) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_EI_S_S_OK),
				    elfedit_atoconst_value_to_str(
				    ELFEDIT_CONST_EI, ei_ndx, 1),
				    conv_magic_value(ehdr->e_ident[ei_ndx]));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_EI_S_S_CHG),
				    elfedit_atoconst_value_to_str(
				    ELFEDIT_CONST_EI, ei_ndx, 1),
				    conv_magic_value(ehdr->e_ident[ei_ndx]),
				    conv_magic_value(mag));
				ret = ELFEDIT_CMDRET_MOD;
				ehdr->e_ident[ei_ndx] = mag;
			}
		}
		break;

	case EHDR_CMD_T_EI_CLASS:
		{
			/* The argument gives the ELFCLASS value */
			int class = (int)elfedit_atoconst_range(
			    argstate.argv[0], MSG_ORIG(MSG_STR_VALUE), 0, 255,
			    ELFEDIT_CONST_ELFCLASS);
			const char *name = elfedit_atoconst_value_to_str(
			    ELFEDIT_CONST_EI, EI_CLASS, 1);

			if (ehdr->e_ident[EI_CLASS] == class) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_EI_S_S_OK), name,
				    conv_ehdr_class(class, 0, &inv_buf1));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_EI_S_S_CHG), name,
				    conv_ehdr_class(ehdr->e_ident[EI_CLASS],
				    0, &inv_buf1),
				    conv_ehdr_class(class, 0, &inv_buf2));
				ret = ELFEDIT_CMDRET_MOD;
				ehdr->e_ident[EI_CLASS] = class;
			}
		}
		break;

	case EHDR_CMD_T_EI_DATA:
		{
			/* The argument gives the ELFDATA value */
			int data = (int)elfedit_atoconst_range(argstate.argv[0],
			    MSG_ORIG(MSG_STR_VALUE), 0, 255,
			    ELFEDIT_CONST_ELFDATA);
			const char *name = elfedit_atoconst_value_to_str(
			    ELFEDIT_CONST_EI, EI_DATA, 1);

			if (ehdr->e_ident[EI_DATA] == data) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_EI_S_S_OK), name,
				    conv_ehdr_data(data, 0, &inv_buf1));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_EI_S_S_CHG), name,
				    conv_ehdr_data(ehdr->e_ident[EI_DATA],
				    0, &inv_buf1),
				    conv_ehdr_data(data, 0, &inv_buf2));
				ret = ELFEDIT_CMDRET_MOD;
				ehdr->e_ident[EI_DATA] = data;
			}
		}
		break;

	case EHDR_CMD_T_EI_VERSION:
		{
			/* The argument gives the version */
			int ver = (int)elfedit_atoconst_range(argstate.argv[0],
			    MSG_ORIG(MSG_STR_VALUE), 0, 255, ELFEDIT_CONST_EV);
			const char *name = elfedit_atoconst_value_to_str(
			    ELFEDIT_CONST_EI, EI_VERSION, 1);

			if (ehdr->e_ident[EI_VERSION] == ver) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_EI_S_S_OK), name,
				    conv_ehdr_vers(ver, 0, &inv_buf1));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_EI_S_S_CHG), name,
				    conv_ehdr_vers(ehdr->e_ident[EI_VERSION],
				    0, &inv_buf1),
				    conv_ehdr_vers(ver, 0, &inv_buf2));
				ret = ELFEDIT_CMDRET_MOD;
				ehdr->e_ident[EI_VERSION] = ver;
			}
		}
		break;

	case EHDR_CMD_T_EI_OSABI:
		{
			/* The argument gives the ABI code */
			int osabi = (int)elfedit_atoconst_range(
			    argstate.argv[0], MSG_ORIG(MSG_STR_VALUE), 0, 255,
			    ELFEDIT_CONST_ELFOSABI);
			const char *name = elfedit_atoconst_value_to_str(
			    ELFEDIT_CONST_EI, EI_OSABI, 1);

			if (ehdr->e_ident[EI_OSABI] == osabi) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_EI_S_S_OK), name,
				    conv_ehdr_osabi(osabi, 0, &inv_buf1));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_EI_S_S_CHG), name,
				    conv_ehdr_osabi(ehdr->e_ident[EI_OSABI],
				    0, &inv_buf1),
				    conv_ehdr_osabi(osabi, 0, &inv_buf2));
				ret = ELFEDIT_CMDRET_MOD_OS_MACH;
				ehdr->e_ident[EI_OSABI] = osabi;
			}
		}
		break;

	case EHDR_CMD_T_EI_ABIVERSION:
		{
			/* The argument gives the ABI version  */
			int abiver = (int)elfedit_atoconst_range(
			    argstate.argv[0], MSG_ORIG(MSG_STR_VALUE), 0, 255,
			    ELFEDIT_CONST_EAV);
			const char *name = elfedit_atoconst_value_to_str(
			    ELFEDIT_CONST_EI, EI_ABIVERSION, 1);

			if (ehdr->e_ident[EI_ABIVERSION] == abiver) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_EI_S_S_OK), name,
				    conv_ehdr_abivers(ehdr->e_ident[EI_OSABI],
				    abiver, CONV_FMT_DECIMAL, &inv_buf1));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_EI_S_S_CHG), name,
				    conv_ehdr_abivers(ehdr->e_ident[EI_OSABI],
				    ehdr->e_ident[EI_ABIVERSION],
				    CONV_FMT_DECIMAL, &inv_buf1),
				    conv_ehdr_abivers(ehdr->e_ident[EI_OSABI],
				    abiver, CONV_FMT_DECIMAL, &inv_buf2));
				ret = ELFEDIT_CMDRET_MOD;
				ehdr->e_ident[EI_ABIVERSION] = abiver;
			}
		}
		break;
	}

	/*
	 * If we modified the ELF header, tell libelf.
	 */
	if (ret == ELFEDIT_CMDRET_MOD)
		elfedit_modified_ehdr(obj_state);

	/* Do autoprint */
	print_ehdr(cmd, e_ident_ndx, 1, &argstate);

	return (ret);
}




/*
 * Command completion functions for the various commands
 */

/*ARGSUSED*/
static void
cpl_e_ident(elfedit_obj_state_t *obj_state, void *cpldata, int argc,
    const char *argv[], int num_opt)
{
	elfedit_atoui_t	ndx;

	/*
	 * This command doesn't accept options, so num_opt should be
	 * 0. This is a defensive measure, in case that should change.
	 */
	argc -= num_opt;
	argv += num_opt;

	if (argc == 1) {
		elfedit_cpl_atoconst(cpldata, ELFEDIT_CONST_EI);
		return;
	}

	if (argc != 2)
		return;

	/*
	 * In order to offer up the right completion strings for
	 * the value, we need to know what index was given for
	 * the first argument. If we don't recognize the index,
	 * we want to return quietly without issuing an error,
	 * so we use elfedit_atoui_range2(), which returns
	 * a success/failure result and does not throw any errors.
	 */
	if (elfedit_atoconst_range2(argv[0], 0, EI_NIDENT - 1,
	    ELFEDIT_CONST_EI, &ndx) == 0)
		return;
	switch (ndx) {
	case EI_CLASS:
		elfedit_cpl_atoconst(cpldata, ELFEDIT_CONST_ELFCLASS);
		break;
	case EI_DATA:
		elfedit_cpl_atoconst(cpldata, ELFEDIT_CONST_ELFDATA);
		break;
	case EI_VERSION:
		elfedit_cpl_atoconst(cpldata, ELFEDIT_CONST_EV);
		break;
	case EI_OSABI:
		elfedit_cpl_atoconst(cpldata, ELFEDIT_CONST_ELFOSABI);
		break;
	}
}

/*ARGSUSED*/
static void
cpl_e_type(elfedit_obj_state_t *obj_state, void *cpldata, int argc,
    const char *argv[], int num_opt)
{
	/*
	 * This command doesn't accept options, so num_opt should be
	 * 0. This is a defensive measure, in case that should change.
	 */
	argc -= num_opt;
	argv += num_opt;

	if (argc == 1)
		elfedit_cpl_atoconst(cpldata, ELFEDIT_CONST_ET);
}

/*ARGSUSED*/
static void
cpl_e_machine(elfedit_obj_state_t *obj_state, void *cpldata, int argc,
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

/*ARGSUSED*/
static void
cpl_e_version(elfedit_obj_state_t *obj_state, void *cpldata, int argc,
    const char *argv[], int num_opt)
{
	/*
	 * This command doesn't accept options, so num_opt should be
	 * 0. This is a defensive measure, in case that should change.
	 */
	argc -= num_opt;
	argv += num_opt;

	if (argc == 1)
		elfedit_cpl_atoconst(cpldata, ELFEDIT_CONST_EV);
}

/*ARGSUSED*/
static void
cpl_e_flags(elfedit_obj_state_t *obj_state, void *cpldata, int argc,
    const char *argv[], int num_opt)
{
	/* This routine allows multiple flags to be specified */
	elfedit_cpl_atoconst(cpldata, ELFEDIT_CONST_EF);
}

/*ARGSUSED*/
static void
cpl_e_shstrndx(elfedit_obj_state_t *obj_state, void *cpldata, int argc,
    const char *argv[], int num_opt)
{
	enum { NAME, INDEX, TYPE } op;
	Word ndx;

	/*
	 * The plainargument can be a section name, index, or
	 * type, based on the options used. All have completions.
	 */
	if (argc != (num_opt + 1))
		return;

	op = NAME;
	for (ndx = 0; ndx < num_opt; ndx++) {
		if (strcmp(argv[ndx], MSG_ORIG(MSG_STR_MINUS_SHNDX)) == 0)
			op = INDEX;
		else if (strcmp(argv[ndx], MSG_ORIG(MSG_STR_MINUS_SHTYP)) == 0)
			op = TYPE;
	}

	if (obj_state == NULL) {	/* No object available */
		if (op == TYPE)
			elfedit_cpl_atoconst(cpldata, ELFEDIT_CONST_SHT);
		return;
	}

	/*
	 * Loop over the sections and supply command completion
	 * for the string tables in the file.
	 */
	for (ndx = 0; ndx < obj_state->os_shnum; ndx++) {
		elfedit_section_t *sec = &obj_state->os_secarr[ndx];

		if (sec->sec_shdr->sh_type != SHT_STRTAB)
			continue;

		switch (op) {
		case NAME:
			elfedit_cpl_match(cpldata, sec->sec_name, 0);
			break;
		case INDEX:
			elfedit_cpl_ndx(cpldata, ndx);
			break;
		case TYPE:
			elfedit_cpl_atoconst(cpldata, ELFEDIT_CONST_SHT_STRTAB);
			break;
		}
	}
}

/*ARGSUSED*/
static void
cpl_ei_class(elfedit_obj_state_t *obj_state, void *cpldata, int argc,
    const char *argv[], int num_opt)
{
	/*
	 * This command doesn't accept options, so num_opt should be
	 * 0. This is a defensive measure, in case that should change.
	 */
	argc -= num_opt;
	argv += num_opt;

	if (argc == 1)
		elfedit_cpl_atoconst(cpldata, ELFEDIT_CONST_ELFCLASS);
}

/*ARGSUSED*/
static void
cpl_ei_data(elfedit_obj_state_t *obj_state, void *cpldata, int argc,
    const char *argv[], int num_opt)
{
	/*
	 * This command doesn't accept options, so num_opt should be
	 * 0. This is a defensive measure, in case that should change.
	 */
	argc -= num_opt;
	argv += num_opt;

	if (argc == 1)
		elfedit_cpl_atoconst(cpldata, ELFEDIT_CONST_ELFDATA);
}

/*ARGSUSED*/
static void
cpl_ei_osabi(elfedit_obj_state_t *obj_state, void *cpldata, int argc,
    const char *argv[], int num_opt)
{
	/*
	 * This command doesn't accept options, so num_opt should be
	 * 0. This is a defensive measure, in case that should change.
	 */
	argc -= num_opt;
	argv += num_opt;

	if (argc == 1)
		elfedit_cpl_atoconst(cpldata, ELFEDIT_CONST_ELFOSABI);
}

/*ARGSUSED*/
static void
cpl_ei_abiversion(elfedit_obj_state_t *obj_state, void *cpldata, int argc,
    const char *argv[], int num_opt)
{
	/*
	 * This command doesn't accept options, so num_opt should be
	 * 0. This is a defensive measure, in case that should change.
	 */
	argc -= num_opt;
	argv += num_opt;

	if (argc == 1)
		elfedit_cpl_atoconst(cpldata, ELFEDIT_CONST_EAV);
}




/*
 * Implementation functions for the commands
 */
static elfedit_cmdret_t
cmd_dump(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(EHDR_CMD_T_DUMP, obj_state, argc, argv));
}


static elfedit_cmdret_t
cmd_e_ident(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(EHDR_CMD_T_E_IDENT, obj_state, argc, argv));
}


static elfedit_cmdret_t
cmd_e_type(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(EHDR_CMD_T_E_TYPE, obj_state, argc, argv));
}


static elfedit_cmdret_t
cmd_e_machine(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(EHDR_CMD_T_E_MACHINE, obj_state, argc, argv));
}


static elfedit_cmdret_t
cmd_e_version(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(EHDR_CMD_T_E_VERSION, obj_state, argc, argv));
}


static elfedit_cmdret_t
cmd_e_entry(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(EHDR_CMD_T_E_ENTRY, obj_state, argc, argv));
}


static elfedit_cmdret_t
cmd_e_phoff(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(EHDR_CMD_T_E_PHOFF, obj_state, argc, argv));
}


static elfedit_cmdret_t
cmd_e_shoff(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(EHDR_CMD_T_E_SHOFF, obj_state, argc, argv));
}


static elfedit_cmdret_t
cmd_e_flags(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(EHDR_CMD_T_E_FLAGS, obj_state, argc, argv));
}


static elfedit_cmdret_t
cmd_e_ehsize(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(EHDR_CMD_T_E_EHSIZE, obj_state, argc, argv));
}


static elfedit_cmdret_t
cmd_e_phentsize(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(EHDR_CMD_T_E_PHENTSIZE, obj_state, argc, argv));
}


static elfedit_cmdret_t
cmd_e_phnum(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(EHDR_CMD_T_E_PHNUM, obj_state, argc, argv));
}


static elfedit_cmdret_t
cmd_e_shentsize(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(EHDR_CMD_T_E_SHENTSIZE, obj_state, argc, argv));
}


static elfedit_cmdret_t
cmd_e_shnum(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(EHDR_CMD_T_E_SHNUM, obj_state, argc, argv));
}


static elfedit_cmdret_t
cmd_e_shstrndx(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(EHDR_CMD_T_E_SHSTRNDX, obj_state, argc, argv));
}


static elfedit_cmdret_t
cmd_ei_mag0(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(EHDR_CMD_T_EI_MAG0, obj_state, argc, argv));
}


static elfedit_cmdret_t
cmd_ei_mag1(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(EHDR_CMD_T_EI_MAG1, obj_state, argc, argv));
}


static elfedit_cmdret_t
cmd_ei_mag2(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(EHDR_CMD_T_EI_MAG2, obj_state, argc, argv));
}


static elfedit_cmdret_t
cmd_ei_mag3(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(EHDR_CMD_T_EI_MAG3, obj_state, argc, argv));
}


static elfedit_cmdret_t
cmd_ei_class(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(EHDR_CMD_T_EI_CLASS, obj_state, argc, argv));
}


static elfedit_cmdret_t
cmd_ei_data(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(EHDR_CMD_T_EI_DATA, obj_state, argc, argv));
}


static elfedit_cmdret_t
cmd_ei_version(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(EHDR_CMD_T_EI_VERSION, obj_state, argc, argv));
}


static elfedit_cmdret_t
cmd_ei_osabi(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(EHDR_CMD_T_EI_OSABI, obj_state, argc, argv));
}


static elfedit_cmdret_t
cmd_ei_abiversion(elfedit_obj_state_t *obj_state, int argc, const char *argv[])
{
	return (cmd_body(EHDR_CMD_T_EI_ABIVERSION, obj_state, argc, argv));
}




/*ARGSUSED*/
elfedit_module_t *
elfedit_init(elfedit_module_version_t version)
{
	/* Many of the commands only accept -o */
	static elfedit_cmd_optarg_t opt_std[] = {
		{ ELFEDIT_STDOA_OPT_O, 0,
		    ELFEDIT_CMDOA_F_INHERIT, 0, 0 },
		{ NULL }
	};


	/* ehdr:dump */
	static const char *name_dump[] = {
	    MSG_ORIG(MSG_CMD_DUMP),
	    MSG_ORIG(MSG_STR_EMPTY),	/* "" makes this the default command */
	    NULL
	};

	/* ehdr:e_ident */
	static const char *name_e_ident[] = {
		MSG_ORIG(MSG_CMD_E_IDENT), NULL };
	static elfedit_cmd_optarg_t arg_e_ident[] = {
		{ MSG_ORIG(MSG_STR_INDEX),
		    /* MSG_INTL(MSG_ARGDESC_E_IDENT_NDX) */
		    ELFEDIT_I18NHDL(MSG_ARGDESC_E_IDENT_NDX),
		    ELFEDIT_CMDOA_F_OPT, 0 },
		{ MSG_ORIG(MSG_STR_VALUE),
		    /* MSG_INTL(MSG_ARGDESC_E_IDENT_VALUE) */
		    ELFEDIT_I18NHDL(MSG_ARGDESC_E_IDENT_VALUE),
		    ELFEDIT_CMDOA_F_OPT, 0 },
		{ NULL }
	};

	/* ehdr:e_type */
	static const char *name_e_type[] = {
		MSG_ORIG(MSG_CMD_E_TYPE), NULL };
	static elfedit_cmd_optarg_t arg_e_type[] = {
		{ MSG_ORIG(MSG_STR_VALUE),
		    /* MSG_INTL(MSG_ARGDESC_E_TYPE_VALUE) */
		    ELFEDIT_I18NHDL(MSG_ARGDESC_E_TYPE_VALUE),
		    ELFEDIT_CMDOA_F_OPT, 0 },
		{ NULL }
	};

	/* ehdr:e_machine */
	static const char *name_e_machine[] = {
		MSG_ORIG(MSG_CMD_E_MACHINE), NULL };
	static elfedit_cmd_optarg_t arg_e_machine[] = {
		{ MSG_ORIG(MSG_STR_TYPE),
		    /* MSG_INTL(MSG_ARGDESC_E_MACHINE_VALUE) */
		    ELFEDIT_I18NHDL(MSG_ARGDESC_E_MACHINE_VALUE),
		    ELFEDIT_CMDOA_F_OPT, 0 },
		{ NULL }
	};

	/* ehdr:e_version */
	static const char *name_e_version[] = {
		MSG_ORIG(MSG_CMD_E_VERSION), NULL };
	static elfedit_cmd_optarg_t arg_e_version[] = {
		{ MSG_ORIG(MSG_STR_VERSION),
		    /* MSG_INTL(MSG_ARGDESC_E_VERSION_VALUE) */
		    ELFEDIT_I18NHDL(MSG_ARGDESC_E_VERSION_VALUE),
		    ELFEDIT_CMDOA_F_OPT, 0 },
		{ NULL }
	};

	/* ehdr:e_entry */
	static const char *name_e_entry[] = {
		MSG_ORIG(MSG_CMD_E_ENTRY), NULL };
	static elfedit_cmd_optarg_t arg_e_entry[] = {
		{ MSG_ORIG(MSG_STR_VALUE),
		    /* MSG_INTL(MSG_ARGDESC_E_ENTRY_VALUE) */
		    ELFEDIT_I18NHDL(MSG_ARGDESC_E_ENTRY_VALUE),
		    ELFEDIT_CMDOA_F_OPT, 0 },
		{ NULL }
	};

	/* ehdr:e_phoff */
	static const char *name_e_phoff[] = {
		MSG_ORIG(MSG_CMD_E_PHOFF), NULL };
	static elfedit_cmd_optarg_t arg_e_phoff[] = {
		{ MSG_ORIG(MSG_STR_OFFSET),
		    /* MSG_INTL(MSG_ARGDESC_E_PHOFF_VALUE) */
		    ELFEDIT_I18NHDL(MSG_ARGDESC_E_PHOFF_VALUE),
		    ELFEDIT_CMDOA_F_OPT, 0 },
		{ NULL }
	};

	/* ehdr:e_shoff */
	static const char *name_e_shoff[] = {
		MSG_ORIG(MSG_CMD_E_SHOFF), NULL };
	static elfedit_cmd_optarg_t arg_e_shoff[] = {
		{ MSG_ORIG(MSG_STR_OFFSET),
		    /* MSG_INTL(MSG_ARGDESC_E_SHOFF_VALUE) */
		    ELFEDIT_I18NHDL(MSG_ARGDESC_E_SHOFF_VALUE),
		    ELFEDIT_CMDOA_F_OPT, 0 },
		{ NULL }
	};

	/* ehdr:e_flags */
	static const char *name_e_flags[] = {
		MSG_ORIG(MSG_CMD_E_FLAGS), NULL };
	static elfedit_cmd_optarg_t opt_e_flags[] = {
		{ ELFEDIT_STDOA_OPT_AND, 0,
		    ELFEDIT_CMDOA_F_INHERIT, EHDR_OPT_F_AND, EHDR_OPT_F_OR },
		{ ELFEDIT_STDOA_OPT_CMP, 0,
		    ELFEDIT_CMDOA_F_INHERIT, EHDR_OPT_F_CMP, 0 },
		{ ELFEDIT_STDOA_OPT_O, 0,
		    ELFEDIT_CMDOA_F_INHERIT, 0, 0 },
		{ ELFEDIT_STDOA_OPT_OR, 0,
		    ELFEDIT_CMDOA_F_INHERIT, EHDR_OPT_F_OR, EHDR_OPT_F_AND },
		{ NULL }
	};
	static elfedit_cmd_optarg_t arg_e_flags[] = {
		{ MSG_ORIG(MSG_STR_FLAGVALUE),
		    /* MSG_INTL(MSG_ARGDESC_E_FLAGS_VALUE) */
		    ELFEDIT_I18NHDL(MSG_ARGDESC_E_FLAGS_VALUE),
		    ELFEDIT_CMDOA_F_OPT | ELFEDIT_CMDOA_F_MULT, 0 },
		{ NULL }
	};

	/* ehdr:e_ehsize */
	static const char *name_e_ehsize[] = {
		MSG_ORIG(MSG_CMD_E_EHSIZE), NULL };
	static elfedit_cmd_optarg_t arg_e_ehsize[] = {
		{ MSG_ORIG(MSG_STR_VALUE),
		    /* MSG_INTL(MSG_ARGDESC_E_EHSIZE_VALUE) */
		    ELFEDIT_I18NHDL(MSG_ARGDESC_E_EHSIZE_VALUE),
		    ELFEDIT_CMDOA_F_OPT, 0 },
		{ NULL }
	};

	/* ehdr:e_phentsize */
	static const char *name_e_phentsize[] = {
		MSG_ORIG(MSG_CMD_E_PHENTSIZE), NULL };
	static elfedit_cmd_optarg_t arg_e_phentsize[] = {
		{ MSG_ORIG(MSG_STR_VALUE),
		    /* MSG_INTL(MSG_ARGDESC_E_PHENTSIZE_VALUE) */
		    ELFEDIT_I18NHDL(MSG_ARGDESC_E_PHENTSIZE_VALUE),
		    ELFEDIT_CMDOA_F_OPT, 0 },
		{ NULL }
	};

	/* ehdr:e_phnum */
	static const char *name_e_phnum[] = {
		MSG_ORIG(MSG_CMD_E_PHNUM), NULL };
	static elfedit_cmd_optarg_t arg_e_phnum[] = {
		{ MSG_ORIG(MSG_STR_VALUE),
		    /* MSG_INTL(MSG_ARGDESC_E_PHNUM_VALUE) */
		    ELFEDIT_I18NHDL(MSG_ARGDESC_E_PHNUM_VALUE),
		    ELFEDIT_CMDOA_F_OPT, 0 },
		{ NULL }
	};

	/* ehdr:e_shentsize */
	static const char *name_e_shentsize[] = {
		MSG_ORIG(MSG_CMD_E_SHENTSIZE), NULL };
	static elfedit_cmd_optarg_t arg_e_shentsize[] = {
		{ MSG_ORIG(MSG_STR_VALUE),
		    /* MSG_INTL(MSG_ARGDESC_E_SHENTSIZE_VALUE) */
		    ELFEDIT_I18NHDL(MSG_ARGDESC_E_SHENTSIZE_VALUE),
		    ELFEDIT_CMDOA_F_OPT, 0 },
		{ NULL }
	};

	/* ehdr:e_shnum */
	static const char *name_e_shnum[] = {
		MSG_ORIG(MSG_CMD_E_SHNUM), NULL };
	static elfedit_cmd_optarg_t arg_e_shnum[] = {
		{ MSG_ORIG(MSG_STR_VALUE),
		    /* MSG_INTL(MSG_ARGDESC_E_SHNUM_VALUE) */
		    ELFEDIT_I18NHDL(MSG_ARGDESC_E_SHNUM_VALUE),
		    ELFEDIT_CMDOA_F_OPT, 0 },
		{ NULL }
	};

	/* ehdr:e_shstrndx */
	static const char *name_e_shstrndx[] = {
		MSG_ORIG(MSG_CMD_E_SHSTRNDX), NULL };
	static elfedit_cmd_optarg_t opt_e_shstrndx[] = {
		{ ELFEDIT_STDOA_OPT_O, 0,
		    ELFEDIT_CMDOA_F_INHERIT, 0, 0 },
		{ MSG_ORIG(MSG_STR_MINUS_SHNDX),
		    /* MSG_INTL(MSG_OPTDESC_SHNDX) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_SHNDX), 0,
		    EHDR_OPT_F_SHNDX, EHDR_OPT_F_SHTYP },
		{ MSG_ORIG(MSG_STR_MINUS_SHTYP),
		    /* MSG_INTL(MSG_OPTDESC_SHTYP) */
		    ELFEDIT_I18NHDL(MSG_OPTDESC_SHTYP), 0,
		    EHDR_OPT_F_SHTYP, EHDR_OPT_F_SHNDX,  },
		{ NULL }
	};
	static elfedit_cmd_optarg_t arg_e_shstrndx[] = {
		{ MSG_ORIG(MSG_STR_SEC),
		    /* MSG_INTL(MSG_ARGDESC_E_SHSTRNDX_SEC) */
		    ELFEDIT_I18NHDL(MSG_ARGDESC_E_SHSTRNDX_SEC),
		    ELFEDIT_CMDOA_F_OPT, 0 },
		{ NULL }
	};

	/* ehdr:ei_mag0 */
	static const char *name_ei_mag0[] = {
		MSG_ORIG(MSG_CMD_EI_MAG0), NULL };
	static elfedit_cmd_optarg_t arg_ei_mag0[] = {
		{ MSG_ORIG(MSG_STR_VALUE),
		    /* MSG_INTL(MSG_ARGDESC_EI_MAG0_VALUE) */
		    ELFEDIT_I18NHDL(MSG_ARGDESC_EI_MAG0_VALUE),
		    ELFEDIT_CMDOA_F_OPT, 0 },
		{ NULL }
	};

	/* ehdr:ei_mag1 */
	static const char *name_ei_mag1[] = {
		MSG_ORIG(MSG_CMD_EI_MAG1), NULL };
	static elfedit_cmd_optarg_t arg_ei_mag1[] = {
		{ MSG_ORIG(MSG_STR_VALUE),
		    /* MSG_INTL(MSG_ARGDESC_EI_MAG1_VALUE) */
		    ELFEDIT_I18NHDL(MSG_ARGDESC_EI_MAG1_VALUE),
		    ELFEDIT_CMDOA_F_OPT, 0 },
		{ NULL }
	};

	/* ehdr:ei_mag2 */
	static const char *name_ei_mag2[] = {
		MSG_ORIG(MSG_CMD_EI_MAG2), NULL };
	static elfedit_cmd_optarg_t arg_ei_mag2[] = {
		{ MSG_ORIG(MSG_STR_VALUE),
		    /* MSG_INTL(MSG_ARGDESC_EI_MAG2_VALUE) */
		    ELFEDIT_I18NHDL(MSG_ARGDESC_EI_MAG2_VALUE),
		    ELFEDIT_CMDOA_F_OPT, 0 },
		{ NULL }
	};

	/* ehdr:ei_mag3 */
	static const char *name_ei_mag3[] = {
		MSG_ORIG(MSG_CMD_EI_MAG3), NULL };
	static elfedit_cmd_optarg_t arg_ei_mag3[] = {
		{ MSG_ORIG(MSG_STR_VALUE),
		    /* MSG_INTL(MSG_ARGDESC_EI_MAG3_VALUE) */
		    ELFEDIT_I18NHDL(MSG_ARGDESC_EI_MAG3_VALUE),
		    ELFEDIT_CMDOA_F_OPT, 0 },
		{ NULL }
	};

	/* ehdr:ei_class */
	static const char *name_ei_class[] = {
		MSG_ORIG(MSG_CMD_EI_CLASS), NULL };
	static elfedit_cmd_optarg_t arg_ei_class[] = {
		{ MSG_ORIG(MSG_STR_VALUE),
		    /* MSG_INTL(MSG_ARGDESC_EI_CLASS_VALUE) */
		    ELFEDIT_I18NHDL(MSG_ARGDESC_EI_CLASS_VALUE),
		    ELFEDIT_CMDOA_F_OPT, 0 },
		{ NULL }
	};

	/* ehdr:ei_data */
	static const char *name_ei_data[] = {
		MSG_ORIG(MSG_CMD_EI_DATA), NULL };
	static elfedit_cmd_optarg_t arg_ei_data[] = {
		{ MSG_ORIG(MSG_STR_VALUE),
		    /* MSG_INTL(MSG_ARGDESC_EI_DATA_VALUE) */
		    ELFEDIT_I18NHDL(MSG_ARGDESC_EI_DATA_VALUE),
		    ELFEDIT_CMDOA_F_OPT, 0 },
		{ NULL }
	};

	/* ehdr:ei_version */
	static const char *name_ei_version[] = {
		MSG_ORIG(MSG_CMD_EI_VERSION), NULL };
	/* Note: arg_e_version is also used for this command */

	/* ehdr:ei_osabi */
	static const char *name_ei_osabi[] = {
		MSG_ORIG(MSG_CMD_EI_OSABI), NULL };
	static elfedit_cmd_optarg_t arg_ei_osabi[] = {
		{ MSG_ORIG(MSG_STR_VALUE),
		    /* MSG_INTL(MSG_ARGDESC_EI_OSABI_VALUE) */
		    ELFEDIT_I18NHDL(MSG_ARGDESC_EI_OSABI_VALUE),
		    ELFEDIT_CMDOA_F_OPT, 0 },
		{ NULL }
	};

	/* ehdr:ei_abiversion */
	static const char *name_ei_abiversion[] = {
		MSG_ORIG(MSG_CMD_EI_ABIVERSION), NULL };
	static elfedit_cmd_optarg_t arg_ei_abiversion[] = {
		{ MSG_ORIG(MSG_STR_VALUE),
		    /* MSG_INTL(MSG_ARGDESC_EI_ABIVERSION_VALUE) */
		    ELFEDIT_I18NHDL(MSG_ARGDESC_EI_ABIVERSION_VALUE),
		    ELFEDIT_CMDOA_F_OPT, 0 },
		{ NULL }
	};




	static elfedit_cmd_t cmds[] = {
		/* ehdr:dump */
		{ cmd_dump, NULL, name_dump,
		    /* MSG_INTL(MSG_DESC_DUMP) */
		    ELFEDIT_I18NHDL(MSG_DESC_DUMP),
		    /* MSG_INTL(MSG_HELP_DUMP) */
		    ELFEDIT_I18NHDL(MSG_HELP_DUMP),
		    NULL, NULL },

		/* ehdr:e_ident */
		{ cmd_e_ident, cpl_e_ident, name_e_ident,
		    /* MSG_INTL(MSG_DESC_E_IDENT) */
		    ELFEDIT_I18NHDL(MSG_DESC_E_IDENT),
		    /* MSG_INTL(MSG_HELP_E_IDENT) */
		    ELFEDIT_I18NHDL(MSG_HELP_E_IDENT),
		    opt_std, arg_e_ident },

		/* ehdr:e_type */
		{ cmd_e_type, cpl_e_type, name_e_type,
		    /* MSG_INTL(MSG_DESC_E_TYPE) */
		    ELFEDIT_I18NHDL(MSG_DESC_E_TYPE),
		    /* MSG_INTL(MSG_HELP_E_TYPE) */
		    ELFEDIT_I18NHDL(MSG_HELP_E_TYPE),
		    opt_std, arg_e_type },

		/* ehdr:e_machine */
		{ cmd_e_machine, cpl_e_machine, name_e_machine,
		    /* MSG_INTL(MSG_DESC_E_MACHINE) */
		    ELFEDIT_I18NHDL(MSG_DESC_E_MACHINE),
		    /* MSG_INTL(MSG_HELP_E_MACHINE) */
		    ELFEDIT_I18NHDL(MSG_HELP_E_MACHINE),
		    opt_std, arg_e_machine },

		/* ehdr:e_version */
		{ cmd_e_version, cpl_e_version, name_e_version,
		    /* MSG_INTL(MSG_DESC_E_VERSION) */
		    ELFEDIT_I18NHDL(MSG_DESC_E_VERSION),
		    /* MSG_INTL(MSG_HELP_E_VERSION) */
		    ELFEDIT_I18NHDL(MSG_HELP_E_VERSION),
		    opt_std, arg_e_version },

		/* ehdr:e_entry */
		{ cmd_e_entry, NULL, name_e_entry,
		    /* MSG_INTL(MSG_DESC_E_ENTRY) */
		    ELFEDIT_I18NHDL(MSG_DESC_E_ENTRY),
		    /* MSG_INTL(MSG_HELP_E_ENTRY) */
		    ELFEDIT_I18NHDL(MSG_HELP_E_ENTRY),
		    opt_std, arg_e_entry },

		/* ehdr:e_phoff */
		{ cmd_e_phoff, NULL, name_e_phoff,
		    /* MSG_INTL(MSG_DESC_E_PHOFF) */
		    ELFEDIT_I18NHDL(MSG_DESC_E_PHOFF),
		    /* MSG_INTL(MSG_HELP_E_PHOFF) */
		    ELFEDIT_I18NHDL(MSG_HELP_E_PHOFF),
		    opt_std, arg_e_phoff },

		/* ehdr:e_shoff */
		{ cmd_e_shoff, NULL, name_e_shoff,
		    /* MSG_INTL(MSG_DESC_E_SHOFF) */
		    ELFEDIT_I18NHDL(MSG_DESC_E_SHOFF),
		    /* MSG_INTL(MSG_HELP_E_SHOFF) */
		    ELFEDIT_I18NHDL(MSG_HELP_E_SHOFF),
		    opt_std, arg_e_shoff },

		/* ehdr:e_flags */
		{ cmd_e_flags, cpl_e_flags, name_e_flags,
		    /* MSG_INTL(MSG_DESC_E_FLAGS) */
		    ELFEDIT_I18NHDL(MSG_DESC_E_FLAGS),
		    /* MSG_INTL(MSG_HELP_E_FLAGS) */
		    ELFEDIT_I18NHDL(MSG_HELP_E_FLAGS),
		    opt_e_flags, arg_e_flags },

		/* ehdr:e_ehsize */
		{ cmd_e_ehsize, NULL, name_e_ehsize,
		    /* MSG_INTL(MSG_DESC_E_EHSIZE) */
		    ELFEDIT_I18NHDL(MSG_DESC_E_EHSIZE),
		    /* MSG_INTL(MSG_HELP_E_EHSIZE) */
		    ELFEDIT_I18NHDL(MSG_HELP_E_EHSIZE),
		    opt_std, arg_e_ehsize },

		/* ehdr:e_phentsize */
		{ cmd_e_phentsize, NULL, name_e_phentsize,
		    /* MSG_INTL(MSG_DESC_E_PHENTSIZE) */
		    ELFEDIT_I18NHDL(MSG_DESC_E_PHENTSIZE),
		    /* MSG_INTL(MSG_HELP_E_PHENTSIZE) */
		    ELFEDIT_I18NHDL(MSG_HELP_E_PHENTSIZE),
		    opt_std, arg_e_phentsize },

		/* ehdr:e_phnum */
		{ cmd_e_phnum, NULL, name_e_phnum,
		    /* MSG_INTL(MSG_DESC_E_PHNUM) */
		    ELFEDIT_I18NHDL(MSG_DESC_E_PHNUM),
		    /* MSG_INTL(MSG_HELP_E_PHNUM) */
		    ELFEDIT_I18NHDL(MSG_HELP_E_PHNUM),
		    opt_std, arg_e_phnum },

		/* ehdr:e_shentsize */
		{ cmd_e_shentsize, NULL, name_e_shentsize,
		    /* MSG_INTL(MSG_DESC_E_SHENTSIZE) */
		    ELFEDIT_I18NHDL(MSG_DESC_E_SHENTSIZE),
		    /* MSG_INTL(MSG_HELP_E_SHENTSIZE) */
		    ELFEDIT_I18NHDL(MSG_HELP_E_SHENTSIZE),
		    opt_std, arg_e_shentsize },

		/* ehdr:e_shnum */
		{ cmd_e_shnum, NULL, name_e_shnum,
		    /* MSG_INTL(MSG_DESC_E_SHNUM) */
		    ELFEDIT_I18NHDL(MSG_DESC_E_SHNUM),
		    /* MSG_INTL(MSG_HELP_E_SHNUM) */
		    ELFEDIT_I18NHDL(MSG_HELP_E_SHNUM),
		    opt_std, arg_e_shnum },

		/* ehdr:e_shstrndx */
		{ cmd_e_shstrndx, cpl_e_shstrndx, name_e_shstrndx,
		    /* MSG_INTL(MSG_DESC_E_SHSTRNDX) */
		    ELFEDIT_I18NHDL(MSG_DESC_E_SHSTRNDX),
		    /* MSG_INTL(MSG_HELP_E_SHSTRNDX) */
		    ELFEDIT_I18NHDL(MSG_HELP_E_SHSTRNDX),
		    opt_e_shstrndx, arg_e_shstrndx },

		/* ehdr:ei_mag0 */
		{ cmd_ei_mag0, NULL, name_ei_mag0,
		    /* MSG_INTL(MSG_DESC_EI_MAG0) */
		    ELFEDIT_I18NHDL(MSG_DESC_EI_MAG0),
		    /* MSG_INTL(MSG_HELP_EI_MAG0) */
		    ELFEDIT_I18NHDL(MSG_HELP_EI_MAG0),
		    opt_std, arg_ei_mag0 },

		/* ehdr:ei_mag1 */
		{ cmd_ei_mag1, NULL, name_ei_mag1,
		    /* MSG_INTL(MSG_DESC_EI_MAG1) */
		    ELFEDIT_I18NHDL(MSG_DESC_EI_MAG1),
		    /* MSG_INTL(MSG_HELP_EI_MAG1) */
		    ELFEDIT_I18NHDL(MSG_HELP_EI_MAG1),
		    opt_std, arg_ei_mag1 },

		/* ehdr:ei_mag2 */
		{ cmd_ei_mag2, NULL, name_ei_mag2,
		    /* MSG_INTL(MSG_DESC_EI_MAG2) */
		    ELFEDIT_I18NHDL(MSG_DESC_EI_MAG2),
		    /* MSG_INTL(MSG_HELP_EI_MAG2) */
		    ELFEDIT_I18NHDL(MSG_HELP_EI_MAG2),
		    opt_std, arg_ei_mag2 },

		/* ehdr:ei_mag3 */
		{ cmd_ei_mag3, NULL, name_ei_mag3,
		    /* MSG_INTL(MSG_DESC_EI_MAG3) */
		    ELFEDIT_I18NHDL(MSG_DESC_EI_MAG3),
		    /* MSG_INTL(MSG_HELP_EI_MAG3) */
		    ELFEDIT_I18NHDL(MSG_HELP_EI_MAG3),
		    opt_std, arg_ei_mag3 },

		/* ehdr:ei_class */
		{ cmd_ei_class, cpl_ei_class, name_ei_class,
		    /* MSG_INTL(MSG_DESC_EI_CLASS) */
		    ELFEDIT_I18NHDL(MSG_DESC_EI_CLASS),
		    /* MSG_INTL(MSG_HELP_EI_CLASS) */
		    ELFEDIT_I18NHDL(MSG_HELP_EI_CLASS),
		    opt_std, arg_ei_class },

		/* ehdr:ei_data */
		{ cmd_ei_data, cpl_ei_data, name_ei_data,
		    /* MSG_INTL(MSG_DESC_EI_DATA) */
		    ELFEDIT_I18NHDL(MSG_DESC_EI_DATA),
		    /* MSG_INTL(MSG_HELP_EI_DATA) */
		    ELFEDIT_I18NHDL(MSG_HELP_EI_DATA),
		    opt_std, arg_ei_data },

		/* ehdr:ei_version */
		{ cmd_ei_version, cpl_e_version, name_ei_version,
		    /* MSG_INTL(MSG_DESC_EI_VERSION) */
		    ELFEDIT_I18NHDL(MSG_DESC_EI_VERSION),
		    /* MSG_INTL(MSG_HELP_EI_VERSION) */
		    ELFEDIT_I18NHDL(MSG_HELP_EI_VERSION),
		    opt_std, arg_e_version },

		/* ehdr:ei_osabi */
		{ cmd_ei_osabi, cpl_ei_osabi, name_ei_osabi,
		    /* MSG_INTL(MSG_DESC_EI_OSABI) */
		    ELFEDIT_I18NHDL(MSG_DESC_EI_OSABI),
		    /* MSG_INTL(MSG_HELP_EI_OSABI) */
		    ELFEDIT_I18NHDL(MSG_HELP_EI_OSABI),
		    opt_std, arg_ei_osabi },

		/* ehdr:ei_abiversion */
		{ cmd_ei_abiversion, cpl_ei_abiversion, name_ei_abiversion,
		    /* MSG_INTL(MSG_DESC_EI_ABIVERSION) */
		    ELFEDIT_I18NHDL(MSG_DESC_EI_ABIVERSION),
		    /* MSG_INTL(MSG_HELP_EI_ABIVERSION) */
		    ELFEDIT_I18NHDL(MSG_HELP_EI_ABIVERSION),
		    opt_std, arg_ei_abiversion },

		{ NULL }
	};

	static elfedit_module_t module = {
	    ELFEDIT_VER_CURRENT, MSG_ORIG(MSG_MOD_NAME),
	    /* MSG_INTL(MSG_MOD_DESC) */
	    ELFEDIT_I18NHDL(MSG_MOD_DESC),
	    cmds, mod_i18nhdl_to_str };

	return (&module);
}
