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

/*
 * Dump an elf file.
 */
#include	<sys/param.h>
#include	<fcntl.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<ctype.h>
#include	<libelf.h>
#include	<link.h>
#include	<stdarg.h>
#include	<unistd.h>
#include	<libgen.h>
#include	<libintl.h>
#include	<locale.h>
#include	<errno.h>
#include	<strings.h>
#include	<debug.h>
#include	<conv.h>
#include	<msg.h>
#include	<_elfdump.h>
#include	<sys/elf_SPARC.h>
#include	<sys/elf_amd64.h>


const Cache	cache_init = {NULL, NULL, NULL, NULL, 0};



/*
 * The -I, -N, and -T options are called "match options", because
 * they allow selecting the items to be displayed based on matching
 * their index, name, or type.
 *
 * The ELF information to which -I, -N, or -T are applied in
 * the current invocation is called the "match item".
 */
typedef enum {
	MATCH_ITEM_PT,		/* Program header (PT_) */
	MATCH_ITEM_SHT		/* Section header (SHT_) */
} match_item_t;

/* match_opt_t is  used to note which match option was used */
typedef enum {
	MATCH_OPT_NAME,		/* Record contains a name */
	MATCH_OPT_NDX,		/* Record contains a single index */
	MATCH_OPT_RANGE,	/* Record contains an index range */
	MATCH_OPT_TYPE,		/* Record contains a type (shdr or phdr) */
} match_opt_t;

typedef struct _match {
	struct _match	*next;		/* Pointer to next item in list */
	match_opt_t	opt_type;
	union {
		const char	*name;	/* MATCH_OPT_NAME */
		struct {		/* MATCH_OPT_NDX and MATCH_OPT_RANGE */
			int	start;
			int	end;	/* Only for MATCH_OPT_RANGE */
		} ndx;
		uint32_t	type;	/* MATCH_OPT_TYPE */
	} value;
} match_rec_t;

static struct {
	match_item_t	item_type;	/* Type of item being matched */
	match_rec_t	*list;		/* Records for (-I, -N, -T) options */
} match_state;



/* Map names to their integer value */
typedef struct {
	const char	*sym_name;
	uint32_t	sym_value;
} atoui_sym_t;

/*
 * ELF section types.
 */
static atoui_sym_t sym_sht[] = {
	{ MSG_ORIG(MSG_SHT_NULL),		SHT_NULL },
	{ MSG_ORIG(MSG_SHT_NULL_ALT1),		SHT_NULL },

	{ MSG_ORIG(MSG_SHT_PROGBITS),		SHT_PROGBITS },
	{ MSG_ORIG(MSG_SHT_PROGBITS_ALT1),	SHT_PROGBITS },

	{ MSG_ORIG(MSG_SHT_SYMTAB),		SHT_SYMTAB },
	{ MSG_ORIG(MSG_SHT_SYMTAB_ALT1),	SHT_SYMTAB },

	{ MSG_ORIG(MSG_SHT_STRTAB),		SHT_STRTAB },
	{ MSG_ORIG(MSG_SHT_STRTAB_ALT1),	SHT_STRTAB },

	{ MSG_ORIG(MSG_SHT_RELA),		SHT_RELA },
	{ MSG_ORIG(MSG_SHT_RELA_ALT1),		SHT_RELA },

	{ MSG_ORIG(MSG_SHT_HASH),		SHT_HASH },
	{ MSG_ORIG(MSG_SHT_HASH_ALT1),		SHT_HASH },

	{ MSG_ORIG(MSG_SHT_DYNAMIC),		SHT_DYNAMIC },
	{ MSG_ORIG(MSG_SHT_DYNAMIC_ALT1),	SHT_DYNAMIC },

	{ MSG_ORIG(MSG_SHT_NOTE),		SHT_NOTE },
	{ MSG_ORIG(MSG_SHT_NOTE_ALT1),		SHT_NOTE },

	{ MSG_ORIG(MSG_SHT_NOBITS),		SHT_NOBITS },
	{ MSG_ORIG(MSG_SHT_NOBITS_ALT1),	SHT_NOBITS },

	{ MSG_ORIG(MSG_SHT_REL),		SHT_REL },
	{ MSG_ORIG(MSG_SHT_REL_ALT1),		SHT_REL },

	{ MSG_ORIG(MSG_SHT_SHLIB),		SHT_SHLIB },
	{ MSG_ORIG(MSG_SHT_SHLIB_ALT1),		SHT_SHLIB },

	{ MSG_ORIG(MSG_SHT_DYNSYM),		SHT_DYNSYM },
	{ MSG_ORIG(MSG_SHT_DYNSYM_ALT1),	SHT_DYNSYM },

	{ MSG_ORIG(MSG_SHT_INIT_ARRAY),		SHT_INIT_ARRAY },
	{ MSG_ORIG(MSG_SHT_INIT_ARRAY_ALT1),	SHT_INIT_ARRAY },

	{ MSG_ORIG(MSG_SHT_FINI_ARRAY),		SHT_FINI_ARRAY },
	{ MSG_ORIG(MSG_SHT_FINI_ARRAY_ALT1),	SHT_FINI_ARRAY },

	{ MSG_ORIG(MSG_SHT_PREINIT_ARRAY),	SHT_PREINIT_ARRAY },
	{ MSG_ORIG(MSG_SHT_PREINIT_ARRAY_ALT1),	SHT_PREINIT_ARRAY },

	{ MSG_ORIG(MSG_SHT_GROUP),		SHT_GROUP },
	{ MSG_ORIG(MSG_SHT_GROUP_ALT1),		SHT_GROUP },

	{ MSG_ORIG(MSG_SHT_SYMTAB_SHNDX),	SHT_SYMTAB_SHNDX },
	{ MSG_ORIG(MSG_SHT_SYMTAB_SHNDX_ALT1),	SHT_SYMTAB_SHNDX },

	{ MSG_ORIG(MSG_SHT_SUNW_SYMSORT),	SHT_SUNW_symsort },
	{ MSG_ORIG(MSG_SHT_SUNW_SYMSORT_ALT1),	SHT_SUNW_symsort },

	{ MSG_ORIG(MSG_SHT_SUNW_TLSSORT),	SHT_SUNW_tlssort },
	{ MSG_ORIG(MSG_SHT_SUNW_TLSSORT_ALT1),	SHT_SUNW_tlssort },

	{ MSG_ORIG(MSG_SHT_SUNW_LDYNSYM),	SHT_SUNW_LDYNSYM },
	{ MSG_ORIG(MSG_SHT_SUNW_LDYNSYM_ALT1),	SHT_SUNW_LDYNSYM },

	{ MSG_ORIG(MSG_SHT_SUNW_DOF),		SHT_SUNW_dof },
	{ MSG_ORIG(MSG_SHT_SUNW_DOF_ALT1),	SHT_SUNW_dof },

	{ MSG_ORIG(MSG_SHT_SUNW_CAP),		SHT_SUNW_cap },
	{ MSG_ORIG(MSG_SHT_SUNW_CAP_ALT1),	SHT_SUNW_cap },

	{ MSG_ORIG(MSG_SHT_SUNW_SIGNATURE),	SHT_SUNW_SIGNATURE },
	{ MSG_ORIG(MSG_SHT_SUNW_SIGNATURE_ALT1), SHT_SUNW_SIGNATURE },

	{ MSG_ORIG(MSG_SHT_SUNW_ANNOTATE),	SHT_SUNW_ANNOTATE },
	{ MSG_ORIG(MSG_SHT_SUNW_ANNOTATE_ALT1),	SHT_SUNW_ANNOTATE },

	{ MSG_ORIG(MSG_SHT_SUNW_DEBUGSTR),	SHT_SUNW_DEBUGSTR },
	{ MSG_ORIG(MSG_SHT_SUNW_DEBUGSTR_ALT1),	SHT_SUNW_DEBUGSTR },

	{ MSG_ORIG(MSG_SHT_SUNW_DEBUG),		SHT_SUNW_DEBUG },
	{ MSG_ORIG(MSG_SHT_SUNW_DEBUG_ALT1),	SHT_SUNW_DEBUG },

	{ MSG_ORIG(MSG_SHT_SUNW_MOVE),		SHT_SUNW_move },
	{ MSG_ORIG(MSG_SHT_SUNW_MOVE_ALT1),	SHT_SUNW_move },

	{ MSG_ORIG(MSG_SHT_SUNW_COMDAT),	SHT_SUNW_COMDAT },
	{ MSG_ORIG(MSG_SHT_SUNW_COMDAT_ALT1),	SHT_SUNW_COMDAT },

	{ MSG_ORIG(MSG_SHT_SUNW_SYMINFO),	SHT_SUNW_syminfo },
	{ MSG_ORIG(MSG_SHT_SUNW_SYMINFO_ALT1),	SHT_SUNW_syminfo },

	{ MSG_ORIG(MSG_SHT_SUNW_VERDEF),	SHT_SUNW_verdef },
	{ MSG_ORIG(MSG_SHT_SUNW_VERDEF_ALT1),	SHT_SUNW_verdef },

	{ MSG_ORIG(MSG_SHT_GNU_VERDEF),		SHT_GNU_verdef },
	{ MSG_ORIG(MSG_SHT_GNU_VERDEF_ALT1),	SHT_GNU_verdef },

	{ MSG_ORIG(MSG_SHT_SUNW_VERNEED),	SHT_SUNW_verneed },
	{ MSG_ORIG(MSG_SHT_SUNW_VERNEED_ALT1),	SHT_SUNW_verneed },

	{ MSG_ORIG(MSG_SHT_GNU_VERNEED),	SHT_GNU_verneed },
	{ MSG_ORIG(MSG_SHT_GNU_VERNEED_ALT1),	SHT_GNU_verneed },

	{ MSG_ORIG(MSG_SHT_SUNW_VERSYM),	SHT_SUNW_versym },
	{ MSG_ORIG(MSG_SHT_SUNW_VERSYM_ALT1),	SHT_SUNW_versym },

	{ MSG_ORIG(MSG_SHT_GNU_VERSYM),		SHT_GNU_versym },
	{ MSG_ORIG(MSG_SHT_GNU_VERSYM_ALT1),	SHT_GNU_versym },

	{ MSG_ORIG(MSG_SHT_SPARC_GOTDATA),	SHT_SPARC_GOTDATA },
	{ MSG_ORIG(MSG_SHT_SPARC_GOTDATA_ALT1),	SHT_SPARC_GOTDATA },

	{ MSG_ORIG(MSG_SHT_AMD64_UNWIND),	SHT_AMD64_UNWIND },
	{ MSG_ORIG(MSG_SHT_AMD64_UNWIND_ALT1),	SHT_AMD64_UNWIND },

	{ NULL }
};

/*
 * Program header PT_* type values
 */
static atoui_sym_t sym_pt[] = {
	{ MSG_ORIG(MSG_PT_NULL),		PT_NULL },
	{ MSG_ORIG(MSG_PT_NULL_ALT1),		PT_NULL },

	{ MSG_ORIG(MSG_PT_LOAD),		PT_LOAD },
	{ MSG_ORIG(MSG_PT_LOAD_ALT1),		PT_LOAD },

	{ MSG_ORIG(MSG_PT_DYNAMIC),		PT_DYNAMIC },
	{ MSG_ORIG(MSG_PT_DYNAMIC_ALT1),	PT_DYNAMIC },

	{ MSG_ORIG(MSG_PT_INTERP),		PT_INTERP },
	{ MSG_ORIG(MSG_PT_INTERP_ALT1),		PT_INTERP },

	{ MSG_ORIG(MSG_PT_NOTE),		PT_NOTE },
	{ MSG_ORIG(MSG_PT_NOTE_ALT1),		PT_NOTE },

	{ MSG_ORIG(MSG_PT_SHLIB),		PT_SHLIB },
	{ MSG_ORIG(MSG_PT_SHLIB_ALT1),		PT_SHLIB },

	{ MSG_ORIG(MSG_PT_PHDR),		PT_PHDR },
	{ MSG_ORIG(MSG_PT_PHDR_ALT1),		PT_PHDR },

	{ MSG_ORIG(MSG_PT_TLS),			PT_TLS },
	{ MSG_ORIG(MSG_PT_TLS_ALT1),		PT_TLS },

	{ MSG_ORIG(MSG_PT_SUNW_UNWIND),		PT_SUNW_UNWIND },
	{ MSG_ORIG(MSG_PT_SUNW_UNWIND_ALT1),	PT_SUNW_UNWIND },

	{ MSG_ORIG(MSG_PT_SUNWBSS),		PT_SUNWBSS },
	{ MSG_ORIG(MSG_PT_SUNWBSS_ALT1),	PT_SUNWBSS },

	{ MSG_ORIG(MSG_PT_SUNWSTACK),		PT_SUNWSTACK },
	{ MSG_ORIG(MSG_PT_SUNWSTACK_ALT1),	PT_SUNWSTACK },

	{ MSG_ORIG(MSG_PT_SUNWDTRACE),		PT_SUNWDTRACE },
	{ MSG_ORIG(MSG_PT_SUNWDTRACE_ALT1),	PT_SUNWDTRACE },

	{ MSG_ORIG(MSG_PT_SUNWCAP),		PT_SUNWCAP },
	{ MSG_ORIG(MSG_PT_SUNWCAP_ALT1),	PT_SUNWCAP },

	{ NULL }
};





const char *
_elfdump_msg(Msg mid)
{
	return (gettext(MSG_ORIG(mid)));
}

/*
 * Determine whether a symbol name should be demangled.
 */
const char *
demangle(const char *name, uint_t flags)
{
	if (flags & FLG_CTL_DEMANGLE)
		return (Elf_demangle_name(name));
	else
		return ((char *)name);
}

/*
 * Define our own standard error routine.
 */
void
failure(const char *file, const char *func)
{
	(void) fprintf(stderr, MSG_INTL(MSG_ERR_FAILURE),
	    file, func, elf_errmsg(elf_errno()));
}

/*
 * The full usage message
 */
static void
detail_usage()
{
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL1));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL2));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL3));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL4));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL5));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL6));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL7));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL8));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL9));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL10));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL11));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL12));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL13));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL14));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL15));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL16));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL17));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL18));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL19));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL20));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL21));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL22));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL23));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL24));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL25));
}

/*
 * Output a block of raw data as hex bytes. Each row is given
 * the index of the first byte in the row.
 *
 * entry:
 *	data - Pointer to first byte of data to be displayed
 *	n - # of bytes of data
 *	prefix - String to be output before each line. Useful
 *		for indenting output.
 *	bytes_per_col - # of space separated bytes to output
 *		in each column.
 *	col_per_row - # of columns to output per row
 *
 * exit:
 *	The formatted data has been sent to stdout. Each row of output
 *	shows (bytes_per_col * col_per_row) bytes of data.
 */
void
dump_hex_bytes(const char *data, size_t n, int indent,
	int bytes_per_col, int col_per_row)
{
	int	bytes_per_row = bytes_per_col * col_per_row;
	int	ndx, byte, word;
	char	string[128], *str = string;
	char	index[MAXNDXSIZE];
	int	index_width;
	int	sp_prefix = 0;


	/*
	 * Determine the width to use for the index string. We follow
	 * 8-byte tab rules, but don't use an actual \t character so
	 * that the output can be arbitrarily shifted without odd
	 * tab effects, and so that all the columns line up no matter
	 * how many lines of output are produced.
	 */
	ndx = n / bytes_per_row;
	(void) snprintf(index, sizeof (index),
	    MSG_ORIG(MSG_FMT_INDEX2), EC_WORD(ndx));
	index_width = strlen(index);
	index_width = S_ROUND(index_width, 8);

	for (ndx = byte = word = 0; n > 0; n--, data++) {
		while (sp_prefix-- > 0)
			*str++ = ' ';

		(void) snprintf(str, sizeof (string),
		    MSG_ORIG(MSG_HEXDUMP_TOK), (int)*data);
		str += 2;
		sp_prefix = 1;

		if (++byte == bytes_per_col) {
			sp_prefix += 2;
			word++;
			byte = 0;
		}
		if (word == col_per_row) {
			*str = '\0';
			(void) snprintf(index, sizeof (index),
			    MSG_ORIG(MSG_FMT_INDEX2), EC_WORD(ndx));
			dbg_print(0, MSG_ORIG(MSG_HEXDUMP_ROW),
			    indent, MSG_ORIG(MSG_STR_EMPTY),
			    index_width, index, string);
			sp_prefix = 0;
			word = 0;
			ndx += bytes_per_row;
			str = string;
		}
	}
	if (byte || word) {
		*str = '\0';	/*  */
		(void) snprintf(index, sizeof (index),
		    MSG_ORIG(MSG_FMT_INDEX2), EC_WORD(ndx));
		dbg_print(0, MSG_ORIG(MSG_HEXDUMP_ROW), indent,
		    MSG_ORIG(MSG_STR_EMPTY), index_width, index, string);
	}
}

/*
 * Convert the ASCII representation of an index, or index range, into
 * binary form, and store it in rec:
 *
 *	index: An positive or 0 valued integer
 *	range: Two indexes, separated by a ':' character, denoting
 *		a range of allowed values. If the second value is omitted,
 *		any values equal to or greater than the first will match.
 *
 * exit:
 *	On success, *rec is filled in with a MATCH_OPT_NDX or MATCH_OPT_RANGE
 *	value, and this function returns (1). On failure, the contents
 *	of *rec are undefined, and (0) is returned.
 */
int
process_index_opt(const char *str, match_rec_t *rec)
{
#define	SKIP_BLANK for (; *str && isspace(*str); str++)

	char	*endptr;

	rec->value.ndx.start = strtol(str, &endptr, 10);
	/* Value must use some of the input, and be 0 or positive */
	if ((str == endptr) || (rec->value.ndx.start < 0))
		return (0);
	str = endptr;

	SKIP_BLANK;
	if (*str != ':') {
		rec->opt_type = MATCH_OPT_NDX;
	} else {
		str++;					/* Skip the ':' */
		rec->opt_type = MATCH_OPT_RANGE;
		SKIP_BLANK;
		if (*str == '\0') {
			rec->value.ndx.end = -1;	/* Indicates "to end" */
		} else {
			rec->value.ndx.end = strtol(str, &endptr, 10);
			if ((str == endptr) || (rec->value.ndx.end < 0))
				return (0);
			str = endptr;
			SKIP_BLANK;
		}
	}

	/* Syntax error if anything is left over */
	if (*str != '\0')
		return (0);

	return (1);

#undef	SKIP_BLANK
}

/*
 * Process the symbolic name to value mappings passed to the
 * atoui() function.
 *
 * entry:
 *	sym - NULL terminated array of name->value mappings.
 *	value - Address of variable to receive corresponding value.
 *
 * exit:
 *	If a mapping is found, *value is set to it, and True is returned.
 *	Otherwise False is returned.
 */
static int
atoui_sym_process(const char *str, const atoui_sym_t *sym, uint32_t *value)
{
	size_t		cmp_len;
	const char	*tail;

	while (isspace(*str))
		str++;

	tail = str + strlen(str);
	while ((tail > str) && isspace(*(tail - 1)))
		tail--;

	cmp_len = tail - str;

	for (; sym->sym_name != NULL; sym++) {
		if ((strlen(sym->sym_name) == cmp_len) &&
		    (strncasecmp(sym->sym_name, str, cmp_len) == 0)) {
			*value = sym->sym_value;
			return (1);
		}
	}

	/* No symbolic mapping was found */
	return (0);
}


/*
 * Convert a string to a numeric value. Strings starting with '0'
 * are taken to be octal, those staring with '0x' are hex, and all
 * others are decimal.
 *
 * entry:
 *	str - String to be converted
 *	sym - NULL, or NULL terminated array of name/value pairs.
 *	v - Address of variable to receive resulting value.
 *
 * exit:
 *	On success, returns True (1) and *v is set to the value.
 *	On failure, returns False (0) and *v is undefined.
 */
static int
atoui(const char *str, const atoui_sym_t *sym, uint32_t *v)
{
	char		*endptr;

	if (sym && atoui_sym_process(str, sym, v))
		return (1);

	*v = strtoull(str, &endptr, 0);

	/* If the left over part contains anything but whitespace, fail */
	for (; *endptr; endptr++)
		if (!isspace(*endptr))
			return (0);
	return (1);
}

/*
 * Called after getopt() processing is finished if there is a non-empty
 * match list. Prepares the matching code for use.
 *
 * exit:
 *	Returns True (1) if no errors are encountered. Writes an
 *	error string to stderr and returns False (0) otherwise.
 */
static int
match_prepare(char *argv0, uint_t flags)
{
	atoui_sym_t	*sym;
	match_rec_t	*list;
	const char	*str;
	int		minus_p = (flags & FLG_SHOW_PHDR) != 0;

	/*
	 * Flag ambiguous attempt to use match option with both -p and
	 * and one or more section SHOW options. In this case, we
	 * can't tell what type of item we're supposed to match against.
	 */
	if (minus_p && (flags & FLG_MASK_SHOW_SHDR)) {
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_AMBIG_MATCH),
		    basename(argv0));
		return (0);
	}

	/* Set the match type, based on the presence of the -p option */
	if (minus_p) {
		match_state.item_type = MATCH_ITEM_PT;
		sym = sym_pt;
	} else {
		match_state.item_type = MATCH_ITEM_SHT;
		sym = sym_sht;
	}

	/*
	 * Scan match list and perform any necessary fixups:
	 *
	 * MATCH_OPT_NAME: If -p is specified, convert MATCH_OPT_NAME (-N)
	 *	requests into MATCH_OPT_TYPE (-T).
	 *
	 * MATCH_OPT_TYPE: Now that we know item type we are matching
	 *	against, we can convert the string saved in the name
	 *	field during getopt() processing into an integer and
	 *	write it into the type field.
	 */
	for (list = match_state.list; list; list = list->next) {
		if ((list->opt_type == MATCH_OPT_NAME) && minus_p)
			list->opt_type = MATCH_OPT_TYPE;

		if (list->opt_type != MATCH_OPT_TYPE)
			continue;

		str = list->value.name;
		if (atoui(str, sym, &list->value.type) == 0) {
			const char *fmt = minus_p ?
			    MSG_INTL(MSG_ERR_BAD_T_PT) :
			    MSG_INTL(MSG_ERR_BAD_T_SHT);

			(void) fprintf(stderr, fmt, basename(argv0), str);
			return (0);
		}
	}

	return (1);
}


/*
 * Returns True (1) if the item with the given name or index should
 * be displayed, and False (0) if it should not be.
 *
 * entry:
 *	match_flags - Bitmask specifying matching options, as described
 *		in _elfdump.h.
 *	name - If MATCH_F_NAME flag is set, name of item under
 *		consideration. Otherwise ignored.
 *		should not be considered.
 *	ndx - If MATCH_F_NDX flag is set, index of item under consideration.
 *	type - If MATCH_F_TYPE is set, type of item under consideration.
 *		If MATCH_F_PHDR is set, this would be a program
 *		header type (PT_). Otherwise, a section header type (SHT_).
 *
 * exit:
 *	True will be returned if the given name/index matches those given
 *	by one of the (-I, -N -T) command line options, or if no such option
 *	was used in the command invocation and MATCH_F_STRICT is not
 *	set.
 */
int
match(match_flags_t match_flags, const char *name, uint_t ndx, uint_t type)
{
	match_item_t item_type = (match_flags & MATCH_F_PHDR) ?
	    MATCH_ITEM_PT  : MATCH_ITEM_SHT;
	match_rec_t *list;

	/*
	 * If there is no match list, then we use the MATCH_F_STRICT
	 * flag to decide what to return. In the strict case, we return
	 * False (0), in the normal case, True (1).
	 */
	if (match_state.list == NULL)
		return ((match_flags & MATCH_F_STRICT) == 0);

	/*
	 * If item being checked is not the current match type,
	 * then allow it.
	 */
	if (item_type != match_state.item_type)
		return (1);

	/* Run through the match records and check for a hit */
	for (list = match_state.list; list; list = list->next) {
		switch (list->opt_type) {
		case MATCH_OPT_NAME:
			if (((match_flags & MATCH_F_NAME) == 0) ||
			    (name == NULL))
				break;
			if (strcmp(list->value.name, name) == 0)
				return (1);
			break;
		case MATCH_OPT_NDX:
			if ((match_flags & MATCH_F_NDX) &&
			    (ndx == list->value.ndx.start))
				return (1);
			break;
		case MATCH_OPT_RANGE:
			/*
			 * A range end value less than 0 means that any value
			 * above the start is acceptible.
			 */
			if ((match_flags & MATCH_F_NDX) &&
			    (ndx >= list->value.ndx.start) &&
			    ((list->value.ndx.end < 0) ||
			    (ndx <= list->value.ndx.end)))
				return (1);
			break;

		case MATCH_OPT_TYPE:
			if ((match_flags & MATCH_F_TYPE) &&
			    (type == list->value.type))
				return (1);
			break;
		}
	}

	/* Nothing matched */
	return (0);
}

/*
 * Add an entry to match_state.list for use by match(). This routine is for
 * use during getopt() processing. It should not be called once
 * match_prepare() has been called.
 *
 * Return True (1) for success. On failure, an error is written
 * to stderr, and False (0) is returned.
 */
static int
add_match_record(char *argv0, match_rec_t *data)
{
	match_rec_t	*rec;
	match_rec_t	*list;

	if ((rec = malloc(sizeof (*rec))) == NULL) {
		int err = errno;
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_MALLOC),
		    basename(argv0), strerror(err));
		return (0);
	}

	*rec = *data;

	/* Insert at end of match_state.list */
	if (match_state.list == NULL) {
		match_state.list = rec;
	} else {
		for (list = match_state.list; list->next != NULL;
		    list = list->next)
			;
		list->next = rec;
	}

	rec->next = NULL;
	return (1);
}

static int
decide(const char *file, int fd, Elf *elf, uint_t flags,
    const char *wname, int wfd)
{
	int r;

	if (gelf_getclass(elf) == ELFCLASS64)
		r = regular64(file, fd, elf, flags, wname, wfd);
	else
		r = regular32(file, fd, elf, flags, wname, wfd);

	return (r);
}

static int
archive(const char *file, int fd, Elf *elf, uint_t flags,
    const char *wname, int wfd)
{
	Elf_Cmd		cmd = ELF_C_READ;
	Elf_Arhdr	*arhdr;
	Elf		*_elf = 0;
	size_t		ptr;
	Elf_Arsym	*arsym = 0;

	/*
	 * Determine if the archive symbol table itself is required.
	 */
	if ((flags & FLG_SHOW_SYMBOLS) &&
	    match(MATCH_F_NAME, MSG_ORIG(MSG_ELF_ARSYM), 0, 0)) {
		/*
		 * Get the archive symbol table.
		 */
		if (((arsym = elf_getarsym(elf, &ptr)) == 0) && elf_errno()) {
			/*
			 * The arsym could be 0 even though there was no error.
			 * Print the error message only when there was
			 * real error from elf_getarsym().
			 */
			failure(file, MSG_ORIG(MSG_ELF_GETARSYM));
			return (0);
		}
	}

	/*
	 * Print the archive symbol table only when the archive symbol
	 * table exists and it was requested to print.
	 */
	if (arsym) {
		size_t		cnt;
		char		index[MAXNDXSIZE];
		size_t		offset = 0, _offset = 0;

		/*
		 * Print out all the symbol entries.
		 */
		dbg_print(0, MSG_INTL(MSG_ARCHIVE_SYMTAB));
		dbg_print(0, MSG_INTL(MSG_ARCHIVE_FIELDS));

		for (cnt = 0; cnt < ptr; cnt++, arsym++) {
			/*
			 * For each object obtain an elf descriptor so that we
			 * can establish the members name.  Note, we have had
			 * archives where the archive header has not been
			 * obtainable so be lenient with errors.
			 */
			if ((offset == 0) || ((arsym->as_off != 0) &&
			    (arsym->as_off != _offset))) {

				if (_elf)
					(void) elf_end(_elf);

				if (elf_rand(elf, arsym->as_off) !=
				    arsym->as_off) {
					failure(file, MSG_ORIG(MSG_ELF_RAND));
					arhdr = 0;
				} else if ((_elf = elf_begin(fd,
				    ELF_C_READ, elf)) == 0) {
					failure(file, MSG_ORIG(MSG_ELF_BEGIN));
					arhdr = 0;
				} else if ((arhdr = elf_getarhdr(_elf)) == 0) {
					failure(file,
					    MSG_ORIG(MSG_ELF_GETARHDR));
					arhdr = 0;
				}

				_offset = arsym->as_off;
				if (offset == 0)
					offset = _offset;
			}

			(void) snprintf(index, MAXNDXSIZE,
			    MSG_ORIG(MSG_FMT_INDEX), EC_XWORD(cnt));
			if (arsym->as_off)
				dbg_print(0, MSG_ORIG(MSG_FMT_ARSYM1), index,
				    /* LINTED */
				    (int)arsym->as_off, arhdr ? arhdr->ar_name :
				    MSG_INTL(MSG_STR_UNKNOWN), (arsym->as_name ?
				    demangle(arsym->as_name, flags) :
				    MSG_INTL(MSG_STR_NULL)));
			else
				dbg_print(0, MSG_ORIG(MSG_FMT_ARSYM2), index,
				    /* LINTED */
				    (int)arsym->as_off);
		}

		if (_elf)
			(void) elf_end(_elf);

		/*
		 * If we only need the archive symbol table return.
		 */
		if ((flags & FLG_SHOW_SYMBOLS) &&
		    match(MATCH_F_STRICT | MATCH_F_NAME,
		    MSG_ORIG(MSG_ELF_ARSYM), -1, -1))
			return (0);

		/*
		 * Reset elf descriptor in preparation for processing each
		 * member.
		 */
		if (offset)
			(void) elf_rand(elf, offset);
	}

	/*
	 * Process each object within the archive.
	 */
	while ((_elf = elf_begin(fd, cmd, elf)) != NULL) {
		char	name[MAXPATHLEN];

		if ((arhdr = elf_getarhdr(_elf)) == NULL) {
			failure(file, MSG_ORIG(MSG_ELF_GETARHDR));
			return (0);
		}
		if (*arhdr->ar_name != '/') {
			(void) snprintf(name, MAXPATHLEN,
			    MSG_ORIG(MSG_FMT_ARNAME), file, arhdr->ar_name);
			dbg_print(0, MSG_ORIG(MSG_FMT_NLSTR), name);

			switch (elf_kind(_elf)) {
			case ELF_K_AR:
				if (archive(name, fd, _elf, flags,
				    wname, wfd) == 1)
					return (1);
				break;
			case ELF_K_ELF:
				if (decide(name, fd, _elf, flags,
				    wname, wfd) == 1)
					return (1);
				break;
			default:
				(void) fprintf(stderr,
				    MSG_INTL(MSG_ERR_BADFILE), name);
				break;
			}
		}

		cmd = elf_next(_elf);
		(void) elf_end(_elf);
	}

	return (0);
}

int
main(int argc, char **argv, char **envp)
{
	Elf		*elf;
	int		var, fd, wfd = 0;
	char		*wname = NULL;
	uint_t		flags = 0;
	match_rec_t	match_data;
	int		ret;

	/*
	 * If we're on a 64-bit kernel, try to exec a full 64-bit version of
	 * the binary.  If successful, conv_check_native() won't return.
	 */
	(void) conv_check_native(argv, envp);

	/*
	 * Establish locale.
	 */
	(void) setlocale(LC_MESSAGES, MSG_ORIG(MSG_STR_EMPTY));
	(void) textdomain(MSG_ORIG(MSG_SUNW_OST_SGS));

	(void) setvbuf(stdout, NULL, _IOLBF, 0);
	(void) setvbuf(stderr, NULL, _IOLBF, 0);

	opterr = 0;
	while ((var = getopt(argc, argv, MSG_ORIG(MSG_STR_OPTIONS))) != EOF) {
		switch (var) {
		case 'C':
			flags |= FLG_CTL_DEMANGLE;
			break;
		case 'c':
			flags |= FLG_SHOW_SHDR;
			break;
		case 'd':
			flags |= FLG_SHOW_DYNAMIC;
			break;
		case 'e':
			flags |= FLG_SHOW_EHDR;
			break;
		case 'G':
			flags |= FLG_SHOW_GOT;
			break;
		case 'g':
			flags |= FLG_SHOW_GROUP;
			break;
		case 'H':
			flags |= FLG_SHOW_CAP;
			break;
		case 'h':
			flags |= FLG_SHOW_HASH;
			break;
		case 'I':
			if (!process_index_opt(optarg, &match_data))
				goto usage_brief;
			if (!add_match_record(argv[0], &match_data))
				return (1);
			flags |= FLG_CTL_MATCH;
			break;
		case 'i':
			flags |= FLG_SHOW_INTERP;
			break;
		case 'k':
			flags |= FLG_CALC_CHECKSUM;
			break;
		case 'l':
			flags |= FLG_CTL_LONGNAME;
			break;
		case 'm':
			flags |= FLG_SHOW_MOVE;
			break;
		case 'N':
			match_data.opt_type = MATCH_OPT_NAME;
			match_data.value.name = optarg;
			if (!add_match_record(argv[0], &match_data))
				return (1);
			flags |= FLG_CTL_MATCH;
			break;
		case 'n':
			flags |= FLG_SHOW_NOTE;
			break;
		case 'P':
			flags |= FLG_CTL_FAKESHDR;
			break;
		case 'p':
			flags |= FLG_SHOW_PHDR;
			break;
		case 'r':
			flags |= FLG_SHOW_RELOC;
			break;
		case 'S':
			flags |= FLG_SHOW_SORT;
			break;
		case 's':
			flags |= FLG_SHOW_SYMBOLS;
			break;
		case 'T':
			/*
			 * We can't evaluate the value yet, because
			 * we need to know if -p is used or not in
			 * order to tell if we're seeing section header
			 * or program header types. So, we save the
			 * string in the name field, and then convert
			 * it to a type integer in a following pass.
			 */
			match_data.opt_type = MATCH_OPT_TYPE;
			match_data.value.name = optarg;
			if (!add_match_record(argv[0], &match_data))
				return (1);
			flags |= FLG_CTL_MATCH;
			break;
		case 'u':
			flags |= FLG_SHOW_UNWIND;
			break;
		case 'v':
			flags |= FLG_SHOW_VERSIONS;
			break;
		case 'w':
			wname = optarg;
			break;
		case 'y':
			flags |= FLG_SHOW_SYMINFO;
			break;
		case '?':
			(void) fprintf(stderr, MSG_INTL(MSG_USAGE_BRIEF),
			    basename(argv[0]));
			detail_usage();
			return (1);
		default:
			break;
		}
	}

	/* -p and -w are mutually exclusive. -w only works with sections */
	if (((flags & FLG_SHOW_PHDR) != 0) && (wname != NULL))
		goto usage_brief;

	/* If a match argument is present, prepare the match state */
	if ((match_state.list != NULL) && (match_prepare(argv[0], flags) == 0))
		return (1);

	/*
	 * Decide what to do if no options specifying something to
	 * show or do are present.
	 *
	 * If there is no -w and no match options, then we will set all
	 * the show flags, causing a full display of everything in the
	 * file that we know how to handle.
	 *
	 * Otherwise, if there is no match list, we generate a usage
	 * error and quit.
	 *
	 * In the case where there is a match list, we go ahead and call
	 * regular() anyway, leaving it to decide what to do. If -w is
	 * present, regular() will use the match list to handle it.
	 * In addition, in the absence of explicit show/calc flags, regular()
	 * will compare the section headers to the match list and use
	 * that to generate the FLG_ bits that will display the information
	 * specified by the match list.
	 */
	if ((flags & ~FLG_MASK_CTL) == 0) {
		if (!wname && (match_state.list == NULL))
			flags |= FLG_MASK_SHOW;
		else if (match_state.list == NULL)
			goto usage_brief;
	}

	/* There needs to be at least 1 filename left following the options */
	if ((var = argc - optind) == 0)
		goto usage_brief;

	/*
	 * If the -l/-C option is specified, set up the liblddbg.so.
	 */
	if (flags & FLG_CTL_LONGNAME)
		dbg_desc->d_extra |= DBG_E_LONG;
	if (flags & FLG_CTL_DEMANGLE)
		dbg_desc->d_extra |= DBG_E_DEMANGLE;

	/*
	 * If the -w option has indicated an output file open it.  It's
	 * arguable whether this option has much use when multiple files are
	 * being processed.
	 *
	 * If wname is non-NULL, we know that -p was not specified, due
	 * to the test above.
	 */
	if (wname) {
		if ((wfd = open(wname, (O_RDWR | O_CREAT | O_TRUNC),
		    0666)) < 0) {
			int err = errno;
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_OPEN),
			    wname, strerror(err));
			return (1);
		}
	}

	/*
	 * Open the input file, initialize the elf interface, and
	 * process it.
	 */
	ret = 0;
	for (; (optind < argc) && (ret == 0); optind++) {
		const char	*file = argv[optind];

		if ((fd = open(argv[optind], O_RDONLY)) == -1) {
			int err = errno;
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_OPEN),
			    file, strerror(err));
			continue;
		}
		(void) elf_version(EV_CURRENT);
		if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL) {
			failure(file, MSG_ORIG(MSG_ELF_BEGIN));
			(void) close(fd);
			continue;
		}

		if (var > 1)
			dbg_print(0, MSG_ORIG(MSG_FMT_NLSTRNL), file);

		switch (elf_kind(elf)) {
		case ELF_K_AR:
			ret = archive(file, fd, elf, flags, wname, wfd);
			break;
		case ELF_K_ELF:
			ret = decide(file, fd, elf, flags, wname, wfd);
			break;
		default:
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADFILE), file);
			break;
		}

		(void) close(fd);
		(void) elf_end(elf);
	}

	if (wfd)
		(void) close(wfd);
	return (ret);

usage_brief:
	/* Control comes here for a simple usage message and exit */
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_BRIEF),
	    basename(argv[0]));
	return (1);

}
