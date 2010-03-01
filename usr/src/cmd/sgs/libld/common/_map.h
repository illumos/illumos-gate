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

/*
 * Local include file for libld mapfile subsystem.
 */

#ifndef	_MAP_DOT_H
#define	_MAP_DOT_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Macro used to size name buffer corresponding to a NULL terminated array
 * of structures each of which contains a name string. Macro is used per-name.
 * 2 extra characters are allowed per item to allow for a ', ' delimiter
 * or NULL termination.
 */
#define	KW_NAME_SIZE(_size) (_size##_SIZE + 2)

/*
 * Variant of isspace() that excludes newline characters. Requires <ctype.h>.
 */
#define	isspace_nonl(_s) (isspace(_s) && ((_s) != '\n'))

/*
 * Type used to insert NULL characters in the mapfile text and later
 * back them out and restore the original character. The mapfile text
 * is held in a single string, so when we want to access sub-strings,
 * it is necessary to temporarily insert NULLs to prevent the entire
 * mapfile from that point forward being output.
 */
typedef struct {
	char	*np_ptr;	/* Address patched with NULL character */
	char	np_ch;		/* Character originally found at *np_ptr */
} ld_map_npatch_t;

/*
 * ld_map_gettoken() uses a table of 128 bytes to determine how to
 * process a token starting with any 7-bit ASCII value. The table is
 * indexed by the character code, and returns one of the TK_* token values.
 */
typedef const char mf_tokdisp_t[128];

/*
 * The definition of an unquoted identifier differs based on the mapfile
 * version. Rather than write a separate function to locate identifiers
 * for each version, we use a single function that relies on a per-character
 * table that encodes which characters can start an identifier, and which
 * can continue one, for each supported mapfile version.
 *
 * Two bits are used for each version, one for the start attribute, and the
 * other for continuation. The first two bits are not used (version 0), the
 * next 2 are used for version 1, the following 2 for version 2, and so on.
 */
#define	TKID_ATTR_B_START	1
#define	TKID_ATTR_B_CONT	2

#define	TKID_ATTR_START(_ver)	(TKID_ATTR_B_START << (_ver * 2))
#define	TKID_ATTR_CONT(_ver)	(TKID_ATTR_B_CONT << (_ver * 2))

/* Convenience macros for chars that both start and continue an identifier */
#define	TKID_ATTR(_ver) ((TKID_ATTR_B_START | TKID_ATTR_B_CONT) << (_ver * 2))

/*
 * State for a mapfile held in memory.
 */
typedef struct {
	Ofl_desc	*mf_ofl;	/* Output descriptor being processed */
	char		*mf_name;	/* Mapfile name */
	Ifl_desc	*mf_ifl;	/* NULL, or pseudo input file */
					/*	descriptor from ld_map_ifl() */
	char		*mf_text;	/* Text of mapfile */
	char		*mf_next;	/* Next char in mapfile to examine */
	const char	*mf_tokdisp;	/* mf_tokdisp_t dispatch table to use */
	Lineno		mf_lineno;	/* Line # within mf_text */
	int		mf_version;	/* Mapfile syntax version */
	int		mf_tkid_start;	/* TKID bitvalue for characters that */
					/*	start an unquoted identifier */
	int		mf_tkid_cont;	/* TKID bitvalue for characters that */
					/*	continue an unquoted ident. */
	int		mf_next_ch;	/* 0, or character read from *mf_next */
					/*	prior to inserting NULL */
	Aliste		mf_ec_insndx;	/* Insert index for entrance criteria */
					/*	Each mapfile starts at the */
					/*	top, inserting each ec in the */
					/*	file in the order seen. */
} Mapfile;

/*
 * A very large percentage of mapfile errors start with the
 * calling sequence:
 *	eprintf(ofl->ofl_lml, ERR_XXX, format, mf->mf_name,
 *		mf->mf_lineno...)
 * The mf_fatal() and mf_warn() varadic macros are used to supply all
 * of boilerplate, resulting in visually simpler code.
 *
 * mf_fatal0()/mf_warn0() are used when the format does not require any
 * additional arguments and the varargs list is empty. The GNU cpp has a
 * syntax for eliminating the extra comma (, ##__VA_ARGS__), but this isn't
 * supported by the Sun compilers yet.
 */
#define	mf_fatal0(_mf, _fmt) \
	eprintf((_mf)->mf_ofl->ofl_lml, ERR_FATAL, _fmt, (_mf)->mf_name, \
	    EC_LINENO((_mf)->mf_lineno))
#define	mf_fatal(_mf, _fmt, ...) \
	eprintf((_mf)->mf_ofl->ofl_lml, ERR_FATAL, _fmt, (_mf)->mf_name, \
	    EC_LINENO((_mf)->mf_lineno), __VA_ARGS__)

#define	mf_warn0(_mf, _fmt) \
	eprintf((_mf)->mf_ofl->ofl_lml, ERR_WARNING, _fmt, (_mf)->mf_name, \
	    EC_LINENO((_mf)->mf_lineno))
#define	mf_warn(_mf, _fmt, ...) \
	eprintf((_mf)->mf_ofl->ofl_lml, ERR_WARNING, _fmt, (_mf)->mf_name, \
	    EC_LINENO((_mf)->mf_lineno), __VA_ARGS__)

/* Possible return values from ld_map_gettoken */
typedef enum {
	TK_ERROR =	-1,	/* Error in lexical analysis */
	TK_EOF =	0,	/* End of file: Requires TK_F_EOFOK to be set */
				/*	or EOF results in TK_ERROR */
	TK_STRING =	1,	/* String literal */
	TK_COLON =	2,	/* : */
	TK_SEMICOLON =	3,	/* ; */
	TK_EQUAL =	4,	/* = */
	TK_PLUSEQ =	5,	/* += */
	TK_MINUSEQ =	6,	/* -= */
	TK_ATSIGN =	7,	/* @ */
	TK_DASH =	8,	/* - */
	TK_LEFTBKT =	9,	/* { */
	TK_RIGHTBKT =	10,	/* } */
	TK_PIPE =	11,	/* | */
	TK_INT =	12,	/* Integer value: Unsigned machine word */
	TK_STAR =	13,	/* * */
	TK_BANG =	14,	/* ! */

	/*
	 * Items below this point are for the use of ld_map_gettoken().
	 * They indicate a character that requires the lexical analyzer
	 * to carry out some additional computation (OPeration), resulting
	 * in one of the simple token types above, which is returned to
	 * the caller. The TK_OP_ tokens are implementation details that are
	 * never returned to a caller of ld_map_gettoken().
	 */
	TK_OP_EOF,		/* end of file */
	TK_OP_ILLCHR,		/* unprintable illegal character */
	TK_OP_BADCHR,		/* printable but unexpected character */
	TK_OP_WS,		/* whitespace */
	TK_OP_NL,		/* newline */
	TK_OP_SIMQUOTE,		/* simple quoting */
	TK_OP_CQUOTE,		/* quoting with C string literal escapes */
	TK_OP_CMT,		/* Comment */
	TK_OP_CDIR,		/* Control directive */
	TK_OP_NUM,		/* Decimial, hex, or octal value */
	TK_OP_ID,		/* unquoted identifier using syntax rules */
				/*	appropriate for mapfile version */
	TK_OP_CEQUAL,		/* One of += or -= */
} Token;

/*
 * Type used by ld_map_gettoken() to return values for token types that
 * have them.
 */
typedef union {
	char	*tkv_str;		/* TK_STRING */
	struct {			/* TK_INT */
		char	*tkvi_str;	/* String making up integer */
		size_t	tkvi_cnt;	/* # characters in tkvi_str */
		Xword	tkvi_value;	/* Resulting value */
	} tkv_int;
} ld_map_tkval_t;

/*
 * Values for gettoken() flags argument. These flags are used to
 * alter gettoken() default behavior under certain conditions.
 */
#define	TK_F_EOFOK	1	/* Quietly return TK_EOF instead of normal */
				/* 	TK_ERROR "premature EOF" error */
#define	TK_F_STRLC	2	/* TK_STRING: Convert string to lowercase */
#define	TK_F_KEYWORD	4	/* For directives and attributes: Disallow */
				/*	quoted TK_STRING tokens */

/*
 * Possible return values from ld_map_strtoxword()
 */
typedef enum {
	STRTOXWORD_OK,		/* Operation successful */
	STRTOXWORD_TOOBIG,	/* Otherwise valid value is too large */
	STRTOXWORD_BAD		/* String not recognized as an integer */
} ld_map_strtoxword_t;

/*
 * Possible return values from ld_map_seg_insert()
 */
typedef enum {
	SEG_INS_OK = 0,		/* Segment was inserted */
	SEG_INS_FAIL = 1,	/* Segment not inserted --- fatal */
	SEG_INS_SKIP = 2	/* Segment not inserted --- ignore */
} ld_map_seg_ins_t;

/*
 * Enumeration of different symbol scope possible in a mapfile
 */
typedef enum {
	FLG_SCOPE_HIDD,		/* symbol defined hidden/local */
	FLG_SCOPE_DFLT,		/* symbol defined default/global */
	FLG_SCOPE_PROT,		/* symbol defined protected/symbolic */
	FLG_SCOPE_EXPT,		/* symbol defined exported */
	FLG_SCOPE_SNGL,		/* symbol defined singleton */
	FLG_SCOPE_ELIM		/* symbol defined eliminate */
} ld_map_scope_t;

/* State of a mapfile symbol version */
typedef struct {
	const char	*mv_name;	/* NULL, or version name */
	Ver_desc	*mv_vdp;	/* Descriptor for version */
	ld_map_scope_t	mv_scope;	/* Current scope type */
	size_t		mv_errcnt;	/* Count of errors against version */
} ld_map_ver_t;

/* State of a mapfile symbol definition */
typedef struct {
	const char	*ms_name;	/* symbol name */
	sd_flag_t	ms_sdflags;	/* 0 / mapfile set flags */
	Word		ms_shndx;	/* SHN_UNDEF / mapfile set sec index */
	uchar_t 	ms_type;	/* STT_NOTYPE / mapfile set type */
	Addr		ms_value;	/* user set value, if ms_value_set */
	Addr		ms_size;	/* 0 / mapfile set size */
	const char	*ms_filtee;	/* NULL or filtee name */
	Boolean		ms_value_set;	/* TRUE if ms_value set, even if to 0 */
	Word		ms_dft_flag;	/* 0, or type of filter in ms_filtee */
} ld_map_sym_t;

#if	defined(_ELF64)

#define	ld_map_cap_sanitize	ld64_map_cap_sanitize
#define	ld_map_cap_set_ovflag	ld64_map_cap_set_ovflag
#define	ld_map_dv		ld64_map_dv
#define	ld_map_dv_entry		ld64_map_dv_entry
#define	ld_map_gettoken		ld64_map_gettoken
#define	ld_map_ifl		ld64_map_ifl
#define	ld_map_parse_v1		ld64_map_parse_v1
#define	ld_map_parse_v2		ld64_map_parse_v2
#define	ld_map_seg_alloc	ld64_map_seg_alloc
#define	ld_map_seg_ent_add	ld64_map_seg_ent_add
#define	ld_map_seg_ent_files	ld64_map_seg_ent_files
#define	ld_map_seg_index	ld64_map_seg_index
#define	ld_map_seg_insert	ld64_map_seg_insert
#define	ld_map_seg_lookup	ld64_map_seg_lookup
#define	ld_map_seg_os_order_add	ld64_map_seg_os_order_add
#define	ld_map_seg_size_symbol	ld64_map_seg_size_symbol
#define	ld_map_seg_stack	ld64_map_seg_stack
#define	ld_map_strtoxword	ld64_map_strtoxword
#define	ld_map_sym_enter	ld64_map_sym_enter
#define	ld_map_sym_filtee	ld64_map_sym_filtee
#define	ld_map_sym_scope	ld64_map_sym_scope
#define	ld_map_sym_autoreduce	ld64_map_sym_autoreduce
#define	ld_map_sym_ver_fini	ld64_map_sym_ver_fini
#define	ld_map_sym_ver_init	ld64_map_sym_ver_init
#define	ld_map_tokenstr		ld64_map_tokenstr

#else

#define	ld_map_cap_sanitize	ld32_map_cap_sanitize
#define	ld_map_cap_set_ovflag	ld32_map_cap_set_ovflag
#define	ld_map_dv		ld32_map_dv
#define	ld_map_dv_entry		ld32_map_dv_entry
#define	ld_map_gettoken		ld32_map_gettoken
#define	ld_map_ifl		ld32_map_ifl
#define	ld_map_parse_v1		ld32_map_parse_v1
#define	ld_map_parse_v2		ld32_map_parse_v2
#define	ld_map_seg_alloc	ld32_map_seg_alloc
#define	ld_map_seg_ent_add	ld32_map_seg_ent_add
#define	ld_map_seg_ent_files	ld32_map_seg_ent_files
#define	ld_map_seg_index	ld32_map_seg_index
#define	ld_map_seg_insert	ld32_map_seg_insert
#define	ld_map_seg_lookup	ld32_map_seg_lookup
#define	ld_map_seg_os_order_add	ld32_map_seg_os_order_add
#define	ld_map_seg_size_symbol	ld32_map_seg_size_symbol
#define	ld_map_seg_stack	ld32_map_seg_stack
#define	ld_map_strtoxword	ld32_map_strtoxword
#define	ld_map_sym_enter	ld32_map_sym_enter
#define	ld_map_sym_filtee	ld32_map_sym_filtee
#define	ld_map_sym_scope	ld32_map_sym_scope
#define	ld_map_sym_autoreduce	ld32_map_sym_autoreduce
#define	ld_map_sym_ver_fini	ld32_map_sym_ver_fini
#define	ld_map_sym_ver_init	ld32_map_sym_ver_init
#define	ld_map_tokenstr		ld32_map_tokenstr

#endif

/*
 * Core functions used to parse mapfiles
 */
extern void		ld_map_lowercase(char *);
extern Token		ld_map_gettoken(Mapfile *, int, ld_map_tkval_t *);
extern Boolean		ld_map_parse_v1(Mapfile *);
extern Boolean		ld_map_parse_v2(Mapfile *);
extern ld_map_strtoxword_t ld_map_strtoxword(const char *restrict,
			    char **restrict, Xword *);
extern const char	*ld_map_tokenstr(Token, ld_map_tkval_t *,
			    Conv_inv_buf_t *);

/*
 * Support code shared between the different mapfile parsing code, used to
 * provide a common implementation manipulating link-editor state.
 */
extern Boolean		ld_map_cap_sanitize(Mapfile *, Word, Capmask *);
extern void		ld_map_cap_set_ovflag(Mapfile *, Word);
extern void		*ld_map_kwfind(const char *, void *, size_t, size_t);
extern char		*ld_map_kwnames(void *, size_t, size_t, char *, size_t);
extern Sdf_desc		*ld_map_dv(Mapfile *, const char *);
extern Boolean		ld_map_dv_entry(Mapfile *, Sdf_desc *, Boolean,
			    const char *);
extern Ifl_desc		*ld_map_ifl(Mapfile *);
extern Sg_desc		*ld_map_seg_alloc(const char *, Word, sg_flags_t);
extern Ent_desc		*ld_map_seg_ent_add(Mapfile *, Sg_desc *, const char *);
extern Boolean		ld_map_seg_ent_files(Mapfile *mf, Ent_desc *,
			    Word, const char *);
extern Xword		ld_map_seg_index(Mapfile *, Sg_desc *);
extern ld_map_seg_ins_t	ld_map_seg_insert(Mapfile *, dbg_state_t, Sg_desc *,
			    avl_index_t where);
extern Boolean		ld_map_seg_os_order_add(Mapfile *, Sg_desc *,
			    const char *);
extern Boolean		ld_map_seg_size_symbol(Mapfile *, Sg_desc *, Token,
			    const char *symname);
extern Sg_desc		*ld_map_seg_stack(Mapfile *);
extern Boolean		ld_map_sym_enter(Mapfile *, ld_map_ver_t *,
			    ld_map_sym_t *);
extern void		ld_map_sym_filtee(Mapfile *, ld_map_ver_t *,
			    ld_map_sym_t *, Word, const char *);
extern void		ld_map_sym_scope(Mapfile *, const char *,
			    ld_map_ver_t *);
extern void		ld_map_sym_autoreduce(Mapfile *, ld_map_ver_t *);
extern Boolean		ld_map_sym_ver_fini(Mapfile *, ld_map_ver_t *);
extern Boolean		ld_map_sym_ver_init(Mapfile *, char *, ld_map_ver_t *);

#ifdef	__cplusplus
}
#endif

#endif /* _MAP_DOT_H */
