/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _ICONV_TM_H
#define	_ICONV_TM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#ifdef	__cplusplus
extern "C" {
#endif


#include <inttypes.h>
#include <sys/isa_defs.h>
#include <sys/types.h>


#if !defined(DEBUG)
#define	NDEBUG	/* for assert() */
#endif /* DEBUG */


#if defined(DEBUG)
#define	ENABLE_TRACE
#endif /* DEBUG */

#define	MAXSEQUENCE	(128)
#define	MAXREGID	(256)
#define	MAXNAMELENGTH	(255)

/*
 * ITM Identifier
 */

#define	ITM_IDENT_LEN			(4)
#define	ITM_IDENT_0			(0x49)
#define	ITM_IDENT_1			(0x54)
#define	ITM_IDENT_2			(0x4d)
#define	ITM_IDENT_3			(0x00)


/*
 * ITM Platform Specification
 */

#define	ITM_SPEC_LEN			(4)
#define	ITM_SPEC_0			(0)
#define	ITM_SPEC_1			(0)
#define	ITM_SPEC_2			(0)
#define	ITM_SPEC_3_UNSPECIFIED		(0)
#define	ITM_SPEC_3_32_BIG_ENDIAN	(1)
#define	ITM_SPEC_3_32_LITTLE_ENDIAN	(2)
#define	ITM_SPEC_3_64_BIG_ENDIAN	(3)
#define	ITM_SPEC_3_64_LITTLE_ENDIAN	(4)


/*
 * ITM Version
 */

#define	ITM_VER_LEN			(4)
#define	ITM_VER_0			(0)
#define	ITM_VER_1			(0)
#define	ITM_VER_2			(0)
#define	ITM_VER_3			(1)


/*
 * PADDING
 */
#define	ITM_PAD_LEN			(4)


/*
 * Generic offset&pointer/data/string
 */
typedef uint32_t	pad_t;
typedef ulong_t		itm_type_t;
typedef uintptr_t	itm_place2_t;	/* position of data */
typedef size_t		itm_size_t;
typedef long		itm_num_t;
typedef union itm_place_union {
	int64_t		itm_64d;	/* positon of real data */
	struct {
#if !defined(_LP64) && !defined(_LITTLE_ENDIAN)
		pad_t		pad;
#endif
		itm_place2_t   ptr;
#if !defined(_LP64) && defined(_LITTLE_ENDIAN)
		pad_t		pad;
#endif
	}itm_place_union_struct;
	char			itm_c[8];
}	itm_place_t;
#define	itm_ptr	itm_place_union_struct.ptr
#define	itm_pad	itm_place_union_struct.pad


typedef struct {
#if !defined(_LP64) && !defined(_LITTLE_ENDIAN)
	pad_t		pad;
#endif
	itm_size_t	size;		/* size in bytes */
#if !defined(_LP64) && defined(_LITTLE_ENDIAN)
	pad_t		pad;
#endif

	itm_place_t	place;		/* place of data */
} itm_data_t;


/*
 * Generic place table information
 */

typedef struct {
#if !defined(_LP64) && !defined(_LITTLE_ENDIAN)
	pad_t		pad1;
#endif
	itm_size_t	size;		/* size in bytes */
#if !defined(_LP64) && defined(_LITTLE_ENDIAN)
	pad_t		pad1;
#endif

	itm_place_t	place;		/* place of place table */

#if !defined(_LP64) && !defined(_LITTLE_ENDIAN)
	pad_t		pad2;
#endif
	itm_num_t	number;		/* number of entry */
#if !defined(_LP64) && defined(_LITTLE_ENDIAN)
	pad_t		pad2;
#endif
} itm_place_tbl_info_t;


/*
 * Generic place table section
 */

typedef struct {
#if !defined(_LP64) && !defined(_LITTLE_ENDIAN)
	pad_t		pad1;
#endif
	itm_size_t	size;		/* size in bytes */
#if !defined(_LP64) && defined(_LITTLE_ENDIAN)
	pad_t		pad1;
#endif

	itm_place_t	place;		/* place of table section */

#if !defined(_LP64) && !defined(_LITTLE_ENDIAN)
	pad_t		pad2;
#endif
	itm_num_t	number;		/* number of table */
#if !defined(_LP64) && defined(_LITTLE_ENDIAN)
	pad_t		pad2;
#endif

} itm_section_info_t;


/*
 * Generic table header
 */

#define	ITM_TBL_MASK		(0x000000ffUL)

#define	ITM_TBL_NONE		(0x00000000UL)
#define	ITM_TBL_ITM		(0x00000001UL)
#define	ITM_TBL_DIREC		(0x00000002UL)
#define	ITM_TBL_COND		(0x00000003UL)
#define	ITM_TBL_MAP		(0x00000004UL)
#define	ITM_TBL_OP		(0x00000005UL)
#define	ITM_TBL_RANGE		(0x00000006UL)
#define	ITM_TBL_ESCAPESEQ	(0x00000007UL)

#define	ITM_TBL_NONE_NONE		(ITM_TBL_NONE  | 0x00000000UL)
#define	ITM_TBL_DIREC_NONE		(ITM_TBL_DIREC | 0x00000000UL)
#define	ITM_TBL_DIREC_RESET		(ITM_TBL_DIREC | 0x00000100UL)
#define	ITM_TBL_COND_NONE		(ITM_TBL_COND  | 0x00000000UL)
#define	ITM_TBL_MAP_NONE		(ITM_TBL_MAP   | 0x00000000UL)
#define	ITM_TBL_MAP_INDEX_FIXED_1_1	(ITM_TBL_MAP   | 0x00000100UL)
#define	ITM_TBL_MAP_INDEX_FIXED		(ITM_TBL_MAP   | 0x00000200UL)
#define	ITM_TBL_MAP_LOOKUP		(ITM_TBL_MAP   | 0x00000300UL)
#define	ITM_TBL_MAP_HASH		(ITM_TBL_MAP   | 0x00000400UL)
#define	ITM_TBL_MAP_DENSE_ENC		(ITM_TBL_MAP   | 0x00000500UL)
#define	ITM_TBL_MAP_VAR			(ITM_TBL_MAP   | 0x00000600UL)
#define	ITM_TBL_OP_NONE			(ITM_TBL_OP    | 0x00000000UL)
#define	ITM_TBL_OP_INIT			(ITM_TBL_OP    | 0x00000100UL)
#define	ITM_TBL_OP_RESET		(ITM_TBL_OP    | 0x00000200UL)
#define	ITM_TBL_RANGE_NONE		(ITM_TBL_RANGE | 0x00000000UL)
#define	ITM_TBL_ESCAPESEQ_NONE		(ITM_TBL_ESCAPESEQ | 0x00000000UL)

typedef struct {
#if !defined(_LP64) && !defined(_LITTLE_ENDIAN)
	pad_t		pad1;
#endif
	itm_type_t	type;		/* type of table */
#if !defined(_LP64) && defined(_LITTLE_ENDIAN)
	pad_t		pad1;
#endif
	itm_place_t	name;		/* name of table */

#if !defined(_LP64) && !defined(_LITTLE_ENDIAN)
	pad_t		pad2;
#endif
	itm_size_t	size;		/* size of table */
#if !defined(_LP64) && defined(_LITTLE_ENDIAN)
	pad_t		pad2;
#endif

#if !defined(_LP64) && !defined(_LITTLE_ENDIAN)
	pad_t		pad3;
#endif
	itm_num_t	number;		/* number of entry */
#if !defined(_LP64) && defined(_LITTLE_ENDIAN)
	pad_t		pad3;
#endif
} itm_tbl_hdr_t;


/*
 * Iconv Code Set Translation Module (ITM) header
 */

typedef struct {
	unsigned char	ident[ITM_IDENT_LEN];	/* identifier */
	unsigned char	spec[ITM_SPEC_LEN];	/* platform specification */
	unsigned char	version[ITM_VER_LEN];	/* version */
	unsigned char	padding[ITM_PAD_LEN];	/* padding  */


#if !defined(_LP64) && !defined(_LITTLE_ENDIAN)
	pad_t		pad1;
#endif
	itm_size_t	itm_hdr_size;		/* ITM header size */
#if !defined(_LP64) && defined(_LITTLE_ENDIAN)
	pad_t		pad1;
#endif

	itm_place_t	itm_size;		/* size of ITM (file size) */
	itm_data_t	type_id;		/* type identifier */
	itm_data_t	interpreter;		/* interpreter */
	itm_place_t	op_init_tbl;		/* init operation table */
	itm_place_t	op_reset_tbl;		/* reset operation table */
	itm_place_t	direc_init_tbl;		/* initial direction table */

#if !defined(_LP64) && !defined(_LITTLE_ENDIAN)
	pad_t		pad3;
#endif
	itm_num_t	reg_num;		/* number of register */
#if !defined(_LP64) && defined(_LITTLE_ENDIAN)
	pad_t		pad3;
#endif

	itm_place_t	info_hdr;		/* ITM Info header */
} itm_hdr_t;


/*
 * ITM Info header
 */
typedef struct {
	itm_section_info_t	str_sec;	/* string section */
	itm_section_info_t	direc_tbl_sec;	/* direction table section */
	itm_section_info_t	cond_tbl_sec;	/* condition table section */
	itm_section_info_t	map_tbl_sec;	/* map table section */
	itm_section_info_t	op_tbl_sec;	/* operation table section */
	itm_section_info_t	range_tbl_sec;	/* range section */
	itm_section_info_t	escapeseq_tbl_sec; /* escapeseq section */
	itm_section_info_t	data_sec;	/* data section */
	itm_section_info_t	name_sec;	/* name section */

	itm_place_tbl_info_t	str_plc_tbl;	/* string info */
	itm_place_tbl_info_t	direc_plc_tbl;	/* direction table info */
	itm_place_tbl_info_t	cond_plc_tbl;	/* condition table info */
	itm_place_tbl_info_t	map_plc_tbl;	/* map table info */
	itm_place_tbl_info_t	op_plc_tbl;	/* operation table info */
	itm_place_tbl_info_t	range_plc_tbl;	/* range info */
	itm_place_tbl_info_t	escapeseq_plc_tbl; /* escape info */
	itm_place_tbl_info_t	data_plc_tbl;	/* data info */
	itm_place_tbl_info_t	name_plc_tbl;	/* name info */
	itm_place_tbl_info_t	reg_plc_tbl;	/* register name info */
} itm_info_hdr_t;


/*
 * Direction
 */

typedef enum {
	ITM_ACTION_NONE,	/* not used */
	ITM_ACTION_DIRECTION,	/* direction */
	ITM_ACTION_MAP,		/* map */
	ITM_ACTION_OPERATION	/* operation */
} itm_action_type_t;

typedef struct {
	itm_place_t		condition;
	itm_place_t		action;
} itm_direc_t;


/*
 * Condition
 */

typedef enum {
	ITM_COND_NONE = 0,	/* not used */
	ITM_COND_BETWEEN = 1,	/* input data is inside of ranges */
	ITM_COND_EXPR = 2,	/* expression */
	ITM_COND_ESCAPESEQ = 3	/* escape sequense */
} itm_cond_type_t;

typedef struct {
	pad_t		pad;
	itm_cond_type_t	type;
	union {
		itm_place_t	place;
		itm_data_t	data;
	}		operand;
} itm_cond_t;

typedef struct {
#if !defined(_LP64) && !defined(_LITTLE_ENDIAN)
	pad_t		pad;
#endif
	itm_size_t	len;
#if !defined(_LP64) && defined(_LITTLE_ENDIAN)
	pad_t		pad;
#endif
} itm_range_hdr_t;

typedef struct {
#if !defined(_LP64) && !defined(_LITTLE_ENDIAN)
	pad_t		pad1;
#endif
	itm_size_t	len_min;
#if !defined(_LP64) && defined(_LITTLE_ENDIAN)
	pad_t		pad1;
#endif

#if !defined(_LP64) && !defined(_LITTLE_ENDIAN)
	pad_t		pad2;
#endif
	itm_size_t	len_max;
#if !defined(_LP64) && defined(_LITTLE_ENDIAN)
	pad_t		pad2;
#endif
} itm_escapeseq_hdr_t;


/*
 * Map table: octet-sequence to octet-sequence: index
 */

typedef struct {
#if !defined(_LP64) && !defined(_LITTLE_ENDIAN)
	pad_t		pad1;
#endif
	itm_size_t	source_len;	/* source length */
#if !defined(_LP64) && defined(_LITTLE_ENDIAN)
	pad_t		pad1;
#endif


#if !defined(_LP64) && !defined(_LITTLE_ENDIAN)
	pad_t		pad2;
#endif
	itm_size_t	result_len;	/* result length */
#if !defined(_LP64) && defined(_LITTLE_ENDIAN)
	pad_t		pad2;
#endif

	itm_place_t	start;		/* start offset */
	itm_place_t	end;		/* end offset */

#if !defined(_LP64) && !defined(_LITTLE_ENDIAN)
	pad_t		pad3_num;
#endif
	itm_num_t	default_error;
/*
 *		-1:path through
 *		 0:with default value
 *		 1:with error table
 *		 2:without error table
 */
#if !defined(_LP64) && defined(_LITTLE_ENDIAN)
	pad_t		pad3_num;
#endif

#if !defined(_LP64) && !defined(_LITTLE_ENDIAN)
	pad_t		pad4_num;
#endif
	itm_num_t	error_num;
#if !defined(_LP64) && defined(_LITTLE_ENDIAN)
	pad_t		pad4_num;
#endif


} itm_map_idx_fix_hdr_t;

/*
 * Map table: octet-sequence to octet-sequence: lookup
 */

typedef struct {
#if !defined(_LP64) && !defined(_LITTLE_ENDIAN)
	pad_t		pad1;
#endif
	itm_size_t	source_len;	/* source length */
#if !defined(_LP64) && defined(_LITTLE_ENDIAN)
	pad_t		pad1;
#endif

#if !defined(_LP64) && !defined(_LITTLE_ENDIAN)
	pad_t		pad2;
#endif
	itm_size_t	result_len;	/* result length */
#if !defined(_LP64) && defined(_LITTLE_ENDIAN)
	pad_t		pad2;
#endif

#if !defined(_LP64) && !defined(_LITTLE_ENDIAN)
	pad_t		pad3_num;
#endif
	itm_num_t	default_error;
/*
 *		-1:path through
 *		 0:with default value
 *		 1:with error table
 *		 2:without error table
 */
#if !defined(_LP64) && defined(_LITTLE_ENDIAN)
	pad_t		pad3_num;
#endif

#if !defined(_LP64) && !defined(_LITTLE_ENDIAN)
	pad_t		pad4_num;
#endif
	itm_num_t	error_num;
#if !defined(_LP64) && defined(_LITTLE_ENDIAN)
	pad_t		pad4_num;
#endif
} itm_map_lookup_hdr_t;

/*
 * Map table: octet-sequence to octet-sequence: hash
 */

typedef struct {
#if !defined(_LP64) && !defined(_LITTLE_ENDIAN)
	pad_t		pad1;
#endif
	itm_size_t	source_len;	/* source length */
#if !defined(_LP64) && defined(_LITTLE_ENDIAN)
	pad_t		pad1;
#endif

#if !defined(_LP64) && !defined(_LITTLE_ENDIAN)
	pad_t		pad2;
#endif
	itm_size_t	result_len;	/* result length */
#if !defined(_LP64) && defined(_LITTLE_ENDIAN)
	pad_t		pad2;
#endif

#if !defined(_LP64) && !defined(_LITTLE_ENDIAN)
	pad_t		pad3;
#endif
	itm_size_t	hash_tbl_size;	/* hash table size */
#if !defined(_LP64) && defined(_LITTLE_ENDIAN)
	pad_t		pad3;
#endif

#if !defined(_LP64) && !defined(_LITTLE_ENDIAN)
	pad_t		pad4;
#endif
	itm_num_t	hash_tbl_num;	/* hash table entryies */
#if !defined(_LP64) && defined(_LITTLE_ENDIAN)
	pad_t		pad4;
#endif

#if !defined(_LP64) && !defined(_LITTLE_ENDIAN)
	pad_t		pad5;
#endif
	itm_size_t	hash_of_size;	/* hash overflow table size */
#if !defined(_LP64) && defined(_LITTLE_ENDIAN)
	pad_t		pad5;
#endif

#if !defined(_LP64) && !defined(_LITTLE_ENDIAN)
	pad_t		pad6;
#endif
	itm_num_t	hash_of_num;	/* hash overflow table entryies */
#if !defined(_LP64) && defined(_LITTLE_ENDIAN)
	pad_t		pad6;
#endif

#if !defined(_LP64) && !defined(_LITTLE_ENDIAN)
	pad_t		pad7_num;
#endif
	itm_num_t	default_error;
/*
 *		-1:path through
 *		 0:with default value
 *		 1:with error table
 *		 2:without error table
 */
#if !defined(_LP64) && defined(_LITTLE_ENDIAN)
	pad_t		pad7_num;
#endif

#if !defined(_LP64) && !defined(_LITTLE_ENDIAN)
	pad_t		pad8_num;
#endif
	itm_num_t	error_num;
#if !defined(_LP64) && defined(_LITTLE_ENDIAN)
	pad_t		pad8_num;
#endif

} itm_map_hash_hdr_t;

/*
 * Map table: octet-sequence to octet-sequence: dense encoding
 */

typedef struct {
#if !defined(_LP64) && !defined(_LITTLE_ENDIAN)
	pad_t		pad1;
#endif
	itm_size_t	source_len;	/* source length */
#if !defined(_LP64) && defined(_LITTLE_ENDIAN)
	pad_t		pad1;
#endif

#if !defined(_LP64) && !defined(_LITTLE_ENDIAN)
	pad_t		pad2;
#endif
	itm_size_t	result_len;	/* result length */
#if !defined(_LP64) && defined(_LITTLE_ENDIAN)
	pad_t		pad2;
#endif

#if !defined(_LP64) && !defined(_LITTLE_ENDIAN)
	pad_t		pad3_num;
#endif
	itm_num_t	default_error;
/*
 *		-1:path through
 *		 0:with default value
 *		 1:with error table
 *		 2:without error table
 */

#if !defined(_LP64) && defined(_LITTLE_ENDIAN)
	pad_t		pad3_num;
#endif

#if !defined(_LP64) && !defined(_LITTLE_ENDIAN)
	pad_t		pad4_num;
#endif
	itm_num_t	error_num;
#if !defined(_LP64) && defined(_LITTLE_ENDIAN)
	pad_t		pad4_num;
#endif
} itm_map_dense_enc_hdr_t;



/*
 * Operation
 */

typedef enum {	/* Operation Type */
	ITM_OP_NONE,		/* not used */
	ITM_OP_ERROR,		/* error */
	ITM_OP_ERROR_D,		/* error */
	ITM_OP_OUT,		/* output */
	ITM_OP_OUT_D,		/* output */
	ITM_OP_OUT_S,		/* output */
	ITM_OP_OUT_R,		/* output */
	ITM_OP_OUT_INVD,	/* output */
	ITM_OP_DISCARD,		/* discard */
	ITM_OP_DISCARD_D,	/* discard */
	ITM_OP_EXPR,		/* expression */
	ITM_OP_IF,		/* if */
	ITM_OP_IF_ELSE,		/* if_else */
	ITM_OP_DIRECTION,	/* switch direction */
	ITM_OP_MAP,		/* use map */
	ITM_OP_OPERATION,	/* invoke operation */
	ITM_OP_INIT,		/* invoke init operation */
	ITM_OP_RESET,		/* invoke reset operation */
	ITM_OP_BREAK,		/* break */
	ITM_OP_RETURN,		/* return */
	ITM_OP_PRINTCHR,	/* print out argument as character */
	ITM_OP_PRINTHD,		/* print out argument as hexadecimal */
	ITM_OP_PRINTINT		/* print out argument as integer */
} itm_op_type_t;

typedef struct {
	pad_t				pad;
	itm_op_type_t			type;
	itm_place_t			name;

	union {
		itm_place_t		operand[3];
		itm_data_t		value;
		struct {
#if !defined(_LP64) && !defined(_LITTLE_ENDIAN)
			pad_t		pad_num;
#endif
			itm_num_t	num;
#if !defined(_LP64) && defined(_LITTLE_ENDIAN)
			pad_t		pad_num;
#endif
		}			itm_op_num;
	}		data;
} itm_op_t;
#define	itm_opnum itm_op_num.num
#define	itm_oppad itm_op_num.pad_num

/*
 * Expression
 */

#define	ITM_EXPR_PROTO(type, op0, op1)	ITM_EXPR_##type##_##op0##_##op1
#define	ITM_EXPR_BIN(type)			\
	ITM_EXPR_PROTO(type, E, E),		\
	ITM_EXPR_PROTO(type, E, D),		\
	ITM_EXPR_PROTO(type, E, R),		\
	ITM_EXPR_PROTO(type, E, INVD),		\
	ITM_EXPR_PROTO(type, D, E),		\
	ITM_EXPR_PROTO(type, D, D),		\
	ITM_EXPR_PROTO(type, D, R),		\
	ITM_EXPR_PROTO(type, D, INVD),		\
	ITM_EXPR_PROTO(type, R, E),		\
	ITM_EXPR_PROTO(type, R, D),		\
	ITM_EXPR_PROTO(type, R, R),		\
	ITM_EXPR_PROTO(type, R, INVD),		\
	ITM_EXPR_PROTO(type, INVD, E),		\
	ITM_EXPR_PROTO(type, INVD, D),		\
	ITM_EXPR_PROTO(type, INVD, R),		\
	ITM_EXPR_PROTO(type, INVD, INVD)

#define	ITM_EXPR_PLUS		ITM_EXPR_PLUS_E_E
#define	ITM_EXPR_MINUS		ITM_EXPR_MINUS_E_E
#define	ITM_EXPR_MUL		ITM_EXPR_MUL_E_E
#define	ITM_EXPR_DIV		ITM_EXPR_DIV_E_E
#define	ITM_EXPR_MOD		ITM_EXPR_MOD_E_E
#define	ITM_EXPR_SHIFT_L	ITM_EXPR_SHIFT_L_E_E
#define	ITM_EXPR_SHIFT_R	ITM_EXPR_SHIFT_R_E_E
#define	ITM_EXPR_OR		ITM_EXPR_OR_E_E
#define	ITM_EXPR_XOR		ITM_EXPR_XOR_E_E
#define	ITM_EXPR_AND		ITM_EXPR_AND_E_E
#define	ITM_EXPR_EQ		ITM_EXPR_EQ_E_E
#define	ITM_EXPR_NE		ITM_EXPR_NE_E_E
#define	ITM_EXPR_GT		ITM_EXPR_GT_E_E
#define	ITM_EXPR_GE		ITM_EXPR_GE_E_E
#define	ITM_EXPR_LT		ITM_EXPR_LT_E_E
#define	ITM_EXPR_LE		ITM_EXPR_LE_E_E

typedef enum {	/* Expression Type */
	ITM_EXPR_NONE,		/* not used */
	ITM_EXPR_NOP,		/* not used */
	ITM_EXPR_NAME,		/* not used */
	ITM_EXPR_INT,		/* integer */
	ITM_EXPR_SEQ,		/* byte sequence */
	ITM_EXPR_REG,		/* register */
	ITM_EXPR_IN_VECTOR,	/* in[expr] */
	ITM_EXPR_IN_VECTOR_D,	/* in[DECIMAL] */
	ITM_EXPR_OUT,		/* out */
	ITM_EXPR_TRUE,		/* true */
	ITM_EXPR_FALSE,		/* false */
	ITM_EXPR_IN,		/* input data */
	ITM_EXPR_UMINUS,	/* unary minus */
	ITM_EXPR_BIN(PLUS),	/* A +	B */
	ITM_EXPR_BIN(MINUS),	/* A -	B */
	ITM_EXPR_BIN(MUL),	/* A *	B */
	ITM_EXPR_BIN(DIV),	/* A /	B */
	ITM_EXPR_BIN(MOD),	/* A %	B */
	ITM_EXPR_BIN(SHIFT_L),	/* A << B */
	ITM_EXPR_BIN(SHIFT_R),	/* A >> B */
	ITM_EXPR_BIN(OR),	/* A |	B */
	ITM_EXPR_BIN(XOR),	/* A ^	B */
	ITM_EXPR_BIN(AND),	/* A &	B */
	ITM_EXPR_BIN(EQ),	/* A == B */
	ITM_EXPR_BIN(NE),	/* A != B */
	ITM_EXPR_BIN(GT),	/* A >	B */
	ITM_EXPR_BIN(GE),	/* A >= B */
	ITM_EXPR_BIN(LT),	/* A <	B */
	ITM_EXPR_BIN(LE),	/* A <= B */
	ITM_EXPR_NOT,		/*   !A	  */
	ITM_EXPR_NEG,		/*   ~A	  */
	ITM_EXPR_LOR,		/* A || B */
	ITM_EXPR_LAND,		/* A && B */
	ITM_EXPR_ASSIGN,	/* A  = B */
	ITM_EXPR_OUT_ASSIGN,	/* out = A */
	ITM_EXPR_IN_EQ,		/* in == A */
	ITM_EXPR_IF,		/* if  */
	ITM_EXPR_ELSE		/* else */
} itm_expr_type_t;

#define	ITM_OPERAND_EXPR	(0)
#define	ITM_OPERAND_PLACE	(1)
#define	ITM_OPERAND_VALUE	(2)
#define	ITM_OPERAND_REGISTER	(3)

typedef struct {
	pad_t			pad;
	itm_expr_type_t		type;
	union {
		itm_place_t		operand[2];
		itm_data_t		value;
		struct {
#if !defined(_LP64) && !defined(_LITTLE_ENDIAN)
			pad_t		pad_num;
#endif
			itm_num_t	num;
#if !defined(_LP64) && defined(_LITTLE_ENDIAN)
			pad_t		pad_num;
#endif
		}			itm_ex_num;
	}	data;
} itm_expr_t;
#define	itm_exnum itm_ex_num.num
#define	itm_expad itm_ex_num.pad_num


#ifdef	__cplusplus
}
#endif

#endif /* !_ICONV_TM_H */
