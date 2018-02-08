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
 *	Copyright (c) 1988 AT&T
 *	  All Rights Reserved
 *
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Map file parsing (Shared Core Code).
 */
#include	<fcntl.h>
#include	<stdio.h>
#include	<unistd.h>
#include	<sys/stat.h>
#include	<errno.h>
#include	<limits.h>
#include	<dirent.h>
#include	<ctype.h>
#include	<debug.h>
#include	"msg.h"
#include	"_libld.h"
#include	"_map.h"

/*
 * There are two styles of mapfile supported by the link-editor:
 *
 * 1)	The original System V defined syntax, as augmented at Sun
 *	from Solaris 2.0 through Solaris 10. This style is also known
 *	as version 1.
 *
 * 2)	A newer syntax, currently at version 2.
 *
 * The original syntax uses special characters (=, :, -, |, etc) as
 * operators to indicate the operation being specified. Over the years,
 * this syntax has been problematic:
 *
 * 1)	Too cryptic: It's hard for people to remember which character
 *	means what.
 *
 * 2)	Limited expansion potential: There only a few special characters
 *	available on the keyboard for new features, and it is difficult to
 *	add options to existing ones.
 *
 * Adding new features into this framework (2) have the effect of
 * making the syntax even more cryptic (1). The newer syntax addresses
 * these issues by moving to an extendible identifier based syntax that
 * allows new features to be added without complicating old ones.
 *
 * The new syntax uses the following terminology:
 *
 * -	Control directives are the directives that start with a '$'.
 *	They control how the mapfile is interpreted. We use the 'cdir_'
 *	prefix on functions and variables related to these directives.
 *
 * -	Conditional Expressions are the expressions found in $if and $elif
 *	control directives. They evaluate to boolean true/false values.
 *	We use the 'cexp_' prefix for functions and variables related to
 *	these expressions.
 *
 * -	Regular Directives are names (SYMBOL, VERSION, etc) that convey
 *	directions to the link-editor for building the output object.
 *
 * This file contains core code used by both mapfile styles: File management,
 * lexical analysis, and other shared core functionality. It also contains
 * the code for control directives, as they are intrinsically part of
 * lexical analysis --- this is disabled when processing Sysv mapfiles.
 */

/*
 * We use a stack of cdir_level_t structs to manage $if/$elif/$else/$endif
 * processing. At each level, we keep track of the information needed to
 * determine whether or not to process nested input lines or skip them,
 * along with information needed to report errors.
 */
typedef struct {
	Lineno		cdl_if_lineno;	/* Line number of opening $if */
	Lineno		cdl_else_lineno; /* 0, or line on which $else seen */
	int		cdl_done;	/* True if no longer accepts input */
	int		cdl_pass;	/* True if currently accepting input */
} cdir_level_t;

/* Operators in the expressions accepted by $if/$elif */
typedef enum {
	CEXP_OP_NONE,		/* Not an operator */
	CEXP_OP_AND,		/* && */
	CEXP_OP_OR,		/* || */
	CEXP_OP_NEG,		/* ! */
	CEXP_OP_OPAR,		/* ( */
	CEXP_OP_CPAR		/* ) */
} cexp_op_t;

/*
 * Type of conditional expression identifier AVL tree nodes
 */
typedef struct cexp_name_node {
	avl_node_t	ceid_avlnode;	/* AVL book-keeping */
	const char	*ceid_name;	/* boolean identifier name */
} cexp_id_node_t;


/*
 * Declare a "stack" type, containing a pointer to data, a count of
 * allocated, and currently used items in the stack. The data type
 * is specified as the _type argument.
 */
#define	STACK(_type) \
	struct { \
		_type	*stk_s;		/* Stack array */ \
		size_t	stk_n;		/* Current stack depth */ \
		size_t	stk_n_alloc;	/* # of elements pointed at by s */ \
	}

/*
 * The following type represents a "generic" stack, where the data
 * type is (void). This type is never instantiated. However, it has
 * the same struct layout as any other STACK(), and is therefore a good
 * generic type that can be used for stack_resize().
 */
typedef STACK(void) generic_stack_t;

/*
 * Ensure that the stack has enough room to push one more item
 */
#define	STACK_RESERVE(_stack, _n_default) \
	(((_stack).stk_n < (_stack).stk_n_alloc) || \
	stack_resize((generic_stack_t *)&(_stack).stk_s, _n_default, \
	sizeof (*(_stack).stk_s)))

/*
 * Reset a stack to empty.
 */
#define	STACK_RESET(_stack) (_stack).stk_n = 0;

/*
 * True if stack is empty, False otherwise.
 */
#define	STACK_IS_EMPTY(_stack) ((_stack).stk_n == 0)

/*
 * Push a value onto a stack. Caller must ensure that stack has room.
 * This macro is intended to be used as the LHS of an assignment, the
 * RHS of which is the value:
 *
 *	STACK_PUSH(stack) = value;
 */
#define	STACK_PUSH(_stack) (_stack).stk_s[(_stack).stk_n++]

/*
 * Pop a value off a stack.  Caller must ensure
 * that stack is not empty.
 */
#define	STACK_POP(_stack) ((_stack).stk_s[--(_stack).stk_n])

/*
 * Access top element on stack without popping. Caller must ensure
 * that stack is not empty.
 */
#define	STACK_TOP(_stack) (((_stack).stk_s)[(_stack).stk_n - 1])

/*
 * Initial sizes used for the stacks: The stacks are allocated on demand
 * to these sizes, and then doubled as necessary until they are large enough.
 *
 * The ideal size would be large enough that only a single allocation
 * occurs, and our defaults should generally have that effect. However,
 * in doing so, we run the risk of a latent error in the resize code going
 * undetected until triggered by a large task in the field. For this reason,
 * we set the sizes to the smallest size possible when compiled for debug.
 */
#ifdef DEBUG
#define	CDIR_STACK_INIT		1
#define	CEXP_OP_STACK_INIT	1
#define	CEXP_VAL_STACK_INIT	1
#else
#define	CDIR_STACK_INIT 	16
#define	CEXP_OP_STACK_INIT	8
#define	CEXP_VAL_STACK_INIT	(CEXP_OP_STACK_INIT * 2) /* 2 vals per binop */
#endif


/*
 * Persistent state maintained by map module in between calls.
 *
 * This is kept as static file scope data, because it is only used
 * when libld is called by ld, and not by rtld. If that should change,
 * the code is designed so that it can become reentrant easily:
 *
 * -	Add a pointer to the output descriptor to a structure of this type,
 *	allocated dynamically on the first call to ld_map_parse().
 * -	Change all references to lms to instead reference the pointer in
 *	the output descriptor.
 *
 * Until then, it is simpler not to expose these details.
 */
typedef struct {
	int	lms_cdir_valid;	/* Allow control dir. on entry to gettoken() */
	STACK(cdir_level_t)	lms_cdir_stack;	/* Conditional input level */
	STACK(cexp_op_t)	lms_cexp_op_stack; /* Cond. expr operators */
	STACK(uchar_t)		lms_cexp_val_stack; /* Cond. expr values */
	avl_tree_t		*lms_cexp_id;
} ld_map_state_t;
static ld_map_state_t lms;


/*
 * Version 1 (SysV) syntax dispatch table for ld_map_gettoken(). For each
 * of the 7-bit ASCII characters, determine how the lexical analyzer
 * should behave.
 *
 * This table must be kept in sync with tkid_attr[] below.
 *
 * Identifier Note:
 * The Linker and Libraries Guide states that the original syntax uses
 * C identifier rules, allowing '.' to be treated as a letter. However,
 * the implementation is considerably looser than that: Any character
 * with an ASCII code (0-127) which is printable and not used to start
 * another token is allowed to start an identifier, and they are terminated
 * by any of: space, double quote, tab, newline, ':', ';', '=', or '#'.
 * The original code has been replaced, but this table encodes the same
 * rules, to ensure backward compatibility.
 */
static const mf_tokdisp_t gettok_dispatch_v1 = {
	TK_OP_EOF,			/* 0 - NUL */
	TK_OP_ILLCHR,			/* 1 - SOH */
	TK_OP_ILLCHR,			/* 2 - STX */
	TK_OP_ILLCHR,			/* 3 - ETX */
	TK_OP_ILLCHR,			/* 4 - EOT */
	TK_OP_ILLCHR,			/* 5 - ENQ */
	TK_OP_ILLCHR,			/* 6 - ACK */
	TK_OP_ILLCHR,			/* 7 - BEL */
	TK_OP_ILLCHR,			/* 8 - BS */
	TK_OP_WS,			/* 9 - HT */
	TK_OP_NL,			/* 10 - NL */
	TK_OP_WS,			/* 11 - VT */
	TK_OP_WS,			/* 12 - FF */
	TK_OP_WS,			/* 13 - CR */
	TK_OP_ILLCHR,			/* 14 - SO */
	TK_OP_ILLCHR,			/* 15 - SI */
	TK_OP_ILLCHR,			/* 16 - DLE */
	TK_OP_ILLCHR,			/* 17 - DC1 */
	TK_OP_ILLCHR,			/* 18 - DC2 */
	TK_OP_ILLCHR,			/* 19 - DC3 */
	TK_OP_ILLCHR,			/* 20 - DC4 */
	TK_OP_ILLCHR,			/* 21 - NAK */
	TK_OP_ILLCHR,			/* 22 - SYN */
	TK_OP_ILLCHR,			/* 23 - ETB */
	TK_OP_ILLCHR,			/* 24 - CAN */
	TK_OP_ILLCHR,			/* 25 - EM */
	TK_OP_ILLCHR,			/* 26 - SUB */
	TK_OP_ILLCHR,			/* 27 - ESC */
	TK_OP_ILLCHR,			/* 28 - FS */
	TK_OP_ILLCHR,			/* 29 - GS */
	TK_OP_ILLCHR,			/* 30 - RS */
	TK_OP_ILLCHR,			/* 31 - US */
	TK_OP_WS,			/* 32 - SP */
	TK_OP_ID,			/* 33 - ! */
	TK_OP_SIMQUOTE,			/* 34 - " */
	TK_OP_CMT,			/* 35 - # */
	TK_OP_ID,			/* 36 - $ */
	TK_OP_ID,			/* 37 - % */
	TK_OP_ID,			/* 38 - & */
	TK_OP_ID,			/* 39 - ' */
	TK_OP_ID,			/* 40 - ( */
	TK_OP_ID,			/* 41 - ) */
	TK_OP_ID,			/* 42 - * */
	TK_OP_ID,			/* 43 - + */
	TK_OP_ID,			/* 44 - , */
	TK_DASH,			/* 45 - - */
	TK_OP_ID,			/* 46 - . */
	TK_OP_ID,			/* 47 - / */
	TK_OP_ID,			/* 48 - 0 */
	TK_OP_ID,			/* 49 - 1 */
	TK_OP_ID,			/* 50 - 2 */
	TK_OP_ID,			/* 51 - 3 */
	TK_OP_ID,			/* 52 - 4 */
	TK_OP_ID,			/* 53 - 5 */
	TK_OP_ID,			/* 54 - 6 */
	TK_OP_ID,			/* 55 - 7 */
	TK_OP_ID,			/* 56 - 8 */
	TK_OP_ID,			/* 57 - 9 */
	TK_COLON,			/* 58 - : */
	TK_SEMICOLON,			/* 59 - ; */
	TK_OP_ID,			/* 60 - < */
	TK_EQUAL,			/* 61 - = */
	TK_OP_ID,			/* 62 - > */
	TK_OP_ID,			/* 63 - ? */
	TK_ATSIGN,			/* 64 - @ */
	TK_OP_ID,			/* 65 - A */
	TK_OP_ID,			/* 66 - B */
	TK_OP_ID,			/* 67 - C */
	TK_OP_ID,			/* 68 - D */
	TK_OP_ID,			/* 69 - E */
	TK_OP_ID,			/* 70 - F */
	TK_OP_ID,			/* 71 - G */
	TK_OP_ID,			/* 72 - H */
	TK_OP_ID,			/* 73 - I */
	TK_OP_ID,			/* 74 - J */
	TK_OP_ID,			/* 75 - K */
	TK_OP_ID,			/* 76 - L */
	TK_OP_ID,			/* 77 - M */
	TK_OP_ID,			/* 78 - N */
	TK_OP_ID,			/* 79 - O */
	TK_OP_ID,			/* 80 - P */
	TK_OP_ID,			/* 81 - Q */
	TK_OP_ID,			/* 82 - R */
	TK_OP_ID,			/* 83 - S */
	TK_OP_ID,			/* 84 - T */
	TK_OP_ID,			/* 85 - U */
	TK_OP_ID,			/* 86 - V */
	TK_OP_ID,			/* 87 - W */
	TK_OP_ID,			/* 88 - X */
	TK_OP_ID,			/* 89 - Y */
	TK_OP_ID,			/* 90 - Z */
	TK_OP_ID,			/* 91 - [ */
	TK_OP_ID,			/* 92 - \ */
	TK_OP_ID,			/* 93 - ] */
	TK_OP_ID,			/* 94 - ^ */
	TK_OP_ID,			/* 95 - _ */
	TK_OP_ID,			/* 96 - ` */
	TK_OP_ID,			/* 97 - a */
	TK_OP_ID,			/* 98 - b */
	TK_OP_ID,			/* 99 - c */
	TK_OP_ID,			/* 100 - d */
	TK_OP_ID,			/* 101 - e */
	TK_OP_ID,			/* 102 - f */
	TK_OP_ID,			/* 103 - g */
	TK_OP_ID,			/* 104 - h */
	TK_OP_ID,			/* 105 - i */
	TK_OP_ID,			/* 106 - j */
	TK_OP_ID,			/* 107 - k */
	TK_OP_ID,			/* 108 - l */
	TK_OP_ID,			/* 109 - m */
	TK_OP_ID,			/* 110 - n */
	TK_OP_ID,			/* 111 - o */
	TK_OP_ID,			/* 112 - p */
	TK_OP_ID,			/* 113 - q */
	TK_OP_ID,			/* 114 - r */
	TK_OP_ID,			/* 115 - s */
	TK_OP_ID,			/* 116 - t */
	TK_OP_ID,			/* 117 - u */
	TK_OP_ID,			/* 118 - v */
	TK_OP_ID,			/* 119 - w */
	TK_OP_ID,			/* 120 - x */
	TK_OP_ID,			/* 121 - y */
	TK_OP_ID,			/* 122 - z */
	TK_LEFTBKT,			/* 123 - { */
	TK_PIPE,			/* 124 - | */
	TK_RIGHTBKT,			/* 125 - } */
	TK_OP_ID,			/* 126 - ~ */
	TK_OP_ILLCHR,			/* 127 - DEL */
};

/*
 * Version 2 syntax dispatch table for ld_map_gettoken(). For each of the
 * 7-bit ASCII characters, determine how the lexical analyzer should behave.
 *
 * This table must be kept in sync with tkid_attr[] below.
 *
 * Identifier Note:
 * We define a letter as being one of the character [A-Z], [a-z], or [_%/.]
 * A digit is the numbers [0-9], or [$-]. An unquoted identifier is defined
 * as a letter, followed by any number of letters or digits. This is a loosened
 * version of the C definition of an identifier. The extra characters not
 * allowed by C are common in section names and/or file paths.
 */
static const mf_tokdisp_t gettok_dispatch_v2 = {
	TK_OP_EOF,			/* 0 - NUL */
	TK_OP_ILLCHR,			/* 1 - SOH */
	TK_OP_ILLCHR,			/* 2 - STX */
	TK_OP_ILLCHR,			/* 3 - ETX */
	TK_OP_ILLCHR,			/* 4 - EOT */
	TK_OP_ILLCHR,			/* 5 - ENQ */
	TK_OP_ILLCHR,			/* 6 - ACK */
	TK_OP_ILLCHR,			/* 7 - BEL */
	TK_OP_ILLCHR,			/* 8 - BS */
	TK_OP_WS,			/* 9 - HT */
	TK_OP_NL,			/* 10 - NL */
	TK_OP_WS,			/* 11 - VT */
	TK_OP_WS,			/* 12 - FF */
	TK_OP_WS,			/* 13 - CR */
	TK_OP_ILLCHR,			/* 14 - SO */
	TK_OP_ILLCHR,			/* 15 - SI */
	TK_OP_ILLCHR,			/* 16 - DLE */
	TK_OP_ILLCHR,			/* 17 - DC1 */
	TK_OP_ILLCHR,			/* 18 - DC2 */
	TK_OP_ILLCHR,			/* 19 - DC3 */
	TK_OP_ILLCHR,			/* 20 - DC4 */
	TK_OP_ILLCHR,			/* 21 - NAK */
	TK_OP_ILLCHR,			/* 22 - SYN */
	TK_OP_ILLCHR,			/* 23 - ETB */
	TK_OP_ILLCHR,			/* 24 - CAN */
	TK_OP_ILLCHR,			/* 25 - EM */
	TK_OP_ILLCHR,			/* 26 - SUB */
	TK_OP_ILLCHR,			/* 27 - ESC */
	TK_OP_ILLCHR,			/* 28 - FS */
	TK_OP_ILLCHR,			/* 29 - GS */
	TK_OP_ILLCHR,			/* 30 - RS */
	TK_OP_ILLCHR,			/* 31 - US */
	TK_OP_WS,			/* 32 - SP */
	TK_BANG,			/* 33 - ! */
	TK_OP_CQUOTE,			/* 34 - " */
	TK_OP_CMT,			/* 35 - # */
	TK_OP_CDIR,			/* 36 - $ */
	TK_OP_ID,			/* 37 - % */
	TK_OP_BADCHR,			/* 38 - & */
	TK_OP_SIMQUOTE,			/* 39 - ' */
	TK_OP_BADCHR,			/* 40 - ( */
	TK_OP_BADCHR,			/* 41 - ) */
	TK_STAR,			/* 42 - * */
	TK_OP_CEQUAL,			/* 43 - + */
	TK_OP_BADCHR,			/* 44 - , */
	TK_OP_CEQUAL,			/* 45 - - */
	TK_OP_ID,			/* 46 - . */
	TK_OP_ID,			/* 47 - / */
	TK_OP_NUM,			/* 48 - 0 */
	TK_OP_NUM,			/* 49 - 1 */
	TK_OP_NUM,			/* 50 - 2 */
	TK_OP_NUM,			/* 51 - 3 */
	TK_OP_NUM,			/* 52 - 4 */
	TK_OP_NUM,			/* 53 - 5 */
	TK_OP_NUM,			/* 54 - 6 */
	TK_OP_NUM,			/* 55 - 7 */
	TK_OP_NUM,			/* 56 - 8 */
	TK_OP_NUM,			/* 57 - 9 */
	TK_COLON,			/* 58 - : */
	TK_SEMICOLON,			/* 59 - ; */
	TK_OP_BADCHR,			/* 60 - < */
	TK_EQUAL,			/* 61 - = */
	TK_OP_BADCHR,			/* 62 - > */
	TK_OP_BADCHR,			/* 63 - ? */
	TK_OP_BADCHR,			/* 64 - @ */
	TK_OP_ID,			/* 65 - A */
	TK_OP_ID,			/* 66 - B */
	TK_OP_ID,			/* 67 - C */
	TK_OP_ID,			/* 68 - D */
	TK_OP_ID,			/* 69 - E */
	TK_OP_ID,			/* 70 - F */
	TK_OP_ID,			/* 71 - G */
	TK_OP_ID,			/* 72 - H */
	TK_OP_ID,			/* 73 - I */
	TK_OP_ID,			/* 74 - J */
	TK_OP_ID,			/* 75 - K */
	TK_OP_ID,			/* 76 - L */
	TK_OP_ID,			/* 77 - M */
	TK_OP_ID,			/* 78 - N */
	TK_OP_ID,			/* 79 - O */
	TK_OP_ID,			/* 80 - P */
	TK_OP_ID,			/* 81 - Q */
	TK_OP_ID,			/* 82 - R */
	TK_OP_ID,			/* 83 - S */
	TK_OP_ID,			/* 84 - T */
	TK_OP_ID,			/* 85 - U */
	TK_OP_ID,			/* 86 - V */
	TK_OP_ID,			/* 87 - W */
	TK_OP_ID,			/* 88 - X */
	TK_OP_ID,			/* 89 - Y */
	TK_OP_ID,			/* 90 - Z */
	TK_OP_BADCHR,			/* 91 - [ */
	TK_OP_BADCHR,			/* 92 - \ */
	TK_OP_BADCHR,			/* 93 - ] */
	TK_OP_BADCHR,			/* 94 - ^ */
	TK_OP_ID,			/* 95 - _ */
	TK_OP_BADCHR,			/* 96 - ` */
	TK_OP_ID,			/* 97 - a */
	TK_OP_ID,			/* 98 - b */
	TK_OP_ID,			/* 99 - c */
	TK_OP_ID,			/* 100 - d */
	TK_OP_ID,			/* 101 - e */
	TK_OP_ID,			/* 102 - f */
	TK_OP_ID,			/* 103 - g */
	TK_OP_ID,			/* 104 - h */
	TK_OP_ID,			/* 105 - i */
	TK_OP_ID,			/* 106 - j */
	TK_OP_ID,			/* 107 - k */
	TK_OP_ID,			/* 108 - l */
	TK_OP_ID,			/* 109 - m */
	TK_OP_ID,			/* 110 - n */
	TK_OP_ID,			/* 111 - o */
	TK_OP_ID,			/* 112 - p */
	TK_OP_ID,			/* 113 - q */
	TK_OP_ID,			/* 114 - r */
	TK_OP_ID,			/* 115 - s */
	TK_OP_ID,			/* 116 - t */
	TK_OP_ID,			/* 117 - u */
	TK_OP_ID,			/* 118 - v */
	TK_OP_ID,			/* 119 - w */
	TK_OP_ID,			/* 120 - x */
	TK_OP_ID,			/* 121 - y */
	TK_OP_ID,			/* 122 - z */
	TK_LEFTBKT,			/* 123 - { */
	TK_OP_BADCHR,			/* 124 - | */
	TK_RIGHTBKT,			/* 125 - } */
	TK_OP_BADCHR,			/* 126 - ~ */
	TK_OP_ILLCHR,			/* 127 - DEL */
};


/*
 * Table used to identify unquoted identifiers. Each element of this array
 * contains a bitmask indicating whether the character it represents starts,
 * or continues an identifier, for each supported mapfile syntax version.
 */
static const char tkid_attr[128] = {
	0,					/* 0 - NUL */
	TKID_ATTR_CONT(1),			/* 1 - SOH */
	TKID_ATTR_CONT(1),			/* 2 - STX */
	TKID_ATTR_CONT(1),			/* 3 - ETX */
	TKID_ATTR_CONT(1),			/* 4 - EOT */
	TKID_ATTR_CONT(1),			/* 5 - ENQ */
	TKID_ATTR_CONT(1),			/* 6 - ACK */
	TKID_ATTR_CONT(1),			/* 7 - BEL */
	TKID_ATTR_CONT(1),			/* 8 - BS */
	0,					/* 9 - HT */
	0,					/* 10 - NL */
	TKID_ATTR_CONT(1),			/* 11 - VT */
	TKID_ATTR_CONT(1),			/* 12 - FF */
	TKID_ATTR_CONT(1),			/* 13 - CR */
	TKID_ATTR_CONT(1),			/* 14 - SO */
	TKID_ATTR_CONT(1),			/* 15 - SI */
	TKID_ATTR_CONT(1),			/* 16 - DLE */
	TKID_ATTR_CONT(1),			/* 17 - DC1 */
	TKID_ATTR_CONT(1),			/* 18 - DC2 */
	TKID_ATTR_CONT(1),			/* 19 - DC3 */
	TKID_ATTR_CONT(1),			/* 20 - DC4 */
	TKID_ATTR_CONT(1),			/* 21 - NAK */
	TKID_ATTR_CONT(1),			/* 22 - SYN */
	TKID_ATTR_CONT(1),			/* 23 - ETB */
	TKID_ATTR_CONT(1),			/* 24 - CAN */
	TKID_ATTR_CONT(1),			/* 25 - EM */
	TKID_ATTR_CONT(1),			/* 26 - SUB */
	TKID_ATTR_CONT(1),			/* 27 - ESC */
	TKID_ATTR_CONT(1),			/* 28 - FS */
	TKID_ATTR_CONT(1),			/* 29 - GS */
	TKID_ATTR_CONT(1),			/* 30 - RS */
	TKID_ATTR_CONT(1),			/* 31 - US */
	0,					/* 32 - SP */
	TKID_ATTR(1),				/* 33 - ! */
	0,					/* 34 - " */
	0,					/* 35 - # */
	TKID_ATTR(1) | TKID_ATTR_CONT(2),	/* 36 - $ */
	TKID_ATTR(1) | TKID_ATTR_CONT(2),	/* 37 - % */
	TKID_ATTR(1),				/* 38 - & */
	TKID_ATTR(1),				/* 39 - ' */
	TKID_ATTR(1),				/* 40 - ( */
	TKID_ATTR(1),				/* 41 - ) */
	TKID_ATTR(1),				/* 42 - * */
	TKID_ATTR(1),				/* 43 - + */
	TKID_ATTR(1),				/* 44 - , */
	TKID_ATTR_CONT(1) | TKID_ATTR_CONT(2),	/* 45 - - */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 46 - . */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 47 - / */
	TKID_ATTR(1) | TKID_ATTR_CONT(2),	/* 48 - 0 */
	TKID_ATTR(1) | TKID_ATTR_CONT(2),	/* 49 - 1 */
	TKID_ATTR(1) | TKID_ATTR_CONT(2),	/* 50 - 2 */
	TKID_ATTR(1) | TKID_ATTR_CONT(2),	/* 51 - 3 */
	TKID_ATTR(1) | TKID_ATTR_CONT(2),	/* 52 - 4 */
	TKID_ATTR(1) | TKID_ATTR_CONT(2),	/* 53 - 5 */
	TKID_ATTR(1) | TKID_ATTR_CONT(2),	/* 54 - 6 */
	TKID_ATTR(1) | TKID_ATTR_CONT(2),	/* 55 - 7 */
	TKID_ATTR(1) | TKID_ATTR_CONT(2),	/* 56 - 8 */
	TKID_ATTR(1) | TKID_ATTR_CONT(2),	/* 57 - 9 */
	0,					/* 58 - : */
	0,					/* 59 - ; */
	TKID_ATTR(1),				/* 60 - < */
	0,					/* 61 - = */
	TKID_ATTR(1),				/* 62 - > */
	TKID_ATTR(1),				/* 63 - ? */
	TKID_ATTR_CONT(1),			/* 64 - @ */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 65 - A */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 66 - B */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 67 - C */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 68 - D */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 69 - E */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 70 - F */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 71 - G */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 72 - H */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 73 - I */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 74 - J */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 75 - K */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 76 - L */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 77 - M */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 78 - N */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 79 - O */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 80 - P */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 81 - Q */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 82 - R */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 83 - S */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 84 - T */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 85 - U */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 86 - V */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 87 - W */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 88 - X */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 89 - Y */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 90 - Z */
	TKID_ATTR(1),				/* 91 - [ */
	TKID_ATTR(1),				/* 92 - \ */
	TKID_ATTR(1),				/* 93 - ] */
	TKID_ATTR(1),				/* 94 - ^ */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 95 - _ */
	TKID_ATTR(1),				/* 96 - ` */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 97 - a */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 98 - b */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 99 - c */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 100 - d */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 101 - e */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 102 - f */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 103 - g */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 104 - h */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 105 - i */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 106 - j */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 107 - k */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 108 - l */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 109 - m */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 110 - n */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 111 - o */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 112 - p */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 113 - q */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 114 - r */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 115 - s */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 116 - t */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 117 - u */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 118 - v */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 119 - w */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 120 - x */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 121 - y */
	TKID_ATTR(1) | TKID_ATTR(2),		/* 122 - z */
	TKID_ATTR_CONT(1),			/* 123 - { */
	TKID_ATTR_CONT(1),			/* 124 - | */
	TKID_ATTR_CONT(1),			/* 125 - } */
	TKID_ATTR(1),				/* 126 - ~ */
	TKID_ATTR_CONT(1),			/* 127 - DEL */
};


/*
 * Advance the given string pointer to the next newline character,
 * or the terminating NULL if there is none.
 */
inline static void
advance_to_eol(char **str)
{
	char	*s = *str;

	while ((*s != '\n') && (*s != '\0'))
		s++;
	*str = s;
}

/*
 * Insert a NULL patch at the given address
 */
inline static void
null_patch_set(char *str, ld_map_npatch_t *np)
{
	np->np_ptr = str;
	np->np_ch = *str;
	*str = '\0';
}

/*
 * Undo a NULL patch
 */
inline static void
null_patch_undo(ld_map_npatch_t *np)
{
	*np->np_ptr = np->np_ch;
}

/*
 * Insert a NULL patch at the end of the line containing str.
 */
static void
null_patch_eol(char *str, ld_map_npatch_t *np)
{
	advance_to_eol(&str);
	null_patch_set(str, np);
}

/*
 * Locate the end of an unquoted identifier.
 *
 * entry:
 *	mf - Mapfile descriptor, positioned to first character
 *		of identifier.
 *
 * exit:
 *	If the item pointed at by mf is not an identifier, returns NULL.
 *	Otherwise, returns pointer to character after the last character
 *	of the identifier.
 */
inline static char *
ident_delimit(Mapfile *mf)
{
	char		*str = mf->mf_next;
	ld_map_npatch_t	np;
	int		c = *str++;

	/* If not a valid start character, report the error */
	if ((c & 0x80) || !(tkid_attr[c] & mf->mf_tkid_start)) {
		null_patch_set(str, &np);
		mf_fatal(mf, MSG_INTL(MSG_MAP_BADCHAR), str);
		null_patch_undo(&np);
		return (NULL);
	}

	/* Keep going until we hit a non-continuing character */
	for (c = *str; !(c & 0x80) && (tkid_attr[c] & mf->mf_tkid_cont);
	    c = *++str)
		;

	return (str);
}

/*
 * Allocate memory for a stack.
 *
 * entry:
 *	stack - Pointer to stack for which memory is required, cast
 *		to the generic stack type.
 *	n_default - Size to use for initial allocation.
 *	elt_size - sizeof(elt), where elt is the actual stack data type.
 *
 * exit:
 *	Returns (1) on success. On error (memory allocation), a message
 *	is printed and False (0) is returned.
 *
 * note:
 *	The caller casts the pointer to their actual datatype-specific stack
 *	to be a (generic_stack_t *). The C language will give all stack
 *	structs the same size and layout as long as the underlying platform
 *	uses a single integral type for pointers. Hence, this cast is safe,
 *	and lets a generic routine modify data-specific types without being
 *	aware of those types.
 */
static Boolean
stack_resize(generic_stack_t *stack, size_t n_default, size_t elt_size)
{
	size_t	new_n_alloc;
	void	*newaddr;

	/* Use initial size first, and double the allocation on each call */
	new_n_alloc = (stack->stk_n_alloc == 0) ?
	    n_default : (stack->stk_n_alloc * 2);

	newaddr = libld_realloc(stack->stk_s, new_n_alloc * elt_size);
	if (newaddr == NULL)
		return (FALSE);

	stack->stk_s = newaddr;
	stack->stk_n_alloc = new_n_alloc;
	return (TRUE);
}

/*
 * AVL comparison function for cexp_id_node_t items.
 *
 * entry:
 *      n1, n2 - pointers to nodes to be compared
 *
 * exit:
 *      Returns -1 if (n1 < n2), 0 if they are equal, and 1 if (n1 > n2)
 */
static int
cexp_ident_cmp(const void *n1, const void *n2)
{
	int	rc;

	rc = strcmp(((cexp_id_node_t *)n1)->ceid_name,
	    ((cexp_id_node_t *)n2)->ceid_name);

	if (rc > 0)
		return (1);
	if (rc < 0)
		return (-1);
	return (0);
}


/*
 * Returns True (1) if name is in the conditional expression identifier
 * AVL tree, and False (0) otherwise.
 */
static int
cexp_ident_test(const char *name)
{
	cexp_id_node_t	node;

	node.ceid_name = name;
	return (avl_find(lms.lms_cexp_id, &node, 0) != NULL);
}

/*
 * Add a new boolean identifier to the conditional expression identifier
 * AVL tree.
 *
 * entry:
 *	mf - If non-NULL, the mapfile descriptor for the mapfile
 *		containing the $add directive. NULL if this is an
 *		initialization call.
 *	name - Name of identifier. Must point at stable storage that will
 *		not be moved or modified by the caller following this call.
 *
 * exit:
 *	On success, True (1) is returned and name has been entered.
 *	On failure, False (0) is returned and an error has been printed.
 */
static int
cexp_ident_add(Mapfile *mf, const char *name)
{
	cexp_id_node_t	*node;

	if (mf != NULL) {
		DBG_CALL(Dbg_map_cexp_id(mf->mf_ofl->ofl_lml, 1,
		    mf->mf_name, mf->mf_lineno, name));

		/* If is already known, don't do it again */
		if (cexp_ident_test(name))
			return (1);
	}

	if ((node = libld_calloc(sizeof (*node), 1)) == NULL)
		return (0);
	node->ceid_name = name;
	avl_add(lms.lms_cexp_id, node);
	return (1);
}

/*
 * Remove a boolean identifier from the conditional expression identifier
 * AVL tree.
 *
 * entry:
 *	mf - Mapfile descriptor
 *	name - Name of identifier.
 *
 * exit:
 *	If the name was in the tree, it has been removed. If not,
 *	then this routine quietly returns.
 */
static void
cexp_ident_clear(Mapfile *mf, const char *name)
{
	cexp_id_node_t	node;
	cexp_id_node_t	*real_node;

	DBG_CALL(Dbg_map_cexp_id(mf->mf_ofl->ofl_lml, 0,
	    mf->mf_name, mf->mf_lineno, name));

	node.ceid_name = name;
	real_node = avl_find(lms.lms_cexp_id, &node, 0);
	if (real_node != NULL)
		avl_remove(lms.lms_cexp_id, real_node);
}

/*
 * Initialize the AVL tree that holds the names of the currently defined
 * boolean identifiers for conditional expressions ($if/$elif).
 *
 * entry:
 *	ofl - Output file descriptor
 *
 * exit:
 *	On success, TRUE (1) is returned and lms.lms_cexp_id is ready for use.
 *	On failure, FALSE (0) is returned.
 */
static Boolean
cexp_ident_init(void)
{
	/* If already done, use it */
	if (lms.lms_cexp_id != NULL)
		return (TRUE);

	lms.lms_cexp_id = libld_calloc(sizeof (*lms.lms_cexp_id), 1);
	if (lms.lms_cexp_id == NULL)
		return (FALSE);
	avl_create(lms.lms_cexp_id, cexp_ident_cmp, sizeof (cexp_id_node_t),
	    SGSOFFSETOF(cexp_id_node_t, ceid_avlnode));


	/* ELFCLASS */
	if (cexp_ident_add(NULL, (ld_targ.t_m.m_class == ELFCLASS32) ?
	    MSG_ORIG(MSG_STR_UELF32) : MSG_ORIG(MSG_STR_UELF64)) == 0)
		return (FALSE);

	/* Machine */
	switch (ld_targ.t_m.m_mach) {
	case EM_386:
	case EM_AMD64:
		if (cexp_ident_add(NULL, MSG_ORIG(MSG_STR_UX86)) == 0)
			return (FALSE);
		break;

	case EM_SPARC:
	case EM_SPARCV9:
		if (cexp_ident_add(NULL, MSG_ORIG(MSG_STR_USPARC)) == 0)
			return (FALSE);
		break;
	}

	/* true is always defined */
	if (cexp_ident_add(NULL, MSG_ORIG(MSG_STR_TRUE)) == 0)
		return (FALSE);

	return (TRUE);
}

/*
 * Validate the string starting at mf->mf_next as being a
 * boolean conditional expression identifier.
 *
 * entry:
 *	mf - Mapfile descriptor
 *	len - NULL, or address of variable to receive strlen() of identifier
 *	directive - If (len == NULL), string giving name of directive being
 *		processed. Ignored if (len != NULL).
 *
 * exit:
 *	On success:
 *	-	If len is NULL, a NULL is inserted following the final
 *		character of the identifier, and the remainder of the string
 *		is tested to ensure it is empty, or only contains whitespace.
 *	-	If len is non-NULL, *len is set to the number of characters
 *		in the identifier, and the rest of the string is not modified.
 *	-	TRUE (1) is returned
 *
 *	On failure, returns FALSE (0).
 */
static Boolean
cexp_ident_validate(Mapfile *mf, size_t *len, const char *directive)
{
	char	*tail;

	if ((tail = ident_delimit(mf)) == NULL)
		return (FALSE);

	/*
	 * If len is non-NULL, we simple count the number of characters
	 * consumed by the identifier and are done. If len is NULL, then
	 * ensure there's nothing left but whitespace, and NULL terminate
	 * the identifier to remove it.
	 */
	if (len != NULL) {
		*len = tail - mf->mf_next;
	} else if (*tail != '\0') {
		*tail++ = '\0';
		while (isspace(*tail))
			tail++;
		if (*tail != '\0') {
			mf_fatal(mf, MSG_INTL(MSG_MAP_BADEXTRA), directive);
			return (FALSE);
		}
	}

	return (TRUE);
}

/*
 * Push a new operator onto the conditional expression operator stack.
 *
 * entry:
 *	mf - Mapfile descriptor
 *	op - Operator to push
 *
 * exit:
 *	On success, TRUE (1) is returned, otherwise FALSE (0).
 */
static Boolean
cexp_push_op(cexp_op_t op)
{
	if (STACK_RESERVE(lms.lms_cexp_op_stack, CEXP_OP_STACK_INIT) == 0)
		return (FALSE);

	STACK_PUSH(lms.lms_cexp_op_stack) = op;
	return (TRUE);
}

/*
 * Evaluate the basic operator (non-paren) at the top of lms.lms_cexp_op_stack,
 * and push the results on lms.lms_cexp_val_stack.
 *
 * exit:
 *	On success, returns TRUE (1). On error, FALSE (0) is returned,
 *	and the caller is responsible for issuing the error.
 */
static Boolean
cexp_eval_op(void)
{
	cexp_op_t	op;
	uchar_t		val;

	op = STACK_POP(lms.lms_cexp_op_stack);
	switch (op) {
	case CEXP_OP_AND:
		if (lms.lms_cexp_val_stack.stk_n < 2)
			return (FALSE);
		val = STACK_POP(lms.lms_cexp_val_stack);
		STACK_TOP(lms.lms_cexp_val_stack) = val &&
		    STACK_TOP(lms.lms_cexp_val_stack);
		break;

	case CEXP_OP_OR:
		if (lms.lms_cexp_val_stack.stk_n < 2)
			return (FALSE);
		val = STACK_POP(lms.lms_cexp_val_stack);
		STACK_TOP(lms.lms_cexp_val_stack) = val ||
		    STACK_TOP(lms.lms_cexp_val_stack);
		break;

	case CEXP_OP_NEG:
		if (lms.lms_cexp_val_stack.stk_n < 1)
			return (FALSE);
		STACK_TOP(lms.lms_cexp_val_stack) =
		    !STACK_TOP(lms.lms_cexp_val_stack);
		break;
	default:
		return (FALSE);
	}

	return (TRUE);
}

/*
 * Evaluate an expression for a $if/$elif control directive.
 *
 * entry:
 *	mf - Mapfile descriptor for NULL terminated string
 *		containing the expression.
 *
 * exit:
 *	The contents of str are modified by this routine.
 *	One of the following values are returned:
 *		-1	Syntax error encountered (an error is printed)
 *		0	The expression evaluates to False
 *		1	The expression evaluates to True.
 *
 * note:
 *	A simplified version of Dijkstra's Shunting Yard algorithm is used
 *	to convert this syntax into postfix form and then evaluate it.
 *	Our version has no functions and a tiny set of operators.
 *
 *	The expressions consist of boolean identifiers, which can be
 *	combined using the following operators, listed from highest
 *	precedence to least:
 *
 *		Operator	Meaning
 *		-------------------------------------------------
 *		(expr)		sub-expression, non-associative
 *		!		logical negation, prefix, left associative
 *		&&  ||		logical and/or, binary, left associative
 *
 *	The operands manipulated by these operators are names, consisting of
 *	a sequence of letters and digits. The first character must be a letter.
 *	Underscore (_) and period (.) are also considered to be characters.
 *	An operand is considered True if it is found in our set of known
 *	names (lms.lms_cexp_id), and False otherwise.
 *
 *	The Shunting Yard algorithm works using two stacks, one for operators,
 *	and a second for operands. The infix input expression is tokenized from
 *	left to right and processed in order. Issues of associativity and
 *	precedence are managed by reducing (poping and evaluating) items with
 *	higer precedence before pushing additional tokens with lower precedence.
 */
static int
cexp_eval_expr(Mapfile *mf)
{
	char		*ident;
	size_t		len;
	cexp_op_t	new_op = CEXP_OP_AND;	/* to catch binop at start */
	ld_map_npatch_t	np;
	char		*str = mf->mf_next;

	STACK_RESET(lms.lms_cexp_op_stack);
	STACK_RESET(lms.lms_cexp_val_stack);

	for (; *str; str++) {

		/* Skip whitespace */
		while (isspace(*str))
			str++;
		if (!*str)
			break;

		switch (*str) {
		case '&':
		case '|':
			if (*(str + 1) != *str)
				goto token_error;
			if ((new_op != CEXP_OP_NONE) &&
			    (new_op != CEXP_OP_CPAR)) {
				mf_fatal0(mf, MSG_INTL(MSG_MAP_CEXP_BADOPUSE));
				return (-1);
			}
			str++;

			/*
			 * As this is a left associative binary operator, we
			 * need to process all operators of equal or higher
			 * precedence before pushing the new operator.
			 */
			while (!STACK_IS_EMPTY(lms.lms_cexp_op_stack)) {
				cexp_op_t op = STACK_TOP(lms.lms_cexp_op_stack);


				if ((op != CEXP_OP_AND) && (op != CEXP_OP_OR) &&
				    (op != CEXP_OP_NEG))
					break;

				if (!cexp_eval_op())
					goto semantic_error;
			}

			new_op = (*str == '&') ? CEXP_OP_AND : CEXP_OP_OR;
			if (!cexp_push_op(new_op))
				return (-1);
			break;

		case '!':
			new_op = CEXP_OP_NEG;
			if (!cexp_push_op(new_op))
				return (-1);
			break;

		case '(':
			new_op = CEXP_OP_OPAR;
			if (!cexp_push_op(new_op))
				return (-1);
			break;

		case ')':
			new_op = CEXP_OP_CPAR;

			/* Evaluate the operator stack until reach '(' */
			while (!STACK_IS_EMPTY(lms.lms_cexp_op_stack) &&
			    (STACK_TOP(lms.lms_cexp_op_stack) != CEXP_OP_OPAR))
				if (!cexp_eval_op())
					goto semantic_error;

			/*
			 * If the top of operator stack is not an open paren,
			 * when we have an error. In this case, the operator
			 * stack will be empty due to the loop above.
			 */
			if (STACK_IS_EMPTY(lms.lms_cexp_op_stack))
				goto unbalpar_error;
			lms.lms_cexp_op_stack.stk_n--;   /* Pop OPAR */
			break;

		default:
			/* Ensure there's room to push another operand */
			if (STACK_RESERVE(lms.lms_cexp_val_stack,
			    CEXP_VAL_STACK_INIT) == 0)
				return (0);
			new_op = CEXP_OP_NONE;

			/*
			 * Operands cannot be numbers. However, we accept two
			 * special cases: '0' means false, and '1' is true.
			 * This is done to support the common C idiom of
			 * '#if 1' and '#if 0' to conditionalize code under
			 * development.
			 */
			if ((*str == '0') || (*str == '1')) {
				STACK_PUSH(lms.lms_cexp_val_stack) =
				    (*str == '1');
				break;
			}

			/* Look up the identifier */
			ident = mf->mf_next = str;
			if (!cexp_ident_validate(mf, &len, NULL))
				return (-1);
			str += len - 1;	  /* loop will advance past final ch */
			null_patch_set(&ident[len], &np);
			STACK_PUSH(lms.lms_cexp_val_stack) =
			    cexp_ident_test(ident);
			null_patch_undo(&np);

			break;
		}
	}

	/* Evaluate the operator stack until empty */
	while (!STACK_IS_EMPTY(lms.lms_cexp_op_stack)) {
		if (STACK_TOP(lms.lms_cexp_op_stack) == CEXP_OP_OPAR)
			goto unbalpar_error;

		if (!cexp_eval_op())
			goto semantic_error;
	}

	/* There should be exactly one value left */
	if (lms.lms_cexp_val_stack.stk_n != 1)
		goto semantic_error;

	/* Final value is the result */
	return (lms.lms_cexp_val_stack.stk_s[0]);

	/* Errors issued more than once are handled below, accessed via goto */

token_error:			/* unexpected characters in input stream */
	mf_fatal(mf, MSG_INTL(MSG_MAP_CEXP_TOKERR), str);
	return (-1);

semantic_error:			/* valid tokens, but in invalid arrangement */
	mf_fatal0(mf, MSG_INTL(MSG_MAP_CEXP_SEMERR));
	return (-1);

unbalpar_error:			/* Extra or missing parenthesis */
	mf_fatal0(mf, MSG_INTL(MSG_MAP_CEXP_UNBALPAR));
	return (-1);
}

/*
 * Process a mapfile control directive. These directives start with
 * the dollar character, and are used to manage details of the mapfile
 * itself, such as version and conditional input.
 *
 * entry:
 *	mf - Mapfile descriptor
 *
 * exit:
 *	Returns TRUE (1) for success, and FALSE (0) on error. In the
 *	error case, a descriptive error is issued.
 */
static Boolean
cdir_process(Mapfile *mf)
{
	typedef enum {			/* Directive types */
		CDIR_T_UNKNOWN = 0,	/* Unrecognized control directive */
		CDIR_T_ADD,		/* $add */
		CDIR_T_CLEAR,		/* $clear */
		CDIR_T_ERROR,		/* $error */
		CDIR_T_VERSION,		/* $mapfile_version */
		CDIR_T_IF,		/* $if */
		CDIR_T_ELIF,		/* $elif */
		CDIR_T_ELSE,		/* $else */
		CDIR_T_ENDIF,		/* $endif */
	} cdir_t;

	typedef enum {		/* Types of arguments accepted by directives */
		ARG_T_NONE,	/* Directive takes no arguments */
		ARG_T_EXPR,	/* Directive takes a conditional expression */
		ARG_T_ID,	/* Conditional expression identifier */
		ARG_T_STR,	/* Non-empty string */
		ARG_T_IGN	/* Ignore the argument */
	} cdir_arg_t;

	typedef struct {
		const char	*md_name;	/* Directive name */
		size_t		md_size;	/* strlen(md_name) */
		cdir_arg_t	md_arg;		/* Type of arguments */
		cdir_t		md_op;		/* CDIR_T_ code */
	} cdir_match_t;

	/* Control Directives: The most likely items are listed first */
	static cdir_match_t match_data[] = {
		{ MSG_ORIG(MSG_STR_CDIR_IF),	MSG_STR_CDIR_IF_SIZE,
		    ARG_T_EXPR,			CDIR_T_IF },
		{ MSG_ORIG(MSG_STR_CDIR_ENDIF),	MSG_STR_CDIR_ENDIF_SIZE,
		    ARG_T_NONE,			CDIR_T_ENDIF },
		{ MSG_ORIG(MSG_STR_CDIR_ELSE),	MSG_STR_CDIR_ELSE_SIZE,
		    ARG_T_NONE,			CDIR_T_ELSE },
		{ MSG_ORIG(MSG_STR_CDIR_ELIF),	MSG_STR_CDIR_ELIF_SIZE,
		    ARG_T_EXPR,			CDIR_T_ELIF },
		{ MSG_ORIG(MSG_STR_CDIR_ERROR),	MSG_STR_CDIR_ERROR_SIZE,
		    ARG_T_STR,			CDIR_T_ERROR },
		{ MSG_ORIG(MSG_STR_CDIR_ADD),	MSG_STR_CDIR_ADD_SIZE,
		    ARG_T_ID,			CDIR_T_ADD },
		{ MSG_ORIG(MSG_STR_CDIR_CLEAR),	MSG_STR_CDIR_CLEAR_SIZE,
		    ARG_T_ID,			CDIR_T_CLEAR },
		{ MSG_ORIG(MSG_STR_CDIR_MFVER),	MSG_STR_CDIR_MFVER_SIZE,
		    ARG_T_IGN,			CDIR_T_VERSION },

		{ NULL,				0,
		    ARG_T_IGN,			CDIR_T_UNKNOWN }
	};

	cdir_match_t	*mdptr;
	char		*tail;
	int		expr_eval;	/* Result of evaluating ARG_T_EXPR */
	Mapfile		arg_mf;
	cdir_level_t	*level;
	int		pass, parent_pass;	/* Currently accepting input */

restart:
	/* Is the immediate context passing input? */
	pass = STACK_IS_EMPTY(lms.lms_cdir_stack) ||
	    STACK_TOP(lms.lms_cdir_stack).cdl_pass;

	/* Is the surrounding (parent) context passing input? */
	parent_pass = (lms.lms_cdir_stack.stk_n <= 1) ||
	    lms.lms_cdir_stack.stk_s[lms.lms_cdir_stack.stk_n - 2].cdl_pass;


	for (mdptr = match_data; mdptr->md_name; mdptr++) {
		/* Prefix must match, or we move on */
		if (strncmp(mf->mf_next, mdptr->md_name,
		    mdptr->md_size) != 0)
			continue;
		tail = mf->mf_next + mdptr->md_size;

		/*
		 * If there isn't whitespace, or a NULL terminator following
		 * the prefix, then even though our prefix matched, the actual
		 * token is longer, and we don't have a match.
		 */
		if (!isspace(*tail) && (*tail != '\0'))
			continue;

		/* We have matched a valid control directive */
		break;
	}

	/* Advance input to end of the current line */
	advance_to_eol(&mf->mf_next);

	/*
	 * Set up a temporary mapfile descriptor to reference the
	 * argument string. The benefit of this second block, is that
	 * we can advance the real one to the next line now, which allows
	 * us to return at any time knowing that the input has been moved
	 * to the proper spot. This simplifies the error cases.
	 *
	 * If we had a match, tail points at the start of the string.
	 * Otherwise, we want to point at the end of the line.
	 */
	arg_mf = *mf;
	if (mdptr->md_name == NULL)
		arg_mf.mf_text = arg_mf.mf_next;
	else
		arg_mf.mf_text = arg_mf.mf_next = tail;

	/*
	 * Null terminate the arguments, and advance the main mapfile
	 * state block to the next line.
	 */
	if (*mf->mf_next == '\n') {
		*mf->mf_next++ = '\0';
		mf->mf_lineno++;
	}

	/* Skip leading whitespace to arguments */
	while (isspace(*arg_mf.mf_next))
		arg_mf.mf_next++;

	/* Strip off any comment present on the line */
	for (tail = arg_mf.mf_next; *tail; tail++)
		if (*tail == '#') {
			*tail = '\0';
			break;
		}

	/*
	 * Process the arguments as necessary depending on their type.
	 * If this control directive is nested inside a surrounding context
	 * that is not currently passing text, then we skip the argument
	 * evaluation. This follows the behavior of the C preprocessor,
	 * which only examines enough to detect the operation within
	 * a disabled section, without issuing errors about the arguments.
	 */
	if (pass || (parent_pass && (mdptr->md_op == CDIR_T_ELIF))) {
		switch (mdptr->md_arg) {
		case ARG_T_NONE:
			if (*arg_mf.mf_next == '\0')
				break;
			/* Args are present, but not wanted */
			mf_fatal(&arg_mf, MSG_INTL(MSG_MAP_CDIR_REQNOARG),
			    mdptr->md_name);
			return (FALSE);

		case ARG_T_EXPR:
			/* Ensure that arguments are present */
			if (*arg_mf.mf_next == '\0')
				goto error_reqarg;
			expr_eval = cexp_eval_expr(&arg_mf);
			if (expr_eval == -1)
				return (FALSE);
			break;

		case ARG_T_ID:
			/* Ensure that arguments are present */
			if (*arg_mf.mf_next == '\0')
				goto error_reqarg;
			if (!cexp_ident_validate(&arg_mf, NULL,
			    mdptr->md_name))
				return (FALSE);
			break;

		case ARG_T_STR:
			/* Ensure that arguments are present */
			if (*arg_mf.mf_next == '\0')
				goto error_reqarg;
			/* Remove trailing whitespace */
			tail = arg_mf.mf_next + strlen(arg_mf.mf_next);
			while ((tail > arg_mf.mf_next) &&
			    isspace(*(tail -1)))
				tail--;
			*tail = '\0';
			break;
		}
	}

	/*
	 * Carry out the specified control directive:
	 */
	if (!STACK_IS_EMPTY(lms.lms_cdir_stack))
		level = &STACK_TOP(lms.lms_cdir_stack);

	switch (mdptr->md_op) {
	case CDIR_T_UNKNOWN:		/* Unrecognized control directive */
		if (!pass)
			break;
		mf_fatal0(&arg_mf, MSG_INTL(MSG_MAP_CDIR_BAD));
		return (FALSE);

	case CDIR_T_ADD:
		if (pass && !cexp_ident_add(&arg_mf, arg_mf.mf_next))
			return (FALSE);
		break;

	case CDIR_T_CLEAR:
		if (pass)
			cexp_ident_clear(&arg_mf, arg_mf.mf_next);
		break;

	case CDIR_T_ERROR:
		if (!pass)
			break;
		mf_fatal(&arg_mf, MSG_INTL(MSG_MAP_CDIR_ERROR),
		    arg_mf.mf_next);
		return (FALSE);

	case CDIR_T_VERSION:
		/*
		 * A $mapfile_version control directive can only appear
		 * as the first directive in a mapfile, and is used to
		 * determine the syntax for the rest of the file. It's
		 * too late to be using it here.
		 */
		if (!pass)
			break;
		mf_fatal0(&arg_mf, MSG_INTL(MSG_MAP_CDIR_REPVER));
		return (FALSE);

	case CDIR_T_IF:
		/* Push a new level on the conditional input stack */
		if (STACK_RESERVE(lms.lms_cdir_stack, CDIR_STACK_INIT) == 0)
			return (FALSE);
		level = &lms.lms_cdir_stack.stk_s[lms.lms_cdir_stack.stk_n++];
		level->cdl_if_lineno = arg_mf.mf_lineno;
		level->cdl_else_lineno = 0;

		/*
		 * If previous level is not passing, this level is disabled.
		 * Otherwise, the expression value determines what happens.
		 */
		if (pass) {
			level->cdl_done = level->cdl_pass = expr_eval;
		} else {
			level->cdl_done = 1;
			level->cdl_pass = 0;
		}
		break;

	case CDIR_T_ELIF:
		/* $elif requires an open $if construct */
		if (STACK_IS_EMPTY(lms.lms_cdir_stack)) {
			mf_fatal(&arg_mf, MSG_INTL(MSG_MAP_CDIR_NOIF),
			    MSG_ORIG(MSG_STR_CDIR_ELIF));
			return (FALSE);
		}

		/* $elif cannot follow $else */
		if (level->cdl_else_lineno > 0) {
			mf_fatal(&arg_mf, MSG_INTL(MSG_MAP_CDIR_ELSE),
			    MSG_ORIG(MSG_STR_CDIR_ELIF),
			    EC_LINENO(level->cdl_else_lineno));
			return (FALSE);
		}

		/*
		 * Accept text from $elif if the level isn't already
		 * done and the expression evaluates to true.
		 */
		level->cdl_pass = !level->cdl_done && expr_eval;
		if (level->cdl_pass)
			level->cdl_done = 1;
		break;

	case CDIR_T_ELSE:
		/* $else requires an open $if construct */
		if (STACK_IS_EMPTY(lms.lms_cdir_stack)) {
			mf_fatal(&arg_mf, MSG_INTL(MSG_MAP_CDIR_NOIF),
			    MSG_ORIG(MSG_STR_CDIR_ELSE));
			return (FALSE);
		}

		/* There can only be one $else in the chain */
		if (level->cdl_else_lineno > 0) {
			mf_fatal(&arg_mf, MSG_INTL(MSG_MAP_CDIR_ELSE),
			    MSG_ORIG(MSG_STR_CDIR_ELSE),
			    EC_LINENO(level->cdl_else_lineno));
			return (FALSE);
		}
		level->cdl_else_lineno = arg_mf.mf_lineno;

		/* Accept text from $else if the level isn't already done */
		level->cdl_pass = !level->cdl_done;
		level->cdl_done = 1;
		break;

	case CDIR_T_ENDIF:
		/* $endif requires an open $if construct */
		if (STACK_IS_EMPTY(lms.lms_cdir_stack)) {
			mf_fatal(&arg_mf, MSG_INTL(MSG_MAP_CDIR_NOIF),
			    MSG_ORIG(MSG_STR_CDIR_ENDIF));
			return (FALSE);
		}
		if (--lms.lms_cdir_stack.stk_n > 0)
			level = &STACK_TOP(lms.lms_cdir_stack);
		break;

	default:
		return (FALSE);
	}

	/* Evaluating the control directive above can change pass status */
	expr_eval = STACK_IS_EMPTY(lms.lms_cdir_stack) ||
	    STACK_TOP(lms.lms_cdir_stack).cdl_pass;
	if (expr_eval != pass) {
		pass = expr_eval;
		DBG_CALL(Dbg_map_pass(arg_mf.mf_ofl->ofl_lml, pass,
		    arg_mf.mf_name, arg_mf.mf_lineno, mdptr->md_name));
	}

	/*
	 * At this point, we have processed a control directive,
	 * updated our conditional state stack, and the input is
	 * positioned at the start of the line following the directive.
	 * If the current level is accepting input, then give control
	 * back to ld_map_gettoken() to resume its normal operation.
	 */
	if (pass)
		return (TRUE);

	/*
	 * The current level is not accepting input. Only another
	 * control directive can change this, so read and discard input
	 * until we encounter one of the following:
	 *
	 * EOF:			Return and let ld_map_gettoken() report it
	 * Control Directive:	Restart this function / evaluate new directive
	 */
	while (*mf->mf_next != '\0') {
		/* Skip leading whitespace */
		while (isspace_nonl(*mf->mf_next))
			mf->mf_next++;

		/*
		 * Control directives start with a '$'. If we hit
		 * one, restart the function at this point
		 */
		if (*mf->mf_next == '$')
			goto restart;

		/* Not a control directive, so advance input to next line */
		advance_to_eol(&mf->mf_next);
		if (*mf->mf_next == '\n') {
			mf->mf_lineno++;
			mf->mf_next++;
		}
	}

	assert(*mf->mf_next == '\0');
	return (TRUE);

	/*
	 * Control directives that require an argument that is not present
	 * jump here to report the error and exit.
	 */
error_reqarg:
	mf_fatal(&arg_mf, MSG_INTL(MSG_MAP_CDIR_REQARG), mdptr->md_name);
	return (FALSE);

}

#ifndef _ELF64
/*
 * Convert a string to lowercase.
 */
void
ld_map_lowercase(char *str)
{
	while (*str = tolower(*str))
		str++;
}
#endif

/*
 * Wrappper on strtoul()/strtoull(), adapted to return an Xword.
 *
 * entry:
 *	str - Pointer to string to be converted.
 *	endptr - As documented for strtoul(3C). Either NULL, or
 *		address of pointer to receive the address of the first
 *		unused character in str (called "final" in strtoul(3C)).
 *	ret_value - Address of Xword variable to receive result.
 *
 * exit:
 *	On success, *ret_value receives the result, *endptr is updated if
 *	endptr is non-NULL, and STRTOXWORD_OK is returned.
 *	On failure, STRTOXWORD_TOBIG is returned if an otherwise valid
 *	value was too large, and STRTOXWORD_BAD is returned if the string
 *	is malformed.
 */
ld_map_strtoxword_t
ld_map_strtoxword(const char *restrict str, char **restrict endptr,
    Xword *ret_value)
{
#if	defined(_ELF64)			/* _ELF64 */
#define	FUNC		strtoull	/* Function to use */
#define	FUNC_MAX	ULLONG_MAX	/* Largest value returned by FUNC */
#define	XWORD_MAX	ULLONG_MAX	/* Largest Xword value */
	uint64_t	value;		/* Variable of FUNC return type  */
#else					/* _ELF32 */
#define	FUNC		strtoul
#define	FUNC_MAX	ULONG_MAX
#define	XWORD_MAX	UINT_MAX
	ulong_t		value;
#endif

	char	*endptr_local;		/* Used if endptr is NULL */

	if (endptr == NULL)
		endptr = &endptr_local;

	errno = 0;
	value = FUNC(str, endptr, 0);
	if ((errno != 0) || (str == *endptr)) {
		if (value  == FUNC_MAX)
			return (STRTOXWORD_TOOBIG);
		else
			return (STRTOXWORD_BAD);
	}

	/*
	 * If this is a 64-bit linker building an ELFCLASS32 object,
	 * the FUNC return type is a 64-bit value, while an Xword is
	 * 32-bit. It is possible for FUNC to be able to convert a value
	 * too large for our return type.
	 */
#if FUNC_MAX != XWORD_MAX
	if (value > XWORD_MAX)
		return (STRTOXWORD_TOOBIG);
#endif

	*ret_value = value;
	return (STRTOXWORD_OK);

#undef FUNC
#undef FUNC_MAX
#undef XWORD_MAC
}

/*
 * Convert the unsigned integer value at the current mapfile input
 * into binary form. All numeric values in mapfiles are treated as
 * unsigned integers of the appropriate width for an address on the
 * given target. Values can be decimal, hex, or octal.
 *
 * entry:
 *	str - String to process.
 *	value - Address of variable to receive resulting value.
 *	notail - If TRUE, an error is issued if non-whitespace
 *		characters other than '#' (comment) are found following
 *		the numeric value before the end of line.
 *
 * exit:
 *	On success:
 *		- *str is advanced to the next character following the value
 *		- *value receives the value
 *		- Returns TRUE (1).
 *	On failure, returns FALSE (0).
 */
static Boolean
ld_map_getint(Mapfile *mf, ld_map_tkval_t *value, Boolean notail)
{
	ld_map_strtoxword_t	s2xw_ret;
	ld_map_npatch_t	np;
	char		*endptr;
	char		*errstr = mf->mf_next;

	value->tkv_int.tkvi_str = mf->mf_next;
	s2xw_ret = ld_map_strtoxword(mf->mf_next, &endptr,
	    &value->tkv_int.tkvi_value);
	if (s2xw_ret != STRTOXWORD_OK) {
		null_patch_eol(mf->mf_next, &np);
		if (s2xw_ret == STRTOXWORD_TOOBIG)
			mf_fatal(mf, MSG_INTL(MSG_MAP_VALUELIMIT), errstr);
		else
			mf_fatal(mf, MSG_INTL(MSG_MAP_MALVALUE), errstr);
		null_patch_undo(&np);
		return (FALSE);
	}

	/* Advance position to item following value, skipping whitespace */
	value->tkv_int.tkvi_cnt = endptr - mf->mf_next;
	mf->mf_next = endptr;
	while (isspace_nonl(*mf->mf_next))
		mf->mf_next++;

	/* If requested, ensure there's nothing left */
	if (notail && (*mf->mf_next != '\n') && (*mf->mf_next != '#') &&
	    (*mf->mf_next != '\0')) {
		null_patch_eol(mf->mf_next, &np);
		mf_fatal(mf, MSG_INTL(MSG_MAP_BADVALUETAIL), errstr);
		null_patch_undo(&np);
		return (FALSE);
	}

	return (TRUE);
}

/*
 * Convert a an unquoted identifier into a TK_STRING token, using the
 * rules for syntax version in use. Used exclusively by ld_map_gettoken().
 *
 * entry:
 *	mf - Mapfile descriptor, positioned to the first character of
 *		the string.
 *	flags - Bitmask of options to control ld_map_gettoken()s behavior
 *	tkv- Address of pointer to variable to receive token value.
 *
 * exit:
 *	On success, mf is advanced past the token, tkv is updated with
 *	the string, and TK_STRING is returned. On error, TK_ERROR is returned.
 */
inline static Token
gettoken_ident(Mapfile *mf, int flags, ld_map_tkval_t *tkv)
{
	char	*end;
	Token	tok;
	ld_map_npatch_t	np;

	tkv->tkv_str = mf->mf_next;
	if ((end = ident_delimit(mf)) == NULL)
		return (TK_ERROR);
	mf->mf_next = end;

	/*
	 * One advantage of reading the entire mapfile into memory is that
	 * we can access the strings within it without having to allocate
	 * more memory or make copies. In order to do that, we need to NULL
	 * terminate this identifier. That is going to overwrite the
	 * following character. The problem this presents is that the next
	 * character may well be the first character of a subsequent token.
	 * The solution to this is:
	 *
	 * 1)	Disallow the case where the next character is able to
	 *	start a string. This is not legal mapfile syntax anyway,
	 *	so catching it here simplifies matters.
	 * 2)	Copy the character into the special mf->mf_next_ch
	 * 3)	The next call to ld_map_gettoken() checks mf->mf_next_ch,
	 *	and if it is non-0, uses it instead of dereferencing the
	 *	mf_next pointer.
	 */
	tok = (*mf->mf_next & 0x80) ?
	    TK_OP_ILLCHR : mf->mf_tokdisp[*mf->mf_next];
	switch (tok) {
	case TK_OP_BADCHR:
		null_patch_eol(mf->mf_next, &np);
		mf_fatal(mf, MSG_INTL(MSG_MAP_BADCHAR), mf->mf_next);
		null_patch_undo(&np);
		return (TK_ERROR);

	case TK_OP_SIMQUOTE:
	case TK_OP_CQUOTE:
	case TK_OP_CDIR:
	case TK_OP_NUM:
	case TK_OP_ID:
		null_patch_eol(mf->mf_next, &np);
		mf_fatal(mf, MSG_INTL(MSG_MAP_WSNEEDED), mf->mf_next);
		null_patch_undo(&np);
		return (TK_ERROR);
	}

	/* Null terminate, saving the replaced character */
	mf->mf_next_ch = *mf->mf_next;
	*mf->mf_next = '\0';

	if (flags & TK_F_STRLC)
		ld_map_lowercase(tkv->tkv_str);
	return (TK_STRING);
}

/*
 * Convert a quoted string into a TK_STRING token, using simple
 * quoting rules:
 *	- Start and end quotes must be present and match
 *	- There are no special characters or escape sequences.
 * This function is used exclusively by ld_map_gettoken().
 *
 * entry:
 *	mf - Mapfile descriptor, positioned to the opening quote character.
 *	flags - Bitmask of options to control ld_map_gettoken()s behavior
 *	tkv- Address of pointer to variable to receive token value.
 *
 * exit:
 *	On success, mf is advanced past the token, tkv is updated with
 *	the string, and TK_STRING is returned. On error, TK_ERROR is returned.
 */
inline static Token
gettoken_simquote_str(Mapfile *mf, int flags, ld_map_tkval_t *tkv)
{
	char	*str, *end;
	char	quote;

	str = mf->mf_next++;
	quote = *str;
	end = mf->mf_next;
	while ((*end != '\0') && (*end != '\n') && (*end != quote))
		end++;
	if (*end != quote) {
		ld_map_npatch_t	np;

		null_patch_eol(end, &np);
		mf_fatal(mf, MSG_INTL(MSG_MAP_NOTERM), str);
		null_patch_undo(&np);
		return (TK_ERROR);
	}

	/*
	 * end is pointing at the closing quote. We can turn that into NULL
	 * termination for the string without needing to restore it later.
	 */
	*end = '\0';
	mf->mf_next = end + 1;
	tkv->tkv_str = str + 1;		/* Skip opening quote */
	if (flags & TK_F_STRLC)
		ld_map_lowercase(tkv->tkv_str);
	return (TK_STRING);
}

/*
 * Convert a quoted string into a TK_STRING token, using C string literal
 * quoting rules:
 *	- Start and end quotes must be present and match
 *	- Backslash is an escape, used to introduce  special characters
 * This function is used exclusively by ld_map_gettoken().
 *
 * entry:
 *	mf - Mapfile descriptor, positioned to the opening quote character.
 *	flags - Bitmask of options to control ld_map_gettoken()s behavior
 *	tkv- Address of pointer to variable to receive token value.
 *
 * exit:
 *	On success, mf is advanced past the token, tkv is updated with
 *	the string, and TK_STRING is returned. On error, TK_ERROR is returned.
 */
inline static Token
gettoken_cquote_str(Mapfile *mf, int flags, ld_map_tkval_t *tkv)
{
	char	*str, *cur, *end;
	char	quote;
	int	c;

	/*
	 * This function goes through the quoted string and copies
	 * it on top of itself, replacing escape sequences with the
	 * characters they denote. There is always enough room for this,
	 * because escapes are multi-character sequences that are converted
	 * to single character results.
	 */
	str = mf->mf_next++;
	quote = *str;
	cur = end = mf->mf_next;
	for (c = *end++; (c != '\0') && (c != '\n') && (c != quote);
	    c = *end++) {
		if (c == '\\') {
			c = conv_translate_c_esc(&end);
			if (c == -1) {
				mf_fatal(mf, MSG_INTL(MSG_MAP_BADCESC), *end);
				return (TK_ERROR);
			}
		}
		*cur++ = c;
	}
	*cur = '\0';		/* terminate the result */
	if (c != quote) {
		ld_map_npatch_t	np;

		null_patch_eol(end, &np);
		mf_fatal(mf, MSG_INTL(MSG_MAP_NOTERM), str);
		null_patch_undo(&np);
		return (TK_ERROR);
	}

	/* end is pointing one character past the closing quote */
	mf->mf_next = end;
	tkv->tkv_str = str + 1;		/* Skip opening quote */
	if (flags & TK_F_STRLC)
		ld_map_lowercase(tkv->tkv_str);
	return (TK_STRING);
}

/*
 * Get a token from the mapfile.
 *
 * entry:
 *	mf - Mapfile descriptor
 *	flags - Bitmask of options to control ld_map_gettoken()s behavior
 *	tkv- Address of pointer to variable to receive token value.
 *
 * exit:
 *	Returns one of the TK_* values, to report the result. If the resulting
 *	token has a value (TK_STRING / TK_INT), and tkv is non-NULL, tkv
 *	is filled in with the resulting value.
 */
Token
ld_map_gettoken(Mapfile *mf, int flags, ld_map_tkval_t *tkv)
{
	int		cdir_allow, ch;
	Token		tok;
	ld_map_npatch_t	np;

	/*
	 * Mapfile control directives all start with a '$' character. However,
	 * they are only valid when they are the first thing on a line. That
	 * happens on the first call to ld_map_gettoken() for a new a new
	 * mapfile, as tracked with lms.lms_cdir_valid, and immediately
	 * following each newline seen in the file.
	 */
	cdir_allow = lms.lms_cdir_valid;
	lms.lms_cdir_valid = 0;

	/* Cycle through the characters looking for tokens. */
	for (;;) {
		/*
		 * Process the next character. This is normally *mf->mf_next,
		 * but if mf->mf_next_ch is non-0, then it contains the
		 * character, and *mf->mf_next contains a NULL termination
		 * from the TK_STRING token returned on the previous call.
		 *
		 * gettoken_ident() ensures that this is never done to
		 * a character that starts a string.
		 */
		if (mf->mf_next_ch == 0) {
			ch = *mf->mf_next;
		} else {
			ch = mf->mf_next_ch;
			mf->mf_next_ch = 0;	/* Reset */
		}

		/* Map the character to a dispatch action */
		tok = (ch & 0x80) ? TK_OP_ILLCHR : mf->mf_tokdisp[ch];

		/*
		 * Items that require processing are identified as OP tokens.
		 * We process them, and return a result non-OP token.
		 *
		 * Non-OP tokens are single character tokens, and we return
		 * them immediately.
		 */
		switch (tok) {
		case TK_OP_EOF:
			/* If EOFOK is set, quietly report it as TK_EOF */
			if ((flags & TK_F_EOFOK) != 0)
				return (TK_EOF);

			/* Treat it as a standard error */
			mf_fatal0(mf, MSG_INTL(MSG_MAP_PREMEOF));
			return (TK_ERROR);

		case TK_OP_ILLCHR:
			mf_fatal(mf, MSG_INTL(MSG_MAP_ILLCHAR), ch);
			mf->mf_next++;
			return (TK_ERROR);

		case TK_OP_BADCHR:
			tk_op_badchr:
			null_patch_eol(mf->mf_next, &np);
			mf_fatal(mf, MSG_INTL(MSG_MAP_BADCHAR), mf->mf_next);
			null_patch_undo(&np);
			mf->mf_next++;
			return (TK_ERROR);

		case TK_OP_WS:	/* White space */
			mf->mf_next++;
			break;

		case TK_OP_NL:	/* White space too, but bump line number. */
			mf->mf_next++;
			mf->mf_lineno++;
			cdir_allow = 1;
			break;

		case TK_OP_SIMQUOTE:
			if (flags & TK_F_KEYWORD)
				goto tk_op_badkwquote;
			return (gettoken_simquote_str(mf, flags, tkv));

		case TK_OP_CQUOTE:
			if (flags & TK_F_KEYWORD) {
			tk_op_badkwquote:
				null_patch_eol(mf->mf_next, &np);
				mf_fatal(mf, MSG_INTL(MSG_MAP_BADKWQUOTE),
				    mf->mf_next);
				null_patch_undo(&np);
				mf->mf_next++;
				return (TK_ERROR);
			}
			return (gettoken_cquote_str(mf, flags, tkv));

		case TK_OP_CMT:
			advance_to_eol(&mf->mf_next);
			break;

		case TK_OP_CDIR:
			/*
			 * Control directives are only valid at the start
			 * of a line.
			 */
			if (!cdir_allow) {
				null_patch_eol(mf->mf_next, &np);
				mf_fatal(mf, MSG_INTL(MSG_MAP_CDIR_NOTBOL),
				    mf->mf_next);
				null_patch_undo(&np);
				mf->mf_next++;
				return (TK_ERROR);
			}
			if (!cdir_process(mf))
				return (TK_ERROR);
			break;

		case TK_OP_NUM:	/* Decimal, hex(0x...), or octal (0...) value */
			if (!ld_map_getint(mf, tkv, FALSE))
				return (TK_ERROR);
			return (TK_INT);

		case TK_OP_ID:		/* Unquoted identifier */
			return (gettoken_ident(mf, flags, tkv));

		case TK_OP_CEQUAL:	/* += or -= */
			if (*(mf->mf_next + 1) != '=')
				goto tk_op_badchr;
			tok = (ch == '+') ? TK_PLUSEQ : TK_MINUSEQ;
			mf->mf_next += 2;
			return (tok);

		default:	/* Non-OP token */
			mf->mf_next++;
			return (tok);
		}
	}

	/*NOTREACHED*/
	assert(0);
	return (TK_ERROR);
}

/*
 * Given a token and value returned by ld_map_gettoken(), return a string
 * representation of it suitable for use in an error message.
 *
 * entry:
 *	tok - Token code. Must not be an OP-token
 *	tkv - Token value
 */
const char *
ld_map_tokenstr(Token tok, ld_map_tkval_t *tkv, Conv_inv_buf_t *inv_buf)
{
	size_t	cnt;

	switch (tok) {
	case TK_ERROR:
		return (MSG_ORIG(MSG_STR_ERROR));
	case TK_EOF:
		return (MSG_ORIG(MSG_STR_EOF));
	case TK_STRING:
		return (tkv->tkv_str);
	case TK_COLON:
		return (MSG_ORIG(MSG_QSTR_COLON));
	case TK_SEMICOLON:
		return (MSG_ORIG(MSG_QSTR_SEMICOLON));
	case TK_EQUAL:
		return (MSG_ORIG(MSG_QSTR_EQUAL));
	case TK_PLUSEQ:
		return (MSG_ORIG(MSG_QSTR_PLUSEQ));
	case TK_MINUSEQ:
		return (MSG_ORIG(MSG_QSTR_MINUSEQ));
	case TK_ATSIGN:
		return (MSG_ORIG(MSG_QSTR_ATSIGN));
	case TK_DASH:
		return (MSG_ORIG(MSG_QSTR_DASH));
	case TK_LEFTBKT:
		return (MSG_ORIG(MSG_QSTR_LEFTBKT));
	case TK_RIGHTBKT:
		return (MSG_ORIG(MSG_QSTR_RIGHTBKT));
	case TK_PIPE:
		return (MSG_ORIG(MSG_QSTR_PIPE));
	case TK_INT:
		cnt = tkv->tkv_int.tkvi_cnt;
		if (cnt >= sizeof (inv_buf->buf))
			cnt = sizeof (inv_buf->buf) - 1;
		(void) memcpy(inv_buf->buf, tkv->tkv_int.tkvi_str, cnt);
		inv_buf->buf[cnt] = '\0';
		return (inv_buf->buf);
	case TK_STAR:
		return (MSG_ORIG(MSG_QSTR_STAR));
	case TK_BANG:
		return (MSG_ORIG(MSG_QSTR_BANG));
	default:
		assert(0);
		break;
	}

	/*NOTREACHED*/
	return (MSG_INTL(MSG_MAP_INTERR));
}

/*
 * Advance the input to the first non-empty line, and determine
 * the mapfile version. The version is specified by the mapfile
 * using a $mapfile_version directive. The original System V
 * syntax lacks this directive, and we use that fact to identify
 * such files. SysV mapfile are implicitly defined to have version 1.
 *
 * entry:
 *	ofl - Output file descriptor
 *	mf - Mapfile block
 *
 * exit:
 *	On success, updates mf->mf_version, and returns TRUE (1).
 *	On failure, returns FALSE (0).
 */
static Boolean
mapfile_version(Mapfile *mf)
{
	char	*line_start = mf->mf_next;
	Boolean	cont = TRUE;
	Boolean	status = TRUE;	/* Assume success */
	Token	tok;

	mf->mf_version = MFV_SYSV;

	/*
	 * Cycle through the characters looking for tokens. Although the
	 * true version is not known yet, we use the v2 dispatch table.
	 * It contains control directives, which we need for this search,
	 * and the other TK_OP_ tokens we will recognize and act on are the
	 * same for both tables.
	 *
	 * It is important not to process any tokens that would lead to
	 * a non-OP token:
	 *
	 * -	The version is required to interpret them
	 * -	Our mapfile descriptor is not fully initialized,
	 *	attempts to run that code will crash the program.
	 */
	while (cont) {
		/* Map the character to a dispatch action */
		tok = (*mf->mf_next & 0x80) ?
		    TK_OP_ILLCHR : gettok_dispatch_v2[*mf->mf_next];

		switch (tok) {
		case TK_OP_WS:	/* White space */
			mf->mf_next++;
			break;

		case TK_OP_NL:	/* White space too, but bump line number. */
			mf->mf_next++;
			mf->mf_lineno++;
			break;

		case TK_OP_CMT:
			advance_to_eol(&mf->mf_next);
			break;

		case TK_OP_CDIR:
			/*
			 * Control directives are only valid at the start
			 * of a line. However, as we have not yet seen
			 * a token, we do not need to test for this, and
			 * can safely assume that we are at the start.
			 */
			if (!strncasecmp(mf->mf_next,
			    MSG_ORIG(MSG_STR_CDIR_MFVER),
			    MSG_STR_CDIR_MFVER_SIZE) &&
			    isspace_nonl(*(mf->mf_next +
			    MSG_STR_CDIR_MFVER_SIZE))) {
				ld_map_tkval_t	ver;

				mf->mf_next += MSG_STR_CDIR_MFVER_SIZE + 1;
				if (!ld_map_getint(mf, &ver, TRUE)) {
					status = cont = FALSE;
					break;
				}
				/*
				 * Is it a valid version? Note that we
				 * intentionally do not allow you to
				 * specify version 1 using the $mapfile_version
				 * syntax, because that's reserved to version
				 * 2 and up.
				 */
				if ((ver.tkv_int.tkvi_value < 2) ||
				    (ver.tkv_int.tkvi_value >= MFV_NUM)) {
					const char *fmt;

					fmt = (ver.tkv_int.tkvi_value < 2) ?
					    MSG_INTL(MSG_MAP_CDIR_BADVDIR) :
					    MSG_INTL(MSG_MAP_CDIR_BADVER);
					mf_fatal(mf, fmt,
					    EC_WORD(ver.tkv_int.tkvi_value));
					status = cont = FALSE;
					break;
				}
				mf->mf_version = ver.tkv_int.tkvi_value;
				cont = FALSE; /* Version recovered. All done */
				break;
			}
			/*
			 * Not a version directive. Reset the current position
			 * to the start of the current line and stop here.
			 * SysV syntax applies.
			 */
			mf->mf_next = line_start;
			cont = FALSE;
			break;

		default:
			/*
			 * If we see anything else, then stop at this point.
			 * The file has System V syntax (version 1), and the
			 * next token should be interpreted as such.
			 */
			cont = FALSE;
			break;
		}
	}

	return (status);
}

/*
 * Parse the mapfile.
 */
Boolean
ld_map_parse(const char *mapfile, Ofl_desc *ofl)
{
	struct stat	stat_buf;	/* stat of mapfile */
	int		mapfile_fd;	/* descriptor for mapfile */
	int		err;
	Mapfile		*mf;		/* Mapfile descriptor */
	size_t		name_len;	/* strlen(mapfile) */

	/*
	 * Determine if we're dealing with a file or a directory.
	 */
	if (stat(mapfile, &stat_buf) == -1) {
		err = errno;
		ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_SYS_STAT), mapfile,
		    strerror(err));
		return (FALSE);
	}
	if (S_ISDIR(stat_buf.st_mode)) {
		DIR		*dirp;
		struct dirent	*denp;

		/*
		 * Open the directory and interpret each visible file as a
		 * mapfile.
		 */
		if ((dirp = opendir(mapfile)) == NULL)
			return (TRUE);

		while ((denp = readdir(dirp)) != NULL) {
			char	path[PATH_MAX];

			/*
			 * Ignore any hidden filenames.  Construct the full
			 * pathname to the new mapfile.
			 */
			if (*denp->d_name == '.')
				continue;
			(void) snprintf(path, PATH_MAX, MSG_ORIG(MSG_STR_PATH),
			    mapfile, denp->d_name);
			if (!ld_map_parse(path, ofl))
				return (FALSE);
		}
		(void) closedir(dirp);
		return (TRUE);
	} else if (!S_ISREG(stat_buf.st_mode)) {
		ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_SYS_NOTREG), mapfile);
		return (FALSE);
	}

	/* Open file */
	if ((mapfile_fd = open(mapfile, O_RDONLY)) == -1) {
		err = errno;
		ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_SYS_OPEN), mapfile,
		    strerror(err));
		return (FALSE);
	}

	/*
	 * Allocate enough memory to hold the state block, mapfile name,
	 * and mapfile text. Text has alignment 1, so it can follow the
	 * state block without padding.
	 */
	name_len = strlen(mapfile) + 1;
	mf = libld_malloc(sizeof (*mf) + name_len + stat_buf.st_size + 1);
	if (mf == NULL)
		return (FALSE);
	mf->mf_ofl = ofl;
	mf->mf_name = (char *)(mf + 1);
	(void) strcpy(mf->mf_name, mapfile);
	mf->mf_text = mf->mf_name + name_len;
	if (read(mapfile_fd, mf->mf_text, stat_buf.st_size) !=
	    stat_buf.st_size) {
		err = errno;
		ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_SYS_READ), mapfile,
		    strerror(err));
		(void) close(mapfile_fd);
		return (FALSE);
	}
	(void) close(mapfile_fd);
	mf->mf_text[stat_buf.st_size] = '\0';
	mf->mf_next = mf->mf_text;
	mf->mf_lineno = 1;
	mf->mf_next_ch = 0;		/* No "lookahead" character yet */
	mf->mf_ec_insndx = 0;		/* Insert entrace criteria at top */

	/*
	 * Read just enough from the mapfile to determine the version,
	 * and then dispatch to the appropriate code for further processing
	 */
	if (!mapfile_version(mf))
		return (FALSE);

	/*
	 * Start and continuation masks for unquoted identifier at this
	 * mapfile version level.
	 */
	mf->mf_tkid_start = TKID_ATTR_START(mf->mf_version);
	mf->mf_tkid_cont = TKID_ATTR_CONT(mf->mf_version);

	DBG_CALL(Dbg_map_parse(ofl->ofl_lml, mapfile, mf->mf_version));

	switch (mf->mf_version) {
	case MFV_SYSV:
		/* Guidance: Use newer mapfile syntax */
		if (OFL_GUIDANCE(ofl, FLG_OFG_NO_MF))
			ld_eprintf(ofl, ERR_GUIDANCE,
			    MSG_INTL(MSG_GUIDE_MAPFILE), mapfile);

		mf->mf_tokdisp = gettok_dispatch_v1;
		if (!ld_map_parse_v1(mf))
			return (FALSE);
		break;

	case MFV_SOLARIS:
		mf->mf_tokdisp = gettok_dispatch_v2;
		STACK_RESET(lms.lms_cdir_stack);

		/*
		 * If the conditional expression identifier tree has not been
		 * initialized, set it up. This is only done on the first
		 * mapfile, because the identifier control directives accumulate
		 * across all the mapfiles.
		 */
		if ((lms.lms_cexp_id == NULL) && !cexp_ident_init())
			return (FALSE);

		/*
		 * Tell ld_map_gettoken() we will accept a '$' as starting a
		 * control directive on the first call. Normally, they are
		 * only allowed after a newline.
		 */
		lms.lms_cdir_valid = 1;

		if (!ld_map_parse_v2(mf))
			return (FALSE);

		/* Did we leave any open $if control directives? */
		if (!STACK_IS_EMPTY(lms.lms_cdir_stack)) {
			while (!STACK_IS_EMPTY(lms.lms_cdir_stack)) {
				cdir_level_t *level =
				    &STACK_POP(lms.lms_cdir_stack);

				mf_fatal(mf, MSG_INTL(MSG_MAP_CDIR_NOEND),
				    EC_LINENO(level->cdl_if_lineno));
			}
			return (FALSE);
		}
		break;
	}

	return (TRUE);
}

/*
 * Sort the segment list. This is necessary if a mapfile has set explicit
 * virtual addresses for segments, or defined a SEGMENT_ORDER directive.
 *
 * Only PT_LOAD segments can be assigned a virtual address.  These segments can
 * be one of two types:
 *
 *  -	Standard segments for text, data or bss.  These segments will have been
 *	inserted before the default text (first PT_LOAD) segment.
 *
 *  -	Empty (reservation) segments.  These segment will have been inserted at
 *	the end of any default PT_LOAD segments.
 *
 * Any standard segments that are assigned a virtual address will be sorted,
 * and as their definitions precede any default PT_LOAD segments, these segments
 * will be assigned sections before any defaults.
 *
 * Any reservation segments are also sorted amoung themselves, as these segments
 * must still follow the standard default segments.
 */
static Boolean
sort_seg_list(Ofl_desc *ofl)
{
	APlist	*sort_segs = NULL, *load_segs = NULL;
	Sg_desc	*sgp1;
	Aliste	idx1;
	Aliste	nsegs;


	/*
	 * We know the number of elements in the sorted list will be
	 * the same as the original, so use this as the initial allocation
	 * size for the replacement aplist.
	 */
	nsegs = aplist_nitems(ofl->ofl_segs);


	/* Add the items below SGID_TEXT to the list */
	for (APLIST_TRAVERSE(ofl->ofl_segs, idx1, sgp1)) {
		if (sgp1->sg_id >= SGID_TEXT)
			break;

		if (aplist_append(&sort_segs, sgp1, nsegs) == NULL)
				return (FALSE);
	}

	/*
	 * If there are any SEGMENT_ORDER items, add them, and set their
	 * FLG_SG_ORDERED flag to identify them in debug output, and to
	 * prevent them from being added again below.
	 */
	for (APLIST_TRAVERSE(ofl->ofl_segs_order, idx1, sgp1)) {
		if (aplist_append(&sort_segs, sgp1, nsegs) == NULL)
			return (FALSE);
		sgp1->sg_flags |= FLG_SG_ORDERED;
	}

	/*
	 * Add the loadable segments to another list in sorted order.
	 */
	DBG_CALL(Dbg_map_sort_title(ofl->ofl_lml, TRUE));
	for (APLIST_TRAVERSE(ofl->ofl_segs, idx1, sgp1)) {
		DBG_CALL(Dbg_map_sort_seg(ofl->ofl_lml, ELFOSABI_SOLARIS,
		    ld_targ.t_m.m_mach, sgp1));

		/* Only interested in PT_LOAD items not in SEGMENT_ORDER list */
		if ((sgp1->sg_phdr.p_type != PT_LOAD) ||
		    (sgp1->sg_flags & FLG_SG_ORDERED))
			continue;

		/*
		 * If the loadable segment does not contain a vaddr, simply
		 * append it to the new list.
		 */
		if ((sgp1->sg_flags & FLG_SG_P_VADDR) == 0) {
			if (aplist_append(&load_segs, sgp1, AL_CNT_SEGMENTS) ==
			    NULL)
				return (FALSE);

		} else {
			Aliste		idx2;
			Sg_desc		*sgp2;
			int		inserted = 0;

			/*
			 * Traverse the segment list we are creating, looking
			 * for a segment that defines a vaddr.
			 */
			for (APLIST_TRAVERSE(load_segs, idx2, sgp2)) {
				/*
				 * Any real segments that contain vaddr's need
				 * to be sorted.  Any reservation segments also
				 * need to be sorted.  However, any reservation
				 * segments should be placed after any real
				 * segments.
				 */
				if (((sgp2->sg_flags &
				    (FLG_SG_P_VADDR | FLG_SG_EMPTY)) == 0) &&
				    (sgp1->sg_flags & FLG_SG_EMPTY))
					continue;

				if ((sgp2->sg_flags & FLG_SG_P_VADDR) &&
				    ((sgp2->sg_flags & FLG_SG_EMPTY) ==
				    (sgp1->sg_flags & FLG_SG_EMPTY))) {
					if (sgp1->sg_phdr.p_vaddr ==
					    sgp2->sg_phdr.p_vaddr) {
						ld_eprintf(ofl, ERR_FATAL,
						    MSG_INTL(MSG_MAP_SEGSAME),
						    sgp1->sg_name,
						    sgp2->sg_name);
						return (FALSE);
					}

					if (sgp1->sg_phdr.p_vaddr >
					    sgp2->sg_phdr.p_vaddr)
						continue;
				}

				/*
				 * Insert this segment before the segment on
				 * the load_segs list.
				 */
				if (aplist_insert(&load_segs, sgp1,
				    AL_CNT_SEGMENTS, idx2) == NULL)
					return (FALSE);
				inserted = 1;
				break;
			}

			/*
			 * If the segment being inspected has not been inserted
			 * in the segment list, simply append it to the list.
			 */
			if ((inserted == 0) && (aplist_append(&load_segs,
			    sgp1, AL_CNT_SEGMENTS) == NULL))
				return (FALSE);
		}
	}

	/*
	 * Add the sorted loadable segments to our initial segment list.
	 */
	for (APLIST_TRAVERSE(load_segs, idx1, sgp1)) {
		if (aplist_append(&sort_segs, sgp1, AL_CNT_SEGMENTS) == NULL)
			return (FALSE);
	}

	/*
	 * Add all other segments to our list.
	 */
	for (APLIST_TRAVERSE(ofl->ofl_segs, idx1, sgp1)) {
		if ((sgp1->sg_id < SGID_TEXT) ||
		    (sgp1->sg_phdr.p_type == PT_LOAD) ||
		    (sgp1->sg_flags & FLG_SG_ORDERED))
			continue;

		if (aplist_append(&sort_segs, sgp1, AL_CNT_SEGMENTS) == NULL)
			return (FALSE);
	}

	/*
	 * Free the original list, and the pt_load list, and use
	 * the new list as the segment list.
	 */
	free(ofl->ofl_segs);
	if (load_segs) free(load_segs);
	ofl->ofl_segs = sort_segs;

	if (DBG_ENABLED) {
		Dbg_map_sort_title(ofl->ofl_lml, FALSE);
		for (APLIST_TRAVERSE(ofl->ofl_segs, idx1, sgp1)) {
			Dbg_map_sort_seg(ofl->ofl_lml, ELFOSABI_SOLARIS,
			    ld_targ.t_m.m_mach, sgp1);
			}
		}

	return (TRUE);
}

/*
 * After all mapfiles have been processed, this routine is used to
 * finish any remaining mapfile related work.
 *
 * exit:
 *	Returns TRUE on success, and FALSE on failure.
 */
Boolean
ld_map_post_process(Ofl_desc *ofl)
{
	Aliste		idx, idx2;
	Is_desc		*isp;
	Sg_desc		*sgp;
	Ent_desc	*enp;
	Sg_desc		*first_seg = NULL;


	DBG_CALL(Dbg_map_post_title(ofl->ofl_lml));

	/*
	 * Per-segment processing:
	 * -	Identify segments with explicit virtual address
	 * -	Details of input and output section order
	 */
	for (APLIST_TRAVERSE(ofl->ofl_segs, idx, sgp)) {
		/*
		 * We are looking for segments. Program headers that represent
		 * segments are required to have a non-NULL name pointer,
		 * while that those that do not are required to have a
		 * NULL name pointer.
		 */
		if (sgp->sg_name == NULL)
			continue;

		/* Remember the first non-disabled segment */
		if ((first_seg == NULL) && !(sgp->sg_flags & FLG_SG_DISABLED))
			first_seg = sgp;

		/*
		 * If a segment has an explicit virtual address, we will
		 * need to sort the segments.
		 */
		if (sgp->sg_flags & FLG_SG_P_VADDR)
			ofl->ofl_flags1 |= FLG_OF1_VADDR;

		/*
		 * The FLG_OF_OS_ORDER flag enables the code that does
		 * output section ordering. Set if the segment has
		 * a non-empty output section order list.
		 */
		if (alist_nitems(sgp->sg_os_order) > 0)
			ofl->ofl_flags |= FLG_OF_OS_ORDER;

		/*
		 * The version 1 and version 2 syntaxes for input section
		 * ordering are different and incompatible enough that we
		 * only allow the use of one or the other for a given segment:
		 *
		 * v1)	The version 1 syntax has the user set the ?O flag on
		 *	the segment. If this is done, all input sections placed
		 *	via an entrance criteria that has a section name are to
		 *	be sorted, using the order of the entrance criteria
		 *	as the sort key.
		 *
		 * v2)	The version 2 syntax has the user specify a name for
		 * 	the entry criteria, and then provide a list of entry
		 * 	criteria names via the IS_ORDER segment attribute.
		 * 	Sections placed via the criteria listed in IS_ORDER
		 * 	are sorted, and the others are not.
		 *
		 * Regardless of the syntax version used, the section sorting
		 * code expects the following:
		 *
		 * -	Segments requiring input section sorting have the
		 *	FLG_SG_IS_ORDER flag set
		 *
		 * -	Entrance criteria referencing the segment that
		 *	participate in input section sorting have a non-zero
		 *	sort key in their ec_ordndx field.
		 *
		 * At this point, the following are true:
		 *
		 * -	All entrance criteria have ec_ordndx set to 0.
		 * -	Segments that require the version 1 behavior have
		 *	the FLG_SG_IS_ORDER flag set, and the segments
		 *	sg_is_order list is empty.
		 * -	Segments that require the version 2 behavior do not
		 *	have FLG_SG_IS_ORDER set, and the sg_is_order list is
		 *	non-empty. This list contains the names of the entrance
		 *	criteria that will participate in input section sorting,
		 *	and their relative order in the list provides the
		 *	sort key to use.
		 *
		 * We must detect these two cases, set the FLG_SG_IS_ORDER
		 * flag as necessary, and fill in all entrance criteria
		 * sort keys. If any input section sorting is to be done,
		 * we also set the FLG_OF_IS_ORDER flag on the output descriptor
		 * to enable the code that does that work.
		 */

		/* Version 1: ?O flag? */
		if (sgp->sg_flags & FLG_SG_IS_ORDER) {
			Word	index = 0;

			ofl->ofl_flags |= FLG_OF_IS_ORDER;
			DBG_CALL(Dbg_map_ent_ord_title(ofl->ofl_lml,
			    sgp->sg_name));

			/*
			 * Give each user defined entrance criteria for this
			 * segment that specifies a section name a
			 * monotonically increasing sort key.
			 */
			for (APLIST_TRAVERSE(ofl->ofl_ents, idx2, enp))
				if ((enp->ec_segment == sgp) &&
				    (enp->ec_is_name != NULL) &&
				    ((enp->ec_flags & FLG_EC_BUILTIN) == 0))
					enp->ec_ordndx = ++index;
			continue;
		}

		/* Version 2: SEGMENT IS_ORDER list? */
		if (aplist_nitems(sgp->sg_is_order) > 0) {
			Word	index = 0;

			ofl->ofl_flags |= FLG_OF_IS_ORDER;
			DBG_CALL(Dbg_map_ent_ord_title(ofl->ofl_lml,
			    sgp->sg_name));

			/*
			 * Give each entrance criteria in the sg_is_order
			 * list a monotonically increasing sort key.
			 */
			for (APLIST_TRAVERSE(sgp->sg_is_order, idx2, enp)) {
				enp->ec_ordndx = ++index;
				enp->ec_segment->sg_flags |= FLG_SG_IS_ORDER;
			}
		}
	}

	/* Sort the segment descriptors if necessary */
	if (((ofl->ofl_flags1 & FLG_OF1_VADDR) ||
	    (aplist_nitems(ofl->ofl_segs_order) > 0)) &&
	    !sort_seg_list(ofl))
		return (FALSE);

	/*
	 * If the output file is a static file without an interpreter, and
	 * if any virtual address is specified, then set the NOHDR flag for
	 * backward compatibility.
	 */
	if (!(ofl->ofl_flags & (FLG_OF_DYNAMIC | FLG_OF_RELOBJ)) &&
	    !(ofl->ofl_osinterp) && (ofl->ofl_flags1 & FLG_OF1_VADDR))
		ofl->ofl_dtflags_1 |= DF_1_NOHDR;

	if (ofl->ofl_flags & FLG_OF_RELOBJ) {
		/*
		 * NOHDR has no effect on a relocatable file.
		 * Make sure this flag isn't set.
		 */
		ofl->ofl_dtflags_1 &= ~DF_1_NOHDR;
	} else if (first_seg != NULL) {
		/*
		 * DF_1_NOHDR might have been set globally by the HDR_NOALLOC
		 * directive. If not, then we want to check the per-segment
		 * flag for the first loadable segment and propagate it
		 * if set.
		 */
		if ((ofl->ofl_dtflags_1 & DF_1_NOHDR) == 0) {
			/*
			 * If we sorted the segments, the first segment
			 * may have changed.
			 */
			if ((ofl->ofl_flags1 & FLG_OF1_VADDR) ||
			    (aplist_nitems(ofl->ofl_segs_order) > 0)) {
				for (APLIST_TRAVERSE(ofl->ofl_segs, idx, sgp)) {
					if (sgp->sg_name == NULL)
						continue;
					if ((sgp->sg_flags & FLG_SG_DISABLED) ==
					    0) {
						first_seg = sgp;
						break;
					}
				}
			}

			/*
			 * If the per-segment NOHDR flag is set on our first
			 * segment, then make it take effect.
			 */
			if (first_seg->sg_flags & FLG_SG_NOHDR)
				ofl->ofl_dtflags_1 |= DF_1_NOHDR;
		}

		/*
		 * For executable and shared objects, the first segment must
		 * be loadable unless NOHDR was specified, because the ELF
		 * header must simultaneously lie at offset 0 of the file and
		 * be included in the first loadable segment. This isn't
		 * possible if some other segment type starts the file
		 */
		if (!(ofl->ofl_dtflags_1 & DF_1_NOHDR) &&
		    (first_seg->sg_phdr.p_type != PT_LOAD)) {
			Conv_inv_buf_t	inv_buf;

			ld_eprintf(ofl, ERR_FATAL,
			    MSG_INTL(MSG_SEG_FIRNOTLOAD),
			    conv_phdr_type(ELFOSABI_SOLARIS, ld_targ.t_m.m_mach,
			    first_seg->sg_phdr.p_type, 0, &inv_buf),
			    first_seg->sg_name);
			return (FALSE);
		}
	}

	/*
	 * Mapfiles may have been used to create symbol definitions
	 * with backing storage.  Although the backing storage is
	 * associated with an input section, the association of the
	 * section to an output section (and segment) is initially
	 * deferred.  Now that all mapfile processing is complete, any
	 * entrance criteria requirements have been processed, and
	 * these backing storage sections can be associated with the
	 * appropriate output section (and segment).
	 */
	if (ofl->ofl_maptext || ofl->ofl_mapdata)
		DBG_CALL(Dbg_sec_backing(ofl->ofl_lml));

	for (APLIST_TRAVERSE(ofl->ofl_maptext, idx, isp)) {
		if (ld_place_section(ofl, isp, NULL,
		    ld_targ.t_id.id_text, NULL) == (Os_desc *)S_ERROR)
			return (FALSE);
	}

	for (APLIST_TRAVERSE(ofl->ofl_mapdata, idx, isp)) {
		if (ld_place_section(ofl, isp, NULL,
		    ld_targ.t_id.id_data, NULL) == (Os_desc *)S_ERROR)
			return (FALSE);
	}

	return (TRUE);
}
