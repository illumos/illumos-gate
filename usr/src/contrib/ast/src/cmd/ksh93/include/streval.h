/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1982-2012 AT&T Intellectual Property          *
*                      and is licensed under the                       *
*                 Eclipse Public License, Version 1.0                  *
*                    by AT&T Intellectual Property                     *
*                                                                      *
*                A copy of the License is available at                 *
*          http://www.eclipse.org/org/documents/epl-v10.html           *
*         (with md5 checksum b35adb5213ca9657e911e9befb180842)         *
*                                                                      *
*              Information and Software Systems Research               *
*                            AT&T Research                             *
*                           Florham Park NJ                            *
*                                                                      *
*                  David Korn <dgk@research.att.com>                   *
*                                                                      *
***********************************************************************/
#pragma prototyped
#ifndef SEQPOINT
/*
 * D. G. Korn
 *
 * arithmetic expression evaluator
 */

/* The following only is needed for const */
#include	<ast.h>
#include	<math.h>
#include	"defs.h"
#if _AST_VERSION >= 20030127L
#   include	<ast_float.h>
#endif

#if _ast_fltmax_double
#define LDBL_LLONG_MAX		DBL_LLONG_MAX
#define LDBL_ULLONG_MAX		DBL_ULLONG_MAX
#define LDBL_LLONG_MIN		DBL_LLONG_MIN
#endif

#ifndef LDBL_LLONG_MAX
#   ifdef LLONG_MAX
#	define LDBL_LLONG_MAX	((Sfdouble_t)LLONG_MAX)
#   else
#	ifdef LLONG_MAX
#	   define LDBL_LLONG_MAX	((Sfdouble_t)LLONG_MAX)
#	else
#	   define LDBL_LLONG_MAX	((Sfdouble_t)((((Sflong_t)1) << (8*sizeof(Sflong_t)-1)) -1 ))
#	endif
#   endif
#endif
#ifndef LDBL_ULLONG_MAX
#   ifdef ULLONG_MAX
#	define LDBL_ULLONG_MAX		((Sfdouble_t)ULLONG_MAX)
#   else
#	define LDBL_ULLONG_MAX		(2.*((Sfdouble_t)LDBL_LLONG_MAX))
#   endif
#endif
#ifndef LDBL_LLONG_MIN
#   ifdef LLONG_MIN
#	define LDBL_LLONG_MIN		((Sfdouble_t)LLONG_MIN)
#   else
#	define LDBL_LLONG_MIN		(-LDBL_LLONG_MAX)
#   endif
#endif
#ifndef LDBL_DIG
#   define LDBL_DIG DBL_DIG
#endif

struct lval
{
	Shell_t		*shp;
	char		*value;
	char		*ovalue;
	Sfdouble_t	(*fun)(Sfdouble_t,...);
	const char	*expr;
	const  void	*ptr;
	int		nosub;
	short		flag;
	short		nargs;
	short		emode;
	short		level;
	short		elen;
	char		eflag;
	char		isfloat;
};

struct mathtab
{
	char		fname[16];
	Sfdouble_t	(*fnptr)(Sfdouble_t,...);
};

typedef struct _arith_
{
	Shell_t		*shp;
	unsigned char	*code;
	const char	*expr;
	Sfdouble_t	(*fun)(const char**,struct lval*,int,Sfdouble_t);
	short		size;
	short		staksize;
	short		emode;
	short		elen;
} Arith_t;
#define ARITH_COMP	04	/* set when compile separate from execute */
#define ARITH_ASSIGNOP	010	/* set during assignment operators  */

#define MAXPREC		15	/* maximum precision level */
#define SEQPOINT	0200	/* sequence point */
#define NOASSIGN	0100	/* assignment legal with this operator */
#define RASSOC		040	/* right associative */
#define NOFLOAT		020	/* illegal with floating point */
#define PRECMASK	017	/* precision bit mask */

#define A_EOF		1
#define A_NEQ		2
#define A_NOT		3
#define A_MOD		4
#define A_ANDAND	5
#define A_AND		6
#define A_LPAR		7
#define A_RPAR		8
#define A_POW		9
#define A_TIMES		10
#define A_PLUSPLUS	11
#define A_PLUS		12
#define A_COMMA		13
#define A_MINUSMINUS	14
#define A_MINUS		15
#define A_DIV		16
#define A_LSHIFT	17
#define A_LE		18
#define A_LT		19
#define A_EQ		20
#define A_ASSIGN	21
#define A_COLON		22
#define A_RSHIFT	23
#define A_GE		24
#define A_GT		25
#define A_QCOLON	26
#define A_QUEST		27
#define A_XOR		28
#define A_OROR		29
#define A_OR		30
#define A_TILDE		31
#define A_REG		32
#define A_DIG		33
#define A_INCR		34
#define A_DECR  	35
#define A_PUSHV 	36
#define A_PUSHL 	37
#define A_PUSHN 	38
#define A_PUSHF 	39
#define A_STORE 	40
#define A_POP   	41
#define A_SWAP  	42
#define A_UMINUS	43
#define A_JMPZ  	44
#define A_JMPNZ		45
#define A_JMP		46
#define A_CALL1F	47
#define A_CALL2F	48
#define A_CALL3F	49
#define A_CALL1I	50
#define A_CALL2I	51
#define A_DOT		52
#define A_LIT		53
#define A_NOTNOT        54
#define A_ASSIGNOP	55
#define A_ENUM		56
#define A_ASSIGNOP1	57


/* define error messages */
extern const unsigned char	strval_precedence[35];
extern const char		strval_states[64];
extern const char		e_moretokens[];
extern const char		e_argcount[];
extern const char		e_paren[];
extern const char		e_badnum[];
extern const char		e_badcolon[];
extern const char		e_recursive[];
extern const char		e_divzero[];
extern const char		e_synbad[];
extern const char		e_notlvalue[];
extern const char		e_function[];
extern const char		e_questcolon[];
extern const char		e_incompatible[];
extern const char		e_domain[];
extern const char		e_overflow[];
extern const char		e_singularity[];
extern const char		e_dict[];
extern const char		e_charconst[];
extern const struct 		mathtab shtab_math[];

/* function code for the convert function */

#define LOOKUP	0
#define ASSIGN	1
#define VALUE	2
#define MESSAGE	3

extern Sfdouble_t strval(Shell_t*,const char*,char**,Sfdouble_t(*)(const char**,struct lval*,int,Sfdouble_t),int);
extern Arith_t *arith_compile(Shell_t *,const char*,char**,Sfdouble_t(*)(const char**,struct lval*,int,Sfdouble_t),int);
extern Sfdouble_t arith_exec(Arith_t*);
#endif /* !SEQPOINT */
