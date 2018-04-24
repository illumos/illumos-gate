%{
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "parseproto.h"
#include <assert.h>

static decl_spec_t	*declspec_Construct(void);
static void		 declspec_Destroy(decl_spec_t *);
static decl_spec_t	*declspec_Init(stt_t, char *);
static char		*declspec_VerifySTT(stt_t, stt_t);
static decl_spec_t	*declspec_AddSTT(decl_spec_t *, stt_t, const char **);
static decl_spec_t	*declspec_AddDS(decl_spec_t *,
			    decl_spec_t *, const char **);
static stt_t		 declspec_GetSTT(decl_spec_t *);
static char		*declspec_GetTag(decl_spec_t *);
static type_t		*type_Construct(void);
static void		 type_Destroy(type_t *);
static type_t		*type_SetPtr(type_t *, stt_t);
static type_t		*type_SetFun(type_t *, decl_t *);
static type_t		*type_AddTail(type_t *, type_t *);
static	const char	*type_Verify(type_t *);

static	decl_t		*decl_Construct(void);
static	decl_t		*decl_AddArg(decl_t *, decl_t *);
static	int		 decl_IsVoid(decl_t *);
static	int		 decl_IsVoidArray(decl_t *);
static	const char	*decl_VerifyArgs(decl_t *);
static	decl_t		*decl_AddDS(decl_t *, decl_spec_t *, const char **);
static	decl_t		*decl_AddTypeTail(decl_t *, type_t *);
static	decl_t		*decl_addptr(decl_t *, type_t *);
static	decl_t		*decl_addary(decl_t *, char *);
static	decl_t		*decl_addfun(decl_t *, decl_t *);
static	decl_t		*decl_addellipsis(decl_t *);

#if defined(DEBUG)
static	void		type_PrintType(type_t *, int);
static	void		decl_PrintDecl(decl_t *, int);
static	void		decl_PrintTraceInfo(decl_t *);
static	char		*de_const(char *);
#endif



static	int	yylex(void);
static	void	yyerror(const char *);
static	int	yyparse(void);

#if defined(MEM_DEBUG)
static	int	declspec_Construct_calls;
static	int	type_Construct_calls;
static	int	decl_Construct_calls;
#endif

#if defined(DEBUG)
static	char	*de_const(char *);
#endif
%}

%union {
	char		*s_val;
	int		 i_val;
	stt_t		 stt_val;
	decl_spec_t	*ds_val;
	type_t		*t_val;
	decl_t		*d_val;
}

%token	<i_val>	ELLIPSIS

%token	<s_val>	INTEGER
%token	<s_val>	IDENTIFIER
%token	<s_val>	TYPEDEF_NAME
%type	<s_val>	constant_expression

%token	<stt_val>	REGISTER
%token	<stt_val>	TYPEDEF	EXTERN	AUTO	STATIC
%token	<stt_val>	VOID	CHAR	SHORT	INT	LONG
%token	<stt_val>	FLOAT	DOUBLE	SIGNED	UNSIGNED
%token	<stt_val>	CONST	VOLATILE	RESTRICT	RESTRICT_KYWD
%type	<stt_val>	struct_or_union
%type	<ds_val>	storage_class_specifier
%type	<ds_val>	type_qualifier
%type	<ds_val>	type_qualifier_list

%token	<ds_val>	STRUCT		UNION
%token	<ds_val>	ENUM
%type	<ds_val>	declaration_specifiers
%type	<ds_val>	type_specifier
%type	<ds_val>	struct_or_union_specifier enum_specifier
%type	<ds_val>	typedef_name

%type	<t_val>		pointer

%type	<d_val>		declaration
%type	<d_val>		init_declarator_list init_declarator
%type	<d_val>		declarator
%type	<d_val>		direct_declarator
%type	<d_val>		parameter_type_list parameter_list
%type	<d_val>		parameter_declaration
%type	<d_val>		abstract_declarator
%type	<d_val>		direct_abstract_declarator

%start	declaration

%%

/*
 * The grammar is derived from ANSI/ISO 9899-1990.
 */

declaration
	: declaration_specifiers init_declarator_list ';'
		{
			decl_t	*dp;

			protop = $$ = $2;

			/* only one declaration allowed */
			assert(protop->d_next == NULL);

			for (dp = $2; dp && (errstr == NULL);
			    dp = dp->d_next) {
				const char	*sp;

				decl_AddDS(dp, $1, &errstr);
				if (sp = decl_Verify(dp))
					errstr = sp;
			}
			declspec_Destroy($1);
		}
	| error ';'
		{
			protop = $$ = NULL;
			errstr = "function prototype syntax error";
		}
/*
 * XXX - Does not support a "stand-alone" declaration specifier. It is
 * essentially a type declaration, for example:
 *
 *	typedef enum { FALSE = 0, TRUE = 1 } boolean_t;
 * or
 *	struct _name { char *first; char *last };
 */

/* XXX	| declaration_specifiers */
	;

declaration_specifiers
	: storage_class_specifier declaration_specifiers
		{
			char const *ep;

			$$ = declspec_AddDS($2, $1, &ep);
			declspec_Destroy($1);

			if (errstr == NULL)
				errstr = ep;
		}
	| storage_class_specifier
	| type_specifier declaration_specifiers
		{
			const char	*ep;

			$$ = declspec_AddDS($2, $1, &ep);
			declspec_Destroy($1);

			if (errstr == NULL)
				errstr = ep;
		}
	| type_specifier
	| type_qualifier declaration_specifiers
		{
			const char	*ep;

			$$ = declspec_AddDS($2, $1, &ep);
			declspec_Destroy($1);

			if (errstr == NULL)
				errstr = ep;
		}
	| type_qualifier
	;

storage_class_specifier
	: REGISTER
		{
			$$ = declspec_Init(SCS_REGISTER, NULL);
		}
/*
 * XXX - Does not support any storage class specifier other than
 * register, and then only for function arguments.
 *
	| TYPEDEF
		{
			$$ = declspec_Init(SCS_TYPEDEF, NULL);
		}
	| EXTERN
		{
			$$ = declspec_Init(SCS_EXTERN, NULL);
		}
	| STATIC
		{
			$$ = declspec_Init(SCS_STATIC, NULL);
		}
	| AUTO
		{
			$$ = declspec_Init(SCS_AUTO, NULL);
		}
 */
	;

type_specifier
	: VOID
		{
			$$ = declspec_Init(TS_VOID, NULL);
			atIDENT = 1;
		}
	| CHAR
		{
			$$ = declspec_Init(TS_CHAR, NULL);
			atIDENT = 1;
		}
	| SHORT
		{
			$$ = declspec_Init(TS_SHORT, NULL);
			atIDENT = 1;
		}
	| INT
		{
			$$ = declspec_Init(TS_INT, NULL);
			atIDENT = 1;
		}
	| LONG
		{
			$$ = declspec_Init(TS_LONG, NULL);
			atIDENT = 1;
		}
	| FLOAT
		{
			$$ = declspec_Init(TS_FLOAT, NULL);
			atIDENT = 1;
		}
	| DOUBLE
		{
			$$ = declspec_Init(TS_DOUBLE, NULL);
			atIDENT = 1;
		}
	| SIGNED
		{
			$$ = declspec_Init(TS_SIGNED, NULL);
			atIDENT = 1;
		}
	| UNSIGNED
		{
			$$ = declspec_Init(TS_UNSIGNED, NULL);
			atIDENT = 1;
		}
	| struct_or_union_specifier
	| enum_specifier
	| typedef_name
	;

typedef_name
	: TYPEDEF_NAME
		{
			$$ = declspec_Init(TS_TYPEDEF, $1);
			atIDENT = 1;
			free($1);
		}
	;

/*
 * The "restrict" keyword is new in the C99 standard.
 * It is type qualifier like const and volatile.
 * We are using "_RESTRICT_KYWD" in headers and source code so
 * it is easily turned on and off by various macros at compile time.
 * In order for the "restrict" keyword to be recognized you must
 * be using a C99 compliant compiler in its native mode.
 */
type_qualifier
	: CONST
		{
			$$ = declspec_Init(TQ_CONST, NULL);
		}
	| VOLATILE
		{
			$$ = declspec_Init(TQ_VOLATILE, NULL);
		}
	| RESTRICT
		{
			$$ = declspec_Init(TQ_RESTRICT, NULL);
		}
	| RESTRICT_KYWD
		{
			$$ = declspec_Init(TQ_RESTRICT_KYWD, NULL);
		}
	;

struct_or_union_specifier
	: struct_or_union { atIDENT = 1; } IDENTIFIER
		{
			$$ = declspec_Init($1, $3);
			free($3);
		}
/*
 * XXX - struct or union definitions are not supported. It is generally
 * not done within the context of a function declaration (prototype) or
 * variable definition.

	| struct_or_union IDENTIFIER '{' struct_declaration_list '}'
	| struct_or_union '{' struct_declaration_list '}'
 */
	;

struct_or_union
	: STRUCT
		{
			$$ = TS_STRUCT;
		}
	| UNION
		{
			$$ = TS_UNION;
		}
	;

init_declarator_list
	: init_declarator
		{
			$$ = $1;
			atIDENT = 1;
		}
/*
 * XXX - Does not support a comma separated list of declarations or
 * definitions. Function prototypes or variable definitions must be
 * given as one per C statement.

	| init_declarator_list ',' init_declarator
		{
			$$ = decl_AddArg($1, $3);
			atIDENT = 1;
		}
*/
	;

init_declarator
	: declarator
/*
 * XXX - Initialization is not supported.

	| declarator '=' initializer
*/
	;


enum_specifier
	: ENUM { atIDENT = 1; } IDENTIFIER
		{
			$$ = declspec_Init(TS_ENUM, $3);
			free($3);
		}
/*
 * XXX - enumerator definition is not supported for the same reasons
 * struct|union definition is not supported.

	| ENUM IDENTIFIER '{' enumerator_list '}'
	| ENUM '{' enumerator_list '}'
*/
	;


declarator
	: pointer direct_declarator
		{
			$$ = decl_addptr($2, $1);
		}
	| direct_declarator
	;

direct_declarator
	: IDENTIFIER
		{
			$$ = decl_SetName(decl_Construct(), $1);
			atIDENT = 0;
			free($1);
		}
	| '(' declarator ')'
		{
			$$ = $2;
		}
	| direct_declarator '[' constant_expression ']'
		{
			$$ = decl_addary($1, $3);
			free($3);
		}
	| direct_declarator '[' ']'
		{
			$$ = decl_addary($1, NULL);
		}
	| direct_declarator '(' parameter_type_list ')'
		{
			$$ = decl_addfun($1, $3);
		}
	| direct_declarator '(' ')'
		{
			$$ = decl_addfun($1, NULL);
		}
	;

pointer
	: '*' type_qualifier_list
		{
			$$ = type_SetPtr(type_Construct(), ($2)->ds_stt);
			declspec_Destroy($2);
		}
	| '*'
		{
			$$ = type_SetPtr(type_Construct(), TQ_NONE);
		}
	| '*' type_qualifier_list pointer
		{
			type_t	*tp = type_Construct();

			type_SetPtr(tp, ($2)->ds_stt);
			declspec_Destroy($2);
			$$ = type_AddTail($3, tp);
		}
	| '*' pointer
		{
			type_t	*tp = type_Construct();

			type_SetPtr(tp, TQ_NONE);
			$$ = type_AddTail($2, tp);
		}
	;

type_qualifier_list
	: type_qualifier
	| type_qualifier_list type_qualifier
		{
			const char	*ep;

			/* XXX - ignore any error */
			$$ = declspec_AddDS($1, $2, &ep);
			declspec_Destroy($2);
		}
	;

parameter_type_list
	: parameter_list
	| parameter_list ',' ELLIPSIS
		{
			$$ = decl_addellipsis($1);
		}
	;

parameter_list
	: parameter_declaration
		{
			const char *sp = type_Verify($1->d_type);

			if (sp)
				errstr = sp;

			$$ = $1;
			atIDENT = 0;
		}
	| parameter_list ',' parameter_declaration
		{
			const char *sp = type_Verify($3->d_type);

			if (sp)
				errstr = sp;

			$$ = decl_AddArg($1, $3);
			atIDENT = 0;
		}
	;

parameter_declaration
	: declaration_specifiers declarator
		{
			const char *ep;

			$$ = decl_AddDS($2, $1, &ep);
			declspec_Destroy($1);

			if (errstr == NULL)
				errstr = ep;
		}
	| declaration_specifiers abstract_declarator
		{
			const char *ep;

			$$ = decl_AddDS($2, $1, &ep);
			declspec_Destroy($1);

			if (errstr == NULL)
				errstr = ep;
		}
	| declaration_specifiers
		{
			const char *ep;

			$$ = decl_AddDS(decl_Construct(), $1, &ep);
			declspec_Destroy($1);

			if (errstr == NULL)
				errstr = ep;
		}
	;

abstract_declarator
	: pointer
		{
			$$ = decl_addptr(decl_Construct(), $1);
		}
	| pointer direct_abstract_declarator
		{
			$$ = decl_addptr($2, $1);
		}
	| direct_abstract_declarator
	;

direct_abstract_declarator
	: '(' abstract_declarator ')'
		{
			$$ = $2;
		}
	| direct_abstract_declarator '[' constant_expression ']'
		{
			$$ = decl_addary($1, $3);
			free($3);
		}
	| '[' constant_expression ']'
		{
			$$ = decl_addary(decl_Construct(), $2);
			free($2);
		}
	| direct_abstract_declarator '[' ']'
		{
			$$ = decl_addary($1, NULL);
		}
	| '[' ']'
		{
			$$ = decl_addary(decl_Construct(), NULL);
		}
	| direct_abstract_declarator '(' parameter_type_list ')'
		{
			$$ = decl_addfun($1, $3);
		}
	| '(' parameter_type_list ')'
		{
			$$ = decl_addfun(decl_Construct(), $2);
		}
	| direct_abstract_declarator '(' ')'
		{
			$$ = decl_addfun($1, NULL);
		}
	| '(' ')'
		{
			$$ = decl_addfun(decl_Construct(), NULL);
		}
	;

/*
 * XXX - General case constant expressions are not supported. It would
 * be easy to implement (for the most part), but there are no cases to
 * date that require such a facility. The grammar does allow an
 * identifier (or typedef name) to be used since the prototype is not
 * processed by CPP. The only integer constant that is supported is
 * decimal.
 */

constant_expression
	: INTEGER
	| IDENTIFIER
	| TYPEDEF_NAME
	;

%%

/* Data Declarations */

typedef struct {
	char	*name;
	int	 token;
	stt_t	 stt;
} keyword_t;

typedef struct {
	stt_t	 s_stt;
	char	*s_str;
} sttpair_t;

/* External Declarations */

static	const keyword_t	*lookup_keyword(const char *);
static	const char	*lookup_sttpair(stt_t);
static	int		 getch(void);
static	void		 ungetch(int);
static	void		 skipwhitespace(void);
static	int		 lookahead(int);
static	void		 skipcomment(void);

/* External Definitions */

static char		*input = NULL;	/* current place in the input stream */
/* at point in stream were identifier is expected */
static int		 atIDENT = 0;
static decl_t		*protop = NULL;	/* pointer to prototype */
static const char	*errstr = NULL;	/* error message */

/*
 * lookup_keyword - Given a string, return the keyword_t or NULL.
 */

static const keyword_t *
lookup_keyword(const char *name) {
	static	const keyword_t	keytbl[] = {
		{	"register",	REGISTER,	SCS_REGISTER	},
#if UNSUPPORTED
		{	"typedef",	TYPEDEF,	SCS_TYPEDEF	},
		{	"auto",		AUTO,		SCS_AUTO	},
		{	"static",	STATIC,		SCS_STATIC	},
		{	"extern",	EXTERN,		SCS_EXTERN	},
#endif /* UNSUPPORTED */
		{	"void",		VOID,		TS_VOID		},
		{	"char",		CHAR,		TS_CHAR		},
		{	"short",	SHORT,		TS_SHORT	},
		{	"int",		INT,		TS_INT		},
		{	"long",		LONG,		TS_LONG		},
		{	"float",	FLOAT,		TS_FLOAT	},
		{	"double",	DOUBLE,		TS_DOUBLE	},
		{	"signed",	SIGNED,		TS_SIGNED	},
		{	"unsigned",	UNSIGNED,	TS_UNSIGNED	},
		{	"struct",	STRUCT,		TS_STRUCT	},
		{	"union",	UNION,		TS_UNION	},
		{	"enum",		ENUM,		TS_ENUM		},

		{	"const",	CONST,		TQ_CONST	},
		{	"volatile",	VOLATILE,	TQ_VOLATILE	},
		{	"restrict",	RESTRICT,	TQ_RESTRICT	},
		{	"_RESTRICT_KYWD",RESTRICT_KYWD,	TQ_RESTRICT_KYWD},
	};
#define	NKEYWORD	(sizeof (keytbl)/sizeof (keyword_t))

	int	i;

	for (i = 0; i < NKEYWORD; ++i) {
		char	*s = keytbl[i].name;

		if ((*s == *name) && (strcmp(s, name) == 0))
			return (&keytbl[i]);
	}

	return (NULL);
}

/*
 * lookup_sttpair - Given an stt_t return a string or NULL.
 *
 */

static const char *
lookup_sttpair(stt_t s) {
	/* valid type specifier combinations */
	static const sttpair_t	stttbl[] = {
		{ TS_VOID,				"void"		},
		{ TS_CHAR,				"char"		},
		{ TS_SIGNED | TS_CHAR,			"signed char"	},
		{ TS_UNSIGNED | TS_CHAR,		"unsigned char"	},
		{ TS_SHORT,				"short"		},
		{ TS_SIGNED | TS_SHORT,			"signed short"	},
		{ TS_SHORT | TS_INT,			"short int"	},
		{ TS_SIGNED | TS_SHORT | TS_INT,
		    "signed short int"				},
		{ TS_UNSIGNED | TS_SHORT,
		    "unsigned short"					},
		{ TS_UNSIGNED | TS_SHORT | TS_INT,
		    "unsigned short int"				},
		{ TS_INT,				"int"		},
		{ TS_SIGNED,				"signed"	},
		{ TS_SIGNED | TS_INT,			"signed int"	},
		{ TS_NO_TS,				""		},
		{ TS_UNSIGNED,				"unsigned"	},
		{ TS_UNSIGNED | TS_INT,			"unsigned int"	},
		{ TS_LONG,				"long"		},
		{ TS_SIGNED | TS_LONG,			"signed long"	},
		{ TS_LONG | TS_INT,			"long int"	},
		{ TS_SIGNED | TS_LONG | TS_INT,
		    "signed long int"					},
		{ TS_UNSIGNED | TS_LONG,		"unsigned long"	},
		{ TS_UNSIGNED | TS_LONG | TS_INT,
		    "unsigned long int"				},
		{ TS_FLOAT,				"float"		},
		{ TS_DOUBLE,				"double"	},
		{ TS_LONG | TS_DOUBLE,			"long double"	},
		{ TS_STRUCT,				"struct"	},
		{ TS_UNION,				"union"		},
		{ TS_ENUM,				"enum"		},
		{ TS_TYPEDEF,				""		},
		/* non-ANSI type: long long */
		{ TS_LONGLONG,				"long long"	},
		{ TS_LONGLONG | TS_INT,			"long long int"	},
		{ TS_SIGNED | TS_LONGLONG,
		    "signed long long"				},
		{ TS_UNSIGNED | TS_LONGLONG,
		    "unsigned long long"				},
		{ TS_SIGNED | TS_LONGLONG | TS_INT,
		    "signed long long int"				},
		{ TS_UNSIGNED | TS_LONGLONG | TS_INT,
		    "unsigned long long int"				},
	};

#define	NDECLSPEC	(sizeof (stttbl)/sizeof (sttpair_t))

	int	i;

	for (i = 0; i < NDECLSPEC; ++i)
		if (s == stttbl[i].s_stt)
			return (stttbl[i].s_str);

	return (NULL);
}

/*
 * yylex - return next token from the the input stream.
 *
 * The lexical analyzer does not recognize all possible C lexical
 * elements. It only recognizes those associated with function
 * declarations (read: prototypes) and data definitions.
 */

static int
yylex(void) {
	char	buf[BUFSIZ];		/* string version of token */
	int	c;
	int	i = 0;

restart:
	skipwhitespace();

	switch (c = getch()) {
	case '/':
		if (lookahead('*')) {
			skipcomment();
			goto restart;
		}
		return (c);

	case '.':
		if (lookahead('.')) {
			if (lookahead('.'))
				return (ELLIPSIS);
		}
		return (c);

	case EOF:
	case '(':
	case ')':
	case ',':
	case '[':
	case ']':
	case ';':
	case '*':
		return (c);

	default:
		if ((c == '_') || isalpha(c)) {
			const keyword_t	*kp;

			do {
				buf[i++] = c;
				c	 = getch();
			} while ((c == '_') || isalnum(c));

			ungetch(c);

			buf[i] = '\0';

			if ((kp = lookup_keyword(buf)) != NULL) {
				yylval.stt_val = kp->stt;
				return (kp->token);
			} else {
				yylval.s_val = strdup(buf);

				return ((atIDENT) ? IDENTIFIER : TYPEDEF_NAME);
			}
		} else if (isdigit(c)) {
			do {
				buf[i++] = c;
			} while (isdigit(c = getch()));

			ungetch(c);

			buf[i]	 = '\0';
			yylval.s_val = strdup(buf);

			return (INTEGER);
		} else
			return (c);
	}
/* NOTREACHED */
}

/* getch - return the next character from the input stream. */

static int
getch(void) {
	int	c;

	if ((c = *input) == '\0')
		c = EOF;
	else				/* only advance on non-NULL */
		input++;

	return (c);
}

/* ungetch - return a character to the input stream. */

static void
ungetch(int c) {
	*(--input) = c;
}

/* skipwhitespace - skip over whitespace in the input stream. */

static void
skipwhitespace(void) {
	int	c;

	while (isspace(c = getch()))
		;

	ungetch(c);
}

/* skipcomment - scan ahead to the next end of comment. */

static void
skipcomment(void) {
	loop {
		int	c;

		switch (c = getch()) {
		case EOF:
			return;

		case '*':
			if (lookahead('/'))
				return;
		}
	}
/* NOTREACHED */
}

/* lookahead - does next character match 'c'? */

static int
lookahead(int c) {
	int	ch = getch();
	int	match;

	if (!(match = (ch == c)))
		ungetch(ch);

	return (match);
}

/* putNtabs - write N '\t' to standard output. */

#if defined(DEBUG)

static void
putNTabs(int n) {
	int	 i;

	for (i = 0; i < n; ++i)
		putchar('\t');
}
#endif	/* DEBUG */

/* D E C L A R A T I O N   S P E C I F I E R S */

/*
 * Declaration specifiers encode storage class, type specifier and type
 * qualifier information. This includes any identifiers associated with
 * struct, union or enum declarations. Typedef names are also encoded
 * in declaration specifiers.
 */

/* declspec_Construct - allocate and initialize a declspec_t. */

static decl_spec_t *
declspec_Construct(void) {
	decl_spec_t	*dsp = malloc(sizeof (decl_spec_t));

	assert(dsp != NULL);
	dsp->ds_stt = SCS_NONE | TS_NO_TS | TQ_NONE;
	dsp->ds_id = NULL;
#if defined(MEM_DEBUG)
	++declspec_Construct_calls;
#endif
	return (dsp);
}

/* declspec_Destroy - free a declspec_t. */

static void
declspec_Destroy(decl_spec_t *dsp) {
	free(dsp->ds_id);
	free(dsp);
#if defined(MEM_DEBUG)
	--declspec_Construct_calls;
#endif
}

/*
 * declspec_Init - allocate and initialize a declspec_t given an
 *	stt_t and identifier.
 *
 * Note:
 *	1) identifier can be NULL.
 *	2) errors resulting in the stt_t and identifier are ignored.
 */

static decl_spec_t *
declspec_Init(stt_t s, char *tagp) {
	const char	*p;
	decl_spec_t	*dsp = declspec_Construct();
	decl_spec_t	 tmp;

	tmp.ds_stt = s;
	tmp.ds_id = tagp;

	declspec_AddDS(dsp, &tmp, &p);		/* XXX ignore any error */

	return (dsp);
}

/*
 * declspec_VerifySTT - verify that the two given stt_t can be combined.
 *
 * Note:
 *	1) The return value is a const char *, non-NULL to indicate an error.
 */

static char *
declspec_VerifySTT(stt_t s1, stt_t s2) {
	stt_t	result;

	if ((s1 | s2) != (s1 ^ s2))
		return ("attempt to add declaration specifier "
		    "that is already present");

	result = (s1 | s2) & TS_MASK;

	if (lookup_sttpair(result) == NULL) {
		if (STT_isbasic(result) && STT_isderived(result))
			return ("attempt to combine basic and "
			    "derived types");

		if (STT_isvoid(result) &&
		    (STT_isbasic(result) || STT_isderived(result)))
			return ("attempt to combine void with "
			    "other type specifiers");

		if (STT_isfloat(result) && STT_isint(result))
			return ("attempt to combine floating and "
			    "integer type specifiers");

		if (STT_ischar(result) && STT_isint(result))
			return ("attempt to combine character and "
			    "integer type specifiers");

		if (STT_has_explicit_sign(result) &&
		    (STT_isfloat(result) || STT_isderived(result)))
			return ("attempt to combine signed or "
			    "unsigned with float or derived type");

		return ("invalid declaration specifier");
	}

	return (NULL);
}

/*
 * declspec_AddSTT - add an stt_t to a decl_spec_t.
 *
 * Note:
 *	1) The "long long" type is handled here.
 *	   If both stt_t include TS_LONG then this is an attempt to use
 *	   "long long". The TS_LONG is cleared from the s1 and s2 and
 *	   then TS_LONGLONG is added to s2. The resulting s1 and s2 are
 *	   passed to declspec_VerifySTT to determine if the result is valid.
 *
 *	2) This method of handling "long long" does detect the case of
 *	   "long double long" and all it's variant forms.
 */

static decl_spec_t *
declspec_AddSTT(decl_spec_t *dsp, stt_t s2, const char **err) {
	stt_t	s1 = dsp->ds_stt;

	/* non-ANSI type: long long */
	if ((s1 & TS_LONG) && (s2 & TS_LONG)) {
		s1		&= ~(TS_LONG);
		dsp->ds_stt = s1;
		s2		&= ~(TS_LONG);
		s2		|= TS_LONGLONG;
	}

	if ((*err = declspec_VerifySTT(s1, s2)) == NULL)
		dsp->ds_stt	|= s2;

	return (dsp);
}

/*
 * declpec_AddDS - add a decl_spec_t to an existing decl_spec_t.
 */

static decl_spec_t *
declspec_AddDS(decl_spec_t *dsp, decl_spec_t *tsp, const char **err) {
	declspec_AddSTT(dsp, tsp->ds_stt, err);

	if ((*err == NULL) && tsp->ds_id) {
		free(dsp->ds_id);
		dsp->ds_id	 = strdup(tsp->ds_id);

		assert(dsp->ds_id != NULL);
	}

	return (dsp);
}

/*
 * declspec_GetSTT - return the stt_t within a decl_spec_t.
 */

static stt_t
declspec_GetSTT(decl_spec_t *dsp) {
	return (dsp->ds_stt);
}

/*
 * declspec_GetTag - return the identifier within a decl_spec_t.
 */

static char *
declspec_GetTag(decl_spec_t *dsp) {
	return (dsp->ds_id);
}

/*
 * declspec_ToString - convert a decl_spec_t into a string.
 *
 * Note:
 *	1) The form of the resulting string is always the same, i.e.
 *
 *		[register] [type_specifier] [const] [volatile]
 *
 * dsp must be correct
 *
 */

char *
declspec_ToString(char *bufp, decl_spec_t *dsp) {
	const char	*s;
	int		 something = 0;

	*bufp = '\0';

	/* storage class specifier */
	switch (dsp->ds_stt & SCS_MASK) {
	case SCS_REGISTER:
		strcat(bufp, "register");
		something = 1;
		break;
	}

	s = lookup_sttpair(dsp->ds_stt & TS_MASK);

	/* type specifier */
	switch (dsp->ds_stt & TS_MASK) {
	case TS_STRUCT:
	case TS_UNION:
	case TS_ENUM:
		if (something)
			strcat(bufp, " ");

		strcat(bufp, s);
		strcat(bufp, " ");
		strcat(bufp, dsp->ds_id);
		break;

	case TS_TYPEDEF:
		if (something)
			strcat(bufp, " ");

		strcat(bufp, dsp->ds_id);
		break;

	default:
		if (something)
			strcat(bufp, " ");

		strcat(bufp, s);
		break;
	}

	if (s)
		something = 1;

	if (something && (dsp->ds_stt & TQ_MASK))
		strcat(bufp, " ");

	if (dsp->ds_stt & TQ_CONST)	/* type qualifier */
		strcat(bufp, "const");

	if (dsp->ds_stt & TQ_VOLATILE) {
		if (dsp->ds_stt & TQ_CONST)
			strcat(bufp, " ");

		strcat(bufp, "volatile");
	}

	/*
	 * It currently acknowledges and ignores restrict or _RESTRICT_KYWD
	 * in code generation because of the uncertain behavior of "restrict".
	 */
	if (dsp->ds_stt & TQ_RESTRICT)
		strcat(bufp, "");

	if (dsp->ds_stt & TQ_RESTRICT_KYWD)
		strcat(bufp, "");

	return (bufp);
}

/* T Y P E   M O D I F I E R S */

/*
 * Type modifiers encode the "array of...", "pointer to ..." and
 * "function returning ..." aspects of C types. The modifiers are kept
 * as a linked list in precedence order. The grammar encodes the
 * precedence order described by the standard.
 *
 * Type modifiers are always added at the end of list and the list is
 * always traversed from head to tail.
 */

/* type_Construct - allocate and initialize a type_t. */

static type_t *
type_Construct(void) {
	type_t	*tp = malloc(sizeof (type_t));

	assert(tp != NULL);

	tp->t_next = NULL;			/* generic */
	tp->t_dt = DD_NONE;

	tp->t_nargs = 0;			/* DD_FUN */
	tp->t_ellipsis = 0;
	tp->t_args = NULL;
						/* DD_PTR */
	tp->t_stt	 = (SCS_NONE | TS_NO_TS | TQ_NONE);

	tp->t_sizestr = NULL;			/* DD_ARY */
#if defined(MEM_DEBUG)
	++type_Construct_calls;
#endif
	return (tp);
}

/* type_Destroy - free a type_t list. */

static void
type_Destroy(type_t *tp) {
	while (tp) {
		type_t	*nextp = tp->t_next;

		switch (tp->t_dt) {
		case DD_FUN:
			decl_Destroy(tp->t_args);
			break;

		case DD_PTR:
			break;

		case DD_ARY:
			free(tp->t_sizestr);
			break;
		}

		free(tp);

		tp = nextp;
#if defined(MEM_DEBUG)
		--type_Construct_calls;
#endif
	}
}

/*
 * type_SetPtr - make a type_t into a "pointer to ..." variant.
 *
 * Note:
 *	1) The stt_t will encode any type qualifiers (const, volatile).
 */

static type_t *
type_SetPtr(type_t *tp, stt_t s) {
	assert(tp->t_dt == DD_NONE);

	tp->t_dt = DD_PTR;
	tp->t_stt = s & TQ_MASK;

	return (tp);
}

/*
 * type_SetAry - make a type_t into an "array of ...", variant.
 *
 * Note:
 *	1) The array dimension can be NULL to indicate undefined, i.e. [].
 */

static type_t *
type_SetAry(type_t *tp, char *dim) {
	assert(tp->t_dt == DD_NONE);
	assert(tp->t_sizestr == NULL);

	tp->t_dt = DD_ARY;

	if (dim) {
		tp->t_sizestr = strdup(dim);
		assert(tp->t_sizestr != NULL);
	} else
		tp->t_sizestr = NULL;

	return (tp);
}

/*
 * type_SetFun - make a type_t into a "function returning ..." variant.
 *
 * Note:
 *	1) The argument list can be NULL to indicate undefined, i.e. ().
 */

static type_t *
type_SetFun(type_t *tp, decl_t *arglist) {
	assert(tp->t_dt == DD_NONE);

	tp->t_dt = DD_FUN;

	if (arglist) {
		tp->t_nargs = decl_GetArgLength(arglist);
		tp->t_args = arglist;
		tp->t_ellipsis = arglist->d_ellipsis;
	}

	return (tp);
}

/*
 * type_AddTail - add a type_t to the end of an existing type_t list.
 *
 * Note:
 *	1) The type_t *tp is added to the end of the type_t *dp list.
 */

static type_t *
type_AddTail(type_t *dp, type_t *tp) {
	type_t	*lastp = dp;
	type_t	*p;

	while (p = lastp->t_next)
		lastp = p;

	lastp->t_next = tp;

	return (dp);
}

#if defined(DEBUG)

/* type_PrintType - print a type_t list onto standard output. */

static void
type_PrintType(type_t *tp, int lvl) {
	decl_spec_t	tmp;
	char		buf[BUFSIZ];

	while (tp) {
		putNTabs(lvl);

		switch (tp->t_dt) {
		case DD_PTR:
			tmp.ds_stt = tp->t_stt;
			tmp.ds_id = NULL;

			printf("[%s] ptr to\n", declspec_ToString(buf, &tmp));
			break;

		case DD_FUN:
			printf("fun [%d%c] %s\n",
			    tp->t_nargs,
			    (tp->t_ellipsis)? '+' : '=',
			    (tp->t_args)? "with arguments" :
			    "undefined arguments");

			if (tp->t_args) {
				decl_PrintDecl(tp->t_args, lvl + 1);

				if (tp->t_ellipsis) {
					putNTabs(lvl + 1);
					printf("...\n");
				}
			}
			break;

		case DD_ARY:
			printf("ary [%s] of\n",
			    (tp->t_sizestr)? tp->t_sizestr : "");
			break;
		}

		tp = tp->t_next;
	}
}
#endif	/* DEBUG */

/*
 * type_Verify - verify a type_t list for semantic correctness.
 *
 * Note:
 *	1) C supports most combinations of type modifiers.
 *	   It does not support three combinations, they are:
 *
 *		function returning array
 *		array of functions
 *		function returning function
 *
 *	2) The enum values associated with type modifiers (i.e. DD_*)
 *	   cannot be modified without changing the table included within the
 *	   function.
 *
 * 	3) The function returns NULL to indicate that the type modifier
 *	   list is valid and non-NULL to indicate an error.
 *
 *	4) A type_t of NULL is permitted to indicate an empty type_t list.
 */

static const char *
type_Verify(type_t *tp) {
	static const char *dttbl[4][4] = {
		/* NONE	ARY	FUN	PTR */
/* NONE */	{NULL,	NULL,	NULL,	NULL},
/* ARY */	{NULL,	NULL,	"array of functions", NULL},
/* FUN */	{NULL,	"function returning array",
		    "function returning function", NULL},
/* PTR */	{NULL,	NULL,	NULL,	NULL},
	};

	if (tp) {
		type_t	*nextp;

		do {
			const char	*p;
			decl_type_t	 nt;

			nt = (nextp = tp->t_next)? nextp->t_dt : DD_NONE;

			if ((p = dttbl[tp->t_dt][nt]) != NULL)
				return (p);

		} while (tp = nextp);
	}

	return (NULL);
}

/* type_GetNext - return the next type_t in the list. */

type_t *
type_GetNext(type_t *tp) {
	return (tp->t_next);
}

/*
 * The following group of functions return and or
 * test various aspects of type modifiers.
 *
 * 1) The three functions: type_IsPtrTo, type_IsFunction and
 *    type_IsArray will accept an argument of NULL.
 *
 * 2) All other functions require one of the above three to be true.
 *    Various asserts are in place to verify correct usage.
 */

int
type_IsArray(type_t *tp) {
	return (tp && (tp->t_dt == DD_ARY));
}

char *
type_GetArraySize(type_t *tp) {
	assert(tp->t_dt == DD_ARY);

	return (tp->t_sizestr);
}

int
type_IsPtrTo(type_t *tp) {
	return (tp && (tp->t_dt == DD_PTR));
}

stt_t
type_GetPtrToTypeQual(type_t *tp) {
	assert(tp->t_dt == DD_PTR);

	return (tp->t_stt);
}

int
type_IsFunction(type_t *tp) {
	return (tp && (tp->t_dt == DD_FUN));
}

int
type_GetArgLength(type_t *tp) {
	assert(tp->t_dt == DD_FUN);

	return (tp->t_nargs);
}

int
type_IsVarargs(type_t *tp) {
	while (tp && tp->t_dt == DD_PTR)
		tp = tp->t_next;

	assert(tp->t_dt == DD_FUN);

	return (tp->t_ellipsis);
}

decl_t *
type_GetArg(type_t *tp) {
	assert(tp->t_dt == DD_FUN);

	return (tp->t_args);
}

/*
 * type_IsPtrFun - determine if the type_t results in a call-able function.
 *
 * Note:
 *	1) The argument can be NULL.
 *
 *	2) The test is true if the type_t list is number of DD_PTR followed
 *	by a DD_FUN.
 */

int
type_IsPtrFun(type_t *tp) {

	if (! (tp && (tp->t_dt == DD_PTR)))
		return (0);

	tp = tp->t_next;

	while (tp && (tp->t_dt == DD_PTR))
		tp = tp->t_next;

	return (tp && (tp->t_dt == DD_FUN));
}

/* D E C L A R A T O R */

/*
 * A decl_t encodes the name,
 * declaration specifiers and type modifiers of an object.
 */

/* decl_Construct - allocate a decl_t. */

static decl_t *
decl_Construct(void) {
	decl_t	*dp = malloc(sizeof (decl_t));

	assert(dp != NULL);

	dp->d_name = NULL;
	dp->d_type = NULL;
	dp->d_next = NULL;
	dp->d_ds = declspec_Construct();
	dp->d_ellipsis = 0;
#if defined(MEM_DEBUG)
	++decl_Construct_calls;
#endif
	return (dp);
}

/* decl_Destroy - free a decl_t list. */

void
decl_Destroy(decl_t *dp) {
	while (dp) {
		decl_t	*nextp = dp->d_next;

		type_Destroy(dp->d_type);
		declspec_Destroy(dp->d_ds);
		free(dp->d_name);
		free(dp);

		dp = nextp;
#if defined(MEM_DEBUG)
		--decl_Construct_calls;
#endif
	}
}

/*
 * decl_GetArgLength - return the length of a decl_t list.
 *
 * Note:
 *	1) The argument may be NULL to indicate an empty list, len == 0.
 */

int
decl_GetArgLength(decl_t *dp) {
	int	len;

	for (len = 0; dp; dp = dp->d_next)
		++len;

	return (len);
}

/*
 * The following group of functions get or test various aspects of a decl_t.
 */

decl_t *
decl_GetNext(decl_t *dp) {
	return (dp->d_next);
}

stt_t
decl_GetDeclSpec(decl_t *dp) {
	return (declspec_GetSTT(dp->d_ds));
}

char *
decl_GetDSName(decl_t *dp) {
	return (declspec_GetTag(dp->d_ds));
}

type_t *
decl_GetType(decl_t *dp) {
	return (dp->d_type);
}

int
decl_IsVarargs(decl_t *dp) {
	return (dp->d_ellipsis);
}

int
decl_IsFunction(decl_t *dp) {
	return (type_IsFunction(dp->d_type));
}

char *
decl_GetName(decl_t *dp) {
	return (dp->d_name);
}

/*
 * decl_AddArg - add a decl_t to the end of an decl_t list.
 */

static decl_t *
decl_AddArg(decl_t *dp, decl_t *tp) {
	decl_t	*lastp = dp;
	decl_t	*p;

	while (p = lastp->d_next)
		lastp = p;

	lastp->d_next = tp;

	return (dp);
}

/*
 * decl_IsVoid - return true if the decl_t is a "pure" void declaration.
 */

static int
decl_IsVoid(decl_t *dp) {
	return ((declspec_GetSTT(dp->d_ds) & TS_VOID) && (dp->d_type == NULL));
}

/*
 * decl_IsVoidArray - return true if the decl_t includes "void []".
 */

static int
decl_IsVoidArray(decl_t *dp) {
	int	 retval = 0;
	type_t	*tp = dp->d_type;

	if (tp) {
		type_t	*np;

		while (np = type_GetNext(tp))
			tp = np;

		retval = type_IsArray(tp) &&
		    (declspec_GetSTT(dp->d_ds) & TS_VOID);
	}

	return (retval);
}

/*
 * decl_Verify - verify a decl_t.
 */

static const char *
decl_Verify(decl_t *dp) {
	const char	*ep = NULL;

	if (decl_IsVoid(dp))
		ep = "type is void";
	else if (decl_IsVoidArray(dp))
		ep = "type is void []";
	else
		ep = type_Verify(dp->d_type);

	return (ep);
}

/*
 * decl_VerifyArgs - verify a decl_t list.
 */

static const char *
decl_VerifyArgs(decl_t *dp) {
	decl_t		*tp = dp;
	const char	*ep = NULL;

	if (dp) {
		int	 nv = 0;
		int	 nargs = decl_GetArgLength(dp);

		for (; dp; dp = dp->d_next)
			if (decl_IsVoid(dp)) {
				++nv;

				if (decl_GetName(dp))
					ep = "argument list includes "
					    "void with identifier";
			} else if (decl_IsVoidArray(dp))
				ep = "argument list includes void []";

		if (nv) {		/* there was some void */
			if (nargs > 1)
				ep = "argument list includes void";

			if (tp->d_ellipsis)
				ep = "argument list includes void and \"...\"";
		}
	}

	return (ep);
}

/* decl_AddDS - add a decl_spec_t to a decl_t. */

static decl_t *
decl_AddDS(decl_t *dp, decl_spec_t *dsp, const char **err) {
	declspec_AddDS(dp->d_ds, dsp, err);

	return (dp);
}

/*
 * decl_SetName - set the name associated with a decl_t.
 *
 * Note:
 *	1) Any previously known name is free'd.
 */

decl_t *
decl_SetName(decl_t *dp, char *s) {
	free(dp->d_name);
	dp->d_name = strdup(s);
	assert(dp->d_name != NULL);

	return (dp);
}

/*
 * decl_AddTypeTail - add a type_t to the end of a decl_t type_t list.
 */

static decl_t *
decl_AddTypeTail(decl_t *dp, type_t *tp) {
	if (dp->d_type)
		type_AddTail(dp->d_type, tp);
	else
		dp->d_type = tp;

	return (dp);
}

/*
 * decl_addptr - add a DD_PTR type_t to the end of a decl_t type_t list.
 */

static decl_t *
decl_addptr(decl_t *dp, type_t *tp) {
	decl_AddTypeTail(dp, tp);

	return (dp);
}

/*
 * decl_addary - allocate and add a DD_ARY type_t to the end of
 *	a decl_t type_t list.
 */

static decl_t *
decl_addary(decl_t *dp, char *sizep) {
	type_t	*tp = type_Construct();

	type_SetAry(tp, sizep);
	decl_AddTypeTail(dp, tp);

	return (dp);
}

/*
 * decl_addfun - allocate and add a DD_FUN type_t to the end of a
 *	 decl_t type_t list.
 */

static decl_t *
decl_addfun(decl_t *dp, decl_t *arglist) {
	const char	*sp;
	type_t	*tp = type_Construct();

	if (sp = decl_VerifyArgs(arglist))
		yyerror(sp);

	type_SetFun(tp, arglist);
	decl_AddTypeTail(dp, tp);

	return (dp);
}

/*
 * decl_addellipsis - set the ellipsis state in a decl_t.
 *
 * Note:
 *	1) This function is only used in the grammar in the
 *	   parameter list parsing.
 */

static decl_t *
decl_addellipsis(decl_t *dp) {
	dp->d_ellipsis = 1;

	return (dp);
}

#if defined(DEBUG)

static void
decl_PrintDecl(decl_t *dp, int lvl) {
	char	buf[BUFSIZ];

	while (dp) {
		putNTabs(lvl);

		printf("name = %s, ds = %s\n",
				(dp->d_name)? dp->d_name : "<null>",
				declspec_ToString(buf, dp->d_ds));

		if (dp->d_type)
			type_PrintType(dp->d_type, lvl + 1);

		dp = dp->d_next;
	}
}
#endif	/* DEBUG */

static char *
char_getend(char *s) {
	while (*s != '\0')
		++s;

	return (s);
}

char *
decl_ToString(char *bufp, decl_dts_t out, decl_t *dp,
    const char *altname) {
	char	 tmp[BUFSIZ];
	char	 tmp2[BUFSIZ];
	const char *namep;
	char	*bend = bufp;
	type_t	*tp = dp->d_type;
	int ffun = 1;

	switch (out) {
	default:
		out = DTS_DECL;
		/* FALLTHRU */
	case DTS_DECL:
		if (altname == NULL) {
			namep = dp->d_name;
		} else {
			namep = altname;
		}
		break;
	case DTS_CAST:
		namep = "(*)";
		break;
	case DTS_RET:
		if (altname == NULL) {
			namep = "_return";
		} else {
			namep = altname;
		}
		break;
	}

	*bufp = '\0';

	strcpy(tmp, (namep) ? namep : "");

	while (tp) {
		switch (tp->t_dt) {
		case DD_PTR:
			if (tp->t_next &&
			    ((tp->t_next->t_dt == DD_ARY) ||
			    (tp->t_next->t_dt == DD_FUN))) {
				if (out == DTS_RET) {
					sprintf(bufp, "(*%s)", namep);
				} else {
					sprintf(bufp, "(*%s)", tmp);
				}
			} else if (tp->t_stt == TQ_CONST) {
				sprintf(bufp, "*const %s", tmp);
			} else if (tp->t_stt == TQ_VOLATILE) {
				sprintf(bufp, "*volatile %s", tmp);
			/*
			 * It currently acknowledges and ignores restrict
			 * or _RESTRICT_KYWD in code generation because
			 * of the uncertain behavior of "restrict".
			 */
			} else if (tp->t_stt == TQ_RESTRICT) {
				sprintf(bufp, "*%s", tmp);
			} else if (tp->t_stt == TQ_RESTRICT_KYWD) {
				sprintf(bufp, "*%s", tmp);
			} else {
				sprintf(bufp, "*%s", tmp);
			}

			break;

		case DD_ARY:
			sprintf(bufp, "%s[%s]",
			    tmp, (tp->t_sizestr)? tp->t_sizestr : "");
			break;

		case DD_FUN:
			if (out == DTS_RET && ffun == 1) {
				strcpy(bufp, namep);
				ffun = 0;
			} else if (tp->t_args == NULL) {
				sprintf(bufp, "%s()", tmp);
			} else {
				char	 buf2[BUFSIZ];
				decl_t	*argp = tp->t_args;

				sprintf(bufp, "%s(", tmp);
				bend = char_getend(bufp);

				for (argp = tp->t_args; argp; /* noinc */) {
					decl_ToString(buf2, DTS_DECL, argp,
					    NULL);
					sprintf(bend, " %s", buf2);

					bend = char_getend(bend);

					if (argp = argp->d_next) {
						sprintf(bend, ",");
						bend = char_getend(bend);
					}
				}

				if (tp->t_ellipsis) {
					sprintf(bend, ", ...");
					bend = char_getend(bend);
				}

				sprintf(bend, ")");
			}
			break;
		}

		tp = tp->t_next;

		strcpy(tmp, bufp);
	}

	if (out == DTS_CAST) {
		sprintf(bufp, "(%s %s)",
		    declspec_ToString(tmp2, dp->d_ds), tmp);
	} else {
		sprintf(bufp, "%s %s",
		    declspec_ToString(tmp2, dp->d_ds), tmp);
	}

	return (bufp);
}

decl_t *
decl_AddArgNames(decl_t *dp) {
	int	 argno = 0;
	decl_t	*p = dp;

	if (decl_IsFunction(dp)) {
		int	 argno = 0;
		decl_t	*p = dp->d_type->t_args;

		while (p) {
			char	*s = decl_GetName(p);

			if ((s == NULL) && !decl_IsVoid(p)) {
				char	buf[BUFSIZ];

				sprintf(buf, "arg%d", argno);
				s = strdup(buf);
				decl_SetName(p, s);
			}

			p = p->d_next;
			++argno;
		}
	}
	return (dp);
}

const char *
decl_Parse(char *str, decl_t **dpp) {
	errstr = NULL;	/* setup the (static) globals */
	input = str;
	atIDENT = 0;
	protop = NULL;

	yyparse();	/* parse the prototype */

	if (errstr == NULL) {		/* success */
		*dpp = protop;
		decl_AddArgNames(protop);
	} else {	/* failure */
		*dpp = NULL;
		decl_Destroy(protop);
	}

	return (errstr);
}

static void
yyerror(const char *err) {
	errstr = err;
}

#if defined(DEBUG)

/* main */

static int yydebug = 1;

int
main(int argc, char *argv[]) {
	int	i;

	yydebug = 1;

	for (i = 1; i < argc; ++i) {
		const char	*es;
		char		 buf[BUFSIZ];
		decl_t		*pp;

		if (es = decl_Parse(argv[i], &pp))
			printf("parse failure: %s\n", es);
		else {
#if GR_DEBUG
			decl_PrintDecl(pp, 0);
			decl_AddArgNames(pp);
#endif
			printf("---\n%s;\n",
			    decl_ToString(buf, DTS_DECL, pp, NULL));
			printf("%s\n",
			    decl_ToString(buf, DTS_CAST, pp, NULL));
			printf("%s;\n",
			    decl_ToString(buf, DTS_RET, pp, "%s"));

#ifdef TRACE
			printf("\n\nTrace Info\n");
			decl_PrintTraceInfo(pp);
#endif
		}

		decl_Destroy(pp);

#if defined(MEM_DEBUG)
		printf("declspec : %d\n", declspec_Construct_calls);
		printf("type     : %d\n", type_Construct_calls);
		printf("decl     : %d\n", decl_Construct_calls);
#endif
	}

	return (0);
}

#ifdef TRACE
void
decl_PrintTraceInfo(decl_t *dp) {
	char	buf[BUFSIZ];
	char	f_type[BUFSIZ];
	char	f_print[BUFSIZ];
	char	a_name[BUFSIZ];
	char	a_type[BUFSIZ];
	char	a_print[BUFSIZ];
	decl_t	*funargs;
	type_t	*tp;
	int	isptrfun;

	if (dp == NULL)
		return;

	fprintf(stderr, "interface = %s\n",
	    (dp->d_name) ? dp->d_name : "<null>");

	isptrfun = type_IsPtrFun(dp->d_type);
	if (type_IsFunction(dp->d_type) || isptrfun)
		decl_GetTraceInfo(dp, f_type, f_print, &funargs);
	else
		return;

	fprintf(stderr, "return type = %s\n", f_type);
	fprintf(stderr, "print function = %s\n", f_print);

	if (isptrfun)
		fprintf(stderr, "function is function pointer\n");

	if (type_IsVarargs(dp->d_type))
		fprintf(stderr, "function is varargs\n");

	while (funargs) {
		snprintf(a_type, BUFSIZ, "%s ",
		    declspec_ToString(buf, funargs->d_ds));
		snprintf(a_print, BUFSIZ, "%s",
		    de_const(declspec_ToString(buf, funargs->d_ds)));

		tp = funargs->d_type;

		while (tp) {
			if (tp->t_dt == DD_PTR || tp->t_dt == DD_ARY) {
				strcat(a_type, "*");
				strcat(a_print, "_P");
			}
			tp = tp->t_next;
		}

		if (funargs->d_name) {
			snprintf(a_name, BUFSIZ, "%s",
			    funargs->d_name ? funargs->d_name : "<nil>");
			fprintf(stderr, "arg name = %s\n", a_name);
			fprintf(stderr, "arg type = %s\n", a_type);
			fprintf(stderr, "print function = %s\n", a_print);
		} else {
			strcpy(a_name, "");
			strcpy(a_print, "");
			fprintf(stderr, "arg type = %s\n", a_type);
		}

		funargs = funargs->d_next;
	}
}
#endif	/* TRACE */
#endif	/* DEBUG */

static char *
de_const(char *str)
{
	return (str);
}


void
decl_GetTraceInfo(decl_t *dp, char *f_type, char *f_print, decl_t **funargs)
{
	char	buf[BUFSIZ];
	type_t	*tp;

	if (dp == NULL)
		return;

	snprintf(f_type, BUFSIZ, "%s ",
	    declspec_ToString(buf, dp->d_ds));
	snprintf(f_print, BUFSIZ, "%s",
	    de_const(declspec_ToString(buf, dp->d_ds)));
	tp = dp->d_type;
	while (tp) {
		if (tp->t_dt == DD_PTR) {
			strcat(f_type, "*");
			strcat(f_print, "*");
		}
		tp = tp->t_next;
	}

	strcat(f_type, "%s");

	tp = decl_GetType(dp);
	if (type_IsPtrFun(tp)) {
		while (tp->t_dt != DD_FUN)
			tp = tp->t_next;
		*funargs = tp->t_args;
	} else {
		*funargs = dp->d_type->t_args;
	}
}

char *
decl_ToFormal(decl_t *dp)
{
	char tmp[BUFSIZ];
	static char bufp[BUFSIZ];
	char *bend;
	type_t	*tp = dp->d_type;

	tmp[0] = 0;
	bufp[0] = 0;
	bend = bufp;

	while (tp) {
		switch (tp->t_dt) {
		case DD_ARY:
			sprintf(bufp, "%s[%s]", tmp,
			    (tp->t_sizestr)? tp->t_sizestr : "");
			break;

		case DD_FUN:
			if (tp->t_args != NULL) {
				char buf2[BUFSIZ];
				decl_t  *argp = tp->t_args;

				bend = char_getend(bufp);

				for (argp = tp->t_args; argp; /* noinc */) {
					decl_ToString(buf2, DTS_DECL, argp,
					    NULL);
					sprintf(bend, " %s", buf2);

					bend    = char_getend(bend);

					if (argp = argp->d_next) {
						sprintf(bend, ",");
						bend    = char_getend(bend);
					}
				}
				if (tp->t_ellipsis) {
					sprintf(bend, ", ...");
					bend    = char_getend(bend);
				}

				sprintf(bend, "");
			}
			break;
		}

		tp  = tp->t_next;

		strcpy(tmp, bufp);
	}

	sprintf(bufp, "%s", tmp);

	return (bufp);
}
