/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1986-2008 AT&T Intellectual Property          *
*                      and is licensed under the                       *
*                  Common Public License, Version 1.0                  *
*                    by AT&T Intellectual Property                     *
*                                                                      *
*                A copy of the License is available at                 *
*            http://www.opensource.org/licenses/cpl1.0.txt             *
*         (with md5 checksum 059e8cd6165cb4c31e351f2b69388fd9)         *
*                                                                      *
*              Information and Software Systems Research               *
*                            AT&T Research                             *
*                           Florham Park NJ                            *
*                                                                      *
*                 Glenn Fowler <gsf@research.att.com>                  *
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * Glenn Fowler
 * AT&T Research
 *
 * preprocessor and proto lexical analyzer fsm
 * define PROTOMAIN for standalone proto
 */

#include "pplib.h"
#include "ppfsm.h"

/*
 * lexical FSM encoding
 * derived from a standalone ansi cpp by Dennis Ritchie
 * modified for libpp by Glenn Fowler
 *
 *   fsm[] is initialized from fsminit[].  The encoding is blown out into
 *   fsm[] for time efficiency.  When in state state, and one of the
 *   characters in ch arrives, enter nextstate.  States >= TERMINAL are
 *   either final, or at least require special action.  In fsminit[] there
 *   is a line for each <state,charset,nextstate>.  Early entries are
 *   overwritten by later ones.  C_XXX is the universal set and should
 *   always be first.  Some of the fsminit[] entries are templates for
 *   groups of states.  The OP entries trigger the state copies.  States
 *   above TERMINAL are represented in fsm[] as negative values.  S_TOK and
 *   S_TOKB encode the resulting token type in the upper bits.  These actions
 *   differ in that S_TOKB has a lookahead char.
 *
 *   fsm[] has three start states:
 *
 *	PROTO	proto (ANSI -> K&R,C++,ANSI)
 *	QUICK	standalone ppcpp()
 *	TOKEN	tokenizing pplex()
 *
 *   If the next state remains the same then the fsm[] transition value is 0.
 *   MAX+1 is a power of 2 so that fsm[state][EOF==MAX+1] actually accesses
 *   fsm[state+1][0] which is ~S_EOB for all states.  This preserves the
 *   power of 2 fsm[] row size for efficient array indexing.  Thanks to
 *   D. G. Korn for the last two observations.  The pseudo non-terminal state
 *   fsm[TERMINAL][state+1] is used to differentiate EOB from EOF.
 *
 *   The bit layout is:
 *
 *	TERM	arg	SPLICE	next
 *	15	14-8	7	6-0
 */

/*
 * NOTE: these must be `control' characters for all native codesets
 *       currently ok for {ascii,ebcdic1,ebcdic2,ebcdic3}
 */

#define C_DEC		001
#define C_EOF		002
#define C_HEX		003
#define C_LET		021
#define C_OCT		022
#define C_XXX		023

#define OP		(-1)
#define END		0
#define COPY		1

#define copy(t,f)	(memcpy(&fsm[t][1],&fsm[f][1],(MAX+1)*sizeof(short)),fsm[TERMINAL][(t)+1]=fsm[TERMINAL][(f)+1])

struct fsminit				/* fsm initialization row	*/
{
	int		state;		/* if in this state		*/
	unsigned char	ch[4];		/* and see one of these		*/
	int		nextstate;	/* enter this state if <TERMINAL*/
};

static struct fsminit	fsminit[] =
{
	/* proto start state */
	{	PROTO,	{ C_XXX },		S_CHR,			},
	{	PROTO,	{ C_EOF },		S_EOF,			},
	{	PROTO,	{ C_DEC },		BAD1,			},
	{	PROTO,	{ '.' },		DOT,			},
	{	PROTO,	{ C_LET },		NID,			},
	{	PROTO,	{ 'L' },		LIT,			},
	{	PROTO,	{ 'd', 'e', 'f', 'i' },	RES1,			},
	{	PROTO,	{ 'r', 's', 't', 'v' },	RES1,			},
	{	PROTO,	{ 'w', 'N' },		RES1,			},
	{	PROTO,	{ '"', '\'' },		S_LITBEG,		},
	{	PROTO,	{ '/' },		COM1,			},
	{	PROTO,	{ '\n' },		S_NL,			},
	{	PROTO,	{ ' ','\t','\f','\v' },	WS1,			},

/* proto {do,else,extern,for,if,inline,return,static,typedef,va_start,void,while,NoN} */
	{	RES1,	{ C_XXX },		S_MACRO,		},
	{	RES1,	{ C_LET, C_DEC },	NID,			},
	{	RES1,	{ 'a' },		RES1a,			},
	{	RES1,	{ 'e' },		RES1e,			},
	{	RES1,	{ 'f' },		RES1f,			},
	{	RES1,	{ 'h' },		RES1h,			},
	{	RES1,	{ 'l' },		RES1l,			},
	{	RES1,	{ 'n' },		RES1n,			},
	{	RES1,	{ 'o' },		RES1o,			},
	{	RES1,	{ 't' },		RES1t,			},
	{	RES1,	{ 'x' },		RES1x,			},
	{	RES1,	{ 'y' },		RES1y,			},

	/* proto reserved {va_start} */
	{	RES1a,	{ C_XXX },		S_RESERVED,		},
	{	RES1a,	{ C_LET, C_DEC },	NID,			},
	{	RES1a,	{ '_','s','t','a' },	RES1a,			},
	{	RES1a,	{ 'r' },		RES1a,			},

	/* proto reserved {return} */
	{	RES1e,	{ C_XXX },		S_RESERVED,		},
	{	RES1e,	{ C_LET, C_DEC },	NID,			},
	{	RES1e,	{ 't','u','r','n' },	RES1e,			},

	/* proto reserved {if} */
	{	RES1f,	{ C_XXX },		S_RESERVED,		},
	{	RES1f,	{ C_LET, C_DEC },	NID,			},

	/* proto reserved {while} */
	{	RES1h,	{ C_XXX },		S_RESERVED,		},
	{	RES1h,	{ C_LET, C_DEC },	NID,			},
	{	RES1h,	{ 'i','l','e' },	RES1h,			},

	/* proto reserved {else} */
	{	RES1l,	{ C_XXX },		S_RESERVED,		},
	{	RES1l,	{ C_LET, C_DEC },	NID,			},
	{	RES1l,	{ 's','e' },		RES1l,			},

	/* proto reserved {inline} */
	{	RES1n,	{ C_XXX },		S_RESERVED,		},
	{	RES1n,	{ C_LET, C_DEC },	NID,			},
	{	RES1n,	{ 'l','i','n','e' },	RES1n,			},

	/* proto reserved {do,for,void} */
	{	RES1o,	{ C_XXX },		S_RESERVED,		},
	{	RES1o,	{ C_LET, C_DEC },	NID,			},
	{	RES1o,	{ 'r','i','d','N' },	RES1o,			},

	/* proto reserved {static} */
	{	RES1t,	{ C_XXX },		S_RESERVED,		},
	{	RES1t,	{ C_LET, C_DEC },	NID,			},
	{	RES1t,	{ 'a','t','i','c' },	RES1t,			},

	/* proto reserved {extern} */
	{	RES1x,	{ C_XXX },		S_RESERVED,		},
	{	RES1x,	{ C_LET, C_DEC },	NID,			},
	{	RES1x,	{ 't','e','r','n' },	RES1x,			},

	/* proto reserved {typedef} */
	{	RES1y,	{ C_XXX },		S_RESERVED,		},
	{	RES1y,	{ C_LET, C_DEC },	NID,			},
	{	RES1y,	{ 'p','e','d','f' },	RES1y,			},

	/* saw /, perhaps start of comment */
	{	COM1,	{ C_XXX },		S_CHRB,			},
	{	COM1,	{ '*' },		COM2,			},
#if PROTOMAIN
	{	COM1,	{ '/' },		COM5,			},
#endif

	/* saw / *, start of comment */
	{	COM2,	{ C_XXX },		COM2,			},
	{	COM2,	{ '\n', C_EOF },	S_COMMENT,		},
	{	COM2,	{ '/' },		COM4,			},
	{	COM2,	{ '*' },		COM3,			},
	{	COM2,	{ '#', ';', ')' },	QUAL(COM2),		},

	/* saw the * possibly ending a comment */
	{	COM3,	{ C_XXX },		COM2,			},
	{	COM3,	{ '\n', C_EOF },	S_COMMENT,		},
	{	COM3,	{ '#', ';', ')' },	QUAL(COM2),		},
	{	COM3,	{ '*' },		COM3,			},
	{	COM3,	{ '/' },		S_COMMENT,		},

	/* saw / in / * comment, possible malformed nest */
	{	COM4,	{ C_XXX },		COM2,			},
	{	COM4,	{ '*', '\n', C_EOF },	S_COMMENT,		},
	{	COM4,	{ '/' },		COM4,			},

	/* saw / /, start of comment */
	{	COM5,	{ C_XXX },		COM5,			},
	{	COM5,	{ '\n', C_EOF },	S_COMMENT,		},
	{	COM5,	{ '/' },		COM6,			},
	{	COM5,	{ '*' },		COM7,			},

	/* saw / in / / comment, possible malformed nest */
	{	COM6,	{ C_XXX },		COM5,			},
	{	COM6,	{ '*', '\n', C_EOF },	S_COMMENT,		},
	{	COM6,	{ '/' },		COM6,			},

	/* saw * in / /, possible malformed nest */
	{	COM7,	{ C_XXX },		COM5,			},
	{	COM7,	{ '\n', C_EOF },	S_COMMENT,		},
	{	COM7,	{ '*' },		COM7,			},
	{	COM7,	{ '/' },		S_COMMENT,		},

	/* normal identifier -- always a macro candidate */
	{	NID,	{ C_XXX },		S_MACRO,		},
	{	NID,	{ C_LET, C_DEC },	NID,			},

	/* saw ., operator or dbl constant */
	{	DOT,	{ C_XXX },		S_CHRB,			},
	{	DOT,	{ '.' },		DOT2,			},
	{	DOT,	{ C_DEC },		BAD1,			},

	/* saw .., possible ... */
	{	DOT2,	{ C_XXX },		BACK(T_INVALID),	},
	{	DOT2,	{ '.' },		KEEP(T_VARIADIC),	},

	/* saw L (possible start of normal wide literal) */
	{	LIT,	{ C_XXX },		S_MACRO,		},
	{	LIT,	{ C_LET, C_DEC },	NID,			},
	{	LIT,	{ '"', '\'' },		QUAL(LIT1),		},

	/* saw " or ' beginning literal */
	{	LIT1,	{ C_XXX },		LIT1,			},
	{	LIT1,	{ '"', '\'' },		S_LITEND,		},
	{	LIT1,	{ '\n', C_EOF },	S_LITEND,		},
	{	LIT1,	{ '\\' },		LIT2,			},

	/* saw \ in literal */
	{	LIT2,	{ C_XXX },		S_LITESC,		},
	{	LIT2,	{ '\n', C_EOF },	S_LITEND,		},

	/* eat malformed numeric constant */
	{	BAD1,	{ C_XXX },		BACK(T_INVALID),	},
	{	BAD1,	{ C_LET, C_DEC, '.' },	BAD1,			},
	{	BAD1,	{ 'e', 'E' },		BAD2,			},

	/* eat malformed numeric fraction|exponent */
	{	BAD2,	{ C_XXX },		BACK(T_INVALID),	},
	{	BAD2,	{ C_LET, C_DEC, '.' },	BAD1,			},
	{	BAD2,	{ '+', '-' },		BAD1,			},

	/* saw white space, eat it up */
	{	WS1,	{ C_XXX },		S_WS,			},
	{	WS1,	{ ' ', '\t' },		WS1,			},
	{	WS1,	{ '\f', '\v' },		S_VS,			},

#if !PROTOMAIN

	/* quick template */
	{	QUICK,	{ C_XXX },		QTOK,			},
	{	QUICK,	{ C_EOF, MARK },	S_CHRB,			},
	{	QUICK,	{ C_LET, C_DEC },	QID,			},
	{	QUICK,	{ 'L' },		LIT0,			},
	{	QUICK,	{ '"', '\'' },		S_LITBEG,		},
	{	QUICK,	{ '/' },		S_CHRB,			},
	{	QUICK,	{ '*' },		QCOM,			},
	{	QUICK,	{ '#' },		SHARP1,			},
	{	QUICK,	{ '\n' },		S_NL,			},
	{	QUICK,	{ '\f', '\v' },		S_VS,			},

	/* copy QUICK to QUICK+1 through MAC0+1 */
	{	OP,	{QUICK,QUICK+1,MAC0+1},	COPY,			},

	/* quick start state */
	{	QUICK,	{ C_EOF },		S_EOF,			},
	{	QUICK,	{ C_DEC },		QNUM,			},
	{	QUICK,	{ MARK },		QTOK,			},
	{	QUICK,	{ '/' },		COM1,			},
	{	QUICK,	{ ' ', '\t' },		QUICK,			},

	/* grab non-macro tokens */
	{	QTOK,	{ C_DEC },		QNUM,			},

	/* grab numeric and invalid tokens */
	{	QNUM,	{ C_LET, C_DEC, '.' },	QNUM,			},
	{	QNUM,	{ 'e', 'E' },		QEXP,			},

	/* grab exponent token */
	{	QEXP,	{ C_LET, C_DEC, '.' },	QNUM,			},
	{	QEXP,	{ '+', '-' },		QNUM,			},

	/* saw *, grab possible bad comment terminator */
	{	QCOM,	{ C_DEC },		QNUM,			},
	{	QCOM,	{ '/' },		S_COMMENT,		},

	/* saw L (possible start of wide string or first macro char) */
	{	MAC0,	{ 'L' },		QID,			},
	{	MAC0,	{ '"', '\'' },		QUAL(LIT1),		},

	/* macro candidate template */
	{	MAC0+1,	{ 'L' },		QID,			},

	/* copy MAC0+1 to MAC0+2 through MACN */
	{	OP,	{MAC0+1,MAC0+2,MACN},	COPY			},

	/* saw L (possible start of wide string or macro L) */
	{	HIT0,	{ C_XXX },		S_MACRO,		},
	{	HIT0,	{ C_LET, C_DEC },	QID,			},
	{	HIT0,	{ '"', '\'' },		QUAL(LIT1),		},

	/* macro hit template */
	{	HIT0+1,	{ C_XXX },		S_MACRO,		},
	{	HIT0+1,	{ C_LET, C_DEC },	QID,			},

	/* copy HIT0+1 to HIT0+2 through HITN */
	{	OP,	{HIT0+1,HIT0+2,HITN},	COPY			},

	/* saw L (possible start of wide literal) */
	{	LIT0,	{ C_XXX },		S_MACRO,		},
	{	LIT0,	{ C_LET, C_DEC },	QID,			},
	{	LIT0,	{ '"', '\'' },		QUAL(LIT1),		},

	/* (!PROTOMAIN COM1) saw /, perhaps start of comment or /= */
	{	COM1,	{ '=' },		KEEP(T_DIVEQ),		},

	/* normal start state */
	{	TOKEN,	{ C_XXX },		S_HUH,			},
	{	TOKEN,	{ C_EOF },		S_EOF,			},
	{	TOKEN,	{ C_DEC },		DEC1,			},
	{	TOKEN,	{ '0' },		OCT1,			},
	{	TOKEN,	{ '.' },		DOT1,			},
	{	TOKEN,	{ C_LET },		NID,			},
	{	TOKEN,	{ 'L' },		LIT,			},
	{	TOKEN,	{ '"', '\'', '<' },	S_LITBEG,		},
	{	TOKEN,	{ '/' },		COM1,			},
	{	TOKEN,	{ '\n' },		S_NL,			},
	{	TOKEN,	{ ' ', '\t' },		WS1,			},
	{	TOKEN,	{ '\f', '\v' },		S_VS,			},
	{	TOKEN,	{ '#' },		SHARP1,			},
	{	TOKEN,	{ ':' },		COLON1,			},
	{	TOKEN,	{ '%' },		PCT1,			},
	{	TOKEN,	{ '&' },		AND1,			},
	{	TOKEN,	{ '*' },		STAR1,			},
	{	TOKEN,	{ '+' },		PLUS1,			},
	{	TOKEN,	{ '-' },		MINUS1,			},
	{	TOKEN,	{ '=' },		EQ1,			},
	{	TOKEN,	{ '!' },		NOT1,			},
	{	TOKEN,	{ '>' },		GT1,			},
	{	TOKEN,	{ '^' },		CIRC1,			},
	{	TOKEN,	{ '|' },		OR1,			},
	{	TOKEN,	{ '(', ')', '[', ']' },	S_CHR,			},
	{	TOKEN,	{ '{', '}', ',', ';' },	S_CHR,			},
	{	TOKEN,	{ '~', '?' },		S_CHR,			},

	/* saw 0, possible oct|hex|dec|dbl constant */
	{	OCT1,	{ C_XXX },		BACK(T_DECIMAL),	},
	{	OCT1,	{ C_LET, C_DEC },	BAD1,			},
	{	OCT1,	{ C_OCT },		OCT2,			},
	{	OCT1,	{ 'e', 'E' },		DBL2,			},
	{	OCT1,	{ 'l', 'L', 'u', 'U' },	QUAL(DEC2),		},
	{	OCT1,	{ 'x', 'X' },		HEX1,			},
	{	OCT1,	{ '.' },		DBL1,			},

	/* saw 0<oct>, oct constant */
	{	OCT2,	{ C_XXX },		BACK(T_OCTAL),		},
	{	OCT2,	{ C_LET, C_DEC },	BAD1,			},
	{	OCT2,	{ C_OCT },		OCT2,			},
	{	OCT2,	{ 'e', 'E' },		DBL2,			},
	{	OCT2,	{ 'l', 'L', 'u', 'U' },	QUAL(OCT3),		},
	{	OCT2,	{ '.' },		DBL1,			},

	/* oct constant qualifier */
	{	OCT3,	{ C_XXX },		BACK(T_OCTAL),		},
	{	OCT3,	{ C_LET, C_DEC, '.' },	BAD1,			},
	{	OCT3,	{ 'l', 'L', 'u', 'U' },	QUAL(OCT3),		},

	/* saw 0 [xX], hex constant */
	{	HEX1,	{ C_XXX },		BACK(T_HEXADECIMAL),	},
	{	HEX1,	{ C_LET },		BAD1,			},
	{	HEX1,	{ C_HEX },		HEX1,			},
	{	HEX1,	{ 'e', 'E' },		HEX3,			},
	{	HEX1,	{ 'l', 'L', 'u', 'U' },	QUAL(HEX2),		},
	{	HEX1,	{ '.' },		HEX4,			},
	{	HEX1,	{ 'p', 'P' },		HEX5,			},

	/* hex constant qualifier */
	{	HEX2,	{ C_XXX },		BACK(T_HEXADECIMAL),	},
	{	HEX2,	{ C_LET, C_DEC, '.' },	BAD1,			},
	{	HEX2,	{ 'l', 'L', 'u', 'U' },	QUAL(HEX2),		},

	/* hex [eE][-+] botch */
	{	HEX3,	{ C_XXX },		BACK(T_HEXADECIMAL),	},
	{	HEX3,	{ C_LET, '.', '-', '+'},BAD1,			},
	{	HEX3,	{ C_HEX },		HEX1,			},
	{	HEX3,	{ 'e', 'E' },		HEX3,			},
	{	HEX3,	{ 'l', 'L', 'u', 'U' },	QUAL(HEX2),		},

	/* hex dbl fraction */
	{	HEX4,	{ C_XXX },		BACK(T_HEXDOUBLE),	},
	{	HEX4,	{ C_LET, '.' },		BAD1,			},
	{	HEX4,	{ C_HEX },		HEX4,			},
	{	HEX4,	{ 'p', 'P' },		HEX5,			},
	{	HEX4,	{ 'f', 'F', 'l', 'L' },	QUAL(HEX8),		},

	/* optional hex dbl exponent sign */
	{	HEX5,	{ C_XXX },		BACK(T_INVALID),	},
	{	HEX5,	{ C_LET, '.' },		BAD1,			},
	{	HEX5,	{ '+', '-' },		HEX6,			},
	{	HEX5,	{ C_DEC },		HEX7,			},

	/* mandatory hex dbl exponent first digit */
	{	HEX6,	{ C_XXX },		BACK(T_INVALID),	},
	{	HEX6,	{ C_LET, '.' },		BAD1,			},
	{	HEX6,	{ C_DEC },		HEX7,			},

	/* hex dbl exponent digits */
	{	HEX7,	{ C_XXX },		BACK(T_HEXDOUBLE),	},
	{	HEX7,	{ C_LET, '.' },		BAD1,			},
	{	HEX7,	{ C_DEC },		HEX7,			},
	{	HEX7,	{ 'f', 'F', 'l', 'L' },	QUAL(HEX8),		},

	/* hex dbl constant qualifier */
	{	HEX8,	{ C_XXX },		BACK(T_HEXDOUBLE),	},
	{	HEX8,	{ C_LET, '.' },		BAD1,			},
	{	HEX8,	{ 'f', 'F', 'l', 'L' },	QUAL(HEX8),		},

	/* saw <dec>, dec constant */
	{	DEC1,	{ C_XXX },		BACK(T_DECIMAL),	},
	{	DEC1,	{ C_LET },		BAD1,			},
	{	DEC1,	{ C_DEC },		DEC1,			},
	{	DEC1,	{ 'e', 'E' },		DBL2,			},
	{	DEC1,	{ 'l', 'L', 'u', 'U' },	QUAL(DEC2),		},
	{	DEC1,	{ '.' },		DBL1,			},

	/* dec constant qualifier */
	{	DEC2,	{ C_XXX },		BACK(T_DECIMAL),	},
	{	DEC2,	{ C_LET, C_DEC },	BAD1,			},
	{	DEC2,	{ 'l', 'L', 'u', 'U' },	QUAL(DEC2),		},

	/* saw ., operator or dbl constant */
	{	DOT1,	{ C_XXX },		S_CHRB,			},
	{	DOT1,	{ '.' },		DOT2,			},
	{	DOT1,	{ C_DEC },		DBL1,			},

	/* dbl fraction */
	{	DBL1,	{ C_XXX },		BACK(T_DOUBLE),		},
	{	DBL1,	{ C_LET, '.' },		BAD1,			},
	{	DBL1,	{ C_DEC },		DBL1,			},
	{	DBL1,	{ 'e', 'E' },		DBL2,			},
	{	DBL1,	{ 'f', 'F', 'l', 'L' },	QUAL(DBL5),		},

	/* optional dbl exponent sign */
	{	DBL2,	{ C_XXX },		BACK(T_INVALID),	},
	{	DBL2,	{ C_LET, '.' },		BAD1,			},
	{	DBL2,	{ '+', '-' },		DBL3,			},
	{	DBL2,	{ C_DEC },		DBL4,			},

	/* mandatory dbl exponent first digit */
	{	DBL3,	{ C_XXX },		BACK(T_INVALID),	},
	{	DBL3,	{ C_LET, '.' },		BAD1,			},
	{	DBL3,	{ C_DEC },		DBL4,			},

	/* dbl exponent digits */
	{	DBL4,	{ C_XXX },		BACK(T_DOUBLE),		},
	{	DBL4,	{ C_LET, '.' },		BAD1,			},
	{	DBL4,	{ C_DEC },		DBL4,			},
	{	DBL4,	{ 'f', 'F', 'l', 'L' },	QUAL(DBL5),		},

	/* dbl constant qualifier */
	{	DBL5,	{ C_XXX },		BACK(T_DOUBLE),		},
	{	DBL5,	{ C_LET, '.' },		BAD1,			},
	{	DBL5,	{ 'f', 'F', 'l', 'L' },	QUAL(DBL5),		},

	/* saw < starting include header */
	{	HDR1,	{ C_XXX },		HDR1,			},
	{	HDR1,	{ '>', '\n', C_EOF },	S_LITEND,		},

	/* saw <binop><space> expecting = */
	{	BIN1,	{ C_XXX },		S_HUH,			},
	{	BIN1,	{ ' ', '\t' },		BIN1,			},

	/* 2-char ops */

	{	SHARP1,	{ C_XXX },		S_SHARP,		},

	{	PCT1,	{ C_XXX },		S_CHRB,			},
	{	PCT1,	{ '=' },		KEEP(T_MODEQ),		},

	{	AND1,	{ C_XXX },		S_CHRB,			},
	{	AND1,	{ '=' },		KEEP(T_ANDEQ),		},
	{	AND1,	{ '&' },		KEEP(T_ANDAND),		},

	{	STAR1,	{ C_XXX },		S_CHRB,			},
	{	STAR1,	{ '=' },		KEEP(T_MPYEQ),		},
	{	STAR1,	{ '/' },		S_COMMENT,		},

	{	PLUS1,	{ C_XXX },		S_CHRB,			},
	{	PLUS1,	{ '=' },		KEEP(T_ADDEQ),		},
	{	PLUS1,	{ '+' },		KEEP(T_ADDADD),		},

	{	MINUS1,	{ C_XXX },		S_CHRB,			},
	{	MINUS1,	{ '=' },		KEEP(T_SUBEQ),		},
	{	MINUS1,	{ '-' },		KEEP(T_SUBSUB),		},
	{	MINUS1,	{ '>' },		KEEP(T_PTRMEM),		},

	{	COLON1,	{ C_XXX },		S_CHRB,			},
	{	COLON1,	{ '=', '>' },		S_HUH,			},

	{	LT1,	{ C_XXX },		S_CHRB,			},
	{	LT1,	{ '=' },		KEEP(T_LE),		},
	{	LT1,	{ '<' },		LSH1,			},

	{	EQ1,	{ C_XXX },		S_CHRB,			},
	{	EQ1,	{ '=' },		KEEP(T_EQ),		},

	{	NOT1,	{ C_XXX },		S_CHRB,			},
	{	NOT1,	{ '=' },		KEEP(T_NE),		},

	{	GT1,	{ C_XXX },		S_CHRB,			},
	{	GT1,	{ '=' },		KEEP(T_GE),		},
	{	GT1,	{ '>' },		RSH1,			},

	{	CIRC1,	{ C_XXX },		S_CHRB,			},
	{	CIRC1,	{ '=' },		KEEP(T_XOREQ),		},

	{	OR1,	{ C_XXX },		S_CHRB,			},
	{	OR1,	{ '=' },		KEEP(T_OREQ),		},
	{	OR1,	{ '|' },		KEEP(T_OROR),		},

	/* 3-char ops */

	{	ARROW1,	{ C_XXX },		BACK(T_PTRMEM),		},
	{	ARROW1,	{ '*' },		KEEP(T_PTRMEMREF),	},

	{	LSH1,	{ C_XXX },		BACK(T_LSHIFT),		},
	{	LSH1,	{ '=' },		KEEP(T_LSHIFTEQ),	},

	{	RSH1,	{ C_XXX },		BACK(T_RSHIFT),		},
	{	RSH1,	{ '=' },		KEEP(T_RSHIFTEQ),	},

#endif

	/* end */
	{	OP,	{ 0 },			END,			}
};

short		fsm[TERMINAL+1][MAX+1];

char		trigraph[MAX+1];

#if PROTOMAIN
static char	spl[] = { '\\', '\r', 0 };
static char	aln[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_$@";
#else
static char	spl[] = { MARK, '?', '\\', '\r', CC_sub, 0 };
static char	aln[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_";
#endif
static char*	let = &aln[10];
static char	hex[] = "fedcbaFEDCBA9876543210";
static char*	dec = &hex[12];
static char*	oct = &hex[14];

/*
 * runtime FSM modifications
 * ppfsm(FSM_INIT,0) must be called first
 */

void
ppfsm(int op, register char* s)
{
	register int			c;
	register int			n;
	register int			i;
	register short*			rp;
	register struct fsminit*	fp;
#if !PROTOMAIN
	char*				t;
	int				x;
#endif

	switch (op)
	{

#if !PROTOMAIN

	case FSM_IDADD:
		while (c = *s++)
			if (!ppisid(c))
			{
				if (fsm[TOKEN][c] == ~S_HUH)
				{
					setid(c);
					for (i = 0; i < TERMINAL; i++)
						fsm[i][c] = IDSTATE(fsm[i]['_']);
				}
				else error(2, "%c: cannot add to identifier set", c);
			}
		break;

	case FSM_IDDEL:
		while (c = *s++)
			if (ppisid(c))
			{
				clrid(c);
				for (i = 0; i < TERMINAL; i++)
					fsm[i][c] = ~S_HUH;
			}
		break;

#endif

	case FSM_INIT:
		for (fp = fsminit;; fp++)
		{
			if ((n = fp->nextstate) >= TERMINAL) n = ~n;
			if (fp->state == OP)
			{
#if !PROTOMAIN
				switch (n)
				{
				case COPY:
					c = fp->ch[0];
					n = fp->ch[2];
					for (i = fp->ch[1]; i <= n; i++)
						copy(i, c);
					continue;
				default:
					break;
				}
#endif
				break;
			}
			rp = fsm[fp->state];
			for (i = 0; i < sizeof(fp->ch) && (c = fp->ch[i]); i++)
			{
				switch (c)
				{
				case C_XXX:
					for (c = 0; c <= MAX; c++)
						rp[c] = n;
					/*FALLTHROUGH*/

				case C_EOF:
					fsm[TERMINAL][fp->state+1] = n < 0 ? ~n : n;
					continue;

				case C_LET:
					s = let;
					break;

				case C_HEX:
					s = hex;
					break;

				case C_DEC:
					s = dec;
					break;

				case C_OCT:
					s = oct;
					break;

				default:
					rp[c] = n;
					continue;
				}
				while (c = *s++)
					rp[c] = n;
			}
		}

		/*
		 * install splice special cases
		 * and same non-terminal transitions
		 */

		for (i = 0; i < TERMINAL; i++)
		{
			rp = fsm[i];
			s = spl;
			while (c = *s++)
				if (c != MARK || !INCOMMENT(rp))
				{
					if (rp[c] >= 0) rp[c] = ~rp[c];
					rp[c] &= ~SPLICE;
				}
			rp[EOB] = ~S_EOB;
			for (c = 0; c <= MAX; c++)
				if (rp[c] == i)
					rp[c] = 0;
		}
		fsm[TERMINAL][0] = ~S_EOB;

#if !PROTOMAIN

		/*
		 * default character types
		 */

		s = let;
		while (c = *s++)
			setid(c);
		s = dec;
		while (c = *s++)
			setdig(c);
		s = spl;
		do setsplice(c = *s++); while (c);

		/*
		 * trigraph map
		 */

		trigraph['='] = '#';
		trigraph['('] = '[';
		trigraph['/'] = '\\';
		trigraph[')'] = ']';
		trigraph['\''] = '^';
		trigraph['<'] = '{';
		trigraph['!'] = '|';
		trigraph['>'] = '}';
		trigraph['-'] = '~';
#endif
		break;

#if !PROTOMAIN

	case FSM_PLUSPLUS:
		if (pp.option & PLUSPLUS)
		{
			fsm[COLON1][':'] = ~KEEP(T_SCOPE);
			fsm[DOT1]['*'] = ~KEEP(T_DOTREF);
			fsm[MINUS1]['>'] = ARROW1;
			fsm[COM1]['/'] = COM5;
			t = "%<:";
			for (i = 0; i < TERMINAL; i++)
			{
				rp = fsm[i];
				if (!INCOMMENT(rp) && !INQUOTE(rp))
				{
					s = t;
					while (c = *s++)
					{
						if (rp[c] > 0) rp[c] = ~rp[c];
						else if (!rp[c]) rp[c] = ~i;
						rp[c] &= ~SPLICE;
					}
				}
			}
			s = t;
			while (c = *s++) setsplice(c);
		}
		else
		{
			fsm[COLON1][':'] = ~S_CHRB;
			fsm[DOT1]['*'] = ~S_CHRB;
			fsm[MINUS1]['>'] = ~KEEP(T_PTRMEM);
			fsm[COM1]['/'] = (pp.option & PLUSCOMMENT) ? COM5 : ~S_CHRB;
		}
		break;

#if COMPATIBLE

	case FSM_COMPATIBILITY:
		if (pp.state & COMPATIBILITY)
		{
			fsm[HEX1]['e'] = HEX1;
			fsm[HEX1]['E'] = HEX1;
			fsm[QNUM]['e'] = QNUM;
			fsm[QNUM]['E'] = QNUM;
			fsm[QNUM]['u'] = ~QUAL(QNUM);
			fsm[QNUM]['U'] = ~QUAL(QNUM);
		}
		else
		{
			fsm[HEX1]['e'] = HEX3;
			fsm[HEX1]['E'] = HEX3;
			fsm[QNUM]['e'] = QEXP;
			fsm[QNUM]['E'] = QEXP;
			fsm[QNUM]['u'] = QNUM;
			fsm[QNUM]['U'] = QNUM;
		}
		break;

#endif

	case FSM_QUOTADD:
		while (c = *s++)
			if (fsm[TOKEN][c] == ~S_HUH)
				for (i = 0; i < TERMINAL; i++)
					fsm[i][c] = fsm[i]['"'];
			else error(2, "%c: cannot add to quote set", c);
		break;

	case FSM_QUOTDEL:
		while (c = *s++)
			if (c != '"' && fsm[TOKEN][c] == fsm[TOKEN]['"'])
				for (i = 0; i < TERMINAL; i++)
					fsm[i][c] = fsm[i]['_'];
		break;

	case FSM_OPSPACE:
		n = s ? BIN1 : ~S_CHRB;
		fsm[COM1][' '] = fsm[COM1]['\t'] = n;
		fsm[AND1][' '] = fsm[AND1]['\t'] = n;
		fsm[STAR1][' '] = fsm[STAR1]['\t'] = n;
		fsm[PCT1][' '] = fsm[PCT1]['\t'] = n;
		fsm[PLUS1][' '] = fsm[PLUS1]['\t'] = n;
		fsm[MINUS1][' '] = fsm[MINUS1]['\t'] = n;
		fsm[CIRC1][' '] = fsm[CIRC1]['\t'] = n;
		fsm[OR1][' '] = fsm[OR1]['\t'] = n;
		fsm[LSH1][' '] = fsm[LSH1]['\t'] = s ? BIN1 : ~BACK(T_LSHIFT);
		fsm[RSH1][' '] = fsm[RSH1]['\t'] = s ? BIN1 : ~BACK(T_RSHIFT);
		break;

	case FSM_MACRO:
		if (pp.truncate && strlen(s) >= pp.truncate)
		{
			x = s[pp.truncate];
			s[pp.truncate] = 0;
		}
		else x = -1;
		i = MAC0 + ((c = *s++) != 'L');
		if ((n = fsm[QUICK][c]) != (i + NMAC))
		{
			n = i;
			if (!*s) n += NMAC;
		}
		if (fsm[QUICK][c] != n)
			fsm[QUICK][c] = fsm[QCOM][c] = fsm[QTOK][c] = n;
		if (c = *s++)
		{
			for (;;)
			{
				if ((i = n) < HIT0)
				{
					if (n < MACN) n++;
					if (!*s)
					{
						n += NMAC;
						break;
					}
					if (fsm[i][c] < HIT0)
						fsm[i][c] = n;
					if (fsm[i + NMAC][c] < HIT0)
						fsm[i + NMAC][c] = n;
				}
				else
				{
					if (n < HITN) n++;
					if (!*s) break;
					if (fsm[i][c] < HIT0)
					{
						n -= NMAC;
						fsm[i][c] = n;
					}
				}
				c = *s++;
			}
			if (x >= 0)
			{
				*s = x;
				for (n = CHAR_MIN; n <= CHAR_MAX; n++)
					if (ppisidig(n))
						fsm[HITN][n] = HITN;
				n = HITN;
			}
			if (fsm[i][c] < n)
				fsm[i][c] = n;
			if (i < HIT0 && fsm[i + NMAC][c] < n)
				fsm[i + NMAC][c] = n;
		}
		break;

#endif

	}
}

#if !PROTOMAIN

/*
 * file buffer refill
 * c is current input char
 */

void
refill(register int c)
{
	if (pp.in->flags & IN_eof)
	{
		pp.in->nextchr--;
		c = 0;
	}
	else
	{
		*((pp.in->nextchr = pp.in->buffer + PPBAKSIZ) - 1) = c;
		c =
#if PROTOTYPE
		(pp.in->flags & IN_prototype) ? pppread(pp.in->nextchr) :
#endif
		read(pp.in->fd, pp.in->nextchr, PPBUFSIZ);
	}
	if (c > 0)
	{
		if (pp.in->nextchr[c - 1] == '\n') pp.in->flags |= IN_newline;
		else pp.in->flags &= ~IN_newline;
#if PROTOTYPE
		if (!(pp.in->flags & IN_prototype))
#endif
		if (c < PPBUFSIZ && (pp.in->flags & IN_regular))
		{
			pp.in->flags |= IN_eof;
			close(pp.in->fd);
			pp.in->fd = -1;
		}
	}
	else
	{
		if (c < 0)
		{
			error(ERROR_SYSTEM|3, "read error");
			c = 0;
		}
		else if ((pp.in->flags ^ pp.in->prev->flags) & IN_c)
		{
			static char	ket[] = { 0, '}', '\n', 0 };

			pp.in->flags ^= IN_c;
			pp.in->nextchr = ket + 1;
			c = 2;
		}
		pp.in->flags |= IN_eof;
	}
#if CHECKPOINT
	pp.in->buflen = c;
#endif
	pp.in->nextchr[c] = 0;
	debug((-7, "refill(\"%s\") = %d = \"%-.*s%s\"", error_info.file, c, (c > 32 ? 32 : c), pp.in->nextchr, c > 32 ? "..." : ""));
	if (pp.test & 0x0080)
		sfprintf(sfstderr, "===== refill(\"%s\") = %d =====\n%s\n===== eob(\"%s\") =====\n", error_info.file, c, pp.in->nextchr, error_info.file);
}

#endif
