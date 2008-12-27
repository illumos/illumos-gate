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
 * preprocessor lexical analyzer definitions
 */

#ifndef _PPFSM_H
#define _PPFSM_H

#define BITSTATE	16		/* bitsof(state)		*/
#define BITNONTERM	7		/* bitsof(non-terminal-state)	*/
#define BITTERM		7		/* bitsof(terminal-state)	*/
#define NMAC		19		/* number of MAC states		*/

#define SPLICE		(1<<BITTERM)

#define	CODE(tok,act)	((((tok)-N_PP)<<(BITTERM+1))|(act))
#define TERM(st)	((st)&((1<<(BITTERM+1))-1))
#define NEXT(st)	(((st)>>(BITTERM+1))&((1<<BITNONTERM)-1))
#define QUAL(st)	(((st)<<(BITTERM+1))|(S_QUAL))
#define	TYPE(st)	(NEXT(st)+N_PP)

#define BACK(tok)	CODE(tok,S_TOKB)
#define KEEP(tok)	CODE(tok,S_TOK)

#undef	MAX
#define MAX		255

#undef	EOB
#define EOB		0
#undef	EOF
#define EOF		(MAX+1)

/*
 * FSM states
 *
 * NOTE: preserve the ranges
 */

#define INDEX(p)	(((p)-fsm[0])/(MAX+1))

#define IDSTATE(x)	(((x)>=0&&INQMACRO(fsm[x]))?QID:(x))

#define INCOMMENT(p)	((p)>=fsm[COM2]&&(p)<=fsm[COM7])
#define INCOMMENTXX(p)	((p)>=fsm[COM5]&&(p)<=fsm[COM7])
#define INQMACRO(p)	((p)>=fsm[MAC0]&&(p)<=fsm[LIT0])
#define INTMACRO(p)	((p)>=fsm[NID]&&(p)<=fsm[LIT])
#define INQUOTE(p)	((p)>=fsm[LIT1]&&(p)<=fsm[LIT2])
#define INOPSPACE(p)	((p)==fsm[BIN1])
#define INSPACE(p)	((p)==fsm[WS1])

/*
 * proto non-terminal states
 */

#define PROTO		0
#define RES1		(PROTO+1)
#define RES1a		(PROTO+2)
#define RES1e		(PROTO+3)
#define RES1f		(PROTO+4)
#define RES1h		(PROTO+5)
#define RES1l		(PROTO+6)
#define RES1n		(PROTO+7)
#define RES1o		(PROTO+8)
#define RES1t		(PROTO+9)
#define RES1x		(PROTO+10)
#define RES1y		(PROTO+11)
#define COM1		(PROTO+12)
#define COM2		(PROTO+13)
#define COM3		(PROTO+14)
#define COM4		(PROTO+15)
#define COM5		(PROTO+16)
#define COM6		(PROTO+17)
#define COM7		(PROTO+18)
#define NID		(PROTO+19)
#define LIT		(PROTO+20)
#define LIT1		(PROTO+21)
#define LIT2		(PROTO+22)
#define BAD1		(PROTO+23)
#define BAD2		(PROTO+24)
#define DOT		(PROTO+25)
#define DOT2		(PROTO+26)
#define WS1		(PROTO+27)

#if PROTOMAIN

#define TERMINAL	(PROTO+28)	/* PROTOMAIN */

#else

/*
 * quick non-terminal states
 */

#define QUICK		(PROTO+28)
#define QTOK		(QUICK+1)
#define QNUM		(QUICK+2)
#define QEXP		(QUICK+3)
#define QCOM		(QUICK+4)
#define QID		(QUICK+5)
#define MAC0		(QUICK+6)
#define MACN		(MAC0+NMAC-1)
#define HIT0		(MACN+1)
#define HITN		(HIT0+NMAC-1)
#define LIT0		(HITN+1)
#define SHARP1		(HITN+2)

/*
 * tokenize non-terminal states
 */

#define TOKEN		(HITN+3)
#define OCT1		(TOKEN+1)
#define OCT2		(TOKEN+2)
#define OCT3		(TOKEN+3)
#define NOT1		(TOKEN+4)
#define PCT1		(TOKEN+5)
#define AND1		(TOKEN+6)
#define STAR1		(TOKEN+7)
#define PLUS1		(TOKEN+8)
#define MINUS1		(TOKEN+9)
#define ARROW1		(TOKEN+10)
#define COLON1		(TOKEN+11)
#define LT1		(TOKEN+12)
#define LSH1		(TOKEN+13)
#define EQ1		(TOKEN+14)
#define RSH1		(TOKEN+15)
#define GT1		(TOKEN+16)
#define CIRC1		(TOKEN+17)
#define OR1		(TOKEN+18)
#define DEC1		(TOKEN+19)
#define DEC2		(TOKEN+20)
#define HEX1		(TOKEN+21)
#define HEX2		(TOKEN+22)
#define HEX3		(TOKEN+23)
#define HEX4		(TOKEN+24)
#define HEX5		(TOKEN+25)
#define HEX6		(TOKEN+26)
#define HEX7		(TOKEN+27)
#define HEX8		(TOKEN+28)
#define DBL1		(TOKEN+29)
#define DBL2		(TOKEN+30)
#define DBL3		(TOKEN+31)
#define DBL4		(TOKEN+32)
#define DBL5		(TOKEN+33)
#define DOT1		(TOKEN+34)
#define HDR1		(TOKEN+35)
#define BIN1		(TOKEN+36)

#define TERMINAL	(TOKEN+37)

#endif

/*
 * quick terminal states grouped together
 */

#define S_CHRB		(TERMINAL+0)
#define S_COMMENT	(TERMINAL+1)
#define S_EOB		(TERMINAL+2)
#define S_LITBEG	(TERMINAL+3)
#define S_LITEND	(TERMINAL+4)
#define S_LITESC	(TERMINAL+5)
#define S_MACRO		(TERMINAL+6)
#define S_NL		(TERMINAL+7)
#define S_QUAL		(TERMINAL+8)
#define S_SHARP		(TERMINAL+9)
#define S_VS		(TERMINAL+10)

/*
 * and the remaining terminal states
 */

#define S_CHR		(TERMINAL+11)
#define S_HUH		(TERMINAL+12)
#define S_TOK		(TERMINAL+13)
#define S_TOKB		(TERMINAL+14)
#define S_WS		(TERMINAL+15)

#define S_RESERVED	(S_HUH)

/*
 * the last terminal state (for tracing)
 */

#define LAST		(S_WS)

/*
 * pseudo terminal states
 */

#define S_EOF		(0)

/*
 * common lex macros
 *
 * NOTE: common local variable names assumed
 */

#define GET(p,c,tp,xp)	\
	do \
	{ \
		if ((c = GETCHR()) == EOB && pp.in->type == IN_FILE) \
			FGET(p, c, tp, xp); \
	} while (0)

#define FGET(p,c,tp,xp)	\
	do \
	{ \
		if (op > xp + PPTOKSIZ) \
		{ \
			if (!INCOMMENT(rp) && !(pp.state & (NOTEXT|SKIPCONTROL))) \
				error(2, "long token truncated"); \
			op = xp + PPTOKSIZ; \
		} \
		if ((pp.in->flags & IN_flush) && pp.level == 1 && !INMACRO(rp) && (!pp.comment || !INCOMMENT(rp)) && (c = op - pp.outbuf) > 0 && *(op - 1) == '\n') \
		{ \
			PPWRITE(c); \
			op = tp = pp.outp = pp.outbuf; \
		} \
		SYNCIN(); \
		refill(p); \
		CACHEIN(); \
		if ((c = GETCHR()) == EOB) BACKIN(); \
	} while (0)

#define POP()		\
	do \
	{ \
		debug((-7, "POP  in=%s next=%s state=%s", ppinstr(cur), pptokchr(*prv->nextchr), pplexstr(INDEX(rp)))); \
		ip = (pp.in = prv)->nextchr; \
	} while (0)

/*
 * fsm implementaion globals
 */

#define fsm		_pp_fsmtab
#define refill		_pp_refill
#define trigraph	_pp_trigraph

/*
 * first index is state, second is char, value is next state
 * except for fsm[TERMINAL] where second is state+1 for EOF transition
 */

extern short		fsm[TERMINAL+1][MAX+1];

/*
 * the index is char, value is trigraph value for <?><?><char>, 0 if invalid
 */

extern char		trigraph[MAX+1];

extern void		refill(int);

#endif
