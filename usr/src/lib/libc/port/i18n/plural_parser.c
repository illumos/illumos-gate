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

#include "lint.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include "libc.h"
#include "gettext.h"

#include "plural_parser.h"

/*
 * 31   28    24    20    16    12     8     4     0
 * +-----+-----+-----+-----+-----+-----+-----+-----+
 * |opnum| priority  |        operator             |
 * +-----+-----+-----+-----+-----+-----+-----+-----+
 */
static const unsigned int	operator[] = {
	0x00000000,		/* NULL */
	0x00000001,		/* INIT */
	0x00100002,		/* EXP */
	0x00200003,		/* NUM */
	0x00300004,		/* VAR */
	0x30400005,		/* CONDC */
	0x30500006,		/* CONDQ */
	0x20600007,		/* OR */
	0x20700008,		/* AND */
	0x20800009,		/* EQ */
	0x2080000a,		/* NEQ */
	0x2090000b,		/* GT */
	0x2090000c,		/* LT */
	0x2090000d,		/* GE */
	0x2090000e,		/* LE */
	0x20a0000f,		/* ADD */
	0x20a00010,		/* SUB */
	0x20b00011,		/* MUL */
	0x20b00012,		/* DIV */
	0x20b00013,		/* MOD */
	0x10c00014,		/* NOT */
	0x00d00015,		/* LPAR */
	0x00e00016,		/* RPAR */
	0x00000017		/* ERR */
};

#define	STACKFREE \
	{ \
		while (stk->index > 0) \
			freeexpr(stk->ptr[--stk->index]); \
		free(stk->ptr); \
	}

#ifdef	PARSE_DEBUG
static const char	*type_name[] = {
	"T_NULL",
	"T_INIT", "T_EXP",	"T_NUM", "T_VAR", "T_CONDC", "T_CONDQ",
	"T_LOR", "T_LAND", "T_EQ", "T_NEQ", "T_GT", "T_LT", "T_GE", "T_LE",
	"T_ADD", "T_SUB", "T_MUL", "T_DIV", "T_MOD", "T_LNOT", "T_LPAR",
	"T_RPAR", "T_ERR"
};
#endif

static void	freeexpr(struct expr *);

static struct expr *
stack_push(struct stack *stk, struct expr *exp)
{
#ifdef	PARSE_DEBUG
	printf("--- stack_push ---\n");
	printf("   type: %s\n", type_name[GETTYPE(exp->op)]);
	printf("   flag: %s\n", type_name[GETTYPE(exp->flag)]);
	printf("------------------\n");
#endif
	stk->ptr[stk->index++] = exp;
	if (stk->index == MAX_STACK_SIZE) {
		/* overflow */
		freeexpr(exp);
		STACKFREE;
		return (NULL);
	}

	return (exp);
}

static struct expr *
stack_pop(struct stack *stk, struct expr *exp_a, struct expr *exp_b)
{
	if (stk->index == 0) {
		/* no item */
		if (exp_a)
			freeexpr(exp_a);
		if (exp_b)
			freeexpr(exp_b);
		STACKFREE;
		return (NULL);
	}
#ifdef	PARSE_DEBUG
	printf("--- stack_pop ---\n");
	printf("   type: %s\n",
	    type_name[GETTYPE((stk->ptr[stk->index - 1])->op)]);
	printf("   flag: %s\n",
	    type_name[GETTYPE((stk->ptr[stk->index - 1])->flag)]);
	printf("-----------------\n");
#endif
	return (stk->ptr[--stk->index]);
}

static void
freeexpr(struct expr *e)
{
#ifdef	PARSE_DEBUG
	printf("--- freeexpr ---\n");
	printf("   type: %s\n", type_name[GETTYPE(e->op)]);
	printf("----------------\n");
#endif
	switch (GETOPNUM(e->op)) {
	case TRINARY:
		if (e->nodes[2])
			freeexpr(e->nodes[2]);
		/* FALLTHROUGH */
	case BINARY:
		if (e->nodes[1])
			freeexpr(e->nodes[1]);
		/* FALLTHROUGH */
	case UNARY:
		if (e->nodes[0])
			freeexpr(e->nodes[0]);
		/* FALLTHROUGH */
	default:
		break;
	}
	free(e);
}

static struct expr *
setop1(unsigned int op, unsigned int num,
    struct stack *stk, unsigned int flag)
{
	struct expr	*newitem;
	unsigned int	type;

	type = GETTYPE(op);

#ifdef	PARSE_DEBUG
	printf("---setop1---\n");
	printf("   op type: %s\n", type_name[type]);
	printf("-----------\n");
#endif

	newitem = (struct expr *)calloc(1, sizeof (struct expr));
	if (!newitem) {
		STACKFREE;
		return (NULL);
	}
	newitem->op = op;
	if (type == T_NUM)
		newitem->num = num;
	newitem->flag = flag;
	return (newitem);
}

static struct expr *
setop_reduce(unsigned int n, unsigned int op, struct stack *stk,
    struct expr *exp1, struct expr *exp2, struct expr *exp3)
{
	struct expr	*newitem;
#ifdef	PARSE_DEBUG
	unsigned int	type;

	type = GETTYPE(op);
	printf("---setop_reduce---\n");
	printf("   n: %d\n", n);
	printf("   op type: %s\n", type_name[type]);
	switch (n) {
	case TRINARY:
		printf("   exp3 type: %s\n", type_name[GETTYPE(exp3->op)]);
	case BINARY:
		printf("   exp2 type: %s\n", type_name[GETTYPE(exp2->op)]);
	case UNARY:
		printf("   exp1 type: %s\n", type_name[GETTYPE(exp1->op)]);
	case NARY:
		break;
	}
	printf("-----------\n");
#endif

	newitem = (struct expr *)calloc(1, sizeof (struct expr));
	if (!newitem) {
		if (exp1)
			freeexpr(exp1);
		if (exp2)
			freeexpr(exp2);
		if (exp3)
			freeexpr(exp3);
		STACKFREE;
		return (NULL);
	}
	newitem->op = op;

	switch (n) {
	case TRINARY:
		newitem->nodes[2] = exp3;
		/* FALLTHROUGH */
	case BINARY:
		newitem->nodes[1] = exp2;
		/* FALLTHROUGH */
	case UNARY:
		newitem->nodes[0] = exp1;
		/* FALLTHROUGH */
	case NARY:
		break;
	}
	return (newitem);
}

static int
reduce(struct expr **nexp, unsigned int n, struct expr *exp, struct stack *stk)
{
	struct expr	*exp_op, *exp1, *exp2, *exp3;
	unsigned int	tmp_flag;
	unsigned int	oop;
#ifdef	PARSE_DEBUG
	printf("---reduce---\n");
	printf("   n: %d\n", n);
	printf("-----------\n");
#endif

	switch (n) {
	case UNARY:
		/* unary operator */
		exp1 = exp;
		exp_op = stack_pop(stk, exp1, NULL);
		if (!exp_op)
			return (1);
		tmp_flag = exp_op->flag;
		oop = exp_op->op;
		freeexpr(exp_op);
		*nexp = setop_reduce(UNARY, oop, stk, exp1, NULL, NULL);
		if (!*nexp)
			return (-1);
		(*nexp)->flag = tmp_flag;
		return (0);
	case BINARY:
		/* binary operator */
		exp2 = exp;
		exp_op = stack_pop(stk, exp2, NULL);
		if (!exp_op)
			return (1);
		exp1 = stack_pop(stk, exp_op, exp2);
		if (!exp1)
			return (1);
		tmp_flag = exp1->flag;
		oop = exp_op->op;
		freeexpr(exp_op);
		*nexp = setop_reduce(BINARY, oop, stk, exp1, exp2, NULL);
		if (!*nexp)
			return (-1);
		(*nexp)->flag = tmp_flag;
		return (0);
	case TRINARY:
		/* trinary operator: conditional */
		exp3 = exp;
		exp_op = stack_pop(stk, exp3, NULL);
		if (!exp_op)
			return (1);
		freeexpr(exp_op);
		exp2 = stack_pop(stk, exp3, NULL);
		if (!exp2)
			return (1);
		exp_op = stack_pop(stk, exp2, exp3);
		if (!exp_op)
			return (1);
		if (GETTYPE(exp_op->op) != T_CONDQ) {
			/* parse failed */
			freeexpr(exp_op);
			freeexpr(exp2);
			freeexpr(exp3);
			STACKFREE;
			return (1);
		}
		oop = exp_op->op;
		freeexpr(exp_op);
		exp1 = stack_pop(stk, exp2, exp3);
		if (!exp1)
			return (1);

		tmp_flag = exp1->flag;
		*nexp = setop_reduce(TRINARY, oop, stk, exp1, exp2, exp3);
		if (!*nexp)
			return (-1);
		(*nexp)->flag = tmp_flag;
		return (0);
	}
	/* NOTREACHED */
	return (0);	/* keep gcc happy */
}

static unsigned int
gettoken(const char **pstr, unsigned int *num, int which)
{
	unsigned char	*sp = *(unsigned char **)pstr;
	unsigned int	n;
	unsigned int	ret;

	while (*sp && ((*sp == ' ') || (*sp == '\t')))
		sp++;
	if (!*sp) {
		if (which == GET_TOKEN)
			*pstr = (const char *)sp;
		return (T_NULL);
	}

	if (isdigit(*sp)) {
		n = *sp - '0';
		sp++;
		while (isdigit(*sp)) {
			n *= 10;
			n += *sp - '0';
			sp++;
		}
		*num = n;
		ret = T_NUM;
	} else if (*sp == 'n') {
		sp++;
		ret = T_VAR;
	} else if (*sp == '(') {
		sp++;
		ret = T_LPAR;
	} else if (*sp == ')') {
		sp++;
		ret = T_RPAR;
	} else if (*sp == '!') {
		sp++;
		if (*sp == '=') {
			sp++;
			ret = T_NEQ;
		} else {
			ret = T_LNOT;
		}
	} else if (*sp == '*') {
		sp++;
		ret = T_MUL;
	} else if (*sp == '/') {
		sp++;
		ret = T_DIV;
	} else if (*sp == '%') {
		sp++;
		ret = T_MOD;
	} else if (*sp == '+') {
		sp++;
		ret = T_ADD;
	} else if (*sp == '-') {
		sp++;
		ret = T_SUB;
	} else if (*sp == '<') {
		sp++;
		if (*sp == '=') {
			sp++;
			ret = T_LE;
		} else {
			ret = T_LT;
		}
	} else if (*sp == '>') {
		sp++;
		if (*sp == '=') {
			sp++;
			ret = T_GE;
		} else {
			ret = T_GT;
		}
	} else if (*sp == '=') {
		sp++;
		if (*sp == '=') {
			sp++;
			ret = T_EQ;
		} else {
			ret = T_ERR;
		}
	} else if (*sp == '&') {
		sp++;
		if (*sp == '&') {
			sp++;
			ret = T_LAND;
		} else {
			ret = T_ERR;
		}
	} else if (*sp == '|') {
		sp++;
		if (*sp == '|') {
			sp++;
			ret = T_LOR;
		} else {
			ret = T_ERR;
		}
	} else if (*sp == '?') {
		sp++;
		ret = T_CONDQ;
	} else if (*sp == ':') {
		sp++;
		ret = T_CONDC;
	} else if ((*sp == '\n') || (*sp == ';')) {
		ret = T_NULL;
	} else {
		ret = T_ERR;
	}
	if (which == GET_TOKEN)
		*pstr = (const char *)sp;
	return (operator[ret]);
}

/*
 * plural_expr
 *
 * INPUT
 * str: string to parse
 *
 * OUTPUT
 * e: parsed expression
 *
 * RETURN
 * -1: Error happend (malloc failed)
 *  1: Parse failed (invalid expression)
 *  0: Parse succeeded
 */
int
plural_expr(struct expr **e, const char *plural_string)
{
	const char	*pstr = plural_string;
	struct stack	*stk, stkbuf;
	struct expr	*exp, *nexp, *exp_op, *ret;
	int	par, result;
	unsigned int	flag, ftype, fprio, fopnum, tmp_flag;
	unsigned int	ntype, nprio, ptype, popnum;
	unsigned int	op, nop, num, type, opnum;

	stk = &stkbuf;
	stk->index = 0;
	stk->ptr = malloc(sizeof (struct expr *) * MAX_STACK_SIZE);
	if (!stk->ptr) {
		/* malloc failed */
		return (-1);
	}

	flag = operator[T_INIT];
	par = 0;
	while ((op = gettoken(&pstr, &num, GET_TOKEN)) != T_NULL) {
		type = GETTYPE(op);
		opnum = GETOPNUM(op);
		ftype = GETTYPE(flag);

#ifdef	PARSE_DEBUG
		printf("*** %s ***\n", type_name[type]);
		printf("   flag: %s\n", type_name[ftype]);
		printf("   par: %d\n", par);
		printf("***********\n");
#endif
		if (type == T_ERR) {
			/* parse failed */
			STACKFREE;
			return (1);
		}
		if (opnum == BINARY) {
			/* binary operation */
			if (ftype != T_EXP) {
				/* parse failed */
#ifdef	PARSE_DEBUG
				printf("ERR: T_EXP is not followed by %s\n",
				    type_name[type]);
#endif
				STACKFREE;
				return (1);
			}
			exp = setop1(op, 0, stk, flag);
			if (!exp)
				return (-1);
			ret = stack_push(stk, exp);
			if (!ret)
				return (1);
			flag = op;
			continue;			/* while-loop */
		}

		if (type == T_CONDQ) {
			/* conditional operation: '?' */
			if (ftype != T_EXP) {
				/* parse failed */
#ifdef	PARSE_DEBUG
				printf("ERR: T_EXP is not followed by %s\n",
				    type_name[type]);
#endif
				STACKFREE;
				return (1);
			}
			exp = setop1(op, 0, stk, flag);
			if (!exp)
				return (-1);
			ret = stack_push(stk, exp);
			if (!ret)
				return (1);
			flag = op;
			continue;			/* while-loop */
		}
		if (type == T_CONDC) {
			/* conditional operation: ':' */
			if (ftype != T_EXP) {
				/* parse failed */
#ifdef	PARSE_DEBUG
				printf("ERR: T_EXP is not followed by %s\n",
				    type_name[type]);
#endif
				STACKFREE;
				return (1);
			}
			exp = setop1(op, 0, stk, flag);
			if (!exp)
				return (-1);
			ret = stack_push(stk, exp);
			if (!ret)
				return (1);
			flag = op;
			continue;			/* while-loop */
		}

		if (type == T_LPAR) {
			/* left parenthesis */
			if (ftype == T_EXP) {
				/* parse failed */
#ifdef	PARSE_DEBUG
				printf("ERR: T_EXP is followed by %s\n",
				    type_name[type]);
#endif
				STACKFREE;
				return (1);
			}
			exp = setop1(op, 0, stk, flag);
			if (!exp)
				return (-1);
			ret = stack_push(stk, exp);
			if (!ret)
				return (1);
			par++;
			flag = op;
			continue;			/* while-loop */
		}
		if (type == T_RPAR) {
			/* right parenthesis */
			if (ftype != T_EXP) {
				/* parse failed */
#ifdef	PARSE_DEBUG
				printf("ERR: T_EXP is not followed by %s\n",
				    type_name[type]);
#endif
				STACKFREE;
				return (1);
			}
			par--;
			if (par < 0) {
				/* parse failed */
#ifdef	PARSE_DEBUG
				printf("ERR: too much T_RPAR\n");
#endif
				STACKFREE;
				return (1);
			}
			exp = stack_pop(stk, NULL, NULL);
			if (!exp)
				return (1);

#ifdef	PARSE_DEBUG
			printf("======================== RPAR for loop in\n");
#endif
			for (; ; ) {
				ptype = GETTYPE(exp->flag);
				popnum = GETOPNUM(exp->flag);

#ifdef	PARSE_DEBUG
				printf("=========== exp->flag: %s\n",
				    type_name[ptype]);
#endif
				if (ptype == T_LPAR) {
					exp_op = stack_pop(stk, exp, NULL);
					if (!exp_op)
						return (1);

					tmp_flag = exp_op->flag;
					freeexpr(exp_op);

					exp->flag = tmp_flag;
					flag = tmp_flag;
					break;	/* break from for-loop */
				}

				if ((popnum == BINARY) ||
				    (ptype == T_LNOT) ||
				    (ptype == T_CONDC)) {
					result = reduce(&nexp, popnum,
					    exp, stk);
					if (result)
						return (result);
					exp = nexp;
					continue;	/* for-loop */
				}
				/* parse failed */
				freeexpr(exp);
				STACKFREE;
				return (1);
			}		/* for-loop */

#ifdef	PARSE_DEBUG
printf("========================= RPAR for loop out\n");
#endif
			/*
			 * Needs to check if exp can be reduced or not
			 */
			goto exp_check;
		}

		if (type == T_LNOT) {
			if (ftype == T_EXP) {
				/* parse failed */
#ifdef	PARSE_DEBUG
				printf("ERR: T_EXP is followed by %s\n",
				    type_name[type]);
#endif
				STACKFREE;
				return (1);
			}
			exp = setop1(op, 0, stk, flag);
			if (!exp)
				return (-1);
			ret = stack_push(stk, exp);
			if (!ret)
				return (1);
			flag = op;
			continue;			/* while-loop */
		}
		if ((type == T_NUM) || (type == T_VAR)) {
			exp = setop1(op, type == T_NUM ? num : 0, stk, flag);
			if (!exp)
				return (-1);
exp_check:
			ftype = GETTYPE(flag);
			if ((ftype == T_INIT) || (ftype == T_LPAR)) {
				/*
				 * if this NUM/VAR is the first EXP,
				 * just push this
				 */
				exp->flag = flag;
				ret = stack_push(stk, exp);
				if (!ret)
					return (1);
				flag = operator[T_EXP];
				continue;		/* while-loop */
			}
			if (ftype == T_EXP) {
				/*
				 * parse failed
				 * NUM/VAR cannot be seen just after
				 * T_EXP
				 */
				freeexpr(exp);
				STACKFREE;
				return (1);
			}

			nop = gettoken(&pstr, &num, PEEK_TOKEN);
			if (nop != T_NULL) {
				ntype = GETTYPE(nop);
				nprio = GETPRIO(nop);
			} else {
				(void) gettoken(&pstr, &num, GET_TOKEN);
				ntype = T_INIT;
				nprio = 0;
			}
#ifdef	PARSE_DEBUG
printf("========================== T_NUM/T_VAR for loop in\n");
#endif
			for (; ; ) {
				ftype = GETTYPE(flag);
				fopnum = GETOPNUM(flag);
				fprio = GETPRIO(flag);
#ifdef	PARSE_DEBUG
				printf("========= flag: %s\n",
				    type_name[ftype]);
#endif
				if ((ftype == T_INIT) || (ftype == T_LPAR)) {
					exp->flag = flag;
					ret = stack_push(stk, exp);
					if (!ret)
						return (1);
					flag = operator[T_EXP];
					break;		/* exit from for-loop */
				}

				if (ftype == T_LNOT) {
					/* LNOT is the strongest */
					result = reduce(&nexp, UNARY, exp, stk);
					if (result)
						return (result);
					exp = nexp;
					flag = nexp->flag;
					continue;	/* for-loop */
				}

				if (fopnum == BINARY) {
					/*
					 * binary operation
					 * T_MUL, T_ADD,  T_CMP,
					 * T_EQ,  T_LAND, T_LOR
					 */
					if ((ntype == T_RPAR) ||
					    (nprio <= fprio)) {
						/* reduce */
						result = reduce(&nexp, BINARY,
						    exp, stk);
						if (result)
							return (result);
						exp = nexp;
						flag = nexp->flag;
						continue; /* for-loop */
					}
					/* shift */
					exp->flag = flag;
					ret = stack_push(stk, exp);
					if (!ret)
						return (1);
					flag = operator[T_EXP];
					break;		/* exit from for loop */
				}

				if (ftype == T_CONDQ) {
					/*
					 * CONDQ is the weakest
					 * always shift
					 */
					exp->flag = flag;
					ret = stack_push(stk, exp);
					if (!ret)
						return (1);
					flag = operator[T_EXP];
					break;		/* exit from for loop */
				}
				if (ftype == T_CONDC) {
					if (nprio <= fprio) {
						/* reduce */
						result = reduce(&nexp, TRINARY,
						    exp, stk);
						if (result)
							return (result);
						exp = nexp;
						flag = nexp->flag;
						continue; /* for-loop */
					}
					/* shift */
					exp->flag = flag;
					ret = stack_push(stk, exp);
					if (!ret)
						return (1);
					flag = operator[T_EXP];
					break;		/* exit from for-loop */
				}
				/* parse failed */
				freeexpr(exp);
				STACKFREE;
				return (1);
			}

#ifdef	PARSE_DEBUG
printf("======================= T_NUM/T_VAR for loop out\n");
#endif
			continue;			/* while-loop */
		}
		/* parse failed */
		STACKFREE;
		return (1);
	}	/* while-loop */

	if (GETTYPE(flag) != T_EXP) {
		/* parse failed */
#ifdef	PARSE_DEBUG
		printf("XXXX ERROR: flag is not T_INIT\n");
		printf("========= flag: %s\n", type_name[GETTYPE(flag)]);
#endif
		STACKFREE;
		return (1);
	} else {
		exp = stack_pop(stk, NULL, NULL);
		if (!exp)
			return (1);

		if (GETTYPE(exp->flag) != T_INIT) {
			/* parse failed */
#ifdef	PARSE_DEBUG
			printf("ERR: flag for the result is not T_INIT\n");
			printf("      %s observed\n",
			    type_name[GETTYPE(exp->flag)]);
#endif
			freeexpr(exp);
			STACKFREE;
			return (1);
		}
		if (stk->index > 0) {
			/*
			 * exp still remains in stack.
			 * parse failed
			 */
			while ((nexp = stack_pop(stk, NULL, NULL)) != NULL)
				freeexpr(nexp);
			freeexpr(exp);
			return (1);
		}

		/* parse succeeded */
		*e = exp;
		STACKFREE;
		return (0);
	}
}

unsigned int
plural_eval(struct expr *exp, unsigned int n)
{
	unsigned int	e1, e2;
	unsigned int	type, opnum;
#ifdef GETTEXT_DEBUG
	(void) printf("*************** plural_eval(%p, %d)\n", exp, n);
	printexpr(exp, 0);
#endif

	type = GETTYPE(exp->op);
	opnum = GETOPNUM(exp->op);

	switch (opnum) {
	case NARY:
		if (type == T_NUM) {
			return (exp->num);
		} else if (type == T_VAR) {
			return (n);
		}
		break;
	case UNARY:
		/* T_LNOT */
		e1 = plural_eval(exp->nodes[0], n);
		return (!e1);
	case BINARY:
		e1 = plural_eval(exp->nodes[0], n);
		/* optimization for T_LOR and T_LAND */
		if (type == T_LOR) {
			return (e1 || plural_eval(exp->nodes[1], n));
		} else if (type == T_LAND) {
			return (e1 && plural_eval(exp->nodes[1], n));
		}
		e2 = plural_eval(exp->nodes[1], n);
		switch (type) {
		case T_EQ:
			return (e1 == e2);
		case T_NEQ:
			return (e1 != e2);
		case T_GT:
			return (e1 > e2);
		case T_LT:
			return (e1 < e2);
		case T_GE:
			return (e1 >= e2);
		case T_LE:
			return (e1 <= e2);
		case T_ADD:
			return (e1 + e2);
		case T_SUB:
			return (e1 - e2);
		case T_MUL:
			return (e1 * e2);
		case T_DIV:
			if (e2 != 0)
				return (e1 / e2);
			break;
		case T_MOD:
			if (e2 != 0)
				return (e1 % e2);
			break;
		}
		break;
	case TRINARY:
		/* T_CONDQ */
		e1 = plural_eval(exp->nodes[0], n);
		if (e1) {
			return (plural_eval(exp->nodes[1], n));
		} else {
			return (plural_eval(exp->nodes[2], n));
		}
	}
	/* should not be here */
	return (0);
}
