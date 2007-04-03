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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>

#include <fcode/private.h>
#include <fcode/log.h>

void (*semi_ptr)(fcode_env_t *env) = do_semi;
void (*does_ptr)(fcode_env_t *env) = install_does;
void (*quote_ptr)(fcode_env_t *env) = do_quote;
void (*blit_ptr)(fcode_env_t *env) = do_literal;
void (*tlit_ptr)(fcode_env_t *env) = do_literal;
void (*do_bdo_ptr)(fcode_env_t *env) = do_bdo;
void (*do_bqdo_ptr)(fcode_env_t *env) = do_bqdo;
void (*create_ptr)(fcode_env_t *env) = do_creator;
void (*do_leave_ptr)(fcode_env_t *env) = do_bleave;
void (*do_loop_ptr)(fcode_env_t *env) = do_bloop;
void (*do_ploop_ptr)(fcode_env_t *env) = do_bploop;

void unaligned_lstore(fcode_env_t *);
void unaligned_wstore(fcode_env_t *);
void unaligned_lfetch(fcode_env_t *);
void unaligned_wfetch(fcode_env_t *);

/* start with the simple maths functions */


void
add(fcode_env_t *env)
{
	fstack_t d;

	CHECK_DEPTH(env, 2, "+");
	d = POP(DS);
	TOS += d;
}

void
subtract(fcode_env_t *env)
{
	fstack_t d;

	CHECK_DEPTH(env, 2, "-");
	d = POP(DS);
	TOS -= d;
}

void
multiply(fcode_env_t *env)
{
	fstack_t d;

	CHECK_DEPTH(env, 2, "*");
	d = POP(DS);
	TOS *= d;
}

void
slash_mod(fcode_env_t *env)
{
	fstack_t d, o, t, rem;
	int sign = 1;

	CHECK_DEPTH(env, 2, "/mod");
	d = POP(DS);
	o = t = POP(DS);

	if (d == 0) {
		throw_from_fclib(env, 1, "/mod divide by zero");
	}
	sign = ((d ^ t) < 0);
	if (d < 0) {
		d = -d;
		if (sign) {
			t += (d-1);
		}
	}
	if (t < 0) {
		if (sign) {
			t -= (d-1);
		}
		t = -t;
	}
	t = t / d;
	if ((o ^ sign) < 0) {
		rem = (t * d) + o;
	} else {
		rem = o - (t*d);
	}
	if (sign) {
		t = -t;
	}
	PUSH(DS, rem);
	PUSH(DS, t);
}

/*
 * 'u/mod' Fcode implementation.
 */
void
uslash_mod(fcode_env_t *env)
{
	u_lforth_t u1, u2;

	CHECK_DEPTH(env, 2, "u/mod");
	u2 = POP(DS);
	u1 = POP(DS);

	if (u2 == 0)
		forth_abort(env, "u/mod: divide by zero");
	PUSH(DS, u1 % u2);
	PUSH(DS, u1 / u2);
}

void
divide(fcode_env_t *env)
{
	CHECK_DEPTH(env, 2, "/");
	slash_mod(env);
	nip(env);
}

void
mod(fcode_env_t *env)
{
	CHECK_DEPTH(env, 2, "mod");
	slash_mod(env);
	drop(env);
}

void
and(fcode_env_t *env)
{
	fstack_t d;

	CHECK_DEPTH(env, 2, "and");
	d = POP(DS);
	TOS &= d;
}

void
or(fcode_env_t *env)
{
	fstack_t d;

	CHECK_DEPTH(env, 2, "or");
	d = POP(DS);
	TOS |= d;
}

void
xor(fcode_env_t *env)
{
	fstack_t d;

	CHECK_DEPTH(env, 2, "xor");
	d = POP(DS);
	TOS ^= d;
}

void
invert(fcode_env_t *env)
{
	CHECK_DEPTH(env, 1, "invert");
	TOS = ~TOS;
}

void
lshift(fcode_env_t *env)
{
	fstack_t d;

	CHECK_DEPTH(env, 2, "lshift");
	d = POP(DS);
	TOS = TOS << d;
}

void
rshift(fcode_env_t *env)
{
	fstack_t d;

	CHECK_DEPTH(env, 2, "rshift");
	d = POP(DS);
	TOS = ((ufstack_t)TOS) >> d;
}

void
rshifta(fcode_env_t *env)
{
	fstack_t d;

	CHECK_DEPTH(env, 2, ">>a");
	d = POP(DS);
	TOS = ((s_lforth_t)TOS) >> d;
}

void
negate(fcode_env_t *env)
{
	CHECK_DEPTH(env, 1, "negate");
	TOS = -TOS;
}

void
f_abs(fcode_env_t *env)
{
	CHECK_DEPTH(env, 1, "abs");
	if (TOS < 0) TOS = -TOS;
}

void
f_min(fcode_env_t *env)
{
	fstack_t d;

	CHECK_DEPTH(env, 2, "min");
	d = POP(DS);
	if (d < TOS)	TOS = d;
}

void
f_max(fcode_env_t *env)
{
	fstack_t d;

	CHECK_DEPTH(env, 2, "max");
	d = POP(DS);
	if (d > TOS)	TOS = d;
}

void
to_r(fcode_env_t *env)
{
	CHECK_DEPTH(env, 1, ">r");
	PUSH(RS, POP(DS));
}

void
from_r(fcode_env_t *env)
{
	CHECK_RETURN_DEPTH(env, 1, "r>");
	PUSH(DS, POP(RS));
}

void
rfetch(fcode_env_t *env)
{
	CHECK_RETURN_DEPTH(env, 1, "r@");
	PUSH(DS, *RS);
}

void
f_exit(fcode_env_t *env)
{
	CHECK_RETURN_DEPTH(env, 1, "exit");
	IP = (token_t *)POP(RS);
}

#define	COMPARE(cmp, rhs)	((((s_lforth_t)TOS) cmp((s_lforth_t)(rhs))) ? \
				    TRUE : FALSE)
#define	UCOMPARE(cmp, rhs) 	((((u_lforth_t)TOS) cmp((u_lforth_t)(rhs))) ? \
				    TRUE : FALSE)
#define	EQUALS		==
#define	NOTEQUALS	!=
#define	LESSTHAN	<
#define	LESSEQUALS	<=
#define	GREATERTHAN	>
#define	GREATEREQUALS	>=

void
zero_equals(fcode_env_t *env)
{
	CHECK_DEPTH(env, 1, "0=");
	TOS = COMPARE(EQUALS, 0);
}

void
zero_not_equals(fcode_env_t *env)
{
	CHECK_DEPTH(env, 1, "0<>");
	TOS = COMPARE(NOTEQUALS, 0);
}

void
zero_less(fcode_env_t *env)
{
	CHECK_DEPTH(env, 1, "0<");
	TOS = COMPARE(LESSTHAN, 0);
}

void
zero_less_equals(fcode_env_t *env)
{
	CHECK_DEPTH(env, 1, "0<=");
	TOS = COMPARE(LESSEQUALS, 0);
}

void
zero_greater(fcode_env_t *env)
{
	CHECK_DEPTH(env, 1, "0>");
	TOS = COMPARE(GREATERTHAN, 0);
}

void
zero_greater_equals(fcode_env_t *env)
{
	CHECK_DEPTH(env, 1, "0>=");
	TOS = COMPARE(GREATEREQUALS, 0);
}

void
less(fcode_env_t *env)
{
	fstack_t d;

	CHECK_DEPTH(env, 2, "<");
	d = POP(DS);
	TOS = COMPARE(LESSTHAN, d);
}

void
greater(fcode_env_t *env)
{
	fstack_t d;

	CHECK_DEPTH(env, 2, ">");
	d = POP(DS);
	TOS = COMPARE(GREATERTHAN, d);
}

void
equals(fcode_env_t *env)
{
	fstack_t d;

	CHECK_DEPTH(env, 2, "=");
	d = POP(DS);
	TOS = COMPARE(EQUALS, d);
}

void
not_equals(fcode_env_t *env)
{
	fstack_t d;

	CHECK_DEPTH(env, 2, "<>");
	d = POP(DS);
	TOS = COMPARE(NOTEQUALS, d);
}


void
unsign_greater(fcode_env_t *env)
{
	ufstack_t d;

	CHECK_DEPTH(env, 2, "u>");
	d = POP(DS);
	TOS = UCOMPARE(GREATERTHAN, d);
}

void
unsign_less_equals(fcode_env_t *env)
{
	ufstack_t d;

	CHECK_DEPTH(env, 2, "u<=");
	d = POP(DS);
	TOS = UCOMPARE(LESSEQUALS, d);
}

void
unsign_less(fcode_env_t *env)
{
	ufstack_t d;

	CHECK_DEPTH(env, 2, "u<");
	d = POP(DS);
	TOS = UCOMPARE(LESSTHAN, d);
}

void
unsign_greater_equals(fcode_env_t *env)
{
	ufstack_t d;

	CHECK_DEPTH(env, 2, "u>=");
	d = POP(DS);
	TOS = UCOMPARE(GREATEREQUALS, d);
}

void
greater_equals(fcode_env_t *env)
{
	fstack_t d;

	CHECK_DEPTH(env, 2, ">=");
	d = POP(DS);
	TOS = COMPARE(GREATEREQUALS, d);
}

void
less_equals(fcode_env_t *env)
{
	fstack_t d;

	CHECK_DEPTH(env, 2, "<=");
	d = POP(DS);
	TOS = COMPARE(LESSEQUALS, d);
}

void
between(fcode_env_t *env)
{
	u_lforth_t hi, lo;

	CHECK_DEPTH(env, 3, "between");
	hi = (u_lforth_t)POP(DS);
	lo = (u_lforth_t)POP(DS);
	TOS = (((u_lforth_t)TOS >= lo) && ((u_lforth_t)TOS <= hi) ? -1 : 0);
}

void
within(fcode_env_t *env)
{
	u_lforth_t lo, hi;

	CHECK_DEPTH(env, 3, "within");
	hi = (u_lforth_t)POP(DS);
	lo = (u_lforth_t)POP(DS);
	TOS = ((((u_lforth_t)TOS >= lo) && ((u_lforth_t)TOS < hi)) ? -1 : 0);
}

void
do_literal(fcode_env_t *env)
{
	PUSH(DS, *IP);
	IP++;
}

void
literal(fcode_env_t *env)
{
	if (env->state) {
		COMPILE_TOKEN(&blit_ptr);
		compile_comma(env);
	}
}

void
do_also(fcode_env_t *env)
{
	token_t *d = *ORDER;

	if (env->order_depth < (MAX_ORDER - 1)) {
		env->order[++env->order_depth] = d;
		debug_msg(DEBUG_CONTEXT, "CONTEXT:also: %d/%p/%p\n",
		    env->order_depth, CONTEXT, env->current);
	} else
		log_message(MSG_WARN, "Vocabulary search order exceeds: %d\n",
		    MAX_ORDER);
}

void
do_previous(fcode_env_t *env)
{
	if (env->order_depth) {
		env->order_depth--;
		debug_msg(DEBUG_CONTEXT, "CONTEXT:previous: %d/%p/%p\n",
		    env->order_depth, CONTEXT, env->current);
	}
}

#ifdef DEBUG
void
do_order(fcode_env_t *env)
{
	int i;

	log_message(MSG_INFO, "Order: Depth: %ld: ", env->order_depth);
	for (i = env->order_depth; i >= 0 && env->order[i]; i--)
		log_message(MSG_INFO, "%p ", (void *)env->order[i]);
	log_message(MSG_INFO, "\n");
}
#endif

void
noop(fcode_env_t *env)
{
	/* what a waste of cycles */
}


#define	FW_PER_FL	(sizeof (lforth_t)/sizeof (wforth_t))

void
lwsplit(fcode_env_t *env)
{
	union {
		u_wforth_t l_wf[FW_PER_FL];
		u_lforth_t l_lf;
	} d;
	int i;

	CHECK_DEPTH(env, 1, "lwsplit");
	d.l_lf = POP(DS);
	for (i = 0; i < FW_PER_FL; i++)
		PUSH(DS, d.l_wf[(FW_PER_FL - 1) - i]);
}

void
wljoin(fcode_env_t *env)
{
	union {
		u_wforth_t l_wf[FW_PER_FL];
		u_lforth_t l_lf;
	} d;
	int i;

	CHECK_DEPTH(env, FW_PER_FL, "wljoin");
	for (i = 0; i < FW_PER_FL; i++)
		d.l_wf[i] = POP(DS);
	PUSH(DS, d.l_lf);
}

void
lwflip(fcode_env_t *env)
{
	union {
		u_wforth_t l_wf[FW_PER_FL];
		u_lforth_t l_lf;
	} d, c;
	int i;

	CHECK_DEPTH(env, 1, "lwflip");
	d.l_lf = POP(DS);
	for (i = 0; i < FW_PER_FL; i++)
		c.l_wf[i] = d.l_wf[(FW_PER_FL - 1) - i];
	PUSH(DS, c.l_lf);
}

void
lbsplit(fcode_env_t *env)
{
	union {
		uchar_t l_bytes[sizeof (lforth_t)];
		u_lforth_t l_lf;
	} d;
	int i;

	CHECK_DEPTH(env, 1, "lbsplit");
	d.l_lf = POP(DS);
	for (i = 0; i < sizeof (lforth_t); i++)
		PUSH(DS, d.l_bytes[(sizeof (lforth_t) - 1) - i]);
}

void
bljoin(fcode_env_t *env)
{
	union {
		uchar_t l_bytes[sizeof (lforth_t)];
		u_lforth_t l_lf;
	} d;
	int i;

	CHECK_DEPTH(env, sizeof (lforth_t), "bljoin");
	for (i = 0; i < sizeof (lforth_t); i++)
		d.l_bytes[i] = POP(DS);
	PUSH(DS, (fstack_t)d.l_lf);
}

void
lbflip(fcode_env_t *env)
{
	union {
		uchar_t l_bytes[sizeof (lforth_t)];
		u_lforth_t l_lf;
	} d, c;
	int i;

	CHECK_DEPTH(env, 1, "lbflip");
	d.l_lf = POP(DS);
	for (i = 0; i < sizeof (lforth_t); i++)
		c.l_bytes[i] = d.l_bytes[(sizeof (lforth_t) - 1) - i];
	PUSH(DS, c.l_lf);
}

void
wbsplit(fcode_env_t *env)
{
	union {
		uchar_t w_bytes[sizeof (wforth_t)];
		u_wforth_t w_wf;
	} d;
	int i;

	CHECK_DEPTH(env, 1, "wbsplit");
	d.w_wf = POP(DS);
	for (i = 0; i < sizeof (wforth_t); i++)
		PUSH(DS, d.w_bytes[(sizeof (wforth_t) - 1) - i]);
}

void
bwjoin(fcode_env_t *env)
{
	union {
		uchar_t w_bytes[sizeof (wforth_t)];
		u_wforth_t w_wf;
	} d;
	int i;

	CHECK_DEPTH(env, sizeof (wforth_t), "bwjoin");
	for (i = 0; i < sizeof (wforth_t); i++)
		d.w_bytes[i] = POP(DS);
	PUSH(DS, d.w_wf);
}

void
wbflip(fcode_env_t *env)
{
	union {
		uchar_t w_bytes[sizeof (wforth_t)];
		u_wforth_t w_wf;
	} c, d;
	int i;

	CHECK_DEPTH(env, 1, "wbflip");
	d.w_wf = POP(DS);
	for (i = 0; i < sizeof (wforth_t); i++)
		c.w_bytes[i] = d.w_bytes[(sizeof (wforth_t) - 1) - i];
	PUSH(DS, c.w_wf);
}

void
upper_case(fcode_env_t *env)
{
	CHECK_DEPTH(env, 1, "upc");
	TOS = toupper(TOS);
}

void
lower_case(fcode_env_t *env)
{
	CHECK_DEPTH(env, 1, "lcc");
	TOS = tolower(TOS);
}

void
pack_str(fcode_env_t *env)
{
	char *buf;
	size_t len;
	char *str;

	CHECK_DEPTH(env, 3, "pack");
	buf = (char *)POP(DS);
	len = (size_t)POP(DS);
	str = (char *)TOS;
	TOS = (fstack_t)buf;
	*buf++ = (uchar_t)len;
	strncpy(buf, str, (len&0xff));
}

void
count_str(fcode_env_t *env)
{
	uchar_t *len;

	CHECK_DEPTH(env, 1, "count");
	len = (uchar_t *)TOS;
	TOS += 1;
	PUSH(DS, *len);
}

void
to_body(fcode_env_t *env)
{
	CHECK_DEPTH(env, 1, ">body");
	TOS = (fstack_t)(((acf_t)TOS)+1);
}

void
to_acf(fcode_env_t *env)
{
	CHECK_DEPTH(env, 1, "body>");
	TOS = (fstack_t)(((acf_t)TOS)-1);
}

/*
 * 'unloop' Fcode implementation, drop 3 loop ctrl elements off return stack.
 */
static void
unloop(fcode_env_t *env)
{
	CHECK_RETURN_DEPTH(env, 3, "unloop");
	RS -= 3;
}

/*
 * 'um*' Fcode implementation.
 */
static void
um_multiply(fcode_env_t *env)
{
	ufstack_t u1, u2;
	dforth_t d;

	CHECK_DEPTH(env, 2, "um*");
	u1 = POP(DS);
	u2 = POP(DS);
	d = u1 * u2;
	push_double(env, d);
}

/*
 * um/mod (d.lo d.hi u -- urem uquot)
 */
static void
um_slash_mod(fcode_env_t *env)
{
	u_dforth_t d;
	uint32_t u, urem, uquot;

	CHECK_DEPTH(env, 3, "um/mod");
	u = (uint32_t)POP(DS);
	d = pop_double(env);
	urem = d % u;
	uquot = d / u;
	PUSH(DS, urem);
	PUSH(DS, uquot);
}

/*
 * d+ (d1.lo d1.hi d2.lo d2.hi -- dsum.lo dsum.hi)
 */
static void
d_plus(fcode_env_t *env)
{
	dforth_t d1, d2;

	CHECK_DEPTH(env, 4, "d+");
	d2 = pop_double(env);
	d1 = pop_double(env);
	d1 += d2;
	push_double(env, d1);
}

/*
 * d- (d1.lo d1.hi d2.lo d2.hi -- ddif.lo ddif.hi)
 */
static void
d_minus(fcode_env_t *env)
{
	dforth_t d1, d2;

	CHECK_DEPTH(env, 4, "d-");
	d2 = pop_double(env);
	d1 = pop_double(env);
	d1 -= d2;
	push_double(env, d1);
}

void
set_here(fcode_env_t *env, uchar_t *new_here, char *where)
{
	if (new_here < HERE) {
		if (strcmp(where, "temporary_execute")) {
			/*
			 * Other than temporary_execute, no one should set
			 * here backwards.
			 */
			log_message(MSG_WARN, "Warning: set_here(%s) back: old:"
			    " %p new: %p\n", where, HERE, new_here);
		}
	}
	if (new_here >= env->base + dict_size)
		forth_abort(env, "Here (%p) set past dictionary end (%p)",
		    new_here, env->base + dict_size);
	HERE = new_here;
}

static void
unaligned_store(fcode_env_t *env)
{
	extern void unaligned_xstore(fcode_env_t *);

	if (sizeof (fstack_t) == sizeof (lforth_t))
		unaligned_lstore(env);
	else
		unaligned_xstore(env);
}

static void
unaligned_fetch(fcode_env_t *env)
{
	extern void unaligned_xfetch(fcode_env_t *);

	if (sizeof (fstack_t) == sizeof (lforth_t))
		unaligned_lfetch(env);
	else
		unaligned_xfetch(env);
}

void
comma(fcode_env_t *env)
{
	CHECK_DEPTH(env, 1, ",");
	DEBUGF(COMMA, dump_comma(env, ","));
	PUSH(DS, (fstack_t)HERE);
	unaligned_store(env);
	set_here(env, HERE + sizeof (fstack_t), "comma");
}

void
lcomma(fcode_env_t *env)
{
	CHECK_DEPTH(env, 1, "l,");
	DEBUGF(COMMA, dump_comma(env, "l,"));
	PUSH(DS, (fstack_t)HERE);
	unaligned_lstore(env);
	set_here(env, HERE + sizeof (u_lforth_t), "lcomma");
}

void
wcomma(fcode_env_t *env)
{
	CHECK_DEPTH(env, 1, "w,");
	DEBUGF(COMMA, dump_comma(env, "w,"));
	PUSH(DS, (fstack_t)HERE);
	unaligned_wstore(env);
	set_here(env, HERE + sizeof (u_wforth_t), "wcomma");
}

void
ccomma(fcode_env_t *env)
{
	CHECK_DEPTH(env, 1, "c,");
	DEBUGF(COMMA, dump_comma(env, "c,"));
	PUSH(DS, (fstack_t)HERE);
	cstore(env);
	set_here(env, HERE + sizeof (uchar_t), "ccomma");
}

void
token_roundup(fcode_env_t *env, char *where)
{
	if ((((token_t)HERE) & (sizeof (token_t) - 1)) != 0) {
		set_here(env, (uchar_t *)TOKEN_ROUNDUP(HERE), where);
	}
}

void
compile_comma(fcode_env_t *env)
{
	CHECK_DEPTH(env, 1, "compile,");
	DEBUGF(COMMA, dump_comma(env, "compile,"));
	token_roundup(env, "compile,");
	PUSH(DS, (fstack_t)HERE);
	unaligned_store(env);
	set_here(env, HERE + sizeof (fstack_t), "compile,");
}

void
unaligned_lfetch(fcode_env_t *env)
{
	fstack_t addr;
	int i;

	CHECK_DEPTH(env, 1, "unaligned-l@");
	addr = POP(DS);
	for (i = 0; i < sizeof (lforth_t); i++, addr++) {
		PUSH(DS, addr);
		cfetch(env);
	}
	bljoin(env);
	lbflip(env);
}

void
unaligned_lstore(fcode_env_t *env)
{
	fstack_t addr;
	int i;

	CHECK_DEPTH(env, 2, "unaligned-l!");
	addr = POP(DS);
	lbsplit(env);
	for (i = 0; i < sizeof (lforth_t); i++, addr++) {
		PUSH(DS, addr);
		cstore(env);
	}
}

void
unaligned_wfetch(fcode_env_t *env)
{
	fstack_t addr;
	int i;

	CHECK_DEPTH(env, 1, "unaligned-w@");
	addr = POP(DS);
	for (i = 0; i < sizeof (wforth_t); i++, addr++) {
		PUSH(DS, addr);
		cfetch(env);
	}
	bwjoin(env);
	wbflip(env);
}

void
unaligned_wstore(fcode_env_t *env)
{
	fstack_t addr;
	int i;

	CHECK_DEPTH(env, 2, "unaligned-w!");
	addr = POP(DS);
	wbsplit(env);
	for (i = 0; i < sizeof (wforth_t); i++, addr++) {
		PUSH(DS, addr);
		cstore(env);
	}
}

/*
 * 'lbflips' Fcode implementation.
 */
static void
lbflips(fcode_env_t *env)
{
	fstack_t len, addr;
	int i;

	CHECK_DEPTH(env, 2, "lbflips");
	len = POP(DS);
	addr = POP(DS);
	for (i = 0; i < len; i += sizeof (lforth_t),
	    addr += sizeof (lforth_t)) {
		PUSH(DS, addr);
		unaligned_lfetch(env);
		lbflip(env);
		PUSH(DS, addr);
		unaligned_lstore(env);
	}
}

/*
 * 'wbflips' Fcode implementation.
 */
static void
wbflips(fcode_env_t *env)
{
	fstack_t len, addr;
	int i;

	CHECK_DEPTH(env, 2, "wbflips");
	len = POP(DS);
	addr = POP(DS);
	for (i = 0; i < len; i += sizeof (wforth_t),
	    addr += sizeof (wforth_t)) {
		PUSH(DS, addr);
		unaligned_wfetch(env);
		wbflip(env);
		PUSH(DS, addr);
		unaligned_wstore(env);
	}
}

/*
 * 'lwflips' Fcode implementation.
 */
static void
lwflips(fcode_env_t *env)
{
	fstack_t len, addr;
	int i;

	CHECK_DEPTH(env, 2, "lwflips");
	len = POP(DS);
	addr = POP(DS);
	for (i = 0; i < len; i += sizeof (lforth_t),
	    addr += sizeof (lforth_t)) {
		PUSH(DS, addr);
		unaligned_lfetch(env);
		lwflip(env);
		PUSH(DS, addr);
		unaligned_lstore(env);
	}
}

void
base(fcode_env_t *env)
{
	PUSH(DS, (fstack_t)&env->num_base);
}

void
dot_s(fcode_env_t *env)
{
	output_data_stack(env, MSG_INFO);
}

void
state(fcode_env_t *env)
{
	PUSH(DS, (fstack_t)&env->state);
}

int
is_digit(char digit, int num_base, fstack_t *dptr)
{
	int error = 0;
	char base;

	if (num_base < 10) {
		base = '0' + (num_base-1);
	} else {
		base = 'a' + (num_base - 10);
	}

	*dptr = 0;
	if (digit > '9') digit |= 0x20;
	if (((digit < '0') || (digit > base)) ||
	    ((digit > '9') && (digit < 'a') && (num_base > 10)))
		error = 1;
	else {
		if (digit <= '9')
			digit -= '0';
		else
			digit = digit - 'a' + 10;
		*dptr = digit;
	}
	return (error);
}

void
dollar_number(fcode_env_t *env)
{
	char *buf;
	fstack_t value;
	int len, sign = 1, error = 0;

	CHECK_DEPTH(env, 2, "$number");
	buf = pop_a_string(env, &len);
	if (*buf == '-') {
		sign = -1;
		buf++;
		len--;
	}
	value = 0;
	while (len-- && !error) {
		fstack_t digit;

		if (*buf == '.') {
			buf++;
			continue;
		}
		value *= env->num_base;
		error = is_digit(*buf++, env->num_base, &digit);
		value += digit;
	}
	if (error) {
		PUSH(DS, -1);
	} else {
		value *= sign;
		PUSH(DS, value);
		PUSH(DS, 0);
	}
}

void
digit(fcode_env_t *env)
{
	fstack_t base;
	fstack_t value;

	CHECK_DEPTH(env, 2, "digit");
	base = POP(DS);
	if (is_digit(TOS, base, &value))
		PUSH(DS, 0);
	else {
		TOS = value;
		PUSH(DS, -1);
	}
}

void
space(fcode_env_t *env)
{
	PUSH(DS, ' ');
}

void
backspace(fcode_env_t *env)
{
	PUSH(DS, '\b');
}

void
bell(fcode_env_t *env)
{
	PUSH(DS, '\a');
}

void
fc_bounds(fcode_env_t *env)
{
	fstack_t lo, hi;

	CHECK_DEPTH(env, 2, "bounds");
	lo = DS[-1];
	hi = TOS;
	DS[-1] = lo+hi;
	TOS = lo;
}

void
here(fcode_env_t *env)
{
	PUSH(DS, (fstack_t)HERE);
}

void
aligned(fcode_env_t *env)
{
	ufstack_t a;

	CHECK_DEPTH(env, 1, "aligned");
	a = (TOS & (sizeof (lforth_t) - 1));
	if (a)
		TOS += (sizeof (lforth_t) - a);
}

void
instance(fcode_env_t *env)
{
	env->instance_mode |= 1;
}

void
semi(fcode_env_t *env)
{

	env->state &= ~1;
	COMPILE_TOKEN(&semi_ptr);

	/*
	 * check if we need to supress expose action;
	 * If so this is an internal word and has no link field
	 * or it is a temporary compile
	 */

	if (env->state == 0) {
		expose_acf(env, "<semi>");
	}
	if (env->state & 8) {
		env->state ^= 8;
	}
}

void
do_create(fcode_env_t *env)
{
	PUSH(DS, (fstack_t)WA);
}

void
drop(fcode_env_t *env)
{
	CHECK_DEPTH(env, 1, "drop");
	(void) POP(DS);
}

void
f_dup(fcode_env_t *env)
{
	fstack_t d;

	CHECK_DEPTH(env, 1, "dup");
	d = TOS;
	PUSH(DS, d);
}

void
over(fcode_env_t *env)
{
	fstack_t d;

	CHECK_DEPTH(env, 2, "over");
	d = DS[-1];
	PUSH(DS, d);
}

void
swap(fcode_env_t *env)
{
	fstack_t d;

	CHECK_DEPTH(env, 2, "swap");
	d = DS[-1];
	DS[-1] = DS[0];
	DS[0]  = d;
}


void
rot(fcode_env_t *env)
{
	fstack_t d;

	CHECK_DEPTH(env, 3, "rot");
	d = DS[-2];
	DS[-2] = DS[-1];
	DS[-1] = TOS;
	TOS    = d;
}

void
minus_rot(fcode_env_t *env)
{
	fstack_t d;

	CHECK_DEPTH(env, 3, "-rot");
	d = TOS;
	TOS    = DS[-1];
	DS[-1] = DS[-2];
	DS[-2] = d;
}

void
tuck(fcode_env_t *env)
{
	fstack_t d;

	CHECK_DEPTH(env, 2, "tuck");
	d = TOS;
	swap(env);
	PUSH(DS, d);
}

void
nip(fcode_env_t *env)
{
	CHECK_DEPTH(env, 2, "nip");
	swap(env);
	drop(env);
}

void
qdup(fcode_env_t *env)
{
	fstack_t d;

	CHECK_DEPTH(env, 1, "?dup");
	d = TOS;
	if (d)
		PUSH(DS, d);
}

void
depth(fcode_env_t *env)
{
	fstack_t d;

	d =  DS - env->ds0;
	PUSH(DS, d);
}

void
pick(fcode_env_t *env)
{
	fstack_t p;

	CHECK_DEPTH(env, 1, "pick");
	p = POP(DS);
	if (p < 0 || p >= (env->ds - env->ds0))
		forth_abort(env, "pick: invalid pick value: %d\n", (int)p);
	p = DS[-p];
	PUSH(DS, p);
}

void
roll(fcode_env_t *env)
{
	fstack_t d, r;

	CHECK_DEPTH(env, 1, "roll");
	r = POP(DS);
	if (r <= 0 || r >= (env->ds - env->ds0))
		forth_abort(env, "roll: invalid roll value: %d\n", (int)r);

	d = DS[-r];
	while (r) {
		DS[-r] = DS[ -(r-1) ];
		r--;
	}
	TOS = d;
}

void
two_drop(fcode_env_t *env)
{
	CHECK_DEPTH(env, 2, "2drop");
	DS -= 2;
}

void
two_dup(fcode_env_t *env)
{
	CHECK_DEPTH(env, 2, "2dup");
	DS[1] = DS[-1];
	DS[2] = TOS;
	DS += 2;
}

void
two_over(fcode_env_t *env)
{
	fstack_t a, b;

	CHECK_DEPTH(env, 4, "2over");
	a = DS[-3];
	b = DS[-2];
	PUSH(DS, a);
	PUSH(DS, b);
}

void
two_swap(fcode_env_t *env)
{
	fstack_t a, b;

	CHECK_DEPTH(env, 4, "2swap");
	a = DS[-3];
	b = DS[-2];
	DS[-3] = DS[-1];
	DS[-2] = TOS;
	DS[-1] = a;
	TOS    = b;
}

void
two_rot(fcode_env_t *env)
{
	fstack_t a, b;

	CHECK_DEPTH(env, 6, "2rot");
	a = DS[-5];
	b = DS[-4];
	DS[-5] = DS[-3];
	DS[-4] = DS[-2];
	DS[-3] = DS[-1];
	DS[-2] = TOS;
	DS[-1] = a;
	TOS    = b;
}

void
two_slash(fcode_env_t *env)
{
	CHECK_DEPTH(env, 1, "2/");
	TOS = TOS >> 1;
}

void
utwo_slash(fcode_env_t *env)
{
	CHECK_DEPTH(env, 1, "u2/");
	TOS = (ufstack_t)((ufstack_t)TOS) >> 1;
}

void
two_times(fcode_env_t *env)
{
	CHECK_DEPTH(env, 1, "2*");
	TOS = (ufstack_t)((ufstack_t)TOS) << 1;
}

void
slash_c(fcode_env_t *env)
{
	PUSH(DS, sizeof (char));
}

void
slash_w(fcode_env_t *env)
{
	PUSH(DS, sizeof (wforth_t));
}

void
slash_l(fcode_env_t *env)
{
	PUSH(DS, sizeof (lforth_t));
}

void
slash_n(fcode_env_t *env)
{
	PUSH(DS, sizeof (fstack_t));
}

void
ca_plus(fcode_env_t *env)
{
	fstack_t d;

	CHECK_DEPTH(env, 2, "ca+");
	d = POP(DS);
	TOS += d * sizeof (char);
}

void
wa_plus(fcode_env_t *env)
{
	fstack_t d;

	CHECK_DEPTH(env, 2, "wa+");
	d = POP(DS);
	TOS += d * sizeof (wforth_t);
}

void
la_plus(fcode_env_t *env)
{
	fstack_t d;

	CHECK_DEPTH(env, 2, "la+");
	d = POP(DS);
	TOS += d * sizeof (lforth_t);
}

void
na_plus(fcode_env_t *env)
{
	fstack_t d;

	CHECK_DEPTH(env, 2, "na+");
	d = POP(DS);
	TOS += d * sizeof (fstack_t);
}

void
char_plus(fcode_env_t *env)
{
	CHECK_DEPTH(env, 1, "char+");
	TOS += sizeof (char);
}

void
wa1_plus(fcode_env_t *env)
{
	CHECK_DEPTH(env, 1, "wa1+");
	TOS += sizeof (wforth_t);
}

void
la1_plus(fcode_env_t *env)
{
	CHECK_DEPTH(env, 1, "la1+");
	TOS += sizeof (lforth_t);
}

void
cell_plus(fcode_env_t *env)
{
	CHECK_DEPTH(env, 1, "cell+");
	TOS += sizeof (fstack_t);
}

void
do_chars(fcode_env_t *env)
{
	CHECK_DEPTH(env, 1, "chars");
}

void
slash_w_times(fcode_env_t *env)
{
	CHECK_DEPTH(env, 1, "/w*");
	TOS *= sizeof (wforth_t);
}

void
slash_l_times(fcode_env_t *env)
{
	CHECK_DEPTH(env, 1, "/l*");
	TOS *= sizeof (lforth_t);
}

void
cells(fcode_env_t *env)
{
	CHECK_DEPTH(env, 1, "cells");
	TOS *= sizeof (fstack_t);
}

void
do_on(fcode_env_t *env)
{
	variable_t *d;

	CHECK_DEPTH(env, 1, "on");
	d = (variable_t *)POP(DS);
	*d = -1;
}

void
do_off(fcode_env_t *env)
{
	variable_t *d;

	CHECK_DEPTH(env, 1, "off");
	d = (variable_t *)POP(DS);
	*d = 0;
}

void
fetch(fcode_env_t *env)
{
	CHECK_DEPTH(env, 1, "@");
	TOS = *((variable_t *)TOS);
}

void
lfetch(fcode_env_t *env)
{
	CHECK_DEPTH(env, 1, "l@");
	TOS = *((lforth_t *)TOS);
}

void
wfetch(fcode_env_t *env)
{
	CHECK_DEPTH(env, 1, "w@");
	TOS = *((wforth_t *)TOS);
}

void
swfetch(fcode_env_t *env)
{
	CHECK_DEPTH(env, 1, "<w@");
	TOS = *((s_wforth_t *)TOS);
}

void
cfetch(fcode_env_t *env)
{
	CHECK_DEPTH(env, 1, "c@");
	TOS = *((uchar_t *)TOS);
}

void
store(fcode_env_t *env)
{
	variable_t *dptr;

	CHECK_DEPTH(env, 2, "!");
	dptr = (variable_t *)POP(DS);
	*dptr = POP(DS);
}

void
addstore(fcode_env_t *env)
{
	variable_t *dptr;

	CHECK_DEPTH(env, 2, "+!");
	dptr = (variable_t *)POP(DS);
	*dptr = POP(DS) + *dptr;
}

void
lstore(fcode_env_t *env)
{
	lforth_t *dptr;

	CHECK_DEPTH(env, 2, "l!");
	dptr = (lforth_t *)POP(DS);
	*dptr = (lforth_t)POP(DS);
}

void
wstore(fcode_env_t *env)
{
	wforth_t *dptr;

	CHECK_DEPTH(env, 2, "w!");
	dptr = (wforth_t *)POP(DS);
	*dptr = (wforth_t)POP(DS);
}

void
cstore(fcode_env_t *env)
{
	uchar_t *dptr;

	CHECK_DEPTH(env, 2, "c!");
	dptr = (uchar_t *)POP(DS);
	*dptr = (uchar_t)POP(DS);
}

void
two_fetch(fcode_env_t *env)
{
	variable_t *d;

	CHECK_DEPTH(env, 1, "2@");
	d = (variable_t *)POP(DS);
	PUSH(DS, (fstack_t)(d + 1));
	unaligned_fetch(env);
	PUSH(DS, (fstack_t)d);
	unaligned_fetch(env);
}

void
two_store(fcode_env_t *env)
{
	variable_t *d;

	CHECK_DEPTH(env, 3, "2!");
	d = (variable_t *)POP(DS);
	PUSH(DS, (fstack_t)d);
	unaligned_store(env);
	PUSH(DS, (fstack_t)(d + 1));
	unaligned_store(env);
}

/*
 * 'move' Fcode reimplemented in fcdriver to check for mapped addresses.
 */
void
fc_move(fcode_env_t *env)
{
	void *dest, *src;
	size_t len;

	CHECK_DEPTH(env, 3, "move");
	len  = (size_t)POP(DS);
	dest = (void *)POP(DS);
	src  = (void *)POP(DS);

	memmove(dest, src, len);
}

void
fc_fill(fcode_env_t *env)
{
	void *dest;
	uchar_t val;
	size_t len;

	CHECK_DEPTH(env, 3, "fill");
	val  = (uchar_t)POP(DS);
	len  = (size_t)POP(DS);
	dest = (void *)POP(DS);
	memset(dest, val, len);
}

void
fc_comp(fcode_env_t *env)
{
	char *str1, *str2;
	size_t len;
	int res;

	CHECK_DEPTH(env, 3, "comp");
	len  = (size_t)POP(DS);
	str1 = (char *)POP(DS);
	str2 = (char *)POP(DS);
	res  = memcmp(str2, str1, len);
	if (res > 0)
		res = 1;
	else if (res < 0)
		res = -1;
	PUSH(DS, res);
}

void
set_temporary_compile(fcode_env_t *env)
{
	if (!env->state) {
		token_roundup(env, "set_temporary_compile");
		PUSH(RS, (fstack_t)HERE);
		env->state = 3;
		COMPILE_TOKEN(&do_colon);
	}
}

void
bmark(fcode_env_t *env)
{
	set_temporary_compile(env);
	env->level++;
	PUSH(DS, (fstack_t)HERE);
}

void
temporary_execute(fcode_env_t *env)
{
	uchar_t *saved_here;

	if ((env->level == 0) && (env->state & 2)) {
		fstack_t d = POP(RS);

		semi(env);

		saved_here = HERE;
		/* execute the temporary definition */
		env->state &= ~2;
		PUSH(DS, d);
		execute(env);

		/* now wind the dictionary back! */
		if (saved_here != HERE) {
			debug_msg(DEBUG_COMMA, "Ignoring set_here in"
			    " temporary_execute\n");
		} else
			set_here(env, (uchar_t *)d, "temporary_execute");
	}
}

void
bresolve(fcode_env_t *env)
{
	token_t *prev = (token_t *)POP(DS);

	env->level--;
	*prev = (token_t)HERE;
	temporary_execute(env);
}

#define	BRANCH_IP(ipp)	((token_t *)(*((token_t *)(ipp))))

void
do_bbranch(fcode_env_t *env)
{
	IP = BRANCH_IP(IP);
}

void
do_bqbranch(fcode_env_t *env)
{
	fstack_t flag;

	CHECK_DEPTH(env, 1, "b?branch");
	flag = POP(DS);
	if (flag) {
		IP++;
	} else {
		IP = BRANCH_IP(IP);
	}
}

void
do_bofbranch(fcode_env_t *env)
{
	fstack_t d;

	CHECK_DEPTH(env, 2, "bofbranch");
	d = POP(DS);
	if (d == TOS) {
		(void) POP(DS);
		IP++;
	} else {
		IP = BRANCH_IP(IP);
	}
}

void
do_bleave(fcode_env_t *env)
{
	CHECK_RETURN_DEPTH(env, 3, "do_bleave");
	(void) POP(RS);
	(void) POP(RS);
	IP = (token_t *)POP(RS);
}

void
loop_inc(fcode_env_t *env, fstack_t inc)
{
	ufstack_t a;

	CHECK_RETURN_DEPTH(env, 2, "loop_inc");

	/*
	 * Note: end condition is when the sign bit of R[0] changes.
	 */
	a = RS[0];
	RS[0] += inc;
	if (((a ^ RS[0]) & SIGN_BIT) == 0) {
		IP = BRANCH_IP(IP);
	} else {
		do_bleave(env);
	}
}

void
do_bloop(fcode_env_t *env)
{
	loop_inc(env, 1);
}

void
do_bploop(fcode_env_t *env)
{
	fstack_t d;

	CHECK_DEPTH(env, 1, "+loop");
	d = POP(DS);
	loop_inc(env, d);
}

void
loop_common(fcode_env_t *env, fstack_t ptr)
{
	short offset = get_short(env);

	COMPILE_TOKEN(ptr);
	env->level--;
	compile_comma(env);
	bresolve(env);
}

void
bloop(fcode_env_t *env)
{
	loop_common(env, (fstack_t)&do_loop_ptr);
}

void
bplusloop(fcode_env_t *env)
{
	loop_common(env, (fstack_t)&do_ploop_ptr);
}

void
common_do(fcode_env_t *env, fstack_t endpt, fstack_t start, fstack_t limit)
{
	ufstack_t i, l;

	/*
	 * Same computation as OBP, sets up so that loop_inc will terminate
	 * when the sign bit of RS[0] changes.
	 */
	i = (start - limit) - SIGN_BIT;
	l  = limit + SIGN_BIT;
	PUSH(RS, endpt);
	PUSH(RS, l);
	PUSH(RS, i);
}

void
do_bdo(fcode_env_t *env)
{
	fstack_t lo, hi;
	fstack_t endpt;

	CHECK_DEPTH(env, 2, "bdo");
	endpt = (fstack_t)BRANCH_IP(IP);
	IP++;
	lo = POP(DS);
	hi = POP(DS);
	common_do(env, endpt, lo, hi);
}

void
do_bqdo(fcode_env_t *env)
{
	fstack_t lo, hi;
	fstack_t endpt;

	CHECK_DEPTH(env, 2, "b?do");
	endpt = (fstack_t)BRANCH_IP(IP);
	IP++;
	lo = POP(DS);
	hi = POP(DS);
	if (lo == hi) {
		IP = (token_t *)endpt;
	} else {
		common_do(env, endpt, lo, hi);
	}
}

void
compile_do_common(fcode_env_t *env, fstack_t ptr)
{
	set_temporary_compile(env);
	COMPILE_TOKEN(ptr);
	bmark(env);
	COMPILE_TOKEN(0);
	bmark(env);
}

void
bdo(fcode_env_t *env)
{
	short offset = (short)get_short(env);
	compile_do_common(env, (fstack_t)&do_bdo_ptr);
}

void
bqdo(fcode_env_t *env)
{
	short offset = (short)get_short(env);
	compile_do_common(env, (fstack_t)&do_bqdo_ptr);
}

void
loop_i(fcode_env_t *env)
{
	fstack_t i;

	CHECK_RETURN_DEPTH(env, 2, "i");
	i = RS[0] + RS[-1];
	PUSH(DS, i);
}

void
loop_j(fcode_env_t *env)
{
	fstack_t j;

	CHECK_RETURN_DEPTH(env, 5, "j");
	j = RS[-3] + RS[-4];
	PUSH(DS, j);
}

void
bleave(fcode_env_t *env)
{

	if (env->state) {
		COMPILE_TOKEN(&do_leave_ptr);
	}
}

void
push_string(fcode_env_t *env, char *str, int len)
{
#define	NSTRINGS	16
	static int string_count = 0;
	static int  buflen[NSTRINGS];
	static char *buffer[NSTRINGS];
	char *dest;

	if (!len) {
		PUSH(DS, 0);
		PUSH(DS, 0);
		return;
	}
	if (len != buflen[string_count]) {
		if (buffer[string_count]) FREE(buffer[string_count]);
		buffer[ string_count ] = (char *)MALLOC(len+1);
		buflen[ string_count ] = len;
	}
	dest = buffer[ string_count++ ];
	string_count = string_count%NSTRINGS;
	memcpy(dest, str, len);
	*(dest+len) = 0;
	PUSH(DS, (fstack_t)dest);
	PUSH(DS, len);
#undef NSTRINGS
}

void
parse_word(fcode_env_t *env)
{
	int len = 0;
	char *next, *dest, *here = "";

	if (env->input) {
		here = env->input->scanptr;
		while (*here == env->input->separator) here++;
		next = strchr(here, env->input->separator);
		if (next) {
			len = next - here;
			while (*next == env->input->separator) next++;
		} else {
			len = strlen(here);
			next = here + len;
		}
		env->input->scanptr = next;
	}
	push_string(env, here, len);
}

void
install_does(fcode_env_t *env)
{
	token_t *dptr;

	dptr  = (token_t *)LINK_TO_ACF(env->lastlink);

	log_message(MSG_WARN, "install_does: Last acf at: %p\n", (void *)dptr);

	*dptr = ((token_t)(IP+1)) | 1;
}

void
does(fcode_env_t *env)
{
	token_t *dptr;

	token_roundup(env, "does");

	if (env->state) {
		COMPILE_TOKEN(&does_ptr);
		COMPILE_TOKEN(&semi_ptr);
	} else {
		dptr  = (token_t *)LINK_TO_ACF(env->lastlink);
		log_message(MSG_WARN, "does: Last acf at: %p\n", (void *)dptr);
		*dptr = ((token_t)(HERE)) | 1;
		env->state |= 1;
	}
	COMPILE_TOKEN(&do_colon);
}

void
do_current(fcode_env_t *env)
{
	debug_msg(DEBUG_CONTEXT, "CONTEXT:pushing &CURRENT\n");
	PUSH(DS, (fstack_t)&env->current);
}

void
do_context(fcode_env_t *env)
{
	debug_msg(DEBUG_CONTEXT, "CONTEXT:pushing &CONTEXT\n");
	PUSH(DS, (fstack_t)&CONTEXT);
}

void
do_definitions(fcode_env_t *env)
{
	env->current = CONTEXT;
	debug_msg(DEBUG_CONTEXT, "CONTEXT:definitions: %d/%p/%p\n",
	    env->order_depth, CONTEXT, env->current);
}

void
make_header(fcode_env_t *env, int flags)
{
	int len;
	char *name;

	name = parse_a_string(env, &len);
	header(env, name, len, flags);
}

void
do_creator(fcode_env_t *env)
{
	make_header(env, 0);
	COMPILE_TOKEN(&do_create);
	expose_acf(env, "<create>");
}

void
create(fcode_env_t *env)
{
	if (env->state) {
		COMPILE_TOKEN(&create_ptr);
	} else
		do_creator(env);
}

void
colon(fcode_env_t *env)
{
	make_header(env, 0);
	env->state |= 1;
	COMPILE_TOKEN(&do_colon);
}

void
recursive(fcode_env_t *env)
{
	expose_acf(env, "<recursive>");
}

void
compile_string(fcode_env_t *env)
{
	int len;
	uchar_t *str, *tostr;

	COMPILE_TOKEN(&quote_ptr);
	len = POP(DS);
	str = (uchar_t *)POP(DS);
	tostr = HERE;
	*tostr++ = len;
	while (len--)
		*tostr++ = *str++;
	*tostr++ = '\0';
	set_here(env, tostr, "compile_string");
	token_roundup(env, "compile_string");
}

void
run_quote(fcode_env_t *env)
{
	char osep;

	osep = env->input->separator;
	env->input->separator = '"';
	parse_word(env);
	env->input->separator = osep;

	if (env->state) {
		compile_string(env);
	}
}

void
does_vocabulary(fcode_env_t *env)
{
	CONTEXT = WA;
	debug_msg(DEBUG_CONTEXT, "CONTEXT:vocabulary: %d/%p/%p\n",
	    env->order_depth, CONTEXT, env->current);
}

void
do_vocab(fcode_env_t *env)
{
	make_header(env, 0);
	COMPILE_TOKEN(does_vocabulary);
	PUSH(DS, 0);
	compile_comma(env);
	expose_acf(env, "<vocabulary>");
}

void
do_forth(fcode_env_t *env)
{
	CONTEXT = (token_t *)(&env->forth_voc_link);
	debug_msg(DEBUG_CONTEXT, "CONTEXT:forth: %d/%p/%p\n",
	    env->order_depth, CONTEXT, env->current);
}

acf_t
voc_find(fcode_env_t *env)
{
	token_t *voc;
	token_t *dptr;
	char *find_name, *name;

	voc = (token_t *)POP(DS);
	find_name = pop_a_string(env, NULL);

	for (dptr = (token_t *)(*voc); dptr; dptr = (token_t *)(*dptr)) {
		if ((name = get_name(dptr)) == NULL)
			continue;
		if (strcmp(find_name, name) == 0) {
			debug_msg(DEBUG_VOC_FIND, "%s -> %p\n", find_name,
			    LINK_TO_ACF(dptr));
			return (LINK_TO_ACF(dptr));
		}
	}
	debug_msg(DEBUG_VOC_FIND, "%s not found\n", find_name);
	return (NULL);
}

void
dollar_find(fcode_env_t *env)
{
	acf_t acf = NULL;
	int i;

	CHECK_DEPTH(env, 2, "$find");
	for (i = env->order_depth; i >= 0 && env->order[i] && !acf; i--) {
		two_dup(env);
		PUSH(DS, (fstack_t)env->order[i]);
		acf = voc_find(env);
	}
	if (acf) {
		two_drop(env);
		PUSH(DS, (fstack_t)acf);
		PUSH(DS, TRUE);
	} else
		PUSH(DS, FALSE);
}

void
interpret(fcode_env_t *env)
{
	char *name;

	parse_word(env);
	while (TOS) {
		two_dup(env);
		dollar_find(env);
		if (TOS) {
			flag_t *flags;

			drop(env);
			nip(env);
			nip(env);
			flags = LINK_TO_FLAGS(ACF_TO_LINK(TOS));

			if ((env->state) &&
			    ((*flags & IMMEDIATE) == 0)) {
				/* Compile in references */
				compile_comma(env);
			} else {
				execute(env);
			}
		} else {
			int bad;
			drop(env);
			dollar_number(env);
			bad = POP(DS);
			if (bad) {
				two_dup(env);
				name = pop_a_string(env, NULL);
				log_message(MSG_INFO, "%s?\n", name);
				break;
			} else {
				nip(env);
				nip(env);
				literal(env);
			}
		}
		parse_word(env);
	}
	two_drop(env);
}

void
evaluate(fcode_env_t *env)
{
	input_typ *old_input = env->input;
	input_typ *eval_bufp = MALLOC(sizeof (input_typ));

	CHECK_DEPTH(env, 2, "evaluate");
	eval_bufp->separator = ' ';
	eval_bufp->maxlen = POP(DS);
	eval_bufp->buffer = (char *)POP(DS);
	eval_bufp->scanptr = eval_bufp->buffer;
	env->input = eval_bufp;
	interpret(env);
	FREE(eval_bufp);
	env->input = old_input;
}

void
make_common_access(fcode_env_t *env,
    char *name, int len,
    int ncells,
    int instance_mode,
    void (*acf_instance)(fcode_env_t *env),
    void (*acf_static)(fcode_env_t *env),
    void (*set_action)(fcode_env_t *env, int))
{
	if (instance_mode && !MYSELF) {
		system_message(env, "No instance context");
	}

	debug_msg(DEBUG_ACTIONS, "make_common_access:%s '%s', %d\n",
	    (instance_mode ? "instance" : ""),
	    (name ? name : ""), ncells);

	if (len)
		header(env, name, len, 0);
	if (instance_mode) {
		token_t *dptr;
		int offset;

		COMPILE_TOKEN(acf_instance);
		dptr = alloc_instance_data(env, INIT_DATA, ncells, &offset);
		debug_msg(DEBUG_ACTIONS, "Data: %p, offset %d\n", (char *)dptr,
		    offset);
		PUSH(DS, offset);
		compile_comma(env);
		while (ncells--)
			*dptr++ = MYSELF->data[INIT_DATA][offset++] = POP(DS);
		env->instance_mode = 0;
	} else {
		COMPILE_TOKEN(acf_static);
		while (ncells--)
			compile_comma(env);
	}
	expose_acf(env, name);
	if (set_action)
		set_action(env, instance_mode);
}

void
do_constant(fcode_env_t *env)
{
	PUSH(DS, (variable_t)(*WA));
}

void
do_crash(fcode_env_t *env)
{
	forth_abort(env, "Unitialized defer");
}

/*
 * 'behavior' Fcode retrieve execution behavior for a defer word.
 */
static void
behavior(fcode_env_t *env)
{
	acf_t defer_xt;
	token_t token;
	acf_t contents_xt;

	CHECK_DEPTH(env, 1, "behavior");
	defer_xt = (acf_t)POP(DS);
	token = *defer_xt;
	contents_xt = (token_t *)(token & ~1);
	if ((token & 1) == 0 || *contents_xt != (token_t)&do_default_action)
		forth_abort(env, "behavior: bad xt: %p indir: %x/%p\n",
		    defer_xt, token & 1, *contents_xt);
	defer_xt++;
	PUSH(DS, *((variable_t *)defer_xt));
}

void
fc_abort(fcode_env_t *env, char *type)
{
	forth_abort(env, "%s Fcode '%s' Executed", type,
	    acf_to_name(env, WA - 1));
}

void
f_abort(fcode_env_t *env)
{
	fc_abort(env, "Abort");
}

/*
 * Fcodes chosen not to support.
 */
void
fc_unimplemented(fcode_env_t *env)
{
	fc_abort(env, "Unimplemented");
}

/*
 * Fcodes that are Obsolete per P1275-1994.
 */
void
fc_obsolete(fcode_env_t *env)
{
	fc_abort(env, "Obsolete");
}

/*
 * Fcodes that are Historical per P1275-1994
 */
void
fc_historical(fcode_env_t *env)
{
	fc_abort(env, "Historical");
}

void
catch(fcode_env_t *env)
{
	error_frame *new;

	CHECK_DEPTH(env, 1, "catch");
	new = MALLOC(sizeof (error_frame));
	new->ds		= DS-1;
	new->rs		= RS;
	new->myself	= MYSELF;
	new->next	= env->catch_frame;
	new->code	= 0;
	env->catch_frame = new;
	execute(env);
	PUSH(DS, new->code);
	env->catch_frame = new->next;
	FREE(new);
}

void
throw_from_fclib(fcode_env_t *env, fstack_t errcode, char *fmt, ...)
{
	error_frame *efp;
	va_list ap;
	char msg[256];

	va_start(ap, fmt);
	vsprintf(msg, fmt, ap);

	if (errcode) {

		env->last_error = errcode;

		/*
		 * No catch frame set => fatal error
		 */
		efp = env->catch_frame;
		if (!efp)
			forth_abort(env, "%s: No catch frame", msg);

		debug_msg(DEBUG_TRACING, "throw_from_fclib: throw: %s\n", msg);

		/*
		 * Setting IP=0 will force the unwinding of the calls
		 * (see execute) which is how we will return (eventually)
		 * to the test in catch that follows 'execute'.
		 */
		DS		= efp->ds;
		RS		= efp->rs;
		MYSELF		= efp->myself;
		IP		= 0;
		efp->code	= errcode;
	}
}

void
throw(fcode_env_t *env)
{
	fstack_t t;

	CHECK_DEPTH(env, 1, "throw");
	t = POP(DS);
	if (t >= -20 && t <= 20)
		throw_from_fclib(env, t, "throw Fcode errcode: 0x%x", (int)t);
	else {
		if (t)
			log_message(MSG_ERROR, "throw: errcode: 0x%x\n",
			    (int)t);
		throw_from_fclib(env, t, "throw Fcode err: %s", (char *)t);
	}
}

void
tick_literal(fcode_env_t *env)
{
	if (env->state) {
		COMPILE_TOKEN(&tlit_ptr);
		compile_comma(env);
	}
}

void
do_tick(fcode_env_t *env)
{
	parse_word(env);
	dollar_find(env);
	invert(env);
	throw(env);
	tick_literal(env);
}

void
bracket_tick(fcode_env_t *env)
{
	do_tick(env);
}

#pragma init(_init)

static void
_init(void)
{
	fcode_env_t *env = initial_env;

	NOTICE;
	ASSERT(env);

	ANSI(0x019, 0,		"i",			loop_i);
	ANSI(0x01a, 0,		"j",			loop_j);
	ANSI(0x01d, 0,		"execute",		execute);
	ANSI(0x01e, 0,		"+",			add);
	ANSI(0x01f, 0,		"-",			subtract);
	ANSI(0x020, 0,		"*",			multiply);
	ANSI(0x021, 0,		"/",			divide);
	ANSI(0x022, 0,		"mod",			mod);
	FORTH(0,		"/mod",			slash_mod);
	ANSI(0x023, 0,		"and",			and);
	ANSI(0x024, 0,		"or",			or);
	ANSI(0x025, 0,		"xor",			xor);
	ANSI(0x026, 0,		"invert",		invert);
	ANSI(0x027, 0,		"lshift",		lshift);
	ANSI(0x028, 0,		"rshift",		rshift);
	ANSI(0x029, 0,		">>a",			rshifta);
	ANSI(0x02a, 0,		"/mod",			slash_mod);
	ANSI(0x02b, 0,		"u/mod",		uslash_mod);
	ANSI(0x02c, 0,		"negate",		negate);
	ANSI(0x02d, 0,		"abs",			f_abs);
	ANSI(0x02e, 0,		"min",			f_min);
	ANSI(0x02f, 0,		"max",			f_max);
	ANSI(0x030, 0,		">r",			to_r);
	ANSI(0x031, 0,		"r>",			from_r);
	ANSI(0x032, 0,		"r@",			rfetch);
	ANSI(0x033, 0,		"exit",			f_exit);
	ANSI(0x034, 0,		"0=",			zero_equals);
	ANSI(0x035, 0,		"0<>",			zero_not_equals);
	ANSI(0x036, 0,		"0<",			zero_less);
	ANSI(0x037, 0,		"0<=",			zero_less_equals);
	ANSI(0x038, 0,		"0>",			zero_greater);
	ANSI(0x039, 0,		"0>=",			zero_greater_equals);
	ANSI(0x03a, 0,		"<",			less);
	ANSI(0x03b, 0,		">",			greater);
	ANSI(0x03c, 0,		"=",			equals);
	ANSI(0x03d, 0,		"<>",			not_equals);
	ANSI(0x03e, 0,		"u>",			unsign_greater);
	ANSI(0x03f, 0,		"u<=",			unsign_less_equals);
	ANSI(0x040, 0,		"u<",			unsign_less);
	ANSI(0x041, 0,		"u>=",			unsign_greater_equals);
	ANSI(0x042, 0,		">=",			greater_equals);
	ANSI(0x043, 0,		"<=",			less_equals);
	ANSI(0x044, 0,		"between",		between);
	ANSI(0x045, 0,		"within",		within);
	ANSI(0x046, 0,		"drop",			drop);
	ANSI(0x047, 0,		"dup",			f_dup);
	ANSI(0x048, 0,		"over",			over);
	ANSI(0x049, 0,		"swap",			swap);
	ANSI(0x04a, 0,		"rot",			rot);
	ANSI(0x04b, 0,		"-rot",			minus_rot);
	ANSI(0x04c, 0,		"tuck",			tuck);
	ANSI(0x04d, 0,		"nip",			nip);
	ANSI(0x04e, 0,		"pick",			pick);
	ANSI(0x04f, 0,		"roll",			roll);
	ANSI(0x050, 0,		"?dup",			qdup);
	ANSI(0x051, 0,		"depth",		depth);
	ANSI(0x052, 0,		"2drop",		two_drop);
	ANSI(0x053, 0,		"2dup",			two_dup);
	ANSI(0x054, 0,		"2over",		two_over);
	ANSI(0x055, 0,		"2swap",		two_swap);
	ANSI(0x056, 0,		"2rot",			two_rot);
	ANSI(0x057, 0,		"2/",			two_slash);
	ANSI(0x058, 0,		"u2/",			utwo_slash);
	ANSI(0x059, 0,		"2*",			two_times);
	ANSI(0x05a, 0,		"/c",			slash_c);
	ANSI(0x05b, 0,		"/w",			slash_w);
	ANSI(0x05c, 0,		"/l",			slash_l);
	ANSI(0x05d, 0,		"/n",			slash_n);
	ANSI(0x05e, 0,		"ca+",			ca_plus);
	ANSI(0x05f, 0,		"wa+",			wa_plus);
	ANSI(0x060, 0,		"la+",			la_plus);
	ANSI(0x061, 0,		"na+",			na_plus);
	ANSI(0x062, 0,		"char+",		char_plus);
	ANSI(0x063, 0,		"wa1+",			wa1_plus);
	ANSI(0x064, 0,		"la1+",			la1_plus);
	ANSI(0x065, 0,		"cell+",		cell_plus);
	ANSI(0x066, 0,		"chars",		do_chars);
	ANSI(0x067, 0,		"/w*",			slash_w_times);
	ANSI(0x068, 0,		"/l*",			slash_l_times);
	ANSI(0x069, 0,		"cells",		cells);
	ANSI(0x06a, 0,		"on",			do_on);
	ANSI(0x06b, 0,		"off",			do_off);
	ANSI(0x06c, 0,		"+!",			addstore);
	ANSI(0x06d, 0,		"@",			fetch);
	ANSI(0x06e, 0,		"l@",			lfetch);
	ANSI(0x06f, 0,		"w@",			wfetch);
	ANSI(0x070, 0,		"<w@",			swfetch);
	ANSI(0x071, 0,		"c@",			cfetch);
	ANSI(0x072, 0,		"!",			store);
	ANSI(0x073, 0,		"l!",			lstore);
	ANSI(0x074, 0,		"w!",			wstore);
	ANSI(0x075, 0,		"c!",			cstore);
	ANSI(0x076, 0,		"2@",			two_fetch);
	ANSI(0x077, 0,		"2!",			two_store);
	ANSI(0x078, 0,		"move",			fc_move);
	ANSI(0x079, 0,		"fill",			fc_fill);
	ANSI(0x07a, 0,		"comp",			fc_comp);
	ANSI(0x07b, 0,		"noop",			noop);
	ANSI(0x07c, 0,		"lwsplit",		lwsplit);
	ANSI(0x07d, 0,		"wljoin",		wljoin);
	ANSI(0x07e, 0,		"lbsplit",		lbsplit);
	ANSI(0x07f, 0,		"bljoin",		bljoin);
	ANSI(0x080, 0,		"wbflip",		wbflip);
	ANSI(0x081, 0,		"upc",			upper_case);
	ANSI(0x082, 0,		"lcc",			lower_case);
	ANSI(0x083, 0,		"pack",			pack_str);
	ANSI(0x084, 0,		"count",		count_str);
	ANSI(0x085, 0,		"body>",		to_acf);
	ANSI(0x086, 0,		">body",		to_body);

	ANSI(0x089, 0,		"unloop",		unloop);

	ANSI(0x09f, 0,		".s",			dot_s);
	ANSI(0x0a0, 0,		"base",			base);
	FCODE(0x0a1, 0,		"convert",		fc_historical);
	ANSI(0x0a2, 0,		"$number",		dollar_number);
	ANSI(0x0a3, 0,		"digit",		digit);

	ANSI(0x0a9, 0,		"bl",			space);
	ANSI(0x0aa, 0,		"bs",			backspace);
	ANSI(0x0ab, 0,		"bell",			bell);
	ANSI(0x0ac, 0,		"bounds",		fc_bounds);
	ANSI(0x0ad, 0,		"here",			here);

	ANSI(0x0af, 0,		"wbsplit",		wbsplit);
	ANSI(0x0b0, 0,		"bwjoin",		bwjoin);

	P1275(0x0cb, 0,		"$find",		dollar_find);

	ANSI(0x0d0, 0,		"c,",			ccomma);
	ANSI(0x0d1, 0,		"w,",			wcomma);
	ANSI(0x0d2, 0,		"l,",			lcomma);
	ANSI(0x0d3, 0,		",",			comma);
	ANSI(0x0d4, 0,		"um*",			um_multiply);
	ANSI(0x0d5, 0,		"um/mod",		um_slash_mod);

	ANSI(0x0d8, 0,		"d+",			d_plus);
	ANSI(0x0d9, 0,		"d-",			d_minus);

	ANSI(0x0dc, 0,		"state",		state);
	ANSI(0x0de, 0,		"behavior",		behavior);
	ANSI(0x0dd, 0,		"compile,",		compile_comma);

	ANSI(0x216, 0,		"abort",		f_abort);
	ANSI(0x217, 0,		"catch",		catch);
	ANSI(0x218, 0,		"throw",		throw);

	ANSI(0x226, 0,		"lwflip",		lwflip);
	ANSI(0x227, 0,		"lbflip",		lbflip);
	ANSI(0x228, 0,		"lbflips",		lbflips);

	ANSI(0x236, 0,		"wbflips",		wbflips);
	ANSI(0x237, 0,		"lwflips",		lwflips);

	FORTH(0,		"forth",		do_forth);
	FORTH(0,		"current",		do_current);
	FORTH(0,		"context",		do_context);
	FORTH(0,		"definitions",		do_definitions);
	FORTH(0,		"vocabulary",		do_vocab);
	FORTH(IMMEDIATE,	":",			colon);
	FORTH(IMMEDIATE,	";",			semi);
	FORTH(IMMEDIATE,	"create",		create);
	FORTH(IMMEDIATE,	"does>",		does);
	FORTH(IMMEDIATE,	"recursive",		recursive);
	FORTH(0,		"parse-word",		parse_word);
	FORTH(IMMEDIATE,	"\"",			run_quote);
	FORTH(IMMEDIATE,	"order",		do_order);
	FORTH(IMMEDIATE,	"also",			do_also);
	FORTH(IMMEDIATE,	"previous",		do_previous);
	FORTH(IMMEDIATE,	"'",			do_tick);
	FORTH(IMMEDIATE,	"[']",			bracket_tick);
	FORTH(0,		"unaligned-l@",		unaligned_lfetch);
	FORTH(0,		"unaligned-l!",		unaligned_lstore);
	FORTH(0,		"unaligned-w@",		unaligned_wfetch);
	FORTH(0,		"unaligned-w!",		unaligned_wstore);
}
