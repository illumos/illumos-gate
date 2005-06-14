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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcode/private.h>
#include <fcdriver/fcdriver.h>

#define	LF_PER_XF	(sizeof (xforth_t)/sizeof (lforth_t))
#define	WF_PER_XF	(sizeof (xforth_t)/sizeof (wforth_t))

void unaligned_xfetch(fcode_env_t *);
void unaligned_xstore(fcode_env_t *);
static void xbsplit(fcode_env_t *);

xforth_t
pop_xforth(fcode_env_t *env)
{
	if (sizeof (xforth_t) == sizeof (fstack_t))
		return (POP(DS));
	return ((xforth_t)pop_double(env));
}

xforth_t
peek_xforth(fcode_env_t *env)
{
	xforth_t d;

	d = pop_xforth(env);
	push_xforth(env, d);
	return (d);
}

void
push_xforth(fcode_env_t *env, xforth_t a)
{
	if (sizeof (xforth_t) == sizeof (fstack_t))
		PUSH(DS, a);
	else
		push_double(env, (dforth_t)a);
}

/*
 * bxjoin     ( b.lo b.2 b.3 b.4 b.5 b.6 b.7 b.hi -- o )
 */
static void
bxjoin(fcode_env_t *env)
{
	union {
		uchar_t b_bytes[sizeof (xforth_t)];
		xforth_t b_xf;
	} b;
	int i;

	CHECK_DEPTH(env, sizeof (xforth_t), "bxjoin");
	for (i = 0; i < sizeof (xforth_t); i++)
		b.b_bytes[i] = POP(DS);
	push_xforth(env, b.b_xf);
}

/*
 * <l@        ( qaddr -- n )
 */
static void
lsfetch(fcode_env_t *env)
{
	s_lforth_t *addr;
	xforth_t a;

	CHECK_DEPTH(env, 1, "<l@");
	addr = (s_lforth_t *)POP(DS);
	a = *addr;
	push_xforth(env, a);
}

/*
 * lxjoin     ( quad.lo quad.hi -- o )
 */
static void
lxjoin(fcode_env_t *env)
{
	union {
		lforth_t b_lf[LF_PER_XF];
		xforth_t b_xf;
	} b;
	int i;

	CHECK_DEPTH(env, LF_PER_XF, "lxjoin");
	for (i = 0; i < LF_PER_XF; i++)
		b.b_lf[i] = POP(DS);
	push_xforth(env, b.b_xf);
}

/*
 * wxjoin     ( w.lo w.2 w.3 w.hi -- o )
 */
static void
wxjoin(fcode_env_t *env)
{
	union {
		wforth_t b_wf[WF_PER_XF];
		xforth_t b_xf;
	} b;
	int i;

	CHECK_DEPTH(env, WF_PER_XF, "wxjoin");
	for (i = 0; i < WF_PER_XF; i++)
		b.b_wf[i] = POP(DS);
	push_xforth(env, b.b_xf);
}

/*
 * x,         ( o -- )
 */
static void
xcomma(fcode_env_t *env)
{
	CHECK_DEPTH(env, 1, "x,");
	DEBUGF(COMMA, dump_comma(env, "x,"));
	PUSH(DS, (fstack_t)HERE);
	unaligned_xstore(env);
	set_here(env, HERE + sizeof (xforth_t), "xcomma");
}

/*
 * x@         ( xaddr  -- o )
 */
void
xfetch(fcode_env_t *env)
{
	xforth_t *addr;
	xforth_t a;

	CHECK_DEPTH(env, 1, "x@");
	addr = (xforth_t *)POP(DS);
	a = *addr;
	push_xforth(env, a);
}

/*
 * x!         ( o xaddr -- )
 */
void
xstore(fcode_env_t *env)
{
	xforth_t *addr;
	xforth_t a;

	CHECK_DEPTH(env, 2, "x!");
	addr = (xforth_t *)POP(DS);
	a = pop_xforth(env);
	*addr = a;
}

/*
 * /x         ( -- n )
 */
static void
slash_x(fcode_env_t *env)
{
	PUSH(DS, sizeof (xforth_t));
}

/*
 * /x*        ( nu1 -- nu2 )
 */
static void
slash_x_times(fcode_env_t *env)
{
	CHECK_DEPTH(env, 1, "/x*");
	TOS *= sizeof (xforth_t);
}

/*
 * xa+        ( addr1 index -- addr2 )
 */
static void
xa_plus(fcode_env_t *env)
{
	fstack_t index;

	CHECK_DEPTH(env, 2, "xa+");
	index = POP(DS);
	TOS += index * sizeof (xforth_t);
}

/*
 * xa1+       ( addr1 -- addr2 )
 */
static void
xa_one_plus(fcode_env_t *env)
{
	CHECK_DEPTH(env, 1, "xa1+");
	TOS += sizeof (xforth_t);
}

/*
 * xbflip     ( oct1 -- oct2 )
 */
void
xbflip(fcode_env_t *env)
{
	union {
		uchar_t b_bytes[sizeof (xforth_t)];
		xforth_t b_xf;
	} b, c;
	int i;

	CHECK_DEPTH(env, 1, "xbflip");
	b.b_xf = pop_xforth(env);
	for (i = 0; i < sizeof (xforth_t); i++)
		c.b_bytes[i] = b.b_bytes[(sizeof (xforth_t) - 1) - i];
	push_xforth(env, c.b_xf);
}

void
unaligned_xfetch(fcode_env_t *env)
{
	fstack_t addr;
	int i;

	CHECK_DEPTH(env, 1, "unaligned-x@");
	addr = POP(DS);
	for (i = 0; i < sizeof (xforth_t); i++, addr++) {
		PUSH(DS, addr);
		cfetch(env);
	}
	bxjoin(env);
	xbflip(env);
}

void
unaligned_xstore(fcode_env_t *env)
{
	fstack_t addr;
	int i;

	CHECK_DEPTH(env, 2, "unaligned-x!");
	addr = POP(DS);
	xbsplit(env);
	for (i = 0; i < sizeof (xforth_t); i++, addr++) {
		PUSH(DS, addr);
		cstore(env);
	}
}

/*
 * xbflips    ( xaddr len -- )
 */
static void
xbflips(fcode_env_t *env)
{
	fstack_t len, addr;
	int i;

	CHECK_DEPTH(env, 2, "xbflips");
	len = POP(DS);
	addr = POP(DS);
	for (i = 0; i < len; i += sizeof (xforth_t),
	    addr += sizeof (xforth_t)) {
		PUSH(DS, addr);
		unaligned_xfetch(env);
		xbflip(env);
		PUSH(DS, addr);
		unaligned_xstore(env);
	}
}

/*
 * xbsplit    ( o -- b.lo b.2 b.3 b.4 b.5 b.6 b.7 b.hi )
 */
static void
xbsplit(fcode_env_t *env)
{
	union {
		uchar_t b_bytes[sizeof (xforth_t)];
		xforth_t b_xf;
	} b;
	int i;

	CHECK_DEPTH(env, 1, "xbsplit");
	b.b_xf = pop_xforth(env);
	for (i = 0; i < sizeof (xforth_t); i++)
		PUSH(DS, b.b_bytes[(sizeof (xforth_t) - 1) - i]);
}

/*
 * xlflip     ( oct1 -- oct2 )
 */
void
xlflip(fcode_env_t *env)
{
	union {
		lforth_t b_lf[LF_PER_XF];
		xforth_t b_xf;
	} b, c;
	int i;

	CHECK_DEPTH(env, 1, "xlflip");
	b.b_xf = pop_xforth(env);
	for (i = 0; i < LF_PER_XF; i++)
		c.b_lf[i] = b.b_lf[(LF_PER_XF - 1) - i];
	push_xforth(env, c.b_xf);
}

/*
 * xlflips    ( xaddr len -- )
 */
static void
xlflips(fcode_env_t *env)
{
	fstack_t len, addr;
	int i;

	CHECK_DEPTH(env, 2, "xlflips");
	len = POP(DS);
	addr = POP(DS);
	for (i = 0; i < len; i += sizeof (xforth_t),
	    addr += sizeof (xforth_t)) {
		PUSH(DS, addr);
		unaligned_xfetch(env);
		xlflip(env);
		PUSH(DS, addr);
		unaligned_xstore(env);
	}
}

/*
 * xlsplit    ( o -- quad.lo quad.hi )
 */
static void
xlsplit(fcode_env_t *env)
{
	union {
		lforth_t b_lf[LF_PER_XF];
		xforth_t b_xf;
	} b;
	int i;

	CHECK_DEPTH(env, 1, "xlsplit");
	b.b_xf = pop_xforth(env);
	for (i = 0; i < LF_PER_XF; i++)
		PUSH(DS, b.b_lf[(LF_PER_XF - 1) - i]);
}


/*
 * xwflip     ( oct1 -- oct2 )
 */
static void
xwflip(fcode_env_t *env)
{
	union {
		wforth_t b_wf[WF_PER_XF];
		xforth_t b_xf;
	} b, c;
	int i;

	CHECK_DEPTH(env, 1, "xwflip");
	b.b_xf = pop_xforth(env);
	for (i = 0; i < WF_PER_XF; i++)
		c.b_wf[i] = b.b_wf[(WF_PER_XF - 1) - i];
	push_xforth(env, c.b_xf);
}

/*
 * xwflips    ( xaddr len -- )
 */
static void
xwflips(fcode_env_t *env)
{
	fstack_t len, addr;
	int i;

	CHECK_DEPTH(env, 2, "xwflips");
	len = POP(DS);
	addr = POP(DS);
	for (i = 0; i < len; i += sizeof (xforth_t),
	    addr += sizeof (xforth_t)) {
		PUSH(DS, addr);
		unaligned_xfetch(env);
		xwflip(env);
		PUSH(DS, addr);
		unaligned_xstore(env);
	}
}

/*
 * xwsplit    ( o -- w.lo w.2 w.3 w.hi )
 */
static void
xwsplit(fcode_env_t *env)
{
	union {
		wforth_t b_wf[WF_PER_XF];
		xforth_t b_xf;
	} b;
	int i;

	CHECK_DEPTH(env, 1, "xwsplit");
	b.b_xf = pop_xforth(env);
	for (i = 0; i < WF_PER_XF; i++)
		PUSH(DS, b.b_wf[(WF_PER_XF - 1) - i]);
}

#pragma init(_init)

static void
_init(void)
{
	fcode_env_t *env = initial_env;

	ASSERT(env);
	NOTICE;
	P1275(0x241,	0,	"bxjoin",		bxjoin);
	P1275(0x242,	0,	"<l@",			lsfetch);
	P1275(0x243,	0,	"lxjoin",		lxjoin);
	P1275(0x244,	0,	"wxjoin",		wxjoin);
	P1275(0x245,	0,	"x,",			xcomma);
	P1275(0x246,	0,	"x@",			xfetch);
	P1275(0x247,	0,	"x!",			xstore);
	P1275(0x248,	0,	"/x",			slash_x);
	P1275(0x249,	0,	"/x*",			slash_x_times);
	P1275(0x24a,	0,	"xa+",			xa_plus);
	P1275(0x24b,	0,	"xa1+",			xa_one_plus);
	P1275(0x24c,	0,	"xbflip",		xbflip);
	P1275(0x24d,	0,	"xbflips",		xbflips);
	P1275(0x24e,	0,	"xbsplit",		xbsplit);
	P1275(0x24f,	0,	"xlflip",		xlflip);
	P1275(0x250,	0,	"xlflips",		xlflips);
	P1275(0x251,	0,	"xlsplit",		xlsplit);
	P1275(0x252,	0,	"xwflip",		xwflip);
	P1275(0x253,	0,	"xwflips",		xwflips);
	P1275(0x254,	0,	"xwsplit",		xwsplit);

	FORTH(0,		"unaligned-x@",		unaligned_xfetch);
	FORTH(0,		"unaligned-x!",		unaligned_xstore);
}
