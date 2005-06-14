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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Routines to capture processor-dependencies in event specification.
 */

#include <sys/types.h>
#include <string.h>
#include <strings.h>
#include <alloca.h>
#include <stdlib.h>
#include <stdio.h>
#include <libintl.h>
#include <assert.h>
#include <errno.h>

#include "libcpc.h"
#include "libcpc_impl.h"

/*
 * Event specifications for Pentium performance counters are based
 * on the content of a getsubopt-like string.
 * The string should contain something that looks like this:
 *
 *	pic0=<eventspec>,pic1=<eventspec>
 *		[,cmask0=<maskspec>][,cmask1=<maskspec>]
 *		[,umask0=<maskspec>][,umask1=<maskspec>]
 *		[,inv[0|1]][,noedge[0|1]]
 *		[,sys[0|1]][,nouser[0|1]]
 *
 * For example:
 *	pic0=data_mem_refs,pic1=l2_ld,sys
 * or
 *	pic0=l2_ld,pic1=bus_drdy_clocks,umask1=0x20,nouser1
 *
 * By default, user event counting is enabled, system event counting
 * is disabled.
 *
 * Note that Pentium and Pentium Pro have different event specifications.
 *
 * The two events must be named.  The names can be ascii or
 * a decimal, octal or hexadecimal number as parsed by strtol(3C).
 *
 * The routine counts the number of errors encountered while parsing
 * the string, if no errors are encountered, the event handle is
 * returned.
 */

const char *
cpc_getusage(int cpuver)
{
	switch (cpuver) {
	case CPC_PENTIUM_PRO_MMX:
	case CPC_PENTIUM_PRO:
		return ("pic0=<event0>,pic1=<event1> "
		    "[,sys[0|1]] "
		    "[,nouser[0|1]] "
		    "[,noedge[0|1]] "
		    "[,pc[0|1]] "
		    "[,int[0|1]] "
		    "[,inv[0|1]] "
		    "[,cmask[0|1]=<maskspec>] "
		    "[,umask[0|1]=<maskspec>] ");
	case CPC_PENTIUM_MMX:
	case CPC_PENTIUM:
		return ("pic0=<event0>,pic1=<event1> "
		    "[,sys[0|1]] "
		    "[,nouser[0|1]] "
		    "[,noedge[0|1]] "
		    "[,pc[0|1]]");
	default:
		return (NULL);
	}
}

struct keyval {
	char *kv_token;
	int (*kv_action)(const char *,
	    const struct keyval *, int, char *, uint32_t *);
	uint_t kv_regno;
	uint32_t kv_mask;
	int kv_shift;
};

/*ARGSUSED*/
static int
eightbits(const char *fn,
    const struct keyval *kv, int cpuver, char *value, uint32_t *bits)
{
	char *eptr = NULL;
	long l;

	if (value == NULL) {
		__cpc_error(fn, gettext("missing '%s' value\n"),
		    kv->kv_token);
		return (-1);
	}
	l = strtol(value, &eptr, 0);
	if (value == eptr || l < 0 || l > UINT8_MAX) {
		__cpc_error(fn, gettext("bad '%s' value\n"), kv->kv_token);
		return (-1);
	}
	bits[kv->kv_regno] |= ((uint8_t)l & kv->kv_mask) << kv->kv_shift;
	return (0);
}

static int
picbits(const char *fn,
    const struct keyval *kv, int cpuver, char *value, uint32_t *bits)
{
	uint8_t val8;
	uint_t regno;

	regno = strcmp(kv->kv_token, "pic0") == 0 ? 0 : 1;

	if (value == NULL) {
		__cpc_error(fn, gettext("missing '%s' value\n"),
		    kv->kv_token);
		return (-1);
	}

	if (__cpc_name_to_reg(cpuver, regno, value, &val8) != 0) {
		switch (cpuver) {
		case CPC_PENTIUM_PRO_MMX:
		case CPC_PENTIUM_PRO:
			assert(kv->kv_regno == regno);
			__cpc_error(fn, gettext(
			    "PerfCtr%d cannot measure '%s' on this cpu\n"),
			    regno, value);
			break;
		case CPC_PENTIUM_MMX:
		case CPC_PENTIUM:
			assert(kv->kv_regno == 0);
			__cpc_error(fn, gettext(
			    "CTR%d cannot measure '%s' on this cpu\n"),
			    regno, value);
			break;
		}
		return (-1);
	}
	bits[kv->kv_regno] |= (val8 & kv->kv_mask) << kv->kv_shift;
	return (0);
}

/*ARGSUSED2*/
static int
bitclr(const char *fn,
    const struct keyval *kv, int cpuver, char *value, uint32_t *bits)
{
	if (value != NULL) {
		__cpc_error(fn, gettext("bad arg to '%s'\n"), kv->kv_token);
		return (-1);
	}
	bits[kv->kv_regno] &= ~(kv->kv_mask << kv->kv_shift);
	return (0);
}

/*ARGSUSED2*/
static int
bitset(const char *fn,
    const struct keyval *kv, int cpuver, char *value, uint32_t *bits)
{
	if (value != NULL) {
		__cpc_error(fn, gettext("bad arg to '%s'\n"), kv->kv_token);
		return (-1);
	}
	bits[kv->kv_regno] |= (kv->kv_mask << kv->kv_shift);
	return (0);
}

static int
nextpair(const char *fn,
    const struct keyval *kv, int cpuver, char *value, uint32_t *bits)
{
	int rv;

	if (value != NULL) {
		__cpc_error(fn, gettext("bad arg to '%s'\n"), kv->kv_token);
		return (-1);
	}
	kv++;
	if ((rv = kv->kv_action(fn, kv, cpuver, value, bits)) != 0)
		return (rv);
	kv++;
	return (kv->kv_action(fn, kv, cpuver, value, bits));
}

/*
 * This token table must match the keyval tables below.
 */

static char * const tokens[] = {
#define	D_pic0		0
	"pic0",			/* takes a valid event name */
#define	D_pic1		1
	"pic1",			/* takes a valid event name */
#define	D_nouser	2
	"nouser",		/* disables user counts */
#define	D_nouser0	3
	"nouser0",
#define	D_nouser1	4
	"nouser1",
#define	D_sys		5
	"sys",			/* enables system counts */
#define	D_sys0		6
	"sys0",
#define	D_sys1		7
	"sys1",
#define	D_noedge	8
	"noedge",		/* disable edge detect */
#define	D_noedge0	9
	"noedge0",
#define	D_noedge1	10
	"noedge1",
#define	D_pc		11
	"pc",			/* sets pin control high */
#define	D_pc0		12
	"pc0",
#define	D_pc1		13
	"pc1",

/*
 * These additional keywords are for Pentium Pro / Pentium II machines.
 */
#define	D_int		14
	"int",			/* enable interrupt on counter overflow */
#define	D_int0		15
	"int0",
#define	D_int1		16
	"int1",
#define	D_inv		17
	"inv",			/* invert cmask comparison */
#define	D_inv0		18
	"inv0",
#define	D_inv1		19
	"inv1",
#define	D_umask0	20
	"umask0",		/* PerfCtr0 unit mask */
#define	D_umask1	21
	"umask1",		/* PerfCtr1 unit mask */
#define	D_cmask0	22
	"cmask0",		/* PerfCtr0 counter mask */
#define	D_cmask1	23
	"cmask1",		/* PerfCtr1 counter mask */
	NULL
};

static const struct keyval p6_keyvals[] = {
	{ "pic0",	picbits,	0,
		CPC_P6_PES_PIC0_MASK,	0 },
	{ "pic1",	picbits,	1,
		CPC_P6_PES_PIC1_MASK,	0 },
	{ "nouser",	nextpair },
	{ "nouser0",	bitclr,		0,
		UINT32_C(1),		CPC_P6_PES_USR },
	{ "nouser1",	bitclr,		1,
		UINT32_C(1),		CPC_P6_PES_USR },
	{ "sys",	nextpair },
	{ "sys0",	bitset,		0,
		UINT32_C(1),		CPC_P6_PES_OS },
	{ "sys1",	bitset,		1,
		UINT32_C(1),		CPC_P6_PES_OS },
	{ "noedge",	nextpair },
	{ "noedge0",	bitclr,		0,
		UINT32_C(1),		CPC_P6_PES_E },
	{ "noedge1",	bitclr,		1,
		UINT32_C(1),		CPC_P6_PES_E },
	{ "pc",		nextpair },
	{ "pc0",	bitset,		0,
		UINT32_C(1),		CPC_P6_PES_PC },
	{ "pc1",	bitset,		1,
		UINT32_C(1),		CPC_P6_PES_PC },
	{ "int",	nextpair },
	{ "int0",	bitset,		0,
		UINT32_C(1),		CPC_P6_PES_INT },
	{ "int1",	bitset,		1,
		UINT32_C(1),		CPC_P6_PES_INT },
	{ "inv",	nextpair },
	{ "inv0",	bitset,		0,
		UINT32_C(1),		CPC_P6_PES_INV },
	{ "inv1",	bitset,		1,
		UINT32_C(1),		CPC_P6_PES_INV },
	{ "umask0",	eightbits,	0,
		CPC_P6_PES_UMASK_MASK,	CPC_P6_PES_UMASK_SHIFT },
	{ "umask1",	eightbits,	1,
		CPC_P6_PES_UMASK_MASK,	CPC_P6_PES_UMASK_SHIFT },
	{ "cmask0",	eightbits,	0,
		CPC_P6_PES_CMASK_MASK,	CPC_P6_PES_CMASK_SHIFT },
	{ "cmask1",	eightbits,	1,
		CPC_P6_PES_CMASK_MASK,	CPC_P6_PES_CMASK_SHIFT },
};

/*
 * Note that this table -must- be an identically indexed
 * subset of p6_keyvals.
 */
static const struct keyval p5_keyvals[] = {
	{ "pic0",	picbits,	0,
		CPC_P5_CESR_ES0_MASK,	CPC_P5_CESR_ES0_SHIFT },
	{ "pic1",	picbits,	0,
		CPC_P5_CESR_ES1_MASK,	CPC_P5_CESR_ES1_SHIFT },
	{ "nouser",	nextpair },
	{ "nouser0",	bitclr,		0,
		UINT32_C(1),		CPC_P5_CESR_USR0 },
	{ "nouser1",	bitclr,		0,
		UINT32_C(1),		CPC_P5_CESR_USR1 },
	{ "sys",	nextpair },
	{ "sys0",	bitset,		0,
		UINT32_C(1),		CPC_P5_CESR_OS0 },
	{ "sys1",	bitset,		0,
		UINT32_C(1),		CPC_P5_CESR_OS1 },
	{ "noedge",	nextpair },
	{ "noedge0",	bitset,		0,
		UINT32_C(1),		CPC_P5_CESR_CLK0 },
	{ "noedge1",	bitset,		0,
		UINT32_C(1),		CPC_P5_CESR_CLK1 },
	{ "pc",		nextpair },
	{ "pc0",	bitset,		0,
		UINT32_C(1),		CPC_P5_CESR_PC0 },
	{ "pc1",	bitset,		0,
		UINT32_C(1),		CPC_P5_CESR_PC1 },
};

#if !defined(NDEBUG)
#pragma	init(__tablecheck)

static void
__tablecheck(void)
{
	uint_t ntokens = sizeof (tokens) / sizeof (tokens[0]) - 1;
	uint_t p6_nkeys = sizeof (p6_keyvals) / sizeof (p6_keyvals[0]);
	uint_t p5_nkeys = sizeof (p5_keyvals) / sizeof (p5_keyvals[0]);
	uint_t n;

	assert(ntokens == p6_nkeys);
	for (n = 0; n < ntokens; n++)
		assert(strcmp(tokens[n], p6_keyvals[n].kv_token) == 0);
	assert(p6_nkeys >= p5_nkeys);
	for (n = 0; n < p5_nkeys; n++)
		assert(strcmp(tokens[n], p5_keyvals[n].kv_token) == 0);
}

#endif	/* !NDEBUG */

int
cpc_strtoevent(int cpuver, const char *spec, cpc_event_t *event)
{
	static const char fn[] = "strtoevent";
	char *value;
	char *pic[2];
	char *opts;
	int errcnt = 0;
	uint_t ntokens;
	const struct keyval *keyvals;
	uint32_t *bits;

	if (spec == NULL)
		return (errcnt = 1);

	bzero(event, sizeof (*event));
	switch (event->ce_cpuver = cpuver) {
	case CPC_PENTIUM_PRO_MMX:
	case CPC_PENTIUM_PRO:
		keyvals = p6_keyvals;
		ntokens = sizeof (p6_keyvals) / sizeof (p6_keyvals[0]);
		bits = &event->ce_pes[0];
		bits[0] = bits[1] =
		    (1u << CPC_P6_PES_USR) | (1u << CPC_P6_PES_E);
		break;
	case CPC_PENTIUM_MMX:
	case CPC_PENTIUM:
		keyvals = p5_keyvals;
		ntokens = sizeof (p5_keyvals) / sizeof (p5_keyvals[0]);
		bits = &event->ce_cesr;
		bits[0] =
		    (1u << CPC_P5_CESR_USR0) | (1u << CPC_P5_CESR_USR1);
		break;
	default:
		return (errcnt = 1);
	}

	pic[0] = pic[1] = NULL;

	opts = strcpy(alloca(strlen(spec) + 1), spec);
	while (*opts != '\0') {
		const struct keyval *kv;
		int idx = getsubopt(&opts, tokens, &value);

		if (idx >= 0 && idx < ntokens) {
			kv = &keyvals[idx];
			if (kv->kv_action(fn, kv, cpuver, value, bits) != 0) {
				errcnt++;
				break;
			}

			if (idx == D_pic0) {
				if (pic[0] != NULL) {
					__cpc_error(fn,
					    "repeated '%s' token\n",
					    tokens[idx]);
					errcnt++;
					break;
				}
				pic[0] = value;
			} else if (idx == D_pic1) {
				if (pic[1] != NULL) {
					__cpc_error(fn,
					    "repeated '%s' token\n",
					    tokens[idx]);
					errcnt++;
					break;
				}
				pic[1] = value;
			}
		} else if (idx == -1) {
			/*
			 * The token given wasn't recognized.
			 * See if it was an implicit pic specification..
			 */
			if (pic[0] == NULL) {
				kv = &keyvals[D_pic0];
				if (kv->kv_action(fn,
				    kv, cpuver, value, bits) != 0) {
					errcnt++;
					break;
				}
				pic[0] = value;
			} else if (pic[1] == NULL) {
				kv = &keyvals[D_pic1];
				if (kv->kv_action(fn,
				    kv, cpuver, value, bits) != 0) {
					errcnt++;
					break;
				}
				pic[1] = value;
			} else {
				__cpc_error(fn,
				    gettext("bad token '%s'\n"), value);
				errcnt++;
				break;
			}
		} else {
			if (idx >= 0 &&
			    idx < sizeof (tokens) / sizeof (tokens[0]))
				__cpc_error(fn,
				    gettext("bad token '%s'\n"), tokens[idx]);
			else
				__cpc_error(fn, gettext("bad token\n"));
			errcnt++;
			break;
		}
	}

	if (pic[0] == NULL || pic[1] == NULL) {
		__cpc_error(fn, gettext("two events must be specified\n"));
		errcnt++;
	}

	return (errcnt);
}

/*
 * Return a printable description of the control registers.
 *
 * This routine should always succeed (notwithstanding heap problems),
 * but may not be able to correctly decode the registers, if, for
 * example, a new processor is under test.
 *
 * The caller is responsible for free(3c)ing the string returned.
 */

static void
flagstostr(char *buf, int flag0, int flag1, int defvalue, char *tok)
{
	buf += strlen(buf);
	if (flag0 != defvalue) {
		if (flag1 != defvalue)
			(void) sprintf(buf, ",%s", tok);
		else
			(void) sprintf(buf, ",%s0", tok);
	} else {
		if (flag1 != defvalue)
			(void) sprintf(buf, ",%s1", tok);
	}
}

static void
masktostr(char *buf, uint8_t bits, char *tok)
{
	if (bits != 0) {
		buf += strlen(buf);
		(void) sprintf(buf, ",%s=0x%x", tok, bits);
	}
}

static char *
val8tostr(uint8_t bits)
{
	char buf[2 + 2 + 1];	/* 0x %2x \0 */
	(void) snprintf(buf, sizeof (buf), "0x%x", bits);
	return (strdup(buf));
}

static char *
regtostr(int cpuver, int regno, uint8_t bits)
{
	const char *sname;

	if ((sname = __cpc_reg_to_name(cpuver, regno, bits)) != NULL)
		return (strdup(sname));
	return (val8tostr(bits));
}

struct xpes {
	uint8_t cmask, umask, evsel;
	int usr, sys, edge, inv, irupt, pc;
};

/*ARGSUSED1*/
static void
unmake_pes(uint32_t pes, int cpuver, struct xpes *xpes)
{
	xpes->cmask = (uint8_t)(pes >> CPC_P6_PES_CMASK_SHIFT);
	xpes->pc = (pes >> CPC_P6_PES_PC) & 1u;
	xpes->inv = (pes >> CPC_P6_PES_INV) & 1u;
	xpes->irupt = (pes >> CPC_P6_PES_INT) & 1u;
	xpes->edge = (pes >> CPC_P6_PES_E) & 1u;
	xpes->sys = (pes >> CPC_P6_PES_OS) & 1u;
	xpes->usr = (pes >> CPC_P6_PES_USR) & 1u;
	xpes->umask = (uint8_t)(pes >> CPC_P6_PES_UMASK_SHIFT);
	xpes->evsel = (uint8_t)pes;
}

struct xcesr {
	uint8_t evsel[2];
	int usr[2], sys[2], clk[2], pc[2];
};

/*ARGSUSED1*/
static void
unmake_cesr(uint32_t cesr, int cpuver, struct xcesr *xcesr)
{
	xcesr->evsel[0] = (cesr >> CPC_P5_CESR_ES0_SHIFT) &
	    CPC_P5_CESR_ES0_MASK;
	xcesr->evsel[1] = (cesr >> CPC_P5_CESR_ES1_SHIFT) &
	    CPC_P5_CESR_ES1_MASK;
	xcesr->usr[0] = (cesr >> CPC_P5_CESR_USR0) & 1u;
	xcesr->usr[1] = (cesr >> CPC_P5_CESR_USR1) & 1u;
	xcesr->sys[0] = (cesr >> CPC_P5_CESR_OS0) & 1u;
	xcesr->sys[1] = (cesr >> CPC_P5_CESR_OS1) & 1u;
	xcesr->clk[0] = (cesr >> CPC_P5_CESR_CLK0) & 1u;
	xcesr->clk[1] = (cesr >> CPC_P5_CESR_CLK1) & 1u;
	xcesr->pc[0] = (cesr >> CPC_P5_CESR_PC0) & 1u;
	xcesr->pc[1] = (cesr >> CPC_P5_CESR_PC1) & 1u;
	/*
	 * If usr and sys are both disabled, the counter is disabled.
	 */
	if (xcesr->usr[0] == 0 && xcesr->sys[0] == 0)
		xcesr->clk[0] = 0;
	if (xcesr->usr[1] == 0 && xcesr->sys[1] == 0)
		xcesr->clk[1] = 0;
}

char *
cpc_eventtostr(cpc_event_t *event)
{
	char *pic[2];
	char buffer[1024];
	int cpuver = event->ce_cpuver;

	switch (cpuver) {
	case CPC_PENTIUM_PRO_MMX:
	case CPC_PENTIUM_PRO:
	{
		struct xpes xpes[2];

		unmake_pes(event->ce_pes[0], cpuver, &xpes[0]);
		if ((pic[0] = regtostr(cpuver, 0, xpes[0].evsel)) == NULL)
			return (NULL);

		unmake_pes(event->ce_pes[1], cpuver, &xpes[1]);
		if ((pic[1] = regtostr(cpuver, 1, xpes[1].evsel)) == NULL) {
			free(pic[0]);
			return (NULL);
		}
		(void) snprintf(buffer, sizeof (buffer), "%s=%s,%s=%s",
		    tokens[D_pic0], pic[0], tokens[D_pic1], pic[1]);
		free(pic[1]);
		free(pic[0]);
		masktostr(buffer, xpes[0].cmask, tokens[D_cmask0]);
		masktostr(buffer, xpes[1].cmask, tokens[D_cmask1]);
		masktostr(buffer, xpes[0].umask, tokens[D_umask0]);
		masktostr(buffer, xpes[1].umask, tokens[D_umask1]);
		flagstostr(buffer,
		    xpes[0].usr, xpes[1].usr, 1, tokens[D_nouser]);
		flagstostr(buffer,
		    xpes[0].sys, xpes[1].sys, 0, tokens[D_sys]);
		flagstostr(buffer,
		    xpes[0].edge, xpes[1].edge, 1, tokens[D_noedge]);
		flagstostr(buffer,
		    xpes[0].irupt, xpes[1].irupt, 0, tokens[D_int]);
		flagstostr(buffer,
		    xpes[0].inv, xpes[1].inv, 0, tokens[D_inv]);
		flagstostr(buffer,
		    xpes[0].pc, xpes[1].pc, 0, tokens[D_pc]);
	}	break;
	case CPC_PENTIUM_MMX:
	case CPC_PENTIUM:
	{
		struct xcesr xcesr;

		unmake_cesr(event->ce_cesr, cpuver, &xcesr);
		if ((pic[0] = regtostr(cpuver, 0, xcesr.evsel[0])) == NULL)
			return (NULL);
		if ((pic[1] = regtostr(cpuver, 1, xcesr.evsel[1])) == NULL) {
			free(pic[0]);
			return (NULL);
		}
		(void) snprintf(buffer, sizeof (buffer), "%s=%s,%s=%s",
		    tokens[D_pic0], pic[0], tokens[D_pic1], pic[1]);
		free(pic[1]);
		free(pic[0]);
		flagstostr(buffer,
		    xcesr.usr[0], xcesr.usr[1], 1, tokens[D_nouser]);
		flagstostr(buffer,
		    xcesr.sys[0], xcesr.sys[1], 0, tokens[D_sys]);
		flagstostr(buffer,
		    xcesr.clk[0], xcesr.clk[1], 0, tokens[D_noedge]);
		flagstostr(buffer,
		    xcesr.pc[0], xcesr.pc[1], 0, tokens[D_pc]);
	}	break;
	default:
		return (NULL);
	}
	return (strdup(buffer));
}

/*
 * Utility operations on events
 */
void
cpc_event_accum(cpc_event_t *accum, cpc_event_t *event)
{
	if (accum->ce_hrt < event->ce_hrt)
		accum->ce_hrt = event->ce_hrt;
	accum->ce_tsc += event->ce_tsc;
	accum->ce_pic[0] += event->ce_pic[0];
	accum->ce_pic[1] += event->ce_pic[1];
}

void
cpc_event_diff(cpc_event_t *diff, cpc_event_t *left, cpc_event_t *right)
{
	diff->ce_hrt = left->ce_hrt;
	diff->ce_tsc = left->ce_tsc - right->ce_tsc;
	diff->ce_pic[0] = left->ce_pic[0] - right->ce_pic[0];
	diff->ce_pic[1] = left->ce_pic[1] - right->ce_pic[1];
}

/*
 * Given a cpc_event_t and cpc_bind_event() flags,
 * translate the cpc_event_t into the cpc_set_t format.
 *
 * Returns NULL on failure.
 */
cpc_set_t *
__cpc_eventtoset(cpc_t *cpc, cpc_event_t *event, int iflags)
{
	cpc_set_t	*set;
	int		cpuver = event->ce_cpuver;
	char		*pic[2];
	int		flags[2] = { 0, 0 };
	int		i;
	int		j;
	int		nattrs;
	cpc_attr_t	*attr;
	int		intr;

	if ((set = cpc_set_create(cpc)) == NULL) {
		return (NULL);
	}

	if (iflags & CPC_BIND_EMT_OVF)
		flags[0] = flags[1] = CPC_OVF_NOTIFY_EMT;

	switch (cpuver) {
	case CPC_PENTIUM_PRO_MMX:
	case CPC_PENTIUM_PRO:
	{
		struct xpes xpes[2];

		for (i = 0; i < 2; i++) {
			intr = 0;
			nattrs = j = 1;
			unmake_pes(event->ce_pes[i], cpuver, &xpes[i]);
			if ((pic[i] = regtostr(cpuver, i,
			    xpes[i].evsel)) == NULL) {
				(void) cpc_set_destroy(cpc, set);
				return (NULL);
			}
			if (xpes[i].usr == 1)
				flags[i] |= CPC_COUNT_USER;
			if (xpes[i].sys == 1)
				flags[i] |= CPC_COUNT_SYSTEM;
			if (xpes[i].irupt == 1) {
				nattrs++;
				intr = 1;
			}

			if (xpes[i].cmask)
				nattrs++;
			if (xpes[i].umask)
				nattrs++;
			if (xpes[i].inv)
				nattrs++;
			if (xpes[i].pc)
				nattrs++;
			if (xpes[i].edge == 0)
				nattrs++;

			if ((attr = (cpc_attr_t *)malloc(nattrs *
			    sizeof (cpc_attr_t))) == NULL) {
				(void) cpc_set_destroy(cpc, set);
				errno = ENOMEM;
				return (NULL);
			}

			/*
			 * Ensure that pic[0] in the cpc_event_t is bound to
			 * physical pic0.
			 */
			attr[0].ca_name = "picnum";
			attr[0].ca_val = i;

			if (intr) {
				attr[j].ca_name = "int";
				attr[j].ca_val = 1;
				j++;
			}
			if (xpes[i].cmask) {
				attr[j].ca_name = "cmask";
				attr[j].ca_val = xpes[i].cmask;
				j++;
			}
			if (xpes[i].umask) {
				attr[j].ca_name = "umask";
				attr[j].ca_val = xpes[i].umask;
				j++;
			}
			if (xpes[i].inv) {
				attr[j].ca_name = "inv";
				attr[j].ca_val = 1;
				j++;
			}
			if (xpes[i].pc) {
				attr[j].ca_name = "pc";
				attr[j].ca_val = 1;
				j++;
			}
			if (xpes[i].edge == 0) {
				attr[j].ca_name = "noedge";
				attr[j].ca_val = 1;
				j++;
			}

			if (cpc_set_add_request(cpc, set, pic[i],
			    event->ce_pic[i], flags[i], nattrs, attr) == -1) {
				(void) cpc_set_destroy(cpc, set);
				free(pic[i]);
				free(attr);
				return (NULL);
			}
			free(pic[i]);
			free(attr);
		}
	}
	break;
	case CPC_PENTIUM_MMX:
	case CPC_PENTIUM:
	{
		struct xcesr xcesr;
		unmake_cesr(event->ce_cesr, cpuver, &xcesr);

		for (i = 0; i < 2; i++) {
			nattrs = j = 1;

			if ((pic[i] = regtostr(cpuver, i, xcesr.evsel[i]))
			    == NULL) {
				(void) cpc_set_destroy(cpc, set);
				return (NULL);
			}

			if (xcesr.usr[i] == 1)
				flags[i] |= CPC_COUNT_USER;
			if (xcesr.sys[i] == 1)
				flags[i] |= CPC_COUNT_SYSTEM;
			if (xcesr.clk[i] == 1)
				nattrs++;
			if (xcesr.pc[i] == 1)
				nattrs++;

			if ((attr = (cpc_attr_t *)malloc(nattrs *
			    sizeof (cpc_attr_t))) == NULL) {
				(void) cpc_set_destroy(cpc, set);
				errno = ENOMEM;
				return (NULL);
			}

			/*
			 * Ensure that pic[0] in the cpc_event_t is bound to
			 * physical pic0.
			 */
			attr[0].ca_name = "picnum";
			attr[0].ca_val = i;

			if (xcesr.clk[i] == 1) {
				attr[j].ca_name = "noedge";
				attr[j].ca_val = 1;
				j++;
			}

			if (xcesr.pc[i] == 1) {
				attr[j].ca_name = "pc";
				attr[j].ca_val = 1;
				j++;
			}

			if (cpc_set_add_request(cpc, set, pic[i],
			    event->ce_pic[i], flags[i], nattrs, attr) == -1) {
				(void) cpc_set_destroy(cpc, set);
				free(pic[i]);
				free(attr);
				return (NULL);
			}

			free(pic[i]);
			free(attr);
		}
	}
	break;
	default:
		(void) cpc_set_destroy(cpc, set);
		return (NULL);
	}

	return (set);
}
