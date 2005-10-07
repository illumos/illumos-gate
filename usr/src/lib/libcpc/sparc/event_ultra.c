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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
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

#include "libcpc.h"
#include "libcpc_impl.h"

/*
 * Event specifications for UltraSPARC performance counters are based
 * on the content of a getsubopt-like string.
 * The string should contain something that looks like this:
 *
 *	pic0=<eventspec>,pic1=<eventspec>
 *		[,nouser][,sys]
 *
 * For example:
 *	pic1=0x4,pic0=Instr_cnt
 * or
 *	pic0=Instr_cnt,pic1=Cycle_cnt,nouser,sys
 *
 * The two events must be named.  The names can be ascii or
 * a decimal, octal or hexadecimal number as parsed by strtol(3C).
 *
 * By default, user event counting is enabled, system event counting
 * is disabled.
 *
 * The routine counts the number of errors encountered while parsing
 * the string, if no errors are encountered, the event handle is
 * returned.
 */

const char *
cpc_getusage(int cpuver)
{
	switch (cpuver) {
	case CPC_ULTRA1:
	case CPC_ULTRA2:
	case CPC_ULTRA3:
	case CPC_ULTRA3_PLUS:
	case CPC_ULTRA3_I:
	case CPC_ULTRA4_PLUS:
		return ("pic0=<event0>,pic1=<event1> "
		    "[,sys] "
		    "[,nouser]");
	default:
		return (NULL);
	}
}

/*
 * This private structure is used to build tables that correspond
 * to the bit patterns in the control registers of the processor.
 */
struct keyval {
	char *kv_token;
	int (*kv_action)(const char *,
	    const struct keyval *, int, char *, uint64_t *);
	uint64_t kv_mask;
	int kv_shift;
};

static int
picbits(const char *fn,
    const struct keyval *kv, int cpuver, char *value, uint64_t *bits)
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
		__cpc_error(fn, gettext("%%pic%d cannot measure "
		    "event '%s' on this cpu\n"), regno, value);
		return (-1);
	}
	*bits |= (((uint64_t)val8 & kv->kv_mask) << kv->kv_shift);
	return (0);
}

/*ARGSUSED*/
static int
bitclr(const char *fn,
    const struct keyval *kv, int cpuver, char *value, uint64_t *bits)
{
	if (value != NULL) {
		__cpc_error(fn, gettext("bad arg to '%s'\n"), kv->kv_token);
		return (-1);
	}
	*bits &= ~(kv->kv_mask << kv->kv_shift);
	return (0);
}

/*ARGSUSED*/
static int
bitset(const char *fn,
    const struct keyval *kv, int cpuver, char *value, uint64_t *bits)
{
	if (value != NULL) {
		__cpc_error(fn, gettext("bad arg to '%s'\n"), kv->kv_token);
		return (-1);
	}
	*bits |= (kv->kv_mask << kv->kv_shift);
	return (0);
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
#define	D_sys		3
	"sys",			/* enables system counts */
	NULL
};

static const struct keyval us2_keyvals[] = {
	{ "pic0",   picbits,
		CPC_ULTRA2_PCR_PIC0_MASK,	CPC_ULTRA_PCR_PIC0_SHIFT },
	{ "pic1",   picbits,
		CPC_ULTRA2_PCR_PIC1_MASK,	CPC_ULTRA_PCR_PIC1_SHIFT },
	{ "nouser", bitclr,
		UINT64_C(1),			CPC_ULTRA_PCR_USR },
	{ "sys",    bitset,
		UINT64_C(1),			CPC_ULTRA_PCR_SYS },
};

static const struct keyval us3_keyvals[] = {
	{ "pic0",   picbits,
		CPC_ULTRA3_PCR_PIC0_MASK,	CPC_ULTRA_PCR_PIC0_SHIFT },
	{ "pic1",   picbits,
		CPC_ULTRA3_PCR_PIC1_MASK,	CPC_ULTRA_PCR_PIC1_SHIFT },
	{ "nouser", bitclr,
		UINT64_C(1),			CPC_ULTRA_PCR_USR },
	{ "sys",    bitset,
		UINT64_C(1),			CPC_ULTRA_PCR_SYS },
};

#if !defined(NDEBUG)
#pragma	init(__tablecheck)

static void
__tablecheck(void)
{
	uint_t ntokens = sizeof (tokens) / sizeof (tokens[0]) - 1;
	uint_t us3_nkeys = sizeof (us3_keyvals) / sizeof (us3_keyvals[0]);
	uint_t us2_nkeys = sizeof (us2_keyvals) / sizeof (us2_keyvals[0]);
	uint_t n;

	assert(ntokens == us3_nkeys);
	for (n = 0; n < ntokens; n++)
		assert(strcmp(tokens[n], us3_keyvals[n].kv_token) == 0);
	assert(us3_nkeys >= us2_nkeys);
	for (n = 0; n < us2_nkeys; n++)
		assert(strcmp(tokens[n], us2_keyvals[n].kv_token) == 0);
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
	uint64_t *bits;

	if (spec == NULL)
		return (errcnt = 1);

	bzero(event, sizeof (*event));
	switch (event->ce_cpuver = cpuver) {
	case CPC_ULTRA1:
	case CPC_ULTRA2:
		keyvals = us2_keyvals;
		ntokens = sizeof (us2_keyvals) / sizeof (us2_keyvals[0]);
		bits = &event->ce_pcr;
		*bits = UINT64_C(1) << CPC_ULTRA_PCR_USR;
		break;
	case CPC_ULTRA3:
	case CPC_ULTRA3_PLUS:
	case CPC_ULTRA3_I:
	case CPC_ULTRA4_PLUS:
		keyvals = us3_keyvals;
		ntokens = sizeof (us3_keyvals) / sizeof	(us3_keyvals[0]);
		bits = &event->ce_pcr;
		*bits = UINT64_C(1) << CPC_ULTRA_PCR_USR;
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

struct xpcr {
	uint8_t pic[2];
	int usr, sys;
};

static void
unmake_pcr(uint64_t pcr, int cpuver, struct xpcr *xpcr)
{
	const struct keyval *kv;

	switch (cpuver) {
	case CPC_ULTRA1:
	case CPC_ULTRA2:
	default:
		kv = us2_keyvals;
		break;
	case CPC_ULTRA3:
	case CPC_ULTRA3_PLUS:
	case CPC_ULTRA3_I:
	case CPC_ULTRA4_PLUS:
		kv = us3_keyvals;
		break;
	}
	xpcr->pic[0] = (uint8_t)((pcr >> kv[D_pic0].kv_shift) &
	    kv[D_pic0].kv_mask);
	xpcr->pic[1] = (uint8_t)((pcr >> kv[D_pic1].kv_shift) &
	    kv[D_pic1].kv_mask);
	xpcr->usr = (pcr >> kv[D_nouser].kv_shift) &
	    kv[D_nouser].kv_mask;
	xpcr->sys = (pcr >> kv[D_sys].kv_shift) &
	    kv[D_sys].kv_mask;
}

char *
cpc_eventtostr(cpc_event_t *event)
{
	struct xpcr xpcr;
	char *pic[2];
	char buffer[1024];

	switch (event->ce_cpuver) {
	case CPC_ULTRA1:
	case CPC_ULTRA2:
	case CPC_ULTRA3:
	case CPC_ULTRA3_PLUS:
	case CPC_ULTRA3_I:
	case CPC_ULTRA4_PLUS:
		break;
	default:
		return (NULL);
	}

	unmake_pcr(event->ce_pcr, event->ce_cpuver, &xpcr);
	if ((pic[0] = regtostr(event->ce_cpuver, 0, xpcr.pic[0])) == NULL)
		return (NULL);
	if ((pic[1] = regtostr(event->ce_cpuver, 1, xpcr.pic[1])) == NULL) {
		free(pic[0]);
		return (NULL);
	}

	(void) snprintf(buffer, sizeof (buffer), "%s=%s,%s=%s",
	    tokens[D_pic0], pic[0], tokens[D_pic1], pic[1]);

	free(pic[1]);
	free(pic[0]);

	if (!xpcr.usr)
		(void) strcat(strcat(buffer, ","), tokens[D_nouser]);
	if (xpcr.sys)
		(void) strcat(strcat(buffer, ","), tokens[D_sys]);

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
	accum->ce_tick += event->ce_tick;
	accum->ce_pic[0] += event->ce_pic[0];
	accum->ce_pic[1] += event->ce_pic[1];
}

void
cpc_event_diff(cpc_event_t *diff, cpc_event_t *left, cpc_event_t *right)
{
	diff->ce_hrt = left->ce_hrt;
	diff->ce_tick = left->ce_tick - right->ce_tick;
	diff->ce_pic[0] = left->ce_pic[0] - right->ce_pic[0];
	diff->ce_pic[1] = left->ce_pic[1] - right->ce_pic[1];
}

/*
 * Given a cpc_event_t and cpc_bind_event() flags, translate the event into the
 * cpc_set_t format.
 *
 * Returns NULL on failure.
 */
cpc_set_t *
__cpc_eventtoset(cpc_t *cpc, cpc_event_t *event, int iflags)
{
	cpc_set_t	*set = NULL;
	struct xpcr	xpcr;
	char		*pic[2];
	uint32_t	flag = 0;
	cpc_attr_t	attr = { "picnum", 0 };

	switch (event->ce_cpuver) {
	case CPC_ULTRA1:
	case CPC_ULTRA2:
	case CPC_ULTRA3:
	case CPC_ULTRA3_PLUS:
	case CPC_ULTRA3_I:
	case CPC_ULTRA4_PLUS:
		break;
	default:
		return (NULL);
	}

	unmake_pcr(event->ce_pcr, event->ce_cpuver, &xpcr);
	if ((pic[0] = regtostr(event->ce_cpuver, 0, xpcr.pic[0])) == NULL)
		return (NULL);
	if ((pic[1] = regtostr(event->ce_cpuver, 1, xpcr.pic[1])) == NULL) {
		free(pic[0]);
		return (NULL);
	}

	if (xpcr.usr)
		flag |= CPC_COUNT_USER;
	if (xpcr.sys)
		flag |= CPC_COUNT_SYSTEM;

	if (iflags & CPC_BIND_EMT_OVF)
		flag |= CPC_OVF_NOTIFY_EMT;

	if ((set = cpc_set_create(cpc)) == NULL)
		goto bad;

	if (cpc_set_add_request(cpc, set, pic[0], event->ce_pic[0], flag,
	    1, &attr) != 0)
		goto bad;

	attr.ca_val = 1;
	if (cpc_set_add_request(cpc, set, pic[1], event->ce_pic[1], flag,
	    1, &attr) != 1)
		goto bad;

	free(pic[0]);
	free(pic[1]);

	return (set);

bad:
	if (set != NULL)
		(void) cpc_set_destroy(cpc, set);
	free(pic[0]);
	free(pic[1]);
	return (NULL);
}
