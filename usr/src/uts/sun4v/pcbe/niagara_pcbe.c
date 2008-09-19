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

/*
 * This file contains preset event names from the Performance Application
 * Programming Interface v3.5 which included the following notice:
 *
 *                             Copyright (c) 2005,6
 *                           Innovative Computing Labs
 *                         Computer Science Department,
 *                            University of Tennessee,
 *                                 Knoxville, TN.
 *                              All Rights Reserved.
 *
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    * Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of the University of Tennessee nor the names of its
 *      contributors may be used to endorse or promote products derived from
 *      this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * This open source software license conforms to the BSD License template.
 */

/*
 * Niagara Performance Counter Backend
 */

#include <sys/cpuvar.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/cpc_impl.h>
#include <sys/cpc_pcbe.h>
#include <sys/modctl.h>
#include <sys/machsystm.h>
#include <sys/sdt.h>
#include <sys/niagararegs.h>

static int ni_pcbe_init(void);
static uint_t ni_pcbe_ncounters(void);
static const char *ni_pcbe_impl_name(void);
static const char *ni_pcbe_cpuref(void);
static char *ni_pcbe_list_events(uint_t picnum);
static char *ni_pcbe_list_attrs(void);
static uint64_t ni_pcbe_event_coverage(char *event);
static uint64_t ni_pcbe_overflow_bitmap(void);
static int ni_pcbe_configure(uint_t picnum, char *event, uint64_t preset,
    uint32_t flags, uint_t nattrs, kcpc_attr_t *attrs, void **data,
    void *token);
static void ni_pcbe_program(void *token);
static void ni_pcbe_allstop(void);
static void ni_pcbe_sample(void *token);
static void ni_pcbe_free(void *config);

extern void ultra_setpcr(uint64_t);
extern uint64_t ultra_getpcr(void);
extern void ultra_setpic(uint64_t);
extern uint64_t ultra_getpic(void);
extern uint64_t ultra_gettick(void);

pcbe_ops_t ni_pcbe_ops = {
	PCBE_VER_1,
	CPC_CAP_OVERFLOW_INTERRUPT | CPC_CAP_OVERFLOW_PRECISE,
	ni_pcbe_ncounters,
	ni_pcbe_impl_name,
	ni_pcbe_cpuref,
	ni_pcbe_list_events,
	ni_pcbe_list_attrs,
	ni_pcbe_event_coverage,
	ni_pcbe_overflow_bitmap,
	ni_pcbe_configure,
	ni_pcbe_program,
	ni_pcbe_allstop,
	ni_pcbe_sample,
	ni_pcbe_free
};

typedef struct _ni_pcbe_config {
	uint8_t		pcbe_picno;	/* 0 for pic0 or 1 for pic1 */
	uint32_t	pcbe_bits;	/* %pcr event code unshifted */
	uint32_t	pcbe_flags;	/* user/system/priv */
	uint32_t	pcbe_pic;	/* unshifted raw %pic value */
} ni_pcbe_config_t;

struct nametable {
	const uint8_t	bits;
	const char	*name;
};

typedef struct _ni_generic_events {
	char *name;
	char *event;
} ni_generic_event_t;

#define	ULTRA_PCR_PRIVPIC	(UINT64_C(1) << CPC_NIAGARA_PCR_PRIVPIC)
#define	NT_END 0xFF
#define	GEN_EVT_END { NULL, NULL }

static const uint64_t   allstopped = ULTRA_PCR_PRIVPIC;

static const struct nametable Niagara_names1[] = {
	{0x00, "Instr_cnt"},
	{NT_END, ""}
};

static const struct nametable Niagara_names0[] = {
	{0x0,	"SB_full"},
	{0x1,	"FP_instr_cnt"},
	{0x2,	"IC_miss"},
	{0x3,	"DC_miss"},
	{0x4,	"ITLB_miss"},
	{0x5,	"DTLB_miss"},
	{0x6,	"L2_imiss"},
	{0x7,	"L2_dmiss_ld"},
	{NT_END, ""}
};

static const struct nametable *Niagara_names[2] = {
	Niagara_names0,
	Niagara_names1
};

static const ni_generic_event_t Niagara_generic_names1[] = {
	{ "PAPI_tot_ins",	"Instr_cnt" },
	{ NULL,			NULL }
};

static const ni_generic_event_t Niagara_generic_names0[] = {
	{ "PAPI_l2_icm",	"L2_imiss" },
	{ "PAPI_l2_ldm",	"L2_dmiss_ld" },
	{ "PAPI_fp_ops",	"FP_instr_cnt" },
	{ "PAPI_l1_icm",	"IC_miss" },
	{ "PAPI_l1_dcm",	"DC_miss" },
	{ "PAPI_tlb_im",	"ITLB_miss" },
	{ "PAPI_tlb_dm",	"DTLB_miss" },
	{ NULL,			NULL }
};

static const ni_generic_event_t *Niagara_generic_names[2] = {
	Niagara_generic_names0,
	Niagara_generic_names1
};

static const struct nametable **events;
static const ni_generic_event_t **generic_events;
static const char *ni_impl_name = "UltraSPARC T1";
static char *pic_events[2];
static uint16_t pcr_pic0_mask;
static uint16_t pcr_pic1_mask;

#define	CPU_REF_URL " Documentation for Sun processors can be found at: " \
			"http://www.sun.com/processors/manuals"

static const char *niagara_cpuref = "See the \"UltraSPARC T1 User's Manual\" "
			"for descriptions of these events." CPU_REF_URL;

static int
ni_pcbe_init(void)
{
	const struct nametable		*n;
	const ni_generic_event_t	*gevp;
	int				i;
	size_t				size;

	events = Niagara_names;
	generic_events = Niagara_generic_names;
	pcr_pic0_mask = CPC_NIAGARA_PCR_PIC0_MASK;
	pcr_pic1_mask = CPC_NIAGARA_PCR_PIC1_MASK;

	/*
	 * Initialize the list of events for each PIC.
	 * Do two passes: one to compute the size necessary and another
	 * to copy the strings. Need room for event, comma, and NULL terminator.
	 */
	for (i = 0; i < 2; i++) {
		size = 0;
		for (n = events[i]; n->bits != NT_END; n++)
			size += strlen(n->name) + 1;
		for (gevp = generic_events[i]; gevp->name != NULL; gevp++)
			size += strlen(gevp->name) + 1;
		pic_events[i] = kmem_alloc(size + 1, KM_SLEEP);
		*pic_events[i] = '\0';
		for (n = events[i]; n->bits != NT_END; n++) {
			(void) strcat(pic_events[i], n->name);
			(void) strcat(pic_events[i], ",");
		}
		for (gevp = generic_events[i]; gevp->name != NULL; gevp++) {
			(void) strcat(pic_events[i], gevp->name);
			(void) strcat(pic_events[i], ",");
		}
		/*
		 * Remove trailing comma.
		 */
		pic_events[i][size - 1] = '\0';
	}

	return (0);
}

static uint_t
ni_pcbe_ncounters(void)
{
	return (2);
}

static const char *
ni_pcbe_impl_name(void)
{
	return (ni_impl_name);
}

static const char *
ni_pcbe_cpuref(void)
{
	return (niagara_cpuref);
}

static char *
ni_pcbe_list_events(uint_t picnum)
{
	ASSERT(picnum >= 0 && picnum < cpc_ncounters);

	return (pic_events[picnum]);
}

static char *
ni_pcbe_list_attrs(void)
{
	return ("");
}

static const ni_generic_event_t *
find_generic_event(int regno, char *name)
{
	const ni_generic_event_t *gevp;

	for (gevp = generic_events[regno]; gevp->name != NULL; gevp++) {
		if (strcmp(gevp->name, name) == 0)
			return (gevp);
	}

	return (NULL);
}

static const struct nametable *
find_event(int regno, char *name)
{
	const struct nametable		*n;

	n = events[regno];

	for (; n->bits != NT_END; n++)
		if (strcmp(name, n->name) == 0)
			return (n);

	return (NULL);
}

static uint64_t
ni_pcbe_event_coverage(char *event)
{
	uint64_t bitmap = 0;

	if ((find_event(0, event) != NULL) ||
	    (find_generic_event(0, event) != NULL))
		bitmap = 0x1;
	if ((find_event(1, event) != NULL) ||
	    (find_generic_event(1, event) != NULL))
		bitmap |= 0x2;

	return (bitmap);
}

/*
 * These processors cannot tell which counter overflowed. The PCBE interface
 * requires such processors to act as if _all_ counters had overflowed.
 */
static uint64_t
ni_pcbe_overflow_bitmap(void)
{
	uint64_t pcr, overflow;

	pcr = ultra_getpcr();
	DTRACE_PROBE1(niagara__getpcr, uint64_t, pcr);
	overflow =  (pcr & CPC_NIAGARA_PCR_OVF_MASK) >>
	    CPC_NIAGARA_PCR_OVF_SHIFT;
#if 0
	/*
	 * Not needed if the CPC framework is responsible to stop counters
	 * and that action ends up clearing overflow flags.
	 */
	if (overflow)
		ultra_setpcr(pcr & ~CPC_NIAGARA_PCR_OVF_MASK);
#endif
	return (overflow);
}

/*ARGSUSED*/
static int
ni_pcbe_configure(uint_t picnum, char *event, uint64_t preset, uint32_t flags,
    uint_t nattrs, kcpc_attr_t *attrs, void **data, void *token)
{
	ni_pcbe_config_t		*conf;
	const struct nametable		*n;
	const ni_generic_event_t	*gevp;
	ni_pcbe_config_t		*other_config;

	/*
	 * If we've been handed an existing configuration, we need only preset
	 * the counter value.
	 */
	if (*data != NULL) {
		conf = *data;
		conf->pcbe_pic = (uint32_t)preset;
		return (0);
	}
	if (picnum < 0 || picnum > 1)
		return (CPC_INVALID_PICNUM);

	if (nattrs != 0)
		return (CPC_INVALID_ATTRIBUTE);

	/*
	 * Find other requests that will be programmed with this one, and ensure
	 * the flags don't conflict.
	 */
	if (((other_config = kcpc_next_config(token, NULL, NULL)) != NULL) &&
	    (other_config->pcbe_flags != flags))
		return (CPC_CONFLICTING_REQS);

	if ((n = find_event(picnum, event)) == NULL) {
		if ((gevp = find_generic_event(picnum, event)) != NULL) {
			n = find_event(picnum, gevp->event);
			ASSERT(n != NULL);
		} else {
			return (CPC_INVALID_EVENT);
		}
	}

	conf = kmem_alloc(sizeof (ni_pcbe_config_t), KM_SLEEP);

	conf->pcbe_picno = picnum;
	conf->pcbe_bits = (uint32_t)n->bits;
	conf->pcbe_flags = flags;
	conf->pcbe_pic = (uint32_t)preset;

	*data = conf;
	return (0);
}

static void
ni_pcbe_program(void *token)
{
	ni_pcbe_config_t	*pic0;
	ni_pcbe_config_t	*pic1;
	ni_pcbe_config_t	*tmp;
	ni_pcbe_config_t	empty = { 1, 0x1c, 0, 0 }; /* SW_count_1 */
	uint64_t		pcr;
	uint64_t		curpic;

	if ((pic0 = (ni_pcbe_config_t *)kcpc_next_config(token, NULL, NULL)) ==
	    NULL)
		panic("ni_pcbe: token %p has no configs", token);

	if ((pic1 = kcpc_next_config(token, pic0, NULL)) == NULL) {
		pic1 = &empty;
		empty.pcbe_flags = pic0->pcbe_flags;
	}

	if (pic0->pcbe_picno != 0) {
		/*
		 * pic0 is counter 1, so if we need the empty config it should
		 * be counter 0.
		 */
		empty.pcbe_picno = 0;
#if 0
		/* no selection for counter 0 */
		empty.pcbe_bits = 0x14; /* SW_count_0 - won't overflow */
#endif
		tmp = pic0;
		pic0 = pic1;
		pic1 = tmp;
	}

	if (pic0->pcbe_picno != 0 || pic1->pcbe_picno != 1)
		panic("ni_pcbe: bad config on token %p\n", token);

	/*
	 * UltraSPARC does not allow pic0 to be configured differently
	 * from pic1. If the flags on these two configurations are
	 * different, they are incompatible. This condition should be
	 * caught at configure time.
	 */
	ASSERT(pic0->pcbe_flags == pic1->pcbe_flags);

	ultra_setpcr(allstopped);
	ultra_setpic(((uint64_t)pic1->pcbe_pic << PIC1_SHIFT) |
	    (uint64_t)pic0->pcbe_pic);

	pcr = (pic0->pcbe_bits & pcr_pic0_mask) << CPC_NIAGARA_PCR_PIC0_SHIFT;
	pcr |= (pic1->pcbe_bits & pcr_pic1_mask) << CPC_NIAGARA_PCR_PIC1_SHIFT;

	if (pic0->pcbe_flags & CPC_COUNT_USER)
		pcr |= (1ull << CPC_NIAGARA_PCR_USR);
	if (pic0->pcbe_flags & CPC_COUNT_SYSTEM)
		pcr |= (1ull << CPC_NIAGARA_PCR_SYS);

	DTRACE_PROBE1(niagara__setpcr, uint64_t, pcr);
	ultra_setpcr(pcr);

	/*
	 * On UltraSPARC, only read-to-read counts are accurate. We cannot
	 * expect the value we wrote into the PIC, above, to be there after
	 * starting the counter. We must sample the counter value now and use
	 * that as the baseline for future samples.
	 */
	curpic = ultra_getpic();
	pic0->pcbe_pic = (uint32_t)(curpic & PIC0_MASK);
	pic1->pcbe_pic = (uint32_t)(curpic >> PIC1_SHIFT);
	DTRACE_PROBE1(niagara__newpic, uint64_t, curpic);
}

static void
ni_pcbe_allstop(void)
{
	ultra_setpcr(allstopped);
}


static void
ni_pcbe_sample(void *token)
{
	uint64_t		curpic;
	int64_t			diff;
	uint64_t		*pic0_data;
	uint64_t		*pic1_data;
	uint64_t		*dtmp;
	uint64_t		tmp;
	ni_pcbe_config_t	*pic0;
	ni_pcbe_config_t	*pic1;
	ni_pcbe_config_t	empty = { 1, 0, 0, 0 };
	ni_pcbe_config_t	*ctmp;

	curpic = ultra_getpic();
	DTRACE_PROBE1(niagara__getpic, uint64_t, curpic);

	if ((pic0 = kcpc_next_config(token, NULL, &pic0_data)) == NULL)
		panic("%s: token %p has no configs", ni_impl_name, token);

	if ((pic1 = kcpc_next_config(token, pic0, &pic1_data)) == NULL) {
		pic1 = &empty;
		pic1_data = &tmp;
	}

	if (pic0->pcbe_picno != 0) {
		empty.pcbe_picno = 0;
		ctmp = pic0;
		pic0 = pic1;
		pic1 = ctmp;
		dtmp = pic0_data;
		pic0_data = pic1_data;
		pic1_data = dtmp;
	}

	if (pic0->pcbe_picno != 0 || pic1->pcbe_picno != 1)
		panic("%s: bad config on token %p\n", ni_impl_name, token);

	diff = (curpic & PIC0_MASK) - (uint64_t)pic0->pcbe_pic;
	if (diff < 0)
		diff += (1ll << 32);
	*pic0_data += diff;

	diff = (curpic >> 32) - (uint64_t)pic1->pcbe_pic;
	if (diff < 0)
		diff += (1ll << 32);
	*pic1_data += diff;

	pic0->pcbe_pic = (uint32_t)(curpic & PIC0_MASK);
	pic1->pcbe_pic = (uint32_t)(curpic >> PIC1_SHIFT);
}

static void
ni_pcbe_free(void *config)
{
	kmem_free(config, sizeof (ni_pcbe_config_t));
}


static struct modlpcbe modlpcbe = {
	&mod_pcbeops,
	"UltraSPARC T1 Performance Counters",
	&ni_pcbe_ops
};

static struct modlinkage modl = {
	MODREV_1,
	&modlpcbe,
};

int
_init(void)
{
	if (ni_pcbe_init() != 0)
		return (ENOTSUP);
	return (mod_install(&modl));
}

int
_fini(void)
{
	return (mod_remove(&modl));
}

int
_info(struct modinfo *mi)
{
	return (mod_info(&modl, mi));
}
