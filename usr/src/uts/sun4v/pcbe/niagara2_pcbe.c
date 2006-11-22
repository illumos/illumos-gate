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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Niagara2 Performance Counter Backend
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/cpuvar.h>
#include <sys/systm.h>
#include <sys/archsystm.h>
#include <sys/cmn_err.h>
#include <sys/cpc_impl.h>
#include <sys/cpc_pcbe.h>
#include <sys/modctl.h>
#include <sys/machsystm.h>
#include <sys/sdt.h>
#include <sys/niagara2regs.h>
#include <sys/hsvc.h>

static int ni2_pcbe_init(void);
static uint_t ni2_pcbe_ncounters(void);
static const char *ni2_pcbe_impl_name(void);
static const char *ni2_pcbe_cpuref(void);
static char *ni2_pcbe_list_events(uint_t picnum);
static char *ni2_pcbe_list_attrs(void);
static uint64_t ni2_pcbe_event_coverage(char *event);
static uint64_t ni2_pcbe_overflow_bitmap(void);
static int ni2_pcbe_configure(uint_t picnum, char *event, uint64_t preset,
    uint32_t flags, uint_t nattrs, kcpc_attr_t *attrs, void **data,
    void *token);
static void ni2_pcbe_program(void *token);
static void ni2_pcbe_allstop(void);
static void ni2_pcbe_sample(void *token);
static void ni2_pcbe_free(void *config);

extern void ultra_setpcr(uint64_t);
extern uint64_t ultra_getpcr(void);
extern void ultra_setpic(uint64_t);
extern uint64_t ultra_getpic(void);
extern uint64_t ultra_gettick(void);
extern char cpu_module_name[];

pcbe_ops_t ni2_pcbe_ops = {
	PCBE_VER_1,
	CPC_CAP_OVERFLOW_INTERRUPT | CPC_CAP_OVERFLOW_PRECISE,
	ni2_pcbe_ncounters,
	ni2_pcbe_impl_name,
	ni2_pcbe_cpuref,
	ni2_pcbe_list_events,
	ni2_pcbe_list_attrs,
	ni2_pcbe_event_coverage,
	ni2_pcbe_overflow_bitmap,
	ni2_pcbe_configure,
	ni2_pcbe_program,
	ni2_pcbe_allstop,
	ni2_pcbe_sample,
	ni2_pcbe_free
};

typedef struct _ni2_pcbe_config {
	uint_t		pcbe_picno;	/* 0 for pic0 or 1 for pic1 */
	uint32_t	pcbe_evsel;	/* %pcr event code unshifted */
	uint32_t	pcbe_flags;	/* hpriv/user/system/priv */
	uint32_t	pcbe_pic;	/* unshifted raw %pic value */
} ni2_pcbe_config_t;

typedef struct _ni2_event {
	const char	*name;
	const uint32_t	emask;
	const uint32_t	emask_valid;	/* Mask of unreserved MASK bits */
} ni2_event_t;

#define	ULTRA_PCR_PRIVPIC	(UINT64_C(1) << CPC_NIAGARA2_PCR_PRIVPIC_SHIFT)
#define	EV_END {NULL, 0, 0}

static const uint64_t   allstopped = ULTRA_PCR_PRIVPIC;

static ni2_event_t ni2_events[] = {
	{ "Idle_strands",			0x000, 0x00 },
	{ "Br_completed",			0x201, 0x7f },
	{ "Br_taken",				0x202, 0x7f },
	{ "Instr_FGU_arithmetic",		0x204, 0x7f },
	{ "Instr_ld",				0x208, 0x7f },
	{ "Instr_st",				0x210, 0x7f },
	{ "Instr_sw",				0x220, 0x7f },
	{ "Instr_other",			0x240, 0x7f },
	{ "Instr_cnt",				0x27d, 0x7f },
	{ "IC_miss",				0x301, 0x3f },
	{ "DC_miss",				0x302, 0x3f },
	{ "ITLB_miss",				0x304, 0x3f },
	{ "DTLB_miss",				0x308, 0x3f },
	{ "L2_imiss",				0x310, 0x3f },
	{ "L2_dmiss_ld",			0x320, 0x3f },
	{ "ITLB_HWTW_ref_L2",			0x404, 0x3c },
	{ "DTLB_HWTW_ref_L2",			0x408, 0x3c },
	{ "ITLB_HWTW_miss_L2",			0x410, 0x3c },
	{ "DTLB_HWTW_miss_L2",			0x420, 0x3c },
	{ "Stream_ld_to_PCX",			0x501, 0x3f },
	{ "Stream_st_to_PCX",			0x502, 0x3f },
	{ "CPU_ld_to_PCX",			0x504, 0x3f },
	{ "CPU_ifetch_to_PCX",			0x508, 0x3f },
	{ "CPU_st_to_PCX",			0x510, 0x3f },
	{ "MMU_ld_to_PCX",			0x520, 0x3f },
	{ "DES_3DES_op",			0x601, 0x3f },
	{ "AES_op",				0x602, 0x3f },
	{ "RC4_op",				0x604, 0x3f },
	{ "MD5_SHA-1_SHA-256_op",		0x608, 0x3f },
	{ "MA_op",				0x610, 0x3f },
	{ "CRC_TCPIP_cksum",			0x620, 0x3f },
	{ "DES_3DES_busy_cycle",		0x701, 0x3f },
	{ "AES_busy_cycle",			0x702, 0x3f },
	{ "RC4_busy_cycle",			0x704, 0x3f },
	{ "MD5_SHA-1_SHA-256_busy_cycle",	0x708, 0x3f },
	{ "MA_busy_cycle",			0x710, 0x3f },
	{ "CRC_MPA_cksum",			0x720, 0x3f },
	EV_END
};

static const char	*ni2_impl_name = "UltraSPARC T2";
static char		*evlist;
static size_t		evlist_sz;
static uint16_t 	pcr_pic0_mask;
static uint16_t 	pcr_pic1_mask;

#define	CPU_REF_URL " Documentation for Sun processors can be found at: " \
			"http://www.sun.com/processors/manuals"

static const char *niagara2_cpuref = "See the \"UltraSPARC T2 User's Manual\" "
			"for descriptions of these events." CPU_REF_URL;

static boolean_t niagara2_hsvc_available = B_TRUE;

static int
ni2_pcbe_init(void)
{
	ni2_event_t	*evp;
	int		status;
	uint64_t	niagara2_hsvc_major;
	uint64_t	niagara2_hsvc_minor;

	pcr_pic0_mask = CPC_NIAGARA2_PCR_PIC0_MASK;
	pcr_pic1_mask = CPC_NIAGARA2_PCR_PIC1_MASK;

	/*
	 * Validate API version for Niagara2 specific hypervisor services
	 */
	status = hsvc_version(HSVC_GROUP_NIAGARA2_CPU, &niagara2_hsvc_major,
	    &niagara2_hsvc_minor);
	if ((status != 0) || (niagara2_hsvc_major != NIAGARA2_HSVC_MAJOR)) {
		cmn_err(CE_WARN, "hypervisor services not negotiated "
		    "or unsupported major number: group: 0x%x major: 0x%lx "
		    "minor: 0x%lx errno: %d", HSVC_GROUP_NIAGARA2_CPU,
		    niagara2_hsvc_major, niagara2_hsvc_minor, status);
		niagara2_hsvc_available = B_FALSE;
	}
	/*
	 * Construct event list.
	 *
	 * First pass:  Calculate size needed. We'll need an additional byte
	 *		for the NULL pointer during the last strcat.
	 *
	 * Second pass: Copy strings.
	 */
	for (evp = ni2_events; evp->name != NULL; evp++)
		evlist_sz += strlen(evp->name) + 1;

	evlist = kmem_alloc(evlist_sz + 1, KM_SLEEP);
	evlist[0] = '\0';

	for (evp = ni2_events; evp->name != NULL; evp++) {
		(void) strcat(evlist, evp->name);
		(void) strcat(evlist, ",");
	}
	/*
	 * Remove trailing comma.
	 */
	evlist[evlist_sz - 1] = '\0';

	return (0);
}

static uint_t
ni2_pcbe_ncounters(void)
{
	return (2);
}

static const char *
ni2_pcbe_impl_name(void)
{
	return (ni2_impl_name);
}

static const char *
ni2_pcbe_cpuref(void)
{
	return (niagara2_cpuref);
}

static char *
ni2_pcbe_list_events(uint_t picnum)
{
	ASSERT(picnum < cpc_ncounters);

	return (evlist);
}

static char *
ni2_pcbe_list_attrs(void)
{
	if (niagara2_hsvc_available == B_TRUE)
		return ("hpriv,emask");
	else
		return ("emask");
}

static ni2_event_t *
find_event(char *name)
{
	ni2_event_t	*evp;

	for (evp = ni2_events; evp->name != NULL; evp++)
		if (strcmp(name, evp->name) == 0)
			return (evp);

	return (NULL);
}

/*ARGSUSED*/
static uint64_t
ni2_pcbe_event_coverage(char *event)
{
	/*
	 * Fortunately, both pic0 and pic1 can count all events.
	 */
	return (0x3);
}

#ifdef N2_ERRATUM_112
uint64_t	ni2_ov_tstamp[NCPU];	/* last overflow time stamp */
uint64_t	ni2_ov_spurious_range = 1000000; /* 1 msec at 1GHz */
#endif

/*
 * These processors cannot tell which counter overflowed. The PCBE interface
 * requires such processors to act as if _all_ counters had overflowed.
 */
static uint64_t
ni2_pcbe_overflow_bitmap(void)
{
	uint64_t	pcr, overflow;
	uint64_t	pic;
	uint32_t	pic0, pic1;
	boolean_t	update_pic = B_FALSE;
#ifdef N2_ERRATUM_112
	uint64_t	tstamp;
	processorid_t	cpun;
#endif

	ASSERT(getpil() >= DISP_LEVEL);
	pcr = ultra_getpcr();
	DTRACE_PROBE1(niagara2__getpcr, uint64_t, pcr);
	overflow =  (pcr & CPC_NIAGARA2_PCR_OV0_MASK) >>
	    CPC_NIAGARA2_PCR_OV0_SHIFT;
	overflow |=  (pcr & CPC_NIAGARA2_PCR_OV1_MASK) >>
	    CPC_NIAGARA2_PCR_OV1_SHIFT;
#ifdef N2_ERRATUM_112
	/*
	 * Niagara2 1.x silicon can generate a duplicate overflow trap per
	 * event. If we take an overflow trap with no counters overflowing,
	 * return a non-zero bitmask with no OV bit set for supported
	 * counter so that the framework can ignore this trap.
	 */
	cpun = CPU->cpu_id;
	tstamp = ultra_gettick();
	if (overflow)
		ni2_ov_tstamp[cpun] = tstamp;
	else if (tstamp < (ni2_ov_tstamp[cpun] + ni2_ov_spurious_range))
		overflow |= 1ULL << 63;
#endif
	pic = ultra_getpic();
	pic0 = (uint32_t)(pic & PIC0_MASK);
	pic1 = (uint32_t)((pic >> PIC1_SHIFT) & PIC0_MASK);

#ifdef N2_ERRATUM_134
	/*
	 * In Niagara2 1.x silicon, PMU doesn't set OV bit for precise events.
	 * So, if we take a trap with the counter within the overflow range
	 * and the OV bit is not set, we assume OV bit should have been set.
	 */

	if (PIC_IN_OV_RANGE(pic0))
		overflow |= 0x1;
	if (PIC_IN_OV_RANGE(pic1))
		overflow |= 0x2;
#endif
	/*
	 * Reset the pic, if it is within the overflow range.
	 */
	if ((overflow & 0x1) && (PIC_IN_OV_RANGE(pic0))) {
		pic0 = 0;
		update_pic = B_TRUE;
	}
	if ((overflow & 0x2) && (PIC_IN_OV_RANGE(pic1))) {
		pic1 = 0;
		update_pic = B_TRUE;
	}

	if (update_pic)
		ultra_setpic(((uint64_t)pic1 << PIC1_SHIFT) | pic0);

	return (overflow);
}

/*ARGSUSED*/
static int
ni2_pcbe_configure(uint_t picnum, char *event, uint64_t preset, uint32_t flags,
    uint_t nattrs, kcpc_attr_t *attrs, void **data, void *token)
{
	ni2_pcbe_config_t	*cfg;
	ni2_pcbe_config_t	*other_config;
	ni2_event_t		*evp;
	int			i;
	uint32_t		evsel;

	/*
	 * If we've been handed an existing configuration, we need only preset
	 * the counter value.
	 */
	if (*data != NULL) {
		cfg = *data;
		cfg->pcbe_pic = (uint32_t)preset;
		return (0);
	}

	if (picnum > 1)
		return (CPC_INVALID_PICNUM);

	if ((evp = find_event(event)) == NULL)
		return (CPC_INVALID_EVENT);

	evsel = evp->emask;

	for (i = 0; i < nattrs; i++) {
		if (strcmp(attrs[i].ka_name, "hpriv") == 0) {
			if (attrs[i].ka_val != 0)
				flags |= CPC_COUNT_HPRIV;
		} else if (strcmp(attrs[i].ka_name, "emask") == 0) {
			if ((attrs[i].ka_val | evp->emask_valid) !=
			    evp->emask_valid)
				return (CPC_ATTRIBUTE_OUT_OF_RANGE);
			evsel |= attrs[i].ka_val;
		} else
			return (CPC_INVALID_ATTRIBUTE);
	}

	/*
	 * Find other requests that will be programmed with this one, and ensure
	 * the flags don't conflict.
	 */
	if (((other_config = kcpc_next_config(token, NULL, NULL)) != NULL) &&
	    (other_config->pcbe_flags != flags))
		return (CPC_CONFLICTING_REQS);

	cfg = kmem_alloc(sizeof (*cfg), KM_SLEEP);

	cfg->pcbe_picno = picnum;
	cfg->pcbe_evsel = evsel;
	cfg->pcbe_flags = flags;
	cfg->pcbe_pic = (uint32_t)preset;

	*data = cfg;
	return (0);
}

static void
ni2_pcbe_program(void *token)
{
	ni2_pcbe_config_t	*pic0;
	ni2_pcbe_config_t	*pic1;
	ni2_pcbe_config_t	*tmp;
	ni2_pcbe_config_t	nullcfg = { 1, 0, 0, 0 };
	uint64_t		pcr;
	uint64_t		curpic;
	uint64_t		toe;

	/* enable trap-on-event for pic0 and pic1 */
	toe = (CPC_COUNT_TOE0 | CPC_COUNT_TOE1);

	if ((pic0 = (ni2_pcbe_config_t *)kcpc_next_config(token, NULL, NULL)) ==
	    NULL)
		panic("ni2_pcbe: token %p has no configs", token);

	if ((pic1 = kcpc_next_config(token, pic0, NULL)) == NULL) {
		pic1 = &nullcfg;
		nullcfg.pcbe_flags = pic0->pcbe_flags;
		toe = CPC_COUNT_TOE0; /* enable trap-on-event for pic0 */
	}

	if (pic0->pcbe_picno != 0) {
		/*
		 * pic0 is counter 1, so if we need the null config it should
		 * be counter 0.
		 */
		nullcfg.pcbe_picno = 0;
		tmp = pic0;
		pic0 = pic1;
		pic1 = tmp;
		toe = CPC_COUNT_TOE1; /* enable trap-on-event for pic1 */
	}

	if (pic0->pcbe_picno != 0 || pic1->pcbe_picno != 1)
		panic("%s: bad config on token %p\n", ni2_impl_name, token);

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

	pcr = (pic0->pcbe_evsel & pcr_pic0_mask) << CPC_NIAGARA2_PCR_PIC0_SHIFT;
	pcr |= (pic1->pcbe_evsel & pcr_pic1_mask) <<
	    CPC_NIAGARA2_PCR_PIC1_SHIFT;

	if (pic0->pcbe_flags & CPC_COUNT_USER)
		pcr |= (1ull << CPC_NIAGARA2_PCR_USR_SHIFT);
	if (pic0->pcbe_flags & CPC_COUNT_SYSTEM)
		pcr |= (1ull << CPC_NIAGARA2_PCR_SYS_SHIFT);
	if (pic0->pcbe_flags & CPC_COUNT_HPRIV)
		pcr |= (1ull << CPC_NIAGARA2_PCR_HPRIV_SHIFT);
	pcr |= toe;

	DTRACE_PROBE1(niagara2__setpcr, uint64_t, pcr);

	/*
	 * PCR is set by HV using API call hv_niagara_setperf().
	 * Silently ignore hvpriv events if access is denied.
	 */
	if (pic0->pcbe_flags & CPC_COUNT_HPRIV) {
		if (hv_niagara_setperf(HV_NIAGARA_SPARC_CTL, pcr) != 0)
			ultra_setpcr(pcr);
	} else
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

	DTRACE_PROBE1(niagara2__newpic, uint64_t, curpic);
}

static void
ni2_pcbe_allstop(void)
{
	ultra_setpcr(allstopped);
}

static void
ni2_pcbe_sample(void *token)
{
	uint64_t		curpic;
	int64_t			diff;
	uint64_t		*pic0_data;
	uint64_t		*pic1_data;
	uint64_t		*dtmp;
	uint64_t		tmp;
	ni2_pcbe_config_t	*pic0;
	ni2_pcbe_config_t	*pic1;
	ni2_pcbe_config_t	nullcfg = { 1, 0, 0, 0 };
	ni2_pcbe_config_t	*ctmp;

	curpic = ultra_getpic();
	DTRACE_PROBE1(niagara2__getpic, uint64_t, curpic);

	if ((pic0 = kcpc_next_config(token, NULL, &pic0_data)) == NULL)
		panic("%s: token %p has no configs", ni2_impl_name, token);

	if ((pic1 = kcpc_next_config(token, pic0, &pic1_data)) == NULL) {
		pic1 = &nullcfg;
		pic1_data = &tmp;
	}

	if (pic0->pcbe_picno != 0) {
		nullcfg.pcbe_picno = 0;
		ctmp = pic0;
		pic0 = pic1;
		pic1 = ctmp;
		dtmp = pic0_data;
		pic0_data = pic1_data;
		pic1_data = dtmp;
	}

	if (pic0->pcbe_picno != 0 || pic1->pcbe_picno != 1)
		panic("%s: bad config on token %p\n", ni2_impl_name, token);

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
ni2_pcbe_free(void *config)
{
	kmem_free(config, sizeof (ni2_pcbe_config_t));
}


static struct modlpcbe modlpcbe = {
	&mod_pcbeops,
	"UltraSPARC T2 Performance Counters v%I%",
	&ni2_pcbe_ops
};

static struct modlinkage modl = {
	MODREV_1,
	&modlpcbe,
};

int
_init(void)
{
	if (ni2_pcbe_init() != 0)
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
