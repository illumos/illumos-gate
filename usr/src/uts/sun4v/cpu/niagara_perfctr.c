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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/async.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ddi_impldefs.h>
#include <sys/machsystm.h>
#include <sys/hypervisor_api.h>
#include <sys/kstat.h>
#if defined(NIAGARA_IMPL)
#include <sys/niagararegs.h>
#elif defined(NIAGARA2_IMPL)
#include <sys/niagara2regs.h>
#endif

extern char cpu_module_name[];

#define	NUM_OF_PICS	2

/*
 * Data structure used to build array of event-names and pcr-mask values
 */
typedef struct ni_kev_mask {
	char		*event_name;
	uint64_t	pcr_mask;
} ni_kev_mask_t;

/*
 * Kstat data structure for DRAM and JBUS performance counters
 *
 * Note that these performance counters are only 31 bits wide. Since
 * the "busstat" command assumes a 32-bit counter, we emulate a 32-bit
 * counter by detecting overflow on read of these performance counters
 * and using the least significant bit of the overflow count as the
 * most significant bit (i.e. bit# 31) of the DRAM and JBUS performance
 * counters.
 */
#define	NUM_OF_PICS	2

typedef struct ni_ksinfo {
	uint8_t		pic_no_evs;			/* number of events */
	uint8_t		pic_sel_shift[NUM_OF_PICS];
	uint8_t		pic_shift[NUM_OF_PICS];
	uint64_t	pic_mask[NUM_OF_PICS];
	kstat_t		*pic_name_ksp[NUM_OF_PICS];
	kstat_t		*cntr_ksp;
	uint32_t	pic_reg;
	uint32_t	pcr_reg;
	uint32_t	pic_overflow[NUM_OF_PICS];	/* overflow count */
	uint32_t	pic_last_val[NUM_OF_PICS];	/* last PIC value */
} ni_ksinfo_t;

static ni_ksinfo_t	*ni_dram_kstats[NIAGARA_DRAM_BANKS];

#if defined(NIAGARA_IMPL)
static ni_ksinfo_t	*ni_jbus_kstat;
#endif

typedef struct ni_perf_regs {
	uint32_t	pcr_reg;
	uint32_t	pic_reg;
} ni_perf_regs_t;

static ni_perf_regs_t dram_perf_regs[] = {
	{HV_NIAGARA_DRAM_CTL0, HV_NIAGARA_DRAM_COUNT0},
	{HV_NIAGARA_DRAM_CTL1, HV_NIAGARA_DRAM_COUNT1},
	{HV_NIAGARA_DRAM_CTL2, HV_NIAGARA_DRAM_COUNT2},
	{HV_NIAGARA_DRAM_CTL3, HV_NIAGARA_DRAM_COUNT3},
};

static void ni_create_name_kstat(char *, ni_ksinfo_t *, ni_kev_mask_t *);
static void ni_delete_name_kstat(ni_ksinfo_t *);

static kstat_t *ni_create_cntr_kstat(char *, int,
	int (*update)(kstat_t *, int), void *);

static int ni_cntr_kstat_update(kstat_t *, int);

static kstat_t *ni_create_picN_kstat(char *, int, int, int,
	ni_kev_mask_t *);

#ifdef DEBUG
static int	ni_perf_debug;
#endif

/*
 * Niagara and Niagara2 DRAM Performance Events
 */
static ni_kev_mask_t
niagara_dram_events[] = {
	{"mem_reads",		0x0},
	{"mem_writes",		0x1},
	{"mem_read_write",	0x2},
	{"bank_busy_stalls",	0x3},
	{"rd_queue_latency",	0x4},
	{"wr_queue_latency",	0x5},
	{"rw_queue_latency",	0x6},
	{"wb_buf_hits",		0x7},
	{"clear_pic", 0xf}
};


#if defined(NIAGARA_IMPL)
/*
 * Niagara JBUS Performance Events
 */
static ni_kev_mask_t
niagara_jbus_events[] = {
	{"jbus_cycles",		0x1},
	{"dma_reads",		0x2},
	{"dma_read_latency",	0x3},
	{"dma_writes",		0x4},
	{"dma_write8",		0x5},
	{"ordering_waits",	0x6},
	{"pio_reads",		0x8},
	{"pio_read_latency",	0x9},
	{"aok_dok_off_cycles",	0xc},
	{"aok_off_cycles",	0xd},
	{"dok_off_cycles",	0xe},
	{"clear_pic",		0xf}
};
#endif

/*
 * Create the picN kstats for DRAM and JBUS events
 */
void
niagara_kstat_init()
{
	int i;
	ni_ksinfo_t *ksinfop;

#ifdef DEBUG
	if (ni_perf_debug)
		printf("ni_kstat_init called\n");
#endif

	/*
	 * Create DRAM perf events kstat
	 */
	for (i = 0; i < NIAGARA_DRAM_BANKS; i++) {
		ksinfop = (ni_ksinfo_t *)kmem_zalloc(sizeof (ni_ksinfo_t),
		    KM_NOSLEEP);

		if (ksinfop == NULL) {
			cmn_err(CE_WARN,
			    "%s: no space for niagara dram kstat\n",
			    cpu_module_name);
			break;
		}
		ksinfop->pic_no_evs =
			sizeof (niagara_dram_events) / sizeof (ni_kev_mask_t);
		ksinfop->pic_sel_shift[0] = NIAGARA_DRAM_PIC0_SEL_SHIFT;
		ksinfop->pic_shift[0] = NIAGARA_DRAM_PIC0_SHIFT;
		ksinfop->pic_mask[0] = NIAGARA_DRAM_PIC0_MASK;
		ksinfop->pic_sel_shift[1] = NIAGARA_DRAM_PIC1_SEL_SHIFT;
		ksinfop->pic_shift[1] = NIAGARA_DRAM_PIC1_SHIFT;
		ksinfop->pic_mask[1] = NIAGARA_DRAM_PIC1_MASK;
		ksinfop->pic_reg = dram_perf_regs[i].pic_reg;
		ksinfop->pcr_reg = dram_perf_regs[i].pcr_reg;
		ni_dram_kstats[i] = ksinfop;

		/* create basic pic event/mask pair (only once) */
		if (i == 0)
			ni_create_name_kstat("dram", ksinfop,
				    niagara_dram_events);

		/* create counter kstats */
		ni_dram_kstats[i]->cntr_ksp = ni_create_cntr_kstat("dram", i,
		    ni_cntr_kstat_update, ksinfop);
	}

#if defined(NIAGARA_IMPL)
	/*
	 * Create JBUS perf events kstat
	 */
	ni_jbus_kstat = (ni_ksinfo_t *)kmem_alloc(sizeof (ni_ksinfo_t),
		KM_NOSLEEP);

	if (ni_jbus_kstat == NULL) {
		cmn_err(CE_WARN, "%s: no space for niagara jbus kstat\n",
		    cpu_module_name);
	} else {
		ni_jbus_kstat->pic_no_evs =
			sizeof (niagara_jbus_events) / sizeof (ni_kev_mask_t);
		ni_jbus_kstat->pic_sel_shift[0] = NIAGARA_JBUS_PIC0_SEL_SHIFT;
		ni_jbus_kstat->pic_shift[0] = NIAGARA_JBUS_PIC0_SHIFT;
		ni_jbus_kstat->pic_mask[0] = NIAGARA_JBUS_PIC0_MASK;
		ni_jbus_kstat->pic_sel_shift[1] = NIAGARA_JBUS_PIC1_SEL_SHIFT;
		ni_jbus_kstat->pic_shift[1] = NIAGARA_JBUS_PIC1_SHIFT;
		ni_jbus_kstat->pic_mask[1] = NIAGARA_JBUS_PIC1_MASK;
		ni_jbus_kstat->pic_reg = HV_NIAGARA_JBUS_COUNT;
		ni_jbus_kstat->pcr_reg = HV_NIAGARA_JBUS_CTL;
		ni_create_name_kstat("jbus", ni_jbus_kstat,
		    niagara_jbus_events);
		ni_jbus_kstat->cntr_ksp = ni_create_cntr_kstat("jbus", 0,
		    ni_cntr_kstat_update, ni_jbus_kstat);
	}
#endif
}

void
niagara_kstat_fini()
{
	int i;

#ifdef DEBUG
	if (ni_perf_debug)
		printf("ni_kstat_fini called\n");
#endif
	for (i = 0; i < NIAGARA_DRAM_BANKS; i++) {
		if (ni_dram_kstats[i] != NULL) {
			ni_delete_name_kstat(ni_dram_kstats[i]);
			if (ni_dram_kstats[i]->cntr_ksp != NULL)
				kstat_delete(ni_dram_kstats[i]->cntr_ksp);
			kmem_free(ni_dram_kstats[i], sizeof (ni_ksinfo_t));
			ni_dram_kstats[i] = NULL;
		}
	}

#if defined(NIAGARA_IMPL)
	if (ni_jbus_kstat != NULL) {
		ni_delete_name_kstat(ni_jbus_kstat);
		if (ni_jbus_kstat->cntr_ksp != NULL)
			kstat_delete(ni_jbus_kstat->cntr_ksp);
		kmem_free(ni_jbus_kstat, sizeof (ni_ksinfo_t));
		ni_jbus_kstat = NULL;
	}
#endif
}

static void
ni_create_name_kstat(char *name, ni_ksinfo_t *pp, ni_kev_mask_t *ev)
{
	int	i;

#ifdef DEBUG
	if (ni_perf_debug > 1)
		printf("ni_create_name_kstat: name: %s\n", name);
#endif
	for (i = 0; i < NUM_OF_PICS; i++) {
		pp->pic_name_ksp[i] = ni_create_picN_kstat(name,
			i, pp->pic_sel_shift[i], pp->pic_no_evs, ev);

		if (pp->pic_name_ksp[i] == NULL) {
			cmn_err(CE_WARN, "%s: unable to create name kstat",
			    cpu_module_name);
		}
	}
}

static void
ni_delete_name_kstat(ni_ksinfo_t *pp)
{
	int	i;

	if (pp != NULL) {
		for (i = 0; i < NUM_OF_PICS; i++) {
			if (pp->pic_name_ksp[i] != NULL)
				kstat_delete(pp->pic_name_ksp[i]);
		}
	}
}

/*
 * Create the picN kstat. Returns a pointer to the
 * kstat which the driver must store to allow it
 * to be deleted when necessary.
 */
static kstat_t *
ni_create_picN_kstat(char *mod_name, int pic, int pic_sel_shift,
	int num_ev, ni_kev_mask_t *ev_array)
{
	struct kstat_named *pic_named_data;
	int	inst = 0;
	int	event;
	char	pic_name[30];
	kstat_t	*picN_ksp = NULL;

	(void) sprintf(pic_name, "pic%d", pic);
	if ((picN_ksp = kstat_create(mod_name, inst, pic_name,
	    "bus", KSTAT_TYPE_NAMED, num_ev, NULL)) == NULL) {
		cmn_err(CE_WARN, "%s %s : kstat create failed",
			mod_name, pic_name);

		/*
		 * It is up to the calling function to delete any kstats
		 * that may have been created already. We just
		 * return NULL to indicate an error has occured.
		 */
		return (NULL);
	}

	pic_named_data = (struct kstat_named *)
	    picN_ksp->ks_data;

	/*
	 * Write event names and their associated pcr masks. The
	 * last entry in the array (clear_pic) is added seperately
	 * below as the pic value must be inverted.
	 */
	for (event = 0; event < num_ev - 1; event++) {
		pic_named_data[event].value.ui64 =
			(ev_array[event].pcr_mask << pic_sel_shift);

		kstat_named_init(&pic_named_data[event],
			ev_array[event].event_name,
			KSTAT_DATA_UINT64);
	}

	/*
	 * add the clear_pic entry.
	 */
	pic_named_data[event].value.ui64 =
		(uint64_t)~(ev_array[event].pcr_mask << pic_sel_shift);

	kstat_named_init(&pic_named_data[event], ev_array[event].event_name,
	    KSTAT_DATA_UINT64);

	kstat_install(picN_ksp);

	return (picN_ksp);
}

/*
 * Create the "counters" kstat.
 */
static kstat_t *
ni_create_cntr_kstat(char *name, int instance, int (*update)(kstat_t *, int),
	void *ksinfop)
{
	struct kstat	*counters_ksp;
	struct kstat_named	*counters_named_data;
	char		pic_str[10];
	int		i;
	int		num_pics = NUM_OF_PICS;

#ifdef DEBUG
	if (ni_perf_debug > 1)
		printf("ni_create_cntr_kstat: name: %s instance: %d\n",
		    name, instance);
#endif

	/*
	 * Size of kstat is num_pics + 1 as it
	 * also contains the %pcr
	 */
	if ((counters_ksp = kstat_create(name, instance, "counters", "bus",
	    KSTAT_TYPE_NAMED, num_pics + 1, KSTAT_FLAG_WRITABLE)) == NULL) {
		cmn_err(CE_WARN,
		    "%s: kstat_create for %s%d failed", cpu_module_name,
		    name, instance);
		return (NULL);
	}

	counters_named_data = (struct kstat_named *)(counters_ksp->ks_data);

	/*
	 * Iinitialize the named kstats
	 */
	kstat_named_init(&counters_named_data[0], "pcr", KSTAT_DATA_UINT64);

	for (i = 0; i < num_pics; i++) {
		(void) sprintf(pic_str, "pic%d", i);

		kstat_named_init(&counters_named_data[i+1], pic_str,
		    KSTAT_DATA_UINT64);
	}

	/*
	 * Store the register offset's in the kstat's
	 * private field so that they are available
	 * to the update function.
	 */
	counters_ksp->ks_private = (void *)ksinfop;
	counters_ksp->ks_update = update;

	kstat_install(counters_ksp);

	return (counters_ksp);
}

/*
 * kstat update function. Handles reads/writes
 * from/to kstat.
 */
static int
ni_cntr_kstat_update(kstat_t *ksp, int rw)
{
	struct kstat_named	*data_p;
	ni_ksinfo_t	*ksinfop = ksp->ks_private;
	uint64_t	pic, pcr;
	int		stat = 0;
	uint32_t	pic0, pic1;

	data_p = (struct kstat_named *)ksp->ks_data;

	if (rw == KSTAT_WRITE) {
#ifdef DEBUG
		if (ni_perf_debug)
			printf("ni_cntr_kstat_update: wr pcr-%d: %lx\n",
			    ksinfop->pcr_reg, data_p[0].value.ui64);
#endif
		if (hv_niagara_setperf(ksinfop->pcr_reg, data_p[0].value.ui64))
			stat = EACCES;
	} else {
		if (hv_niagara_getperf(ksinfop->pic_reg, &pic) != 0 ||
		    hv_niagara_getperf(ksinfop->pcr_reg, &pcr) != 0)
			stat = EACCES;
		else {

			data_p[0].value.ui64 = pcr;

			/*
			 * Generate a 32-bit PIC0 value by detecting overflow
			 */
			pic0 = (uint32_t)((pic >> ksinfop->pic_shift[0]) &
			    ksinfop->pic_mask[0]);
			if (pic0 < ksinfop->pic_last_val[0])
				ksinfop->pic_overflow[0]++;
			ksinfop->pic_last_val[0] = pic0;
			pic0 += (ksinfop->pic_overflow[0] & 1) << 31;
			data_p[1].value.ui64 = (uint64_t)pic0;

			/*
			 * Generate a 32-bit PIC1 value by detecting overflow
			 */
			pic1 = (uint32_t)((pic >> ksinfop->pic_shift[1]) &
			    ksinfop->pic_mask[1]);
			if (pic1 < ksinfop->pic_last_val[1])
				ksinfop->pic_overflow[1]++;
			ksinfop->pic_last_val[1] = pic1;
			pic1 += (ksinfop->pic_overflow[1] & 1) << 31;
			data_p[2].value.ui64 = (uint64_t)pic1;
		}
#ifdef DEBUG
		if (ni_perf_debug)
			printf("ni_cntr_kstat_update: rd pcr%d: %lx  "
			    "pic%d: %16lx pic0: %8lx pic1: %8lx\n",
			    ksinfop->pcr_reg, pcr, ksinfop->pic_reg, pic,
			    data_p[1].value.ui64, data_p[2].value.ui64);
#endif
	}
	return (stat);
}
