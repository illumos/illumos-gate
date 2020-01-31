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

#include <sys/types.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/kstat.h>
#include <fpc.h>

/*
 * CLEAR_PIC is needed by busstat to extract the current event type of a PIC.
 * There will be an entry for CLEAR_PIC in each fi_kev_mask_t table below, but
 * they are different from the other entries in that busstat won't show them to
 * the user.
 */
#define	DEVICE_NAME_LEN		4
#define	PIC_STR_LEN		12

/*
 * Data structure used to build array of event-names and pcr-mask values
 */
typedef struct fi_kev_mask {
	char		*event_name;
	uint64_t	pcr_mask;
} fi_kev_mask_t;

typedef struct fi_ksinfo {
	uint32_t	pic_num_events;
	uint32_t	pic_leaf_id;
	uint8_t		pic_sel_shift[NUM_MAX_COUNTERS];
	kstat_t		*pic_name_ksp[NUM_MAX_COUNTERS];
	kstat_t		*cntr_ksp;
	fire_perfcnt_t	pic_reg_group;
} fi_ksinfo_t;

static fi_ksinfo_t *fi_imu_kstats[NUM_LEAVES];
static fi_ksinfo_t *fi_mmu_kstats[NUM_LEAVES];
static fi_ksinfo_t *fi_tlu_kstats[NUM_LEAVES];
static fi_ksinfo_t *fi_lpu_kstats[NUM_LEAVES];
static fi_ksinfo_t *fi_jbc_kstat;

static int fpc_create_name_kstat(char *name, fi_ksinfo_t *pp, fi_kev_mask_t *ev,
    int base, int num_cntrs);
static void fpc_delete_name_kstat(fi_ksinfo_t *pp);
static kstat_t *fpc_create_cntr_kstat(char *name, int instance,
    int (*update)(kstat_t *, int), void *ksinfop, int num_pics);
static int fpc_cntr_kstat_update(kstat_t *ksp, int rw);
static int fpc_dev_kstat(fire_perfcnt_t reg_group, uint8_t num_inst);
static kstat_t *fpc_create_picN_kstat(char *mod_name, int pic,
    int pic_sel_shift, int num_ev, fi_kev_mask_t *ev_array);
/*
 * Below are event lists, which map an event name specified on the commandline
 * with a value to program the event register with.
 *
 * The last entry will be the mask of the entire event field for the PIC and
 * counter type.
 */

/*
 * JBC performance events.
 */
static fi_kev_mask_t
fire_jbc_events[] = {
	{JBC01_S_EVT_NONE,		JBC01_EVT_NONE},
	{JBC01_S_EVT_CLK,		JBC01_EVT_CLK},
	{JBC01_S_EVT_IDLE,		JBC01_EVT_IDLE},
	{JBC01_S_EVT_FIRE,		JBC01_EVT_FIRE},
	{JBC01_S_EVT_READ_LATENCY,	JBC01_EVT_READ_LATENCY},
	{JBC01_S_EVT_READ_SAMPLE,	JBC01_EVT_READ_SAMPLE},
	{JBC01_S_EVT_I2C_PIO,		JBC01_EVT_I2C_PIO},
	{JBC01_S_EVT_EBUS_PIO,		JBC01_EVT_EBUS_PIO},
	{JBC01_S_EVT_RINGA_PIO,		JBC01_EVT_RINGA_PIO},
	{JBC01_S_EVT_RINGB_PIO,		JBC01_EVT_RINGB_PIO},
	{JBC01_S_EVT_PARTIAL_WR,	JBC01_EVT_PARTIAL_WR},
	{JBC01_S_EVT_TOTAL_WR,		JBC01_EVT_TOTAL_WR},
	{JBC01_S_EVT_TOTAL_RD,		JBC01_EVT_TOTAL_RD},
	{JBC01_S_EVT_AOKOFF,		JBC01_EVT_AOKOFF},
	{JBC01_S_EVT_DOKOFF,		JBC01_EVT_DOKOFF},
	{JBC01_S_EVT_DAOKOFF,		JBC01_EVT_DAOKOFF},
	{JBC01_S_EVT_JBUS_COH_XACT,	JBC01_EVT_JBUS_COH_XACT},
	{JBC01_S_EVT_FIRE_COH_XACT,	JBC01_EVT_FIRE_COH_XACT},
	{JBC01_S_EVT_JBUS_NCOH_XACT,	JBC01_EVT_JBUS_NCOH_XACT},
	{JBC01_S_EVT_FGN_IO_HIT,	JBC01_EVT_FGN_IO_HIT},
	{JBC01_S_EVT_FIRE_WBS,		JBC01_EVT_FIRE_WBS},
	{JBC01_S_EVT_PCIEA_PIO_WR,	JBC01_EVT_PCIEA_PIO_WR},
	{JBC01_S_EVT_PCIEA_PIO_RD,	JBC01_EVT_PCIEA_PIO_RD},
	{JBC01_S_EVT_PCIEB_PIO_WR,	JBC01_EVT_PCIEB_PIO_WR},
	{JBC01_S_EVT_PCIEB_PIO_RD,	JBC01_EVT_PCIEB_PIO_RD},
	{COMMON_S_CLEAR_PIC,		JBC01_EVT_MASK}
};

/*
 * IMU performance events
 */
static fi_kev_mask_t
fire_imu_events[] = {
	{IMU01_S_EVT_NONE,		IMU01_EVT_NONE},
	{IMU01_S_EVT_CLK,		IMU01_EVT_CLK},
	{IMU01_S_EVT_MONDO,		IMU01_EVT_MONDO},
	{IMU01_S_EVT_MSI,		IMU01_EVT_MSI},
	{IMU01_S_EVT_MONDO_NAKS,	IMU01_EVT_MONDO_NAKS},
	{IMU01_S_EVT_EQ_WR,		IMU01_EVT_EQ_WR},
	{IMU01_S_EVT_EQ_MONDO,		IMU01_EVT_EQ_MONDO},
	{COMMON_S_CLEAR_PIC,		IMU01_EVT_MASK}
};

/*
 * MMU performance events
 */
static fi_kev_mask_t
fire_mmu_events[] = {
	{MMU01_S_EVT_NONE,		MMU01_EVT_NONE},
	{MMU01_S_EVT_CLK,		MMU01_EVT_CLK},
	{MMU01_S_EVT_TRANS,		MMU01_EVT_TRANSL},
	{MMU01_S_EVT_STALL,		MMU01_EVT_STALL},
	{MMU01_S_EVT_TRANSL_MISS,	MMU01_EVT_TRANSL_MISS},
	{MMU01_S_EVT_TBLWLK_STALL,	MMU01_EVT_TBLWLK_STALL},
	{MMU01_S_EVT_BYPASS_TRANSL,	MMU01_EVT_BYPASS_TRANSL},
	{MMU01_S_EVT_TRANSL_TRANSL,	MMU01_EVT_TRANSL_TRANSL},
	{MMU01_S_EVT_FLOW_CNTL_STALL,	MMU01_EVT_FLOW_CNTL_STALL},
	{MMU01_S_EVT_FLUSH_CACHE_ENT,	MMU01_EVT_FLUSH_CACHE_ENT},
	{COMMON_S_CLEAR_PIC,		MMU01_EVT_MASK}
};

/*
 * TLU performance events for counters 0 and 1
 */
static fi_kev_mask_t
fire_tlu_events[] = {
	{TLU01_S_EVT_NONE,			TLU01_EVT_NONE},
	{TLU01_S_EVT_CLK,			TLU01_EVT_CLK},
	{TLU01_S_EVT_COMPL,			TLU01_EVT_COMPL},
	{TLU01_S_EVT_XMT_POST_CR_UNAV,		TLU01_EVT_XMT_POST_CR_UNAV},
	{TLU01_S_EVT_XMT_NPOST_CR_UNAV,		TLU01_EVT_XMT_NPOST_CR_UNAV},
	{TLU01_S_EVT_XMT_CMPL_CR_UNAV,		TLU01_EVT_XMT_CMPL_CR_UNAV},
	{TLU01_S_EVT_XMT_ANY_CR_UNAV,		TLU01_EVT_XMT_ANY_CR_UNAV},
	{TLU01_S_EVT_RETRY_CR_UNAV,		TLU01_EVT_RETRY_CR_UNAV},
	{TLU01_S_EVT_MEMRD_PKT_RCVD,		TLU01_EVT_MEMRD_PKT_RCVD},
	{TLU01_S_EVT_MEMWR_PKT_RCVD,		TLU01_EVT_MEMWR_PKT_RCVD},
	{TLU01_S_EVT_RCV_CR_THRESH,		TLU01_EVT_RCV_CR_THRESH},
	{TLU01_S_EVT_RCV_PST_HDR_CR_EXH,	TLU01_EVT_RCV_PST_HDR_CR_EXH},
	{TLU01_S_EVT_RCV_PST_DA_CR_MPS,		TLU01_EVT_RCV_PST_DA_CR_MPS},
	{TLU01_S_EVT_RCV_NPST_HDR_CR_EXH,	TLU01_EVT_RCV_NPST_HDR_CR_EXH},
	{TLU01_S_EVT_RCVR_L0S,			TLU01_EVT_RCVR_L0S},
	{TLU01_S_EVT_RCVR_L0S_TRANS,		TLU01_EVT_RCVR_L0S_TRANS},
	{TLU01_S_EVT_XMTR_L0S,			TLU01_EVT_XMTR_L0S},
	{TLU01_S_EVT_XMTR_L0S_TRANS,		TLU01_EVT_XMTR_L0S_TRANS},
	{TLU01_S_EVT_RCVR_ERR,			TLU01_EVT_RCVR_ERR},
	{TLU01_S_EVT_BAD_TLP,			TLU01_EVT_BAD_TLP},
	{TLU01_S_EVT_BAD_DLLP,			TLU01_EVT_BAD_DLLP},
	{TLU01_S_EVT_REPLAY_ROLLOVER,		TLU01_EVT_REPLAY_ROLLOVER},
	{TLU01_S_EVT_REPLAY_TMO,		TLU01_EVT_REPLAY_TMO},
	{COMMON_S_CLEAR_PIC,			TLU01_EVT_MASK}
};

/*
 * TLU performance events for counter 2
 */
static fi_kev_mask_t
fire_tlu2_events[] = {
	{TLU2_S_EVT_NONE,			TLU2_EVT_NONE},
	{TLU2_S_EVT_NON_POST_COMPL_TIME,	TLU2_EVT_NON_POST_COMPL_TIME},
	{TLU2_S_EVT_XMT_DATA_WORD,		TLU2_EVT_XMT_DATA_WORD},
	{TLU2_S_EVT_RCVD_DATA_WORD,		TLU2_EVT_RCVD_DATA_WORD},
	{COMMON_S_CLEAR_PIC,			TLU2_EVT_MASK}
};

/*
 * LPU performance events
 */
static fi_kev_mask_t
fire_lpu_events[] = {
	{LPU12_S_EVT_RESET,		LPU12_EVT_RESET},
	{LPU12_S_EVT_TLP_RCVD,		LPU12_EVT_TLP_RCVD},
	{LPU12_S_EVT_DLLP_RCVD,		LPU12_EVT_DLLP_RCVD},
	{LPU12_S_EVT_ACK_DLLP_RCVD,	LPU12_EVT_ACK_DLLP_RCVD},
	{LPU12_S_EVT_NAK_DLLP_RCVD,	LPU12_EVT_NAK_DLLP_RCVD},
	{LPU12_S_EVT_RETRY_START,	LPU12_EVT_RETRY_START},
	{LPU12_S_EVT_REPLAY_TMO,	LPU12_EVT_REPLAY_TMO},
	{LPU12_S_EVT_ACK_NAK_LAT_TMO,	LPU12_EVT_ACK_NAK_LAT_TMO},
	{LPU12_S_EVT_BAD_DLLP,		LPU12_EVT_BAD_DLLP},
	{LPU12_S_EVT_BAD_TLP,		LPU12_EVT_BAD_TLP},
	{LPU12_S_EVT_NAK_DLLP_SENT,	LPU12_EVT_NAK_DLLP_SENT},
	{LPU12_S_EVT_ACK_DLLP_SENT,	LPU12_EVT_ACK_DLLP_SENT},
	{LPU12_S_EVT_RCVR_ERROR,	LPU12_EVT_RCVR_ERROR},
	{LPU12_S_EVT_LTSSM_RECOV_ENTRY,	LPU12_EVT_LTSSM_RECOV_ENTRY},
	{LPU12_S_EVT_REPLAY_IN_PROG,	LPU12_EVT_REPLAY_IN_PROG},
	{LPU12_S_EVT_TLP_XMT_IN_PROG,	LPU12_EVT_TLP_XMT_IN_PROG},
	{LPU12_S_EVT_CLK_CYC,		LPU12_EVT_CLK_CYC},
	{LPU12_S_EVT_TLP_DLLP_XMT_PROG,	LPU12_EVT_TLP_DLLP_XMT_PROG},
	{LPU12_S_EVT_TLP_DLLP_RCV_PROG,	LPU12_EVT_TLP_DLLP_RCV_PROG},
	{COMMON_S_CLEAR_PIC,		LPU12_EVT_MASK}
};

int
fpc_kstat_init(dev_info_t *dip)
{
	fire_perfcnt_t i;
	int avail;
	uint8_t num_inst = 0;

	if (fpc_perfcnt_module_init(dip, &avail) != DDI_SUCCESS)
		return (DDI_FAILURE);

	if (avail & PCIE_A_REGS_AVAIL)
		num_inst++;
	if (avail & PCIE_B_REGS_AVAIL)
		num_inst++;

	for (i = jbc; i < MAX_REG_TYPES; i++) {
		if (i == jbc) {
			if (avail & JBUS_REGS_AVAIL) {
				if (fpc_dev_kstat(i, 1) != SUCCESS)
					return (DDI_FAILURE);
			}
		} else {
			if (!num_inst)
				break;
			if (fpc_dev_kstat(i, num_inst) != SUCCESS)
				return (DDI_FAILURE);
		}
	}

	return (DDI_SUCCESS);
}

static int
fpc_dev_kstat(fire_perfcnt_t reg_group, uint8_t num_inst)
{
	int i, base_cntrid, num_cntrs;
	uint32_t num_events, num_events2;
	char dev_name[DEVICE_NAME_LEN];
	fi_ksinfo_t *ksinfop;
	fi_kev_mask_t *fire_events, *fire_events2;

	switch (reg_group) {
	case imu:
		(void) strncpy(dev_name, "imu", sizeof (dev_name));
		num_events = sizeof (fire_imu_events) / sizeof (fi_kev_mask_t);
		fire_events = fire_imu_events;
		num_cntrs = NUM_IMU_COUNTERS;
		break;
	case mmu:
		(void) strncpy(dev_name, "mmu", sizeof (dev_name));
		num_events = sizeof (fire_mmu_events) / sizeof (fi_kev_mask_t);
		fire_events = fire_mmu_events;
		num_cntrs = NUM_MMU_COUNTERS;
		break;
	case lpu:
		(void) strncpy(dev_name, "lpu", sizeof (dev_name));
		num_events = sizeof (fire_lpu_events) / sizeof (fi_kev_mask_t);
		fire_events = fire_lpu_events;
		num_cntrs = NUM_LPU_COUNTERS;
		break;
	case tlu:
		(void) strncpy(dev_name, "tlu", sizeof (dev_name));
		num_events = sizeof (fire_tlu_events) / sizeof (fi_kev_mask_t);
		num_events2 = sizeof (fire_tlu2_events) /
		    sizeof (fi_kev_mask_t);
		fire_events = fire_tlu_events;
		fire_events2 = fire_tlu2_events;
		num_cntrs = NUM_TLU_COUNTERS;
		break;
	case jbc:
		(void) strncpy(dev_name, "jbc", sizeof (dev_name));
		num_events = sizeof (fire_jbc_events) / sizeof (fi_kev_mask_t);
		fire_events = fire_jbc_events;
		num_cntrs = NUM_JBC_COUNTERS;
		break;
	default:
		return (FAILURE);
	}

	for (i = 0; i < num_inst; i++) {
		ksinfop = kmem_zalloc(sizeof (fi_ksinfo_t), KM_SLEEP);

		ksinfop->pic_num_events = num_events;
		ksinfop->pic_reg_group = reg_group;
		ksinfop->pic_leaf_id = i;
		ksinfop->pic_sel_shift[0] = PIC0_EVT_SEL_SHIFT;

		if (reg_group == lpu)
			ksinfop->pic_sel_shift[1] = PIC2_EVT_SEL_SHIFT;
		else
			ksinfop->pic_sel_shift[1] = PIC1_EVT_SEL_SHIFT;

		/*
		 * All error cleanup (deleting kstats and freeing memory) is
		 * done in fire_kstat_fini. So we need to save the ksinfop
		 * pointer before any possible error exit so fire_kstat_fini
		 * can find it.
		 */
		if (reg_group == imu)
			fi_imu_kstats[i] = ksinfop;
		else if (reg_group == mmu)
			fi_mmu_kstats[i] = ksinfop;
		else if (reg_group == lpu)
			fi_lpu_kstats[i] = ksinfop;
		else if (reg_group == tlu)
			fi_tlu_kstats[i] = ksinfop;
		else if (reg_group == jbc)
			fi_jbc_kstat = ksinfop;

		/* Create basic pic event-type pair (only once) */
		if (i == 0) {
			base_cntrid = 0;

			/* The extra counter for TLU is handled separately */
			if (reg_group == tlu)
				num_cntrs--;

			if (fpc_create_name_kstat(dev_name, ksinfop,
			    fire_events, base_cntrid, num_cntrs) != SUCCESS)
				goto err;

			/*
			 * extra counter for TLU. The events associated with
			 * this third counter are different from the events
			 * for the first and second counters.
			 */
			if (reg_group == tlu) {
				ksinfop->pic_sel_shift[2] = PIC2_EVT_SEL_SHIFT;
				base_cntrid += num_cntrs;
				num_cntrs = 1;
				ksinfop->pic_num_events = num_events2;
				if (fpc_create_name_kstat(dev_name, ksinfop,
				    fire_events2, base_cntrid, num_cntrs)
				    != SUCCESS)
					goto err;

				num_cntrs = NUM_TLU_COUNTERS;
			}

		}

		/* create counter kstats */
		ksinfop->cntr_ksp = fpc_create_cntr_kstat(dev_name, i,
		    fpc_cntr_kstat_update, ksinfop, num_cntrs);
		if (ksinfop->cntr_ksp == NULL)
			goto err;

	}
	return (SUCCESS);
err:
	return (FAILURE);

}

static int
fpc_create_name_kstat(char *name, fi_ksinfo_t *pp, fi_kev_mask_t *ev,
    int base, int num_cntrs)
{
	int i;

#ifdef DEBUG
	FPC_DBG2("fpc_create_name_kstat: name: %s\n", name);
#endif

	for (i = base; i < (base + num_cntrs); i++) {
		pp->pic_name_ksp[i] = fpc_create_picN_kstat(name, i,
		    pp->pic_sel_shift[i], pp->pic_num_events, ev);

		if (pp->pic_name_ksp[i] == NULL)
			return (FAILURE);
	}
	return (SUCCESS);
}

/*
 * Create the picN kstat. Returns a pointer to the
 * kstat which the driver must store to allow it
 * to be deleted when necessary.
 */
static kstat_t *
fpc_create_picN_kstat(char *mod_name, int pic, int pic_sel_shift, int num_ev,
    fi_kev_mask_t *ev_array)
{
	int event;
	char pic_name[PIC_STR_LEN];
	kstat_t	*picN_ksp = NULL;
	struct kstat_named *pic_named_data;

	(void) snprintf(pic_name, sizeof (pic_name), "pic%d", pic);
	if ((picN_ksp = kstat_create(mod_name, 0, pic_name,
	    "bus", KSTAT_TYPE_NAMED, num_ev, 0)) == NULL) {
		cmn_err(CE_WARN, "%s %s : kstat create failed",
		    mod_name, pic_name);
		return (NULL);
	}

	pic_named_data = (struct kstat_named *)picN_ksp->ks_data;

	/*
	 * Fill up data section of the kstat
	 * Write event names and their associated pcr masks.
	 * num_ev - 1 is because CLEAR_PIC is added separately.
	 */
	for (event = 0; event < num_ev - 1; event++) {
		pic_named_data[event].value.ui64 =
		    (ev_array[event].pcr_mask << pic_sel_shift);

		kstat_named_init(&pic_named_data[event],
		    ev_array[event].event_name, KSTAT_DATA_UINT64);
	}

	/*
	 * add the clear_pic entry
	 */
	pic_named_data[event].value.ui64 =
	    (uint64_t)~(ev_array[event].pcr_mask << pic_sel_shift);

	kstat_named_init(&pic_named_data[event], ev_array[event].event_name,
	    KSTAT_DATA_UINT64);

	kstat_install(picN_ksp);

#ifdef DEBUG
	FPC_DBG2("fpc_create_picN_kstat: name %s, pic %d, num_ev %d, "
	    "pic_sel_shift %d\n", mod_name, pic, num_ev, pic_sel_shift);
#endif

	return (picN_ksp);
}

/*
 * Create the "counters" kstat.
 */
static kstat_t *
fpc_create_cntr_kstat(char *name, int instance, int (*update)(kstat_t *, int),
    void *ksinfop, int num_pics)
{
	int i;
	char pic_str[PIC_STR_LEN];
	struct kstat *counters_ksp;
	struct kstat_named *counters_named_data;

#ifdef DEBUG
	FPC_DBG1("fpc_create_cntr_kstat: name: %s instance: %d\n",
	    name, instance);
#endif

	/*
	 * Size of kstat is num_pics + 1. extra one for pcr.
	 */
	if ((counters_ksp = kstat_create(name, instance, "counters", "bus",
	    KSTAT_TYPE_NAMED, num_pics + 1, KSTAT_FLAG_WRITABLE)) == NULL) {
		cmn_err(CE_WARN, "kstat_create for %s%d failed",
		    name, instance);
		return (NULL);
	}

	counters_named_data = (struct kstat_named *)(counters_ksp->ks_data);
	kstat_named_init(&counters_named_data[0], "pcr", KSTAT_DATA_UINT64);

	for (i = 0; i < num_pics; i++) {
		(void) snprintf(pic_str, sizeof (pic_str), "pic%d", i);

		kstat_named_init(&counters_named_data[i+1], pic_str,
		    KSTAT_DATA_UINT64);
	}

	/*
	 * Store the reg type and other info. in the kstat's private field
	 * so that they are available to the update function.
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
fpc_cntr_kstat_update(kstat_t *ksp, int rw)
{
	struct kstat_named *data_p;
	fi_ksinfo_t *ksinfop = ksp->ks_private;
	uint64_t counters[NUM_MAX_COUNTERS];
	uint64_t event;

	data_p = (struct kstat_named *)ksp->ks_data;

	if (rw == KSTAT_WRITE) {
#ifdef DEBUG
		FPC_DBG2("fpc_cntr_kstat_update: wr %ld\n",
		    data_p[0].value.ui64);
#endif

		if (fpc_perfcnt_program(ksinfop->pic_leaf_id,
		    ksinfop->pic_reg_group, data_p[0].value.ui64) != SUCCESS)
			return (EIO);
	} else {
		counters[2] = 0;
		if (fpc_perfcnt_read(ksinfop->pic_leaf_id,
		    ksinfop->pic_reg_group, &event, counters) != SUCCESS)
			return (EIO);

		data_p[0].value.ui64 = event;
		data_p[1].value.ui64 = counters[0];
		data_p[2].value.ui64 = counters[1];

		if (ksinfop->pic_reg_group == tlu) {
			data_p[3].value.ui64 = counters[2];
		}
#ifdef DEBUG
		FPC_DBG2("fpc_cntr_kstat_update: rd event %ld, cntr0"
		    " %ld, cntr1 %ld, cntr2 %ld\n", data_p[0].value.ui64,
		    counters[0], counters[1], counters[2]);
#endif
	}
	return (0);
}

void
fpc_kstat_fini(dev_info_t *dip)
{
	int i;

#ifdef DEBUG
	FPC_DBG1("fpc_kstat_fini called\n");
#endif

	for (i = 0; i < NUM_LEAVES; i++) {
		/* IMU */
		if (fi_imu_kstats[i] != NULL) {
			fpc_delete_name_kstat(fi_imu_kstats[i]);
			if (fi_imu_kstats[i]->cntr_ksp != NULL)
				kstat_delete(fi_imu_kstats[i]->cntr_ksp);
			kmem_free(fi_imu_kstats[i], sizeof (fi_ksinfo_t));
			fi_imu_kstats[i] = NULL;
		}

		/* MMU */
		if (fi_mmu_kstats[i] != NULL) {
			fpc_delete_name_kstat(fi_mmu_kstats[i]);
			if (fi_mmu_kstats[i]->cntr_ksp != NULL)
				kstat_delete(fi_mmu_kstats[i]->cntr_ksp);
			kmem_free(fi_mmu_kstats[i], sizeof (fi_ksinfo_t));
			fi_mmu_kstats[i] = NULL;
		}

		/* LPU */
		if (fi_lpu_kstats[i] != NULL) {
			fpc_delete_name_kstat(fi_lpu_kstats[i]);
			if (fi_lpu_kstats[i]->cntr_ksp != NULL)
				kstat_delete(fi_lpu_kstats[i]->cntr_ksp);
			kmem_free(fi_lpu_kstats[i], sizeof (fi_ksinfo_t));
			fi_lpu_kstats[i] = NULL;
		}

		/* TLU */
		if (fi_tlu_kstats[i] != NULL) {
			fpc_delete_name_kstat(fi_tlu_kstats[i]);
			if (fi_tlu_kstats[i]->cntr_ksp != NULL)
				kstat_delete(fi_tlu_kstats[i]->cntr_ksp);
			kmem_free(fi_tlu_kstats[i], sizeof (fi_ksinfo_t));
			fi_tlu_kstats[i] = NULL;
		}
	}

	/* JBC */
	if (fi_jbc_kstat != NULL) {
		fpc_delete_name_kstat(fi_jbc_kstat);
		if (fi_jbc_kstat->cntr_ksp != NULL)
			kstat_delete(fi_jbc_kstat->cntr_ksp);
		kmem_free(fi_jbc_kstat, sizeof (fi_ksinfo_t));
		fi_jbc_kstat = NULL;
	}

	(void) fpc_perfcnt_module_fini(dip);
}

static void
fpc_delete_name_kstat(fi_ksinfo_t *pp)
{
	int i;

	if (pp != NULL) {
		for (i = 0; i < NUM_MAX_COUNTERS; i++) {
			if (pp->pic_name_ksp[i] != NULL)
				kstat_delete(pp->pic_name_ksp[i]);
		}
	}
}
