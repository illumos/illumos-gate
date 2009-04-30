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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * tavor_stats.c
 *    Tavor IB Performance Statistics routines
 *
 *    Implements all the routines necessary for setting up, querying, and
 *    (later) tearing down all the kstats necessary for implementing to
 *    the interfaces necessary to provide busstat(1M) access.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>

#include <sys/ib/adapters/tavor/tavor.h>

static kstat_t *tavor_kstat_picN_create(tavor_state_t *state, int num_pic,
    int num_evt, tavor_ks_mask_t *ev_array);
static kstat_t *tavor_kstat_cntr_create(tavor_state_t *state, int num_pic,
    int (*update)(kstat_t *, int));
static int tavor_kstat_cntr_update(kstat_t *ksp, int rw);

/*
 * Tavor IB Performance Events structure
 *    This structure is read-only and is used to setup the individual kstats
 *    and to initialize the tki_ib_perfcnt[] array for each Tavor instance.
 */
tavor_ks_mask_t tavor_ib_perfcnt_list[TAVOR_CNTR_NUMENTRIES] = {
	{"port_xmit_data", TAVOR_HW_PMEG_PORTXMITDATA_OFFSET,
	    0, 0xFFFFFFFF, 0, 0},
	{"port_recv_data", TAVOR_HW_PMEG_PORTRECVDATA_OFFSET,
	    0, 0xFFFFFFFF, 0, 0},
	{"port_xmit_pkts", TAVOR_HW_PMEG_PORTXMITPKTS_OFFSET,
	    0, 0xFFFFFFFF, 0, 0},
	{"port_recv_pkts", TAVOR_HW_PMEG_PORTRECVPKTS_OFFSET,
	    0, 0xFFFFFFFF, 0, 0},
	{"port_recv_err", TAVOR_HW_PMEG_PORTRECVERR_OFFSET,
	    0, 0xFFFF, 0, 0},
	{"port_xmit_discards", TAVOR_HW_PMEG_PORTXMITDISCARD_OFFSET,
	    0, 0xFFFF, 0, 0},
	{"vl15_dropped", TAVOR_HW_PMEG_VL15DROPPED_OFFSET,
	    0, 0xFFFF, 0, 0},
	{"port_xmit_wait", TAVOR_HW_PMEG_PORTXMITWAIT_OFFSET,
	    0, 0xFFFFFFFF, 0, 0},
	{"port_recv_remote_phys_err", TAVOR_HW_PMEG_PORTRECVREMPHYSERR_OFFSET,
	    0, 0xFFFF, 0, 0},
	{"port_xmit_constraint_err", TAVOR_HW_PMEG_PORTXMITCONSTERR_OFFSET,
	    0, 0xFF, 0, 0},
	{"port_recv_constraint_err", TAVOR_HW_PMEG_PORTRECVCONSTERR_OFFSET,
	    0, 0xFF, 0, 0},
	{"symbol_err_counter", TAVOR_HW_PMEG_SYMBOLERRCNT_OFFSET,
	    0, 0xFFFF, 0, 0},
	{"link_err_recovery_cnt", TAVOR_HW_PMEG_LINKERRRECOVERCNT_OFFSET,
	    0, 0xFFFF, 0, 0},
	{"link_downed_cnt", TAVOR_HW_PMEG_LINKDOWNEDCNT_OFFSET,
	    16, 0xFFFF, 0, 0},
	{"excessive_buffer_overruns", TAVOR_HW_PMEG_EXCESSBUFOVERRUN_OFFSET,
	    0, 0xF, 0, 0},
	{"local_link_integrity_err", TAVOR_HW_PMEG_LOCALLINKINTERR_OFFSET,
	    8, 0xF, 0, 0},
	{"clear_pic", 0, 0, 0, 0}
};


/*
 * tavor_kstat_init()
 *    Context: Only called from attach() path context
 */
int
tavor_kstat_init(tavor_state_t *state)
{
	tavor_ks_info_t		*ksi;
	uint_t			numports;
	int			i;

	TAVOR_TNF_ENTER(tavor_kstat_init);

	/* Allocate a kstat info structure */
	ksi = (tavor_ks_info_t *)kmem_zalloc(sizeof (tavor_ks_info_t),
	    KM_SLEEP);
	if (ksi == NULL) {
		TNF_PROBE_0(tavor_kstat_init_kma_fail, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_kstat_init);
		return (DDI_FAILURE);
	}
	state->ts_ks_info = ksi;

	/*
	 * Create as many "pic" kstats as we have IB ports.  Enable all
	 * of the events specified in the "tavor_ib_perfcnt_list" structure.
	 */
	numports = state->ts_cfg_profile->cp_num_ports;
	for (i = 0; i < numports; i++) {
		ksi->tki_picN_ksp[i] = tavor_kstat_picN_create(state, i,
		    TAVOR_CNTR_NUMENTRIES, tavor_ib_perfcnt_list);
		if (ksi->tki_picN_ksp[i] == NULL) {
			TNF_PROBE_0(tavor_kstat_init_picN_fail,
			    TAVOR_TNF_ERROR, "");
			goto kstat_init_fail;
		}
	}

	/* Create the "counters" kstat too */
	ksi->tki_cntr_ksp = tavor_kstat_cntr_create(state, numports,
	    tavor_kstat_cntr_update);
	if (ksi->tki_cntr_ksp == NULL) {
		TNF_PROBE_0(tavor_kstat_init_cntr_fail, TAVOR_TNF_ERROR, "");
		goto kstat_init_fail;
	}

	/* Initialize the control register and initial counter values */
	ksi->tki_pcr  = 0;
	ksi->tki_pic0 = 0;
	ksi->tki_pic1 = 0;

	/*
	 * Initialize the Tavor tki_ib_perfcnt[] array values using the
	 * default values in tavor_ib_perfcnt_list[]
	 */
	for (i = 0; i < TAVOR_CNTR_NUMENTRIES; i++) {
		ksi->tki_ib_perfcnt[i] = tavor_ib_perfcnt_list[i];
	}

	TAVOR_TNF_EXIT(tavor_kstat_init);
	return (DDI_SUCCESS);


kstat_init_fail:

	/* Delete all the previously created kstats */
	if (ksi->tki_cntr_ksp != NULL) {
		kstat_delete(ksi->tki_cntr_ksp);
	}
	for (i = 0; i < numports; i++) {
		if (ksi->tki_picN_ksp[i] != NULL) {
			kstat_delete(ksi->tki_picN_ksp[i]);
		}
	}

	/* Free the kstat info structure */
	kmem_free(ksi, sizeof (tavor_ks_info_t));

	TAVOR_TNF_EXIT(tavor_kstat_init);
	return (DDI_FAILURE);
}


/*
 * tavor_kstat_init()
 *    Context: Only called from attach() and/or detach() path contexts
 */
void
tavor_kstat_fini(tavor_state_t *state)
{
	tavor_ks_info_t		*ksi;
	uint_t			numports;
	int			i;

	TAVOR_TNF_ENTER(tavor_kstat_fini);

	/* Get pointer to kstat info */
	ksi = state->ts_ks_info;

	/* Delete all the "pic" kstats (one per port) */
	numports = state->ts_cfg_profile->cp_num_ports;
	for (i = 0; i < numports; i++) {
		if (ksi->tki_picN_ksp[i] != NULL) {
			kstat_delete(ksi->tki_picN_ksp[i]);
		}
	}

	/* Delete the "counter" kstats (one per port) */
	kstat_delete(ksi->tki_cntr_ksp);

	/* Free the kstat info structure */
	kmem_free(ksi, sizeof (tavor_ks_info_t));

	TAVOR_TNF_EXIT(tavor_kstat_fini);
}


/*
 * tavor_kstat_picN_create()
 *    Context: Only called from attach() path context
 */
static kstat_t *
tavor_kstat_picN_create(tavor_state_t *state, int num_pic, int num_evt,
    tavor_ks_mask_t *ev_array)
{
	kstat_t			*picN_ksp;
	struct kstat_named	*pic_named_data;
	int			drv_instance, i;
	char			*drv_name;
	char			pic_name[16];

	TAVOR_TNF_ENTER(tavor_kstat_picN_create);

	/*
	 * Create the "picN" kstat.  In the steps, below we will attach
	 * all of our named event types to it.
	 */
	drv_name = (char *)ddi_driver_name(state->ts_dip);
	drv_instance = ddi_get_instance(state->ts_dip);
	(void) sprintf(pic_name, "pic%d", num_pic);
	picN_ksp = kstat_create(drv_name, drv_instance, pic_name, "bus",
	    KSTAT_TYPE_NAMED, num_evt, NULL);
	if (picN_ksp == NULL) {
		TNF_PROBE_0(tavor_kstat_picN_create_kstat_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_kstat_picN_create);
		return (NULL);
	}
	pic_named_data = (struct kstat_named *)(picN_ksp->ks_data);

	/*
	 * Write event names and their associated pcr masks. The last entry
	 * in the array (clear_pic) is added separately below (as its pic
	 * value must be inverted).
	 */
	for (i = 0; i < num_evt - 1; i++) {
		pic_named_data[i].value.ui64 =
		    ((uint64_t)i << (num_pic * TAVOR_CNTR_SIZE));
		kstat_named_init(&pic_named_data[i], ev_array[i].ks_evt_name,
		    KSTAT_DATA_UINT64);
	}

	/* Add the "clear_pic" entry */
	pic_named_data[i].value.ui64 =
	    ~((uint64_t)TAVOR_CNTR_MASK << (num_pic * TAVOR_CNTR_SIZE));
	kstat_named_init(&pic_named_data[i], ev_array[i].ks_evt_name,
	    KSTAT_DATA_UINT64);

	/* Install the kstat */
	kstat_install(picN_ksp);

	TAVOR_TNF_EXIT(tavor_kstat_picN_create);
	return (picN_ksp);
}


/*
 * tavor_kstat_cntr_create()
 *    Context: Only called from attach() path context
 */
static kstat_t *
tavor_kstat_cntr_create(tavor_state_t *state, int num_pic,
    int (*update)(kstat_t *, int))
{
	struct kstat		*cntr_ksp;
	struct kstat_named	*cntr_named_data;
	int			drv_instance, i;
	char			*drv_name;
	char			pic_str[16];

	TAVOR_TNF_ENTER(tavor_kstat_cntr_create);

	/*
	 * Create the "counters" kstat.  In the steps, below we will attach
	 * all of our "pic" to it.   Note:  The size of this kstat is
	 * num_pic + 1 because it also contains the "%pcr".
	 */
	drv_name = (char *)ddi_driver_name(state->ts_dip);
	drv_instance = ddi_get_instance(state->ts_dip);
	cntr_ksp = kstat_create(drv_name, drv_instance, "counters", "bus",
	    KSTAT_TYPE_NAMED, num_pic + 1, KSTAT_FLAG_WRITABLE);
	if (cntr_ksp == NULL) {
		TNF_PROBE_0(tavor_kstat_picN_create_kstat_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_kstat_cntr_create);
		return (NULL);
	}
	cntr_named_data = (struct kstat_named *)(cntr_ksp->ks_data);

	/*
	 * Initialize the named kstats (for the "pcr" and for the
	 * individual "pic" kstats)
	 */
	kstat_named_init(&cntr_named_data[0], "pcr", KSTAT_DATA_UINT64);
	for (i = 0; i < num_pic; i++) {
		(void) sprintf(pic_str, "pic%d", i);
		kstat_named_init(&cntr_named_data[i+1], pic_str,
		    KSTAT_DATA_UINT64);
	}

	/*
	 * Store the Tavor softstate pointer in the kstat's private field so
	 * that it is available to the update function.
	 */
	cntr_ksp->ks_private = (void *)state;
	cntr_ksp->ks_update  = update;

	/* Install the kstat */
	kstat_install(cntr_ksp);

	TAVOR_TNF_ENTER(tavor_kstat_cntr_create);
	return (cntr_ksp);
}


/*
 * tavor_kstat_cntr_update()
 *    Context: Called from the kstat context
 */
static int
tavor_kstat_cntr_update(kstat_t *ksp, int rw)
{
	tavor_state_t		*state;
	tavor_ks_mask_t		*ib_perf;
	tavor_ks_info_t		*ksi;
	struct kstat_named	*data;
	uint64_t		offset, pcr;
	uint32_t		pic0, pic1, tmp;
	uint32_t		shift, mask, oldval;
	uint_t			numports, indx;

	TAVOR_TNF_ENTER(tavor_kstat_cntr_update);

	/*
	 * Extract the Tavor softstate pointer, kstat data, pointer to the
	 * kstat info structure, and pointer to the tki_ib_perfcnt[] array
	 * from the input parameters.  Note: For warlock purposes, these
	 * parameters are all accessed only in this routine and are,
	 * therefore, protected by the lock used by the kstat framework.
	 */
	state	= ksp->ks_private;
	data	= (struct kstat_named *)(ksp->ks_data);
	ksi	= state->ts_ks_info;
	ib_perf = &ksi->tki_ib_perfcnt[0];
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*ksi))
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*data))
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*ib_perf))

	/*
	 * Depending on whether we are reading the "pic" counters or
	 * writing the "pcr" control register, we need to handle and
	 * fill in the kstat data appropriately.
	 *
	 * If this is a write to the "pcr", then extract the value from
	 * the kstat data and store it in the kstat info structure.
	 *
	 * Otherwise, if this is a read of the "pic" counter(s), then
	 * extract the register offset, size, and mask values from the
	 * ib_perf[] array.  Then read the corresponding register and store
	 * it into the kstat data.  Note:  We only read/fill in pic1 if more
	 * than one port is configured.
	 */
	numports = state->ts_cfg_profile->cp_num_ports;
	if (rw == KSTAT_WRITE) {
		/* Update the stored "pcr" value */
		ksi->tki_pcr = data[0].value.ui64;
		TAVOR_TNF_EXIT(tavor_kstat_cntr_update);
		return (0);
	} else {
		/*
		 * Get the current "pcr" value and extract the lower
		 * portion (corresponding to the counters for "pic0")
		 */
		pcr  = ksi->tki_pcr;
		indx = pcr & TAVOR_CNTR_MASK;
		data[0].value.ui64 = pcr;

		/*
		 * Fill in the "pic0" counter, corresponding to port 1.
		 * This involves reading in the current value in the register
		 * and calculating how many events have happened since this
		 * register was last polled.  Then we save away the current
		 * value for the counter and increment the "pic0" total by
		 * the number of new events.
		 */
		offset = ib_perf[indx].ks_reg_offset;
		shift  = ib_perf[indx].ks_reg_shift;
		mask   = ib_perf[indx].ks_reg_mask;
		oldval = ib_perf[indx].ks_old_pic0;

		pic0   = ddi_get32(state->ts_reg_cmdhdl, (uint32_t *)
		    (uintptr_t)((uintptr_t)state->ts_reg_cmd_baseaddr +
		    offset));
		tmp = ((pic0 >> shift) & mask);

		ib_perf[indx].ks_old_pic0 = tmp;

		tmp = tmp - oldval;
		ksi->tki_pic0 += tmp;
		data[1].value.ui64 = ksi->tki_pic0;

		/*
		 * If necessary, fill in the "pic1" counter for port 2.
		 * This works the same as above except that we extract the
		 * upper bits (corresponding to the counters for "pic1")
		 */
		if (numports == TAVOR_NUM_PORTS) {
			indx   = pcr >> TAVOR_CNTR_SIZE;
			offset = ib_perf[indx].ks_reg_offset;
			shift  = ib_perf[indx].ks_reg_shift;
			mask   = ib_perf[indx].ks_reg_mask;
			oldval = ib_perf[indx].ks_old_pic1;

			pic1   = ddi_get32(state->ts_reg_cmdhdl, (uint32_t *)
			    (uintptr_t)((uintptr_t)state->ts_reg_cmd_baseaddr +
			    offset + TAVOR_HW_PORT_SIZE));
			tmp = ((pic1 >> shift) & mask);

			ib_perf[indx].ks_old_pic1 = tmp;

			tmp = tmp - oldval;
			ksi->tki_pic1 += tmp;
			data[2].value.ui64 = ksi->tki_pic1;
		}

		TAVOR_TNF_EXIT(tavor_kstat_cntr_update);
		return (0);
	}
}
