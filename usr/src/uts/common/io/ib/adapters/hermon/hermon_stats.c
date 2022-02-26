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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * hermon_stats.c
 *    Hermon IB Performance Statistics routines
 *
 *    Implements all the routines necessary for setting up, querying, and
 *    (later) tearing down all the kstats necessary for implementing to
 *    the interfaces necessary to provide busstat(8) access.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>

#include <sys/ib/adapters/hermon/hermon.h>

static kstat_t *hermon_kstat_picN_create(hermon_state_t *state, int num_pic,
    int num_evt, hermon_ks_mask_t *ev_array);
static kstat_t *hermon_kstat_cntr_create(hermon_state_t *state, int num_pic,
    int (*update)(kstat_t *, int));
static int hermon_kstat_cntr_update(kstat_t *ksp, int rw);

void hermon_kstat_perfcntr64_create(hermon_state_t *state, uint_t port_num);
static int hermon_kstat_perfcntr64_read(hermon_state_t *state, uint_t port,
    int reset);
static void hermon_kstat_perfcntr64_thread_exit(hermon_ks_info_t *ksi);
static int hermon_kstat_perfcntr64_update(kstat_t *ksp, int rw);

/*
 * Hermon IB Performance Events structure
 *    This structure is read-only and is used to setup the individual kstats
 *    and to initialize the tki_ib_perfcnt[] array for each Hermon instance.
 */
hermon_ks_mask_t hermon_ib_perfcnt_list[HERMON_CNTR_NUMENTRIES] = {
	{"port_xmit_data", 0, 0},
	{"port_recv_data", 0, 0},
	{"port_xmit_pkts", 0, 0},
	{"port_recv_pkts", 0, 0},
	{"port_recv_err", 0, 0},
	{"port_xmit_discards", 0, 0},
	{"vl15_dropped", 0, 0},
	{"port_xmit_wait", 0, 0},
	{"port_recv_remote_phys_err", 0, 0},
	{"port_xmit_constraint_err", 0, 0},
	{"port_recv_constraint_err", 0, 0},
	{"symbol_err_counter", 0, 0},
	{"link_err_recovery_cnt", 0, 0},
	{"link_downed_cnt", 0, 0},
	{"excessive_buffer_overruns", 0, 0},
	{"local_link_integrity_err", 0, 0},
	{"clear_pic", 0, 0}
};

/*
 * Return the maximum of (x) and (y)
 */
#define	MAX(x, y)	(((x) > (y)) ? (x) : (y))

/*
 * Set (x) to the maximum of (x) and (y)
 */
#define	SET_TO_MAX(x, y)	\
{				\
	if ((x) < (y))		\
		(x) = (y);	\
}

/*
 * hermon_kstat_init()
 *    Context: Only called from attach() path context
 */
int
hermon_kstat_init(hermon_state_t *state)
{
	hermon_ks_info_t		*ksi;
	uint_t			numports;
	int			i;

	/* Allocate a kstat info structure */
	ksi = (hermon_ks_info_t *)kmem_zalloc(sizeof (hermon_ks_info_t),
	    KM_SLEEP);
	if (ksi == NULL) {
		return (DDI_FAILURE);
	}
	state->hs_ks_info = ksi;

	/*
	 * Create as many "pic" and perfcntr64 kstats as we have IB ports.
	 * Enable all of the events specified in the "hermon_ib_perfcnt_list"
	 * structure.
	 */
	numports = state->hs_cfg_profile->cp_num_ports;
	for (i = 0; i < numports; i++) {
		ksi->hki_picN_ksp[i] = hermon_kstat_picN_create(state, i,
		    HERMON_CNTR_NUMENTRIES, hermon_ib_perfcnt_list);
		if (ksi->hki_picN_ksp[i] == NULL) {
			goto kstat_init_fail;
		}

		hermon_kstat_perfcntr64_create(state, i + 1);
		if (ksi->hki_perfcntr64[i].hki64_ksp == NULL) {
			goto kstat_init_fail;
		}
	}

	/* Create the "counters" kstat too */
	ksi->hki_cntr_ksp = hermon_kstat_cntr_create(state, numports,
	    hermon_kstat_cntr_update);
	if (ksi->hki_cntr_ksp == NULL) {
		goto kstat_init_fail;
	}

	/* Initialize the control register and initial counter values */
	ksi->hki_pcr  = 0;
	ksi->hki_pic0 = 0;
	ksi->hki_pic1 = 0;

	/*
	 * Initialize the Hermon hki_ib_perfcnt[] array values using the
	 * default values in hermon_ib_perfcnt_list[]
	 */
	for (i = 0; i < HERMON_CNTR_NUMENTRIES; i++) {
		ksi->hki_ib_perfcnt[i] = hermon_ib_perfcnt_list[i];
	}

	mutex_init(&ksi->hki_perfcntr64_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&ksi->hki_perfcntr64_cv, NULL, CV_DRIVER, NULL);

	return (DDI_SUCCESS);


kstat_init_fail:

	/* Delete all the previously created kstats */
	if (ksi->hki_cntr_ksp != NULL) {
		kstat_delete(ksi->hki_cntr_ksp);
	}
	for (i = 0; i < numports; i++) {
		if (ksi->hki_picN_ksp[i] != NULL) {
			kstat_delete(ksi->hki_picN_ksp[i]);
		}
		if (ksi->hki_perfcntr64[i].hki64_ksp != NULL) {
			kstat_delete(ksi->hki_perfcntr64[i].hki64_ksp);
		}
	}

	/* Free the kstat info structure */
	kmem_free(ksi, sizeof (hermon_ks_info_t));

	return (DDI_FAILURE);
}


/*
 * hermon_kstat_init()
 *    Context: Only called from attach() and/or detach() path contexts
 */
void
hermon_kstat_fini(hermon_state_t *state)
{
	hermon_ks_info_t	*ksi;
	uint_t			numports;
	int			i;

	/* Get pointer to kstat info */
	ksi = state->hs_ks_info;

	/*
	 * Signal the perfcntr64_update_thread to exit and wait until the
	 * thread exits.
	 */
	mutex_enter(&ksi->hki_perfcntr64_lock);
	hermon_kstat_perfcntr64_thread_exit(ksi);
	mutex_exit(&ksi->hki_perfcntr64_lock);

	/* Delete all the "pic" and perfcntr64 kstats (one per port) */
	numports = state->hs_cfg_profile->cp_num_ports;
	for (i = 0; i < numports; i++) {
		if (ksi->hki_picN_ksp[i] != NULL) {
			kstat_delete(ksi->hki_picN_ksp[i]);
		}

		if (ksi->hki_perfcntr64[i].hki64_ksp != NULL) {
			kstat_delete(ksi->hki_perfcntr64[i].hki64_ksp);
		}
	}

	/* Delete the "counter" kstats (one per port) */
	kstat_delete(ksi->hki_cntr_ksp);

	cv_destroy(&ksi->hki_perfcntr64_cv);
	mutex_destroy(&ksi->hki_perfcntr64_lock);

	/* Free the kstat info structure */
	kmem_free(ksi, sizeof (hermon_ks_info_t));
}


/*
 * hermon_kstat_picN_create()
 *    Context: Only called from attach() path context
 */
static kstat_t *
hermon_kstat_picN_create(hermon_state_t *state, int num_pic, int num_evt,
    hermon_ks_mask_t *ev_array)
{
	kstat_t			*picN_ksp;
	struct kstat_named	*pic_named_data;
	int			drv_instance, i;
	char			*drv_name;
	char			pic_name[16];

	/*
	 * Create the "picN" kstat.  In the steps, below we will attach
	 * all of our named event types to it.
	 */
	drv_name = (char *)ddi_driver_name(state->hs_dip);
	drv_instance = ddi_get_instance(state->hs_dip);
	(void) sprintf(pic_name, "pic%d", num_pic);
	picN_ksp = kstat_create(drv_name, drv_instance, pic_name, "bus",
	    KSTAT_TYPE_NAMED, num_evt, 0);
	if (picN_ksp == NULL) {
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
		    ((uint64_t)i << (num_pic * HERMON_CNTR_SIZE));
		kstat_named_init(&pic_named_data[i], ev_array[i].ks_evt_name,
		    KSTAT_DATA_UINT64);
	}

	/* Add the "clear_pic" entry */
	pic_named_data[i].value.ui64 =
	    ~((uint64_t)HERMON_CNTR_MASK << (num_pic * HERMON_CNTR_SIZE));
	kstat_named_init(&pic_named_data[i], ev_array[i].ks_evt_name,
	    KSTAT_DATA_UINT64);

	/* Install the kstat */
	kstat_install(picN_ksp);

	return (picN_ksp);
}


/*
 * hermon_kstat_cntr_create()
 *    Context: Only called from attach() path context
 */
static kstat_t *
hermon_kstat_cntr_create(hermon_state_t *state, int num_pic,
    int (*update)(kstat_t *, int))
{
	struct kstat		*cntr_ksp;
	struct kstat_named	*cntr_named_data;
	int			drv_instance, i;
	char			*drv_name;
	char			pic_str[16];

	/*
	 * Create the "counters" kstat.  In the steps, below we will attach
	 * all of our "pic" to it.   Note:  The size of this kstat is
	 * num_pic + 1 because it also contains the "%pcr".
	 */
	drv_name = (char *)ddi_driver_name(state->hs_dip);
	drv_instance = ddi_get_instance(state->hs_dip);
	cntr_ksp = kstat_create(drv_name, drv_instance, "counters", "bus",
	    KSTAT_TYPE_NAMED, num_pic + 1, KSTAT_FLAG_WRITABLE);
	if (cntr_ksp == NULL) {
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
	 * Store the Hermon softstate pointer in the kstat's private field so
	 * that it is available to the update function.
	 */
	cntr_ksp->ks_private = (void *)state;
	cntr_ksp->ks_update  = update;

	/* Install the kstat */
	kstat_install(cntr_ksp);

	return (cntr_ksp);
}


/*
 * hermon_kstat_cntr_update()
 *    Context: Called from the kstat context
 */
static int
hermon_kstat_cntr_update(kstat_t *ksp, int rw)
{
	hermon_state_t		*state;
	hermon_ks_mask_t		*ib_perf;
	hermon_ks_info_t		*ksi;
	struct kstat_named	*data;
	uint64_t		pcr;
	uint32_t		tmp;
	uint32_t		oldval;
	uint_t			numports, indx;
	int			status;
	hermon_hw_sm_perfcntr_t	sm_perfcntr;

	/*
	 * Extract the Hermon softstate pointer, kstat data, pointer to the
	 * kstat info structure, and pointer to the hki_ib_perfcnt[] array
	 * from the input parameters.  Note: For warlock purposes, these
	 * parameters are all accessed only in this routine and are,
	 * therefore, protected by the lock used by the kstat framework.
	 */
	state	= ksp->ks_private;
	data	= (struct kstat_named *)(ksp->ks_data);
	ksi	= state->hs_ks_info;
	ib_perf = &ksi->hki_ib_perfcnt[0];
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
	numports = state->hs_cfg_profile->cp_num_ports;
	if (rw == KSTAT_WRITE) {
		/* Update the stored "pcr" value */
		ksi->hki_pcr = data[0].value.ui64;
		return (0);
	} else {
		/*
		 * Get the current "pcr" value and extract the lower
		 * portion (corresponding to the counters for "pic0")
		 */
		pcr  = ksi->hki_pcr;
		indx = pcr & HERMON_CNTR_MASK;
		data[0].value.ui64 = pcr;

		/*
		 * Fill in the "pic0" counter, corresponding to port 1.
		 * This involves reading in the current value in the register
		 * and calculating how many events have happened since this
		 * register was last polled.  Then we save away the current
		 * value for the counter and increment the "pic0" total by
		 * the number of new events.
		 */
		oldval = ib_perf[indx].ks_old_pic0;

		status = hermon_getperfcntr_cmd_post(state, 1,
		    HERMON_CMD_NOSLEEP_SPIN, &sm_perfcntr, 0);
		if (status != HERMON_CMD_SUCCESS) {
			return (-1);
		}
		switch (indx) {
		case 0:		/* port_xmit_data */
			tmp = sm_perfcntr.portxmdata;
			break;
		case 1:		/* port_recv_data */
			tmp = sm_perfcntr.portrcdata;
			break;
		case 2:		/* port_xmit_pkts */
			tmp = sm_perfcntr.portxmpkts;
			break;
		case 3:		/* port_recv_pkts */
			tmp = sm_perfcntr.portrcpkts;
			break;
		case 4:		/* port_recv_err */
			tmp = sm_perfcntr.portrcv;
			break;
		case 5:		/* port_xmit_discards */
			tmp = sm_perfcntr.portxmdiscard;
			break;
		case 6:		/* vl15_dropped */
			tmp = sm_perfcntr.vl15drop;
			break;
		case 7:		/* port_xmit_wait */
			tmp = sm_perfcntr.portxmwait;
			break;
		case 8:		/* port_recv_remote_phys_err */
			tmp = sm_perfcntr.portrcvrem;
			break;
		case 9:		/* port_xmit_constraint_err */
			tmp = sm_perfcntr.portxmconstr;
			break;
		case 10:	/* port_recv_constraint_err */
			tmp = sm_perfcntr.portrcconstr;
			break;
		case 11:	/* symbol_err_counter */
			tmp = sm_perfcntr.symerr;
			break;
		case 12:	/* link_err_recovery_cnt */
			tmp = sm_perfcntr.linkerrrec;
			break;
		case 13:	/* link_downed_cnt */
			tmp = sm_perfcntr.linkdown;
			break;
		case 14:	/* excessive_buffer_overruns */
			tmp = sm_perfcntr.xsbuffovrun;
			break;
		case 15:	/* local_link_integrity_err */
			tmp = sm_perfcntr.locallinkint;
			break;
		case 16:	/* clear_pic */
			tmp = 0;	/* XXX */
			break;
		default:
			cmn_err(CE_CONT, "perf counter out of range\n");
		}

		ib_perf[indx].ks_old_pic0 = tmp;

		tmp = tmp - oldval;
		ksi->hki_pic0 += tmp;
		data[1].value.ui64 = ksi->hki_pic0;

		/*
		 * If necessary, fill in the "pic1" counter for port 2.
		 * This works the same as above except that we extract the
		 * upper bits (corresponding to the counters for "pic1")
		 */
		if (numports == HERMON_MAX_PORTS) {
			indx   = pcr >> HERMON_CNTR_SIZE;
			oldval = ib_perf[indx].ks_old_pic1;

			status = hermon_getperfcntr_cmd_post(state, 2,
			    HERMON_CMD_NOSLEEP_SPIN, &sm_perfcntr, 0);
			if (status != HERMON_CMD_SUCCESS) {
				return (-1);
			}
			switch (indx) {
			case 0:		/* port_xmit_data */
				tmp = sm_perfcntr.portxmdata;
				break;
			case 1:		/* port_recv_data */
				tmp = sm_perfcntr.portrcdata;
				break;
			case 2:		/* port_xmit_pkts */
				tmp = sm_perfcntr.portxmpkts;
				break;
			case 3:		/* port_recv_pkts */
				tmp = sm_perfcntr.portrcpkts;
				break;
			case 4:		/* port_recv_err */
				tmp = sm_perfcntr.portrcv;
				break;
			case 5:		/* port_xmit_discards */
				tmp = sm_perfcntr.portxmdiscard;
				break;
			case 6:		/* vl15_dropped */
				tmp = sm_perfcntr.vl15drop;
				break;
			case 7:		/* port_xmit_wait */
				tmp = sm_perfcntr.portxmwait;
				break;
			case 8:		/* port_recv_remote_phys_err */
				tmp = sm_perfcntr.portrcvrem;
				break;
			case 9:		/* port_xmit_constraint_err */
				tmp = sm_perfcntr.portxmconstr;
				break;
			case 10:	/* port_recv_constraint_err */
				tmp = sm_perfcntr.portrcconstr;
				break;
			case 11:	/* symbol_err_counter */
				tmp = sm_perfcntr.symerr;
				break;
			case 12:	/* link_err_recovery_cnt */
				tmp = sm_perfcntr.linkerrrec;
				break;
			case 13:	/* link_downed_cnt */
				tmp = sm_perfcntr.linkdown;
				break;
			case 14:	/* excessive_buffer_overruns */
				tmp = sm_perfcntr.xsbuffovrun;
				break;
			case 15:	/* local_link_integrity_err */
				tmp = sm_perfcntr.locallinkint;
				break;
			case 16:	/* clear_pic */
				tmp = 0;	/* XXX */
				break;
			default:
				cmn_err(CE_CONT, "perf counter out of range\n");
			}

			ib_perf[indx].ks_old_pic1 = tmp;

			tmp = tmp - oldval;
			ksi->hki_pic1 += tmp;
			data[2].value.ui64 = ksi->hki_pic1;
		}

		return (0);
	}
}

/*
 * 64 bit kstats for performance counters:
 *
 * Export 64 bit performance counters in kstats.
 *
 * If the HCA hardware supports 64 bit extended port counters, we use the
 * hardware based counters. If the HCA hardware does not support extended port
 * counters, we maintain 64 bit performance counters in software using the
 * 32 bit hardware port counters.
 *
 * The software based counters are maintained as follows:
 *
 * We create a thread that, every one second, reads the values of 32 bit
 * hardware counters and adds them to the 64 bit software counters. Immediately
 * after reading, it resets the 32 bit hardware counters to zero (so that they
 * start counting from zero again). At any time the current value of a counter
 * is going to be the sum of the 64 bit software counter and the 32 bit
 * hardware counter.
 *
 * Since this work need not be done if there is no consumer, by default
 * we do not maintain 64 bit software counters. To enable this the consumer
 * needs to write a non-zero value to the "enable" component of the of
 * perf_counters kstat. Writing zero to this component will disable this work.
 * NOTE: The enabling or disabling applies to software based counters only.
 * Hardware based counters counters are always enabled.
 *
 * If performance monitor is enabled in subnet manager, the SM could
 * periodically reset the hardware counters by sending perf-MADs. So only
 * one of either our software 64 bit counters or the SM performance monitor
 * could be enabled at the same time. However, if both of them are enabled at
 * the same time we still do our best by keeping track of the values of the
 * last read 32 bit hardware counters. If the current read of a 32 bit hardware
 * counter is less than the last read of the counter, we ignore the current
 * value and go with the last read value.
 */

/*
 * hermon_kstat_perfcntr64_create()
 *    Context: Only called from attach() path context
 *
 * Create "port#/perf_counters" kstat for the specified port number.
 */
void
hermon_kstat_perfcntr64_create(hermon_state_t *state, uint_t port_num)
{
	hermon_ks_info_t	*ksi = state->hs_ks_info;
	struct kstat		*cntr_ksp;
	struct kstat_named	*cntr_named_data;
	int			drv_instance;
	char			*drv_name;
	char			kname[32];
	int			status, ext_width_supported;

	ASSERT(port_num != 0);

	status = hermon_is_ext_port_counters_supported(state, port_num,
	    HERMON_CMD_NOSLEEP_SPIN, &ext_width_supported);
	if (status == HERMON_CMD_SUCCESS) {
		ksi->hki_perfcntr64[port_num - 1].
		    hki64_ext_port_counters_supported = ext_width_supported;
	}

	drv_name = (char *)ddi_driver_name(state->hs_dip);
	drv_instance = ddi_get_instance(state->hs_dip);
	(void) snprintf(kname, sizeof (kname), "port%u/perf_counters",
	    port_num);
	cntr_ksp = kstat_create(drv_name, drv_instance, kname, "ib",
	    KSTAT_TYPE_NAMED, HERMON_PERFCNTR64_NUM_COUNTERS,
	    KSTAT_FLAG_WRITABLE);
	if (cntr_ksp == NULL) {
		return;
	}
	cntr_named_data = (struct kstat_named *)(cntr_ksp->ks_data);

	kstat_named_init(&cntr_named_data[HERMON_PERFCNTR64_ENABLE_IDX],
	    "enable", KSTAT_DATA_UINT32);
	kstat_named_init(&cntr_named_data[HERMON_PERFCNTR64_XMIT_DATA_IDX],
	    "xmit_data", KSTAT_DATA_UINT64);
	kstat_named_init(&cntr_named_data[HERMON_PERFCNTR64_RECV_DATA_IDX],
	    "recv_data", KSTAT_DATA_UINT64);
	kstat_named_init(&cntr_named_data[HERMON_PERFCNTR64_XMIT_PKTS_IDX],
	    "xmit_pkts", KSTAT_DATA_UINT64);
	kstat_named_init(&cntr_named_data[HERMON_PERFCNTR64_RECV_PKTS_IDX],
	    "recv_pkts", KSTAT_DATA_UINT64);

	ksi->hki_perfcntr64[port_num - 1].hki64_ksp = cntr_ksp;
	ksi->hki_perfcntr64[port_num - 1].hki64_port_num = port_num;
	ksi->hki_perfcntr64[port_num - 1].hki64_state = state;

	cntr_ksp->ks_private = &ksi->hki_perfcntr64[port_num - 1];
	cntr_ksp->ks_update  = hermon_kstat_perfcntr64_update;

	/* Install the kstat */
	kstat_install(cntr_ksp);
}

/*
 * hermon_kstat_perfcntr64_read()
 *
 * Read the values of 32 bit hardware counters.
 *
 * If reset is true, reset the 32 bit hardware counters. Add the values of the
 * 32 bit hardware counters to the 64 bit software counters.
 *
 * If reset is false, just save the values read from the 32 bit hardware
 * counters in hki64_last_read[].
 *
 * See the general comment on the 64 bit performance counters
 * regarding the use of last read 32 bit hardware counter values.
 */
static int
hermon_kstat_perfcntr64_read(hermon_state_t *state, uint_t port, int reset)
{
	hermon_ks_info_t	*ksi = state->hs_ks_info;
	hermon_perfcntr64_ks_info_t *ksi64 = &ksi->hki_perfcntr64[port - 1];
	int			status, i;
	uint32_t		tmp;
	hermon_hw_sm_perfcntr_t	sm_perfcntr;

	ASSERT(MUTEX_HELD(&ksi->hki_perfcntr64_lock));
	ASSERT(port != 0);

	/* read the 32 bit hardware counters */
	status = hermon_getperfcntr_cmd_post(state, port,
	    HERMON_CMD_NOSLEEP_SPIN, &sm_perfcntr, 0);
	if (status != HERMON_CMD_SUCCESS) {
		return (status);
	}

	if (reset) {
		/* reset the hardware counters */
		status = hermon_getperfcntr_cmd_post(state, port,
		    HERMON_CMD_NOSLEEP_SPIN, NULL, 1);
		if (status != HERMON_CMD_SUCCESS) {
			return (status);
		}

		/*
		 * Update 64 bit software counters
		 */
		tmp = MAX(sm_perfcntr.portxmdata,
		    ksi64->hki64_last_read[HERMON_PERFCNTR64_XMIT_DATA_IDX]);
		ksi64->hki64_counters[HERMON_PERFCNTR64_XMIT_DATA_IDX] += tmp;

		tmp = MAX(sm_perfcntr.portrcdata,
		    ksi64->hki64_last_read[HERMON_PERFCNTR64_RECV_DATA_IDX]);
		ksi64->hki64_counters[HERMON_PERFCNTR64_RECV_DATA_IDX] += tmp;

		tmp = MAX(sm_perfcntr.portxmpkts,
		    ksi64->hki64_last_read[HERMON_PERFCNTR64_XMIT_PKTS_IDX]);
		ksi64->hki64_counters[HERMON_PERFCNTR64_XMIT_PKTS_IDX] += tmp;

		tmp = MAX(sm_perfcntr.portrcpkts,
		    ksi64->hki64_last_read[HERMON_PERFCNTR64_RECV_PKTS_IDX]);
		ksi64->hki64_counters[HERMON_PERFCNTR64_RECV_PKTS_IDX] += tmp;

		for (i = 0; i < HERMON_PERFCNTR64_NUM_COUNTERS; i++)
			ksi64->hki64_last_read[i] = 0;

	} else {
		/*
		 * Update ksi64->hki64_last_read[]
		 */
		SET_TO_MAX(
		    ksi64->hki64_last_read[HERMON_PERFCNTR64_XMIT_DATA_IDX],
		    sm_perfcntr.portxmdata);

		SET_TO_MAX(
		    ksi64->hki64_last_read[HERMON_PERFCNTR64_RECV_DATA_IDX],
		    sm_perfcntr.portrcdata);

		SET_TO_MAX(
		    ksi64->hki64_last_read[HERMON_PERFCNTR64_XMIT_PKTS_IDX],
		    sm_perfcntr.portxmpkts);

		SET_TO_MAX(
		    ksi64->hki64_last_read[HERMON_PERFCNTR64_RECV_PKTS_IDX],
		    sm_perfcntr.portrcpkts);
	}

	return (HERMON_CMD_SUCCESS);
}

/*
 * hermon_kstat_perfcntr64_update_thread()
 *    Context: Entry point for a kernel thread
 *
 * Maintain 64 bit performance counters in software using the 32 bit
 * hardware counters.
 */
static void
hermon_kstat_perfcntr64_update_thread(void *arg)
{
	hermon_state_t		*state = (hermon_state_t *)arg;
	hermon_ks_info_t	*ksi = state->hs_ks_info;
	uint_t			i;
	clock_t			delta = drv_usectohz(1000000);

	mutex_enter(&ksi->hki_perfcntr64_lock);
	/*
	 * Every one second update the values 64 bit software counters
	 * for all ports. Exit if HERMON_PERFCNTR64_THREAD_EXIT flag is set.
	 */
	while (!(ksi->hki_perfcntr64_flags & HERMON_PERFCNTR64_THREAD_EXIT)) {
		for (i = 0; i < state->hs_cfg_profile->cp_num_ports; i++) {
			if (ksi->hki_perfcntr64[i].hki64_enabled) {
				(void) hermon_kstat_perfcntr64_read(state,
				    i + 1, 1);
			}
		}
		/* sleep for a second */
		(void) cv_reltimedwait(&ksi->hki_perfcntr64_cv,
		    &ksi->hki_perfcntr64_lock, delta, TR_CLOCK_TICK);
	}
	ksi->hki_perfcntr64_flags = 0;
	mutex_exit(&ksi->hki_perfcntr64_lock);
}

/*
 * hermon_kstat_perfcntr64_thread_create()
 *    Context: Called from the kstat context
 *
 * Create a thread that maintains 64 bit performance counters in software.
 */
static void
hermon_kstat_perfcntr64_thread_create(hermon_state_t *state)
{
	hermon_ks_info_t	*ksi = state->hs_ks_info;
	kthread_t		*thr;

	ASSERT(MUTEX_HELD(&ksi->hki_perfcntr64_lock));

	/*
	 * One thread per hermon instance. Don't create a thread if already
	 * created.
	 */
	if (!(ksi->hki_perfcntr64_flags & HERMON_PERFCNTR64_THREAD_CREATED)) {
		thr = thread_create(NULL, 0,
		    hermon_kstat_perfcntr64_update_thread,
		    state, 0, &p0, TS_RUN, minclsyspri);
		ksi->hki_perfcntr64_thread_id = thr->t_did;
		ksi->hki_perfcntr64_flags |= HERMON_PERFCNTR64_THREAD_CREATED;
	}
}

/*
 * hermon_kstat_perfcntr64_thread_exit()
 *    Context: Called from attach, detach or kstat context
 */
static void
hermon_kstat_perfcntr64_thread_exit(hermon_ks_info_t *ksi)
{
	kt_did_t	tid;

	ASSERT(MUTEX_HELD(&ksi->hki_perfcntr64_lock));

	if (ksi->hki_perfcntr64_flags & HERMON_PERFCNTR64_THREAD_CREATED) {
		/*
		 * Signal the thread to exit and wait until the thread exits.
		 */
		ksi->hki_perfcntr64_flags |= HERMON_PERFCNTR64_THREAD_EXIT;
		tid = ksi->hki_perfcntr64_thread_id;
		cv_signal(&ksi->hki_perfcntr64_cv);

		mutex_exit(&ksi->hki_perfcntr64_lock);
		thread_join(tid);
		mutex_enter(&ksi->hki_perfcntr64_lock);
	}
}

/*
 * hermon_kstat_perfcntr64_update_ext()
 *    Context: Called from the kstat context
 *
 * Update perf_counters kstats with the values of the extended port counters
 * from the hardware.
 */
static int
hermon_kstat_perfcntr64_update_ext(hermon_perfcntr64_ks_info_t *ksi64, int rw,
    struct kstat_named *data)
{
	hermon_hw_sm_extperfcntr_t	sm_extperfcntr;

	/*
	 * The "enable" component of the kstat is the only writable kstat.
	 * It is a no-op when the hardware supports extended port counters.
	 */
	if (rw == KSTAT_WRITE)
		return (0);

	/*
	 * Read the counters and update kstats.
	 */
	if (hermon_getextperfcntr_cmd_post(ksi64->hki64_state,
	    ksi64->hki64_port_num, HERMON_CMD_NOSLEEP_SPIN, &sm_extperfcntr) !=
	    HERMON_CMD_SUCCESS) {
		return (EIO);
	}

	data[HERMON_PERFCNTR64_ENABLE_IDX].value.ui32 = 1;

	data[HERMON_PERFCNTR64_XMIT_DATA_IDX].value.ui64 =
	    sm_extperfcntr.portxmdata;

	data[HERMON_PERFCNTR64_RECV_DATA_IDX].value.ui64 =
	    sm_extperfcntr.portrcdata;

	data[HERMON_PERFCNTR64_XMIT_PKTS_IDX].value.ui64 =
	    sm_extperfcntr.portxmpkts;

	data[HERMON_PERFCNTR64_RECV_PKTS_IDX].value.ui64 =
	    sm_extperfcntr.portrcpkts;

	return (0);
}

/*
 * hermon_kstat_perfcntr64_update()
 *    Context: Called from the kstat context
 *
 * See the general comment on 64 bit kstats for performance counters:
 */
static int
hermon_kstat_perfcntr64_update(kstat_t *ksp, int rw)
{
	hermon_state_t			*state;
	struct kstat_named		*data;
	hermon_ks_info_t		*ksi;
	hermon_perfcntr64_ks_info_t	*ksi64;
	int				i, thr_exit;
	int				rv;

	ksi64	= ksp->ks_private;
	state	= ksi64->hki64_state;
	ksi	= state->hs_ks_info;
	data	= (struct kstat_named *)(ksp->ks_data);

	mutex_enter(&ksi->hki_perfcntr64_lock);

	if (ksi64->hki64_ext_port_counters_supported) {
		rv = hermon_kstat_perfcntr64_update_ext(ksi64, rw, data);
		mutex_exit(&ksi->hki_perfcntr64_lock);
		return (rv);
	}

	/*
	 * 64 bit performance counters maintained by the software is not
	 * enabled by default. Enable them upon a writing a non-zero value
	 * to "enable" kstat. Disable them upon a writing zero to the
	 * "enable" kstat.
	 */
	if (rw == KSTAT_WRITE) {
		if (data[HERMON_PERFCNTR64_ENABLE_IDX].value.ui32) {
			if (ksi64->hki64_enabled == 0) {
				/*
				 * Reset the hardware counters to ensure that
				 * the hardware counter doesn't max out
				 * (and hence stop counting) before we get
				 * a chance to reset the counter in
				 * hermon_kstat_perfcntr64_update_thread.
				 */
				if (hermon_getperfcntr_cmd_post(state,
				    ksi64->hki64_port_num,
				    HERMON_CMD_NOSLEEP_SPIN, NULL, 1) !=
				    HERMON_CMD_SUCCESS) {
					mutex_exit(&ksi->hki_perfcntr64_lock);
					return (EIO);
				}

				/* Enable 64 bit software counters */
				ksi64->hki64_enabled = 1;
				for (i = 0;
				    i < HERMON_PERFCNTR64_NUM_COUNTERS; i++) {
					ksi64->hki64_counters[i] = 0;
					ksi64->hki64_last_read[i] = 0;
				}
				hermon_kstat_perfcntr64_thread_create(state);
			}

		} else if (ksi64->hki64_enabled) {
			/* Disable 64 bit software counters */
			ksi64->hki64_enabled = 0;
			thr_exit = 1;
			for (i = 0; i < state->hs_cfg_profile->cp_num_ports;
			    i++) {
				if (ksi->hki_perfcntr64[i].hki64_enabled) {
					thr_exit = 0;
					break;
				}
			}
			if (thr_exit)
				hermon_kstat_perfcntr64_thread_exit(ksi);
		}
	} else if (ksi64->hki64_enabled) {
		/*
		 * Read the counters and update kstats.
		 */
		if (hermon_kstat_perfcntr64_read(state, ksi64->hki64_port_num,
		    0) != HERMON_CMD_SUCCESS) {
			mutex_exit(&ksi->hki_perfcntr64_lock);
			return (EIO);
		}

		data[HERMON_PERFCNTR64_ENABLE_IDX].value.ui32 = 1;

		data[HERMON_PERFCNTR64_XMIT_DATA_IDX].value.ui64 =
		    ksi64->hki64_counters[HERMON_PERFCNTR64_XMIT_DATA_IDX] +
		    ksi64->hki64_last_read[HERMON_PERFCNTR64_XMIT_DATA_IDX];

		data[HERMON_PERFCNTR64_RECV_DATA_IDX].value.ui64 =
		    ksi64->hki64_counters[HERMON_PERFCNTR64_RECV_DATA_IDX] +
		    ksi64->hki64_last_read[HERMON_PERFCNTR64_RECV_DATA_IDX];

		data[HERMON_PERFCNTR64_XMIT_PKTS_IDX].value.ui64 =
		    ksi64->hki64_counters[HERMON_PERFCNTR64_XMIT_PKTS_IDX] +
		    ksi64->hki64_last_read[HERMON_PERFCNTR64_XMIT_PKTS_IDX];

		data[HERMON_PERFCNTR64_RECV_PKTS_IDX].value.ui64 =
		    ksi64->hki64_counters[HERMON_PERFCNTR64_RECV_PKTS_IDX] +
		    ksi64->hki64_last_read[HERMON_PERFCNTR64_RECV_PKTS_IDX];

	} else {
		/* return 0 in kstats if not enabled */
		data[HERMON_PERFCNTR64_ENABLE_IDX].value.ui32 = 0;
		for (i = 1; i < HERMON_PERFCNTR64_NUM_COUNTERS; i++)
			data[i].value.ui64 = 0;
	}

	mutex_exit(&ksi->hki_perfcntr64_lock);
	return (0);
}
