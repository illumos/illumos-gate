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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * This file provides prototype function definitions.
 */
#ifndef	_PMCS_PROTO_H
#define	_PMCS_PROTO_H
#ifdef	__cplusplus
extern "C" {
#endif


typedef enum {
	PMCS_PRT_DEBUG = 0,
	PMCS_PRT_DEBUG1,
	PMCS_PRT_DEBUG2,
	PMCS_PRT_DEBUG3,
	PMCS_PRT_DEBUG_CONFIG,
	PMCS_PRT_DEBUG_IPORT,
	PMCS_PRT_DEBUG_MAP,
	PMCS_PRT_DEBUG_UNDERFLOW,
	PMCS_PRT_DEBUG_SCSI_STATUS,
	PMCS_PRT_DEBUG_PHY_LOCKING,
	PMCS_PRT_DEBUG_DEV_STATE,
	PMCS_PRT_DEBUG_DEVEL,
	PMCS_PRT_INFO,
	PMCS_PRT_WARN,
	PMCS_PRT_ERR
} pmcs_prt_level_t;

#define	pmcs_prt(pwp, level, phy, tgt, fmt...) {		\
	int lvl = level;					\
	if (((pwp->debug_mask & (1 << lvl)) != 0) ||		\
	    (lvl > PMCS_PRT_DEBUG_DEVEL)) {			\
		pmcs_prt_impl(pwp, lvl, phy, tgt, fmt);		\
	}							\
}

/*PRINTFLIKE5*/
void
pmcs_prt_impl(pmcs_hw_t *, pmcs_prt_level_t, pmcs_phy_t *, pmcs_xscsi_t *,
    const char *, ...) __KPRINTFLIKE(5);

boolean_t pmcs_assign_device(pmcs_hw_t *, pmcs_xscsi_t *);
void pmcs_remove_device(pmcs_hw_t *, pmcs_phy_t *);
void pmcs_handle_dead_phys(pmcs_hw_t *);

int pmcs_acquire_scratch(pmcs_hw_t *, boolean_t);
void pmcs_release_scratch(pmcs_hw_t *);

/* get a work structure */
pmcwork_t *pmcs_gwork(pmcs_hw_t *, uint32_t, pmcs_phy_t *);

/* put a work structure */
void pmcs_pwork(pmcs_hw_t *, struct pmcwork *);

/* given a tag, find a work structure */
pmcwork_t *pmcs_tag2wp(pmcs_hw_t *, uint32_t, boolean_t);

/*
 * Abort function
 */
int pmcs_abort(pmcs_hw_t *, pmcs_phy_t *, uint32_t, int, int);

/*
 * SSP Task Management Function
 */
int pmcs_ssp_tmf(pmcs_hw_t *, pmcs_phy_t *, uint8_t, uint32_t, uint64_t,
    uint32_t *);

/*
 * Abort NCQ function
 */
int pmcs_sata_abort_ncq(pmcs_hw_t *, pmcs_phy_t *);

/*
 * Interrupt Functions
 */
void pmcs_general_intr(pmcs_hw_t *);
void pmcs_iodone_intr(pmcs_hw_t *);
void pmcs_event_intr(pmcs_hw_t *);
void pmcs_timed_out(pmcs_hw_t *, uint32_t, const char *);

/*
 * Abort handler
 */
int pmcs_abort_handler(pmcs_hw_t *);

/*
 * Deregister all expander connected devices
 */
void pmcs_deregister_devices(pmcs_hw_t *, pmcs_phy_t *);
int pmcs_register_device(pmcs_hw_t *, pmcs_phy_t *);
void pmcs_deregister_device(pmcs_hw_t *, pmcs_phy_t *);

/*
 * endian transform a data structure
 */
void pmcs_endian_transform(pmcs_hw_t *, void *, void *, const uint8_t *);

/* get the connection rate string */
const char *pmcs_get_rate(unsigned int);

/* get the device type string */
const char *pmcs_get_typename(pmcs_dtype_t pmcs_dtype);

/* get the SAS Task Management function name */
const char *pmcs_tmf2str(int);

/* get the PMC status string */
const char *pmcs_status_str(uint32_t);

/*
 * WWN to Byte Array and vice versa conversion
 */
uint64_t pmcs_barray2wwn(uint8_t[8]);
void pmcs_wwn2barray(uint64_t, uint8_t[8]);

/*
 * Print f/w version
 */
void pmcs_report_fwversion(pmcs_hw_t *);

/*
 * Build a device name.
 */
void pmcs_phy_name(pmcs_hw_t *, pmcs_phy_t *, char *, size_t);

/*
 * Find a PHY by wwn
 */
pmcs_phy_t *pmcs_find_phy_by_wwn(pmcs_hw_t *, uint64_t);

/*
 * Find a PHY by sas_address
 */
pmcs_phy_t *pmcs_find_phy_by_sas_address(pmcs_hw_t *, pmcs_iport_t *,
    pmcs_phy_t *, char *);

/*
 * Print out a FIS
 */
void pmcs_fis_dump(pmcs_hw_t *, fis_t);

/*
 * Print an IOMB
 */
void pmcs_print_entry(pmcs_hw_t *, int, char *, void *);

void pmcs_spinup_release(pmcs_hw_t *, pmcs_phy_t *phyp);

/*
 * Handler for events - can be called from interrupt level or from worker thread
 */
void pmcs_ack_events(pmcs_hw_t *);

/*
 * This function does some initial setup and hardware validation
 */
int pmcs_setup(pmcs_hw_t *);

/*
 * These functions start and stop the MPI (message passing interface)
 */
int pmcs_start_mpi(pmcs_hw_t *);
int pmcs_stop_mpi(pmcs_hw_t *);

/*
 * This function checks firmware revisions against required revisions
 * and attempts to flash new firmware (if possible).
 */
int pmcs_firmware_update(pmcs_hw_t *);

/*
 * This function runs ECHO commands to test both interrupts and queues
 */
int pmcs_echo_test(pmcs_hw_t *);

/*
 * These functions start, reset, and stop the physical chip PHYs
 */
int pmcs_start_phy(pmcs_hw_t *, int, int, int);
int pmcs_start_phys(pmcs_hw_t *);
void pmcs_stop_phy(pmcs_hw_t *, int);
void pmcs_stop_phys(pmcs_hw_t *);

/*
 * These functions setup/teardown iport tgtmap
 */
int pmcs_iport_tgtmap_create(pmcs_iport_t *);
int pmcs_iport_tgtmap_destroy(pmcs_iport_t *);

/*
 * Utility and wrapper functions for SAS_DIAG_EXECUTE
 */
int pmcs_sas_diag_execute(pmcs_hw_t *, uint32_t, uint32_t, uint8_t);
int pmcs_get_diag_report(pmcs_hw_t *, uint32_t, uint8_t);
int pmcs_clear_diag_counters(pmcs_hw_t *, uint8_t);

/*
 * Register Dump (including "internal" registers)
 */
void pmcs_register_dump(pmcs_hw_t *);
void pmcs_iqp_trace(pmcs_hw_t *, uint32_t);
void pmcs_register_dump_int(pmcs_hw_t *);
int pmcs_dump_binary(pmcs_hw_t *, uint32_t *, uint32_t,
    uint32_t, caddr_t, uint32_t);
int pmcs_dump_feregs(pmcs_hw_t *, uint32_t *, uint8_t,
    caddr_t, uint32_t);

/*
 * This function perform a soft reset.
 * Hard reset is platform specific.
 */
int pmcs_soft_reset(pmcs_hw_t *, boolean_t);

/*
 * This is a hot reset which will attempt reconfiguration after reset.
 */
int pmcs_hot_reset(pmcs_hw_t *);

/*
 * Some more reset functions
 */
int pmcs_reset_dev(pmcs_hw_t *, pmcs_phy_t *, uint64_t);
int pmcs_reset_phy(pmcs_hw_t *, pmcs_phy_t *, uint8_t);

/*
 * These functions do topology configuration changes
 */
void pmcs_discover(pmcs_hw_t *);
void pmcs_set_changed(pmcs_hw_t *, pmcs_phy_t *, boolean_t, int);
void pmcs_kill_changed(pmcs_hw_t *, pmcs_phy_t *, int);
void pmcs_clear_phy(pmcs_hw_t *, pmcs_phy_t *);
int pmcs_kill_device(pmcs_hw_t *, pmcs_phy_t *);

/*
 * Firmware flash function
 */
int pmcs_fw_flash(pmcs_hw_t *, pmcs_fw_hdr_t *, uint32_t);

/*
 * Set a new value for the interrupt coalescing timer.  If it's being set
 * to zero (disabling), then re-enable auto clear if necessary.  If it's
 * being changed from zero, turn off auto clear if it was on.
 */
typedef enum {
	DECREASE_TIMER = 0,
	INCREASE_TIMER
} pmcs_coal_timer_adj_t;

void pmcs_check_intr_coal(void *arg);
void pmcs_set_intr_coal_timer(pmcs_hw_t *pwp, pmcs_coal_timer_adj_t adj);

/*
 * Misc supporting routines
 */
void pmcs_check_iomb_status(pmcs_hw_t *pwp, uint32_t *iomb);
void pmcs_clear_xp(pmcs_hw_t *, pmcs_xscsi_t *);
void pmcs_create_one_phy_stats(pmcs_iport_t *, pmcs_phy_t *);
int pmcs_run_sata_cmd(pmcs_hw_t *, pmcs_phy_t *, fis_t, uint32_t,
    uint32_t, uint32_t);
int pmcs_sata_identify(pmcs_hw_t *, pmcs_phy_t *);
void pmcs_sata_work(pmcs_hw_t *);
boolean_t pmcs_dma_setup(pmcs_hw_t *pwp, ddi_dma_attr_t *dma_attr,
    ddi_acc_handle_t *acch, ddi_dma_handle_t *dmah, size_t length,
    caddr_t *kvap, uint64_t *dma_addr);
void pmcs_fm_ereport(pmcs_hw_t *pwp, char *detail);
int pmcs_check_dma_handle(ddi_dma_handle_t handle);
int pmcs_check_acc_handle(ddi_acc_handle_t handle);
int pmcs_check_acc_dma_handle(pmcs_hw_t *pwp);
int pmcs_get_nvmd(pmcs_hw_t *pwp, pmcs_nvmd_type_t nvmd_type, uint8_t nvmd,
    uint32_t offset, char *buf, uint32_t size_left);
boolean_t pmcs_set_nvmd(pmcs_hw_t *pwp, pmcs_nvmd_type_t nvmd_type,
    uint8_t *buf, size_t len);
void pmcs_complete_work_impl(pmcs_hw_t *pwp, pmcwork_t *pwrk, uint32_t *iomb,
    size_t amt);
void pmcs_flush_target_queues(pmcs_hw_t *, pmcs_xscsi_t *, uint8_t);
boolean_t pmcs_iport_has_targets(pmcs_hw_t *, pmcs_iport_t *);
void pmcs_free_dma_chunklist(pmcs_hw_t *);
void pmcs_dev_state_recovery(pmcs_hw_t *, pmcs_phy_t *);
void pmcs_deregister_device_work(pmcs_hw_t *, pmcs_phy_t *);
int pmcs_send_err_recovery_cmd(pmcs_hw_t *, uint8_t, pmcs_phy_t *,
    pmcs_xscsi_t *);
void pmcs_start_ssp_event_recovery(pmcs_hw_t *pwp, pmcwork_t *pwrk,
    uint32_t *iomb, size_t amt);
void pmcs_ssp_event_recovery(pmcs_hw_t *);

pmcs_iport_t *pmcs_get_iport_by_wwn(pmcs_hw_t *pwp, uint64_t wwn);
pmcs_phy_t *pmcs_promote_next_phy(pmcs_phy_t *pptr);
void pmcs_hold_iport(pmcs_iport_t *iport);
void pmcs_rele_iport(pmcs_iport_t *iport);
int pmcs_iport_configure_phys(pmcs_iport_t *iport);
void pmcs_iport_teardown_phys(pmcs_iport_t *iport);

void pmcs_lock_phy(pmcs_phy_t *);
void pmcs_unlock_phy(pmcs_phy_t *);

void pmcs_destroy_target(pmcs_xscsi_t *);
void pmcs_phymap_activate(void *, char *, void **);
void pmcs_phymap_deactivate(void *, char *, void *);
void pmcs_add_phy_to_iport(pmcs_iport_t *, pmcs_phy_t *);
void pmcs_remove_phy_from_iport(pmcs_iport_t *, pmcs_phy_t *);
void pmcs_free_all_phys(pmcs_hw_t *, pmcs_phy_t *);
void pmcs_free_phys(pmcs_hw_t *, pmcs_phy_t *);

int pmcs_phy_constructor(void *, void *, int);
void pmcs_phy_destructor(void *, void *);

void pmcs_inc_phy_ref_count(pmcs_phy_t *);
void pmcs_dec_phy_ref_count(pmcs_phy_t *);

/* Worker thread */
void pmcs_worker(void *);

pmcs_phy_t *pmcs_get_root_phy(pmcs_phy_t *);
pmcs_xscsi_t *pmcs_get_target(pmcs_iport_t *, char *, boolean_t);

void pmcs_fatal_handler(pmcs_hw_t *);

/*
 * Schedule device state recovery for this device immediately
 */
void pmcs_start_dev_state_recovery(pmcs_xscsi_t *, pmcs_phy_t *);

/*
 * Functions to serialize SMP requests
 */
void pmcs_smp_acquire(pmcs_iport_t *iport);
void pmcs_smp_release(pmcs_iport_t *iport);

/*
 * Update attached-port-pm and target-port-pm properties on a PHY
 */
void pmcs_update_phy_pm_props(pmcs_phy_t *, uint64_t, uint64_t, boolean_t);

/*
 * Determine whether it's worth retrying enumeration
 */
void pmcs_status_disposition(pmcs_phy_t *, uint32_t);

/*
 * Write out firmware event log (if configured to do so) if it's filled up
 */
void pmcs_gather_fwlog(pmcs_hw_t *);

#ifdef	__cplusplus
}
#endif
#endif	/* _PMCS_PROTO_H */
