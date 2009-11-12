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
 *
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file contains various support routines.
 */

#include <sys/scsi/adapters/pmcs/pmcs.h>

/*
 * Local static data
 */
static int tgtmap_usec = MICROSEC;

/*
 * SAS Topology Configuration
 */
static void pmcs_new_tport(pmcs_hw_t *, pmcs_phy_t *);
static void pmcs_configure_expander(pmcs_hw_t *, pmcs_phy_t *, pmcs_iport_t *);

static boolean_t pmcs_check_expanders(pmcs_hw_t *, pmcs_phy_t *);
static void pmcs_check_expander(pmcs_hw_t *, pmcs_phy_t *);
static void pmcs_clear_expander(pmcs_hw_t *, pmcs_phy_t *, int);

static int pmcs_expander_get_nphy(pmcs_hw_t *, pmcs_phy_t *);
static int pmcs_expander_content_discover(pmcs_hw_t *, pmcs_phy_t *,
    pmcs_phy_t *);

static int pmcs_smp_function_result(pmcs_hw_t *, smp_response_frame_t *);
static boolean_t pmcs_validate_devid(pmcs_phy_t *, pmcs_phy_t *, uint32_t);
static void pmcs_clear_phys(pmcs_hw_t *, pmcs_phy_t *);
static int pmcs_configure_new_devices(pmcs_hw_t *, pmcs_phy_t *);
static boolean_t pmcs_report_observations(pmcs_hw_t *);
static boolean_t pmcs_report_iport_observations(pmcs_hw_t *, pmcs_iport_t *,
    pmcs_phy_t *);
static pmcs_phy_t *pmcs_find_phy_needing_work(pmcs_hw_t *, pmcs_phy_t *);
static int pmcs_kill_devices(pmcs_hw_t *, pmcs_phy_t *);
static void pmcs_lock_phy_impl(pmcs_phy_t *, int);
static void pmcs_unlock_phy_impl(pmcs_phy_t *, int);
static pmcs_phy_t *pmcs_clone_phy(pmcs_phy_t *);
static boolean_t pmcs_configure_phy(pmcs_hw_t *, pmcs_phy_t *);
static void pmcs_reap_dead_phy(pmcs_phy_t *);
static pmcs_iport_t *pmcs_get_iport_by_ua(pmcs_hw_t *, char *);
static boolean_t pmcs_phy_target_match(pmcs_phy_t *);
static void pmcs_handle_ds_recovery_error(pmcs_phy_t *phyp,
    pmcs_xscsi_t *tgt, pmcs_hw_t *pwp, const char *func_name, int line,
    char *reason_string);

/*
 * Often used strings
 */
const char pmcs_nowrk[] = "%s: unable to get work structure";
const char pmcs_nomsg[] = "%s: unable to get Inbound Message entry";
const char pmcs_timeo[] = "!%s: command timed out";

extern const ddi_dma_attr_t pmcs_dattr;

/*
 * Some Initial setup steps.
 */

int
pmcs_setup(pmcs_hw_t *pwp)
{
	uint32_t barval = pwp->mpibar;
	uint32_t i, scratch, regbar, regoff, barbar, baroff;
	uint32_t new_ioq_depth, ferr = 0;

	/*
	 * Check current state. If we're not at READY state,
	 * we can't go further.
	 */
	scratch = pmcs_rd_msgunit(pwp, PMCS_MSGU_SCRATCH1);
	if ((scratch & PMCS_MSGU_AAP_STATE_MASK) == PMCS_MSGU_AAP_STATE_ERROR) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: AAP Error State (0x%x)",
		    __func__, pmcs_rd_msgunit(pwp, PMCS_MSGU_SCRATCH1) &
		    PMCS_MSGU_AAP_ERROR_MASK);
		pmcs_fm_ereport(pwp, DDI_FM_DEVICE_INVAL_STATE);
		ddi_fm_service_impact(pwp->dip, DDI_SERVICE_LOST);
		return (-1);
	}
	if ((scratch & PMCS_MSGU_AAP_STATE_MASK) != PMCS_MSGU_AAP_STATE_READY) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: AAP unit not ready (state 0x%x)",
		    __func__, scratch & PMCS_MSGU_AAP_STATE_MASK);
		pmcs_fm_ereport(pwp, DDI_FM_DEVICE_INVAL_STATE);
		ddi_fm_service_impact(pwp->dip, DDI_SERVICE_LOST);
		return (-1);
	}

	/*
	 * Read the offset from the Message Unit scratchpad 0 register.
	 * This allows us to read the MPI Configuration table.
	 *
	 * Check its signature for validity.
	 */
	baroff = barval;
	barbar = barval >> PMCS_MSGU_MPI_BAR_SHIFT;
	baroff &= PMCS_MSGU_MPI_OFFSET_MASK;

	regoff = pmcs_rd_msgunit(pwp, PMCS_MSGU_SCRATCH0);
	regbar = regoff >> PMCS_MSGU_MPI_BAR_SHIFT;
	regoff &= PMCS_MSGU_MPI_OFFSET_MASK;

	if (regoff > baroff) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: bad MPI Table Length (register offset=0x%08x, "
		    "passed offset=0x%08x)", __func__, regoff, baroff);
		return (-1);
	}
	if (regbar != barbar) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: bad MPI BAR (register BAROFF=0x%08x, "
		    "passed BAROFF=0x%08x)", __func__, regbar, barbar);
		return (-1);
	}
	pwp->mpi_offset = regoff;
	if (pmcs_rd_mpi_tbl(pwp, PMCS_MPI_AS) != PMCS_SIGNATURE) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: Bad MPI Configuration Table Signature 0x%x", __func__,
		    pmcs_rd_mpi_tbl(pwp, PMCS_MPI_AS));
		return (-1);
	}

	if (pmcs_rd_mpi_tbl(pwp, PMCS_MPI_IR) != PMCS_MPI_REVISION1) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: Bad MPI Configuration Revision 0x%x", __func__,
		    pmcs_rd_mpi_tbl(pwp, PMCS_MPI_IR));
		return (-1);
	}

	/*
	 * Generate offsets for the General System, Inbound Queue Configuration
	 * and Outbound Queue configuration tables. This way the macros to
	 * access those tables will work correctly.
	 */
	pwp->mpi_gst_offset =
	    pwp->mpi_offset + pmcs_rd_mpi_tbl(pwp, PMCS_MPI_GSTO);
	pwp->mpi_iqc_offset =
	    pwp->mpi_offset + pmcs_rd_mpi_tbl(pwp, PMCS_MPI_IQCTO);
	pwp->mpi_oqc_offset =
	    pwp->mpi_offset + pmcs_rd_mpi_tbl(pwp, PMCS_MPI_OQCTO);

	pwp->fw = pmcs_rd_mpi_tbl(pwp, PMCS_MPI_FW);

	pwp->max_cmd = pmcs_rd_mpi_tbl(pwp, PMCS_MPI_MOIO);
	pwp->max_dev = pmcs_rd_mpi_tbl(pwp, PMCS_MPI_INFO0) >> 16;

	pwp->max_iq = PMCS_MNIQ(pmcs_rd_mpi_tbl(pwp, PMCS_MPI_INFO1));
	pwp->max_oq = PMCS_MNOQ(pmcs_rd_mpi_tbl(pwp, PMCS_MPI_INFO1));
	pwp->nphy = PMCS_NPHY(pmcs_rd_mpi_tbl(pwp, PMCS_MPI_INFO1));
	if (pwp->max_iq <= PMCS_NIQ) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: not enough Inbound Queues supported "
		    "(need %d, max_oq=%d)", __func__, pwp->max_iq, PMCS_NIQ);
		return (-1);
	}
	if (pwp->max_oq <= PMCS_NOQ) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: not enough Outbound Queues supported "
		    "(need %d, max_oq=%d)", __func__, pwp->max_oq, PMCS_NOQ);
		return (-1);
	}
	if (pwp->nphy == 0) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: zero phys reported", __func__);
		return (-1);
	}
	if (PMCS_HPIQ(pmcs_rd_mpi_tbl(pwp, PMCS_MPI_INFO1))) {
		pwp->hipri_queue = (1 << PMCS_IQ_OTHER);
	}


	for (i = 0; i < pwp->nphy; i++) {
		PMCS_MPI_EVQSET(pwp, PMCS_OQ_EVENTS, i);
		PMCS_MPI_NCQSET(pwp, PMCS_OQ_EVENTS, i);
	}

	pmcs_wr_mpi_tbl(pwp, PMCS_MPI_INFO2,
	    (PMCS_OQ_EVENTS << GENERAL_EVENT_OQ_SHIFT) |
	    (PMCS_OQ_EVENTS << DEVICE_HANDLE_REMOVED_SHIFT));

	/*
	 * Verify that ioq_depth is valid (> 0 and not so high that it
	 * would cause us to overrun the chip with commands).
	 */
	if (pwp->ioq_depth == 0) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: I/O queue depth set to 0. Setting to %d",
		    __func__, PMCS_NQENTRY);
		pwp->ioq_depth = PMCS_NQENTRY;
	}

	if (pwp->ioq_depth < PMCS_MIN_NQENTRY) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: I/O queue depth set too low (%d). Setting to %d",
		    __func__, pwp->ioq_depth, PMCS_MIN_NQENTRY);
		pwp->ioq_depth = PMCS_MIN_NQENTRY;
	}

	if (pwp->ioq_depth > (pwp->max_cmd / (PMCS_IO_IQ_MASK + 1))) {
		new_ioq_depth = pwp->max_cmd / (PMCS_IO_IQ_MASK + 1);
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: I/O queue depth set too high (%d). Setting to %d",
		    __func__, pwp->ioq_depth, new_ioq_depth);
		pwp->ioq_depth = new_ioq_depth;
	}

	/*
	 * Allocate consistent memory for OQs and IQs.
	 */
	pwp->iqp_dma_attr = pwp->oqp_dma_attr = pmcs_dattr;
	pwp->iqp_dma_attr.dma_attr_align =
	    pwp->oqp_dma_attr.dma_attr_align = PMCS_QENTRY_SIZE;

	/*
	 * The Rev C chip has the ability to do PIO to or from consistent
	 * memory anywhere in a 64 bit address space, but the firmware is
	 * not presently set up to do so.
	 */
	pwp->iqp_dma_attr.dma_attr_addr_hi =
	    pwp->oqp_dma_attr.dma_attr_addr_hi = 0x000000FFFFFFFFFFull;

	for (i = 0; i < PMCS_NIQ; i++) {
		if (pmcs_dma_setup(pwp, &pwp->iqp_dma_attr,
		    &pwp->iqp_acchdls[i],
		    &pwp->iqp_handles[i], PMCS_QENTRY_SIZE * pwp->ioq_depth,
		    (caddr_t *)&pwp->iqp[i], &pwp->iqaddr[i]) == B_FALSE) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
			    "Failed to setup DMA for iqp[%d]", i);
			return (-1);
		}
		bzero(pwp->iqp[i], PMCS_QENTRY_SIZE * pwp->ioq_depth);
	}

	for (i = 0; i < PMCS_NOQ; i++) {
		if (pmcs_dma_setup(pwp, &pwp->oqp_dma_attr,
		    &pwp->oqp_acchdls[i],
		    &pwp->oqp_handles[i], PMCS_QENTRY_SIZE * pwp->ioq_depth,
		    (caddr_t *)&pwp->oqp[i], &pwp->oqaddr[i]) == B_FALSE) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
			    "Failed to setup DMA for oqp[%d]", i);
			return (-1);
		}
		bzero(pwp->oqp[i], PMCS_QENTRY_SIZE * pwp->ioq_depth);
	}

	/*
	 * Install the IQ and OQ addresses (and null out the rest).
	 */
	for (i = 0; i < pwp->max_iq; i++) {
		pwp->iqpi_offset[i] = pmcs_rd_iqc_tbl(pwp, PMCS_IQPIOFFX(i));
		if (i < PMCS_NIQ) {
			if (i != PMCS_IQ_OTHER) {
				pmcs_wr_iqc_tbl(pwp, PMCS_IQC_PARMX(i),
				    pwp->ioq_depth | (PMCS_QENTRY_SIZE << 16));
			} else {
				pmcs_wr_iqc_tbl(pwp, PMCS_IQC_PARMX(i),
				    (1 << 30) | pwp->ioq_depth |
				    (PMCS_QENTRY_SIZE << 16));
			}
			pmcs_wr_iqc_tbl(pwp, PMCS_IQBAHX(i),
			    DWORD1(pwp->iqaddr[i]));
			pmcs_wr_iqc_tbl(pwp, PMCS_IQBALX(i),
			    DWORD0(pwp->iqaddr[i]));
			pmcs_wr_iqc_tbl(pwp, PMCS_IQCIBAHX(i),
			    DWORD1(pwp->ciaddr+IQ_OFFSET(i)));
			pmcs_wr_iqc_tbl(pwp, PMCS_IQCIBALX(i),
			    DWORD0(pwp->ciaddr+IQ_OFFSET(i)));
		} else {
			pmcs_wr_iqc_tbl(pwp, PMCS_IQC_PARMX(i), 0);
			pmcs_wr_iqc_tbl(pwp, PMCS_IQBAHX(i), 0);
			pmcs_wr_iqc_tbl(pwp, PMCS_IQBALX(i), 0);
			pmcs_wr_iqc_tbl(pwp, PMCS_IQCIBAHX(i), 0);
			pmcs_wr_iqc_tbl(pwp, PMCS_IQCIBALX(i), 0);
		}
	}

	for (i = 0; i < pwp->max_oq; i++) {
		pwp->oqci_offset[i] = pmcs_rd_oqc_tbl(pwp, PMCS_OQCIOFFX(i));
		if (i < PMCS_NOQ) {
			pmcs_wr_oqc_tbl(pwp, PMCS_OQC_PARMX(i), pwp->ioq_depth |
			    (PMCS_QENTRY_SIZE << 16) | OQIEX);
			pmcs_wr_oqc_tbl(pwp, PMCS_OQBAHX(i),
			    DWORD1(pwp->oqaddr[i]));
			pmcs_wr_oqc_tbl(pwp, PMCS_OQBALX(i),
			    DWORD0(pwp->oqaddr[i]));
			pmcs_wr_oqc_tbl(pwp, PMCS_OQPIBAHX(i),
			    DWORD1(pwp->ciaddr+OQ_OFFSET(i)));
			pmcs_wr_oqc_tbl(pwp, PMCS_OQPIBALX(i),
			    DWORD0(pwp->ciaddr+OQ_OFFSET(i)));
			pmcs_wr_oqc_tbl(pwp, PMCS_OQIPARM(i),
			    pwp->oqvec[i] << 24);
			pmcs_wr_oqc_tbl(pwp, PMCS_OQDICX(i), 0);
		} else {
			pmcs_wr_oqc_tbl(pwp, PMCS_OQC_PARMX(i), 0);
			pmcs_wr_oqc_tbl(pwp, PMCS_OQBAHX(i), 0);
			pmcs_wr_oqc_tbl(pwp, PMCS_OQBALX(i), 0);
			pmcs_wr_oqc_tbl(pwp, PMCS_OQPIBAHX(i), 0);
			pmcs_wr_oqc_tbl(pwp, PMCS_OQPIBALX(i), 0);
			pmcs_wr_oqc_tbl(pwp, PMCS_OQIPARM(i), 0);
			pmcs_wr_oqc_tbl(pwp, PMCS_OQDICX(i), 0);
		}
	}

	/*
	 * Set up logging, if defined.
	 */
	if (pwp->fwlog) {
		uint64_t logdma = pwp->fwaddr;
		pmcs_wr_mpi_tbl(pwp, PMCS_MPI_MELBAH, DWORD1(logdma));
		pmcs_wr_mpi_tbl(pwp, PMCS_MPI_MELBAL, DWORD0(logdma));
		pmcs_wr_mpi_tbl(pwp, PMCS_MPI_MELBS, PMCS_FWLOG_SIZE >> 1);
		pmcs_wr_mpi_tbl(pwp, PMCS_MPI_MELSEV, pwp->fwlog);
		logdma += (PMCS_FWLOG_SIZE >> 1);
		pmcs_wr_mpi_tbl(pwp, PMCS_MPI_IELBAH, DWORD1(logdma));
		pmcs_wr_mpi_tbl(pwp, PMCS_MPI_IELBAL, DWORD0(logdma));
		pmcs_wr_mpi_tbl(pwp, PMCS_MPI_IELBS, PMCS_FWLOG_SIZE >> 1);
		pmcs_wr_mpi_tbl(pwp, PMCS_MPI_IELSEV, pwp->fwlog);
	}

	/*
	 * Interrupt vectors, outbound queues, and odb_auto_clear
	 *
	 * MSI/MSI-X:
	 * If we got 4 interrupt vectors, we'll assign one to each outbound
	 * queue as well as the fatal interrupt, and auto clear can be set
	 * for each.
	 *
	 * If we only got 2 vectors, one will be used for I/O completions
	 * and the other for the other two vectors.  In this case, auto_
	 * clear can only be set for I/Os, which is fine.  The fatal
	 * interrupt will be mapped to the PMCS_FATAL_INTERRUPT bit, which
	 * is not an interrupt vector.
	 *
	 * MSI/MSI-X/INT-X:
	 * If we only got 1 interrupt vector, auto_clear must be set to 0,
	 * and again the fatal interrupt will be mapped to the
	 * PMCS_FATAL_INTERRUPT bit (again, not an interrupt vector).
	 */

	switch (pwp->int_type) {
	case PMCS_INT_MSIX:
	case PMCS_INT_MSI:
		switch (pwp->intr_cnt) {
		case 1:
			pmcs_wr_mpi_tbl(pwp, PMCS_MPI_FERR, PMCS_FERRIE |
			    (PMCS_FATAL_INTERRUPT << PMCS_FERIV_SHIFT));
			pwp->odb_auto_clear = 0;
			break;
		case 2:
			pmcs_wr_mpi_tbl(pwp, PMCS_MPI_FERR, PMCS_FERRIE |
			    (PMCS_FATAL_INTERRUPT << PMCS_FERIV_SHIFT));
			pwp->odb_auto_clear = (1 << PMCS_FATAL_INTERRUPT) |
			    (1 << PMCS_MSIX_IODONE);
			break;
		case 4:
			pmcs_wr_mpi_tbl(pwp, PMCS_MPI_FERR, PMCS_FERRIE |
			    (PMCS_MSIX_FATAL << PMCS_FERIV_SHIFT));
			pwp->odb_auto_clear = (1 << PMCS_MSIX_FATAL) |
			    (1 << PMCS_MSIX_GENERAL) | (1 << PMCS_MSIX_IODONE) |
			    (1 << PMCS_MSIX_EVENTS);
			break;
		}
		break;

	case PMCS_INT_FIXED:
		pmcs_wr_mpi_tbl(pwp, PMCS_MPI_FERR,
		    PMCS_FERRIE | (PMCS_FATAL_INTERRUPT << PMCS_FERIV_SHIFT));
		pwp->odb_auto_clear = 0;
		break;
	}

	/*
	 * Enable Interrupt Reassertion
	 * Default Delay 1000us
	 */
	ferr = pmcs_rd_mpi_tbl(pwp, PMCS_MPI_FERR);
	if ((ferr & PMCS_MPI_IRAE) == 0) {
		ferr &= ~(PMCS_MPI_IRAU | PMCS_MPI_IRAD_MASK);
		pmcs_wr_mpi_tbl(pwp, PMCS_MPI_FERR, ferr | PMCS_MPI_IRAE);
	}

	pmcs_wr_topunit(pwp, PMCS_OBDB_AUTO_CLR, pwp->odb_auto_clear);
	pwp->mpi_table_setup = 1;
	return (0);
}

/*
 * Start the Message Passing protocol with the PMC chip.
 */
int
pmcs_start_mpi(pmcs_hw_t *pwp)
{
	int i;

	pmcs_wr_msgunit(pwp, PMCS_MSGU_IBDB, PMCS_MSGU_IBDB_MPIINI);
	for (i = 0; i < 1000; i++) {
		if ((pmcs_rd_msgunit(pwp, PMCS_MSGU_IBDB) &
		    PMCS_MSGU_IBDB_MPIINI) == 0) {
			break;
		}
		drv_usecwait(1000);
	}
	if (pmcs_rd_msgunit(pwp, PMCS_MSGU_IBDB) & PMCS_MSGU_IBDB_MPIINI) {
		return (-1);
	}
	drv_usecwait(500000);

	/*
	 * Check to make sure we got to INIT state.
	 */
	if (PMCS_MPI_S(pmcs_rd_gst_tbl(pwp, PMCS_GST_BASE)) !=
	    PMCS_MPI_STATE_INIT) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: MPI launch failed (GST 0x%x DBCLR 0x%x)", __func__,
		    pmcs_rd_gst_tbl(pwp, PMCS_GST_BASE),
		    pmcs_rd_msgunit(pwp, PMCS_MSGU_IBDB_CLEAR));
		return (-1);
	}
	return (0);
}

/*
 * Stop the Message Passing protocol with the PMC chip.
 */
int
pmcs_stop_mpi(pmcs_hw_t *pwp)
{
	int i;

	for (i = 0; i < pwp->max_iq; i++) {
		pmcs_wr_iqc_tbl(pwp, PMCS_IQC_PARMX(i), 0);
		pmcs_wr_iqc_tbl(pwp, PMCS_IQBAHX(i), 0);
		pmcs_wr_iqc_tbl(pwp, PMCS_IQBALX(i), 0);
		pmcs_wr_iqc_tbl(pwp, PMCS_IQCIBAHX(i), 0);
		pmcs_wr_iqc_tbl(pwp, PMCS_IQCIBALX(i), 0);
	}
	for (i = 0; i < pwp->max_oq; i++) {
		pmcs_wr_oqc_tbl(pwp, PMCS_OQC_PARMX(i), 0);
		pmcs_wr_oqc_tbl(pwp, PMCS_OQBAHX(i), 0);
		pmcs_wr_oqc_tbl(pwp, PMCS_OQBALX(i), 0);
		pmcs_wr_oqc_tbl(pwp, PMCS_OQPIBAHX(i), 0);
		pmcs_wr_oqc_tbl(pwp, PMCS_OQPIBALX(i), 0);
		pmcs_wr_oqc_tbl(pwp, PMCS_OQIPARM(i), 0);
		pmcs_wr_oqc_tbl(pwp, PMCS_OQDICX(i), 0);
	}
	pmcs_wr_mpi_tbl(pwp, PMCS_MPI_FERR, 0);
	pmcs_wr_msgunit(pwp, PMCS_MSGU_IBDB, PMCS_MSGU_IBDB_MPICTU);
	for (i = 0; i < 2000; i++) {
		if ((pmcs_rd_msgunit(pwp, PMCS_MSGU_IBDB) &
		    PMCS_MSGU_IBDB_MPICTU) == 0) {
			break;
		}
		drv_usecwait(1000);
	}
	if (pmcs_rd_msgunit(pwp, PMCS_MSGU_IBDB) & PMCS_MSGU_IBDB_MPICTU) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: MPI stop failed", __func__);
		return (-1);
	}
	return (0);
}

/*
 * Do a sequence of ECHO messages to test for MPI functionality,
 * all inbound and outbound queue functionality and interrupts.
 */
int
pmcs_echo_test(pmcs_hw_t *pwp)
{
	echo_test_t fred;
	struct pmcwork *pwrk;
	uint32_t *msg, count;
	int iqe = 0, iqo = 0, result, rval = 0;
	int iterations;
	hrtime_t echo_start, echo_end, echo_total;

	ASSERT(pwp->max_cmd > 0);

	/*
	 * We want iterations to be max_cmd * 3 to ensure that we run the
	 * echo test enough times to iterate through every inbound queue
	 * at least twice.
	 */
	iterations = pwp->max_cmd * 3;

	echo_total = 0;
	count = 0;

	while (count < iterations) {
		pwrk = pmcs_gwork(pwp, PMCS_TAG_TYPE_WAIT, NULL);
		if (pwrk == NULL) {
			pmcs_prt(pwp, PMCS_PRT_ERR, NULL, NULL,
			    pmcs_nowrk, __func__);
			rval = -1;
			break;
		}

		mutex_enter(&pwp->iqp_lock[iqe]);
		msg = GET_IQ_ENTRY(pwp, iqe);
		if (msg == NULL) {
			mutex_exit(&pwp->iqp_lock[iqe]);
			pmcs_pwork(pwp, pwrk);
			pmcs_prt(pwp, PMCS_PRT_ERR, NULL, NULL,
			    pmcs_nomsg, __func__);
			rval = -1;
			break;
		}

		bzero(msg, PMCS_QENTRY_SIZE);

		if (iqe == PMCS_IQ_OTHER) {
			/* This is on the high priority queue */
			msg[0] = LE_32(PMCS_HIPRI(pwp, iqo, PMCIN_ECHO));
		} else {
			msg[0] = LE_32(PMCS_IOMB_IN_SAS(iqo, PMCIN_ECHO));
		}
		msg[1] = LE_32(pwrk->htag);
		fred.signature = 0xdeadbeef;
		fred.count = count;
		fred.ptr = &count;
		(void) memcpy(&msg[2], &fred, sizeof (fred));
		pwrk->state = PMCS_WORK_STATE_ONCHIP;

		INC_IQ_ENTRY(pwp, iqe);

		echo_start = gethrtime();
		DTRACE_PROBE2(pmcs__echo__test__wait__start,
		    hrtime_t, echo_start, uint32_t, pwrk->htag);

		if (++iqe == PMCS_NIQ) {
			iqe = 0;
		}
		if (++iqo == PMCS_NOQ) {
			iqo = 0;
		}

		WAIT_FOR(pwrk, 250, result);

		echo_end = gethrtime();
		DTRACE_PROBE2(pmcs__echo__test__wait__end,
		    hrtime_t, echo_end, int, result);

		echo_total += (echo_end - echo_start);

		pmcs_pwork(pwp, pwrk);
		if (result) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
			    "%s: command timed out on echo test #%d",
			    __func__, count);
			rval = -1;
			break;
		}
	}

	/*
	 * The intr_threshold is adjusted by PMCS_INTR_THRESHOLD in order to
	 * remove the overhead of things like the delay in getting signaled
	 * for completion.
	 */
	if (echo_total != 0) {
		pwp->io_intr_coal.intr_latency =
		    (echo_total / iterations) / 2;
		pwp->io_intr_coal.intr_threshold =
		    PMCS_INTR_THRESHOLD(PMCS_QUANTUM_TIME_USECS * 1000 /
		    pwp->io_intr_coal.intr_latency);
	}

	return (rval);
}

/*
 * Start the (real) phys
 */
int
pmcs_start_phy(pmcs_hw_t *pwp, int phynum, int linkmode, int speed)
{
	int result;
	uint32_t *msg;
	struct pmcwork *pwrk;
	pmcs_phy_t *pptr;
	sas_identify_af_t sap;

	mutex_enter(&pwp->lock);
	pptr = pwp->root_phys + phynum;
	if (pptr == NULL) {
		mutex_exit(&pwp->lock);
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: cannot find port %d", __func__, phynum);
		return (0);
	}

	pmcs_lock_phy(pptr);
	mutex_exit(&pwp->lock);

	pwrk = pmcs_gwork(pwp, PMCS_TAG_TYPE_WAIT, pptr);
	if (pwrk == NULL) {
		pmcs_unlock_phy(pptr);
		pmcs_prt(pwp, PMCS_PRT_ERR, pptr, NULL, pmcs_nowrk, __func__);
		return (-1);
	}

	mutex_enter(&pwp->iqp_lock[PMCS_IQ_OTHER]);
	msg = GET_IQ_ENTRY(pwp, PMCS_IQ_OTHER);

	if (msg == NULL) {
		mutex_exit(&pwp->iqp_lock[PMCS_IQ_OTHER]);
		pmcs_unlock_phy(pptr);
		pmcs_pwork(pwp, pwrk);
		pmcs_prt(pwp, PMCS_PRT_ERR, pptr, NULL, pmcs_nomsg, __func__);
		return (-1);
	}
	msg[0] = LE_32(PMCS_HIPRI(pwp, PMCS_OQ_EVENTS, PMCIN_PHY_START));
	msg[1] = LE_32(pwrk->htag);
	msg[2] = LE_32(linkmode | speed | phynum);
	bzero(&sap, sizeof (sap));
	sap.device_type = SAS_IF_DTYPE_ENDPOINT;
	sap.ssp_ini_port = 1;

	if (pwp->separate_ports) {
		pmcs_wwn2barray(pwp->sas_wwns[phynum], sap.sas_address);
	} else {
		pmcs_wwn2barray(pwp->sas_wwns[0], sap.sas_address);
	}

	ASSERT(phynum < SAS2_PHYNUM_MAX);
	sap.phy_identifier = phynum & SAS2_PHYNUM_MASK;
	(void) memcpy(&msg[3], &sap, sizeof (sas_identify_af_t));
	pwrk->state = PMCS_WORK_STATE_ONCHIP;
	INC_IQ_ENTRY(pwp, PMCS_IQ_OTHER);

	pptr->state.prog_min_rate = (lowbit((ulong_t)speed) - 1);
	pptr->state.prog_max_rate = (highbit((ulong_t)speed) - 1);
	pptr->state.hw_min_rate = PMCS_HW_MIN_LINK_RATE;
	pptr->state.hw_max_rate = PMCS_HW_MAX_LINK_RATE;

	pmcs_unlock_phy(pptr);
	WAIT_FOR(pwrk, 1000, result);
	pmcs_pwork(pwp, pwrk);

	if (result) {
		pmcs_prt(pwp, PMCS_PRT_ERR, pptr, NULL, pmcs_timeo, __func__);
	} else {
		mutex_enter(&pwp->lock);
		pwp->phys_started |= (1 << phynum);
		mutex_exit(&pwp->lock);
	}

	return (0);
}

int
pmcs_start_phys(pmcs_hw_t *pwp)
{
	int i;

	for (i = 0; i < pwp->nphy; i++) {
		if ((pwp->phyid_block_mask & (1 << i)) == 0) {
			if (pmcs_start_phy(pwp, i,
			    (pwp->phymode << PHY_MODE_SHIFT),
			    pwp->physpeed << PHY_LINK_SHIFT)) {
				return (-1);
			}
			if (pmcs_clear_diag_counters(pwp, i)) {
				pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
				    "%s: failed to reset counters on PHY (%d)",
				    __func__, i);
			}
		}
	}
	return (0);
}

/*
 * Called with PHY locked
 */
int
pmcs_reset_phy(pmcs_hw_t *pwp, pmcs_phy_t *pptr, uint8_t type)
{
	uint32_t *msg;
	uint32_t iomb[(PMCS_QENTRY_SIZE << 1) >> 2];
	const char *mbar;
	uint32_t amt;
	uint32_t pdevid;
	uint32_t stsoff;
	uint32_t status;
	int result, level, phynum;
	struct pmcwork *pwrk;
	uint32_t htag;

	ASSERT(mutex_owned(&pptr->phy_lock));

	bzero(iomb, PMCS_QENTRY_SIZE);
	phynum = pptr->phynum;
	level = pptr->level;
	if (level > 0) {
		pdevid = pptr->parent->device_id;
	}

	pwrk = pmcs_gwork(pwp, PMCS_TAG_TYPE_WAIT, pptr);

	if (pwrk == NULL) {
		pmcs_prt(pwp, PMCS_PRT_ERR, pptr, NULL, pmcs_nowrk, __func__);
		return (ENOMEM);
	}

	pwrk->arg = iomb;

	/*
	 * If level > 0, we need to issue an SMP_REQUEST with a PHY_CONTROL
	 * function to do either a link reset or hard reset.  If level == 0,
	 * then we do a LOCAL_PHY_CONTROL IOMB to do link/hard reset to the
	 * root (local) PHY
	 */
	if (level) {
		stsoff = 2;
		iomb[0] = LE_32(PMCS_HIPRI(pwp, PMCS_OQ_GENERAL,
		    PMCIN_SMP_REQUEST));
		iomb[1] = LE_32(pwrk->htag);
		iomb[2] = LE_32(pdevid);
		iomb[3] = LE_32(40 << SMP_REQUEST_LENGTH_SHIFT);
		/*
		 * Send SMP PHY CONTROL/HARD or LINK RESET
		 */
		iomb[4] = BE_32(0x40910000);
		iomb[5] = 0;

		if (type == PMCS_PHYOP_HARD_RESET) {
			mbar = "SMP PHY CONTROL/HARD RESET";
			iomb[6] = BE_32((phynum << 24) |
			    (PMCS_PHYOP_HARD_RESET << 16));
		} else {
			mbar = "SMP PHY CONTROL/LINK RESET";
			iomb[6] = BE_32((phynum << 24) |
			    (PMCS_PHYOP_LINK_RESET << 16));
		}
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, NULL,
		    "%s: sending %s to %s for phy 0x%x",
		    __func__, mbar, pptr->parent->path, pptr->phynum);
		amt = 7;
	} else {
		/*
		 * Unlike most other Outbound messages, status for
		 * a local phy operation is in DWORD 3.
		 */
		stsoff = 3;
		iomb[0] = LE_32(PMCS_HIPRI(pwp, PMCS_OQ_GENERAL,
		    PMCIN_LOCAL_PHY_CONTROL));
		iomb[1] = LE_32(pwrk->htag);
		if (type == PMCS_PHYOP_LINK_RESET) {
			mbar = "LOCAL PHY LINK RESET";
			iomb[2] = LE_32((PMCS_PHYOP_LINK_RESET << 8) | phynum);
		} else {
			mbar = "LOCAL PHY HARD RESET";
			iomb[2] = LE_32((PMCS_PHYOP_HARD_RESET << 8) | phynum);
		}
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, NULL,
		    "%s: sending %s to %s", __func__, mbar, pptr->path);
		amt = 3;
	}

	mutex_enter(&pwp->iqp_lock[PMCS_IQ_OTHER]);
	msg = GET_IQ_ENTRY(pwp, PMCS_IQ_OTHER);
	if (msg == NULL) {
		mutex_exit(&pwp->iqp_lock[PMCS_IQ_OTHER]);
		pmcs_pwork(pwp, pwrk);
		pmcs_prt(pwp, PMCS_PRT_ERR, pptr, NULL, pmcs_nomsg, __func__);
		return (ENOMEM);
	}
	COPY_MESSAGE(msg, iomb, amt);
	htag = pwrk->htag;
	pwrk->state = PMCS_WORK_STATE_ONCHIP;
	INC_IQ_ENTRY(pwp, PMCS_IQ_OTHER);

	pmcs_unlock_phy(pptr);
	WAIT_FOR(pwrk, 1000, result);
	pmcs_pwork(pwp, pwrk);
	pmcs_lock_phy(pptr);

	if (result) {
		pmcs_prt(pwp, PMCS_PRT_ERR, pptr, NULL, pmcs_timeo, __func__);

		if (pmcs_abort(pwp, pptr, htag, 0, 0)) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, pptr, NULL,
			    "%s: Unable to issue SMP abort for htag 0x%08x",
			    __func__, htag);
		} else {
			pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, pptr, NULL,
			    "%s: Issuing SMP ABORT for htag 0x%08x",
			    __func__, htag);
		}
		return (EIO);
	}
	status = LE_32(iomb[stsoff]);

	if (status != PMCOUT_STATUS_OK) {
		char buf[32];
		const char *es =  pmcs_status_str(status);
		if (es == NULL) {
			(void) snprintf(buf, sizeof (buf), "Status 0x%x",
			    status);
			es = buf;
		}
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, NULL,
		    "%s: %s action returned %s for %s", __func__, mbar, es,
		    pptr->path);
		return (EIO);
	}

	return (0);
}

/*
 * Stop the (real) phys.  No PHY or softstate locks are required as this only
 * happens during detach.
 */
void
pmcs_stop_phy(pmcs_hw_t *pwp, int phynum)
{
	int result;
	pmcs_phy_t *pptr;
	uint32_t *msg;
	struct pmcwork *pwrk;

	pptr =  pwp->root_phys + phynum;
	if (pptr == NULL) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: unable to find port %d", __func__, phynum);
		return;
	}

	if (pwp->phys_started & (1 << phynum)) {
		pwrk = pmcs_gwork(pwp, PMCS_TAG_TYPE_WAIT, pptr);

		if (pwrk == NULL) {
			pmcs_prt(pwp, PMCS_PRT_ERR, pptr, NULL,
			    pmcs_nowrk, __func__);
			return;
		}

		mutex_enter(&pwp->iqp_lock[PMCS_IQ_OTHER]);
		msg = GET_IQ_ENTRY(pwp, PMCS_IQ_OTHER);

		if (msg == NULL) {
			mutex_exit(&pwp->iqp_lock[PMCS_IQ_OTHER]);
			pmcs_pwork(pwp, pwrk);
			pmcs_prt(pwp, PMCS_PRT_ERR, pptr, NULL,
			    pmcs_nomsg, __func__);
			return;
		}

		msg[0] = LE_32(PMCS_HIPRI(pwp, PMCS_OQ_EVENTS, PMCIN_PHY_STOP));
		msg[1] = LE_32(pwrk->htag);
		msg[2] = LE_32(phynum);
		pwrk->state = PMCS_WORK_STATE_ONCHIP;
		/*
		 * Make this unconfigured now.
		 */
		INC_IQ_ENTRY(pwp, PMCS_IQ_OTHER);
		WAIT_FOR(pwrk, 1000, result);

		pmcs_pwork(pwp, pwrk);
		if (result) {
			pmcs_prt(pwp, PMCS_PRT_ERR,
			    pptr, NULL, pmcs_timeo, __func__);
		}

		pwp->phys_started &= ~(1 << phynum);
	}

	pptr->configured = 0;
}

/*
 * No locks should be required as this is only called during detach
 */
void
pmcs_stop_phys(pmcs_hw_t *pwp)
{
	int i;
	for (i = 0; i < pwp->nphy; i++) {
		if ((pwp->phyid_block_mask & (1 << i)) == 0) {
			pmcs_stop_phy(pwp, i);
		}
	}
}

/*
 * Run SAS_DIAG_EXECUTE with cmd and cmd_desc passed.
 * 	ERR_CNT_RESET: return status of cmd
 *	DIAG_REPORT_GET: return value of the counter
 */
int
pmcs_sas_diag_execute(pmcs_hw_t *pwp, uint32_t cmd, uint32_t cmd_desc,
    uint8_t phynum)
{
	uint32_t htag, *ptr, status, msg[PMCS_MSG_SIZE << 1];
	int result;
	struct pmcwork *pwrk;

	pwrk = pmcs_gwork(pwp, PMCS_TAG_TYPE_WAIT, NULL);
	if (pwrk == NULL) {
		pmcs_prt(pwp, PMCS_PRT_ERR, NULL, NULL, pmcs_nowrk, __func__);
		return (DDI_FAILURE);
	}
	pwrk->arg = msg;
	htag = pwrk->htag;
	msg[0] = LE_32(PMCS_HIPRI(pwp, PMCS_OQ_EVENTS, PMCIN_SAS_DIAG_EXECUTE));
	msg[1] = LE_32(htag);
	msg[2] = LE_32((cmd << PMCS_DIAG_CMD_SHIFT) |
	    (cmd_desc << PMCS_DIAG_CMD_DESC_SHIFT) | phynum);

	mutex_enter(&pwp->iqp_lock[PMCS_IQ_OTHER]);
	ptr = GET_IQ_ENTRY(pwp, PMCS_IQ_OTHER);
	if (ptr == NULL) {
		mutex_exit(&pwp->iqp_lock[PMCS_IQ_OTHER]);
		pmcs_pwork(pwp, pwrk);
		pmcs_prt(pwp, PMCS_PRT_ERR, NULL, NULL, pmcs_nomsg, __func__);
		return (DDI_FAILURE);
	}
	COPY_MESSAGE(ptr, msg, 3);
	pwrk->state = PMCS_WORK_STATE_ONCHIP;
	INC_IQ_ENTRY(pwp, PMCS_IQ_OTHER);

	WAIT_FOR(pwrk, 1000, result);

	pmcs_pwork(pwp, pwrk);

	if (result) {
		pmcs_timed_out(pwp, htag, __func__);
		return (DDI_FAILURE);
	}

	status = LE_32(msg[3]);

	/* Return for counter reset */
	if (cmd == PMCS_ERR_CNT_RESET)
		return (status);

	/* Return for counter value */
	if (status) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: failed, status (0x%x)", __func__, status);
		return (DDI_FAILURE);
	}
	return (LE_32(msg[4]));
}

/* Get the current value of the counter for desc on phynum and return it. */
int
pmcs_get_diag_report(pmcs_hw_t *pwp, uint32_t desc, uint8_t phynum)
{
	return (pmcs_sas_diag_execute(pwp, PMCS_DIAG_REPORT_GET, desc, phynum));
}

/* Clear all of the counters for phynum. Returns the status of the command. */
int
pmcs_clear_diag_counters(pmcs_hw_t *pwp, uint8_t phynum)
{
	uint32_t	cmd = PMCS_ERR_CNT_RESET;
	uint32_t	cmd_desc;

	cmd_desc = PMCS_INVALID_DWORD_CNT;
	if (pmcs_sas_diag_execute(pwp, cmd, cmd_desc, phynum))
		return (DDI_FAILURE);

	cmd_desc = PMCS_DISPARITY_ERR_CNT;
	if (pmcs_sas_diag_execute(pwp, cmd, cmd_desc, phynum))
		return (DDI_FAILURE);

	cmd_desc = PMCS_LOST_DWORD_SYNC_CNT;
	if (pmcs_sas_diag_execute(pwp, cmd, cmd_desc, phynum))
		return (DDI_FAILURE);

	cmd_desc = PMCS_RESET_FAILED_CNT;
	if (pmcs_sas_diag_execute(pwp, cmd, cmd_desc, phynum))
		return (DDI_FAILURE);

	return (DDI_SUCCESS);
}

/*
 * Get firmware timestamp
 */
int
pmcs_get_time_stamp(pmcs_hw_t *pwp, uint64_t *ts)
{
	uint32_t htag, *ptr, msg[PMCS_MSG_SIZE << 1];
	int result;
	struct pmcwork *pwrk;

	pwrk = pmcs_gwork(pwp, PMCS_TAG_TYPE_WAIT, NULL);
	if (pwrk == NULL) {
		pmcs_prt(pwp, PMCS_PRT_ERR, NULL, NULL, pmcs_nowrk, __func__);
		return (-1);
	}
	pwrk->arg = msg;
	htag = pwrk->htag;
	msg[0] = LE_32(PMCS_HIPRI(pwp, PMCS_OQ_EVENTS, PMCIN_GET_TIME_STAMP));
	msg[1] = LE_32(pwrk->htag);

	mutex_enter(&pwp->iqp_lock[PMCS_IQ_OTHER]);
	ptr = GET_IQ_ENTRY(pwp, PMCS_IQ_OTHER);
	if (ptr == NULL) {
		mutex_exit(&pwp->iqp_lock[PMCS_IQ_OTHER]);
		pmcs_pwork(pwp, pwrk);
		pmcs_prt(pwp, PMCS_PRT_ERR, NULL, NULL, pmcs_nomsg, __func__);
		return (-1);
	}
	COPY_MESSAGE(ptr, msg, 2);
	pwrk->state = PMCS_WORK_STATE_ONCHIP;
	INC_IQ_ENTRY(pwp, PMCS_IQ_OTHER);

	WAIT_FOR(pwrk, 1000, result);

	pmcs_pwork(pwp, pwrk);

	if (result) {
		pmcs_timed_out(pwp, htag, __func__);
		return (-1);
	}
	*ts = LE_32(msg[2]) | (((uint64_t)LE_32(msg[3])) << 32);
	return (0);
}

/*
 * Dump all pertinent registers
 */

void
pmcs_register_dump(pmcs_hw_t *pwp)
{
	int i;
	uint32_t val;

	pmcs_prt(pwp, PMCS_PRT_INFO, NULL, NULL, "pmcs%d: Register dump start",
	    ddi_get_instance(pwp->dip));
	pmcs_prt(pwp, PMCS_PRT_INFO, NULL, NULL,
	    "OBDB (intr): 0x%08x (mask): 0x%08x (clear): 0x%08x",
	    pmcs_rd_msgunit(pwp, PMCS_MSGU_OBDB),
	    pmcs_rd_msgunit(pwp, PMCS_MSGU_OBDB_MASK),
	    pmcs_rd_msgunit(pwp, PMCS_MSGU_OBDB_CLEAR));
	pmcs_prt(pwp, PMCS_PRT_INFO, NULL, NULL, "SCRATCH0: 0x%08x",
	    pmcs_rd_msgunit(pwp, PMCS_MSGU_SCRATCH0));
	pmcs_prt(pwp, PMCS_PRT_INFO, NULL, NULL, "SCRATCH1: 0x%08x",
	    pmcs_rd_msgunit(pwp, PMCS_MSGU_SCRATCH1));
	pmcs_prt(pwp, PMCS_PRT_INFO, NULL, NULL, "SCRATCH2: 0x%08x",
	    pmcs_rd_msgunit(pwp, PMCS_MSGU_SCRATCH2));
	pmcs_prt(pwp, PMCS_PRT_INFO, NULL, NULL, "SCRATCH3: 0x%08x",
	    pmcs_rd_msgunit(pwp, PMCS_MSGU_SCRATCH3));
	for (i = 0; i < PMCS_NIQ; i++) {
		pmcs_prt(pwp, PMCS_PRT_INFO, NULL, NULL, "IQ %d: CI %u PI %u",
		    i, pmcs_rd_iqci(pwp, i), pmcs_rd_iqpi(pwp, i));
	}
	for (i = 0; i < PMCS_NOQ; i++) {
		pmcs_prt(pwp, PMCS_PRT_INFO, NULL, NULL, "OQ %d: CI %u PI %u",
		    i, pmcs_rd_oqci(pwp, i), pmcs_rd_oqpi(pwp, i));
	}
	val = pmcs_rd_gst_tbl(pwp, PMCS_GST_BASE);
	pmcs_prt(pwp, PMCS_PRT_INFO, NULL, NULL,
	    "GST TABLE BASE: 0x%08x (STATE=0x%x QF=%d GSTLEN=%d HMI_ERR=0x%x)",
	    val, PMCS_MPI_S(val), PMCS_QF(val), PMCS_GSTLEN(val) * 4,
	    PMCS_HMI_ERR(val));
	pmcs_prt(pwp, PMCS_PRT_INFO, NULL, NULL, "GST TABLE IQFRZ0: 0x%08x",
	    pmcs_rd_gst_tbl(pwp, PMCS_GST_IQFRZ0));
	pmcs_prt(pwp, PMCS_PRT_INFO, NULL, NULL, "GST TABLE IQFRZ1: 0x%08x",
	    pmcs_rd_gst_tbl(pwp, PMCS_GST_IQFRZ1));
	pmcs_prt(pwp, PMCS_PRT_INFO, NULL, NULL, "GST TABLE MSGU TICK: 0x%08x",
	    pmcs_rd_gst_tbl(pwp, PMCS_GST_MSGU_TICK));
	pmcs_prt(pwp, PMCS_PRT_INFO, NULL, NULL, "GST TABLE IOP TICK: 0x%08x",
	    pmcs_rd_gst_tbl(pwp, PMCS_GST_IOP_TICK));
	for (i = 0; i < pwp->nphy; i++) {
		uint32_t rerrf, pinfo, started = 0, link = 0;
		pinfo = pmcs_rd_gst_tbl(pwp, PMCS_GST_PHY_INFO(i));
		if (pinfo & 1) {
			started = 1;
			link = pinfo & 2;
		}
		rerrf = pmcs_rd_gst_tbl(pwp, PMCS_GST_RERR_INFO(i));
		pmcs_prt(pwp, PMCS_PRT_INFO, NULL, NULL,
		    "GST TABLE PHY%d STARTED=%d LINK=%d RERR=0x%08x",
		    i, started, link, rerrf);
	}
	pmcs_prt(pwp, PMCS_PRT_INFO, NULL, NULL, "pmcs%d: Register dump end",
	    ddi_get_instance(pwp->dip));
}

/*
 * Handle SATA Abort and other error processing
 */
int
pmcs_abort_handler(pmcs_hw_t *pwp)
{
	pmcs_phy_t *pptr, *pnext, *pnext_uplevel[PMCS_MAX_XPND];
	int r, level = 0;

	pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL, "%s", __func__);

	mutex_enter(&pwp->lock);
	pptr = pwp->root_phys;
	mutex_exit(&pwp->lock);

	while (pptr) {
		/*
		 * XXX: Need to make sure this doesn't happen
		 * XXX: when non-NCQ commands are running.
		 */
		pmcs_lock_phy(pptr);
		if (pptr->need_rl_ext) {
			ASSERT(pptr->dtype == SATA);
			if (pmcs_acquire_scratch(pwp, B_FALSE)) {
				goto next_phy;
			}
			r = pmcs_sata_abort_ncq(pwp, pptr);
			pmcs_release_scratch(pwp);
			if (r == ENOMEM) {
				goto next_phy;
			}
			if (r) {
				r = pmcs_reset_phy(pwp, pptr,
				    PMCS_PHYOP_LINK_RESET);
				if (r == ENOMEM) {
					goto next_phy;
				}
				/* what if other failures happened? */
				pptr->abort_pending = 1;
				pptr->abort_sent = 0;
			}
		}
		if (pptr->abort_pending == 0 || pptr->abort_sent) {
			goto next_phy;
		}
		pptr->abort_pending = 0;
		if (pmcs_abort(pwp, pptr, pptr->device_id, 1, 1) == ENOMEM) {
			pptr->abort_pending = 1;
			goto next_phy;
		}
		pptr->abort_sent = 1;

next_phy:
		if (pptr->children) {
			pnext = pptr->children;
			pnext_uplevel[level++] = pptr->sibling;
		} else {
			pnext = pptr->sibling;
			while ((pnext == NULL) && (level > 0)) {
				pnext = pnext_uplevel[--level];
			}
		}

		pmcs_unlock_phy(pptr);
		pptr = pnext;
	}

	return (0);
}

/*
 * Register a device (get a device handle for it).
 * Called with PHY lock held.
 */
int
pmcs_register_device(pmcs_hw_t *pwp, pmcs_phy_t *pptr)
{
	struct pmcwork *pwrk;
	int result = 0;
	uint32_t *msg;
	uint32_t tmp, status;
	uint32_t iomb[(PMCS_QENTRY_SIZE << 1) >> 2];

	mutex_enter(&pwp->iqp_lock[PMCS_IQ_OTHER]);
	msg = GET_IQ_ENTRY(pwp, PMCS_IQ_OTHER);

	if (msg == NULL ||
	    (pwrk = pmcs_gwork(pwp, PMCS_TAG_TYPE_WAIT, pptr)) == NULL) {
		mutex_exit(&pwp->iqp_lock[PMCS_IQ_OTHER]);
		result = ENOMEM;
		goto out;
	}

	pwrk->arg = iomb;
	pwrk->dtype = pptr->dtype;

	msg[1] = LE_32(pwrk->htag);
	msg[0] = LE_32(PMCS_HIPRI(pwp, PMCS_OQ_GENERAL, PMCIN_REGISTER_DEVICE));
	tmp = PMCS_DEVREG_TLR |
	    (pptr->link_rate << PMCS_DEVREG_LINK_RATE_SHIFT);
	if (IS_ROOT_PHY(pptr)) {
		msg[2] = LE_32(pptr->portid |
		    (pptr->phynum << PMCS_PHYID_SHIFT));
	} else {
		msg[2] = LE_32(pptr->portid);
	}
	if (pptr->dtype == SATA) {
		if (IS_ROOT_PHY(pptr)) {
			tmp |= PMCS_DEVREG_TYPE_SATA_DIRECT;
		} else {
			tmp |= PMCS_DEVREG_TYPE_SATA;
		}
	} else {
		tmp |= PMCS_DEVREG_TYPE_SAS;
	}
	msg[3] = LE_32(tmp);
	msg[4] = LE_32(PMCS_DEVREG_IT_NEXUS_TIMEOUT);
	(void) memcpy(&msg[5], pptr->sas_address, 8);

	CLEAN_MESSAGE(msg, 7);
	pwrk->state = PMCS_WORK_STATE_ONCHIP;
	INC_IQ_ENTRY(pwp, PMCS_IQ_OTHER);

	pmcs_unlock_phy(pptr);
	WAIT_FOR(pwrk, 250, result);
	pmcs_lock_phy(pptr);
	pmcs_pwork(pwp, pwrk);

	if (result) {
		pmcs_prt(pwp, PMCS_PRT_ERR, pptr, NULL, pmcs_timeo, __func__);
		result = ETIMEDOUT;
		goto out;
	}
	status = LE_32(iomb[2]);
	tmp = LE_32(iomb[3]);
	switch (status) {
	case PMCS_DEVREG_OK:
	case PMCS_DEVREG_DEVICE_ALREADY_REGISTERED:
	case PMCS_DEVREG_PHY_ALREADY_REGISTERED:
		if (pmcs_validate_devid(pwp->root_phys, pptr, tmp) == B_FALSE) {
			result = EEXIST;
			goto out;
		} else if (status != PMCS_DEVREG_OK) {
			if (tmp == 0xffffffff) {	/* F/W bug */
				pmcs_prt(pwp, PMCS_PRT_INFO, pptr, NULL,
				    "%s: phy %s already has bogus devid 0x%x",
				    __func__, pptr->path, tmp);
				result = EIO;
				goto out;
			} else {
				pmcs_prt(pwp, PMCS_PRT_INFO, pptr, NULL,
				    "%s: phy %s already has a device id 0x%x",
				    __func__, pptr->path, tmp);
			}
		}
		break;
	default:
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, NULL,
		    "%s: status 0x%x when trying to register device %s",
		    __func__, status, pptr->path);
		result = EIO;
		goto out;
	}
	pptr->device_id = tmp;
	pptr->valid_device_id = 1;
	pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, pptr, NULL, "Phy %s/" SAS_ADDR_FMT
	    " registered with device_id 0x%x (portid %d)", pptr->path,
	    SAS_ADDR_PRT(pptr->sas_address), tmp, pptr->portid);
out:
	return (result);
}

/*
 * Deregister a device (remove a device handle).
 * Called with PHY locked.
 */
void
pmcs_deregister_device(pmcs_hw_t *pwp, pmcs_phy_t *pptr)
{
	struct pmcwork *pwrk;
	uint32_t msg[PMCS_MSG_SIZE], *ptr, status;
	uint32_t iomb[(PMCS_QENTRY_SIZE << 1) >> 2];
	int result;

	pwrk = pmcs_gwork(pwp, PMCS_TAG_TYPE_WAIT, pptr);
	if (pwrk == NULL) {
		return;
	}

	pwrk->arg = iomb;
	pwrk->dtype = pptr->dtype;
	mutex_enter(&pwp->iqp_lock[PMCS_IQ_OTHER]);
	ptr = GET_IQ_ENTRY(pwp, PMCS_IQ_OTHER);
	if (ptr == NULL) {
		mutex_exit(&pwp->iqp_lock[PMCS_IQ_OTHER]);
		pmcs_pwork(pwp, pwrk);
		return;
	}
	msg[0] = LE_32(PMCS_HIPRI(pwp, PMCS_OQ_GENERAL,
	    PMCIN_DEREGISTER_DEVICE_HANDLE));
	msg[1] = LE_32(pwrk->htag);
	msg[2] = LE_32(pptr->device_id);
	pwrk->state = PMCS_WORK_STATE_ONCHIP;
	COPY_MESSAGE(ptr, msg, 3);
	INC_IQ_ENTRY(pwp, PMCS_IQ_OTHER);

	pmcs_unlock_phy(pptr);
	WAIT_FOR(pwrk, 250, result);
	pmcs_pwork(pwp, pwrk);
	pmcs_lock_phy(pptr);

	if (result) {
		pmcs_prt(pwp, PMCS_PRT_ERR, pptr, NULL, pmcs_timeo, __func__);
		return;
	}
	status = LE_32(iomb[2]);
	if (status != PMCOUT_STATUS_OK) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, NULL,
		    "%s: status 0x%x when trying to deregister device %s",
		    __func__, status, pptr->path);
	} else {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, NULL,
		    "%s: device %s deregistered", __func__, pptr->path);
		pptr->valid_device_id = 0;
		pptr->device_id = PMCS_INVALID_DEVICE_ID;
	}
}

/*
 * Deregister all registered devices.
 */
void
pmcs_deregister_devices(pmcs_hw_t *pwp, pmcs_phy_t *phyp)
{
	/*
	 * Start at the maximum level and walk back to level 0.  This only
	 * gets done during detach after all threads and timers have been
	 * destroyed, so there's no need to hold the softstate or PHY lock.
	 */
	while (phyp) {
		if (phyp->children) {
			pmcs_deregister_devices(pwp, phyp->children);
		}
		if (phyp->valid_device_id) {
			pmcs_deregister_device(pwp, phyp);
		}
		phyp = phyp->sibling;
	}
}

/*
 * Perform a 'soft' reset on the PMC chip
 */
int
pmcs_soft_reset(pmcs_hw_t *pwp, boolean_t no_restart)
{
	uint32_t s2, sfrbits, gsm, rapchk, wapchk, wdpchk, spc, tsmode;
	pmcs_phy_t *pptr;
	char *msg = NULL;
	int i;

	/*
	 * Disable interrupts
	 */
	pmcs_wr_msgunit(pwp, PMCS_MSGU_OBDB_MASK, 0xffffffff);
	pmcs_wr_msgunit(pwp, PMCS_MSGU_OBDB_CLEAR, 0xffffffff);

	pmcs_prt(pwp, PMCS_PRT_INFO, NULL, NULL, "%s", __func__);

	if (pwp->locks_initted) {
		mutex_enter(&pwp->lock);
	}
	pwp->blocked = 1;

	/*
	 * Step 1
	 */
	s2 = pmcs_rd_msgunit(pwp, PMCS_MSGU_SCRATCH2);
	if ((s2 & PMCS_MSGU_HOST_SOFT_RESET_READY) == 0) {
		pmcs_wr_gsm_reg(pwp, RB6_ACCESS, RB6_NMI_SIGNATURE);
		pmcs_wr_gsm_reg(pwp, RB6_ACCESS, RB6_NMI_SIGNATURE);
		for (i = 0; i < 100; i++) {
			s2 = pmcs_rd_msgunit(pwp, PMCS_MSGU_SCRATCH2) &
			    PMCS_MSGU_HOST_SOFT_RESET_READY;
			if (s2) {
				break;
			}
			drv_usecwait(10000);
		}
		s2 = pmcs_rd_msgunit(pwp, PMCS_MSGU_SCRATCH2) &
		    PMCS_MSGU_HOST_SOFT_RESET_READY;
		if (s2 == 0) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
			    "%s: PMCS_MSGU_HOST_SOFT_RESET_READY never came "
			    "ready", __func__);
			pmcs_register_dump(pwp);
			if ((pmcs_rd_msgunit(pwp, PMCS_MSGU_SCRATCH1) &
			    PMCS_MSGU_CPU_SOFT_RESET_READY) == 0 ||
			    (pmcs_rd_msgunit(pwp, PMCS_MSGU_SCRATCH2) &
			    PMCS_MSGU_CPU_SOFT_RESET_READY) == 0) {
				pwp->state = STATE_DEAD;
				pwp->blocked = 0;
				if (pwp->locks_initted) {
					mutex_exit(&pwp->lock);
				}
				return (-1);
			}
		}
	}

	/*
	 * Step 2
	 */
	pmcs_wr_gsm_reg(pwp, NMI_EN_VPE0_IOP, 0);
	drv_usecwait(10);
	pmcs_wr_gsm_reg(pwp, NMI_EN_VPE0_AAP1, 0);
	drv_usecwait(10);
	pmcs_wr_topunit(pwp, PMCS_EVENT_INT_ENABLE, 0);
	drv_usecwait(10);
	pmcs_wr_topunit(pwp, PMCS_EVENT_INT_STAT,
	    pmcs_rd_topunit(pwp, PMCS_EVENT_INT_STAT));
	drv_usecwait(10);
	pmcs_wr_topunit(pwp, PMCS_ERROR_INT_ENABLE, 0);
	drv_usecwait(10);
	pmcs_wr_topunit(pwp, PMCS_ERROR_INT_STAT,
	    pmcs_rd_topunit(pwp, PMCS_ERROR_INT_STAT));
	drv_usecwait(10);

	sfrbits = pmcs_rd_msgunit(pwp, PMCS_MSGU_SCRATCH1) &
	    PMCS_MSGU_AAP_SFR_PROGRESS;
	sfrbits ^= PMCS_MSGU_AAP_SFR_PROGRESS;
	pmcs_prt(pwp, PMCS_PRT_DEBUG2, NULL, NULL, "PMCS_MSGU_HOST_SCRATCH0 "
	    "%08x -> %08x", pmcs_rd_msgunit(pwp, PMCS_MSGU_HOST_SCRATCH0),
	    HST_SFT_RESET_SIG);
	pmcs_wr_msgunit(pwp, PMCS_MSGU_HOST_SCRATCH0, HST_SFT_RESET_SIG);

	/*
	 * Step 3
	 */
	gsm = pmcs_rd_gsm_reg(pwp, GSM_CFG_AND_RESET);
	pmcs_prt(pwp, PMCS_PRT_DEBUG2, NULL, NULL, "GSM %08x -> %08x", gsm,
	    gsm & ~PMCS_SOFT_RESET_BITS);
	pmcs_wr_gsm_reg(pwp, GSM_CFG_AND_RESET, gsm & ~PMCS_SOFT_RESET_BITS);

	/*
	 * Step 4
	 */
	rapchk = pmcs_rd_gsm_reg(pwp, READ_ADR_PARITY_CHK_EN);
	pmcs_prt(pwp, PMCS_PRT_DEBUG2, NULL, NULL, "READ_ADR_PARITY_CHK_EN "
	    "%08x -> %08x", rapchk, 0);
	pmcs_wr_gsm_reg(pwp, READ_ADR_PARITY_CHK_EN, 0);
	wapchk = pmcs_rd_gsm_reg(pwp, WRITE_ADR_PARITY_CHK_EN);
	pmcs_prt(pwp, PMCS_PRT_DEBUG2, NULL, NULL, "WRITE_ADR_PARITY_CHK_EN "
	    "%08x -> %08x", wapchk, 0);
	pmcs_wr_gsm_reg(pwp, WRITE_ADR_PARITY_CHK_EN, 0);
	wdpchk = pmcs_rd_gsm_reg(pwp, WRITE_DATA_PARITY_CHK_EN);
	pmcs_prt(pwp, PMCS_PRT_DEBUG2, NULL, NULL, "WRITE_DATA_PARITY_CHK_EN "
	    "%08x -> %08x", wdpchk, 0);
	pmcs_wr_gsm_reg(pwp, WRITE_DATA_PARITY_CHK_EN, 0);

	/*
	 * Step 5
	 */
	drv_usecwait(100);

	/*
	 * Step 5.5 (Temporary workaround for 1.07.xx Beta)
	 */
	tsmode = pmcs_rd_gsm_reg(pwp, PMCS_GPIO_TRISTATE_MODE_ADDR);
	pmcs_prt(pwp, PMCS_PRT_DEBUG2, NULL, NULL, "GPIO TSMODE %08x -> %08x",
	    tsmode, tsmode & ~(PMCS_GPIO_TSMODE_BIT0|PMCS_GPIO_TSMODE_BIT1));
	pmcs_wr_gsm_reg(pwp, PMCS_GPIO_TRISTATE_MODE_ADDR,
	    tsmode & ~(PMCS_GPIO_TSMODE_BIT0|PMCS_GPIO_TSMODE_BIT1));
	drv_usecwait(10);

	/*
	 * Step 6
	 */
	spc = pmcs_rd_topunit(pwp, PMCS_SPC_RESET);
	pmcs_prt(pwp, PMCS_PRT_DEBUG2, NULL, NULL, "SPC_RESET %08x -> %08x",
	    spc, spc & ~(PCS_IOP_SS_RSTB|PCS_AAP1_SS_RSTB));
	pmcs_wr_topunit(pwp, PMCS_SPC_RESET,
	    spc & ~(PCS_IOP_SS_RSTB|PCS_AAP1_SS_RSTB));
	drv_usecwait(10);

	/*
	 * Step 7
	 */
	spc = pmcs_rd_topunit(pwp, PMCS_SPC_RESET);
	pmcs_prt(pwp, PMCS_PRT_DEBUG2, NULL, NULL, "SPC_RESET %08x -> %08x",
	    spc, spc & ~(BDMA_CORE_RSTB|OSSP_RSTB));
	pmcs_wr_topunit(pwp, PMCS_SPC_RESET, spc & ~(BDMA_CORE_RSTB|OSSP_RSTB));

	/*
	 * Step 8
	 */
	drv_usecwait(100);

	/*
	 * Step 9
	 */
	spc = pmcs_rd_topunit(pwp, PMCS_SPC_RESET);
	pmcs_prt(pwp, PMCS_PRT_DEBUG2, NULL, NULL, "SPC_RESET %08x -> %08x",
	    spc, spc | (BDMA_CORE_RSTB|OSSP_RSTB));
	pmcs_wr_topunit(pwp, PMCS_SPC_RESET, spc | (BDMA_CORE_RSTB|OSSP_RSTB));

	/*
	 * Step 10
	 */
	drv_usecwait(100);

	/*
	 * Step 11
	 */
	gsm = pmcs_rd_gsm_reg(pwp, GSM_CFG_AND_RESET);
	pmcs_prt(pwp, PMCS_PRT_DEBUG2, NULL, NULL, "GSM %08x -> %08x", gsm,
	    gsm | PMCS_SOFT_RESET_BITS);
	pmcs_wr_gsm_reg(pwp, GSM_CFG_AND_RESET, gsm | PMCS_SOFT_RESET_BITS);
	drv_usecwait(10);

	/*
	 * Step 12
	 */
	pmcs_prt(pwp, PMCS_PRT_DEBUG2, NULL, NULL, "READ_ADR_PARITY_CHK_EN "
	    "%08x -> %08x", pmcs_rd_gsm_reg(pwp, READ_ADR_PARITY_CHK_EN),
	    rapchk);
	pmcs_wr_gsm_reg(pwp, READ_ADR_PARITY_CHK_EN, rapchk);
	drv_usecwait(10);
	pmcs_prt(pwp, PMCS_PRT_DEBUG2, NULL, NULL, "WRITE_ADR_PARITY_CHK_EN "
	    "%08x -> %08x", pmcs_rd_gsm_reg(pwp, WRITE_ADR_PARITY_CHK_EN),
	    wapchk);
	pmcs_wr_gsm_reg(pwp, WRITE_ADR_PARITY_CHK_EN, wapchk);
	drv_usecwait(10);
	pmcs_prt(pwp, PMCS_PRT_DEBUG2, NULL, NULL, "WRITE_DATA_PARITY_CHK_EN "
	    "%08x -> %08x", pmcs_rd_gsm_reg(pwp, WRITE_DATA_PARITY_CHK_EN),
	    wapchk);
	pmcs_wr_gsm_reg(pwp, WRITE_DATA_PARITY_CHK_EN, wdpchk);
	drv_usecwait(10);

	/*
	 * Step 13
	 */
	spc = pmcs_rd_topunit(pwp, PMCS_SPC_RESET);
	pmcs_prt(pwp, PMCS_PRT_DEBUG2, NULL, NULL, "SPC_RESET %08x -> %08x",
	    spc, spc | (PCS_IOP_SS_RSTB|PCS_AAP1_SS_RSTB));
	pmcs_wr_topunit(pwp, PMCS_SPC_RESET,
	    spc | (PCS_IOP_SS_RSTB|PCS_AAP1_SS_RSTB));

	/*
	 * Step 14
	 */
	drv_usecwait(100);

	/*
	 * Step 15
	 */
	for (spc = 0, i = 0; i < 1000; i++) {
		drv_usecwait(1000);
		spc = pmcs_rd_msgunit(pwp, PMCS_MSGU_SCRATCH1);
		if ((spc & PMCS_MSGU_AAP_SFR_PROGRESS) == sfrbits) {
			break;
		}
	}

	if ((spc & PMCS_MSGU_AAP_SFR_PROGRESS) != sfrbits) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "SFR didn't toggle (sfr 0x%x)", spc);
		pwp->state = STATE_DEAD;
		pwp->blocked = 0;
		if (pwp->locks_initted) {
			mutex_exit(&pwp->lock);
		}
		return (-1);
	}

	/*
	 * Step 16
	 */
	pmcs_wr_msgunit(pwp, PMCS_MSGU_OBDB_MASK, 0xffffffff);
	pmcs_wr_msgunit(pwp, PMCS_MSGU_OBDB_CLEAR, 0xffffffff);

	/*
	 * Wait for up to 5 seconds for AAP state to come either ready or error.
	 */
	for (i = 0; i < 50; i++) {
		spc = pmcs_rd_msgunit(pwp, PMCS_MSGU_SCRATCH1) &
		    PMCS_MSGU_AAP_STATE_MASK;
		if (spc == PMCS_MSGU_AAP_STATE_ERROR ||
		    spc == PMCS_MSGU_AAP_STATE_READY) {
			break;
		}
		drv_usecwait(100000);
	}
	spc = pmcs_rd_msgunit(pwp, PMCS_MSGU_SCRATCH1);
	if ((spc & PMCS_MSGU_AAP_STATE_MASK) != PMCS_MSGU_AAP_STATE_READY) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "soft reset failed (state 0x%x)", spc);
		pwp->state = STATE_DEAD;
		pwp->blocked = 0;
		if (pwp->locks_initted) {
			mutex_exit(&pwp->lock);
		}
		return (-1);
	}


	if (pwp->state == STATE_DEAD || pwp->state == STATE_UNPROBING ||
	    pwp->state == STATE_PROBING || pwp->locks_initted == 0) {
		pwp->blocked = 0;
		if (pwp->locks_initted) {
			mutex_exit(&pwp->lock);
		}
		return (0);
	}

	/*
	 * Return at this point if we dont need to startup.
	 */
	if (no_restart) {
		return (0);
	}

	ASSERT(pwp->locks_initted != 0);

	/*
	 * Clean up various soft state.
	 */
	bzero(pwp->ports, sizeof (pwp->ports));

	pmcs_free_all_phys(pwp, pwp->root_phys);

	for (pptr = pwp->root_phys; pptr; pptr = pptr->sibling) {
		pmcs_lock_phy(pptr);
		pmcs_clear_phy(pwp, pptr);
		pmcs_unlock_phy(pptr);
	}

	if (pwp->targets) {
		for (i = 0; i < pwp->max_dev; i++) {
			pmcs_xscsi_t *xp = pwp->targets[i];

			if (xp == NULL) {
				continue;
			}
			mutex_enter(&xp->statlock);
			pmcs_clear_xp(pwp, xp);
			mutex_exit(&xp->statlock);
		}
	}

	bzero(pwp->shadow_iqpi, sizeof (pwp->shadow_iqpi));
	for (i = 0; i < PMCS_NIQ; i++) {
		if (pwp->iqp[i]) {
			bzero(pwp->iqp[i], PMCS_QENTRY_SIZE * pwp->ioq_depth);
			pmcs_wr_iqpi(pwp, i, 0);
			pmcs_wr_iqci(pwp, i, 0);
		}
	}
	for (i = 0; i < PMCS_NOQ; i++) {
		if (pwp->oqp[i]) {
			bzero(pwp->oqp[i], PMCS_QENTRY_SIZE * pwp->ioq_depth);
			pmcs_wr_oqpi(pwp, i, 0);
			pmcs_wr_oqci(pwp, i, 0);
		}

	}
	if (pwp->fwlogp) {
		bzero(pwp->fwlogp, PMCS_FWLOG_SIZE);
	}
	STAILQ_INIT(&pwp->wf);
	bzero(pwp->work, sizeof (pmcwork_t) * pwp->max_cmd);
	for (i = 0; i < pwp->max_cmd - 1; i++) {
		pmcwork_t *pwrk = &pwp->work[i];
		STAILQ_INSERT_TAIL(&pwp->wf, pwrk, next);
	}

	/*
	 * Clear out any leftover commands sitting in the work list
	 */
	for (i = 0; i < pwp->max_cmd; i++) {
		pmcwork_t *pwrk = &pwp->work[i];
		mutex_enter(&pwrk->lock);
		if (pwrk->state == PMCS_WORK_STATE_ONCHIP) {
			switch (PMCS_TAG_TYPE(pwrk->htag)) {
			case PMCS_TAG_TYPE_WAIT:
				mutex_exit(&pwrk->lock);
				break;
			case PMCS_TAG_TYPE_CBACK:
			case PMCS_TAG_TYPE_NONE:
				pmcs_pwork(pwp, pwrk);
				break;
			default:
				break;
			}
		} else if (pwrk->state == PMCS_WORK_STATE_IOCOMPQ) {
			pwrk->dead = 1;
			mutex_exit(&pwrk->lock);
		} else {
			/*
			 * The other states of NIL, READY and INTR
			 * should not be visible outside of a lock being held.
			 */
			pmcs_pwork(pwp, pwrk);
		}
	}

	/*
	 * Restore Interrupt Mask
	 */
	pmcs_wr_msgunit(pwp, PMCS_MSGU_OBDB_MASK, pwp->intr_mask);
	pmcs_wr_msgunit(pwp, PMCS_MSGU_OBDB_CLEAR, 0xffffffff);

	pwp->blocked = 0;
	pwp->mpi_table_setup = 0;
	mutex_exit(&pwp->lock);

	/*
	 * Set up MPI again.
	 */
	if (pmcs_setup(pwp)) {
		msg = "unable to setup MPI tables again";
		goto fail_restart;
	}
	pmcs_report_fwversion(pwp);

	/*
	 * Restart MPI
	 */
	if (pmcs_start_mpi(pwp)) {
		msg = "unable to restart MPI again";
		goto fail_restart;
	}

	mutex_enter(&pwp->lock);
	pwp->blocked = 0;
	SCHEDULE_WORK(pwp, PMCS_WORK_RUN_QUEUES);
	mutex_exit(&pwp->lock);

	/*
	 * Run any completions
	 */
	PMCS_CQ_RUN(pwp);

	/*
	 * Delay
	 */
	drv_usecwait(1000000);
	return (0);

fail_restart:
	mutex_enter(&pwp->lock);
	pwp->state = STATE_DEAD;
	mutex_exit(&pwp->lock);
	pmcs_prt(pwp, PMCS_PRT_ERR, NULL, NULL,
	    "%s: Failed: %s", __func__, msg);
	return (-1);
}

/*
 * Reset a device or a logical unit.
 */
int
pmcs_reset_dev(pmcs_hw_t *pwp, pmcs_phy_t *pptr, uint64_t lun)
{
	int rval = 0;

	if (pptr == NULL) {
		return (ENXIO);
	}

	pmcs_lock_phy(pptr);
	if (pptr->dtype == SAS) {
		/*
		 * Some devices do not support SAS_I_T_NEXUS_RESET as
		 * it is not a mandatory (in SAM4) task management
		 * function, while LOGIC_UNIT_RESET is mandatory.
		 *
		 * The problem here is that we need to iterate over
		 * all known LUNs to emulate the semantics of
		 * "RESET_TARGET".
		 *
		 * XXX: FIX ME
		 */
		if (lun == (uint64_t)-1) {
			lun = 0;
		}
		rval = pmcs_ssp_tmf(pwp, pptr, SAS_LOGICAL_UNIT_RESET, 0, lun,
		    NULL);
	} else if (pptr->dtype == SATA) {
		if (lun != 0ull) {
			pmcs_unlock_phy(pptr);
			return (EINVAL);
		}
		rval = pmcs_reset_phy(pwp, pptr, PMCS_PHYOP_LINK_RESET);
	} else {
		pmcs_unlock_phy(pptr);
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, NULL,
		    "%s: cannot reset a SMP device yet (%s)",
		    __func__, pptr->path);
		return (EINVAL);
	}

	/*
	 * Now harvest any commands killed by this action
	 * by issuing an ABORT for all commands on this device.
	 *
	 * We do this even if the the tmf or reset fails (in case there
	 * are any dead commands around to be harvested *anyway*).
	 * We don't have to await for the abort to complete.
	 */
	if (pmcs_abort(pwp, pptr, 0, 1, 0)) {
		pptr->abort_pending = 1;
		SCHEDULE_WORK(pwp, PMCS_WORK_ABORT_HANDLE);
	}

	pmcs_unlock_phy(pptr);
	return (rval);
}

/*
 * Called with PHY locked.
 */
static int
pmcs_get_device_handle(pmcs_hw_t *pwp, pmcs_phy_t *pptr)
{
	if (pptr->valid_device_id == 0) {
		int result = pmcs_register_device(pwp, pptr);

		/*
		 * If we changed while registering, punt
		 */
		if (pptr->changed) {
			RESTART_DISCOVERY(pwp);
			return (-1);
		}

		/*
		 * If we had a failure to register, check against errors.
		 * An ENOMEM error means we just retry (temp resource shortage).
		 */
		if (result == ENOMEM) {
			PHY_CHANGED(pwp, pptr);
			RESTART_DISCOVERY(pwp);
			return (-1);
		}

		/*
		 * An ETIMEDOUT error means we retry (if our counter isn't
		 * exhausted)
		 */
		if (result == ETIMEDOUT) {
			if (ddi_get_lbolt() < pptr->config_stop) {
				PHY_CHANGED(pwp, pptr);
				RESTART_DISCOVERY(pwp);
			} else {
				pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, pptr, NULL,
				    "%s: Retries exhausted for %s, killing",
				    __func__, pptr->path);
				pptr->config_stop = 0;
				pmcs_kill_changed(pwp, pptr, 0);
			}
			return (-1);
		}
		/*
		 * Other errors or no valid device id is fatal, but don't
		 * preclude a future action.
		 */
		if (result || pptr->valid_device_id == 0) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, pptr, NULL,
			    "%s: %s could not be registered", __func__,
			    pptr->path);
			return (-1);
		}
	}
	return (0);
}

int
pmcs_iport_tgtmap_create(pmcs_iport_t *iport)
{
	ASSERT(iport);
	if (iport == NULL)
		return (B_FALSE);

	pmcs_prt(iport->pwp, PMCS_PRT_DEBUG_MAP, NULL, NULL, "%s", __func__);

	/* create target map */
	if (scsi_hba_tgtmap_create(iport->dip, SCSI_TM_FULLSET, tgtmap_usec,
	    2048, NULL, NULL, NULL, &iport->iss_tgtmap) != DDI_SUCCESS) {
		pmcs_prt(iport->pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: failed to create tgtmap", __func__);
		return (B_FALSE);
	}
	return (B_TRUE);
}

int
pmcs_iport_tgtmap_destroy(pmcs_iport_t *iport)
{
	ASSERT(iport && iport->iss_tgtmap);
	if ((iport == NULL) || (iport->iss_tgtmap == NULL))
		return (B_FALSE);

	pmcs_prt(iport->pwp, PMCS_PRT_DEBUG_MAP, NULL, NULL, "%s", __func__);

	/* destroy target map */
	scsi_hba_tgtmap_destroy(iport->iss_tgtmap);
	return (B_TRUE);
}

/*
 * Query the phymap and populate the iport handle passed in.
 * Called with iport lock held.
 */
int
pmcs_iport_configure_phys(pmcs_iport_t *iport)
{
	pmcs_hw_t		*pwp;
	pmcs_phy_t		*pptr;
	sas_phymap_phys_t	*phys;
	int			phynum;
	int			inst;

	ASSERT(iport);
	ASSERT(mutex_owned(&iport->lock));
	pwp = iport->pwp;
	ASSERT(pwp);
	inst = ddi_get_instance(iport->dip);

	mutex_enter(&pwp->lock);
	ASSERT(pwp->root_phys != NULL);

	/*
	 * Query the phymap regarding the phys in this iport and populate
	 * the iport's phys list. Hereafter this list is maintained via
	 * port up and down events in pmcs_intr.c
	 */
	ASSERT(list_is_empty(&iport->phys));
	phys = sas_phymap_ua2phys(pwp->hss_phymap, iport->ua);
	while ((phynum = sas_phymap_phys_next(phys)) != -1) {
		/* Grab the phy pointer from root_phys */
		pptr = pwp->root_phys + phynum;
		ASSERT(pptr);
		pmcs_lock_phy(pptr);
		ASSERT(pptr->phynum == phynum);

		/*
		 * Set a back pointer in the phy to this iport.
		 */
		pptr->iport = iport;

		/*
		 * If this phy is the primary, set a pointer to it on our
		 * iport handle, and set our portid from it.
		 */
		if (!pptr->subsidiary) {
			iport->pptr = pptr;
			iport->portid = pptr->portid;
		}

		/*
		 * Finally, insert the phy into our list
		 */
		pmcs_add_phy_to_iport(iport, pptr);
		pmcs_unlock_phy(pptr);

		pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, pptr, NULL, "%s: found "
		    "phy %d [0x%p] on iport%d, refcnt(%d)", __func__, phynum,
		    (void *)pptr, inst, iport->refcnt);
	}
	mutex_exit(&pwp->lock);
	sas_phymap_phys_free(phys);
	RESTART_DISCOVERY(pwp);
	return (DDI_SUCCESS);
}

/*
 * Return the iport that ua is associated with, or NULL.  If an iport is
 * returned, it will be held and the caller must release the hold.
 */
static pmcs_iport_t *
pmcs_get_iport_by_ua(pmcs_hw_t *pwp, char *ua)
{
	pmcs_iport_t	*iport = NULL;

	rw_enter(&pwp->iports_lock, RW_READER);
	for (iport = list_head(&pwp->iports);
	    iport != NULL;
	    iport = list_next(&pwp->iports, iport)) {
		mutex_enter(&iport->lock);
		if (strcmp(iport->ua, ua) == 0) {
			mutex_exit(&iport->lock);
			mutex_enter(&iport->refcnt_lock);
			iport->refcnt++;
			mutex_exit(&iport->refcnt_lock);
			break;
		}
		mutex_exit(&iport->lock);
	}
	rw_exit(&pwp->iports_lock);

	return (iport);
}

/*
 * Return the iport that pptr is associated with, or NULL.
 * If an iport is returned, there is a hold that the caller must release.
 */
pmcs_iport_t *
pmcs_get_iport_by_phy(pmcs_hw_t *pwp, pmcs_phy_t *pptr)
{
	pmcs_iport_t	*iport = NULL;
	char		*ua;

	ua = sas_phymap_lookup_ua(pwp->hss_phymap, pwp->sas_wwns[0],
	    pmcs_barray2wwn(pptr->sas_address));
	if (ua) {
		iport = pmcs_get_iport_by_ua(pwp, ua);
		if (iport) {
			mutex_enter(&iport->lock);
			iport->ua_state = UA_ACTIVE;
			pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, pptr, NULL, "%s: "
			    "found iport [0x%p] on ua (%s) for phy [0x%p], "
			    "refcnt (%d)", __func__, (void *)iport, ua,
			    (void *)pptr, iport->refcnt);
			mutex_exit(&iport->lock);
		}
	}

	return (iport);
}

void
pmcs_rele_iport(pmcs_iport_t *iport)
{
	/*
	 * Release a refcnt on this iport. If this is the last reference,
	 * signal the potential waiter in pmcs_iport_unattach().
	 */
	ASSERT(iport->refcnt > 0);
	mutex_enter(&iport->refcnt_lock);
	iport->refcnt--;
	mutex_exit(&iport->refcnt_lock);
	if (iport->refcnt == 0) {
		cv_signal(&iport->refcnt_cv);
	}
	pmcs_prt(iport->pwp, PMCS_PRT_DEBUG_CONFIG, NULL, NULL, "%s: iport "
	    "[0x%p] refcnt (%d)", __func__, (void *)iport, iport->refcnt);
}

void
pmcs_phymap_activate(void *arg, char *ua, void **privp)
{
	_NOTE(ARGUNUSED(privp));
	pmcs_hw_t	*pwp = arg;
	pmcs_iport_t	*iport = NULL;

	mutex_enter(&pwp->lock);
	if ((pwp->state == STATE_UNPROBING) || (pwp->state == STATE_DEAD)) {
		mutex_exit(&pwp->lock);
		return;
	}
	pwp->phymap_active++;
	mutex_exit(&pwp->lock);

	if (scsi_hba_iportmap_iport_add(pwp->hss_iportmap, ua, NULL) !=
	    DDI_SUCCESS) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG_MAP, NULL, NULL, "%s: failed to "
		    "add iport handle on unit address [%s]", __func__, ua);
	} else {
		pmcs_prt(pwp, PMCS_PRT_DEBUG_MAP, NULL, NULL, "%s: "
		    "phymap_active count (%d), added iport handle on unit "
		    "address [%s]", __func__, pwp->phymap_active, ua);
	}

	/* Set the HBA softstate as our private data for this unit address */
	*privp = (void *)pwp;

	/*
	 * We are waiting on attach for this iport node, unless it is still
	 * attached. This can happen if a consumer has an outstanding open
	 * on our iport node, but the port is down.  If this is the case, we
	 * need to configure our iport here for reuse.
	 */
	iport = pmcs_get_iport_by_ua(pwp, ua);
	if (iport) {
		mutex_enter(&iport->lock);
		if (pmcs_iport_configure_phys(iport) != DDI_SUCCESS) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, NULL, NULL, "%s: "
			    "failed to configure phys on iport [0x%p] at "
			    "unit address (%s)", __func__, (void *)iport, ua);
		}
		iport->ua_state = UA_ACTIVE;
		pmcs_smhba_add_iport_prop(iport, DATA_TYPE_INT32, PMCS_NUM_PHYS,
		    &iport->nphy);
		mutex_exit(&iport->lock);
		pmcs_rele_iport(iport);
	}

}

void
pmcs_phymap_deactivate(void *arg, char *ua, void *privp)
{
	_NOTE(ARGUNUSED(privp));
	pmcs_hw_t	*pwp = arg;
	pmcs_iport_t	*iport;

	mutex_enter(&pwp->lock);
	pwp->phymap_active--;
	mutex_exit(&pwp->lock);

	if (scsi_hba_iportmap_iport_remove(pwp->hss_iportmap, ua) !=
	    DDI_SUCCESS) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG_MAP, NULL, NULL, "%s: failed to "
		    "remove iport handle on unit address [%s]", __func__, ua);
	} else {
		pmcs_prt(pwp, PMCS_PRT_DEBUG_MAP, NULL, NULL, "%s: "
		    "phymap_active count (%d), removed iport handle on unit "
		    "address [%s]", __func__, pwp->phymap_active, ua);
	}

	iport = pmcs_get_iport_by_ua(pwp, ua);

	if (iport == NULL) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, NULL, NULL, "%s: failed "
		    "lookup of iport handle on unit addr (%s)", __func__, ua);
		return;
	}

	mutex_enter(&iport->lock);
	iport->ua_state = UA_INACTIVE;
	iport->portid = PMCS_IPORT_INVALID_PORT_ID;
	pmcs_remove_phy_from_iport(iport, NULL);
	mutex_exit(&iport->lock);
	pmcs_rele_iport(iport);
}

/*
 * Top-level discovery function
 */
void
pmcs_discover(pmcs_hw_t *pwp)
{
	pmcs_phy_t		*pptr;
	pmcs_phy_t		*root_phy;
	boolean_t		config_changed;

	DTRACE_PROBE2(pmcs__discover__entry, ulong_t, pwp->work_flags,
	    boolean_t, pwp->config_changed);

	mutex_enter(&pwp->lock);

	if (pwp->state != STATE_RUNNING) {
		mutex_exit(&pwp->lock);
		return;
	}

	/* Ensure we have at least one phymap active */
	if (pwp->phymap_active == 0) {
		mutex_exit(&pwp->lock);
		pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, NULL, NULL,
		    "%s: phymap inactive, exiting", __func__);
		return;
	}

	mutex_exit(&pwp->lock);

	/*
	 * If no iports have attached, but we have PHYs that are up, we
	 * are waiting for iport attach to complete.  Restart discovery.
	 */
	rw_enter(&pwp->iports_lock, RW_READER);
	if (!pwp->iports_attached) {
		rw_exit(&pwp->iports_lock);
		pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, NULL, NULL,
		    "%s: no iports attached, retry discovery", __func__);
		SCHEDULE_WORK(pwp, PMCS_WORK_DISCOVER);
		return;
	}
	rw_exit(&pwp->iports_lock);

	mutex_enter(&pwp->config_lock);
	if (pwp->configuring) {
		mutex_exit(&pwp->config_lock);
		pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, NULL, NULL,
		    "%s: configuration already in progress", __func__);
		return;
	}

	if (pmcs_acquire_scratch(pwp, B_FALSE)) {
		mutex_exit(&pwp->config_lock);
		pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, NULL, NULL,
		    "%s: cannot allocate scratch", __func__);
		SCHEDULE_WORK(pwp, PMCS_WORK_DISCOVER);
		return;
	}

	pwp->configuring = 1;
	pwp->config_changed = B_FALSE;
	mutex_exit(&pwp->config_lock);

	pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, NULL, NULL, "Discovery begin");

	/*
	 * The order of the following traversals is important.
	 *
	 * The first one checks for changed expanders.
	 *
	 * The second one aborts commands for dead devices and deregisters them.
	 *
	 * The third one clears the contents of dead expanders from the tree
	 *
	 * The fourth one clears now dead devices in expanders that remain.
	 */

	/*
	 * 1. Check expanders marked changed (but not dead) to see if they still
	 * have the same number of phys and the same SAS address. Mark them,
	 * their subsidiary phys (if wide) and their descendents dead if
	 * anything has changed. Check the devices they contain to see if
	 * *they* have changed. If they've changed from type NOTHING we leave
	 * them marked changed to be configured later (picking up a new SAS
	 * address and link rate if possible). Otherwise, any change in type,
	 * SAS address or removal of target role will cause us to mark them
	 * (and their descendents) as dead (and cause any pending commands
	 * and associated devices to be removed).
	 *
	 * NOTE: We don't want to bail on discovery if the config has
	 * changed until *after* we run pmcs_kill_devices.
	 */
	root_phy = pwp->root_phys;
	config_changed = pmcs_check_expanders(pwp, root_phy);

	/*
	 * 2. Descend the tree looking for dead devices and kill them
	 * by aborting all active commands and then deregistering them.
	 */
	if (pmcs_kill_devices(pwp, root_phy) || config_changed) {
		goto out;
	}

	/*
	 * 3. Check for dead expanders and remove their children from the tree.
	 * By the time we get here, the devices and commands for them have
	 * already been terminated and removed.
	 *
	 * We do this independent of the configuration count changing so we can
	 * free any dead device PHYs that were discovered while checking
	 * expanders. We ignore any subsidiary phys as pmcs_clear_expander
	 * will take care of those.
	 *
	 * NOTE: pmcs_clear_expander requires softstate lock
	 */
	mutex_enter(&pwp->lock);
	for (pptr = pwp->root_phys; pptr; pptr = pptr->sibling) {
		/*
		 * Call pmcs_clear_expander for every root PHY.  It will
		 * recurse and determine which (if any) expanders actually
		 * need to be cleared.
		 */
		pmcs_lock_phy(pptr);
		pmcs_clear_expander(pwp, pptr, 0);
		pmcs_unlock_phy(pptr);
	}
	mutex_exit(&pwp->lock);

	/*
	 * 4. Check for dead devices and nullify them. By the time we get here,
	 * the devices and commands for them have already been terminated
	 * and removed. This is different from step 2 in that this just nulls
	 * phys that are part of expanders that are still here but used to
	 * be something but are no longer something (e.g., after a pulled
	 * disk drive). Note that dead expanders had their contained phys
	 * removed from the tree- here, the expanders themselves are
	 * nullified (unless they were removed by being contained in another
	 * expander phy).
	 */
	pmcs_clear_phys(pwp, root_phy);

	/*
	 * 5. Now check for and configure new devices.
	 */
	if (pmcs_configure_new_devices(pwp, root_phy)) {
		goto restart;
	}

out:
	DTRACE_PROBE2(pmcs__discover__exit, ulong_t, pwp->work_flags,
	    boolean_t, pwp->config_changed);
	pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, NULL, NULL, "Discovery end");

	mutex_enter(&pwp->config_lock);

	if (pwp->config_changed == B_FALSE) {
		/*
		 * Observation is stable, report what we currently see to
		 * the tgtmaps for delta processing. Start by setting
		 * BEGIN on all tgtmaps.
		 */
		mutex_exit(&pwp->config_lock);
		if (pmcs_report_observations(pwp) == B_FALSE) {
			goto restart;
		}
		mutex_enter(&pwp->config_lock);
	} else {
		/*
		 * If config_changed is TRUE, we need to reschedule
		 * discovery now.
		 */
		pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, NULL, NULL,
		    "%s: Config has changed, will re-run discovery", __func__);
		SCHEDULE_WORK(pwp, PMCS_WORK_DISCOVER);
	}

	pmcs_release_scratch(pwp);
	pwp->configuring = 0;
	mutex_exit(&pwp->config_lock);

#ifdef DEBUG
	pptr = pmcs_find_phy_needing_work(pwp, pwp->root_phys);
	if (pptr != NULL) {
		if (!WORK_IS_SCHEDULED(pwp, PMCS_WORK_DISCOVER)) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, NULL,
			    "PHY %s dead=%d changed=%d configured=%d "
			    "but no work scheduled", pptr->path, pptr->dead,
			    pptr->changed, pptr->configured);
		}
		pmcs_unlock_phy(pptr);
	}
#endif

	return;

restart:
	/* Clean up and restart discovery */
	pmcs_release_scratch(pwp);
	mutex_enter(&pwp->config_lock);
	pwp->configuring = 0;
	RESTART_DISCOVERY_LOCKED(pwp);
	mutex_exit(&pwp->config_lock);
}

/*
 * Return any PHY that needs to have scheduled work done.  The PHY is returned
 * locked.
 */
static pmcs_phy_t *
pmcs_find_phy_needing_work(pmcs_hw_t *pwp, pmcs_phy_t *pptr)
{
	pmcs_phy_t *cphyp, *pnext;

	while (pptr) {
		pmcs_lock_phy(pptr);

		if (pptr->changed || (pptr->dead && pptr->valid_device_id)) {
			return (pptr);
		}

		pnext = pptr->sibling;

		if (pptr->children) {
			cphyp = pptr->children;
			pmcs_unlock_phy(pptr);
			cphyp = pmcs_find_phy_needing_work(pwp, cphyp);
			if (cphyp) {
				return (cphyp);
			}
		} else {
			pmcs_unlock_phy(pptr);
		}

		pptr = pnext;
	}

	return (NULL);
}

/*
 * Report current observations to SCSA.
 */
static boolean_t
pmcs_report_observations(pmcs_hw_t *pwp)
{
	pmcs_iport_t		*iport;
	scsi_hba_tgtmap_t	*tgtmap;
	char			*ap;
	pmcs_phy_t		*pptr;
	uint64_t		wwn;

	/*
	 * Observation is stable, report what we currently see to the tgtmaps
	 * for delta processing. Start by setting BEGIN on all tgtmaps.
	 */
	rw_enter(&pwp->iports_lock, RW_READER);
	for (iport = list_head(&pwp->iports); iport != NULL;
	    iport = list_next(&pwp->iports, iport)) {
		/*
		 * Unless we have at least one phy up, skip this iport.
		 * Note we don't need to lock the iport for report_skip
		 * since it is only used here.  We are doing the skip so that
		 * the phymap and iportmap stabilization times are honored -
		 * giving us the ability to recover port operation within the
		 * stabilization time without unconfiguring targets using the
		 * port.
		 */
		if (!sas_phymap_uahasphys(pwp->hss_phymap, iport->ua)) {
			iport->report_skip = 1;
			continue;		/* skip set_begin */
		}
		iport->report_skip = 0;

		tgtmap = iport->iss_tgtmap;
		ASSERT(tgtmap);
		if (scsi_hba_tgtmap_set_begin(tgtmap) != DDI_SUCCESS) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG_MAP, NULL, NULL,
			    "%s: cannot set_begin tgtmap ", __func__);
			rw_exit(&pwp->iports_lock);
			return (B_FALSE);
		}
		pmcs_prt(pwp, PMCS_PRT_DEBUG_MAP, NULL, NULL,
		    "%s: set begin on tgtmap [0x%p]", __func__, (void *)tgtmap);
	}
	rw_exit(&pwp->iports_lock);

	/*
	 * Now, cycle through all levels of all phys and report
	 * observations into their respective tgtmaps.
	 */
	pptr = pwp->root_phys;

	while (pptr) {
		pmcs_lock_phy(pptr);

		/*
		 * Skip PHYs that have nothing attached or are dead.
		 */
		if ((pptr->dtype == NOTHING) || pptr->dead) {
			pmcs_unlock_phy(pptr);
			pptr = pptr->sibling;
			continue;
		}

		if (pptr->changed) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, pptr, NULL,
			    "%s: oops, PHY %s changed; restart discovery",
			    __func__, pptr->path);
			pmcs_unlock_phy(pptr);
			return (B_FALSE);
		}

		/*
		 * Get the iport for this root PHY, then call the helper
		 * to report observations for this iport's targets
		 */
		iport = pmcs_get_iport_by_phy(pwp, pptr);
		if (iport == NULL) {
			/* No iport for this tgt */
			pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, NULL, NULL,
			    "%s: no iport for this target", __func__);
			pmcs_unlock_phy(pptr);
			pptr = pptr->sibling;
			continue;
		}

		if (!iport->report_skip) {
			if (pmcs_report_iport_observations(
			    pwp, iport, pptr) == B_FALSE) {
				pmcs_rele_iport(iport);
				pmcs_unlock_phy(pptr);
				return (B_FALSE);
			}
		}
		pmcs_rele_iport(iport);
		pmcs_unlock_phy(pptr);
		pptr = pptr->sibling;
	}

	/*
	 * The observation is complete, end sets. Note we will skip any
	 * iports that are active, but have no PHYs in them (i.e. awaiting
	 * unconfigure). Set to restart discovery if we find this.
	 */
	rw_enter(&pwp->iports_lock, RW_READER);
	for (iport = list_head(&pwp->iports);
	    iport != NULL;
	    iport = list_next(&pwp->iports, iport)) {

		if (iport->report_skip)
			continue;		/* skip set_end */

		tgtmap = iport->iss_tgtmap;
		ASSERT(tgtmap);
		if (scsi_hba_tgtmap_set_end(tgtmap, 0) != DDI_SUCCESS) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG_MAP, NULL, NULL,
			    "%s: cannot set_end tgtmap ", __func__);
			rw_exit(&pwp->iports_lock);
			return (B_FALSE);
		}
		pmcs_prt(pwp, PMCS_PRT_DEBUG_MAP, NULL, NULL,
		    "%s: set end on tgtmap [0x%p]", __func__, (void *)tgtmap);
	}

	/*
	 * Now that discovery is complete, set up the necessary
	 * DDI properties on each iport node.
	 */
	for (iport = list_head(&pwp->iports); iport != NULL;
	    iport = list_next(&pwp->iports, iport)) {
		/* Set up the DDI properties on each phy */
		pmcs_smhba_set_phy_props(iport);

		/* Set up the 'attached-port' property on the iport */
		ap = kmem_zalloc(PMCS_MAX_UA_SIZE, KM_SLEEP);
		mutex_enter(&iport->lock);
		pptr = iport->pptr;
		mutex_exit(&iport->lock);
		if (pptr == NULL) {
			/*
			 * This iport is down, but has not been
			 * removed from our list (unconfigured).
			 * Set our value to '0'.
			 */
			(void) snprintf(ap, 1, "%s", "0");
		} else {
			/* Otherwise, set it to remote phy's wwn */
			pmcs_lock_phy(pptr);
			wwn = pmcs_barray2wwn(pptr->sas_address);
			(void) scsi_wwn_to_wwnstr(wwn, 1, ap);
			pmcs_unlock_phy(pptr);
		}
		if (ndi_prop_update_string(DDI_DEV_T_NONE, iport->dip,
		    SCSI_ADDR_PROP_ATTACHED_PORT,  ap) != DDI_SUCCESS) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL, "%s: Failed "
			    "to set prop ("SCSI_ADDR_PROP_ATTACHED_PORT")",
			    __func__);
		}
		kmem_free(ap, PMCS_MAX_UA_SIZE);
	}
	rw_exit(&pwp->iports_lock);

	return (B_TRUE);
}

/*
 * Report observations into a particular iport's target map
 *
 * Called with phyp (and all descendents) locked
 */
static boolean_t
pmcs_report_iport_observations(pmcs_hw_t *pwp, pmcs_iport_t *iport,
    pmcs_phy_t *phyp)
{
	pmcs_phy_t		*lphyp;
	scsi_hba_tgtmap_t	*tgtmap;
	scsi_tgtmap_tgt_type_t	tgt_type;
	char			*ua;
	uint64_t		wwn;

	tgtmap = iport->iss_tgtmap;
	ASSERT(tgtmap);

	lphyp = phyp;
	while (lphyp) {
		switch (lphyp->dtype) {
		default:		/* Skip unknown PHYs. */
			/* for non-root phys, skip to sibling */
			goto next_phy;

		case SATA:
		case SAS:
			tgt_type = SCSI_TGT_SCSI_DEVICE;
			break;

		case EXPANDER:
			tgt_type = SCSI_TGT_SMP_DEVICE;
			break;
		}

		if (lphyp->dead) {
			goto next_phy;
		}

		wwn = pmcs_barray2wwn(lphyp->sas_address);
		ua = scsi_wwn_to_wwnstr(wwn, 1, NULL);

		pmcs_prt(pwp, PMCS_PRT_DEBUG_MAP, lphyp, NULL,
		    "iport_observation: adding %s on tgtmap [0x%p] phy [0x%p]",
		    ua, (void *)tgtmap, (void*)lphyp);

		if (scsi_hba_tgtmap_set_add(tgtmap, tgt_type, ua, NULL) !=
		    DDI_SUCCESS) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG_MAP,  NULL, NULL,
			    "%s: failed to add address %s", __func__, ua);
			scsi_free_wwnstr(ua);
			return (B_FALSE);
		}
		scsi_free_wwnstr(ua);

		if (lphyp->children) {
			if (pmcs_report_iport_observations(pwp, iport,
			    lphyp->children) == B_FALSE) {
				return (B_FALSE);
			}
		}

		/* for non-root phys, report siblings too */
next_phy:
		if (IS_ROOT_PHY(lphyp)) {
			lphyp = NULL;
		} else {
			lphyp = lphyp->sibling;
		}
	}

	return (B_TRUE);
}

/*
 * Check for and configure new devices.
 *
 * If the changed device is a SATA device, add a SATA device.
 *
 * If the changed device is a SAS device, add a SAS device.
 *
 * If the changed device is an EXPANDER device, do a REPORT
 * GENERAL SMP command to find out the number of contained phys.
 *
 * For each number of contained phys, allocate a phy, do a
 * DISCOVERY SMP command to find out what kind of device it
 * is and add it to the linked list of phys on the *next* level.
 *
 * NOTE: pptr passed in by the caller will be a root PHY
 */
static int
pmcs_configure_new_devices(pmcs_hw_t *pwp, pmcs_phy_t *pptr)
{
	int rval = 0;
	pmcs_iport_t *iport;
	pmcs_phy_t *pnext, *orig_pptr = pptr, *root_phy, *pchild;

	/*
	 * First, walk through each PHY at this level
	 */
	while (pptr) {
		pmcs_lock_phy(pptr);
		pnext = pptr->sibling;

		/*
		 * Set the new dtype if it has changed
		 */
		if ((pptr->pend_dtype != NEW) &&
		    (pptr->pend_dtype != pptr->dtype)) {
			pptr->dtype = pptr->pend_dtype;
		}

		if (pptr->changed == 0 || pptr->dead || pptr->configured) {
			goto next_phy;
		}

		/*
		 * Confirm that this target's iport is configured
		 */
		root_phy = pmcs_get_root_phy(pptr);
		iport = pmcs_get_iport_by_phy(pwp, root_phy);
		if (iport == NULL) {
			/* No iport for this tgt, restart */
			pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, NULL, NULL,
			    "%s: iport not yet configured, "
			    "retry discovery", __func__);
			pnext = NULL;
			rval = -1;
			goto next_phy;
		}

		switch (pptr->dtype) {
		case NOTHING:
			pptr->changed = 0;
			break;
		case SATA:
		case SAS:
			pptr->iport = iport;
			pmcs_new_tport(pwp, pptr);
			break;
		case EXPANDER:
			pmcs_configure_expander(pwp, pptr, iport);
			break;
		}
		pmcs_rele_iport(iport);

		mutex_enter(&pwp->config_lock);
		if (pwp->config_changed) {
			mutex_exit(&pwp->config_lock);
			pnext = NULL;
			goto next_phy;
		}
		mutex_exit(&pwp->config_lock);

next_phy:
		pmcs_unlock_phy(pptr);
		pptr = pnext;
	}

	if (rval != 0) {
		return (rval);
	}

	/*
	 * Now walk through each PHY again, recalling ourselves if they
	 * have children
	 */
	pptr = orig_pptr;
	while (pptr) {
		pmcs_lock_phy(pptr);
		pnext = pptr->sibling;
		pchild = pptr->children;
		pmcs_unlock_phy(pptr);

		if (pchild) {
			rval = pmcs_configure_new_devices(pwp, pchild);
			if (rval != 0) {
				break;
			}
		}

		pptr = pnext;
	}

	return (rval);
}

/*
 * Set all phys and descendent phys as changed if changed == B_TRUE, otherwise
 * mark them all as not changed.
 *
 * Called with parent PHY locked.
 */
void
pmcs_set_changed(pmcs_hw_t *pwp, pmcs_phy_t *parent, boolean_t changed,
    int level)
{
	pmcs_phy_t *pptr;

	if (level == 0) {
		if (changed) {
			PHY_CHANGED(pwp, parent);
		} else {
			parent->changed = 0;
		}
		if (parent->dtype == EXPANDER && parent->level) {
			parent->width = 1;
		}
		if (parent->children) {
			pmcs_set_changed(pwp, parent->children, changed,
			    level + 1);
		}
	} else {
		pptr = parent;
		while (pptr) {
			if (changed) {
				PHY_CHANGED(pwp, pptr);
			} else {
				pptr->changed = 0;
			}
			if (pptr->dtype == EXPANDER && pptr->level) {
				pptr->width = 1;
			}
			if (pptr->children) {
				pmcs_set_changed(pwp, pptr->children, changed,
				    level + 1);
			}
			pptr = pptr->sibling;
		}
	}
}

/*
 * Take the passed phy mark it and its descendants as dead.
 * Fire up reconfiguration to abort commands and bury it.
 *
 * Called with the parent PHY locked.
 */
void
pmcs_kill_changed(pmcs_hw_t *pwp, pmcs_phy_t *parent, int level)
{
	pmcs_phy_t *pptr = parent;

	while (pptr) {
		pptr->link_rate = 0;
		pptr->abort_sent = 0;
		pptr->abort_pending = 1;
		SCHEDULE_WORK(pwp, PMCS_WORK_ABORT_HANDLE);
		pptr->need_rl_ext = 0;

		if (pptr->dead == 0) {
			PHY_CHANGED(pwp, pptr);
			RESTART_DISCOVERY(pwp);
		}

		pptr->dead = 1;

		if (pptr->children) {
			pmcs_kill_changed(pwp, pptr->children, level + 1);
		}

		/*
		 * Only kill siblings at level > 0
		 */
		if (level == 0) {
			return;
		}

		pptr = pptr->sibling;
	}
}

/*
 * Go through every PHY and clear any that are dead (unless they're expanders)
 */
static void
pmcs_clear_phys(pmcs_hw_t *pwp, pmcs_phy_t *pptr)
{
	pmcs_phy_t *pnext, *phyp;

	phyp = pptr;
	while (phyp) {
		if (IS_ROOT_PHY(phyp)) {
			pmcs_lock_phy(phyp);
		}

		if ((phyp->dtype != EXPANDER) && phyp->dead) {
			pmcs_clear_phy(pwp, phyp);
		}

		if (phyp->children) {
			pmcs_clear_phys(pwp, phyp->children);
		}

		pnext = phyp->sibling;

		if (IS_ROOT_PHY(phyp)) {
			pmcs_unlock_phy(phyp);
		}

		phyp = pnext;
	}
}

/*
 * Clear volatile parts of a phy.  Called with PHY locked.
 */
void
pmcs_clear_phy(pmcs_hw_t *pwp, pmcs_phy_t *pptr)
{
	pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, pptr, NULL, "%s: %s",
	    __func__, pptr->path);
	ASSERT(mutex_owned(&pptr->phy_lock));
	/* keep sibling */
	/* keep children */
	/* keep parent */
	pptr->device_id = PMCS_INVALID_DEVICE_ID;
	/* keep hw_event_ack */
	pptr->ncphy = 0;
	/* keep phynum */
	pptr->width = 0;
	pptr->ds_recovery_retries = 0;
	/* keep dtype */
	pptr->config_stop = 0;
	pptr->spinup_hold = 0;
	pptr->atdt = 0;
	/* keep portid */
	pptr->link_rate = 0;
	pptr->valid_device_id = 0;
	pptr->abort_sent = 0;
	pptr->abort_pending = 0;
	pptr->need_rl_ext = 0;
	pptr->subsidiary = 0;
	pptr->configured = 0;
	/* Only mark dead if it's not a root PHY and its dtype isn't NOTHING */
	/* XXX: What about directly attached disks? */
	if (!IS_ROOT_PHY(pptr) && (pptr->dtype != NOTHING))
		pptr->dead = 1;
	pptr->changed = 0;
	/* keep SAS address */
	/* keep path */
	/* keep ref_count */
	/* Don't clear iport on root PHYs - they are handled in pmcs_intr.c */
	if (!IS_ROOT_PHY(pptr)) {
		pptr->iport = NULL;
	}
	/* keep target */
}

/*
 * Allocate softstate for this target if there isn't already one.  If there
 * is, just redo our internal configuration.  If it is actually "new", we'll
 * soon get a tran_tgt_init for it.
 *
 * Called with PHY locked.
 */
static void
pmcs_new_tport(pmcs_hw_t *pwp, pmcs_phy_t *pptr)
{
	pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, pptr, NULL, "%s: phy 0x%p @ %s",
	    __func__, (void *)pptr, pptr->path);

	if (pmcs_configure_phy(pwp, pptr) == B_FALSE) {
		/*
		 * If the config failed, mark the PHY as changed.
		 */
		PHY_CHANGED(pwp, pptr);
		pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, pptr, NULL,
		    "%s: pmcs_configure_phy failed for phy 0x%p", __func__,
		    (void *)pptr);
		return;
	}

	/* Mark PHY as no longer changed */
	pptr->changed = 0;

	/*
	 * If the PHY has no target pointer, see if there's a dead PHY that
	 * matches.
	 */
	if (pptr->target == NULL) {
		pmcs_reap_dead_phy(pptr);
	}

	/*
	 * Only assign the device if there is a target for this PHY with a
	 * matching SAS address.  If an iport is disconnected from one piece
	 * of storage and connected to another within the iport stabilization
	 * time, we can get the PHY/target mismatch situation.
	 *
	 * Otherwise, it'll get done in tran_tgt_init.
	 */
	if (pptr->target) {
		mutex_enter(&pptr->target->statlock);
		if (pmcs_phy_target_match(pptr) == B_FALSE) {
			mutex_exit(&pptr->target->statlock);
			if (!IS_ROOT_PHY(pptr)) {
				pmcs_dec_phy_ref_count(pptr);
			}
			pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, NULL,
			    "%s: Not assigning existing tgt %p for PHY %p "
			    "(WWN mismatch)", __func__, (void *)pptr->target,
			    (void *)pptr);
			pptr->target = NULL;
			return;
		}

		if (!pmcs_assign_device(pwp, pptr->target)) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, pptr, pptr->target,
			    "%s: pmcs_assign_device failed for target 0x%p",
			    __func__, (void *)pptr->target);
		}
		mutex_exit(&pptr->target->statlock);
	}
}

/*
 * Called with PHY lock held.
 */
static boolean_t
pmcs_configure_phy(pmcs_hw_t *pwp, pmcs_phy_t *pptr)
{
	char *dtype;

	ASSERT(mutex_owned(&pptr->phy_lock));

	/*
	 * Mark this device as no longer changed.
	 */
	pptr->changed = 0;

	/*
	 * If we don't have a device handle, get one.
	 */
	if (pmcs_get_device_handle(pwp, pptr)) {
		return (B_FALSE);
	}

	pptr->configured = 1;

	switch (pptr->dtype) {
	case SAS:
		dtype = "SAS";
		break;
	case SATA:
		dtype = "SATA";
		break;
	case EXPANDER:
		dtype = "SMP";
		break;
	default:
		dtype = "???";
	}

	pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, pptr, NULL, "config_dev: %s "
	    "dev %s " SAS_ADDR_FMT " dev id 0x%x lr 0x%x", dtype, pptr->path,
	    SAS_ADDR_PRT(pptr->sas_address), pptr->device_id, pptr->link_rate);

	return (B_TRUE);
}

/*
 * Called with PHY locked
 */
static void
pmcs_configure_expander(pmcs_hw_t *pwp, pmcs_phy_t *pptr, pmcs_iport_t *iport)
{
	pmcs_phy_t *ctmp, *clist = NULL, *cnext;
	int result, i, nphy = 0;
	boolean_t root_phy = B_FALSE;

	ASSERT(iport);

	/*
	 * Step 1- clear our "changed" bit. If we need to retry/restart due
	 * to resource shortages, we'll set it again. While we're doing
	 * configuration, other events may set it again as well.  If the PHY
	 * is a root PHY and is currently marked as having changed, reset the
	 * config_stop timer as well.
	 */
	if (IS_ROOT_PHY(pptr) && pptr->changed) {
		pptr->config_stop = ddi_get_lbolt() +
		    drv_usectohz(PMCS_MAX_CONFIG_TIME);
	}
	pptr->changed = 0;

	/*
	 * Step 2- make sure we don't overflow
	 */
	if (pptr->level == PMCS_MAX_XPND-1) {
		pmcs_prt(pwp, PMCS_PRT_WARN, pptr, NULL,
		    "%s: SAS expansion tree too deep", __func__);
		return;
	}

	/*
	 * Step 3- Check if this expander is part of a wide phy that has
	 * already been configured.
	 *
	 * This is known by checking this level for another EXPANDER device
	 * with the same SAS address and isn't already marked as a subsidiary
	 * phy and a parent whose SAS address is the same as our SAS address
	 * (if there are parents).
	 */
	if (!IS_ROOT_PHY(pptr)) {
		/*
		 * No need to lock the parent here because we're in discovery
		 * and the only time a PHY's children pointer can change is
		 * in discovery; either in pmcs_clear_expander (which has
		 * already been called) or here, down below.  Plus, trying to
		 * grab the parent's lock here can cause deadlock.
		 */
		ctmp = pptr->parent->children;
	} else {
		ctmp = pwp->root_phys;
		root_phy = B_TRUE;
	}

	while (ctmp) {
		/*
		 * If we've checked all PHYs up to pptr, we stop. Otherwise,
		 * we'll be checking for a primary PHY with a higher PHY
		 * number than pptr, which will never happen.  The primary
		 * PHY on non-root expanders will ALWAYS be the lowest
		 * numbered PHY.
		 */
		if (ctmp == pptr) {
			break;
		}

		/*
		 * If pptr and ctmp are root PHYs, just grab the mutex on
		 * ctmp.  No need to lock the entire tree.  If they are not
		 * root PHYs, there is no need to lock since a non-root PHY's
		 * SAS address and other characteristics can only change in
		 * discovery anyway.
		 */
		if (root_phy) {
			mutex_enter(&ctmp->phy_lock);
		}

		if (ctmp->dtype == EXPANDER && ctmp->width &&
		    memcmp(ctmp->sas_address, pptr->sas_address, 8) == 0) {
			int widephy = 0;
			/*
			 * If these phys are not root PHYs, compare their SAS
			 * addresses too.
			 */
			if (!root_phy) {
				if (memcmp(ctmp->parent->sas_address,
				    pptr->parent->sas_address, 8) == 0) {
					widephy = 1;
				}
			} else {
				widephy = 1;
			}
			if (widephy) {
				ctmp->width++;
				pptr->subsidiary = 1;
				pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, pptr, NULL,
				    "%s: PHY %s part of wide PHY %s "
				    "(now %d wide)", __func__, pptr->path,
				    ctmp->path, ctmp->width);
				if (root_phy) {
					mutex_exit(&ctmp->phy_lock);
				}
				return;
			}
		}

		cnext = ctmp->sibling;
		if (root_phy) {
			mutex_exit(&ctmp->phy_lock);
		}
		ctmp = cnext;
	}

	/*
	 * Step 4- If we don't have a device handle, get one.  Since this
	 * is the primary PHY, make sure subsidiary is cleared.
	 */
	pptr->subsidiary = 0;
	if (pmcs_get_device_handle(pwp, pptr)) {
		goto out;
	}
	pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, pptr, NULL, "Config expander %s "
	    SAS_ADDR_FMT " dev id 0x%x lr 0x%x", pptr->path,
	    SAS_ADDR_PRT(pptr->sas_address), pptr->device_id, pptr->link_rate);

	/*
	 * Step 5- figure out how many phys are in this expander.
	 */
	nphy = pmcs_expander_get_nphy(pwp, pptr);
	if (nphy <= 0) {
		if (nphy == 0 && ddi_get_lbolt() < pptr->config_stop) {
			PHY_CHANGED(pwp, pptr);
			RESTART_DISCOVERY(pwp);
		} else {
			pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, pptr, NULL,
			    "%s: Retries exhausted for %s, killing", __func__,
			    pptr->path);
			pptr->config_stop = 0;
			pmcs_kill_changed(pwp, pptr, 0);
		}
		goto out;
	}

	/*
	 * Step 6- Allocate a list of phys for this expander and figure out
	 * what each one is.
	 */
	for (i = 0; i < nphy; i++) {
		ctmp = kmem_cache_alloc(pwp->phy_cache, KM_SLEEP);
		bzero(ctmp, sizeof (pmcs_phy_t));
		ctmp->device_id = PMCS_INVALID_DEVICE_ID;
		ctmp->sibling = clist;
		ctmp->pend_dtype = NEW;	/* Init pending dtype */
		ctmp->config_stop = ddi_get_lbolt() +
		    drv_usectohz(PMCS_MAX_CONFIG_TIME);
		clist = ctmp;
	}

	mutex_enter(&pwp->config_lock);
	if (pwp->config_changed) {
		RESTART_DISCOVERY_LOCKED(pwp);
		mutex_exit(&pwp->config_lock);
		/*
		 * Clean up the newly allocated PHYs and return
		 */
		while (clist) {
			ctmp = clist->sibling;
			kmem_cache_free(pwp->phy_cache, clist);
			clist = ctmp;
		}
		return;
	}
	mutex_exit(&pwp->config_lock);

	/*
	 * Step 7- Now fill in the rest of the static portions of the phy.
	 */
	for (i = 0, ctmp = clist; ctmp; ctmp = ctmp->sibling, i++) {
		ctmp->parent = pptr;
		ctmp->pwp = pwp;
		ctmp->level = pptr->level+1;
		ctmp->portid = pptr->portid;
		if (ctmp->tolerates_sas2) {
			ASSERT(i < SAS2_PHYNUM_MAX);
			ctmp->phynum = i & SAS2_PHYNUM_MASK;
		} else {
			ASSERT(i < SAS_PHYNUM_MAX);
			ctmp->phynum = i & SAS_PHYNUM_MASK;
		}
		pmcs_phy_name(pwp, ctmp, ctmp->path, sizeof (ctmp->path));
		pmcs_lock_phy(ctmp);
	}

	/*
	 * Step 8- Discover things about each phy in the expander.
	 */
	for (i = 0, ctmp = clist; ctmp; ctmp = ctmp->sibling, i++) {
		result = pmcs_expander_content_discover(pwp, pptr, ctmp);
		if (result <= 0) {
			if (ddi_get_lbolt() < pptr->config_stop) {
				PHY_CHANGED(pwp, pptr);
				RESTART_DISCOVERY(pwp);
			} else {
				pptr->config_stop = 0;
				pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, pptr, NULL,
				    "%s: Retries exhausted for %s, killing",
				    __func__, pptr->path);
				pmcs_kill_changed(pwp, pptr, 0);
			}
			goto out;
		}

		/* Set pend_dtype to dtype for 1st time initialization */
		ctmp->pend_dtype = ctmp->dtype;
	}

	/*
	 * Step 9- Install the new list on the next level. There should be
	 * no children pointer on this PHY.  If there is, we'd need to know
	 * how it happened (The expander suddenly got more PHYs?).
	 */
	ASSERT(pptr->children == NULL);
	if (pptr->children != NULL) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, NULL, "%s: Already child "
		    "PHYs attached  to PHY %s: This should never happen",
		    __func__, pptr->path);
		goto out;
	} else {
		pptr->children = clist;
	}

	clist = NULL;
	pptr->ncphy = nphy;
	pptr->configured = 1;

	/*
	 * We only set width if we're greater than level 0.
	 */
	if (pptr->level) {
		pptr->width = 1;
	}

	/*
	 * Now tell the rest of the world about us, as an SMP node.
	 */
	pptr->iport = iport;
	pmcs_new_tport(pwp, pptr);

out:
	while (clist) {
		ctmp = clist->sibling;
		pmcs_unlock_phy(clist);
		kmem_cache_free(pwp->phy_cache, clist);
		clist = ctmp;
	}
}

/*
 * 2. Check expanders marked changed (but not dead) to see if they still have
 * the same number of phys and the same SAS address. Mark them, their subsidiary
 * phys (if wide) and their descendents dead if anything has changed. Check the
 * the devices they contain to see if *they* have changed. If they've changed
 * from type NOTHING we leave them marked changed to be configured later
 * (picking up a new SAS address and link rate if possible). Otherwise, any
 * change in type, SAS address or removal of target role will cause us to
 * mark them (and their descendents) as dead and cause any pending commands
 * and associated devices to be removed.
 *
 * Called with PHY (pptr) locked.
 */

static void
pmcs_check_expander(pmcs_hw_t *pwp, pmcs_phy_t *pptr)
{
	int nphy, result;
	pmcs_phy_t *ctmp, *local, *local_list = NULL, *local_tail = NULL;
	boolean_t kill_changed, changed;

	pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, pptr, NULL,
	    "%s: check %s", __func__, pptr->path);

	/*
	 * Step 1: Mark phy as not changed. We will mark it changed if we need
	 * to retry.
	 */
	pptr->changed = 0;

	/*
	 * Reset the config_stop time. Although we're not actually configuring
	 * anything here, we do want some indication of when to give up trying
	 * if we can't communicate with the expander.
	 */
	pptr->config_stop = ddi_get_lbolt() +
	    drv_usectohz(PMCS_MAX_CONFIG_TIME);

	/*
	 * Step 2: Figure out how many phys are in this expander. If
	 * pmcs_expander_get_nphy returns 0 we ran out of resources,
	 * so reschedule and try later. If it returns another error,
	 * just return.
	 */
	nphy = pmcs_expander_get_nphy(pwp, pptr);
	if (nphy <= 0) {
		if ((nphy == 0) && (ddi_get_lbolt() < pptr->config_stop)) {
			PHY_CHANGED(pwp, pptr);
			RESTART_DISCOVERY(pwp);
		} else {
			pptr->config_stop = 0;
			pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, pptr, NULL,
			    "%s: Retries exhausted for %s, killing", __func__,
			    pptr->path);
			pmcs_kill_changed(pwp, pptr, 0);
		}
		return;
	}

	/*
	 * Step 3: If the number of phys don't agree, kill the old sub-tree.
	 */
	if (nphy != pptr->ncphy) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, pptr, NULL,
		    "%s: number of contained phys for %s changed from %d to %d",
		    __func__, pptr->path, pptr->ncphy, nphy);
		/*
		 * Force a rescan of this expander after dead contents
		 * are cleared and removed.
		 */
		pmcs_kill_changed(pwp, pptr, 0);
		return;
	}

	/*
	 * Step 4: if we're at the bottom of the stack, we're done
	 * (we can't have any levels below us)
	 */
	if (pptr->level == PMCS_MAX_XPND-1) {
		return;
	}

	/*
	 * Step 5: Discover things about each phy in this expander.  We do
	 * this by walking the current list of contained phys and doing a
	 * content discovery for it to a local phy.
	 */
	ctmp = pptr->children;
	ASSERT(ctmp);
	if (ctmp == NULL) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, pptr, NULL,
		    "%s: No children attached to expander @ %s?", __func__,
		    pptr->path);
		return;
	}

	while (ctmp) {
		/*
		 * Allocate a local PHY to contain the proposed new contents
		 * and link it to the rest of the local PHYs so that they
		 * can all be freed later.
		 */
		local = pmcs_clone_phy(ctmp);

		if (local_list == NULL) {
			local_list = local;
			local_tail = local;
		} else {
			local_tail->sibling = local;
			local_tail = local;
		}

		/*
		 * Need to lock the local PHY since pmcs_expander_content_
		 * discovery may call pmcs_clear_phy on it, which expects
		 * the PHY to be locked.
		 */
		pmcs_lock_phy(local);
		result = pmcs_expander_content_discover(pwp, pptr, local);
		pmcs_unlock_phy(local);
		if (result <= 0) {
			if (ddi_get_lbolt() < pptr->config_stop) {
				PHY_CHANGED(pwp, pptr);
				RESTART_DISCOVERY(pwp);
			} else {
				pptr->config_stop = 0;
				pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, pptr, NULL,
				    "%s: Retries exhausted for %s, killing",
				    __func__, pptr->path);
				pmcs_kill_changed(pwp, pptr, 0);
			}

			/*
			 * Release all the local PHYs that we allocated.
			 */
			pmcs_free_phys(pwp, local_list);
			return;
		}

		ctmp = ctmp->sibling;
	}

	/*
	 * Step 6: Compare the local PHY's contents to our current PHY.  If
	 * there are changes, take the appropriate action.
	 * This is done in two steps (step 5 above, and 6 here) so that if we
	 * have to bail during this process (e.g. pmcs_expander_content_discover
	 * fails), we haven't actually changed the state of any of the real
	 * PHYs.  Next time we come through here, we'll be starting over from
	 * scratch.  This keeps us from marking a changed PHY as no longer
	 * changed, but then having to bail only to come back next time and
	 * think that the PHY hadn't changed.  If this were to happen, we
	 * would fail to properly configure the device behind this PHY.
	 */
	local = local_list;
	ctmp = pptr->children;

	while (ctmp) {
		changed = B_FALSE;
		kill_changed = B_FALSE;

		/*
		 * We set local to local_list prior to this loop so that we
		 * can simply walk the local_list while we walk this list.  The
		 * two lists should be completely in sync.
		 *
		 * Clear the changed flag here.
		 */
		ctmp->changed = 0;

		if (ctmp->dtype != local->dtype) {
			if (ctmp->dtype != NOTHING) {
				pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, ctmp, NULL,
				    "%s: %s type changed from %s to %s "
				    "(killing)", __func__, ctmp->path,
				    PHY_TYPE(ctmp), PHY_TYPE(local));
				/*
				 * Force a rescan of this expander after dead
				 * contents are cleared and removed.
				 */
				changed = B_TRUE;
				kill_changed = B_TRUE;
			} else {
				changed = B_TRUE;
				pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, ctmp, NULL,
				    "%s: %s type changed from NOTHING to %s",
				    __func__, ctmp->path, PHY_TYPE(local));
			}

		} else if (ctmp->atdt != local->atdt) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, ctmp, NULL, "%s: "
			    "%s attached device type changed from %d to %d "
			    "(killing)", __func__, ctmp->path, ctmp->atdt,
			    local->atdt);
			/*
			 * Force a rescan of this expander after dead
			 * contents are cleared and removed.
			 */
			changed = B_TRUE;

			if (local->atdt == 0) {
				kill_changed = B_TRUE;
			}
		} else if (ctmp->link_rate != local->link_rate) {
			pmcs_prt(pwp, PMCS_PRT_INFO, ctmp, NULL, "%s: %s "
			    "changed speed from %s to %s", __func__, ctmp->path,
			    pmcs_get_rate(ctmp->link_rate),
			    pmcs_get_rate(local->link_rate));
			/* If the speed changed from invalid, force rescan */
			if (!PMCS_VALID_LINK_RATE(ctmp->link_rate)) {
				changed = B_TRUE;
				RESTART_DISCOVERY(pwp);
			} else {
				/* Just update to the new link rate */
				ctmp->link_rate = local->link_rate;
			}

			if (!PMCS_VALID_LINK_RATE(local->link_rate)) {
				kill_changed = B_TRUE;
			}
		} else if (memcmp(ctmp->sas_address, local->sas_address,
		    sizeof (ctmp->sas_address)) != 0) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, ctmp, NULL,
			    "%s: SAS Addr for %s changed from " SAS_ADDR_FMT
			    "to " SAS_ADDR_FMT " (kill old tree)", __func__,
			    ctmp->path, SAS_ADDR_PRT(ctmp->sas_address),
			    SAS_ADDR_PRT(local->sas_address));
			/*
			 * Force a rescan of this expander after dead
			 * contents are cleared and removed.
			 */
			changed = B_TRUE;
		} else {
			pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, ctmp, NULL,
			    "%s: %s looks the same (type %s)",
			    __func__, ctmp->path, PHY_TYPE(ctmp));
			/*
			 * If EXPANDER, still mark it changed so we
			 * re-evaluate its contents.  If it's not an expander,
			 * but it hasn't been configured, also mark it as
			 * changed so that it will undergo configuration.
			 */
			if (ctmp->dtype == EXPANDER) {
				changed = B_TRUE;
			} else if ((ctmp->dtype != NOTHING) &&
			    !ctmp->configured) {
				ctmp->changed = 1;
			} else {
				/* It simply hasn't changed */
				ctmp->changed = 0;
			}
		}

		/*
		 * If the PHY changed, call pmcs_kill_changed if indicated,
		 * update its contents to reflect its current state and mark it
		 * as changed.
		 */
		if (changed) {
			/*
			 * pmcs_kill_changed will mark the PHY as changed, so
			 * only do PHY_CHANGED if we did not do kill_changed.
			 */
			if (kill_changed) {
				pmcs_kill_changed(pwp, ctmp, 0);
			} else {
				/*
				 * If we're not killing the device, it's not
				 * dead.  Mark the PHY as changed.
				 */
				PHY_CHANGED(pwp, ctmp);

				if (ctmp->dead) {
					pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG,
					    ctmp, NULL, "%s: Unmarking PHY %s "
					    "dead, restarting discovery",
					    __func__, ctmp->path);
					ctmp->dead = 0;
					RESTART_DISCOVERY(pwp);
				}
			}

			/*
			 * If the dtype of this PHY is now NOTHING, mark it as
			 * unconfigured.  Set pend_dtype to what the new dtype
			 * is.  It'll get updated at the end of the discovery
			 * process.
			 */
			if (local->dtype == NOTHING) {
				bzero(ctmp->sas_address,
				    sizeof (local->sas_address));
				ctmp->atdt = 0;
				ctmp->link_rate = 0;
				ctmp->pend_dtype = NOTHING;
				ctmp->configured = 0;
			} else {
				(void) memcpy(ctmp->sas_address,
				    local->sas_address,
				    sizeof (local->sas_address));
				ctmp->atdt = local->atdt;
				ctmp->link_rate = local->link_rate;
				ctmp->pend_dtype = local->dtype;
			}
		}

		local = local->sibling;
		ctmp = ctmp->sibling;
	}

	/*
	 * If we got to here, that means we were able to see all the PHYs
	 * and we can now update all of the real PHYs with the information
	 * we got on the local PHYs.  Once that's done, free all the local
	 * PHYs.
	 */

	pmcs_free_phys(pwp, local_list);
}

/*
 * Top level routine to check expanders.  We call pmcs_check_expander for
 * each expander.  Since we're not doing any configuration right now, it
 * doesn't matter if this is breadth-first.
 */
static boolean_t
pmcs_check_expanders(pmcs_hw_t *pwp, pmcs_phy_t *pptr)
{
	pmcs_phy_t *phyp, *pnext, *pchild;
	boolean_t config_changed = B_FALSE;

	pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, pptr, NULL,
	    "%s: %s", __func__, pptr->path);

	/*
	 * Check each expander at this level
	 */
	phyp = pptr;
	while (phyp && !config_changed) {
		pmcs_lock_phy(phyp);

		if ((phyp->dtype == EXPANDER) && phyp->changed &&
		    !phyp->dead && !phyp->subsidiary &&
		    phyp->configured) {
			pmcs_check_expander(pwp, phyp);
		}

		pnext = phyp->sibling;
		pmcs_unlock_phy(phyp);

		mutex_enter(&pwp->config_lock);
		config_changed = pwp->config_changed;
		mutex_exit(&pwp->config_lock);

		phyp = pnext;
	}

	if (config_changed) {
		return (config_changed);
	}

	/*
	 * Now check the children
	 */
	phyp = pptr;
	while (phyp && !config_changed) {
		pmcs_lock_phy(phyp);
		pnext = phyp->sibling;
		pchild = phyp->children;
		pmcs_unlock_phy(phyp);

		if (pchild) {
			(void) pmcs_check_expanders(pwp, pchild);
		}

		mutex_enter(&pwp->config_lock);
		config_changed = pwp->config_changed;
		mutex_exit(&pwp->config_lock);

		phyp = pnext;
	}

	/*
	 * We're done
	 */
	return (config_changed);
}

/*
 * Called with softstate and PHY locked
 */
static void
pmcs_clear_expander(pmcs_hw_t *pwp, pmcs_phy_t *pptr, int level)
{
	pmcs_phy_t *ctmp;

	ASSERT(mutex_owned(&pwp->lock));
	ASSERT(mutex_owned(&pptr->phy_lock));
	ASSERT(pptr->level < PMCS_MAX_XPND - 1);

	pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, pptr, NULL,
	    "%s: checking %s", __func__, pptr->path);

	ctmp = pptr->children;
	while (ctmp) {
		/*
		 * If the expander is dead, mark its children dead
		 */
		if (pptr->dead) {
			ctmp->dead = 1;
		}
		if (ctmp->dtype == EXPANDER) {
			pmcs_clear_expander(pwp, ctmp, level + 1);
		}
		ctmp = ctmp->sibling;
	}

	/*
	 * If this expander is not dead, we're done here.
	 */
	if (!pptr->dead) {
		return;
	}

	/*
	 * Now snip out the list of children below us and release them
	 */
	ctmp = pptr->children;
	while (ctmp) {
		pmcs_phy_t *nxt = ctmp->sibling;
		pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, ctmp, NULL,
		    "%s: dead PHY 0x%p (%s) (ref_count %d)", __func__,
		    (void *)ctmp, ctmp->path, ctmp->ref_count);
		/*
		 * Put this PHY on the dead PHY list for the watchdog to
		 * clean up after any outstanding work has completed.
		 */
		mutex_enter(&pwp->dead_phylist_lock);
		ctmp->dead_next = pwp->dead_phys;
		pwp->dead_phys = ctmp;
		mutex_exit(&pwp->dead_phylist_lock);
		pmcs_unlock_phy(ctmp);
		ctmp = nxt;
	}

	pptr->children = NULL;

	/*
	 * Clear subsidiary phys as well.  Getting the parent's PHY lock
	 * is only necessary if level == 0 since otherwise the parent is
	 * already locked.
	 */
	if (!IS_ROOT_PHY(pptr)) {
		if (level == 0) {
			mutex_enter(&pptr->parent->phy_lock);
		}
		ctmp = pptr->parent->children;
		if (level == 0) {
			mutex_exit(&pptr->parent->phy_lock);
		}
	} else {
		ctmp = pwp->root_phys;
	}

	while (ctmp) {
		if (ctmp == pptr) {
			ctmp = ctmp->sibling;
			continue;
		}
		/*
		 * We only need to lock subsidiary PHYs on the level 0
		 * expander.  Any children of that expander, subsidiaries or
		 * not, will already be locked.
		 */
		if (level == 0) {
			pmcs_lock_phy(ctmp);
		}
		if (ctmp->dtype != EXPANDER || ctmp->subsidiary == 0 ||
		    memcmp(ctmp->sas_address, pptr->sas_address,
		    sizeof (ctmp->sas_address)) != 0) {
			if (level == 0) {
				pmcs_unlock_phy(ctmp);
			}
			ctmp = ctmp->sibling;
			continue;
		}
		pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, ctmp, NULL,
		    "%s: subsidiary %s", __func__, ctmp->path);
		pmcs_clear_phy(pwp, ctmp);
		if (level == 0) {
			pmcs_unlock_phy(ctmp);
		}
		ctmp = ctmp->sibling;
	}

	pmcs_clear_phy(pwp, pptr);
}

/*
 * Called with PHY locked and with scratch acquired. We return 0 if
 * we fail to allocate resources or notice that the configuration
 * count changed while we were running the command. We return
 * less than zero if we had an I/O error or received an unsupported
 * configuration. Otherwise we return the number of phys in the
 * expander.
 */
#define	DFM(m, y) if (m == NULL) m = y
static int
pmcs_expander_get_nphy(pmcs_hw_t *pwp, pmcs_phy_t *pptr)
{
	struct pmcwork *pwrk;
	char buf[64];
	const uint_t rdoff = 0x100;	/* returned data offset */
	smp_response_frame_t *srf;
	smp_report_general_resp_t *srgr;
	uint32_t msg[PMCS_MSG_SIZE], *ptr, htag, status, ival;
	int result;

	ival = 0x40001100;
again:
	pwrk = pmcs_gwork(pwp, PMCS_TAG_TYPE_WAIT, pptr);
	if (pwrk == NULL) {
		result = 0;
		goto out;
	}
	(void) memset(pwp->scratch, 0x77, PMCS_SCRATCH_SIZE);
	pwrk->arg = pwp->scratch;
	pwrk->dtype = pptr->dtype;
	mutex_enter(&pwp->iqp_lock[PMCS_IQ_OTHER]);
	ptr = GET_IQ_ENTRY(pwp, PMCS_IQ_OTHER);
	if (ptr == NULL) {
		mutex_exit(&pwp->iqp_lock[PMCS_IQ_OTHER]);
		pmcs_prt(pwp, PMCS_PRT_DEBUG2, pptr, NULL,
		    "%s: GET_IQ_ENTRY failed", __func__);
		pmcs_pwork(pwp, pwrk);
		result = 0;
		goto out;
	}

	msg[0] = LE_32(PMCS_HIPRI(pwp, PMCS_OQ_GENERAL, PMCIN_SMP_REQUEST));
	msg[1] = LE_32(pwrk->htag);
	msg[2] = LE_32(pptr->device_id);
	msg[3] = LE_32((4 << SMP_REQUEST_LENGTH_SHIFT) | SMP_INDIRECT_RESPONSE);
	/*
	 * Send SMP REPORT GENERAL (of either SAS1.1 or SAS2 flavors).
	 */
	msg[4] = BE_32(ival);
	msg[5] = 0;
	msg[6] = 0;
	msg[7] = 0;
	msg[8] = 0;
	msg[9] = 0;
	msg[10] = 0;
	msg[11] = 0;
	msg[12] = LE_32(DWORD0(pwp->scratch_dma+rdoff));
	msg[13] = LE_32(DWORD1(pwp->scratch_dma+rdoff));
	msg[14] = LE_32(PMCS_SCRATCH_SIZE - rdoff);
	msg[15] = 0;

	COPY_MESSAGE(ptr, msg, PMCS_MSG_SIZE);
	pwrk->state = PMCS_WORK_STATE_ONCHIP;
	htag = pwrk->htag;
	INC_IQ_ENTRY(pwp, PMCS_IQ_OTHER);

	pmcs_unlock_phy(pptr);
	WAIT_FOR(pwrk, 1000, result);
	pmcs_lock_phy(pptr);
	pmcs_pwork(pwp, pwrk);

	mutex_enter(&pwp->config_lock);
	if (pwp->config_changed) {
		RESTART_DISCOVERY_LOCKED(pwp);
		mutex_exit(&pwp->config_lock);
		result = 0;
		goto out;
	}
	mutex_exit(&pwp->config_lock);

	if (result) {
		pmcs_timed_out(pwp, htag, __func__);
		pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, pptr, NULL,
		    "%s: Issuing SMP ABORT for htag 0x%08x", __func__, htag);
		if (pmcs_abort(pwp, pptr, htag, 0, 0)) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, pptr, NULL,
			    "%s: Unable to issue SMP ABORT for htag 0x%08x",
			    __func__, htag);
		} else {
			pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, pptr, NULL,
			    "%s: Issuing SMP ABORT for htag 0x%08x",
			    __func__, htag);
		}
		result = 0;
		goto out;
	}
	ptr = (void *)pwp->scratch;
	status = LE_32(ptr[2]);
	if (status == PMCOUT_STATUS_UNDERFLOW ||
	    status == PMCOUT_STATUS_OVERFLOW) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG_UNDERFLOW, pptr, NULL,
		    "%s: over/underflow", __func__);
		status = PMCOUT_STATUS_OK;
	}
	srf = (smp_response_frame_t *)&((uint32_t *)pwp->scratch)[rdoff >> 2];
	srgr = (smp_report_general_resp_t *)
	    &((uint32_t *)pwp->scratch)[(rdoff >> 2)+1];

	if (status != PMCOUT_STATUS_OK) {
		char *nag = NULL;
		(void) snprintf(buf, sizeof (buf),
		    "%s: SMP op failed (0x%x)", __func__, status);
		switch (status) {
		case PMCOUT_STATUS_IO_PORT_IN_RESET:
			DFM(nag, "I/O Port In Reset");
			/* FALLTHROUGH */
		case PMCOUT_STATUS_ERROR_HW_TIMEOUT:
			DFM(nag, "Hardware Timeout");
			/* FALLTHROUGH */
		case PMCOUT_STATUS_ERROR_INTERNAL_SMP_RESOURCE:
			DFM(nag, "Internal SMP Resource Failure");
			/* FALLTHROUGH */
		case PMCOUT_STATUS_XFER_ERR_PHY_NOT_READY:
			DFM(nag, "PHY Not Ready");
			/* FALLTHROUGH */
		case PMCOUT_STATUS_OPEN_CNX_ERROR_CONNECTION_RATE_NOT_SUPPORTED:
			DFM(nag, "Connection Rate Not Supported");
			/* FALLTHROUGH */
		case PMCOUT_STATUS_IO_XFER_OPEN_RETRY_TIMEOUT:
			DFM(nag, "Open Retry Timeout");
			/* FALLTHROUGH */
		case PMCOUT_STATUS_SMP_RESP_CONNECTION_ERROR:
			DFM(nag, "Response Connection Error");
			pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, NULL,
			    "%s: expander %s SMP operation failed (%s)",
			    __func__, pptr->path, nag);
			break;

		/*
		 * For the IO_DS_NON_OPERATIONAL case, we need to kick off
		 * device state recovery and return 0 so that the caller
		 * doesn't assume this expander is dead for good.
		 */
		case PMCOUT_STATUS_IO_DS_NON_OPERATIONAL: {
			pmcs_xscsi_t *xp = pptr->target;

			pmcs_prt(pwp, PMCS_PRT_DEBUG_DEV_STATE, pptr, xp,
			    "%s: expander %s device state non-operational",
			    __func__, pptr->path);

			if (xp == NULL) {
				pmcs_prt(pwp, PMCS_PRT_DEBUG_DEV_STATE, pptr,
				    xp, "%s: No target to do DS recovery for "
				    "PHY %p (%s), attempting PHY hard reset",
				    __func__, (void *)pptr, pptr->path);
				(void) pmcs_reset_phy(pwp, pptr,
				    PMCS_PHYOP_HARD_RESET);
				break;
			}

			mutex_enter(&xp->statlock);
			pmcs_start_dev_state_recovery(xp, pptr);
			mutex_exit(&xp->statlock);
			break;
		}

		default:
			pmcs_print_entry(pwp, PMCS_PRT_DEBUG, buf, ptr);
			result = -EIO;
			break;
		}
	} else if (srf->srf_frame_type != SMP_FRAME_TYPE_RESPONSE) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, NULL,
		    "%s: bad response frame type 0x%x",
		    __func__, srf->srf_frame_type);
		result = -EINVAL;
	} else if (srf->srf_function != SMP_FUNC_REPORT_GENERAL) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, NULL,
		    "%s: bad response function 0x%x",
		    __func__, srf->srf_function);
		result = -EINVAL;
	} else if (srf->srf_result != 0) {
		/*
		 * Check to see if we have a value of 3 for failure and
		 * whether we were using a SAS2.0 allocation length value
		 * and retry without it.
		 */
		if (srf->srf_result == 3 && (ival & 0xff00)) {
			ival &= ~0xff00;
			pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, NULL,
			    "%s: err 0x%x with SAS2 request- retry with SAS1",
			    __func__, srf->srf_result);
			goto again;
		}
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, NULL,
		    "%s: bad response 0x%x", __func__, srf->srf_result);
		result = -EINVAL;
	} else if (srgr->srgr_configuring) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, NULL,
		    "%s: expander at phy %s is still configuring",
		    __func__, pptr->path);
		result = 0;
	} else {
		result = srgr->srgr_number_of_phys;
		if (ival & 0xff00) {
			pptr->tolerates_sas2 = 1;
		}
		pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, pptr, NULL,
		    "%s has %d phys and %s SAS2", pptr->path, result,
		    pptr->tolerates_sas2? "tolerates" : "does not tolerate");
	}
out:
	return (result);
}

/*
 * Called with expander locked (and thus, pptr) as well as all PHYs up to
 * the root, and scratch acquired. Return 0 if we fail to allocate resources
 * or notice that the configuration changed while we were running the command.
 *
 * We return less than zero if we had an I/O error or received an
 * unsupported configuration.
 */
static int
pmcs_expander_content_discover(pmcs_hw_t *pwp, pmcs_phy_t *expander,
    pmcs_phy_t *pptr)
{
	struct pmcwork *pwrk;
	char buf[64];
	uint8_t sas_address[8];
	uint8_t att_sas_address[8];
	smp_response_frame_t *srf;
	smp_discover_resp_t *sdr;
	const uint_t rdoff = 0x100;	/* returned data offset */
	uint8_t *roff;
	uint32_t status, *ptr, msg[PMCS_MSG_SIZE], htag;
	int result;
	uint8_t	ini_support;
	uint8_t	tgt_support;

	pwrk = pmcs_gwork(pwp, PMCS_TAG_TYPE_WAIT, expander);
	if (pwrk == NULL) {
		result = 0;
		goto out;
	}
	(void) memset(pwp->scratch, 0x77, PMCS_SCRATCH_SIZE);
	pwrk->arg = pwp->scratch;
	pwrk->dtype = expander->dtype;
	msg[0] = LE_32(PMCS_HIPRI(pwp, PMCS_OQ_GENERAL, PMCIN_SMP_REQUEST));
	msg[1] = LE_32(pwrk->htag);
	msg[2] = LE_32(expander->device_id);
	msg[3] = LE_32((12 << SMP_REQUEST_LENGTH_SHIFT) |
	    SMP_INDIRECT_RESPONSE);
	/*
	 * Send SMP DISCOVER (of either SAS1.1 or SAS2 flavors).
	 */
	if (expander->tolerates_sas2) {
		msg[4] = BE_32(0x40101B00);
	} else {
		msg[4] = BE_32(0x40100000);
	}
	msg[5] = 0;
	msg[6] = BE_32((pptr->phynum << 16));
	msg[7] = 0;
	msg[8] = 0;
	msg[9] = 0;
	msg[10] = 0;
	msg[11] = 0;
	msg[12] = LE_32(DWORD0(pwp->scratch_dma+rdoff));
	msg[13] = LE_32(DWORD1(pwp->scratch_dma+rdoff));
	msg[14] = LE_32(PMCS_SCRATCH_SIZE - rdoff);
	msg[15] = 0;
	mutex_enter(&pwp->iqp_lock[PMCS_IQ_OTHER]);
	ptr = GET_IQ_ENTRY(pwp, PMCS_IQ_OTHER);
	if (ptr == NULL) {
		mutex_exit(&pwp->iqp_lock[PMCS_IQ_OTHER]);
		result = 0;
		goto out;
	}

	COPY_MESSAGE(ptr, msg, PMCS_MSG_SIZE);
	pwrk->state = PMCS_WORK_STATE_ONCHIP;
	htag = pwrk->htag;
	INC_IQ_ENTRY(pwp, PMCS_IQ_OTHER);

	/*
	 * Drop PHY lock while waiting so other completions aren't potentially
	 * blocked.
	 */
	pmcs_unlock_phy(expander);
	WAIT_FOR(pwrk, 1000, result);
	pmcs_lock_phy(expander);
	pmcs_pwork(pwp, pwrk);

	mutex_enter(&pwp->config_lock);
	if (pwp->config_changed) {
		RESTART_DISCOVERY_LOCKED(pwp);
		mutex_exit(&pwp->config_lock);
		result = 0;
		goto out;
	}
	mutex_exit(&pwp->config_lock);

	if (result) {
		pmcs_prt(pwp, PMCS_PRT_WARN, pptr, NULL, pmcs_timeo, __func__);
		if (pmcs_abort(pwp, expander, htag, 0, 0)) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, pptr, NULL,
			    "%s: Unable to issue SMP ABORT for htag 0x%08x",
			    __func__, htag);
		} else {
			pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, pptr, NULL,
			    "%s: Issuing SMP ABORT for htag 0x%08x",
			    __func__, htag);
		}
		result = -ETIMEDOUT;
		goto out;
	}
	ptr = (void *)pwp->scratch;
	/*
	 * Point roff to the DMA offset for returned data
	 */
	roff = pwp->scratch;
	roff += rdoff;
	srf = (smp_response_frame_t *)roff;
	sdr = (smp_discover_resp_t *)(roff+4);
	status = LE_32(ptr[2]);
	if (status == PMCOUT_STATUS_UNDERFLOW ||
	    status == PMCOUT_STATUS_OVERFLOW) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG_UNDERFLOW, pptr, NULL,
		    "%s: over/underflow", __func__);
		status = PMCOUT_STATUS_OK;
	}
	if (status != PMCOUT_STATUS_OK) {
		char *nag = NULL;
		(void) snprintf(buf, sizeof (buf),
		    "%s: SMP op failed (0x%x)", __func__, status);
		switch (status) {
		case PMCOUT_STATUS_ERROR_HW_TIMEOUT:
			DFM(nag, "Hardware Timeout");
			/* FALLTHROUGH */
		case PMCOUT_STATUS_ERROR_INTERNAL_SMP_RESOURCE:
			DFM(nag, "Internal SMP Resource Failure");
			/* FALLTHROUGH */
		case PMCOUT_STATUS_XFER_ERR_PHY_NOT_READY:
			DFM(nag, "PHY Not Ready");
			/* FALLTHROUGH */
		case PMCOUT_STATUS_OPEN_CNX_ERROR_CONNECTION_RATE_NOT_SUPPORTED:
			DFM(nag, "Connection Rate Not Supported");
			/* FALLTHROUGH */
		case PMCOUT_STATUS_IO_XFER_OPEN_RETRY_TIMEOUT:
			DFM(nag, "Open Retry Timeout");
			/* FALLTHROUGH */
		case PMCOUT_STATUS_SMP_RESP_CONNECTION_ERROR:
			DFM(nag, "Response Connection Error");
			pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, NULL,
			    "%s: expander %s SMP operation failed (%s)",
			    __func__, pptr->path, nag);
			break;
		default:
			pmcs_print_entry(pwp, PMCS_PRT_DEBUG, buf, ptr);
			result = -EIO;
			break;
		}
		goto out;
	} else if (srf->srf_frame_type != SMP_FRAME_TYPE_RESPONSE) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, NULL,
		    "%s: bad response frame type 0x%x",
		    __func__, srf->srf_frame_type);
		result = -EINVAL;
		goto out;
	} else if (srf->srf_function != SMP_FUNC_DISCOVER) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, NULL,
		    "%s: bad response function 0x%x",
		    __func__, srf->srf_function);
		result = -EINVAL;
		goto out;
	} else if (srf->srf_result != SMP_RES_FUNCTION_ACCEPTED) {
		result = pmcs_smp_function_result(pwp, srf);
		/* Need not fail if PHY is Vacant */
		if (result != SMP_RES_PHY_VACANT) {
			result = -EINVAL;
			goto out;
		}
	}

	ini_support = (sdr->sdr_attached_sata_host |
	    (sdr->sdr_attached_smp_initiator << 1) |
	    (sdr->sdr_attached_stp_initiator << 2) |
	    (sdr->sdr_attached_ssp_initiator << 3));

	tgt_support = (sdr->sdr_attached_sata_device |
	    (sdr->sdr_attached_smp_target << 1) |
	    (sdr->sdr_attached_stp_target << 2) |
	    (sdr->sdr_attached_ssp_target << 3));

	pmcs_wwn2barray(BE_64(sdr->sdr_sas_addr), sas_address);
	pmcs_wwn2barray(BE_64(sdr->sdr_attached_sas_addr), att_sas_address);

	switch (sdr->sdr_attached_device_type) {
	case SAS_IF_DTYPE_ENDPOINT:
		pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, pptr, NULL,
		    "exp_content: %s atdt=0x%x lr=%x is=%x ts=%x SAS="
		    SAS_ADDR_FMT " attSAS=" SAS_ADDR_FMT " atPHY=%x",
		    pptr->path,
		    sdr->sdr_attached_device_type,
		    sdr->sdr_negotiated_logical_link_rate,
		    ini_support,
		    tgt_support,
		    SAS_ADDR_PRT(sas_address),
		    SAS_ADDR_PRT(att_sas_address),
		    sdr->sdr_attached_phy_identifier);

		if (sdr->sdr_attached_sata_device ||
		    sdr->sdr_attached_stp_target) {
			pptr->dtype = SATA;
		} else if (sdr->sdr_attached_ssp_target) {
			pptr->dtype = SAS;
		} else if (tgt_support || ini_support) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, pptr, NULL,
			    "%s: %s has tgt support=%x init support=(%x)",
			    __func__, pptr->path, tgt_support, ini_support);
		}
		break;
	case SAS_IF_DTYPE_EDGE:
	case SAS_IF_DTYPE_FANOUT:
		pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, pptr, NULL,
		    "exp_content: %s atdt=0x%x lr=%x is=%x ts=%x SAS="
		    SAS_ADDR_FMT " attSAS=" SAS_ADDR_FMT " atPHY=%x",
		    pptr->path,
		    sdr->sdr_attached_device_type,
		    sdr->sdr_negotiated_logical_link_rate,
		    ini_support,
		    tgt_support,
		    SAS_ADDR_PRT(sas_address),
		    SAS_ADDR_PRT(att_sas_address),
		    sdr->sdr_attached_phy_identifier);
		if (sdr->sdr_attached_smp_target) {
			/*
			 * Avoid configuring phys that just point back
			 * at a parent phy
			 */
			if (expander->parent &&
			    memcmp(expander->parent->sas_address,
			    att_sas_address,
			    sizeof (expander->parent->sas_address)) == 0) {
				pmcs_prt(pwp, PMCS_PRT_DEBUG3, pptr, NULL,
				    "%s: skipping port back to parent "
				    "expander (%s)", __func__, pptr->path);
				pptr->dtype = NOTHING;
				break;
			}
			pptr->dtype = EXPANDER;

		} else if (tgt_support || ini_support) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, pptr, NULL,
			    "%s has tgt support=%x init support=(%x)",
			    pptr->path, tgt_support, ini_support);
			pptr->dtype = EXPANDER;
		}
		break;
	default:
		pptr->dtype = NOTHING;
		break;
	}
	if (pptr->dtype != NOTHING) {
		pmcs_phy_t *ctmp;

		/*
		 * If the attached device is a SATA device and the expander
		 * is (possibly) a SAS2 compliant expander, check for whether
		 * there is a NAA=5 WWN field starting at this offset and
		 * use that for the SAS Address for this device.
		 */
		if (expander->tolerates_sas2 && pptr->dtype == SATA &&
		    (roff[SAS_ATTACHED_NAME_OFFSET] >> 8) == 0x5) {
			(void) memcpy(pptr->sas_address,
			    &roff[SAS_ATTACHED_NAME_OFFSET], 8);
		} else {
			(void) memcpy(pptr->sas_address, att_sas_address, 8);
		}
		pptr->atdt = (sdr->sdr_attached_device_type);
		/*
		 * Now run up from the expander's parent up to the top to
		 * make sure we only use the least common link_rate.
		 */
		for (ctmp = expander->parent; ctmp; ctmp = ctmp->parent) {
			if (ctmp->link_rate <
			    sdr->sdr_negotiated_logical_link_rate) {
				pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, pptr, NULL,
				    "%s: derating link rate from %x to %x due "
				    "to %s being slower", pptr->path,
				    sdr->sdr_negotiated_logical_link_rate,
				    ctmp->link_rate,
				    ctmp->path);
				sdr->sdr_negotiated_logical_link_rate =
				    ctmp->link_rate;
			}
		}
		pptr->link_rate = sdr->sdr_negotiated_logical_link_rate;
		pptr->state.prog_min_rate = sdr->sdr_prog_min_phys_link_rate;
		pptr->state.hw_min_rate = sdr->sdr_hw_min_phys_link_rate;
		pptr->state.prog_max_rate = sdr->sdr_prog_max_phys_link_rate;
		pptr->state.hw_max_rate = sdr->sdr_hw_max_phys_link_rate;
		PHY_CHANGED(pwp, pptr);
	} else {
		pmcs_clear_phy(pwp, pptr);
	}
	result = 1;
out:
	return (result);
}

/*
 * Get a work structure and assign it a tag with type and serial number
 * If a structure is returned, it is returned locked.
 */
pmcwork_t *
pmcs_gwork(pmcs_hw_t *pwp, uint32_t tag_type, pmcs_phy_t *phyp)
{
	pmcwork_t *p;
	uint16_t snum;
	uint32_t off;

	mutex_enter(&pwp->wfree_lock);
	p = STAILQ_FIRST(&pwp->wf);
	if (p == NULL) {
		/*
		 * If we couldn't get a work structure, it's time to bite
		 * the bullet, grab the pfree_lock and copy over all the
		 * work structures from the pending free list to the actual
		 * free list.  This shouldn't happen all that often.
		 */
		mutex_enter(&pwp->pfree_lock);
		pwp->wf.stqh_first = pwp->pf.stqh_first;
		pwp->wf.stqh_last = pwp->pf.stqh_last;
		STAILQ_INIT(&pwp->pf);
		mutex_exit(&pwp->pfree_lock);

		p = STAILQ_FIRST(&pwp->wf);
		if (p == NULL) {
			mutex_exit(&pwp->wfree_lock);
			return (NULL);
		}
	}
	STAILQ_REMOVE(&pwp->wf, p, pmcwork, next);
	snum = pwp->wserno++;
	mutex_exit(&pwp->wfree_lock);

	off = p - pwp->work;

	mutex_enter(&p->lock);
	ASSERT(p->state == PMCS_WORK_STATE_NIL);
	ASSERT(p->htag == PMCS_TAG_FREE);
	p->htag = (tag_type << PMCS_TAG_TYPE_SHIFT) & PMCS_TAG_TYPE_MASK;
	p->htag |= ((snum << PMCS_TAG_SERNO_SHIFT) & PMCS_TAG_SERNO_MASK);
	p->htag |= ((off << PMCS_TAG_INDEX_SHIFT) & PMCS_TAG_INDEX_MASK);
	p->start = gethrtime();
	p->state = PMCS_WORK_STATE_READY;
	p->ssp_event = 0;
	p->dead = 0;

	if (phyp) {
		p->phy = phyp;
		pmcs_inc_phy_ref_count(phyp);
	}

	return (p);
}

/*
 * Called with pwrk lock held.  Returned with lock released.
 */
void
pmcs_pwork(pmcs_hw_t *pwp, pmcwork_t *p)
{
	ASSERT(p != NULL);
	ASSERT(mutex_owned(&p->lock));

	p->last_ptr = p->ptr;
	p->last_arg = p->arg;
	p->last_phy = p->phy;
	p->last_xp = p->xp;
	p->last_htag = p->htag;
	p->last_state = p->state;
	p->finish = gethrtime();

	if (p->phy) {
		pmcs_dec_phy_ref_count(p->phy);
	}

	p->state = PMCS_WORK_STATE_NIL;
	p->htag = PMCS_TAG_FREE;
	p->xp = NULL;
	p->ptr = NULL;
	p->arg = NULL;
	p->phy = NULL;
	p->abt_htag = 0;
	p->timer = 0;
	mutex_exit(&p->lock);

	if (mutex_tryenter(&pwp->wfree_lock) == 0) {
		mutex_enter(&pwp->pfree_lock);
		STAILQ_INSERT_TAIL(&pwp->pf, p, next);
		mutex_exit(&pwp->pfree_lock);
	} else {
		STAILQ_INSERT_TAIL(&pwp->wf, p, next);
		mutex_exit(&pwp->wfree_lock);
	}
}

/*
 * Find a work structure based upon a tag and make sure that the tag
 * serial number matches the work structure we've found.
 * If a structure is found, its lock is held upon return.
 */
pmcwork_t *
pmcs_tag2wp(pmcs_hw_t *pwp, uint32_t htag)
{
	pmcwork_t *p;
	uint32_t idx = PMCS_TAG_INDEX(htag);

	p = &pwp->work[idx];

	mutex_enter(&p->lock);
	if (p->htag == htag) {
		return (p);
	}
	mutex_exit(&p->lock);
	pmcs_prt(pwp, PMCS_PRT_DEBUG2, NULL, NULL,
	    "INDEX 0x%x HTAG 0x%x got p->htag 0x%x", idx, htag, p->htag);
	return (NULL);
}

/*
 * Issue an abort for a command or for all commands.
 *
 * Since this can be called from interrupt context,
 * we don't wait for completion if wait is not set.
 *
 * Called with PHY lock held.
 */
int
pmcs_abort(pmcs_hw_t *pwp, pmcs_phy_t *pptr, uint32_t tag, int all_cmds,
    int wait)
{
	pmcwork_t *pwrk;
	pmcs_xscsi_t *tgt;
	uint32_t msg[PMCS_MSG_SIZE], *ptr;
	int result, abt_type;
	uint32_t abt_htag, status;

	if (pptr->abort_all_start) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, NULL, "%s: ABORT_ALL for "
		    "(%s) already in progress.", __func__, pptr->path);
		return (EBUSY);
	}

	switch (pptr->dtype) {
	case SAS:
		abt_type = PMCIN_SSP_ABORT;
		break;
	case SATA:
		abt_type = PMCIN_SATA_ABORT;
		break;
	case EXPANDER:
		abt_type = PMCIN_SMP_ABORT;
		break;
	default:
		return (0);
	}

	pwrk = pmcs_gwork(pwp, wait ? PMCS_TAG_TYPE_WAIT : PMCS_TAG_TYPE_NONE,
	    pptr);

	if (pwrk == NULL) {
		pmcs_prt(pwp, PMCS_PRT_ERR, pptr, NULL, pmcs_nowrk, __func__);
		return (ENOMEM);
	}

	pwrk->dtype = pptr->dtype;
	if (wait) {
		pwrk->arg = msg;
	}
	if (pptr->valid_device_id == 0) {
		pmcs_pwork(pwp, pwrk);
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, NULL,
		    "%s: Invalid DeviceID", __func__);
		return (ENODEV);
	}
	msg[0] = LE_32(PMCS_HIPRI(pwp, PMCS_OQ_GENERAL, abt_type));
	msg[1] = LE_32(pwrk->htag);
	msg[2] = LE_32(pptr->device_id);
	if (all_cmds) {
		msg[3] = 0;
		msg[4] = LE_32(1);
		pwrk->ptr = NULL;
		pptr->abort_all_start = gethrtime();
	} else {
		msg[3] = LE_32(tag);
		msg[4] = 0;
		pwrk->abt_htag = tag;
	}
	mutex_enter(&pwp->iqp_lock[PMCS_IQ_OTHER]);
	ptr = GET_IQ_ENTRY(pwp, PMCS_IQ_OTHER);
	if (ptr == NULL) {
		mutex_exit(&pwp->iqp_lock[PMCS_IQ_OTHER]);
		pmcs_pwork(pwp, pwrk);
		pmcs_prt(pwp, PMCS_PRT_ERR, pptr, NULL, pmcs_nomsg, __func__);
		return (ENOMEM);
	}

	COPY_MESSAGE(ptr, msg, 5);
	if (all_cmds) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, NULL,
		    "%s: aborting all commands for %s device %s. (htag=0x%x)",
		    __func__, pmcs_get_typename(pptr->dtype), pptr->path,
		    msg[1]);
	} else {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, NULL,
		    "%s: aborting tag 0x%x for %s device %s. (htag=0x%x)",
		    __func__, tag, pmcs_get_typename(pptr->dtype), pptr->path,
		    msg[1]);
	}
	pwrk->state = PMCS_WORK_STATE_ONCHIP;

	INC_IQ_ENTRY(pwp, PMCS_IQ_OTHER);
	if (!wait) {
		mutex_exit(&pwrk->lock);
		return (0);
	}

	abt_htag = pwrk->htag;
	pmcs_unlock_phy(pwrk->phy);
	WAIT_FOR(pwrk, 1000, result);
	pmcs_lock_phy(pwrk->phy);

	tgt = pwrk->xp;
	pmcs_pwork(pwp, pwrk);

	if (tgt != NULL) {
		mutex_enter(&tgt->aqlock);
		if (!STAILQ_EMPTY(&tgt->aq)) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, tgt,
			    "%s: Abort complete (result=0x%x), but "
			    "aq not empty (tgt 0x%p), waiting",
			    __func__, result, (void *)tgt);
			cv_wait(&tgt->abort_cv, &tgt->aqlock);
		}
		mutex_exit(&tgt->aqlock);
	}

	if (all_cmds) {
		pptr->abort_all_start = 0;
		cv_signal(&pptr->abort_all_cv);
	}

	if (result) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, tgt,
		    "%s: Abort (htag 0x%08x) request timed out",
		    __func__, abt_htag);
		if (tgt != NULL) {
			mutex_enter(&tgt->statlock);
			if ((tgt->dev_state != PMCS_DEVICE_STATE_IN_RECOVERY) &&
			    (tgt->dev_state !=
			    PMCS_DEVICE_STATE_NON_OPERATIONAL)) {
				pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, tgt,
				    "%s: Trying DS error recovery for tgt 0x%p",
				    __func__, (void *)tgt);
				(void) pmcs_send_err_recovery_cmd(pwp,
				    PMCS_DEVICE_STATE_IN_RECOVERY, tgt);
			}
			mutex_exit(&tgt->statlock);
		}
		return (ETIMEDOUT);
	}

	status = LE_32(msg[2]);
	if (status != PMCOUT_STATUS_OK) {
		/*
		 * The only non-success status are IO_NOT_VALID &
		 * IO_ABORT_IN_PROGRESS.
		 * In case of IO_ABORT_IN_PROGRESS, the other ABORT cmd's
		 * status is of concern and this duplicate cmd status can
		 * be ignored.
		 * If IO_NOT_VALID, that's not an error per-se.
		 * For abort of single I/O complete the command anyway.
		 * If, however, we were aborting all, that is a problem
		 * as IO_NOT_VALID really means that the IO or device is
		 * not there. So, discovery process will take of the cleanup.
		 */
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, tgt,
		    "%s: abort result 0x%x", __func__, LE_32(msg[2]));
		if (all_cmds) {
			PHY_CHANGED(pwp, pptr);
			RESTART_DISCOVERY(pwp);
		} else {
			return (EINVAL);
		}

		return (0);
	}

	if (tgt != NULL) {
		mutex_enter(&tgt->statlock);
		if (tgt->dev_state == PMCS_DEVICE_STATE_IN_RECOVERY) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, tgt,
			    "%s: Restoring OPERATIONAL dev_state for tgt 0x%p",
			    __func__, (void *)tgt);
			(void) pmcs_send_err_recovery_cmd(pwp,
			    PMCS_DEVICE_STATE_OPERATIONAL, tgt);
		}
		mutex_exit(&tgt->statlock);
	}

	return (0);
}

/*
 * Issue a task management function to an SSP device.
 *
 * Called with PHY lock held.
 * statlock CANNOT be held upon entry.
 */
int
pmcs_ssp_tmf(pmcs_hw_t *pwp, pmcs_phy_t *pptr, uint8_t tmf, uint32_t tag,
    uint64_t lun, uint32_t *response)
{
	int result, ds;
	uint8_t local[PMCS_QENTRY_SIZE << 1], *xd;
	sas_ssp_rsp_iu_t *rptr = (void *)local;
	static const uint8_t ssp_rsp_evec[] = {
		0x58, 0x61, 0x56, 0x72, 0x00
	};
	uint32_t msg[PMCS_MSG_SIZE], *ptr, status;
	struct pmcwork *pwrk;
	pmcs_xscsi_t *xp;

	pwrk = pmcs_gwork(pwp, PMCS_TAG_TYPE_WAIT, pptr);
	if (pwrk == NULL) {
		pmcs_prt(pwp, PMCS_PRT_ERR, pptr, NULL, pmcs_nowrk, __func__);
		return (ENOMEM);
	}
	/*
	 * NB: We use the PMCS_OQ_GENERAL outbound queue
	 * NB: so as to not get entangled in normal I/O
	 * NB: processing.
	 */
	msg[0] = LE_32(PMCS_HIPRI(pwp, PMCS_OQ_GENERAL,
	    PMCIN_SSP_INI_TM_START));
	msg[1] = LE_32(pwrk->htag);
	msg[2] = LE_32(pptr->device_id);
	if (tmf == SAS_ABORT_TASK || tmf == SAS_QUERY_TASK) {
		msg[3] = LE_32(tag);
	} else {
		msg[3] = 0;
	}
	msg[4] = LE_32(tmf);
	msg[5] = BE_32((uint32_t)lun);
	msg[6] = BE_32((uint32_t)(lun >> 32));
	msg[7] = LE_32(PMCIN_MESSAGE_REPORT);

	mutex_enter(&pwp->iqp_lock[PMCS_IQ_OTHER]);
	ptr = GET_IQ_ENTRY(pwp, PMCS_IQ_OTHER);
	if (ptr == NULL) {
		mutex_exit(&pwp->iqp_lock[PMCS_IQ_OTHER]);
		pmcs_pwork(pwp, pwrk);
		pmcs_prt(pwp, PMCS_PRT_ERR, pptr, NULL, pmcs_nomsg, __func__);
		return (ENOMEM);
	}
	COPY_MESSAGE(ptr, msg, 7);
	pwrk->arg = msg;
	pwrk->dtype = pptr->dtype;

	xp = pptr->target;
	if (xp != NULL) {
		mutex_enter(&xp->statlock);
		if (xp->dev_state == PMCS_DEVICE_STATE_NON_OPERATIONAL) {
			mutex_exit(&xp->statlock);
			mutex_exit(&pwp->iqp_lock[PMCS_IQ_OTHER]);
			pmcs_pwork(pwp, pwrk);
			pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, xp, "%s: Not "
			    "sending '%s' because DS is '%s'", __func__,
			    pmcs_tmf2str(tmf), pmcs_status_str
			    (PMCOUT_STATUS_IO_DS_NON_OPERATIONAL));
			return (EIO);
		}
		mutex_exit(&xp->statlock);
	}

	pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, xp,
	    "%s: sending '%s' to %s (lun %llu) tag 0x%x", __func__,
	    pmcs_tmf2str(tmf), pptr->path, (unsigned long long) lun, tag);
	pwrk->state = PMCS_WORK_STATE_ONCHIP;
	INC_IQ_ENTRY(pwp, PMCS_IQ_OTHER);

	pmcs_unlock_phy(pptr);
	/*
	 * This is a command sent to the target device, so it can take
	 * significant amount of time to complete when path & device is busy.
	 * Set a timeout to 20 seconds
	 */
	WAIT_FOR(pwrk, 20000, result);
	pmcs_lock_phy(pptr);
	pmcs_pwork(pwp, pwrk);

	if (result) {
		if (xp == NULL) {
			return (ETIMEDOUT);
		}

		mutex_enter(&xp->statlock);
		pmcs_start_dev_state_recovery(xp, pptr);
		mutex_exit(&xp->statlock);
		return (ETIMEDOUT);
	}

	status = LE_32(msg[2]);
	if (status != PMCOUT_STATUS_OK) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, xp,
		    "%s: status %s for TMF %s action to %s, lun %llu",
		    __func__, pmcs_status_str(status),  pmcs_tmf2str(tmf),
		    pptr->path, (unsigned long long) lun);
		if ((status == PMCOUT_STATUS_IO_DS_NON_OPERATIONAL) ||
		    (status == PMCOUT_STATUS_OPEN_CNX_ERROR_BREAK) ||
		    (status == PMCOUT_STATUS_OPEN_CNX_ERROR_IT_NEXUS_LOSS)) {
			ds = PMCS_DEVICE_STATE_NON_OPERATIONAL;
		} else if (status == PMCOUT_STATUS_IO_DS_IN_RECOVERY) {
			/*
			 * If the status is IN_RECOVERY, it's an indication
			 * that it's now time for us to request to have the
			 * device state set to OPERATIONAL since we're the ones
			 * that requested recovery to begin with.
			 */
			ds = PMCS_DEVICE_STATE_OPERATIONAL;
		} else {
			ds = PMCS_DEVICE_STATE_IN_RECOVERY;
		}
		if (xp != NULL) {
			mutex_enter(&xp->statlock);
			if (xp->dev_state != ds) {
				pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, xp,
				    "%s: Sending err recovery cmd"
				    " for tgt 0x%p (status = %s)",
				    __func__, (void *)xp,
				    pmcs_status_str(status));
				(void) pmcs_send_err_recovery_cmd(pwp, ds, xp);
			}
			mutex_exit(&xp->statlock);
		}
		return (EIO);
	} else {
		ds = PMCS_DEVICE_STATE_OPERATIONAL;
		if (xp != NULL) {
			mutex_enter(&xp->statlock);
			if (xp->dev_state != ds) {
				pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, xp,
				    "%s: Sending err recovery cmd"
				    " for tgt 0x%p (status = %s)",
				    __func__, (void *)xp,
				    pmcs_status_str(status));
				(void) pmcs_send_err_recovery_cmd(pwp, ds, xp);
			}
			mutex_exit(&xp->statlock);
		}
	}
	if (LE_32(msg[3]) == 0) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, xp,
		    "TMF completed with no response");
		return (EIO);
	}
	pmcs_endian_transform(pwp, local, &msg[5], ssp_rsp_evec);
	xd = (uint8_t *)(&msg[5]);
	xd += SAS_RSP_HDR_SIZE;
	if (rptr->datapres != SAS_RSP_DATAPRES_RESPONSE_DATA) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, xp,
		    "%s: TMF response not RESPONSE DATA (0x%x)",
		    __func__, rptr->datapres);
		return (EIO);
	}
	if (rptr->response_data_length != 4) {
		pmcs_print_entry(pwp, PMCS_PRT_DEBUG,
		    "Bad SAS RESPONSE DATA LENGTH", msg);
		return (EIO);
	}
	(void) memcpy(&status, xd, sizeof (uint32_t));
	status = BE_32(status);
	if (response != NULL)
		*response = status;
	/*
	 * The status is actually in the low-order byte.  The upper three
	 * bytes contain additional information for the TMFs that support them.
	 * However, at this time we do not issue any of those.  In the other
	 * cases, the upper three bytes are supposed to be 0, but it appears
	 * they aren't always.  Just mask them off.
	 */
	switch (status & 0xff) {
	case SAS_RSP_TMF_COMPLETE:
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, xp,
		    "%s: TMF complete", __func__);
		result = 0;
		break;
	case SAS_RSP_TMF_SUCCEEDED:
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, xp,
		    "%s: TMF succeeded", __func__);
		result = 0;
		break;
	case SAS_RSP_INVALID_FRAME:
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, xp,
		    "%s: TMF returned INVALID FRAME", __func__);
		result = EIO;
		break;
	case SAS_RSP_TMF_NOT_SUPPORTED:
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, xp,
		    "%s: TMF returned TMF NOT SUPPORTED", __func__);
		result = EIO;
		break;
	case SAS_RSP_TMF_FAILED:
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, xp,
		    "%s: TMF returned TMF FAILED", __func__);
		result = EIO;
		break;
	case SAS_RSP_TMF_INCORRECT_LUN:
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, xp,
		    "%s: TMF returned INCORRECT LUN", __func__);
		result = EIO;
		break;
	case SAS_RSP_OVERLAPPED_OIPTTA:
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, xp,
		    "%s: TMF returned OVERLAPPED INITIATOR PORT TRANSFER TAG "
		    "ATTEMPTED", __func__);
		result = EIO;
		break;
	default:
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, xp,
		    "%s: TMF returned unknown code 0x%x", __func__, status);
		result = EIO;
		break;
	}
	return (result);
}

/*
 * Called with PHY lock held and scratch acquired
 */
int
pmcs_sata_abort_ncq(pmcs_hw_t *pwp, pmcs_phy_t *pptr)
{
	const char *utag_fail_fmt = "%s: untagged NCQ command failure";
	const char *tag_fail_fmt = "%s: NCQ command failure (tag 0x%x)";
	uint32_t msg[PMCS_QENTRY_SIZE], *ptr, result, status;
	uint8_t *fp = pwp->scratch, ds;
	fis_t fis;
	pmcwork_t *pwrk;
	pmcs_xscsi_t *tgt;

	pwrk = pmcs_gwork(pwp, PMCS_TAG_TYPE_WAIT, pptr);
	if (pwrk == NULL) {
		return (ENOMEM);
	}
	msg[0] = LE_32(PMCS_IOMB_IN_SAS(PMCS_OQ_IODONE,
	    PMCIN_SATA_HOST_IO_START));
	msg[1] = LE_32(pwrk->htag);
	msg[2] = LE_32(pptr->device_id);
	msg[3] = LE_32(512);
	msg[4] = LE_32(SATA_PROTOCOL_PIO | PMCIN_DATADIR_2_INI);
	msg[5] = LE_32((READ_LOG_EXT << 16) | (C_BIT << 8) | FIS_REG_H2DEV);
	msg[6] = LE_32(0x10);
	msg[8] = LE_32(1);
	msg[9] = 0;
	msg[10] = 0;
	msg[11] = 0;
	msg[12] = LE_32(DWORD0(pwp->scratch_dma));
	msg[13] = LE_32(DWORD1(pwp->scratch_dma));
	msg[14] = LE_32(512);
	msg[15] = 0;

	pwrk->arg = msg;
	pwrk->dtype = pptr->dtype;

	mutex_enter(&pwp->iqp_lock[PMCS_IQ_OTHER]);
	ptr = GET_IQ_ENTRY(pwp, PMCS_IQ_OTHER);
	if (ptr == NULL) {
		mutex_exit(&pwp->iqp_lock[PMCS_IQ_OTHER]);
		pmcs_pwork(pwp, pwrk);
		return (ENOMEM);
	}
	COPY_MESSAGE(ptr, msg, PMCS_QENTRY_SIZE);
	pwrk->state = PMCS_WORK_STATE_ONCHIP;
	INC_IQ_ENTRY(pwp, PMCS_IQ_OTHER);

	pmcs_unlock_phy(pptr);
	WAIT_FOR(pwrk, 250, result);
	pmcs_lock_phy(pptr);
	pmcs_pwork(pwp, pwrk);

	tgt = pptr->target;
	if (result) {
		pmcs_prt(pwp, PMCS_PRT_INFO, pptr, tgt, pmcs_timeo, __func__);
		return (EIO);
	}
	status = LE_32(msg[2]);
	if (status != PMCOUT_STATUS_OK || LE_32(msg[3])) {
		if (tgt == NULL) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, tgt,
			    "%s: cannot find target for phy 0x%p for "
			    "dev state recovery", __func__, (void *)pptr);
			return (EIO);
		}

		mutex_enter(&tgt->statlock);

		pmcs_print_entry(pwp, PMCS_PRT_DEBUG, "READ LOG EXT", msg);
		if ((status == PMCOUT_STATUS_IO_DS_NON_OPERATIONAL) ||
		    (status == PMCOUT_STATUS_OPEN_CNX_ERROR_BREAK) ||
		    (status == PMCOUT_STATUS_OPEN_CNX_ERROR_IT_NEXUS_LOSS)) {
			ds = PMCS_DEVICE_STATE_NON_OPERATIONAL;
		} else {
			ds = PMCS_DEVICE_STATE_IN_RECOVERY;
		}
		if (tgt->dev_state != ds) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, tgt, "%s: Trying "
			    "SATA DS Recovery for tgt(0x%p) for status(%s)",
			    __func__, (void *)tgt, pmcs_status_str(status));
			(void) pmcs_send_err_recovery_cmd(pwp, ds, tgt);
		}

		mutex_exit(&tgt->statlock);
		return (EIO);
	}
	fis[0] = (fp[4] << 24) | (fp[3] << 16) | (fp[2] << 8) | FIS_REG_D2H;
	fis[1] = (fp[8] << 24) | (fp[7] << 16) | (fp[6] << 8) | fp[5];
	fis[2] = (fp[12] << 24) | (fp[11] << 16) | (fp[10] << 8) | fp[9];
	fis[3] = (fp[16] << 24) | (fp[15] << 16) | (fp[14] << 8) | fp[13];
	fis[4] = 0;
	if (fp[0] & 0x80) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, tgt,
		    utag_fail_fmt, __func__);
	} else {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, tgt,
		    tag_fail_fmt, __func__, fp[0] & 0x1f);
	}
	pmcs_fis_dump(pwp, fis);
	pptr->need_rl_ext = 0;
	return (0);
}

/*
 * Transform a structure from CPU to Device endian format, or
 * vice versa, based upon a transformation vector.
 *
 * A transformation vector is an array of bytes, each byte
 * of which is defined thusly:
 *
 *  bit 7: from CPU to desired endian, otherwise from desired endian
 *	   to CPU format
 *  bit 6: Big Endian, else Little Endian
 *  bits 5-4:
 *       00 Undefined
 *       01 One Byte quantities
 *       02 Two Byte quantities
 *       03 Four Byte quantities
 *
 *  bits 3-0:
 *       00 Undefined
 *       Number of quantities to transform
 *
 * The vector is terminated by a 0 value.
 */

void
pmcs_endian_transform(pmcs_hw_t *pwp, void *orig_out, void *orig_in,
    const uint8_t *xfvec)
{
	uint8_t c, *out = orig_out, *in = orig_in;

	if (xfvec == NULL) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: null xfvec", __func__);
		return;
	}
	if (out == NULL) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: null out", __func__);
		return;
	}
	if (in == NULL) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: null in", __func__);
		return;
	}
	while ((c = *xfvec++) != 0) {
		int nbyt = (c & 0xf);
		int size = (c >> 4) & 0x3;
		int bige = (c >> 4) & 0x4;

		switch (size) {
		case 1:
		{
			while (nbyt-- > 0) {
				*out++ = *in++;
			}
			break;
		}
		case 2:
		{
			uint16_t tmp;
			while (nbyt-- > 0) {
				(void) memcpy(&tmp, in, sizeof (uint16_t));
				if (bige) {
					tmp = BE_16(tmp);
				} else {
					tmp = LE_16(tmp);
				}
				(void) memcpy(out, &tmp, sizeof (uint16_t));
				out += sizeof (uint16_t);
				in += sizeof (uint16_t);
			}
			break;
		}
		case 3:
		{
			uint32_t tmp;
			while (nbyt-- > 0) {
				(void) memcpy(&tmp, in, sizeof (uint32_t));
				if (bige) {
					tmp = BE_32(tmp);
				} else {
					tmp = LE_32(tmp);
				}
				(void) memcpy(out, &tmp, sizeof (uint32_t));
				out += sizeof (uint32_t);
				in += sizeof (uint32_t);
			}
			break;
		}
		default:
			pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
			    "%s: bad size", __func__);
			return;
		}
	}
}

const char *
pmcs_get_rate(unsigned int linkrt)
{
	const char *rate;
	switch (linkrt) {
	case SAS_LINK_RATE_1_5GBIT:
		rate = "1.5";
		break;
	case SAS_LINK_RATE_3GBIT:
		rate = "3.0";
		break;
	case SAS_LINK_RATE_6GBIT:
		rate = "6.0";
		break;
	default:
		rate = "???";
		break;
	}
	return (rate);
}

const char *
pmcs_get_typename(pmcs_dtype_t type)
{
	switch (type) {
	case NOTHING:
		return ("NIL");
	case SATA:
		return ("SATA");
	case SAS:
		return ("SSP");
	case EXPANDER:
		return ("EXPANDER");
	}
	return ("????");
}

const char *
pmcs_tmf2str(int tmf)
{
	switch (tmf) {
	case SAS_ABORT_TASK:
		return ("Abort Task");
	case SAS_ABORT_TASK_SET:
		return ("Abort Task Set");
	case SAS_CLEAR_TASK_SET:
		return ("Clear Task Set");
	case SAS_LOGICAL_UNIT_RESET:
		return ("Logical Unit Reset");
	case SAS_I_T_NEXUS_RESET:
		return ("I_T Nexus Reset");
	case SAS_CLEAR_ACA:
		return ("Clear ACA");
	case SAS_QUERY_TASK:
		return ("Query Task");
	case SAS_QUERY_TASK_SET:
		return ("Query Task Set");
	case SAS_QUERY_UNIT_ATTENTION:
		return ("Query Unit Attention");
	default:
		return ("Unknown");
	}
}

const char *
pmcs_status_str(uint32_t status)
{
	switch (status) {
	case PMCOUT_STATUS_OK:
		return ("OK");
	case PMCOUT_STATUS_ABORTED:
		return ("ABORTED");
	case PMCOUT_STATUS_OVERFLOW:
		return ("OVERFLOW");
	case PMCOUT_STATUS_UNDERFLOW:
		return ("UNDERFLOW");
	case PMCOUT_STATUS_FAILED:
		return ("FAILED");
	case PMCOUT_STATUS_ABORT_RESET:
		return ("ABORT_RESET");
	case PMCOUT_STATUS_IO_NOT_VALID:
		return ("IO_NOT_VALID");
	case PMCOUT_STATUS_NO_DEVICE:
		return ("NO_DEVICE");
	case PMCOUT_STATUS_ILLEGAL_PARAMETER:
		return ("ILLEGAL_PARAMETER");
	case PMCOUT_STATUS_LINK_FAILURE:
		return ("LINK_FAILURE");
	case PMCOUT_STATUS_PROG_ERROR:
		return ("PROG_ERROR");
	case PMCOUT_STATUS_EDC_IN_ERROR:
		return ("EDC_IN_ERROR");
	case PMCOUT_STATUS_EDC_OUT_ERROR:
		return ("EDC_OUT_ERROR");
	case PMCOUT_STATUS_ERROR_HW_TIMEOUT:
		return ("ERROR_HW_TIMEOUT");
	case PMCOUT_STATUS_XFER_ERR_BREAK:
		return ("XFER_ERR_BREAK");
	case PMCOUT_STATUS_XFER_ERR_PHY_NOT_READY:
		return ("XFER_ERR_PHY_NOT_READY");
	case PMCOUT_STATUS_OPEN_CNX_PROTOCOL_NOT_SUPPORTED:
		return ("OPEN_CNX_PROTOCOL_NOT_SUPPORTED");
	case PMCOUT_STATUS_OPEN_CNX_ERROR_ZONE_VIOLATION:
		return ("OPEN_CNX_ERROR_ZONE_VIOLATION");
	case PMCOUT_STATUS_OPEN_CNX_ERROR_BREAK:
		return ("OPEN_CNX_ERROR_BREAK");
	case PMCOUT_STATUS_OPEN_CNX_ERROR_IT_NEXUS_LOSS:
		return ("OPEN_CNX_ERROR_IT_NEXUS_LOSS");
	case PMCOUT_STATUS_OPENCNX_ERROR_BAD_DESTINATION:
		return ("OPENCNX_ERROR_BAD_DESTINATION");
	case PMCOUT_STATUS_OPEN_CNX_ERROR_CONNECTION_RATE_NOT_SUPPORTED:
		return ("OPEN_CNX_ERROR_CONNECTION_RATE_NOT_SUPPORTED");
	case PMCOUT_STATUS_OPEN_CNX_ERROR_STP_RESOURCES_BUSY:
		return ("OPEN_CNX_ERROR_STP_RESOURCES_BUSY");
	case PMCOUT_STATUS_OPEN_CNX_ERROR_WRONG_DESTINATION:
		return ("OPEN_CNX_ERROR_WRONG_DESTINATION");
	case PMCOUT_STATUS_OPEN_CNX_ERROR_UNKNOWN_EROOR:
		return ("OPEN_CNX_ERROR_UNKNOWN_EROOR");
	case PMCOUT_STATUS_IO_XFER_ERROR_NAK_RECEIVED:
		return ("IO_XFER_ERROR_NAK_RECEIVED");
	case PMCOUT_STATUS_XFER_ERROR_ACK_NAK_TIMEOUT:
		return ("XFER_ERROR_ACK_NAK_TIMEOUT");
	case PMCOUT_STATUS_XFER_ERROR_PEER_ABORTED:
		return ("XFER_ERROR_PEER_ABORTED");
	case PMCOUT_STATUS_XFER_ERROR_RX_FRAME:
		return ("XFER_ERROR_RX_FRAME");
	case PMCOUT_STATUS_IO_XFER_ERROR_DMA:
		return ("IO_XFER_ERROR_DMA");
	case PMCOUT_STATUS_XFER_ERROR_CREDIT_TIMEOUT:
		return ("XFER_ERROR_CREDIT_TIMEOUT");
	case PMCOUT_STATUS_XFER_ERROR_SATA_LINK_TIMEOUT:
		return ("XFER_ERROR_SATA_LINK_TIMEOUT");
	case PMCOUT_STATUS_XFER_ERROR_SATA:
		return ("XFER_ERROR_SATA");
	case PMCOUT_STATUS_XFER_ERROR_REJECTED_NCQ_MODE:
		return ("XFER_ERROR_REJECTED_NCQ_MODE");
	case PMCOUT_STATUS_XFER_ERROR_ABORTED_DUE_TO_SRST:
		return ("XFER_ERROR_ABORTED_DUE_TO_SRST");
	case PMCOUT_STATUS_XFER_ERROR_ABORTED_NCQ_MODE:
		return ("XFER_ERROR_ABORTED_NCQ_MODE");
	case PMCOUT_STATUS_IO_XFER_OPEN_RETRY_TIMEOUT:
		return ("IO_XFER_OPEN_RETRY_TIMEOUT");
	case PMCOUT_STATUS_SMP_RESP_CONNECTION_ERROR:
		return ("SMP_RESP_CONNECTION_ERROR");
	case PMCOUT_STATUS_XFER_ERROR_UNEXPECTED_PHASE:
		return ("XFER_ERROR_UNEXPECTED_PHASE");
	case PMCOUT_STATUS_XFER_ERROR_RDY_OVERRUN:
		return ("XFER_ERROR_RDY_OVERRUN");
	case PMCOUT_STATUS_XFER_ERROR_RDY_NOT_EXPECTED:
		return ("XFER_ERROR_RDY_NOT_EXPECTED");
	case PMCOUT_STATUS_XFER_ERROR_CMD_ISSUE_ACK_NAK_TIMEOUT:
		return ("XFER_ERROR_CMD_ISSUE_ACK_NAK_TIMEOUT");
	case PMCOUT_STATUS_XFER_ERROR_CMD_ISSUE_BREAK_BEFORE_ACK_NACK:
		return ("XFER_ERROR_CMD_ISSUE_BREAK_BEFORE_ACK_NACK");
	case PMCOUT_STATUS_XFER_ERROR_CMD_ISSUE_PHY_DOWN_BEFORE_ACK_NAK:
		return ("XFER_ERROR_CMD_ISSUE_PHY_DOWN_BEFORE_ACK_NAK");
	case PMCOUT_STATUS_XFER_ERROR_OFFSET_MISMATCH:
		return ("XFER_ERROR_OFFSET_MISMATCH");
	case PMCOUT_STATUS_XFER_ERROR_ZERO_DATA_LEN:
		return ("XFER_ERROR_ZERO_DATA_LEN");
	case PMCOUT_STATUS_XFER_CMD_FRAME_ISSUED:
		return ("XFER_CMD_FRAME_ISSUED");
	case PMCOUT_STATUS_ERROR_INTERNAL_SMP_RESOURCE:
		return ("ERROR_INTERNAL_SMP_RESOURCE");
	case PMCOUT_STATUS_IO_PORT_IN_RESET:
		return ("IO_PORT_IN_RESET");
	case PMCOUT_STATUS_IO_DS_NON_OPERATIONAL:
		return ("DEVICE STATE NON-OPERATIONAL");
	case PMCOUT_STATUS_IO_DS_IN_RECOVERY:
		return ("DEVICE STATE IN RECOVERY");
	default:
		return (NULL);
	}
}

uint64_t
pmcs_barray2wwn(uint8_t ba[8])
{
	uint64_t result = 0;
	int i;

	for (i = 0; i < 8; i++) {
		result <<= 8;
		result |= ba[i];
	}
	return (result);
}

void
pmcs_wwn2barray(uint64_t wwn, uint8_t ba[8])
{
	int i;
	for (i = 0; i < 8; i++) {
		ba[7 - i] = wwn & 0xff;
		wwn >>= 8;
	}
}

void
pmcs_report_fwversion(pmcs_hw_t *pwp)
{
	const char *fwsupport;
	switch (PMCS_FW_TYPE(pwp)) {
	case PMCS_FW_TYPE_RELEASED:
		fwsupport = "Released";
		break;
	case PMCS_FW_TYPE_DEVELOPMENT:
		fwsupport = "Development";
		break;
	case PMCS_FW_TYPE_ALPHA:
		fwsupport = "Alpha";
		break;
	case PMCS_FW_TYPE_BETA:
		fwsupport = "Beta";
		break;
	default:
		fwsupport = "Special";
		break;
	}
	pmcs_prt(pwp, PMCS_PRT_INFO, NULL, NULL,
	    "Chip Revision: %c; F/W Revision %x.%x.%x %s", 'A' + pwp->chiprev,
	    PMCS_FW_MAJOR(pwp), PMCS_FW_MINOR(pwp), PMCS_FW_MICRO(pwp),
	    fwsupport);
}

void
pmcs_phy_name(pmcs_hw_t *pwp, pmcs_phy_t *pptr, char *obuf, size_t olen)
{
	if (pptr->parent) {
		pmcs_phy_name(pwp, pptr->parent, obuf, olen);
		(void) snprintf(obuf, olen, "%s.%02x", obuf, pptr->phynum);
	} else {
		(void) snprintf(obuf, olen, "pp%02x", pptr->phynum);
	}
}

/*
 * Implementation for pmcs_find_phy_by_devid.
 * If the PHY is found, it is returned locked.
 */
static pmcs_phy_t *
pmcs_find_phy_by_devid_impl(pmcs_phy_t *phyp, uint32_t device_id)
{
	pmcs_phy_t *match, *cphyp, *nphyp;

	ASSERT(!mutex_owned(&phyp->phy_lock));

	while (phyp) {
		pmcs_lock_phy(phyp);

		if ((phyp->valid_device_id) && (phyp->device_id == device_id)) {
			return (phyp);
		}
		if (phyp->children) {
			cphyp = phyp->children;
			pmcs_unlock_phy(phyp);
			match = pmcs_find_phy_by_devid_impl(cphyp, device_id);
			if (match) {
				ASSERT(mutex_owned(&match->phy_lock));
				return (match);
			}
			pmcs_lock_phy(phyp);
		}

		if (IS_ROOT_PHY(phyp)) {
			pmcs_unlock_phy(phyp);
			phyp = NULL;
		} else {
			nphyp = phyp->sibling;
			pmcs_unlock_phy(phyp);
			phyp = nphyp;
		}
	}

	return (NULL);
}

/*
 * If the PHY is found, it is returned locked
 */
pmcs_phy_t *
pmcs_find_phy_by_devid(pmcs_hw_t *pwp, uint32_t device_id)
{
	pmcs_phy_t *phyp, *match = NULL;

	phyp = pwp->root_phys;

	while (phyp) {
		match = pmcs_find_phy_by_devid_impl(phyp, device_id);
		if (match) {
			ASSERT(mutex_owned(&match->phy_lock));
			return (match);
		}
		phyp = phyp->sibling;
	}

	return (NULL);
}

/*
 * This function is called as a sanity check to ensure that a newly registered
 * PHY doesn't have a device_id that exists with another registered PHY.
 */
static boolean_t
pmcs_validate_devid(pmcs_phy_t *parent, pmcs_phy_t *phyp, uint32_t device_id)
{
	pmcs_phy_t *pptr;
	boolean_t rval;

	pptr = parent;

	while (pptr) {
		if (pptr->valid_device_id && (pptr != phyp) &&
		    (pptr->device_id == device_id)) {
			pmcs_prt(pptr->pwp, PMCS_PRT_DEBUG, pptr, NULL,
			    "%s: phy %s already exists as %s with "
			    "device id 0x%x", __func__, phyp->path,
			    pptr->path, device_id);
			return (B_FALSE);
		}

		if (pptr->children) {
			rval = pmcs_validate_devid(pptr->children, phyp,
			    device_id);
			if (rval == B_FALSE) {
				return (rval);
			}
		}

		pptr = pptr->sibling;
	}

	/* This PHY and device_id are valid */
	return (B_TRUE);
}

/*
 * If the PHY is found, it is returned locked
 */
static pmcs_phy_t *
pmcs_find_phy_by_wwn_impl(pmcs_phy_t *phyp, uint8_t *wwn)
{
	pmcs_phy_t *matched_phy, *cphyp, *nphyp;

	ASSERT(!mutex_owned(&phyp->phy_lock));

	while (phyp) {
		pmcs_lock_phy(phyp);

		if (phyp->valid_device_id) {
			if (memcmp(phyp->sas_address, wwn, 8) == 0) {
				return (phyp);
			}
		}

		if (phyp->children) {
			cphyp = phyp->children;
			pmcs_unlock_phy(phyp);
			matched_phy = pmcs_find_phy_by_wwn_impl(cphyp, wwn);
			if (matched_phy) {
				ASSERT(mutex_owned(&matched_phy->phy_lock));
				return (matched_phy);
			}
			pmcs_lock_phy(phyp);
		}

		/*
		 * Only iterate through non-root PHYs
		 */
		if (IS_ROOT_PHY(phyp)) {
			pmcs_unlock_phy(phyp);
			phyp = NULL;
		} else {
			nphyp = phyp->sibling;
			pmcs_unlock_phy(phyp);
			phyp = nphyp;
		}
	}

	return (NULL);
}

pmcs_phy_t *
pmcs_find_phy_by_wwn(pmcs_hw_t *pwp, uint64_t wwn)
{
	uint8_t ebstr[8];
	pmcs_phy_t *pptr, *matched_phy;

	pmcs_wwn2barray(wwn, ebstr);

	pptr = pwp->root_phys;
	while (pptr) {
		matched_phy = pmcs_find_phy_by_wwn_impl(pptr, ebstr);
		if (matched_phy) {
			ASSERT(mutex_owned(&matched_phy->phy_lock));
			return (matched_phy);
		}

		pptr = pptr->sibling;
	}

	return (NULL);
}


/*
 * pmcs_find_phy_by_sas_address
 *
 * Find a PHY that both matches "sas_addr" and is on "iport".
 * If a matching PHY is found, it is returned locked.
 */
pmcs_phy_t *
pmcs_find_phy_by_sas_address(pmcs_hw_t *pwp, pmcs_iport_t *iport,
    pmcs_phy_t *root, char *sas_addr)
{
	int ua_form = 1;
	uint64_t wwn;
	char addr[PMCS_MAX_UA_SIZE];
	pmcs_phy_t *pptr, *pnext, *pchild;

	if (root == NULL) {
		pptr = pwp->root_phys;
	} else {
		pptr = root;
	}

	while (pptr) {
		pmcs_lock_phy(pptr);
		/*
		 * If the PHY is dead or does not have a valid device ID,
		 * skip it.
		 */
		if ((pptr->dead) || (!pptr->valid_device_id)) {
			goto next_phy;
		}

		if (pptr->iport != iport) {
			goto next_phy;
		}

		wwn = pmcs_barray2wwn(pptr->sas_address);
		(void *) scsi_wwn_to_wwnstr(wwn, ua_form, addr);
		if (strncmp(addr, sas_addr, strlen(addr)) == 0) {
			return (pptr);
		}

		if (pptr->children) {
			pchild = pptr->children;
			pmcs_unlock_phy(pptr);
			pnext = pmcs_find_phy_by_sas_address(pwp, iport, pchild,
			    sas_addr);
			if (pnext) {
				return (pnext);
			}
			pmcs_lock_phy(pptr);
		}

next_phy:
		pnext = pptr->sibling;
		pmcs_unlock_phy(pptr);
		pptr = pnext;
	}

	return (NULL);
}

void
pmcs_fis_dump(pmcs_hw_t *pwp, fis_t fis)
{
	switch (fis[0] & 0xff) {
	case FIS_REG_H2DEV:
		pmcs_prt(pwp, PMCS_PRT_INFO, NULL, NULL,
		    "FIS REGISTER HOST TO DEVICE: "
		    "OP=0x%02x Feature=0x%04x Count=0x%04x Device=0x%02x "
		    "LBA=%llu", BYTE2(fis[0]), BYTE3(fis[2]) << 8 |
		    BYTE3(fis[0]), WORD0(fis[3]), BYTE3(fis[1]),
		    (unsigned long long)
		    (((uint64_t)fis[2] & 0x00ffffff) << 24 |
		    ((uint64_t)fis[1] & 0x00ffffff)));
		break;
	case FIS_REG_D2H:
		pmcs_prt(pwp, PMCS_PRT_INFO, NULL, NULL,
		    "FIS REGISTER DEVICE TO HOST: Status=0x%02x "
		    "Error=0x%02x Dev=0x%02x Count=0x%04x LBA=%llu",
		    BYTE2(fis[0]), BYTE3(fis[0]), BYTE3(fis[1]), WORD0(fis[3]),
		    (unsigned long long)(((uint64_t)fis[2] & 0x00ffffff) << 24 |
		    ((uint64_t)fis[1] & 0x00ffffff)));
		break;
	default:
		pmcs_prt(pwp, PMCS_PRT_INFO, NULL, NULL,
		    "FIS: 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x",
		    fis[0], fis[1], fis[2], fis[3], fis[4], fis[5], fis[6]);
		break;
	}
}

void
pmcs_print_entry(pmcs_hw_t *pwp, int level, char *msg, void *arg)
{
	uint32_t *mb = arg;
	size_t i;

	pmcs_prt(pwp, level, NULL, NULL, msg);
	for (i = 0; i < (PMCS_QENTRY_SIZE / sizeof (uint32_t)); i += 4) {
		pmcs_prt(pwp, level, NULL, NULL,
		    "Offset %2lu: 0x%08x 0x%08x 0x%08x 0x%08x",
		    i * sizeof (uint32_t), LE_32(mb[i]),
		    LE_32(mb[i+1]), LE_32(mb[i+2]), LE_32(mb[i+3]));
	}
}

/*
 * If phyp == NULL we're being called from the worker thread, in which
 * case we need to check all the PHYs.  In this case, the softstate lock
 * will be held.
 * If phyp is non-NULL, just issue the spinup release for the specified PHY
 * (which will already be locked).
 */
void
pmcs_spinup_release(pmcs_hw_t *pwp, pmcs_phy_t *phyp)
{
	uint32_t *msg;
	struct pmcwork *pwrk;
	pmcs_phy_t *tphyp;

	if (phyp != NULL) {
		ASSERT(mutex_owned(&phyp->phy_lock));
		pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, phyp, NULL,
		    "%s: Issuing spinup release only for PHY %s", __func__,
		    phyp->path);
		mutex_enter(&pwp->iqp_lock[PMCS_IQ_OTHER]);
		msg = GET_IQ_ENTRY(pwp, PMCS_IQ_OTHER);
		if (msg == NULL || (pwrk =
		    pmcs_gwork(pwp, PMCS_TAG_TYPE_NONE, NULL)) == NULL) {
			mutex_exit(&pwp->iqp_lock[PMCS_IQ_OTHER]);
			SCHEDULE_WORK(pwp, PMCS_WORK_SPINUP_RELEASE);
			return;
		}

		phyp->spinup_hold = 0;
		bzero(msg, PMCS_QENTRY_SIZE);
		msg[0] = LE_32(PMCS_HIPRI(pwp, PMCS_OQ_GENERAL,
		    PMCIN_LOCAL_PHY_CONTROL));
		msg[1] = LE_32(pwrk->htag);
		msg[2] = LE_32((0x10 << 8) | phyp->phynum);

		pwrk->dtype = phyp->dtype;
		pwrk->state = PMCS_WORK_STATE_ONCHIP;
		mutex_exit(&pwrk->lock);
		INC_IQ_ENTRY(pwp, PMCS_IQ_OTHER);
		return;
	}

	ASSERT(mutex_owned(&pwp->lock));

	tphyp = pwp->root_phys;
	while (tphyp) {
		pmcs_lock_phy(tphyp);
		if (tphyp->spinup_hold == 0) {
			pmcs_unlock_phy(tphyp);
			tphyp = tphyp->sibling;
			continue;
		}

		pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, phyp, NULL,
		    "%s: Issuing spinup release for PHY %s", __func__,
		    phyp->path);

		mutex_enter(&pwp->iqp_lock[PMCS_IQ_OTHER]);
		msg = GET_IQ_ENTRY(pwp, PMCS_IQ_OTHER);
		if (msg == NULL || (pwrk =
		    pmcs_gwork(pwp, PMCS_TAG_TYPE_NONE, NULL)) == NULL) {
			pmcs_unlock_phy(tphyp);
			mutex_exit(&pwp->iqp_lock[PMCS_IQ_OTHER]);
			SCHEDULE_WORK(pwp, PMCS_WORK_SPINUP_RELEASE);
			break;
		}

		tphyp->spinup_hold = 0;
		bzero(msg, PMCS_QENTRY_SIZE);
		msg[0] = LE_32(PMCS_HIPRI(pwp, PMCS_OQ_GENERAL,
		    PMCIN_LOCAL_PHY_CONTROL));
		msg[1] = LE_32(pwrk->htag);
		msg[2] = LE_32((0x10 << 8) | tphyp->phynum);

		pwrk->dtype = phyp->dtype;
		pwrk->state = PMCS_WORK_STATE_ONCHIP;
		mutex_exit(&pwrk->lock);
		INC_IQ_ENTRY(pwp, PMCS_IQ_OTHER);
		pmcs_unlock_phy(tphyp);

		tphyp = tphyp->sibling;
	}
}

/*
 * Abort commands on dead PHYs and deregister them as well as removing
 * the associated targets.
 */
static int
pmcs_kill_devices(pmcs_hw_t *pwp, pmcs_phy_t *phyp)
{
	pmcs_phy_t *pnext, *pchild;
	boolean_t remove_device;
	int rval = 0;

	while (phyp) {
		pmcs_lock_phy(phyp);
		pchild = phyp->children;
		pnext = phyp->sibling;
		pmcs_unlock_phy(phyp);

		if (pchild) {
			rval = pmcs_kill_devices(pwp, pchild);
			if (rval) {
				return (rval);
			}
		}

		/*
		 * pmcs_remove_device requires the softstate lock.
		 */
		mutex_enter(&pwp->lock);
		pmcs_lock_phy(phyp);
		if (phyp->dead && phyp->valid_device_id) {
			remove_device = B_TRUE;
		} else {
			remove_device = B_FALSE;
		}

		if (remove_device) {
			pmcs_remove_device(pwp, phyp);
			mutex_exit(&pwp->lock);

			rval = pmcs_kill_device(pwp, phyp);

			if (rval) {
				pmcs_unlock_phy(phyp);
				return (rval);
			}
		} else {
			mutex_exit(&pwp->lock);
		}

		pmcs_unlock_phy(phyp);
		phyp = pnext;
	}

	return (rval);
}

/*
 * Called with PHY locked
 */
int
pmcs_kill_device(pmcs_hw_t *pwp, pmcs_phy_t *pptr)
{
	int r, result;
	uint32_t msg[PMCS_MSG_SIZE], *ptr, status;
	struct pmcwork *pwrk;

	pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, NULL, "kill %s device @ %s",
	    pmcs_get_typename(pptr->dtype), pptr->path);

	/*
	 * There may be an outstanding ABORT_ALL running, which we wouldn't
	 * know just by checking abort_pending.  We can, however, check
	 * abort_all_start.  If it's non-zero, there is one, and we'll just
	 * sit here and wait for it to complete.  If we don't, we'll remove
	 * the device while there are still commands pending.
	 */
	if (pptr->abort_all_start) {
		while (pptr->abort_all_start) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, NULL,
			    "%s: Waiting for outstanding ABORT_ALL on PHY 0x%p",
			    __func__, (void *)pptr);
			cv_wait(&pptr->abort_all_cv, &pptr->phy_lock);
		}
	} else if (pptr->abort_pending) {
		r = pmcs_abort(pwp, pptr, pptr->device_id, 1, 1);

		if (r) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, NULL,
			    "%s: ABORT_ALL returned non-zero status (%d) for "
			    "PHY 0x%p", __func__, r, (void *)pptr);
			return (r);
		}
		pptr->abort_pending = 0;
	}

	if (pptr->valid_device_id == 0) {
		return (0);
	}

	if ((pwrk = pmcs_gwork(pwp, PMCS_TAG_TYPE_WAIT, pptr)) == NULL) {
		pmcs_prt(pwp, PMCS_PRT_ERR, pptr, NULL, pmcs_nowrk, __func__);
		return (ENOMEM);
	}
	pwrk->arg = msg;
	pwrk->dtype = pptr->dtype;
	msg[0] = LE_32(PMCS_HIPRI(pwp, PMCS_OQ_GENERAL,
	    PMCIN_DEREGISTER_DEVICE_HANDLE));
	msg[1] = LE_32(pwrk->htag);
	msg[2] = LE_32(pptr->device_id);

	mutex_enter(&pwp->iqp_lock[PMCS_IQ_OTHER]);
	ptr = GET_IQ_ENTRY(pwp, PMCS_IQ_OTHER);
	if (ptr == NULL) {
		mutex_exit(&pwp->iqp_lock[PMCS_IQ_OTHER]);
		mutex_exit(&pwrk->lock);
		pmcs_prt(pwp, PMCS_PRT_ERR, pptr, NULL, pmcs_nomsg, __func__);
		return (ENOMEM);
	}

	COPY_MESSAGE(ptr, msg, 3);
	pwrk->state = PMCS_WORK_STATE_ONCHIP;
	INC_IQ_ENTRY(pwp, PMCS_IQ_OTHER);

	pmcs_unlock_phy(pptr);
	WAIT_FOR(pwrk, 250, result);
	pmcs_lock_phy(pptr);
	pmcs_pwork(pwp, pwrk);

	if (result) {
		return (ETIMEDOUT);
	}
	status = LE_32(msg[2]);
	if (status != PMCOUT_STATUS_OK) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, NULL,
		    "%s: status 0x%x when trying to deregister device %s",
		    __func__, status, pptr->path);
	}

	pptr->device_id = PMCS_INVALID_DEVICE_ID;
	PHY_CHANGED(pwp, pptr);
	RESTART_DISCOVERY(pwp);
	pptr->valid_device_id = 0;
	return (0);
}

/*
 * Acknowledge the SAS h/w events that need acknowledgement.
 * This is only needed for first level PHYs.
 */
void
pmcs_ack_events(pmcs_hw_t *pwp)
{
	uint32_t msg[PMCS_MSG_SIZE], *ptr;
	struct pmcwork *pwrk;
	pmcs_phy_t *pptr;

	for (pptr = pwp->root_phys; pptr; pptr = pptr->sibling) {
		pmcs_lock_phy(pptr);
		if (pptr->hw_event_ack == 0) {
			pmcs_unlock_phy(pptr);
			continue;
		}
		mutex_enter(&pwp->iqp_lock[PMCS_IQ_OTHER]);
		ptr = GET_IQ_ENTRY(pwp, PMCS_IQ_OTHER);

		if ((ptr == NULL) || (pwrk =
		    pmcs_gwork(pwp, PMCS_TAG_TYPE_NONE, NULL)) == NULL) {
			mutex_exit(&pwp->iqp_lock[PMCS_IQ_OTHER]);
			pmcs_unlock_phy(pptr);
			SCHEDULE_WORK(pwp, PMCS_WORK_SAS_HW_ACK);
			break;
		}

		msg[0] = LE_32(PMCS_HIPRI(pwp, PMCS_OQ_GENERAL,
		    PMCIN_SAW_HW_EVENT_ACK));
		msg[1] = LE_32(pwrk->htag);
		msg[2] = LE_32(pptr->hw_event_ack);

		mutex_exit(&pwrk->lock);
		pwrk->dtype = pptr->dtype;
		pptr->hw_event_ack = 0;
		COPY_MESSAGE(ptr, msg, 3);
		INC_IQ_ENTRY(pwp, PMCS_IQ_OTHER);
		pmcs_unlock_phy(pptr);
	}
}

/*
 * Load DMA
 */
int
pmcs_dma_load(pmcs_hw_t *pwp, pmcs_cmd_t *sp, uint32_t *msg)
{
	ddi_dma_cookie_t *sg;
	pmcs_dmachunk_t *tc;
	pmcs_dmasgl_t *sgl, *prior;
	int seg, tsc;
	uint64_t sgl_addr;

	/*
	 * If we have no data segments, we're done.
	 */
	if (CMD2PKT(sp)->pkt_numcookies == 0) {
		return (0);
	}

	/*
	 * Get the S/G list pointer.
	 */
	sg = CMD2PKT(sp)->pkt_cookies;

	/*
	 * If we only have one dma segment, we can directly address that
	 * data within the Inbound message itself.
	 */
	if (CMD2PKT(sp)->pkt_numcookies == 1) {
		msg[12] = LE_32(DWORD0(sg->dmac_laddress));
		msg[13] = LE_32(DWORD1(sg->dmac_laddress));
		msg[14] = LE_32(sg->dmac_size);
		msg[15] = 0;
		return (0);
	}

	/*
	 * Otherwise, we'll need one or more external S/G list chunks.
	 * Get the first one and its dma address into the Inbound message.
	 */
	mutex_enter(&pwp->dma_lock);
	tc = pwp->dma_freelist;
	if (tc == NULL) {
		SCHEDULE_WORK(pwp, PMCS_WORK_ADD_DMA_CHUNKS);
		mutex_exit(&pwp->dma_lock);
		pmcs_prt(pwp, PMCS_PRT_DEBUG2, NULL, NULL,
		    "%s: out of SG lists", __func__);
		return (-1);
	}
	pwp->dma_freelist = tc->nxt;
	mutex_exit(&pwp->dma_lock);

	tc->nxt = NULL;
	sp->cmd_clist = tc;
	sgl = tc->chunks;
	(void) memset(tc->chunks, 0, PMCS_SGL_CHUNKSZ);
	sgl_addr = tc->addr;
	msg[12] = LE_32(DWORD0(sgl_addr));
	msg[13] = LE_32(DWORD1(sgl_addr));
	msg[14] = 0;
	msg[15] = LE_32(PMCS_DMASGL_EXTENSION);

	prior = sgl;
	tsc = 0;

	for (seg = 0; seg < CMD2PKT(sp)->pkt_numcookies; seg++) {
		/*
		 * If the current segment count for this chunk is one less than
		 * the number s/g lists per chunk and we have more than one seg
		 * to go, we need another chunk. Get it, and make sure that the
		 * tail end of the the previous chunk points the new chunk
		 * (if remembering an offset can be called 'pointing to').
		 *
		 * Note that we can store the offset into our command area that
		 * represents the new chunk in the length field of the part
		 * that points the PMC chip at the next chunk- the PMC chip
		 * ignores this field when the EXTENSION bit is set.
		 *
		 * This is required for dma unloads later.
		 */
		if (tsc == (PMCS_SGL_NCHUNKS - 1) &&
		    seg < (CMD2PKT(sp)->pkt_numcookies - 1)) {
			mutex_enter(&pwp->dma_lock);
			tc = pwp->dma_freelist;
			if (tc == NULL) {
				SCHEDULE_WORK(pwp, PMCS_WORK_ADD_DMA_CHUNKS);
				mutex_exit(&pwp->dma_lock);
				pmcs_dma_unload(pwp, sp);
				pmcs_prt(pwp, PMCS_PRT_DEBUG2, NULL, NULL,
				    "%s: out of SG lists", __func__);
				return (-1);
			}
			pwp->dma_freelist = tc->nxt;
			tc->nxt = sp->cmd_clist;
			mutex_exit(&pwp->dma_lock);

			sp->cmd_clist = tc;
			(void) memset(tc->chunks, 0, PMCS_SGL_CHUNKSZ);
			sgl = tc->chunks;
			sgl_addr = tc->addr;
			prior[PMCS_SGL_NCHUNKS-1].sglal =
			    LE_32(DWORD0(sgl_addr));
			prior[PMCS_SGL_NCHUNKS-1].sglah =
			    LE_32(DWORD1(sgl_addr));
			prior[PMCS_SGL_NCHUNKS-1].sglen = 0;
			prior[PMCS_SGL_NCHUNKS-1].flags =
			    LE_32(PMCS_DMASGL_EXTENSION);
			prior = sgl;
			tsc = 0;
		}
		sgl[tsc].sglal = LE_32(DWORD0(sg->dmac_laddress));
		sgl[tsc].sglah = LE_32(DWORD1(sg->dmac_laddress));
		sgl[tsc].sglen = LE_32(sg->dmac_size);
		sgl[tsc++].flags = 0;
		sg++;
	}
	return (0);
}

/*
 * Unload DMA
 */
void
pmcs_dma_unload(pmcs_hw_t *pwp, pmcs_cmd_t *sp)
{
	pmcs_dmachunk_t *cp;

	mutex_enter(&pwp->dma_lock);
	while ((cp = sp->cmd_clist) != NULL) {
		sp->cmd_clist = cp->nxt;
		cp->nxt = pwp->dma_freelist;
		pwp->dma_freelist = cp;
	}
	mutex_exit(&pwp->dma_lock);
}

/*
 * Take a chunk of consistent memory that has just been allocated and inserted
 * into the cip indices and prepare it for DMA chunk usage and add it to the
 * freelist.
 *
 * Called with dma_lock locked (except during attach when it's unnecessary)
 */
void
pmcs_idma_chunks(pmcs_hw_t *pwp, pmcs_dmachunk_t *dcp,
    pmcs_chunk_t *pchunk, unsigned long lim)
{
	unsigned long off, n;
	pmcs_dmachunk_t *np = dcp;
	pmcs_chunk_t *tmp_chunk;

	if (pwp->dma_chunklist == NULL) {
		pwp->dma_chunklist = pchunk;
	} else {
		tmp_chunk = pwp->dma_chunklist;
		while (tmp_chunk->next) {
			tmp_chunk = tmp_chunk->next;
		}
		tmp_chunk->next = pchunk;
	}

	/*
	 * Install offsets into chunk lists.
	 */
	for (n = 0, off = 0; off < lim; off += PMCS_SGL_CHUNKSZ, n++) {
		np->chunks = (void *)&pchunk->addrp[off];
		np->addr = pchunk->dma_addr + off;
		np->acc_handle = pchunk->acc_handle;
		np->dma_handle = pchunk->dma_handle;
		if ((off + PMCS_SGL_CHUNKSZ) < lim) {
			np = np->nxt;
		}
	}
	np->nxt = pwp->dma_freelist;
	pwp->dma_freelist = dcp;
	pmcs_prt(pwp, PMCS_PRT_DEBUG2, NULL, NULL,
	    "added %lu DMA chunks ", n);
}

/*
 * Change the value of the interrupt coalescing timer.  This is done currently
 * only for I/O completions.  If we're using the "auto clear" feature, it can
 * be turned back on when interrupt coalescing is turned off and must be
 * turned off when the coalescing timer is on.
 * NOTE: PMCS_MSIX_GENERAL and PMCS_OQ_IODONE are the same value.  As long
 * as that's true, we don't need to distinguish between them.
 */

void
pmcs_set_intr_coal_timer(pmcs_hw_t *pwp, pmcs_coal_timer_adj_t adj)
{
	if (adj == DECREASE_TIMER) {
		/* If the timer is already off, nothing to do. */
		if (pwp->io_intr_coal.timer_on == B_FALSE) {
			return;
		}

		pwp->io_intr_coal.intr_coal_timer -= PMCS_COAL_TIMER_GRAN;

		if (pwp->io_intr_coal.intr_coal_timer == 0) {
			/* Disable the timer */
			pmcs_wr_topunit(pwp, PMCS_INT_COALESCING_CONTROL, 0);

			if (pwp->odb_auto_clear & (1 << PMCS_MSIX_IODONE)) {
				pmcs_wr_topunit(pwp, PMCS_OBDB_AUTO_CLR,
				    pwp->odb_auto_clear);
			}

			pwp->io_intr_coal.timer_on = B_FALSE;
			pwp->io_intr_coal.max_io_completions = B_FALSE;
			pwp->io_intr_coal.num_intrs = 0;
			pwp->io_intr_coal.int_cleared = B_FALSE;
			pwp->io_intr_coal.num_io_completions = 0;

			DTRACE_PROBE1(pmcs__intr__coalesce__timer__off,
			    pmcs_io_intr_coal_t *, &pwp->io_intr_coal);
		} else {
			pmcs_wr_topunit(pwp, PMCS_INT_COALESCING_TIMER,
			    pwp->io_intr_coal.intr_coal_timer);
		}
	} else {
		/*
		 * If the timer isn't on yet, do the setup for it now.
		 */
		if (pwp->io_intr_coal.timer_on == B_FALSE) {
			/* If auto clear is being used, turn it off. */
			if (pwp->odb_auto_clear & (1 << PMCS_MSIX_IODONE)) {
				pmcs_wr_topunit(pwp, PMCS_OBDB_AUTO_CLR,
				    (pwp->odb_auto_clear &
				    ~(1 << PMCS_MSIX_IODONE)));
			}

			pmcs_wr_topunit(pwp, PMCS_INT_COALESCING_CONTROL,
			    (1 << PMCS_MSIX_IODONE));
			pwp->io_intr_coal.timer_on = B_TRUE;
			pwp->io_intr_coal.intr_coal_timer =
			    PMCS_COAL_TIMER_GRAN;

			DTRACE_PROBE1(pmcs__intr__coalesce__timer__on,
			    pmcs_io_intr_coal_t *, &pwp->io_intr_coal);
		} else {
			pwp->io_intr_coal.intr_coal_timer +=
			    PMCS_COAL_TIMER_GRAN;
		}

		if (pwp->io_intr_coal.intr_coal_timer > PMCS_MAX_COAL_TIMER) {
			pwp->io_intr_coal.intr_coal_timer = PMCS_MAX_COAL_TIMER;
		}

		pmcs_wr_topunit(pwp, PMCS_INT_COALESCING_TIMER,
		    pwp->io_intr_coal.intr_coal_timer);
	}

	/*
	 * Adjust the interrupt threshold based on the current timer value
	 */
	pwp->io_intr_coal.intr_threshold =
	    PMCS_INTR_THRESHOLD(PMCS_QUANTUM_TIME_USECS * 1000 /
	    (pwp->io_intr_coal.intr_latency +
	    (pwp->io_intr_coal.intr_coal_timer * 1000)));
}

/*
 * Register Access functions
 */
uint32_t
pmcs_rd_iqci(pmcs_hw_t *pwp, uint32_t qnum)
{
	uint32_t iqci;

	if (ddi_dma_sync(pwp->cip_handles, 0, 0, DDI_DMA_SYNC_FORKERNEL) !=
	    DDI_SUCCESS) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: ddi_dma_sync failed?", __func__);
	}

	iqci = LE_32(
	    ((uint32_t *)((void *)pwp->cip))[IQ_OFFSET(qnum) >> 2]);

	return (iqci);
}

uint32_t
pmcs_rd_oqpi(pmcs_hw_t *pwp, uint32_t qnum)
{
	uint32_t oqpi;

	if (ddi_dma_sync(pwp->cip_handles, 0, 0, DDI_DMA_SYNC_FORKERNEL) !=
	    DDI_SUCCESS) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: ddi_dma_sync failed?", __func__);
	}

	oqpi = LE_32(
	    ((uint32_t *)((void *)pwp->cip))[OQ_OFFSET(qnum) >> 2]);

	return (oqpi);
}

uint32_t
pmcs_rd_gsm_reg(pmcs_hw_t *pwp, uint32_t off)
{
	uint32_t rv, newaxil, oldaxil;

	newaxil = off & ~GSM_BASE_MASK;
	off &= GSM_BASE_MASK;
	mutex_enter(&pwp->axil_lock);
	oldaxil = ddi_get32(pwp->top_acc_handle,
	    &pwp->top_regs[PMCS_AXI_TRANS >> 2]);
	ddi_put32(pwp->top_acc_handle,
	    &pwp->top_regs[PMCS_AXI_TRANS >> 2], newaxil);
	drv_usecwait(10);
	if (ddi_get32(pwp->top_acc_handle,
	    &pwp->top_regs[PMCS_AXI_TRANS >> 2]) != newaxil) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "AXIL register update failed");
	}
	rv = ddi_get32(pwp->gsm_acc_handle, &pwp->gsm_regs[off >> 2]);
	ddi_put32(pwp->top_acc_handle,
	    &pwp->top_regs[PMCS_AXI_TRANS >> 2], oldaxil);
	drv_usecwait(10);
	if (ddi_get32(pwp->top_acc_handle,
	    &pwp->top_regs[PMCS_AXI_TRANS >> 2]) != oldaxil) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "AXIL register restore failed");
	}
	mutex_exit(&pwp->axil_lock);
	return (rv);
}

void
pmcs_wr_gsm_reg(pmcs_hw_t *pwp, uint32_t off, uint32_t val)
{
	uint32_t newaxil, oldaxil;

	newaxil = off & ~GSM_BASE_MASK;
	off &= GSM_BASE_MASK;
	mutex_enter(&pwp->axil_lock);
	oldaxil = ddi_get32(pwp->top_acc_handle,
	    &pwp->top_regs[PMCS_AXI_TRANS >> 2]);
	ddi_put32(pwp->top_acc_handle,
	    &pwp->top_regs[PMCS_AXI_TRANS >> 2], newaxil);
	drv_usecwait(10);
	if (ddi_get32(pwp->top_acc_handle,
	    &pwp->top_regs[PMCS_AXI_TRANS >> 2]) != newaxil) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "AXIL register update failed");
	}
	ddi_put32(pwp->gsm_acc_handle, &pwp->gsm_regs[off >> 2], val);
	ddi_put32(pwp->top_acc_handle,
	    &pwp->top_regs[PMCS_AXI_TRANS >> 2], oldaxil);
	drv_usecwait(10);
	if (ddi_get32(pwp->top_acc_handle,
	    &pwp->top_regs[PMCS_AXI_TRANS >> 2]) != oldaxil) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "AXIL register restore failed");
	}
	mutex_exit(&pwp->axil_lock);
}

uint32_t
pmcs_rd_topunit(pmcs_hw_t *pwp, uint32_t off)
{
	switch (off) {
	case PMCS_SPC_RESET:
	case PMCS_SPC_BOOT_STRAP:
	case PMCS_SPC_DEVICE_ID:
	case PMCS_DEVICE_REVISION:
		off = pmcs_rd_gsm_reg(pwp, off);
		break;
	default:
		off = ddi_get32(pwp->top_acc_handle,
		    &pwp->top_regs[off >> 2]);
		break;
	}
	return (off);
}

void
pmcs_wr_topunit(pmcs_hw_t *pwp, uint32_t off, uint32_t val)
{
	switch (off) {
	case PMCS_SPC_RESET:
	case PMCS_DEVICE_REVISION:
		pmcs_wr_gsm_reg(pwp, off, val);
		break;
	default:
		ddi_put32(pwp->top_acc_handle, &pwp->top_regs[off >> 2], val);
		break;
	}
}

uint32_t
pmcs_rd_msgunit(pmcs_hw_t *pwp, uint32_t off)
{
	return (ddi_get32(pwp->msg_acc_handle, &pwp->msg_regs[off >> 2]));
}

uint32_t
pmcs_rd_mpi_tbl(pmcs_hw_t *pwp, uint32_t off)
{
	return (ddi_get32(pwp->mpi_acc_handle,
	    &pwp->mpi_regs[(pwp->mpi_offset + off) >> 2]));
}

uint32_t
pmcs_rd_gst_tbl(pmcs_hw_t *pwp, uint32_t off)
{
	return (ddi_get32(pwp->mpi_acc_handle,
	    &pwp->mpi_regs[(pwp->mpi_gst_offset + off) >> 2]));
}

uint32_t
pmcs_rd_iqc_tbl(pmcs_hw_t *pwp, uint32_t off)
{
	return (ddi_get32(pwp->mpi_acc_handle,
	    &pwp->mpi_regs[(pwp->mpi_iqc_offset + off) >> 2]));
}

uint32_t
pmcs_rd_oqc_tbl(pmcs_hw_t *pwp, uint32_t off)
{
	return (ddi_get32(pwp->mpi_acc_handle,
	    &pwp->mpi_regs[(pwp->mpi_oqc_offset + off) >> 2]));
}

uint32_t
pmcs_rd_iqpi(pmcs_hw_t *pwp, uint32_t qnum)
{
	return (ddi_get32(pwp->mpi_acc_handle,
	    &pwp->mpi_regs[pwp->iqpi_offset[qnum] >> 2]));
}

uint32_t
pmcs_rd_oqci(pmcs_hw_t *pwp, uint32_t qnum)
{
	return (ddi_get32(pwp->mpi_acc_handle,
	    &pwp->mpi_regs[pwp->oqci_offset[qnum] >> 2]));
}

void
pmcs_wr_msgunit(pmcs_hw_t *pwp, uint32_t off, uint32_t val)
{
	ddi_put32(pwp->msg_acc_handle, &pwp->msg_regs[off >> 2], val);
}

void
pmcs_wr_mpi_tbl(pmcs_hw_t *pwp, uint32_t off, uint32_t val)
{
	ddi_put32(pwp->mpi_acc_handle,
	    &pwp->mpi_regs[(pwp->mpi_offset + off) >> 2], (val));
}

void
pmcs_wr_gst_tbl(pmcs_hw_t *pwp, uint32_t off, uint32_t val)
{
	ddi_put32(pwp->mpi_acc_handle,
	    &pwp->mpi_regs[(pwp->mpi_gst_offset + off) >> 2], val);
}

void
pmcs_wr_iqc_tbl(pmcs_hw_t *pwp, uint32_t off, uint32_t val)
{
	ddi_put32(pwp->mpi_acc_handle,
	    &pwp->mpi_regs[(pwp->mpi_iqc_offset + off) >> 2], val);
}

void
pmcs_wr_oqc_tbl(pmcs_hw_t *pwp, uint32_t off, uint32_t val)
{
	ddi_put32(pwp->mpi_acc_handle,
	    &pwp->mpi_regs[(pwp->mpi_oqc_offset + off) >> 2], val);
}

void
pmcs_wr_iqci(pmcs_hw_t *pwp, uint32_t qnum, uint32_t val)
{
	((uint32_t *)((void *)pwp->cip))[IQ_OFFSET(qnum) >> 2] = val;
	if (ddi_dma_sync(pwp->cip_handles, 0, 0, DDI_DMA_SYNC_FORDEV) !=
	    DDI_SUCCESS) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: ddi_dma_sync failed?", __func__);
	}
}

void
pmcs_wr_iqpi(pmcs_hw_t *pwp, uint32_t qnum, uint32_t val)
{
	ddi_put32(pwp->mpi_acc_handle,
	    &pwp->mpi_regs[pwp->iqpi_offset[qnum] >> 2], val);
}

void
pmcs_wr_oqci(pmcs_hw_t *pwp, uint32_t qnum, uint32_t val)
{
	ddi_put32(pwp->mpi_acc_handle,
	    &pwp->mpi_regs[pwp->oqci_offset[qnum] >> 2], val);
}

void
pmcs_wr_oqpi(pmcs_hw_t *pwp, uint32_t qnum, uint32_t val)
{
	((uint32_t *)((void *)pwp->cip))[OQ_OFFSET(qnum) >> 2] = val;
	if (ddi_dma_sync(pwp->cip_handles, 0, 0, DDI_DMA_SYNC_FORDEV) !=
	    DDI_SUCCESS) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: ddi_dma_sync failed?", __func__);
	}
}

/*
 * Check the status value of an outbound IOMB and report anything bad
 */

void
pmcs_check_iomb_status(pmcs_hw_t *pwp, uint32_t *iomb)
{
	uint16_t 	opcode;
	int		offset;

	if (iomb == NULL) {
		return;
	}

	opcode = LE_32(iomb[0]) & 0xfff;

	switch (opcode) {
		/*
		 * The following have no status field, so ignore them
		 */
	case PMCOUT_ECHO:
	case PMCOUT_SAS_HW_EVENT:
	case PMCOUT_GET_DEVICE_HANDLE:
	case PMCOUT_SATA_EVENT:
	case PMCOUT_SSP_EVENT:
	case PMCOUT_DEVICE_HANDLE_ARRIVED:
	case PMCOUT_SMP_REQUEST_RECEIVED:
	case PMCOUT_GPIO:
	case PMCOUT_GPIO_EVENT:
	case PMCOUT_GET_TIME_STAMP:
	case PMCOUT_SKIP_ENTRIES:
	case PMCOUT_GET_NVMD_DATA:	/* Actually lower 16 bits of word 3 */
	case PMCOUT_SET_NVMD_DATA:	/* but ignore - we don't use these */
	case PMCOUT_DEVICE_HANDLE_REMOVED:
	case PMCOUT_SSP_REQUEST_RECEIVED:
		return;

	case PMCOUT_GENERAL_EVENT:
		offset = 1;
		break;

	case PMCOUT_SSP_COMPLETION:
	case PMCOUT_SMP_COMPLETION:
	case PMCOUT_DEVICE_REGISTRATION:
	case PMCOUT_DEREGISTER_DEVICE_HANDLE:
	case PMCOUT_SATA_COMPLETION:
	case PMCOUT_DEVICE_INFO:
	case PMCOUT_FW_FLASH_UPDATE:
	case PMCOUT_SSP_ABORT:
	case PMCOUT_SATA_ABORT:
	case PMCOUT_SAS_DIAG_MODE_START_END:
	case PMCOUT_SAS_HW_EVENT_ACK_ACK:
	case PMCOUT_SMP_ABORT:
	case PMCOUT_SET_DEVICE_STATE:
	case PMCOUT_GET_DEVICE_STATE:
	case PMCOUT_SET_DEVICE_INFO:
		offset = 2;
		break;

	case PMCOUT_LOCAL_PHY_CONTROL:
	case PMCOUT_SAS_DIAG_EXECUTE:
	case PMCOUT_PORT_CONTROL:
		offset = 3;
		break;

	case PMCOUT_GET_INFO:
	case PMCOUT_GET_VPD:
	case PMCOUT_SAS_ASSISTED_DISCOVERY_EVENT:
	case PMCOUT_SATA_ASSISTED_DISCOVERY_EVENT:
	case PMCOUT_SET_VPD:
	case PMCOUT_TWI:
		pmcs_print_entry(pwp, PMCS_PRT_DEBUG,
		    "Got response for deprecated opcode", iomb);
		return;

	default:
		pmcs_print_entry(pwp, PMCS_PRT_DEBUG,
		    "Got response for unknown opcode", iomb);
		return;
	}

	if (LE_32(iomb[offset]) != PMCOUT_STATUS_OK) {
		pmcs_print_entry(pwp, PMCS_PRT_DEBUG,
		    "bad status on TAG_TYPE_NONE command", iomb);
	}
}

/*
 * Called with statlock held
 */
void
pmcs_clear_xp(pmcs_hw_t *pwp, pmcs_xscsi_t *xp)
{
	_NOTE(ARGUNUSED(pwp));

	ASSERT(mutex_owned(&xp->statlock));

	pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, xp, "%s: Device 0x%p is gone.",
	    __func__, (void *)xp);

	/*
	 * Clear the dip now.  This keeps pmcs_remove_device from attempting
	 * to call us on the same device while we're still flushing queues.
	 * The only side effect is we can no longer update SM-HBA properties,
	 * but this device is going away anyway, so no matter.
	 */
	xp->dip = NULL;

	xp->special_running = 0;
	xp->recovering = 0;
	xp->recover_wait = 0;
	xp->draining = 0;
	xp->new = 0;
	xp->assigned = 0;
	xp->dev_state = 0;
	xp->tagmap = 0;
	xp->dev_gone = 1;
	xp->event_recovery = 0;
	xp->dtype = NOTHING;
	xp->wq_recovery_tail = NULL;
	/* Don't clear xp->phy */
	/* Don't clear xp->actv_cnt */

	/*
	 * Flush all target queues
	 */
	pmcs_flush_target_queues(pwp, xp, PMCS_TGT_ALL_QUEUES);
}

static int
pmcs_smp_function_result(pmcs_hw_t *pwp, smp_response_frame_t *srf)
{
	int result = srf->srf_result;

	switch (result) {
	case SMP_RES_UNKNOWN_FUNCTION:
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: SMP DISCOVER Response "
		    "Function Result: Unknown SMP Function(0x%x)",
		    __func__, result);
		break;
	case SMP_RES_FUNCTION_FAILED:
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: SMP DISCOVER Response "
		    "Function Result: SMP Function Failed(0x%x)",
		    __func__, result);
		break;
	case SMP_RES_INVALID_REQUEST_FRAME_LENGTH:
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: SMP DISCOVER Response "
		    "Function Result: Invalid Request Frame Length(0x%x)",
		    __func__, result);
		break;
	case SMP_RES_INCOMPLETE_DESCRIPTOR_LIST:
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: SMP DISCOVER Response "
		    "Function Result: Incomplete Descriptor List(0x%x)",
		    __func__, result);
		break;
	case SMP_RES_PHY_DOES_NOT_EXIST:
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: SMP DISCOVER Response "
		    "Function Result: PHY does not exist(0x%x)",
		    __func__, result);
		break;
	case SMP_RES_PHY_VACANT:
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: SMP DISCOVER Response "
		    "Function Result: PHY Vacant(0x%x)",
		    __func__, result);
		break;
	default:
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: SMP DISCOVER Response "
		    "Function Result: (0x%x)",
		    __func__, result);
		break;
	}

	return (result);
}

/*
 * Do all the repetitive stuff necessary to setup for DMA
 *
 * pwp: Used for dip
 * dma_attr: ddi_dma_attr_t to use for the mapping
 * acch: ddi_acc_handle_t to use for the mapping
 * dmah: ddi_dma_handle_t to use
 * length: Amount of memory for mapping
 * kvp: Pointer filled in with kernel virtual address on successful return
 * dma_addr: Pointer filled in with DMA address on successful return
 */
boolean_t
pmcs_dma_setup(pmcs_hw_t *pwp, ddi_dma_attr_t *dma_attr, ddi_acc_handle_t *acch,
    ddi_dma_handle_t *dmah, size_t length, caddr_t *kvp, uint64_t *dma_addr)
{
	dev_info_t		*dip = pwp->dip;
	ddi_dma_cookie_t	cookie;
	size_t			real_length;
	uint_t			ddma_flag = DDI_DMA_CONSISTENT;
	uint_t			ddabh_flag = DDI_DMA_CONSISTENT | DDI_DMA_RDWR;
	uint_t			cookie_cnt;
	ddi_device_acc_attr_t	mattr = {
		DDI_DEVICE_ATTR_V0,
		DDI_NEVERSWAP_ACC,
		DDI_STRICTORDER_ACC,
		DDI_DEFAULT_ACC
	};

	*acch = NULL;
	*dmah = NULL;

	if (ddi_dma_alloc_handle(dip, dma_attr, DDI_DMA_SLEEP, NULL, dmah) !=
	    DDI_SUCCESS) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "Failed to allocate DMA handle");
		return (B_FALSE);
	}

	if (ddi_dma_mem_alloc(*dmah, length, &mattr, ddma_flag, DDI_DMA_SLEEP,
	    NULL, kvp, &real_length, acch) != DDI_SUCCESS) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "Failed to allocate DMA mem");
		ddi_dma_free_handle(dmah);
		*dmah = NULL;
		return (B_FALSE);
	}

	if (ddi_dma_addr_bind_handle(*dmah, NULL, *kvp, real_length,
	    ddabh_flag, DDI_DMA_SLEEP, NULL, &cookie, &cookie_cnt)
	    != DDI_DMA_MAPPED) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL, "Failed to bind DMA");
		ddi_dma_free_handle(dmah);
		ddi_dma_mem_free(acch);
		*dmah = NULL;
		*acch = NULL;
		return (B_FALSE);
	}

	if (cookie_cnt != 1) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL, "Multiple cookies");
		if (ddi_dma_unbind_handle(*dmah) != DDI_SUCCESS) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL, "Condition "
			    "failed at %s():%d", __func__, __LINE__);
		}
		ddi_dma_free_handle(dmah);
		ddi_dma_mem_free(acch);
		*dmah = NULL;
		*acch = NULL;
		return (B_FALSE);
	}

	*dma_addr = cookie.dmac_laddress;

	return (B_TRUE);
}

/*
 * Flush requested queues for a particular target.  Called with statlock held
 */
void
pmcs_flush_target_queues(pmcs_hw_t *pwp, pmcs_xscsi_t *tgt, uint8_t queues)
{
	pmcs_cmd_t	*sp;
	pmcwork_t	*pwrk;

	ASSERT(pwp != NULL);
	ASSERT(tgt != NULL);

	pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, tgt,
	    "%s: Flushing queues (%d) for target 0x%p", __func__,
	    queues, (void *)tgt);

	/*
	 * Commands on the wait queue (or the special queue below) don't have
	 * work structures associated with them.
	 */
	if (queues & PMCS_TGT_WAIT_QUEUE) {
		mutex_enter(&tgt->wqlock);
		while ((sp = STAILQ_FIRST(&tgt->wq)) != NULL) {
			STAILQ_REMOVE(&tgt->wq, sp, pmcs_cmd, cmd_next);
			pmcs_prt(pwp, PMCS_PRT_DEBUG1, NULL, tgt,
			    "%s: Removing cmd 0x%p from wq for target 0x%p",
			    __func__, (void *)sp, (void *)tgt);
			CMD2PKT(sp)->pkt_reason = CMD_DEV_GONE;
			CMD2PKT(sp)->pkt_state = STATE_GOT_BUS;
			mutex_exit(&tgt->wqlock);
			pmcs_dma_unload(pwp, sp);
			mutex_enter(&pwp->cq_lock);
			STAILQ_INSERT_TAIL(&pwp->cq, sp, cmd_next);
			mutex_exit(&pwp->cq_lock);
			mutex_enter(&tgt->wqlock);
		}
		mutex_exit(&tgt->wqlock);
	}

	/*
	 * Commands on the active queue will have work structures associated
	 * with them.
	 */
	if (queues & PMCS_TGT_ACTIVE_QUEUE) {
		mutex_enter(&tgt->aqlock);
		while ((sp = STAILQ_FIRST(&tgt->aq)) != NULL) {
			STAILQ_REMOVE(&tgt->aq, sp, pmcs_cmd, cmd_next);
			pwrk = pmcs_tag2wp(pwp, sp->cmd_tag);
			mutex_exit(&tgt->aqlock);
			mutex_exit(&tgt->statlock);
			/*
			 * If we found a work structure, mark it as dead
			 * and complete it
			 */
			if (pwrk != NULL) {
				pwrk->dead = 1;
				CMD2PKT(sp)->pkt_reason = CMD_DEV_GONE;
				CMD2PKT(sp)->pkt_state = STATE_GOT_BUS;
				pmcs_complete_work_impl(pwp, pwrk, NULL, 0);
			}
			pmcs_prt(pwp, PMCS_PRT_DEBUG1, NULL, tgt,
			    "%s: Removing cmd 0x%p from aq for target 0x%p",
			    __func__, (void *)sp, (void *)tgt);
			pmcs_dma_unload(pwp, sp);
			mutex_enter(&pwp->cq_lock);
			STAILQ_INSERT_TAIL(&pwp->cq, sp, cmd_next);
			mutex_exit(&pwp->cq_lock);
			mutex_enter(&tgt->aqlock);
			mutex_enter(&tgt->statlock);
		}
		mutex_exit(&tgt->aqlock);
	}

	if (queues & PMCS_TGT_SPECIAL_QUEUE) {
		while ((sp = STAILQ_FIRST(&tgt->sq)) != NULL) {
			STAILQ_REMOVE(&tgt->sq, sp, pmcs_cmd, cmd_next);
			pmcs_prt(pwp, PMCS_PRT_DEBUG1, NULL, tgt,
			    "%s: Removing cmd 0x%p from sq for target 0x%p",
			    __func__, (void *)sp, (void *)tgt);
			CMD2PKT(sp)->pkt_reason = CMD_DEV_GONE;
			CMD2PKT(sp)->pkt_state = STATE_GOT_BUS;
			pmcs_dma_unload(pwp, sp);
			mutex_enter(&pwp->cq_lock);
			STAILQ_INSERT_TAIL(&pwp->cq, sp, cmd_next);
			mutex_exit(&pwp->cq_lock);
		}
	}
}

void
pmcs_complete_work_impl(pmcs_hw_t *pwp, pmcwork_t *pwrk, uint32_t *iomb,
    size_t amt)
{
	switch (PMCS_TAG_TYPE(pwrk->htag)) {
	case PMCS_TAG_TYPE_CBACK:
	{
		pmcs_cb_t callback = (pmcs_cb_t)pwrk->ptr;
		(*callback)(pwp, pwrk, iomb);
		break;
	}
	case PMCS_TAG_TYPE_WAIT:
		if (pwrk->arg && iomb && amt) {
			(void) memcpy(pwrk->arg, iomb, amt);
		}
		cv_signal(&pwrk->sleep_cv);
		mutex_exit(&pwrk->lock);
		break;
	case PMCS_TAG_TYPE_NONE:
#ifdef DEBUG
		pmcs_check_iomb_status(pwp, iomb);
#endif
		pmcs_pwork(pwp, pwrk);
		break;
	default:
		/*
		 * We will leak a structure here if we don't know
		 * what happened
		 */
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: Unknown PMCS_TAG_TYPE (%x)",
		    __func__, PMCS_TAG_TYPE(pwrk->htag));
		break;
	}
}

/*
 * Determine if iport still has targets. During detach(9E), if SCSA is
 * successfull in its guarantee of tran_tgt_free(9E) before detach(9E),
 * this should always return B_FALSE.
 */
boolean_t
pmcs_iport_has_targets(pmcs_hw_t *pwp, pmcs_iport_t *iport)
{
	pmcs_xscsi_t *xp;
	int i;

	mutex_enter(&pwp->lock);

	if (!pwp->targets || !pwp->max_dev) {
		mutex_exit(&pwp->lock);
		return (B_FALSE);
	}

	for (i = 0; i < pwp->max_dev; i++) {
		xp = pwp->targets[i];
		if ((xp == NULL) || (xp->phy == NULL) ||
		    (xp->phy->iport != iport)) {
			continue;
		}

		mutex_exit(&pwp->lock);
		return (B_TRUE);
	}

	mutex_exit(&pwp->lock);
	return (B_FALSE);
}

/*
 * Called with softstate lock held
 */
void
pmcs_destroy_target(pmcs_xscsi_t *target)
{
	pmcs_hw_t *pwp = target->pwp;
	pmcs_iport_t *iport;

	ASSERT(pwp);
	ASSERT(mutex_owned(&pwp->lock));

	if (!target->ua) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, target,
		    "%s: target %p iport address is null",
		    __func__, (void *)target);
	}

	iport = pmcs_get_iport_by_ua(pwp, target->ua);
	if (iport == NULL) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, target,
		    "%s: no iport associated with tgt(0x%p)",
		    __func__, (void *)target);
		return;
	}

	pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, NULL, target,
	    "%s: free target %p", __func__, (void *)target);
	if (target->ua) {
		strfree(target->ua);
	}

	mutex_destroy(&target->wqlock);
	mutex_destroy(&target->aqlock);
	mutex_destroy(&target->statlock);
	cv_destroy(&target->reset_cv);
	cv_destroy(&target->abort_cv);
	ddi_soft_state_bystr_fini(&target->lun_sstate);
	ddi_soft_state_bystr_free(iport->tgt_sstate, target->unit_address);
	pmcs_rele_iport(iport);
}

/*
 * Get device state.  Called with statlock and PHY lock held.
 */
int
pmcs_get_dev_state(pmcs_hw_t *pwp, pmcs_xscsi_t *xp, uint8_t *ds)
{
	uint32_t htag, *ptr, msg[PMCS_MSG_SIZE];
	int result;
	struct pmcwork *pwrk;
	pmcs_phy_t *phyp;

	pmcs_prt(pwp, PMCS_PRT_DEBUG3, NULL, xp, "%s: tgt(0x%p)", __func__,
	    (void *)xp);
	if (xp == NULL) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, xp,
		    "%s: Target is NULL", __func__);
		return (-1);
	}

	ASSERT(mutex_owned(&xp->statlock));
	phyp = xp->phy;
	ASSERT(mutex_owned(&phyp->phy_lock));

	pwrk = pmcs_gwork(pwp, PMCS_TAG_TYPE_WAIT, phyp);
	if (pwrk == NULL) {
		pmcs_prt(pwp, PMCS_PRT_ERR, phyp, xp, pmcs_nowrk, __func__);
		return (-1);
	}
	pwrk->arg = msg;
	pwrk->dtype = phyp->dtype;

	if (phyp->valid_device_id == 0) {
		pmcs_pwork(pwp, pwrk);
		pmcs_prt(pwp, PMCS_PRT_DEBUG, phyp, xp,
		    "%s: Invalid DeviceID", __func__);
		return (-1);
	}
	htag = pwrk->htag;
	msg[0] = LE_32(PMCS_HIPRI(pwp, PMCS_OQ_GENERAL,
	    PMCIN_GET_DEVICE_STATE));
	msg[1] = LE_32(pwrk->htag);
	msg[2] = LE_32(phyp->device_id);

	mutex_enter(&pwp->iqp_lock[PMCS_IQ_OTHER]);
	ptr = GET_IQ_ENTRY(pwp, PMCS_IQ_OTHER);
	if (ptr == NULL) {
		mutex_exit(&pwp->iqp_lock[PMCS_IQ_OTHER]);
		pmcs_pwork(pwp, pwrk);
		pmcs_prt(pwp, PMCS_PRT_ERR, phyp, xp, pmcs_nomsg, __func__);
		return (-1);
	}
	COPY_MESSAGE(ptr, msg, PMCS_MSG_SIZE);
	pwrk->state = PMCS_WORK_STATE_ONCHIP;
	INC_IQ_ENTRY(pwp, PMCS_IQ_OTHER);
	mutex_exit(&xp->statlock);
	pmcs_unlock_phy(phyp);
	WAIT_FOR(pwrk, 1000, result);
	pmcs_lock_phy(phyp);
	pmcs_pwork(pwp, pwrk);
	mutex_enter(&xp->statlock);

	if (result) {
		pmcs_timed_out(pwp, htag, __func__);
		pmcs_prt(pwp, PMCS_PRT_DEBUG, phyp, xp,
		    "%s: cmd timed out, returning ", __func__);
		return (-1);
	}
	if (LE_32(msg[2]) == 0) {
		*ds = (uint8_t)(LE_32(msg[4]));
		if (*ds !=  xp->dev_state) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG_DEV_STATE, phyp, xp,
			    "%s: retrieved_ds=0x%x, target_ds=0x%x", __func__,
			    *ds, xp->dev_state);
		}
		return (0);
	} else {
		pmcs_prt(pwp, PMCS_PRT_DEBUG_DEV_STATE, phyp, xp,
		    "%s: cmd failed Status(0x%x), returning ", __func__,
		    LE_32(msg[2]));
		return (-1);
	}
}

/*
 * Set device state.  Called with target's statlock and PHY lock held.
 */
int
pmcs_set_dev_state(pmcs_hw_t *pwp, pmcs_xscsi_t *xp, uint8_t ds)
{
	uint32_t htag, *ptr, msg[PMCS_MSG_SIZE];
	int result;
	uint8_t pds, nds;
	struct pmcwork *pwrk;
	pmcs_phy_t *phyp;

	pmcs_prt(pwp, PMCS_PRT_DEBUG_DEV_STATE, NULL, xp,
	    "%s: ds(0x%x), tgt(0x%p)", __func__, ds, (void *)xp);
	if (xp == NULL) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, xp,
		    "%s: Target is Null", __func__);
		return (-1);
	}

	phyp = xp->phy;
	pwrk = pmcs_gwork(pwp, PMCS_TAG_TYPE_WAIT, phyp);
	if (pwrk == NULL) {
		pmcs_prt(pwp, PMCS_PRT_ERR, phyp, xp, pmcs_nowrk, __func__);
		return (-1);
	}
	if (phyp == NULL) {
		pmcs_pwork(pwp, pwrk);
		pmcs_prt(pwp, PMCS_PRT_DEBUG_DEV_STATE, phyp, xp,
		    "%s: PHY is Null", __func__);
		return (-1);
	}
	if (phyp->valid_device_id == 0) {
		pmcs_pwork(pwp, pwrk);
		pmcs_prt(pwp, PMCS_PRT_DEBUG_DEV_STATE, phyp, xp,
		    "%s: Invalid DeviceID", __func__);
		return (-1);
	}
	pwrk->arg = msg;
	pwrk->dtype = phyp->dtype;
	htag = pwrk->htag;
	msg[0] = LE_32(PMCS_HIPRI(pwp, PMCS_OQ_GENERAL,
	    PMCIN_SET_DEVICE_STATE));
	msg[1] = LE_32(pwrk->htag);
	msg[2] = LE_32(phyp->device_id);
	msg[3] = LE_32(ds);

	mutex_enter(&pwp->iqp_lock[PMCS_IQ_OTHER]);
	ptr = GET_IQ_ENTRY(pwp, PMCS_IQ_OTHER);
	if (ptr == NULL) {
		mutex_exit(&pwp->iqp_lock[PMCS_IQ_OTHER]);
		pmcs_pwork(pwp, pwrk);
		pmcs_prt(pwp, PMCS_PRT_ERR, phyp, xp, pmcs_nomsg, __func__);
		return (-1);
	}
	COPY_MESSAGE(ptr, msg, PMCS_MSG_SIZE);
	pwrk->state = PMCS_WORK_STATE_ONCHIP;
	INC_IQ_ENTRY(pwp, PMCS_IQ_OTHER);

	mutex_exit(&xp->statlock);
	pmcs_unlock_phy(phyp);
	WAIT_FOR(pwrk, 1000, result);
	pmcs_lock_phy(phyp);
	pmcs_pwork(pwp, pwrk);
	mutex_enter(&xp->statlock);

	if (result) {
		pmcs_timed_out(pwp, htag, __func__);
		pmcs_prt(pwp, PMCS_PRT_DEBUG_DEV_STATE, phyp, xp,
		    "%s: cmd timed out, returning", __func__);
		return (-1);
	}
	if (LE_32(msg[2]) == 0) {
		pds = (uint8_t)(LE_32(msg[4]) >> 4);
		nds = (uint8_t)(LE_32(msg[4]) & 0x0000000f);
		pmcs_prt(pwp, PMCS_PRT_DEBUG_DEV_STATE, phyp, xp,
		    "%s: previous_ds=0x%x, new_ds=0x%x", __func__, pds, nds);
		xp->dev_state = nds;
		return (0);
	} else {
		pmcs_prt(pwp, PMCS_PRT_DEBUG_DEV_STATE, phyp, xp,
		    "%s: cmd failed Status(0x%x), returning ", __func__,
		    LE_32(msg[2]));
		return (-1);
	}
}

void
pmcs_dev_state_recovery(pmcs_hw_t *pwp, pmcs_phy_t *phyp)
{
	uint8_t	ds;
	int rc;
	pmcs_xscsi_t *tgt;
	pmcs_phy_t *pptr, *pnext, *pchild;

	/*
	 * First time, check to see if we're already performing recovery
	 */
	if (phyp == NULL) {
		mutex_enter(&pwp->lock);
		if (pwp->ds_err_recovering) {
			mutex_exit(&pwp->lock);
			SCHEDULE_WORK(pwp, PMCS_WORK_DS_ERR_RECOVERY);
			return;
		}

		pwp->ds_err_recovering = 1;
		pptr = pwp->root_phys;
		mutex_exit(&pwp->lock);
	} else {
		pptr = phyp;
	}

	while (pptr) {
		/*
		 * Since ds_err_recovering is set, we can be assured these
		 * PHYs won't disappear on us while we do this.
		 */
		pmcs_lock_phy(pptr);
		pchild = pptr->children;
		pnext = pptr->sibling;
		pmcs_unlock_phy(pptr);

		if (pchild) {
			pmcs_dev_state_recovery(pwp, pchild);
		}

		tgt = NULL;
		pmcs_lock_phy(pptr);

		if (pptr->dead) {
			goto next_phy;
		}

		tgt = pptr->target;
		if (tgt == NULL || tgt->dev_gone) {
			if (pptr->dtype != NOTHING) {
				pmcs_prt(pwp, PMCS_PRT_DEBUG2, pptr, tgt,
				    "%s: no target for DS error recovery for "
				    "PHY 0x%p", __func__, (void *)pptr);
			}
			goto next_phy;
		}

		mutex_enter(&tgt->statlock);

		if (tgt->recover_wait == 0) {
			goto next_phy;
		}

		/*
		 * Step 1: Put the device into the IN_RECOVERY state
		 */
		rc = pmcs_get_dev_state(pwp, tgt, &ds);
		if (rc != 0) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, tgt,
			    "%s: pmcs_get_dev_state on PHY %s "
			    "failed (rc=%d)",
			    __func__, pptr->path, rc);

			pmcs_handle_ds_recovery_error(pptr, tgt, pwp,
			    __func__, __LINE__, "pmcs_get_dev_state");

			goto next_phy;
		}

		if ((tgt->dev_state == ds) &&
		    (ds == PMCS_DEVICE_STATE_IN_RECOVERY)) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG_DEV_STATE, pptr, tgt,
			    "%s: Target 0x%p already IN_RECOVERY", __func__,
			    (void *)tgt);
		} else {
			tgt->dev_state = ds;
			ds = PMCS_DEVICE_STATE_IN_RECOVERY;
			rc = pmcs_send_err_recovery_cmd(pwp, ds, tgt);
			pmcs_prt(pwp, PMCS_PRT_DEBUG_DEV_STATE, pptr, tgt,
			    "%s: pmcs_send_err_recovery_cmd "
			    "result(%d) tgt(0x%p) ds(0x%x) tgt->ds(0x%x)",
			    __func__, rc, (void *)tgt, ds, tgt->dev_state);

			if (rc) {
				pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, tgt,
				    "%s: pmcs_send_err_recovery_cmd to PHY %s "
				    "failed (rc=%d)",
				    __func__, pptr->path, rc);

				pmcs_handle_ds_recovery_error(pptr, tgt, pwp,
				    __func__, __LINE__,
				    "pmcs_send_err_recovery_cmd");

				goto next_phy;
			}
		}

		/*
		 * Step 2: Perform a hard reset on the PHY
		 */
		pmcs_prt(pwp, PMCS_PRT_DEBUG_DEV_STATE, pptr, tgt,
		    "%s: Issue HARD_RESET to PHY %s", __func__, pptr->path);
		/*
		 * Must release statlock here because pmcs_reset_phy will
		 * drop and reacquire the PHY lock.
		 */
		mutex_exit(&tgt->statlock);
		rc = pmcs_reset_phy(pwp, pptr, PMCS_PHYOP_HARD_RESET);
		mutex_enter(&tgt->statlock);
		if (rc) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, tgt,
			    "%s: HARD_RESET to PHY %s failed (rc=%d)",
			    __func__, pptr->path, rc);

			pmcs_handle_ds_recovery_error(pptr, tgt, pwp,
			    __func__, __LINE__, "HARD_RESET");

			goto next_phy;
		}

		/*
		 * Step 3: Abort all I/Os to the device
		 */
		if (pptr->abort_all_start) {
			while (pptr->abort_all_start) {
				pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, tgt,
				    "%s: Waiting for outstanding ABORT_ALL on "
				    "PHY 0x%p", __func__, (void *)pptr);
				cv_wait(&pptr->abort_all_cv, &pptr->phy_lock);
			}
		} else {
			mutex_exit(&tgt->statlock);
			rc = pmcs_abort(pwp, pptr, pptr->device_id, 1, 1);
			mutex_enter(&tgt->statlock);
			if (rc != 0) {
				pptr->abort_pending = 1;
				pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, tgt,
				    "%s: pmcs_abort to PHY %s failed (rc=%d)",
				    __func__, pptr->path, rc);

				pmcs_handle_ds_recovery_error(pptr, tgt,
				    pwp, __func__, __LINE__, "pmcs_abort");

				goto next_phy;
			}
		}

		/*
		 * Step 4: Set the device back to OPERATIONAL state
		 */
		pmcs_prt(pwp, PMCS_PRT_DEBUG_DEV_STATE, pptr, tgt,
		    "%s: Set PHY/tgt 0x%p/0x%p to OPERATIONAL state",
		    __func__, (void *)pptr, (void *)tgt);
		rc = pmcs_set_dev_state(pwp, tgt,
		    PMCS_DEVICE_STATE_OPERATIONAL);
		if (rc == 0) {
			tgt->recover_wait = 0;
			pptr->ds_recovery_retries = 0;
			/*
			 * Don't bother to run the work queues if the PHY
			 * is dead.
			 */
			if (tgt->phy && !tgt->phy->dead) {
				SCHEDULE_WORK(pwp, PMCS_WORK_RUN_QUEUES);
				(void) ddi_taskq_dispatch(pwp->tq, pmcs_worker,
				    pwp, DDI_NOSLEEP);
			}
		} else {
			pmcs_prt(pwp, PMCS_PRT_DEBUG_DEV_STATE, pptr, tgt,
			    "%s: Failed to SET tgt 0x%p to OPERATIONAL state",
			    __func__, (void *)tgt);

			pmcs_handle_ds_recovery_error(pptr, tgt, pwp,
			    __func__, __LINE__, "SET tgt to OPERATIONAL state");

			goto next_phy;
		}

next_phy:
		if (tgt) {
			mutex_exit(&tgt->statlock);
		}
		pmcs_unlock_phy(pptr);
		pptr = pnext;
	}

	/*
	 * Only clear ds_err_recovering if we're exiting for good and not
	 * just unwinding from recursion
	 */
	if (phyp == NULL) {
		mutex_enter(&pwp->lock);
		pwp->ds_err_recovering = 0;
		mutex_exit(&pwp->lock);
	}
}

/*
 * Called with target's statlock and PHY lock held.
 */
int
pmcs_send_err_recovery_cmd(pmcs_hw_t *pwp, uint8_t dev_state, pmcs_xscsi_t *tgt)
{
	pmcs_phy_t *pptr;
	int rc = -1;

	ASSERT(tgt != NULL);
	ASSERT(mutex_owned(&tgt->statlock));

	if (tgt->recovering) {
		return (0);
	}

	tgt->recovering = 1;
	pptr = tgt->phy;

	if (pptr == NULL) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG_DEV_STATE, pptr, tgt,
		    "%s: PHY is Null", __func__);
		return (-1);
	}

	ASSERT(mutex_owned(&pptr->phy_lock));

	pmcs_prt(pwp, PMCS_PRT_DEBUG_DEV_STATE, pptr, tgt,
	    "%s: ds: 0x%x, tgt ds(0x%x)", __func__, dev_state, tgt->dev_state);

	switch (dev_state) {
	case PMCS_DEVICE_STATE_IN_RECOVERY:
		if (tgt->dev_state == PMCS_DEVICE_STATE_IN_RECOVERY) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG_DEV_STATE, pptr, tgt,
			    "%s: Target 0x%p already IN_RECOVERY", __func__,
			    (void *)tgt);
			rc = 0;	/* This is not an error */
			goto no_action;
		}

		rc = pmcs_set_dev_state(pwp, tgt,
		    PMCS_DEVICE_STATE_IN_RECOVERY);
		if (rc != 0) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG_DEV_STATE, pptr, tgt,
			    "%s(1): Failed to SET tgt(0x%p) to _IN_RECOVERY",
			    __func__, (void *)tgt);
		}

		break;

	case PMCS_DEVICE_STATE_OPERATIONAL:
		if (tgt->dev_state != PMCS_DEVICE_STATE_IN_RECOVERY) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG_DEV_STATE, pptr, tgt,
			    "%s: Target 0x%p not ready to go OPERATIONAL",
			    __func__, (void *)tgt);
			goto no_action;
		}

		rc = pmcs_set_dev_state(pwp, tgt,
		    PMCS_DEVICE_STATE_OPERATIONAL);
		tgt->reset_success = 1;
		if (rc != 0) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG_DEV_STATE, pptr, tgt,
			    "%s(2): Failed to SET tgt(0x%p) to OPERATIONAL",
			    __func__, (void *)tgt);
			tgt->reset_success = 0;
		}

		break;

	case PMCS_DEVICE_STATE_NON_OPERATIONAL:
		PHY_CHANGED(pwp, pptr);
		RESTART_DISCOVERY(pwp);
		pmcs_prt(pwp, PMCS_PRT_DEBUG_DEV_STATE, pptr, tgt,
		    "%s: Device at %s is non-operational",
		    __func__, pptr->path);
		tgt->dev_state = PMCS_DEVICE_STATE_NON_OPERATIONAL;
		rc = 0;

		break;

	default:
		pmcs_prt(pwp, PMCS_PRT_DEBUG_DEV_STATE, pptr, tgt,
		    "%s: Invalid state requested (%d)", __func__,
		    dev_state);
		break;

	}

no_action:
	tgt->recovering = 0;
	return (rc);
}

/*
 * pmcs_lock_phy_impl
 *
 * This function is what does the actual work for pmcs_lock_phy.  It will
 * lock all PHYs from phyp down in a top-down fashion.
 *
 * Locking notes:
 * 1. level starts from 0 for the PHY ("parent") that's passed in.  It is
 * not a reflection of the actual level of the PHY in the SAS topology.
 * 2. If parent is an expander, then parent is locked along with all its
 * descendents.
 * 3. Expander subsidiary PHYs at level 0 are not locked.  It is the
 * responsibility of the caller to individually lock expander subsidiary PHYs
 * at level 0 if necessary.
 * 4. Siblings at level 0 are not traversed due to the possibility that we're
 * locking a PHY on the dead list.  The siblings could be pointing to invalid
 * PHYs.  We don't lock siblings at level 0 anyway.
 */
static void
pmcs_lock_phy_impl(pmcs_phy_t *phyp, int level)
{
	pmcs_phy_t *tphyp;

	ASSERT((phyp->dtype == SAS) || (phyp->dtype == SATA) ||
	    (phyp->dtype == EXPANDER) || (phyp->dtype == NOTHING));

	/*
	 * Start walking the PHYs.
	 */
	tphyp = phyp;
	while (tphyp) {
		/*
		 * If we're at the top level, only lock ourselves.  For anything
		 * at level > 0, traverse children while locking everything.
		 */
		if ((level > 0) || (tphyp == phyp)) {
			pmcs_prt(tphyp->pwp, PMCS_PRT_DEBUG_PHY_LOCKING, tphyp,
			    NULL, "%s: PHY 0x%p parent 0x%p path %s lvl %d",
			    __func__, (void *)tphyp, (void *)tphyp->parent,
			    tphyp->path, level);
			mutex_enter(&tphyp->phy_lock);

			if (tphyp->children) {
				pmcs_lock_phy_impl(tphyp->children, level + 1);
			}
		}

		if (level == 0) {
			return;
		}

		tphyp = tphyp->sibling;
	}
}

/*
 * pmcs_lock_phy
 *
 * This function is responsible for locking a PHY and all its descendents
 */
void
pmcs_lock_phy(pmcs_phy_t *phyp)
{
#ifdef DEBUG
	char *callername = NULL;
	ulong_t off;

	ASSERT(phyp != NULL);

	callername = modgetsymname((uintptr_t)caller(), &off);

	if (callername == NULL) {
		pmcs_prt(phyp->pwp, PMCS_PRT_DEBUG_PHY_LOCKING, phyp, NULL,
		    "%s: PHY 0x%p path %s caller: unknown", __func__,
		    (void *)phyp, phyp->path);
	} else {
		pmcs_prt(phyp->pwp, PMCS_PRT_DEBUG_PHY_LOCKING, phyp, NULL,
		    "%s: PHY 0x%p path %s caller: %s+%lx", __func__,
		    (void *)phyp, phyp->path, callername, off);
	}
#else
	pmcs_prt(phyp->pwp, PMCS_PRT_DEBUG_PHY_LOCKING, phyp, NULL,
	    "%s: PHY 0x%p path %s", __func__, (void *)phyp, phyp->path);
#endif
	pmcs_lock_phy_impl(phyp, 0);
}

/*
 * pmcs_unlock_phy_impl
 *
 * Unlock all PHYs from phyp down in a bottom-up fashion.
 */
static void
pmcs_unlock_phy_impl(pmcs_phy_t *phyp, int level)
{
	pmcs_phy_t *phy_next;

	ASSERT((phyp->dtype == SAS) || (phyp->dtype == SATA) ||
	    (phyp->dtype == EXPANDER) || (phyp->dtype == NOTHING));

	/*
	 * Recurse down to the bottom PHYs
	 */
	if (level == 0) {
		if (phyp->children) {
			pmcs_unlock_phy_impl(phyp->children, level + 1);
		}
	} else {
		phy_next = phyp;
		while (phy_next) {
			if (phy_next->children) {
				pmcs_unlock_phy_impl(phy_next->children,
				    level + 1);
			}
			phy_next = phy_next->sibling;
		}
	}

	/*
	 * Iterate through PHYs unlocking all at level > 0 as well the top PHY
	 */
	phy_next = phyp;
	while (phy_next) {
		if ((level > 0) || (phy_next == phyp)) {
			pmcs_prt(phy_next->pwp, PMCS_PRT_DEBUG_PHY_LOCKING,
			    phy_next, NULL,
			    "%s: PHY 0x%p parent 0x%p path %s lvl %d",
			    __func__, (void *)phy_next,
			    (void *)phy_next->parent, phy_next->path, level);
			mutex_exit(&phy_next->phy_lock);
		}

		if (level == 0) {
			return;
		}

		phy_next = phy_next->sibling;
	}
}

/*
 * pmcs_unlock_phy
 *
 * Unlock a PHY and all its descendents
 */
void
pmcs_unlock_phy(pmcs_phy_t *phyp)
{
#ifdef DEBUG
	char *callername = NULL;
	ulong_t off;

	ASSERT(phyp != NULL);

	callername = modgetsymname((uintptr_t)caller(), &off);

	if (callername == NULL) {
		pmcs_prt(phyp->pwp, PMCS_PRT_DEBUG_PHY_LOCKING, phyp, NULL,
		    "%s: PHY 0x%p path %s caller: unknown", __func__,
		    (void *)phyp, phyp->path);
	} else {
		pmcs_prt(phyp->pwp, PMCS_PRT_DEBUG_PHY_LOCKING, phyp, NULL,
		    "%s: PHY 0x%p path %s caller: %s+%lx", __func__,
		    (void *)phyp, phyp->path, callername, off);
	}
#else
	pmcs_prt(phyp->pwp, PMCS_PRT_DEBUG_PHY_LOCKING, phyp, NULL,
	    "%s: PHY 0x%p path %s", __func__, (void *)phyp, phyp->path);
#endif
	pmcs_unlock_phy_impl(phyp, 0);
}

/*
 * pmcs_get_root_phy
 *
 * For a given phy pointer return its root phy.
 * The caller must be holding the lock on every PHY from phyp up to the root.
 */
pmcs_phy_t *
pmcs_get_root_phy(pmcs_phy_t *phyp)
{
	ASSERT(phyp);

	while (phyp) {
		if (IS_ROOT_PHY(phyp)) {
			break;
		}
		phyp = phyp->parent;
	}

	return (phyp);
}

/*
 * pmcs_free_dma_chunklist
 *
 * Free DMA S/G chunk list
 */
void
pmcs_free_dma_chunklist(pmcs_hw_t *pwp)
{
	pmcs_chunk_t	*pchunk;

	while (pwp->dma_chunklist) {
		pchunk = pwp->dma_chunklist;
		pwp->dma_chunklist = pwp->dma_chunklist->next;
		if (pchunk->dma_handle) {
			if (ddi_dma_unbind_handle(pchunk->dma_handle) !=
			    DDI_SUCCESS) {
				pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
				    "Condition failed at %s():%d",
				    __func__, __LINE__);
			}
			ddi_dma_free_handle(&pchunk->dma_handle);
			ddi_dma_mem_free(&pchunk->acc_handle);
		}
		kmem_free(pchunk, sizeof (pmcs_chunk_t));
	}
}


/*
 * Start ssp event recovery. We have to schedule recovery operation because
 * it involves sending multiple commands to device and we should not do it
 * in the interrupt context.
 * If it is failure of a recovery command, let the recovery thread deal with it.
 * Called with pmcwork lock held.
 */

void
pmcs_start_ssp_event_recovery(pmcs_hw_t *pwp, pmcwork_t *pwrk, uint32_t *iomb,
    size_t amt)
{
	pmcs_xscsi_t *tgt = pwrk->xp;
	uint32_t event = LE_32(iomb[2]);
	pmcs_phy_t *pptr = pwrk->phy;
	uint32_t tag;

	if (tgt != NULL) {
		mutex_enter(&tgt->statlock);
		if (!tgt->assigned) {
			if (pptr) {
				pmcs_dec_phy_ref_count(pptr);
			}
			pptr = NULL;
			pwrk->phy = NULL;
		}
		mutex_exit(&tgt->statlock);
	}
	if (pptr == NULL) {
		/*
		 * No target, need to run RE-DISCOVERY here.
		 */
		if (pwrk->state != PMCS_WORK_STATE_TIMED_OUT) {
			pwrk->state = PMCS_WORK_STATE_INTR;
		}
		/*
		 * Although we cannot mark phy to force abort nor mark phy
		 * as changed, killing of a target would take care of aborting
		 * commands for the device.
		 */
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: No valid target for event processing found. "
		    "Scheduling RECONFIGURE",  __func__);
		pmcs_pwork(pwp, pwrk);
		RESTART_DISCOVERY(pwp);
		return;
	} else {
		pmcs_lock_phy(pptr);
		mutex_enter(&tgt->statlock);
		if (event == PMCOUT_STATUS_OPEN_CNX_ERROR_IT_NEXUS_LOSS) {
			if (tgt->dev_state !=
			    PMCS_DEVICE_STATE_NON_OPERATIONAL) {
				pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, tgt,
				    "%s: Device at %s is non-operational",
				    __func__, pptr->path);
				tgt->dev_state =
				    PMCS_DEVICE_STATE_NON_OPERATIONAL;
			}
			pptr->abort_pending = 1;
			mutex_exit(&tgt->statlock);
			pmcs_unlock_phy(pptr);
			mutex_exit(&pwrk->lock);
			SCHEDULE_WORK(pwp, PMCS_WORK_ABORT_HANDLE);
			RESTART_DISCOVERY(pwp);
			return;
		}

		/*
		 * If this command is run in WAIT mode, it is a failing recovery
		 * command. If so, just wake up recovery thread waiting for
		 * command completion.
		 */
		tag = PMCS_TAG_TYPE(pwrk->htag);
		if (tag == PMCS_TAG_TYPE_WAIT) {
			pwrk->htag |= PMCS_TAG_DONE;
			if (pwrk->arg && amt) {
				(void) memcpy(pwrk->arg, iomb, amt);
			}
			cv_signal(&pwrk->sleep_cv);
			mutex_exit(&tgt->statlock);
			pmcs_unlock_phy(pptr);
			mutex_exit(&pwrk->lock);
			return;
		}

		/*
		 * To recover from primary failures,
		 * we need to schedule handling events recovery.
		 */
		tgt->event_recovery = 1;
		mutex_exit(&tgt->statlock);
		pmcs_unlock_phy(pptr);
		pwrk->ssp_event = event;
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, tgt,
		    "%s: Scheduling SSP event recovery for tgt(0x%p) "
		    "pwrk(%p) tag(0x%x)", __func__, (void *)tgt, (void *)pwrk,
		    pwrk->htag);
		mutex_exit(&pwrk->lock);
		SCHEDULE_WORK(pwp, PMCS_WORK_SSP_EVT_RECOVERY);
	}

	/* Work cannot be completed until event recovery is completed. */
}

/*
 * SSP target event recovery
 * Entered with a phy lock held
 * Pwrk lock is not needed - pwrk is on the target aq and no other thread
 * will do anything with it until this thread starts the chain of recovery.
 * Statlock may be acquired and released.
 */

void
pmcs_tgt_event_recovery(pmcs_hw_t *pwp, pmcwork_t *pwrk)
{
	pmcs_phy_t *pptr = pwrk->phy;
	pmcs_cmd_t *sp = pwrk->arg;
	pmcs_lun_t *lun = sp->cmd_lun;
	pmcs_xscsi_t *tgt = pwrk->xp;
	uint32_t event;
	uint32_t htag;
	uint32_t status;
	uint8_t dstate;
	int rv;

	ASSERT(pwrk->arg != NULL);
	ASSERT(pwrk->xp != NULL);
	pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, tgt, "%s: event recovery for "
	    "target 0x%p", __func__, (void *)pwrk->xp);
	htag = pwrk->htag;
	event = pwrk->ssp_event;
	pwrk->ssp_event = 0xffffffff;
	if (event == PMCOUT_STATUS_XFER_ERR_BREAK ||
	    event == PMCOUT_STATUS_XFER_ERR_PHY_NOT_READY ||
	    event == PMCOUT_STATUS_XFER_ERROR_CMD_ISSUE_ACK_NAK_TIMEOUT) {
		/* Command may be still pending on device */
		rv = pmcs_ssp_tmf(pwp, pptr, SAS_QUERY_TASK, htag,
		    lun->lun_num, &status);
		if (rv != 0) {
			goto out;
		}
		if (status == SAS_RSP_TMF_COMPLETE) {
			/* Command NOT pending on a device */
			pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, tgt,
			    "%s: No pending command for tgt 0x%p",
			    __func__, (void *)tgt);
			/* Nothing more to do, just abort it on chip */
			htag = 0;
		}
	}
	/*
	 * All other events left the command pending in the host
	 * Send abort task and abort it on the chip
	 */
	if (htag != 0) {
		if (pmcs_ssp_tmf(pwp, pptr, SAS_ABORT_TASK, htag,
		    lun->lun_num, &status))
			goto out;
	}
	(void) pmcs_abort(pwp, pptr, pwrk->htag, 0, 1);
	/*
	 * Abort either took care of work completion, or put device in
	 * a recovery state
	 */
	return;
out:
	/* Abort failed, do full device recovery */
	mutex_enter(&tgt->statlock);
	if (!pmcs_get_dev_state(pwp, tgt, &dstate))
		tgt->dev_state = dstate;

	if ((tgt->dev_state != PMCS_DEVICE_STATE_IN_RECOVERY) &&
	    (tgt->dev_state != PMCS_DEVICE_STATE_NON_OPERATIONAL)) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, tgt,
		    "%s: Setting IN_RECOVERY for tgt 0x%p",
		    __func__, (void *)tgt);
		(void) pmcs_send_err_recovery_cmd(pwp,
		    PMCS_DEVICE_STATE_IN_RECOVERY, tgt);
	}
	mutex_exit(&tgt->statlock);
}

/*
 * SSP event recovery task.
 */
void
pmcs_ssp_event_recovery(pmcs_hw_t *pwp)
{
	int idx;
	pmcs_xscsi_t *tgt;
	pmcs_cmd_t *cp;
	pmcwork_t *pwrk;
	pmcs_phy_t *pphy;
	int er_flag;
	uint32_t idxpwrk;

restart:
	for (idx = 0; idx < pwp->max_dev; idx++) {
		mutex_enter(&pwp->lock);
		tgt = pwp->targets[idx];
		mutex_exit(&pwp->lock);
		if (tgt != NULL) {
			mutex_enter(&tgt->statlock);
			if (!tgt->assigned) {
				mutex_exit(&tgt->statlock);
				continue;
			}
			pphy = tgt->phy;
			er_flag = tgt->event_recovery;
			mutex_exit(&tgt->statlock);
			if (pphy != NULL && er_flag != 0) {
				pmcs_lock_phy(pphy);
				mutex_enter(&tgt->statlock);
				pmcs_prt(pwp, PMCS_PRT_DEBUG, pphy, tgt,
				    "%s: found target(0x%p)", __func__,
				    (void *) tgt);

				/* Check what cmd expects recovery */
				mutex_enter(&tgt->aqlock);
				STAILQ_FOREACH(cp, &tgt->aq, cmd_next) {
					/*
					 * Since work structure is on this
					 * target aq, and only this thread
					 * is accessing it now, we do not need
					 * to lock it
					 */
					idxpwrk = PMCS_TAG_INDEX(cp->cmd_tag);
					pwrk = &pwp->work[idxpwrk];
					if (pwrk->htag != cp->cmd_tag) {
						/*
						 * aq may contain TMF commands,
						 * so we may not find work
						 * structure with htag
						 */
						break;
					}
					if (pwrk->ssp_event != 0 &&
					    pwrk->ssp_event !=
					    PMCS_REC_EVENT) {
						pmcs_prt(pwp,
						    PMCS_PRT_DEBUG, pphy, tgt,
						    "%s: pwrk(%p) ctag(0x%x)",
						    __func__, (void *) pwrk,
						    cp->cmd_tag);
						mutex_exit(&tgt->aqlock);
						mutex_exit(&tgt->statlock);
						pmcs_tgt_event_recovery(
						    pwp, pwrk);
						/*
						 * We dropped statlock, so
						 * restart scanning from scratch
						 */
						pmcs_unlock_phy(pphy);
						goto restart;
					}
				}
				mutex_exit(&tgt->aqlock);
				tgt->event_recovery = 0;
				pmcs_prt(pwp, PMCS_PRT_DEBUG, pphy, tgt,
				    "%s: end of SSP event recovery for "
				    "target(0x%p)", __func__, (void *) tgt);
				mutex_exit(&tgt->statlock);
				pmcs_unlock_phy(pphy);
			}
		}
	}
	pmcs_prt(pwp, PMCS_PRT_DEBUG, pphy, tgt, "%s: "
	    "end of SSP event recovery for pwp(0x%p)", __func__, (void *) pwp);
}

/*ARGSUSED2*/
int
pmcs_phy_constructor(void *buf, void *arg, int kmflags)
{
	pmcs_hw_t *pwp = (pmcs_hw_t *)arg;
	pmcs_phy_t *phyp = (pmcs_phy_t *)buf;

	mutex_init(&phyp->phy_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(pwp->intr_pri));
	cv_init(&phyp->abort_all_cv, NULL, CV_DRIVER, NULL);
	return (0);
}

/*ARGSUSED1*/
void
pmcs_phy_destructor(void *buf, void *arg)
{
	pmcs_phy_t *phyp = (pmcs_phy_t *)buf;

	cv_destroy(&phyp->abort_all_cv);
	mutex_destroy(&phyp->phy_lock);
}

/*
 * Free all PHYs from the kmem_cache starting at phyp as well as everything
 * on the dead_phys list.
 *
 * NOTE: This function does not free root PHYs as they are not allocated
 * from the kmem_cache.
 *
 * No PHY locks are acquired as this should only be called during DDI_DETACH
 * or soft reset (while pmcs interrupts are disabled).
 */
void
pmcs_free_all_phys(pmcs_hw_t *pwp, pmcs_phy_t *phyp)
{
	pmcs_phy_t *tphyp, *nphyp;

	if (phyp == NULL) {
		return;
	}

	tphyp = phyp;
	while (tphyp) {
		nphyp = tphyp->sibling;

		if (tphyp->children) {
			pmcs_free_all_phys(pwp, tphyp->children);
			tphyp->children = NULL;
		}
		if (!IS_ROOT_PHY(tphyp)) {
			kmem_cache_free(pwp->phy_cache, tphyp);
		}

		tphyp = nphyp;
	}

	tphyp = pwp->dead_phys;
	while (tphyp) {
		nphyp = tphyp->sibling;
		kmem_cache_free(pwp->phy_cache, tphyp);
		tphyp = nphyp;
	}
	pwp->dead_phys = NULL;
}

/*
 * Free a list of PHYs linked together by the sibling pointer back to the
 * kmem cache from whence they came.  This function does not recurse, so the
 * caller must ensure there are no children.
 */
void
pmcs_free_phys(pmcs_hw_t *pwp, pmcs_phy_t *phyp)
{
	pmcs_phy_t *next_phy;

	while (phyp) {
		next_phy = phyp->sibling;
		ASSERT(!mutex_owned(&phyp->phy_lock));
		kmem_cache_free(pwp->phy_cache, phyp);
		phyp = next_phy;
	}
}

/*
 * Make a copy of an existing PHY structure.  This is used primarily in
 * discovery to compare the contents of an existing PHY with what gets
 * reported back by an expander.
 *
 * This function must not be called from any context where sleeping is
 * not possible.
 *
 * The new PHY is returned unlocked.
 */
static pmcs_phy_t *
pmcs_clone_phy(pmcs_phy_t *orig_phy)
{
	pmcs_phy_t *local;

	local = kmem_cache_alloc(orig_phy->pwp->phy_cache, KM_SLEEP);

	/*
	 * Go ahead and just copy everything...
	 */
	*local = *orig_phy;

	/*
	 * But the following must be set appropriately for this copy
	 */
	local->sibling = NULL;
	local->children = NULL;
	mutex_init(&local->phy_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(orig_phy->pwp->intr_pri));

	return (local);
}

int
pmcs_check_acc_handle(ddi_acc_handle_t handle)
{
	ddi_fm_error_t de;

	if (handle == NULL) {
		return (DDI_FAILURE);
	}
	ddi_fm_acc_err_get(handle, &de, DDI_FME_VER0);
	return (de.fme_status);
}

int
pmcs_check_dma_handle(ddi_dma_handle_t handle)
{
	ddi_fm_error_t de;

	if (handle == NULL) {
		return (DDI_FAILURE);
	}
	ddi_fm_dma_err_get(handle, &de, DDI_FME_VER0);
	return (de.fme_status);
}


void
pmcs_fm_ereport(pmcs_hw_t *pwp, char *detail)
{
	uint64_t ena;
	char buf[FM_MAX_CLASS];

	(void) snprintf(buf, FM_MAX_CLASS, "%s.%s", DDI_FM_DEVICE, detail);
	ena = fm_ena_generate(0, FM_ENA_FMT1);
	if (DDI_FM_EREPORT_CAP(pwp->fm_capabilities)) {
		ddi_fm_ereport_post(pwp->dip, buf, ena, DDI_NOSLEEP,
		    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0, NULL);
	}
}

int
pmcs_check_acc_dma_handle(pmcs_hw_t *pwp)
{
	pmcs_chunk_t *pchunk;
	int i;

	/* check all acc & dma handles allocated in attach */
	if ((pmcs_check_acc_handle(pwp->pci_acc_handle) != DDI_SUCCESS) ||
	    (pmcs_check_acc_handle(pwp->msg_acc_handle) != DDI_SUCCESS) ||
	    (pmcs_check_acc_handle(pwp->top_acc_handle) != DDI_SUCCESS) ||
	    (pmcs_check_acc_handle(pwp->mpi_acc_handle) != DDI_SUCCESS) ||
	    (pmcs_check_acc_handle(pwp->gsm_acc_handle) != DDI_SUCCESS)) {
		goto check_failed;
	}

	for (i = 0; i < PMCS_NIQ; i++) {
		if ((pmcs_check_dma_handle(
		    pwp->iqp_handles[i]) != DDI_SUCCESS) ||
		    (pmcs_check_acc_handle(
		    pwp->iqp_acchdls[i]) != DDI_SUCCESS)) {
			goto check_failed;
		}
	}

	for (i = 0; i < PMCS_NOQ; i++) {
		if ((pmcs_check_dma_handle(
		    pwp->oqp_handles[i]) != DDI_SUCCESS) ||
		    (pmcs_check_acc_handle(
		    pwp->oqp_acchdls[i]) != DDI_SUCCESS)) {
			goto check_failed;
		}
	}

	if ((pmcs_check_dma_handle(pwp->cip_handles) != DDI_SUCCESS) ||
	    (pmcs_check_acc_handle(pwp->cip_acchdls) != DDI_SUCCESS)) {
		goto check_failed;
	}

	if (pwp->fwlog &&
	    ((pmcs_check_dma_handle(pwp->fwlog_hndl) != DDI_SUCCESS) ||
	    (pmcs_check_acc_handle(pwp->fwlog_acchdl) != DDI_SUCCESS))) {
		goto check_failed;
	}

	if (pwp->regdump_hndl && pwp->regdump_acchdl &&
	    ((pmcs_check_dma_handle(pwp->regdump_hndl) != DDI_SUCCESS) ||
	    (pmcs_check_acc_handle(pwp->regdump_acchdl)
	    != DDI_SUCCESS))) {
		goto check_failed;
	}


	pchunk = pwp->dma_chunklist;
	while (pchunk) {
		if ((pmcs_check_acc_handle(pchunk->acc_handle)
		    != DDI_SUCCESS) ||
		    (pmcs_check_dma_handle(pchunk->dma_handle)
		    != DDI_SUCCESS)) {
			goto check_failed;
		}
		pchunk = pchunk->next;
	}

	return (0);

check_failed:

	return (1);
}

/*
 * pmcs_handle_dead_phys
 *
 * If the PHY has no outstanding work associated with it, remove it from
 * the dead PHY list and free it.
 *
 * If pwp->ds_err_recovering or pwp->configuring is set, don't run.
 * This keeps routines that need to submit work to the chip from having to
 * hold PHY locks to ensure that PHYs don't disappear while they do their work.
 */
void
pmcs_handle_dead_phys(pmcs_hw_t *pwp)
{
	pmcs_phy_t *phyp, *nphyp, *pphyp;

	mutex_enter(&pwp->lock);
	mutex_enter(&pwp->config_lock);

	if (pwp->configuring | pwp->ds_err_recovering) {
		mutex_exit(&pwp->config_lock);
		mutex_exit(&pwp->lock);
		return;
	}

	/*
	 * Check every PHY in the dead PHY list
	 */
	mutex_enter(&pwp->dead_phylist_lock);
	phyp = pwp->dead_phys;
	pphyp = NULL;	/* Set previous PHY to NULL */

	while (phyp != NULL) {
		pmcs_lock_phy(phyp);
		ASSERT(phyp->dead);

		nphyp = phyp->dead_next;

		/*
		 * Check for outstanding work
		 */
		if (phyp->ref_count > 0) {
			pmcs_unlock_phy(phyp);
			pphyp = phyp;	/* This PHY becomes "previous" */
		} else if (phyp->target) {
			pmcs_unlock_phy(phyp);
			pmcs_prt(pwp, PMCS_PRT_DEBUG1, phyp, phyp->target,
			    "%s: Not freeing PHY 0x%p: target 0x%p is not free",
			    __func__, (void *)phyp, (void *)phyp->target);
			pphyp = phyp;
		} else {
			/*
			 * No outstanding work or target references. Remove it
			 * from the list and free it
			 */
			pmcs_prt(pwp, PMCS_PRT_DEBUG, phyp, phyp->target,
			    "%s: Freeing inactive dead PHY 0x%p @ %s "
			    "target = 0x%p", __func__, (void *)phyp,
			    phyp->path, (void *)phyp->target);
			/*
			 * If pphyp is NULL, then phyp was the head of the list,
			 * so just reset the head to nphyp. Otherwise, the
			 * previous PHY will now point to nphyp (the next PHY)
			 */
			if (pphyp == NULL) {
				pwp->dead_phys = nphyp;
			} else {
				pphyp->dead_next = nphyp;
			}
			/*
			 * If the target still points to this PHY, remove
			 * that linkage now.
			 */
			if (phyp->target) {
				mutex_enter(&phyp->target->statlock);
				if (phyp->target->phy == phyp) {
					phyp->target->phy = NULL;
				}
				mutex_exit(&phyp->target->statlock);
			}
			pmcs_unlock_phy(phyp);
			kmem_cache_free(pwp->phy_cache, phyp);
		}

		phyp = nphyp;
	}

	mutex_exit(&pwp->dead_phylist_lock);
	mutex_exit(&pwp->config_lock);
	mutex_exit(&pwp->lock);
}

void
pmcs_inc_phy_ref_count(pmcs_phy_t *phyp)
{
	atomic_inc_32(&phyp->ref_count);
}

void
pmcs_dec_phy_ref_count(pmcs_phy_t *phyp)
{
	ASSERT(phyp->ref_count != 0);
	atomic_dec_32(&phyp->ref_count);
}

/*
 * pmcs_reap_dead_phy
 *
 * This function is called from pmcs_new_tport when we have a PHY
 * without a target pointer.  It's possible in that case that this PHY
 * may have a "brother" on the dead_phys list.  That is, it may be the same as
 * this one but with a different root PHY number (e.g. pp05 vs. pp04).  If
 * that's the case, update the dead PHY and this new PHY.  If that's not the
 * case, we should get a tran_tgt_init on this after it's reported to SCSA.
 *
 * Called with PHY locked.
 */
static void
pmcs_reap_dead_phy(pmcs_phy_t *phyp)
{
	pmcs_hw_t *pwp = phyp->pwp;
	pmcs_phy_t *ctmp;

	ASSERT(mutex_owned(&phyp->phy_lock));

	/*
	 * Check the dead PHYs list
	 */
	mutex_enter(&pwp->dead_phylist_lock);
	ctmp = pwp->dead_phys;
	while (ctmp) {
		if ((ctmp->iport != phyp->iport) ||
		    (memcmp((void *)&ctmp->sas_address[0],
		    (void *)&phyp->sas_address[0], 8))) {
			ctmp = ctmp->dead_next;
			continue;
		}

		/*
		 * Same SAS address on same iport.  Now check to see if
		 * the PHY path is the same with the possible exception
		 * of the root PHY number.
		 * The "5" is the string length of "pp00."
		 */
		if ((strnlen(phyp->path, 5) >= 5) &&
		    (strnlen(ctmp->path, 5) >= 5)) {
			if (memcmp((void *)&phyp->path[5],
			    (void *)&ctmp->path[5],
			    strnlen(phyp->path, 32) - 5) == 0) {
				break;
			}
		}

		ctmp = ctmp->dead_next;
	}
	mutex_exit(&pwp->dead_phylist_lock);

	/*
	 * Found a match.  Remove the target linkage and drop the
	 * ref count on the old PHY.  Then, increment the ref count
	 * on the new PHY to compensate.
	 */
	if (ctmp) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, ctmp, NULL,
		    "%s: Found match in dead PHY list for new PHY %s",
		    __func__, phyp->path);
		if (ctmp->target) {
			/*
			 * If there is a pointer to the target in the dead
			 * PHY, and that PHY's ref_count drops to 0, we can
			 * clear the target linkage now.  If the PHY's
			 * ref_count is > 1, then there may be multiple
			 * LUNs still remaining, so leave the linkage.
			 */
			pmcs_inc_phy_ref_count(phyp);
			pmcs_dec_phy_ref_count(ctmp);
			phyp->target = ctmp->target;
			/*
			 * Update the target's linkage as well
			 */
			mutex_enter(&phyp->target->statlock);
			phyp->target->phy = phyp;
			phyp->target->dtype = phyp->dtype;
			mutex_exit(&phyp->target->statlock);

			if (ctmp->ref_count == 0) {
				ctmp->target = NULL;
			}
		}
	}
}

/*
 * Called with iport lock held
 */
void
pmcs_add_phy_to_iport(pmcs_iport_t *iport, pmcs_phy_t *phyp)
{
	ASSERT(mutex_owned(&iport->lock));
	ASSERT(phyp);
	ASSERT(!list_link_active(&phyp->list_node));
	iport->nphy++;
	pmcs_smhba_add_iport_prop(iport, DATA_TYPE_INT32, PMCS_NUM_PHYS,
	    &iport->nphy);
	list_insert_tail(&iport->phys, phyp);
	mutex_enter(&iport->refcnt_lock);
	iport->refcnt++;
	mutex_exit(&iport->refcnt_lock);
}

/*
 * Called with the iport lock held
 */
void
pmcs_remove_phy_from_iport(pmcs_iport_t *iport, pmcs_phy_t *phyp)
{
	pmcs_phy_t *pptr, *next_pptr;

	ASSERT(mutex_owned(&iport->lock));

	/*
	 * If phyp is NULL, remove all PHYs from the iport
	 */
	if (phyp == NULL) {
		for (pptr = list_head(&iport->phys); pptr != NULL;
		    pptr = next_pptr) {
			next_pptr = list_next(&iport->phys, pptr);
			mutex_enter(&pptr->phy_lock);
			pptr->iport = NULL;
			mutex_exit(&pptr->phy_lock);
			pmcs_rele_iport(iport);
			list_remove(&iport->phys, pptr);
		}
		iport->nphy = 0;
		return;
	}

	ASSERT(phyp);
	ASSERT(iport->nphy > 0);
	ASSERT(list_link_active(&phyp->list_node));
	iport->nphy--;
	pmcs_smhba_add_iport_prop(iport, DATA_TYPE_INT32, PMCS_NUM_PHYS,
	    &iport->nphy);
	list_remove(&iport->phys, phyp);
	pmcs_rele_iport(iport);
}

/*
 * This function checks to see if the target pointed to by phyp is still
 * correct.  This is done by comparing the target's unit address with the
 * SAS address in phyp.
 *
 * Called with PHY locked and target statlock held
 */
static boolean_t
pmcs_phy_target_match(pmcs_phy_t *phyp)
{
	uint64_t wwn;
	char unit_address[PMCS_MAX_UA_SIZE];
	boolean_t rval = B_FALSE;

	ASSERT(phyp);
	ASSERT(phyp->target);
	ASSERT(mutex_owned(&phyp->phy_lock));
	ASSERT(mutex_owned(&phyp->target->statlock));

	wwn = pmcs_barray2wwn(phyp->sas_address);
	(void) scsi_wwn_to_wwnstr(wwn, 1, unit_address);

	if (memcmp((void *)unit_address, (void *)phyp->target->unit_address,
	    strnlen(phyp->target->unit_address, PMCS_MAX_UA_SIZE)) == 0) {
		rval = B_TRUE;
	}

	return (rval);
}

void
pmcs_start_dev_state_recovery(pmcs_xscsi_t *xp, pmcs_phy_t *phyp)
{
	ASSERT(mutex_owned(&xp->statlock));
	ASSERT(xp->pwp != NULL);

	if (xp->recover_wait == 0) {
		pmcs_prt(xp->pwp, PMCS_PRT_DEBUG_DEV_STATE, phyp, xp,
		    "%s: Start ds_recovery for tgt 0x%p/PHY 0x%p (%s)",
		    __func__, (void *)xp, (void *)phyp, phyp->path);
		xp->recover_wait = 1;

		/*
		 * Rather than waiting for the watchdog timer, we'll
		 * kick it right now.
		 */
		SCHEDULE_WORK(xp->pwp, PMCS_WORK_DS_ERR_RECOVERY);
		(void) ddi_taskq_dispatch(xp->pwp->tq, pmcs_worker, xp->pwp,
		    DDI_NOSLEEP);
	}
}

/*
 * Increment the phy ds error retry count.
 * If too many retries, mark phy dead and restart discovery;
 * otherwise schedule ds recovery.
 */
static void
pmcs_handle_ds_recovery_error(pmcs_phy_t *phyp, pmcs_xscsi_t *tgt,
    pmcs_hw_t *pwp, const char *func_name, int line, char *reason_string)
{
	ASSERT(mutex_owned(&phyp->phy_lock));

	phyp->ds_recovery_retries++;

	if (phyp->ds_recovery_retries > PMCS_MAX_DS_RECOVERY_RETRIES) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, phyp, tgt,
		    "%s: retry limit reached after %s to PHY %s failed",
		    func_name, reason_string, phyp->path);
		tgt->recover_wait = 0;
		phyp->dead = 1;
		PHY_CHANGED_AT_LOCATION(pwp, phyp, func_name, line);
		RESTART_DISCOVERY(pwp);
	} else {
		SCHEDULE_WORK(pwp, PMCS_WORK_DS_ERR_RECOVERY);
	}
}
