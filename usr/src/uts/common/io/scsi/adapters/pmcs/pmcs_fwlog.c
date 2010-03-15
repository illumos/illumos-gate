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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file contains firmware log routines.
 */

#include <sys/scsi/adapters/pmcs/pmcs.h>
#include <sys/scsi/adapters/pmcs/pmcs_fwlog.h>

static int pmcs_dump_ioqs(pmcs_hw_t *, caddr_t, uint32_t);
static int pmcs_dump_spc_ver(pmcs_hw_t *, caddr_t, uint32_t);
static int pmcs_dump_mpi_table(pmcs_hw_t *, caddr_t, uint32_t);
static int pmcs_dump_gsm_conf(pmcs_hw_t *, caddr_t, uint32_t);
static int pmcs_dump_pcie_conf(pmcs_hw_t *, caddr_t, uint32_t);
static uint32_t pmcs_get_axil(pmcs_hw_t *);
static boolean_t pmcs_shift_axil(pmcs_hw_t *, uint32_t);
static void pmcs_restore_axil(pmcs_hw_t *, uint32_t);
static int pmcs_dump_gsm(pmcs_hw_t *, caddr_t, uint32_t);
static int pmcs_dump_gsm_addiregs(pmcs_hw_t *, caddr_t, uint32_t);
static int pmcs_dump_hsst_sregs(pmcs_hw_t *, caddr_t, uint32_t);
static int pmcs_dump_sspa_sregs(pmcs_hw_t *, caddr_t, uint32_t);
static int pmcs_dump_fwlog(pmcs_hw_t *, caddr_t, uint32_t);
static void pmcs_write_fwlog(pmcs_hw_t *, pmcs_fw_event_hdr_t *);

/*
 * Dump internal registers. Used after a firmware crash.
 * Here dump various registers for firmware forensics,
 * including MPI, GSM configuration, firmware log, IO Queues etc.
 */
void
pmcs_register_dump_int(pmcs_hw_t *pwp)
{
	int n = 0;
	uint32_t size_left = 0;
	uint8_t slice = 0;
	caddr_t buf = NULL;

	pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
	    "pmcs%d: Internal register dump", ddi_get_instance(pwp->dip));
	ASSERT(mutex_owned(&pwp->lock));

	if (pwp->regdumpp == NULL) {
		pwp->regdumpp =
		    kmem_zalloc(PMCS_REG_DUMP_SIZE, KM_NOSLEEP);
		if (pwp->regdumpp == NULL) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
			    "%s: register dump memory not allocated", __func__);
			return;
		}
	}
	buf = pwp->regdumpp;
	size_left = PMCS_REG_DUMP_SIZE - 1;

	n = pmcs_dump_spc_ver(pwp, buf, size_left);
	ASSERT(size_left >= n);
	buf += n; size_left -= n;
	n = pmcs_dump_gsm_conf(pwp, buf, size_left);
	ASSERT(size_left >= n);
	buf += n; size_left -= n;
	n = pmcs_dump_pcie_conf(pwp, buf, size_left);
	ASSERT(size_left >= n);
	buf += n; size_left -= n;
	n = pmcs_dump_mpi_table(pwp, buf, size_left);
	ASSERT(size_left >= n);
	buf += n; size_left -= n;
	n = pmcs_dump_ioqs(pwp, buf, size_left);
	ASSERT(size_left >= n);
	buf += n; size_left -= n;

	if (pwp->state == STATE_DEAD) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: HBA dead, skipping AAP1/IOP registers and event logs",
		    __func__);
		goto skip_logs;
	}

	mutex_exit(&pwp->lock);
	slice = (PMCS_REGISTER_DUMP_FLASH_SIZE / PMCS_FLASH_CHUNK_SIZE);
	n = snprintf(buf, size_left, "\nDump AAP1 register: \n"
	    "-----------------\n");
	ASSERT(size_left >= n);
	buf += n; size_left -= n;
	for (uint8_t j = 0; j < slice; j++) {
		n = pmcs_get_nvmd(pwp, PMCS_NVMD_REG_DUMP,
		    PMCIN_NVMD_AAP1, (j * PMCS_FLASH_CHUNK_SIZE),
		    buf, size_left);
		if (n == PMCS_FLASH_CHUNK_SIZE) {
			ASSERT(size_left >= n);
			buf += n; size_left -= n;
		} else if ((n < PMCS_FLASH_CHUNK_SIZE) && (n > 0)) {
			ASSERT(size_left >= n);
			buf += n; size_left -= n;
			break;
		} else if (n == 0) {
			n = snprintf(buf, size_left, "AAP1: Content of "
			    "register dump on flash is NULL\n");
			ASSERT(size_left >= n);
			buf += n; size_left -= n;
			break;
		} else {
			n = snprintf(buf, size_left,
			    "AAP1: Unable to obtain internal register dump\n");
			ASSERT(size_left >= n);
			buf += n; size_left -= n;
			break;
		}

	}

	n = snprintf(buf, size_left, "\nDump IOP register: \n"
	    "-----------------\n");
	ASSERT(size_left >= n);
	buf += n; size_left -= n;
	for (uint8_t j = 0; j < slice; j++) {
		n = pmcs_get_nvmd(pwp, PMCS_NVMD_REG_DUMP,
		    PMCIN_NVMD_IOP, (j * PMCS_FLASH_CHUNK_SIZE),
		    buf, size_left);
		if (n == PMCS_FLASH_CHUNK_SIZE) {
			ASSERT(size_left >= n);
			buf += n; size_left -= n;
		} else if ((n < PMCS_FLASH_CHUNK_SIZE) && (n > 0)) {
			ASSERT(size_left >= n);
			buf += n; size_left -= n;
			break;
		} else if (n == 0) {
			n = snprintf(buf, size_left,
			    "IOP: Content of internal register dump is NULL\n");
			ASSERT(size_left >= n);
			buf += n; size_left -= n;
			break;
		} else {
			n = snprintf(buf, size_left,
			    "IOP: Unable to obtain internal register dump\n");
			ASSERT(size_left >= n);
			buf += n; size_left -= n;
			break;
		}

	}

	n = snprintf(buf, size_left, "\nDump AAP1 event log: \n"
	    "-----------------\n");
	ASSERT(size_left >= n);
	buf += n; size_left -= n;
	for (uint8_t j = 0; j < slice; j++) {
		n = pmcs_get_nvmd(pwp, PMCS_NVMD_EVENT_LOG,
		    PMCIN_NVMD_AAP1, (j * PMCS_FLASH_CHUNK_SIZE),
		    buf, size_left);
		if (n > 0) {
			ASSERT(size_left >= n);
			buf += n; size_left -= n;
		} else {
			n = snprintf(buf, size_left,
			    "AAP1: Unable to obtain event log on flash\n");
			ASSERT(size_left >= n);
			buf += n; size_left -= n;
			break;
		}
	}

	n = snprintf(buf, size_left, "\nDump IOP event log: \n"
	    "-----------------\n");
	ASSERT(size_left >= n);
	buf += n; size_left -= n;
	for (uint8_t j = 0; j < slice; j++) {
		n = pmcs_get_nvmd(pwp, PMCS_NVMD_EVENT_LOG,
		    PMCIN_NVMD_IOP, (j * PMCS_FLASH_CHUNK_SIZE),
		    buf, size_left);
		if (n > 0) {
			ASSERT(size_left >= n);
			buf += n; size_left -= n;
		} else {
			n = snprintf(buf, size_left,
			    "IOP: Unable to obtain event log dump\n");
			ASSERT(size_left >= n);
			buf += n; size_left -= n;
			break;
		}
	}
	mutex_enter(&pwp->lock);

skip_logs:
	n = pmcs_dump_gsm_addiregs(pwp, buf, size_left);
	ASSERT(size_left >= n);
	buf += n; size_left -= n;

	n = pmcs_dump_hsst_sregs(pwp, buf, size_left);
	ASSERT(size_left >= n);
	buf += n; size_left -= n;

	n = pmcs_dump_sspa_sregs(pwp, buf, size_left);
	ASSERT(size_left >= n);
	buf += n; size_left -= n;
	n = snprintf(buf, size_left, "\nDump firmware log: \n"
	    "-----------------\n");
	ASSERT(size_left >= n);
	buf += n; size_left -= n;

	n = pmcs_dump_fwlog(pwp, buf, size_left);
	ASSERT(size_left >= n);
	buf += n; size_left -= n;

	n = pmcs_dump_gsm(pwp, buf, size_left);
	ASSERT(size_left >= n);
	buf += n; size_left -= n;

	n = snprintf(buf, size_left, "-----------------\n"
	    "\n------------ Dump internal registers end  -------------\n");
	ASSERT(size_left >= n);
	buf += n; size_left -= n;
}

static int
pmcs_dump_fwlog(pmcs_hw_t *pwp, caddr_t buf, uint32_t size_left)
{
	pmcs_fw_event_hdr_t *evl_hdr;
	int n = 0, retries = 0;
	uint32_t evlog_latest_idx;
	boolean_t log_is_current = B_FALSE;

	if (pwp->fwlogp == NULL) {
		n = snprintf(buf, size_left, "\nFirmware logging "
		    "not enabled\n");
		return (n);
	}

	/*
	 * First, check to make sure all entries have been DMAed to the
	 * log buffer.
	 *
	 * We'll wait the required 50ms, but if the latest entry keeps
	 * changing, we'll only retry twice
	 */
	evl_hdr = (pmcs_fw_event_hdr_t *)pwp->fwlogp;
	evlog_latest_idx = evl_hdr->fw_el_latest_idx;

	while ((log_is_current == B_FALSE) && (retries < 3)) {
		drv_usecwait(50 * 1000);
		if (evl_hdr->fw_el_latest_idx == evlog_latest_idx) {
			log_is_current = B_TRUE;
		} else {
			++retries;
			pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
			    "%s: event log is still being updated... waiting",
			    __func__);
			evlog_latest_idx = evl_hdr->fw_el_latest_idx;
		}
	}

	n = pmcs_dump_binary(pwp, pwp->fwlogp, 0, (PMCS_FWLOG_SIZE >> 2),
	    buf, size_left);

	return (n);
}

/*
 * Dump Inbound and Outbound Queues.
 */
static int
pmcs_dump_ioqs(pmcs_hw_t *pwp, caddr_t buf, uint32_t size_left)
{
	uint8_t i = 0, k = 0;
	uint32_t j = 0, depth = 0;
	int n = 0;
	uint32_t *ptr = NULL;

	n += snprintf(&buf[n], (size_left - n), "\nDump I/O queues: \n"
	    "-----------------\n");
	for (i = 0; i < PMCS_NIQ; i++) {
		depth = PMCS_IQDX(pmcs_rd_iqc_tbl(pwp, PMCS_IQC_PARMX(i)));
		n += snprintf(&buf[n], (size_left - n),
		    "IQ[%d] Details:\n-----------------\n", i);
		n += snprintf(&buf[n], (size_left - n),
		    "    depth = 0x%04x\n", depth);
		n += snprintf(&buf[n], (size_left - n),
		    "    latest ci = 0x%02x\n", pmcs_rd_iqci(pwp, i));
		n += snprintf(&buf[n], (size_left - n),
		    "    latest pi = 0x%02x\n", pmcs_rd_iqpi(pwp, i));
		for (j = 0; j < depth; j++) {
			n += snprintf(&buf[n], (size_left - n),
			    "IOMB[%d]:\n", j);
			ptr = &pwp->iqp[i][(j * PMCS_QENTRY_SIZE) >> 2];
			for (k = 0; k < (PMCS_QENTRY_SIZE / sizeof (uint32_t));
			    k += 8) {
				n += snprintf(&buf[n], (size_left - n),
				    "0x%08x 0x%08x 0x%08x 0x%08x "
				    "0x%08x 0x%08x 0x%08x 0x%08x\n",
				    LE_32(ptr[k]), LE_32(ptr[k+1]),
				    LE_32(ptr[k+2]), LE_32(ptr[k+3]),
				    LE_32(ptr[k+4]), LE_32(ptr[k+5]),
				    LE_32(ptr[k+6]), LE_32(ptr[k+7]));
			}
		}
	}
	for (i = 0; i < PMCS_NOQ; i++) {
		depth = PMCS_OQDX(pmcs_rd_oqc_tbl(pwp, PMCS_OQC_PARMX(i)));
		n += snprintf(&buf[n], (size_left - n),
		    "OQ[%d] Details:\n", i);
		n += snprintf(&buf[n], (size_left - n),
		    "    depth = 0x%04x\n", depth);
		n += snprintf(&buf[n], (size_left - n),
		    "    latest ci = 0x%02x\n", pmcs_rd_oqci(pwp, i));
		n += snprintf(&buf[n], (size_left - n),
		    "    latest pi = 0x%02x\n", pmcs_rd_oqpi(pwp, i));
		for (j = 0; j < depth; j++) {
			n += snprintf(&buf[n], (size_left - n),
			    "IOMB[%d]:\n", j);
			ptr = &pwp->oqp[i][(j * PMCS_QENTRY_SIZE) >> 2];
			for (k = 0; k < (PMCS_QENTRY_SIZE / sizeof (uint32_t));
			    k += 8) {
				n += snprintf(&buf[n], (size_left - n),
				    "0x%08x 0x%08x 0x%08x 0x%08x "
				    "0x%08x 0x%08x 0x%08x 0x%08x\n",
				    LE_32(ptr[k]), LE_32(ptr[k+1]),
				    LE_32(ptr[k+2]), LE_32(ptr[k+3]),
				    LE_32(ptr[k+4]), LE_32(ptr[k+5]),
				    LE_32(ptr[k+6]), LE_32(ptr[k+7]));
			}
		}

	}
	n += snprintf(&buf[n], (size_left - n), "-----------------\n"
	    "Dump I/O queues end \n");
	return (n);
}

/*
 * Dump SPC Version.
 */
static int
pmcs_dump_spc_ver(pmcs_hw_t *pwp, caddr_t buf, uint32_t size_left)
{
	int n = 0;

	n += snprintf(&buf[n], (size_left - n), "\nDump SPC version: \n"
	    "-----------------\n");
	n += snprintf(&buf[n], (size_left - n), "Firmware Release Type = "
	    "0x%02x\n", PMCS_FW_TYPE(pwp));
	n += snprintf(&buf[n], (size_left - n), "    Sub-Minor Release "
	    "Number = 0x%02x\n", PMCS_FW_MICRO(pwp));
	n += snprintf(&buf[n], (size_left - n), "    Minor Release "
	    "Number = 0x%02x\n", PMCS_FW_MINOR(pwp));
	n += snprintf(&buf[n], (size_left - n), "    Major Release "
	    "Number = 0x%02x\n", PMCS_FW_MAJOR(pwp));
	n += snprintf(&buf[n], (size_left - n), "SPC DeviceID = 0x%04x\n",
	    pmcs_rd_topunit(pwp, PMCS_SPC_DEVICE_ID));
	n += snprintf(&buf[n], (size_left - n), "SPC Device Revision = "
	    "0x%08x\n", pmcs_rd_topunit(pwp, PMCS_DEVICE_REVISION));
	n += snprintf(&buf[n], (size_left - n), "SPC BootStrap Register = "
	    "0x%08x\n", pmcs_rd_topunit(pwp, PMCS_SPC_BOOT_STRAP));
	n += snprintf(&buf[n], (size_left - n), "SPC Reset Register = 0x%08x\n",
	    pmcs_rd_topunit(pwp, PMCS_SPC_RESET));
	n += snprintf(&buf[n], (size_left - n), "-----------------\n"
	    "Dump SPC version end \n");
	return (n);
}

/*
 * Dump MPI Table.
 */
static int
pmcs_dump_mpi_table(pmcs_hw_t *pwp, caddr_t buf, uint32_t size_left)
{
	int n = 0;

	n += snprintf(&buf[n], (size_left - n), "\nDump MSGU registers: \n"
	    "-----------------\n");
	n += snprintf(&buf[n], (size_left - n), "inb_doorbell = 0x%08x\n",
	    pmcs_rd_msgunit(pwp, PMCS_MSGU_IBDB));
	n += snprintf(&buf[n], (size_left - n), "inb_doorbell_clear = 0x%08x"
	    "\n", pmcs_rd_msgunit(pwp, PMCS_MSGU_IBDB_CLEAR));
	n += snprintf(&buf[n], (size_left - n), "outb_doorbell = 0x%08x"
	    "\n", pmcs_rd_msgunit(pwp, PMCS_MSGU_OBDB));
	n += snprintf(&buf[n], (size_left - n), "outb_doorbell_clear = 0x%08x"
	    "\n", pmcs_rd_msgunit(pwp, PMCS_MSGU_OBDB_CLEAR));
	n += snprintf(&buf[n], (size_left - n), "scratch_pad0 = 0x%08x"
	    "\n", pmcs_rd_msgunit(pwp, PMCS_MSGU_SCRATCH0));
	n += snprintf(&buf[n], (size_left - n), "scratch_pad1 = 0x%08x"
	    "\n", pmcs_rd_msgunit(pwp, PMCS_MSGU_SCRATCH1));
	n += snprintf(&buf[n], (size_left - n), "scratch_pad2 = 0x%08x"
	    "\n", pmcs_rd_msgunit(pwp, PMCS_MSGU_SCRATCH2));
	n += snprintf(&buf[n], (size_left - n), "scratch_pad3 = 0x%08x"
	    "\n", pmcs_rd_msgunit(pwp, PMCS_MSGU_SCRATCH3));
	n += snprintf(&buf[n], (size_left - n), "host_scratch_pad0 = 0x%08x"
	    "\n", pmcs_rd_msgunit(pwp, PMCS_MSGU_HOST_SCRATCH0));
	n += snprintf(&buf[n], (size_left - n), "host_scratch_pad1 = 0x%08x"
	    "\n", pmcs_rd_msgunit(pwp, PMCS_MSGU_HOST_SCRATCH1));
	n += snprintf(&buf[n], (size_left - n), "host_scratch_pad2 = 0x%08x"
	    "\n", pmcs_rd_msgunit(pwp, PMCS_MSGU_HOST_SCRATCH2));
	n += snprintf(&buf[n], (size_left - n), "host_scratch_pad3 = 0x%08x"
	    "\n", pmcs_rd_msgunit(pwp, PMCS_MSGU_HOST_SCRATCH3));
	n += snprintf(&buf[n], (size_left - n), "host_scratch_pad4 = 0x%08x"
	    "\n", pmcs_rd_msgunit(pwp, PMCS_MSGU_HOST_SCRATCH4));
	n += snprintf(&buf[n], (size_left - n), "host_scratch_pad5 = 0x%08x"
	    "\n", pmcs_rd_msgunit(pwp, PMCS_MSGU_HOST_SCRATCH5));
	n += snprintf(&buf[n], (size_left - n), "host_scratch_pad6 = 0x%08x"
	    "\n", pmcs_rd_msgunit(pwp, PMCS_MSGU_HOST_SCRATCH6));
	n += snprintf(&buf[n], (size_left - n), "host_scratch_pad7 = 0x%08x"
	    "\n", pmcs_rd_msgunit(pwp, PMCS_MSGU_HOST_SCRATCH7));
	n += snprintf(&buf[n], (size_left - n), "outb_doorbell_mask = 0x%08x"
	    "\n", pmcs_rd_msgunit(pwp, PMCS_MSGU_OBDB_MASK));

	n += snprintf(&buf[n], (size_left - n), "MPI Configuration Table: \n"
	    "-----------------\n");
	n += snprintf(&buf[n], (size_left - n), "ASCII Signature = 0x%08x\n",
	    pmcs_rd_mpi_tbl(pwp, PMCS_MPI_AS));
	n += snprintf(&buf[n], (size_left - n), "Firmware Release Type = "
	    "0x%08x\n", PMCS_FW_TYPE(pwp));
	n += snprintf(&buf[n], (size_left - n), "Firmware Release Variant = "
	    "0x%08x\n", PMCS_FW_VARIANT(pwp));
	n += snprintf(&buf[n], (size_left - n), "Firmware Sub-Minor Release "
	    "Number = 0x%08x\n", PMCS_FW_MICRO(pwp));
	n += snprintf(&buf[n], (size_left - n), "Firmware Minor Release "
	    "Number = 0x%08x\n", PMCS_FW_MINOR(pwp));
	n += snprintf(&buf[n], (size_left - n), "Firmware Major Release "
	    "Number = 0x%08x\n", PMCS_FW_MAJOR(pwp));
	n += snprintf(&buf[n], (size_left - n), "Maximum Outstanding I/Os "
	    "supported = 0x%08x\n", pmcs_rd_mpi_tbl(pwp, PMCS_MPI_MOIO));
	n += snprintf(&buf[n], (size_left - n), "Maximum Scatter-Gather List "
	    "Elements = 0x%08x\n",
	    PMCS_MSGL(pmcs_rd_mpi_tbl(pwp, PMCS_MPI_INFO0)));
	n += snprintf(&buf[n], (size_left - n), "Maximum number of devices "
	    "connected to the SPC = 0x%08x\n",
	    PMCS_MD(pmcs_rd_mpi_tbl(pwp, PMCS_MPI_INFO0)));
	n += snprintf(&buf[n], (size_left - n), "Maximum Number of IQs "
	    "supported = 0x%08x\n",
	    PMCS_MNIQ(pmcs_rd_mpi_tbl(pwp, PMCS_MPI_INFO1)));
	n += snprintf(&buf[n], (size_left - n), "Maximum Number of OQs "
	    "supported = 0x%08x\n",
	    PMCS_MNOQ(pmcs_rd_mpi_tbl(pwp, PMCS_MPI_INFO1)));
	n += snprintf(&buf[n], (size_left - n), "High Priority Queue supported"
	    " = 0x%08x\n", PMCS_HPIQ(pmcs_rd_mpi_tbl(pwp, PMCS_MPI_INFO1)));
	n += snprintf(&buf[n], (size_left - n), "Interrupt Coalescing supported"
	    " = 0x%08x\n", PMCS_ICS(pmcs_rd_mpi_tbl(pwp, PMCS_MPI_INFO1)));
	n += snprintf(&buf[n], (size_left - n), "Number of Phys = "
	    "0x%08x\n", PMCS_NPHY(pmcs_rd_mpi_tbl(pwp, PMCS_MPI_INFO1)));
	n += snprintf(&buf[n], (size_left - n), "SAS Revision Specification = "
	    "0x%08x\n", PMCS_SASREV(pmcs_rd_mpi_tbl(pwp, PMCS_MPI_INFO1)));
	n += snprintf(&buf[n], (size_left - n), "General Status Table Offset = "
	    "0x%08x\n", pmcs_rd_mpi_tbl(pwp, PMCS_MPI_GSTO));
	n += snprintf(&buf[n], (size_left - n), "Inbound Queue Configuration "
	    "Table Offset = 0x%08x\n", pmcs_rd_mpi_tbl(pwp, PMCS_MPI_IQCTO));
	n += snprintf(&buf[n], (size_left - n), "Outbound Queue Configuration "
	    "Table Offset = 0x%08x\n", pmcs_rd_mpi_tbl(pwp, PMCS_MPI_OQCTO));
	n += snprintf(&buf[n], (size_left - n), "Inbound Queue Normal/High "
	    "Priority Processing Depth = 0x%02x 0x%02x\n",
	    (pmcs_rd_mpi_tbl(pwp, PMCS_MPI_INFO2) & IQ_NORMAL_PRI_DEPTH_MASK),
	    ((pmcs_rd_mpi_tbl(pwp, PMCS_MPI_INFO2) &
	    IQ_HIPRI_PRI_DEPTH_MASK) >> IQ_HIPRI_PRI_DEPTH_SHIFT));
	n += snprintf(&buf[n], (size_left - n), "General Event Notification "
	    "Queue = 0x%02x\n", (pmcs_rd_mpi_tbl(pwp, PMCS_MPI_INFO2) &
	    GENERAL_EVENT_OQ_MASK) >> GENERAL_EVENT_OQ_SHIFT);
	n += snprintf(&buf[n], (size_left - n), "Device Handle Removed "
	    "Notification Queue = 0x%02x\n",
	    (uint32_t)(pmcs_rd_mpi_tbl(pwp, PMCS_MPI_INFO2) &
	    DEVICE_HANDLE_REMOVED_MASK) >> DEVICE_HANDLE_REMOVED_SHIFT);
	for (uint8_t i = 0; i < pwp->nphy; i++) {
		uint32_t woff = i / 4;
		uint32_t shf = (i % 4) * 8;
		n += snprintf(&buf[n], (size_left - n), "SAS HW Event "
		    "Notification Queue - PHY ID %d = 0x%02x\n", i,
		    (pmcs_rd_mpi_tbl(pwp, PMCS_MPI_EVQS + (woff << 2)) >> shf)
		    & 0xff);
	}
	for (uint8_t i = 0; i < pwp->nphy; i++) {
		uint32_t woff = i / 4;
		uint32_t shf = (i % 4) * 8;
		n += snprintf(&buf[n], (size_left - n), "SATA NCQ Error "
		    "Event Notification Queue - PHY ID %d = 0x%02x\n", i,
		    (pmcs_rd_mpi_tbl(pwp, PMCS_MPI_SNCQ + (woff << 2)) >> shf)
		    & 0xff);
	}
	for (uint8_t i = 0; i < pwp->nphy; i++) {
		uint32_t woff = i / 4;
		uint32_t shf = (i % 4) * 8;
		n += snprintf(&buf[n], (size_left - n), "I_T Nexus Target "
		    "Event Notification Queue - PHY ID %d = 0x%02x\n", i,
		    (pmcs_rd_mpi_tbl(pwp, PMCS_MPI_IT_NTENQ +
		    (woff << 2)) >> shf) & 0xff);
	}
	for (uint8_t i = 0; i < pwp->nphy; i++) {
		uint32_t woff = i / 4;
		uint32_t shf = (i % 4) * 8;
		n += snprintf(&buf[n], (size_left - n), "SSP Target "
		    "Event Notification Queue - PHY ID %d = 0x%02x\n", i,
		    (pmcs_rd_mpi_tbl(pwp, PMCS_MPI_SSP_TENQ +
		    (woff << 2)) >> shf) & 0xff);
	}

	n += snprintf(&buf[n], (size_left - n), "I/O Abort Delay = 0x%04x\n",
	    pmcs_rd_mpi_tbl(pwp, PMCS_MPI_IOABTDLY) & 0xffff);
	n += snprintf(&buf[n], (size_left - n),
	    "Customization Setting = 0x%08x\n",
	    pmcs_rd_mpi_tbl(pwp, PMCS_MPI_CUSTSET));
	n += snprintf(&buf[n], (size_left - n), "MSGU Event Log Buffer Address "
	    "Higher = 0x%08x\n", pmcs_rd_mpi_tbl(pwp, PMCS_MPI_MELBAH));
	n += snprintf(&buf[n], (size_left - n), "MSGU Event Log Buffer Address "
	    "Lower = 0x%08x\n", pmcs_rd_mpi_tbl(pwp, PMCS_MPI_MELBAL));
	n += snprintf(&buf[n], (size_left - n), "MSGU Event Log Buffer Size "
	    "= 0x%08x\n", pmcs_rd_mpi_tbl(pwp, PMCS_MPI_MELBS));
	n += snprintf(&buf[n], (size_left - n), "MSGU Event Log Severity "
	    "= 0x%08x\n", pmcs_rd_mpi_tbl(pwp, PMCS_MPI_MELSEV));
	n += snprintf(&buf[n], (size_left - n), "IOP Event Log Buffer Address "
	    "Higher = 0x%08x\n", pmcs_rd_mpi_tbl(pwp, PMCS_MPI_IELBAH));
	n += snprintf(&buf[n], (size_left - n), "IOP Event Log Buffer Address "
	    "Lower = 0x%08x\n", pmcs_rd_mpi_tbl(pwp, PMCS_MPI_IELBAL));
	n += snprintf(&buf[n], (size_left - n), "IOP Event Log Buffer Size "
	    "= 0x%08x\n", pmcs_rd_mpi_tbl(pwp, PMCS_MPI_IELBS));
	n += snprintf(&buf[n], (size_left - n), "IOP Event Log Severity "
	    "= 0x%08x\n", pmcs_rd_mpi_tbl(pwp, PMCS_MPI_IELSEV));
	n += snprintf(&buf[n], (size_left - n), "Fatal Error Interrupt "
	    "= 0x%08x\n", pmcs_rd_mpi_tbl(pwp, PMCS_MPI_FERR));
	n += snprintf(&buf[n], (size_left - n),
	    "Fatal Error Register Dump Offset "
	    "For MSGU = 0x%08x\n", pmcs_rd_mpi_tbl(pwp, PMCS_FERDOMSGU));
	n += snprintf(&buf[n], (size_left - n),
	    "Fatal Error Register Dump Length "
	    "For MSGU = 0x%08x\n", pmcs_rd_mpi_tbl(pwp, PMCS_FERDLMSGU));
	n += snprintf(&buf[n], (size_left - n),
	    "Fatal Error Register Dump Offset "
	    "For IOP = 0x%08x\n", pmcs_rd_mpi_tbl(pwp, PMCS_FERDOIOP));
	n += snprintf(&buf[n], (size_left - n),
	    "Fatal Error Register Dump Length "
	    "For IOP = 0x%08x\n", pmcs_rd_mpi_tbl(pwp, PMCS_FERDLIOP));

	n += snprintf(&buf[n], (size_left - n), "Dump GS Table: \n"
	    "-----------------\n");
	n += snprintf(&buf[n], (size_left - n),  "GST MPI State: 0x%08x\n",
	    pmcs_rd_gst_tbl(pwp, PMCS_GST_BASE));
	n += snprintf(&buf[n], (size_left - n),  "Inbound Queue Freeze State 0 "
	    "= 0x%08x\n", pmcs_rd_gst_tbl(pwp, PMCS_GST_IQFRZ0));
	n += snprintf(&buf[n], (size_left - n), "Inbound Queue Freeze State 1 "
	    "= 0x%08x\n", pmcs_rd_gst_tbl(pwp, PMCS_GST_IQFRZ1));
	n += snprintf(&buf[n], (size_left - n), "MSGU Tick Count = 0x%08x \n",
	    pmcs_rd_gst_tbl(pwp, PMCS_GST_MSGU_TICK));
	n += snprintf(&buf[n], (size_left - n), "IOP Tick Count = 0x%08x\n",
	    pmcs_rd_gst_tbl(pwp, PMCS_GST_IOP_TICK));
	for (uint8_t i = 0; i < pwp->nphy; i++) {
		n += snprintf(&buf[n], (size_left - n), " Phy %d state = "
		    "0x%08x\n", i, pmcs_rd_gst_tbl(pwp, PMCS_GST_PHY_INFO(i)));
	}
	for (uint8_t i = 0; i < pwp->nphy; i++) {
		n += snprintf(&buf[n], (size_left - n), " Recoverable Error "
		    "Information %d = 0x%08x\n", i,
		    pmcs_rd_gst_tbl(pwp, PMCS_GST_RERR_INFO(i)));
	}

	n += snprintf(&buf[n], (size_left - n), "Dump IQCT Table\n"
	    "-----------------\n");
	for (uint8_t i = 0; i < PMCS_NIQ; i++) {
		n += snprintf(&buf[n], (size_left - n), "Inbound Queue "
		    "Configuration Table - [%d]:\n", i);
		n += snprintf(&buf[n], (size_left - n), "    Inbound Queue "
		    "Depth = 0x%08x\n",
		    PMCS_IQDX(pmcs_rd_iqc_tbl(pwp, PMCS_IQC_PARMX(i))));
		n += snprintf(&buf[n], (size_left - n), "    Inbound Queue "
		    "Element Size and Priority = 0x%08x 0x%08x\n",
		    PMCS_IQESX(pmcs_rd_iqc_tbl(pwp, PMCS_IQC_PARMX(i))),
		    PMCS_IQPX(pmcs_rd_iqc_tbl(pwp, PMCS_IQC_PARMX(i))));
		n += snprintf(&buf[n], (size_left - n), "    Inbound Queue "
		    "Base Address High = 0x%08x\n",
		    pmcs_rd_iqc_tbl(pwp, PMCS_IQBAHX(i)));
		n += snprintf(&buf[n], (size_left - n), "    Inbound Queue "
		    "Base Address Low = 0x%08x\n",
		    pmcs_rd_iqc_tbl(pwp, PMCS_IQBALX(i)));
		n += snprintf(&buf[n], (size_left - n), "    Inbound Queue "
		    "Consumer Index Base Address High = 0x%08x\n",
		    pmcs_rd_iqc_tbl(pwp, PMCS_IQCIBAHX(i)));
		n += snprintf(&buf[n], (size_left - n), "    Inbound Queue "
		    "Consumer Index Base Address Low = 0x%08x\n",
		    pmcs_rd_iqc_tbl(pwp, PMCS_IQCIBALX(i)));
		n += snprintf(&buf[n], (size_left - n), "    Inbound Queue "
		    "Producer Index PCI BAR = 0x%08x\n",
		    pmcs_rd_iqc_tbl(pwp, PMCS_IQPIBARX(i)));
		n += snprintf(&buf[n], (size_left - n), "    Inbound Queue "
		    "Producer Index PCI BAR offset = 0x%08x\n",
		    pmcs_rd_iqc_tbl(pwp, PMCS_IQPIOFFX(i)));
	}

	n += snprintf(&buf[n], (size_left - n), "Dump OQCT Table: \n"
	    "-----------------\n");
	for (uint8_t i = 0; i < PMCS_NOQ; i++) {
		n += snprintf(&buf[n], (size_left - n), "Outbound Queue "
		    "Configuration Table - [%d]:\n", i);
		n += snprintf(&buf[n], (size_left - n), "    Outbound Queue "
		    "Depth = 0x%08x\n",
		    PMCS_OQDX(pmcs_rd_oqc_tbl(pwp, PMCS_OQC_PARMX(i))));
		n += snprintf(&buf[n], (size_left - n), "    Outbound Queue "
		    "Element Size = 0x%08x\n",
		    PMCS_OQESX(pmcs_rd_oqc_tbl(pwp, PMCS_OQC_PARMX(i))));
		n += snprintf(&buf[n], (size_left - n), "    Outbound Queue "
		    "Base Address High = 0x%08x\n",
		    pmcs_rd_oqc_tbl(pwp, PMCS_OQBAHX(i)));
		n += snprintf(&buf[n], (size_left - n), "    Outbound Queue "
		    "Base Address Low = 0x%08x\n",
		    pmcs_rd_oqc_tbl(pwp, PMCS_OQBALX(i)));
		n += snprintf(&buf[n], (size_left - n), "    Outbound Queue "
		    "Producer Index Base Address High = 0x%08x\n",
		    pmcs_rd_oqc_tbl(pwp, PMCS_OQPIBAHX(i)));
		n += snprintf(&buf[n], (size_left - n), "    Outbound Queue "
		    "Producer Index Base Address Low = 0x%08x\n",
		    pmcs_rd_oqc_tbl(pwp, PMCS_OQPIBALX(i)));
		n += snprintf(&buf[n], (size_left - n), "    Outbound Queue "
		    "Consumer Index PCI BAR = 0x%08x\n",
		    pmcs_rd_oqc_tbl(pwp, PMCS_OQCIBARX(i)));
		n += snprintf(&buf[n], (size_left - n), "    Outbound Queue "
		    "Consumer Index PCI BAR offset = 0x%08x\n",
		    pmcs_rd_oqc_tbl(pwp, PMCS_OQCIOFFX(i)));

		n += snprintf(&buf[n], (size_left - n), "    Outbound Queue "
		    "Interrupt Coalescing Timeout = 0x%08x\n",
		    PMCS_OQICT(pmcs_rd_oqc_tbl(pwp, PMCS_OQIPARM(i))));
		n += snprintf(&buf[n], (size_left - n), "    Outbound Queue "
		    "Interrupt Coalescing Count = 0x%08x\n",
		    PMCS_OQICC(pmcs_rd_oqc_tbl(pwp, PMCS_OQIPARM(i))));
		n += snprintf(&buf[n], (size_left - n), "    Outbound Queue "
		    "Interrupt Vector =  0x%08x\n",
		    PMCS_OQIV(pmcs_rd_oqc_tbl(pwp, PMCS_OQIPARM(i))));
		n += snprintf(&buf[n], (size_left - n), "    Outbound Queue "
		    "Dynamic Interrupt Coalescing Timeout = 0x%08x\n",
		    pmcs_rd_oqc_tbl(pwp, PMCS_OQDICX(i)));

	}
	n += snprintf(&buf[n], (size_left - n), "-----------------\n"
	    "Dump MPI Table end\n");
	return (n);
}

/*ARGSUSED*/
int
pmcs_dump_binary(pmcs_hw_t *pwp, uint32_t *addr, uint32_t off,
    uint32_t words_to_read, caddr_t buf, uint32_t size_left)
{
	uint32_t i;
	int n = 0;
	char c = ' ';

	for (i = 0, n = 0; i < words_to_read; i++) {
		if ((i & 7) == 0) {
			n += snprintf(&buf[n], (size_left - n),
			    "%08x: ", (i << 2) + off);
		}
		if ((i + 1) & 7) {
			c = ' ';
		} else {
			c = '\n';
		}
		n += snprintf(&buf[n], (size_left - n), "%08x%c", addr[i], c);
	}
	return (n);
}

/*
 * Dump Global Shared Memory Configuration Registers
 */
static int
pmcs_dump_gsm_conf(pmcs_hw_t *pwp, caddr_t buf, uint32_t size_left)
{
	int n = 0;

	n += snprintf(&buf[n], (size_left - n), "\nDump GSM configuration "
	    "registers: \n -----------------\n");
	n += snprintf(&buf[n], (size_left - n), "RB6 Access Register = "
	    "0x%08x\n", pmcs_rd_gsm_reg(pwp, RB6_ACCESS));
	n += snprintf(&buf[n], (size_left - n), "CFG and RST = 0x%08x\n",
	    pmcs_rd_gsm_reg(pwp, GSM_CFG_AND_RESET));
	n += snprintf(&buf[n], (size_left - n), "RAM ECC ERR INDICATOR= "
	    "0x%08x\n", pmcs_rd_gsm_reg(pwp, RAM_ECC_DOUBLE_ERROR_INDICATOR));
	n += snprintf(&buf[n], (size_left - n), "READ ADR PARITY CHK EN = "
	    "0x%08x\n", pmcs_rd_gsm_reg(pwp, READ_ADR_PARITY_CHK_EN));
	n += snprintf(&buf[n], (size_left - n), "WRITE ADR PARITY CHK EN = "
	    "0x%08x\n", pmcs_rd_gsm_reg(pwp, WRITE_ADR_PARITY_CHK_EN));
	n += snprintf(&buf[n], (size_left - n), "WRITE DATA PARITY CHK EN= "
	    "0x%08x\n", pmcs_rd_gsm_reg(pwp, WRITE_DATA_PARITY_CHK_EN));
	n += snprintf(&buf[n], (size_left - n),
	    "READ ADR PARITY ERROR INDICATOR = 0x%08x\n",
	    pmcs_rd_gsm_reg(pwp, READ_ADR_PARITY_ERROR_INDICATOR));
	n += snprintf(&buf[n], (size_left - n),
	    "WRITE ADR PARITY ERROR INDICATOR = 0x%08x\n",
	    pmcs_rd_gsm_reg(pwp, WRITE_ADR_PARITY_ERROR_INDICATOR));
	n += snprintf(&buf[n], (size_left - n),
	    "WRITE DATA PARITY ERROR INDICATOR = 0x%08x\n",
	    pmcs_rd_gsm_reg(pwp, WRITE_DATA_PARITY_ERROR_INDICATOR));
	n += snprintf(&buf[n], (size_left - n), "NMI Enable VPE0 IOP Register"
	    " = 0x%08x\n", pmcs_rd_gsm_reg(pwp, NMI_EN_VPE0_IOP));
	n += snprintf(&buf[n], (size_left - n), "NMI Enable VPE0 AAP1 Register"
	    " = 0x%08x\n", pmcs_rd_gsm_reg(pwp, NMI_EN_VPE0_AAP1));
	n += snprintf(&buf[n], (size_left - n), "-----------------\n"
	    "Dump GSM configuration registers end \n");
	return (n);
}

/*
 * Dump PCIe Configuration Registers.
 */
static int
pmcs_dump_pcie_conf(pmcs_hw_t *pwp, caddr_t buf, uint32_t size_left)
{
	int n = 0;
	uint32_t i = 0;

	n += snprintf(&buf[n], (size_left - n), "\nDump PCIe configuration "
	    "registers: \n -----------------\n");
	n += snprintf(&buf[n], (size_left - n), "VENID = 0x%04x\n",
	    pci_config_get16(pwp->pci_acc_handle, PCI_CONF_VENID));
	n += snprintf(&buf[n], (size_left - n), "DEVICE_ID = 0x%04x\n",
	    pci_config_get16(pwp->pci_acc_handle, PCI_CONF_DEVID));
	n += snprintf(&buf[n], (size_left - n), "CFGCMD = 0x%04x\n",
	    pci_config_get16(pwp->pci_acc_handle, PCI_CONF_COMM));
	n += snprintf(&buf[n], (size_left - n), "CFGSTAT = 0x%04x\n",
	    pci_config_get16(pwp->pci_acc_handle, PCI_CONF_STAT));
	n += snprintf(&buf[n], (size_left - n), "CLSCODE and REVID = 0x%08x\n",
	    pci_config_get32(pwp->pci_acc_handle, PCI_CONF_REVID));
	n += snprintf(&buf[n], (size_left - n), "BIST HDRTYPE LATTIM CLSIZE = "
	    "0x%08x\n",
	    pci_config_get32(pwp->pci_acc_handle, PCI_CONF_CACHE_LINESZ));
	n += snprintf(&buf[n], (size_left - n), "MEMBASE-I LOWER = 0x%08x\n",
	    pci_config_get32(pwp->pci_acc_handle, PCI_CONF_BASE0));
	n += snprintf(&buf[n], (size_left - n), "MEMBASE-I UPPER = 0x%08x\n",
	    pci_config_get32(pwp->pci_acc_handle, PCI_CONF_BASE1));
	n += snprintf(&buf[n], (size_left - n), "MEMBASE-II LOWER = 0x%08x\n",
	    pci_config_get32(pwp->pci_acc_handle, PCI_CONF_BASE2));
	n += snprintf(&buf[n], (size_left - n), "MEMBASE-II UPPER = 0x%08x\n",
	    pci_config_get32(pwp->pci_acc_handle, PCI_CONF_BASE3));
	n += snprintf(&buf[n], (size_left - n), "MEMBASE-III = 0x%08x\n",
	    pci_config_get32(pwp->pci_acc_handle, PCI_CONF_BASE4));
	n += snprintf(&buf[n], (size_left - n), "MEMBASE-IV = 0x%08x\n",
	    pci_config_get32(pwp->pci_acc_handle, PCI_CONF_BASE5));
	n += snprintf(&buf[n], (size_left - n), "SVID = 0x%08x\n",
	    pci_config_get32(pwp->pci_acc_handle, PCI_CONF_SUBVENID));
	n += snprintf(&buf[n], (size_left - n), "ROMBASE = 0x%08x\n",
	    pci_config_get32(pwp->pci_acc_handle, PCI_CONF_ROM));
	n += snprintf(&buf[n], (size_left - n), "CAP_PTR = 0x%02x\n",
	    pci_config_get8(pwp->pci_acc_handle, PCI_CONF_CAP_PTR));
	n += snprintf(&buf[n], (size_left - n), "MAXLAT MINGNT INTPIN "
	    "INTLINE = 0x%08x\n",
	    pci_config_get32(pwp->pci_acc_handle, PCI_CONF_ILINE));
	n += snprintf(&buf[n], (size_left - n), "PMC PM_NEXT_CAP PM_CAP_ID = "
	    "0x%08x\n", pci_config_get32(pwp->pci_acc_handle, PMCS_PCI_PMC));
	n += snprintf(&buf[n], (size_left - n), "PMCSR = 0x%08x\n",
	    pci_config_get32(pwp->pci_acc_handle, PMCS_PCI_PMCSR));
	n += snprintf(&buf[n], (size_left - n),
	    "MC MSI_NEXT_CAP MSI_CAP_ID = 0x%08x\n",
	    pci_config_get32(pwp->pci_acc_handle, PMCS_PCI_MSI));
	n += snprintf(&buf[n], (size_left - n), "MAL = 0x%08x\n",
	    pci_config_get32(pwp->pci_acc_handle, PMCS_PCI_MAL));
	n += snprintf(&buf[n], (size_left - n), "MAU = 0x%08x\n",
	    pci_config_get32(pwp->pci_acc_handle, PMCS_PCI_MAU));
	n += snprintf(&buf[n], (size_left - n), "MD = 0x%04x\n",
	    pci_config_get16(pwp->pci_acc_handle, PMCS_PCI_MD));
	n += snprintf(&buf[n], (size_left - n),
	    "PCIE_CAP PCIE_NEXT_CAP PCIE_CAP_ID = 0x%08x\n",
	    pci_config_get32(pwp->pci_acc_handle, PMCS_PCI_PCIE));
	n += snprintf(&buf[n], (size_left - n), "DEVICE_CAP = 0x%08x\n",
	    pci_config_get32(pwp->pci_acc_handle, PMCS_PCI_DEV_CAP));
	n += snprintf(&buf[n], (size_left - n),
	    "DEVICE_STAT DEVICE_CTRL = 0x%08x\n",
	    pci_config_get32(pwp->pci_acc_handle, PMCS_PCI_DEV_CTRL));
	n += snprintf(&buf[n], (size_left - n), "LINK_CAP = 0x%08x\n",
	    pci_config_get32(pwp->pci_acc_handle, PMCS_PCI_LINK_CAP));
	n += snprintf(&buf[n], (size_left - n),
	    "LINK_STAT LINK_CTRL = 0x%08x\n",
	    pci_config_get32(pwp->pci_acc_handle, PMCS_PCI_LINK_CTRL));
	n += snprintf(&buf[n], (size_left - n), "MSIX_CAP = 0x%08x\n",
	    pci_config_get32(pwp->pci_acc_handle, PMCS_PCI_MSIX_CAP));
	n += snprintf(&buf[n], (size_left - n), "TBL_OFFSET = 0x%08x\n",
	    pci_config_get32(pwp->pci_acc_handle, PMCS_PCI_TBL_OFFSET));
	n += snprintf(&buf[n], (size_left - n), "PBA_OFFSET = 0x%08x\n",
	    pci_config_get32(pwp->pci_acc_handle, PMCS_PCI_PBA_OFFSET));
	n += snprintf(&buf[n], (size_left - n), "PCIE_CAP_HD = 0x%08x\n",
	    pci_config_get32(pwp->pci_acc_handle, PMCS_PCI_PCIE_CAP_HD));
	n += snprintf(&buf[n], (size_left - n), "UE_STAT = 0x%08x\n",
	    pci_config_get32(pwp->pci_acc_handle, PMCS_PCI_UE_STAT));
	n += snprintf(&buf[n], (size_left - n), "UE_MASK = 0x%08x\n",
	    pci_config_get32(pwp->pci_acc_handle, PMCS_PCI_UE_MASK));
	n += snprintf(&buf[n], (size_left - n), "UE_SEV = 0x%08x\n",
	    pci_config_get32(pwp->pci_acc_handle, PMCS_PCI_UE_SEV));
	n += snprintf(&buf[n], (size_left - n), "CE_STAT = 0x%08x\n",
	    pci_config_get32(pwp->pci_acc_handle, PMCS_PCI_CE_STAT));
	n += snprintf(&buf[n], (size_left - n), "CE_MASK = 0x%08x\n",
	    pci_config_get32(pwp->pci_acc_handle, PMCS_PCI_CE_MASK));
	n += snprintf(&buf[n], (size_left - n), "ADV_ERR_CTRL = 0x%08x\n",
	    pci_config_get32(pwp->pci_acc_handle, PMCS_PCI_ADV_ERR_CTRL));
	for (i = 0; i < 4; i++) {
		n += snprintf(&buf[n], (size_left - n), "HD_LOG_DW%d = "
		    "0x%08x\n", i, pci_config_get32(pwp->pci_acc_handle,
		    (PMCS_PCI_HD_LOG_DW + i * 4)));
	}
	n += snprintf(&buf[n], (size_left - n), "-----------------\n"
	    "Dump PCIe configuration registers end \n");
	return (n);
}
/*
 * Called with axil_lock held
 */
static boolean_t
pmcs_shift_axil(pmcs_hw_t *pwp, uint32_t offset)
{
	uint32_t newaxil = offset & ~GSM_BASE_MASK;

	ASSERT(mutex_owned(&pwp->axil_lock));
	ddi_put32(pwp->top_acc_handle,
	    &pwp->top_regs[PMCS_AXI_TRANS >> 2], newaxil);
	drv_usecwait(10);

	if (ddi_get32(pwp->top_acc_handle,
	    &pwp->top_regs[PMCS_AXI_TRANS >> 2]) != newaxil) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "AXIL register update failed");
		return (B_FALSE);
	}
	return (B_TRUE);
}

static uint32_t
pmcs_get_axil(pmcs_hw_t *pwp)
{
	uint32_t regval = 0;
	mutex_enter(&pwp->axil_lock);
	regval = ddi_get32(pwp->top_acc_handle,
	    &pwp->top_regs[PMCS_AXI_TRANS >> 2]);
	mutex_exit(&pwp->axil_lock);
	return (regval);
}

static void
pmcs_restore_axil(pmcs_hw_t *pwp, uint32_t oldaxil)
{
	mutex_enter(&pwp->axil_lock);
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

/*
 * Dump Additional GSM Registers.
 */
static int
pmcs_dump_gsm_addiregs(pmcs_hw_t *pwp, caddr_t buf, uint32_t size_left)
{
	uint32_t i = 0;
	int n = 0, j = 0, nums = 0;
	uint32_t gsm_addr = 0, addr = 0;

	n += snprintf(&buf[n], (size_left - n), "\nDump GSM Sparse Registers:"
	    "\n-----------------\n");
	for (i = 0; i < sizeof (gsm_spregs) / sizeof (pmcs_sparse_regs_t);
	    i++) {
		gsm_addr =
		    gsm_spregs[i].shift_addr + gsm_spregs[i].offset_start;
		nums = gsm_spregs[i].offset_end - gsm_spregs[i].offset_start;
		if (gsm_spregs[i].flag & PMCS_SPREGS_BLOCK_START) {
			n += snprintf(&buf[n], (size_left - n), "\n%s - 0x%08X"
			    "[MEMBASE-III SHIFT = 0x%08X]\nOffset:\n",
			    gsm_spregs[i].desc ? gsm_spregs[i].desc : "NULL",
			    gsm_spregs[i].base_addr, gsm_spregs[i].shift_addr);
		}

		if (nums == 0) {
			n += snprintf(&buf[n], (size_left - n),
			    "[%04X]: %08X\n", gsm_spregs[i].offset_start,
			    pmcs_rd_gsm_reg(pwp, gsm_addr));
		} else if (nums > 0) {
			n += snprintf(&buf[n], (size_left - n),
			    "\n[%04X] - [%04X]: \n", gsm_spregs[i].offset_start,
			    gsm_spregs[i].offset_end);

			j = 0;
			while (nums > 0) {
				addr = gsm_addr + j * 4;
				n += snprintf(&buf[n], (size_left - n),
				    "[%04X]: %08X\n", addr & GSM_BASE_MASK,
				    pmcs_rd_gsm_reg(pwp, addr));
				j++;
				nums -= 4;
			}
		}

	}

	n += snprintf(&buf[n], (size_left - n), "-----------------\n"
	    "------------ Dump GSM Sparse Registers end ------------\n");
	return (n);

}

/*
 * Dump GSM Memory Regions.
 */
static int
pmcs_dump_gsm(pmcs_hw_t *pwp, caddr_t buf, uint32_t size_left)
{
	int n = 0;
	uint32_t i = 0;
	uint32_t oldaxil = 0;
	uint32_t gsm_addr = 0;
	uint32_t *local_buf = NULL;

	local_buf = kmem_zalloc(GSM_SM_BLKSZ, KM_NOSLEEP);
	if (local_buf == NULL) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: local_buf memory not allocated", __func__);
		return (0);
	}

	oldaxil = pmcs_get_axil(pwp);
	mutex_enter(&pwp->axil_lock);
	n += snprintf(&buf[n], (size_left - n), "\nDump GSM IO Status Table: \n"
	    " -----------------\n");
	for (i = 0; i < 4; i++) {
		gsm_addr = IO_STATUS_TABLE_BASE + GSM_SM_BLKSZ * i;
		if (pmcs_shift_axil(pwp, gsm_addr) == B_TRUE) {
			gsm_addr &= GSM_BASE_MASK;
			ddi_rep_get32(pwp->gsm_acc_handle, local_buf,
			    &pwp->gsm_regs[gsm_addr >> 2], GSM_SM_BLKSZ >> 2,
			    DDI_DEV_AUTOINCR);
			n += pmcs_dump_binary(pwp, local_buf, i * GSM_SM_BLKSZ,
			    GSM_SM_BLKSZ >> 2, &buf[n], size_left - n);
		}
	}
	n += snprintf(&buf[n], (size_left - n), "\n-----------------\n"
	    "Dump GSM IO Status Table end \n");
	n += snprintf(&buf[n], (size_left - n), "\nDump Ring Buffer Storage: \n"
	    " -----------------\n");
	for (i = 0; i < 2; i++) {
		gsm_addr = RING_BUF_STORAGE_0 + GSM_SM_BLKSZ * i;
		if (pmcs_shift_axil(pwp, gsm_addr) == B_TRUE) {
			gsm_addr &= GSM_BASE_MASK;
			ddi_rep_get32(pwp->gsm_acc_handle, local_buf,
			    &pwp->gsm_regs[gsm_addr >> 2], GSM_SM_BLKSZ >> 2,
			    DDI_DEV_AUTOINCR);
			n += pmcs_dump_binary(pwp, local_buf, i * GSM_SM_BLKSZ,
			    GSM_SM_BLKSZ >> 2, &buf[n], size_left - n);
		}
	}
	n += snprintf(&buf[n], (size_left - n), "\n-----------------\n"
	    "Dump Ring Buffer Storage end \n");

	n += snprintf(&buf[n], (size_left - n), "\nDump Ring Buffer Pointers:\n"
	    " -----------------\n");
		gsm_addr = RING_BUF_PTR_ACC_BASE + RING_BUF_PTR_OFF;
		if (pmcs_shift_axil(pwp, gsm_addr) == B_TRUE) {
			gsm_addr &= GSM_BASE_MASK;
			ddi_rep_get32(pwp->gsm_acc_handle, local_buf,
			    &pwp->gsm_regs[gsm_addr >> 2],
			    RING_BUF_PTR_SIZE >> 2, DDI_DEV_AUTOINCR);
			n += pmcs_dump_binary(pwp, local_buf, 0,
			    RING_BUF_PTR_SIZE >> 2, &buf[n], size_left - n);
		}
	n += snprintf(&buf[n], (size_left - n), "\n-----------------\n"
	    "Dump Ring Buffer Pointers end \n");

	n += snprintf(&buf[n], (size_left - n), "\nDump Ring Buffer Access: \n"
	    " -----------------\n");
		gsm_addr = RING_BUF_PTR_ACC_BASE + RING_BUF_ACC_OFF;
		if (pmcs_shift_axil(pwp, gsm_addr) == B_TRUE) {
			gsm_addr &= GSM_BASE_MASK;
			ddi_rep_get32(pwp->gsm_acc_handle, local_buf,
			    &pwp->gsm_regs[gsm_addr >> 2],
			    RING_BUF_ACC_SIZE >> 2, DDI_DEV_AUTOINCR);
			n += pmcs_dump_binary(pwp, local_buf, 0,
			    RING_BUF_ACC_SIZE >> 2, &buf[n], size_left - n);
		}
	n += snprintf(&buf[n], (size_left - n), "\n-----------------\n"
	    "Dump Ring Buffer Access end \n");

	n += snprintf(&buf[n], (size_left - n), "\nDump GSM SM: \n"
	    " -----------------\n");
	for (i = 0; i < 16; i++) {
		gsm_addr = GSM_SM_BASE + GSM_SM_BLKSZ * i;
		if (pmcs_shift_axil(pwp, gsm_addr) == B_TRUE) {
			gsm_addr &= GSM_BASE_MASK;
			ddi_rep_get32(pwp->gsm_acc_handle, local_buf,
			    &pwp->gsm_regs[gsm_addr >> 2],
			    GSM_SM_BLKSZ >> 2, DDI_DEV_AUTOINCR);
			n += pmcs_dump_binary(pwp, local_buf, i * GSM_SM_BLKSZ,
			    GSM_SM_BLKSZ >> 2, &buf[n], size_left - n);
		}
	}
	mutex_exit(&pwp->axil_lock);
	pmcs_restore_axil(pwp, oldaxil);

	n += snprintf(&buf[n], (size_left - n), "\n-----------------\n"
	    "Dump GSM SM end \n");
	n += snprintf(&buf[n], (size_left - n), "-----------------\n"
	    "\n------------ Dump GSM Memory Regions end  -------------\n");
	if (local_buf) {
		kmem_free(local_buf, GSM_SM_BLKSZ);
	}
	return (n);
}

/*
 * Trace current Inbound Message host sent to SPC.
 */
void
pmcs_iqp_trace(pmcs_hw_t *pwp, uint32_t qnum)
{
	uint32_t k = 0;
	int n = 0;
	uint32_t *ptr = NULL;
	char *tbuf = pwp->iqpt->curpos;
	uint32_t size_left = pwp->iqpt->size_left;

	if (tbuf == NULL) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: trace buffer is not ready,"
		    " Inbound Message from host to SPC is not traced",
		    __func__);
		return;
	} else if (size_left < PMCS_QENTRY_SIZE * PMCS_QENTRY_SIZE) {
		tbuf = pwp->iqpt->curpos = pwp->iqpt->head;
		size_left = pwp->iqpt->size_left = PMCS_IQP_TRACE_BUFFER_SIZE;
	}

	ptr = &pwp->iqp[qnum][pwp->shadow_iqpi[qnum] *
	    (PMCS_QENTRY_SIZE >> 2)];
	for (k = 0; k < (PMCS_QENTRY_SIZE / sizeof (uint32_t));
	    k += 8) {
		n += snprintf(&tbuf[n], (size_left - n),
		    "0x%08x 0x%08x 0x%08x 0x%08x "
		    "0x%08x 0x%08x 0x%08x 0x%08x\n",
		    LE_32(ptr[k]), LE_32(ptr[k+1]),
		    LE_32(ptr[k+2]), LE_32(ptr[k+3]),
		    LE_32(ptr[k+4]), LE_32(ptr[k+5]),
		    LE_32(ptr[k+6]), LE_32(ptr[k+7]));
	}
	pwp->iqpt->size_left -= n;
	if (pwp->iqpt->size_left > 0) {
		pwp->iqpt->curpos += n;
	} else {
		pwp->iqpt->curpos =
		    pwp->iqpt->head + PMCS_IQP_TRACE_BUFFER_SIZE - 1;
	}
}

/*
 * Capture HSST State Registers.
 */
static int
pmcs_dump_hsst_sregs(pmcs_hw_t *pwp, caddr_t buf, uint32_t size_left)
{
	uint32_t i = 0, j = 0, addr = 0;
	int n = 0;

	n += snprintf(&buf[n], (size_left - n), "\nHSST State Capture : \n"
	    "-----------------\n");
	n += snprintf(&buf[n], (size_left - n), "%s \t %s \n",
	    hsst_state[8].desc ? hsst_state[8].desc : "NULL",
	    hsst_state[16].desc ? hsst_state[16].desc : "NULL");

	for (i = 0; i < 8; i++) {
		addr = hsst_state[i].offset_start +
		    hsst_state[i].shift_addr;
		n += snprintf(&buf[n], (size_left - n), "Phy[%1d]\n", i);
		for (j = 0; j < 6; j++) {
			pmcs_wr_gsm_reg(pwp, addr, j);
			pmcs_wr_gsm_reg(pwp, addr, (0x0100 + j));
			addr = hsst_state[i+8].offset_start +
			    hsst_state[i+8].shift_addr;
			n += snprintf(&buf[n], (size_left - n),
			    "[%08X]: %08X\t", addr, pmcs_rd_gsm_reg(pwp, addr));
			addr = hsst_state[i+16].offset_start +
			    hsst_state[i+16].shift_addr;
			n += snprintf(&buf[n], (size_left - n),
			    "[%08X]: %08X\n", addr, pmcs_rd_gsm_reg(pwp, addr));
		}

	}
	return (n);

}

/*
 * Capture SSPA State Registers.
 */
static int
pmcs_dump_sspa_sregs(pmcs_hw_t *pwp, caddr_t buf, uint32_t size_left)
{
	uint32_t i = 0, rv = 0, addr = 0;
	int n = 0;

	n += snprintf(&buf[n], (size_left - n), "\nSSPA State Capture : \n"
	    "-----------------\n");
	for (i = 0; i < 8; i++) {
		if (sspa_state[i].flag & PMCS_SPREGS_BLOCK_START) {
			n += snprintf(&buf[n], (size_left - n), "%s \n",
			    sspa_state[i].desc ? sspa_state[i].desc : "NULL");
		}
		addr = sspa_state[i].offset_start + sspa_state[i].shift_addr;
		rv = pmcs_rd_gsm_reg(pwp, addr);
		rv |= PMCS_SSPA_CONTROL_REGISTER_BIT27;
		pmcs_wr_gsm_reg(pwp, addr, rv);
		n += snprintf(&buf[n], (size_left - n), "[%08X]: %08X \n",
		    addr, pmcs_rd_gsm_reg(pwp, addr));

	}
	return (n);
}

/*
 * Dump fatal error register content from GSM.
 */
int
pmcs_dump_feregs(pmcs_hw_t *pwp, uint32_t *addr, uint8_t nvmd,
    caddr_t buf, uint32_t size_left)
{
	uint32_t offset = 0, length = 0;
	int i = 0;
	uint8_t *ptr = (uint8_t *)addr;

	if ((addr == NULL) || (buf == NULL)) {
		return (0);
	}
	switch (nvmd) {
		case PMCIN_NVMD_AAP1:
			offset = pmcs_rd_mpi_tbl(pwp, PMCS_FERDOMSGU);
			length = pmcs_rd_mpi_tbl(pwp, PMCS_FERDLMSGU);
			break;
		case PMCIN_NVMD_IOP:
			offset = pmcs_rd_mpi_tbl(pwp, PMCS_FERDOIOP);
			length = pmcs_rd_mpi_tbl(pwp, PMCS_FERDLIOP);
			break;
		default:
			pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
			    "UNKNOWN NVMD DEVICE %s():%d", __func__, __LINE__);
			return (0);
	}

	while ((i < length) && (ptr[i + offset] != 0xff) &&
	    (ptr[i + offset] != '\0')) {
		i += snprintf(&buf[i], (size_left - i),
		    "%c", ptr[i + offset]);
	}
	return (i);
}

/*
 * Write out either the AAP1 or IOP event log
 */
static void
pmcs_write_fwlog(pmcs_hw_t *pwp, pmcs_fw_event_hdr_t *fwlogp)
{
	struct vnode *vnp;
	caddr_t fwlogfile, bufp;
	rlim64_t rlimit;
	ssize_t resid;
	offset_t offset = 0;
	int error;
	uint32_t data_len;

	if (fwlogp == pwp->fwlogp_aap1) {
		fwlogfile = pwp->fwlogfile_aap1;
	} else {
		fwlogfile = pwp->fwlogfile_iop;
	}

	if ((error = vn_open(fwlogfile, UIO_SYSSPACE, FCREAT|FWRITE, 0644,
	    &vnp, CRCREAT, 0)) != 0) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: Could not create '%s', error %d", __func__,
		    fwlogfile, error);
		return;
	}

	bufp = (caddr_t)fwlogp;
	data_len = PMCS_FWLOG_SIZE / 2;
	rlimit = data_len + 1;
	for (;;) {
		error = vn_rdwr(UIO_WRITE, vnp, bufp, data_len, offset,
		    UIO_SYSSPACE, FSYNC, rlimit, CRED(), &resid);
		if (error) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
			    "%s: could not write %s, error %d", __func__,
			    fwlogfile, error);
			break;
		}
		if (resid == data_len) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
			    "%s: Out of space in %s, error %d", __func__,
			    fwlogfile, error);
			error = ENOSPC;
			break;
		}
		if (resid == 0)
			break;
		offset += (data_len - resid);
		data_len = (ssize_t)resid;
	}

	if (error = VOP_CLOSE(vnp, FWRITE, 1, (offset_t)0, kcred, NULL)) {
		if (!error) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
			    "%s: Error on close %s, error %d", __func__,
			    fwlogfile, error);
		}
	}

	VN_RELE(vnp);
}

/*
 * Check the in-memory event log.  If it's filled up to or beyond the
 * threshold, write it out to the configured filename.
 */
void
pmcs_gather_fwlog(pmcs_hw_t *pwp)
{
	uint32_t num_entries_aap1, num_entries_iop, fname_suffix;

	ASSERT(!mutex_owned(&pwp->lock));

	/*
	 * Get our copies of the latest indices
	 */
	pwp->fwlog_latest_idx_aap1 = pwp->fwlogp_aap1->fw_el_latest_idx;
	pwp->fwlog_latest_idx_iop = pwp->fwlogp_iop->fw_el_latest_idx;

	/*
	 * We need entries in the log before we can know how big they are
	 */
	if ((pwp->fwlog_max_entries_aap1 == 0) &&
	    (pwp->fwlogp_aap1->fw_el_latest_idx != 0)) {
		pwp->fwlog_max_entries_aap1 =
		    (PMCS_FWLOG_SIZE / 2) / pwp->fwlogp_aap1->fw_el_entry_size;
		pwp->fwlog_threshold_aap1 =
		    (pwp->fwlog_max_entries_aap1 * PMCS_FWLOG_THRESH) / 100;
	}

	if ((pwp->fwlog_max_entries_iop == 0) &&
	    (pwp->fwlogp_iop->fw_el_latest_idx != 0)) {
		pwp->fwlog_max_entries_iop =
		    (PMCS_FWLOG_SIZE / 2) / pwp->fwlogp_iop->fw_el_entry_size;
		pwp->fwlog_threshold_iop =
		    (pwp->fwlog_max_entries_iop * PMCS_FWLOG_THRESH) / 100;
	}

	/*
	 * Check if we've reached the threshold in the AAP1 log.  We do this
	 * by comparing the latest index with our copy of the oldest index
	 * (not the chip's).
	 */
	if (pwp->fwlog_latest_idx_aap1 >= pwp->fwlog_oldest_idx_aap1) {
		/* Log has not wrapped */
		num_entries_aap1 =
		    pwp->fwlog_latest_idx_aap1 - pwp->fwlog_oldest_idx_aap1;
	} else {
		/* Log has wrapped */
		num_entries_aap1 = pwp->fwlog_max_entries_aap1 -
		    (pwp->fwlog_oldest_idx_aap1 - pwp->fwlog_latest_idx_aap1);
	}

	/*
	 * Now check the IOP log
	 */
	if (pwp->fwlog_latest_idx_iop >= pwp->fwlog_oldest_idx_iop) {
		/* Log has not wrapped */
		num_entries_iop = pwp->fwlog_latest_idx_iop -
		    pwp->fwlog_oldest_idx_iop;
	} else {
		/* Log has wrapped */
		num_entries_iop = pwp->fwlog_max_entries_iop -
		    (pwp->fwlog_oldest_idx_iop - pwp->fwlog_latest_idx_iop);
	}

	if ((num_entries_aap1 < pwp->fwlog_threshold_aap1) &&
	    (num_entries_iop < pwp->fwlog_threshold_iop)) {
		return;
	}

	/*
	 * We also can't write the event log out if it's too early in boot
	 * (i.e. the root fs isn't mounted yet).
	 */
	if (!modrootloaded) {
		return;
	}

	/*
	 * Write out the necessary log file(s), update the "oldest" pointers
	 * and the suffix to the written filenames.
	 */
	if (num_entries_aap1 >= pwp->fwlog_threshold_aap1) {
		pmcs_write_fwlog(pwp, pwp->fwlogp_aap1);
		pwp->fwlog_oldest_idx_aap1 = pwp->fwlog_latest_idx_aap1;

		fname_suffix = strlen(pwp->fwlogfile_aap1) - 1;
		if (pwp->fwlogfile_aap1[fname_suffix] == '4') {
			pwp->fwlogfile_aap1[fname_suffix] = '0';
		} else {
			++pwp->fwlogfile_aap1[fname_suffix];
		}
	}

	if (num_entries_iop >= pwp->fwlog_threshold_iop) {
		pmcs_write_fwlog(pwp, pwp->fwlogp_iop);
		pwp->fwlog_oldest_idx_iop = pwp->fwlog_latest_idx_iop;

		fname_suffix = strlen(pwp->fwlogfile_iop) - 1;
		if (pwp->fwlogfile_iop[fname_suffix] == '4') {
			pwp->fwlogfile_iop[fname_suffix] = '0';
		} else {
			++pwp->fwlogfile_iop[fname_suffix];
		}
	}
}
