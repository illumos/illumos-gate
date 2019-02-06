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
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

#include <limits.h>
#include <sys/mdb_modapi.h>
#include <mdb/mdb_ctf.h>
#include <sys/sysinfo.h>
#include <sys/byteorder.h>
#include <sys/nvpair.h>
#include <sys/damap.h>
#include <sys/scsi/scsi.h>
#include <sys/scsi/adapters/pmcs/pmcs.h>
#ifndef _KMDB
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#endif	/* _KMDB */

/*
 * We need use this to pass the settings when display_iport
 */
typedef struct per_iport_setting {
	uint_t  pis_damap_info; /* -m: DAM/damap */
	uint_t  pis_dtc_info; /* -d: device tree children: dev_info/path_info */
} per_iport_setting_t;

/*
 * This structure is used for sorting work structures by the wserno
 */
typedef struct wserno_list {
	int serno;
	int idx;
	struct wserno_list *next;
	struct wserno_list *prev;
} wserno_list_t;

#define	MDB_RD(a, b, c)		mdb_vread(a, b, (uintptr_t)c)
#define	NOREAD(a, b)		mdb_warn("could not read " #a " at 0x%p", b)

static pmcs_hw_t ss;
static pmcs_xscsi_t **targets = NULL;
static int target_idx;

static uint32_t	sas_phys, sata_phys, exp_phys, num_expanders, empty_phys;

static pmcs_phy_t *pmcs_next_sibling(pmcs_phy_t *phyp);
static void display_one_work(pmcwork_t *wp, int verbose, int idx);

static void
print_sas_address(pmcs_phy_t *phy)
{
	int idx;

	for (idx = 0; idx < 8; idx++) {
		mdb_printf("%02x", phy->sas_address[idx]);
	}
}

static void
pmcs_fwtime_to_systime(struct pmcs_hw ss, uint32_t fw_hi, uint32_t fw_lo,
    struct timespec *stime)
{
	uint64_t fwtime;
	time_t secs;
	long nsecs;
	boolean_t backward_time = B_FALSE;

	fwtime = ((uint64_t)fw_hi << 32) | fw_lo;

	/*
	 * If fwtime < ss.fw_timestamp, then we need to adjust the clock
	 * time backwards from ss.sys_timestamp.  Otherwise, the adjustment
	 * goes forward in time
	 */
	if (fwtime >= ss.fw_timestamp) {
		fwtime -= ss.fw_timestamp;
	} else {
		fwtime = ss.fw_timestamp - fwtime;
		backward_time = B_TRUE;
	}

	secs = ((time_t)fwtime / NSECS_PER_SEC);
	nsecs = ((long)fwtime % NSECS_PER_SEC);

	stime->tv_sec = ss.sys_timestamp.tv_sec;
	stime->tv_nsec = ss.sys_timestamp.tv_nsec;

	if (backward_time) {
		if (stime->tv_nsec < nsecs) {
			stime->tv_sec--;
			stime->tv_nsec = stime->tv_nsec + NSECS_PER_SEC - nsecs;
		} else {
			stime->tv_nsec -= nsecs;
		}
		stime->tv_sec -= secs;
	} else {
		if (stime->tv_nsec + nsecs > NSECS_PER_SEC) {
			stime->tv_sec++;
		}
		stime->tv_nsec = (stime->tv_nsec + nsecs) % NSECS_PER_SEC;
		stime->tv_sec += secs;
	}
}

/*ARGSUSED*/
static void
display_ic(struct pmcs_hw m, int verbose)
{
	int msec_per_tick;

	if (mdb_readvar(&msec_per_tick, "msec_per_tick") == -1) {
		mdb_warn("can't read msec_per_tick");
		msec_per_tick = 0;
	}

	mdb_printf("\n");
	mdb_printf("Interrupt coalescing timer info\n");
	mdb_printf("-------------------------------\n");
	if (msec_per_tick == 0) {
		mdb_printf("Quantum                       : ?? ms\n");
	} else {
		mdb_printf("Quantum                       : %d ms\n",
		    m.io_intr_coal.quantum * msec_per_tick);
	}
	mdb_printf("Timer enabled                 : ");
	if (m.io_intr_coal.timer_on) {
		mdb_printf("Yes\n");
		mdb_printf("Coalescing timer value        : %d us\n",
		    m.io_intr_coal.intr_coal_timer);
	} else {
		mdb_printf("No\n");
	}
	mdb_printf("Total nsecs between interrupts: %ld\n",
	    m.io_intr_coal.nsecs_between_intrs);
	mdb_printf("Time of last I/O interrupt    : %ld\n",
	    m.io_intr_coal.last_io_comp);
	mdb_printf("Number of I/O interrupts      : %d\n",
	    m.io_intr_coal.num_intrs);
	mdb_printf("Number of I/O completions     : %d\n",
	    m.io_intr_coal.num_io_completions);
	mdb_printf("Max I/O completion interrupts : %d\n",
	    m.io_intr_coal.max_io_completions);
	mdb_printf("Measured ECHO int latency     : %d ns\n",
	    m.io_intr_coal.intr_latency);
	mdb_printf("Interrupt threshold           : %d\n",
	    m.io_intr_coal.intr_threshold);
}

/*ARGSUSED*/
static int
pmcs_iport_phy_walk_cb(uintptr_t addr, const void *wdata, void *priv)
{
	struct pmcs_phy		phy;

	if (mdb_vread(&phy, sizeof (struct pmcs_phy), addr) !=
	    sizeof (struct pmcs_phy)) {
		return (DCMD_ERR);
	}

	mdb_printf("%16p %2d\n", addr, phy.phynum);

	return (0);
}

static int
display_iport_damap(dev_info_t *pdip)
{
	int rval = DCMD_ERR;
	struct dev_info dip;
	scsi_hba_tran_t sht;
	mdb_ctf_id_t istm_ctfid; /* impl_scsi_tgtmap_t ctf_id */
	ulong_t tmd_offset = 0; /* tgtmap_dam offset to impl_scsi_tgtmap_t */
	uintptr_t dam0;
	uintptr_t dam1;

	if (mdb_vread(&dip, sizeof (struct dev_info), (uintptr_t)pdip) !=
	    sizeof (struct dev_info)) {
		return (rval);
	}

	if (dip.devi_driver_data == NULL) {
		return (rval);
	}

	if (mdb_vread(&sht, sizeof (scsi_hba_tran_t),
	    (uintptr_t)dip.devi_driver_data) != sizeof (scsi_hba_tran_t)) {
		return (rval);
	}

	if (sht.tran_tgtmap == NULL) {
		return (rval);
	}

	if (mdb_ctf_lookup_by_name("impl_scsi_tgtmap_t", &istm_ctfid) != 0) {
		return (rval);
	}

	if (mdb_ctf_offsetof(istm_ctfid, "tgtmap_dam", &tmd_offset) != 0) {
		return (rval);
	}

	tmd_offset /= NBBY;
	mdb_vread(&dam0, sizeof (dam0),
	    (uintptr_t)(tmd_offset + (char *)sht.tran_tgtmap));
	mdb_vread(&dam1, sizeof (dam1),
	    (uintptr_t)(sizeof (dam0) + tmd_offset + (char *)sht.tran_tgtmap));

	if (dam0 != 0) {
		rval = mdb_call_dcmd("damap", dam0, DCMD_ADDRSPEC, 0, NULL);
		mdb_printf("\n");
		if (rval != DCMD_OK) {
			return (rval);
		}
	}

	if (dam1 != 0) {
		rval = mdb_call_dcmd("damap", dam1, DCMD_ADDRSPEC, 0, NULL);
		mdb_printf("\n");
	}

	return (rval);
}

/* ARGSUSED */
static int
display_iport_di_cb(uintptr_t addr, const void *wdata, void *priv)
{
	uint_t *idx = (uint_t *)priv;
	struct dev_info dip;
	char devi_name[MAXNAMELEN];
	char devi_addr[MAXNAMELEN];

	if (mdb_vread(&dip, sizeof (struct dev_info), (uintptr_t)addr) !=
	    sizeof (struct dev_info)) {
		return (DCMD_ERR);
	}

	if (mdb_readstr(devi_name, sizeof (devi_name),
	    (uintptr_t)dip.devi_node_name) == -1) {
		devi_name[0] = '?';
		devi_name[1] = '\0';
	}

	if (mdb_readstr(devi_addr, sizeof (devi_addr),
	    (uintptr_t)dip.devi_addr) == -1) {
		devi_addr[0] = '?';
		devi_addr[1] = '\0';
	}

	mdb_printf("  %3d: @%-21s%10s@\t%p::devinfo -s\n",
	    (*idx)++, devi_addr, devi_name, addr);
	return (DCMD_OK);
}

/* ARGSUSED */
static int
display_iport_pi_cb(uintptr_t addr, const void *wdata, void *priv)
{
	uint_t *idx = (uint_t *)priv;
	struct mdi_pathinfo mpi;
	char pi_addr[MAXNAMELEN];

	if (mdb_vread(&mpi, sizeof (struct mdi_pathinfo), (uintptr_t)addr) !=
	    sizeof (struct mdi_pathinfo)) {
		return (DCMD_ERR);
	}

	if (mdb_readstr(pi_addr, sizeof (pi_addr),
	    (uintptr_t)mpi.pi_addr) == -1) {
		pi_addr[0] = '?';
		pi_addr[1] = '\0';
	}

	mdb_printf("  %3d: @%-21s %p::print struct mdi_pathinfo\n",
	    (*idx)++, pi_addr, addr);
	return (DCMD_OK);
}

static int
display_iport_dtc(dev_info_t *pdip)
{
	int rval = DCMD_ERR;
	struct dev_info dip;
	struct mdi_phci phci;
	uint_t didx = 1;
	uint_t pidx = 1;

	if (mdb_vread(&dip, sizeof (struct dev_info), (uintptr_t)pdip) !=
	    sizeof (struct dev_info)) {
		return (rval);
	}

	mdb_printf("Device tree children - dev_info:\n");
	if (dip.devi_child == NULL) {
		mdb_printf("\tdevi_child is NULL, no dev_info\n\n");
		goto skip_di;
	}

	/*
	 * First, we dump the iport's children dev_info node information.
	 * use existing walker: devinfo_siblings
	 */
	mdb_printf("\t#: @unit-address               name@\tdrill-down\n");
	rval = mdb_pwalk("devinfo_siblings", display_iport_di_cb,
	    (void *)&didx, (uintptr_t)dip.devi_child);
	mdb_printf("\n");

skip_di:
	/*
	 * Then we try to dump the iport's path_info node information.
	 * use existing walker: mdipi_phci_list
	 */
	mdb_printf("Device tree children - path_info:\n");
	if (mdb_vread(&phci, sizeof (struct mdi_phci),
	    (uintptr_t)dip.devi_mdi_xhci) != sizeof (struct mdi_phci)) {
		mdb_printf("\tdevi_mdi_xhci is NULL, no path_info\n\n");
		return (rval);
	}

	if (phci.ph_path_head == NULL) {
		mdb_printf("\tph_path_head is NULL, no path_info\n\n");
		return (rval);
	}

	mdb_printf("\t#: @unit-address          drill-down\n");
	rval = mdb_pwalk("mdipi_phci_list", display_iport_pi_cb,
	    (void *)&pidx, (uintptr_t)phci.ph_path_head);
	mdb_printf("\n");
	return (rval);
}

static void
display_iport_more(dev_info_t *dip, per_iport_setting_t *pis)
{
	if (pis->pis_damap_info) {
		(void) display_iport_damap(dip);
	}

	if (pis->pis_dtc_info) {
		(void) display_iport_dtc(dip);
	}
}

/*ARGSUSED*/
static int
pmcs_iport_walk_cb(uintptr_t addr, const void *wdata, void *priv)
{
	struct pmcs_iport	iport;
	uintptr_t		list_addr;
	char			*ua_state;
	char			portid[4];
	char			unit_address[34];
	per_iport_setting_t	*pis = (per_iport_setting_t *)priv;

	if (mdb_vread(&iport, sizeof (struct pmcs_iport), addr) !=
	    sizeof (struct pmcs_iport)) {
		return (DCMD_ERR);
	}

	if (mdb_readstr(unit_address, sizeof (unit_address),
	    (uintptr_t)(iport.ua)) == -1) {
		strncpy(unit_address, "Unset", sizeof (unit_address));
	}

	if (iport.portid == 0xffff) {
		mdb_snprintf(portid, sizeof (portid), "%s", "-");
	} else if (iport.portid == PMCS_IPORT_INVALID_PORT_ID) {
		mdb_snprintf(portid, sizeof (portid), "%s", "N/A");
	} else {
		mdb_snprintf(portid, sizeof (portid), "%d", iport.portid);
	}

	switch (iport.ua_state) {
	case UA_INACTIVE:
		ua_state = "Inactive";
		break;
	case UA_PEND_ACTIVATE:
		ua_state = "PendActivate";
		break;
	case UA_ACTIVE:
		ua_state = "Active";
		break;
	case UA_PEND_DEACTIVATE:
		ua_state = "PendDeactivate";
		break;
	default:
		ua_state = "Unknown";
	}

	if (strlen(unit_address) < 3) {
		/* Standard iport unit address */
		mdb_printf("UA %-16s %16s %8s %8s %16s", "Iport", "UA State",
		    "PortID", "NumPhys", "DIP\n");
		mdb_printf("%2s %16p %16s %8s %8d %16p\n", unit_address, addr,
		    ua_state, portid, iport.nphy, iport.dip);
	} else {
		/* Temporary iport unit address */
		mdb_printf("%-32s %16s %20s %8s %8s %16s", "UA", "Iport",
		    "UA State", "PortID", "NumPhys", "DIP\n");
		mdb_printf("%32s %16p %20s %8s %8d %16p\n", unit_address, addr,
		    ua_state, portid, iport.nphy, iport.dip);
	}

	if (iport.nphy > 0) {
		mdb_inc_indent(4);
		mdb_printf("%-18s %8s", "Phy", "PhyNum\n");
		mdb_inc_indent(2);
		list_addr =
		    (uintptr_t)(addr + offsetof(struct pmcs_iport, phys));
		if (mdb_pwalk("list", pmcs_iport_phy_walk_cb, NULL,
		    list_addr) == -1) {
			mdb_warn("pmcs iport walk failed");
		}
		mdb_dec_indent(6);
		mdb_printf("\n");
	}

	/*
	 * See if we need to show more information based on 'd' or 'm' options
	 */
	display_iport_more(iport.dip, pis);

	return (0);
}

/*ARGSUSED*/
static void
display_iport(struct pmcs_hw m, uintptr_t addr, int verbose,
    per_iport_setting_t *pis)
{
	uintptr_t	list_addr;

	if (m.iports_attached) {
		mdb_printf("Iport information:\n");
		mdb_printf("-----------------\n");
	} else {
		mdb_printf("No Iports found.\n\n");
		return;
	}

	list_addr = (uintptr_t)(addr + offsetof(struct pmcs_hw, iports));

	if (mdb_pwalk("list", pmcs_iport_walk_cb, pis, list_addr) == -1) {
		mdb_warn("pmcs iport walk failed");
	}

	mdb_printf("\n");
}

/* ARGSUSED */
static int
pmcs_utarget_walk_cb(uintptr_t addr, const void *wdata, void *priv)
{
	pmcs_phy_t phy;

	if (mdb_vread(&phy, sizeof (pmcs_phy_t), (uintptr_t)addr) == -1) {
		mdb_warn("pmcs_utarget_walk_cb: Failed to read PHY at %p",
		    (void *)addr);
		return (DCMD_ERR);
	}

	if (phy.configured && (phy.target == NULL)) {
		mdb_printf("SAS address: ");
		print_sas_address(&phy);
		mdb_printf("  DType: ");
		switch (phy.dtype) {
		case SAS:
			mdb_printf("%4s", "SAS");
			break;
		case SATA:
			mdb_printf("%4s", "SATA");
			break;
		case EXPANDER:
			mdb_printf("%4s", "SMP");
			break;
		default:
			mdb_printf("%4s", "N/A");
			break;
		}
		mdb_printf("  Path: %s\n", phy.path);
	}

	return (0);
}

static void
display_unconfigured_targets(uintptr_t addr)
{
	mdb_printf("Unconfigured target SAS address:\n\n");

	if (mdb_pwalk("pmcs_phys", pmcs_utarget_walk_cb, NULL, addr) == -1) {
		mdb_warn("pmcs phys walk failed");
	}
}

static void
display_completion_queue(struct pmcs_hw ss)
{
	pmcs_iocomp_cb_t ccb, *ccbp;
	pmcwork_t work;

	if (ss.iocomp_cb_head == NULL) {
		mdb_printf("Completion queue is empty.\n");
		return;
	}

	ccbp = ss.iocomp_cb_head;
	mdb_printf("%8s %10s %20s %8s %8s O D\n",
	    "HTag", "State", "Phy Path", "Target", "Timer");

	while (ccbp) {
		if (mdb_vread(&ccb, sizeof (pmcs_iocomp_cb_t),
		    (uintptr_t)ccbp) != sizeof (pmcs_iocomp_cb_t)) {
			mdb_warn("Unable to read completion queue entry\n");
			return;
		}

		if (mdb_vread(&work, sizeof (pmcwork_t), (uintptr_t)ccb.pwrk)
		    != sizeof (pmcwork_t)) {
			mdb_warn("Unable to read work structure\n");
			return;
		}

		/*
		 * Only print the work structure if it's still active.  If
		 * it's not, it's been completed since we started looking at
		 * it.
		 */
		if (work.state != PMCS_WORK_STATE_NIL) {
			display_one_work(&work, 0, 0);
		}
		ccbp = ccb.next;
	}
}

static void
display_event_log(struct pmcs_hw ss)
{
	pmcs_fw_event_hdr_t fwhdr;
	char *header_id, *entry, *fwlogp;
	uint32_t total_size = PMCS_FWLOG_SIZE, log_size, index, *swapp, sidx;
	pmcs_fw_event_entry_t *fw_entryp;
	struct timespec systime;

	if (ss.fwlogp == NULL) {
		mdb_printf("There is no firmware event log.\n");
		return;
	}

	fwlogp = (char *)ss.fwlogp;

	while (total_size != 0) {
		if (mdb_vread(&fwhdr, sizeof (pmcs_fw_event_hdr_t),
		    (uintptr_t)fwlogp) != sizeof (pmcs_fw_event_hdr_t)) {
			mdb_warn("Unable to read firmware event log header\n");
			return;
		}

		/*
		 * Firmware event log is little-endian
		 */
		swapp = (uint32_t *)&fwhdr;
		for (sidx = 0; sidx < (sizeof (pmcs_fw_event_hdr_t) /
		    sizeof (uint32_t)); sidx++) {
			*swapp = LE_32(*swapp);
			swapp++;
		}

		if (fwhdr.fw_el_signature == PMCS_FWLOG_AAP1_SIG) {
			header_id = "AAP1";
		} else if (fwhdr.fw_el_signature == PMCS_FWLOG_IOP_SIG) {
			header_id = "IOP";
		} else {
			mdb_warn("Invalid firmware event log signature\n");
			return;
		}

		mdb_printf("Event Log:    %s\n", header_id);
		mdb_printf("Oldest entry: %d\n", fwhdr.fw_el_oldest_idx);
		mdb_printf("Latest entry: %d\n", fwhdr.fw_el_latest_idx);

		entry = mdb_alloc(fwhdr.fw_el_entry_size, UM_SLEEP);
		fw_entryp = (pmcs_fw_event_entry_t *)((void *)entry);
		total_size -= sizeof (pmcs_fw_event_hdr_t);
		log_size = fwhdr.fw_el_buf_size;
		fwlogp += fwhdr.fw_el_entry_start_offset;
		swapp = (uint32_t *)((void *)entry);
		index = 0;

		mdb_printf("%8s %16s %32s %8s %3s %8s %8s %8s %8s",
		    "Index", "Timestamp", "Time", "Seq Num", "Sev", "Word 0",
		    "Word 1", "Word 2", "Word 3");
		mdb_printf("\n");

		while (log_size != 0) {
			if (mdb_vread(entry, fwhdr.fw_el_entry_size,
			    (uintptr_t)fwlogp) != fwhdr.fw_el_entry_size) {
				mdb_warn("Unable to read event log entry\n");
				goto bail_out;
			}

			for (sidx = 0; sidx < (fwhdr.fw_el_entry_size /
			    sizeof (uint32_t)); sidx++) {
				*(swapp + sidx) = LE_32(*(swapp + sidx));
			}

			if (fw_entryp->ts_upper || fw_entryp->ts_lower) {
				pmcs_fwtime_to_systime(ss, fw_entryp->ts_upper,
				    fw_entryp->ts_lower, &systime);
				mdb_printf("%8d %08x%08x [%Y.%09ld] %8d %3d "
				    "%08x %08x %08x %08x\n", index,
				    fw_entryp->ts_upper, fw_entryp->ts_lower,
				    systime, fw_entryp->seq_num,
				    fw_entryp->severity, fw_entryp->logw0,
				    fw_entryp->logw1, fw_entryp->logw2,
				    fw_entryp->logw3);
			}

			fwlogp += fwhdr.fw_el_entry_size;
			total_size -= fwhdr.fw_el_entry_size;
			log_size -= fwhdr.fw_el_entry_size;
			index++;
		}

		mdb_printf("\n");
	}

bail_out:
	mdb_free(entry, fwhdr.fw_el_entry_size);
}

/*ARGSUSED*/
static void
display_hwinfo(struct pmcs_hw m, int verbose)
{
	struct pmcs_hw	*mp = &m;
	char		*fwsupport;

	switch (PMCS_FW_TYPE(mp)) {
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

	mdb_printf("\nHardware information:\n");
	mdb_printf("---------------------\n");

	mdb_printf("Chip revision:    %c\n", 'A' + m.chiprev);
	mdb_printf("SAS WWID:         %"PRIx64"\n", m.sas_wwns[0]);
	mdb_printf("Firmware version: %x.%x.%x (%s)\n",
	    PMCS_FW_MAJOR(mp), PMCS_FW_MINOR(mp), PMCS_FW_MICRO(mp),
	    fwsupport);
	mdb_printf("ILA version:      %08x\n", m.ila_ver);
	mdb_printf("Active f/w img:   %c\n", (m.fw_active_img) ? 'A' : 'B');

	mdb_printf("Number of PHYs:   %d\n", m.nphy);
	mdb_printf("Maximum commands: %d\n", m.max_cmd);
	mdb_printf("Maximum devices:  %d\n", m.max_dev);
	mdb_printf("I/O queue depth:  %d\n", m.ioq_depth);
	mdb_printf("Open retry intvl: %d usecs\n", m.open_retry_interval);
	if (m.fwlog == 0) {
		mdb_printf("Firmware logging: Disabled\n");
	} else {
		mdb_printf("Firmware logging: Enabled (%d)\n", m.fwlog);
	}
	if (m.fwlog_file == 0) {
		mdb_printf("Firmware logfile: Not configured\n");
	} else {
		mdb_printf("Firmware logfile: Configured\n");
		mdb_inc_indent(2);
		mdb_printf("AAP1 log file:  %s\n", m.fwlogfile_aap1);
		mdb_printf("IOP logfile:    %s\n", m.fwlogfile_iop);
		mdb_dec_indent(2);
	}
}

static void
display_targets(struct pmcs_hw m, int verbose, int totals_only)
{
	char		*dtype;
	pmcs_xscsi_t	xs;
	pmcs_phy_t	phy;
	uint16_t	max_dev, idx;
	uint32_t	sas_targets = 0, smp_targets = 0, sata_targets = 0;

	max_dev = m.max_dev;

	if (targets == NULL) {
		targets = mdb_alloc(sizeof (targets) * max_dev, UM_SLEEP);
	}

	if (MDB_RD(targets, sizeof (targets) * max_dev, m.targets) == -1) {
		NOREAD(targets, m.targets);
		return;
	}

	if (!totals_only) {
		mdb_printf("\nTarget information:\n");
		mdb_printf("---------------------------------------\n");
		mdb_printf("VTGT %-16s %-16s %-5s %4s %6s %s", "SAS Address",
		    "PHY Address", "DType", "Actv", "OnChip", "DS");
		mdb_printf("\n");
	}

	for (idx = 0; idx < max_dev; idx++) {
		if (targets[idx] == NULL) {
			continue;
		}

		if (MDB_RD(&xs, sizeof (xs), targets[idx]) == -1) {
			NOREAD(pmcs_xscsi_t, targets[idx]);
			continue;
		}

		/*
		 * It has to be new or assigned to be of interest.
		 */
		if (xs.new == 0 && xs.assigned == 0) {
			continue;
		}

		switch (xs.dtype) {
		case NOTHING:
			dtype = "None";
			break;
		case SATA:
			dtype = "SATA";
			sata_targets++;
			break;
		case SAS:
			dtype = "SAS";
			sas_targets++;
			break;
		case EXPANDER:
			dtype = "SMP";
			smp_targets++;
			break;
		}

		if (totals_only) {
			continue;
		}

		if (xs.phy) {
			if (MDB_RD(&phy, sizeof (phy), xs.phy) == -1) {
				NOREAD(pmcs_phy_t, xs.phy);
				continue;
			}
			mdb_printf("%4d ", idx);
			print_sas_address(&phy);
			mdb_printf(" %16p", xs.phy);
		} else {
			mdb_printf("%4d %16s", idx, "<no phy avail>");
		}
		mdb_printf(" %5s", dtype);
		mdb_printf(" %4d", xs.actv_pkts);
		mdb_printf(" %6d", xs.actv_cnt);
		mdb_printf(" %2d", xs.dev_state);

		if (verbose) {
			if (xs.new) {
				mdb_printf(" new");
			}
			if (xs.assigned) {
				mdb_printf(" assigned");
			}
			if (xs.draining) {
				mdb_printf(" draining");
			}
			if (xs.reset_wait) {
				mdb_printf(" reset_wait");
			}
			if (xs.resetting) {
				mdb_printf(" resetting");
			}
			if (xs.recover_wait) {
				mdb_printf(" recover_wait");
			}
			if (xs.recovering) {
				mdb_printf(" recovering");
			}
			if (xs.event_recovery) {
				mdb_printf(" event recovery");
			}
			if (xs.special_running) {
				mdb_printf(" special_active");
			}
			if (xs.ncq) {
				mdb_printf(" ncq_tagmap=0x%x qdepth=%d",
				    xs.tagmap, xs.qdepth);
			} else if (xs.pio) {
				mdb_printf(" pio");
			}
		}

		mdb_printf("\n");
	}

	if (!totals_only) {
		mdb_printf("\n");
	}

	mdb_printf("%19s %d (%d SAS + %d SATA + %d SMP)\n",
	    "Configured targets:", (sas_targets + sata_targets + smp_targets),
	    sas_targets, sata_targets, smp_targets);
}

static char *
work_state_to_string(uint32_t state)
{
	char *state_string;

	switch (state) {
	case PMCS_WORK_STATE_NIL:
		state_string = "Free";
		break;
	case PMCS_WORK_STATE_READY:
		state_string = "Ready";
		break;
	case PMCS_WORK_STATE_ONCHIP:
		state_string = "On Chip";
		break;
	case PMCS_WORK_STATE_INTR:
		state_string = "In Intr";
		break;
	case PMCS_WORK_STATE_IOCOMPQ:
		state_string = "I/O Comp";
		break;
	case PMCS_WORK_STATE_ABORTED:
		state_string = "I/O Aborted";
		break;
	case PMCS_WORK_STATE_TIMED_OUT:
		state_string = "I/O Timed Out";
		break;
	default:
		state_string = "INVALID";
		break;
	}

	return (state_string);
}

static void
display_one_work(pmcwork_t *wp, int verbose, int idx)
{
	char		*state, *last_state;
	char		*path;
	pmcs_xscsi_t	xs;
	pmcs_phy_t	phy;
	int		tgt;

	state = work_state_to_string(wp->state);
	last_state = work_state_to_string(wp->last_state);

	if (wp->ssp_event && wp->ssp_event != 0xffffffff) {
		mdb_printf("SSP event 0x%x", wp->ssp_event);
	}

	tgt = -1;
	if (wp->xp) {
		if (MDB_RD(&xs, sizeof (xs), wp->xp) == -1) {
			NOREAD(pmcs_xscsi_t, wp->xp);
		} else {
			tgt = xs.target_num;
		}
	}
	if (wp->phy) {
		if (MDB_RD(&phy, sizeof (phy), wp->phy) == -1) {
			NOREAD(pmcs_phy_t, wp->phy);
		}
		path = phy.path;
	} else {
		path = "N/A";
	}

	if (verbose) {
		mdb_printf("%4d ", idx);
	}
	if (tgt == -1) {
		mdb_printf("%08x %10s %20s      N/A %8u %1d %1d ",
		    wp->htag, state, path, wp->timer,
		    wp->onwire, wp->dead);
	} else {
		mdb_printf("%08x %10s %20s %8d %8u %1d %1d ",
		    wp->htag, state, path, tgt, wp->timer,
		    wp->onwire, wp->dead);
	}
	if (verbose) {
		mdb_printf("%08x %10s 0x%016p 0x%016p 0x%016p\n",
		    wp->last_htag, last_state, wp->last_phy, wp->last_xp,
		    wp->last_arg);
	} else {
		mdb_printf("\n");
	}
}

static void
display_work(struct pmcs_hw m, int verbose, int wserno)
{
	int		idx;
	boolean_t	header_printed = B_FALSE;
	pmcwork_t	*wp;
	wserno_list_t	*sernop, *sp, *newsp, *sphead = NULL;
	uintptr_t	_wp;
	int		serno;

	wp = mdb_alloc(sizeof (pmcwork_t) * m.max_cmd, UM_SLEEP);
	_wp = (uintptr_t)m.work;
	sernop = mdb_alloc(sizeof (wserno_list_t) * m.max_cmd, UM_SLEEP);
	bzero(sernop, sizeof (wserno_list_t) * m.max_cmd);

	mdb_printf("\nActive Work structure information:\n");
	mdb_printf("----------------------------------\n");

	/*
	 * Read in all the work structures
	 */
	for (idx = 0; idx < m.max_cmd; idx++, _wp += sizeof (pmcwork_t)) {
		if (MDB_RD(wp + idx, sizeof (pmcwork_t), _wp) == -1) {
			NOREAD(pmcwork_t, _wp);
			continue;
		}
	}

	/*
	 * Sort by serial number?
	 */
	if (wserno) {
		for (idx = 0; idx < m.max_cmd; idx++) {
			if ((wp + idx)->htag == 0) {
				serno = PMCS_TAG_SERNO((wp + idx)->last_htag);
			} else {
				serno = PMCS_TAG_SERNO((wp + idx)->htag);
			}

			/* Start at the beginning of the list */
			sp = sphead;
			newsp = sernop + idx;
			/* If this is the first entry, just add it */
			if (sphead == NULL) {
				sphead = sernop;
				sphead->serno = serno;
				sphead->idx = idx;
				sphead->next = NULL;
				sphead->prev = NULL;
				continue;
			}

			newsp->serno = serno;
			newsp->idx = idx;

			/* Find out where in the list this goes */
			while (sp) {
				/* This item goes before sp */
				if (serno < sp->serno) {
					newsp->next = sp;
					newsp->prev = sp->prev;
					if (newsp->prev == NULL) {
						sphead = newsp;
					} else {
						newsp->prev->next = newsp;
					}
					sp->prev = newsp;
					break;
				}

				/*
				 * If sp->next is NULL, this entry goes at the
				 * end of the list
				 */
				if (sp->next == NULL) {
					sp->next = newsp;
					newsp->next = NULL;
					newsp->prev = sp;
					break;
				}

				sp = sp->next;
			}
		}

		/*
		 * Now print the sorted list
		 */
		mdb_printf(" Idx %8s %10s %20s %8s %8s O D ",
		    "HTag", "State", "Phy Path", "Target", "Timer");
		mdb_printf("%8s %10s %18s %18s %18s\n", "LastHTAG",
		    "LastState", "LastPHY", "LastTgt", "LastArg");

		sp = sphead;
		while (sp) {
			display_one_work(wp + sp->idx, 1, sp->idx);
			sp = sp->next;
		}

		goto out;
	}

	/*
	 * Now print the list, sorted by index
	 */
	for (idx = 0; idx < m.max_cmd; idx++) {
		if (!verbose && ((wp + idx)->htag == PMCS_TAG_TYPE_FREE)) {
			continue;
		}

		if (header_printed == B_FALSE) {
			if (verbose) {
				mdb_printf("%4s ", "Idx");
			}
			mdb_printf("%8s %10s %20s %8s %8s O D ",
			    "HTag", "State", "Phy Path", "Target", "Timer");
			if (verbose) {
				mdb_printf("%8s %10s %18s %18s %18s\n",
				    "LastHTAG", "LastState", "LastPHY",
				    "LastTgt", "LastArg");
			} else {
				mdb_printf("\n");
			}
			header_printed = B_TRUE;
		}

		display_one_work(wp + idx, verbose, idx);
	}

out:
	mdb_free(wp, sizeof (pmcwork_t) * m.max_cmd);
	mdb_free(sernop, sizeof (wserno_list_t) * m.max_cmd);
}

static void
print_spcmd(pmcs_cmd_t *sp, void *kaddr, int printhdr, int verbose)
{
	int cdb_size, idx;
	struct scsi_pkt pkt;
	uchar_t cdb[256];

	if (printhdr) {
		if (verbose) {
			mdb_printf("%16s %16s %16s %8s %s CDB\n", "Command",
			    "SCSA pkt", "DMA Chunks", "HTAG", "SATL Tag");
		} else {
			mdb_printf("%16s %16s %16s %8s %s\n", "Command",
			    "SCSA pkt", "DMA Chunks", "HTAG", "SATL Tag");
		}
	}

	mdb_printf("%16p %16p %16p %08x %08x ",
	    kaddr, sp->cmd_pkt, sp->cmd_clist, sp->cmd_tag, sp->cmd_satltag);

	/*
	 * If we're printing verbose, dump the CDB as well.
	 */
	if (verbose) {
		if (sp->cmd_pkt) {
			if (mdb_vread(&pkt, sizeof (struct scsi_pkt),
			    (uintptr_t)sp->cmd_pkt) !=
			    sizeof (struct scsi_pkt)) {
				mdb_warn("Unable to read SCSI pkt\n");
				return;
			}
			cdb_size = pkt.pkt_cdblen;
			if (mdb_vread(&cdb[0], cdb_size,
			    (uintptr_t)pkt.pkt_cdbp) != cdb_size) {
				mdb_warn("Unable to read CDB\n");
				return;
			}

			for (idx = 0; idx < cdb_size; idx++) {
				mdb_printf("%02x ", cdb[idx]);
			}
		} else {
			mdb_printf("N/A");
		}

		mdb_printf("\n");
	} else {
		mdb_printf("\n");
	}
}

/*ARGSUSED1*/
static void
display_waitqs(struct pmcs_hw m, int verbose)
{
	pmcs_cmd_t	*sp, s;
	pmcs_xscsi_t	xs;
	int		first, i;
	int		max_dev = m.max_dev;

	sp = m.dq.stqh_first;
	first = 1;
	while (sp) {
		if (first) {
			mdb_printf("\nDead Command Queue:\n");
			mdb_printf("---------------------------\n");
		}
		if (MDB_RD(&s, sizeof (s), sp) == -1) {
			NOREAD(pmcs_cmd_t, sp);
			break;
		}
		print_spcmd(&s, sp, first, verbose);
		sp = s.cmd_next.stqe_next;
		first = 0;
	}

	sp = m.cq.stqh_first;
	first = 1;
	while (sp) {
		if (first) {
			mdb_printf("\nCompletion Command Queue:\n");
			mdb_printf("---------------------------\n");
		}
		if (MDB_RD(&s, sizeof (s), sp) == -1) {
			NOREAD(pmcs_cmd_t, sp);
			break;
		}
		print_spcmd(&s, sp, first, verbose);
		sp = s.cmd_next.stqe_next;
		first = 0;
	}


	if (targets == NULL) {
		targets = mdb_alloc(sizeof (targets) * max_dev, UM_SLEEP);
	}

	if (MDB_RD(targets, sizeof (targets) * max_dev, m.targets) == -1) {
		NOREAD(targets, m.targets);
		return;
	}

	for (i = 0; i < max_dev; i++) {
		if (targets[i] == NULL) {
			continue;
		}
		if (MDB_RD(&xs, sizeof (xs), targets[i]) == -1) {
			NOREAD(pmcs_xscsi_t, targets[i]);
			continue;
		}
		sp = xs.wq.stqh_first;
		first = 1;
		while (sp) {
			if (first) {
				mdb_printf("\nTarget %u Wait Queue:\n",
				    xs.target_num);
				mdb_printf("---------------------------\n");
			}
			if (MDB_RD(&s, sizeof (s), sp) == -1) {
				NOREAD(pmcs_cmd_t, sp);
				break;
			}
			print_spcmd(&s, sp, first, verbose);
			sp = s.cmd_next.stqe_next;
			first = 0;
		}
		sp = xs.aq.stqh_first;
		first = 1;
		while (sp) {
			if (first) {
				mdb_printf("\nTarget %u Active Queue:\n",
				    xs.target_num);
				mdb_printf("---------------------------\n");
			}
			if (MDB_RD(&s, sizeof (s), sp) == -1) {
				NOREAD(pmcs_cmd_t, sp);
				break;
			}
			print_spcmd(&s, sp, first, verbose);
			sp = s.cmd_next.stqe_next;
			first = 0;
		}
		sp = xs.sq.stqh_first;
		first = 1;
		while (sp) {
			if (first) {
				mdb_printf("\nTarget %u Special Queue:\n",
				    xs.target_num);
				mdb_printf("---------------------------\n");
			}
			if (MDB_RD(&s, sizeof (s), sp) == -1) {
				NOREAD(pmcs_cmd_t, sp);
				break;
			}
			print_spcmd(&s, sp, first, verbose);
			sp = s.cmd_next.stqe_next;
			first = 0;
		}
	}
}

static char *
ibq_type(int qnum)
{
	if (qnum < 0 || qnum >= PMCS_NIQ) {
		return ("UNKNOWN");
	}

	if (qnum < PMCS_IQ_OTHER) {
		return ("I/O");
	}

	return ("Other");
}

static char *
obq_type(int qnum)
{
	switch (qnum) {
	case PMCS_OQ_IODONE:
		return ("I/O");
	case PMCS_OQ_GENERAL:
		return ("General");
	case PMCS_OQ_EVENTS:
		return ("Events");
	default:
		return ("UNKNOWN");
	}
}

static char *
iomb_cat(uint32_t cat)
{
	switch (cat) {
	case PMCS_IOMB_CAT_NET:
		return ("NET");
	case PMCS_IOMB_CAT_FC:
		return ("FC");
	case PMCS_IOMB_CAT_SAS:
		return ("SAS");
	case PMCS_IOMB_CAT_SCSI:
		return ("SCSI");
	default:
		return ("???");
	}
}

static char *
iomb_event(uint8_t event)
{
	switch (event) {
	case IOP_EVENT_PHY_STOP_STATUS:
		return ("PHY STOP");
	case IOP_EVENT_SAS_PHY_UP:
		return ("PHY UP");
	case IOP_EVENT_SATA_PHY_UP:
		return ("SATA PHY UP");
	case IOP_EVENT_SATA_SPINUP_HOLD:
		return ("SATA SPINUP HOLD");
	case IOP_EVENT_PHY_DOWN:
		return ("PHY DOWN");
	case IOP_EVENT_BROADCAST_CHANGE:
		return ("BROADCAST CHANGE");
	case IOP_EVENT_BROADCAST_SES:
		return ("BROADCAST SES");
	case IOP_EVENT_PHY_ERR_INBOUND_CRC:
		return ("INBOUND CRC ERROR");
	case IOP_EVENT_HARD_RESET_RECEIVED:
		return ("HARD RESET");
	case IOP_EVENT_EVENT_ID_FRAME_TIMO:
		return ("IDENTIFY FRAME TIMEOUT");
	case IOP_EVENT_BROADCAST_EXP:
		return ("BROADCAST EXPANDER");
	case IOP_EVENT_PHY_START_STATUS:
		return ("PHY START");
	case IOP_EVENT_PHY_ERR_INVALID_DWORD:
		return ("INVALID DWORD");
	case IOP_EVENT_PHY_ERR_DISPARITY_ERROR:
		return ("DISPARITY ERROR");
	case IOP_EVENT_PHY_ERR_CODE_VIOLATION:
		return ("CODE VIOLATION");
	case IOP_EVENT_PHY_ERR_LOSS_OF_DWORD_SYN:
		return ("LOSS OF DWORD SYNC");
	case IOP_EVENT_PHY_ERR_PHY_RESET_FAILD:
		return ("PHY RESET FAILED");
	case IOP_EVENT_PORT_RECOVERY_TIMER_TMO:
		return ("PORT RECOVERY TIMEOUT");
	case IOP_EVENT_PORT_RECOVER:
		return ("PORT RECOVERY");
	case IOP_EVENT_PORT_RESET_TIMER_TMO:
		return ("PORT RESET TIMEOUT");
	case IOP_EVENT_PORT_RESET_COMPLETE:
		return ("PORT RESET COMPLETE");
	case IOP_EVENT_BROADCAST_ASYNC_EVENT:
		return ("BROADCAST ASYNC");
	case IOP_EVENT_IT_NEXUS_LOSS:
		return ("I/T NEXUS LOSS");
	default:
		return ("Unknown Event");
	}
}

static char *
inbound_iomb_opcode(uint32_t opcode)
{
	switch (opcode) {
	case PMCIN_ECHO:
		return ("ECHO");
	case PMCIN_GET_INFO:
		return ("GET_INFO");
	case PMCIN_GET_VPD:
		return ("GET_VPD");
	case PMCIN_PHY_START:
		return ("PHY_START");
	case PMCIN_PHY_STOP:
		return ("PHY_STOP");
	case PMCIN_SSP_INI_IO_START:
		return ("INI_IO_START");
	case PMCIN_SSP_INI_TM_START:
		return ("INI_TM_START");
	case PMCIN_SSP_INI_EXT_IO_START:
		return ("INI_EXT_IO_START");
	case PMCIN_DEVICE_HANDLE_ACCEPT:
		return ("DEVICE_HANDLE_ACCEPT");
	case PMCIN_SSP_TGT_IO_START:
		return ("TGT_IO_START");
	case PMCIN_SSP_TGT_RESPONSE_START:
		return ("TGT_RESPONSE_START");
	case PMCIN_SSP_INI_EDC_EXT_IO_START:
		return ("INI_EDC_EXT_IO_START");
	case PMCIN_SSP_INI_EDC_EXT_IO_START1:
		return ("INI_EDC_EXT_IO_START1");
	case PMCIN_SSP_TGT_EDC_IO_START:
		return ("TGT_EDC_IO_START");
	case PMCIN_SSP_ABORT:
		return ("SSP_ABORT");
	case PMCIN_DEREGISTER_DEVICE_HANDLE:
		return ("DEREGISTER_DEVICE_HANDLE");
	case PMCIN_GET_DEVICE_HANDLE:
		return ("GET_DEVICE_HANDLE");
	case PMCIN_SMP_REQUEST:
		return ("SMP_REQUEST");
	case PMCIN_SMP_RESPONSE:
		return ("SMP_RESPONSE");
	case PMCIN_SMP_ABORT:
		return ("SMP_ABORT");
	case PMCIN_ASSISTED_DISCOVERY:
		return ("ASSISTED_DISCOVERY");
	case PMCIN_REGISTER_DEVICE:
		return ("REGISTER_DEVICE");
	case PMCIN_SATA_HOST_IO_START:
		return ("SATA_HOST_IO_START");
	case PMCIN_SATA_ABORT:
		return ("SATA_ABORT");
	case PMCIN_LOCAL_PHY_CONTROL:
		return ("LOCAL_PHY_CONTROL");
	case PMCIN_GET_DEVICE_INFO:
		return ("GET_DEVICE_INFO");
	case PMCIN_TWI:
		return ("TWI");
	case PMCIN_FW_FLASH_UPDATE:
		return ("FW_FLASH_UPDATE");
	case PMCIN_SET_VPD:
		return ("SET_VPD");
	case PMCIN_GPIO:
		return ("GPIO");
	case PMCIN_SAS_DIAG_MODE_START_END:
		return ("SAS_DIAG_MODE_START_END");
	case PMCIN_SAS_DIAG_EXECUTE:
		return ("SAS_DIAG_EXECUTE");
	case PMCIN_SAS_HW_EVENT_ACK:
		return ("SAS_HW_EVENT_ACK");
	case PMCIN_GET_TIME_STAMP:
		return ("GET_TIME_STAMP");
	case PMCIN_PORT_CONTROL:
		return ("PORT_CONTROL");
	case PMCIN_GET_NVMD_DATA:
		return ("GET_NVMD_DATA");
	case PMCIN_SET_NVMD_DATA:
		return ("SET_NVMD_DATA");
	case PMCIN_SET_DEVICE_STATE:
		return ("SET_DEVICE_STATE");
	case PMCIN_GET_DEVICE_STATE:
		return ("GET_DEVICE_STATE");
	default:
		return ("UNKNOWN");
	}
}

static char *
outbound_iomb_opcode(uint32_t opcode)
{
	switch (opcode) {
	case PMCOUT_ECHO:
		return ("ECHO");
	case PMCOUT_GET_INFO:
		return ("GET_INFO");
	case PMCOUT_GET_VPD:
		return ("GET_VPD");
	case PMCOUT_SAS_HW_EVENT:
		return ("SAS_HW_EVENT");
	case PMCOUT_SSP_COMPLETION:
		return ("SSP_COMPLETION");
	case PMCOUT_SMP_COMPLETION:
		return ("SMP_COMPLETION");
	case PMCOUT_LOCAL_PHY_CONTROL:
		return ("LOCAL_PHY_CONTROL");
	case PMCOUT_SAS_ASSISTED_DISCOVERY_EVENT:
		return ("SAS_ASSISTED_DISCOVERY_SENT");
	case PMCOUT_SATA_ASSISTED_DISCOVERY_EVENT:
		return ("SATA_ASSISTED_DISCOVERY_SENT");
	case PMCOUT_DEVICE_REGISTRATION:
		return ("DEVICE_REGISTRATION");
	case PMCOUT_DEREGISTER_DEVICE_HANDLE:
		return ("DEREGISTER_DEVICE_HANDLE");
	case PMCOUT_GET_DEVICE_HANDLE:
		return ("GET_DEVICE_HANDLE");
	case PMCOUT_SATA_COMPLETION:
		return ("SATA_COMPLETION");
	case PMCOUT_SATA_EVENT:
		return ("SATA_EVENT");
	case PMCOUT_SSP_EVENT:
		return ("SSP_EVENT");
	case PMCOUT_DEVICE_HANDLE_ARRIVED:
		return ("DEVICE_HANDLE_ARRIVED");
	case PMCOUT_SSP_REQUEST_RECEIVED:
		return ("SSP_REQUEST_RECEIVED");
	case PMCOUT_DEVICE_INFO:
		return ("DEVICE_INFO");
	case PMCOUT_FW_FLASH_UPDATE:
		return ("FW_FLASH_UPDATE");
	case PMCOUT_SET_VPD:
		return ("SET_VPD");
	case PMCOUT_GPIO:
		return ("GPIO");
	case PMCOUT_GPIO_EVENT:
		return ("GPIO_EVENT");
	case PMCOUT_GENERAL_EVENT:
		return ("GENERAL_EVENT");
	case PMCOUT_TWI:
		return ("TWI");
	case PMCOUT_SSP_ABORT:
		return ("SSP_ABORT");
	case PMCOUT_SATA_ABORT:
		return ("SATA_ABORT");
	case PMCOUT_SAS_DIAG_MODE_START_END:
		return ("SAS_DIAG_MODE_START_END");
	case PMCOUT_SAS_DIAG_EXECUTE:
		return ("SAS_DIAG_EXECUTE");
	case PMCOUT_GET_TIME_STAMP:
		return ("GET_TIME_STAMP");
	case PMCOUT_SAS_HW_EVENT_ACK_ACK:
		return ("SAS_HW_EVENT_ACK_ACK");
	case PMCOUT_PORT_CONTROL:
		return ("PORT_CONTROL");
	case PMCOUT_SKIP_ENTRIES:
		return ("SKIP_ENTRIES");
	case PMCOUT_SMP_ABORT:
		return ("SMP_ABORT");
	case PMCOUT_GET_NVMD_DATA:
		return ("GET_NVMD_DATA");
	case PMCOUT_SET_NVMD_DATA:
		return ("SET_NVMD_DATA");
	case PMCOUT_DEVICE_HANDLE_REMOVED:
		return ("DEVICE_HANDLE_REMOVED");
	case PMCOUT_SET_DEVICE_STATE:
		return ("SET_DEVICE_STATE");
	case PMCOUT_GET_DEVICE_STATE:
		return ("GET_DEVICE_STATE");
	case PMCOUT_SET_DEVICE_INFO:
		return ("SET_DEVICE_INFO");
	default:
		return ("UNKNOWN");
	}
}

static uint32_t
get_devid_from_ob_iomb(struct pmcs_hw ss, uint32_t *qentryp, uint16_t opcode)
{
	uint32_t devid = PMCS_INVALID_DEVICE_ID;

	switch (opcode) {
	/*
	 * These are obtained via the HTAG which is in word 1
	 */
	case PMCOUT_SSP_COMPLETION:
	case PMCOUT_SMP_COMPLETION:
	case PMCOUT_DEREGISTER_DEVICE_HANDLE:
	case PMCOUT_GET_DEVICE_HANDLE:
	case PMCOUT_SATA_COMPLETION:
	case PMCOUT_SSP_ABORT:
	case PMCOUT_SATA_ABORT:
	case PMCOUT_SMP_ABORT:
	case PMCOUT_SAS_HW_EVENT_ACK_ACK: {
		uint32_t	htag;
		pmcwork_t	*wp;
		pmcs_phy_t	*phy;
		uintptr_t	_wp, _phy;
		uint16_t	index;

		htag = LE_32(*(qentryp + 1));
		index = htag & PMCS_TAG_INDEX_MASK;

		wp = mdb_alloc(sizeof (pmcwork_t), UM_SLEEP);
		_wp = (uintptr_t)ss.work + (sizeof (pmcwork_t) * index);

		if (MDB_RD(wp, sizeof (pmcwork_t), _wp) == -1) {
			NOREAD(pmcwork_t, _wp);
			mdb_free(wp, sizeof (pmcwork_t));
			break;
		}

		phy = mdb_alloc(sizeof (pmcs_phy_t), UM_SLEEP);
		if (wp->phy == NULL) {
			_phy = (uintptr_t)wp->last_phy;
		} else {
			_phy = (uintptr_t)wp->phy;
		}

		/*
		 * If we have a PHY, read it in and get it's handle
		 */
		if (_phy != 0) {
			if (MDB_RD(phy, sizeof (*phy), _phy) == -1) {
				NOREAD(pmcs_phy_t, phy);
			} else {
				devid = phy->device_id;
			}
		}

		mdb_free(phy, sizeof (pmcs_phy_t));
		mdb_free(wp, sizeof (pmcwork_t));
		break;
	}

	/*
	 * The device ID is in the outbound IOMB at word 1
	 */
	case PMCOUT_SSP_REQUEST_RECEIVED:
		devid = LE_32(*(qentryp + 1)) & PMCS_DEVICE_ID_MASK;
		break;

	/*
	 * The device ID is in the outbound IOMB at word 2
	 */
	case PMCOUT_DEVICE_HANDLE_ARRIVED:
	case PMCOUT_DEVICE_HANDLE_REMOVED:
		devid = LE_32(*(qentryp + 2)) & PMCS_DEVICE_ID_MASK;
		break;

	/*
	 * In this (very rare - never seen it) state, the device ID
	 * comes from the HTAG in the inbound IOMB, which would be word
	 * 3 in the outbound IOMB
	 */
	case PMCOUT_GENERAL_EVENT:
	/*
	 * The device ID is in the outbound IOMB at word 3
	 */
	case PMCOUT_DEVICE_REGISTRATION:
	case PMCOUT_DEVICE_INFO:
	case PMCOUT_SET_DEVICE_STATE:
	case PMCOUT_GET_DEVICE_STATE:
	case PMCOUT_SET_DEVICE_INFO:
		devid = LE_32(*(qentryp + 3)) & PMCS_DEVICE_ID_MASK;
		break;

	/*
	 * Device ID is in the outbound IOMB at word 4
	 */
	case PMCOUT_SATA_EVENT:
	case PMCOUT_SSP_EVENT:
		devid = LE_32(*(qentryp + 4)) & PMCS_DEVICE_ID_MASK;
		break;
	}

	return (devid);
}

static boolean_t
iomb_is_dev_hdl_specific(uint32_t word0, boolean_t inbound)
{
	uint16_t opcode = word0 & PMCS_IOMB_OPCODE_MASK;

	if (inbound) {
		switch (opcode) {
		case PMCIN_SSP_INI_IO_START:
		case PMCIN_SSP_INI_TM_START:
		case PMCIN_SSP_INI_EXT_IO_START:
		case PMCIN_SSP_TGT_IO_START:
		case PMCIN_SSP_TGT_RESPONSE_START:
		case PMCIN_SSP_ABORT:
		case PMCIN_DEREGISTER_DEVICE_HANDLE:
		case PMCIN_SMP_REQUEST:
		case PMCIN_SMP_RESPONSE:
		case PMCIN_SMP_ABORT:
		case PMCIN_ASSISTED_DISCOVERY:
		case PMCIN_SATA_HOST_IO_START:
		case PMCIN_SATA_ABORT:
		case PMCIN_GET_DEVICE_INFO:
		case PMCIN_SET_DEVICE_STATE:
		case PMCIN_GET_DEVICE_STATE:
			return (B_TRUE);
		}

		return (B_FALSE);
	}

	switch (opcode) {
	case PMCOUT_SSP_COMPLETION:
	case PMCOUT_SMP_COMPLETION:
	case PMCOUT_DEVICE_REGISTRATION:
	case PMCOUT_DEREGISTER_DEVICE_HANDLE:
	case PMCOUT_GET_DEVICE_HANDLE:
	case PMCOUT_SATA_COMPLETION:
	case PMCOUT_SATA_EVENT:
	case PMCOUT_SSP_EVENT:
	case PMCOUT_DEVICE_HANDLE_ARRIVED:
	case PMCOUT_SSP_REQUEST_RECEIVED:
	case PMCOUT_DEVICE_INFO:
	case PMCOUT_FW_FLASH_UPDATE:
	case PMCOUT_GENERAL_EVENT:
	case PMCOUT_SSP_ABORT:
	case PMCOUT_SATA_ABORT:
	case PMCOUT_SAS_HW_EVENT_ACK_ACK:
	case PMCOUT_SMP_ABORT:
	case PMCOUT_DEVICE_HANDLE_REMOVED:
	case PMCOUT_SET_DEVICE_STATE:
	case PMCOUT_GET_DEVICE_STATE:
	case PMCOUT_SET_DEVICE_INFO:
		return (B_TRUE);
	}

	return (B_FALSE);
}

static void
dump_one_qentry_outbound(struct pmcs_hw ss, uint32_t *qentryp, int idx,
    uint64_t devid_filter)
{
	int qeidx;
	uint32_t word0 = LE_32(*qentryp);
	uint32_t word1 = LE_32(*(qentryp + 1));
	uint8_t iop_event;
	uint32_t devid;

	/*
	 * Check to see if we're filtering on a device ID
	 */
	if (devid_filter != PMCS_INVALID_DEVICE_ID) {
		if (!iomb_is_dev_hdl_specific(word0, B_FALSE)) {
			return;
		}

		/*
		 * Go find the device id.  It might be in the outbound
		 * IOMB or we may have to go find the work structure and
		 * get it from there.
		 */
		devid = get_devid_from_ob_iomb(ss, qentryp,
		    word0 & PMCS_IOMB_OPCODE_MASK);
		if ((devid == PMCS_INVALID_DEVICE_ID) ||
		    (devid_filter != devid)) {
			return;
		}
	}

	mdb_printf("Entry #%02d\n", idx);
	mdb_inc_indent(2);

	mdb_printf("Header: 0x%08x (", word0);
	if (word0 & PMCS_IOMB_VALID) {
		mdb_printf("VALID, ");
	}
	if (word0 & PMCS_IOMB_HIPRI) {
		mdb_printf("HIPRI, ");
	}
	mdb_printf("OBID=%d, ",
	    (word0 & PMCS_IOMB_OBID_MASK) >> PMCS_IOMB_OBID_SHIFT);
	mdb_printf("CAT=%s, ",
	    iomb_cat((word0 & PMCS_IOMB_CAT_MASK) >> PMCS_IOMB_CAT_SHIFT));
	mdb_printf("OPCODE=%s",
	    outbound_iomb_opcode(word0 & PMCS_IOMB_OPCODE_MASK));
	if ((word0 & PMCS_IOMB_OPCODE_MASK) == PMCOUT_SAS_HW_EVENT) {
		iop_event = IOP_EVENT_EVENT(word1);
		mdb_printf(" <%s>", iomb_event(iop_event));
	}
	mdb_printf(")\n");

	mdb_printf("Remaining Payload:\n");

	mdb_inc_indent(2);
	for (qeidx = 1; qeidx < (PMCS_QENTRY_SIZE / 4); qeidx++) {
		mdb_printf("%08x ", LE_32(*(qentryp + qeidx)));
	}
	mdb_printf("\n");
	mdb_dec_indent(4);
}

static void
display_outbound_queues(struct pmcs_hw ss, uint64_t devid_filter,
    uint_t verbose)
{
	int		idx, qidx;
	uintptr_t	obqp;
	uint32_t	*cip;
	uint32_t	*qentryp = mdb_alloc(PMCS_QENTRY_SIZE, UM_SLEEP);
	uint32_t	last_consumed, oqpi;

	mdb_printf("\n");
	mdb_printf("Outbound Queues\n");
	mdb_printf("---------------\n");

	mdb_inc_indent(2);

	for (qidx = 0; qidx < PMCS_NOQ; qidx++) {
		obqp = (uintptr_t)ss.oqp[qidx];

		if (obqp == 0) {
			mdb_printf("No outbound queue ptr for queue #%d\n",
			    qidx);
			continue;
		}

		mdb_printf("Outbound Queue #%d (Queue Type = %s)\n", qidx,
		    obq_type(qidx));
		/*
		 * Chip is the producer, so read the actual producer index
		 * and not the driver's version
		 */
		cip = (uint32_t *)((void *)ss.cip);
		if (MDB_RD(&oqpi, 4, cip + OQPI_BASE_OFFSET +
		    (qidx * 4)) == -1) {
			mdb_warn("Couldn't read oqpi\n");
			break;
		}

		mdb_printf("Producer index: %d  Consumer index: %d\n\n",
		    LE_32(oqpi), ss.oqci[qidx]);
		mdb_inc_indent(2);

		if (ss.oqci[qidx] == 0) {
			last_consumed = ss.ioq_depth - 1;
		} else {
			last_consumed = ss.oqci[qidx] - 1;
		}


		if (!verbose) {
			mdb_printf("Last processed entry:\n");
			if (MDB_RD(qentryp, PMCS_QENTRY_SIZE,
			    (obqp + (PMCS_QENTRY_SIZE * last_consumed)))
			    == -1) {
				mdb_warn("Couldn't read queue entry at 0x%p\n",
				    (obqp + (PMCS_QENTRY_SIZE *
				    last_consumed)));
				break;
			}
			dump_one_qentry_outbound(ss, qentryp, last_consumed,
			    devid_filter);
			mdb_printf("\n");
			mdb_dec_indent(2);
			continue;
		}

		for (idx = 0; idx < ss.ioq_depth; idx++) {
			if (MDB_RD(qentryp, PMCS_QENTRY_SIZE,
			    (obqp + (PMCS_QENTRY_SIZE * idx))) == -1) {
				mdb_warn("Couldn't read queue entry at 0x%p\n",
				    (obqp + (PMCS_QENTRY_SIZE * idx)));
				break;
			}
			dump_one_qentry_outbound(ss, qentryp, idx,
			    devid_filter);
		}

		mdb_printf("\n");
		mdb_dec_indent(2);
	}

	mdb_dec_indent(2);
	mdb_free(qentryp, PMCS_QENTRY_SIZE);
}

static void
dump_one_qentry_inbound(uint32_t *qentryp, int idx, uint64_t devid_filter)
{
	int qeidx;
	uint32_t word0 = LE_32(*qentryp);
	uint32_t devid = LE_32(*(qentryp + 2));

	/*
	 * Check to see if we're filtering on a device ID
	 */
	if (devid_filter != PMCS_INVALID_DEVICE_ID) {
		if (iomb_is_dev_hdl_specific(word0, B_TRUE)) {
			if (devid_filter != devid) {
				return;
			}
		} else {
			return;
		}
	}

	mdb_printf("Entry #%02d\n", idx);
	mdb_inc_indent(2);

	mdb_printf("Header: 0x%08x (", word0);
	if (word0 & PMCS_IOMB_VALID) {
		mdb_printf("VALID, ");
	}
	if (word0 & PMCS_IOMB_HIPRI) {
		mdb_printf("HIPRI, ");
	}
	mdb_printf("OBID=%d, ",
	    (word0 & PMCS_IOMB_OBID_MASK) >> PMCS_IOMB_OBID_SHIFT);
	mdb_printf("CAT=%s, ",
	    iomb_cat((word0 & PMCS_IOMB_CAT_MASK) >> PMCS_IOMB_CAT_SHIFT));
	mdb_printf("OPCODE=%s",
	    inbound_iomb_opcode(word0 & PMCS_IOMB_OPCODE_MASK));
	mdb_printf(")\n");

	mdb_printf("HTAG: 0x%08x\n", LE_32(*(qentryp + 1)));
	mdb_printf("Remaining Payload:\n");

	mdb_inc_indent(2);
	for (qeidx = 2; qeidx < (PMCS_QENTRY_SIZE / 4); qeidx++) {
		mdb_printf("%08x ", LE_32(*(qentryp + qeidx)));
	}
	mdb_printf("\n");
	mdb_dec_indent(4);
}

static void
display_inbound_queues(struct pmcs_hw ss, uint64_t devid_filter, uint_t verbose)
{
	int		idx, qidx, iqci, last_consumed;
	uintptr_t	ibqp;
	uint32_t	*qentryp = mdb_alloc(PMCS_QENTRY_SIZE, UM_SLEEP);
	uint32_t	*cip;

	mdb_printf("\n");
	mdb_printf("Inbound Queues\n");
	mdb_printf("--------------\n");

	mdb_inc_indent(2);

	for (qidx = 0; qidx < PMCS_NIQ; qidx++) {
		ibqp = (uintptr_t)ss.iqp[qidx];

		if (ibqp == 0) {
			mdb_printf("No inbound queue ptr for queue #%d\n",
			    qidx);
			continue;
		}

		mdb_printf("Inbound Queue #%d (Queue Type = %s)\n", qidx,
		    ibq_type(qidx));

		cip = (uint32_t *)((void *)ss.cip);
		if (MDB_RD(&iqci, 4, cip + (qidx * 4)) == -1) {
			mdb_warn("Couldn't read iqci\n");
			break;
		}
		iqci = LE_32(iqci);

		mdb_printf("Producer index: %d  Consumer index: %d\n\n",
		    ss.shadow_iqpi[qidx], iqci);
		mdb_inc_indent(2);

		if (iqci == 0) {
			last_consumed = ss.ioq_depth - 1;
		} else {
			last_consumed = iqci - 1;
		}

		if (!verbose) {
			mdb_printf("Last processed entry:\n");
			if (MDB_RD(qentryp, PMCS_QENTRY_SIZE,
			    (ibqp + (PMCS_QENTRY_SIZE * last_consumed)))
			    == -1) {
				mdb_warn("Couldn't read queue entry at 0x%p\n",
				    (ibqp + (PMCS_QENTRY_SIZE *
				    last_consumed)));
				break;
			}
			dump_one_qentry_inbound(qentryp, last_consumed,
			    devid_filter);
			mdb_printf("\n");
			mdb_dec_indent(2);
			continue;
		}

		for (idx = 0; idx < ss.ioq_depth; idx++) {
			if (MDB_RD(qentryp, PMCS_QENTRY_SIZE,
			    (ibqp + (PMCS_QENTRY_SIZE * idx))) == -1) {
				mdb_warn("Couldn't read queue entry at 0x%p\n",
				    (ibqp + (PMCS_QENTRY_SIZE * idx)));
				break;
			}
			dump_one_qentry_inbound(qentryp, idx, devid_filter);
		}

		mdb_printf("\n");
		mdb_dec_indent(2);
	}

	mdb_dec_indent(2);
	mdb_free(qentryp, PMCS_QENTRY_SIZE);
}

/*
 * phy is our copy of the PHY structure.  phyp is the pointer to the actual
 * kernel PHY data structure
 */
static void
display_phy(struct pmcs_phy phy, struct pmcs_phy *phyp, int verbose,
    int totals_only)
{
	char		*dtype, *speed;
	char		*yes = "Yes";
	char		*no = "No";
	char		*cfgd = no;
	char		*apend = no;
	char		*asent = no;
	char		*dead = no;
	char		*changed = no;
	char		route_attr, route_method;

	switch (phy.dtype) {
	case NOTHING:
		dtype = "None";
		break;
	case SATA:
		dtype = "SATA";
		if (phy.configured) {
			++sata_phys;
		}
		break;
	case SAS:
		dtype = "SAS";
		if (phy.configured) {
			++sas_phys;
		}
		break;
	case EXPANDER:
		dtype = "EXP";
		if (phy.configured) {
			++exp_phys;
		}
		break;
	}

	if (phy.dtype == NOTHING) {
		empty_phys++;
	} else if ((phy.dtype == EXPANDER) && phy.configured) {
		num_expanders++;
	}

	if (totals_only) {
		return;
	}

	switch (phy.link_rate) {
	case SAS_LINK_RATE_1_5GBIT:
		speed = "1.5Gb/s";
		break;
	case SAS_LINK_RATE_3GBIT:
		speed = "3 Gb/s";
		break;
	case SAS_LINK_RATE_6GBIT:
		speed = "6 Gb/s";
		break;
	default:
		speed = "N/A";
		break;
	}

	if ((phy.dtype != NOTHING) || verbose) {
		print_sas_address(&phy);

		if (phy.device_id != PMCS_INVALID_DEVICE_ID) {
			mdb_printf(" %3d %4d %6s %4s ",
			    phy.device_id, phy.phynum, speed, dtype);
		} else {
			mdb_printf(" N/A %4d %6s %4s ",
			    phy.phynum, speed, dtype);
		}

		if (verbose) {
			if (phy.abort_sent) {
				asent = yes;
			}
			if (phy.abort_pending) {
				apend = yes;
			}
			if (phy.configured) {
				cfgd = yes;
			}
			if (phy.dead) {
				dead = yes;
			}
			if (phy.changed) {
				changed = yes;
			}

			switch (phy.routing_attr) {
			case SMP_ROUTING_DIRECT:
				route_attr = 'D';
				break;
			case SMP_ROUTING_SUBTRACTIVE:
				route_attr = 'S';
				break;
			case SMP_ROUTING_TABLE:
				route_attr = 'T';
				break;
			default:
				route_attr = '?';
				break;
			}

			switch (phy.routing_method) {
			case SMP_ROUTING_DIRECT:
				route_method = 'D';
				break;
			case SMP_ROUTING_SUBTRACTIVE:
				route_method = 'S';
				break;
			case SMP_ROUTING_TABLE:
				route_method = 'T';
				break;
			default:
				route_attr = '?';
				break;
			}

			mdb_printf("%-4s %-4s %-4s %-4s %-4s %3d %3c/%1c %3d "
			    "%1d 0x%p ", cfgd, apend, asent, changed, dead,
			    phy.ref_count, route_attr, route_method,
			    phy.enum_attempts, phy.reenumerate, phy.phy_lock);
		}

		mdb_printf("Path: %s\n", phy.path);

		/*
		 * In verbose mode, on the next line print the drill down
		 * info to see either the DISCOVER response or the REPORT
		 * GENERAL response depending on the PHY's dtype
		 */
		if (verbose) {
			uintptr_t tphyp = (uintptr_t)phyp;

			mdb_inc_indent(4);
			switch (phy.dtype) {
			case EXPANDER:
				if (!phy.configured) {
					break;
				}
				mdb_printf("REPORT GENERAL response: %p::"
				    "print smp_report_general_resp_t\n",
				    (tphyp + offsetof(struct pmcs_phy,
				    rg_resp)));
				break;
			case SAS:
			case SATA:
				mdb_printf("DISCOVER response: %p::"
				    "print smp_discover_resp_t\n",
				    (tphyp + offsetof(struct pmcs_phy,
				    disc_resp)));
				break;
			default:
				break;
			}
			mdb_dec_indent(4);
		}
	}
}

static void
display_phys(struct pmcs_hw ss, int verbose, struct pmcs_phy *parent, int level,
    int totals_only)
{
	pmcs_phy_t	phy;
	pmcs_phy_t	*pphy = parent;

	mdb_inc_indent(3);

	if (parent == NULL) {
		pphy = (pmcs_phy_t *)ss.root_phys;
	} else {
		pphy = (pmcs_phy_t *)parent;
	}

	if (level == 0) {
		sas_phys = 0;
		sata_phys = 0;
		exp_phys = 0;
		num_expanders = 0;
		empty_phys = 0;
	}

	if (!totals_only) {
		if (level == 0) {
			mdb_printf("PHY information\n");
		}
		mdb_printf("--------\n");
		mdb_printf("Level %2d\n", level);
		mdb_printf("--------\n");
		mdb_printf("SAS Address      Hdl Phy#  Speed Type ");

		if (verbose) {
			mdb_printf("Cfgd AbtP AbtS Chgd Dead Ref RtA/M Enm R "
			    "Lock\n");
		} else {
			mdb_printf("\n");
		}
	}

	while (pphy) {
		if (MDB_RD(&phy, sizeof (phy), (uintptr_t)pphy) == -1) {
			NOREAD(pmcs_phy_t, phy);
			break;
		}

		display_phy(phy, pphy, verbose, totals_only);

		if (phy.children) {
			display_phys(ss, verbose, phy.children, level + 1,
			    totals_only);
			if (!totals_only) {
				mdb_printf("\n");
			}
		}

		pphy = phy.sibling;
	}

	mdb_dec_indent(3);

	if (level == 0) {
		if (verbose) {
			mdb_printf("%19s %d (%d SAS + %d SATA + %d SMP) "
			    "(+%d subsidiary + %d empty)\n", "Occupied PHYs:",
			    (sas_phys + sata_phys + num_expanders),
			    sas_phys, sata_phys, num_expanders,
			    (exp_phys - num_expanders), empty_phys);
		} else {
			mdb_printf("%19s %d (%d SAS + %d SATA + %d SMP)\n",
			    "Occupied PHYs:",
			    (sas_phys + sata_phys + num_expanders),
			    sas_phys, sata_phys, num_expanders);
		}
	}
}

/*
 * filter is used to indicate whether we are filtering log messages based
 * on "instance".  The other filtering (based on options) depends on the
 * values that are passed in for "sas_addr" and "phy_path".
 *
 * MAX_INST_STRLEN is the largest string size from which we will attempt
 * to convert to an instance number.  The string will be formed up as
 * "0t<inst>\0" so that mdb_strtoull can parse it properly.
 */
#define	MAX_INST_STRLEN	8

static int
pmcs_dump_tracelog(boolean_t filter, int instance, uint64_t tail_lines,
    const char *phy_path, uint64_t sas_address, uint64_t verbose)
{
	pmcs_tbuf_t *tbuf_addr;
	uint_t tbuf_idx;
	pmcs_tbuf_t tbuf;
	boolean_t wrap, elem_filtered;
	uint_t start_idx, elems_to_print, idx, tbuf_num_elems;
	char *bufp;
	char elem_inst[MAX_INST_STRLEN], ei_idx;
	uint64_t sas_addr;
	uint8_t *sas_addressp;

	/* Get the address of the first element */
	if (mdb_readvar(&tbuf_addr, "pmcs_tbuf") == -1) {
		mdb_warn("can't read pmcs_tbuf");
		return (DCMD_ERR);
	}

	/* Get the total number */
	if (mdb_readvar(&tbuf_num_elems, "pmcs_tbuf_num_elems") == -1) {
		mdb_warn("can't read pmcs_tbuf_num_elems");
		return (DCMD_ERR);
	}

	/* Get the current index */
	if (mdb_readvar(&tbuf_idx, "pmcs_tbuf_idx") == -1) {
		mdb_warn("can't read pmcs_tbuf_idx");
		return (DCMD_ERR);
	}

	/* Indicator as to whether the buffer has wrapped */
	if (mdb_readvar(&wrap, "pmcs_tbuf_wrap") == -1) {
		mdb_warn("can't read pmcs_tbuf_wrap");
		return (DCMD_ERR);
	}

	/*
	 * On little-endian systems, the SAS address passed in will be
	 * byte swapped.  Take care of that here.
	 */
#if defined(_LITTLE_ENDIAN)
	sas_addr = ((sas_address << 56) |
	    ((sas_address << 40) & 0xff000000000000ULL) |
	    ((sas_address << 24) & 0xff0000000000ULL) |
	    ((sas_address << 8)  & 0xff00000000ULL) |
	    ((sas_address >> 8)  & 0xff000000ULL) |
	    ((sas_address >> 24) & 0xff0000ULL) |
	    ((sas_address >> 40) & 0xff00ULL) |
	    (sas_address  >> 56));
#else
	sas_addr = sas_address;
#endif
	sas_addressp = (uint8_t *)&sas_addr;

	/* Ensure the tail number isn't greater than the size of the log */
	if (tail_lines > tbuf_num_elems) {
		tail_lines = tbuf_num_elems;
	}

	/* Figure out where we start and stop */
	if (wrap) {
		if (tail_lines) {
			/* Do we need to wrap backwards? */
			if (tail_lines > tbuf_idx) {
				start_idx = tbuf_num_elems - (tail_lines -
				    tbuf_idx);
			} else {
				start_idx = tbuf_idx - tail_lines;
			}
			elems_to_print = tail_lines;
		} else {
			start_idx = tbuf_idx;
			elems_to_print = tbuf_num_elems;
		}
	} else {
		if (tail_lines > tbuf_idx) {
			tail_lines = tbuf_idx;
		}
		if (tail_lines) {
			start_idx = tbuf_idx - tail_lines;
			elems_to_print = tail_lines;
		} else {
			start_idx = 0;
			elems_to_print = tbuf_idx;
		}
	}

	idx = start_idx;

	/* Dump the buffer contents */
	while (elems_to_print != 0) {
		if (MDB_RD(&tbuf, sizeof (pmcs_tbuf_t), (tbuf_addr + idx))
		    == -1) {
			NOREAD(tbuf, (tbuf_addr + idx));
			return (DCMD_ERR);
		}

		/*
		 * Check for filtering on HBA instance
		 */
		elem_filtered = B_FALSE;

		if (filter) {
			bufp = tbuf.buf;
			/* Skip the driver name */
			while (*bufp < '0' || *bufp > '9') {
				bufp++;
			}

			ei_idx = 0;
			elem_inst[ei_idx++] = '0';
			elem_inst[ei_idx++] = 't';
			while (*bufp != ':' && ei_idx < (MAX_INST_STRLEN - 1)) {
				elem_inst[ei_idx++] = *bufp;
				bufp++;
			}
			elem_inst[ei_idx] = 0;

			/* Get the instance */
			if ((int)mdb_strtoull(elem_inst) != instance) {
				elem_filtered = B_TRUE;
			}
		}

		if (!elem_filtered && (phy_path || sas_address)) {
			/*
			 * This message is not being filtered by HBA instance.
			 * Now check to see if we're filtering based on
			 * PHY path or SAS address.
			 * Filtering is an "OR" operation.  So, if any of the
			 * criteria matches, this message will be printed.
			 */
			elem_filtered = B_TRUE;

			if (phy_path != NULL) {
				if (strncmp(phy_path, tbuf.phy_path,
				    PMCS_TBUF_UA_MAX_SIZE) == 0) {
					elem_filtered = B_FALSE;
				}
			}
			if (sas_address != 0) {
				if (memcmp(sas_addressp, tbuf.phy_sas_address,
				    8) == 0) {
					elem_filtered = B_FALSE;
				}
			}
		}

		if (!elem_filtered) {
			/*
			 * If the -v flag was given, print the firmware
			 * timestamp along with the clock time
			 */
			mdb_printf("%Y.%09ld ", tbuf.timestamp);
			if (verbose) {
				mdb_printf("(0x%" PRIx64 ") ",
				    tbuf.fw_timestamp);
			}
			mdb_printf("%s\n", tbuf.buf);
		}

		--elems_to_print;
		if (++idx == tbuf_num_elems) {
			idx = 0;
		}
	}

	return (DCMD_OK);
}

/*
 * Walkers
 */
static int
targets_walk_i(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == 0) {
		mdb_warn("Can not perform global walk\n");
		return (WALK_ERR);
	}

	/*
	 * Address provided belongs to HBA softstate.  Get the targets pointer
	 * to begin the walk.
	 */
	if (mdb_vread(&ss, sizeof (pmcs_hw_t), wsp->walk_addr) !=
	    sizeof (pmcs_hw_t)) {
		mdb_warn("Unable to read HBA softstate\n");
		return (WALK_ERR);
	}

	if (targets == NULL) {
		targets = mdb_alloc(sizeof (targets) * ss.max_dev, UM_SLEEP);
	}

	if (MDB_RD(targets, sizeof (targets) * ss.max_dev, ss.targets) == -1) {
		NOREAD(targets, ss.targets);
		return (WALK_ERR);
	}

	target_idx = 0;
	wsp->walk_addr = (uintptr_t)(targets[0]);
	wsp->walk_data = mdb_alloc(sizeof (pmcs_xscsi_t), UM_SLEEP);

	return (WALK_NEXT);
}

static int
targets_walk_s(mdb_walk_state_t *wsp)
{
	int status;

	if (target_idx == ss.max_dev) {
		return (WALK_DONE);
	}

	if (mdb_vread(wsp->walk_data, sizeof (pmcs_xscsi_t),
	    wsp->walk_addr) == -1) {
		mdb_warn("Failed to read target at %p", (void *)wsp->walk_addr);
		return (WALK_DONE);
	}

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	do {
		wsp->walk_addr = (uintptr_t)(targets[++target_idx]);
	} while ((wsp->walk_addr == 0) && (target_idx < ss.max_dev));

	if (target_idx == ss.max_dev) {
		return (WALK_DONE);
	}

	return (status);
}

static void
targets_walk_f(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (pmcs_xscsi_t));
}


static pmcs_phy_t *
pmcs_next_sibling(pmcs_phy_t *phyp)
{
	pmcs_phy_t parent;

	/*
	 * First, if this is a root PHY, there are no more siblings
	 */
	if (phyp->level == 0) {
		return (NULL);
	}

	/*
	 * Otherwise, next sibling is the parent's sibling
	 */
	while (phyp->level > 0) {
		if (mdb_vread(&parent, sizeof (pmcs_phy_t),
		    (uintptr_t)phyp->parent) == -1) {
			mdb_warn("pmcs_next_sibling: Failed to read PHY at %p",
			    (void *)phyp->parent);
			return (NULL);
		}

		if (parent.sibling != NULL) {
			break;
		}

		/*
		 * If this PHY's sibling is NULL and it's a root phy,
		 * we're done.
		 */
		if (parent.level == 0) {
			return (NULL);
		}

		phyp = phyp->parent;
	}

	return (parent.sibling);
}

static int
phy_walk_i(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == 0) {
		mdb_warn("Can not perform global walk\n");
		return (WALK_ERR);
	}

	/*
	 * Address provided belongs to HBA softstate.  Get the targets pointer
	 * to begin the walk.
	 */
	if (mdb_vread(&ss, sizeof (pmcs_hw_t), wsp->walk_addr) !=
	    sizeof (pmcs_hw_t)) {
		mdb_warn("Unable to read HBA softstate\n");
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)(ss.root_phys);
	wsp->walk_data = mdb_alloc(sizeof (pmcs_phy_t), UM_SLEEP);

	return (WALK_NEXT);
}

static int
phy_walk_s(mdb_walk_state_t *wsp)
{
	pmcs_phy_t *phyp, *nphyp;
	int status;

	if (mdb_vread(wsp->walk_data, sizeof (pmcs_phy_t),
	    wsp->walk_addr) == -1) {
		mdb_warn("phy_walk_s: Failed to read PHY at %p",
		    (void *)wsp->walk_addr);
		return (WALK_DONE);
	}

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	phyp = (pmcs_phy_t *)wsp->walk_data;
	if (phyp->children) {
		wsp->walk_addr = (uintptr_t)(phyp->children);
	} else {
		wsp->walk_addr = (uintptr_t)(phyp->sibling);
	}

	if (wsp->walk_addr == 0) {
		/*
		 * We reached the end of this sibling list.  Trudge back up
		 * to the parent and find the next sibling after the expander
		 * we just finished traversing, if there is one.
		 */
		nphyp = pmcs_next_sibling(phyp);

		if (nphyp == NULL) {
			return (WALK_DONE);
		}

		wsp->walk_addr = (uintptr_t)nphyp;
	}

	return (status);
}

static void
phy_walk_f(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (pmcs_phy_t));
}

static void
display_matching_work(struct pmcs_hw ss, uintmax_t index, uintmax_t snum,
    uintmax_t tag_type)
{
	int		idx;
	pmcwork_t	work, *wp = &work;
	uintptr_t	_wp;
	boolean_t	printed_header = B_FALSE;
	uint32_t	mask, mask_val, match_val;
	char		*match_type;

	if (index != UINT_MAX) {
		match_type = "index";
		mask = PMCS_TAG_INDEX_MASK;
		mask_val = index << PMCS_TAG_INDEX_SHIFT;
		match_val = index;
	} else if (snum != UINT_MAX) {
		match_type = "serial number";
		mask = PMCS_TAG_SERNO_MASK;
		mask_val = snum << PMCS_TAG_SERNO_SHIFT;
		match_val = snum;
	} else {
		switch (tag_type) {
		case PMCS_TAG_TYPE_NONE:
			match_type = "tag type NONE";
			break;
		case PMCS_TAG_TYPE_CBACK:
			match_type = "tag type CBACK";
			break;
		case PMCS_TAG_TYPE_WAIT:
			match_type = "tag type WAIT";
			break;
		}
		mask = PMCS_TAG_TYPE_MASK;
		mask_val = tag_type << PMCS_TAG_TYPE_SHIFT;
		match_val = tag_type;
	}

	_wp = (uintptr_t)ss.work;

	for (idx = 0; idx < ss.max_cmd; idx++, _wp += sizeof (pmcwork_t)) {
		if (MDB_RD(&work, sizeof (pmcwork_t), _wp) == -1) {
			NOREAD(pmcwork_t, _wp);
			continue;
		}

		if ((work.htag & mask) != mask_val) {
			continue;
		}

		if (printed_header == B_FALSE) {
			if (tag_type) {
				mdb_printf("\nWork structures matching %s\n\n",
				    match_type, match_val);
			} else {
				mdb_printf("\nWork structures matching %s of "
				    "0x%x\n\n", match_type, match_val);
			}
			mdb_printf("%8s %10s %20s %8s %8s O D\n",
			    "HTag", "State", "Phy Path", "Target", "Timer");
			printed_header = B_TRUE;
		}

		display_one_work(wp, 0, 0);
	}

	if (!printed_header) {
		mdb_printf("No work structure matches found\n");
	}
}

static int
pmcs_tag(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct	pmcs_hw		ss;
	uintmax_t		tag_type = UINT_MAX;
	uintmax_t		snum = UINT_MAX;
	uintmax_t		index = UINT_MAX;
	int			args = 0;
	void			*pmcs_state;
	char			*state_str;
	struct dev_info		dip;

	if (!(flags & DCMD_ADDRSPEC)) {
		pmcs_state = NULL;
		if (mdb_readvar(&pmcs_state, "pmcs_softc_state") == -1) {
			mdb_warn("can't read pmcs_softc_state");
			return (DCMD_ERR);
		}
		if (mdb_pwalk_dcmd("genunix`softstate", "pmcs`pmcs_tag", argc,
		    argv, (uintptr_t)pmcs_state) == -1) {
			mdb_warn("mdb_pwalk_dcmd failed");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (mdb_getopts(argc, argv,
	    'i', MDB_OPT_UINT64, &index,
	    's', MDB_OPT_UINT64, &snum,
	    't', MDB_OPT_UINT64, &tag_type) != argc)
		return (DCMD_USAGE);

	/*
	 * Count the number of supplied options and make sure they are
	 * within appropriate ranges.  If they're set to UINT_MAX, that means
	 * they were not supplied, in which case reset them to 0.
	 */
	if (index != UINT_MAX) {
		args++;
		if (index > PMCS_TAG_INDEX_MASK) {
			mdb_warn("Index is out of range\n");
			return (DCMD_USAGE);
		}
	}

	if (tag_type != UINT_MAX) {
		args++;
		switch (tag_type) {
		case PMCS_TAG_TYPE_NONE:
		case PMCS_TAG_TYPE_CBACK:
		case PMCS_TAG_TYPE_WAIT:
			break;
		default:
			mdb_warn("Invalid tag type\n");
			return (DCMD_USAGE);
		}
	}

	if (snum != UINT_MAX) {
		args++;
		if (snum > (PMCS_TAG_SERNO_MASK >> PMCS_TAG_SERNO_SHIFT)) {
			mdb_warn("Serial number is out of range\n");
			return (DCMD_USAGE);
		}
	}

	/*
	 * Make sure 1 and only 1 option is specified
	 */
	if ((args == 0) || (args > 1)) {
		mdb_warn("Exactly one of -i, -s and -t must be specified\n");
		return (DCMD_USAGE);
	}

	if (MDB_RD(&ss, sizeof (ss), addr) == -1) {
		NOREAD(pmcs_hw_t, addr);
		return (DCMD_ERR);
	}

	if (MDB_RD(&dip, sizeof (struct dev_info), ss.dip) == -1) {
		NOREAD(pmcs_hw_t, addr);
		return (DCMD_ERR);
	}

	/* processing completed */

	if (((flags & DCMD_ADDRSPEC) && !(flags & DCMD_LOOP)) ||
	    (flags & DCMD_LOOPFIRST)) {
		if ((flags & DCMD_LOOP) && !(flags & DCMD_LOOPFIRST))
			mdb_printf("\n");
		mdb_printf("%16s %9s %4s B C  WorkFlags wserno DbgMsk %16s\n",
		    "Address", "State", "Inst", "DIP");
		mdb_printf("================================="
		    "============================================\n");
	}

	switch (ss.state) {
	case STATE_NIL:
		state_str = "Invalid";
		break;
	case STATE_PROBING:
		state_str = "Probing";
		break;
	case STATE_RUNNING:
		state_str = "Running";
		break;
	case STATE_UNPROBING:
		state_str = "Unprobing";
		break;
	case STATE_DEAD:
		state_str = "Dead";
		break;
	case STATE_IN_RESET:
		state_str = "In Reset";
		break;
	}

	mdb_printf("%16p %9s %4d %1d %1d 0x%08x 0x%04x 0x%04x %16p\n", addr,
	    state_str, dip.devi_instance, ss.blocked, ss.configuring,
	    ss.work_flags, ss.wserno, ss.debug_mask, ss.dip);
	mdb_printf("\n");

	mdb_inc_indent(4);
	display_matching_work(ss, index, snum, tag_type);
	mdb_dec_indent(4);
	mdb_printf("\n");

	return (DCMD_OK);
}

#ifndef _KMDB
static int
pmcs_dump_fwlog(struct pmcs_hw *ss, int instance, const char *ofile)
{
	uint8_t *fwlogp;
	int	ofilefd = -1;
	char	ofilename[MAXPATHLEN];
	int	rval = DCMD_OK;

	if (ss->fwlogp == NULL) {
		mdb_warn("Firmware event log disabled for instance %d",
		    instance);
		return (DCMD_OK);
	}

	if (snprintf(ofilename, MAXPATHLEN, "%s%d", ofile, instance) >
	    MAXPATHLEN) {
		mdb_warn("Output filename is too long for instance %d",
		    instance);
		return (DCMD_ERR);
	}

	fwlogp = mdb_alloc(PMCS_FWLOG_SIZE, UM_SLEEP);

	if (MDB_RD(fwlogp, PMCS_FWLOG_SIZE, ss->fwlogp) == -1) {
		NOREAD(fwlogp, ss->fwlogp);
		rval = DCMD_ERR;
		goto cleanup;
	}

	ofilefd = open(ofilename, O_WRONLY | O_CREAT,
	    S_IRUSR | S_IRGRP | S_IROTH);
	if (ofilefd < 0) {
		mdb_warn("Unable to open '%s' to dump instance %d event log",
		    ofilename, instance);
		rval = DCMD_ERR;
		goto cleanup;
	}

	if (write(ofilefd, fwlogp, PMCS_FWLOG_SIZE) != PMCS_FWLOG_SIZE) {
		mdb_warn("Failed to write %d bytes to output file: instance %d",
		    PMCS_FWLOG_SIZE, instance);
		rval = DCMD_ERR;
		goto cleanup;
	}

	mdb_printf("Event log for instance %d written to %s\n", instance,
	    ofilename);

cleanup:
	if (ofilefd >= 0) {
		close(ofilefd);
	}
	mdb_free(fwlogp, PMCS_FWLOG_SIZE);
	return (rval);
}

static int
pmcs_fwlog(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	void		*pmcs_state;
	const char	*ofile = NULL;
	struct pmcs_hw	ss;
	struct dev_info	dip;

	if (mdb_getopts(argc, argv, 'o', MDB_OPT_STR, &ofile, NULL) != argc) {
		return (DCMD_USAGE);
	}

	if (ofile == NULL) {
		mdb_printf("No output file specified\n");
		return (DCMD_USAGE);
	}

	if (!(flags & DCMD_ADDRSPEC)) {
		pmcs_state = NULL;
		if (mdb_readvar(&pmcs_state, "pmcs_softc_state") == -1) {
			mdb_warn("can't read pmcs_softc_state");
			return (DCMD_ERR);
		}
		if (mdb_pwalk_dcmd("genunix`softstate", "pmcs`pmcs_fwlog", argc,
		    argv, (uintptr_t)pmcs_state) == -1) {
			mdb_warn("mdb_pwalk_dcmd failed for pmcs_log");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (MDB_RD(&ss, sizeof (ss), addr) == -1) {
		NOREAD(pmcs_hw_t, addr);
		return (DCMD_ERR);
	}

	if (MDB_RD(&dip, sizeof (struct dev_info), ss.dip) == -1) {
		NOREAD(pmcs_hw_t, addr);
		return (DCMD_ERR);
	}

	return (pmcs_dump_fwlog(&ss, dip.devi_instance, ofile));
}
#endif	/* _KMDB */

static int
pmcs_log(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	void		*pmcs_state;
	struct pmcs_hw	ss;
	struct dev_info	dip;
	const char	*match_phy_path = NULL;
	uint64_t	match_sas_address = 0, tail_lines = 0;
	uint_t		verbose = 0;

	if (!(flags & DCMD_ADDRSPEC)) {
		pmcs_state = NULL;
		if (mdb_readvar(&pmcs_state, "pmcs_softc_state") == -1) {
			mdb_warn("can't read pmcs_softc_state");
			return (DCMD_ERR);
		}
		if (mdb_pwalk_dcmd("genunix`softstate", "pmcs`pmcs_log", argc,
		    argv, (uintptr_t)pmcs_state) == -1) {
			mdb_warn("mdb_pwalk_dcmd failed for pmcs_log");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (mdb_getopts(argc, argv,
	    'l', MDB_OPT_UINT64, &tail_lines,
	    'p', MDB_OPT_STR, &match_phy_path,
	    's', MDB_OPT_UINT64, &match_sas_address,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose,
	    NULL) != argc) {
		return (DCMD_USAGE);
	}

	if (MDB_RD(&ss, sizeof (ss), addr) == -1) {
		NOREAD(pmcs_hw_t, addr);
		return (DCMD_ERR);
	}

	if (MDB_RD(&dip, sizeof (struct dev_info), ss.dip) == -1) {
		NOREAD(pmcs_hw_t, addr);
		return (DCMD_ERR);
	}

	if (!(flags & DCMD_LOOP)) {
		return (pmcs_dump_tracelog(B_TRUE, dip.devi_instance,
		    tail_lines, match_phy_path, match_sas_address, verbose));
	} else if (flags & DCMD_LOOPFIRST) {
		return (pmcs_dump_tracelog(B_FALSE, 0, tail_lines,
		    match_phy_path, match_sas_address, verbose));
	} else {
		return (DCMD_OK);
	}
}

static int
pmcs_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct pmcs_hw		ss;
	uint_t			verbose = FALSE;
	uint_t			phy_info = FALSE;
	uint_t			hw_info = FALSE;
	uint_t			target_info = FALSE;
	uint_t			work_info = FALSE;
	uint_t			ic_info = FALSE;
	uint_t			iport_info = FALSE;
	uint_t			waitqs_info = FALSE;
	uint_t			ibq = FALSE;
	uint_t			obq = FALSE;
	uint_t			tgt_phy_count = FALSE;
	uint_t			compq = FALSE;
	uint_t			unconfigured = FALSE;
	uint_t			damap_info = FALSE;
	uint_t			dtc_info = FALSE;
	uint_t			wserno = FALSE;
	uint_t			fwlog = FALSE;
	boolean_t		devid_filter = FALSE;
	uintptr_t		pdevid;
	uint32_t		devid;
	int			rv = DCMD_OK;
	void			*pmcs_state;
	char			*state_str;
	struct dev_info		dip;
	per_iport_setting_t	pis;

	if (!(flags & DCMD_ADDRSPEC)) {
		pmcs_state = NULL;
		if (mdb_readvar(&pmcs_state, "pmcs_softc_state") == -1) {
			mdb_warn("can't read pmcs_softc_state");
			return (DCMD_ERR);
		}
		if (mdb_pwalk_dcmd("genunix`softstate", "pmcs`pmcs", argc, argv,
		    (uintptr_t)pmcs_state) == -1) {
			mdb_warn("mdb_pwalk_dcmd failed");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (mdb_getopts(argc, argv,
	    'c', MDB_OPT_SETBITS, TRUE, &compq,
	    'd', MDB_OPT_SETBITS, TRUE, &dtc_info,
	    'D', MDB_OPT_UINTPTR_SET, &devid_filter, &pdevid,
	    'e', MDB_OPT_SETBITS, TRUE, &fwlog,
	    'h', MDB_OPT_SETBITS, TRUE, &hw_info,
	    'i', MDB_OPT_SETBITS, TRUE, &ic_info,
	    'I', MDB_OPT_SETBITS, TRUE, &iport_info,
	    'm', MDB_OPT_SETBITS, TRUE, &damap_info,
	    'p', MDB_OPT_SETBITS, TRUE, &phy_info,
	    'q', MDB_OPT_SETBITS, TRUE, &ibq,
	    'Q', MDB_OPT_SETBITS, TRUE, &obq,
	    's', MDB_OPT_SETBITS, TRUE, &wserno,
	    't', MDB_OPT_SETBITS, TRUE, &target_info,
	    'T', MDB_OPT_SETBITS, TRUE, &tgt_phy_count,
	    'u', MDB_OPT_SETBITS, TRUE, &unconfigured,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose,
	    'w', MDB_OPT_SETBITS, TRUE, &work_info,
	    'W', MDB_OPT_SETBITS, TRUE, &waitqs_info,
	    NULL) != argc)
		return (DCMD_USAGE);

	/*
	 * The 'd' and 'm' options implicitly enable the 'I' option
	 */
	pis.pis_damap_info = damap_info;
	pis.pis_dtc_info = dtc_info;
	if (damap_info || dtc_info) {
		iport_info = TRUE;
	}

	/*
	 * The -D option is meaningless without -q and/or -Q, and implies
	 * verbosity.
	 */
	if (devid_filter) {
		devid = (uint64_t)pdevid & 0xffffffff;
		if (!ibq && !obq) {
			mdb_printf("-D requires either -q or -Q\n");
			return (DCMD_USAGE);
		}
		if (devid > PMCS_DEVICE_ID_MASK) {
			mdb_printf("Device ID invalid\n");
			return (DCMD_USAGE);
		}
		verbose = TRUE;
	}

	if (MDB_RD(&ss, sizeof (ss), addr) == -1) {
		NOREAD(pmcs_hw_t, addr);
		return (DCMD_ERR);
	}

	if (MDB_RD(&dip, sizeof (struct dev_info), ss.dip) == -1) {
		NOREAD(pmcs_hw_t, addr);
		return (DCMD_ERR);
	}

	/* processing completed */

	if (((flags & DCMD_ADDRSPEC) && !(flags & DCMD_LOOP)) ||
	    (flags & DCMD_LOOPFIRST) || phy_info || target_info || hw_info ||
	    work_info || waitqs_info || ibq || obq || tgt_phy_count || compq ||
	    unconfigured || fwlog) {
		if ((flags & DCMD_LOOP) && !(flags & DCMD_LOOPFIRST))
			mdb_printf("\n");
		mdb_printf("%16s %9s %4s B C  WorkFlags wserno DbgMsk %16s\n",
		    "Address", "State", "Inst", "DIP");
		mdb_printf("================================="
		    "============================================\n");
	}

	switch (ss.state) {
	case STATE_NIL:
		state_str = "Invalid";
		break;
	case STATE_PROBING:
		state_str = "Probing";
		break;
	case STATE_RUNNING:
		state_str = "Running";
		break;
	case STATE_UNPROBING:
		state_str = "Unprobing";
		break;
	case STATE_DEAD:
		state_str = "Dead";
		break;
	case STATE_IN_RESET:
		state_str = "In Reset";
		break;
	}

	mdb_printf("%16p %9s %4d %1d %1d 0x%08x 0x%04x 0x%04x %16p\n", addr,
	    state_str, dip.devi_instance, ss.blocked, ss.configuring,
	    ss.work_flags, ss.wserno, ss.debug_mask, ss.dip);
	mdb_printf("\n");

	mdb_inc_indent(4);

	if (waitqs_info)
		display_waitqs(ss, verbose);

	if (hw_info)
		display_hwinfo(ss, verbose);

	if (phy_info || tgt_phy_count)
		display_phys(ss, verbose, NULL, 0, tgt_phy_count);

	if (target_info || tgt_phy_count)
		display_targets(ss, verbose, tgt_phy_count);

	if (work_info || wserno)
		display_work(ss, verbose, wserno);

	if (ic_info)
		display_ic(ss, verbose);

	if (ibq)
		display_inbound_queues(ss, devid, verbose);

	if (obq)
		display_outbound_queues(ss, devid, verbose);

	if (iport_info)
		display_iport(ss, addr, verbose, &pis);

	if (compq)
		display_completion_queue(ss);

	if (unconfigured)
		display_unconfigured_targets(addr);

	if (fwlog)
		display_event_log(ss);

	mdb_dec_indent(4);

	return (rv);
}

void
pmcs_help()
{
	mdb_printf("Prints summary information about each pmcs instance.\n"
	    "    -c: Dump the completion queue\n"
	    "    -d: Print per-iport information about device tree children\n"
	    "    -D <device ID>: With -q/-Q, filter by device handle\n"
	    "    -e: Display the in-memory firmware event log\n"
	    "    -h: Print more detailed hardware information\n"
	    "    -i: Print interrupt coalescing information\n"
	    "    -I: Print information about each iport\n"
	    "    -m: Print per-iport information about DAM/damap state\n"
	    "    -p: Print information about each attached PHY\n"
	    "    -q: Dump inbound queues\n"
	    "    -Q: Dump outbound queues\n"
	    "    -s: Dump all work structures sorted by serial number\n"
	    "    -t: Print information about each configured target\n"
	    "    -T: Print target and PHY count summary\n"
	    "    -u: Show SAS address of all unconfigured targets\n"
	    "    -w: Dump work structures\n"
	    "    -W: List pmcs cmds waiting on various queues\n"
	    "    -v: Add verbosity to the above options\n");
}

void
pmcs_log_help()
{
	mdb_printf("Dump the pmcs log buffer, possibly with filtering.\n"
	    "    -l TAIL_LINES:          Dump the last TAIL_LINES messages\n"
	    "    -p PHY_PATH:            Dump messages matching PHY_PATH\n"
	    "    -s SAS_ADDRESS:         Dump messages matching SAS_ADDRESS\n\n"
	    "Where: PHY_PATH can be found with ::pmcs -p (e.g. pp04.18.18.01)\n"
	    "       SAS_ADDRESS can be found with ::pmcs -t "
	    "(e.g. 5000c5000358c221)\n");
}
void
pmcs_tag_help()
{
	mdb_printf("Print all work structures by matching the tag.\n"
	    "    -i index:        Match tag index (0x000 - 0xfff)\n"
	    "    -s serialnumber: Match serial number (0x0000 - 0xffff)\n"
	    "    -t tagtype:      Match tag type [NONE(1), CBACK(2), "
	    "WAIT(3)]\n");
}

static const mdb_dcmd_t dcmds[] = {
	{ "pmcs", "?[-cdehiImpQqtTuwWv] [-D <device ID>]",
	    "print pmcs information", pmcs_dcmd, pmcs_help
	},
	{ "pmcs_log",
	    "?[-v] [-p PHY_PATH | -s SAS_ADDRESS | -l TAIL_LINES]",
	    "dump pmcs log file", pmcs_log, pmcs_log_help
	},
	{ "pmcs_tag", "?[-t tagtype|-s serialnum|-i index]",
	    "Find work structures by tag type, serial number or index",
	    pmcs_tag, pmcs_tag_help
	},
#ifndef _KMDB
	{ "pmcs_fwlog",
	    "?-o output_file",
	    "dump pmcs firmware event log to output_file", pmcs_fwlog, NULL
	},
#endif	/* _KMDB */
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "pmcs_targets", "walk target structures",
		targets_walk_i, targets_walk_s, targets_walk_f },
	{ "pmcs_phys", "walk PHY structures",
		phy_walk_i, phy_walk_s, phy_walk_f },
	{ NULL }
};

static const mdb_modinfo_t modinfo = {
	MDB_API_VERSION, dcmds, walkers
};

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
