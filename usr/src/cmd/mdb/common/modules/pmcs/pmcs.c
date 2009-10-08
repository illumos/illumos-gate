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

#include <limits.h>
#include <sys/mdb_modapi.h>
#include <sys/sysinfo.h>
#include <sys/scsi/scsi.h>
#include <sys/scsi/adapters/pmcs/pmcs.h>

#define	MDB_RD(a, b, c)	mdb_vread(a, b, (uintptr_t)c)
#define	NOREAD(a, b)	mdb_warn("could not read " #a " at 0x%p", b)

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

/*ARGSUSED*/
static int
pmcs_iport_walk_cb(uintptr_t addr, const void *wdata, void *priv)
{
	struct pmcs_iport	iport;
	uintptr_t		list_addr;
	char			*ua_state;
	char			portid[4];
	char			unit_address[34];

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

	return (0);
}

/*ARGSUSED*/
static void
display_iport(struct pmcs_hw m, uintptr_t addr, int verbose)
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

	if (mdb_pwalk("list", pmcs_iport_walk_cb, NULL, list_addr) == -1) {
		mdb_warn("pmcs iport walk failed");
	}

	mdb_printf("\n");
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

	mdb_printf("Number of PHYs:   %d\n", m.nphy);
	mdb_printf("Maximum commands: %d\n", m.max_cmd);
	mdb_printf("Maximum devices:  %d\n", m.max_dev);
	mdb_printf("I/O queue depth:  %d\n", m.ioq_depth);
	if (m.fwlog == 0) {
		mdb_printf("Firmware logging: Disabled\n");
	} else {
		mdb_printf("Firmware logging: Enabled (%d)\n", m.fwlog);
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
		mdb_printf("VTGT %-16s %-16s %-5s %8s %s", "SAS Address",
		    "PHY Address", "DType", "Active", "DS");
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
		 * It has to be one of new, assigned or dying to be of interest.
		 */
		if (xs.new == 0 && xs.assigned == 0 && xs.dying == 0) {
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
		mdb_printf(" %8d", xs.actv_cnt);
		mdb_printf(" %2d", xs.dev_state);

		if (verbose) {
			if (xs.new) {
				mdb_printf(" new");
			} else if (xs.dying) {
				mdb_printf(" dying");
			} else if (xs.assigned) {
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
		mdb_printf("%08x %10s 0x%016p 0x%016p\n",
		    wp->last_htag, last_state, wp->last_phy, wp->last_xp);
	} else {
		mdb_printf("\n");
	}
}

static void
display_work(struct pmcs_hw m, int verbose)
{
	int		idx;
	boolean_t	header_printed = B_FALSE;
	pmcwork_t	work, *wp = &work;
	uintptr_t	_wp;

	mdb_printf("\nActive Work structure information:\n");
	mdb_printf("----------------------------------\n");

	_wp = (uintptr_t)m.work;

	for (idx = 0; idx < m.max_cmd; idx++, _wp += sizeof (pmcwork_t)) {
		if (MDB_RD(&work, sizeof (pmcwork_t), _wp) == -1) {
			NOREAD(pmcwork_t, _wp);
			continue;
		}

		if (!verbose && (wp->htag == PMCS_TAG_TYPE_FREE)) {
			continue;
		}

		if (header_printed == B_FALSE) {
			if (verbose) {
				mdb_printf("%4s ", "Idx");
			}
			mdb_printf("%8s %10s %20s %8s %8s O D ",
			    "HTag", "State", "Phy Path", "Target", "Timer");
			if (verbose) {
				mdb_printf("%8s %10s %18s %18s\n", "LastHTAG",
				    "LastState", "LastPHY", "LastTgt");
			} else {
				mdb_printf("\n");
			}
			header_printed = B_TRUE;
		}

		display_one_work(wp, verbose, idx);
	}
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
		break;
	case PMCS_OQ_GENERAL:
		return ("General");
		break;
	case PMCS_OQ_EVENTS:
		return ("Events");
		break;
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
		break;
	case PMCS_IOMB_CAT_FC:
		return ("FC");
		break;
	case PMCS_IOMB_CAT_SAS:
		return ("SAS");
		break;
	case PMCS_IOMB_CAT_SCSI:
		return ("SCSI");
		break;
	default:
		return ("???");
	}
}

static char *
inbound_iomb_opcode(uint32_t opcode)
{
	switch (opcode) {
	case PMCIN_ECHO:
		return ("ECHO");
		break;
	case PMCIN_GET_INFO:
		return ("GET_INFO");
		break;
	case PMCIN_GET_VPD:
		return ("GET_VPD");
		break;
	case PMCIN_PHY_START:
		return ("PHY_START");
		break;
	case PMCIN_PHY_STOP:
		return ("PHY_STOP");
		break;
	case PMCIN_SSP_INI_IO_START:
		return ("INI_IO_START");
		break;
	case PMCIN_SSP_INI_TM_START:
		return ("INI_TM_START");
		break;
	case PMCIN_SSP_INI_EXT_IO_START:
		return ("INI_EXT_IO_START");
		break;
	case PMCIN_DEVICE_HANDLE_ACCEPT:
		return ("DEVICE_HANDLE_ACCEPT");
		break;
	case PMCIN_SSP_TGT_IO_START:
		return ("TGT_IO_START");
		break;
	case PMCIN_SSP_TGT_RESPONSE_START:
		return ("TGT_RESPONSE_START");
		break;
	case PMCIN_SSP_INI_EDC_EXT_IO_START:
		return ("INI_EDC_EXT_IO_START");
		break;
	case PMCIN_SSP_INI_EDC_EXT_IO_START1:
		return ("INI_EDC_EXT_IO_START1");
		break;
	case PMCIN_SSP_TGT_EDC_IO_START:
		return ("TGT_EDC_IO_START");
		break;
	case PMCIN_SSP_ABORT:
		return ("SSP_ABORT");
		break;
	case PMCIN_DEREGISTER_DEVICE_HANDLE:
		return ("DEREGISTER_DEVICE_HANDLE");
		break;
	case PMCIN_GET_DEVICE_HANDLE:
		return ("GET_DEVICE_HANDLE");
		break;
	case PMCIN_SMP_REQUEST:
		return ("SMP_REQUEST");
		break;
	case PMCIN_SMP_RESPONSE:
		return ("SMP_RESPONSE");
		break;
	case PMCIN_SMP_ABORT:
		return ("SMP_ABORT");
		break;
	case PMCIN_ASSISTED_DISCOVERY:
		return ("ASSISTED_DISCOVERY");
		break;
	case PMCIN_REGISTER_DEVICE:
		return ("REGISTER_DEVICE");
		break;
	case PMCIN_SATA_HOST_IO_START:
		return ("SATA_HOST_IO_START");
		break;
	case PMCIN_SATA_ABORT:
		return ("SATA_ABORT");
		break;
	case PMCIN_LOCAL_PHY_CONTROL:
		return ("LOCAL_PHY_CONTROL");
		break;
	case PMCIN_GET_DEVICE_INFO:
		return ("GET_DEVICE_INFO");
		break;
	case PMCIN_TWI:
		return ("TWI");
		break;
	case PMCIN_FW_FLASH_UPDATE:
		return ("FW_FLASH_UPDATE");
		break;
	case PMCIN_SET_VPD:
		return ("SET_VPD");
		break;
	case PMCIN_GPIO:
		return ("GPIO");
		break;
	case PMCIN_SAS_DIAG_MODE_START_END:
		return ("SAS_DIAG_MODE_START_END");
		break;
	case PMCIN_SAS_DIAG_EXECUTE:
		return ("SAS_DIAG_EXECUTE");
		break;
	case PMCIN_SAW_HW_EVENT_ACK:
		return ("SAS_HW_EVENT_ACK");
		break;
	case PMCIN_GET_TIME_STAMP:
		return ("GET_TIME_STAMP");
		break;
	case PMCIN_PORT_CONTROL:
		return ("PORT_CONTROL");
		break;
	case PMCIN_GET_NVMD_DATA:
		return ("GET_NVMD_DATA");
		break;
	case PMCIN_SET_NVMD_DATA:
		return ("SET_NVMD_DATA");
		break;
	case PMCIN_SET_DEVICE_STATE:
		return ("SET_DEVICE_STATE");
		break;
	case PMCIN_GET_DEVICE_STATE:
		return ("GET_DEVICE_STATE");
		break;
	default:
		return ("UNKNOWN");
		break;
	}
}

static char *
outbound_iomb_opcode(uint32_t opcode)
{
	switch (opcode) {
	case PMCOUT_ECHO:
		return ("ECHO");
		break;
	case PMCOUT_GET_INFO:
		return ("GET_INFO");
		break;
	case PMCOUT_GET_VPD:
		return ("GET_VPD");
		break;
	case PMCOUT_SAS_HW_EVENT:
		return ("SAS_HW_EVENT");
		break;
	case PMCOUT_SSP_COMPLETION:
		return ("SSP_COMPLETION");
		break;
	case PMCOUT_SMP_COMPLETION:
		return ("SMP_COMPLETION");
		break;
	case PMCOUT_LOCAL_PHY_CONTROL:
		return ("LOCAL_PHY_CONTROL");
		break;
	case PMCOUT_SAS_ASSISTED_DISCOVERY_EVENT:
		return ("SAS_ASSISTED_DISCOVERY_SENT");
		break;
	case PMCOUT_SATA_ASSISTED_DISCOVERY_EVENT:
		return ("SATA_ASSISTED_DISCOVERY_SENT");
		break;
	case PMCOUT_DEVICE_REGISTRATION:
		return ("DEVICE_REGISTRATION");
		break;
	case PMCOUT_DEREGISTER_DEVICE_HANDLE:
		return ("DEREGISTER_DEVICE_HANDLE");
		break;
	case PMCOUT_GET_DEVICE_HANDLE:
		return ("GET_DEVICE_HANDLE");
		break;
	case PMCOUT_SATA_COMPLETION:
		return ("SATA_COMPLETION");
		break;
	case PMCOUT_SATA_EVENT:
		return ("SATA_EVENT");
		break;
	case PMCOUT_SSP_EVENT:
		return ("SSP_EVENT");
		break;
	case PMCOUT_DEVICE_HANDLE_ARRIVED:
		return ("DEVICE_HANDLE_ARRIVED");
		break;
	case PMCOUT_SMP_REQUEST_RECEIVED:
		return ("SMP_REQUEST_RECEIVED");
		break;
	case PMCOUT_SSP_REQUEST_RECEIVED:
		return ("SSP_REQUEST_RECEIVED");
		break;
	case PMCOUT_DEVICE_INFO:
		return ("DEVICE_INFO");
		break;
	case PMCOUT_FW_FLASH_UPDATE:
		return ("FW_FLASH_UPDATE");
		break;
	case PMCOUT_SET_VPD:
		return ("SET_VPD");
		break;
	case PMCOUT_GPIO:
		return ("GPIO");
		break;
	case PMCOUT_GPIO_EVENT:
		return ("GPIO_EVENT");
		break;
	case PMCOUT_GENERAL_EVENT:
		return ("GENERAL_EVENT");
		break;
	case PMCOUT_TWI:
		return ("TWI");
		break;
	case PMCOUT_SSP_ABORT:
		return ("SSP_ABORT");
		break;
	case PMCOUT_SATA_ABORT:
		return ("SATA_ABORT");
		break;
	case PMCOUT_SAS_DIAG_MODE_START_END:
		return ("SAS_DIAG_MODE_START_END");
		break;
	case PMCOUT_SAS_DIAG_EXECUTE:
		return ("SAS_DIAG_EXECUTE");
		break;
	case PMCOUT_GET_TIME_STAMP:
		return ("GET_TIME_STAMP");
		break;
	case PMCOUT_SAS_HW_EVENT_ACK_ACK:
		return ("SAS_HW_EVENT_ACK_ACK");
		break;
	case PMCOUT_PORT_CONTROL:
		return ("PORT_CONTROL");
		break;
	case PMCOUT_SKIP_ENTRIES:
		return ("SKIP_ENTRIES");
		break;
	case PMCOUT_SMP_ABORT:
		return ("SMP_ABORT");
		break;
	case PMCOUT_GET_NVMD_DATA:
		return ("GET_NVMD_DATA");
		break;
	case PMCOUT_SET_NVMD_DATA:
		return ("SET_NVMD_DATA");
		break;
	case PMCOUT_DEVICE_HANDLE_REMOVED:
		return ("DEVICE_HANDLE_REMOVED");
		break;
	case PMCOUT_SET_DEVICE_STATE:
		return ("SET_DEVICE_STATE");
		break;
	case PMCOUT_GET_DEVICE_STATE:
		return ("GET_DEVICE_STATE");
		break;
	case PMCOUT_SET_DEVICE_INFO:
		return ("SET_DEVICE_INFO");
		break;
	default:
		return ("UNKNOWN");
		break;
	}
}

static void
dump_one_qentry_outbound(uint32_t *qentryp, int idx)
{
	int qeidx;
	uint32_t word0 = LE_32(*qentryp);

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
display_outbound_queues(struct pmcs_hw ss, uint_t verbose)
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

		if (obqp == NULL) {
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
			dump_one_qentry_outbound(qentryp, last_consumed);
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
			dump_one_qentry_outbound(qentryp, idx);
		}

		mdb_printf("\n");
		mdb_dec_indent(2);
	}

	mdb_dec_indent(2);
	mdb_free(qentryp, PMCS_QENTRY_SIZE);
}

static void
dump_one_qentry_inbound(uint32_t *qentryp, int idx)
{
	int qeidx;
	uint32_t word0 = LE_32(*qentryp);

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
display_inbound_queues(struct pmcs_hw ss, uint_t verbose)
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

		if (ibqp == NULL) {
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
			dump_one_qentry_inbound(qentryp, last_consumed);
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
			dump_one_qentry_inbound(qentryp, idx);
		}

		mdb_printf("\n");
		mdb_dec_indent(2);
	}

	mdb_dec_indent(2);
	mdb_free(qentryp, PMCS_QENTRY_SIZE);
}

static void
display_phy(struct pmcs_phy phy, int verbose, int totals_only)
{
	char		*dtype, *speed;
	char		*yes = "Yes";
	char		*no = "No";
	char		*cfgd = no;
	char		*apend = no;
	char		*asent = no;
	char		*dead = no;
	char		*changed = no;

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

			mdb_printf("%-4s %-4s %-4s %-4s %-4s %3d "
			    "0x%p ", cfgd, apend, asent,
			    changed, dead, phy.ref_count, phy.phy_lock);
		}

		mdb_printf("Path: %s\n", phy.path);
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
			mdb_printf("Cfgd AbtP AbtS Chgd Dead Ref Lock\n");
		} else {
			mdb_printf("\n");
		}
	}

	while (pphy) {
		if (MDB_RD(&phy, sizeof (phy), (uintptr_t)pphy) == -1) {
			NOREAD(pmcs_phy_t, phy);
			break;
		}

		display_phy(phy, verbose, totals_only);

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
 * MAX_INST_STRLEN is the largest string size from which we will attempt
 * to convert to an instance number.  The string will be formed up as
 * "0t<inst>\0" so that mdb_strtoull can parse it properly.
 */
#define	MAX_INST_STRLEN	8

static int
pmcs_dump_tracelog(boolean_t filter, int instance)
{
	pmcs_tbuf_t *tbuf_addr;
	uint_t tbuf_idx;
	pmcs_tbuf_t tbuf;
	boolean_t wrap, elem_filtered;
	uint_t start_idx, elems_to_print, idx, tbuf_num_elems;
	char *bufp;
	char elem_inst[MAX_INST_STRLEN], ei_idx;

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

	/* Figure out where we start and stop */
	if (wrap) {
		start_idx = tbuf_idx;
		elems_to_print = tbuf_num_elems;
	} else {
		start_idx = 0;
		elems_to_print = tbuf_idx;
	}

	idx = start_idx;

	/* Dump the buffer contents */
	while (elems_to_print != 0) {
		if (MDB_RD(&tbuf, sizeof (pmcs_tbuf_t), (tbuf_addr + idx))
		    == -1) {
			NOREAD(tbuf, (tbuf_addr + idx));
			return (DCMD_ERR);
		}

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

		if (!elem_filtered) {
			mdb_printf("%Y.%09ld %s\n", tbuf.timestamp, tbuf.buf);
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
	if (wsp->walk_addr == NULL) {
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
	} while ((wsp->walk_addr == NULL) && (target_idx < ss.max_dev));

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

		phyp = phyp->parent;
	}

	return (parent.sibling);
}

static int
phy_walk_i(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL) {
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

	if (wsp->walk_addr == NULL) {
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

static int
pmcs_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct	pmcs_hw		ss;
	uint_t			verbose = FALSE;
	uint_t			phy_info = FALSE;
	uint_t			hw_info = FALSE;
	uint_t			target_info = FALSE;
	uint_t			work_info = FALSE;
	uint_t			ic_info = FALSE;
	uint_t			iport_info = FALSE;
	uint_t			waitqs_info = FALSE;
	uint_t			tracelog = FALSE;
	uint_t			ibq = FALSE;
	uint_t			obq = FALSE;
	uint_t			tgt_phy_count = FALSE;
	uint_t			compq = FALSE;
	int			rv = DCMD_OK;
	void			*pmcs_state;
	char			*state_str;
	struct dev_info		dip;

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
	    'h', MDB_OPT_SETBITS, TRUE, &hw_info,
	    'i', MDB_OPT_SETBITS, TRUE, &ic_info,
	    'I', MDB_OPT_SETBITS, TRUE, &iport_info,
	    'l', MDB_OPT_SETBITS, TRUE, &tracelog,
	    'p', MDB_OPT_SETBITS, TRUE, &phy_info,
	    'q', MDB_OPT_SETBITS, TRUE, &ibq,
	    'Q', MDB_OPT_SETBITS, TRUE, &obq,
	    't', MDB_OPT_SETBITS, TRUE, &target_info,
	    'T', MDB_OPT_SETBITS, TRUE, &tgt_phy_count,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose,
	    'w', MDB_OPT_SETBITS, TRUE, &work_info,
	    'W', MDB_OPT_SETBITS, TRUE, &waitqs_info,
	    NULL) != argc)
		return (DCMD_USAGE);

	if (MDB_RD(&ss, sizeof (ss), addr) == -1) {
		NOREAD(pmcs_hw_t, addr);
		return (DCMD_ERR);
	}

	if (MDB_RD(&dip, sizeof (struct dev_info), ss.dip) == -1) {
		NOREAD(pmcs_hw_t, addr);
		return (DCMD_ERR);
	}

	/*
	 * Dumping the trace log is special.  It's global, not per-HBA.
	 * Thus, a provided address is ignored.  In addition, other options
	 * cannot be specified at the same time.
	 */
	if (tracelog) {
		if (hw_info || ic_info || iport_info || phy_info || work_info ||
		    target_info || waitqs_info || ibq || obq || tgt_phy_count ||
		    compq) {
			return (DCMD_USAGE);
		}

		if ((flags & DCMD_ADDRSPEC) && !(flags & DCMD_LOOP)) {
			return (pmcs_dump_tracelog(B_TRUE, dip.devi_instance));
		} else if (flags & DCMD_LOOPFIRST) {
			return (pmcs_dump_tracelog(B_FALSE, 0));
		} else {
			return (DCMD_OK);
		}
	}

	/* processing completed */

	if (((flags & DCMD_ADDRSPEC) && !(flags & DCMD_LOOP)) ||
	    (flags & DCMD_LOOPFIRST) || phy_info || target_info || hw_info ||
	    work_info || waitqs_info || ibq || obq || tgt_phy_count || compq) {
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

	if (work_info)
		display_work(ss, verbose);

	if (ic_info)
		display_ic(ss, verbose);

	if (ibq)
		display_inbound_queues(ss, verbose);

	if (obq)
		display_outbound_queues(ss, verbose);

	if (iport_info)
		display_iport(ss, addr, verbose);

	if (compq)
		display_completion_queue(ss);

	mdb_dec_indent(4);

	return (rv);
}

void
pmcs_help()
{
	mdb_printf("Prints summary information about each pmcs instance.\n"
	    "    -c: Dump the completion queue\n"
	    "    -h: Print more detailed hardware information\n"
	    "    -i: Print interrupt coalescing information\n"
	    "    -I: Print information about each iport\n"
	    "    -l: Dump the trace log (cannot be used with other options)\n"
	    "    -p: Print information about each attached PHY\n"
	    "    -q: Dump inbound queues\n"
	    "    -Q: Dump outbound queues\n"
	    "    -t: Print information about each known target\n"
	    "    -T: Print target and PHY count summary\n"
	    "    -w: Dump work structures\n"
	    "    -W: List pmcs cmds waiting on various queues\n"
	    "    -v: Add verbosity to the above options\n");
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
	{ "pmcs", "?[-chiIpQqtTwWv] | -l", "print pmcs information",
	    pmcs_dcmd, pmcs_help
	},
	{ "pmcs_tag", "?[-t tagtype|-s serialnum|-i index]",
	    "Find work structures by tag type, serial number or index",
	    pmcs_tag, pmcs_tag_help
	},
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
