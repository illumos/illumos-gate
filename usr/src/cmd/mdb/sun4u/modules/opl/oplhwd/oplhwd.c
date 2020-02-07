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

#include <sys/mdb_modapi.h>
#include <sys/types.h>
#include <sys/dditypes.h>
#include <sys/fcode.h>
#include <sys/machcpuvar.h>
#include <sys/opl.h>
#include <sys/opl_cfg.h>

static uintptr_t tmptr;

/*
 * print hardware descriptor
 */

/* Verbosity bits */
#define	DUMP_HDR	0x00001		/* Header */
#define	DUMP_SB_STAT	0x00002		/* System Board Status */
#define	DUMP_DINFO	0x00004		/* Domain Information */
#define	DUMP_SB_INFO	0x00008		/* System Board Information */
#define	DUMP_CMU_CHAN	0x00010		/* CPU/Memory Channel */
#define	DUMP_CHIPS	0x00020		/* Phyiscal CPUs */
#define	DUMP_MEM	0x00040		/* Memory Information */
#define	DUMP_PCI_CH	0x00080		/* PCI Channel */
#define	DUMP_MEM_BANKS	0x00100		/* Memory Banks */
#define	DUMP_MEM_CHUNKS	0x00200		/* Memory Chunks */
#define	DUMP_MEM_DIMMS	0x00400		/* Memory DIMMS */
#define	DUMP_MEM_CS	0x00800		/* Memory CS */
#define	DUMP_CORES	0x01000		/* CPU Cores Information */
#define	DUMP_SCS	0x02000		/* SC Information */
#define	DUMP_MISSING	0x10000		/* Miscellenous Information */
#define	DUMP_COMP_NAME	0x20000		/* Component Name */


/* A nice mix of most of what you want */
#define	DUMP_ALL	(DUMP_HDR | DUMP_SB_STAT | DUMP_DINFO |		\
			DUMP_SB_INFO | DUMP_CMU_CHAN | DUMP_CHIPS |	\
			DUMP_MEM | DUMP_PCI_CH | DUMP_MEM_BANKS |	\
			DUMP_CORES | DUMP_SCS)


#define	DUMP_VERBOSE	(DUMP_ALL | DUMP_MEM_CHUNKS | DUMP_MEM_CS)
#define	DUMP_FULL	(DUMP_VERBOSE | DUMP_MISSING | DUMP_COMP_NAME)


#define	MIA(stat)		((stat) == HWD_STAT_MISS)
#define	DONT_BOTHER(stat, v)	(MIA(stat) && (v != HWD_STAT_PRESENT))

static char *hwd_stat_decode(int stat)
{
	switch (stat) {
	case HWD_STAT_UNKNOWN:
		return ("UNKNOWN");
	case HWD_STAT_PRESENT:
		return ("PRESENT");
	case HWD_STAT_MISS:
		return ("MISS");
	case HWD_STAT_MISCONFIG:
		return ("MISCONFIG");
	case HWD_STAT_PASS:
		return ("PASS");
	case HWD_STAT_FAIL:
		return ("FAIL_XSCF");
	case HWD_STAT_FAIL_OBP:
		return ("FAIL_OBP");
	case HWD_STAT_FAIL_OS:
		return ("FAIL_OS");
	default:
		return ("?");
	}
}

static void
dumpmemhwd(hwd_memory_t *memp, int v, int mv)
{
	int i, j;

	mdb_printf("\nMemory:\tstart\t0x%llx\tsize\t0x%llx\tmirror mode %d\n",
	    memp->mem_start_address, memp->mem_size, memp->mem_mirror_mode);
	mdb_printf("\tdivision mode\t0x%x\tpiece number\t0x%llx",
	    memp->mem_division_mode, memp->mem_piece_number);
	mdb_printf("\tcs interleave %d\n", memp->mem_cs_interleave);

	/* banks */
	for (i = 0; i < HWD_BANKS_PER_CMU; i++) {
		if (DONT_BOTHER(memp->mem_banks[i].bank_status, mv)) {
			mdb_printf("\tBank %d\tstatus\t0x%x (%s)\n",
			    i, memp->mem_banks[i].bank_status,
			    hwd_stat_decode(memp->mem_banks[i].bank_status));
			continue;
		}
		mdb_printf("\tBank %d\tstatus\t0x%x (%s)\treg addr\t0x%llx\n",
		    i, memp->mem_banks[i].bank_status,
		    hwd_stat_decode(memp->mem_banks[i].bank_status),
		    memp->mem_banks[i].bank_register_address);
		if (v & DUMP_MEM_BANKS) {
			mdb_printf("\t\tcs status\t0x%x 0x%x\n",
			    memp->mem_banks[i].bank_cs_status[0],
			    memp->mem_banks[i].bank_cs_status[1]);
			mdb_printf("\t\tMAC OCD\tDIMM OCDs\n");
			mdb_printf("\t\t%x\t%x %x  %x %x  %x %x  %x %x\n",
			    memp->mem_banks[i].bank_mac_ocd,
			    memp->mem_banks[i].bank_dimm_ocd[0][0],
			    memp->mem_banks[i].bank_dimm_ocd[0][1],
			    memp->mem_banks[i].bank_dimm_ocd[1][0],
			    memp->mem_banks[i].bank_dimm_ocd[1][1],
			    memp->mem_banks[i].bank_dimm_ocd[2][0],
			    memp->mem_banks[i].bank_dimm_ocd[2][1],
			    memp->mem_banks[i].bank_dimm_ocd[3][0],
			    memp->mem_banks[i].bank_dimm_ocd[3][1]);
		}
	}
	/* chunks */
	for (i = 0; i < HWD_MAX_MEM_CHUNKS; i++) {
		if ((memp->mem_chunks[i].chnk_start_address == 0) && (mv != 1))
			continue;
		mdb_printf("\tchunk %d\tstart\t0x%llx\tsize\t0x%llx\n",
		    i, memp->mem_chunks[i].chnk_start_address,
		    memp->mem_chunks[i].chnk_size);
	}
	/* dimms */
	for (i = 0; i < HWD_DIMMS_PER_CMU; i++) {
		if (DONT_BOTHER(memp->mem_dimms[i].dimm_status, mv)) {
			if (v & DUMP_MEM_DIMMS)
				mdb_printf("\tDIMM %d\tstatus\t0x%x (%s)\n",
				    i, memp->mem_dimms[i].dimm_status,
				    hwd_stat_decode(
				    memp->mem_dimms[i].dimm_status));
			continue;
		}
		mdb_printf("\tDIMM %d\tstatus\t0x%x (%s)\tcapacity\t0x%llx\n",
		    i, memp->mem_dimms[i].dimm_status,
		    hwd_stat_decode(memp->mem_dimms[i].dimm_status),
		    memp->mem_dimms[i].dimm_capacity);
		mdb_printf("\t\trank\t%x\tavailable capacity\t0x%llx\n",
		    memp->mem_dimms[i].dimm_rank,
		    memp->mem_dimms[i].dimm_available_capacity);
	}
	/* cs */
	for (i = 0; i < 2; i++) {
		if (DONT_BOTHER(memp->mem_cs[i].cs_status, mv)) {
			mdb_printf("\tCS %d:\tstatus\t0x%x (%s)\n",
			    i, memp->mem_cs[i].cs_status,
			    hwd_stat_decode(memp->mem_cs[i].cs_status));
			continue;
		}
		mdb_printf("\tCS %d:\tstatus\t0x%x (%s)\tavailable\t0x%llx\n",
		    i, memp->mem_cs[i].cs_status,
		    hwd_stat_decode(memp->mem_cs[i].cs_status),
		    memp->mem_cs[i].cs_available_capacity);
		mdb_printf("\t\tno of dimms\t%x\tdimm capacity\t0x%llx\n",
		    memp->mem_cs[i].cs_number_of_dimms,
		    memp->mem_cs[i].cs_dimm_capacity);
		mdb_printf("\t\tPA <-> MAC conversion\n\t\t");
		for (j = 0; j < 20; j++)
			mdb_printf("%02x ", memp->mem_cs[i].cs_pa_mac_table[j]);
		mdb_printf("\n\t\t");
		for (j = 20; j < 40; j++)
			mdb_printf("%02x ", memp->mem_cs[i].cs_pa_mac_table[j]);
		mdb_printf("\n\t\t");
		for (j = 40; j < 60; j++)
			mdb_printf("%02x ", memp->mem_cs[i].cs_pa_mac_table[j]);
		mdb_printf("\n\t\t");
		for (j = 60; j < 64; j++)
			mdb_printf("%02x ", memp->mem_cs[i].cs_pa_mac_table[j]);
		mdb_printf("\n");
	}
}

/* ARGSUSED */
static void
dumpchiphwd(hwd_cpu_chip_t *chipp, int ch, int v, int mv)
{
	int cp, co;
	hwd_cpu_t *cpup;
	hwd_core_t *corep;

	mdb_printf("\nChip %d:\tstatus\t0x%x (%s)\tportid\t%x\n",
	    ch, chipp->chip_status, hwd_stat_decode(chipp->chip_status),
	    chipp->chip_portid);

	if (MIA(chipp->chip_status))
		return;

	for (co = 0; co < HWD_CORES_PER_CPU_CHIP; co++) {
		corep = &chipp->chip_cores[co];

		mdb_printf("\tCore %d:\tstatus\t0x%x (%s)\tconfig\t0x%llx\n",
		    co, corep->core_status,
		    hwd_stat_decode(corep->core_status),
		    corep->core_config);

		if (MIA(corep->core_status))
			continue;

		if (v & DUMP_CORES) {
			mdb_printf("\t\tfrequency\t0x%llx\tversion\t0x%llx\n",
			    corep->core_frequency, corep->core_version);
			mdb_printf("\t\t(manuf/impl/mask: %x/%x/%x)\n",
			    corep->core_manufacturer,
			    corep->core_implementation, corep->core_mask);
			mdb_printf("\t\t\tSize\tLinesize\tAssoc\n");
			mdb_printf("\t\tL1I$\t%x\t%x\t\t%x\n",
			    corep->core_l1_icache_size,
			    corep->core_l1_icache_line_size,
			    corep->core_l1_icache_associativity);
			mdb_printf("\t\tL1D$\t%x\t%x\t\t%x\n",
			    corep->core_l1_dcache_size,
			    corep->core_l1_dcache_line_size,
			    corep->core_l1_dcache_associativity);
			mdb_printf("\t\tL2$\t%x\t%x\t\t%x",
			    corep->core_l2_cache_size,
			    corep->core_l2_cache_line_size,
			    corep->core_l2_cache_associativity);
			mdb_printf("\tsharing\t%x\n",
			    corep->core_l2_cache_sharing);
			mdb_printf("\t\tITLB entries\t0x%x\tDTLB entries "
			    "0x%x\n", corep->core_num_itlb_entries,
			    corep->core_num_dtlb_entries);
		}

		for (cp = 0; cp < HWD_CPUS_PER_CORE; cp++) {
			cpup = &corep->core_cpus[cp];
			mdb_printf("\t\tCPU %d:\tstatus\t0x%x (%s)\tcpuid"
			    " = 0x%x\n", cp, cpup->cpu_status,
			    hwd_stat_decode(cpup->cpu_status),
			    cpup->cpu_cpuid);
			if (v & DUMP_COMP_NAME)
				mdb_printf("\t\t\tcomponent name:%s\n",
				    cpup->cpu_component_name);
		}
	}
}

/* ARGSUSED */
static void
dumppcihwd(hwd_pci_ch_t *pcip, int ch, int v, int mv)
{
	int lf;
	hwd_leaf_t *leafp;

	mdb_printf("\nPCI CH %d:\tstatus\t0x%x (%s)\n",
	    ch, pcip->pci_status, hwd_stat_decode(pcip->pci_status));

	for (lf = 0; lf < HWD_LEAVES_PER_PCI_CHANNEL; lf++) {
		leafp = &pcip->pci_leaf[lf];

		if (DONT_BOTHER(leafp->leaf_status, mv)) {
			mdb_printf("\tleaf %d:\tstatus\t0x%x (%s)\n",
			    lf, leafp->leaf_status,
			    hwd_stat_decode(leafp->leaf_status));
			continue;
		}
		mdb_printf("\tleaf %d:\tstatus\t0x%x (%s)\tportid 0x%x",
		    lf, leafp->leaf_status,
		    hwd_stat_decode(leafp->leaf_status), leafp->leaf_port_id);
		mdb_printf("\ttype0x%x\n)",
		    leafp->leaf_slot_type);
		mdb_printf("\t\t\tOffset\t\tSize\n");
		mdb_printf("\t\tcfgio\t0x%llx\t0x%llx\t\t%x\n",
		    leafp->leaf_cfgio_offset,
		    leafp->leaf_cfgio_size);
		mdb_printf("\t\tmem32\t0x%llx\t0x%llx\t\t%x\n",
		    leafp->leaf_mem32_offset,
		    leafp->leaf_mem32_size);
		mdb_printf("\t\tmem64\t0x%llx\t0x%llx\t\t%x\n",
		    leafp->leaf_mem64_offset,
		    leafp->leaf_mem64_size);
	}
}

/* ARGSUSED */
static void
dumpahwd(int bd, int v)
{
	opl_board_cfg_t		boardcfg;
	hwd_header_t		hwd_hdr;
	hwd_sb_status_t		hwd_sb_status;
	hwd_domain_info_t	hwd_dinfo;
	hwd_sb_t		hwd_sb;
	caddr_t			statusp, dinfop, sbp = NULL;

	/* A flag for whether or not to dump stuff that is missing */
	int mv = 0;

	if (v & DUMP_MISSING)
		mv = 1;

	bzero(&boardcfg, sizeof (opl_board_cfg_t));
	bzero(&hwd_hdr, sizeof (hwd_header_t));
	bzero(&hwd_sb_status, sizeof (hwd_sb_status_t));
	bzero(&hwd_dinfo, sizeof (hwd_domain_info_t));
	bzero(&hwd_sb, sizeof (hwd_sb_t));


	if (mdb_vread(&boardcfg, sizeof (opl_board_cfg_t),
	    tmptr + (bd * sizeof (opl_board_cfg_t))) == -1) {
		mdb_warn("failed to read opl_board_cfg at %p",
		    (tmptr + (bd * sizeof (opl_board_cfg_t))));
		return;
	}

	if (boardcfg.cfg_hwd == NULL) {
		mdb_printf("Board %d has no HWD info\n", bd);
		return;
	}

	mdb_printf("Board %d:\thwd pointer\t%8llx\n", bd, boardcfg.cfg_hwd);

	/* We always need the header, for offsets */
	if (mdb_vread(&hwd_hdr, sizeof (hwd_header_t),
	    (uintptr_t)boardcfg.cfg_hwd) == -1) {
		mdb_warn("failed to read hwd_header_t at %p\n",
		    boardcfg.cfg_hwd);
		return;
	}

	/* Figure out the inside pointers, in case we need them... */
	statusp = (caddr_t)boardcfg.cfg_hwd + hwd_hdr.hdr_sb_status_offset;
	dinfop = (caddr_t)boardcfg.cfg_hwd + hwd_hdr.hdr_domain_info_offset;
	sbp = (caddr_t)boardcfg.cfg_hwd + hwd_hdr.hdr_sb_info_offset;

	/* The sb data is what we will surely be dumping */
	if (mdb_vread(&hwd_sb, sizeof (hwd_sb_t), (uintptr_t)sbp) == -1) {
		mdb_warn("failed to read hwd_sb_t at %p\n", sbp);
		return;
	}

	if (v & DUMP_HDR) {
		/* Print the interesting stuff from the header */
		mdb_printf("\t\tversion\t%x.%x\tDID\t%x\tmagic\t0x%x\n\n",
		    hwd_hdr.hdr_version.major, hwd_hdr.hdr_version.minor,
		    hwd_hdr.hdr_domain_id, hwd_hdr.hdr_magic);
		mdb_printf("\tstatus offset = 0x%x\t(addr=%llx)\n",
		    hwd_hdr.hdr_sb_status_offset, statusp);
		mdb_printf("\tdomain offset = 0x%x\t(addr=%llx)\n",
		    hwd_hdr.hdr_domain_info_offset, dinfop);
		mdb_printf("\tboard  offset = 0x%x\t(addr=%llx)\n",
		    hwd_hdr.hdr_sb_info_offset, sbp);
	}

	if (v & DUMP_SB_STAT) {
		int i;
		if (mdb_vread(&hwd_sb_status, sizeof (hwd_sb_status_t),
		    (uintptr_t)statusp) == -1) {
			mdb_warn("failed to read hwd_sb_status_t at %p\n",
			    statusp);
			return;
		}
		mdb_printf("\nSTATUS:\tBoard\tStatus\n");
		for (i = 0; i < HWD_SBS_PER_DOMAIN; i++) {
			if (DONT_BOTHER(hwd_sb_status.sb_status[i], mv))
				continue;
			mdb_printf("\t%d\t0x%x (%s)\n", i,
			    hwd_sb_status.sb_status[i],
			    hwd_stat_decode(hwd_sb_status.sb_status[i]));
		}
	}

	/* Domain Info */
	if (v & DUMP_DINFO) {
		if (mdb_vread(&hwd_dinfo, sizeof (hwd_domain_info_t),
		    (uintptr_t)dinfop) == -1) {
			mdb_warn("failed to read hwd_domain_info_t at %p\n",
			    dinfop);
			return;
		}
		mdb_printf("\nDomain info:\tReset reason\t0x%x",
		    hwd_dinfo.dinf_reset_factor);
		mdb_printf("\tHost ID 0x%x\n", hwd_dinfo.dinf_host_id);
		mdb_printf("\tSystem freq\t0x%llx\tStick freq\t0x%llx\n",
		    hwd_dinfo.dinf_system_frequency,
		    hwd_dinfo.dinf_stick_frequency);
		mdb_printf("\tSCF timeout \t0x%x\tModel info\t%x",
		    hwd_dinfo.dinf_scf_command_timeout,
		    hwd_dinfo.dinf_model_info);
		if (hwd_dinfo.dinf_dr_status == 0)
			mdb_printf("\tDR capable\n");
		else
			mdb_printf("\tNOT DR capable (%x)\n",
			    hwd_dinfo.dinf_dr_status);
		mdb_printf("\tMAC address\t%02x.%02x.%02x.%02x.%02x.%02x",
		    hwd_dinfo.dinf_mac_address[0],
		    hwd_dinfo.dinf_mac_address[1],
		    hwd_dinfo.dinf_mac_address[2],
		    hwd_dinfo.dinf_mac_address[3],
		    hwd_dinfo.dinf_mac_address[4],
		    hwd_dinfo.dinf_mac_address[5]);
		mdb_printf("\tcpu_start_time\t0x%llx\n",
		    hwd_dinfo.dinf_cpu_start_time);
		mdb_printf("\tcfg policy\t%x\tdiag lvl\t%x\tboot mode\t%x\n",
		    hwd_dinfo.dinf_config_policy, hwd_dinfo.dinf_diag_level,
		    hwd_dinfo.dinf_boot_mode);
		mdb_printf("\tBanner name\t%s\n",
		    hwd_dinfo.dinf_banner_name);
		mdb_printf("\tPlatform token\t%s\n",
		    hwd_dinfo.dinf_platform_token);
		mdb_printf("\tFloating bd bitmap\t%04x\n",
		    hwd_dinfo.dinf_floating_board_bitmap);
		mdb_printf("\tChassis Serial#\t%s\n",
		    hwd_dinfo.dinf_chassis_sn);
		mdb_printf("\tBrand Control\t%d\n",
		    hwd_dinfo.dinf_brand_control);

	}

	/* SB info */
	if (v & DUMP_SB_INFO) {
		mdb_printf("\nBoard:\tstatus =0x%x (%s)\tmode =0x%x (%s)\
		    \tPSB =0x%x\n", hwd_sb.sb_status,
		    hwd_stat_decode(hwd_sb.sb_status),
		    hwd_sb.sb_mode, (hwd_sb.sb_mode == 0 ? "PSB" : "XSB"),
		    hwd_sb.sb_psb_number);
	}

	/* CMU Chan info */
	if (v & DUMP_CMU_CHAN) {
		hwd_cmu_chan_t *cmup;
		cmup = &hwd_sb.sb_cmu.cmu_ch;

		mdb_printf("\nCMU CH: status\t0x%x (%s)\tportid=0x%x"
		    " LSB = 0x%x\n",
		    cmup->chan_status, hwd_stat_decode(cmup->chan_status),
		    cmup->chan_portid, ((cmup->chan_portid) >> 4));

		if (v & DUMP_COMP_NAME)
			mdb_printf("\tcomponent name:%s\n",
			    cmup->chan_component_name);

		/* scf_interface */
		mdb_printf("\tscf:\tstatus\t0x%x (%s)\n",
		    cmup->chan_scf_interface.scf_status,
		    hwd_stat_decode(cmup->chan_scf_interface.scf_status));
		if (v & DUMP_COMP_NAME)
			mdb_printf("\t\tcomponent name:%s\n",
			    cmup->chan_scf_interface.scf_component_name);

		/* serial */
		mdb_printf("\tserial:\tstatus\t0x%x (%s)\n",
		    cmup->chan_serial.tty_status,
		    hwd_stat_decode(cmup->chan_serial.tty_status));
		if (v & DUMP_COMP_NAME)
			mdb_printf("\t\tcomponent name:%s\n",
			    cmup->chan_serial.tty_component_name);

		/* fmem */
		mdb_printf("\tfmem[0]\tstatus\t0x%x (%s)",
		    cmup->chan_fmem[0].fmem_status,
		    hwd_stat_decode(cmup->chan_fmem[0].fmem_status));
		mdb_printf("\tused %x\tversion %x.%x.%x\n",
		    cmup->chan_fmem[0].fmem_used,
		    cmup->chan_fmem[0].fmem_version.fver_major,
		    cmup->chan_fmem[0].fmem_version.fver_minor,
		    cmup->chan_fmem[0].fmem_version.fver_local);
		if (v & DUMP_COMP_NAME)
			mdb_printf("\t\tcomponent name:%s\n",
			    cmup->chan_fmem[0].fmem_component_name);
		mdb_printf("\tfmem[1]\tstatus\t0x%x (%s)",
		    cmup->chan_fmem[1].fmem_status,
		    hwd_stat_decode(cmup->chan_fmem[1].fmem_status));
		mdb_printf("\tused %x\tversion %x.%x.%x\n",
		    cmup->chan_fmem[1].fmem_used,
		    cmup->chan_fmem[1].fmem_version.fver_major,
		    cmup->chan_fmem[1].fmem_version.fver_minor,
		    cmup->chan_fmem[1].fmem_version.fver_local);
		if (v & DUMP_COMP_NAME)
			mdb_printf("\t\tcomponent name:%s\n",
			    cmup->chan_fmem[1].fmem_component_name);

	}

	/* CMU SC info */
	if (v & DUMP_SCS) {
		hwd_sc_t *scp;
		int sc;

		for (sc = 0; sc < HWD_SCS_PER_CMU; sc++) {

			scp = &hwd_sb.sb_cmu.cmu_scs[sc];

			if (DONT_BOTHER(scp->sc_status, mv)) {
				mdb_printf("\nSC %d:\tstatus\t0x%x (%s)\n",
				    sc, scp->sc_status,
				    hwd_stat_decode(scp->sc_status));
			} else {
				mdb_printf("\nSC %d:\tstatus\t0x%x (%s)\t",
				    sc, scp->sc_status,
				    hwd_stat_decode(scp->sc_status));
				mdb_printf("register addr\t0x%llx\n",
				    scp->sc_register_address);
			}
		}

	}

	if (v & DUMP_MEM)
		dumpmemhwd(&hwd_sb.sb_cmu.cmu_memory, v, mv);

	if (v & DUMP_CHIPS) {
		int ch;
		for (ch = 0; ch < HWD_CPU_CHIPS_PER_CMU; ch++) {
			if (MIA(hwd_sb.sb_cmu.cmu_cpu_chips[ch].chip_status)) {
				mdb_printf("\nChip %d: status\t0x%x (%s)\n",
				    ch,
				    hwd_sb.sb_cmu.cmu_cpu_chips[ch].chip_status,
				    "MISS");
				continue;
			}
			dumpchiphwd(&hwd_sb.sb_cmu.cmu_cpu_chips[ch], ch, v,
			    mv);
		}
	}

	if (v & DUMP_PCI_CH) {
		int ch;
		for (ch = 0; ch < HWD_CPU_CHIPS_PER_CMU; ch++) {
			if (MIA(hwd_sb.sb_pci_ch[ch].pci_status)) {
				mdb_printf("\nPCI CH %d:\tstatus\t0x%x (%s)\n",
				    ch, hwd_sb.sb_pci_ch[ch].pci_status,
				    "MISS");
				continue;
			}
			dumppcihwd(&hwd_sb.sb_pci_ch[ch], ch, v, mv);
		}
	}
}

/*
 * oplhwd dcmd - Print out the per-board HWD, nicely formatted.
 */
/*ARGSUSED*/
static int
oplhwd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int		bdi;
	uint64_t	v_mode = DUMP_HDR;
	uint_t		obits = 0;
	GElf_Sym	tmsym;
	uint64_t	bdo;

	/*
	 * Either use the board number, or get an arg for it, or
	 * show all of them.
	 */

	if (flags & DCMD_ADDRSPEC) {
		bdi = addr;
	} else {
		bdi = -1;
	}

	bdo = bdi;
	if (mdb_getopts(argc, argv,
	    'a', MDB_OPT_SETBITS, DUMP_FULL, &obits,	 /* All possible info */
	    'b', MDB_OPT_UINT64, &bdo,			 /* board number */
	    'd', MDB_OPT_SETBITS, DUMP_DINFO, &obits,	 /* domain info */
	    's', MDB_OPT_SETBITS, DUMP_SB_STAT, &obits,	 /* SB status */
	    'i', MDB_OPT_SETBITS, DUMP_SB_INFO, &obits,	 /* SB info */
	    'c', MDB_OPT_SETBITS, DUMP_CMU_CHAN, &obits, /* CMU chan  */
	    'h', MDB_OPT_SETBITS, DUMP_CHIPS, &obits,	 /* chips */
	    'm', MDB_OPT_SETBITS, DUMP_MEM, &obits,	 /* memory */
	    'p', MDB_OPT_SETBITS, DUMP_PCI_CH, &obits,	 /* PCI chans */
	    'k', MDB_OPT_SETBITS, DUMP_MEM_BANKS, &obits, /* banks */
	    'o', MDB_OPT_SETBITS, DUMP_CORES, &obits,	  /* core details */
	    'r', MDB_OPT_SETBITS, DUMP_SCS, &obits,	  /* SC info */
	    'C', MDB_OPT_SETBITS, DUMP_COMP_NAME, &obits,  /* SC info */
	    'v', MDB_OPT_SETBITS, DUMP_VERBOSE, &obits,	/* all of the above */
	    NULL) != argc)
		return (DCMD_USAGE);
	bdi = bdo;
	v_mode |= obits;

	if (mdb_lookup_by_obj("opl_cfg", "opl_boards", &tmsym) == -1) {
		mdb_warn("unable to reference opl_boards\n");
		return (DCMD_ERR);
	}

	tmptr = (uintptr_t)tmsym.st_value;
	mdb_printf("Board %d:\tboardcfg \t%8llx\n", 0, tmptr);

	if (bdi < 0) {
		/* get active boards */
		for (bdi = 0; bdi < OPL_MAX_BOARDS; bdi++)
			dumpahwd(bdi, v_mode);
	} else {
		dumpahwd(bdi, v_mode);
	}
	return (DCMD_OK);
}

/*
 * ::oplhwd help
 */
static void
oplhwd_help(void)
{
	mdb_printf("oplhwd will dump HWD only for a particular board"
	    " on which,");
	mdb_printf("an earlier DR operation has been executed.\n");
	mdb_printf("-b NUM \tlist oplhwd entry for a board\n"
	    "-s \t\tlist oplhwd entry with SB status\n"
	    "-d \t\tlist oplhwd entry with Domain info.\n"
	    "-i \t\tlist oplhwd entry with SB info.\n"
	    "-h \t\tlist oplhwd entry with Chips details\n"
	    "-o \t\tlist oplhwd entry with Core details\n"
	    "-m \t\tlist oplhwd entry with Memory info.\n"
	    "-k \t\tlist oplhwd entry with Memory Bank info.\n"
	    "-r \t\tlist oplhwd entry with SC info.\n"
	    "-c \t\tlist oplhwd entry with CMU channels\n"
	    "-p \t\tlist oplhwd entry with PCI channels\n"
	    "-a \t\tlist oplhwd entry with all possible info.\n"
	    "-C \t\tlist oplhwd entry with component names\n"
	    "-v \t\tlist oplhwd entry in verbose mode\n");
}

/*
 * MDB module linkage information:
 *
 * We declare a list of structures describing our dcmds, and a function
 * named _mdb_init to return a pointer to our module information.
 */

static const mdb_dcmd_t dcmds[] = {
	{ "oplhwd", "?[ -b NUM ] [ -sdihomkrcp ] [ -a ] [ -C ] [ -v ]",
	"dump hardware descriptor for SUNW,SPARC-Enterprise",
	oplhwd, oplhwd_help },
	{ NULL }
};

static const mdb_modinfo_t modinfo = {
	MDB_API_VERSION, dcmds, NULL
};

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
