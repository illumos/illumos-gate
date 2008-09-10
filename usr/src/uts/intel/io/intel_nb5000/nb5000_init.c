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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/log.h>
#include <sys/systm.h>
#include <sys/modctl.h>
#include <sys/errorq.h>
#include <sys/controlregs.h>
#include <sys/fm/util.h>
#include <sys/fm/protocol.h>
#include <sys/sysevent.h>
#include <sys/pghw.h>
#include <sys/cyclic.h>
#include <sys/pci_cfgspace.h>
#include <sys/mc_intel.h>
#include <sys/smbios.h>
#include <sys/pci.h>
#include <sys/pcie.h>
#include "nb5000.h"
#include "nb_log.h"
#include "dimm_phys.h"
#include "rank.h"

int nb_hw_memory_scrub_enable = 1;
static int nb_sw_scrub_disabled = 0;

int nb_5000_memory_controller = 0;
int nb_number_memory_controllers = NB_5000_MAX_MEM_CONTROLLERS;
int nb_dimms_per_channel = 0;
static int ndimms = 0;

nb_dimm_t **nb_dimms;
int nb_ndimm;
uint32_t nb_chipset;
enum nb_memory_mode nb_mode;
bank_select_t nb_banks[NB_MAX_MEM_BRANCH_SELECT];
rank_select_t nb_ranks[NB_5000_MAX_MEM_CONTROLLERS][NB_MAX_MEM_RANK_SELECT];
uint32_t top_of_low_memory;
uint8_t spare_rank[NB_5000_MAX_MEM_CONTROLLERS];

errorq_t *nb_queue;
kmutex_t nb_mutex;

static uint8_t nb_err0_int;
static uint8_t nb_err1_int;
static uint8_t nb_err2_int;
static uint8_t nb_mcerr_int;
static uint32_t nb_emask_int;

static uint32_t nb_err0_fbd;
static uint32_t nb_err1_fbd;
static uint32_t nb_err2_fbd;
static uint32_t nb_mcerr_fbd;
static uint32_t nb_emask_fbd;

static uint16_t nb_err0_fsb;
static uint16_t nb_err1_fsb;
static uint16_t nb_err2_fsb;
static uint16_t nb_mcerr_fsb;
static uint16_t nb_emask_fsb;

static uint16_t nb_err0_thr;
static uint16_t nb_err1_thr;
static uint16_t nb_err2_thr;
static uint16_t nb_mcerr_thr;
static uint16_t nb_emask_thr;

static uint32_t	emask_uncor_pex[NB_PCI_DEV];
static uint32_t emask_cor_pex[NB_PCI_DEV];
static uint32_t emask_rp_pex[NB_PCI_DEV];
static uint32_t docmd_pex[NB_PCI_DEV];
static uint32_t uncerrsev[NB_PCI_DEV];

static uint8_t l_mcerr_int;
static uint32_t l_mcerr_fbd;
static uint16_t l_mcerr_fsb;
static uint16_t l_mcerr_thr;

uint_t nb5000_emask_fbd = EMASK_5000_FBD_RES;
uint_t nb5400_emask_fbd = 0;
int nb5000_reset_emask_fbd = 1;
uint_t nb5000_mask_poll_fbd = EMASK_FBD_NF;
uint_t nb5000_mask_bios_fbd = EMASK_FBD_FATAL;
uint_t nb5400_mask_poll_fbd = EMASK_5400_FBD_NF;
uint_t nb5400_mask_bios_fbd = EMASK_5400_FBD_FATAL;

uint_t nb5000_emask_fsb = 0;
int nb5000_reset_emask_fsb = 1;
uint_t nb5000_mask_poll_fsb = EMASK_FSB_NF;
uint_t nb5000_mask_bios_fsb = EMASK_FSB_FATAL;

uint_t nb5400_emask_int = 0;

uint_t nb7300_emask_int = EMASK_INT_7300;
uint_t nb7300_emask_int_step0 = EMASK_INT_7300_STEP_0;
uint_t nb5000_emask_int = EMASK_INT_5000;
int nb5000_reset_emask_int = 1;
uint_t nb5000_mask_poll_int = EMASK_INT_NF;
uint_t nb5000_mask_bios_int = EMASK_INT_FATAL;

uint_t nb_mask_poll_thr = EMASK_THR_NF;
uint_t nb_mask_bios_thr = EMASK_THR_FATAL;

int nb5000_reset_uncor_pex = 0;
uint_t nb5000_mask_uncor_pex = 0;
int nb5000_reset_cor_pex = 0;
uint_t nb5000_mask_cor_pex = 0xffffffff;
int nb_set_docmd = 1;
uint32_t nb5000_rp_pex = 0x1;
uint32_t nb5000_docmd_pex_mask = DOCMD_PEX_MASK;
uint32_t nb5400_docmd_pex_mask = DOCMD_5400_PEX_MASK;
uint32_t nb5000_docmd_pex = DOCMD_PEX;
uint32_t nb5400_docmd_pex = DOCMD_5400_PEX;

int nb_mask_mc_set;

typedef struct find_dimm_label {
	void (*label_function)(int, char *, int);
} find_dimm_label_t;

static void x8450_dimm_label(int, char *, int);

static struct platform_label {
	const char *sys_vendor;		/* SMB_TYPE_SYSTEM vendor prefix */
	const char *sys_product;	/* SMB_TYPE_SYSTEM product prefix */
	find_dimm_label_t dimm_label;
	int dimms_per_channel;
} platform_label[] = {
	{ "SUN MICROSYSTEMS", "SUN BLADE X8450 SERVER MODULE",
	    x8450_dimm_label, 8 },
	{ NULL, NULL, NULL, 0 }
};

static unsigned short
read_spd(int bus)
{
	unsigned short rt = 0;
	int branch = bus >> 1;
	int channel = bus & 1;

	rt = SPD_RD(branch, channel);

	return (rt);
}

static void
write_spdcmd(int bus, uint32_t val)
{
	int branch = bus >> 1;
	int channel = bus & 1;
	SPDCMD_WR(branch, channel, val);
}

static int
read_spd_eeprom(int bus, int slave, int addr)
{
	int retry = 4;
	int wait;
	int spd;
	uint32_t cmd;

	for (;;) {
		wait = 1000;
		for (;;) {
			spd = read_spd(bus);
			if ((spd & SPD_BUSY) == 0)
				break;
			if (--wait == 0)
				return (-1);
			drv_usecwait(10);
		}
		cmd = SPD_EEPROM_WRITE | SPD_ADDR(slave, addr);
		write_spdcmd(bus, cmd);
		wait = 1000;
		for (;;) {
			spd = read_spd(bus);
			if ((spd & SPD_BUSY) == 0)
				break;
			if (--wait == 0) {
				spd = SPD_BUS_ERROR;
				break;
			}
			drv_usecwait(10);
		}
		while ((spd & SPD_BUS_ERROR) == 0 &&
		    (spd & (SPD_READ_DATA_VALID|SPD_BUSY)) !=
		    SPD_READ_DATA_VALID) {
			spd = read_spd(bus);
			if (--wait == 0)
				return (-1);
		}
		if ((spd & SPD_BUS_ERROR) == 0)
			break;
		if (--retry == 0)
			return (-1);
	}
	return (spd & 0xff);
}

static void
nb_fini()
{
	int i, j;
	int nchannels = nb_number_memory_controllers * 2;
	nb_dimm_t **dimmpp;
	nb_dimm_t *dimmp;

	dimmpp = nb_dimms;
	for (i = 0; i < nchannels; i++) {
		for (j = 0; j < nb_dimms_per_channel; j++) {
			dimmp = *dimmpp;
			if (dimmp) {
				kmem_free(dimmp, sizeof (nb_dimm_t));
				*dimmpp = NULL;
			}
			dimmp++;
		}
	}
	kmem_free(nb_dimms, sizeof (nb_dimm_t *) *
	    nb_number_memory_controllers * 2 * nb_dimms_per_channel);
	nb_dimms = NULL;
	dimm_fini();
}

void
nb_scrubber_enable()
{
	uint32_t mc;

	if (!nb_hw_memory_scrub_enable)
		return;

	mc = MC_RD();
	if ((mc & MC_MIRROR) != 0) /* mirror mode */
		mc |= MC_PATROL_SCRUB;
	else
		mc |= MC_PATROL_SCRUB|MC_DEMAND_SCRUB;
	MC_WR(mc);

	if (nb_sw_scrub_disabled++)
		cmi_mc_sw_memscrub_disable();
}

static nb_dimm_t *
nb_dimm_init(int channel, int dimm, uint16_t mtr)
{
	nb_dimm_t *dp;
	int i, t;
	int spd_sz;

	if (MTR_PRESENT(mtr) == 0)
		return (NULL);
	t = read_spd_eeprom(channel, dimm, 2) & 0xf;

	if (t != 9)
		return (NULL);

	dp = kmem_zalloc(sizeof (nb_dimm_t), KM_SLEEP);

	t = read_spd_eeprom(channel, dimm, 0) & 0xf;
	if (t == 1)
		spd_sz = 128;
	else if (t == 2)
		spd_sz = 176;
	else
		spd_sz = 256;
	dp->manufacture_id = read_spd_eeprom(channel, dimm, 117) |
	    (read_spd_eeprom(channel, dimm, 118) << 8);
	dp->manufacture_location = read_spd_eeprom(channel, dimm, 119);
	dp->serial_number =
	    (read_spd_eeprom(channel, dimm, 122) << 24) |
	    (read_spd_eeprom(channel, dimm, 123) << 16) |
	    (read_spd_eeprom(channel, dimm, 124) << 8) |
	    read_spd_eeprom(channel, dimm, 125);
	t = read_spd_eeprom(channel, dimm, 121);
	dp->manufacture_week = (t >> 4) * 10 + (t & 0xf);
	dp->manufacture_year = read_spd_eeprom(channel, dimm, 120);
	if (spd_sz > 128) {
		for (i = 0; i < sizeof (dp->part_number); i++) {
			dp->part_number[i] =
			    read_spd_eeprom(channel, dimm, 128 + i);
		}
		for (i = 0; i < sizeof (dp->revision); i++) {
			dp->revision[i] =
			    read_spd_eeprom(channel, dimm, 146 + i);
		}
	}
	dp->mtr_present = MTR_PRESENT(mtr);
	dp->nranks = MTR_NUMRANK(mtr);
	dp->nbanks = MTR_NUMBANK(mtr);
	dp->ncolumn = MTR_NUMCOL(mtr);
	dp->nrow = MTR_NUMROW(mtr);
	dp->width = MTR_WIDTH(mtr);
	dp->dimm_size = MTR_DIMMSIZE(mtr);

	return (dp);
}

static uint64_t
mc_range(int controller, uint64_t base)
{
	int i;
	uint64_t limit = 0;

	for (i = 0; i < NB_MEM_BRANCH_SELECT; i++) {
		if (nb_banks[i].way[controller] && base >= nb_banks[i].base &&
		    base < nb_banks[i].limit) {
			limit = nb_banks[i].limit;
			if (base <= top_of_low_memory &&
			    limit > top_of_low_memory) {
				limit -= TLOW_MAX - top_of_low_memory;
			}
			if (nb_banks[i].way[0] && nb_banks[i].way[1] &&
			    nb_mode != NB_MEMORY_MIRROR) {
				limit = limit / 2;
			}
		}
	}
	return (limit);
}

void
nb_mc_init()
{
	uint16_t tolm;
	uint16_t mir;
	uint32_t hole_base;
	uint32_t hole_size;
	uint32_t dmir;
	uint64_t base;
	uint64_t limit;
	uint8_t way0, way1, rank0, rank1, rank2, rank3, branch_interleave;
	int i, j, k;
	uint8_t interleave;

	base = 0;
	tolm = TOLM_RD();
	top_of_low_memory = ((uint32_t)(tolm >> 12) & 0xf) << 28;
	for (i = 0; i < NB_MEM_BRANCH_SELECT; i++) {
		mir = MIR_RD(i);
		limit = (uint64_t)(mir >> 4) << 28;
		way0 = mir & 1;
		way1 = (mir >> 1) & 1;
		if (way0 == 0 && way1 == 0) {
			way0 = 1;
			way1 = 1;
		}
		if (limit > top_of_low_memory)
			limit += TLOW_MAX - top_of_low_memory;
		nb_banks[i].base = base;
		nb_banks[i].limit = limit;
		nb_banks[i].way[0] = way0;
		nb_banks[i].way[1] = way1;
		base = limit;
	}
	for (i = 0; i < nb_number_memory_controllers; i++) {
		base = 0;

		for (j = 0; j < NB_MEM_RANK_SELECT; j++) {
			dmir = DMIR_RD(i, j);
			limit = ((uint64_t)(dmir >> 16) & 0xff) << 28;
			if (limit == 0) {
				limit = mc_range(i, base);
			}
			branch_interleave = 0;
			hole_base = 0;
			hole_size = 0;
			DMIR_RANKS(dmir, rank0, rank1, rank2, rank3);
			if (rank0 == rank1)
				interleave = 1;
			else if (rank0 == rank2)
				interleave = 2;
			else
				interleave = 4;
			if (nb_mode != NB_MEMORY_MIRROR &&
			    nb_mode != NB_MEMORY_SINGLE_CHANNEL) {
				for (k = 0; k < NB_MEM_BRANCH_SELECT; k++) {
					if (base >= nb_banks[k].base &&
					    base < nb_banks[k].limit) {
						if (nb_banks[i].way[0] &&
						    nb_banks[i].way[1]) {
							interleave *= 2;
							limit *= 2;
							branch_interleave = 1;
						}
						break;
					}
				}
			}
			if (base < top_of_low_memory &&
			    limit > top_of_low_memory) {
				hole_base = top_of_low_memory;
				hole_size = TLOW_MAX - top_of_low_memory;
				limit += hole_size;
			} else if (base > top_of_low_memory) {
				limit += TLOW_MAX - top_of_low_memory;
			}
			nb_ranks[i][j].base = base;
			nb_ranks[i][j].limit = limit;
			nb_ranks[i][j].rank[0] = rank0;
			nb_ranks[i][j].rank[1] = rank1;
			nb_ranks[i][j].rank[2] = rank2;
			nb_ranks[i][j].rank[3] = rank3;
			nb_ranks[i][j].interleave = interleave;
			nb_ranks[i][j].branch_interleave = branch_interleave;
			nb_ranks[i][j].hole_base = hole_base;
			nb_ranks[i][j].hole_size = hole_size;
			if (limit > base) {
				dimm_add_rank(i, rank0, branch_interleave, 0,
				    base, hole_base, hole_size, interleave,
				    limit);
				if (rank0 != rank1) {
					dimm_add_rank(i, rank1,
					    branch_interleave, 1, base,
					    hole_base, hole_size, interleave,
					    limit);
					if (rank0 != rank2) {
						dimm_add_rank(i, rank2,
						    branch_interleave, 2, base,
						    hole_base, hole_size,
						    interleave, limit);
						dimm_add_rank(i, rank3,
						    branch_interleave, 3, base,
						    hole_base, hole_size,
						    interleave, limit);
					}
				}
			}
			base = limit;
		}
	}
}

void
nb_used_spare_rank(int branch, int bad_rank)
{
	int i;
	int j;

	for (i = 0; i < NB_MEM_RANK_SELECT; i++) {
		for (j = 0; j < NB_RANKS_IN_SELECT; j++) {
			if (nb_ranks[branch][i].rank[j] == bad_rank) {
				nb_ranks[branch][i].rank[j] =
				    spare_rank[branch];
				i = NB_MEM_RANK_SELECT;
				break;
			}
		}
	}
}

/*ARGSUSED*/
static int
memoryarray(smbios_hdl_t *shp, const smbios_struct_t *sp, void *arg)
{
	smbios_memarray_t ma;

	if (sp->smbstr_type == SMB_TYPE_MEMARRAY &&
	    smbios_info_memarray(shp, sp->smbstr_id, &ma) == 0) {
		ndimms += ma.smbma_ndevs;
	}
	return (0);
}

find_dimm_label_t *
find_dimms_per_channel()
{
	struct platform_label *pl;
	smbios_info_t si;
	smbios_system_t sy;
	id_t id;
	int read_memarray = 1;
	find_dimm_label_t *rt = NULL;

	if (ksmbios != NULL) {
		if ((id = smbios_info_system(ksmbios, &sy)) != SMB_ERR &&
		    smbios_info_common(ksmbios, id, &si) != SMB_ERR) {
			for (pl = platform_label; pl->sys_vendor; pl++) {
				if (strncmp(pl->sys_vendor,
				    si.smbi_manufacturer,
				    strlen(pl->sys_vendor)) == 0 &&
				    strncmp(pl->sys_product, si.smbi_product,
				    strlen(pl->sys_product)) == 0) {
					nb_dimms_per_channel =
					    pl->dimms_per_channel;
					read_memarray = 0;
					rt = &pl->dimm_label;
					break;
				}
			}
		}
		if (read_memarray)
			(void) smbios_iter(ksmbios, memoryarray, 0);
	}
	if (nb_dimms_per_channel == 0) {
		if (ndimms) {
			nb_dimms_per_channel = ndimms /
			    (nb_number_memory_controllers * 2);
		} else {
			nb_dimms_per_channel = NB_MAX_DIMMS_PER_CHANNEL;
		}
	}
	return (rt);
}

static int
dimm_label(smbios_hdl_t *shp, const smbios_struct_t *sp, void *arg)
{
	nb_dimm_t ***dimmpp = arg;
	nb_dimm_t *dimmp;
	smbios_memdevice_t md;

	if (sp->smbstr_type == SMB_TYPE_MEMDEVICE) {
		dimmp = **dimmpp;
		if (dimmp && smbios_info_memdevice(shp, sp->smbstr_id,
		    &md) == 0 && md.smbmd_dloc != NULL) {
			(void) snprintf(dimmp->label,
			    sizeof (dimmp->label), "%s", md.smbmd_dloc);
		}
		(*dimmpp)++;
	}
	return (0);
}

void
nb_smbios()
{
	nb_dimm_t **dimmpp;

	if (ksmbios != NULL) {
		dimmpp = nb_dimms;
		(void) smbios_iter(ksmbios, dimm_label, &dimmpp);
	}
}

static void
x8450_dimm_label(int dimm, char *label, int label_sz)
{
	int channel = dimm >> 3;

	dimm = dimm & 0x7;
	(void) snprintf(label, label_sz, "D%d", (dimm * 4) + channel);
}

static void
nb_dimms_init(find_dimm_label_t *label_function)
{
	int i, j, k, l;
	uint16_t mtr;
	uint32_t mc, mca;
	uint32_t spcpc;
	uint8_t spcps;
	nb_dimm_t **dimmpp;

	mca = MCA_RD();
	mc = MC_RD();
	if (mca & MCA_SCHDIMM)  /* single-channel mode */
		nb_mode = NB_MEMORY_SINGLE_CHANNEL;
	else if ((mc & MC_MIRROR) != 0) /* mirror mode */
		nb_mode = NB_MEMORY_MIRROR;
	else
		nb_mode = NB_MEMORY_NORMAL;
	nb_dimms = (nb_dimm_t **)kmem_zalloc(sizeof (nb_dimm_t *) *
	    nb_number_memory_controllers * 2 * nb_dimms_per_channel, KM_SLEEP);
	dimmpp = nb_dimms;
	for (i = 0; i < nb_number_memory_controllers; i++) {
		if (nb_mode == NB_MEMORY_NORMAL) {
			spcpc = SPCPC_RD(i);
			spcps = SPCPS_RD(i);
			if ((spcpc & SPCPC_SPARE_ENABLE) != 0 &&
			    (spcps & SPCPS_SPARE_DEPLOYED) != 0)
				nb_mode = NB_MEMORY_SPARE_RANK;
			spare_rank[i] = SPCPC_SPRANK(spcpc);
		}
		for (j = 0; j < nb_dimms_per_channel; j++) {
			mtr = MTR_RD(i, j);
			k = i * 2;
			dimmpp[j] = nb_dimm_init(k, j, mtr);
			if (dimmpp[j]) {
				nb_ndimm ++;
				dimm_add_geometry(i, j, dimmpp[j]->nbanks,
				    dimmpp[j]->width, dimmpp[j]->ncolumn,
				    dimmpp[j]->nrow);
				if (label_function) {
					label_function->label_function(
					    (k * nb_dimms_per_channel) + j,
					    dimmpp[j]->label,
					    sizeof (dimmpp[j]->label));
				}
			}
			dimmpp[j + nb_dimms_per_channel] =
			    nb_dimm_init(k + 1, j, mtr);
			l = j + nb_dimms_per_channel;
			if (dimmpp[l]) {
				if (label_function) {
					label_function->label_function(
					    (k * nb_dimms_per_channel) + l,
					    dimmpp[l]->label,
					    sizeof (dimmpp[l]->label));
				}
				nb_ndimm ++;
			}
		}
		dimmpp += nb_dimms_per_channel * 2;
	}
	if (label_function == NULL)
		nb_smbios();
}

static void
nb_pex_init()
{
	int i;
	uint32_t mask;

	for (i = 0; i < NB_PCI_DEV; i++) {
		switch (nb_chipset) {
		case INTEL_NB_5000P:
		case INTEL_NB_5000X:
			if (i == 1 || i > 8)
				continue;
			break;
		case INTEL_NB_5000V:
			if (i == 1 || i > 3)
				continue;
			break;
		case INTEL_NB_5000Z:
			if (i == 1 || i > 5)
				continue;
			break;
		case INTEL_NB_5400:
			break;
		case INTEL_NB_7300:
			if (i > 8)
				continue;
			break;
		}
		emask_uncor_pex[i] = EMASK_UNCOR_PEX_RD(i);
		emask_cor_pex[i] = EMASK_COR_PEX_RD(i);
		emask_rp_pex[i] = EMASK_RP_PEX_RD(i);
		docmd_pex[i] = PEX_ERR_DOCMD_RD(i);
		uncerrsev[i] = UNCERRSEV_RD(i);

		if (nb5000_reset_uncor_pex)
			EMASK_UNCOR_PEX_WR(i, nb5000_mask_uncor_pex);
		if (nb5000_reset_cor_pex)
			EMASK_COR_PEX_WR(i, nb5000_mask_cor_pex);
		if (nb_set_docmd) {
			if (nb_chipset == INTEL_NB_5400) {
				/* disable masking of ERR pins used by DOCMD */
				PEX_ERR_PIN_MASK_WR(i, 0x10);

				mask = (docmd_pex[i] & nb5400_docmd_pex_mask) |
				    (nb5400_docmd_pex & ~nb5400_docmd_pex_mask);
			} else {
				mask = (docmd_pex[i] & nb5000_docmd_pex_mask) |
				    (nb5000_docmd_pex & ~nb5000_docmd_pex_mask);
			}
			PEX_ERR_DOCMD_WR(i, mask);
		}

		/* RP error message (CE/NFE/FE) detect mask */
		EMASK_RP_PEX_WR(i, nb5000_rp_pex);

		/* Setup ESI port registers to enable SERR for southbridge */
		if (i == 0) {
			uint16_t regw;

			/* Command Register - Enable SERR */
			regw = nb_pci_getw(0, i, 0, PCI_CONF_COMM, 0);
			nb_pci_putw(0, i, 0, PCI_CONF_COMM,
			    regw | PCI_COMM_SERR_ENABLE);

			/* Root Control Register - SERR on NFE/FE */
			PEXROOTCTL_WR(i, PCIE_ROOTCTL_SYS_ERR_ON_NFE_EN |
			    PCIE_ROOTCTL_SYS_ERR_ON_FE_EN);

			/* AER UE Mask - Mask UR */
			UNCERRMSK_WR(i, PCIE_AER_UCE_UR);
		}
	}
}

static void
nb_pex_fini()
{
	int i;

	for (i = 0; i < NB_PCI_DEV; i++) {
		switch (nb_chipset) {
		case INTEL_NB_5000P:
		case INTEL_NB_5000X:
			if (i == 1 && i > 8)
				continue;
			break;
		case INTEL_NB_5000V:
			if (i == 1 || i > 3)
				continue;
			break;
		case INTEL_NB_5000Z:
			if (i == 1 || i > 5)
				continue;
			break;
		case INTEL_NB_5400:
			break;
		case INTEL_NB_7300:
			if (i > 8)
				continue;
			break;
		}
		EMASK_UNCOR_PEX_WR(i, emask_uncor_pex[i]);
		EMASK_COR_PEX_WR(i, emask_cor_pex[i]);
		EMASK_RP_PEX_WR(i, emask_rp_pex[i]);
		PEX_ERR_DOCMD_WR(i, docmd_pex[i]);

		if (nb5000_reset_uncor_pex)
			EMASK_UNCOR_PEX_WR(i, nb5000_mask_uncor_pex);
		if (nb5000_reset_cor_pex)
			EMASK_COR_PEX_WR(i, nb5000_mask_cor_pex);
	}
}

void
nb_int_init()
{
	uint8_t err0_int;
	uint8_t err1_int;
	uint8_t err2_int;
	uint8_t mcerr_int;
	uint32_t emask_int;
	uint16_t stepping;

	err0_int = ERR0_INT_RD();
	err1_int = ERR1_INT_RD();
	err2_int = ERR2_INT_RD();
	mcerr_int = MCERR_INT_RD();
	emask_int = EMASK_INT_RD();

	nb_err0_int = err0_int;
	nb_err1_int = err1_int;
	nb_err2_int = err2_int;
	nb_mcerr_int = mcerr_int;
	nb_emask_int = emask_int;

	ERR0_INT_WR(0xff);
	ERR1_INT_WR(0xff);
	ERR2_INT_WR(0xff);
	MCERR_INT_WR(0xff);
	EMASK_INT_WR(0xff);

	mcerr_int &= ~nb5000_mask_bios_int;
	mcerr_int |= nb5000_mask_bios_int & (~err0_int | ~err1_int | ~err2_int);
	mcerr_int |= nb5000_mask_poll_int;
	err0_int |= nb5000_mask_poll_int;
	err1_int |= nb5000_mask_poll_int;
	err2_int |= nb5000_mask_poll_int;

	l_mcerr_int = mcerr_int;
	ERR0_INT_WR(err0_int);
	ERR1_INT_WR(err1_int);
	ERR2_INT_WR(err2_int);
	MCERR_INT_WR(mcerr_int);
	if (nb5000_reset_emask_int) {
		if (nb_chipset == INTEL_NB_7300) {
			stepping = NB5000_STEPPING();
			if (stepping == 0)
				EMASK_5000_INT_WR(nb7300_emask_int_step0);
			else
				EMASK_5000_INT_WR(nb7300_emask_int);
		} else if (nb_chipset == INTEL_NB_5400) {
			EMASK_5400_INT_WR(nb5400_emask_int |
			    (emask_int & EMASK_INT_RES));
		} else {
			EMASK_5000_INT_WR(nb5000_emask_int);
		}
	} else {
		EMASK_INT_WR(nb_emask_int);
	}
}

void
nb_int_fini()
{
	ERR0_INT_WR(0xff);
	ERR1_INT_WR(0xff);
	ERR2_INT_WR(0xff);
	MCERR_INT_WR(0xff);
	EMASK_INT_WR(0xff);

	ERR0_INT_WR(nb_err0_int);
	ERR1_INT_WR(nb_err1_int);
	ERR2_INT_WR(nb_err2_int);
	MCERR_INT_WR(nb_mcerr_int);
	EMASK_INT_WR(nb_emask_int);
}

void
nb_int_mask_mc(uint32_t mc_mask_int)
{
	uint32_t emask_int;

	emask_int = MCERR_INT_RD();
	if ((emask_int & mc_mask_int) != mc_mask_int) {
		MCERR_INT_WR(emask_int|mc_mask_int);
		nb_mask_mc_set = 1;
	}
}

void
nb_fbd_init()
{
	uint32_t err0_fbd;
	uint32_t err1_fbd;
	uint32_t err2_fbd;
	uint32_t mcerr_fbd;
	uint32_t emask_fbd;
	uint32_t emask_bios_fbd;
	uint32_t emask_poll_fbd;

	err0_fbd = ERR0_FBD_RD();
	err1_fbd = ERR1_FBD_RD();
	err2_fbd = ERR2_FBD_RD();
	mcerr_fbd = MCERR_FBD_RD();
	emask_fbd = EMASK_FBD_RD();

	nb_err0_fbd = err0_fbd;
	nb_err1_fbd = err1_fbd;
	nb_err2_fbd = err2_fbd;
	nb_mcerr_fbd = mcerr_fbd;
	nb_emask_fbd = emask_fbd;

	ERR0_FBD_WR(0xffffffff);
	ERR1_FBD_WR(0xffffffff);
	ERR2_FBD_WR(0xffffffff);
	MCERR_FBD_WR(0xffffffff);
	EMASK_FBD_WR(0xffffffff);

	if (nb_chipset == INTEL_NB_7300 && nb_mode == NB_MEMORY_MIRROR) {
		/* MCH 7300 errata 34 */
		emask_bios_fbd = nb5000_mask_bios_fbd & ~EMASK_FBD_M23;
		emask_poll_fbd = nb5000_mask_poll_fbd;
		mcerr_fbd |= EMASK_FBD_M23;
	} else if (nb_chipset == INTEL_NB_5400) {
		emask_bios_fbd = nb5400_mask_bios_fbd;
		emask_poll_fbd = nb5400_mask_poll_fbd;
	} else {
		emask_bios_fbd = nb5000_mask_bios_fbd;
		emask_poll_fbd = nb5000_mask_poll_fbd;
	}
	mcerr_fbd &= ~emask_bios_fbd;
	mcerr_fbd |= emask_bios_fbd & (~err0_fbd | ~err1_fbd | ~err2_fbd);
	mcerr_fbd |= emask_poll_fbd;
	err0_fbd |= emask_poll_fbd;
	err1_fbd |= emask_poll_fbd;
	err2_fbd |= emask_poll_fbd;

	l_mcerr_fbd = mcerr_fbd;
	ERR0_FBD_WR(err0_fbd);
	ERR1_FBD_WR(err1_fbd);
	ERR2_FBD_WR(err2_fbd);
	MCERR_FBD_WR(mcerr_fbd);
	if (nb5000_reset_emask_fbd) {
		if (nb_chipset == INTEL_NB_5400)
			EMASK_FBD_WR(nb5400_emask_fbd);
		else
			EMASK_FBD_WR(nb5000_emask_fbd);
	} else {
		EMASK_FBD_WR(nb_emask_fbd);
	}
}

void
nb_fbd_mask_mc(uint32_t mc_mask_fbd)
{
	uint32_t emask_fbd;

	emask_fbd = MCERR_FBD_RD();
	if ((emask_fbd & mc_mask_fbd) != mc_mask_fbd) {
		MCERR_FBD_WR(emask_fbd|mc_mask_fbd);
		nb_mask_mc_set = 1;
	}
}

void
nb_fbd_fini()
{
	ERR0_FBD_WR(0xffffffff);
	ERR1_FBD_WR(0xffffffff);
	ERR2_FBD_WR(0xffffffff);
	MCERR_FBD_WR(0xffffffff);
	EMASK_FBD_WR(0xffffffff);

	ERR0_FBD_WR(nb_err0_fbd);
	ERR1_FBD_WR(nb_err1_fbd);
	ERR2_FBD_WR(nb_err2_fbd);
	MCERR_FBD_WR(nb_mcerr_fbd);
	EMASK_FBD_WR(nb_emask_fbd);
}

static void
nb_fsb_init()
{
	uint16_t err0_fsb;
	uint16_t err1_fsb;
	uint16_t err2_fsb;
	uint16_t mcerr_fsb;
	uint16_t emask_fsb;

	err0_fsb = ERR0_FSB_RD(0);
	err1_fsb = ERR1_FSB_RD(0);
	err2_fsb = ERR2_FSB_RD(0);
	mcerr_fsb = MCERR_FSB_RD(0);
	emask_fsb = EMASK_FSB_RD(0);

	ERR0_FSB_WR(0, 0xffff);
	ERR1_FSB_WR(0, 0xffff);
	ERR2_FSB_WR(0, 0xffff);
	MCERR_FSB_WR(0, 0xffff);
	EMASK_FSB_WR(0, 0xffff);

	ERR0_FSB_WR(1, 0xffff);
	ERR1_FSB_WR(1, 0xffff);
	ERR2_FSB_WR(1, 0xffff);
	MCERR_FSB_WR(1, 0xffff);
	EMASK_FSB_WR(1, 0xffff);

	nb_err0_fsb = err0_fsb;
	nb_err1_fsb = err1_fsb;
	nb_err2_fsb = err2_fsb;
	nb_mcerr_fsb = mcerr_fsb;
	nb_emask_fsb = emask_fsb;

	mcerr_fsb &= ~nb5000_mask_bios_fsb;
	mcerr_fsb |= nb5000_mask_bios_fsb & (~err2_fsb | ~err1_fsb | ~err0_fsb);
	mcerr_fsb |= nb5000_mask_poll_fsb;
	err0_fsb |= nb5000_mask_poll_fsb;
	err1_fsb |= nb5000_mask_poll_fsb;
	err2_fsb |= nb5000_mask_poll_fsb;

	l_mcerr_fsb = mcerr_fsb;
	ERR0_FSB_WR(0, err0_fsb);
	ERR1_FSB_WR(0, err1_fsb);
	ERR2_FSB_WR(0, err2_fsb);
	MCERR_FSB_WR(0, mcerr_fsb);
	if (nb5000_reset_emask_fsb) {
		EMASK_FSB_WR(0, nb5000_emask_fsb);
	} else {
		EMASK_FSB_WR(0, nb_emask_fsb);
	}

	ERR0_FSB_WR(1, err0_fsb);
	ERR1_FSB_WR(1, err1_fsb);
	ERR2_FSB_WR(1, err2_fsb);
	MCERR_FSB_WR(1, mcerr_fsb);
	if (nb5000_reset_emask_fsb) {
		EMASK_FSB_WR(1, nb5000_emask_fsb);
	} else {
		EMASK_FSB_WR(1, nb_emask_fsb);
	}

	if (nb_chipset == INTEL_NB_7300) {
		ERR0_FSB_WR(2, 0xffff);
		ERR1_FSB_WR(2, 0xffff);
		ERR2_FSB_WR(2, 0xffff);
		MCERR_FSB_WR(2, 0xffff);
		EMASK_FSB_WR(2, 0xffff);

		ERR0_FSB_WR(3, 0xffff);
		ERR1_FSB_WR(3, 0xffff);
		ERR2_FSB_WR(3, 0xffff);
		MCERR_FSB_WR(3, 0xffff);
		EMASK_FSB_WR(3, 0xffff);

		ERR0_FSB_WR(2, err0_fsb);
		ERR1_FSB_WR(2, err1_fsb);
		ERR2_FSB_WR(2, err2_fsb);
		MCERR_FSB_WR(2, mcerr_fsb);
		if (nb5000_reset_emask_fsb) {
			EMASK_FSB_WR(2, nb5000_emask_fsb);
		} else {
			EMASK_FSB_WR(2, nb_emask_fsb);
		}

		ERR0_FSB_WR(3, err0_fsb);
		ERR1_FSB_WR(3, err1_fsb);
		ERR2_FSB_WR(3, err2_fsb);
		MCERR_FSB_WR(3, mcerr_fsb);
		if (nb5000_reset_emask_fsb) {
			EMASK_FSB_WR(3, nb5000_emask_fsb);
		} else {
			EMASK_FSB_WR(3, nb_emask_fsb);
		}
	}
}

static void
nb_fsb_fini() {
	ERR0_FSB_WR(0, 0xffff);
	ERR1_FSB_WR(0, 0xffff);
	ERR2_FSB_WR(0, 0xffff);
	MCERR_FSB_WR(0, 0xffff);
	EMASK_FSB_WR(0, 0xffff);

	ERR0_FSB_WR(0, nb_err0_fsb);
	ERR1_FSB_WR(0, nb_err1_fsb);
	ERR2_FSB_WR(0, nb_err2_fsb);
	MCERR_FSB_WR(0, nb_mcerr_fsb);
	EMASK_FSB_WR(0, nb_emask_fsb);

	ERR0_FSB_WR(1, 0xffff);
	ERR1_FSB_WR(1, 0xffff);
	ERR2_FSB_WR(1, 0xffff);
	MCERR_FSB_WR(1, 0xffff);
	EMASK_FSB_WR(1, 0xffff);

	ERR0_FSB_WR(1, nb_err0_fsb);
	ERR1_FSB_WR(1, nb_err1_fsb);
	ERR2_FSB_WR(1, nb_err2_fsb);
	MCERR_FSB_WR(1, nb_mcerr_fsb);
	EMASK_FSB_WR(1, nb_emask_fsb);

	if (nb_chipset == INTEL_NB_7300) {
		ERR0_FSB_WR(2, 0xffff);
		ERR1_FSB_WR(2, 0xffff);
		ERR2_FSB_WR(2, 0xffff);
		MCERR_FSB_WR(2, 0xffff);
		EMASK_FSB_WR(2, 0xffff);

		ERR0_FSB_WR(2, nb_err0_fsb);
		ERR1_FSB_WR(2, nb_err1_fsb);
		ERR2_FSB_WR(2, nb_err2_fsb);
		MCERR_FSB_WR(2, nb_mcerr_fsb);
		EMASK_FSB_WR(2, nb_emask_fsb);

		ERR0_FSB_WR(3, 0xffff);
		ERR1_FSB_WR(3, 0xffff);
		ERR2_FSB_WR(3, 0xffff);
		MCERR_FSB_WR(3, 0xffff);
		EMASK_FSB_WR(3, 0xffff);

		ERR0_FSB_WR(3, nb_err0_fsb);
		ERR1_FSB_WR(3, nb_err1_fsb);
		ERR2_FSB_WR(3, nb_err2_fsb);
		MCERR_FSB_WR(3, nb_mcerr_fsb);
		EMASK_FSB_WR(3, nb_emask_fsb);
	}
}

void
nb_fsb_mask_mc(int fsb, uint16_t mc_mask_fsb)
{
	uint16_t emask_fsb;

	emask_fsb = MCERR_FSB_RD(fsb);
	if ((emask_fsb & mc_mask_fsb) != mc_mask_fsb) {
		MCERR_FSB_WR(fsb, emask_fsb|mc_mask_fsb|EMASK_FBD_RES);
		nb_mask_mc_set = 1;
	}
}

static void
nb_thr_init()
{
	uint16_t err0_thr;
	uint16_t err1_thr;
	uint16_t err2_thr;
	uint16_t mcerr_thr;
	uint16_t emask_thr;

	if (nb_chipset == INTEL_NB_5400) {
		err0_thr = ERR0_THR_RD(0);
		err1_thr = ERR1_THR_RD(0);
		err2_thr = ERR2_THR_RD(0);
		mcerr_thr = MCERR_THR_RD(0);
		emask_thr = EMASK_THR_RD(0);

		ERR0_THR_WR(0xffff);
		ERR1_THR_WR(0xffff);
		ERR2_THR_WR(0xffff);
		MCERR_THR_WR(0xffff);
		EMASK_THR_WR(0xffff);

		nb_err0_thr = err0_thr;
		nb_err1_thr = err1_thr;
		nb_err2_thr = err2_thr;
		nb_mcerr_thr = mcerr_thr;
		nb_emask_thr = emask_thr;

		mcerr_thr &= ~nb_mask_bios_thr;
		mcerr_thr |= nb_mask_bios_thr &
		    (~err2_thr | ~err1_thr | ~err0_thr);
		mcerr_thr |= nb_mask_poll_thr;
		err0_thr |= nb_mask_poll_thr;
		err1_thr |= nb_mask_poll_thr;
		err2_thr |= nb_mask_poll_thr;

		l_mcerr_thr = mcerr_thr;
		ERR0_THR_WR(err0_thr);
		ERR1_THR_WR(err1_thr);
		ERR2_THR_WR(err2_thr);
		MCERR_THR_WR(mcerr_thr);
		EMASK_THR_WR(nb_emask_thr);
	}
}

static void
nb_thr_fini()
{
	if (nb_chipset == INTEL_NB_5400) {
		ERR0_THR_WR(0xffff);
		ERR1_THR_WR(0xffff);
		ERR2_THR_WR(0xffff);
		MCERR_THR_WR(0xffff);
		EMASK_THR_WR(0xffff);

		ERR0_THR_WR(nb_err0_thr);
		ERR1_THR_WR(nb_err1_thr);
		ERR2_THR_WR(nb_err2_thr);
		MCERR_THR_WR(nb_mcerr_thr);
		EMASK_THR_WR(nb_emask_thr);
	}
}

void
nb_thr_mask_mc(uint16_t mc_mask_thr)
{
	uint16_t emask_thr;

	emask_thr = MCERR_THR_RD(0);
	if ((emask_thr & mc_mask_thr) != mc_mask_thr) {
		MCERR_THR_WR(emask_thr|mc_mask_thr);
		nb_mask_mc_set = 1;
	}
}

void
nb_mask_mc_reset()
{
	MCERR_FBD_WR(l_mcerr_fbd);
	MCERR_INT_WR(l_mcerr_int);
	MCERR_FSB_WR(0, l_mcerr_fsb);
	MCERR_FSB_WR(1, l_mcerr_fsb);
	if (nb_chipset == INTEL_NB_7300) {
		MCERR_FSB_WR(2, l_mcerr_fsb);
		MCERR_FSB_WR(3, l_mcerr_fsb);
	}
	if (nb_chipset == INTEL_NB_5400) {
		MCERR_THR_WR(l_mcerr_thr);
	}
}

int
nb_dev_init()
{
	find_dimm_label_t *label_function_p;

	label_function_p = find_dimms_per_channel();
	mutex_init(&nb_mutex, NULL, MUTEX_DRIVER, NULL);
	nb_queue = errorq_create("nb_queue", nb_drain, NULL, NB_MAX_ERRORS,
	    sizeof (nb_logout_t), 1, ERRORQ_VITAL);
	if (nb_queue == NULL) {
		mutex_destroy(&nb_mutex);
		return (EAGAIN);
	}
	nb_int_init();
	nb_thr_init();
	dimm_init();
	nb_dimms_init(label_function_p);
	nb_mc_init();
	nb_pex_init();
	nb_fbd_init();
	nb_fsb_init();
	nb_scrubber_enable();
	return (0);
}

int
nb_init()
{
	/* return ENOTSUP if there is no PCI config space support. */
	if (pci_getl_func == NULL)
		return (ENOTSUP);

	/* get vendor and device */
	nb_chipset = (*pci_getl_func)(0, 0, 0, PCI_CONF_VENID);
	switch (nb_chipset) {
	default:
		if (nb_5000_memory_controller == 0)
			return (ENOTSUP);
		break;
	case INTEL_NB_7300:
	case INTEL_NB_5000P:
	case INTEL_NB_5000X:
		break;
	case INTEL_NB_5000V:
	case INTEL_NB_5000Z:
		nb_number_memory_controllers = 1;
		break;
	case INTEL_NB_5400:
	case INTEL_NB_5400A:
	case INTEL_NB_5400B:
		nb_chipset = INTEL_NB_5400;
		break;
	}
	return (0);
}

void
nb_dev_reinit()
{
	int i, j;
	int nchannels = nb_number_memory_controllers * 2;
	nb_dimm_t **dimmpp;
	nb_dimm_t *dimmp;
	nb_dimm_t **old_nb_dimms;
	int old_nb_dimms_per_channel;
	find_dimm_label_t *label_function_p;

	old_nb_dimms = nb_dimms;
	old_nb_dimms_per_channel = nb_dimms_per_channel;

	dimm_fini();
	label_function_p = find_dimms_per_channel();
	dimm_init();
	nb_dimms_init(label_function_p);
	nb_mc_init();
	nb_pex_init();
	nb_int_init();
	nb_thr_init();
	nb_fbd_init();
	nb_fsb_init();
	nb_scrubber_enable();

	dimmpp = old_nb_dimms;
	for (i = 0; i < nchannels; i++) {
		for (j = 0; j < old_nb_dimms_per_channel; j++) {
			dimmp = *dimmpp;
			if (dimmp) {
				kmem_free(dimmp, sizeof (nb_dimm_t));
				*dimmpp = NULL;
			}
			dimmp++;
		}
	}
	kmem_free(old_nb_dimms, sizeof (nb_dimm_t *) *
	    nb_number_memory_controllers * 2 * old_nb_dimms_per_channel);
}

void
nb_dev_unload()
{
	errorq_destroy(nb_queue);
	nb_queue = NULL;
	mutex_destroy(&nb_mutex);
	nb_int_fini();
	nb_thr_fini();
	nb_fbd_fini();
	nb_fsb_fini();
	nb_pex_fini();
	nb_fini();
}

void
nb_unload()
{
}
