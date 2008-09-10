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
#include "nb5000.h"
#include "nb_log.h"
#include "dimm_phys.h"

static uint32_t uerrcnt[2];
static uint32_t cerrcnta[2][2];
static uint32_t cerrcntb[2][2];
static uint32_t cerrcntc[2][2];
static uint32_t cerrcntd[2][2];
static nb_logout_t nb_log;

struct mch_error_code {
	int intel_error_list;	/* error number in Chipset Error List */
	uint32_t emask;		/* mask for machine check */
	uint32_t error_bit;	/* error bit in fault register */
};

static struct mch_error_code fat_fbd_error_code[] = {
	{ 23, EMASK_FBD_M23, ERR_FAT_FBD_M23 },
	{ 3, EMASK_FBD_M3, ERR_FAT_FBD_M3 },
	{ 2, EMASK_FBD_M2, ERR_FAT_FBD_M2 },
	{ 1, EMASK_FBD_M1, ERR_FAT_FBD_M1 }
};

static int
intel_fat_fbd_err(uint32_t fat_fbd)
{
	int rt = -1;
	int nerr = 0;
	uint32_t emask_fbd = 0;
	int i;
	int sz;

	sz = sizeof (fat_fbd_error_code) / sizeof (struct mch_error_code);

	for (i = 0; i < sz; i++) {
		if (fat_fbd & fat_fbd_error_code[i].error_bit) {
			rt = fat_fbd_error_code[i].intel_error_list;
			emask_fbd |= fat_fbd_error_code[i].emask;
			nerr++;
		}
	}

	if (emask_fbd)
		nb_fbd_mask_mc(emask_fbd);
	if (nerr > 1)
		rt = -1;
	return (rt);
}

static char *
fat_memory_error(const nb_regs_t *rp, void *data)
{
	int channel;
	uint32_t ferr_fat_fbd, nrecmemb;
	uint32_t nrecmema;
	char *intr = "nb.unknown";
	nb_mem_scatchpad_t *sp = &((nb_scatchpad_t *)data)->ms;

	ferr_fat_fbd = rp->nb.fat_fbd_regs.ferr_fat_fbd;
	if ((ferr_fat_fbd & ERR_FAT_FBD_MASK) == 0) {
		sp->intel_error_list =
		    intel_fat_fbd_err(rp->nb.fat_fbd_regs.nerr_fat_fbd);
		sp->branch = -1;
		sp->channel = -1;
		sp->rank = -1;
		sp->dimm = -1;
		sp->bank = -1;
		sp->cas = -1;
		sp->ras = -1;
		sp->pa = -1LL;
		sp->offset = -1;
		return (intr);
	}
	sp->intel_error_list = intel_fat_fbd_err(ferr_fat_fbd);
	channel = (ferr_fat_fbd >> 28) & 3;
	sp->branch = channel >> 1;
	sp->channel = channel;
	if ((ferr_fat_fbd & (ERR_FAT_FBD_M2|ERR_FAT_FBD_M1)) != 0) {
		if ((ferr_fat_fbd & ERR_FAT_FBD_M1) != 0)
			intr = "nb.fbd.alert";	/* Alert on FB-DIMM M1 */
		else
			intr = "nb.fbd.crc";	/* CRC error FB_DIMM M2 */
		nrecmema = rp->nb.fat_fbd_regs.nrecmema;
		nrecmemb = rp->nb.fat_fbd_regs.nrecmemb;
		sp->rank = (nrecmema >> 8) & RANK_MASK;
		sp->dimm = sp->rank >> 1;
		sp->bank = (nrecmema >> 12) & BANK_MASK;
		sp->cas = (nrecmemb >> 16) & CAS_MASK;
		sp->ras = nrecmemb & RAS_MASK;
		sp->pa = dimm_getphys(sp->branch, sp->rank, sp->bank, sp->ras,
		    sp->cas);
		sp->offset = dimm_getoffset(sp->branch, sp->rank, sp->bank,
		    sp->ras, sp->cas);
	} else {
		if ((ferr_fat_fbd & ERR_FAT_FBD_M3) != 0)
			intr = "nb.fbd.otf";	/* thermal temp > Tmid M3 */
		else if ((ferr_fat_fbd & ERR_FAT_FBD_M23) != 0) {
			intr = "nb.fbd.reset_timeout";
			sp->channel = -1;
		}
		sp->rank = -1;
		sp->dimm = -1;
		sp->bank = -1;
		sp->cas = -1;
		sp->ras = -1;
		sp->pa = -1LL;
		sp->offset = -1;
	}
	return (intr);
}


static struct mch_error_code nf_fbd_error_code[] = {
	{ 29, EMASK_FBD_M29, ERR_NF_FBD_M29 },
	{ 28, EMASK_FBD_M28, ERR_NF_FBD_M28 },
	{ 27, EMASK_FBD_M27, ERR_NF_FBD_M27 },
	{ 26, EMASK_FBD_M26, ERR_NF_FBD_M26 },
	{ 25, EMASK_FBD_M25, ERR_NF_FBD_M25 },
	{ 24, EMASK_FBD_M24, ERR_NF_FBD_M24 },
	{ 22, EMASK_FBD_M22, ERR_NF_FBD_M22 },
	{ 21, EMASK_FBD_M21, ERR_NF_FBD_M21 },
	{ 20, EMASK_FBD_M20, ERR_NF_FBD_M20 },
	{ 19, EMASK_FBD_M19, ERR_NF_FBD_M19 },
	{ 18, EMASK_FBD_M18, ERR_NF_FBD_M18 },
	{ 17, EMASK_FBD_M17, ERR_NF_FBD_M17 },
	{ 16, EMASK_FBD_M16, ERR_NF_FBD_M16 },
	{ 15, EMASK_FBD_M15, ERR_NF_FBD_M15 },
	{ 14, EMASK_FBD_M14, ERR_NF_FBD_M14 },
	{ 13, EMASK_FBD_M13, ERR_NF_FBD_M13 },
	{ 12, EMASK_FBD_M12, ERR_NF_FBD_M12 },
	{ 11, EMASK_FBD_M11, ERR_NF_FBD_M11 },
	{ 10, EMASK_FBD_M10, ERR_NF_FBD_M10 },
	{ 9, EMASK_FBD_M9, ERR_NF_FBD_M9 },
	{ 8, EMASK_FBD_M8, ERR_NF_FBD_M8 },
	{ 7, EMASK_FBD_M7, ERR_NF_FBD_M7 },
	{ 6, EMASK_FBD_M6, ERR_NF_FBD_M6 },
	{ 5, EMASK_FBD_M5, ERR_NF_FBD_M5 },
	{ 4, EMASK_FBD_M4, ERR_NF_FBD_M4 }
};

static int
intel_nf_fbd_err(uint32_t nf_fbd)
{
	int rt = -1;
	int nerr = 0;
	uint32_t emask_fbd = 0;
	int i;
	int sz;

	sz = sizeof (nf_fbd_error_code) / sizeof (struct mch_error_code);

	for (i = 0; i < sz; i++) {
		if (nf_fbd & nf_fbd_error_code[i].error_bit) {
			rt = nf_fbd_error_code[i].intel_error_list;
			emask_fbd |= nf_fbd_error_code[i].emask;
			nerr++;
		}
	}
	if (emask_fbd)
		nb_fbd_mask_mc(emask_fbd);
	if (nerr > 1)
		rt = -1;
	return (rt);
}

static char *
nf_memory_error(const nb_regs_t *rp, void *data)
{
	uint32_t ferr_nf_fbd, recmemb, redmemb;
	uint32_t recmema;
	int branch, channel, ecc_locator;
	char *intr = "nb.unknown";
	nb_mem_scatchpad_t *sp = &((nb_scatchpad_t *)data)->ms;

	sp->rank = -1;
	sp->dimm = -1;
	sp->bank = -1;
	sp->cas = -1;
	sp->ras = -1LL;
	sp->pa = -1LL;
	sp->offset = -1;
	ferr_nf_fbd = rp->nb.nf_fbd_regs.ferr_nf_fbd;
	if ((ferr_nf_fbd & ERR_NF_FBD_MASK) == 0) {
		sp->branch = -1;
		sp->channel = -1;
		sp->intel_error_list =
		    intel_nf_fbd_err(rp->nb.nf_fbd_regs.nerr_nf_fbd);
		return (intr);
	}
	sp->intel_error_list = intel_nf_fbd_err(ferr_nf_fbd);
	channel = (ferr_nf_fbd >> ERR_FBD_CH_SHIFT) & 3;
	branch = channel >> 1;
	sp->branch = branch;
	sp->channel = channel;
	if (ferr_nf_fbd & ERR_NF_FBD_MASK) {
		if (ferr_nf_fbd & ERR_NF_FBD_ECC_UE) {
			/*
			 * uncorrectable ECC M4 - M12
			 * we can only isolate to pair of dimms
			 * for single dimm configuration let eversholt
			 * sort it out with out needing a special rule
			 */
			sp->channel = -1;
			recmema = rp->nb.nf_fbd_regs.recmema;
			recmemb = rp->nb.nf_fbd_regs.recmemb;
			sp->rank = (recmema >> 8) & RANK_MASK;
			sp->bank = (recmema >> 12) & BANK_MASK;
			sp->cas = (recmemb >> 16) & CAS_MASK;
			sp->ras = recmemb & RAS_MASK;
			intr = "nb.mem_ue";
		} else if (ferr_nf_fbd & ERR_NF_FBD_M13) {
			/*
			 * write error M13
			 * we can only isolate to pair of dimms
			 */
			sp->channel = -1;
			if (nb_mode != NB_MEMORY_MIRROR) {
				recmema = rp->nb.nf_fbd_regs.recmema;
				sp->rank = (recmema >> 8) & RANK_MASK;
				sp->bank = (recmema >> 12) & BANK_MASK;
				sp->cas = (recmemb >> 16) & CAS_MASK;
				sp->ras = recmemb & RAS_MASK;
			}
			intr = "nb.fbd.ma"; /* memory alert */
		} else if (ferr_nf_fbd & ERR_NF_FBD_MA) { /* M14, M15 and M21 */
			intr = "nb.fbd.ch"; /* FBD on channel */
		} else if ((ferr_nf_fbd & ERR_NF_FBD_ECC_CE) != 0) {
			/* correctable ECC M17-M20 */
			recmema = rp->nb.nf_fbd_regs.recmema;
			recmemb = rp->nb.nf_fbd_regs.recmemb;
			sp->rank = (recmema >> 8) & RANK_MASK;
			redmemb = rp->nb.nf_fbd_regs.redmemb;
			ecc_locator = redmemb & 0x3ffff;
			if (ecc_locator & 0x1ff)
				sp->channel = branch << 1;
			else if (ecc_locator & 0x3fe00)
				sp->channel = (branch << 1) + 1;
			sp->dimm = sp->rank >> 1;
			sp->bank = (recmema >> 12) & BANK_MASK;
			sp->cas = (recmemb >> 16) & CAS_MASK;
			sp->ras = recmemb & RAS_MASK;
			intr = "nb.mem_ce";
		} else if ((ferr_nf_fbd & ERR_NF_FBD_SPARE) != 0) {
			/* spare dimm M27, M28 */
			intr = "nb.mem_ds";
			sp->channel = -1;
			if (rp->nb.nf_fbd_regs.spcps & SPCPS_SPARE_DEPLOYED) {
				sp->rank =
				    SPCPS_FAILED_RANK(rp->nb.nf_fbd_regs.spcps);
				nb_used_spare_rank(sp->branch, sp->rank);
				nb_config_gen++;
			}
		} else if ((ferr_nf_fbd & ERR_NF_FBD_M22) != 0) {
			intr = "nb.spd";	/* SPD protocol */
		}
	}
	if (sp->ras != -1) {
		sp->pa = dimm_getphys(sp->branch, sp->rank, sp->bank, sp->ras,
		    sp->cas);
		sp->offset = dimm_getoffset(sp->branch, sp->rank, sp->bank,
		    sp->ras, sp->cas);
	}
	return (intr);
}

static struct mch_error_code fat_int_error_code[] = {
	{ 14, EMASK_INT_B14, ERR_FAT_INT_B14 },
	{ 12, EMASK_INT_B12, ERR_FAT_INT_B12 },
	{ 25, EMASK_INT_B25, ERR_FAT_INT_B25 },
	{ 23, EMASK_INT_B23, ERR_FAT_INT_B23 },
	{ 21, EMASK_INT_B21, ERR_FAT_INT_B21 },
	{ 7, EMASK_INT_B7, ERR_FAT_INT_B7 },
	{ 4, EMASK_INT_B4, ERR_FAT_INT_B4 },
	{ 3, EMASK_INT_B3, ERR_FAT_INT_B3 },
	{ 2, EMASK_INT_B2, ERR_FAT_INT_B2 },
	{ 1, EMASK_INT_B1, ERR_FAT_INT_B1 }
};

static struct mch_error_code nf_int_error_code[] = {
	{ 27, 0, ERR_NF_INT_B27 },
	{ 24, 0, ERR_NF_INT_B24 },
	{ 22, EMASK_INT_B22, ERR_NF_INT_B22 },
	{ 20, EMASK_INT_B20, ERR_NF_INT_B20 },
	{ 19, EMASK_INT_B19, ERR_NF_INT_B19 },
	{ 18, 0, ERR_NF_INT_B18 },
	{ 17, 0, ERR_NF_INT_B17 },
	{ 16, 0, ERR_NF_INT_B16 },
	{ 11, EMASK_INT_B11, ERR_NF_INT_B11 },
	{ 10, EMASK_INT_B10, ERR_NF_INT_B10 },
	{ 9, EMASK_INT_B9, ERR_NF_INT_B9 },
	{ 8, EMASK_INT_B8, ERR_NF_INT_B8 },
	{ 6, EMASK_INT_B6, ERR_NF_INT_B6 },
	{ 5, EMASK_INT_B5, ERR_NF_INT_B5 }
};

static int
intel_int_err(uint16_t err_fat_int, uint16_t err_nf_int)
{
	int rt = -1;
	int nerr = 0;
	uint32_t emask_int = 0;
	int i;
	int sz;

	sz = sizeof (fat_int_error_code) / sizeof (struct mch_error_code);

	for (i = 0; i < sz; i++) {
		if (err_fat_int & fat_int_error_code[i].error_bit) {
			rt = fat_int_error_code[i].intel_error_list;
			emask_int |= fat_int_error_code[i].emask;
			nerr++;
		}
	}

	if (nb_chipset == INTEL_NB_5400 &&
	    (err_nf_int & NERR_NF_5400_INT_B26) != 0) {
		err_nf_int &= ~NERR_NF_5400_INT_B26;
		rt = 26;
		nerr++;
	}

	sz = sizeof (nf_int_error_code) / sizeof (struct mch_error_code);

	for (i = 0; i < sz; i++) {
		if (err_nf_int & nf_int_error_code[i].error_bit) {
			rt = nf_int_error_code[i].intel_error_list;
			emask_int |= nf_int_error_code[i].emask;
			nerr++;
		}
	}

	if (emask_int)
		nb_int_mask_mc(emask_int);
	if (nerr > 1)
		rt = -1;
	return (rt);
}

static void
log_int_err(nb_regs_t *rp, int *interpose)
{
	int t = 0;

	rp->flag = NB_REG_LOG_INT;
	rp->nb.int_regs.ferr_fat_int = FERR_FAT_INT_RD(interpose);
	rp->nb.int_regs.ferr_nf_int = FERR_NF_INT_RD(&t);
	*interpose |= t;
	rp->nb.int_regs.nerr_fat_int = NERR_FAT_INT_RD(&t);
	*interpose |= t;
	rp->nb.int_regs.nerr_nf_int = NERR_NF_INT_RD(&t);
	*interpose |= t;
	rp->nb.int_regs.nrecint = NRECINT_RD();
	rp->nb.int_regs.recint = RECINT_RD();
	rp->nb.int_regs.nrecsf = NRECSF_RD();
	rp->nb.int_regs.recsf = RECSF_RD();

	if (rp->nb.int_regs.ferr_fat_int || *interpose)
		FERR_FAT_INT_WR(rp->nb.int_regs.ferr_fat_int);
	if (rp->nb.int_regs.ferr_nf_int || *interpose)
		FERR_NF_INT_WR(rp->nb.int_regs.ferr_nf_int);
	if (rp->nb.int_regs.nerr_fat_int)
		NERR_FAT_INT_WR(rp->nb.int_regs.nerr_fat_int);
	if (rp->nb.int_regs.nerr_nf_int)
		NERR_NF_INT_WR(rp->nb.int_regs.nerr_nf_int);
	/* if interpose write read-only registers to clear from pcii cache */
	if (*interpose) {
		NRECINT_WR();
		RECINT_WR();
		NRECSF_WR();
		RECSF_WR();
	}
}

static void
log_thermal_err(nb_regs_t *rp, int *interpose)
{
	int t = 0;

	rp->flag = NB_REG_LOG_THR;
	rp->nb.thr_regs.ferr_fat_thr = FERR_FAT_THR_RD(interpose);
	rp->nb.thr_regs.nerr_fat_thr = NERR_FAT_THR_RD(&t);
	*interpose |= t;
	rp->nb.thr_regs.ferr_nf_thr = FERR_NF_THR_RD(&t);
	*interpose |= t;
	rp->nb.thr_regs.nerr_nf_thr = NERR_NF_THR_RD(&t);
	*interpose |= t;
	rp->nb.thr_regs.ctsts = CTSTS_RD();
	rp->nb.thr_regs.thrtsts = THRTSTS_RD();

	if (rp->nb.thr_regs.ferr_fat_thr || *interpose)
		FERR_FAT_THR_WR(rp->nb.thr_regs.ferr_fat_thr);
	if (rp->nb.thr_regs.nerr_fat_thr || *interpose)
		NERR_FAT_THR_WR(rp->nb.thr_regs.nerr_fat_thr);
	if (rp->nb.thr_regs.ferr_nf_thr || *interpose)
		FERR_NF_THR_WR(rp->nb.thr_regs.ferr_nf_thr);
	if (rp->nb.thr_regs.nerr_nf_thr || *interpose)
		NERR_NF_THR_WR(rp->nb.thr_regs.nerr_nf_thr);

	if (*interpose) {
		CTSTS_WR(rp->nb.thr_regs.ctsts);
		THRTSTS_WR(rp->nb.thr_regs.thrtsts);
	}
}

static void
log_dma_err(nb_regs_t *rp, int *interpose)
{
	rp->flag = NB_REG_LOG_DMA;

	rp->nb.dma_regs.pcists = PCISTS_RD(interpose);
	rp->nb.dma_regs.pexdevsts = PCIDEVSTS_RD();
}

static struct mch_error_code fat_fsb_error_code[] = {
	{ 9, EMASK_FSB_F9, ERR_FAT_FSB_F9 },
	{ 2, EMASK_FSB_F2, ERR_FAT_FSB_F2 },
	{ 1, EMASK_FSB_F1, ERR_FAT_FSB_F1 }
};

static struct mch_error_code nf_fsb_error_code[] = {
	{ 8, EMASK_FSB_F8, ERR_NF_FSB_F8 },
	{ 7, EMASK_FSB_F7, ERR_NF_FSB_F7 },
	{ 6, EMASK_FSB_F6, ERR_NF_FSB_F6 }
};

static int
intel_fsb_err(int fsb, uint8_t err_fat_fsb, uint8_t err_nf_fsb)
{
	int rt = -1;
	int nerr = 0;
	uint16_t emask_fsb = 0;
	int i;
	int sz;

	sz = sizeof (fat_fsb_error_code) / sizeof (struct mch_error_code);

	for (i = 0; i < sz; i++) {
		if (err_fat_fsb & fat_fsb_error_code[i].error_bit) {
			rt = fat_fsb_error_code[i].intel_error_list;
			emask_fsb |= fat_fsb_error_code[i].emask;
			nerr++;
		}
	}

	sz = sizeof (nf_fsb_error_code) / sizeof (struct mch_error_code);

	for (i = 0; i < sz; i++) {
		if (err_nf_fsb & nf_fsb_error_code[i].error_bit) {
			rt = nf_fsb_error_code[i].intel_error_list;
			emask_fsb |= nf_fsb_error_code[i].emask;
			nerr++;
		}
	}

	if (emask_fsb)
		nb_fsb_mask_mc(fsb, emask_fsb);
	if (nerr > 1)
		rt = -1;
	return (rt);
}

static void
log_fsb_err(uint64_t ferr, nb_regs_t *rp, int *interpose)
{
	uint8_t fsb;
	int t = 0;

	fsb = GE_FERR_FSB(ferr);
	rp->flag = NB_REG_LOG_FSB;

	rp->nb.fsb_regs.fsb = fsb;
	rp->nb.fsb_regs.ferr_fat_fsb = FERR_FAT_FSB_RD(fsb, interpose);
	rp->nb.fsb_regs.ferr_nf_fsb = FERR_NF_FSB_RD(fsb, &t);
	*interpose |= t;
	rp->nb.fsb_regs.nerr_fat_fsb = NERR_FAT_FSB_RD(fsb, &t);
	*interpose |= t;
	rp->nb.fsb_regs.nerr_nf_fsb = NERR_NF_FSB_RD(fsb, &t);
	*interpose |= t;
	rp->nb.fsb_regs.nrecfsb = NRECFSB_RD(fsb);
	rp->nb.fsb_regs.nrecfsb_addr = NRECADDR_RD(fsb);
	rp->nb.fsb_regs.recfsb = RECFSB_RD(fsb);
	if (rp->nb.fsb_regs.ferr_fat_fsb || *interpose)
		FERR_FAT_FSB_WR(fsb, rp->nb.fsb_regs.ferr_fat_fsb);
	if (rp->nb.fsb_regs.ferr_nf_fsb || *interpose)
		FERR_NF_FSB_WR(fsb, rp->nb.fsb_regs.ferr_nf_fsb);
	/* if interpose write read-only registers to clear from pcii cache */
	if (*interpose) {
		NRECFSB_WR(fsb);
		NRECADDR_WR(fsb);
		RECFSB_WR(fsb);
	}
}

static struct mch_error_code fat_pex_error_code[] = {
	{ 19, EMASK_UNCOR_PEX_IO19, PEX_FAT_IO19 },
	{ 18, EMASK_UNCOR_PEX_IO18, PEX_FAT_IO18 },
	{ 10, EMASK_UNCOR_PEX_IO10, PEX_FAT_IO10 },
	{ 9, EMASK_UNCOR_PEX_IO9, PEX_FAT_IO9 },
	{ 8, EMASK_UNCOR_PEX_IO8, PEX_FAT_IO8 },
	{ 7, EMASK_UNCOR_PEX_IO7, PEX_FAT_IO7 },
	{ 6, EMASK_UNCOR_PEX_IO6, PEX_FAT_IO6 },
	{ 5, EMASK_UNCOR_PEX_IO5, PEX_FAT_IO5 },
	{ 4, EMASK_UNCOR_PEX_IO4, PEX_FAT_IO4 },
	{ 3, EMASK_UNCOR_PEX_IO3, PEX_FAT_IO3 },
	{ 2, EMASK_UNCOR_PEX_IO2, PEX_FAT_IO2 },
	{ 0, EMASK_UNCOR_PEX_IO0, PEX_FAT_IO0 }
};

static struct mch_error_code fat_unit_pex_5400_error_code[] = {
	{ 32, EMASK_UNIT_PEX_IO32, PEX_5400_FAT_IO32 },
	{ 31, EMASK_UNIT_PEX_IO31, PEX_5400_FAT_IO31 },
	{ 30, EMASK_UNIT_PEX_IO30, PEX_5400_FAT_IO30 },
	{ 29, EMASK_UNIT_PEX_IO29, PEX_5400_FAT_IO29 },
	{ 27, EMASK_UNIT_PEX_IO27, PEX_5400_FAT_IO27 },
	{ 26, EMASK_UNIT_PEX_IO26, PEX_5400_FAT_IO26 },
	{ 25, EMASK_UNIT_PEX_IO25, PEX_5400_FAT_IO25 },
	{ 24, EMASK_UNIT_PEX_IO24, PEX_5400_FAT_IO24 },
	{ 23, EMASK_UNIT_PEX_IO23, PEX_5400_FAT_IO23 },
	{ 22, EMASK_UNIT_PEX_IO22, PEX_5400_FAT_IO22 },
};

static struct mch_error_code fat_pex_5400_error_code[] = {
	{ 19, EMASK_UNCOR_PEX_IO19, PEX_5400_FAT_IO19 },
	{ 18, EMASK_UNCOR_PEX_IO18, PEX_5400_FAT_IO18 },
	{ 10, EMASK_UNCOR_PEX_IO10, PEX_5400_FAT_IO10 },
	{ 9, EMASK_UNCOR_PEX_IO9, PEX_5400_FAT_IO9 },
	{ 8, EMASK_UNCOR_PEX_IO8, PEX_5400_FAT_IO8 },
	{ 7, EMASK_UNCOR_PEX_IO7, PEX_5400_FAT_IO7 },
	{ 6, EMASK_UNCOR_PEX_IO6, PEX_5400_FAT_IO6 },
	{ 5, EMASK_UNCOR_PEX_IO5, PEX_5400_FAT_IO5 },
	{ 4, EMASK_UNCOR_PEX_IO4, PEX_5400_FAT_IO4 },
	{ 2, EMASK_UNCOR_PEX_IO2, PEX_5400_FAT_IO2 },
	{ 0, EMASK_UNCOR_PEX_IO0, PEX_5400_FAT_IO0 }
};

static struct mch_error_code fat_rp_5400_error_code[] = {
	{ 1, EMASK_RP_PEX_IO1, PEX_5400_FAT_IO1 }
};

static struct mch_error_code fat_rp_error_code[] = {
	{ 1, EMASK_RP_PEX_IO1, PEX_FAT_IO1 }
};

static struct mch_error_code uncor_pex_error_code[] = {
	{ 19, EMASK_UNCOR_PEX_IO19, PEX_NF_IO19 },
	{ 9, EMASK_UNCOR_PEX_IO9, PEX_NF_IO9 },
	{ 8, EMASK_UNCOR_PEX_IO8, PEX_NF_IO8 },
	{ 7, EMASK_UNCOR_PEX_IO7, PEX_NF_IO7 },
	{ 6, EMASK_UNCOR_PEX_IO6, PEX_NF_IO6 },
	{ 5, EMASK_UNCOR_PEX_IO5, PEX_NF_IO5 },
	{ 4, EMASK_UNCOR_PEX_IO4, PEX_NF_IO4 },
	{ 3, EMASK_UNCOR_PEX_IO3, PEX_NF_IO3 },
	{ 0, EMASK_UNCOR_PEX_IO0, PEX_NF_IO0 }
};

static struct mch_error_code uncor_pex_5400_error_code[] = {
	{ 33, EMASK_UNIT_PEX_IO33, PEX_5400_NF_IO33 },
	{ 32, EMASK_UNIT_PEX_IO32, PEX_5400_NF_IO32 },
	{ 31, EMASK_UNIT_PEX_IO31, PEX_5400_NF_IO31 },
	{ 30, EMASK_UNIT_PEX_IO30, PEX_5400_NF_IO30 },
	{ 29, EMASK_UNIT_PEX_IO29, PEX_5400_NF_IO29 },
	{ 28, EMASK_UNIT_PEX_IO28, PEX_5400_NF_IO28 },
	{ 27, EMASK_UNIT_PEX_IO27, PEX_5400_NF_IO27 },
	{ 26, EMASK_UNIT_PEX_IO26, PEX_5400_NF_IO26 },
	{ 25, EMASK_UNIT_PEX_IO25, PEX_5400_NF_IO25 },
	{ 24, EMASK_UNIT_PEX_IO24, PEX_5400_NF_IO24 },
	{ 23, EMASK_UNIT_PEX_IO23, PEX_5400_NF_IO23 },
};

static struct mch_error_code cor_pex_error_code[] = {
	{ 20, EMASK_COR_PEX_IO20, PEX_5400_NF_IO20 },
	{ 16, EMASK_COR_PEX_IO16, PEX_NF_IO16 },
	{ 15, EMASK_COR_PEX_IO15, PEX_NF_IO15 },
	{ 14, EMASK_COR_PEX_IO14, PEX_NF_IO14 },
	{ 13, EMASK_COR_PEX_IO13, PEX_NF_IO13 },
	{ 12, EMASK_COR_PEX_IO12, PEX_NF_IO12 },
	{ 10, 0, PEX_NF_IO10 },
	{ 2, 0, PEX_NF_IO2 }
};

static struct mch_error_code rp_pex_5400_error_code[] = {
	{ 17, EMASK_RP_PEX_IO17, PEX_5400_NF_IO17 },
	{ 11, EMASK_RP_PEX_IO11, PEX_5400_NF_IO11 }
};

static struct mch_error_code cor_pex_5400_error_code1[] = {
	{ 19, EMASK_UNCOR_PEX_IO19, PEX_5400_NF_IO19 },
	{ 10, EMASK_UNCOR_PEX_IO10, PEX_5400_NF_IO10 },
	{ 9, EMASK_UNCOR_PEX_IO9, PEX_5400_NF_IO9 },
	{ 8, EMASK_UNCOR_PEX_IO8, PEX_5400_NF_IO8 },
	{ 7, EMASK_UNCOR_PEX_IO7, PEX_5400_NF_IO7 },
	{ 6, EMASK_UNCOR_PEX_IO6, PEX_5400_NF_IO6 },
	{ 5, EMASK_UNCOR_PEX_IO5, PEX_5400_NF_IO5 },
	{ 4, EMASK_UNCOR_PEX_IO4, PEX_5400_NF_IO4 },
	{ 2, EMASK_UNCOR_PEX_IO2, PEX_5400_NF_IO2 },
	{ 0, EMASK_UNCOR_PEX_IO0, PEX_5400_NF_IO0 }
};

static struct mch_error_code cor_pex_5400_error_code2[] = {
	{ 20, EMASK_COR_PEX_IO20, PEX_5400_NF_IO20 },
	{ 16, EMASK_COR_PEX_IO16, PEX_5400_NF_IO16 },
	{ 15, EMASK_COR_PEX_IO15, PEX_5400_NF_IO15 },
	{ 14, EMASK_COR_PEX_IO14, PEX_5400_NF_IO14 },
	{ 13, EMASK_COR_PEX_IO13, PEX_5400_NF_IO13 },
	{ 12, EMASK_COR_PEX_IO12, PEX_5400_NF_IO12 }
};

static struct mch_error_code cor_pex_5400_error_code3[] = {
	{ 33, EMASK_UNIT_PEX_IO33, PEX_5400_NF_IO33 },
	{ 32, EMASK_UNIT_PEX_IO32, PEX_5400_NF_IO32 },
	{ 31, EMASK_UNIT_PEX_IO31, PEX_5400_NF_IO31 },
	{ 30, EMASK_UNIT_PEX_IO30, PEX_5400_NF_IO30 },
	{ 29, EMASK_UNIT_PEX_IO29, PEX_5400_NF_IO29 },
	{ 28, EMASK_UNIT_PEX_IO28, PEX_5400_NF_IO28 },
	{ 27, EMASK_UNIT_PEX_IO27, PEX_5400_NF_IO27 },
	{ 26, EMASK_UNIT_PEX_IO26, PEX_5400_NF_IO26 },
	{ 25, EMASK_UNIT_PEX_IO25, PEX_5400_NF_IO25 },
	{ 24, EMASK_UNIT_PEX_IO24, PEX_5400_NF_IO24 },
	{ 23, EMASK_UNIT_PEX_IO23, PEX_5400_NF_IO23 }
};

static struct mch_error_code rp_pex_error_code[] = {
	{ 17, EMASK_RP_PEX_IO17, PEX_NF_IO17 },
	{ 11, EMASK_RP_PEX_IO11, PEX_NF_IO11 },
};

static int
intel_pex_err(uint32_t pex_fat, uint32_t pex_nf_cor)
{
	int rt = -1;
	int nerr = 0;
	int i;
	int sz;

	sz = sizeof (fat_pex_error_code) / sizeof (struct mch_error_code);

	for (i = 0; i < sz; i++) {
		if (pex_fat & fat_pex_error_code[i].error_bit) {
			rt = fat_pex_error_code[i].intel_error_list;
			nerr++;
		}
	}
	sz = sizeof (fat_rp_error_code) / sizeof (struct mch_error_code);

	for (i = 0; i < sz; i++) {
		if (pex_fat & fat_rp_error_code[i].error_bit) {
			rt = fat_rp_error_code[i].intel_error_list;
			nerr++;
		}
	}
	sz = sizeof (uncor_pex_error_code) / sizeof (struct mch_error_code);

	for (i = 0; i < sz; i++) {
		if (pex_nf_cor & uncor_pex_error_code[i].error_bit) {
			rt = uncor_pex_error_code[i].intel_error_list;
			nerr++;
		}
	}

	sz = sizeof (cor_pex_error_code) / sizeof (struct mch_error_code);

	for (i = 0; i < sz; i++) {
		if (pex_nf_cor & cor_pex_error_code[i].error_bit) {
			rt = cor_pex_error_code[i].intel_error_list;
			nerr++;
		}
	}
	sz = sizeof (rp_pex_error_code) / sizeof (struct mch_error_code);

	for (i = 0; i < sz; i++) {
		if (pex_nf_cor & rp_pex_error_code[i].error_bit) {
			rt = rp_pex_error_code[i].intel_error_list;
			nerr++;
		}
	}

	if (nerr > 1)
		rt = -1;
	return (rt);
}

static struct mch_error_code fat_thr_error_code[] = {
	{ 2, EMASK_THR_F2, ERR_FAT_THR_F2 },
	{ 1, EMASK_THR_F1, ERR_FAT_THR_F1 }
};

static struct mch_error_code nf_thr_error_code[] = {
	{ 5, EMASK_THR_F5, ERR_NF_THR_F5 },
	{ 4, EMASK_THR_F4, ERR_NF_THR_F4 },
	{ 3, EMASK_THR_F3, ERR_NF_THR_F3 }
};

static int
intel_thr_err(uint8_t err_fat_thr, uint8_t err_nf_thr)
{
	int rt = -1;
	int nerr = 0;
	uint16_t emask_thr = 0;
	int i;
	int sz;

	sz = sizeof (fat_thr_error_code) / sizeof (struct mch_error_code);

	for (i = 0; i < sz; i++) {
		if (err_fat_thr & fat_thr_error_code[i].error_bit) {
			rt = fat_thr_error_code[i].intel_error_list;
			emask_thr |= fat_thr_error_code[i].emask;
			nerr++;
		}
	}

	sz = sizeof (nf_thr_error_code) / sizeof (struct mch_error_code);

	for (i = 0; i < sz; i++) {
		if (err_nf_thr & nf_thr_error_code[i].error_bit) {
			rt = nf_thr_error_code[i].intel_error_list;
			emask_thr |= nf_thr_error_code[i].emask;
			nerr++;
		}
	}

	if (emask_thr)
		nb_thr_mask_mc(emask_thr);
	if (nerr > 1)
		rt = -1;
	return (rt);
}

static int
intel_pex_5400_err(uint32_t pex_fat, uint32_t pex_nf_cor)
{
	int rt = -1;
	int nerr = 0;
	int i;
	int sz;

	sz = sizeof (fat_pex_5400_error_code) / sizeof (struct mch_error_code);

	for (i = 0; i < sz; i++) {
		if (pex_fat & fat_pex_5400_error_code[i].error_bit) {
			rt = fat_pex_5400_error_code[i].intel_error_list;
			nerr++;
		}
	}
	sz = sizeof (fat_rp_5400_error_code) / sizeof (struct mch_error_code);

	for (i = 0; i < sz; i++) {
		if (pex_fat & fat_rp_5400_error_code[i].error_bit) {
			rt = fat_rp_5400_error_code[i].intel_error_list;
			nerr++;
		}
	}
	sz = sizeof (fat_unit_pex_5400_error_code) /
	    sizeof (struct mch_error_code);

	for (i = 0; i < sz; i++) {
		if (pex_fat &
		    fat_unit_pex_5400_error_code[i].error_bit) {
			rt = fat_unit_pex_5400_error_code[i].intel_error_list;
			nerr++;
		}
	}
	sz = sizeof (uncor_pex_5400_error_code) /
	    sizeof (struct mch_error_code);

	for (i = 0; i < sz; i++) {
		if (pex_fat & uncor_pex_5400_error_code[i].error_bit) {
			rt = uncor_pex_5400_error_code[i].intel_error_list;
			nerr++;
		}
	}

	sz = sizeof (rp_pex_5400_error_code) / sizeof (struct mch_error_code);

	for (i = 0; i < sz; i++) {
		if (pex_nf_cor & rp_pex_5400_error_code[i].error_bit) {
			rt = rp_pex_5400_error_code[i].intel_error_list;
			nerr++;
		}
	}

	sz = sizeof (cor_pex_5400_error_code1) / sizeof (struct mch_error_code);

	for (i = 0; i < sz; i++) {
		if (pex_nf_cor & cor_pex_5400_error_code1[i].error_bit) {
			rt = cor_pex_5400_error_code1[i].intel_error_list;
			nerr++;
		}
	}

	sz = sizeof (cor_pex_5400_error_code2) / sizeof (struct mch_error_code);

	for (i = 0; i < sz; i++) {
		if (pex_nf_cor & cor_pex_5400_error_code2[i].error_bit) {
			rt = cor_pex_5400_error_code2[i].intel_error_list;
			nerr++;
		}
	}

	sz = sizeof (cor_pex_5400_error_code3) / sizeof (struct mch_error_code);

	for (i = 0; i < sz; i++) {
		if (pex_nf_cor & cor_pex_5400_error_code3[i].error_bit) {
			rt = cor_pex_5400_error_code3[i].intel_error_list;
			nerr++;
		}
	}

	if (nerr > 1)
		rt = -1;
	return (rt);
}

static void
log_pex_err(uint64_t ferr, nb_regs_t *rp, int *interpose)
{
	uint8_t pex = (uint8_t)-1;
	int t = 0;

	rp->flag = NB_REG_LOG_PEX;
	pex = GE_ERR_PEX(ferr);

	rp->nb.pex_regs.pex = pex;
	rp->nb.pex_regs.pex_fat_ferr =  PEX_FAT_FERR_RD(pex, interpose);
	rp->nb.pex_regs.pex_fat_nerr = PEX_FAT_NERR_RD(pex, &t);
	*interpose |= t;
	rp->nb.pex_regs.pex_nf_corr_ferr = PEX_NF_FERR_RD(pex, &t);
	*interpose |= t;
	rp->nb.pex_regs.pex_nf_corr_nerr = PEX_NF_NERR_RD(pex, &t);
	*interpose |= t;
	rp->nb.pex_regs.uncerrsev = UNCERRSEV_RD(pex);
	rp->nb.pex_regs.rperrsts = RPERRSTS_RD(pex);
	rp->nb.pex_regs.rperrsid = RPERRSID_RD(pex);
	if (pex != (uint8_t)-1)
		rp->nb.pex_regs.uncerrsts = UNCERRSTS_RD(pex);
	else
		rp->nb.pex_regs.uncerrsts = 0;
	rp->nb.pex_regs.aerrcapctrl = AERRCAPCTRL_RD(pex);
	rp->nb.pex_regs.corerrsts = CORERRSTS_RD(pex);
	rp->nb.pex_regs.pexdevsts = PEXDEVSTS_RD(pex);

	if (rp->nb.pex_regs.pex_fat_ferr || *interpose)
		PEX_FAT_FERR_WR(pex, rp->nb.pex_regs.pex_fat_ferr);
	if (rp->nb.pex_regs.pex_fat_nerr)
		PEX_FAT_NERR_WR(pex, rp->nb.pex_regs.pex_fat_nerr);
	if (rp->nb.pex_regs.pex_nf_corr_ferr || *interpose)
		PEX_NF_FERR_WR(pex, rp->nb.pex_regs.pex_nf_corr_ferr);
	if (rp->nb.pex_regs.pex_nf_corr_nerr)
		PEX_NF_NERR_WR(pex, rp->nb.pex_regs.pex_nf_corr_nerr);
	if (*interpose)
		UNCERRSTS_WR(pex, rp->nb.pex_regs.uncerrsts);
	if (*interpose)
		RPERRSTS_WR(pex, rp->nb.pex_regs.rperrsts);
	if (*interpose)
		PEXDEVSTS_WR(pex, 0);
}

static void
log_fat_fbd_err(nb_regs_t *rp, int *interpose)
{
	int channel, branch;
	int t = 0;

	rp->flag = NB_REG_LOG_FAT_FBD;
	rp->nb.fat_fbd_regs.ferr_fat_fbd = FERR_FAT_FBD_RD(interpose);
	channel = (rp->nb.fat_fbd_regs.ferr_fat_fbd >> 28) & 3;
	branch = channel >> 1;
	rp->nb.fat_fbd_regs.nerr_fat_fbd = NERR_FAT_FBD_RD(&t);
	*interpose |= t;
	rp->nb.fat_fbd_regs.nrecmema = NRECMEMA_RD(branch);
	rp->nb.fat_fbd_regs.nrecmemb = NRECMEMB_RD(branch);
	rp->nb.fat_fbd_regs.nrecfglog = NRECFGLOG_RD(branch);
	rp->nb.fat_fbd_regs.nrecfbda = NRECFBDA_RD(branch);
	rp->nb.fat_fbd_regs.nrecfbdb = NRECFBDB_RD(branch);
	rp->nb.fat_fbd_regs.nrecfbdc = NRECFBDC_RD(branch);
	rp->nb.fat_fbd_regs.nrecfbdd = NRECFBDD_RD(branch);
	rp->nb.fat_fbd_regs.nrecfbde = NRECFBDE_RD(branch);
	rp->nb.fat_fbd_regs.nrecfbdf = NRECFBDF_RD(branch);
	rp->nb.fat_fbd_regs.spcps = SPCPS_RD(branch);
	rp->nb.fat_fbd_regs.spcpc = SPCPC_RD(branch);
	rp->nb.fat_fbd_regs.uerrcnt = UERRCNT_RD(branch);
	rp->nb.fat_fbd_regs.uerrcnt_last = uerrcnt[branch];
	uerrcnt[branch] = rp->nb.fat_fbd_regs.uerrcnt;
	rp->nb.fat_fbd_regs.badrama = BADRAMA_RD(branch);
	rp->nb.fat_fbd_regs.badramb = BADRAMB_RD(branch);
	rp->nb.fat_fbd_regs.badcnt = BADCNT_RD(branch);
	if (rp->nb.fat_fbd_regs.ferr_fat_fbd || *interpose)
		FERR_FAT_FBD_WR(rp->nb.fat_fbd_regs.ferr_fat_fbd);
	if (rp->nb.fat_fbd_regs.nerr_fat_fbd)
		NERR_FAT_FBD_WR(rp->nb.fat_fbd_regs.nerr_fat_fbd);
	/* if interpose write read-only registers to clear from pcii cache */
	if (*interpose) {
		NRECMEMA_WR(branch);
		NRECMEMB_WR(branch);
		NRECFGLOG_WR(branch);
		NRECFBDA_WR(branch);
		NRECFBDB_WR(branch);
		NRECFBDC_WR(branch);
		NRECFBDD_WR(branch);
		NRECFBDE_WR(branch);
		NRECFBDF_WR(branch);
	}
}

static void
log_nf_fbd_err(nb_regs_t *rp, int *interpose)
{
	int channel, branch;
	int t = 0;

	rp->flag = NB_REG_LOG_NF_FBD;
	rp->nb.nf_fbd_regs.ferr_nf_fbd = FERR_NF_FBD_RD(interpose);
	channel = (rp->nb.nf_fbd_regs.ferr_nf_fbd >> 28) & 3;
	branch = channel >> 1;
	rp->nb.nf_fbd_regs.nerr_nf_fbd = NERR_NF_FBD_RD(&t);
	*interpose |= t;
	rp->nb.nf_fbd_regs.redmemb = REDMEMB_RD();
	rp->nb.nf_fbd_regs.recmema = RECMEMA_RD(branch);
	rp->nb.nf_fbd_regs.recmemb = RECMEMB_RD(branch);
	rp->nb.nf_fbd_regs.recfglog = RECFGLOG_RD(branch);
	rp->nb.nf_fbd_regs.recfbda = RECFBDA_RD(branch);
	rp->nb.nf_fbd_regs.recfbdb = RECFBDB_RD(branch);
	rp->nb.nf_fbd_regs.recfbdc = RECFBDC_RD(branch);
	rp->nb.nf_fbd_regs.recfbdd = RECFBDD_RD(branch);
	rp->nb.nf_fbd_regs.recfbde = RECFBDE_RD(branch);
	rp->nb.nf_fbd_regs.recfbdf = RECFBDF_RD(branch);
	rp->nb.nf_fbd_regs.spcps = SPCPS_RD(branch);
	rp->nb.nf_fbd_regs.spcpc = SPCPC_RD(branch);
	if (nb_chipset == INTEL_NB_7300 || nb_chipset == INTEL_NB_5400) {
		rp->nb.nf_fbd_regs.cerrcnta = CERRCNTA_RD(branch, channel);
		rp->nb.nf_fbd_regs.cerrcntb = CERRCNTB_RD(branch, channel);
		rp->nb.nf_fbd_regs.cerrcntc = CERRCNTC_RD(branch, channel);
		rp->nb.nf_fbd_regs.cerrcntd = CERRCNTD_RD(branch, channel);
	} else {
		rp->nb.nf_fbd_regs.cerrcnta = CERRCNT_RD(branch);
		rp->nb.nf_fbd_regs.cerrcntb = 0;
		rp->nb.nf_fbd_regs.cerrcntc = 0;
		rp->nb.nf_fbd_regs.cerrcntd = 0;
	}
	rp->nb.nf_fbd_regs.cerrcnta_last = cerrcnta[branch][channel & 1];
	rp->nb.nf_fbd_regs.cerrcntb_last = cerrcntb[branch][channel & 1];
	rp->nb.nf_fbd_regs.cerrcntc_last = cerrcntc[branch][channel & 1];
	rp->nb.nf_fbd_regs.cerrcntd_last = cerrcntd[branch][channel & 1];
	cerrcnta[branch][channel & 1] = rp->nb.nf_fbd_regs.cerrcnta;
	cerrcntb[branch][channel & 1] = rp->nb.nf_fbd_regs.cerrcntb;
	cerrcntc[branch][channel & 1] = rp->nb.nf_fbd_regs.cerrcntc;
	cerrcntd[branch][channel & 1] = rp->nb.nf_fbd_regs.cerrcntd;
	rp->nb.nf_fbd_regs.badrama = BADRAMA_RD(branch);
	rp->nb.nf_fbd_regs.badramb = BADRAMB_RD(branch);
	rp->nb.nf_fbd_regs.badcnt = BADCNT_RD(branch);
	if (rp->nb.nf_fbd_regs.ferr_nf_fbd || *interpose)
		FERR_NF_FBD_WR(rp->nb.nf_fbd_regs.ferr_nf_fbd);
	if (rp->nb.nf_fbd_regs.nerr_nf_fbd)
		NERR_NF_FBD_WR(rp->nb.nf_fbd_regs.nerr_nf_fbd);
	/* if interpose write read-only registers to clear from pcii cache */
	if (*interpose) {
		RECMEMA_WR(branch);
		RECMEMB_WR(branch);
		RECFGLOG_WR(branch);
		RECFBDA_WR(branch);
		RECFBDB_WR(branch);
		RECFBDC_WR(branch);
		RECFBDD_WR(branch);
		RECFBDE_WR(branch);
		RECFBDF_WR(branch);
		SPCPS_WR(branch);
	}
}

static void
log_ferr(uint64_t ferr, uint32_t *nerrp, nb_logout_t *log, int willpanic)
{
	nb_regs_t *rp = &log->nb_regs;
	uint32_t nerr = *nerrp;
	int interpose = 0;

	log->acl_timestamp = gethrtime_waitfree();
	if ((ferr & (GE_PCIEX_FATAL | GE_PCIEX_NF)) != 0) {
		log_pex_err(ferr, rp, &interpose);
		*nerrp = nerr & ~(GE_PCIEX_FATAL | GE_PCIEX_NF);
	} else if ((ferr & GE_FBD_FATAL) != 0) {
		log_fat_fbd_err(rp, &interpose);
		*nerrp = nerr & ~GE_NERR_FBD_FATAL;
	} else if ((ferr & GE_FBD_NF) != 0) {
		log_nf_fbd_err(rp, &interpose);
		*nerrp = nerr & ~GE_NERR_FBD_NF;
	} else if ((ferr & (GE_FERR_FSB_FATAL | GE_FERR_FSB_NF)) != 0) {
		log_fsb_err(ferr, rp, &interpose);
		*nerrp = nerr & ~(GE_NERR_FSB_FATAL | GE_NERR_FSB_NF);
	} else if ((ferr & (GE_DMA_FATAL | GE_DMA_NF)) != 0) {
		log_dma_err(rp, &interpose);
		*nerrp = nerr & ~(GE_DMA_FATAL | GE_DMA_NF);
	} else if ((ferr & (GE_INT_FATAL | GE_INT_NF)) != 0) {
		log_int_err(rp, &interpose);
		*nerrp = nerr & ~(GE_INT_FATAL | GE_INT_NF);
	} else if (nb_chipset == INTEL_NB_5400 &&
	    (ferr & (GE_FERR_THERMAL_FATAL | GE_FERR_THERMAL_NF)) != 0) {
		log_thermal_err(rp, &interpose);
		*nerrp = nerr & ~(GE_FERR_THERMAL_FATAL | GE_FERR_THERMAL_NF);
	}
	if (interpose)
		log->type = "inject";
	else
		log->type = "error";
	errorq_dispatch(nb_queue, log, sizeof (nb_logout_t),
	    willpanic ? ERRORQ_SYNC : ERRORQ_ASYNC);
}

static void
log_nerr(uint32_t *errp, nb_logout_t *log, int willpanic)
{
	uint32_t err;
	nb_regs_t *rp = &log->nb_regs;
	int interpose = 0;

	err = *errp;
	log->acl_timestamp = gethrtime_waitfree();
	if ((err & (GE_PCIEX_FATAL | GE_PCIEX_NF)) != 0) {
		log_pex_err(err, rp, &interpose);
		*errp = err & ~(GE_PCIEX_FATAL | GE_PCIEX_NF);
	} else if ((err & GE_NERR_FBD_FATAL) != 0) {
		log_fat_fbd_err(rp, &interpose);
		*errp = err & ~GE_NERR_FBD_FATAL;
	} else if ((err & GE_NERR_FBD_NF) != 0) {
		log_nf_fbd_err(rp, &interpose);
		*errp = err & ~GE_NERR_FBD_NF;
	} else if ((err & (GE_NERR_FSB_FATAL | GE_NERR_FSB_NF)) != 0) {
		log_fsb_err(GE_NERR_TO_FERR_FSB(err), rp, &interpose);
		*errp = err & ~(GE_NERR_FSB_FATAL | GE_NERR_FSB_NF);
	} else if ((err & (GE_DMA_FATAL | GE_DMA_NF)) != 0) {
		log_dma_err(rp, &interpose);
		*errp = err & ~(GE_DMA_FATAL | GE_DMA_NF);
	} else if ((err & (GE_INT_FATAL | GE_INT_NF)) != 0) {
		log_int_err(rp, &interpose);
		*errp = err & ~(GE_INT_FATAL | GE_INT_NF);
	}
	if (interpose)
		log->type = "inject";
	else
		log->type = "error";
	errorq_dispatch(nb_queue, log, sizeof (nb_logout_t),
	    willpanic ? ERRORQ_SYNC : ERRORQ_ASYNC);
}

/*ARGSUSED*/
void
nb_error_trap(cmi_hdl_t hdl, boolean_t ismc, boolean_t willpanic)
{
	uint64_t ferr;
	uint32_t nerr, err;
	int nmc = 0;
	int i;

	if (mutex_tryenter(&nb_mutex) == 0)
		return;

	nerr = NERR_GLOBAL_RD();
	err = nerr;
	for (i = 0; i < NB_MAX_ERRORS; i++) {
		ferr = FERR_GLOBAL_RD();
		nb_log.nb_regs.chipset = nb_chipset;
		nb_log.nb_regs.ferr = ferr;
		nb_log.nb_regs.nerr = nerr;
		if (ferr) {
			log_ferr(ferr, &err, &nb_log, willpanic);
			FERR_GLOBAL_WR(ferr);
			nmc++;
		} else if (err) {
			log_nerr(&err, &nb_log, willpanic);
			nmc++;
		}
	}
	if (nerr) {
		NERR_GLOBAL_WR(nerr);
	}
	if (nmc == 0 && nb_mask_mc_set)
		nb_mask_mc_reset();
	mutex_exit(&nb_mutex);
}

static void
nb_fsb_err_payload(const nb_regs_t *nb_regs, nvlist_t *payload,
    nb_scatchpad_t *data)
{
	int intel_error_list;
	char buf[32];

	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_FSB,
	    DATA_TYPE_UINT8, nb_regs->nb.fsb_regs.fsb, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_FERR_FAT_FSB,
	    DATA_TYPE_UINT8, nb_regs->nb.fsb_regs.ferr_fat_fsb, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_NERR_FAT_FSB,
	    DATA_TYPE_UINT8, nb_regs->nb.fsb_regs.nerr_fat_fsb, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_FERR_NF_FSB,
	    DATA_TYPE_UINT8, nb_regs->nb.fsb_regs.ferr_nf_fsb, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_NERR_NF_FSB,
	    DATA_TYPE_UINT8, nb_regs->nb.fsb_regs.nerr_nf_fsb, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_NRECFSB,
	    DATA_TYPE_UINT32, nb_regs->nb.fsb_regs.nrecfsb, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_NRECFSB_ADDR,
	    DATA_TYPE_UINT64, nb_regs->nb.fsb_regs.nrecfsb_addr, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_RECFSB,
	    DATA_TYPE_UINT32, nb_regs->nb.fsb_regs.recfsb, NULL);
	intel_error_list = data->intel_error_list;
	if (intel_error_list >= 0)
		(void) snprintf(buf, sizeof (buf), "F%d", intel_error_list);
	else
		(void) snprintf(buf, sizeof (buf), "Multiple or unknown error");
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_ERROR_NO,
	    DATA_TYPE_STRING, buf, NULL);
}

static void
nb_pex_err_payload(const nb_regs_t *nb_regs, nvlist_t *payload,
    nb_scatchpad_t *data)
{
	int intel_error_list;
	char buf[32];

	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_PEX,
	    DATA_TYPE_UINT8, nb_regs->nb.pex_regs.pex, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_PEX_FAT_FERR,
	    DATA_TYPE_UINT32, nb_regs->nb.pex_regs.pex_fat_ferr, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_PEX_FAT_NERR,
	    DATA_TYPE_UINT32, nb_regs->nb.pex_regs.pex_fat_nerr, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_PEX_NF_CORR_FERR,
	    DATA_TYPE_UINT32, nb_regs->nb.pex_regs.pex_nf_corr_ferr, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_PEX_NF_CORR_NERR,
	    DATA_TYPE_UINT32, nb_regs->nb.pex_regs.pex_nf_corr_nerr, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_UNCERRSEV,
	    DATA_TYPE_UINT32, nb_regs->nb.pex_regs.uncerrsev, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_RPERRSTS,
	    DATA_TYPE_UINT32, nb_regs->nb.pex_regs.rperrsts, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_RPERRSID,
	    DATA_TYPE_UINT32, nb_regs->nb.pex_regs.rperrsid, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_UNCERRSTS,
	    DATA_TYPE_UINT32, nb_regs->nb.pex_regs.uncerrsts, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_AERRCAPCTRL,
	    DATA_TYPE_UINT32, nb_regs->nb.pex_regs.aerrcapctrl, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_CORERRSTS,
	    DATA_TYPE_UINT32, nb_regs->nb.pex_regs.corerrsts, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_PEXDEVSTS,
	    DATA_TYPE_UINT16, nb_regs->nb.pex_regs.pexdevsts, NULL);
	intel_error_list = data->intel_error_list;
	if (intel_error_list >= 0)
		(void) snprintf(buf, sizeof (buf), "IO%d", intel_error_list);
	else
		(void) snprintf(buf, sizeof (buf), "Multiple or unknown error");
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_ERROR_NO,
	    DATA_TYPE_STRING, buf, NULL);
}

static void
nb_int_err_payload(const nb_regs_t *nb_regs, nvlist_t *payload,
    nb_scatchpad_t *data)
{
	int intel_error_list;
	char buf[32];

	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_FERR_FAT_INT,
	    DATA_TYPE_UINT16, nb_regs->nb.int_regs.ferr_fat_int, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_FERR_NF_INT,
	    DATA_TYPE_UINT16, nb_regs->nb.int_regs.ferr_nf_int, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_NERR_FAT_INT,
	    DATA_TYPE_UINT16, nb_regs->nb.int_regs.nerr_fat_int, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_NERR_NF_INT,
	    DATA_TYPE_UINT16, nb_regs->nb.int_regs.nerr_nf_int, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_NRECINT,
	    DATA_TYPE_UINT32, nb_regs->nb.int_regs.nrecint, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_RECINT,
	    DATA_TYPE_UINT32, nb_regs->nb.int_regs.recint, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_NRECSF,
	    DATA_TYPE_UINT64, nb_regs->nb.int_regs.nrecsf, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_RECSF,
	    DATA_TYPE_UINT64, nb_regs->nb.int_regs.recsf, NULL);
	intel_error_list = data->intel_error_list;
	if (intel_error_list >= 0)
		(void) snprintf(buf, sizeof (buf), "B%d", intel_error_list);
	else
		(void) snprintf(buf, sizeof (buf), "Multiple or unknown error");
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_ERROR_NO,
	    DATA_TYPE_STRING, buf, NULL);
}

static void
nb_fat_fbd_err_payload(const nb_regs_t *nb_regs, nvlist_t *payload,
    nb_scatchpad_t *data)
{
	nb_mem_scatchpad_t *sp;
	char buf[32];

	sp = &((nb_scatchpad_t *)data)->ms;

	if (sp->ras != -1) {
		fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_BANK,
		    DATA_TYPE_INT32, sp->bank, NULL);
		fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_CAS,
		    DATA_TYPE_INT32, sp->cas, NULL);
		fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_RAS,
		    DATA_TYPE_INT32, sp->ras, NULL);
		if (sp->offset != -1LL) {
			fm_payload_set(payload, FM_FMRI_MEM_OFFSET,
			    DATA_TYPE_UINT64, sp->offset, NULL);
		}
		if (sp->pa != -1LL) {
			fm_payload_set(payload, FM_FMRI_MEM_PHYSADDR,
			    DATA_TYPE_UINT64, sp->pa, NULL);
		}
	}
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_FERR_FAT_FBD,
	    DATA_TYPE_UINT32, nb_regs->nb.fat_fbd_regs.ferr_fat_fbd, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_NERR_FAT_FBD,
	    DATA_TYPE_UINT32, nb_regs->nb.fat_fbd_regs.nerr_fat_fbd, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_NRECMEMA,
	    DATA_TYPE_UINT32, nb_regs->nb.fat_fbd_regs.nrecmema, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_NRECMEMB,
	    DATA_TYPE_UINT32, nb_regs->nb.fat_fbd_regs.nrecmemb, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_NRECFGLOG,
	    DATA_TYPE_UINT32, nb_regs->nb.fat_fbd_regs.nrecfglog, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_NRECFBDA,
	    DATA_TYPE_UINT32, nb_regs->nb.fat_fbd_regs.nrecfbda, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_NRECFBDB,
	    DATA_TYPE_UINT32, nb_regs->nb.fat_fbd_regs.nrecfbdb, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_NRECFBDC,
	    DATA_TYPE_UINT32, nb_regs->nb.fat_fbd_regs.nrecfbdc, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_NRECFBDD,
	    DATA_TYPE_UINT32, nb_regs->nb.fat_fbd_regs.nrecfbdd, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_NRECFBDE,
	    DATA_TYPE_UINT32, nb_regs->nb.fat_fbd_regs.nrecfbde, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_NRECFBDF,
	    DATA_TYPE_UINT32, nb_regs->nb.fat_fbd_regs.nrecfbdf, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_SPCPS,
	    DATA_TYPE_UINT8, nb_regs->nb.fat_fbd_regs.spcps, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_SPCPC,
	    DATA_TYPE_UINT32, nb_regs->nb.fat_fbd_regs.spcpc, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_UERRCNT,
	    DATA_TYPE_UINT32, nb_regs->nb.fat_fbd_regs.uerrcnt, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_UERRCNT_LAST,
	    DATA_TYPE_UINT32, nb_regs->nb.fat_fbd_regs.uerrcnt_last, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_BADRAMA,
	    DATA_TYPE_UINT32, nb_regs->nb.fat_fbd_regs.badrama, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_BADRAMB,
	    DATA_TYPE_UINT16, nb_regs->nb.fat_fbd_regs.badramb, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_BADCNT,
	    DATA_TYPE_UINT32, nb_regs->nb.fat_fbd_regs.badcnt, NULL);

	if (sp->intel_error_list >= 0)
		(void) snprintf(buf, sizeof (buf), "M%d", sp->intel_error_list);
	else
		(void) snprintf(buf, sizeof (buf), "Multiple or unknown error");
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_ERROR_NO,
	    DATA_TYPE_STRING, buf, NULL);
}

static void
nb_nf_fbd_err_payload(const nb_regs_t *nb_regs, nvlist_t *payload,
    nb_scatchpad_t *data)
{
	nb_mem_scatchpad_t *sp;
	char buf[32];

	sp = &((nb_scatchpad_t *)data)->ms;

	if (sp->dimm == -1 && sp->rank != -1) {
		fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_RANK,
		    DATA_TYPE_INT32, sp->rank, NULL);
	}
	if (sp->ras != -1) {
		fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_BANK,
		    DATA_TYPE_INT32, sp->bank, NULL);
		fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_CAS,
		    DATA_TYPE_INT32, sp->cas, NULL);
		fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_RAS,
		    DATA_TYPE_INT32, sp->ras, NULL);
		if (sp->offset != -1LL) {
			fm_payload_set(payload, FM_FMRI_MEM_OFFSET,
			    DATA_TYPE_UINT64, sp->offset, NULL);
		}
		if (sp->pa != -1LL) {
			fm_payload_set(payload, FM_FMRI_MEM_PHYSADDR,
			    DATA_TYPE_UINT64, sp->pa, NULL);
		}
	}
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_FERR_NF_FBD,
	    DATA_TYPE_UINT32, nb_regs->nb.nf_fbd_regs.ferr_nf_fbd, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_NERR_NF_FBD,
	    DATA_TYPE_UINT32, nb_regs->nb.nf_fbd_regs.nerr_nf_fbd, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_RECMEMA,
	    DATA_TYPE_UINT32, nb_regs->nb.nf_fbd_regs.recmema, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_RECMEMB,
	    DATA_TYPE_UINT32, nb_regs->nb.nf_fbd_regs.recmemb, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_RECFGLOG,
	    DATA_TYPE_UINT32, nb_regs->nb.nf_fbd_regs.recfglog, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_RECFBDA,
	    DATA_TYPE_UINT32, nb_regs->nb.nf_fbd_regs.recfbda, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_RECFBDB,
	    DATA_TYPE_UINT32, nb_regs->nb.nf_fbd_regs.recfbdb, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_RECFBDC,
	    DATA_TYPE_UINT32, nb_regs->nb.nf_fbd_regs.recfbdc, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_RECFBDD,
	    DATA_TYPE_UINT32, nb_regs->nb.nf_fbd_regs.recfbdd, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_RECFBDE,
	    DATA_TYPE_UINT32, nb_regs->nb.nf_fbd_regs.recfbde, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_RECFBDF,
	    DATA_TYPE_UINT32, nb_regs->nb.nf_fbd_regs.recfbdf, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_SPCPS,
	    DATA_TYPE_UINT8, nb_regs->nb.nf_fbd_regs.spcps, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_SPCPC,
	    DATA_TYPE_UINT32, nb_regs->nb.nf_fbd_regs.spcpc, NULL);
	if (nb_chipset == INTEL_NB_7300 || nb_chipset == INTEL_NB_5400) {
		fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_CERRCNTA,
		    DATA_TYPE_UINT32, nb_regs->nb.nf_fbd_regs.cerrcnta, NULL);
		fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_CERRCNTB,
		    DATA_TYPE_UINT32, nb_regs->nb.nf_fbd_regs.cerrcntb, NULL);
		if (nb_chipset == INTEL_NB_7300) {
			fm_payload_set(payload,
			    FM_EREPORT_PAYLOAD_NAME_CERRCNTC,
			    DATA_TYPE_UINT32, nb_regs->nb.nf_fbd_regs.cerrcntc,
			    NULL);
			fm_payload_set(payload,
			    FM_EREPORT_PAYLOAD_NAME_CERRCNTD,
			    DATA_TYPE_UINT32, nb_regs->nb.nf_fbd_regs.cerrcntd,
			    NULL);
		}
		fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_CERRCNTA_LAST,
		    DATA_TYPE_UINT32, nb_regs->nb.nf_fbd_regs.cerrcnta_last,
		    NULL);
		fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_CERRCNTB_LAST,
		    DATA_TYPE_UINT32, nb_regs->nb.nf_fbd_regs.cerrcntb_last,
		    NULL);
		if (nb_chipset == INTEL_NB_7300) {
			fm_payload_set(payload,
			    FM_EREPORT_PAYLOAD_NAME_CERRCNTC_LAST,
			    DATA_TYPE_UINT32,
			    nb_regs->nb.nf_fbd_regs.cerrcntc_last, NULL);
			fm_payload_set(payload,
			    FM_EREPORT_PAYLOAD_NAME_CERRCNTD_LAST,
			    DATA_TYPE_UINT32,
			    nb_regs->nb.nf_fbd_regs.cerrcntd_last, NULL);
		}
	} else {
		fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_CERRCNT,
		    DATA_TYPE_UINT32, nb_regs->nb.nf_fbd_regs.cerrcnta, NULL);
		fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_CERRCNT_LAST,
		    DATA_TYPE_UINT32, nb_regs->nb.nf_fbd_regs.cerrcnta_last,
		    NULL);
	}
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_BADRAMA,
	    DATA_TYPE_UINT32, nb_regs->nb.nf_fbd_regs.badrama, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_BADRAMB,
	    DATA_TYPE_UINT16, nb_regs->nb.nf_fbd_regs.badramb, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_BADCNT,
	    DATA_TYPE_UINT32, nb_regs->nb.nf_fbd_regs.badcnt, NULL);

	if (sp->intel_error_list >= 0)
		(void) snprintf(buf, sizeof (buf), "M%d", sp->intel_error_list);
	else
		(void) snprintf(buf, sizeof (buf), "Multiple or unknown error");
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_ERROR_NO,
	    DATA_TYPE_STRING, buf, NULL);
}

static void
nb_dma_err_payload(const nb_regs_t *nb_regs, nvlist_t *payload)
{
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_PCISTS,
	    DATA_TYPE_UINT16, nb_regs->nb.dma_regs.pcists, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_PEXDEVSTS,
	    DATA_TYPE_UINT16, nb_regs->nb.dma_regs.pexdevsts, NULL);
}

static void
nb_thr_err_payload(const nb_regs_t *nb_regs, nvlist_t *payload,
    nb_scatchpad_t *data)
{
	char buf[32];

	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_FERR_FAT_THR,
	    DATA_TYPE_UINT8, nb_regs->nb.thr_regs.ferr_fat_thr, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_NERR_FAT_THR,
	    DATA_TYPE_UINT8, nb_regs->nb.thr_regs.nerr_fat_thr, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_FERR_NF_THR,
	    DATA_TYPE_UINT8, nb_regs->nb.thr_regs.ferr_nf_thr, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_NERR_NF_THR,
	    DATA_TYPE_UINT8, nb_regs->nb.thr_regs.nerr_nf_thr, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_CTSTS,
	    DATA_TYPE_UINT8, nb_regs->nb.thr_regs.ctsts, NULL);
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_THRTSTS,
	    DATA_TYPE_UINT16, nb_regs->nb.thr_regs.thrtsts, NULL);
	if (data->intel_error_list >= 0) {
		(void) snprintf(buf, sizeof (buf), "TH%d",
		    data->intel_error_list);
	} else {
		(void) snprintf(buf, sizeof (buf), "Multiple or unknown error");
	}
	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_ERROR_NO,
	    DATA_TYPE_STRING, buf, NULL);
}

static void
nb_ereport_add_logout(nvlist_t *payload, const nb_logout_t *acl,
    nb_scatchpad_t *data)
{
	const nb_regs_t *nb_regs = &acl->nb_regs;

	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_MC_TYPE,
	    DATA_TYPE_STRING, acl->type, NULL);
	switch (nb_regs->flag) {
	case NB_REG_LOG_FSB:
		nb_fsb_err_payload(nb_regs, payload, data);
		break;
	case NB_REG_LOG_PEX:
		nb_pex_err_payload(nb_regs, payload, data);
		break;
	case NB_REG_LOG_INT:
		nb_int_err_payload(nb_regs, payload, data);
		break;
	case NB_REG_LOG_FAT_FBD:
		nb_fat_fbd_err_payload(nb_regs, payload, data);
		break;
	case NB_REG_LOG_NF_FBD:
		nb_nf_fbd_err_payload(nb_regs, payload, data);
		break;
	case NB_REG_LOG_DMA:
		nb_dma_err_payload(nb_regs, payload);
		break;
	case NB_REG_LOG_THR:
		nb_thr_err_payload(nb_regs, payload, data);
		break;
	default:
		fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_FERR_GLOBAL,
		    DATA_TYPE_UINT64, nb_regs->ferr, NULL);
		fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_NERR_GLOBAL,
		    DATA_TYPE_UINT32, nb_regs->nerr, NULL);
		break;
	}
}

void
nb_fsb_report(const nb_regs_t *nb_regs, char *class, nvlist_t *detector,
    nb_scatchpad_t *data)
{
	int chip;

	if (nb_chipset == INTEL_NB_7300)
		chip = nb_regs->nb.fsb_regs.fsb * 2;
	else
		chip = nb_regs->nb.fsb_regs.fsb;
	fm_fmri_hc_set(detector, FM_HC_SCHEME_VERSION, NULL, NULL, 2,
	    "motherboard", 0, "chip", chip);

	if (nb_regs->nb.fsb_regs.ferr_fat_fsb == 0 &&
	    nb_regs->nb.fsb_regs.ferr_nf_fsb == 0) {
		data->intel_error_list = intel_fsb_err(nb_regs->nb.fsb_regs.fsb,
		    nb_regs->nb.fsb_regs.nerr_fat_fsb,
		    nb_regs->nb.fsb_regs.nerr_nf_fsb);
	} else {
		data->intel_error_list = intel_fsb_err(nb_regs->nb.fsb_regs.fsb,
		    nb_regs->nb.fsb_regs.ferr_fat_fsb,
		    nb_regs->nb.fsb_regs.ferr_nf_fsb);
	}
	(void) snprintf(class, FM_MAX_CLASS, "%s.%s.%s.%s",
	    FM_ERROR_CPU, FM_EREPORT_CPU_INTEL, "nb", "fsb");
}

void
nb_pex_report(const nb_regs_t *nb_regs, char *class, nvlist_t *detector,
    nb_scatchpad_t *data)
{
	int hostbridge;

	if (nb_regs->nb.pex_regs.pex == 0) {
		fm_fmri_hc_set(detector, FM_HC_SCHEME_VERSION, NULL, NULL, 1,
		    "motherboard", 0);
	} else {
		hostbridge = nb_regs->nb.pex_regs.pex - 1;
		fm_fmri_hc_set(detector, FM_HC_SCHEME_VERSION, NULL, NULL, 2,
		    "motherboard", 0,
		    "hostbridge", hostbridge);
	}

	if (nb_regs->nb.pex_regs.pex_fat_ferr == 0 &&
	    nb_regs->nb.pex_regs.pex_nf_corr_ferr == 0) {
		if (nb_chipset == INTEL_NB_5400) {
			data->intel_error_list =
			    intel_pex_5400_err(
			    nb_regs->nb.pex_regs.pex_fat_nerr,
			    nb_regs->nb.pex_regs.pex_nf_corr_nerr);
		} else {
			data->intel_error_list =
			    intel_pex_err(nb_regs->nb.pex_regs.pex_fat_nerr,
			    nb_regs->nb.pex_regs.pex_nf_corr_nerr);
		}
	} else {
		if (nb_chipset == INTEL_NB_5400) {
			data->intel_error_list =
			    intel_pex_5400_err(
			    nb_regs->nb.pex_regs.pex_fat_ferr,
			    nb_regs->nb.pex_regs.pex_nf_corr_ferr);
		} else {
			data->intel_error_list =
			    intel_pex_err(nb_regs->nb.pex_regs.pex_fat_ferr,
			    nb_regs->nb.pex_regs.pex_nf_corr_ferr);
		}
	}

	if (nb_regs->nb.pex_regs.pex == 0) {
		(void) snprintf(class, FM_MAX_CLASS, "%s.%s.%s.%s",
		    FM_ERROR_CPU, FM_EREPORT_CPU_INTEL, "nb", "esi");
	} else {
		(void) snprintf(class, FM_MAX_CLASS, "%s.%s.%s.%s",
		    FM_ERROR_CPU, FM_EREPORT_CPU_INTEL, "nb", "pex");
	}
}

void
nb_int_report(const nb_regs_t *nb_regs, char *class, nvlist_t *detector,
    void *data)
{
	fm_fmri_hc_set(detector, FM_HC_SCHEME_VERSION, NULL, NULL, 1,
	    "motherboard", 0);

	if (nb_regs->nb.int_regs.ferr_fat_int == 0 &&
	    nb_regs->nb.int_regs.ferr_nf_int == 0) {
		((nb_scatchpad_t *)data)->intel_error_list =
		    intel_int_err(nb_regs->nb.int_regs.nerr_fat_int,
		    nb_regs->nb.int_regs.nerr_nf_int);
	} else {
		((nb_scatchpad_t *)data)->intel_error_list =
		    intel_int_err(nb_regs->nb.int_regs.ferr_fat_int,
		    nb_regs->nb.int_regs.ferr_nf_int);
	}
	(void) snprintf(class, FM_MAX_CLASS, "%s.%s.%s.%s",
	    FM_ERROR_CPU, FM_EREPORT_CPU_INTEL, "nb", "ie");
}

void
nb_fat_fbd_report(const nb_regs_t *nb_regs, char *class, nvlist_t *detector,
    void *data)
{
	char *intr;
	nb_mem_scatchpad_t *sp;

	intr = fat_memory_error(nb_regs, data);
	sp = &((nb_scatchpad_t *)data)->ms;

	if (sp->dimm != -1) {
		fm_fmri_hc_set(detector, FM_HC_SCHEME_VERSION, NULL, NULL, 5,
		    "motherboard", 0,
		    "memory-controller", sp->branch,
		    "dram-channel", sp->channel,
		    "dimm", sp->dimm,
		    "rank", sp->rank);
	} else if (sp->channel != -1) {
		fm_fmri_hc_set(detector, FM_HC_SCHEME_VERSION, NULL, NULL, 3,
		    "motherboard", 0,
		    "memory-controller", sp->branch,
		    "dram-channel", sp->channel);
	} else if (sp->branch != -1) {
		fm_fmri_hc_set(detector, FM_HC_SCHEME_VERSION, NULL, NULL, 2,
		    "motherboard", 0,
		    "memory-controller", sp->branch);
	} else {
		fm_fmri_hc_set(detector, FM_HC_SCHEME_VERSION, NULL, NULL, 1,
		    "motherboard", 0);
	}

	(void) snprintf(class, FM_MAX_CLASS, "%s.%s.%s",
	    FM_ERROR_CPU, FM_EREPORT_CPU_INTEL, intr);
}

void
nb_nf_fbd_report(const nb_regs_t *nb_regs, char *class, nvlist_t *detector,
    void *data)
{
	char *intr;
	nb_mem_scatchpad_t *sp;

	intr = nf_memory_error(nb_regs, data);
	sp = &((nb_scatchpad_t *)data)->ms;

	if (sp->dimm != -1) {
		fm_fmri_hc_set(detector, FM_HC_SCHEME_VERSION, NULL, NULL, 5,
		    "motherboard", 0,
		    "memory-controller", sp->branch,
		    "dram-channel", sp->channel,
		    "dimm", sp->dimm,
		    "rank", sp->rank);
	} else if (sp->channel != -1) {
		fm_fmri_hc_set(detector, FM_HC_SCHEME_VERSION, NULL, NULL, 3,
		    "motherboard", 0,
		    "memory-controller", sp->branch,
		    "dram-channel", sp->channel);
	} else if (sp->branch != -1) {
		fm_fmri_hc_set(detector, FM_HC_SCHEME_VERSION, NULL, NULL, 2,
		    "motherboard", 0,
		    "memory-controller", sp->branch);
	} else {
		fm_fmri_hc_set(detector, FM_HC_SCHEME_VERSION, NULL, NULL, 1,
		    "motherboard", 0);
	}

	(void) snprintf(class, FM_MAX_CLASS, "%s.%s.%s",
	    FM_ERROR_CPU, FM_EREPORT_CPU_INTEL, intr);
}

void
nb_dma_report(char *class, nvlist_t *detector)
{
	fm_fmri_hc_set(detector, FM_HC_SCHEME_VERSION, NULL, NULL, 1,
	    "motherboard", 0);

	(void) snprintf(class, FM_MAX_CLASS, "%s.%s.%s.%s",
	    FM_ERROR_CPU, FM_EREPORT_CPU_INTEL, "nb", "dma");
}

void
nb_thr_report(const nb_regs_t *nb_regs, char *class, nvlist_t *detector,
    void *data)
{
	((nb_scatchpad_t *)data)->intel_error_list =
	    intel_thr_err(nb_regs->nb.thr_regs.ferr_fat_thr,
	    nb_regs->nb.thr_regs.ferr_nf_thr);
	fm_fmri_hc_set(detector, FM_HC_SCHEME_VERSION, NULL, NULL, 1,
	    "motherboard", 0);

	(void) snprintf(class, FM_MAX_CLASS, "%s.%s.%s.%s",
	    FM_ERROR_CPU, FM_EREPORT_CPU_INTEL, "nb", "otf");
}


nvlist_t *
nb_report(const nb_regs_t *nb_regs, char *class, nv_alloc_t *nva, void *scratch)
{
	nvlist_t *detector = fm_nvlist_create(nva);

	switch (nb_regs->flag) {
	case NB_REG_LOG_FSB:
		nb_fsb_report(nb_regs, class, detector, scratch);
		break;
	case NB_REG_LOG_PEX:
		nb_pex_report(nb_regs, class, detector, scratch);
		break;
	case NB_REG_LOG_INT:
		nb_int_report(nb_regs, class, detector, scratch);
		break;
	case NB_REG_LOG_FAT_FBD:
		nb_fat_fbd_report(nb_regs, class, detector, scratch);
		break;
	case NB_REG_LOG_NF_FBD:
		nb_nf_fbd_report(nb_regs, class, detector, scratch);
		break;
	case NB_REG_LOG_DMA:
		nb_dma_report(class, detector);
		break;
	case NB_REG_LOG_THR:
		nb_thr_report(nb_regs, class, detector, scratch);
		break;
	default:
		fm_fmri_hc_set(detector, FM_HC_SCHEME_VERSION, NULL, NULL, 1,
		    "motherboard", 0);

		(void) snprintf(class, FM_MAX_CLASS, "%s.%s.%s.%s",
		    FM_ERROR_CPU, FM_EREPORT_CPU_INTEL, "nb", "unknown");
	}
	return (detector);
}

/*ARGSUSED*/
void
nb_drain(void *ignored, const void *data, const errorq_elem_t *eqe)
{
	nb_logout_t *acl = (nb_logout_t *)data;
	errorq_elem_t *eqep, *scr_eqep;
	nvlist_t *ereport, *detector;
	nv_alloc_t *nva = NULL;
	char buf[FM_MAX_CLASS];
	nb_scatchpad_t nb_scatchpad;

	if (panicstr) {
		if ((eqep = errorq_reserve(ereport_errorq)) == NULL)
			return;
		ereport = errorq_elem_nvl(ereport_errorq, eqep);
		/*
		 * Now try to allocate another element for scratch space and
		 * use that for further scratch space (eg for constructing
		 * nvlists to add the main ereport).  If we can't reserve
		 * a scratch element just fallback to working within the
		 * element we already have, and hope for the best.  All this
		 * is necessary because the fixed buffer nv allocator does
		 * not reclaim freed space and nvlist construction is
		 * expensive.
		 */
		if ((scr_eqep = errorq_reserve(ereport_errorq)) != NULL)
			nva = errorq_elem_nva(ereport_errorq, scr_eqep);
		else
			nva = errorq_elem_nva(ereport_errorq, eqep);
	} else {
		ereport = fm_nvlist_create(NULL);
	}
	detector = nb_report(&acl->nb_regs, buf, nva, &nb_scatchpad);
	if (detector == NULL)
		return;
	fm_ereport_set(ereport, FM_EREPORT_VERSION, buf,
	    fm_ena_generate(acl->acl_timestamp, FM_ENA_FMT1), detector, NULL);
	/*
	 * We're done with 'detector' so reclaim the scratch space.
	 */
	if (panicstr) {
		fm_nvlist_destroy(detector, FM_NVA_RETAIN);
		nv_alloc_reset(nva);
	} else {
		fm_nvlist_destroy(detector, FM_NVA_FREE);
	}

	/*
	 * Encode the error-specific data that was saved in the logout area.
	 */
	nb_ereport_add_logout(ereport, acl, &nb_scatchpad);

	if (panicstr) {
		errorq_commit(ereport_errorq, eqep, ERRORQ_SYNC);
		if (scr_eqep)
			errorq_cancel(ereport_errorq, scr_eqep);
	} else {
		(void) fm_ereport_post(ereport, EVCH_TRYHARD);
		fm_nvlist_destroy(ereport, FM_NVA_FREE);
	}
}
