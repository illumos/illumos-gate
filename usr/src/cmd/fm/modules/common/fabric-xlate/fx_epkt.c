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
#include <sys/types.h>
#include <px_err.h>

#include "fabric-xlate.h"

#define	EPKT_DESC(b, o, p, c, d) (BLOCK_##b << 16 | OP_##o << 12 | \
    PH_##p << 8 | CND_##c << 4 | DIR_##d)

/* EPKT Table used only for RC/RP errors */
typedef struct fab_epkt_tbl {
	uint32_t	epkt_desc;
	uint32_t	pcie_ue_sts;	/* Equivalent PCIe UE Status */
	uint16_t	pci_err_sts;	/* Equivalent PCI Error Status */
	uint16_t	pci_bdg_sts;	/* Equivalent PCI Bridge Status */
	const char	*tgt_class;	/* Target Ereport Class */
} fab_epkt_tbl_t;

static fab_epkt_tbl_t fab_epkt_tbl[] = {
	EPKT_DESC(MMU, XLAT, DATA, INV, RDWR),
	PCIE_AER_UCE_CA, 0, PCI_STAT_S_TARG_AB, 0,
	EPKT_DESC(MMU, XLAT, ADDR, UNMAP, RDWR),
	PCIE_AER_UCE_CA, 0, PCI_STAT_S_TARG_AB, 0,
	EPKT_DESC(MMU, XLAT, DATA, PROT, RDWR),
	PCIE_AER_UCE_CA, 0, PCI_STAT_S_TARG_AB, 0,

	EPKT_DESC(INTR, MSI32, DATA, ILL, IRR),
	PCIE_AER_UCE_MTLP, PCI_STAT_S_SYSERR, 0, 0,

	EPKT_DESC(PORT, PIO, IRR, RCA, WRITE),
	PCIE_AER_UCE_CA, PCI_STAT_S_SYSERR, PCI_STAT_S_TARG_AB, 0,

	EPKT_DESC(PORT, PIO, IRR, RUR, WRITE),
	PCIE_AER_UCE_UR, PCI_STAT_S_SYSERR, 0, 0,

	EPKT_DESC(PORT, PIO, IRR, INV, RDWR),
	PCIE_AER_UCE_MTLP, PCI_STAT_S_SYSERR, 0, 0,

	EPKT_DESC(PORT, PIO, IRR, TO, READ),
	PCIE_AER_UCE_TO, PCI_STAT_S_SYSERR, 0, PCI_TARG_MA,
	EPKT_DESC(PORT, PIO, IRR, TO, WRITE),
	PCIE_AER_UCE_TO, PCI_STAT_S_SYSERR, 0, PCI_TARG_MA,

	EPKT_DESC(PORT, PIO, IRR, UC, IRR),
	PCIE_AER_UCE_UC, PCI_STAT_S_SYSERR, 0, 0,

	EPKT_DESC(PORT, LINK, FC, TO, IRR),
	PCIE_AER_UCE_FCP, PCI_STAT_S_SYSERR, 0, 0,

	0, 0, 0, 0, 0
};

/* ARGSUSED */
void
fab_epkt_to_data(fmd_hdl_t *hdl, nvlist_t *nvl, fab_data_t *data)
{
	data->nvl = nvl;

	/* Always Root Complex */
	data->dev_type = PCIE_PCIECAP_DEV_TYPE_ROOT;

	data->pcie_ue_sev = (PCIE_AER_UCE_DLP | PCIE_AER_UCE_SD |
	    PCIE_AER_UCE_FCP | PCIE_AER_UCE_RO | PCIE_AER_UCE_MTLP);
}

static int
fab_xlate_epkt(fmd_hdl_t *hdl, fab_data_t *data, px_rc_err_t *epktp)
{
	fab_epkt_tbl_t *entry;
	uint32_t temp;

	for (entry = fab_epkt_tbl; entry->epkt_desc != 0; entry++) {
		temp = *(uint32_t *)&epktp->rc_descr >> 12;
		if (entry->epkt_desc == temp)
			goto send;
	}

	return (0);

send:
	fmd_hdl_debug(hdl, "Translate epkt DESC = %#x\n", temp);

	/* Fill in PCI Status Register */
	data->pci_err_status = entry->pci_err_sts;
	data->pci_bdg_sec_stat = entry->pci_bdg_sts;

	/* Fill in the device status register */
	if (epktp->rc_descr.STOP)
		data->pcie_err_status = PCIE_DEVSTS_FE_DETECTED;
	else if (epktp->rc_descr.C)
		data->pcie_err_status = PCIE_DEVSTS_CE_DETECTED;
	else
		data->pcie_err_status = PCIE_DEVSTS_NFE_DETECTED;

	/* Fill in the AER UE register */
	data->pcie_ue_status = entry->pcie_ue_sts;

	/* Fill in the AER Control register */
	temp = entry->pcie_ue_sts;
	for (data->pcie_adv_ctl = (uint32_t)-1; temp; data->pcie_adv_ctl++)
		temp = temp >> 1;

	/* Send target ereports */
	data->pcie_ue_no_tgt_erpt = B_TRUE;
	if (entry->tgt_class && !epktp->rc_descr.STOP) {
		if (epktp->rc_descr.D) {
			data->pcie_ue_tgt_trans = PF_ADDR_DMA;
			data->pcie_ue_tgt_addr = epktp->addr;
		} else if (epktp->rc_descr.M) {
			data->pcie_ue_tgt_trans = PF_ADDR_PIO;
			data->pcie_ue_tgt_addr = epktp->addr;
		}

		if (data->pcie_ue_tgt_trans)
			fab_send_tgt_erpt(hdl, data, entry->tgt_class,
			    B_TRUE);
	}
	return (1);
}

void
fab_xlate_epkt_erpts(fmd_hdl_t *hdl, nvlist_t *nvl, const char *class)
{
	fab_data_t data = {0};
	px_rc_err_t epkt = {0};
	pcie_tlp_hdr_t *tlp_hdr;
	void *ptr;
	uint8_t ver;
	int err;
	char *rppath = NULL;
	nvlist_t *detector;

	fmd_hdl_debug(hdl, "epkt ereport received: %s\n", class);
	fab_epkt_to_data(hdl, nvl, &data);

	err = nvlist_lookup_uint8(nvl, "epkt_ver", &ver);
	err |= nvlist_lookup_uint32(nvl, "desc", (uint32_t *)&epkt.rc_descr);
	err |= nvlist_lookup_uint32(nvl, "size", &epkt.size);
	err |= nvlist_lookup_uint64(nvl, "addr", &epkt.addr);
	err |= nvlist_lookup_uint64(nvl, "hdr1", &epkt.hdr[0]);
	err |= nvlist_lookup_uint64(nvl, "hdr2", &epkt.hdr[1]);
	err |= nvlist_lookup_uint64(nvl, "reserved", &epkt.reserved);

	if (err != 0) {
		fmd_hdl_debug(hdl, "Failed to retrieve all epkt payloads");
		return;
	}

	fmd_hdl_debug(hdl, "epkt flags: %c%c%c%c%c%c%c%c%c %s",
	    epkt.rc_descr.S ? 'S' : '-', epkt.rc_descr.M ? 'M' : '-',
	    epkt.rc_descr.S ? 'Q' : '-', epkt.rc_descr.D ? 'D' : '-',
	    epkt.rc_descr.R ? 'R' : '-', epkt.rc_descr.H ? 'H' : '-',
	    epkt.rc_descr.C ? 'C' : '-', epkt.rc_descr.I ? 'I' : '-',
	    epkt.rc_descr.B ? 'B' : '-', epkt.rc_descr.STOP ? "STOP" : "");

	/*
	 * If the least byte of the 'reserved' is non zero, it is device
	 * and function of the port
	 */
	if (epkt.reserved && 0xff)
		rppath = fab_find_rppath_by_df(hdl, nvl, epkt.reserved & 0xff);

	if (epkt.rc_descr.H) {
		data.pcie_ue_hdr[0] = (uint32_t)(epkt.hdr[0] >> 32);
		data.pcie_ue_hdr[1] = (uint32_t)epkt.hdr[0];
		data.pcie_ue_hdr[2] = (uint32_t)(epkt.hdr[1] >> 32);
		data.pcie_ue_hdr[3] = (uint32_t)(epkt.hdr[1]);

		tlp_hdr = (pcie_tlp_hdr_t *)&data.pcie_ue_hdr[0];
		ptr = &data.pcie_ue_hdr[1];
		switch (tlp_hdr->type) {
		case PCIE_TLP_TYPE_IO:
		case PCIE_TLP_TYPE_MEM:
		case PCIE_TLP_TYPE_MEMLK:
		{
			pcie_mem64_t *pmp = ptr;
			data.pcie_ue_tgt_trans = PF_ADDR_PIO;
			data.pcie_ue_tgt_bdf = pmp->rid;
			if (tlp_hdr->fmt & 0x1)
				data.pcie_ue_tgt_addr =
				    ((uint64_t)pmp->addr1 << 32) | pmp->addr0;
			else
				data.pcie_ue_tgt_addr =
				    ((pcie_memio32_t *)ptr)->addr0;

			break;
		}

		case PCIE_TLP_TYPE_CFG0:
		case PCIE_TLP_TYPE_CFG1:
		{
			pcie_cfg_t *pcp = ptr;

			data.pcie_ue_tgt_trans = PF_ADDR_CFG;
			data.pcie_ue_tgt_bdf =
			    (pcp->bus << 8) | (pcp->dev << 3) | pcp->func;
			break;
		}

		case PCIE_TLP_TYPE_CPL:
		case PCIE_TLP_TYPE_CPLLK:
			data.pcie_ue_tgt_bdf = ((pcie_cpl_t *)ptr)->rid;
			break;
		}

		fmd_hdl_debug(hdl, "HEADER 0 0x%x", data.pcie_ue_hdr[0]);
		fmd_hdl_debug(hdl, "HEADER 1 0x%x", data.pcie_ue_hdr[1]);
		fmd_hdl_debug(hdl, "HEADER 2 0x%x", data.pcie_ue_hdr[2]);
		fmd_hdl_debug(hdl, "HEADER 3 0x%x", data.pcie_ue_hdr[3]);
		fmd_hdl_debug(hdl, "In header bdf = %#hx addr = %#llx",
		    data.pcie_ue_tgt_bdf,
		    (uint64_t)data.pcie_ue_tgt_addr);

		/* find the root port to which this error is related */
		if (data.pcie_ue_tgt_bdf)
			rppath = fab_find_rppath_by_devbdf(hdl, nvl,
			    data.pcie_ue_tgt_bdf);
	}

	/*
	 * reset the detector in the original ereport to the root port
	 */
	if (rppath && nvlist_alloc(&detector, NV_UNIQUE_NAME, 0) == 0) {
		(void) nvlist_add_string(detector, FM_VERSION,
		    FM_DEV_SCHEME_VERSION);
		(void) nvlist_add_string(detector, FM_FMRI_SCHEME,
		    FM_FMRI_SCHEME_DEV);
		(void) nvlist_add_string(detector, FM_FMRI_DEV_PATH, rppath);
		(void) nvlist_remove_all(nvl, FM_EREPORT_DETECTOR);
		(void) nvlist_add_nvlist(nvl, FM_EREPORT_DETECTOR, detector);
		nvlist_free(detector);
	}

	fmd_hdl_strfree(hdl, rppath);

	(void) fab_xlate_epkt(hdl, &data, &epkt);
	fab_xlate_pcie_erpts(hdl, &data);
}
