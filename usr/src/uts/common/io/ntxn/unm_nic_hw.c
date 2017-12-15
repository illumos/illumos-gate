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
 * Copyright 2008 NetXen, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strlog.h>
#include <sys/kmem.h>
#include <sys/stat.h>
#include <sys/kstat.h>
#include <sys/vtrace.h>
#include <sys/dlpi.h>
#include <sys/strsun.h>
#include <sys/ethernet.h>
#include <sys/modctl.h>
#include <sys/errno.h>
#include <sys/dditypes.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sysmacros.h>

#include <sys/pci.h>

#include "unm_nic.h"
#include "unm_nic_hw.h"
#include "nic_cmn.h"
#include "unm_brdcfg.h"
#include "driver_info.h"

long unm_niu_gbe_phy_read(struct unm_adapter_s *,
		long reg, unm_crbword_t *readval);

#define	MASK(n)			((1ULL<<(n))-1)
#define	MN_WIN(addr) (((addr & 0x1fc0000) >> 1) | ((addr >> 25) & 0x3ff))
#define	OCM_WIN(addr) (((addr & 0x1ff0000) >> 1) |	\
		((addr >> 25) & 0x3ff)) // 64K?
#define	MS_WIN(addr) (addr & 0x0ffc0000)
#define	UNM_PCI_MN_2M   (0)
#define	UNM_PCI_MS_2M   (0x80000)
#define	UNM_PCI_OCM0_2M (0xc0000)
#define	VALID_OCM_ADDR(addr) (((addr) & 0x3f800) != 0x3f800)
#define	GET_MEM_OFFS_2M(addr) (addr & MASK(18))

#define	CRB_BLK(off)	((off >> 20) & 0x3f)
#define	CRB_SUBBLK(off)	((off >> 16) & 0xf)
#define	CRB_WINDOW_2M	(0x130060)
#define	UNM_PCI_CAMQM_2M_END	(0x04800800UL)
#define	CRB_HI(off)	((crb_hub_agt[CRB_BLK(off)] << 20) | ((off) & 0xf0000))
#define	UNM_PCI_CAMQM_2M_BASE	(0x000ff800UL)
#define	CRB_INDIRECT_2M	(0x1e0000UL)

static crb_128M_2M_block_map_t	crb_128M_2M_map[64] = {
	    {{{0, 0, 0, 0}}}, /* 0: PCI */
	    {{{1, 0x0100000, 0x0102000, 0x120000}, /* 1: PCIE */
	    {1, 0x0110000, 0x0120000, 0x130000},
	    {1, 0x0120000, 0x0122000, 0x124000},
	    {1, 0x0130000, 0x0132000, 0x126000},
	    {1, 0x0140000, 0x0142000, 0x128000},
	    {1, 0x0150000, 0x0152000, 0x12a000},
	    {1, 0x0160000, 0x0170000, 0x110000},
	    {1, 0x0170000, 0x0172000, 0x12e000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {1, 0x01e0000, 0x01e0800, 0x122000},
	    {0, 0x0000000, 0x0000000, 0x000000}}},
	    {{{1, 0x0200000, 0x0210000, 0x180000}}}, /* 2: MN */
	    {{{0, 0, 0, 0}}}, /* 3: */
	    {{{1, 0x0400000, 0x0401000, 0x169000}}}, /* 4: P2NR1 */
	    {{{1, 0x0500000, 0x0510000, 0x140000}}}, /* 5: SRE   */
	    {{{1, 0x0600000, 0x0610000, 0x1c0000}}}, /* 6: NIU   */
	    {{{1, 0x0700000, 0x0704000, 0x1b8000}}}, /* 7: QM    */
	    {{{1, 0x0800000, 0x0802000, 0x170000}, /* 8: SQM0  */
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {1, 0x08f0000, 0x08f2000, 0x172000}}},
	    {{{1, 0x0900000, 0x0902000, 0x174000}, /* 9: SQM1 */
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {1, 0x09f0000, 0x09f2000, 0x176000}}},
	    {{{0, 0x0a00000, 0x0a02000, 0x178000}, /* 10: SQM2 */
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {1, 0x0af0000, 0x0af2000, 0x17a000}}},
	    {{{0, 0x0b00000, 0x0b02000, 0x17c000}, /* 11: SQM3 */
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {1, 0x0bf0000, 0x0bf2000, 0x17e000}}},
	    {{{1, 0x0c00000, 0x0c04000, 0x1d4000}}}, /* 12: I2Q */
	    {{{1, 0x0d00000, 0x0d04000, 0x1a4000}}}, /* 13: TMR */
	    {{{1, 0x0e00000, 0x0e04000, 0x1a0000}}}, /* 14: ROMUSB */
	    {{{1, 0x0f00000, 0x0f01000, 0x164000}}}, /* 15: PEG4 */
	    {{{0, 0x1000000, 0x1004000, 0x1a8000}}}, /* 16: XDMA */
	    {{{1, 0x1100000, 0x1101000, 0x160000}}}, /* 17: PEG0 */
	    {{{1, 0x1200000, 0x1201000, 0x161000}}}, /* 18: PEG1 */
	    {{{1, 0x1300000, 0x1301000, 0x162000}}}, /* 19: PEG2 */
	    {{{1, 0x1400000, 0x1401000, 0x163000}}}, /* 20: PEG3 */
	    {{{1, 0x1500000, 0x1501000, 0x165000}}}, /* 21: P2ND */
	    {{{1, 0x1600000, 0x1601000, 0x166000}}}, /* 22: P2NI */
	    {{{0, 0, 0, 0}}}, /* 23: */
	    {{{0, 0, 0, 0}}}, /* 24: */
	    {{{0, 0, 0, 0}}}, /* 25: */
	    {{{0, 0, 0, 0}}}, /* 26: */
	    {{{0, 0, 0, 0}}}, /* 27: */
	    {{{0, 0, 0, 0}}}, /* 28: */
	    {{{1, 0x1d00000, 0x1d10000, 0x190000}}}, /* 29: MS */
	    {{{1, 0x1e00000, 0x1e01000, 0x16a000}}}, /* 30: P2NR2 */
	    {{{1, 0x1f00000, 0x1f10000, 0x150000}}}, /* 31: EPG */
	    {{{0}}}, /* 32: PCI */
	    {{{1, 0x2100000, 0x2102000, 0x120000}, /* 33: PCIE */
	    {1, 0x2110000, 0x2120000, 0x130000},
	    {1, 0x2120000, 0x2122000, 0x124000},
	    {1, 0x2130000, 0x2132000, 0x126000},
	    {1, 0x2140000, 0x2142000, 0x128000},
	    {1, 0x2150000, 0x2152000, 0x12a000},
	    {1, 0x2160000, 0x2170000, 0x110000},
	    {1, 0x2170000, 0x2172000, 0x12e000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000}}},
	    {{{1, 0x2200000, 0x2204000, 0x1b0000}}}, /* 34: CAM */
	    {{{0}}}, /* 35: */
	    {{{0}}}, /* 36: */
	    {{{0}}}, /* 37: */
	    {{{0}}}, /* 38: */
	    {{{0}}}, /* 39: */
	    {{{1, 0x2800000, 0x2804000, 0x1a4000}}}, /* 40: TMR */
	    {{{1, 0x2900000, 0x2901000, 0x16b000}}}, /* 41: P2NR3 */
	    {{{1, 0x2a00000, 0x2a00400, 0x1ac400}}}, /* 42: RPMX1 */
	    {{{1, 0x2b00000, 0x2b00400, 0x1ac800}}}, /* 43: RPMX2 */
	    {{{1, 0x2c00000, 0x2c00400, 0x1acc00}}}, /* 44: RPMX3 */
	    {{{1, 0x2d00000, 0x2d00400, 0x1ad000}}}, /* 45: RPMX4 */
	    {{{1, 0x2e00000, 0x2e00400, 0x1ad400}}}, /* 46: RPMX5 */
	    {{{1, 0x2f00000, 0x2f00400, 0x1ad800}}}, /* 47: RPMX6 */
	    {{{1, 0x3000000, 0x3000400, 0x1adc00}}}, /* 48: RPMX7 */
	    {{{0, 0x3100000, 0x3104000, 0x1a8000}}}, /* 49: XDMA */
	    {{{1, 0x3200000, 0x3204000, 0x1d4000}}}, /* 50: I2Q */
	    {{{1, 0x3300000, 0x3304000, 0x1a0000}}}, /* 51: ROMUSB */
	    {{{0}}}, /* 52: */
	    {{{1, 0x3500000, 0x3500400, 0x1ac000}}}, /* 53: RPMX0 */
	    {{{1, 0x3600000, 0x3600400, 0x1ae000}}}, /* 54: RPMX8 */
	    {{{1, 0x3700000, 0x3700400, 0x1ae400}}}, /* 55: RPMX9 */
	    {{{1, 0x3800000, 0x3804000, 0x1d0000}}}, /* 56: OCM0 */
	    {{{1, 0x3900000, 0x3904000, 0x1b4000}}}, /* 57: CRYPTO */
	    {{{1, 0x3a00000, 0x3a04000, 0x1d8000}}}, /* 58: SMB */
	    {{{0}}}, /* 59: I2C0 */
	    {{{0}}}, /* 60: I2C1 */
	    {{{1, 0x3d00000, 0x3d04000, 0x1d8000}}}, /* 61: LPC */
	    {{{1, 0x3e00000, 0x3e01000, 0x167000}}}, /* 62: P2NC */
	    {{{1, 0x3f00000, 0x3f01000, 0x168000}}} /* 63: P2NR0 */
};

/*
 * top 12 bits of crb internal address (hub, agent)
 */
static unsigned crb_hub_agt[64] = {
	0,
	UNM_HW_CRB_HUB_AGT_ADR_PS,
	UNM_HW_CRB_HUB_AGT_ADR_MN,
	UNM_HW_CRB_HUB_AGT_ADR_MS,
	0,
	UNM_HW_CRB_HUB_AGT_ADR_SRE,
	UNM_HW_CRB_HUB_AGT_ADR_NIU,
	UNM_HW_CRB_HUB_AGT_ADR_QMN,
	UNM_HW_CRB_HUB_AGT_ADR_SQN0,
	UNM_HW_CRB_HUB_AGT_ADR_SQN1,
	UNM_HW_CRB_HUB_AGT_ADR_SQN2,
	UNM_HW_CRB_HUB_AGT_ADR_SQN3,
	UNM_HW_CRB_HUB_AGT_ADR_I2Q,
	UNM_HW_CRB_HUB_AGT_ADR_TIMR,
	UNM_HW_CRB_HUB_AGT_ADR_ROMUSB,
	UNM_HW_CRB_HUB_AGT_ADR_PGN4,
	UNM_HW_CRB_HUB_AGT_ADR_XDMA,
	UNM_HW_CRB_HUB_AGT_ADR_PGN0,
	UNM_HW_CRB_HUB_AGT_ADR_PGN1,
	UNM_HW_CRB_HUB_AGT_ADR_PGN2,
	UNM_HW_CRB_HUB_AGT_ADR_PGN3,
	UNM_HW_CRB_HUB_AGT_ADR_PGND,
	UNM_HW_CRB_HUB_AGT_ADR_PGNI,
	UNM_HW_CRB_HUB_AGT_ADR_PGS0,
	UNM_HW_CRB_HUB_AGT_ADR_PGS1,
	UNM_HW_CRB_HUB_AGT_ADR_PGS2,
	UNM_HW_CRB_HUB_AGT_ADR_PGS3,
	0,
	UNM_HW_CRB_HUB_AGT_ADR_PGSI,
	UNM_HW_CRB_HUB_AGT_ADR_SN,
	0,
	UNM_HW_CRB_HUB_AGT_ADR_EG,
	0,
	UNM_HW_CRB_HUB_AGT_ADR_PS,
	UNM_HW_CRB_HUB_AGT_ADR_CAM,
	0,
	0,
	0,
	0,
	0,
	UNM_HW_CRB_HUB_AGT_ADR_TIMR,
	0,
	UNM_HW_CRB_HUB_AGT_ADR_RPMX1,
	UNM_HW_CRB_HUB_AGT_ADR_RPMX2,
	UNM_HW_CRB_HUB_AGT_ADR_RPMX3,
	UNM_HW_CRB_HUB_AGT_ADR_RPMX4,
	UNM_HW_CRB_HUB_AGT_ADR_RPMX5,
	UNM_HW_CRB_HUB_AGT_ADR_RPMX6,
	UNM_HW_CRB_HUB_AGT_ADR_RPMX7,
	UNM_HW_CRB_HUB_AGT_ADR_XDMA,
	UNM_HW_CRB_HUB_AGT_ADR_I2Q,
	UNM_HW_CRB_HUB_AGT_ADR_ROMUSB,
	0,
	UNM_HW_CRB_HUB_AGT_ADR_RPMX0,
	UNM_HW_CRB_HUB_AGT_ADR_RPMX8,
	UNM_HW_CRB_HUB_AGT_ADR_RPMX9,
	UNM_HW_CRB_HUB_AGT_ADR_OCM0,
	0,
	UNM_HW_CRB_HUB_AGT_ADR_SMB,
	UNM_HW_CRB_HUB_AGT_ADR_I2C0,
	UNM_HW_CRB_HUB_AGT_ADR_I2C1,
	0,
	UNM_HW_CRB_HUB_AGT_ADR_PGNC,
	0,
};

#define	CRB_WIN_LOCK_TIMEOUT 100000000

static void
crb_win_lock(struct unm_adapter_s *adapter)
{
	int i;
	int done = 0, timeout = 0;

	while (!done) {
		/* acquire semaphore3 from PCI HW block */
		adapter->unm_nic_hw_read_wx(adapter,
		    UNM_PCIE_REG(PCIE_SEM7_LOCK), &done, 4);
		if (done == 1)
			break;
		if (timeout >= CRB_WIN_LOCK_TIMEOUT) {
			cmn_err(CE_WARN, "%s%d: crb_win_lock timed out\n",
			    adapter->name, adapter->instance);
			return;
		}
		timeout++;
		/*
		 *  Yield CPU
		 */
		for (i = 0; i < 20; i++)
			;
	}
	adapter->unm_crb_writelit_adapter(adapter, UNM_CRB_WIN_LOCK_ID,
	    adapter->portnum);
}

static void
crb_win_unlock(struct unm_adapter_s *adapter)
{
	int	val;

	adapter->unm_nic_hw_read_wx(adapter, UNM_PCIE_REG(PCIE_SEM7_UNLOCK),
	    &val, 4);
}

/*
 * Changes the CRB window to the specified window.
 */
void
unm_nic_pci_change_crbwindow_128M(unm_adapter *adapter, uint32_t wndw)
{
	unm_pcix_crb_window_t	window;
	unsigned long			offset;
	uint32_t				tmp;

	if (adapter->curr_window == wndw) {
		return;
	}

	/*
	 * Move the CRB window.
	 * We need to write to the "direct access" region of PCI
	 * to avoid a race condition where the window register has
	 * not been successfully written across CRB before the target
	 * register address is received by PCI. The direct region bypasses
	 * the CRB bus.
	 */
	offset = PCI_OFFSET_SECOND_RANGE(adapter,
	    UNM_PCIX_PH_REG(PCIE_CRB_WINDOW_REG(adapter->ahw.pci_func)));

	*(unm_crbword_t *)&window = 0;
	window.addrbit = wndw;
	UNM_NIC_PCI_WRITE_32(*(unsigned int *)&window, (void*) (offset));
	/* MUST make sure window is set before we forge on... */
	while ((tmp = UNM_NIC_PCI_READ_32((void*) offset)) !=
	    *(uint32_t *)&window) {
		cmn_err(CE_WARN, "%s: %s WARNING: CRB window value not "
		    "registered properly: 0x%08x.\n",
		    unm_nic_driver_name, __FUNCTION__, tmp);
	}

	adapter->curr_window = wndw;
}


/*
 * Changes the CRB window to the specified window.
 */
/* ARGSUSED */
void
unm_nic_pci_change_crbwindow_2M(unm_adapter *adapter, uint32_t wndw)
{
}


uint32_t
unm_nic_get_crbwindow(unm_adapter *adapter)
{
	return (adapter->curr_window);
}

/*
 * Return -1 if off is not valid,
 *	 1 if window access is needed. 'off' is set to offset from
 *	   CRB space in 128M pci map
 *	 0 if no window access is needed. 'off' is set to 2M addr
 * In: 'off' is offset from base in 128M pci map
 */
int
unm_nic_pci_get_crb_addr_2M(unm_adapter *adapter, u64 *off, int len)
{
	unsigned long end = *off + len;
	crb_128M_2M_sub_block_map_t *m;


	if (*off >= UNM_CRB_MAX)
		return (-1);

	if (*off >= UNM_PCI_CAMQM && (end <= UNM_PCI_CAMQM_2M_END)) {
		*off = (*off - UNM_PCI_CAMQM) + UNM_PCI_CAMQM_2M_BASE +
		    adapter->ahw.pci_base0;
		return (0);
	}

	if (*off < UNM_PCI_CRBSPACE)
		return (-1);

	*off -= UNM_PCI_CRBSPACE;
	end = *off + len;
	/*
	 * Try direct map
	 */

	m = &crb_128M_2M_map[CRB_BLK(*off)].sub_block[CRB_SUBBLK(*off)];

	if (m->valid && (m->start_128M <= *off) && (m->end_128M >= end)) {
		*off = *off + m->start_2M - m->start_128M +
		    adapter->ahw.pci_base0;
		return (0);
	}

	/*
	 * Not in direct map, use crb window
	 */
	return (1);
}
/*
 * In: 'off' is offset from CRB space in 128M pci map
 * Out: 'off' is 2M pci map addr
 * side effect: lock crb window
 */
static void
unm_nic_pci_set_crbwindow_2M(unm_adapter *adapter, u64 *off)
{
	u32 win_read;

	adapter->crb_win = CRB_HI(*off);
	UNM_NIC_PCI_WRITE_32(adapter->crb_win, (void *) (CRB_WINDOW_2M +
	    adapter->ahw.pci_base0));
	/*
	 * Read back value to make sure write has gone through before trying
	 * to use it.
	 */
	win_read = UNM_NIC_PCI_READ_32((void *)
	    (CRB_WINDOW_2M + adapter->ahw.pci_base0));
	if (win_read != adapter->crb_win) {
		cmn_err(CE_WARN, "%s: Written crbwin (0x%x) != Read crbwin "
		    "(0x%x), off=0x%llx\n", __FUNCTION__, adapter->crb_win,
		    win_read, *off);
	}
	*off = (*off & MASK(16)) + CRB_INDIRECT_2M +
	    adapter->ahw.pci_base0;
}

int
unm_nic_hw_write_ioctl_128M(unm_adapter *adapter, u64 off, void *data, int len)
{
	void		*addr;
	u64		offset = off;

	if (ADDR_IN_WINDOW1(off)) { // Window 1
		addr = CRB_NORMALIZE(adapter, off);
		if (!addr) {
			offset = CRB_NORMAL(off);
			if (adapter->ahw.pci_len0 == 0)
				offset -= UNM_PCI_CRBSPACE;
			addr = (void *) ((uint8_t *)adapter->ahw.pci_base0 +
			    offset);
		}
		UNM_READ_LOCK(&adapter->adapter_lock);
	} else {// Window 0
		addr = (void *) (uptr_t)(pci_base_offset(adapter, off));
		if (!addr) {
			offset = off;
			addr = (void *) ((uint8_t *)adapter->ahw.pci_base0 +
			    offset);
		}
		UNM_WRITE_LOCK_IRQS(&adapter->adapter_lock, flags);
		unm_nic_pci_change_crbwindow_128M(adapter, 0);
	}

	switch (len) {
		case 1:
			UNM_NIC_PCI_WRITE_8 (*(__uint8_t *)data, addr);
			break;
		case 2:
			UNM_NIC_PCI_WRITE_16 (*(__uint16_t *)data, addr);
			break;
		case 4:
			UNM_NIC_PCI_WRITE_32 (*(__uint32_t *)data, addr);
			break;
		case 8:
			UNM_NIC_PCI_WRITE_64 (*(__uint64_t *)data, addr);
			break;
		default:
#if !defined(NDEBUG)
		if ((len & 0x7) != 0)
			cmn_err(CE_WARN, "%s: %s len(%d) not multiple of 8.\n",
			    unm_nic_driver_name, __FUNCTION__, len);
#endif
		UNM_NIC_HW_BLOCK_WRITE_64(data, addr, (len>>3));
		break;
	}
	if (ADDR_IN_WINDOW1(off)) {// Window 1
		UNM_READ_UNLOCK(&adapter->adapter_lock);
	} else {// Window 0
		unm_nic_pci_change_crbwindow_128M(adapter, 1);
		UNM_WRITE_UNLOCK_IRQR(&adapter->adapter_lock, flags);
	}

	return (0);
}

/*
 * Note : 'len' argument should be either 1, 2, 4, or a multiple of 8.
 */
int
unm_nic_hw_write_wx_128M(unm_adapter *adapter, u64 off, void *data, int len)
{
	/*
	 * This is modified from _unm_nic_hw_write().
	 * unm_nic_hw_write does not exist now.
	 */

	void *addr;

	if (ADDR_IN_WINDOW1(off)) {// Window 1
		addr = CRB_NORMALIZE(adapter, off);
		UNM_READ_LOCK(&adapter->adapter_lock);
	} else {// Window 0
		addr = (void *) (uptr_t)(pci_base_offset(adapter, off));
		UNM_WRITE_LOCK_IRQS(&adapter->adapter_lock, flags);
		unm_nic_pci_change_crbwindow_128M(adapter, 0);
	}


	if (!addr) {
		if (ADDR_IN_WINDOW1(off)) {// Window 1
			UNM_READ_UNLOCK(&adapter->adapter_lock);
		} else {// Window 0
			unm_nic_pci_change_crbwindow_128M(adapter, 1);
			UNM_WRITE_UNLOCK_IRQR(&adapter->adapter_lock, flags);
		}
		return (1);
	}

	switch (len) {
		case 1:
			UNM_NIC_PCI_WRITE_8 (*(__uint8_t *)data, addr);
			break;
		case 2:
			UNM_NIC_PCI_WRITE_16 (*(__uint16_t *)data, addr);
			break;
		case 4:
			UNM_NIC_PCI_WRITE_32 (*(__uint32_t *)data, addr);
			break;
		case 8:
			UNM_NIC_PCI_WRITE_64 (*(__uint64_t *)data, addr);
			break;
		default:
#if !defined(NDEBUG)
			if ((len & 0x7) != 0)
				cmn_err(CE_WARN,
				    "%s: %s  len(%d) not multiple of 8.\n",
				    unm_nic_driver_name, __FUNCTION__, len);
#endif
			UNM_NIC_HW_BLOCK_WRITE_64(data, addr, (len>>3));
			break;
	}
	if (ADDR_IN_WINDOW1(off)) {// Window 1
		UNM_READ_UNLOCK(&adapter->adapter_lock);
	} else {// Window 0
		unm_nic_pci_change_crbwindow_128M(adapter, 1);
		UNM_WRITE_UNLOCK_IRQR(&adapter->adapter_lock, flags);
	}

	return (0);
}

/*
 * Note : only 32-bit writes!
 */
void
unm_nic_pci_write_normalize_128M(unm_adapter *adapter, u64 off, u32 data)
{
	UNM_NIC_PCI_WRITE_32(data, CRB_NORMALIZE(adapter, off));
}

/*
 * Note : only 32-bit reads!
 */
u32
unm_nic_pci_read_normalize_128M(unm_adapter *adapter, u64 off)
{
	return (UNM_NIC_PCI_READ_32(CRB_NORMALIZE(adapter, off)));
}

/*
 * Note : only 32-bit writes!
 */
int
unm_nic_pci_write_immediate_128M(unm_adapter *adapter, u64 off, u32 *data)
{
	UNM_NIC_PCI_WRITE_32(*data,
	    (void *) (uptr_t)(PCI_OFFSET_SECOND_RANGE(adapter, off)));
	return (0);
}

/*
 * Note : only 32-bit reads!
 */
int
unm_nic_pci_read_immediate_128M(unm_adapter *adapter, u64 off, u32 *data)
{
	*data = UNM_NIC_PCI_READ_32((void *)
	    (uptr_t)(pci_base_offset(adapter, off)));
	return (0);
}

/*
 * Note : only 32-bit writes!
 */
void
unm_nic_pci_write_normalize_2M(unm_adapter *adapter, u64 off, u32 data)
{
	u32 temp = data;

	adapter->unm_nic_hw_write_wx(adapter, off, &temp, 4);
}

/*
 * Note : only 32-bit reads!
 */
u32
unm_nic_pci_read_normalize_2M(unm_adapter *adapter, u64 off)
{
	u32 temp;

	adapter->unm_nic_hw_read_wx(adapter, off, &temp, 4);

	return (temp);
}

/*
 * Note : only 32-bit writes!
 */
int
unm_nic_pci_write_immediate_2M(unm_adapter *adapter, u64 off, u32 *data)
{
	u32 temp = *data;

	adapter->unm_nic_hw_write_wx(adapter, off, &temp, 4);

	return (0);
}

/*
 * Note : only 32-bit reads!
 */
int
unm_nic_pci_read_immediate_2M(unm_adapter *adapter, u64 off, u32 *data)
{
	u32 temp;

	adapter->unm_nic_hw_read_wx(adapter, off, &temp, 4);

	*data = temp;

	return (0);
}

/*
 * write cross hw window boundary is not supported
 * 'len' should be either 1, 2, 4, or multiple of 8
 */
int
unm_nic_hw_write_wx_2M(unm_adapter *adapter, u64 off, void *data, int len)
{
	int rv;

	rv = unm_nic_pci_get_crb_addr_2M(adapter, &off, len);

	if (rv == -1) {
		cmn_err(CE_PANIC, "%s: invalid offset: 0x%016llx\n",
		    __FUNCTION__, off);
		return (-1);
	}

	if (rv == 1) {
		UNM_WRITE_LOCK_IRQS(&adapter->adapter_lock, flags);
		crb_win_lock(adapter);
		unm_nic_pci_set_crbwindow_2M(adapter, &off);
	}

	switch (len) {
	case 1:
		UNM_NIC_PCI_WRITE_8(*(__uint8_t *)data, (void *) (uptr_t)off);
		break;
	case 2:
		UNM_NIC_PCI_WRITE_16(*(__uint16_t *)data, (void *) (uptr_t)off);
		break;
	case 4:
		UNM_NIC_PCI_WRITE_32(*(__uint32_t *)data, (void *) (uptr_t)off);
		break;
	case 8:
		UNM_NIC_PCI_WRITE_64(*(__uint64_t *)data, (void *) (uptr_t)off);
		break;
	default:
#if !defined(NDEBUG)
		if ((len & 0x7) != 0)
			cmn_err(CE_WARN, "%s: %s  len(%d) not multiple of 8.\n",
			    unm_nic_driver_name, __FUNCTION__, len);
#endif
		UNM_NIC_HW_BLOCK_WRITE_64(data, (uptr_t)off, (len>>3));
		break;
	}
	if (rv == 1) {
		crb_win_unlock(adapter);
		UNM_WRITE_UNLOCK_IRQR(&adapter->adapter_lock, flags);
	}

	return (0);
}

int
unm_nic_hw_read_ioctl_128M(unm_adapter *adapter, u64 off, void *data, int len)
{
	void		*addr;
	u64		offset;

	if (ADDR_IN_WINDOW1(off)) {// Window 1
		addr = CRB_NORMALIZE(adapter, off);
		if (!addr) {
			offset = CRB_NORMAL(off);
			if (adapter->ahw.pci_len0 == 0)
				offset -= UNM_PCI_CRBSPACE;
			addr = (void *) ((uint8_t *)adapter->ahw.pci_base0 +
			    offset);
		}
		UNM_READ_LOCK(&adapter->adapter_lock);
	} else {// Window 0
		addr = (void *) (uptr_t)(pci_base_offset(adapter, off));
		if (!addr) {
			offset = off;
			addr = (void *) ((uint8_t *)adapter->ahw.pci_base0 +
			    offset);
		}
		UNM_WRITE_LOCK_IRQS(&adapter->adapter_lock, flags);
		unm_nic_pci_change_crbwindow_128M(adapter, 0);
	}

	switch (len) {
	case 1:
		*(__uint8_t  *)data = UNM_NIC_PCI_READ_8(addr);
		break;
	case 2:
		*(__uint16_t *)data = UNM_NIC_PCI_READ_16(addr);
		break;
	case 4:
		*(__uint32_t *)data = UNM_NIC_PCI_READ_32(addr);
		break;
	case 8:
		*(__uint64_t *)data = UNM_NIC_PCI_READ_64(addr);
		break;
	default:
#if !defined(NDEBUG)
		if ((len & 0x7) != 0)
			cmn_err(CE_WARN, "%s: %s len(%d) not multiple of 8.\n",
			    unm_nic_driver_name, __FUNCTION__, len);
#endif
		UNM_NIC_HW_BLOCK_READ_64(data, addr, (len>>3));
		break;
	}

	if (ADDR_IN_WINDOW1(off)) {// Window 1
		UNM_READ_UNLOCK(&adapter->adapter_lock);
	} else {// Window 0
		unm_nic_pci_change_crbwindow_128M(adapter, 1);
		UNM_WRITE_UNLOCK_IRQR(&adapter->adapter_lock, flags);
	}

	return (0);
}

int
unm_nic_hw_read_wx_2M(unm_adapter *adapter, u64 off, void *data, int len)
{
	int rv;

	rv = unm_nic_pci_get_crb_addr_2M(adapter, &off, len);

	if (rv == -1) {
		cmn_err(CE_PANIC, "%s: invalid offset: 0x%016llx\n",
		    __FUNCTION__, off);
		return (-1);
	}

	if (rv == 1) {
		UNM_WRITE_LOCK_IRQS(&adapter->adapter_lock, flags);
		crb_win_lock(adapter);
		unm_nic_pci_set_crbwindow_2M(adapter, &off);
	}

	switch (len) {
	case 1:
		*(__uint8_t  *)data = UNM_NIC_PCI_READ_8((void *) (uptr_t)off);
		break;
	case 2:
		*(__uint16_t *)data = UNM_NIC_PCI_READ_16((void *) (uptr_t)off);
		break;
	case 4:
		*(__uint32_t *)data = UNM_NIC_PCI_READ_32((void *) (uptr_t)off);
		break;
	case 8:
		*(__uint64_t *)data = UNM_NIC_PCI_READ_64((void *) (uptr_t)off);
		break;
	default:
#if !defined(NDEBUG)
		if ((len & 0x7) != 0)
			cmn_err(CE_WARN, "%s: %s len(%d) not multiple of 8.\n",
			    unm_nic_driver_name, __FUNCTION__, len);
#endif
		UNM_NIC_HW_BLOCK_READ_64(data, (void *) (uptr_t)off, (len>>3));
		break;
	}

	if (rv == 1) {
		crb_win_unlock(adapter);
		UNM_WRITE_UNLOCK_IRQR(&adapter->adapter_lock, flags);
	}

	return (0);
}

int
unm_nic_hw_read_wx_128M(unm_adapter *adapter, u64 off, void *data, int len)
{
	void *addr;

	if (ADDR_IN_WINDOW1(off)) {
		// Window 1
		addr = CRB_NORMALIZE(adapter, off);
		UNM_READ_LOCK(&adapter->adapter_lock);
	} else {// Window 0
		addr = (void *) (uptr_t)(pci_base_offset(adapter, off));
		UNM_WRITE_LOCK_IRQS(&adapter->adapter_lock, flags);
		unm_nic_pci_change_crbwindow_128M(adapter, 0);
	}

	if (!addr) {
		if (ADDR_IN_WINDOW1(off)) {// Window 1
			UNM_READ_UNLOCK(&adapter->adapter_lock);
		} else {// Window 0
			unm_nic_pci_change_crbwindow_128M(adapter, 1);
			UNM_WRITE_UNLOCK_IRQR(&adapter->adapter_lock, flags);
		}
		return (1);
	}

	switch (len) {
		case 1:
			*(__uint8_t  *)data = UNM_NIC_PCI_READ_8(addr);
			break;
		case 2:
			*(__uint16_t *)data = UNM_NIC_PCI_READ_16(addr);
			break;
		case 4:
			*(__uint32_t *)data = UNM_NIC_PCI_READ_32(addr);
			break;
		case 8:
			*(__uint64_t *)data = UNM_NIC_PCI_READ_64(addr);
			break;
		default:
#if !defined(NDEBUG)
			if ((len & 0x7) != 0)
				cmn_err(CE_WARN,
				    "%s: %s len(%d) not multiple of 8.\n",
				    unm_nic_driver_name, __FUNCTION__, len);
#endif
			UNM_NIC_HW_BLOCK_READ_64(data, addr, (len>>3));
			break;
	}

	if (ADDR_IN_WINDOW1(off)) {// Window 1
		UNM_READ_UNLOCK(&adapter->adapter_lock);
	} else {// Window 0
		unm_nic_pci_change_crbwindow_128M(adapter, 1);
		UNM_WRITE_UNLOCK_IRQR(&adapter->adapter_lock, flags);
	}

	return (0);
}

/*  PCI Windowing for DDR regions.  */
#define	ADDR_IN_RANGE(addr, low, high)	    \
	(((addr) <= (high)) && ((low) ? ((addr) >= (low)) : 1))

/*
 * check memory access boundary.
 * used by test agent. support ddr access only for now
 */
/* ARGSUSED */
static unsigned long
unm_nic_pci_mem_bound_check(struct unm_adapter_s *adapter,
    unsigned long long addr, int size)
{
	if (!ADDR_IN_RANGE(addr, UNM_ADDR_DDR_NET, UNM_ADDR_DDR_NET_MAX) ||
	    !ADDR_IN_RANGE(addr + size -1, UNM_ADDR_DDR_NET,
	    UNM_ADDR_DDR_NET_MAX) || ((size != 1) && (size != 2) &&
	    (size != 4) && (size != 8)))
		return (0);

	return (1);
}

int unm_pci_set_window_warning_count = 0;

unsigned long long
unm_nic_pci_set_window_128M(struct unm_adapter_s *adapter,
    unsigned long long addr)
{
	int		window;
	unsigned long long	qdr_max;

	if (NX_IS_REVISION_P2(adapter->ahw.revision_id)) {
		qdr_max = NX_P2_ADDR_QDR_NET_MAX;
	} else {
		qdr_max = NX_P3_ADDR_QDR_NET_MAX;
	}

	if (ADDR_IN_RANGE(addr, UNM_ADDR_DDR_NET, UNM_ADDR_DDR_NET_MAX)) {
		/* DDR network side */
		/* MN access should never come here */
		cmn_err(CE_PANIC, "%s\n", __FUNCTION__);
		addr = -1ULL;
	} else if (ADDR_IN_RANGE(addr, UNM_ADDR_OCM0, UNM_ADDR_OCM0_MAX)) {
		addr -= UNM_ADDR_OCM0;
		addr += UNM_PCI_OCM0;
	} else if (ADDR_IN_RANGE(addr, UNM_ADDR_OCM1, UNM_ADDR_OCM1_MAX)) {
		addr -= UNM_ADDR_OCM1;
		addr += UNM_PCI_OCM1;
	} else if (ADDR_IN_RANGE(addr, UNM_ADDR_QDR_NET, qdr_max)) {
		/* QDR network side */
		addr -= UNM_ADDR_QDR_NET;
		window = (addr >> 22) & 0x3f;
		if (adapter->ahw.qdr_sn_window != window) {
			adapter->ahw.qdr_sn_window = window;
			UNM_NIC_PCI_WRITE_32((window << 22),
			    (void *) (uptr_t)(PCI_OFFSET_SECOND_RANGE(adapter,
			    UNM_PCIX_PH_REG(PCIE_SN_WINDOW_REG(
			    adapter->ahw.pci_func)))));
			/* MUST make sure window is set before we forge on... */
			(void) UNM_NIC_PCI_READ_32((void *)
			    (uptr_t)(PCI_OFFSET_SECOND_RANGE(adapter,
			    UNM_PCIX_PH_REG(PCIE_SN_WINDOW_REG(
			    adapter->ahw.pci_func)))));
		}
		addr -= (window * 0x400000);
		addr += UNM_PCI_QDR_NET;
	} else {
		/*
		 * peg gdb frequently accesses memory that doesn't exist,
		 * this limits the chit chat so debugging isn't slowed down.
		 */
		if ((unm_pci_set_window_warning_count++ < 8) ||
		    (unm_pci_set_window_warning_count%64 == 0)) {
			cmn_err(CE_WARN, "%s: Warning:unm_nic_pci_set_window() "
			    "Unknown address range!\n", unm_nic_driver_name);
		}
		addr = -1ULL;
	}
	return (addr);
}

unsigned long long
unm_nic_pci_set_window_2M(struct unm_adapter_s *adapter,
    unsigned long long addr)
{
	int window;
	u32 win_read;

	if (ADDR_IN_RANGE(addr, UNM_ADDR_DDR_NET, UNM_ADDR_DDR_NET_MAX)) {
		/* DDR network side */
		window = MN_WIN(addr);
		adapter->ahw.ddr_mn_window = window;
		adapter->unm_nic_hw_write_wx(adapter, adapter->ahw.mn_win_crb |
		    UNM_PCI_CRBSPACE, &window, 4);
		adapter->unm_nic_hw_read_wx(adapter, adapter->ahw.mn_win_crb |
		    UNM_PCI_CRBSPACE, &win_read, 4);
		if ((win_read << 17) != window) {
			cmn_err(CE_WARN,
			    "%s: Written MNwin (0x%x) != Read MNwin (0x%x)\n",
			    __FUNCTION__, window, win_read);
		}
		addr = GET_MEM_OFFS_2M(addr) + UNM_PCI_DDR_NET;
	} else if (ADDR_IN_RANGE(addr, UNM_ADDR_OCM0, UNM_ADDR_OCM0_MAX)) {
		unsigned int temp1;
// OCM: pci_addr[20:18] == 011 && pci_addr[17:11] != 7f
		if ((addr & 0x00ff800) == 0xff800) {
			// if bits 19:18&17:11 are on
			cmn_err(CE_WARN, "%s: QM access not handled.\n",
			    __FUNCTION__);
			addr = -1ULL;
		}

		window = OCM_WIN(addr);
		adapter->ahw.ddr_mn_window = window;
		adapter->unm_nic_hw_write_wx(adapter, adapter->ahw.mn_win_crb |
		    UNM_PCI_CRBSPACE, &window, 4);
		adapter->unm_nic_hw_read_wx(adapter, adapter->ahw.mn_win_crb |
		    UNM_PCI_CRBSPACE, &win_read, 4);
		temp1 = ((window & 0x1FF) << 7) |
		    ((window & 0x0FFFE0000) >> 17);
		if (win_read != temp1) {
			cmn_err(CE_WARN,
			    "%s: Written OCMwin(0x%x) != Read OCMwin(0x%x)\n",
			    __FUNCTION__, temp1, win_read);
		}
		addr = GET_MEM_OFFS_2M(addr) + UNM_PCI_OCM0_2M;

	} else if (ADDR_IN_RANGE(addr, UNM_ADDR_QDR_NET,
	    NX_P3_ADDR_QDR_NET_MAX)) {
		/* QDR network side */
		window = MS_WIN(addr);
		adapter->ahw.qdr_sn_window = window;
		adapter->unm_nic_hw_write_wx(adapter, adapter->ahw.ms_win_crb |
		    UNM_PCI_CRBSPACE, &window, 4);
		adapter->unm_nic_hw_read_wx(adapter, adapter->ahw.ms_win_crb |
		    UNM_PCI_CRBSPACE, &win_read, 4);
		if (win_read != window) {
			cmn_err(CE_WARN,
			    "%s: Written MSwin (0x%x) != Read MSwin (0x%x)\n",
			    __FUNCTION__, window, win_read);
		}
		addr = GET_MEM_OFFS_2M(addr) + UNM_PCI_QDR_NET;

	} else {
		/*
		 * peg gdb frequently accesses memory that doesn't exist,
		 * this limits the chit chat so debugging isn't slowed down.
		 */
		if ((unm_pci_set_window_warning_count++ < 8) ||
		    (unm_pci_set_window_warning_count%64 == 0)) {
			cmn_err(CE_WARN, "%s%d: %s Unknown address range!\n",
			    adapter->name, adapter->instance, __FUNCTION__);
		}
		addr = -1ULL;
	}
	return (addr);
}

/* check if address is in the same windows as the previous access */
static unsigned long
unm_nic_pci_is_same_window(struct unm_adapter_s *adapter,
    unsigned long long addr)
{
	int			window;
	unsigned long long	qdr_max;

	if (NX_IS_REVISION_P2(adapter->ahw.revision_id)) {
		qdr_max = NX_P2_ADDR_QDR_NET_MAX;
	} else {
		qdr_max = NX_P3_ADDR_QDR_NET_MAX;
	}

	if (ADDR_IN_RANGE(addr, UNM_ADDR_DDR_NET, UNM_ADDR_DDR_NET_MAX)) {
		/* DDR network side */
		/* MN access can not come here */
		cmn_err(CE_PANIC, "%s\n", __FUNCTION__);
#if 0
		window = ((addr - UNM_ADDR_DDR_NET) >> 25) & 0x3ff;
		if (adapter->ahw.ddr_mn_window == window) {
			return (1);
		}
#endif
	} else if (ADDR_IN_RANGE(addr, UNM_ADDR_OCM0, UNM_ADDR_OCM0_MAX)) {
		return (1);
	} else if (ADDR_IN_RANGE(addr, UNM_ADDR_OCM1, UNM_ADDR_OCM1_MAX)) {
		return (1);
	} else if (ADDR_IN_RANGE(addr, UNM_ADDR_QDR_NET, qdr_max)) {
		/* QDR network side */
		window = ((addr - UNM_ADDR_QDR_NET) >> 22) & 0x3f;
		if (adapter->ahw.qdr_sn_window == window) {
			return (1);
		}
	}

	return (0);
}

static int
unm_nic_pci_mem_read_direct(struct unm_adapter_s *adapter,
    u64 off, void *data, int size)
{
	void			*addr;
	int				ret = 0;
	u64				start;

#if 0
	/*
	 * This check can not be currently executed, since phanmon findq
	 * command breaks this check whereby 8 byte reads are being attempted
	 * on "aligned-by-4" addresses on x86. Reason this works is our version
	 * breaks up the access into 2 consecutive 4 byte writes; on other
	 * architectures, this might require "aligned-by-8" addresses and we
	 * will run into trouble.
	 *
	 * Check alignment for expected sizes of 1, 2, 4, 8. Other size
	 * values will not trigger access.
	 */
	if ((off & (size - 1)) != 0)
		return (-1);
#endif

	UNM_WRITE_LOCK_IRQS(&adapter->adapter_lock, flags);

	/*
	 * If attempting to access unknown address or straddle hw windows,
	 * do not access.
	 */
	if (((start = adapter->unm_nic_pci_set_window(adapter, off)) == -1UL) ||
	    (unm_nic_pci_is_same_window(adapter, off + size -1) == 0)) {
		UNM_WRITE_UNLOCK_IRQR(&adapter->adapter_lock, flags);
		cmn_err(CE_WARN, "%s out of bound pci memory access. "
		    "offset is 0x%llx\n", unm_nic_driver_name, off);
		return (-1);
	}

	addr = (void *) (uptr_t)(pci_base_offset(adapter, start));
	if (!addr)
		addr = (void *) ((uint8_t *)adapter->ahw.pci_base0 + start);

	switch (size) {
		case 1:
			*(__uint8_t  *)data = UNM_NIC_PCI_READ_8(addr);
			break;
		case 2:
			*(__uint16_t *)data = UNM_NIC_PCI_READ_16(addr);
			break;
		case 4:
			*(__uint32_t *)data = UNM_NIC_PCI_READ_32(addr);
			break;
		case 8:
			*(__uint64_t *)data = UNM_NIC_PCI_READ_64(addr);
			break;
		default:
			ret = -1;
			break;
	}

	UNM_WRITE_UNLOCK_IRQR(&adapter->adapter_lock, flags);
	return (ret);
}

static int
unm_nic_pci_mem_write_direct(struct unm_adapter_s *adapter, u64 off,
    void *data, int size)
{
	void	*addr;
	int		ret = 0;
	u64		start;

#if 0
	/*
	 * This check can not be currently executed, since firmware load
	 * breaks this check whereby 8 byte writes are being attempted on
	 * "aligned-by-4" addresses on x86. Reason this works is our version
	 * breaks up the access into 2 consecutive 4 byte writes; on other
	 * architectures, this might require "aligned-by-8" addresses and we
	 * will run into trouble.
	 *
	 * Check alignment for expected sizes of 1, 2, 4, 8. Other size
	 * values will not trigger access.
	 */
	if ((off & (size - 1)) != 0)
		return (-1);
#endif

	UNM_WRITE_LOCK_IRQS(&adapter->adapter_lock, flags);

	/*
	 * If attempting to access unknown address or straddle hw windows,
	 * do not access.
	 */
	if (((start = adapter->unm_nic_pci_set_window(adapter, off)) == -1UL) ||
	    (unm_nic_pci_is_same_window(adapter, off + size -1) == 0)) {
		UNM_WRITE_UNLOCK_IRQR(&adapter->adapter_lock, flags);
		cmn_err(CE_WARN, "%s out of bound pci memory access. "
		    "offset is 0x%llx\n", unm_nic_driver_name, off);
		return (-1);
	}

	addr = (void *) (uptr_t)(pci_base_offset(adapter, start));
	if (!addr)
		addr = (void *) ((uint8_t *)adapter->ahw.pci_base0 + start);

	switch (size) {
		case 1:
			UNM_NIC_PCI_WRITE_8(*(__uint8_t  *)data, addr);
			break;
		case 2:
			UNM_NIC_PCI_WRITE_16(*(__uint16_t *)data, addr);
			break;
		case 4:
			UNM_NIC_PCI_WRITE_32(*(__uint32_t *)data, addr);
			break;
		case 8:
			UNM_NIC_PCI_WRITE_64(*(__uint64_t *)data, addr);
			break;
		default:
			ret = -1;
			break;
	}
	UNM_WRITE_UNLOCK_IRQR(&adapter->adapter_lock, flags);
	return (ret);
}


int
unm_nic_pci_mem_write_128M(struct unm_adapter_s *adapter, u64 off, void *data,
    int size)
{
	int		i, j, ret = 0, loop, sz[2], off0;
	__uint32_t		temp;
	__uint64_t		off8, mem_crb, tmpw, word[2] = {0, 0};
#define	MAX_CTL_CHECK   1000

	/*
	 * If not MN, go check for MS or invalid.
	 */
	if (unm_nic_pci_mem_bound_check(adapter, off, size) == 0)
		return (unm_nic_pci_mem_write_direct(adapter, off, data, size));

	off8 = off & 0xfffffff8;
	off0 = off & 0x7;
	sz[0] = (size < (8 - off0)) ? size : (8 - off0);
	sz[1] = size - sz[0];
	loop = ((off0 + size - 1) >> 3) + 1;
	/* LINTED: E_FALSE_LOGICAL_EXPR */
	mem_crb = (uptr_t)(pci_base_offset(adapter, UNM_CRB_DDR_NET));

	if ((size != 8) || (off0 != 0))  {
		for (i = 0; i < loop; i++) {
			if (adapter->unm_nic_pci_mem_read(adapter,
			    off8 + (i << 3), &word[i], 8))
				return (-1);
		}
	}

	switch (size) {
		case 1:
			tmpw = *((__uint8_t *)data);
			break;
		case 2:
			tmpw = *((__uint16_t *)data);
			break;
		case 4:
			tmpw = *((__uint32_t *)data);
			break;
		case 8:
		default:
			tmpw = *((__uint64_t *)data);
			break;
	}
	word[0] &= ~((~(~0ULL << (sz[0] * 8))) << (off0 * 8));
	word[0] |= tmpw << (off0 * 8);

	if (loop == 2) {
		word[1] &= ~(~0ULL << (sz[1] * 8));
		word[1] |= tmpw >> (sz[0] * 8);
	}

	UNM_WRITE_LOCK_IRQS(&adapter->adapter_lock, flags);
	unm_nic_pci_change_crbwindow_128M(adapter, 0);

	for (i = 0; i < loop; i++) {
		UNM_NIC_PCI_WRITE_32((__uint32_t)(off8 + (i << 3)),
		    (void *) (uptr_t)(mem_crb+MIU_TEST_AGT_ADDR_LO));
		UNM_NIC_PCI_WRITE_32(0,
		    (void *) (uptr_t)(mem_crb+MIU_TEST_AGT_ADDR_HI));
		UNM_NIC_PCI_WRITE_32(word[i] & 0xffffffff,
		    (void *) (uptr_t)(mem_crb+MIU_TEST_AGT_WRDATA_LO));
		UNM_NIC_PCI_WRITE_32((word[i] >> 32) & 0xffffffff,
		    (void *) (uptr_t)(mem_crb+MIU_TEST_AGT_WRDATA_HI));
		UNM_NIC_PCI_WRITE_32(MIU_TA_CTL_ENABLE|MIU_TA_CTL_WRITE,
		    (void *) (uptr_t)(mem_crb+MIU_TEST_AGT_CTRL));
		UNM_NIC_PCI_WRITE_32(MIU_TA_CTL_START | MIU_TA_CTL_ENABLE |
		    MIU_TA_CTL_WRITE,
		    (void *) (uptr_t)(mem_crb+MIU_TEST_AGT_CTRL));

		for (j = 0; j < MAX_CTL_CHECK; j++) {
			temp = UNM_NIC_PCI_READ_32((void *)
			    (uptr_t)(mem_crb+MIU_TEST_AGT_CTRL));
			if ((temp & MIU_TA_CTL_BUSY) == 0) {
				break;
			}
		}

		if (j >= MAX_CTL_CHECK) {
			cmn_err(CE_WARN, "%s: %s Fail to write thru agent\n",
			    __FUNCTION__, unm_nic_driver_name);
			ret = -1;
			break;
		}
	}

	unm_nic_pci_change_crbwindow_128M(adapter, 1);
	UNM_WRITE_UNLOCK_IRQR(&adapter->adapter_lock, flags);
	return (ret);
}

int
unm_nic_pci_mem_read_128M(struct unm_adapter_s *adapter, u64 off, void *data,
    int size)
{
	int		i, j = 0, k, start, end, loop, sz[2], off0[2];
	__uint32_t		temp;
	__uint64_t		off8, val, mem_crb, word[2] = {0, 0};
#define	MAX_CTL_CHECK   1000

	/*
	 * If not MN, go check for MS or invalid.
	 */
	if (unm_nic_pci_mem_bound_check(adapter, off, size) == 0)
		return (unm_nic_pci_mem_read_direct(adapter, off, data, size));

	off8 = off & 0xfffffff8;
	off0[0] = off & 0x7;
	off0[1] = 0;
	sz[0] = (size < (8 - off0[0])) ? size : (8 - off0[0]);
	sz[1] = size - sz[0];
	loop = ((off0[0] + size - 1) >> 3) + 1;
	/* LINTED: E_FALSE_LOGICAL_EXPR */
	mem_crb = (uptr_t)(pci_base_offset(adapter, UNM_CRB_DDR_NET));

	UNM_WRITE_LOCK_IRQS(&adapter->adapter_lock, flags);
	unm_nic_pci_change_crbwindow_128M(adapter, 0);

	for (i = 0; i < loop; i++) {
		UNM_NIC_PCI_WRITE_32((__uint32_t)(off8 + (i << 3)),
		    (void *) (uptr_t)(mem_crb+MIU_TEST_AGT_ADDR_LO));
		UNM_NIC_PCI_WRITE_32(0,
		    (void *) (uptr_t)(mem_crb+MIU_TEST_AGT_ADDR_HI));
		UNM_NIC_PCI_WRITE_32(MIU_TA_CTL_ENABLE,
		    (void *) (uptr_t)(mem_crb+MIU_TEST_AGT_CTRL));
		UNM_NIC_PCI_WRITE_32(MIU_TA_CTL_START|MIU_TA_CTL_ENABLE,
		    (void *) (uptr_t)(mem_crb+MIU_TEST_AGT_CTRL));

		for (j = 0; j < MAX_CTL_CHECK; j++) {
			temp = UNM_NIC_PCI_READ_32((void *)
			    (uptr_t)(mem_crb+MIU_TEST_AGT_CTRL));
			if ((temp & MIU_TA_CTL_BUSY) == 0) {
				break;
			}
		}

		if (j >= MAX_CTL_CHECK) {
			cmn_err(CE_WARN, "%s: %s Fail to read through agent\n",
			    __FUNCTION__, unm_nic_driver_name);
			break;
		}

		start = off0[i] >> 2;
		end   = (off0[i] + sz[i] - 1) >> 2;
		word[i] = 0;
		for (k = start; k <= end; k++) {
			word[i] |= ((__uint64_t)UNM_NIC_PCI_READ_32(
			    (void *) (uptr_t)(mem_crb +
			    MIU_TEST_AGT_RDDATA(k))) << (32*k));
		}
	}

	unm_nic_pci_change_crbwindow_128M(adapter, 1);
	UNM_WRITE_UNLOCK_IRQR(&adapter->adapter_lock, flags);

	if (j >= MAX_CTL_CHECK)
		return (-1);

	if (sz[0] == 8) {
		val = word[0];
	} else {
		val = ((word[0] >> (off0[0] * 8)) & (~(~0ULL << (sz[0] * 8)))) |
		    ((word[1] & (~(~0ULL << (sz[1] * 8)))) << (sz[0] * 8));
	}

	switch (size) {
	case 1:
		*(__uint8_t  *)data = val;
		break;
	case 2:
		*(__uint16_t *)data = val;
		break;
	case 4:
		*(__uint32_t *)data = val;
		break;
	case 8:
		*(__uint64_t *)data = val;
		break;
	}
	return (0);
}



int
unm_nic_pci_mem_write_2M(struct unm_adapter_s *adapter, u64 off, void *data,
    int size)
{
	int	i, j, ret = 0, loop, sz[2], off0;
	__uint32_t	temp;
	__uint64_t	off8, mem_crb, tmpw, word[2] = {0, 0};
#define	MAX_CTL_CHECK   1000

	/*
	 * If not MN, go check for MS or invalid.
	 */
	if (off >= UNM_ADDR_QDR_NET && off <= NX_P3_ADDR_QDR_NET_MAX) {
		mem_crb = UNM_CRB_QDR_NET;
	} else {
		mem_crb = UNM_CRB_DDR_NET;
		if (unm_nic_pci_mem_bound_check(adapter, off, size) == 0)
			return (unm_nic_pci_mem_write_direct(adapter,
			    off, data, size));
	}

	off8 = off & 0xfffffff8;
	off0 = off & 0x7;
	sz[0] = (size < (8 - off0)) ? size : (8 - off0);
	sz[1] = size - sz[0];
	loop = ((off0 + size - 1) >> 3) + 1;

	if ((size != 8) || (off0 != 0)) {
		for (i = 0; i < loop; i++) {
			if (adapter->unm_nic_pci_mem_read(adapter,
			    off8 + (i << 3), &word[i], 8))
				return (-1);
		}
	}

	switch (size) {
		case 1:
			tmpw = *((__uint8_t *)data);
			break;
		case 2:
			tmpw = *((__uint16_t *)data);
			break;
		case 4:
			tmpw = *((__uint32_t *)data);
			break;
		case 8:
		default:
			tmpw = *((__uint64_t *)data);
			break;
	}

	word[0] &= ~((~(~0ULL << (sz[0] * 8))) << (off0 * 8));
	word[0] |= tmpw << (off0 * 8);

	if (loop == 2) {
		word[1] &= ~(~0ULL << (sz[1] * 8));
		word[1] |= tmpw >> (sz[0] * 8);
	}

// don't lock here - write_wx gets the lock if each time
// UNM_WRITE_LOCK_IRQS(&adapter->adapter_lock, flags);
// unm_nic_pci_change_crbwindow_128M(adapter, 0);

	for (i = 0; i < loop; i++) {
		temp = off8 + (i << 3);
		adapter->unm_nic_hw_write_wx(adapter,
		    mem_crb+MIU_TEST_AGT_ADDR_LO, &temp, 4);
		temp = 0;
		adapter->unm_nic_hw_write_wx(adapter,
		    mem_crb+MIU_TEST_AGT_ADDR_HI, &temp, 4);
		temp = word[i] & 0xffffffff;
		adapter->unm_nic_hw_write_wx(adapter,
		    mem_crb+MIU_TEST_AGT_WRDATA_LO, &temp, 4);
		temp = (word[i] >> 32) & 0xffffffff;
		adapter->unm_nic_hw_write_wx(adapter,
		    mem_crb+MIU_TEST_AGT_WRDATA_HI, &temp, 4);
		temp = MIU_TA_CTL_ENABLE | MIU_TA_CTL_WRITE;
		adapter->unm_nic_hw_write_wx(adapter,
		    mem_crb+MIU_TEST_AGT_CTRL, &temp, 4);
		temp = MIU_TA_CTL_START | MIU_TA_CTL_ENABLE | MIU_TA_CTL_WRITE;
		adapter->unm_nic_hw_write_wx(adapter,
		    mem_crb+MIU_TEST_AGT_CTRL, &temp, 4);

		for (j = 0; j < MAX_CTL_CHECK; j++) {
			adapter->unm_nic_hw_read_wx(adapter,
			    mem_crb + MIU_TEST_AGT_CTRL, &temp, 4);
			if ((temp & MIU_TA_CTL_BUSY) == 0) {
				break;
			}
		}

		if (j >= MAX_CTL_CHECK) {
			cmn_err(CE_WARN, "%s: Fail to write through agent\n",
			    unm_nic_driver_name);
			ret = -1;
			break;
		}
	}

//  unm_nic_pci_change_crbwindow_128M(adapter, 1);
//  UNM_WRITE_UNLOCK_IRQR(&adapter->adapter_lock, flags);
	return (ret);
}

int
unm_nic_pci_mem_read_2M(struct unm_adapter_s *adapter, u64 off, void *data,
    int size)
{
// unsigned long   flags;
	int		i, j = 0, k, start, end, loop, sz[2], off0[2];
	__uint32_t	temp;
	__uint64_t	off8, val, mem_crb, word[2] = {0, 0};
#define	MAX_CTL_CHECK   1000

	/*
	 * If not MN, go check for MS or invalid.
	 */

	if (off >= UNM_ADDR_QDR_NET && off <= NX_P3_ADDR_QDR_NET_MAX) {
		mem_crb = UNM_CRB_QDR_NET;
	} else {
		mem_crb = UNM_CRB_DDR_NET;
		if (unm_nic_pci_mem_bound_check(adapter, off, size) == 0)
			return (unm_nic_pci_mem_read_direct(adapter,
			    off, data, size));
	}

	off8 = off & 0xfffffff8;
	off0[0] = off & 0x7;
	off0[1] = 0;
	sz[0] = (size < (8 - off0[0])) ? size : (8 - off0[0]);
	sz[1] = size - sz[0];
	loop = ((off0[0] + size - 1) >> 3) + 1;

// don't get lock - write_wx will get it
// UNM_WRITE_LOCK_IRQS(&adapter->adapter_lock, flags);
// unm_nic_pci_change_crbwindow_128M(adapter, 0);

	for (i = 0; i < loop; i++) {
		temp = off8 + (i << 3);
		adapter->unm_nic_hw_write_wx(adapter,
		    mem_crb + MIU_TEST_AGT_ADDR_LO, &temp, 4);
		temp = 0;
		adapter->unm_nic_hw_write_wx(adapter,
		    mem_crb + MIU_TEST_AGT_ADDR_HI, &temp, 4);
		temp = MIU_TA_CTL_ENABLE;
		adapter->unm_nic_hw_write_wx(adapter,
		    mem_crb + MIU_TEST_AGT_CTRL, &temp, 4);
		temp = MIU_TA_CTL_START | MIU_TA_CTL_ENABLE;
		adapter->unm_nic_hw_write_wx(adapter,
		    mem_crb + MIU_TEST_AGT_CTRL, &temp, 4);

		for (j = 0; j < MAX_CTL_CHECK; j++) {
			adapter->unm_nic_hw_read_wx(adapter,
			    mem_crb + MIU_TEST_AGT_CTRL, &temp, 4);
			if ((temp & MIU_TA_CTL_BUSY) == 0) {
				break;
			}
		}

		if (j >= MAX_CTL_CHECK) {
			cmn_err(CE_WARN, "%s: Fail to read through agent\n",
			    unm_nic_driver_name);
			break;
		}

		start = off0[i] >> 2;
		end   = (off0[i] + sz[i] - 1) >> 2;
		for (k = start; k <= end; k++) {
			adapter->unm_nic_hw_read_wx(adapter,
			    mem_crb + MIU_TEST_AGT_RDDATA(k), &temp, 4);
			word[i] |= ((__uint64_t)temp << (32 * k));
		}
	}

// unm_nic_pci_change_crbwindow_128M(adapter, 1);
// UNM_WRITE_UNLOCK_IRQR(&adapter->adapter_lock, flags);

	if (j >= MAX_CTL_CHECK)
		return (-1);

	if (sz[0] == 8) {
		val = word[0];
	} else {
		val = ((word[0] >> (off0[0] * 8)) & (~(~0ULL << (sz[0] * 8)))) |
		    ((word[1] & (~(~0ULL << (sz[1] * 8)))) << (sz[0] * 8));
	}

	switch (size) {
		case 1:
			*(__uint8_t  *)data = val;
			break;
		case 2:
			*(__uint16_t *)data = val;
			break;
		case 4:
			*(__uint32_t *)data = val;
			break;
		case 8:
			*(__uint64_t *)data = val;
			break;
	}
	return (0);
}

int
unm_crb_writelit_adapter_2M(struct unm_adapter_s *adapter, unsigned long off,
    int data)
{
	return (unm_nic_hw_write_wx_2M(adapter, off, &data, 4));
}

int
unm_crb_writelit_adapter_128M(struct unm_adapter_s *adapter, unsigned long off,
    int data)
{
	void *addr;

	if (ADDR_IN_WINDOW1(off)) {
		UNM_READ_LOCK(&adapter->adapter_lock);
		UNM_NIC_PCI_WRITE_32(data, CRB_NORMALIZE(adapter, off));
		UNM_READ_UNLOCK(&adapter->adapter_lock);
	} else {
		// unm_nic_write_w0 (adapter, off, data);
		UNM_WRITE_LOCK_IRQS(&adapter->adapter_lock, flags);
		unm_nic_pci_change_crbwindow_128M(adapter, 0);
		addr = (void *) (pci_base_offset(adapter, off));
		UNM_NIC_PCI_WRITE_32(data, addr);
		unm_nic_pci_change_crbwindow_128M(adapter, 1);
		UNM_WRITE_UNLOCK_IRQR(&adapter->adapter_lock, flags);
	}

	return (0);
}

int
unm_nic_get_board_info(struct unm_adapter_s *adapter)
{
	int	rv = 0;
	unm_board_info_t  *boardinfo;
	int		i;
	int		addr = BRDCFG_START;
	uint32_t	  *ptr32;
	uint32_t	gpioval;

	boardinfo = &adapter->ahw.boardcfg;
	ptr32 = (uint32_t *)boardinfo;

	for (i = 0; i < sizeof (unm_board_info_t) / sizeof (uint32_t); i++) {
		if (rom_fast_read(adapter, addr, (int *)ptr32) == -1) {
			return (-1);
		}
		DPRINTF(1, (CE_WARN, "ROM(%d): %x\n", i, *ptr32));
		ptr32++;
		addr += sizeof (uint32_t);
	}

	if (boardinfo->magic != UNM_BDINFO_MAGIC) {
		DPRINTF(1, (CE_WARN, "%s: ERROR reading board config."
		    " Read %x, expected %x\n", unm_nic_driver_name,
		    boardinfo->magic, UNM_BDINFO_MAGIC));
		rv = -1;
	}

	if (boardinfo->header_version != UNM_BDINFO_VERSION) {
		DPRINTF(1, (CE_WARN, "%s: Unknown board config version."
		    " Read %x, expected %x\n", unm_nic_driver_name,
		    boardinfo->header_version, UNM_BDINFO_VERSION));
		rv = -1;
	}

	if (boardinfo->board_type == UNM_BRDTYPE_P3_4_GB_MM) {
		gpioval = UNM_CRB_READ_VAL_ADAPTER(UNM_ROMUSB_GLB_PAD_GPIO_I,
		    adapter);
		if ((gpioval & 0x8000) == 0)
			boardinfo->board_type = UNM_BRDTYPE_P3_10G_TRP;
	}

	DPRINTF(0, (CE_WARN, "Discovered board type:0x%x  ",
	    boardinfo->board_type));

	switch ((unm_brdtype_t)boardinfo->board_type) {
	case UNM_BRDTYPE_P2_SB35_4G:
		adapter->ahw.board_type = UNM_NIC_GBE;
		break;
	case UNM_BRDTYPE_P2_SB31_10G:
	case UNM_BRDTYPE_P2_SB31_10G_IMEZ:
	case UNM_BRDTYPE_P2_SB31_10G_HMEZ:
	case UNM_BRDTYPE_P2_SB31_10G_CX4:
	case UNM_BRDTYPE_P3_HMEZ:
	case UNM_BRDTYPE_P3_XG_LOM:
	case UNM_BRDTYPE_P3_10G_CX4:
	case UNM_BRDTYPE_P3_10G_CX4_LP:
	case UNM_BRDTYPE_P3_IMEZ:
	case UNM_BRDTYPE_P3_10G_SFP_PLUS:
	case UNM_BRDTYPE_P3_10G_XFP:
	case UNM_BRDTYPE_P3_10000_BASE_T:
		adapter->ahw.board_type = UNM_NIC_XGBE;
		break;
	case UNM_BRDTYPE_P3_REF_QG:
	case UNM_BRDTYPE_P3_4_GB:
	case UNM_BRDTYPE_P3_4_GB_MM:
		adapter->ahw.board_type = UNM_NIC_GBE;
		break;
	case UNM_BRDTYPE_P1_BD:
	case UNM_BRDTYPE_P1_SB:
	case UNM_BRDTYPE_P1_SMAX:
	case UNM_BRDTYPE_P1_SOCK:
		adapter->ahw.board_type = UNM_NIC_GBE;
		break;
	case UNM_BRDTYPE_P3_10G_TRP:
		if (adapter->portnum < 2)
			adapter->ahw.board_type = UNM_NIC_XGBE;
		else
			adapter->ahw.board_type = UNM_NIC_GBE;
		break;
	default:
		DPRINTF(1, (CE_WARN, "%s: Unknown(%x)\n", unm_nic_driver_name,
		    boardinfo->board_type));
		break;
	}

	return (rv);
}

/* NIU access sections */

int
unm_nic_macaddr_set(struct unm_adapter_s *adapter, __uint8_t *addr)
{
	int		ret = 0, i, retry_count = 10;
	unsigned char		mac_addr[MAX_ADDR_LEN];

	/* For P3, we should not set MAC in HW any more */
	if (NX_IS_REVISION_P3(adapter->ahw.revision_id))
		return (0);

	switch (adapter->ahw.board_type) {
		case UNM_NIC_GBE:
	/*
	 * Flaky Mac address registers on qgig require several writes.
	 */
			for (i = 0; i < retry_count; ++i) {
				if (unm_niu_macaddr_set(adapter, addr) != 0)
					return (-1);

				(void) unm_niu_macaddr_get(adapter,
				    (unsigned char *)mac_addr);
				if (memcmp(mac_addr, addr, 6) == 0)
					return (0);
			}
			cmn_err(CE_WARN, "%s: Flaky MAC addr registers\n",
			    unm_nic_driver_name);
			break;

		case UNM_NIC_XGBE:
			ret = unm_niu_xg_macaddr_set(adapter, addr);
			break;

		default:
			cmn_err(CE_WARN,  "\r\nUnknown board type encountered"
			    " while setting the MAC address.\n");
			return (-1);
	}
	return (ret);
}

#define	MTU_FUDGE_FACTOR 100
int
unm_nic_set_mtu(struct unm_adapter_s *adapter, int new_mtu)
{
	long		port = adapter->physical_port;
	int			ret = 0;
	u32			port_mode = 0;

	if (adapter->ahw.revision_id >= NX_P3_A2)
		return (nx_fw_cmd_set_mtu(adapter, new_mtu));

	new_mtu += MTU_FUDGE_FACTOR; /* so that MAC accepts frames > MTU */
	switch (adapter->ahw.board_type) {
		case UNM_NIC_GBE:
			unm_nic_write_w0(adapter,
			    UNM_NIU_GB_MAX_FRAME_SIZE(adapter->physical_port),
			    new_mtu);

			break;

		case UNM_NIC_XGBE:
			adapter->unm_nic_hw_read_wx(adapter, UNM_PORT_MODE_ADDR,
			    &port_mode, 4);
			if (port_mode == UNM_PORT_MODE_802_3_AP) {
				unm_nic_write_w0(adapter,
				    UNM_NIU_AP_MAX_FRAME_SIZE(port), new_mtu);
			} else {
				if (adapter->physical_port == 0) {
					unm_nic_write_w0(adapter,
					    UNM_NIU_XGE_MAX_FRAME_SIZE,
					    new_mtu);
				} else {
					unm_nic_write_w0(adapter,
					    UNM_NIU_XG1_MAX_FRAME_SIZE,
					    new_mtu);
				}
			}
			break;

		default:
			cmn_err(CE_WARN, "%s: Unknown brdtype\n",
			    unm_nic_driver_name);
	}

	return (ret);
}

int
unm_nic_set_promisc_mode(struct unm_adapter_s *adapter)
{
	int		ret;

	if (adapter->promisc)
		return (0);

	switch (adapter->ahw.board_type) {
		case UNM_NIC_GBE:
			ret = unm_niu_set_promiscuous_mode(adapter,
			    UNM_NIU_PROMISCOUS_MODE);
			break;

		case UNM_NIC_XGBE:
			ret = unm_niu_xg_set_promiscuous_mode(adapter,
			    UNM_NIU_PROMISCOUS_MODE);
			break;

		default:
			cmn_err(CE_WARN, "%s: Unknown brdtype\n",
			    unm_nic_driver_name);
			ret = -1;
			break;
	}

if (!ret)
	adapter->promisc = 1;

		return (ret);
}

int
unm_nic_unset_promisc_mode(struct unm_adapter_s *adapter)
{
	int	ret = 0;

	/*
	 * P3 does not unset promiscous mode. Why?
	 */
	if (adapter->ahw.revision_id >= NX_P3_A2) {
		return (0);
	}

	if (!adapter->promisc)
		return (0);

	switch (adapter->ahw.board_type) {
		case UNM_NIC_GBE:
			ret = unm_niu_set_promiscuous_mode(adapter,
			    UNM_NIU_NON_PROMISCOUS_MODE);
			break;

		case UNM_NIC_XGBE:
			ret = unm_niu_xg_set_promiscuous_mode(adapter,
			    UNM_NIU_NON_PROMISCOUS_MODE);
			break;

		default:
			cmn_err(CE_WARN, "%s: Unknown brdtype\n",
			    unm_nic_driver_name);
			ret = -1;
			break;
	}

	if (!ret)
		adapter->promisc = 0;

	return (ret);
}

long
unm_nic_phy_read(unm_adapter *adapter, long reg, __uint32_t *readval)
{
	long	ret = 0;

	switch (adapter->ahw.board_type) {
	case UNM_NIC_GBE:
		ret = unm_niu_gbe_phy_read(adapter, reg, readval);
		break;

	case UNM_NIC_XGBE:
		DPRINTF(1, (CE_WARN,
		    "%s: Function %s is not implemented for XG\n",
		    unm_nic_driver_name, __FUNCTION__));
		break;

	default:
		DPRINTF(1, (CE_WARN, "%s: Unknown board type\n",
		    unm_nic_driver_name));
	}

	return (ret);
}

long
unm_nic_init_port(struct unm_adapter_s *adapter)
{
	long	portnum = adapter->physical_port;
	long	ret = 0;
	long	reg = 0;
	u32			port_mode = 0;

	unm_nic_set_link_parameters(adapter);

	switch (adapter->ahw.board_type) {
	case UNM_NIC_GBE:
		ret = unm_niu_enable_gbe_port(adapter);
		break;

	case UNM_NIC_XGBE:
		adapter->unm_nic_hw_read_wx(adapter, UNM_PORT_MODE_ADDR,
		    &port_mode, 4);
		if (port_mode == UNM_PORT_MODE_802_3_AP) {
			ret = unm_niu_enable_gbe_port(adapter);
		} else {
			adapter->unm_crb_writelit_adapter(adapter,
			    UNM_NIU_XGE_CONFIG_0 + (0x10000 * portnum), 0x5);
			UNM_CRB_READ_CHECK_ADAPTER(UNM_NIU_XGE_CONFIG_1 +
			    (0x10000 * portnum), &reg, adapter);
			if (adapter->ahw.revision_id < NX_P3_A2)
				reg = (reg & ~0x2000UL);
			adapter->unm_crb_writelit_adapter(adapter,
			    UNM_NIU_XGE_CONFIG_1 + (0x10000 * portnum), reg);
		}
		break;

	default:
		DPRINTF(1, (CE_WARN, "%s: Unknown board type\n",
		    unm_nic_driver_name));
	}

	return (ret);
}

void
unm_nic_stop_port(struct unm_adapter_s *adapter)
{

	(void) mac_unregister(adapter->mach);

	switch (adapter->ahw.board_type) {
	case UNM_NIC_GBE:
		(void) unm_niu_disable_gbe_port(adapter);
		break;

	case UNM_NIC_XGBE:
		(void) unm_niu_disable_xg_port(adapter);
		break;

	default:
		DPRINTF(1, (CE_WARN, "%s: Unknown board type\n",
		    unm_nic_driver_name));
	}
}

void
unm_crb_write_adapter(unsigned long off, void *data,
    struct unm_adapter_s *adapter)
{
	(void) adapter->unm_nic_hw_write_wx(adapter, off, data, 4);
}

int
unm_crb_read_adapter(unsigned long off, void *data,
    struct unm_adapter_s *adapter)
{
	return (adapter->unm_nic_hw_read_wx(adapter, off, data, 4));
}

int
unm_crb_read_val_adapter(unsigned long off, struct unm_adapter_s *adapter)
{
	int data;

	adapter->unm_nic_hw_read_wx(adapter, off, &data, 4);
	return (data);
}

void
unm_nic_set_link_parameters(struct unm_adapter_s *adapter)
{
	unm_niu_phy_status_t status;
	uint16_t defval = (uint16_t)-1;
	unm_niu_control_t mode;
	u32 port_mode = 0;

	unm_nic_read_w0(adapter, UNM_NIU_MODE, (uint32_t *)&mode);
	if (mode.enable_ge) { // Gb 10/100/1000 Mbps mode
		adapter->unm_nic_hw_read_wx(adapter, UNM_PORT_MODE_ADDR,
		    &port_mode, 4);
		if (port_mode == UNM_PORT_MODE_802_3_AP) {
			adapter->link_speed = MBPS_1000;
			adapter->link_duplex = LINK_DUPLEX_FULL;
		} else {
		if (unm_nic_phy_read(adapter,
		    UNM_NIU_GB_MII_MGMT_ADDR_PHY_STATUS,
		    (unm_crbword_t *)&status) == 0) {
			if (status.link) {
				switch (status.speed) {
				case 0: adapter->link_speed = MBPS_10;
					break;
				case 1: adapter->link_speed = MBPS_100;
					break;
				case 2: adapter->link_speed = MBPS_1000;
					break;
				default:
					adapter->link_speed = defval;
					break;
				}
				switch (status.duplex) {
				case 0: adapter->link_duplex = LINK_DUPLEX_HALF;
					break;
				case 1: adapter->link_duplex = LINK_DUPLEX_FULL;
					break;
				default:
					adapter->link_duplex = defval;
					break;
				}
			} else {
				adapter->link_speed = defval;
				adapter->link_duplex = defval;
			}
		} else {
			adapter->link_speed = defval;
			adapter->link_duplex = defval;
		}
		}
	}
}

void
unm_nic_flash_print(struct unm_adapter_s *adapter)
{
	int valid = 1;
	unm_board_info_t *board_info = &(adapter->ahw.boardcfg);

	if (board_info->magic != UNM_BDINFO_MAGIC) {
		cmn_err(CE_WARN, "%s UNM Unknown board config, Read 0x%x "
		    "expected as 0x%x\n", unm_nic_driver_name,
		    board_info->magic, UNM_BDINFO_MAGIC);
		valid = 0;
	}
	if (board_info->header_version != UNM_BDINFO_VERSION) {
		cmn_err(CE_WARN, "%s UNM Unknown board config version."
		    " Read %x, expected %x\n", unm_nic_driver_name,
		    board_info->header_version, UNM_BDINFO_VERSION);
		valid = 0;
	}
	if (valid) {
		unm_user_info_t  user_info;
		int	i;
		int	addr = USER_START;
		int	*ptr32;

		ptr32 = (int *)&user_info;
		for (i = 0; i < sizeof (unm_user_info_t) / sizeof (uint32_t);
		    i++) {
			if (rom_fast_read(adapter, addr, ptr32) == -1) {
				cmn_err(CE_WARN,
				    "%s: ERROR reading %s board userarea.\n",
				    unm_nic_driver_name, unm_nic_driver_name);
				return;
			}
			ptr32++;
			addr += sizeof (uint32_t);
		}
		if (verbmsg != 0) {
			char	*brd_name;
			GET_BRD_NAME_BY_TYPE(board_info->board_type, brd_name);
			cmn_err(CE_NOTE, "%s %s Board S/N %s  Chip id 0x%x\n",
			    unm_nic_driver_name, brd_name, user_info.serial_num,
			    board_info->chip_id);
		}
	}
}

static int
nx_nic_send_cmd_descs(unm_adapter *adapter, cmdDescType0_t *cmd_desc_arr,
    int nr_elements)
{
	struct unm_cmd_buffer	*pbuf;
	unsigned int		i = 0, producer;

	/*
	 * We need to check if space is available.
	 */
	UNM_SPIN_LOCK(&adapter->tx_lock);
	producer = adapter->cmdProducer;

	do {
		pbuf = &adapter->cmd_buf_arr[producer];
		pbuf->head = pbuf->tail = NULL;
		pbuf->msg = NULL;
		(void) memcpy(&adapter->ahw.cmdDescHead[producer],
		    &cmd_desc_arr[i], sizeof (cmdDescType0_t));
		unm_desc_dma_sync(adapter->ahw.cmd_desc_dma_handle, producer,
		    1, adapter->MaxTxDescCount, sizeof (cmdDescType0_t),
		    DDI_DMA_SYNC_FORDEV);
		producer = get_next_index(producer, adapter->MaxTxDescCount);
		i++;
	} while (i != nr_elements);

	adapter->cmdProducer = adapter->ahw.cmdProducer = producer;
	adapter->freecmds -= i;

	unm_nic_update_cmd_producer(adapter, producer);

	UNM_SPIN_UNLOCK(&adapter->tx_lock);
	return (0);
}

typedef struct {
	u64	qhdr, req_hdr, words[6];
} nx_nic_req_t;

typedef struct {
	u8	op, tag, mac_addr[6];
} nx_mac_req_t;

static void
nx_p3_sre_macaddr_change(unm_adapter *adapter, u8 *addr, u8 op)
{
	nx_nic_req_t	req;
	nx_mac_req_t	mac_req;
	int		rv;

	(void) memset(&req, 0, sizeof (nx_nic_req_t));
	req.qhdr |= (NX_NIC_REQUEST << 23);
	req.req_hdr |= NX_MAC_EVENT;
	req.req_hdr |= ((u64)adapter->portnum << 16);
	mac_req.op = op;
	(void) memcpy(&mac_req.mac_addr, addr, 6);
	req.words[0] = HOST_TO_LE_64(*(u64 *)(uintptr_t)&mac_req);

	rv = nx_nic_send_cmd_descs(adapter, (cmdDescType0_t *)&req, 1);
	if (rv != 0)
		cmn_err(CE_WARN, "%s%d: Could not send mac update\n",
		    adapter->name, adapter->instance);
}

static int
nx_p3_nic_set_promisc(unm_adapter *adapter, u32 mode)
{
	nx_nic_req_t	req;

	(void) memset(&req, 0, sizeof (nx_nic_req_t));

	req.qhdr |= (NX_HOST_REQUEST << 23);
	req.req_hdr |= NX_NIC_H2C_OPCODE_PROXY_SET_VPORT_MISS_MODE;
	req.req_hdr |= ((u64)adapter->portnum << 16);
	req.words[0] = HOST_TO_LE_64(mode);

	return (nx_nic_send_cmd_descs(adapter, (cmdDescType0_t *)&req, 1));
}

/*
 * Currently only invoked at interface initialization time
 */
void
nx_p3_nic_set_multi(unm_adapter *adapter)
{
	u8	bcast_addr[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

	if (nx_p3_nic_set_promisc(adapter, VPORT_MISS_MODE_ACCEPT_ALL))
		cmn_err(CE_WARN, "Could not set promisc mode\n");

	nx_p3_sre_macaddr_change(adapter, adapter->mac_addr, NETXEN_MAC_ADD);
	nx_p3_sre_macaddr_change(adapter, bcast_addr, NETXEN_MAC_ADD);
}
