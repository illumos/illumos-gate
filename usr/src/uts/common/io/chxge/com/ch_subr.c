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
 * Copyright (C) 2003-2005 Chelsio Communications.  All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* ch_subr.c */

#include "common.h"
#include "elmer0.h"
#include "regs.h"

#include "gmac.h"
#include "cphy.h"
#include "sge.h"
#include "tp.h"
#include "espi.h"

#ifdef CONFIG_CHELSIO_T1_OFFLOAD
#include "mc3.h"
#include "mc4.h"
#include "mc5.h"
#include "ulp.h"
#endif
#ifdef CONFIG_CHELSIO_T1_COUGAR
#include "cspi.h"
#endif

/*
 * t1_wait_op_done - wait until an operation is completed
 * @adapter: the adapter performing the operation
 * @reg: the register to check for completion
 * @mask: a single-bit field within @reg that indicates completion
 * @polarity: the value of the field when the operation is completed
 * @attempts: number of check iterations
 * @delay: delay in usecs between iterations
 * @attempts: number of check iterations
 * @delay: delay in usecs between iterations
 *
 * Wait until an operation is completed by checking a bit in a register
 * up to @attempts times.	Returns %0 if the operation completes and %1
 * otherwise.
 */
int t1_wait_op_done(adapter_t *adapter, int reg, u32 mask, int polarity,
		int attempts, int delay)
{
	while (attempts) {
		u32 val = t1_read_reg_4(adapter, reg) & mask;
		if (!!val == polarity)
			return (0);
		if (--attempts == 0)
			return (1);
		if (delay)
			DELAY_US(delay);
	}

	return (1);
}

/* #define TPI_ATTEMPTS 50 */
#define	TPI_ATTEMPTS 100

/*
 * Write a register over the TPI interface (unlocked and locked versions).
 */
int
__t1_tpi_write(adapter_t *adapter, u32 addr, u32 value)
{
	int tpi_busy;

	t1_write_reg_4(adapter, A_TPI_ADDR, addr);
	t1_write_reg_4(adapter, A_TPI_WR_DATA, value);
	t1_write_reg_4(adapter, A_TPI_CSR, F_TPIWR);

	tpi_busy = t1_wait_op_done(adapter, A_TPI_CSR, F_TPIRDY, 1,
		TPI_ATTEMPTS, 3);
	if (tpi_busy)
		CH_ALERT("%s: TPI write to 0x%x failed\n",
			adapter_name(adapter), addr);
	return (tpi_busy);
}

int
t1_tpi_write(adapter_t *adapter, u32 addr, u32 value)
{
	int ret;

	TPI_LOCK(adapter);
	ret = __t1_tpi_write(adapter, addr, value);
	TPI_UNLOCK(adapter);
	return (ret);
}

/*
 * Read a register over the TPI interface (unlocked and locked versions).
 */
int
__t1_tpi_read(adapter_t *adapter, u32 addr, u32 *valp)
{
	int tpi_busy;

	t1_write_reg_4(adapter, A_TPI_ADDR, addr);
	t1_write_reg_4(adapter, A_TPI_CSR, 0);

	tpi_busy = t1_wait_op_done(adapter, A_TPI_CSR, F_TPIRDY, 1,
		TPI_ATTEMPTS, 3);

	if (tpi_busy)
		CH_ALERT("%s: TPI read from 0x%x failed\n",
			adapter_name(adapter), addr);
	else
		*valp = t1_read_reg_4(adapter, A_TPI_RD_DATA);
	return (tpi_busy);
}

int
t1_tpi_read(adapter_t *adapter, u32 addr, u32 *valp)
{
	int ret;

	TPI_LOCK(adapter);
	ret = __t1_tpi_read(adapter, addr, valp);
	TPI_UNLOCK(adapter);
	return (ret);
}

/*
 * Set a TPI parameter.
 */
static void t1_tpi_par(adapter_t *adapter, u32 value)
{
	t1_write_reg_4(adapter, A_TPI_PAR, V_TPIPAR(value));
}

/*
 * Called when a port's link settings change to propagate the new values to the
 * associated PHY and MAC.  After performing the common tasks it invokes an
 * OS-specific handler.
 */
void
link_changed(adapter_t *adapter, int port_id)
{
	int link_ok, speed, duplex, fc;
	struct cphy *phy = adapter->port[port_id].phy;
	struct link_config *lc = &adapter->port[port_id].link_config;

	phy->ops->get_link_status(phy, &link_ok, &speed, &duplex, &fc);

	lc->speed = speed < 0 ? SPEED_INVALID : speed;
	lc->duplex = duplex < 0 ? DUPLEX_INVALID : duplex;
	if (!(lc->requested_fc & PAUSE_AUTONEG))
		fc = lc->requested_fc & (PAUSE_RX | PAUSE_TX);

	if (link_ok && speed >= 0 && lc->autoneg == AUTONEG_ENABLE) {
		/* Set MAC speed, duplex, and flow control to match PHY. */
		struct cmac *mac = adapter->port[port_id].mac;

		mac->ops->set_speed_duplex_fc(mac, speed, duplex, fc);
		lc->fc = (unsigned char)fc;
	}
	t1_os_link_changed(adapter, port_id, link_ok, speed, duplex, fc);
}

static int t1_pci_intr_handler(adapter_t *adapter)
{
	u32 pcix_cause;

	(void) t1_os_pci_read_config_4(adapter, A_PCICFG_INTR_CAUSE,
		&pcix_cause);

	if (pcix_cause) {
		(void) t1_os_pci_write_config_4(adapter, A_PCICFG_INTR_CAUSE,
			pcix_cause);
		t1_fatal_err(adapter);    /* PCI errors are fatal */
	}
	return (0);
}

#ifdef CONFIG_CHELSIO_T1_1G
#include "fpga_defs.h"

/*
 * PHY interrupt handler for FPGA boards.
 */
static int fpga_phy_intr_handler(adapter_t *adapter)
{
	int p;
	u32 cause = t1_read_reg_4(adapter, FPGA_GMAC_ADDR_INTERRUPT_CAUSE);

	for_each_port(adapter, p)
		if (cause & (1 << p)) {
			struct cphy *phy = adapter->port[p].phy;
			int phy_cause = phy->ops->interrupt_handler(phy);

			if (phy_cause & cphy_cause_link_change)
				link_changed(adapter, p);
		}
	t1_write_reg_4(adapter, FPGA_GMAC_ADDR_INTERRUPT_CAUSE, cause);
	return (0);
}

/*
 * Slow path interrupt handler for FPGAs.
 */
static int fpga_slow_intr(adapter_t *adapter)
{
	u32 cause = t1_read_reg_4(adapter, A_PL_CAUSE);

	cause &= ~F_PL_INTR_SGE_DATA;
	if (cause & F_PL_INTR_SGE_ERR)
		(void) t1_sge_intr_error_handler(adapter->sge);

	if (cause & FPGA_PCIX_INTERRUPT_GMAC)
		(void) fpga_phy_intr_handler(adapter);

	if (cause & FPGA_PCIX_INTERRUPT_TP) {
		/*
		 * FPGA doesn't support MC4 interrupts and it requires
		 * this odd layer of indirection for MC5.
		 */
		u32 tp_cause = t1_read_reg_4(adapter,
			FPGA_TP_ADDR_INTERRUPT_CAUSE);
#ifdef CONFIG_CHELSIO_T1_OFFLOAD
		if (tp_cause & FPGA_TP_INTERRUPT_MC5)
			t1_mc5_intr_handler(adapter->mc5);
#endif
		/* Clear TP interrupt */
		t1_write_reg_4(adapter, FPGA_TP_ADDR_INTERRUPT_CAUSE,
			tp_cause);
	}
#ifdef CONFIG_CHELSIO_T1_OFFLOAD
	if (cause & FPGA_PCIX_INTERRUPT_MC3)
		(void) t1_mc3_intr_handler(adapter->mc3);
#endif
	if (cause & FPGA_PCIX_INTERRUPT_PCIX)
		(void) t1_pci_intr_handler(adapter);

	/* Clear the interrupts just processed. */
	if (cause)
		t1_write_reg_4(adapter, A_PL_CAUSE, cause);

	return (cause != 0);
}

/*
 * FPGA MDIO initialization.
 */
static void fpga_mdio_init(adapter_t *adapter, const struct board_info *bi)
{
	(void) bi;	/* avoid warnings */
	t1_write_reg_4(adapter, A_MI0_CLK, V_MI0_CLK_DIV(3));
}

/*
 * FPGA MDIO read/write operations.
 */
static int fpga_mdio_read(adapter_t *adapter, int phy_addr, int mmd_addr,
	int reg_addr, unsigned int *val)
{
	if (mmd_addr)
		return (-EINVAL);

	/* Check if MDI is busy; this shouldn't happen. */
	if (t1_read_reg_4(adapter, A_MI0_CSR) & F_MI0_BUSY) {
		CH_ALERT("%s: MDIO busy at start of read\n",
			adapter_name(adapter));
		return (-EBUSY);
	}
	t1_write_reg_4(adapter, A_MI0_ADDR,
		V_MI0_PHY_REG_ADDR(reg_addr) | V_MI0_PHY_ADDR(phy_addr));
	*val = t1_read_reg_4(adapter, A_MI0_DATA_EXT);

	return (0);
}

static int fpga_mdio_write(adapter_t *adapter, int phy_addr, int mmd_addr,
	int reg_addr, unsigned int val)
{
	if (mmd_addr)
		return (-EINVAL);

	/* Check if MDI is busy; this shouldn't happen. */
	if (t1_read_reg_4(adapter, A_MI0_CSR) & F_MI0_BUSY) {
		CH_ALERT("%s: MDIO busy at start of write\n",
			adapter_name(adapter));
		return (-EBUSY);
	}
	t1_write_reg_4(adapter, A_MI0_ADDR,
		V_MI0_PHY_REG_ADDR(reg_addr) | V_MI0_PHY_ADDR(phy_addr));
	t1_write_reg_4(adapter, A_MI0_DATA_EXT, val);
	return (0);
}

static struct mdio_ops fpga_mdio_ops = {
	fpga_mdio_init,
	fpga_mdio_read,
	fpga_mdio_write
};
#endif

/*
 * Wait until Elmer's MI1 interface is ready for new operations.
 */
static int mi1_wait_until_ready(adapter_t *adapter, int mi1_reg)
{
	int attempts = 100, busy;

	do {
		u32 val;

		(void) __t1_tpi_read(adapter, mi1_reg, &val);
		busy = val & F_MI1_OP_BUSY;
		if (busy)
			DELAY_US(10);
	} while (busy && --attempts);
	if (busy)
		CH_ALERT("%s: MDIO operation timed out\n",
			adapter_name(adapter));
	return (busy);
}

/*
 * MI1 MDIO initialization.
 */
static void mi1_mdio_init(adapter_t *adapter, const struct board_info *bi)
{
	u32 clkdiv = bi->clock_elmer0 / (2 * bi->mdio_mdc) - 1;
	u32 val = F_MI1_PREAMBLE_ENABLE | V_MI1_MDI_INVERT(bi->mdio_mdiinv) |
		V_MI1_MDI_ENABLE(bi->mdio_mdien) | V_MI1_CLK_DIV(clkdiv);

	if (!(bi->caps & SUPPORTED_10000baseT_Full))
		val |= V_MI1_SOF(1);
	(void) t1_tpi_write(adapter, A_ELMER0_PORT0_MI1_CFG, val);
}

#if defined(CONFIG_CHELSIO_T1_1G) || defined(CONFIG_CHELSIO_T1_COUGAR)
/*
 * Elmer MI1 MDIO read/write operations.
 */
static int mi1_mdio_read(adapter_t *adapter, int phy_addr, int mmd_addr,
	int reg_addr, unsigned int *valp)
{
	u32 addr = V_MI1_REG_ADDR(reg_addr) | V_MI1_PHY_ADDR(phy_addr);

	if (mmd_addr)
		return (-EINVAL);

	TPI_LOCK(adapter);
	(void) __t1_tpi_write(adapter, A_ELMER0_PORT0_MI1_ADDR, addr);
	(void) __t1_tpi_write(adapter, A_ELMER0_PORT0_MI1_OP,
		MI1_OP_DIRECT_READ);
	(void) mi1_wait_until_ready(adapter, A_ELMER0_PORT0_MI1_OP);
	(void) __t1_tpi_read(adapter, A_ELMER0_PORT0_MI1_DATA, valp);
	TPI_UNLOCK(adapter);
	return (0);
}

static int mi1_mdio_write(adapter_t *adapter, int phy_addr, int mmd_addr,
	int reg_addr, unsigned int val)
{
	u32 addr = V_MI1_REG_ADDR(reg_addr) | V_MI1_PHY_ADDR(phy_addr);

	if (mmd_addr)
		return (-EINVAL);

	TPI_LOCK(adapter);
	(void) __t1_tpi_write(adapter, A_ELMER0_PORT0_MI1_ADDR, addr);
	(void) __t1_tpi_write(adapter, A_ELMER0_PORT0_MI1_DATA, val);
	(void) __t1_tpi_write(adapter, A_ELMER0_PORT0_MI1_OP,
		MI1_OP_DIRECT_WRITE);
	(void) mi1_wait_until_ready(adapter, A_ELMER0_PORT0_MI1_OP);
	TPI_UNLOCK(adapter);
	return (0);
}

#if defined(CONFIG_CHELSIO_T1_1G) || defined(CONFIG_CHELSIO_T1_COUGAR)
static struct mdio_ops mi1_mdio_ops = {
	mi1_mdio_init,
	mi1_mdio_read,
	mi1_mdio_write
};
#endif

#endif

#if 0
static int mi1_mdio_ext_readinc(adapter_t *adapter, int phy_addr, int mmd_addr,
				int reg_addr, unsigned int *valp)
{
	u32 addr = V_MI1_REG_ADDR(mmd_addr) | V_MI1_PHY_ADDR(phy_addr);

	TPI_LOCK(adapter);

	/* Write the address we want. */
	(void) __t1_tpi_write(adapter, A_ELMER0_PORT0_MI1_ADDR, addr);
	(void) __t1_tpi_write(adapter, A_ELMER0_PORT0_MI1_DATA, reg_addr);
	(void) __t1_tpi_write(adapter, A_ELMER0_PORT0_MI1_OP,
		MI1_OP_INDIRECT_ADDRESS);
	(void) mi1_wait_until_ready(adapter, A_ELMER0_PORT0_MI1_OP);

	/* Write the operation we want. */
	(void) __t1_tpi_write(adapter, A_ELMER0_PORT0_MI1_OP,
		MI1_OP_INDIRECT_READ_INC);
	(void) mi1_wait_until_ready(adapter, A_ELMER0_PORT0_MI1_OP);

	/* Read the data. */
	(void) __t1_tpi_read(adapter, A_ELMER0_PORT0_MI1_DATA, valp);
	TPI_UNLOCK(adapter);
	return (0);
}
#endif

static int mi1_mdio_ext_read(adapter_t *adapter, int phy_addr, int mmd_addr,
	int reg_addr, unsigned int *valp)
{
	u32 addr = V_MI1_REG_ADDR(mmd_addr) | V_MI1_PHY_ADDR(phy_addr);

	TPI_LOCK(adapter);

	/* Write the address we want. */
	(void) __t1_tpi_write(adapter, A_ELMER0_PORT0_MI1_ADDR, addr);
	(void) __t1_tpi_write(adapter, A_ELMER0_PORT0_MI1_DATA, reg_addr);
	(void) __t1_tpi_write(adapter, A_ELMER0_PORT0_MI1_OP,
		MI1_OP_INDIRECT_ADDRESS);
	(void) mi1_wait_until_ready(adapter, A_ELMER0_PORT0_MI1_OP);

	/* Write the operation we want. */
	(void) __t1_tpi_write(adapter, A_ELMER0_PORT0_MI1_OP,
		MI1_OP_INDIRECT_READ);
	(void) mi1_wait_until_ready(adapter, A_ELMER0_PORT0_MI1_OP);

	/* Read the data. */
	(void) __t1_tpi_read(adapter, A_ELMER0_PORT0_MI1_DATA, valp);
	TPI_UNLOCK(adapter);
	return (0);
}

static int mi1_mdio_ext_write(adapter_t *adapter, int phy_addr, int mmd_addr,
	int reg_addr, unsigned int val)
{
	u32 addr = V_MI1_REG_ADDR(mmd_addr) | V_MI1_PHY_ADDR(phy_addr);

	TPI_LOCK(adapter);

	/* Write the address we want. */
	(void) __t1_tpi_write(adapter, A_ELMER0_PORT0_MI1_ADDR, addr);
	(void) __t1_tpi_write(adapter, A_ELMER0_PORT0_MI1_DATA, reg_addr);
	(void) __t1_tpi_write(adapter, A_ELMER0_PORT0_MI1_OP,
		MI1_OP_INDIRECT_ADDRESS);
	(void) mi1_wait_until_ready(adapter, A_ELMER0_PORT0_MI1_OP);

	/* Write the data. */
	(void) __t1_tpi_write(adapter, A_ELMER0_PORT0_MI1_DATA, val);
	(void) __t1_tpi_write(adapter, A_ELMER0_PORT0_MI1_OP,
		MI1_OP_INDIRECT_WRITE);
	(void) mi1_wait_until_ready(adapter, A_ELMER0_PORT0_MI1_OP);
	TPI_UNLOCK(adapter);
	return (0);
}

static struct mdio_ops mi1_mdio_ext_ops = {
	mi1_mdio_init,
	mi1_mdio_ext_read,
	mi1_mdio_ext_write
};

enum {
	CH_BRD_T110_1CU,
	CH_BRD_N110_1F,
	CH_BRD_N210_1F,
	CH_BRD_T210_1F,
	CH_BRD_T210_1CU,
#ifdef CONFIG_CHELSIO_T1_OFFLOAD
#ifdef CONFIG_CHELSIO_T1_1G
	CH_BRD_T204_4CU,
	CH_BRD_T204V_4CU,
	CH_BRD_6800_4CU,
	CH_BRD_7500_4CU,
	CH_BRD_7500_4F,
	CH_BRD_T101_1CU_LB,
	CH_BRD_T101_1F_LB,
#endif
	CH_BRD_8000_1F,
	CH_BRD_T110_1F,
#ifdef CONFIG_CHELSIO_T1_COUGAR
#ifdef CONFIG_CHELSIO_T1_1G
	CH_BRD_COUGAR_4CU,
#endif
	CH_BRD_COUGAR_1F,
#endif
#ifdef CONFIG_USERMODE
	CH_BRD_SIMUL,
#endif
#endif
};

static struct board_info t1_board[] = {

{ CHBT_BOARD_CHT110, 1/*ports#*/,
  SUPPORTED_10000baseT_Full /*caps*/, CHBT_TERM_T1,
  CHBT_MAC_PM3393, CHBT_PHY_MY3126,
  125000000/*clk-core*/, 150000000/*clk-mc3*/, 125000000/*clk-mc4*/,
  1/*espi-ports*/, 0/*clk-cspi*/, 44/*clk-elmer0*/, 1/*mdien*/,
  1/*mdiinv*/, 1/*mdc*/, 1/*phybaseaddr*/, &t1_pm3393_ops,
  &t1_my3126_ops, &mi1_mdio_ext_ops,
  "Chelsio T110 1x10GBase-CX4 TOE" },

{ CHBT_BOARD_N110, 1/*ports#*/,
  SUPPORTED_10000baseT_Full | SUPPORTED_FIBRE /*caps*/, CHBT_TERM_T1,
  CHBT_MAC_PM3393, CHBT_PHY_88X2010,
  125000000/*clk-core*/, 0/*clk-mc3*/, 0/*clk-mc4*/,
  1/*espi-ports*/, 0/*clk-cspi*/, 44/*clk-elmer0*/, 0/*mdien*/,
  0/*mdiinv*/, 1/*mdc*/, 0/*phybaseaddr*/, &t1_pm3393_ops,
  &t1_mv88x201x_ops, &mi1_mdio_ext_ops,
  "Chelsio N110 1x10GBaseX NIC" },

{ CHBT_BOARD_N210, 1/*ports#*/,
  SUPPORTED_10000baseT_Full | SUPPORTED_FIBRE /*caps*/, CHBT_TERM_T2,
  CHBT_MAC_PM3393, CHBT_PHY_88X2010,
  125000000/*clk-core*/, 0/*clk-mc3*/, 0/*clk-mc4*/,
  1/*espi-ports*/, 0/*clk-cspi*/, 44/*clk-elmer0*/, 0/*mdien*/,
  0/*mdiinv*/, 1/*mdc*/, 0/*phybaseaddr*/, &t1_pm3393_ops,
  &t1_mv88x201x_ops, &mi1_mdio_ext_ops,
  "Chelsio N210 1x10GBaseX NIC" },

{ CHBT_BOARD_CHT210, 1/*ports#*/,
  SUPPORTED_10000baseT_Full /*caps*/, CHBT_TERM_T2,
  CHBT_MAC_PM3393, CHBT_PHY_88X2010,
  125000000/*clk-core*/, 133000000/*clk-mc3*/, 125000000/*clk-mc4*/,
  1/*espi-ports*/, 0/*clk-cspi*/, 44/*clk-elmer0*/, 0/*mdien*/,
  0/*mdiinv*/, 1/*mdc*/, 0/*phybaseaddr*/, &t1_pm3393_ops, 
  &t1_mv88x201x_ops, &mi1_mdio_ext_ops,
  "Chelsio T210 1x10GBaseX TOE" },

{ CHBT_BOARD_CHT210, 1/*ports#*/,
  SUPPORTED_10000baseT_Full /*caps*/, CHBT_TERM_T2,
  CHBT_MAC_PM3393, CHBT_PHY_MY3126,
  125000000/*clk-core*/, 133000000/*clk-mc3*/, 125000000/*clk-mc4*/,
  1/*espi-ports*/, 0/*clk-cspi*/, 44/*clk-elmer0*/, 1/*mdien*/,
  1/*mdiinv*/, 1/*mdc*/, 1/*phybaseaddr*/, &t1_pm3393_ops,
  &t1_my3126_ops, &mi1_mdio_ext_ops,
  "Chelsio T210 1x10GBase-CX4 TOE" },

#ifdef CONFIG_CHELSIO_T1_OFFLOAD
#ifdef CONFIG_CHELSIO_T1_1G
{ CHBT_BOARD_CHT204, 4/*ports#*/,
  SUPPORTED_100baseT_Full | SUPPORTED_1000baseT_Full | SUPPORTED_Autoneg |
  SUPPORTED_PAUSE | SUPPORTED_TP /*caps*/, CHBT_TERM_T2, CHBT_MAC_IXF1010, CHBT_PHY_88E1111,
  100000000/*clk-core*/, 133000000/*clk-mc3*/, 100000000/*clk-mc4*/,
  4/*espi-ports*/, 0/*clk-cspi*/, 44/*clk-elmer0*/, 0/*mdien*/,
  0/*mdiinv*/, 1/*mdc*/, 4/*phybaseaddr*/, &t1_ixf1010_ops,
  &t1_mv88e1xxx_ops, &mi1_mdio_ops,
  "Chelsio T204 4x100/1000BaseT TOE" },
{ CHBT_BOARD_CHT204V, 4/*ports#*/,
  SUPPORTED_10baseT_Half | SUPPORTED_10baseT_Full | SUPPORTED_100baseT_Half |
  SUPPORTED_100baseT_Full | SUPPORTED_1000baseT_Full | SUPPORTED_Autoneg |
  SUPPORTED_PAUSE | SUPPORTED_TP /*caps*/, CHBT_TERM_T2, CHBT_MAC_VSC7321, CHBT_PHY_88E1111,
  100000000/*clk-core*/, 133000000/*clk-mc3*/, 100000000/*clk-mc4*/,
  4/*espi-ports*/, 0/*clk-cspi*/, 44/*clk-elmer0*/, 0/*mdien*/,
  0/*mdiinv*/, 1/*mdc*/, 4/*phybaseaddr*/, &t1_vsc7326_ops,
  &t1_mv88e1xxx_ops, &mi1_mdio_ops,
  "Chelsio T204V 4x100/1000BaseT TOE" },

{ CHBT_BOARD_6800, 1/*ports#*/,
  SUPPORTED_10baseT_Half | SUPPORTED_10baseT_Full | SUPPORTED_100baseT_Half |
  SUPPORTED_100baseT_Full | SUPPORTED_1000baseT_Half |
  SUPPORTED_1000baseT_Full | SUPPORTED_Autoneg | SUPPORTED_TP /*caps*/,
  CHBT_TERM_FPGA, CHBT_MAC_CHELSIO_A, CHBT_PHY_88E1041,
  16000000/*clk-core*/, 16000000/*clk-mc3*/, 16000000/*clk-mc4*/,
  0/*espi-ports*/, 0/*clk-cspi*/, 0/*clk-elmer0*/, 0/*mdien*/,
  0/*mdiinv*/, 4/*mdc*/, 0/*phybaseaddr*/, &t1_chelsio_mac_ops, &t1_mv88e1xxx_ops, &fpga_mdio_ops,
  "Chelsio FPGA 4x10/100/1000BaseT TOE" },

{ CHBT_BOARD_7500, 4/*ports#*/,
  SUPPORTED_100baseT_Full | SUPPORTED_1000baseT_Full | SUPPORTED_Autoneg |
  SUPPORTED_TP /*caps*/, CHBT_TERM_T1, CHBT_MAC_IXF1010, CHBT_PHY_88E1041,
  87500000/*clk-core*/, 87500000/*clk-mc3*/, 87500000/*clk-mc4*/,
  4/*espi-ports*/, 0/*clk-cspi*/, 40/*clk-elmer0*/, 0/*mdien*/,
  0/*mdiinv*/, 4/*mdc*/, 0/*phybaseaddr*/, &t1_ixf1010_ops,
  &t1_mv88e1xxx_ops, &mi1_mdio_ops,
  "Chelsio 7500 4x100/1000BaseT TOE" },

{ CHBT_BOARD_7500, 4/*ports#*/,
  SUPPORTED_1000baseT_Full | SUPPORTED_Autoneg | SUPPORTED_FIBRE /*caps*/,
  CHBT_TERM_T1, CHBT_MAC_IXF1010, CHBT_PHY_88E1041,
  87500000/*clk-core*/, 87500000/*clk-mc3*/, 87500000/*clk-mc4*/,
  4/*espi-ports*/, 0/*clk-cspi*/, 40/*clk-elmer0*/, 0/*mdien*/,
  0/*mdiinv*/, 4/*mdc*/, 0/*phybaseaddr*/, &t1_ixf1010_ops,
  &t1_mv88e1xxx_ops, &mi1_mdio_ops,
  "Chelsio 7500 4x1000BaseX TOE" },

{ CHBT_BOARD_CHT101, 1/*ports#*/,
  SUPPORTED_100baseT_Full | SUPPORTED_1000baseT_Full | SUPPORTED_Autoneg |
  SUPPORTED_TP | SUPPORTED_PAUSE | SUPPORTED_LOOPBACK /*caps*/, CHBT_TERM_T1, CHBT_MAC_IXF1010, CHBT_PHY_88E1111,
  83300000/*clk-core*/, 83300000/*clk-mc3*/, 83300000/*clk-mc4*/,
  2/*espi-ports*/, 0/*clk-cspi*/, 40/*clk-elmer0*/, 0/*mdien*/, 
  0/*mdiinv*/, 4/*mdc*/, 4/*phybaseaddr*/, &t1_ixf1010_ops, 
  &t1_mv88e1xxx_ops, &mi1_mdio_ops,
  "Chelsio T101 1x100/1000BaseT TOE" },

{ CHBT_BOARD_CHT101, 1/*ports#*/,
  SUPPORTED_1000baseT_Full | SUPPORTED_Autoneg | SUPPORTED_FIBRE | SUPPORTED_PAUSE | SUPPORTED_LOOPBACK /*caps*/,
  CHBT_TERM_T1, CHBT_MAC_IXF1010, CHBT_PHY_88E1111, 
  83300000/*clk-core*/, 83300000/*clk-mc3*/, 83300000/*clk-mc4*/,
  2/*espi-ports*/, 0/*clk-cspi*/, 40/*clk-elmer0*/, 0/*mdien*/, 
  0/*mdiinv*/, 4/*mdc*/, 4/*phybaseaddr*/, &t1_ixf1010_ops, 
  &t1_mv88e1xxx_ops, &mi1_mdio_ops,
  "Chelsio T101 1x1000BaseX TOE" },
#endif

{ CHBT_BOARD_8000, 1/*ports#*/,
  SUPPORTED_10000baseT_Full | SUPPORTED_FIBRE /*caps*/, CHBT_TERM_T1,
  CHBT_MAC_PM3393, CHBT_PHY_XPAK,
  125000000/*clk-core*/, 150000000/*clk-mc3*/, 125000000/*clk-mc4*/,
  1/*espi-ports*/, 0/*clk-cspi*/, 40/*clk-elmer0*/, 1/*mdien*/,
  1/*mdiinv*/, 1/*mdc*/, 0/*phybaseaddr*/, &t1_pm3393_ops,
  &t1_xpak_ops, &mi1_mdio_ext_ops,
  "Chelsio 8000 1x10GBaseX TOE" },

{ CHBT_BOARD_CHT110, 1/*ports#*/,
  SUPPORTED_10000baseT_Full | SUPPORTED_FIBRE /*caps*/, CHBT_TERM_T1,
  CHBT_MAC_PM3393, CHBT_PHY_XPAK,
  125000000/*clk-core*/, 150000000/*clk-mc3*/, 125000000/*clk-mc4*/,
  1/*espi-ports*/, 0/*clk-cspi*/, 44/*clk-elmer0*/, 1/*mdien*/,
  1/*mdiinv*/, 1/*mdc*/, 1/*phybaseaddr*/, &t1_pm3393_ops,
  &t1_xpak_ops, &mi1_mdio_ext_ops,
  "Chelsio T110 1x10GBaseX TOE" },

#ifdef CONFIG_CHELSIO_T1_COUGAR
#ifdef CONFIG_CHELSIO_T1_1G
{ CHBT_BOARD_COUGAR, 4/*ports#*/,
  SUPPORTED_10baseT_Half | SUPPORTED_10baseT_Full | SUPPORTED_100baseT_Half |
  SUPPORTED_100baseT_Full | SUPPORTED_1000baseT_Half |
  SUPPORTED_1000baseT_Full | SUPPORTED_Autoneg | SUPPORTED_TP /*caps*/,
  CHBT_TERM_T1, CHBT_MAC_VSC7321, CHBT_PHY_88E1041,
  87500000/*clk-core*/, 87500000/*clk-mc3*/, 87500000/*clk-mc4*/,
  4/*espi-ports*/, 333300000/*clk-cspi*/, 40/*clk-elmer0*/, 0/*mdien*/, 
  0/*mdiinv*/, 4/*mdc*/, 0/*phybaseaddr*/, &t1_vsc7321_ops,
  &t1_mv88e1xxx_ops, &mi1_mdio_ops,
  "Chelsio Cougar 4x100/1000BaseT TOE" },
#endif

{ CHBT_BOARD_COUGAR, 1/*ports#*/,
  SUPPORTED_10000baseT_Full | SUPPORTED_FIBRE /*caps*/, CHBT_TERM_T1,
  CHBT_MAC_VSC7321, CHBT_PHY_XPAK, 
  87500000/*clk-core*/, 87500000/*clk-mc3*/, 87500000/*clk-mc4*/,
  1/*espi-ports*/, 333300000/*clk-cspi*/, 40/*clk-elmer0*/, 1/*mdien*/, 
  1/*mdiinv*/, 1/*mdc*/, 0/*phybaseaddr*/, &t1_vsc7321_ops,
  &t1_xpak_ops, &mi1_mdio_ext_ops,
  "Chelsio Cougar 1x10GBaseX TOE" },
#endif

#ifdef CONFIG_USERMODE
{ CHBT_BOARD_SIMUL, 1/*ports#*/,
  0/*caps*/, CHBT_TERM_T1, CHBT_MAC_DUMMY, CHBT_PHY_DUMMY, 
  125000000/*clk-core*/, 125000000/*clk-mc3*/, 125000000/*clk-mc4*/,
  1/*espi-ports*/, 0/*clk-cspi*/, 0/*clk-elmer0*/, 0/*mdien*/, 
  0/*mdiinv*/, 0/*mdc*/, 0/*phybaseaddr*/, &t1_dummy_mac_ops,
  &t1_dummy_phy_ops, NULL, "Chelsio simulation environment TOE" },
#endif
#endif
};

struct pci_device_id t1_pci_tbl[] = {
	CH_DEVICE(8, 0, CH_BRD_T110_1CU),
	CH_DEVICE(8, 1, CH_BRD_T110_1CU),
	CH_DEVICE(7, 0, CH_BRD_N110_1F),
	CH_DEVICE(10, 1, CH_BRD_N210_1F),
	CH_DEVICE(11, 1, CH_BRD_T210_1F),
	CH_DEVICE(14, 1, CH_BRD_T210_1CU),
#ifdef CONFIG_CHELSIO_T1_OFFLOAD
#ifdef CONFIG_CHELSIO_T1_1G
	CH_DEVICE(12, 1, CH_BRD_T204_4CU),
	CH_DEVICE(13, 1, CH_BRD_T204V_4CU),
	CH_DEVICE(1, 0, CH_BRD_6800_4CU),
	CH_DEVICE(2, 1, CH_BRD_7500_4CU),
	CH_DEVICE(2, 3, CH_BRD_7500_4F),
	CH_DEVICE(4, 0, CH_BRD_T101_1CU_LB),
	CH_DEVICE(4, 2, CH_BRD_T101_1F_LB),
#endif
	CH_DEVICE(3, 0, CH_BRD_8000_1F),
	CH_DEVICE(3, 1, CH_BRD_8000_1F),
	CH_DEVICE(6, 0, CH_BRD_T110_1F),
	CH_DEVICE(6, 1, CH_BRD_T110_1F),
#ifdef CONFIG_CHELSIO_T1_COUGAR
#ifdef CONFIG_CHELSIO_T1_1G
	CH_DEVICE(5, 0, CH_BRD_COUGAR_4CU),
#endif
	CH_DEVICE(5, 1, CH_BRD_COUGAR_1F),
#endif
#ifdef CONFIG_USERMODE
	CH_DEVICE(0x5000, PCI_ANY_ID, CH_BRD_SIMUL),
#endif
#endif
        { 0, }
};

#ifndef CH_DEVICE_COMMON
/*
 * Return the board_info structure with a given index.  Out-of-range indices
 * return NULL.
 */
const struct board_info *
t1_get_board_info(unsigned int board_id)
{
	return (board_id < DIMOF(t1_board) ? &t1_board[board_id] : NULL);
}
#else
/*
 * Return the board_info structure that corresponds to a given PCI devid/ssid
 * pair.  Return NULL if the id combination is unknown.
 */
const struct board_info *t1_get_board_info_from_ids(unsigned int devid,
						    unsigned short ssid)
{
	struct pci_device_id *p;

	for (p = t1_pci_tbl; p->devid; ++p)
		if (p->devid == devid && p->ssid == ssid)
			return (&t1_board[p->board_info_index]);
	return (NULL);
}
#endif

typedef struct {
	u32 format_version;
	u8 serial_number[16];
	u8 mac_base_address[6];
	u8 pad[2];	/* make multiple-of-4 size requirement explicit */
} chelsio_vpd_t;

#define	EEPROMSIZE	(8 * 1024)
#define	EEPROM_MAX_POLL	4

/*
 * Read SEEPROM. A zero is written to the flag register when the addres is
 * written to the Control register. The hardware device will set the flag to a
 * one when 4B have been transferred to the Data register.
 */
int
t1_seeprom_read(adapter_t *adapter, u32 addr, u32 *data)
{
	int i = EEPROM_MAX_POLL;
	u16 val;

	if (addr >= EEPROMSIZE || (addr & 3))
	return (-EINVAL);

	(void) t1_os_pci_write_config_2(adapter, A_PCICFG_VPD_ADDR, (u16)addr);
	do {
		DELAY_US(50);
		(void) t1_os_pci_read_config_2(adapter,
			A_PCICFG_VPD_ADDR, &val);
	} while (!(val & F_VPD_OP_FLAG) && --i);

	if (!(val & F_VPD_OP_FLAG)) {
		CH_ERR("%s: reading EEPROM address 0x%x failed\n",
			adapter_name(adapter), addr);
		return (-EIO);
	}
	(void) t1_os_pci_read_config_4(adapter, A_PCICFG_VPD_DATA, data);
	*data = le32_to_cpu(*data);
	return (0);
}

static int t1_eeprom_vpd_get(adapter_t *adapter, chelsio_vpd_t *vpd)
{
	int addr, ret = 0;

	for (addr = 0; !ret && addr < sizeof (*vpd); addr += sizeof (u32))
		ret = t1_seeprom_read(adapter, addr,
			(u32 *)((u8 *)vpd + addr));

	return (ret);
}

/*
 * Read a port's MAC address from the VPD ROM.
 */
static int vpd_macaddress_get(adapter_t *adapter, int index, u8 mac_addr[])
{
	chelsio_vpd_t vpd;

	if (t1_eeprom_vpd_get(adapter, &vpd))
	return (1);
	memcpy(mac_addr, vpd.mac_base_address, 5);
	mac_addr[5] = vpd.mac_base_address[5] + index;
	return (0);
}

/*
 * Set up the MAC/PHY according to the requested link settings.
 *
 * If the PHY can auto-negotiate first decide what to advertise, then
 * enable/disable auto-negotiation as desired and reset.
 *
 * If the PHY does not auto-negotiate we just reset it.
 *
 * If auto-negotiation is off set the MAC to the proper speed/duplex/FC,
 * otherwise do it later based on the outcome of auto-negotiation.
 */
int
t1_link_start(struct cphy *phy, struct cmac *mac, struct link_config *lc)
{
	unsigned int fc = lc->requested_fc & (PAUSE_RX | PAUSE_TX);

	if (lc->supported & SUPPORTED_Autoneg) {
		lc->advertising &= ~(ADVERTISED_ASYM_PAUSE | ADVERTISED_PAUSE);
		if (fc) {
			if (fc == ((PAUSE_RX | PAUSE_TX) & !is_T2(mac->adapter)))
				lc->advertising |= ADVERTISED_PAUSE;
			else {
				lc->advertising |= ADVERTISED_ASYM_PAUSE;
				if (fc == PAUSE_RX)
					lc->advertising |= ADVERTISED_PAUSE;
			}
		}
		phy->ops->advertise(phy, lc->advertising);

		if (lc->autoneg == AUTONEG_DISABLE) {
			lc->speed = lc->requested_speed;
			lc->duplex = lc->requested_duplex;
			lc->fc = (unsigned char)fc;
			mac->ops->set_speed_duplex_fc(mac, lc->speed,
						      lc->duplex, fc);
			/* Also disables autoneg */
			phy->state = PHY_AUTONEG_RDY;
			phy->ops->set_speed_duplex(phy, lc->speed, lc->duplex);
			phy->ops->reset(phy, 0);
		} else {
			phy->state = PHY_AUTONEG_EN;
			phy->ops->autoneg_enable(phy); /* also resets PHY */
		}
	} else {
		phy->state = PHY_AUTONEG_RDY;
		mac->ops->set_speed_duplex_fc(mac, -1, -1, fc);
		lc->fc = (unsigned char)fc;
		phy->ops->reset(phy, 0);
	}
	return 0;
}

/*
 * External interrupt handler for boards using elmer0.
 */
int
elmer0_ext_intr_handler(adapter_t *adapter)
{
	struct cphy *phy;
	int phy_cause;
	u32 cause;

	(void) t1_tpi_read(adapter, A_ELMER0_INT_CAUSE, &cause);

	switch (board_info(adapter)->board) {
#ifdef CONFIG_CHELSIO_T1_1G
        case CHBT_BOARD_CHT204:
        case CHBT_BOARD_CHT204V: { 
                int i, port_bit;
		for_each_port(adapter, i) {
			port_bit = i ? i + 1 : 0;
			if (!(cause & (1 << port_bit))) continue;

			phy = adapter->port[i].phy;
			phy_cause = phy->ops->interrupt_handler(phy);
			if (phy_cause & cphy_cause_link_change)
				link_changed(adapter, i);
		}
		break;
	}
	case CHBT_BOARD_CHT101:
		if (cause & ELMER0_GP_BIT1) { /* Marvell 88E1111 interrupt */
			phy = adapter->port[0].phy;
			phy_cause = phy->ops->interrupt_handler(phy);
			if (phy_cause & cphy_cause_link_change)
				link_changed(adapter, 0);
		}
		break;
	case CHBT_BOARD_7500: {
		int p;
		/*
		 * Elmer0's interrupt cause isn't useful here because there is
		 * only one bit that can be set for all 4 ports.  This means
		 * we are forced to check every PHY's interrupt status
		 * register to see who initiated the interrupt.
		 */
		for_each_port(adapter, p) {
			phy = adapter->port[p].phy;
			phy_cause = phy->ops->interrupt_handler(phy);
			if (phy_cause & cphy_cause_link_change)
			    link_changed(adapter, p);
		}
		break;
	}
#endif
	case CHBT_BOARD_CHT210:
	case CHBT_BOARD_N210:
	case CHBT_BOARD_N110:
		if (cause & ELMER0_GP_BIT6) { /* Marvell 88x2010 interrupt */
			phy = adapter->port[0].phy;
			phy_cause = phy->ops->interrupt_handler(phy);
			if (phy_cause & cphy_cause_link_change)
				link_changed(adapter, 0);
		}
		break;
	case CHBT_BOARD_8000:
	case CHBT_BOARD_CHT110:
		CH_DBG(adapter, INTR, "External interrupt cause 0x%x\n",
			cause);
		if (cause & ELMER0_GP_BIT1) {	/* PMC3393 INTB */
			struct cmac *mac = adapter->port[0].mac;

			mac->ops->interrupt_handler(mac);
		}
		if (cause & ELMER0_GP_BIT5) {	/* XPAK MOD_DETECT */
			u32 mod_detect;

			(void) t1_tpi_read(adapter, A_ELMER0_GPI_STAT,
				&mod_detect);
			CH_MSG(adapter, INFO, LINK, "XPAK %s\n",
				mod_detect ? "removed" : "inserted");
		}
		break;
#ifdef CONFIG_CHELSIO_T1_COUGAR
	case CHBT_BOARD_COUGAR:
		if (adapter->params.nports == 1) {
			if (cause & ELMER0_GP_BIT1) {	/* Vitesse MAC */
				struct cmac *mac = adapter->port[0].mac;
				mac->ops->interrupt_handler(mac);
			}
			if (cause & ELMER0_GP_BIT5) {	/* XPAK MOD_DETECT */
			}
		} else {
			int i, port_bit;

			for_each_port(adapter, i) {
				port_bit = i ? i + 1 : 0;
				if (!(cause & (1 << port_bit))) continue;

				phy = adapter->port[i].phy;
				phy_cause = phy->ops->interrupt_handler(phy);
				if (phy_cause & cphy_cause_link_change)
					link_changed(adapter, i);
			}
		}
		break;
#endif
	}
	(void) t1_tpi_write(adapter, A_ELMER0_INT_CAUSE, cause);
	return (0);
}

/* Enables all interrupts. */
void
t1_interrupts_enable(adapter_t *adapter)
{
	unsigned int i;

	adapter->slow_intr_mask = F_PL_INTR_SGE_ERR | F_PL_INTR_TP;
	(void) t1_sge_intr_enable(adapter->sge);
	t1_tp_intr_enable(adapter->tp);
#ifdef CONFIG_CHELSIO_T1_OFFLOAD
	if (adapter->mc4) {
		adapter->slow_intr_mask |= F_PL_INTR_MC3 | F_PL_INTR_MC4 |
			F_PL_INTR_ULP | F_PL_INTR_MC5;
	/*
	 * T2 -- Disable interrupts for now b/c we are not clearing
	 * correctly yet.
	 */
		/* t1_ulp_intr_enable(adapter->ulp); */
		t1_ulp_intr_disable(adapter->ulp);

		t1_mc3_intr_enable(adapter->mc3);
		t1_mc4_intr_enable(adapter->mc4);
		t1_mc5_intr_enable(adapter->mc5);
	}
#endif
	if (adapter->espi) {
		adapter->slow_intr_mask |= F_PL_INTR_ESPI;
		t1_espi_intr_enable(adapter->espi);
	}

	/* Enable MAC/PHY interrupts for each port. */
	for_each_port(adapter, i) {
		adapter->port[i].mac->ops->interrupt_enable(adapter->
			port[i].mac);
		adapter->port[i].phy->ops->interrupt_enable(adapter->
			port[i].phy);
	}

	/* Enable PCIX & external chip interrupts on ASIC boards. */
	if (t1_is_asic(adapter)) {
		u32 pl_intr = t1_read_reg_4(adapter, A_PL_ENABLE);

		/* PCI-X interrupts */
		(void) t1_os_pci_write_config_4(adapter, A_PCICFG_INTR_ENABLE,
			0xffffffff);

		adapter->slow_intr_mask |= F_PL_INTR_EXT | F_PL_INTR_PCIX;
		pl_intr |= F_PL_INTR_EXT | F_PL_INTR_PCIX;
		t1_write_reg_4(adapter, A_PL_ENABLE, pl_intr);
	}
}

/* Disables all interrupts. */
void
t1_interrupts_disable(adapter_t * adapter)
{
	unsigned int i;

	(void) t1_sge_intr_disable(adapter->sge);
	t1_tp_intr_disable(adapter->tp);
#ifdef CONFIG_CHELSIO_T1_OFFLOAD
	if (adapter->mc4) {
		t1_ulp_intr_disable(adapter->ulp);
		t1_mc3_intr_disable(adapter->mc3);
		t1_mc4_intr_disable(adapter->mc4);
		t1_mc5_intr_disable(adapter->mc5);
	}
#endif
	if (adapter->espi)
		t1_espi_intr_disable(adapter->espi);

	/* Disable MAC/PHY interrupts for each port. */
	for_each_port(adapter, i) {
		adapter->port[i].mac->ops->interrupt_disable(adapter->
			port[i].mac);
		adapter->port[i].phy->ops->interrupt_disable(adapter->
			port[i].phy);
	}

	/* Disable PCIX & external chip interrupts. */
	if (t1_is_asic(adapter))
		t1_write_reg_4(adapter, A_PL_ENABLE, 0);

	/* PCI-X interrupts */
	(void) t1_os_pci_write_config_4(adapter, A_PCICFG_INTR_ENABLE, 0);

	adapter->slow_intr_mask = 0;
}

/* Clears all interrupts */
void
t1_interrupts_clear(adapter_t * adapter)
{
	unsigned int i;

	(void) t1_sge_intr_clear(adapter->sge);
	t1_tp_intr_clear(adapter->tp);
#ifdef CONFIG_CHELSIO_T1_OFFLOAD
	if (adapter->mc4) {
		t1_ulp_intr_clear(adapter->ulp);
		t1_mc3_intr_clear(adapter->mc3);
		t1_mc4_intr_clear(adapter->mc4);
		t1_mc5_intr_clear(adapter->mc5);
	}
#endif
	if (adapter->espi)
		t1_espi_intr_clear(adapter->espi);

	/* Clear MAC/PHY interrupts for each port. */
	for_each_port(adapter, i) {
		adapter->port[i].mac->ops->interrupt_clear(adapter->
			port[i].mac);
		adapter->port[i].phy->ops->interrupt_clear(adapter->
			port[i].phy);
	}

	/* Enable interrupts for external devices. */
	if (t1_is_asic(adapter)) {
		u32 pl_intr = t1_read_reg_4(adapter, A_PL_CAUSE);

		t1_write_reg_4(adapter, A_PL_CAUSE,
			pl_intr | F_PL_INTR_EXT | F_PL_INTR_PCIX);
	}

	/* PCI-X interrupts */
	(void) t1_os_pci_write_config_4(adapter, A_PCICFG_INTR_CAUSE,
		0xffffffff);
}

/*
 * Slow path interrupt handler for ASICs.
 */
static int asic_slow_intr(adapter_t *adapter)
{
	u32 cause = t1_read_reg_4(adapter, A_PL_CAUSE);

	cause &= adapter->slow_intr_mask;
	if (!cause)
		return (0);
	if (cause & F_PL_INTR_SGE_ERR)
		(void) t1_sge_intr_error_handler(adapter->sge);
	if (cause & F_PL_INTR_TP)
		(void) t1_tp_intr_handler(adapter->tp);
#ifdef CONFIG_CHELSIO_T1_OFFLOAD
	if (cause & F_PL_INTR_MC3)
		(void) t1_mc3_intr_handler(adapter->mc3);
	if (cause & F_PL_INTR_MC4)
		(void) t1_mc4_intr_handler(adapter->mc4);
	if (cause & F_PL_INTR_ULP)
		(void) t1_ulp_intr_handler(adapter->ulp);
	if (cause & F_PL_INTR_MC5)
		(void) t1_mc5_intr_handler(adapter->mc5);
#endif
	if (cause & F_PL_INTR_ESPI)
		(void) t1_espi_intr_handler(adapter->espi);
	if (cause & F_PL_INTR_PCIX)
		(void) t1_pci_intr_handler(adapter);
	if (cause & F_PL_INTR_EXT)
		t1_os_elmer0_ext_intr(adapter);

	/* Clear the interrupts just processed. */
	t1_write_reg_4(adapter, A_PL_CAUSE, cause);
	(void) t1_read_reg_4(adapter, A_PL_CAUSE); /* flush writes */
	return (1);
}

int
t1_slow_intr_handler(adapter_t *adapter)
{
#ifdef CONFIG_CHELSIO_T1_1G
	if (!t1_is_asic(adapter))
		return (fpga_slow_intr(adapter));
#endif
	return (asic_slow_intr(adapter));
}

/* Power sequencing is a work-around for Intel's XPAKs. */
static void
power_sequence_xpak(adapter_t * adapter)
{
	u32 mod_detect;
	u32 gpo;

	/* Check for XPAK */
	(void) t1_tpi_read(adapter, A_ELMER0_GPI_STAT, &mod_detect);
	if (!(ELMER0_GP_BIT5 & mod_detect)) {
		/* XPAK is present */
		(void) t1_tpi_read(adapter, A_ELMER0_GPO, &gpo);
		gpo |= ELMER0_GP_BIT18;
		(void) t1_tpi_write(adapter, A_ELMER0_GPO, gpo);
	}
}

int __devinit t1_get_board_rev(adapter_t *adapter, const struct board_info *bi,
	struct adapter_params *p)
{
	p->chip_version = bi->chip_term;
	p->is_asic = (p->chip_version != CHBT_TERM_FPGA);
	if (p->chip_version == CHBT_TERM_T1 ||
	    p->chip_version == CHBT_TERM_T2 ||
	    p->chip_version == CHBT_TERM_FPGA) {
		u32 val = t1_read_reg_4(adapter, A_TP_PC_CONFIG);

		val = G_TP_PC_REV(val);
		if (val == 2)
			p->chip_revision = TERM_T1B;
		else if (val == 3)
			p->chip_revision = TERM_T2;
		else
			return (-1);
	} else
		return (-1);
	return (0);
}

/*
 * Enable board components other than the Chelsio chip, such as external MAC
 * and PHY.
 */
static int board_init(adapter_t *adapter, const struct board_info *bi)
{
	switch (bi->board) {
	case CHBT_BOARD_8000:
	case CHBT_BOARD_N110:
	case CHBT_BOARD_N210:
	case CHBT_BOARD_CHT210:
	case CHBT_BOARD_COUGAR:
		t1_tpi_par(adapter, 0xf);
		(void) t1_tpi_write(adapter, A_ELMER0_GPO, 0x800);
		break;
	case CHBT_BOARD_CHT110:
		t1_tpi_par(adapter, 0xf);
		(void) t1_tpi_write(adapter, A_ELMER0_GPO, 0x1800);

		/*
		 * TBD XXX Might not need.  This fixes a problem
		 * described in the Intel SR XPAK errata.
		 */
		power_sequence_xpak(adapter);
		break;
#ifdef CONFIG_CHELSIO_T1_1G
	case CHBT_BOARD_CHT204:
	case CHBT_BOARD_CHT204V:
                t1_tpi_par(adapter, 0xf);
                (void) t1_tpi_write(adapter, A_ELMER0_GPO, 0x804);
                break;
	case CHBT_BOARD_CHT101:
	case CHBT_BOARD_7500:
		t1_tpi_par(adapter, 0xf);
		(void) t1_tpi_write(adapter, A_ELMER0_GPO, 0x1804);
		break;
#endif
	}
	return (0);
}

/*
 * Initialize and configure the Terminator HW modules.  Note that external
 * MAC and PHYs are initialized separately.
 */
int
t1_init_hw_modules(adapter_t *adapter)
{
	int err = -EIO;
	const struct board_info *bi = board_info(adapter);

#ifdef CONFIG_CHELSIO_T1_OFFLOAD
	if (adapter->mc3 && t1_mc3_init(adapter->mc3, bi->clock_mc3))
		goto out_err;
	if (adapter->mc4 && t1_mc4_init(adapter->mc4, bi->clock_mc4))
		goto out_err;
	if (adapter->mc5 && t1_mc5_init(adapter->mc5,
					adapter->params.mc5.nservers,
					adapter->params.mc5.nroutes, 1, 0))
		goto out_err;
	if (adapter->ulp && t1_ulp_init(adapter->ulp,
					adapter->params.tp.pm_tx_base))
		goto out_err;
#endif
	if (!adapter->mc4) {
		u32 val = t1_read_reg_4(adapter, A_MC4_CFG);

		t1_write_reg_4(adapter, A_MC4_CFG, val | F_READY | F_MC4_SLOW);
		t1_write_reg_4(adapter, A_MC5_CONFIG,
			F_M_BUS_ENABLE | F_TCAM_RESET);
	}

#ifdef CONFIG_CHELSIO_T1_COUGAR
	if (adapter->cspi && t1_cspi_init(adapter->cspi))
		goto out_err;
#endif
	if (adapter->espi && t1_espi_init(adapter->espi, bi->chip_mac,
		bi->espi_nports))
		goto out_err;

	if (t1_tp_reset(adapter->tp, &adapter->params.tp, bi->clock_core))
		goto out_err;

	err = t1_sge_configure(adapter->sge, &adapter->params.sge);
	if (err)
		goto out_err;

#ifdef CONFIG_CHELSIO_T1_OFFLOAD
	(void) t1_tp_set_coalescing_size(adapter->tp,
		min(adapter->params.sge.large_buf_capacity,
			TP_MAX_RX_COALESCING_SIZE));
#endif
	err = 0;
out_err:
	return (err);
}

/*
 * Determine a card's PCI mode.
 */
static void __devinit get_pci_mode(adapter_t *adapter, struct pci_params *p)
{
	static unsigned short speed_map[] = { 33, 66, 100, 133 };
	u32 pci_mode;

	(void) t1_os_pci_read_config_4(adapter, A_PCICFG_MODE, &pci_mode);
	p->speed = speed_map[G_PCI_MODE_CLK(pci_mode)];
	p->width = (pci_mode & F_PCI_MODE_64BIT) ? 64 : 32;
	p->is_pcix = (pci_mode & F_PCI_MODE_PCIX) != 0;
}

/*
 * Release the structures holding the SW per-Terminator-HW-module state.
 */
void
t1_free_sw_modules(adapter_t *adapter)
{
	unsigned int i;

	for_each_port(adapter, i) {
		struct cmac *mac = adapter->port[i].mac;
		struct cphy *phy = adapter->port[i].phy;

		if (mac)
			mac->ops->destroy(mac);
		if (phy)
			phy->ops->destroy(phy);
	}

	if (adapter->sge)
		(void) t1_sge_destroy(adapter->sge);
	if (adapter->tp)
		t1_tp_destroy(adapter->tp);
	if (adapter->espi)
		t1_espi_destroy(adapter->espi);
#ifdef CONFIG_CHELSIO_T1_OFFLOAD
	if (adapter->mc5)
		t1_mc5_destroy(adapter->mc5);
	if (adapter->mc3)
		t1_mc3_destroy(adapter->mc3);
	if (adapter->mc4)
		t1_mc4_destroy(adapter->mc4);
	if (adapter->ulp)
		t1_ulp_destroy(adapter->ulp);
#endif
#ifdef CONFIG_CHELSIO_T1_COUGAR
	if (adapter->cspi)
		t1_cspi_destroy(adapter->cspi);
#endif
}

static void __devinit init_link_config(struct link_config *lc,
	const struct board_info *bi)
{
	lc->supported = bi->caps;
	lc->requested_speed = lc->speed = SPEED_INVALID;
	lc->requested_duplex = lc->duplex = DUPLEX_INVALID;
	lc->requested_fc = lc->fc = PAUSE_RX | PAUSE_TX;
	if (lc->supported & SUPPORTED_Autoneg) {
		lc->advertising = lc->supported;
		lc->autoneg = AUTONEG_ENABLE;
		lc->requested_fc |= PAUSE_AUTONEG;
	} else {
		lc->advertising = 0;
		lc->autoneg = AUTONEG_DISABLE;
	}
}

#ifdef CONFIG_CHELSIO_T1_OFFLOAD
void init_mtus(unsigned short mtus[])
{
	mtus[0] = 68;
	mtus[1] = 508;
	mtus[2] = 576;
	mtus[3] = 1492;
	mtus[4] = 1500;
	mtus[5] = 2000;
	mtus[6] = 4000;
	mtus[7] = 9000;
}
#endif

/*
 * Allocate and initialize the data structures that hold the SW state of
 * the Terminator HW modules.
 */
int __devinit t1_init_sw_modules(adapter_t *adapter,
	const struct board_info *bi)
{
	unsigned int i;

	adapter->params.brd_info = bi;
	adapter->params.nports = bi->port_number;
	adapter->params.stats_update_period = bi->gmac->stats_update_period;

	adapter->sge = t1_sge_create(adapter, &adapter->params.sge);
	if (!adapter->sge) {
		CH_ERR("%s: SGE initialization failed\n",
			adapter_name(adapter));
		goto error;
	}

#ifdef CONFIG_CHELSIO_T1_OFFLOAD
	if (bi->clock_mc4) {
		/*
		 * Must wait 200us after power up before touching the
		 * memory controllers.
		 */
		DELAY_US(200);

		adapter->mc3 = t1_mc3_create(adapter);
		if (!adapter->mc3) {
			CH_ERR("%s: MC3 initialization failed\n",
				adapter_name(adapter));
			goto error;
		}

		adapter->mc4 = t1_mc4_create(adapter);
		if (!adapter->mc4) {
			CH_ERR("%s: MC4 initialization failed\n",
				adapter_name(adapter));
			goto error;
		}

		if (!adapter->params.mc5.mode)
			adapter->params.mc5.mode = MC5_MODE_144_BIT;
		adapter->mc5 = t1_mc5_create(adapter,
			adapter->params.mc5.mode);
		if (!adapter->mc5) {
			CH_ERR("%s: MC5 initialization failed\n",
				adapter_name(adapter));
			goto error;
		}

		adapter->ulp = t1_ulp_create(adapter);
		if (!adapter->ulp) {
			CH_ERR("%s: ULP initialization failed\n",
				adapter_name(adapter));
			goto error;
		}

		adapter->params.tp.pm_size = t1_mc3_get_size(adapter->mc3);
		adapter->params.tp.cm_size = t1_mc4_get_size(adapter->mc4);

		adapter->params.mc5.nservers = DEFAULT_SERVER_REGION_LEN;
		adapter->params.mc5.nroutes = DEFAULT_RT_REGION_LEN;

		init_mtus(adapter->params.mtus);
	}
#endif

#ifdef CONFIG_CHELSIO_T1_COUGAR
	if (bi->clock_cspi && !(adapter->cspi = t1_cspi_create(adapter))) {
		CH_ERR("%s: CSPI initialization failed\n",
			adapter_name(adapter));
		goto error;
	}
#endif

	if (bi->espi_nports && !(adapter->espi = t1_espi_create(adapter))) {
		CH_ERR("%s: ESPI initialization failed\n",
			adapter_name(adapter));
		goto error;
	}

	adapter->tp = t1_tp_create(adapter, &adapter->params.tp);
	if (!adapter->tp) {
		CH_ERR("%s: TP initialization failed\n",
			adapter_name(adapter));
		goto error;
	}

	(void) board_init(adapter, bi);
	bi->mdio_ops->init(adapter, bi);
	if (bi->gphy->reset)
		bi->gphy->reset(adapter);
	if (bi->gmac->reset)
		bi->gmac->reset(adapter);

	for_each_port(adapter, i) {
		u8 hw_addr[6];
		struct cmac *mac;
		int phy_addr = bi->mdio_phybaseaddr + i;

		adapter->port[i].phy = bi->gphy->create(adapter, phy_addr,
							bi->mdio_ops);
		if (!adapter->port[i].phy) {
			CH_ERR("%s: PHY %d initialization failed\n",
				adapter_name(adapter), i);
			goto error;
		}

		adapter->port[i].mac = mac = bi->gmac->create(adapter, i);
		if (!mac) {
			CH_ERR("%s: MAC %d initialization failed\n",
				adapter_name(adapter), i);
			goto error;
		}

		/*
		 * Get the port's MAC addresses either from the EEPROM if one
		 * exists or the one hardcoded in the MAC.
		 */
		if (!t1_is_asic(adapter) || bi->chip_mac == CHBT_MAC_DUMMY)
			mac->ops->macaddress_get(mac, hw_addr);
		else if (vpd_macaddress_get(adapter, i, hw_addr)) {
			CH_ERR("%s: could not read MAC address from VPD ROM\n",
				port_name(adapter, i));
			goto error;
		}
		t1_os_set_hw_addr(adapter, i, hw_addr);
		init_link_config(&adapter->port[i].link_config, bi);
	}

	get_pci_mode(adapter, &adapter->params.pci);
	t1_interrupts_clear(adapter);
	return (0);

error:
	t1_free_sw_modules(adapter);
	return (-1);
}
