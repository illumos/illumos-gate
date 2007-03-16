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

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* ch_mac.c */

#include "gmac.h"
#include "regs.h"
#include "fpga_defs.h"

#define	MAC_CSR_INTERFACE_GMII	0x0
#define	MAC_CSR_INTERFACE_TBI	0x1
#define	MAC_CSR_INTERFACE_MII	0x2
#define	MAC_CSR_INTERFACE_RMII	0x3

/* Chelsio's MAC statistics. */
struct mac_statistics {

	/* Transmit */
	u32 TxFramesTransmittedOK;
	u32 TxReserved1;
	u32 TxReserved2;
	u32 TxOctetsTransmittedOK;
	u32 TxFramesWithDeferredXmissions;
	u32 TxLateCollisions;
	u32 TxFramesAbortedDueToXSCollisions;
	u32 TxFramesLostDueToIntMACXmitError;
	u32 TxReserved3;
	u32 TxMulticastFrameXmittedOK;
	u32 TxBroadcastFramesXmittedOK;
	u32 TxFramesWithExcessiveDeferral;
	u32 TxPAUSEMACCtrlFramesTransmitted;

	/* Receive */
	u32 RxFramesReceivedOK;
	u32 RxFrameCheckSequenceErrors;
	u32 RxAlignmentErrors;
	u32 RxOctetsReceivedOK;
	u32 RxFramesLostDueToIntMACRcvError;
	u32 RxMulticastFramesReceivedOK;
	u32 RxBroadcastFramesReceivedOK;
	u32 RxInRangeLengthErrors;
	u32 RxTxOutOfRangeLengthField;
	u32 RxFrameTooLongErrors;
	u32 RxPAUSEMACCtrlFramesReceived;
};

static int static_aPorts[] = {
	FPGA_GMAC_INTERRUPT_PORT0,
	FPGA_GMAC_INTERRUPT_PORT1,
	FPGA_GMAC_INTERRUPT_PORT2,
	FPGA_GMAC_INTERRUPT_PORT3
};

struct _cmac_instance {
	u32 index;
};

static int mac_intr_enable(struct cmac *mac)
{
	u32 mac_intr;

	if (t1_is_asic(mac->adapter)) {
		/* ASIC */
		/*EMPTY*/
		/* We don't use the on chip MAC for ASIC products. */
	} else {
		/* FPGA */

		/* Set parent gmac interrupt. */
		mac_intr = t1_read_reg_4(mac->adapter, A_PL_ENABLE);
		mac_intr |= FPGA_PCIX_INTERRUPT_GMAC;
		t1_write_reg_4(mac->adapter, A_PL_ENABLE, mac_intr);

		mac_intr = t1_read_reg_4(mac->adapter,
			FPGA_GMAC_ADDR_INTERRUPT_ENABLE);
		mac_intr |= static_aPorts[mac->instance->index];
		t1_write_reg_4(mac->adapter,
			FPGA_GMAC_ADDR_INTERRUPT_ENABLE, mac_intr);
	}

	return (0);
}

static int mac_intr_disable(struct cmac *mac)
{
	u32 mac_intr;

	if (t1_is_asic(mac->adapter)) {
		/* ASIC */
		/*EMPTY*/
		/* We don't use the on chip MAC for ASIC products. */
	} else {
		/* FPGA */

		/* Set parent gmac interrupt. */
		mac_intr = t1_read_reg_4(mac->adapter, A_PL_ENABLE);
		mac_intr &= ~FPGA_PCIX_INTERRUPT_GMAC;
		t1_write_reg_4(mac->adapter, A_PL_ENABLE, mac_intr);

		mac_intr = t1_read_reg_4(mac->adapter,
			FPGA_GMAC_ADDR_INTERRUPT_ENABLE);
		mac_intr &= ~(static_aPorts[mac->instance->index]);
		t1_write_reg_4(mac->adapter,
			FPGA_GMAC_ADDR_INTERRUPT_ENABLE, mac_intr);
	}

	return (0);
}

static int mac_intr_clear(struct cmac *mac)
{
	u32 mac_intr;

	if (t1_is_asic(mac->adapter)) {
		/* ASIC */
		/*EMPTY*/
		/* We don't use the on chip MAC for ASIC products. */
	} else {
		/* FPGA */

		/* Set parent gmac interrupt. */
		t1_write_reg_4(mac->adapter, A_PL_CAUSE,
			FPGA_PCIX_INTERRUPT_GMAC);

		mac_intr = t1_read_reg_4(mac->adapter,
			FPGA_GMAC_ADDR_INTERRUPT_CAUSE);
		mac_intr |= (static_aPorts[mac->instance->index]);
		t1_write_reg_4(mac->adapter,
			FPGA_GMAC_ADDR_INTERRUPT_CAUSE, mac_intr);
	}

	return (0);
}

static int mac_get_address(struct cmac *mac, u8 addr[6])
{
	u32 data32_lo, data32_hi;

	data32_lo = t1_read_reg_4(mac->adapter,
			MAC_REG_IDLO(mac->instance->index));
	data32_hi = t1_read_reg_4(mac->adapter,
			MAC_REG_IDHI(mac->instance->index));

	addr[0] = (u8) ((data32_hi >> 8) & 0xFF);
	addr[1] = (u8) ((data32_hi) & 0xFF);
	addr[2] = (u8) ((data32_lo >> 24) & 0xFF);
	addr[3] = (u8) ((data32_lo >> 16) & 0xFF);
	addr[4] = (u8) ((data32_lo >> 8) & 0xFF);
	addr[5] = (u8) ((data32_lo) & 0xFF);
	return (0);
}

static int mac_reset(struct cmac *mac)
{
	u32 data32;
	int mac_in_reset, time_out = 100;
	int idx = mac->instance->index;

	data32 = t1_read_reg_4(mac->adapter, MAC_REG_CSR(idx));
	t1_write_reg_4(mac->adapter, MAC_REG_CSR(idx),
		data32 | F_MAC_RESET);

	do {
		data32 = t1_read_reg_4(mac->adapter,
			MAC_REG_CSR(idx));
		mac_in_reset = data32 & F_MAC_RESET;
		if (mac_in_reset)
			DELAY_US(1);
	} while (mac_in_reset && --time_out);

	if (mac_in_reset) {
		CH_ERR("%s: MAC %d reset timed out\n",
			adapter_name(mac->adapter), idx);
		return (2);
	}

	return (0);
}

static int mac_set_rx_mode(struct cmac *mac, struct t1_rx_mode *rm)
{
	u32 val;

	val = t1_read_reg_4(mac->adapter,
			    MAC_REG_CSR(mac->instance->index));
	val &= ~(F_MAC_PROMISC | F_MAC_MC_ENABLE);
	val |= V_MAC_PROMISC(t1_rx_mode_promisc(rm) != 0);
	val |= V_MAC_MC_ENABLE(t1_rx_mode_allmulti(rm) != 0);
	t1_write_reg_4(mac->adapter,
		MAC_REG_CSR(mac->instance->index), val);

	return (0);
}

static int mac_set_speed_duplex_fc(struct cmac *mac, int speed, int duplex,
	int fc)
{
	u32 data32;

	data32 = t1_read_reg_4(mac->adapter,
		MAC_REG_CSR(mac->instance->index));
	data32 &= ~(F_MAC_HALF_DUPLEX | V_MAC_SPEED(M_MAC_SPEED) |
		V_INTERFACE(M_INTERFACE) | F_MAC_TX_PAUSE_ENABLE |
		F_MAC_RX_PAUSE_ENABLE);

	switch (speed) {
	case SPEED_10:
	case SPEED_100:
		data32 |= V_INTERFACE(MAC_CSR_INTERFACE_MII);
		data32 |= V_MAC_SPEED(speed == SPEED_10 ? 0 : 1);
		break;
	case SPEED_1000:
		data32 |= V_INTERFACE(MAC_CSR_INTERFACE_GMII);
		data32 |= V_MAC_SPEED(2);
		break;
	}

	if (duplex >= 0)
		data32 |= V_MAC_HALF_DUPLEX(duplex == DUPLEX_HALF);

	if (fc >= 0) {
		data32 |= V_MAC_RX_PAUSE_ENABLE((fc & PAUSE_RX) != 0);
		data32 |= V_MAC_TX_PAUSE_ENABLE((fc & PAUSE_TX) != 0);
	}

	t1_write_reg_4(mac->adapter,
		MAC_REG_CSR(mac->instance->index), data32);
	return (0);
}

static int mac_enable(struct cmac *mac, int which)
{
	u32 val;

	val = t1_read_reg_4(mac->adapter,
			    MAC_REG_CSR(mac->instance->index));
	if (which & MAC_DIRECTION_RX)
		val |= F_MAC_RX_ENABLE;
	if (which & MAC_DIRECTION_TX)
		val |= F_MAC_TX_ENABLE;
	t1_write_reg_4(mac->adapter,
		MAC_REG_CSR(mac->instance->index), val);
	return (0);
}

static int mac_disable(struct cmac *mac, int which)
{
	u32 val;

	val = t1_read_reg_4(mac->adapter,
		MAC_REG_CSR(mac->instance->index));
	if (which & MAC_DIRECTION_RX)
		val &= ~F_MAC_RX_ENABLE;
	if (which & MAC_DIRECTION_TX)
		val &= ~F_MAC_TX_ENABLE;
	t1_write_reg_4(mac->adapter,
		MAC_REG_CSR(mac->instance->index), val);
	return (0);
}

int
mac_set_ifs(struct cmac *mac, u32 mode)
{
	t1_write_reg_4(mac->adapter,
		MAC_REG_IFS(mac->instance->index), mode);

	return (0);
}

int
mac_enable_isl(struct cmac *mac)
{
	u32 data32 = t1_read_reg_4(mac->adapter,
		MAC_REG_CSR(mac->instance->index));
	data32 |= F_MAC_RX_ENABLE | F_MAC_TX_ENABLE;
	t1_write_reg_4(mac->adapter,
		MAC_REG_CSR(mac->instance->index), data32);

	return (0);
}

static int mac_set_mtu(struct cmac *mac, int mtu)
{
	if (mtu > 9600)
		return (-EINVAL);
	t1_write_reg_4(mac->adapter,
		MAC_REG_LARGEFRAMELENGTH(mac->instance->index),
		mtu + 14 + 4);
	return (0);
}

/* ARGSUSED */
static const struct cmac_statistics *mac_update_statistics(struct cmac *mac,
	int flag)
{
	struct mac_statistics st;
	u32 *p = (u32 *) & st, i;

	t1_write_reg_4(mac->adapter,
		MAC_REG_RMCNT(mac->instance->index), 0);
	for (i = 0; i < sizeof (st) / sizeof (u32); i++)
		*p++ = t1_read_reg_4(mac->adapter,
			MAC_REG_RMDATA(mac->instance->index));

	/* XXX convert stats */
	return (&mac->stats);
}

static void mac_destroy(struct cmac *mac)
{
	t1_os_free((void *)mac, sizeof (*mac) + sizeof (cmac_instance));
}

#ifdef C99_NOT_SUPPORTED
static struct cmac_ops chelsio_mac_ops = {
	mac_destroy,
	mac_reset,
	mac_intr_enable,
	mac_intr_disable,
	mac_intr_clear,
	NULL,
	mac_enable,
	mac_disable,
	NULL,
	NULL,
	mac_set_mtu,
	mac_set_rx_mode,
	mac_set_speed_duplex_fc,
	NULL,
	mac_update_statistics,
	mac_get_address,
	NULL
};
#else
static struct cmac_ops chelsio_mac_ops = {
	.destroy		= mac_destroy,
	.reset			= mac_reset,
	.interrupt_enable	= mac_intr_enable,
	.interrupt_disable	= mac_intr_disable,
	.interrupt_clear	= mac_intr_clear,
	.enable			= mac_enable,
	.disable		= mac_disable,
	.set_mtu		= mac_set_mtu,
	.set_rx_mode		= mac_set_rx_mode,
	.set_speed_duplex_fc	= mac_set_speed_duplex_fc,
	.macaddress_get		= mac_get_address,
	.statistics_update	= mac_update_statistics,
};
#endif

static struct cmac *mac_create(adapter_t *adapter, int index)
{
	struct cmac *mac;
	u32 data32;

	if (index >= 4)
		return (NULL);

	mac = t1_os_malloc_wait_zero(sizeof (*mac) + sizeof (cmac_instance));
	if (!mac)
		return (NULL);

	mac->ops = &chelsio_mac_ops;
	mac->instance = (cmac_instance *) (mac + 1);

	mac->instance->index = index;
	mac->adapter = adapter;

	data32 = t1_read_reg_4(adapter, MAC_REG_CSR(mac->instance->index));
	data32 &= ~(F_MAC_RESET | F_MAC_PROMISC | F_MAC_PROMISC |
		    F_MAC_LB_ENABLE | F_MAC_RX_ENABLE | F_MAC_TX_ENABLE);
	data32 |= F_MAC_JUMBO_ENABLE;
	t1_write_reg_4(adapter, MAC_REG_CSR(mac->instance->index), data32);

	/* Initialize the random backoff seed. */
	data32 = 0x55aa + (3 * index);
	t1_write_reg_4(adapter,
		MAC_REG_GMRANDBACKOFFSEED(mac->instance->index), data32);

	/* Check to see if the mac address needs to be set manually. */
	data32 = t1_read_reg_4(adapter, MAC_REG_IDLO(mac->instance->index));
	if (data32 == 0 || data32 == 0xffffffff) {
		/*
		 * Add a default MAC address if we can't read one.
		 */
		t1_write_reg_4(adapter, MAC_REG_IDLO(mac->instance->index),
			0x43FFFFFF - index);
		t1_write_reg_4(adapter, MAC_REG_IDHI(mac->instance->index),
			0x0007);
	}

	(void) mac_set_mtu(mac, 1500);
	return (mac);
}

struct gmac t1_chelsio_mac_ops = {
	0,
	mac_create
};
