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

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* espi.c */

#include "common.h"
#include "regs.h"
#include "espi.h"

struct peespi {
	adapter_t *adapter;
	struct espi_intr_counts intr_cnt;
	u32 misc_ctrl;
	SPINLOCK lock;
};

#define ESPI_INTR_MASK (F_DIP4ERR | F_RXDROP | F_TXDROP | F_RXOVERFLOW | \
			F_RAMPARITYERR | F_DIP2PARITYERR)
#define MON_MASK  (V_MONITORED_PORT_NUM(3) | F_MONITORED_DIRECTION \
			| F_MONITORED_INTERFACE)

#define TRICN_CNFG 14
#define TRICN_CMD_READ  0x11
#define TRICN_CMD_WRITE 0x21
#define TRICN_CMD_ATTEMPTS 10

static int tricn_write(adapter_t *adapter, int bundle_addr, int module_addr,
		       int ch_addr, int reg_offset, u32 wr_data)
{
	int busy;

	t1_write_reg_4(adapter, A_ESPI_CMD_ADDR, V_WRITE_DATA(wr_data) |
		       V_REGISTER_OFFSET(reg_offset) |
		       V_CHANNEL_ADDR(ch_addr) | V_MODULE_ADDR(module_addr) |
		       V_BUNDLE_ADDR(bundle_addr) |
		       V_SPI4_COMMAND(TRICN_CMD_WRITE));
	t1_write_reg_4(adapter, A_ESPI_GOSTAT, 0);

	busy = t1_wait_op_done(adapter, A_ESPI_GOSTAT, F_ESPI_CMD_BUSY, 0,
			TRICN_CMD_ATTEMPTS, 0);

	if (busy)
		CH_ERR("%s: TRICN write timed out\n", adapter_name(adapter));

	return busy;
}

#if 0
static int tricn_read(adapter_t *adapter, int bundle_addr, int module_addr,
		      int ch_addr, int reg_offset, u8 *rd_data)
{
	int busy, attempts = TRICN_CMD_ATTEMPTS;
	u32 status;

	t1_write_reg_4(adapter, A_ESPI_CMD_ADDR,
		       V_REGISTER_OFFSET(reg_offset) |
		       V_CHANNEL_ADDR(ch_addr) | V_MODULE_ADDR(module_addr) |
		       V_BUNDLE_ADDR(bundle_addr) |
		       V_SPI4_COMMAND(TRICN_CMD_READ));
	t1_write_reg_4(adapter, A_ESPI_GOSTAT, 0);

	do {
		status = t1_read_reg_4(adapter, A_ESPI_GOSTAT);
		busy = status & F_ESPI_CMD_BUSY;
	} while (busy && --attempts);

	if (busy)
		CH_ERR("%s: TRICN read timed out\n", adapter_name(adapter));
	else
		*rd_data = G_READ_DATA(status);
	return busy;
}
#endif

static int tricn_init(adapter_t *adapter)
{
	int i, sme = 1;

	if (!(t1_read_reg_4(adapter, A_ESPI_RX_RESET) & F_RX_CLK_STATUS)) {
		CH_ERR("%s: ESPI clock not ready\n", adapter_name(adapter));
		return (-1);
	 }

	t1_write_reg_4(adapter, A_ESPI_RX_RESET, F_ESPI_RX_CORE_RST);
	
	if (sme) {
		(void) tricn_write(adapter, 0, 0, 0, TRICN_CNFG, 0x81);
		(void) tricn_write(adapter, 0, 1, 0, TRICN_CNFG, 0x81);
		(void) tricn_write(adapter, 0, 2, 0, TRICN_CNFG, 0x81);
	}
	for (i=1; i<= 8; i++) (void) tricn_write(adapter, 0, 0, i, TRICN_CNFG, 0xf1);
	for (i=1; i<= 2; i++) (void) tricn_write(adapter, 0, 1, i, TRICN_CNFG, 0xf1);
	for (i=1; i<= 3; i++) (void) tricn_write(adapter, 0, 2, i, TRICN_CNFG, 0xe1);
	(void) tricn_write(adapter, 0, 2, 4, TRICN_CNFG, 0xf1);
	(void) tricn_write(adapter, 0, 2, 5, TRICN_CNFG, 0xe1);
	(void) tricn_write(adapter, 0, 2, 6, TRICN_CNFG, 0xf1);
	(void) tricn_write(adapter, 0, 2, 7, TRICN_CNFG, 0x80);
	(void) tricn_write(adapter, 0, 2, 8, TRICN_CNFG, 0xf1);

	t1_write_reg_4(adapter, A_ESPI_RX_RESET, F_ESPI_RX_CORE_RST | F_ESPI_RX_LNK_RST);

	return 0;
}

void t1_espi_intr_enable(struct peespi *espi)
{
	u32 enable, pl_intr = t1_read_reg_4(espi->adapter, A_PL_ENABLE);

	/*
	 * Cannot enable ESPI interrupts on T1B because HW asserts the
	 * interrupt incorrectly, namely the driver gets ESPI interrupts
	 * but no data is actually dropped (can verify this reading the ESPI
	 * drop registers).  Also, once the ESPI interrupt is asserted it
	 * cannot be cleared (HW bug).
	 */
	enable = t1_is_T1B(espi->adapter) ? 0 : ESPI_INTR_MASK;
	t1_write_reg_4(espi->adapter, A_ESPI_INTR_ENABLE, enable);
	t1_write_reg_4(espi->adapter, A_PL_ENABLE, pl_intr | F_PL_INTR_ESPI);
}

void t1_espi_intr_clear(struct peespi *espi)
{
	(void) t1_read_reg_4(espi->adapter, A_ESPI_DIP2_ERR_COUNT);
	t1_write_reg_4(espi->adapter, A_ESPI_INTR_STATUS, 0xffffffff);
	t1_write_reg_4(espi->adapter, A_PL_CAUSE, F_PL_INTR_ESPI);
}

void t1_espi_intr_disable(struct peespi *espi)
{
	u32 pl_intr = t1_read_reg_4(espi->adapter, A_PL_ENABLE);

	t1_write_reg_4(espi->adapter, A_ESPI_INTR_ENABLE, 0);
	t1_write_reg_4(espi->adapter, A_PL_ENABLE, pl_intr & ~F_PL_INTR_ESPI);
}

int t1_espi_intr_handler(struct peespi *espi)
{
	u32 status = t1_read_reg_4(espi->adapter, A_ESPI_INTR_STATUS);

	if (status & F_DIP4ERR)
		espi->intr_cnt.DIP4_err++;
	if (status & F_RXDROP)
		espi->intr_cnt.rx_drops++;
	if (status & F_TXDROP)
		espi->intr_cnt.tx_drops++;
	if (status & F_RXOVERFLOW)
		espi->intr_cnt.rx_ovflw++;
	if (status & F_RAMPARITYERR)
		espi->intr_cnt.parity_err++;
	if (status & F_DIP2PARITYERR) {
		espi->intr_cnt.DIP2_parity_err++;
		(void) t1_read_reg_4(espi->adapter, A_ESPI_DIP2_ERR_COUNT);
	 }

	/*
	 * For T1B we need to write 1 to clear ESPI interrupts.  For T2+ we
	 * write the status as is.
	 */
	if (status && t1_is_T1B(espi->adapter))
		status = 1;
	t1_write_reg_4(espi->adapter, A_ESPI_INTR_STATUS, status);
	return 0;
}

const struct espi_intr_counts *t1_espi_get_intr_counts(struct peespi *espi)
{
	return &espi->intr_cnt;
}

static void espi_setup_for_pm3393(adapter_t *adapter)
{
	u32 wmark = t1_is_T1B(adapter) ? 0x4000 : 0x3200;

	t1_write_reg_4(adapter, A_ESPI_SCH_TOKEN0, 0x1f4);
	t1_write_reg_4(adapter, A_ESPI_SCH_TOKEN1, 0x1f4);
	t1_write_reg_4(adapter, A_ESPI_SCH_TOKEN2, 0x1f4);
	t1_write_reg_4(adapter, A_ESPI_SCH_TOKEN3, 0x1f4);
	t1_write_reg_4(adapter, A_ESPI_RX_FIFO_ALMOST_EMPTY_WATERMARK, 0x100);
	t1_write_reg_4(adapter, A_ESPI_RX_FIFO_ALMOST_FULL_WATERMARK, wmark);
	t1_write_reg_4(adapter, A_ESPI_CALENDAR_LENGTH, 3);
	t1_write_reg_4(adapter, A_ESPI_TRAIN, 0x08000008);
	t1_write_reg_4(adapter, A_PORT_CONFIG,
		       V_RX_NPORTS(1) | V_TX_NPORTS(1));
}

static void espi_setup_for_vsc7321(adapter_t *adapter)
{
#ifdef CONFIG_CHELSIO_T1_COUGAR
	u32 wmark = t1_is_T1B(adapter) ? 0x4000 : 0x3200;

        t1_write_reg_4(adapter, A_ESPI_SCH_TOKEN0, 0x1f4);
        t1_write_reg_4(adapter, A_ESPI_SCH_TOKEN1, 0x1f4);
        t1_write_reg_4(adapter, A_ESPI_SCH_TOKEN2, 0x1f4);
	t1_write_reg_4(adapter, A_ESPI_SCH_TOKEN3, 0x1f4);
        t1_write_reg_4(adapter, A_ESPI_RX_FIFO_ALMOST_EMPTY_WATERMARK, 0x100);
        t1_write_reg_4(adapter, A_ESPI_RX_FIFO_ALMOST_FULL_WATERMARK, wmark);
        t1_write_reg_4(adapter, A_ESPI_CALENDAR_LENGTH, 3);
 	t1_write_reg_4(adapter, A_PORT_CONFIG,
		       V_RX_NPORTS(1) | V_TX_NPORTS(1));
#else
        t1_write_reg_4(adapter, A_ESPI_SCH_TOKEN0, 0x1f4);
        t1_write_reg_4(adapter, A_ESPI_SCH_TOKEN1, 0x1f401f4);
        t1_write_reg_4(adapter, A_ESPI_SCH_TOKEN2, 0x1f4);
	t1_write_reg_4(adapter, A_ESPI_RX_FIFO_ALMOST_FULL_WATERMARK, 0xa00);
	t1_write_reg_4(adapter, A_ESPI_RX_FIFO_ALMOST_EMPTY_WATERMARK, 0x1ff);
	t1_write_reg_4(adapter, A_ESPI_CALENDAR_LENGTH, 1);
        t1_write_reg_4(adapter, A_PORT_CONFIG,
                       V_RX_NPORTS(4) | V_TX_NPORTS(4));
#endif
	t1_write_reg_4(adapter, A_ESPI_TRAIN, 0x08000008);
}

/*
 * Note that T1B requires at least 2 ports for IXF1010 due to a HW bug.
 */
static void espi_setup_for_ixf1010(adapter_t *adapter, int nports)
{
	t1_write_reg_4(adapter, A_ESPI_CALENDAR_LENGTH, 1);
	if (nports == 4) {
		if (is_T2(adapter)) {
			t1_write_reg_4(adapter, A_ESPI_RX_FIFO_ALMOST_FULL_WATERMARK,
				0xf00);
			t1_write_reg_4(adapter, A_ESPI_RX_FIFO_ALMOST_EMPTY_WATERMARK,
				0x3c0);
		} else {
			t1_write_reg_4(adapter, A_ESPI_RX_FIFO_ALMOST_FULL_WATERMARK,
				0x7ff);
			t1_write_reg_4(adapter, A_ESPI_RX_FIFO_ALMOST_EMPTY_WATERMARK,
				0x1ff);
		}
	} else {
		t1_write_reg_4(adapter, A_ESPI_RX_FIFO_ALMOST_FULL_WATERMARK,
			       0x1fff);
		t1_write_reg_4(adapter, A_ESPI_RX_FIFO_ALMOST_EMPTY_WATERMARK,
			       0x7ff);
	}
	t1_write_reg_4(adapter, A_PORT_CONFIG,
		       V_RX_NPORTS(nports) | V_TX_NPORTS(nports));
}

int t1_espi_init(struct peespi *espi, int mac_type, int nports)
{
	u32 status_enable_extra = 0;
	adapter_t *adapter = espi->adapter;

	/* Disable ESPI training.  MACs that can handle it enable it below. */
	t1_write_reg_4(adapter, A_ESPI_TRAIN, 0);

	if (is_T2(adapter)) {
		t1_write_reg_4(adapter, A_ESPI_MISC_CONTROL,
			       V_OUT_OF_SYNC_COUNT(4) |
			       V_DIP2_PARITY_ERR_THRES(3) | V_DIP4_THRES(1));
        	t1_write_reg_4(adapter, A_ESPI_MAXBURST1_MAXBURST2,
			nports == 4 ? 0x200040 : 0x1000080);
	} else
		t1_write_reg_4(adapter, A_ESPI_MAXBURST1_MAXBURST2, 0x800100);

	if (mac_type == CHBT_MAC_PM3393)
		espi_setup_for_pm3393(adapter);
	else if (mac_type == CHBT_MAC_VSC7321)
		espi_setup_for_vsc7321(adapter);
	else if (mac_type == CHBT_MAC_IXF1010) {
		status_enable_extra = F_INTEL1010MODE;
		espi_setup_for_ixf1010(adapter, nports);
	} else
		return -1;

	t1_write_reg_4(adapter, A_ESPI_FIFO_STATUS_ENABLE,
		       status_enable_extra | F_RXSTATUSENABLE);

	if (is_T2(adapter)) {
		(void) tricn_init(adapter);
		/*
		 * Always position the control at the 1st port egress IN
		 * (sop,eop) counter to reduce PIOs for T/N210 workaround.
		 */
		espi->misc_ctrl = t1_read_reg_4(adapter, A_ESPI_MISC_CONTROL);
		espi->misc_ctrl &= ~MON_MASK;
		espi->misc_ctrl |= F_MONITORED_DIRECTION;
		if (adapter->params.nports == 1)
			espi->misc_ctrl |= F_MONITORED_INTERFACE;
		t1_write_reg_4(adapter, A_ESPI_MISC_CONTROL, espi->misc_ctrl);
		SPIN_LOCK_INIT(espi->lock);    
	}

	return 0;
}

void t1_espi_destroy(struct peespi *espi)
{
	if (is_T2(espi->adapter)) {
		SPIN_LOCK_DESTROY(espi->lock);
	}
	t1_os_free((void *)espi, sizeof(*espi));
}

struct peespi *t1_espi_create(adapter_t *adapter)
{
	struct peespi *espi = t1_os_malloc_wait_zero(sizeof(*espi));

	if (espi)
		espi->adapter = adapter;
	return espi;
}

void t1_espi_set_misc_ctrl(adapter_t *adapter, u32 val)
{
	struct peespi *espi = adapter->espi;

	if (!is_T2(adapter))
		return;
	SPIN_LOCK(espi->lock);
	espi->misc_ctrl = (val & ~MON_MASK) |
		(espi->misc_ctrl & MON_MASK);
	t1_write_reg_4(adapter, A_ESPI_MISC_CONTROL, espi->misc_ctrl);
	SPIN_UNLOCK(espi->lock);
}

u32 t1_espi_get_mon(adapter_t *adapter, u32 addr, u8 wait)
{
	struct peespi *espi = adapter->espi;
	u32 sel;

	if (!is_T2(adapter)) return 0;
	sel = V_MONITORED_PORT_NUM((addr & 0x3c) >> 2);
	if (!wait) {
		if (!SPIN_TRYLOCK(espi->lock))
			return 0;
        }
	else
		SPIN_LOCK(espi->lock);
	if ((sel != (espi->misc_ctrl & MON_MASK))) {
		t1_write_reg_4(adapter, A_ESPI_MISC_CONTROL,
			((espi->misc_ctrl & ~MON_MASK) | sel));
		sel = t1_read_reg_4(adapter, A_ESPI_SCH_TOKEN3);
		t1_write_reg_4(adapter, A_ESPI_MISC_CONTROL,
			espi->misc_ctrl);
        }
	else
		sel = t1_read_reg_4(adapter, A_ESPI_SCH_TOKEN3);
	SPIN_UNLOCK(espi->lock);
	return sel;
}

/*
 * This function is for T204 only.
 * compare with t1_espi_get_mon(), it reads espiInTxSop[0 ~ 3] in
 * one shot, since there is no per port counter on the out side.
 */
int
t1_espi_get_mon_t204(adapter_t *adapter, u32 *valp, u8 wait)
{
	struct peespi *espi = adapter->espi;
	u8 i, nport = (u8)adapter->params.nports;

	if (!wait) {
		if (!SPIN_TRYLOCK(espi->lock))
			return -1;
	} else
		SPIN_LOCK(espi->lock);
	if ((espi->misc_ctrl & MON_MASK) != F_MONITORED_DIRECTION ) {
		espi->misc_ctrl = (espi->misc_ctrl & ~MON_MASK) |
			F_MONITORED_DIRECTION;
		t1_write_reg_4(adapter, A_ESPI_MISC_CONTROL, espi->misc_ctrl);
	}
	for (i = 0 ; i < nport; i++, valp++) {
		if (i) {
			t1_write_reg_4(adapter, A_ESPI_MISC_CONTROL,
			(espi->misc_ctrl | V_MONITORED_PORT_NUM(i)));
		}
		*valp = t1_read_reg_4(adapter, A_ESPI_SCH_TOKEN3);
	}

	t1_write_reg_4(adapter, A_ESPI_MISC_CONTROL, espi->misc_ctrl);

	SPIN_UNLOCK(espi->lock);
	return 0;
}
