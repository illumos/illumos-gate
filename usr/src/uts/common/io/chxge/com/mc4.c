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
 * This file is part of the Chelsio T1 Ethernet driver.
 *
 * Copyright (C) 2003-2005 Chelsio Communications.  All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* mc4.c */

#include "common.h"
#include "regs.h"
#include "mc4.h"

struct pemc4 {
	adapter_t *adapter;
	unsigned int size;
	unsigned int nwords;           /* MC4 width in terms of 32-bit words */
	struct pemc4_intr_counts intr_cnt;
};

void t1_mc4_destroy(struct pemc4 *mc4)
{
	t1_os_free((void *)mc4, sizeof(*mc4));
}

#define is_MC4A(adapter) (!t1_is_T1B(adapter))

/* Calculate amount of MC4 memory. */
static unsigned int __devinit mc4_calc_size(adapter_t *adapter)
{
	u32 mc4_cfg = t1_read_reg_4(adapter, A_MC4_CFG);
	unsigned int width = is_MC4A(adapter) ? G_MC4A_WIDTH(mc4_cfg) :
		                                !!(mc4_cfg & F_MC4_NARROW);

	return (256 * 1024 * 1024) >> width;
}

/*
 * Write a value to a register and check that the write completed.  These
 * writes normally complete in a cycle or two, so one read should suffice but
 * just in case we give them a bit of grace period.  Note that the very first
 * read exists to flush the posted write to the device.
 */
static int wrreg_wait(adapter_t *adapter, unsigned int addr, u32 val)
{
	int attempts = 2;

	t1_write_reg_4(adapter,	addr, val);
	val = t1_read_reg_4(adapter, addr);                   /* flush */
	while (attempts--) {
		if (!(t1_read_reg_4(adapter, addr) & F_BUSY))
			return 0;
		if (attempts)
			DELAY_US(1);
	}
	CH_ERR("%s: write to MC4 register 0x%x timed out\n",
	       adapter_name(adapter), addr);
	return -EIO;
}

#define MC4_DLL_DONE (F_MASTER_DLL_LOCKED | F_MASTER_DLL_MAX_TAP_COUNT)

int t1_mc4_init(struct pemc4 *mc4, unsigned int mc4_clock)
{
	int attempts;
	u32 val;
	unsigned int width, ext_mode, slow_mode;
	adapter_t *adapter = mc4->adapter;

	/* Power up the FCRAMs. */
	val = t1_read_reg_4(adapter, A_MC4_CFG);
	t1_write_reg_4(adapter, A_MC4_CFG, val | F_POWER_UP);
	val = t1_read_reg_4(adapter, A_MC4_CFG);               /* flush */

	if (is_MC4A(adapter)) {
		slow_mode = val & F_MC4A_SLOW;
		width = G_MC4A_WIDTH(val);

		/* If we're not in slow mode, we are using the DLLs */
		if (!slow_mode) {
			/* Clear Reset */
			val = t1_read_reg_4(adapter, A_MC4_STROBE);
			t1_write_reg_4(adapter, A_MC4_STROBE,
				       val & ~F_SLAVE_DLL_RESET);

			/* Wait for slave DLLs to lock */
			DELAY_US(2 * 512 / (mc4_clock / 1000000) + 1);
		}
	} else {
		slow_mode = val & F_MC4_SLOW;
		width = !!(val & F_MC4_NARROW);

		/* Initializes the master DLL and slave delay lines. */
		if (t1_is_asic(adapter) && !slow_mode) {
			val = t1_read_reg_4(adapter, A_MC4_STROBE);
			t1_write_reg_4(adapter, A_MC4_STROBE,
				       val & ~F_MASTER_DLL_RESET);

			/* Wait for the master DLL to lock. */
			attempts = 100;
			do {
				DELAY_US(1);
				val = t1_read_reg_4(adapter, A_MC4_STROBE);
			} while (!(val & MC4_DLL_DONE) && --attempts);
			if (!(val & MC4_DLL_DONE)) {
				CH_ERR("%s: MC4 DLL lock failed\n",
				       adapter_name(adapter));
				goto out_fail;
			}
		}
	}

	mc4->nwords = 4 >> width;

	/* Set the FCRAM output drive strength and enable DLLs if needed */
	ext_mode = t1_is_asic(adapter) && !slow_mode ? 0 : 1;
	if (wrreg_wait(adapter, A_MC4_EXT_MODE, ext_mode))
		goto out_fail;

	/* Specify the FCRAM operating parameters */
	if (wrreg_wait(adapter, A_MC4_MODE, 0x32))
		goto out_fail;

	/* Initiate an immediate refresh and wait for the write to complete. */
	val = t1_read_reg_4(adapter, A_MC4_REFRESH);
	if (wrreg_wait(adapter, A_MC4_REFRESH, val & ~F_REFRESH_ENABLE))
		goto out_fail;

	/* 2nd immediate refresh as before */
	if (wrreg_wait(adapter, A_MC4_REFRESH, val & ~F_REFRESH_ENABLE))
		goto out_fail;

	/* Convert to KHz first to avoid 64-bit division. */
	mc4_clock /= 1000;                            /* Hz->KHz */
	mc4_clock = mc4_clock * 7812 + mc4_clock / 2; /* ns */
	mc4_clock /= 1000000;                         /* KHz->MHz, ns->us */

	/* Enable periodic refresh. */
	t1_write_reg_4(adapter, A_MC4_REFRESH,
		       F_REFRESH_ENABLE | V_REFRESH_DIVISOR(mc4_clock));
	(void) t1_read_reg_4(adapter, A_MC4_REFRESH);    /* flush */

	t1_write_reg_4(adapter, A_MC4_ECC_CNTL,
		       F_ECC_GENERATION_ENABLE | F_ECC_CHECK_ENABLE);

	/* Use the BIST engine to clear all of the MC4 memory. */
	t1_write_reg_4(adapter, A_MC4_BIST_ADDR_BEG, 0);
	t1_write_reg_4(adapter, A_MC4_BIST_ADDR_END, (mc4->size << width) - 1);
	t1_write_reg_4(adapter, A_MC4_BIST_DATA, 0);
	t1_write_reg_4(adapter, A_MC4_BIST_OP, V_OP(1) | 0x1f0);
	(void) t1_read_reg_4(adapter, A_MC4_BIST_OP);              /* flush */

	attempts = 100;
	do {
		DELAY_MS(100);
		val = t1_read_reg_4(adapter, A_MC4_BIST_OP);
	} while ((val & F_BUSY) && --attempts);
	if (val & F_BUSY) {
		CH_ERR("%s: MC4 BIST timed out\n", adapter_name(adapter));
		goto out_fail;
	}

	/* Enable normal memory accesses. */
	val = t1_read_reg_4(adapter, A_MC4_CFG);
	t1_write_reg_4(adapter, A_MC4_CFG, val | F_READY);
	val = t1_read_reg_4(adapter, A_MC4_CFG);               /* flush */
	return 0;

 out_fail:
	return -1;
}

struct pemc4 * __devinit t1_mc4_create(adapter_t *adapter)
{
	struct pemc4 *mc4 = t1_os_malloc_wait_zero(sizeof(*mc4));

	if (mc4) {
		mc4->adapter = adapter;
		mc4->size = mc4_calc_size(adapter);
	}
	return mc4;
}

unsigned int t1_mc4_get_size(struct pemc4 *mc4)
{
	return mc4->size;
}

#define MC4_INT_MASK (F_MC4_CORR_ERR | F_MC4_UNCORR_ERR | F_MC4_ADDR_ERR)
#define MC4_INT_FATAL (F_MC4_UNCORR_ERR | F_MC4_ADDR_ERR)

void t1_mc4_intr_enable(struct pemc4 *mc4)
{
	u32 pl_intr;

	if (t1_is_asic(mc4->adapter)) {
		t1_write_reg_4(mc4->adapter, A_MC4_INT_ENABLE, MC4_INT_MASK);

		pl_intr = t1_read_reg_4(mc4->adapter, A_PL_ENABLE);
		t1_write_reg_4(mc4->adapter, A_PL_ENABLE,
			       pl_intr | F_PL_INTR_MC4);
	}
}

void t1_mc4_intr_disable(struct pemc4 *mc4)
{
	u32 pl_intr;

	if (t1_is_asic(mc4->adapter)) {
		t1_write_reg_4(mc4->adapter, A_MC4_INT_ENABLE, 0);

		pl_intr = t1_read_reg_4(mc4->adapter, A_PL_ENABLE);
		t1_write_reg_4(mc4->adapter, A_PL_ENABLE,
			       pl_intr & ~F_PL_INTR_MC4);
	}
}

void t1_mc4_intr_clear(struct pemc4 *mc4)
{
	if (t1_is_asic(mc4->adapter)) {
		t1_write_reg_4(mc4->adapter, A_MC4_INT_CAUSE, 0xffffffff);
		t1_write_reg_4(mc4->adapter, A_PL_CAUSE, F_PL_INTR_MC4);
	}
}

int t1_mc4_intr_handler(struct pemc4 *mc4)
{
	adapter_t *adapter = mc4->adapter;
	u32 cause = t1_read_reg_4(adapter, A_MC4_INT_CAUSE);

	if (cause & F_MC4_CORR_ERR) {
		mc4->intr_cnt.corr_err++;
		CH_WARN("%s: MC4 correctable error at addr 0x%x, "
			"data 0x%x 0x%x 0x%x 0x%x 0x%x\n",
			adapter_name(adapter),
			G_MC4_CE_ADDR(t1_read_reg_4(adapter, A_MC4_CE_ADDR)),
			t1_read_reg_4(adapter, A_MC4_CE_DATA0),
			t1_read_reg_4(adapter, A_MC4_CE_DATA1),
			t1_read_reg_4(adapter, A_MC4_CE_DATA2),
			t1_read_reg_4(adapter, A_MC4_CE_DATA3),
			t1_read_reg_4(adapter, A_MC4_CE_DATA4));
	}

	if (cause & F_MC4_UNCORR_ERR) {
		mc4->intr_cnt.uncorr_err++;
		CH_ALERT("%s: MC4 uncorrectable error at addr 0x%x, "
			 "data 0x%x 0x%x 0x%x 0x%x 0x%x\n",
			 adapter_name(adapter),
			 G_MC4_UE_ADDR(t1_read_reg_4(adapter, A_MC4_UE_ADDR)),
			 t1_read_reg_4(adapter, A_MC4_UE_DATA0),
			 t1_read_reg_4(adapter, A_MC4_UE_DATA1),
			 t1_read_reg_4(adapter, A_MC4_UE_DATA2),
			 t1_read_reg_4(adapter, A_MC4_UE_DATA3),
			 t1_read_reg_4(adapter, A_MC4_UE_DATA4));
	}

	if (cause & F_MC4_ADDR_ERR) {
		mc4->intr_cnt.addr_err++;
		CH_ALERT("%s: MC4 address error\n", adapter_name(adapter));
	}

	if (cause & MC4_INT_FATAL)
		t1_fatal_err(adapter);

	t1_write_reg_4(mc4->adapter, A_MC4_INT_CAUSE, cause);
	return 0;
}

const struct pemc4_intr_counts *t1_mc4_get_intr_counts(struct pemc4 *mc4)
{
	return &mc4->intr_cnt;
}

/*
 * Read n 256-bit words from MC4 starting at word start, using backdoor
 * accesses.
 */
int t1_mc4_bd_read(struct pemc4 *mc4, unsigned int start, unsigned int n,
		   u32 *buf)
{
	adapter_t *adap = mc4->adapter;
	unsigned int size256 = mc4->size / 32, c = 8 / mc4->nwords, i;

	if (start >= size256 || start + n > size256)
		return -EINVAL;

	for (i = 8, start *= 16 * c, n *= c; n; --n, start += 16) {
		int attempts = 10;
		u32 val;

		t1_write_reg_4(adap, A_MC4_BD_ADDR, start);
		t1_write_reg_4(adap, A_MC4_BD_OP, 0);
		val = t1_read_reg_4(adap, A_MC4_BD_OP);
		while ((val & F_BUSY) && attempts--)
			val = t1_read_reg_4(adap, A_MC4_BD_OP);

		if (val & F_BUSY)
			return -EIO;

		buf[--i] = t1_read_reg_4(adap, A_MC4_BD_DATA3);
		if (mc4->nwords >= 2)
			buf[--i] = t1_read_reg_4(adap, A_MC4_BD_DATA2);
		if (mc4->nwords == 4) {
			buf[--i] = t1_read_reg_4(adap, A_MC4_BD_DATA1);
			buf[--i] = t1_read_reg_4(adap, A_MC4_BD_DATA0);
		}
		if (i == 0) {
			i = 8;
			buf += 8;
		}
	}
	return 0;
}
