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

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* mc3.c */

#include "common.h"
#include "regs.h"
#include "mc3.h"

#ifdef CONFIG_CHELSIO_T1_1G
# include "fpga_defs.h"
#endif

struct pemc3 {
	adapter_t *adapter;
	unsigned int size;
	struct pemc3_intr_counts intr_cnt;
};

#define MC3_INTR_MASK (F_MC3_CORR_ERR | F_MC3_UNCORR_ERR | \
		       V_MC3_PARITY_ERR(M_MC3_PARITY_ERR) | F_MC3_ADDR_ERR)
#define MC3_INTR_FATAL (F_MC3_UNCORR_ERR | V_MC3_PARITY_ERR(M_MC3_PARITY_ERR) | F_MC3_ADDR_ERR)

void t1_mc3_intr_enable(struct pemc3 *mc3)
{
	u32 en = t1_read_reg_4(mc3->adapter, A_PL_ENABLE);

	if (t1_is_asic(mc3->adapter)) {
		t1_write_reg_4(mc3->adapter, A_MC3_INT_ENABLE, MC3_INTR_MASK);
		t1_write_reg_4(mc3->adapter, A_PL_ENABLE, en | F_PL_INTR_MC3);
#ifdef CONFIG_CHELSIO_T1_1G
	} else {
		t1_write_reg_4(mc3->adapter, FPGA_MC3_REG_INTRENABLE,
			       MC3_INTR_MASK);
		t1_write_reg_4(mc3->adapter, A_PL_ENABLE,
			       en | FPGA_PCIX_INTERRUPT_MC3);
#endif
	}
}

void t1_mc3_intr_disable(struct pemc3 *mc3)
{
	u32 pl_intr = t1_read_reg_4(mc3->adapter, A_PL_ENABLE);

	if (t1_is_asic(mc3->adapter)) {
		t1_write_reg_4(mc3->adapter, A_MC3_INT_ENABLE, 0);
		t1_write_reg_4(mc3->adapter, A_PL_ENABLE,
			       pl_intr & ~F_PL_INTR_MC3);
#ifdef CONFIG_CHELSIO_T1_1G
	} else {
		t1_write_reg_4(mc3->adapter, FPGA_MC3_REG_INTRENABLE, 0);
		t1_write_reg_4(mc3->adapter, A_PL_ENABLE,
			       pl_intr & ~FPGA_PCIX_INTERRUPT_MC3);
#endif
	}
}

void t1_mc3_intr_clear(struct pemc3 *mc3)
{
	if (t1_is_asic(mc3->adapter)) {
		if (t1_is_T1B(mc3->adapter)) {
			/*
			 * Workaround for T1B bug: we must write to enable
			 * register to clear interrupts.
			 */
			u32 old_en;

			old_en = t1_read_reg_4(mc3->adapter, A_MC3_INT_ENABLE);
			t1_write_reg_4(mc3->adapter, A_MC3_INT_ENABLE,
				       0xffffffff);
			t1_write_reg_4(mc3->adapter, A_MC3_INT_ENABLE, old_en);
		} else
			t1_write_reg_4(mc3->adapter, A_MC3_INT_CAUSE,
				       0xffffffff);

		t1_write_reg_4(mc3->adapter, A_PL_CAUSE, F_PL_INTR_MC3);
#ifdef CONFIG_CHELSIO_T1_1G
	} else {
		t1_write_reg_4(mc3->adapter, FPGA_MC3_REG_INTRCAUSE,
			       0xffffffff);
		t1_write_reg_4(mc3->adapter, A_PL_CAUSE,
			       FPGA_PCIX_INTERRUPT_MC3);
#endif
	}
}

int t1_mc3_intr_handler(struct pemc3 *mc3)
{
	adapter_t *adapter = mc3->adapter;
	int cause_reg = A_MC3_INT_CAUSE;
	u32 cause;

#ifdef CONFIG_CHELSIO_T1_1G
	if (!t1_is_asic(adapter))
		cause_reg = FPGA_MC3_REG_INTRCAUSE;
#endif
	cause = t1_read_reg_4(adapter, cause_reg);

	if (cause & F_MC3_CORR_ERR) {
		mc3->intr_cnt.corr_err++;
		CH_WARN("%s: MC3 correctable error at addr 0x%x, "
			"data 0x%x 0x%x 0x%x 0x%x 0x%x\n",
			adapter_name(adapter),
			G_MC3_CE_ADDR(t1_read_reg_4(adapter, A_MC3_CE_ADDR)),
			t1_read_reg_4(adapter, A_MC3_CE_DATA0),
			t1_read_reg_4(adapter, A_MC3_CE_DATA1),
			t1_read_reg_4(adapter, A_MC3_CE_DATA2),
			t1_read_reg_4(adapter, A_MC3_CE_DATA3),
			t1_read_reg_4(adapter, A_MC3_CE_DATA4));
	}

	if (cause & F_MC3_UNCORR_ERR) {
		mc3->intr_cnt.uncorr_err++;
		CH_ALERT("%s: MC3 uncorrectable error at addr 0x%x, "
			 "data 0x%x 0x%x 0x%x 0x%x 0x%x\n",
			 adapter_name(adapter),
			 G_MC3_UE_ADDR(t1_read_reg_4(adapter, A_MC3_UE_ADDR)),
			 t1_read_reg_4(adapter, A_MC3_UE_DATA0),
			 t1_read_reg_4(adapter, A_MC3_UE_DATA1),
			 t1_read_reg_4(adapter, A_MC3_UE_DATA2),
			 t1_read_reg_4(adapter, A_MC3_UE_DATA3),
			 t1_read_reg_4(adapter, A_MC3_UE_DATA4));
	}

	if (G_MC3_PARITY_ERR(cause)) {
		mc3->intr_cnt.parity_err++;
		CH_ALERT("%s: MC3 parity error 0x%x\n", adapter_name(adapter),
			 G_MC3_PARITY_ERR(cause));
	}

	if (cause & F_MC3_ADDR_ERR) {
		mc3->intr_cnt.addr_err++;
		CH_ALERT("%s: MC3 address error\n", adapter_name(adapter));
	}

	if (cause & MC3_INTR_FATAL)
		t1_fatal_err(adapter);

	if (t1_is_T1B(adapter)) {
		/*
		 * Workaround for T1B bug: we must write to enable register to
		 * clear interrupts.
		 */
		t1_write_reg_4(adapter, A_MC3_INT_ENABLE, cause);
		/* restore enable */
		t1_write_reg_4(adapter, A_MC3_INT_ENABLE, MC3_INTR_MASK);
	} else
		t1_write_reg_4(adapter, cause_reg, cause);

	return 0;
}

#define is_MC3A(adapter) (!t1_is_T1B(adapter))

/*
 * Write a value to a register and check that the write completed.  These
 * writes normally complete in a cycle or two, so one read should suffice.
 * The very first read exists to flush the posted write to the device.
 */
static int wrreg_wait(adapter_t *adapter, unsigned int addr, u32 val)
{
	t1_write_reg_4(adapter,	addr, val);
	val = t1_read_reg_4(adapter, addr);                   /* flush */
	if (!(t1_read_reg_4(adapter, addr) & F_BUSY))
		return 0;
	CH_ERR("%s: write to MC3 register 0x%x timed out\n",
	       adapter_name(adapter), addr);
	return -EIO;
}

#define MC3_DLL_DONE (F_MASTER_DLL_LOCKED | F_MASTER_DLL_MAX_TAP_COUNT)

int t1_mc3_init(struct pemc3 *mc3, unsigned int mc3_clock)
{
	u32 val;
	unsigned int width, fast_asic, attempts;
	adapter_t *adapter = mc3->adapter;

	/* Check to see if ASIC is running in slow mode. */
	val = t1_read_reg_4(adapter, A_MC3_CFG);
	width = is_MC3A(adapter) ? G_MC3_WIDTH(val) : 0;
	fast_asic = t1_is_asic(adapter) && !(val & F_MC3_SLOW);

	val &= ~(V_MC3_BANK_CYCLE(M_MC3_BANK_CYCLE) |
		 V_REFRESH_CYCLE(M_REFRESH_CYCLE) |
		 V_PRECHARGE_CYCLE(M_PRECHARGE_CYCLE) |
		 F_ACTIVE_TO_READ_WRITE_DELAY |
		 V_ACTIVE_TO_PRECHARGE_DELAY(M_ACTIVE_TO_PRECHARGE_DELAY) |
		 V_WRITE_RECOVERY_DELAY(M_WRITE_RECOVERY_DELAY));

	if (mc3_clock <= 100000000)
		val |= V_MC3_BANK_CYCLE(7) | V_REFRESH_CYCLE(4) |
			V_PRECHARGE_CYCLE(2) | V_ACTIVE_TO_PRECHARGE_DELAY(5) |
			V_WRITE_RECOVERY_DELAY(2);
	else if (mc3_clock <= 133000000)
		val |= V_MC3_BANK_CYCLE(9) | V_REFRESH_CYCLE(5) |
			V_PRECHARGE_CYCLE(3) | F_ACTIVE_TO_READ_WRITE_DELAY |
			V_ACTIVE_TO_PRECHARGE_DELAY(6) |
			V_WRITE_RECOVERY_DELAY(2);
	else
		val |= V_MC3_BANK_CYCLE(0xA) | V_REFRESH_CYCLE(6) |
			V_PRECHARGE_CYCLE(3) | F_ACTIVE_TO_READ_WRITE_DELAY |
			V_ACTIVE_TO_PRECHARGE_DELAY(7) |
			V_WRITE_RECOVERY_DELAY(3);
	t1_write_reg_4(adapter, A_MC3_CFG, val);

	val = t1_read_reg_4(adapter, A_MC3_CFG);
	t1_write_reg_4(adapter, A_MC3_CFG, val | F_CLK_ENABLE);
	val = t1_read_reg_4(adapter, A_MC3_CFG);                 /* flush */

	if (fast_asic) {                                     /* setup DLLs */
		val = t1_read_reg_4(adapter, A_MC3_STROBE);
		if (is_MC3A(adapter)) {
			t1_write_reg_4(adapter, A_MC3_STROBE,
				       val & ~F_SLAVE_DLL_RESET);

			/* Wait for slave DLLs to lock */
			DELAY_US(2 * 512 / (mc3_clock / 1000000) + 1);
		} else {
			/* Initialize the master DLL and slave delay lines. */
			t1_write_reg_4(adapter, A_MC3_STROBE,
				       val & ~F_MASTER_DLL_RESET);

			/* Wait for the master DLL to lock. */
			attempts = 100;
			do {
				DELAY_US(1);
				val = t1_read_reg_4(adapter, A_MC3_STROBE);
			} while (!(val & MC3_DLL_DONE) && --attempts);
			if (!(val & MC3_DLL_DONE)) {
				CH_ERR("%s: MC3 DLL lock failed\n",
				       adapter_name(adapter));
				goto out_fail;
			}
		}
	}

	/* Initiate a precharge and wait for the precharge to complete. */
	if (wrreg_wait(adapter, A_MC3_PRECHARG, 0))
		goto out_fail;

	/* Set the SDRAM output drive strength and enable DLLs if needed */
	if (wrreg_wait(adapter, A_MC3_EXT_MODE, fast_asic ? 0 : 1))
		goto out_fail;

	/* Specify the SDRAM operating parameters. */
	if (wrreg_wait(adapter, A_MC3_MODE, fast_asic ? 0x161 : 0x21))
		goto out_fail;

	/* Initiate a precharge and wait for the precharge to complete. */
	if (wrreg_wait(adapter, A_MC3_PRECHARG, 0))
		goto out_fail;

	/* Initiate an immediate refresh and wait for the write to complete. */
	val = t1_read_reg_4(adapter, A_MC3_REFRESH);
	if (wrreg_wait(adapter, A_MC3_REFRESH, val & ~F_REFRESH_ENABLE))
		goto out_fail;

	/* 2nd immediate refresh as before */
	if (wrreg_wait(adapter, A_MC3_REFRESH, val & ~F_REFRESH_ENABLE))
		goto out_fail;

	/* Specify the SDRAM operating parameters. */
	if (wrreg_wait(adapter, A_MC3_MODE, fast_asic ? 0x61 : 0x21))
		goto out_fail;

	/* Convert to KHz first to avoid 64-bit division. */
	mc3_clock /=  1000;                            /* Hz->KHz */
	mc3_clock = mc3_clock * 7812 + mc3_clock / 2;  /* ns */
	mc3_clock /= 1000000;                          /* KHz->MHz, ns->us */

	/* Enable periodic refresh. */
	t1_write_reg_4(adapter, A_MC3_REFRESH,
		       F_REFRESH_ENABLE | V_REFRESH_DIVISOR(mc3_clock));
	(void) t1_read_reg_4(adapter, A_MC3_REFRESH);    /* flush */

	t1_write_reg_4(adapter, A_MC3_ECC_CNTL,
		       F_ECC_GENERATION_ENABLE | F_ECC_CHECK_ENABLE);

	/* Use the BIST engine to clear MC3 memory and initialize ECC. */
	t1_write_reg_4(adapter, A_MC3_BIST_ADDR_BEG, 0);
	t1_write_reg_4(adapter, A_MC3_BIST_ADDR_END, (mc3->size << width) - 1);
	t1_write_reg_4(adapter, A_MC3_BIST_DATA, 0);
	t1_write_reg_4(adapter, A_MC3_BIST_OP, V_OP(1) | 0x1f0);
	(void) t1_read_reg_4(adapter, A_MC3_BIST_OP);              /* flush */

	attempts = 100;
	do {
		DELAY_MS(100);
		val = t1_read_reg_4(adapter, A_MC3_BIST_OP);
	} while ((val & F_BUSY) && --attempts);
	if (val & F_BUSY) {
		CH_ERR("%s: MC3 BIST timed out\n", adapter_name(adapter));
		goto out_fail;
	}

	/* Enable normal memory accesses. */
	val = t1_read_reg_4(adapter, A_MC3_CFG);
	t1_write_reg_4(adapter, A_MC3_CFG, val | F_READY);
	return 0;

 out_fail:
	return -1;
}
	
static unsigned int __devinit mc3_calc_size(const adapter_t *adapter, u32 cfg)
{
	unsigned int banks = !!(cfg & F_BANKS) + 1;
	unsigned int org = !!(cfg & F_ORGANIZATION) + 1;
	unsigned int density = G_DENSITY(cfg);

	unsigned int capacity_in_MB = is_MC3A(adapter) ?
		((256 << density) * banks) / (org << G_MC3_WIDTH(cfg)) :
		((128 << density) * (16 / org) * banks) / 8;

	return capacity_in_MB * 1024 * 1024;
}

struct pemc3 * __devinit t1_mc3_create(adapter_t *adapter)
{
	struct pemc3 *mc3 = t1_os_malloc_wait_zero(sizeof(*mc3));

	if (mc3) {
		mc3->adapter = adapter;
		mc3->size = mc3_calc_size(adapter,
					  t1_read_reg_4(adapter, A_MC3_CFG));
	}
	return mc3;
}

void t1_mc3_destroy(struct pemc3 *mc3)
{
	t1_os_free((void *)mc3, sizeof(*mc3));
}

unsigned int t1_mc3_get_size(struct pemc3 *mc3)
{
	return mc3->size;
}

const struct pemc3_intr_counts *t1_mc3_get_intr_counts(struct pemc3 *mc3)
{
	return &mc3->intr_cnt;
}
