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

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* mc5.c */

#include "common.h"
#include "regs.h"
#include "mc5.h"

/* DBGI command mode */
enum {
      	DBGI_MODE_MBUS,
	DBGI_MODE_LARA_7000,
	DBGI_MODE_LARA_8000,
	DBGI_MODE_NETL_4000,
	DBGI_MODE_NETL_5000,
	DBGI_MODE_IDT_52100
};

/* Lara command register address and values (low 32 bits) */
#define MC5_LRA_CMDREG_ADR0		0x00180038
#define MC5_LRA_CMDREG_72KEY_DATA0	0x00000182
#define MC5_LRA_CMDREG_144KEY_DATA0	0x00AAAB82

/* Lara config register address and values (low 32 bits) */
#define MC5_LRA_CFGREG_ADR0		0x0018003D
#define MC5_LRA_CFGREG_72KEY_DATA0	0x00000000
#define MC5_LRA_CFGREG_144KEY_DATA0	0x55555555

/* Lara GMR base addresses (low 32 bits) */
#define MC5_LRA_GMRREG_BASE_ADR0_1	0x00180020
#define MC5_LRA_GMRREG_BASE_ADR0_2	0x00180060

/* Lara 7000 data and mask array base addresses (low 32 bits) */
#define MC5_LRA_DATARY_BASE_ADR0	0x00000000
#define MC5_LRA_MSKARY_BASE_ADR0	0x00080000

/* Lara commands */
#define MC5_LRA_CMD_READ		0x00000000
#define MC5_LRA_CMD_WRITE		0x00010001
#define MC5_LRA_CMD_SEARCH		0x00020002
#define MC5_LRA_CMD_LEARN		0x00030003

/* IDT 75P52100 commands */
#define MC5_IDT_CMD_READ		0x0
#define MC5_IDT_CMD_WRITE		0x1
#define MC5_IDT_CMD_SEARCH		0x2
#define MC5_IDT_CMD_LEARN		0x3
#define MC5_IDT_CMD_NFA_SEARCH		0x4

/* IDT LAR register address and value for 144-bit mode (low 32 bits) */
#define MC5_IDT_LAR_ADR0		0x180006
#define MC5_IDT_LAR_MODE144		0xffff0000

/* IDT SCR and SSR addresses (low 32 bits) */
#define MC5_IDT_SCR_ADR0		0x180000
#define MC5_IDT_SSR0_ADR0		0x180002
#define MC5_IDT_SSR1_ADR0		0x180004

/* IDT GMR base address (low 32 bits) */
#define MC5_IDT_GMR_BASE_ADR0		0x180020

/* IDT data and mask array base addresses (low 32 bits) */
#define MC5_IDT_DATARY_BASE_ADR0	0x00000000
#define MC5_IDT_MSKARY_BASE_ADR0	0x00080000

#define IDT_ELOOKUP_2Mb			0x7000
#define IDT_ELOOKUP_9Mb			0x16000

enum {
	LARA_7000,
	LARA_8000,
	NETLOGIC_4000,
	NETLOGIC_5000,
	IDT75P52100
};

static unsigned int tcam_part_size[] = {
	4718592, /* 4.5Mb */
	9437184, /* 9Mb */
	18874368 /* 18Mb */
};

struct pemc5 {
	adapter_t *adapter;
	unsigned int tcam_size;
	unsigned int part_size;
	unsigned char part_type;
	unsigned char parity_enabled;
	unsigned char issue_syn;
	unsigned char mode;
	struct pemc5_intr_counts intr_counts;
#ifdef SUPPORT_MODE72
	u32 lip[MC5_LIP_NUM_OF_ENTRIES];
	unsigned int lip_index;
#endif
};

#define MAX_WRITE_ATTEMPTS 5

/*
 * Issue a command to the TCAM and wait for its completion.  The address and
 * any data required by the command must have been setup by the caller.
 */
static int mc5_cmd_write(adapter_t *adapter, u32 cmd)
{
	t1_write_reg_4(adapter, A_MC5_DBGI_REQ_CMD, cmd);
	return t1_wait_op_done(adapter, A_MC5_DBGI_RSP_STATUS,
		F_DBGI_RSP_VALID, 1, MAX_WRITE_ATTEMPTS, 1);
}


unsigned int t1_mc5_get_tcam_size(struct pemc5 *mc5)
{
	return mc5->tcam_size;
}

static int set_tcam_rtbl_base(struct pemc5 *mc5, unsigned int rtbl_base)
{
	if (rtbl_base >= t1_mc5_get_tcam_size(mc5)) return -1;
	t1_write_reg_4(mc5->adapter, A_MC5_ROUTING_TABLE_INDEX, rtbl_base);
	return 0;
}

unsigned int t1_mc5_get_tcam_rtbl_base(struct pemc5 *mc5)
{
	return t1_read_reg_4(mc5->adapter, A_MC5_ROUTING_TABLE_INDEX);
}

unsigned int t1_mc5_get_tcam_rtbl_size(struct pemc5 *mc5)
{
	unsigned int tcam_size = t1_mc5_get_tcam_size(mc5);
	unsigned int tcam_rtable_base = t1_mc5_get_tcam_rtbl_base(mc5);

	return tcam_size - tcam_rtable_base;
}

static int set_tcam_server_base(struct pemc5 *mc5, unsigned int server_base)
{
	if (server_base >= t1_mc5_get_tcam_size(mc5)) return -1;
	t1_write_reg_4(mc5->adapter, A_MC5_SERVER_INDEX, server_base);
	return 0;
}

unsigned int t1_mc5_get_tcam_server_base(struct pemc5 *mc5)
{
	return t1_read_reg_4(mc5->adapter, A_MC5_SERVER_INDEX);
}

unsigned int t1_mc5_get_tcam_server_size(struct pemc5 *mc5)
{
	unsigned int tcam_rtable_base = t1_mc5_get_tcam_rtbl_base(mc5);
	unsigned int tcam_server_base = t1_mc5_get_tcam_server_base(mc5);

	return tcam_rtable_base - tcam_server_base;
}

static inline void dbgi_wr_addr3(adapter_t *adapter, u32 v1, u32 v2, u32 v3)
{
	t1_write_reg_4(adapter, A_MC5_DBGI_REQ_ADDR0, v1);
	t1_write_reg_4(adapter, A_MC5_DBGI_REQ_ADDR1, v2);
	t1_write_reg_4(adapter, A_MC5_DBGI_REQ_ADDR2, v3);
}

static inline void dbgi_wr_data3(adapter_t *adapter, u32 v1, u32 v2, u32 v3)
{
	t1_write_reg_4(adapter, A_MC5_DBGI_REQ_DATA0, v1);
	t1_write_reg_4(adapter, A_MC5_DBGI_REQ_DATA1, v2);
	t1_write_reg_4(adapter, A_MC5_DBGI_REQ_DATA2, v3);
}

static inline void dbgi_rd_rsp3(adapter_t *adapter, u32 *v1, u32 *v2, u32 *v3)
{
	*v1 = t1_read_reg_4(adapter, A_MC5_DBGI_RSP_DATA0);
	*v2 = t1_read_reg_4(adapter, A_MC5_DBGI_RSP_DATA1);
	*v3 = t1_read_reg_4(adapter, A_MC5_DBGI_RSP_DATA2);
}

/*
 * Write data to the TCAM register at address (0, 0, addr_lo) using the TCAM
 * command cmd.  The data to be written must have been set up by the caller.
 * Returns -1 on failure, 0 on success.
 */
static int mc5_write(adapter_t *adapter, u32 addr_lo, u32 cmd)
{
	t1_write_reg_4(adapter, A_MC5_DBGI_REQ_ADDR0, addr_lo);
	if (mc5_cmd_write(adapter, cmd) == 0)
		return 0;
	CH_ERR("%s: MC5 timeout writing to TCAM address 0x%x\n",
	       adapter_name(adapter), addr_lo);
	return -1;
}

static int init_mask_data_array(struct pemc5 *mc5, u32 mask_array_base,
				u32 data_array_base, u32 write_cmd)
{
	unsigned int i;
	adapter_t *adap = mc5->adapter;

	/*
	 * We need the size of the TCAM data and mask arrays in terms of
	 * 72-bit entries.
	 */
	unsigned int size72 = tcam_part_size[mc5->part_size] / 72;
	unsigned int server_base = t1_mc5_get_tcam_server_base(mc5);
	if (mc5->mode == MC5_MODE_144_BIT)
		server_base *= 2;  /* 1 144-bit entry is 2 72-bit entries */

	/* Clear the data array */
	dbgi_wr_data3(adap, 0, 0, 0);
	for (i = 0; i < size72; i++)
		if (mc5_write(adap, data_array_base + i, write_cmd))
			return -1;

	/* Initialize the mask array. */
	dbgi_wr_data3(adap, 0xffffffff, 0xffffffff, 0xff);
	for (i = 0; i < size72; i++) {
		if (i == server_base)   /* entering server or routing region */
			t1_write_reg_4(adap, A_MC5_DBGI_REQ_DATA0,
				       mc5->mode == MC5_MODE_144_BIT ?
				       0xfffffff9 : 0xfffffffd);
		if (mc5_write(adap, mask_array_base + i, write_cmd))
			return -1;
	}
	return 0;
}

static int init_lara7000(struct pemc5 *mc5)
{
	int i;
	adapter_t *adap = mc5->adapter;

	t1_write_reg_4(adap, A_MC5_RSP_LATENCY,
		       t1_is_asic(adap) ? 0x0a0a0a0a : 0x09090909);

	if (mc5->parity_enabled) {
		t1_write_reg_4(adap, A_MC5_AOPEN_SRCH_CMD, 0x20022);
		t1_write_reg_4(adap, A_MC5_SYN_SRCH_CMD, 0x20022);
		t1_write_reg_4(adap, A_MC5_ACK_SRCH_CMD, 0x20022);
	}

	/* Set DBGI command mode for Lara TCAM. */
	t1_write_reg_4(adap, A_MC5_DBGI_CONFIG, DBGI_MODE_LARA_7000);

	dbgi_wr_data3(adap, mc5->mode == MC5_MODE_144_BIT ?
		      MC5_LRA_CMDREG_144KEY_DATA0 : MC5_LRA_CMDREG_72KEY_DATA0,
		      0, 0);
	if (mc5_write(adap, MC5_LRA_CMDREG_ADR0, MC5_LRA_CMD_WRITE))
		goto err;

	dbgi_wr_data3(adap, mc5->mode == MC5_MODE_144_BIT ?
		      MC5_LRA_CFGREG_144KEY_DATA0 : MC5_LRA_CFGREG_72KEY_DATA0,
		      0, 0);
	if (mc5_write(adap, MC5_LRA_CFGREG_ADR0, MC5_LRA_CMD_WRITE))
		goto err;

	/* Global Mask Registers (GMR) 0-15 */
	for (i = 0; i < 16; i++) {
		if (i == 8 || i == 9)
			dbgi_wr_data3(adap, mc5->mode == MC5_MODE_72_BIT ?
				      0xfffffffd : 0xfffffff9, 0xffffffff,
				      0xff);
		else
			dbgi_wr_data3(adap, 0xffffffff, 0xffffffff, 0xff);

		if (mc5_write(adap, MC5_LRA_GMRREG_BASE_ADR0_1 + i,
			      MC5_LRA_CMD_WRITE))
			goto err;
	}

	/* Global Mask Registers (GMR) 16-31 */
	for (i = 0; i < 16; i++) {
		if (i <= 1 && mc5->mode == MC5_MODE_72_BIT)
			dbgi_wr_data3(adap, 0xfffffffd, 0xffffc003, 0xff);
		else if (i == 0)
			dbgi_wr_data3(adap, 0xfffffff9, 0xffffffff, 0xff);
		else if (i == 1)
			dbgi_wr_data3(adap, 0xfffffff9, 0xffff8007, 0xff);
		else
			dbgi_wr_data3(adap, 0xffffffff, 0xffffffff, 0xff);

		if (mc5_write(adap, MC5_LRA_GMRREG_BASE_ADR0_2 + i,
			      MC5_LRA_CMD_WRITE))
			goto err;
	}
	return init_mask_data_array(mc5, MC5_LRA_MSKARY_BASE_ADR0,
				    MC5_LRA_DATARY_BASE_ADR0,
				    MC5_LRA_CMD_WRITE);
 err:
	return -EIO;
}

static int init_idt52100(struct pemc5 *mc5)
{
	int i;
	adapter_t *adap = mc5->adapter;

	t1_write_reg_4(adap, A_MC5_RSP_LATENCY, 0x151515);
	t1_write_reg_4(adap, A_MC5_PART_ID_INDEX, 2);

	/*
	 * Use GMRs 8-9 for ACK and AOPEN searches, GMRs 12-13 for SYN search,
	 * and GMRs 14-15 for ELOOKUP.
	 */
	t1_write_reg_4(adap, A_MC5_POPEN_DATA_WR_CMD, MC5_IDT_CMD_WRITE);
	t1_write_reg_4(adap, A_MC5_POPEN_MASK_WR_CMD, MC5_IDT_CMD_WRITE);
	t1_write_reg_4(adap, A_MC5_AOPEN_SRCH_CMD, MC5_IDT_CMD_SEARCH);
	t1_write_reg_4(adap, A_MC5_AOPEN_LRN_CMD, MC5_IDT_CMD_LEARN);
	t1_write_reg_4(adap, A_MC5_SYN_SRCH_CMD, MC5_IDT_CMD_SEARCH | 0x6000);
	t1_write_reg_4(adap, A_MC5_SYN_LRN_CMD, MC5_IDT_CMD_LEARN);
	t1_write_reg_4(adap, A_MC5_ACK_SRCH_CMD, MC5_IDT_CMD_SEARCH);
	t1_write_reg_4(adap, A_MC5_ACK_LRN_CMD, MC5_IDT_CMD_LEARN);
	t1_write_reg_4(adap, A_MC5_ILOOKUP_CMD, MC5_IDT_CMD_SEARCH);
	t1_write_reg_4(adap, A_MC5_ELOOKUP_CMD, MC5_IDT_CMD_SEARCH | 0x7000);
	t1_write_reg_4(adap, A_MC5_DATA_WRITE_CMD, MC5_IDT_CMD_WRITE);
	t1_write_reg_4(adap, A_MC5_DATA_READ_CMD, MC5_IDT_CMD_READ);

	/* Set DBGI command mode for IDT TCAM. */
	t1_write_reg_4(adap, A_MC5_DBGI_CONFIG, DBGI_MODE_IDT_52100);

	/* Set up LAR */
	dbgi_wr_data3(adap, MC5_IDT_LAR_MODE144, 0, 0);
	if (mc5_write(adap, MC5_IDT_LAR_ADR0, MC5_IDT_CMD_WRITE))
		goto err;

	/* Set up SSRs */
	dbgi_wr_data3(adap, 0xffffffff, 0xffffffff, 0);
	if (mc5_write(adap, MC5_IDT_SSR0_ADR0, MC5_IDT_CMD_WRITE) ||
	    mc5_write(adap, MC5_IDT_SSR1_ADR0, MC5_IDT_CMD_WRITE))
		goto err;

	/* Set up GMRs */
	for (i = 0; i < 32; ++i) {
		if (i >= 12 && i < 15)
			dbgi_wr_data3(adap, 0xfffffff9, 0xffffffff, 0xff);
		else if (i == 15)
			dbgi_wr_data3(adap, 0xfffffff9, 0xffff8007, 0xff);
		else
			dbgi_wr_data3(adap, 0xffffffff, 0xffffffff, 0xff);

		if (mc5_write(adap, MC5_IDT_GMR_BASE_ADR0 + i,
			      MC5_IDT_CMD_WRITE))
			goto err;
	}

	/* Set up SCR */
	dbgi_wr_data3(adap, 1, 0, 0);
	if (mc5_write(adap, MC5_IDT_SCR_ADR0, MC5_IDT_CMD_WRITE))
		goto err;

	return init_mask_data_array(mc5, MC5_IDT_MSKARY_BASE_ADR0,
				    MC5_IDT_DATARY_BASE_ADR0,
				    MC5_IDT_CMD_WRITE);
 err:
	return -EIO;
}

/* Put MC5 in DBGI mode. */
static inline void mc5_dbgi_mode_enable(struct pemc5 *mc5)
{
	t1_write_reg_4(mc5->adapter, A_MC5_CONFIG,
		       V_MODE(mc5->mode == MC5_MODE_72_BIT) |
		       F_DBGI_ENABLE | V_NUM_LIP(MC5_LIP_NUM_OF_ENTRIES - 1));
}

/* Put MC5 in M-Bus mode. */
static void mc5_dbgi_mode_disable(struct pemc5 *mc5)
{
	t1_write_reg_4(mc5->adapter, A_MC5_CONFIG,
		       V_MODE(mc5->mode == MC5_MODE_72_BIT) |
		       V_COMPRESSION_ENABLE(mc5->mode == MC5_MODE_72_BIT) |
		       V_PARITY_ENABLE(mc5->parity_enabled) |
		       V_SYN_ISSUE_MODE(mc5->issue_syn) | F_M_BUS_ENABLE |
		       V_NUM_LIP(MC5_LIP_NUM_OF_ENTRIES - 1));
}

/*
 * Initialization that requires the OS and protocol layers to already
 * be intialized goes here.
 */
int t1_mc5_init(struct pemc5 *mc5, unsigned int nservers,
		unsigned int nroutes, int parity, int syn)
{
	u32 cfg;
	int err = 0;
	unsigned int tcam_size = t1_mc5_get_tcam_size(mc5);
	adapter_t *adap = mc5->adapter;

	/* Reset the TCAM */
	cfg = t1_read_reg_4(adap, A_MC5_CONFIG) & ~F_MODE;
	cfg |= V_MODE(mc5->mode == MC5_MODE_72_BIT) | F_TCAM_RESET;
	t1_write_reg_4(adap, A_MC5_CONFIG, cfg);
	if (t1_wait_op_done(adap, A_MC5_CONFIG, F_TCAM_READY, 1, 500, 0)) {
		CH_ERR("%s: TCAM reset timed out\n", adapter_name(adap));
		return -1;
	}

	if (set_tcam_rtbl_base(mc5, tcam_size - nroutes) ||
	    set_tcam_server_base(mc5, tcam_size - nroutes - nservers))
		return -EINVAL;

#ifdef SUPPORT_MODE72
	if (mc5->mode == MC5_MODE_72_BIT)
		t1_mc5_lip_write_entries(mc5);
#endif
	mc5->issue_syn = (unsigned char)syn;
	mc5->parity_enabled = (unsigned char)parity;

	/* All the TCAM addresses we access have only the low 32 bits non 0 */
	t1_write_reg_4(adap, A_MC5_DBGI_REQ_ADDR1, 0);
	t1_write_reg_4(adap, A_MC5_DBGI_REQ_ADDR2, 0);

	mc5_dbgi_mode_enable(mc5);

	switch (mc5->part_type) {
	case LARA_7000:
		err = init_lara7000(mc5);
		break;
	case IDT75P52100:
		err = init_idt52100(mc5);
		break;
	default:
		CH_ERR("%s: unsupported TCAM type\n", adapter_name(adap));
		err = -EINVAL;
		break;
	}

	mc5_dbgi_mode_disable(mc5);
	return err;
}

/*
 *	read_mc5_range - dump a part of the memory managed by MC5
 *	@mc5: the MC5 handle
 *	@start: the start address for the dump
 *	@n: number of 72-bit words to read
 *	@buf: result buffer
 *
 *	Read n 72-bit words from MC5 memory from the given start location.
 */
int t1_read_mc5_range(struct pemc5 *mc5, unsigned int start,
		      unsigned int n, u32 *buf)
{
	u32 read_cmd;
	/* int err = 0; */
	adapter_t *adap = mc5->adapter;

	if (mc5->part_type == LARA_7000)
		read_cmd = MC5_LRA_CMD_READ;
	else if (mc5->part_type == IDT75P52100)
		read_cmd = MC5_IDT_CMD_READ;
	else
		return -EINVAL;

	mc5_dbgi_mode_enable(mc5);

	while (n--) {
		t1_write_reg_4(adap, A_MC5_DBGI_REQ_ADDR0, start++);
		if (mc5_cmd_write(adap, read_cmd)) {
			/* err = -EIO; */
			break;
		}
		dbgi_rd_rsp3(adap, buf + 2, buf + 1, buf);
		buf += 3;
	}

	mc5_dbgi_mode_disable(mc5);
	return 0;
}

#define MC5_INT_MASK (F_MC5_INT_HIT_OUT_ACTIVE_REGION_ERR | \
	F_MC5_INT_HIT_IN_RT_REGION_ERR | F_MC5_INT_LIP0_ERR | \
	F_MC5_INT_LIP_MISS_ERR | F_MC5_INT_PARITY_ERR | \
	F_MC5_INT_ACTIVE_REGION_FULL | F_MC5_INT_NFA_SRCH_ERR | \
	F_MC5_INT_UNKNOWN_CMD | F_MC5_INT_DEL_ACT_EMPTY)
#define MC5_INT_FATAL (F_MC5_INT_PARITY_ERR | F_MC5_INT_REQUESTQ_PARITY_ERR | \
	F_MC5_INT_DISPATCHQ_PARITY_ERR)

void t1_mc5_intr_enable(struct pemc5 *mc5)
{
	u32 mask = MC5_INT_MASK;

	if (!mc5->parity_enabled)
		mask &= ~F_MC5_INT_PARITY_ERR;

#ifdef CONFIG_CHELSIO_T1_1G
	if (!t1_is_asic(mc5->adapter)) {
		/*
		 * Enable child block for MC5.
		 *
		 * NOTE: Assumes TP parent interrupt block is enabled. 
		 *       MC5 requires TP parent block to be enabled.
		 */
		t1_write_reg_4(mc5->adapter, A_MC5_INT_ENABLE, mask);
	} else
#endif
	{
		u32 pl_intr = t1_read_reg_4(mc5->adapter, A_PL_ENABLE);

		t1_write_reg_4(mc5->adapter, A_PL_ENABLE,
			       pl_intr | F_PL_INTR_MC5);
		t1_write_reg_4(mc5->adapter, A_MC5_INT_ENABLE,
			       mask | F_MC5_INT_REQUESTQ_PARITY_ERR |
			       F_MC5_INT_DISPATCHQ_PARITY_ERR);
	}
}

void t1_mc5_intr_disable(struct pemc5 *mc5)
{
#ifdef CONFIG_CHELSIO_T1_1G
	if (!t1_is_asic(mc5->adapter))
		t1_write_reg_4(mc5->adapter, A_MC5_INT_ENABLE, 0);
	else
#endif
	{
		u32 pl_intr = t1_read_reg_4(mc5->adapter, A_PL_ENABLE);

		t1_write_reg_4(mc5->adapter, A_PL_ENABLE,
			       pl_intr & ~F_PL_INTR_MC5);
		t1_write_reg_4(mc5->adapter, A_MC5_INT_ENABLE, 0);
	}
}

void t1_mc5_intr_clear(struct pemc5 *mc5)
{
#ifdef CONFIG_CHELSIO_T1_1G
	if (!t1_is_asic(mc5->adapter)) {
		t1_write_reg_4(mc5->adapter, A_MC5_INT_CAUSE, 0xffffffff);
	} else 
#endif
	{
		t1_write_reg_4(mc5->adapter, A_PL_CAUSE, F_PL_INTR_MC5);
		t1_write_reg_4(mc5->adapter, A_MC5_INT_CAUSE, 0xffffffff);
	}
}

/*
 * We don't really do anything with MC5 interrupts, just record them.
 */
void t1_mc5_intr_handler(struct pemc5 *mc5)
{
	adapter_t *adap = mc5->adapter;
	u32 cause = t1_read_reg_4(adap, A_MC5_INT_CAUSE);

	if (cause & F_MC5_INT_HIT_OUT_ACTIVE_REGION_ERR)
		mc5->intr_counts.hit_out_active_region_err++;

	if (cause & F_MC5_INT_HIT_IN_ACTIVE_REGION_ERR)
		mc5->intr_counts.hit_in_active_region_err++;

	if (cause & F_MC5_INT_HIT_IN_RT_REGION_ERR)
		mc5->intr_counts.hit_in_routing_region_err++;

	if (cause & F_MC5_INT_MISS_ERR)
		mc5->intr_counts.miss_err++;

	if (cause & F_MC5_INT_LIP0_ERR)
		mc5->intr_counts.lip_equal_zero_err++;

	if (cause & F_MC5_INT_LIP_MISS_ERR)
		mc5->intr_counts.lip_miss_err++;

	if ((cause & F_MC5_INT_PARITY_ERR) && mc5->parity_enabled) {
		CH_ALERT("%s: MC5 parity error\n", adapter_name(adap));
		mc5->intr_counts.parity_err++;
	}

	if (cause & F_MC5_INT_ACTIVE_REGION_FULL)
		mc5->intr_counts.active_region_full_err++;

	if (cause & F_MC5_INT_NFA_SRCH_ERR)
		mc5->intr_counts.next_free_addr_srch_err++;

	if (cause & F_MC5_INT_SYN_COOKIE)
		mc5->intr_counts.syn_cookie++;

	if (cause & F_MC5_INT_SYN_COOKIE_BAD)
		mc5->intr_counts.syn_cookie_bad_message++;

	if (cause & F_MC5_INT_SYN_COOKIE_OFF)
		mc5->intr_counts.syn_cookie_off_message++;

	if (cause & F_MC5_INT_UNKNOWN_CMD)
		mc5->intr_counts.receive_unknown_cmd++;

	if (cause & F_MC5_INT_REQUESTQ_PARITY_ERR) {
		CH_ALERT("%s: MC5 request queue parity error\n",
			 adapter_name(adap));
		mc5->intr_counts.parity_in_request_q_err++;
	}

	if (cause & F_MC5_INT_DISPATCHQ_PARITY_ERR) {
		CH_ALERT("%s: MC5 dispatch queue parity error\n",
			 adapter_name(adap));
		mc5->intr_counts.parity_in_dispatch_q_err++;
	}

	if (cause & F_MC5_INT_DEL_ACT_EMPTY)
		mc5->intr_counts.del_and_act_is_empty++;

	if (cause & MC5_INT_FATAL)
		t1_fatal_err(adap);

	t1_write_reg_4(adap, A_MC5_INT_CAUSE, cause);
}

const struct pemc5_intr_counts *t1_mc5_get_intr_counts(struct pemc5 *mc5)
{
	return &mc5->intr_counts;
}

struct pemc5 * __devinit t1_mc5_create(adapter_t *adapter, int mode)
{
	struct pemc5 *mc5;
	u32 cfg, bits_per_entry;

	if (mode != MC5_MODE_144_BIT && mode != MC5_MODE_72_BIT)
		return NULL;

	mc5 = t1_os_malloc_wait_zero(sizeof(*mc5));
	if (!mc5) return NULL;

	mc5->adapter = adapter;
	mc5->mode = (unsigned char) mode;

	cfg = t1_read_reg_4(adapter, A_MC5_CONFIG);
	mc5->part_size = G_TCAM_PART_SIZE(cfg);
	mc5->part_type = (unsigned char) G_TCAM_PART_TYPE(cfg);
	if (cfg & F_TCAM_PART_TYPE_HI)
		mc5->part_type |= 4;

	/*
	 * Calculate the size of the TCAM based on the total memory, mode, and
	 * count information retrieved from the hardware.
	 */
	bits_per_entry = mode == MC5_MODE_144_BIT ? 144 : 72;
	mc5->tcam_size = tcam_part_size[mc5->part_size] / bits_per_entry;

	return mc5;
}

void t1_mc5_destroy(struct pemc5 *mc5)
{
	t1_os_free((void *)mc5, sizeof(*mc5));
}

#ifdef SUPPORT_MODE72
static int mc5_cmp(const void *pi, const void *pj)
{
	const u32 *pii = (const u32 *)pi;
	const u32 *pjj = (const u32 *)pj;

	if (*pii < *pjj)
		return -1;

	return *pii > *pjj;
}

/*
 * DESC: Write local IP addresses to the TCAM
 *
 * NOTES: IP addresses should be in host byte order. So, an IP address:
 *        of 10.0.0.140 == (data = 0x0A00008C)
 */
static int mc5_set_lip_entries(struct pemc5 *mc5, u32 *p,
			       int num_of_lip_addresses)
{
	int i;

	/*
	 * Disable compression and M bus mode so that the TP core
	 * doesn't access the TCAM  while we are writing. 
	 */
	u32 cfg = t1_read_reg_4(mc5->adapter, A_MC5_CONFIG);
	t1_write_reg_4(mc5->adapter, A_MC5_CONFIG,
		       cfg & ~(F_M_BUS_ENABLE | F_COMPRESSION_ENABLE));

	/* MC5 should now be ready to program the LIP addresses. */
	for (i = 0; i < num_of_lip_addresses; i++) {
		t1_write_reg_4(mc5->adapter, A_MC5_LIP_RAM_DATA, p[i]);
		t1_write_reg_4(mc5->adapter, A_MC5_LIP_RAM_ADDR, 0x100 + i);
	}

	/* Restore MC5 mode. */
	t1_write_reg_4(mc5->adapter, A_MC5_CONFIG, cfg | F_COMPRESSION_ENABLE);
	return 0;
}

/*
 * The purpose of this routine is to write all of the local IP addresses
 * into the TCAM in sorted order. This is a requirement from the TCAM.
 */
void t1_mc5_lip_write_entries(struct pemc5 *mc5)
{
	u32 filler = 0;
	int i;

	if (mc5->lip_index) {
		qsort(mc5->lip, mc5->lip_index, sizeof(u32), mc5_cmp);
		filler = mc5->lip[mc5->lip_index - 1];
	}
	for (i = mc5->lip_index; i < MC5_LIP_NUM_OF_ENTRIES; i++)
		mc5->lip[i] = filler;
	mc5_set_lip_entries(mc5, mc5->lip, MC5_LIP_NUM_OF_ENTRIES);
}

void t1_mc5_lip_clear_entries(struct pemc5 *mc5)
{
	mc5->lip_index = 0;
}

/*
 * Add a local IP address to the LIP table.
 */
int t1_mc5_lip_add_entry(struct pemc5 *mc5, u32 lip)
{
	if (mc5->lip_index >= MC5_LIP_NUM_OF_ENTRIES) return 1;
	mc5->lip[mc5->lip_index++] = lip;
	return 0;
}
#endif
