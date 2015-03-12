#ifndef ECORE_INIT_H
#define ECORE_INIT_H

#include "init_defs.h"
#include "aeu_inputs.h"

#if defined(_B10KD_EXT)
#include "b10ext_redefs.h"
#include "b10ext.h"
#endif

/* Returns the index of start or end of a specific block stage in ops array*/
#define BLOCK_OPS_IDX(block, stage, end) \
			(2*(((block)*NUM_OF_INIT_PHASES) + (stage)) + (end))


#define INITOP_SET		0	/* set the HW directly */
#define INITOP_CLEAR		1	/* clear the HW directly */
#define INITOP_INIT		2	/* set the init-value array */

/****************************************************************************
* ILT management
****************************************************************************/
struct ilt_line {
	lm_address_t page_mapping;
	void *page;
	u32 size;
};

struct ilt_client_info {
	u32 page_size;
	u16 start;
	u16 end;
	u16 client_num;
	u16 flags;
#define ILT_CLIENT_SKIP_INIT	0x1
#define ILT_CLIENT_SKIP_MEM	0x2
};

struct ecore_ilt {
	u32 start_line;
	struct ilt_line		*lines;
	struct ilt_client_info	clients[4];
#define ILT_CLIENT_CDU	0
#define ILT_CLIENT_QM	1
#define ILT_CLIENT_SRC	2
#define ILT_CLIENT_TM	3
};

/****************************************************************************
* SRC configuration
****************************************************************************/
struct src_ent {
	u8 opaque[56];
	u64 next;
};

/****************************************************************************
* Parity configuration
****************************************************************************/
#define BLOCK_PRTY_INFO(block, en_mask, m1, m1h, m2, m3) \
{ \
	block##_REG_##block##_PRTY_MASK, \
	block##_REG_##block##_PRTY_STS_CLR, \
	en_mask, {m1, m1h, m2, m3}, #block \
}

#define BLOCK_PRTY_INFO_0(block, en_mask, m1, m1h, m2, m3) \
{ \
	block##_REG_##block##_PRTY_MASK_0, \
	block##_REG_##block##_PRTY_STS_CLR_0, \
	en_mask, {m1, m1h, m2, m3}, #block"_0" \
}

#define BLOCK_PRTY_INFO_1(block, en_mask, m1, m1h, m2, m3) \
{ \
	block##_REG_##block##_PRTY_MASK_1, \
	block##_REG_##block##_PRTY_STS_CLR_1, \
	en_mask, {m1, m1h, m2, m3}, #block"_1" \
}

static const struct {
	u32 mask_addr;
	u32 sts_clr_addr;
	u32 en_mask;		/* Mask to enable parity attentions */
	struct {
		u32 e1;		/* 57710 */
		u32 e1h;	/* 57711 */
		u32 e2;		/* 57712 */
		u32 e3;		/* 578xx */
	} reg_mask;		/* Register mask (all valid bits) */
	char name[8];		/* Block's longest name is 7 characters long
				 * (name + suffix)
				 */
} ecore_blocks_parity_data[] = {
	/* bit 19 masked */
	/* REG_WR(bp, PXP_REG_PXP_PRTY_MASK, 0x80000); */
	/* bit 5,18,20-31 */
	/* REG_WR(bp, PXP2_REG_PXP2_PRTY_MASK_0, 0xfff40020); */
	/* bit 5 */
	/* REG_WR(bp, PXP2_REG_PXP2_PRTY_MASK_1, 0x20);	*/
	/* REG_WR(bp, HC_REG_HC_PRTY_MASK, 0x0); */
	/* REG_WR(bp, MISC_REG_MISC_PRTY_MASK, 0x0); */

	/* Block IGU, MISC, PXP and PXP2 parity errors as long as we don't
	 * want to handle "system kill" flow at the moment.
	 */
	BLOCK_PRTY_INFO(PXP, 0x7ffffff, 0x3ffffff, 0x3ffffff, 0x7ffffff,
			0x7ffffff),
	BLOCK_PRTY_INFO_0(PXP2,	0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
			  0xffffffff),
	BLOCK_PRTY_INFO_1(PXP2,	0x1ffffff, 0x7f, 0x7f, 0x7ff, 0x1ffffff),
	BLOCK_PRTY_INFO(HC, 0x7, 0x7, 0x7, 0, 0),
	BLOCK_PRTY_INFO(NIG, 0xffffffff, 0x3fffffff, 0xffffffff, 0, 0),
	BLOCK_PRTY_INFO_0(NIG,	0xffffffff, 0, 0, 0xffffffff, 0xffffffff),
	BLOCK_PRTY_INFO_1(NIG,	0xffff, 0, 0, 0xff, 0xffff),
	BLOCK_PRTY_INFO(IGU, 0x7ff, 0, 0, 0x7ff, 0x7ff),
	BLOCK_PRTY_INFO(MISC, 0x1, 0x1, 0x1, 0x1, 0x1),
	BLOCK_PRTY_INFO(QM, 0, 0x1ff, 0xfff, 0xfff, 0xfff),
	BLOCK_PRTY_INFO(ATC, 0x1f, 0, 0, 0x1f, 0x1f),
	BLOCK_PRTY_INFO(PGLUE_B, 0x3, 0, 0, 0x3, 0x3),
	BLOCK_PRTY_INFO(DORQ, 0, 0x3, 0x3, 0x3, 0x3),
	{GRCBASE_UPB + PB_REG_PB_PRTY_MASK,
		GRCBASE_UPB + PB_REG_PB_PRTY_STS_CLR, 0xf,
		{0xf, 0xf, 0xf, 0xf}, "UPB"},
	{GRCBASE_XPB + PB_REG_PB_PRTY_MASK,
		GRCBASE_XPB + PB_REG_PB_PRTY_STS_CLR, 0,
		{0xf, 0xf, 0xf, 0xf}, "XPB"},
	BLOCK_PRTY_INFO(SRC, 0x4, 0x7, 0x7, 0x7, 0x7),
	BLOCK_PRTY_INFO(CDU, 0, 0x1f, 0x1f, 0x1f, 0x1f),
	BLOCK_PRTY_INFO(CFC, 0, 0xf, 0xf, 0xf, 0x3f),
	BLOCK_PRTY_INFO(DBG, 0, 0x1, 0x1, 0x1, 0x1),
	BLOCK_PRTY_INFO(DMAE, 0, 0xf, 0xf, 0xf, 0xf),
	BLOCK_PRTY_INFO(BRB1, 0, 0xf, 0xf, 0xf, 0xf),
	BLOCK_PRTY_INFO(PRS, (1<<6), 0xff, 0xff, 0xff, 0xff),
	BLOCK_PRTY_INFO(PBF, 0, 0, 0x3ffff, 0xfffff, 0xfffffff),
	BLOCK_PRTY_INFO(TM, 0, 0, 0x7f, 0x7f, 0x7f),
	BLOCK_PRTY_INFO(TSDM, 0x18, 0x7ff, 0x7ff, 0x7ff, 0x7ff),
	BLOCK_PRTY_INFO(CSDM, 0x8, 0x7ff, 0x7ff, 0x7ff, 0x7ff),
	BLOCK_PRTY_INFO(USDM, 0x38, 0x7ff, 0x7ff, 0x7ff, 0x7ff),
	BLOCK_PRTY_INFO(XSDM, 0x8, 0x7ff, 0x7ff, 0x7ff, 0x7ff),
	BLOCK_PRTY_INFO(TCM, 0, 0, 0x7ffffff, 0x7ffffff, 0x7ffffff),
	BLOCK_PRTY_INFO(CCM, 0, 0, 0x7ffffff, 0x7ffffff, 0x7ffffff),
	BLOCK_PRTY_INFO(UCM, 0, 0, 0x7ffffff, 0x7ffffff, 0x7ffffff),
	BLOCK_PRTY_INFO(XCM, 0, 0, 0x3fffffff, 0x3fffffff, 0x3fffffff),
	BLOCK_PRTY_INFO_0(TSEM, 0, 0xffffffff, 0xffffffff, 0xffffffff,
			  0xffffffff),
	BLOCK_PRTY_INFO_1(TSEM, 0, 0x3, 0x1f, 0x3f, 0x3f),
	BLOCK_PRTY_INFO_0(USEM, 0, 0xffffffff, 0xffffffff, 0xffffffff,
			  0xffffffff),
	BLOCK_PRTY_INFO_1(USEM, 0, 0x3, 0x1f, 0x1f, 0x1f),
	BLOCK_PRTY_INFO_0(CSEM, 0, 0xffffffff, 0xffffffff, 0xffffffff,
			  0xffffffff),
	BLOCK_PRTY_INFO_1(CSEM, 0, 0x3, 0x1f, 0x1f, 0x1f),
	BLOCK_PRTY_INFO_0(XSEM, 0, 0xffffffff, 0xffffffff, 0xffffffff,
			  0xffffffff),
	BLOCK_PRTY_INFO_1(XSEM, 0, 0x3, 0x1f, 0x3f, 0x3f),
};


/* [28] MCP Latched rom_parity
 * [29] MCP Latched ump_rx_parity
 * [30] MCP Latched ump_tx_parity
 * [31] MCP Latched scpad_parity
 */
#define MISC_AEU_ENABLE_MCP_PRTY_SUB_BITS	\
	(AEU_INPUTS_ATTN_BITS_MCP_LATCHED_ROM_PARITY | \
	 AEU_INPUTS_ATTN_BITS_MCP_LATCHED_UMP_RX_PARITY | \
	 AEU_INPUTS_ATTN_BITS_MCP_LATCHED_UMP_TX_PARITY)

#define MISC_AEU_ENABLE_MCP_PRTY_BITS	\
	(MISC_AEU_ENABLE_MCP_PRTY_SUB_BITS | \
	 AEU_INPUTS_ATTN_BITS_MCP_LATCHED_SCPAD_PARITY)

/* Below registers control the MCP parity attention output. When
 * MISC_AEU_ENABLE_MCP_PRTY_BITS are set - attentions are
 * enabled, when cleared - disabled.
 */
static const struct {
	u32 addr;
	u32 bits;
} mcp_attn_ctl_regs[] = {
	{ MISC_REG_AEU_ENABLE4_FUNC_0_OUT_0,
		MISC_AEU_ENABLE_MCP_PRTY_BITS },
	{ MISC_REG_AEU_ENABLE4_NIG_0,
		MISC_AEU_ENABLE_MCP_PRTY_SUB_BITS },
	{ MISC_REG_AEU_ENABLE4_PXP_0,
		MISC_AEU_ENABLE_MCP_PRTY_SUB_BITS },
	{ MISC_REG_AEU_ENABLE4_FUNC_1_OUT_0,
		MISC_AEU_ENABLE_MCP_PRTY_BITS },
	{ MISC_REG_AEU_ENABLE4_NIG_1,
		MISC_AEU_ENABLE_MCP_PRTY_SUB_BITS },
	{ MISC_REG_AEU_ENABLE4_PXP_1,
		MISC_AEU_ENABLE_MCP_PRTY_SUB_BITS }
};

static __inline void ecore_set_mcp_parity(struct _lm_device_t *pdev, u8 enable)
{
	int i;
	u32 reg_val;

	for (i = 0; i < ARRSIZE(mcp_attn_ctl_regs); i++) {
		reg_val = REG_RD(pdev, mcp_attn_ctl_regs[i].addr);

		if (enable)
			reg_val |= MISC_AEU_ENABLE_MCP_PRTY_BITS; /* Linux is using mcp_attn_ctl_regs[i].bits */
		else
			reg_val &= ~MISC_AEU_ENABLE_MCP_PRTY_BITS; /* Linux is using mcp_attn_ctl_regs[i].bits */

		REG_WR(pdev, mcp_attn_ctl_regs[i].addr, reg_val);
	}
}

static __inline u32 ecore_parity_reg_mask(struct _lm_device_t *pdev, int idx)
{
	if (CHIP_IS_E1(pdev))
		return ecore_blocks_parity_data[idx].reg_mask.e1;
	else if (CHIP_IS_E1H(pdev))
		return ecore_blocks_parity_data[idx].reg_mask.e1h;
	else if (CHIP_IS_E2(pdev))
		return ecore_blocks_parity_data[idx].reg_mask.e2;
	else /* CHIP_IS_E3 */
		return ecore_blocks_parity_data[idx].reg_mask.e3;
}

static __inline void ecore_disable_blocks_parity(struct _lm_device_t *pdev)
{
	int i;

	for (i = 0; i < ARRSIZE(ecore_blocks_parity_data); i++) {
		u32 dis_mask = ecore_parity_reg_mask(pdev, i);

		if (dis_mask) {
			REG_WR(pdev, ecore_blocks_parity_data[i].mask_addr,
			       dis_mask);
			DbgMessage(pdev, WARNi, "Setting parity mask "
						 "for %s to\t\t0x%x\n",
				    ecore_blocks_parity_data[i].name, dis_mask);
		}
	}

	/* Disable MCP parity attentions */
	ecore_set_mcp_parity(pdev, FALSE);
}

/**
 * Clear the parity error status registers.
 */
static __inline void ecore_clear_blocks_parity(struct _lm_device_t *pdev)
{
	int i;
	u32 reg_val, mcp_aeu_bits =
		AEU_INPUTS_ATTN_BITS_MCP_LATCHED_ROM_PARITY |
		AEU_INPUTS_ATTN_BITS_MCP_LATCHED_SCPAD_PARITY |
		AEU_INPUTS_ATTN_BITS_MCP_LATCHED_UMP_RX_PARITY |
		AEU_INPUTS_ATTN_BITS_MCP_LATCHED_UMP_TX_PARITY;

	/* Clear SEM_FAST parities */
	REG_WR(pdev, XSEM_REG_FAST_MEMORY + SEM_FAST_REG_PARITY_RST, 0x1);
	REG_WR(pdev, TSEM_REG_FAST_MEMORY + SEM_FAST_REG_PARITY_RST, 0x1);
	REG_WR(pdev, USEM_REG_FAST_MEMORY + SEM_FAST_REG_PARITY_RST, 0x1);
	REG_WR(pdev, CSEM_REG_FAST_MEMORY + SEM_FAST_REG_PARITY_RST, 0x1);

	for (i = 0; i < ARRSIZE(ecore_blocks_parity_data); i++) {
		u32 reg_mask = ecore_parity_reg_mask(pdev, i);

		if (reg_mask) {
			reg_val = REG_RD(pdev, ecore_blocks_parity_data[i].
					 sts_clr_addr);
			if (reg_val & reg_mask) {
				DbgMessage(pdev, WARNi,
					   "Parity errors in %s: 0x%x\n",
					   ecore_blocks_parity_data[i].name,
					   reg_val & reg_mask);
			}
		}
	}

	/* Check if there were parity attentions in MCP */
	reg_val = REG_RD(pdev, MISC_REG_AEU_AFTER_INVERT_4_MCP);
	if (reg_val & mcp_aeu_bits) {
		DbgMessage(pdev, WARNi, "Parity error in MCP: 0x%x\n",
			   reg_val & mcp_aeu_bits);
	}

	/* Clear parity attentions in MCP:
	 * [7]  clears Latched rom_parity
	 * [8]  clears Latched ump_rx_parity
	 * [9]  clears Latched ump_tx_parity
	 * [10] clears Latched scpad_parity (both ports)
	 */
	REG_WR(pdev, MISC_REG_AEU_CLR_LATCH_SIGNAL, 0x780);
}

static __inline void ecore_enable_blocks_parity(struct _lm_device_t *pdev)
{
	int i;

	for (i = 0; i < ARRSIZE(ecore_blocks_parity_data); i++) {
		u32 reg_mask = ecore_parity_reg_mask(pdev, i);

		if (reg_mask)
			REG_WR(pdev, ecore_blocks_parity_data[i].mask_addr,
				ecore_blocks_parity_data[i].en_mask & reg_mask);
	}

	/* Enable MCP parity attentions */
	ecore_set_mcp_parity(pdev, TRUE);
}


#endif /* ECORE_INIT_H */

