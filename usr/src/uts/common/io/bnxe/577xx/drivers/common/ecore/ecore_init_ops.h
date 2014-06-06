#ifndef ECORE_INIT_OPS_H
#define ECORE_INIT_OPS_H


#ifndef PDEV_ILT
#define PDEV_ILT(bp)	NULL
#endif

#ifndef PDEV_FUNC
#define PDEV_FUNC(bp)	0
#endif

#ifndef PDEV_PORT
#define PDEV_PORT(bp)	0
#endif

#ifndef ECORE_ILT_FREE
#define ECORE_ILT_FREE(x, y, sz)
#endif

#ifndef ECORE_ILT_ZALLOC
#define ECORE_ILT_ZALLOC(x, y, sz)
#endif

#ifndef ILOG2
#define ILOG2(x)	x
#endif

#define FORCE32	(u32)

static int ecore_gunzip(struct _lm_device_t *pdev, const u8 *zbuf, int len);
static void ecore_reg_wr_ind(struct _lm_device_t *pdev, u32 addr, u32 val);
static void ecore_write_dmae_phys_len(struct _lm_device_t *pdev,
				      lm_address_t phys_addr, u32 addr,
				      u32 len);

static void ecore_init_str_wr(struct _lm_device_t *pdev, u32 addr,
			      const u32 *data, u32 len)
{
	u32 i;

	for (i = 0; i < len; i++)
		REG_WR(pdev, addr + i*4, data[i]);
}

static void ecore_init_ind_wr(struct _lm_device_t *pdev, u32 addr,
			      const u32 *data, u32 len)
{
	u32 i;

	for (i = 0; i < len; i++)
		ecore_reg_wr_ind(pdev, addr + i*4, data[i]);
}

static void ecore_write_big_buf(struct _lm_device_t *pdev, u32 addr, u32 len,
				u8 wb)
{
	if (DMAE_READY(pdev))
		ecore_write_dmae_phys_len(pdev, GUNZIP_PHYS(pdev), addr, len);

	/* in E1 chips BIOS initiated ZLR may interrupt widebus writes */
	else if (wb && CHIP_IS_E1(pdev))
		ecore_init_ind_wr(pdev, addr, GUNZIP_BUF(pdev), len);

	/* in later chips PXP root complex handles BIOS ZLR w/o interrupting */
	else
		ecore_init_str_wr(pdev, addr, GUNZIP_BUF(pdev), len);
}

static void ecore_init_fill(struct _lm_device_t *pdev, u32 addr, int fill,
			    u32 len, u8 wb)
{
	u32 buf_len = (((len*4) > FW_BUF_SIZE) ? FW_BUF_SIZE : (len*4));
	u32 buf_len32 = buf_len/4;
	u32 i;

	mm_memset(GUNZIP_BUF(pdev), (u8)fill, buf_len);

	for (i = 0; i < len; i += buf_len32) {
		u32 cur_len = min(buf_len32, len - i);

		ecore_write_big_buf(pdev, addr + i*4, cur_len, wb);
	}
}

static void ecore_write_big_buf_wb(struct _lm_device_t *pdev, u32 addr, u32 len)
{
	if (DMAE_READY(pdev))
		ecore_write_dmae_phys_len(pdev, GUNZIP_PHYS(pdev), addr, len);

	/* in E1 chips BIOS initiated ZLR may interrupt widebus writes */
	else if (CHIP_IS_E1(pdev))
		ecore_init_ind_wr(pdev, addr, GUNZIP_BUF(pdev), len);

	/* in later chips PXP root complex handles BIOS ZLR w/o interrupting */
	else
		ecore_init_str_wr(pdev, addr, GUNZIP_BUF(pdev), len);
}

static void ecore_init_wr_64(struct _lm_device_t *pdev, u32 addr,
			     const u32 *data, u32 len64)
{
	u32 buf_len32 = FW_BUF_SIZE/4;
	u32 len = len64*2;
	u64 data64 = 0;
	u32 i;

	/* 64 bit value is in a blob: first low DWORD, then high DWORD */
	data64 = HILO_U64((*(data + 1)), (*data));

	len64 = min((u32)(FW_BUF_SIZE/8), len64);
	for (i = 0; i < len64; i++) {
		u64 *pdata = ((u64 *)(GUNZIP_BUF(pdev))) + i;

		*pdata = data64;
	}

	for (i = 0; i < len; i += buf_len32) {
		u32 cur_len = min(buf_len32, len - i);

		ecore_write_big_buf_wb(pdev, addr + i*4, cur_len);
	}
}

/*********************************************************
   There are different blobs for each PRAM section.
   In addition, each blob write operation is divided into a few operations
   in order to decrease the amount of phys. contiguous buffer needed.
   Thus, when we select a blob the address may be with some offset
   from the beginning of PRAM section.
   The same holds for the INT_TABLE sections.
**********************************************************/
#define IF_IS_INT_TABLE_ADDR(base, addr) \
			if (((base) <= (addr)) && ((base) + 0x400 >= (addr)))

#define IF_IS_PRAM_ADDR(base, addr) \
			if (((base) <= (addr)) && ((base) + 0x40000 >= (addr)))

static const u8 *ecore_sel_blob(struct _lm_device_t *pdev, u32 addr,
				const u8 *data)
{
	IF_IS_INT_TABLE_ADDR(TSEM_REG_INT_TABLE, addr)
		data = INIT_TSEM_INT_TABLE_DATA(pdev);
	else
		IF_IS_INT_TABLE_ADDR(CSEM_REG_INT_TABLE, addr)
			data = INIT_CSEM_INT_TABLE_DATA(pdev);
	else
		IF_IS_INT_TABLE_ADDR(USEM_REG_INT_TABLE, addr)
			data = INIT_USEM_INT_TABLE_DATA(pdev);
	else
		IF_IS_INT_TABLE_ADDR(XSEM_REG_INT_TABLE, addr)
			data = INIT_XSEM_INT_TABLE_DATA(pdev);
	else
		IF_IS_PRAM_ADDR(TSEM_REG_PRAM, addr)
			data = INIT_TSEM_PRAM_DATA(pdev);
	else
		IF_IS_PRAM_ADDR(CSEM_REG_PRAM, addr)
			data = INIT_CSEM_PRAM_DATA(pdev);
	else
		IF_IS_PRAM_ADDR(USEM_REG_PRAM, addr)
			data = INIT_USEM_PRAM_DATA(pdev);
	else
		IF_IS_PRAM_ADDR(XSEM_REG_PRAM, addr)
			data = INIT_XSEM_PRAM_DATA(pdev);

	return data;
}

static void ecore_init_wr_wb(struct _lm_device_t *pdev, u32 addr,
			     const u32 *data, u32 len)
{
	if (DMAE_READY(pdev))
		VIRT_WR_DMAE_LEN(pdev, data, addr, len, 0);

	/* in E1 chips BIOS initiated ZLR may interrupt widebus writes */
	else if (CHIP_IS_E1(pdev))
		ecore_init_ind_wr(pdev, addr, data, len);

	/* in later chips PXP root complex handles BIOS ZLR w/o interrupting */
	else
		ecore_init_str_wr(pdev, addr, data, len);
}

#ifndef FW_ZIP_SUPPORT /* ! BNX2X_UPSTREAM */
static void ecore_init_fw(struct _lm_device_t *pdev, u32 addr, u32 len)
{
	const u8 *data = NULL;

	data = ecore_sel_blob(pdev, addr, (const u8 *)data);

	if (DMAE_READY(pdev))
		VIRT_WR_DMAE_LEN(pdev, data, addr, len, 1);

	/* in E1 BIOS initiated ZLR may interrupt widebus writes */
	else if (CHIP_IS_E1(pdev))
		ecore_init_ind_wr(pdev, addr, (const u32 *)data, len);

	/* in later chips PXP root complex handles BIOS ZLR w/o interrupting */
	else
		ecore_init_str_wr(pdev, addr, (const u32 *)data, len);
}

#endif

#ifdef ECORE_UPSTREAM /* ECORE_UPSTREAM */
static void ecore_wr_64(struct _lm_device_t *pdev, u32 reg, u32 val_lo,
			u32 val_hi)
{
	u32 wb_write[2];

	wb_write[0] = val_lo;
	wb_write[1] = val_hi;
	REG_WR_DMAE_LEN(pdev, reg, wb_write, 2);
}
#endif

static void ecore_init_wr_zp(struct _lm_device_t *pdev, u32 addr, u32 len,
			     u32 blob_off)
{
	const u8 *data = NULL;
	int rc;
	u32 i;

	data = ecore_sel_blob(pdev, addr, data) + blob_off*4;

	rc = ecore_gunzip(pdev, data, len);
	if (rc)
		return;

	/* gunzip_outlen is in dwords */
	len = GUNZIP_OUTLEN(pdev);
	for (i = 0; i < len; i++)
		((u32 *)GUNZIP_BUF(pdev))[i] = FORCE32
				mm_cpu_to_le32(((u32 *)GUNZIP_BUF(pdev))[i]);

	ecore_write_big_buf_wb(pdev, addr, len);
}

static void ecore_init_block(struct _lm_device_t *pdev, u32 block, u32 stage)
{
	u16 op_start =
		INIT_OPS_OFFSETS(pdev)[BLOCK_OPS_IDX(block, stage,
						     STAGE_START)];
	u16 op_end =
		INIT_OPS_OFFSETS(pdev)[BLOCK_OPS_IDX(block, stage,
						     STAGE_END)];
	const union init_op *op;
	u32 op_idx, op_type, addr, len;
	const u32 *data, *data_base;

	/* If empty block */
	if (op_start == op_end)
		return;

	data_base = INIT_DATA(pdev);

	for (op_idx = op_start; op_idx < op_end; op_idx++) {

		op = (const union init_op *)&(INIT_OPS(pdev)[op_idx]);
		/* Get generic data */
		op_type = op->raw.op;
		addr = op->raw.offset;
		/* Get data that's used for OP_SW, OP_WB, OP_FW, OP_ZP and
		 * OP_WR64 (we assume that op_arr_write and op_write have the
		 * same structure).
		 */
		len = op->arr_wr.data_len;
		data = data_base + op->arr_wr.data_off;

		switch (op_type) {
		case OP_RD:
			REG_RD(pdev, addr);
			break;
		case OP_WR:
			REG_WR(pdev, addr, op->write.val);
			break;
		case OP_SW:
			ecore_init_str_wr(pdev, addr, data, len);
			break;
		case OP_WB:
			ecore_init_wr_wb(pdev, addr, data, len);
			break;
#ifndef FW_ZIP_SUPPORT /* ! BNX2X_UPSTREAM */
		case OP_FW:
			ecore_init_fw(pdev, addr, len);
			break;
#endif
		case OP_ZR:
			ecore_init_fill(pdev, addr, 0, op->zero.len, 0);
			break;
		case OP_WB_ZR:
			ecore_init_fill(pdev, addr, 0, op->zero.len, 1);
			break;
		case OP_ZP:
			ecore_init_wr_zp(pdev, addr, len,
					 op->arr_wr.data_off);
			break;
		case OP_WR_64:
			ecore_init_wr_64(pdev, addr, data, len);
			break;
		case OP_IF_MODE_AND:
			/* if any of the flags doesn't match, skip the
			 * conditional block.
			 */
			if ((INIT_MODE_FLAGS(pdev) &
				op->if_mode.mode_bit_map) !=
				op->if_mode.mode_bit_map)
				op_idx += op->if_mode.cmd_offset;
			break;
		case OP_IF_MODE_OR:
			/* if all the flags don't match, skip the conditional
			 * block.
			 */
			if ((INIT_MODE_FLAGS(pdev) &
				op->if_mode.mode_bit_map) == 0)
				op_idx += op->if_mode.cmd_offset;
			break;
#ifndef BNX2X_UPSTREAM /* ! BNX2X_UPSTREAM */
		    /* the following opcodes are unused at the moment. */
		case OP_IF_PHASE:
		case OP_RT:
		case OP_DELAY:
		case OP_VERIFY:
#endif
		default:
			/* Should never get here! */
			DbgBreakIf(TRUE);
			break;
		}
	}
}


/****************************************************************************
* PXP Arbiter
****************************************************************************/
/*
 * This code configures the PCI read/write arbiter
 * which implements a weighted round robin
 * between the virtual queues in the chip.
 *
 * The values were derived for each PCI max payload and max request size.
 * since max payload and max request size are only known at run time,
 * this is done as a separate init stage.
 */

#define NUM_WR_Q			13
#define NUM_RD_Q			29
#define MAX_RD_ORD			3
#define MAX_WR_ORD			2

/* configuration for one arbiter queue */
struct arb_line {
	int l;
	int add;
	int ubound;
};

/* derived configuration for each read queue for each max request size */
static const struct arb_line read_arb_data[NUM_RD_Q][MAX_RD_ORD + 1] = {
/* 1 */	{ {8, 64, 25}, {16, 64, 25}, {32, 64, 25}, {64, 64, 41} },
	{ {4, 8,  4},  {4,  8,  4},  {4,  8,  4},  {4,  8,  4}  },
	{ {4, 3,  3},  {4,  3,  3},  {4,  3,  3},  {4,  3,  3}  },
	{ {8, 3,  6},  {16, 3,  11}, {16, 3,  11}, {16, 3,  11} },
	{ {8, 64, 25}, {16, 64, 25}, {32, 64, 25}, {64, 64, 41} },
	{ {8, 3,  6},  {16, 3,  11}, {32, 3,  21}, {64, 3,  41} },
	{ {8, 3,  6},  {16, 3,  11}, {32, 3,  21}, {64, 3,  41} },
	{ {8, 3,  6},  {16, 3,  11}, {32, 3,  21}, {64, 3,  41} },
	{ {8, 3,  6},  {16, 3,  11}, {32, 3,  21}, {64, 3,  41} },
/* 10 */{ {8, 3,  6},  {16, 3,  11}, {32, 3,  21}, {32, 3,  21} },
	{ {8, 3,  6},  {16, 3,  11}, {32, 3,  21}, {32, 3,  21} },
	{ {8, 3,  6},  {16, 3,  11}, {32, 3,  21}, {32, 3,  21} },
	{ {8, 3,  6},  {16, 3,  11}, {32, 3,  21}, {32, 3,  21} },
	{ {8, 3,  6},  {16, 3,  11}, {32, 3,  21}, {32, 3,  21} },
	{ {8, 3,  6},  {16, 3,  11}, {32, 3,  21}, {32, 3,  21} },
	{ {8, 3,  6},  {16, 3,  11}, {32, 3,  21}, {32, 3,  21} },
	{ {8, 64, 6},  {16, 64, 11}, {32, 64, 21}, {32, 64, 21} },
	{ {8, 3,  6},  {16, 3,  11}, {32, 3,  21}, {32, 3,  21} },
	{ {8, 3,  6},  {16, 3,  11}, {32, 3,  21}, {32, 3,  21} },
/* 20 */{ {8, 3,  6},  {16, 3,  11}, {32, 3,  21}, {32, 3,  21} },
	{ {8, 3,  6},  {16, 3,  11}, {32, 3,  21}, {32, 3,  21} },
	{ {8, 3,  6},  {16, 3,  11}, {32, 3,  21}, {32, 3,  21} },
	{ {8, 3,  6},  {16, 3,  11}, {32, 3,  21}, {32, 3,  21} },
	{ {8, 3,  6},  {16, 3,  11}, {32, 3,  21}, {32, 3,  21} },
	{ {8, 3,  6},  {16, 3,  11}, {32, 3,  21}, {32, 3,  21} },
	{ {8, 3,  6},  {16, 3,  11}, {32, 3,  21}, {32, 3,  21} },
	{ {8, 3,  6},  {16, 3,  11}, {32, 3,  21}, {32, 3,  21} },
	{ {8, 3,  6},  {16, 3,  11}, {32, 3,  21}, {32, 3,  21} },
	{ {8, 64, 25}, {16, 64, 41}, {32, 64, 81}, {64, 64, 120} }
};

/* derived configuration for each write queue for each max request size */
static const struct arb_line write_arb_data[NUM_WR_Q][MAX_WR_ORD + 1] = {
/* 1 */	{ {4, 6,  3},  {4,  6,  3},  {4,  6,  3} },
	{ {4, 2,  3},  {4,  2,  3},  {4,  2,  3} },
	{ {8, 2,  6},  {16, 2,  11}, {16, 2,  11} },
	{ {8, 2,  6},  {16, 2,  11}, {32, 2,  21} },
	{ {8, 2,  6},  {16, 2,  11}, {32, 2,  21} },
	{ {8, 2,  6},  {16, 2,  11}, {32, 2,  21} },
	{ {8, 64, 25}, {16, 64, 25}, {32, 64, 25} },
	{ {8, 2,  6},  {16, 2,  11}, {16, 2,  11} },
	{ {8, 2,  6},  {16, 2,  11}, {16, 2,  11} },
/* 10 */{ {8, 9,  6},  {16, 9,  11}, {32, 9,  21} },
	{ {8, 47, 19}, {16, 47, 19}, {32, 47, 21} },
	{ {8, 9,  6},  {16, 9,  11}, {16, 9,  11} },
	{ {8, 64, 25}, {16, 64, 41}, {32, 64, 81} }
};

/* register addresses for read queues */
static const struct arb_line read_arb_addr[NUM_RD_Q-1] = {
/* 1 */	{PXP2_REG_RQ_BW_RD_L0, PXP2_REG_RQ_BW_RD_ADD0,
		PXP2_REG_RQ_BW_RD_UBOUND0},
	{PXP2_REG_PSWRQ_BW_L1, PXP2_REG_PSWRQ_BW_ADD1,
		PXP2_REG_PSWRQ_BW_UB1},
	{PXP2_REG_PSWRQ_BW_L2, PXP2_REG_PSWRQ_BW_ADD2,
		PXP2_REG_PSWRQ_BW_UB2},
	{PXP2_REG_PSWRQ_BW_L3, PXP2_REG_PSWRQ_BW_ADD3,
		PXP2_REG_PSWRQ_BW_UB3},
	{PXP2_REG_RQ_BW_RD_L4, PXP2_REG_RQ_BW_RD_ADD4,
		PXP2_REG_RQ_BW_RD_UBOUND4},
	{PXP2_REG_RQ_BW_RD_L5, PXP2_REG_RQ_BW_RD_ADD5,
		PXP2_REG_RQ_BW_RD_UBOUND5},
	{PXP2_REG_PSWRQ_BW_L6, PXP2_REG_PSWRQ_BW_ADD6,
		PXP2_REG_PSWRQ_BW_UB6},
	{PXP2_REG_PSWRQ_BW_L7, PXP2_REG_PSWRQ_BW_ADD7,
		PXP2_REG_PSWRQ_BW_UB7},
	{PXP2_REG_PSWRQ_BW_L8, PXP2_REG_PSWRQ_BW_ADD8,
		PXP2_REG_PSWRQ_BW_UB8},
/* 10 */{PXP2_REG_PSWRQ_BW_L9, PXP2_REG_PSWRQ_BW_ADD9,
		PXP2_REG_PSWRQ_BW_UB9},
	{PXP2_REG_PSWRQ_BW_L10, PXP2_REG_PSWRQ_BW_ADD10,
		PXP2_REG_PSWRQ_BW_UB10},
	{PXP2_REG_PSWRQ_BW_L11, PXP2_REG_PSWRQ_BW_ADD11,
		PXP2_REG_PSWRQ_BW_UB11},
	{PXP2_REG_RQ_BW_RD_L12, PXP2_REG_RQ_BW_RD_ADD12,
		PXP2_REG_RQ_BW_RD_UBOUND12},
	{PXP2_REG_RQ_BW_RD_L13, PXP2_REG_RQ_BW_RD_ADD13,
		PXP2_REG_RQ_BW_RD_UBOUND13},
	{PXP2_REG_RQ_BW_RD_L14, PXP2_REG_RQ_BW_RD_ADD14,
		PXP2_REG_RQ_BW_RD_UBOUND14},
	{PXP2_REG_RQ_BW_RD_L15, PXP2_REG_RQ_BW_RD_ADD15,
		PXP2_REG_RQ_BW_RD_UBOUND15},
	{PXP2_REG_RQ_BW_RD_L16, PXP2_REG_RQ_BW_RD_ADD16,
		PXP2_REG_RQ_BW_RD_UBOUND16},
	{PXP2_REG_RQ_BW_RD_L17, PXP2_REG_RQ_BW_RD_ADD17,
		PXP2_REG_RQ_BW_RD_UBOUND17},
	{PXP2_REG_RQ_BW_RD_L18, PXP2_REG_RQ_BW_RD_ADD18,
		PXP2_REG_RQ_BW_RD_UBOUND18},
/* 20 */{PXP2_REG_RQ_BW_RD_L19, PXP2_REG_RQ_BW_RD_ADD19,
		PXP2_REG_RQ_BW_RD_UBOUND19},
	{PXP2_REG_RQ_BW_RD_L20, PXP2_REG_RQ_BW_RD_ADD20,
		PXP2_REG_RQ_BW_RD_UBOUND20},
	{PXP2_REG_RQ_BW_RD_L22, PXP2_REG_RQ_BW_RD_ADD22,
		PXP2_REG_RQ_BW_RD_UBOUND22},
	{PXP2_REG_RQ_BW_RD_L23, PXP2_REG_RQ_BW_RD_ADD23,
		PXP2_REG_RQ_BW_RD_UBOUND23},
	{PXP2_REG_RQ_BW_RD_L24, PXP2_REG_RQ_BW_RD_ADD24,
		PXP2_REG_RQ_BW_RD_UBOUND24},
	{PXP2_REG_RQ_BW_RD_L25, PXP2_REG_RQ_BW_RD_ADD25,
		PXP2_REG_RQ_BW_RD_UBOUND25},
	{PXP2_REG_RQ_BW_RD_L26, PXP2_REG_RQ_BW_RD_ADD26,
		PXP2_REG_RQ_BW_RD_UBOUND26},
	{PXP2_REG_RQ_BW_RD_L27, PXP2_REG_RQ_BW_RD_ADD27,
		PXP2_REG_RQ_BW_RD_UBOUND27},
	{PXP2_REG_PSWRQ_BW_L28, PXP2_REG_PSWRQ_BW_ADD28,
		PXP2_REG_PSWRQ_BW_UB28}
};

/* register addresses for write queues */
static const struct arb_line write_arb_addr[NUM_WR_Q-1] = {
/* 1 */	{PXP2_REG_PSWRQ_BW_L1, PXP2_REG_PSWRQ_BW_ADD1,
		PXP2_REG_PSWRQ_BW_UB1},
	{PXP2_REG_PSWRQ_BW_L2, PXP2_REG_PSWRQ_BW_ADD2,
		PXP2_REG_PSWRQ_BW_UB2},
	{PXP2_REG_PSWRQ_BW_L3, PXP2_REG_PSWRQ_BW_ADD3,
		PXP2_REG_PSWRQ_BW_UB3},
	{PXP2_REG_PSWRQ_BW_L6, PXP2_REG_PSWRQ_BW_ADD6,
		PXP2_REG_PSWRQ_BW_UB6},
	{PXP2_REG_PSWRQ_BW_L7, PXP2_REG_PSWRQ_BW_ADD7,
		PXP2_REG_PSWRQ_BW_UB7},
	{PXP2_REG_PSWRQ_BW_L8, PXP2_REG_PSWRQ_BW_ADD8,
		PXP2_REG_PSWRQ_BW_UB8},
	{PXP2_REG_PSWRQ_BW_L9, PXP2_REG_PSWRQ_BW_ADD9,
		PXP2_REG_PSWRQ_BW_UB9},
	{PXP2_REG_PSWRQ_BW_L10, PXP2_REG_PSWRQ_BW_ADD10,
		PXP2_REG_PSWRQ_BW_UB10},
	{PXP2_REG_PSWRQ_BW_L11, PXP2_REG_PSWRQ_BW_ADD11,
		PXP2_REG_PSWRQ_BW_UB11},
/* 10 */{PXP2_REG_PSWRQ_BW_L28, PXP2_REG_PSWRQ_BW_ADD28,
		PXP2_REG_PSWRQ_BW_UB28},
	{PXP2_REG_RQ_BW_WR_L29, PXP2_REG_RQ_BW_WR_ADD29,
		PXP2_REG_RQ_BW_WR_UBOUND29},
	{PXP2_REG_RQ_BW_WR_L30, PXP2_REG_RQ_BW_WR_ADD30,
		PXP2_REG_RQ_BW_WR_UBOUND30}
};

static void ecore_init_pxp_arb(struct _lm_device_t *pdev, int r_order,
			       int w_order)
{
	u32 val, i;

	if (r_order > MAX_RD_ORD) {
		DbgMessage(pdev, WARNi, "read order of %d  order adjusted to %d\n",
			   r_order, MAX_RD_ORD);
		r_order = MAX_RD_ORD;
	}
	if (w_order > MAX_WR_ORD) {
		DbgMessage(pdev, WARNi, "write order of %d  order adjusted to %d\n",
			   w_order, MAX_WR_ORD);
		w_order = MAX_WR_ORD;
	}
	if (CHIP_REV_IS_FPGA(pdev)) {
		DbgMessage(pdev, WARNi, "write order adjusted to 1 for FPGA\n");
		w_order = 0;
	}
	DbgMessage(pdev, INFORMi, "read order %d  write order %d\n", r_order, w_order);

	for (i = 0; i < NUM_RD_Q-1; i++) {
		REG_WR(pdev, read_arb_addr[i].l, read_arb_data[i][r_order].l);
		REG_WR(pdev, read_arb_addr[i].add,
		       read_arb_data[i][r_order].add);
		REG_WR(pdev, read_arb_addr[i].ubound,
		       read_arb_data[i][r_order].ubound);
	}

	for (i = 0; i < NUM_WR_Q-1; i++) {
		if ((write_arb_addr[i].l == PXP2_REG_RQ_BW_WR_L29) ||
		    (write_arb_addr[i].l == PXP2_REG_RQ_BW_WR_L30)) {

			REG_WR(pdev, write_arb_addr[i].l,
			       write_arb_data[i][w_order].l);

			REG_WR(pdev, write_arb_addr[i].add,
			       write_arb_data[i][w_order].add);

			REG_WR(pdev, write_arb_addr[i].ubound,
			       write_arb_data[i][w_order].ubound);
		} else {

			val = REG_RD(pdev, write_arb_addr[i].l);
			REG_WR(pdev, write_arb_addr[i].l,
			       val | (write_arb_data[i][w_order].l << 10));

			val = REG_RD(pdev, write_arb_addr[i].add);
			REG_WR(pdev, write_arb_addr[i].add,
			       val | (write_arb_data[i][w_order].add << 10));

			val = REG_RD(pdev, write_arb_addr[i].ubound);
			REG_WR(pdev, write_arb_addr[i].ubound,
			       val | (write_arb_data[i][w_order].ubound << 7));
		}
	}

	val =  write_arb_data[NUM_WR_Q-1][w_order].add;
	val += write_arb_data[NUM_WR_Q-1][w_order].ubound << 10;
	val += write_arb_data[NUM_WR_Q-1][w_order].l << 17;
	REG_WR(pdev, PXP2_REG_PSWRQ_BW_RD, val);

	val =  read_arb_data[NUM_RD_Q-1][r_order].add;
	val += read_arb_data[NUM_RD_Q-1][r_order].ubound << 10;
	val += read_arb_data[NUM_RD_Q-1][r_order].l << 17;
	REG_WR(pdev, PXP2_REG_PSWRQ_BW_WR, val);

	REG_WR(pdev, PXP2_REG_RQ_WR_MBS0, w_order);
	REG_WR(pdev, PXP2_REG_RQ_WR_MBS1, w_order);
	REG_WR(pdev, PXP2_REG_RQ_RD_MBS0, r_order);
	REG_WR(pdev, PXP2_REG_RQ_RD_MBS1, r_order);

	if ((CHIP_IS_E1(pdev) || CHIP_IS_E1H(pdev)) && (r_order == MAX_RD_ORD))
		REG_WR(pdev, PXP2_REG_RQ_PDR_LIMIT, 0xe00);

	if (CHIP_IS_E3(pdev))
		REG_WR(pdev, PXP2_REG_WR_USDMDP_TH, (0x4 << w_order));
	else if (CHIP_IS_E2(pdev))
		REG_WR(pdev, PXP2_REG_WR_USDMDP_TH, (0x8 << w_order));
	else
		REG_WR(pdev, PXP2_REG_WR_USDMDP_TH, (0x18 << w_order));

	if (!CHIP_IS_E1(pdev)) {
		/*    MPS      w_order     optimal TH      presently TH
		 *    128         0             0               2
		 *    256         1             1               3
		 *    >=512       2             2               3
		 */
		/* DMAE is special */
		if (!CHIP_IS_E1H(pdev)) {
			/* E2 can use optimal TH */
			val = w_order;
			REG_WR(pdev, PXP2_REG_WR_DMAE_MPS, val);
		} else {
			val = ((w_order == 0) ? 2 : 3);
			REG_WR(pdev, PXP2_REG_WR_DMAE_MPS, 2);
		}

		REG_WR(pdev, PXP2_REG_WR_HC_MPS, val);
		REG_WR(pdev, PXP2_REG_WR_USDM_MPS, val);
		REG_WR(pdev, PXP2_REG_WR_CSDM_MPS, val);
		REG_WR(pdev, PXP2_REG_WR_TSDM_MPS, val);
		REG_WR(pdev, PXP2_REG_WR_XSDM_MPS, val);
		REG_WR(pdev, PXP2_REG_WR_QM_MPS, val);
		REG_WR(pdev, PXP2_REG_WR_TM_MPS, val);
		REG_WR(pdev, PXP2_REG_WR_SRC_MPS, val);
		REG_WR(pdev, PXP2_REG_WR_DBG_MPS, val);
		REG_WR(pdev, PXP2_REG_WR_CDU_MPS, val);
	}

	/* Validate number of tags suppoted by device */
#define PCIE_REG_PCIER_TL_HDR_FC_ST		0x2980
	val = REG_RD(pdev, PCIE_REG_PCIER_TL_HDR_FC_ST);
	val &= 0xFF;
	if (val <= 0x20)
		REG_WR(pdev, PXP2_REG_PGL_TAGS_LIMIT, 0x20);
}

#ifdef ECORE_UPSTREAM /* ECORE_UPSTREAM */
/****************************************************************************
* ILT management
****************************************************************************/
/*
 * This codes hides the low level HW interaction for ILT management and
 * configuration. The API consists of a shadow ILT table which is set by the
 * driver and a set of routines to use it to configure the HW.
 *
 */

/* ILT HW init operations */

/* ILT memory management operations */
#define ILT_MEMOP_ALLOC		0
#define ILT_MEMOP_FREE		1

/* the phys address is shifted right 12 bits and has an added
 * 1=valid bit added to the 53rd bit
 * then since this is a wide register(TM)
 * we split it into two 32 bit writes
 */
#define ILT_ADDR1(x)		((u32)(((u64)x >> 12) & 0xFFFFFFFF))
#define ILT_ADDR2(x)		((u32)((1 << 20) | ((u64)x >> 44)))
#define ILT_RANGE(f, l)		(((l) << 10) | f)

static int ecore_ilt_line_mem_op(struct _lm_device_t *pdev,
				 struct ilt_line *line, u32 size, u8 memop)
{
	if (memop == ILT_MEMOP_FREE) {
		ECORE_ILT_FREE(line->page, line->page_mapping, line->size);
		return 0;
	}
	ECORE_ILT_ZALLOC(line->page, &line->page_mapping, size);
	if (!line->page)
		return -1;
	line->size = size;
	return 0;
}


static int ecore_ilt_client_mem_op(struct _lm_device_t *pdev, int cli_num,
				   u8 memop)
{
	int i, rc;
	struct ecore_ilt *ilt = PDEV_ILT(pdev);
	struct ilt_client_info *ilt_cli = &ilt->clients[cli_num];

	if (!ilt || !ilt->lines)
		return -1;

	if (ilt_cli->flags & (ILT_CLIENT_SKIP_INIT | ILT_CLIENT_SKIP_MEM))
		return 0;

	for (rc = 0, i = ilt_cli->start; i <= ilt_cli->end && !rc; i++) {
		rc = ecore_ilt_line_mem_op(pdev, &ilt->lines[i],
					   ilt_cli->page_size, memop);
	}
	return rc;
}

static int ecore_ilt_mem_op_cnic(struct _lm_device_t *pdev, u8 memop)
{
	int rc = 0;

	if (CONFIGURE_NIC_MODE(pdev))
		rc = ecore_ilt_client_mem_op(pdev, ILT_CLIENT_SRC, memop);
	if (!rc)
		rc = ecore_ilt_client_mem_op(pdev, ILT_CLIENT_TM, memop);

	return rc;
}

static int ecore_ilt_mem_op(struct _lm_device_t *pdev, u8 memop)
{
	int rc = ecore_ilt_client_mem_op(pdev, ILT_CLIENT_CDU, memop);
	if (!rc)
		rc = ecore_ilt_client_mem_op(pdev, ILT_CLIENT_QM, memop);
	if (!rc && CNIC_SUPPORT(pdev) && !CONFIGURE_NIC_MODE(pdev))
		rc = ecore_ilt_client_mem_op(pdev, ILT_CLIENT_SRC, memop);

	return rc;
}

static void ecore_ilt_line_wr(struct _lm_device_t *pdev, int abs_idx,
			      lm_address_t page_mapping)
{
	u32 reg;

	if (CHIP_IS_E1(pdev))
		reg = PXP2_REG_RQ_ONCHIP_AT + abs_idx*8;
	else
		reg = PXP2_REG_RQ_ONCHIP_AT_B0 + abs_idx*8;

	ecore_wr_64(pdev, reg, ILT_ADDR1(page_mapping.as_u64), ILT_ADDR2(page_mapping.as_u64));
}

static void ecore_ilt_line_init_op(struct _lm_device_t *pdev,
				   struct ecore_ilt *ilt, int idx, u8 initop)
{
	lm_address_t	null_mapping;
	int abs_idx = ilt->start_line + idx;


	switch (initop) {
	case INITOP_INIT:
		/* set in the init-value array */
	case INITOP_SET:
		ecore_ilt_line_wr(pdev, abs_idx, ilt->lines[idx].page_mapping);
		break;
	case INITOP_CLEAR:
		null_mapping.as_u64 = 0;
		ecore_ilt_line_wr(pdev, abs_idx, null_mapping);
		break;
	}
}

static void ecore_ilt_boundry_init_op(struct _lm_device_t *pdev,
				      struct ilt_client_info *ilt_cli,
				      u32 ilt_start, u8 initop)
{
	u32 start_reg = 0;
	u32 end_reg = 0;

	/* The boundary is either SET or INIT,
	   CLEAR => SET and for now SET ~~ INIT */

	/* find the appropriate regs */
	if (CHIP_IS_E1(pdev)) {
		switch (ilt_cli->client_num) {
		case ILT_CLIENT_CDU:
			start_reg = PXP2_REG_PSWRQ_CDU0_L2P;
			break;
		case ILT_CLIENT_QM:
			start_reg = PXP2_REG_PSWRQ_QM0_L2P;
			break;
		case ILT_CLIENT_SRC:
			start_reg = PXP2_REG_PSWRQ_SRC0_L2P;
			break;
		case ILT_CLIENT_TM:
			start_reg = PXP2_REG_PSWRQ_TM0_L2P;
			break;
		}
		REG_WR(pdev, start_reg + PDEV_FUNC(pdev)*4,
		       ILT_RANGE((ilt_start + ilt_cli->start),
				 (ilt_start + ilt_cli->end)));
	} else {
		switch (ilt_cli->client_num) {
		case ILT_CLIENT_CDU:
			start_reg = PXP2_REG_RQ_CDU_FIRST_ILT;
			end_reg = PXP2_REG_RQ_CDU_LAST_ILT;
			break;
		case ILT_CLIENT_QM:
			start_reg = PXP2_REG_RQ_QM_FIRST_ILT;
			end_reg = PXP2_REG_RQ_QM_LAST_ILT;
			break;
		case ILT_CLIENT_SRC:
			start_reg = PXP2_REG_RQ_SRC_FIRST_ILT;
			end_reg = PXP2_REG_RQ_SRC_LAST_ILT;
			break;
		case ILT_CLIENT_TM:
			start_reg = PXP2_REG_RQ_TM_FIRST_ILT;
			end_reg = PXP2_REG_RQ_TM_LAST_ILT;
			break;
		}
		REG_WR(pdev, start_reg, (ilt_start + ilt_cli->start));
		REG_WR(pdev, end_reg, (ilt_start + ilt_cli->end));
	}
}

static void ecore_ilt_client_init_op_ilt(struct _lm_device_t *pdev,
					 struct ecore_ilt *ilt,
					 struct ilt_client_info *ilt_cli,
					 u8 initop)
{
	int i;

	if (ilt_cli->flags & ILT_CLIENT_SKIP_INIT)
		return;

	for (i = ilt_cli->start; i <= ilt_cli->end; i++)
		ecore_ilt_line_init_op(pdev, ilt, i, initop);

	/* init/clear the ILT boundries */
	ecore_ilt_boundry_init_op(pdev, ilt_cli, ilt->start_line, initop);
}

static void ecore_ilt_client_init_op(struct _lm_device_t *pdev,
				     struct ilt_client_info *ilt_cli, u8 initop)
{
	struct ecore_ilt *ilt = PDEV_ILT(pdev);

	ecore_ilt_client_init_op_ilt(pdev, ilt, ilt_cli, initop);
}

static void ecore_ilt_client_id_init_op(struct _lm_device_t *pdev,
					int cli_num, u8 initop)
{
	struct ecore_ilt *ilt = PDEV_ILT(pdev);
	struct ilt_client_info *ilt_cli = &ilt->clients[cli_num];

	ecore_ilt_client_init_op(pdev, ilt_cli, initop);
}

static void ecore_ilt_init_op_cnic(struct _lm_device_t *pdev, u8 initop)
{
	if (CONFIGURE_NIC_MODE(pdev))
		ecore_ilt_client_id_init_op(pdev, ILT_CLIENT_SRC, initop);
	ecore_ilt_client_id_init_op(pdev, ILT_CLIENT_TM, initop);
}

static void ecore_ilt_init_op(struct _lm_device_t *pdev, u8 initop)
{
	ecore_ilt_client_id_init_op(pdev, ILT_CLIENT_CDU, initop);
	ecore_ilt_client_id_init_op(pdev, ILT_CLIENT_QM, initop);
	if (CNIC_SUPPORT(pdev) && !CONFIGURE_NIC_MODE(pdev))
		ecore_ilt_client_id_init_op(pdev, ILT_CLIENT_SRC, initop);
}

static void ecore_ilt_init_client_psz(struct _lm_device_t *pdev, int cli_num,
				      u32 psz_reg, u8 initop)
{
	struct ecore_ilt *ilt = PDEV_ILT(pdev);
	struct ilt_client_info *ilt_cli = &ilt->clients[cli_num];

	if (ilt_cli->flags & ILT_CLIENT_SKIP_INIT)
		return;

	switch (initop) {
	case INITOP_INIT:
		/* set in the init-value array */
	case INITOP_SET:
		REG_WR(pdev, psz_reg, ILOG2(ilt_cli->page_size >> 12));
		break;
	case INITOP_CLEAR:
		break;
	}
}

/*
 * called during init common stage, ilt clients should be initialized
 * prioir to calling this function
 */
static void ecore_ilt_init_page_size(struct _lm_device_t *pdev, u8 initop)
{
	ecore_ilt_init_client_psz(pdev, ILT_CLIENT_CDU,
				  PXP2_REG_RQ_CDU_P_SIZE, initop);
	ecore_ilt_init_client_psz(pdev, ILT_CLIENT_QM,
				  PXP2_REG_RQ_QM_P_SIZE, initop);
	ecore_ilt_init_client_psz(pdev, ILT_CLIENT_SRC,
				  PXP2_REG_RQ_SRC_P_SIZE, initop);
	ecore_ilt_init_client_psz(pdev, ILT_CLIENT_TM,
				  PXP2_REG_RQ_TM_P_SIZE, initop);
}

/****************************************************************************
* QM initializations
****************************************************************************/
#define QM_QUEUES_PER_FUNC	16 /* E1 has 32, but only 16 are used */
#define QM_INIT_MIN_CID_COUNT	31
#define QM_INIT(cid_cnt)	(cid_cnt > QM_INIT_MIN_CID_COUNT)

/* called during init port stage */
static void ecore_qm_init_cid_count(struct _lm_device_t *pdev, int qm_cid_count,
				    u8 initop)
{
	int port = PDEV_PORT(pdev);

	if (QM_INIT(qm_cid_count)) {
		switch (initop) {
		case INITOP_INIT:
			/* set in the init-value array */
		case INITOP_SET:
			REG_WR(pdev, QM_REG_CONNNUM_0 + port*4,
			       qm_cid_count/16 - 1);
			break;
		case INITOP_CLEAR:
			break;
		}
	}
}

static void ecore_qm_set_ptr_table(struct _lm_device_t *pdev, int qm_cid_count,
				   u32 base_reg, u32 reg)
{
	int i;
	u32 wb_data[2] = {0, 0};
	for (i = 0; i < 4 * QM_QUEUES_PER_FUNC; i++) {
		REG_WR(pdev, base_reg + i*4,
		       qm_cid_count * 4 * (i % QM_QUEUES_PER_FUNC));
		ecore_init_wr_wb(pdev, reg + i*8,
				 wb_data, 2);
	}
}

/* called during init common stage */
static void ecore_qm_init_ptr_table(struct _lm_device_t *pdev, int qm_cid_count,
				    u8 initop)
{
	if (!QM_INIT(qm_cid_count))
		return;

	switch (initop) {
	case INITOP_INIT:
		/* set in the init-value array */
	case INITOP_SET:
		ecore_qm_set_ptr_table(pdev, qm_cid_count,
				       QM_REG_BASEADDR, QM_REG_PTRTBL);
		if (CHIP_IS_E1H(pdev))
			ecore_qm_set_ptr_table(pdev, qm_cid_count,
					       QM_REG_BASEADDR_EXT_A,
					       QM_REG_PTRTBL_EXT_A);
		break;
	case INITOP_CLEAR:
		break;
	}
}

#endif
/****************************************************************************
* SRC initializations
****************************************************************************/
#ifdef ECORE_L5
/* called during init func stage */
static void ecore_src_init_t2(struct _lm_device_t *pdev, struct src_ent *t2,
			      lm_address_t t2_mapping, int src_cid_count)
{
	int i;
	int port = PDEV_PORT(pdev);

	/* Initialize T2 */
	for (i = 0; i < src_cid_count-1; i++)
		t2[i].next = (u64)(t2_mapping.as_u64 +
			     (i+1)*sizeof(struct src_ent));

	/* tell the searcher where the T2 table is */
	REG_WR(pdev, SRC_REG_COUNTFREE0 + port*4, src_cid_count);

	ecore_wr_64(pdev, SRC_REG_FIRSTFREE0 + port*16,
		    U64_LO(t2_mapping.as_u64), U64_HI(t2_mapping.as_u64));

	ecore_wr_64(pdev, SRC_REG_LASTFREE0 + port*16,
		    U64_LO((u64)t2_mapping.as_u64 +
			   (src_cid_count-1) * sizeof(struct src_ent)),
		    U64_HI((u64)t2_mapping.as_u64 +
			   (src_cid_count-1) * sizeof(struct src_ent)));
}
#endif
#endif /* ECORE_INIT_OPS_H */
