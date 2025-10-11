/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2025 Oxide Computer Company
 */

/*
 * Intel SMBus Message Transport controller driver.
 *
 * This is a DMA based SMBus controller that is found in some of the various
 * Atom and Xeon-D based platforms. The hardware divides registers into three
 * rough groups. There are the general registers, controller specific registers,
 * and target specific registers. We don't implement the target.
 *
 * The device can support a ring of DMA transfers. We only will have one
 * outstanding at a time, so we go with a simple length of 4 entries and have a
 * single data DMA buffer that is used by all commands.
 *
 * Unlike the PCH-based SMBus controller, this controller supports both SMBus
 * 2.0 commands and can perform arbitrary commands over I2C.
 */

#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/pci.h>
#include <sys/sysmacros.h>

#include <sys/i2c/controller.h>
#include "ismt.h"

/*
 * The controller has a single BAR, SMTBAR, which is found in the BAR 0/1. This
 * translates to reg[1] as reg[0] contains the config space information about
 * the device.
 */
#define	ISMT_REGNO	1

/*
 * Because we never use the offset and address for syncing, we want to cast the
 * DMA sync call to void, but lets be paranoid on debug.
 */
#ifdef	DEBUG
#define	ISMT_DMA_SYNC(buf, flag)	ASSERT0(ddi_dma_sync((buf).id_hdl, \
					    0, 0, flag))
#else
#define	ISMT_DMA_SYNC(buf, flag)	(void) ddi_dma_sync((buf).id_hdl, \
					    0, 0, flag)
#endif	/* DEBUG */


/*
 * Allocation sizes for our ring and DMA data buffer. We size the ring at 4
 * entries (though it seems like we could probably get away with just one). The
 * data buffer we size at 128 bytes, which covers both the maximum read and
 * maximum write in one go (though we shouldn't exceed it either one). The last
 * one of these, the interrupt cause log size is the hardest. It defitely is
 * written before every interrupt, but whether we need one of these per entry in
 * the log or it just clobbers the last location is unclear. It doesn't actually
 * ask for a size so we just double the number of ring entries.
 */
#define	ISMT_RING_NENTS		4
#define	ISMT_RING_DMA_SIZE	(ISMT_RING_NENTS  * sizeof (ismt_desc_t))
#define	ISMT_DATA_BUF_SIZE	128U
#define	ISMT_ICL_DMA_SIZE	(ISMT_RING_NENTS * sizeof (uint32_t) * 2)

typedef enum {
	ISMT_INIT_PCI		= 1 << 0,
	ISMT_INIT_REGS		= 1 << 1,
	ISMT_INIT_INTR_ALLOC	= 1 << 2,
	ISMT_INIT_INTR_HDL	= 1 << 3,
	ISMT_INIT_SYNC		= 1 << 4,
	ISMT_INIT_INTR_EN	= 1 << 5,
	ISMT_INIT_I2C		= 1 << 6
} ismt_init_t;

typedef struct {
	ddi_dma_handle_t id_hdl;
	caddr_t id_va;
	ddi_acc_handle_t id_acc;
	size_t id_alloc_len;
	size_t id_size;
} ismt_dma_t;

typedef struct {
	dev_info_t *ismt_dip;
	ddi_acc_handle_t ismt_cfg;
	ismt_init_t ismt_init;
	/*
	 * Register related data
	 */
	caddr_t ismt_base;
	off_t ismt_regsize;
	ddi_acc_handle_t ismt_regs;
	/*
	 * DMA Information
	 */
	ismt_dma_t ismt_ring_dma;
	ismt_dma_t ismt_data_dma;
	ismt_dma_t ismt_icl_dma;
	/*
	 * Interrupt data
	 */
	int ismt_nintrs;
	int ismt_itype;
	ddi_intr_handle_t ismt_intr_hdl;
	uint_t ismt_intr_pri;
	/*
	 * Request and framework synchronization.
	 */
	i2c_speed_t ismt_speed;
	kmutex_t ismt_mutex;
	kcondvar_t ismt_cv;
	i2c_ctrl_hdl_t *ismt_hdl;
	uint32_t ismt_head;
	uint32_t ismt_tail;
	ismt_desc_t *ismt_ring;
	smbus_req_t *ismt_req;
	i2c_req_t *ismt_i2creq;
	i2c_error_t *ismt_err;
	bool ismt_req_done;
} ismt_t;

/*
 * Consolidated DMA attributes for the descriptor ring and the data buffer. We
 * use the stricter requirements from each because we don't actually allocate
 * that much DMA memory here to make this simpler.
 */
static const ddi_dma_attr_t ismt_dma_attr = {
	.dma_attr_version = DMA_ATTR_V0,
	/*
	 * Our DMA attributes can appear anywhere in 64-bit space.
	 */
	.dma_attr_addr_lo = 0,
	.dma_attr_addr_hi = UINT64_MAX,
	/*
	 * Up to 255 bytes are allowed to be specified for transmit / recieve,
	 * where as the descriptor ring allows for up to 256 16 byte
	 * descriptors. We use the latter for here, with the knowledge that
	 * we're never allocating more than an amount that can fit due to the
	 * maxxfer value below.
	 */
	.dma_attr_count_max = 256 * sizeof (ismt_desc_t),
	/*
	 * The descriptor ring requires 64 byte alignment, where as the data
	 * buffer requires byte alignment. Use 64 byte alignment.
	 */
	.dma_attr_align = 0x40,
	/*
	 * Cargo culted burst sizes as PCIe probably doens't have quite the same
	 * concerns.
	 */
	.dma_attr_burstsizes = 0xfff,
	/*
	 * We set the minimum and maximum to the sizes here. The size limits are
	 * really set by PCIe breaking up transactions, not anything in the
	 * kernel. Therefore we set the maximum to the same as
	 * dma_attr_count_max, partially so we can avoid complaints about DMA
	 * less than a page by x86 rootnex.
	 */
	.dma_attr_minxfer = 1,
	.dma_attr_maxxfer = 256 * sizeof (ismt_desc_t),
	/*
	 * Their are no segment restrictions and only one cookie can be used.
	 * For the granularity we basically set this to 1 because everything we
	 * allocate will be a multiple of this and we only have one cookie so it
	 * won't really be split..
	 */
	.dma_attr_seg = UINT64_MAX,
	.dma_attr_sgllen = 1,
	.dma_attr_granular = 1,
	.dma_attr_flags = 0
};

static uint32_t
ismt_read32(ismt_t *ismt, uint32_t reg)
{
	ASSERT3U(reg, <, ismt->ismt_regsize);
	return (ddi_get32(ismt->ismt_regs, (uint32_t *)(ismt->ismt_base +
	    reg)));
}

static void
ismt_write32(ismt_t *ismt, uint32_t reg, uint32_t val)
{
	ASSERT3U(reg, <, ismt->ismt_regsize);
	ddi_put32(ismt->ismt_regs, (uint32_t *)(ismt->ismt_base + reg), val);
}

static void
ismt_write64(ismt_t *ismt, uint32_t reg, uint64_t val)
{
	ASSERT3U(reg, <, ismt->ismt_regsize);
	ddi_put64(ismt->ismt_regs, (uint64_t *)(ismt->ismt_base + reg), val);
}

static i2c_errno_t
ismt_prop_info(void *arg, i2c_prop_t prop, i2c_prop_info_t *info)
{
	switch (prop) {
	case I2C_PROP_BUS_SPEED:
		i2c_prop_info_set_pos_bit32(info, I2C_SPEED_STD |
		    I2C_SPEED_FAST | I2C_SPEED_FPLUS);
		break;
	case SMBUS_PROP_SUP_OPS:
	case I2C_PROP_MAX_READ:
	case I2C_PROP_MAX_WRITE:
	case SMBUS_PROP_MAX_BLOCK:
		break;
	default:
		return (I2C_PROP_E_UNSUP);
	}

	i2c_prop_info_set_perm(info, I2C_PROP_PERM_RO);

	return (I2C_CORE_E_OK);
}

/*
 * Currently all the information that we return is static. If this changes, we
 * should ensure we hold ismt_mutex during this.
 */
static i2c_errno_t
ismt_prop_get(void *arg, i2c_prop_t prop, void *buf, size_t buflen)
{
	ismt_t *ismt = arg;
	uint32_t val;

	switch (prop) {
	case I2C_PROP_BUS_SPEED:
		val = ismt->ismt_speed;
		break;
	case SMBUS_PROP_SUP_OPS:
		val = SMBUS_PROP_OP_QUICK_COMMAND | SMBUS_PROP_OP_SEND_BYTE |
		    SMBUS_PROP_OP_RECV_BYTE | SMBUS_PROP_OP_WRITE_BYTE |
		    SMBUS_PROP_OP_READ_BYTE | SMBUS_PROP_OP_WRITE_WORD |
		    SMBUS_PROP_OP_READ_WORD | SMBUS_PROP_OP_PROCESS_CALL |
		    SMBUS_PROP_OP_WRITE_BLOCK | SMBUS_PROP_OP_READ_BLOCK |
		    SMBUS_PROP_OP_BLOCK_PROCESS_CALL |
		    SMBUS_PROP_OP_I2C_WRITE_BLOCK |
		    SMBUS_PROP_OP_I2C_READ_BLOCK;
		break;
	case I2C_PROP_MAX_READ:
	case I2C_PROP_MAX_WRITE:
		val = ISMT_MAX_I2C;
		break;
	case SMBUS_PROP_MAX_BLOCK:
		val = ISMT_MAX_SMBUS;
		break;
	default:
		return (I2C_PROP_E_UNSUP);
	}

	VERIFY3U(buflen, >=, sizeof (val));
	bcopy(&val, buf, sizeof (val));
	return (I2C_CORE_E_OK);
}

static void
ismt_io_error(ismt_t *ismt, uint32_t sts)
{
	i2c_ctrl_error_t err;
	VERIFY3P(ismt->ismt_err, !=, NULL);

	if (ISMT_DESC_STS_GET_NACK(sts) != 0) {
		if (ISMT_DESC_STS_GET_WRLEN(sts) == 0) {
			err = I2C_CTRL_E_ADDR_NACK;
		} else {
			err = I2C_CTRL_E_DATA_NACK;
		}
	} else if (ISMT_DESC_STS_GET_CRC(sts) != 0) {
		/*
		 * As we don't enable PEC right now, we don't expect to see
		 * this. When we do, then this should be changed.
		 */
		err = I2C_CTRL_E_DRIVER;
	} else if (ISMT_DESC_STS_GET_CLTO(sts) != 0) {
		err = I2C_CTRL_E_SMBUS_CLOCK_LOW;
	} else if (ISMT_DESC_STS_GET_COL(sts) != 0) {
		err = I2C_CTRL_E_ARB_LOST;
	} else if (ISMT_DESC_STS_GET_LPR(sts) != 0) {
		err = I2C_CTRL_E_DRIVER;
	} else {
		err = I2C_CTRL_E_INTERNAL;
	}

	i2c_ctrl_io_error(ismt->ismt_err, I2C_CORE_E_CONTROLLER, err);
}

/*
 * Process the current completion.
 */
static void
ismt_io(ismt_t *ismt)
{
	ismt_desc_t *desc;
	uint32_t sts;

	VERIFY(MUTEX_HELD(&ismt->ismt_mutex));
	ISMT_DMA_SYNC(ismt->ismt_ring_dma, DDI_DMA_SYNC_FORKERNEL);
	ISMT_DMA_SYNC(ismt->ismt_data_dma, DDI_DMA_SYNC_FORKERNEL);
	desc = &ismt->ismt_ring[ismt->ismt_tail];
	ismt->ismt_tail = (ismt->ismt_tail + 1) % ISMT_RING_NENTS;
	const uint8_t *buf = (uint8_t *)ismt->ismt_data_dma.id_va;

	sts = LE_32(desc->id_status);
	if (ISMT_DESC_STS_GET_SCS(sts) == 0) {
		ismt_io_error(ismt, sts);
		return;
	}

	if (ismt->ismt_i2creq != NULL) {
		VERIFY3P(ismt->ismt_req, ==, NULL);
		if (ismt->ismt_i2creq->ir_rlen > 0) {
			VERIFY3U(ismt->ismt_i2creq->ir_rlen, ==,
			    ISMT_DESC_STS_GET_RDLEN(sts));
			bcopy(buf, ismt->ismt_i2creq->ir_rdata,
			    ISMT_DESC_STS_GET_RDLEN(sts));
		}
		i2c_ctrl_io_success(ismt->ismt_err);
		return;
	}

	switch (ismt->ismt_req->smbr_op) {
	case SMBUS_OP_QUICK_COMMAND:
	case SMBUS_OP_SEND_BYTE:
	case SMBUS_OP_WRITE_BYTE:
	case SMBUS_OP_WRITE_WORD:
	case SMBUS_OP_WRITE_BLOCK:
	case SMBUS_OP_I2C_WRITE_BLOCK:
		/*
		 * Nothing to do for writes.
		 */
		break;
	case SMBUS_OP_RECV_BYTE:
	case SMBUS_OP_READ_BYTE:
		ismt->ismt_req->smbr_rdata[0] = buf[0];
		break;
	case SMBUS_OP_READ_WORD:
	case SMBUS_OP_PROCESS_CALL:
		ismt->ismt_req->smbr_rdata[0] = buf[0];
		ismt->ismt_req->smbr_rdata[1] = buf[1];
		break;
	case SMBUS_OP_READ_BLOCK:
	case SMBUS_OP_BLOCK_PROCESS_CALL:
		if (ISMT_DESC_STS_GET_RDLEN(sts) != buf[0] + 1) {
			i2c_ctrl_io_error(ismt->ismt_err, I2C_CORE_E_CONTROLLER,
			    I2C_CTRL_E_DRIVER);
			return;
		}
		ismt->ismt_req->smbr_rlen = buf[0];
		bcopy(&buf[1], ismt->ismt_req->smbr_rdata, buf[0]);
		break;
	case SMBUS_OP_I2C_READ_BLOCK:
		bcopy(buf, ismt->ismt_req->smbr_rdata,
		    ISMT_DESC_STS_GET_RDLEN(sts));
		break;
	case SMBUS_OP_WRITE_U32:
	case SMBUS_OP_WRITE_U64:
	case SMBUS_OP_READ_U32:
	case SMBUS_OP_READ_U64:
	case SMBUS_OP_HOST_NOTIFY:
	default:
		panic("programmer error: unsupported request type 0x%x should "
		    "not have been completed", ismt->ismt_req->smbr_op);
	}

	i2c_ctrl_io_success(ismt->ismt_err);
}

/*
 * When we're using MSI interrupts then the hardware will automatically clear
 * the controller's interrupt status register based on our configuration.
 * However if we're using INTx, then we will need to take care of reading the
 * various status registers and checking what has happened.
 *
 * One nice thing is that we'll otherwise always get an interrupt when the whole
 * operation is done.
 */
static uint_t
ismt_intr(caddr_t arg1, caddr_t arg2)
{
	ismt_t *ismt = (ismt_t *)arg1;
	uint32_t msts;
	bool mis, meis;

	mutex_enter(&ismt->ismt_mutex);
	if (ismt->ismt_itype == DDI_INTR_TYPE_FIXED) {
		msts = ismt_read32(ismt, ISMT_R_MSTS);
		mis = ISMT_R_MSTS_GET_MIS(msts);
		meis = ISMT_R_MSTS_GET_MEIS(msts);

		if (!mis && !meis) {
			mutex_exit(&ismt->ismt_mutex);
			return (DDI_INTR_UNCLAIMED);
		}
		ismt_write32(ismt, ISMT_R_MSTS, msts);
	}

	ismt_io(ismt);
	ismt->ismt_req_done = true;
	cv_signal(&ismt->ismt_cv);
	mutex_exit(&ismt->ismt_mutex);
	return (DDI_INTR_CLAIMED);
}

static void
ismt_wait(ismt_t *ismt)
{
	VERIFY(MUTEX_HELD(&ismt->ismt_mutex));
	VERIFY(ismt->ismt_req == NULL || ismt->ismt_i2creq == NULL);
	VERIFY3P(ismt->ismt_req, !=, ismt->ismt_i2creq);

	uint32_t to = i2c_ctrl_timeout_delay_us(ismt->ismt_hdl, I2C_CTRL_TO_IO);
	clock_t abs = ddi_get_lbolt() + drv_usectohz(to);
	while (!ismt->ismt_req_done) {
		clock_t ret = cv_timedwait(&ismt->ismt_cv, &ismt->ismt_mutex,
		    abs);
		if (ret == -1) {
			break;
		}
	}

	/*
	 * The command timed out. We need to set the KILL bit, complete the
	 * transaction, and go from there.
	 */
	if (!ismt->ismt_req_done) {
		uint32_t val = ISMT_R_GCTRL_SET_KILL(0, 1);
		ismt_write32(ismt, ISMT_R_GCTRL, val);
		i2c_ctrl_io_error(ismt->ismt_err, I2C_CORE_E_CONTROLLER,
		    I2C_CTRL_E_REQ_TO);
		ismt->ismt_req_done = true;
	}
}

static void
ismt_io_reset(ismt_t *ismt)
{
	VERIFY(MUTEX_HELD(&ismt->ismt_mutex));
	bzero(ismt->ismt_data_dma.id_va, ISMT_DATA_BUF_SIZE);
	bzero(ismt->ismt_icl_dma.id_va, ISMT_ICL_DMA_SIZE);
	ismt->ismt_req = NULL;
	ismt->ismt_i2creq = NULL;
	ismt->ismt_err = NULL;
	ismt->ismt_req_done = false;
}

/*
 * Set the things that are common across all I/O requests: the address, the
 * request for the fair bit, and ask for an interrupt. Hardware will ownly honor
 * the bit if we're using MSIs and otherwise will always inject the interrupt,
 * so we set this regardless.
 */
static void
ismt_io_cmd_init(const i2c_addr_t *addr, uint32_t *cmdp)
{
	uint32_t cmd;

	ASSERT3U(addr->ia_type, ==, I2C_ADDR_7BIT);
	cmd = ISMT_DESC_CMD_SET_ADDR(0, addr->ia_addr);
	cmd = ISMT_DESC_CMD_SET_INT(cmd, 1);
	cmd = ISMT_DESC_CMD_SET_FAIR(cmd, 1);
	*cmdp = cmd;
}

static void
ismt_io_cmd_submit(ismt_t *ismt, uint32_t cmd, bool data)
{
	ismt_desc_t *desc;

	VERIFY(MUTEX_HELD(&ismt->ismt_mutex));
	desc = &ismt->ismt_ring[ismt->ismt_head];
	bzero(desc, sizeof (desc));

	desc->id_cmd_addr = LE_32(cmd);
	if (data) {
		const ddi_dma_cookie_t *c;

		c = ddi_dma_cookie_one(ismt->ismt_data_dma.id_hdl);
		desc->id_low = LE_32(bitx64(c->dmac_laddress, 31, 0));
		desc->id_high = LE_32(bitx64(c->dmac_laddress, 63, 32));
		ISMT_DMA_SYNC(ismt->ismt_data_dma, DDI_DMA_SYNC_FORDEV);
	}
	ISMT_DMA_SYNC(ismt->ismt_ring_dma, DDI_DMA_SYNC_FORDEV);

	/*
	 * Proceed to tell hardware to process this command. The datasheet
	 * suggests we need to update the descriptor pointer and then come back
	 * and ask the hardware to start as we can't set SS until at least one
	 * descriptor has been programmed.
	 */
	ismt->ismt_head = (ismt->ismt_head + 1) % ISMT_RING_NENTS;
	uint32_t mctrl = ismt_read32(ismt, ISMT_R_MCTRL);
	mctrl = ISMT_R_MCTRL_SET_FMHP(mctrl, ismt->ismt_head);
	ismt_write32(ismt, ISMT_R_MCTRL, mctrl);
	mctrl = ISMT_R_MCTRL_SET_SS(mctrl, 1);
	ismt_write32(ismt, ISMT_R_MCTRL, mctrl);

	/*
	 * The command is running. We now need to wait for an interrupt or poll
	 * for completion. Unlike other drivers, we always have the interrupt
	 * enabled, which means we can't really poll.
	 */
	ismt_wait(ismt);
}

static void
ismt_io_smbus(void *arg, uint32_t port, smbus_req_t *req)
{
	ismt_t *ismt = arg;
	uint8_t *buf;
	uint32_t cmd;
	bool data = false;

	mutex_enter(&ismt->ismt_mutex);
	ismt_io_reset(ismt);
	ismt->ismt_req = req;
	ismt->ismt_err = &req->smbr_error;

	buf = (uint8_t *)ismt->ismt_data_dma.id_va;

	/*
	 * Set up the descriptor. In particualr we need to determine whether to
	 * set:
	 *
	 *  - The read address bit (default is write)
	 *  - The block request bit
	 *  - The C/WRL bit which determines whether the write field is the
	 *    command.
	 *  - The read and write length, if non-zero.
	 *  - Whether we are going to use the data pointer and if we need to do
	 *    anyhting to get it ready
	 *
	 * The read address bit and whether we use data are bools that we apply
	 * at the end.
	 */
	ismt_io_cmd_init(&req->smbr_addr, &cmd);
	switch (req->smbr_op) {
	case SMBUS_OP_QUICK_COMMAND:
		if ((req->smbr_flags & I2C_IO_REQ_F_QUICK_WRITE) != 0) {
			cmd = ISMT_DESC_CMD_SET_RW(cmd, ISMT_DESC_CMD_RW_WRITE);
		} else {
			cmd = ISMT_DESC_CMD_SET_RW(cmd, ISMT_DESC_CMD_RW_READ);
		}
		break;
	case SMBUS_OP_SEND_BYTE:
		cmd = ISMT_DESC_CMD_SET_RW(cmd, ISMT_DESC_CMD_RW_WRITE);
		cmd = ISMT_DESC_CMD_SET_CWRL(cmd, 1);
		cmd = ISMT_DESC_CMD_SET_WRLEN(cmd, req->smbr_wdata[0]);
		break;
	case SMBUS_OP_WRITE_BYTE:
		cmd = ISMT_DESC_CMD_SET_RW(cmd, ISMT_DESC_CMD_RW_WRITE);
		cmd = ISMT_DESC_CMD_SET_WRLEN(cmd, 2);
		data = true;
		buf[0] = req->smbr_cmd;
		buf[1] = req->smbr_wdata[0];
		break;
	case SMBUS_OP_WRITE_WORD:
		cmd = ISMT_DESC_CMD_SET_RW(cmd, ISMT_DESC_CMD_RW_WRITE);
		cmd = ISMT_DESC_CMD_SET_WRLEN(cmd, 3);
		data = true;
		buf[0] = req->smbr_cmd;
		buf[1] = req->smbr_wdata[0];
		buf[2] = req->smbr_wdata[1];
		break;
	case SMBUS_OP_WRITE_BLOCK:
		cmd = ISMT_DESC_CMD_SET_RW(cmd, ISMT_DESC_CMD_RW_WRITE);
		cmd = ISMT_DESC_CMD_SET_BLK(cmd, 1);
		VERIFY3U(req->smbr_wlen, <=, ISMT_MAX_SMBUS);
		cmd = ISMT_DESC_CMD_SET_WRLEN(cmd, req->smbr_wlen + 1);
		data = true;
		buf[0] = req->smbr_cmd;
		bcopy(req->smbr_wdata, &buf[1], req->smbr_wlen);
		break;
	case SMBUS_OP_I2C_WRITE_BLOCK:
		cmd = ISMT_DESC_CMD_SET_RW(cmd, ISMT_DESC_CMD_RW_WRITE);
		cmd = ISMT_DESC_CMD_SET_I2C(cmd, 1);
		VERIFY3U(req->smbr_wlen, >, 0);
		VERIFY3U(req->smbr_wlen, <=, ISMT_MAX_I2C);
		cmd = ISMT_DESC_CMD_SET_WRLEN(cmd, req->smbr_wlen + 1);
		data = true;
		buf[0] = req->smbr_cmd;
		bcopy(req->smbr_wdata, &buf[1], req->smbr_wlen);
		break;
	case SMBUS_OP_RECV_BYTE:
		cmd = ISMT_DESC_CMD_SET_RW(cmd, ISMT_DESC_CMD_RW_READ);
		cmd = ISMT_DESC_CMD_SET_RDLEN(cmd, 1);
		data = true;
		break;
	case SMBUS_OP_READ_BYTE:
		cmd = ISMT_DESC_CMD_SET_RW(cmd, ISMT_DESC_CMD_RW_READ);
		cmd = ISMT_DESC_CMD_SET_CWRL(cmd, 1);
		cmd = ISMT_DESC_CMD_SET_WRLEN(cmd, req->smbr_cmd);
		cmd = ISMT_DESC_CMD_SET_RDLEN(cmd, 1);
		data = true;
		break;
	case SMBUS_OP_READ_WORD:
		cmd = ISMT_DESC_CMD_SET_RW(cmd, ISMT_DESC_CMD_RW_READ);
		cmd = ISMT_DESC_CMD_SET_CWRL(cmd, 1);
		cmd = ISMT_DESC_CMD_SET_WRLEN(cmd, req->smbr_cmd);
		cmd = ISMT_DESC_CMD_SET_RDLEN(cmd, 2);
		data = true;
		break;
	case SMBUS_OP_READ_BLOCK:
		cmd = ISMT_DESC_CMD_SET_RW(cmd, ISMT_DESC_CMD_RW_READ);
		cmd = ISMT_DESC_CMD_SET_BLK(cmd, 1);
		cmd = ISMT_DESC_CMD_SET_CWRL(cmd, 1);
		cmd = ISMT_DESC_CMD_SET_WRLEN(cmd, req->smbr_cmd);
		VERIFY3U(req->smbr_rlen, >, 0);
		VERIFY3U(req->smbr_rlen, <=, ISMT_MAX_SMBUS);
		cmd = ISMT_DESC_CMD_SET_RDLEN(cmd, req->smbr_rlen + 1);
		data = true;
		break;
	case SMBUS_OP_I2C_READ_BLOCK:
		cmd = ISMT_DESC_CMD_SET_RW(cmd, ISMT_DESC_CMD_RW_READ);
		cmd = ISMT_DESC_CMD_SET_I2C(cmd, 1);
		cmd = ISMT_DESC_CMD_SET_CWRL(cmd, 1);
		cmd = ISMT_DESC_CMD_SET_WRLEN(cmd, req->smbr_cmd);
		VERIFY3U(req->smbr_rlen, >, 0);
		VERIFY3U(req->smbr_rlen, <=, ISMT_MAX_I2C);
		cmd = ISMT_DESC_CMD_SET_RDLEN(cmd, req->smbr_rlen);
		data = true;
		break;
	case SMBUS_OP_PROCESS_CALL:
		cmd = ISMT_DESC_CMD_SET_RW(cmd, ISMT_DESC_CMD_RW_WRITE);
		cmd = ISMT_DESC_CMD_SET_WRLEN(cmd, 3);
		cmd = ISMT_DESC_CMD_SET_RDLEN(cmd, 2);
		data = true;
		buf[0] = req->smbr_cmd;
		buf[1] = req->smbr_wdata[0];
		buf[2] = req->smbr_wdata[1];
		break;
	case SMBUS_OP_BLOCK_PROCESS_CALL:
		cmd = ISMT_DESC_CMD_SET_RW(cmd, ISMT_DESC_CMD_RW_WRITE);
		cmd = ISMT_DESC_CMD_SET_WRLEN(cmd, req->smbr_wlen + 1);
		cmd = ISMT_DESC_CMD_SET_RDLEN(cmd, req->smbr_rlen + 1);
		data = true;
		buf[0] = req->smbr_cmd;
		bcopy(req->smbr_wdata, &buf[1], req->smbr_wlen);
		break;
	/*
	 * As the datasheets don't have a way to directly run the U32/U64
	 * operations, we allow our translation layer to take care of it.
	 */
	case SMBUS_OP_READ_U32:
	case SMBUS_OP_READ_U64:
	case SMBUS_OP_WRITE_U32:
	case SMBUS_OP_WRITE_U64:
	case SMBUS_OP_HOST_NOTIFY:
	default:
		dev_err(ismt->ismt_dip, CE_WARN, "!framework passed "
		    "unsupported SMBus command 0x%x", req->smbr_op);
		i2c_ctrl_io_error(&req->smbr_error, I2C_CORE_E_CONTROLLER,
		    I2C_CTRL_E_UNSUP_CMD);
		goto done;

	}

	ismt_io_cmd_submit(ismt, cmd, data);
done:
	ismt->ismt_req = NULL;
	ismt->ismt_i2creq = NULL;
	ismt->ismt_err = NULL;
	ismt->ismt_req_done = false;
	mutex_exit(&ismt->ismt_mutex);
}

static void
ismt_io_i2c(void *arg, uint32_t port, i2c_req_t *req)
{
	ismt_t *ismt = arg;
	uint8_t *buf;
	uint32_t cmd;
	bool data = false;

	mutex_enter(&ismt->ismt_mutex);
	ismt_io_reset(ismt);
	ismt->ismt_i2creq = req;
	ismt->ismt_err = &req->ir_error;

	buf = (uint8_t *)ismt->ismt_data_dma.id_va;

	/*
	 * I2C Commands are required to always set the I2C bit and we must never
	 * set the block bit. The remaining flags and set up depend on whether
	 * we're doing a write, a read, or a write folowed by a read.
	 */
	ismt_io_cmd_init(&req->ir_addr, &cmd);
	cmd = ISMT_DESC_CMD_SET_I2C(cmd, 1);
	cmd = ISMT_DESC_CMD_SET_BLK(cmd, 0);

	if (req->ir_rlen > 0) {
		cmd = ISMT_DESC_CMD_SET_RW(cmd, ISMT_DESC_CMD_RW_READ);
		VERIFY3U(req->ir_rlen, <, ISMT_MAX_I2C);
		data = true;
		cmd = ISMT_DESC_CMD_SET_RDLEN(cmd, req->ir_rlen);
	}

	if (req->ir_wlen > 0) {
		cmd = ISMT_DESC_CMD_SET_RW(cmd, ISMT_DESC_CMD_RW_WRITE);

		/*
		 * The datasheet tells us that if we have a 1 byte write, we
		 * need to set C/WRL and it will encode the data byte. Otherwise
		 * we use the normal write length.
		 */
		if (req->ir_wlen == 1) {
			cmd = ISMT_DESC_CMD_SET_CWRL(cmd, 1);
			cmd = ISMT_DESC_CMD_SET_WRLEN(cmd, req->ir_wdata[0]);
		} else {
			VERIFY3U(req->ir_wlen, >, 0);
			VERIFY3U(req->ir_wlen, <, ISMT_MAX_I2C);
			cmd = ISMT_DESC_CMD_SET_WRLEN(cmd, req->ir_wlen);
			data = true;
			bcopy(req->ir_wdata, buf, req->ir_wlen);
		}
	}

	ismt_io_cmd_submit(ismt, cmd, data);

	ismt->ismt_req = NULL;
	ismt->ismt_i2creq = NULL;
	ismt->ismt_req_done = false;
	mutex_exit(&ismt->ismt_mutex);
}

static const i2c_ctrl_ops_t ismt_ctrl_ops = {
	.i2c_port_name_f = i2c_ctrl_port_name_portno,
	.i2c_io_i2c_f = ismt_io_i2c,
	.i2c_io_smbus_f = ismt_io_smbus,
	.i2c_prop_info_f = ismt_prop_info,
	.i2c_prop_get_f = ismt_prop_get
};

static bool
ismt_setup_regs(ismt_t *ismt)
{
	int ret;
	ddi_device_acc_attr_t attr;

	bzero(&attr, sizeof (attr));
	attr.devacc_attr_version = DDI_DEVICE_ATTR_V1;
	attr.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
	attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;
	attr.devacc_attr_access = DDI_DEFAULT_ACC;

	if (ddi_dev_regsize(ismt->ismt_dip, ISMT_REGNO, &ismt->ismt_regsize) !=
	    DDI_SUCCESS) {
		dev_err(ismt->ismt_dip, CE_WARN, "failed to get regs[%u] size",
		    ISMT_REGNO);
		return (false);
	}

	ret = ddi_regs_map_setup(ismt->ismt_dip, ISMT_REGNO, &ismt->ismt_base,
	    0, ismt->ismt_regsize, &attr, &ismt->ismt_regs);
	if (ret != DDI_SUCCESS) {
		dev_err(ismt->ismt_dip, CE_WARN, "failed to map regs[%u]: %u",
		    ISMT_REGNO, ret);
		return (false);
	}

	ismt->ismt_init |= ISMT_INIT_REGS;
	return (true);
}

static void
ismt_dma_free(ismt_dma_t *dma)
{
	/* Proxy for DMA handle bound */
	if (dma->id_size != 0) {
		(void) ddi_dma_unbind_handle(dma->id_hdl);
		dma->id_size = 0;
	}

	if (dma->id_acc != NULL) {
		ddi_dma_mem_free(&dma->id_acc);
		dma->id_acc = NULL;
		dma->id_va = NULL;
		dma->id_alloc_len = 0;
	}

	if (dma->id_hdl != NULL) {
		ddi_dma_free_handle(&dma->id_hdl);
		dma->id_hdl = NULL;
	}

	ASSERT0(dma->id_size);
	ASSERT0(dma->id_alloc_len);
	ASSERT3P(dma->id_acc, ==, NULL);
	ASSERT3P(dma->id_hdl, ==, NULL);
	ASSERT3P(dma->id_va, ==, NULL);
}

static bool
ismt_dma_alloc(ismt_t *ismt, ismt_dma_t *dma, size_t size)
{
	int ret;
	ddi_device_acc_attr_t acc;
	uint_t flags = DDI_DMA_CONSISTENT;

	bzero(dma, sizeof (ismt_dma_t));
	ret = ddi_dma_alloc_handle(ismt->ismt_dip, &ismt_dma_attr,
	    DDI_DMA_SLEEP, NULL, &dma->id_hdl);
	if (ret != DDI_SUCCESS) {
		dev_err(ismt->ismt_dip, CE_WARN, "!failed to allocate DMA "
		    "handle: %d", ret);
		return (false);
	}

	bzero(&acc, sizeof (acc));
	acc.devacc_attr_version = DDI_DEVICE_ATTR_V1;
	acc.devacc_attr_endian_flags = DDI_NEVERSWAP_ACC;
	acc.devacc_attr_dataorder = DDI_STRICTORDER_ACC;
	acc.devacc_attr_access = DDI_DEFAULT_ACC;
	ret = ddi_dma_mem_alloc(dma->id_hdl, size, &acc, flags,
	    DDI_DMA_SLEEP, NULL, &dma->id_va, &dma->id_alloc_len,
	    &dma->id_acc);
	if (ret != DDI_SUCCESS) {
		dev_err(ismt->ismt_dip, CE_WARN, "!failed to allocate %lu "
		    "bytes of DMA memory: %d", size, ret);
		ismt_dma_free(dma);
		return (false);
	}

	bzero(dma->id_va, dma->id_alloc_len);
	ret = ddi_dma_addr_bind_handle(dma->id_hdl, NULL, dma->id_va,
	    dma->id_alloc_len, DDI_DMA_RDWR | flags, DDI_DMA_DONTWAIT, NULL,
	    NULL, NULL);
	if (ret != DDI_SUCCESS) {
		dev_err(ismt->ismt_dip, CE_WARN, "!failed to bind %lu bytes of "
		    "DMA memory: %d", dma->id_alloc_len, ret);
		ismt_dma_free(dma);
		return (false);
	}

	dma->id_size = size;
	return (true);
}

static bool
ismt_alloc_intr(ismt_t *ismt)
{
	int ret, types;

	ret = ddi_intr_get_supported_types(ismt->ismt_dip, &types);
	if (ret != DDI_SUCCESS) {
		dev_err(ismt->ismt_dip, CE_WARN, "failed to get supproted "
		    "interrupt types: 0x%d", ret);
		return (false);
	}

	/*
	 * We only expect hardware to support MSIs and INTx.
	 */
	if ((types & DDI_INTR_TYPE_MSI) != 0) {
		ret = ddi_intr_alloc(ismt->ismt_dip, &ismt->ismt_intr_hdl,
		    DDI_INTR_TYPE_MSI, 0, 1, &ismt->ismt_nintrs,
		    DDI_INTR_ALLOC_STRICT);
		if (ret == DDI_SUCCESS) {
			ismt->ismt_itype = DDI_INTR_TYPE_MSI;
			return (true);
		}
		dev_err(ismt->ismt_dip, CE_WARN, "!failed to allocate MSI "
		    "interrupt");
	}

	if ((types & DDI_INTR_TYPE_FIXED) != 0) {
		ret = ddi_intr_alloc(ismt->ismt_dip, &ismt->ismt_intr_hdl,
		    DDI_INTR_TYPE_MSI, 0, 1, &ismt->ismt_nintrs,
		    DDI_INTR_ALLOC_STRICT);
		if (ret == DDI_SUCCESS) {
			ismt->ismt_itype = DDI_INTR_TYPE_FIXED;
			return (true);
		}
		dev_err(ismt->ismt_dip, CE_WARN, "!failed to allocate INTx "
		    "interrupt");
	}

	dev_err(ismt->ismt_dip, CE_WARN, "failed to allocate any interrupts "
	    "from type 0x%x", types);
	return (false);
}

static bool
ismt_setup_intr(ismt_t *ismt)
{
	int ret = ddi_intr_add_handler(ismt->ismt_intr_hdl, ismt_intr, ismt,
	    NULL);
	if (ret != DDI_SUCCESS) {
		dev_err(ismt->ismt_dip, CE_WARN, "failed to add interrupt "
		    "handler: 0x%x", ret);
		return (false);
	}
	ismt->ismt_init |= ISMT_INIT_INTR_HDL;

	ret = ddi_intr_get_pri(ismt->ismt_intr_hdl, &ismt->ismt_intr_pri);
	if (ret != DDI_SUCCESS) {
		dev_err(ismt->ismt_dip, CE_WARN, "failed to get interrupt "
		    "priority");
		return (false);
	}

	return (true);
}

/*
 * Go through and set up hardware for use. We need to explicitly take care of:
 *
 *  - The Interrupt Cause Log
 *  - The Controller DMA ring
 *  - Firmware Head and Tail Registers
 *  - Enabling generation of interrupts
 *
 * We use the hardwar defaults for the device retry policy.
 */
static void
ismt_ctrl_init(ismt_t *ismt)
{
	uint32_t val;
	const ddi_dma_cookie_t *c;

	c = ddi_dma_cookie_one(ismt->ismt_icl_dma.id_hdl);
	ismt_write64(ismt, ISMT_R_SMTICL, c->dmac_laddress);

	c = ddi_dma_cookie_one(ismt->ismt_ring_dma.id_hdl);
	ismt_write64(ismt, ISMT_R_MDBA, c->dmac_laddress);

	val = ISMT_R_MDS_SET_SIZE(0, ISMT_RING_NENTS - 1);
	ismt_write32(ismt, ISMT_R_MDS, val);

	val = ISMT_R_MCTRL_SET_FMHP(0, 0);
	val = ISMT_R_MCTRL_SET_MEIE(val, 1);
	ismt_write32(ismt, ISMT_R_MCTRL, val);

	val = ISMT_R_MSTS_SET_HMTP(0, 0);
	ismt_write32(ismt, ISMT_R_MSTS, val);

	ismt->ismt_head = ismt->ismt_tail = 0;
	ismt->ismt_ring = (ismt_desc_t *)ismt->ismt_ring_dma.id_va;

	val = ismt_read32(ismt, ISMT_R_SPGT);
	switch (ISMT_R_SPGT_GET_SPD(val)) {
	case ISMT_R_SPT_SPD_80K:
	case ISMT_R_SPT_SPD_100K:
		ismt->ismt_speed = I2C_SPEED_STD;
		break;
	case ISMT_R_SPT_SPD_400K:
		ismt->ismt_speed = I2C_SPEED_FAST;
		break;
	case ISMT_R_SPT_SPD_1M:
		ismt->ismt_speed = I2C_SPEED_FPLUS;
		break;
	}
}

static bool
ismt_enable_intr(ismt_t *ismt)
{
	int ret = ddi_intr_enable(ismt->ismt_intr_hdl);
	if (ret != DDI_SUCCESS) {
		dev_err(ismt->ismt_dip, CE_WARN, "failed to enable interrupt "
		    "handler: %d", ret);
		return (false);
	}

	ismt->ismt_init |= ISMT_INIT_INTR_EN;
	return (true);
}

static bool
ismt_register(ismt_t *ismt)
{
	i2c_ctrl_reg_error_t ret;
	i2c_ctrl_register_t *reg;

	ret = i2c_ctrl_register_alloc(I2C_CTRL_PROVIDER, &reg);
	if (ret != 0) {
		dev_err(ismt->ismt_dip, CE_WARN, "failed to allocate i2c "
		    "controller registration structure: 0x%x", ret);
		return (false);
	}

	reg->ic_type = I2C_CTRL_TYPE_SMBUS;
	reg->ic_nports = 1;
	reg->ic_dip = ismt->ismt_dip;
	reg->ic_drv = ismt;
	reg->ic_ops = &ismt_ctrl_ops;

	ret = i2c_ctrl_register(reg, &ismt->ismt_hdl);
	i2c_ctrl_register_free(reg);
	if (ret != 0) {
		dev_err(ismt->ismt_dip, CE_WARN, "failed to register with i2c "
		    "framework: 0x%x", ret);
		return (false);
	}
	ismt->ismt_init |= ISMT_INIT_I2C;

	return (true);
}

static void
ismt_cleanup(ismt_t *ismt)
{
	if ((ismt->ismt_init & ISMT_INIT_INTR_EN) != 0) {
		/*
		 * If this fails while tearing down, there isn't much we can do.
		 */
		int ret = ddi_intr_disable(ismt->ismt_intr_hdl);
		if (ret != DDI_SUCCESS) {
			dev_err(ismt->ismt_dip, CE_WARN, "failed to disable "
			    "interrupt handler: %d", ret);
		}

		ismt->ismt_init &= ~ISMT_INIT_INTR_EN;
	}

	if ((ismt->ismt_init & ISMT_INIT_SYNC) != 0) {
		cv_destroy(&ismt->ismt_cv);
		mutex_destroy(&ismt->ismt_mutex);
		ismt->ismt_init &= ~ISMT_INIT_SYNC;
	}

	if ((ismt->ismt_init & ISMT_INIT_INTR_HDL) != 0) {
		int ret = ddi_intr_remove_handler(ismt->ismt_intr_hdl);
		if (ret != 0) {
			dev_err(ismt->ismt_dip, CE_WARN, "failed to remove "
			    "interrupt handler: 0x%x", ret);
		}
		ismt->ismt_init &= ~ISMT_INIT_INTR_HDL;
	}
	if ((ismt->ismt_init & ISMT_INIT_INTR_ALLOC) != 0) {
		int ret = ddi_intr_free(ismt->ismt_intr_hdl);
		if (ret != DDI_SUCCESS) {
			dev_err(ismt->ismt_dip, CE_WARN, "failed to free "
			    "device interrupt: 0x%x", ret);
		}

		ismt->ismt_init &= ~ISMT_INIT_INTR_ALLOC;
	}

	ismt_dma_free(&ismt->ismt_icl_dma);
	ismt_dma_free(&ismt->ismt_data_dma);
	ismt_dma_free(&ismt->ismt_ring_dma);

	if ((ismt->ismt_init & ISMT_INIT_REGS) != 0) {
		ddi_regs_map_free(&ismt->ismt_regs);
		ismt->ismt_regs = NULL;
		ismt->ismt_regsize = 0;
		ismt->ismt_init &= ~ISMT_INIT_REGS;
	}

	if ((ismt->ismt_init & ISMT_INIT_PCI) != 0) {
		pci_config_teardown(&ismt->ismt_cfg);
		ismt->ismt_cfg = NULL;
		ismt->ismt_init &= ~ISMT_INIT_PCI;
	}

	ASSERT0(ismt->ismt_init);
	ddi_set_driver_private(ismt->ismt_dip, NULL);
	kmem_free(ismt, sizeof (ismt_t));
}

int
ismt_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	ismt_t *ismt;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
	default:
		return (DDI_FAILURE);
	}

	ismt = kmem_zalloc(sizeof (ismt_t), KM_SLEEP);
	ismt->ismt_dip = dip;
	ddi_set_driver_private(dip, ismt);

	if (pci_config_setup(dip, &ismt->ismt_cfg) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "failed to set up config space");
		goto cleanup;
	}
	ismt->ismt_init |= ISMT_INIT_PCI;

	if (!ismt_setup_regs(ismt))
		goto cleanup;

	if (!ismt_dma_alloc(ismt, &ismt->ismt_ring_dma, ISMT_RING_DMA_SIZE)) {
		dev_err(dip, CE_WARN, "failed to allocate ring DMA memory");
		goto cleanup;
	}

	if (!ismt_dma_alloc(ismt, &ismt->ismt_data_dma, ISMT_DATA_BUF_SIZE)) {
		dev_err(dip, CE_WARN, "failed to allocate data buffer DMA "
		    "memory");
		goto cleanup;
	}

	if (!ismt_dma_alloc(ismt, &ismt->ismt_icl_dma, ISMT_ICL_DMA_SIZE)) {
		dev_err(dip, CE_WARN, "failed to allocate interrupt cause DMA "
		    "memory");
		goto cleanup;
	}

	if (!ismt_alloc_intr(ismt))
		goto cleanup;
	ismt->ismt_init |= ISMT_INIT_INTR_ALLOC;

	if (!ismt_setup_intr(ismt))
		goto cleanup;

	mutex_init(&ismt->ismt_mutex, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(ismt->ismt_intr_pri));
	cv_init(&ismt->ismt_cv, NULL, CV_DRIVER, NULL);
	ismt->ismt_init |= ISMT_INIT_SYNC;

	ismt_ctrl_init(ismt);

	if (!ismt_enable_intr(ismt))
		goto cleanup;

	if (!ismt_register(ismt))
		goto cleanup;

	return (DDI_SUCCESS);

cleanup:
	ismt_cleanup(ismt);
	return (DDI_FAILURE);
}

int
ismt_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	ismt_t *ismt;

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
	default:
		return (DDI_FAILURE);
	}

	ismt = ddi_get_driver_private(dip);
	if (ismt == NULL) {
		dev_err(dip, CE_WARN, "asked to detach, but missing private "
		    "data");
		return (DDI_FAILURE);
	}

	VERIFY3P(ismt->ismt_dip, ==, dip);
	i2c_ctrl_reg_error_t ret = i2c_ctrl_unregister(ismt->ismt_hdl);
	if (ret != 0) {
		dev_err(dip, CE_WARN, "failed to unregister from i2c "
		    "framework 0x%x", ret);
		return (DDI_FAILURE);
	}
	ismt->ismt_init &= ~ISMT_INIT_I2C;
	ismt_cleanup(ismt);

	return (DDI_SUCCESS);
}

static struct dev_ops ismt_dev_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_identify = nulldev,
	.devo_probe = nulldev,
	.devo_attach = ismt_attach,
	.devo_detach = ismt_detach,
	.devo_reset = nodev,
	.devo_quiesce = ddi_quiesce_not_supported,
};

static struct modldrv ismt_modldrv = {
	.drv_modops = &mod_driverops,
	.drv_linkinfo = "Intel SMBus Message Target",
	.drv_dev_ops = &ismt_dev_ops
};

static struct modlinkage ismt_modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &ismt_modldrv, NULL }
};

int
_init(void)
{
	int ret;

	i2c_ctrl_mod_init(&ismt_dev_ops);
	if ((ret = mod_install(&ismt_modlinkage)) != 0) {
		i2c_ctrl_mod_fini(&ismt_dev_ops);
	}

	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&ismt_modlinkage, modinfop));
}

int
_fini(void)
{
	int ret;

	if ((ret = mod_remove(&ismt_modlinkage)) == 0) {
		i2c_ctrl_mod_fini(&ismt_dev_ops);
	}

	return (ret);
}
