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
 * Intel PCH (ICH) SMBus Controller
 *
 * This driver supports a wide variety of controllers, having been found in
 * various Intel chipsets since the late 1990s. The hardware has evolved a
 * little bit, but it is a controller that only supports SMBus 2.0 and a little
 * bit of I2C emulation to support EEPROMs that fit in a single address byte. It
 * cannot run arbitrary I2C commands.
 *
 * As a result, the hardware interface is structured around issuing specific
 * SMBus commands and operations. For non-block based commands this is
 * straightforward. Unfortunately, for block commands it is less simple. In the
 * hardware's evolution, support for a block buffer was added. Prior to this one
 * has to read and write a single byte at a time. With this, one can instead use
 * the 32-byte buffer for transactions. Notably, 32 bytes comes from the SMBus
 * 2.0 block limit.
 *
 * While this 32-byte buffer is a great simplifying thing, it actually doesn't
 * work with I2C emulation and therefore we have to do per-byte I/Os in the
 * device. Because I2C block I/Os are much more common than SMBus, this means
 * that the block buffer flag, like the I2C flag, are enabled on a per-request
 * basis.
 *
 * When operating in the byte mode, we basically track how many bytes there are
 * to transmit and receive and will issue all transmit bytes before any repeated
 * start that requires reading.
 */

#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/pci.h>
#include <sys/sysmacros.h>

#include <sys/i2c/controller.h>
#include "pchsmbus.h"

/*
 * The controller only has a single BAR which contains what we need. This may be
 * in I/O space or MMIO space, but which it is doesn't make a difference to the
 * driver itself.
 */
#define	PCHSMBUS_REGNO	1

typedef enum {
	PCHSMBUS_INIT_PCI		= 1 << 0,
	PCHSMBUS_INIT_REGS		= 1 << 1,
	PCHSMBUS_INIT_INTR_ALLOC	= 1 << 2,
	PCHSMBUS_INIT_INTR_HDL		= 1 << 3,
	PCHSMBUS_INIT_SYNC		= 1 << 4,
	PCHSMBUS_INIT_CTRL		= 1 << 5,
	PCHSMBUS_INIT_INTR_EN		= 1 << 6,
	PCHSMBUS_INIT_I2C		= 1 << 7,
	/*
	 * The following are used at run time.
	 */
	PCHSMBUS_RUN_BUF_EN		= 1 << 8,
	PCHSMBUS_RUN_I2C_EN		= 1 << 9
} pchsmbus_init_t;

typedef struct {
	dev_info_t *ps_dip;
	ddi_acc_handle_t ps_cfg;
	pchsmbus_init_t ps_init;
	pch_smbus_feat_t ps_feats;
	/*
	 * Register related data
	 */
	caddr_t ps_base;
	off_t ps_regsize;
	ddi_acc_handle_t ps_regs;
	uint32_t ps_init_hcfg;
	uint8_t ps_init_hctl;
	uint8_t ps_init_scmd;
	/*
	 * Interrupt data
	 */
	int ps_nintrs;
	ddi_intr_handle_t ps_intr_hdl;
	uint_t ps_intr_pri;
	/*
	 * Request and framework synchronization
	 */
	kmutex_t ps_mutex;
	kcondvar_t ps_cv;
	i2c_ctrl_hdl_t *ps_hdl;
	smbus_req_t *ps_req;
	uint16_t ps_req_off;
	uint8_t ps_req_hctl;
	bool ps_req_done;
	i2c_ctrl_error_t ps_kill_err;
} pchsmbus_t;

typedef struct {
	uint16_t pcm_did;
	pch_smbus_feat_t pcm_feat;
} pchsmbus_hw_map_t;

static const pchsmbus_hw_map_t pchsmbus_feats[] = {
	{ PCH_SMBUS_ICH0_82801AA, 0 },
	{ PCH_SMBUS_ICH0_82901AB, 0 },
	{ PCH_SMBUS_ICH2_82801BA, PCH_SMBUS_FEAT_TARG },
	{ PCH_SMBUS_ICH3_82801CA, PCH_SMBUS_FEAT_ALL_ICH3 },
	{ PCH_SMBUS_ICH4_82801DB, PCH_SMBUS_FEAT_ALL_ICH4 },
	{ PCH_SMBUS_ICH5_82801Ex, PCH_SMBUS_FEAT_ALL_ICH5 },
	{ PCH_SMBUS_6300ESB, PCH_SMBUS_FEAT_ALL_ICH5 },
	{ PCH_SMBUS_ICH6, PCH_SMBUS_FEAT_ALL_ICH5 },
	{ PCH_SMBUS_631xESB, PCH_SMBUS_FEAT_ALL_ICH5 },
	{ PCH_SMBUS_ICH7, PCH_SMBUS_FEAT_ALL_ICH5 },
	{ PCH_SMBUS_ICH8, PCH_SMBUS_FEAT_ALL_ICH8 },
	{ PCH_SMBUS_ICH9, PCH_SMBUS_FEAT_ALL_ICH8 },
	{ PCH_SMBUS_ICH10_CORP, PCH_SMBUS_FEAT_ALL_ICH8 },
	{ PCH_SMBUS_ICH10_USER, PCH_SMBUS_FEAT_ALL_ICH8 },
	{ PCH_SMBUS_PCH5, PCH_SMBUS_FEAT_ALL_ICH8 },
	{ PCH_SMBUS_C600, PCH_SMBUS_FEAT_ALL_ICH8 },
	{ PCH_SMBUS_C600_SMB0, PCH_SMBUS_FEAT_ALL_ICH8 },
	{ PCH_SMBUS_C600_SMB1, PCH_SMBUS_FEAT_ALL_ICH8 },
	{ PCH_SMBUS_C600_SMB2, PCH_SMBUS_FEAT_ALL_ICH8 },
	{ PCH_SMBUS_DH89xxCC, PCH_SMBUS_FEAT_ALL_ICH8 },
	{ PCH_SMBUS_DH89xxCL, PCH_SMBUS_FEAT_ALL_ICH8 },
	{ PCH_SMBUS_PCH6, PCH_SMBUS_FEAT_ALL_ICH8 },
	{ PCH_SMBUS_PCH7, PCH_SMBUS_FEAT_ALL_ICH8 },
	{ PCH_SMBUS_PCH8, PCH_SMBUS_FEAT_ALL_ICH8 },
	{ PCH_SMBUS_PCH8_LP, PCH_SMBUS_FEAT_ALL_ICH8 },
	{ PCH_SMBUS_C610, PCH_SMBUS_FEAT_ALL_ICH8 },
	{ PCH_SMBUS_C610_MS0, PCH_SMBUS_FEAT_ALL_ICH8 },
	{ PCH_SMBUS_C610_MS1, PCH_SMBUS_FEAT_ALL_ICH8 },
	{ PCH_SMBUS_C610_MS2, PCH_SMBUS_FEAT_ALL_ICH8 },
	{ PCH_SMBUS_PCH9, PCH_SMBUS_FEAT_ALL_ICH8 },
	{ PCH_SMBUS_PCH9_LP, PCH_SMBUS_FEAT_ALL_ICH8 },
	{ PCH_SMBUS_BAYTRAIL, PCH_SMBUS_FEAT_ALL_ICH8 },
	{ PCH_SMBUS_100, PCH_SMBUS_FEAT_ALL_ICH8 },
	{ PCH_SMBUS_DENVERTON, PCH_SMBUS_FEAT_ALL_ICH8 },
	{ PCH_SMBUS_C740, PCH_SMBUS_FEAT_ALL_ICH8 },
	{ PCH_SMBUS_APOLLO, PCH_SMBUS_FEAT_ALL_ICH8 },
	{ PCH_SMBUS_200, PCH_SMBUS_FEAT_ALL_ICH8 },
	{ PCH_SMBUS_GEMINI, PCH_SMBUS_FEAT_ALL_ICH8 },
	{ PCH_SMBUS_C620, PCH_SMBUS_FEAT_ALL_ICH8 },
	{ PCH_SMBUS_C620_SUPER, PCH_SMBUS_FEAT_ALL_ICH8 },
	{ PCH_SMBUS_300, PCH_SMBUS_FEAT_ALL_ICH8 },
	{ PCH_SMBUS_ICE_LAKE_D, PCH_SMBUS_FEAT_ALL_ICH8 },
	{ PCH_SMBUS_495_PKG, PCH_SMBUS_FEAT_ALL_ICH8 },
	{ PCH_SMBUS_400, PCH_SMBUS_FEAT_ALL_ICH8 },
	{ PCH_SMBUS_400_PKG, PCH_SMBUS_FEAT_ALL_ICH8 },
	{ PCH_SMBUS_ELKHART, PCH_SMBUS_FEAT_ALL_ICH8 },
	{ PCH_SMBUS_500, PCH_SMBUS_FEAT_ALL_ICH8 },
	{ PCH_SMBUS_500_PKG, PCH_SMBUS_FEAT_ALL_ICH8 },
	{ PCH_SMBUS_JASPER, PCH_SMBUS_FEAT_ALL_ICH8 },
	{ PCH_SMBUS_600, PCH_SMBUS_FEAT_ALL_ICH8 },
	{ PCH_SMBUS_600_PKG, PCH_SMBUS_FEAT_ALL_ICH8 },
	{ PCH_SMBUS_800, PCH_SMBUS_FEAT_ALL_ICH8 },
	{ PCH_SMBUS_METEOR_PS, PCH_SMBUS_FEAT_ALL_ICH8 },
	{ PCH_SMBUS_PANTHER_H, PCH_SMBUS_FEAT_ALL_ICH8 },
	{ PCH_SMBUS_PANTHER_P, PCH_SMBUS_FEAT_ALL_ICH8 }
};

static uint8_t
pchsmbus_read8(pchsmbus_t *pch, uint8_t regno)
{
	ASSERT3U(regno, <, pch->ps_regsize);

	return (ddi_get8(pch->ps_regs, (uint8_t *)(pch->ps_base + regno)));
}

static void
pchsmbus_write8(pchsmbus_t *pch, uint8_t regno, uint8_t val)
{
	ASSERT3U(regno, <, pch->ps_regsize);

	ddi_put8(pch->ps_regs, (uint8_t *)(pch->ps_base + regno), val);
}

static i2c_errno_t
pchsmbus_prop_info(void *arg, i2c_prop_t prop, i2c_prop_info_t *info)
{
	switch (prop) {
	case I2C_PROP_BUS_SPEED:
		i2c_prop_info_set_def_u32(info, I2C_SPEED_STD);
		i2c_prop_info_set_pos_bit32(info, I2C_SPEED_STD);
		break;
	case SMBUS_PROP_SUP_OPS:
	case SMBUS_PROP_MAX_BLOCK:
		break;
	default:
		return (I2C_PROP_E_UNSUP);
	}

	/*
	 * We can't set any timing properties or the speed really, so we
	 * indicate that all properties are read-only.
	 */
	i2c_prop_info_set_perm(info, I2C_PROP_PERM_RO);

	return (I2C_CORE_E_OK);
}

static i2c_errno_t
pchsmbus_prop_get(void *arg, i2c_prop_t prop, void *buf, size_t buflen)
{
	uint32_t val;

	switch (prop) {
	case I2C_PROP_BUS_SPEED:
		val = I2C_SPEED_STD;
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
	case SMBUS_PROP_MAX_BLOCK:
		val = SMBUS_V2_MAX_BLOCK;
		break;
	default:
		return (I2C_PROP_E_UNSUP);
	}

	VERIFY3U(buflen, >=, sizeof (val));
	bcopy(&val, buf, sizeof (val));
	return (I2C_CORE_E_OK);
}

static bool
pchsmbus_bus_avail(pchsmbus_t *pch)
{
	const uint32_t count = i2c_ctrl_timeout_count(pch->ps_hdl,
	    I2C_CTRL_TO_BUS_ACT);
	const uint32_t wait = i2c_ctrl_timeout_delay_us(pch->ps_hdl,
	    I2C_CTRL_TO_BUS_ACT);

	for (uint32_t i = 0; i < count; i++) {
		uint8_t hsts = pchsmbus_read8(pch, PCH_R_BAR_HSTS);
		if ((hsts & PCH_HSTS_BUSY) == 0) {
			return (true);
		}

		delay(drv_usectohz(wait));
	}

	dev_err(pch->ps_dip, CE_WARN, "controller timed out waiting for "
	    "bus activity to cease");
	return (false);
}

static void
pchsmbus_set_addr(pchsmbus_t *pch, const smbus_req_t *req, bool write)
{
	uint8_t addr = 0;
	uint8_t wbit = write ? PCH_R_TSA_RW_WRITE : PCH_R_TSA_RW_READ;


	ASSERT3U(req->smbr_addr.ia_type, ==, I2C_ADDR_7BIT);
	addr = PCH_R_TSA_SET_ADDR(addr, req->smbr_addr.ia_addr);
	addr = PCH_R_TSA_SET_RW(addr, wbit);
	pchsmbus_write8(pch, PCH_R_BAR_TSA, addr);
}

static pch_smbus_cmd_t
pchsmbus_req_to_cmd(const smbus_req_t *req)
{
	switch (req->smbr_op) {
	case SMBUS_OP_QUICK_COMMAND:
		return (PCH_SMBUS_CMD_QUICK);
	case SMBUS_OP_SEND_BYTE:
	case SMBUS_OP_RECV_BYTE:
		return (PCH_SMBUS_CMD_BYTE);
	case SMBUS_OP_WRITE_BYTE:
	case SMBUS_OP_READ_BYTE:
		return (PCH_SMBUS_CMD_BYTE_DATA);
	case SMBUS_OP_WRITE_WORD:
	case SMBUS_OP_READ_WORD:
		return (PCH_SMBUS_CMD_WORD_DATA);
	case SMBUS_OP_WRITE_BLOCK:
	case SMBUS_OP_READ_BLOCK:
	case SMBUS_OP_I2C_WRITE_BLOCK:
		return (PCH_SMBUS_CMD_BLOCK);
	case SMBUS_OP_PROCESS_CALL:
		return (PCH_SMBUS_CMD_PROC_CALL);
	case SMBUS_OP_BLOCK_PROCESS_CALL:
		return (PCH_SMBUS_CMD_BLOCK_PROC);
	case SMBUS_OP_I2C_READ_BLOCK:
		return (PCH_SMBUS_CMD_I2C_READ);
	default:
		panic("asked to translate unexpected request type: 0x%x",
		    req->smbr_op);
	}
}

/*
 * Initialize a block request. These are the most complicated requests to deal
 * with because of the different variations. There are two modes of operation: a
 * 32 byte buffer that we can use to just take care of the operation in one shot
 * or a single byte at a time operation. Most hardware supports the 32 byte
 * buffer; however, when performing an I2C read or write, it must operate in
 * byte at a time mode.
 *
 * We also need to update the controller registers. This means specifically:
 *
 *  - Enabling I2C mode specifically for I2C block writes. This is not required
 *    for I2C block reads which have their own dedicated command in the
 *    controller.
 *  - Enabling the 32-byte buffer for block reads when it's supported in
 *    hardware. This cannot be done for I2C operations and must be done for
 *    block procedure calls. We will not advertise support for block procedure
 *    calls to the framework if they are not supported in hardware.
 *
 * Note, regardless of whether this is the 'i2c' form or not, we are going to
 * end up issuing the 'command' register. When doing an i2c block read, the
 * controller will issue a repeated start and do the transition to a read.
 */
static void
pchsmbus_io_init_block(pchsmbus_t *pch, const smbus_req_t *req)
{
	bool write, want_buf = false, want_i2c = false;

	switch (req->smbr_op) {
	case SMBUS_OP_WRITE_BLOCK:
	case SMBUS_OP_BLOCK_PROCESS_CALL:
		want_buf = true;
		write = true;
		break;
	case SMBUS_OP_READ_BLOCK:
		want_buf = true;
		write = false;
		break;
	case SMBUS_OP_I2C_WRITE_BLOCK:
		write = true;
		want_buf = false;
		/*
		 * This is the only operation that requires an explicit I2C
		 * enable. This causes us to skip sending the byte count. This
		 * isn't required for the I2C Read Block operation because it's
		 * just part of the controller's semantics.
		 */
		want_i2c = true;
		break;
	case SMBUS_OP_I2C_READ_BLOCK:
		/*
		 * Yes, this seems on the face an oxymoron. The reason for this
		 * is buried in the datasheets (though some are inconsistent).
		 * When issuing an I2C block read we first are going to do a
		 * write with a byte and then issue a repeated start with a
		 * read. The first thing we do will be a write, hence we set
		 * this.
		 *
		 * However, this gets more nuanced. There exists the SPD write
		 * disable bit which was added in the PCH7 generation. When this
		 * is set, this needs to be false. This is likely why some
		 * chipsets after this generation say this should always be
		 * treated as a read (i.e. Ice Lake-D); however, this is also
		 * contradicted by other devices between PCH7 and Ice Lake such
		 * as the 100/200-series chipsets. A right mess, isn't it?
		 */
		write = PCH_R_HCFG_GET_SPDWD(pch->ps_init_hcfg) == 0;
		break;
	default:
		panic("programmer error: not a block type: 0x%x\n",
		    req->smbr_op);
	}

	if ((pch->ps_feats & PCH_SMBUS_FEAT_32B_BUF) == 0)
		want_buf = false;

	VERIFY(!(want_i2c && want_buf));
	if (want_i2c) {
		uint32_t val = pci_config_get32(pch->ps_cfg, PCH_R_PCIE_HCFG);
		val = PCH_R_HCFG_SET_I2CEN(val, 1);
		pci_config_put32(pch->ps_cfg, PCH_R_PCIE_HCFG, val);
		pch->ps_init |= PCHSMBUS_RUN_I2C_EN;
	}

	if (want_buf) {
		uint8_t val = pchsmbus_read8(pch, PCH_R_BAR_AUXC);
		val = PCH_R_AUXC_SET_E32B(val, 1);
		pchsmbus_write8(pch, PCH_R_BAR_AUXC, val);
		pch->ps_init |= PCHSMBUS_RUN_BUF_EN;
	}

	/*
	 * All operations get the address and the command register set. Though
	 * of course the I2C Block read actually doesn't use the command
	 * register and instead uses the data 1 register for it.
	 */
	pchsmbus_set_addr(pch, req, write);
	if (req->smbr_op == SMBUS_OP_I2C_READ_BLOCK) {
		pchsmbus_write8(pch, PCH_R_BAR_HD1, req->smbr_cmd);
	} else {
		pchsmbus_write8(pch, PCH_R_BAR_HCMD, req->smbr_cmd);
	}

	/*
	 * If this is a read command, there is nothing else to do. For the
	 * various write types we must actually write the data in question.
	 */
	if (req->smbr_op == SMBUS_OP_I2C_READ_BLOCK || SMBUS_OP_READ_BLOCK) {
		return;
	}

	/*
	 * For all writes, regardless of length, indicate how many bytes are in
	 * the transaction.
	 */
	pchsmbus_write8(pch, PCH_R_BAR_HD0, req->smbr_wlen);
	uint16_t wlen = req->smbr_wlen;
	if (!want_buf) {
		wlen = 1;
	}

	/*
	 * Explicitly reset the index into the buffer. This is a nop if we're
	 * not using the buffer.
	 */
	(void) pchsmbus_read8(pch, PCH_R_BAR_HCTL);
	for (uint16_t i = 0; i < wlen; i++, pch->ps_req_off++) {
		pchsmbus_write8(pch, PCH_R_BAR_HBD, req->smbr_wdata[i]);
	}
}

/*
 * We have one of three different general classes of errors that we need to
 * prioritize and synthesize into useful errors upstack. We treat them in the
 * following order:
 *
 * 1) The FAIL error takes priority as this is set due to a request by us to
 *    abort the error. The driver sets the appropriate error to use in our
 *    device structure before issuing this.
 * 2) The Bus Error indicates that something went wrong on the bus itself. The
 *    datasheet says it's a general transaction collision or a bus arbitration
 *    loss. We always translate that into I2C_CTRL_E_ARB_LOST.
 * 3) The device error is a combination of different possibilities. The most
 *    common case is getting no acknowledgement. However, this can also happen
 *    because the driver requests an illegal command, a PEC error occurs, or we
 *    exceed the 25 ms SMBus timeout. This is definitely unfortunate, but we
 *    basically just stick to the unknown I2C_CTRL_E_NACK.
 */
static void
pchsmbus_io_error(pchsmbus_t *pch, pch_smbus_sts_t status)
{
	i2c_ctrl_error_t err;

	if ((status & PCH_HSTS_FAIL) != 0) {
		ASSERT3U(pch->ps_kill_err, !=, I2C_CTRL_E_OK);
		err = pch->ps_kill_err;
	} else if ((status & PCH_HSTS_BUS_ERR)) {
		err = I2C_CTRL_E_ARB_LOST;
	} else {
		err = I2C_CTRL_E_NACK;
	}

	i2c_ctrl_io_error(&pch->ps_req->smbr_error, I2C_CORE_E_CONTROLLER,
	    err);
	pch->ps_req_done = true;
}

/*
 * We have received a byte done callback. This means that we're either
 * performing a read or write. The controller does not support performing both
 * without the buffer enabled.
 *
 * If we are writing, we need to write the next byte into the buffer. If there
 * is any more.
 *
 * If we are reading, we need to read the next byte out of the buffer. It the
 * subsequent byte (the one after we just read) would be the last one, then we
 * need to indicate to the controller that this it will be the last byte. When
 * executing an SMBus block read, the data length is not known in advance.
 *
 * In both cases, reading or writing all bytes is not indicating of completing
 * the command. The controller explicitly sets the INTR status bit for that.
 */
static void
pchsmbus_io_byte_done(pchsmbus_t *pch)
{
	ASSERT(MUTEX_HELD(&pch->ps_mutex));
	ASSERT3U(pch->ps_init & PCHSMBUS_RUN_BUF_EN, ==, 0);
	ASSERT3P(pch->ps_req, !=, NULL);

	if (pch->ps_req->smbr_op == SMBUS_OP_WRITE_BLOCK ||
	    pch->ps_req->smbr_op == SMBUS_OP_I2C_WRITE_BLOCK) {
		if (pch->ps_req_off < pch->ps_req->smbr_wlen) {
			pchsmbus_write8(pch, PCH_R_BAR_HBD,
			    pch->ps_req->smbr_wdata[pch->ps_req_off]);
			pch->ps_req_off++;
		}
		return;
	}

	/*
	 * I2C block reads already know the size that they care about. However,
	 * normal SMBus block reads have it in their first byte, which will be
	 * in the HD0 register, not the HDB register like normal data.
	 */
	if (pch->ps_req->smbr_rlen == 0) {
		ASSERT3U(pch->ps_req->smbr_op, ==, SMBUS_OP_READ_BLOCK);

		uint8_t len = pchsmbus_read8(pch, PCH_R_BAR_HD0);
		if (len == 0 || len > SMBUS_V2_MAX_BLOCK) {
			pch->ps_kill_err = I2C_CTRL_E_BAD_SMBUS_RLEN;
			uint8_t val = PCH_R_HCTL_SET_KILL(0, 1);
			pchsmbus_write8(pch, PCH_R_BAR_HCTL, val);
			return;
		}
		pch->ps_req->smbr_rlen = len;
		return;
	}

	pch->ps_req->smbr_rdata[pch->ps_req_off] = pchsmbus_read8(pch,
	    PCH_R_BAR_HBD);
	pch->ps_req_off++;
	if (pch->ps_req_off + 1 == pch->ps_req->smbr_rlen) {
		uint8_t hctl = PCH_R_HCTL_SET_LAST(pch->ps_req_hctl, 1);
		pchsmbus_write8(pch, PCH_R_BAR_HCTL, hctl);
	}
}

/*
 * We've been told that the request completed successfully. The action that we
 * must take will vary based upon the type of request. Here is where we read out
 * result data. For writes, we're simply done. Note, for block requests, we will
 * have already processed it if we're not operating in block mode.
 */
static void
pchsmbus_io_req_done(pchsmbus_t *pch)
{
	uint8_t len;

	pch->ps_req_done = true;
	switch (pch->ps_req->smbr_op) {
	case SMBUS_OP_QUICK_COMMAND:
	case SMBUS_OP_SEND_BYTE:
	case SMBUS_OP_WRITE_BYTE:
	case SMBUS_OP_WRITE_WORD:
	case SMBUS_OP_WRITE_BLOCK:
	case SMBUS_OP_I2C_WRITE_BLOCK:
		/*
		 * There is nothing to do for all write requests.
		 */
		break;
	case SMBUS_OP_RECV_BYTE:
	case SMBUS_OP_READ_BYTE:
		pch->ps_req->smbr_rdata[0] = pchsmbus_read8(pch, PCH_R_BAR_HD0);
		break;
	case SMBUS_OP_READ_WORD:
	case SMBUS_OP_PROCESS_CALL:
		pch->ps_req->smbr_rdata[0] = pchsmbus_read8(pch, PCH_R_BAR_HD0);
		pch->ps_req->smbr_rdata[1] = pchsmbus_read8(pch, PCH_R_BAR_HD1);
		break;
	case SMBUS_OP_READ_BLOCK:
	case SMBUS_OP_BLOCK_PROCESS_CALL:
	case SMBUS_OP_I2C_READ_BLOCK:
		/*
		 * Byte mode already has all of its data.
		 */
		if ((pch->ps_init & PCHSMBUS_RUN_BUF_EN) == 0) {
			break;
		}

		len = pchsmbus_read8(pch, PCH_R_BAR_HD0);
		if (len == 0 || len > SMBUS_V2_MAX_BLOCK) {
			i2c_ctrl_io_error(&pch->ps_req->smbr_error,
			    I2C_CORE_E_CONTROLLER,
			    I2C_CTRL_E_BAD_SMBUS_RLEN);
			return;
		}

		pch->ps_req->smbr_rlen = len;
		/* Explicitly reset the buffer index */
		(void) pchsmbus_read8(pch, PCH_R_BAR_HCTL);
		for (uint16_t i = 0; i < pch->ps_req->smbr_rlen; i++) {
			pch->ps_req->smbr_rdata[i] = pchsmbus_read8(pch,
			    PCH_R_BAR_HBD);
		}
		break;
	case SMBUS_OP_HOST_NOTIFY:
	case SMBUS_OP_WRITE_U32:
	case SMBUS_OP_READ_U32:
	case SMBUS_OP_WRITE_U64:
	case SMBUS_OP_READ_U64:
	default:
		panic("programmer error: unsupported request type 0x%x should "
		    "not have been completed", pch->ps_req->smbr_op);
	}

	i2c_ctrl_io_success(&pch->ps_req->smbr_error);
}

/*
 * We have been given a status register read from the driver, whether by polling
 * or by an interrupt. We must look at the bits present, clear anything that
 * needs to be, and then take action to advance the state machine. Here's how we
 * have to react to each bit:
 *
 *  - Byte Done: This indicates a byte has been transferred when we're not in
 *    the 32 byte buffer mode. At this time, we either write the next byte or
 *    read the next byte out of the buffer.
 *  - Alert: This shouldn't be generated, so we generally ignore it, but clear
 *    it just for completeness.
 *  - Fail, Bus Error, Device Error: The transaction is over. We need to guess
 *    the best error that we can with the unfortunately limited information that
 *    we get.
 *  - Interrupt: This indicates that the entire command was completed and is the
 *    only thing that we should use to signal successful completion.
 */
static bool
pchsmbus_io(pchsmbus_t *pch, pch_smbus_sts_t status)
{
	ASSERT(MUTEX_HELD(&pch->ps_mutex));

	/*
	 * Is there actually activity for us to process or not. If not, then
	 * we're done. Mask off bits like In Use and related. Clear them now and
	 * proceed to process them all in turn.
	 */
	status &= PCH_HSTS_CLEAR_PRE;
	if (status == 0) {
		return (false);
	}

	if ((status & PCH_HSTS_ERRORS) != 0) {
		pchsmbus_io_error(pch, status);
		goto done;
	}

	if ((status & PCH_HSTS_BYTE_DONE) != 0) {
		pchsmbus_io_byte_done(pch);
	}

	if ((status & PCH_HSTS_INTR) != 0) {
		pchsmbus_io_req_done(pch);
	}

done:
	/*
	 * We clear the status codes last as when operating in byte at a time
	 * mode, the data must be read and written prior to clearing this status
	 * to indicate that we are done.
	 */
	pchsmbus_write8(pch, PCH_R_BAR_HSTS, status);
	return (true);
}

static uint_t
pchsmbus_intr(caddr_t arg1, caddr_t arg2)
{
	pchsmbus_t *pch = (pchsmbus_t *)arg1;
	pch_smbus_sts_t sts;

	mutex_enter(&pch->ps_mutex);
	sts = pchsmbus_read8(pch, PCH_R_BAR_HSTS);
	if (!pchsmbus_io(pch, sts)) {
		mutex_exit(&pch->ps_mutex);
		return (DDI_INTR_UNCLAIMED);
	}

	if (pch->ps_req_done) {
		cv_signal(&pch->ps_cv);
	}
	mutex_exit(&pch->ps_mutex);
	return (DDI_INTR_CLAIMED);
}

static void
pchsmbus_wait(pchsmbus_t *pch, bool poll)
{
	uint32_t to, spin;

	VERIFY(MUTEX_HELD(&pch->ps_mutex));
	VERIFY3P(pch->ps_req, !=, NULL);

	to = i2c_ctrl_timeout_delay_us(pch->ps_hdl, I2C_CTRL_TO_IO);
	spin = i2c_ctrl_timeout_delay_us(pch->ps_hdl, I2C_CTRL_TO_POLL_CTRL);

	if (!poll) {
		clock_t abs = ddi_get_lbolt() + drv_usectohz(to);
		while (!pch->ps_req_done) {
			clock_t ret = cv_timedwait(&pch->ps_cv, &pch->ps_mutex,
			    abs);
			if (ret == -1) {
				break;
			}
		}
	} else {
		hrtime_t abs = gethrtime() + USEC2NSEC(to);

		while (!pch->ps_req_done && gethrtime() < abs) {
			drv_usecwait(spin);
			uint8_t status = pchsmbus_read8(pch, PCH_R_BAR_HSTS);
			(void) pchsmbus_io(pch, status);
		}
	}

	/*
	 * If this is not done, we're going to set the kill bit. The next user
	 * will be the one that waits for the kill to actually complete with the
	 * normal call to pchsmbus_bus_avail(). The FAIL status in the HSTS
	 * register will get cleared before the next transaction begins and the
	 * HCTL KILL bit will be cleared when we issue the next command.
	 */
	if (!pch->ps_req_done) {
		uint8_t val = PCH_R_HCTL_SET_KILL(0, 1);
		pchsmbus_write8(pch, PCH_R_BAR_HCTL, val);
		i2c_ctrl_io_error(&pch->ps_req->smbr_error,
		    I2C_CORE_E_CONTROLLER, I2C_CTRL_E_REQ_TO);
		pch->ps_req_done = true;
	}
}

static void
pchsmbus_io_smbus(void *arg, uint32_t port, smbus_req_t *req)
{
	bool poll;
	pchsmbus_t *pch = arg;

	ASSERT3U(port, ==, 0);

	mutex_enter(&pch->ps_mutex);
	if (!pchsmbus_bus_avail(pch)) {
		mutex_exit(&pch->ps_mutex);
		i2c_ctrl_io_error(&req->smbr_error, I2C_CORE_E_CONTROLLER,
		    I2C_CTRL_E_BUS_BUSY);
		return;
	}

	ASSERT3P(pch->ps_req, ==, NULL);
	pch->ps_req = req;
	pch->ps_req_off = 0;
	pch->ps_req_done = false;

	/*
	 * Determine whether or not we should use interrupts or poll for
	 * completion. We may have been asked to poll explicitly. We may also
	 * not have interrupt support.
	 */
	poll = (req->smbr_flags & I2C_IO_REQ_F_POLL) != 0;
	if (pch->ps_nintrs == 0)
		poll = true;

	switch (req->smbr_op) {
	case SMBUS_OP_QUICK_COMMAND:
		pchsmbus_set_addr(pch, req, (req->smbr_flags &
		    I2C_IO_REQ_F_QUICK_WRITE) != 0);
		break;
	case SMBUS_OP_SEND_BYTE:
		pchsmbus_set_addr(pch, req, true);
		pchsmbus_write8(pch, PCH_R_BAR_HCMD, req->smbr_wdata[0]);
		break;
	case SMBUS_OP_WRITE_BYTE:
		pchsmbus_set_addr(pch, req, true);
		pchsmbus_write8(pch, PCH_R_BAR_HCMD, req->smbr_cmd);
		pchsmbus_write8(pch, PCH_R_BAR_HD0, req->smbr_wdata[0]);
		break;
	case SMBUS_OP_WRITE_WORD:
	case SMBUS_OP_PROCESS_CALL:
		pchsmbus_set_addr(pch, req, true);
		pchsmbus_write8(pch, PCH_R_BAR_HCMD, req->smbr_cmd);
		pchsmbus_write8(pch, PCH_R_BAR_HD0, req->smbr_wdata[0]);
		pchsmbus_write8(pch, PCH_R_BAR_HD1, req->smbr_wdata[1]);
		break;
	case SMBUS_OP_RECV_BYTE:
		pchsmbus_set_addr(pch, req, false);
		break;
	case SMBUS_OP_READ_BYTE:
	case SMBUS_OP_READ_WORD:
		pchsmbus_set_addr(pch, req, false);
		pchsmbus_write8(pch, PCH_R_BAR_HCMD, req->smbr_cmd);
		break;
	case SMBUS_OP_WRITE_BLOCK:
	case SMBUS_OP_BLOCK_PROCESS_CALL:
	case SMBUS_OP_READ_BLOCK:
	case SMBUS_OP_I2C_WRITE_BLOCK:
	case SMBUS_OP_I2C_READ_BLOCK:
		pchsmbus_io_init_block(pch, req);
		break;
	case SMBUS_OP_HOST_NOTIFY:
	case SMBUS_OP_WRITE_U32:
	case SMBUS_OP_READ_U32:
	case SMBUS_OP_WRITE_U64:
	case SMBUS_OP_READ_U64:
	default:
		dev_err(pch->ps_dip, CE_WARN, "!framework passed unsupported "
		    "SMBus command 0x%x", req->smbr_op);
		i2c_ctrl_io_error(&req->smbr_error, I2C_CORE_E_CONTROLLER,
		    I2C_CTRL_E_UNSUP_CMD);
		goto done;
	}

	/*
	 * Prepare to issue the command. We do this in a few different steps:
	 *
	 * 1) We set up command-specific parameters such as I2C enable. If the
	 *    block enable is present, then it will have been already enabled.
	 * 2) Clear all interrupts.
	 * 3) Actually begin the transaction, indicating whether or not
	 *    interrupts should occur.
	 * 4) Poll or wait for completion.
	 */
	pchsmbus_write8(pch, PCH_R_BAR_HSTS, PCH_HSTS_CLEAR_PRE);
	pch_smbus_cmd_t cmd = pchsmbus_req_to_cmd(req);
	uint8_t ctl = PCH_R_HCTL_SET_CMD(0, cmd);
	ctl = PCH_R_HCTL_SET_START(ctl, 1);
	ctl = PCH_R_HCTL_SET_INT_EN(ctl, !poll);
	pchsmbus_write8(pch, PCH_R_BAR_HCTL, ctl);
	pch->ps_req_hctl = ctl;

	pchsmbus_wait(pch, poll);

done:
	/*
	 * Now that this operation has completed, whether successful or not,
	 * restore the host configuration and block enable to our defaults.
	 */
	if ((pch->ps_init & PCHSMBUS_RUN_I2C_EN) != 0) {
		uint32_t val = pci_config_get32(pch->ps_cfg, PCH_R_PCIE_HCFG);
		val = PCH_R_HCFG_SET_I2CEN(val, 0);
		pci_config_put32(pch->ps_cfg, PCH_R_PCIE_HCFG, val);
		pch->ps_init &= ~PCHSMBUS_RUN_I2C_EN;
	}

	if ((pch->ps_init & PCHSMBUS_RUN_BUF_EN) != 0) {
		uint8_t val = pchsmbus_read8(pch, PCH_R_BAR_AUXC);
		val = PCH_R_AUXC_SET_E32B(val, 0);
		pchsmbus_write8(pch, PCH_R_BAR_AUXC, val);
		pch->ps_init &= ~PCHSMBUS_RUN_BUF_EN;
	}

	pch->ps_req = NULL;
	pch->ps_req_off = 0;
	pch->ps_req_hctl = 0;
	pch->ps_req_done = false;
	pch->ps_kill_err = I2C_CTRL_E_OK;
	mutex_exit(&pch->ps_mutex);
}

static const i2c_ctrl_ops_t pchsmbus_ctrl_ops = {
	.i2c_port_name_f = i2c_ctrl_port_name_portno,
	.i2c_io_smbus_f = pchsmbus_io_smbus,
	.i2c_prop_info_f = pchsmbus_prop_info,
	.i2c_prop_get_f = pchsmbus_prop_get
};

static bool
pchsmbus_supported(pchsmbus_t *pch)
{
	uint16_t id = pci_config_get16(pch->ps_cfg, PCI_CONF_VENID);

	if (id != PCH_SMBUS_VID_INTEL) {
		dev_err(pch->ps_dip, CE_WARN, "found unsupported non-Intel "
		    "vendor ID: 0x%x", id);
		return (false);
	}

	id = pci_config_get16(pch->ps_cfg, PCI_CONF_DEVID);
	for (size_t i = 0; i < ARRAY_SIZE(pchsmbus_feats); i++) {
		if (id != pchsmbus_feats[i].pcm_did)
			continue;

		pch->ps_feats = pchsmbus_feats[i].pcm_feat;
		return (true);
	}

	dev_err(pch->ps_dip, CE_WARN, "found unsupported device ID: 0x%x", id);
	return (false);
}

static bool
pchsmbus_setup_regs(pchsmbus_t *pch)
{
	int ret;
	ddi_device_acc_attr_t attr;

	bzero(&attr, sizeof (attr));
	attr.devacc_attr_version = DDI_DEVICE_ATTR_V1;
	attr.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
	attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;
	attr.devacc_attr_access = DDI_DEFAULT_ACC;

	if (ddi_dev_regsize(pch->ps_dip, PCHSMBUS_REGNO, &pch->ps_regsize) !=
	    DDI_SUCCESS) {
		dev_err(pch->ps_dip, CE_WARN, "failed to get regs[%u] size",
		    PCHSMBUS_REGNO);
		return (false);
	}

	ret = ddi_regs_map_setup(pch->ps_dip, PCHSMBUS_REGNO, &pch->ps_base,
	    0, pch->ps_regsize, &attr, &pch->ps_regs);
	if (ret != DDI_SUCCESS) {
		dev_err(pch->ps_dip, CE_WARN, "failed to map regs[%u]: %u",
		    PCHSMBUS_REGNO, ret);
		return (false);
	}

	pch->ps_init |= PCHSMBUS_INIT_REGS;
	return (true);
}

/*
 * Go ahead and set up interrupts. It is possible that we don't get access to
 * interrupts because firmware has enabled it to be delivered via a #SMI. If
 * that's the case, we will just always rely on polling. Because that is the
 * nature of this hardware, we treat the failure to detect interrupts as
 * non-fatal, but if we find one and cannot actually set it up, we will fail
 * then.
 */
static bool
pchsmbus_setup_intr(pchsmbus_t *pch)
{
	int types, ret;

	pch->ps_nintrs = 0;
	pch->ps_intr_pri = 0;

	/*
	 * If the SMI enable flag is set, that means that firmware is on the
	 * scene and we will just need to poll for completion rather than
	 * assuming we get interrupts. That's fine. Why it means that they won't
	 * fight us for the controller despite that is a deeper mystery.
	 */
	if (PCH_R_HCFG_GET_SMI_EN(pch->ps_init_hcfg) != 0) {
		dev_err(pch->ps_dip, CE_WARN, "!firmware has taken our "
		    "interrupt for itself via #SMI; limiting to polling");
		return (true);
	}

	ret = ddi_intr_get_supported_types(pch->ps_dip, &types);
	if (ret != DDI_SUCCESS) {
		dev_err(pch->ps_dip, CE_WARN, "failed to get supported "
		    "interrupt types: 0x%x; limiting to polling", ret);
		return (true);
	}

	/*
	 * Hardware only supports INTx style fixed interrupts. That hasn't
	 * changed in 25 years of hardware. If we don't find a fixed interrupt
	 * that's that.
	 */
	if ((types & DDI_INTR_TYPE_FIXED) == 0) {
		dev_err(pch->ps_dip, CE_WARN, "missing support for fixed "
		    "interrupts: found 0x%x; limiting to polling", types);
		return (true);
	}

	ret = ddi_intr_alloc(pch->ps_dip, &pch->ps_intr_hdl,
	    DDI_INTR_TYPE_FIXED, 0, 1, &pch->ps_nintrs, DDI_INTR_ALLOC_STRICT);
	if (ret != DDI_SUCCESS) {
		dev_err(pch->ps_dip, CE_WARN, "failed to allocate "
		    "interrupts: 0x%x", ret);
		return (false);
	}
	pch->ps_init |= PCHSMBUS_INIT_INTR_ALLOC;

	ret = ddi_intr_add_handler(pch->ps_intr_hdl, pchsmbus_intr, pch, NULL);
	if (ret != DDI_SUCCESS) {
		dev_err(pch->ps_dip, CE_WARN, "failed to add interrupt "
		    "handler: 0x%x", ret);
		return (false);
	}
	pch->ps_init |= PCHSMBUS_INIT_INTR_HDL;

	ret = ddi_intr_get_pri(pch->ps_intr_hdl, &pch->ps_intr_pri);
	if (ret != DDI_SUCCESS) {
		dev_err(pch->ps_dip, CE_WARN, "failed to get interrupt "
		    "priority");
		return (false);
	}

	return (true);
}

/*
 * Go through and set up the controller for general use. In particular, there
 * are a few things that we go through and make sure are set in a way that makes
 * sense for us:
 *
 *  - We always disable automatic PEC. The Auxiliary 32 byte buffer control will
 *    be enabled when it can be used.
 *  - We disable any events that can be generated by the target.
 *  - We make sure that SMBus timing is enabled by default.
 *  - Ensure that interrupts are disabled and that the PEC feature is not set.
 *    Interrupts will be enabled when we actually enable commands.
 *  - We actually enable the controller.
 */
static void
pchsmbus_ctrl_init(pchsmbus_t *pch)
{
	if ((pch->ps_feats & PCH_SMBUS_FEAT_HW_PEC) != 0) {
		uint8_t val = pchsmbus_read8(pch, PCH_R_BAR_AUXC);
		val = PCH_R_AUXC_SET_AAC(val, 0);
		pchsmbus_write8(pch, PCH_R_BAR_AUXC, val);
	}

	if ((pch->ps_feats & PCH_SMBUS_FEAT_TARG_NOTIFY) != 0) {
		pch->ps_init_scmd = pchsmbus_read8(pch, PCH_R_BAR_SCMD);

		uint8_t val = PCH_R_SCMD_SET_SMB_D(pch->ps_init_scmd, 1);
		val = PCH_R_SCMD_SET_HNI(val, 0);
		pchsmbus_write8(pch, PCH_R_BAR_SCMD, 0);
	}

	/*
	 * Save the initial control register to restore later. However, don't
	 * save the kill bit which stops transactions. At this point, make sure
	 * interrupts and related activity are all disabled.
	 */
	pch->ps_init_hctl = pchsmbus_read8(pch, PCH_R_BAR_HCTL);
	pch->ps_init_hctl = PCH_R_HCTL_SET_KILL(pch->ps_init_hctl, 0);
	pchsmbus_write8(pch, PCH_R_BAR_HCTL, 0);

	uint32_t val = pch->ps_init_hcfg;
	val = PCH_R_HCFG_SET_EN(val, 1);
	val = PCH_R_HCFG_SET_I2CEN(val, PCH_R_HCFG_I2CEN_SMBUS);
	pci_config_put32(pch->ps_cfg, PCH_R_PCIE_HCFG, val);

	pch->ps_init |= PCHSMBUS_INIT_CTRL;
}

static bool
pchsmbus_enable_intr(pchsmbus_t *pch)
{
	int ret = ddi_intr_enable(pch->ps_intr_hdl);
	if (ret != DDI_SUCCESS) {
		dev_err(pch->ps_dip, CE_WARN, "failed to enable interrupt "
		    "handler: %d", ret);
		return (false);
	}

	pch->ps_init |= PCHSMBUS_INIT_INTR_EN;
	return (true);
}

static bool
pchsmbus_register(pchsmbus_t *pch)
{
	i2c_ctrl_reg_error_t ret;
	i2c_ctrl_register_t *reg;

	ret = i2c_ctrl_register_alloc(I2C_CTRL_PROVIDER, &reg);
	if (ret != 0) {
		dev_err(pch->ps_dip, CE_WARN, "failed to allocate i2c "
		    "controller registration structure: 0x%x", ret);
		return (false);
	}

	reg->ic_type = I2C_CTRL_TYPE_SMBUS;
	reg->ic_nports = 1;
	reg->ic_dip = pch->ps_dip;
	reg->ic_drv = pch;
	reg->ic_ops = &pchsmbus_ctrl_ops;

	ret = i2c_ctrl_register(reg, &pch->ps_hdl);
	i2c_ctrl_register_free(reg);
	if (ret != 0) {
		dev_err(pch->ps_dip, CE_WARN, "failed to register with i2c "
		    "framework: 0x%x", ret);
		return (false);
	}

	pch->ps_init |= PCHSMBUS_INIT_I2C;
	return (true);
}

static void
pchsmbus_cleanup(pchsmbus_t *pch)
{
	if ((pch->ps_init & PCHSMBUS_INIT_INTR_EN) != 0) {
		/*
		 * If this fails while tearing down, there isn't much we can do.
		 */
		int ret = ddi_intr_disable(pch->ps_intr_hdl);
		if (ret != DDI_SUCCESS) {
			dev_err(pch->ps_dip, CE_WARN, "failed to disable "
			    "interrupt handler: %d", ret);
		}
		pch->ps_init &= ~PCHSMBUS_INIT_INTR_EN;
	}

	/*
	 * We restore several of the controllers original values as the BIOS may
	 * use this device and can rely on it.
	 */
	if ((pch->ps_init & PCHSMBUS_INIT_CTRL) != 0) {
		if ((pch->ps_feats & PCH_SMBUS_FEAT_TARG_NOTIFY) != 0) {
			pchsmbus_write8(pch, PCH_R_BAR_SCMD, pch->ps_init_scmd);
		}

		pchsmbus_write8(pch, PCH_R_BAR_HCTL, pch->ps_init_hctl);
		pci_config_put32(pch->ps_cfg, PCH_R_PCIE_HCFG,
		    pch->ps_init_hcfg);
		pch->ps_init &= ~PCHSMBUS_INIT_CTRL;
	}

	if ((pch->ps_init & PCHSMBUS_INIT_SYNC) != 0) {
		cv_destroy(&pch->ps_cv);
		mutex_destroy(&pch->ps_mutex);
		pch->ps_init &= ~PCHSMBUS_INIT_SYNC;
	}

	if ((pch->ps_init & PCHSMBUS_INIT_INTR_HDL) != 0) {
		int ret = ddi_intr_remove_handler(pch->ps_intr_hdl);
		if (ret != 0) {
			dev_err(pch->ps_dip, CE_WARN, "failed to remove "
			    "interrupt handler: 0x%x", ret);
		}
		pch->ps_init &= ~PCHSMBUS_INIT_INTR_HDL;
	}

	if ((pch->ps_init & PCHSMBUS_INIT_INTR_ALLOC) != 0) {
		int ret = ddi_intr_free(pch->ps_intr_hdl);
		if (ret != DDI_SUCCESS) {
			dev_err(pch->ps_dip, CE_WARN, "failed to free "
			    "device interrupt: 0x%x", ret);
		}
		pch->ps_init &= ~PCHSMBUS_INIT_INTR_ALLOC;
	}

	if ((pch->ps_init & PCHSMBUS_INIT_REGS) != 0) {
		ddi_regs_map_free(&pch->ps_regs);
		pch->ps_base = NULL;
		pch->ps_regsize = 0;
		pch->ps_init &= ~PCHSMBUS_INIT_REGS;
	}

	if ((pch->ps_init & PCHSMBUS_INIT_PCI) != 0) {
		pci_config_teardown(&pch->ps_cfg);
		pch->ps_cfg = NULL;
		pch->ps_init &= ~PCHSMBUS_INIT_PCI;
	}

	ASSERT0(pch->ps_init);
	ddi_set_driver_private(pch->ps_dip, NULL);
	kmem_free(pch, sizeof (pchsmbus_t));
}

int
pchsmbus_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	pchsmbus_t *pch;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
	default:
		return (DDI_FAILURE);
	}

	pch = kmem_zalloc(sizeof (pchsmbus_t), KM_SLEEP);
	pch->ps_dip = dip;
	ddi_set_driver_private(dip, pch);

	if (pci_config_setup(dip, &pch->ps_cfg) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "failed to set up config space");
		goto cleanup;
	}
	pch->ps_init |= PCHSMBUS_INIT_PCI;

	if (!pchsmbus_supported(pch))
		goto cleanup;

	if (!pchsmbus_setup_regs(pch))
		goto cleanup;

	/*
	 * Snapshot the original value of the host configuration register. This
	 * is something that some systems will restore on detach as sometimes
	 * firmware uses this controller. In addition, we need this to determine
	 * if we have interrupts available to us.
	 */
	pch->ps_init_hcfg = pci_config_get32(pch->ps_cfg, PCH_R_PCIE_HCFG);

	if (!pchsmbus_setup_intr(pch))
		goto cleanup;

	/*
	 * Now that we (potentially) have our interrupt. Go ahead and get our
	 * intrrupt and CV. If we don't have an interrupt this'll turn into a
	 * NULL.
	 */
	mutex_init(&pch->ps_mutex, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(pch->ps_intr_pri));
	cv_init(&pch->ps_cv, NULL, CV_DRIVER, NULL);
	pch->ps_init |= PCHSMBUS_INIT_SYNC;

	pchsmbus_ctrl_init(pch);

	if (!pchsmbus_enable_intr(pch))
		goto cleanup;

	if (!pchsmbus_register(pch))
		goto cleanup;

	return (DDI_SUCCESS);

cleanup:
	pchsmbus_cleanup(pch);
	return (DDI_FAILURE);
}

int
pchsmbus_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	pchsmbus_t *pch;

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
	default:
		return (DDI_FAILURE);
	}

	pch = ddi_get_driver_private(dip);
	if (pch == NULL) {
		dev_err(dip, CE_WARN, "asked to detach, but missing private "
		    "data");
		return (DDI_FAILURE);
	}

	VERIFY3P(pch->ps_dip, ==, dip);
	i2c_ctrl_reg_error_t ret = i2c_ctrl_unregister(pch->ps_hdl);
	if (ret != 0) {
		dev_err(dip, CE_WARN, "failed to unregister from i2c "
		    "framework 0x%x", ret);
		return (DDI_FAILURE);
	}
	pch->ps_init &= ~PCHSMBUS_INIT_I2C;
	pchsmbus_cleanup(pch);

	return (DDI_SUCCESS);
}

static struct dev_ops pchsmbus_dev_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_identify = nulldev,
	.devo_probe = nulldev,
	.devo_attach = pchsmbus_attach,
	.devo_detach = pchsmbus_detach,
	.devo_reset = nodev,
	.devo_quiesce = ddi_quiesce_not_supported,
};

static struct modldrv pchsmbus_modldrv = {
	.drv_modops = &mod_driverops,
	.drv_linkinfo = "Intel ICH/PCH SMBus Controller",
	.drv_dev_ops = &pchsmbus_dev_ops
};

static struct modlinkage pchsmbus_modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &pchsmbus_modldrv, NULL }
};

int
_init(void)
{
	int ret;

	i2c_ctrl_mod_init(&pchsmbus_dev_ops);
	if ((ret = mod_install(&pchsmbus_modlinkage)) != 0) {
		i2c_ctrl_mod_fini(&pchsmbus_dev_ops);
	}

	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&pchsmbus_modlinkage, modinfop));
}

int
_fini(void)
{
	int ret;

	if ((ret = mod_remove(&pchsmbus_modlinkage)) == 0) {
		i2c_ctrl_mod_fini(&pchsmbus_dev_ops);
	}

	return (ret);
}
