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
 * I/O related functions.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <endian.h>

#include "libi2c_impl.h"

void
i2c_io_req_fini(i2c_io_req_t *req)
{
	free(req);
}

bool
i2c_io_req_init(i2c_port_t *port, i2c_io_req_t **reqp)
{
	i2c_hdl_t *hdl = port->port_hdl;
	i2c_io_req_t *req;

	if (reqp == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid i2c_io_req_t output pointer: %p", reqp));
	}

	req = calloc(1, sizeof (i2c_io_req_t));
	if (req == NULL) {
		int e = errno;
		return (i2c_error(hdl, I2C_ERR_NO_MEM, e, "failed to allocate "
		    "memory for a new i2c_io_req_t"));
	}
	req->io_port = port;

	*reqp = req;
	return (i2c_success(hdl));
}

/*
 * Set the address for a request. Note that we don't care if the address is
 * reserved or not in the library. We ultimately leave that to the kernel.
 */
bool
i2c_io_req_set_addr(i2c_io_req_t *req, const i2c_addr_t *addr)
{
	i2c_hdl_t *hdl = req->io_port->port_hdl;

	if (addr == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid i2c_addr_t pointer: %p", addr));
	}

	if (!i2c_addr_validate(hdl, addr)) {
		return (false);
	}

	req->io_addr = *addr;
	req->io_addr_valid = true;
	return (i2c_success(hdl));
}

bool
i2c_io_req_set_transmit_data(i2c_io_req_t *req, const void *buf, size_t len)
{
	i2c_hdl_t *hdl = req->io_port->port_hdl;

	if (buf == NULL && len > 0) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "transmit "
		    "buffer cannot be a NULL pointer when the length is "
		    "non-zero (0x%zu)", len));
	} else if (buf != NULL && len == 0) {
		return (i2c_error(hdl, I2C_ERR_IO_WRITE_LEN_RANGE, 0,
		    "transmit data length cannot be zero when given a "
		    "non-NULL pointer " "(%p)", buf));
	} else if (len > I2C_REQ_MAX) {
		return (i2c_error(hdl, I2C_ERR_IO_WRITE_LEN_RANGE, 0, "cannot "
		    "transmit more than %zu bytes in a request, valid range is "
		    "[0x00, 0x%x]", len, I2C_REQ_MAX));
	}

	req->io_tx_len = len;
	req->io_tx_buf = buf;
	return (i2c_success(hdl));
}

bool
i2c_io_req_set_receive_buf(i2c_io_req_t *req, void *buf, size_t len)
{
	i2c_hdl_t *hdl = req->io_port->port_hdl;

	if (buf == NULL && len > 0) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "receive "
		    "buffer cannot be a NULL pointer when the length is "
		    "non-zero (0x%zu)", len));
	} else if (buf != NULL && len == 0) {
		return (i2c_error(hdl, I2C_ERR_IO_READ_LEN_RANGE, 0, "receive "
		    "data length cannot be zero when given a non-NULL pointer "
		    "(%p)", buf));
	} else if (len > I2C_REQ_MAX) {
		return (i2c_error(hdl, I2C_ERR_IO_READ_LEN_RANGE, 0, "cannot "
		    "receive more %zu bytes in a request, valid range is "
		    "[0x00, 0x%x]", len, I2C_REQ_MAX));
	}

	req->io_rx_len = len;
	req->io_rx_buf = buf;
	return (i2c_success(hdl));
}

bool
i2c_io_req_exec(i2c_io_req_t *req)
{
	i2c_hdl_t *hdl = req->io_port->port_hdl;
	i2c_req_t i2c;

	if (!req->io_addr_valid) {
		return (i2c_error(hdl, I2C_ERR_IO_REQ_MISSING_FIELDS, 0,
		    "cannot execute I/O request due to missing fields: "
		    "device address"));
	}

	if (req->io_tx_len == 0 && req->io_rx_len == 0) {
		return (i2c_error(hdl, I2C_ERR_IO_REQ_IO_INVALID, 0,
		    "I/O request invalid: no transmit or receive specified"));
	}

	(void) memset(&i2c, 0, sizeof (i2c_req_t));
	i2c.ir_addr = req->io_addr;
	i2c.ir_wlen = req->io_tx_len;
	i2c.ir_rlen = req->io_rx_len;
	if (i2c.ir_wlen > 0) {
		(void) memcpy(i2c.ir_wdata, req->io_tx_buf, req->io_tx_len);
	}

	if (ioctl(req->io_port->port_fd, UI2C_IOCTL_I2C_REQ, &i2c) != 0) {
		int e = errno;
		return (i2c_ioctl_syserror(hdl, e, "I2C I/O request"));
	}

	if (i2c.ir_error.i2c_error != I2C_CORE_E_OK) {
		return (i2c_ioctl_error(hdl, &i2c.ir_error, "I2C I/O request"));
	}

	if (i2c.ir_rlen > 0) {
		(void) memcpy(req->io_rx_buf, i2c.ir_rdata, req->io_rx_len);
	}

	return (i2c_success(hdl));
}

void
smbus_io_req_fini(smbus_io_req_t *req)
{
	free(req);
}


/*
 * Reset all I/O fields before we set something.
 */
static void
smbus_io_req_reset(smbus_io_req_t *req)
{
	req->sir_op_valid = false;
	req->sir_op = UINT32_MAX;
	req->sir_flags = 0;
	req->sir_cmd = 0;
	req->sir_write = 0;
	req->sir_writep = NULL;
	req->sir_wlen = 0;
	req->sir_rlen = 0;
}

bool
smbus_io_req_init(i2c_port_t *port, smbus_io_req_t **reqp)
{
	i2c_hdl_t *hdl = port->port_hdl;
	smbus_io_req_t *req;

	if (reqp == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid smbus_io_req_t output pointer: %p", reqp));
	}

	req = calloc(1, sizeof (smbus_io_req_t));
	if (req == NULL) {
		int e = errno;
		return (i2c_error(hdl, I2C_ERR_NO_MEM, e, "failed to allocate "
		    "memory for a new smbus_io_req_t"));
	}
	req->sir_port = port;
	smbus_io_req_reset(req);

	*reqp = req;
	return (i2c_success(hdl));
}

bool
smbus_io_req_set_addr(smbus_io_req_t *req, const i2c_addr_t *addr)
{
	i2c_hdl_t *hdl = req->sir_port->port_hdl;

	if (addr == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid i2c_addr_t pointer: %p", addr));
	}

	if (!i2c_addr_validate(hdl, addr)) {
		return (false);
	}

	req->sir_addr = *addr;
	req->sir_addr_valid = true;
	return (i2c_success(hdl));
}

bool
smbus_io_req_set_quick_cmd(smbus_io_req_t *req, bool write)
{
	smbus_io_req_reset(req);
	req->sir_op_valid = true;
	req->sir_op = SMBUS_OP_QUICK_COMMAND;
	req->sir_flags = write ? I2C_IO_REQ_F_QUICK_WRITE : 0;

	return (i2c_success(req->sir_port->port_hdl));
}

bool
smbus_io_req_set_send_byte(smbus_io_req_t *req, uint8_t u8)
{
	smbus_io_req_reset(req);
	req->sir_op_valid = true;
	req->sir_op = SMBUS_OP_SEND_BYTE;
	req->sir_write = u8;

	return (i2c_success(req->sir_port->port_hdl));
}

bool
smbus_io_req_set_write_u8(smbus_io_req_t *req, uint8_t cmd, uint8_t u8)
{
	smbus_io_req_reset(req);
	req->sir_op_valid = true;
	req->sir_op = SMBUS_OP_WRITE_BYTE;
	req->sir_cmd = cmd;
	req->sir_write = u8;

	return (i2c_success(req->sir_port->port_hdl));
}

bool
smbus_io_req_set_write_u16(smbus_io_req_t *req, uint8_t cmd, uint16_t u16)
{
	smbus_io_req_reset(req);
	req->sir_op_valid = true;
	req->sir_op = SMBUS_OP_WRITE_WORD;
	req->sir_cmd = cmd;
	req->sir_write = u16;

	return (i2c_success(req->sir_port->port_hdl));
}

bool
smbus_io_req_set_write_u32(smbus_io_req_t *req, uint8_t cmd, uint32_t u32)
{
	smbus_io_req_reset(req);
	req->sir_op_valid = true;
	req->sir_op = SMBUS_OP_WRITE_U32;
	req->sir_cmd = cmd;
	req->sir_write = u32;

	return (i2c_success(req->sir_port->port_hdl));
}

bool
smbus_io_req_set_write_u64(smbus_io_req_t *req, uint8_t cmd, uint64_t u64)
{
	smbus_io_req_reset(req);
	req->sir_op_valid = true;
	req->sir_op = SMBUS_OP_WRITE_U64;
	req->sir_cmd = cmd;
	req->sir_write = u64;

	return (i2c_success(req->sir_port->port_hdl));
}

bool
smbus_io_req_set_write_block(smbus_io_req_t *req, uint8_t cmd,
    const void *wdata, size_t wlen, bool i2c)
{
	i2c_hdl_t *hdl = req->sir_port->port_hdl;

	if (wdata == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid input data pointer: %p", wdata));
	}

	if (wlen == 0) {
		return (i2c_error(hdl, I2C_ERR_IO_WRITE_LEN_RANGE, 0, "write "
		    "block requests must tranmit a non-zero amount of data"));
	} else if (wlen > I2C_REQ_MAX) {
		/*
		 * We only check against the maximum size range and leave it to
		 * the kernel to do the actual SMBus check as some block I2C
		 * writes can exceed SMBus 2.0 limits (especially after
		 * translation).
		 */
		return (i2c_error(hdl, I2C_ERR_IO_WRITE_LEN_RANGE, 0, "cannot "
		    "transmit %zu bytes in a request, valid range is [0x00, "
		    "0x%x]", wlen, I2C_REQ_MAX));
	}

	smbus_io_req_reset(req);
	req->sir_op_valid = true;
	req->sir_op = i2c ? SMBUS_OP_I2C_WRITE_BLOCK : SMBUS_OP_WRITE_BLOCK;
	req->sir_cmd = cmd;
	req->sir_writep = wdata;
	req->sir_wlen = wlen;

	return (i2c_success(hdl));
}

bool
smbus_io_req_set_recv_byte(smbus_io_req_t *req, uint8_t *u8p)
{
	i2c_hdl_t *hdl = req->sir_port->port_hdl;

	if (u8p == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid uint8_t pointer: %p", u8p));
	}

	smbus_io_req_reset(req);
	req->sir_op_valid = true;
	req->sir_op = SMBUS_OP_RECV_BYTE;
	req->sir_readp = u8p;

	return (i2c_success(hdl));
}

bool
smbus_io_req_set_read_u8(smbus_io_req_t *req, uint8_t cmd, uint8_t *u8p)
{
	i2c_hdl_t *hdl = req->sir_port->port_hdl;

	if (u8p == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid uint8_t pointer: %p", u8p));
	}

	smbus_io_req_reset(req);
	req->sir_op_valid = true;
	req->sir_op = SMBUS_OP_READ_BYTE;
	req->sir_cmd = cmd;
	req->sir_readp = u8p;

	return (i2c_success(hdl));
}

bool
smbus_io_req_set_read_u16(smbus_io_req_t *req, uint8_t cmd, uint16_t *u16p)
{
	i2c_hdl_t *hdl = req->sir_port->port_hdl;

	if (u16p == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid uint16_t pointer: %p", u16p));
	}

	smbus_io_req_reset(req);
	req->sir_op_valid = true;
	req->sir_op = SMBUS_OP_READ_WORD;
	req->sir_cmd = cmd;
	req->sir_readp = u16p;

	return (i2c_success(hdl));
}

bool
smbus_io_req_set_read_u32(smbus_io_req_t *req, uint8_t cmd, uint32_t *u32p)
{
	i2c_hdl_t *hdl = req->sir_port->port_hdl;

	if (u32p == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid uint32_t pointer: %p", u32p));
	}

	smbus_io_req_reset(req);
	req->sir_op_valid = true;
	req->sir_op = SMBUS_OP_READ_U32;
	req->sir_cmd = cmd;
	req->sir_readp = u32p;

	return (i2c_success(hdl));
}

bool
smbus_io_req_set_read_u64(smbus_io_req_t *req, uint8_t cmd, uint64_t *u64p)
{
	i2c_hdl_t *hdl = req->sir_port->port_hdl;

	if (u64p == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid uint64_t pointer: %p", u64p));
	}

	smbus_io_req_reset(req);
	req->sir_op_valid = true;
	req->sir_op = SMBUS_OP_READ_U64;
	req->sir_cmd = cmd;
	req->sir_readp = u64p;

	return (i2c_success(hdl));
}

bool
smbus_io_req_set_read_block_i2c(smbus_io_req_t *req, uint8_t cmd, void *rdata,
    size_t rlen)
{
	i2c_hdl_t *hdl = req->sir_port->port_hdl;

	if (rdata == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid output data pointer: %p", rdata));
	}

	if (rlen == 0) {
		return (i2c_error(hdl, I2C_ERR_IO_READ_LEN_RANGE, 0, "read "
		    "block requests must tranmit a non-zero amount of data"));
	} else if (rlen > I2C_REQ_MAX) {
		return (i2c_error(hdl, I2C_ERR_IO_WRITE_LEN_RANGE, 0, "cannot "
		    "receive %zu bytes in a request, valid range is [0x00, "
		    "0x%x]", rlen, I2C_REQ_MAX));
	}

	smbus_io_req_reset(req);
	req->sir_op_valid = true;
	req->sir_op = SMBUS_OP_I2C_READ_BLOCK;
	req->sir_cmd = cmd;
	req->sir_readp = rdata;
	req->sir_rlen = rlen;

	return (i2c_success(req->sir_port->port_hdl));
}

bool
smbus_io_req_set_process_call(smbus_io_req_t *req, uint8_t cmd, uint16_t wdata,
    uint16_t *rdatap)
{
	i2c_hdl_t *hdl = req->sir_port->port_hdl;

	if (rdatap == NULL) {
		return (i2c_error(hdl, I2C_ERR_BAD_PTR, 0, "encountered "
		    "invalid output data pointer: %p", rdatap));
	}

	smbus_io_req_reset(req);
	req->sir_op_valid = true;
	req->sir_op = SMBUS_OP_PROCESS_CALL;
	req->sir_cmd = cmd;
	req->sir_write = wdata;
	req->sir_readp = rdatap;

	return (i2c_success(req->sir_port->port_hdl));
}

bool
smbus_io_req_exec(smbus_io_req_t *req)
{
	i2c_hdl_t *hdl = req->sir_port->port_hdl;
	smbus_req_t smbus;

	if (!req->sir_addr_valid || !req->sir_op_valid) {
		const char *miss;

		if (!req->sir_addr_valid && !req->sir_op_valid) {
			miss = "device address, SMBus operation code";
		} else if (!req->sir_op_valid) {
			miss = "SMBus operation code";
		} else {
			miss = "device address";
		}
		return (i2c_error(hdl, I2C_ERR_IO_REQ_MISSING_FIELDS, 0,
		    "cannot execute I/O request due to missing fields: %s",
		    miss));
	}

	(void) memset(&smbus, 0, sizeof (smbus_req_t));
	smbus.smbr_op = req->sir_op;
	smbus.smbr_flags = req->sir_flags;
	smbus.smbr_addr = req->sir_addr;
	smbus.smbr_cmd = req->sir_cmd;

	/*
	 * Copy relevant data into the request for anything that needs to write.
	 * The actual write length or read length is only relevant for block
	 * requests. The rest get their length dictated by the actual opcode.
	 * SMBus transmits all data in little endian.
	 */
	switch (req->sir_op) {
	case SMBUS_OP_SEND_BYTE:
	case SMBUS_OP_WRITE_BYTE:
		smbus.smbr_wdata[0] = (uint8_t)req->sir_write;
		break;
	case SMBUS_OP_WRITE_WORD:
	case SMBUS_OP_PROCESS_CALL: {
		uint16_t u16 = htole16((uint16_t)req->sir_write);
		(void) memcpy(smbus.smbr_wdata, &u16, sizeof (u16));
		break;
	}
	case SMBUS_OP_WRITE_U32: {
		uint32_t u32 = htole32((uint32_t)req->sir_write);
		(void) memcpy(smbus.smbr_wdata, &u32, sizeof (u32));
		break;
	}
	case SMBUS_OP_WRITE_U64: {
		uint64_t u64 = htole64(req->sir_write);
		(void) memcpy(smbus.smbr_wdata, &u64, sizeof (u64));
		break;
	}
	case SMBUS_OP_I2C_WRITE_BLOCK:
	case SMBUS_OP_WRITE_BLOCK:
		smbus.smbr_wlen = req->sir_wlen;
		(void) memcpy(smbus.smbr_wdata, req->sir_writep, req->sir_wlen);
		break;
	case SMBUS_OP_I2C_READ_BLOCK:
		smbus.smbr_rlen = req->sir_rlen;
		break;
	default:
		break;
	}

	if (ioctl(req->sir_port->port_fd, UI2C_IOCTL_SMBUS_REQ, &smbus) != 0) {
		int e = errno;
		return (i2c_ioctl_syserror(hdl, e, "SMBus I/O request"));
	}

	if (smbus.smbr_error.i2c_error != I2C_CORE_E_OK) {
		return (i2c_ioctl_error(hdl, &smbus.smbr_error,
		    "SMBus I/O request"));
	}

	switch (req->sir_op) {
	case SMBUS_OP_RECV_BYTE:
	case SMBUS_OP_READ_BYTE:
		*(uint8_t *)req->sir_readp = smbus.smbr_rdata[0];
		break;
	case SMBUS_OP_READ_WORD:
	case SMBUS_OP_PROCESS_CALL: {
		uint16_t u16;
		(void) memcpy(&u16, smbus.smbr_rdata, sizeof (uint16_t));
		*(uint16_t *)req->sir_readp = letoh16(u16);
		break;
	}
	case SMBUS_OP_READ_U32: {
		uint32_t u32;
		(void) memcpy(&u32, smbus.smbr_rdata, sizeof (uint32_t));
		*(uint32_t *)req->sir_readp = letoh32(u32);
		break;
	}
	case SMBUS_OP_READ_U64: {
		uint64_t u64;
		(void) memcpy(&u64, smbus.smbr_rdata, sizeof (uint64_t));
		*(uint64_t *)req->sir_readp = letoh64(u64);
		break;
	}
	/*
	 * Right now, only I2C Read block is supported earlier since we haven't
	 * plumbed through all the variable length read functions for lack of
	 * testing.
	 */
	case SMBUS_OP_READ_BLOCK:
	case SMBUS_OP_I2C_READ_BLOCK:
	case SMBUS_OP_BLOCK_PROCESS_CALL:
		(void) memcpy(req->sir_readp, smbus.smbr_rdata,
		    smbus.smbr_rlen);
	default:
		break;
	}

	return (i2c_success(hdl));
}
