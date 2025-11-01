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
 * This tests the kernel's ability to detect invalid I/O requests. For I2C
 * requests this includes:
 *
 *  - Invalid addresses
 *  - Invalid flags
 *  - Bad read and write combinations
 *
 * For SMBus operations this incldues:
 *
 *  - Invalid addresses
 *  - Invalid flags, both general and operation-specific
 *  - Invalid operations
 *  - Operations which are unsupported
 *  - Specifying read and write length on operations that where it is fixed by
 *    the specification.
 *  - Bad read and write lengths for block requests
 *
 * All of the I/O tests operate against a non-existent on smbussim1. They should
 * never succeed as a result; however, they could fail for the wrong reason.
 */

#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <stdio.h>
#include <sys/debug.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/sysmacros.h>

#include <sys/i2c/ioctl.h>
#include "i2c_ioctl_util.h"

static bool
test_one_i2c(int fd, i2c_req_t *req, i2c_errno_t err, const char *desc)
{
	bool ret = true;

	req->ir_error.i2c_error = INT32_MAX;
	req->ir_error.i2c_ctrl = INT32_MAX;
	if (ioctl(fd, UI2C_IOCTL_I2C_REQ, req) != 0) {
		warnx("TEST FAILED: %s: unexpected ioctl failure: %s",
		    desc, strerrordesc_np(errno));
		return (false);
	}

	if (req->ir_error.i2c_error != err) {
		warnx("TEST FAILED: %s: I2C ioctl failed with I2C error 0x%x, "
		    "expected 0x%x", desc, req->ir_error.i2c_error, err);
		ret = false;
	}

	if (req->ir_error.i2c_ctrl != I2C_CTRL_E_OK) {
		warnx("TEST FAILED: %s: I2C ioctl has unexpected controller "
		    "error 0x%x", desc, req->ir_error.i2c_ctrl);
		ret = false;
	}

	if (ret) {
		(void) printf("TEST PASSED: %s correctly failed with I2C "
		    "error 0x%x\n", desc, err);
	}

	return (ret);
}

static bool
test_i2c_reqs(int fd)
{
	bool ret = true;
	i2c_req_t req;

	/*
	 * Set up the request as a one byte read request.
	 */
	(void) memset(&req, 0, sizeof (i2c_req_t));
	req.ir_rlen = 1;

	for (size_t i = 0; i < nbad_addrs; i++) {
		char desc[128];

		(void) snprintf(desc, sizeof (desc), "i2c: bad address %zu "
		    "(0x%x,0x%x)", i, bad_addrs[i].ba_type,
		    bad_addrs[i].ba_addr);
		req.ir_addr.ia_type = bad_addrs[i].ba_type;
		req.ir_addr.ia_addr = bad_addrs[i].ba_addr;

		if (!test_one_i2c(fd, &req, bad_addrs[i].ba_error, desc)) {
			ret = false;
		}
	}

	req.ir_addr.ia_type = I2C_ADDR_7BIT;
	req.ir_addr.ia_addr = 0x23;

	uint32_t bad_flags[] = { I2C_IO_REQ_F_QUICK_WRITE, 0x23, 0x777,
	    INT32_MAX, UINT32_MAX, 0x42 };
	for (size_t i = 0; i < ARRAY_SIZE(bad_flags); i++) {
		char desc[128];

		(void) snprintf(desc, sizeof (desc), "i2c: bad flags 0x%x",
		    bad_flags[i]);
		req.ir_flags = bad_flags[i];
		if (!test_one_i2c(fd, &req, I2C_CORE_E_BAD_I2C_REQ_FLAGS,
		    desc)) {
			ret = false;
		}
	}

	req.ir_flags = 0;
	req.ir_rlen = 0;
	req.ir_wlen = 0;
	if (!test_one_i2c(fd, &req, I2C_CORE_E_NEED_READ_OR_WRITE,
	    "i2c r=0, w=0")) {
		ret = false;
	}

	req.ir_rlen = 1;
	req.ir_wlen = I2C_REQ_MAX + 1;
	if (!test_one_i2c(fd, &req, I2C_CORE_E_BAD_I2C_REQ_WRITE_LEN,
	    "i2c r=1, w=257")) {
		ret = false;
	}

	req.ir_rlen = 1;
	req.ir_wlen = UINT16_MAX;
	if (!test_one_i2c(fd, &req, I2C_CORE_E_BAD_I2C_REQ_WRITE_LEN,
	    "i2c r=1, w=ffff")) {
		ret = false;
	}

	req.ir_rlen = I2C_REQ_MAX + 1;
	req.ir_wlen = 0;
	if (!test_one_i2c(fd, &req, I2C_CORE_E_BAD_I2C_REQ_READ_LEN,
	    "i2c r=257, w=0")) {
		ret = false;
	}

	req.ir_rlen = UINT16_MAX;
	req.ir_wlen = 0;
	if (!test_one_i2c(fd, &req, I2C_CORE_E_BAD_I2C_REQ_READ_LEN,
	    "i2c r=UINT16_MAX, w=0")) {
		ret = false;
	}

	return (ret);
}

static bool
test_one_smbus(int fd, smbus_req_t *req, i2c_errno_t err, const char *desc)
{
	bool ret = true;

	req->smbr_error.i2c_error = INT32_MAX;
	req->smbr_error.i2c_ctrl = INT32_MAX;
	if (ioctl(fd, UI2C_IOCTL_SMBUS_REQ, req) != 0) {
		warnx("TEST FAILED: %s: unexpected smbus ioctl failure: %s",
		    desc, strerrordesc_np(errno));
		return (false);
	}

	if (req->smbr_error.i2c_error != err) {
		warnx("TEST FAILED: %s: SMBus ioctl failed with I2C error "
		    "0x%x, expected 0x%x", desc, req->smbr_error.i2c_error,
		    err);
		ret = false;
	}

	if (req->smbr_error.i2c_ctrl != I2C_CTRL_E_OK) {
		warnx("TEST FAILED: %s: SMBus ioctl has unexpected controller "
		    "error 0x%x", desc, req->smbr_error.i2c_ctrl);
		ret = false;
	}

	if (ret) {
		(void) printf("TEST PASSED: %s correctly failed with I2C "
		    "error 0x%x\n", desc, err);
	}

	return (ret);
}


static bool
test_smbus_reqs(int fd)
{
	bool ret = true;
	smbus_req_t req;

	/*
	 * Set up the request as a read byte.
	 */
	(void) memset(&req, 0, sizeof (i2c_req_t));
	req.smbr_cmd = 0x23;
	req.smbr_op = SMBUS_OP_READ_BYTE;

	for (size_t i = 0; i < nbad_addrs; i++) {
		char desc[128];

		(void) snprintf(desc, sizeof (desc), "smbus: bad address %zu "
		    "(0x%x,0x%x)", i, bad_addrs[i].ba_type,
		    bad_addrs[i].ba_addr);
		req.smbr_addr.ia_type = bad_addrs[i].ba_type;
		req.smbr_addr.ia_addr = bad_addrs[i].ba_addr;

		if (!test_one_smbus(fd, &req, bad_addrs[i].ba_error, desc)) {
			ret = false;
		}
	}

	/*
	 * The quick flag should work only with the quick operation, hence why
	 * it's included in the group below.
	 */
	req.smbr_addr.ia_type = I2C_ADDR_7BIT;
	req.smbr_addr.ia_addr = 0x23;

	uint32_t bad_flags[] = { I2C_IO_REQ_F_QUICK_WRITE, 0x23, 0x777,
	    INT32_MAX, UINT32_MAX, 0x42 };
	for (size_t i = 0; i < ARRAY_SIZE(bad_flags); i++) {
		char desc[128];

		(void) snprintf(desc, sizeof (desc), "smbus: bad flags 0x%x",
		    bad_flags[i]);
		req.smbr_flags = bad_flags[i];
		if (!test_one_smbus(fd, &req, I2C_CORE_E_BAD_SMBUS_REQ_FLAGS,
		    desc)) {
			ret = false;
		}
	}

	req.smbr_flags = 0;
	uint32_t bad_ops[] = { SMBUS_OP_I2C_READ_BLOCK + 1,
		SMBUS_OP_I2C_READ_BLOCK << 1, 0x42, 0x7777, INT32_MAX };
	for (size_t i = 0; i < ARRAY_SIZE(bad_ops); i++) {
		char desc[128];

		(void) snprintf(desc, sizeof (desc), "smbus: bad operation "
		    "0x%x", bad_ops[i]);
		req.smbr_op = bad_ops[i];
		if (!test_one_smbus(fd, &req, I2C_CORE_E_BAD_SMBUS_OP, desc)) {
			ret = false;
		}
	}

	smbus_op_t unsup_ops[] = { SMBUS_OP_READ_BLOCK, SMBUS_OP_HOST_NOTIFY,
	    SMBUS_OP_BLOCK_PROCESS_CALL };

	for (size_t i = 0; i < ARRAY_SIZE(unsup_ops); i++) {
		char desc[128];

		(void) snprintf(desc, sizeof (desc), "smbus: unsupported "
		    "operation 0x%x", unsup_ops[i]);
		req.smbr_op = unsup_ops[i];
		if (!test_one_smbus(fd, &req, I2C_CORE_E_UNSUP_SMBUS_OP,
		    desc)) {
			ret = false;
		}
	}

	smbus_op_t norw_ops[] = { SMBUS_OP_QUICK_COMMAND, SMBUS_OP_SEND_BYTE,
	    SMBUS_OP_RECV_BYTE, SMBUS_OP_WRITE_BYTE, SMBUS_OP_READ_BYTE,
	    SMBUS_OP_WRITE_WORD, SMBUS_OP_READ_WORD, SMBUS_OP_PROCESS_CALL,
	    SMBUS_OP_WRITE_U32, SMBUS_OP_READ_U32, SMBUS_OP_WRITE_U64,
	    SMBUS_OP_READ_U64 };

	for (size_t i = 0; i < ARRAY_SIZE(norw_ops); i++) {
		char desc[128];

		(void) snprintf(desc, sizeof (desc), "smbus: op 0x%x fails "
		    "with read length", norw_ops[i]);
		req.smbr_op = norw_ops[i];
		req.smbr_rlen = 0x4;
		req.smbr_wlen = 0x0;
		if (!test_one_smbus(fd, &req, I2C_CORE_E_BAD_SMBUS_READ_LEN,
		    desc)) {
			ret = false;
		}

		(void) snprintf(desc, sizeof (desc), "smbus: op 0x%x fails "
		    "with write length", norw_ops[i]);
		req.smbr_op = norw_ops[i];
		req.smbr_rlen = 0x0;
		req.smbr_wlen = 0x4;
		if (!test_one_smbus(fd, &req, I2C_CORE_E_BAD_SMBUS_WRITE_LEN,
		    desc)) {
			ret = false;
		}
	}

	smbus_op_t wrblk_ops[] = { SMBUS_OP_WRITE_BLOCK,
	    SMBUS_OP_I2C_WRITE_BLOCK };
	for (size_t i = 0; i < ARRAY_SIZE(wrblk_ops); i++) {
		char desc[128];

		req.smbr_op = wrblk_ops[i];
		(void) snprintf(desc, sizeof (desc), "smbus op 0x%x fails with "
		    "read and write", wrblk_ops[i]);
		req.smbr_rlen = 0x1;
		req.smbr_wlen = 0x8;
		if (!test_one_smbus(fd, &req, I2C_CORE_E_BAD_SMBUS_READ_LEN,
		    desc)) {
			ret = false;
		}

		(void) snprintf(desc, sizeof (desc), "smbus op 0x%x fails with "
		    "read and no write", wrblk_ops[i]);
		req.smbr_rlen = 0x2;
		req.smbr_wlen = 0x0;
		if (!test_one_smbus(fd, &req, I2C_CORE_E_BAD_SMBUS_READ_LEN,
		    desc)) {
			ret = false;
		}

		(void) snprintf(desc, sizeof (desc), "smbus op 0x%x fails with "
		    "no read and no write", wrblk_ops[i]);
		req.smbr_rlen = 0x0;
		req.smbr_wlen = 0x0;
		if (!test_one_smbus(fd, &req, I2C_CORE_E_BAD_SMBUS_WRITE_LEN,
		    desc)) {
			ret = false;
		}

		(void) snprintf(desc, sizeof (desc), "smbus op 0x%x fails with "
		    "oversize write 1", wrblk_ops[i]);
		req.smbr_rlen = 0x0;
		req.smbr_wlen = I2C_REQ_MAX + 1;
		if (!test_one_smbus(fd, &req, I2C_CORE_E_BAD_SMBUS_WRITE_LEN,
		    desc)) {
			ret = false;
		}

		(void) snprintf(desc, sizeof (desc), "smbus op 0x%x fails with "
		    "oversize write 2", wrblk_ops[i]);
		req.smbr_rlen = 0x0;
		req.smbr_wlen = UINT16_MAX;
		if (!test_one_smbus(fd, &req, I2C_CORE_E_BAD_SMBUS_WRITE_LEN,
		    desc)) {
			ret = false;
		}
	}

	req.smbr_op = SMBUS_OP_I2C_READ_BLOCK;
	req.smbr_rlen = 0x2;
	req.smbr_wlen = 0x2;
	if (!test_one_smbus(fd, &req, I2C_CORE_E_BAD_SMBUS_WRITE_LEN,
	    "block read fails with read and write")) {
		ret = false;
	}

	req.smbr_rlen = 0x0;
	req.smbr_wlen = 0x2;
	if (!test_one_smbus(fd, &req, I2C_CORE_E_BAD_SMBUS_READ_LEN,
	    "block read fails with no read and write")) {
		ret = false;
	}

	req.smbr_rlen = 0x0;
	req.smbr_wlen = 0x0;
	if (!test_one_smbus(fd, &req, I2C_CORE_E_BAD_SMBUS_READ_LEN,
	    "block read fails with no read and no write")) {
		ret = false;
	}

	req.smbr_rlen = I2C_REQ_MAX + 1;
	req.smbr_wlen = 0x0;
	if (!test_one_smbus(fd, &req, I2C_CORE_E_BAD_SMBUS_READ_LEN,
	    "block read fails with oversize read 1")) {
		ret = false;
	}

	req.smbr_rlen = UINT16_MAX;
	req.smbr_wlen = 0x0;
	if (!test_one_smbus(fd, &req, I2C_CORE_E_BAD_SMBUS_READ_LEN,
	    "block read fails with oversize read 2")) {
		ret = false;
	}

	return (ret);
}

int
main(void)
{
	int ret = EXIT_SUCCESS;
	int fd = i2c_ioctl_test_get_fd(I2C_D_PORT, "smbussim1/0", O_RDWR);

	if (!test_i2c_reqs(fd)) {
		ret = EXIT_FAILURE;
	}

	if (!test_smbus_reqs(fd)) {
		ret = EXIT_FAILURE;
	}

	VERIFY0(close(fd));
	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests passed successfully\n");
	}
	return (ret);
}
