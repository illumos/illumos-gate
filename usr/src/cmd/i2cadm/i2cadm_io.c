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
 * Perform I/O on a given I2C bus, allowing a given mux segment to be activated
 * or a specific device.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>
#include <sys/hexdump.h>
#include <fcntl.h>
#include <unistd.h>

#include "i2cadm.h"

/*
 * Currently we don't have an SMBus block read present here. The main reason is
 * that we haven't been able to test this end-to-end and therefore don't have a
 * great API for extracting the target read length. If we have something we can
 * test against, then we can go ahead and add this.
 */
typedef enum {
	I2CADM_IO_M_I2C,
	I2CADM_IO_M_QUICK_READ,
	I2CADM_IO_M_QUICK_WRITE,
	I2CADM_IO_M_RECV_U8,
	I2CADM_IO_M_READ_U8,
	I2CADM_IO_M_READ_U16,
	I2CADM_IO_M_READ_U32,
	I2CADM_IO_M_READ_U64,
	I2CADM_IO_M_READ_BLOCK_I2C,
	I2CADM_IO_M_SEND_U8,
	I2CADM_IO_M_WRITE_U8,
	I2CADM_IO_M_WRITE_U16,
	I2CADM_IO_M_WRITE_U32,
	I2CADM_IO_M_WRITE_U64,
	I2CADM_IO_M_WRITE_BLOCK,
	I2CADM_IO_M_WRITE_BLOCK_I2C,
	I2CADM_IO_M_CALL
} i2cadm_io_mode_t;

typedef enum {
	/*
	 * Indicates that the size of this is fixed and the target size is
	 * specified in the mode_rlen and mode_wlen fields.
	 */
	I2CADM_IO_T_FIXED,
	/*
	 * Indicates that a variable read or write length is required, but not
	 * both.
	 */
	I2CADM_IO_T_VAR_READ,
	I2CADM_IO_T_VAR_WRITE,
	/*
	 * Indicates that both a variable read and write length is required. The
	 * next one is that only one of them is required, but both are allowed.
	 */
	I2CADM_IO_T_VAR_RW,
	I2CADM_IO_T_VAR_R_OR_W
} i2cadm_io_type_t;

typedef struct {
	const char *mode_str;
	const char *mode_help;
	i2cadm_io_mode_t mode_val;
	i2cadm_io_type_t mode_io;
	bool mode_need_cmd;
	uint32_t mode_rlen;
	uint32_t mode_wlen;
	size_t mode_dlen;
} i2cadm_mode_info_t;

typedef struct i2cadm_io_req {
	const i2cadm_mode_info_t *io_mode;
	i2c_io_req_t *io_i2c;
	smbus_io_req_t *io_smbus;
	uint8_t io_cmd;
	uint16_t io_rlen;
	uint16_t io_wlen;
	void *io_wdata;
	void *io_rdata;
} i2cadm_io_req_t;

static const i2cadm_mode_info_t i2cadm_io_modes[] = {
	[I2CADM_IO_M_I2C] = {
		.mode_str = "i2c",
		.mode_help = "\t\t\tgeneral-purpose I2C I/O",
		.mode_val = I2CADM_IO_M_I2C,
		.mode_io = I2CADM_IO_T_VAR_R_OR_W,
		.mode_dlen = sizeof (uint8_t)
	},
	[I2CADM_IO_M_QUICK_READ] = {
		.mode_str = "quick-read",
		.mode_help = "\t\tSMBus quick read",
		.mode_val = I2CADM_IO_M_QUICK_READ,
		.mode_io = I2CADM_IO_T_FIXED
	},
	[I2CADM_IO_M_QUICK_WRITE] = {
		.mode_str = "quick-write",
		.mode_help = "\t\tSMBus write read",
		.mode_val = I2CADM_IO_M_QUICK_WRITE,
		.mode_io = I2CADM_IO_T_FIXED
	},
	[I2CADM_IO_M_RECV_U8] = {
		.mode_str = "recv-u8",
		.mode_help = "\t\t\tSMBus receive byte",
		.mode_val = I2CADM_IO_M_RECV_U8,
		.mode_io = I2CADM_IO_T_FIXED,
		.mode_rlen = sizeof (uint8_t),
		.mode_dlen = sizeof (uint8_t)
	},
	[I2CADM_IO_M_READ_U8] = {
		.mode_str = "read-u8",
		.mode_help = "\t\t\tSMBus read byte with command",
		.mode_val = I2CADM_IO_M_READ_U8,
		.mode_io = I2CADM_IO_T_FIXED,
		.mode_need_cmd = true,
		.mode_rlen = sizeof (uint8_t),
		.mode_dlen = sizeof (uint8_t)
	},
	[I2CADM_IO_M_READ_U16] = {
		.mode_str = "read-u16",
		.mode_help = "\t\tSMBus read word with command",
		.mode_val = I2CADM_IO_M_READ_U16,
		.mode_io = I2CADM_IO_T_FIXED,
		.mode_need_cmd = true,
		.mode_rlen = sizeof (uint16_t),
		.mode_dlen = sizeof (uint16_t)
	},
	[I2CADM_IO_M_READ_U32] = {
		.mode_str = "read-u32",
		.mode_help = "\t\tSMBus read u32 with command",
		.mode_val = I2CADM_IO_M_READ_U32,
		.mode_io = I2CADM_IO_T_FIXED,
		.mode_need_cmd = true,
		.mode_rlen = sizeof (uint32_t),
		.mode_dlen = sizeof (uint32_t)
	},
	[I2CADM_IO_M_READ_U64] = {
		.mode_str = "read-u64",
		.mode_help = "\t\tSMBus read u64 with command",
		.mode_val = I2CADM_IO_M_READ_U64,
		.mode_io = I2CADM_IO_T_FIXED,
		.mode_need_cmd = true,
		.mode_rlen = sizeof (uint64_t),
		.mode_dlen = sizeof (uint64_t)
	},
	[I2CADM_IO_M_READ_BLOCK_I2C] = {
		.mode_str = "read-block-i2c",
		.mode_help = "\t\tSMBus I2C block read with command (length "
		    "not sent)",
		.mode_val = I2CADM_IO_M_READ_BLOCK_I2C,
		.mode_io = I2CADM_IO_T_VAR_READ,
		.mode_need_cmd = true,
		.mode_dlen = sizeof (uint8_t)
	},
	[I2CADM_IO_M_SEND_U8] = {
		.mode_str = "send-u8",
		.mode_help = "\t\t\tSMBus send byte",
		.mode_val = I2CADM_IO_M_SEND_U8,
		.mode_io = I2CADM_IO_T_FIXED,
		.mode_wlen = sizeof (uint8_t),
		.mode_dlen = sizeof (uint8_t)
	},
	[I2CADM_IO_M_WRITE_U8] = {
		.mode_str = "write-u8",
		.mode_help = "\t\tSMBus write byte with command",
		.mode_val = I2CADM_IO_M_WRITE_U8,
		.mode_io = I2CADM_IO_T_FIXED,
		.mode_need_cmd = true,
		.mode_wlen = sizeof (uint8_t),
		.mode_dlen = sizeof (uint8_t)
	},
	[I2CADM_IO_M_WRITE_U16] = {
		.mode_str = "write-u16",
		.mode_help = "\t\tSMBus write word with command",
		.mode_val = I2CADM_IO_M_WRITE_U16,
		.mode_io = I2CADM_IO_T_FIXED,
		.mode_need_cmd = true,
		.mode_wlen = sizeof (uint16_t),
		.mode_dlen = sizeof (uint16_t)
	},
	[I2CADM_IO_M_WRITE_U32] = {
		.mode_str = "write-u32",
		.mode_help = "\t\tSMBus write u32 with command",
		.mode_val = I2CADM_IO_M_WRITE_U32,
		.mode_io = I2CADM_IO_T_FIXED,
		.mode_need_cmd = true,
		.mode_wlen = sizeof (uint32_t),
		.mode_dlen = sizeof (uint32_t)
	},
	[I2CADM_IO_M_WRITE_U64] = {
		.mode_str = "write-u64",
		.mode_help = "\t\tSMBus write u64 with command",
		.mode_val = I2CADM_IO_M_WRITE_U64,
		.mode_io = I2CADM_IO_T_FIXED,
		.mode_need_cmd = true,
		.mode_wlen = sizeof (uint64_t),
		.mode_dlen = sizeof (uint64_t)
	},
	[I2CADM_IO_M_WRITE_BLOCK] = {
		.mode_str = "write-block",
		.mode_help = "\t\tSMBus block write with command and length",
		.mode_val = I2CADM_IO_M_WRITE_BLOCK,
		.mode_io = I2CADM_IO_T_VAR_WRITE,
		.mode_need_cmd = true,
		.mode_dlen = sizeof (uint8_t)
	},
	[I2CADM_IO_M_WRITE_BLOCK_I2C] = {
		.mode_str = "write-block-i2c",
		.mode_help = "\t\tSMBus I2C block write with command (length "
		    "not sent)",
		.mode_val = I2CADM_IO_M_WRITE_BLOCK_I2C,
		.mode_io = I2CADM_IO_T_VAR_WRITE,
		.mode_need_cmd = true,
		.mode_dlen = sizeof (uint8_t)
	},
	[I2CADM_IO_M_CALL] = {
		.mode_str = "call",
		.mode_help = "\t\t\tSMBus process call with command (tx and "
		    "rx a u16)",
		.mode_val = I2CADM_IO_M_CALL,
		.mode_io = I2CADM_IO_T_FIXED,
		.mode_need_cmd = true,
		.mode_rlen = sizeof (uint16_t),
		.mode_wlen = sizeof (uint16_t),
		.mode_dlen = sizeof (uint16_t)
	}
};

void
i2cadm_io_usage(FILE *f)
{
	(void) fprintf(f, "\ti2cadm io [-m mode] -d dest [-a addr] [-c cmd] "
	    "[-w wlen] [-r rlen] [-o output] <data>\n");
}

static void
i2cadm_io_help(const char *fmt, ...)
{
	if (fmt != NULL) {
		va_list ap;

		va_start(ap, fmt);
		vwarnx(fmt, ap);
		va_end(ap);
	}

	(void) fprintf(stderr, "Usage:  i2cadm io [-m mode] -d dest [-a addr] "
	    "[-r rlen] [-w wlen] [-o output]\n\t<data>\n");
	(void) fprintf(stderr, "\nPerform I/O to any arbitrary I2C address on "
	    "the specified controller and\nport. If a mux is part of the "
	    "destination path, then it will be activated\nprior to issuing "
	    "the I/O. Transmitted data will be taken from positional\n"
	    "arguments.\n\nThe following options are supported:\n\n"
	    "\t-a addr\t\tthe 7-bit address to send the I/O to\n"
	    "\t-d dest\t\tspecifies the controller and port to target\n"
	    "\t-m mode\t\tsets the type of I/O issued, defaults to I2C\n"
	    "\t-o output\twrite raw data read to file output\n"
	    "\t-r rlen\t\tsets the number of bytes to read\n"
	    "\t-w wlen\t\tsets the number of bytes to write\n"
	    "\nThe following I/O modes are supported:\n");

	for (size_t i = 0; i < ARRAY_SIZE(i2cadm_io_modes); i++) {
		(void) fprintf(stderr, "\t%s%s\n", i2cadm_io_modes[i].mode_str,
		    i2cadm_io_modes[i].mode_help);
	}
	exit(EXIT_FAILURE);
}

static const i2cadm_mode_info_t *
i2cadm_io_parse_mode(const char *str)
{
	for (size_t i = 0; i < ARRAY_SIZE(i2cadm_io_modes); i++) {
		if (strcasecmp(str, i2cadm_io_modes[i].mode_str) == 0) {
			return (&i2cadm_io_modes[i]);
		}
	}

	warnx("unknown I/O mode: %s", str);
	(void) printf("Valid I/O Modes:\n");
	for (size_t i = 0; i < ARRAY_SIZE(i2cadm_io_modes); i++) {
		(void) printf("\t%s%s\n", i2cadm_io_modes[i].mode_str,
		    i2cadm_io_modes[i].mode_help);
	}
	exit(EXIT_FAILURE);
}

static bool
i2cadm_io_read_ok(const i2cadm_mode_info_t *mode)
{
	switch (mode->mode_io) {
	case I2CADM_IO_T_FIXED:
		return (mode->mode_rlen != 0);
	case I2CADM_IO_T_VAR_READ:
	case I2CADM_IO_T_VAR_RW:
	case I2CADM_IO_T_VAR_R_OR_W:
		return (true);
	case I2CADM_IO_T_VAR_WRITE:
	default:
		return (false);
	}
}

static bool
i2cadm_io_read_req(const i2cadm_mode_info_t *mode)
{
	switch (mode->mode_io) {
	case I2CADM_IO_T_VAR_READ:
	case I2CADM_IO_T_VAR_RW:
		return (true);
	case I2CADM_IO_T_FIXED:
	case I2CADM_IO_T_VAR_WRITE:
	case I2CADM_IO_T_VAR_R_OR_W:
	default:
		return (false);
	}
}

static bool
i2cadm_io_write_req(const i2cadm_mode_info_t *mode)
{
	switch (mode->mode_io) {
	case I2CADM_IO_T_VAR_WRITE:
	case I2CADM_IO_T_VAR_RW:
		return (true);
	case I2CADM_IO_T_FIXED:
	case I2CADM_IO_T_VAR_READ:
	case I2CADM_IO_T_VAR_R_OR_W:
	default:
		return (false);
	}
}

static bool
i2cadm_io_write_ok(const i2cadm_mode_info_t *mode)
{
	switch (mode->mode_io) {
	case I2CADM_IO_T_FIXED:
		return (mode->mode_wlen != 0);
	case I2CADM_IO_T_VAR_WRITE:
	case I2CADM_IO_T_VAR_RW:
	case I2CADM_IO_T_VAR_R_OR_W:
		return (true);
	case I2CADM_IO_T_VAR_READ:
	default:
		return (false);
	}
}

/*
 * Look at the specific requested mode and parse the corresponding read and
 * write lengths. There are a few different cases for how a command performs
 * I/O:
 *
 *  - Commands that have a built-in length. For example, SMBus read/write
 *    u8/16 commands. Here if someone specifies the exact required length,
 *    that's fine, otherwise it's an error.
 *  - Commands that require both a read and write length: block call.
 *  - Commands that require either a read or a write length: other block
 *    operations.
 *  - Commands that require at least one I/O direction, but can use both, aka
 *    I2C.
 */
static void
i2cadm_io_parse_rw_len(i2cadm_io_req_t *req, const char *rstr, const char *wstr)
{
	const i2cadm_mode_info_t *mode = req->io_mode;
	const char *modestr = mode->mode_str;
	i2cadm_io_type_t type = mode->mode_io;

	/*
	 * First check if we have the required strings for the command mode.
	 */
	if (rstr == NULL && i2cadm_io_read_req(mode)) {
		errx(EXIT_FAILURE, "missing required I/O read length "
		    "(-r) which is required for I/O mode %s", modestr);
	}

	if (wstr == NULL && i2cadm_io_write_req(mode)) {
		errx(EXIT_FAILURE, "missing required I/O write length "
		    "(-w) which is required for I/O mode %s", modestr);
	}

	if (type == I2CADM_IO_T_VAR_R_OR_W && rstr == NULL && wstr == NULL) {
		errx(EXIT_FAILURE, "I/O mode %s requires at least one or both "
		    "of a read length (-r) and write length (-w) to be "
		    "specified", modestr);
	}

	/*
	 * Now if we have a string, check if it is allowed. If so, then parse
	 * it. If this was a fixed length we need to verify that things match.
	 */
	if (rstr != NULL) {
		const char *errstr;

		if (!i2cadm_io_read_ok(mode)) {
			errx(EXIT_FAILURE, "I/O mode %s does not allow "
			    "specifying a read length (-r)", modestr);
		}

		req->io_rlen = (uint16_t)strtonumx(rstr, 1, I2C_REQ_MAX,
		    &errstr, 0);
		if (errstr != NULL) {
			errx(EXIT_FAILURE, "invalid read length: %s is %s, "
			    "valid values are between 1 and %u", rstr, errstr,
			    I2C_REQ_MAX);
		}

		if (type == I2CADM_IO_T_FIXED && req->io_rlen !=
		    mode->mode_rlen) {
			errx(EXIT_FAILURE, "I/O mode %s has a fixed read "
			    "length of %u bytes, either do not specify -r or "
			    "set it to %u, not %s", modestr, mode->mode_rlen,
			    mode->mode_rlen, rstr);
		}
	} else if (type == I2CADM_IO_T_FIXED) {
		req->io_rlen = mode->mode_rlen;
	}

	if (wstr != NULL) {
		const char *errstr;

		if (!i2cadm_io_write_ok(mode)) {
			errx(EXIT_FAILURE, "I/O mode %s does not allow "
			    "specifying a write length (-w)", modestr);
		}

		req->io_wlen = (uint16_t)strtonumx(wstr, 1, I2C_REQ_MAX,
		    &errstr, 0);
		if (errstr != NULL) {
			errx(EXIT_FAILURE, "invalid write length: %s is %s, "
			    "valid values are between 1 and %u", wstr, errstr,
			    I2C_REQ_MAX);
		}

		if (type == I2CADM_IO_T_FIXED && req->io_wlen !=
		    mode->mode_wlen) {
			errx(EXIT_FAILURE, "I/O mode %s has a fixed write "
			    "length of %u bytes, either do not specify -w or "
			    "set it to %u, not %s", modestr, mode->mode_wlen,
			    mode->mode_wlen, wstr);
		}
	} else if (type == I2CADM_IO_T_FIXED) {
		req->io_wlen = mode->mode_wlen;
	}
}

/*
 * Go through and parse data into the requisite format. Different commands have
 * a different data size element. While most are a uint8_t, some are larger. We
 * adjust what we are parsing at this phase.
 *
 * We require one argument per data point. We should probably in the future
 * allow for something like looking for comma characters, but this works for
 * now.
 */
static void
i2cadm_io_parse_data(i2cadm_io_req_t *req, int argc, char *argv[])
{
	uint32_t nents;

	VERIFY3U(req->io_wlen, !=, 0);
	VERIFY3U(req->io_mode->mode_dlen, !=, 0);
	VERIFY0(req->io_wlen % req->io_mode->mode_dlen);

	nents = req->io_wlen / req->io_mode->mode_dlen;
	if (nents > 1 && req->io_mode->mode_dlen != 1) {
		errx(EXIT_FAILURE, "fatal internal error, cannot handle "
		    "I/O request with multiple non-byte sized data points");
	}

	req->io_wdata = calloc(nents, req->io_mode->mode_dlen);
	if (req->io_wdata == NULL) {
		err(EXIT_FAILURE, "failed to allocate write data buffer (%u "
		    "elements, %zu bytes)", nents, req->io_mode->mode_dlen);
	}

	if (argc != nents) {
		errx(EXIT_FAILURE, "write data requires %u elements, but only "
		    "found %d remaining arguments", nents, argc);
	}

	for (int i = 0; i < argc; i++) {
		unsigned long long ull, max;
		char *eptr;
		uint8_t *u8;
		uint16_t *u16;
		uint32_t *u32;
		uint64_t *u64;

		/*
		 * Note, we can't use strtonumx here because we want to be able
		 * to parse a uint64_t but strtonumx maxes out at a long long.
		 */
		errno = 0;
		ull = strtoull(argv[i], &eptr, 0);
		if (errno != 0 || *eptr != '\0') {
			errx(EXIT_FAILURE, "failed to parse data element %s",
			    argv[i]);
		}

		switch (req->io_mode->mode_dlen) {
		case 1:
			max = UINT8_MAX;
			break;
		case 2:
			max = UINT16_MAX;
			break;
		case 4:
			max = UINT32_MAX;
			break;
		case 8:
			max = UINT64_MAX;
			break;
		default:
			abort();
		}

		if (ull > max) {
			errx(EXIT_FAILURE, "data element %s is outside the "
			    "bounds for a %zu byte datum ([0, 0x%llx])",
			    argv[i], req->io_mode->mode_dlen, max);
		}

		switch (req->io_mode->mode_dlen) {
		case 1:
			u8 = req->io_wdata;
			u8[i] = (uint8_t)ull;
			break;
		case 2:
			u16 = req->io_wdata;
			u16[i] = (uint16_t)ull;
			break;
		case 4:
			u32 = req->io_wdata;
			u32[i] = (uint32_t)ull;
			break;
		case 8:
			u64 = req->io_wdata;
			u64[i] = (uint64_t)ull;
			break;
		default:
			abort();
		}
	}
}

static void
i2cadm_io_write(const i2cadm_io_req_t *req, const i2cadm_mode_info_t *mode,
    int ofd)
{
	size_t to_write = 0, off = 0;

	switch (mode->mode_val) {
	case I2CADM_IO_M_I2C:
	case I2CADM_IO_M_READ_BLOCK_I2C:
		to_write = req->io_rlen;
		break;
	case I2CADM_IO_M_RECV_U8:
	case I2CADM_IO_M_READ_U8:
		to_write = sizeof (uint8_t);
		break;
	case I2CADM_IO_M_READ_U16:
		to_write = sizeof (uint16_t);
		break;
	case I2CADM_IO_M_READ_U32:
		to_write = sizeof (uint32_t);
		break;
	case I2CADM_IO_M_READ_U64:
		to_write = sizeof (uint64_t);
		break;
	default:
		break;
	}

	while (to_write > 0) {
		ssize_t ret = write(ofd, req->io_rdata + off, to_write);
		if (ret < 0) {
			err(EXIT_FAILURE, "failed to write %zu bytes to "
			    "output file at offset %zu", to_write, off);
		}

		to_write -= ret;
		off += ret;
	}
}

static void
i2cadm_io_init(const i2cadm_io_req_t *req, const i2cadm_mode_info_t *mode)
{
	switch (mode->mode_val) {
	case I2CADM_IO_M_I2C:
		if (req->io_rlen != 0 &&
		    !i2c_io_req_set_receive_buf(req->io_i2c, req->io_rdata,
		    req->io_rlen)) {
			i2cadm_fatal("failed to set I2C read buffer");
		}

		if (req->io_wlen != 0 &&
		    !i2c_io_req_set_transmit_data(req->io_i2c, req->io_wdata,
		    req->io_wlen)) {
			i2cadm_fatal("Failed to set I2C write buffer");
		}
		break;
	case I2CADM_IO_M_QUICK_READ:
		if (!smbus_io_req_set_quick_cmd(req->io_smbus, false)) {
			i2cadm_fatal("failed to set quick command request");
		}
		break;
	case I2CADM_IO_M_QUICK_WRITE:
		if (!smbus_io_req_set_quick_cmd(req->io_smbus, true)) {
			i2cadm_fatal("failed to set quick command request");
		}
		break;
	case I2CADM_IO_M_RECV_U8:
		if (!smbus_io_req_set_recv_byte(req->io_smbus, req->io_rdata)) {
			i2cadm_fatal("failed to set receive byte request");
		}
		break;
	case I2CADM_IO_M_READ_U8:
		if (!smbus_io_req_set_read_u8(req->io_smbus, req->io_cmd,
		    req->io_rdata)) {
			i2cadm_fatal("failed to set read byte request");
		}
		break;
	case I2CADM_IO_M_READ_U16:
		if (!smbus_io_req_set_read_u16(req->io_smbus, req->io_cmd,
		    req->io_rdata)) {
			i2cadm_fatal("failed to set read word request");
		}
		break;
	case I2CADM_IO_M_READ_U32:
		if (!smbus_io_req_set_read_u32(req->io_smbus, req->io_cmd,
		    req->io_rdata)) {
			i2cadm_fatal("failed to set read u32 request");
		}
		break;
	case I2CADM_IO_M_READ_U64:
		if (!smbus_io_req_set_read_u64(req->io_smbus, req->io_cmd,
		    req->io_rdata)) {
			i2cadm_fatal("failed to set read u64 request");
		}
		break;
	case I2CADM_IO_M_READ_BLOCK_I2C:
		if (!smbus_io_req_set_read_block_i2c(req->io_smbus, req->io_cmd,
		    req->io_rdata, req->io_rlen)) {
			i2cadm_fatal("failed to set read block request");
		}
		break;
	case I2CADM_IO_M_SEND_U8:
		if (!smbus_io_req_set_send_byte(req->io_smbus,
		    *(uint8_t *)req->io_wdata)) {
			i2cadm_fatal("failed to set send byte request");
		}
		break;
	case I2CADM_IO_M_WRITE_U8:
		if (!smbus_io_req_set_write_u8(req->io_smbus, req->io_cmd,
		    *(uint8_t *)req->io_wdata)) {
			i2cadm_fatal("failed to set write byte request");
		}
		break;
	case I2CADM_IO_M_WRITE_U16:
		if (!smbus_io_req_set_write_u16(req->io_smbus, req->io_cmd,
		    *(uint16_t *)req->io_wdata)) {
			i2cadm_fatal("failed to set write word request");
		}
		break;
	case I2CADM_IO_M_WRITE_U32:
		if (!smbus_io_req_set_write_u32(req->io_smbus, req->io_cmd,
		    *(uint32_t *)req->io_wdata)) {
			i2cadm_fatal("failed to set write u32 request");
		}
		break;
	case I2CADM_IO_M_WRITE_U64:
		if (!smbus_io_req_set_write_u64(req->io_smbus, req->io_cmd,
		    *(uint64_t *)req->io_wdata)) {
			i2cadm_fatal("failed to set write u64 request");
		}
		break;
	case I2CADM_IO_M_WRITE_BLOCK:
	case I2CADM_IO_M_WRITE_BLOCK_I2C:
		if (!smbus_io_req_set_write_block(req->io_smbus, req->io_cmd,
		    req->io_wdata, req->io_wlen,
		    mode->mode_val == I2CADM_IO_M_WRITE_BLOCK_I2C)) {
			i2cadm_fatal("failed to set write block request");
		}
		break;
	case I2CADM_IO_M_CALL:
		if (!smbus_io_req_set_process_call(req->io_smbus, req->io_cmd,
		    *(uint16_t *)req->io_wdata, req->io_rdata)) {
			i2cadm_fatal("failed to set process call request");
		}
		break;
	}
}

static void
i2cadm_io_print(const i2cadm_io_req_t *req, const i2cadm_mode_info_t *mode)
{
	switch (mode->mode_val) {
	case I2CADM_IO_M_I2C:
	case I2CADM_IO_M_READ_BLOCK_I2C:
		/*
		 * If we didn't actually get any bytes (READ BLOCK) or this
		 * request didn't include a read (I2C), don't do anything.
		 */
		if (req->io_rlen == 0)
			break;

		/*
		 * While convention wants to include HDF_ADDR here, we do not
		 * since we may be reading at some arbitrary offset via
		 * registers. We're not going to try to interpret that.
		 */
		(void) hexdump_file(req->io_rdata, req->io_rlen, HDF_HEADER |
		    HDF_ASCII, stdout);
		break;
	case I2CADM_IO_M_RECV_U8:
	case I2CADM_IO_M_READ_U8:
		(void) printf("0x%x\n", *(uint8_t *)req->io_rdata);
		break;
	case I2CADM_IO_M_READ_U16:
		(void) printf("0x%x\n", *(uint16_t *)req->io_rdata);
		break;
	case I2CADM_IO_M_READ_U32:
		(void) printf("0x%x\n", *(uint32_t *)req->io_rdata);
		break;
	case I2CADM_IO_M_READ_U64:
		(void) printf("0x%" PRIx64 "\n", *(uint64_t *)req->io_rdata);
		break;
	default:
		VERIFY3U(req->io_rlen, ==, 0);
		break;
	}
}

int
i2cadm_io(int argc, char *argv[])
{
	int c, ofd = -1;
	const i2cadm_mode_info_t *mode = &i2cadm_io_modes[I2CADM_IO_M_I2C];
	const char *dpath = NULL, *addrstr = NULL, *cmdstr = NULL;
	const char *wstr = NULL, *rstr = NULL, *output = NULL;
	i2c_port_t *port;
	i2c_dev_info_t *info;
	i2c_addr_t addr;
	i2cadm_io_req_t req;

	while ((c = getopt(argc, argv, ":a:c:d:m:o:r:w:")) != -1) {
		switch (c) {
		case 'a':
			addrstr = optarg;
			break;
		case 'c':
			cmdstr = optarg;
			break;
		case 'd':
			dpath = optarg;
			break;
		case 'm':
			mode = i2cadm_io_parse_mode(optarg);
			break;
		case 'o':
			output = optarg;
			break;
		case 'r':
			rstr = optarg;
			break;
		case 'w':
			wstr = optarg;
			break;
		case ':':
			i2cadm_io_help("option -%c requires an argument",
			    optopt);
			exit(EXIT_USAGE);
		case '?':
			i2cadm_io_help("unknown option: -%c", optopt);
			exit(EXIT_USAGE);
		}
	}

	/*
	 * First establish that we have a valid destination and address that
	 * we're targetting. If the user gives us a full path to a device, then
	 * we don't want -a to be specified. if not, then we need -a
	 * ("addrstr").
	 */
	if (dpath == NULL) {
		errx(EXIT_FAILURE, "missing required destination path");
	}

	if (!i2c_port_dev_init_by_path(i2cadm.i2c_hdl, dpath, true, &port,
	    &info)) {
		i2cadm_fatal("failed to parse path %s", dpath);
	}

	if (info != NULL) {
		if (addrstr != NULL) {
			errx(EXIT_FAILURE, "target address specified twice: "
			    "either use an I2C path that specified a device or "
			    "-a, not both");
		}

		addr = *i2c_device_info_addr_primary(info);
		i2c_device_info_free(info);
		info = NULL;
	} else {
		if (addrstr == NULL) {
			errx(EXIT_FAILURE, "missing target address: specify an "
			    "I2C path that refers to a device or use -a");
		}

		if (!i2c_addr_parse(i2cadm.i2c_hdl, addrstr, &addr)) {
			i2cadm_fatal("failed to parse address %s", addrstr);
		}
	}

	bzero(&req, sizeof (req));
	req.io_mode = mode;
	if (mode->mode_val == I2CADM_IO_M_I2C) {
		if (!i2c_io_req_init(port, &req.io_i2c)) {
			i2cadm_fatal("failed to initialize I2C I/O request");
		}

		if (!i2c_io_req_set_addr(req.io_i2c, &addr)) {
			i2cadm_fatal("failed to set I2C request address");
		}
	} else {
		if (!smbus_io_req_init(port, &req.io_smbus)) {
			i2cadm_fatal("failed to initialize SMBus I/O request");
		}

		if (!smbus_io_req_set_addr(req.io_smbus, &addr)) {
			i2cadm_fatal("failed to set I2C request address");
		}
	}

	if (mode->mode_need_cmd) {
		const char *errstr = NULL;
		if (cmdstr == NULL) {
			errx(EXIT_FAILURE, "missing required SMBus command "
			    "value (-c) for I/O mode %s", mode->mode_str);
		}
		req.io_cmd = (uint8_t)strtonumx(cmdstr, 0, UINT8_MAX, &errstr,
		    0);
		if (errstr != NULL) {
			errx(EXIT_FAILURE, "invalid command value (-c): %s "
			    "is %s, valid values are between 0x00 and 0x%x",
			    cmdstr, errstr, UINT8_MAX);
		}
	} else {
		if (cmdstr != NULL) {
			errx(EXIT_FAILURE, "I/O mode %s does not allow "
			    "specifying an SMBus cmd (-c)", mode->mode_str);
		}
	}

	i2cadm_io_parse_rw_len(&req, rstr, wstr);
	argc -= optind;
	argv += optind;

	if (req.io_wlen == 0) {
		if (argc != 0) {
			errx(EXIT_USAGE, "encountered extraneous arguments "
			    "starting with %s", argv[0]);
		}
	} else {
		i2cadm_io_parse_data(&req, argc, argv);
	}

	if (req.io_rlen != 0) {
		req.io_rdata = calloc(req.io_rlen, sizeof (uint8_t));
		if (req.io_rdata == NULL) {
			err(EXIT_FAILURE, "failed to allocate %u bytes for "
			    "request read buffer", req.io_rlen);
		}

		if (output != NULL) {
			ofd = open(output, O_RDWR | O_TRUNC | O_CREAT);
			if (ofd < 0) {
				err(EXIT_FAILURE, "failed to open ouput "
				    "file (-o) %s", output);
			}
		}
	} else if (output != NULL) {
		errx(EXIT_FAILURE, "cannot specify output file -o when no "
		    "data is being read");
	}

	i2cadm_io_init(&req, mode);

	if (req.io_i2c != NULL) {
		if (!i2c_io_req_exec(req.io_i2c)) {
			i2cadm_fatal("failed to execute I2C request");
		}
	} else {
		if (!smbus_io_req_exec(req.io_smbus)) {
			i2cadm_fatal("failed to execute SMBus request");
		}
	}

	if (ofd != -1) {
		i2cadm_io_write(&req, mode, ofd);
		(void) close(ofd);
	} else {
		i2cadm_io_print(&req, mode);
	}

	if (req.io_i2c != NULL) {
		i2c_io_req_fini(req.io_i2c);
	}
	if (req.io_smbus != NULL) {
		smbus_io_req_fini(req.io_smbus);
	}

	free(req.io_wdata);
	free(req.io_rdata);
	i2c_port_fini(port);
	return (EXIT_SUCCESS);
}
