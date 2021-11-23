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
 * Copyright 2021 Oxide Computer Company
 */

#include "ena_hw.h"
#include "ena.h"

uint32_t
ena_hw_bar_read32(const ena_t *ena, const uint16_t offset)
{
	caddr_t addr = ena->ena_reg_base + offset;
	return (ena_hw_abs_read32(ena, (uint32_t *)addr));
}

uint32_t
ena_hw_abs_read32(const ena_t *ena, uint32_t *addr)
{
	VERIFY3U(addr, >=, ena->ena_reg_base);
	VERIFY3U(addr, <, ena->ena_reg_base + (ena->ena_reg_size - 4));

	return (ddi_get32(ena->ena_reg_hdl, addr));
}

void
ena_hw_bar_write32(const ena_t *ena, const uint16_t offset, const uint32_t val)
{
	caddr_t addr = ena->ena_reg_base + offset;
	ena_hw_abs_write32(ena, (uint32_t *)addr, val);
}

void
ena_hw_abs_write32(const ena_t *ena, uint32_t *addr, const uint32_t val)
{
	VERIFY3P(ena, !=, NULL);
	VERIFY3P(addr, !=, NULL);
	VERIFY3U(addr, >=, ena->ena_reg_base);
	VERIFY3U(addr, <, ena->ena_reg_base + (ena->ena_reg_size - 4));

	ddi_put32(ena->ena_reg_hdl, addr, val);
}

int
enahw_resp_status_to_errno(ena_t *ena, enahw_resp_status_t status)
{
	int ret = 0;

	switch (status) {
	case ENAHW_RESP_SUCCESS:
		break;

	case ENAHW_RESP_RESOURCE_ALLOCATION_FAILURE:
		ret = ENOMEM;
		break;

	case ENAHW_RESP_UNSUPPORTED_OPCODE:
		ret = ENOTSUP;
		break;

	case ENAHW_RESP_BAD_OPCODE:
	case ENAHW_RESP_MALFORMED_REQUEST:
	case ENAHW_RESP_ILLEGAL_PARAMETER:
		ret = EINVAL;
		break;

	case ENAHW_RESP_RESOURCE_BUSY:
		ret = EAGAIN;
		break;

	case ENAHW_RESP_UNKNOWN_ERROR:
	default:
		/*
		 * If the device presents us with an "unknwon error"
		 * code, or the status code is undefined, then we log
		 * an error and convert it to EIO.
		 */
		ena_err(ena, "unexpected status code: %d", status);
		ret = EIO;
		break;
	}

	return (ret);
}
