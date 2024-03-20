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
 * Copyright 2024 Oxide Computer Company
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
		 * If the device presents us with an "unknown error"
		 * code, or the status code is undefined, then we log
		 * an error and convert it to EIO.
		 */
		ena_err(ena, "unexpected status code: %d", status);
		ret = EIO;
		break;
	}

	return (ret);
}

const char *
enahw_reset_reason(enahw_reset_reason_t reason)
{
	switch (reason) {
	case ENAHW_RESET_NORMAL:
		return ("normal");
	case ENAHW_RESET_KEEP_ALIVE_TO:
		return ("keep-alive timeout");
	case ENAHW_RESET_ADMIN_TO:
		return ("admin timeout");
	case ENAHW_RESET_MISS_TX_CMPL:
		return ("missed TX completion");
	case ENAHW_RESET_INV_RX_REQ_ID:
		return ("invalid RX request ID");
	case ENAHW_RESET_INV_TX_REQ_ID:
		return ("invalid TX request ID");
	case ENAHW_RESET_TOO_MANY_RX_DESCS:
		return ("too many RX descs");
	case ENAHW_RESET_INIT_ERR:
		return ("initialization error");
	case ENAHW_RESET_DRIVER_INVALID_STATE:
		return ("invalid driver state");
	case ENAHW_RESET_OS_TRIGGER:
		return ("OS trigger");
	case ENAHW_RESET_OS_NETDEV_WD:
		return ("netdev watchdog");
	case ENAHW_RESET_SHUTDOWN:
		return ("shutdown");
	case ENAHW_RESET_USER_TRIGGER:
		return ("user trigger");
	case ENAHW_RESET_GENERIC:
		return ("generic");
	case ENAHW_RESET_MISS_INTERRUPT:
		return ("missed interrupt");
	case ENAHW_RESET_SUSPECTED_POLL_STARVATION:
		return ("suspected poll starvation");
	case ENAHW_RESET_RX_DESCRIPTOR_MALFORMED:
		return ("malformed RX descriptor");
	case ENAHW_RESET_TX_DESCRIPTOR_MALFORMED:
		return ("malformed TX descriptor");
	case ENAHW_RESET_MISSING_ADMIN_INTERRUPT:
		return ("missing admin interrupt");
	case ENAHW_RESET_DEVICE_REQUEST:
		return ("device request");
	default:
		return ("unknown");
	}
}

#ifdef DEBUG
static const ena_reg_t reg_cache_template[ENAHW_NUM_REGS] = {
	{
		.er_name = "Version",
		.er_offset = ENAHW_REG_VERSION
	},
	{
		.er_name = "Controller Version",
		.er_offset = ENAHW_REG_CONTROLLER_VERSION
	},
	{
		.er_name = "Caps",
		.er_offset = ENAHW_REG_CAPS
	},
	{
		.er_name = "Extended Caps",
		.er_offset = ENAHW_REG_CAPS_EXT
	},
	{
		.er_name = "Admin SQ Base Low",
		.er_offset = ENAHW_REG_ASQ_BASE_LO
	},
	{
		.er_name = "Admin SQ Base High",
		.er_offset = ENAHW_REG_ASQ_BASE_HI
	},
	{
		.er_name = "Admin SQ Caps",
		.er_offset = ENAHW_REG_ASQ_CAPS
	},
	{
		.er_name = "Gap 0x1C",
		.er_offset = ENAHW_REG_GAP_1C
	},
	{
		.er_name = "Admin CQ Base Low",
		.er_offset = ENAHW_REG_ACQ_BASE_LO
	},
	{
		.er_name = "Admin CQ Base High",
		.er_offset = ENAHW_REG_ACQ_BASE_HI
	},
	{
		.er_name = "Admin CQ Caps",
		.er_offset = ENAHW_REG_ACQ_CAPS
	},
	{
		.er_name = "Admin SQ Doorbell",
		.er_offset = ENAHW_REG_ASQ_DB
	},
	{
		.er_name = "Admin CQ Tail",
		.er_offset = ENAHW_REG_ACQ_TAIL
	},
	{
		.er_name = "Admin Event Notification Queue Caps",
		.er_offset = ENAHW_REG_AENQ_CAPS
	},
	{
		.er_name = "Admin Event Notification Queue Base Low",
		.er_offset = ENAHW_REG_AENQ_BASE_LO
	},
	{
		.er_name = "Admin Event Notification Queue Base High",
		.er_offset = ENAHW_REG_AENQ_BASE_HI
	},
	{
		.er_name = "Admin Event Notification Queue Head Doorbell",
		.er_offset = ENAHW_REG_AENQ_HEAD_DB
	},
	{
		.er_name = "Admin Event Notification Queue Tail",
		.er_offset = ENAHW_REG_AENQ_TAIL
	},
	{
		.er_name = "Gap 0x48",
		.er_offset = ENAHW_REG_GAP_48
	},
	{
		.er_name = "Interrupt Mask (disable interrupts)",
		.er_offset = ENAHW_REG_INTERRUPT_MASK
	},
	{
		.er_name = "Gap 0x50",
		.er_offset = ENAHW_REG_GAP_50
	},
	{
		.er_name = "Device Control",
		.er_offset = ENAHW_REG_DEV_CTL
	},
	{
		.er_name = "Device Status",
		.er_offset = ENAHW_REG_DEV_STS
	},
	{
		.er_name = "MMIO Register Read",
		.er_offset = ENAHW_REG_MMIO_REG_READ
	},
	{
		.er_name = "MMIO Response Address Low",
		.er_offset = ENAHW_REG_MMIO_RESP_LO
	},
	{
		.er_name = "MMIO Response Address High",
		.er_offset = ENAHW_REG_MMIO_RESP_HI
	},
	{
		.er_name = "RSS Indirection Entry Update",
		.er_offset = ENAHW_REG_RSS_IND_ENTRY_UPDATE
	},
};

void
ena_update_regcache(ena_t *ena)
{
	for (uint_t i = 0; i < ENAHW_NUM_REGS; i++) {
		ena_reg_t *r = &ena->ena_reg[i];

		r->er_value = ena_hw_bar_read32(ena, r->er_offset);
	}
}

void
ena_init_regcache(ena_t *ena)
{
	bcopy(reg_cache_template, ena->ena_reg, sizeof (ena->ena_reg));
	ena_update_regcache(ena);
}
#endif /* DEBUG */
