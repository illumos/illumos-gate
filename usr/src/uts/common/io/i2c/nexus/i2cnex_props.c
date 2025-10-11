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
 * This file contains logic for getting information about and manipulating
 * properties.
 */

#include <sys/sunddi.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>

#include "i2cnex.h"

typedef struct i2c_prop_table {
	const char *ipt_name;
	i2c_prop_type_t ipt_type;
	i2c_prop_type_t ipt_pos;
} i2c_prop_table_t;

static const i2c_prop_table_t i2c_prop_table[] = {
	[I2C_PROP_BUS_SPEED] = {
		.ipt_name = "speed",
		.ipt_type = I2C_PROP_TYPE_U32,
		.ipt_pos = I2C_PROP_TYPE_BIT32
	},
	[I2C_PROP_NPORTS] = {
		.ipt_name = "ports",
		.ipt_type = I2C_PROP_TYPE_U32,
		.ipt_pos = I2C_PROP_TYPE_U32,
	},
	[I2C_PROP_TYPE] = {
		.ipt_name = "type",
		.ipt_type = I2C_PROP_TYPE_U32,
		.ipt_pos = I2C_PROP_TYPE_U32,
	},
	[SMBUS_PROP_SUP_OPS] = {
		.ipt_name = "smbus-ops",
		.ipt_type = I2C_PROP_TYPE_BIT32,
		.ipt_pos = I2C_PROP_TYPE_BIT32,
	},
	[I2C_PROP_MAX_READ] = {
		.ipt_name = "i2c-max-read",
		.ipt_type = I2C_PROP_TYPE_U32,
		.ipt_pos = I2C_PROP_TYPE_U32,
	},
	[I2C_PROP_MAX_WRITE] = {
		.ipt_name = "i2c-max-write",
		.ipt_type = I2C_PROP_TYPE_U32,
		.ipt_pos = I2C_PROP_TYPE_U32,
	},
	[SMBUS_PROP_MAX_BLOCK] = {
		.ipt_name = "smbus-max-block",
		.ipt_type = I2C_PROP_TYPE_U32,
		.ipt_pos = I2C_PROP_TYPE_U32,
	},
	[I2C_PROP_STD_SCL_HIGH] = {
		.ipt_name = "clock-Thigh-std",
		.ipt_type = I2C_PROP_TYPE_U32,
		.ipt_pos = I2C_PROP_TYPE_U32,
	},
	[I2C_PROP_STD_SCL_LOW] = {
		.ipt_name = "clock-Tlow-std",
		.ipt_type = I2C_PROP_TYPE_U32,
		.ipt_pos = I2C_PROP_TYPE_U32,
	},
	[I2C_PROP_FAST_SCL_HIGH] = {
		.ipt_name = "clock-Thigh-fast",
		.ipt_type = I2C_PROP_TYPE_U32,
		.ipt_pos = I2C_PROP_TYPE_U32,
	},
	[I2C_PROP_FAST_SCL_LOW] = {
		.ipt_name = "clock-Tlow-fast",
		.ipt_type = I2C_PROP_TYPE_U32,
		.ipt_pos = I2C_PROP_TYPE_U32,
	},
	[I2C_PROP_HIGH_SCL_HIGH] = {
		.ipt_name = "clock-Thigh-high",
		.ipt_type = I2C_PROP_TYPE_U32,
		.ipt_pos = I2C_PROP_TYPE_U32,
	},
	[I2C_PROP_HIGH_SCL_LOW] = {
		.ipt_name = "clock-Tlow-high",
		.ipt_type = I2C_PROP_TYPE_U32,
		.ipt_pos = I2C_PROP_TYPE_U32,
	}
};

uint16_t
i2c_prop_nstd(void)
{
	CTASSERT(ARRAY_SIZE(i2c_prop_table) < UINT16_MAX);
	return ((uint16_t)ARRAY_SIZE(i2c_prop_table));
}

static const i2c_prop_table_t *
i2c_prop_find(i2c_prop_t prop)
{
	if (prop >= ARRAY_SIZE(i2c_prop_table)) {
		return (NULL);
	}

	VERIFY3P(i2c_prop_table[prop].ipt_name, !=, NULL);
	return (&i2c_prop_table[prop]);
}

bool
i2c_prop_info(i2c_ctrl_t *ctrl, ui2c_prop_info_t *info)
{
	i2c_errno_t ret;
	const i2c_prop_table_t *table;
	i2c_prop_t propid = info->upi_prop;
	i2c_prop_range_t *range;

	bzero(info, sizeof (ui2c_prop_info_t));
	info->upi_prop = propid;
	table = i2c_prop_find(propid);
	if (table == NULL) {
		return (i2c_error(&info->upi_error, I2C_PROP_E_UNKNOWN, 0));
	}

	(void) strlcpy(info->upi_name, table->ipt_name,
	    sizeof (info->upi_name));
	info->upi_type = table->ipt_type;
	info->upi_pos_len = sizeof (i2c_prop_range_t);
	info->upi_perm = I2C_PROP_PERM_RO;
	range = (i2c_prop_range_t *)info->upi_pos;
	range->ipr_type = table->ipt_pos;

	switch (info->upi_prop) {
	case I2C_PROP_NPORTS:
	case I2C_PROP_TYPE:
		/*
		 * These properties are handled by the framework. There's
		 * nothing to do for these as we already set them to read only
		 * just above. there is no default value and there is no
		 * possible range.
		 */
		return (true);
	default:
		break;
	}

	ret = ctrl->ic_ops->i2c_prop_info_f(ctrl->ic_drv, propid,
	    (i2c_prop_info_t *)info);
	if (ret != I2C_CORE_E_OK) {
		return (i2c_error(&info->upi_error, ret, 0));
	}

	return (true);
}

bool
i2c_prop_get(i2c_ctrl_t *ctrl, i2c_prop_t prop, void *buf,
    uint32_t *buflen, i2c_error_t *err)
{
	i2c_errno_t ret;
	size_t osize = *buflen;
	const i2c_prop_table_t *table;

	table = i2c_prop_find(prop);
	if (table == NULL) {
		return (i2c_error(err, I2C_PROP_E_UNKNOWN, 0));
	}

	switch (table->ipt_type) {
	case I2C_PROP_TYPE_U32:
	case I2C_PROP_TYPE_BIT32:
		*buflen = sizeof (uint32_t);
		if (osize < sizeof (uint32_t)) {
			return (i2c_error(err, I2C_PROP_E_SMALL_BUF, 0));
		}
		break;
	}


	switch (prop) {
	case I2C_PROP_NPORTS:
		bcopy(&ctrl->ic_nports, buf, sizeof (uint32_t));
		return (true);
	case I2C_PROP_TYPE:
		bcopy(&ctrl->ic_type, buf, sizeof (uint32_t));
		return (true);
	default:
		break;
	}

	ret = ctrl->ic_ops->i2c_prop_get_f(ctrl->ic_drv, prop,
	    buf, *buflen);
	if (ret != I2C_CORE_E_OK) {
		return (i2c_error(err, ret, 0));
	}

	return (true);
}

bool
i2c_prop_set(i2c_txn_t *txn, i2c_ctrl_t *ctrl, i2c_prop_t prop, const void *buf,
    uint32_t buflen, i2c_error_t *err)
{
	i2c_errno_t ret;
	const i2c_prop_table_t *table;

	VERIFY(i2c_txn_held(txn));
	VERIFY3P(txn->txn_ctrl, ==, ctrl);

	table = i2c_prop_find(prop);
	if (table == NULL) {
		return (i2c_error(err, I2C_PROP_E_UNKNOWN, 0));
	}

	switch (table->ipt_type) {
	case I2C_PROP_TYPE_U32:
	case I2C_PROP_TYPE_BIT32:
		if (buflen < sizeof (uint32_t)) {
			return (i2c_error(err, I2C_PROP_E_SMALL_BUF, 0));
		} else if (buflen != sizeof (uint32_t)) {
			return (i2c_error(err, I2C_PROP_E_TOO_BIG_BUF, 0));
		}
		break;
	}

	if (ctrl->ic_ops->i2c_prop_set_f == NULL) {
		return (i2c_error(err, I2C_PROP_E_SET_UNSUP, 0));
	}

	/*
	 * Enforce that specific properties are read-only.
	 */
	switch (prop) {
	case I2C_PROP_NPORTS:
	case I2C_PROP_TYPE:
	case SMBUS_PROP_SUP_OPS:
	case I2C_PROP_MAX_READ:
	case I2C_PROP_MAX_WRITE:
	case SMBUS_PROP_MAX_BLOCK:
		return (i2c_error(err, I2C_PROP_E_READ_ONLY, 0));
	default:
		break;
	}

	ret = ctrl->ic_ops->i2c_prop_set_f(ctrl->ic_drv, prop,
	    buf, buflen);
	if (ret != I2C_CORE_E_OK) {
		return (i2c_error(err, ret, 0));
	}

	return (true);
}

void
i2c_prop_info_set_perm(i2c_prop_info_t *pi, i2c_prop_perm_t perm)
{
	ui2c_prop_info_t *info = (ui2c_prop_info_t *)pi;

	VERIFY(perm == I2C_PROP_PERM_RO || perm == I2C_PROP_PERM_RW);
	info->upi_perm = perm;
}

void
i2c_prop_info_set_def_u32(i2c_prop_info_t *pi, uint32_t val)
{
	ui2c_prop_info_t *info = (ui2c_prop_info_t *)pi;

	VERIFY(info->upi_type == I2C_PROP_TYPE_U32 ||
	    info->upi_type == I2C_PROP_TYPE_BIT32);
	info->upi_def_len = sizeof (uint32_t);
	bcopy(&val, info->upi_def, sizeof (uint32_t));
}

void
i2c_prop_info_set_range_u32(i2c_prop_info_t *pi, uint32_t min, uint32_t max)
{
	ui2c_prop_info_t *info = (ui2c_prop_info_t *)pi;
	i2c_prop_range_t *range;

	VERIFY(info->upi_type == I2C_PROP_TYPE_U32);
	VERIFY3U(min, <=, max);
	if (info->upi_pos_len + sizeof (i2c_prop_u32_range_t) >
	    sizeof (info->upi_pos)) {
		return;
	}

	info->upi_pos_len += sizeof (i2c_prop_u32_range_t);
	range = (i2c_prop_range_t *)info->upi_pos;
	VERIFY(range->ipr_type == I2C_PROP_TYPE_U32);
	range->ipr_range[range->ipr_count].ipvr_u32.ipur_min = min;
	range->ipr_range[range->ipr_count].ipvr_u32.ipur_max = max;
	range->ipr_count++;
}

void
i2c_prop_info_set_pos_bit32(i2c_prop_info_t *pi, uint32_t val)
{
	ui2c_prop_info_t *info = (ui2c_prop_info_t *)pi;
	i2c_prop_range_t *range;

	VERIFY(info->upi_type == I2C_PROP_TYPE_U32 ||
	    info->upi_type == I2C_PROP_TYPE_BIT32);
	CTASSERT(sizeof (i2c_prop_range_t) + sizeof (uint32_t) <
	    sizeof (info->upi_pos));
	info->upi_pos_len = sizeof (i2c_prop_range_t) + sizeof (uint32_t);
	range = (i2c_prop_range_t *)info->upi_pos;
	VERIFY(range->ipr_type == I2C_PROP_TYPE_BIT32);
	range->ipr_count = 1;
	range->ipr_range[0].ipvr_bit32 = val;
}

const char *
i2c_prop_name(i2c_prop_t prop)
{
	const i2c_prop_table_t *table = i2c_prop_find(prop);
	if (table == NULL) {
		return (NULL);
	}

	return (table->ipt_name);
}
