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
 * This file contains misc. utility functions.
 */

#include <sys/ddi.h>
#include <sys/sunddi.h>

#include "i2cnex.h"

void
i2c_port_parent_iter(i2c_port_t *port, i2c_port_f func, void *arg)
{
	for (i2c_nexus_t *nex = port->ip_nex->in_pnex; nex != NULL;
	    nex = nex->in_pnex) {
		if (nex->in_type != I2C_NEXUS_T_PORT)
			continue;
		if (!func(nex->in_data.in_port, arg))
			return;
	}
}

void
i2c_port_iter(i2c_port_t *port, i2c_port_f func, void *arg)
{
	for (i2c_nexus_t *nex = port->ip_nex; nex != NULL; nex = nex->in_pnex) {
		if (nex->in_type != I2C_NEXUS_T_PORT)
			continue;
		if (!func(nex->in_data.in_port, arg))
			return;
	}
}

bool
i2c_dip_is_dev(dev_info_t *dip)
{
	bool ret;
	char *dtype;

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "device_type", &dtype) != DDI_PROP_SUCCESS) {
		return (false);
	}

	ret = strcmp(dtype, "i2c");
	ddi_prop_free(dtype);
	return (ret == 0);
}

/*
 * This translates a device to a dip. It should already have been validated as
 * being an i2c type device. This should panic rather than fail as it means a
 * programmer error has occurred and something bad is going to happen.
 */
i2c_nexus_t *
i2c_dev_to_nexus(dev_info_t *dip)
{
	i2c_nexus_t *nex;

	VERIFY(i2c_dip_is_dev(dip));
	nex = ddi_get_parent_data(dip);
	VERIFY3P(nex, !=, NULL);
	VERIFY3U(nex->in_type, ==, I2C_NEXUS_T_DEV);
	VERIFY3P(nex->in_dip, ==, dip);

	return (nex);
}

/*
 * This is a variant of error setting that is intended for use by controllers
 * drivers. We also have a separate one for muxes and the main internal ones as
 * well. We opt to use different signatures for internal vs. external functions
 * and for each device type so we retain a bit of flexibility at the cost of
 * minor duplication.
 *
 * i2c_ctrl_*: For controllers.
 * i2c_io_*: For muxes and other device types that are both providers and
 * consumers.
 * i2c_error/i2c_success: Internal use in the driver.
 */
void
i2c_ctrl_io_success(i2c_error_t *ep)
{
	ep->i2c_error = I2C_CORE_E_OK;
	ep->i2c_ctrl = I2C_CTRL_E_OK;
}

void
i2c_ctrl_io_error(i2c_error_t *ep, i2c_errno_t err, i2c_ctrl_error_t ctrl)
{
	ep->i2c_error = err;
	ep->i2c_ctrl = ctrl;
}

bool
i2c_io_error(i2c_error_t *errp, i2c_errno_t err, i2c_ctrl_error_t ctrl)
{
	i2c_ctrl_io_error(errp, err, ctrl);
	return (false);
}

bool
i2c_error(i2c_error_t *ioc, i2c_errno_t err, i2c_ctrl_error_t ctrl)
{
	ioc->i2c_error = err;
	ioc->i2c_ctrl = ctrl;

	return (false);
}

void
i2c_success(i2c_error_t *ioc)
{
	ioc->i2c_error = I2C_CORE_E_OK;
	ioc->i2c_ctrl = I2C_CTRL_E_OK;
}
