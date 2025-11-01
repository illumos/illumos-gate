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
 * Basic emulation of a PCA9548. We basically only support passing through a
 * single bus so we treat this as a mux. This is definitely a bit of hack.
 */

#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <sys/sysmacros.h>
#include <stdbit.h>
#include <sys/debug.h>

#include "i2csimd.h"

#define	PCA_NPORTS	8

typedef struct pca9548 {
	uint8_t pca_data;
	i2csimd_port_t *pca_root;
	i2csimd_port_t *pca_ports;
} pca9548_t;

/*
 * Only the last byte written is honored as a selection.
 */
static bool
pca9548_write(void *arg, uint32_t len, const uint8_t *buf)
{
	pca9548_t *pca = arg;

	if (len > 0) {
		if (buf[len - 1] == pca->pca_data)
			return (true);

		if (pca->pca_data != 0) {
			uint32_t idx = stdc_first_trailing_one_uc(
			    pca->pca_data) - 1;
			VERIFY3U(idx, <, PCA_NPORTS);
			i2csimd_port_t *port = &pca->pca_ports[idx];

			for (size_t i = 0; i < ARRAY_SIZE(port->port_devs);
			    i++) {
				if (port->port_devs[i] != NULL)
					pca->pca_root->port_devs[i] = NULL;
			}
		}

		pca->pca_data = buf[len - 1];
		if (pca->pca_data != 0) {
			uint32_t idx = stdc_first_trailing_one_uc(
			    pca->pca_data) - 1;
			VERIFY3U(idx, <, PCA_NPORTS);
			i2csimd_port_t *port = &pca->pca_ports[idx];

			for (size_t i = 0; i < ARRAY_SIZE(port->port_devs);
			    i++) {
				if (port->port_devs[i] != NULL)
					pca->pca_root->port_devs[i] =
					    port->port_devs[i];
			}
		}

	}

	return (true);
}

/*
 * It's not clear what happens if we try to read more bytes to one of these, so
 * just pick a bad behavior which is fill the entire buffer.
 */
static bool
pca9548_read(void *arg, uint32_t len, uint8_t *buf)
{
	pca9548_t *pca = arg;

	if (len > 0) {
		(void) memset(buf, pca->pca_data, len);
	}

	return (true);
}

static const i2csimd_ops_t pca9548_ops = {
	.sop_write = pca9548_write,
	.sop_read = pca9548_read
};

i2csimd_dev_t *
i2csimd_make_pca9548(uint8_t addr, i2csimd_port_t *root,
    i2csimd_port_t ports[8])
{
	pca9548_t *pca = calloc(1, sizeof (pca9548_t));
	if (pca == NULL) {
		err(EXIT_FAILURE, "failed to allocate a pca9548_t");
	}
	pca->pca_data = UINT8_MAX;
	pca->pca_root = root;
	pca->pca_ports = ports;

	i2csimd_dev_t *dev = calloc(1, sizeof (i2csimd_dev_t));
	if (dev == NULL) {
		err(EXIT_FAILURE, "failed to allocate i2csimd_dev_t");
	}

	dev->dev_name = "pca9548";
	dev->dev_addr = addr;
	dev->dev_arg = pca;
	dev->dev_ops = &pca9548_ops;

	return (dev);
}
