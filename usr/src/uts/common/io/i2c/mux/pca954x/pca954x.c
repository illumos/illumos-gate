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
 * Device driver for the PCA954x and compatible devices.
 *
 * The PCA954x is a series of classic I2C switches and muxes with relatively
 * similar programming interfaces. The device is fairly simple. It has a single
 * control register with a number of bits that correspond to each channel. On
 * some families when there are less than 8 channels, some of the upper bits are
 * used for forwarding information about alerts. These are currently not used.
 *
 * The following table summarizes supported device families:
 *
 * DEVICE	PORTS	TYPE		NOTES
 * ------	-----	----		-----
 * PCA9543	2	Switch		Has alert bits in the upper nibble
 * PCA9545	4	Switch		Has alert bits in the upper nibble
 * PCA9546	4	Switch		-
 * PCA9548	8	Switch		-
 * PCA9846	4	Switch		Has device ID register (0x10b)
 * PCA9848	8	Switch		Has device ID register (0x10a)
 *
 * It would also be reasonable in the future to add support for the variants
 * that have an explicit enable field.
 */

#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sysmacros.h>
#include <sys/bitext.h>

#include <sys/i2c/mux.h>
#include <sys/i2c/client.h>

/*
 * The PCA954x family that we suppot is arranged such that it has a single byte
 * control register. There is no index to read or write here. We use the SMBus
 * interface in this driver for simplicity.
 */
#define	PCA_954X_SET_CHAN(r, idx, v)	bitset8(r, idx, idx, v)
#define	PCA_954X_CHAN_DIS	0
#define	PCA_954X_CHAN_EN	1
#define	PCA_954X_GET_INT(r, idx, v)	bitx8(r, idx + 4, idx + 4)

/*
 * This represents the common names that the PCA94x can use. The first name is
 * the common name that an administrator manually creating the device might use.
 * The second is a the compatible-style entry that is commonly found in the wild
 * for the various device trees.
 */
typedef struct {
	const char *pi_name;
	const char *pi_compat;
	uint32_t pi_nports;
	bool pi_intr;
} pca954x_ident_t;

static const pca954x_ident_t pca954x_idents[] = {
	{ "pca9543", "nxp,pca9543", 2, true },
	{ "pca9545", "nxp,pca9545", 4, true },
	{ "pca9546", "nxp,pca9546", 4, false },
	{ "pca9548", "nxp,pca9548", 8, false },
	{ "pca9846", "nxp,pca9846", 4, false },
	{ "pca9848", "nxp,pca9848", 4, false }
};

typedef struct pca954x {
	dev_info_t *pca_dip;
	const pca954x_ident_t *pca_ident;
	i2c_client_t *pca_client;
	i2c_mux_hdl_t *pca_mux;
} pca954x_t;

static bool
pca954x_port_enable(void *arg, i2c_txn_t *txn, uint32_t port, uint32_t flags,
    i2c_error_t *err)
{
	pca954x_t *pca = arg;

	if (flags != 0) {
		return (i2c_io_error(err, I2C_MUX_E_BAD_FLAG, 0));
	}

	VERIFY3U(port, !=, I2C_MUX_PORT_ALL);
	VERIFY3U(port, <, pca->pca_ident->pi_nports);
	uint8_t val = PCA_954X_SET_CHAN(0, port, PCA_954X_CHAN_EN);


	if (!smbus_client_send_byte(txn, pca->pca_client, val, err)) {
		return (false);
	}

	return (true);
}

static bool
pca954x_port_disable(void *arg, i2c_txn_t *txn, uint32_t port, uint32_t flags,
    i2c_error_t *err)
{
	pca954x_t *pca = arg;
	uint8_t val = 0;

	if (flags != 0) {
		return (i2c_io_error(err, I2C_MUX_E_BAD_FLAG, 0));
	}

	VERIFY3U(port, ==, I2C_MUX_PORT_ALL);
	for (uint32_t i = 0; i < pca->pca_ident->pi_nports; i++) {
		val = PCA_954X_SET_CHAN(val, i, PCA_954X_CHAN_DIS);
	}

	if (!smbus_client_send_byte(txn, pca->pca_client, 0, err)) {
		return (false);
	}

	return (true);
}

static const i2c_mux_ops_t pca954x_mux_ops = {
	.mux_port_name_f = i2c_mux_port_name_portno,
	.mux_port_enable_f = pca954x_port_enable,
	.mux_port_disable_f = pca954x_port_disable
};

/*
 * Attempt to match an instance of the driver using the binding name and its
 * actual name itself.
 */
static bool
pca954x_identify(pca954x_t *pca)
{
	const char *bind = ddi_binding_name(pca->pca_dip);
	const char *name = ddi_node_name(pca->pca_dip);

	for (size_t i = 0; i < ARRAY_SIZE(pca954x_idents); i++) {
		if (strcmp(bind, pca954x_idents[i].pi_name) == 0 ||
		    strcmp(bind, pca954x_idents[i].pi_compat) == 0 ||
		    strcmp(name, pca954x_idents[i].pi_name) == 0 ||
		    strcmp(name, pca954x_idents[i].pi_compat) == 0) {
			pca->pca_ident = &pca954x_idents[i];
			return (true);
		}
	}

	dev_err(pca->pca_dip, CE_WARN, "failed to match against node name %s "
	    "and binding name %s", name, bind);
	return (false);
}

static bool
pca954x_i2c_init(pca954x_t *pca)
{
	i2c_errno_t err;

	if ((err = i2c_client_init(pca->pca_dip, 0, &pca->pca_client)) !=
	    I2C_CORE_E_OK) {
		dev_err(pca->pca_dip, CE_WARN, "failed to create i2c client: "
		    "0x%x", err);
		return (false);
	}

	return (true);
}

static bool
pca954x_mux_init(pca954x_t *pca)
{
	i2c_mux_reg_error_t ret;
	i2c_mux_register_t *regp;

	ret = i2c_mux_register_alloc(I2C_MUX_PROVIDER, &regp);
	if (ret != I2C_MUX_REG_E_OK) {
		dev_err(pca->pca_dip, CE_WARN, "failed to get mux reister "
		    "structure: 0x%x", ret);
		return (false);
	}

	regp->mr_nports = pca->pca_ident->pi_nports;
	regp->mr_dip = pca->pca_dip;
	regp->mr_drv = pca;
	regp->mr_ops = &pca954x_mux_ops;

	ret = i2c_mux_register(regp, &pca->pca_mux);
	i2c_mux_register_free(regp);
	if (ret != I2C_MUX_REG_E_OK) {
		dev_err(pca->pca_dip, CE_WARN, "failed to register with i2c "
		    "mux framework: 0x%x", ret);
		return (false);
	}

	return (true);
}

static void
pca954x_cleanup(pca954x_t *pca)
{
	i2c_client_destroy(pca->pca_client);
	ddi_set_driver_private(pca->pca_dip, NULL);
	pca->pca_dip = NULL;
	kmem_free(pca, sizeof (pca954x_t));
}

int
pca954x_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	pca954x_t *pca;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	pca = kmem_zalloc(sizeof (pca954x_t), KM_SLEEP);
	pca->pca_dip = dip;
	ddi_set_driver_private(dip, pca);

	if (!pca954x_identify(pca))
		goto cleanup;

	if (!pca954x_i2c_init(pca))
		goto cleanup;

	if (!pca954x_mux_init(pca))
		goto cleanup;

	return (DDI_SUCCESS);

cleanup:
	pca954x_cleanup(pca);
	return (DDI_FAILURE);
}

int
pca954x_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	pca954x_t *pca;

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	pca = ddi_get_driver_private(dip);
	if (pca == NULL) {
		dev_err(dip, CE_WARN, "asked to detach, but missing private "
		    "data");
		return (DDI_FAILURE);
	}
	VERIFY3P(pca->pca_dip, ==, dip);


	if (i2c_mux_unregister(pca->pca_mux) != I2C_MUX_REG_E_OK) {
		return (DDI_FAILURE);
	}

	pca954x_cleanup(pca);

	return (DDI_SUCCESS);
}

static struct dev_ops pca954x_dev_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_identify = nulldev,
	.devo_probe = nulldev,
	.devo_attach = pca954x_attach,
	.devo_detach = pca954x_detach,
	.devo_reset = nodev,
	.devo_quiesce = ddi_quiesce_not_needed
};

static struct modldrv pca954x_modldrv = {
	.drv_modops = &mod_driverops,
	.drv_linkinfo = "PCA954x I2C Switch",
	.drv_dev_ops = &pca954x_dev_ops
};

static struct modlinkage pca954x_modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &pca954x_modldrv, NULL }
};

int
_init(void)
{
	int ret;

	i2c_mux_mod_init(&pca954x_dev_ops);
	if ((ret = mod_install(&pca954x_modlinkage)) != 0) {
		i2c_mux_mod_fini(&pca954x_dev_ops);
	}

	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&pca954x_modlinkage, modinfop));
}

int
_fini(void)
{
	int ret;

	if ((ret = mod_remove(&pca954x_modlinkage)) == 0) {
		i2c_mux_mod_fini(&pca954x_dev_ops);
	}

	return (ret);
}
