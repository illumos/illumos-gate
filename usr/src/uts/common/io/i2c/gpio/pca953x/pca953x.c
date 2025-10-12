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
 * GPIO Controller for devices that are in the PCA953x style. These devices have
 * a group of 4 control registers for every 8 bits of GPIOs. These control
 * registers are:
 *
 *  - Input Register: Read-only current value, subject to polarity
 *  - Output Register: Output values
 *  - Polarity Inversion: Controls whether the input/output polarity is inverted
 *  - I/O Configuration: Controls whether the pin is an input or output
 *
 * The devices families change up how these are laid out. For the 4-bit and
 * 8-bit devies such as the PCA9536/7 and PCA9538, these are laid out as
 * registers 0-3. The 4-bit version just ignores the upper bits.
 *
 * For the 16-bit versions such as the PCA9535 and PCA9539, the registers are
 * doubled up. Meaning you have both Input registers at 0/1, both output
 * registers at at 2/3, etc.
 *
 * For the 40-bit PCA9506, this is set up so that all 40-bits for a given device
 * are in a row with reserved registers up to the next 8 byte gap. So input
 * registers cover 0-7, output 8-15, etc.
 */

#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>
#include <sys/bitext.h>

#include <sys/i2c/client.h>
#include <sys/gpio/kgpio_provider.h>
#include <sys/gpio/pca953x.h>

/*
 * These are the logical registers that exist in this series of devices. There
 * are multiple different instances of them and their spacing depends on the
 * device. There is an additional MASK register that is present on some devices,
 * but not all. Currently those are not exposed.
 */
typedef enum {
	PCA953X_R_INPUT	=	0,
	PCA953X_R_OUTPUT,
	PCA953X_R_POLARITY,
	PCA953X_R_CONFIG
} pca953x_regs_t;

#define	PCA953X_R_INPUT_GET_IN(r, idx)		bitx8(r, idx, idx)
#define	PCA953X_R_INPUT_GET_OUT(r, idx)		bitx8(r, idx, idx)
#define	PCA953X_R_INPUT_SET_OUT(r, idx, v)	bitset8(r, idx, idx, v)
#define	PCA953X_R_POLARITY_GET_POL(r, idx)	bitx8(r, idx, idx)
#define	PCA953X_R_POLARITY_SET_POL(r, idx, v)	bitset8(r, idx, idx, v)
#define	PCA953X_R_POLARITY_DEF		0
#define	PCA953X_R_POLARITY_INVERT	0
#define	PCA953X_R_CONFIG_GET_CFG(r, idx)	bitx8(r, idx, idx)
#define	PCA953X_R_CONFIG_SET_CFG(r, idx, v)	bitset8(r, idx, idx, v)
#define	PCA953X_R_CONFIG_OUTPUT		0
#define	PCA953X_R_CONFIG_INPUT		1

typedef struct pca953x_ident {
	const char *pi_name;
	const char *pi_compat;
	/*
	 * Maximum register for the device, inclusive.
	 */
	uint32_t pi_nregs;
	/*
	 * Total number of GPIOs per device.
	 */
	uint32_t pi_ngpios;
	/*
	 * The number of banks of 8 GPIOs between register groups.
	 */
	uint32_t pi_nbanks;
} pca953x_ident_t;

typedef struct pca953x {
	dev_info_t *pca_dip;
	const pca953x_ident_t *pca_ident;
	i2c_client_t *pca_client;
	i2c_reg_hdl_t *pca_regs;
} pca953x_t;

static const pca953x_ident_t pca953x_idents[] = {
	{ "pca9505", "nxp,pca9505", 39, 40, 8 },
	{ "pca9506", "nxp,pca9506", 39, 40, 8 },
	{ "pca9535", "nxp,pca9535", 7, 16, 2 },
	{ "pca9539", "nxp,pca9539", 7, 16, 2 },
};

/*
 * Map a given gpio_id and register to the corrseponding bit and byte. Each
 * register has nbanks worth of reigsters. This may be more than there are
 * GPIOs.
 */
static void
pca953x_gpio_to_reg_bit(const pca953x_t *pca, const uint32_t gpio_id,
    const pca953x_regs_t reg, uint8_t *regp, uint8_t *bitp)
{
	VERIFY3U(gpio_id, <=, UINT8_MAX);
	VERIFY3U(gpio_id, <, pca->pca_ident->pi_ngpios);

	if (bitp != NULL)
		*bitp = gpio_id % NBBY;
	if (regp != NULL)
		*regp = pca->pca_ident->pi_nbanks * reg + gpio_id / NBBY;
}

static int
pca953x_gpio_regs_get(pca953x_t *pca, uint32_t gpio_id, i2c_txn_t **txnp,
    uint8_t *inp, uint8_t *outp, uint8_t *polp, uint8_t *cfgp)
{
	i2c_error_t err;
	uint8_t reg;

	err.i2c_error = i2c_bus_lock(pca->pca_client, 0, txnp);
	if (err.i2c_error == I2C_CORE_E_LOCK_WAIT_SIGNAL) {
		return (EINTR);
	} else if (err.i2c_error != I2C_CORE_E_OK) {
		dev_err(pca->pca_dip, CE_WARN, "!unexpected i2c error while "
		    "attempting to take bus lock: 0x%x", err.i2c_error);
		return (EIO);
	}

	pca953x_gpio_to_reg_bit(pca, gpio_id, PCA953X_R_INPUT, &reg, NULL);
	if (inp != NULL && !i2c_reg_get(*txnp, pca->pca_regs, reg, inp,
	    sizeof (uint8_t), &err)) {
		dev_err(pca->pca_dip, CE_WARN, "!failed to read input "
		    "register 0x%x: 0x%x/0x%x", reg, err.i2c_error,
		    err.i2c_ctrl);
		goto err;
	}

	pca953x_gpio_to_reg_bit(pca, gpio_id, PCA953X_R_OUTPUT, &reg, NULL);
	if (outp != NULL && !i2c_reg_get(*txnp, pca->pca_regs, reg, outp,
	    sizeof (uint8_t), &err)) {
		dev_err(pca->pca_dip, CE_WARN, "!failed to read output "
		    "register 0x%x: 0x%x/0x%x", reg, err.i2c_error,
		    err.i2c_ctrl);
		goto err;
	}

	pca953x_gpio_to_reg_bit(pca, gpio_id, PCA953X_R_POLARITY, &reg, NULL);
	if (polp != NULL && !i2c_reg_get(*txnp, pca->pca_regs, reg, polp,
	    sizeof (uint8_t), &err)) {
		dev_err(pca->pca_dip, CE_WARN, "!failed to read polarity "
		    "register 0x%x: 0x%x/0x%x", reg, err.i2c_error,
		    err.i2c_ctrl);
		goto err;
	}
	pca953x_gpio_to_reg_bit(pca, gpio_id, PCA953X_R_CONFIG, &reg, NULL);
	if (cfgp != NULL && !i2c_reg_get(*txnp, pca->pca_regs, reg, cfgp,
	    sizeof (uint8_t), &err)) {
		dev_err(pca->pca_dip, CE_WARN, "!failed to read config "
		    "register 0x%x: 0x%x/0x%x", reg, err.i2c_error,
		    err.i2c_ctrl);
		goto err;
	}

	return (0);

err:
	i2c_bus_unlock(*txnp);
	*txnp = NULL;
	return (EIO);
}

static int
pca953x_gpio_regs_put(pca953x_t *pca, i2c_txn_t *txn, uint32_t gpio_id,
    uint8_t out, uint8_t nout, uint8_t pol, uint8_t npol, uint8_t cfg,
    uint8_t ncfg)
{
	uint8_t reg;
	i2c_error_t err;

	pca953x_gpio_to_reg_bit(pca, gpio_id, PCA953X_R_OUTPUT, &reg, NULL);
	if (out != nout && i2c_reg_put(txn, pca->pca_regs, reg, &nout,
	    sizeof (uint8_t), &err)) {
		dev_err(pca->pca_dip, CE_WARN, "!failed to write output "
		    "register 0x%x: 0x%x/0x%x", reg, err.i2c_error,
		    err.i2c_ctrl);
		return (EIO);
	}

	pca953x_gpio_to_reg_bit(pca, gpio_id, PCA953X_R_POLARITY, &reg, NULL);
	if (pol != npol && i2c_reg_put(txn, pca->pca_regs, reg, &npol,
	    sizeof (uint8_t), &err)) {
		dev_err(pca->pca_dip, CE_WARN, "!failed to write polarity "
		    "register 0x%x: 0x%x/0x%x", reg, err.i2c_error,
		    err.i2c_ctrl);
		return (EIO);
	}

	pca953x_gpio_to_reg_bit(pca, gpio_id, PCA953X_R_CONFIG, &reg, NULL);
	if (cfg != ncfg && i2c_reg_put(txn, pca->pca_regs, reg, &ncfg,
	    sizeof (uint8_t), &err)) {
		dev_err(pca->pca_dip, CE_WARN, "!failed to write config "
		    "register 0x%x: 0x%x/0x%x", reg, err.i2c_error,
		    err.i2c_ctrl);
		return (EIO);
	}

	return (0);
}

/*
 * The PCA953x family describes GPIO names as IO<BANK>_<BIT>, e.g. IO0_3, IO4_7,
 * etc. We basically try to parse out the bank and bit. <BIT> usually goes from
 * [7:0] but some devices with less GPIOs won't fit there.
 */
static int
pca953x_op_name2id(void *arg, const char *name, uint32_t *idp)
{
	char *eptr;
	u_longlong_t bank, bit;
	const pca953x_t *pca = arg;
	uint32_t gpio;

	if (name[0] != 'I' || name[1] != 'O' || name[2] == '\0') {
		return (ENOENT);
	}

	if (ddi_strtoull(name + 2, &eptr, 10, &bank) != 0 ||
	    *eptr != '_') {
		return (ENOENT);
	}

	if (ddi_strtoull(eptr + 1, &eptr, 10, &bit) != 0 || *eptr != '\0') {
		return (ENOENT);
	}

	if (bank > pca->pca_ident->pi_ngpios / NBBY ||
	    bit >= NBBY) {
		return (ENOENT);
	}

	gpio = bank * NBBY + bit;
	if (gpio > pca->pca_ident->pi_ngpios) {
		return (ENOENT);
	}

	*idp = gpio;
	return (0);
}

static void
pca953x_gpio_attr_get_name(uint32_t gpio, nvlist_t *nvl, nvlist_t *meta,
    uint8_t in, uint8_t out, uint8_t pol, uint8_t cfg)
{
	char buf[32];
	uint8_t bit = gpio % NBBY;
	uint8_t bank = gpio / NBBY;

	(void) snprintf(buf, sizeof (buf), "IO%u_%u", bank, bit);
	kgpio_nvl_attr_fill_str(nvl, meta, KGPIO_ATTR_NAME, buf, 0, NULL,
	    KGPIO_PROT_RO);
}

static void
pca953x_gpio_attr_get_input(uint32_t gpio, nvlist_t *nvl, nvlist_t *meta,
    uint8_t in, uint8_t out, uint8_t pol, uint8_t cfg)
{
	uint8_t bit = gpio % NBBY;
	pca953x_gpio_input_t input;
	uint32_t input_pos[2] = { PCA953X_GPIO_INPUT_LOW,
	    PCA953X_GPIO_INPUT_HIGH };

	if (PCA953X_R_INPUT_GET_IN(in, bit) == 0) {
		input = PCA953X_GPIO_INPUT_LOW;
	} else {
		input = PCA953X_GPIO_INPUT_HIGH;
	}

	kgpio_nvl_attr_fill_u32(nvl, meta, PCA953X_GPIO_ATTR_INPUT, input,
	    ARRAY_SIZE(input_pos), input_pos, KGPIO_PROT_RO);
}

static void
pca953x_gpio_attr_get_output(uint32_t gpio, nvlist_t *nvl, nvlist_t *meta,
    uint8_t in, uint8_t out, uint8_t pol, uint8_t cfg)
{
	uint8_t bit = gpio % NBBY;
	pca953x_gpio_output_t output;
	uint32_t output_pos[3] = { PCA953X_GPIO_OUTPUT_DISABLED,
	    PCA953X_GPIO_OUTPUT_LOW, PCA953X_GPIO_OUTPUT_HIGH };

	if (PCA953X_R_CONFIG_GET_CFG(cfg, bit) == PCA953X_R_CONFIG_INPUT) {
		output = PCA953X_GPIO_OUTPUT_DISABLED;
	} else if (PCA953X_R_INPUT_GET_OUT(out, bit) == 0) {
		output = PCA953X_GPIO_OUTPUT_LOW;
	} else {
		output = PCA953X_GPIO_OUTPUT_HIGH;
	}

	kgpio_nvl_attr_fill_u32(nvl, meta, PCA953X_GPIO_ATTR_OUTPUT, output,
	    ARRAY_SIZE(output_pos), output_pos, KGPIO_PROT_RW);
}

static void
pca953x_gpio_attr_get_polarity(uint32_t gpio, nvlist_t *nvl, nvlist_t *meta,
    uint8_t in, uint8_t out, uint8_t pol, uint8_t cfg)
{
	uint8_t bit = gpio % NBBY;
	pca953x_gpio_polarity_t polarity;
	uint32_t polarity_pos[2] = { PCA953X_GPIO_POLARITY_NORMAL,
	    PCA953X_GPIO_POLARITY_INVERTED };

	if (PCA953X_R_POLARITY_GET_POL(pol, bit) == PCA953X_R_POLARITY_DEF) {
		polarity = PCA953X_GPIO_POLARITY_NORMAL;
	} else {
		polarity = PCA953X_GPIO_POLARITY_INVERTED;
	}

	kgpio_nvl_attr_fill_u32(nvl, meta, PCA953X_GPIO_ATTR_POLARITY, polarity,
	    ARRAY_SIZE(polarity_pos), polarity_pos, KGPIO_PROT_RW);
}

static bool
pca953x_gpio_attr_set_ro(uint8_t bit, nvpair_t *pair, nvlist_t *errs,
    uint8_t *outp, uint8_t *polp, uint8_t *cfgp)
{
	const char *name = nvpair_name(pair);
	fnvlist_add_uint32(errs, name, (uint32_t)KGPIO_ATTR_ERR_ATTR_RO);
	return (false);
}

static bool
pca953x_gpio_attr_set_output(uint8_t bit, nvpair_t *pair, nvlist_t *errs,
    uint8_t *outp, uint8_t *polp, uint8_t *cfgp)
{
	uint32_t val;

	if (nvpair_value_uint32(pair, &val) != 0) {
		fnvlist_add_uint32(errs, nvpair_name(pair),
		    (uint32_t)KGPIO_ATTR_ERR_BAD_TYPE);
		return (false);
	}

	switch (val) {
	case PCA953X_GPIO_OUTPUT_DISABLED:
		*cfgp = PCA953X_R_CONFIG_SET_CFG(*cfgp, bit,
		    PCA953X_R_CONFIG_INPUT);
		break;
	case PCA953X_GPIO_OUTPUT_LOW:
		*cfgp = PCA953X_R_CONFIG_SET_CFG(*cfgp, bit,
		    PCA953X_R_CONFIG_OUTPUT);
		*outp = PCA953X_R_INPUT_SET_OUT(*outp, bit, 0);
		break;
	case PCA953X_GPIO_OUTPUT_HIGH:
		*cfgp = PCA953X_R_CONFIG_SET_CFG(*cfgp, bit,
		    PCA953X_R_CONFIG_OUTPUT);
		*outp = PCA953X_R_INPUT_SET_OUT(*outp, bit, 1);
		break;
	default:
		fnvlist_add_uint32(errs, nvpair_name(pair),
		    (uint32_t)KGPIO_ATTR_ERR_UNKNOWN_VAL);
		return (false);
	}

	return (true);
}

static bool
pca953x_gpio_attr_set_polarity(uint8_t bit, nvpair_t *pair, nvlist_t *errs,
    uint8_t *outp, uint8_t *polp, uint8_t *cfgp)
{
	uint32_t val;

	if (nvpair_value_uint32(pair, &val) != 0) {
		fnvlist_add_uint32(errs, nvpair_name(pair),
		    (uint32_t)KGPIO_ATTR_ERR_BAD_TYPE);
		return (false);
	}

	switch (val) {
	case PCA953X_GPIO_POLARITY_NORMAL:
		*polp = PCA953X_R_POLARITY_SET_POL(*polp, bit,
		    PCA953X_R_POLARITY_DEF);
		break;
	case PCA953X_GPIO_POLARITY_INVERTED:
		*polp = PCA953X_R_POLARITY_SET_POL(*polp, bit,
		    PCA953X_R_POLARITY_INVERT);
		break;
	default:
		fnvlist_add_uint32(errs, nvpair_name(pair),
		    (uint32_t)KGPIO_ATTR_ERR_UNKNOWN_VAL);
		return (false);
	}

	return (true);
}

typedef void (*pca953x_gpio_attr_get_f)(uint32_t, nvlist_t *, nvlist_t *,
    uint8_t, uint8_t, uint8_t, uint8_t);
typedef bool (*pca953x_gpio_attr_set_f)(uint8_t, nvpair_t *, nvlist_t *,
    uint8_t *, uint8_t *, uint8_t *);

typedef struct {
	const char *pgat_attr;
	pca953x_gpio_attr_get_f pgat_get;
	pca953x_gpio_attr_set_f pgat_set;
} pca953x_gpio_attr_table_t;

static const pca953x_gpio_attr_table_t pca953x_gpio_attrs[] = {
	{ KGPIO_ATTR_NAME, pca953x_gpio_attr_get_name,
	    pca953x_gpio_attr_set_ro },
	{ PCA953X_GPIO_ATTR_INPUT, pca953x_gpio_attr_get_input,
	    pca953x_gpio_attr_set_ro },
	{ PCA953X_GPIO_ATTR_OUTPUT, pca953x_gpio_attr_get_output,
	    pca953x_gpio_attr_set_output },
	{ PCA953X_GPIO_ATTR_POLARITY, pca953x_gpio_attr_get_polarity,
	    pca953x_gpio_attr_set_polarity},
};

static int
pca953x_op_attr_get(void *arg, uint32_t gpio_id, nvlist_t *nvl)
{
	int ret;
	i2c_txn_t *txn;
	uint8_t in, out, pol, cfg;
	pca953x_t *pca = arg;

	if ((ret = pca953x_gpio_regs_get(pca, gpio_id, &txn, &in, &out, &pol,
	    &cfg)) != 0) {
		return (ret);
	}

	nvlist_t *meta = fnvlist_alloc();
	for (size_t i = 0; i < ARRAY_SIZE(pca953x_gpio_attrs); i++) {
		pca953x_gpio_attrs[i].pgat_get(gpio_id, nvl, meta, in, out,
		    pol, cfg);
	}

	fnvlist_add_nvlist(nvl, KGPIO_ATTR_META, meta);
	fnvlist_free(meta);

	i2c_bus_unlock(txn);
	return (0);
}

static int
pca953x_op_attr_set(void *arg, uint32_t gpio_id, nvlist_t *nvl, nvlist_t *errs)
{
	int ret;
	i2c_txn_t *txn;
	uint8_t out, pol, cfg, nout, npol, ncfg;
	pca953x_t *pca = arg;
	uint8_t bit = gpio_id % NBBY;
	bool valid = true;

	if ((ret = pca953x_gpio_regs_get(pca, gpio_id, &txn, NULL, &out, &pol,
	    &cfg)) != 0) {
		return (ret);
	}

	nvlist_t *meta = fnvlist_alloc();
	for (nvpair_t *nvpair = nvlist_next_nvpair(nvl, NULL); nvpair != NULL;
	    nvpair = nvlist_next_nvpair(nvl, nvpair)) {
		for (size_t i = 0; i < ARRAY_SIZE(pca953x_gpio_attrs); i++) {
			const char *name = nvpair_name(nvpair);

			if (strcmp(pca953x_gpio_attrs[i].pgat_attr, name) == 0)
				continue;

			if (!pca953x_gpio_attrs[i].pgat_set(bit, nvpair, errs,
			    &nout, &npol, &ncfg)) {
				valid = false;
			}
		}
	}

	if (valid) {
		ret = pca953x_gpio_regs_put(pca, txn, gpio_id, out, nout, pol,
		    npol, cfg, ncfg);
	} else {
		ret = EINVAL;
	}

	fnvlist_add_nvlist(nvl, KGPIO_ATTR_META, meta);
	fnvlist_free(meta);

	i2c_bus_unlock(txn);
	return (0);
}

/*
 * When the broader DPIO framework supports polling more fully, then we can add
 * DPIO_C_POLL here on models that support interrupt notification, if we know
 * how it's wired up (likely itself a GPIO).
 */
static int
pca953x_op_cap(void *arg, uint32_t gpio_id, dpio_caps_t *caps)
{
	return (DPIO_C_READ | DPIO_C_WRITE);
}

static int
pca953x_op_dpio_input(void *arg, uint32_t gpio_id, dpio_input_t *input)
{
	i2c_error_t err;
	uint8_t reg, bit, val;
	pca953x_t *pca = arg;

	pca953x_gpio_to_reg_bit(pca, gpio_id, PCA953X_R_INPUT, &reg, &bit);
	if (!i2c_reg_get(NULL, pca->pca_regs, reg, &val, sizeof (val), &err)) {
		dev_err(pca->pca_dip, CE_WARN, "!failed to read GPIO "
		    "register 0x%x: 0x%x/0x%x", reg, err.i2c_error,
		    err.i2c_ctrl);
		return (EIO);
	}

	if (PCA953X_R_INPUT_GET_IN(val, bit) == 0) {
		*input = DPIO_INPUT_LOW;
	} else {
		*input = DPIO_INPUT_HIGH;
	}

	return (0);
}

static int
pca953x_op_dpio_output_state(void *arg, uint32_t gpio_id,
    dpio_output_t *outputp)
{
	int ret;
	i2c_txn_t *txn;
	uint8_t output, config;
	uint8_t bit = gpio_id % NBBY;
	pca953x_t *pca = arg;

	if ((ret = pca953x_gpio_regs_get(pca, gpio_id, &txn, NULL, &output,
	    NULL, &config)) != 0) {
		return (ret);
	}

	if (PCA953X_R_CONFIG_GET_CFG(config, bit) == PCA953X_R_CONFIG_INPUT) {
		*outputp = DPIO_OUTPUT_DISABLE;
	} else if (PCA953X_R_INPUT_GET_OUT(output, bit) == 0) {
		*outputp = DPIO_OUTPUT_LOW;
	} else {
		*outputp = DPIO_OUTPUT_HIGH;
	}

	i2c_bus_unlock(txn);
	return (0);
}

static int
pca953x_op_dpio_output(void *arg, uint32_t gpio_id, dpio_output_t val)
{
	int ret;
	i2c_txn_t *txn;
	uint8_t out, cfg, nout, ncfg;
	uint8_t bit = gpio_id % NBBY;
	pca953x_t *pca = arg;

	if ((ret = pca953x_gpio_regs_get(pca, gpio_id, &txn, NULL, &out, NULL,
	    &cfg)) != 0) {
		return (ret);
	}

	switch (val) {
	case DPIO_OUTPUT_LOW:
		ncfg = PCA953X_R_CONFIG_SET_CFG(cfg, bit,
		    PCA953X_R_CONFIG_OUTPUT);
		nout = PCA953X_R_INPUT_SET_OUT(out, bit, 0);
		break;
	case DPIO_OUTPUT_HIGH:
		ncfg = PCA953X_R_CONFIG_SET_CFG(cfg, bit,
		    PCA953X_R_CONFIG_OUTPUT);
		nout = PCA953X_R_INPUT_SET_OUT(out, bit, 1);
		break;
	case DPIO_OUTPUT_DISABLE:
		ncfg = PCA953X_R_CONFIG_SET_CFG(cfg, bit,
		    PCA953X_R_CONFIG_INPUT);
		nout = out;
		break;
	default:
		ret = EINVAL;
		goto out;
	}

	ret = pca953x_gpio_regs_put(pca, txn, gpio_id, out, nout,
	    0, 0, cfg, ncfg);
out:
	i2c_bus_unlock(txn);
	return (ret);
}

static const kgpio_ops_t pca953x_gpio_ops = {
	.kgo_name2id = pca953x_op_name2id,
	.kgo_get = pca953x_op_attr_get,
	.kgo_set = pca953x_op_attr_set,
	.kgo_cap = pca953x_op_cap,
	.kgo_input = pca953x_op_dpio_input,
	.kgo_output_state = pca953x_op_dpio_output_state,
	.kgo_output = pca953x_op_dpio_output
};

static bool
pca953x_identify(pca953x_t *pca)
{
	const char *bind = ddi_binding_name(pca->pca_dip);
	const char *name = ddi_node_name(pca->pca_dip);

	for (size_t i = 0; i < ARRAY_SIZE(pca953x_idents); i++) {
		if (strcmp(bind, pca953x_idents[i].pi_name) == 0 ||
		    strcmp(bind, pca953x_idents[i].pi_compat) == 0 ||
		    strcmp(name, pca953x_idents[i].pi_name) == 0 ||
		    strcmp(name, pca953x_idents[i].pi_compat) == 0) {
			pca->pca_ident = &pca953x_idents[i];
			return (true);
		}
	}


	dev_err(pca->pca_dip, CE_WARN, "failed to match against node name %s "
	    "and binding name %s", name, bind);
	return (false);
}

static bool
pca953x_i2c_init(pca953x_t *pca)
{
	i2c_errno_t err;
	i2c_reg_acc_attr_t attr;

	if ((err = i2c_client_init(pca->pca_dip, 0, &pca->pca_client)) !=
	    I2C_CORE_E_OK) {
		dev_err(pca->pca_dip, CE_WARN, "failed to create i2c client: "
		    "0x%x", err);
		return (false);
	}

	bzero(&attr, sizeof (attr));
	attr.i2cacc_version = I2C_REG_ACC_ATTR_V0;
	attr.i2cacc_addr_len = 1;
	attr.i2cacc_reg_len = 1;
	attr.i2cacc_addr_max = pca->pca_ident->pi_nregs;

	if ((err = i2c_reg_handle_init(pca->pca_client, &attr,
	    &pca->pca_regs)) != I2C_CORE_E_OK) {
		dev_err(pca->pca_dip, CE_WARN, "failed to create register "
		    "handle: %s (0x%x)", i2c_client_errtostr(pca->pca_client,
		    err), err);
		return (false);
	}

	return (true);
}

static void
pca953x_cleanup(pca953x_t *pca)
{
	i2c_reg_handle_destroy(pca->pca_regs);
	i2c_client_destroy(pca->pca_client);
	ddi_set_driver_private(pca->pca_dip, NULL);
	pca->pca_dip = NULL;
	kmem_free(pca, sizeof (pca953x_t));
}

int
pca953x_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int ret;
	pca953x_t *pca;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	pca = kmem_zalloc(sizeof (pca953x_t), KM_SLEEP);
	pca->pca_dip = dip;
	ddi_set_driver_private(dip, pca);

	if (!pca953x_identify(pca))
		goto cleanup;

	if (!pca953x_i2c_init(pca))
		goto cleanup;

	if ((ret = kgpio_register(pca->pca_dip, &pca953x_gpio_ops, pca,
	    pca->pca_ident->pi_ngpios)) != 0) {
		dev_err(pca->pca_dip, CE_WARN, "failed to register with gpio "
		    "framework: 0x%x", ret);
		goto cleanup;
	}

	return (DDI_SUCCESS);

cleanup:
	pca953x_cleanup(pca);
	return (DDI_FAILURE);
}

int
pca953x_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int ret;
	pca953x_t *pca;

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

	if ((ret = kgpio_unregister(pca->pca_dip)) != 0) {
		dev_err(pca->pca_dip, CE_WARN, "failed to unregister from "
		    "gpio framework: 0x%x", ret);
		return (DDI_FAILURE);
	}

	pca953x_cleanup(pca);
	return (DDI_SUCCESS);
}

static struct dev_ops pca953x_dev_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_identify = nulldev,
	.devo_probe = nulldev,
	.devo_attach = pca953x_attach,
	.devo_detach = pca953x_detach,
	.devo_reset = nodev,
	.devo_quiesce = ddi_quiesce_not_needed
};

static struct modldrv pca953x_modldrv = {
	.drv_modops = &mod_driverops,
	.drv_linkinfo = "PCA953x GPIO driver",
	.drv_dev_ops = &pca953x_dev_ops
};

static struct modlinkage pca953x_modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &pca953x_modldrv, NULL }
};


int
_init(void)
{
	return (mod_install(&pca953x_modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&pca953x_modlinkage, modinfop));
}

int
_fini(void)
{
	return (mod_remove(&pca953x_modlinkage));
}
