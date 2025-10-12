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
 * Device driver for the LTC4306 4-channel mux and its 2-channel variant the
 * LTC4305.
 *
 * The two devieces are generally register compatible. The main difference is
 * that several of the bits are reserved the LTC4305 that correspond to
 * downstream busses 3/4 (the datasheet is ones based). In addition, the
 * LTC4306 also supports two GPIOs.
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
#include <sys/gpio/kgpio_provider.h>
#include <sys/gpio/ltc4306.h>

/*
 * LTC4306 registers. Note, we've made up the register names as the datasheet
 * just calls them registers 0-4.
 *
 * Register 0 is the status register. It contains information about the overall
 * device and alerts.
 */
#define	LTC430X_R_STS	0
#define	LTC430X_R_STS_GET_DS_CON(r)	bitx8(r, 7, 7)
#define	LTC430X_R_STS_GET_ALERT(r, a)	bitx8(r, 6 - a, 6 - a)
#define	LTC430X_R_STS_GET_FAIL_CONN(r)	bitx8(r, 2, 2)
#define	LTC430X_R_STS_GET_TO_LATCH(r)	bitx8(r, 1, 1)
#define	LTC430X_R_STS_GET_TO_CUR(r)	bitx8(r, 0, 0)

/*
 * Register 1 contains information about the rise time time accelerator and the
 * GPIO input / output values.
 */
#define	LTC430X_R_GPIO	1
#define	LTC430X_R_GPIO_SET_US_ACCEL(r, v)	bitset8(r, 7, 7, v)
#define	LTC430X_R_GPIO_SET_DS_ACCEL(r, v)	bitset8(r, 6, 6, v)
#define	LTC430X_R_GPIO_SET_OUTPUT(r, idx, v)	bitset8(r, 5 - idx, 5 - idx, v)
#define	LTC430X_R_GPIO_GET_OUTPUT(r, idx)	bitx8(r, 5 - idx, 5 - idx)
#define	LTC430X_R_GPIO_GET_INPUT(r, idx)	bitx8(r, 1 - idx, 1 - idx)

/*
 * Register 2 controls the GPIO input and output type and mode. In addition, it
 * has timeout and connection controls.
 */
#define	LTC430X_R_CFG	2
#define	LTC430X_R_CFG_SET_GPIO_DIR(r, idx, v)	bitset8(r, 7 - idx, 7 - idx, v)
#define	LTC430X_R_CFG_GET_GPIO_DIR(r, idx)	bitx8(r, 7 - idx, 7 - idx)
#define	LTC430X_R_CFG_GPIO_DIR_OUTPUT	0
#define	LTC430X_R_CFG_GPIO_DIR_INPUT	1
#define	LTC430X_R_CFG_SET_CONN_REQ(r, v)	bitset8(r, 5, 5)
#define	LTC430X_R_CFG_SET_GPIO_TYPE(r, idx, v)	bitset8(r, 4 - idx, 4 - idx, v)
#define	LTC430X_R_CFG_GET_GPIO_TYPE(r, idx)	bitx8(r, 4 - idx, 4 - idx)
#define	LTC430X_R_CFG_GPIO_OPEN_DRAIN	0
#define	LTC430X_R_CFG_GPIO_PUSH_PULL	1
#define	LTC430X_R_CFG_SET_MASS_WRITE(r, v)	bitset8(r, 2, 2)
#define	LTC430X_R_CFG_SET_TIMEOUT(r, v)		bitset8(r, 1, 0)
#define	LTC430X_R_CFG_TIMEOUT_NONE	0
#define	LTC430X_R_CFG_TIMEOUT_30MS	1
#define	LTC430X_R_CFG_TIMEOUT_15MS	2
#define	LTC430X_R_CFG_TIMEOUT_7P5MS	3

/*
 * Register three controls the actual switch enable and disable, as well as the
 * current state of the bus.
 */
#define	LTC430X_R_SWITCH	3
#define	LTC430X_R_SWITCH_SET_SWITCH(r, idx, v)	bitset8(r, 7 - idx, 7 - idx, v)
#define	LTC430X_R_SWITCH_DISCON		0
#define	LTC430X_R_SWITCH_CON		1
#define	LTC430X_R_SWITCH_GET_STATUS(r, idx)	bitx8(r, 3 - idx, 3 - idx)

static const i2c_reg_acc_attr_t ltc430x_reg_attr = {
	.i2cacc_version = I2C_REG_ACC_ATTR_V0,
	.i2cacc_addr_len = 1,
	.i2cacc_reg_len = 1,
	.i2cacc_addr_max = LTC430X_R_SWITCH
};

typedef struct {
	const char *li_name;
	const char *li_compat;
	uint32_t li_nports;
	uint32_t li_ngpios;
} ltc430x_ident_t;

static const ltc430x_ident_t ltc430x_idents[] = {
	{ "ltc4305", "lltc,ltc4305", 2, 0 },
	{ "ltc4306", "lltc,ltc4306", 4, 2 }
};

typedef struct ltc4306 {
	dev_info_t *ltc_dip;
	const ltc430x_ident_t *ltc_ident;
	i2c_client_t *ltc_client;
	i2c_reg_hdl_t *ltc_regs;
	i2c_mux_hdl_t *ltc_mux;
} ltc430x_t;

static bool
ltc430x_port_enable(void *arg, i2c_txn_t *txn, uint32_t port, uint32_t flags,
    i2c_error_t *err)
{
	uint8_t val;
	ltc430x_t *ltc = arg;

	if (flags != 0) {
		return (i2c_io_error(err, I2C_MUX_E_BAD_FLAG, 0));
	}

	/*
	 * The framework promises us that we're only getting valid ports.
	 */
	VERIFY3U(port, !=, I2C_MUX_PORT_ALL);
	VERIFY3U(port, <, ltc->ltc_ident->li_nports);
	val = LTC430X_R_SWITCH_SET_SWITCH(0, port, LTC430X_R_SWITCH_CON);

	if (!i2c_reg_put(txn, ltc->ltc_regs, LTC430X_R_SWITCH, &val,
	    sizeof (val), err)) {
		return (false);
	}

	return (true);
}

static bool
ltc430x_port_disable(void *arg, i2c_txn_t *txn, uint32_t port, uint32_t flags,
    i2c_error_t *err)
{
	uint8_t val = 0;
	ltc430x_t *ltc = arg;

	if (flags != 0) {
		return (i2c_io_error(err, I2C_MUX_E_BAD_FLAG, 0));
	}

	ASSERT3U(port, ==, I2C_MUX_PORT_ALL);
	for (uint8_t i = 0; i < ltc->ltc_ident->li_nports; i++) {
		val = LTC430X_R_SWITCH_SET_SWITCH(val, i,
		    LTC430X_R_SWITCH_DISCON);
	}

	if (!i2c_reg_put(txn, ltc->ltc_regs, LTC430X_R_SWITCH, &val,
	    sizeof (val), err)) {
		return (false);
	}

	return (true);
}

static const i2c_mux_ops_t ltc430x_mux_ops = {
	.mux_port_name_f = i2c_mux_port_name_portno_1s,
	.mux_port_enable_f = ltc430x_port_enable,
	.mux_port_disable_f = ltc430x_port_disable
};

/*
 * The LTC4306 only has two GPIOs which the datasheet calls GPIO1 and GPIO2.
 * These will map to our two GPIO IDs.
 */
static const char *ltc430x_gpio_names[2] = { "GPIO1", "GPIO2" };

static int
ltc430x_op_name2id(void *arg, const char *name, uint32_t *idp)
{
	for (size_t i = 0; i < ARRAY_SIZE(ltc430x_gpio_names); i++) {
		if (strcmp(ltc430x_gpio_names[i], name) == 0) {
			*idp = i;
			return (0);
		}
	}

	return (ENOENT);
}

static int
ltc430x_gpio_regs_get(ltc430x_t *ltc, i2c_txn_t **txnp, uint8_t *gpiop,
    uint8_t *cfgp)
{
	i2c_error_t err;

	err.i2c_error = i2c_bus_lock(ltc->ltc_client, 0, txnp);
	if (err.i2c_error == I2C_CORE_E_LOCK_WAIT_SIGNAL) {
		return (EINTR);
	} else if (err.i2c_error != I2C_CORE_E_OK) {
		dev_err(ltc->ltc_dip, CE_WARN, "!unexpected i2c error while "
		    "attempting to take bus lock: 0x%x", err.i2c_error);
		return (EIO);
	}

	if (!i2c_reg_get(*txnp, ltc->ltc_regs, LTC430X_R_GPIO, gpiop,
	    sizeof (uint8_t), &err)) {
		i2c_bus_unlock(*txnp);
		*txnp = NULL;
		dev_err(ltc->ltc_dip, CE_WARN, "!failed to read GPIO "
		    "register: 0x%x/0x%x", err.i2c_error, err.i2c_ctrl);
		return (EIO);
	}

	if (!i2c_reg_get(*txnp, ltc->ltc_regs, LTC430X_R_CFG, cfgp,
	    sizeof (uint8_t), &err)) {
		i2c_bus_unlock(*txnp);
		*txnp = NULL;
		dev_err(ltc->ltc_dip, CE_WARN, "!failed to read CFG "
		    "register: 0x%x/0x%x", err.i2c_error, err.i2c_ctrl);
		return (EIO);
	}

	return (0);
}

/*
 * Write GPIO output register values. The hardware requires that these are a
 * series of one byte writes. We always write the GPIO register ahead of the
 * configuration register so that new output values are set ahead of changing
 * whether the register is an input or output.
 */
static int
ltc430x_gpio_regs_put(ltc430x_t *ltc, i2c_txn_t *txn, uint8_t gpio,
    uint8_t ngpio, uint8_t cfg, uint8_t ncfg)
{
	i2c_error_t err;

	if (gpio != ngpio && !i2c_reg_put(txn, ltc->ltc_regs, LTC430X_R_GPIO,
	    &gpio, sizeof (gpio), &err)) {
		dev_err(ltc->ltc_dip, CE_WARN, "!failed to write GPIO "
		    "register: 0x%x/0x%x", err.i2c_error,
		    err.i2c_ctrl);
		return (EIO);
	}

	if (cfg != ncfg && !i2c_reg_put(txn, ltc->ltc_regs, LTC430X_R_CFG,
	    &cfg, sizeof (cfg), &err)) {
		dev_err(ltc->ltc_dip, CE_WARN, "!failed to write CFG"
		    "register: 0x%x/0x%x", err.i2c_error,
		    err.i2c_ctrl);
		return (EIO);
	};

	return (0);
}

static void
ltc430x_gpio_attr_get_name(uint32_t gpio_id, nvlist_t *nvl, nvlist_t *meta,
    uint8_t gpio, uint8_t cfg)
{
	VERIFY3U(gpio_id, <, ARRAY_SIZE(ltc430x_gpio_names));

	kgpio_nvl_attr_fill_str(nvl, meta, KGPIO_ATTR_NAME,
	    ltc430x_gpio_names[gpio_id], 0, NULL, KGPIO_PROT_RO);
}

static void
ltc430x_gpio_attr_get_input(uint32_t gpio_id, nvlist_t *nvl, nvlist_t *meta,
    uint8_t gpio, uint8_t cfg)
{
	ltc4306_gpio_input_t input;
	uint32_t input_pos[2] = { LTC4306_GPIO_INPUT_LOW,
	    LTC4306_GPIO_INPUT_HIGH };

	if (LTC430X_R_GPIO_GET_INPUT(gpio, gpio_id) == 0) {
		input = LTC4306_GPIO_INPUT_LOW;
	} else {
		input = LTC4306_GPIO_INPUT_HIGH;
	}
	kgpio_nvl_attr_fill_u32(nvl, meta, LTC4306_GPIO_ATTR_INPUT, input,
	    ARRAY_SIZE(input_pos), input_pos, KGPIO_PROT_RO);
}

static void
ltc430x_gpio_attr_get_output(uint32_t gpio_id, nvlist_t *nvl, nvlist_t *meta,
    uint8_t gpio, uint8_t cfg)
{
	ltc4306_gpio_output_t output;
	uint32_t output_pos[3] = { LTC4306_GPIO_OUTPUT_DISABLED,
	    LTC4306_GPIO_OUTPUT_LOW, LTC4306_GPIO_OUTPUT_HIGH };

	if (LTC430X_R_CFG_GET_GPIO_DIR(cfg, gpio_id) ==
	    LTC430X_R_CFG_GPIO_DIR_INPUT) {
		output = LTC4306_GPIO_OUTPUT_DISABLED;
	} else if (LTC430X_R_GPIO_GET_OUTPUT(gpio, gpio_id) == 0) {
		output = LTC4306_GPIO_OUTPUT_LOW;
	} else {
		output = LTC4306_GPIO_OUTPUT_HIGH;
	}
	kgpio_nvl_attr_fill_u32(nvl, meta, LTC4306_GPIO_ATTR_OUTPUT, output,
	    ARRAY_SIZE(output_pos), output_pos, KGPIO_PROT_RW);
}

static bool
ltc430x_gpio_attr_set_ro(uint32_t gpio_id, nvpair_t *pair, nvlist_t *errs,
    uint8_t *gpiop, uint8_t *cfgp)
{
	const char *name = nvpair_name(pair);
	fnvlist_add_uint32(errs, name, (uint32_t)KGPIO_ATTR_ERR_ATTR_RO);
	return (false);
}

static void
ltc430x_gpio_attr_get_output_mode(uint32_t gpio_id, nvlist_t *nvl,
    nvlist_t *meta, uint8_t gpio, uint8_t cfg)
{
	ltc4306_gpio_output_mode_t mode;
	uint32_t mode_pos[2] = { LTC4306_GPIO_OUTPUT_MODE_PUSH_PULL,
	    LTC4306_GPIO_OUTPUT_MODE_OPEN_DRAIN };

	if (LTC430X_R_CFG_GET_GPIO_TYPE(cfg, gpio_id) ==
	    LTC430X_R_CFG_GPIO_OPEN_DRAIN) {
		mode = LTC4306_GPIO_OUTPUT_MODE_OPEN_DRAIN;
	} else {
		mode = LTC4306_GPIO_OUTPUT_MODE_PUSH_PULL;
	}
	kgpio_nvl_attr_fill_u32(nvl, meta, LTC4306_GPIO_ATTR_OUTPUT_MODE, mode,
	    ARRAY_SIZE(mode_pos), mode_pos, KGPIO_PROT_RW);
}

static bool
ltc430x_gpio_attr_set_output(uint32_t gpio_id, nvpair_t *pair, nvlist_t *errs,
    uint8_t *gpiop, uint8_t *cfgp)
{
	uint32_t val;

	if (nvpair_value_uint32(pair, &val) != 0) {
		fnvlist_add_uint32(errs, nvpair_name(pair),
		    (uint32_t)KGPIO_ATTR_ERR_BAD_TYPE);
		return (false);
	}

	switch (val) {
	case LTC4306_GPIO_OUTPUT_DISABLED:
		*cfgp = LTC430X_R_CFG_SET_GPIO_DIR(*cfgp, gpio_id,
		    LTC430X_R_CFG_GPIO_DIR_INPUT);
		break;
	case LTC4306_GPIO_OUTPUT_LOW:
		*gpiop = LTC430X_R_GPIO_SET_OUTPUT(*gpiop, gpio_id, 0);
		*cfgp = LTC430X_R_CFG_SET_GPIO_DIR(*cfgp, gpio_id,
		    LTC430X_R_CFG_GPIO_DIR_OUTPUT);
		break;
	case LTC4306_GPIO_OUTPUT_HIGH:
		*gpiop = LTC430X_R_GPIO_SET_OUTPUT(*gpiop, gpio_id, 1);
		*cfgp = LTC430X_R_CFG_SET_GPIO_DIR(*cfgp, gpio_id,
		    LTC430X_R_CFG_GPIO_DIR_OUTPUT);
		break;
	default:
		fnvlist_add_uint32(errs, nvpair_name(pair),
		    (uint32_t)KGPIO_ATTR_ERR_UNKNOWN_VAL);
		return (false);
	}

	return (true);
}

static bool
ltc430x_gpio_attr_set_output_mode(uint32_t gpio_id, nvpair_t *pair,
    nvlist_t *errs, uint8_t *gpiop, uint8_t *cfgp)
{
	uint32_t val;

	if (nvpair_value_uint32(pair, &val) != 0) {
		fnvlist_add_uint32(errs, nvpair_name(pair),
		    (uint32_t)KGPIO_ATTR_ERR_BAD_TYPE);
		return (false);
	}

	switch (val) {
	case LTC4306_GPIO_OUTPUT_MODE_PUSH_PULL:
		*cfgp = LTC430X_R_CFG_SET_GPIO_TYPE(*cfgp, gpio_id,
		    LTC430X_R_CFG_GPIO_PUSH_PULL);
		break;
	case LTC4306_GPIO_OUTPUT_MODE_OPEN_DRAIN:
		*cfgp = LTC430X_R_CFG_SET_GPIO_TYPE(*cfgp, gpio_id,
		    LTC430X_R_CFG_GPIO_OPEN_DRAIN);
		break;
	default:
		fnvlist_add_uint32(errs, nvpair_name(pair),
		    (uint32_t)KGPIO_ATTR_ERR_UNKNOWN_VAL);
		return (false);
	}

	return (true);
}

typedef void (*ltc430x_gpio_attr_get_f)(uint32_t, nvlist_t *, nvlist_t *,
    uint8_t, uint8_t);
typedef bool (*ltc430x_gpio_attr_set_f)(uint32_t, nvpair_t *, nvlist_t *,
    uint8_t *, uint8_t *);

typedef struct {
	const char *lgat_attr;
	ltc430x_gpio_attr_get_f lgat_get;
	ltc430x_gpio_attr_set_f lgat_set;
} ltc430x_gpio_attr_table_t;

static const ltc430x_gpio_attr_table_t ltc430x_gpio_attrs[] = {
	{ KGPIO_ATTR_NAME, ltc430x_gpio_attr_get_name,
	    ltc430x_gpio_attr_set_ro },
	{ LTC4306_GPIO_ATTR_INPUT, ltc430x_gpio_attr_get_input,
	    ltc430x_gpio_attr_set_ro },
	{ LTC4306_GPIO_ATTR_OUTPUT, ltc430x_gpio_attr_get_output,
	    ltc430x_gpio_attr_set_output },
	{ LTC4306_GPIO_ATTR_OUTPUT_MODE, ltc430x_gpio_attr_get_output_mode,
	    ltc430x_gpio_attr_set_output_mode },
};

static int
ltc430x_op_attr_get(void *arg, uint32_t gpio_id, nvlist_t *nvl)
{
	int ret;
	i2c_txn_t *txn;
	uint8_t gpio, cfg;
	ltc430x_t *ltc = arg;

	if ((ret = ltc430x_gpio_regs_get(ltc, &txn, &gpio, &cfg)) != 0) {
		return (ret);
	}

	nvlist_t *meta = fnvlist_alloc();
	for (size_t i = 0; i < ARRAY_SIZE(ltc430x_gpio_attrs); i++) {
		ltc430x_gpio_attrs[i].lgat_get(gpio_id, nvl, meta, gpio, cfg);
	}

	fnvlist_add_nvlist(nvl, KGPIO_ATTR_META, meta);
	fnvlist_free(meta);

	i2c_bus_unlock(txn);
	return (0);
}
static int
ltc430x_op_attr_set(void *arg, uint32_t gpio_id, nvlist_t *nvl, nvlist_t *errs)
{
	int ret;
	i2c_txn_t *txn;
	uint8_t gpio, cfg, ngpio, ncfg;
	ltc430x_t *ltc = arg;
	bool valid = true;

	if ((ret = ltc430x_gpio_regs_get(ltc, &txn, &gpio, &cfg)) != 0) {
		return (ret);
	}

	ngpio = gpio;
	ncfg = cfg;
	for (nvpair_t *nvpair = nvlist_next_nvpair(nvl, NULL); nvpair != NULL;
	    nvpair = nvlist_next_nvpair(nvl, nvpair)) {
		const char *name = nvpair_name(nvpair);

		for (size_t i = 0; i < ARRAY_SIZE(ltc430x_gpio_attrs); i++) {
			if (strcmp(name, ltc430x_gpio_attrs[i].lgat_attr) != 0)
				continue;

			if (!ltc430x_gpio_attrs[i].lgat_set(gpio_id, nvpair,
			    errs, &ngpio, &ncfg)) {
				valid = false;
			}
		}
	}

	if (valid) {
		ret = ltc430x_gpio_regs_put(ltc, txn, gpio, ngpio, cfg, ncfg);
	} else {
		ret = EINVAL;
	}
	i2c_bus_unlock(txn);
	return (ret);
}

static int
ltc430x_op_cap(void *arg, uint32_t gpio_id, dpio_caps_t *caps)
{
	return (DPIO_C_READ | DPIO_C_WRITE);
}

static int
ltc430x_op_dpio_input(void *arg, uint32_t gpio_id, dpio_input_t *input)
{
	i2c_error_t err;
	uint8_t val;
	ltc430x_t *ltc = arg;

	if (!i2c_reg_get(NULL, ltc->ltc_regs, LTC430X_R_GPIO, &val,
	    sizeof (val), &err)) {
		dev_err(ltc->ltc_dip, CE_WARN, "!failed to read GPIO and CFG "
		    "registers: 0x%x/0x%x", err.i2c_error, err.i2c_ctrl);
		return (EIO);
	}

	if (LTC430X_R_GPIO_GET_INPUT(val, gpio_id) == 0) {
		*input = DPIO_INPUT_LOW;
	} else {
		*input = DPIO_INPUT_HIGH;
	}

	return (0);
}

static int
ltc430x_op_dpio_output_state(void *arg, uint32_t gpio_id,
    dpio_output_t *output)
{
	int ret;
	i2c_txn_t *txn;
	uint8_t gpio, cfg;
	ltc430x_t *ltc = arg;

	if ((ret = ltc430x_gpio_regs_get(ltc, &txn, &gpio, &cfg)) != 0) {
		return (ret);
	}

	if (LTC430X_R_CFG_GET_GPIO_DIR(cfg, gpio_id) ==
	    LTC430X_R_CFG_GPIO_DIR_INPUT) {
		*output = DPIO_OUTPUT_DISABLE;
	} else if (LTC430X_R_GPIO_GET_OUTPUT(gpio, gpio_id) == 0) {
		*output = DPIO_OUTPUT_LOW;
	} else {
		*output = DPIO_OUTPUT_HIGH;
	}

	i2c_bus_unlock(txn);
	return (0);
}

static int
ltc430x_op_dpio_output(void *arg, uint32_t gpio_id, dpio_output_t output)
{
	int ret;
	i2c_txn_t *txn;
	uint8_t gpio, cfg, ngpio, ncfg;
	ltc430x_t *ltc = arg;

	if ((ret = ltc430x_gpio_regs_get(ltc, &txn, &gpio, &cfg)) != 0) {
		return (ret);
	}

	switch (output) {
	case DPIO_OUTPUT_LOW:
		ngpio = LTC430X_R_GPIO_SET_OUTPUT(gpio, gpio_id, 0);
		ncfg = LTC430X_R_CFG_SET_GPIO_DIR(cfg, gpio_id,
		    LTC430X_R_CFG_GPIO_DIR_OUTPUT);
		break;
	case DPIO_OUTPUT_HIGH:
		ngpio = LTC430X_R_GPIO_SET_OUTPUT(gpio, gpio_id, 1);
		ncfg = LTC430X_R_CFG_SET_GPIO_DIR(cfg, gpio_id,
		    LTC430X_R_CFG_GPIO_DIR_OUTPUT);
		break;
	case DPIO_OUTPUT_DISABLE:
		ngpio = gpio;
		ncfg = LTC430X_R_CFG_SET_GPIO_DIR(cfg, gpio_id,
		    LTC430X_R_CFG_GPIO_DIR_INPUT);
		break;
	default:
		ret = EINVAL;
		goto out;
	}

	ret = ltc430x_gpio_regs_put(ltc, txn, gpio, ngpio, cfg, ncfg);
out:
	i2c_bus_unlock(txn);
	return (ret);
}

static const kgpio_ops_t ltc430x_gpio_ops = {
	.kgo_name2id = ltc430x_op_name2id,
	.kgo_get = ltc430x_op_attr_get,
	.kgo_set = ltc430x_op_attr_set,
	.kgo_cap = ltc430x_op_cap,
	.kgo_input = ltc430x_op_dpio_input,
	.kgo_output_state = ltc430x_op_dpio_output_state,
	.kgo_output = ltc430x_op_dpio_output
};

static bool
ltc430x_identify(ltc430x_t *ltc)
{
	const char *bind = ddi_binding_name(ltc->ltc_dip);
	const char *name = ddi_node_name(ltc->ltc_dip);

	for (size_t i = 0; i < ARRAY_SIZE(ltc430x_idents); i++) {
		if (strcmp(bind, ltc430x_idents[i].li_name) == 0 ||
		    strcmp(bind, ltc430x_idents[i].li_compat) == 0 ||
		    strcmp(name, ltc430x_idents[i].li_name) == 0 ||
		    strcmp(name, ltc430x_idents[i].li_compat) == 0) {
			ltc->ltc_ident = &ltc430x_idents[i];
			return (true);
		}
	}


	dev_err(ltc->ltc_dip, CE_WARN, "failed to match against node name %s "
	    "and binding name %s", name, bind);
	return (false);
}

static bool
ltc430x_i2c_init(ltc430x_t *ltc)
{
	i2c_errno_t err;

	if ((err = i2c_client_init(ltc->ltc_dip, 0, &ltc->ltc_client)) !=
	    I2C_CORE_E_OK) {
		dev_err(ltc->ltc_dip, CE_WARN, "failed to create i2c client: "
		    "0x%x", err);
		return (false);
	}

	if ((err = i2c_reg_handle_init(ltc->ltc_client, &ltc430x_reg_attr,
	    &ltc->ltc_regs)) != I2C_CORE_E_OK) {
		dev_err(ltc->ltc_dip, CE_WARN, "failed to create register "
		    "handle: %s (0x%x)", i2c_client_errtostr(ltc->ltc_client,
		    err), err);
		return (false);
	}

	return (true);
}

static bool
ltc430x_mux_init(ltc430x_t *ltc)
{
	i2c_mux_reg_error_t ret;
	i2c_mux_register_t *regp;

	ret = i2c_mux_register_alloc(I2C_MUX_PROVIDER, &regp);
	if (ret != I2C_MUX_REG_E_OK) {
		dev_err(ltc->ltc_dip, CE_WARN, "failed to get mux reister "
		    "structure: 0x%x", ret);
		return (false);
	}

	regp->mr_nports = ltc->ltc_ident->li_nports;
	regp->mr_dip = ltc->ltc_dip;
	regp->mr_drv = ltc;
	regp->mr_ops = &ltc430x_mux_ops;

	ret = i2c_mux_register(regp, &ltc->ltc_mux);
	i2c_mux_register_free(regp);
	if (ret != I2C_MUX_REG_E_OK) {
		dev_err(ltc->ltc_dip, CE_WARN, "failed to register with i2c "
		    "mux framework: 0x%x", ret);
		return (false);
	}

	return (true);
}

static bool
ltc430x_gpio_fini(ltc430x_t *ltc)
{
	int ret;

	if (ltc->ltc_ident->li_ngpios == 0) {
		return (true);
	}

	if ((ret = kgpio_unregister(ltc->ltc_dip)) != 0) {
		dev_err(ltc->ltc_dip, CE_WARN, "failed to unregister from "
		    "gpio framework: 0x%x", ret);
		return (false);
	}

	return (true);
}

static bool
ltc430x_gpio_init(ltc430x_t *ltc)
{
	int ret;

	/*
	 * There's nothing to register with if this doesn't actually exist.
	 */
	if (ltc->ltc_ident->li_ngpios == 0) {
		return (true);
	}

	if ((ret = kgpio_register(ltc->ltc_dip, &ltc430x_gpio_ops, ltc,
	    ltc->ltc_ident->li_ngpios)) != 0) {
		dev_err(ltc->ltc_dip, CE_WARN, "failed to register with gpio "
		    "framework: 0x%x", ret);
		return (false);
	}

	return (true);
}

static void
ltc430x_cleanup(ltc430x_t *ltc)
{
	i2c_reg_handle_destroy(ltc->ltc_regs);
	i2c_client_destroy(ltc->ltc_client);
	ddi_set_driver_private(ltc->ltc_dip, NULL);
	ltc->ltc_dip = NULL;
	kmem_free(ltc, sizeof (ltc430x_t));
}

int
ltc430x_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	ltc430x_t *ltc;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	ltc = kmem_zalloc(sizeof (ltc430x_t), KM_SLEEP);
	ltc->ltc_dip = dip;
	ddi_set_driver_private(dip, ltc);

	if (!ltc430x_identify(ltc))
		goto cleanup;

	if (!ltc430x_i2c_init(ltc))
		goto cleanup;

	if (!ltc430x_mux_init(ltc))
		goto cleanup;

	if (!ltc430x_gpio_init(ltc))
		goto cleanup;

	return (DDI_SUCCESS);

cleanup:
	ltc430x_cleanup(ltc);
	return (DDI_FAILURE);
}

int
ltc430x_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	ltc430x_t *ltc;

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	ltc = ddi_get_driver_private(dip);
	if (ltc == NULL) {
		dev_err(dip, CE_WARN, "asked to detach, but missing private "
		    "data");
		return (DDI_FAILURE);
	}
	VERIFY3P(ltc->ltc_dip, ==, dip);

	if (!ltc430x_gpio_fini(ltc)) {
		return (DDI_FAILURE);
	}

	if (i2c_mux_unregister(ltc->ltc_mux) != I2C_MUX_REG_E_OK) {
		/*
		 * We're not actually detaching, so try to register with the
		 * kgpio provider again.
		 */
		(void) ltc430x_gpio_init(ltc);
		return (DDI_FAILURE);
	}

	ltc430x_cleanup(ltc);

	return (DDI_SUCCESS);
}

static struct dev_ops ltc430x_dev_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_identify = nulldev,
	.devo_probe = nulldev,
	.devo_attach = ltc430x_attach,
	.devo_detach = ltc430x_detach,
	.devo_reset = nodev,
	.devo_quiesce = ddi_quiesce_not_needed
};

static struct modldrv ltc430x_modldrv = {
	.drv_modops = &mod_driverops,
	.drv_linkinfo = "LTC4305/6 I2C Mux",
	.drv_dev_ops = &ltc430x_dev_ops
};

static struct modlinkage ltc430x_modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &ltc430x_modldrv, NULL }
};


int
_init(void)
{
	int ret;

	i2c_mux_mod_init(&ltc430x_dev_ops);
	if ((ret = mod_install(&ltc430x_modlinkage)) != 0) {
		i2c_mux_mod_fini(&ltc430x_dev_ops);
	}

	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&ltc430x_modlinkage, modinfop));
}

int
_fini(void)
{
	int ret;

	if ((ret = mod_remove(&ltc430x_modlinkage)) == 0) {
		i2c_mux_mod_fini(&ltc430x_dev_ops);
	}

	return (ret);
}
