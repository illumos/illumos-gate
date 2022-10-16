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
 * Copyright 2022 Oxide Computer Company
 */

/*
 * This is a simulator driver for the GPIO subsystem that exists for testing
 * purposes.
 */

#include <sys/types.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/stat.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/cmn_err.h>
#include <sys/sysmacros.h>
#include <sys/stdbool.h>

#include <sys/gpio/gpio_sim.h>
#include <sys/gpio/kgpio_provider.h>

typedef enum {
	/*
	 * Use specific pull strengths
	 */
	GPIO_SIM_F_USE_PS	= 1 << 0,
	/*
	 * Treat as open drain, limiting output options
	 */
	GPIO_SIM_F_OPEN_DRAIN	= 1 << 1,
	/*
	 * Indicates that this is something whose input should toggle when we
	 * run our periodic if the output is disabled.
	 */
	GPIO_SIM_F_PERIODIC	= 1 << 2
} gpio_sim_flags_t;

typedef struct gpio_sim_info {
	const char *gsp_name;
	gpio_sim_output_t gsp_output;
	gpio_sim_input_t gsp_input;
	gpio_sim_pull_t gsp_pull;
	gpio_sim_voltage_t gsp_volt;
	gpio_sim_speed_t gsp_speed;
	/* This controls which set of pull up values we say are valid */
	gpio_sim_flags_t gsp_flags;
} gpio_sim_pin_t;

/*
 * This is the initial table of GPIOs that exist in the driver and are then
 * copied into each instances state so that way they can modify their state.
 */
static const gpio_sim_pin_t gpio_sim_pins[] = {
	{ "1v8", GPIO_SIM_OUTPUT_DISABLED, GPIO_SIM_INPUT_HIGH,
	    GPIO_SIM_PULL_UP_40K, GPIO_SIM_VOLTAGE_1P8, GPIO_SIM_SPEED_LOW,
	    GPIO_SIM_F_USE_PS },
	{ "3v3", GPIO_SIM_OUTPUT_DISABLED, GPIO_SIM_INPUT_LOW,
	    GPIO_SIM_PULL_DOWN, GPIO_SIM_VOLTAGE_3P3, GPIO_SIM_SPEED_LOW,
	    0 },
	{ "12V", GPIO_SIM_OUTPUT_HIGH, GPIO_SIM_INPUT_HIGH,
	    GPIO_SIM_PULL_DISABLED, GPIO_SIM_VOLTAGE_12P0,
	    GPIO_SIM_SPEED_MEDIUM, 0 },
	{ "54V", GPIO_SIM_OUTPUT_LOW, GPIO_SIM_INPUT_LOW,
	    GPIO_SIM_PULL_DOWN_23K, GPIO_SIM_VOLTAGE_54P5,
	    GPIO_SIM_SPEED_VERY_HIGH, GPIO_SIM_F_USE_PS },
	{ "periodic-500ms", GPIO_SIM_OUTPUT_DISABLED, GPIO_SIM_INPUT_LOW,
	    GPIO_SIM_PULL_DISABLED, GPIO_SIM_VOLTAGE_1P8, GPIO_SIM_SPEED_LOW,
	    GPIO_SIM_F_PERIODIC },
	{ "open-drain", GPIO_SIM_OUTPUT_DISABLED, GPIO_SIM_INPUT_HIGH,
	    GPIO_SIM_PULL_DISABLED, GPIO_SIM_VOLTAGE_1P8, GPIO_SIM_SPEED_MEDIUM,
	    GPIO_SIM_F_OPEN_DRAIN },
};

typedef struct gpio_sim {
	dev_info_t *gs_dip;
	uint32_t gs_npins;
	kmutex_t gs_mutex;
	gpio_sim_pin_t *gs_pins;
	ddi_periodic_t gs_period;
} gpio_sim_t;

static void *gpio_sim_state;

/*
 * This basically simulates an "interrupt" that has occurred and changed the
 * state of the periodic pin. In the future, when we have the ability to tell
 * the framework that an interrupt has occurred that should cause a poll event
 * to happen, we should call back into it -- but we must not hold our locks
 * across that.
 */
static void
gpio_sim_periodic(void *arg)
{
	gpio_sim_t *gs = arg;

	mutex_enter(&gs->gs_mutex);
	for (uint32_t i = 0; i < gs->gs_npins; i++) {
		gpio_sim_pin_t *pin = &gs->gs_pins[i];
		if ((pin->gsp_flags & GPIO_SIM_F_PERIODIC) == 0 ||
		    pin->gsp_output != GPIO_SIM_OUTPUT_DISABLED) {
			continue;
		}

		if (pin->gsp_input == GPIO_SIM_INPUT_LOW) {
			pin->gsp_input = GPIO_SIM_INPUT_HIGH;
		} else {
			pin->gsp_input = GPIO_SIM_INPUT_LOW;
		}
	}
	mutex_exit(&gs->gs_mutex);
}

static void
gpio_sim_update_input(gpio_sim_pin_t *pin)
{
	switch (pin->gsp_output) {
	case GPIO_SIM_OUTPUT_DISABLED:
		if ((pin->gsp_flags & GPIO_SIM_F_OPEN_DRAIN) != 0) {
			pin->gsp_input = GPIO_SIM_INPUT_HIGH;
			break;
		}

		switch (pin->gsp_pull) {
		case GPIO_SIM_PULL_UP:
		case GPIO_SIM_PULL_UP_5K:
		case GPIO_SIM_PULL_UP_40K:
			pin->gsp_input = GPIO_SIM_INPUT_HIGH;
			break;
		case GPIO_SIM_PULL_BOTH:
		case GPIO_SIM_PULL_DISABLED:
		case GPIO_SIM_PULL_DOWN:
		case GPIO_SIM_PULL_DOWN_23K:
		default:
			pin->gsp_input = GPIO_SIM_INPUT_LOW;
			break;
		}
		break;
	case GPIO_SIM_OUTPUT_LOW:
		pin->gsp_input = GPIO_SIM_INPUT_LOW;
		break;
	case GPIO_SIM_OUTPUT_HIGH:
		pin->gsp_input = GPIO_SIM_INPUT_HIGH;
		break;
	default:
		break;
	}
}

static int
gpio_sim_op_name2id(void *arg, const char *name, uint32_t *idp)
{
	gpio_sim_t *gs = arg;

	for (uint32_t i = 0; i < gs->gs_npins; i++) {
		if (strcmp(name, gs->gs_pins[i].gsp_name) == 0) {
			*idp = i;
			return (0);
		}
	}

	return (ENOENT);
}

static int
gpio_sim_op_attr_get(void *arg, uint32_t gpio_id, nvlist_t *nvl)
{
	gpio_sim_pin_t *pin;
	nvlist_t *meta;

	gpio_sim_t *gs = arg;
	gpio_sim_output_t output_od[2] = { GPIO_SIM_OUTPUT_DISABLED,
	    GPIO_SIM_OUTPUT_LOW };
	gpio_sim_output_t output_pp[3] = { GPIO_SIM_OUTPUT_DISABLED,
	    GPIO_SIM_OUTPUT_LOW, GPIO_SIM_OUTPUT_HIGH };
	gpio_sim_input_t inputs[2] = { GPIO_SIM_INPUT_LOW,
	    GPIO_SIM_INPUT_HIGH };
	gpio_sim_pull_t pulls_nops[4] = { GPIO_SIM_PULL_DISABLED,
	    GPIO_SIM_PULL_DOWN, GPIO_SIM_PULL_UP, GPIO_SIM_PULL_BOTH };
	gpio_sim_pull_t pulls_ps[4] = { GPIO_SIM_PULL_DISABLED,
	    GPIO_SIM_PULL_DOWN_23K, GPIO_SIM_PULL_UP_5K, GPIO_SIM_PULL_UP_40K };
	gpio_sim_speed_t speeds[4] = { GPIO_SIM_SPEED_LOW,
	    GPIO_SIM_SPEED_MEDIUM, GPIO_SIM_SPEED_HIGH,
	    GPIO_SIM_SPEED_VERY_HIGH };

	pin = &gs->gs_pins[gpio_id];
	meta = fnvlist_alloc();

	mutex_enter(&gs->gs_mutex);
	kgpio_nvl_attr_fill_str(nvl, meta, KGPIO_ATTR_NAME, pin->gsp_name, 0,
	    NULL, KGPIO_PROT_RO);
	if ((pin->gsp_flags & GPIO_SIM_F_OPEN_DRAIN) != 0) {
		kgpio_nvl_attr_fill_u32(nvl, meta, GPIO_SIM_ATTR_OUTPUT,
		    pin->gsp_output, ARRAY_SIZE(output_od), output_od,
		    KGPIO_PROT_RW);
	} else {
		kgpio_nvl_attr_fill_u32(nvl, meta, GPIO_SIM_ATTR_OUTPUT,
		    pin->gsp_output, ARRAY_SIZE(output_pp), output_pp,
		    KGPIO_PROT_RW);
	}
	kgpio_nvl_attr_fill_u32(nvl, meta, GPIO_SIM_ATTR_INPUT,
	    pin->gsp_input, ARRAY_SIZE(inputs), inputs, KGPIO_PROT_RO);
	if ((pin->gsp_flags & GPIO_SIM_F_USE_PS) != 0) {
		kgpio_nvl_attr_fill_u32(nvl, meta, GPIO_SIM_ATTR_PULL,
		    pin->gsp_pull, ARRAY_SIZE(pulls_ps), pulls_ps,
		    KGPIO_PROT_RW);
	} else {
		kgpio_nvl_attr_fill_u32(nvl, meta, GPIO_SIM_ATTR_PULL,
		    pin->gsp_pull, ARRAY_SIZE(pulls_nops), pulls_nops,
		    KGPIO_PROT_RW);
	}
	kgpio_nvl_attr_fill_u32(nvl, meta, GPIO_SIM_ATTR_VOLTAGE, pin->gsp_volt,
	    1, &pin->gsp_volt, KGPIO_PROT_RO);
	kgpio_nvl_attr_fill_u32(nvl, meta, GPIO_SIM_ATTR_SPEED, pin->gsp_speed,
	    ARRAY_SIZE(speeds), speeds, KGPIO_PROT_RW);

	mutex_exit(&gs->gs_mutex);

	fnvlist_add_nvlist(nvl, KGPIO_ATTR_META, meta);
	fnvlist_free(meta);

	return (0);
}

static bool
gpio_sim_op_attr_set_output(gpio_sim_pin_t *pin, nvpair_t *nvpair,
    nvlist_t *errs)
{
	uint32_t val;

	if (nvpair_value_uint32(nvpair, &val) != 0) {
		fnvlist_add_uint32(errs, nvpair_name(nvpair),
		    (uint32_t)KGPIO_ATTR_ERR_BAD_TYPE);
		return (false);
	}

	switch (val) {
	case GPIO_SIM_OUTPUT_DISABLED:
	case GPIO_SIM_OUTPUT_LOW:
		pin->gsp_output = val;
		break;
	case GPIO_SIM_OUTPUT_HIGH:
		if ((pin->gsp_flags & GPIO_SIM_F_OPEN_DRAIN) != 0) {
			fnvlist_add_uint32(errs, nvpair_name(nvpair),
			    (uint32_t)KGPIO_ATTR_ERR_CANT_APPLY_VAL);
			return (false);
		}
		pin->gsp_output = val;
		break;
	default:
		fnvlist_add_uint32(errs, nvpair_name(nvpair),
		    (uint32_t)KGPIO_ATTR_ERR_UNKNOWN_VAL);
		return (false);
	}

	return (true);
}

static bool
gpio_sim_op_attr_set_pull(gpio_sim_pin_t *pin, nvpair_t *nvpair, nvlist_t *errs)
{
	uint32_t val;

	if (nvpair_value_uint32(nvpair, &val) != 0) {
		fnvlist_add_uint32(errs, nvpair_name(nvpair),
		    (uint32_t)KGPIO_ATTR_ERR_BAD_TYPE);
		return (false);
	}

	switch (val) {
	case GPIO_SIM_PULL_DISABLED:
		pin->gsp_pull = val;
		break;
	case GPIO_SIM_PULL_DOWN:
	case GPIO_SIM_PULL_UP:
	case GPIO_SIM_PULL_BOTH:
		if ((pin->gsp_flags & GPIO_SIM_F_USE_PS) != 0) {
			fnvlist_add_uint32(errs, nvpair_name(nvpair),
			    (uint32_t)KGPIO_ATTR_ERR_CANT_APPLY_VAL);
			return (false);
		}
		pin->gsp_pull = val;
		break;
	case GPIO_SIM_PULL_DOWN_23K:
	case GPIO_SIM_PULL_UP_5K:
	case GPIO_SIM_PULL_UP_40K:
		if ((pin->gsp_flags & GPIO_SIM_F_USE_PS) == 0) {
			fnvlist_add_uint32(errs, nvpair_name(nvpair),
			    (uint32_t)KGPIO_ATTR_ERR_CANT_APPLY_VAL);
			return (false);
		}
		pin->gsp_pull = val;
		break;
	default:
		fnvlist_add_uint32(errs, nvpair_name(nvpair),
		    (uint32_t)KGPIO_ATTR_ERR_UNKNOWN_VAL);
		return (false);
	}

	return (true);
}

static int
gpio_sim_op_attr_set(void *arg, uint32_t gpio_id, nvlist_t *nvl, nvlist_t *errs)
{
	gpio_sim_t *gs = arg;
	gpio_sim_pin_t *pin, orig;
	bool valid = true;

	mutex_enter(&gs->gs_mutex);
	pin = &gs->gs_pins[gpio_id];
	bcopy(pin, &orig, sizeof (pin));
	for (nvpair_t *nvpair = nvlist_next_nvpair(nvl, NULL); nvpair != NULL;
	    nvpair = nvlist_next_nvpair(nvl, nvpair)) {
		const char *name = nvpair_name(nvpair);

		if (strcmp(name, KGPIO_ATTR_NAME) == 0 ||
		    strcmp(name, GPIO_SIM_ATTR_INPUT) == 0 ||
		    strcmp(name, GPIO_SIM_ATTR_VOLTAGE) == 0) {
			fnvlist_add_uint32(errs, nvpair_name(nvpair),
			    (uint32_t)KGPIO_ATTR_ERR_ATTR_RO);
			valid = false;
		} else if (strcmp(name, GPIO_SIM_ATTR_OUTPUT) == 0) {
			if (!gpio_sim_op_attr_set_output(pin, nvpair, errs)) {
				valid = false;
			}
		} else if (strcmp(name, GPIO_SIM_ATTR_PULL) == 0) {
			if (!gpio_sim_op_attr_set_pull(pin, nvpair, errs)) {
				valid = false;
			}
		} else if (strcmp(name, GPIO_SIM_ATTR_SPEED) == 0) {
			uint32_t val;

			if (nvpair_value_uint32(nvpair, &val) != 0) {
				fnvlist_add_uint32(errs, nvpair_name(nvpair),
				    (uint32_t)KGPIO_ATTR_ERR_BAD_TYPE);
				valid = false;
				continue;
			}

			switch (val) {
			case GPIO_SIM_SPEED_LOW:
			case GPIO_SIM_SPEED_MEDIUM:
			case GPIO_SIM_SPEED_HIGH:
			case GPIO_SIM_SPEED_VERY_HIGH:
				pin->gsp_speed = val;
				break;
			default:
				fnvlist_add_uint32(errs, nvpair_name(nvpair),
				    (uint32_t)KGPIO_ATTR_ERR_UNKNOWN_VAL);
				valid = false;
				break;
			}
		} else {
			fnvlist_add_uint32(errs, name,
			    (uint32_t)KGPIO_ATTR_ERR_UNKNOWN_ATTR);
			valid = false;
		}
	}

	/*
	 * Because we're modifying things in place rather than building up state
	 * to change in hardware, we need to restore the original pin state if
	 * we found an error.
	 */
	if (!valid) {
		bcopy(&orig, pin, sizeof (pin));
	} else {
		gpio_sim_update_input(pin);
	}

	mutex_exit(&gs->gs_mutex);
	return (valid ? 0 : EINVAL);
}

static int
gpio_sim_op_attr_cap(void *arg, uint32_t gpio_id, dpio_caps_t *caps)
{
	gpio_sim_t *gs = arg;

	*caps = DPIO_C_READ | DPIO_C_WRITE;
	if ((gs->gs_pins[gpio_id].gsp_flags & GPIO_SIM_F_PERIODIC) != 0) {
		*caps |= DPIO_C_POLL;
	}

	return (0);
}

static int
gpio_sim_op_attr_dpio_input(void *arg, uint32_t gpio_id, dpio_input_t *input)
{
	gpio_sim_t *gs = arg;

	mutex_enter(&gs->gs_mutex);
	if (gs->gs_pins[gpio_id].gsp_input == GPIO_SIM_INPUT_HIGH) {
		*input = DPIO_INPUT_HIGH;
	} else {
		*input = DPIO_INPUT_LOW;
	}
	mutex_exit(&gs->gs_mutex);
	return (0);
}

static int
gpio_sim_op_attr_dpio_output_state(void *arg, uint32_t gpio_id,
    dpio_output_t *output)
{
	gpio_sim_t *gs = arg;

	mutex_enter(&gs->gs_mutex);
	switch (gs->gs_pins[gpio_id].gsp_output) {
	case GPIO_SIM_OUTPUT_DISABLED:
		*output = DPIO_OUTPUT_DISABLE;
		break;
	case GPIO_SIM_OUTPUT_LOW:
		*output = DPIO_OUTPUT_LOW;
		break;
	case GPIO_SIM_OUTPUT_HIGH:
		*output = DPIO_OUTPUT_HIGH;
		break;
	default:
		mutex_exit(&gs->gs_mutex);
		return (EIO);
	}
	mutex_exit(&gs->gs_mutex);

	return (0);
}

static int
gpio_sim_op_attr_dpio_output(void *arg, uint32_t gpio_id,
    dpio_output_t output)
{
	gpio_sim_t *gs = arg;
	gpio_sim_pin_t *pin;

	pin = &gs->gs_pins[gpio_id];

	mutex_enter(&gs->gs_mutex);
	switch (output) {
	case DPIO_OUTPUT_DISABLE:
		pin->gsp_output = GPIO_SIM_OUTPUT_DISABLED;
		break;
	case DPIO_OUTPUT_LOW:
		pin->gsp_output = GPIO_SIM_OUTPUT_LOW;
		break;
	case DPIO_OUTPUT_HIGH:
		if ((pin->gsp_flags & GPIO_SIM_F_OPEN_DRAIN) != 0) {
			mutex_exit(&gs->gs_mutex);
			return (ENOTSUP);
		}
		pin->gsp_output = GPIO_SIM_OUTPUT_HIGH;
		break;
	default:
		mutex_exit(&gs->gs_mutex);
		return (EINVAL);
	}

	gpio_sim_update_input(pin);
	mutex_exit(&gs->gs_mutex);

	return (0);
}

static const kgpio_ops_t gpio_sim_ops = {
	.kgo_name2id = gpio_sim_op_name2id,
	.kgo_get = gpio_sim_op_attr_get,
	.kgo_set = gpio_sim_op_attr_set,
	.kgo_cap = gpio_sim_op_attr_cap,
	.kgo_input = gpio_sim_op_attr_dpio_input,
	.kgo_output_state = gpio_sim_op_attr_dpio_output_state,
	.kgo_output = gpio_sim_op_attr_dpio_output
};

static void
gpio_sim_cleanup(gpio_sim_t *gs)
{
	int inst = ddi_get_instance(gs->gs_dip);

	ddi_periodic_delete(gs->gs_period);
	kmem_free(gs->gs_pins, sizeof (gpio_sim_pin_t) * gs->gs_npins);
	mutex_destroy(&gs->gs_mutex);
	ddi_soft_state_free(gpio_sim_state, inst);
}

static int
gpio_sim_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int inst, ret;
	gpio_sim_t *gs;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	inst = ddi_get_instance(dip);
	if (ddi_get_soft_state(gpio_sim_state, inst) != NULL) {
		dev_err(dip, CE_WARN, "dip is already attached?!");
		return (DDI_FAILURE);
	}

	if (ddi_soft_state_zalloc(gpio_sim_state, inst) != 0) {
		dev_err(dip, CE_WARN, "failed to allocate soft state");
		return (DDI_FAILURE);
	}

	gs = ddi_get_soft_state(gpio_sim_state, inst);
	ASSERT3P(gs, !=, NULL);

	gs->gs_npins = ARRAY_SIZE(gpio_sim_pins);
	gs->gs_pins = kmem_alloc(sizeof (gpio_sim_pin_t) * gs->gs_npins,
	    KM_SLEEP);
	bcopy(gpio_sim_pins, gs->gs_pins, sizeof (gpio_sim_pin_t) *
	    gs->gs_npins);
	mutex_init(&gs->gs_mutex, NULL, MUTEX_DRIVER, NULL);
	gs->gs_dip = dip;
	gs->gs_period = ddi_periodic_add(gpio_sim_periodic, gs, MSEC2NSEC(500),
	    DDI_IPL_0);

	ret = kgpio_register(dip, &gpio_sim_ops, gs, gs->gs_npins);
	if (ret != 0) {
		dev_err(dip, CE_WARN, "failed to register with kgpio "
		    "interface: %d\n", ret);
		gpio_sim_cleanup(gs);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
gpio_sim_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int inst, ret;
	gpio_sim_t *gs;

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	inst = ddi_get_instance(dip);
	gs = ddi_get_soft_state(gpio_sim_state, inst);
	if (gs == NULL) {
		dev_err(dip, CE_WARN, "asked to detach instance with no state");
		return (DDI_FAILURE);
	}

	ASSERT3P(dip, ==, gs->gs_dip);

	ret = kgpio_unregister(gs->gs_dip);
	if (ret != 0) {
		dev_err(dip, CE_WARN, "failed to unregister from kgpio "
		    "framework: %d", ret);
		return (DDI_FAILURE);
	}

	gpio_sim_cleanup(gs);
	return (DDI_SUCCESS);
}

static struct dev_ops gpio_sim_dev_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_identify = nulldev,
	.devo_probe = nulldev,
	.devo_attach = gpio_sim_attach,
	.devo_detach = gpio_sim_detach,
	.devo_reset = nodev,
	.devo_quiesce = ddi_quiesce_not_needed,
};

static struct modldrv gpio_sim_modldrv = {
	.drv_modops = &mod_driverops,
	.drv_linkinfo = "GPIO Simulator Driver",
	.drv_dev_ops = &gpio_sim_dev_ops
};

static struct modlinkage gpio_sim_modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &gpio_sim_modldrv, NULL }
};

int
_init(void)
{
	int ret;

	ret = ddi_soft_state_init(&gpio_sim_state, sizeof (gpio_sim_t), 1);
	if (ret != 0) {
		return (ret);

	}

	ret = mod_install(&gpio_sim_modlinkage);
	if (ret != 0) {
		ddi_soft_state_fini(&gpio_sim_state);
		return (ret);
	}

	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&gpio_sim_modlinkage, modinfop));
}

int
_fini(void)
{
	int ret;

	ret = mod_remove(&gpio_sim_modlinkage);
	if (ret != 0) {
		return (ret);
	}

	ddi_soft_state_fini(&gpio_sim_state);
	return (ret);
}
