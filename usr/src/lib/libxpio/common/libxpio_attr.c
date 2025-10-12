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
 * This file implements all of the access to and manipulating of attributes. An
 * attribute is a thinly veiled reference to the underlying nvlist_t of data
 * that we were given. Attributes are treated as the underlying nvpair data.
 * This gets us out of some allocation bits, but means that we need to always
 * ask for the gpio information itself depending on what we're trying to do as
 * that has a pointer to our nvlist.
 */

#include <strings.h>
#include <sys/gpio/zen_gpio.h>
#include <sys/gpio/gpio_sim.h>
#include <sys/gpio/pca953x.h>
#include <sys/gpio/ltc4306.h>
#include <sys/sysmacros.h>

#include "libxpio_impl.h"

/*
 * These are data tables that exist for each attribute. They provide a general
 * means of mapping between a string and a known uint32_t value. Currently we
 * assume that these strings do not need translation and localization. There
 * should be one table of values which is then wrapped up inside something else.
 */
typedef struct {
	uint32_t xp_val;
	const char *xp_name;
} xpio_pair_t;

static const xpio_pair_t zen_gpio_pad_pairs[] = {
	{ ZEN_GPIO_PAD_TYPE_GPIO, "gpio" },
	{ ZEN_GPIO_PAD_TYPE_SD, "sd" },
	{ ZEN_GPIO_PAD_TYPE_I2C, "i2c" },
	{ ZEN_GPIO_PAD_TYPE_I3C, "i3c" },
	{ 0x00, NULL }
};

static const xpio_pair_t zen_gpio_cap_pairs[] = {
	{ ZEN_GPIO_C_AGPIO, "AGPIO" },
	{ ZEN_GPIO_C_REMOTE, "Remote" },
	{ 0x00, NULL }
};

static const xpio_pair_t zen_gpio_driver_pairs[] = {
	{ ZEN_GPIO_DRIVER_UNKNOWN, "unknown" },
	{ ZEN_GPIO_DRIVER_PUSH_PULL, "push-pull" },
	{ ZEN_GPIO_DRIVER_OPEN_DRAIN, "open-drain" },
	{ 0x00, NULL }
};

static const xpio_pair_t zen_gpio_output_pairs[] = {
	{ ZEN_GPIO_OUTPUT_DISABLED, "disabled" },
	{ ZEN_GPIO_OUTPUT_LOW, "low" },
	{ ZEN_GPIO_OUTPUT_HIGH, "high" },
	{ 0x00, NULL }
};

static const xpio_pair_t zen_gpio_input_pairs[] = {
	{ ZEN_GPIO_INPUT_LOW, "low" },
	{ ZEN_GPIO_INPUT_HIGH, "high" },
	{ 0x00, NULL }
};

static const xpio_pair_t zen_gpio_voltage_pairs[] = {
	{ ZEN_GPIO_V_UNKNOWN, "unknown" },
	{ ZEN_GPIO_V_1P1_S3, "1.1V" },
	{ ZEN_GPIO_V_1P8_S5, "1.8V" },
	{ ZEN_GPIO_V_1P8_S0, "1.8V" },
	{ ZEN_GPIO_V_3P3_S5, "3.3V" },
	{ ZEN_GPIO_V_3P3_S0, "3.3V" },
	{ 0x00, NULL }
};

static const xpio_pair_t zen_gpio_pull_pairs[] = {
	{ ZEN_GPIO_PULL_DISABLED, "disabled" },
	{ ZEN_GPIO_PULL_DOWN, "down" },
	{ ZEN_GPIO_PULL_UP_4K, "4k-up" },
	{ ZEN_GPIO_PULL_UP_8K, "8k-up" },
	{ ZEN_GPIO_PULL_UP, "up" },
	{ ZEN_GPIO_PULL_DOWN_UP, "up|down" },
	{ ZEN_GPIO_PULL_DOWN_UP_4K, "4k-up|down" },
	{ ZEN_GPIO_PULL_DOWN_UP_8K, "8k-up|down" },
	{ 0x00, NULL }
};

static const xpio_pair_t zen_gpio_drive_pairs[] = {
	{ ZEN_GPIO_DRIVE_UNKNOWN, "unknown" },
	{ ZEN_GPIO_DRIVE_40R, "40R" },
	{ ZEN_GPIO_DRIVE_60R, "60R" },
	{ ZEN_GPIO_DRIVE_80R, "80R" },
	{ 0x00, NULL }
};

static const xpio_pair_t zen_gpio_dbt_mode_pairs[] = {
	{ ZEN_GPIO_DEBOUNCE_MODE_NONE, "none" },
	{ ZEN_GPIO_DEBOUNCE_MODE_KEEP_LOW, "keep-low-glitch" },
	{ ZEN_GPIO_DEBOUNCE_MODE_KEEP_HIGH, "keep-high-glitch" },
	{ ZEN_GPIO_DEBOUNCE_MODE_REMOVE, "remove-glitch" },
	{ 0x00, NULL }
};

static const xpio_pair_t zen_gpio_dbt_unit_pairs[] = {
	{ ZEN_GPIO_DEBOUNCE_UNIT_2RTC, "61us" },
	{ ZEN_GPIO_DEBOUNCE_UNIT_8RTC, "244us" },
	{ ZEN_GPIO_DEBOUNCE_UNIT_512RTC, "15.6ms" },
	{ ZEN_GPIO_DEBOUNCE_UNIT_2048RTC, "62.5ms" },
	{ 0x00, NULL }
};

static const xpio_pair_t zen_gpio_trigger_mode_pairs[] = {
	{ ZEN_GPIO_TRIGGER_UNKNOWN, "unknown" },
	{ ZEN_GPIO_TRIGGER_EDGE_HIGH, "edge/high" },
	{ ZEN_GPIO_TRIGGER_EDGE_LOW, "edge/low" },
	{ ZEN_GPIO_TRIGGER_EDGE_BOTH, "edge/both" },
	{ ZEN_GPIO_TRIGGER_LEVEL_HIGH, "level/high" },
	{ ZEN_GPIO_TRIGGER_LEVEL_LOW, "level/low" },
	{ 0x00, NULL }
};

static const xpio_pair_t zen_gpio_status_pairs[] = {
	{ ZEN_GPIO_STATUS_WAKE, "wake" },
	{ ZEN_GPIO_STATUS_INTR, "interrupt" },
	{ 0x00, NULL }
};

static const xpio_pair_t gpio_sim_output_pairs[] = {
	{ GPIO_SIM_OUTPUT_DISABLED, "disabled" },
	{ GPIO_SIM_OUTPUT_LOW, "low" },
	{ GPIO_SIM_OUTPUT_HIGH, "high" },
	{ 0x00, NULL }
};

static const xpio_pair_t gpio_sim_input_pairs[] = {
	{ GPIO_SIM_INPUT_LOW, "low" },
	{ GPIO_SIM_INPUT_HIGH, "high" },
	{ 0x00, NULL }
};

static const xpio_pair_t gpio_sim_pull_pairs[] = {
	{ GPIO_SIM_PULL_DISABLED, "disabled" },
	{ GPIO_SIM_PULL_DOWN, "down" },
	{ GPIO_SIM_PULL_DOWN_23K, "23k-down" },
	{ GPIO_SIM_PULL_UP, "up" },
	{ GPIO_SIM_PULL_UP_5K, "5k-up" },
	{ GPIO_SIM_PULL_UP_40K, "40k-up" },
	{ GPIO_SIM_PULL_BOTH, "up|down" },
	{ 0x00, NULL }
};

static const xpio_pair_t gpio_sim_voltage_pairs[] = {
	{ GPIO_SIM_VOLTAGE_1P8, "1.8V" },
	{ GPIO_SIM_VOLTAGE_3P3, "3.3V" },
	{ GPIO_SIM_VOLTAGE_12P0, "12.0V" },
	{ GPIO_SIM_VOLTAGE_54P5, "54.5V" },
	{ 0x00, NULL }
};

static const xpio_pair_t gpio_sim_speed_pairs[] = {
	{ GPIO_SIM_SPEED_LOW, "low" },
	{ GPIO_SIM_SPEED_MEDIUM, "medium" },
	{ GPIO_SIM_SPEED_HIGH, "high" },
	{ GPIO_SIM_SPEED_VERY_HIGH, "very-high" },
	{ 0x00, NULL }
};

static const xpio_pair_t pca953x_input_pairs[] = {
	{ PCA953X_GPIO_INPUT_LOW, "low" },
	{ PCA953X_GPIO_INPUT_HIGH, "high" },
	{ 0x00, NULL }
};

static const xpio_pair_t pca953x_output_pairs[] = {
	{ PCA953X_GPIO_OUTPUT_DISABLED, "disabled" },
	{ PCA953X_GPIO_OUTPUT_LOW, "low" },
	{ PCA953X_GPIO_OUTPUT_HIGH, "high" },
	{ 0x00, NULL }
};

static const xpio_pair_t pca953x_polarity_pairs[] = {
	{ PCA953X_GPIO_POLARITY_NORMAL, "normal" },
	{ PCA953X_GPIO_POLARITY_INVERTED, "inverted" },
	{ 0x00, NULL }
};

static const xpio_pair_t ltc4306_input_pairs[] = {
	{ LTC4306_GPIO_INPUT_LOW, "low" },
	{ LTC4306_GPIO_INPUT_HIGH, "high" },
	{ 0x00, NULL }
};

static const xpio_pair_t ltc4306_output_pairs[] = {
	{ LTC4306_GPIO_OUTPUT_DISABLED, "disabled" },
	{ LTC4306_GPIO_OUTPUT_LOW, "low" },
	{ LTC4306_GPIO_OUTPUT_HIGH, "high" },
	{ 0x00, NULL }
};

static const xpio_pair_t ltc4306_output_mode_pairs[] = {
	{ LTC4306_GPIO_OUTPUT_MODE_PUSH_PULL, "push-pull" },
	{ LTC4306_GPIO_OUTPUT_MODE_OPEN_DRAIN, "open-drain" },
	{ 0x00, NULL }
};

/*
 * These two different functions are intended for different uses. Basically
 * today most attributes that providers expose are semantic enums that describe
 * state. The tostr_f function pointer is intended for when translating from the
 * provider's notion of it to a humans. The tou32_f is intended for translating
 * from a human's notion to a providers. The latter translation still works for
 * properties that are read-only, mainly because it is the provider's job to be
 * the source of truth for what is read-only or not.
 */
typedef bool (*xpio_xlate_tostr_f)(const uint32_t, const xpio_pair_t *, char *,
    size_t);
typedef bool (*xpio_xlate_tou32_f)(const char *, const xpio_pair_t *,
    uint32_t *);

typedef struct {
	const char *xt_name;
	const xpio_pair_t *xt_pairs;
	xpio_xlate_tostr_f xt_xlate_tostr;
	xpio_xlate_tou32_f xt_xlate_tou32;
} xpio_translate_t;

static bool
xpio_attr_xlate_tostr_direct(const uint32_t val, const xpio_pair_t *pairs,
    char *buf, size_t buflen)
{
	for (uint_t i = 0; pairs[i].xp_name != NULL; i++) {
		if (val == pairs[i].xp_val) {
			return (strlcpy(buf, pairs[i].xp_name, buflen) <
			    buflen);
		}
	}
	return (false);
}

static bool
xpio_attr_xlate_tou32_direct(const char *str, const xpio_pair_t *pairs,
    uint32_t *outp)
{
	for (uint_t i = 0; pairs[i].xp_name != NULL; i++) {
		if (strcmp(str, pairs[i].xp_name) == 0) {
			*outp = pairs[i].xp_val;
			return (true);
		}
	}
	return (false);
}

static bool
xpio_attr_xlate_tostr_bitfield(const uint32_t val, const xpio_pair_t *pairs,
    char *buf, size_t buflen)
{
	size_t off = 0;
	bool first = true;

	buf[0] = '\0';
	for (uint_t i = 0; pairs[i].xp_name != NULL; i++) {
		int ret;

		if ((pairs[i].xp_val & val) != pairs[i].xp_val) {
			continue;
		}

		ret = snprintf(buf + off, buflen - off, "%s%s",
		    first ? "" : "|", pairs[i].xp_name);
		if (ret >= (buflen - off)) {
			return (false);
		}
		off += ret;
		first = false;
	}

	return (true);
}

/*
 * We expect a bit field to have a series of strings that are | delineated. This
 * means that we need to search and only look at the portion of the string that
 * matches the '|'. This leads to use needing to check two things for a match:
 *
 *   o That a strncmp() with the found string length matches.
 *   o That the total length indicates the end of the pair's string. This must
 *     be done after the first check as the first check returning zero
 *     effectively gives us a guarantee on the pair's length and that the next
 *     byte is valid.
 */
static bool
xpio_attr_xlate_tou32_bitfield(const char *str, const xpio_pair_t *pairs,
    uint32_t *outp)
{
	*outp = 0;
	bool found = false;

	while (*str != '\0') {
		size_t len;
		const char *pipe = strchr(str, '|');
		bool match = false;

		if (pipe != NULL) {
			len = (uintptr_t)pipe - (uintptr_t)str;
		} else {
			len = strlen(str);
		}

		for (uint_t i = 0; pairs[i].xp_name != NULL; i++) {
			if (strncmp(pairs[i].xp_name, str, len) == 0 &&
			    pairs[i].xp_name[len] == '\0') {
				found = true;
				match = true;
				*outp |= pairs[i].xp_val;
				match = true;
				break;
			}
		}

		if (!match) {
			return (false);
		}

		if (pipe != NULL) {
			str = pipe + 1;
		} else {
			break;
		}
	}

	return (found);
}

static bool
xpio_attr_xlate_tostr_hex(const uint32_t val, const xpio_pair_t *pairs,
    char *buf, size_t buflen)
{
	return (snprintf(buf, buflen, "0x%x", val) < buflen);
}

static bool
xpio_attr_xlate_tou32_hex(const char *str, const xpio_pair_t *pairs,
    uint32_t *outp)
{
	char *eptr;
	unsigned long long l;

	errno = 0;
	l = strtoull(str, &eptr, 0);
	if (errno != 0 || *eptr != '\0' || l > UINT32_MAX) {
		return (false);
	}

	*outp = (uint32_t)l;
	return (true);
}

static const xpio_translate_t xpio_attr_xlates[] = {
	/* zen_gpio(4D) attrs */
	{ ZEN_GPIO_ATTR_PAD_TYPE, zen_gpio_pad_pairs,
	    xpio_attr_xlate_tostr_direct, xpio_attr_xlate_tou32_direct },
	{ ZEN_GPIO_ATTR_CAPS, zen_gpio_cap_pairs,
	    xpio_attr_xlate_tostr_bitfield, xpio_attr_xlate_tou32_bitfield },
	{ ZEN_GPIO_ATTR_OUTPUT_DRIVER, zen_gpio_driver_pairs,
	    xpio_attr_xlate_tostr_direct, xpio_attr_xlate_tou32_direct },
	{ ZEN_GPIO_ATTR_OUTPUT, zen_gpio_output_pairs,
	    xpio_attr_xlate_tostr_direct, xpio_attr_xlate_tou32_direct },
	{ ZEN_GPIO_ATTR_INPUT, zen_gpio_input_pairs,
	    xpio_attr_xlate_tostr_direct, xpio_attr_xlate_tou32_direct },
	{ ZEN_GPIO_ATTR_VOLTAGE, zen_gpio_voltage_pairs,
	    xpio_attr_xlate_tostr_direct, xpio_attr_xlate_tou32_direct },
	{ ZEN_GPIO_ATTR_PULL, zen_gpio_pull_pairs,
	    xpio_attr_xlate_tostr_direct, xpio_attr_xlate_tou32_direct },
	{ ZEN_GPIO_ATTR_DRIVE_STRENGTH, zen_gpio_drive_pairs,
	    xpio_attr_xlate_tostr_direct, xpio_attr_xlate_tou32_direct },
	{ ZEN_GPIO_ATTR_DEBOUNCE_MODE, zen_gpio_dbt_mode_pairs,
	    xpio_attr_xlate_tostr_direct, xpio_attr_xlate_tou32_direct },
	{ ZEN_GPIO_ATTR_DEBOUNCE_UNIT, zen_gpio_dbt_unit_pairs,
	    xpio_attr_xlate_tostr_direct, xpio_attr_xlate_tou32_direct },
	{ ZEN_GPIO_ATTR_DEBOUNCE_COUNT, NULL, xpio_attr_xlate_tostr_hex,
	    xpio_attr_xlate_tou32_hex },
	{ ZEN_GPIO_ATTR_TRIGGER_MODE, zen_gpio_trigger_mode_pairs,
	    xpio_attr_xlate_tostr_direct, xpio_attr_xlate_tou32_direct },
	{ ZEN_GPIO_ATTR_STATUS, zen_gpio_status_pairs,
	    xpio_attr_xlate_tostr_bitfield, xpio_attr_xlate_tou32_bitfield },
	{ ZEN_GPIO_ATTR_RAW_REG, NULL, xpio_attr_xlate_tostr_hex,
	    xpio_attr_xlate_tou32_hex },
	/* gpio_sim(4D) attrs */
	{ GPIO_SIM_ATTR_OUTPUT, gpio_sim_output_pairs,
	    xpio_attr_xlate_tostr_direct, xpio_attr_xlate_tou32_direct },
	{ GPIO_SIM_ATTR_INPUT, gpio_sim_input_pairs,
	    xpio_attr_xlate_tostr_direct, xpio_attr_xlate_tou32_direct },
	{ GPIO_SIM_ATTR_PULL, gpio_sim_pull_pairs,
	    xpio_attr_xlate_tostr_direct, xpio_attr_xlate_tou32_direct },
	{ GPIO_SIM_ATTR_VOLTAGE, gpio_sim_voltage_pairs,
	    xpio_attr_xlate_tostr_direct, xpio_attr_xlate_tou32_direct },
	{ GPIO_SIM_ATTR_SPEED, gpio_sim_speed_pairs,
	    xpio_attr_xlate_tostr_direct, xpio_attr_xlate_tou32_direct },
	/* pca953x(4D) attrs */
	{ PCA953X_GPIO_ATTR_INPUT, pca953x_input_pairs,
	    xpio_attr_xlate_tostr_direct, xpio_attr_xlate_tou32_direct },
	{ PCA953X_GPIO_ATTR_OUTPUT, pca953x_output_pairs,
	    xpio_attr_xlate_tostr_direct, xpio_attr_xlate_tou32_direct },
	{ PCA953X_GPIO_ATTR_POLARITY, pca953x_polarity_pairs,
	    xpio_attr_xlate_tostr_direct, xpio_attr_xlate_tou32_direct },
	/* ltc4306(4D) attrs */
	{ LTC4306_GPIO_ATTR_INPUT, ltc4306_input_pairs,
	    xpio_attr_xlate_tostr_direct, xpio_attr_xlate_tou32_direct },
	{ LTC4306_GPIO_ATTR_OUTPUT, ltc4306_output_pairs,
	    xpio_attr_xlate_tostr_direct, xpio_attr_xlate_tou32_direct },
	{ LTC4306_GPIO_ATTR_OUTPUT_MODE, ltc4306_output_mode_pairs,
	    xpio_attr_xlate_tostr_direct, xpio_attr_xlate_tou32_direct }
};

bool
xpio_gpio_attr_xlate_uint32_to_str(xpio_gpio_info_t *gi, xpio_gpio_attr_t *attr,
    uint32_t val, char *buf, size_t buflen)
{
	const char *name = xpio_gpio_attr_name(gi, attr);

	for (size_t i = 0; i < ARRAY_SIZE(xpio_attr_xlates); i++) {
		if (strcmp(name, xpio_attr_xlates[i].xt_name) != 0)
			continue;

		return (xpio_attr_xlates[i].xt_xlate_tostr(val,
		    xpio_attr_xlates[i].xt_pairs, buf, buflen));
	}

	return (false);
}

bool
xpio_gpio_attr_xlate_to_str(xpio_gpio_info_t *gi, xpio_gpio_attr_t *attr,
    char *buf, size_t buflen)
{
	uint32_t val;

	if (!xpio_gpio_attr_value_uint32(attr, &val)) {
		return (false);
	}

	return (xpio_gpio_attr_xlate_uint32_to_str(gi, attr, val, buf, buflen));
}

xpio_gpio_attr_t *
xpio_gpio_attr_find(xpio_gpio_info_t *gi, const char *name)
{
	nvpair_t *pair;

	if (strcmp(name, KGPIO_ATTR_META) == 0) {
		return (NULL);
	}

	if (nvlist_lookup_nvpair(gi->xgi_nvl, name, &pair) != 0) {
		return (NULL);
	}

	switch (nvpair_type(pair)) {
	case DATA_TYPE_UINT32:
	case DATA_TYPE_STRING:
		break;
	default:
		return (NULL);
	}

	return ((xpio_gpio_attr_t *)pair);
}

xpio_gpio_attr_t *
xpio_gpio_attr_next(xpio_gpio_info_t *gi, xpio_gpio_attr_t *attr)
{
	nvpair_t *pair_in = (nvpair_t *)attr;

	for (;;) {
		nvpair_t *next = nvlist_next_nvpair(gi->xgi_nvl, pair_in);
		if (next == NULL) {
			return (NULL);
		}

		switch (nvpair_type(next)) {
		case DATA_TYPE_UINT32:
		case DATA_TYPE_STRING:
			break;
		default:
			pair_in = next;
			continue;
		}

		if (strcmp(KGPIO_ATTR_META, nvpair_name(next)) == 0) {
			pair_in = next;
			continue;
		}

		return ((xpio_gpio_attr_t *)next);
	}
}

const char *
xpio_gpio_attr_name(xpio_gpio_info_t *gi, xpio_gpio_attr_t *attr)
{
	nvpair_t *pair = (nvpair_t *)attr;
	return (nvpair_name(pair));
}

xpio_attr_type_t
xpio_gpio_attr_type(xpio_gpio_info_t *gi, xpio_gpio_attr_t *attr)
{
	nvpair_t *pair = (nvpair_t *)attr;

	/*
	 * We should only have handed out an nvpair that matches these two types
	 * at this point.
	 */
	switch (nvpair_type(pair)) {
	case DATA_TYPE_UINT32:
		return (XPIO_ATTR_TYPE_UINT32);
	case DATA_TYPE_STRING:
		return (XPIO_ATTR_TYPE_STRING);
	default:
		abort();
	}
}

static const char *
xpio_gpio_attr_type_name(xpio_attr_type_t type)
{
	switch (type) {
	case XPIO_ATTR_TYPE_UINT32:
		return ("XPIO_ATTR_TYPE_UINT32");
	case XPIO_ATTR_TYPE_STRING:
		return ("XPIO_ATTR_TYPE_STRING");
	default:
		abort();
	}
}

bool
xpio_gpio_attr_value_string(xpio_gpio_attr_t *attr, const char **outp)
{
	char *lookup;

	if (nvpair_value_string((nvpair_t *)attr, &lookup) != 0) {
		return (false);
	}

	*outp = lookup;
	return (true);
}

bool
xpio_gpio_attr_value_uint32(xpio_gpio_attr_t *attr, uint32_t *outp)
{
	return (nvpair_value_uint32((nvpair_t *)attr, outp) == 0);
}

void
xpio_gpio_attr_possible_string(xpio_gpio_info_t *gi, xpio_gpio_attr_t *attr,
    const char ***outp, uint_t *countp)
{
	nvlist_t *meta_nvl, *attr_nvl;
	const char *key = nvpair_name((nvpair_t *)attr);
	char **strp;

	*outp = NULL;
	*countp = 0;

	if (nvlist_lookup_nvlist(gi->xgi_nvl, KGPIO_ATTR_META, &meta_nvl) !=
	    0) {
		return;
	}

	if (nvlist_lookup_nvlist(meta_nvl, key, &attr_nvl) != 0) {
		return;
	}

	if (nvlist_lookup_string_array(attr_nvl, KGPIO_ATTR_POS, &strp,
	    countp) != 0) {
		*outp = (const char **)strp;
	}
}

void
xpio_gpio_attr_possible_uint32(xpio_gpio_info_t *gi, xpio_gpio_attr_t *attr,
    uint32_t **outp, uint_t *countp)
{
	nvlist_t *meta_nvl, *attr_nvl;
	const char *key = nvpair_name((nvpair_t *)attr);

	*outp = NULL;
	*countp = 0;

	if (nvlist_lookup_nvlist(gi->xgi_nvl, KGPIO_ATTR_META, &meta_nvl) !=
	    0) {
		return;
	}

	if (nvlist_lookup_nvlist(meta_nvl, key, &attr_nvl) != 0) {
		return;
	}

	(void) nvlist_lookup_uint32_array(attr_nvl, KGPIO_ATTR_POS, outp,
	    countp);
}

xpio_attr_prot_t
xpio_gpio_attr_prot(xpio_gpio_info_t *gi, xpio_gpio_attr_t *attr)
{
	uint32_t prot;
	nvlist_t *meta_nvl, *attr_nvl;
	const char *key = nvpair_name((nvpair_t *)attr);

	if (nvlist_lookup_nvlist(gi->xgi_nvl, KGPIO_ATTR_META, &meta_nvl) !=
	    0) {
		return (XPIO_ATTR_PROT_RO);
	}

	if (nvlist_lookup_nvlist(meta_nvl, key, &attr_nvl) != 0) {
		return (XPIO_ATTR_PROT_RO);
	}

	if (nvlist_lookup_uint32(attr_nvl, KGPIO_ATTR_PROT, &prot) != 0) {
		return (XPIO_ATTR_PROT_RO);
	}

	switch (prot) {
	case KGPIO_PROT_RW:
		return (XPIO_ATTR_PROT_RW);
	case KGPIO_PROT_RO:
	default:
		return (XPIO_ATTR_PROT_RO);
	}
}

bool
xpio_gpio_attr_set_uint32(xpio_gpio_update_t *update, xpio_gpio_attr_t *attr,
    uint32_t val)
{
	int ret;
	xpio_attr_type_t type = xpio_gpio_attr_type(update->xgo_gpio, attr);
	const char *key = xpio_gpio_attr_name(update->xgo_gpio, attr);

	if (type != XPIO_ATTR_TYPE_UINT32) {
		return (xpio_update_error(update, XPIO_UPDATE_ERR_BAD_TYPE, 0,
		    "attribute type for %s is %s, not a uint32", key,
		    xpio_gpio_attr_type_name(type)));
	}

	ret = nvlist_add_uint32(update->xgo_update, key, val);
	switch (ret) {
	case 0:
		return (xpio_update_success(update));
	case ENOMEM:
		return (xpio_update_error(update, XPIO_UPDATE_ERR_NO_MEM, ret,
		    "failed to allocate memory to insert attribute %s into "
		    "update structure", key));
	default:
		return (xpio_update_error(update, XPIO_UPDATE_ERR_INTERNAL, ret,
		    "unexpected internal error while trying to insert "
		    "attribute %s into update structure: %s", key,
		    strerror(ret)));
	}
}

bool
xpio_gpio_attr_set_str(xpio_gpio_update_t *update, xpio_gpio_attr_t *attr,
    const char *val)
{
	int ret;
	xpio_attr_type_t type = xpio_gpio_attr_type(update->xgo_gpio, attr);
	const char *key = xpio_gpio_attr_name(update->xgo_gpio, attr);

	if (type != XPIO_ATTR_TYPE_STRING) {
		return (xpio_update_error(update, XPIO_UPDATE_ERR_BAD_TYPE, 0,
		    "attribute type for %s is %s, not a string", key,
		    xpio_gpio_attr_type_name(type)));
	}

	ret = nvlist_add_string(update->xgo_update, key, val);
	switch (ret) {
	case 0:
		return (xpio_update_success(update));
	case ENOMEM:
		return (xpio_update_error(update, XPIO_UPDATE_ERR_NO_MEM, ret,
		    "failed to allocate memory to insert attribute %s into "
		    "update structure", key));
	default:
		return (xpio_update_error(update, XPIO_UPDATE_ERR_INTERNAL, ret,
		    "unexpected internal error while trying to insert "
		    "attribute %s into update structure: %s", key,
		    strerror(ret)));
	}
}

/*
 * This update path attempts to translate the passed in string into the
 * appropriate attribute type. This is designed for tools that want to work in
 * the more human values that we have for various GPIO attributes.
 */
bool
xpio_gpio_attr_from_str(xpio_gpio_update_t *update, xpio_gpio_attr_t *attr,
    const char *raw_val)
{
	xpio_attr_type_t type = xpio_gpio_attr_type(update->xgo_gpio, attr);
	const char *key = xpio_gpio_attr_name(update->xgo_gpio, attr);

	/*
	 * If the data type for this is a string, then we can just insert the
	 * value as is and there is no need for translation. Otherwise, we must
	 * look at the data type and perform the appropriate translation.
	 */
	if (type == XPIO_ATTR_TYPE_STRING) {
		return (xpio_gpio_attr_set_str(update, attr, raw_val));
	}

	for (size_t i = 0; i < ARRAY_SIZE(xpio_attr_xlates); i++) {
		uint32_t u32;

		if (strcmp(key, xpio_attr_xlates[i].xt_name) != 0)
			continue;
		if (!xpio_attr_xlates[i].xt_xlate_tou32(raw_val,
		    xpio_attr_xlates[i].xt_pairs, &u32)) {
			return (xpio_update_error(update,
			    XPIO_UPDATE_ERR_CANT_XLATE, 0, "failed to  "
			    "translate attribute %s value %s to a uint32",
			    key, raw_val));
		}

		return (xpio_gpio_attr_set_uint32(update, attr, u32));
	}

	return (xpio_update_error(update, XPIO_UPDATE_ERR_INTERNAL, ENOENT,
	    "missing internal translator for attr %s to type %s", key,
	    xpio_gpio_attr_type_name(type)));

}

xpio_gpio_attr_err_t *
xpio_gpio_attr_err_next(xpio_gpio_update_t *update, xpio_gpio_attr_err_t *cur)
{
	nvpair_t *pair_in = (nvpair_t *)cur;

	if (update->xgo_err_nvl == NULL) {
		return (NULL);
	}

	for (;;) {
		nvpair_t *next = nvlist_next_nvpair(update->xgo_err_nvl,
		    pair_in);
		if (next == NULL) {
			return (NULL);
		}

		if (nvpair_type(next) != DATA_TYPE_UINT32) {
			pair_in = next;
			continue;
		}

		return ((xpio_gpio_attr_err_t *)next);
	}
}

const char *
xpio_gpio_attr_err_name(xpio_gpio_attr_err_t *err)
{
	nvpair_t *pair = (nvpair_t *)err;
	return (nvpair_name(pair));
}

xpio_update_err_t
xpio_gpio_attr_err_err(xpio_gpio_attr_err_t *err)
{
	uint32_t val;
	nvpair_t *pair = (nvpair_t *)err;

	if (nvpair_value_uint32(pair, &val) != 0) {
		return (XPIO_UPDATE_ERR_INTERNAL);
	}

	switch (val) {
	case KGPIO_ATTR_ERR_OK:
		return (XPIO_UPDATE_ERR_OK);
	case KGPIO_ATTR_ERR_ATTR_RO:
		return (XPIO_UPDATE_ERR_RO);
	case KGPIO_ATTR_ERR_UNKNOWN_ATTR:
		return (XPIO_UPDATE_ERR_UNKNOWN_ATTR);
	case KGPIO_ATTR_ERR_BAD_TYPE:
		return (XPIO_UPDATE_ERR_BAD_TYPE);
	case KGPIO_ATTR_ERR_UNKNOWN_VAL:
		return (XPIO_UPDATE_ERR_CANT_XLATE);
	case KGPIO_ATTR_ERR_CANT_APPLY_VAL:
		return (XPIO_UPDATE_ERR_CANT_APPLY_VAL);
	default:
		return (XPIO_UPDATE_ERR_INTERNAL);
	}
}
