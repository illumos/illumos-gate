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

#ifndef _SYS_GPIO_LTC4306_H
#define	_SYS_GPIO_LTC4306_H

/*
 * LTC4306 driver GPIO attribute definitions.
 *
 * The LTC4306 supports two basic attributes in addition to the standard name
 * attribute KGPIO_ATTR_NAME.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * LTC4306_GPIO_ATTR_INTPUT -- ro
 *	uint32_t -- ltc4306_gpio_input_t
 */
#define	LTC4306_GPIO_ATTR_INPUT		"ltc4306:input"
typedef enum {
	LTC4306_GPIO_INPUT_LOW,
	LTC4306_GPIO_INPUT_HIGH
} ltc4306_gpio_input_t;

/*
 * LTC4306_GPIO_ATTR_OUTPUT -- rw
 *	uint32_t -- ltc4306_gpio_output_t
 *
 * This controls the GPIO's output value. If the GPIO is configured as an input,
 * modifying this will not impact anything. When the output is set to disabled,
 * then the pin is put into an input-only mode.
 */
#define	LTC4306_GPIO_ATTR_OUTPUT	"ltc4306:output"
typedef enum {
	LTC4306_GPIO_OUTPUT_DISABLED,
	LTC4306_GPIO_OUTPUT_LOW,
	LTC4306_GPIO_OUTPUT_HIGH
} ltc4306_gpio_output_t;

/*
 * LTC4306_GPIO_ATTR_OUTPUT_MODE -- rw
 *	uint32_t -- ltc4306_gpio_output_mode_t
 *
 * This controls whether the pin is configured as an open-drain pin or a
 * push-pull.
 */
#define	LTC4306_GPIO_ATTR_OUTPUT_MODE	"ltc4306:output_mode"
typedef enum {
	LTC4306_GPIO_OUTPUT_MODE_PUSH_PULL,
	LTC4306_GPIO_OUTPUT_MODE_OPEN_DRAIN
} ltc4306_gpio_output_mode_t;

#ifdef __cplusplus
}
#endif

#endif /* _SYS_GPIO_LTC4306_H */
