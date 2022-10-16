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

#ifndef _SYS_GPIO_GPIO_SIM_H
#define	_SYS_GPIO_GPIO_SIM_H

/*
 * GPIO Simulator Driver attribute definitions.
 *
 * This driver is purely synthetic, it exists for testing.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * KGPIO_ATTR_NAME -- ro
 *	string
 *
 * This contains the GPIO's name. These names are semantic things that we use to
 * make understanding testing easier.
 */

/*
 * GPIO_SIM_ATTR_OUTPUT -- rw
 *	uint32_t -- gpio_sim_output_t
 *
 * GPIO_SIM_ATTR_INPUT -- ro
 *	uint32_t -- gpio_sim_input_t
 *
 * This pair allows you to set the GPIO's output and then see what the input
 * value is.
 */
#define	GPIO_SIM_ATTR_OUTPUT	"sim:output"
typedef enum {
	GPIO_SIM_OUTPUT_DISABLED,
	GPIO_SIM_OUTPUT_LOW,
	GPIO_SIM_OUTPUT_HIGH
} gpio_sim_output_t;

#define	GPIO_SIM_ATTR_INPUT	"sim:input"
typedef enum {
	GPIO_SIM_INPUT_LOW,
	GPIO_SIM_INPUT_HIGH
} gpio_sim_input_t;

/*
 * To make this somewhat usable, we define an additional three properties that
 * are used to describe information about a GPIO.
 *
 * GPIO_SIM_ATTR_PULL -- rw
 *	uint32_t -- gpio_sim_pull_t
 *
 * This is a synthetic version of the pull-up/down control.
 *
 * GPIO_SIM_ATTR_VOLTAGE -- ro
 *	uint32_t -- gpio_sim_voltage_t
 *
 * This is a synthetic read-only value that we use as part of our testing.
 *
 * GPIO_SIM_ATTR_SPEED -- rw
 *	uint32_t -- gpio_sim_speed_t
 *
 * This would control something like the various rise times exist on a GPIO and
 * is an homage to the fact that everyone wants to set the fastest, but
 * generally you actually want the slowest!
 */
#define	GPIO_SIM_ATTR_PULL	"sim:pull"
typedef enum {
	GPIO_SIM_PULL_DISABLED,
	GPIO_SIM_PULL_DOWN,
	GPIO_SIM_PULL_DOWN_23K,
	GPIO_SIM_PULL_UP,
	GPIO_SIM_PULL_UP_5K,
	GPIO_SIM_PULL_UP_40K,
	GPIO_SIM_PULL_BOTH
} gpio_sim_pull_t;

#define	GPIO_SIM_ATTR_VOLTAGE	"sim:voltage"
typedef enum {
	GPIO_SIM_VOLTAGE_1P8,
	GPIO_SIM_VOLTAGE_3P3,
	GPIO_SIM_VOLTAGE_12P0,
	GPIO_SIM_VOLTAGE_54P5
} gpio_sim_voltage_t;

#define	GPIO_SIM_ATTR_SPEED	"sim:speed"
typedef enum {
	GPIO_SIM_SPEED_LOW,
	GPIO_SIM_SPEED_MEDIUM,
	GPIO_SIM_SPEED_HIGH,
	GPIO_SIM_SPEED_VERY_HIGH
} gpio_sim_speed_t;

#ifdef __cplusplus
}
#endif

#endif /* _SYS_GPIO_GPIO_SIM_H */
