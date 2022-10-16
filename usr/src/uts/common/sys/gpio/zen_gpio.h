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

#ifndef _SYS_GPIO_ZEN_GPIO_H
#define	_SYS_GPIO_ZEN_GPIO_H

/*
 * AMD Zen GPIO attribute definitions.
 *
 * This covers most attributes for Zen 1 - 4 based GPIOs (and possibly earlier
 * families). Most attributes are passed through for user consumption with a few
 * exceptions right now around interrupt and wake control as those are not
 * things that we expect to be manipulated.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * These five attributes are used to communicate basic identifying information
 * about the GPIO.
 *
 * KGPIO_ATTR_NAME -- ro
 *	string
 *
 * This contains the GPIO's name. This is the GPIO portion of the name that the
 * PPR uses.
 *
 * ZEN_GPIO_ATTR_PAD_NAME -- ro
 *	string
 *
 * This contains the name of the pad that the GPIO uses according to the PPR.
 * This may match the GPIO's name, but may be different.
 *
 * ZEN_GPIO_ATTR_PAD_TYPE -- ro
 *	uint32_t -- zen_gpio_pad_type_t
 *
 * This describes the type of pad that we have.
 *
 * ZEN_GPIO_ATTR_PIN -- ro
 *	string
 *
 * This contains the name of the pin on the socket.
 *
 * ZEN_GPIO_ATTR_CAPS -- ro
 *
 * This contains some of the internal notes on the capabilities the pin
 * theoretially has.
 */
#define	ZEN_GPIO_ATTR_PAD_NAME	"zen:pad_name"
#define	ZEN_GPIO_ATTR_PAD_TYPE	"zen:pad_type"
#define	ZEN_GPIO_ATTR_PIN	"zen:pin"
#define	ZEN_GPIO_ATTR_CAPS	"zen:caps"

typedef enum {
	ZEN_GPIO_PAD_TYPE_GPIO,
	ZEN_GPIO_PAD_TYPE_SD,
	ZEN_GPIO_PAD_TYPE_I2C,
	ZEN_GPIO_PAD_TYPE_I3C
} zen_gpio_pad_type_t;

typedef enum {
	/*
	 * Indicates that the GPIO supports interrupts.
	 */
	ZEN_GPIO_C_AGPIO = 1 << 0,
	/*
	 * Indicates that the GPIO is part of a remote block, which
	 * means more shenanigans to get it to work.
	 */
	ZEN_GPIO_C_REMOTE = 1 << 1
} zen_gpio_cap_t;

/*
 * ZEN_GPIO_ATTR_OUTPUT_DRIVER -- ro
 *	uint32_t -- zen_gpio_driver_mode_t
 *
 * This describes the mode of the output driver for a given GPIO. Note, in Zen 4
 * this is configurable for I3C based GPIOs.
 */
#define	ZEN_GPIO_ATTR_OUTPUT_DRIVER	"zen:output_driver"
typedef enum {
	ZEN_GPIO_DRIVER_UNKNOWN,
	ZEN_GPIO_DRIVER_PUSH_PULL,
	ZEN_GPIO_DRIVER_OPEN_DRAIN
} zen_gpio_driver_mode_t;

/*
 * ZEN_GPIO_ATTR_OUTPUT -- rw
 *	uint32_t -- zen_gpio_output_t
 *
 * This controls what the GPIO's output is. For open-drain style pins, the only
 * options that are valid are disabled and low.
 */
#define	ZEN_GPIO_ATTR_OUTPUT	"zen:output"
typedef enum {
	ZEN_GPIO_OUTPUT_DISABLED,
	ZEN_GPIO_OUTPUT_LOW,
	ZEN_GPIO_OUTPUT_HIGH
} zen_gpio_output_t;

/*
 * ZEN_GPIO_ATTR_INPUT -- ro
 *	uint32_t -- zen_gpio_input_t
 *
 * This describes the current input value of the pin.
 */
#define	ZEN_GPIO_ATTR_INPUT	"zen:input"
typedef enum {
	ZEN_GPIO_INPUT_LOW,
	ZEN_GPIO_INPUT_HIGH
} zen_gpio_input_t;

/*
 * ZEN_GPIO_ATTR_VOLTAGE -- ro
 *	zen_gpio_voltage_t
 *
 * This describes the different type of voltages that a given pin supports.
 * Note, all the pad registers are not driven as part of the GPIO driver and
 * therefore changes to this are not supported (today).
 */
#define	ZEN_GPIO_ATTR_VOLTAGE	"zen:voltage"

typedef enum {
	ZEN_GPIO_V_UNKNOWN = 0,
	ZEN_GPIO_V_1P1_S3 = 1 << 0,
	ZEN_GPIO_V_1P8_S5 = 1 << 1,
	ZEN_GPIO_V_1P8_S0 = 1 << 2,
	ZEN_GPIO_V_3P3_S5 = 1 << 3,
	ZEN_GPIO_V_3P3_S0 = 1 << 4
} zen_gpio_voltage_t;

/*
 * ZEN_GPIO_ATTR_PULL -- rw
 *	uint32_t -- zen_gpio_pull_t
 *
 * This controls the pull and strength of a GPIO. Note, some pins require a
 * strength to be specified where as others do not support this. This varies
 * based on the specific chip and socket.
 */
#define	ZEN_GPIO_ATTR_PULL	"zen:pull"

typedef enum {
	ZEN_GPIO_PULL_DISABLED = 0,
	ZEN_GPIO_PULL_DOWN,
	ZEN_GPIO_PULL_UP_4K,
	ZEN_GPIO_PULL_UP_8K,
	ZEN_GPIO_PULL_UP,
	/*
	 * The following are possible values, but not ones that we allow to be
	 * set. That is, these are illegal combinations, but there is nothing
	 * that stops hardware from being able to shout them at us.
	 */
	ZEN_GPIO_PULL_DOWN_UP,
	ZEN_GPIO_PULL_DOWN_UP_4K,
	ZEN_GPIO_PULL_DOWN_UP_8K
} zen_gpio_pull_t;

/*
 * ZEN_GPIO_ATTR_DRIVE_STRENGTH -- rw
 *	uint32_t -- zen_gpio_drive_strength_t
 */
#define	ZEN_GPIO_ATTR_DRIVE_STRENGTH	"zen:drive_strength"

typedef enum {
	ZEN_GPIO_DRIVE_UNKNOWN,
	ZEN_GPIO_DRIVE_40R,
	ZEN_GPIO_DRIVE_60R,
	ZEN_GPIO_DRIVE_80R
} zen_gpio_drive_strength_t;

/*
 * These three attributes are used to control the debounce configuration which
 * ties into interrupt generation.
 *
 * ZEN_GPIO_ATTR_DEBOUNCE_MODE -- rw
 *	uint32 -- zen_gpio_debounce_mode_t
 *
 * This controls how the debounce logic works internally and what actions should
 * be taken.
 *
 * ZEN_GPIO_ATTR_DEBOUNCE_UNIT -- rw
 *	uint32_t -- zen_gpio_debounce_unit_t
 *
 * This controls the unit and graunlarity. This is phrased in terms of units of
 * the RTC clock and translates into 61 us, 244 us, 15.6 ms, and 62.5 ms.
 *
 * ZEN_GPIO_ATTR_DEBOUNCE_COUNT -- rw
 *	 uint32_t
 *
 * This is the number of debounce count units should be used. This is capped to
 * a 4-bit value.
 */
#define	ZEN_GPIO_ATTR_DEBOUNCE_MODE	"zen:debounce_mode"
#define	ZEN_GPIO_ATTR_DEBOUNCE_UNIT	"zen:debounce_unit"
#define	ZEN_GPIO_ATTR_DEBOUNCE_COUNT	"zen:debounce_count"

typedef enum {
	ZEN_GPIO_DEBOUNCE_MODE_NONE = 0,
	ZEN_GPIO_DEBOUNCE_MODE_KEEP_LOW,
	ZEN_GPIO_DEBOUNCE_MODE_KEEP_HIGH,
	ZEN_GPIO_DEBOUNCE_MODE_REMOVE,
} zen_gpio_debounce_mode_t;

typedef enum {
	ZEN_GPIO_DEBOUNCE_UNIT_2RTC = 0,
	ZEN_GPIO_DEBOUNCE_UNIT_8RTC,
	ZEN_GPIO_DEBOUNCE_UNIT_512RTC,
	ZEN_GPIO_DEBOUNCE_UNIT_2048RTC,
} zen_gpio_debounce_unit_t;

/*
 * ZEN_GPIO_ATTR_TRIGGER_MODE -- rw -- uint32_t zen_gpio_trigger_t enum
 *
 * This attribute controls how the device generates interrupts. In particular,
 * this covers whether it's edge or level triggered and what constitutes and
 * edge. Debounce logic still applies.
 */
#define	ZEN_GPIO_ATTR_TRIGGER_MODE	"zen:trigger_mode"

typedef enum {
	ZEN_GPIO_TRIGGER_UNKNOWN = 0,
	ZEN_GPIO_TRIGGER_EDGE_HIGH,
	ZEN_GPIO_TRIGGER_EDGE_LOW,
	ZEN_GPIO_TRIGGER_EDGE_BOTH,
	ZEN_GPIO_TRIGGER_LEVEL_HIGH,
	ZEN_GPIO_TRIGGER_LEVEL_LOW
} zen_gpio_trigger_t;

/*
 * ZEN_GPIO_ATTR_STATUS -- ro
 *	uint32_t -- zen_gpio_status_t
 *
 * This enumeration is a bitfield of status flags that the gpio has.
 */
#define	ZEN_GPIO_ATTR_STATUS	"zen:status"

typedef enum {
	ZEN_GPIO_STATUS_WAKE	= 1 << 0,
	ZEN_GPIO_STATUS_INTR	= 1 << 1,
} zen_gpio_status_t;

/*
 * ZEN_GPIO_ATTR_RAW_REG -- ro
 *	uint32_t
 *
 * This is an attribute which includes the raw register value for the gpio
 * register. This is here for debugging purposes.
 */
#define	ZEN_GPIO_ATTR_RAW_REG	"zen:raw_reg"

#ifdef __cplusplus
}
#endif

#endif /* _SYS_GPIO_ZEN_GPIO_H */
