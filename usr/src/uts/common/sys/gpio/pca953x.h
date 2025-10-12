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

#ifndef _SYS_GPIO_PCA953X_H
#define	_SYS_GPIO_PCA953X_H

/*
 * PCA953x driver GPIO attribute definitions.
 *
 * The PCA953x driver provides a very simple GPIO interface that supports four
 * basic attributes: controlling the output, controlling the input polarity, and
 * the standard name attribute.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * PCA953X_GPIO_ATTR_INTPUT -- ro
 *	uint32_t -- pca953x_gpio_input_t
 */
#define	PCA953X_GPIO_ATTR_INPUT		"pca953x:input"
typedef enum {
	PCA953X_GPIO_INPUT_LOW,
	PCA953X_GPIO_INPUT_HIGH
} pca953x_gpio_input_t;

/*
 * PCA953X_GPIO_ATTR_OUTPUT -- rw
 *	uint32_t -- pca953x_gpio_output_t
 *
 * This controls the GPIO's output value. If the GPIO is configured as an input,
 * modifying this will not impact anything. When the output is set to disabled,
 * then the pin is put into an input-only mode.
 */
#define	PCA953X_GPIO_ATTR_OUTPUT	"pca953x:output"
typedef enum {
	PCA953X_GPIO_OUTPUT_DISABLED,
	PCA953X_GPIO_OUTPUT_LOW,
	PCA953X_GPIO_OUTPUT_HIGH
} pca953x_gpio_output_t;

/*
 * PCA953X_GPIO_ATTR_POLARITY -- rw
 *	uint32_t -- pca953x_gpio_polarity_t
 *
 * This controls whether the input register reads back an inverted value or not.
 */
#define	PCA953X_GPIO_ATTR_POLARITY	"pca953x:polarity"
typedef enum {
	PCA953X_GPIO_POLARITY_NORMAL,
	PCA953X_GPIO_POLARITY_INVERTED
} pca953x_gpio_polarity_t;

#ifdef __cplusplus
}
#endif

#endif /* _SYS_GPIO_PCA953X_H */
