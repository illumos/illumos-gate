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

#ifndef _SYS_GPIO_KGPIO_ATTR_H
#define	_SYS_GPIO_KGPIO_ATTR_H

/*
 * This file contains the shared definitions that are useful for understanding
 * attributes. This includes both the shared fields and required attributes as
 * well as more advanced error codes related to attributes.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * GPIOs themselves are made up of several attributes that are communicated as
 * an nvlist_t. While most attributes are determined by the provider and are
 * required to be prefixed as such, a few are standardized across everything.
 *
 * Note: At this time, the possible information only allows for fully enumerated
 * lists of values. We should consider adding support for ranges ala mac.
 */
#define	KGPIO_ATTR_NAME	"name"
#define	KGPIO_ATTR_META	"metadata"
#define	KGPIO_ATTR_PROT	"protection"
#define	KGPIO_ATTR_POS	"possible"

typedef enum {
	KGPIO_PROT_RO,
	KGPIO_PROT_RW
} kgpio_prot_t;

/*
 * When setting attributes, these are valid reasons that an attribute may be
 * invalid or not settable.
 */
typedef enum {
	/*
	 * Actually, no problem.
	 */
	KGPIO_ATTR_ERR_OK,
	/*
	 * Indicates that an attempt was made to set a read-only attribute.
	 */
	KGPIO_ATTR_ERR_ATTR_RO,
	/*
	 * Indicates that the requested attribute was not known to the provider.
	 */
	KGPIO_ATTR_ERR_UNKNOWN_ATTR,
	/*
	 * Indicates that the attributes type is not correct.
	 */
	KGPIO_ATTR_ERR_BAD_TYPE,
	/*
	 * Indicates that the attribute's value was unknown to the provider.
	 */
	KGPIO_ATTR_ERR_UNKNOWN_VAL,
	/*
	 * Indicates that while the provider knows this value, it is not valid
	 * for this GPIO or for the GPIO in its current configuration (e.g.
	 * asking for a high push-pull output for an open-drain pin).
	 */
	KGPIO_ATTR_ERR_CANT_APPLY_VAL
} kgpio_attr_err_t;

#ifdef __cplusplus
}
#endif

#endif /* _SYS_GPIO_KGPIO_ATTR_H */
