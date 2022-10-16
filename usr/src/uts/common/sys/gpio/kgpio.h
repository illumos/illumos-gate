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

#ifndef _SYS_GPIO_KGPIO_H
#define	_SYS_GPIO_KGPIO_H

/*
 * User / Kernel kgpio interface
 */

#include <sys/stdint.h>
#include <sys/param.h>
#include <sys/gpio/kgpio_attr.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	KGPIO_IOC	(('k' << 24) | ('g' << 16) | ('p' << 8))

/*
 * Obtain basic information about a GPIO controller.
 */
#define	KGPIO_IOC_CTRL_INFO	(KGPIO_IOC | 1)
typedef struct {
	uint32_t	kci_ngroups;
	uint32_t	kci_ngpios;
	uint32_t	kci_ndpios;
	uint32_t	kci_pad;
	char		kci_devpath[MAXPATHLEN];
} kgpio_ctrl_info_t;

/*
 * This gets detailed information about a given GPIO. It includes all the
 * provider's attributes as well for the GPIO.
 */
#define	KGPIO_IOC_GPIO_INFO	(KGPIO_IOC | 2)

typedef enum {
	KGPIO_GPIO_F_DPIO	= 1 << 0
} kgpio_gpio_flags_t;

typedef struct {
	uint32_t		kgi_id;
	kgpio_gpio_flags_t	kgi_flags;
	uintptr_t		kgi_attr;
	size_t			kgi_attr_len;
} kgpio_gpio_info_t;

/*
 * This is used to set the attributes of a given GPIO. It takes an nvlist_t and
 * also returns an nvlist_t of errors.
 */
#define	KGPIO_IOC_GPIO_UPDATE	(KGPIO_IOC | 3)

typedef enum {
	/*
	 * This flag is set by the kernel on return. If the system returns 0,
	 * then this must be checked to see if there were errors available.
	 */
	KGPIO_UPDATE_ERROR = 1 << 0,
	/*
	 * Indicates that the information in the error NVL is valid.
	 */
	KGPIO_UPDATE_ERR_NVL_VALID = 1 << 1
} kgpio_update_flags_t;

typedef struct {
	uint32_t		kgu_id;
	kgpio_update_flags_t	kgu_flags;
	uintptr_t		kgu_attr;
	size_t			kgu_attr_len;
	uintptr_t		kgu_err;
	size_t			kgu_err_len;
} kgpio_update_t;

/*
 * This is used to create a DPIO from a given GPIO.
 */
#define	KGPIO_IOC_DPIO_CREATE	(KGPIO_IOC | 4)

typedef enum {
	/*
	 * Indicates that reading the input value of the DPIO is allowed.
	 */
	KGPIO_DPIO_F_READ	= 1 << 0,
	/*
	 * Indicates that setting the output value of the DPIO is allowed.
	 */
	KGPIO_DPIO_F_WRITE	= 1 << 1,
	/*
	 * Indicates that the DPIO should be restricted to only the kernel.
	 */
	KGPIO_DPIO_F_KERNEL	= 1 << 2
} kgpio_dpio_flags_t;

#define	KGPIO_DPIO_NAMELEN	32

typedef struct {
	uint32_t		kdc_id;
	kgpio_dpio_flags_t	kdc_flags;
	char			kdc_name[KGPIO_DPIO_NAMELEN];
} kgpio_dpio_create_t;

/*
 * This is used to destroy a DPIO that is bound to the specific GPIO.
 */
#define	KGPIO_IOC_DPIO_DESTROY	(KGPIO_IOC | 5)
typedef struct {
	uint32_t	kdd_id;
	uint32_t	kdd_pad;
} kgpio_dpio_destroy_t;

/*
 * Determines if a GPIO with the specified name is present on the given
 * controller. If so, its ID is returned.
 */
#define	KGPIO_IOC_GPIO_NAME2ID	(KGPIO_IOC | 6)
typedef struct {
	char		kin_name[MAXPATHLEN];
	uint32_t	kin_id;
} kgpio_ioc_name2id_t;

/*
 * Kernel-specific views for 32-bit.
 */
#ifdef	_KERNEL
typedef struct {
	uint32_t		kgi_id;
	kgpio_gpio_flags_t	kgi_flags;
	uintptr32_t		kgi_attr;
	size32_t		kgi_attr_len;
} kgpio_gpio_info32_t;

typedef struct {
	uint32_t		kgu_id;
	kgpio_update_flags_t	kgu_flags;
	uintptr32_t		kgu_attr;
	size32_t		kgu_attr_len;
	uintptr32_t		kgu_err;
	size32_t		kgu_err_len;
} kgpio_update32_t;
#endif	/* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_GPIO_KGPIO_H */
