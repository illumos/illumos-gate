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

#ifndef _LIBXPIO_H
#define	_LIBXPIO_H

/*
 * An evolving, but private, interface to the kernel GPIO and DPIO subsystems
 * (hence xPIO).
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <libdevinfo.h>
#include <sys/gpio/dpio.h>

typedef enum {
	XPIO_ERR_OK = 0,
	/*
	 * Indicates that there was a memory allocation error. The system error
	 * contains the specific errno.
	 */
	XPIO_ERR_NO_MEM,
	/*
	 * Indicates that an error occurred while trying to use the devinfo
	 * library.
	 */
	XPIO_ERR_LIBDEVINFO,
	/*
	 * Indicates that an internal error condition occurred.
	 */
	XPIO_ERR_INTERNAL,
	/*
	 * Indicates that the function was given an invalid pointer argument.
	 */
	XPIO_ERR_BAD_PTR,
	/*
	 * Indicate that the passed in minor node name was not the right type.
	 */
	XPIO_ERR_WRONG_MINOR_TYPE,
	/*
	 * Indicates a failure to open a device file.
	 */
	XPIO_ERR_OPEN_DEV,
	/*
	 * Indicates a failure to talk with the kgpio subsystem.
	 */
	XPIO_ERR_KGPIO,
	/*
	 * Indicates that the specified GPIO controller does not exist.
	 */
	XPIO_ERR_BAD_CTRL_NAME,
	/*
	 * Indicates that the requested GPIO name or number does not exist.
	 */
	XPIO_ERR_BAD_GPIO_ID,
	/*
	 * Indicates that there was something wrong with the attributes that
	 * were handed in an update. The update structure has additional
	 * information.
	 */
	XPIO_ERR_BAD_UPDATE,
	/*
	 * Indicates that an attempt to perform an update cannot proceed because
	 * the structure has already been used for an update and has error
	 * information associated with it.
	 */
	XPIO_ERR_UPDATE_USED,
	/*
	 * Indicates that the features that were passed in to create the DPIO
	 * included something that was invalid.
	 */
	XPIO_ERR_BAD_DPIO_FEAT,
	/*
	 * Indicates that the name of the DPIO was invalid or does not exist.
	 */
	XPIO_ERR_BAD_DPIO_NAME,
	/*
	 * Indicates that the name of the GPIO was invalid.
	 */
	XPIO_ERR_BAD_GPIO_NAME,
	/*
	 * Indicates that an attempt to lookup something (e.g. a GPIO) did not
	 * succeed.
	 */
	XPIO_ERR_NO_LOOKUP_MATCH
} xpio_err_t;

typedef enum {
	XPIO_ATTR_TYPE_STRING,
	XPIO_ATTR_TYPE_UINT32
} xpio_attr_type_t;

typedef enum {
	XPIO_ATTR_PROT_RO,
	XPIO_ATTR_PROT_RW
} xpio_attr_prot_t;

typedef struct xpio xpio_t;
typedef struct xpio_ctrl xpio_ctrl_t;
typedef struct xpio_ctrl_info xpio_ctrl_info_t;
typedef struct xpio_gpio_info xpio_gpio_info_t;
typedef struct xpio_gpio_attr xpio_gpio_attr_t;
typedef struct xpio_gpio_attr_err xpio_gpio_attr_err_t;
typedef struct xpio_gpio_update xpio_gpio_update_t;
typedef struct xpio_dpio_info xpio_dpio_info_t;


extern xpio_t *xpio_init(void);
extern void xpio_fini(xpio_t *);

extern xpio_err_t xpio_err(xpio_t *);
extern int32_t xpio_syserr(xpio_t *);
extern const char *xpio_errmsg(xpio_t *);
extern const char *xpio_err2str(xpio_t *, xpio_err_t);

/*
 * Controller Discovery Functions
 */
typedef struct {
	di_minor_t xcd_minor;
} xpio_ctrl_disc_t;

typedef bool (*xpio_ctrl_disc_f)(xpio_t *, xpio_ctrl_disc_t *, void *);
extern void xpio_ctrl_discover(xpio_t *, xpio_ctrl_disc_f, void *);

extern bool xpio_ctrl_init(xpio_t *, di_minor_t, xpio_ctrl_t **);
extern bool xpio_ctrl_init_by_name(xpio_t *, const char *, xpio_ctrl_t **);
extern void xpio_ctrl_fini(xpio_ctrl_t *);

/*
 * Get information about a controller. Once obtained, the lifetime is disjoint
 * from the controller.
 */
extern bool xpio_ctrl_info(xpio_ctrl_t *, xpio_ctrl_info_t **);
extern void xpio_ctrl_info_free(xpio_ctrl_info_t *);
extern uint32_t xpio_ctrl_info_ngpios(xpio_ctrl_info_t *);
extern uint32_t xpio_ctrl_info_ndpios(xpio_ctrl_info_t *);
extern const char *xpio_ctrl_info_devpath(xpio_ctrl_info_t *);

/*
 * Ways to translae between human known names to the provider's underlying IDs.
 * This only searches the specified controller.
 */
extern bool xpio_gpio_lookup_id(xpio_ctrl_t *, const char *, uint32_t *);

/*
 * Snapshot information about a GPIO, walk and understand its attributes. Once
 * obtained, the lifetime is disjoint from the underlying controller and handle.
 * Each gpio can be operated on in parallel safely. Attributes are tied to the
 * corresponding gpio.
 */
extern bool xpio_gpio_info(xpio_ctrl_t *, uint32_t, xpio_gpio_info_t **);
extern uint32_t xpio_gpio_id(xpio_gpio_info_t *);
extern xpio_gpio_attr_t *xpio_gpio_attr_next(xpio_gpio_info_t *,
    xpio_gpio_attr_t *);
extern xpio_gpio_attr_t *xpio_gpio_attr_find(xpio_gpio_info_t *, const char *);
extern const char *xpio_gpio_attr_name(xpio_gpio_info_t *, xpio_gpio_attr_t *);
extern xpio_attr_type_t xpio_gpio_attr_type(xpio_gpio_info_t *,
    xpio_gpio_attr_t *);
extern xpio_attr_prot_t xpio_gpio_attr_prot(xpio_gpio_info_t *,
    xpio_gpio_attr_t *);
extern bool xpio_gpio_attr_value_uint32(xpio_gpio_attr_t *, uint32_t *);
extern bool xpio_gpio_attr_value_string(xpio_gpio_attr_t *, const char **);
extern void xpio_gpio_attr_possible_uint32(xpio_gpio_info_t *,
    xpio_gpio_attr_t *, uint32_t **, uint_t *);
extern void xpio_gpio_attr_possible_string(xpio_gpio_info_t *,
    xpio_gpio_attr_t *, const char ***, uint_t *);
extern bool xpio_gpio_attr_xlate_to_str(xpio_gpio_info_t *, xpio_gpio_attr_t *,
    char *, size_t);
extern bool xpio_gpio_attr_xlate_uint32_to_str(xpio_gpio_info_t *,
    xpio_gpio_attr_t *, uint32_t, char *, size_t);
extern void xpio_gpio_info_free(xpio_gpio_info_t *);

/*
 * The GPIO update data structure is used to track all of the updates that need
 * to occur to a given GPIO. This structure is tied to the gpio information
 * because the attributes that a given GPIO has may vary between GPIOs in a
 * given provider. This update structure can then be given to xpio_gpio_set() to
 * actually set the information.
 *
 * When it comes to error handling and checking here, we only attempt to verify
 * that an attribute is one that the provider reported to us. We do not attempt
 * to verify whether it is read-only or not. However, as part of translating
 * values, we will verify the types. There are two different groups of setting
 * functions. One is intended for CLI applications which just takes a string and
 * does all the translation that is necessary as part of setting the attribute.
 * The other set allows one to specify the types of values themselves.
 *
 * To try and provide reasonable error handling, we provide a unique set of
 * error routines (e.g. these do not require the xpio_t). Finally, as part of
 * attempting to set a gpio, errors will be returned as something that one can
 * iterate and determine what wrong with each attribute value to attempt to make
 * error handling easier.
 */
typedef enum {
	/*
	 * Indicates that the update was OK.
	 */
	XPIO_UPDATE_ERR_OK,
	/*
	 * Indicates that there was an attempt to update a read-only attribute.
	 */
	XPIO_UPDATE_ERR_RO,
	/*
	 * Indicates that the attribute's name was unknown to the provider.
	 */
	XPIO_UPDATE_ERR_UNKNOWN_ATTR,
	/*
	 * Indicates that the value for a given attribute's type was incorrect.
	 */
	XPIO_UPDATE_ERR_BAD_TYPE,
	/*
	 * Indicates that the system didn't know the value in question.
	 */
	XPIO_UPDATE_ERR_UNKNOWN_VAL,
	/*
	 * Indicates that the system was unable to translate an attribute value
	 * into its underlying type.
	 */
	XPIO_UPDATE_ERR_CANT_XLATE,
	/*
	 * Indicates that this was a valid attribute, but it could not be
	 * applied.
	 */
	XPIO_UPDATE_ERR_CANT_APPLY_VAL,
	/*
	 * Indicates that we ran out of memory processing something.
	 */
	XPIO_UPDATE_ERR_NO_MEM,
	/*
	 * Indicates that an internal error occurred in the library.
	 */
	XPIO_UPDATE_ERR_INTERNAL
} xpio_update_err_t;

extern bool xpio_gpio_update_init(xpio_t *, xpio_gpio_info_t *,
    xpio_gpio_update_t **);

extern xpio_update_err_t xpio_update_err(xpio_gpio_update_t *);
extern int32_t xpio_update_syserr(xpio_gpio_update_t *);
extern const char *xpio_update_errmsg(xpio_gpio_update_t *);
extern const char *xpio_update_err2str(xpio_gpio_update_t *,
    xpio_update_err_t);

/*
 * These two routines allow a caller to set an attribute's value directly. There
 * is no checking on whether the attribute's value is known or valid.
 */
extern bool xpio_gpio_attr_set_str(xpio_gpio_update_t *, xpio_gpio_attr_t *,
    const char *);
extern bool xpio_gpio_attr_set_uint32(xpio_gpio_update_t *, xpio_gpio_attr_t *,
    uint32_t);
/*
 * The two update functions above assume that you have already determined the
 * right type. This one performs any translation that might be required to go
 * from a string to the underlying type and then sets the attribute
 * appropriately. This will also verify that the value is known to the system,
 * unlike the ones above.
 */
extern bool xpio_gpio_attr_from_str(xpio_gpio_update_t *,
    xpio_gpio_attr_t *, const char *);

/*
 * This proceeds to update the GPIO that this update structure is for. After
 * calling this, if this fails, then one can iterate the update structure for
 * errors that occurred.
 */
extern bool xpio_gpio_update(xpio_ctrl_t *, xpio_gpio_update_t *);
extern xpio_gpio_attr_err_t *xpio_gpio_attr_err_next(xpio_gpio_update_t *,
    xpio_gpio_attr_err_t *);
extern const char *xpio_gpio_attr_err_name(xpio_gpio_attr_err_t *);
extern xpio_update_err_t xpio_gpio_attr_err_err(xpio_gpio_attr_err_t *);

/*
 * This tears down the xpio_gpio_update_t, at which point any outstanding
 * xpio_gpio_attr_err_t's are no longer valid (that is their lifetime is joined
 * together).
 */
extern void xpio_gpio_update_free(xpio_gpio_update_t *);

/*
 * Create a DPIO from the specified GPIO. The DPIO's supported features are
 * based on the following bitfield.
 */
typedef enum {
	XPIO_DPIO_F_READ	= 1 << 0,
	XPIO_DPIO_F_WRITE	= 1 << 1,
	XPIO_DPIO_F_KERNEL	= 1 << 2,
} xpio_dpio_features_t;

extern bool xpio_dpio_create(xpio_ctrl_t *, xpio_gpio_info_t *, const char *,
    xpio_dpio_features_t);
extern bool xpio_dpio_destroy(xpio_ctrl_t *, xpio_gpio_info_t *);

/*
 * DPIO Discovery and Basic Information
 */
typedef struct {
	di_minor_t xdd_minor;
} xpio_dpio_disc_t;

typedef bool (*xpio_dpio_disc_f)(xpio_t *, xpio_dpio_disc_t *, void *);
extern void xpio_dpio_discover(xpio_t *, xpio_dpio_disc_f, void *);

extern bool xpio_dpio_info(xpio_t *, di_minor_t, xpio_dpio_info_t **);
extern const char *xpio_dpio_info_ctrl(xpio_dpio_info_t *);
extern const char *xpio_dpio_info_name(xpio_dpio_info_t *);
extern uint32_t xpio_dpio_info_gpionum(xpio_dpio_info_t *);
extern dpio_caps_t xpio_dpio_info_caps(xpio_dpio_info_t *);
extern dpio_flags_t xpio_dpio_info_flags(xpio_dpio_info_t *);
extern void xpio_dpio_info_free(xpio_dpio_info_t *);

#ifdef __cplusplus
}
#endif

#endif /* _LIBXPIO_H */
