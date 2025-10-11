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
 * libi2c error manipulation and translation.
 */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <upanic.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>

#include "libi2c_impl.h"

static void
i2c_error_common(i2c_err_data_t *ep, i2c_err_t err, int32_t sys,
    const char *fmt, va_list ap)
{
	int ret;

	ep->ie_err = err;
	ep->ie_syserr = sys;
	ep->ie_ctrl_err = I2C_CTRL_E_OK;
	ret = vsnprintf(ep->ie_errmsg, sizeof (ep->ie_errmsg), fmt, ap);
	if (ret >= sizeof (ep->ie_errmsg)) {
		ep->ie_errlen = sizeof (ep->ie_errmsg) - 1;
	} else if (ret <= 0) {
		ep->ie_errlen = 0;
		ep->ie_errmsg[0] = '\0';
	} else {
		ep->ie_errlen = (size_t)ret;
	}
}

bool
i2c_error(i2c_hdl_t *hdl, i2c_err_t err, int32_t sys, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	i2c_error_common(&hdl->ih_err, err, sys, fmt, ap);
	va_end(ap);

	return (false);
}

static bool
i2c_success_common(i2c_err_data_t *err)
{
	err->ie_err = I2C_ERR_OK;
	err->ie_syserr = 0;
	err->ie_ctrl_err = I2C_CTRL_E_OK;
	err->ie_errmsg[0] = '\0';
	err->ie_errlen = 0;

	return (true);
}

bool
i2c_success(i2c_hdl_t *hdl)
{
	return (i2c_success_common(&hdl->ih_err));
}

i2c_err_t
i2c_err(i2c_hdl_t *hdl)
{
	return (hdl->ih_err.ie_err);
}

i2c_ctrl_error_t
i2c_ctrl_err(i2c_hdl_t *hdl)
{
	return (hdl->ih_err.ie_ctrl_err);
}

int32_t
i2c_syserr(i2c_hdl_t *hdl)
{
	return (hdl->ih_err.ie_syserr);
}

const char *
i2c_errmsg(i2c_hdl_t *hdl)
{
	return (hdl->ih_err.ie_errmsg);
}

const char *
i2c_errtostr(i2c_hdl_t *hdl, i2c_err_t err)
{
	switch (err) {
	case I2C_ERR_OK:
		return ("I2C_ERR_OK");
	case I2C_ERR_CONTROLLER:
		return ("I2C_ERR_CONTROLLER");
	case I2C_ERR_BAD_PTR:
		return ("I2C_ERR_BAD_PTR");
	case I2C_ERR_NO_MEM:
		return ("I2C_ERR_NO_MEM");
	case I2C_ERR_LIBDEVINFO:
		return ("I2C_ERR_LIBDEVINFO");
	case I2C_ERR_BAD_DEVI:
		return ("I2C_ERR_BAD_DEVI");
	case I2C_ERR_INTERNAL:
		return ("I2C_ERR_INTERNAL");
	case I2C_ERR_PRIVS:
		return ("I2C_ERR_PRIVS");
	case I2C_ERR_OPEN_DEV:
		return ("I2C_ERR_OPEN_DEV");
	case I2C_ERR_BAD_CONTROLLER:
		return ("I2C_ERR_BAD_CONTROLLER");
	case I2C_ERR_BAD_PORT:
		return ("I2C_ERR_BAD_PORT");
	case I2C_ERR_BAD_DEVICE:
		return ("I2C_ERR_BAD_DEVICE");
	case I2C_ERR_BAD_ADDR_TYPE:
		return ("I2C_ERR_BAD_ADDR_TYPE");
	case I2C_ERR_BAD_ADDR:
		return ("I2C_ERR_BAD_ADDR");
	case I2C_ERR_UNSUP_ADDR_TYPE:
		return ("I2C_ERR_UNSUP_ADDR_TYPE");
	case I2C_ERR_ADDR_RSVD:
		return ("I2C_ERR_ADDR_RSVD");
	case I2C_ERR_ADDR_IN_USE:
		return ("I2C_ERR_ADDR_IN_USE");
	case I2C_ERR_ADDR_UNKNOWN:
		return ("I2C_ERR_ADDR_UNKNOWN");
	case I2C_ERR_IO_READ_LEN_RANGE:
		return ("I2C_ERR_IO_READ_LEN_RANGE");
	case I2C_ERR_IO_WRITE_LEN_RANGE:
		return ("I2C_ERR_IO_WRITE_LEN_RANGE");
	case I2C_ERR_IO_REQ_MISSING_FIELDS:
		return ("I2C_ERR_IO_REQ_MISSING_FIELDS");
	case I2C_ERR_IO_REQ_IO_INVALID:
		return ("I2C_ERR_IO_REQ_IO_INVALID");
	case I2C_ERR_CANT_XLATE_IO_REQ:
		return ("I2C_ERR_CANT_XLATE_IO_REQ");
	case I2C_ERR_SMBUS_OP_UNSUP:
		return ("I2C_ERR_SMBUS_OP_UNSUP");
	case I2C_ERR_LOCK_WAIT_SIGNAL:
		return ("I2C_ERR_LOCK_WAIT_SIGNAL");
	case I2C_ERR_LOCK_WOULD_BLOCK:
		return ("I2C_ERR_LOCK_WOULD_BLOCK");
	case I2C_ERR_NO_KERN_MEM:
		return ("I2C_ERR_NO_KERN_MEM");
	case I2C_ERR_BAD_DEV_NAME:
		return ("I2C_ERR_BAD_DEV_NAME");
	case I2C_ERR_COMPAT_LEN_RANGE:
		return ("I2C_ERR_COMPAT_LEN_RANGE");
	case I2C_ERR_ADD_DEV_REQ_MISSING_FIELDS:
		return ("I2C_ERR_ADD_DEV_REQ_MISSING_FIELDS");
	case I2C_ERR_NEXUS:
		return ("I2C_ERR_NEXUS");
	case I2C_ERR_OP_IN_PROGRESS:
		return ("I2C_ERR_OP_IN_PROGRESS");
	case I2C_ERR_PROP_UNSUP:
		return ("I2C_ERR_PROP_UNSUP");
	case I2C_ERR_BAD_PROP:
		return ("I2C_ERR_BAD_PROP");
	case I2C_ERR_SET_PROP_UNSUP:
		return ("I2C_ERR_SET_PROP_UNSUP");
	case I2C_ERR_PROP_READ_ONLY:
		return ("I2C_ERR_PROP_READ_ONLY");
	case I2C_ERR_PROP_BUF_TOO_SMALL:
		return ("I2C_ERR_PROP_BUF_TOO_SMALL");
	case I2C_ERR_PROP_BUF_TOO_BIG:
		return ("I2C_ERR_PROP_BUF_TOO_BIG");
	case I2C_ERR_BAD_PROP_VAL:
		return ("I2C_ERR_BAD_PROP_VAL");
	case I2C_ERR_NO_PROP_DEF_VAL:
		return ("I2C_ERR_NO_PROP_DEF_VAL");
	case I2C_ERR_PROP_TYPE_MISMATCH:
		return ("I2C_ERR_PROP_TYPE_MISMATCH");
	case I2C_ERR_BUF_TOO_SMALL:
		return ("I2C_ERR_BUF_TOO_SMALL");
	default:
		return ("unknown error");
	}
}

const char *
i2c_ctrl_errtostr(i2c_hdl_t *hdl, i2c_ctrl_error_t err)
{
	switch (err) {
	case I2C_CTRL_E_OK:
		return ("I2C_CTRL_E_OK");
	case I2C_CTRL_E_INTERNAL:
		return ("I2C_CTRL_E_INTERNAL");
	case I2C_CTRL_E_DRIVER:
		return ("I2C_CTRL_E_DRIVER");
	case I2C_CTRL_E_UNSUP_CMD:
		return ("I2C_CTRL_E_UNSUP_CMD");
	case I2C_CTRL_E_BUS_BUSY:
		return ("I2C_CTRL_E_BUS_BUSY");
	case I2C_CTRL_E_ADDR_NACK:
		return ("I2C_CTRL_E_ADDR_NACK");
	case I2C_CTRL_E_DATA_NACK:
		return ("I2C_CTRL_E_DATA_NACK");
	case I2C_CTRL_E_NACK:
		return ("I2C_CTRL_E_NACK");
	case I2C_CTRL_E_ARB_LOST:
		return ("I2C_CTRL_E_ARB_LOST");
	case I2C_CTRL_E_BAD_ACK:
		return ("I2C_CTRL_E_BAD_ACK");
	case I2C_CTRL_E_REQ_TO:
		return ("I2C_CTRL_E_REQ_TO");
	case I2C_CTRL_E_BAD_SMBUS_RLEN:
		return ("I2C_CTRL_E_BAD_SMBUS_RLEN");
	case I2C_CTRL_E_SMBUS_CLOCK_LOW:
		return ("I2C_CTRL_E_SMBUS_CLOCK_LOW");
	default:
		return ("unkonwn error");
	}
}

/*
 * Most of our ioctls are designed to give us a semantic error. However, there
 * are cases where we may fail outside of that. We opt to abort on a subset of
 * these that represent gross library programmer error: mainly EBADF and EFAULT.
 * Note, EFAULT generally covers the core ioctl structures and not any
 * additional buffers that are passed in, therefore if this triggers then we
 * have done something terribly wrong.
 */
bool
i2c_ioctl_syserror(i2c_hdl_t *hdl, int err, const char *desc)
{
	switch (err) {
	case EFAULT:
	case EBADF: {
		const char *base = "fatal libi2c internal programming error: "
		    "failed to issue ioctl";
		char msg[1024];
		int ret;
		const char *up;
		size_t ulen;

		ret = snprintf(msg, sizeof (msg), "%s %s: %s (hdl %p)",
		    base, desc, strerror(err), hdl);
		if (ret >= sizeof (msg)) {
			ulen = sizeof (msg);
			up = msg;
		} else if (ret <= 0) {
			up = base;
			ulen = strlen(base) + 1;
		} else {
			ulen = (size_t)ret;
			up = msg;
		}

		upanic(up, ulen);
	}
	case EPERM:
		return (i2c_error(hdl, I2C_ERR_PRIVS, err, "failed to issue %s "
		    "ioctl due to missing privileges", desc));
	default:
		return (i2c_error(hdl, I2C_ERR_INTERNAL, err,
		    "failed to issue %s ioctl due to unexpected system error: "
		    "%s", desc, strerrordesc_np(err)));
	}
}

typedef struct {
	i2c_errno_t kl_kern;
	i2c_err_t kl_lib;
	const char *kl_desc;
} i2c_ktolmap_t;

/*
 * This facilitates mapping kernel errors to user library errors along with a
 * short description. This is ordered based on the order of the kernel ioctls so
 * we can more easily spot missing entries. The description is used to help
 * users understand what happened.
 */
static const i2c_ktolmap_t i2c_ktolmap[] = {
	/*
	 * We skip I2C_CORE_E_OK because it not reach here. We also handle the
	 * controller error, I2C_CORE_E_CONTROLLER, specifically so it is not
	 * translated here
	 */
	{ I2C_CORE_E_BAD_ADDR_TYPE, I2C_ERR_BAD_ADDR_TYPE, "invalid I2C "
	    "address family type" },
	{ I2C_CORE_E_BAD_ADDR, I2C_ERR_BAD_ADDR, "invalid I2C address" },
	{ I2C_CORE_E_UNSUP_ADDR_TYPE, I2C_ERR_UNSUP_ADDR_TYPE, "address "
	    "family not supported by the controller" },
	{ I2C_CORE_E_ADDR_RSVD, I2C_ERR_ADDR_RSVD, "I2C address is reserved" },
	{ I2C_CORE_E_ADDR_IN_USE, I2C_ERR_ADDR_IN_USE, "I2C addrses is already "
	    "used" },
	{ I2C_CORE_E_ADDR_REFCNT, I2C_ERR_INTERNAL, "address could not be "
	    "assigned due to kernel reference count exhaustion" },
	{ I2C_CORE_E_UNKNOWN_ADDR, I2C_ERR_ADDR_UNKNOWN, "I2C address does not "
	    "map to a known device" },
	{ I2C_CORE_E_CANT_XLATE_REQ, I2C_ERR_CANT_XLATE_IO_REQ, "I/O request "
	    "could not be translated to something the controller supports" },
	{ I2C_CORE_E_NEED_READ_OR_WRITE, I2C_ERR_IO_REQ_IO_INVALID, "request "
	    "requires data to transmit or receive, but neither specified" },
	/*
	 * We have purposefully skipped I2C_CORE_E_BAD_I2C_REQ_FLAGS and
	 * I2C_CORE_E_BAD_SMBUS_REQ_FLAGS as these are not flags that users are
	 * able to set and therefore the only reason these should be wrong is if
	 * we screwed something up in the library.
	 */
	{ I2C_CORE_E_BAD_I2C_REQ_READ_LEN, I2C_ERR_IO_READ_LEN_RANGE, "invalid "
	    "receive length" },
	{ I2C_CORE_E_BAD_I2C_REQ_WRITE_LEN, I2C_ERR_IO_WRITE_LEN_RANGE,
	    "invalid transmit length" },
	{ I2C_CORE_E_BAD_SMBUS_READ_LEN, I2C_ERR_IO_READ_LEN_RANGE, "invalid "
	    "receive length" },
	{ I2C_CORE_E_BAD_SMBUS_WRITE_LEN, I2C_ERR_IO_WRITE_LEN_RANGE,
	    "invalid transmit length" },
	{ I2C_CORE_E_UNSUP_SMBUS_OP, I2C_ERR_SMBUS_OP_UNSUP, "SMBus operation "
	    "unsupported by controller or system" },
	{ I2C_CORE_E_LOCK_WOULD_BLOCK, I2C_ERR_LOCK_WOULD_BLOCK, "lock not "
	    "available and no blocking allowed" },
	{ I2C_CORE_E_LOCK_WAIT_SIGNAL, I2C_ERR_LOCK_WAIT_SIGNAL, "signal "
	    "received while blocking" },
	/*
	 * We have purposefully skipped the nvlist device related errors,
	 * I2C_IOCTL_E_NVL_TOO_BIG, I2C_IOCTL_E_NVL_INVALID,
	 * I2C_IOCTL_E_NVL_KEY_MISSING, I2C_IOCTL_E_NVL_KEY_UNKNOWN, and
	 * I2C_IOCTL_E_NVL_KEY_BAD_TYPE. These are things that generally only
	 * the library can screw up.
	 */
	{ I2C_IOCTL_E_BAD_USER_DATA, I2C_ERR_BAD_PTR, "the kernel detected an "
	    "invalid user buffer while trying to read/write the passed in "
	    "buffer" },
	{ I2C_IOCTL_E_NO_KERN_MEM, I2C_ERR_NO_KERN_MEM, "the kerenl failed "
	    "to allocate memory for this operation" },
	{ I2C_IOCTL_E_BAD_DEV_NAME, I2C_ERR_BAD_DEV_NAME, "invalid device "
	    "or compatible name" },
	{ I2C_IOCTL_E_COMPAT_LEN_RANGE, I2C_ERR_COMPAT_LEN_RANGE, "invalid "
	    "compatible string length" },
	{ I2C_IOCTL_E_NEXUS, I2C_ERR_NEXUS, "unexpected kernel nexus driver "
	    "error" },
	/*
	 * We have purposefully skipped I2C_IOCTL_E_NO_BUS_LOCK_NEXUS as there
	 * is no way to take an explicit lock in userland right now.
	 */
	{ I2C_IOCTL_E_IN_PROGRESS, I2C_ERR_OP_IN_PROGRESS, "cannot perform "
	    "requested operation, handle already performing one" },
	/*
	 * All I2C_CLIENT class errors are skipped as they should not be
	 * returned to userland.
	 */
	{ I2C_PROP_E_UNSUP, I2C_ERR_PROP_UNSUP, "property unsupported by "
	    "controller" },
	{ I2C_PROP_E_UNKNOWN, I2C_ERR_BAD_PROP, "unknown property" },
	{ I2C_PROP_E_READ_ONLY, I2C_ERR_PROP_READ_ONLY, "property is "
	    "read-only" },
	{ I2C_PROP_E_SMALL_BUF, I2C_ERR_PROP_BUF_TOO_SMALL, "data buffer too "
	    "small for property" },
	{ I2C_PROP_E_TOO_BIG_BUF, I2C_ERR_PROP_BUF_TOO_BIG, "data buffer too "
	    "big for property" },
	/*
	 * Indicates that the property value is invalid.
	 */
	{ I2C_PROP_E_BAD_VAL, I2C_ERR_BAD_PROP, "invalid property value" },
	/*
	 * Indicates that the controller doesn't support setting properties.
	 */
	{ I2C_PROP_E_SET_UNSUP, I2C_ERR_SET_PROP_UNSUP, "controller does not "
	    "support setting properties" },
	/*
	 * Currently all MUX class errors are skipped as they aren't really
	 * expected here.
	 */
};

bool
i2c_ioctl_error(i2c_hdl_t *hdl, const i2c_error_t *ioc, const char *desc)
{
	int ret;
	i2c_err_data_t *err = &hdl->ih_err;
	VERIFY3U(ioc->i2c_error, !=, I2C_CORE_E_OK);

	err->ie_syserr = 0;

	if (ioc->i2c_error == I2C_CORE_E_CONTROLLER) {
		const char *code = i2c_ctrl_errtostr(hdl, ioc->i2c_ctrl);

		err->ie_err = I2C_ERR_CONTROLLER;
		err->ie_ctrl_err = ioc->i2c_ctrl;
		ret = snprintf(err->ie_errmsg, sizeof (err->ie_errmsg),
		    "failed to execute %s command: received controller "
		    "error %s (0x%x)", desc, code, ioc->i2c_ctrl);
	} else {
		const i2c_ktolmap_t *map = NULL;
		for (size_t i = 0; i < ARRAY_SIZE(i2c_ktolmap); i++) {
			if (i2c_ktolmap[i].kl_kern == ioc->i2c_error) {
				map = &i2c_ktolmap[i];
				break;
			}
		}

		if (map != NULL) {
			err->ie_err = map->kl_lib;
			ret = snprintf(err->ie_errmsg, sizeof (err->ie_errmsg),
			    "failed to execute %s command: %s", desc,
			    map->kl_desc);
		} else {
			err->ie_err = I2C_ERR_INTERNAL;
			ret = snprintf(err->ie_errmsg, sizeof (err->ie_errmsg),
			    "failed to execute %s command: failed to map "
			    "kernel error 0x%x to a known cause", desc,
			    ioc->i2c_error);
		}
	}

	if (ret >= sizeof (err->ie_errmsg)) {
		err->ie_errlen = sizeof (err->ie_errlen) - 1;
	} else if (ret <= 0) {
		err->ie_errlen = 0;
		err->ie_errmsg[0] = '\0';
	} else {
		err->ie_errlen = (size_t)ret;
	}

	return (false);
}

bool
i2c_nvlist_error(i2c_hdl_t *hdl, int ret, const char *desc)
{
	if (ret == 0) {
		return (true);
	}

	if (ret == ENOMEM) {
		return (i2c_error(hdl, I2C_ERR_NO_MEM, ret, "failed to "
		    "allocate memory to %s", desc));
	}

	return (i2c_error(hdl, I2C_ERR_INTERNAL, ret, "unexpected internal "
	    "error while trying to %s", desc));
}
