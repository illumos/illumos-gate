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
 * Dedicated Purpose I/O related routines
 */

#include <unistd.h>
#include <strings.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/debug.h>

#include "libxpio_impl.h"

/*
 * To avoid translation of flags we assume the kernel flags and our library
 * flags are the same. The casts are required as that gets us the underlying
 * enum's value in a way that a static assertion can handle.
 */
CTASSERT((uint32_t)XPIO_DPIO_F_READ == (uint32_t)KGPIO_DPIO_F_READ);
CTASSERT((uint32_t)XPIO_DPIO_F_WRITE == (uint32_t)KGPIO_DPIO_F_WRITE);
CTASSERT((uint32_t)XPIO_DPIO_F_KERNEL == (uint32_t)KGPIO_DPIO_F_KERNEL);

/*
 * We do not have a /dev entry point for the dpinfo minor that we need to use to
 * get information about DPIOs as this is private to the implementation. We
 * therefore record it here.
 */
static const char *xpio_dpinfo_path = "/devices/pseudo/kgpio@0:dpinfo";

typedef struct {
	xpio_t *xdc_xpio;
	xpio_dpio_disc_f xdc_func;
	void *xdc_arg;
} xpio_dpio_cb_t;

static int
xpio_dpio_discover_cb(di_node_t di, di_minor_t minor, void *arg)
{
	bool ret;
	xpio_dpio_cb_t *cb = arg;
	xpio_dpio_disc_t disc;

	disc.xdd_minor = minor;

	ret = cb->xdc_func(cb->xdc_xpio, &disc, cb->xdc_arg);
	if (ret) {
		return (DI_WALK_CONTINUE);
	} else {
		return (DI_WALK_TERMINATE);
	}
}

void
xpio_dpio_discover(xpio_t *xpio, xpio_dpio_disc_f func, void *arg)
{
	xpio_dpio_cb_t cb;

	cb.xdc_xpio = xpio;
	cb.xdc_func = func;
	cb.xdc_arg = arg;
	(void) di_walk_minor(xpio->xp_devinfo, DDI_NT_GPIO_DPIO, 0, &cb,
	    xpio_dpio_discover_cb);
}

void
xpio_dpio_info_free(xpio_dpio_info_t *info)
{
	free(info);
}

const char *
xpio_dpio_info_ctrl(xpio_dpio_info_t *info)
{
	return (info->xdi_ctrl);
}

const char *
xpio_dpio_info_name(xpio_dpio_info_t *info)
{
	/*
	 * The raw minor name which is what we use to go to the kernel with
	 * includes a 'dpio:' prefix. However, that is not what users actually
	 * create and use, so strip that out of the returned name.
	 */
	return (info->xdi_dpio + 5);
}

uint32_t
xpio_dpio_info_gpionum(xpio_dpio_info_t *info)
{
	return (info->xdi_gpio);
}

dpio_caps_t
xpio_dpio_info_caps(xpio_dpio_info_t *info)
{
	return (info->xdi_caps);
}

dpio_flags_t
xpio_dpio_info_flags(xpio_dpio_info_t *info)
{
	return (info->xdi_flags);
}

bool
xpio_dpio_info(xpio_t *xpio, di_minor_t minor, xpio_dpio_info_t **outp)
{
	int fd = -1;
	xpio_dpio_info_t *info = NULL;
	dpio_info_t dpi;

	if (minor == DI_NODE_NIL) {
		return (xpio_error(xpio, XPIO_ERR_BAD_PTR, 0, "encountered "
		    "invalid di_minor_t: %p", minor));
	}

	if (outp == NULL) {
		return (xpio_error(xpio, XPIO_ERR_BAD_PTR, 0, "encountered "
		    "invalid xpio_ctrl_t output pointer: %p", outp));
	}
	*outp = NULL;

	if (strcmp(di_minor_nodetype(minor), DDI_NT_GPIO_DPIO) != 0) {
		return (xpio_error(xpio, XPIO_ERR_WRONG_MINOR_TYPE, 0,
		    "minor %s has incorrect node type: %s, expected %s",
		    di_minor_name(minor), di_minor_nodetype(minor),
		    DDI_NT_GPIO_DPIO));
	}

	if ((fd = open(xpio_dpinfo_path, O_RDONLY)) < 0) {
		int e = errno;
		return (xpio_error(xpio, XPIO_ERR_OPEN_DEV, e, "failed to open "
		    "DPIO information minor: %s", strerror(e)));
	}

	info = calloc(1, sizeof (xpio_dpio_info_t));
	if (info == NULL) {
		int e = errno;
		(void) xpio_error(xpio, XPIO_ERR_NO_MEM, e, "failed to "
		    "allocate memory for a xpio_dpio_info_t: %s", strerror(e));
		goto err;
	}

	(void) memset(&dpi, 0, sizeof (dpi));
	if (strlcpy(dpi.dpi_dpio, di_minor_name(minor),
	    sizeof (dpi.dpi_dpio)) >= sizeof (dpi.dpi_dpio)) {
		(void) xpio_error(xpio, XPIO_ERR_INTERNAL, 0, "DPIO name "
		    "somehow exceeded expected system length");
		goto err;
	}

	if (ioctl(fd, DPIO_IOC_INFO, &dpi) != 0) {
		int e = errno;
		switch (e) {
		case ENOENT:
			(void) xpio_error(xpio, XPIO_ERR_BAD_DPIO_NAME, 0,
			    "DPIO %s does not exist", di_minor_name(minor));
			goto err;
		case EFAULT:
			abort();
		default:
			(void) xpio_error(xpio, XPIO_ERR_KGPIO, e, "failed to "
			    "issue dpio information ioctl for dpio %s: %s",
			    di_minor_name(minor), strerror(e));

			goto err;
		}
	}

	(void) memcpy(info->xdi_dpio, dpi.dpi_dpio, sizeof (dpi.dpi_dpio));
	(void) memcpy(info->xdi_ctrl, dpi.dpi_ctrl, sizeof (dpi.dpi_ctrl));
	info->xdi_gpio = dpi.dpi_gpio;
	info->xdi_caps = dpi.dpi_caps;
	info->xdi_flags = dpi.dpi_flags;

	(void) close(fd);
	*outp = info;
	return (xpio_success(xpio));

err:
	if (fd >= 0) {
		(void) close(fd);
	}
	free(info);
	return (false);
}

bool
xpio_dpio_create(xpio_ctrl_t *ctrl, xpio_gpio_info_t *gi, const char *name,
    xpio_dpio_features_t feat)
{
	kgpio_dpio_create_t create;
	xpio_t *xpio = ctrl->xc_xpio;
	const uint32_t all_feats = XPIO_DPIO_F_READ | XPIO_DPIO_F_WRITE |
	    XPIO_DPIO_F_KERNEL;

	if (gi == NULL) {
		return (xpio_error(xpio, XPIO_ERR_BAD_PTR, 0, "encountered "
		    "invalid xpio_gpio_info_t pointer: %p", gi));
	}

	if (name == NULL) {
		return (xpio_error(xpio, XPIO_ERR_BAD_PTR, 0, "encountered "
		    "invalid pointer for DPIO name: %p", name));
	}

	if ((feat & ~all_feats) != 0) {
		return (xpio_error(xpio, XPIO_ERR_BAD_DPIO_FEAT, 0, "found "
		    "unknown dpio features specified: 0x%x",
		    feat & ~all_feats));
	}

	(void) memset(&create, 0, sizeof (create));
	if (strlcpy(create.kdc_name, name, sizeof (create.kdc_name)) >=
	    sizeof (create.kdc_name)) {
		return (xpio_error(xpio, XPIO_ERR_BAD_DPIO_NAME, 0,
		    "requested DPIO name is longer than the maximum supported "
		    "(%zu characters including '\\0')",
		    sizeof (create.kdc_name)));
	}

	/*
	 * Right now there is a 1:1 mapping between library and kgpio features.
	 */
	create.kdc_flags = (kgpio_dpio_flags_t)feat;
	create.kdc_id = gi->xgi_id;

	/*
	 * At some point it'd be good for us to take this apart and create much
	 * more useful semantic errors rather than this generic error as it
	 * basically requires someone to go into the code to figure out what
	 * happened. Basically, we want something like with update.
	 */
	if (ioctl(ctrl->xc_fd, KGPIO_IOC_DPIO_CREATE, &create) != 0) {
		int e = errno;
		return (xpio_error(xpio, XPIO_ERR_KGPIO, e, "failed to create "
		    "dpio %s: %s", name, strerror(e)));
	}

	return (xpio_success(xpio));
}

bool
xpio_dpio_destroy(xpio_ctrl_t *ctrl, xpio_gpio_info_t *gi)
{
	kgpio_dpio_destroy_t destroy;
	xpio_t *xpio = ctrl->xc_xpio;

	if (gi == NULL) {
		return (xpio_error(xpio, XPIO_ERR_BAD_PTR, 0, "encountered "
		    "invalid xpio_gpio_info_t pointer: %p", gi));
	}

	destroy.kdd_id = gi->xgi_id;


	/*
	 * At some point it'd be good for us to take this apart and create much
	 * more useful semantic errors rather than this generic error as it
	 * basically requires someone to go into the code to figure out what
	 * happened. Basically, we want something like with update.
	 */
	if (ioctl(ctrl->xc_fd, KGPIO_IOC_DPIO_DESTROY, &destroy) != 0) {
		int e = errno;
		return (xpio_error(xpio, XPIO_ERR_KGPIO, e, "failed to destroy "
		    "dpio %s/%u: %s", ctrl->xc_name, gi->xgi_id, strerror(e)));
	}
	return (xpio_success(xpio));
}
