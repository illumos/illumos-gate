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
 * An evolving, but private, interface to the kernel xPIO (GPIO and DPIO)
 * subsystem.
 */

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <libdevinfo.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/debug.h>

#include "libxpio_impl.h"

xpio_err_t
xpio_err(xpio_t *xpio)
{
	return (xpio->xp_err);
}

xpio_update_err_t
xpio_update_err(xpio_gpio_update_t *update)
{
	return (update->xgo_err);
}

int32_t
xpio_syserr(xpio_t *xpio)
{
	return (xpio->xp_syserr);
}

int32_t
xpio_update_syserr(xpio_gpio_update_t *update)
{
	return (update->xgo_syserr);
}

const char *
xpio_errmsg(xpio_t *xpio)
{
	return (xpio->xp_errmsg);
}

const char *
xpio_update_errmsg(xpio_gpio_update_t *update)
{
	return (update->xgo_errmsg);
}

const char *
xpio_err2str(xpio_t *xpio, xpio_err_t err)
{
	switch (err) {
	case XPIO_ERR_OK:
		return ("XPIO_ERR_OK");
	case XPIO_ERR_NO_MEM:
		return ("XPIO_ERR_NO_MEM");
	case XPIO_ERR_LIBDEVINFO:
		return ("XPIO_ERR_LIBDEVINFO");
	case XPIO_ERR_INTERNAL:
		return ("XPIO_ERR_INTERNAL");
	case XPIO_ERR_BAD_PTR:
		return ("XPIO_ERR_BAD_PTR");
	case XPIO_ERR_WRONG_MINOR_TYPE:
		return ("XPIO_ERR_WRONG_MINOR_TYPE");
	case XPIO_ERR_OPEN_DEV:
		return ("XPIO_ERR_OPEN_DEV");
	case XPIO_ERR_KGPIO:
		return ("XPIO_ERR_KGPIO");
	case XPIO_ERR_BAD_CTRL_NAME:
		return ("XPIO_ERR_BAD_CTRL_NAME");
	case XPIO_ERR_BAD_GPIO_ID:
		return ("XPIO_ERR_BAD_GPIO_ID");
	case XPIO_ERR_BAD_UPDATE:
		return ("XPIO_ERR_BAD_UPDATE");
	case XPIO_ERR_BAD_DPIO_FEAT:
		return ("XPIO_ERR_BAD_DPIO_FEAT");
	case XPIO_ERR_BAD_DPIO_NAME:
		return ("XPIO_ERR_BAD_DPIO_NAME");
	case XPIO_ERR_BAD_GPIO_NAME:
		return ("XPIO_ERR_BAD_GPIO_NAME");
	case XPIO_ERR_NO_LOOKUP_MATCH:
		return ("XPIO_ERR_NO_LOOKUP_MATCH");
	default:
		return ("unknown error");
	}

}

const char *
xpio_update_err2str(xpio_gpio_update_t *update, xpio_update_err_t err)
{
	switch (err) {
	case XPIO_UPDATE_ERR_OK:
		return ("XPIO_UPDATE_ERR_OK");
	case XPIO_UPDATE_ERR_RO:
		return ("XPIO_UPDATE_ERR_RO");
	case XPIO_UPDATE_ERR_UNKNOWN_ATTR:
		return ("XPIO_UPDATE_ERR_UNKNOWN_ATTR");
	case XPIO_UPDATE_ERR_BAD_TYPE:
		return ("XPIO_UPDATE_ERR_BAD_TYPE");
	case XPIO_UPDATE_ERR_UNKNOWN_VAL:
		return ("XPIO_UPDATE_ERR_UNKNOWN_VAL");
	case XPIO_UPDATE_ERR_CANT_APPLY_VAL:
		return ("XPIO_UPDATE_ERR_CANT_APPLY_VAL");
	case XPIO_UPDATE_ERR_NO_MEM:
		return ("XPIO_UPDATE_ERR_NO_MEM");
	case XPIO_UPDATE_ERR_INTERNAL:
		return ("XPIO_UPDATE_ERR_INTERNAL");
	default:
		return ("unknown error");
	}
}

bool
xpio_error(xpio_t *xpio, xpio_err_t err, int32_t sys, const char *fmt, ...)
{
	va_list ap;

	xpio->xp_err = err;
	xpio->xp_syserr = sys;
	va_start(ap, fmt);
	(void) vsnprintf(xpio->xp_errmsg, sizeof (xpio->xp_errmsg), fmt, ap);
	va_end(ap);
	return (false);
}

bool
xpio_update_error(xpio_gpio_update_t *update, xpio_update_err_t err,
    int32_t sys, const char *fmt, ...)
{
	va_list ap;

	update->xgo_err = err;
	update->xgo_syserr = sys;
	va_start(ap, fmt);
	(void) vsnprintf(update->xgo_errmsg, sizeof (update->xgo_errmsg), fmt,
	    ap);
	va_end(ap);
	return (false);
}
bool
xpio_success(xpio_t *xpio)
{
	xpio->xp_err = XPIO_ERR_OK;
	xpio->xp_syserr = 0;
	xpio->xp_errmsg[0] = '\0';
	return (true);
}

bool
xpio_update_success(xpio_gpio_update_t *update)
{
	update->xgo_err = XPIO_UPDATE_ERR_OK;
	update->xgo_syserr = 0;
	update->xgo_errmsg[0] = '\0';
	return (true);
}

typedef struct {
	xpio_t *xcc_xpio;
	xpio_ctrl_disc_f xcc_func;
	void *xcc_arg;
} xpio_ctrl_cb_t;

static int
xpio_ctrl_discover_cb(di_node_t di, di_minor_t minor, void *arg)
{
	bool ret;
	xpio_ctrl_cb_t *cb = arg;
	xpio_ctrl_disc_t disc;

	disc.xcd_minor = minor;

	ret = cb->xcc_func(cb->xcc_xpio, &disc, cb->xcc_arg);
	if (ret) {
		return (DI_WALK_CONTINUE);
	} else {
		return (DI_WALK_TERMINATE);
	}
}

void
xpio_ctrl_discover(xpio_t *xpio, xpio_ctrl_disc_f func, void *arg)
{
	xpio_ctrl_cb_t cb;

	cb.xcc_xpio = xpio;
	cb.xcc_func = func;
	cb.xcc_arg = arg;
	(void) di_walk_minor(xpio->xp_devinfo, DDI_NT_GPIO_CTRL, 0, &cb,
	    xpio_ctrl_discover_cb);
}

void
xpio_ctrl_fini(xpio_ctrl_t *ctrl)
{
	if (ctrl == NULL) {
		return;
	}

	if (ctrl->xc_fd >= 0) {
		(void) close(ctrl->xc_fd);
		ctrl->xc_fd = -1;
	}

	free(ctrl);
}

void
xpio_ctrl_info_free(xpio_ctrl_info_t *infop)
{
	free(infop);
}

uint32_t
xpio_ctrl_info_ngpios(xpio_ctrl_info_t *infop)
{
	return (infop->xci_ngpios);
}

uint32_t
xpio_ctrl_info_ndpios(xpio_ctrl_info_t *infop)
{
	return (infop->xci_ndpios);
}

const char *
xpio_ctrl_info_devpath(xpio_ctrl_info_t *infop)
{
	return (infop->xci_devpath);
}

bool
xpio_ctrl_info(xpio_ctrl_t *ctrl, xpio_ctrl_info_t **outp)
{
	kgpio_ctrl_info_t info;
	xpio_t *xpio = ctrl->xc_xpio;
	xpio_ctrl_info_t *out;

	if (outp == NULL) {
		return (xpio_error(xpio, XPIO_ERR_BAD_PTR, 0, "encountered "
		    "invalid xpio_ctrl_info_t output pointer: %p", outp));
	}

	(void) memset(&info, 0, sizeof (info));
	if (ioctl(ctrl->xc_fd, KGPIO_IOC_CTRL_INFO, &info) != 0) {
		int e = errno;
		return (xpio_error(xpio, XPIO_ERR_KGPIO, e, "failed to issue "
		    "controller information ioctl to %s: %s", ctrl->xc_name,
		    strerror(e)));
	}

	out = calloc(1, sizeof (xpio_ctrl_info_t));
	if (out == NULL) {
		int e = errno;
		return (xpio_error(xpio, XPIO_ERR_NO_MEM, e, "failed to "
		    "allocate memory for a new xpio_ctrl_info_t: %s",
		    strerror(e)));
	}

	out->xci_ngpios = info.kci_ngpios;
	out->xci_ndpios = info.kci_ndpios;
	(void) memcpy(out->xci_devpath, info.kci_devpath,
	    sizeof (info.kci_devpath));

	*outp = out;
	return (xpio_success(xpio));
}

bool
xpio_ctrl_init(xpio_t *xpio, di_minor_t minor, xpio_ctrl_t **outp)
{
	xpio_ctrl_t *ctrl;
	char *path, buf[PATH_MAX];

	if (minor == DI_NODE_NIL) {
		return (xpio_error(xpio, XPIO_ERR_BAD_PTR, 0, "encountered "
		    "invalid di_minor_t: %p", minor));
	}

	if (outp == NULL) {
		return (xpio_error(xpio, XPIO_ERR_BAD_PTR, 0, "encountered "
		    "invalid xpio_ctrl_t output pointer: %p", outp));
	}
	*outp = NULL;

	if (strcmp(di_minor_nodetype(minor), DDI_NT_GPIO_CTRL) != 0) {
		return (xpio_error(xpio, XPIO_ERR_WRONG_MINOR_TYPE, 0,
		    "minor %s has incorrect node type: %s, expected %s",
		    di_minor_name(minor), di_minor_nodetype(minor),
		    DDI_NT_GPIO_CTRL));
	}

	path = di_devfs_minor_path(minor);
	if (path == NULL) {
		int e = errno;
		return (xpio_error(xpio, XPIO_ERR_LIBDEVINFO, e, "failed to "
		    "obtain /devices path for the requested minor: %s",
		    strerror(e)));
	}

	if (snprintf(buf, sizeof (buf), "/devices%s", path) >= sizeof (buf)) {
		di_devfs_path_free(path);
		return (xpio_error(xpio, XPIO_ERR_INTERNAL, 0, "failed to "
		    "construct full /devices minor path, would have overflown "
		    "internal buffer"));
	}
	di_devfs_path_free(path);

	ctrl = calloc(1, sizeof (*ctrl));
	if (ctrl == NULL) {
		int e = errno;
		return (xpio_error(xpio, XPIO_ERR_NO_MEM, e, "failed to "
		    "allocate memory for a new xpio_ctrl_t: %s", strerror(e)));
	}

	ctrl->xc_xpio = xpio;
	ctrl->xc_minor = minor;
	ctrl->xc_name = di_minor_name(minor);

	ctrl->xc_fd = open(buf, O_RDWR);
	if (ctrl->xc_fd < 0) {
		int e = errno;
		xpio_ctrl_fini(ctrl);
		return (xpio_error(xpio, XPIO_ERR_OPEN_DEV, e, "failed to open "
		    "device path %s: %s", buf, strerror(e)));
	}

	*outp = ctrl;
	return (xpio_success(xpio));
}

typedef struct {
	bool xcia_found;
	const char *xcia_name;
	xpio_ctrl_t *xcia_ctrl;
} xpio_ctrl_init_arg_t;

static bool
xpio_ctrl_init_by_name_cb(xpio_t *xpio, xpio_ctrl_disc_t *disc, void *arg)
{
	xpio_ctrl_init_arg_t *init = arg;

	if (strcmp(di_minor_name(disc->xcd_minor), init->xcia_name) != 0) {
		return (true);
	}

	/*
	 * As we've found a match. Attempt to open it. Whether we succeed or
	 * fail, we're done at this point.
	 */
	init->xcia_found = true;
	(void) xpio_ctrl_init(xpio, disc->xcd_minor, &init->xcia_ctrl);
	return (false);
}

bool
xpio_ctrl_init_by_name(xpio_t *xpio, const char *name, xpio_ctrl_t **outp)
{
	xpio_ctrl_init_arg_t init;

	if (name == NULL) {
		return (xpio_error(xpio, XPIO_ERR_BAD_PTR, 0, "encountered "
		    "invalid name pointer: %p", name));
	}

	if (outp == NULL) {
		return (xpio_error(xpio, XPIO_ERR_BAD_PTR, 0, "encountered "
		    "invalid xpio_crl_t output pointer: %p", outp));
	}
	*outp = NULL;

	init.xcia_found = false;
	init.xcia_name = name;
	init.xcia_ctrl = NULL;

	xpio_ctrl_discover(xpio, xpio_ctrl_init_by_name_cb, &init);
	if (!init.xcia_found) {
		return (xpio_error(xpio, XPIO_ERR_BAD_CTRL_NAME, 0, "failed to "
		    "find controller %s", init.xcia_name));
	}

	/*
	 * If we have a NULL controller, but it was found, then we know that
	 * this exists and instead had an error.
	 */
	if (init.xcia_ctrl == NULL) {
		return (false);
	}

	*outp = init.xcia_ctrl;
	return (xpio_success(xpio));
}

void
xpio_gpio_info_free(xpio_gpio_info_t *gi)
{
	if (gi == NULL) {
		return;
	}

	nvlist_free(gi->xgi_nvl);
	free(gi);
}

uint32_t
xpio_gpio_id(xpio_gpio_info_t *gi)
{
	return (gi->xgi_id);
}

bool
xpio_gpio_info(xpio_ctrl_t *ctrl, uint32_t gpio_num, xpio_gpio_info_t **outp)
{
	xpio_t *xpio = ctrl->xc_xpio;
	char *nvl_buf = NULL;
	kgpio_gpio_info_t info;
	bool ret;
	int nvl_ret;
	xpio_gpio_info_t *gi;

	if (outp == NULL) {
		return (xpio_error(xpio, XPIO_ERR_BAD_PTR, 0, "encountered "
		    "invalid xpio_gpio_info_t output pointer: %p", outp));

	}

	nvl_buf = malloc(XPIO_NVL_LEN);
	if (nvl_buf == NULL) {
		int e = errno;
		return (xpio_error(xpio, XPIO_ERR_NO_MEM, e, "failed to "
		    "allocate memory for temporary data: %s", strerror(e)));
	}

	(void) memset(&info, 0, sizeof (info));
	info.kgi_id = gpio_num;
	info.kgi_attr = (uintptr_t)nvl_buf;
	info.kgi_attr_len = XPIO_NVL_LEN;

	if (ioctl(ctrl->xc_fd, KGPIO_IOC_GPIO_INFO, &info) != 0) {
		int e = errno;

		switch (e) {
		case ENOENT:
			ret = xpio_error(xpio, XPIO_ERR_BAD_GPIO_ID, 0, "gpio "
			    "%u does is not a valid GPIO for controller %s",
			    gpio_num, ctrl->xc_name);
			break;
		case EOVERFLOW:
			ret = xpio_error(xpio, XPIO_ERR_INTERNAL, 0,
			    "internal error occurred: serialized nvlist "
			    "exceeds library capabilities: wanted %zu bytes",
			    info.kgi_attr_len);
			break;
		case EFAULT:
			abort();
		default:
			ret = xpio_error(xpio, XPIO_ERR_KGPIO, e, "failed to "
			    "issue gpio information ioctl for gpio %u: %s",
			    gpio_num, strerror(e));
			break;
		}
		goto out;
	}

	gi = calloc(1, sizeof (xpio_gpio_info_t));
	if (gi == NULL) {
		int e = errno;
		ret = xpio_error(xpio, XPIO_ERR_NO_MEM, e, "failed to "
		    "allocate memory for a xpio_gpio_info_t: %s", strerror(e));
		goto out;
	}

	gi->xgi_flags = info.kgi_flags;
	gi->xgi_id = gpio_num;
	nvl_ret = nvlist_unpack(nvl_buf, info.kgi_attr_len, &gi->xgi_nvl, 0);
	if (nvl_ret != 0) {
		free(gi);
		ret = xpio_error(xpio, XPIO_ERR_INTERNAL, nvl_ret, "kernel "
		    "gave us an unparseable nvlist_t: %s", strerror(nvl_ret));
	} else {
		*outp = gi;
		ret = xpio_success(xpio);
	}
out:
	free(nvl_buf);
	return (ret);
}

void
xpio_gpio_update_free(xpio_gpio_update_t *update)
{
	if (update == NULL) {
		return;
	}

	if (update->xgo_update != NULL) {
		nvlist_free(update->xgo_update);
		update->xgo_update = NULL;
	}

	if (update->xgo_err_nvl != NULL) {
		nvlist_free(update->xgo_err_nvl);
		update->xgo_err_nvl = NULL;
	}

	free(update);
}

bool
xpio_gpio_update(xpio_ctrl_t *ctrl, xpio_gpio_update_t *update)
{
	xpio_t *xpio = ctrl->xc_xpio;
	int nvl_ret;
	kgpio_update_t kgu;
	size_t pack_size;
	bool ret;
	char *update_buf = NULL, *err_buf = NULL;

	if (update == NULL) {
		return (xpio_error(xpio, XPIO_ERR_BAD_PTR, 0, "encountered "
		    "invalid xpio_gpio_update_t pointer: %p", update));
	}

	if (update->xgo_err_nvl != NULL) {
		return (xpio_error(xpio, XPIO_ERR_UPDATE_USED, 0, "this "
		    "update structure was already used and has error "
		    "information associated with it"));
	}

	nvl_ret = nvlist_size(update->xgo_update, &pack_size, NV_ENCODE_NATIVE);
	if (nvl_ret != 0) {
		return (xpio_error(xpio, XPIO_ERR_INTERNAL, nvl_ret, "failed "
		    "to determine packed update nvlist_t size: %s",
		    strerror(nvl_ret)));
	}

	update_buf = malloc(pack_size);
	if (update_buf == NULL) {
		int e = errno;
		ret = xpio_error(xpio, XPIO_ERR_NO_MEM, e, "failed to allocate "
		    "%zu bytes for the packed nvlist buffer: %s", pack_size,
		    strerror(e));
		goto out;
	}

	err_buf = malloc(XPIO_NVL_LEN);
	if (err_buf == NULL) {
		int e = errno;
		ret = xpio_error(xpio, XPIO_ERR_NO_MEM, e, "failed to allocate "
		    "%u bytes for the packed error buffer: %s", XPIO_NVL_LEN,
		    strerror(e));
		goto out;
	}

	nvl_ret = nvlist_pack(update->xgo_update, &update_buf, &pack_size,
	    NV_ENCODE_NATIVE, 0);
	if (nvl_ret != 0) {
		ret = xpio_error(xpio, XPIO_ERR_INTERNAL, nvl_ret, "failed to "
		    "pack update data: %s", strerror(nvl_ret));
		goto out;
	}

	(void) memset(&kgu, '\0', sizeof (kgpio_update_t));
	kgu.kgu_id = update->xgo_gpio->xgi_id;
	kgu.kgu_attr = (uintptr_t)update_buf;
	kgu.kgu_attr_len = pack_size;
	kgu.kgu_err = (uintptr_t)err_buf;
	kgu.kgu_err_len = XPIO_NVL_LEN;

	if (ioctl(ctrl->xc_fd, KGPIO_IOC_GPIO_UPDATE, &kgu) != 0) {
		int e = errno;
		ret = xpio_error(xpio, XPIO_ERR_KGPIO, e, "failed to isue "
		    "gpio attribute update ioctl to %s, %u: %s", ctrl->xc_name,
		    update->xgo_gpio->xgi_id, strerror(e));
		goto out;
	}

	/*
	 * With no flags and a zero return value, this was successful. That's
	 * good.
	 */
	if (kgu.kgu_flags == 0) {
		ret = xpio_success(xpio);
		goto out;
	}

	/*
	 * We should have packed information. Attempt to serialize it back into
	 * an nvlist for allowing the user to understand what happened.
	 */
	if ((kgu.kgu_flags & KGPIO_UPDATE_ERR_NVL_VALID) != 0) {
		nvl_ret = nvlist_unpack((char *)kgu.kgu_err, kgu.kgu_err_len,
		    &update->xgo_err_nvl, 0);
		if (nvl_ret != 0) {
			ret = xpio_error(xpio, XPIO_ERR_INTERNAL, nvl_ret,
			    "kernel gave us an unparseable error nvlist_t for "
			    "update failure: %s", strerror(nvl_ret));
			goto out;
		}
	}

	ret = xpio_error(xpio, XPIO_ERR_BAD_UPDATE, 0, "failed to apply GPIO "
	    "update, invalid or unsupported attributes");
out:
	free(update_buf);
	free(err_buf);
	return (ret);
}

bool
xpio_gpio_lookup_id(xpio_ctrl_t *ctrl, const char *name, uint32_t *idp)
{
	xpio_t *xpio = ctrl->xc_xpio;
	kgpio_ioc_name2id_t id;

	if (name == NULL) {
		return (xpio_error(xpio, XPIO_ERR_BAD_PTR, 0, "encountered "
		    "invalid name pointer: %p", name));
	}

	if (idp == NULL) {
		return (xpio_error(xpio, XPIO_ERR_BAD_PTR, 0, "encountered "
		    "invalid id pointer: %p", idp));
	}

	(void) memset(&id, 0, sizeof (id));

	if (strlcpy(id.kin_name, name, sizeof (id.kin_name)) >=
	    sizeof (id.kin_name)) {
		return (xpio_error(xpio, XPIO_ERR_BAD_GPIO_NAME, 0, "GPIO name "
		    "'%s' is too long and invalid", name));
	}

	if (ioctl(ctrl->xc_fd, KGPIO_IOC_GPIO_NAME2ID, &id) != 0) {
		int e = errno;
		switch (e) {
		case ENOENT:
			return (xpio_error(xpio, XPIO_ERR_NO_LOOKUP_MATCH, 0,
			    "GPIO name '%s' is unknown on controller %s",
			    name, ctrl->xc_name));
		case EINVAL:
			return (xpio_error(xpio, XPIO_ERR_BAD_GPIO_NAME, 0,
			    "GPIO name '%s' is invalid", name));
		default:
			return (xpio_error(xpio, XPIO_ERR_KGPIO, e,
			    "failed to issue GPIO name to GPIO id ioctl to "
			    "%s: %s", ctrl->xc_name, strerror(e)));
		}
	}

	*idp = id.kin_id;
	return (xpio_success(xpio));
}

bool
xpio_gpio_update_init(xpio_t *xpio, xpio_gpio_info_t *gi,
    xpio_gpio_update_t **outp)
{
	int ret;
	xpio_gpio_update_t *update;

	if (gi == NULL) {
		return (xpio_error(xpio, XPIO_ERR_BAD_PTR, 0, "encountered "
		    "invalid xpio_gpio_info_t pointer: %p", gi));
	}

	if (outp == NULL) {
		return (xpio_error(xpio, XPIO_ERR_BAD_PTR, 0, "encountered "
		    "invalid xpio_gpio_update_t output pointer: %p", outp));
	}

	update = calloc(1, sizeof (xpio_gpio_update_t));
	if (update == NULL) {
		int e = errno;
		return (xpio_error(xpio, XPIO_ERR_NO_MEM, e, "failed to "
		    "allocate memory for xpio_gpio_update_t: %s", strerror(e)));
	}

	ret = nvlist_alloc(&update->xgo_update, NV_UNIQUE_NAME, 0);
	if (ret != 0) {
		free(update);
		if (ret == ENOMEM) {
			return (xpio_error(xpio, XPIO_ERR_NO_MEM, ret, "failed "
			    "to allocate nvlist_t for xpio_gpio_update_t"));
		}

		return (xpio_error(xpio, XPIO_ERR_INTERNAL, ret, "failed to "
		    "create nvlist_t for xpio_gpio_update_t: %s",
		    strerror(ret)));
	}

	update->xgo_gpio = gi;
	*outp = update;
	return (xpio_success(xpio));
}

void
xpio_fini(xpio_t *xpio)
{
	if (xpio == NULL)
		return;

	if (xpio->xp_devinfo != DI_NODE_NIL) {
		di_fini(xpio->xp_devinfo);
		xpio->xp_devinfo = NULL;
	}

	free(xpio);
}

xpio_t *
xpio_init(void)
{
	xpio_t *xpio;

	xpio = calloc(1, sizeof (xpio_t));
	if (xpio == NULL) {
		return (NULL);
	}
	xpio->xp_err = XPIO_ERR_OK;

	xpio->xp_devinfo = di_init("/", DINFOCPYALL);
	if (xpio->xp_devinfo == DI_NODE_NIL) {
		xpio_fini(xpio);
		return (NULL);
	}

	return (xpio);
}
