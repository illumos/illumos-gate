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

#ifndef _LIBXPIO_IMPL_H
#define	_LIBXPIO_IMPL_H

/*
 * Internal implementation pieces of libxpio.
 */

#include <libxpio.h>
#include <sys/gpio/kgpio.h>
#include <sys/gpio/kgpio_provider.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Maximum size of an internal error message.
 */
#define	XPIO_ERR_LEN	1024

/*
 * Maximum size of an nvlist attribute buffer that we'll alloc right now.
 */
#define	XPIO_NVL_LEN	(16 * 1024)

struct xpio {
	xpio_err_t xp_err;
	int32_t xp_syserr;
	char xp_errmsg[XPIO_ERR_LEN];
	di_node_t xp_devinfo;
};

struct xpio_ctrl {
	list_node_t xc_link;
	xpio_t *xc_xpio;
	di_minor_t xc_minor;
	const char *xc_name;
	int xc_fd;
};

struct xpio_ctrl_info {
	uint32_t xci_ngpios;
	uint32_t xci_ndpios;
	char xci_devpath[MAXPATHLEN];
};

struct xpio_gpio_info {
	uint32_t xgi_id;
	kgpio_gpio_flags_t xgi_flags;
	nvlist_t *xgi_nvl;
};

struct xpio_gpio_update {
	xpio_update_err_t xgo_err;
	int32_t xgo_syserr;
	char xgo_errmsg[XPIO_ERR_LEN];
	xpio_gpio_info_t *xgo_gpio;
	nvlist_t *xgo_update;
	nvlist_t *xgo_err_nvl;
};

struct xpio_dpio_info {
	char xdi_dpio[DPIO_NAMELEN];
	char xdi_ctrl[DPIO_NAMELEN];
	uint32_t xdi_gpio;
	dpio_caps_t xdi_caps;
	dpio_flags_t xdi_flags;
};

extern bool xpio_error(xpio_t *, xpio_err_t, int32_t, const char *,
    ...)  __PRINTFLIKE(4);
extern bool xpio_success(xpio_t *);
extern bool xpio_update_error(xpio_gpio_update_t *, xpio_update_err_t, int32_t,
    const char *, ...)  __PRINTFLIKE(4);
extern bool xpio_update_success(xpio_gpio_update_t *);

#ifdef __cplusplus
}
#endif

#endif /* _LIBXPIO_IMPL_H */
