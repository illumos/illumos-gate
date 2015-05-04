/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2015, Joyent, Inc.
 * Copyright 2014 Nexenta Systems, Inc. All rights reserved.
 */

#ifndef	_LIBBRAND_H
#define	_LIBBRAND_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>

typedef struct __brand_handle *brand_handle_t;

typedef struct priv_iter_s {
	char	*pi_name;
	char	*pi_set;
	char	*pi_iptype;
} priv_iter_t;

extern brand_handle_t brand_open(const char *);
extern void brand_close(brand_handle_t);

extern boolean_t brand_allow_exclusive_ip(brand_handle_t);

extern int brand_get_attach(brand_handle_t, const char *, const char *,
    char *, size_t);
extern int brand_get_boot(brand_handle_t, const char *, const char *,
    char *, size_t);
extern int brand_get_brandname(brand_handle_t, char *, size_t);
extern int brand_get_clone(brand_handle_t, const char *, const char *,
    char *, size_t);
extern int brand_get_detach(brand_handle_t, const char *, const char *,
    char *, size_t);
extern int brand_get_shutdown(brand_handle_t, const char *, const char *,
    char *, size_t);
extern int brand_get_halt(brand_handle_t, const char *, const char *,
    char *, size_t);
extern int brand_get_initname(brand_handle_t, char *, size_t);
extern boolean_t brand_restartinit(brand_handle_t);
extern int brand_get_install(brand_handle_t, const char *, const char *,
    char *, size_t);
extern int brand_get_installopts(brand_handle_t, char *, size_t);
extern int brand_get_login_cmd(brand_handle_t, const char *, char *, size_t);
extern int brand_get_forcedlogin_cmd(brand_handle_t, const char *,
    char *, size_t);
extern int brand_get_modname(brand_handle_t, char *, size_t);
extern int brand_get_postattach(brand_handle_t, const char *, const char *,
    char *, size_t);
extern int brand_get_postclone(brand_handle_t, const char *, const char *,
    char *, size_t);
extern int brand_get_postinstall(brand_handle_t, const char *, const char *,
    char *, size_t);
extern int brand_get_postsnap(brand_handle_t, const char *, const char *,
    char *, size_t);
extern int brand_get_poststatechange(brand_handle_t, const char *, const char *,
    char *, size_t);
extern int brand_get_predetach(brand_handle_t, const char *, const char *,
    char *, size_t);
extern int brand_get_presnap(brand_handle_t, const char *, const char *,
    char *, size_t);
extern int brand_get_prestatechange(brand_handle_t, const char *, const char *,
    char *, size_t);
extern int brand_get_preuninstall(brand_handle_t, const char *, const char *,
    char *, size_t);
extern int brand_get_query(brand_handle_t, const char *, const char *,
    char *, size_t);
extern int brand_get_uninstall(brand_handle_t, const char *, const char *,
    char *, size_t);
extern int brand_get_validatesnap(brand_handle_t, const char *, const char *,
    char *, size_t);
extern int brand_get_user_cmd(brand_handle_t, const char *, char *, size_t);
extern int brand_get_verify_cfg(brand_handle_t, char *, size_t);
extern int brand_get_verify_adm(brand_handle_t, const char *, const char *,
    char *, size_t);
extern int brand_get_sysboot(brand_handle_t, const char *, const char *, char *,
    size_t);

extern int brand_config_iter_privilege(brand_handle_t,
    int (*func)(void *, priv_iter_t *), void *);

extern int brand_platform_iter_devices(brand_handle_t, const char *,
    int (*)(void *, const char *, const char *), void *, const char *);
extern int brand_platform_iter_gmounts(brand_handle_t, const char *,
    const char *, int (*)(void *, const char *, const char *, const char *,
    const char *), void *);
extern int brand_platform_iter_link(brand_handle_t, int (*)(void *,
    const char *, const char *), void *);
extern int brand_platform_iter_mounts(brand_handle_t, int (*)(void *,
    const char *, const char *, const char *, const char *), void *);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBBRAND_H */
