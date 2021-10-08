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
 * Copyright 2015 Joyent, Inc.
 */

#ifndef _LIBVARPD_H
#define	_LIBVARPD_H

/*
 * varpd interfaces
 */

#include <sys/types.h>
#include <stdint.h>
#include <sys/mac.h>
#include <libvarpd_client.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct __varpd_handle varpd_handle_t;
typedef struct __varpd_prop_handle varpd_prop_handle_t;
typedef struct __varpd_instance_handle varpd_instance_handle_t;

extern int libvarpd_create(varpd_handle_t **);
extern void libvarpd_destroy(varpd_handle_t *);

extern int libvarpd_persist_enable(varpd_handle_t *, const char *);
extern int libvarpd_persist_restore(varpd_handle_t *);
extern int libvarpd_persist_disable(varpd_handle_t *);

extern int libvarpd_instance_create(varpd_handle_t *, datalink_id_t,
    const char *, varpd_instance_handle_t **);
extern uint64_t libvarpd_instance_id(varpd_instance_handle_t *);
extern varpd_instance_handle_t *libvarpd_instance_lookup(varpd_handle_t *,
    uint64_t);
extern void libvarpd_instance_destroy(varpd_instance_handle_t *);
extern int libvarpd_instance_activate(varpd_instance_handle_t *);

extern int libvarpd_plugin_load(varpd_handle_t *, const char *);
typedef int (*libvarpd_plugin_walk_f)(varpd_handle_t *, const char *, void *);
extern int libvarpd_plugin_walk(varpd_handle_t *, libvarpd_plugin_walk_f,
    void *);

extern int libvarpd_prop_handle_alloc(varpd_handle_t *,
    varpd_instance_handle_t *, varpd_prop_handle_t **);
extern void libvarpd_prop_handle_free(varpd_prop_handle_t *);
extern int libvarpd_prop_nprops(varpd_instance_handle_t *, uint_t *);
extern int libvarpd_prop_info_fill(varpd_prop_handle_t *, uint_t);
extern int libvarpd_prop_info(varpd_prop_handle_t *, const char **, uint_t *,
    uint_t *, const void **, uint32_t *, const mac_propval_range_t **);
extern int libvarpd_prop_get(varpd_prop_handle_t *, void *, uint32_t *);
extern int libvarpd_prop_set(varpd_prop_handle_t *, const void *, uint32_t);

extern int libvarpd_door_server_create(varpd_handle_t *, const char *);
extern void libvarpd_door_server_destroy(varpd_handle_t *);

extern void *libvarpd_overlay_lookup_run(void *);
extern void libvarpd_overlay_lookup_quiesce(varpd_handle_t *);

#ifdef __cplusplus
}
#endif

#endif /* _LIBVARPD_H */
