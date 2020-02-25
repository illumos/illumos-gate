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
 * Copyright (c) 2015 Joyent, Inc.
 * Copyright 2020 OmniOS Community Edition (OmniOSce) Association.
 */

#ifndef _LIBDLOVERLAY_H
#define	_LIBDLOVERLAY_H

/*
 * libdladm Overlay device routines
 */

#include <libdladm.h>
#include <libdladm_impl.h>
#include <sys/overlay.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dladm_overlay_attr {
	datalink_id_t		oa_linkid;
	char			oa_name[MAXLINKNAMELEN];
	char			oa_encap[OVERLAY_PROP_SIZEMAX];
	char			oa_search[OVERLAY_PROP_SIZEMAX];
	uint64_t		oa_vid;
	uint32_t		oa_flags;
} dladm_overlay_attr_t;

#define	DLADM_OVERLAY_F_DROP	0x0001
#define	DLADM_OVERLAY_F_DEFAULT	0xf000

typedef struct dladm_overlay_point {
	uint_t			dop_dest;
	struct ether_addr	dop_mac;
	uint16_t		dop_flags;
	struct in6_addr		dop_ip;
	uint16_t		dop_port;
} dladm_overlay_point_t;

typedef struct dladm_overlay_status {
	boolean_t	dos_degraded;
	char		dos_fmamsg[256];
} dladm_overlay_status_t;

extern dladm_status_t dladm_overlay_create(dladm_handle_t, const char *,
    const char *, const char *, uint64_t, dladm_arg_list_t *, dladm_errlist_t *,
    uint32_t);
extern dladm_status_t dladm_overlay_delete(dladm_handle_t, datalink_id_t,
    uint32_t);
extern dladm_status_t dladm_overlay_up(dladm_handle_t, datalink_id_t,
    dladm_errlist_t *);

typedef void (*dladm_overlay_status_f)(dladm_handle_t, datalink_id_t,
    dladm_overlay_status_t *, void *);
extern dladm_status_t dladm_overlay_status(dladm_handle_t, datalink_id_t,
    dladm_overlay_status_f, void *);

extern dladm_status_t dladm_overlay_cache_flush(dladm_handle_t, datalink_id_t);
extern dladm_status_t dladm_overlay_cache_delete(dladm_handle_t, datalink_id_t,
    const struct ether_addr *);
extern dladm_status_t dladm_overlay_cache_set(dladm_handle_t, datalink_id_t,
    const struct ether_addr *, char *);
extern dladm_status_t dladm_overlay_cache_get(dladm_handle_t, datalink_id_t,
    const struct ether_addr *, dladm_overlay_point_t *);

#define	DLADM_OVERLAY_PROP_SIZEMAX	256
#define	DLADM_OVERLAY_PROP_NAMELEN	32

typedef struct __dladm_overlay_propinfo *dladm_overlay_propinfo_handle_t;

extern dladm_status_t dladm_overlay_prop_info(dladm_overlay_propinfo_handle_t,
    const char **, uint_t *, uint_t *, const void **, uint32_t *,
    const mac_propval_range_t **);
extern dladm_status_t dladm_overlay_get_prop(dladm_handle_t, datalink_id_t,
    dladm_overlay_propinfo_handle_t, void *buf, size_t *bufsize);

typedef int (*dladm_overlay_prop_f)(dladm_handle_t, datalink_id_t,
    dladm_overlay_propinfo_handle_t, void *);
extern dladm_status_t dladm_overlay_walk_prop(dladm_handle_t, datalink_id_t,
    dladm_overlay_prop_f, void *arg, dladm_errlist_t *);

typedef int (*dladm_overlay_cache_f)(dladm_handle_t, datalink_id_t,
    const struct ether_addr *, const dladm_overlay_point_t *, void *);
extern dladm_status_t dladm_overlay_walk_cache(dladm_handle_t, datalink_id_t,
    dladm_overlay_cache_f, void *);

/*
 * Some day we'll want to support being able to set properties after creation.
 * If we do, the following strawman API might serve us well.
 *
 * extern dladm_status_t dladm_overlay_prop_lookup(dladm_handle_t,
 *     datalink_id_t, const char *, dladm_overlay_propinfo_handle_t *);
 * extern void dladm_overlay_prop_handle_free(dladm_handle_t, datalink_id_t,
 *     dladm_overlay_propinfo_handle_t *);
 * extern dladm_status_t dladm_overlay_set_prop(dladm_handle_t, datalink_id_t,
 *     dladm_propinfo_handle_t, void *buf, size_t *bufsize);
 * extern dladm_status_t dladm_overlay_str_to_buf(dladm_handle_t, datalink_id_t,
 *     dladm_overlay_propinfo_handle_t *, const char *, void *, size_t *);
 * extern dladm_status_t dladm_overlay_buf_to_str(dladm_handle_t, datalink_id_t,
 *     dladm_overlay_propinfo_handle_t *, const void *, const size_t, char *,
 *     size_t *);
 */

#ifdef __cplusplus
}
#endif

#endif /* _LIBDLOVERLAY_H */
