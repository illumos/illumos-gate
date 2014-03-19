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
 * Copyright (c) 2014 Joyent, Inc.  All rights reserved.
 */

#ifndef _LIBVND_H
#define	_LIBVND_H

/*
 * libvnd interfaces
 */

#include <stdint.h>
#include <sys/vnd_errno.h>
#include <sys/frameio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	LIBVND_NAMELEN	32

typedef struct vnd_handle vnd_handle_t;

extern vnd_handle_t *vnd_create(const char *, const char *, const char *,
    vnd_errno_t *, int *);
extern vnd_handle_t *vnd_open(const char *, const char *, vnd_errno_t *, int *);
extern int vnd_unlink(vnd_handle_t *);
extern void vnd_close(vnd_handle_t *);
extern vnd_errno_t vnd_errno(vnd_handle_t *);
extern int vnd_syserrno(vnd_handle_t *);
extern const char *vnd_strerror(vnd_errno_t);
extern const char *vnd_strsyserror(int);

extern int vnd_pollfd(vnd_handle_t *);

typedef struct vnd_info {
	uint32_t vi_version;
	zoneid_t vi_zone;
	char vi_name[LIBVND_NAMELEN];
	char vi_datalink[LIBVND_NAMELEN];
} vnd_info_t;

typedef int (*vnd_walk_cb_t)(vnd_info_t *, void *);
extern int vnd_walk(vnd_walk_cb_t, void *, vnd_errno_t *, int *);

typedef enum vnd_prop {
	VND_PROP_RXBUF = 0,
	VND_PROP_TXBUF,
	VND_PROP_MAXBUF,
	VND_PROP_MINTU,
	VND_PROP_MAXTU,
	VND_PROP_MAX
} vnd_prop_t;

typedef struct vnd_prop_buf {
	uint64_t vpb_size;
} vnd_prop_buf_t;

extern int vnd_prop_get(vnd_handle_t *, vnd_prop_t, void *, size_t);
extern int vnd_prop_set(vnd_handle_t *, vnd_prop_t, void *, size_t);
extern int vnd_prop_writeable(vnd_prop_t, boolean_t *);

typedef int (*vnd_prop_iter_f)(vnd_handle_t *, vnd_prop_t, void *);
extern int vnd_prop_iter(vnd_handle_t *, vnd_prop_iter_f, void *);

extern int vnd_frameio_read(vnd_handle_t *, frameio_t *);
extern int vnd_frameio_write(vnd_handle_t *, frameio_t *);

#ifdef __cplusplus
}
#endif

#endif /* _LIBVND_H */
