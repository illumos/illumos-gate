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
 * Copyright (c) 2018, Joyent, Inc.
 */

#ifndef _SYS_SDEV_PLUGIN_H
#define	_SYS_SDEV_PLUGIN_H

/*
 * Kernel sdev plugin interface
 */

#ifdef _KERNEL

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/vnode.h>

#endif	/* _KERNEL */

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _KERNEL

typedef uintptr_t sdev_plugin_hdl_t;
typedef uintptr_t sdev_ctx_t;

/*
 * Valid return values for sdev_plugin_validate_t.
 */
typedef enum sdev_plugin_validate {
	SDEV_VTOR_INVALID = -1,
	SDEV_VTOR_SKIP = 0,
	SDEV_VTOR_VALID	= 1,
	SDEV_VTOR_STALE	= 2
} sdev_plugin_validate_t;

/*
 * Valid flags
 */
typedef enum sdev_plugin_flags {
	SDEV_PLUGIN_NO_NCACHE = 0x1,
	SDEV_PLUGIN_SUBDIR = 0x2
} sdev_plugin_flags_t;

#define	SDEV_PLUGIN_FLAGS_MASK	0x3

/*
 * Functions a module must implement
 */
typedef sdev_plugin_validate_t (*sp_valid_f)(sdev_ctx_t);
typedef int (*sp_filldir_f)(sdev_ctx_t);
typedef void (*sp_inactive_f)(sdev_ctx_t);

#define	SDEV_PLUGIN_VERSION	1

typedef struct sdev_plugin_ops {
	int spo_version;
	sdev_plugin_flags_t spo_flags;
	sp_valid_f spo_validate;
	sp_filldir_f spo_filldir;
	sp_inactive_f spo_inactive;
} sdev_plugin_ops_t;

extern sdev_plugin_hdl_t sdev_plugin_register(const char *, sdev_plugin_ops_t *,
    int *);
extern int sdev_plugin_unregister(sdev_plugin_hdl_t);

typedef enum sdev_ctx_flags {
	SDEV_CTX_GLOBAL = 0x2	/* node belongs to the GZ */
} sdev_ctx_flags_t;

/*
 * Context helper functions
 */
extern sdev_ctx_flags_t sdev_ctx_flags(sdev_ctx_t);
extern const char *sdev_ctx_name(sdev_ctx_t);
extern const char *sdev_ctx_path(sdev_ctx_t);
extern int sdev_ctx_minor(sdev_ctx_t, minor_t *);
extern enum vtype sdev_ctx_vtype(sdev_ctx_t);

/*
 * Callbacks to manipulate nodes
 */
extern int sdev_plugin_mkdir(sdev_ctx_t, char *);
extern int sdev_plugin_mknod(sdev_ctx_t, char *, mode_t, dev_t);

#endif	/* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_SDEV_PLUGIN_H */
