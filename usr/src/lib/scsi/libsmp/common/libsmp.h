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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_LIBSMP_H
#define	_LIBSMP_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/scsi/impl/usmp.h>
#include <sys/scsi/generic/smp_frames.h>
#include <libnvpair.h>
#include <stdarg.h>

#define	LIBSMP_VERSION		1

#define	SMP_TARGET_C_LONG_RESP	0x01	/* Long response (SAS-2 10.4.3.4) */
#define	SMP_TARGET_C_ZONING	0x02	/* Zoning supported */
#define	SMP_TARGET_C_ZG_256	0x04	/* 256 zone groups supported */

typedef enum smp_errno {
	ESMP_NONE,		/* no error */
	ESMP_NOMEM,		/* no memory */
	ESMP_ZERO_LENGTH,	/* zero-length allocation requested */
	ESMP_VERSION,		/* library version mismatch */
	ESMP_BADTARGET,		/* invalid target specification */
	ESMP_BADFUNC,		/* invalid SMP function */
	ESMP_BADENGINE,		/* engine library corrupt */
	ESMP_NOENGINE,		/* engine library not found */
	ESMP_ENGINE_INIT,	/* engine initialization failed */
	ESMP_ENGINE_VER,	/* engine version mismatch */
	ESMP_ENGINE_BADPATH,	/* engine path contains no usable components */
	ESMP_BADLENGTH,		/* buffer length overflow or size error */
	ESMP_NEEDBUF,		/* missing required buffer */
	ESMP_PLUGIN,		/* no plugins found */
	ESMP_IO,		/* I/O operation failed */
	ESMP_SYS,		/* system call failed */
	ESMP_PERM,		/* insufficient permissions */
	ESMP_RANGE,		/* parameter outside valid range */
	ESMP_NOTSUP,		/* operation not supported */
	ESMP_UNKNOWN,		/* error of unknown type */
	ESMP_REPGEN_FAILED,	/* initial report general command failed */
	ESMP_MAX		/* maximum libsmp errno value */
} smp_errno_t;

typedef struct smp_target_def {
	const char *std_engine;
	const void *std_def;
} smp_target_def_t;

struct smp_target;
typedef struct smp_target smp_target_t;

struct smp_action;
typedef struct smp_action smp_action_t;

extern int smp_init(int);
extern void smp_fini(void);

extern smp_target_t *smp_open(const smp_target_def_t *);
extern uint_t smp_target_getcap(const smp_target_t *);
extern uint16_t smp_target_get_change_count(const smp_target_t *);
extern void smp_target_set_change_count(smp_target_t *, uint16_t);
extern const char *smp_target_vendor(const smp_target_t *);
extern const char *smp_target_product(const smp_target_t *);
extern const char *smp_target_revision(const smp_target_t *);
extern const char *smp_target_component_vendor(const smp_target_t *);
extern uint16_t smp_target_component_id(const smp_target_t *);
extern uint8_t smp_target_component_revision(const smp_target_t *);
extern void smp_target_name(const smp_target_t *, char *, size_t);
extern uint64_t smp_target_addr(const smp_target_t *);
extern void smp_close(smp_target_t *);

extern smp_errno_t smp_errno(void);
extern smp_errno_t smp_errcode(const char *);
extern const char *smp_errmsg(void);
extern const char *smp_strerror(smp_errno_t);
extern const char *smp_errname(smp_errno_t);

extern char *smp_trim_strdup(const char *, size_t);

extern smp_action_t *smp_action_alloc(smp_function_t, smp_target_t *, size_t);
extern smp_action_t *smp_action_xalloc(smp_function_t, smp_target_t *,
    void *, size_t, void *, size_t);
extern uint32_t smp_action_get_timeout(const smp_action_t *);
extern void smp_action_set_timeout(smp_action_t *, uint32_t);
extern void smp_action_get_request(const smp_action_t *, void **, size_t *);
extern void smp_action_get_response(const smp_action_t *,
    smp_result_t *, void **, size_t *);
extern int smp_exec(smp_action_t *, smp_target_t *);
extern void smp_action_free(smp_action_t *);

extern nvlist_t *smp_discover(const smp_target_def_t **, size_t);
extern nvlist_t *smp_discover_targets(smp_target_t **, size_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBSMP_H */
