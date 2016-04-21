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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2016 Joyent, Inc.
 */

#ifndef	_LIBSCSI_H
#define	_LIBSCSI_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/scsi/impl/spc3_types.h>
#include <stdarg.h>

#define	LIBSCSI_VERSION		1
#define	LIBSCSI_STATUS_INVALID	((sam4_status_t)-1)
#define	LIBSCSI_DEFAULT_ENGINE_PATH	"/usr/lib/scsi/plugins/scsi/engines"
#define	LIBSCSI_DEFAULT_ENGINE	"uscsi"

/*
 * Flags for action creation.  Selected to avoid overlap with the uscsi
 * flags with similar or identical meaning.
 */
#define	LIBSCSI_AF_READ		0x80000000
#define	LIBSCSI_AF_WRITE	0x40000000
#define	LIBSCSI_AF_SILENT	0x20000000
#define	LIBSCSI_AF_DIAGNOSE	0x10000000
#define	LIBSCSI_AF_ISOLATE	0x08000000
#define	LIBSCSI_AF_RQSENSE	0x04000000

typedef enum libscsi_errno {
	ESCSI_NONE,		/* no error */
	ESCSI_NOMEM,		/* no memory */
	ESCSI_ZERO_LENGTH,	/* zero-length allocation requested */
	ESCSI_VERSION,		/* library version mismatch */
	ESCSI_BADTARGET,	/* invalid target specification */
	ESCSI_BADCMD,		/* invalid SCSI command */
	ESCSI_BADENGINE,	/* engine library corrupt */
	ESCSI_NOENGINE,		/* engine library not found */
	ESCSI_ENGINE_INIT,	/* engine initialization failed */
	ESCSI_ENGINE_VER,	/* engine version mismatch */
	ESCSI_ENGINE_BADPATH,	/* engine path contains no usable components */
	ESCSI_BADFLAGS,		/* incorrect action flags */
	ESCSI_BOGUSFLAGS,	/* unknown flag value */
	ESCSI_BADLENGTH,	/* buffer length overflow */
	ESCSI_NEEDBUF,		/* missing required buffer */
	ESCSI_IO,		/* I/O operation failed */
	ESCSI_SYS,		/* system call failed */
	ESCSI_PERM,		/* insufficient permissions */
	ESCSI_RANGE,		/* parameter outside valid range */
	ESCSI_NOTSUP,		/* operation not supported */
	ESCSI_UNKNOWN,		/* error of unknown type */
	ESCSI_INQUIRY_FAILED,	/* initial inquiry command failed */
	ESCSI_MAX		/* maximum libscsi errno value */
} libscsi_errno_t;

struct libscsi_hdl;
typedef struct libscsi_hdl libscsi_hdl_t;

struct libscsi_target;
typedef struct libscsi_target libscsi_target_t;

typedef struct libscsi_status {
	uint64_t lss_status;		/* SCSI status of this command */
	size_t lss_sense_len;		/* Length in bytes of sense data */
	uint8_t *lss_sense_data;	/* Pointer to sense data */
} libscsi_status_t;

struct libscsi_action;
typedef struct libscsi_action libscsi_action_t;

typedef struct libscsi_engine_ops {
	void *(*lseo_open)(libscsi_hdl_t *, const void *);
	void (*lseo_close)(libscsi_hdl_t *, void *);
	int (*lseo_exec)(libscsi_hdl_t *, void *, libscsi_action_t *);
	void (*lseo_target_name)(libscsi_hdl_t *, void *, char *, size_t);
	int (*lseo_max_transfer)(libscsi_hdl_t *, void *, size_t *);
} libscsi_engine_ops_t;

typedef struct libscsi_engine {
	const char *lse_name;
	uint_t lse_libversion;
	const libscsi_engine_ops_t *lse_ops;
} libscsi_engine_t;

extern libscsi_hdl_t *libscsi_init(uint_t, libscsi_errno_t *);
extern void libscsi_fini(libscsi_hdl_t *);

extern libscsi_target_t *libscsi_open(libscsi_hdl_t *, const char *,
    const void *);
extern void libscsi_close(libscsi_hdl_t *, libscsi_target_t *);
extern libscsi_hdl_t *libscsi_get_handle(libscsi_target_t *);

extern const char *libscsi_vendor(libscsi_target_t *);
extern const char *libscsi_product(libscsi_target_t *);
extern const char *libscsi_revision(libscsi_target_t *);
extern int libscsi_max_transfer(libscsi_target_t *, size_t *);

extern libscsi_errno_t libscsi_errno(libscsi_hdl_t *);
extern const char *libscsi_errmsg(libscsi_hdl_t *);
extern const char *libscsi_strerror(libscsi_errno_t);
extern const char *libscsi_errname(libscsi_errno_t);
extern libscsi_errno_t libscsi_errcode(const char *);

extern libscsi_action_t *libscsi_action_alloc(libscsi_hdl_t *, spc3_cmd_t,
    uint_t, void *, size_t);
extern sam4_status_t libscsi_action_get_status(const libscsi_action_t *);
extern void libscsi_action_set_timeout(libscsi_action_t *, uint32_t);
extern uint32_t libscsi_action_get_timeout(const libscsi_action_t *);
extern uint_t libscsi_action_get_flags(const libscsi_action_t *);
extern uint8_t *libscsi_action_get_cdb(const libscsi_action_t *);
extern int libscsi_action_get_buffer(const libscsi_action_t *,
    uint8_t **, size_t *, size_t *);
extern int libscsi_action_get_sense(const libscsi_action_t *,
    uint8_t **, size_t *, size_t *);
extern int libscsi_action_parse_sense(const libscsi_action_t *, uint64_t *,
    uint64_t *, uint64_t *, diskaddr_t *);
extern void libscsi_action_set_status(libscsi_action_t *, sam4_status_t);
extern int libscsi_action_set_datalen(libscsi_action_t *, size_t);
extern int libscsi_action_set_senselen(libscsi_action_t *, size_t);
extern int libscsi_exec(libscsi_action_t *, libscsi_target_t *);
extern void libscsi_action_free(libscsi_action_t *);

extern const char *libscsi_sense_key_name(uint64_t);
extern const char *libscsi_sense_code_name(uint64_t, uint64_t);

/*
 * Interfaces for engine providers
 */
extern void *libscsi_alloc(libscsi_hdl_t *, size_t);
extern void *libscsi_zalloc(libscsi_hdl_t *, size_t);
extern char *libscsi_strdup(libscsi_hdl_t *, const char *);
extern void libscsi_free(libscsi_hdl_t *, void *);
extern libscsi_status_t *libscsi_status_alloc(libscsi_hdl_t *, size_t);
extern int libscsi_status_fill(libscsi_hdl_t *, libscsi_status_t *,
    uint16_t, size_t);
extern void libscsi_status_free(libscsi_hdl_t *, libscsi_status_t *);

extern int libscsi_set_errno(libscsi_hdl_t *, libscsi_errno_t);
extern int libscsi_verror(libscsi_hdl_t *, libscsi_errno_t, const char *,
    va_list);
extern int libscsi_error(libscsi_hdl_t *, libscsi_errno_t, const char *, ...);

typedef const libscsi_engine_t *(*libscsi_engine_init_f)(libscsi_hdl_t *);

/*
 * Generic SCSI utility functions.
 */
extern size_t libscsi_cmd_cdblen(libscsi_hdl_t *, uint8_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBSCSI_H */
