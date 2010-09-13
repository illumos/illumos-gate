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

#ifndef	_LIBSMP_PLUGIN_H
#define	_LIBSMP_PLUGIN_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/scsi/generic/smp_frames.h>
#include <scsi/libsmp.h>

#include <stddef.h>

#define	LIBSMP_PLUGIN_VERSION	1
#define	LIBSMP_ENGINE_VERSION	1

#ifndef SMP_REQ_MINLEN
#define	SMP_REQ_MINLEN	\
	(offsetof(smp_request_frame_t, srf_data[0]) + sizeof (smp_crc_t))
#endif
#ifndef	SMP_RESP_MINLEN
#define	SMP_RESP_MINLEN	\
	(offsetof(smp_response_frame_t, srf_data[0]) + sizeof (smp_crc_t))
#endif

#define	VERIFY(x)	((void)((x) || smp_assert(#x, __FILE__, __LINE__)))

#ifdef DEBUG
#define	ASSERT(x)	VERIFY(x)
#else
#define	ASSERT(x)
#endif

struct smp_engine;
typedef struct smp_engine smp_engine_t;

struct smp_plugin;
typedef struct smp_plugin smp_plugin_t;

typedef struct smp_engine_ops {
	void *(*seo_open)(const void *);
	void (*seo_close)(void *);
	int (*seo_exec)(void *, smp_action_t *);
	void (*seo_target_name)(void *, char *, size_t);
	uint64_t (*seo_target_addr)(void *);
} smp_engine_ops_t;

typedef struct smp_engine_config {
	const char *sec_name;
	const smp_engine_ops_t *sec_ops;
} smp_engine_config_t;

#define	SMP_FD_F_NEEDS_CHANGE_COUNT	0x0001
#define	SMP_FD_F_PROVIDES_CHANGE_COUNT	0x0002
#define	SMP_FD_F_READ			0x0004
#define	SMP_FD_F_WRITE			0x0008

typedef struct smp_function_def {
	smp_function_t sfd_function;
	uint_t sfd_capmask;
	uint_t sfd_capset;
	uint_t sfd_flags;
	size_t (*sfd_rq_len)(size_t, smp_target_t *);
	off_t (*sfd_rq_dataoff)(smp_action_t *, smp_target_t *);
	void (*sfd_rq_setframe)(smp_action_t *, smp_target_t *);
	size_t (*sfd_rs_datalen)(smp_action_t *, smp_target_t *);
	off_t (*sfd_rs_dataoff)(smp_action_t *, smp_target_t *);
	void (*sfd_rs_getparams)(smp_action_t *, smp_target_t *);
} smp_function_def_t;

typedef struct smp_plugin_config {
	const char *spc_name;
	smp_function_def_t *spc_functions;
} smp_plugin_config_t;

extern int smp_assert(const char *, const char *, int);

extern void *smp_alloc(size_t);
extern void *smp_zalloc(size_t);
extern char *smp_strdup(const char *);
extern void smp_free(void *);

extern int smp_set_errno(smp_errno_t);
extern int smp_verror(smp_errno_t, const char *, va_list);
extern int smp_error(smp_errno_t, const char *, ...);

extern void smp_action_get_request_frame(const smp_action_t *,
    void **, size_t *);
extern void smp_action_get_response_frame(const smp_action_t *,
    void **, size_t *);
extern void smp_action_set_response_len(smp_action_t *, size_t);
extern void smp_action_set_result(smp_action_t *, smp_result_t);
extern const smp_function_def_t *smp_action_get_function_def(
    const smp_action_t *);

extern int smp_engine_register(smp_engine_t *, int,
    const smp_engine_config_t *);

extern int smp_plugin_register(smp_plugin_t *, int,
    const smp_plugin_config_t *);
extern void smp_plugin_setspecific(smp_plugin_t *, void *);
extern void *smp_plugin_getspecific(smp_plugin_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBSMP_PLUGIN_H */
