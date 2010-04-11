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

#ifndef	_SMP_IMPL_H
#define	_SMP_IMPL_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/scsi/generic/smp_frames.h>

#include <scsi/libsmp.h>
#include <scsi/libsmp_plugin.h>

#include <pthread.h>

#define	LIBSMP_ERRMSGLEN	512

#define	LIBSMP_DEFAULT_PLUGINDIR	"/usr/lib/scsi/plugins/smp"
#define	LIBSMP_PLUGIN_ENGINE		"engine"
#define	LIBSMP_PLUGIN_FRAMEWORK		"framework"
#define	LIBSMP_PLUGIN_VENDOR		"vendor"

#define	LIBSMP_PLUGIN_EXT		".so"

#define	LIBSMP_DEFAULT_ENGINE		"usmp"

struct smp_engine {
	char *se_name;
	const smp_engine_ops_t *se_ops;
	void *se_object;
	int (*se_init)(struct smp_engine *);
	void (*se_fini)(struct smp_engine *);
	uint_t se_refcnt;
	struct smp_engine *se_next;
};

struct smp_plugin {
	struct smp_plugin *sp_next;
	struct smp_plugin *sp_prev;
	smp_target_t *sp_target;
	uint64_t sp_priority;
	void *sp_object;
	void *sp_data;
	boolean_t sp_initialized;
	const smp_function_def_t *sp_functions;
	int (*sp_init)(smp_plugin_t *);
	void (*sp_fini)(smp_plugin_t *);
};

#define	SMP_ACTION_F_OFFSET		0x01
#define	SMP_ACTION_F_EXEC		0x02
#define	SMP_ACTION_F_DECODE		0x04

struct smp_action {
	uint32_t sa_timeout;
	const smp_function_def_t *sa_def;
	uint8_t *sa_request;
	size_t sa_request_rqsd;
	size_t sa_request_alloc_len;
	off_t sa_request_data_off;
	uint8_t *sa_response;
	size_t sa_response_alloc_len;
	size_t sa_response_engine_len;
	size_t sa_response_data_len;
	off_t sa_response_data_off;
	smp_result_t sa_result;
	uint_t sa_flags;
	uint_t sa_cap;
	uint8_t sa_buf[1];
};

struct smp_target {
	smp_engine_t *st_engine;
	void *st_priv;
	uint_t st_mtbf_request;
	uint_t st_mtbf_response;
	uint16_t st_change_count;
	smp_plugin_t *st_plugin_first;
	smp_plugin_t *st_plugin_last;
	char *st_vendor;
	char *st_product;
	char *st_revision;
	char *st_component_vendor;
	uint16_t st_component_id;
	uint8_t st_component_revision;
	smp_report_general_resp_t st_repgen;
};

extern void smp_engine_init(void);
extern void smp_engine_fini(void);

extern int smp_plugin_load(smp_target_t *);
extern void smp_plugin_unload(smp_target_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SMP_IMPL_H */
