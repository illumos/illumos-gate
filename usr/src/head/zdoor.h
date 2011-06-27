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
 * Copyright 2011 Joyent, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _ZDOOR_H
#define	_ZDOOR_H

#include <sys/types.h>
#include <zone.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct zdoor_handle *zdoor_handle_t;

typedef struct zdoor_cookie {
	char *zdc_zonename;
	char *zdc_service;
	void *zdc_biscuit;
} zdoor_cookie_t;

typedef struct zdoor_result {
	char *zdr_data;
	size_t zdr_size;
} zdoor_result_t;

typedef zdoor_result_t *(*zdoor_callback) (zdoor_cookie_t *cookie,
	char *argp, size_t arpg_sz);

#define	ZDOOR_OK		0
#define	ZDOOR_ERROR		-1
#define	ZDOOR_NOT_GLOBAL_ZONE	-2
#define	ZDOOR_ZONE_NOT_RUNNING	-3
#define	ZDOOR_ZONE_FORBIDDEN	-4
#define	ZDOOR_ARGS_ERROR	-5
#define	ZDOOR_OUT_OF_MEMORY	-6

extern zdoor_handle_t	zdoor_handle_init();

extern int	zdoor_open(zdoor_handle_t handle, const char *zonename,
	const char *service, void *biscuit, zdoor_callback callback);

extern void *	zdoor_close(zdoor_handle_t handle, const char *zonename,
	const char *service);

extern void 	zdoor_handle_destroy(zdoor_handle_t handle);

#ifdef __cplusplus
}
#endif

#endif	/* _ZDOOR_H */
