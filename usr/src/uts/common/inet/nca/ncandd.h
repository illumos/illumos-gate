/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_NCANDD_H
#define	_SYS_NCANDD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* Named Dispatch Parameter Management Structure */
typedef struct ncaparam_s {
	ulong_t	param_min;
	ulong_t	param_max;
	ulong_t	param_val;
	char	*param_name;
} ncaparam_t;

extern ncaparam_t nca_param_arr[];

#define	nca_log_cycle			(uint32_t)nca_param_arr[0].param_val
#define	no_caching			(uint32_t)nca_param_arr[1].param_val
#define	nca_log_size			(uint64_t)nca_param_arr[2].param_val
#define	nca_max_cache_size		(uint32_t)nca_param_arr[3].param_val
#define	nca_http_timeout		(uint32_t)nca_param_arr[4].param_val
#define	nca_http_keep_alive_timeout	(uint32_t)nca_param_arr[5].param_val
#define	nca_http_keep_alive_max		(uint32_t)nca_param_arr[6].param_val
#define	nca_inq_nointr			(uint32_t)nca_param_arr[7].param_val
#define	nca_use_hwcksum			(uint32_t)nca_param_arr[8].param_val
#define	nca_segmap_min_size		(uint32_t)nca_param_arr[9].param_val

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_NCANDD_H */
