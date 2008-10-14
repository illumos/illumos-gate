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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SD_SAFESTORE_RAM_H
#define	_SD_SAFESTORE_RAM_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _KERNEL

typedef struct ss_ram_config_s {
	uint_t ss_configured;		/* configured bit */
	ss_voldata_impl_t *sn_volumes; /* volume directory */
	struct ss_wr_cctl	*sn_wr_cctl; /* the write control blocks   */
	ss_centry_info_impl_t *sn_gl_centry_info; /* dirty bits */
	struct  _sd_wr_queue	sn_wr_queue; /* the write queue */
} ss_ram_config_t;

/* internal volume directory stream struct must be same size as ss_vdir_t */
typedef struct ss_ram_vdir_s {
	intptr_t rv_type;	/* stream type */
	union {
		struct {
			ss_voldata_impl_t *rv_current;
			ss_voldata_impl_t *rv_end;
		} rv_all;

		struct {
			intptr_t v[5];
		} rv_vol;

		struct {
			intptr_t n[5];
		} rv_node;
	} rv_u;
} ss_ram_vdir_t;

/* internal centry stream struct must be same size as ss_cdir_t */
typedef struct ss_ram_cdir_t_s {
	intptr_t rc_type;	/* stream type */
	union {
		struct {
			ss_wr_cctl_t *rc_current;
			ss_wr_cctl_t *rc_end;
		} rc_all;

		struct {
			intptr_t v[5];
		} rc_vol;

		struct {
			intptr_t n[5];
		} rc_node;
	} rc_u;
}ss_ram_cdir_t;

typedef ss_wr_cctl_t *ss_ram_resource_t;
typedef ss_wr_cctl_t *ss_ram_resourcelist_t;

#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif	/* _SD_SAFESTORE_RAM_H */
