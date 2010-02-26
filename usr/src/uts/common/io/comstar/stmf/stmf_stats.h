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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#ifndef _STMF_STATS_H
#define	_STMF_STATS_H

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct stmf_kstat_itl_info {
	kstat_named_t		i_rport_name;
	kstat_named_t		i_rport_alias;
	kstat_named_t		i_lport_name;
	kstat_named_t		i_lport_alias;
	kstat_named_t		i_protocol;
	kstat_named_t		i_lu_guid;
	kstat_named_t		i_lu_alias;
	kstat_named_t		i_lu_number;
	kstat_named_t		i_task_waitq_elapsed;
	kstat_named_t		i_task_read_elapsed;
	kstat_named_t		i_task_write_elapsed;
	kstat_named_t		i_lu_read_elapsed;
	kstat_named_t		i_lu_write_elapsed;
	kstat_named_t		i_lport_read_elapsed;
	kstat_named_t		i_lport_write_elapsed;
} stmf_kstat_itl_info_t;

typedef struct stmf_kstat_lu_info {
	kstat_named_t		i_lun_guid;
	kstat_named_t		i_lun_alias;
} stmf_kstat_lu_info_t;

typedef struct stmf_kstat_tgt_info {
	kstat_named_t		i_tgt_name;
	kstat_named_t		i_tgt_alias;
	kstat_named_t		i_protocol;
} stmf_kstat_tgt_info_t;

#ifdef	__cplusplus
}
#endif

#endif /* _STMF_STATS_H */
