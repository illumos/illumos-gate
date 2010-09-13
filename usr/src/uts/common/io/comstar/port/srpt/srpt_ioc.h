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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _SRPT_IOC_H
#define	_SRPT_IOC_H

/*
 * Prototypes and data structures specific to I/O Controller
 * operation.
 */

#ifdef	__cplusplus
extern "C" {
#endif
#include "srpt_impl.h"

int srpt_ioc_attach();
void srpt_ioc_attach_hca(ib_guid_t hca_guid, boolean_t checked);
void srpt_ioc_detach();
void srpt_ioc_detach_hca(ib_guid_t hca_guid);
void srpt_ioc_update(void);
void srpt_ioc_init_profile(srpt_ioc_t *ioc);
ibt_status_t srpt_ioc_svc_bind(srpt_target_port_t *tgt, uint_t portnum);
void srpt_ioc_svc_unbind(srpt_target_port_t *tgt, uint_t portnum);
void srpt_ioc_svc_unbind_all(srpt_target_port_t *tgt);

srpt_ioc_t *srpt_ioc_get_locked(ib_guid_t guid);
srpt_ioc_t *srpt_ioc_get(ib_guid_t guid);

ibt_status_t srpt_ioc_post_recv_iu(srpt_ioc_t *ioc, srpt_iu_t *iu);
void srpt_ioc_repost_recv_iu(srpt_ioc_t *ioc, srpt_iu_t *iu);

stmf_data_buf_t *srpt_ioc_ds_alloc_dbuf(struct scsi_task *task,
	uint32_t size, uint32_t *pminsize, uint32_t flags);
void srpt_ioc_ds_free_dbuf(struct stmf_dbuf_store *ds,
	stmf_data_buf_t *dbuf);

#ifdef	__cplusplus
}
#endif

#endif /* _SRPT_IOC_H */
