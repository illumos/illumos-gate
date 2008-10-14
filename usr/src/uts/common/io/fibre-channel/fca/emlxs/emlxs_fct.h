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
 * Copyright 2008 Emulex.  All rights reserved.
 * Use is subject to License terms.
 */


#ifndef _EMLXS_FCT_H
#define	_EMLXS_FCT_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef SFCT_SUPPORT

#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/stat.h>
#include <sys/pci.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>


#ifdef	NS_RSNN_NN
#undef	NS_RSNN_NN
#endif	/* NS_RSNN_NN */

#include <stmf_defines.h>

#ifdef FC_WELL_KNOWN_ADDR
#undef FC_WELL_KNOWN_ADDR
#endif	/* FC_WELL_KNOWN_ADDR */

#include <fct_defines.h>
#include <stmf.h>
#include <portif.h>
#include <fct.h>

#ifndef LINK_SPEED_8G
#define	LINK_SPEED_8G	5
#endif	/* LINK_SPEED_8G */

#ifndef LINK_SPEED_10G
#define	LINK_SPEED_10G	6
#endif	/* LINK_SPEED_10G */

#ifndef MODSYM_SUPPORT
#pragma weak fct_alloc
#pragma weak fct_free
#pragma weak fct_scsi_task_alloc
#pragma weak fct_register_local_port
#pragma weak fct_deregister_local_port
#pragma weak fct_handle_event
#pragma weak fct_post_rcvd_cmd
#pragma weak fct_ctl
#pragma weak fct_send_response_done
#pragma weak fct_send_cmd_done
#pragma weak fct_scsi_data_xfer_done
#pragma weak fct_handle_rcvd_flogi
#pragma weak fct_port_shutdown
#pragma weak fct_port_initialize
#pragma weak stmf_deregister_port_provider
#pragma weak stmf_free
#pragma weak stmf_alloc
#pragma weak stmf_register_port_provider
extern void *stmf_alloc();
extern void *fct_alloc();
#endif	/* MODSYM_SUPPORT */

struct emlxs_fct_dmem_bucket;
typedef struct emlxs_fct_dmem_bctl {
	struct emlxs_fct_dmem_bucket *bctl_bucket;
	struct emlxs_fct_dmem_bctl *bctl_next;
	uint64_t bctl_dev_addr;
	stmf_data_buf_t *bctl_buf;

} emlxs_fct_dmem_bctl_t;

typedef struct emlxs_fct_dmem_bucket {
	uint32_t dmem_buf_size;
	uint32_t dmem_nbufs;
	uint32_t dmem_nbufs_free;
	uint8_t *dmem_host_addr;
	uint64_t dmem_dev_addr;
	ddi_dma_handle_t dmem_dma_handle;
	ddi_acc_handle_t dmem_acc_handle;
	emlxs_fct_dmem_bctl_t *dmem_bctl_free_list;
	void *dmem_bctls_mem;
	kmutex_t dmem_lock;

} emlxs_fct_dmem_bucket_t;


#endif	/* SFCT_SUPPORT */

#ifdef	__cplusplus
}
#endif

#endif	/* _EMLXS_FCT_H */
