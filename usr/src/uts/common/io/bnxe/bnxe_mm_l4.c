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
 * Copyright 2014 QLogic Corporation
 * The contents of this file are subject to the terms of the
 * QLogic End User License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the License at
 * http://www.qlogic.com/Resources/Documents/DriverDownloadHelp/
 * QLogic_End_User_Software_License.txt
 * See the License for the specific language governing permissions
 * and limitations under the License.
 */

#include "bnxe.h"

void
mm_acquire_tcp_lock(
    lm_device_t *pdev,
    lm_tcp_con_t *tcp_con)
{
    BnxeDbgBreak((um_device_t *)pdev);
}


void
mm_release_tcp_lock(
    lm_device_t *pdev,
    lm_tcp_con_t *tcp_con)
{
    BnxeDbgBreak((um_device_t *)pdev);
}


void MM_ACQUIRE_TOE_LOCK(lm_device_t *pDev)
{
    BNXE_LOCK_ENTER_TOE((um_device_t *)pDev);
}


void MM_RELEASE_TOE_LOCK(lm_device_t *pDev)
{
    BNXE_LOCK_EXIT_TOE((um_device_t *)pDev);
}


void MM_ACQUIRE_TOE_GRQ_LOCK_DPC(lm_device_t *pdev, u8_t idx)
{
    BnxeDbgBreak((um_device_t *)pdev);
}


void MM_RELEASE_TOE_GRQ_LOCK_DPC(lm_device_t *pdev, u8_t idx)
{
    BnxeDbgBreak((um_device_t *)pdev);
}


void MM_ACQUIRE_TOE_GRQ_LOCK(lm_device_t *pdev, u8_t idx)
{
    BnxeDbgBreak((um_device_t *)pdev);
}


void MM_RELEASE_TOE_GRQ_LOCK(lm_device_t *pdev, u8_t idx)
{
    BnxeDbgBreak((um_device_t *)pdev);
}


void mm_tcp_complete_path_upload_request(
    struct _lm_device_t * pdev,
    lm_path_state_t     * path
    )
{
    BnxeDbgBreak((um_device_t *)pdev);
}


void mm_tcp_complete_neigh_upload_request(
    struct _lm_device_t * pdev,
    lm_neigh_state_t    * neigh
    )
{
    BnxeDbgBreak((um_device_t *)pdev);
}


void mm_tcp_comp_slow_path_request(
    struct _lm_device_t *pdev,
    lm_tcp_state_t *tcp,
    lm_tcp_slow_path_request_t *sp_request)
{
    BnxeDbgBreak((um_device_t *)pdev);
}


void mm_tcp_complete_bufs(
    struct _lm_device_t *pdev,
    lm_tcp_state_t      *tcp,
    lm_tcp_con_t        *tcp_con,   /* Rx OR Tx connection */
    s_list_t            *buf_list,  /* list of lm_tcp_buffer_t */
    lm_status_t         lm_status   /* completion status for all given TBs */)
{
    BnxeDbgBreak((um_device_t *)pdev);
}


u8_t mm_tcp_indicating_bufs(
    lm_tcp_con_t * con        /* connection to be checked */
    )
{
    BnxeDbgBreak(NULL);
    return 0;
}


void mm_tcp_abort_bufs (
    IN    struct _lm_device_t     * pdev,  /* device handle */
    IN    lm_tcp_state_t          * tcp,   /* L4 state handle */
    IN    lm_tcp_con_t            * con,   /* connection handle */
    IN    lm_status_t               status /* status to abort buffers with */
    )
{
    BnxeDbgBreak((um_device_t *)pdev);
}


void mm_tcp_indicate_rst_received(
    IN   lm_device_t     * pdev,
    IN   lm_tcp_state_t  * tcp
    )
{
    BnxeDbgBreak((um_device_t *)pdev);
}


void mm_tcp_indicate_fin_received(
    IN   struct _lm_device_t     * pdev,   /* device handle */
    IN   lm_tcp_state_t          * tcp     /* L4 state handle */
    )
{
    BnxeDbgBreak((um_device_t *)pdev);
}


void mm_tcp_graceful_disconnect_done(
    IN   struct _lm_device_t     * pdev,    /* device handle */
    IN   lm_tcp_state_t          * tcp,     /* L4 state handle */
    IN   lm_status_t               status   /* May be SUCCESS, ABORTED or UPLOAD IN PROGRESS */
    )
{
    BnxeDbgBreak((um_device_t *)pdev);
}


u32_t mm_tcp_rx_indicate_gen_buf (
    struct _lm_device_t * pdev,
    lm_tcp_state_t      * tcp,
    lm_frag_list_t      * frag_list,
    void                * return_buffer_ctx
    )
{
    BnxeDbgBreak((um_device_t *)pdev);
    return 0;
}


void mm_tcp_rx_indicate_gen (
    struct _lm_device_t * pdev,
    lm_tcp_state_t      * tcp
    )
{
    BnxeDbgBreak((um_device_t *)pdev);
}


static void _schedule_work_item_for_alloc_gen_bufs(um_device_t * pdev)
{
    BnxeDbgBreak((um_device_t *)pdev);
}


static void _schedule_work_item_for_free_gen_bufs(
    um_device_t * pdev,
    lm_tcp_gen_buf_t * gen_buf
    )
{
    BnxeDbgBreak((um_device_t *)pdev);
}


u32_t mm_tcp_get_gen_bufs(
    struct _lm_device_t * pdev,
    d_list_t            * gb_list,
    u32_t                 nbufs,
    u8_t                  sb_idx
    )
{
    BnxeDbgBreak((um_device_t *)pdev);
    return 0;
}


void mm_tcp_return_gen_bufs(
    lm_device_t      * pdev,
    lm_tcp_gen_buf_t * gen_buf,
    u32_t              flags,
    u8_t               grq_idxxx
    )
{
    BnxeDbgBreak((um_device_t *)pdev);
}


void mm_tcp_return_list_of_gen_bufs(
    struct _lm_device_t * pdev,
    d_list_t            * returned_list_of_gen_bufs,
    u32_t                 flags,
    u8_t                  grq_idxxx
    )
{
    BnxeDbgBreak((um_device_t *)pdev);
}


u32_t mm_tcp_copy_to_tcp_buf(
    lm_device_t     * pdev,
    lm_tcp_state_t  * tcp_state,
    lm_tcp_buffer_t * tcp_buf,         /* TCP buffer to copy to      */
    u8_t            * mem_buf,         /* Memory buffer to copy from */
    u32_t             tcp_buf_offset,
    u32_t             nbytes
    )
{
    BnxeDbgBreak((um_device_t *)pdev);
    return 0;
}


void
mm_tcp_indicate_retrieve_indication(
    lm_device_t *pdev,
    lm_tcp_state_t *tcp_state,
    l4_upload_reason_t upload_reason)
{
    BnxeDbgBreak((um_device_t *)pdev);
}


void mm_tcp_update_required_gen_bufs(
    struct _lm_device_t * pdev,
    u32_t  new_mss,
    u32_t  old_mss,
    u32_t  new_initial_rcv_wnd,
    u32_t  old_initial_rcv_wnd)
{
    BnxeDbgBreak((um_device_t *)pdev);
}


lm_status_t mm_tcp_post_empty_slow_path_request(
    struct _lm_device_t * pdev,
    lm_tcp_state_t      * tcp,
    u32_t                 request_type)
{
    BnxeDbgBreak((um_device_t *)pdev);
    return 0;
}


void mm_tcp_del_tcp_state(
    struct _lm_device_t * pdev,
    lm_tcp_state_t * tcp)
{
    BnxeDbgBreak((um_device_t *)pdev);
}


u32_t mm_tcp_rx_peninsula_to_rq_copy_dmae(
    struct _lm_device_t * pdev,
    lm_tcp_state_t      * tcp,
    lm_address_t          gen_buf_phys,
    u32_t                 gen_buf_offset,
    lm_tcp_buffer_t     * tcp_buf,
    u32_t                 tcp_buf_offset,
    u32_t                 nbytes
    )
{
    BnxeDbgBreak((um_device_t *)pdev);
    return 0;
}

