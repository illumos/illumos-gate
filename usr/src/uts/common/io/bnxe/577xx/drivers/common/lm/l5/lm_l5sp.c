

#include "lm5710.h"
#include "command.h"
#include "everest_l5cm_constants.h"
#include "lm_l5if.h"

static lm_status_t lm_sc_post_init_request(
    IN  struct _lm_device_t *pdev,
    IN  lm_iscsi_state_t *iscsi,
    IN  lm_iscsi_slow_path_request_t *sp_req,
    OUT u8_t *command,
    OUT u64_t *data)
{
    DbgMessage(pdev, VERBOSEl5sp, "##lm__post_initiate_offload_request\n");
    DbgBreakIf(iscsi->hdr.status != STATE_STATUS_INIT_CONTEXT);

    *command = ISCSI_RAMROD_CMD_ID_INIT;
    *data = iscsi->ctx_phys.as_u64;

    return LM_STATUS_PENDING;
}



static lm_status_t lm_sc_post_update_request(
    IN  struct _lm_device_t *pdev,
    IN  lm_iscsi_state_t *iscsi,
    IN  lm_iscsi_slow_path_request_t *sp_req,
    OUT u8_t *command,
    OUT u64_t *data)
{
    struct protocol_common_spe     spe       = {0};

    DbgMessage(pdev, VERBOSEl5sp, "##lm__post_initiate_offload_request\n");
    DbgBreakIf(iscsi->hdr.status != STATE_STATUS_NORMAL);

    *command = ISCSI_RAMROD_CMD_ID_UPDATE_CONN;
    spe.data.phy_address.hi = iscsi->sp_req_data.phys_addr.as_u32.high;
    spe.data.phy_address.lo = iscsi->sp_req_data.phys_addr.as_u32.low;
    *data = *((u64_t*)(&(spe.data.phy_address)));

    return LM_STATUS_PENDING;
}



/* Desciption:
 *  post slow path request of given type for given iscsi state
 * Assumptions:
 *  - caller initialized request->type according to its specific request
 *  - caller allocated space for request->data, according to the specific request type
 *  - all previous slow path requests for given tcp state are already completed
 * Returns:
 *  PENDING, SUCCESS or any failure */
lm_status_t lm_sc_post_slow_path_request(
    IN  struct _lm_device_t *pdev,
    IN  lm_iscsi_state_t *iscsi,
    IN  lm_iscsi_slow_path_request_t *request)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    u64_t       data      = 0;
    u8_t        command   = 0;

    DbgBreakIf(!(pdev && iscsi && request));
    DbgMessage(pdev, VERBOSEl5sp, "### lm_sc_post_slow_path_request cid=%d, type=%d\n", iscsi->cid, request->type);

    switch (request->type)
    {
    /* NirV: called under lock, iscsi_state is being changed */
    case SP_REQUEST_SC_INIT:
        lm_status = lm_sc_post_init_request(pdev, iscsi, request, &command, &data);
        break;

    case SP_REQUEST_SC_UPDATE:
        lm_status = lm_sc_post_update_request(pdev, iscsi, request, &command, &data);
        break;

    default:
        lm_status = LM_STATUS_FAILURE;
        DbgBreakMsg("Illegal slow path request type!\n");
        break;
    }

    if (lm_status == LM_STATUS_PENDING)
    {
        DbgMessage(pdev, VERBOSEl5sp,
                   "calling lm_command_post, cid=%d, command=%d, con_type=%d, data=%lx\n",
                   iscsi->cid, command, ISCSI_CONNECTION_TYPE, data);
        lm_command_post(pdev, iscsi->cid, command, CMD_PRIORITY_NORMAL, ISCSI_CONNECTION_TYPE/*ulp*/, data);
    }

    request->status = lm_status;
    return lm_status;
}



/* Desciption:
 *  initiate a caller allocated lm iscsi state
 * Assumptions:
 *  - caller already zeroed given iscsi state
 * Returns:
 *  SUCCESS or any failure */
lm_status_t lm_sc_init_iscsi_state(
    struct _lm_device_t *pdev,
    lm_state_block_t *state_blk,
    lm_iscsi_state_t *iscsi)
{
    DbgMessage(pdev, VERBOSEl5sp, "###lm_sc_init_iscsi_state, ptr=%p\n", iscsi);
    DbgBreakIf(!(pdev && state_blk && iscsi));

    iscsi->hdr.state_blk     = state_blk;
    iscsi->hdr.state_id      = STATE_ID_UNKNOWN;
    iscsi->hdr.status        = STATE_STATUS_INIT;
    d_list_push_tail(&pdev->iscsi_info.run_time.iscsi_list, &iscsi->hdr.link);

    // NirV: sc: future statistics update

    /* the rest of the iscsi state's fields that require initialization value other than 0,
     * will be initialized later (when lm_sc_init_iscsi_context is called) */

    return LM_STATUS_SUCCESS;
}



/* Desciption:
 *  delete iscsi state from lm _except_ from actual freeing of memory.
 *  the task of freeing of memory is done in lm_sc_free_iscsi_state()
 * Assumptions:
 *  global toe lock is taken by the caller
 */
void lm_sc_del_iscsi_state(
    struct _lm_device_t *pdev,
    lm_iscsi_state_t *iscsi)
{
    u8_t notify_fw = 1;

    DbgMessage(pdev, VERBOSEl5sp, "###lm_sc_del_iscsi_state\n");
    DbgBreakIf(!(pdev && iscsi));
    DbgBreakIf(iscsi->hdr.status >= STATE_STATUS_OFFLOAD_PENDING &&
               iscsi->hdr.status < STATE_STATUS_UPLOAD_DONE);

    /* just a moment before we delete this connection, lets take it's info... */
    /*lm_tcp_collect_stats(pdev, tcp);*/

    d_list_remove_entry(
        &pdev->iscsi_info.run_time.iscsi_list,
        &iscsi->hdr.link);
    /*pdev->iscsi_info.stats.total_upld++;*/


  /* tcp->cid could have not been initialized if delete of state
     is a result of a failed initialization */
    DbgBreakIf(iscsi->hdr.status != STATE_STATUS_UPLOAD_DONE &&
               iscsi->hdr.status != STATE_STATUS_INIT_OFFLOAD_ERR);

    if (iscsi->hdr.status == STATE_STATUS_INIT_OFFLOAD_ERR) {
        notify_fw = 0;
    }

    lm_free_cid_resc(pdev, ISCSI_CONNECTION_TYPE, iscsi->cid, notify_fw);

    iscsi->hdr.state_blk     = NULL;
    iscsi->cid = 0;
    iscsi->ctx_virt = NULL;
    iscsi->ctx_phys.as_u64 = 0;
} /* lm_sc_del_iscsi_state */


/* clean up the lm_fcoe_state */
void
lm_fc_del_fcoe_state(
    struct _lm_device_t             *pdev,
    lm_fcoe_state_t                 *fcoe)
{
    DbgMessage(pdev, VERBOSEl5sp, "###lm_fc_del_fcoe_state\n");
    DbgBreakIf(!(pdev && fcoe));
    /*
    DbgBreakIf(fcoe->hdr.status >= STATE_STATUS_OFFLOAD_PENDING &&
               fcoe->hdr.status < STATE_STATUS_UPLOAD_DONE);
    */

    /* remove the lm_fcoe_state from the state list */
    d_list_remove_entry(&pdev->fcoe_info.run_time.fcoe_list, &fcoe->hdr.link);

  /* tcp->cid could have not been initialized if delete of state
     is a result of a failed initialization */

    /*
    DbgBreakIf(fcoe->hdr.status != STATE_STATUS_UPLOAD_DONE &&
               fcoe->hdr.status != STATE_STATUS_INIT_OFFLOAD_ERR);
    */
} /* lm_fc_del_fcoe_state */



lm_status_t
lm_fc_init_fcoe_state(
    struct _lm_device_t             *pdev,
    lm_state_block_t                *state_blk,
    lm_fcoe_state_t                 *fcoe)
{
    DbgMessage(pdev, VERBOSEl5sp, "###lm_fc_init_fcoe_state, ptr=%p\n", fcoe);
    DbgBreakIf(!(pdev && state_blk && fcoe));

    fcoe->hdr.state_blk     = state_blk;
    fcoe->hdr.state_id      = STATE_ID_UNKNOWN;
    fcoe->hdr.status        = STATE_STATUS_INIT;
    d_list_push_tail(&pdev->fcoe_info.run_time.fcoe_list, &fcoe->hdr.link);

    /* the rest of the fcoe state's fields that require initialization value other than 0,
     * will be initialized later (when lm_fc_init_fcoe_context is called) */

    return LM_STATUS_SUCCESS;
}



void lm_sc_init_sp_req_type(
    struct _lm_device_t          * pdev,
    lm_iscsi_state_t             * iscsi,
    lm_iscsi_slow_path_request_t * lm_req,
    void                         * req_input_data)
{
    void *update_kwqe_virt;
    struct protocol_common_spe spe = {0};

    switch(lm_req->type) {
    case SP_REQUEST_SC_INIT:
        break;
    case SP_REQUEST_SC_UPDATE:

        spe.data.phy_address.hi = iscsi->sp_req_data.phys_addr.as_u32.high;
        spe.data.phy_address.lo = iscsi->sp_req_data.phys_addr.as_u32.low;

        update_kwqe_virt = &iscsi->sp_req_data.virt_addr->update_ctx.kwqe;
        mm_memcpy(update_kwqe_virt, req_input_data, sizeof(struct iscsi_kwqe_conn_update));

        break;
    default:
        DbgBreakMsg("lm_sc_init_sp_req_type: Illegal slow path request type!\n");
    }
} /* lm_init_sp_req_type */
