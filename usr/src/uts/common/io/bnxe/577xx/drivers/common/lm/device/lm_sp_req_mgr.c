
#include "lm5710.h"
#include "lm_sp_req_mgr.h"
#include "context.h"



lm_status_t
lm_sp_req_manager_init(
    struct _lm_device_t *pdev, 
    u32_t cid
    )
{
    lm_sp_req_manager_t *sp_req_mgr = NULL;

    if CHK_NULL(pdev)
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    sp_req_mgr = lm_cid_sp_req_mgr(pdev, cid);
    if CHK_NULL(sp_req_mgr)
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    s_list_clear(&sp_req_mgr->pending_reqs);
    sp_req_mgr->blocked = FALSE;
    sp_req_mgr->req_seq_number = 1;
    sp_req_mgr->sp_data_virt_addr = NULL;
    sp_req_mgr->sp_data_phys_addr.as_u64 = 0;

    return LM_STATUS_SUCCESS;
}



lm_status_t
lm_sp_req_manager_shutdown(
    struct _lm_device_t *pdev, 
    u32_t cid
    )
{
    lm_sp_req_manager_t *sp_req_mgr = NULL;

    if CHK_NULL(pdev)
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    sp_req_mgr = lm_cid_sp_req_mgr(pdev, cid);
    if CHK_NULL(sp_req_mgr)
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    if (ERR_IF(!s_list_is_empty(&sp_req_mgr->pending_reqs)))
    {
        DbgBreakIf( !s_list_is_empty(&sp_req_mgr->pending_reqs) );
        return LM_STATUS_INVALID_PARAMETER;
    }
    
    sp_req_mgr->blocked = TRUE;
    sp_req_mgr->sp_data_virt_addr = NULL;
    sp_req_mgr->sp_data_phys_addr.as_u64 = 0;

    return LM_STATUS_SUCCESS;
}



lm_status_t
lm_sp_req_manager_post(
    struct _lm_device_t *pdev, 
    u32_t cid,
    struct _lm_sp_req_common_t *sp_req
    )
{
    lm_sp_req_manager_t *sp_req_mgr = NULL;
    lm_status_t          lm_status  = LM_STATUS_FAILURE;

    if (CHK_NULL(pdev) || CHK_NULL(sp_req))
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    sp_req_mgr = lm_cid_sp_req_mgr(pdev, cid);
    if CHK_NULL(sp_req_mgr)
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

//    DbgMessage(pdev, FATAL/*INFORM*/, "###lm_sp_req_manager_post, before lock cid=%d\n", cid);
	MM_ACQUIRE_SP_REQ_MGR_LOCK(pdev);
//    DbgMessage(pdev, FATAL/*INFORM*/, "###lm_sp_req_manager_post, inside lock cid=%d\n", cid);

	if (sp_req_mgr->blocked)
    {
//        DbgMessage(pdev, FATAL/*INFORM*/, "###lm_sp_req_manager_post, adding to list cid=%d\n", cid);

		s_list_push_tail(&sp_req_mgr->pending_reqs, &sp_req->link);
		sp_req = NULL;
        lm_status = LM_STATUS_PENDING;
	}
    else
    {
//        DbgMessage(pdev, FATAL/*INFORM*/, "###lm_sp_req_manager_post, calling req_post_function, cid=%d\n", cid);

        sp_req->req_seq_number = ++sp_req_mgr->req_seq_number;
        sp_req_mgr->posted_req = sp_req;
        sp_req_mgr->blocked = TRUE;
	}
	MM_RELEASE_SP_REQ_MGR_LOCK(pdev);

	if (sp_req != NULL)
    {
        lm_status = ((req_post_function)sp_req->req_post_func)(pdev, sp_req->req_post_ctx, sp_req);
//        DbgMessage(pdev, FATAL/*INFORM*/, "###lm_sp_req_manager_post, req_post_function, cid=%d, lm_status=%d\n", cid, lm_status);
    }

    return lm_status;
}



lm_status_t
lm_sp_req_manager_complete(
    struct _lm_device_t *pdev, 
    u32_t cid,
    u32_t seq_num,
    lm_sp_req_common_t **sp_req
    )
{
    lm_sp_req_manager_t *sp_req_mgr = NULL;
    lm_status_t         lm_status   = LM_STATUS_SUCCESS;

    if (CHK_NULL(pdev) || CHK_NULL(sp_req))
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    *sp_req = NULL;

    sp_req_mgr = lm_cid_sp_req_mgr(pdev, cid);
    if CHK_NULL(sp_req_mgr)
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    MM_ACQUIRE_SP_REQ_MGR_LOCK(pdev);

    /* in iscsi we use sp_req_mgr.posted_req to store last req, */
    /* so instead of getting the seq num as param, we'll find it ourselves */
    if (seq_num == 0)
    {
        if CHK_NULL(sp_req_mgr->posted_req)
        {
            MM_RELEASE_SP_REQ_MGR_LOCK(pdev);
            return LM_STATUS_INVALID_PARAMETER;
        }

        seq_num = sp_req_mgr->posted_req->req_seq_number;
    }

    if ( ERR_IF( seq_num != sp_req_mgr->req_seq_number ) ||
         ERR_IF( sp_req_mgr->blocked == FALSE ) )
    {
//        DbgMessage(pdev, FATAL/*INFORM*/, "###lm_sp_req_manager_complete, cid=%d, seq_num=%d, sp_req_mgr->req_seq_number=%d\n", cid, seq_num, sp_req_mgr->req_seq_number);
        DbgBreakIf( seq_num != sp_req_mgr->req_seq_number );
        DbgBreakIf( (sp_req_mgr->blocked == FALSE) && (sp_req_mgr->posted_req != NULL) );
        MM_RELEASE_SP_REQ_MGR_LOCK(pdev);
        return LM_STATUS_INVALID_PARAMETER;
    }

	if (!s_list_is_empty(&sp_req_mgr->pending_reqs))
    {
//        DbgMessage(pdev, FATAL/*INFORM*/, "###lm_sp_req_manager_complete, popping from list cid=%d\n", cid);

        *sp_req = (lm_sp_req_common_t *)s_list_pop_head(&sp_req_mgr->pending_reqs);

        if (CHK_NULL(*sp_req))
        {
            MM_RELEASE_SP_REQ_MGR_LOCK(pdev);
    		return LM_STATUS_INVALID_PARAMETER;
        }

		(*sp_req)->req_seq_number = ++sp_req_mgr->req_seq_number;
        sp_req_mgr->posted_req = (*sp_req);
    }
    else
    {
//        DbgMessage(pdev, FATAL/*INFORM*/, "###lm_sp_req_manager_complete, no pending reqs, cid=%d\n", cid);

        sp_req_mgr->blocked = FALSE;
        sp_req_mgr->posted_req = NULL;
    }

    MM_RELEASE_SP_REQ_MGR_LOCK(pdev);

	if ((*sp_req) != NULL)
    {
        lm_status = ((req_post_function)(*sp_req)->req_post_func)(pdev, (*sp_req)->req_post_ctx, *sp_req);
//        DbgMessage(pdev, FATAL/*INFORM*/, "###lm_sp_req_manager_complete, req_post_function, cid=%d, lm_status=%d\n", cid, lm_status);
    }

    return lm_status;
}



lm_status_t
lm_sp_req_manager_block(
    struct _lm_device_t *pdev, 
    u32_t cid
    )
{
    lm_sp_req_manager_t *sp_req_mgr = NULL;

    if CHK_NULL(pdev)
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    sp_req_mgr = lm_cid_sp_req_mgr(pdev, cid);
    if CHK_NULL(sp_req_mgr)
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    MM_ACQUIRE_SP_REQ_MGR_LOCK(pdev);

//    DbgMessage(pdev, FATAL/*INFORM*/, "###lm_sp_req_manager_block, blocking sq req mgr, cid=%d\n", cid);
	sp_req_mgr->blocked = TRUE;

    MM_RELEASE_SP_REQ_MGR_LOCK(pdev);

    return LM_STATUS_SUCCESS;
}



/* same as complete, execpt for seq number and asserts */
lm_status_t
lm_sp_req_manager_unblock(
    struct _lm_device_t *pdev, 
    u32_t cid,
    lm_sp_req_common_t **sp_req
    )
{
    lm_sp_req_manager_t *sp_req_mgr = NULL;
    lm_status_t          lm_status  = LM_STATUS_SUCCESS;

    if (CHK_NULL(pdev) || CHK_NULL(sp_req))
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    *sp_req = NULL;

    sp_req_mgr = lm_cid_sp_req_mgr(pdev, cid);
    if CHK_NULL(sp_req_mgr)
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    MM_ACQUIRE_SP_REQ_MGR_LOCK(pdev);

    if (!s_list_is_empty(&sp_req_mgr->pending_reqs))
    {
//        DbgMessage(pdev, FATAL/*INFORM*/, "###lm_sp_req_manager_unblock, popping from list cid=%d\n", cid);

        *sp_req = (lm_sp_req_common_t *)s_list_pop_head(&sp_req_mgr->pending_reqs);

        if (CHK_NULL(*sp_req))
        {
            MM_RELEASE_SP_REQ_MGR_LOCK(pdev);
            return LM_STATUS_INVALID_PARAMETER;
        }

        (*sp_req)->req_seq_number = ++sp_req_mgr->req_seq_number;
        sp_req_mgr->posted_req = (*sp_req);
    }
    else
    {
//        DbgMessage(pdev, FATAL/*INFORM*/, "###lm_sp_req_manager_unblock, no pending reqs, cid=%d\n", cid);

        sp_req_mgr->blocked = FALSE;
        sp_req_mgr->posted_req = NULL;
    }

    MM_RELEASE_SP_REQ_MGR_LOCK(pdev);

	if ((*sp_req) != NULL)
    {
		lm_status = ((req_post_function)(*sp_req)->req_post_func)(pdev, (*sp_req)->req_post_ctx, *sp_req);
//        DbgMessage(pdev, FATAL/*INFORM*/, "###lm_sp_req_manager_unblock, req_post_function, cid=%d, lm_status=%d\n", cid, lm_status);
    }

    return lm_status;
}



lm_status_t
lm_sp_req_manager_set_sp_data(
    struct _lm_device_t *pdev,
    u32_t cid,
    void *virt_addr,
    lm_address_t phys_addr
    )
{
    lm_sp_req_manager_t *sp_req_mgr = NULL;
    
    if CHK_NULL(pdev)
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    sp_req_mgr = lm_cid_sp_req_mgr(pdev, cid);
    if CHK_NULL(sp_req_mgr)
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    MM_ACQUIRE_SP_REQ_MGR_LOCK(pdev);

    sp_req_mgr->sp_data_virt_addr = virt_addr;
    sp_req_mgr->sp_data_phys_addr = phys_addr;

    MM_RELEASE_SP_REQ_MGR_LOCK(pdev);

    return LM_STATUS_SUCCESS;
}

