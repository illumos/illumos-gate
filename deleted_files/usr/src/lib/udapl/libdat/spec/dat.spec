#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/udapl/libdat/spec/dat.spec

function	dat_ia_query
declaration	DAT_RETURN dat_ia_query(DAT_IA_HANDLE, DAT_EVD_HANDLE*, DAT_IA_ATTR_MASK, DAT_IA_ATTR*, DAT_PROVIDER_ATTR_MASK, DAT_PROVIDER_ATTR*)
include		<dat/udat.h>
version		SUNW_1.1
end

function	dat_registry_list_providers
declaration	DAT_RETURN dat_registry_list_providers(DAT_COUNT max_to_return, DAT_COUNT *entries_returned, DAT_PROVIDER_INFO *(dat_provider_list[]))
include		<dat/dat.h>
version		SUNW_1.1
end		

function	dat_ia_openv
declaration	DAT_RETURN dat_ia_openv(const DAT_NAME_PTR, DAT_COUNT, DAT_EVD_HANDLE *, DAT_IA_HANDLE *, DAT_UINT32, DAT_UINT32, DAT_BOOLEAN)
include		<dat/dat.h>
version		SUNW_1.1
end		

function	dat_ia_close
declaration	DAT_RETURN dat_ia_close(DAT_IA_HANDLE, DAT_CLOSE_FLAGS)
include		<dat/dat.h>
version		SUNW_1.1
end	

function	dat_registry_add_provider
declaration	DAT_RETURN dat_registry_add_provider(DAT_PROVIDER*, const DAT_PROVIDER_INFO*)
include		<dat/dat_registry.h>	
version		SUNW_1.1
end

function	dat_registry_remove_provider
declaration	DAT_RETURN dat_registry_remove_provider(DAT_PROVIDER*, const DAT_PROVIDER_INFO*)
include		<dat/dat_registry.h>	
version		SUNW_1.1
end

function	dat_strerror
declaration	DAT_RETURN dat_strerror(DAT_RETURN, const char **,const char **)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_set_consumer_context
declaration	DAT_RETURN dat_set_consumer_context(DAT_IA_HANDLE, DAT_CONTEXT)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_get_consumer_context
declaration	DAT_RETURN dat_get_consumer_context(DAT_IA_HANDLE, DAT_CONTEXT*)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_get_handle_type
declaration	DAT_RETURN dat_get_handle_type(DAT_IA_HANDLE, DAT_HANDLE_TYPE*)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_cr_query
declaration	DAT_RETURN dat_cr_query(DAT_CR_HANDLE, DAT_CR_PARAM_MASK, DAT_CR_PARAM*)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_cr_accept
declaration	DAT_RETURN dat_cr_accept(DAT_CR_HANDLE, DAT_EP_HANDLE, DAT_COUNT, const DAT_PVOID)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_cr_reject
declaration	DAT_RETURN dat_cr_reject(DAT_CR_HANDLE)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_cr_handoff
declaration	DAT_RETURN dat_cr_handoff(DAT_CR_HANDLE, DAT_CONN_QUAL)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_evd_create
declaration	DAT_RETURN dat_evd_create(DAT_IA_HANDLE, DAT_COUNT, DAT_CNO_HANDLE, DAT_EVD_FLAGS, DAT_EVD_HANDLE*)
include		<dat/udat.h>
version		SUNW_1.1
end

function	dat_evd_modify_cno
declaration	DAT_RETURN dat_evd_modify_cno(DAT_EVD_HANDLE, DAT_CNO_HANDLE)
include		<dat/udat.h>
version		SUNW_1.1
end

function	dat_evd_enable
declaration	DAT_RETURN dat_evd_enable(DAT_EVD_HANDLE)
include		<dat/udat.h>
version		SUNW_1.1
end

function	dat_evd_wait
declaration	DAT_RETURN dat_evd_wait(DAT_EVD_HANDLE, DAT_TIMEOUT, DAT_COUNT, DAT_EVENT*, DAT_COUNT*)
include		<dat/udat.h>
version		SUNW_1.1
end

function	dat_evd_disable
declaration	DAT_RETURN dat_evd_disable(DAT_EVD_HANDLE)
include		<dat/udat.h>
version		SUNW_1.1
end

function	dat_evd_set_unwaitable
declaration	DAT_RETURN dat_evd_set_unwaitable(DAT_EVD_HANDLE)
include		<dat/udat.h>
version		SUNW_1.1
end

function	dat_evd_clear_unwaitable
declaration	DAT_RETURN dat_evd_clear_unwaitable(DAT_EVD_HANDLE)
include		<dat/udat.h>
version		SUNW_1.1
end

function	dat_evd_query
declaration	DAT_RETURN dat_evd_query(DAT_EVD_HANDLE, DAT_EVD_PARAM_MASK, DAT_EVD_PARAM*)
include		<dat/udat.h>
version		SUNW_1.1
end

function	dat_evd_resize
declaration	DAT_RETURN dat_evd_resize(DAT_EVD_HANDLE, DAT_COUNT)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_evd_post_se
declaration	DAT_RETURN dat_evd_post_se(DAT_EVD_HANDLE, const DAT_EVENT*)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_evd_dequeue
declaration	DAT_RETURN dat_evd_dequeue(DAT_EVD_HANDLE, DAT_EVENT*)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_evd_free
declaration	DAT_RETURN dat_evd_free(DAT_EVD_HANDLE) 
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_ep_create
declaration	DAT_RETURN dat_ep_create(DAT_IA_HANDLE, DAT_PZ_HANDLE, DAT_EVD_HANDLE, DAT_EVD_HANDLE,DAT_EVD_HANDLE, const DAT_EP_ATTR*, DAT_EP_HANDLE*)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_ep_query
declaration	DAT_RETURN dat_ep_query(DAT_EP_HANDLE, DAT_EP_PARAM_MASK, DAT_EP_PARAM*)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_ep_modify
declaration	DAT_RETURN dat_ep_modify(DAT_EP_HANDLE, DAT_EP_PARAM_MASK, const DAT_EP_PARAM*)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_ep_connect
declaration	DAT_RETURN dat_ep_connect(DAT_EP_HANDLE, DAT_IA_ADDRESS_PTR, DAT_CONN_QUAL, DAT_TIMEOUT, DAT_COUNT, const DAT_PVOID, DAT_QOS, DAT_CONNECT_FLAGS)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_ep_dup_connect
declaration	DAT_RETURN dat_ep_dup_connect(DAT_EP_HANDLE, DAT_EP_HANDLE, DAT_TIMEOUT, DAT_COUNT, const DAT_PVOID, DAT_QOS)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_ep_disconnect
declaration	DAT_RETURN dat_ep_disconnect(DAT_EP_HANDLE, DAT_CLOSE_FLAGS)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_ep_post_send
declaration	DAT_RETURN dat_ep_post_send(DAT_EP_HANDLE, DAT_COUNT, DAT_LMR_TRIPLET*, DAT_DTO_COOKIE, DAT_COMPLETION_FLAGS)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_ep_post_recv
declaration	DAT_RETURN dat_ep_post_recv(DAT_EP_HANDLE, DAT_COUNT, DAT_LMR_TRIPLET*, DAT_DTO_COOKIE, DAT_COMPLETION_FLAGS)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_ep_post_rdma_read
declaration	DAT_RETURN dat_ep_post_rdma_read(DAT_EP_HANDLE, DAT_COUNT, DAT_LMR_TRIPLET*, DAT_DTO_COOKIE, const DAT_RMR_TRIPLET*, DAT_COMPLETION_FLAGS)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_ep_post_rdma_write
declaration	DAT_RETURN dat_ep_post_rdma_write(DAT_EP_HANDLE, DAT_COUNT, DAT_LMR_TRIPLET*, DAT_DTO_COOKIE, const DAT_RMR_TRIPLET*, DAT_COMPLETION_FLAGS)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_ep_get_status
declaration	DAT_RETURN dat_ep_get_status(DAT_EP_HANDLE, DAT_EP_STATE*, DAT_BOOLEAN*, DAT_BOOLEAN*)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_ep_free
declaration	DAT_RETURN dat_ep_free(DAT_EP_HANDLE)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_ep_reset
declaration	DAT_RETURN dat_ep_reset(DAT_EP_HANDLE)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_lmr_create
declaration	DAT_RETURN dat_lmr_create(DAT_IA_HANDLE, DAT_MEM_TYPE, DAT_REGION_DESCRIPTION, DAT_VLEN, DAT_PZ_HANDLE, DAT_MEM_PRIV_FLAGS, DAT_LMR_HANDLE*, DAT_LMR_CONTEXT*, DAT_RMR_CONTEXT*, DAT_VLEN*, DAT_VADDR*)
include		<dat/udat.h>
version		SUNW_1.1
end

function	dat_lmr_query
declaration	DAT_RETURN dat_lmr_query(DAT_LMR_HANDLE, DAT_LMR_PARAM_MASK, DAT_LMR_PARAM*)
include		<dat/udat.h>
version		SUNW_1.1
end

function	dat_lmr_free
declaration	DAT_RETURN dat_lmr_free(DAT_LMR_HANDLE)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_lmr_sync_rdma_read
declaration	DAT_RETURN dat_lmr_sync_rdma_read(DAT_IA_HANDLE, const DAT_LMR_TRIPLET*, DAT_VLEN)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_lmr_sync_rdma_write
declaration	DAT_RETURN dat_lmr_sync_rdma_write(DAT_IA_HANDLE, const DAT_LMR_TRIPLET*, DAT_VLEN)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_rmr_create
declaration	DAT_RETURN dat_rmr_create(DAT_PZ_HANDLE, DAT_RMR_HANDLE*)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_rmr_query
declaration	DAT_RETURN dat_rmr_query(DAT_RMR_HANDLE, DAT_RMR_PARAM_MASK, DAT_RMR_PARAM *)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_rmr_bind
declaration	DAT_RETURN dat_rmr_bind(DAT_RMR_HANDLE, const DAT_LMR_TRIPLET*, DAT_MEM_PRIV_FLAGS, DAT_EP_HANDLE, DAT_RMR_COOKIE, DAT_COMPLETION_FLAGS, DAT_RMR_CONTEXT*)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_rmr_free
declaration	DAT_RETURN dat_rmr_free(DAT_RMR_HANDLE)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_psp_create
declaration	DAT_RETURN dat_psp_create(DAT_IA_HANDLE, DAT_CONN_QUAL, DAT_EVD_HANDLE, DAT_PSP_FLAGS, DAT_PSP_HANDLE*)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_psp_create_any
declaration	DAT_RETURN dat_psp_create_any(DAT_IA_HANDLE, DAT_CONN_QUAL*, DAT_EVD_HANDLE, DAT_PSP_FLAGS, DAT_PSP_HANDLE*)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_psp_query
declaration	DAT_RETURN dat_psp_query(DAT_PSP_HANDLE, DAT_PSP_PARAM_MASK, DAT_PSP_PARAM*)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_psp_free
declaration	DAT_RETURN dat_psp_free(DAT_PSP_HANDLE)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_rsp_create
declaration	DAT_RETURN dat_rsp_create(DAT_IA_HANDLE, DAT_CONN_QUAL, DAT_EP_HANDLE, DAT_EVD_HANDLE, DAT_RSP_HANDLE*)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_rsp_query
declaration	DAT_RETURN dat_rsp_query(DAT_RSP_HANDLE, DAT_RSP_PARAM_MASK, DAT_RSP_PARAM*)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_rsp_free
declaration	DAT_RETURN dat_rsp_free(DAT_RSP_HANDLE)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_pz_create
declaration	DAT_RETURN dat_pz_create(DAT_IA_HANDLE, DAT_PZ_HANDLE*)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_pz_query
declaration	DAT_RETURN dat_pz_query(DAT_PZ_HANDLE, DAT_PZ_PARAM_MASK, DAT_PZ_PARAM*)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_pz_free
declaration	DAT_RETURN dat_pz_free(DAT_PZ_HANDLE)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_ep_create_with_srq
declaration	DAT_RETURN dat_ep_create_with_srq(DAT_IA_HANDLE, DAT_PZ_HANDLE, DAT_EVD_HANDLE, DAT_EVD_HANDLE, DAT_EVD_HANDLE, DAT_SRQ_HANDLE, DAT_EP_ATTR*, DAT_EP_HANDLE*)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_ep_recv_query
declaration	DAT_RETURN dat_ep_recv_query(DAT_EP_HANDLE, DAT_COUNT*, DAT_COUNT*)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_ep_set_watermark
declaration	DAT_RETURN dat_ep_set_watermark(DAT_EP_HANDLE, DAT_COUNT, DAT_COUNT)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_srq_create
declaration	DAT_RETURN dat_srq_create(DAT_IA_HANDLE, DAT_PZ_HANDLE, DAT_SRQ_ATTR*, DAT_SRQ_HANDLE*)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_srq_free
declaration	DAT_RETURN dat_srq_free(DAT_SRQ_HANDLE)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_srq_post_recv
declaration	DAT_RETURN dat_srq_post_recv(DAT_SRQ_HANDLE, DAT_COUNT, DAT_LMR_TRIPLET*, DAT_DTO_COOKIE)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_srq_query
declaration	DAT_RETURN dat_srq_query(DAT_SRQ_HANDLE, DAT_SRQ_PARAM_MASK, DAT_SRQ_PARAM*)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_srq_resize
declaration	DAT_RETURN dat_srq_resize(DAT_SRQ_HANDLE, DAT_COUNT)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_srq_set_lw
declaration	DAT_RETURN dat_srq_set_lw(DAT_SRQ_HANDLE, DAT_COUNT)
include		<dat/dat.h>
version		SUNW_1.1
end

function	dat_cno_create
declaration	DAT_RETURN dat_cno_create(DAT_IA_HANDLE, DAT_OS_WAIT_PROXY_AGENT, DAT_CNO_HANDLE*)
include		<dat/udat.h>
version		SUNW_1.1
end

function	dat_cno_modify_agent
declaration	DAT_RETURN dat_cno_modify_agent(DAT_CNO_HANDLE, DAT_OS_WAIT_PROXY_AGENT)
include		<dat/udat.h>
version		SUNW_1.1
end

function	dat_cno_query
declaration	DAT_RETURN dat_cno_query(DAT_CNO_HANDLE, DAT_CNO_PARAM_MASK, DAT_CNO_PARAM*)
include		<dat/udat.h>
version		SUNW_1.1
end

function	dat_cno_free
declaration	DAT_RETURN dat_cno_free(DAT_CNO_HANDLE)
include		<dat/udat.h>
version		SUNW_1.1
end

function	dat_cno_wait
declaration	DAT_RETURN dat_cno_wait(DAT_CNO_HANDLE, DAT_TIMEOUT, DAT_EVD_HANDLE*)
include		<dat/udat.h>
version		SUNW_1.1
end
