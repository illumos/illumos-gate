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
 * Copyright (c) 2002-2004, Network Appliance, Inc. All rights reserved.
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#ifndef _UDAT_H_
#define	_UDAT_H_

/*
 *
 * HEADER: udat.h
 *
 * PURPOSE: defines the user DAT API
 *
 * Description: Header file for "uDAPL: User Direct Access Programming
 *              Library, Version: 1.2"
 *
 * Mapping rules:
 *      All global symbols are prepended with "DAT_" or "dat_"
 *      All DAT objects have an 'api' tag which, such as 'ep' or 'lmr'
 *      The method table is in the provider definition structure.
 *
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <dat/udat_config.h>

#include <dat/dat_platform_specific.h>

typedef enum dat_mem_type
{
	/* Shared between udat and kdat */
	DAT_MEM_TYPE_VIRTUAL		= 0x00,
	DAT_MEM_TYPE_LMR		= 0x01,
	/* udat specific */
	DAT_MEM_TYPE_SHARED_VIRTUAL	= 0x02,
	DAT_MEM_TYPE_SO_VIRTUAL		= 0x03
} DAT_MEM_TYPE;

/* dat handle types */
typedef enum dat_handle_type
{
	DAT_HANDLE_TYPE_CR,
	DAT_HANDLE_TYPE_EP,
	DAT_HANDLE_TYPE_EVD,
	DAT_HANDLE_TYPE_IA,
	DAT_HANDLE_TYPE_LMR,
	DAT_HANDLE_TYPE_PSP,
	DAT_HANDLE_TYPE_PZ,
	DAT_HANDLE_TYPE_RMR,
	DAT_HANDLE_TYPE_RSP,
	DAT_HANDLE_TYPE_CNO,
	DAT_HANDLE_TYPE_SRQ
} DAT_HANDLE_TYPE;

/*
 * EVD state consists of 3 orthogonal substates. One for
 * enabled/disabled, one for waitable/unwaitable, and one
 * for configuration. Within each substates the values are
 * mutually exclusive.
 */
typedef enum dat_evd_state
{
	DAT_EVD_STATE_ENABLED 		= 0x01,
	DAT_EVD_STATE_DISABLED 		= 0x02,
	DAT_EVD_STATE_WAITABLE 		= 0x04,
	DAT_EVD_STATE_UNWAITABLE 	= 0x08,
	DAT_EVD_STATE_CONFIG_NOTIFY 	= 0x10,
	DAT_EVD_STATE_CONFIG_SOLICITED 	= 0x20,
	DAT_EVD_STATE_CONFIG_THRESHOLD 	= 0x30
} DAT_EVD_STATE;

typedef enum dat_evd_param_mask
{
	DAT_EVD_FIELD_IA_HANDLE    	= 0x01,
	DAT_EVD_FIELD_EVD_QLEN		= 0x02,
	DAT_EVD_FIELD_EVD_STATE    	= 0x04,
	DAT_EVD_FIELD_CNO		= 0x08,
	DAT_EVD_FIELD_EVD_FLAGS		= 0x10,

	DAT_EVD_FIELD_ALL		= 0x1F
} DAT_EVD_PARAM_MASK;

typedef DAT_UINT64 DAT_PROVIDER_ATTR_MASK;

#include <dat/dat.h>

typedef DAT_HANDLE	DAT_CNO_HANDLE;

struct dat_evd_param
{
	DAT_IA_HANDLE		ia_handle;
	DAT_COUNT		evd_qlen;
	DAT_EVD_STATE		evd_state;
	DAT_CNO_HANDLE		cno_handle;
	DAT_EVD_FLAGS		evd_flags;
};

#define	DAT_LMR_COOKIE_SIZE 40 /* size of DAT_LMR_COOKIE in bytes */
typedef char (* DAT_LMR_COOKIE)[DAT_LMR_COOKIE_SIZE];

/* Format for OS wait proxy agent function */

typedef void (*DAT_AGENT_FUNC)(
	DAT_PVOID,	/* instance data   */
	DAT_EVD_HANDLE  /* Event Dispatcher*/);

/* Definition */

typedef struct dat_os_wait_proxy_agent
{
	DAT_PVOID instance_data;
	DAT_AGENT_FUNC proxy_agent_func;
} DAT_OS_WAIT_PROXY_AGENT;

/* Define NULL Proxy agent */

#define	DAT_OS_WAIT_PROXY_AGENT_NULL \
	(DAT_OS_WAIT_PROXY_AGENT) { \
	(DAT_PVOID) NULL, \
	(DAT_AGENT_FUNC) NULL }


/* Flags */

/*
 * The value specified by the uDAPL Consumer for dat_ia_open to indicate
 * that not async EVD should be created for the opening instance of an IA.
 * The same IA have been open before that has the only async EVD to
 * handle async errors for all open instances of the IA.
 */

#define	DAT_EVD_ASYNC_EXISTS (DAT_EVD_HANDLE) 0x1

/*
 * The value return by the dat_ia_query for the case when there is no
 * async EVD for the IA instance. Consumer had specified the value of
 * DAT_EVD_ASYNC_EXISTS for the async_evd_handle for dat_ia_open.
 */

#define	DAT_EVD_OUT_OF_SCOPE (DAT_EVD_HANDLE) 0x2

/*
 * Memory types
 *
 * Specifing memory type for LMR create. A consumer must use a single
 * value when registering memory. The union of any of these
 * flags is used in the provider parameters to indicate what memory
 * type provider supports for LMR memory creation.
 */



/* For udapl only */

typedef struct dat_shared_memory
{
	DAT_PVOID		virtual_address;
	DAT_LMR_COOKIE		shared_memory_id;
} DAT_SHARED_MEMORY;

typedef union dat_region_description
{
	DAT_PVOID		for_va;
	DAT_LMR_HANDLE		for_lmr_handle;
	DAT_SHARED_MEMORY	for_shared_memory;	/* For udapl only */
} DAT_REGION_DESCRIPTION;

/* LMR Arguments */

struct dat_lmr_param
{
	DAT_IA_HANDLE		ia_handle;
	DAT_MEM_TYPE		mem_type;
	DAT_REGION_DESCRIPTION	region_desc;
	DAT_VLEN		length;
	DAT_PZ_HANDLE		pz_handle;
	DAT_MEM_PRIV_FLAGS	mem_priv;
	DAT_LMR_CONTEXT		lmr_context;
	DAT_RMR_CONTEXT		rmr_context;
	DAT_VLEN		registered_size;
	DAT_VADDR		registered_address;
};


typedef struct dat_cno_param
{
	DAT_IA_HANDLE		ia_handle;
	DAT_OS_WAIT_PROXY_AGENT	agent;
} DAT_CNO_PARAM;

typedef enum dat_cno_param_mask
{
	DAT_CNO_FIELD_IA_HANDLE	= 0x1,
	DAT_CNO_FIELD_AGENT	= 0x2,

	DAT_CNO_FIELD_ALL	= 0x3
} DAT_CNO_PARAM_MASK;


/* General Provider attributes. udat specific. */
typedef enum dat_pz_support
{
	DAT_PZ_UNIQUE,
	DAT_PZ_SAME,
	DAT_PZ_SHAREABLE
} DAT_PZ_SUPPORT;

/*
 * Provider should support merging of all event stream types. Provider
 * attribute specify support for merging different event stream types.
 * It is a 2D binary matrix where each row and column represents an event
 * stream type. Each binary entry is 1 if the event streams of its raw
 * and column can fed the same EVD, and 0 otherwise. The order of event
 * streams in row and column is the same as in the definition of
 * DAT_EVD_FLAGS: index 0 - Software Event, 1- Connection Request,
 * 2 - DTO Completion, 3 - Connection event, 4 - RMR Bind Completion,
 * 5 - Asynchronous event. By definition each diagonal entry is 1.
 * Consumer allocates an array for it and passes it IN as a pointer
 * for the array that Provider fills. Provider must fill the array
 * that Consumer passes.
 */

struct dat_provider_attr
{
	char				provider_name[DAT_NAME_MAX_LENGTH];
	DAT_UINT32			provider_version_major;
	DAT_UINT32			provider_version_minor;
	DAT_UINT32			dapl_version_major;
	DAT_UINT32			dapl_version_minor;
	DAT_MEM_TYPE			lmr_mem_types_supported;
	DAT_IOV_OWNERSHIP		iov_ownership_on_return;
	DAT_QOS				dat_qos_supported;
	DAT_COMPLETION_FLAGS		completion_flags_supported;
	DAT_BOOLEAN			is_thread_safe;
	DAT_COUNT			max_private_data_size;
	DAT_BOOLEAN			supports_multipath;
	DAT_EP_CREATOR_FOR_PSP		ep_creator;
	DAT_PZ_SUPPORT			pz_support;
	DAT_UINT32			optimal_buffer_alignment;
	const DAT_BOOLEAN		evd_stream_merging_supported[6][6];
	DAT_BOOLEAN			srq_supported;
	DAT_COUNT			srq_watermarks_supported;
	DAT_BOOLEAN			srq_ep_pz_difference_supported;
	DAT_COUNT			srq_info_supported;
	DAT_COUNT			ep_recv_info_supported;
	DAT_BOOLEAN			lmr_sync_req;
	DAT_BOOLEAN			dto_async_return_guaranteed;
	DAT_BOOLEAN			rdma_write_for_rdma_read_req;
	DAT_COUNT			num_provider_specific_attr;
	DAT_NAMED_ATTR *		provider_specific_attr;
};

#define	DAT_PROVIDER_FIELD_PROVIDER_NAME		UINT64_C(0x0000001)
#define	DAT_PROVIDER_FIELD_PROVIDER_VERSION_MAJOR	UINT64_C(0x0000002)
#define	DAT_PROVIDER_FIELD_PROVIDER_VERSION_MINOR	UINT64_C(0x0000004)
#define	DAT_PROVIDER_FIELD_DAPL_VERSION_MAJOR		UINT64_C(0x0000008)
#define	DAT_PROVIDER_FIELD_DAPL_VERSION_MINOR		UINT64_C(0x0000010)
#define	DAT_PROVIDER_FIELD_LMR_MEM_TYPE_SUPPORTED	UINT64_C(0x0000020)
#define	DAT_PROVIDER_FIELD_IOV_OWNERSHIP		UINT64_C(0x0000040)
#define	DAT_PROVIDER_FIELD_DAT_QOS_SUPPORTED		UINT64_C(0x0000080)
#define	DAT_PROVIDER_FIELD_COMPLETION_FLAGS_SUPPORTED	UINT64_C(0x0000100)
#define	DAT_PROVIDER_FIELD_IS_THREAD_SAFE		UINT64_C(0x0000200)
#define	DAT_PROVIDER_FIELD_MAX_PRIVATE_DATA_SIZE	UINT64_C(0x0000400)
#define	DAT_PROVIDER_FIELD_SUPPORTS_MULTIPATH		UINT64_C(0x0000800)
#define	DAT_PROVIDER_FIELD_EP_CREATOR			UINT64_C(0x0001000)
#define	DAT_PROVIDER_FIELD_PZ_SUPPORT			UINT64_C(0x0002000)
#define	DAT_PROVIDER_FIELD_OPTIMAL_BUFFER_ALIGNMENT	UINT64_C(0x0004000)
#define	DAT_PROVIDER_FIELD_EVD_STREAM_MERGING_SUPPORTED	UINT64_C(0x0008000)
#define	DAT_PROVIDER_FIELD_SRQ_SUPPORTED		UINT64_C(0x0010000)
#define	DAT_PROVIDER_FIELD_SRQ_WATERMARKS_SUPPORTED	UINT64_C(0x0020000)
#define	DAT_PROVIDER_FIELD_SRQ_EP_PZ_DIFFERENCE_SUPPORTED \
							UINT64_C(0x0040000)
#define	DAT_PROVIDER_FIELD_SRQ_INFO_SUPPORTED		UINT64_C(0x0080000)
#define	DAT_PROVIDER_FIELD_EP_RECV_INFO_SUPPORTED	UINT64_C(0x0100000)
#define	DAT_PROVIDER_FIELD_LMR_SYNC_REQ			UINT64_C(0x0200000)
#define	DAT_PROVIDER_FIELD_DTO_ASYNC_RETURN_GUARANTEED	UINT64_C(0x0400000)
#define	DAT_PROVIDER_FIELD_RDMA_WRITE_FOR_RDMA_READ_REQ	UINT64_C(0x0800000)
#define	DAT_PROVIDER_FIELD_NUM_PROVIDER_SPECIFIC_ATTR	UINT64_C(0x1000000)
#define	DAT_PROVIDER_FIELD_PROVIDER_SPECIFIC_ATTR	UINT64_C(0x2000000)

#define	DAT_PROVIDER_FIELD_ALL				UINT64_C(0x3FFFFFF)
#define	DAT_PROVIDER_FIELD_NONE				UINT64_C(0x0)

#include <dat/udat_vendor_specific.h>

/* ************************************************************************ */

/*
 * User DAT functions definitions.
 */


extern DAT_RETURN dat_lmr_create(
	IN	DAT_IA_HANDLE,		/* ia_handle		*/
	IN	DAT_MEM_TYPE,		/* mem_type		*/
	IN	DAT_REGION_DESCRIPTION,	/* region_description   */
	IN	DAT_VLEN,		/* length		*/
	IN	DAT_PZ_HANDLE,		/* pz_handle		*/
	IN	DAT_MEM_PRIV_FLAGS,	/* privileges		*/
	OUT	DAT_LMR_HANDLE *,	/* lmr_handle		*/
	OUT	DAT_LMR_CONTEXT *,	/* lmr_context		*/
	OUT	DAT_RMR_CONTEXT *,	/* rmr_context		*/
	OUT	DAT_VLEN *,		/* registered_length	*/
	OUT	DAT_VADDR *);		/* registered_address   */

/* Event Functions */

extern DAT_RETURN dat_evd_create(
	IN	DAT_IA_HANDLE,		/* ia_handle		*/
	IN	DAT_COUNT,		/* evd_min_qlen		*/
	IN	DAT_CNO_HANDLE,		/* cno_handle		*/
	IN	DAT_EVD_FLAGS,		/* evd_flags		*/
	OUT	DAT_EVD_HANDLE *);	/* evd_handle		*/

extern DAT_RETURN dat_evd_modify_cno(
	IN	DAT_EVD_HANDLE,		/* evd_handle		*/
	IN	DAT_CNO_HANDLE);	/* cno_handle		*/

extern DAT_RETURN dat_cno_create(
	IN	DAT_IA_HANDLE,		/* ia_handle		*/
	IN	DAT_OS_WAIT_PROXY_AGENT,	/* agent		*/
	OUT	DAT_CNO_HANDLE *);	/* cno_handle		*/

extern DAT_RETURN dat_cno_modify_agent(
	IN	DAT_CNO_HANDLE,			/* cno_handle		*/
	IN	DAT_OS_WAIT_PROXY_AGENT);	/* agent		*/

extern DAT_RETURN dat_cno_query(
	IN	DAT_CNO_HANDLE,		/* cno_handle		*/
	IN	DAT_CNO_PARAM_MASK,	/* cno_param_mask	*/
	OUT	DAT_CNO_PARAM *);	/* cno_param		*/

extern DAT_RETURN dat_cno_free(
	IN DAT_CNO_HANDLE);		/* cno_handle		*/

extern DAT_RETURN dat_cno_wait(
	IN	DAT_CNO_HANDLE,		/* cno_handle		*/
	IN	DAT_TIMEOUT,		/* timeout		*/
	OUT	DAT_EVD_HANDLE *);	/* evd_handle		*/

extern DAT_RETURN dat_evd_enable(
	IN	DAT_EVD_HANDLE);	/* evd_handle		*/

extern DAT_RETURN dat_evd_wait(
	IN	DAT_EVD_HANDLE,		/* evd_handle		*/
	IN	DAT_TIMEOUT,		/* Timeout		*/
	IN	DAT_COUNT,		/* Threshold		*/
	OUT	DAT_EVENT *,		/* event		*/
	OUT	DAT_COUNT *);		/* N more events	*/

extern DAT_RETURN dat_evd_disable(
	IN	DAT_EVD_HANDLE);	/* evd_handle		*/

extern DAT_RETURN dat_evd_set_unwaitable(
	IN DAT_EVD_HANDLE);		/* evd_handle */

extern DAT_RETURN dat_evd_clear_unwaitable(
	IN DAT_EVD_HANDLE); /* evd_handle */

#ifdef __cplusplus
}
#endif

#endif /* _UDAT_H_ */
