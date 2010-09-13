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
 * Copyright (c) 2002-2003, Network Appliance, Inc. All rights reserved.
 */

/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *
 * HEADER: dapl_vendor.h
 *
 * PURPOSE:
 *	Vendor provides values for their implementation. Most of
 *	these values are returned in the DAT_IA_ATTR parameter of
 *	dat_ia_query()
 *
 */

#ifndef _DAPL_VENDOR_H_
#define	_DAPL_VENDOR_H_

#ifdef __cplusplus
extern "C" {
#endif

/*
 * DAT_IA_ATTR attributes
 *
 * These values are used in the provider support routine
 * dapls_ib_query_hca (). Many of the values there are HW
 * specific, the the vendor should look to make sure they are
 * appropriate for their implementation. Specifically,
 * vendors are encouraged to update transport and vendor
 * attributes: the reference implementation sets these to NULL.
 */

/*
 * Product name of the adapter.
 * Returned in DAT_IA_ATTR.adapter_name
 * adapter name is limited to DAT_NAME_MAX_LENGTH
 */
#define	VN_ADAPTER_NAME		"InfiniBand HCA Tavor"


/*
 * Vendor name
 * Returned in DAT_IA_ATTR.vendor_name
 */
#define	VN_VENDOR_NAME		"SUNW"


/*
 * PROVIDER Attributes
 *
 * These values are used in ./common/dapl_ia_query.c, in dapl_ia_query ().
 * The values below are the most common for vendors to change, but
 * there are several other values that may be updated once the
 * implementation becomes mature.
 *
 */

/*
 * Provider Versions
 * Returned in DAT_PROVIDER_ATTR.provider_version_major and
 * DAT_PROVIDER_ATTR.provider_version_minor
 */

#define	VN_PROVIDER_MAJOR	1
#define	VN_PROVIDER_MINOR	0

/*
 * Provider support for memory types. The reference implementation
 * always supports DAT_MEM_TYPE_VIRTUAL and DAT_MEM_TYPE_LMR, so
 * the vendor must indicate if they support DAT_MEM_TYPE_SHARED_VIRTUAL.
 * Set this value to '1' if DAT_MEM_TYPE_SHARED_VIRTUAL is supported.
 *
 * Returned in DAT_PROVIDER_ATTR.lmr_mem_types_supported
 */

#define	VN_MEM_SHARED_VIRTUAL_SUPPORT 1


/*
 *
 * This value will be assigned to dev_name_prefix in ./udapl/dapl_init.c.
 *
 * DAT is designed to support multiple DAPL instances simultaneously,
 * with different dapl libraries originating from different providers.
 * There is always the possibility of name conflicts, so a dat name
 * prefix is provided to make a vendor's adapter name unique. This is
 * especially true of the IBM Access API, which returns adapter
 * names that are simply ordinal numbers (e.g. 0, 1, 2). If
 * a vendor doesn't need or want a prefix, it should be left
 * as a NULL (use "").
 *
 * Values that might be used:
 *  #define VN_PREFIX		"jni"	(JNI: OS Acces API)
 *  #define VN_PREFIX		"ibm"	(IBM: OS Acces API)
 *  #define VN_PREFIX		""      (Mellanox: VAPI)
 *  #define VN_PREFIX		""      (Intel: IB Common API)
 */
#define	VN_PREFIX		""

#ifdef __cplusplus
}
#endif

#endif /* _DAPL_VENDOR_H_ */
