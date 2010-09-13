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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *
 * MODULE: dat_strerror.c
 *
 * PURPOSE: Convert DAT_RETURN values to humman readable string
 *
 * $Id: dat_strerror.c,v 1.2 2003/08/06 14:40:29 jlentini Exp $
 */

#include <dat/udat.h>


/*
 *
 * Internal Function Declarations
 *
 */

DAT_RETURN
dat_strerror_major(
    IN  DAT_RETURN 		value,
    OUT const char 		**message);

DAT_RETURN
dat_strerror_minor(
    IN  DAT_RETURN 		value,
    OUT const char 		**message);


/*
 *
 * Internal Function Definitions
 *
 */

DAT_RETURN
dat_strerror_major(
    IN  DAT_RETURN 		value,
    OUT const char 		**message)
{
	switch (DAT_GET_TYPE(value)) {
	case DAT_SUCCESS:
	{
		*message = "DAT_SUCCESS";
		return (DAT_SUCCESS);
	}
	case DAT_ABORT:
	{
		*message = "DAT_ABORT";
		return (DAT_SUCCESS);
	}
	case DAT_CONN_QUAL_IN_USE:
	{
		*message = "DAT_CONN_QUAL_IN_USE";
		return (DAT_SUCCESS);
	}
	case DAT_INSUFFICIENT_RESOURCES:
	{
		*message = "DAT_INSUFFICIENT_RESOURCES";
		return (DAT_SUCCESS);
	}
	case DAT_INTERNAL_ERROR:
	{
		*message = "DAT_INTERNAL_ERROR";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_HANDLE:
	{
		*message = "DAT_INVALID_HANDLE";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_PARAMETER:
	{
		*message = "DAT_INVALID_PARAMETER";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_STATE:
	{
		*message = "DAT_INVALID_STATE";
		return (DAT_SUCCESS);
	}
	case DAT_LENGTH_ERROR:
	{
		*message = "DAT_LENGTH_ERROR";
		return (DAT_SUCCESS);
	}
	case DAT_MODEL_NOT_SUPPORTED:
	{
		*message = "DAT_MODEL_NOT_SUPPORTED";
		return (DAT_SUCCESS);
	}
	case DAT_NAME_NOT_FOUND:
	{
		*message = "DAT_NAME_NOT_FOUND";
		return (DAT_SUCCESS);
	}
	case DAT_PRIVILEGES_VIOLATION:
	{
		*message = "DAT_PRIVILEGES_VIOLATION";
		return (DAT_SUCCESS);
	}
	case DAT_PROTECTION_VIOLATION:
	{
		*message = "DAT_PROTECTION_VIOLATION";
		return (DAT_SUCCESS);
	}
	case DAT_QUEUE_EMPTY:
	{
		*message = "DAT_QUEUE_EMPTY";
		return (DAT_SUCCESS);
	}
	case DAT_QUEUE_FULL:
	{
		*message = "DAT_QUEUE_FULL";
		return (DAT_SUCCESS);
	}
	case DAT_TIMEOUT_EXPIRED:
	{
		*message = "DAT_TIMEOUT_EXPIRED";
		return (DAT_SUCCESS);
	}
	case DAT_PROVIDER_ALREADY_REGISTERED:
	{
		*message = "DAT_PROVIDER_ALREADY_REGISTERED";
		return (DAT_SUCCESS);
	}
	case DAT_PROVIDER_IN_USE:
	{
		*message = "DAT_PROVIDER_IN_USE";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_ADDRESS:
	{
		*message = "DAT_INVALID_ADDRESS";
		return (DAT_SUCCESS);
	}
	case DAT_INTERRUPTED_CALL:
	{
		*message = "DAT_INTERRUPTED_CALL";
		return (DAT_SUCCESS);
	}
	case DAT_NOT_IMPLEMENTED:
	{
		*message = "DAT_NOT_IMPLEMENTED";
		return (DAT_SUCCESS);
	}
	default:
	{
		return (DAT_INVALID_PARAMETER);
	}
	}
}


DAT_RETURN
dat_strerror_minor(
    IN  DAT_RETURN 		value,
    OUT const char 		**message)
{
	switch (DAT_GET_SUBTYPE(value)) {
	case DAT_NO_SUBTYPE:
	{
		*message = "";
		return (DAT_SUCCESS);
	}
	case DAT_SUB_INTERRUPTED:
	{
		*message = "DAT_SUB_INTERRUPTED";
		return (DAT_SUCCESS);
	}
	case DAT_RESOURCE_MEMORY:
	{
		*message = "DAT_RESOURCE_MEMORY";
		return (DAT_SUCCESS);
	}
	case DAT_RESOURCE_DEVICE:
	{
		*message = "DAT_RESOURCE_DEVICE";
		return (DAT_SUCCESS);
	}
	case DAT_RESOURCE_TEP:
	{
		*message = "DAT_RESOURCE_TEP";
		return (DAT_SUCCESS);
	}
	case DAT_RESOURCE_TEVD:
	{
		*message = "DAT_RESOURCE_TEVD";
		return (DAT_SUCCESS);
	}
	case DAT_RESOURCE_PROTECTION_DOMAIN:
	{
		*message = "DAT_RESOURCE_PROTECTION_DOMAIN";
		return (DAT_SUCCESS);
	}
	case DAT_RESOURCE_MEMORY_REGION:
	{
		*message = "DAT_RESOURCE_MEMORY_REGION";
		return (DAT_SUCCESS);
	}
	case DAT_RESOURCE_ERROR_HANDLER:
	{
		*message = "DAT_RESOURCE_ERROR_HANDLER";
		return (DAT_SUCCESS);
	}
	case DAT_RESOURCE_CREDITS:
	{
		*message = "DAT_RESOURCE_CREDITS";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_HANDLE_IA:
	{
		*message = "DAT_INVALID_HANDLE_IA";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_HANDLE_EP:
	{
		*message = "DAT_INVALID_HANDLE_EP";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_HANDLE_LMR:
	{
		*message = "DAT_INVALID_HANDLE_LMR";
		return (DAT_SUCCESS);
	}
	case  DAT_INVALID_HANDLE_RMR:
	{
		*message = "DAT_INVALID_HANDLE_RMR";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_HANDLE_PZ:
	{
		*message = "DAT_INVALID_HANDLE_PZ";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_HANDLE_PSP:
	{
		*message = "DAT_INVALID_HANDLE_PSP";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_HANDLE_RSP:
	{
		*message = "DAT_INVALID_HANDLE_RSP";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_HANDLE_CR:
	{
		*message = "DAT_INVALID_HANDLE_CR";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_HANDLE_CNO:
	{
		*message = "DAT_INVALID_HANDLE_CNO";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_HANDLE_EVD_CR:
	{
		*message = "DAT_INVALID_HANDLE_EVD_CR";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_HANDLE_EVD_REQUEST:
	{
		*message = "DAT_INVALID_HANDLE_EVD_REQUEST";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_HANDLE_EVD_RECV:
	{
		*message = "DAT_INVALID_HANDLE_EVD_RECV";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_HANDLE_EVD_CONN:
	{
		*message = "DAT_INVALID_HANDLE_EVD_CONN";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_HANDLE_EVD_ASYNC:
	{
		*message = "DAT_INVALID_HANDLE_EVD_ASYNC";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_ARG1:
	{
		*message = "DAT_INVALID_ARG1";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_ARG2:
	{
		*message = "DAT_INVALID_ARG2";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_ARG3:
	{
		*message = "DAT_INVALID_ARG3";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_ARG4:
	{
		*message = "DAT_INVALID_ARG4";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_ARG5:
	{
		*message = "DAT_INVALID_ARG5";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_ARG6:
	{
		*message = "DAT_INVALID_ARG6";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_ARG7:
	{
		*message = "DAT_INVALID_ARG7";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_ARG8:
	{
		*message = "DAT_INVALID_ARG8";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_ARG9:
	{
		*message = "DAT_INVALID_ARG9";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_ARG10:
	{
		*message = "DAT_INVALID_ARG10";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_STATE_EP_UNCONNECTED:
	{
		*message = "DAT_INVALID_STATE_EP_UNCONNECTED";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_STATE_EP_ACTCONNPENDING:
	{
		*message = "DAT_INVALID_STATE_EP_ACTCONNPENDING";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_STATE_EP_PASSCONNPENDING:
	{
		*message = "DAT_INVALID_STATE_EP_PASSCONNPENDING";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_STATE_EP_TENTCONNPENDING:
	{
		*message = "DAT_INVALID_STATE_EP_TENTCONNPENDING";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_STATE_EP_CONNECTED:
	{
		*message = "DAT_INVALID_STATE_EP_CONNECTED";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_STATE_EP_DISCONNECTED:
	{
		*message = "DAT_INVALID_STATE_EP_DISCONNECTED";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_STATE_EP_RESERVED:
	{
		*message = "DAT_INVALID_STATE_EP_RESERVED";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_STATE_EP_COMPLPENDING:
	{
		*message = "DAT_INVALID_STATE_EP_COMPLPENDING";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_STATE_EP_DISCPENDING:
	{
		*message = "DAT_INVALID_STATE_EP_DISCPENDING";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_STATE_EP_PROVIDERCONTROL:
	{
		*message = "DAT_INVALID_STATE_EP_PROVIDERCONTROL";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_STATE_EP_NOTREADY:
	{
		*message = "DAT_INVALID_STATE_EP_NOTREADY";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_STATE_CNO_IN_USE:
	{
		*message = "DAT_INVALID_STATE_CNO_IN_USE";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_STATE_CNO_DEAD:
	{
		*message = "DAT_INVALID_STATE_CNO_DEAD";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_STATE_EVD_OPEN:
	{
		*message = "DAT_INVALID_STATE_EVD_OPEN";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_STATE_EVD_ENABLED:
	{
		*message = "DAT_INVALID_STATE_EVD_ENABLED";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_STATE_EVD_DISABLED:
	{
		*message = "DAT_INVALID_STATE_EVD_DISABLED";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_STATE_EVD_WAITABLE:
	{
		*message = "DAT_INVALID_STATE_EVD_WAITABLE";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_STATE_EVD_UNWAITABLE:
	{
		*message = "DAT_INVALID_STATE_EVD_UNWAITABLE";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_STATE_EVD_IN_USE:
	{
		*message = "DAT_INVALID_STATE_EVD_IN_USE";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_STATE_EVD_CONFIG_NOTIFY:
	{
		*message = "DAT_INVALID_STATE_EVD_CONFIG_NOTIFY";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_STATE_EVD_CONFIG_SOLICITED:
	{
		*message = "DAT_INVALID_STATE_EVD_CONFIG_SOLICITED";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_STATE_EVD_CONFIG_THRESHOLD:
	{
		*message = "DAT_INVALID_STATE_EVD_CONFIG_THRESHOLD";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_STATE_EVD_WAITER:
	{
		*message = "DAT_INVALID_STATE_EVD_WAITER";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_STATE_EVD_ASYNC:
	{
		*message = "DAT_INVALID_STATE_EVD_ASYNC";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_STATE_IA_IN_USE:
	{
		*message = "DAT_INVALID_STATE_IA_IN_USE";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_STATE_LMR_IN_USE:
	{
		*message = "DAT_INVALID_STATE_LMR_IN_USE";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_STATE_LMR_FREE:
	{
		*message = "DAT_INVALID_STATE_LMR_FREE";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_STATE_PZ_IN_USE:
	{
		*message = "DAT_INVALID_STATE_PZ_IN_USE";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_STATE_PZ_FREE:
	{
		*message = "DAT_INVALID_STATE_PZ_FREE";
		return (DAT_SUCCESS);
	}
	case DAT_PRIVILEGES_READ:
	{
		*message = "DAT_PRIVILEGES_READ";
		return (DAT_SUCCESS);
	}
	case DAT_PRIVILEGES_WRITE:
	{
		*message = "DAT_PRIVILEGES_WRITE";
		return (DAT_SUCCESS);
	}
	case DAT_PRIVILEGES_RDMA_READ:
	{
		*message = "DAT_PRIVILEGES_RDMA_READ";
		return (DAT_SUCCESS);
	}
	case DAT_PRIVILEGES_RDMA_WRITE:
	{
		*message = "DAT_PRIVILEGES_RDMA_WRITE";
		return (DAT_SUCCESS);
	}
	case DAT_PROTECTION_READ:
	{
		*message = "DAT_PROTECTION_READ";
		return (DAT_SUCCESS);
	}
	case DAT_PROTECTION_WRITE:
	{
		*message = "DAT_PROTECTION_WRITE";
		return (DAT_SUCCESS);
	}
	case DAT_PROTECTION_RDMA_READ:
	{
		*message = "DAT_PROTECTION_RDMA_READ";
		return (DAT_SUCCESS);
	}
	case DAT_PROTECTION_RDMA_WRITE:
	{
		*message = "DAT_PROTECTION_RDMA_WRITE";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_ADDRESS_UNSUPPORTED:
	{
		*message = "DAT_INVALID_ADDRESS_UNSUPPORTED";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_ADDRESS_UNREACHABLE:
	{
		*message = "DAT_INVALID_ADDRESS_UNREACHABLE";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_ADDRESS_MALFORMED:
	{
		*message = "DAT_INVALID_ADDRESS_MALFORMED";
		return (DAT_SUCCESS);
	}
	case DAT_INVALID_RO_COOKIE:
		*message = "DAT_INVALID_RO_COOKIE";
		return (DAT_SUCCESS);
	default:
	{
		return (DAT_INVALID_PARAMETER);
	}
	}
}


/*
 *
 * External Function Definitions
 *
 */

DAT_RETURN
dat_strerror(
	IN  DAT_RETURN 		value,
	OUT const char 		**major_message,
	OUT const char		**minor_message)
{
	/*
	 * The DAT specification contains a note to implementers
	 * suggesting that the consumer's DAT_RETURN value be used
	 * as an index into a table of text strings. However,
	 * the DAT_RETURN values are not consecutive. Therefore this
	 * implementation does not follow the suggested implementation.
	 */

	if (DAT_SUCCESS != dat_strerror_major(value, major_message)) {
		return (DAT_INVALID_PARAMETER);
	} else if (DAT_SUCCESS != dat_strerror_minor(value, minor_message)) {
		return (DAT_INVALID_PARAMETER);
	} else {
		return (DAT_SUCCESS);
	}
}
