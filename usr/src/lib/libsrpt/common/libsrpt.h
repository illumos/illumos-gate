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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_LIBSRPT_H
#define	_LIBSRPT_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <libnvpair.h>

/*
 * Function:  srpt_GetConfig()
 *
 * Parameters:
 *    cfg	Current SRPT configuration in nvlist form
 *    token	Configuration generation number.  Use this token
 *		if updating the configuration with srpt_SetConfig.
 *
 * Return Values:
 *    0		Success
 *    ENOMEM	Could not allocate resources
 *    EINVAL	Invalid parameter
 */
int
srpt_GetConfig(nvlist_t **cfg, uint64_t *token);

/*
 * Function:  srpt_SetConfig()
 *
 * Parameters:
 *    cfg	SRPT configuration in nvlist form
 *    token	Configuration generation number from srpt_GetConfig.
 *		Use this token to ensure the configuration hasn't been
 *		updated by another user since the time it was fetched.
 *
 * Return Values:
 *    0		Success
 *    ENOMEM	Could not allocate resources
 *    EINVAL	Invalid parameter
 *    ECANCELED Configuration updated by another user
 */
int
srpt_SetConfig(nvlist_t *cfg, uint64_t token);

/*
 * Function:  srpt_GetDefaultState()
 *
 * Parameters:
 *    enabled	If B_TRUE, indicates that targets will be created for all
 *		discovered HCAs that have not been specifically disabled.
 *		If B_FALSE, targets will not be created unless the HCA has
 *		been specifically enabled.  See also srpt_SetDefaultState().
 *
 * Return Values:
 *    0		Success
 *    ENOMEM	Could not allocate resources
 *    EINVAL	Invalid parameter
 */
int
srpt_GetDefaultState(boolean_t *enabled);

/*
 * Function:  srpt_SetDefaultState()
 *
 * Parameters:
 *    enabled	If B_TRUE, indicates that targets will be created for all
 *		discovered HCAs that have not been specifically disabled.
 *		If B_FALSE, targets will not be created unless the HCA has
 *		been specifically enabled.  See also srpt_SetDefaultState().
 *
 * Return Values:
 *    0		Success
 *    ENOMEM	Could not allocate resources
 *    EINVAL	Invalid parameter
 */
int
srpt_SetDefaultState(boolean_t enabled);

/*
 * Function:  srpt_SetTargetState()
 *
 * Parameters:
 *    hca_guid	HCA GUID.  See description of srpt_NormalizeGuid
 *    enabled	If B_TRUE, indicates that a target will be created for
 *		this HCA when the SRPT SMF service is enabled.  If B_FALSE,
 *		a target will not be created
 *
 * Return Values:
 *    0		Success
 *    ENOMEM	Could not allocate resources
 *    EINVAL	Invalid parameter
 */
int
srpt_SetTargetState(char *hca_guid, boolean_t enabled);

/*
 * Function:  srpt_GetTargetState()
 *
 * Parameters:
 *    hca_guid	HCA GUID.  See description of srpt_NormalizeGuid
 *    enabled	If B_TRUE, indicates that a target will be created for
 *		this HCA when the SRPT SMF service is enabled.  If B_FALSE,
 *		a target will not be created
 *
 * Return Values:
 *    0		Success
 *    ENOMEM	Could not allocate resources
 *    EINVAL	Invalid parameter
 */
int
srpt_GetTargetState(char *hca_guid, boolean_t *enabled);

/*
 * Function:  srpt_ResetTarget()
 *
 * Clears the HCA-specific configuration.  Target creation will revert to
 * the default.
 *
 * Parameters:
 *    hca_guid	HCA GUID.  See description of srpt_NormalizeGuid
 *
 * Return Values:
 *    0		Success
 *    ENOMEM	Could not allocate resources
 *    EINVAL	Invalid parameter
 */
int
srpt_ResetTarget(char *hca_guid);

/*
 * srpt_NormalizeGuid()
 *
 * Parameters:
 *    in	HCA GUID.  Must be in one of the following forms:
 *		    3BA000100CD18	- base hex form
 *		    0003BA000100CD18	- base hex form with leading zeroes
 *		    hca:3BA000100CD18	- form from cfgadm and/or /dev/cfg
 *		    eui.0003BA000100CD18 - EUI form
 *
 *    buf	Buffer to hold normalized guid string.  Must be at least
 *		17 chars long.
 *    buflen	Length of provided buffer
 *    int_guid	Optional.  If not NULL, the integer form of the GUID will also
 *		be returned.
 * Return Values:
 *    0		Success
 *    EINVAL	Invalid HCA GUID or invalid parameter.
 */
int
srpt_NormalizeGuid(char *in, char *buf, size_t buflen, uint64_t *int_guid);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBSRPT_H */
