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

#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <strings.h>
#include <libintl.h>
#include <libscf.h>
#include <libnvpair.h>

#include <libstmf.h>
#include <libsrpt.h>

#include "srpt_common.h"

#define	SRPT_PROV_NAME	"srpt"

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
srpt_GetConfig(nvlist_t **cfg, uint64_t *token)
{
	int		ret = 0;
	nvlist_t	*cfg_nv = NULL;
	uint64_t	stmf_token = 0;
	nvlist_t	*hcanv = NULL;

	if (!cfg) {
		return (EINVAL);
	}

	*cfg = NULL;

	ret = stmfGetProviderDataProt(SRPT_PROV_NAME, &cfg_nv,
	    STMF_PORT_PROVIDER_TYPE, &stmf_token);

	if (ret == STMF_STATUS_SUCCESS) {
		ret = 0;
	} else if (ret == STMF_ERROR_NOT_FOUND) {
		/* Not initialized yet */
		ret = nvlist_alloc(&cfg_nv, NV_UNIQUE_NAME, 0);
		if (ret != 0) {
			return (ret);
		}
		/* create the HCA list */
		ret = nvlist_alloc(&hcanv, NV_UNIQUE_NAME, 0);
		if (ret == 0) {
			ret = nvlist_add_nvlist(cfg_nv, SRPT_PROP_HCALIST,
			    hcanv);
			if (ret != 0) {
				nvlist_free(hcanv);
			}
		}
		if (ret != 0) {
			nvlist_free(cfg_nv);
			cfg_nv = NULL;
		}
	} else if (ret == STMF_ERROR_NOMEM) {
		ret = ENOMEM;
	} else {
		ret = EINVAL;
	}

	*cfg = cfg_nv;
	*token = stmf_token;

	return (ret);
}

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
srpt_SetConfig(nvlist_t *cfg, uint64_t token)
{
	int		ret = 0;

	ret = stmfSetProviderDataProt(SRPT_PROV_NAME, cfg,
	    STMF_PORT_PROVIDER_TYPE, &token);

	if (ret == STMF_STATUS_SUCCESS) {
		ret = 0;
	} else if (ret == STMF_ERROR_NOMEM) {
		ret = ENOMEM;
	} else if (ret == STMF_ERROR_PROV_DATA_STALE) {
		ret = ECANCELED;  /* could be a better errno */
	} else {
		ret = EINVAL;
	}

	return (ret);
}

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
srpt_GetDefaultState(boolean_t *enabled)
{
	int		ret;
	nvlist_t	*cfgnv;
	uint64_t	token;
	boolean_t	val = B_TRUE;

	if (enabled == NULL) {
		return (EINVAL);
	}

	ret = srpt_GetConfig(&cfgnv, &token);
	if (ret != 0) {
		return (ret);
	}

	if (cfgnv != NULL) {
		ret = nvlist_lookup_boolean_value(cfgnv,
		    SRPT_PROP_DEFAULT_ENABLED, &val);

		if (ret == ENOENT) {
			ret = 0;
		}
	}

	*enabled = val;
	return (ret);
}

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
srpt_SetDefaultState(boolean_t enabled)
{
	int		ret;
	nvlist_t	*cfgnv;
	uint64_t	token;

	ret = srpt_GetConfig(&cfgnv, &token);
	if (ret != 0) {
		return (ret);
	}

	if (cfgnv == NULL) {
		ret = nvlist_alloc(&cfgnv, NV_UNIQUE_NAME, 0);
		if (ret != 0) {
			return (ret);
		}
	}

	ret = nvlist_add_boolean_value(cfgnv, SRPT_PROP_DEFAULT_ENABLED,
	    enabled);

	if (ret == 0) {
		ret = srpt_SetConfig(cfgnv, token);
	}

	nvlist_free(cfgnv);

	return (ret);
}

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
srpt_SetTargetState(char *hca_guid, boolean_t enabled)
{
	int		ret;
	nvlist_t	*cfgnv;
	uint64_t	token;
	nvlist_t	*hcalist;
	nvlist_t	*hcanv;
	char		guid[32];
	uint64_t	hcaguid;

	if (hca_guid == NULL) {
		return (EINVAL);
	}

	ret = srpt_NormalizeGuid(hca_guid, guid, sizeof (guid), &hcaguid);
	if (ret != 0) {
		return (ret);
	}

	ret = srpt_GetConfig(&cfgnv, &token);
	if (ret != 0) {
		return (ret);
	}

	/* get the list of HCAs */
	ret = nvlist_lookup_nvlist(cfgnv, SRPT_PROP_HCALIST, &hcalist);
	if (ret != 0) {
		nvlist_free(cfgnv);
		return (ret);
	}

	ret = nvlist_lookup_nvlist(hcalist, guid, &hcanv);
	if (ret == ENOENT) {
		/* no entry yet */
		ret = nvlist_alloc(&hcanv, NV_UNIQUE_NAME, 0);
		if (ret == 0) {
			ret = nvlist_add_uint64(hcanv, SRPT_PROP_GUID, hcaguid);
		}
	}

	if (ret == 0) {
		ret = nvlist_add_boolean_value(hcanv, SRPT_PROP_ENABLED,
		    enabled);
	}

	if (ret == 0) {
		ret = nvlist_add_nvlist(hcalist, guid, hcanv);
	}

	if (ret == 0) {
		ret = srpt_SetConfig(cfgnv, token);
	}

	nvlist_free(cfgnv);

	return (ret);
}

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
srpt_GetTargetState(char *hca_guid, boolean_t *enabled)
{
	int		ret;
	nvlist_t	*cfgnv;
	uint64_t	token;
	nvlist_t	*hcalist;
	nvlist_t	*hcanv;
	boolean_t	defaultState = B_TRUE;
	char		guid[32];

	if (hca_guid == NULL) {
		return (EINVAL);
	}

	ret = srpt_NormalizeGuid(hca_guid, guid, sizeof (guid), NULL);
	if (ret != 0) {
		return (ret);
	}

	ret = srpt_GetConfig(&cfgnv, &token);
	if (ret != 0) {
		return (ret);
	}

	/* get the list of HCAs */
	ret = nvlist_lookup_nvlist(cfgnv, SRPT_PROP_HCALIST, &hcalist);
	if (ret != 0) {
		nvlist_free(cfgnv);
		return (ret);
	}

	/*
	 * Find the default, for the likely case that this HCA isn't
	 * explicitly set.
	 */
	(void) nvlist_lookup_boolean_value(cfgnv, SRPT_PROP_DEFAULT_ENABLED,
	    &defaultState);

	ret = nvlist_lookup_nvlist(hcalist, guid, &hcanv);
	if (ret == 0) {
		ret = nvlist_lookup_boolean_value(hcanv, SRPT_PROP_ENABLED,
		    enabled);
	}

	if (ret == ENOENT) {
		/* not explicitly set, use the default */
		*enabled = defaultState;
		ret = 0;
	}

	nvlist_free(cfgnv);

	return (ret);

}

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
srpt_ResetTarget(char *hca_guid)
{
	int		ret;
	nvlist_t	*cfgnv;
	nvlist_t	*hcalist;
	uint64_t	token;
	char		guid[32];

	if (hca_guid == NULL) {
		return (EINVAL);
	}

	ret = srpt_NormalizeGuid(hca_guid, guid, sizeof (guid), NULL);
	if (ret != 0) {
		return (ret);
	}

	ret = srpt_GetConfig(&cfgnv, &token);
	if (ret != 0) {
		return (ret);
	}

	/* get the list of HCAs */
	ret = nvlist_lookup_nvlist(cfgnv, SRPT_PROP_HCALIST, &hcalist);
	if (ret != 0) {
		nvlist_free(cfgnv);
		return (ret);
	}

	/* don't set config if we don't actually change anything */
	if (nvlist_exists(hcalist, guid)) {
		(void) nvlist_remove_all(hcalist, guid);

		if (ret == 0) {
			ret = srpt_SetConfig(cfgnv, token);
		}
	}

	nvlist_free(cfgnv);

	return (ret);
}

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
srpt_NormalizeGuid(char *in, char *buf, size_t buflen, uint64_t *int_guid)
{
	uint64_t	guid;
	char		*bufp = in;
	char		*end = NULL;

	if ((in == NULL) || (buf == NULL)) {
		return (EINVAL);
	}

	if (strncasecmp(bufp, "eui.", 4) == 0) {
		/* EUI form */
		bufp += 4;
	} else if (strncasecmp(bufp, "hca:", 4) == 0) {
		/* cfgadm and /dev/hca form */
		bufp += 4;
	}

	/*
	 * strtoull() does not return EINVAL as documented.  Lucky
	 * for us, neither 0 nor ULLONG_MAX will be valid.  Trap on
	 * those and fail.
	 */
	guid = strtoull(bufp, &end, 16);
	if ((guid == 0) || (guid == ULLONG_MAX) ||
	    ((end != NULL) && (strlen(end) > 0))) {
		return (EINVAL);
	}

#if 0
	(void) snprintf(buf, buflen, "%llX", guid);
#endif
	SRPT_FORMAT_HCAKEY(buf, buflen, guid);

	if (int_guid) {
		*int_guid = guid;
	}

	return (0);
}
