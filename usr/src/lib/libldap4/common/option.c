/*
 * Copyright (c) 1995-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include "lber.h"
#include "ldap.h"
#include "ldap-private.h"
#include "ldap-int.h"

extern LDAPControl ** ldap_controls_dup(LDAPControl **ctrls);

/*
 * ldap_get_option()
 */
int
ldap_get_option(LDAP *ld, int option, void *outvalue)
{
	if (ld == NULL)
		return (-1);
#ifdef _REENTRANT
	LOCK_LDAP(ld);
#endif
	switch (option) {
	case LDAP_OPT_API_INFO:
		((LDAPAPIInfo *)outvalue)->ldapai_api_version =
			LDAP_API_VERSION;
		if (((LDAPAPIInfo *)outvalue)->ldapai_info_version !=
			LDAP_API_INFO_VERSION) {
			((LDAPAPIInfo *)outvalue)->ldapai_info_version =
				LDAP_API_INFO_VERSION;
#ifdef _REENTRANT
				UNLOCK_LDAP(ld);
#endif
				return (-1);
		}
		((LDAPAPIInfo *)outvalue)->ldapai_protocol_version =
			LDAP_VERSION_MAX;
		/* No extensions are currently supported */
		((LDAPAPIInfo *)outvalue)->ldapai_extensions = NULL;
		((LDAPAPIInfo *)outvalue)->ldapai_vendor_name =
			strdup(LDAP_VENDOR_NAME);
		((LDAPAPIInfo *)outvalue)->ldapai_vendor_version =
			LDAP_VENDOR_VERSION;
		break;
	case LDAP_OPT_DESC:	/* depricated option */
		*(int *)outvalue = ld->ld_sb.sb_sd;
		break;
	case LDAP_OPT_DEREF:
		*(int *)outvalue = ld->ld_deref;
		break;
	case LDAP_OPT_SIZELIMIT:
		*(int *)outvalue = ld->ld_sizelimit;
		break;
	case LDAP_OPT_TIMELIMIT:
		*(int *)outvalue = ld->ld_timelimit;
		break;
	case LDAP_OPT_REBIND_FN:	/* depricated option */
		outvalue = (void *)ld->ld_rebindproc;
		break;
	case LDAP_OPT_REBIND_ARG:	/* depricated option */
		outvalue = ld->ld_rebind_extra_arg;
		break;
	case LDAP_OPT_REFERRALS:
		*(int *)outvalue = ld->ld_follow_referral;
		break;
	case LDAP_OPT_RESTART:
		*(int *)outvalue = ld->ld_restart;
		break;
	case LDAP_OPT_PROTOCOL_VERSION:
		*(int *)outvalue = ld->ld_version;
		break;
	case LDAP_OPT_SERVER_CONTROLS:
		outvalue = ld->ld_srvctrls;
		break;
	case LDAP_OPT_CLIENT_CONTROLS:
		outvalue = ld->ld_cltctrls;
		break;
	case LDAP_OPT_API_FEATURE_INFO:
		if ((((LDAPAPIFeatureInfo *)outvalue)->ldapaif_info_version !=
			LDAP_FEATURE_INFO_VERSION) ||
			(((LDAPAPIFeatureInfo *)outvalue)->ldapaif_name ==
			NULL)) {
			((LDAPAPIFeatureInfo *)outvalue)->ldapaif_info_version =
				LDAP_FEATURE_INFO_VERSION;
#ifdef _REENTRANT
				UNLOCK_LDAP(ld);
#endif
				return (-1);
		}
		/*
		 * This option must be completed when optional api's (or
		 * (extensions) are supported by this library.  Right now
		 * there are none, and therefore this section can not be
		 * completed.
		 */
		break;
	case LDAP_OPT_HOST_NAME:
		*(char **)outvalue = ld->ld_host;
		break;
	case LDAP_OPT_ERROR_NUMBER:
		*(int *)outvalue = ld->ld_errno;
		break;
	case LDAP_OPT_ERROR_STRING:
		*(char **)outvalue = ld->ld_error;
		break;
	case LDAP_OPT_MATCHED_DN:
/*	case LDAP_OPT_ERROR_MATCHED:	depricated option */
		*(char **)outvalue = ld->ld_matched;
		break;
	case LDAP_X_OPT_CONNECT_TIMEOUT:
		*((int *)outvalue) = ld->ld_connect_timeout;
		break;
	default:
#ifdef _REENTRANT
		UNLOCK_LDAP(ld);
#endif
		return (-1);
	}

#ifdef _REENTRANT
	UNLOCK_LDAP(ld);
#endif
	return (0);
}

int
ldap_set_option(LDAP *ld, int option, void *invalue)
{
	if (ld == NULL)
		return (-1);
#ifdef _REENTRANT
	LOCK_LDAP(ld);
#endif
	switch (option) {
	case LDAP_OPT_DESC:
		break;
	case LDAP_OPT_DEREF:
		if (*(int *)invalue != LDAP_DEREF_NEVER &&
			*(int *)invalue != LDAP_DEREF_SEARCHING &&
			*(int *)invalue != LDAP_DEREF_FINDING &&
			*(int *)invalue != LDAP_DEREF_ALWAYS) {
#ifdef _REENTRANT
			UNLOCK_LDAP(ld);
#endif
			return (-1);
		}
		ld->ld_deref = *(int *)invalue;
		break;
	case LDAP_OPT_SIZELIMIT:
		ld->ld_sizelimit = *(int *)invalue;
		break;
	case LDAP_OPT_TIMELIMIT:
		ld->ld_timelimit = *(int *)invalue;
		break;
	case LDAP_OPT_REBIND_FN:
		/* cast needs to be updated when ldap.h gets updated */
		ld->ld_rebindproc = (LDAP_REBIND_FUNCTION *)invalue;
		break;
	case LDAP_OPT_REBIND_ARG:
		ld->ld_rebind_extra_arg = invalue;
		break;
	case LDAP_OPT_REFERRALS:
		if (invalue != LDAP_OPT_ON && invalue != LDAP_OPT_OFF) {
#ifdef _REENTRANT
			UNLOCK_LDAP(ld);
#endif
			return (-1);
		}
		ld->ld_follow_referral = invalue ? 1 : 0;
		break;
	case LDAP_OPT_RESTART:
		if (invalue != LDAP_OPT_ON && invalue != LDAP_OPT_OFF) {
#ifdef _REENTRANT
			UNLOCK_LDAP(ld);
#endif
			return (-1);
		}
		ld->ld_restart = invalue ? 1 : 0;
		break;
	case LDAP_OPT_PROTOCOL_VERSION:
		if (*(int *)invalue < LDAP_VERSION1 ||
			*(int *)invalue > LDAP_VERSION3) {
#ifdef _REENTRANT
			UNLOCK_LDAP(ld);
#endif
			return (-1);
		}
		ld->ld_version = *(int *)invalue;
		break;
	case LDAP_OPT_SERVER_CONTROLS:
		if (ld->ld_srvctrls != NULL) {
			ldap_controls_free(ld->ld_srvctrls);
		}
		ld->ld_srvctrls = NULL;
		if (invalue != NULL)
			ld->ld_srvctrls = ldap_controls_dup(invalue);
		break;
	case LDAP_OPT_CLIENT_CONTROLS:
		if (ld->ld_cltctrls != NULL) {
			ldap_controls_free(ld->ld_cltctrls);
		}
		ld->ld_cltctrls = NULL;
		if (invalue != NULL)
			ld->ld_cltctrls = ldap_controls_dup(invalue);
		break;
	case LDAP_OPT_HOST_NAME:
		if (ld->ld_host != NULL) {
			free(ld->ld_host);
		}
		ld->ld_host = NULL;
		if ((char *)invalue != NULL)
			ld->ld_host = strdup((char *)invalue);
		break;
	case LDAP_OPT_ERROR_NUMBER:
		break;
	case LDAP_OPT_ERROR_STRING:
		break;
	case LDAP_OPT_MATCHED_DN:
		if (ld->ld_matched)
			free(ld->ld_matched);
		ld->ld_matched = NULL;
		if ((char *)invalue != NULL)
			ld->ld_matched = strdup((char *)invalue);
		break;
	case LDAP_X_OPT_CONNECT_TIMEOUT:
		ld->ld_connect_timeout = *((int *)invalue);
		break;
	default:
#ifdef _REENTRANT
		UNLOCK_LDAP(ld);
#endif
		return (-1);
	}
#ifdef _REENTRANT
	UNLOCK_LDAP(ld);
#endif
	return (0);
}
