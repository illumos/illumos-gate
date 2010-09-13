/*
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>

#ifdef MACOS
#include "macos.h"
#endif /* MACOS */

#if !defined( MACOS ) && !defined( DOS )
#include <sys/types.h>
#include <sys/socket.h>
#endif

#include "lber.h"
#include "ldap.h"
#include "ldap-int.h"

int ldap_create_page_control(LDAP *ld, unsigned int pagesize, struct berval *cookie, char isCritical, LDAPControl **output)
{
	BerElement *ber;
	int rc;

	if (NULL == ld || NULL == output)
		return (LDAP_PARAM_ERROR);

	if ((ber = ber_alloc_t(LBER_USE_DER)) == NULLBER){
		return (LDAP_NO_MEMORY);
	}
	
	if (ber_printf(ber, "{io}", pagesize,
			(cookie && cookie->bv_val) ? cookie->bv_val : "",
			(cookie && cookie->bv_val) ? cookie->bv_len : 0)
				 == LBER_ERROR) {
		ber_free(ber, 1);
		return (LDAP_ENCODING_ERROR);
	}

	rc = nsldapi_build_control(LDAP_CONTROL_SIMPLE_PAGE, ber, 1, isCritical,
		output);

	ld->ld_errno = rc;
	return (rc);
}

int ldap_parse_page_control(LDAP *ld, LDAPControl **controls, unsigned int *totalcount, struct berval **cookie)
{
	int i, rc;
	BerElement *theBer;
	LDAPControl *listCtrlp;
	
	for (i = 0; controls[i] != NULL; i++){
		if (strcmp(controls[i]->ldctl_oid, "1.2.840.113556.1.4.319") == 0) {
			listCtrlp = controls[i];
			if ((theBer = ber_init(&listCtrlp->ldctl_value)) == NULLBER){
				return (LDAP_NO_MEMORY);
			}
			if ((rc = ber_scanf(theBer, "{iO}", totalcount, cookie)) == LBER_ERROR){
				ber_free(theBer, 1);
				return (LDAP_DECODING_ERROR);
			}
			ber_free(theBer, 1);
			return (LDAP_SUCCESS);
		}
	}
	return (LDAP_CONTROL_NOT_FOUND);
}

