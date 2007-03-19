/*
 *
 * Copyright 1999 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 *
 * Comments:
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>

#include "lber.h"
#include "ldap.h"
#include "ldap-private.h"
#include "ldap-int.h"


int ldap_create_virtuallist_control(LDAP *ld, LDAPVirtualList *ldvlistp,
	LDAPControl **ctrlp)
{
	BerElement *ber;
	int rc;

	if (NULL == ld)
		return (LDAP_PARAM_ERROR);

	if (NULL == ctrlp || NULL == ldvlistp)
		return (LDAP_PARAM_ERROR);

	if ((ber = alloc_ber_with_options(ld)) == NULLBER) {
		ld->ld_errno = LDAP_NO_MEMORY;
		return (LDAP_NO_MEMORY);
	}

	if (ber_printf(ber, "{ii", ldvlistp->ldvlist_before_count,
		ldvlistp->ldvlist_after_count) == -1) {
		ld->ld_errno = LDAP_ENCODING_ERROR;
		ber_free(ber, 1);
		return (LDAP_ENCODING_ERROR);
	}

	if (NULL == ldvlistp->ldvlist_attrvalue) {
		if (ber_printf(ber, "t{ii}}", LDAP_TAG_VLV_BY_INDEX,
			ldvlistp->ldvlist_index,
			ldvlistp->ldvlist_size) == -1) {
			ld->ld_errno = LDAP_ENCODING_ERROR;
			ber_free(ber, 1);
			return (LDAP_ENCODING_ERROR);
		}
	} else {
		if (ber_printf(ber, "to}", LDAP_TAG_VLV_BY_VALUE,
			ldvlistp->ldvlist_attrvalue,
			strlen(ldvlistp->ldvlist_attrvalue)) == -1) {
			ld->ld_errno = LDAP_ENCODING_ERROR;
			ber_free(ber, 1);
			return (LDAP_ENCODING_ERROR);
		}
	}

	rc = ldap_build_control(LDAP_CONTROL_VLVREQUEST, ber, 1, 1, ctrlp);
	ld->ld_errno = rc;
	return (rc);
}


int ldap_parse_virtuallist_control(LDAP *ld, LDAPControl **ctrls,
	unsigned long *target_posp, unsigned long *list_sizep, int *errcodep)
{
	BerElement *ber;
	int i, foundListControl;
	LDAPControl *listCtrlp;

	if (NULL == ld)
		return (LDAP_PARAM_ERROR);

	/* only ldapv3 or higher can do virtual lists. */
	if (ld->ld_version != LDAP_VERSION3) {
		ld->ld_errno = LDAP_NOT_SUPPORTED;
		return (LDAP_NOT_SUPPORTED);
	}

	/* find the listControl in the list of controls if it exists */
	if (ctrls == NULL) {
		ld->ld_errno = LDAP_NOT_SUPPORTED;
		return (LDAP_NOT_SUPPORTED);
	}

	foundListControl = 0;
	for (i = 0; ((ctrls[i] != NULL) && (!foundListControl)); i++) {
		foundListControl = !(strcmp(ctrls[i]->ldctl_oid,
			LDAP_CONTROL_VLVRESPONSE));
	}
	if (!foundListControl) {
		ld->ld_errno = LDAP_CONTROL_NOT_FOUND;
		return (LDAP_CONTROL_NOT_FOUND);
	} else {
		/* let local var point to the listControl */
		listCtrlp = ctrls[i-1];
	}

	/* allocate a Ber element with the contents of the list_control's */
	/* struct berval */
	if ((ber = ber_init(&listCtrlp->ldctl_value)) == NULL) {
		ld->ld_errno = LDAP_NO_MEMORY;
		return (LDAP_NO_MEMORY);
	}

	/* decode the result from the Berelement */
	if (LBER_ERROR == ber_scanf(ber, "{iie}", target_posp, list_sizep,
		errcodep)) {
		ld->ld_errno = LDAP_DECODING_ERROR;
		ber_free(ber, 1);
		return (LDAP_DECODING_ERROR);
	}

	/* the ber encoding is no longer needed */
	ber_free(ber, 1);

	return (LDAP_SUCCESS);
}
