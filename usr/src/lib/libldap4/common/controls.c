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

static int ldap_control_copy_contents(LDAPControl *, LDAPControl *);

void ldap_control_free (LDAPControl *ctrl)
{
	if (ctrl != NULL){
		if (ctrl->ldctl_oid)
			free (ctrl->ldctl_oid);
		if (ctrl->ldctl_value.bv_val != NULL)
			free (ctrl->ldctl_value.bv_val);
		free ((char *)ctrl);
	}
	return;
}

void ldap_controls_free (LDAPControl **ctrls)
{
	int i;

	if (ctrls == NULL)
		return;
	
	for (i = 0; ctrls[i] != NULL; i++){
		ldap_control_free(ctrls[i]);
	}
	free((char *)ctrls);
}

LDAPControl * ldap_control_dup(LDAPControl *ctrl)
{
	LDAPControl *newctrl;

	if ((newctrl = (LDAPControl *)calloc(1, sizeof(LDAPControl))) == NULL)
		return (NULL);

	if (ldap_control_copy_contents(newctrl, ctrl) != LDAP_SUCCESS) {
		free(newctrl);
		return (NULL);
	}

	return(newctrl);
}


static int ldap_control_copy_contents(LDAPControl *ctrl_dst,
LDAPControl *ctrl_src)
{
	size_t  len;

	if (NULL == ctrl_dst || NULL == ctrl_src) {
		return (LDAP_PARAM_ERROR);
	}

	ctrl_dst->ldctl_iscritical = ctrl_src->ldctl_iscritical;

	/* fill in the fields of this new control */
	if ((ctrl_dst->ldctl_oid = strdup(ctrl_src->ldctl_oid)) == NULL) {
		return (LDAP_NO_MEMORY);
	}

	len = (size_t)(ctrl_src->ldctl_value).bv_len;
	if (ctrl_src->ldctl_value.bv_val == NULL || len <= 0) {
		ctrl_dst->ldctl_value.bv_len = 0;
		ctrl_dst->ldctl_value.bv_val = NULL;
	} else {
		ctrl_dst->ldctl_value.bv_len = len;
		if ((ctrl_dst->ldctl_value.bv_val = malloc(len))
			== NULL) {
			free(ctrl_dst->ldctl_oid);
			return (LDAP_NO_MEMORY);
		}
		SAFEMEMCPY(ctrl_dst->ldctl_value.bv_val,
			ctrl_src->ldctl_value.bv_val, len);
	}

	return (LDAP_SUCCESS);
}


LDAPControl ** ldap_controls_dup(LDAPControl ** ctrls)
{
	int i;
	LDAPControl **newctrls;
	
	for (i = 0; ctrls[i] != NULL; i++);
	newctrls = (LDAPControl **)calloc(i+1, sizeof(LDAPControl*));
	if (newctrls == NULL) {
		return (NULL);
	}
	
	for (i = 0; ctrls[i] != NULL; i++) {
		newctrls[i] = ldap_control_dup(ctrls[i]);
		if (newctrls[i] == NULL) {
			ldap_controls_free(newctrls);
			return (NULL);
		}
	}
	return (newctrls);
}

int ldap_controls_code (BerElement *ber, LDAPControl **ctrls)
{
	int i, rc;

	if (ctrls && ctrls[0]){
		rc = ber_printf(ber, "t{", LDAP_TAG_CONTROL_LIST);
		if (rc == -1){
			ber_free(ber, 1);
			return(LDAP_ENCODING_ERROR);
		}
		
		for (i = 0; ctrls[i] != NULL; i++){
			rc = ber_printf(ber, "{s", ctrls[i]->ldctl_oid);
			if (rc == -1){
				ber_free(ber, 1);
				return(LDAP_ENCODING_ERROR);
			}
			if (ctrls[i]->ldctl_iscritical){
				rc = ber_printf(ber, "b",  ctrls[i]->ldctl_iscritical);
				if (rc == -1){
					ber_free(ber, 1);
					return(LDAP_ENCODING_ERROR);
				}
			}
			
			if (ctrls[i]->ldctl_value.bv_val)
				rc = ber_printf(ber, "o}", ctrls[i]->ldctl_value.bv_val, ctrls[i]->ldctl_value.bv_len);
			else
				rc = ber_printf(ber, "}");
			if (rc == -1){
				ber_free(ber, 1);
				return(LDAP_ENCODING_ERROR);
			}
		}

		rc = ber_printf(ber, "}");
		if (rc == -1){
			ber_free(ber, 1);
			return(LDAP_ENCODING_ERROR);
		}
	}
	return (LDAP_SUCCESS);
}

/* Decode the sequence of control from the ber, return a NULL terminated list of LDAPControl* */
LDAPControl ** ldap_controls_decode(BerElement *ber, int *errcode) 
{
	LDAPControl ** ctrls = NULL;
	
	char *opaque;
	unsigned int tag, len;
	int i = 0, count = 0;

	BerElement tmpber = *ber;

	for (tag = ber_first_element(&tmpber, &len, &opaque);
		 tag != LBER_DEFAULT;
		 tag = ber_next_element(&tmpber, &len, opaque )) {
		count ++;
		ber_skip_tag(&tmpber, &len);
	}
	

	if ((ctrls = (LDAPControl **)calloc(count + 1, sizeof(LDAPControl *))) == NULL){
		*errcode = LDAP_NO_MEMORY;
		return(NULL);
	}
	
	for (tag = ber_first_element(ber, &len, &opaque );
		 tag != LBER_DEFAULT;
		 tag = ber_next_element (ber, &len, opaque )) {
		LDAPControl *aCtrl;
		unsigned int ttag, tlen;
		
		if ((aCtrl = (LDAPControl *)calloc(1, sizeof(LDAPControl))) == NULL) {
			*errcode = LDAP_NO_MEMORY;
			ldap_controls_free(ctrls);
			return (NULL);
		}
		if (ber_scanf(ber, "{a", &aCtrl->ldctl_oid) == LBER_ERROR){
			*errcode = LDAP_PROTOCOL_ERROR;
			free(aCtrl);
			ldap_controls_free(ctrls);
			return (NULL);
		}
		aCtrl->ldctl_iscritical = 0;
		ttag = ber_peek_tag(ber, &tlen);
		if (ttag == 0x01) { /* Boolean : criticality */
			if (ber_scanf(ber, "b", &aCtrl->ldctl_iscritical) == LBER_ERROR){
				*errcode = LDAP_PROTOCOL_ERROR;
				free(aCtrl);
				ldap_controls_free(ctrls);
				return (NULL);
			}
			ttag = ber_peek_tag(ber, &tlen);
		}
		if (ttag == 0x04) { /* Octet string : value (it's optional)*/
			if (ber_scanf(ber, "o", &aCtrl->ldctl_value) == LBER_ERROR){
				*errcode = LDAP_PROTOCOL_ERROR;
				free(aCtrl);
				ldap_controls_free(ctrls);
				return (NULL);
			}
			
		} else if (ttag != LBER_DEFAULT){
			*errcode = LDAP_PROTOCOL_ERROR;
			free(aCtrl);
			ldap_controls_free(ctrls);
			return (NULL);
		}
		
		if (ber_scanf(ber, "}") == LBER_ERROR){
			*errcode = LDAP_PROTOCOL_ERROR;
			free(aCtrl);
			ldap_controls_free(ctrls);
			return (NULL);
		}
		/* add aCtrl in ctrls */
		ctrls[i++] = aCtrl;
	}
	return (ctrls);
}

/* build an allocated LDAPv3 control.  Returns an LDAP error code. */
int ldap_build_control(char *oid, BerElement *ber, int freeber,
char iscritical, LDAPControl **ctrlp)
{
	int		rc;
	struct berval	*bvp;

	if (ber == NULL) {
		bvp = NULL;
	} else {
		/* allocate struct berval with contents of the BER encoding */
		rc = ber_flatten(ber, &bvp);
		if (freeber) {
			ber_free(ber, 1);
		}
		if (rc == -1) {
			return (LDAP_NO_MEMORY);
		}
	}

	/* allocate the new control structure */
	if ((*ctrlp = (LDAPControl *)calloc(1, sizeof (LDAPControl)))
	    == NULL) {
		if (bvp != NULL) {
			ber_bvfree(bvp);
		}
		return (LDAP_NO_MEMORY);
	}

	/* fill in the fields of this new control */
	(*ctrlp)->ldctl_iscritical = iscritical;
	if (((*ctrlp)->ldctl_oid = strdup(oid)) == NULL) {
		free(*ctrlp);
		*ctrlp = NULL;
		if (bvp != NULL) {
			ber_bvfree(bvp);
		}
		return (LDAP_NO_MEMORY);
	}

	if (bvp == NULL) {
		(*ctrlp)->ldctl_value.bv_len = 0;
		(*ctrlp)->ldctl_value.bv_val = NULL;
	} else {
		(*ctrlp)->ldctl_value = *bvp;	/* struct copy */
		free(bvp);	/* free container, not contents! */
	}

	return (LDAP_SUCCESS);
}
