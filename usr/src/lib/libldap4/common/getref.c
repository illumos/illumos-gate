/*
 *
 * Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 *
 * Comments:   
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include "lber.h"
#include "ldap.h"
#include "ldap-private.h"
#include "ldap-int.h"

LDAPMessage * ldap_first_reference(LDAP *ld, LDAPMessage *res)
{
	LDAPMessage *msg = res;

	while ( msg != NULLMSG) {
		if (msg->lm_msgtype == LDAP_RES_SEARCH_REFERENCE)
			break;
		msg = msg->lm_chain;
	}
	return (msg);
}

LDAPMessage * ldap_next_reference(LDAP *ld, LDAPMessage *entry)
{
	LDAPMessage *msg;
	
	if ( entry == NULLMSG)
		return( NULLMSG );

	msg = entry->lm_chain;
	while(msg != NULLMSG){
		if (msg->lm_msgtype == LDAP_RES_SEARCH_REFERENCE)
			break;
		msg = msg->lm_chain;
	}
	
	return( msg );
}

int
ldap_count_references( LDAP *ld, LDAPMessage *res )
{
	int	i;

	for ( i = 0; res != NULL; res = res->lm_chain )
		if (res->lm_msgtype == LDAP_RES_SEARCH_REFERENCE) 
			i++;

	return( i );
}

char ** ldap_get_reference_urls(LDAP *ld, LDAPMessage *res)
{
	BerElement tmp;
	char **urls = NULL;
	
	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 1274, "ldap_get_reference_urls\n"), 0, 0, 0 );
	
	if (res == NULL){
		ld->ld_errno = LDAP_PARAM_ERROR;
		return (NULL);
	}
	tmp = *res->lm_ber; /* struct copy */
	if ( ber_scanf( &tmp, "{v}", &urls) == LBER_ERROR){
		ld->ld_errno = LDAP_DECODING_ERROR;
		return (NULL);
	}
	return (urls);
}
