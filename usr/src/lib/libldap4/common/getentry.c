/*
 * Portions Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *  Copyright (c) 1990 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  getentry.c
 */

#ifndef lint 
static char copyright[] = "@(#) Copyright (c) 1990 Regents of the University of Michigan.\nAll rights reserved.\n";
#endif

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#ifdef MACOS
#include <stdlib.h>
#include "macos.h"
#else /* MACOS */
#if defined( DOS ) || defined( _WIN32 )
#include <malloc.h>
#include "msdos.h"
#else /* DOS */
#include <sys/types.h>
#include <sys/socket.h>
#endif /* DOS */
#endif /* MACOS */

#include "lber.h"
#include "ldap.h"
#include "ldap-private.h"

/* ARGSUSED */
LDAPMessage *
ldap_first_entry( LDAP *ld, LDAPMessage *res )
{
	LDAPMessage *msg = res;

	while ( msg != NULLMSG) {
		if (msg->lm_msgtype == LDAP_RES_SEARCH_ENTRY)
			break;
		msg = msg->lm_chain;
	}
	return (msg);
}

/* ARGSUSED */
LDAPMessage *ldap_next_entry( LDAP *ld, LDAPMessage *entry )
{
	LDAPMessage *msg;
	
	if ( entry == NULLMSG)
		return( NULLMSG );

	msg = entry->lm_chain;
	while(msg != NULLMSG){
		if (msg->lm_msgtype == LDAP_RES_SEARCH_ENTRY)
			break;
		msg = msg->lm_chain;
	}
	
	return( msg );
}

/* ARGSUSED */
int
ldap_count_entries( LDAP *ld, LDAPMessage *res )
{
	int	i;

	for ( i = 0; res != NULL; res = res->lm_chain )
		if (res->lm_msgtype == LDAP_RES_SEARCH_ENTRY) 
			i++;

	return( i );
}
