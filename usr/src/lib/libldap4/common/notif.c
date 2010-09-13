/*
 *
 * Copyright 13/01/98 Sun Microsystems, Inc. All Rights Reserved
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

LDAPMessage *ldap_first_notif(LDAP *ld)
{
	return ld->ld_notifs;
}

LDAPMessage *ldap_next_notif(LDAP *ld, LDAPMessage *current)
{
	if ( current == NULLMSG )
		return NULLMSG;
	else
		return current->lm_next;
}

int ldap_reset_notif(LDAP *ld, int freeit)
{
	LDAPMessage *L_n=NULLMSG;
	LDAPMessage *L_q=NULLMSG;

	if ( freeit )
	{
		for (L_n=ld->ld_notifs; L_n!=NULLMSG; L_n=L_n->lm_next)
		{
			if ( L_n->lm_next != NULLMSG )
			{
				L_q = L_n->lm_next;
				ldap_msgfree(L_n);
				L_n = L_q;
			}
			else
			{
				ldap_msgfree(L_n);
				break;
			}
		}
	}
	ld->ld_notifs = NULLMSG;

	return (LDAP_SUCCESS);
}

int ldap_remove_notif(LDAP *ld, LDAPMessage *notif, int freeit)
{
	LDAPMessage *L_n=NULLMSG, *L_q=NULLMSG;

	for ( L_n=ld->ld_notifs; L_n!=NULLMSG; L_n=L_n->lm_next)
	{
		if ( L_n == notif)
		{
			if ( L_q == NULLMSG )
				ld->ld_notifs = L_n->lm_next;
			else
				L_q->lm_next = L_n->lm_next;

			L_n->lm_next = NULLMSG;
			if ( freeit )
				ldap_msgfree(L_n);

			break;
		}
		L_q = L_n;
	}
	return (LDAP_SUCCESS);
}

/* Add in tail */
int ldap_add_notif(LDAP *ld, LDAPMessage *notif)
{
	LDAPMessage *L_n=NULLMSG, *L_q=NULLMSG;

	for ( L_n=ld->ld_notifs; L_n!=NULLMSG; L_n=L_n->lm_next)
		L_q = L_n;

	notif->lm_next = NULLMSG;
	if ( L_q == NULLMSG )
		ld->ld_notifs = notif;
	else
		L_q->lm_next = notif;

	return (LDAP_SUCCESS);
}	

/* Add in head */
int ldap_insert_notif(LDAP *ld, LDAPMessage *notif)
{

	notif->lm_next = ld->ld_notifs;
	ld->ld_notifs = notif;

	return (LDAP_SUCCESS);
}

