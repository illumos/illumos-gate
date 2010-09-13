/*
 * Portions Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *  Copyright (c) 1993 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  kbind.c
 */

#ifndef lint 
static char copyright[] = "@(#) Copyright (c) 1993 Regents of the University of Michigan.\nAll rights reserved.\n";
#endif

#ifdef KERBEROS

#include <stdio.h>
#include <string.h>

#ifdef MACOS
#include <stdlib.h>
#include "macos.h"
#else /* MACOS */
#ifdef DOS
#include "msdos.h"
#endif /* DOS */
#include <krb.h>
#include <stdlib.h>
#if !defined(DOS) && !defined( _WIN32 )
#include <sys/types.h>
#endif /* !DOS && !_WIN32 */
#include <sys/time.h>
#include <sys/socket.h>
#endif /* MACOS */

#include "lber.h"
#include "ldap.h"
#include "ldap-private.h"
#include "ldap-int.h"



/*
 * ldap_kerberos_bind1 - initiate a bind to the ldap server using
 * kerberos authentication.  The dn is supplied.  It is assumed the user
 * already has a valid ticket granting ticket.  The msgid of the
 * request is returned on success (suitable for passing to ldap_result()),
 * -1 is returned if there's trouble.
 *
 * Example:
 *	ldap_kerberos_bind1( ld, "cn=manager, o=university of michigan, c=us" )
 */
int
ldap_kerberos_bind1( LDAP *ld, char *dn )
{
	BerElement	*ber;
	char		*cred;
	int		rc, credlen;
	char		*get_kerberosv4_credentials();
#ifdef STR_TRANSLATION
	int		str_translation_on;
#endif /* STR_TRANSLATION */

	/*
	 * The bind request looks like this:
	 *	BindRequest ::= SEQUENCE {
	 *		version		INTEGER,
	 *		name		DistinguishedName,
	 *		authentication	CHOICE {
	 *			krbv42ldap	[1] OCTET STRING
	 *			krbv42dsa	[2] OCTET STRING
	 *		}
	 *	}
	 * all wrapped up in an LDAPMessage sequence.
	 */

#if defined( SUN ) && defined( _REENTRANT )
	int rv;

        LOCK_LDAP(ld);
#endif
	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 186, "ldap_kerberos_bind1\n"), 0, 0, 0 );

	if ( dn == NULL )
		dn = "";

	if ( (cred = get_kerberosv4_credentials( ld, dn, "ldapserver",
	    &credlen )) == NULL ) {
#if defined( SUN ) && defined( _REENTRANT )
		UNLOCK_LDAP(ld);
#endif
		return( -1 );	/* ld_errno should already be set */
	}

	/* create a message to send */
	if ( (ber = alloc_ber_with_options( ld )) == NULLBER ) {
		free( cred );
#if defined( SUN ) && defined( _REENTRANT )
		UNLOCK_LDAP(ld);
#endif
		return( -1 );
	}

#ifdef STR_TRANSLATION
	if (( str_translation_on = (( ber->ber_options &
	    LBER_TRANSLATE_STRINGS ) != 0 ))) {	/* turn translation off */
		ber->ber_options &= ~LBER_TRANSLATE_STRINGS;
	}
#endif /* STR_TRANSLATION */

	/* fill it in */
	rc = ber_printf( ber, "{it{isto}}", ++ld->ld_msgid, LDAP_REQ_BIND,
	    ld->ld_version, dn, LDAP_AUTH_KRBV41, cred, credlen );

#ifdef STR_TRANSLATION
	if ( str_translation_on ) {	/* restore translation */
		ber->ber_options |= LBER_TRANSLATE_STRINGS;
	}
#endif /* STR_TRANSLATION */

	if ( rc == -1 ) {
		free( cred );
		ber_free( ber, 1 );
		ld->ld_errno = LDAP_ENCODING_ERROR;
#if defined( SUN ) && defined( _REENTRANT )
		UNLOCK_LDAP(ld);
#endif
		return( -1 );
	}

	free( cred );

#ifndef NO_CACHE
	if ( ld->ld_cache != NULL ) {
		ldap_flush_cache( ld );
	}
#endif /* !NO_CACHE */

	/* send the message */
#if defined( SUN ) && defined( _REENTRANT )
	rv = send_initial_request( ld, LDAP_REQ_BIND, dn, ber );
        UNLOCK_LDAP(ld);
	return ( rv );
#else
	return ( send_initial_request( ld, LDAP_REQ_BIND, dn, ber ));
#endif
}

int
ldap_kerberos_bind1_s( LDAP *ld, char *dn )
{
	int		msgid;
	LDAPMessage	*res;

	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 187, "ldap_kerberos_bind1_s\n"), 0, 0, 0 );

	/* initiate the bind */
	if ( (msgid = ldap_kerberos_bind1( ld, dn )) == -1 )
		return( ld->ld_errno );

	/* wait for a result */
	if ( ldap_result( ld, ld->ld_msgid, 1, (struct timeval *) 0, &res )
	    == -1 ) {
		return( ld->ld_errno );	/* ldap_result sets ld_errno */
	}

	return( ldap_result2error( ld, res, 1 ) );
}

/*
 * ldap_kerberos_bind2 - initiate a bind to the X.500 server using
 * kerberos authentication.  The dn is supplied.  It is assumed the user
 * already has a valid ticket granting ticket.  The msgid of the
 * request is returned on success (suitable for passing to ldap_result()),
 * -1 is returned if there's trouble.
 *
 * Example:
 *	ldap_kerberos_bind2( ld, "cn=manager, o=university of michigan, c=us" )
 */
int
ldap_kerberos_bind2( LDAP *ld, char *dn )
{
	BerElement	*ber;
	char		*cred;
	int		rc, credlen;
	char		*get_kerberosv4_credentials();
#ifdef STR_TRANSLATION
	int		str_translation_on;
#endif /* STR_TRANSLATION */

#if defined( SUN ) && defined( _REENTRANT )
	int rv;

        LOCK_LDAP(ld);
#endif
	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 188, "ldap_kerberos_bind2\n"), 0, 0, 0 );

	if ( dn == NULL )
		dn = "";

	if ( (cred = get_kerberosv4_credentials( ld, dn, "x500dsa", &credlen ))
	    == NULL ) {
#if defined( SUN ) && defined( _REENTRANT )
		UNLOCK_LDAP(ld);
#endif
		return( -1 );	/* ld_errno should already be set */
	}

	/* create a message to send */
	if ( (ber = alloc_ber_with_options( ld )) == NULLBER ) {
		free( cred );
#if defined( SUN ) && defined( _REENTRANT )
		UNLOCK_LDAP(ld);
#endif
		return( -1 );
	}

#ifdef STR_TRANSLATION
	if (( str_translation_on = (( ber->ber_options &
	    LBER_TRANSLATE_STRINGS ) != 0 ))) {	/* turn translation off */
		ber->ber_options &= ~LBER_TRANSLATE_STRINGS;
	}
#endif /* STR_TRANSLATION */

	/* fill it in */
	rc = ber_printf( ber, "{it{isto}}", ++ld->ld_msgid, LDAP_REQ_BIND,
	    ld->ld_version, dn, LDAP_AUTH_KRBV42, cred, credlen );


#ifdef STR_TRANSLATION
	if ( str_translation_on ) {	/* restore translation */
		ber->ber_options |= LBER_TRANSLATE_STRINGS;
	}
#endif /* STR_TRANSLATION */

	free( cred );

	if ( rc == -1 ) {
		ber_free( ber, 1 );
		ld->ld_errno = LDAP_ENCODING_ERROR;
#if defined( SUN ) && defined( _REENTRANT )
		UNLOCK_LDAP(ld);
#endif
		return( -1 );
	}

	/* send the message */
#if defined( SUN ) && defined( _REENTRANT )
	rv = send_initial_request( ld, LDAP_REQ_BIND, dn, ber );
        UNLOCK_LDAP(ld);
	return ( rv );
#endif
	return ( send_initial_request( ld, LDAP_REQ_BIND, dn, ber ));
}

/* synchronous bind to DSA using kerberos */
int
ldap_kerberos_bind2_s( LDAP *ld, char *dn )
{
	int		msgid;
	LDAPMessage	*res;

	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 189, "ldap_kerberos_bind2_s\n"), 0, 0, 0 );

	/* initiate the bind */
	if ( (msgid = ldap_kerberos_bind2( ld, dn )) == -1 )
		return( ld->ld_errno );

	/* wait for a result */
	if ( ldap_result( ld, ld->ld_msgid, 1, (struct timeval *) 0, &res )
	    == -1 ) {
		return( ld->ld_errno );	/* ldap_result sets ld_errno */
	}

	return( ldap_result2error( ld, res, 1 ) );
}

/* synchronous bind to ldap and DSA using kerberos */
int
ldap_kerberos_bind_s( LDAP *ld, char *dn )
{
	int	err;

	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 190, "ldap_kerberos_bind_s\n"), 0, 0, 0 );

	if ( (err = ldap_kerberos_bind1_s( ld, dn )) != LDAP_SUCCESS )
		return( err );

	return( ldap_kerberos_bind2_s( ld, dn ) );
}


#ifndef AUTHMAN
/*
 * get_kerberosv4_credentials - obtain kerberos v4 credentials for ldap.
 * The dn of the entry to which to bind is supplied.  It's assumed the
 * user already has a tgt.
 */

char *
get_kerberosv4_credentials( LDAP *ld, char *who, char *service, int *len )
{
	KTEXT_ST	ktxt;
	int		err;
	char		realm[REALM_SZ], *cred, *krbinstance;

	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 191, "get_kerberosv4_credentials\n"), 0, 0, 0 );

	if ( (err = krb_get_tf_realm( tkt_string(), realm )) != KSUCCESS ) {
#ifndef NO_USERINTERFACE
		fprintf( stderr, "krb_get_tf_realm failed (%s)\n",
		    krb_err_txt[err] );
#endif /* NO_USERINTERFACE */
		ld->ld_errno = LDAP_INVALID_CREDENTIALS;
		return( NULL );
	}

#ifdef LDAP_REFERRALS
	krbinstance = ld->ld_defconn->lconn_krbinstance;
#else /* LDAP_REFERRALS */
	krbinstance = ld->ld_host;
#endif /* LDAP_REFERRALS */

	if ( (err = krb_mk_req( &ktxt, service, krbinstance, realm, 0 ))
	    != KSUCCESS ) {
#ifndef NO_USERINTERFACE
		fprintf( stderr, "krb_mk_req failed (%s)\n", krb_err_txt[err] );
#endif /* NO_USERINTERFACE */
		ld->ld_errno = LDAP_INVALID_CREDENTIALS;
		return( NULL );
	}

	if ( ( cred = malloc( ktxt.length )) == NULL ) {
		ld->ld_errno = LDAP_NO_MEMORY;
		return( NULL );
	}

	*len = ktxt.length;
	memcpy( cred, ktxt.dat, ktxt.length );

	return( cred );
}

#endif /* !AUTHMAN */
#endif /* KERBEROS */
