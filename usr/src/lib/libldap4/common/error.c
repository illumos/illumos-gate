/*
 * Portions Copyright 1999 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include <stdlib.h> /* free() for Solaris */
#ifdef MACOS
#include <stdlib.h>
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
#include "ldap-int.h"

struct ldaperror {
	int	e_code;
	char	*e_reason;
};

static struct ldaperror ldap_errlist[] = {
#ifdef SUN
	LDAP_SUCCESS, 			0,
	LDAP_OPERATIONS_ERROR, 		0,
	LDAP_PROTOCOL_ERROR, 		0,
	LDAP_TIMELIMIT_EXCEEDED,	0,
	LDAP_SIZELIMIT_EXCEEDED, 	0,
	LDAP_COMPARE_FALSE, 		0,
	LDAP_COMPARE_TRUE, 		0,
	LDAP_AUTH_METHOD_NOT_SUPPORTED, 0,
	LDAP_STRONG_AUTH_REQUIRED, 	0,
	LDAP_PARTIAL_RESULTS, 		0,
/* new with ldapv3 */
	LDAP_REFERRAL,			0,
	LDAP_ADMINLIMIT_EXCEEDED,	0,
	LDAP_UNAVAILABLE_CRITICAL_EXTENSION, 	0,
	LDAP_CONFIDENTIALITY_REQUIRED,	0,
/* end of new */
	LDAP_NO_SUCH_ATTRIBUTE, 	0,
	LDAP_UNDEFINED_TYPE, 		0,
	LDAP_INAPPROPRIATE_MATCHING, 	0,
	LDAP_CONSTRAINT_VIOLATION, 	0,
	LDAP_TYPE_OR_VALUE_EXISTS, 	0,
	LDAP_INVALID_SYNTAX, 		0,
	LDAP_NO_SUCH_OBJECT, 		0,
	LDAP_ALIAS_PROBLEM, 		0,
	LDAP_INVALID_DN_SYNTAX,		0,
	LDAP_IS_LEAF, 			0,
	LDAP_ALIAS_DEREF_PROBLEM, 	0,
	LDAP_INAPPROPRIATE_AUTH, 	0,
	LDAP_INVALID_CREDENTIALS, 	0,
	LDAP_INSUFFICIENT_ACCESS, 	0,
	LDAP_BUSY, 			0,
	LDAP_UNAVAILABLE, 		0,
	LDAP_UNWILLING_TO_PERFORM, 	0,
	LDAP_LOOP_DETECT, 		0,
	LDAP_NAMING_VIOLATION, 		0,
	LDAP_OBJECT_CLASS_VIOLATION, 	0,
	LDAP_NOT_ALLOWED_ON_NONLEAF, 	0,
	LDAP_NOT_ALLOWED_ON_RDN, 	0,
	LDAP_ALREADY_EXISTS, 		0,
	LDAP_NO_OBJECT_CLASS_MODS, 	0,
	LDAP_RESULTS_TOO_LARGE,		0,
/* new with ldapv3 */
	LDAP_AFFECTS_MULTIPLE_DSAS, 0,
/* end of new */
	LDAP_OTHER, 			0,
	LDAP_SERVER_DOWN,		0,
	LDAP_LOCAL_ERROR,		0,
	LDAP_ENCODING_ERROR,		0,
	LDAP_DECODING_ERROR,		0,
	LDAP_TIMEOUT,			0,
	LDAP_AUTH_UNKNOWN,		0,
	LDAP_FILTER_ERROR,		0,
	LDAP_USER_CANCELLED,		0,
	LDAP_PARAM_ERROR,		0,
	LDAP_NO_MEMORY,			0,
/* new with ldapv3 */
	LDAP_CONNECT_ERROR,		0,
	LDAP_NOT_SUPPORTED,		0,
	LDAP_CONTROL_NOT_FOUND,	0,
	LDAP_NO_RESULTS_RETURNED,	0,
	LDAP_MORE_RESULTS_TO_RETURN,	0,
	LDAP_CLIENT_LOOP,		0,
	LDAP_REFERRAL_LIMIT_EXCEEDED,	0,
/* end of new */
#else
	LDAP_SUCCESS, 			"Success",
	LDAP_OPERATIONS_ERROR, 		"Operations error",
	LDAP_PROTOCOL_ERROR, 		"Protocol error",
	LDAP_TIMELIMIT_EXCEEDED,	"Timelimit exceeded",
	LDAP_SIZELIMIT_EXCEEDED, 	"Sizelimit exceeded",
	LDAP_COMPARE_FALSE, 		"Compare false",
	LDAP_COMPARE_TRUE, 		"Compare true",
	LDAP_AUTH_METHOD_NOT_SUPPORTED, "Authentication method not supported",
	LDAP_STRONG_AUTH_REQUIRED, 	"Strong authentication required",
	LDAP_PARTIAL_RESULTS, 		"Partial results and referral received",
/* new with ldapv3 */
	LDAP_REFERRAL,			"Referral received",
	LDAP_ADMINLIMIT_EXCEEDED,	"Admin. limit exceeded",
	LDAP_UNAVAILABLE_CRITICAL_EXTENSION, 	"Unavailable critical extension",
	LDAP_CONFIDENTIALITY_REQUIRED,	"Confidentiality required",
/* end of new */
	LDAP_NO_SUCH_ATTRIBUTE, 	"No such attribute",
	LDAP_UNDEFINED_TYPE, 		"Undefined attribute type",
	LDAP_INAPPROPRIATE_MATCHING, 	"Inappropriate matching",
	LDAP_CONSTRAINT_VIOLATION, 	"Constraint violation",
	LDAP_TYPE_OR_VALUE_EXISTS, 	"Type or value exists",
	LDAP_INVALID_SYNTAX, 		"Invalid syntax",
	LDAP_NO_SUCH_OBJECT, 		"No such object",
	LDAP_ALIAS_PROBLEM, 		"Alias problem",
	LDAP_INVALID_DN_SYNTAX,		"Invalid DN syntax",
	LDAP_IS_LEAF, 			"Object is a leaf",
	LDAP_ALIAS_DEREF_PROBLEM, 	"Alias dereferencing problem",
	LDAP_INAPPROPRIATE_AUTH, 	"Inappropriate authentication",
	LDAP_INVALID_CREDENTIALS, 	"Invalid credentials",
	LDAP_INSUFFICIENT_ACCESS, 	"Insufficient access",
	LDAP_BUSY, 			"DSA is busy",
	LDAP_UNAVAILABLE, 		"DSA is unavailable",
	LDAP_UNWILLING_TO_PERFORM, 	"DSA is unwilling to perform",
	LDAP_LOOP_DETECT, 		"Loop detected",
	LDAP_NAMING_VIOLATION, 		"Naming violation",
	LDAP_OBJECT_CLASS_VIOLATION, 	"Object class violation",
	LDAP_NOT_ALLOWED_ON_NONLEAF, 	"Operation not allowed on nonleaf",
	LDAP_NOT_ALLOWED_ON_RDN, 	"Operation not allowed on RDN",
	LDAP_ALREADY_EXISTS, 		"Already exists",
	LDAP_NO_OBJECT_CLASS_MODS, 	"Cannot modify object class",
	LDAP_RESULTS_TOO_LARGE,		"Results too large",
/* new with ldapv3 */
	LDAP_AFFECTS_MULTIPLE_DSAS, "Affects multiple DSAs",
/* end of new */
	LDAP_OTHER, 			"Unknown error",
	LDAP_SERVER_DOWN,		"Can't contact LDAP server",
	LDAP_LOCAL_ERROR,		"Local error",
	LDAP_ENCODING_ERROR,		"Encoding error",
	LDAP_DECODING_ERROR,		"Decoding error",
	LDAP_TIMEOUT,			"Timed out",
	LDAP_AUTH_UNKNOWN,		"Unknown authentication method",
	LDAP_FILTER_ERROR,		"Bad search filter",
	LDAP_USER_CANCELLED,		"User cancelled operation",
	LDAP_PARAM_ERROR,		"Bad parameter to an ldap routine",
	LDAP_NO_MEMORY,			"Out of memory",
/* new with ldapv3 */
	LDAP_CONNECT_ERROR,		"Connection error",
	LDAP_NOT_SUPPORTED,		"Not supported",
	LDAP_CONTROL_NOT_FOUND,	"Control not found",
	LDAP_NO_RESULTS_RETURNED,	"No results have been returned",
	LDAP_MORE_RESULTS_TO_RETURN,	"More results to return",
	LDAP_CLIENT_LOOP,		"Loop detected in referrals",
	LDAP_REFERRAL_LIMIT_EXCEEDED,	"Too many referrals followed",
/* end of new */
#endif
	-1, 0
};

#ifdef SUN
#pragma init	(fill_ldap_errlist)

static void fill_ldap_errlist()
{
	int i=0;
	Debug(LDAP_DEBUG_TRACE, "fill_ldap_errlist\n", 0, 0, 0 );
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 130, "Success");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 131, "Operations error");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 132, "Protocol error");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 133, "Timelimit exceeded");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 134, "Sizelimit exceeded");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 135, "Compare false");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 136, "Compare true");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 137, "Strong authentication not supported");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 138, "Strong authentication required");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 139, "Partial results and referral received");
/* new with ldapv3 */
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 1262, "Referral received");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 1263, "Admin. limit exceeded");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 1264, "Unavailable critical extension");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 1265, "Confidentiality required");
/* end of new */
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 140, "No such attribute");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 141, "Undefined attribute type");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 142, "Inappropriate matching");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 143, "Constraint violation");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 144, "Type or value exists");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 145, "Invalid syntax");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 146, "No such object");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 147, "Alias problem");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 148, "Invalid DN syntax");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 149, "Object is a leaf");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 150, "Alias dereferencing problem");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 151, "Inappropriate authentication");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 152, "Invalid credentials");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 153, "Insufficient access");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 154, "DSA is busy");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 155, "DSA is unavailable");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 156, "DSA is unwilling to perform");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 157, "Loop detected");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 158, "Naming violation");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 159, "Object class violation");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 160, "Operation not allowed on nonleaf");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 161, "Operation not allowed on RDN");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 162, "Already exists");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 163, "Cannot modify object class");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 164, "Results too large");
/* new with ldapv3 */
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 1266, "Affects multiple DSAs");
/* end of new */
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 165, "Unknown error");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 166, "Can't contact LDAP server");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 167, "Local error");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 168, "Encoding error");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 169, "Decoding error");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 170, "Timed out");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 171, "Unknown authentication method");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 172, "Bad search filter");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 173, "User cancelled operation");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 174, "Bad parameter to an ldap routine");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 175, "Out of memory");

	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 1267, "Connection error");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 1268, "Not supported");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 1269, "Control not found");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 1270, "No results have been returned");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 1271, "More results to return");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 1272, "Loop detected in referrals");
	ldap_errlist[i++].e_reason = catgets(slapdcat, 1, 1273, "Too many referrals followed");
}
#endif

char *
ldap_err2string( int err )
{
	int	i;

	Debug( LDAP_DEBUG_TRACE, "ldap_err2string\n", 0, 0, 0 );

	for ( i = 0; ldap_errlist[i].e_code != -1; i++ ) {
		if ( err == ldap_errlist[i].e_code )
			return( ldap_errlist[i].e_reason );
	}

	return( catgets(slapdcat, 1 , 165, "Unknown error") );
}

#ifndef NO_USERINTERFACE
void
ldap_perror( LDAP *ld, char *s )
{
	int	i;

	Debug( LDAP_DEBUG_TRACE, "ldap_perror\n", 0, 0, 0 );

	if ( ld == NULL ) {
		perror( s );
		return;
	}
#ifdef SUN
	/* for I18N */
	if ( ldap_errlist[0].e_reason == NULL ) {
		fill_ldap_errlist();
	} /* end if */
#endif

	for ( i = 0; ldap_errlist[i].e_code != -1; i++ ) {
		if ( ld->ld_errno == ldap_errlist[i].e_code ) {
			(void) fprintf( stderr, "%s: %s\n", s,
			    ldap_errlist[i].e_reason );
			if ( ld->ld_matched != NULL && *ld->ld_matched != '\0' )
				(void) fprintf( stderr, catgets(slapdcat, 1, 176, "%1$s: matched: %2$s\n"), s,
				    ld->ld_matched );
			if ( ld->ld_error != NULL && *ld->ld_error != '\0' )
				(void) fprintf( stderr, catgets(slapdcat, 1, 177, "%1$s: additional info: %2$s\n"),
				    s, ld->ld_error );
			(void) fflush( stderr );
			return;
		}
	}

	(void) fprintf( stderr, catgets(slapdcat, 1, 178, "%1$s: Not an LDAP errno %2$d\n"), s, ld->ld_errno );
	(void) fflush( stderr );
}

#else

void
ldap_perror( LDAP *ld, char *s )
{
}

#endif /* NO_USERINTERFACE */


int
ldap_result2error( LDAP *ld, LDAPMessage *r, int freeit )
{
	LDAPMessage	*lm;
	BerElement	ber;
	int		along;
	int		rc;

	Debug( LDAP_DEBUG_TRACE, "ldap_result2error\n", 0, 0, 0 );

	if ( r == NULLMSG )
		return( LDAP_PARAM_ERROR );

	for ( lm = r; lm->lm_chain != NULL; lm = lm->lm_chain )
		;	/* NULL */

	if ( ld->ld_error ) {
		free( ld->ld_error );
		ld->ld_error = NULL;
	}
	if ( ld->ld_matched ) {
		free( ld->ld_matched );
		ld->ld_matched = NULL;
	}

	ber = *(lm->lm_ber);
	if ( ld->ld_version == LDAP_VERSION2 ) {
		rc = ber_scanf( &ber, "{iaa}", &along, &ld->ld_matched,
		    &ld->ld_error );
	} else {
		rc = ber_scanf( &ber, "{ia}", &along, &ld->ld_error );
	}
	if ( rc == LBER_ERROR ) {
		ld->ld_errno = LDAP_DECODING_ERROR;
	} else {
		ld->ld_errno = along;
	}

	if ( freeit )
		ldap_msgfree( r );

	return( ld->ld_errno );
}
