/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*-
 *
 * The contents of this file are subject to the Netscape Public License
 * Version 1.0 (the "NPL"); you may not use this file except in
 * compliance with the NPL.  You may obtain a copy of the NPL at
 * http://www.mozilla.org/NPL/
 *
 * Software distributed under the NPL is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the NPL
 * for the specific language governing rights and limitations under the
 * NPL.
 *
 * The Initial Developer of this code under the NPL is Netscape
 * Communications Corporation.  Portions created by Netscape are
 * Copyright (C) 1998 Netscape Communications Corporation.  All Rights
 * Reserved.
 */
#include "ldap-int.h"

struct ldaperror {
	int	e_code;
	char	*e_reason;
};

#ifdef _SOLARIS_SDK
#include <synch.h>
static struct ldaperror ldap_errlist[] = {
	{ LDAP_SUCCESS, 			0 },
	{ LDAP_OPERATIONS_ERROR, 		0 },
	{ LDAP_PROTOCOL_ERROR, 			0 },
	{ LDAP_TIMELIMIT_EXCEEDED,		0 },
	{ LDAP_SIZELIMIT_EXCEEDED, 		0 },
	{ LDAP_COMPARE_FALSE, 			0 },
	{ LDAP_COMPARE_TRUE, 			0 },
	{ LDAP_STRONG_AUTH_NOT_SUPPORTED,	0 },
	{ LDAP_STRONG_AUTH_REQUIRED, 		0 },
	{ LDAP_PARTIAL_RESULTS, 		0 },
	{ LDAP_REFERRAL, 			0 },
	{ LDAP_ADMINLIMIT_EXCEEDED,		0 },
	{ LDAP_UNAVAILABLE_CRITICAL_EXTENSION,	0 },
	{ LDAP_CONFIDENTIALITY_REQUIRED,	0 },
	{ LDAP_SASL_BIND_IN_PROGRESS,		0 },

	{ LDAP_NO_SUCH_ATTRIBUTE, 		0 },
	{ LDAP_UNDEFINED_TYPE, 			0 },
	{ LDAP_INAPPROPRIATE_MATCHING, 		0 },
	{ LDAP_CONSTRAINT_VIOLATION, 		0 },
	{ LDAP_TYPE_OR_VALUE_EXISTS, 		0 },
	{ LDAP_INVALID_SYNTAX, 			0 },

	{ LDAP_NO_SUCH_OBJECT, 			0 },
	{ LDAP_ALIAS_PROBLEM, 			0 },
	{ LDAP_INVALID_DN_SYNTAX,		0 },
	{ LDAP_IS_LEAF, 			0 },
	{ LDAP_ALIAS_DEREF_PROBLEM, 		0 },

	{ LDAP_INAPPROPRIATE_AUTH, 		0 },
	{ LDAP_INVALID_CREDENTIALS, 		0 },
	{ LDAP_INSUFFICIENT_ACCESS, 		0 },
	{ LDAP_BUSY, 				0 },
	{ LDAP_UNAVAILABLE, 			0 },
	{ LDAP_UNWILLING_TO_PERFORM, 		0 },
	{ LDAP_LOOP_DETECT, 			0 },
	{ LDAP_SORT_CONTROL_MISSING,    	0 },
	{ LDAP_INDEX_RANGE_ERROR,		0 }, 

	{ LDAP_NAMING_VIOLATION, 		0 },
	{ LDAP_OBJECT_CLASS_VIOLATION, 		0 },
	{ LDAP_NOT_ALLOWED_ON_NONLEAF, 		0 },
	{ LDAP_NOT_ALLOWED_ON_RDN, 		0 },
	{ LDAP_ALREADY_EXISTS, 			0 },
	{ LDAP_NO_OBJECT_CLASS_MODS, 		0 },
	{ LDAP_RESULTS_TOO_LARGE,		0 },
	{ LDAP_AFFECTS_MULTIPLE_DSAS,		0 },

	{ LDAP_OTHER, 				0 },
	{ LDAP_SERVER_DOWN,			0 },
	{ LDAP_LOCAL_ERROR,			0 },
	{ LDAP_ENCODING_ERROR,			0 },
	{ LDAP_DECODING_ERROR,			0 },
	{ LDAP_TIMEOUT,				0 },
	{ LDAP_AUTH_UNKNOWN,			0 },
	{ LDAP_FILTER_ERROR,			0 },
	{ LDAP_USER_CANCELLED,			0 },
	{ LDAP_PARAM_ERROR,			0 },
	{ LDAP_NO_MEMORY,			0 },
	{ LDAP_CONNECT_ERROR,			0 },
	{ LDAP_NOT_SUPPORTED,			0 },
	{ LDAP_CONTROL_NOT_FOUND,		0 },
	{ LDAP_NO_RESULTS_RETURNED,		0 },
	{ LDAP_MORE_RESULTS_TO_RETURN,		0 },
	{ LDAP_CLIENT_LOOP,			0 },
	{ LDAP_REFERRAL_LIMIT_EXCEEDED,		0 },
	{ -1, 0 }
};
const int last_index = sizeof(ldap_errlist)/sizeof(ldap_errlist[0]) - 2;
#else
static struct ldaperror ldap_errlist[] = {
	{ LDAP_SUCCESS, 			"Success" },
	{ LDAP_OPERATIONS_ERROR, 		"Operations error" },
	{ LDAP_PROTOCOL_ERROR, 			"Protocol error" },
	{ LDAP_TIMELIMIT_EXCEEDED,		"Timelimit exceeded" },
	{ LDAP_SIZELIMIT_EXCEEDED, 		"Sizelimit exceeded" },
	{ LDAP_COMPARE_FALSE, 			"Compare false" },
	{ LDAP_COMPARE_TRUE, 			"Compare true" },
	{ LDAP_STRONG_AUTH_NOT_SUPPORTED,	"Authentication method not supported" },
	{ LDAP_STRONG_AUTH_REQUIRED, 		"Strong authentication required" },
	{ LDAP_PARTIAL_RESULTS, 		"Partial results and referral received" },
	{ LDAP_REFERRAL, 			"Referral received" },
	{ LDAP_ADMINLIMIT_EXCEEDED,		"Administrative limit exceeded" },
	{ LDAP_UNAVAILABLE_CRITICAL_EXTENSION,	"Unavailable critical extension" },
	{ LDAP_CONFIDENTIALITY_REQUIRED,	"Confidentiality required" },
	{ LDAP_SASL_BIND_IN_PROGRESS,		"SASL bind in progress" },

	{ LDAP_NO_SUCH_ATTRIBUTE, 		"No such attribute" },
	{ LDAP_UNDEFINED_TYPE, 			"Undefined attribute type" },
	{ LDAP_INAPPROPRIATE_MATCHING, 		"Inappropriate matching" },
	{ LDAP_CONSTRAINT_VIOLATION, 		"Constraint violation" },
	{ LDAP_TYPE_OR_VALUE_EXISTS, 		"Type or value exists" },
	{ LDAP_INVALID_SYNTAX, 			"Invalid syntax" },

	{ LDAP_NO_SUCH_OBJECT, 			"No such object" },
	{ LDAP_ALIAS_PROBLEM, 			"Alias problem" },
	{ LDAP_INVALID_DN_SYNTAX,		"Invalid DN syntax" },
	{ LDAP_IS_LEAF, 			"Object is a leaf" },
	{ LDAP_ALIAS_DEREF_PROBLEM, 		"Alias dereferencing problem" },

	{ LDAP_INAPPROPRIATE_AUTH, 		"Inappropriate authentication" },
	{ LDAP_INVALID_CREDENTIALS, 		"Invalid credentials" },
	{ LDAP_INSUFFICIENT_ACCESS, 		"Insufficient access" },
	{ LDAP_BUSY, 				"DSA is busy" },
	{ LDAP_UNAVAILABLE, 			"DSA is unavailable" },
	{ LDAP_UNWILLING_TO_PERFORM, 		"DSA is unwilling to perform" },
	{ LDAP_LOOP_DETECT, 			"Loop detected" },
    { LDAP_SORT_CONTROL_MISSING,    "Sort Control is missing"  },
    { LDAP_INDEX_RANGE_ERROR,              "Search results exceed the range specified by the offsets" }, 
    
    { LDAP_NAMING_VIOLATION, 		"Naming violation" },
	{ LDAP_OBJECT_CLASS_VIOLATION, 		"Object class violation" },
	{ LDAP_NOT_ALLOWED_ON_NONLEAF, 		"Operation not allowed on nonleaf" },
	{ LDAP_NOT_ALLOWED_ON_RDN, 		"Operation not allowed on RDN" },
	{ LDAP_ALREADY_EXISTS, 			"Already exists" },
	{ LDAP_NO_OBJECT_CLASS_MODS, 		"Cannot modify object class" },
	{ LDAP_RESULTS_TOO_LARGE,		"Results too large" },
	{ LDAP_AFFECTS_MULTIPLE_DSAS,		"Affects multiple servers" },

	{ LDAP_OTHER, 				"Unknown error" },
	{ LDAP_SERVER_DOWN,			"Can't contact LDAP server" },
	{ LDAP_LOCAL_ERROR,			"Local error" },
	{ LDAP_ENCODING_ERROR,			"Encoding error" },
	{ LDAP_DECODING_ERROR,			"Decoding error" },
	{ LDAP_TIMEOUT,				"Timed out" },
	{ LDAP_AUTH_UNKNOWN,			"Unknown authentication method" },
	{ LDAP_FILTER_ERROR,			"Bad search filter" },
	{ LDAP_USER_CANCELLED,			"User cancelled operation" },
	{ LDAP_PARAM_ERROR,			"Bad parameter to an ldap routine" },
	{ LDAP_NO_MEMORY,			"Out of memory" },
	{ LDAP_CONNECT_ERROR,			"Can't connect to the LDAP server" },
	{ LDAP_NOT_SUPPORTED,			"Not supported by this version of the LDAP protocol" },
	{ LDAP_CONTROL_NOT_FOUND,		"Requested LDAP control not found" },
	{ LDAP_NO_RESULTS_RETURNED,		"No results returned" },
	{ LDAP_MORE_RESULTS_TO_RETURN,		"More results to return" },
	{ LDAP_CLIENT_LOOP,			"Client detected loop" },
	{ LDAP_REFERRAL_LIMIT_EXCEEDED,		"Referral hop limit exceeded" },
	{ -1, 0 }
};
#endif

#ifdef _SOLARIS_SDK
static mutex_t		err_mutex = DEFAULTMUTEX;

static void fill_ldap_errlist()
{
	int i=0;
	mutex_lock(&err_mutex);

	LDAPDebug(LDAP_DEBUG_TRACE, "fill_ldap_errlist\n", 0, 0, 0 );

	if (ldap_errlist[last_index].e_reason != NULL) {
		mutex_unlock(&err_mutex);
		return;
	}

	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN, "Success");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN, "Operations error");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN, "Protocol error");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN,
				"Timelimit exceeded");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN,
				"Sizelimit exceeded");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN, "Compare false");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN, "Compare true");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN,
				"Authentication method not supported");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN,
				"Strong authentication required");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN,
				"Partial results and referral received");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN,
				"Referral received");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN,
				"Administrative limit exceeded");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN,
				"Unavailable critical extension");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN,
				"Confidentiality required");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN,
				"SASL bind in progress");

	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN,
				"No such attribute");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN,
				"Undefined attribute type");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN,
				"Inappropriate matching");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN,
				"Constraint violation");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN,
				"Type or value exists");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN, "Invalid syntax");

	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN, "No such object");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN, "Alias problem");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN,
				"Invalid DN syntax");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN, "Object is a leaf");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN,
				"Alias dereferencing problem");

	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN,
				"Inappropriate authentication");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN,
				"Invalid credentials");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN,
				"Insufficient access");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN, "DSA is busy");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN,
				"DSA is unavailable");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN,
				"DSA is unwilling to perform");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN, "Loop detected");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN,
				"Sort Control is missing");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN,
		"Search results exceed the range specified by the offsets");

	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN, "Naming violation");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN,
				"Object class violation");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN,
				"Operation not allowed on nonleaf");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN,
				"Operation not allowed on RDN");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN, "Already exists");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN,
				"Cannot modify object class");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN,
				"Results too large");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN,
				"Affects multiple servers");

	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN, "Unknown error");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN,
				"Can't contact LDAP server");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN, "Local error");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN, "Encoding error");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN, "Decoding error");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN, "Timed out");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN,
				"Unknown authentication method");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN,
				"Bad search filter");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN,
				"User cancelled operation");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN,
				"Bad parameter to an ldap routine");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN, "Out of memory");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN,
				"Can't connect to the LDAP server");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN,
			"Not supported by this version of the LDAP protocol");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN,
				"Requested LDAP control not found");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN,
				"No results returned");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN,
				"More results to return");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN,
				"Client detected loop");
	ldap_errlist[i++].e_reason = dgettext(TEXT_DOMAIN,
				"Referral hop limit exceeded");
	mutex_unlock(&err_mutex);
}
#endif

char *
LDAP_CALL
ldap_err2string( int err )
{
	int	i;

	LDAPDebug( LDAP_DEBUG_TRACE, "ldap_err2string\n", 0, 0, 0 );

#ifdef _SOLARIS_SDK
	/* Make sure errlist is initialized before referencing err string */
	if (ldap_errlist[last_index].e_reason == NULL)
		fill_ldap_errlist();
#endif

	for ( i = 0; ldap_errlist[i].e_code != -1; i++ ) {
		if ( err == ldap_errlist[i].e_code )
			return( ldap_errlist[i].e_reason );
	}

	return( dgettext(TEXT_DOMAIN, "Unknown error") );
}


static char *
nsldapi_safe_strerror( int e )
{
	char *s;

	if (( s = strerror( e )) == NULL ) {
		s = dgettext(TEXT_DOMAIN, "unknown error");
	}

	return( s );
}


void
LDAP_CALL
ldap_perror( LDAP *ld, const char *s )
{
	int	i, err;
	char	*matched, *errmsg, *separator;
	char    msg[1024];

	LDAPDebug( LDAP_DEBUG_TRACE, "ldap_perror\n", 0, 0, 0 );

#ifdef _SOLARIS_SDK
	/* Make sure errlist is initialized before referencing err string */
	if (ldap_errlist[last_index].e_reason == NULL)
		fill_ldap_errlist();
#endif

	if ( s == NULL ) {
		s = separator = "";
	} else {
		separator = ": ";
	}

	if ( ld == NULL ) {
		sprintf( msg, "%s%s%s", s, separator,
		    nsldapi_safe_strerror( errno ) );
		ber_err_print( msg );
		return;
	}

	LDAP_MUTEX_LOCK( ld, LDAP_ERR_LOCK );
	err = LDAP_GET_LDERRNO( ld, &matched, &errmsg );
	for ( i = 0; ldap_errlist[i].e_code != -1; i++ ) {
		if ( err == ldap_errlist[i].e_code ) {
			sprintf( msg, "%s%s%s", s, separator,
				    ldap_errlist[i].e_reason );
			ber_err_print( msg );
			if ( err == LDAP_CONNECT_ERROR ) {
				ber_err_print( " - " );
				ber_err_print( nsldapi_safe_strerror(
				    LDAP_GET_ERRNO( ld )));
			}
			ber_err_print( "\n" );
			if ( matched != NULL && *matched != '\0' ) {
				sprintf( msg, dgettext(TEXT_DOMAIN,
					"%s%smatched: %s\n"),
				    s, separator, matched );
				ber_err_print( msg );
			}
			if ( errmsg != NULL && *errmsg != '\0' ) {
				sprintf( msg, dgettext(TEXT_DOMAIN,
					"%s%sadditional info: %s\n"),
				    s, separator, errmsg );
				ber_err_print( msg );
			}
			LDAP_MUTEX_UNLOCK( ld, LDAP_ERR_LOCK );
			return;
		}
	}
	sprintf( msg, dgettext(TEXT_DOMAIN, "%s%sNot an LDAP errno %d\n"),
		s, separator, err );
	ber_err_print( msg );
	LDAP_MUTEX_UNLOCK( ld, LDAP_ERR_LOCK );
}

int
LDAP_CALL
ldap_result2error( LDAP *ld, LDAPMessage *r, int freeit )
{
	int	lderr_parse, lderr;

	lderr_parse = ldap_parse_result( ld, r, &lderr, NULL, NULL, NULL,
	    NULL, freeit );

	if ( lderr_parse != LDAP_SUCCESS ) {
		return( lderr_parse );
	}

	return( lderr );
}

int
LDAP_CALL
ldap_get_lderrno( LDAP *ld, char **m, char **s )
{
	if ( !NSLDAPI_VALID_LDAP_POINTER( ld )) {
		return( LDAP_PARAM_ERROR );	/* punt */
	}

	if ( ld->ld_get_lderrno_fn == NULL ) {
		if ( m != NULL ) {
			*m = ld->ld_matched;
		}
		if ( s != NULL ) {
			*s = ld->ld_error;
		}
		return( ld->ld_errno );
	} else {
		return( ld->ld_get_lderrno_fn( m, s, ld->ld_lderrno_arg ) );
	}
}


/*
 * Note: there is no need for callers of ldap_set_lderrno() to lock the
 * ld mutex.  If applications intend to share an LDAP session handle
 * between threads they *must* perform their own locking around the
 * session handle or they must install a "set lderrno" thread callback
 * function.
 * 
 */
int
LDAP_CALL
ldap_set_lderrno( LDAP *ld, int e, char *m, char *s )
{
	if ( !NSLDAPI_VALID_LDAP_POINTER( ld )) {
		return( LDAP_PARAM_ERROR );
	}

	if ( ld->ld_set_lderrno_fn != NULL ) {
		ld->ld_set_lderrno_fn( e, m, s, ld->ld_lderrno_arg );
	} else {
        LDAP_MUTEX_LOCK( ld, LDAP_ERR_LOCK );
		ld->ld_errno = e;
		if ( ld->ld_matched ) {
			NSLDAPI_FREE( ld->ld_matched );
		}
		ld->ld_matched = m;
		if ( ld->ld_error ) {
			NSLDAPI_FREE( ld->ld_error );
		}
		ld->ld_error = s;
        LDAP_MUTEX_UNLOCK( ld, LDAP_ERR_LOCK );
	}

	return( LDAP_SUCCESS );
}


/*
 * Returns an LDAP error that says whether parse succeeded.  The error code
 * from the LDAP result itself is returned in the errcodep result parameter.
 * If any of the result params. (errcodep, matchednp, errmsgp, referralsp,
 * or serverctrlsp) are NULL we don't return that info.
 */
int
LDAP_CALL
ldap_parse_result( LDAP *ld, LDAPMessage *res, int *errcodep, char **matchednp,
	char **errmsgp, char ***referralsp, LDAPControl ***serverctrlsp,
	int freeit )
{
	LDAPMessage		*lm;
	int			err, errcode;
	char			*m, *e;

	LDAPDebug( LDAP_DEBUG_TRACE, "ldap_parse_result\n", 0, 0, 0 );

	if ( !NSLDAPI_VALID_LDAP_POINTER( ld ) ||
	    !NSLDAPI_VALID_LDAPMESSAGE_POINTER( res )) {
		return( LDAP_PARAM_ERROR );
	}

	/* skip over entries and references to find next result in this chain */
	for ( lm = res; lm != NULL; lm = lm->lm_chain ) {	
		if ( lm->lm_msgtype != LDAP_RES_SEARCH_ENTRY &&
		    lm->lm_msgtype != LDAP_RES_SEARCH_REFERENCE ) {
			break;
		}
	}

	if ( lm == NULL ) {
		err = LDAP_NO_RESULTS_RETURNED;
		LDAP_SET_LDERRNO( ld, err, NULL, NULL );
		return( err );
	}

	err = nsldapi_parse_result( ld, lm->lm_msgtype, lm->lm_ber, &errcode,
	    &m, &e, referralsp, serverctrlsp );

	if ( err == LDAP_SUCCESS ) {
		if ( errcodep != NULL ) {
			*errcodep = errcode;
		}
		if ( matchednp != NULL ) {
			*matchednp = nsldapi_strdup( m );
		}
		if ( errmsgp != NULL ) {
			*errmsgp = nsldapi_strdup( e );
		}

		/*
		 * if there are more result messages in the chain, arrange to
		 * return the special LDAP_MORE_RESULTS_TO_RETURN "error" code.
		 */
		for ( lm = lm->lm_chain; lm != NULL; lm = lm->lm_chain ) {	
			if ( lm->lm_msgtype != LDAP_RES_SEARCH_ENTRY &&
			    lm->lm_msgtype != LDAP_RES_SEARCH_REFERENCE ) {
				err = LDAP_MORE_RESULTS_TO_RETURN;
				break;
			}
		}
	} else {
		m = e = NULL;
	}

	if ( freeit ) {
		ldap_msgfree( res );
	}

	LDAP_SET_LDERRNO( ld, ( err == LDAP_SUCCESS ) ? errcode : err, m, e );

	return( err );
}


/*
 * returns an LDAP error code indicating success or failure of parsing
 * does NOT set any error information inside "ld"
 */
int
nsldapi_parse_result( LDAP *ld, int msgtype, BerElement *rber, int *errcodep,
    char **matchednp, char **errmsgp, char ***referralsp,
    LDAPControl ***serverctrlsp )
{
	BerElement	ber;
	ber_len_t	len;
	int		berrc, err, errcode;
	ber_int_t	along;
	char		*m, *e;

	/*
	 * Parse the result message.  LDAPv3 result messages look like this:
	 *
	 *	LDAPResult ::= SEQUENCE {
	 *		resultCode	ENUMERATED { ... },
	 *		matchedDN	LDAPDN,
	 *		errorMessage	LDAPString,
	 *		referral	[3] Referral OPTIONAL
	 *		opSpecificStuff	OPTIONAL
	 *	}
	 *
	 * all wrapped up in an LDAPMessage sequence which looks like this:
	 *	LDAPMessage ::= SEQUENCE {
	 *		messageID	MessageID,
	 *		LDAPResult	CHOICE { ... },	// message type
	 *		controls	[0] Controls OPTIONAL
	 *	}
	 *
	 * LDAPv2 messages don't include referrals or controls.
	 * LDAPv1 messages don't include matchedDN, referrals, or controls.
	 *
	 * ldap_result() pulls out the message id, so by the time a result
	 * message gets here we are sitting at the start of the LDAPResult.
	 */

	err = LDAP_SUCCESS;	/* optimistic */
	m = e = NULL;
	if ( matchednp != NULL ) {
		*matchednp = NULL;
	}
	if ( errmsgp != NULL ) {
		*errmsgp = NULL;
	}
	if ( referralsp != NULL ) {
		*referralsp = NULL;
	}
	if ( serverctrlsp != NULL ) {
		*serverctrlsp = NULL;
	}
	ber = *rber;		/* struct copy */

	if ( NSLDAPI_LDAP_VERSION( ld ) < LDAP_VERSION2 ) {
		berrc = ber_scanf( &ber, "{ia}", &along, &e );
		errcode = (int)along;	/* XXX lossy cast */
	} else {
		if (( berrc = ber_scanf( &ber, "{iaa", &along, &m, &e ))
		    != LBER_ERROR ) {
			errcode = (int)along;	/* XXX lossy cast */
			/* check for optional referrals */
			if ( ber_peek_tag( &ber, &len ) == LDAP_TAG_REFERRAL ) {
				if ( referralsp == NULL ) {
					/* skip referrals */
					berrc = ber_scanf( &ber, "x" );
				} else {
					/* suck out referrals */
					berrc = ber_scanf( &ber, "v",
					    referralsp );
				}
			} else if ( referralsp != NULL ) {
				*referralsp = NULL;
			}
		}

		if ( berrc != LBER_ERROR ) {
			/*
			 * skip past optional operation-specific elements:
			 *   bind results - serverSASLcreds
			 *   extendedop results -  OID plus value
			 */
			if ( msgtype == LDAP_RES_BIND ) {
				if ( ber_peek_tag( &ber, &len ) == 
				    LDAP_TAG_SASL_RES_CREDS ) {
					berrc = ber_scanf( &ber, "x" );
				}
			} else if ( msgtype == LDAP_RES_EXTENDED ) {
				if ( ber_peek_tag( &ber, &len ) ==
				    LDAP_TAG_EXOP_RES_OID ) {
					berrc = ber_scanf( &ber, "x" );
				}
				if ( berrc != LBER_ERROR &&
				    ber_peek_tag( &ber, &len ) ==
				    LDAP_TAG_EXOP_RES_VALUE ) {
					berrc = ber_scanf( &ber, "x" );
				}
			}
		}

		/* pull out controls (if requested and any are present) */
		if ( berrc != LBER_ERROR && serverctrlsp != NULL &&
		    ( berrc = ber_scanf( &ber, "}" )) != LBER_ERROR ) {
			err = nsldapi_get_controls( &ber, serverctrlsp );
		}
	}

	if ( berrc == LBER_ERROR && err == LDAP_SUCCESS ) {
		err = LDAP_DECODING_ERROR;
	}

	if ( errcodep != NULL ) {
		*errcodep = errcode;
	}
	if ( matchednp != NULL ) {
		*matchednp = m;
	} else if ( m != NULL ) {
		NSLDAPI_FREE( m );
	}
	if ( errmsgp != NULL ) {
		*errmsgp = e;
	} else if ( e != NULL ) {
		NSLDAPI_FREE( e );
	}

	return( err );
}
