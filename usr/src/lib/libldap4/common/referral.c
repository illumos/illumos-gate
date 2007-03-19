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
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include "portable.h"
#include "lber.h"
#include "ldap.h"
#include "ldap-private.h"
#include "ldap-int.h"

static BerElement *
re_encode_request( LDAP *ld, BerElement *origber, int msgid, LDAPURLDesc *urldesc );
static void addFollowedRef(LDAPRequest *lr, char *ref);
static void addToFollowRef(LDAPRequest *lr, char *ref);
static int addUnFollowedRef(LDAP *ld, LDAPRequest *lr, char *ref);

char ** ldap_errormsg2referrals(char *errmsg) {
	char ** refs;
	int count;
	size_t  len;
	char *p, *ref;
	
	if (errmsg == NULL){
		return (NULL);
	}
	len = strlen( errmsg );
	for ( p = errmsg; len >= LDAP_REF_STR_LEN; ++p, --len ) {
		if (( *p == 'R' || *p == 'r' ) && strncasecmp( p,
		    LDAP_REF_STR, LDAP_REF_STR_LEN ) == 0 ) {
			*p = '\0';
			p += LDAP_REF_STR_LEN;
			break;
		}
	}

	if ( len < LDAP_REF_STR_LEN ) {
		return( NULL);
	}
	count = 1;
    ref = p;
	while ((ref = strchr(ref, '\n')) != NULL)
		count++;
	
	if ((refs = (char **)calloc(count + 1, sizeof(char *))) == NULL){
		return (NULL);
	}
	
	count = 0;
	for (ref = p; ref != NULL; ref= p){
		if ((p = strchr(ref, '\n')) != NULL){
			*p = '\0';
		}
		refs[count++] = strdup(ref);
		if (p != NULL)
			*p++ = '\n';
	}
	return (refs);
}

char *ldap_referral2error_msg(char ** refs)
{
	int i;
	size_t len = 0;
	char *msg = NULL;
	
	if (refs == NULL)
		return (msg);
	
	for (i = 0; refs[i] != NULL; i++){
		len += strlen (refs[i]) + 1;
	}
	
	if ((len > 0) && ((msg = (char *)malloc(len + LDAP_REF_STR_LEN + 2)) != NULL)) {
		strncpy(msg, LDAP_REF_STR, LDAP_REF_STR_LEN);
		for (i = 0; refs[i] != NULL; i++) {
			strcat(msg, refs[i]);
			strcat(msg, "\n");
		}
	}
	return (msg);
}


int
chase_referrals( LDAP *ld, LDAPRequest *lr, char **refs, int *count, int samerequest )
{
	int		rc, len, newdn, i, j, refcnt, errCode;
	char		*p, *ports, *ref, *tmpref, *refdn;
	LDAPRequest	*origreq;
	LDAPServer	*srv;
	BerElement	*ber;
	LDAPURLDesc *ludp;
	
	
	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 215, "=> chase_referrals\n"), 0, 0, 0 );

	ld->ld_errno = LDAP_SUCCESS;	/* optimistic */
	*count = 0;
	if ( refs == NULL ) {
		return( LDAP_SUCCESS );
	}

#ifdef _REENTRANT
	LOCK_LDAP(ld);
#endif

	if ( lr->lr_parentcnt >= ld->ld_refhoplimit ) {
		Debug( LDAP_DEBUG_ANY,
			   catgets(slapdcat, 1, 216, "more than %d referral hops (dropping)\n"),
			   ld->ld_refhoplimit, 0, 0 );
		/* XXX report as error in ld->ld_errno? */
		rc = ld->ld_errno = (ld->ld_version >= LDAP_VERSION3) ? LDAP_REFERRAL_LIMIT_EXCEEDED : LDAP_OTHER;
#ifdef _REENTRANT
		UNLOCK_LDAP(ld);
#endif
		return( rc );
	}

	/* find original request */
	for ( origreq = lr; origreq->lr_parent != NULL;
	     origreq = origreq->lr_parent ) {
		;
	}

	for (refcnt = 0; refs[refcnt] != NULL; refcnt++)
		; /* Count number of referrals */
	Debug(LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 1277, "%d possible referrals to chase\n"), refcnt, 0,0);

	rc = 0;
	/* parse out & follow referrals */
	for (i = 0; rc == 0 && refs[i] != NULL; i++) {
		Debug(LDAP_DEBUG_TRACE, catgets(slapdcat, 1, -1, "Try to chase %s\n"), refs[i], 0,0);

		/* Parse URL */
		if (ldap_url_parse(refs[i], &ludp) != 0){
			Debug(LDAP_DEBUG_TRACE, catgets(slapdcat, 1, -1, "Bad URL for referral %s\n"), refs[i], 0,0);
			errCode = LDAP_PARAM_ERROR;
			addUnFollowedRef(ld, lr, refs[i]);
			/* try next URL */
			continue;
		}
		
		/* Encode previous request with new URL */
		if (( ber = re_encode_request( ld, origreq->lr_ber, ++ld->ld_msgid, ludp )) == NULL ) {
			Debug(LDAP_DEBUG_TRACE, catgets(slapdcat, 1, -1, "Error while encoding request for referral\n"), 0, 0,0);
			ldap_free_urldesc(ludp);
			errCode = ld->ld_errno;
			addUnFollowedRef(ld, lr, refs[i]);
			/* try next URL */
			continue;
		}

		if (( srv = (LDAPServer *)calloc( 1, sizeof( LDAPServer ))) == NULL ) {
			ldap_free_urldesc(ludp);
			ber_free( ber, 1 );
			rc = ld->ld_errno = LDAP_NO_MEMORY;
#ifdef _REENTRANT
			UNLOCK_LDAP(ld);
#endif
			return( rc );
		}

		if (( srv->lsrv_host = strdup( ludp->lud_host ? ludp->lud_host : ld->ld_defhost)) == NULL ) {
			ldap_free_urldesc(ludp);
			free( (char *)srv );
			ber_free( ber, 1 );
			rc = ld->ld_errno = LDAP_NO_MEMORY;
#ifdef _REENTRANT
			UNLOCK_LDAP(ld);
#endif
			return( rc );
		}
		
		srv->lsrv_port = ludp->lud_port ? ludp->lud_port : LDAP_PORT;

		if ( srv != NULL && send_server_request( ld, ber, ld->ld_msgid,
		    lr, srv, NULL, 1 ) >= 0 ) {
			++*count;
			Debug(LDAP_DEBUG_TRACE, catgets(slapdcat, 1, -1, "Request has been forwarded to %s\n"), refs[i], 0,0);
			addFollowedRef(lr, refs[i]);
			for (j = i+1; refs[j] != NULL; j++){
				addToFollowRef(lr, refs[j]);
			}
			ldap_free_urldesc(ludp);
			break;
		} else {
			Debug( LDAP_DEBUG_ANY,
				   catgets(slapdcat, 1, 220, "Unable to chase referral (%s)\n"), 
				   ldap_err2string( ld->ld_errno ), 0, 0 );
			addUnFollowedRef(ld, lr, refs[i]);
			errCode = ld->ld_errno;
		}
		ldap_free_urldesc(ludp); /* So far spawn all requests */
	}

#ifdef _REENTRANT
	UNLOCK_LDAP(ld);
#endif
	if (refs[i] != NULL) {
		rc = LDAP_SUCCESS;
	} else {
		Debug(LDAP_DEBUG_TRACE, catgets(slapdcat, 1, -1, "No referral was successfully chased (last error %d)\n"), errCode, 0, 0);
		rc = errCode;
	}
	Debug ( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 1278, "<= chase_referrals --- \n"), 0,0,0);
	
	return( rc );
}

static void addFollowedRef(LDAPRequest *lr, char *ref)
{
	int i;

	if (lr->lr_ref_followed == NULL){
		if ((lr->lr_ref_followed = (char **)calloc(2, sizeof(char*))) == NULL)
			return;
		i = 0;
	} else {
		for (i = 0; lr->lr_ref_followed[i] != NULL; i++);
		if ((lr->lr_ref_followed = (char **)realloc((char *)lr->lr_ref_followed, (i+2) * sizeof(char *))) == NULL){
			return;
		}
	}
	lr->lr_ref_followed[i++] = strdup(ref);
	lr->lr_ref_followed[i] = NULL;
	return;
}

static void addToFollowRef(LDAPRequest *lr, char *ref)
{
	int i;

	if (lr->lr_ref_tofollow == NULL){
		if ((lr->lr_ref_tofollow = (char **)calloc(2, sizeof(char*))) == NULL)
			return;
		i = 0;
	} else {
		for (i = 0; lr->lr_ref_tofollow[i] != NULL; i++);
		if ((lr->lr_ref_tofollow = (char **)realloc((char *)lr->lr_ref_tofollow, (i+2) * sizeof(char *))) == NULL){
			return;
		}
	}
	lr->lr_ref_tofollow[i++] = strdup(ref);
	lr->lr_ref_tofollow[i] = NULL;
	return;
}

static int addUnFollowedRef(LDAP *ld, LDAPRequest *lr, char *ref)
{
	int i;

	if (lr->lr_ref_unfollowed == NULL){
		if ((lr->lr_ref_unfollowed = (char **)calloc(2, sizeof(char*))) == NULL){
			ld->ld_errno = LDAP_NO_MEMORY;
			return (-1);
		}
		i = 0;
	} else {
		for (i = 0; lr->lr_ref_unfollowed[i] != NULL; i++);
		if ((lr->lr_ref_unfollowed = (char **)realloc((char *)lr->lr_ref_unfollowed, (i+2) * sizeof(char *))) == NULL){
			ld->ld_errno = LDAP_NO_MEMORY;
			return (-1);
		}
	}
	lr->lr_ref_unfollowed[i++] = strdup(ref);
	lr->lr_ref_unfollowed[i] = NULL;
	return (0);
}


int
append_referral( LDAP *ld, char **referralsp, char *s )
{
	int	first;

	if ( *referralsp == NULL ) {
		first = 1;
		*referralsp = (char *)malloc( strlen( s ) + LDAP_REF_STR_LEN
		    + 1 );
	} else {
		first = 0;
		*referralsp = (char *)realloc( *referralsp,
		    strlen( *referralsp ) + strlen( s ) + 2 );
	}

	if ( *referralsp == NULL ) {
		ld->ld_errno = LDAP_NO_MEMORY;
		return( -1 );
	}

	if ( first ) {
		strcpy( *referralsp, LDAP_REF_STR );
	} else {
		strcat( *referralsp, "\n" );
	}
	strcat( *referralsp, s );

	return( 0 );
}



static BerElement *
re_encode_request( LDAP *ld, BerElement *origber, int msgid, LDAPURLDesc *urldesc )
{
/*
 * XXX this routine knows way too much about how the lber library works!
 */
	unsigned int	along, tag, len;
	int		ver, scope, deref, sizelimit, timelimit, attrsonly;
	int		rc, hasCtrls;
	BerElement	tmpber, *ber;
	char	*dn, *seqstart;

	Debug( LDAP_DEBUG_TRACE,
	    catgets(slapdcat, 1, 221, "re_encode_request: new msgid %1$d, new dn <%2$s>\n"),
	    msgid, ( urldesc->lud_dn == NULL ) ? "NONE" : urldesc->lud_dn, 0 );

	tmpber = *origber;

	/*
	 * all LDAP requests are sequences that start with a message id,
	 * followed by a sequence that is tagged with the operation code
	 */
	/* Bad assumption : delete op is not a sequence. 
	 * So we have a special processing for it : it's much simpler 
	 */
	if ( ber_scanf( &tmpber, "{i", &along ) != LDAP_TAG_MSGID ||
	    ( tag = ber_peek_tag( &tmpber, &along )) == LBER_DEFAULT ) {
                ld->ld_errno = LDAP_DECODING_ERROR;
		return( NULL );
	}
	
	/* Special case :  delete request is not a sequence of... */
	if (tag == LDAP_REQ_EXTENDED){
		/* return error, I don't know how to do it automatically */
		ld->ld_errno = LDAP_NOT_SUPPORTED;
		return (NULL);
	}
	
	if ( (ber = alloc_ber_with_options( ld )) == NULLBER ) {
		return (NULL);
	}
	
	if (tag == LDAP_REQ_DELETE) {
		if ( ber_get_stringa( &tmpber, &dn ) == LBER_DEFAULT ) {
			ld->ld_errno = LDAP_DECODING_ERROR;
			Debug(LDAP_DEBUG_TRACE, 
				  catgets(slapdcat, 1, 1279,"Error in decoding delete DN"),0,0,0);
			ber_free( ber, 1);
			return( NULL );
		}
		/* Check if controls */
		hasCtrls = 0;
		if (ber_peek_tag(&tmpber, &len) == LDAP_TAG_CONTROL_LIST){
			hasCtrls = 1;
		}
		
		if ( urldesc->lud_dn && *urldesc->lud_dn ) {
			free( dn );
			dn = urldesc->lud_dn;
		}
		if ( ber_printf( ber, "{its", msgid, tag, dn ) == -1 ) {
			Debug(LDAP_DEBUG_TRACE, "Error in re_encoding delete request",0,0,0);
			ld->ld_errno = LDAP_ENCODING_ERROR;
			ber_free( ber, 1 );
			return (NULL);
		}
		/* Now add controls if any */
		if (hasCtrls && ber_write( ber, tmpber.ber_ptr, len, 0 ) != len ) {
			ld->ld_errno = LDAP_ENCODING_ERROR;
			ber_free( ber, 1 );
			return( NULL );
		}
		if (ber_printf( ber, "}" ) == -1 ) {
			ld->ld_errno = LDAP_ENCODING_ERROR;
			ber_free( ber, 1 );
			return( NULL );
		}
		
#ifdef LDAP_DEBUG
		if ( ldap_debug & LDAP_DEBUG_PACKETS ) {
			Debug( LDAP_DEBUG_ANY, catgets(slapdcat, 1, 222, "re_encode_request new request is:\n"),
				   0, 0, 0 );
			ber_dump( ber, 0 );
		}
#endif /* LDAP_DEBUG */
		return (ber);
	}

	if (( tag = ber_skip_tag( &tmpber, &along )) == LBER_DEFAULT ) {
			ld->ld_errno = LDAP_DECODING_ERROR;
			return( NULL );
	}
	/* Keep length and pointer */
	seqstart = tmpber.ber_ptr;

	/* bind requests have a version number before the DN & other stuff */
	if ( tag == LDAP_REQ_BIND && ber_get_int( &tmpber, &ver ) ==
	    LBER_DEFAULT ) {
		ld->ld_errno = LDAP_DECODING_ERROR;
		ber_free( ber, 1 );
		return( NULL );
	}

	/* the rest of the request is the DN followed by other stuff */
	if ( ber_get_stringa( &tmpber, &dn ) == LBER_DEFAULT ) {
		ber_free( ber, 1 );
		return( NULL );
	}
	if ( urldesc->lud_dn != NULL ) {
		free( dn );
		dn = urldesc->lud_dn;
	}

	/* see what to do with CONTROLS */

	if ( tag == LDAP_REQ_BIND ) {
		rc = ber_printf( ber, "{it{is", msgid, tag, ver, dn );
	} else {
		rc = ber_printf( ber, "{it{s", msgid, tag, dn );
	}

	if ( rc == -1 ) {
		ber_free( ber, 1 );
		return( NULL );
	}

 	if (tag == LDAP_REQ_SEARCH) { 
		/* Now for SEARCH, decode more of the request */
		if (ber_scanf(&tmpber, "iiiib", &scope, &deref, &sizelimit, &timelimit, &attrsonly) == LBER_DEFAULT){
			ld->ld_errno = LDAP_DECODING_ERROR;
			ber_free( ber, 1 );
			return( NULL );
		}
		if (ber_printf(ber, "iiiib", urldesc->lud_scope == LDAP_SCOPE_UNKNOWN ? scope : urldesc->lud_scope,
					   deref, sizelimit, timelimit, attrsonly) == -1) {
			ld->ld_errno = LDAP_ENCODING_ERROR;
			ber_free( ber, 1 );
			return( NULL );
		}
		/* We should then decode and check the filter as opposed to ludp->lud_filter */
		/* Same for attributes */
		/* Later */
 	} 
	/* The rest is the same for all requests */

	/* Copy Buffer from tmpber.ber_ptr for along - (tmpber.ber_ptr - seqstart) */
	/* It's the rest of the request */
	len  = along - ( tmpber.ber_ptr - seqstart);
	if ( ber_write( ber, tmpber.ber_ptr, len, 0) != len ||
		 ber_printf( ber, "}" ) == -1 ) {
		ld->ld_errno = LDAP_ENCODING_ERROR;
			ber_free( ber, 1 );
			return( NULL );
	}

	if (seqstart + along < tmpber.ber_end){ /* there's probably some controls, copy them also */
		len = tmpber.ber_end - seqstart - along;
		if ( ber_write( ber, seqstart + along, len, 0) != len ){
			ld->ld_errno = LDAP_ENCODING_ERROR;
			ber_free( ber, 1 );
			return( NULL );
			}
	}

	if ( ber_printf(ber, "}") == -1) {
		ld->ld_errno = LDAP_ENCODING_ERROR;
		ber_free( ber, 1 );
		return( NULL );
	}

#ifdef LDAP_DEBUG
	if ( ldap_debug & LDAP_DEBUG_PACKETS ) {
		Debug( LDAP_DEBUG_ANY, catgets(slapdcat, 1, 222, "re_encode_request new request is:\n"),
		    0, 0, 0 );
		ber_dump( ber, 0 );
	}
#endif /* LDAP_DEBUG */

	return( ber );
}


LDAPRequest *
find_request_by_msgid( LDAP *ld, int msgid )
{
    	LDAPRequest	*lr;

	for ( lr = ld->ld_requests; lr != NULL; lr = lr->lr_next ) {
		if ( msgid == lr->lr_msgid ) {
			break;
		}
	}

	return( lr );
}
