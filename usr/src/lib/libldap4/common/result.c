/*
 * Copyright 1998-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *  Copyright (c) 1990 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  result.c - wait for an ldap result
 */

#ifndef lint 
static char copyright[] = "@(#) Copyright (c) 1990 Regents of the University of Michigan.\nAll rights reserved.\n";
#endif

#include <stdio.h>
#include <string.h>
#ifdef MACOS
#include <stdlib.h>
#include <time.h>
#include "macos.h"
#else /* MACOS */
#if defined( DOS ) || defined( _WIN32 )
#include <time.h>
#include "msdos.h"
#ifdef PCNFS
#include <tklib.h>
#include <tk_errno.h>
#include <bios.h>
#endif /* PCNFS */
#ifdef NCSA
#include "externs.h"
#endif /* NCSA */
#else /* DOS */
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#ifdef _AIX
#include <sys/select.h>
#endif /* _AIX */
#include "portable.h"
#endif /* DOS */
#endif /* MACOS */
#ifdef VMS
#include "ucx_select.h"
#endif
#include "lber.h"
#include "ldap.h"
#include "ldap-private.h"
#include "ldap-int.h"

#ifdef USE_SYSCONF
#include <unistd.h>
#endif /* USE_SYSCONF */

#ifdef NEEDPROTOS
static int ldap_abandoned( LDAP *ld, int msgid );
static int ldap_mark_abandoned( LDAP *ld, int msgid );
static int wait4msg( LDAP *ld, int msgid, int all, struct timeval *timeout,
	LDAPMessage **result );
static int read1msg( LDAP *ld, int msgid, int all, Sockbuf *sb, LDAPConn *lc,
	LDAPMessage **result );
static int build_result_ber( LDAP *ld, BerElement *ber, LDAPRequest *lr );
static void merge_error_info( LDAP *ld, LDAPRequest *parentr, LDAPRequest *lr );
#ifdef CLDAP
static int ldap_select1( LDAP *ld, struct timeval *timeout );
#endif
static int Ref_AddToRequest(LDAPRequest *lr, char **refs);
static void Ref_FreeAll(LDAPRequest *lr);
#else /* NEEDPROTOS */
static int ldap_abandoned();
static int ldap_mark_abandoned();
static int wait4msg();
static int read1msg();
static int build_result_ber();
static void merge_error_info();
#ifdef CLDAP
static int ldap_select1();
#endif
#endif /* NEEDPROTOS */

#if !defined( MACOS ) && !defined( DOS )
extern int	errno;
#endif

/*
 * ldap_result - wait for an ldap result response to a message from the
 * ldap server.  If msgid is -1, any message will be accepted, otherwise
 * ldap_result will wait for a response with msgid.
 * If all is LDAP_MSG_ONE the first message with id msgid will be accepted. 
 * If all is LDAP_MSG_RECEIVED, the received messages with the id msgid will
 * be accepted.
 * Otherwise, ldap_result will wait for all responses with id msgid and
 * then return a pointer to the entire list of messages.  This is only
 * useful for search responses, which can be of 3 message types (zero or
 * more entries, zero or more references, one or more results).  The type
 * of the first message* received is returned.
 * When waiting, any messages that have been abandoned are discarded.
 *
 * Example:
 *	ldap_result( s, msgid, all, timeout, result )
 */
int
ldap_result( LDAP *ld, int msgid, int all, struct timeval *timeout,
	LDAPMessage **result )
{
	LDAPMessage	*lm, *lastlm, *nextlm;
	int rv;

	/*
	 * First, look through the list of responses we have received on
	 * this association and see if the response we're interested in
	 * is there.  If it is, return it.  If not, call wait4msg() to
	 * wait until it arrives or timeout occurs.
	 */

#ifdef _REENTRANT
	LOCK_RESPONSE(ld);
	LOCK_LDAP(ld);
#endif
	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 223, "ldap_result\n"), 0, 0, 0 );

	*result = NULLMSG;
	lastlm = NULLMSG;

	/* look in the received responses */
	for ( lm = ld->ld_responses; lm != NULLMSG; lm = nextlm ) {
		nextlm = lm->lm_next;

		/* if the msg has been abandonned, free it */
		if ( ldap_abandoned( ld, lm->lm_msgid ) ) {
			ldap_mark_abandoned( ld, lm->lm_msgid );

			if ( lastlm == NULLMSG ) {
				ld->ld_responses = lm->lm_next;
			} else {
				lastlm->lm_next = nextlm;
			}

			ldap_msgfree( lm );

			continue;
		}

		if ( msgid == LDAP_RES_ANY || lm->lm_msgid == msgid ) {
			LDAPMessage	*tmp;

			/* If return ONE or RECEIVED message(s) or not a search result, return lm */
			if ( all == LDAP_MSG_ONE || all == LDAP_MSG_RECEIVED
				 || (lm->lm_msgtype != LDAP_RES_SEARCH_RESULT
					&& lm->lm_msgtype != LDAP_RES_SEARCH_ENTRY
					&& lm->lm_msgtype != LDAP_RES_SEARCH_REFERENCE) )
				break;

			/* Search in the set of messages if one is a search result */
			for ( tmp = lm; tmp != NULLMSG; tmp = tmp->lm_chain ) {
				if ( tmp->lm_msgtype == LDAP_RES_SEARCH_RESULT )
					break;
			}
			/* No, well wait for the result message */
			if ( tmp == NULLMSG ) {
#ifdef _REENTRANT
				UNLOCK_LDAP(ld);
#endif
				rv = wait4msg( ld, msgid, all, timeout, result );
#ifdef _REENTRANT
				UNLOCK_RESPONSE(ld);
#endif
				return( rv );
			}
			/* Here we have the Search result pointed by tmp */
			break;
		}
		/* Check next response */
		lastlm = lm;
	}

	/* No response matching found : Wait for one  */
	if ( lm == NULLMSG ) {
#ifdef _REENTRANT
		UNLOCK_LDAP(ld);
#endif
		rv = wait4msg( ld, msgid, all, timeout, result );
#ifdef _REENTRANT
		UNLOCK_RESPONSE(ld);
#endif
		return( rv );
	}

	/* lm points to the message (chain) to return */

	/* Remove message to return from ld_responses list */
	if ( lastlm == NULLMSG ) {
		if (all == LDAP_MSG_ONE && lm->lm_chain != NULLMSG){
			ld->ld_responses = lm->lm_chain;
		} else {
			ld->ld_responses = lm->lm_next;
		}
	} else {
		if (all == LDAP_MSG_ONE && lm->lm_chain != NULLMSG) {
			lastlm->lm_next = lm->lm_chain;
		} else {
			lastlm->lm_next = lm->lm_next;
		}
	}

	if ( all == LDAP_MSG_ONE )
		lm->lm_chain = NULLMSG;
	/* Otherwise return the whole chain */
	/* No reponses attached */
	lm->lm_next = NULLMSG;

	*result = lm;
	ld->ld_errno = LDAP_SUCCESS;
	rv = lm->lm_msgtype;
#ifdef _REENTRANT
	UNLOCK_LDAP(ld);
	UNLOCK_RESPONSE(ld);
#endif
	return( rv );
}

static int
wait4msg( LDAP *ld, int msgid, int all, struct timeval *timeout,
	LDAPMessage **result )
{
	int		rc;
	struct timeval	tv, *tvp;
	time_t		start_time, tmp_time;
	LDAPConn	*lc, *nextlc;

#ifdef LDAP_DEBUG
	if ( timeout == NULL ) {
		Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 224, "wait4msg (infinite timeout)\n"),
		    0, 0, 0 );
	} else {
		Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 225, "wait4msg (timeout %1$ld sec, %2$ld usec)\n"),
		    timeout->tv_sec, timeout->tv_usec, 0 );
	}
#endif /* LDAP_DEBUG */

	if ( timeout == NULL ) {
		tvp = NULL;
	} else {
		tv = *timeout;
		tvp = &tv;
		start_time = time( NULL );
	}
		    
	rc = -2;
	while ( rc == -2 ) {
#ifdef LDAP_DEBUG
		if ( ldap_debug & LDAP_DEBUG_TRACE ) {
			dump_connection( ld, ld->ld_conns, 1 );
			dump_requests_and_responses( ld );
		}
#endif /* LDAP_DEBUG */
		for ( lc = ld->ld_conns; lc != NULL; lc = lc->lconn_next ) {
			if ( lc->lconn_sb->sb_ber.ber_ptr <
			    lc->lconn_sb->sb_ber.ber_end ) {
				/* A Message is available, decode and process it */
				rc = read1msg( ld, msgid, all, lc->lconn_sb,
				    lc, result );
				break;
			}
		}
		/* There was no message available : Wait for one */
		if ( lc == NULL ) {
			rc = do_ldap_select( ld, tvp );


#if defined( LDAP_DEBUG ) && !defined( MACOS ) && !defined( DOS )
			if ( rc == -1 ) {
			    Debug( LDAP_DEBUG_TRACE,
				    catgets(slapdcat, 1, 226, "do_ldap_select returned -1: errno %d\n"),
				    errno, 0, 0 );
			}
#endif

#if !defined( MACOS ) && !defined( DOS )
			if ( rc == 0 || ( rc == -1 && (ld->ld_restart || errno != EINTR ))) {
#else
			if ( rc == -1 || rc == 0 ) {
#endif
				ld->ld_errno = (rc == -1 ? LDAP_SERVER_DOWN :
				    LDAP_TIMEOUT);
				if ( rc == -1 ) {
#ifdef _REENTRANT
					LOCK_LDAP(ld);
#endif
					nsldapi_connection_lost_nolock( ld, NULL);
#ifdef _REENTRANT
					UNLOCK_LDAP(ld);
#endif
				}
				return( rc );
			}

			if ( rc == -1 ) {
				rc = -2;	/* select interrupted: Continue the loop */
			} else {
				rc = -2;
				for ( lc = ld->ld_conns; rc == -2 && lc != NULL;
				    lc = nextlc ) {
					nextlc = lc->lconn_next;
					if ( lc->lconn_status == LDAP_CONNST_CONNECTED) {
						/* Check on each connection. */
						long is_ready = is_read_ready( ld, lc->lconn_sb );
						
						if (is_ready > 0) {
							/* A Message is available, decode and process it */
							rc = read1msg( ld, msgid, all,
										   lc->lconn_sb, lc, result );
						} else if ( is_ready < 0){
							/* Error in the select : what to do in here ? */
							/* So far : */
							rc = -1;
						}
					}
				}
			}
		}

		if ( rc == -2 && tvp != NULL ) {
			tmp_time = time( NULL );
			if (( tv.tv_sec -=  ( tmp_time - start_time )) <= 0 ) {
				/* At this point if all == LDAP_MSG_RECEIVED, we must 
				   return all available messages for the msgid */
				if (all == LDAP_MSG_RECEIVED) {
					/* Search in responses if some have the correct id */
					/* if yes return the chain */
					/* Otherwise return timeout */ 
					break;
				}

				rc = 0;	/* timed out */
				ld->ld_errno = LDAP_TIMEOUT;
				break;
			}

			Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 227, "wait4msg:  %ld secs to go\n"),
				tv.tv_sec, 0, 0 );
			start_time = tmp_time;
		}
	}

	return( rc );
}


static int
read1msg( LDAP *ld, int msgid, int all, Sockbuf *sb,
    LDAPConn *lc,
    LDAPMessage **result )
{
	BerElement	ber;
	LDAPMessage	*new, *L_res, *l, *prev, *tmp;
	int		id;
	unsigned int	tag, atag, len;
	int		foundit = 0;
	LDAPRequest	*lr, *lrparent;
	LDAPRef *theReferences;
	BerElement	tmpber;
	int		rc, refer_cnt, hadref, simple_request, samereq = 0, total_count;
	int retcode;
	int theErrCode = LDAP_SUCCESS;
	unsigned int	lderr;
	char *msgtypestr;
	char ** theRefs = NULL;
	char * theOid = NULL;
	char *lddn, *lderrmsg;
	
	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 228, "read1msg\n"), 0, 0, 0 );

read_from_sb:
	lderr = LDAP_SUCCESS; /* Be optimistic */
	
	ber_zero_init( &ber, 0 );
	set_ber_options( ld, &ber );

	/* get the next message */
	if ( (tag = ber_get_next( sb, &len, &ber ))
	    != LDAP_TAG_MESSAGE ) {
		ld->ld_errno = (tag == LBER_DEFAULT ? LDAP_SERVER_DOWN :
		    LDAP_LOCAL_ERROR);
		if ( tag == LBER_DEFAULT ) {
#ifdef _REENTRANT
			LOCK_LDAP(ld);
#endif
			nsldapi_connection_lost_nolock( ld, sb );
#ifdef _REENTRANT
			UNLOCK_LDAP(ld);
#endif
		}
		return( -1 );
	}

	/* message id */
	if ( ber_get_int( &ber, &id ) == LBER_ERROR ) {
		ld->ld_errno = LDAP_DECODING_ERROR;
		return( -1 );
	}

	/* if it's been abandoned, toss it */
	if ( ldap_abandoned( ld, (int)id ) ) {
		free( ber.ber_buf );	/* gack! */
		return( -2 );	/* continue looking */
	}

	/* the message type */
	if ( (tag = ber_peek_tag( &ber, &len )) == LBER_ERROR ) {
		ld->ld_errno = LDAP_DECODING_ERROR;
		return( -1 );
	}

	/* KE
	 * Treat unsolicited notification if we got one!
	 * 	id==0
	 * 	tag==LDAP_RES_EXTENDED
	 * 
	 * 	resultCode==	protocolError
	 *							strongAuthRequired
	 * 						unavailable
	 *		tag==LDAP_TAG_EXT_RESPNAME
	 *		response name (oid)==1.3.6.1.1.4.1.1466.20036
	 * 	no response field
	 * 
	 * Example:
	 * --------
	 * Ber format: 	{iaata}
	 * which means: 	returnCode dn errorMessage LDAP_TAG_EXT_RESPNAME "1.3.6.1.1.4.1.1466.20036"
	 */
	if ( (id==0) && (tag==LDAP_RES_EXTENDED) )
	{
		tmpber = ber;
		if (ber_scanf( &ber, "{iaa", &lderr, &lddn, &lderrmsg) != LBER_ERROR)
		{
			if (ber_peek_tag ( &ber, &atag) == LDAP_TAG_EXT_RESPNAME)
			{
			  if ( ber_get_stringa( &ber, &theOid) == LBER_ERROR )
				{
					ld->ld_errno = LDAP_DECODING_ERROR;
					return(-1);
				}
			}
			else
			{
				ld->ld_errno = LDAP_DECODING_ERROR;
				return(-1);
			}

			if (ber_peek_tag ( &ber, &atag) == LDAP_TAG_EXT_RESPONSE)
			{
				/* this field must be absent */
				ld->ld_errno = LDAP_DECODING_ERROR;
				return(-1);
			}
			if ( ber_scanf(&ber, "}")== LBER_ERROR)
			{
				ld->ld_errno = LDAP_DECODING_ERROR;
				return(-1);
			}      

			/* make a new ldap message to return the result */
			if ( (new = (LDAPMessage *) calloc( 1, sizeof(LDAPMessage) )) == NULL ) 
			{
				ld->ld_errno = LDAP_NO_MEMORY;
				return(-1);
			}
			new->lm_msgid = 0;
			new->lm_msgtype = tag;
			new->lm_ber = ber_dup( &tmpber );

			if ( 	(strncmp(theOid, "1.3.6.1.1.4.1.1466.20036", 24)==0) && 
					(lderr==LDAP_PROTOCOL_ERROR) || 
					(lderr==LDAP_STRONG_AUTH_REQUIRED) ||
					(lderr==LDAP_UNAVAILABLE) )
			{
				/* make a new ldap message to return the result */
				if ( (L_res = (LDAPMessage *) calloc( 1, sizeof(LDAPMessage) )) == NULL ) 
				{
					ld->ld_errno = LDAP_NO_MEMORY;
					return(-1);
				}
				L_res->lm_msgid = 0;
				L_res->lm_msgtype = tag;
				L_res->lm_ber = ber_dup( &tmpber );
				*result = L_res;

				/* It is a notice of disconnection
				 * Return immediatly with an error code to stop
				 * reading any new message and to prevent the use
				 */
				ld->ld_errno = LDAP_SERVER_DOWN;
				ldap_insert_notif(ld, new);		/* in head */
				return(-1);
			}
			else
			{
				/* This is another notification
				 *	Keep on the processing of received messages 
				 */
				ldap_add_notif(ld, new);			/* in tail */
				goto read_from_sb;
			}
		}
		else
		{
			Debug(LDAP_DEBUG_ANY, catgets(slapdcat, 1, 1673, "Error while decoding Extended Response message"), NULL, NULL, NULL);
			ld->ld_errno = LDAP_DECODING_ERROR;
			return(-1);
		}
	}
	else if (( lr = find_request_by_msgid( ld, id )) == NULL ) 
	{
		Debug( LDAP_DEBUG_ANY, catgets(slapdcat, 1, 229, "no request for response with msgid %ld (tossing)\n"), id, 0, 0 );
		free( ber.ber_buf );	/* gack! */
		return( -2 );	/* continue looking */
	}

	if (tag == LDAP_RES_SEARCH_ENTRY)
		msgtypestr = catgets(slapdcat, 1, 1281, "search entry");
	else if (tag == LDAP_RES_SEARCH_REFERENCE)
		msgtypestr = catgets(slapdcat, 1, 1282, "search reference");
	else 
		msgtypestr = catgets(slapdcat, 1, 1283, "result");
	
	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 230, "got %1$s msgid %2$ld, original id %3$d\n"),
		   msgtypestr, id, lr->lr_origid );

	id = lr->lr_origid;

	/* REFERRALS HANDLING*/
	refer_cnt = 0;
	simple_request = 0;
	hadref = 0;
	rc = -2;	/* default is to keep looking (no response found) */
	lr->lr_res_msgtype = tag;

	if ( tag != LDAP_RES_SEARCH_ENTRY ) { /* If it's not an entry, ie it's a result or a reference */
		if ( ld->ld_version >= LDAP_VERSION2 &&
			    ( lr->lr_parent != NULL ||
				  ld->ld_follow_referral /* || ClientControl to follow referral present */ )) {
			tmpber = ber;
			if (tag == LDAP_RES_SEARCH_REFERENCE){
				/* LDAP V3 reference. Decode it */
				Debug(LDAP_DEBUG_TRACE, catgets(slapdcat, 1, -1, "LDAP search reference received. Will follow it later\n"),
					  0, 0,0);
				if (ber_scanf(&tmpber, "{v}", &theRefs) == LBER_ERROR){
					Debug ( LDAP_DEBUG_ANY, catgets(slapdcat, 1, 1284, "Error while decoding Search Reference Result message\n"),
							NULL, NULL, NULL);
					rc = -1;
					theRefs = NULL;
				} else {
					/* Store the referrals in request. We will follow them when the result arrives */
					Ref_AddToRequest(lr, theRefs);
					theRefs = NULL;
					free( ber.ber_buf );	/* gack! */
					ber.ber_buf = NULL;
					return (rc);
				}
			} else {
				if (ber_scanf( &tmpber, "{iaa", &lderr, &lr->lr_res_matched, &lr->lr_res_error) != LBER_ERROR){
					if (lderr == LDAP_PARTIAL_RESULTS){
						Debug(LDAP_DEBUG_TRACE, catgets(slapdcat, 1, -1, "LDAPv2 partial error received\n"), 0, 0,0);
						/* Ldapv2 referrals */
						theRefs = ldap_errormsg2referrals(lr->lr_res_error);
						ber_scanf(&tmpber, "}");
					} else if (lderr == LDAP_REFERRAL ){
						/* We have some referrals, decode them */
						Debug(LDAP_DEBUG_TRACE, catgets(slapdcat, 1, -1, "LDAPv3 referral error received\n"), 0, 0,0);
						if (ber_peek_tag ( &tmpber, &atag) == LDAP_TAG_REFERRAL){
							if (ber_scanf(&tmpber, "{v}}", &theRefs) == LBER_ERROR){
								Debug( LDAP_DEBUG_ANY, catgets(slapdcat, 1, 1285, "Error while decoding referrals in msg\n"),
									   NULL, NULL, NULL );
								rc = -1; /* ??? */
								theRefs = NULL;
							}
						} /* else error there should be at least one ref */						
					} else if (((lderr == LDAP_NO_SUCH_OBJECT) || 
							   (lderr == LDAP_BUSY) ||
							   (lderr == LDAP_UNAVAILABLE) ||
							   (lderr == LDAP_SERVER_DOWN) ||
							   (lderr == LDAP_CONNECT_ERROR)) && 
							   (lr->lr_parent != NULL) && /* its  subrequest */
							   (lr->lr_ref_tofollow != NULL)) { /* And it has some other referral to try */
						samereq = 1;
						theRefs = lr->lr_ref_tofollow;
						lr->lr_ref_tofollow = NULL;
						lrparent = lr->lr_parent;
						/* delete lr */
						free_request(ld, lr);
						/* lr now points on parent request */
						lr = lrparent;
						/* Follow referrals */
					} else {
						/* Here we have a simple result */
						hadref = lr->lr_outrefcnt;
					}
				} else {
					Debug( LDAP_DEBUG_ANY, catgets(slapdcat, 1, 1286, "Error while decoding result for request %$1d\n"),
						   lr->lr_origid, NULL, NULL);
					rc = -1; /* ??? */
				}
			}

			total_count = 0;
			if (tag != LDAP_RES_SEARCH_REFERENCE && lr->lr_references) {
				/* Some search references pending... Let's try to chase them */
				hadref = 1;
				theReferences = lr->lr_references;

				Debug(LDAP_DEBUG_TRACE, catgets(slapdcat, 1, -1, "Now following the search references received\n"),
					  0, 0,0);
				
				while (theReferences != NULL){
					if ((retcode = chase_referrals(ld, lr, theReferences->lref_refs , &refer_cnt, 0)) != LDAP_SUCCESS) {
						/* think about what to do */
						Debug( LDAP_DEBUG_ANY, catgets(slapdcat, 1, -1, "Error while chasing referral (%1$d)\n"),
							   retcode, NULL, NULL);
						theErrCode = LDAP_REFERRAL;
					}
					if (refer_cnt >= 0)
						total_count += refer_cnt;
					theReferences = theReferences->lref_next;
				}
				Ref_FreeAll(lr);
				if (theErrCode != LDAP_SUCCESS) {
					if (ld->ld_error != NULL && *ld->ld_error) {
						if (lr->lr_res_error)
							free(lr->lr_res_error);
						lr->lr_res_error = strdup(ld->ld_error);
					}
				}
				lr->lr_res_errno = theErrCode;
			}
			/* if theRefs != NULL we have some referrals to chase, do it */
			if (theRefs){
				hadref = 1;
				if ((retcode = chase_referrals(ld, lr, theRefs, &refer_cnt, samereq)) != LDAP_SUCCESS){
					/* think about what to do */
					Debug( LDAP_DEBUG_ANY, catgets(slapdcat, 1, -1, "Error while chasing referral (%1$d)\n"),
						   retcode, NULL, NULL);
				}
				
				if (refer_cnt >= 0)
					total_count += refer_cnt;

				ldap_value_free(theRefs);
				if (samereq){ /* Just tried another referral for same request */
					free(ber.ber_buf);
					ber.ber_buf = NULL;
					rc = -2;
					/* continue */
				}
				if (retcode != LDAP_SUCCESS) {
					if (ld->ld_version == LDAP_VERSION2){
						if (lr->lr_res_error)
							free(lr->lr_res_error);
						lr->lr_res_error = ldap_referral2error_msg(lr->lr_ref_unfollowed);
					} else if (ld->ld_error != NULL && *ld->ld_error) {
						if (lr->lr_res_error)
							free(lr->lr_res_error);
						lr->lr_res_error = strdup(ld->ld_error);
					}
				}
				lr->lr_res_errno = ld->ld_errno;
				
			}  else if (theErrCode == LDAP_SUCCESS) {
				/* no referral have been chased */
				lr->lr_res_errno = (lderr == LDAP_PARTIAL_RESULTS || lderr == LDAP_REFERRAL) ? LDAP_SUCCESS : lderr;
			}
			
			Debug( LDAP_DEBUG_TRACE,
				   catgets(slapdcat, 1, 231, "new result:  res_errno: %1$d, res_error: <%2$s>, res_matched: <%3$s>\n"),
				   lr->lr_res_errno, lr->lr_res_error ? lr->lr_res_error : "",
				   lr->lr_res_matched ? lr->lr_res_matched : "" );
		}
	
		
		Debug( LDAP_DEBUG_TRACE,
			   catgets(slapdcat, 1, 232, "read1msg:  %1$d new referrals\n"), total_count, 0, 0 );
		
		if ( refer_cnt != 0 ) {	/* chasing referrals */
			free( ber.ber_buf );	/* gack! */
			ber.ber_buf = NULL;
			if ( refer_cnt < 0 ) {
				return( -1 );	/* fatal error */
			}
			lr->lr_status = LDAP_REQST_CHASINGREFS;
		} else if (tag == LDAP_RES_SEARCH_REFERENCE && !ld->ld_follow_referral) {
			/* We had a ref and we don't follow referral : Do nothing there ?! */
			Debug( LDAP_DEBUG_TRACE,
				   catgets(slapdcat, 1, -1, "read1msg: returning search reference\n"), 0, 0, 0 );

		} else {
			/* No referral chasing */
			if ( lr->lr_outrefcnt <= 0 && lr->lr_parent == NULL ) {
				/* request without any referrals */
				simple_request = ( hadref ? 0 : 1 );
			} else {
				/* request with referrals or child request */
				free( ber.ber_buf );	/* gack! */
				ber.ber_buf = NULL;
			}


 			while ( lr->lr_parent != NULL ) {
 				merge_error_info( ld, lr->lr_parent, lr );
 				lr = lr->lr_parent;
 				if ( --lr->lr_outrefcnt > 0 ) {
 					break;	/* not completedly done yet */
 				}
 			}
			
			if ( lr->lr_outrefcnt <= 0 && lr->lr_parent == NULL ) { /* The main request has no more outstanding refs */
				id = lr->lr_msgid;
				tag = lr->lr_res_msgtype;
				Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 233, "request %1$ld done\n"),
				    id, 0, 0 );
				Debug( LDAP_DEBUG_TRACE,
					   catgets(slapdcat, 1, 234, "res_errno: %1$d, res_error: <%2$s>, res_matched: <%3$s>\n"),
					   lr->lr_res_errno, lr->lr_res_error ? lr->lr_res_error : "",
					   lr->lr_res_matched ? lr->lr_res_matched : "" );
				if ( !simple_request ) { /* We have to rebuild the result */
					if ( ber.ber_buf != NULL ) {
						free( ber.ber_buf ); /* gack! */
						ber.ber_buf = NULL;
					}
					if ( build_result_ber( ld, &ber, lr )
					    == LBER_ERROR ) {
						ld->ld_errno = LDAP_NO_MEMORY;
						rc = -1; /* fatal error */
					}
				}

				free_request( ld, lr );
			}

			if ( lc != NULL ) {
				free_connection( ld, lc, 0, 1 );
			}
		}
	}

	if ( ber.ber_buf == NULL ) { /* If the buffer has been freed, return */
		return( rc );
	}
	/* End of REFERRALS */

	/* make a new ldap message */
	if ( (new = (LDAPMessage *) calloc( 1, sizeof(LDAPMessage) ))
	    == NULL ) {
		ld->ld_errno = LDAP_NO_MEMORY;
		return( -1 );
	}
	new->lm_msgid = (int)id;
	new->lm_msgtype = tag;
	new->lm_ber = ber_dup( &ber );

#ifndef NO_CACHE
	if ( ld->ld_cache != NULL ) {
		add_result_to_cache( ld, new );
	}
#endif /* NO_CACHE */

	/* is this the one we're looking for? */
	if ( msgid == LDAP_RES_ANY || id == msgid ) {
		if ( all == LDAP_MSG_ONE	/* all apply only to search, so if not a search,return the val */
		    || (new->lm_msgtype != LDAP_RES_SEARCH_RESULT
				&& new->lm_msgtype != LDAP_RES_SEARCH_ENTRY
				&& new->lm_msgtype != LDAP_RES_SEARCH_REFERENCE) ) {
			*result = new;
			ld->ld_errno = LDAP_SUCCESS;
			return( tag );
		} else if ( new->lm_msgtype == LDAP_RES_SEARCH_RESULT) {
			foundit = 1;	/* return the chain later */
		}
	}

	/* 
	 * if not, we must add it to the list of responses.  if
	 * the msgid is already there, it must be part of an existing
	 * search response.
	 */

	prev = NULLMSG;
	for ( l = ld->ld_responses; l != NULLMSG; l = l->lm_next ) {
		if ( l->lm_msgid == new->lm_msgid )
			break;
		prev = l;
	}

	/* not part of an existing search response */
	if ( l == NULLMSG ) {
		if ( foundit ) { /* it a search result anyway, so return it */
			*result = new;
			ld->ld_errno = LDAP_SUCCESS;
			return( tag );
		}

		new->lm_next = ld->ld_responses;
		ld->ld_responses = new;
		return( -2 );	/* continue looking */
	}

	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 235, "adding response id %1$d type %2$d:\n"),
	    new->lm_msgid, new->lm_msgtype, 0 );

	/* part of a search response - add to end of list of entries or references */
	for ( tmp = l; tmp->lm_chain != NULLMSG &&
	    (tmp->lm_chain->lm_msgtype == LDAP_RES_SEARCH_ENTRY ||
		 tmp->lm_chain->lm_msgtype == LDAP_RES_SEARCH_REFERENCE);
	    tmp = tmp->lm_chain )
		;	/* NULL */
	tmp->lm_chain = new;

	/* return the whole chain if that's what we were looking for */
	if ( foundit ) {
		if ( prev == NULLMSG )
			ld->ld_responses = l->lm_next;
		else
			prev->lm_next = l->lm_next;
		*result = l;
		ld->ld_errno = LDAP_SUCCESS;
		return( l->lm_msgtype ); /* Patch 16 : was return(tag) */
	}

	return( -2 );	/* continue looking */
}


static int
build_result_ber( LDAP *ld, BerElement *ber, LDAPRequest *lr )
{
	unsigned int	len;
	int		along;

	Debug (LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 1287, "=> building_ber_error msgid %ld\n"), lr->lr_msgid, 0,0);
	ber_zero_init( ber, 0 );
	set_ber_options( ld, ber );
	if (ld->ld_version == LDAP_VERSION3){
		if ( ber_printf( ber, "{it{ess", 
						 lr->lr_msgid, 
						 lr->lr_res_msgtype,
						 lr->lr_res_errno,
						 lr->lr_res_matched ? lr->lr_res_matched : "",
						 lr->lr_res_error ? lr->lr_res_error : "" ) == LBER_ERROR){
			return (LBER_ERROR);
		}
		if (lr->lr_res_errno == LDAP_REFERRAL && 
			ber_printf(ber, "t{v}", LDAP_TAG_REFERRAL, lr->lr_ref_unfollowed) == LBER_ERROR){
			return (LBER_ERROR);
		}
		if (ber_printf(ber, "}}") == LBER_ERROR){
			return (LBER_ERROR);
		}
	} else {
		if ( ber_printf( ber, "{it{ess}}", 
						 lr->lr_msgid,
						 lr->lr_res_msgtype, 
						 lr->lr_res_errno,
						 lr->lr_res_matched ? lr->lr_res_matched : "",
						 lr->lr_res_error ? lr->lr_res_error : "" ) == LBER_ERROR ) {
			return( LBER_ERROR );
		}
	}
	
	ber_reset( ber, 1 );
	if ( ber_skip_tag( ber, &len ) == LBER_ERROR ) {
		return( LBER_ERROR );
	}

	if ( ber_get_int( ber, &along ) == LBER_ERROR ) {
		return( LBER_ERROR );
	}

	return( ber_peek_tag( ber, &len ));
}


static void
merge_error_info( LDAP *ld, LDAPRequest *parentr, LDAPRequest *lr )
{
	int i, j;
/*
 * Merge error information in "lr" with "parentr" error code and string.
 */
	if ( lr->lr_res_errno == LDAP_PARTIAL_RESULTS ) {
		parentr->lr_res_errno = lr->lr_res_errno;
		if ( lr->lr_res_error != NULL ) {
			(void)append_referral( ld, &parentr->lr_res_error,
			    lr->lr_res_error );
		}
	} else if ( lr->lr_res_errno != LDAP_SUCCESS &&
	    parentr->lr_res_errno == LDAP_SUCCESS ) {
		parentr->lr_res_errno = lr->lr_res_errno;
		if ( parentr->lr_res_error != NULL ) {
			free( parentr->lr_res_error );
		}
		parentr->lr_res_error = lr->lr_res_error;
		lr->lr_res_error = NULL;
		if ( NAME_ERROR( lr->lr_res_errno )) {
			if ( parentr->lr_res_matched != NULL ) {
				free( parentr->lr_res_matched );
			}
			parentr->lr_res_matched = lr->lr_res_matched;
			lr->lr_res_matched = NULL;
		}
		if (lr->lr_ref_unfollowed != NULL){
			for (i=0;lr->lr_ref_unfollowed[i] != NULL; i++);
			j = 0;
			if (parentr->lr_ref_unfollowed != NULL){
				for (j=0;parentr->lr_ref_unfollowed[j]!= NULL ;j++);
				j++;
			}
			parentr->lr_ref_unfollowed = (char **)realloc (parentr->lr_ref_unfollowed, (j+i+1) * sizeof(char *));
			if (parentr->lr_ref_unfollowed != NULL){
				for (i = 0; lr->lr_ref_unfollowed[i] != NULL; i++){
					parentr->lr_ref_unfollowed[j+i] = lr->lr_ref_unfollowed[i];
					lr->lr_ref_unfollowed[i] = NULL;
				}
				parentr->lr_ref_unfollowed[i+j+1] = NULL;
			} else {
				if (parentr->lr_res_errno == LDAP_SUCCESS)
					parentr->lr_res_errno =  LDAP_NO_MEMORY;
			}
		}
	}

	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 236, "merged parent (id %1$d) error info:  "),
	    parentr->lr_msgid, 0, 0 );
	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 237, "result errno %1$d, error <%2$s>, matched <%3$s>\n"),
		   parentr->lr_res_errno, 
		   parentr->lr_res_error ? parentr->lr_res_error : "", 
		   parentr->lr_res_matched ? parentr->lr_res_matched : "" );
}

#ifdef CLDAP
#if !defined( MACOS ) && !defined( DOS ) && !defined( _WIN32 )
static int
ldap_select1( LDAP *ld, struct timeval *timeout )
{
	fd_set		readfds;
	static int	tblsize;

	if ( tblsize == 0 ) {
#ifdef USE_SYSCONF
		tblsize = (int) sysconf( _SC_OPEN_MAX );
#else /* USE_SYSCONF */
		tblsize = getdtablesize();
#endif /* USE_SYSCONF */
	}

	FD_ZERO( &readfds );
	FD_SET( ld->ld_sb.sb_sd, &readfds );

	return( select( tblsize, &readfds, 0, 0, timeout ) );
}
#endif /* !MACOS */


#ifdef MACOS
static int
ldap_select1( LDAP *ld, struct timeval *timeout )
{
	return( tcpselect( ld->ld_sb.sb_sd, timeout ));
}
#endif /* MACOS */


#if ( defined( DOS ) && defined( WINSOCK )) || defined( _WIN32 )
static int
ldap_select1( LDAP *ld, struct timeval *timeout )
{
    fd_set          readfds;
    int             rc;

    FD_ZERO( &readfds );
    FD_SET( ld->ld_sb.sb_sd, &readfds );

    rc = select( 1, &readfds, 0, 0, timeout );
    return( rc == SOCKET_ERROR ? -1 : rc );
}
#endif /* WINSOCK || _WIN32 */


#ifdef DOS
#ifdef PCNFS
static int
ldap_select1( LDAP *ld, struct timeval *timeout )
{
	fd_set	readfds;
	int	res;

	FD_ZERO( &readfds );
	FD_SET( ld->ld_sb.sb_sd, &readfds );

	res = select( FD_SETSIZE, &readfds, NULL, NULL, timeout );
	if ( res == -1 && errno == EINTR) {
		/* We've been CTRL-C'ed at this point.  It'd be nice to
		   carry on but PC-NFS currently won't let us! */
		printf("\n*** CTRL-C ***\n");
		exit(-1);
	}
	return( res );
}
#endif /* PCNFS */

#ifdef NCSA
static int
ldap_select1( LDAP *ld, struct timeval *timeout )
{
	int rc;
	clock_t	endtime;

	if ( timeout != NULL ) {
		endtime = timeout->tv_sec * CLK_TCK +
			timeout->tv_usec * CLK_TCK / 1000000 + clock();
	}

	do {
		Stask();
		rc = netqlen( ld->ld_sb.sb_sd );
	} while ( rc <= 0 && ( timeout == NULL || clock() < endtime ));

	return( rc > 0 ? 1 : 0 );
}
#endif /* NCSA */
#endif /* DOS */
#endif /* CLDAP */


int
ldap_msgfree( LDAPMessage *lm )
{
	LDAPMessage	*next;
	int		type = 0;

	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 238, "ldap_msgfree\n"), 0, 0, 0 );

	for ( ; lm != NULLMSG; lm = next ) {
		next = lm->lm_chain;
		type = lm->lm_msgtype;
		if (lm->lm_ber) 
			ber_free( lm->lm_ber, 1 );
		free( (char *) lm );
	}

	return( type );
}

/*
 * ldap_msgdelete - delete a message.  It returns:
 *	0	if the entire message was deleted
 *	-1	if the message was not found, or only part of it was found
 */
int
ldap_msgdelete( LDAP *ld, int msgid )
{
	LDAPMessage	*lm, *prev;

#ifdef _REENTRANT
	LOCK_LDAP(ld);
	LOCK_RESPONSE(ld);
#endif
	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 239, "ldap_msgdelete\n"), 0, 0, 0 );

	prev = NULLMSG;
	for ( lm = ld->ld_responses; lm != NULLMSG; lm = lm->lm_next ) {
		if ( lm->lm_msgid == msgid )
			break;
		prev = lm;
	}

	if ( lm == NULLMSG ) {
#ifdef _REENTRANT
		UNLOCK_LDAP(ld);
		UNLOCK_RESPONSE(ld);
#endif
		return( -1 );
	}

	if ( prev == NULLMSG )
		ld->ld_responses = lm->lm_next;
	else
		prev->lm_next = lm->lm_next;

	if ( ldap_msgfree( lm ) == LDAP_RES_SEARCH_ENTRY ) {
#ifdef _REENTRANT
		UNLOCK_LDAP(ld);
		UNLOCK_RESPONSE(ld);
#endif
		return( -1 );
	}

#ifdef _REENTRANT
	UNLOCK_LDAP(ld);
	UNLOCK_RESPONSE(ld);
#endif
	return( 0 );
}


/*
 * return 1 if message msgid is waiting to be abandoned, 0 otherwise
 */
static int
ldap_abandoned( LDAP *ld, int msgid )
{
	int	i;

	if ( ld == NULL ) return(1);
	if ( ld->ld_abandoned == NULL )
		return( 0 );

	for ( i = 0; ld->ld_abandoned[i] != -1; i++ )
		if ( ld->ld_abandoned[i] == msgid )
			return( 1 );

	return( 0 );
}


static int
ldap_mark_abandoned( LDAP *ld, int msgid )
{
	int	i;

	if ( ld->ld_abandoned == NULL )
		return( -1 );

	for ( i = 0; ld->ld_abandoned[i] != -1; i++ )
		if ( ld->ld_abandoned[i] == msgid )
			break;

	if ( ld->ld_abandoned[i] == -1 )
		return( -1 );

	for ( ; ld->ld_abandoned[i] != -1; i++ ) {
		ld->ld_abandoned[i] = ld->ld_abandoned[i + 1];
	}

	return( 0 );
}


#ifdef CLDAP
int
cldap_getmsg( LDAP *ld, struct timeval *timeout, BerElement *ber )
{
	int		rc;
	unsigned int	tag, len;

#ifdef _REENTRANT
	LOCK_LDAP(ld);
#endif
	if ( ld->ld_sb.sb_ber.ber_ptr >= ld->ld_sb.sb_ber.ber_end ) {
		rc = ldap_select1( ld, timeout );
		if ( rc == -1 || rc == 0 ) {
			ld->ld_errno = (rc == -1 ? LDAP_SERVER_DOWN :
			    LDAP_TIMEOUT);
#ifdef _REENTRANT
			UNLOCK_LDAP(ld);
#endif
			return( rc );
		}
	}

	/* get the next message */
	if ( (tag = ber_get_next( &ld->ld_sb, &len, ber ))
	    != LDAP_TAG_MESSAGE ) {
		ld->ld_errno = (tag == LBER_DEFAULT ? LDAP_SERVER_DOWN :
		    LDAP_LOCAL_ERROR);
#ifdef _REENTRANT
		UNLOCK_LDAP(ld);
#endif
		return( -1 );
	}

#ifdef _REENTRANT
	UNLOCK_LDAP(ld);
#endif
	return( tag );
}
#endif /* CLDAP */

/* ldapv3 API extensions */

int ldap_msgtype(LDAPMessage *res)
{
	if (res == NULL)
		return (LDAP_RES_ANY);
	return (res->lm_msgtype);
}


int ldap_msgid(LDAPMessage *res)
{
	if (res == NULL)
		return (LDAP_RES_ANY);
	return (res->lm_msgid);
}

int ldap_parse_result(LDAP *ld, LDAPMessage *res, int *errcodep, char **matcheddnp,
					  char **errmsgp, char ***referralsp, LDAPControl ***serverctrlsp,
					  int freeit)
{
	LDAPMessage *lm;
	BerElement ber;
	unsigned int alen;
	int along;
	unsigned int tag;
	int i;
	size_t rc;
	char * acharp = NULL, * a2ndcharp = NULL;
	char ** arefs = NULL;
	
	Debug( LDAP_DEBUG_TRACE, "ldap_parse_result\n", 0, 0, 0 );

	if (res == NULLMSG)
		return (LDAP_PARAM_ERROR);

	if (matcheddnp && *matcheddnp){
		free(*matcheddnp);
		*matcheddnp = NULL;
	}
	if (errmsgp && *errmsgp){
		free(*errmsgp);
		*errmsgp = NULL;
	}
	if (referralsp && *referralsp){
		free_strarray(*referralsp);
		*referralsp = NULL;
	}
	
	if (serverctrlsp && *serverctrlsp){
		ldap_controls_free(*serverctrlsp);
		*serverctrlsp = NULL;
	}
	
	for (lm = res; lm->lm_chain != NULL; lm = lm->lm_chain)

		if ( lm->lm_msgtype != LDAP_RES_SEARCH_ENTRY 
			 && lm->lm_msgtype != LDAP_RES_SEARCH_REFERENCE)
			break;

	ber = *(lm->lm_ber);
	
#ifdef _REENTRANT
	LOCK_LDAP(ld);
#endif
	if (ld->ld_version == LDAP_VERSION3) {
		rc = ber_scanf( &ber, "{iaa", &along, &acharp, &a2ndcharp);
		if (rc == LBER_ERROR){
			if (freeit)
				ldap_msgfree( res );
#ifdef _REENTRANT
			UNLOCK_LDAP(ld);
#endif
			return (LDAP_DECODING_ERROR);
		}
		if (matcheddnp) {
			*matcheddnp = acharp;
		} else {
			ldap_memfree(acharp);
		}
		if (errmsgp) {
			*errmsgp = a2ndcharp;
		} else {
			ldap_memfree(a2ndcharp);
		}
				
		if (errcodep) {
			*errcodep = along;
		}

		if (along == LDAP_REFERRAL){
			if (ber_peek_tag ( &ber, &tag) == LDAP_TAG_REFERRAL) {
				rc = ber_scanf(&ber, "{v}", &arefs);
				if (rc == LBER_ERROR){
					/* try to free other stuff */
					if (freeit)
						ldap_msgfree( res );
#ifdef _REENTRANT
					UNLOCK_LDAP(ld);
#endif
					return (LDAP_DECODING_ERROR);
				}
				if (referralsp) {
					*referralsp = arefs;
				} else {
					for (i = 0; arefs[i] != NULL; i++)
						ldap_memfree(arefs[i]);
					ldap_memfree((char *)arefs);
				}
			} else {
				/* referral errcode without URL is forbiden */
				if (freeit)
					ldap_msgfree( res );
#ifdef _REENTRANT
				UNLOCK_LDAP(ld);
#endif
				return (LDAP_DECODING_ERROR);
			}
		}
		rc = ber_scanf(&ber, "}");
		if (rc == LBER_ERROR){
			if (freeit)
				ldap_msgfree( res );
#ifdef _REENTRANT
			UNLOCK_LDAP(ld);
#endif
			return (LDAP_DECODING_ERROR);
		}
		/* It's the end of the result but the PDU may have controls */
		if (serverctrlsp && (ber_peek_tag(&ber, &alen) == LDAP_TAG_CONTROL_LIST)) {
			Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 392, "Controls found in result\n"), 0, 0, 0 );
			*serverctrlsp =  ldap_controls_decode(&ber,
							    (int *)&rc);
			if (*serverctrlsp == NULL) {
				if (freeit)
					ldap_msgfree( res );
#ifdef _REENTRANT
				UNLOCK_LDAP(ld);
#endif
				return (LDAP_DECODING_ERROR);
			}
		} else {
			Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 393, "NO controls found in result\n"), 0, 0, 0 );
		}
	}
	else if (ld->ld_version == LDAP_VERSION2) {
		rc = ber_scanf( &ber, "{iaa}", &along, &acharp,
		     &a2ndcharp );
		if (rc == LBER_ERROR){
			if (freeit)
				ldap_msgfree( res );
#ifdef _REENTRANT
			UNLOCK_LDAP(ld);
#endif
			return (LDAP_DECODING_ERROR);
		}
		if (matcheddnp) {
			*matcheddnp = acharp;
		} else {
			ldap_memfree(acharp);
		}
		if (errmsgp) {
			*errmsgp = a2ndcharp;
		} else {
			ldap_memfree(a2ndcharp);
		}
		if (errcodep) {
			*errcodep = along;
		}
	}
	else {
		rc = ber_scanf( &ber, "{ia}", &along, &a2ndcharp );
		if (rc == LBER_ERROR){
			if (freeit)
				ldap_msgfree( res );
#ifdef _REENTRANT
			UNLOCK_LDAP(ld);
#endif
			return (LDAP_DECODING_ERROR);
		}
		
		if (errmsgp) {
			*errmsgp = a2ndcharp;
		} else {
			ldap_memfree(a2ndcharp);
		}
		if (errcodep) {
			*errcodep = along;
		}
	}
	
	if ( freeit )
		ldap_msgfree(res);
	
#ifdef _REENTRANT
	UNLOCK_LDAP(ld);
#endif
	return (LDAP_SUCCESS);
}

int ldap_parse_sasl_bind_result(LDAP *ld, LDAPMessage *res, struct berval **servercredp, int freeit)
{
	LDAPMessage *lm;
	BerElement ber;
	int along;
	unsigned int tag;
	int i;
	size_t rc;
	char * acharp = NULL, *a2ndcharp = NULL;
	char ** arefs = NULL;
	struct berval * creds = NULL;
	
	Debug( LDAP_DEBUG_TRACE, "ldap_parse_extended_result\n", 0, 0, 0 );

	if (res == NULLMSG)
		return (LDAP_PARAM_ERROR);
	
#ifdef _REENTRANT
	LOCK_LDAP(ld);
#endif
	if ((res->lm_msgtype != LDAP_RES_BIND) || (ld->ld_version != LDAP_VERSION3)){
		ld->ld_errno = LDAP_PARAM_ERROR;
#ifdef _REENTRANT
		UNLOCK_LDAP(ld);
#endif
		return (LDAP_PARAM_ERROR);
	}
#ifdef _REENTRANT
	UNLOCK_LDAP(ld);
#endif
	
	ber = *(res->lm_ber);
	rc = ber_scanf( &ber, "{iaa", &along, &acharp, &a2ndcharp);
	if (rc == LBER_ERROR){
		if (freeit)
			ldap_msgfree( res );
#ifdef _REENTRANT
		LOCK_LDAP(ld);
#endif
		ld->ld_errno = LDAP_DECODING_ERROR;
#ifdef _REENTRANT
		UNLOCK_LDAP(ld);
#endif
		return (LDAP_DECODING_ERROR);
	}
	ldap_memfree(acharp);
	ldap_memfree(a2ndcharp);
	if (along == LDAP_SUCCESS || along == LDAP_SASL_BIND_INPROGRESS){
		/* Decode the serverSaslCreds if any */
		if (ber_peek_tag ( &ber, &tag) == LDAP_TAG_SASLCREDS) {
			rc = ber_get_stringal( &ber, &creds);
			if (rc == LBER_ERROR ){
				if (freeit)
					ldap_msgfree(res);
#ifdef _REENTRANT
				LOCK_LDAP(ld);
#endif
				ld->ld_errno = LDAP_DECODING_ERROR;
#ifdef _REENTRANT
				UNLOCK_LDAP(ld);
#endif
				return (LDAP_DECODING_ERROR);
			}
			if (servercredp) {
				*servercredp = creds;
			} else {
				ber_bvfree( creds );
			}
		}
	} else if (along == LDAP_REFERRAL) {
		if (ber_peek_tag ( &ber, &tag) == LDAP_TAG_REFERRAL){
			rc = ber_scanf(&ber, "{v}", &arefs);
			if (rc == LBER_ERROR){
				/* try to free other stuff */
				if (freeit)
					ldap_msgfree( res );
#ifdef _REENTRANT
				LOCK_LDAP(ld);
#endif
				ld->ld_errno = LDAP_DECODING_ERROR;
#ifdef _REENTRANT
				UNLOCK_LDAP(ld);
#endif
				return (LDAP_DECODING_ERROR);
			}
			for (i = 0; arefs[i] != NULL; i++)
				ldap_memfree(arefs[i]);
			ldap_memfree((char *)arefs);
		} else {
			/* There should be at least one ref */
			if (freeit)
				ldap_msgfree( res );
#ifdef _REENTRANT
			LOCK_LDAP(ld);
#endif
			ld->ld_errno = LDAP_DECODING_ERROR;
#ifdef _REENTRANT
			UNLOCK_LDAP(ld);
#endif
			return (LDAP_DECODING_ERROR);
		}
	}
		
	rc = ber_scanf(&ber, "}");
	if (rc == LBER_ERROR){
		if (freeit)
			ldap_msgfree( res );
#ifdef _REENTRANT
		LOCK_LDAP(ld);
#endif
		ld->ld_errno = LDAP_DECODING_ERROR;
#ifdef _REENTRANT
		UNLOCK_LDAP(ld);
#endif
		return (LDAP_DECODING_ERROR);
	}
	
	if ( freeit )
		ldap_msgfree(res);
#ifdef _REENTRANT
	LOCK_LDAP(ld);
#endif
	ld->ld_errno = along;
#ifdef _REENTRANT
	UNLOCK_LDAP(ld);
#endif
	return (along);
}

int ldap_parse_extended_result(LDAP *ld, LDAPMessage *res, char **resultoidp, 
							   struct berval **resultdata, int freeit)
{
	LDAPMessage *lm;
	BerElement ber;
	int along;
	unsigned int tag;
	int i;
	size_t rc;
	char * acharp = NULL, *a2ndcharp = NULL, *anoid = NULL;
	char **arefs = NULL;
	struct berval * aresp = NULL;
	
	Debug( LDAP_DEBUG_TRACE, "ldap_parse_sasl_bind_result\n", 0, 0, 0 );

	if ( res == NULLMSG )
		return (LDAP_PARAM_ERROR);
		
#ifdef _REENTRANT
	LOCK_LDAP(ld);
#endif
	if ((res->lm_msgtype != LDAP_RES_EXTENDED) || (ld->ld_version != LDAP_VERSION3))
	{
		if ( res->lm_msgid != 0 )
#ifdef _REENTRANT
			UNLOCK_LDAP(ld);
#endif
			return (LDAP_PARAM_ERROR);
	}
#ifdef _REENTRANT
	UNLOCK_LDAP(ld);
#endif
	
	ber = *(res->lm_ber);
	rc = ber_scanf( &ber, "{iaa", &along, &acharp, &a2ndcharp);
	if (rc == LBER_ERROR){
		if (freeit)
			ldap_msgfree( res );
		return (LDAP_DECODING_ERROR);
	}
	ldap_memfree(acharp);
	ldap_memfree(a2ndcharp);

	if (along == LDAP_REFERRAL) {
		if (ber_peek_tag ( &ber, &tag) == LDAP_TAG_REFERRAL){
			rc = ber_scanf(&ber, "{v}", &arefs);
			if (rc == LBER_ERROR){
				/* try to free other stuff */
				if (freeit)
					ldap_msgfree( res );
				return (LDAP_DECODING_ERROR);
			}
			for (i = 0; arefs[i] != NULL; i++)
				ldap_memfree(arefs[i]);
			ldap_memfree((char *)arefs);
		} else {
			/* There should be at least one ref */
			if (freeit)
				ldap_msgfree( res );
			return (LDAP_DECODING_ERROR);
		}
	}

	if (ber_peek_tag ( &ber, &tag) == LDAP_TAG_EXT_RESPNAME) {
		rc = ber_get_stringa( &ber, &anoid);
		if (rc == LBER_ERROR ){
			if (freeit)
				ldap_msgfree(res);
			return (LDAP_DECODING_ERROR);
		}
		if (resultoidp) {
			*resultoidp = anoid;
		} else {
			ldap_memfree( anoid );
		}
	}
	if (ber_peek_tag ( &ber, &tag) == LDAP_TAG_EXT_RESPONSE) {
		rc = ber_get_stringal( &ber, &aresp);
		if (rc == LBER_ERROR ){
			if (freeit)
				ldap_msgfree(res);
			return (LDAP_DECODING_ERROR);
		}
		if (resultdata) {
			*resultdata = aresp;
		} else {
			ber_bvfree( aresp );
		}
	}
		
	rc = ber_scanf(&ber, "}");
	if (rc == LBER_ERROR){
		if (freeit)
			ldap_msgfree( res );
		return (LDAP_DECODING_ERROR);
	}
	
	if ( freeit )
		ldap_msgfree(res);
	
	return (along);
}


static int Ref_AddToRequest(LDAPRequest *lr, char **refs) {
	int count;
	LDAPRef *lref;
	LDAPRef *newRef;
	
	if ((newRef = (LDAPRef *)calloc(1, sizeof (LDAPRef))) == NULL){
		return LDAP_NO_MEMORY;
	}
	newRef->lref_refs = refs;
	newRef->lref_next = NULL;
	lref = lr->lr_references;
	if (lref == NULL){
		lr->lr_references = newRef;
	} else {
		while (lref->lref_next != NULL)
			lref = lref->lref_next;
		lref->lref_next = newRef;
	}
	return LDAP_SUCCESS;
}

static void Ref_FreeAll(LDAPRequest *lr)
{
	LDAPRef *lref, *next;
	lref = lr->lr_references;
	while (lref != NULL){
		next = lref->lref_next;
		ldap_value_free(lref->lref_refs);
		free (lref);
		lref = next;
	}
	lr->lr_references = NULL;
}
