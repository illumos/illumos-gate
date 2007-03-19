/*
 * Portions Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 *  Copyright (c) 1993 The Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  cache.c - local caching support for LDAP
 */

#ifndef NO_CACHE

#ifndef lint 
static char copyright[] = "@(#) Copyright (c) 1993 The Regents of the University of Michigan.\nAll rights reserved.\n";
#endif

#include <stdio.h>
#include <string.h>
#ifdef MACOS
#include <stdlib.h>
#include <time.h>
#include "macos.h"
#else /* MACOS */
#if defined( DOS ) || defined( _WIN32 )
#include <malloc.h>
#include "msdos.h"
#ifdef NCSA
#include "externs.h"
#endif /* NCSA */
#ifdef WINSOCK
#include <time.h>
#endif /* WINSOCK */
#else /* DOS */
#include <sys/types.h>
#include <sys/socket.h>
#endif /* DOS */
#endif /* MACOS */
#include "lber.h"
#include "ldap.h"
#include "ldap-private.h"
#include "ldap-int.h"

#ifdef NEEDPROTOS
static int		cache_hash( BerElement *ber );
static LDAPMessage	*msg_dup( LDAPMessage *msg );
static int		request_cmp( BerElement	*req1, BerElement *req2 );
static int		chain_contains_dn( LDAPMessage *msg, char *dn );
static ssize_t msg_size( LDAPMessage *msg );
static void		check_cache_memused( LDAPCache *lc );
static void		uncache_entry_or_req( LDAP *ld, char *dn, int msgid );
#else /* NEEDPROTOS */
static int		cache_hash();
static LDAPMessage	*msg_dup();
static int		request_cmp();
static int		chain_contains_dn();
static ssize_t		msg_size();
static void		check_cache_memused();
static void		uncache_entry_or_req();
#endif /* NEEDPROTOS */


int
ldap_enable_cache( LDAP *ld, time_t timeout, ssize_t maxmem )
{
#if defined( SUN ) && defined( _REENTRANT )
	LOCK_LDAP(ld);
#endif	
	if ( ld->ld_cache == NULLLDCACHE ) {
		if (( ld->ld_cache = (LDAPCache *)malloc( sizeof( LDAPCache )))
		    == NULLLDCACHE ) {
			ld->ld_errno = LDAP_NO_MEMORY;
#if defined( SUN ) && defined( _REENTRANT )
			UNLOCK_LDAP(ld);
#endif
			return( -1 );
		}
		(void) memset( ld->ld_cache, 0, sizeof( LDAPCache ));
		ld->ld_cache->lc_memused = sizeof( LDAPCache );
	}

	ld->ld_cache->lc_timeout = timeout;
	ld->ld_cache->lc_maxmem = maxmem;
	check_cache_memused( ld->ld_cache );
	ld->ld_cache->lc_enabled = 1;
#if defined( SUN ) && defined( _REENTRANT )
	UNLOCK_LDAP(ld);
#endif
	return( 0 );
}


void
ldap_disable_cache( LDAP *ld )
{
#if defined( SUN ) && defined( _REENTRANT )
	LOCK_LDAP(ld);
#endif	
	if ( ld->ld_cache != NULLLDCACHE ) {
		ld->ld_cache->lc_enabled = 0;
	}
#if defined( SUN ) && defined( _REENTRANT )
	UNLOCK_LDAP(ld);
#endif
}



void
ldap_set_cache_options( LDAP *ld, unsigned int opts )
{
#if defined( SUN ) && defined( _REENTRANT )
	LOCK_LDAP(ld);
#endif	
	if ( ld->ld_cache != NULLLDCACHE ) {
		ld->ld_cache->lc_options = opts;
	}
#if defined( SUN ) && defined( _REENTRANT )
	UNLOCK_LDAP(ld);
#endif
}
	

void
ldap_destroy_cache( LDAP *ld )
{
#if defined( SUN ) && defined( _REENTRANT )
	LOCK_LDAP(ld);
#endif	
	if ( ld->ld_cache != NULLLDCACHE ) {
		ldap_flush_cache( ld );
		free( (char *)ld->ld_cache );
		ld->ld_cache = NULLLDCACHE;
	}
#if defined( SUN ) && defined( _REENTRANT )
	UNLOCK_LDAP(ld);
#endif
}


void
ldap_flush_cache( LDAP *ld )
{
	int		i;
	LDAPMessage	*m, *next;

#if defined( SUN ) && defined( _REENTRANT )
	LOCK_LDAP(ld);
#endif	
	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 90, "ldap_flush_cache\n"), 0, 0, 0 );

	if ( ld->ld_cache != NULLLDCACHE ) {
		/* delete all requests in the queue */
		for ( m = ld->ld_cache->lc_requests; m != NULLMSG; m = next ) {
			next = m->lm_next;
			ldap_msgfree( m );
		}
		ld->ld_cache->lc_requests = NULLMSG;

		/* delete all messages in the cache */
		for ( i = 0; i < LDAP_CACHE_BUCKETS; ++i ) {
			for ( m = ld->ld_cache->lc_buckets[ i ];
			    m != NULLMSG; m = next ) {
				next = m->lm_next;
				ldap_msgfree( m );
			}
			ld->ld_cache->lc_buckets[ i ] = NULLMSG;
		}
		ld->ld_cache->lc_memused = sizeof( LDAPCache );
	}
#if defined( SUN ) && defined( _REENTRANT )
	UNLOCK_LDAP(ld);
#endif
}


void
ldap_uncache_request( LDAP *ld, int msgid )
{
#if defined( SUN ) && defined( _REENTRANT )
	LOCK_LDAP(ld);
#endif	
	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 91, "ldap_uncache_request %1$d ld_cache %2$x\n"),
	    msgid, ld->ld_cache, 0 );

	uncache_entry_or_req( ld, NULL, msgid );
#if defined( SUN ) && defined( _REENTRANT )
	UNLOCK_LDAP(ld);
#endif
}


void
ldap_uncache_entry( LDAP *ld, char *dn )
{
#if defined( SUN ) && defined( _REENTRANT )
	LOCK_LDAP(ld);
#endif	
	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 92, "ldap_uncache_entry %1$s ld_cache %2$x\n"),
	    dn, ld->ld_cache, 0 );

	uncache_entry_or_req( ld, dn, 0 );
#if defined( SUN ) && defined( _REENTRANT )
	UNLOCK_LDAP(ld);
#endif
}


static void
uncache_entry_or_req( LDAP *ld,
	char *dn,		/* if non-NULL, uncache entry */
	int msgid )		/* request to uncache (if dn == NULL) */
{
	int		i;
	LDAPMessage	*m, *prev, *next;

	Debug( LDAP_DEBUG_TRACE,
	    catgets(slapdcat, 1, 93, "ldap_uncache_entry_or_req  dn %1$s  msgid %2$d  ld_cache %3$x\n"),
	    dn, msgid, ld->ld_cache );

	if ( ld->ld_cache == NULLLDCACHE ) {
	    return;
	}

	/* first check the request queue */
	prev = NULLMSG;
	for ( m = ld->ld_cache->lc_requests; m != NULLMSG; m = next ) {
		next = m->lm_next;
		if (( dn != NULL && chain_contains_dn( m, dn )) ||
			( dn == NULL && m->lm_msgid == msgid )) {
			if ( prev == NULLMSG ) {
				ld->ld_cache->lc_requests = next;
			} else {
				prev->lm_next = next;
			}
			ld->ld_cache->lc_memused -= msg_size( m );
			ldap_msgfree( m );
		} else {
			prev = m;
		}
	}

	/* now check the rest of the cache */
	for ( i = 0; i < LDAP_CACHE_BUCKETS; ++i ) {
		prev = NULLMSG;
		for ( m = ld->ld_cache->lc_buckets[ i ]; m != NULLMSG;
		    m = next ) {
			next = m->lm_next;
			if (( dn != NULL && chain_contains_dn( m, dn )) ||
				( dn == NULL && m->lm_msgid == msgid )) {
				if ( prev == NULLMSG ) {
					ld->ld_cache->lc_buckets[ i ] = next;
				} else {
					prev->lm_next = next;
				}
				ld->ld_cache->lc_memused -= msg_size( m );
				ldap_msgfree( m );
			} else {
				prev = m;
			}
		}
	}
}


void
add_request_to_cache( LDAP *ld, unsigned int msgtype, BerElement *request )
{
	LDAPMessage	*new;
	size_t		len;

	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 94, "add_request_to_cache\n"), 0, 0, 0 );

	ld->ld_errno = LDAP_SUCCESS;
	if ( ld->ld_cache == NULLLDCACHE ||
	    ( ld->ld_cache->lc_enabled == 0 )) {
		return;
	}

	if (( new = (LDAPMessage *) calloc( 1, sizeof(LDAPMessage) ))
	    != NULL ) {
		if (( new->lm_ber = alloc_ber_with_options( ld )) == NULLBER ) {
			free( (char *)new );
			return;
		}
		len = request->ber_ptr - request->ber_buf;
		if (( new->lm_ber->ber_buf = (char *) malloc( len ))
		    == NULL ) {
			ber_free( new->lm_ber, 0 );
			free( (char *)new );
			ld->ld_errno = LDAP_NO_MEMORY;
			return;
		}
		SAFEMEMCPY( new->lm_ber->ber_buf, request->ber_buf, len );
		new->lm_ber->ber_ptr = new->lm_ber->ber_buf;
		new->lm_ber->ber_end = new->lm_ber->ber_buf + len;
		new->lm_msgid = ld->ld_msgid;
		new->lm_msgtype = (int) msgtype;;
		new->lm_next = ld->ld_cache->lc_requests;
		ld->ld_cache->lc_requests = new;
	} else {
		ld->ld_errno = LDAP_NO_MEMORY;
	}
}


void
add_result_to_cache( LDAP *ld, LDAPMessage *result )
{
	LDAPMessage	*m, **mp, *req, *new, *prev;
	int		err, keep;

	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 95, "add_result_to_cache: id %1$d, type %2$d\n"), 
		result->lm_msgid, result->lm_msgtype, 0 );

	if ( ld->ld_cache == NULLLDCACHE ||
	    ( ld->ld_cache->lc_enabled == 0 )) {
		Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 96, "artc: cache disabled\n"), 0, 0, 0 );
		return;
	}

	if ( result->lm_msgtype != LDAP_RES_SEARCH_ENTRY &&
	    result->lm_msgtype != LDAP_RES_SEARCH_RESULT &&
	    result->lm_msgtype != LDAP_RES_SEARCH_REFERENCE &&
	    result->lm_msgtype != LDAP_RES_COMPARE ) {
		/*
		 * only cache search and compare operations
		 */
		Debug( LDAP_DEBUG_TRACE,
		    catgets(slapdcat, 1, 97, "artc: only caching search & compare operations\n"), 0, 0, 0 );
		return;
	}

	/*
	 * if corresponding request is in the lc_requests list, add this
	 * result to it.  if this result completes the results for the
	 * request, add the request/result chain to the cache proper.
	 */
	prev = NULLMSG;
	for ( m = ld->ld_cache->lc_requests; m != NULL; m = m->lm_next ) {
		if ( m->lm_msgid == result->lm_msgid ) {
			break;
		}
		prev = m;
	}

	if ( m != NULLMSG ) {	/* found request; add to end of chain */
		req = m;
		for ( ; m->lm_chain != NULLMSG; m = m->lm_chain )
			;
		if (( new = msg_dup( result )) != NULLMSG ) {
			new->lm_chain = NULLMSG;
			m->lm_chain = new;
			Debug( LDAP_DEBUG_TRACE,
			    catgets(slapdcat, 1, 98, "artc: result added to cache request chain\n"),
			    0, 0, 0 );
		}
		if ( result->lm_msgtype == LDAP_RES_SEARCH_RESULT ||
		    result->lm_msgtype == LDAP_RES_COMPARE ) {
			/*
			 * this result completes the chain of results
			 * add to cache proper if appropriate
			 */
			keep = 0;	/* pessimistic */
			err = ldap_result2error( ld, result, 0 );
			if ( err == LDAP_SUCCESS ||
			    ( result->lm_msgtype == LDAP_RES_COMPARE &&
			    ( err == LDAP_COMPARE_FALSE ||
			    err == LDAP_COMPARE_TRUE ||
			    err == LDAP_NO_SUCH_ATTRIBUTE ))) {
				keep = 1;
			}

			if ( ld->ld_cache->lc_options == 0 ) {
				if ( err == LDAP_SIZELIMIT_EXCEEDED ) {
				    keep = 1;
				}
			} else if (( ld->ld_cache->lc_options &
				LDAP_CACHE_OPT_CACHEALLERRS ) != 0 ) {
				keep = 1;
			}

			if ( prev == NULLMSG ) {
				ld->ld_cache->lc_requests = req->lm_next;
			} else {
				prev->lm_next = req->lm_next;
			}

			if ( !keep ) {
				Debug( LDAP_DEBUG_TRACE,
				    catgets(slapdcat, 1, 99, "artc: not caching result with error %d\n"),
				    err, 0, 0 );
				ldap_msgfree( req );
			} else {
				mp = &ld->ld_cache->lc_buckets[
				    cache_hash( req->lm_ber ) ];
				req->lm_next = *mp;
				*mp = req;
				req->lm_time = time( NULL );
				ld->ld_cache->lc_memused += msg_size( req );
				check_cache_memused( ld->ld_cache );
				Debug( LDAP_DEBUG_TRACE,
				    catgets(slapdcat, 1, 100, "artc: cached result with error %d\n"),
				    err, 0, 0 );
			}
		}
	} else {
		Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 101, "artc: msgid not in request list\n"),
		    0, 0, 0 );
	}
}


/*
 * look in the cache for this request
 * return 0 if found, -1 if not
 * if found, the corresponding result messages are added to the incoming
 * queue with the correct (new) msgid so that subsequent ldap_result calls
 * will find them.
 */
int
check_cache( LDAP *ld, unsigned int msgtype, BerElement *request )
{
	LDAPMessage	*m, *new, *prev, *next;
	BerElement	reqber;
	int		first, hash;
	unsigned long	validtime;

	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 102, "check_cache\n"), 0, 0, 0 );

	if ( ld->ld_cache == NULLLDCACHE ||
	    ( ld->ld_cache->lc_enabled == 0 )) {
		return( -1 );
	}

	reqber.ber_buf = reqber.ber_ptr = request->ber_buf;
	reqber.ber_end = request->ber_ptr;

	validtime = time( NULL ) - ld->ld_cache->lc_timeout;

	prev = NULLMSG;
	hash = cache_hash( &reqber );
	for ( m = ld->ld_cache->lc_buckets[ hash ]; m != NULLMSG; m = next ) {
		Debug( LDAP_DEBUG_TRACE,catgets(slapdcat, 1, 103, "cc: examining id %1$d,type %2$d\n"),
		    m->lm_msgid, m->lm_msgtype, 0 );
		if ( m->lm_time < validtime ) {
			/* delete expired message */
			next = m->lm_next;
			if ( prev == NULL ) {
				ld->ld_cache->lc_buckets[ hash ] = next;
			} else {
				prev->lm_next = next;
			}
			Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 104, "cc: expired id %d\n"),
			    m->lm_msgid, 0, 0 );
			ld->ld_cache->lc_memused -= msg_size( m );
			ldap_msgfree( m );
		} else {
		    if ( m->lm_msgtype == msgtype &&
			request_cmp( m->lm_ber, &reqber ) == 0 ) {
			    break;
		    }
		    next = m->lm_next;
		    prev = m;
		}
	}

	if ( m == NULLMSG ) {
		return( -1 );
	}

	/*
	 * add duplicates of responses to incoming queue
	 */
	first = 1;
#if defined( SUN ) && defined( _REENTRANT )	
	LOCK_RESPONSE(ld);
#endif
	for ( m = m->lm_chain; m != NULLMSG; m = m->lm_chain ) {
		if (( new = msg_dup( m )) == NULLMSG ) {
#if defined( SUN ) && defined( _REENTRANT )	
			UNLOCK_RESPONSE(ld);
#endif
			return( -1 );
		}

		new->lm_msgid = ld->ld_msgid;
		new->lm_chain = NULLMSG;
		if ( first ) {
			new->lm_next = ld->ld_responses;
			ld->ld_responses = new;
			first = 0;
		} else {
			prev->lm_chain = new;
		}
		prev = new;
		Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 105, "cc: added type %d\n"),
		    new->lm_msgtype, 0, 0 );
	}

	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 106, "cc: result returned from cache\n"), 0, 0, 0 );
#if defined( SUN ) && defined( _REENTRANT )	
	UNLOCK_RESPONSE(ld);
#endif
	return( 0 );
}


static int
cache_hash( BerElement *ber )
{
	BerElement	bercpy;
	unsigned int	len;

	/*
         * just take the length of the packet and mod with # of buckets
	 */
	bercpy = *ber;
	if ( ber_skip_tag( &bercpy, &len ) == LBER_ERROR
		|| ber_scanf( &bercpy, "x" ) == LBER_ERROR ) {
	    len = 0;	/* punt: just return zero */
	} else {
	    len = (int) ( bercpy.ber_end - bercpy.ber_ptr );
	}

	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 107, "cache_hash: len is %1$ld, returning %2$ld\n"),
	    len, len % LDAP_CACHE_BUCKETS, 0 );
	return ( len % LDAP_CACHE_BUCKETS );
}


static LDAPMessage *
msg_dup( LDAPMessage *msg )
{
	LDAPMessage	*new;
	size_t		len;

	if (( new = (LDAPMessage *)malloc( sizeof(LDAPMessage))) != NULL ) {
		*new = *msg;	/* struct copy */
		if (( new->lm_ber = ber_dup( msg->lm_ber )) == NULLBER ) {
			free( (char *)new );
			return( NULLMSG );
		}
		len = msg->lm_ber->ber_end - msg->lm_ber->ber_buf;
		if (( new->lm_ber->ber_buf = (char *) malloc( len )) == NULL ) {
			ber_free( new->lm_ber, 0 );
			free( (char *)new );
			return( NULLMSG );
		}
		SAFEMEMCPY( new->lm_ber->ber_buf, msg->lm_ber->ber_buf, len );

		new->lm_ber->ber_ptr = new->lm_ber->ber_buf +
			( msg->lm_ber->ber_ptr - msg->lm_ber->ber_buf );
		new->lm_ber->ber_end = new->lm_ber->ber_buf + len;
	}

	return( new );
}


static int
request_cmp( BerElement *req1, BerElement *req2 )
{
	unsigned int	len;
   size_t slen;
	BerElement	r1, r2;

	r1 = *req1;	/* struct copies */
	r2 = *req2;

	/*
	 * skip the enclosing tags (sequence markers) and the msg ids
	 */
	if ( ber_skip_tag( &r1, &len ) == LBER_ERROR || ber_scanf( &r1, "x" )
	    == LBER_ERROR ) {
	    return( -1 );
	}
	if ( ber_skip_tag( &r2, &len ) == LBER_ERROR || ber_scanf( &r2, "x" ) 
	    == LBER_ERROR ) {
	    return( -1 );
	}

	/*
	 * check remaining length and bytes if necessary
	 */
	if (( slen = r1.ber_end - r1.ber_ptr ) != r2.ber_end - r2.ber_ptr ) {
		return( -1 );	/* different lengths */
	}
	return( memcmp( r1.ber_ptr, r2.ber_ptr, slen ));
}	


static int
chain_contains_dn( LDAPMessage *msg, char *dn )
{
	LDAPMessage	*m;
	BerElement	ber;
	int		msgid;
	char		*s;
	int		rc;


	/*
	 * first check the base or dn of the request
	 */
	ber = *msg->lm_ber;	/* struct copy */
	if ( ber_scanf( &ber, "{i{a", &msgid, &s ) != LBER_ERROR ) {
	    rc = ( strcasecmp( dn, s ) == 0 ) ? 1 : 0;
	    free( s );
	    if ( rc != 0 ) {
		return( rc );
	    }
	}

	if ( msg->lm_msgtype == LDAP_REQ_COMPARE ) {
		return( 0 );
	}

	/*
	 * now check the dn of each search result
	 */
	rc = 0;
	for ( m = msg->lm_chain; m != NULLMSG && rc == 0 ; m = m->lm_chain ) {
		if ( m->lm_msgtype != LDAP_RES_SEARCH_ENTRY ) {
			continue;
		}
		ber = *m->lm_ber;	/* struct copy */
		if ( ber_scanf( &ber, "{a", &s ) != LBER_ERROR ) {
			rc = ( strcasecmp( dn, s ) == 0 ) ? 1 : 0;
			free( s );
		}
	}

	return( rc );
}


static ssize_t
msg_size( LDAPMessage *msg )
{
	LDAPMessage	*m;
	ssize_t		size;

	size = 0;
	for ( m = msg; m != NULLMSG; m = m->lm_chain ) {
		size += sizeof( LDAPMessage ) + m->lm_ber->ber_end -
		    m->lm_ber->ber_buf;
	}

	return( size );
}


#define THRESHOLD_FACTOR	3 / 4
#define SIZE_FACTOR		2 / 3

static void
check_cache_memused( LDAPCache *lc )
{
/*
 * this routine is called to check if the cache is too big (lc_maxmem >
 * minimum cache size and lc_memused > lc_maxmem).  If too big, it reduces
 * the cache size to < SIZE_FACTOR * lc_maxmem. The algorithm is as follows:
 *    remove_threshold = lc_timeout seconds;
 *    do {
 *        remove everything older than remove_threshold seconds;
 *        remove_threshold = remove_threshold * THRESHOLD_FACTOR;
 *    } while ( cache size is > SIZE_FACTOR * lc_maxmem )
 */
	int		i;
	unsigned long	remove_threshold, validtime;
	LDAPMessage	*m, *prev, *next;

	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 108, "check_cache_memused: %1$ld bytes in use (%2$ld max)\n"),
	    lc->lc_memused, lc->lc_maxmem, 0 );

	if ( lc->lc_maxmem <= sizeof( LDAPCache )
	    || lc->lc_memused <= lc->lc_maxmem * SIZE_FACTOR ) {
		return;
	}

	remove_threshold = lc->lc_timeout;
	while ( lc->lc_memused > lc->lc_maxmem * SIZE_FACTOR ) {
		validtime = time( NULL ) - remove_threshold;
		for ( i = 0; i < LDAP_CACHE_BUCKETS; ++i ) {
			prev = NULLMSG;
			for ( m = lc->lc_buckets[ i ]; m != NULLMSG;
			    m = next ) {
				next = m->lm_next;
				if ( m->lm_time < validtime ) {
					if ( prev == NULLMSG ) {
						lc->lc_buckets[ i ] = next;
					} else {
						prev->lm_next = next;
					}
					lc->lc_memused -= msg_size( m );
					Debug( LDAP_DEBUG_TRACE,
					    catgets(slapdcat, 1, 109, "ccm: removed %d\n"),
					    m->lm_msgid, 0, 0 );
					ldap_msgfree( m );
				} else {
					prev = m;
				}
			}
		}
		remove_threshold *= THRESHOLD_FACTOR;
	}

	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 110, "ccm: reduced usage to %ld bytes\n"),
	    lc->lc_memused, 0, 0 );
}

#endif /* !NO_CACHE */
