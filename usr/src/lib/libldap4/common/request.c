/*
 * Copyright 1998-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *  Copyright (c) 1995 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  request.c - sending of ldap requests; handling of referrals
 */

#ifndef lint 
static char copyright[] = "@(#) Copyright (c) 1995 Regents of the University of Michigan.\nAll rights reserved.\n";
#endif

#include <stdio.h>
#include <string.h>
#ifdef MACOS
#include <stdlib.h>
#include <time.h>
#include "macos.h"
#else /* MACOS */
#if defined( DOS ) || defined( _WIN32 )
#include "msdos.h"
#include <time.h>
#include <stdlib.h>
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
static LDAPConn *find_connection( LDAP *ld, LDAPServer *srv, int any );
static void use_connection( LDAP *ld, LDAPConn *lc );
static void free_servers( LDAPServer *srvlist );
#else /* NEEDPROTOS */
static LDAPConn *find_connection();
static void use_connection();
static void free_servers();
#endif /* NEEDPROTOS */


#ifdef LDAP_DNS
#ifdef NEEDPROTOS
static LDAPServer *dn2servers( LDAP *ld, char *dn );
#else /* NEEDPROTOS */
static LDAPServer *dn2servers();
#endif /* NEEDPROTOS */
#endif /* LDAP_DNS */


BerElement *
alloc_ber_with_options( LDAP *ld )
{
	BerElement	*ber;

    	if (( ber = ber_alloc_t( ld->ld_lberoptions )) == NULLBER ) {
		ld->ld_errno = LDAP_NO_MEMORY;
#ifdef STR_TRANSLATION
	} else {
		set_ber_options( ld, ber );
#endif /* STR_TRANSLATION */
	}

	return( ber );
}


void
set_ber_options( LDAP *ld, BerElement *ber )
{
	ber->ber_options = ld->ld_lberoptions;
#ifdef STR_TRANSLATION
	if (( ld->ld_lberoptions & LBER_TRANSLATE_STRINGS ) != 0 ) {
		ber_set_string_translators( ber,
		    ld->ld_lber_encode_translate_proc,
		    ld->ld_lber_decode_translate_proc );
	}
#endif /* STR_TRANSLATION */
}


int
send_initial_request( LDAP *ld, unsigned int msgtype, char *dn,
	BerElement *ber )
{
	LDAPServer	*servers;
	int rv;

#ifdef _REENTRANT
        LOCK_LDAP(ld);
#endif
	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 209, "send_initial_request\n"), 0, 0, 0 );

#ifdef LDAP_DNS
	if (( ld->ld_options & LDAP_OPT_DNS ) != 0 && ldap_is_dns_dn( dn )) {
		if (( servers = dn2servers( ld, dn )) == NULL ) {
			ber_free( ber, 1 );
#ifdef _REENTRANT
			UNLOCK_LDAP(ld);
#endif
			return( -1 );
		}

#ifdef LDAP_DEBUG
		if ( ldap_debug & LDAP_DEBUG_TRACE ) {
			LDAPServer	*srv;

			for ( srv = servers; srv != NULL;
			    srv = srv->lsrv_next ) {
				fprintf( stderr,
				    "LDAP server %s:  dn %s, port %d\n",
				    srv->lsrv_host, ( srv->lsrv_dn == NULL ) ?
				    "(default)" : srv->lsrv_dn,
				    srv->lsrv_port );
			}
		}
#endif /* LDAP_DEBUG */
	} else {
#endif /* LDAP_DNS */
		/*
		 * use of DNS is turned off or this is an X.500 DN...
		 * use our default connection
		 */
		servers = NULL;
#ifdef LDAP_DNS
	}	
#endif /* LDAP_DNS */

#ifdef _REENTRANT
    UNLOCK_LDAP(ld);
#endif
	rv = send_server_request( ld, ber, ld->ld_msgid, NULL, servers,
							  NULL, 0 );
	return ( rv );
}

int
send_server_request( LDAP *ld, BerElement *ber, int msgid, LDAPRequest
	*parentreq, LDAPServer *srvlist, LDAPConn *lc, int bind )
{
	LDAPRequest	*lr;
	int err;
	
#ifdef _REENTRANT
        LOCK_LDAP(ld);
#endif
	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 210, "send_server_request\n"), 0, 0, 0 );

	ld->ld_errno = LDAP_SUCCESS;	/* optimistic */
	/* Be optimistic : increment parentreq initially.
	   If it fails we must decrement it */
	if (parentreq != NULL){
		parentreq->lr_outrefcnt++;
	}
	
	if ( lc == NULL ) {
		if ( srvlist == NULL ) {
			if  (ld->ld_defconn == NULL){ /* Not connected yet on the default connection, ie init was called not open */
				if ((err = open_default_ldap_connection(ld)) != LDAP_SUCCESS){
					ld->ld_errno = err;
					ber_free(ber, 1);
					if (parentreq != NULL){
						parentreq->lr_outrefcnt--;
					}
#ifdef _REENTRANT
					UNLOCK_LDAP(ld);
#endif
					return( -1 );
				}
			}
			
			lc = ld->ld_defconn;
		} else {
			if (( lc = find_connection( ld, srvlist, 1 )) ==
			    NULL ) {
				lc = new_connection( ld, &srvlist, 0, 1, bind );
			}
			free_servers( srvlist );
		}
	}

	if ( lc == NULL || lc->lconn_status != LDAP_CONNST_CONNECTED ) {
		ber_free( ber, 1 );
		if ( ld->ld_errno == LDAP_SUCCESS ) {
			ld->ld_errno = LDAP_SERVER_DOWN;
		}
		if (parentreq != NULL){
			parentreq->lr_outrefcnt--;
		}
#ifdef _REENTRANT
		UNLOCK_LDAP(ld);
#endif
		return( -1 );
	}

	use_connection( ld, lc );
	if (( lr = (LDAPRequest *)calloc( 1, sizeof( LDAPRequest ))) ==
	    NULL ) {
		ld->ld_errno = LDAP_NO_MEMORY;
		free_connection( ld, lc, 0, 0 );
		ber_free( ber, 1 );
#ifdef _REENTRANT
		UNLOCK_LDAP(ld);
#endif
		return( -1 );
	} 
	lr->lr_msgid = msgid;
	lr->lr_status = LDAP_REQST_INPROGRESS;
	lr->lr_res_errno = LDAP_SUCCESS;	/* optimistic */
	lr->lr_ber = ber;
	lr->lr_conn = lc;
	if ( parentreq != NULL ) {	/* sub-request */
/* 		++parentreq->lr_outrefcnt; */
		lr->lr_origid = parentreq->lr_origid;
		lr->lr_parentcnt = parentreq->lr_parentcnt + 1;
		lr->lr_parent = parentreq;
		lr->lr_refnext = parentreq->lr_refnext;
		parentreq->lr_refnext = lr;
	} else {			/* original request */
		lr->lr_origid = lr->lr_msgid;
	}

	if (( lr->lr_next = ld->ld_requests ) != NULL ) {
		lr->lr_next->lr_prev = lr;
	}
	ld->ld_requests = lr;
	lr->lr_prev = NULL;

	if ( ber_flush( lc->lconn_sb, ber, 0 ) != 0 ) {
#ifdef notyet
		extern int	errno;

		if ( errno == EWOULDBLOCK ) {
			/* need to continue write later */
			lr->lr_status = LDAP_REQST_WRITING;
			mark_select_write( ld, lc->lconn_sb );
		} else {
#else /* notyet */
			ld->ld_errno = LDAP_SERVER_DOWN;
			free_request( ld, lr );
			free_connection( ld, lc, 0, 0 );
#ifdef _REENTRANT
			UNLOCK_LDAP(ld);
#endif
			return( -1 );
#endif /* notyet */
#ifdef notyet
		}
#endif /* notyet */
	} else {
		if ( parentreq == NULL ) {
			ber->ber_end = ber->ber_ptr;
			ber->ber_ptr = ber->ber_buf;
		}

		/* sent -- waiting for a response */
		mark_select_read( ld, lc->lconn_sb );
	}

	ld->ld_errno = LDAP_SUCCESS;
#ifdef _REENTRANT
        UNLOCK_LDAP(ld);
#endif
	return( msgid );
}


LDAPConn *
new_connection( LDAP *ld, LDAPServer **srvlistp, int use_ldsb,
	int connect, int bind )
{
	LDAPConn	*lc;
	LDAPServer	*prevsrv, *srv;
	Sockbuf		*sb;

	/*
	 * make a new LDAP server connection
	 * XXX open connection synchronously for now
	 */
	if (( lc = (LDAPConn *)calloc( 1, sizeof( LDAPConn ))) == NULL ||
	    ( !use_ldsb && ( sb = (Sockbuf *)calloc( 1, sizeof( Sockbuf )))
	    == NULL )) {
		if ( lc != NULL ) {
			free( (char *)lc );
		}
		ld->ld_errno = LDAP_NO_MEMORY;
		return( NULL );
	}

#ifdef _REENTRANT
	LOCK_LDAP(ld);
#endif
	lc->lconn_sb = ( use_ldsb ) ? &ld->ld_sb : sb;

	if ( connect ) {
		prevsrv = NULL;

		for ( srv = *srvlistp; srv != NULL; srv = srv->lsrv_next ) {
			if ( open_ldap_connection( ld, lc->lconn_sb,
			    srv->lsrv_host, srv->lsrv_port,
			    &lc->lconn_krbinstance, 0 ) != -1 ) {
				break;
			}
			prevsrv = srv;
		}

		if ( srv == NULL ) {
		    if ( !use_ldsb ) {
				free( (char *)lc->lconn_sb );
		    }
		    free( (char *)lc );
		    ld->ld_errno = LDAP_SERVER_DOWN;
#ifdef _REENTRANT
		    UNLOCK_LDAP(ld);
#endif
		    return( NULL );
		}

		if ( prevsrv == NULL ) {
		    *srvlistp = srv->lsrv_next;
		} else {
		    prevsrv->lsrv_next = srv->lsrv_next;
		}
		lc->lconn_server = srv;
	}

	lc->lconn_status = LDAP_CONNST_CONNECTED;
	lc->lconn_next = ld->ld_conns;
	ld->ld_conns = lc;

	/*
	 * XXX for now, we always do a synchronous bind.  This will have
	 * to change in the long run...
	 */
	if ( bind ) {
		int		err, freepasswd, authmethod;
		char		*binddn, *passwd;
		LDAPConn	*savedefconn;

		freepasswd = err = 0;

		if ( ld->ld_version == LDAP_VERSION3 && ld->ld_rebindproc == NULL){
			/* Nothing to do */
			Debug(LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 1280, "new_connection: bind no needed with ldapv3\n"), 0,0,0);
		} else {
			if ( ld->ld_rebindproc == NULL ) {
				binddn = passwd = "";
				authmethod = LDAP_AUTH_SIMPLE;
			} else {
				if (( err = (*ld->ld_rebindproc)( ld, &binddn, &passwd,
												  &authmethod, 0, ld->ld_rebind_extra_arg )) == LDAP_SUCCESS ) {
					freepasswd = 1;
				} else {
					ld->ld_errno = err;
					err = -1;
				}
			}
			
			if ( err == 0 ) {
				savedefconn = ld->ld_defconn;
				ld->ld_defconn = lc;
				++lc->lconn_refcnt;	/* avoid premature free */
				
				if ( ldap_bind_s( ld, binddn, passwd, authmethod ) !=
					 LDAP_SUCCESS ) {
					err = -1;
				}
				--lc->lconn_refcnt;
				ld->ld_defconn = savedefconn;
			}

			if ( freepasswd ) {
				(*ld->ld_rebindproc)( ld, &binddn, &passwd,
									  &authmethod, 1, ld->ld_rebind_extra_arg );
			}
			
			if ( err != 0 ) {
				free_connection( ld, lc, 1, 0 );
				lc = NULL;
			}
		}
	}

#ifdef _REENTRANT
	UNLOCK_LDAP(ld);
#endif
	return( lc );
}


static LDAPConn *
find_connection( LDAP *ld, LDAPServer *srv, int any )
/*
 * return an existing connection (if any) to the server srv
 * if "any" is non-zero, check for any server in the "srv" chain
 */
{
	LDAPConn	*lc;
	LDAPServer	*ls;

#ifdef _REENTRANT
        LOCK_LDAP(ld);
#endif
	for ( lc = ld->ld_conns; lc != NULL; lc = lc->lconn_next ) {
		for ( ls = srv; ls != NULL; ls = ls->lsrv_next ) {
			if ( lc->lconn_server->lsrv_host != NULL &&
			    ls->lsrv_host != NULL && strcasecmp(
			    ls->lsrv_host, lc->lconn_server->lsrv_host ) == 0
			    && ls->lsrv_port == lc->lconn_server->lsrv_port ) {
#ifdef _REENTRANT
				UNLOCK_LDAP(ld);
#endif
				return( lc );
			}
			if ( !any ) {
				break;
			}
		}
	}

#ifdef _REENTRANT
        UNLOCK_LDAP(ld);
#endif
	return( NULL );
}



static void
use_connection( LDAP *ld, LDAPConn *lc )
{
	++lc->lconn_refcnt;
	lc->lconn_lastused = time( 0 );
}


void
free_connection( LDAP *ld, LDAPConn *lc, int force, int unbind )
{
	LDAPConn	*tmplc, *prevlc;

	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 211, "free_connection\n"), 0, 0, 0 );

	if ( force || --lc->lconn_refcnt <= 0 ) {
		if ( lc->lconn_status == LDAP_CONNST_CONNECTED ) {
			mark_select_clear( ld, lc->lconn_sb );
			if ( unbind ) {
				send_unbind( ld, lc->lconn_sb );
			}
			close_ldap_connection( lc->lconn_sb );
			if ( lc->lconn_sb->sb_ber.ber_buf != NULL ) {
				free( lc->lconn_sb->sb_ber.ber_buf );
				lc->lconn_sb->sb_ber.ber_buf = NULL;
			}
		}
		prevlc = NULL;
		for ( tmplc = ld->ld_conns; tmplc != NULL;
		    tmplc = tmplc->lconn_next ) {
			if ( tmplc == lc ) {
				if ( prevlc == NULL ) {
				    ld->ld_conns = tmplc->lconn_next;
				} else {
				    prevlc->lconn_next = tmplc->lconn_next;
				}
				break;
			}
		}
		free_servers( lc->lconn_server );
		if ( lc->lconn_krbinstance != NULL ) {
			free( lc->lconn_krbinstance );
		}
		if ( lc->lconn_sb != &ld->ld_sb ) {
			free( (char *)lc->lconn_sb );
		}
		free( lc );
		Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 212, "free_connection: actually freed\n"),
		    0, 0, 0 );
	} else {
		lc->lconn_lastused = time( 0 );
		Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 213, "free_connection: refcnt %d\n"),
		    lc->lconn_refcnt, 0, 0 );
	}
}


#ifdef LDAP_DEBUG
void
dump_connection( LDAP *ld, LDAPConn *lconns, int all )
{
	LDAPConn	*lc;

	fprintf( stderr, "** Connection%s:\n", all ? "s" : "" );
	for ( lc = lconns; lc != NULL; lc = lc->lconn_next ) {
		if ( lc->lconn_server != NULL ) {
			fprintf( stderr, "* host: %s  port: %d%s\n",
			    ( lc->lconn_server->lsrv_host == NULL ) ? "(null)"
			    : lc->lconn_server->lsrv_host,
			    lc->lconn_server->lsrv_port, ( lc->lconn_sb ==
			    &ld->ld_sb ) ? "  (default)" : "" );
		}
		fprintf( stderr, "  refcnt: %d  status: %s\n", lc->lconn_refcnt,
		    ( lc->lconn_status == LDAP_CONNST_NEEDSOCKET ) ?
		    "NeedSocket" : ( lc->lconn_status ==
		    LDAP_CONNST_CONNECTING ) ? "Connecting" : "Connected" );
		fprintf( stderr, "  last used: %s\n",
		    ctime( &lc->lconn_lastused ));
		if ( !all ) {
			break;
		}
	}
}


void
dump_requests_and_responses( LDAP *ld )
{
	LDAPRequest	*lr;
	LDAPMessage	*lm, *l;

	fprintf( stderr, "** Outstanding Requests:\n" );
	if (( lr = ld->ld_requests ) == NULL ) {
		fprintf( stderr, "   Empty\n" );
	}
	for ( ; lr != NULL; lr = lr->lr_next ) {
	    fprintf( stderr, " * msgid %d,  origid %d, status %s\n",
		lr->lr_msgid, lr->lr_origid, ( lr->lr_status ==
		LDAP_REQST_INPROGRESS ) ? "InProgress" :
		( lr->lr_status == LDAP_REQST_CHASINGREFS ) ? "ChasingRefs" :
		( lr->lr_status == LDAP_REQST_NOTCONNECTED ) ? "NotConnected" :
		"Writing" );
	    fprintf( stderr, "   outstanding referrals %d, parent count %d\n",
		    lr->lr_outrefcnt, lr->lr_parentcnt );
	}

	fprintf( stderr, "** Response Queue:\n" );
#ifdef _REENTRANT
        LOCK_RESPONSE(ld);
#endif
	if (( lm = ld->ld_responses ) == NULLMSG ) {
		fprintf( stderr, "   Empty\n" );
	}
	for ( ; lm != NULLMSG; lm = lm->lm_next ) {
		fprintf( stderr, " * msgid %d,  type %d\n",
		    lm->lm_msgid, lm->lm_msgtype );
		if (( l = lm->lm_chain ) != NULL ) {
			fprintf( stderr, "   chained responses:\n" );
			for ( ; l != NULLMSG; l = l->lm_chain ) {
				fprintf( stderr,
				    "  * msgid %d,  type %d\n",
				    l->lm_msgid, l->lm_msgtype );
			}
		}
	}
#ifdef _REENTRANT
	UNLOCK_RESPONSE(ld);
#endif
}
#endif /* LDAP_DEBUG */


void
free_request( LDAP *ld, LDAPRequest *lr )
{
	LDAPRequest	*tmplr, *nextlr;
	int i;
	
	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 214, "free_request (origid %1$d, msgid %2$d)\n"),
		lr->lr_origid, lr->lr_msgid, 0 );

	if ( lr->lr_parent != NULL ) {
		--lr->lr_parent->lr_outrefcnt;
	} else {
		/* free all referrals (child requests) */
		for ( tmplr = lr->lr_refnext; tmplr != NULL; tmplr = nextlr ) {
			nextlr = tmplr->lr_refnext;
			free_request( ld, tmplr );
		}
	}

	if ( lr->lr_prev == NULL ) {
		ld->ld_requests = lr->lr_next;
	} else {
		lr->lr_prev->lr_next = lr->lr_next;
	}

	if ( lr->lr_next != NULL ) {
		lr->lr_next->lr_prev = lr->lr_prev;
	}

	if ( lr->lr_ber != NULL ) {
		ber_free( lr->lr_ber, 1 );
	}

	if ( lr->lr_res_error != NULL ) {
		free( lr->lr_res_error );
	}

	if ( lr->lr_res_matched != NULL ) {
		free( lr->lr_res_matched );
	}
	
	if ( lr->lr_ref_tofollow != NULL ) {
		for (i= 0; lr->lr_ref_tofollow[i] != NULL; i++)
			free(lr->lr_ref_tofollow[i]);
		free(lr->lr_ref_tofollow);
	}
	if ( lr->lr_ref_unfollowed != NULL ) {
		for (i= 0; lr->lr_ref_unfollowed[i] != NULL; i++)
			free(lr->lr_ref_unfollowed[i]);
		free(lr->lr_ref_unfollowed);
	}
	if ( lr->lr_ref_followed != NULL ) {
		for (i= 0; lr->lr_ref_followed[i] != NULL; i++)
			free(lr->lr_ref_followed[i]);
		free(lr->lr_ref_followed);
	}
	
	free( lr );
}


static void
free_servers( LDAPServer *srvlist )
{
    LDAPServer	*nextsrv;

    while ( srvlist != NULL ) {
	nextsrv = srvlist->lsrv_next;
	if ( srvlist->lsrv_dn != NULL ) {
		free( srvlist->lsrv_dn );
	}
	if ( srvlist->lsrv_host != NULL ) {
		free( srvlist->lsrv_host );
	}
	free( srvlist );
	srvlist = nextsrv;
    }
}

/*
 * nsldapi_connection_lost_nolock() resets "ld" to a non-connected, known
 * state.  It should be called whenever a fatal error occurs on the
 * Sockbuf "sb."  sb == NULL means we don't know specifically where
 * the problem was so we assume all connections are bad.
 */
void
nsldapi_connection_lost_nolock( LDAP *ld, Sockbuf *sb )
{
	LDAPRequest	*lr;

	/*
	 * change status of all pending requests that are associated with "sb
	 *	to "connection dead."
	 * also change the connection status to "dead" and remove it from
	 *	the list of sockets we are interested in.
	 */
	for ( lr = ld->ld_requests; lr != NULL; lr = lr->lr_next ) {
		if ( sb == NULL ||
		    ( lr->lr_conn != NULL && lr->lr_conn->lconn_sb == sb )) {
			lr->lr_status = LDAP_REQST_CONNDEAD;
			if ( lr->lr_conn != NULL ) {
				lr->lr_conn->lconn_status = LDAP_CONNST_DEAD;
			}
		}
	}
}

#ifdef LDAP_DNS
static LDAPServer *
dn2servers( LDAP *ld, char *dn )	/* dn can also be a domain.... */
{
	char		*p, *domain, *host, *server_dn, **dxs;
	int		i, port;
	LDAPServer	*srvlist, *prevsrv, *srv;

	if (( domain = strrchr( dn, '@' )) != NULL ) {
		++domain;
	} else {
		domain = dn;
	}

	if (( dxs = getdxbyname( domain )) == NULL ) {
		ld->ld_errno = LDAP_NO_MEMORY;
		return( NULL );
	}

	srvlist = NULL;

	for ( i = 0; dxs[ i ] != NULL; ++i ) {
		port = LDAP_PORT;
		server_dn = NULL;
		if ( strchr( dxs[ i ], ':' ) == NULL ) {
			host = dxs[ i ];
		} else if ( strlen( dxs[ i ] ) >= 7 &&
		    strncmp( dxs[ i ], "ldap://", 7 ) == 0 ) {
			host = dxs[ i ] + 7;
			if (( p = strchr( host, ':' )) == NULL ) {
				p = host;
			} else {
				*p++ = '\0';
				port = atoi( p );
			}
			if (( p = strchr( p, '/' )) != NULL ) {
				server_dn = ++p;
				if ( *server_dn == '\0' ) {
					server_dn = NULL;
				}
			}
		} else {
			host = NULL;
		}

		if ( host != NULL ) {	/* found a server we can use */
			if (( srv = (LDAPServer *)calloc( 1,
			    sizeof( LDAPServer ))) == NULL ) {
				free_servers( srvlist );
				srvlist = NULL;
				break;		/* exit loop & return */
			}

			/* add to end of list of servers */
			if ( srvlist == NULL ) {
				srvlist = srv;
			} else {
				prevsrv->lsrv_next = srv;
			}
			prevsrv = srv;
			
			/* copy in info. */
			if (( srv->lsrv_host = strdup( host )) == NULL ||
			    ( server_dn != NULL && ( srv->lsrv_dn =
			    strdup( server_dn )) == NULL )) {
				free_servers( srvlist );
				srvlist = NULL;
				break;		/* exit loop & return */
			}
			srv->lsrv_port = port;
		}
	}

	ldap_value_free( dxs );

	if ( srvlist == NULL ) {
		ld->ld_errno = LDAP_SERVER_DOWN;
	}

	return( srvlist );
}
#endif /* LDAP_DNS */
