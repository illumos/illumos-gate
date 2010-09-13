/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *  Copyright (c) 1996 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  LIBLDAP url.c -- LDAP URL related routines
 *
 *  LDAP URLs look like this:
 *    l d a p : / / hostport / dn [ ? attributes [ ? scope [ ? filter [ ? extensions ] ] ] ]
 *
 *  where:
 *   attributes is a comma separated list
 *   scope is one of these three strings:  base one sub (default=base)
 *   filter is an string-represented filter as in RFC 1558
 *	 extensions is a comma separated list of extension
 *   and extension is like this: [ ! ] oid/x-oid [ = value ]
 *
 *  e.g.,  ldap://ldap.itd.umich.edu/c=US?o,description?one?o=umich
 *
 *  We also tolerate URLs that look like: <ldapurl> and <URL:ldapurl>
 */

#ifndef lint 
static char copyright[] = "@(#) Copyright (c) 1996 Regents of the University of Michigan.\nAll rights reserved.\n";
#endif

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#ifdef MACOS
#include <stdlib.h>
#include "macos.h"
#endif /* MACOS */

#if defined( DOS ) || defined( _WIN32 )
#include <stdlib.h>
#include <malloc.h>
#include "msdos.h"
#endif /* DOS || _WIN32 */

#if !defined(MACOS) && !defined(DOS) && !defined( _WIN32 )
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#endif /* !MACOS && !DOS && !_WIN32 */

#include "lber.h"
#include "ldap.h"
#include "ldap-private.h"
#include "ldap-int.h"


#ifdef NEEDPROTOS
static int skip_url_prefix( char **urlp, int *enclosedp );
static void hex_unescape( char *s );
static int unhex( char c );
#else /* NEEDPROTOS */
static int skip_url_prefix();
static void hex_unescape();
static int unhex();
#endif /* NEEDPROTOS */


int
ldap_is_ldap_url( char *url )
{
	int	enclosed;

	return( url != NULL && skip_url_prefix( &url, &enclosed ));
}


static int
skip_url_prefix( char **urlp, int *enclosedp )
{
/*
 * return non-zero if this looks like a LDAP URL; zero if not
 * if non-zero returned, *urlp will be moved past "ldap://" part of URL
 */
	if ( *urlp == NULL ) {
		return( 0 );
	}

	/* skip leading '<' (if any) */
	if ( **urlp == '<' ) {
		*enclosedp = 1;
		++*urlp;
	} else {
		*enclosedp = 0;
	}

	/* skip leading "URL:" (if any) */
	if ( strlen( *urlp ) >= LDAP_URL_URLCOLON_LEN && strncasecmp(
	    *urlp, LDAP_URL_URLCOLON, LDAP_URL_URLCOLON_LEN ) == 0 ) {
		*urlp += LDAP_URL_URLCOLON_LEN;
	}

	/* check for missing "ldap://" prefix */
	if ( strlen( *urlp ) < LDAP_URL_PREFIX_LEN ||
	    strncasecmp( *urlp, LDAP_URL_PREFIX, LDAP_URL_PREFIX_LEN ) != 0 ) {
		return( 0 );
	}

	/* skip over "ldap://" prefix and return success */
	*urlp += LDAP_URL_PREFIX_LEN;
	return( 1 );
}

int ldap_url_extension_parse( char *exts, LDAPURLExt *** lueppp)
{
	/* Pick apart the pieces of an LDAP URL Extensions */
	/* No copy of exts is made, LDAPURLExt's points to exts string */
	LDAPURLExt ** lues;
	LDAPURLExt *luep;
	int i = 0;
	char *p = exts;
	char *ptr, *ptr2;
	
	*lueppp = NULL;
	
	/* Count the number of , in extensions */ 
	while ( (p = strchr (p, ',')) != NULL){
		i++;
	}
	/* There are at most i+1 extensions */
	if ((lues = (LDAPURLExt **)calloc(i+2, sizeof(LDAPURLExt *))) == NULL){
		return (LDAP_URL_ERR_MEM);
	}
	
	p = exts;
	i = 0;

	while ( p ) {
		if ((ptr = strchr(p, ',')) != NULL)
			*ptr++ = '\0';
		else
			ptr = NULL;
		
		if ((luep = (LDAPURLExt *)calloc(1, sizeof(LDAPURLExt))) == NULL){
			ldap_free_urlexts(lues);
			return (LDAP_URL_ERR_MEM);
		}
		lues[i] = luep;
		
		if (*p == '!'){
			luep->lue_iscritical = 1;
			p++;
		}
		luep->lue_type = p;

		if (( ptr2 = strchr(p, '=')) != NULL) {
			*ptr2++ = '\0';
			luep->lue_value = ptr2;
			hex_unescape(ptr2);
		}
		
		i++;
		p = ptr;
	}
	*lueppp = lues;

	return( 0 );
}


int
ldap_url_parse( char *url, LDAPURLDesc **ludpp )
{
/*
 *  Pick apart the pieces of an LDAP URL.
 */

	LDAPURLDesc	*ludp;
	char  *attrs = NULL;
	char  *p = NULL;
	char  *q = NULL;
	char  *x = NULL;
	int	  enclosed, i, nattrs, errcode;

	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 262, "ldap_url_parse(%s)\n"), url, 0, 0 );

	*ludpp = NULL;	/* pessimistic */

	if ( !skip_url_prefix( &url, &enclosed )) {
		return( LDAP_URL_ERR_NOTLDAP );
	}

	/* allocate return struct */
	if (( ludp = (LDAPURLDesc *)calloc( 1, sizeof( LDAPURLDesc )))
	    == NULLLDAPURLDESC ) {
		return( LDAP_URL_ERR_MEM );
	}

	ludp->lud_port = LDAP_PORT;

	/* make working copy of the remainder of the URL */
	if (( url = strdup( url )) == NULL ) {
		ldap_free_urldesc( ludp );
		return( LDAP_URL_ERR_MEM );
	}

	if ( enclosed && *((p = url + strlen( url ) - 1)) == '>' ) {
		*p = '\0';
	}

	/* set defaults */
	/* LP By default don't set them... Then we can check if they are present or not in URL */
	ludp->lud_scope = LDAP_SCOPE_UNKNOWN;
	ludp->lud_filter = NULL;


	/* lud_string is the only malloc'd string space we use */
	ludp->lud_string = url;

	/* scan forward for '/' that marks end of hostport and begin. of dn */
	if (( ludp->lud_dn = strchr( url, '/' )) != NULL ) {
		*ludp->lud_dn++ = '\0';
	}

	/* terminate hostport; point to start of dn */

	if (( p = strchr( url, ':' )) != NULL ) {
		*p++ = '\0';
		ludp->lud_port = atoi( p );
	}

	if ( *url == '\0' ) {
		ludp->lud_host = NULL;
	} else {
		ludp->lud_host = url;
		hex_unescape( ludp->lud_host );
	}

	if (ludp->lud_dn != NULL){
		/* scan for '?' that marks end of dn and beginning of attributes */
		if (( attrs = strchr( ludp->lud_dn, '?' )) != NULL ) {
			/* terminate dn; point to start of attrs. */
			*attrs++ = '\0';
			
			/* scan for '?' that marks end of attrs and begin. of scope */
			if (( p = strchr( attrs, '?' )) != NULL ) {
				/*
				 * terminate attrs; point to start of scope and scan for
				 * '?' that marks end of scope and begin. of filter
				 */
				*p++ = '\0';
				
				if (( q = strchr( p, '?' )) != NULL ) {
					/* terminate scope; point to start of filter */
					*q++ = '\0';
					
					if (( x = strchr(q, '?')) != NULL ) {
						/* terminate filter; point to start of extension */
						*x++ = '\0';
						
						if (*x != '\0'){
							/* parse extensions */
						}
					}
					
					if ( *q != '\0' ) {
						ludp->lud_filter = q;
						hex_unescape( ludp->lud_filter );
					}
			}
				
				if ( strcasecmp( p, "one" ) == 0 ) {
					ludp->lud_scope = LDAP_SCOPE_ONELEVEL;
				} else if ( strcasecmp( p, "base" ) == 0 ) {
					ludp->lud_scope = LDAP_SCOPE_BASE;
				} else if ( strcasecmp( p, "sub" ) == 0 ) {
					ludp->lud_scope = LDAP_SCOPE_SUBTREE;
				} else if ( *p != '\0' ) {
					ldap_free_urldesc( ludp );
					return( LDAP_URL_ERR_BADSCOPE );
				}
			}
		}
		if ( *ludp->lud_dn == '\0' ) {
			ludp->lud_dn = NULL;
		} else {
			hex_unescape( ludp->lud_dn );
		}

		/*
		 * if attrs list was included, turn it into a null-terminated array
		 */
		if ( attrs != NULL && *attrs != '\0' ) {
			for ( nattrs = 1, p = attrs; *p != '\0'; ++p ) {
				if ( *p == ',' ) {
					++nattrs;
				}
		}
			
			if (( ludp->lud_attrs = (char **)calloc( nattrs + 1,
													 sizeof( char * ))) == NULL ) {
				ldap_free_urldesc( ludp );
				return( LDAP_URL_ERR_MEM );
			}
			
			for ( i = 0, p = attrs; i < nattrs; ++i ) {
				ludp->lud_attrs[ i ] = p;
				if (( p = strchr( p, ',' )) != NULL ) {
				*p++ ='\0';
				}
				hex_unescape( ludp->lud_attrs[ i ] );
			}
		}
		
		if (x != NULL && *x != '\0'){
			if (errcode = ldap_url_extension_parse(x, &ludp->lud_extensions)){
				ldap_free_urldesc(ludp);
				return ( errcode );
			}
		}
	}

	*ludpp = ludp;

	return( 0 );
}

void ldap_free_urlexts( LDAPURLExt ** lues)
{
	int i;
	for (i = 0; lues[i] != NULL; i++){
		free(lues[i]);
	}
	free(lues);
}


void
ldap_free_urldesc( LDAPURLDesc *ludp )
{
	if ( ludp != NULLLDAPURLDESC ) {
		if ( ludp->lud_string != NULL ) {
			free( ludp->lud_string );
		}
		if ( ludp->lud_attrs != NULL ) {
			free( ludp->lud_attrs );
		}
		if (ludp->lud_extensions != NULL) {
			ldap_free_urlexts(ludp->lud_extensions);
		}
		free( ludp );
	}
}



int
ldap_url_search( LDAP *ld, char *url, int attrsonly )
{
	int		err;
	LDAPURLDesc	*ludp;
	BerElement	*ber;
	LDAPServer	*srv = NULL;

#ifdef _REENTRANT
        LOCK_LDAP(ld);
#endif
	if ( ldap_url_parse( url, &ludp ) != 0 ) {
		ld->ld_errno = LDAP_PARAM_ERROR;
#ifdef _REENTRANT
		UNLOCK_LDAP(ld);
#endif
		return( -1 );
	}

	if (( ber = ldap_build_search_req( ld, ludp->lud_dn,
									   ludp->lud_scope == LDAP_SCOPE_UNKNOWN ? LDAP_SCOPE_BASE : ludp->lud_scope,
									   ludp->lud_filter ? ludp->lud_filter : "(objectclass=*)",
									   ludp->lud_attrs, attrsonly, NULL, NULL, -1 )) == NULLBER ) {
#ifdef _REENTRANT
		UNLOCK_LDAP(ld);
#endif
		return( -1 );
	}

	err = 0;

	if ( ludp->lud_host != NULL || ludp->lud_port != 0 ) {
		if (( srv = (LDAPServer *)calloc( 1, sizeof( LDAPServer )))
		    == NULL || ( srv->lsrv_host = strdup( ludp->lud_host ==
		    NULL ? ld->ld_defhost : ludp->lud_host )) == NULL ) {
			if ( srv != NULL ) {
				free( srv );
			}
			ld->ld_errno = LDAP_NO_MEMORY;
			err = -1;
		} else {
			if ( ludp->lud_port == 0 ) {
				srv->lsrv_port = LDAP_PORT;
			} else {
				 srv->lsrv_port = ludp->lud_port;
			}
		}
	}

	if ( err != 0 ) {
		ber_free( ber, 1 );
	} else {
		err = send_server_request( ld, ber, ld->ld_msgid, NULL, srv, NULL, 1 );
	}

	ldap_free_urldesc( ludp );

#ifdef _REENTRANT
        UNLOCK_LDAP(ld);
#endif
	return( err );
}


int
ldap_url_search_st( LDAP *ld, char *url, int attrsonly,
	struct timeval *timeout, LDAPMessage **res )
{
	int	msgid;
	int retcode = LDAP_SUCCESS;

	if (( msgid = ldap_url_search( ld, url, attrsonly )) == -1 ) {
		return( ld->ld_errno );
	}

	if ( ldap_result( ld, msgid, 1, timeout, res ) == -1 ) {
		return( ld->ld_errno );
	}

	if ( ld->ld_errno == LDAP_TIMEOUT ) {
		(void) ldap_abandon( ld, msgid );
		ld->ld_errno = LDAP_TIMEOUT;
		return( ld->ld_errno );
	}

#ifdef  _REENTRANT
	LOCK_LDAP(ld);
#endif	
	retcode = ldap_parse_result(ld, *res, &ld->ld_errno, &ld->ld_matched, &ld->ld_error,
								&ld->ld_referrals, &ld->ld_ret_ctrls, 0);
	if (retcode == LDAP_SUCCESS)
		retcode = ld->ld_errno;
#ifdef  _REENTRANT
	UNLOCK_LDAP(ld);
#endif	

	return (retcode);
}


int
ldap_url_search_s( LDAP *ld, char *url, int attrsonly, LDAPMessage **res )
{
	int	msgid;
	int retcode = LDAP_SUCCESS;

	if (( msgid = ldap_url_search( ld, url, attrsonly )) == -1 ) {
		return( ld->ld_errno );
	}

	if ( ldap_result( ld, msgid, 1, (struct timeval *)NULL, res ) == -1 ) {
		return( ld->ld_errno );
	}

#ifdef  _REENTRANT
	LOCK_LDAP(ld);
#endif	
	retcode = ldap_parse_result(ld, *res, &ld->ld_errno, &ld->ld_matched, &ld->ld_error,
								&ld->ld_referrals, &ld->ld_ret_ctrls, 0);
	if (retcode == LDAP_SUCCESS)
		retcode = ld->ld_errno;
#ifdef  _REENTRANT
	UNLOCK_LDAP(ld);
#endif	

	return (retcode);
}


static void
hex_unescape( char *s )
{
/*
 * Remove URL hex escapes from s... done in place.  The basic concept for
 * this routine is borrowed from the WWW library HTUnEscape() routine.
 */
	char	*p;

	for ( p = s; *s != '\0'; ++s ) {
		if ( *s == '%' ) {
			if ( *++s != '\0' ) {
				*p = unhex( *s ) << 4;
			}
			if ( *++s != '\0' ) {
				*p++ += unhex( *s );
			}
		} else {
			*p++ = *s;
		}
	}

	*p = '\0';
}


static int
unhex( char c )
{
	return( c >= '0' && c <= '9' ? c - '0'
	    : c >= 'A' && c <= 'F' ? c - 'A' + 10
	    : c - 'a' + 10 );
}


/*
 * Locate the LDAP URL associated with a DNS domain name. 
 *
 * The supplied DNS domain name is converted into a distinguished
 * name. The directory entry specified by that distinguished name
 * is searched for a labeledURI attribute. If successful then the
 * LDAP URL is returned. If unsuccessful then that entry's parent
 * is searched and so on until the target distinguished name is
 * reduced to only two nameparts.
 *
 * For example, if 'ny.eng.wiz.com' is the DNS domain then the
 * following entries are searched until one succeeds:
 * 		dc=ny,dc=eng,dc=wiz,dc=com
 * 		dc=eng,dc=wiz,dc=com
 * 		dc=wiz,dc=com
 *
 * If dns_name is NULL then the environment variable LOCALDOMAIN is used.
 * If attrs is not NULL then it is appended to the URL's attribute list.
 * If scope is not NULL then it overrides the URL's scope.
 * If filter is not NULL then it is merged with the URL's filter.
 *
 * If an error is encountered then zero is returned, otherwise a string
 * URL is returned. The caller should free the returned string if it is
 * non-zero.
 */

char *
ldap_dns_to_url(
	LDAP	*ld,
	char	*dns_name,
	char	*attrs,
	char	*scope,
	char	*filter
)
{
	char		*dn;
	char		*url = 0;
	char		*url2 = 0;
	LDAPURLDesc	*urldesc;
	char		*cp;
	char		*cp2;
	size_t		attrs_len = 0;
	size_t		scope_len = 0;
	size_t		filter_len = 0;
	int		nameparts;
	int		no_attrs = 0;
	int		no_scope = 0;

	if (dns_name == 0) {
		dns_name = (char *)getenv("LOCALDOMAIN");
	}

	if ((ld == NULL) || ((dn = ldap_dns_to_dn(dns_name, &nameparts)) ==
	    NULL))
		return (0);

	if ((url = ldap_dn_to_url(ld, dn, nameparts)) == NULL) {
		free(dn);
		return (0);
	}
	free(dn);

	/* merge filter and/or scope and/or attributes with URL */
	if (attrs || scope || filter) {

		if (attrs)
			attrs_len = strlen(attrs) + 2; /* for comma and NULL */

		if (scope)
			scope_len = strlen(scope) + 1; /* for NULL */

		if (filter)
			filter_len = strlen(filter) + 4;
			    /* for ampersand, parentheses and NULL */

		if (ldap_is_ldap_url(url)) {

			if ((url2 = (char *)malloc(attrs_len + scope_len +
			    filter_len + strlen(url) + 1)) == NULL) {
				return (0);
			}
			cp = url;
			cp2 = url2;

			/* copy URL scheme, hostname, port number and DN */
			while (*cp && (*cp != '?')) {
				*cp2++ = *cp++;
			}

			/* handle URL attributes */

			if (*cp == '?') {	/* test first '?' */
				*cp2++ = *cp++; /* copy first '?' */

				if (*cp == '?') {	/* test second '?' */

					/* insert supplied attributes */
					if (attrs) {
						while (*attrs) {
							*cp2++ = *attrs++;
						}
					} else {
						no_attrs = 1;
					}

				} else {

					/* copy URL attributes */
					while (*cp && (*cp != '?')) {
						*cp2++ = *cp++;
					}

					/* append supplied attributes */
					if (attrs) {
						*cp2++ = ',';
						while (*attrs) {
							*cp2++ = *attrs++;
						}
					}
				}

			} else {
				/* append supplied attributes */
				if (attrs) {
					*cp2++ = '?';
					while (*attrs) {
						*cp2++ = *attrs++;
					}
				} else {
					no_attrs = 1;
				}
			}

			/* handle URL scope */

			if (*cp == '?') {	/* test second '?' */
				*cp2++ = *cp++; /* copy second '?' */

				if (*cp == '?') {	/* test third '?' */

					/* insert supplied scope */
					if (scope) {
						while (*scope) {
							*cp2++ = *scope++;
						}
					} else {
						no_scope = 1;
					}

				} else {

					if (scope) {
						/* skip over URL scope */
						while (*cp && (*cp != '?')) {
							*cp++;
						}
						/* insert supplied scope */
						while (*scope) {
							*cp2++ = *scope++;
						}
					} else {

						/* copy URL scope */
						while (*cp && (*cp != '?')) {
							*cp2++ = *cp++;
						}
					}
				}

			} else {
				/* append supplied scope */
				if (scope) {
					if (no_attrs) {
						*cp2++ = '?';
					}
					*cp2++ = '?';
					while (*scope) {
						*cp2++ = *scope++;
					}
				} else {
					no_scope = 1;
				}
			}

			/* handle URL filter */

			if (*cp == '?') {	/* test third '?' */
				*cp2++ = *cp++; /* copy third '?' */

				if (filter) {

					/* merge URL and supplied filters */

					*cp2++ = '(';
					*cp2++ = '&';
					/* copy URL filter */
					while (*cp) {
						*cp2++ = *cp++;
					}
					/* append supplied filter */
					while (*filter) {
						*cp2++ = *filter++;
					}
					*cp2++ = ')';
				} else {

					/* copy URL filter */
					while (*cp) {
						*cp2++ = *cp++;
					}
				}

			} else {
				/* append supplied filter */
				if (filter) {
					if (no_scope) {
						if (no_attrs) {
							*cp2++ = '?';
						}
						*cp2++ = '?';
					}
					*cp2++ = '?';
					while (*filter) {
						*cp2++ = *filter++;
					}
				}
			}

			*cp2++ = '\0';
			free (url);
			url = url2;

		} else {
			return (0);	/* not an LDAP URL */
		}
	}
	return (url);
}


/*
 * Locate the LDAP URL associated with a distinguished name.
 *
 * The number of nameparts in the supplied distinguished name must be
 * provided. The specified directory entry is searched for a labeledURI
 * attribute. If successful then the LDAP URL is returned. If unsuccessful
 * then that entry's parent is searched and so on until the target
 * distinguished name is reduced to only two nameparts.
 *
 * For example, if 'l=ny,ou=eng,o=wiz,c=us' is the distinguished name
 * then the following entries are searched until one succeeds:
 * 		l=ny,ou=eng,o=wiz,c=us
 * 		ou=eng,o=wiz,c=us
 * 		o=wiz,c=us
 *
 * If an error is encountered then zero is returned, otherwise a string
 * URL is returned. The caller should free the returned string if it is
 * non-zero.
 */

char *
ldap_dn_to_url(
	LDAP	*ld,
	char	*dn,
	int	nameparts
)
{
	char		*next_dn = dn;
	char		*url = 0;
	char		*attrs[2] = {"labeledURI", 0};
	LDAPMessage	*res, *e;
	char		**vals;

	/*
	 * Search for a URL in the named entry or its parent entry.
	 * Continue until only 2 nameparts remain.
	 */
	while (dn && (nameparts > 1) && (! url)) {

		/* search for the labeledURI attribute */
		if (ldap_search_s(ld, dn, LDAP_SCOPE_BASE,
		    "(objectClass=*)", attrs, 0, &res) == LDAP_SUCCESS) {

			/* locate the first entry returned */
			if ((e = ldap_first_entry(ld, res)) != NULL) {

				/* locate the labeledURI attribute */
				if ((vals =
				    ldap_get_values(ld, e, "labeledURI")) !=
				    NULL) {

					/* copy the attribute value */
					if ((url = strdup((char *)vals[0])) !=
					    NULL) {
						ldap_value_free(vals);
					}
				}
			}
			/* free the search results */
			ldap_msgfree(res);
		}

		if (! url) {
			/* advance along the DN by one namepart */
			if (next_dn = strchr(dn, ',')) {
				next_dn++;
				dn = next_dn;
				nameparts--;
			}
		}
	}

	return (url);
}
