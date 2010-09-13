/*
 *
 * Portions Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *  Copyright (c) 1990 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  ufn.c
 */

#ifndef lint 
static char copyright[] = "@(#) Copyright (c) 1993 Regents of the University of Michigan.\nAll rights reserved.\n";
#endif

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h> /* malloc(), realloc(), free() */

#ifdef MACOS
#include <stdlib.h>
#include "macos.h"
#else /* MACOS */
#if defined( DOS ) || defined( _WIN32 )
#include "msdos.h"
#else /* DOS */
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#endif /* DOS */
#endif /* MACOS */

#include "lber.h"
#include "ldap.h"
#include "ldap-private.h"
#include "ldap-int.h"
#ifdef SUN
/*
 * to include definition of FILTERFILE and or TEMPLATEFILE
 */
#include "ldapconfig.h" 
#endif

#ifdef NEEDPROTOS
typedef int (*cancelptype)( void *cancelparm );
#else /* NEEDPROTOS */
typedef int (*cancelptype)();
#endif /* NEEDPROTOS */

#ifdef NEEDPROTOS
static int ldap_ufn_search_ctx( LDAP *ld, char **ufncomp, int ncomp, 
	char *prefix, char **attrs, int attrsonly, LDAPMessage **res, 
	cancelptype cancelproc, void *cancelparm, char *tag1, char *tag2,
	char *tag3 );
static LDAPMessage *ldap_msg_merge( LDAP *ld, LDAPMessage *a, LDAPMessage *b );
static LDAPMessage *ldap_ufn_expand( LDAP *ld, cancelptype cancelproc,
	void *cancelparm, char **dns, char *filter, int scope,
	char **attrs, int aonly, int *err );
LDAPFiltDesc *ldap_ufn_setfilter( LDAP *ld, char *fname );
#else /* NEEDPROTOS */
static LDAPMessage *ldap_msg_merge();
static LDAPMessage *ldap_ufn_expand();
LDAPFiltDesc *ldap_ufn_setfilter();
#endif /* NEEDPROTOS */
static LDAPMessage *ldap_msg_merge();
static LDAPMessage *ldap_ufn_expand();

/*
 * ldap_ufn_search_ctx - do user friendly searching; provide cancel feature;
 *			specify ldapfilter.conf tags for each phase of search
 *
 *	ld		LDAP descriptor
 *	ufncomp		the exploded user friendly name to look for
 *	ncomp		number of elements in ufncomp
 *	prefix		where to start searching
 *	attrs		list of attribute types to return for matches
 *	attrsonly	1 => attributes only 0 => attributes and values
 *	res		will contain the result of the search
 *	cancelproc	routine that returns non-zero if operation should be
 *			cancelled.  This can be NULL.  If it is non-NULL, the
 *			routine will be called periodically.
 *	cancelparm	void * that is passed to cancelproc
 *	tag[123]	the ldapfilter.conf tag that will be used in phases
 *			1, 2, and 3 of the search, respectively
 *
 * Example:
 *	char		*attrs[] = { "mail", "title", 0 };
 *	char		*ufncomp[] = { "howes", "umich", "us", 0 }
 *	LDAPMessage	*res;
 *	error = ldap_ufn_search_ctx( ld, ufncomp, 3, NULL, attrs, attrsonly,
 *			&res, acancelproc, along, "ufn first",
 *			"ufn intermediate", "ufn last" );
 */

static int
ldap_ufn_search_ctx( LDAP *ld, char **ufncomp, int ncomp, char *prefix,
	char **attrs, int attrsonly, LDAPMessage **res, cancelptype cancelproc,
	void *cancelparm, char *tag1, char *tag2, char *tag3 )
{
	char		*dn, *ftag;
	char		**dns;
	int		max, i, err, scope, phase, tries;
	LDAPFiltInfo	*fi;
	LDAPMessage	*tmpcand;
	LDAPMessage	*candidates;
	/* LDAPMessage	*ldap_msg_merge(), *ldap_ufn_expand(); */
	static char	*objattrs[] = { "objectClass", NULL };

	/* 
	 * look up ufn components from most to least significant.
	 * there are 3 phases.  
	 * 	phase 1	search the root for orgs or countries
	 * 	phase 2	search for orgs
	 * 	phase 3	search for a person
	 * in phases 1 and 2, we are building a list of candidate DNs,
	 * below which we will search for the final component of the ufn.
	 * for each component we try the filters listed in the
	 * filterconfig file, first one-level (except the last compoment),
	 * then subtree.  if any of them produce any results, we go on to
	 * the next component.
	 */

#if defined( SUN ) && defined( _REENTRANT )
        LOCK_LDAP(ld);
#endif
	*res = NULL;
	candidates = NULL;
	phase = 1;
	for ( ncomp--; ncomp != -1; ncomp-- ) {
		if ( *ufncomp[ncomp] == '"' ) {
			char	*quote;

			if ( (quote = strrchr( ufncomp[ncomp], '"' )) != NULL )
				*quote = '\0';
			(void) strcpy( ufncomp[ncomp], ufncomp[ncomp] + 1 );
		}
		if ( ncomp == 0 )
			phase = 3;

		switch ( phase ) {
		case 1:
			ftag = tag1;
			scope = LDAP_SCOPE_ONELEVEL;
			break;
		case 2:
			ftag = tag2;
			scope = LDAP_SCOPE_ONELEVEL;
			break;
		case 3:
			ftag = tag3;
			scope = LDAP_SCOPE_SUBTREE;
			break;
		}

		/*
		 * construct an array of DN's to search below from the
		 * list of candidates.
		 */

		if ( candidates == NULL ) {
			if ( prefix != NULL ) {
				if ( (dns = (char **) malloc( sizeof(char *)
				    * 2 )) == NULL ) {
#if defined( SUN ) && defined( _REENTRANT )
					UNLOCK_LDAP(ld);
#endif
					return( ld->ld_errno = LDAP_NO_MEMORY );
				}
				dns[0] = strdup( prefix );
				dns[1] = NULL;
			} else {
				dns = NULL;
			}
		} else {
			i = 0, max = 0;
			for ( tmpcand = candidates; tmpcand != NULL &&
			    tmpcand->lm_msgtype != LDAP_RES_SEARCH_RESULT;
			    tmpcand = tmpcand->lm_chain )
			{
				if ( (dn = ldap_get_dn( ld, tmpcand )) == NULL )
					continue;

				if ( dns == NULL ) {
					if ( (dns = (char **) malloc(
					    sizeof(char *) * 8 )) == NULL ) {
						ld->ld_errno = LDAP_NO_MEMORY;
#if defined( SUN ) && defined( _REENTRANT )
						UNLOCK_LDAP(ld);
#endif
						return( LDAP_NO_MEMORY );
					}
					max = 8;
				} else if ( i >= max ) {
					if ( (dns = (char **) realloc( dns,
					    sizeof(char *) * 2 * max ))
					    == NULL )
					{
						ld->ld_errno = LDAP_NO_MEMORY;
#if defined( SUN ) && defined( _REENTRANT )
						UNLOCK_LDAP(ld);
#endif
						return( LDAP_NO_MEMORY );
					}
					max *= 2;
				}
				dns[i++] = dn;
				dns[i] = NULL;
			}
			ldap_msgfree( candidates );
			candidates = NULL;
		}
		tries = 0;
	tryagain:
		tries++;
		for ( fi = ldap_getfirstfilter( ld->ld_filtd, ftag,
		    ufncomp[ncomp] ); fi != NULL;
		    fi = ldap_getnextfilter( ld->ld_filtd ) )
		{
			if ( (candidates = ldap_ufn_expand( ld, cancelproc,
			    cancelparm, dns, fi->lfi_filter, scope,
			    phase == 3 ? attrs : objattrs,
			    phase == 3 ? attrsonly : 1, &err )) != NULL )
			{
				break;
			}

			if ( err == -1 || err == LDAP_USER_CANCELLED ) {
				if ( dns != NULL ) {
					ldap_value_free( dns );
					dns = NULL;
				}
#if defined( SUN ) && defined( _REENTRANT )
				UNLOCK_LDAP(ld);
#endif
				return( err );
			}
		}

		if ( candidates == NULL ) {
			if ( tries < 2 && phase != 3 ) {
				scope = LDAP_SCOPE_SUBTREE;
				goto tryagain;
			} else {
				if ( dns != NULL ) {
					ldap_value_free( dns );
					dns = NULL;
				}
#if defined( SUN ) && defined( _REENTRANT )
				UNLOCK_LDAP(ld);
#endif
				return( err );
			}
		}

		/* go on to the next component */
		if ( phase == 1 )
			phase++;
		if ( dns != NULL ) {
			ldap_value_free( dns );
			dns = NULL;
		}
	}
	*res = candidates;

#if defined( SUN ) && defined( _REENTRANT )
        UNLOCK_LDAP(ld);
#endif
	return( err );
}

int
ldap_ufn_search_ct( LDAP *ld, char *ufn, char **attrs, int attrsonly,
	LDAPMessage **res, cancelptype cancelproc, void *cancelparm,
	char *tag1, char *tag2, char *tag3 )
{
	char	**ufncomp, **prefixcomp;
	char	*pbuf;
	int	ncomp, pcomp, i, err;

#if defined( SUN ) && defined( _REENTRANT )
        LOCK_LDAP(ld);
#endif
	/* initialize the getfilter stuff if it's not already */
	if ( ld->ld_filtd == NULL && ldap_ufn_setfilter( ld, FILTERFILE )
	    == NULL ) {
#if defined( SUN ) && defined( _REENTRANT )
		UNLOCK_LDAP(ld);
#endif
		return( ld->ld_errno = LDAP_LOCAL_ERROR );
	}

	/* call ldap_explode_dn() to break the ufn into its components */
	if ( (ufncomp = ldap_explode_dn( ufn, 0 )) == NULL ) {
#if defined( SUN ) && defined( _REENTRANT )
		UNLOCK_LDAP(ld);
#endif
		return( ld->ld_errno = LDAP_LOCAL_ERROR );
	}
	for ( ncomp = 0; ufncomp[ncomp] != NULL; ncomp++ )
		;	/* NULL */

	/* more than two components => try it fully qualified first */
	if ( ncomp > 2 || ld->ld_ufnprefix == NULL ) {
		err = ldap_ufn_search_ctx( ld, ufncomp, ncomp, NULL, attrs,
		    attrsonly, res, cancelproc, cancelparm, tag1, tag2, tag3 );

		if ( ldap_count_entries( ld, *res ) > 0 ) {
			ldap_value_free( ufncomp );
#if defined( SUN ) && defined( _REENTRANT )
			UNLOCK_LDAP(ld);
#endif
			return( err );
		} else {
			ldap_msgfree( *res );
			*res = NULL;
		}
	}

	if ( ld->ld_ufnprefix == NULL ) {
		ldap_value_free( ufncomp );
#if defined( SUN ) && defined( _REENTRANT )
		UNLOCK_LDAP(ld);
#endif
		return( err );
	}

	/* if that failed, or < 2 components, use the prefix */
	if ( (prefixcomp = ldap_explode_dn( ld->ld_ufnprefix, 0 )) == NULL ) {
		ldap_value_free( ufncomp );
#if defined( SUN ) && defined( _REENTRANT )
		UNLOCK_LDAP(ld);
#endif
		return( ld->ld_errno = LDAP_LOCAL_ERROR );
	}
	for ( pcomp = 0; prefixcomp[pcomp] != NULL; pcomp++ )
		;	/* NULL */
	if ( (pbuf = (char *) malloc( strlen( ld->ld_ufnprefix ) + 1 ))
	    == NULL ) {	
		ldap_value_free( ufncomp );
		ldap_value_free( prefixcomp );
#if defined( SUN ) && defined( _REENTRANT )
		UNLOCK_LDAP(ld);
#endif
		return( ld->ld_errno = LDAP_NO_MEMORY );
	}

	for ( i = 0; i < pcomp; i++ ) {
		int	j;

		*pbuf = '\0';
		for ( j = i; j < pcomp; j++ ) {
			(void) strcat( pbuf, prefixcomp[j] );
			if ( j + 1 < pcomp )
				(void) strcat( pbuf, "," );
		}
		err = ldap_ufn_search_ctx( ld, ufncomp, ncomp, pbuf, attrs,
		    attrsonly, res, cancelproc, cancelparm, tag1, tag2, tag3 );

		if ( ldap_count_entries( ld, *res ) > 0 ) {
			break;
		} else {
			ldap_msgfree( *res );
			*res = NULL;
		}
	}

	ldap_value_free( ufncomp );
	ldap_value_free( prefixcomp );
	free( pbuf );

#if defined( SUN ) && defined( _REENTRANT )
        UNLOCK_LDAP(ld);
#endif
	return( err );
}

/*
 * same as ldap_ufn_search_ct, except without the ability to specify
 * ldapfilter.conf tags.
 */
int
ldap_ufn_search_c( LDAP *ld, char *ufn, char **attrs, int attrsonly,
	LDAPMessage **res, cancelptype cancelproc, void *cancelparm )
{
	return( ldap_ufn_search_ct( ld, ufn, attrs, attrsonly, res, cancelproc,
	    cancelparm, "ufn first", "ufn intermediate", "ufn last" ) );
}

/*
 * same as ldap_ufn_search_c without the cancel function
 */
int
ldap_ufn_search_s( LDAP *ld, char *ufn, char **attrs, int attrsonly,
	LDAPMessage **res )
{
	struct timeval	tv;

	tv.tv_sec = ld->ld_timelimit;

	return( ldap_ufn_search_ct( ld, ufn, attrs, attrsonly, res,
		ld->ld_timelimit ? ldap_ufn_timeout : NULL,
		ld->ld_timelimit ? (void *) &tv : NULL,
		"ufn first", "ufn intermediate", "ufn last" ) );
}


/*
 * ldap_msg_merge - merge two ldap search result chains.  the more
 * serious of the two error result codes is kept.
 */

static LDAPMessage *
ldap_msg_merge( LDAP *ld, LDAPMessage *a, LDAPMessage *b )
{
	LDAPMessage	*end, *aprev, *aend, *bprev, *bend;

	if ( a == NULL )
		return( b );

	if ( b == NULL )
		return( a );

	/* find the ends of the a and b chains */
	aprev = NULL;
	for ( aend = a; aend->lm_chain != NULL; aend = aend->lm_chain )
		aprev = aend;
	bprev = NULL;
	for ( bend = b; bend->lm_chain != NULL; bend = bend->lm_chain )
		bprev = bend;

	/* keep result a */
	if ( ldap_result2error( ld, aend, 0 ) != LDAP_SUCCESS ) {
		/* remove result b */
		ldap_msgfree( bend );
		if ( bprev != NULL )
			bprev->lm_chain = NULL;
		else
			b = NULL;
		end = aend;
		if ( aprev != NULL )
			aprev->lm_chain = NULL;
		else
			a = NULL;
	/* keep result b */
	} else {
		/* remove result a */
		ldap_msgfree( aend );
		if ( aprev != NULL )
			aprev->lm_chain = NULL;
		else
			a = NULL;
		end = bend;
		if ( bprev != NULL )
			bprev->lm_chain = NULL;
		else
			b = NULL;
	}

	if ( (a == NULL && b == NULL) || (a == NULL && bprev == NULL) ||
	    (b == NULL && aprev == NULL) )
		return( end );

	if ( a == NULL ) {
		bprev->lm_chain = end;
		return( b );
	} else if ( b == NULL ) {
		aprev->lm_chain = end;
		return( a );
	} else {
		bprev->lm_chain = end;
		aprev->lm_chain = b;
		return( a );
	}
}

static LDAPMessage *
ldap_ufn_expand( LDAP *ld, cancelptype cancelproc, void *cancelparm,
	char **dns, char *filter, int scope, char **attrs, int aonly,
	int *err )
{
	LDAPMessage	*tmpcand, *tmpres;
	char		*dn;
	int		i, msgid;
	struct timeval	tv;

	/* search for this component below the current candidates */
	tmpcand = NULL;
	i = 0;
	do {
		if ( dns != NULL )
			dn = dns[i];
		else
			dn = "";

		if (( msgid = ldap_search( ld, dn, scope, filter, attrs,
		    aonly )) == -1 ) {
			ldap_msgfree( tmpcand );
			*err = ld->ld_errno;
			return( NULL );
		}

		tv.tv_sec = 0;
		tv.tv_usec = 100000;	/* 1/10 of a second */

		do {
			*err = ldap_result( ld, msgid, 1, &tv, &tmpres );
			if ( *err == 0 && cancelproc != NULL &&
			    (*cancelproc)( cancelparm ) != 0 ) {
				ldap_abandon( ld, msgid );
				*err = LDAP_USER_CANCELLED;
				ld->ld_errno = LDAP_USER_CANCELLED;
			}
		} while ( *err == 0 );

		if ( *err == LDAP_USER_CANCELLED || *err < 0 ||
		    ( *err = ldap_result2error( ld, tmpres, 0 )) == -1 ) {
			ldap_msgfree( tmpcand );
			return( NULL );
		}
		
		tmpcand = ldap_msg_merge( ld, tmpcand, tmpres );

		i++;
	} while ( dns != NULL && dns[i] != NULL );

	if ( ldap_count_entries( ld, tmpcand ) > 0 ) {
		return( tmpcand );
	} else {
		ldap_msgfree( tmpcand );
		return( NULL );
	}
}

/*
 * ldap_ufn_setfilter - set the filter config file used in ufn searching
 */

LDAPFiltDesc *
ldap_ufn_setfilter( LDAP *ld, char *fname )
{
#if defined( SUN ) && defined( _REENTRANT )
	LDAPFiltDesc *rv;
	
        LOCK_LDAP(ld);
#endif
	if ( ld->ld_filtd != NULL )
		ldap_getfilter_free( ld->ld_filtd );

#if defined( SUN ) && defined( _REENTRANT )
        ld->ld_filtd = ldap_init_getfilter( fname );
	rv = ld->ld_filtd;
        UNLOCK_LDAP(ld);
	return( rv );
#else
	return( ld->ld_filtd = ldap_init_getfilter( fname ) );
#endif
}

void
ldap_ufn_setprefix( LDAP *ld, char *prefix )
{
#if defined( SUN ) && defined( _REENTRANT )
        LOCK_LDAP(ld);
#endif
	if ( ld->ld_ufnprefix != NULL )
		free( ld->ld_ufnprefix );

	ld->ld_ufnprefix = strdup( prefix );
#if defined( SUN ) && defined( _REENTRANT )
        UNLOCK_LDAP(ld);
#endif
}

int
ldap_ufn_timeout( void *tvparam )
{
	struct timeval	*tv;

	tv = (struct timeval *)tvparam;

	if ( tv->tv_sec != 0 ) {
		tv->tv_usec = tv->tv_sec * 1000000;	/* sec => micro sec */
		tv->tv_sec = 0;
	}
	tv->tv_usec -= 100000;	/* 1/10 of a second */

	return( tv->tv_usec <= 0 ? 1 : 0 );
}
