/*
 *
 * Portions Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright (c) 1993, 1994 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 *
 * searchpref.c:  search preferences library routines for LDAP clients
 * 17 May 1994 by Gordon Good
 */

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#ifdef MACOS
#include "macos.h"
#else /* MACOS */
#ifdef DOS
#include <malloc.h>
#include "msdos.h"
#else /* DOS */
#include <sys/types.h>
#include <sys/file.h>
#ifndef VMS
#include <unistd.h>
#endif /* VMS */
#endif /* DOS */
#endif /* MACOS */

#include "lber.h"
#include "ldap.h"
#include "ldap-private.h"

#ifndef NEEDPROTOS
int next_line_tokens();
void free_strarray();
static void free_searchobj();
static int read_next_searchobj();
#else /* !NEEDPROTOS */
int next_line_tokens( char **bufp, ssize_t *blenp, char ***toksp );
void free_strarray( char **sap );
static void free_searchobj( struct ldap_searchobj *so );
static int read_next_searchobj( char **bufp, ssize_t *blenp,
	struct ldap_searchobj **sop, int soversion );
#endif /* !NEEDPROTOS */


static char		*sobjoptions[] = {
    "internal",
    NULL
};


static unsigned int	sobjoptvals[] = {
    LDAP_SEARCHOBJ_OPT_INTERNAL,
};


int
ldap_init_searchprefs( char *file, struct ldap_searchobj **solistp )
{
    FILE	*fp;
    char	*buf;
    ssize_t	rlen, len;
    int		rc, eof;

    if (( fp = fopen( file, "r" )) == NULL ) {
	return( LDAP_SEARCHPREF_ERR_FILE );
    }

    if ( fseek( fp, 0L, SEEK_END ) != 0 ) {	/* move to end to get len */
	fclose( fp );
	return( LDAP_SEARCHPREF_ERR_FILE );
    }

    len = ftell( fp );

    if ( fseek( fp, 0L, SEEK_SET ) != 0 ) {	/* back to start of file */
	fclose( fp );
	return( LDAP_SEARCHPREF_ERR_FILE );
    }

    if (( buf = malloc( (size_t)len )) == NULL ) {
	fclose( fp );
	return( LDAP_SEARCHPREF_ERR_MEM );
    }

    rlen = fread( buf, (size_t) 1, (size_t)len, fp );
    eof = feof( fp );
    fclose( fp );

    if ( rlen != len && !eof ) {	/* error:  didn't get the whole file */
	free( buf );
	return( LDAP_SEARCHPREF_ERR_FILE );
    }

    rc = ldap_init_searchprefs_buf( buf, rlen, solistp );
    free( buf );

    return( rc );
}


int
ldap_init_searchprefs_buf( char *buf, ssize_t buflen,
	struct ldap_searchobj **solistp )
{
    int				rc, version;
    char			**toks;
    struct ldap_searchobj	*prevso, *so;

    *solistp = prevso = NULLSEARCHOBJ;

    if ( next_line_tokens( &buf, &buflen, &toks ) != 2 ||
	    strcasecmp( toks[ 0 ], "version" ) != 0 ) {
	free_strarray( toks );
	return( LDAP_SEARCHPREF_ERR_SYNTAX );
    }
    version = atoi( toks[ 1 ] );
    free_strarray( toks );
    if ( version != LDAP_SEARCHPREF_VERSION &&
	    version != LDAP_SEARCHPREF_VERSION_ZERO ) {
	return( LDAP_SEARCHPREF_ERR_VERSION );
    }

    while ( buflen > 0 && ( rc = read_next_searchobj( &buf, &buflen, &so,
	    version )) == 0 && so != NULLSEARCHOBJ ) {
	if ( prevso == NULLSEARCHOBJ ) {
	    *solistp = so;
	} else {
	    prevso->so_next = so;
	}
	prevso = so;
    }

    if ( rc != 0 ) {
	ldap_free_searchprefs( *solistp );
    }

    return( rc );
}
	    


void
ldap_free_searchprefs( struct ldap_searchobj *solist )
{
    struct ldap_searchobj	*so, *nextso;

    if ( solist != NULL ) {
	for ( so = solist; so != NULL; so = nextso ) {
	    nextso = so->so_next;
	    free_searchobj( so );
	}
    }
    /* XXX XXX need to do some work here */
}


static void
free_searchobj( struct ldap_searchobj *so )
{
    if ( so != NULL ) {
	if ( so->so_objtypeprompt != NULL ) {
	    free(  so->so_objtypeprompt );
	}
	if ( so->so_prompt != NULL ) {
	    free(  so->so_prompt );
	}
	if ( so->so_filterprefix != NULL ) {
	    free(  so->so_filterprefix );
	}
	if ( so->so_filtertag != NULL ) {
	    free(  so->so_filtertag );
	}
	if ( so->so_defaultselectattr != NULL ) {
	    free(  so->so_defaultselectattr );
	}
	if ( so->so_defaultselecttext != NULL ) {
	    free(  so->so_defaultselecttext );
	}
	if ( so->so_salist != NULL ) {
	    struct ldap_searchattr *sa, *nextsa;
	    for ( sa = so->so_salist; sa != NULL; sa = nextsa ) {
		nextsa = sa->sa_next;
		if ( sa->sa_attrlabel != NULL ) {
		    free( sa->sa_attrlabel );
		}
		if ( sa->sa_attr != NULL ) {
		    free( sa->sa_attr );
		}
		if ( sa->sa_selectattr != NULL ) {
		    free( sa->sa_selectattr );
		}
		if ( sa->sa_selecttext != NULL ) {
		    free( sa->sa_selecttext );
		}
		free( sa );
	    }
	}
	if ( so->so_smlist != NULL ) {
	    struct ldap_searchmatch *sm, *nextsm;
	    for ( sm = so->so_smlist; sm != NULL; sm = nextsm ) {
		nextsm = sm->sm_next;
		if ( sm->sm_matchprompt != NULL ) {
		    free( sm->sm_matchprompt );
		}
		if ( sm->sm_filter != NULL ) {
		    free( sm->sm_filter );
		}
		free( sm );
	    }
	}
	free( so );
    }
}



struct ldap_searchobj *
ldap_first_searchobj( struct ldap_searchobj *solist )
{
    return( solist );
}


struct ldap_searchobj *
ldap_next_searchobj( struct ldap_searchobj *solist, struct ldap_searchobj *so )
{
    return( so == NULLSEARCHOBJ ? so : so->so_next );
}



static int
read_next_searchobj( char **bufp, ssize_t *blenp, struct ldap_searchobj **sop,
	int soversion )
{
    int				i, j, tokcnt;
    char			**toks;
    struct ldap_searchobj	*so;
    struct ldap_searchattr	**sa;
    struct ldap_searchmatch	**sm;

    *sop = NULL;

    /*
     * Object type prompt comes first
     */
    if (( tokcnt = next_line_tokens( bufp, blenp, &toks )) != 1 ) {
	free_strarray( toks );
	return( tokcnt == 0 ? 0 : LDAP_SEARCHPREF_ERR_SYNTAX );
    }

    if (( so = (struct ldap_searchobj *)calloc( (size_t) 1,
	    sizeof( struct ldap_searchobj ))) == NULL ) {
	free_strarray( toks );
	return(  LDAP_SEARCHPREF_ERR_MEM );
    }
    so->so_objtypeprompt = toks[ 0 ];
    free( (char *)toks );

    /*
     * if this is post-version zero, options come next
     */
    if ( soversion > LDAP_SEARCHPREF_VERSION_ZERO ) {
	if (( tokcnt = next_line_tokens( bufp, blenp, &toks )) < 1 ) {
	    free_strarray( toks );
	    ldap_free_searchprefs( so );
	    return( LDAP_SEARCHPREF_ERR_SYNTAX );
	}
	for ( i = 0; toks[ i ] != NULL; ++i ) {
	    for ( j = 0; sobjoptions[ j ] != NULL; ++j ) {
		if ( strcasecmp( toks[ i ], sobjoptions[ j ] ) == 0 ) {
		    so->so_options |= sobjoptvals[ j ];
		}
	    }
	}
	free_strarray( toks );
    }

    /*
     * "Fewer choices" prompt is next
     */
    if (( tokcnt = next_line_tokens( bufp, blenp, &toks )) != 1 ) {
	free_strarray( toks );
	ldap_free_searchprefs( so );
	return( LDAP_SEARCHPREF_ERR_SYNTAX );
    }
    so->so_prompt = toks[ 0 ];
    free( (char *)toks );

    /*
     * Filter prefix for "More Choices" searching is next
     */
    if (( tokcnt = next_line_tokens( bufp, blenp, &toks )) != 1 ) {
	free_strarray( toks );
	ldap_free_searchprefs( so );
	return( LDAP_SEARCHPREF_ERR_SYNTAX );
    }
    so->so_filterprefix = toks[ 0 ];
    free( (char *)toks );

    /*
     * "Fewer Choices" filter tag comes next
     */
    if (( tokcnt = next_line_tokens( bufp, blenp, &toks )) != 1 ) {
	free_strarray( toks );
	ldap_free_searchprefs( so );
	return( LDAP_SEARCHPREF_ERR_SYNTAX );
    }
    so->so_filtertag = toks[ 0 ];
    free( (char *)toks );

    /*
     * Selection (disambiguation) attribute comes next
     */
    if (( tokcnt = next_line_tokens( bufp, blenp, &toks )) != 1 ) {
	free_strarray( toks );
	ldap_free_searchprefs( so );
	return( LDAP_SEARCHPREF_ERR_SYNTAX );
    }
    so->so_defaultselectattr = toks[ 0 ];
    free( (char *)toks );

    /*
     * Label for selection (disambiguation) attribute
     */
    if (( tokcnt = next_line_tokens( bufp, blenp, &toks )) != 1 ) {
	free_strarray( toks );
	ldap_free_searchprefs( so );
	return( LDAP_SEARCHPREF_ERR_SYNTAX );
    }
    so->so_defaultselecttext = toks[ 0 ];
    free( (char *)toks );

    /*
     * Search scope is next
     */
    if (( tokcnt = next_line_tokens( bufp, blenp, &toks )) != 1 ) {
	free_strarray( toks );
	ldap_free_searchprefs( so );
	return( LDAP_SEARCHPREF_ERR_SYNTAX );
    }
    if ( !strcasecmp(toks[ 0 ], "subtree" )) {
	so->so_defaultscope = LDAP_SCOPE_SUBTREE;
    } else if ( !strcasecmp(toks[ 0 ], "onelevel" )) {
	so->so_defaultscope = LDAP_SCOPE_ONELEVEL;
    } else if ( !strcasecmp(toks[ 0 ], "base" )) {
	so->so_defaultscope = LDAP_SCOPE_BASE;
    } else {
	ldap_free_searchprefs( so );
	return( LDAP_SEARCHPREF_ERR_SYNTAX );
    }
    free_strarray( toks );


    /*
     * "More Choices" search option list comes next
     */
    sa = &( so->so_salist );
    while (( tokcnt = next_line_tokens( bufp, blenp, &toks )) > 0 ) {
	if ( tokcnt < 5 ) {
	    free_strarray( toks );
	    ldap_free_searchprefs( so );
	    return( LDAP_SEARCHPREF_ERR_SYNTAX );
	}
	if (( *sa = ( struct ldap_searchattr * ) calloc( (size_t) 1,
		sizeof( struct ldap_searchattr ))) == NULL ) {
	    free_strarray( toks );
	    ldap_free_searchprefs( so );
	    return(  LDAP_SEARCHPREF_ERR_MEM );
	}
	( *sa )->sa_attrlabel = toks[ 0 ];
	( *sa )->sa_attr = toks[ 1 ];
	( *sa )->sa_selectattr = toks[ 3 ];
	( *sa )->sa_selecttext = toks[ 4 ];
	/* Deal with bitmap */
	( *sa )->sa_matchtypebitmap = 0;
	for ( i = (int) strlen( toks[ 2 ] ) - 1, j = 0; i >= 0; i--, j++ ) {
	    if ( toks[ 2 ][ i ] == '1' ) {
		( *sa )->sa_matchtypebitmap |= (1 << j);
	    }
	}
	free( toks[ 2 ] );
	free( ( char * ) toks );
	sa = &(( *sa )->sa_next);
    }
    *sa = NULL;

    /*
     * Match types are last
     */
    sm = &( so->so_smlist );
    while (( tokcnt = next_line_tokens( bufp, blenp, &toks )) > 0 ) {
	if ( tokcnt < 2 ) {
	    free_strarray( toks );
	    ldap_free_searchprefs( so );
	    return( LDAP_SEARCHPREF_ERR_SYNTAX );
	}
	if (( *sm = ( struct ldap_searchmatch * ) calloc( (size_t) 1,
		sizeof( struct ldap_searchmatch ))) == NULL ) {
	    free_strarray( toks );
	    ldap_free_searchprefs( so );
	    return(  LDAP_SEARCHPREF_ERR_MEM );
	}
	( *sm )->sm_matchprompt = toks[ 0 ];
	( *sm )->sm_filter = toks[ 1 ];
	free( ( char * ) toks );
	sm = &(( *sm )->sm_next );
    }
    *sm = NULL;

    *sop = so;
    return( 0 );
}
