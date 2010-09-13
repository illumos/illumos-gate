/*
 * Copyright 2000-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *  Copyright (c) 1993 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  getfilter.c -- optional add-on to libldap
 */

#ifndef lint 
static char copyright[] = "@(#) Copyright (c) 1993 Regents of the University of Michigan.\nAll rights reserved.\n";
#endif

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#if defined(NeXT)
#include <regex.h>
#endif
#ifdef MACOS
#include <stdlib.h>
#include "macos.h"
#else /* MACOS */
#ifdef DOS
#include <malloc.h>
#include "msdos.h"
#else /* DOS */
#include <sys/types.h>
#include <sys/file.h>
#include <stdlib.h>
#include <errno.h>
#ifndef VMS
#include <unistd.h>
#endif /* VMS */
#endif /* DOS */
#endif /* MACOS */

#include "lber.h"
#include "ldap.h"
#include "ldap-private.h"
#include "ldap-int.h"
#include "regex.h"

#ifdef NEEDPROTOS
static int break_into_words( char *str, char *delims, char ***wordsp );
int next_line_tokens( char **bufp, ssize_t *blenp, char ***toksp );
void free_strarray( char **sap );
#else /* NEEDPROTOS */
static int break_into_words();
int next_line_tokens();
void free_strarray();
#endif /* NEEDPROTOS */

#if !defined( MACOS ) && !defined( DOS )
extern int	errno;
extern char	*re_comp();
#endif

#define FILT_MAX_LINE_LEN	1024

LDAPFiltDesc *
ldap_init_getfilter( char *fname )
{
    FILE		*fp;
    char		*buf;
    ssize_t	rlen, len;
    int 		eof;
    LDAPFiltDesc	*lfdp;

    if (( fp = fopen( fname, "r" )) == NULL ) {
	return( NULL );
    }

    if ( fseek( fp, 0L, SEEK_END ) != 0 ) {	/* move to end to get len */
	fclose( fp );
	return( NULL );
    }

    len = ftell( fp );

    if ( fseek( fp, 0L, SEEK_SET ) != 0 ) {	/* back to start of file */
	fclose( fp );
	return( NULL );
    }

    if (( buf = malloc( len )) == NULL ) {
	fclose( fp );
	return( NULL );
    }

    rlen = fread( buf, (size_t) 1, len, fp );
    eof = feof( fp );
    fclose( fp );

    if ( rlen != len && !eof ) {	/* error:  didn't get the whole file */
	free( buf );
	return( NULL );
    }


    lfdp = ldap_init_getfilter_buf( buf, rlen );
    free( buf );

    return( lfdp );
}


LDAPFiltDesc *
ldap_init_getfilter_buf( char *buf, ssize_t buflen )
{
    LDAPFiltDesc	*lfdp;
    LDAPFiltList	*flp, *nextflp;
    LDAPFiltInfo	*fip, *nextfip;
    char		*tag, **tok;
    int			tokcnt, i;

    if (( lfdp = (LDAPFiltDesc *)calloc( (size_t) 1, sizeof( LDAPFiltDesc))) == NULL ) {
	return( NULL );
    }

    flp = nextflp = NULL;
    fip = NULL;
    tag = NULL;

    while ( buflen > 0 && ( tokcnt = next_line_tokens( &buf, &buflen, &tok ))
	    > 0 ) {

	switch( tokcnt ) {
	case 1:		/* tag line */
	    if ( tag != NULL ) {
		free( tag );
	    }
	    tag = tok[ 0 ];
	    free( tok );
	    break;
	case 4:
	case 5:		/* start of filter info. list */
	    if (( nextflp = (LDAPFiltList *)calloc( (size_t) 1, sizeof( LDAPFiltList )))
		    == NULL ) {
		ldap_getfilter_free( lfdp );
		return( NULL );
	    }
	    nextflp->lfl_tag = strdup( tag );
	    nextflp->lfl_pattern = tok[ 0 ];
	    if ( re_comp( nextflp->lfl_pattern ) != NULL ) {
#ifndef NO_USERINTERFACE
		ldap_getfilter_free( lfdp );
		fprintf( stderr, "bad regular expresssion %s\n",
			nextflp->lfl_pattern );
#if !defined( MACOS ) && !defined( DOS )
		errno = EINVAL;
#endif
#endif /* NO_USERINTERFACE */
		free_strarray( tok );
		return( NULL );
	    }
		
	    nextflp->lfl_delims = tok[ 1 ];
	    nextflp->lfl_ilist = NULL;
	    nextflp->lfl_next = NULL;
	    if ( flp == NULL ) {	/* first one */
		lfdp->lfd_filtlist = nextflp;
	    } else {
		flp->lfl_next = nextflp;
	    }
	    flp = nextflp;
	    fip = NULL;
	    for ( i = 2; i < 5; ++i ) {
		tok[ i - 2 ] = tok[ i ];
	    }
	    /* fall through */

	case 2:
	case 3:		/* filter, desc, and optional search scope */
	    if ( nextflp != NULL ) { /* add to info list */
		if (( nextfip = (LDAPFiltInfo *)calloc( (size_t) 1,
			sizeof( LDAPFiltInfo ))) == NULL ) {
		    ldap_getfilter_free( lfdp );
		    free_strarray( tok );
		    return( NULL );
		}
		if ( fip == NULL ) {	/* first one */
		    nextflp->lfl_ilist = nextfip;
		} else {
		    fip->lfi_next = nextfip;
		}
		fip = nextfip;
		nextfip->lfi_next = NULL;
		nextfip->lfi_filter = tok[ 0 ];
		nextfip->lfi_desc = tok[ 1 ];
		if ( tok[ 2 ] != NULL ) {
		    if ( strcasecmp( tok[ 2 ], "subtree" ) == 0 ) {
			nextfip->lfi_scope = LDAP_SCOPE_SUBTREE;
		    } else if ( strcasecmp( tok[ 2 ], "onelevel" ) == 0 ) {
			nextfip->lfi_scope = LDAP_SCOPE_ONELEVEL;
		    } else if ( strcasecmp( tok[ 2 ], "base" ) == 0 ) {
			nextfip->lfi_scope = LDAP_SCOPE_BASE;
		    } else {
			free_strarray( tok );
			ldap_getfilter_free( lfdp );
#if !defined( MACOS ) && !defined( DOS )
			errno = EINVAL;
#endif
			return( NULL );
		    }
		    free( tok[ 2 ] );
		    tok[ 2 ] = NULL;
		} else {
		    nextfip->lfi_scope = LDAP_SCOPE_SUBTREE;	/* default */
		}
		nextfip->lfi_isexact = ( strchr( tok[ 0 ], '*' ) == NULL &&
			strchr( tok[ 0 ], '~' ) == NULL );
		free( tok );
	    }
	    break;

	default:
	    free_strarray( tok );
	    ldap_getfilter_free( lfdp );
#if !defined( MACOS ) && !defined( DOS )
	    errno = EINVAL;
#endif
	    return( NULL );
	}
    }

    if ( tag != NULL ) {
	free( tag );
    }

    return( lfdp );
}


void
ldap_setfilteraffixes( LDAPFiltDesc *lfdp, char *prefix, char *suffix )
{
    if ( lfdp->lfd_filtprefix != NULL ) {
	free( lfdp->lfd_filtprefix );
    }
    lfdp->lfd_filtprefix = ( prefix == NULL ) ? NULL : strdup( prefix );

    if ( lfdp->lfd_filtsuffix != NULL ) {
	free( lfdp->lfd_filtsuffix );
    }
    lfdp->lfd_filtsuffix = ( suffix == NULL ) ? NULL : strdup( suffix );
}


LDAPFiltInfo *
ldap_getfirstfilter( LDAPFiltDesc *lfdp, char *tagpat, char *value )
{
    LDAPFiltList	*flp;

    if ( lfdp->lfd_curvalcopy != NULL ) {
	free( lfdp->lfd_curvalcopy );
	free( lfdp->lfd_curvalwords );
    }

    lfdp->lfd_curval = value;
    lfdp->lfd_curfip = NULL;

    for ( flp = lfdp->lfd_filtlist; flp != NULL; flp = flp->lfl_next ) {
	if ( re_comp( tagpat ) == NULL && re_exec( flp->lfl_tag ) == 1
		&& re_comp( flp->lfl_pattern ) == NULL
		&& re_exec( lfdp->lfd_curval ) == 1 ) {
	    lfdp->lfd_curfip = flp->lfl_ilist;
	    break;
	}
    }

    if ( lfdp->lfd_curfip == NULL ) {
	return( NULL );
    }

    if (( lfdp->lfd_curvalcopy = strdup( value )) == NULL ) {
	return( NULL );
    }

    if ( break_into_words( lfdp->lfd_curvalcopy, flp->lfl_delims,
		&lfdp->lfd_curvalwords ) < 0 ) {
	free( lfdp->lfd_curvalcopy );
	lfdp->lfd_curvalcopy = NULL;
	return( NULL );
    }

    return( ldap_getnextfilter( lfdp ));
}


LDAPFiltInfo *
ldap_getnextfilter( LDAPFiltDesc *lfdp )
{
    LDAPFiltInfo	*fip;

    fip = lfdp->lfd_curfip;

    if ( fip == NULL ) {
	return( NULL );
    }

    lfdp->lfd_curfip = fip->lfi_next;

    ldap_build_filter( lfdp->lfd_filter, (size_t) LDAP_FILT_MAXSIZ, fip->lfi_filter,
	    lfdp->lfd_filtprefix, lfdp->lfd_filtsuffix, NULL,
	    lfdp->lfd_curval, lfdp->lfd_curvalwords );
    lfdp->lfd_retfi.lfi_filter = lfdp->lfd_filter;
    lfdp->lfd_retfi.lfi_desc = fip->lfi_desc;
    lfdp->lfd_retfi.lfi_scope = fip->lfi_scope;
    lfdp->lfd_retfi.lfi_isexact = fip->lfi_isexact;

    return( &lfdp->lfd_retfi );
}


void
ldap_build_filter( char *filtbuf, size_t buflen, char *pattern,
	char *prefix, char *suffix, char *attr, char *value, char **valwords )
{
	char	*p, *f;
	size_t	slen;
	int	i, wordcount, wordnum, endwordnum;
	
	if ( valwords == NULL ) {
	    wordcount = 0;
	} else {
	    for ( wordcount = 0; valwords[ wordcount ] != NULL; ++wordcount ) {
		;
	    }
	}

	f = filtbuf;

	if ( prefix != NULL ) {
	    strcpy( f, prefix );
	    f += strlen( prefix );
	}

	for ( p = pattern; *p != '\0'; ++p ) {
	    if ( *p == '%' ) {
		++p;
		if ( *p == 'v' ) {
		    if ( isdigit( *(p+1))) {
			++p;
			wordnum = *p - '1';
			if ( *(p+1) == '-' ) {
			    ++p;
			    if ( isdigit( *(p+1))) {
				++p;
				endwordnum = *p - '1';	/* e.g., "%v2-4" */
#ifndef SUN /* Patch from innosoft Craig.Watkins 08.Jul.97 */
				if ( endwordnum > wordcount - 1 ) {
				    endwordnum = wordcount - 1;
				}
#endif
			    } else {
				endwordnum = wordcount - 1;  /* e.g., "%v2-" */
			    }
			} else {
			    endwordnum = wordnum;	/* e.g., "%v2" */
			}
#ifdef SUN /* Patch from innosoft Craig.Watkins 08.Jul.97 */
			if ( endwordnum > wordcount - 1 ) {
				endwordnum = wordcount - 1;
			}
#endif
			if ( wordcount > 0 ) {
			    for ( i = wordnum; i <= endwordnum; ++i ) {
				if ( i > wordnum ) {  /* add blank btw words */
				    *f++ = ' ';
				}
				slen = strlen( valwords[ i ] );
				SAFEMEMCPY( f, valwords[ i ], slen );
				f += slen;
			    }
			}
		    } else if ( *(p+1) == '$' ) {
			++p;
			if ( wordcount > 0 ) {
			    wordnum = wordcount - 1;
			    slen = strlen( valwords[ wordnum ] );
			    SAFEMEMCPY( f, valwords[ wordnum ], slen );
			    f += slen;
			}
		    } else if ( value != NULL ) {
			slen = strlen( value );
			SAFEMEMCPY( f, value, slen );
			f += slen;
		    }
		} else if ( *p == 'a' && attr != NULL ) {
		    slen = strlen( attr );
		    SAFEMEMCPY( f, attr, slen );
		    f += slen;
		} else {
		    *f++ = *p;
		}
	    } else {
		*f++ = *p;
	    }
		
	    if ( f - filtbuf > buflen ) {
		/* sanity check */
		--f;
		break;
	    }
	}

	if ( suffix != NULL && ( f - filtbuf ) < buflen ) {
	    strcpy( f, suffix );
	} else {
	    *f = '\0';
	}
}


static int
break_into_words( char *str, char *delims, char ***wordsp )
{
    char	*word, **words;
    int		count;
	
    if (( words = (char **)calloc( (size_t) 1, sizeof( char * ))) == NULL ) {
	return( -1 );
    }
    count = 0;
    words[ count ] = NULL;

    word = strtok( str, delims );
    while ( word != NULL ) {
	if (( words = (char **)realloc( words,
		( count + 2 ) * sizeof( char * ))) == NULL ) {
	    return( -1 );
	}

	words[ count ] = word;
	words[ ++count ] = NULL;
	word = strtok( NULL, delims );
    }
	
    *wordsp = words;
    return( count );
}
