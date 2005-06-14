/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * tmplout.c:  display template library output routines for LDAP clients
 * 12 April 1994 by Mark C Smith
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <tzfile.h>
#include <stdlib.h>
#ifdef MACOS
#include "macos.h"
#else /* MACOS */
#ifdef DOS
#include <malloc.h>
#include "msdos.h"
#else /* DOS */
#include <sys/time.h>
#include <sys/types.h>
#include <sys/file.h>
#endif /* DOS */
#endif /* MACOS */

#ifdef VMS
#include <sys/socket.h>
#endif /* VMS */

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
static int do_entry2text( LDAP *ld, char *buf, char *base, LDAPMessage *entry,
	struct ldap_disptmpl *tmpl, char **defattrs, char ***defvals,
	writeptype writeproc, void *writeparm, char *eol, int rdncount,
	unsigned int opts, char *urlprefix );
static int do_entry2text_search( LDAP *ld, char *dn, char *base,
	LDAPMessage *entry, struct ldap_disptmpl *tmpllist, char **defattrs,
	char ***defvals, writeptype writeproc, void *writeparm, char *eol,
	int rdncount, unsigned int opts, char *urlprefix );
static int do_vals2text( LDAP *ld, char *buf, char **vals, char *label,
	int labelwidth, unsigned int syntaxid, writeptype writeproc,
	void *writeparm, char *eol, int rdncount, char *urlprefix );
static int max_label_len( struct ldap_disptmpl *tmpl );
static int output_label( char *buf, char *label, int width,
	writeptype writeproc, void *writeparm, char *eol, int html );
static int output_dn( char *buf, char *dn, int width, int rdncount,
	writeptype writeproc, void *writeparm, char *eol, char *urlprefix );
static void strcat_escaped( char *s1, char *s2 );
static char *time2text( char *ldtimestr, int dateonly );
static time_t gtime( struct tm *tm );
static int searchaction( LDAP *ld, char *buf, char *base, LDAPMessage *entry,
	char *dn, struct ldap_tmplitem *tip, int labelwidth, int rdncount,
	writeptype writeproc, void *writeparm, char *eol, char *urlprefix );
#else /* NEEDPROTOS */
static int do_entry2text();
static int do_entry2text_search();
static int do_vals2text();
static int max_label_len();
static int output_label();
static int output_dn();
static void strcat_escaped();
static char *time2text();
static time_t gtime();
static int searchaction();
#endif /* NEEDPROTOS */

#define DEF_LABEL_WIDTH		15
#define SEARCH_TIMEOUT_SECS	120
#define OCATTRNAME		"objectClass"


#define NONFATAL_LDAP_ERR( err )	( err == LDAP_SUCCESS || \
	err == LDAP_TIMELIMIT_EXCEEDED || err == LDAP_SIZELIMIT_EXCEEDED )

#define DEF_LDAP_URL_PREFIX	"ldap:///"

 
int
ldap_entry2text(
	LDAP			*ld,
	char			*buf,		/* NULL for "use internal" */
	LDAPMessage		*entry,
	struct ldap_disptmpl	*tmpl,
	char			**defattrs,
	char			***defvals,
	writeptype		writeproc,
	void			*writeparm,
	char			*eol,
	int			rdncount,
	unsigned int		opts
)
{
#if defined( SUN ) && defined( _REENTRANT )
    int rv;
    
    LOCK_LDAP(ld);
#endif
    Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 253, "ldap_entry2text\n"), 0, 0, 0 );

#if defined( SUN ) && defined( _REENTRANT )
    rv = do_entry2text( ld, buf, NULL, entry, tmpl, defattrs, defvals,
		writeproc, writeparm, eol, rdncount, opts, NULL );
    UNLOCK_LDAP(ld);
    return( rv );
#else
    return( do_entry2text( ld, buf, NULL, entry, tmpl, defattrs, defvals,
		writeproc, writeparm, eol, rdncount, opts, NULL ));
#endif
}



int
ldap_entry2html(
	LDAP			*ld,
	char			*buf,		/* NULL for "use internal" */
	LDAPMessage		*entry,
	struct ldap_disptmpl	*tmpl,
	char			**defattrs,
	char			***defvals,
	writeptype		writeproc,
	void			*writeparm,
	char			*eol,
	int			rdncount,
	unsigned int		opts,
	char			*base,
	char			*urlprefix
)
{
#if defined( SUN ) && defined( _REENTRANT )
    int rv;
    
    LOCK_LDAP(ld);
#endif
    Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 254, "ldap_entry2html\n"), 0, 0, 0 );

    if ( urlprefix == NULL ) {
	urlprefix = DEF_LDAP_URL_PREFIX;
    }

#if defined( SUN ) && defined( _REENTRANT )
    rv = do_entry2text( ld, buf, base, entry, tmpl, defattrs, defvals,
				writeproc, writeparm, eol, rdncount, opts, urlprefix );
    UNLOCK_LDAP(ld);
    return( rv );
#else
    return( do_entry2text( ld, buf, base, entry, tmpl, defattrs, defvals,
		writeproc, writeparm, eol, rdncount, opts, urlprefix ));
#endif
}


static int
do_entry2text(
	LDAP			*ld,
	char			*buf,		/* NULL for use-internal */
	char			*base,		/* used for search actions */
	LDAPMessage		*entry,
	struct ldap_disptmpl	*tmpl,
	char			**defattrs,
	char			***defvals,
	writeptype		writeproc,
	void			*writeparm,
	char			*eol,
	int			rdncount,
	unsigned int		opts,
	char			*urlprefix	/* if non-NULL, do HTML */
)
{
    int				i, err, html, show, labelwidth;
    int				freebuf,  freevals;
    char			*dn, **vals;
    struct ldap_tmplitem	*rowp, *colp;

    if (( dn = ldap_get_dn( ld, entry )) == NULL ) {
	return( ld->ld_errno );
    }

    if ( buf == NULL ) {
	if (( buf = malloc( LDAP_DTMPL_BUFSIZ )) == NULL ) {
	    ld->ld_errno = LDAP_NO_MEMORY;
	    free( dn );
	    return( ld->ld_errno );
	}
	freebuf = 1;
    } else {
	freebuf = 0;
    }

    html = ( urlprefix != NULL );

    if ( html ) {
	/*
	 * add HTML intro. and title
	 */
	if (!(( opts & LDAP_DISP_OPT_HTMLBODYONLY ) != 0 )) {
	    sprintf( buf, "<HTML>%s<HEAD>%s<TITLE>%s%s - ", eol, eol, eol,
		    ( tmpl == NULL ) ? "Entry" : tmpl->dt_name );
	    (*writeproc)( writeparm, buf, strlen( buf ));
	    output_dn( buf, dn, 0, rdncount, writeproc, writeparm, "", NULL );
	    sprintf( buf, "%s</TITLE>%s</HEAD>%s<BODY>%s<H3>%s - ", eol, eol,
		    eol, eol, ( tmpl == NULL ) ? "Entry" : tmpl->dt_name );
	    (*writeproc)( writeparm, buf, strlen( buf ));
	    output_dn( buf, dn, 0, rdncount, writeproc, writeparm, "", NULL );
	    sprintf( buf, "</H3>%s", eol );
	    (*writeproc)( writeparm, buf, strlen( buf ));
	}

	if (( opts & LDAP_DISP_OPT_NONLEAF ) != 0 &&
		( vals = ldap_explode_dn( dn, 0 )) != NULL ) {
	    char	*untagged;

	    /*
	     * add "Move Up" link
	     */
	    sprintf( buf, "<A HREF=\"%s", urlprefix );
	    for ( i = 1; vals[ i ] != NULL; ++i ) {
		if ( i > 1 ) {
		     strcat_escaped( buf, ", " );
		}
		strcat_escaped( buf, vals[ i ] );
	    }
	    if ( vals[ 1 ] != NULL ) {
		untagged = strchr( vals[ 1 ], '=' );
	    } else {
		untagged = "=The World";
	    }
	    sprintf( buf + strlen( buf ),
		    "%s\">Move Up To <EM>%s</EM></A>%s<BR>",
		    ( vals[ 1 ] == NULL ) ? "??one" : "",
		    ( untagged != NULL ) ? untagged + 1 : vals[ 1 ], eol, eol );
	    (*writeproc)( writeparm, buf, strlen( buf ));

	    /*
	     * add "Browse" link
	     */
	    untagged = strchr( vals[ 0 ], '=' );
	    sprintf( buf, "<A HREF=\"%s", urlprefix );
	    strcat_escaped( buf, dn );
	    sprintf( buf + strlen( buf ), "??one?(!(objectClass=dsa))\">Browse Below <EM>%s</EM></A>%s%s",
		    ( untagged != NULL ) ? untagged + 1 : vals[ 0 ], eol, eol );
	    (*writeproc)( writeparm, buf, strlen( buf ));

	    ldap_value_free( vals );
	}

	(*writeproc)( writeparm, "<HR>", 4 );	/* horizontal rule */
    } else {
	(*writeproc)( writeparm, "\"", 1 );
	output_dn( buf, dn, 0, rdncount, writeproc, writeparm, "", NULL );
	sprintf( buf, "\"%s", eol );
	(*writeproc)( writeparm, buf, strlen( buf ));
    }

    if ( tmpl != NULL && ( opts & LDAP_DISP_OPT_AUTOLABELWIDTH ) != 0 ) {
	labelwidth = max_label_len( tmpl ) + 3;
    } else {
	labelwidth = DEF_LABEL_WIDTH;;
    }

    err = LDAP_SUCCESS;

    if ( tmpl == NULL ) {
	BerElement	*ber;
	char		*attr;

	ber = NULL;
	for ( attr = ldap_first_attribute( ld, entry, &ber );
		NONFATAL_LDAP_ERR( err ) && attr != NULL;
		attr = ldap_next_attribute( ld, entry, ber )) {
	    if (( vals = ldap_get_values( ld, entry, attr )) == NULL ) {
		freevals = 0;
		if ( defattrs != NULL ) {
		    for ( i = 0; defattrs[ i ] != NULL; ++i ) {
			if ( strcasecmp( attr, defattrs[ i ] ) == 0 ) {
			    break;
			}
		    }
		    if ( defattrs[ i ] != NULL ) {
			vals = defvals[ i ];
		    }
		}
	    } else {
		freevals = 1;
	    }

	    if ( islower( *attr )) {	/* cosmetic -- upcase attr. name */
		*attr = toupper( *attr );
	    }

	    err = do_vals2text( ld, buf, vals, attr, labelwidth,
		    LDAP_SYN_CASEIGNORESTR, writeproc, writeparm, eol, 
		    rdncount, urlprefix );
	    if ( freevals ) {
		ldap_value_free( vals );
	    }
	}
    } else {
	for ( rowp = ldap_first_tmplrow( tmpl );
		NONFATAL_LDAP_ERR( err ) && rowp != NULLTMPLITEM;
		rowp = ldap_next_tmplrow( tmpl, rowp )) {
	    for ( colp = ldap_first_tmplcol( tmpl, rowp ); colp != NULLTMPLITEM;
		    colp = ldap_next_tmplcol( tmpl, rowp, colp )) {
		vals = NULL;
		if ( colp->ti_attrname == NULL || ( vals = ldap_get_values( ld,
			entry, colp->ti_attrname )) == NULL ) {
		    freevals = 0;
		    if ( !LDAP_IS_TMPLITEM_OPTION_SET( colp,
			    LDAP_DITEM_OPT_HIDEIFEMPTY ) && defattrs != NULL
			    && colp->ti_attrname != NULL ) {
			for ( i = 0; defattrs[ i ] != NULL; ++i ) {
			    if ( strcasecmp( colp->ti_attrname, defattrs[ i ] )
				    == 0 ) {
				break;
			    }
			}
			if ( defattrs[ i ] != NULL ) {
			    vals = defvals[ i ];
			}
		    }
		} else {
		    freevals = 1;
		    if ( LDAP_IS_TMPLITEM_OPTION_SET( colp,
			    LDAP_DITEM_OPT_SORTVALUES ) && vals[ 0 ] != NULL
			    && vals[ 1 ] != NULL ) {
			ldap_sort_values( ld, vals, ldap_sort_strcasecmp );
		    }
		}

		/*
		 * don't bother even calling do_vals2text() if no values
		 * or boolean with value false and "hide if false" option set
		 */
		show = ( vals != NULL && vals[ 0 ] != NULL );
		if ( show && LDAP_GET_SYN_TYPE( colp->ti_syntaxid )
			== LDAP_SYN_TYPE_BOOLEAN && LDAP_IS_TMPLITEM_OPTION_SET(
			colp, LDAP_DITEM_OPT_HIDEIFFALSE ) &&
			toupper( vals[ 0 ][ 0 ] ) != 'T' ) {
		    show = 0;
		}

		if ( colp->ti_syntaxid == LDAP_SYN_SEARCHACTION ) {
		    if (( opts & LDAP_DISP_OPT_DOSEARCHACTIONS ) != 0 ) {
			if ( colp->ti_attrname == NULL || ( show &&
				toupper( vals[ 0 ][ 0 ] ) == 'T' )) {
			    err = searchaction( ld, buf, base, entry, dn, colp,
				    labelwidth, rdncount, writeproc,
				    writeparm, eol, urlprefix );
			}
		    }
		    show = 0;
		}

		if ( show ) {
		    err = do_vals2text( ld, buf, vals, colp->ti_label,
			labelwidth, colp->ti_syntaxid, writeproc, writeparm,
			eol, rdncount, urlprefix );
		}

		if ( freevals ) {
		    ldap_value_free( vals );
		}
	    }
	}
    }

    if ( html  && !(( opts & LDAP_DISP_OPT_HTMLBODYONLY ) != 0 )) {
	sprintf( buf, "</BODY>%s</HTML>%s", eol, eol );
	(*writeproc)( writeparm, buf, strlen( buf ));
    }

    free( dn );
    if ( freebuf ) {
	free( buf );
    }

    return( err );
}

	
int
ldap_entry2text_search(
	LDAP			*ld,
	char			*dn,		/* if NULL, use entry */
	char			*base,		/* if NULL, no search actions */
	LDAPMessage		*entry, 	/* if NULL, use dn */
	struct ldap_disptmpl*	tmpllist,	/* if NULL, load default file */
	char			**defattrs,
	char			***defvals,
	writeptype		writeproc,
	void			*writeparm,
	char			*eol,
	int			rdncount,	/* if 0, display full DN */
	unsigned int		opts
)
{
#if defined( SUN ) && defined( _REENTRANT )
	int rv;
	
        LOCK_LDAP(ld);
#endif
    Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 255, "ldap_entry2text_search\n"), 0, 0, 0 );

#if defined( SUN ) && defined( _REENTRANT )
    rv = do_entry2text_search( ld, dn, base, entry, tmpllist, defattrs,
	    defvals, writeproc, writeparm, eol, rdncount, opts, NULL );
    UNLOCK_LDAP(ld);
    return( rv );
#else
    return( do_entry2text_search( ld, dn, base, entry, tmpllist, defattrs,
	    defvals, writeproc, writeparm, eol, rdncount, opts, NULL ));
#endif
}



int
ldap_entry2html_search(
	LDAP			*ld,
	char			*dn,		/* if NULL, use entry */
	char			*base,		/* if NULL, no search actions */
	LDAPMessage		*entry, 	/* if NULL, use dn */
	struct ldap_disptmpl*	tmpllist,	/* if NULL, load default file */
	char			**defattrs,
	char			***defvals,
	writeptype		writeproc,
	void			*writeparm,
	char			*eol,
	int			rdncount,	/* if 0, display full DN */
	unsigned int		opts,
	char			*urlprefix
)
{
#if defined( SUN ) && defined( _REENTRANT )
	int rv;
	
        LOCK_LDAP(ld);
#endif
    Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 256, "ldap_entry2html_search\n"), 0, 0, 0 );

#if defined( SUN ) && defined( _REENTRANT )
    rv = do_entry2text_search( ld, dn, base, entry, tmpllist, defattrs,
	    defvals, writeproc, writeparm, eol, rdncount, opts, urlprefix );
    UNLOCK_LDAP(ld);
    return( rv );
#else
    return( do_entry2text_search( ld, dn, base, entry, tmpllist, defattrs,
	    defvals, writeproc, writeparm, eol, rdncount, opts, urlprefix ));
#endif
}


static int
do_entry2text_search(
	LDAP			*ld,
	char			*dn,		/* if NULL, use entry */
	char			*base,		/* if NULL, no search actions */
	LDAPMessage		*entry, 	/* if NULL, use dn */
	struct ldap_disptmpl*	tmpllist,	/* if NULL, load default file */
	char			**defattrs,
	char			***defvals,
	writeptype		writeproc,
	void			*writeparm,
	char			*eol,
	int			rdncount,	/* if 0, display full DN */
	unsigned int		opts,
	char			*urlprefix
)
{
    int				err, freedn, freetmpls, html;
    char			*buf, **fetchattrs, **vals;
    LDAPMessage			*ldmp;
    struct ldap_disptmpl	*tmpl;
    struct timeval		timeout;

    if ( dn == NULL && entry == NULLMSG ) {
	ld->ld_errno = LDAP_PARAM_ERROR;
	return( ld->ld_errno );
    }

    html = ( urlprefix != NULL );

    timeout.tv_sec = SEARCH_TIMEOUT_SECS;
    timeout.tv_usec = 0;

    if (( buf = malloc( LDAP_DTMPL_BUFSIZ )) == NULL ) {
	ld->ld_errno = LDAP_NO_MEMORY;
	return( ld->ld_errno );
    }

    freedn = freetmpls = 0;
    tmpl = NULL;

    if ( tmpllist == NULL ) {
	if (( err = ldap_init_templates( TEMPLATEFILE, &tmpllist )) != 0 ) {
	    sprintf( buf, "%sUnable to read template file %s (error %d)%s%s",
		    html ? "<!-- " : "", TEMPLATEFILE, err,
		    html ? "-->" : "", eol );
	    (*writeproc)( writeparm, buf, strlen( buf ));
	}
	freetmpls = 1;
    }

    if ( dn == NULL ) {
	if (( dn = ldap_get_dn( ld, entry )) == NULL ) {
	    free( buf );
	    if ( freetmpls ) {
		ldap_free_templates( tmpllist );
	    }
	    return( ld->ld_errno );
	}
	freedn = 1;
    }


    if ( tmpllist != NULL ) {
	ldmp = NULLMSG;

	if ( entry == NULL ) {
	    char	*ocattrs[2];

	    ocattrs[0] = OCATTRNAME;
	    ocattrs[1] = NULL;
#ifdef CLDAP
	    if ( LDAP_IS_CLDAP( ld ))
		    err = cldap_search_s( ld, dn, LDAP_SCOPE_BASE,
			"objectClass=*", ocattrs, 0, &ldmp, NULL );
	    else
#endif /* CLDAP */
		    err = ldap_search_st( ld, dn, LDAP_SCOPE_BASE,
			    "objectClass=*", ocattrs, 0, &timeout, &ldmp );

	    if ( err == LDAP_SUCCESS ) {
		entry = ldap_first_entry( ld, ldmp );
	    }
	}

	if ( entry != NULL ) {
	    vals = ldap_get_values( ld, entry, OCATTRNAME );
	    tmpl = ldap_oc2template( vals, tmpllist );
	    if ( vals != NULL ) {
		ldap_value_free( vals );
	    }
	}
	if ( ldmp != NULL ) {
	    ldap_msgfree( ldmp );
	}
    }

    entry = NULL;

    if ( tmpl == NULL ) {
	fetchattrs = NULL;
    } else {
	fetchattrs = ldap_tmplattrs( tmpl, NULL, 1, LDAP_SYN_OPT_DEFER );
    }

#ifdef CLDAP
    if ( LDAP_IS_CLDAP( ld ))
	err = cldap_search_s( ld, dn, LDAP_SCOPE_BASE, "objectClass=*",
		fetchattrs, 0, &ldmp, NULL );
    else
#endif /* CLDAP */
	err = ldap_search_st( ld, dn, LDAP_SCOPE_BASE, "objectClass=*",
		fetchattrs, 0, &timeout, &ldmp );

    if ( freedn ) {
	free( dn );
    }
    if ( fetchattrs != NULL ) {
	ldap_value_free( fetchattrs );
    }

    if ( err != LDAP_SUCCESS ||
	    ( entry = ldap_first_entry( ld, ldmp )) == NULL ) {
	if ( freetmpls ) {
            ldap_free_templates( tmpllist );
        }
	free( buf );
	return( ld->ld_errno );
    }

    err = do_entry2text( ld, buf, base, entry, tmpl, defattrs, defvals,
	    writeproc, writeparm, eol, rdncount, opts, urlprefix );

    free( buf );
    if ( freetmpls ) {
	ldap_free_templates( tmpllist );
    }
    ldap_msgfree( ldmp );
    return( err );
}
	    

int
ldap_vals2text(
	LDAP			*ld,
	char			*buf,		/* NULL for "use internal" */
	char			**vals,
	char			*label,
	int			labelwidth,	/* 0 means use default */
	unsigned int		syntaxid,
	writeptype		writeproc,
	void			*writeparm,
	char			*eol,
	int			rdncount
)
{
#if defined( SUN ) && defined( _REENTRANT )
	int rv;
	
        LOCK_LDAP(ld);
#endif
    Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 257, "ldap_vals2text\n"), 0, 0, 0 );

#if defined( SUN ) && defined( _REENTRANT )
    rv = do_vals2text( ld, buf, vals, label, labelwidth, syntaxid,
			  writeproc, writeparm, eol, rdncount, NULL );
    UNLOCK_LDAP(ld);
    return( rv );
#else
    return( do_vals2text( ld, buf, vals, label, labelwidth, syntaxid,
		writeproc, writeparm, eol, rdncount, NULL ));
#endif
}


int
ldap_vals2html(
	LDAP			*ld,
	char			*buf,		/* NULL for "use internal" */
	char			**vals,
	char			*label,
	int			labelwidth,	/* 0 means use default */
	unsigned int		syntaxid,
	writeptype		writeproc,
	void			*writeparm,
	char			*eol,
	int			rdncount,
	char			*urlprefix
)
{
#if defined( SUN ) && defined( _REENTRANT )
	int rv;
	
        LOCK_LDAP(ld);
#endif
    Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 258, "ldap_vals2html\n"), 0, 0, 0 );

    if ( urlprefix == NULL ) {
	urlprefix = DEF_LDAP_URL_PREFIX;
    }

#if defined( SUN ) && defined( _REENTRANT )
    rv = do_vals2text( ld, buf, vals, label, labelwidth, syntaxid,
		       writeproc, writeparm, eol, rdncount, urlprefix );
    UNLOCK_LDAP(ld);
    return( rv );
#else
    return( do_vals2text( ld, buf, vals, label, labelwidth, syntaxid,
		writeproc, writeparm, eol, rdncount, urlprefix ));
#endif
}


static int
do_vals2text(
	LDAP			*ld,
	char			*buf,		/* NULL for "use internal" */
	char			**vals,
	char			*label,
	int			labelwidth,	/* 0 means use default */
	unsigned int		syntaxid,
	writeptype		writeproc,
	void			*writeparm,
	char			*eol,
	int			rdncount,
	char			*urlprefix
)
{
    int		i, html, writeoutval, freebuf, notascii;
    char	*p, *s, *outval;


    if ( vals == NULL ) {
	return( LDAP_SUCCESS );
    }

    html = ( urlprefix != NULL );

    switch( LDAP_GET_SYN_TYPE( syntaxid )) {
    case LDAP_SYN_TYPE_TEXT:
    case LDAP_SYN_TYPE_BOOLEAN:
	break;		/* we only bother with these two types... */
    default:
	return( LDAP_SUCCESS );
    }

    if ( labelwidth == 0 || labelwidth < 0 ) {
	labelwidth = DEF_LABEL_WIDTH;
    }

    if ( buf == NULL ) {
	if (( buf = malloc( LDAP_DTMPL_BUFSIZ )) == NULL ) {
	    ld->ld_errno = LDAP_NO_MEMORY;
	    return( ld->ld_errno );
	}
	freebuf = 1;
    } else {
	freebuf = 0;
    }

    output_label( buf, label, labelwidth, writeproc, writeparm, eol, html );

    for ( i = 0; vals[ i ] != NULL; ++i ) {
	for ( p = vals[ i ]; *p != '\0'; ++p ) {
	    if ( !isascii( *p )) {
		break;
	    }
	}
	notascii = ( *p != '\0' );
	outval = notascii ? "(unable to display non-ASCII text value)"
		: vals[ i ];

	writeoutval = 0;	/* if non-zero, write outval after switch */

	switch( syntaxid ) {
	case LDAP_SYN_CASEIGNORESTR:
	    ++writeoutval;
	    break;

	case LDAP_SYN_RFC822ADDR:
	    if ( html ) {
		strcpy( buf, "<DD><A HREF=\"mailto:" );
		strcat_escaped( buf, outval );
		sprintf( buf + strlen( buf ), "\">%s</A><BR>%s", outval, eol );
		(*writeproc)( writeparm, buf, strlen( buf ));
	    } else {
		++writeoutval;
	    }
	    break;

	case LDAP_SYN_DN:	/* for now */
	    output_dn( buf, outval, labelwidth, rdncount, writeproc,
		    writeparm, eol, urlprefix );
	    break;

	case LDAP_SYN_MULTILINESTR:
	    if ( i > 0 && !html ) {
		output_label( buf, label, labelwidth, writeproc,
			writeparm, eol, html );
	    }

	    p = s = outval;
	    while (( s = strchr( s, '$' )) != NULL ) {
		*s++ = '\0';
		while ( isspace( *s )) {
		    ++s;
		}
		if ( html ) {
		    sprintf( buf, "<DD>%s<BR>%s", p, eol );
		} else {
		    sprintf( buf, "%-*s%s%s", labelwidth, " ", p, eol );
		}
		(*writeproc)( writeparm, buf, strlen( buf ));
		p = s;
	    }
	    outval = p;
	    ++writeoutval;
	    break;

	case LDAP_SYN_BOOLEAN:
	    outval = toupper( outval[ 0 ] ) == 'T' ? "TRUE" : "FALSE";
	    ++writeoutval;
	    break;

	case LDAP_SYN_TIME:
	case LDAP_SYN_DATE:
	    outval = time2text( outval, syntaxid == LDAP_SYN_DATE );
	    ++writeoutval;
	    break;

	case LDAP_SYN_LABELEDURL:
	    if ( !notascii && ( p = strchr( outval, '$' )) != NULL ) {
		*p++ = '\0';
		while ( isspace( *p )) {
		    ++p;
		}
		s = outval;
	    } else if ( !notascii && ( s = strchr( outval, ' ' )) != NULL ) {
		*s++ = '\0';
		while ( isspace( *s )) {
		    ++s;
		}
		p = outval;
	    } else {
		s = "URL";
		p = outval;
	    }

	    /*
	     * at this point `s' points to the label & `p' to the URL
	     */
	    if ( html ) {
		sprintf( buf, "<DD><A HREF=\"%s\">%s</A><BR>%s", p, s, eol );
	    } else {
		sprintf( buf, "%-*s%s%s%-*s%s%s", labelwidth, " ",
		    s, eol, labelwidth + 2, " ",p , eol );
	    }
	    (*writeproc)( writeparm, buf, strlen( buf ));
	    break;

	default:
	    sprintf( buf, " Can't display item type %ld%s",
		    syntaxid, eol );
	    (*writeproc)( writeparm, buf, strlen( buf ));
	}

	if ( writeoutval ) {
	    if ( html ) {
		sprintf( buf, "<DD>%s<BR>%s", outval, eol );
	    } else {
		sprintf( buf, "%-*s%s%s", labelwidth, " ", outval, eol );
	    }
	    (*writeproc)( writeparm, buf, strlen( buf ));
	}
    }

    if ( freebuf ) {
	free( buf );
    }

    return( LDAP_SUCCESS );
}


static int
max_label_len( struct ldap_disptmpl *tmpl )
{
    struct ldap_tmplitem	*rowp, *colp;
    int				len, maxlen;

    maxlen = 0;

    for ( rowp = ldap_first_tmplrow( tmpl ); rowp != NULLTMPLITEM;
	    rowp = ldap_next_tmplrow( tmpl, rowp )) {
	for ( colp = ldap_first_tmplcol( tmpl, rowp ); colp != NULLTMPLITEM;
		colp = ldap_next_tmplcol( tmpl, rowp, colp )) {
	    if (( len = strlen( colp->ti_label )) > maxlen ) {
		maxlen = len;
	    }
	}
    }

    return( maxlen );
}


static int
output_label( char *buf, char *label, int width, writeptype writeproc,
	void *writeparm, char *eol, int html )
{
    char	*p;

    if ( html ) {
	sprintf( buf, "<DT><B>%s</B>", label );
    } else {
	sprintf( buf, " %s:", label );
	p = buf + strlen( buf );

	while ( p - buf < width ) {
	    *p++ = ' ';
	}

	*p = '\0';
	strcat( buf, eol );
    }

    return ((*writeproc)( writeparm, buf, strlen( buf )));
}


static int
output_dn( char *buf, char *dn, int width, int rdncount,
	writeptype writeproc, void *writeparm, char *eol, char *urlprefix )
{
    char	**dnrdns;
    int		i;

    if (( dnrdns = ldap_explode_dn( dn, 1 )) == NULL ) {
	return( -1 );
    }

    if ( urlprefix != NULL ) {
	sprintf( buf, "<DD><A HREF=\"%s", urlprefix );
	strcat_escaped( buf, dn );
	strcat( buf, "\">" );
    } else if ( width > 0 ) {
	sprintf( buf, "%-*s", width, " " );
    } else {
	*buf = '\0';
    }

    for ( i = 0; dnrdns[ i ] != NULL && ( rdncount == 0 || i < rdncount );
	    ++i ) {
	if ( i > 0 ) {
	    strcat( buf, ", " );
	}
	strcat( buf, dnrdns[ i ] );
    }

    if ( urlprefix != NULL ) {
	strcat( buf, "</A><BR>" );
    }

    ldap_value_free( dnrdns );

    strcat( buf, eol );

    return ((*writeproc)( writeparm, buf, strlen( buf )));
}



#define HREF_CHAR_ACCEPTABLE( c )	(( c >= '-' && c <= '9' ) ||	\
					 ( c >= '@' && c <= 'Z' ) ||	\
					 ( c == '_' ) ||		\
					 ( c >= 'a' && c <= 'z' ))

static void
strcat_escaped( char *s1, char *s2 )
{
    char	*p, *q;
    char	*hexdig = "0123456789ABCDEF";

    p = s1 + strlen( s1 );
    for ( q = s2; *q != '\0'; ++q ) {
	if ( HREF_CHAR_ACCEPTABLE( *q )) {
	    *p++ = *q;
	} else {
	    *p++ = '%';
	    *p++ = hexdig[ *q >> 4 ];
	    *p++ = hexdig[ *q & 0x0F ];
	}
    }

    *p = '\0';
}


#define GET2BYTENUM( p )	(( *p - '0' ) * 10 + ( *(p+1) - '0' ))

static char *
time2text( char *ldtimestr, int dateonly )
{
    struct tm		t;
    char		*p, zone, *fmterr = "badly formatted time";
    time_t		gmttime;
    int			century;
    static char 	timestr[128];

    memset( (char *)&t, 0, sizeof( struct tm ));
    if ( (int) strlen( ldtimestr ) < 13 ) {
	return( fmterr );
    }

    for ( p = ldtimestr; p - ldtimestr < 12; ++p ) {
	if ( !isdigit( *p )) {
	    return( fmterr );
	}
    }

    p = ldtimestr;
    century = GET2BYTENUM( p ) * 100; p += 2;
    century += GET2BYTENUM( p ); p += 2;
    /* tm_year is the offset of number of years from TM_YEAR_BASE */
    t.tm_year = century - TM_YEAR_BASE; 
    t.tm_mon = GET2BYTENUM( p ) - 1; p += 2;
    t.tm_mday = GET2BYTENUM( p ); p += 2;
    t.tm_hour = GET2BYTENUM( p ); p += 2;
    t.tm_min = GET2BYTENUM( p ); p += 2;
    t.tm_sec = GET2BYTENUM( p ); p += 2;

    /*strftime will return for e.g. Thu Aug 19 2001 */
    if (strftime(timestr, sizeof(timestr), "%a %b %d %Y", &t)  == 0) {
	return( fmterr );
    }
    if (dateonly)  {
	strcpy(timestr + 11, timestr + 20);
    }
    return( timestr );
}



/* gtime.c - inverse gmtime */

#if !defined( MACOS ) && !defined( _WIN32 ) && !defined( DOS )
#include <sys/time.h>
#endif /* !MACOS */

/* gtime(): the inverse of localtime().
	This routine was supplied by Mike Accetta at CMU many years ago.
 */

static int	dmsize[] = {
    31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
};

#define	dysize(y)	\
	(((y) % 4) ? 365 : (((y) % 100) ? 366 : (((y) % 400) ? 365 : 366)))

#define	YEAR(y)		((y) >= 100 ? (y) : (y) + 1900)

/*  */

static time_t	gtime ( struct tm *tm )
{
    register int    i,
                    sec,
                    mins,
                    hour,
                    mday,
                    mon,
                    year;
    register time_t   result;

    if ((sec = tm -> tm_sec) < 0 || sec > 59
	    || (mins = tm -> tm_min) < 0 || mins > 59
	    || (hour = tm -> tm_hour) < 0 || hour > 24
	    || (mday = tm -> tm_mday) < 1 || mday > 31
	    || (mon = tm -> tm_mon + 1) < 1 || mon > 12)
	return ((time_t) -1);
    if (hour == 24) {
	hour = 0;
	mday++;
    }
    year = YEAR (tm -> tm_year);

    result = 0L;
    for (i = 1970; i < year; i++)
	result += dysize (i);
    if (dysize (year) == 366 && mon >= 3)
	result++;
    while (--mon)
	result += dmsize[mon - 1];
    result += mday - 1;
    result = 24 * result + hour;
    result = 60 * result + mins;
    result = 60 * result + sec;

    return result;
}

static int
searchaction( LDAP *ld, char *buf, char *base, LDAPMessage *entry, char *dn,
	struct ldap_tmplitem *tip, int labelwidth, int rdncount,
	writeptype writeproc, void *writeparm, char *eol, char *urlprefix )
{
    int			err, lderr, i, count, html;
    char		**vals, **members;
    char		*value, *filtpattern, *attr, *selectname;
    char		*retattrs[2], filter[ 256 ];
    LDAPMessage		*ldmp;
    struct timeval	timeout;

    html = ( urlprefix != NULL );

    for ( i = 0; tip->ti_args != NULL && tip->ti_args[ i ] != NULL; ++i ) {
	;
    }
    if ( i < 3 ) {
	return( LDAP_PARAM_ERROR );
    }
    attr = tip->ti_args[ 0 ];
    filtpattern = tip->ti_args[ 1 ];
    retattrs[ 0 ] = tip->ti_args[ 2 ];
    retattrs[ 1 ] = NULL;
    selectname = tip->ti_args[ 3 ];

    vals = NULL;
    if ( attr == NULL ) {
	value = NULL;
    } else if ( strcasecmp( attr, "-dnb" ) == 0 ) {
	return( LDAP_PARAM_ERROR );
    } else if ( strcasecmp( attr, "-dnt" ) == 0 ) {
	value = dn;
    } else if (( vals = ldap_get_values( ld, entry, attr )) != NULL ) {
	value = vals[ 0 ];
    } else {
	value = NULL;
    }

    ldap_build_filter( filter, sizeof( filter ), filtpattern, NULL, NULL, NULL,
	    value, NULL );

    if ( html ) {
	/*
	 * if we are generating HTML, we add an HREF link that embodies this
	 * search action as an LDAP URL, instead of actually doing the search
	 * now.
	 */
	sprintf( buf, "<DT><A HREF=\"%s", urlprefix );
	if ( base != NULL ) {
	    strcat_escaped( buf, base );
	}
	strcat( buf, "??sub?" );
	strcat_escaped( buf, filter );
	sprintf( buf + strlen( buf ), "\"><B>%s</B></A><DD><BR>%s",
		tip->ti_label, eol );
	if ((*writeproc)( writeparm, buf, strlen( buf )) < 0 ) {
	    return( LDAP_LOCAL_ERROR );
	}
	return( LDAP_SUCCESS );
    }

    timeout.tv_sec = SEARCH_TIMEOUT_SECS;
    timeout.tv_usec = 0;

#ifdef CLDAP
    if ( LDAP_IS_CLDAP( ld ))
	lderr = cldap_search_s( ld, base, LDAP_SCOPE_SUBTREE, filter, retattrs,
		0, &ldmp, NULL );
    else
#endif /* CLDAP */
	lderr = ldap_search_st( ld, base, LDAP_SCOPE_SUBTREE, filter, retattrs,
		0, &timeout, &ldmp );

    if ( lderr == LDAP_SUCCESS || NONFATAL_LDAP_ERR( lderr )) {
	if (( count = ldap_count_entries( ld, ldmp )) > 0 ) {
	    if (( members = (char **)malloc( (count + 1) * sizeof(char *)))
		    == NULL ) {
		err = LDAP_NO_MEMORY;
	    } else {
		for ( i = 0, entry = ldap_first_entry( ld, ldmp );
			entry != NULL;
			entry = ldap_next_entry( ld, entry ), ++i ) {
		    members[ i ] = ldap_get_dn( ld, entry );
		}
		members[ i ] = NULL;

		ldap_sort_values( ld, members, ldap_sort_strcasecmp );

		err = do_vals2text( ld, NULL, members, tip->ti_label,
			html ? -1 : 0, LDAP_SYN_DN, writeproc, writeparm,
			eol, rdncount, urlprefix );

		ldap_value_free( members );
	    }
	}
	ldap_msgfree( ldmp );
    }

    
    if ( vals != NULL ) {
	ldap_value_free( vals );
    }

    return(( err == LDAP_SUCCESS ) ? lderr : err );
}
