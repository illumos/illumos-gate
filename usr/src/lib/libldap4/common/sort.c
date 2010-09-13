/*
 *
 * Portions Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright (c) 1994 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 *
 * sort.c:  LDAP library entry and value sort routines
 */

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#ifdef MACOS
#include "macos.h"
#else /* MACOS */
#ifdef DOS
#include <malloc.h>
#include "msdos.h"
#endif /* DOS */
#endif /* MACOS */

#include "lber.h"
#include "ldap.h"
#include "ldap-private.h"
#include "ldap-int.h"

struct entrything {
	char		**et_vals;
	LDAPMessage	*et_msg;
};

#ifndef NEEDPROTOS
static int	(*et_cmp_fn)();
static int	et_cmp();
#else /* !NEEDPROTOS */
static int	(*et_cmp_fn)( char *a, char *b );
#ifdef SUN
static int	et_cmp( const void *aa, const void *bb);
#else
static int	et_cmp( void *aa, void *bb);
#endif
#endif /* !NEEDPROTOS */

int
ldap_sort_strcasecmp(
    char	**a,
    char	**b
)
{
	return( strcasecmp( *a, *b ) );
}

static int
et_cmp(
#ifdef SUN
	const void	*aa,
	const void	*bb
#else
	void	*aa,
	void	*bb
#endif
)
{
	int			i, rc;
	struct entrything	*a = (struct entrything *)aa;
	struct entrything	*b = (struct entrything *)bb;

	if ( a->et_vals == NULL && b->et_vals == NULL )
		return( 0 );
	if ( a->et_vals == NULL )
		return( -1 );
	if ( b->et_vals == NULL )
		return( 1 );

	for ( i = 0; a->et_vals[i] && b->et_vals[i]; i++ ) {
		if ( (rc = (*et_cmp_fn)( a->et_vals[i], b->et_vals[i] ))
		    != 0 ) {
			return( rc );
		}
	}

	if ( a->et_vals[i] == NULL && b->et_vals[i] == NULL )
		return( 0 );
	if ( a->et_vals[i] == NULL )
		return( -1 );
	return( 1 );
}

int
ldap_sort_entries(
    LDAP	*ld,
    LDAPMessage	**chain,
    char	*attr,		/* NULL => sort by DN */
    int		(*cmp)()
)
{
	int			i;
	size_t			count;
	struct entrything	*et;
	LDAPMessage		*e, *last;
	LDAPMessage		**ep;

	count = ldap_count_entries( ld, *chain );

	if ( (et = (struct entrything *) malloc( count *
	    sizeof(struct entrything) )) == NULL ) {
		ld->ld_errno = LDAP_NO_MEMORY;
		return( -1 );
	}

	e = *chain;
	for ( i = 0; i < count; i++ ) {
		et[i].et_msg = e;
		if ( attr == NULL ) {
			char	*dn;

			dn = ldap_get_dn( ld, e );
			et[i].et_vals = ldap_explode_dn( dn, 1 );
			free( dn );
		} else {
			et[i].et_vals = ldap_get_values( ld, e, attr );
		}

		e = e->lm_chain;
	}
	last = e;

	et_cmp_fn = cmp;
#ifdef SUN
	qsort( et, count, sizeof(struct entrything), et_cmp );
#else
	qsort( et, count, sizeof(struct entrything), (void *) et_cmp );
#endif

	ep = chain;
	for ( i = 0; i < count; i++ ) {
		*ep = et[i].et_msg;
		ep = &(*ep)->lm_chain;

		ldap_value_free( et[i].et_vals );
	}
	*ep = last;
	free( (char *) et );

	return( 0 );
}

/* ARGSUSED */
int
ldap_sort_values(
    LDAP	*ld,
    char	**vals,
    int		(*cmp)()
)
{
	size_t	nel;

	for ( nel = 0; vals[nel] != NULL; nel++ )
		;	/* NULL */

	qsort( vals, nel, sizeof(char *), cmp );

	return( 0 );
}
