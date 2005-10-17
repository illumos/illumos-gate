/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* ldapmodrdn.c - generic program to modify an entry's RDN using LDAP */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <locale.h>
#include <ctype.h>
#include <lber.h>
#include <ldap.h>
#include <locale.h>
#include "ldaptool.h"

static int	contoper, remove_oldrdn;
static LDAP	*ld;

static int domodrdn( LDAP *ld, char *dn, char *rdn, char *newsuperior, 
			int remove_oldrdn); 
static void options_callback( int option, char *optarg );

static void usage( void )
{
	fprintf(stderr, gettext("usage: %s [options] [dn newrdn [newsuperior]]\n"), ldaptool_progname);
	fprintf( stderr, gettext("options:\n"));
	ldaptool_common_usage( 0 );
	fprintf( stderr, gettext("    -c\t\tcontinuous mode\n") );
	fprintf( stderr, gettext("    -r\t\tremove old RDN from the entries\n"));
	fprintf( stderr, gettext("    -f file\tread changes from `file'\n") );
	exit(LDAP_PARAM_ERROR );
}

int 
main(int argc, char **argv )
{
	char *myname, *entrydn, *rdn, buf[ 4096 ];
	int rc, havedn, deref, optind;
	char * L_newParent = NULL;
	int haverdn = 0;

	int L_protoVersion = LDAP_VERSION3;

	char *locale = setlocale(LC_ALL, "");
	textdomain(TEXT_DOMAIN);
	ldaplogconfigf(NULL); 


	contoper =  remove_oldrdn = 0;

	if ((myname = strrchr(argv[0], '/')) == NULL)
		myname = argv[0];
	else
		++myname;

	optind = ldaptool_process_args( argc, argv, "cr", 0, options_callback);
	
	if ( optind == -1 ) {
		usage();
	}

	if ( ldaptool_fp == NULL ) {
	ldaptool_fp = stdin;
	}

	havedn = 0;
	if (argc - optind == 3) 		/* accept as arguments: dn rdn newsuperior */
	{
		if (( L_newParent = strdup( argv[argc - 1] )) == NULL ) 
		{
			perror( "strdup" );
			exit( LDAP_NO_MEMORY );
		}

		if (( rdn = strdup( argv[argc - 2] )) == NULL ) 
		{
			perror( "strdup" );
			exit( LDAP_NO_MEMORY );
		}

		if (( entrydn = strdup( argv[argc - 3] )) == NULL ) 
		{
			perror( "strdup" );
			exit( LDAP_NO_MEMORY );
		}
		++havedn;
	} 
	else if (argc - optind == 2) 		/* accept as arguments: dn rdn */
	{
		if (( rdn = strdup( argv[argc - 1] )) == NULL ) 
		{
			perror( "strdup" );
			exit( LDAP_NO_MEMORY );
		}

		if (( entrydn = strdup( argv[argc - 2] )) == NULL ) 
		{
			perror( "strdup" );
			exit( 1 );
		}
		++havedn;
	} 
	else if ( argc - optind != 0 ) 
	{
		fprintf( stderr, gettext("%s: invalid number of arguments, only two or three allowed\n"), myname);
		usage();
		exit( 1 );
	}

	ld = ldaptool_ldap_init (0);

	if ( !ldaptool_not ) {
		deref = LDAP_DEREF_NEVER;	/* this seems prudent */
		ldap_set_option( ld, LDAP_OPT_DEREF, &deref );
	}

	ldaptool_bind( ld );

	rc = 0;
	if (havedn)
	{
		rc = domodrdn(ld, entrydn, rdn, L_newParent, remove_oldrdn);
	}
	else while (	(rc == 0 || contoper) && 
					(fgets(buf, sizeof(buf), ldaptool_fp) != NULL) )

	{
		/* 
		 * The format of the file is one of the following:
		 * 	dn
		 * 	rdn
		 * 	newsuperior
		 * 	<blank lines...>
		 * OR
		 * 	dn
		 * 	rdn
		 * 	<blank lines...>
		 * both types of sequences can be found in the file
		 */
		
		if ( (strlen(buf) == 1) && (ldaptool_fp == stdin) )
			break;

		buf[ strlen( buf ) - 1 ] = '\0';	/* remove nl */
		if ( *buf != '\0' ) 		/* blank lines optional, skip */
		{
			if ( haverdn )		/* first type of sequence */
			{
				if (( L_newParent = strdup( buf )) == NULL ) 
				{
					perror( "strdup" );
					exit( LDAP_NO_MEMORY );
				}
				if ( L_newParent && (L_protoVersion == LDAP_VERSION) )
				{
					printf( gettext("LDAP Server is V2: <newsuperior> argument is ignored...\n") );
					L_newParent = NULL;
				}
				rc = domodrdn(ld, entrydn, rdn, L_newParent, remove_oldrdn);
				haverdn = 0;
			}
			else if ( havedn ) 		/* have DN, get RDN */
			{
				if (( rdn = strdup( buf )) == NULL ) 
				{
					perror( "strdup" );
					exit( LDAP_NO_MEMORY );
				}
				havedn = 0;
				++haverdn;
			}
			else if ( !havedn ) 		/* don't have DN yet */
			{
				if (( entrydn = strdup( buf )) == NULL)
				{
					perror( "strdup" );
					exit( LDAP_NO_MEMORY );
				}
				++havedn;
			}
		}
		else
		{
			printf(gettext("kex: new line %d\n"), rc);
			if ( haverdn )		/* second type of sequence */
			{
				rc = domodrdn(ld, entrydn, rdn, NULL, remove_oldrdn);
				haverdn = 0;
			}
		}
	}
	if ( (rc == 0 || contoper) && haverdn )		/* second type of sequence */
	{
		rc = domodrdn(ld, entrydn, rdn, NULL, remove_oldrdn);
		haverdn = 0;
	}

	ldaptool_cleanup( ld );

	exit( rc );
}

static void
options_callback( int option, char *optarg )
{
	switch( option ) {
		case 'c':	/* continuous operation mode */
			++contoper;
			break;
		case 'r':	/* remove old RDN */
			++remove_oldrdn;
			break;
		default:
		usage();
	}
}

static int
domodrdn( LDAP *ld, char *dn, char *rdn, char *newsuperior, int remove_oldrdn )
{
	int	rc = LDAP_SUCCESS;

	if ( ldaptool_verbose )
		printf( gettext("new RDN: %1$s (%2$skeep existing values)\n"),
						rdn, remove_oldrdn ? "do not " : "" );
 
	printf( gettext("%1$srenaming entry %2$s\n"), 
			ldaptool_not ? "!" : "", dn );

	if ( !ldaptool_not ) 
	{
		rc = ldap_rename_s( ld, dn, rdn, newsuperior, remove_oldrdn, NULL, NULL );
		if ( rc != LDAP_SUCCESS )
			fprintf(stderr, gettext("ldap_rename_s: %s\n"), ldap_err2string(rc));
		else if ( ldaptool_verbose )
			printf( gettext("rename completed\n") );
	}

	putchar('\n');

	return( rc );
}
