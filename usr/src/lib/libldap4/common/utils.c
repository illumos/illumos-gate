/*
 *
 * Copyright %G% Sun Microsystems, Inc. All Rights Reserved
 *
 *
 * Comments:   
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>

void free_strarray( char **sap )
{
    int		i;

    if ( sap != NULL ) {
		for ( i = 0; sap[ i ] != NULL; ++i ) {
			free( sap[ i ] );
		}
		free( (char *)sap );
    }
}
