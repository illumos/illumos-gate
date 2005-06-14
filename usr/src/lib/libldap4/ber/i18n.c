/*
 *
 * Portions Copyright %G% Sun Microsystems, Inc. 
 * All Rights Reserved
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <nl_types.h>
/* #include <lthread.h> */
#include <pthread.h>
#include <thread.h>

nl_catd slapdcat = 0;
int     notdone = 1;
static pthread_mutex_t log_mutex;
pthread_mutex_t systime_mutex;

void i18n_catopen(char * name)
{
	if ( notdone ) {
		notdone = 0;
		slapdcat = catopen(name, NL_CAT_LOCALE);
	} /* end if */
}

