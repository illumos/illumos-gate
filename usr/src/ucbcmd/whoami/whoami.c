/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

/*
 * Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, Sun Microsystems, Inc.
 * All Rights Reserved.
 */

#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.1	*/


#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <locale.h>
#include <stdlib.h>

#define	MSG	"whoami: no login associated with uid %u.\n"

/*
 * whoami
 */
struct	passwd *getpwuid();

void
main()
{
	register struct passwd *pp;
	uid_t	euid;

	/* Set locale environment variables local definitions */
	(void) setlocale(LC_ALL, "");
#if	!defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"  /* Use this only if it wasn't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	euid = geteuid();
	pp = getpwuid(euid);
	if (pp == 0) {
		(void) printf(gettext(MSG), euid);
		exit(1);
	}
	printf("%s\n", pp->pw_name);
	exit(0);
	/*NOTREACHED*/
}
