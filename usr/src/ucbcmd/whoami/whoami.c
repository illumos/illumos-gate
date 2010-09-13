/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <locale.h>
#include <stdlib.h>

#define	MSG	"whoami: no login associated with uid %u.\n"

/*
 * whoami
 */

int
main(int argc, char *argv[])
/*ARGSUSED*/
{
	struct passwd *pp;
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
	(void) printf("%s\n", pp->pw_name);
	return (0);
}
