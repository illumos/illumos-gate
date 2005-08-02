/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved. The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * groups
 */

#include <sys/param.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>

static void showgroups(char *);

int	groups[NGROUPS_UMAX];

int
main(int argc, char *argv[])
{
	int ngroups, i, j;
	char *sep = "";
	struct group *gr;
	struct passwd *pw;

	if (argc > 1) {
		for (i=1; i < argc ; i++)
        		showgroups(argv[i]);
		exit(0) ;
	}

	ngroups = getgroups(NGROUPS_UMAX, groups);
	if ((pw = getpwuid(getuid())) == NULL) {
		fprintf(stderr, "groups: could not find passwd entry\n");
		exit(1);
	}

	for (i = 0; i < ngroups; i++) {
		gr = getgrgid(groups[i]);
		if (gr == NULL) {
			printf("%s%d", sep, groups[i]);
			sep = " ";
			continue;
		}
		printf("%s%s", sep, gr->gr_name);
		sep = " ";
	}
	printf("\n");
	return (0);
}

void
showgroups(char *user)
{
	struct group *gr;
	struct passwd *pw;
	char **cp;
	char *sep = "";
	int pwgid_printed = 0 ;

	if ((pw = getpwnam(user)) == NULL) {
		fprintf(stderr, "groups: %s : No such user\n", user);
		return;
	}
	setgrent() ;
	printf("%s : ", user) ;
	while (gr = getgrent()) {
		if (pw->pw_gid == gr->gr_gid) {
			/* 
			 * To avoid duplicate group entries 
			 */
			if (pwgid_printed==0) {
			    printf("%s%s", sep, gr->gr_name);
			    sep = " ";
			    pwgid_printed = 1 ;
			}
			continue ;
		}	
		for (cp = gr->gr_mem; cp && *cp; cp++)
			if (strcmp(*cp, user) == 0) {
				printf("%s%s", sep, gr->gr_name);
				sep = " ";
				break;
			}
	}
	printf("\n");
	endgrent() ;
}
