/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.8	*/

#include <stdio.h>
#include <pwd.h>
#include <string.h>
#include <sys/types.h>

#define NUMARGS		6
#define MAXARGS		25	
#define ENVIRON		"/standard/pref/.environ"
#define VARIABLES	"/standard/pref/.variables"
#define COLOR		"/standard/pref/.colorpref"
#define WPREF		"/standard/WASTEBASKET/.pref"

static char Interpreter[] = "fmli";	
static char vmsys[BUFSIZ];
static char home[BUFSIZ];
static char pidbuf[BUFSIZ];

main(argc, argv)
int argc;
char *argv[];
{
	char *Objlist[MAXARGS];
	char fmlibuf[BUFSIZ];
	char introbuf[BUFSIZ];
	char aliasbuf[BUFSIZ];
	char cmdbuf[BUFSIZ];
	register int i,j;
	extern pid_t getpid();
/*
	int isatty();
*/
	static void sanity_check();
	char *getenv();
	char *tmpenv;
	char *newbuf;
	char varbuf[BUFSIZ];
	char buf[BUFSIZ];
	FILE *fp;

	if ( (tmpenv = getenv("VMSYS")) == NULL ) {
		fprintf(stderr, "\r\nThe environment variable \"VMSYS\" must be set in\nyour environment before you can use FACE.\r\n\n");
		exit(1);
	}
	else
		strcpy(vmsys, tmpenv);

	if ( (tmpenv = getenv("OASYS")) == NULL ) {
		fprintf(stderr, "\r\nThe environment variable \"OASYS\" must be set in\nyour environment before you can use FACE.\r\n\n");
		exit(1);
	}

	sprintf(fmlibuf, "/usr/bin/%s", Interpreter);
	if (access(fmlibuf, 01)) {
		fprintf(stderr, "\r\nYou have not installed the \"AT&T FMLI\" package.\nPlease do so before attempting to use FACE.\r\n\n");
		exit(1);
	}

	if ( getenv("FACEPID") != NULL ) {
		fprintf(stderr, "\r\nYou already have FACE running.\r\n\n");
		exit(1);
	}
	sprintf(pidbuf, "FACEPID=%ld", getpid());
	putenv(pidbuf);

	sanity_check();

	sprintf(introbuf, "%s%s", vmsys, "/bin/initial");
	sprintf(aliasbuf, "%s%s", vmsys, "/pathalias");
	sprintf(cmdbuf, "%s%s", vmsys, "/bin/cmdfile");
	Objlist[0] = fmlibuf;
	Objlist[1] = "-i";
	Objlist[2] = introbuf; 
	Objlist[3] = "-a";
	Objlist[4] = aliasbuf;
	Objlist[5] = "-c";
	Objlist[6] = cmdbuf;
	if (argc == 1) {
		/*
		 * Use the Office Menu as the default if no arguments
		 */
		char objbuf[BUFSIZ];

		sprintf(objbuf, "%s%s", vmsys, "/OBJECTS/Menu.face");
		Objlist[NUMARGS + 1] = objbuf;
		Objlist[NUMARGS + 2] = NULL;
	}
	else {
		/*
		 * Arguments to FACE are Object paths
		 */
		for (i = 1; i < argc && (i < (MAXARGS - 3)); i++)
			Objlist[i + NUMARGS] = argv[i];
		Objlist[i + NUMARGS] = (char *) NULL;
	}
/* removed by miked, put back into .faceprofile
	if ( isatty( 0 ) )
		system("tput init; stty tab3");
*/

	sprintf(varbuf, "%s%s", home, "/pref/.variables");
	fp = fopen(varbuf, "r");
	while (fgets(buf, BUFSIZ, fp) != NULL) {
		if (buf[strlen(buf) - 1] == '\n')
			buf[strlen(buf) - 1]='\0';
		newbuf = (char *)malloc(strlen(buf) + 1);
		j = 0;
		for ( i = 0; buf[i]; i++ ) {
			if ( buf[i] != '"' )
				newbuf[j++] = buf[i];
		}
		newbuf[j] = '\0';
		putenv(newbuf);
	}

	putenv("VMFMLI=true");
	execvp(fmlibuf, Objlist);

	fprintf(stderr, "\r\nAn error has occurred while trying to use the \"AT&T FMLI\" package.\nThe file %s will not execute properly.\nThis situation must be corrected before you can proceed.\r\n\n",fmlibuf);
	exit(1);
}

char	user[20];

static
void
sanity_check()
{
	char	pref[BUFSIZ];
	char	environ[BUFSIZ];
	char	variables[BUFSIZ];
	char	color[BUFSIZ];
	char	tmp[BUFSIZ];
	char	bin[BUFSIZ];
	char	wastebasket[BUFSIZ];
	char	wpref[BUFSIZ];
	char	cmd[BUFSIZ];
	char	*getenv();
	uid_t	uid;
	struct	passwd *ppw;

	uid = geteuid();
	ppw = getpwuid(uid);
	strcpy(user, ppw->pw_name);
	strcpy(home, getenv("HOME"));
	if (access(home, 07))
		error(home);

	sprintf(pref, "%s/pref", home);
	sprintf(environ, "%s/.environ", pref);
	sprintf(variables, "%s/.variables", pref);
	sprintf(color, "%s/.colorpref", pref);
	sprintf(tmp, "%s/tmp", home);
	sprintf(bin, "%s/bin", home);
	sprintf(wastebasket, "%s/WASTEBASKET", home);
	sprintf(wpref, "%s/.pref", wastebasket);

	if (access(pref, 00)) 
		mkdir(pref, 0777);
	else if (access(pref, 07))
		error(pref);
		
	if (access(environ, 00)) {
		sprintf(cmd, "cp %s%s %s", vmsys, ENVIRON, environ);
		system(cmd);
	} else if (access(environ, 06))
		error(environ);

	if (access(variables, 00)) {
		sprintf(cmd, "cp %s%s %s", vmsys, VARIABLES, variables);
		system(cmd);
	} else if (access(variables, 06))
		error(variables);

	if (access(color, 00)) {
		sprintf(cmd, "cp %s%s %s", vmsys, COLOR, color);
		system(cmd);
	} else if (access(color, 06))
		error(color);

	if (access(tmp, 00))
		mkdir(tmp, 0777);
	else if (access(tmp, 07))
		error(tmp);

	if (access(bin, 00))
		mkdir(bin, 0777);
	else if (access(bin, 07))
		error(bin);

	if (access(wastebasket, 00))
		mkdir(wastebasket, 0777);

	if (access(wpref, 00)) {
		sprintf(cmd, "cp %s%s %s", vmsys, WPREF, wpref);
		system(cmd);
	} 
}

error(object)
char	*object;
{
	fprintf(stderr, "The permission of '%s' is not properly set for user '%s'.\n", object, user);
	exit(1);
}
