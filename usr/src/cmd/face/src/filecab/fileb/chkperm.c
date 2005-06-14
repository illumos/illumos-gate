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
/*
 * Copyright 2000 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * 			chkperm.c
 *
 * chkperm -t cap-name [-u username]
 *
 *	Test the user's permission or preference for cap-name.
 *	cap-name is a capability that chkperm understands
 *	the current list is:
 *
 *		unix - can the user escape to the shell with the unix command
 *		admin - does the user have the System Admin menu entry
 *		invoke - does the user invoke FACE at login
 *		exit - does the user get a confirmation when exiting FACE
 *		progs - does the user have personal programs installed
 *			NOTE: this is used by user vmsys to determine
 *			if any global applications are installed
 *
 *	if the user has permission for the feature or the preference
 *	is selected, chkperm does a return(0) else it does return(1)
 *
 *	if there is no entry for the user in the permission file,
 *	an entry is created with default values and the default
 *	value for the selected cap-name is returned.
 *	The default values are:
 *
 *		unix - yes
 *		admin - no
 *		invoke - no
 *		exit - yes
 *		progs - no
 *
 *	if the -u option is specified, its argument overides the username
 *	of the user who invoked the command.
 *
 *
 * chkperm -e cap-name [-u username]
 *
 *  	echo the value of the cap-name for the user as
 *	a string on stdout. yes and no are possible results.
 *
 *	if there is no entry for the user in the permission file,
 *	an entry is created with default values and the default
 *	value for the selected cap-name is returned.
 *
 *	always does a return (0) unless an error occurs.
 *
 *
 * chkperm -y cap-name [-u username]
 *
 *  	Set the cap-name value for user to yes
 *
 *	if there is no entry for the user, an entry is created with
 *	the above default values for the other cap-names
 *
 *	always does a return (0) unless an error occurs.
 *
 *
 * chkperm -n cap-name [-u username]
 *
 *  	Set the cap-name value for user to no
 *
 *	if there is no entry for the user, an entry is created with
 *	the above default values for the other cap-names
 *
 *	always does a return (0) unless an error occurs.
 *
 *
 * chkperm -v [-u username]
 *
 *  	Verify if the user is defined as a FACE user.
 *
 *	If the user is a FACE user, chkperm does a return (0)
 *	otherwise it does a return (255)
 *
 *
 * chkperm -d [-u username]
 *
 *  	Delete the user as a FACE user.  It only invalidates the
 *	the user's entry in the permissions file.  It does not
 *	remove any FACE specific files from the user's environment.
 *
 *	always does a return (0) unless an error occurs.
 *
 *
 * chkperm -l
 *
 *  	Return to standard output a list of all defined face users.
 *
 *	It does a return (255) if no users exist yet otherwise it does
 *	a return (0) unless an error occurs.
 *
 *
 * general comments:
 *
 *	the permissions are stored in $VMSYS/lib/.facerc
 *
 *	if chkperm is invoked and the file does not exist, it will
 *	be created.
 *
 *	this file is owned by vmsys with permissions 600
 *
 *	chkperm runs setuid vmsys so it can read and write this file
 *
 *	if new cap-names are added to chkperm and the program is
 *	then run on an old datafile, the values returned for the
 *	new cap-names will always be no/FAIL until those caps are
 *	given values with -y or -n.
 *
 *
 * errorrs ( sic ):
 *
 *	if file io errors occur, chkperm -t will return the default
 *	value for cap-name.
 *
 *	all variants of chkperm will put error strings on stderr
 *
 *	if any syntax errors occur,
 *	a return (1) is done and an
 *	error is put on stderr.
 *
 */
#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <pwd.h>
#include <unistd.h>
#include <fcntl.h>
#include "wish.h"

#ifdef DEBUG
#define	BASE		"HOME"
#define	FACERC		"/test/perms/facerc"
#else
#define	BASE		"VMSYS"
#define	FACERC		"/lib/.facerc"
#endif /* DEBUG */

char fbase[] = BASE;
char frest[] = FACERC;

struct caps_type {
	char *name;
	int dflt;
};

#define	YES		'0'
#define	NO		'1'

#define	g_val(A)	(((A) == FAIL) ? NO : YES)
#define	p_val(A)	(((A) == YES) ? SUCCESS : FAIL)
#define	e_val(A)	(((A) == YES) ? "yes" : "no")

#define	CAPLENGTH 	7
#define	CAPS		5
#define	MAXCAPS		32
/*
 *  Dont change MAXCAPS.  If you do, this program will not be
 *  compatible with old versions.
 *
 *  Changing CAPS is OK as long as it is < MAXCAPS
 */

static struct caps_type caps[CAPS] = {
	{ "unix",	SUCCESS },
	{ "admin",	FAIL },
	{ "invoke",	FAIL },
	{ "exit",	SUCCESS },
	{ "progs",	FAIL }
};

struct cap_file_type {
	char name[L_cuserid];
	char cap_val[MAXCAPS];
};

char uname_in[L_cuserid];
int uflg, eflg, vflg, dflg;

main(argc, argv)
int argc;
char **argv;
{
	register optchar;
	extern char *optarg;
	char caparg[CAPLENGTH];
	int lflg = 0, tflg = 0, yflg = 0, nflg = 0, opterr = 0;

	int list_user();
	int del_user();
	int get_value();
	int set_value();
	int cap_index();
	extern uid_t getuid();
	extern char *getenv();

	uflg = 0;
	eflg = 0;
	vflg = 0;
	dflg = 0;

	while ((optchar = getopt(argc, argv, "?lvdt:e:y:n:u:")) != EOF)
		switch (optchar)
		{
		case 'l':
		    if (lflg || dflg || vflg || tflg || eflg || yflg || nflg) {
				opterr++;
				break;
		    }
		    lflg++;
		    continue;
		case 'd':
		    if (lflg || dflg || vflg || tflg || eflg || yflg || nflg) {
				opterr++;
				break;
		    }
		    dflg++;
		    continue;
		case 'v':
		    if (lflg || dflg || vflg || tflg || eflg || yflg || nflg) {
				opterr++;
				break;
		    }
		    vflg++;
		    continue;
		case 't':
		    if (lflg || dflg || vflg || tflg || eflg || yflg || nflg) {
				opterr++;
				break;
		    }
		    tflg++;
		    strlcpy(caparg, optarg, sizeof (caparg));
		    continue;
		case 'e':
		    if (lflg || dflg || vflg || tflg || eflg || yflg || nflg) {
				opterr++;
				break;
		    }
		    eflg++;
		    strlcpy(caparg, optarg, sizeof (caparg));
		    continue;
		case 'y':
		    if (lflg || dflg || vflg || tflg || eflg || yflg || nflg) {
				opterr++;
				break;
		    }
		    yflg++;
		    strlcpy(caparg, optarg, sizeof (caparg));
		    continue;
		case 'n':
		    if (lflg || dflg || vflg || tflg || eflg || yflg || nflg) {
				opterr++;
				break;
		    }
		    nflg++;
		    strlcpy(caparg, optarg, sizeof (caparg));
		    continue;
		case 'u':
			if (*optarg == NULL) {
				opterr++;
				break;
			}
			sprintf(uname_in, "%.*s", (L_cuserid-1), optarg);
			uflg++;
			continue;
		case '?':
			opterr++;
			break;
		}

	if (!(lflg || dflg || vflg || tflg || eflg || yflg || nflg)) opterr++;

	if (opterr)
	{
		fprintf(stderr,
	"Usage: chkperm -l|-d|-v|-t cap|-e cap|-y cap|-n cap [-u user-name]\n");
		exit(FAIL);
	}

	if ((dflg || yflg || nflg || uflg || lflg) && getuid() != 0) {
		if (dflg)
			fprintf(stderr,
			"You must be super-user to undefine a FACE user.\n");
		else if (uflg)
			fprintf(stderr,
		      "You must be super-user to act for another FACE user.\n");
		else if (lflg)
			fprintf(stderr,
			"You must be super-user to list all FACE users.\n");
		else
			fprintf(stderr,
		"You must be super-user to set FACE permissions for a user.\n");
		exit(FAIL);
	}

	if (lflg)
		exit(list_user());

	if (dflg)
		exit(del_user());

	if (vflg)
		exit(get_value(0));

	if (tflg || eflg)
		exit(get_value(cap_index(caparg)));

	if (yflg)
		exit(set_value(cap_index(caparg), SUCCESS));

	if (nflg)
	  exit(set_value(cap_index(caparg), FAIL));

	fprintf (stderr, 
	"Usage: chkperm -l|-d|-v|-t cap|-e cap|-y cap|-n cap [-u user-name]\n"
		);
}


int
cap_index(capname)
char *capname;
{
	register index;

	for (index = 0; index < CAPS; index++)
		if (strcmp(capname, caps[index].name) == 0)
			return (index);

	fprintf(stderr, "Invalid cap-name: %s\n", capname);
	return (FAIL);
}


int
get_value(cap_index)
int cap_index;
{
	char *uname;
	FILE *fp;
	struct cap_file_type *iobuf;
	int found, index;

	char *get_uname();
	FILE *open_file();

	if (cap_index == FAIL)
		return (FAIL);

	if ((uname = get_uname()) == NULL)
		return (FAIL);

	if ((fp = open_file()) == NULL)
		return (FAIL);

	iobuf = (struct cap_file_type *) malloc(sizeof (struct cap_file_type));

	found = 0;

	while (fread((char *)iobuf, sizeof (*iobuf), 1, fp) != 0) {
		if (strcmp((*iobuf).name, uname) == 0) {
			found++;
			break;
		}
	}

	if (vflg) {
		if (found)
			return (SUCCESS);
		else
			return (FAIL);
	}


	if (!found) {
		(void) strcpy((*iobuf).name, uname);
		for (index = 0; index < CAPS; index++)
			(*iobuf).cap_val[index] = g_val(caps[index].dflt);
/*
		(void) fseek(fp, 0L, 2);

		if (fwrite((char *)iobuf, sizeof (*iobuf), 1, fp) != 1) {
			fprintf(stderr, "Error writing permissions file.\n");
			return (FAIL);
		}
*/
	}

	(void) fclose(fp);

	if (eflg) {
		printf("%s", e_val((*iobuf).cap_val[cap_index]));
		return (SUCCESS);
	}
	else
		return (p_val((*iobuf).cap_val[cap_index]));
}


int
set_value(cap_index, cap_value)
int cap_index, cap_value;
{
	char *uname;
	FILE *fp;
	struct cap_file_type *iobuf;
	int found, index;
	long foff;

	char *get_uname();
	FILE *open_file();

	if (cap_index == FAIL)
		return (FAIL);

	if ((uname = get_uname()) == NULL)
		return (FAIL);

	if ((fp = open_file()) == NULL)
		return (FAIL);

	iobuf = (struct cap_file_type *) malloc(sizeof (struct cap_file_type));

	foff = ftell(fp);
	found = 0;

	while (fread((char *)iobuf, sizeof (*iobuf), 1, fp) != 0) {
		if (strcmp((*iobuf).name, uname) == 0) {
			found++;
			break;
		}
		foff = ftell(fp);
	}

	if (!found) {
		(void) strcpy((*iobuf).name, uname);
		for (index = 0; index < CAPS; index++)
			(*iobuf).cap_val[index] = g_val(caps[index].dflt);
	}

	(*iobuf).cap_val[cap_index] = g_val(cap_value);

	if (found)
		(void) fseek(fp, foff, 0);
	else
		(void) fseek(fp, 0L, 2);

	if (fwrite((char *)iobuf, sizeof (*iobuf), 1, fp) != 1) {
		fprintf(stderr, "Error writing permissions file.\n");
		return (FAIL);
	}

	(void) fclose(fp);

	return (SUCCESS);
}

int
del_user()
{
	char *uname;
	FILE *fp;
	struct cap_file_type *iobuf;
	int found, index;
	long foff;

	char *get_uname();
	FILE *open_file();

	if ((uname = get_uname()) == NULL)
		return (FAIL);

	if ((fp = open_file()) == NULL)
		return (FAIL);

	iobuf = (struct cap_file_type *) malloc(sizeof (struct cap_file_type));

	foff = ftell(fp);
	found = 0;

	while (fread((char *)iobuf, sizeof (*iobuf), 1, fp) != 0) {
		if (strcmp((*iobuf).name, uname) == 0) {
			found++;
			break;
		}
		foff = ftell(fp);
	}

	if (found) {
		(void) strcpy((*iobuf).name, "");
		for (index = 0; index < CAPS; index++)
			(*iobuf).cap_val[index] = g_val(caps[index].dflt);

		(void) fseek(fp, foff, 0);

		if (fwrite((char *)iobuf, sizeof (*iobuf), 1, fp) != 1) {
			fprintf(stderr, "Error writing permissions file.\n");
			return (FAIL);
		}
	}

	(void) fclose(fp);

	return (SUCCESS);
}

int
list_user()
{
	FILE *fp;
	struct cap_file_type *iobuf;
	int found = 0;

	FILE *open_file();

	if ((fp = open_file()) == NULL)
		return (FAIL);

	iobuf = (struct cap_file_type *) malloc(sizeof (struct cap_file_type));

	while (fread((char *)iobuf, sizeof (*iobuf), 1, fp) != 0) {
		if ((*iobuf).name[0]) {
			(void) printf("%s\n", (*iobuf).name);
			found++;
		}
	}

	(void) fclose(fp);

	return (found?SUCCESS:FAIL);
}


char *
get_uname()
{
	char *user;
	struct passwd *pw;
	extern uid_t getuid();

	if (uflg)
		return (uname_in);
	/*
	 *	Get login name from uid.  getpwuid was used because
	 *	getlogin() fails when running layers.
	 */

	if ((pw = getpwuid(getuid())) == NULL) {
		fprintf(stderr, "Can't read user name on system.\n");
		return (NULL);
	}

	user = strdup(pw->pw_name);

	endpwent();

	return (user);
}


FILE *
open_file()
{
	char fpath[BUFSIZ];
	char *fpt;
	FILE *fp;
	int fd;
	char *getenv();

	if ((fpt = getenv(fbase)) == NULL) {
		fprintf(stderr, "$%s must be set in the environment.\n", fbase);
		return (NULL);
	}

	(void) snprintf(fpath, sizeof (fpath), "%s%s", fpt, frest);

	/*
	* for now, make sure we can only create non-world writable files
	* called ".facerc" (the O_EXCL|O_CREAT won't follow symlinks
	*/
	if (access(fpath, 00)) {
		fd = open(fpath, O_RDWR|O_CREAT|O_EXCL, 0644);
		if (fd < 0) {
			fprintf(stderr, "Error creating %s\n", fpath);
			return (NULL);
		}
		fp = fdopen(fd, "w+");
	} else {
		fd = open(fpath, O_RDWR);
		if (fd < 0) {
			fprintf(stderr, "Error accessing %s\n", fpath);
			return (NULL);
		}
		fp = fdopen(fd, "r+");
	}

	if (fp == NULL) {
		close(fd);
		fprintf(stderr, "Error accessing %s\n", fpath);
		return (NULL);
	}
	(void) lockf(fd, F_LOCK, 0L);

	return (fp);
}
