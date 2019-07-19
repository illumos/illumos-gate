/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 *	Copyright (c) 1983, 1984, 1986, 1986, 1987, 1988, 1989 AT&T
 *	  All Rights Reserved
 */

/*
 *  Vacation
 *  Copyright (c) 1983  Eric P. Allman
 *  Berkeley, California
 *
 *  Copyright (c) 1983 Regents of the University of California.
 *  All rights reserved.  The Berkeley software License Agreement
 *  specifies the terms and conditions for redistribution.
 */

#include <pwd.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <sysexits.h>
#include <string.h>
#include <ctype.h>
#include <sm/bitops.h>
#include "conf.h"

/*
 *  MAILCOMPAT -- Deliver mail to a user's mailbox with the "From's" stuffed.
 */

typedef int bool;

#define	FALSE	0
#define	TRUE	1

bool	Debug = FALSE;
char	*myname;		/* person who is to have their mail filtered */
char	*homedir;		/* home directory of said person */
char	*AliasList[MAXLINE];	/* list of aliases to allow */
char    *fromp;
char    *fromuser;
int	AliasCount = 0;

static char *newstr();

int	ask(char *);
int	sendmessage(char *);
void	AutoInstall(void);
void	usrerr(const char *, ...);

int
main(argc, argv)
	int argc;
	char **argv;
{
	register char *p;
	struct passwd *pw;
	extern char *getfrom();

	/* process arguments */
	while (--argc > 0 && (p = *++argv) != NULL && *p == '-')
	{
		switch (*++p)
		{
		    case 'd':	/* debug */
			Debug = TRUE;
			break;
		    default:
			usrerr("Unknown flag -%s", p);
			exit(EX_USAGE);
		}
	}

	/* verify recipient argument */
	if (argc != 1)
	{
		if (argc == 0)
			AutoInstall();
		else
			usrerr("Usage: mailcompat username (or) mailcompat -r");
		exit(EX_USAGE);
	}

	myname = p;
	/* find user's home directory */
	pw = getpwnam(myname);
	if (pw == NULL)
	{
		usrerr("user: %s look up failed, name services outage ?", myname);
		exit(EX_TEMPFAIL);
	}
	homedir = newstr(pw->pw_dir);

	/* read message from standard input (just from line) */
	fromuser = getfrom(&fromp);
	return (sendmessage(fromuser));
}

/*
**  sendmessage -- read message from standard input do the from stuffing
**             and forward to /bin/mail, Being sure to delete any
**             content-length headers (/bin/mail recalculates them).
**
**
**	Parameters:
**		none.
**
**
**	Side Effects:
**		Reads first line from standard input.
*/

#define	L_HEADER	"Content-Length:"
#define	LL_HEADER	15

int
sendmessage(from)
char *from;
{
	static char line[MAXLINE];
	static char command[MAXLINE];
	bool in_body = FALSE;
	FILE *mail_fp;
	static char user_name[L_cuserid];

	if (from == NULL)
		from = cuserid(user_name);

	snprintf(command, sizeof (command), "/bin/mail -f %s -d %s", from,
	    myname);
	mail_fp = popen(command, "w");

	/* read the  line */
	while (fgets(line, sizeof line, stdin) != NULL)
	{
		if (line[0] == (char)'\n')  /* end of mail headers */
			in_body = TRUE;
		if (in_body && (strncmp(line, "From ", 5) == 0))
			fprintf(mail_fp, ">");
		if (in_body || (strncasecmp(line, L_HEADER, LL_HEADER) != 0))
			fputs(line, mail_fp);
	}
	return (pclose(mail_fp));
}

char *
getfrom(shortp)
char **shortp;
{
	static char line[MAXLINE];
	register char *p, *start, *at, *bang;
	char saveat;

	/* read the from line */
	if (fgets(line, sizeof line, stdin) == NULL ||
	    strncmp(line, "From ", 5) != NULL)
	{
		usrerr("No initial From line");
		exit(EX_USAGE);
	}

	/* find the end of the sender address and terminate it */
	start = &line[5];
	p = strchr(start, ' ');
	if (p == NULL)
	{
		usrerr("Funny From line '%s'", line);
		exit(EX_USAGE);
	}
	*p = '\0';

	/*
	 * Strip all but the rightmost UUCP host
	 * to prevent loops due to forwarding.
	 * Start searching leftward from the leftmost '@'.
	 *	a!b!c!d yields a short name of c!d
	 *	a!b!c!d@e yields a short name of c!d@e
	 *	e@a!b!c yields the same short name
	 */
#ifdef VDEBUG
printf("start='%s'\n", start);
#endif /* VDEBUG */
	*shortp = start;			/* assume whole addr */
	if ((at = strchr(start, '@')) == NULL)	/* leftmost '@' */
		at = p;				/* if none, use end of addr */
	saveat = *at;
	*at = '\0';
	if ((bang = strrchr(start, '!')) != NULL) {	/* rightmost '!' */
		char *bang2;
		*bang = '\0';
		if ((bang2 = strrchr(start, '!')) != NULL) /* 2nd rightmost '!' */
			*shortp = bang2 + 1;		/* move past ! */
		*bang = '!';
	}
	*at = saveat;
#ifdef VDEBUG
printf("place='%s'\n", *shortp);
#endif /* VDEBUG */

	/* return the sender address */
	return newstr(start);
}

/*
**  USRERR -- print user error
**
**	Parameters:
**		f -- format.
**
**	Returns:
**		none.
**
**	Side Effects:
**		none.
*/

void
usrerr(const char *f, ...)
{
	va_list alist;

	va_start(alist, f);
	(void) fprintf(stderr, "mailcompat: ");
	(void) vfprintf(stderr, f, alist);
	(void) fprintf(stderr, "\n");
	va_end(alist);
}

/*
**  NEWSTR -- copy a string
**
**	Parameters:
**		s -- the string to copy.
**
**	Returns:
**		A copy of the string.
**
**	Side Effects:
**		none.
*/

char *
newstr(s)
	char *s;
{
	char *p;
	size_t psize = strlen(s) + 1;

	p = malloc(psize);
	if (p == NULL)
	{
		usrerr("newstr: cannot alloc memory");
		exit(EX_OSERR);
	}
	strlcpy(p, s, psize);
	return (p);
}

/*
 * When invoked with no arguments, we fall into an automatic installation
 * mode, stepping the user through a default installation.
 */
void
AutoInstall()
{
	char forward[MAXLINE];
	char line[MAXLINE];
	static char user_name[L_cuserid];
	FILE *f;

	myname = cuserid(user_name);
	homedir = getenv("HOME");
	if (homedir == NULL) {
		usrerr("Home directory unknown");
		exit(EX_CONFIG);
	}

	printf("This program can be used to store your mail in a format\n");
	printf("that you can read with SunOS 4.X based mail readers\n");
	(void) strlcpy(forward, homedir, sizeof (forward));
	(void) strlcat(forward, "/.forward", sizeof (forward));
	f = fopen(forward, "r");
	if (f) {
		printf("You have a .forward file in your home directory");
		printf("  containing:\n");
		while (fgets(line, MAXLINE, f))
			printf("    %s", line);
		fclose(f);
		if (!ask("Would you like to remove it and disable the mailcompat feature"))
			exit(0);
		if (unlink(forward))
			perror("Error removing .forward file:");
		else
			printf("Back to normal reception of mail.\n");
		exit(0);
	}

	printf("To enable the mailcompat feature a \".forward\" ");
	printf("file is created.\n");
	if (!ask("Would you like to enable the mailcompat feature")) {
		printf("OK, mailcompat feature NOT enabled.\n");
		exit(0);
	}
	f = fopen(forward, "w");
	if (f == NULL) {
		perror("Error opening .forward file");
		exit(EX_USAGE);
	}
	fprintf(f, "\"|/usr/bin/mailcompat %s\"\n", myname);
	fclose(f);
	printf("Mailcompat feature ENABLED.");
	printf("Run mailcompat with no arguments to remove it\n");
}


/*
 * Ask the user a question until we get a reasonable answer
 */
int
ask(prompt)
	char *prompt;
{
	char line[MAXLINE];

	for (;;) {
		printf("%s? ", prompt);
		fflush(stdout);
		fgets(line, sizeof (line), stdin);
		if (line[0] == 'y' || line[0] == 'Y')
			return (TRUE);
		if (line[0] == 'n' || line[0] == 'N')
			return (FALSE);
		printf("Please reply \"yes\" or \"no\" (\'y\' or \'n\')\n");
	}
	/* NOTREACHED */
}
