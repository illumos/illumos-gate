/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 *
 *	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T
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

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <sysexits.h>
#include <pwd.h>
#include <ndbm.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <strings.h>
#include <errno.h>

/*
 *  VACATION -- return a message to the sender when on vacation.
 *
 *	This program could be invoked as a message receiver
 *	when someone is on vacation.  It returns a message
 *	specified by the user to whoever sent the mail, taking
 *	care not to return a message too often to prevent
 *	"I am on vacation" loops.
 *
 *	For best operation, this program should run setuid to
 *	root or uucp or someone else that sendmail will believe
 *	a -f flag from.  Otherwise, the user must be careful
 *	to include a header on their .vacation.msg file.
 *
 *	Positional Parameters:
 *		the user to collect the vacation message from.
 *
 *	Flag Parameters:
 *		-I	initialize the database.
 *		-d	turn on debugging.
 *		-tT	set the timeout to T.  messages arriving more
 *			often than T will be ignored to avoid loops.
 *
 *	Side Effects:
 *		A message is sent back to the sender.
 *
 *	Author:
 *		Eric Allman
 *		UCB/INGRES
 */

#define	MAXLINE	256	/* max size of a line */

#define	ONEWEEK	(60L*60L*24L*7L)
#define	MsgFile "/.vacation.msg"
#define	FilterFile "/.vacation.filter"
#define	DbFileBase "/.vacation"
#define	_PATH_TMP	"/tmp/vacation.XXXXXX"

typedef int bool;

#define	FALSE	0
#define	TRUE	1

static time_t	Timeout = ONEWEEK;	/* timeout between notices per user */
static DBM	*db;
static bool	Debug = FALSE;
static bool	ListMode = FALSE;
static bool	AnswerAll = FALSE;	/* default: answer if in To:/Cc: only */
static char	*Subject = NULL;	/* subject in message header */
static char	*EncodedSubject = NULL;	/* subject in message header */
static char	Charset[MAXLINE];	/* for use in reply message */
static char	*AliasList[MAXLINE];	/* list of aliases to allow */
static int	AliasCount = 0;
static char	*myname;		/* name of person "on vacation" */
static char	*homedir;		/* home directory of said person */

extern time_t	convtime(char *, char);
extern bool	decode_rfc2047(char *, char *, char *);

static bool	ask(char *);
static bool	junkmail(char *);
static bool	filter_ok(char *, char *);
static bool	knows(char *);
static bool	sameword(char *, char *);
static char	*getfrom(char **);
static char	*newstr(char *);
static void	AutoInstall();
static void	initialize(char *);
static void	sendmessage(char *, char *, char *);
static void	setknows(char *);
static void	dumplist();

void	usrerr(const char *, ...);

int
main(argc, argv)
	int argc;
	char **argv;
{
	char *from;
	char *p, *at, *c;
	struct passwd *pw;
	char *shortfrom;
	char buf[MAXLINE];
	char *message_file = MsgFile;
	char *db_file_base = DbFileBase;
	char *filter_file = FilterFile;
	char *sender;
	bool sender_oob = FALSE;
	bool initialize_only = FALSE;

	/* process arguments */
	while (--argc > 0 && (p = *++argv) != NULL && *p == '-')
	{
		switch (*++p)
		{
		    case 'a':	/* add this to list of acceptable aliases */
			AliasList[AliasCount++] = argv[1];
			if (argc > 0) {
				argc--; argv++;
			}
			break;

		    case 'd':	/* debug */
			Debug = TRUE;
			break;

		    case 'e':	/* alternate filter file */
			filter_file = argv[1];
			if (argc > 0) {
				argc--; argv++;
			}
			break;

		    case 'f':	/* alternate database file name base */
			db_file_base = argv[1];
			if (argc > 0) {
				argc--; argv++;
			}
			break;

		    case 'I':	/* initialize */
			initialize_only = TRUE;
			break;

		    case 'j':	/* answer all mail, even if not in To/Cc */
			AnswerAll = TRUE;
			break;

		    case 'l':	/* list all respondees */
			ListMode = TRUE;
			break;

		    case 'm':	/* alternate message file */
			message_file = argv[1];
			if (argc > 0) {
				argc--; argv++;
			}
			break;

		    case 's':	/* sender: use this instead of getfrom() */
			sender = argv[1];
			sender_oob = TRUE;
			if (argc > 0) {
				argc--; argv++;
			}
			break;

		    case 't':	/* set timeout */
			Timeout = convtime(++p, 'w');
			break;

		    default:
			usrerr("Unknown flag -%s", p);
			exit(EX_USAGE);
		}
	}

	if (initialize_only)
	{
		initialize(db_file_base);
		exit(EX_OK);
	}

	/* verify recipient argument */
	if (argc == 0 && !ListMode)
		AutoInstall();

	if (argc != 1 && !ListMode)
	{
		usrerr("Usage:\tvacation username\n\tvacation -I\n"
		    "\tvacation -l");
		exit(EX_USAGE);
	}

	myname = p;
	Charset[0] = '\0';

	/* find user's home directory */
	if (ListMode)
		pw = getpwuid(getuid());
	else
		pw = getpwnam(myname);
	if (pw == NULL)
	{
		usrerr("user %s look up failed, name services outage ?",
		    myname);
		exit(EX_TEMPFAIL);
	}
	homedir = newstr(pw->pw_dir);

	(void) snprintf(buf, sizeof (buf), "%s%s%s", homedir,
			(db_file_base[0] == '/') ? "" : "/", db_file_base);
	if (!(db = dbm_open(buf, O_RDWR, 0))) {
		usrerr("%s: %s\n", buf, strerror(errno));
		exit(EX_DATAERR);
	}

	if (ListMode) {
		dumplist();
		exit(EX_OK);
	}

	if (sender_oob)
	{
		at = strchr(sender, '@');
		if (at != NULL)
			for (c = at + 1; *c; c++)
				*c = (char)tolower((char)*c);
		from = sender;
		shortfrom = sender;
	}
	else
		/* read message from standard input (just from line) */
		from = getfrom(&shortfrom);

	/* check if junk mail or this person is already informed */
	if (!junkmail(shortfrom) && filter_ok(shortfrom, filter_file) &&
	    !knows(shortfrom))
	{
		/* mark this person as knowing */
		setknows(shortfrom);

		/* send the message back */
		(void) strlcpy(buf, homedir, sizeof (buf));
		if (message_file[0] != '/')
		    (void) strlcat(buf, "/", sizeof (buf));
		(void) strlcat(buf, message_file, sizeof (buf));
		if (Debug)
			printf("Sending %s to %s\n", buf, from);
		else
		{
			sendmessage(buf, from, myname);
			/*NOTREACHED*/
		}
	}
	while (fgets(buf, MAXLINE, stdin) != NULL)
		continue; /* drain input */
	return (EX_OK);
}

struct entry {
	time_t	when;
	long	when_size;
	char	*who;
	long	who_size;
	struct	entry *next;
	struct	entry *prev;
};

static void
dump_content(key_size, key_ptr, content_size, content_ptr)
	long key_size, content_size;
	char *key_ptr, *content_ptr;
{
	time_t then;

	if (content_size == sizeof (then)) {
		bcopy(content_ptr, (char *)&then, sizeof (then));
		(void) printf("%-53.40*s: %s", (int)key_size, key_ptr,
		    ctime(&then));
	} else {
		(void) fprintf(stderr, "content size error: %d\n",
		    (int)content_size);
	}
}

static void
dump_all_content(first)
	struct entry *first;
{
	struct entry *which;

	for (which = first; which != NULL; which = which->next) {
		dump_content(which->who_size, which->who, which->when_size,
		    (char *)&(which->when));
	}
}

static void
dumplist()
{
	datum content, key;
	struct entry *first = NULL, *last = NULL, *new_entry, *curr;

	for (key = dbm_firstkey(db); key.dptr != NULL; key = dbm_nextkey(db)) {
		content = dbm_fetch(db, key);
		new_entry = (struct entry *)malloc(sizeof (struct entry));
		if (new_entry == NULL)
			perror("out of memory");
		new_entry->next = NULL;
		new_entry->who = (char *)malloc(key.dsize);
		if (new_entry->who == NULL)
			perror("out of memory");
		new_entry->who_size = key.dsize;
		(void) strlcpy(new_entry->who, key.dptr, key.dsize);
		bcopy(content.dptr, (char *)&(new_entry->when),
		    sizeof (new_entry->when));
		new_entry->when_size = content.dsize;
		if (first == NULL) { /* => so is last */
			new_entry->prev = NULL;
			new_entry->next = NULL;
			first = new_entry;
			last = new_entry;
		} else {
			for (curr = first; curr != NULL &&
			    new_entry->when > curr->when; curr = curr->next)
				;
			if (curr == NULL) {
				last->next = new_entry;
				new_entry->prev = last;
				new_entry->next = NULL;
				last = new_entry;
			} else {
				new_entry->next = curr;
				new_entry->prev = curr->prev;
				if (curr->prev == NULL)
					first = new_entry;
				else
					curr->prev->next = new_entry;
				curr->prev = new_entry;
			}
		}
	}
	dump_all_content(first);
	dbm_close(db);
}

/*
 *  GETFROM -- read message from standard input and return sender
 *
 *	Parameters:
 *		none.
 *
 *	Returns:
 *		pointer to the sender address.
 *
 *	Side Effects:
 *		Reads first line from standard input.
 */

static char *
getfrom(shortp)
char **shortp;
{
	static char line[MAXLINE];
	char *p, *start, *at, *bang, *c;
	char saveat;

	/* read the from line */
	if (fgets(line, sizeof (line), stdin) == NULL ||
	    strncmp(line, "From ", 5) != NULL)
	{
		usrerr("No initial From line");
		exit(EX_PROTOCOL);
	}

	/* find the end of the sender address and terminate it */
	start = &line[5];
	p = strchr(start, ' ');
	if (p == NULL)
	{
		usrerr("Funny From line '%s'", line);
		exit(EX_PROTOCOL);
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
		/* 2nd rightmost '!' */
		if ((bang2 = strrchr(start, '!')) != NULL)
			*shortp = bang2 + 1;		/* move past ! */
		*bang = '!';
	}
	*at = saveat;
#ifdef VDEBUG
printf("place='%s'\n", *shortp);
#endif /* VDEBUG */
	for (c = at + 1; *c; c++)
		*c = (char)tolower((char)*c);

	/* return the sender address */
	return (start);
}

/*
 *  JUNKMAIL -- read the header and tell us if this is junk/bulk mail.
 *
 *	Parameters:
 *		from -- the Return-Path of the sender.  We assume that
 *			anything from "*-REQUEST@*" is bulk mail.
 *
 *	Returns:
 *		TRUE -- if this is junk or bulk mail (that is, if the
 *			sender shouldn't receive a response).
 *		FALSE -- if the sender deserves a response.
 *
 *	Side Effects:
 *		May read the header from standard input.  When this
 *		returns the position on stdin is undefined.
 */

static bool
junkmail(from)
	char *from;
{
	register char *p;
	char buf[MAXLINE+1];
	bool inside, onlist;

	/* test for inhuman sender */
	p = strrchr(from, '@');
	if (p != NULL)
	{
		*p = '\0';
		if (sameword(&p[-8],  "-REQUEST") ||
		    sameword(&p[-10], "Postmaster") ||
		    sameword(&p[-13], "MAILER-DAEMON"))
		{
			*p = '@';
			return (TRUE);
		}
		*p = '@';
	}

#define	Delims " \n\t:,:;()<>@!"

	/* read the header looking for "interesting" lines */
	inside = FALSE;
	onlist = FALSE;
	while (fgets(buf, MAXLINE, stdin) != NULL && buf[0] != '\n')
	{
		if (buf[0] != ' ' && buf[0] != '\t' && strchr(buf, ':') == NULL)
			return (FALSE);			/* no header found */

		p = strtok(buf, Delims);
		if (p == NULL)
			continue;

		if (sameword(p, "To") || sameword(p, "Cc"))
		{
			inside = TRUE;
			p = strtok((char *)NULL, Delims);
			if (p == NULL)
				continue;

		} else				/* continuation line? */
		    if (inside)
			inside =  (buf[0] == ' ' || buf[0] == '\t');

		if (inside) {
		    int i;

		    do {
			if (sameword(p, myname))
				onlist = TRUE;		/* I am on the list */

			for (i = 0; i < AliasCount; i++)
			    if (sameword(p, AliasList[i]))
				onlist = TRUE;		/* alias on list */

		    } while (p = strtok((char *)NULL, Delims));
		    continue;
		}

		if (sameword(p, "Precedence"))
		{
			/* find the value of this field */
			p = strtok((char *)NULL, Delims);
			if (p == NULL)
				continue;

			/* see if it is "junk" or "bulk" */
			p[4] = '\0';
			if (sameword(p, "junk") || sameword(p, "bulk"))
				return (TRUE);
		}

		if (sameword(p, "Subject"))
		{
			char *decoded_subject;

			Subject = newstr(buf+9);
			if (p = strrchr(Subject, '\n'))
				*p = '\0';
			EncodedSubject = newstr(Subject);
			decoded_subject = newstr(Subject);
			if (decode_rfc2047(Subject, decoded_subject, Charset))
				Subject = decoded_subject;
			else
				Charset[0] = '\0';
			if (Debug)
				printf("Subject=%s\n", Subject);
		}
	}
	if (AnswerAll)
		return (FALSE);
	else
		return (!onlist);
}

/*
 *  FILTER_OK -- see if the Return-Path is in the filter file.
 *		 Note that a non-existent filter file means everything
 *		 is OK, but an empty file means nothing is OK.
 *
 *	Parameters:
 *		from -- the Return-Path of the sender.
 *
 *	Returns:
 *		TRUE -- if this is in the filter file
 *			(sender should receive a response).
 *		FALSE -- if the sender does not deserve a response.
 */

static bool
filter_ok(from, filter_file)
	char *from;
	char *filter_file;
{
	char file[MAXLINE];
	char line[MAXLINE];
	char *match_start;
	size_t line_len, from_len;
	bool result = FALSE;
	bool negated = FALSE;
	FILE *f;

	from_len = strlen(from);
	(void) strlcpy(file, homedir, sizeof (file));
	if (filter_file[0] != '/')
	    (void) strlcat(file, "/", sizeof (file));
	(void) strlcat(file, filter_file, sizeof (file));
	f = fopen(file, "r");
	if (f == NULL) {
		/*
		 * If the file does not exist, then there is no filter to
		 * apply, so we simply return TRUE.
		 */
		if (Debug)
			(void) printf("%s does not exist, filter ok.\n",
			    file);
		return (TRUE);
	}
	while (fgets(line, MAXLINE, f)) {
		line_len = strlen(line);
		/* zero out trailing newline */
		if (line[line_len - 1] == '\n')
			line[--line_len] = '\0';
		/* skip blank lines */
		if (line_len == 0)
			continue;
		/* skip comment lines */
		if (line[0] == '#')
			continue;
		if (line[0] == '!') {
			negated = TRUE;
			match_start = &line[1];
			line_len--;
		} else {
			negated = FALSE;
			match_start = &line[0];
		}
		if (strchr(line, '@') != NULL) {
			/* @ => full address */
			if (strcasecmp(match_start, from) == 0) {
				result = TRUE;
				if (Debug)
					(void) printf("filter match on %s\n",
					    line);
				break;
			}
		} else {
			/* no @ => domain */
			if (from_len <= line_len)
				continue;
			/*
			 * Make sure the last part of from is the domain line
			 * and that the character immediately preceding is an
			 * '@' or a '.', otherwise we could get false positives
			 * from e.g. twinsun.com for sun.com .
			 */
			if (strncasecmp(&from[from_len - line_len],
			    match_start, line_len) == 0 &&
			    (from[from_len - line_len -1] == '@' ||
			    from[from_len - line_len -1] == '.')) {
				result = TRUE;
				if (Debug)
					(void) printf("filter match on %s\n",
					    line);
				break;
			}
		}
	}
	(void) fclose(f);
	if (Debug && !result)
		(void) printf("no filter match\n");
	return (!negated && result);
}

/*
 *  KNOWS -- predicate telling if user has already been informed.
 *
 *	Parameters:
 *		user -- the user who sent this message.
 *
 *	Returns:
 *		TRUE if 'user' has already been informed that the
 *			recipient is on vacation.
 *		FALSE otherwise.
 *
 *	Side Effects:
 *		none.
 */

static bool
knows(user)
	char *user;
{
	datum key, data;
	time_t now, then;

	(void) time(&now);
	key.dptr = user;
	key.dsize = strlen(user) + 1;
	data = dbm_fetch(db, key);
	if (data.dptr == NULL)
		return (FALSE);

	bcopy(data.dptr, (char *)&then, sizeof (then));
	if (then + Timeout < now)
		return (FALSE);
	if (Debug)
		printf("User %s already knows\n", user);
	return (TRUE);
}

/*
 *  SETKNOWS -- set that this user knows about the vacation.
 *
 *	Parameters:
 *		user -- the user who should be marked.
 *
 *	Returns:
 *		none.
 *
 *	Side Effects:
 *		The dbm file is updated as appropriate.
 */

static void
setknows(user)
	char *user;
{
	datum key, data;
	time_t now;

	key.dptr = user;
	key.dsize = strlen(user) + 1;
	(void) time(&now);
	data.dptr = (char *)&now;
	data.dsize = sizeof (now);
	dbm_store(db, key, data, DBM_REPLACE);
}

static bool
any8bitchars(line)
	char *line;
{
	char *c;

	for (c = line; *c; c++)
		if (*c & 0x80)
			return (TRUE);
	return (FALSE);
}

/*
 *  SENDMESSAGE -- send a message to a particular user.
 *
 *	Parameters:
 *		msgf -- filename containing the message.
 *		user -- user who should receive it.
 *
 *	Returns:
 *		none.
 *
 *	Side Effects:
 *		sends mail to 'user' using /usr/lib/sendmail.
 */

static void
sendmessage(msgf, user, myname)
	char *msgf;
	char *user;
	char *myname;
{
	FILE *f, *fpipe, *tmpf;
	char line[MAXLINE];
	char *p, *tmpf_name;
	int i, pipefd[2], tmpfd;
	bool seen8bitchars = FALSE;
	bool in_header = TRUE;

	/* find the message to send */
	f = fopen(msgf, "r");
	if (f == NULL)
	{
		f = fopen("/etc/mail/vacation.def", "r");
		if (f == NULL) {
			usrerr("No message to send");
			exit(EX_OSFILE);
		}
	}

	if (pipe(pipefd) < 0) {
		usrerr("pipe() failed");
		exit(EX_OSERR);
	}
	i = fork();
	if (i < 0) {
		usrerr("fork() failed");
		exit(EX_OSERR);
	}
	if (i == 0) {
		dup2(pipefd[0], 0);
		close(pipefd[0]);
		close(pipefd[1]);
		fclose(f);
		execl("/usr/lib/sendmail", "sendmail", "-eq", "-f", myname,
			"--", user, NULL);
		usrerr("can't exec /usr/lib/sendmail");
		exit(EX_OSERR);
	}
	close(pipefd[0]);
	fpipe = fdopen(pipefd[1], "w");
	if (fpipe == NULL) {
		usrerr("fdopen() failed");
		exit(EX_OSERR);
	}
	fprintf(fpipe, "To: %s\n", user);
	fputs("Auto-Submitted: auto-replied\n", fpipe);
	fputs("X-Mailer: vacation %I%\n", fpipe);

	/*
	 * We used to write directly to the pipe.  But now we need to know
	 * what character set to use, and we need to examine the entire
	 * message to determine this.  So write to a temp file first.
	 */
	tmpf_name = strdup(_PATH_TMP);
	if (tmpf_name == NULL) {
		usrerr("newstr: cannot alloc memory");
		exit(EX_OSERR);
	}
	tmpfd = -1;
	tmpfd = mkstemp(tmpf_name);
	if (tmpfd == -1) {
		usrerr("can't open temp file %s", tmpf_name);
		exit(EX_OSERR);
	}
	tmpf = fdopen(tmpfd, "w");
	if (tmpf == NULL) {
		usrerr("can't open temp file %s", tmpf_name);
		exit(EX_OSERR);
	}
	while (fgets(line, MAXLINE, f)) {
		/*
		 * Check for a line with no ':' character.  If it's just \n,
		 * we're at the end of the headers and all is fine.  Or if
		 * it starts with white-space, then it's a continuation header.
		 * Otherwise, it's the start of the body, which means the
		 * header/body separator was skipped.  So output it.
		 */
		if (in_header && line[0] != '\0' && strchr(line, ':') == NULL) {
			if (line[0] == '\n')
				in_header = FALSE;
			else if (!isspace(line[0])) {
				in_header = FALSE;
				fputs("\n", tmpf);
			}
		}
		p = strchr(line, '$');
		if (p && strncmp(p, "$SUBJECT", 8) == 0) {
			*p = '\0';
			seen8bitchars |= any8bitchars(line);
			fputs(line, tmpf);
			if (Subject) {
				if (in_header)
					fputs(EncodedSubject, tmpf);
				else {
					seen8bitchars |= any8bitchars(Subject);
					fputs(Subject, tmpf);
				}
			}
			seen8bitchars |= any8bitchars(p+8);
			fputs(p+8, tmpf);
			continue;
		}
		seen8bitchars |= any8bitchars(line);
		fputs(line, tmpf);
	}
	fclose(f);
	fclose(tmpf);

	/*
	 * If we haven't seen a funky Subject with Charset, use the default.
	 * If we have and it's us-ascii, 8-bit chars in the message file will
	 * still result in iso-8859-1.
	 */
	if (Charset[0] == '\0')
		(void) strlcpy(Charset, (seen8bitchars) ? "iso-8859-1" :
		    "us-ascii", sizeof (Charset));
	else if ((strcasecmp(Charset, "us-ascii") == 0) && seen8bitchars)
		(void) strlcpy(Charset, "iso-8859-1", sizeof (Charset));
	if (Debug)
		printf("Charset is %s\n", Charset);
	fprintf(fpipe, "Content-Type: text/plain; charset=%s\n", Charset);
	fputs("Mime-Version: 1.0\n", fpipe);

	/*
	 * Now read back in from the temp file and write to the pipe.
	 */
	tmpf = fopen(tmpf_name, "r");
	if (tmpf == NULL) {
		usrerr("can't open temp file %s", tmpf_name);
		exit(EX_OSERR);
	}
	while (fgets(line, MAXLINE, tmpf))
		fputs(line, fpipe);
	fclose(fpipe);
	fclose(tmpf);
	(void) unlink(tmpf_name);
	free(tmpf_name);
}

/*
 *  INITIALIZE -- initialize the database before leaving for vacation
 *
 *	Parameters:
 *		none.
 *
 *	Returns:
 *		none.
 *
 *	Side Effects:
 *		Initializes the files .vacation.{pag,dir} in the
 *		caller's home directory.
 */

static void
initialize(db_file_base)
	char *db_file_base;
{
	char *homedir;
	char buf[MAXLINE];
	DBM *db;

	setgid(getgid());
	setuid(getuid());
	homedir = getenv("HOME");
	if (homedir == NULL) {
		usrerr("No home!");
		exit(EX_NOUSER);
	}
	(void) snprintf(buf, sizeof (buf), "%s%s%s", homedir,
		(db_file_base[0] == '/') ? "" : "/", db_file_base);

	if (!(db = dbm_open(buf, O_WRONLY|O_CREAT|O_TRUNC, 0644))) {
		usrerr("%s: %s\n", buf, strerror(errno));
		exit(EX_DATAERR);
	}
	dbm_close(db);
}

/*
 *  USRERR -- print user error
 *
 *	Parameters:
 *		f -- format.
 *
 *	Returns:
 *		none.
 *
 *	Side Effects:
 *		none.
 */

/* PRINTFLIKE1 */
void
usrerr(const char *f, ...)
{
	va_list alist;

	va_start(alist, f);
	(void) fprintf(stderr, "vacation: ");
	(void) vfprintf(stderr, f, alist);
	(void) fprintf(stderr, "\n");
	va_end(alist);
}

/*
 *  NEWSTR -- copy a string
 *
 *	Parameters:
 *		s -- the string to copy.
 *
 *	Returns:
 *		A copy of the string.
 *
 *	Side Effects:
 *		none.
 */

static char *
newstr(s)
	char *s;
{
	char *p;
	size_t s_sz = strlen(s);

	p = malloc(s_sz + 1);
	if (p == NULL)
	{
		usrerr("newstr: cannot alloc memory");
		exit(EX_OSERR);
	}
	(void) strlcpy(p, s, s_sz + 1);
	return (p);
}

/*
 *  SAMEWORD -- return TRUE if the words are the same
 *
 *	Ignores case.
 *
 *	Parameters:
 *		a, b -- the words to compare.
 *
 *	Returns:
 *		TRUE if a & b match exactly (modulo case)
 *		FALSE otherwise.
 *
 *	Side Effects:
 *		none.
 */

static bool
sameword(a, b)
	register char *a, *b;
{
	char ca, cb;

	do
	{
		ca = *a++;
		cb = *b++;
		if (isascii(ca) && isupper(ca))
			ca = ca - 'A' + 'a';
		if (isascii(cb) && isupper(cb))
			cb = cb - 'A' + 'a';
	} while (ca != '\0' && ca == cb);
	return (ca == cb);
}

/*
 * When invoked with no arguments, we fall into an automatic installation
 * mode, stepping the user through a default installation.
 */

static void
AutoInstall()
{
	char file[MAXLINE];
	char forward[MAXLINE];
	char cmd[MAXLINE];
	char line[MAXLINE];
	char *editor;
	FILE *f;
	struct passwd *pw;
	extern mode_t umask(mode_t cmask);

	umask(022);
	pw = getpwuid(getuid());
	if (pw == NULL) {
		usrerr("User ID unknown");
		exit(EX_NOUSER);
	}
	myname = strdup(pw->pw_name);
	if (myname == NULL) {
		usrerr("Out of memory");
		exit(EX_OSERR);
	}
	homedir = getenv("HOME");
	if (homedir == NULL) {
		usrerr("Home directory unknown");
		exit(EX_NOUSER);
	}

	printf("This program can be used to answer your mail automatically\n");
	printf("when you go away on vacation.\n");
	(void) strlcpy(file, homedir, sizeof (file));
	(void) strlcat(file, MsgFile, sizeof (file));
	do {
		f = fopen(file, "r");
		if (f) {
			printf("You have a message file in %s.\n", file);
			if (ask("Would you like to see it")) {
				(void) snprintf(cmd, sizeof (cmd),
				    "/usr/bin/more %s", file);
				system(cmd);
			}
			if (ask("Would you like to edit it"))
				f = NULL;
		} else {
			printf("You need to create a message file"
			    " in %s first.\n", file);
			f = fopen(file, "w");
			if (f == NULL) {
				usrerr("Cannot open %s", file);
				exit(EX_CANTCREAT);
			}
			fprintf(f, "Subject: away from my mail\n");
			fprintf(f, "\nI will not be reading my mail"
			    " for a while.\n");
			fprintf(f, "Your mail regarding \"$SUBJECT\" will"
			    " be read when I return.\n");
			fclose(f);
			f = NULL;
		}
		if (f == NULL) {
			editor = getenv("VISUAL");
			if (editor == NULL)
				editor = getenv("EDITOR");
			if (editor == NULL)
				editor = "/usr/bin/vi";
			(void) snprintf(cmd, sizeof (cmd), "%s %s", editor,
			    file);
			printf("Please use your editor (%s)"
			    " to edit this file.\n", editor);
			system(cmd);
		}
	} while (f == NULL);
	fclose(f);
	(void) strlcpy(forward, homedir, sizeof (forward));
	(void) strlcat(forward, "/.forward", sizeof (forward));
	f = fopen(forward, "r");
	if (f) {
		printf("You have a .forward file"
		    " in your home directory containing:\n");
		while (fgets(line, MAXLINE, f))
			printf("    %s", line);
		fclose(f);
		if (!ask("Would you like to remove it and"
		    " disable the vacation feature"))
			exit(EX_OK);
		if (unlink(forward))
			perror("Error removing .forward file:");
		else
			printf("Back to normal reception of mail.\n");
		exit(EX_OK);
	}

	printf("To enable the vacation feature"
	    " a \".forward\" file is created.\n");
	if (!ask("Would you like to enable the vacation feature")) {
		printf("OK, vacation feature NOT enabled.\n");
		exit(EX_OK);
	}
	f = fopen(forward, "w");
	if (f == NULL) {
		perror("Error opening .forward file");
		exit(EX_CANTCREAT);
	}
	fprintf(f, "\\%s, \"|/usr/bin/vacation %s\"\n", myname, myname);
	fclose(f);
	printf("Vacation feature ENABLED."
	    " Please remember to turn it off when\n");
	printf("you get back from vacation. Bon voyage.\n");

	initialize(DbFileBase);
	exit(EX_OK);
}


/*
 * Ask the user a question until we get a reasonable answer
 */

static bool
ask(prompt)
	char *prompt;
{
	char line[MAXLINE];
	char *res;

	for (;;) {
		printf("%s? ", prompt);
		fflush(stdout);
		res = fgets(line, sizeof (line), stdin);
		if (res == NULL)
			return (FALSE);
		if (res[0] == 'y' || res[0] == 'Y')
			return (TRUE);
		if (res[0] == 'n' || res[0] == 'N')
			return (FALSE);
		printf("Please reply \"yes\" or \"no\" (\'y\' or \'n\')\n");
	}
}
