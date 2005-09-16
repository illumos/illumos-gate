/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved.  The Berkeley Software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef FILEC
/*
 * Tenex style file name recognition, .. and more.
 * History:
 *	Author: Ken Greer, Sept. 1975, CMU.
 *	Finally got around to adding to the Cshell., Ken Greer, Dec. 1981.
 */

#include "sh.h"
#include <sys/types.h>
#include <dirent.h>
#include <pwd.h>
#include "sh.tconst.h"

#define	TRUE	1
#define	FALSE	0
#define	ON	1
#define	OFF	0

#define	ESC	'\033'

extern DIR *opendir_(tchar *);

static char *BELL = "\07";
static char *CTRLR = "^R\n";

typedef enum {LIST, RECOGNIZE} COMMAND;

static jmp_buf osetexit;		/* saved setexit() state */
static struct termios  tty_save;	/* saved terminal state */
static struct termios  tty_new;		/* new terminal state */

static int	is_prefix(tchar *, tchar *);
static int	is_suffix(tchar *, tchar *);
static int	ignored(tchar *);

/*
 * Put this here so the binary can be patched with adb to enable file
 * completion by default.  Filec controls completion, nobeep controls
 * ringing the terminal bell on incomplete expansions.
 */
bool filec = 0;

static void
setup_tty(int on)
{
	int omask;
#ifdef TRACE
	tprintf("TRACE- setup_tty()\n");
#endif

	omask = sigblock(sigmask(SIGINT));
	if (on) {
		/*
		 * The shell makes sure that the tty is not in some weird state
		 * and fixes it if it is.  But it should be noted that the
		 * tenex routine will not work correctly in CBREAK or RAW mode
		 * so this code below is, therefore, mandatory.
		 *
		 * Also, in order to recognize the ESC (filename-completion)
		 * character, set EOL to ESC.  This way, ESC will terminate
		 * the line, but still be in the input stream.
		 * EOT (filename list) will also terminate the line,
		 * but will not appear in the input stream.
		 *
		 * The getexit/setexit contortions ensure that the
		 * tty state will be restored if the user types ^C.
		 */
		(void) ioctl(SHIN, TCGETS,  (char *)&tty_save);
		getexit(osetexit);
		if (setjmp(reslab)) {
			(void) ioctl(SHIN, TCSETSW,  (char *)&tty_save);
			resexit(osetexit);
			reset();
		}
		tty_new = tty_save;
		tty_new.c_cc[VEOL] = ESC;
		tty_new.c_iflag |= IMAXBEL | BRKINT | IGNPAR;
		tty_new.c_lflag |= ICANON;
		tty_new.c_lflag |= ECHOCTL;
		tty_new.c_oflag &= ~OCRNL;
		(void) ioctl(SHIN, TCSETSW,  (char *)&tty_new);
	} else {
		/*
		 * Reset terminal state to what user had when invoked
		 */
		(void) ioctl(SHIN, TCSETSW,  (char *)&tty_save);
		resexit(osetexit);
	}
	(void) sigsetmask(omask);
}

static void
termchars(void)
{
	extern char *tgetstr();
	char bp[1024];
	static char area[256];
	static int been_here = 0;
	char *ap = area;
	char *s;
	char *term;

#ifdef TRACE
	tprintf("TRACE- termchars()\n");
#endif
	if (been_here)
		return;
	been_here = TRUE;

	if ((term = getenv("TERM")) == NULL)
		return;
	if (tgetent(bp, term) != 1)
		return;
	if (s = tgetstr("vb", &ap))		/* Visible Bell */
		BELL = s;
}

/*
 * Move back to beginning of current line
 */
static void
back_to_col_1(void)
{
	int omask;

#ifdef TRACE
	tprintf("TRACE- back_to_col_1()\n");
#endif
	omask = sigblock(sigmask(SIGINT));
	(void) write(SHOUT, "\r", 1);
	(void) sigsetmask(omask);
}

/*
 * Push string contents back into tty queue
 */
static void
pushback(tchar *string, int echoflag)
{
	tchar *p;
	struct termios tty;
	int omask, retry = 0;

#ifdef TRACE
	tprintf("TRACE- pushback()\n");
#endif
	omask = sigblock(sigmask(SIGINT));
	tty = tty_new;
	if (!echoflag)
		tty.c_lflag &= ~ECHO;

again:
	(void) ioctl(SHIN, TCSETSF, (char *)&tty);

	for (p = string; *p; p++) {
		char	mbc[MB_LEN_MAX];
		int	i, j = wctomb(mbc, (wchar_t)*p);

		if (j < 0) {
			/* Error! But else what can we do? */
			continue;
		}
		for (i = 0; i < j; ++i) {
			if (ioctl(SHIN, TIOCSTI, mbc + i) != 0 &&
			    errno == EAGAIN) {
				if (retry++ < 5)
					goto again;
				/* probably no worth retrying any more */
			}
		}
	}

	if (tty.c_lflag != tty_new.c_lflag)
		(void) ioctl(SHIN, TCSETS,  (char *)&tty_new);
	(void) sigsetmask(omask);
}

/*
 * Concatenate src onto tail of des.
 * Des is a string whose maximum length is count.
 * Always null terminate.
 */
void
catn(tchar *des, tchar *src, int count)
{
#ifdef TRACE
	tprintf("TRACE- catn()\n");
#endif

	while (--count >= 0 && *des)
		des++;
	while (--count >= 0)
		if ((*des++ = *src++) == '\0')
			return;
	*des = '\0';
}

static int
max(a, b)
{

	return (a > b ? a : b);
}

/*
 * Like strncpy but always leave room for trailing \0
 * and always null terminate.
 */
void
copyn(tchar *des, tchar *src, int count)
{

#ifdef TRACE
	tprintf("TRACE- copyn()\n");
#endif
	while (--count >= 0)
		if ((*des++ = *src++) == '\0')
			return;
	*des = '\0';
}

/*
 * For qsort()
 */
static int
fcompare(tchar **file1, tchar **file2)
{

#ifdef TRACE
	tprintf("TRACE- fcompare()\n");
#endif
	return (strcoll_(*file1, *file2));
}

static char
filetype(tchar *dir, tchar *file, int nosym)
{
	tchar path[MAXPATHLEN + 1];
	struct stat statb;

#ifdef TRACE
	tprintf("TRACE- filetype()\n");
#endif
	if (dir) {
		catn(strcpy_(path, dir), file, MAXPATHLEN);
		if (nosym) {
			if (stat_(path, &statb) < 0)
				return (' ');
		} else {
			if (lstat_(path, &statb) < 0)
				return (' ');
		}
		if ((statb.st_mode & S_IFMT) == S_IFLNK)
			return ('@');
		if ((statb.st_mode & S_IFMT) == S_IFDIR)
			return ('/');
		if (((statb.st_mode & S_IFMT) == S_IFREG) &&
		    (statb.st_mode & 011))
			return ('*');
	}
	return (' ');
}

/*
 * Print sorted down columns
 */
static void
print_by_column(tchar *dir, tchar *items[], int count, int looking_for_command)
{
	int i, rows, r, c, maxwidth = 0, columns;

#ifdef TRACE
	tprintf("TRACE- print_by_column()\n");
#endif
	for (i = 0; i < count; i++)
		maxwidth = max(maxwidth, tswidth(items[i]));

	/* for the file tag and space */
	maxwidth += looking_for_command ? 1 : 2;
	columns = max(78 / maxwidth, 1);
	rows = (count + (columns - 1)) / columns;

	for (r = 0; r < rows; r++) {
		for (c = 0; c < columns; c++) {
			i = c * rows + r;
			if (i < count) {
				int w;

				/*
				 * Print filename followed by
				 * '@' or '/' or '*' or ' '
				 */
				printf("%t", items[i]);
				w = tswidth(items[i]);
				if (!looking_for_command) {
					printf("%c",
					    (tchar) filetype(dir, items[i], 0));
					w++;
				}
				if (c < columns - 1)	/* last column? */
					for (; w < maxwidth; w++)
						printf(" ");
			}
		}
		printf("\n");
	}
}

/*
 * Expand file name with possible tilde usage
 *	~person/mumble
 * expands to
 *	home_directory_of_person/mumble
 */
tchar *
tilde(tchar *new, tchar *old)
{
	tchar *o, *p;
	struct passwd *pw;
	static tchar person[40];
	char person_[40];		/* work */
	tchar *pw_dir;			/* work */

#ifdef TRACE
	tprintf("TRACE- tilde()\n");
#endif
	if (old[0] != '~')
		return (strcpy_(new, old));

	for (p = person, o = &old[1]; *o && *o != '/'; *p++ = *o++)
		;
	*p = '\0';
	if (person[0] == '\0')
		(void) strcpy_(new, value(S_home /* "home" */));
	else {
		pw = getpwnam(tstostr(person_, person));
		if (pw == NULL)
			return (NULL);
		pw_dir = strtots((tchar *)NULL, pw->pw_dir);	/* allocate */
		(void) strcpy_(new, pw_dir);
		xfree(pw_dir);					/* free it */
	}
	(void) strcat_(new, o);
	return (new);
}

/*
 * Cause pending line to be printed
 */
static void
sim_retype(void)
{
#ifdef notdef
	struct termios tty_pending;

#ifdef TRACE
	tprintf("TRACE- sim_retypr()\n");
#endif
	tty_pending = tty_new;
	tty_pending.c_lflag |= PENDIN;

	(void) ioctl(SHIN, TCSETS,  (char *)&tty_pending);
#else
#ifdef TRACE
	tprintf("TRACE- sim_retype()\n");
#endif
	(void) write(SHOUT, CTRLR, strlen(CTRLR));
	printprompt();
#endif
}

static int
beep_outc(int c)
{
	char	buf[1];

	buf[0] = c;

	(void) write(SHOUT, buf, 1);

	return 0;
}

static void
beep(void)
{

#ifdef TRACE
	tprintf("TRACE- beep()\n");
#endif
	if (adrof(S_nobeep /* "nobeep" */) == 0)
		(void) tputs(BELL, 0, beep_outc);
}

/*
 * Erase that silly ^[ and print the recognized part of the string.
 */
static void
print_recognized_stuff(tchar *recognized_part)
{
	int unit =  didfds ? 1 : SHOUT;

#ifdef TRACE
	tprintf("TRACE- print_recognized_stuff()\n");
#endif

	/*
	 * An optimized erasing of that silly ^[
	 *
	 * One would think that line speeds have become fast enough that this
	 * isn't necessary, but it turns out that the visual difference is
	 * quite noticeable.
	 */
	flush();
	switch (tswidth(recognized_part)) {
	case 0:
		/* erase two characters: ^[ */
		write(unit, "\b\b  \b\b", sizeof "\b\b  \b\b" - 1);
		break;

	case 1:
		/* overstrike the ^, erase the [ */
		write(unit, "\b\b", 2);
		printf("%t", recognized_part);
		write(unit, "  \b\b", 4);
		break;

	default:
		/* overstrike both characters ^[ */
		write(unit, "\b\b", 2);
		printf("%t", recognized_part);
		break;
	}
	flush();
}

/*
 * Parse full path in file into 2 parts: directory and file names
 * Should leave final slash (/) at end of dir.
 */
static void
extract_dir_and_name(tchar *path, tchar *dir, tchar *name)
{
	tchar  *p;

#ifdef TRACE
	tprintf("TRACE- extract_dir_and_name()\n");
#endif
	p = rindex_(path, '/');
	if (p == NOSTR) {
		copyn(name, path, MAXNAMLEN);
		dir[0] = '\0';
	} else {
		copyn(name, ++p, MAXNAMLEN);
		copyn(dir, path, p - path);
	}
}

tchar *
getentry(DIR *dir_fd, int looking_for_lognames)
{
	struct passwd *pw;
	struct dirent *dirp;
	/*
	 * For char * -> tchar * Conversion
	 */
	static tchar strbuf[MAXNAMLEN+1];

#ifdef TRACE
	tprintf("TRACE- getentry()\n");
#endif
	if (looking_for_lognames) {
		if ((pw = getpwent()) == NULL)
			return (NULL);
		return (strtots(strbuf, pw->pw_name));
	}
	if (dirp = readdir(dir_fd))
		return (strtots(strbuf, dirp->d_name));
	return (NULL);
}

static void
free_items(tchar **items)
{
	int i;

#ifdef TRACE
	tprintf("TRACE- free_items()\n");
#endif
	for (i = 0; items[i]; i++)
		xfree(items[i]);
	xfree((char *)items);
}

#define	FREE_ITEMS(items) { \
	int omask;\
\
	omask = sigblock(sigmask(SIGINT));\
	free_items(items);\
	items = NULL;\
	(void) sigsetmask(omask);\
}

/*
 * Perform a RECOGNIZE or LIST command on string "word".
 */
static int
search2(tchar *word, COMMAND command, int max_word_length)
{
	static tchar **items = NULL;
	DIR *dir_fd;
	int numitems = 0, ignoring = TRUE, nignored = 0;
	int name_length, looking_for_lognames;
	tchar tilded_dir[MAXPATHLEN + 1], dir[MAXPATHLEN + 1];
	tchar name[MAXNAMLEN + 1], extended_name[MAXNAMLEN+1];
	tchar *entry;
#define	MAXITEMS 1024
#ifdef TRACE
	tprintf("TRACE- search2()\n");
#endif

	if (items != NULL)
		FREE_ITEMS(items);

	looking_for_lognames = (*word == '~') && (index_(word, '/') == NULL);
	if (looking_for_lognames) {
		(void) setpwent();
		copyn(name, &word[1], MAXNAMLEN);	/* name sans ~ */
	} else {
		extract_dir_and_name(word, dir, name);
		if (tilde(tilded_dir, dir) == 0)
			return (0);
		dir_fd = opendir_(*tilded_dir ? tilded_dir : S_DOT /* "." */);
		if (dir_fd == NULL)
			return (0);
	}

again:	/* search for matches */
	name_length = strlen_(name);
	for (numitems = 0; entry = getentry(dir_fd, looking_for_lognames); ) {
		if (!is_prefix(name, entry))
			continue;
		/* Don't match . files on null prefix match */
		if (name_length == 0 && entry[0] == '.' &&
		    !looking_for_lognames)
			continue;
		if (command == LIST) {
			if (numitems >= MAXITEMS) {
				printf("\nYikes!! Too many %s!!\n",
				    looking_for_lognames ?
					"names in password file":"files");
				break;
			}
			if (items == NULL)
				items =  (tchar **)xcalloc(sizeof (items[1]),
				    MAXITEMS+1);
			items[numitems] = (tchar *)xalloc((unsigned)(strlen_(entry) + 1) * sizeof (tchar));
			copyn(items[numitems], entry, MAXNAMLEN);
			numitems++;
		} else {			/* RECOGNIZE command */
			if (ignoring && ignored(entry))
				nignored++;
			else if (recognize(extended_name,
			    entry, name_length, ++numitems))
				break;
		}
	}
	if (ignoring && numitems == 0 && nignored > 0) {
		ignoring = FALSE;
		nignored = 0;
		if (looking_for_lognames)
			(void) setpwent();
		else
			rewinddir(dir_fd);
		goto again;
	}

	if (looking_for_lognames)
		(void) endpwent();
	else {
		unsetfd(dir_fd->dd_fd);
		closedir_(dir_fd);
	}
	if (command == RECOGNIZE && numitems > 0) {
		if (looking_for_lognames)
			copyn(word, S_TIL /* "~" */, 1);
		else
			/* put back dir part */
			copyn(word, dir, max_word_length);
		/* add extended name */
		catn(word, extended_name, max_word_length);
		return (numitems);
	}
	if (command == LIST) {
		qsort((char *)items, numitems, sizeof (items[1]),
		    (int (*)(const void *, const void *))fcompare);
		/*
		 * Never looking for commands in this version, so final
		 * argument forced to 0.  If command name completion is
		 * reinstated, this must change.
		 */
		print_by_column(looking_for_lognames ? NULL : tilded_dir,
		    items, numitems, 0);
		if (items != NULL)
			FREE_ITEMS(items);
	}
	return (0);
}

/*
 * Object: extend what user typed up to an ambiguity.
 * Algorithm:
 * On first match, copy full entry (assume it'll be the only match)
 * On subsequent matches, shorten extended_name to the first
 * character mismatch between extended_name and entry.
 * If we shorten it back to the prefix length, stop searching.
 */
int
recognize(tchar *extended_name, tchar *entry, int name_length, int numitems)
{

#ifdef TRACE
	tprintf("TRACE- recognize()\n");
#endif
	if (numitems == 1)				/* 1st match */
		copyn(extended_name, entry, MAXNAMLEN);
	else {					/* 2nd and subsequent matches */
		tchar *x, *ent;
		int len = 0;

		x = extended_name;
		for (ent = entry; *x && *x == *ent++; x++, len++)
			;
		*x = '\0';			/* Shorten at 1st char diff */
		if (len == name_length)		/* Ambiguous to prefix? */
			return (-1);		/* So stop now and save time */
	}
	return (0);
}

/*
 * Return true if check items initial chars in template
 * This differs from PWB imatch in that if check is null
 * it items anything
 */
static int
is_prefix(tchar *check, tchar *template)
{
#ifdef TRACE
	tprintf("TRACE- is_prefix()\n");
#endif

	do
		if (*check == 0)
			return (TRUE);
	while (*check++ == *template++);
	return (FALSE);
}

/*
 *  Return true if the chars in template appear at the
 *  end of check, i.e., are its suffix.
 */
static int
is_suffix(tchar *check, tchar *template)
{
	tchar *c, *t;

#ifdef TRACE
	tprintf("TRACE- is_suffix()\n");
#endif
	for (c = check; *c++; )
		;
	for (t = template; *t++; )
		;
	for (;;) {
		if (t == template)
			return (TRUE);
		if (c == check || *--t != *--c)
			return (FALSE);
	}
}

int
tenex(tchar *inputline, int inputline_size)
{
	int numitems, num_read, should_retype;
	int i;

#ifdef TRACE
	tprintf("TRACE- tenex()\n");
#endif
	setup_tty(ON);
	termchars();
	num_read = 0;
	should_retype = FALSE;
	while ((i = read_(SHIN, inputline+num_read, inputline_size-num_read))
	    > 0) {
		static tchar *delims = S_DELIM /* " '\"\t;&<>()|`" */;
		tchar *str_end, *word_start, last_char;
		int space_left;
		struct termios tty;
		COMMAND command;

		num_read += i;
		inputline[num_read] = '\0';
		last_char = inputline[num_read - 1] & TRIM;

		/*
		 * read_() can return more than requested size if there
		 * is multibyte character at the end.
		 */
		if ((num_read >= inputline_size) || (last_char == '\n'))
			break;

		str_end = &inputline[num_read];
		if (last_char == ESC) {
			command = RECOGNIZE;
			*--str_end = '\0';	/* wipe out trailing ESC */
		} else
			command = LIST;

		tty = tty_new;
		tty.c_lflag &= ~ECHO;
		(void) ioctl(SHIN, TCSETSF, (char *)&tty);

		if (command == LIST)
			printf("\n");
		/*
		 * Find LAST occurence of a delimiter in the inputline.
		 * The word start is one character past it.
		 */
		for (word_start = str_end; word_start > inputline;
		    --word_start) {
			if (index_(delims, word_start[-1]) ||
			    isauxsp(word_start[-1]))
				break;
		}
		space_left = inputline_size - (word_start - inputline) - 1;
		numitems = search2(word_start, command, space_left);

		/*
		 * Tabs in the input line cause trouble after a pushback.
		 * tty driver won't backspace over them because column
		 * positions are now incorrect. This is solved by retyping
		 * over current line.
		 */
		if (index_(inputline, '\t')) {	/* tab tchar in input line? */
			back_to_col_1();
			should_retype = TRUE;
		}
		if (command == LIST)		/* Always retype after a LIST */
			should_retype = TRUE;
		if (should_retype)
			printprompt();
		pushback(inputline, should_retype);
		num_read = 0;			/* chars will be reread */
		should_retype = FALSE;

		/*
		 * Avoid a race condition by echoing what we're recognized
		 * _after_ pushing back the command line.  This way, if the
		 * user waits until seeing this output before typing more
		 * stuff, the resulting keystrokes won't race with the STIed
		 * input we've pushed back.  (Of course, if the user types
		 * ahead, the race still exists and it's quite possible that
		 * the pushed back input line will interleave with the
		 * keystrokes in unexpected ways.)
		 */
		if (command == RECOGNIZE) {
			/* print from str_end on */
			print_recognized_stuff(str_end);
			if (numitems != 1)	/* Beep = No match/ambiguous */
				beep();
		}
	}
	setup_tty(OFF);
	return (num_read);
}

static int
ignored(tchar *entry)
{
	struct varent *vp;
	tchar **cp;

#ifdef TRACE
	tprintf("TRACE- ignored()\n");
#endif
	if ((vp = adrof(S_fignore /* "fignore" */)) == NULL ||
	    (cp = vp->vec) == NULL)
		return (FALSE);
	for (; *cp != NULL; cp++)
		if (is_suffix(entry, *cp))
			return (TRUE);
	return (FALSE);
}
#endif /* FILEC */
