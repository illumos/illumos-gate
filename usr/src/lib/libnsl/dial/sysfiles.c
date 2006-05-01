/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
/*	  All Rights Reserved	*/

/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mt.h"
#include "uucp.h"

#include <unistd.h>
#include <string.h>
#include "sysfiles.h"
#include <sys/stropts.h>

/*
 * manage systems files (Systems, Devices, and Dialcodes families).
 *
 * also manage new file Devconfig, allows per-device setup.
 * present use is to specify what streams modules to push/pop for
 * AT&T TLI/streams network.
 *
 * TODO:
 *	call bsfix()?
 *	combine the 3 versions of everything (sys, dev, and dial) into one.
 *	allow arbitrary classes of service.
 *	need verifysys() for uucheck.
 *	nameserver interface?
 *	pass sysname (or 0) to getsysline().  (might want reg. exp. or
 *		NS processing)
 */

/* private variables */
static void tokenize(void);
static void nameparse(void);
static void setfile(char **, char *);
static void setioctl(char **, char *);
static void scansys(const char *);
static void scancfg(char *, char *);
static void setconfig(void);
static int namematch(const char *label, char *line, const char *name);
static int nextdialers(void);
static int nextdevices(void);
static int nextsystems(void);
static int getline(FILE *, char *);

/* pointer arrays might be dynamically allocated */
static char *Systems[64];	/* list of Systems files */
static char *Devices[64];	/* list of Devices files */
static char *Dialers[64];	/* list of Dialers files */
static char *Pops[64];		/* list of STREAMS modules to be popped */
static char *Pushes[64];	/* list of STREAMS modules to be pushed */

static int nsystems;		/* index into list of Systems files */
static int ndevices;		/* index into list of Devices files */
static int ndialers;		/* index into list of Dialers files */
static int npops;		/* index into list of STREAMS modules */
							/* to be popped */
static int npushes;		/* index into list of STREAMS modules */
							/* to be pushed */

static unsigned connecttime, expecttime;

static FILE *fsystems;
static FILE *fdevices;
static FILE *fdialers;

/* this might be dynamically allocated */
#define	NTOKENS 16
static char *tokens[NTOKENS], **tokptr;

/* export these */
static void setservice(const char *service);
static void sysreset(void);
static void devreset(void);
static void dialreset(void);
static void setdevcfg(char *, char *);
static void setservice(const char *);

/* import these */
extern char *strsave(const char *);
static int eaccess(char *, mode_t);

/*
 * setservice init's Systems, Devices, Dialers lists from Sysfiles
 */
static void
setservice(const char *service)
{
	setconfig();
	scansys(service);
}

/*
 * setdevcfg init's Pops, Pushes lists from Devconfig
 */

static void
setdevcfg(char *service, char *device)
{
	scancfg(service, device);
}

/*	administrative files access */
static int
sysaccess(int type)
{
	char errformat[BUFSIZ];

	switch (type) {
	case ACCESS_SYSTEMS:
		return (access(Systems[nsystems], R_OK));
	case ACCESS_DEVICES:
		return (access(Devices[ndevices], R_OK));
	case ACCESS_DIALERS:
		return (access(Dialers[ndialers], R_OK));
	case EACCESS_SYSTEMS:
		return (eaccess(Systems[nsystems], R_OK));
	case EACCESS_DEVICES:
		return (eaccess(Devices[ndevices], R_OK));
	case EACCESS_DIALERS:
		return (eaccess(Dialers[ndialers], R_OK));
	}
	(void) sprintf(errformat, "bad access type %d", type);
	logent(errformat, "sysaccess");
	return (FAIL);
}


/*
 * read Sysfiles, set up lists of Systems/Devices/Dialers file names.
 * allow multiple entries for a given service, allow a service
 * type to describe resources more than once, e.g., systems=foo:baz systems=bar.
 */
static void
scansys(const char *service)
{	FILE *f;
	char *tok, buf[BUFSIZ];

	Systems[0] = Devices[0] = Dialers[0] = NULL;
	if ((f = fopen(SYSFILES, "rF")) != 0) {
		while (getline(f, buf) > 0) {
			/* got a (logical) line from Sysfiles */
			/* strtok's of this buf continue in tokenize() */
			tok = strtok(buf, " \t");
			if (namematch("service=", tok, service)) {
				tokenize();
				nameparse();
			}
		}
		(void) fclose(f);
	}

	/* if didn't find entries in Sysfiles, use defaults */
	if (Systems[0] == NULL) {
		Systems[0] = strsave(SYSTEMS);
		ASSERT(Systems[0] != NULL, "Ct_ALLOCATE", "scansys: Systems",
									0);
		Systems[1] = NULL;
	}
	if (Devices[0] == NULL) {
		Devices[0] = strsave(DEVICES);
		ASSERT(Devices[0] != NULL, "Ct_ALLOCATE", "scansys: Devices",
									0);
		Devices[1] = NULL;
	}
	if (Dialers[0] == NULL) {
		Dialers[0] = strsave(DIALERS);
		ASSERT(Dialers[0] != NULL, "Ct_ALLOCATE", "scansys: Dialers",
									0);
		Dialers[1] = NULL;
	}
}


/*
 * read Devconfig.  allow multiple entries for a given service, allow a service
 * type to describe resources more than once, e.g., push=foo:baz push=bar.
 */
static void
scancfg(char *service, char *device)
{	FILE *f;
	char *tok, buf[BUFSIZ];

	/* (re)initialize device-specific information */
	npops = npushes = 0;
	Pops[0] = Pushes[0] = NULL;
	connecttime = CONNECTTIME;
	expecttime = EXPECTTIME;

	if ((f = fopen(DEVCONFIG, "rF")) != 0) {
		while (getline(f, buf) > 0) {
			/* got a (logical) line from Devconfig */
			/* strtok's of this buf continue in tokenize() */
			tok = strtok(buf, " \t");
			if (namematch("service=", tok, service)) {
				tok = strtok((char *)0, " \t");
				if (namematch("device=", tok, device)) {
					tokenize();
					nameparse();
				}
			}
		}
		(void) fclose(f);
	}
	return;

}

/*
 *  given a file pointer and buffer, construct logical line in buffer
 *  (i.e., concatenate lines ending in '\').  return length of line
 *  ASSUMES that buffer is BUFSIZ long!
 */

static int
getline(FILE *f, char *line)
{	char *lptr, *lend;

	lptr = line;
	while (fgets(lptr, (line + BUFSIZ) - lptr, f) != NULL) {
		lend = lptr + strlen(lptr);
		if (lend == lptr || lend[-1] != '\n')
			/* empty buf or line too long! */
			break;
		*--lend = '\0'; /* lop off ending '\n' */
		if (lend == line) /* empty line - ignore */
			continue;
		lptr = lend;
		if (lend[-1] != '\\')
			break;
		/* continuation */
		lend[-1] = ' ';
	}
	return (lptr - line);
}

/*
 * given a label (e.g., "service=", "device="), a name ("cu", "uucico"),
 *  and a line:  if line begins with the label and if the name appears
 * in a colon-separated list of names following the label, return true;
 * else return false
 */
static int
namematch(const char *label, char *line, const char *name)
{
	char *lend;

	if (strncmp(label, line, strlen(label)) != SAME)
		return (FALSE);	/* probably a comment line */
	line += strlen(label);
	if (*line == '\0')
		return (FALSE);
	/*
	 * can't use strtok() in the following because scansys(),
	 * scancfg() do an initializing call to strtok() before
	 * coming here and then CONTINUE calling strtok() in tokenize(),
	 * after returning from namematch().
	 */
	while ((lend = strchr(line, ':')) != NULL) {
		*lend = '\0';
		if (strcmp(line, name) == SAME)
			return (TRUE);
		line = lend+1;
	}
	return (strcmp(line, name) == SAME);
}

/*
 * tokenize() continues pulling tokens out of a buffer -- the
 * initializing call to strtok must have been made before calling
 * tokenize() -- and starts stuffing 'em into tokptr.
 */
static void
tokenize(void)
{
	char *tok;

	tokptr = tokens;
	while ((tok = strtok(NULL, " \t")) != NULL) {
		*tokptr++ = tok;
		if (tokptr - tokens >= NTOKENS)
			break;
	}
	*tokptr = NULL;
}

/*
 * look at top token in array: should be line of the form
 *	name=item1:item2:item3...
 * if name is one we recognize, then call set[file|ioctl] to set up
 * corresponding list.  otherwise, log bad name.
 */
static void
nameparse(void)
{
	char **line, *equals;
	int temp;

#define	setuint(a, b, c) a = (((temp = atoi(b)) <= 0) ? (c) : temp)

	for (line = tokens; (line - tokens) < NTOKENS && *line; line++) {
		equals = strchr(*line, '=');
		if (equals == NULL)
			continue;	/* may be meaningful someday? */
		*equals = '\0';
		/* ignore entry with empty rhs */
		if (*++equals == '\0')
			continue;
		if (strcmp(*line, "systems") == SAME)
			setfile(Systems, equals);
		else if (strcmp(*line, "devices") == SAME)
			setfile(Devices, equals);
		else if (strcmp(*line, "dialers") == SAME)
			setfile(Dialers, equals);
		else if (strcmp(*line, "pop") == SAME)
			setioctl(Pops, equals);
		else if (strcmp(*line, "push") == SAME)
			setioctl(Pushes, equals);
		else if (strcmp(*line, "connecttime") == SAME)
			setuint(connecttime, equals, CONNECTTIME);
		else if (strcmp(*line, "expecttime") == SAME)
			setuint(expecttime, equals, EXPECTTIME);
		else if (strcmp(*line, "msgtime") == SAME)
			continue;
		else {
			char errformat[BUFSIZ];

			(void) snprintf(errformat, sizeof (errformat),
						"unrecognized label %s", *line);
			logent(errformat, "Sysfiles|Devconfig");
		}
	}
}

/*
 * given the list for a particular type (systems, devices,...)
 * and a line of colon-separated files, add 'em to list
 */

static void
setfile(char **type, char *line)
{
	char **tptr, *tok;
	char expandpath[BUFSIZ];

	if (*line == 0)
		return;
	tptr = type;
	while (*tptr)		/* skip over existing entries to */
		tptr++;		/* concatenate multiple entries */

	for (tok = strtok(line, ":"); tok != NULL; tok = strtok(NULL, ":")) {
		expandpath[0] = '\0';
		if (*tok != '/')
			/* by default, file names are relative to SYSDIR */
			(void) snprintf(expandpath, sizeof (expandpath),
								"%s/", SYSDIR);
		(void) strcat(expandpath, tok);
		if (eaccess(expandpath, R_OK) != 0)
			/* if we can't read it, no point in adding to list */
			continue;
		*tptr = strsave(expandpath);
		ASSERT(*tptr != NULL, "Ct_ALLOCATE", "setfile: tptr", 0);
		tptr++;
	}
}

/*
 * given the list for a particular ioctl (push, pop)
 * and a line of colon-separated modules, add 'em to list
 */

static void
setioctl(char **type, char *line)
{
	char **tptr, *tok;

	if (*line == 0)
		return;
	tptr = type;
	while (*tptr)		/* skip over existing entries to */
		tptr++;		/* concatenate multiple entries */
	for (tok = strtok(line, ":"); tok != NULL; tok = strtok(NULL, ":")) {
		*tptr = strsave(tok);
		ASSERT(*tptr != NULL, "Ct_ALLOCATE", "setioctl: tptr", 0);
		tptr++;
	}
}

/*
 * reset Systems files
 */
static void
sysreset(void)
{
	if (fsystems)
		(void) fclose(fsystems);
	fsystems = NULL;
	nsystems = 0;
	devreset();
}

/*
 * reset Devices files
 */
static void
devreset(void)
{
	if (fdevices)
		(void) fclose(fdevices);
	fdevices = NULL;
	ndevices = 0;
	dialreset();
}

/*
 * reset Dialers files
 */
static void
dialreset(void)
{
	if (fdialers)
		(void) fclose(fdialers);
	fdialers = NULL;
	ndialers = 0;
}

/*
 * get next line from Systems file
 * return TRUE if successful, FALSE if not
 */
static int
getsysline(char *buf, int len)
{
	if (Systems[0] == NULL)
		/* not initialized via setservice() - use default */
		setservice("uucico");

	/* initialize devices and dialers whenever a new line is read */
	/* from systems */
	devreset();
	if (fsystems == NULL)
		if (nextsystems() == FALSE)
			return (FALSE);

	for (;;) {
		while (fgets(buf, len, fsystems) != NULL)
			if ((*buf != '#') && (*buf != ' ') &&
				(*buf != '\t') && (*buf != '\n'))
			return (TRUE);
		if (nextsystems() == FALSE)
			return (FALSE);
	}
}

/*
 * move to next systems file.  return TRUE if successful, FALSE if not
 */
static int
nextsystems(void)
{
	devreset();

	if (fsystems != NULL) {
		(void) fclose(fsystems);
		nsystems++;
	} else {
		nsystems = 0;
	}
	for (; Systems[nsystems] != NULL; nsystems++)
		if ((fsystems = fopen(Systems[nsystems], "rF")) != NULL)
			return (TRUE);
	return (FALSE);
}

/*
 * get next line from Devices file
 * return TRUE if successful, FALSE if not
 */
static int
getdevline(char *buf, int len)
{
	if (Devices[0] == NULL)
		/* not initialized via setservice() - use default */
		setservice("uucico");

	if (fdevices == NULL)
		if (nextdevices() == FALSE)
			return (FALSE);
	for (;;) {
		if (fgets(buf, len, fdevices) != NULL)
			return (TRUE);
		if (nextdevices() == FALSE)
			return (FALSE);
	}
}

/*
 * move to next devices file.  return TRUE if successful, FALSE if not
 */
static int
nextdevices(void)
{
	if (fdevices != NULL) {
		(void) fclose(fdevices);
		ndevices++;
	} else {
		ndevices = 0;
	}
	for (; Devices[ndevices] != NULL; ndevices++)
		if ((fdevices = fopen(Devices[ndevices], "rF")) != NULL)
			return (TRUE);
	return (FALSE);
}


/*
 * get next line from Dialers file
 * return TRUE if successful, FALSE if not
 */

static int
getdialline(char *buf, int len)
{
	if (Dialers[0] == NULL)
		/* not initialized via setservice() - use default */
		setservice("uucico");

	if (fdialers == NULL)
		if (nextdialers() == FALSE)
			return (FALSE);
	for (;;) {
		if (fgets(buf, len, fdialers) != NULL)
			return (TRUE);
		if (nextdialers() == FALSE)
			return (FALSE);
	}
}

/*
 * move to next dialers file.  return TRUE if successful, FALSE if not
 */
static int
nextdialers(void)
{
	if (fdialers) {
		(void) fclose(fdialers);
		ndialers++;
	} else {
		ndialers = 0;
	}

	for (; Dialers[ndialers] != NULL; ndialers++)
		if ((fdialers = fopen(Dialers[ndialers], "rF")) != NULL)
			return (TRUE);
	return (FALSE);
}

/*
 * get next module to be popped
 * return TRUE if successful, FALSE if not
 */
static int
getpop(char *buf, size_t len, int *optional)
{
	int slen;

	if (Pops[0] == NULL || Pops[npops] == NULL)
		return (FALSE);

	/*	if the module name is enclosed in parentheses,	*/
	/*	is optional. set flag & strip parens		*/
	slen = strlen(Pops[npops]) - 1;
	if (Pops[npops][0] == '(' && Pops[npops][slen] == ')') {
		*optional = 1;
		len = (slen < len ? slen : len);
		(void) strncpy(buf, &(Pops[npops++][1]), len);
	} else {
		*optional = 0;
		(void) strncpy(buf, Pops[npops++], len);
	}
	buf[len-1] = '\0';
	return (TRUE);
}

/*
 * get next module to be pushed
 * return TRUE if successful, FALSE if not
 */
static int
getpush(char *buf, size_t len)
{
	if (Pushes[0] == NULL || Pushes[npushes] == NULL)
		return (FALSE);
	(void) strncpy(buf, Pushes[npushes++], len);
	return (TRUE);
}

/*
 * pop/push requested modules
 * return TRUE if successful, FALSE if not
 */
static int
pop_push(int fd)
{
	char	strmod[FMNAMESZ], onstream[FMNAMESZ];
	int		optional;

	/*	check for streams modules to pop	*/
	while (getpop(strmod, sizeof (strmod), &optional)) {
		DEBUG(5, (optional ?
			(const char *)"pop_push: optionally POPing %s\n" :
			(const char *)"pop_push: POPing %s\n"), strmod);
		if (ioctl(fd, I_LOOK, onstream) == -1) {
			DEBUG(5, "pop_push: I_LOOK on fd %d failed ", fd);
			DEBUG(5, "errno %d\n", errno);
			return (FALSE);
		}
		if (strcmp(strmod, onstream) != SAME) {
			if (optional)
				continue;
			DEBUG(5, "pop_push: I_POP: %s not there\n", strmod);
			return (FALSE);
		}
		if (ioctl(fd, I_POP, 0) == -1) {
			DEBUG(5, "pop_push: I_POP on fd %d failed ", fd);
			DEBUG(5, "errno %d\n", errno);
			return (FALSE);
		}
	}

	/*	check for streams modules to push	*/
	while (getpush(strmod, sizeof (strmod))) {
		DEBUG(5, "pop_push: PUSHing %s\n", strmod);
		if (ioctl(fd, I_PUSH, strmod) == -1) {
			DEBUG(5, "pop_push: I_PUSH on fd %d failed ", fd);
			DEBUG(5, "errno %d\n", errno);
			return (FALSE);
		}
	}
	return (TRUE);
}

#ifndef SMALL
/*
 *	return name of currently open Systems file
 */
static char *
currsys(void)
{
	return (Systems[nsystems]);
}

/*
 *	return name of currently open Devices file
 */
static char *
currdev(void)
{
	return (Devices[ndevices]);
}

/*
 *	return name of currently open Dialers file
 */
static char *
currdial(void)
{
	return (Dialers[ndialers]);
}
#endif

/*
 * set configuration parameters provided in Config file
 */
static void
setconfig(void)
{
	FILE *f;
	char buf[BUFSIZ];
	char *tok;
	extern char _ProtoCfg[];

	if ((f = fopen(CONFIG, "rF")) != 0) {
	while (getline(f, buf) > 0) {
		/* got a (logical) line from Config file */
		tok = strtok(buf, " \t");
		if ((tok != NULL) && (*tok != '#')) {
			/* got a token */
			/*
			 * this probably should be table driven when
			 * the list of configurable parameters grows.
			 */
			if (strncmp("Protocol=", tok, strlen("Protocol=")) ==
								SAME) {
				tok += strlen("Protocol=");
				if (*tok != '\0') {
					if (_ProtoCfg[0] != '\0') {
						/*EMPTY*/
						DEBUG(7, "Protocol string %s ",
								tok);
						DEBUG(7, "overrides %s\n",
								_ProtoCfg);
					}
					(void) strcpy(_ProtoCfg, tok);
				}
			} else {
				/*EMPTY*/
				DEBUG(7, "Unknown configuration parameter %s\n",
								tok);
			}
		}
	}
	(void) fclose(f);
	}
}
