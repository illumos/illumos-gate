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

/*
 * Copyright (c) 1988, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#include "uucp.h"

#include <unistd.h>
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
 *    call bsfix()?
 *    combine the 3 versions of everything (sys, dev, and dial) into one.
 *    allow arbitrary classes of service.
 *    need verifysys() for uucheck.
 *    nameserver interface?
 *    pass sysname (or 0) to getsysline().  (might want reg. exp. or NS processing 
 */

/* private variables */
static void tokenize(), nameparse(), setfile(), setioctl(),
	scansys(), scancfg(), setconfig();
static int namematch(), nextdialers(), nextdevices(), nextsystems(), getaline();

/* pointer arrays might be dynamically allocated */
static char *Systems[64] = {0};	/* list of Systems files */
static char *Devices[64] = {0};	/* list of Devices files */
static char *Dialers[64] = {0};	/* list of Dialers files */
static char *Pops[64] = {0};	/* list of STREAMS modules to be popped */
static char *Pushes[64] = {0};	/* list of STREAMS modules to be pushed */

static int nsystems;		/* index into list of Systems files */
static int ndevices;		/* index into list of Devices files */
static int ndialers;		/* index into list of Dialers files */
static int npops;		/* index into list of STREAMS modules */
							/*to be popped */
static int npushes;		/* index into list of STREAMS modules */
							/*to be pushed */

GLOBAL unsigned connecttime = CONNECTTIME;
GLOBAL unsigned expecttime = EXPECTTIME;
GLOBAL unsigned msgtime = MSGTIME;

static FILE *fsystems;
static FILE *fdevices;
static FILE *fdialers;

static char errformat[BUFSIZ];

/* this might be dynamically allocated */
#define NTOKENS 16
static char *tokens[NTOKENS], **tokptr;

/* export these */
EXTERN void sysreset(), devreset(), dialreset(), setdevcfg(), setservice();
EXTERN char *strsave();

/* import these */
extern char *strcpy(), *strtok(), *strchr(), *strsave();
EXTERN int eaccess();

/*
 * setservice init's Systems, Devices, Dialers lists from Sysfiles
 */
GLOBAL void
setservice(service)
char *service;
{
	char	*prev = _uu_setlocale(LC_ALL, "C");

	setconfig();
	scansys(service);
	(void) _uu_resetlocale(LC_ALL, prev);
	return;
}

/*
 * setdevcfg init's Pops, Pushes lists from Devconfig
 */

GLOBAL void
setdevcfg(service, device)
char *service, *device;
{
	char	*prev = _uu_setlocale(LC_ALL, "C");

	scancfg(service, device);
	(void) _uu_resetlocale(LC_ALL, prev);
	return;
}

/*	administrative files access */
GLOBAL int
sysaccess(type)
int type;
{
	switch (type) {

	case ACCESS_SYSTEMS:
		return(access(Systems[nsystems], R_OK));
	case ACCESS_DEVICES:
		return(access(Devices[ndevices], R_OK));
	case ACCESS_DIALERS:
		return(access(Dialers[ndialers], R_OK));
	case EACCESS_SYSTEMS:
		return(eaccess(Systems[nsystems], R_OK));
	case EACCESS_DEVICES:
		return(eaccess(Devices[ndevices], R_OK));
	case EACCESS_DIALERS:
		return(eaccess(Dialers[ndialers], R_OK));
	default:
		(void)sprintf(errformat, "bad access type %d", type);
		logent(errformat, "sysaccess");
		return(FAIL);
	}
}


/*
 * read Sysfiles, set up lists of Systems/Devices/Dialers file names.
 * allow multiple entries for a given service, allow a service
 * type to describe resources more than once, e.g., systems=foo:baz systems=bar.
 */
static void
scansys(service)
char *service;
{	FILE *f;
	char *tok, buf[BUFSIZ];

	Systems[0] = Devices[0] = Dialers[0] = NULL;
	if ((f = fopen(SYSFILES, "r")) != 0) {
		while (getaline(f, buf) > 0) { 
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
		ASSERT(Systems[0] != NULL, Ct_ALLOCATE, "scansys: Systems", 0);
		Systems[1] = NULL;
	}
	if (Devices[0] == NULL) {
		Devices[0] = strsave(DEVICES);
		ASSERT(Devices[0] != NULL, Ct_ALLOCATE, "scansys: Devices", 0);
		Devices[1] = NULL;
	}
	if (Dialers[0] == NULL) {
		Dialers[0] = strsave(DIALERS);
		ASSERT(Dialers[0] != NULL, Ct_ALLOCATE, "scansys: Dialers", 0);
		Dialers[1] = NULL;
	}
	return;
}


/*
 * read Devconfig.  allow multiple entries for a given service, allow a service
 * type to describe resources more than once, e.g., push=foo:baz push=bar.
 */
static void
scancfg(service, device)
char *service, *device;
{	FILE *f;
	char *tok, buf[BUFSIZ];

	/* (re)initialize device-specific information */

	npops = npushes = 0;
	Pops[0] = Pushes[0] = NULL;
	connecttime = CONNECTTIME;
	expecttime = EXPECTTIME;
	msgtime = MSGTIME;

	if ((f = fopen(DEVCONFIG, "r")) != 0) {
		while (getaline(f, buf) > 0) {
			/* got a (logical) line from Devconfig */
			/* strtok's of this buf continue in tokenize() */
			tok = strtok(buf, " \t");
			if (namematch("service=", tok, service)) {
				tok = strtok((char *)0, " \t");
				if ( namematch("device=", tok, device)) {
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
getaline(f, line)
FILE *f;
char *line;
{	char *lptr, *lend;

	lptr = line;
	while (fgets(lptr, (line + BUFSIZ) - lptr, f) != NULL) {
		lend = lptr + strlen(lptr);
		if (lend == lptr || lend[-1] != '\n')	
			/* empty buf or line too long! */
			break;
		*--lend = '\0'; /* lop off ending '\n' */
		if ( lend == line ) /* empty line - ignore */
			continue;
		lptr = lend;
		if (lend[-1] != '\\')
			break;
		/* continuation */
		lend[-1] = ' ';
	}
	return(lptr - line);
}

/*
 * given a label (e.g., "service=", "device="), a name ("cu", "uucico"),
 *  and a line:  if line begins with the label and if the name appears
 * in a colon-separated list of names following the label, return true;
 * else return false
 */
static int
namematch(label, line, name)
char *label, *line, *name;
{	char *lend;

	if (strncmp(label, line, strlen(label)) != SAME) {
		return(FALSE);	/* probably a comment line */
	}
	line += strlen(label);
	if (*line == '\0')
		return(FALSE);
	/*
	 * can't use strtok() in the following because scansys(),
	 * scancfg() do an initializing call to strtok() before
	 * coming here and then CONTINUE calling strtok() in tokenize(),
	 * after returning from namematch().
	 */
	while ((lend = strchr(line, ':')) != NULL) {
		*lend = '\0';
		if (strcmp(line, name) == SAME)
			return(TRUE);
		line = lend+1;
	}
	return(strcmp(line, name) == SAME);
}

/*
 * tokenize() continues pulling tokens out of a buffer -- the
 * initializing call to strtok must have been made before calling
 * tokenize() -- and starts stuffing 'em into tokptr.
 */
static void
tokenize()
{	char *tok;

	tokptr = tokens;
	while ((tok = strtok((char *) NULL, " \t")) != NULL) {
		*tokptr++ = tok;
		if (tokptr - tokens >= NTOKENS)
			break;
	}
	*tokptr = NULL;
	return;
}

/*
 * look at top token in array: should be line of the form
 *	name=item1:item2:item3...
 * if name is one we recognize, then call set[file|ioctl] to set up 
 * corresponding list.  otherwise, log bad name.
 */
static void
nameparse()
{	char **line, *equals;
	int temp;

#define setuint(a,b,c) a = ( ((temp = atoi(b)) <= 0) ? (c) : temp )

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
			setuint(msgtime, equals, MSGTIME);
		else {
			(void)sprintf(errformat,"unrecognized label %s",*line);
			logent(errformat, "Sysfiles|Devconfig");
		}
	}
	return;
}

/*
 * given the list for a particular type (systems, devices,...)
 * and a line of colon-separated files, add 'em to list
 */

static void
setfile(type, line)
char **type, *line;
{	char **tptr, *tok;
	char expandpath[BUFSIZ];

	if (*line == 0)
		return;
	tptr = type;
	while (*tptr)		/* skip over existing entries to*/
		tptr++;		/* concatenate multiple entries */

	for (tok = strtok(line, ":"); tok != NULL;
	tok = strtok((char *) NULL, ":")) {
		expandpath[0] = '\0';
		if ( *tok != '/' )
			/* by default, file names are relative to SYSDIR */
			sprintf(expandpath, "%s/", SYSDIR);
		strcat(expandpath, tok);
		if (eaccess(expandpath, R_OK) != 0)
			/* if we can't read it, no point in adding to list */
			continue;
		*tptr = strsave(expandpath);
		ASSERT(*tptr != NULL, Ct_ALLOCATE, "setfile: tptr", 0);
		tptr++;
	}
	return;
}

/*
 * given the list for a particular ioctl (push, pop)
 * and a line of colon-separated modules, add 'em to list
 */

static void
setioctl(type, line)
char **type, *line;
{	char **tptr, *tok;

	if (*line == 0)
		return;
	tptr = type;
	while (*tptr)		/* skip over existing entries to*/
		tptr++;		/* concatenate multiple entries */
	for (tok = strtok(line, ":"); tok != NULL;
	tok = strtok((char *) NULL, ":")) {
		*tptr = strsave(tok);
		ASSERT(*tptr != NULL, Ct_ALLOCATE, "setioctl: tptr", 0);
		tptr++;
	}
	return;
}

/*
 * reset Systems files
 */
GLOBAL void
sysreset()
{
	if (fsystems)
		fclose(fsystems);
	fsystems = NULL;
	nsystems = 0;
	devreset();
	return;
}

/*
 * reset Devices files
 */
GLOBAL void		
devreset()
{
	if (fdevices)
		fclose(fdevices);
	fdevices = NULL;
	ndevices = 0;
	dialreset();
	return;
}

/*
 * reset Dialers files
 */
GLOBAL void		
dialreset()
{
	if (fdialers)
		fclose(fdialers);
	fdialers = NULL;
	ndialers = 0;
	return;
}

/*
 * get next line from Systems file
 * return TRUE if successful, FALSE if not
 */
GLOBAL int
getsysline(buf, len)
char *buf;
{
	char	*prev = _uu_setlocale(LC_ALL, "C");

	if (Systems[0] == NULL)
		/* not initialized via setservice() - use default */
		setservice("uucico");

	/* initialize devices and dialers whenever a new line is read */
	/* from systems */
	devreset();
	if (fsystems == NULL)
		if (nextsystems() == FALSE) {
			(void) _uu_resetlocale(LC_ALL, prev);
			return(FALSE);
		}

	ASSERT(len >= BUFSIZ, "BUFFER TOO SMALL", "getsysline", 0);
	for(;;) {
		while (getaline(fsystems, buf) != 0)
		    if ((*buf != '#') && (*buf != ' ') &&
			(*buf != '\t') && (*buf != '\n')) {
			(void) _uu_resetlocale(LC_ALL, prev);
			return(TRUE);
		}
		if (nextsystems() == FALSE) {
			(void) _uu_resetlocale(LC_ALL, prev);
			return(FALSE);
		}
	}
}

/*
 * move to next systems file.  return TRUE if successful, FALSE if not
 */
static int
nextsystems()
{
	devreset();

	if (fsystems != NULL) {
		(void) fclose(fsystems);
		nsystems++;
	} else {
		nsystems = 0;
	}
	for ( ; Systems[nsystems] != NULL; nsystems++)
		if ((fsystems = fopen(Systems[nsystems], "r")) != NULL)
			return(TRUE);
	return(FALSE);
}
		
/*
 * get next line from Devices file
 * return TRUE if successful, FALSE if not
 */
GLOBAL int
getdevline(buf, len)
char *buf;
{
	char	*prev = _uu_setlocale(LC_ALL, "C");

	if (Devices[0] == NULL)
		/* not initialized via setservice() - use default */
		setservice("uucico");

	if (fdevices == NULL)
		if (nextdevices() == FALSE) {
			(void) _uu_resetlocale(LC_ALL, prev);
			return(FALSE);
		}
	for(;;) {
		if (fgets(buf, len, fdevices) != NULL) {
			(void) _uu_resetlocale(LC_ALL, prev);
			return(TRUE);
		}
		if (nextdevices() == FALSE) {
			(void) _uu_resetlocale(LC_ALL, prev);
			return(FALSE);
		}
	}
}

/*
 * move to next devices file.  return TRUE if successful, FALSE if not
 */
static int
nextdevices()
{
	if (fdevices != NULL) {
		(void) fclose(fdevices);
		ndevices++;
	} else {
		ndevices = 0;
	}
	for ( ; Devices[ndevices] != NULL; ndevices++)
		if ((fdevices = fopen(Devices[ndevices], "r")) != NULL)
			return(TRUE);
	return(FALSE);
}

		
/*
 * get next line from Dialers file
 * return TRUE if successful, FALSE if not
 */

GLOBAL int
getdialline(buf, len)
char *buf;
{
	char	*prev = _uu_setlocale(LC_ALL, "C");

	if (Dialers[0] == NULL)
		/* not initialized via setservice() - use default */
		setservice("uucico");

	if (fdialers == NULL)
		if (nextdialers() == FALSE) {
			(void) _uu_resetlocale(LC_ALL, prev);
			return(FALSE);
		}
	for(;;) {
		if (fgets(buf, len, fdialers) != NULL) {
			(void) _uu_resetlocale(LC_ALL, prev);
			return(TRUE);
		}
		if (nextdialers() == FALSE) {
			(void) _uu_resetlocale(LC_ALL, prev);
			return(FALSE);
		}
	}
}

/*
 * move to next dialers file.  return TRUE if successful, FALSE if not
 */
static int
nextdialers()
{
	if (fdialers) {
		(void) fclose(fdialers);
		ndialers++;
	} else {
		ndialers = 0;
	}
	
	for ( ; Dialers[ndialers] != NULL; ndialers++)
		if ((fdialers = fopen(Dialers[ndialers], "r")) != NULL)
			return(TRUE);
	return(FALSE);
}

/*
 * get next module to be popped
 * return TRUE if successful, FALSE if not
 */
static int
getpop(buf, len, optional)
char *buf;
int len, *optional;
{
	int slen;

	if ( Pops[0] == NULL || Pops[npops] == NULL )
		return(FALSE);

	/*	if the module name is enclosed in parentheses,	*/
	/*	is optional. set flag & strip parens		*/
	slen = strlen(Pops[npops]) - 1;
	if ( Pops[npops][0] == '('  && Pops[npops][slen] == ')' ) {
		*optional = 1;
		len = ( slen < len ? slen : len );
		strncpy(buf, &(Pops[npops++][1]), len);
	} else {
		*optional = 0;
		strncpy(buf, Pops[npops++], len);
	}
	buf[len-1] = '\0';
	return(TRUE);
}

/*
 * get next module to be pushed
 * return TRUE if successful, FALSE if not
 */
static int
getpush(buf, len)
char *buf;
int len;
{
	if ( Pushes[0] == NULL || Pushes[npushes] == NULL )
		return(FALSE);
	strncpy(buf, Pushes[npushes++], len);
	return(TRUE);
}

/*
 * pop/push requested modules
 * return TRUE if successful, FALSE if not
 */
GLOBAL int
pop_push(fd)
int fd;
{
    char	strmod[FMNAMESZ], onstream[FMNAMESZ];
    int		optional;
    char	*prev = _uu_setlocale(LC_ALL, "C");

    /*	check for streams modules to pop	*/
    while ( getpop(strmod, sizeof(strmod), &optional) ) {
	DEBUG(5, (optional ? "pop_push: optionally POPing %s\n"
			   : "pop_push: POPing %s\n" ), strmod);
	if ( ioctl(fd, I_LOOK, onstream) == -1 ) {
	    DEBUG(5, "pop_push: I_LOOK on fd %d failed ", fd);
	    DEBUG(5, "errno %d\n", errno);
	    (void) _uu_resetlocale(LC_ALL, prev);
	    return(FALSE);
	}
	if ( strcmp(strmod, onstream) != SAME ) {
	    if ( optional )
		continue;
	    DEBUG(5, "pop_push: I_POP: %s not there\n", strmod);
	    (void) _uu_resetlocale(LC_ALL, prev);
	    return(FALSE);
	}
	if ( ioctl(fd, I_POP, 0) == -1 ) {
	    DEBUG(5, "pop_push: I_POP on fd %d failed ", fd);
	    DEBUG(5, "errno %d\n", errno);
	    (void) _uu_resetlocale(LC_ALL, prev);
	    return(FALSE);
	}
    }

    /*	check for streams modules to push	*/
    while ( getpush(strmod, sizeof(strmod)) ) {
	DEBUG(5, "pop_push: PUSHing %s\n", strmod);
	if ( ioctl(fd, I_PUSH, strmod) == -1 ) {
	    DEBUG(5, "pop_push: I_PUSH on fd %d failed ", fd);
	    DEBUG(5, "errno %d\n", errno);
	    (void) _uu_resetlocale(LC_ALL, prev);
	    return(FALSE);
	}
    }
    (void) _uu_resetlocale(LC_ALL, prev);
    return(TRUE);
}

/*
 * 	return name of currently open Systems file
 */
GLOBAL char *
currsys()
{
	return(Systems[nsystems]);
}

/*
 * 	return name of currently open Devices file
 */
GLOBAL char *
currdev()
{
	return(Devices[ndevices]);
}

/*
 * 	return name of currently open Dialers file
 */
GLOBAL char *
currdial()
{
	return(Dialers[ndialers]);
}

/*
 * set configuration parameters provided in Config file
 */
static void
setconfig()
{
    FILE *f;
    char buf[BUFSIZ];
    char *tok;
    extern char _ProtoCfg[];

    if ((f = fopen(CONFIG, "r")) != 0) {
	while (getaline(f, buf) > 0) { 
	    /* got a (logical) line from Config file */
	    tok = strtok(buf, " \t");
	    if ( (tok != NULL) && (*tok != '#') ) {
		/* got a token */

		/* this probably should be table driven when
		 * the list of configurable parameters grows.
		 */
		if (strncmp("Protocol=", tok, strlen("Protocol=")) == SAME) {
		    tok += strlen("Protocol=");
		    if ( *tok != '\0' ) {
			if ( _ProtoCfg[0] != '\0' ) {
			    DEBUG(7, "Protocol string %s ", tok);
			    DEBUG(7, "overrides %s\n", _ProtoCfg);
		        }
		        strcpy(_ProtoCfg, tok);
		    }
	        } else {
		    DEBUG(7, "Unknown configuration parameter %s\n", tok);
	        }
	    }
	}
    }
}
