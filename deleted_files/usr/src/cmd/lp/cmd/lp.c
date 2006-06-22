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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* lp -- print files on a line printer */

#include <stdio.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <assert.h>
#include <locale.h>
#include <string.h>
#include "requests.h"
#include "lp.h"
#include "msgs.h"
#include "printers.h"

#define WHO_AM_I	I_AM_LP
#include "oam.h"

#define TRUE 1
#define FALSE 0
#define ALERT_CMD "/etc/lp/alerts/jobdone"
		/* file to run when job is done if -p option is selected */
short alertMsg = FALSE;		/* TRUE => user wants notification via
				   running /etc/lp/alerts/jobdone
				   FALSE => don't do it */
#define HOLD 1
#define RESUME 2
#define IMMEDIATE 3
#define POSTSCRIPT	"postscript"

static struct stat stbuf;	/* Global stat buffer */
static char *dest = NULL;	/* destination class or printer */
static char *title = NULL;	/* User-supplied title for output */
static int specialh = 0;	/* -H flag indicates special handling */
static char *formname = NULL;	/* form to use */
static char *char_set = NULL;	/* print wheel or character set to use */
static char *cont_type = NULL;	/* content type of input files */
static char *curdir;		/* working directory at time of request */
static char reqfile[20];	/* name of request file */
static char *stdinfile;
static char *rfilebase;
static short priority = -1;	/* priority of print request */
static short copies = 0;	/* number of copies of output */
static char **opts = NULL;	/* options for interface program */
static char **yopts = NULL;	/* options for filter program */
static char *pages = NULL;	/* pages to be printed */
static short silent = FALSE;	/* don't run off at the mouth */
static short mail = FALSE;	/* TRUE => user wants mail, FALSE ==> no mail */
static short wrt = FALSE;	/* TRUE => user wants notification on tty
				 * via write, FALSE => don't write
				 */
static short raw = FALSE;	/* set option xx"stty=raw"xx and raw flag if
				 * true
				 */
static short copy = FALSE;	/* TRUE => copy files, FALSE ==> don't */
static char *pre_rqid = NULL;	/* previos request id (-i option) */
static char *reqid = NULL;	/* request id for this job */

static char **files = NULL;	/* list of file to be printed */
static int nfiles = 0;		/* # of files on cmd line (excluding "-") */
static int stdinp = 0;		/* indicates how many times to print std input
				 *-1 ==> standard input empty
				 */
static int Tflag = 0;		/* 0, -T not specified, 1, -T specified
				 * this flag used for autorecognizing
				 * postscript
				 * if == 1, autorec. ps. is off!
				 */

static int exit_code = 0;	/* exit with this value */

extern char *sprintlist();
extern int appendlist();

static void startup(), clean_up(), err_exit(), savestd(), arps(REQUEST *rqp),
	ack_job(), catch(), allocfiles(), end_change(char *, REQUEST *);
static int psfile(char *);
static char *start_ch(char *), *getfiles(int), *que_job(REQUEST *);
static REQUEST *makereq();

#define OPTSTRING "q:H:f:d:T:S:o:y:P:i:cmwpn:st:r"

static void
chk_cont_type(str)
char *str;
{
    if (STREQU(str, NAME_ANY) || STREQU(str, NAME_TERMINFO)) {
	LP_ERRMSG2(ERROR, E_LP_BADOARG, 'T', str);
	exit(1);
    }
}

char *
mkAlertCmd(char *reqfile)
{
	char *str,*ptr;
	int len;

	str = (char *) malloc(strlen(ALERT_CMD) + strlen(dest) +
		strlen(reqfile) + 3);
	ptr = strchr(reqfile,'-');
	len = (ptr ? ptr-reqfile : strlen(reqfile));
	sprintf(str,"%s %s %.*s", ALERT_CMD, dest, len, reqfile);

	return(str);
}

int
main(int argc, char *argv[])
{
    int letter;
    char *p, **templist, **stemp;
    char *file;
    REQUEST *reqp, *makereq();
    int fileargs = 0;
    extern char *optarg;
    extern int optind, opterr, optopt;

    (void) setlocale (LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define TEXT_DOMAIN "SYS_TEST"
#endif
    (void) textdomain(TEXT_DOMAIN);

    opterr = 0; /* disable printing of errors by getopt */
    while ((letter = getopt(argc, argv, OPTSTRING)) != -1)
	switch(letter) {
	case 'c':	/* copy files */
	    if (copy) LP_ERRMSG1(WARNING, E_LP_2MANY, 'c');
	    copy = TRUE;
	    break;
	case 'd':	/* destination */
	    if (dest) LP_ERRMSG1(WARNING, E_LP_2MANY, 'd');
	    dest = optarg;
	    if (!isprinter(dest) && !isclass(dest) && !STREQU(dest, NAME_ANY)) {
		LP_ERRMSG1(ERROR, E_LP_DSTUNK, dest);
		exit (1);
	    }
	    break;
	case 'f':
	    if (formname) LP_ERRMSG1(WARNING, E_LP_2MANY, 'f');
	    formname = optarg;
	    break;
	case 'H':
	    if (specialh) LP_ERRMSG1(WARNING, E_LP_2MANY, 'H');
	    if (STREQU(optarg, "hold")) specialh = HOLD;
	    else if (STREQU(optarg, "resume")) specialh = RESUME;
	    else if (STREQU(optarg, "immediate")) specialh = IMMEDIATE;
	    else {
		LP_ERRMSG2(ERROR, E_LP_BADOARG, 'H', optarg);
		exit(1);
	    }
	    break;
	case 'i':
	    if (pre_rqid) LP_ERRMSG1(WARNING, E_LP_2MANY, 'i');
	    pre_rqid = optarg;
	    break;
	case 'm':	/* mail */
	    if (mail) LP_ERRMSG1(WARNING, E_LP_2MANY, 'm');
	    mail = TRUE;
	    break;
	case 'n':	/* # of copies */
	    if (copies) LP_ERRMSG1(WARNING, E_LP_2MANY, 'n');
	    if (
		*optarg == 0
	     || (copies=(int)strtol(optarg, &p, 10)) <= 0
	     || *p
	    ) {
		LP_ERRMSG2(ERROR, E_LP_BADOARG, 'n', optarg);
		exit(1);
	    }
	    break;
	case 'o':	/* option for interface program */
	    stemp = templist = getlist(optarg, " \t", "");  /* MR bl88-13915 */
	    if (!stemp)
		break;			/* MR bl88-14720 */
	    while (*templist)
		appendlist(&opts, *templist++);
	    freelist(stemp);
	    break;
	case 'y':
	    stemp = templist = getlist(optarg, " \t", ",");
	    if (!stemp)
		break;			/* MR bl88-14720 */
	    while (*templist)
		appendlist(&yopts, *templist++);
	    freelist(stemp);
	    break;
	case 'P':
	    if (pages) LP_ERRMSG1(WARNING, E_LP_2MANY, 'P');
	    pages = optarg;
	    break;
	case 'q':
	    if (priority != -1) LP_ERRMSG1(WARNING, E_LP_2MANY, 'q');
	    priority = (int)strtol(optarg, &p, 10);
	    if (*p || priority<0 || priority>39) {
		LP_ERRMSG1(ERROR, E_LP_BADPRI, optarg);
	 	exit(1);
	    }
	    break;
	case 'r':
	    if (raw) LP_ERRMSG1(WARNING, E_LP_2MANY, 'r');
	    raw = TRUE;
	    break;
	case 's':	/* silent */
	    if (silent) LP_ERRMSG1(WARNING, E_LP_2MANY, 's');
	    silent = 1;
	    break;
	case 'S':
	    if (char_set) LP_ERRMSG1(WARNING, E_LP_2MANY, 'S');
	    char_set = optarg;
	    break;
	case 't':	/* title */
	    if (title) LP_ERRMSG1(WARNING, E_LP_2MANY, 't');
	    title = optarg;
	    break;
	case 'T':
	    if (cont_type) LP_ERRMSG1(WARNING, E_LP_2MANY, 'T');
	    chk_cont_type(optarg);
	    cont_type = optarg;
	    Tflag++;
	    break;
        case 'p':
	    if (alertMsg) LP_ERRMSG1(WARNING, E_LP_2MANY, 'p');
	    alertMsg = TRUE;
	    break;
	case 'w':	/* write */
	    if (wrt) LP_ERRMSG1(WARNING, E_LP_2MANY, 'w');
	    wrt = TRUE;
	    break;
	default:
	    if (optopt == '?') {

                (void)printf(
			gettext("usage:\n\n(submit file(s) for printing)\n"));

		(void) printf (gettext(\
"lp [options] { file-name ... | - }\n"));

		(void) printf (gettext(
"	[-c]					(make copies first)\n"
"	[-d destination]			(printer/class to use)\n"
"	[-f form [-d any]]			(print on this form)\n"
"	[-H hold]				(don't print yet)\n"
"	[-H immediate]				(print first--reserved)\n"
"	[-m | -w]				(mail/write when done)\n"
"	[-p]					(notify when done via ToolTalk)\n"
"	[-n copies]				(print this many copies)\n"
"	[-o nobanner]				(no banner page)\n"));

		(void) printf (gettext(
"	[-o nofilebreak]			(no inter-file formfeed)\n"
"	[-o length=scaled-number]		(page length)\n"
"	[-o width=scaled-number]		(page width)\n"));

		(void) printf (gettext(
"	[-o lpi=scaled-number]			(line pitch)\n"
"	[-o cpi=scaled-number]			(character pitch)\n"));

		(void) printf (gettext(
"	[-o stty='stty-options']		(port characteristics)\n"
"	[-o other-local-options]		(as defined locally)\n"));

		(void) printf (gettext(
"	[-P page-list]				(locally defined)\n"
"	[-q priority]				(priority level)\n"
"	[-r]					(use no filter)\n"));

		(void) printf (gettext(
"	[-s]					(no request-id message)\n"
"	[-S char-set | print-wheel [-d any]]	(font to start with)\n"
"	[-t title]				(title for banner page)\n"
"	[-T file-type]				(type of input files)\n"
"	[-y local-modes]			(locally defined)\n"
"\n"));

		(void) printf(gettext(
"  (change previous request)\n"
"    lp -i request-id {options}\n"
"	[-H resume]				(resume held request)\n"
"	[other options listed above]\n"));

		exit(0);
	    }
	    (p = "-X")[1] = optopt;
	    if (strchr(OPTSTRING, optopt))
		LP_ERRMSG1(ERROR, E_LP_OPTARG, p);
	    else
		LP_ERRMSG1(ERROR, E_LP_OPTION, p);
	    exit(1);
	}

    if ((mail && wrt) || (mail && alertMsg) || (wrt && alertMsg))
	LP_ERRMSG(WARNING, E_LPP_COMBMW);

    while (optind < argc) {
	fileargs++;
	file = argv[optind++];
	if(strcmp(file, "-") == 0) {
	    stdinp++;
	    appendlist(&files, file);
	} else {
	    if(Access(file, 4/*read*/) || Stat(file, &stbuf)) {
		if (errno == EOVERFLOW)
			LP_ERRMSG2(WARNING, E_LP_LARGEFILE, file, errno);
		else
			LP_ERRMSG2(WARNING, E_LP_BADFILE, file, errno);
		exit_code = 1;
	    } else if((stbuf.st_mode & S_IFMT) == S_IFDIR) {
		LP_ERRMSG1(WARNING, E_LP_ISDIR, file);
		exit_code = 1;
	    } else if(stbuf.st_size == 0) {
		LP_ERRMSG1(WARNING, E_LP_EMPTY, file);
		exit_code = 1;
	    } else {
		nfiles++;
		appendlist(&files, file);
		continue;
	    }
	}
    }

    if(fileargs == 0) {
	if (!pre_rqid) stdinp = 1;
    } else if (pre_rqid) {
	LP_ERRMSG(ERROR, E_LPP_ILLARG);
	exit(1);
    } else if(nfiles == 0 && stdinp == 0) {
	LP_ERRMSG(ERROR, E_LP_NOFILES);
	exit(1);
    }

/* args parsed, now let's do it */

    startup();	/* open message queue
		and catch interupts so it gets closed too */

    if (!(reqp = makereq())) {	/* establish defaults & sanity check args */
	LP_ERRMSG1(ERROR, E_LPP_FGETREQ, pre_rqid);
	err_exit();
    }

    /* allocate files for request, standard input and files if copy */
    if (pre_rqid) {
	if (putrequest(reqfile, reqp) == -1) {	/* write request file */
puterr:
	    switch(errno) {
	    default:
		LP_ERRMSG(ERROR, E_LPP_FPUTREQ);
		err_exit();
	    }
	}
	end_change(pre_rqid, reqp);
	reqid = pre_rqid;
    } else {
	allocfiles();
	if(stdinp > 0) {
	    savestd();	/* save standard input */
	}
	reqp->file_list = files;
	arps(reqp);	/* autorecognize postscript */
	if (alertMsg) reqp->alert = mkAlertCmd(reqfile);
	if (putrequest(reqfile, reqp) == -1) goto puterr;
	reqid = que_job(reqp);
    }

    signal(SIGHUP, SIG_IGN);
    signal(SIGINT, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);
    signal(SIGTERM, SIG_IGN);

    clean_up();
    ack_job();		/* issue request id message */

    return (exit_code);
}
/* startup -- initialization routine */

static void
startup()
{
    void catch();
    int	try = 0;

    for (;;)
	if (mopen() == 0) break;
	else {
	    if (errno == ENOSPC && try++ < 5) {
		(void) sleep(3);
		continue;
	    }
	    LP_ERRMSG(ERROR, E_LP_MOPEN);
	    exit(1);
	}

    if(signal(SIGHUP, SIG_IGN) != SIG_IGN)
	signal(SIGHUP, catch);
    if(signal(SIGINT, SIG_IGN) != SIG_IGN)
	signal(SIGINT, catch);
    if(signal(SIGQUIT, SIG_IGN) != SIG_IGN)
	signal(SIGQUIT, catch);
    if(signal(SIGTERM, SIG_IGN) != SIG_IGN)
	signal(SIGTERM, catch);

    (void) umask(0000);
    curdir = getcwd(NULL, 512);
}

/* catch -- catch signals */

static void
catch()
{
    signal(SIGHUP, SIG_IGN);
    signal(SIGINT, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    err_exit();
}

/* clean_up -- called by catch() after interrupts
   or by err_exit() after errors */

static void
clean_up()
{
    (void)mclose ();
}

static void
err_exit()
{
    clean_up();
    exit(1);
}

/*
 * copyfile(stream, name) -- copy stream to file "name"
 */

static void
copyfile(stream, name)
FILE *stream;
char *name;
{
    FILE *ostream;
    int i;
    char buf[BUFSIZ];

    if ((ostream = fopen(name, "w")) == NULL) {
	LP_ERRMSG2(ERROR, E_LP_BADFILE, name, errno);
	return;
    }

    Chmod(name, 0600);
    errno = 0;
    while ((i = fread(buf, sizeof(char), BUFSIZ, stream)) > 0) {
	(void) fwrite(buf, sizeof(char), i, ostream);
	if (feof(stream)) break;
    }
    if (errno != 0) {
	if (errno == ENOSPC) {
		LP_ERRMSG(ERROR, E_LP_NOSPACE);
	} else {
		LP_ERRMSG2(ERROR, E_LP_BADFILE, name, errno);
	}
	err_exit();
    }

    (void) fclose(ostream);
}
/* makereq -- sanity check args, establish defaults */

static REQUEST *
makereq()
{
    static REQUEST rq;
    REQUEST *oldrqp;
    char *preqfile;
    char **optp, *pdest = dest;

    /*
     * begin changes for 1112940
     * The test used to look like: if (!dest && !pre_rqid && !cont_type)
     * Now, if either LPDEST or a default is set, use those instead of "any".
     * This is probably more like what the user expects and the SVID isn't
     * real clear about the interaction of LPDEST, the default and -T.
     * If the printer can't handle this content, we'll get an error later.
     */
    if (!dest && !pre_rqid) {
	if ((dest = getenv("LPDEST")) && *dest)
	    ;
	else {
	    if (!(dest = getdefault())) {
                if (cont_type)
		    dest = "any";
                else {
 		    LP_ERRMSG(ERROR, E_LPP_NODEST);
		    err_exit();
                }
	    }
	}
    }
    /* end changes for 1112940 */

    if (!dest) dest = "any";

    if (!pre_rqid && !cont_type) {
	cont_type = getenv("LPTYPE");
	if (cont_type != (char *) NULL) {
		Tflag++;/* for autorecognizing postscript, LPTYPE is	*/
			/* equivalent to specifying "-T"		*/
	}
    }
    if (!pre_rqid && !cont_type)
	cont_type = NAME_SIMPLE;

    if (formname && opts)
	for (optp = opts; *optp; optp++)
	    if (STRNEQU("lpi=", *optp, 4)
	     || STRNEQU("cpi=", *optp, 4)
	     || STRNEQU("length=", *optp, 7)
	     || STRNEQU("width=", *optp, 6)) {
		LP_ERRMSG(ERROR, E_LP_OPTCOMB);
		err_exit();
	    }

    if (raw && (yopts || pages)) {
	LP_ERRMSG(ERROR, E_LP_OPTCOMB);
	err_exit();
    }

    /* now to build the request */
    if (pre_rqid) {
	preqfile = start_ch(pre_rqid);
	(void) strlcpy(reqfile, preqfile, sizeof (reqfile));
	if (!(oldrqp = getrequest(preqfile))) return (NULL);
	rq.copies = (copies) ? copies : oldrqp->copies;
	rq.destination = (pdest) ? dest : oldrqp->destination;
	rq.file_list = oldrqp->file_list;
	rq.form = (formname) ? formname : oldrqp->form;
	rq.actions = (specialh) ? ((specialh == HOLD) ? ACT_HOLD :
	    ((specialh == RESUME) ? ACT_RESUME : ACT_IMMEDIATE)) :
	    oldrqp->actions;
	if (wrt) rq.actions |= ACT_WRITE;
	if (mail) rq.actions |= ACT_MAIL;
	if (raw) {
	    rq.actions |= ACT_RAW;
	    /*appendlist(&opts, "stty=raw");*/
	}
	rq.options = (opts) ? sprintlist(opts) : oldrqp->options;
	rq.priority = (priority == -1) ? oldrqp->priority : priority;
	rq.pages = (pages) ? pages : oldrqp->pages;
	rq.charset = (char_set) ? char_set : oldrqp->charset;
	rq.modes = (yopts) ? sprintlist(yopts) : oldrqp->modes;
	rq.title = (title) ? title : oldrqp->title;
	rq.input_type = (cont_type) ? cont_type : oldrqp->input_type;
	rq.alert = (alertMsg) ? mkAlertCmd(reqfile) : oldrqp->alert;
	rq.user = oldrqp->user;
	rq.outcome = 0;
	rq.version = VERSION_NEW_LP;
	return(&rq);
    }
    rq.copies = (copies) ? copies : 1;
    rq.destination = dest;
    rq.form = formname;
    rq.actions = (specialh) ? ((specialh == HOLD) ? ACT_HOLD :
	((specialh == RESUME) ? ACT_RESUME : ACT_IMMEDIATE)) : 0;
    if (wrt) rq.actions |= ACT_WRITE;
    if (mail) rq.actions |= ACT_MAIL;
    if (raw) {
	rq.actions |= ACT_RAW;
	/*appendlist(&opts, "stty=raw");*/
    }
    rq.alert = NULL;
    rq.options = sprintlist(opts);
    rq.priority = priority;
    rq.pages = pages;
    rq.charset = char_set;
    rq.modes = sprintlist(yopts);
    rq.title = title;
    rq.input_type = cont_type;
    rq.file_list = 0;
    rq.user = getname();
    rq.version = VERSION_NEW_LP;
    return(&rq);
}

/* files -- process command line file arguments */
static void
allocfiles()
{
    char **reqfiles = 0, **filep, *p, *prefix;
    FILE *f;
    int numfiles, filenum = 1;

    numfiles = 1 + ((stdinp > 0) ? 1 : 0) + ((copy) ? nfiles : 0);

    if ((prefix = getfiles(numfiles)) == NULL)
    {
	numfiles += nfiles;
	prefix = getfiles(numfiles);
	copy = 1;
    }

    (void) strlcpy(reqfile, prefix, sizeof (reqfile));
    (void) strlcat(reqfile, "-0000", sizeof (reqfile));
    rfilebase = makepath(Lp_Temp, reqfile, NULL);
    if (stdinp > 0) {
	stdinfile = strdup(rfilebase);
	p = strchr(stdinfile, 0) - 4;
	*p++ = '1';
	*p = 0;
	filenum++;
    }
    p = strchr(reqfile, 0) - 4; *p++ = '0'; *p = 0;
    p = strchr(rfilebase, 0) - 4;

    if (!files) appendlist(&files, "-");

    for (filep = files; *filep; filep++) {
	if(STREQU(*filep, "-")) {
	    if(stdinp > 0)
		appendlist(&reqfiles, stdinfile);
	} else {
	    if(copy) {
		if (f = fopen(*filep, "r")) {
		    (void) snprintf(p, sizeof ("0000"), "%d", filenum++);
		    copyfile(f, rfilebase);
		    appendlist(&reqfiles, rfilebase);
		    (void) fclose(f);
		} else
		    LP_ERRMSG2(WARNING, E_LP_BADFILE, *filep, errno);
	    } else {
		if (**filep == '/' || (curdir && *curdir))
		    appendlist(&reqfiles,
			(**filep == '/') ? *filep
				: makepath(curdir, *filep, (char *)0));
		else {
		    LP_ERRMSG (ERROR, E_LPP_CURDIR);
		    err_exit ();
		}
	    }
	}
    }
    freelist(files);
    files = reqfiles;
}

/* start_ch -- start change request */
static char *
start_ch(char *rqid)
{
    int size, type;
    short status;
    char message[100],
	 reply[100],
	 *rqfile;

    size = putmessage(message, S_START_CHANGE_REQUEST, rqid);
    assert(size != -1);
    if (msend(message)) {
	LP_ERRMSG(ERROR, E_LP_MSEND);
	err_exit();
    }
    if ((type = mrecv(reply, 100)) == -1) {
	LP_ERRMSG(ERROR, E_LP_MRECV);
	err_exit();
    }
    if (type != R_START_CHANGE_REQUEST
	   || getmessage(reply, type, &status, &rqfile) == -1) {
	LP_ERRMSG1(ERROR, E_LP_BADREPLY, type);
	err_exit();
    }

    switch (status) {
    case MOK:
	return(strdup(rqfile));
    case MNOPERM:
	LP_ERRMSG(ERROR, E_LP_NOTADM);
	break;
    case MUNKNOWN:
	LP_ERRMSG1(ERROR, E_LP_UNKREQID, rqid);
	break;
    case MBUSY:
	LP_ERRMSG1(ERROR, E_LP_BUSY, rqid);
	break;
    case M2LATE:
	LP_ERRMSG1(ERROR, E_LP_2LATE, rqid);
	break;
    case MGONEREMOTE:
	LP_ERRMSG1(ERROR, E_LP_GONEREMOTE, rqid);
	break;
    default:
	LP_ERRMSG1(ERROR, E_LP_BADSTATUS, status);
    }
    err_exit();
    /*NOTREACHED*/
    return (NULL);
}

static void
end_change(char *rqid, REQUEST *rqp)
{
    int size, type;
    long chkbits;
    short status;
    char message[255],
	 reply[100],
	 *chkp;

    size = putmessage(message, S_END_CHANGE_REQUEST, rqid);
    assert(size != -1);
    if (msend(message)) {
	LP_ERRMSG(ERROR, E_LP_MSEND);
	err_exit();
    }
    if ((type = mrecv(reply, 100)) == -1) {
	LP_ERRMSG(ERROR, E_LP_MRECV);
	err_exit();
    }
    if (type != R_END_CHANGE_REQUEST
	   || getmessage(reply, type, &status, &chkbits) == -1) {
	LP_ERRMSG1(ERROR, E_LP_BADREPLY, type);
	err_exit();
    }

    switch (status) {
    case MOK:
	return;
    case MNOPERM:
	LP_ERRMSG(ERROR, E_LP_NOTADM);
	break;
    case MNOSTART:
	LP_ERRMSG(ERROR, E_LPP_NOSTART);
	break;
    case MNODEST:
	LP_ERRMSG1(ERROR, E_LP_DSTUNK, rqp->destination);
	break;
    case MDENYDEST:
	if (chkbits) {
	    chkp = message;
		/* PCK_TYPE indicates a Terminfo error, and should */
		/* be handled as a ``get help'' problem.	   */
	    if (chkbits & PCK_TYPE) chkp += sprintf(chkp, "");
	    if (chkbits & PCK_CHARSET)
		chkp += sprintf(chkp, "-S character-set, ");
	    if (chkbits & PCK_CPI) chkp += sprintf(chkp, "-o cpi=, ");
	    if (chkbits & PCK_LPI) chkp += sprintf(chkp, "-o lpi=, ");
	    if (chkbits & PCK_WIDTH) chkp += sprintf(chkp, "-o width=, ");
	    if (chkbits & PCK_LENGTH) chkp += sprintf(chkp, "-o length=, ");
	    if (chkbits & PCK_BANNER) chkp += sprintf(chkp, "-o nobanner, ");
	    if (chkbits & PCK_PAPER)
		chkp += snprintf(chkp, sizeof (message) - (chkp - message),
			gettext("does not print on specified type of paper, "));

	    if (chkp - 2 >= message + sizeof (message))
		    message[sizeof(message) - 1] = 0;
	    else
		    chkp[-2] = 0;
	    LP_ERRMSG1(ERROR, E_LP_PTRCHK, message);
	}
	else LP_ERRMSG1(ERROR, E_LP_DENYDEST, rqp->destination);
	break;
    case MNOMEDIA:
	LP_ERRMSG(ERROR, E_LPP_NOMEDIA);
	break;
    case MDENYMEDIA:
	if (chkbits & PCK_CHARSET) LP_ERRMSG(ERROR, E_LPP_FORMCHARSET);
	else LP_ERRMSG1(ERROR, E_LPP_DENYMEDIA, rqp->form);
	break;
    case MNOMOUNT:
	LP_ERRMSG(ERROR, E_LPP_NOMOUNT);
	break;
    case MNOFILTER:
	LP_ERRMSG(ERROR, E_LP_NOFILTER);
	break;
    case MERRDEST:
	LP_ERRMSG1(ERROR, E_LP_REQDENY, rqp->destination);
	break;
    case MNOOPEN:
	LP_ERRMSG(ERROR, E_LPP_NOOPEN);
	break;
    default:
	LP_ERRMSG1(ERROR, E_LP_BADSTATUS, status);
    }
    err_exit();
}

/* getfile -- allocate the requested number of temp files */
static char *
getfiles(int number)
{
    int size, type;
    short status;
    char message[100],
	 reply[100],
	 *pfix;

    size = putmessage(message, S_ALLOC_FILES, number);
    assert(size != -1);
    if (msend(message)) {
	LP_ERRMSG(ERROR, E_LP_MSEND);
	err_exit();
    }
    if ((type = mrecv(reply, 100)) == -1) {
	LP_ERRMSG(ERROR, E_LP_MRECV);
	err_exit();
    }
    if (type != R_ALLOC_FILES
	   || getmessage(reply, type, &status, &pfix) == -1) {
	LP_ERRMSG1(ERROR, E_LP_BADREPLY, type);
	err_exit();
    }

    switch (status) {
    case MOK:
	return(strdup(pfix));
    case MOKREMOTE:
	clean_up();
	startup();
	return(NULL);
    case MNOMEM:
	LP_ERRMSG(ERROR, E_LP_NOSPACE);
	break;
    case MERRDEST:
	LP_ERRMSG(ERROR, E_LP_NOREQ);
	break;
    default:
	LP_ERRMSG1(ERROR, E_LP_BADSTATUS, status);
    }
    err_exit();
    /*NOTREACHED*/
    return (NULL);
}

static char *
que_job(REQUEST *rqp)
{
    int size, type;
    long chkbits;
    short status;
    char message[255],
	 reply[100],
	 *chkp,
	 *req_id;

    size = putmessage(message, S_PRINT_REQUEST, reqfile);
    assert(size != -1);
    if (msend(message)) {
	LP_ERRMSG(ERROR, E_LP_MSEND);
	err_exit();
    }
    if ((type = mrecv(reply, 100)) == -1) {
	LP_ERRMSG(ERROR, E_LP_MRECV);
	err_exit();
    }
    if (type != R_PRINT_REQUEST
	   || getmessage(reply, type, &status, &req_id, &chkbits) == -1) {
	LP_ERRMSG1(ERROR, E_LP_BADREPLY, type);
	err_exit();
    }

    switch (status) {
    case MOK:
	return(strdup(req_id));
    case MNOPERM:
	LP_ERRMSG(ERROR, E_LP_NOTADM);
	break;
    case MNODEST:
	LP_ERRMSG1(ERROR, E_LP_DSTUNK, rqp->destination);
	break;
    case MDENYDEST:
	if (chkbits) {
	    chkp = message;
		/* PCK_TYPE indicates a Terminfo error, and should */
		/* be handled as a ``get help'' problem.	   */
	    if (chkbits & PCK_TYPE) chkp += sprintf(chkp, "");
	    if (chkbits & PCK_CHARSET) chkp += sprintf(chkp, "-S character-set, ");
	    if (chkbits & PCK_CPI) chkp += sprintf(chkp, "-o cpi=, ");
	    if (chkbits & PCK_LPI) chkp += sprintf(chkp, "-o lpi=, ");
	    if (chkbits & PCK_WIDTH) chkp += sprintf(chkp, "-o width=, ");
	    if (chkbits & PCK_LENGTH) chkp += sprintf(chkp, "-o length=, ");
	    if (chkbits & PCK_BANNER) chkp += sprintf(chkp, "-o nobanner, ");
	    if (chkbits & PCK_PAPER)
		chkp += snprintf(chkp, sizeof (message) - (chkp - message),
			gettext("does not print on specified type of paper, "));

	    if (chkp - 2 >= message + sizeof (message))
		    message[sizeof(message) - 1] = 0;
	    else
		chkp[-2] = 0;
	    LP_ERRMSG1(ERROR, E_LP_PTRCHK, message);
	}
	else LP_ERRMSG1(ERROR, E_LP_DENYDEST, rqp->destination);
	break;
    case MNOMEDIA:
	LP_ERRMSG(ERROR, E_LPP_NOMEDIA);
	break;
    case MDENYMEDIA:
	if (chkbits & PCK_CHARSET) LP_ERRMSG(ERROR, E_LPP_FORMCHARSET);
	else LP_ERRMSG1(ERROR, E_LPP_DENYMEDIA, rqp->form);
	break;
    case MNOMOUNT:
	LP_ERRMSG(ERROR, E_LPP_NOMOUNT);
	break;
    case MNOFILTER:
	LP_ERRMSG(ERROR, E_LP_NOFILTER);
	break;
    case MERRDEST:
	LP_ERRMSG1(ERROR, E_LP_REQDENY, rqp->destination);
	break;
    case MNOOPEN:
	LP_ERRMSG(ERROR, E_LPP_NOOPEN);
	break;
    case MUNKNOWN:
	LP_ERRMSG(ERROR, E_LPP_ODDFILE);
	break;
    default:
	LP_ERRMSG1(ERROR, E_LP_BADSTATUS, status);
    }
    err_exit();
    /*NOTREACHED*/
    return (NULL);
}

/* ack_job -- issue request id message */
static void
ack_job()
{
    if(silent || pre_rqid) return;
    printf(gettext("request id is %s "), reqid);
    if (nfiles > 0) {
	if (stdinp > 0) {
	    printf(gettext(
			"(%d file(s) and standard input)\n"), nfiles);
	} else {
	    printf(gettext("(%d file(s))\n"), nfiles);
	}
    } else if (stdinp > 0) {
	printf(gettext("(standard input)\n"));
    } else
    	printf("\n");
}

/* savestd -- save standard input */
static void
savestd()
{
    copyfile(stdin, stdinfile);
    Stat(stdinfile, &stbuf);
    if(stbuf.st_size == 0) {
	if(nfiles == 0) {
	    LP_ERRMSG(ERROR, E_LP_NOFILES);
	    err_exit();
	} else	{/* inhibit printing of std input */
	    LP_ERRMSG1(WARNING, E_LP_EMPTY, "(standard input)");
	    stdinp = -1;
	}
    }
    else {	/* see if our non-zero size file is postscript	*/
	if (!Tflag && psfile(stdinfile)) {
		cont_type = POSTSCRIPT;
	}
    }
}

/* psfile():	Determine whether a file is postscript or not
 *	input:	char string of the filename
 *	ouput:	0 if the file isn't postscript,
 *		non-zero if it is.
 * Description:
 *	This routine looks to see if the "%!" characters are the first
 *	parts of the document (See PostScript Language Reference Manual,
 *	Second Edition - Adobe Systems Inc.; Appendix G - D.S.C. 3.0, p. 621).
 *
 *	This code has been blatently (and legally) ripped off from lpr,
 *	with only one apology: USL should've done this in the first place!!
 */

#define PSCOM   "%!"
#define PC_PSCOM   "\004%!"

static int
psfile(char *fname)
{
        int             fd;
        register int    ret = 0;
        char            buf[sizeof(PC_PSCOM)-1];

        if ((fd = open(fname, O_RDONLY)) >= 0 &&
            read(fd, buf, sizeof(buf)) == sizeof(buf) &&
            ((strncmp(buf, PSCOM, sizeof(PSCOM)-1) == 0) ||
             (strncmp(buf, PC_PSCOM, sizeof(PC_PSCOM)-1) == 0)))
                        ret++;
        (void)close(fd);
        return(ret);
}

/* arps():	autorecognize postscript files
 *	input:	REQUEST pointer.
 *	ouput:	none directly; the REQUEST pointer may be modified.
 *	description:
 *		this routine is called before the REQUEST structure
 *		is written to disk. the list of files to be printed is
 *		examined to see if all of the files are postscript. if
 *		they are, then the input_type field is changed to
 *		"postscript".
 *
 *		NOTE WELL - autorecognition is not done under the following
 *		conditions:
 *		1) The -T flag has been used.
 *		2) *Any* file in the file_list is *not* postscript. Right now,
 *			this is actually an ugly design decision. The request
 *			file specifies only one input_type for all of the files
 *			in the request. If any type isn't postscript, then
 *			input_type is unmodified, and the request will be
 *			treated as "simple". The reason for this is due
 *			to the design of the lp subsystem. What's need is
 *			to change the request handling to allow for multiple
 *			file types per request. However, this current
 *			implementation will fit in 100% with the original
 *			design of the lp subsystem.
 */
static void
arps(REQUEST * rqp)
{
	char **lfiles;
	int start = 0;
	int current;

	if (Tflag != 0) {
		return;
	}

	lfiles = rqp->file_list;
	start = psfile(*lfiles);

	for (lfiles++; (lfiles != NULL) && (*lfiles != NULL); lfiles++) {
		current = psfile(*lfiles);
		if (current != start) {
			return;
		}
	}

	if (start != 0) {	/* all the files are postscript	*/
		rqp->input_type = POSTSCRIPT;
	}
}
