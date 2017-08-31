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
 * Copyright 2017 Gary Mills
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#include <time.h>
#include "uucp.h"

#ifdef	V7
#define O_RDONLY	0
#endif
#define KILLMSG "the system administrator has killed job"
#define USAGE1	"[-q] | [-m] | [-k JOB [-n]] | [-r JOB [-n]] | [-p]"
#define USAGE2	"[-a] [-s SYSTEM [-j]] [-u USER] [-S STATE]"
#define USAGE3  "-t SYSTEM [-d number] [-c]"
#define LOCK "LCK.."
#define STST_MAX	132
#define MAXDATE		12
#define MINTIME		60
#define MINUTES		60
#define CHAR		"a"
#define MAXSTATE	4
/* #include "logs.h" */
struct m {
	char	mach[15];		/* machine name */
	char	locked;
	int	ccount, xcount;
	int	count, type;
	long	retrytime;
	time_t lasttime;
	short	c_age;			/* age of oldest C. file */
	short	x_age;			/* age of oldest X. file */
	char	stst[STST_MAX];
} M[UUSTAT_TBL+2];


struct userdate {
	char uhour[3];
	char umin[3];
	char lhour[3];
	char lmin[3];
};

struct userdate userformat;
struct userdate *friendlyptr = &userformat;	

extern long atol();
static int whattodo();
static int readperf();
static void queuetime();
static void xfertime();
static char * gmt();
static char * gmts();
static void errortn();
static void friendlytime();
static void complete();
static int state();
static int gnameflck();
static void kprocessC();
static int convert();
void uprocessC(), printit(), docalc(), procState();

static short State, Queued, Running, Complete, Interrupted;

static char mailmsg[BUFSIZ];
static char outbuf[BUFSIZ+1];
static int count;
static short jobcount;
static short execute;
static char lowerlimit[MAXDATE+1], upperlimit[MAXDATE+1];
static float totalque, totalxfer;
static long totaljob, totalbytes;
static long inputsecs;
#ifdef ATTSV
extern void qsort();		/* qsort(3) and comparison test */
#endif /* ATTSV */
int sortcnt = -1;
extern int machcmp();
extern int _age();		/* find the age of a file */
static long calcnum;	
extern char Jobid[];	/* jobid for status or kill option */
short Kill;		/*  == 1 if -k specified */
short Rejuvenate;	/*  == 1 for -r specified */
short Uopt;		/*  == 1 if -u option specified */
short Sysopt;		/*  == 1 if -s option specified */
static short Calctime;   /*  == 1 if -t parameter set */
short Summary;		/*  == 1 if -q or -m is specified */
short Queue;		/*  == 1 if -q option set - queue summary */
short Machines;		/*  == 1 if -m option set - machines summary */
short Psopt;		/*  == 1 if -p option set - output "ps" of LCK pids */
static short Window;    /*  == 1 if -d parameter set with -t option */
static short nonotf;    /*  == 1 if -n parameter set with -k option */
short avgqueue;		/*  == 1 if -c parameter set with -t option */
short avgxfer;		/*  will be set to 1 if -c not specified    */
short Jobcount;		/* == 1 if -j parameter set with -s option */
char f[NAMESIZE];

int
main(argc, argv, envp)
char *argv[];
char **envp;
{
	struct m *m, *machine();
	DIR *spooldir, *subdir, *machdir, *gradedir;
	char *str, *rindex();
	char subf[256], gradef[256];
	char *c, lckdir[BUFSIZ];
	char buf[BUFSIZ];
	char chkname[MAXFULLNAME];
	char *vec[7];
	int i, chkid;
	char fullpath[MAXFULLNAME];
	long temp;
	
	char arglist[MAXSTATE+1];

	/* Set locale environment variables local definitions */
	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it wasn't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	User[0] = '\0';
	Rmtname[0] = '\0';
	Jobid[0] = '\0';
	Psopt=Machines=Summary=Queue=Kill=Rejuvenate=Uopt=Sysopt=Jobcount=0;
	execute=avgqueue=avgxfer=Calctime=Window=0;
	jobcount=nonotf=0;

	/* set calcnum to default time in minutes */
	calcnum=MINTIME;

	(void) strcpy(Progname, "uustat");
	Uid = getuid();
	Euid = geteuid();
	guinfo(Uid, Loginuser);
	uucpname(Myname);
	while ((i = getopt(argc, argv, "acjk:mnpr:qs:u:x:t:d:S:")) != EOF) {
		switch(i){
		case 'a':
			Sysopt = 1;
			break;
		case 'c':
			avgqueue = 1;
			break;
		case 'd':
			Window = 1;
			calcnum = atoi(optarg);
			if (calcnum <= 0)
				calcnum = MINTIME;
			break;
		case 'k':
			(void) strncpy(Jobid, optarg, NAMESIZE);
			Jobid[NAMESIZE-1] = '\0';
			Kill = 1;
			break;
		case 'j':
			Jobcount = 1;
			break;
		case 'm':
			Machines = Summary = 1;
			break;
		case 'n':
			nonotf = 1;
			break;
		case 'p':
			Psopt = 1;
			break;
		case 'r':
			(void) strncpy(Jobid, optarg, NAMESIZE);
			Jobid[NAMESIZE-1] = '\0';
			Rejuvenate = 1;
			break;
		case 'q':
			Queue = Summary = 1;
			break;
		case 's':
			(void) strncpy(Rmtname, optarg, MAXBASENAME);

			Rmtname[MAXBASENAME] = '\0';
			if (versys(Rmtname)) {
				fprintf(stderr, gettext("Invalid system\n"));
				exit(1);
			}
			Sysopt = 1;
			break;
		case 't':
			Calctime = 1;
			(void) strncpy(Rmtname, optarg, MAXBASENAME);
			Rmtname[MAXBASENAME] = '\0';
			if (versys(Rmtname)) {
				fprintf(stderr, gettext("Invalid system\n"));
				exit(1);
			}
			break;
		case 'u':
			(void) strncpy(User, optarg, 8);
			User[8] = '\0';
			if(gninfo(User, &chkid, chkname)) {
				fprintf(stderr, gettext("Invalid user\n"));
				exit(1);
			}
			Uopt = 1;
			execute = 1;
			break;
		case 'x':
			Debug = atoi(optarg);
			if (Debug <= 0)
				Debug = 1;
			break;
		case 'S':
			if (strlen(optarg) > sizeof (arglist)) {
				errortn();
				exit(1);
			}
			State = 1;
			(void) strlcpy(arglist, optarg, sizeof (arglist));
			procState(arglist);
			break;
		default:
			errortn();		
			exit(1);
		}
	}

	if (argc != optind) {
		errortn();
		exit(1);
	}

	DEBUG(9, "Progname (%s): STARTED\n", Progname);
	DEBUG(9, "User=%s, ", User);
	DEBUG(9, "Loginuser=%s, ", Loginuser);
	DEBUG(9, "Jobid=%s, ", Jobid);
	DEBUG(9, "Rmtname=%s\n", Rmtname);

	/* -j only allowed with -s */
	if (Jobcount && !Sysopt)
		{
		errortn();
		exit(1);
		}
       if ((Calctime + Psopt + Machines + Queue + Kill + Rejuvenate + (Uopt|Sysopt |State)) >1) {
		/* only -u, -S and -s can be used together */
		errortn();
		exit(1);
	}
	if ((avgqueue | Window) & (!Calctime))
		{
		errortn();
		exit(1);
	}

	if (  !(Calctime | Kill | Rejuvenate | Uopt | Sysopt | Queue| Machines | State) ) {
		(void) strcpy(User, Loginuser);
		Uopt = 1;
	}

	if ( nonotf && !(Kill | Rejuvenate) ) {
		errortn();
		exit(1);
	}

	/*****************************************/
	/* PROCESS THE OPTIONS                   */
	/*****************************************/

	if (State && Complete)
		{
		   DEBUG(9, "calling complete %d\n",Complete);
		   complete();
		}
	
	if (Calctime) {
		count = readperf(calcnum);

		if (count != 0)
			docalc();
		
	}

	if (Psopt) {
		/* do "ps -flp" or pids in LCK files */
		lckpid();
		/* lckpid will not return */
	}

	if (Summary) {
	    /*   Gather data for Summary option report  */
	    if (chdir(STATDIR) || (spooldir = opendir(STATDIR)) == NULL)
		exit(101);		/* good old code 101 */
	    while (gnamef(spooldir, f) == TRUE) {
		if (freopen(f, "r", stdin) == NULL)
			continue;
		m = machine(f);
		if (fgets(buf, sizeof(buf), stdin) == NULL)
			continue;
		if (getargs(buf, vec, 5) < 5)
			continue;
		m->type = atoi(vec[0]);
		m->count = atoi(vec[1]);
		m->lasttime = atol(vec[2]);
		m->retrytime = atol(vec[3]);
		(void) strncpy(m->stst, vec[4], STST_MAX);
		str = rindex(m->stst, ' ');
		(void) machine(++str);	/* longer name? */
		*str = '\0';
			
	    }
	    closedir(spooldir);
	}


	if (Summary) {
	    /*  search for LCK machines  */
	    char flck[MAXNAMESIZE];

	    (void) strcpy(lckdir, LOCKPRE);
	    *strrchr(lckdir, '/') = '\0';
	    /* open lock directory */
	    if (chdir(lckdir) != 0 || (subdir = opendir(lckdir)) == NULL)
		exit(101);		/* good old code 101 */

	    while (gnameflck(subdir, flck) == TRUE) {
		/* XXX - this is disgusting... */
		if (EQUALSN("LCK..", flck, 5)) {
		    if (!EQUALSN(flck + 5, "cul", 3)
		     && !EQUALSN(flck + 5, "cua", 3)
		     && !EQUALSN(flck + 5, "tty", 3)
		     && !EQUALSN(flck + 5, "dtsw", 4)
		     && !EQUALSN(flck + 5, "vadic", 5)
		     && !EQUALSN(flck + 5, "micom", 5))
			machine(flck + 5)->locked++;
		}
	    }
	}

	if (chdir(SPOOL) != 0 || (spooldir = opendir(SPOOL)) == NULL)
		exit(101);		/* good old code 101 */

	while (gnamef(spooldir, f) == TRUE) {
	 /* at /var/spool/uucp directory */
	 /* f will contain remote machine names */
	   
          if (EQUALSN("LCK..", f, 5))
		continue;

          if (*Rmtname && !EQUALSN(Rmtname, f, MAXBASENAME))
		continue;

          if ( (Kill || Rejuvenate)
	      && (!EQUALSN(f, Jobid, strlen(Jobid)-5)) )
		    continue;

	  if (DIRECTORY(f))  {
		if (chdir(f) != 0)
			exit(101);
		(void) sprintf(fullpath, "%s/%s", SPOOL, f);
		machdir = opendir(fullpath);
		if (machdir == NULL)
			exit(101);
				
		m = machine(f);
		while (gnamef(machdir, gradef) == TRUE) {
			/* at /var/spool/uucp/remote_name */
			/* gradef will contain job_grade directory names */

	     		if (DIRECTORY(gradef) && (gradedir = opendir(gradef))) {
				/* at /var/spool/uucp/remote_name/job_grade */

		  		while (gnamef(gradedir, subf) == TRUE) {
				    /* subf will contain file names */
				    /* files can be C. or D. or A., etc.. */

				    if (subf[1] == '.') {
		  		      if (subf[0] == CMDPRE) {
					/* if file name is C. */
					m->ccount++;

					if (Kill || Rejuvenate)
					    kprocessC(gradef, subf);
					else if (Uopt | Sysopt | Queued | Running | Interrupted) 
				 	   /* go print out C. file info */
				  	   uprocessC(f ,gradef, subf);

					else 	/* get the age of the C. file */
				 	   if ( (i = _age(gradef, subf))>m->c_age)
						m->c_age = i;
					}
		    		    }
				}
				closedir(gradedir);
			}

			else if (gradef[0] == XQTPRE && gradef[1] == '.') {
			   m->xcount++;
			   if ( (i = _age(machdir, gradef)) > m->x_age)
				m->x_age = i;
			}
		}
		closedir(machdir);
	  }	
	  /* cd back to /var/spoool/uucp dir */
	  if (chdir(SPOOL) != 0)
		exit(101);	
	} /* while more files in spooldir */
	closedir(spooldir);

	if (Jobcount && (jobcount != 0))
		printf("job count = %d\n",jobcount);

	/* for Kill or Rejuvenate - will not get here unless it failed */
	if (Kill) {
	    printf(gettext("Can't find Job %s; Not killed\n"), Jobid);
	    exit(1);
	} else if (Rejuvenate) {
	    printf(gettext("Can't find Job %s; Not rejuvenated\n"), Jobid);
	    exit(1);
	}

	/* Make sure the overflow entry is null since it may be incorrect */
	M[UUSTAT_TBL].mach[0] = NULLCHAR;
	if (Summary) {
	    for((sortcnt = 0, m = &M[0]);*(m->mach) != NULL;(sortcnt++,m++))
			;
	    qsort((char *)M, (unsigned int)sortcnt, sizeof(struct m), machcmp);
	    for (m = M; m->mach[0] != NULLCHAR; m++)
		printit(m);
	}
	return (0);
}


/*
 * uprocessC - get information about C. file
 *
 */

void
uprocessC(machine, dir, file)
char   *machine, *dir, *file;
{
	struct stat s;
	struct tm *tp;
	char fullname[MAXFULLNAME], buf[BUFSIZ], user[9];
	char xfullname[MAXFULLNAME];
	char file1[BUFSIZ], file2[BUFSIZ], file3[BUFSIZ], type[2], opt[256];
	short goodRecord = 0;
	FILE *fp, *xfp;
	short first = 1;
	int statefound = 0;
	extern long fsize();
	char format_tmp[BUFSIZ+1];
	fp=xfp=NULL;

	/*********************************************/
	/* initialize output buffer to blanks        */
	/*********************************************/

	if (Complete && !Queued && !Running && !Interrupted)
		return;
	outbuf[0] = NULLCHAR;

	DEBUG(9, "uprocessC(%s, ", dir);
	DEBUG(9, "%s);\n", file);

	if (Jobid[0] != '\0' && (!EQUALS(Jobid, &file[2])) ) {
		/* kill job - not this one */
		return;
	}

	(void) sprintf(fullname, "%s/%s", dir, file);
	if (stat(fullname, &s) != 0) {
	     /* error - can't stat */
	    DEBUG(4, "Can't stat file (%s),", fullname);
	    DEBUG(4, " errno (%d) -- skip it!\n", errno);
	}

	fp = fopen(fullname, "r");
	if (fp == NULL) {
		DEBUG(4, "Can't open file (%s), ", fullname);
		DEBUG(4, "errno=%d -- skip it!\n", errno);
		return;
	}
	tp = localtime(&s.st_mtime);

	if (s.st_size == 0 && User[0] == '\0') { /* dummy D. for polling */
	    sprintf(format_tmp,"%-12s  %2.2d/%2.2d-%2.2d:%2.2d:%2.2d  (POLL)\n",
		&file[2], tp->tm_mon + 1, tp->tm_mday, tp->tm_hour,
		tp->tm_min, tp->tm_sec);
		(void) strcat(outbuf, format_tmp);
	}
	else while (fgets(buf, BUFSIZ, fp) != NULL) {
	    if (sscanf(buf,"%s%s%s%s%s%s", type, file1, file2,
	      user, opt, file3) <5) {
		DEBUG(4, "short line (%s)\n", buf);
		continue;
	    }
	    DEBUG(9, "type (%s), ", type);
	    DEBUG(9, "file1 (%s)", file1);
	    DEBUG(9, "file2 (%s)", file2);
	    DEBUG(9, "file3 (%s)", file3);
	    DEBUG(9, "user (%s)", user);

	    goodRecord = 0;

	    if (User[0] != '\0' && (!EQUALS(User, user)) ) 
		continue;


	    if (first)
	       {
	        sprintf(format_tmp,"%-12s", &file[2]);
		(void) strcat(outbuf, format_tmp);

		/* if the job state is requested call the
		   state function to determine this job's state */

		if (State)
		{ 
		   statefound = state(dir, file);		
	           DEBUG(9, "uprocessC: statefound value = %d\n", statefound);
 		   if ((whattodo(statefound) != TRUE))
			{
			   outbuf[0] = NULLCHAR;
			   return;
			}
		   else
			{
			   if (statefound == 1)
				(void) strcat(outbuf, "queued");
			   else if (statefound == 2)
				(void) strcat(outbuf, "running");
			   else if (statefound == 3)
				(void) strcat(outbuf, "interrupted");
			}
		}
		sprintf(format_tmp, " %2.2d/%2.2d-%2.2d:%2.2d ",
		    tp->tm_mon + 1, tp->tm_mday, tp->tm_hour,
		    tp->tm_min);
		(void) strcat(outbuf, format_tmp);
	       }
	    else
	       {
		sprintf(format_tmp,"%-12s %2.2d/%2.2d-%2.2d:%2.2d ",
		    "", tp->tm_mon + 1, tp->tm_mday, tp->tm_hour,
		    tp->tm_min);
		(void) strcat(outbuf, format_tmp);
		}
	    first = 0;

	    sprintf(format_tmp,"%s  %s  ", type, machine);
	    (void) strcat(outbuf, format_tmp);
	    if (*type == 'R')
	       {
	        sprintf(format_tmp,"%s  %s ", user, file1);
	        (void) strcat(outbuf, format_tmp);
	       }
	    else if (file2[0] != 'X')
		{
		 sprintf(format_tmp,"%s %ld %s ", user, fsize(dir, file3, file1), file1);
		 (void) strcat(outbuf, format_tmp);
		}
	    else if (*type == 'S' && file2[0] == 'X') {
		(void) sprintf(xfullname, "%s/%s", dir, file1);
		xfp = fopen(xfullname, "r");
		if (xfp == NULL) { /* program error */
		    DEBUG(4, "Can't read %s, ", xfullname);
		    DEBUG(4, "errno=%d -- skip it!\n", errno);
		    sprintf(format_tmp,"%s  ", user);
		    (void) strcat(outbuf, format_tmp);
		    (void) strcat(outbuf,"????\n");
		}
		else {
		    char command[BUFSIZ], uline_u[BUFSIZ], uline_m[BUFSIZ];
		    char retaddr[BUFSIZ], *username;

		    *retaddr = *uline_u = *uline_m = '\0';
		    while (fgets(buf, BUFSIZ, xfp) != NULL) {
			switch(buf[0]) {
			case 'C':
				strcpy(command, buf + 2);
				break;
			case 'U':
				sscanf(buf + 2, "%s%s", uline_u, uline_m);
				break;
			case 'R':
				sscanf(buf+2, "%s", retaddr);
				break;
			}
		    }
		    username = user;
		    if (*uline_u != '\0')
			    username = uline_u;
		    if (*retaddr != '\0')
			username = retaddr;
		    if (!EQUALS(uline_m, Myname))
			printf("%s!", uline_m);
		    sprintf(format_tmp,"%s  %s", username, command);
		    (void) strcat(outbuf, format_tmp);
		}
	    }
       	strcat(outbuf, "\n");
	fputs(outbuf, stdout);
        outbuf[0] = NULLCHAR;
	goodRecord = 1;
       } /* end of while more data in buffer */
	
       /* successful processing of a job, increment job count
	  counter */	
	if (goodRecord)
            jobcount++;

	if (xfp != NULL)
	    fclose(xfp);

	fclose(fp);
	return;
}
/*
 * whattodo - determine what to do with current C dot file
 *  	     depending on any combination (2**3 - 1) of input 
 *	     job states
 */
static int
whattodo(inputint)
int inputint;
{
	/* Maybe some commentary here will help explain this truth
	   table.

	Queued		|Running	|Interrupted
	-------------------------------------------------
		X	|		|
	-------------------------------------------------
			|	X	|
	-------------------------------------------------
			|		|      X
	-------------------------------------------------
		X	|	X	|
	-------------------------------------------------
			|	X	|      X
	-------------------------------------------------
		X	|		|      X
	-------------------------------------------------
		X	|	X	|      X
	-------------------------------------------------

	Now do you understand.  All  possible combinations have to
	be evaluated to determine whether or not to print the C dot
	information out or not! Well, all but 000, because if neither
	of these states are input by the user we would not be 
	examing the C dot file anyway!
	*/

	if (Queued && Running && Interrupted)
		return(TRUE);
	else if ((Queued && !Running && !Interrupted) && (inputint == 1))
		return(TRUE);
	else if ((Running && !Queued && !Interrupted) && (inputint == 2))				return(TRUE);
	else if ((Interrupted && !Queued && !Running) && (inputint == 3))				return(TRUE);
	else if ((Queued && Running && !Interrupted) && 
		(inputint == 1 || inputint == 2))
	  		return(TRUE);
	else if ((!Queued && Running && Interrupted) && 
		(inputint == 2 || inputint == 3))
			return(TRUE);
	else if ((Queued && !Running && Interrupted) && 
		(inputint ==1 || inputint == 3))
			return(TRUE);
	else return(FALSE);
}
/*
 * kprocessC - process kill or rejuvenate job
 */

static void
kprocessC(dir, file)
char *file, *dir;
{
	struct stat s;
	struct tm *tp;
	extern struct tm *localtime();
	char fullname[MAXFULLNAME], buf[BUFSIZ], user[9];
	char rfullname[MAXFULLNAME];
	char file1[BUFSIZ], file2[BUFSIZ], file3[BUFSIZ], type[2], opt[256];
	FILE *fp, *xfp;
 	struct utimbuf times;
	short ret;
	short first = 1;

	DEBUG(9, "kprocessC(%s, ", dir);
	DEBUG(9, "%s);\n", file);

	if ((!EQUALS(Jobid, &file[2])) ) {
		/* kill job - not this one */
		return;
	}

	(void) sprintf(fullname, "%s/%s", dir, file);
	if (stat(fullname, &s) != 0) {
	     /* error - can't stat */
	    if(Kill) {
		fprintf(stderr,
		  gettext("Can't stat:%s, errno (%d)--can't kill it!\n"),
		  fullname, errno);
	    } else {
		fprintf(stderr,
		  gettext("Can't stat:%s, errno (%d)--can't rejuvenate it!\n"),
		  fullname, errno);
	    }
	    exit(1);
	}

	fp = fopen(fullname, "r");
	if (fp == NULL) {
	    if(Kill) {
		fprintf(stderr,
		  gettext("Can't read:%s, errno (%d)--can't kill it!\n"),
		  fullname, errno);
	    } else {
		fprintf(stderr,
		  gettext("Can't read:%s, errno (%d)--can't rejuvenate it!\n"),
		  fullname, errno);
	    }
	    exit(1);
	}

 	times.actime = times.modtime = time((time_t *)NULL);
 
	while (fgets(buf, BUFSIZ, fp) != NULL) {
	    if (sscanf(buf,"%s%s%s%s%s%s", type, file1, file2,
	      user, opt, file3) <6) {
		if(Kill) {
		    fprintf(stderr,
		      gettext("Bad format:%s, errno (%d)--can't kill it!\n"),
		      fullname, errno);
		} else {
		    fprintf(stderr,
		      gettext("Bad format:%s, errno (%d)--can't rejuvenate it!\n"),
		      fullname, errno);
		}
	        exit(1);
	    }

	    DEBUG(9, "buf in uprocessK = %s\n ", buf);
	    DEBUG(9, "fullname is %s\n",fullname);
	    DEBUG(9, "type (%s), ", type);
	    DEBUG(9, "file1 (%s)", file1);
	    DEBUG(9, "file2 (%s)", file2);
	    DEBUG(9, "file3 (%s)", file3);
	    DEBUG(9, "user (%s)", user);


	    if (first) {
	        if ((access(fullname, 02) != 0)
		    && !PREFIX(Loginuser, user)
		    && !PREFIX(user, Loginuser) ) {
			/* not allowed - not owner or root */
			if(Kill)
			    fprintf(stderr, gettext("Not owner,"
			      " uucp or root - can't kill job %s\n"), Jobid);
			else
			    fprintf(stderr, gettext("Not owner, uucp or root -"
			      " can't rejuvenate job %s\n"), Jobid);
		    exit(1);
		}
		first = 0;
	    }

	    /* remove D. file */
	    (void) sprintf(rfullname, "%s/%s", dir, file3);
	    DEBUG(4, "Remove %s\n", rfullname);
	    if (Kill) 
		ret = unlink(rfullname);
	    else /* Rejuvenate */
 		ret = utime(rfullname, &times);
	    if (ret != 0 && errno != ENOENT) {
		/* program error?? */
		if(Kill)
		    fprintf(stderr, gettext("Error: Can't kill,"
		      " File (%s), errno (%d)\n"), rfullname, errno);
		else
		    fprintf(stderr, gettext("Error: Can't rejuvenated,"
		      " File (%s), errno (%d)\n"), rfullname, errno);
		exit(1);
	    }
	}

	DEBUG(4, "Remove %s\n", fullname);
	if (Kill)
	    ret = unlink(fullname);
	else /* Rejuvenate */
		ret = utime(fullname, &times);
	
	if (ret != 0) {
	    /* program error?? */
	    if(Kill)
	        fprintf(stderr, gettext("Error1: Can't kill,"
	          " File (%s), errno (%d)\n"), fullname, errno);
	    else
	        fprintf(stderr, gettext("Error1: Can't rejuvenate,"
	          " File (%s), errno (%d)\n"), fullname, errno);
	    exit(1);
	}
	/* if kill done by SA then send user mail */
	else if (!EQUALS(Loginuser, user))
	   {
		sprintf(mailmsg, "%s %s", KILLMSG, Jobid);
		mailst(user, "job killed", mailmsg, "", ""); 
	   }
	fclose(fp);
	if (!nonotf) {
		if(Kill)
			printf(gettext("Job: %s successfully killed\n"), Jobid);
		else
			printf(gettext("Job: %s successfully rejuvenated\n"),
			    Jobid);
		}
	exit(0);
}

/*
 * fsize - return the size of f1 or f2 (if f1 does not exist)
 *	f1 is the local name
 *
 */

long
fsize(dir, f1, f2)
char *dir, *f1, *f2;
{
	struct stat s;
	char fullname[BUFSIZ];

	(void) sprintf(fullname, "%s/%s", dir, f1);
	if (stat(fullname, &s) == 0) {
	    return(s.st_size);
	}
	if (stat(f2, &s) == 0) {
	    return(s.st_size);
	}

	return(-99999);
}

void cleanup(){}
void logent(){}		/* to load ulockf.c */
void systat(){}		/* to load utility.c */

struct m	*
machine(name)
char	*name;
{
	struct m *m;
	size_t	namelen;

	DEBUG(9, "machine(%s), ", name);
	namelen = strlen(name);
	for (m = M; m->mach[0] != NULLCHAR; m++)
		/* match on overlap? */
		if (EQUALSN(name, m->mach, MAXBASENAME)) {
			/* use longest name */
			if (namelen > strlen(m->mach))
				(void) strcpy(m->mach, name);
			return(m);
		}

	/*
	 * The table is set up with 2 extra entries
	 * When we go over by one, output error to errors log
	 * When more than one over, just reuse the previous entry
	 */
	DEBUG(9, "m-M=%d\n", m-M);
	if (m-M >= UUSTAT_TBL) {
	    if (m-M == UUSTAT_TBL) {
		errent("MACHINE TABLE FULL", "", UUSTAT_TBL,
		__FILE__, __LINE__);
		(void) fprintf(stderr,
		    gettext("WARNING: Table Overflow--output not complete\n"));
	    }
	    else
		/* use the last entry - overwrite it */
		m = &M[UUSTAT_TBL];
	}

	(void) strcpy(m->mach, name);
	m->c_age= m->x_age= m->lasttime= m->locked= m->ccount= m->xcount= 0;
	m->stst[0] = '\0';
	return(m);
}

void
printit(m)
struct m *m;
{
	struct tm *tp;
	time_t	t;
	int	minimum;
	extern struct tm *localtime();

	if (m->ccount == 0
	 && m->xcount == 0
	 /*&& m->stst[0] == '\0'*/
	 && m->locked == 0
	 && Queue
	 && m->type == 0)
		return;
	printf("%-10s", m->mach);
	if (Queue) {
		if (m->ccount)
			printf("%3dC", m->ccount);
		else
			printf("    ");
		if (m->c_age)
			printf("(%d)", m->c_age);
		else
			printf("   ");
		if (m->xcount)
			printf("%3dX", m->xcount);
		else
			printf("    ");
		if (m->x_age)
			printf("(%d) ", m->x_age);
		else
			printf("    ");
	} else
		printf(" ");

	if (m->lasttime) {
	    tp = localtime(&m->lasttime);
	    printf("%2.2d/%2.2d-%2.2d:%2.2d ",
		tp->tm_mon + 1, tp->tm_mday, tp->tm_hour,
		tp->tm_min);
	}
/*	if (m->locked && m->type != SS_INPROGRESS) */
	if (m->locked)
		printf("Locked ");
	if (m->stst[0] != '\0') {
		printf("%s", m->stst);
		switch (m->type) {
		case SS_SEQBAD:
		case SS_LOGIN_FAILED:
		case SS_DIAL_FAILED:
		case SS_BAD_LOG_MCH:
		case SS_BADSYSTEM:
		case SS_CANT_ACCESS_DEVICE:
		case SS_DEVICE_FAILED:
		case SS_WRONG_MCH:
		case SS_RLOCKED:
		case SS_RUNKNOWN:
		case SS_RLOGIN:
		case SS_UNKNOWN_RESPONSE:
		case SS_STARTUP:
		case SS_CHAT_FAILED:
			(void) time(&t);
			t = m->retrytime - (t - m->lasttime);
			if (t > 0) {
				minimum = (t + 59) / 60;
				printf("Retry: %d:%2.2d", minimum/60, minimum%60);
			}
			if (m->count > 1)
				printf(" Count: %d", m->count);
		}
	}
	putchar('\n');
	return;
}

#define MAXLOCKS 100	/* Maximum number of lock files this will handle */

int
lckpid()
{
    int i;
    int fd, ret;
    pid_t pid, list[MAXLOCKS];
    char alpid[SIZEOFPID+2];	/* +2 for '\n' and null */
    char buf[BUFSIZ], f[MAXNAMESIZE];
    char *c, lckdir[BUFSIZ];
    DIR *dir;

    DEBUG(9, "lckpid() - entered\n%s", "");
    for (i=0; i<MAXLOCKS; i++)
	list[i] = -1;
    (void) strcpy(lckdir, LOCKPRE);
    *strrchr(lckdir, '/') = '\0';
    DEBUG(9, "lockdir (%s)\n", lckdir);

    /* open lock directory */
    if (chdir(lckdir) != 0 || (dir = opendir(lckdir)) == NULL)
		exit(101);		/* good old code 101 */
    while (gnameflck(dir, f) == TRUE) {
	/* find all lock files */
	DEBUG(9, "f (%s)\n", f);
	if (EQUALSN("LCK.", f, 4) || EQUALSN("LK.", f, 3)) {
	    /* read LCK file */
	    fd = open(f, O_RDONLY);
	    printf("%s: ", f);
	    ret = read(fd, alpid, SIZEOFPID+2); /* +2 for '\n' and null */
	    pid = strtol(alpid, (char **) NULL, 10);
	    (void) close(fd);
	    if (ret != -1) {
		printf("%ld\n", (long) pid);
		for(i=0; i<MAXLOCKS; i++) {
		    if (list[i] == pid)
			break;
		    if (list[i] == -1) {
		        list[i] = pid;
		        break;
		    }
		}
	    }
	    else
		printf("????\n");
	}
    }
    fflush(stdout);
    *buf = NULLCHAR;
    for (i=0; i<MAXLOCKS; i++) {
	if( list[i] == -1)
		break;
	(void) sprintf(&buf[strlen(buf)], "%d ", list[i]);
    }

    if (i > 0)
#ifdef V7
	execl("/bin/ps", "uustat-ps", buf, (char *) 0);
#else
	execl("/usr/bin/ps", "ps", "-flp", buf, (char *) 0);
#endif
    exit(0);
}

/*
 * get next file name from lock directory
 *	p	 -> file description of directory file to read
 *	filename -> address of buffer to return filename in
 *		    must be of size NAMESIZE
 * returns:
 *	FALSE	-> end of directory read
 *	TRUE	-> returned name
 */
static int
gnameflck(p, filename)
char *filename;
DIR *p;
{
	struct dirent dentry;
	struct dirent *dp = &dentry;

	for (;;) {
		if ((dp = readdir(p)) == NULL)
			return(FALSE);
		if (dp->d_ino != 0 && dp->d_name[0] != '.')
			break;
	}

	(void) strncpy(filename, dp->d_name, MAXNAMESIZE-1);
	filename[MAXNAMESIZE-1] = '\0';
	return(TRUE);
}

int
machcmp(a,b)
char *a,*b;
{
	return(strcmp(((struct m *) a)->mach,((struct m *) b)->mach));
}

static long _sec_per_day = 86400L;

/*
 * _age - find the age of "file" in days
 * return:
 *	age of file
 *	0 - if stat fails
 */

int
_age(dir, file)
char * file;	/* the file name */
char * dir;	/* system spool directory */
{
	char fullname[MAXFULLNAME];
	static time_t ptime = 0;
	time_t time();
	struct stat stbuf;

	if (!ptime)
		(void) time(&ptime);
	(void) sprintf(fullname, "%s/%s", dir, file);
	if (stat(fullname, &stbuf) != -1) {
		return ((int)((ptime - stbuf.st_mtime)/_sec_per_day));
	}
	else
		return(0);
}
/* Function:  complete - find and print jobids of completed jobs for
 *		         user.
 *
 * Look thru the /var/uucp/.Admin/account file (if present)
 * for all jobs initiated by user and print.
 *
 * Parameters:	
 *
 *		Username - user that initiated uustat request
 *
 * Returns:
 *
 */
static void
complete()
{

	/* Function name: complete
	   Author:	  Roland T. Conwell
	   Date:	  July 31, 1986
	   Naration: This function will search through
		     /var/uucp/.Admin/account file
		     for all jobs submitted by User.  If User jobs are
		     found the state of 'completed' will be
		     printed on stdout. Module called by uustat main

	*/
char abuf[BUFSIZ];
FILE *fp;
char accno[15], jobid[15], system[15], loginame[15], time[20], dest[15];
char size[15];
char grade[2], jgrade[2];
char status[2];
int x;

fp = fopen(ACCOUNT, "r");
if (fp == NULL)
   {
	fprintf(stderr, gettext("Can't open account log\n"));
		return;
   }
while (fgets(abuf, BUFSIZ, fp) != NULL)
   {

	x = sscanf(abuf, "%s%s%s%s%s%s%s%s%s%s",
		accno,jobid, size, status, grade, jgrade, system, loginame,
		time, dest);
	if (x < 6)
		continue;

	if (!EQUALS(status, "C"))
		continue;

	DEBUG(9, "COMPLETE: accno = %s\n", accno);
	DEBUG(9, "COMPLETE: jobid = %s\n", jobid);
	DEBUG(9, "COMPLETE: size = %s\n", size);
	DEBUG(9, "COMPLETE: status = %s\n", status);
	DEBUG(9, "COMPLETE: grade = %s\n", grade);
	DEBUG(9, "COMPLETE: jgrade = %s\n", jgrade);
	DEBUG(9, "COMPLETE: system = %s\n", system);
	DEBUG(9, "COMPLETE: loginame = %s\n", loginame);
	DEBUG(9, "COMPLETE: time = %s\n", time);
	DEBUG(9, "COMPLETE: dest = %s\n", dest);

	if (*Rmtname && !EQUALS(Rmtname, dest))
		continue;
	if (*User && !EQUALS(User, loginame))
		continue;
	if (State && !Uopt)
	  {
	   if (EQUALS(Loginuser, loginame))
		{
			printf("%s completed\n",jobid);
			jobcount++;
		}
	  }
	else
	  {
		printf("%s completed\n", jobid);
		jobcount++;
	  }
   }
   fclose(fp);
   return;
}

/* Function: state - determine if Cdotfile is queued or running
 *
 * This function searches thru the directory jcdir for a Adotfile 
 * that matches the Cdotfile.  If found then look for a matching
 * lock file.  If a Adotfile and a lock file is found then the
 * job is in the running state.  If no Adotfile is found then the
 * job is in the queued state.  If a Adotfile is found and no
 * lock file is found then the job is queued.
 * 
 * Parameters:
 *
 *	jcdir    -   the job grade directory to search
 *	cdotfile -   the Cdotfile whose state is to be determined
 *
 * Returns: 
 *
 */
static int
state(jcdir, cdotfile)
char *jcdir, *cdotfile;
{
	short found, foundlck, CequalA;	
	char comparef[MAXBASENAME+1], afile[MAXBASENAME+1], cfile[MAXBASENAME+1];
	char lckfile[MAXBASENAME+1], lockname[MAXBASENAME+1];
	char lckdir[BUFSIZ+1];
	DIR *subjcdir, *sjcdir;
	int rtnstate = 0;
	foundlck = 0;
	CequalA = 0;
	sjcdir = opendir(jcdir);
	if (sjcdir == NULL)
		return (0);

	while (gnamef(sjcdir, comparef) == TRUE) {
	    if (comparef[0] == 'A') {

		(void) strcpy(afile, comparef);
		*strchr(afile, 'A') = ' ';
		(void) strcpy(cfile, cdotfile);
		*strchr(cfile, 'C') = ' ';

		if (EQUALS(cfile, afile)) {
	 	    /* now we have a C. and A. for same job */
	  	    /* check for LCK..machine.job_grade     */
		    /* if no LCK file at this point we will */
		    /* print the RUNNING state	        */
			CequalA = 1;

			(void) strcpy(lckdir, LOCKPRE);
			*strrchr(lckdir, '/') = '\0';
			/* open lock directory */
			
			subjcdir = opendir(lckdir);
			if (subjcdir == NULL)
			   exit(101); /* I know, I know! */
			(void) sprintf(lockname,"%s%s.%s",LOCK, f, jcdir);
			while (gnamef(subjcdir, lckfile) == TRUE)
			  {
			    DEBUG(9, "STATE: lockfile = %s\n",lckfile);
			    if (EQUALS(lockname, lckfile))
			          foundlck = 1;
			  }
			closedir(subjcdir);	

			}
		}	

	}

	closedir(sjcdir);
	/* got adot, cdot and lock file */

	if (Running && foundlck)
		rtnstate = 2;
	else if (Interrupted && CequalA && !foundlck)
		rtnstate = 3;
	else if (Queued && !CequalA && !foundlck)
		rtnstate = 1;
	DEBUG(9, "STATE: returning with value %d\n",rtnstate);
	return(rtnstate);

} /* end of state.c */



static int 
readperf(timerange)
long timerange;
{
	
	char proto[2], jc[2], role[2];
	char rectype[5],  time[MAXDATE+1], pid[10],wmachine[10];
	char remote[10],device[10], netid[20], jobid[20];
	static float queuetime, tat;
	static long size;
        struct tm tm_tmp;	
	time_t t_time, t_starttime, t_upperlimit;

	char options[10];
	static float rst, ust, kst, xferrate, utt, ktt;
	static float rtt, wfield, xfield, yfield;

	struct perfrec *recptr;
	static float tqt;
	static int jobs;
	char abuf[BUFSIZ];
	FILE *fp;
	static int x;
	char *strptr, *startime;
	int recordcnt;

	totalxfer=totalbytes=recordcnt=totaljob=totalque=0;
	lowerlimit[0] = '\0';
	upperlimit[0] = '\0';
	
 
	inputsecs = convert(timerange);
	startime = gmts();
	strncpy(lowerlimit, startime, MAXDATE);
	strncpy(upperlimit, gmt(), MAXDATE);

	/* convert lowerlimit and upperlimit to HH:MM format */
	friendlytime(lowerlimit, upperlimit);

	fp = fopen(PERFLOG, "r");
	if (fp == NULL)
 	  {
		(void) fprintf(stderr, gettext("Can't open performance log\n"));
			return(0);
	   }


	while (fgets(abuf, BUFSIZ, fp) != NULL)
	  {
	    DEBUG(9, "READPERF: abuf before = %s\n",abuf);

	    if (!EQUALSN(abuf, "xfer", 4))
		continue;

            /* convert all '|'s to blanks for sscanf */
	    for (strptr = abuf; *strptr != '\0'; strptr++)
		if (*strptr == '|')
		    *strptr = ' ';
	    DEBUG(9, "READPERF: abuf = %s\n",abuf);

	    x = sscanf(abuf, "%s%*s%s%s%s%s%s%s%*s%s%s%f%f%ld%s%f%f%f%f%f%f%f%f%f%*s", 
		rectype, time, pid, wmachine, role, remote, device, netid,
		jobid, &queuetime, &tat, &size, options, &rst,
		&ust, &kst, &xferrate, &utt, &ktt, &rtt, &wfield,
		&xfield);

		DEBUG(9, "READPERF: rectype = %s\n",rectype);
		DEBUG(9, "READPERF: time = %s\n",time);
		DEBUG(9, "READPERF: pid = %s\n",pid);
		DEBUG(9, "READPERF: remote = %s\n",remote);
		DEBUG(9, "READPERF: jobid = %s\n",jobid);
		DEBUG(9, "READPERF: queuetime = %f\n",queuetime);
		DEBUG(9, "READPERF: tat = %f\n",tat);
		DEBUG(9, "READPERF: xferrate = %f\n",xferrate);

		abuf[0] = '\0';
		
		if (!EQUALS(Rmtname, remote))
			continue;

		if (!EQUALS(role, "M"))
			continue;

		if (x < 18)
			continue;

		DEBUG(9, "READPERF: startime = %s\n", startime);
		DEBUG(9, "READPERF: lowerlimit = %s\n", lowerlimit);
		DEBUG(9, "READPERF: time = %s\n", time);
		DEBUG(9, "READPERF: upperlimit = %s\n", upperlimit);

		strptime(time, "%y %m %d %H %M %S", &tm_tmp);
		t_time = mktime(&tm_tmp);
		strptime(startime, "%y %m %d %H %M %S", &tm_tmp);
		t_starttime = mktime(&tm_tmp);
		strptime(upperlimit, "%y %m %d %H %M %S", &tm_tmp);
		t_upperlimit = mktime(&tm_tmp);

		DEBUG(9, "READPERF: t_time = %d\n", t_time);
		DEBUG(9, "READPERF: t_starttime = %d\n", t_starttime);
		DEBUG(9, "READPERF: t_upperlimit = %d\n", t_upperlimit);
		if (t_starttime <= t_time && t_upperlimit >= t_time)
		{
			totaljob++;	
			totalque = totalque + queuetime;
			totalxfer = totalxfer + xferrate;
			totalbytes = totalbytes + size;
			recordcnt = recordcnt + 1;
		DEBUG(9, "  processing recordcnt %d\n", recordcnt);
		}
	DEBUG(9, "END step 1 %d\n", recordcnt);
  	 } /* while */
	DEBUG(9, "END step 2 recordcnt %d\n", recordcnt);

	fclose(fp);
	return(recordcnt);


} /* end of readperf */

void
docalc()
{
   if (avgqueue)
	queuetime();
   else
	xfertime();
   return;
}

static int
convert(intime)
long intime;
{
	long outtime;

	outtime = intime * 60;
	return(outtime);

}
static void
queuetime()
{
 	static double avgqtime;

	avgqtime = totalque / totaljob;

	printf("average queue time to [%s] for last [%ld] minutes:  %6.2f seconds\n",Rmtname, calcnum, avgqtime);
 	 printf("data gathered from %s:%s to %s:%s GMT\n", friendlyptr->uhour, friendlyptr->umin, friendlyptr->lhour, friendlyptr->lmin);
	return;
}


static void
xfertime()
{
         static double avgxrate;

	avgxrate = totalbytes / totalxfer;

	printf("average transfer rate with [ %s ] for last [%ld] minutes: %6.2f bytes/sec\n", Rmtname, calcnum, avgxrate);
 	 printf("data gathered from %s:%s to %s:%s GMT\n", friendlyptr->uhour, friendlyptr->umin, friendlyptr->lhour, friendlyptr->lmin);
	return;
}

/*
 * Local Function:	gmts - Generate Start Time String
 *
 * This function returns the address to a string containing the start
 * time, or upperlimit, for searching the PERFLOG.
 * The start time is in GMT in the form YYMMDDhhmmss.
 *
 * Parameters:
 *
 *	none
 *
 * Return:
 *
 *	An address of a static character array containing the date.
 */

static char *
gmts()
{
	static char	date[] = "YYMMDDhhmmss";

	struct tm 		*td;
	time_t			now;	/* Current time. */
	time_t			temp;
	now = time((time_t *) 0);

	/* inputsecs is declared global to this file */
	DEBUG(9, "GMTS: now = %ld\n", now);
	DEBUG(9, "GMTS: inputsecs = %ld\n", inputsecs);

	temp = (now - inputsecs);
	td = gmtime(&temp);
	(void) sprintf(date, "%02d%02d%02d%02d%02d%02d",
				(td->tm_year % 100),
				td->tm_mon + 1,
				td->tm_mday,
				td->tm_hour,
				td->tm_min,
				td->tm_sec
		      );
	return date;
}

/*
 * Local Function:	gmt - Generate Current Time String
 *
 * This function returns the address to a string containing the current
 * GMT in the form YYMMDDhhmmss.
 *
 * Parameters:
 *
 *	none
 *
 * Return:
 *
 *	An address of a static character array containing the date.
 */

static char *
gmt()
{
	static char	date[] = "YYMMDDhhmmss";

	struct tm	*td;
	time_t			now;	/* Current time. */

	now = time((time_t *) 0);
	td = gmtime(&now);
	(void) sprintf(date, "%02d%02d%02d%02d%02d%02d",
				(td->tm_year % 100),
				td->tm_mon + 1,
				td->tm_mday,
				td->tm_hour,
				td->tm_min,
				td->tm_sec
		      );
	return date;
}

static void
friendlytime(uplimit, lolimit)
char *uplimit, *lolimit;
{

	friendlyptr->uhour[0] = *(uplimit+6);
	friendlyptr->uhour[1] = *(uplimit+7);
	friendlyptr->lhour[0] = *(lolimit+6);
	friendlyptr->lhour[1] = *(lolimit+7);
	friendlyptr->umin[0]  = *(uplimit+8);
	friendlyptr->umin[1]  = *(uplimit+9);
	friendlyptr->lmin[0]  = *(lolimit+8);
	friendlyptr->lmin[1]  = *(lolimit+9);

	friendlyptr->uhour[2] = '\0';
	friendlyptr->lhour[2] = '\0';
	friendlyptr->umin[2] = '\0';
	friendlyptr->lmin[2] = '\0';
	return;
}

void
procState(inputargs)
char * inputargs;
{
	if (strchr(inputargs, 'q') != NULL)
		Queued = 1;
	if (strchr(inputargs, 'r') != NULL)
		Running = 1;
	if (strchr(inputargs, 'i') != NULL)
		Interrupted = 1;
	if (strchr(inputargs, 'c') != NULL)
		Complete = 1;

	if ((size_t)(Queued + Running + Interrupted + Complete) < strlen(inputargs))
		{
			errortn();
			exit(1);
		}
	return;
}

static void
errortn()
{


	(void) fprintf(stderr, gettext("\tUsage: %s " USAGE1 "\n"),
	    Progname);
	(void) fprintf(stderr, gettext("or\n\tUsage: %s " USAGE2 "\n"),
	    Progname);
	(void) fprintf(stderr, gettext("or\n\tUsage: %s " USAGE3 "\n"),
	    Progname);
	return;
}
