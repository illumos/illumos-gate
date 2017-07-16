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
 * Copyright 2014 Garrett D'Amore
 */
/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Network Listener Process
 *
 *		command line:
 *
 *		listen [ -m minor_prefix ] netspec
 *
 */

/* system include files	*/

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <memory.h>
#include <sys/utsname.h>
#include <sys/tiuser.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mkdev.h>
#include <values.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include <sys/ipc.h>
#include <sys/poll.h>
#include <sys/stropts.h>
#include <sac.h>
#include <utmpx.h>

/* listener include files */

#include "lsparam.h"		/* listener parameters		*/
#include "lsfiles.h"		/* listener files info		*/
#include "lserror.h"		/* listener error codes		*/
#include "lsnlsmsg.h"		/* NLPS listener protocol	*/
#include "lssmbmsg.h"		/* MS_NET identifier		*/
#include "lsdbf.h"		/* data base file stuff		*/
#include "listen.h"

/* defines	*/

#define NAMESIZE	(NAMEBUFSZ-1)

#define SPLhi()		Splflag = 1
#define SPLlo()		Splflag = 0

#define GEN	1
#define LOGIN	0

/* global variables	*/

int	NLPS_proc = 0;	/* set if process is a listener child		*/
pid_t	Pid;		/* listener's process ID 			*/
char	*Progname;	/* listener's basename (from argv[0])		*/
static	char Provbuf[PATHSIZE];
char	*Provider = Provbuf;	/* name of transport provider		*/
char	*Netspec = NETSPEC;
char	*Minor_prefix;		/* prefix for minor device names	*/
int	Dbf_entries;		/* number of private addresses in dbf file*/
int	Valid_addrs;		/* number of addresses bound		*/
struct	pollfd *Pollfds;	/* for polling fds			*/
dbf_t	*Dbfhead;		/* Beginning of in-memory database	*/
dbf_t	*Newdbf;		/* Beginning of in-memory database (reread) */
char	*Server_cmd_lines;	/* database space			*/
char	*New_cmd_lines;		/* database space (reread) 		*/
long	Ndesc;			/* Number of per-process file descriptors */
int	Readdb;			/* set to TRUE by SAC_READDB message	*/
struct	netconfig *Netconf;	/* netconfig structure for this network	*/

struct	call_list	Free_call;
struct	call_list	*Free_call_p = &Free_call; /* call free list 	*/
struct	call_list	*Priv_call;	/* call save pending list 	*/

/* FILE DESCRIPTOR MANAGEMENT:
 *
 * The listener uses 6 (sometimes 7) file descriptors:
 *	fd 0:	Originally opened to /dev/null, used to accept incoming calls.
 *	fd 1:	In the parent, a connection to _sacpipe.  Closed in the child
 *		and dup'ed to 0.
 *	fd 2:	In the parent, a connection to _pmpipe.  Dup'ed in the child
 *		to 0.
 *	fd 3:	Originally opened to /dev/null, this file descriptor is 
 *		reserved to open the STREAMS pipe when passing the connection
 *		to a standing server.
 *	fd 4:	Opened to the pid file.  We have to keep it open to keep the
 *		lock active.
 *	fd 5:	Opened to the log file.
 *	fd 6:	Opened to the debug file ONLY when compiled with DEBUGMODE.
 *
 * The remaining file descriptors are available for binding private addresses.
 */

#ifndef DEBUGMODE
#define USEDFDS	6
#else
#define	USEDFDS	7
FILE	*Debugfp;		/* for the debugging file	*/
#endif

int	Acceptfd;		/* to accept connections (fd 0)	*/
int	Sacpipefd;		/* pipe TO sac process (fd 1)	*/
int	Pmpipefd;		/* pipe FROM sac process (fd 2) */
int	Passfd;			/* pipe used to pass FD (fd 3)	*/
int	Pidfd;			/* locked pid file (fd 4)	*/
FILE	*Logfp;			/* for logging listener activity*/

struct	pmmsg	Pmmsg;		/* to respond to SAC		*/
int	State = PM_STARTING;	/* current SAC state		*/
char	Mytag[15];

char	Lastmsg[BUFSIZ];	/* contains last msg logged (by stampbuf) */
int	Logmax = LOGMAX;	/* number of entriet to allow in logfile  */

int	Splflag;		/* logfile critical region flag		  */

static char *badnspmsg = "Bad netspec on command line ( Pathname too long )";
static char *badstart  = "Listener failed to start properly";
static char *nologfile = "Unable to open listener log file during initialization";
static char *usage     = "Usage: listen [ -m minor_prefix ] network_device";
static char *nopmtag   = "Fatal error: Unable to get PMTAG from environment";
static char tzenv[BUFSIZ];

#define TZFILE	"/etc/default/init"
#define TZSTR	"TZ="

void	check_sac_mesg();	/* routine to process messages from sac */
void	rpc_register();		/* routine to register rpc services */
void	rpc_unregister();	/* routine to unregister rpc services */
extern	struct	netconfig	*getnetconfigent();
extern	char	*t_alloc();
extern	void	logexit();
extern	int	t_errno;
extern	int	errno;

#ifndef TRUE
#define	TRUE	1
#define FALSE	0
#endif

static void mod_prvaddr(void);
static void pitchcall(struct call_list *pending, struct t_discon *discon);
static void clr_call(struct t_call *call);
static void trycon(struct call_list *phead, int fd);
static void send_dis(struct call_list *phead, int fd);
static void doevent(struct call_list *phead, int fd);
static void listen(void);
static void rst_signals(void);
static void catch_signals(void);
static void net_open(void);
static void init_files(void);
static void pid_open(void);

int
main(int argc, char **argv)
{
	struct stat buf;
	int ret;
	char scratch[BUFSIZ];
	char log[BUFSIZ];
	char olog[BUFSIZ];
	char *scratch_p = scratch;
	char *mytag_p;
	FILE *fp;
	extern char *getenv();
	char *parse();
	int	c;
	extern	char *optarg;
	extern	int optind;
	int i;
	char	*Mytag_p = Mytag;

	/* Get my port monitor tag out of the environment		*/
	if ((mytag_p = getenv("PMTAG")) == NULL) {
		/* no place to write */
		exit(1);
	}
	strcpy(Mytag, mytag_p);

	/* open log file */
	sprintf(log, "%s/%s/%s", ALTDIR, Mytag_p, LOGNAME);
	sprintf(olog, "%s/%s/%s", ALTDIR, Mytag_p, OLOGNAME);
	if (stat(log, &buf) == 0) {
		/* file exists, try and save it but if we can't don't worry */
		unlink(olog);
		rename(log, olog);
	}
	if ((i = open(log, O_WRONLY|O_CREAT|O_APPEND, 0444)) < 0)
		logexit(1, nologfile);
	/* as stated above, the log file should be file descriptor 5 */
	if ((ret = fcntl(i, F_DUPFD, 5)) != 5)
		logexit(1, nologfile);
	Logfp = fdopen(ret, "a+");

	/* Get my port monitor tag out of the environment		*/
	if ((mytag_p = getenv("PMTAG")) == NULL) {
		logexit(1, nopmtag);
	}
	strcpy(Mytag, mytag_p);

	(void) umask(022);
	Readdb = FALSE;

	if (geteuid() != (uid_t) 0) {
		logmessage("Must be root to start listener");
		logexit(1, badstart);
	}

	while ((c = getopt(argc, argv, "m:")) != EOF) 
		switch (c) {
		case 'm':
			Minor_prefix = optarg;
			break;
		default:
			logexit(1, usage);
			break;
		}

	if ((Netspec = argv[optind]) == NULL) {
		logexit(1, usage);
	}
	if ((Netconf = getnetconfigent(Netspec)) == NULL) {
		sprintf(scratch, "no netconfig entry for <%s>", Netspec);
		logmessage(scratch);
		logexit(1, badstart);
	}
	if (!Minor_prefix)
		Minor_prefix = argv[optind];

	if ((int) strlen(Netspec) > PATHSIZE)  {
		logmessage(badnspmsg);
		logexit(1, badstart);
	}

	/* 
	 * SAC will start the listener in the correct directory, so we
	 * don't need to chdir there, as we did in older versions
	 */

	strcpy(Provbuf, "/dev/");
	strcat(Provbuf, Netspec);

	(void) umask(0);

	init_files();		/* open Accept, Sac, Pm, Pass files	*/
	pid_open();		/* create pid file			*/

#ifdef	DEBUGMODE
	sprintf(scratch, "%s/%s/%s", ALTDIR, Mytag, DBGNAME);
	Debugfp = fopen(scratch, "w");
#endif


#ifdef	DEBUGMODE
	if ((!Logfp) || (!Debugfp)) 
#else
	if (!Logfp)
#endif
		logexit(1, badstart);

/*
 * In case we started with no environment, find out what timezone we're
 * in.  This will get passed to children, so only need to do once.
 */

	if (getenv("TZ") == NULL) {
		fp = fopen(TZFILE, "r");
		if (fp) {
			while (fgets(tzenv, BUFSIZ, fp)) {
				if (tzenv[strlen(tzenv) - 1] == '\n')
					tzenv[strlen(tzenv) - 1] = '\0';
				if (!strncmp(TZSTR, tzenv, strlen(TZSTR))) {
					putenv(parse(tzenv));
					break;
				}
			}
			fclose(fp);
		}
		else {
			sprintf(scratch, "couldn't open %s, default to GMT",
			    TZFILE);
			logmessage(scratch);
		}
	}

	logmessage("@(#)listen:listen.c	1.19.9.1");

#ifdef	DEBUGMODE
	logmessage("Listener process with DEBUG capability");
#endif

	sprintf(scratch, "Listener port monitor tag: %s", Mytag_p);
	logmessage(scratch);
	DEBUG((9, "Minor prefix: %s  Netspec %s", Minor_prefix, Netspec));

	/* fill in Pmmesg fields that always stay the same */

	Pmmsg.pm_maxclass = MAXCLASS;
	strcpy(Pmmsg.pm_tag, Mytag_p);
	Pmmsg.pm_size = 0;

	/* Find out what state to start in.  If not in env, exit */
	if ((scratch_p = getenv("ISTATE")) == NULL)
		logexit(1, "ERROR: ISTATE variable not set in environment");
	
	if (!strcmp(scratch_p, "enabled")) {
		State = PM_ENABLED;
		logmessage("Starting state: ENABLED");
	}
	else {
		State = PM_DISABLED;
		logmessage("Starting state: DISABLED");
	}

	/* try to get my "basename"		*/
	Progname = strrchr(argv[0], '/');
	if (Progname && Progname[1])
		++Progname;
	else
		Progname = argv[0];

	catch_signals();

	/* 
	 * Allocate memory for private address and file descriptor table 
	 * Here we are assuming that no matter how many private addresses
	 * exist in the system if the system limit is 20 then we will only
	 * get 20 file descriptors
	 */

	Ndesc = ulimit(4,0L);		/* get num of file des on system */

	read_dbf(DB_INIT);
	net_open();			/* init, open, bind names 	*/

	for (i = 3; i < Ndesc; i++)  {	/* leave stdout, stderr open	*/
		fcntl(i, F_SETFD, 1);	/* set close on exec flag*/
	}

	logmessage("Initialization Complete");

	listen();
	return (0);
}


/*
 * pid_open:
 *
 * open pidfile with specified oflags and modes and lock it
 *
 */

static char *pidopenmsg ="Can't create process ID file in home directory";
static char *pidlockmsg ="Can't lock PID file: listener may already be running";

static void
pid_open(void)
{
	int ret;
	unsigned int i;
	char pidstring[20];

	if ((Pidfd = open(PIDNAME, PIDOFLAG, PIDMODE)) == -1)  {
		logmessage(pidopenmsg);
		error(E_CREAT, EXIT | NOCORE | NO_MSG);
	}

	if (lockf(Pidfd, 2, 0L) == -1)  {
		logmessage(pidlockmsg);
		logexit(1, badstart);
	}

	Pid = getpid();
	i = sprintf(pidstring, "%ld", Pid) + 1;
	ftruncate(Pidfd, 0);

	while ((ret = write(Pidfd, pidstring, i)) != i) {
		if (errno == EINTR)
			continue;
		if (ret < 0)
			sys_error(E_PIDWRITE, EXIT);
		else
			error(E_PIDWRITE, EXIT);
	}

}

/*
 * init_files: open initial files for the listener (see FILE DESC MGMT comment)
 */

static char *pmopenmsg = "Can't open pipe to read SAC messages";
static char *sacopenmsg = "Can't open pipe to respond to SAC messages";

static void
init_files(void)
{
	close(0);
        if ((Acceptfd = open("/dev/null", O_RDWR)) != 0) {
		logmessage("Trouble opening /dev/null");
                sys_error(E_SYS_ERROR, EXIT | NOCORE);
	}

	close(1);
	if ((Sacpipefd = open(SACPIPE, O_RDWR|O_NDELAY)) != 1) {
		logmessage(sacopenmsg);
		error(E_CREAT, EXIT | NOCORE | NO_MSG);
	}

	close(2);
	if ((Pmpipefd = open(PMPIPE, O_RDWR|O_NDELAY)) != 2) {
		logmessage(pmopenmsg);
		error(E_CREAT, EXIT | NOCORE | NO_MSG);
	}

	close(3);
	if ((Passfd = dup(Acceptfd)) != 3) {
		logmessage("Trouble duping /dev/null");
                sys_error(E_SYS_ERROR, EXIT | NOCORE);
	}

}
		

/*
 * net_open: open and bind communications channels
 *		The name generation code in net_open, open_bind and bind is, 
 * 		for the	most part, specific to STARLAN NETWORK.  
 *		This name generation code is included in the listener
 *		as a developer debugging aid.
 */

static void
net_open(void)
{
#ifdef	CHARADDR
	char pbuf[NAMEBUFSZ + 1];
#endif	/* CHARADDR	*/
	int i;
	dbf_t *dp;
	char scratch[BUFSIZ];

	DEBUG((9,"in net_open"));

	/* set up free call list and pending connection lists */

	Free_call_p->cl_head = (struct callsave *) NULL;
	Free_call_p->cl_tail = (struct callsave *) NULL;

	/* Pending calls are linked in a structure, one per fild descriptor */
	if ((Priv_call = (struct call_list *) malloc(Ndesc *(sizeof(
				struct call_list)))) == NULL)  
		error(E_MALLOC,NOCORE | EXIT);

	i = 0;
	Valid_addrs = 0;
	/* first do static addrs */
	while ( (i < Dbf_entries) ) {
		dp = &Dbfhead[i];
		if (!(dp->dbf_sflags & DFLAG)) {
			if (add_prvaddr(dp) == 0)
				Valid_addrs++;
		}
		i++;
	}
	i = 0;
	/* second pass for dynamic addrs */
	while ( (i < Dbf_entries) ) {
		dp = &Dbfhead[i];
		if (dp->dbf_sflags & DFLAG) {
			if (add_prvaddr(dp) == 0)
				Valid_addrs++;
		}
		i++;
	}

	sprintf(scratch, "Net opened, %d %s bound, %d fds free", Valid_addrs, 
		(Valid_addrs == 1) ? "address" : "addresses",
		Ndesc-Valid_addrs-USEDFDS);
	logmessage(scratch);
}


/*
 * Following are some general queueing routines.  The call list head contains
 * a pointer to the head of the queue and to the tail of the queue.  Normally,
 * calls are added to the tail and removed from the head to ensure they are
 * processed in the order received, however, because of the possible interruption
 * of an acceptance with the resulting requeueing, it is necessary to have a
 * way to do a "priority queueing" which inserts at the head of the queue for
 * immediate processing
 */

/*
 * queue:
 *
 * add calls to tail of queue
 */


void
queue(head, cp)
struct call_list *head;
struct callsave *cp;
{
	DEBUG((9,"in queue"));
	if (head->cl_tail == (struct callsave *) NULL) {
		cp->c_np = (struct callsave *) NULL;
		head->cl_head = head->cl_tail = cp;
	}
	else {
		cp->c_np = head->cl_tail->c_np;
		head->cl_tail->c_np = cp;
		head->cl_tail = cp;
	}
}


/*
 * pqueue:
 *
 * priority queuer, add calls to head of queue
 */

void
pqueue(head, cp)
struct call_list *head;
struct callsave *cp;
{
	if (head->cl_head == (struct callsave *) NULL) {
		cp->c_np = (struct callsave *) NULL;
		head->cl_head = head->cl_tail = cp;
	}
	else {
		cp->c_np = head->cl_head;
		head->cl_head = cp;
	}
}


/*
 * dequeue:
 *
 * remove a call from the head of queue
 */


struct callsave *
dequeue(head)
struct call_list *head;
{
	struct callsave *ret;

	DEBUG((9,"in dequeue"));
	if (head->cl_head == (struct callsave *) NULL)  {
#ifdef OLD
		DEBUG((9,"cl_head = null"));
		error(E_CANT_HAPPEN, EXIT);
#endif
		DEBUG((9, "NULL return"));
		return((struct callsave *) NULL);
	}
	ret = head->cl_head;
	head->cl_head = ret->c_np;
	if (head->cl_head == (struct callsave *) NULL)
		head->cl_tail = (struct callsave *) NULL;
	return(ret);
}


/*
 * open_bind:
 *
 * open the network and bind the endpoint to 'name'
 * this routine is also used by listen(), so it can't exit
 * under all error conditions: 
 *	if there are no minor devices avaliable in the network driver, 
 * 		open_bind returns -1.  (error message will be logged).
 *	if the open fails because all file descriptors are in use, 
 *		open_bind returns -2.  (no message logged).  This should 
 *		only happen when too many private addresses are specified.
 *	if the bind fails, open_bind returns -3  (no message logged).  This
 *		happens when a duplicate address is bound, and the message
 *		should be logged by the routine that calls open_bind.
 * All other errors cause an exit.
 *
 * If clen is zero, transport provider picks the name and these
 * routines (open_bind and bind) ignore name and qlen -- 
 * this option is used when binding a name for accepting a connection 
 * (not for listening.)  You MUST supply a name, qlen and clen when
 * opening/binding a name for listening.
 *
 * Assumptions: driver returns ENXIO when all devices are allocated.
 */

int
open_bind(name, qlen, clen, conp, adrp)
char *name;
int qlen;
int clen;
unsigned int *conp;
char **adrp;
{
	int fd;
	int ret;

	DEBUG((9,"in open_bind, qlen=%d clen=%d conp=%d",qlen,clen,conp));
	while ((fd = t_open(Provider, NETOFLAG, NULL)) < 0) {
		if (t_errno == TSYSERR) {
			switch (errno) {
			case EINTR:
				continue;
			case EMFILE:
				return(-2);
				break;
			case ENXIO:
			case ENOSR:
			case ENOSPC:
			case EAGAIN:
				tli_error(E_FD1OPEN, CONTINUE);
				logmessage("No network minor devices (ENXIO/ENOSR)");
				return(-1);
				break;
			}
			DEBUG((9,"problem in t_open"));
			tli_error(E_FD1OPEN, EXIT);
		}
	}

	ret = bind(fd, name, qlen, clen, adrp);
	DEBUG((9, "bind returns %d", ret));

	if (ret < 0) {
		t_close(fd);
		return(-3);
	}
	if (conp)
		*conp = ret;
	return(fd);
}


int
bind(fd, name, qlen, clen, ap)
int fd;
char *name;
int qlen;
int clen;
char **ap;
{
	struct t_bind *req = (struct t_bind *)0;
	struct t_bind *ret = (struct t_bind *)0;
	char	*p, *q;
	unsigned int	retval;
	extern void	nlsaddr2c();
	extern int	memcmp();
	extern int	errno;

#ifdef	CHARADDR
	char pbuf[NAMEBUFSZ + 1];
#endif
	char scratch[BUFSIZ];

	DEBUG((9,"in bind, fd = %d, clen = %d", fd, clen));
	
	if (clen)  {
		errno = t_errno = 0;
		while (!(req = (struct t_bind *)t_alloc(fd,T_BIND,T_ALL)) ) {
			if ((t_errno != TSYSERR) || (errno != EAGAIN))
				tli_error( E_T_ALLOC, EXIT);
			else
				tli_error( E_T_ALLOC, CONTINUE);
		}

		errno = t_errno = 0;
		while (!(ret = (struct t_bind *)t_alloc(fd,T_BIND,T_ALL)) ) {
			if ((t_errno != TSYSERR) || (errno != EAGAIN))
				tli_error( E_T_ALLOC, EXIT);
			else
				tli_error( E_T_ALLOC, CONTINUE);
		}

		if (clen > (int) req->addr.maxlen)  {
			sprintf(scratch,"Truncating name size from %d to %d", 
				clen, req->addr.maxlen);
			logmessage(scratch);
			clen = req->addr.maxlen;
		}

		if (clen == -1) {
			req->addr.len = 0;
		}
		else {
			(void)memcpy(req->addr.buf, name, clen);
			req->addr.len = clen;
		}
		req->qlen = qlen;

#if defined(CHARADDR) && defined(DEBUGMODE)
		(void)memcpy(pbuf, req->addr.buf, req->addr.len);
		pbuf[req->addr.len] = (char)0;
		DEBUG((3,"bind: fd=%d, logical name=%c%s%c, len=%d",
			fd, '\"',pbuf, '\"', req->addr.len));
#endif	/* CHARADDR  && DEBUGMODE */


#if defined(CHARADDR) && defined(DEBUGMODE)
		(void)memcpy(pbuf, req->addr.buf, req->addr.len);
		pbuf[req->addr.len] = (char)0;
		DEBUG((3,"bind: fd=%d, address=%c%s%c, len=%d",
			fd, '\"',pbuf, '\"', req->addr.len));
#endif	/* CHARADDR  && DEBUGMODE */


	}

	if (t_bind(fd, req, ret))  {
		DEBUG((1,"t_bind failed; t_errno %d errno %d", t_errno, errno));
		if (qlen)	/* starup only */
			tli_error(E_T_BIND, EXIT | NOCORE);
		/* here during normal service */
		if ((t_errno == TNOADDR) || ((t_errno == TSYSERR) && (errno == EAGAIN))) {
			/* our name space is all used up */
			tli_error(E_T_BIND, CONTINUE);
			t_close(fd);
			if (clen)  {
				if ( t_free((char *)req, T_BIND) )
					tli_error(E_T_FREE, EXIT);
				if ( t_free((char *)ret, T_BIND) )
					tli_error(E_T_FREE, EXIT);
			}
			return(-1);
		}
		/* otherwise, irrecoverable error */
		tli_error(E_T_BIND, EXIT | NOCORE);
	}
	DEBUG((9, "t_bind succeeded"));

	if (clen)  {
		retval = ret->qlen;
		if (clen == -1) {
			/* dynamic address */
			*ap = (char *) malloc(((ret->addr.len) << 1) + 3);
			if (*ap) {
				(*ap)[0] = '\\';
				(*ap)[1] = 'x';
				nlsaddr2c(*ap+2,ret->addr.buf,(int)ret->addr.len);
			}
		}
		else if ( (ret->addr.len != req->addr.len) ||
		     (memcmp( req->addr.buf, ret->addr.buf, (int) req->addr.len)) )  {
			p = (char *) malloc(((ret->addr.len) << 1) + 1);
			q = (char *) malloc(((req->addr.len) << 1) + 1);
			if (p && q) {
				nlsaddr2c(p, ret->addr.buf, (int)ret->addr.len);
				nlsaddr2c(q, req->addr.buf, (int)req->addr.len);
				sprintf(scratch, "Requested address \\x%s", q);
				logmessage(scratch);
				sprintf(scratch, "Actual address    \\x%s", p);
				logmessage(scratch);
				free(p);
				free(q);
			}
			DEBUG((9, "failed to bind requested address"));
			t_unbind(fd);
			t_close(fd);
			if ( t_free((char *)req, T_BIND) )
				tli_error(E_T_FREE, EXIT);
			if ( t_free((char *)ret, T_BIND) )
				tli_error(E_T_FREE, EXIT);
			return(-1);
		}

		if ( t_free((char *)req, T_BIND) )
			tli_error(E_T_FREE, EXIT);

		if ( t_free((char *)ret, T_BIND) )
			tli_error(E_T_FREE, EXIT);
		return(retval);
	}
	return((unsigned int) 0);
}


/*
 * catch_signals:
 *		Ignore some, catch the rest. Use SIGTERM to kill me.
 */

sigset_t Oset;
struct sigaction Sigterm;
struct sigaction Sigcld;

static void
catch_signals(void)
{
	sigset_t sset;
	sigset_t eset;
	struct sigaction sigact;
	extern void sigterm();

	(void) sigfillset(&sset);
	(void) sigdelset(&sset, SIGTERM);
	(void) sigdelset(&sset, SIGCLD);
	(void) sigprocmask(SIG_SETMASK, &sset, &Oset);

	sigact.sa_flags = 0;
	sigact.sa_handler = sigterm;
	sigact.sa_mask = sset;
	sigaction(SIGTERM, &sigact, &Sigterm);
	sigact.sa_flags = SA_NOCLDWAIT;
	sigact.sa_handler = SIG_IGN;
	sigact.sa_mask = sset;
	sigaction(SIGCLD, &sigact, &Sigcld);
}


/*
 * rst_signals:
 *		After forking but before exec'ing a server,
 *		reset all signals to original setting.
 */

static void
rst_signals(void)
{
	struct sigaction sigact;

	sigaction(SIGTERM, &Sigterm, NULL);
	sigaction(SIGCLD, &Sigcld, NULL);
	sigprocmask(SIG_SETMASK, &Oset, NULL);
}


/*
 * sigterm:	Clean up and exit.
 */

void
sigterm()
{
	extern char *shaddr;
	extern char *sh2addr;

	error(E_SIGTERM, EXIT | NORMAL | NOCORE);	/* calls cleanup */
}


/*
 * listen:	listen for and process connection requests.
 */

static char *dbfnewdmsg = "Using new data base file";

static void
listen(void)
{
	int	i;
	dbf_t	*dbp	= Dbfhead;
	struct	pollfd	*sp;
	struct		call_list *phead; /* pending head */

	DEBUG((9,"in listen, tag %s", Pmmsg.pm_tag));
	
	if ((Pollfds = (struct pollfd *) malloc(Ndesc * sizeof(struct pollfd)))
			== NULL)
		error(E_MALLOC,NOCORE | EXIT);

	/* setup poll structures for sac messages and private addresses */
	sp = Pollfds;
	sp->fd = Pmpipefd;
	sp->events = POLLIN;
	sp->revents = 0;
	sp++;
	for (dbp = Dbfhead; dbp && dbp->dbf_svc_code; dbp++) {
		if (dbp->dbf_fd >= 0) {
			sp->fd = dbp->dbf_fd;
			DEBUG((9, "adding %d to poll struct", dbp->dbf_fd));
			sp->events = POLLIN;
			sp->revents = 0;
			sp++;
		}
	}
	errno = t_errno = 0;

	for (;;) {
		DEBUG((9,"listen(): TOP of loop"));

		/* +1 for Pmpipefd */
		if (poll(Pollfds, Valid_addrs + 1, -1) < 0) {
			if (errno == EINTR)
				continue;
			/* poll error */
			sys_error(E_POLL, EXIT);
		}
		else {
			/* incoming request or message */
			for (i = 0, sp = Pollfds; i < Valid_addrs + 1; i++, sp++) {
				switch (sp->revents) {
				case POLLIN:
					if (sp->fd == Pmpipefd) {
						DEBUG((9,"sac message received"));
						check_sac_mesg();
					}
					else {
						DEBUG((9,"Connection requested "));
						phead = ((sp->fd) + Priv_call);
						doevent(phead, (sp->fd));
						if (State == PM_ENABLED)
							trycon(phead, (sp->fd));
						else
							send_dis(phead, (sp->fd));
					}
					break;
				case 0:
					break;
				/* distinguish the various errors for the user */
				case POLLERR:
					logmessage("poll() returned POLLERR");
					error(E_SYS_ERROR, EXIT | NO_MSG);
					break;
				case POLLHUP:
					logmessage("poll() returned POLLHUP");
					error(E_SYS_ERROR, EXIT | NO_MSG);
					break;
				case POLLNVAL:
					logmessage("poll() returned POLLNVAL");
					error(E_SYS_ERROR, EXIT | NO_MSG);
					break;
				case POLLPRI:
					logmessage("poll() returned POLLPRI");
					error(E_SYS_ERROR, EXIT | NO_MSG);
					break;
				case POLLOUT:
					logmessage("poll() returned POLLOUT");
					error(E_SYS_ERROR, EXIT | NO_MSG);
					break;
				default:
					logmessage("poll() returned unrecognized event");
					error(E_SYS_ERROR, EXIT | NO_MSG);
				}
				sp->revents = 0;
			}
		}

		if (Readdb) {
			DEBUG((9,"dbf file has been modified"));
			logmessage("Re-reading database");
			/* have to close an fd because read_dbf needs it */
			close(Acceptfd);
			if (!read_dbf(DB_REREAD)) {
				/* MUST re-open Acceptfd to insure it is free later */
				dup(Passfd);
				mod_prvaddr();
			}
			else {
				dup(Passfd);
				logmessage(dbfnewdmsg);
			}
			Readdb = FALSE;
		}
	}
}


/*
 * check_sac_mesg:	check the pipe to see if SAC has sent a message
 */

void
check_sac_mesg()
{
	int	length;
	struct	sacmsg sacmsg;

	DEBUG((9, "in check_sac_mesg..."));
	
	/* read all messages out of pipe */
	while ((length = read(Pmpipefd, &sacmsg, sizeof(sacmsg))) != 0) {
		if (length < 0) {
			if (errno == EINTR)
				continue;
			DEBUG((9, "read of _pmpipe failed"));
			return;
		}

		switch (sacmsg.sc_type) {
		case SC_STATUS:
			DEBUG((9, "Got SC_STATUS message"));
			Pmmsg.pm_type = PM_STATUS;
			Pmmsg.pm_state = State;
			break;
		case SC_ENABLE:
			DEBUG((9, "Got SC_ENABLE message"));
			if (State != PM_ENABLED)
				logmessage("New state: ENABLED");
			Pmmsg.pm_type = PM_STATUS;
			State = PM_ENABLED;
			Pmmsg.pm_state = PM_ENABLED;
			break;
		case SC_DISABLE:
			DEBUG((9, "Got SC_DISABLE message"));
			if (State != PM_DISABLED)
				logmessage("New state: DISABLED");
			Pmmsg.pm_type = PM_STATUS;
			State = PM_DISABLED;
			Pmmsg.pm_state = PM_DISABLED;
			break;
		case SC_READDB:
			DEBUG((9, "Got SC_READDB message"));
			Readdb = TRUE;
			Pmmsg.pm_type = PM_STATUS;
			Pmmsg.pm_state = State;
			break;
		default:
			DEBUG((9, "Got UNKNOWN message"));
			Pmmsg.pm_type = PM_UNKNOWN;
			Pmmsg.pm_state = State;
			logmessage("Received unknown message from sac -- ignored");
			break;
		}
		DEBUG((9, "Responding with state %d", Pmmsg.pm_state));
		while (write(Sacpipefd, &Pmmsg, sizeof(Pmmsg)) != sizeof(Pmmsg)) {
			if (errno == EINTR)
				continue;
			DEBUG((9, "sanity response failed"));
			break;
		}
	}
}


/*
 * doevent:	handle an asynchronous event
 */

static void
doevent(struct call_list *phead, int fd)
{
	static struct t_discon *disc;
	struct callsave *current;
	struct t_call *call;
	char scratch[BUFSIZ];

	DEBUG((9, "in doevent"));
	switch (t_look(fd)) {
	case 0:
		sys_error(E_POLL, EXIT);
		/* no return */
		break;
	case T_LISTEN:
	DEBUG((9, "case t_listen "));
		current = dequeue(Free_call_p);
		call = current->c_cp;
		if (t_listen(fd, call) < 0) {
			tli_error(E_T_LISTEN, CONTINUE);
			clr_call(call);
			queue(Free_call_p, current);
			return;
		}
		queue(phead, current);
		DEBUG((9, "incoming call seq # %d", call->sequence));
		break;
	case T_DISCONNECT:
	DEBUG((9, "case t_disconnect"));
		if (disc == NULL) {
			while (!(disc = (struct t_discon *)t_alloc(fd, T_DIS, T_ALL)) ) {
		   		if (t_errno == TBADF)
					DEBUG((9,"listen - fd not transport end point"));
				if ((t_errno != TSYSERR) || (errno != EAGAIN))
					tli_error(E_T_ALLOC, EXIT);
				else  
					tli_error(E_T_ALLOC, CONTINUE);
			}
		}
		if (t_rcvdis(fd, disc) < 0) {
			tli_error(E_T_RCVDIS, EXIT);
			/* no return */
		}
		sprintf(scratch, "Disconnect on fd %d, seq # %d", fd, disc->sequence);
		logmessage(scratch);
		DEBUG((9, "incoming disconnect seq # %d", disc->sequence));
		pitchcall(phead, disc);
		break;
	default:
	DEBUG((9, "case default"));
		tli_error(E_T_LOOK, CONTINUE);
		break;
		
	}
}

/*
 * send_dis:	send a disconnect
 *		called when we are in state PM_DISABLED
 */

static void
send_dis(struct call_list *phead, int fd)
{
	struct t_call *call;
	struct callsave *current;
	char	scratch[BUFSIZ];

	DEBUG((9, "sending disconnect"));
	while (!EMPTYLIST(phead)) {
		current = dequeue(phead);
		call = current->c_cp;
		if (t_snddis(fd, call) < 0) {
			if (t_errno == TLOOK) {
				DEBUG((9, "collision during snddis"));
				pqueue(phead, current);
				return;
			}
			else
				tli_error(E_T_SNDDIS, CONTINUE);
		}
		sprintf(scratch, "Incoming call while disabled: fd %d, seq %d", fd, call->sequence);
		logmessage(scratch);
		clr_call(call);
		queue(Free_call_p, current);
	}
	return;
}


/*
 * trycon:	try to accept a connection
 */

static void
trycon(struct call_list *phead, int fd)
{
	struct callsave *current;
	struct t_call *call;
	int i;
	pid_t pid;
	dbf_t *dbp;
	char scratch[BUFSIZ];
	extern dbf_t *getentry();

	DEBUG((9, "in trycon"));
	while (!EMPTYLIST(phead)) {
		current = dequeue(phead);
		call = current->c_cp;

		if ((dbp = getentry(fd)) == NULL) {
			sprintf(scratch, "No service bound to incoming fd %d: call disconnected", fd);
			logmessage(scratch);
			t_snddis(fd, call);
			clr_call(call);
			queue(Free_call_p, current);
			continue;
		}

		if (dbp->dbf_flags & DBF_OFF) {
			sprintf(scratch, "Request for service on fd %d denied: disabled", fd);
			logmessage(scratch);
			t_snddis(fd, call);
			clr_call(call);
			queue(Free_call_p, current);
			continue;
		}

		DEBUG((9, "try to accept #%d", call->sequence));
		SPLhi();
		close(Acceptfd);
		if ((Acceptfd = open_bind(NULL, 0, 0, (unsigned int *) 0, NULL)) != 0) {
			error(E_OPENBIND, CONTINUE);
			clr_call(call);
			queue(Free_call_p, current);
			continue;	/* let transport provider generate disconnect */
		}
		SPLlo();
		if (t_accept(fd, Acceptfd, call) < 0) {
			if (t_errno == TLOOK) {
				t_close(Acceptfd);
				SPLhi();
				if (dup(Passfd) != 0)
					logmessage("Trouble duping fd 0");
				SPLlo();
				logmessage("Incoming call during t_accept -- queueing current call");
				DEBUG((9, "save call #%d", call->sequence));
				pqueue(phead, current);
				return;
			}
			else {
				t_close(Acceptfd);
				SPLhi();
				if (dup(Passfd) != 0)
					logmessage("Trouble duping fd 0");
				SPLlo();
				tli_error(E_T_ACCEPT, CONTINUE);
				clr_call(call);
				queue(Free_call_p, current);
				continue;
			}
		}

		sprintf(scratch, "Connect: fd %d, svctag %s, seq %d, type %s",
			fd, dbp->dbf_svc_code, call->sequence,
			(dbp->dbf_sflags & PFLAG) ? "passfd" : "exec");
		logmessage(scratch);

		DEBUG((9, "Accepted call %d", call->sequence));

		if (dbp->dbf_sflags & PFLAG) {

			close(Passfd);

			if (pushmod(Acceptfd, dbp->dbf_modules)) {
				sprintf(scratch, "Could not push modules: %s", dbp->dbf_modules);
				logmessage(scratch);
				goto cleanup;
			}

			/* doconfig needs a file descriptor, so use Passfd */
			DEBUG((9, "Running doconfig on %s", dbp->dbf_svc_code));
			if ((i = doconfig(Acceptfd, dbp->dbf_svc_code, NOASSIGN|NORUN)) != 0) {
				DEBUG((9, "doconfig exited with code %d", i));
				sprintf(scratch, "doconfig failed on line %d of script %s", i, dbp->dbf_svc_code);
				logmessage(scratch);
				goto cleanup;
			}

			/* open pipe to pass fd through */
			if ((Passfd = open(dbp->dbf_cmd_line, O_WRONLY)) < 0) {
				/* bad pipe? */
				sprintf(scratch,"Open failed: %s", dbp->dbf_cmd_line);
				logmessage(scratch);
				goto cleanup;
			}

			if (ioctl(Passfd, I_SENDFD, Acceptfd) < 0) {
				/* clean up call, log error */
				sprintf(scratch,"Passfd failed: %s", dbp->dbf_cmd_line);
				logmessage(scratch);
			}
cleanup:
			/* clean up this call */
			clr_call(call);
			t_close(Acceptfd);
			close(Passfd);
			Acceptfd = open("/dev/null", O_RDWR);
			Passfd = dup(Acceptfd);
			queue(Free_call_p, current);
		}
		else {
			if ((pid = fork()) < 0)
				log(E_FORK_SERVICE);
			else if (!pid) {
				setpgrp();
				/* so log files are correct */
				Pid = getpid();

				if (senviron(call))  {
					logmessage("Can't expand server's environment");
				}

				start_server(Acceptfd, dbp);
#ifdef	COREDUMP
				abort();
#endif
				exit(1); /* server failed, don't log */
					/* no return */
			}	
			/* only parent gets here */
			clr_call(call);
			t_close(Acceptfd);
			queue(Free_call_p, current);
			SPLhi();
			if (dup(Passfd) != 0)
				logmessage("Trouble duping fd 0");
			SPLlo();
		}
	}
}

/*
 * common code to  start a server process (for any service)
 * The first argument in argv is the full pathname of server. 
 * Before exec-ing the server, the caller's
 * logical address, opt and udata are addded to the environment. 
 */

static char homeenv[BUFSIZ];
static char pathenv[BUFSIZ];

int
start_server(netfd, dbp)
int netfd;
dbf_t *dbp;
{
	char	*path;
	char	**argvp;
	extern	char **environ;
	extern	char **mkdbfargv();
	struct passwd *pwdp;
	struct	group *grpp;
	char	msgbuf[256];
	int	i;


	argvp = mkdbfargv(dbp);
	path = *argvp;

	/* set up stdout and stderr before pushing optional modules	*/
	/* this child doesn't need access to _sacpipe and _pmpipe	*/

	(void) close(Sacpipefd);
	(void) close(Pmpipefd);

	if (dbp->dbf_flags & DBF_UTMP) {
		pid_t	tmp;
		struct	stat	sbuf;
		char	device[20];
		char	dummy[PMTAGSIZE + 1];
		struct	utmpx utline;

		/* 
		 * create a utmpx entry --
		 * we do an extra fork here to make init this process's
		 * parent.  this lets init clean up the utmpx entry when
		 * this proc dies.
		 *
		 * the utmpx routines need a file descriptor!
		 */

		DEBUG((9, "Creating a utmpx entry for this service "));
		if ((tmp = fork()) < 0) {
			logmessage("Can't fork to create utmpx entry");
			exit(2);
		}
		if (tmp)
			exit(0);	/* kill parent */

		/* 
		 * child continues processing, creating utmp and exec'ing
		 * the service
		 */

		setpgrp();
		if (fstat(0, &sbuf) < 0) {
			logmessage("Stat failed on fd 0: no line field "
			    "available for utmpx entry");
			*device = '\0';
		}
		else {
			if (minor(sbuf.st_rdev) < 100)
				sprintf(device, "%.9s%02d", Minor_prefix,
				    minor(sbuf.st_rdev));
			else
				sprintf(device, "%.8s%03d", Minor_prefix,
				    minor(sbuf.st_rdev));
			DEBUG((9, "Device: %s", device));
		}
		/*
		 * prepend a "." so this can be distinguished as a "funny"
		 * utmpx entry that may never get a DEAD_PROCESS entry in
		 * the wtmpx file.
		 */
		sprintf(dummy, ".%s", Mytag);
		/* XXX - utmp - fix login name length */
		strncpy(utline.ut_user, dummy, sizeof (utline.ut_user) - 1);
		sprintf(utline.ut_id, "ls%c%c", SC_WILDC, SC_WILDC);
		strncpy(utline.ut_line, device, sizeof (utline.ut_line) - 1);
		utline.ut_pid = getpid();
		utline.ut_type = USER_PROCESS;
		utline.ut_exit.e_termination = 0;
		utline.ut_exit.e_exit = 0;
		utline.ut_xtime = (time_t) time((time_t *)0);
		makeutx(&utline);
	}

	if (dup(0) != 1 || dup(0) != 2) {
		logmessage("Dup of fd 0 failed");
		exit(2); /* server, don't log */
	}


	if (pushmod(netfd, dbp->dbf_modules)) {
		logmessage("Can't push server's modules: exit");
		exit(2); /* server, don't log */
	}

	rst_signals();
	
	DEBUG((9, "Running doconfig on %s", dbp->dbf_svc_code));
	if ((i = doconfig(Acceptfd, dbp->dbf_svc_code, 0)) != 0) {
		DEBUG((9, "doconfig exited with code %d", i));
		sprintf(msgbuf, "doconfig failed on line %d of script %s", i, dbp->dbf_svc_code);
		logmessage(msgbuf);
		exit(2);
	}

	if ((pwdp = getpwnam(dbp->dbf_id)) == NULL)  {
		sprintf(msgbuf, "Missing or bad passwd entry for <%s>",dbp->dbf_id);
		logmessage(msgbuf);
		exit(2); /* server, don't log */
	}		

	if (setgid(pwdp->pw_gid)) {
		if ((grpp = getgrgid(pwdp->pw_gid)) == NULL) {
			sprintf(msgbuf, "No group entry for %ld", pwdp->pw_gid);
			logmessage(msgbuf);
			exit(2); /* server, don't log */
		}
		sprintf(msgbuf, "Cannot set group id to %s", grpp->gr_name);
		logmessage(msgbuf);
		exit(2); /* server, don't log */
	}

	if (setuid(pwdp->pw_uid)) {
		sprintf(msgbuf, "Cannot set user id to %s", dbp->dbf_id);
		logmessage(msgbuf);
		exit(2); /* server, don't log */
	}

	if (chdir(pwdp->pw_dir)) {
                sprintf(msgbuf, "Cannot chdir to %s", pwdp->pw_dir);
                logmessage(msgbuf);
                exit(2); /* server, don't log */
        }


	DEBUG((9, "New uid %ld New gid %ld", getuid(), getgid()));

	sprintf(homeenv, "HOME=%s", pwdp->pw_dir);
	putenv(homeenv);
	if (pwdp->pw_uid)
		sprintf(pathenv, "PATH=/usr/bin:");
	else
		sprintf(pathenv, "PATH=/usr/sbin:/usr/bin");
	putenv(pathenv);

	endpwent();

	execve(path, argvp, environ);

	/* exec returns only on failure!		*/

	logmessage("ERROR: could not exec server");
	sys_error(E_SYS_ERROR, CONTINUE);
	return(-1);
}


/*
 * senviron:	Update environment before exec-ing the server:
 *		The callers logical address is placed in the
 *		environment in hex/ascii character representation.
 *
 * Note:	no need to free the malloc'ed buffers since this process
 *		will either exec or exit.
 */

static char provenv[2*PATHSIZE];
static char prefenv[2*PATHSIZE];

int
senviron(call)
struct t_call *call;
{
	char *p;
	extern void nlsaddr2c();
	extern char *getenv();


/*
 * The following code handles the case where the listener was started with
 * no environment.  If so, supply a reasonable default path.  Parent already
 * set TZ on startup if it wasn't, so don't need to do it here.
 */

	if (getenv("PATH") == NULL)
		putenv("PATH=/usr/sbin:/usr/bin");

	if ((p = (char *)malloc(((call->addr.len)<<1) + 18)) == NULL)
		return(-1);
	strcpy(p, NLSADDR);
	strcat(p, "=");
	nlsaddr2c(p + strlen(p), call->addr.buf, (int)call->addr.len);
	DEBUG((7, "Adding %s to server's environment", p));
	putenv(p);

	if ((p = (char *)malloc(((call->opt.len)<<1) + 16)) == NULL)
		return(-1);
	strcpy(p, NLSOPT);
	strcat(p, "=");
	nlsaddr2c(p + strlen(p), call->opt.buf, (int)call->opt.len);
	DEBUG((7, "Adding %s to server's environment", p));
	putenv(p);

	p = provenv;
	strcpy(p, NLSPROVIDER);
	strcat(p, "=");
	strcat(p, Netspec);
	DEBUG((7, "Adding %s to environment", p));
	putenv(p);

	/*
	 * MPREFIX is NEW for SVR4.0.  It tells the nlps_server what to use
	 * as a minor device prefix.  THIS SHOULD BE DOCUMENTED!
	 */
	p = prefenv;
	strcpy(p, "MPREFIX");
	strcat(p, "=");
	strcat(p, Minor_prefix);
	DEBUG((7, "Adding %s to environment", p));
	putenv(p);

	if ((p = (char *)malloc(((call->udata.len)<<1) + 20)) == NULL)
		return(-1);
	strcpy(p, NLSUDATA);
	strcat(p, "=");
	if ((int)call->udata.len >= 0)
		nlsaddr2c(p + strlen(p), call->udata.buf, (int)call->udata.len);
	putenv(p);
	return (0);
}


/*
 * parse:	Parse TZ= string like init does for consistency
 *		Work on string in place since result will
 *		either be the same or shorter.
 */

char *
parse(s)
char *s;
{
	char *p;
	char *tp;
	char scratch[BUFSIZ];
	int delim;

	tp = p = s + strlen("TZ=");	/* skip TZ= in parsing */
	if ((*p == '"') || (*p == '\'')) {
		/* it is quoted */
		delim = *p++;
		for (;;) {
			if (*p == '\0') {
				/* etc/default/init ill-formed, go without TZ */
				sprintf(scratch, "%s ill-formed", TZFILE);
				logmessage(scratch);
				strcpy(s, "TZ=");
				return(s);
			}
			if (*p == delim) {
				*tp = '\0';
				return(s);
			}
			else {
				*tp++ = *p++;
			}
		}
	}
	else { /* look for comment or trailing whitespace */
		for ( ; *p && !isspace(*p) && *p != '#'; ++p)
			;
		/* if a comment or trailing whitespace, trash it */
		if (*p) {
			*p = '\0';
		}
		return(s);
	}
}


/*
 * clr_call:	clear out a call structure
 */

static void
clr_call(struct t_call *call)
{
	call->sequence = 0;
	call->addr.len = 0;
	call->opt.len = 0;
	call->udata.len = 0;
	memset(call->addr.buf, 0, (int)call->addr.maxlen);
	memset(call->opt.buf, 0, (int)call->opt.maxlen);
	memset(call->udata.buf, 0, (int)call->udata.maxlen);
}


/*
 * pitchcall: remove call from pending list
 */

static void
pitchcall(struct call_list *pending, struct t_discon *discon)
{
	struct callsave *p, *oldp;

	DEBUG((9, "pitching call, sequence # is %d", discon->sequence));
	if (EMPTYLIST(pending)) {
		discon->sequence = -1;
		return;
	}
	p = pending->cl_head;
	oldp = (struct callsave *) NULL;
	while (p) {
		if (p->c_cp->sequence == discon->sequence) {
			if (oldp == (struct callsave *) NULL) {
				pending->cl_head = p->c_np;
				if (pending->cl_head == (struct callsave *) NULL) {
					pending->cl_tail = (struct callsave *) NULL;
				}
			}
			else if (p == pending->cl_tail) {
				oldp->c_np = p->c_np;
				pending->cl_tail = oldp;
			}
			else {
				oldp->c_np = p->c_np;
			}
			clr_call(p->c_cp);
			queue(Free_call_p, p);
			discon->sequence = -1;
			return;
		}
		oldp = p;
		p = p->c_np;
	}
	logmessage("received disconnect with no pending call");
	discon->sequence = -1;
	return;
}

/*
 * add_prvaddr:  open and bind the private address specified in the database
 *               entry passed into the routine.  Update the maxcon and fd 
 *               entries in the database structure
 *
 *	This routine is very sloppy with malloc'ed memory, but addresses
 *	shouldn't ever change enough for this to matter.
 */

int
add_prvaddr(dbp)
dbf_t *dbp;
{
	extern	char	*t_alloc();
	int	j;
	struct	call_list *temp_pend;
	struct	callsave *tmp;
	char	scratch[BUFSIZ];
	int	bindfd;
	extern	struct	netbuf *stoa();
	char	str[NAMEBUFSZ];
	char	*lstr = str;
	struct	netbuf	netbuf;
	int	maxcon;
	char	*ap;
	int	clen;

	DEBUG((9,"in add_prvaddr, addr %s, svc %s",
		(dbp->dbf_sflags & DFLAG) ? "DYNAMIC" : dbp->dbf_prv_adr,
		dbp->dbf_svc_code)); 
	netbuf.buf = NULL;
	netbuf.maxlen = 0;
	netbuf.len = 0;
	if (!(dbp->dbf_sflags & DFLAG)) {
		strcpy(lstr, dbp->dbf_prv_adr);

		/* call stoa - convert from rfs address to netbuf */

		if (stoa(lstr, &netbuf) == (struct netbuf *)NULL)  {
			DEBUG((9,"stoa returned null, errno = %d\n",errno));
			error(1, E_MALLOC);
			return(-1);
		}
		clen = netbuf.len;
	}
	else {
		clen = -1;
	}
	if ((bindfd = open_bind(netbuf.buf, MAXCON, clen, &maxcon, &ap)) < 0) {
		switch (bindfd) {
		case -1:
			return(-1);
			break;
		case -2:
			sprintf(scratch, "  Service %s ignored: out of file descriptors", dbp->dbf_svc_code);
			logmessage(scratch);
			return(-1);
			break;
		case -3:
			sprintf(scratch, "  Service %s ignored: unable to bind requested address", dbp->dbf_svc_code);
			logmessage(scratch);
			return(-1);
			break;
		default:
			error(E_OPENBIND, EXIT);	
		}
	}
	if (clen == -1) {
		sprintf(scratch,"Service %s: fd %d dynamic addr %s", dbp->dbf_svc_code, bindfd, ap);
		dbp->dbf_prv_adr = ap;
	}
	else {
		sprintf(scratch,"Service %s: fd %d addr %s", dbp->dbf_svc_code, bindfd, dbp->dbf_prv_adr);
	}
	logmessage(scratch);
	rpc_register(dbp);
	temp_pend = Priv_call + bindfd;
	dbp->dbf_fd = bindfd;
	dbp->dbf_maxcon = maxcon;
	temp_pend->cl_head = (struct callsave *) NULL;
	temp_pend->cl_tail = (struct callsave *) NULL;
	for (j=0; j < maxcon; ++j)  {
		if ((tmp = (struct callsave *) malloc(sizeof(struct callsave))) == NULL)  {
			error (E_MALLOC, NOCORE | EXIT);
		}
		if ((tmp->c_cp = (struct t_call *) t_alloc(bindfd, T_CALL,
				T_ALL)) == NULL) {
			tli_error(E_T_ALLOC,EXIT);
		}
		queue(Free_call_p, tmp);	
	}
	return(0);
}

/*
 * mod_prvaddr -- after re-reading the database, take appropriate action for
 *		  new, deleted, or changed addresses.
 */
static void
mod_prvaddr(void)
{
	dbf_t	*entry_p;
	dbf_t	*oldentry_p;
	char	scratch[BUFSIZ];
	dbf_t	*svc_code_match();
	int	bound;
	struct	pollfd	*sp;

	DEBUG((9, "in mod_prvaddr..."));
	/* 
	 * for each entry in the new table, check for a svc code match.
	 * if there is a svc code match and the address matches, all we
	 * need to do is update the new table.  if the addresses are
	 * different, we need to remove the old one and replace it.
	 */
	for (entry_p = Newdbf; entry_p && entry_p->dbf_svc_code; entry_p++) {
		if ((oldentry_p = svc_code_match(entry_p->dbf_svc_code)) != NULL) {
			/* matched svc code.  see if address matches. */
			DEBUG((9, "MATCHED service code"));
			if ((strcmp(oldentry_p->dbf_prv_adr, entry_p->dbf_prv_adr) == 0) || ((oldentry_p->dbf_sflags & DFLAG) && (entry_p->dbf_sflags & DFLAG))) {
				DEBUG((9, "SAME addresses, old %s, new %s",
				oldentry_p->dbf_prv_adr, entry_p->dbf_prv_adr));
				/* update new table with fd, set old fd to -1 */
				DEBUG((9, "Old fd %d",  oldentry_p->dbf_fd));
				entry_p->dbf_fd = oldentry_p->dbf_fd;
				entry_p->dbf_maxcon = oldentry_p->dbf_maxcon;
				oldentry_p->dbf_fd = -1;
				if ((oldentry_p->dbf_sflags & DFLAG) && (entry_p->dbf_sflags & DFLAG)) {
					entry_p->dbf_prv_adr = oldentry_p->dbf_prv_adr;
				}
				if (entry_p->dbf_fd != -1) {
					sprintf(scratch, "Service %s: fd %d addr %s",
						entry_p->dbf_svc_code, entry_p->dbf_fd,
						entry_p->dbf_prv_adr);
					logmessage(scratch);
				}
				if ((oldentry_p->dbf_version != entry_p->dbf_version) || (oldentry_p->dbf_prognum != entry_p->dbf_prognum)) {
					rpc_unregister(oldentry_p);
					rpc_register(entry_p);
				}
			}
		}
	}

	/* now unbind the remaining addresses in the old table (fd != -1) */

	for (oldentry_p = Dbfhead; oldentry_p && oldentry_p->dbf_svc_code; oldentry_p++) {
		if (oldentry_p->dbf_fd != -1) {
			DEBUG((9, "deleting %s",  oldentry_p->dbf_svc_code));
			if (del_prvaddr(oldentry_p) == 0)
				Valid_addrs--;
		}
	}

	/* now bind all of the new addresses (fd == -1) */
	/* 
	 * this tries to bind any addresses that failed to bind successfully
	 * when the address changed.  This means that if a service is moved to
	 * an address that is being deleted, the first attempt to bind it will
	 * fail, the old address will be removed, and this bind will succeed
	 */

	/* first the static addrs */
	for (entry_p = Newdbf; entry_p && entry_p->dbf_svc_code; entry_p++) {
		if ((entry_p->dbf_fd == -1) && (!(entry_p->dbf_sflags & DFLAG))) {
			DEBUG((9, "adding %s",  entry_p->dbf_svc_code));
			if (add_prvaddr(entry_p) == 0)
				Valid_addrs++;
		}
	}
	/* then the dynamic addrs */
	for (entry_p = Newdbf; entry_p && entry_p->dbf_svc_code; entry_p++) {
		if ((entry_p->dbf_fd == -1) && (entry_p->dbf_sflags & DFLAG)) {
			DEBUG((9, "adding %s",  entry_p->dbf_svc_code));
			if (add_prvaddr(entry_p) == 0)
				Valid_addrs++;
		}
	}

	/* free old database, set up new pollfd table, and we're done */

	free(Dbfhead);
	free(Server_cmd_lines);
	Dbfhead = Newdbf;
	Newdbf = NULL;
	Server_cmd_lines = New_cmd_lines;
	sprintf(scratch, "Re-read complete, %d %s bound, %d fds free", Valid_addrs, 
		(Valid_addrs == 1) ? "address" : "addresses",
		Ndesc-Valid_addrs-USEDFDS);
	logmessage(scratch);

	/* Pollfds[0] is for _pmpipe */
	sp = &Pollfds[1];
	for (entry_p = Dbfhead; entry_p && entry_p->dbf_svc_code; entry_p++) {
		if (entry_p->dbf_fd >= 0) {
			sp->fd = entry_p->dbf_fd;
			DEBUG((9, "adding %d to poll struct", entry_p->dbf_fd));
			sp->events = POLLIN;
			sp->revents = 0;
			sp++;
		}
	}
}

/*
 * unbind the address, close the file descriptor, and free call structs
 */

int
del_prvaddr(dbp)
dbf_t	*dbp;
{
	struct	callsave	*tmp;
	struct	call_list	*q;
	struct	t_call		*call;
	int	i;
	char	scratch[BUFSIZ];

	DEBUG((9, "in del_prvaddr..."));
	rpc_unregister(dbp);
	if (dbp->dbf_fd < 0) 
		return -1;

	q = Priv_call + dbp->dbf_fd;
	i = 0;

	/* delete pending calls */
	while ((tmp = dequeue(q)) != NULL) {
		i++;
		call = tmp->c_cp;
		t_snddis(dbp->dbf_fd, call);
		t_free((char *)call, T_CALL);
		free(tmp);
	}

	/* delete free call structs we don't need */
	for ( ; i < dbp->dbf_maxcon; i++) {
		tmp = dequeue(Free_call_p);
		t_free((char *)tmp->c_cp, T_CALL);
		free(tmp);
	}

	t_unbind(dbp->dbf_fd);
	t_close(dbp->dbf_fd);
	sprintf(scratch, "Unbind %s: fd %d addr %s", dbp->dbf_svc_code, 
		dbp->dbf_fd, dbp->dbf_prv_adr);
	logmessage(scratch);
	dbp->dbf_fd = -1;
	return 0;
}


/* 
 * look through the old database file to see if this service code matches
 * one already present
 */

dbf_t *
svc_code_match(new_code)
char	*new_code;
{
	dbf_t	*dbp;

	for (dbp = Dbfhead; dbp && dbp->dbf_svc_code; dbp++) {
		if (strcmp(dbp->dbf_svc_code, new_code) == 0)
			return(dbp);
	}
	return((dbf_t *)NULL);
}


/*
 * register an rpc service with rpcbind
 */

void
rpc_register(dbp)
dbf_t *dbp;
{
	char	str[NAMEBUFSZ];
	char	scratch[BUFSIZ];
	char	*lstr = str;
	struct	netbuf	netbuf;
	extern	struct	netbuf *stoa();
	extern	int	errno;

	DEBUG((9, "in rpc_register"));
	if (dbp->dbf_prognum == -1 || dbp->dbf_version == -1)
		/* not an rpc service */
		return;

	rpc_unregister(dbp);
	netbuf.buf = NULL;
	netbuf.maxlen = 0;
	netbuf.len = 0;
	strcpy(lstr, dbp->dbf_prv_adr);
	if (stoa(lstr, &netbuf) == (struct netbuf *)NULL)  {
		DEBUG((9,"stoa returned null, errno = %d\n",errno));
		error(1, E_MALLOC);
		return;
	}
	if (rpcb_set(dbp->dbf_prognum, dbp->dbf_version, Netconf, &netbuf)) {
		sprintf(scratch,"  registered with rpcbind, prognum %d version %d", dbp->dbf_prognum, dbp->dbf_version);
		logmessage(scratch);
	}
	else {
		logmessage("rpcb_set failed, service not registered with rpcbind");
	}
	return;
}


/*
 * unregister an rpc service with rpcbind
 */

void
rpc_unregister(dbp)
dbf_t *dbp;
{
	DEBUG((9, "in rpc_unregister"));
	if (dbp->dbf_prognum == -1 || dbp->dbf_version == -1)
		/* not an rpc service */
		return;
	(void) rpcb_unset(dbp->dbf_prognum, dbp->dbf_version, Netconf);
}
