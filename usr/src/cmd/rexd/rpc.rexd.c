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
 * rexd - a remote execution daemon based on SUN Remote Procedure Calls
 *
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <netinet/in.h>
#include <rpc/rpc.h>
#include <rpc/svc_soc.h>
#include <rpc/key_prot.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/mntent.h>
#include <sys/mnttab.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <wait.h>
#include <sys/systeminfo.h>

#include <sys/ttold.h>

#include "rex.h"

#include <security/pam_appl.h>
#include <stropts.h>
#include <sys/stream.h>
/*	#include <sys/termios.h>	XXX	*/
#include <sys/ttcompat.h>

#include <bsm/audit.h>

/* #define	stderr	stdout */		/* XXX		*/

#define	ListnerTimeout 300	/* seconds listner stays alive */
#define	WaitLimit 10		/* seconds to wait after io is closed */
#define	MOUNTED "/etc/mnttab"
#define	TempDir "/tmp_rex"	/* directory to hold temp mounts */
static	char TempName[] = "/tmp_rex/rexdXXXXXX";
				/* name template for temp mount points */
#define	TempMatch 13		/* unique prefix of above */

SVCXPRT	*ListnerTransp;		/* non-null means still a listner */

static	char **Argv;		/* saved argument vector (for ps) */
static char *LastArgv;		/* saved end-of-argument vector */
int OutputSocket;		/* socket for stop/cont notification */
int MySocket;			/* transport socket */
int HasHelper = 0;		/* must kill helpers (interactive mode) */
int DesOnly  =  0;		/* unix credentials too weak */
int confd;			/* console fd */

int	Debug = 0;

pam_handle_t *pamh;		/* PAM handle */

time_t time_now;

extern int Master;		/* half of the pty */
extern char **environ;

int child = 0;			/* pid of the executed process */
int ChildStatus = 0;		/* saved return status of child */
int ChildDied = 0;		/* true when above is valid */
char nfsdir[MAXPATHLEN];	/* file system we mounted */
char *tmpdir;			/* where above is mounted, NULL if none */

extern	void	rex_cleanup(void);
extern	int	ValidUser(char *host, uid_t uid, gid_t gid,
			char *error, char *shell,
			char *dir, struct rex_start *rst);

extern void audit_rexd_fail(char *, char *, char *, uid_t, gid_t,
				char *, char **);
extern void audit_rexd_success(char *, char *, uid_t, gid_t,
				char *, char **);
extern void audit_rexd_setup();

extern int audit_settid(int);

/* process rex requests */
void		dorex(struct svc_req *rqstp, SVCXPRT *transp);
void		ListnerTimer(int);		/* destroy listener	*/
void		CatchChild(int);		/* handle child signals	*/
void		oob(int);			/* out of band signals	*/
void		sigwinch(int);	/* window change signals -- dummy */
FILE		*setmntent(char *fname, char *flag);
extern void	HelperRead(pollfd_t *fdp, int, int *);

int
main(int argc, char **argv)
{
	/*
	 * the server is a typical RPC daemon, except that we only
	 * accept TCP connections.
	 */
	int pollretval;
	int npollfds = 0;
	pollfd_t *pollset = NULL;
	struct sockaddr_in addr;
	int maxrecsz = RPC_MAXDATASIZE;

	audit_rexd_setup();	/* BSM */

	/*
	 * Remember the start and extent of argv for setproctitle().
	 * Open the console for error printouts, but don't let it be
	 * our controlling terminal.
	 */
	if (argc > 1) {
		if (strcmp("-s", argv[1]) == 0)
			DesOnly = 1;

		if (strcmp("-d", argv[1]) == 0)
			Debug = 1;
	}

	if (argc > 2) {
		if (strcmp("-s", argv[2]) == 0)
			DesOnly = 1;

		if (strcmp("-d", argv[2]) == 0)
			Debug = 1;
	}

	/*
	 * argv start and extent for setproctitle()
	 */
	Argv = argv;
	if (argc > 0)
		LastArgv = argv[argc-1] + strlen(argv[argc-1]);
	else
		LastArgv = NULL;

	/*
	 * console open for errors w/o being the controlling terminal
	 */

	if ((confd = open("/dev/console", 1)) > 0) {
		close(1);
		close(2);
		confd = dup2(confd, 1); /* console fd copied to stdout */
		dup(1);		/* console fd copied to stderr */
	}

	setsid();		/* get rid of controlling terminal	*/

	/*
	 * setup signals
	 */
	sigset(SIGCHLD, CatchChild);
	sigset(SIGPIPE, SIG_IGN);
	sigset(SIGALRM, ListnerTimer);

	/*
	 * Enable non-blocking mode and maximum record size checks for
	 * connection oriented transports.
	 */
	if (!rpc_control(RPC_SVC_CONNMAXREC_SET, &maxrecsz)) {
		fprintf(stderr, "rexd: unable to set RPC max record size\n");
	}

	/*
	 * determine how we started to see if we are already in the background
	 * and get appropriately registered with rpcbind (portmapper)
	 */

	if (isfrominetd(0)) {
		/*
		 * Started from inetd: use fd 0 as socket
		 */
		if (Debug)
			printf("Started from inetd\n");

		if ((ListnerTransp = svctcp_create(0, 0, 0)) == NULL) {
			fprintf(stderr, "rexd: svctcp_create error\n");
			exit(1);
		}

		if (!svc_register(ListnerTransp, REXPROG, REXVERS, dorex, 0)) {
			fprintf(stderr, "rexd: service register error\n");
			exit(1);
		}

		alarm(ListnerTimeout);
	} else {

		if (Debug)
			printf("started from shell\n");
		if (!Debug) {
			/*
			 * Started from shell, background
			 * thyself and run forever.
			 */

			int pid = fork();

			if (pid < 0) { /* fork error	*/
				perror("rpc.rexd: can't fork");
				exit(1);
			}

			if (pid) { /* parent terminates	*/
				exit(0);
			}
		}

		/*
		 * child process continues to establish connections
		 */

		if (Debug)
			printf("before svctcp_create() call\n");
		if ((ListnerTransp = svctcp_create(RPC_ANYSOCK, 0, 0))
		    == NULL) {
			fprintf(stderr, "rexd: svctcp_create: error\n");
			exit(1);
		}

		pmap_unset(REXPROG, REXVERS);

		if (!svc_register(ListnerTransp, REXPROG, REXVERS,
				dorex, IPPROTO_TCP)) {
			fprintf(stderr, "rexd: service rpc register: error\n");
			exit(1);
		}
	}

	/*
	 * Create a private temporary directory to hold rexd's mounts
	 */
	if (mkdir(TempDir, 0777) < 0)
		if (errno != EEXIST) {
			perror("rexd: mkdir");
			fprintf(stderr,
				"rexd: can't create temp directory %s\n",
				TempDir);
			exit(1);
		}

	if (Debug)
		printf("created temporary directory\n");


	/*
	 * normally we would call svc_run() at this point, but we need to be
	 * informed of when the RPC connection is broken, in case the other
	 * side crashes.
	 */
	while (TRUE) {
		if (Debug)
			printf("Entered While loop\n");

		if (MySocket) {
			int i;
			char *waste;

			/* try to find MySocket in the pollfd set */
			for (i = 0; i < svc_max_pollfd; i++)
				if (svc_pollfd[i].fd == MySocket)
					break;
			/*
			 * If we didn't find it, the connection died for
			 * some random reason, e.g. client crashed.
			 */
			if (i == svc_max_pollfd) {
				if (Debug)
					printf("Connection died\n");
				(void) rex_wait(&waste);
				rex_cleanup();
				exit(1);
			}
		}

		/*
		 * Get existing array of pollfd's, should really compress
		 * this but it shouldn't get very large (or sparse).
		 */
		if (npollfds != svc_max_pollfd) {
			pollset = realloc(pollset,
					sizeof (pollfd_t) * svc_max_pollfd);
			npollfds = svc_max_pollfd;
		}

		if (npollfds == 0)
			break;	/* None waiting, hence return */

		(void) memcpy(pollset, svc_pollfd,
					sizeof (pollfd_t) * svc_max_pollfd);

		if (Debug)
			printf("Before select readfds\n");
		switch (pollretval = poll(pollset, npollfds, -1)) {
		case -1:
			if (Debug)
				printf("Poll failed\n");
			if (errno == EINTR)
				continue;
			perror("rexd: poll failed");
			exit(1);

		case 0:
			if (Debug)
				printf("Poll returned zero\n");
			fprintf(stderr, "rexd: poll returned zero\r\n");
			continue;

		default:
			if (Debug)
				printf("Before HelperRead\n");
			if (HasHelper)
				HelperRead(pollset, npollfds, &pollretval);
			if (Debug)
				printf("After HelperRead\n");
			time_now = time((time_t *)0);
			if (Debug)
				printf("before svc_getreq_poll\n");
			svc_getreq_poll(pollset, pollretval);
		}
		if (Debug)
			printf("After switch\n");
	}
	return (0);
}

/*
 * This function gets called after the listner has timed out waiting
 * for any new connections coming in.
 */
void
ListnerTimer(int junk)
{
	/*
	 * svc_destroy not done here due to problems with M_ERROR
	 * on stream head and inetd
	 */
	exit(0);
}

struct authunix_parms
*authdes_to_unix(des_cred)
struct authdes_cred *des_cred;
{
	struct authunix_parms *unix_cred;
	static struct authunix_parms au;
	static uint_t    stuff[32];
	char publickey[HEXKEYBYTES+1];


	unix_cred = &au;

	unix_cred->aup_gids = (gid_t *)stuff;

	unix_cred->aup_machname = "";
	if (getpublickey(des_cred->adc_fullname.name, publickey) == 0)
		return (NULL);

	if (netname2user(des_cred->adc_fullname.name,
			&(unix_cred->aup_uid),
			&(unix_cred->aup_gid),
			(int *)&(unix_cred->aup_len),
			unix_cred->aup_gids) == FALSE)
		return (NULL);
	else
		return (unix_cred);
}

/*
 * dorex - handle one of the rex procedure calls, dispatching to the
 *	correct function.
 */
void
dorex(rqstp, transp)
struct svc_req *rqstp;
SVCXPRT *transp;
{
	struct rex_start *rst;
	struct rex_result result;
	struct authunix_parms *unix_cred;
	struct sockaddr_in *calleraddr;


	if (ListnerTransp) {

		/*
		 * First call - fork a server for this connection
		 */
		int fd, pid, count;

		for (count = 0; (pid = fork()) < 0; count++) {
			if (count > 4)
				{
					perror("rexd: cannot fork");
					break;
				}
			sleep(5);
		}

		if (pid != 0) {

			/*
			 * Parent - return to service loop to accept further
			 * connections.
			 */
			alarm(ListnerTimeout);
			svc_destroy(transp);
			return;
		}

		/*
		 * child - close listner transport to avoid confusion
		 * Also need to close all other service transports
		 * besides the one we are interested in.
		 * Save ours so that we know when it goes away.
		 */
		if (Debug)
			printf("child server process\n");

		alarm(0);



		if (transp != ListnerTransp) {

			close(ListnerTransp->xp_sock);
			xprt_unregister(ListnerTransp);
		}
		ListnerTransp = NULL;

		MySocket = transp->xp_sock;

		/* temp workaround to restore sanity in TLI state */
		if (transp->xp_sock != 0)
			t_close(0); /* opened in parent possibly by inetd */

		/*
		 * XXX: svc_pollfd[] is a read-only structure. This
		 * appears to be dead code, which should be removed.
		 * However, until it can be clearly understood, leaving
		 * in.
		 */
		for (fd = 1; fd < svc_max_pollfd; fd++) {
			if (fd != transp->xp_sock && svc_pollfd[fd].fd == fd) {

				printf("close of fd %d\n", fd);
				close(fd);
				svc_pollfd[fd].fd = -1;
				svc_pollfd[fd].events = 0;
				svc_pollfd[fd].revents = 0;
			}
		}
	}

	/*
	 * execute the requested prodcedure
	 */
	switch (rqstp->rq_proc)	{
	case NULLPROC:
		if (Debug)	/*	XXX	*/
			printf("dorex: call to NULLPROC\n");

		if (svc_sendreply(transp, xdr_void, 0) == FALSE) {

			fprintf(stderr, "rexd: nullproc err");
			exit(1);
		}
		return;

	case REXPROC_START:
		if (Debug)	/*	XXX	*/
			printf("dorex: call to REXPROC_START\n");


		rst = (struct rex_start *)malloc(sizeof (struct rex_start));
		memset((char *)rst, '\0', sizeof (*rst));

		if (svc_getargs(transp, xdr_rex_start, (char *)rst) == FALSE) {

			svcerr_decode(transp);
			exit(1);
		}
		if (Debug)
			printf("svc_getargs: suceeded\n");

		if (rqstp->rq_cred.oa_flavor == AUTH_DES) {

			unix_cred = authdes_to_unix(rqstp->rq_clntcred);

		} else if (rqstp->rq_cred.oa_flavor == AUTH_UNIX) {

			if (DesOnly) {
				fprintf(stderr,
					"Unix too weak auth(DesOnly)!\n");
				unix_cred = NULL;
			} else
				unix_cred =
				(struct authunix_parms *)rqstp->rq_clntcred;

		} else {

			fprintf(stderr, "Unknown weak auth!\n");
			svcerr_weakauth(transp);
			sleep(5);
			exit(1);
		}

		if (unix_cred == NULL) {

			svcerr_weakauth(transp);
			sleep(5);
			exit(1);
		}

		calleraddr = svc_getcaller(transp);

		result.rlt_stat = (int)rex_startup(rst,
						unix_cred,
						(char **)&result.rlt_message,
						calleraddr);

		if (Debug)
			printf("rex_startup: completed\n");

		if (svc_sendreply(transp, xdr_rex_result, (char *)&result)
		    == FALSE) {
			fprintf(stderr, "rexd: reply failed\n");
			rex_cleanup();
			exit(1);
		}

		if (Debug)
			printf("svc_sendreply: suceeded\n");

		if (result.rlt_stat) {

			rex_cleanup();
			exit(0);
		}
		return;

	case REXPROC_MODES:
		{
			struct rex_ttymode mode;

			if (Debug) /*	XXX	*/
				printf("dorex: call to REXPROC_MODES\n");

			if (svc_getargs(transp, xdr_rex_ttymode,
					(char *)&mode) == FALSE) {
				svcerr_decode(transp);
				exit(1);
			}
			if (Debug)
				printf("svc_getargs succ REXPROC_MODES call\n");

			SetPtyMode(&mode); /* XXX	Fix?	*/

			if (svc_sendreply(transp, xdr_void, 0) == FALSE) {

				fprintf(stderr, "rexd: mode reply failed");
				exit(1);
			}
		}
		return;

	case REXPROC_WINCH: /* XXX	Fix?	*/
		{
			struct rex_ttysize size;

			if (Debug) /*	XXX	*/
				printf("dorex: call to REXPROC_WINCH\n");

			if (svc_getargs(transp, xdr_rex_ttysize, (char *)&size)
			    == FALSE) {
				svcerr_decode(transp);
				exit(1);
			}

			SetPtySize(&size);

			if (svc_sendreply(transp, xdr_void, 0) == FALSE) {

				fprintf(stderr,
					"rexd: window change reply failed");
				exit(1);
			}
		}
		return;

	case REXPROC_SIGNAL:
		{
			int sigNumber;

			if (Debug) /*	XXX	*/
				printf("dorex: call to REXPROC_SIGNAL\n");

			if (svc_getargs(transp, xdr_int,
					(char *)&sigNumber) == FALSE) {
				svcerr_decode(transp);
				exit(1);
			}

			SendSignal(sigNumber);

			if (svc_sendreply(transp, xdr_void, 0) == FALSE) {
				fprintf(stderr, "rexd: signal reply failed");
				exit(1);
			}
		}
		return;

	case REXPROC_WAIT:
		if (Debug)	/*	XXX	*/
			printf("dorex: call to REXPROC_WAIT\n");

		result.rlt_stat = rex_wait(&result.rlt_message);

		if (svc_sendreply(transp, xdr_rex_result, (char *)&result)
		    == FALSE) {
			fprintf(stderr, "rexd: reply failed\n");
			exit(1);
		}

		rex_cleanup();
		exit(0);

		/* NOTREACHED */
	default:
		if (Debug)
			printf("dorex: call to bad process!\n");

		svcerr_noproc(transp);
		exit(1);
	}
}

/*
 * signal handler for SIGCHLD - called when user process dies or is stopped
 */
void
CatchChild(int junk)
{
	pid_t	pid;
	int	status;

	if (Debug)
		printf("Enter Catchild\n");

	while ((pid = waitpid((pid_t)-1, &status, WNOHANG|WUNTRACED)) > 0) {

		if (Debug) printf("After waitpid\n");
		if (pid == child) {
			if (Debug)
				printf("pid==child\n");
			if (WIFSTOPPED(status)) {
				sigset_t nullsigset;

				if (Debug)
					printf("WIFSTOPPED\n");
				/* tell remote client to stop */
				send(OutputSocket, "", 1, MSG_OOB);

				sigemptyset(&nullsigset);
				/* port of BSD sigpause(0); */
				sigsuspend(&nullsigset);
				/* restart child */
				/* killpg() of SunOS 4.1.1 */
				kill((-child), SIGCONT);
				return;
			}

			/*
			 * XXX this probably does not cover all interesting
			 * exit cases hence reread the man page to determine
			 * if we need more data or more test cases
			 */

			ChildStatus = status;
			ChildDied = 1;

			if (HasHelper && svc_pollfd[Master].fd == -1) {
				if (Debug)
					printf("Within If HasHelper\n");
				KillHelper(child);
				HasHelper = 0;
			}
		}
	}
}

/*
 * oob -- called when we should restart the stopped child.
 */
void
oob(int junk)
{
	int atmark;
	char waste[BUFSIZ], mark;

	for (;;) {

		if (ioctl(OutputSocket, SIOCATMARK, &atmark) < 0) {
			perror("ioctl");
			break;
		}

		if (atmark)
			break;

		(void) read(OutputSocket, waste, sizeof (waste));
	}

	(void) recv(OutputSocket, &mark, 1, MSG_OOB);
}

/*
 * rex_wait - wait for command to finish, unmount the file system,
 * and return the exit status.
 * message gets an optional string error message.
 */
int
rex_wait(message)
char **message;
{
	static char error[1024];
	int count;

	*message = error;
	strcpy(error, "");
	if (child == 0) {
		errprintf(error, "No process to wait for!\n");
		rex_cleanup();
		return (1);
	}

	kill(child, SIGHUP);

	for (count = 0; !ChildDied && count < WaitLimit; count++)
		sleep(1);

	if (ChildStatus & 0xFF)
		return (ChildStatus);

	return (ChildStatus >> 8);
}


/*
 * cleanup - unmount and remove our temporary directory
 */
void
rex_cleanup()
{

	if (tmpdir) {

		if (child && !ChildDied) {

			fprintf(stderr,
				"rexd: child killed to unmount %s\r\n",
				nfsdir);
			kill(child, SIGKILL);
		}
		chdir("/");

		if (nfsdir[0] && umount_nfs(nfsdir, tmpdir))
			fprintf(stderr, "rexd: couldn't umount %s from %s\r\n",
				nfsdir,
				tmpdir);
		if (rmdir(tmpdir) < 0)
			if (errno != EBUSY)
				perror("rmdir");
		tmpdir = NULL;

	}

	if (Debug)
		printf("rex_cleaup: HasHelper=%d\n", HasHelper);
	if (HasHelper)
		KillHelper(child);

	HasHelper = 0;
}


/*
 * This function does the server work to get a command executed
 * Returns 0 if OK, nonzero if error
 */
int
rex_startup(rst, ucred, message, calleraddr)
struct rex_start *rst;
struct authunix_parms *ucred;
char **message;
struct sockaddr_in *calleraddr;
{
	char hostname[255];
	char *p, *wdhost, *fsname, *subdir;
	char dirbuf[1024];
	static char error[1024];
	char defaultShell[1024]; /* command executed if none given */
	char defaultDir[1024];	/* directory used if none given */
	int len;
	int fd0, fd1, fd2;
	extern pam_handle_t *pamh;
	char *user = NULL;

	if (Debug)
		printf("Beginning of Rex_Startup\n");

	if (child) {		/* already started */
		if (Debug)
			printf("Killing \"child\" process\n");
		kill((-child), SIGKILL); /* killpg() of SunOS 4.1.1 */
		return (1);
	}


	*message = error;
	(void) strcpy(error, "");
/*	sigset(SIGCHLD, CatchChild); */


	if (ValidUser(ucred->aup_machname,
		(uid_t)ucred->aup_uid,
		(gid_t)ucred->aup_gid,
		error,
		defaultShell, defaultDir, rst))
		return (1);

	if (rst->rst_fsname && strlen(rst->rst_fsname)) {
		fsname = rst->rst_fsname;
		subdir = rst->rst_dirwithin;
		wdhost = rst->rst_host;
	} else {
		fsname = defaultDir;
		subdir = "";
		wdhost = hostname;
	}

	sysinfo(SI_HOSTNAME, hostname, 255);

	if (Debug)
		printf("rexd: errno %d after gethostname\n", errno);

	if (Debug) {
		printf("rex_startup on host %s:\nrequests fsname=%s",
			hostname, fsname);
		printf("\t\tsubdir=%s\t\twdhost=%s\n", subdir, wdhost);
	}
	if (strcmp(wdhost, hostname) == 0) {

		/*
		 * The requested directory is local to our machine,
		 * so just change to it.
		 */
		strcpy(dirbuf, fsname);
	} else {

		static char wanted[1024];
		static char mountedon[1024];

		strcpy(wanted, wdhost);
		strcat(wanted, ":");
		strcat(wanted, fsname);

		if (AlreadyMounted(wanted, mountedon)) {

			if (Debug)
				printf("AlreadyMounted (%d)\n", errno);

			/*
			 * The requested directory is already mounted.  If the
			 * mount is not by another rexd, just change to it.
			 * Otherwise, mount it again.  If just changing to
			 * the mounted directy, be careful. It might be mounted
			 * in a different place.
			 * (dirbuf is modified in place!)
			 */
			if (strncmp(mountedon, TempName, TempMatch) == 0) {
				tmpdir = mktemp(TempName);
				/*
				 * XXX errno is set to ENOENT on success
				 * of mktemp because of accesss checks for file
				 */
				if (errno == ENOENT)
					errno = 0;

				if (mkdir(tmpdir, 0777)) {
					perror("Already Mounted");
					if (pamh) {
						pam_end(pamh, PAM_ABORT);
						pamh = NULL;
					}
					return (1);
				}

				if (Debug)
					printf("created %s (%d)\n",
						tmpdir, errno);

				strcpy(nfsdir, wanted);

				if (mount_nfs(wanted, tmpdir, error)) {
					if (Debug)
					printf("mount_nfs:error return\n");
					if (pamh) {
						pam_end(pamh, PAM_ABORT);
						pamh = NULL;
					}
					return (1);
				}
				if (Debug)
					printf("mount_nfs: success return\n");

				strcpy(dirbuf, tmpdir);

			} else
				strcpy(dirbuf, mountedon);

		} else {
			if (Debug)
				printf("not AlreadyMounted (%d)\n", errno);
			/*
			 * The requested directory is not mounted anywhere,
			 * so try to mount our own copy of it.  We set nfsdir
			 * so that it gets unmounted later, and tmpdir so that
			 * it also gets removed when we are done.
			 */
			tmpdir = mktemp(TempName);

			/*
			 * XXX errno is set to ENOENT on success of mktemp
			 * becuase of accesss checks for file
			 */
			if (errno == ENOENT)
				errno = 0;
			if (mkdir(tmpdir, 0777)) {
				perror("Not Already Mounted");
				if (pamh) {
					pam_end(pamh, PAM_ABORT);
					pamh = NULL;
				}
				return (1);
			}

			if (Debug)
				printf("created %s (%d)\n", tmpdir, errno);

			strcpy(nfsdir, wanted);

			if (mount_nfs(wanted, tmpdir, error)) {
				if (Debug)
					printf("mount_nfs:error return\n");
				if (pamh) {
					pam_end(pamh, PAM_ABORT);
					pamh = NULL;
				}
				return (1);
			}
			if (Debug)
				printf("mount_nfs: success return\n");
			strcpy(dirbuf, tmpdir);
		}
	}

	/*
	 * "dirbuf" now contains the local mount point, so just tack on
	 * the subdirectory to get the pathname to which we "chdir"
	 */
	strcat(dirbuf, subdir);


	fd0 = socket(AF_INET, SOCK_STREAM, 0);
	if (Debug)
		printf("Before doconnect\n");
	fd0 = doconnect(calleraddr, rst->rst_port0, fd0);
	OutputSocket = fd0;

	/*
	 * Arrange for fd0 to send the SIGURG signal when out-of-band data
	 * arrives, which indicates that we should send the stopped child a
	 * SIGCONT signal so that we can resume work.
	 */
	(void) fcntl(fd0, F_SETOWN, getpid());
	/*	ioctl(fd0, SIOCSPGRP, ?X?); */
	sigset(SIGURG, oob);

	if (Debug)
		printf("Before \"use same port\"\n");
	if (rst->rst_port0 == rst->rst_port1) {
		/*
		 * use the same connection for both stdin and stdout
		 */
		fd1 = fd0;
	}

	if (rst->rst_flags & REX_INTERACTIVE) {
		/*
		 * allocate a pseudo-terminal if necessary
		 */
		if (Debug)
			printf("Before AllocatePty call\n");

		/* AllocatePty has grantpt() call which has bug */
		/* Hence clear SIGCHLD handler setting */
		sigset(SIGCHLD, SIG_DFL);
		if (AllocatePty(fd0, fd1)) {
			errprintf(error, "rexd: cannot allocate a pty\n");
			if (pamh) {
				pam_end(pamh, PAM_ABORT);
				pamh = NULL;
			}
			return (1);
		}
		HasHelper = 1;
	}
	/*
	 * this sigset()call moved to after AllocatePty() call
	 * because a bug in waitpid() inside grantpt()
	 * causes CatchChild() to be invoked.
	 */

	sigset(SIGCHLD, CatchChild);

	if (rst->rst_flags & REX_INTERACTIVE) {
		sigset(SIGWINCH, sigwinch); /* a dummy signal handler */
		/* block the sigpause until signal in */
		/* child releases the signal */
		sighold(SIGWINCH);
	}

	if (Debug)
		printf("Before a \"child\" fork\n");

	child = fork();

	if (child < 0) {
		errprintf(error, "rexd: can't fork\n");
		if (pamh) {
			pam_end(pamh, PAM_ABORT);
			pamh = NULL;
		}
		return (1);
	}

	if (child) {
		/*
		 * parent rexd: close network connections if needed,
		 * then return to the main loop.
		 */
		if ((rst->rst_flags & REX_INTERACTIVE) == 0) {
			close(fd0);
			close(fd1);
		}
		if (Debug)
			printf("Parent ret to main loop, child does startup\n");
		if (pamh) {
			pam_end(pamh, PAM_SUCCESS);
			pamh = NULL;
		}
		return (0);
	}

	/* child rexd */

	if (Debug)
		printf("Child rexd\n");

	/* setpgrp(0, 0) */
	setsid();		/* make session leader */

	if (Debug)
		printf("After setsid\n");

	if (rst->rst_flags & REX_INTERACTIVE) {
		if (Debug)
			printf("Before OpenPtySlave\n");
		/* reopen slave so that child has controlling tty */
		OpenPtySlave();
		if (Debug)
			printf("After OpenPtySlave\n");
	}

	if (rst->rst_port0 != rst->rst_port1) {

		if (Debug)
			printf("rst_port0 != rst_port1\n"); /*	XXX	*/

		fd1 = socket(AF_INET, SOCK_STREAM, 0);
		shutdown(fd0, 1); /* 1=>further sends disallowed */
		fd1 = doconnect(calleraddr, rst->rst_port1, fd1);
		shutdown(fd1, 0); /* 0=>further receives disallowed */
	}

	if (rst->rst_port1 == rst->rst_port2) {
		if (Debug)
			printf("rst_port1 == rst_port2\n"); /*	XXX	*/

		/*
		 * Use the same connection for both stdout and stderr
		 */
		fd2 = fd1;
	} else {
		if (Debug)
			printf("rst_port1 != rst_port2\n"); /*	XXX	*/

		fd2 = socket(AF_INET, SOCK_STREAM, 0);
		fd2 = doconnect(calleraddr, rst->rst_port2, fd2);
		shutdown(fd2, 0); /* 0=>further receives disallowed */
	}

	if (rst->rst_flags & REX_INTERACTIVE) {

		/*
		 * use ptys instead of sockets in interactive mode
		 */
		DoHelper(&fd0, &fd1, &fd2);
		LoginUser();
	}

	dup2(fd0, 0);
	dup2(fd1, 1);
	dup2(fd2, 2);

	/* setup terminal ID (use read file descriptor) */
	if (audit_settid(fd0) != 0) {
		errprintf("cannot set audit characteristics\n");
		return (1);
	}

	closefrom(3);

	if (Debug)
		printf("After close-all-fds-loop-- errno=%d\n", errno);

	environ = rst->rst_env;

	if (pam_get_item(pamh, PAM_USER, (void **)&user) != PAM_SUCCESS) {
		audit_rexd_fail("user id is not valid",
				ucred->aup_machname,
				user,
				ucred->aup_uid,
				ucred->aup_gid,
				defaultShell,
				rst->rst_cmd);	    /* BSM */
		fprintf(stderr, "rexd: invalid uid/gid.\n");
		exit(1);
	}

	/* set the real (and effective) GID */
	if (setgid(ucred->aup_gid) == -1) {
		fprintf(stderr, "rexd: invalid gid.\n");
		exit(1);
	}
	/* Set the supplementary group access list. */
	if (setgroups(ucred->aup_len, (gid_t *)ucred->aup_gids) == -1) {
		fprintf(stderr, "rexd: invalid group list.\n");
		exit(1);
	}

	if (pam_setcred(pamh, PAM_ESTABLISH_CRED) != PAM_SUCCESS) {
		audit_rexd_fail("user id is not valid",
				ucred->aup_machname,
				user,
				ucred->aup_uid,
				ucred->aup_gid,
				defaultShell,
				rst->rst_cmd);	    /* BSM */
		fprintf(stderr, "rexd: invalid uid/gid.\n");
		exit(1);
	}

	audit_rexd_success(ucred->aup_machname,
				user,
				ucred->aup_uid,
				ucred->aup_gid,
				defaultShell,
				rst->rst_cmd);	/* BSM */

	/* set the real (and effective) UID */
	if (setuid(ucred->aup_uid) == -1) {
		fprintf(stderr, "rexd: invalid uid.\n");
		exit(1);
	}

	if (pamh) {
		pam_end(pamh, PAM_SUCCESS);
		pamh = NULL;
	}

	if (Debug)	/*	XXX	*/
		fprintf(stderr, "uid %d gid %d (%d)\n",
			ucred->aup_uid, ucred->aup_gid, errno);

	if (chdir(dirbuf)) {
		fprintf(stderr, "rexd: can't chdir to %s\n", dirbuf);
		exit(1);
	}

	sigset(SIGINT, SIG_DFL);
	sigset(SIGHUP, SIG_DFL);
	sigset(SIGQUIT, SIG_DFL);

	if (rst->rst_flags & REX_INTERACTIVE) {
		/* pause to sync with first SIGWINCH sent as part of */
		sigpause(SIGWINCH);
		/* protocol and handled by parent doing other rex primitves */
		sigrelse(SIGWINCH);
		sigset(SIGWINCH, SIG_DFL);
	}

	if (rst->rst_cmd == (char **)NULL) {

		/*
		 * Null command means execute the default shell for this user
		 */
		char *args[2];

		args[0] = defaultShell;
		args[1] = NULL;

		execvp(defaultShell, args);

		fprintf(stderr, "rexd: can't exec shell %s\n", defaultShell);
		exit(1);
	}

	if (Debug)
		for (len = 0; rst->rst_cmd[len] != (char *)NULL &&
			*rst->rst_cmd[len] != NULL; len++)
			printf("cmds: %s (%d)\n", rst->rst_cmd[len], errno);


	/*	XXX	*/
	if (Debug)
		for (len = 0; rst->rst_env[len] != (char *)NULL &&
			*rst->rst_env[len] != NULL; len++)
			printf("envs: %s\n", rst->rst_env[len]);


	execvp(rst->rst_cmd[0], rst->rst_cmd);

	/*	XXX	get rid of errno in parens	*/
	fprintf(stderr, "rexd: can't exec %s (%d)\n", *rst->rst_cmd, errno);
	exit(1);
}

/*
 * Search the mount table to see if the given file system is already
 * mounted.  If so, return the place that it is mounted on.
 */
int
AlreadyMounted(fsname, mountedon)
char *fsname;
char *mountedon;
{
	FILE		*table;
	struct mnttab	 mt;

	table = setmntent(MOUNTED, "r");
	if (table == NULL)
		return (0);

	while ((getmntent(table, &mt)) != (-1)) {

		if (strcmp(mt.mnt_special, fsname) == 0) {
			strcpy(mountedon, mt.mnt_mountp);
			endmntent(table);
			return (1);
		}
	}
	endmntent(table);

	return (0);
}


/*
 * connect to the indicated IP address/port, and return the
 * resulting file descriptor.
 */
int
doconnect(sin, port, fd)
struct sockaddr_in *sin;
short port;
int fd;
{
	sin->sin_port = ntohs(port);

	if (connect(fd, (struct sockaddr *)sin, sizeof (*sin))) {

		perror("rexd: connect");
		exit(1);
	}

	return (fd);
}

void
sigwinch(int junk)
{
}

/*
 *  SETPROCTITLE -- set the title of this process for "ps"
 *
 *	Does nothing if there were not enough arguments on the command
 *	line for the information.
 *
 *	Side Effects:
 *		Clobbers argv[] of our main procedure.
 */
void
setproctitle(user, host)
char *user, *host;
{
	register char *tohere;

	tohere = Argv[0];
	if ((int)(LastArgv == NULL) ||
	    (int)(strlen(user)+strlen(host)+3) >
	    (int)(LastArgv - tohere))
		return;

	*tohere++ = '-';		/* So ps prints (rpc.rexd)	*/
	sprintf(tohere, "%s@%s", user, host);
	while (*tohere++)		/* Skip to end of printf output	*/
		;
	while (tohere < LastArgv)	/* Avoid confusing ps		*/
		*tohere++ = ' ';
}


/*
 * Determine if started from inetd or not
 */

int
isfrominetd(fd)
int fd;
{
	/*
	 * If fd looks like a TLI endpoint, we assume
	 * that we were started by a port monitor. If
	 * t_getstate fails with TBADF, this is not a
	 * TLI endpoint.
	 */
	if (t_getstate(0) != -1 || t_errno != TBADF)
		return (1);
	return (0);
}
