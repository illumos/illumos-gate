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
 * PPPoE Server-mode daemon for use with Solaris PPP 4.0.
 *
 * Copyright (c) 2000-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <stropts.h>
#include <wait.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <net/sppptun.h>
#include <net/pppoe.h>

#include "common.h"
#include "pppoed.h"
#include "logging.h"

static int tunfd;		/* Global connection to tunnel device */

char *myname;			/* Copied from argv[0] for logging */
static int main_argc;		/* Saved for reparse on SIGHUP */
static char **main_argv;	/* Saved for reparse on SIGHUP */

static time_t time_started;	/* Time daemon was started; for debug */
static time_t last_reread;	/* Last time configuration was read. */

/* Various operational statistics. */
static unsigned long input_packets, padi_packets, padr_packets;
static unsigned long output_packets;
static unsigned long sessions_started;

static sigset_t sigmask;	/* Global signal mask */

/*
 * Used for handling errors that occur before we daemonize.
 */
static void
early_error(const char *str)
{
	const char *cp;

	cp = mystrerror(errno);
	if (isatty(2)) {
		(void) fprintf(stderr, "%s: %s: %s\n", myname, str, cp);
	} else {
		reopen_log();
		logerr("%s: %s", str, cp);
	}
	exit(1);
}

/*
 * Open the sppptun driver.
 */
static void
open_tunnel_dev(void)
{
	struct ppptun_peer ptp;

	tunfd = open(tunnam, O_RDWR);
	if (tunfd == -1) {
		early_error(tunnam);
	}

	/*
	 * Tell the device driver that I'm a daemon handling inbound
	 * connections, not a PPP session.
	 */
	(void) memset(&ptp, '\0', sizeof (ptp));
	ptp.ptp_style = PTS_PPPOE;
	ptp.ptp_flags = PTPF_DAEMON;
	(void) memcpy(ptp.ptp_address.pta_pppoe.ptma_mac, ether_bcast,
	    sizeof (ptp.ptp_address.pta_pppoe.ptma_mac));
	if (strioctl(tunfd, PPPTUN_SPEER, &ptp, sizeof (ptp), sizeof (ptp)) <
	    0) {
		myperror("PPPTUN_SPEER");
		exit(1);
	}
}

/*
 * Callback function for fdwalk.  Closes everything but the tunnel
 * file descriptor when becoming daemon.  (Log file must be reopened
 * manually, since syslog file descriptor, if any, is unknown.)
 */
/*ARGSUSED*/
static int
fdcloser(void *arg, int fd)
{
	if (fd != tunfd)
		(void) close(fd);
	return (0);
}

/*
 * Become a daemon.
 */
static void
daemonize(void)
{
	pid_t cpid;

	/*
	 * A little bit of magic here.  By the first fork+setsid, we
	 * disconnect from our current controlling terminal and become
	 * a session group leader.  By forking again without setsid,
	 * we make certain that we're not the session group leader and
	 * can never reacquire a controlling terminal.
	 */
	if ((cpid = fork()) == (pid_t)-1) {
		early_error("fork 1");
	}
	if (cpid != 0) {
		(void) wait(NULL);
		_exit(0);
	}
	if (setsid() == (pid_t)-1) {
		early_error("setsid");
	}
	if ((cpid = fork()) == (pid_t)-1) {
		early_error("fork 2");
	}
	if (cpid != 0) {
		/* Parent just exits */
		(void) printf("%d\n", (int)cpid);
		(void) fflush(stdout);
		_exit(0);
	}
	(void) chdir("/");
	(void) umask(0);
	(void) fdwalk(fdcloser, NULL);
	reopen_log();
}

/*
 * Handle SIGHUP -- close and reopen non-syslog log files and reparse
 * options.
 */
/*ARGSUSED*/
static void
handle_hup(int sig)
{
	close_log_files();
	global_logging();
	last_reread = time(NULL);
	parse_options(tunfd, main_argc, main_argv);
}

/*
 * Handle SIGINT -- write current daemon status to /tmp.
 */
/*ARGSUSED*/
static void
handle_int(int sig)
{
	FILE *fp;
	char dumpname[MAXPATHLEN];
	time_t now;
	struct rusage rusage;

	(void) snprintf(dumpname, sizeof (dumpname), "/tmp/pppoed.%ld",
	    getpid());
	if ((fp = fopen(dumpname, "w+")) == NULL) {
		logerr("%s: %s", dumpname, mystrerror(errno));
		return;
	}
	now = time(NULL);
	(void) fprintf(fp, "pppoed running %s", ctime(&now));
	(void) fprintf(fp, "Started on     %s", ctime(&time_started));
	if (last_reread != 0)
		(void) fprintf(fp, "Last reconfig  %s", ctime(&last_reread));
	(void) putc('\n', fp);
	if (getrusage(RUSAGE_SELF, &rusage) == 0) {
		(void) fprintf(fp,
		    "CPU usage:  user %ld.%06ld, system %ld.%06ld\n",
		    rusage.ru_utime.tv_sec, rusage.ru_utime.tv_usec,
		    rusage.ru_stime.tv_sec, rusage.ru_stime.tv_usec);
	}
	(void) fprintf(fp, "Packets:  %lu received (%lu PADI, %lu PADR), ",
	    input_packets, padi_packets, padr_packets);
	(void) fprintf(fp, "%lu transmitted\n", output_packets);
	(void) fprintf(fp, "Sessions started:  %lu\n\n", sessions_started);
	dump_configuration(fp);
	(void) fclose(fp);
}

static void
add_signal_handlers(void)
{
	struct sigaction sa;

	(void) sigemptyset(&sigmask);
	(void) sigaddset(&sigmask, SIGHUP);
	(void) sigaddset(&sigmask, SIGCHLD);
	(void) sigaddset(&sigmask, SIGINT);
	(void) sigprocmask(SIG_BLOCK, &sigmask, NULL);

	sa.sa_mask = sigmask;
	sa.sa_flags = 0;

	/* Signals to handle */
	sa.sa_handler = handle_hup;
	if (sigaction(SIGHUP, &sa, NULL) < 0)
		early_error("sigaction HUP");
	sa.sa_handler = handle_int;
	if (sigaction(SIGINT, &sa, NULL) < 0)
		early_error("sigaction INT");

	/*
	 * Signals to ignore.  Ignoring SIGCHLD in this way makes the
	 * children exit without ever creating zombies.  (No wait(2)
	 * call required.)
	 */
	sa.sa_handler = SIG_IGN;
	if (sigaction(SIGPIPE, &sa, NULL) < 0)
		early_error("sigaction PIPE");
	sa.sa_flags = SA_NOCLDWAIT;
	if (sigaction(SIGCHLD, &sa, NULL) < 0)
		early_error("sigaction CHLD");
}

/*
 * Dispatch a message from the tunnel driver.  It could be an actual
 * PPPoE message or just an event notification.
 */
static void
handle_input(uint32_t *ctrlbuf, int ctrllen, uint32_t *databuf, int datalen)
{
	poep_t *poep = (poep_t *)databuf;
	union ppptun_name ptn;
	int retv;
	struct strbuf ctrl;
	struct strbuf data;
	void *srvp;
	boolean_t launch;
	struct ppptun_control *ptc;

	if (ctrllen != sizeof (*ptc)) {
		logdbg("bogus %d byte control message from driver",
		    ctrllen);
		return;
	}
	ptc = (struct ppptun_control *)ctrlbuf;

	/* Switch out on event notifications. */
	switch (ptc->ptc_action) {
	case PTCA_TEST:
		logdbg("test reply for discriminator %X", ptc->ptc_discrim);
		return;

	case PTCA_CONTROL:
		break;

	case PTCA_DISCONNECT:
		logdbg("session %d disconnected on %s; send PADT",
		    ptc->ptc_rsessid, ptc->ptc_name);
		poep = poe_mkheader(pkt_output, POECODE_PADT,
		    ptc->ptc_rsessid);
		ptc->ptc_action = PTCA_CONTROL;
		ctrl.len = sizeof (*ptc);
		ctrl.buf = (caddr_t)ptc;
		data.len = poe_length(poep) + sizeof (*poep);
		data.buf = (caddr_t)poep;
		if (putmsg(tunfd, &ctrl, &data, 0) < 0) {
			logerr("putmsg PADT: %s", mystrerror(errno));
		} else {
			output_packets++;
		}
		return;

	case PTCA_UNPLUMB:
		logdbg("%s unplumbed", ptc->ptc_name);
		return;

	default:
		logdbg("unexpected code %d from driver", ptc->ptc_action);
		return;
	}

	/* Only PPPoE control messages get here. */

	input_packets++;
	if (datalen < sizeof (*poep)) {
		logdbg("incomplete PPPoE message from %s/%s",
		    ehost(&ptc->ptc_address), ptc->ptc_name);
		return;
	}

	/* Server handles only PADI and PADR; all others are ignored. */
	if (poep->poep_code == POECODE_PADI) {
		padi_packets++;
	} else if (poep->poep_code == POECODE_PADR) {
		padr_packets++;
	} else {
		loginfo("unexpected %s from %s",
		    poe_codename(poep->poep_code), ehost(&ptc->ptc_address));
		return;
	}
	logdbg("Recv from %s/%s: %s", ehost(&ptc->ptc_address), ptc->ptc_name,
	    poe_codename(poep->poep_code));

	/* Parse out service and formulate template reply. */
	retv = locate_service(poep, datalen, ptc->ptc_name, &ptc->ptc_address,
	    pkt_output, &srvp);

	/* Continue formulating reply */
	launch = B_FALSE;
	if (retv != 1) {
		/* Ignore initiation if we don't offer a service. */
		if (retv <= 0 && poep->poep_code == POECODE_PADI) {
			logdbg("no services; no reply");
			return;
		}
		if (retv == 0)
			(void) poe_add_str((poep_t *)pkt_output, POETT_NAMERR,
			    "No such service.");
	} else {
		/* Exactly one service chosen; if it's PADR, then we start. */
		if (poep->poep_code == POECODE_PADR) {
			launch = B_TRUE;
		}
	}
	poep = (poep_t *)pkt_output;

	/* Select control interface for output. */
	(void) strncpy(ptn.ptn_name, ptc->ptc_name, sizeof (ptn.ptn_name));
	if (strioctl(tunfd, PPPTUN_SCTL, &ptn, sizeof (ptn), 0) < 0) {
		logerr("PPPTUN_SCTL %s: %s", ptn.ptn_name, mystrerror(errno));
		return;
	}

	/* Launch the PPP service */
	if (launch && launch_service(tunfd, poep, srvp, ptc))
		sessions_started++;

	/* Send the reply. */
	ctrl.len = sizeof (*ptc);
	ctrl.buf = (caddr_t)ptc;
	data.len = poe_length(poep) + sizeof (*poep);
	data.buf = (caddr_t)poep;
	if (putmsg(tunfd, &ctrl, &data, 0) < 0) {
		logerr("putmsg %s: %s", ptc->ptc_name, mystrerror(errno));
	} else {
		output_packets++;
		logdbg("Send to   %s/%s: %s", ehost(&ptc->ptc_address),
		    ptc->ptc_name, poe_codename(poep->poep_code));
	}
}

static void
main_loop(void)
{
	struct strbuf ctrl;
	struct strbuf data;
	int flags;
	int rc;
	int err;

	for (;;) {
		ctrl.maxlen = PKT_OCTL_LEN;
		ctrl.buf = (caddr_t)pkt_octl;
		data.maxlen = PKT_INPUT_LEN;
		data.buf = (caddr_t)pkt_input;
		/* Allow signals only while idle */
		(void) sigprocmask(SIG_UNBLOCK, &sigmask, NULL);
		errno = 0;
		flags = 0;
		rc = mygetmsg(tunfd, &ctrl, &data, &flags);
		err = errno;
		/*
		 * Block signals -- data structures must not change
		 * while we're busy dispatching the client's request
		 */
		(void) sigprocmask(SIG_BLOCK, &sigmask, NULL);
		if (rc == -1) {
			if (err == EAGAIN || err == EINTR)
				continue;
			logerr("%s getmsg: %s", tunnam, mystrerror(err));
			exit(1);
		}
		if (rc > 0)
			logwarn("%s returned truncated data", tunnam);
		else
			handle_input(pkt_octl, ctrl.len, pkt_input, data.len);
	}
}

int
main(int argc, char **argv)
{
	prog_name = "pppoed";
	log_level = 1;		/* Default to error messages only at first */

	time_started = time(NULL);

	if ((myname = argv[0]) == NULL)
		myname = "pppoed";

	main_argc = argc;
	main_argv = argv;

	open_tunnel_dev();
	add_signal_handlers();
	daemonize();

	parse_options(tunfd, argc, argv);
	main_loop();

	return (0);
}
