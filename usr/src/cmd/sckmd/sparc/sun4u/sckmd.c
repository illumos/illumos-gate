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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * sckmd - Starcat Key Management Daemon
 *
 * The sckmd is a daemon that runs on a domain and is responsible for
 * establishing security associations (SAs) for secure communication
 * with the System Controller (SC). All SAs are created on the SC
 * and propogated to the sckmd through the sckm driver running on
 * the domain. The sckmd then passes the SA to the key engine via the
 * PF_KEY interface.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/times.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <net/pfkeyv2.h>
#include <netinet/in.h>
#include <ipsec_util.h>

#include <sys/sckm_io.h>


#ifdef SCKMD_DEBUG
#define	OPT_STR	"ds"
#else /* SCKMD_DEBUG */
#define	OPT_STR	""
#endif /* SCKMD_DEBUG */

#define	KM_DEV	"/dev/kmdrv"

#define	SCKMD_MAX_MSG_SIZE	1024
#define	SCKMD_ERR_MSG_SIZE	512
#define	SCKMD_MSG_HDR_SIZE	sizeof (struct sadb_msg)

#define	SCKMD_CURR_PFKEY_VER	PF_KEY_V2
#define	SCKMD_PFKEY_TIMEOUT	3000	/* 3 seconds */


static pid_t mypid;
static int standalone;
static int debug;
static int keysock;
static uint32_t seq = 0;
static uint64_t msg_buf[SCKMD_MAX_MSG_SIZE];


static int process_sckm_req(int fd, sckm_ioctl_getreq_t *msg);
static int send_sckm_status(int fd, sckm_ioctl_status_t *msg);
static int get_pfkey_reply(uint32_t req_seq, uint8_t req_type, int *err);
static struct sadb_msg *read_pfkey_msg(void);
static int convert_pfkey_msg(struct sadb_msg *msg);
static void sckmd_log(int priority, char *fmt, ...);


/*
 * main:
 *
 * Initialize sckmd and enter an infinite loop. The loop waits for
 * sckm messages from the sckm driver and dispatches each message
 * to be processed synchronously.
 */
int
main(int argc, char **argv)
{
	int			opt;
	int			fd;
	sckm_ioctl_getreq_t	msg;


	/*
	 * Set defaults
	 */
	standalone = 0;
	debug = 0;
	mypid = getpid();

	openlog("sckmd", LOG_CONS | LOG_NDELAY, LOG_DAEMON);

	/*
	 * Check command line options
	 */
	opterr = 0;	/* disable getopt error messages */
	while ((opt = getopt(argc, argv, OPT_STR)) != EOF) {

		switch (opt) {

		case 'd':
			debug++;
			break;

		case 's':
			standalone++;
			break;

		default:
			sckmd_log(LOG_ERR, "unknown command line option\n");
			exit(1);
		}
	}

	sckmd_log(LOG_DEBUG, "starting sckmd...\n");

	/*
	 * IPsec must get loaded in-kernel.  The easiest way to do this is
	 * to open (then close) a PF_KEY socket.
	 */
	if ((keysock = socket(PF_KEY, SOCK_RAW, SCKMD_CURR_PFKEY_VER)) == -1) {
		sckmd_log(LOG_DEBUG, "PF_KEY open for IPsec load failed: %s\n",
		    strerror(errno));
		exit(1);
	}
	(void) close(keysock);
	sckmd_log(LOG_ERR, "PF_KEY socket for IPsec load succeeded.\n");

	/* must be root */
	if (geteuid() != 0) {
		sckmd_log(LOG_ERR, "must run as root\n");
		exit(1);
	}

	if (standalone == 0) {

		int	i;

		for (i = 0; i < NOFILE; i++) {
			(void) close(i);
		}

		(void) chdir("/");
		(void) umask(0);
		if (fork() != 0) {
			exit(0);
		}
		(void) setpgrp();

		/* reinitialize syslog after closing all fds */
		openlog("sckmd", LOG_CONS | LOG_NDELAY, LOG_DAEMON);
	}

	/* open driver */
	if ((fd = open(KM_DEV, O_RDONLY)) == -1) {
		sckmd_log(LOG_ERR, "error initializing km driver: %s\n",
		    strerror(errno));
		exit(1);
	}

	/*
	 * Main processing loop
	 */
	for (;;) {

		/* initialize the ioctl request */
		(void) memset(&msg, 0, sizeof (sckm_ioctl_getreq_t));
		msg.buf = (caddr_t)msg_buf;
		(void) memset(&msg_buf, 0, SCKMD_MAX_MSG_SIZE);
		msg.buf_len = SCKMD_MAX_MSG_SIZE;

		/* wait for the next message */
		if (ioctl(fd, SCKM_IOCTL_GETREQ, &msg) == -1) {
			sckmd_log(LOG_ERR, "failed to receive sckm message: "
			    "%s\n", strerror(errno));
			continue;
		}

		/* pass the message to pf_key */
		if (process_sckm_req(fd, &msg) == -1) {
			sckmd_log(LOG_DEBUG, "error processing sckm message\n");
			continue;
		}
	}

	/*NOTREACHED*/
	return (0);
}


/*
 * process_sckm_req:
 *
 * Process a sckm request message. If the message is valid, pass the
 * included SADB message to PF_KEY and return status to the sckm driver.
 * The function only fails if it is unable to return a status message
 * to the driver.
 */
static int
process_sckm_req(int fd, sckm_ioctl_getreq_t *msg)
{
	sckm_ioctl_status_t	reply;
	struct sadb_msg		*pfkey_msg;
	unsigned int		msg_ver;
	unsigned int		msg_type;
	unsigned int		msg_len;
	int			err;


	if (msg == NULL) {
		sckmd_log(LOG_ERR, "invalid message\n");
		return (-1);
	}

	/* initialize a reply message */
	(void) memset(&reply, 0, sizeof (sckm_ioctl_status_t));
	reply.transid = msg->transid;

	/* currently, we only support sadb messages */
	if (msg->type != SCKM_IOCTL_REQ_SADB) {
		sckmd_log(LOG_ERR, "unsupported message type (%d)\n",
		    msg->type);
		reply.status = SCKM_IOCTL_STAT_ERR_REQ;
		return (send_sckm_status(fd, &reply));
	}

	/* check that we have at least the sadb header */
	if (msg->buf_len < sizeof (struct sadb_msg)) {
		sckmd_log(LOG_ERR, "incomplete sadb message received\n");
		reply.status = SCKM_IOCTL_STAT_ERR_REQ;
		return (send_sckm_status(fd, &reply));
	}

	/* LINTED Pointer Cast Alignment Warning */
	pfkey_msg = (struct sadb_msg *)msg->buf;
	msg_ver = pfkey_msg->sadb_msg_version;
	msg_len = SADB_64TO8(pfkey_msg->sadb_msg_len);
	msg_type = pfkey_msg->sadb_msg_type;

	/* check for an unsupported PF_KEY version */
	if ((msg_ver > SCKMD_CURR_PFKEY_VER) || (msg_ver < PF_KEY_V2)) {

		sckmd_log(LOG_ERR, "unsupported PF_KEY version (%d)\n",
		    msg_ver);
		reply.status = SCKM_IOCTL_STAT_ERR_VERSION;
		reply.sadb_msg_version = SCKMD_CURR_PFKEY_VER;
		return (send_sckm_status(fd, &reply));
	}

	/* convert the PF_KEY message if necessary */
	if (msg_ver != SCKMD_CURR_PFKEY_VER) {

		if (convert_pfkey_msg(pfkey_msg) == -1) {
			reply.status = SCKM_IOCTL_STAT_ERR_VERSION;
			reply.sadb_msg_version = SCKMD_CURR_PFKEY_VER;
			return (send_sckm_status(fd, &reply));
		}
	}

	/*
	 * Process the PF_KEY message
	 */
	pfkey_msg->sadb_msg_seq = ++seq;
	pfkey_msg->sadb_msg_pid = mypid;

	switch (msg_type) {

	case SADB_UPDATE:
	case SADB_ADD:
	case SADB_DELETE:

		/*
		 * Only update, add, and delete are supported. Pass the
		 * message directly to PF_KEY.
		 */
		break;

	default:
		sckmd_log(LOG_ERR, "received unsupported operation "
		    "from client (%d)\n", msg_type);
		reply.status = SCKM_IOCTL_STAT_ERR_SADB_TYPE;
		return (send_sckm_status(fd, &reply));
	}

	/* initialize global key socket */
	if ((keysock = socket(PF_KEY, SOCK_RAW, SCKMD_CURR_PFKEY_VER)) == -1) {
		sckmd_log(LOG_ERR, "error initializing PF_KEY socket: %s\n",
		    strerror(errno));
		reply.status = SCKM_IOCTL_STAT_ERR_OTHER;
		return (send_sckm_status(fd, &reply));
	}

	/* send the PF_KEY message */
	if (write(keysock, pfkey_msg, msg_len) != msg_len) {
		sckmd_log(LOG_ERR, "PF_KEY write failed\n");
		reply.status = SCKM_IOCTL_STAT_ERR_OTHER;
		close(keysock);
		return (send_sckm_status(fd, &reply));
	}

	/* wait for key engine reply */
	if (get_pfkey_reply(pfkey_msg->sadb_msg_seq, msg_type, &err) == -1) {
		reply.status = err;
		if (err == SCKM_IOCTL_STAT_ERR_PFKEY) {
			reply.sadb_msg_errno = errno;
		}
	} else {
		sckmd_log(LOG_DEBUG, "PF_KEY operation succeeded\n");
		reply.status = SCKM_IOCTL_STAT_SUCCESS;
	}

	close(keysock);
	return (send_sckm_status(fd, &reply));
}


/*
 * send_sckm_status:
 *
 * Send a sckm status message to the sckm driver
 */
static int
send_sckm_status(int fd, sckm_ioctl_status_t *msg)
{
	if (ioctl(fd, SCKM_IOCTL_STATUS, msg) == -1) {
		sckmd_log(LOG_ERR, "error sending sckm status message: %s\n",
		    strerror(errno));
		return (-1);
	}

	return (0);
}


/*
 * get_pfkey_reply:
 *
 * Wait for a reply from PF_KEY. Get the reply from the socket using
 * the global file desciptor 'keysock'. If PF_KEY returns an error,
 * the global errno is set to the error returned in the reply message.
 * If an error occurs, the parameter 'err' is set to one of the error
 * codes prefixed by SCKM_IOCTL_STAT_ERR to indicate the overall status
 * of the operation.
 */
static int
get_pfkey_reply(uint32_t req_seq, uint8_t req_type, int *err)
{
	int		timeout;
	int		pollstatus;
	clock_t		before;
	clock_t		after;
	double		diff;
	struct tms	unused;
	struct pollfd	pfd;
	struct sadb_msg *msg;

	static char *pfkey_msg_type[] = {
		"RESERVED",
		"GETSPI",
		"UPDATE",
		"ADD",
		"DELETE",
		"GET",
		"ACQUIRE",
		"REGISTER",
		"EXPIRE",
		"FLUSH",
		"DUMP",
		"X_PROMISC",
		"X_INVERSE_ACQUIRE",
	};


	sckmd_log(LOG_DEBUG, "waiting for key engine reply\n");

	timeout = SCKMD_PFKEY_TIMEOUT;

	pfd.fd = keysock;
	pfd.events = POLLIN;

	while (timeout > 0) {

		before = times(&unused);

		pfd.revents = 0;
		pollstatus = poll(&pfd, 1, timeout);

		/* check for a timeout */
		if (pollstatus == 0) {
			sckmd_log(LOG_NOTICE, "timed out waiting for PF_KEY "
			    "reply\n");
			*err = SCKM_IOCTL_STAT_ERR_TIMEOUT;
			return (-1);
		}

		/* read in the next PF_KEY message */
		msg = read_pfkey_msg();

		if (msg == NULL) {
			*err = SCKM_IOCTL_STAT_ERR_OTHER;
			return (-1);
		}

		/* check if the message is intended for us */
		if (msg->sadb_msg_seq == req_seq &&
		    msg->sadb_msg_pid == mypid) {
			break;
		}

		after = times(&unused);

		diff = (double)(after - before)/(double)CLK_TCK;
		timeout -= (int)(diff * 1000);
	}

	/* check for a timeout */
	if (timeout <= 0) {
		sckmd_log(LOG_NOTICE, "timed out waiting for PF_KEY "
		    "reply\n");
		*err = SCKM_IOCTL_STAT_ERR_TIMEOUT;
		return (-1);
	}

	/* did we get what we were expecting? */
	if (msg->sadb_msg_type != req_type) {
		sckmd_log(LOG_ERR, "unexpected message type from PF_KEY: %d\n",
		    msg->sadb_msg_type);
		*err = SCKM_IOCTL_STAT_ERR_OTHER;
		return (-1);
	}

	/*
	 * Check for errors in SADB message, but ignore the
	 * ESRCH error for DELETE operation. This can happen if the SP
	 * sends a DELETE request first before sending the ADD
	 * request, just to make sure the keys are installed without a failure.
	 */
	if ((msg->sadb_msg_errno != 0) && !((msg->sadb_msg_errno == ESRCH) &&
	    (msg->sadb_msg_type == SADB_DELETE))) {

		char	   unknown_type_str[16];
		int	   unknown_type = 0;
		int	   arr_sz;
		const char *diagnostic_str;

		arr_sz  = sizeof (pfkey_msg_type) / sizeof (*pfkey_msg_type);

		/* generate unknown type string, if necessary */
		if (msg->sadb_msg_type >= arr_sz) {
			(void) snprintf(unknown_type_str,
			    sizeof (unknown_type_str), "UNKNOWN-%d",
			    msg->sadb_msg_type);
			unknown_type = 1;
		}

		/* use libipsecutil to lookup the SADB diagnostic string */
		diagnostic_str = keysock_diag(msg->sadb_x_msg_diagnostic);

		sckmd_log(LOG_ERR, "PF_KEY error: type=%s, errno=%d: %s, "
		    "diagnostic code=%d: %s\n",
		    (unknown_type) ? unknown_type_str :
		    pfkey_msg_type[msg->sadb_msg_type],
		    msg->sadb_msg_errno, strerror(msg->sadb_msg_errno),
		    msg->sadb_x_msg_diagnostic, diagnostic_str);

		*err = SCKM_IOCTL_STAT_ERR_PFKEY;
		errno = msg->sadb_msg_errno;
		return (-1);
	}

	return (0);
}


/*
 * read_pfkey_msg:
 *
 * Get a PF_KEY message from the socket using the global file descriptor
 * 'keysock'. Data is stored in the global buffer 'msg_buf'. The function
 * returns a pointer to the next PF_KEY message. Note that this is not
 * necessarily at the start of 'msg_buf'. NULL is returned for errors.
 */
static struct sadb_msg *
read_pfkey_msg(void)
{
	static uint64_t	*offset;
	static int	len;
	struct sadb_msg	*retval;


	/* Assume offset and len are initialized to NULL and 0 */

	if ((offset == NULL) || (offset - len == msg_buf)) {
		/* read a new block from the socket. */
		len = read(keysock, &msg_buf, sizeof (msg_buf));

		if (len == -1) {
			sckmd_log(LOG_ERR, "PF_KEY read: %s\n",
			    strerror(errno));

			offset = NULL;
			return (NULL);
		}
		offset = msg_buf;
		len = SADB_8TO64(len);
	}

	retval = (struct sadb_msg *)offset;
	offset += retval->sadb_msg_len;

	if (offset > msg_buf + len) {
		sckmd_log(LOG_ERR, "PF_KEY read: message corruption, "
		    "message length %d exceeds boundary %d\n",
		    SADB_64TO8(retval->sadb_msg_len),
		    SADB_64TO8((msg_buf + len) - (uint64_t *)retval));

		offset = NULL;
		return (NULL);
	}

	return (retval);
}


/*
 * convert_pfkey_msg:
 *
 * Convert a lower version PF_KEY message to the current version
 * being used by sckmd.
 *
 * Currently, there is only one implemented version of PF_KEY (v2).
 * If future versions are added to the PF_KEY specification (RFC 2367),
 * this function should be updated to provide backwards compatibility
 * with version 2 and above.
 */
static int
convert_pfkey_msg(struct sadb_msg *msg)
{
	sckmd_log(LOG_DEBUG, "PF_KEY conversion necessary...\n");

	switch (msg->sadb_msg_version) {

	case PF_KEY_V2:
		/*
		 * Current supported version:
		 * No conversion required
		 */
		break;
	default:
		sckmd_log(LOG_ERR, "No conversion possible for "
		    "PF_KEY version %d\n", msg->sadb_msg_version);
		return (-1);
	}

	return (0);
}


/*
 * sckmd_log:
 *
 * Log a message using the syslog facility. If sckmd is running in
 * standalone mode (global flag 'standalone' set), messages are also
 * sent to stderr.
 */
static void
sckmd_log(int priority, char *fmt, ...)
{
	va_list	vap;
	char	err[SCKMD_ERR_MSG_SIZE];


	/* if this is a debug message, check if debugging is enabled */
	if ((priority == LOG_DEBUG) && (debug == 0)) {
		return;
	}

	va_start(vap, fmt);
	vsnprintf(err, SCKMD_ERR_MSG_SIZE, fmt, vap);
	va_end(vap);

	/* send message to stderr if in standalone mode */
	if (standalone != 0) {
		fprintf(stderr, err);
	}

	/* always log the message */
	syslog(priority, err);
}
