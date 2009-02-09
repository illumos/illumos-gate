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
 * supporting modules.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sem.h>
#include <sys/poll.h>
#include <wait.h>
#include <time.h>
#include <netinet/in.h>
#include <thread.h>
#include <signal.h>
#include <ctype.h>
#include <langinfo.h>
#include <libintl.h>
#include <syslog.h>
#include "vntsd.h"
#include "chars.h"

/*  vntsd_write_line() - write a line to TCP client */
int
vntsd_write_line(vntsd_client_t *clientp, char *line)
{
	int rv;

	rv = vntsd_write_client(clientp, line, strlen(line));
	if (rv == VNTSD_SUCCESS) {
		rv = vntsd_write_client(clientp, vntsd_eol, VNTSD_EOL_LEN);
	}

	return (rv);
}

/*  vntsd_write_lines() write one or more lines to client.  */
int
vntsd_write_lines(vntsd_client_t *clientp, char *lines)
{
	char	*buf;
	char	*line;
	char 	*endofline;

	buf = strdup(lines);
	if (buf == NULL) {
		return (VNTSD_ERR_NO_MEM);
	}

	line = buf;

	while ((line != NULL) && (*line != '\0')) {

		endofline = strchr(line, '\n');
		if (endofline != NULL) {
			*endofline = '\0';
		}

		(void) vntsd_write_line(clientp, line);

		if (endofline != NULL)
			line = endofline + 1;
		else
			line = NULL;
	}

	free(buf);
	return (VNTSD_SUCCESS);
}

/* vntsd_get_yes_no() -  read in a "y" or "n" */
int
vntsd_get_yes_no(vntsd_client_t *clientp, char *msg, int *yes_no)
{
	char	c;
	char	yesno[8];
	int	rv;

	/* create [y/n] prompt */
	(void) snprintf(yesno, sizeof (yesno), "[%c/%c] ",
	    *nl_langinfo(YESSTR), *nl_langinfo(NOSTR));

	for (; ; ) {
		if ((rv = vntsd_write_client(clientp, msg, strlen(msg)))
		    != VNTSD_SUCCESS) {
			return (rv);
		}

		if ((rv = vntsd_write_client(clientp, yesno, strlen(yesno))) !=
		    VNTSD_SUCCESS) {
			return (rv);
		}

		if ((rv = vntsd_read_data(clientp, &c))
		    != VNTSD_SUCCESS) {
			return (rv);
		}

		/* echo */
		if ((rv = vntsd_write_client(clientp, &c, 1)) !=
		    VNTSD_SUCCESS) {
			return (rv);
		}

		if ((rv = vntsd_write_client(clientp, vntsd_eol,
		    VNTSD_EOL_LEN)) != VNTSD_SUCCESS) {
			return (rv);
		}

		c = tolower(c);

		if (c == *nl_langinfo(YESSTR)) {
			*yes_no = B_TRUE;
			return (VNTSD_SUCCESS);
		}

		if (c == *nl_langinfo(NOSTR)) {
			*yes_no = B_FALSE;
			return (VNTSD_SUCCESS);
		}

		if ((rv = vntsd_write_line(clientp,
		    gettext("Invalid response. Try again.")))
		    != VNTSD_SUCCESS) {
			return (rv);
		}
	}

	/*NOTREACHED*/
	return (0);
}

/* vntsd_open_vcc()  -  open a vcc port */
int
vntsd_open_vcc(char *dev_name, uint_t cons_no)
{
	int	drvfd;
	int	sz;
	char	*path;
	sz = strlen(VCC_DEVICE_PATH) + strlen(dev_name)+1;

	path = calloc(sz, 1);

	if (path == NULL) {
		return (-1);
	}

	(void) snprintf(path, sz-1, VCC_DEVICE_PATH, dev_name);

	for (; ; ) {
		drvfd = open(path, O_RDWR);

		if ((drvfd < 0) && (errno == EAGAIN)) {
			if (vntsd_vcc_ioctl(VCC_FORCE_CLOSE, cons_no, &cons_no)
			    != VNTSD_SUCCESS) {
				break;
			}
		} else {
			break;
		}
	}


	if (drvfd < 0) {
		D1(stderr, "t@%d open_vcc@%s exit\n", thr_self(), dev_name);
		free(path);
		return (-1);
	}

	free(path);
	return (drvfd);
}

/* vntsd_cons_by_consno() - match a console structure to cons no */
boolean_t
vntsd_cons_by_consno(vntsd_cons_t *consp, int *cons_id)
{
	if (consp->status & VNTSD_CONS_DELETED) {
		return (B_FALSE);
	}
	return (consp->cons_no == *cons_id);
}

/* vntsd_write_client() write to telnet client */
int
vntsd_write_client(vntsd_client_t *client, char *buffer, size_t sz)
{
	int rv;


	/* write to client */
	rv = vntsd_write_fd(client->sockfd, buffer, sz);

	/* client has output, reset timer */
	vntsd_reset_timer(client->cons_tid);

	return (rv);
}

/* vntsd_write_fd() write to tcp socket file descriptor  */
int
vntsd_write_fd(int fd, void *buf, size_t sz)
{
	int n;

	while (sz > 0) {
		n = write(fd, buf, sz);
		if (n < 0) {
			if (errno == EINTR) {
				return (VNTSD_STATUS_INTR);
			}

			return (VNTSD_STATUS_CLIENT_QUIT);
		}

		if (n == 0) {
			return (VNTSD_STATUS_CLIENT_QUIT);
		}

		buf =  (caddr_t)buf + n;
		sz -= n;
	}
	return (VNTSD_SUCCESS);

}

/*
 * vntsd_read_char() - read a char from TCP Clienti. Returns:
 * VNTSD_SUCCESS, VNTSD_STATUS_CLIENT_QUIT or VNTSD_STATUS_INTR
 */
int
vntsd_read_char(vntsd_client_t *clientp, char *c)
{
	int		n;
	vntsd_timeout_t tmo;
	int		rv;

	tmo.tid = thr_self();
	tmo.minutes = 0;
	tmo.clientp = clientp;

	/* attach to timer */
	if ((rv = vntsd_attach_timer(&tmo)) != VNTSD_SUCCESS) {
		return (rv);
	}

	n = read(clientp->sockfd, c, 1);

	/* detach from timer */
	if ((rv = vntsd_detach_timer(&tmo)) != VNTSD_SUCCESS) {
		return (rv);
	}

	if (n == 1) {
		return (VNTSD_SUCCESS);
	}

	if (n == 0) {
		return (VNTSD_STATUS_CLIENT_QUIT);
	}

	/*
	 * read error or wake up by signal, either console is being removed or
	 * timeout occurs.
	 */
	if (errno == EINTR) {
		return (VNTSD_STATUS_INTR);
	}

	/* any other error, we close client */
	return (VNTSD_STATUS_CLIENT_QUIT);
}

/*
 * vntsd_read_data() -  handle special commands
 * such as telnet, daemon and ctrl cmds. Returns:
 * from vntsd_read_char:
 *	    VNTSD_STATUS_CLIENT_QUIT
 *	    VNTSD_STATUS_INTR
 * from vnts_process_daemon_cmd:
 *	    VNTSD_STATUS_RESELECT_CONS
 *	    VNTSD_STATUS_MOV_CONS_FORWARD
 *	    VNTSD_STATUS_MOV_CONS_BACKWARD
 *	    VNTSD_STATUS_ACQURE_WRITER
 *	    VNTSD_STATUS_CONTINUE
 * from vntsd_telnet_cmd
 *	    VNTSD_STATUS_CONTINUE
 */
int
vntsd_read_data(vntsd_client_t *clientp, char *c)
{
	int rv;

	for (; ; ) {
		if ((rv = vntsd_read_char(clientp, c)) != VNTSD_SUCCESS) {
			return (rv);
		}

		/* daemon cmd? */
		rv = vntsd_process_daemon_cmd(clientp, *c);

		if (rv == VNTSD_SUCCESS) {
			/* telnet cmd? */
			rv = vntsd_telnet_cmd(clientp, *c);
		}

		if (rv == VNTSD_STATUS_CONTINUE) {
			/*
			 * either a daemon cmd or a telnet cmd
			 * was processed.
			 */
			clientp->prev_char = 0;
			continue;
		}

		return (rv);
	}

	/*NOTREACHED*/
	return (0);
}
/* vntsd_read_line() -  read a line from TCP client */
int
vntsd_read_line(vntsd_client_t *clientp, char *buf, int *in_sz)
{
	char	c;
	int	rv;
	int	out_sz = 0;


	for (; ; ) {

		if ((rv =  vntsd_read_data(clientp, &c)) !=  VNTSD_SUCCESS) {
			return (rv);
		}

		if (c == BS) {
			/* back */
			if ((rv = vntsd_write_client(clientp, &c, 1)) !=
			    VNTSD_SUCCESS) {
				return (rv);
			}

			c = ' ';
			if ((rv = vntsd_write_client(clientp, &c, 1)) !=
			    VNTSD_SUCCESS) {
				return (rv);
			}

			buf--;
			out_sz--;
			continue;
		}
		/* echo */
		if ((rv = vntsd_write_client(clientp, &c, 1)) !=
		    VNTSD_SUCCESS) {
			return (rv);
		}

		*buf++ = c;
		out_sz++;

		if (c == CR) {
			/* end of line */
			*in_sz = out_sz;
			return (VNTSD_SUCCESS);
		}

		if (out_sz == *in_sz) {
			return (VNTSD_SUCCESS);
		}
	}

	/*NOTREACHED*/
	return (0);
}

/* free a client */
void
vntsd_free_client(vntsd_client_t *clientp)
{

	if (clientp->sockfd != -1) {
		(void) close(clientp->sockfd);
	}

	(void) mutex_destroy(&clientp->lock);

	free(clientp);
}


/* check if a vcc console port still ok */
boolean_t
vntsd_vcc_cons_alive(vntsd_cons_t *consp)
{
	vcc_console_t	vcc_cons;
	int		rv;

	assert(consp);
	assert(consp->group);

	/* construct current configuration */
	(void) strncpy(vcc_cons.domain_name, consp->domain_name, MAXPATHLEN);
	(void) strncpy(vcc_cons.group_name, consp->group->group_name,
	    MAXPATHLEN);
	vcc_cons.tcp_port = consp->group->tcp_port;
	vcc_cons.cons_no   = consp->cons_no;

	/* call vcc to verify */
	rv = vntsd_vcc_ioctl(VCC_CONS_STATUS, consp->cons_no, &vcc_cons);
	if (rv != VNTSD_SUCCESS) {
		return (B_FALSE);
	}

	if (vcc_cons.cons_no == -1) {
		/* port is gone */
		return (B_FALSE);
	}

	/* port is ok */
	return (B_TRUE);

}

/* add to total if a console is alive  */
static boolean_t
total_cons(vntsd_cons_t *consp, int *num_cons)
{
	int rv;

	assert(consp->group);
	rv = vntsd_vcc_err(consp);
	if (rv == VNTSD_STATUS_CONTINUE) {
		(*num_cons)++;
	}
	return (B_FALSE);
}


/* total alive consoles in a group  */
int
vntsd_chk_group_total_cons(vntsd_group_t *groupp)
{
	uint_t num_cons = 0;

	(void) vntsd_que_find(groupp->conspq, (compare_func_t)total_cons,
	    &num_cons);
	return (num_cons);
}

/* vntsd_log() log function for errors */
void
vntsd_log(vntsd_status_t status, char *msg)
{
	char	*status_msg = NULL;
	int	critical = 0;

	switch (status) {

	case VNTSD_SUCCESS:
		status_msg = "STATUS_OK";
		break;

	case VNTSD_STATUS_CONTINUE:
		status_msg = "CONTINUE";
		break;

	case VNTSD_STATUS_EXIT_SIG:
		critical = 1;
		status_msg = "KILL SIGNAL RECV";
		break;

	case VNTSD_STATUS_SIG:
		status_msg = "SIG RECV";
		break;

	case VNTSD_STATUS_NO_HOST_NAME:
		status_msg = "Warining NO HOST NAME";
		break;

	case VNTSD_STATUS_CLIENT_QUIT:
		status_msg = "CLIENT CLOSED  GROUP CONNECTION";
		break;

	case VNTSD_STATUS_RESELECT_CONS:
		status_msg = "CLIENT RESELECTS CONSOLE";
		break;

	case VNTSD_STATUS_VCC_IO_ERR:
		status_msg = "CONSOLE WAS DELETED";
		break;

	case VNTSD_STATUS_MOV_CONS_FORWARD:
		status_msg = "MOVE CONSOLE FORWARD";
		break;

	case VNTSD_STATUS_MOV_CONS_BACKWARD:
		status_msg = "MOVE CONSOLE BACKWARD";
		break;

	case VNTSD_STATUS_ACQUIRE_WRITER:
		status_msg = "FORCE CONSOLE WRITE";
		break;

	case VNTSD_STATUS_INTR:
		status_msg = "RECV SIGNAL";
		break;

	case VNTSD_STATUS_DISCONN_CONS:
		status_msg = "DELETING CONSOLE";
		break;

	case VNTSD_STATUS_NO_CONS:
		status_msg = "All console(s) in the group have been deleted.";
		break;

	case VNTSD_STATUS_AUTH_ENABLED:
		critical = 1;
		status_msg = "VNTSD_STATUS_AUTH_ENABLED";
		break;

	case VNTSD_ERR_NO_MEM:
		critical = 1;
		status_msg = "NO MEMORY";
		break;

	case VNTSD_ERR_NO_DRV:
		critical = 1;
		status_msg = "NO VCC DRIVER";
		break;

	case VNTSD_ERR_WRITE_CLIENT:
		status_msg  =  "WRITE CLIENT ERR";
		break;

	case VNTSD_ERR_EL_NOT_FOUND:
		critical = 1;
		status_msg = "ELEMENT_NOT_FOUND";
		break;

	case VNTSD_ERR_VCC_CTRL_DATA:
		critical = 1;
		status_msg = "VCC CTRL DATA  ERROR";
		break;

	case VNTSD_ERR_VCC_POLL:
		critical = 1;
		status_msg = "VCC POLL ERROR";
		break;

	case VNTSD_ERR_VCC_IOCTL:
		critical = 1;
		status_msg = "VCC IOCTL ERROR";
		break;

	case VNTSD_ERR_VCC_GRP_NAME:
		critical = 1;
		status_msg = "VCC GROUP NAME ERROR";
		break;

	case VNTSD_ERR_CREATE_LISTEN_THR:
		critical = 1;
		status_msg = "FAIL TO CREATE LISTEN THREAD";
		break;

	case VNTSD_ERR_CREATE_WR_THR:
		critical = 1;
		status_msg = "FAIL TO CREATE WRITE THREAD";
		break;

	case VNTSD_ERR_ADD_CONS_FAILED:
		critical = 1;
		status_msg = "FAIL TO ADD A CONSOLE";
		break;

	case VNTSD_ERR_LISTEN_SOCKET:
		critical = 1;
		status_msg = "LISTEN SOCKET ERROR";
		break;

	case VNTSD_ERR_LISTEN_OPTS:
		critical = 1;
		status_msg = "SET SOCKET OPTIONS ERROR";
		break;

	case VNTSD_ERR_LISTEN_BIND:
		critical = 1;
		status_msg = "BIND SOCKET ERROR";
		break;

	case VNTSD_STATUS_ACCEPT_ERR:
		critical = 1;
		status_msg = "LISTEN ACCEPT ERROR";
		break;

	case VNTSD_ERR_CREATE_CONS_THR:
		critical = 1;
		status_msg = "CREATE CONSOLE THREAD ERROR ";
		break;

	case VNTSD_ERR_SIG:
		critical = 1;
		status_msg = "RECV UNKNOWN SIG";
		break;

	case VNTSD_ERR_UNKNOWN_CMD:
		critical = 1;
		status_msg = "RECV UNKNOWN COMMAND";
		break;

	case VNTSD_ERR_CLIENT_TIMEOUT:
		status_msg  =  "CLOSE CLIENT BECAUSE TIMEOUT";
		break;
	default:
		status_msg = "Unknown status recv";
		break;
	}


	if (critical) {
		syslog(LOG_ERR, "%s: thread[%d] %s\n", status_msg,
		    thr_self(), msg);
	}
#ifdef DEBUG
	DERR(stderr, "%s: thread[%d] %s\n", status_msg, thr_self(), msg);
	syslog(LOG_ERR, "%s: thread[%d] %s\n", status_msg, thr_self(), msg);
#endif
}
