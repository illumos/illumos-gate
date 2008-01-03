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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Vntsd handles two types of special commands, one is telnet
 * commands and another is vntsd special commands.
 * telnet commands supported are:
 * WILL
 * WONT
 * DO
 * DONT
 *  TEL_ECHO
 *  SUPRESS
 *  LINEMODE
 * BRK
 * AYT
 * HT
 *
 * Vntsd special commands are:
 *  Send break		(~#)
 *  Exit		(~.)
 *  Force write access	(~w)
 *  Console next	(~n)
 *  Console previous	(~p)
 *  Help		(~?)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <thread.h>
#include <ctype.h>
#include <sys/termio.h>
#include <libintl.h>
#include <syslog.h>
#include "vntsd.h"
#include "chars.h"

char vntsd_eol[] = { CR, LF, 0};

typedef	int	    (*e_func_t)(vntsd_client_t *clientp);
/* structure for daemon special cmd */
typedef struct {
	char e_char;				/* char to match on */
	char *e_help;				/* help string */
	e_func_t e_func;			/* command */
} esctable_t;

/* genbrk() -  send a break to vcc driver */
static int
genbrk(vntsd_client_t *clientp)
{

	vntsd_cons_t *consp;

	assert(clientp);
	assert(clientp->cons);

	consp = clientp->cons;
	D1(stderr, "t@%d genbrk fd=%d sockfd %d\n", thr_self(),
	    consp->vcc_fd, clientp->sockfd);

	assert(consp->clientpq != NULL);
	if (consp->clientpq->handle != clientp) {
		/* reader */
		return (vntsd_write_line(clientp,
			    gettext(VNTSD_NO_WRITE_ACCESS_MSG)));
	}

	/* writer */
	if (ioctl(consp->vcc_fd, TCSBRK, NULL)) {
		return (VNTSD_ERR_VCC_IOCTL);
	}

	return (VNTSD_STATUS_CONTINUE);
}

/*
 * console_forward()  - cycle client to the next console
 * in the group queue.
 */
static int
console_forward(vntsd_client_t *clientp)
{
	/* forward when there are mutiple consoles in the group */
	if (clientp->cons->group->num_cons > 1)
		return (VNTSD_STATUS_MOV_CONS_FORWARD);

	return (VNTSD_STATUS_CONTINUE);

}

/*
 * console_backward()  - cycle client to the previous
 * console in the group queue.
 */
static int
console_backward(vntsd_client_t *clientp)
{
	/* backward when there are mutiple consoles in the group */
	if (clientp->cons->group->num_cons > 1)
		return (VNTSD_STATUS_MOV_CONS_BACKWARD);

	return (VNTSD_STATUS_CONTINUE);

}

/* acquire_write() - acquire write access to a console. */
static int
acquire_write(vntsd_client_t *clientp)
{
	int	rv;
	int	yes_no = 1;
	vntsd_cons_t *consp;

	assert(clientp);
	consp = clientp->cons;
	assert(consp);

	if (consp->clientpq->handle == clientp) {
		/* client is a  writer */
		if ((rv = vntsd_write_line(clientp,
			    gettext("You have write permission"))) !=
		    VNTSD_SUCCESS) {
			return (rv);

		}
		return (VNTSD_STATUS_CONTINUE);
	}

	/* message to client */
	if ((rv = vntsd_write_client(clientp, vntsd_eol, VNTSD_EOL_LEN))
	    != VNTSD_SUCCESS) {
		return (rv);
	}

	/*
	 * TRANSLATION_NOTE
	 * The following string should be formatted to fit on multiple lines
	 * assuming a line width of at most 78 characters. There must be no
	 * trailing newline.
	 */
	if ((rv = vntsd_write_lines(clientp,
			    gettext("Warning: another user currently "
	    "has write permission\nto this console and forcibly removing "
	    "him/her will terminate\nany current write action and all work "
	    "will be lost."))) != VNTSD_SUCCESS) {
		return (rv);
	}

	/* get client yes no */
	if ((rv = vntsd_write_client(clientp, vntsd_eol,
			    VNTSD_EOL_LEN)) != VNTSD_SUCCESS) {
		return (rv);
	}

	if ((rv = vntsd_get_yes_no(clientp,
			    gettext("Would you like to continue?"),
			    &yes_no)) != VNTSD_SUCCESS) {
		return (rv);
	}

	if (yes_no == B_FALSE) {
		/* client change mind no need to acquire  write access */
		return (VNTSD_STATUS_CONTINUE);
	}

	return (VNTSD_STATUS_ACQUIRE_WRITER);
}

/* client_exit()  - disconnect client from the console. */
static int
client_exit(void)
{
	return (VNTSD_STATUS_RESELECT_CONS);
}

static int daemon_cmd_help(vntsd_client_t *clientp);

/* table for daemon commands */

static esctable_t  etable[] = {

	/* send a break to vcc */
	{'#', "Send break",  genbrk},

	/* exit */
	{'.', "Exit from this console",  (e_func_t)client_exit},

	/* acquire write access */
	{'w', "Force write access", acquire_write},

	/* connect to next console in queue */
	{'n', "Console next", (e_func_t)console_forward},

	/* connect to previous console in queue */
	{'p', "Console previous", (e_func_t)console_backward},

	/* help must be next to last */
	{'?', "Help", daemon_cmd_help},

	/* table terminator */
	{0, 0, 0}
};

void
vntsd_init_esctable_msgs(void)
{
	esctable_t  *p;

	for (p = etable; p->e_char != '\0'; p++) {
		p->e_help = gettext(p->e_help);
	}
}

/* daemon_cmd_help() - print help. */
static int
daemon_cmd_help(vntsd_client_t *clientp)
{
	esctable_t  *p;
	int	    rv;
	char	    buf[VNTSD_LINE_LEN];

	if ((rv = vntsd_write_client(clientp, vntsd_eol,
			    VNTSD_EOL_LEN)) != VNTSD_SUCCESS) {
	    return (rv);
	}

	/*
	 * TRANSLATION_NOTE
	 * VNTSD is the name of the VNTS daemon and should not be translated.
	 */
	if ((rv = vntsd_write_line(clientp, gettext("VNTSD commands"))) !=
	    VNTSD_SUCCESS) {
		return (rv);
	}

	for (p = etable; p->e_char; p++) {
		(void) snprintf(buf, sizeof (buf),
				"~%c --%s", p->e_char, p->e_help);

		if ((rv = vntsd_write_line(clientp, buf)) != VNTSD_SUCCESS) {
			return (rv);
		}
	}

	return (VNTSD_STATUS_CONTINUE);
}

/* exit from daemon command */
static int
exit_daemon_cmd(vntsd_client_t *clientp, int rv)
{
	(void) mutex_lock(&clientp->lock);
	clientp->status &= ~VNTSD_CLIENT_DISABLE_DAEMON_CMD;
	(void) mutex_unlock(&clientp->lock);
	return (rv);
}

/*
 * vntsd_process_daemon_cmd() - special commands
 * "<RET>~"  vntsd daemon commands
 * "<RET>~~" enter '~' character
 */
int
vntsd_process_daemon_cmd(vntsd_client_t *clientp, char c)
{
	esctable_t *p;
	int	    rv;
	char	    prev_char;

	prev_char = clientp->prev_char;

	if (c != VNTSD_DAEMON_CMD || (prev_char != 0 && prev_char != CR)) {
		/* not a daemon command */
		return (VNTSD_SUCCESS);
	}

	if (clientp->status & VNTSD_CLIENT_DISABLE_DAEMON_CMD) {
		return (VNTSD_STATUS_CONTINUE);
	}

	/* no reentry to process_daemon_cmd */
	(void) mutex_lock(&clientp->lock);
	clientp->status |= VNTSD_CLIENT_DISABLE_DAEMON_CMD;
	(void) mutex_unlock(&clientp->lock);

	D3(stderr, "t@%d process_daemon_cmd %d %d \n", thr_self(),
	    clientp->cons->vcc_fd, clientp->sockfd);

	/* read in command */
	if ((rv = vntsd_read_char(clientp, &c)) != VNTSD_SUCCESS) {
		return (exit_daemon_cmd(clientp, rv));
	}

	if (c == VNTSD_DAEMON_CMD) {
		/*
		 * received another '~'
		 * a user types '~~' to get '~'
		 */
		(void) mutex_lock(&clientp->lock);
		clientp->status &= ~VNTSD_CLIENT_DISABLE_DAEMON_CMD;
		(void) mutex_unlock(&clientp->lock);
		return (VNTSD_SUCCESS);
	}

	for (p = etable; p->e_char; p++) {
		if (p->e_char == c) {
			/* found match */
			assert(p->e_func);
			rv = (*p->e_func)(clientp);
			return (exit_daemon_cmd(clientp, rv));
		}
	}

	/* no match, print out the help */
	p--;
	assert(p->e_char == '?');
	rv = (*p->e_func)(clientp);

	return (exit_daemon_cmd(clientp, rv));

}

/* vntsd_set_telnet_options() - change  telnet client to  character mode. */
int
vntsd_set_telnet_options(int fd)
{
	/* set client telnet options */
	uint8_t buf[] = {IAC, DONT, LINEMODE, IAC, WILL, SUPRESS, IAC, WILL,
		TEL_ECHO, IAC, DONT, TERM_TYPE, IAC, DONT, TERM_SP,
		IAC, DONT, STATUS, IAC, DONT, FC, IAC, DONT, TM, IAC, DONT, ENV,
		IAC, DONT, WIN_SIZE};

	return (vntsd_write_fd(fd, (char *)buf, 30));
}

/*  vntsd_telnet_cmd() process telnet commands */
int
vntsd_telnet_cmd(vntsd_client_t *clientp, char c)
{
	uint8_t	buf[4];
	char	cmd;
	int	rv = VNTSD_STATUS_CONTINUE;

	bzero(buf, 4);

	if ((uint8_t)c != IAC) {
		/* not telnet cmd */
		return (VNTSD_SUCCESS);
	}

	if ((rv = vntsd_read_char(clientp, &cmd)) != VNTSD_SUCCESS) {
		return (rv);
	}

	if ((uint8_t)cmd != BRK) {
		if ((rv = vntsd_read_char(clientp, &c)) != VNTSD_SUCCESS) {
			return (rv);
		}
	}


	switch ((uint8_t)cmd) {

	case WILL:

		switch ((uint8_t)c) {
		case TEL_ECHO:
		case SUPRESS:
		case LINEMODE:
			break;
		default:
			syslog(LOG_ERR, "not support telnet WILL %x\n", c);
			break;
		}
		break;

	case  WONT:

		switch ((uint8_t)c) {
		case TEL_ECHO:
		case SUPRESS:
		case LINEMODE:
		default:
			syslog(LOG_ERR, "not support telnet WONT %x\n", c);
			break;
		}
		break;

	case DO:
	case DONT:

		buf[0] = IAC;
		buf[1] = WILL;
		buf[2] = c;
		rv = vntsd_write_client(clientp, (char *)buf, 3);

		break;

	case BRK:

		/* send break to vcc */
		rv = genbrk(clientp);
		break;

	case IP:

		break;

	case AYT:

		rv = vntsd_write_client(clientp, &c, 1);
		break;

	case HT:
		return (VNTSD_STATUS_CONTINUE);

	default:
		syslog(LOG_ERR, "not support telnet ctrl %x\n", c);
		break;
	}

	if (rv == VNTSD_SUCCESS) {
		return (VNTSD_STATUS_CONTINUE);
	} else {
		return (rv);
	}
}


/*
 * vntsd_ctrl_cmd()   - control keys
 * read and write suspend are supported.
 */
int
vntsd_ctrl_cmd(vntsd_client_t *clientp, char c)
{
	int	cmd;

	D3(stderr, "t@%d vntsd_ctrl_cmd%d %d\n", thr_self(),
	    clientp->cons->vcc_fd, clientp->sockfd);

	if ((c != START) && (c != STOP)) {
		/* not a supported control command */
		return (VNTSD_SUCCESS);
	}

	if (c == START) {
		D3(stderr, "t@%d client restart\n", thr_self());

		/* send resume read */
		cmd = 1;

		if (ioctl(clientp->cons->vcc_fd, TCXONC, &cmd)) {
			return (VNTSD_STATUS_VCC_IO_ERR);
		}

	}

	if (c == STOP) {
		D3(stderr, "t@%d client suspend\n", thr_self());

		/* send suspend read */
		cmd = 0;

		if (ioctl(clientp->cons->vcc_fd, TCXONC, &cmd)) {
			return (VNTSD_STATUS_VCC_IO_ERR);
		}

	}

	return (VNTSD_STATUS_CONTINUE);
}
