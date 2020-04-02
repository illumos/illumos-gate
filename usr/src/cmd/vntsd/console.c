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

/*
 * Listen thread creates a console thread whenever there is a tcp client
 * made a conection to its port. In the console thread, if there are
 * multiple consoles in the group, client will be asked for a console selection.
 * a write thread for a console is created when first client connects to a
 * selected console and console thread becomes read thread for the client.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <thread.h>
#include <synch.h>
#include <signal.h>
#include <assert.h>
#include <ctype.h>
#include <syslog.h>
#include <libintl.h>
#include <netdb.h>
#include "vntsd.h"
#include "chars.h"

/*  display domain names in the group */
static boolean_t
display_domain_name(vntsd_cons_t *consp,  int  *fd)
{
	char	buf[VNTSD_LINE_LEN];
	char	*status;


	if (consp->clientpq != NULL) {
		status = gettext("connected");
	} else if (consp->status & VNTSD_CONS_DELETED) {
		status = gettext("removing...");
	} else {
		status = gettext("online");
	}

	(void) snprintf(buf, sizeof (buf), "%-20d%-30s%-25s%s",
	    consp->cons_no, consp->domain_name, status, vntsd_eol);

	return (vntsd_write_fd(*fd, buf, strlen(buf)) != VNTSD_SUCCESS);
}

/* output connected message to tcp client */
static int
write_connect_msg(vntsd_client_t *clientp, char *group_name,
    char *domain_name)
{

	int	rv = VNTSD_SUCCESS;
	char	buf[VNTSD_LINE_LEN];

	if ((rv = vntsd_write_client(clientp, vntsd_eol, VNTSD_EOL_LEN)) !=
	    VNTSD_SUCCESS) {
		return (rv);
	}

	(void) snprintf(buf, sizeof (buf),
	    gettext("Connecting to console \"%s\" in group \"%s\" ...."),
	    domain_name, group_name);

	if ((rv = vntsd_write_line(clientp, buf)) != VNTSD_SUCCESS) {
		return (rv);
	}

	if ((rv = vntsd_write_line(clientp,
	    gettext("Press ~? for control options .."))) != VNTSD_SUCCESS) {
		return (rv);
	}

	return (VNTSD_SUCCESS);
}

static int
create_write_thread(vntsd_cons_t *consp)
{

	assert(consp);

	/* create write thread for the console */
	(void) mutex_lock(&consp->lock);
	if (thr_create(NULL, 0, (thr_func_t)vntsd_write_thread,
	    (void *)consp, 0, &consp->wr_tid)) {

		DERR(stderr, "t@%d create_rd_wr_thread@%d: "
		    "create write thread failed\n",
		    thr_self(), consp->cons_no);
		(void) close(consp->vcc_fd);
		consp->vcc_fd = -1;
		(void) mutex_unlock(&consp->lock);

		return (VNTSD_ERR_CREATE_WR_THR);
	}
	(void) mutex_unlock(&consp->lock);
	return (VNTSD_SUCCESS);
}

/* Display all domain consoles in a group. */
static int
list_all_domains(vntsd_group_t *groupp, vntsd_client_t *clientp)
{
	char	    vntsd_line[VNTSD_LINE_LEN];
	int	    rv = VNTSD_SUCCESS;

	if ((rv = vntsd_write_client(clientp, vntsd_eol, VNTSD_EOL_LEN))
	    != VNTSD_SUCCESS) {
		return (rv);
	}

	/*
	 * TRANSLATION_NOTE
	 * The following three strings of the form "DOMAIN .." are table
	 * headers and should be all uppercase.
	 */
	(void) snprintf(vntsd_line, sizeof (vntsd_line),
	    "%-20s%-30s%-25s",
	    gettext("DOMAIN ID"), gettext("DOMAIN NAME"),
	    gettext("DOMAIN STATE"));

	if ((rv = vntsd_write_line(clientp, vntsd_line)) != VNTSD_SUCCESS) {
		return (rv);
	}

	(void) mutex_lock(&groupp->lock);

	if (vntsd_que_find(groupp->conspq, (compare_func_t)display_domain_name,
	    &(clientp->sockfd)) != NULL) {
		rv = VNTSD_ERR_WRITE_CLIENT;
	}

	(void) mutex_unlock(&groupp->lock);

	return (rv);
}

/* display help */
static int
display_help(vntsd_client_t *clientp)
{
	int	rv = VNTSD_SUCCESS;
	char	*bufp;

	rv = vntsd_write_client(clientp, vntsd_eol, VNTSD_EOL_LEN);
	if (rv != VNTSD_SUCCESS) {
		return (rv);
	}

	/*
	 * TRANSLATION_NOTE
	 * The following three strings of the form ". -- ..." are help
	 * messages for single character commands. Do not translate the
	 * character before the --.
	 */
	bufp = gettext("h -- this help");

	if ((rv = vntsd_write_line(clientp, bufp)) != VNTSD_SUCCESS) {
		return (rv);
	}

	bufp = gettext("l -- list of consoles");

	if ((rv = vntsd_write_line(clientp, bufp)) != VNTSD_SUCCESS) {
		return (rv);
	}

	bufp = gettext("q -- quit");

	if ((rv = vntsd_write_line(clientp, bufp)) != VNTSD_SUCCESS) {
		return (rv);
	}

	/*
	 * TRANSLATION_NOTE
	 * In the following string, "id" is a short mnemonic for
	 * "identifier" and both occurrences should be translated.
	 */

	bufp = gettext("c{id}, n{name} -- connect to a console of domain {id}"
	    " or domain {name}");

	if ((rv = vntsd_write_line(clientp, bufp)) != VNTSD_SUCCESS) {
		return (rv);
	}

	return (VNTSD_SUCCESS);
}

/* cons_by_name() - find a console structure according to  a ldom's name */
static boolean_t
cons_by_name(vntsd_cons_t *consp, char *name)
{
	if (consp->status & VNTSD_CONS_DELETED) {
		return (B_FALSE);
	}
	return (strcmp(consp->domain_name, name) == 0);
}

/* name_to_cons_no - convert a ldom's name to its consno */
static int
name_to_cons_no(vntsd_group_t *groupp, char *name)
{
	vntsd_cons_t *consp;

	consp = (vntsd_cons_t *)vntsd_que_find(groupp->conspq,
	    (compare_func_t)cons_by_name, name);

	if (consp == NULL) {
		return (-1);
	}

	return (consp->cons_no);
}

/* select a console to connect */
static int
select_cons(vntsd_group_t *groupp, vntsd_cons_t **consp,
    vntsd_client_t *clientp, char c)
{
	int	    cons_no = -1;
	int	    n;
	int	    i;
	char	    buf[VNTSD_LINE_LEN];
	int	    rv;



	(void) mutex_lock(&groupp->lock);
	if (groupp->num_cons == 0) {
		(void) mutex_unlock(&groupp->lock);
		/* no console in this group */
		return (VNTSD_STATUS_NO_CONS);
	}
	(void) mutex_unlock(&groupp->lock);


	/* c{id} or n{name} */

	n = VNTSD_LINE_LEN;

	if ((rv = vntsd_read_line(clientp, buf, &n)) != VNTSD_SUCCESS) {
		return (rv);
	}

	/* parse command */
	for (i = 0; i < n; i++) {
		switch (c) {

		case 'c':
			/* c{id} or c {id} */
			if (isspace(buf[i])) {
				continue;
			}

			if (!isdigit(buf[i])) {
				return (VNTSD_ERR_INVALID_INPUT);
			}

			cons_no = atoi(buf + i);
			break;

		case 'n':
			/* n{name) or n {name} */
			if (isspace(buf[i])) {
				continue;
			}

			buf[n-1] = 0;
			cons_no = name_to_cons_no(groupp, buf+i);
			break;

		default:
			/* should never get here */
			return (VNTSD_ERR_INVALID_INPUT);

		}

		/* got user selection */
		break;
	}

	if (cons_no < 0) {
		return (VNTSD_ERR_INVALID_INPUT);
	}

	/* get selected console */
	(void) mutex_lock(&groupp->lock);

	*consp = (vntsd_cons_t *)vntsd_que_find(groupp->conspq,
	    (compare_func_t)vntsd_cons_by_consno, &cons_no);

	if (*consp == NULL) {
		/* during console selection, the console has been  deleted */
		(void) mutex_unlock(&groupp->lock);

		return (VNTSD_ERR_INVALID_INPUT);
	}
	if ((*consp)->status & VNTSD_CONS_DELETED) {
		return (VNTSD_ERR_INVALID_INPUT);
	}

	(void) mutex_unlock(&groupp->lock);

	return (VNTSD_SUCCESS);
}

/* compare if there is a match console in the gorup */
static boolean_t
find_cons_in_group(vntsd_cons_t *consp_in_group, vntsd_cons_t *consp)
{
	if (consp_in_group == consp) {
		return (B_TRUE);
	} else {
		return (B_FALSE);
	}
}

/* connect a client to a console */
static int
connect_cons(vntsd_cons_t *consp, vntsd_client_t *clientp)
{
	int	rv, rv1;
	vntsd_group_t *groupp;

	assert(consp);
	groupp = consp->group;
	assert(groupp);
	assert(clientp);

	(void) mutex_lock(&groupp->lock);

	/* check if console is valid */
	consp = vntsd_que_find(groupp->conspq,
	    (compare_func_t)find_cons_in_group, consp);

	if (consp == NULL) {
		(void) mutex_unlock(&groupp->lock);
		return (VNTSD_STATUS_NO_CONS);
	}
	if (consp->status & VNTSD_CONS_DELETED) {
		(void) mutex_unlock(&groupp->lock);
		return (VNTSD_STATUS_NO_CONS);
	}

	(void) mutex_lock(&consp->lock);
	(void) mutex_lock(&clientp->lock);


	clientp->cons = consp;

	/* enable daemon cmd */
	clientp->status &= ~VNTSD_CLIENT_DISABLE_DAEMON_CMD;

	if (consp->clientpq == NULL && consp->vcc_fd == -1) {

		/*
		 *  the first connection to a console - a writer
		 *  and the console has not opened.
		 */
		consp->vcc_fd = vntsd_open_vcc(consp->dev_name, consp->cons_no);
		if (consp->vcc_fd < 0) {
			(void) mutex_unlock(&clientp->lock);
			(void) mutex_unlock(&consp->lock);
			(void) mutex_unlock(&groupp->lock);
			assert(consp->group);
			return (vntsd_vcc_err(consp));
		}
	}

	(void) mutex_unlock(&clientp->lock);

	/*
	 * move the client from group's no console selected queue
	 * to cons queue
	 */

	rv = vntsd_que_rm(&groupp->no_cons_clientpq, clientp);
	assert(rv == VNTSD_SUCCESS);

	rv = vntsd_que_append(&consp->clientpq, clientp);
	(void) mutex_unlock(&groupp->lock);

	if (rv != VNTSD_SUCCESS) {
		if (consp->clientpq->handle == clientp) {
			/* writer */
			(void) close(consp->vcc_fd);
			consp->vcc_fd = -1;
		}

		(void) mutex_unlock(&consp->lock);
		return (rv);
	}

	(void) mutex_unlock(&consp->lock);

	if (consp->clientpq->handle == clientp) {
		/* create a write thread */
		rv = create_write_thread(consp);
		if (rv != VNTSD_SUCCESS) {
			return (rv);
		}
	}

	/* write connecting message */
	if ((rv = write_connect_msg(clientp, consp->group->group_name,
	    consp->domain_name)) != VNTSD_SUCCESS) {
			return (rv);
	}

	/* process input from client */
	rv = vntsd_read(clientp);

	/* client disconnected from the console */
	(void) mutex_lock(&groupp->lock);

	/* remove client from console queue */
	(void) mutex_lock(&consp->lock);
	rv1 = vntsd_que_rm(&consp->clientpq, clientp);
	assert(rv1 == VNTSD_SUCCESS);

	/* append client to group's no console selected  queue */
	rv1 = vntsd_que_append(&groupp->no_cons_clientpq, clientp);
	(void) mutex_unlock(&groupp->lock);

	if (consp->clientpq == NULL) {
		/* clean up console since there is no client connected to it */
		assert(consp->vcc_fd != -1);

		/* force write thread to exit */
		assert(consp->wr_tid != (thread_t)-1);
		(void) thr_kill(consp->wr_tid, SIGUSR1);
		(void) mutex_unlock(&consp->lock);
		(void) thr_join(consp->wr_tid, NULL, NULL);
		(void) mutex_lock(&consp->lock);
	}

	if (consp->status & VNTSD_CONS_SIG_WAIT) {
		/* console is waiting for client to disconnect */
		(void) cond_signal(&consp->cvp);
	}

	(void) mutex_unlock(&consp->lock);

	return (rv1 == VNTSD_SUCCESS ? rv : rv1);

}

/* read command line input */
static int
read_cmd(vntsd_client_t *clientp, char *prompt, char *cmd)
{
	int		rv;

	/* disable daemon special command */
	(void) mutex_lock(&clientp->lock);
	clientp->status |= VNTSD_CLIENT_DISABLE_DAEMON_CMD;
	(void) mutex_unlock(&clientp->lock);

	rv = vntsd_write_client(clientp, vntsd_eol, VNTSD_EOL_LEN);
	if (rv != VNTSD_SUCCESS) {
		return (rv);
	}

	rv = vntsd_write_client(clientp, prompt, strlen(prompt));
	if (rv != VNTSD_SUCCESS) {
		return (rv);
	}

	if ((rv = vntsd_read_data(clientp, cmd)) != VNTSD_SUCCESS) {
		return (rv);
	}
	if (*cmd == BS) {
		return (VNTSD_SUCCESS);
	}

	rv = vntsd_write_client(clientp, cmd, 1);

	*cmd = tolower(*cmd);

	return (rv);
}

/* reset client for selecting a console in the group */
static void
client_init(vntsd_client_t *clientp)
{
	(void) mutex_lock(&clientp->lock);
	clientp->cons = NULL;
	clientp->status = 0;
	(void) mutex_unlock(&clientp->lock);
}
/* is there any connection to a given console? */
static boolean_t
is_client_que_empty(vntsd_cons_t *consp)
{
	boolean_t  has_client = B_FALSE;

	(void) mutex_lock(&consp->lock);

	if (consp->clientpq != NULL)
		has_client = B_TRUE;

	(void) mutex_unlock(&consp->lock);

	return (has_client);
}

/*
 * close one opened console.
 * This function is passed to vntsd_que_walk to close one console.
 * The function returns B_FALSE so that vntsd_que_walk will
 * continue to apply the function to all consoles in the group.
 */
static boolean_t
close_one_vcc_fd(vntsd_cons_t *consp)
{
	(void) mutex_lock(&consp->lock);

	if (consp->vcc_fd != -1) {
		(void) close(consp->vcc_fd);
		consp->vcc_fd = -1;
	}

	(void) mutex_unlock(&consp->lock);

	return (B_FALSE);
}


/* clean up client and exit the thread */
static void
client_fini(vntsd_group_t *groupp, vntsd_client_t *clientp)
{

	assert(groupp);
	assert(clientp);

	/* disconnct client from tcp port */
	assert(clientp->sockfd != -1);
	(void) close(clientp->sockfd);

	(void) mutex_lock(&groupp->lock);

	/*
	 * close all consoles in the group if the client is the
	 * last one connected to the group
	 */
	if (vntsd_que_walk(groupp->conspq, (el_func_t)is_client_que_empty) ==
	    VNTSD_SUCCESS) {
		(void) vntsd_que_walk(groupp->conspq,
		    (el_func_t)close_one_vcc_fd);
	}


	(void) vntsd_que_rm(&groupp->no_cons_clientpq, clientp);

	if ((groupp->no_cons_clientpq == NULL) &&
	    (groupp->status & VNTSD_GROUP_SIG_WAIT)) {
		/*
		 * group is waiting to be deleted. - signal the group's
		 * listen thread - the VNTSD_GROUP_SIG_WAIT state will
		 * be cleared when the listen thread exits.
		 */
		(void) cond_signal(&groupp->cvp);
	}
	(void) mutex_unlock(&groupp->lock);

	(void) mutex_destroy(&clientp->lock);
	free(clientp);

	thr_exit(0);
}

/*  check client's status. exit if client quits or fatal errors */
static void
console_chk_status(vntsd_group_t *groupp, vntsd_client_t *clientp, int status)
{
	char    err_msg[VNTSD_LINE_LEN];

	D1(stderr, "t@%d console_chk_status() status=%d "
	    "client status=%x num consoles=%d \n",
	    thr_self(), status, clientp->status, groupp->num_cons);

	(void) snprintf(err_msg, VNTSD_LINE_LEN, "console_chk_status client%d"
	    " num_cos=%d", clientp->sockfd, groupp->num_cons);

	/*
	 * obtain group lock to protect groupp->num_cons.
	 * When groupp->num_cons == 0, close client and exit the tread.
	 */
	(void) mutex_lock(&groupp->lock);

	if (groupp->num_cons == 0) {
		/* no more console in the group */
		(void) mutex_unlock(&groupp->lock);
		client_fini(groupp, clientp);
		return;
	}

	if (status == VNTSD_STATUS_INTR) {
		/* reason for signal? */
		status = vntsd_cons_chk_intr(clientp);
	}

	switch (status) {

	case VNTSD_STATUS_CLIENT_QUIT:
		(void) mutex_unlock(&groupp->lock);
		client_fini(groupp, clientp);
		return;

	case VNTSD_STATUS_RESELECT_CONS:

		if (clientp->cons == NULL) {
			/*
			 * domain was deleted before client connects to it
			 * connect to other console in the same group
			 */
			(void) mutex_unlock(&groupp->lock);
			client_init(clientp);
			return;
		}

		if ((groupp->num_cons == 1) &&
		    ((clientp->status & VNTSD_CLIENT_CONS_DELETED) ||
		    (groupp->conspq->handle == clientp->cons))) {
			/* no other selection available */
			(void) mutex_unlock(&groupp->lock);
			client_fini(groupp, clientp);
		} else {
			(void) mutex_unlock(&groupp->lock);
			client_init(clientp);
		}

		return;

	case VNTSD_STATUS_VCC_IO_ERR:
		if ((clientp->status & VNTSD_CLIENT_CONS_DELETED) == 0) {
			/* check if console was deleted  */
			(void) mutex_unlock(&groupp->lock);
			status = vntsd_vcc_err(clientp->cons);
			(void) mutex_lock(&groupp->lock);
		}

		if (status != VNTSD_STATUS_CONTINUE) {
			/* console was deleted */
			if (groupp->num_cons <= 1) {
				(void) mutex_unlock(&groupp->lock);
				client_fini(groupp, clientp);
				return;
			}
		}

		(void) mutex_unlock(&groupp->lock);
		/* console is ok */
		client_init(clientp);
		return;

	case VNTSD_STATUS_MOV_CONS_FORWARD:
	case VNTSD_STATUS_MOV_CONS_BACKWARD:
		if (groupp->num_cons == 1) {
			/* same console */
			(void) mutex_unlock(&groupp->lock);
			return;
		}

		/* get selected console */
		clientp->cons = vntsd_que_pos(groupp->conspq,
		    clientp->cons,
		    (status == VNTSD_STATUS_MOV_CONS_FORWARD)?(1):(-1));
		(void) mutex_unlock(&groupp->lock);
		return;

	case VNTSD_SUCCESS:
	case VNTSD_STATUS_CONTINUE:
		(void) mutex_unlock(&groupp->lock);
		client_init(clientp);
		return;


	case VNTSD_STATUS_NO_CONS:
		/*
		 * there are two cases when the status is VNTSD_SATATUS_NO_CONS.
		 * case 1. the console was removed but there is at least one
		 * another console in the group that client can connect to.
		 * case 2. there is no console in the group. Client needs to
		 * be disconnected from vntsd.
		 */
		if (groupp->num_cons == 0) {
			(void) mutex_unlock(&groupp->lock);
			client_fini(groupp, clientp);
		} else {
			(void) mutex_unlock(&groupp->lock);
			client_init(clientp);
		}
		return;


	case VNTSD_ERR_INVALID_INPUT:
		(void) mutex_unlock(&groupp->lock);
		return;

	default:
		/* fatal error */
		(void) mutex_unlock(&groupp->lock);
		vntsd_log(status, err_msg);
		client_fini(groupp, clientp);
		return;
	}
}

/* console thread */
void *
vntsd_console_thread(vntsd_thr_arg_t *argp)
{
	vntsd_group_t	    *groupp;
	vntsd_cons_t	    *consp;
	vntsd_client_t	    *clientp;

	char		    buf[MAXHOSTNAMELEN];
	char		    prompt[72];
	char		    cmd;
	int		    rv = VNTSD_SUCCESS;
	int		    num_cons;


	groupp = (vntsd_group_t *)argp->handle;
	clientp = (vntsd_client_t *)argp->arg;

	assert(groupp);
	assert(clientp);

	/* free argp, which was allocated in listen thread */
	free(argp);

	/* check if group is removed */

	D1(stderr, "t@%d get_client_sel@%lld:client@%d\n", thr_self(),
	    groupp->tcp_port, clientp->sockfd);

	bzero(buf, MAXHOSTNAMELEN);

	/* host name */
	if (gethostname(buf, MAXHOSTNAMELEN)) {
		vntsd_log(VNTSD_STATUS_NO_HOST_NAME, "vntsd_console_thread()");
		(void) snprintf(buf, sizeof (buf), "unkown host");
	}

	if (snprintf(prompt, sizeof (prompt),
	    "%s-vnts-%s: h, l, c{id}, n{name}, q:",
	    buf, groupp->group_name) >= sizeof (prompt)) {
		/* long prompt doesn't fit, use short one */
		(void) snprintf(prompt, sizeof (prompt),
		    "vnts: h, l, c{id}, n{name}, q:");
	}


	for (;;) {
		cmd = ' ';
		D1(stderr, "t@%d console_thread()@%lld:client@%d\n", thr_self(),
		    groupp->tcp_port, clientp->sockfd);

		num_cons = vntsd_chk_group_total_cons(groupp);

		if ((num_cons > 1) && (clientp->cons == NULL)) {
			/*  console to connect to */
			rv = read_cmd(clientp, prompt, &cmd);
			/* check error and may exit */
			console_chk_status(groupp, clientp, rv);

			/* any console is removed from group? */
			num_cons = vntsd_chk_group_total_cons(groupp);
			if (num_cons <= 1) {
				cmd = ' ';
			}
		}

		switch (cmd) {

		case 'l':

			/* list domain names */
			rv = list_all_domains(groupp, clientp);
			break;


		case 'q':

			rv = VNTSD_STATUS_CLIENT_QUIT;
			break;

		case ' ':

			if (num_cons == 0) {
				/* no console in the group */
				rv = VNTSD_STATUS_NO_CONS;
				break;
			}

			if (clientp->cons == NULL) {
				if (num_cons == 1) {
					/* by pass selecting console */
					consp = (vntsd_cons_t *)
					    (groupp->conspq->handle);
				} else {
					continue;
				}

			} else {
				consp = clientp->cons;
			}

			/* connect to console */
			rv = connect_cons(consp, clientp);

			break;

		case 'c':
		case 'n':
			/* select console */
			if (clientp->cons == NULL) {
				rv = select_cons(groupp, &consp, clientp, cmd);
				if (rv == VNTSD_ERR_INVALID_INPUT) {
					rv = display_help(clientp);
					break;
				}

				/*
				 * all consoles in the group
				 * may be gone before this client
				 * could select one.
				 */
				if (rv != VNTSD_SUCCESS)
					break;

			} else {
				consp = clientp->cons;
			}
			assert(consp);

			/* connect to console */
			rv = connect_cons(consp, clientp);
			D1(stderr, "t@%d console_thread()"
			    "connect_cons returns %d\n",
			    thr_self(), rv);
			break;

		case 'h':
		default:
			rv = display_help(clientp);
			break;

		}

		/* check error and may  exit */
		console_chk_status(groupp, clientp, rv);
	}

	/*NOTREACHED*/
	return (NULL);
}
