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


#define	FD_SETSIZE	65536
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/conf.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <errno.h>
#include <door.h>
#include <signal.h>
#include <siginfo.h>
#include <sys/ethernet.h>
#include <libscf.h>
#include <syslog.h>
#include <synch.h>
#include <libxml/xmlreader.h>
#include <sys/resource.h>
#include <syslog.h>
#include <sys/select.h>
#include <iscsitgt_impl.h>
#include <umem.h>

#include "queue.h"
#include "port.h"
#include "iscsi_conn.h"
#include "target.h"
#include "utility.h"
#include "iscsi_ffp.h"
#include "errcode.h"
#include "t10.h"
#include "mgmt_scf.h"

#include "isns_client.h"

#define	EMPTY_CONFIG "<config version='1.0'>\n</config>\n"

/* ---- Forward declarations ---- */
static void variable_handler(tgt_node_t *, target_queue_t *, target_queue_t *,
    ucred_t *);


/* ---- Global configuration data. ---- */
char		*target_basedir		= NULL;
char		*target_log		= DEFAULT_TARGET_LOG;
char		*config_file		= DEFAULT_CONFIG_LOCATION;
char		*pgr_basedir		= NULL;
int		iscsi_port		= 3260, /* defined by the spec */
		dbg_lvl			= 0,
		door_min_space;
tgt_node_t	*main_config,
		*targets_config;
Boolean_t	enforce_strict_guid	= True,
		thin_provisioning	= False,
		disable_tpgs		= False,
		dbg_timestamps		= False,
		pgr_persist		= True;
int		targets_vers_maj,
		targets_vers_min,
		main_vers_maj,
		main_vers_min;
pthread_rwlock_t	targ_config_mutex;
umem_cache_t	*iscsi_cmd_cache,
		*t10_cmd_cache,
		*queue_cache;

typedef struct var_table {
	char	*v_name;
	int	*v_value;
} var_table_t;

typedef struct cmd_table {
	char	*c_name;
	void	(*c_func)(tgt_node_t *, target_queue_t *, target_queue_t *,
		ucred_t *);
} cmd_table_t;

admin_table_t admin_prop_list[] = {
	{XML_ELEMENT_BASEDIR,		update_basedir,	NULL},
	{XML_ELEMENT_CHAPSECRET,	0,	NULL},
	{XML_ELEMENT_CHAPNAME,		0,	NULL},
	{XML_ELEMENT_RAD_ACCESS,	0,	NULL},
	{XML_ELEMENT_RAD_SERV,		valid_radius_srv, NULL},
	{XML_ELEMENT_RAD_SECRET,	0,	NULL},
	{XML_ELEMENT_ISNS_ACCESS,	0,	NULL},
	{XML_ELEMENT_ISNS_SERV,		valid_isns_srv,	NULL},
	{XML_ELEMENT_FAST,		0,	NULL},
	{XML_ELEMENT_DELETE_CHAPSECRET,	0,	XML_ELEMENT_CHAPSECRET},
	{XML_ELEMENT_DELETE_CHAPNAME,	0,	XML_ELEMENT_CHAPNAME},
	{XML_ELEMENT_DELETE_RAD_SECRET,	0,	XML_ELEMENT_RAD_SECRET},
	{XML_ELEMENT_DELETE_RAD_SERV,	0,	XML_ELEMENT_RAD_SERV},
	{0,				0}
};

/*
 * Global variables which can be set via the management XML interface
 * with the syntax of "<variable><dbg_lvl>0x033</dbg_lvl></variable>"
 */
var_table_t var_table[] = {
	{ "dbg_lvl", &dbg_lvl },
	{ "qlog_lvl", &qlog_lvl },
	/* ---- End of Table marker ---- */
	{ NULL, 0 }
};

/*
 * Commands which are run via the management XML interface
 */
cmd_table_t cmd_table[] = {
	{ "variable",	variable_handler },
	{ "create",	create_func },
	{ "modify",	modify_func },
	{ "delete",	remove_func },
	{ "list",	list_func },
	/* ---- End of Table marker ---- */
	{ NULL,		NULL }
};

/*
 * []----
 * | process_config -- parse the main configuration file
 * |
 * | Everything in the configuratin file is optional. That's because
 * | the management CLI can set the value to everything and update
 * | the configuration.
 * []----
 */
static Boolean_t
process_config()
{
	tgt_node_t		*node = NULL;

#ifndef lint
	LIBXML_TEST_VERSION;
#endif

	if (mgmt_get_main_config(&node) == False) {
		return (False);
	}

	main_vers_maj = XML_VERS_MAIN_MAJ;
	main_vers_min = XML_VERS_MAIN_MIN;
	if (validate_version(node, &main_vers_maj, &main_vers_min) ==
	    False) {
		syslog(LOG_ERR, "Target main config invalid");
		return (False);
	}

	/*
	 * The base directory is optional in the sense that the daemon
	 * can start without it, but the daemon can't really do
	 * anything until the administrator sets the value.
	 */
	(void) tgt_find_value_str(node, XML_ELEMENT_BASEDIR,
	    &target_basedir);

	/*
	 * These are optional settings for the target. Each of
	 * these has a default value which can be overwritten in
	 * the configuration.
	 */
	(void) tgt_find_value_str(node, XML_ELEMENT_TARGLOG,
	    &target_log);
	(void) tgt_find_value_int(node, XML_ELEMENT_ISCSIPORT,
	    &iscsi_port);
	(void) tgt_find_value_intchk(node, XML_ELEMENT_DBGLVL, &dbg_lvl);
	(void) tgt_find_value_boolean(node, XML_ELEMENT_ENFORCE,
	    &enforce_strict_guid);
	(void) tgt_find_value_boolean(node, XML_ELEMENT_THIN_PROVO,
	    &thin_provisioning);
	(void) tgt_find_value_boolean(node, XML_ELEMENT_DISABLE_TPGS,
	    &disable_tpgs);
	(void) tgt_find_value_boolean(node, XML_ELEMENT_TIMESTAMPS,
	    &dbg_timestamps);
	(void) tgt_find_value_boolean(node, XML_ELEMENT_PGR_PERSIST,
	    &pgr_persist);
	(void) tgt_find_value_str(node, XML_ELEMENT_PGR_BASEDIR,
	    &pgr_basedir);
	if (tgt_find_value_intchk(node, XML_ELEMENT_LOGLVL,
	    &qlog_lvl) == True)
		queue_log(True);

	main_config = node;
	targets_config = node;

	return (True);
}

/*
 * []----
 * | logout_cleanup -- see if the initiator did what was requested
 * |
 * | When a target issues an asynchrouns event with the code set to
 * | "logout requested" the initiator is supposed to respond with
 * | a LogoutRequested PDU within a certain amount of time. If it
 * | fails to do so, it's the targets responsibility to clean up.
 * | We will check logout status in a 1 second interval, if the
 * | initiators responded to the logout request then logout is
 * | conpleted, if ASYNC_LOGOUT_TIMEOUT seconds (currently 10)
 * | is reached then we will reissue the management request to
 * | to logout which will cause the connections to close.
 * []----
 */
static void *
logout_cleanup(void *v)
{
	int		msg_sent, i;
	char		*targ = (char *)v;
	mgmt_request_t	m;
	iscsi_conn_t	*conn;
	extern pthread_mutex_t port_mutex;
	Boolean_t	logout = False;

	bzero(&m, sizeof (m));
	m.m_request	= mgmt_logout;
	m.m_q		= queue_alloc();
	msg_sent	= 0;

	/*
	 * The for loop is to manage the wait time for the
	 * logout request to complete, if logout completed
	 * before ASYNC_LOGOUT_TIMEOUT then done
	 */
	for (i = 0; i < ASYNC_LOGOUT_TIMEOUT; i++) {
		logout = True;
		(void) pthread_mutex_lock(&port_mutex);
		for (conn = conn_head; conn; conn = conn->c_next) {
			if ((conn->c_state == S7_LOGOUT_REQUESTED) &&
			    (strcmp(conn->c_sess->s_t_name, targ) == 0)) {
				logout = False;
				break;
			}
		}
		(void) pthread_mutex_unlock(&port_mutex);
		if (logout)
			break;
		else
			(void) sleep(1);
	}

	/*
	 * Logout did not complete, queue message to shutdown
	 * connection.
	 */
	if (logout == False) {
		(void) pthread_mutex_lock(&port_mutex);
		for (conn = conn_head; conn; conn = conn->c_next) {
			if ((conn->c_state == S7_LOGOUT_REQUESTED) &&
			    (strcmp(conn->c_sess->s_t_name, targ) == 0)) {
				queue_message_set(conn->c_dataq, 0,
				    msg_mgmt_rqst, &m);
				msg_sent++;
			}
		}
		(void) pthread_mutex_unlock(&port_mutex);
	}

	/*
	 * Wait to see if they received the message.
	 */
	for (i = 0; i < msg_sent; i++)
		queue_message_free(queue_message_get(m.m_q));
	queue_free(m.m_q, NULL);
	free(targ);

	queue_message_set(mgmtq, 0, msg_pthread_join,
	    (void *)(uintptr_t)pthread_self());
	return ((void *)0);
}

void
logout_targ(char *targ)
{
	mgmt_request_t	m;
	iscsi_conn_t	*conn;
	int		i, msg_sent;
	pthread_t	junk;
	extern pthread_mutex_t	port_mutex;

	/*
	 * Now we look for connections to this target and issue
	 * a request to asynchronously logout.
	 */
	bzero(&m, sizeof (m));
	m.m_request	= mgmt_logout;
	m.m_q		= queue_alloc();
	msg_sent	= 0;

	(void) pthread_mutex_lock(&port_mutex);
	for (conn = conn_head; conn; conn = conn->c_next) {
		if (conn->c_state != S5_LOGGED_IN)
			continue;
		if (conn->c_sess->s_type == SessionDiscovery)
			continue;

		if (strcmp(conn->c_sess->s_t_name, targ) == 0) {
			queue_message_set(conn->c_dataq, 0, msg_mgmt_rqst, &m);
			msg_sent++;
		}
	}
	(void) pthread_mutex_unlock(&port_mutex);

	/* ---- Wait to see if they received the message. ---- */
	for (i = 0; i < msg_sent; i++)
		queue_message_free(queue_message_get(m.m_q));

	queue_free(m.m_q, NULL);

	/* ---- Start housecleaning thread ---- */
	(void) pthread_create(&junk, NULL, logout_cleanup,
	    (void *)strdup(targ));
}

/*
 * [] ---- XML Management Handlers ---- []
 */

/*
 * []----
 * | variable_handler -- used to set a couple of internal global variables
 * []----
 */
/*ARGSUSED*/
void
variable_handler(tgt_node_t *x, target_queue_t *reply, target_queue_t *mgmt,
    ucred_t *cred)
{
	char			*reply_buf	= NULL;
	var_table_t		*v;
	tgt_node_t		*c;

	if (check_auth_modify(cred) != True) {
		xml_rtn_msg(&reply_buf, ERR_NO_PERMISSION);
		queue_str(reply, 0, msg_mgmt_rply, reply_buf);
		return;
	}
	for (c = x->x_child; c; c = c->x_sibling) {

		for (v = var_table; v->v_name; v++) {
			if (strcmp(c->x_name, v->v_name) == 0) {
				*v->v_value = strtol(c->x_value, NULL, 0);
				if (strcmp(v->v_name, "qlog_lvl") == 0)
					queue_log(True);
				xml_rtn_msg(&reply_buf, ERR_SUCCESS);
				break;
			}
		}
		if (v->v_name == NULL)
			xml_rtn_msg(&reply_buf, ERR_NO_MATCH);

		queue_str(reply, 0, msg_mgmt_rply, reply_buf);
	}
}

/*
 * []----
 * | parse_xml -- incoming management requests are sent here for processing
 * []----
 */
static void
parse_xml(tgt_node_t *x, target_queue_t *reply, target_queue_t *mgmt,
    ucred_t *cred)
{
	char		*reply_msg	= NULL;
	cmd_table_t	*c;

	if ((x->x_name == NULL) || (x->x_state == NodeFree)) {
		xml_rtn_msg(&reply_msg, ERR_SYNTAX_EMPTY);
		queue_message_set(reply, 0, msg_mgmt_rply, reply_msg);
		return;
	}

	for (c = cmd_table; c->c_name != NULL; c++)
		if (strcmp(c->c_name, x->x_name) == 0)
			break;
	if (c->c_name == NULL) {
		xml_rtn_msg(&reply_msg, ERR_INVALID_COMMAND);
		queue_message_set(reply, 0, msg_mgmt_rply, reply_msg);
	} else {
		(c->c_func)(x, reply, mgmt, cred);
	}
}

/*
 * space_message -- create a message indicating the amount of space needed.
 *
 * This code could have been inline in the server_for_door function, but
 * at system startup we'll determine the minimum amount of space needed for
 * a door call return pointer. This minimum amount of space will be either
 * a "need more space" or a "success" message. So, have this code as a function
 * reduces any duplication.
 */
static void
space_message(char **buf, int size)
{
	char	lbuf[16];
	tgt_buf_add_tag_and_attr(buf, XML_ELEMENT_ERROR, "version='1.0'");
	(void) snprintf(lbuf, sizeof (lbuf), "%d", size);
	tgt_buf_add(buf, XML_ELEMENT_MORESPACE, lbuf);
	tgt_buf_add_tag(buf, XML_ELEMENT_ERROR, Tag_End);
}

/*ARGSUSED*/
static void
server_for_door(void *cookie, char *argp, size_t arg_size, door_desc_t *dp,
    uint_t n_desc)
{
	target_queue_t		*mgmtq		= (target_queue_t *)cookie;
	mgmt_request_t		m;
	msg_t			*msg		= NULL;
	tgt_node_t		*node		= NULL;
	xmlTextReaderPtr	r;
	char			*err_rply	= NULL;
	ucred_t			*uc		= NULL;
	size_t			cur_space;

	/*
	 * A well written application will always give us enough space
	 * to send either a "success" message or a "more space needed".
	 * If the minimum amount of space isn't given then just return
	 * with a NULL pointer.
	 */
	if (arg_size < door_min_space) {
		(void) door_return(NULL, 0, NULL, 0);
		return;
	}

	/*
	 * Pick up the user credentials of the client application. Used to
	 * validate that the effective user ID is either root or the process
	 * has the privilege to complete the operation.
	 */
	if (door_ucred(&uc) != 0) {
		xml_rtn_msg(&err_rply, ERR_BAD_CREDS);
		(void) strlcpy(argp, err_rply, arg_size);
		free(err_rply);
		(void) door_return(argp, strlen(argp) + 1, NULL, 0);
		return;
	}

	if (validate_xml(argp) != True) {
		xml_rtn_msg(&err_rply, ERR_INVALID_XML_REQUEST);
		(void) strlcpy(argp, err_rply, arg_size);
		free(err_rply);
		(void) door_return(argp, strlen(argp) + 1, NULL, 0);
		return;
	}

	bzero(&m, sizeof (m));

	if ((r = (xmlTextReaderPtr)xmlReaderForMemory(argp, strlen(argp),
	    NULL, NULL, 0)) != NULL) {
		while (xmlTextReaderRead(r)) {
			if (tgt_node_process(r, &node) == False)
				break;
		}
		if (node != NULL) {
			m.m_q		= queue_alloc();
			m.m_request	= mgmt_parse_xml;
			m.m_time	= time(NULL);
			m.m_targ_name	= NULL;
			m.m_u.m_node	= node;
			m.m_cred	= uc;

			queue_message_set(mgmtq, 0, msg_mgmt_rqst, &m);
			if ((msg = queue_message_get(m.m_q)) == NULL) {
				(void) xmlFreeTextReader(r);
				(void) xmlCleanupParser();
				(void) ucred_free(uc);
				tgt_node_free(node);
				if (m.m_q != NULL)
					queue_free(m.m_q, NULL);
				(void) door_return("", 1, NULL, 0);
				return;
			}

			/*
			 * Check to see if the response can fit into the
			 * incoming argument buffer. If so, copy the response
			 * to that buffer so that we can free the data.
			 * If it's not big enough we'll request an updated
			 * space message, then delete the current data, allowing
			 * the request to be requeued again.
			 */
			if ((cur_space = strlen(msg->msg_data)) < arg_size) {
				(void) strlcpy(argp, msg->msg_data, arg_size);
			} else {
				/*
				 * err_rply will be copied to argp at the end
				 */
				space_message(&err_rply, cur_space + 1);
			}
			free(msg->msg_data);
			queue_message_free(msg);
		} else {
			xml_rtn_msg(&err_rply, ERR_NULL_XML_MESSAGE);
		}

		xmlFreeTextReader(r);
		xmlCleanupParser();

	} else {
		xml_rtn_msg(&err_rply, ERR_INIT_XML_READER_FAILED);
	}

	if (node != NULL)
		tgt_node_free(node);
	if (err_rply != NULL) {
		(void) strlcpy(argp, err_rply, arg_size);
		free(err_rply);
	}
	if (m.m_q != NULL)
		queue_free(m.m_q, NULL);

	ucred_free(uc);
	(void) door_return(argp, strlen(argp) + 1, NULL, 0);
}

/*
 * []----
 * | setup_door -- Create a door portal for management requests
 * |
 * | First check to see if another daemon is already running by attempting
 * | to send an empty request to the door. If successful it means this
 * | daemon should exit.
 * []----
 */
static void
setup_door(target_queue_t *q, char *door_name)
{
	int		did, fd;
	struct stat	s;
	door_arg_t	d;
	char		*msg = NULL;

	/*
	 * Figure out what the minimum amount of space required to send back
	 * either a success message or a need more space one.
	 *
	 * Commands fall into one of three categories.
	 * (1) Idempotent commands, like list operations, which can
	 *    return large ammounts of data. If there's not enough room
	 *    the client is informed and the command is run again with a
	 *    larger buffer.
	 * (2) Create, modify, or delete operations that fail. These
	 *    commands may return an error message which is larger than
	 *    the incoming request buffer. If so, the client is informed
	 *    that a larger buffer is needed and the command is rerun. This
	 *    time it'll recieve the full error message. So, these commands
	 *    are idempotent because no state changes occur on failure.
	 * (3) Create, modify, or delete operations which are successful.
	 *    Since successful completion means state has change the daemon
	 *    must always be able to report success, other wise a second
	 *    attempt with a larger buffer would then fail, where the first
	 *    one actually succeeded.
	 */
	xml_rtn_msg(&msg, ERR_SUCCESS);
	door_min_space = strlen(msg);
	free(msg);
	msg = NULL;
	/*
	 * Use an impossibly big number which will create the longest string
	 */
	space_message(&msg, 0x80000000);
	door_min_space = MAX(door_min_space, strlen(msg));
	free(msg);

	door_min_space++;	/* add 1 for the NULL byte */

	/*
	 * DOOR_MIN_SPACE will be the amount used by the library as the default.
	 * Currently this will be set to 128 (check iscsitgt_impl.h for value).
	 * Since this will be a compiled value and the "success" or "more space"
	 * messages could grown we need to detect if there will be a problem.
	 * By failing here consistently, SMF will put the daemon in maintenance
	 * state and this will be caught during testing. Otherwise the library
	 * would receive a NULL back, but not know how much space is really
	 * required.
	 */
	if (door_min_space > DOOR_MIN_SPACE) {
		syslog(LOG_ERR,
		    "Calculated min space (%d) is larger than default (%d)",
		    door_min_space, DOOR_MIN_SPACE);
		assert(0);
	}

	if ((fd = open(door_name, 0)) >= 0) {

		/*
		 * There's at least a file with the same name as our
		 * door. Let's see if someone is currently answering
		 * by sending an empty XML request.
		 */
		d.data_ptr	= "<config></config>";
		d.data_size	= strlen(d.data_ptr) + 1;
		d.desc_ptr	= NULL;
		d.desc_num	= 0;
		d.rbuf		= NULL;
		d.rsize		= 0;

		if (door_call(fd, &d) == 0) {

			/*
			 * If the door_call succeeds that means another
			 * daemon is already running so let's just exit.
			 */
			exit(0);
		}
		(void) close(fd);
	}

	if ((did = door_create(server_for_door, (void *)q, 0)) < 0) {
		syslog(LOG_ERR, "door_create");
		exit(1);
	}

	if (stat(door_name, &s) < 0) {
		int	newfd;
		if ((newfd = creat(door_name, 0666)) < 0) {
			syslog(LOG_ERR, "creat failed");
			exit(1);
		}
		(void) close(newfd);
	}
	(void) fdetach(door_name);

	/*
	 * Open the door for general access. As the calls come in we'll
	 * get the credentials and validate within each operation as to the
	 * required privileges.
	 */
	(void) chmod(door_name, 0666);

	if (fattach(did, door_name) < 0) {
		syslog(LOG_ERR, "fattach failed errno=%d", errno);
		exit(2);
	}
}

/*ARGSUSED*/
void
exit_after_door_setup(int sig, siginfo_t *sip, void *v)
{
	exit(SMF_EXIT_OK);
}

int
main(int argc, char **argv)
{
	char			c, *p, *door_name;
	msg_t			*msg;
	target_queue_t		*q;
	port_args_t		port1, port2;
	Boolean_t		mgmt_up		= False;
	Boolean_t		daemonize	= True;
	Boolean_t		console_output	= True;
	pthread_t		junk;
	mgmt_request_t		*mgmt;
	struct sigaction	act;
	struct rlimit		rl;
	void			*thr_status;

	door_name	= ISCSI_TARGET_MGMT_DOOR;

	while ((c = getopt(argc, argv, "c:d:")) != EOF) {
		switch (c) {
		case 'c':
			config_file = optarg;
			break;
		case 'd':
			door_name = optarg;
			break;
		}
	}

	/*
	 * If the initiator closes the socket because of a protocol error
	 * or bad digest on the header packet we'll receive a SIGPIPE if we're
	 * in the middle of a write operation. There's no need to receive
	 * a signal when a -1 from the write will handle things correctly.
	 * So, ignore SIGPIPE's.
	 */
	(void) sigignore(SIGPIPE);

	/*
	 * Setup memory caches
	 */
	if ((iscsi_cmd_cache = umem_cache_create("iSCSI conn cmds",
	    sizeof (iscsi_cmd_t), 8, NULL, NULL, NULL, NULL, NULL, 0)) ==
	    NULL) {
		perror("cache create");
		exit(SMF_EXIT_ERR_CONFIG);
	}
	if ((t10_cmd_cache = umem_cache_create("T10 cmds",
	    sizeof (t10_cmd_t), 8, NULL, NULL, NULL, NULL, NULL, 0)) == NULL) {
		perror("cache create");
		exit(SMF_EXIT_ERR_CONFIG);
	}
	if ((queue_cache = umem_cache_create("Queue messages",
	    sizeof (msg_t), 8, NULL, NULL, NULL, NULL, NULL, 0)) == NULL) {
		perror("cache create");
		exit(SMF_EXIT_ERR_CONFIG);
	}

	/*
	 * Look at the function lu_buserr_handler() in t10_sam.c to see the
	 * details of why we need to handle segmentation violations.
	 */
	bzero(&act, sizeof (act));
	act.sa_sigaction	= lu_buserr_handler;
	act.sa_flags		= SA_SIGINFO;

	if (sigaction(SIGBUS, &act, NULL) == -1) {
		perror("sigaction");
		exit(SMF_EXIT_ERR_CONFIG);
	}


	if (mgmt_convert_conf() == CONVERT_FAIL)
		exit(SMF_EXIT_ERR_CONFIG);

	if (process_config() == False)
		exit(SMF_EXIT_ERR_CONFIG);

	/*
	 * During the normal corse of events 'target_basedir' will be
	 * free when the administrator changes the base directory. Instead
	 * of trying to check for the initial case of this value being set
	 * to some static string, always allocate that string.
	 * NOTE: This must be done *after* process_config() is called since
	 * it's possible and very likely that this value will be set at that
	 * time.
	 */
	if (target_basedir == NULL)
		target_basedir = strdup(DEFAULT_TARGET_BASEDIR);

	(void) tgt_find_value_boolean(main_config, XML_ELEMENT_DBGDAEMON,
	    &daemonize);

	q = queue_alloc();
	if (daemonize == True) {
		closefrom(0);

		/*
		 * Set up a signal handler to catch SIGUSR2. Once the child
		 * has setup the door, it will signal the parent that it's
		 * safe to exit. Without doing this it's possible that the
		 * daemon will start and the parent exit before the child has
		 * setup the door. If that happens 'zfs share -a iscsi' which
		 * is run from svc-iscsitgt will fail to open the door and try
		 * to wait for the iscsitgt service to come online. Since
		 * the zfs command is part of the service start, the service
		 * will not come online and we'll fail to share any ZVOLs.
		 */
		bzero(&act, sizeof (act));
		act.sa_sigaction	= exit_after_door_setup;
		act.sa_flags		= SA_SIGINFO;
		if (sigaction(SIGUSR2, &act, NULL) == -1) {
			perror("sigaction");
			exit(SMF_EXIT_ERR_CONFIG);
		}

		switch (fork()) {
		case 0:
			/*
			 * As the child process, setup the door and then
			 * signal the parent that it can exit since the child
			 * is now ready to start accepting requests on the
			 * door.
			 */
			setup_door(q, door_name);
			(void) kill(getppid(), SIGUSR2);
			break;

		case -1:
			/* ---- Failed to fork!. Trouble ---- */
			exit(SMF_EXIT_ERR_CONFIG);

		default:
			/*
			 * If pause() returns with an error something
			 * interrupted the process which was not a SIGUSR2.
			 * Exit with an error code such that SMF can flag
			 * this problem.
			 */
			if (pause() == -1)
				exit(SMF_EXIT_ERR_CONFIG);
		}
	} else {

		/*
		 * The daemon is working in debug mode, so go ahead and
		 * setup the door now.
		 */
		setup_door(q, door_name);
	}

	/*
	 * Initialize the various subsystems. In most cases these are
	 * just initializing mutexs.
	 */
	(void) pthread_rwlock_init(&targ_config_mutex, NULL);
	iscsi_cmd_init();
	session_init();
	t10_init(q);
	port_init();
	queue_init();
	util_init();
	(void) isns_init(q);

	/*
	 * If there's no MAC address currently available don't worry about
	 * it. The first time an initiator connects the SAM-3 layer will
	 * attempt to create a GUID and force another look for a MAC address.
	 */
	if (if_find_mac(q) == False)
		queue_prt(q, Q_GEN_DETAILS, "MAIN: No MAC address available");

	/*
	 * At a minimum we need two file descriptors for each target, one for
	 * the socket and one for the backing store. If there's more than one
	 * initiator attached to a given target than that number goes up by 1.
	 * Once we have multiple sessions per connection that to will cause
	 * an increase.
	 */
	if ((getrlimit(RLIMIT_NOFILE, &rl) == 0) &&
	    (rl.rlim_cur < TARGET_NOFILE)) {
		rl.rlim_cur = TARGET_NOFILE;
		if (setrlimit(RLIMIT_NOFILE, &rl) != 0)
			syslog(LOG_NOTICE,
			    "Can't set new limit for open files");
	}

	port1.port_mgmtq	= q;
	port1.port_num		= iscsi_port;
	(void) pthread_create(&junk, NULL, port_watcher, &port1);

	if ((tgt_find_value_int(main_config, XML_ELEMENT_MGMTPORT,
	    &port2.port_num) == True) && (port2.port_num != -1)) {
		port2.port_mgmtq	= q;
		port2.port_dataq	= queue_alloc();
		(void) pthread_create(&junk, NULL, port_management, &port2);
	}

	do {
		msg = queue_message_get(q);

		switch (msg->msg_type) {
		case msg_pthread_join:
			(void) pthread_join((pthread_t)(uintptr_t)msg->msg_data,
			    &thr_status);
			if (thr_status != 0)
				queue_prt(q, Q_GEN_ERRS,
				    "Thread %d exit with %d",
				    msg->msg_data, thr_status);
			msg->msg_data = NULL;
			break;

		case msg_log:
			if ((p = strchr(msg->msg_data, '\n')) != NULL)
				*p = '\0';
			p = (char *)msg->msg_data;
			if ((msg->msg_pri_level & dbg_lvl) == 0)
				break;

			if (mgmt_up == True)
				queue_str(port2.port_dataq, Q_GEN_DETAILS,
				    msg_log, p);
			if (console_output == True)
				(void) printf("%s\n", p);
			break;

		case msg_mgmt_rqst:
			mgmt = (mgmt_request_t *)msg->msg_data;
			if (mgmt->m_request == mgmt_parse_xml)
				parse_xml(mgmt->m_u.m_node, mgmt->m_q, q,
				    mgmt->m_cred);
			msg->msg_data = NULL;
			break;

		case msg_status:
			p = (char *)msg->msg_data;
			/*
			 * NOTE:
			 * These are real error conditons being sent from
			 * the other threads and should be logged in
			 * some manner, either syslog() or using a FMA
			 * interface.
			 */
			(void) printf("STATUS: %s\n", p);
			break;

		default:
			break;
		}

		if (msg->msg_data != NULL)
			free(msg->msg_data);
		queue_message_free(msg);
	/*CONSTANTCONDITION*/
	} while (1);

	return (0);
}
