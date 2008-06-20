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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <sys/param.h>
#include <fcntl.h>
#include <errno.h>
#include <strings.h>
#include <dirent.h>
#include <priv.h>
#include <syslog.h>

#include <iscsitgt_impl.h>
#include "utility.h"
#include "queue.h"
#include "target.h"
#include "iscsi_cmd.h"
#include "iscsi_conn.h"
#include "port.h"
#include "errcode.h"
#include "mgmt_scf.h"
#include "isns_client.h"

static char *list_targets(tgt_node_t *x);
static char *list_initiator(tgt_node_t *x);
static char *list_tpgt(tgt_node_t *x);
static char *list_admin(tgt_node_t *x);
static void target_info(char **msg, char *targ_name, tgt_node_t *tnode);
static void target_stat(char **msg, char *iname, mgmt_type_t type);

/*ARGSUSED*/
void
list_func(tgt_node_t *p, target_queue_t *reply, target_queue_t *mgmt,
    ucred_t *cred)
{
	tgt_node_t	*x;
	char		msgbuf[80];
	char		*reply_msg	= NULL;

	if (p->x_child == NULL) {
		xml_rtn_msg(&reply_msg, ERR_SYNTAX_MISSING_OBJECT);
	} else {
		x = p->x_child;

		if (x->x_name == NULL) {
			xml_rtn_msg(&reply_msg, ERR_SYNTAX_MISSING_OBJECT);
		} else if (strcmp(x->x_name, XML_ELEMENT_TARG) == 0) {
			reply_msg = list_targets(x);
		} else if (strcmp(x->x_name, XML_ELEMENT_INIT) == 0) {
			reply_msg = list_initiator(x);
		} else if (strcmp(x->x_name, XML_ELEMENT_TPGT) == 0) {
			reply_msg = list_tpgt(x);
		} else if (strcmp(x->x_name, XML_ELEMENT_ADMIN) == 0) {
			reply_msg = list_admin(x);
		} else {
			(void) snprintf(msgbuf, sizeof (msgbuf),
			    "Unknown object '%s' for list element",
			    x->x_name);
			xml_rtn_msg(&reply_msg, ERR_INVALID_OBJECT);
		}
	}
	queue_message_set(reply, 0, msg_mgmt_rply, reply_msg);
}

/*ARGSUSED*/
static char *
list_targets(tgt_node_t *x)
{
	char		*msg	= NULL;
	char		*prop	= NULL;
	char		*iname	= NULL;
	tgt_node_t	*targ	= NULL;
	Boolean_t	luninfo	= False;
	Boolean_t	dostat	= False;

	/*
	 * It's okay to not supply a "name" element. That just means the
	 * administrator wants a complete list of targets. However if a
	 * "name" is supplied then there must be a value for that element.
	 */
	if ((tgt_find_value_str(x, XML_ELEMENT_NAME, &prop) == True) &&
	    (prop == NULL)) {
		xml_rtn_msg(&msg, ERR_SYNTAX_MISSING_NAME);
		return (msg);
	}

	/* ---- optional arguments ---- */
	(void) tgt_find_value_boolean(x, XML_ELEMENT_LUNINFO, &luninfo);
	(void) tgt_find_value_boolean(x, XML_ELEMENT_IOSTAT, &dostat);

	tgt_buf_add_tag_and_attr(&msg, XML_ELEMENT_RESULT, "version='1.0'");
	while ((targ = tgt_node_next_child(targets_config, XML_ELEMENT_TARG,
	    targ)) != NULL) {
		if (targ->x_value == NULL) {
			tgt_buf_add(&msg, XML_ELEMENT_TARG,
			    "bogus entry");
			continue;
		}
		if (tgt_find_value_str(targ, XML_ELEMENT_INAME, &iname) ==
		    False) {
			tgt_buf_add(&msg, XML_ELEMENT_TARG,
			    "missing iscsi-name");
			continue;
		}
		if (prop != NULL) {
			if (strcmp(prop, targ->x_value) == 0) {
				tgt_buf_add_tag(&msg, XML_ELEMENT_TARG,
				    Tag_Start);
				tgt_buf_add_tag(&msg, targ->x_value,
				    Tag_String);
				tgt_buf_add(&msg, XML_ELEMENT_INAME, iname);
				if (luninfo == True)
					target_info(&msg, iname, targ);
				if (dostat == True)
					target_stat(&msg, iname,
					    mgmt_full_phase_statistics);
				tgt_buf_add_tag(&msg, XML_ELEMENT_TARG,
				    Tag_End);
			}
		} else {
			tgt_buf_add_tag(&msg, XML_ELEMENT_TARG, Tag_Start);
			tgt_buf_add_tag(&msg, targ->x_value, Tag_String);
			tgt_buf_add(&msg, XML_ELEMENT_INAME, iname);
			if (dostat == True)
				target_stat(&msg, iname,
				    mgmt_full_phase_statistics);
			if (luninfo == True)
				target_info(&msg, iname, targ);
			tgt_buf_add_tag(&msg, XML_ELEMENT_TARG, Tag_End);
		}
		free(iname);
	}
	tgt_buf_add_tag(&msg, XML_ELEMENT_RESULT, Tag_End);
	free(prop);

	return (msg);
}

/*ARGSUSED*/
static char *
list_initiator(tgt_node_t *x)
{
	char		*msg	= NULL;
	char		*attr	= NULL;
	char		*prop	= NULL;
	Boolean_t	verbose	= False;
	tgt_node_t	*init	= NULL;

	/* ---- Optional arguments ---- */
	if ((tgt_find_value_str(x, XML_ELEMENT_NAME, &prop) == True) &&
	    (prop == NULL)) {
		xml_rtn_msg(&msg, ERR_SYNTAX_MISSING_NAME);
		return (msg);
	}
	(void) tgt_find_value_boolean(x, XML_ELEMENT_VERBOSE, &verbose);

	tgt_buf_add_tag_and_attr(&msg, XML_ELEMENT_RESULT, "version='1.0'");
	while ((init = tgt_node_next_child(main_config, XML_ELEMENT_INIT, init))
	    != NULL) {
		if ((prop == NULL) ||
		    ((prop != NULL) && (strcmp(prop, init->x_value) == 0))) {

			tgt_buf_add_tag(&msg, XML_ELEMENT_INIT, Tag_Start);
			tgt_buf_add_tag(&msg, init->x_value, Tag_String);

			if (tgt_find_value_str(init, XML_ELEMENT_INAME,
			    &attr) == True) {
				tgt_buf_add(&msg, XML_ELEMENT_INAME, attr);
				free(attr);
			}

			if (tgt_find_value_str(init, XML_ELEMENT_CHAPSECRET,
			    &attr) == True) {
				tgt_buf_add(&msg, XML_ELEMENT_CHAPSECRET,
				    "Set");
				free(attr);
			}

			if (tgt_find_value_str(init, XML_ELEMENT_CHAPNAME,
			    &attr) == True) {
				tgt_buf_add(&msg, XML_ELEMENT_CHAPNAME, attr);
				free(attr);
			}

			tgt_buf_add_tag(&msg, XML_ELEMENT_INIT, Tag_End);
		}
	}

	if (prop != NULL)
		free(prop);

	tgt_buf_add_tag(&msg, XML_ELEMENT_RESULT, Tag_End);

	return (msg);
}

/*ARGSUSED*/
static char *
list_tpgt(tgt_node_t *x)
{
	char		*msg	= NULL;
	char		*prop	= NULL;
	Boolean_t	verbose	= False;
	tgt_node_t	*tpgt	= NULL;
	tgt_node_t	*ip	= NULL;

	/* ---- Optional arguments ---- */
	if ((tgt_find_value_str(x, XML_ELEMENT_NAME, &prop) == True) &&
	    (prop == NULL)) {
		xml_rtn_msg(&msg, ERR_SYNTAX_MISSING_NAME);
		return (msg);
	}
	(void) tgt_find_value_boolean(x, XML_ELEMENT_VERBOSE, &verbose);

	tgt_buf_add_tag_and_attr(&msg, XML_ELEMENT_RESULT, "version='1.0'");
	while ((tpgt = tgt_node_next_child(main_config, XML_ELEMENT_TPGT, tpgt))
	    != NULL) {
		if ((prop == NULL) ||
		    ((prop != NULL) && (strcmp(prop, tpgt->x_value) == 0))) {

			tgt_buf_add_tag(&msg, XML_ELEMENT_TPGT, Tag_Start);
			tgt_buf_add_tag(&msg, tpgt->x_value, Tag_String);

			while ((ip = tgt_node_next(tpgt, XML_ELEMENT_IPADDR,
			    ip)) != NULL) {
				tgt_buf_add(&msg, ip->x_name, ip->x_value);
			}

			tgt_buf_add_tag(&msg, XML_ELEMENT_TPGT, Tag_End);
		}
	}
	tgt_buf_add_tag(&msg, XML_ELEMENT_RESULT, Tag_End);

	if (prop != NULL)
		free(prop);
	return (msg);
}

/*ARGSUSED*/
static char *
list_admin(tgt_node_t *x)
{
	char		*msg	= NULL;
	admin_table_t	*p;
	tgt_node_t	*node	= NULL;
	tgt_node_t	*isns_srv_node	= NULL;
	Boolean_t	enabled = False;

	tgt_buf_add_tag_and_attr(&msg, XML_ELEMENT_RESULT, "version='1.0'");
	tgt_buf_add_tag(&msg, XML_ELEMENT_ADMIN, Tag_Start);

	node = NULL;
	for (p = admin_prop_list; p->name != NULL; p++) {
		node = tgt_node_next_child(main_config, p->name, NULL);
		if (node) {
			if (strcmp(p->name, XML_ELEMENT_CHAPSECRET) == 0) {
				tgt_buf_add(&msg, p->name, "Set");
			} else if (strcmp(p->name, XML_ELEMENT_ISNS_ACCESS)
			    == 0) {
				tgt_buf_add(&msg, p->name, node->x_value);
				/* check the isns discovery */
				if (node->x_value &&
				    strcmp(node->x_value, "true") == 0) {
					enabled = True;
				}
			} else if (strcmp(p->name, XML_ELEMENT_ISNS_SERV)
			    == 0) {
				tgt_buf_add(&msg, p->name, node->x_value);
				/*
				 * check the state of isns server connection.
				 */
				if (node->x_value != NULL) {
					isns_srv_node = node;
				}
			} else {
				tgt_buf_add(&msg, p->name, node->x_value);
			}
		}
	}

	/*
	 * check the state of isns server connection and add the node.
	 * the conncection state is dynamic so it doesn't get stored in
	 * incore config.
	 */
	if (enabled && isns_srv_node) {
		if (isns_open(isns_srv_node->x_value) == -1) {
			tgt_buf_add(&msg, XML_ELEMENT_ISNS_SERVER_STATUS,
			    "Unavailable");
		} else {
			tgt_buf_add(&msg, XML_ELEMENT_ISNS_SERVER_STATUS,
			    "Available");
		}
	} else {
		tgt_buf_add(&msg, XML_ELEMENT_ISNS_SERVER_STATUS,
		"Not applicable");
	}

	tgt_buf_add_tag(&msg, XML_ELEMENT_ADMIN, Tag_End);
	tgt_buf_add_tag(&msg, XML_ELEMENT_RESULT, Tag_End);

	return (msg);
}

static void
target_stat(char **msg, char *targ_name, mgmt_type_t type)
{
	iscsi_conn_t	*c;
	msg_t		*m;
	target_queue_t	*q = queue_alloc();
	mgmt_request_t	mgmt_rqst;
	int		msg_sent;
	int		i;
	extern pthread_mutex_t	port_mutex;

	mgmt_rqst.m_q		= q;
	mgmt_rqst.m_u.m_resp	= msg;
	mgmt_rqst.m_time	= time(NULL);
	mgmt_rqst.m_request	= type;
	(void) pthread_mutex_init(&mgmt_rqst.m_resp_mutex, NULL);

	(void) pthread_mutex_lock(&port_mutex);
	mgmt_rqst.m_targ_name	= targ_name;
	msg_sent		= 0;
	for (c = conn_head; c; c = c->c_next) {
		if (c->c_state == S5_LOGGED_IN) {
			/*
			 * Only send requests for statistics to
			 * connections that are up. Could even
			 * go further and only look at connections
			 * which are S5_LOGGED_IN, but there may
			 * be statistics, such as connection time,
			 * which we'd like to have.
			 */
			queue_message_set(c->c_dataq, 0, msg_mgmt_rqst,
			    &mgmt_rqst);
			msg_sent++;
		}
	}
	(void) pthread_mutex_unlock(&port_mutex);

	/*
	 * Comment: main.c:list_targets:1
	 * We wait for the responses without the port_mutex
	 * being held. There is a small window between when the
	 * connection last listens for a message and when the
	 * queue is freed. During that time the connection will
	 * attempt to grab the port_mutex lock so that it
	 * can unlink itself and call queueu_free(). If we sent
	 * the message with the lock held and then wait for a response
	 * it's possible that the connection will deadlock waiting
	 * to get the port_mutex.
	 */
	for (i = 0; i < msg_sent; i++) {
		m = queue_message_get(q);
		queue_message_free(m);
	}
	queue_free(q, NULL);
}

static void
target_info(char **msg, char *targ_name, tgt_node_t *tnode)
{
	char			lun_buf[16];
	char			*prop;
	char			*local_name = NULL;
	tgt_node_t		*lnode;	/* list node */
	tgt_node_t		*lnp; /* list node pointer */
	tgt_node_t		*lun;
	tgt_node_t		*params;
	int			lun_num;
	Boolean_t		incore;
	struct stat		s;

	if ((lnode = tgt_node_next(tnode, XML_ELEMENT_ACLLIST, NULL)) !=
	    NULL) {
		lnp = NULL;
		tgt_buf_add_tag(msg, XML_ELEMENT_ACLLIST, Tag_Start);
		while ((lnp = tgt_node_next(lnode, XML_ELEMENT_INIT, lnp)) !=
		    NULL)
			tgt_buf_add(msg, XML_ELEMENT_INIT, lnp->x_value);
		tgt_buf_add_tag(msg, XML_ELEMENT_ACLLIST, Tag_End);
	}

	if ((lnode = tgt_node_next(tnode, XML_ELEMENT_TPGTLIST, NULL)) !=
	    NULL) {
		lnp = NULL;
		tgt_buf_add_tag(msg, XML_ELEMENT_TPGTLIST, Tag_Start);
		while ((lnp = tgt_node_next(lnode, XML_ELEMENT_TPGT, lnp)) !=
		    NULL)
			tgt_buf_add(msg, XML_ELEMENT_TPGT, lnp->x_value);
		tgt_buf_add_tag(msg, XML_ELEMENT_TPGTLIST, Tag_End);
	}

	if ((lnode = tgt_node_next(tnode, XML_ELEMENT_ALIAS, NULL)) != NULL)
		tgt_buf_add(msg, XML_ELEMENT_ALIAS, lnode->x_value);

	if ((lnode = tgt_node_next(tnode, XML_ELEMENT_MAXRECV, NULL)) != NULL)
		tgt_buf_add(msg, XML_ELEMENT_MAXRECV, lnode->x_value);

	if ((lnode = tgt_node_next(tnode, XML_ELEMENT_LUNLIST, NULL)) == NULL)
		return;

	if (tgt_find_attr_str(tnode, XML_ELEMENT_INCORE, &prop) == True) {
		if (strcmp(prop, "true") == 0)
			incore = True;
		else
			incore = False;
		free(prop);
	} else
		incore = False;

	tgt_buf_add_tag(msg, XML_ELEMENT_LUNINFO, Tag_Start);
	lun = NULL;
	while ((lun = tgt_node_next(lnode, XML_ELEMENT_LUN, lun)) != NULL) {
		if ((tgt_find_value_int(lun, XML_ELEMENT_LUN, &lun_num)) ==
		    False)
			continue;
		if (incore == False) {
			local_name = get_local_name(targ_name);
			if (local_name != NULL) {
				(void) mgmt_get_param(&params, local_name,
				    lun_num);
				free(local_name);
			} else {
				continue;
			}
		} else {
			params = lun;
		}

		tgt_buf_add_tag(msg, XML_ELEMENT_LUN, Tag_Start);
		(void) snprintf(lun_buf, sizeof (lun_buf), "%d", lun_num);
		tgt_buf_add_tag(msg, lun_buf, Tag_String);

		if (tgt_find_value_str(params, XML_ELEMENT_GUID, &prop) ==
		    True) {
			tgt_buf_add(msg, XML_ELEMENT_GUID, prop);
			free(prop);
		}
		if (tgt_find_value_str(params, XML_ELEMENT_VID, &prop) ==
		    True) {
			tgt_buf_add(msg, XML_ELEMENT_VID, prop);
			free(prop);
		}
		if (tgt_find_value_str(params, XML_ELEMENT_PID, &prop) ==
		    True) {
			tgt_buf_add(msg, XML_ELEMENT_PID, prop);
			free(prop);
		}
		if (tgt_find_value_str(params, XML_ELEMENT_DTYPE, &prop) ==
		    True) {
			tgt_buf_add(msg, XML_ELEMENT_DTYPE, prop);
			free(prop);
		}
		if (tgt_find_value_str(params, XML_ELEMENT_SIZE, &prop) ==
		    True) {
			tgt_buf_add(msg, XML_ELEMENT_SIZE, prop);
			free(prop);
		}
		if (tgt_find_value_str(params, XML_ELEMENT_BACK, &prop) ==
		    True) {
			tgt_buf_add(msg, XML_ELEMENT_BACK, prop);
			if (stat(prop, &s) == 0) {
				tgt_buf_add(msg, XML_ELEMENT_STATUS,
				    TGT_STATUS_ONLINE);
			} else {
				tgt_buf_add(msg, XML_ELEMENT_STATUS,
				    strerror(errno));
			}
			free(prop);
		}
		tgt_buf_add_tag(msg, XML_ELEMENT_LUN, Tag_End);

		if (incore == False)
			tgt_node_free(params);
	}
	tgt_buf_add_tag(msg, XML_ELEMENT_LUNINFO, Tag_End);
}
