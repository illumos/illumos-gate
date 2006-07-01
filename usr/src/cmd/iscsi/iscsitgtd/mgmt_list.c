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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <time.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <sys/param.h>
#include <fcntl.h>
#include <errno.h>
#include <strings.h>
#include <dirent.h>

#include "utility.h"
#include <xml.h>
#include "queue.h"
#include "target.h"
#include "iscsi_cmd.h"
#include "iscsi_conn.h"
#include "port.h"
#include "errcode.h"

static char *list_targets(xml_node_t *x);
static char *list_initiator(xml_node_t *x);
static char *list_tpgt(xml_node_t *x);
static char *list_admin(xml_node_t *x);
static void target_info(char **msg, char *targ_name, xml_node_t *tnode);
static void target_stat(char **msg, char *iname, mgmt_type_t type);

/*ARGSUSED*/
void
list_func(xml_node_t *p, target_queue_t *reply, target_queue_t *mgmt)
{
	xml_node_t	*x;
	char		msgbuf[80],
			*reply_msg	= NULL;

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

static char *
list_targets(xml_node_t *x)
{
	char		*msg	= NULL,
			*prop	= NULL,
			*iname	= NULL;
	xml_node_t	*targ	= NULL;
	Boolean_t	luninfo	= False,
			dostat	= False;

	/*
	 * It's okay to not supply a "name" element. That just means the
	 * administrator wants a complete list of targets. However if a
	 * "name" is supplied then there must be a value for that element.
	 */
	if ((xml_find_value_str(x, XML_ELEMENT_NAME, &prop) == True) &&
	    (prop == NULL)) {
		xml_rtn_msg(&msg, ERR_SYNTAX_MISSING_NAME);
		return (msg);
	}

	/* ---- optional arguments ---- */
	(void) xml_find_value_boolean(x, XML_ELEMENT_LUNINFO, &luninfo);
	(void) xml_find_value_boolean(x, XML_ELEMENT_IOSTAT, &dostat);

	buf_add_tag_and_attr(&msg, XML_ELEMENT_RESULT, "version='1.0'");
	while ((targ = xml_node_next(targets_config, XML_ELEMENT_TARG,
	    targ)) != NULL) {
		if (targ->x_value == NULL) {
			xml_add_tag(&msg, XML_ELEMENT_TARG,
				    "bogus entry");
			continue;
		}
		if (xml_find_value_str(targ, XML_ELEMENT_INAME, &iname) ==
		    False) {
			xml_add_tag(&msg, XML_ELEMENT_TARG,
				    "missing iscsi-name");
			continue;
		}
		if (prop != NULL) {
			if (strcmp(prop, targ->x_value) == 0) {
				buf_add_tag(&msg, XML_ELEMENT_TARG, Tag_Start);
				buf_add_tag(&msg, targ->x_value, Tag_String);
				xml_add_tag(&msg, XML_ELEMENT_INAME, iname);
				if (luninfo == True)
					target_info(&msg, iname, targ);
				if (dostat == True)
					target_stat(&msg, iname,
					    mgmt_full_phase_statistics);
				buf_add_tag(&msg, XML_ELEMENT_TARG, Tag_End);
			}
		} else {
			buf_add_tag(&msg, XML_ELEMENT_TARG, Tag_Start);
			buf_add_tag(&msg, targ->x_value, Tag_String);
			xml_add_tag(&msg, XML_ELEMENT_INAME, iname);
			if (dostat == True)
				target_stat(&msg, iname,
				    mgmt_full_phase_statistics);
			if (luninfo == True)
				target_info(&msg, iname, targ);
			buf_add_tag(&msg, XML_ELEMENT_TARG, Tag_End);
		}
		free(iname);
	}
	buf_add_tag(&msg, XML_ELEMENT_RESULT, Tag_End);
	free(prop);

	return (msg);
}

static char *
list_initiator(xml_node_t *x)
{
	char		*msg	= NULL,
			*attr,
			*prop	= NULL;
	Boolean_t	verbose	= False;
	xml_node_t	*init	= NULL;

	/* ---- Optional arguments ---- */
	if ((xml_find_value_str(x, XML_ELEMENT_NAME, &prop) == True) &&
	    (prop == NULL)) {
		xml_rtn_msg(&msg, ERR_SYNTAX_MISSING_NAME);
		return (msg);
	}
	(void) xml_find_value_boolean(x, XML_ELEMENT_VERBOSE, &verbose);

	buf_add_tag_and_attr(&msg, XML_ELEMENT_RESULT, "version='1.0'");
	while ((init = xml_node_next(main_config, XML_ELEMENT_INIT, init)) !=
	    NULL) {
		if ((prop == NULL) ||
		    ((prop != NULL) && (strcmp(prop, init->x_value) == 0))) {

			buf_add_tag(&msg, XML_ELEMENT_INIT, Tag_Start);
			buf_add_tag(&msg, init->x_value, Tag_String);

			if (xml_find_value_str(init, XML_ELEMENT_INAME,
			    &attr) == True) {
				xml_add_tag(&msg, XML_ELEMENT_INAME, attr);
				free(attr);
			}

			if (xml_find_value_str(init, XML_ELEMENT_CHAPSECRET,
			    &attr) == True) {
				xml_add_tag(&msg, XML_ELEMENT_CHAPSECRET,
				    attr);
				free(attr);
			}

			if (xml_find_value_str(init, XML_ELEMENT_CHAPNAME,
			    &attr) == True) {
				xml_add_tag(&msg, XML_ELEMENT_CHAPNAME, attr);
				free(attr);
			}

			buf_add_tag(&msg, XML_ELEMENT_INIT, Tag_End);
		}
	}

	if (prop != NULL)
		free(prop);

	buf_add_tag(&msg, XML_ELEMENT_RESULT, Tag_End);

	return (msg);
}

static char *
list_tpgt(xml_node_t *x)
{
	char		*msg	= NULL,
			*prop	= NULL;
	Boolean_t	verbose	= False;
	xml_node_t	*tpgt	= NULL,
			*ip	= NULL;

	/* ---- Optional arguments ---- */
	if ((xml_find_value_str(x, XML_ELEMENT_NAME, &prop) == True) &&
	    (prop == NULL)) {
		xml_rtn_msg(&msg, ERR_SYNTAX_MISSING_NAME);
		return (msg);
	}
	(void) xml_find_value_boolean(x, XML_ELEMENT_VERBOSE, &verbose);

	buf_add_tag_and_attr(&msg, XML_ELEMENT_RESULT, "version='1.0'");
	while ((tpgt = xml_node_next(main_config, XML_ELEMENT_TPGT, tpgt)) !=
	    NULL) {
		if ((prop == NULL) ||
		    ((prop != NULL) && (strcmp(prop, tpgt->x_value) == 0))) {

			buf_add_tag(&msg, XML_ELEMENT_TPGT, Tag_Start);
			buf_add_tag(&msg, tpgt->x_value, Tag_String);

			while ((ip = xml_node_next(tpgt, XML_ELEMENT_IPADDR,
			    ip)) != NULL) {
				xml_add_tag(&msg, ip->x_name, ip->x_value);
			}

			buf_add_tag(&msg, XML_ELEMENT_TPGT, Tag_End);
		}
	}
	buf_add_tag(&msg, XML_ELEMENT_RESULT, Tag_End);

	if (prop != NULL)
		free(prop);
	return (msg);
}

/*ARGSUSED*/
static char *
list_admin(xml_node_t *x)
{
	char		*msg	= NULL;
	admin_table_t	*p;
	xml_node_t	*node	= NULL;

	buf_add_tag_and_attr(&msg, XML_ELEMENT_RESULT, "version='1.0'");
	buf_add_tag(&msg, XML_ELEMENT_ADMIN, Tag_Start);

	node = NULL;
	for (p = admin_prop_list; p->name != NULL; p++) {
		node = xml_node_next_child(main_config, p->name, NULL);
		if (node) {
			xml_add_tag(&msg, p->name, node->x_value);
		}
	}

	buf_add_tag(&msg, XML_ELEMENT_ADMIN, Tag_End);
	buf_add_tag(&msg, XML_ELEMENT_RESULT, Tag_End);

	return (msg);
}

static void
target_stat(char **msg, char *targ_name, mgmt_type_t type)
{
	iscsi_conn_t	*c;
	msg_t		*m;
	target_queue_t	*q = queue_alloc();
	mgmt_request_t	mgmt_rqst;
	int		msg_sent,
			i;
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
target_info(char **msg, char *targ_name, xml_node_t *tnode)
{
	char			path[MAXPATHLEN],
				lun_buf[16],
				*prop;
	xmlTextReaderPtr	r;
	xml_node_t		*lnode,	/* list node */
				*lnp, /* list node pointer */
				*lun,
				*params;
	int			xml_fd,
				lun_num;

	if ((lnode = xml_node_next(tnode, XML_ELEMENT_ACLLIST, NULL)) !=
	    NULL) {
		lnp = NULL;
		buf_add_tag(msg, XML_ELEMENT_ACLLIST, Tag_Start);
		while ((lnp = xml_node_next(lnode, XML_ELEMENT_INIT, lnp)) !=
		    NULL)
			xml_add_tag(msg, XML_ELEMENT_INIT, lnp->x_value);
		buf_add_tag(msg, XML_ELEMENT_ACLLIST, Tag_End);
	}

	if ((lnode = xml_node_next(tnode, XML_ELEMENT_TPGTLIST, NULL)) !=
	    NULL) {
		lnp = NULL;
		buf_add_tag(msg, XML_ELEMENT_TPGTLIST, Tag_Start);
		while ((lnp = xml_node_next(lnode, XML_ELEMENT_TPGT, lnp)) !=
		    NULL)
			xml_add_tag(msg, XML_ELEMENT_TPGT, lnp->x_value);
		buf_add_tag(msg, XML_ELEMENT_TPGTLIST, Tag_End);
	}

	if ((lnode = xml_node_next(tnode, XML_ELEMENT_ALIAS, NULL)) != NULL)
		xml_add_tag(msg, XML_ELEMENT_ALIAS, lnode->x_value);

	if ((lnode = xml_node_next(tnode, XML_ELEMENT_MAXRECV, NULL)) != NULL)
		xml_add_tag(msg, XML_ELEMENT_MAXRECV, lnode->x_value);

	if ((lnode = xml_node_next(tnode, XML_ELEMENT_LUNLIST, NULL)) == NULL)
		return;

	buf_add_tag(msg, XML_ELEMENT_LUNINFO, Tag_Start);
	lun = NULL;
	while ((lun = xml_node_next(lnode, XML_ELEMENT_LUN, lun)) != NULL) {
		if ((xml_find_value_int(lun, XML_ELEMENT_LUN, &lun_num)) ==
		    False)
			continue;
		(void) snprintf(path, sizeof (path), "%s/%s/%s%d",
		    target_basedir, targ_name, PARAMBASE, lun_num);
		if ((xml_fd = open(path, O_RDONLY)) < 0)
			continue;
		if ((r = (xmlTextReaderPtr)xmlReaderForFd(xml_fd,
		    NULL, NULL, 0)) == NULL)
			continue;

		params = NULL;
		while (xmlTextReaderRead(r) == 1) {
			if (xml_process_node(r, &params) == False)
				break;
		}
		(void) close(xml_fd);
		xmlTextReaderClose(r);
		xmlFreeTextReader(r);

		buf_add_tag(msg, XML_ELEMENT_LUN, Tag_Start);
		snprintf(lun_buf, sizeof (lun_buf), "%d", lun_num);
		buf_add_tag(msg, lun_buf, Tag_String);

		if (xml_find_value_str(params, XML_ELEMENT_GUID, &prop) ==
		    True) {
			xml_add_tag(msg, XML_ELEMENT_GUID, prop);
			free(prop);
		}
		if (xml_find_value_str(params, XML_ELEMENT_VID, &prop) ==
		    True) {
			xml_add_tag(msg, XML_ELEMENT_VID, prop);
			free(prop);
		}
		if (xml_find_value_str(params, XML_ELEMENT_PID, &prop) ==
		    True) {
			xml_add_tag(msg, XML_ELEMENT_PID, prop);
			free(prop);
		}
		if (xml_find_value_str(params, XML_ELEMENT_DTYPE, &prop) ==
		    True) {
			xml_add_tag(msg, XML_ELEMENT_DTYPE, prop);
			free(prop);
		}
		if (xml_find_value_str(params, XML_ELEMENT_SIZE, &prop) ==
		    True) {
			xml_add_tag(msg, XML_ELEMENT_SIZE, prop);
			free(prop);
		}
		if (xml_find_value_str(params, XML_ELEMENT_STATUS, &prop) ==
		    True) {
			xml_add_tag(msg, XML_ELEMENT_STATUS, prop);
			free(prop);
		}
		if (xml_find_value_str(params, XML_ELEMENT_BACK, &prop) ==
		    True) {
			xml_add_tag(msg, XML_ELEMENT_BACK, prop);
			free(prop);
		}
		buf_add_tag(msg, XML_ELEMENT_LUN, Tag_End);

		xml_tree_free(params);
	}
	buf_add_tag(msg, XML_ELEMENT_LUNINFO, Tag_End);
}
