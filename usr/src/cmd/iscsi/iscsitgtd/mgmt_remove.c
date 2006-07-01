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

/*
 * This file deals with XML data for removing various configuration data.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <errno.h>
#include <strings.h>
#include <unistd.h>

#include "utility.h"
#include "xml.h"
#include "queue.h"
#include "target.h"
#include "iscsi_cmd.h"
#include "errcode.h"

static char *remove_target(xml_node_t *x);
static char *remove_initiator(xml_node_t *x);
static char *remove_tpgt(xml_node_t *x);

/*ARGSUSED*/
void
remove_func(xml_node_t *p, target_queue_t *reply, target_queue_t *mgmt)
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
			reply_msg = remove_target(x);
		} else if (strcmp(x->x_name, XML_ELEMENT_INIT) == 0) {
			reply_msg = remove_initiator(x);
		} else if (strcmp(x->x_name, XML_ELEMENT_TPGT) == 0) {
			reply_msg = remove_tpgt(x);
		} else {
			(void) snprintf(msgbuf, sizeof (msgbuf),
			    "Unknown object '%s' for delete element",
			    x->x_name);
			xml_rtn_msg(&reply_msg, ERR_INVALID_OBJECT);
		}
	}
	queue_message_set(reply, 0, msg_mgmt_rply, reply_msg);
}

static char *
remove_target(xml_node_t *x)
{
	char		*msg			= NULL,
			*prop			= NULL;
	xml_node_t	*targ			= NULL,
			*list,
			*c			= NULL;
	Boolean_t	change_made		= False;
	int		lun_num;

	if (xml_find_value_str(x, XML_ELEMENT_NAME, &prop) == False) {
		xml_rtn_msg(&msg, ERR_SYNTAX_MISSING_NAME);
		return (msg);
	}

	while ((targ = xml_node_next(targets_config, XML_ELEMENT_TARG, targ)) !=
	    NULL) {
		if (strcmp(targ->x_value, prop) == 0)
			break;
	}
	free(prop);
	if (targ == NULL) {
		xml_rtn_msg(&msg, ERR_TARG_NOT_FOUND);
		return (msg);
	}
	if (xml_find_value_str(x, XML_ELEMENT_ACL, &prop) == True) {
		if (prop == NULL) {
			xml_rtn_msg(&msg, ERR_SYNTAX_EMPTY_ACL);
			return (msg);
		}
		if ((list = xml_node_next(targ, XML_ELEMENT_ACLLIST, NULL)) ==
		    NULL) {
			free(prop);
			xml_rtn_msg(&msg, ERR_ACL_NOT_FOUND);
			return (msg);
		}
		c = xml_alloc_node(XML_ELEMENT_INIT, String, prop);
		if (xml_remove_child(list, c, MatchBoth) == False) {
			xml_rtn_msg(&msg, ERR_INIT_NOT_FOUND);
			goto error;
		}
		xml_free_node(c);
		if (list->x_child == NULL)
			(void) xml_remove_child(targ, list, MatchName);
		free(prop);
		change_made = True;
	}
	if (xml_find_value_str(x, XML_ELEMENT_TPGT, &prop) == True) {
		if (prop == NULL) {
			xml_rtn_msg(&msg, ERR_SYNTAX_EMPTY_TPGT);
			return (msg);
		}
		if ((list = xml_node_next(targ, XML_ELEMENT_TPGTLIST, NULL)) ==
		    NULL) {
			free(prop);
			xml_rtn_msg(&msg, ERR_ACL_NOT_FOUND);
			return (msg);
		}
		c = xml_alloc_node(XML_ELEMENT_TPGT, String, prop);
		if (xml_remove_child(list, c, MatchBoth) == False) {
			xml_rtn_msg(&msg, ERR_TPGT_NOT_FOUND);
			goto error;
		}
		xml_free_node(c);
		if (list->x_child == NULL)
			(void) xml_remove_child(targ, list, MatchName);
		free(prop);
		change_made = True;
	}
	if (xml_find_value_int(x, XML_ELEMENT_LUN, &lun_num) == True) {

		if (xml_find_value_intchk(x, XML_ELEMENT_LUN, &lun_num) ==
		    False) {
			xml_rtn_msg(&msg, ERR_LUN_INVALID_RANGE);
			return (msg);
		}

		/*
		 * Save the iscsi-name which we'll need to remove LUNs.
		 */
		if (xml_find_value_str(targ, XML_ELEMENT_INAME, &prop) ==
		    False) {
			xml_rtn_msg(&msg, ERR_TARGCFG_MISSING_INAME);
			return (msg);
		}

		logout_targ(prop);
		thick_provo_stop(prop, lun_num);

		remove_target_common(targ->x_value, lun_num, &msg);
		if (msg != NULL)
			goto error;

		iscsi_inventory_change(prop);
		free(prop);
		change_made = True;
	}

	if (change_made == True) {
		if (update_config_targets(&msg) == True)
			xml_rtn_msg(&msg, ERR_SUCCESS);
	} else {
		xml_rtn_msg(&msg, ERR_SYNTAX_MISSING_OPERAND);
	}

	return (msg);

error:
	if (c != NULL)
		xml_free_node(c);
	if (prop != NULL)
		free(prop);
	return (msg);
}

static char *
remove_initiator(xml_node_t *x)
{
	char		*msg	= NULL,
			*name;
	xml_node_t	*node	= NULL;

	if (xml_find_value_str(x, XML_ELEMENT_NAME, &name) == False) {
		xml_rtn_msg(&msg, ERR_SYNTAX_MISSING_NAME);
		return (msg);
	}
	while ((node = xml_node_next(main_config, XML_ELEMENT_INIT, node)) !=
	    NULL) {
		if (strcmp(node->x_value, name) == 0)
			break;
	}
	free(name);
	if (node == NULL) {
		xml_rtn_msg(&msg, ERR_INIT_NOT_FOUND);
		return (msg);
	}
	if (xml_find_value_str(x, XML_ELEMENT_ALL, &name) == False) {
		xml_rtn_msg(&msg, ERR_SYNTAX_MISSING_ALL);
		return (msg);
	}
	(void) xml_remove_child(main_config, node, MatchBoth);

	if (update_config_main(&msg) == True)
		xml_rtn_msg(&msg, ERR_SUCCESS);

	return (msg);
}

static char *
remove_tpgt(xml_node_t *x)
{
	char		*msg		= NULL,
			*prop		= NULL;
	xml_node_t	*node		= NULL,
			*c		= NULL;
	Boolean_t	change_made	= False;

	if (xml_find_value_str(x, XML_ELEMENT_NAME, &prop) == False) {
		xml_rtn_msg(&msg, ERR_SYNTAX_MISSING_NAME);
		return (msg);
	}
	while ((node = xml_node_next(main_config, XML_ELEMENT_TPGT, node)) !=
	    NULL) {
		if (strcmp(node->x_value, prop) == 0)
			break;
	}
	free(prop);
	if (node == NULL) {
		xml_rtn_msg(&msg, ERR_TPGT_NOT_FOUND);
		return (msg);
	}
	if (xml_find_value_str(x, XML_ELEMENT_IPADDR, &prop) == True) {
		if (prop == NULL) {
			xml_rtn_msg(&msg, ERR_SYNTAX_EMPTY_IPADDR);
			return (msg);
		}
		c = xml_alloc_node(XML_ELEMENT_IPADDR, String, prop);
		if (xml_remove_child(node, c, MatchBoth) == False) {
			xml_rtn_msg(&msg, ERR_INVALID_IP);
			goto error;
		}
		xml_free_node(c);
		free(prop);
		change_made = True;
	}
	if ((change_made != True) &&
	    (xml_find_value_str(x, XML_ELEMENT_ALL, &prop) == True)) {
		xml_remove_child(main_config, node, MatchBoth);
		change_made = True;
	}

	if (change_made == True) {
		if (update_config_main(&msg) == True)
			xml_rtn_msg(&msg, ERR_SUCCESS);
	} else {
		xml_rtn_msg(&msg, ERR_SYNTAX_MISSING_OPERAND);
	}

	return (msg);

error:
	if (c != NULL)
		xml_free_node(c);
	if (prop != NULL)
		free(prop);
	return (msg);
}
