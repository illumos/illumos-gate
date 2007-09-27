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
 * This file deals with XML data for removing various configuration data.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <errno.h>
#include <strings.h>
#include <unistd.h>
#include <priv.h>
#include <syslog.h>
#include <libzfs.h>

#include <iscsitgt_impl.h>
#include "utility.h"
#include "queue.h"
#include "target.h"
#include "iscsi_cmd.h"
#include "errcode.h"
#include "isns_client.h"
#include "mgmt_scf.h"

static char *remove_target(tgt_node_t *x);
static char *remove_initiator(tgt_node_t *x);
static char *remove_tpgt(tgt_node_t *x);
static char *remove_zfs(tgt_node_t *x, ucred_t *cred);


/*ARGSUSED*/
void
remove_func(tgt_node_t *p, target_queue_t *reply, target_queue_t *mgmt,
    ucred_t *cred)
{
	tgt_node_t	*x;
	char		msgbuf[80];
	char		*reply_msg	= NULL;

	if (check_auth_addremove(cred) != True) {
		xml_rtn_msg(&reply_msg, ERR_NO_PERMISSION);
	} else if (p->x_child == NULL) {
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
		} else if (strcmp(x->x_name, XML_ELEMENT_ZFS) == 0) {
			reply_msg = remove_zfs(x, cred);
		} else {
			(void) snprintf(msgbuf, sizeof (msgbuf),
			    "Unknown object '%s' for delete element",
			    x->x_name);
			xml_rtn_msg(&reply_msg, ERR_INVALID_OBJECT);
		}
	}
	queue_message_set(reply, 0, msg_mgmt_rply, reply_msg);
}

/*
 * remove_zfs -- unshare a ZVOL from the target
 */
static char *
remove_zfs(tgt_node_t *x, ucred_t *cred)
{
	char		*prop;
	char		*msg		= NULL;
	tgt_node_t		*targ = NULL;
	libzfs_handle_t		*zh = NULL;
	const priv_set_t	*eset;

	if (tgt_find_value_str(x, XML_ELEMENT_NAME, &prop) == False) {
		xml_rtn_msg(&msg, ERR_SYNTAX_MISSING_NAME);
		return (msg);
	}

	if ((zh = libzfs_init()) == NULL) {
		xml_rtn_msg(&msg, ERR_INTERNAL_ERROR);
		free(prop);
		return (msg);
	}

	eset = ucred_getprivset(cred, PRIV_EFFECTIVE);
	if (eset != NULL ? !priv_ismember(eset, PRIV_SYS_CONFIG) :
	    ucred_geteuid(cred) != 0) {
		/*
		 * See if user has ZFS dataset permissions to do operation
		 */
		if (zfs_iscsi_perm_check(zh, prop, cred) != 0) {
			xml_rtn_msg(&msg, ERR_NO_PERMISSION);
			free(prop);
			libzfs_fini(zh);
			return (msg);
		}
	}

	libzfs_fini(zh);

	while ((targ = tgt_node_next(targets_config, XML_ELEMENT_TARG, targ))
	    != NULL) {
		if (strcmp(targ->x_value, prop) == 0)
			break;
	}
	free(prop);
	if (targ == NULL) {
		/*
		 * We're unsharing a target. If we don't have a reference
		 * then there's no problem.
		 */
		xml_rtn_msg(&msg, ERR_SUCCESS);
		return (msg);
	}
	if (tgt_find_value_str(targ, XML_ELEMENT_INAME, &prop) ==
	    False) {
		xml_rtn_msg(&msg, ERR_TARGCFG_MISSING_INAME);
		return (msg);
	}

	tgt_node_remove(targets_config, targ, MatchBoth);

	/*
	 * Wait until here to issue a logout to any initiators that
	 * might be logged into the target. Certain initiators are
	 * sneaky in that if asked to logout they will, but turn right
	 * around and log back into the target. By waiting until here
	 * to issue the logout we'll have removed reference to the target
	 * such that this can't happen.
	 */
	if (isns_enabled() == True) {
		if (isns_dereg(prop) != 0)
			syslog(LOG_INFO, "ISNS dereg failed\n");
	}
	logout_targ(prop);
	free(prop);

	xml_rtn_msg(&msg, ERR_SUCCESS);
	return (msg);
}

static char *
remove_target(tgt_node_t *x)
{
	char		*msg			= NULL;
	char		*prop			= NULL;
	tgt_node_t	*targ			= NULL;
	tgt_node_t	*list;
	tgt_node_t	*c			= NULL;
	Boolean_t	change_made		= False;
	int		lun_num;

	if (tgt_find_value_str(x, XML_ELEMENT_NAME, &prop) == False) {
		xml_rtn_msg(&msg, ERR_SYNTAX_MISSING_NAME);
		return (msg);
	}

	while ((targ = tgt_node_next(targets_config, XML_ELEMENT_TARG, targ)) !=
	    NULL) {
		if (strcmp(targ->x_value, prop) == 0)
			break;
	}
	free(prop);
	if (targ == NULL) {
		xml_rtn_msg(&msg, ERR_TARG_NOT_FOUND);
		return (msg);
	}
	if (tgt_find_value_str(x, XML_ELEMENT_ACL, &prop) == True) {
		if (prop == NULL) {
			xml_rtn_msg(&msg, ERR_SYNTAX_EMPTY_ACL);
			return (msg);
		}
		if ((list = tgt_node_next(targ, XML_ELEMENT_ACLLIST, NULL)) ==
		    NULL) {
			free(prop);
			xml_rtn_msg(&msg, ERR_ACL_NOT_FOUND);
			return (msg);
		}
		c = tgt_node_alloc(XML_ELEMENT_INIT, String, prop);
		if (tgt_node_remove(list, c, MatchBoth) == False) {
			xml_rtn_msg(&msg, ERR_INIT_NOT_FOUND);
			goto error;
		}
		tgt_node_free(c);
		if (list->x_child == NULL)
			(void) tgt_node_remove(targ, list, MatchName);
		free(prop);
		change_made = True;
	}
	if (tgt_find_value_str(x, XML_ELEMENT_TPGT, &prop) == True) {
		if (prop == NULL) {
			xml_rtn_msg(&msg, ERR_SYNTAX_EMPTY_TPGT);
			return (msg);
		}
		if ((list = tgt_node_next(targ, XML_ELEMENT_TPGTLIST, NULL)) ==
		    NULL) {
			free(prop);
			xml_rtn_msg(&msg, ERR_ACL_NOT_FOUND);
			return (msg);
		}
		c = tgt_node_alloc(XML_ELEMENT_TPGT, String, prop);
		if (tgt_node_remove(list, c, MatchBoth) == False) {
			xml_rtn_msg(&msg, ERR_TPGT_NOT_FOUND);
			goto error;
		}
		tgt_node_free(c);
		if (list->x_child == NULL)
			(void) tgt_node_remove(targ, list, MatchName);
		free(prop);

		/* update isns */
		if (isns_enabled()) {
			if (isns_dev_update(targ->x_value, ISNS_MOD_TPGT) != 0)
				syslog(LOG_ALERT, "ISNS register failed\n");
		}

		change_made = True;
	}
	if (tgt_find_value_int(x, XML_ELEMENT_LUN, &lun_num) == True) {

		if (tgt_find_value_intchk(x, XML_ELEMENT_LUN, &lun_num) ==
		    False) {
			xml_rtn_msg(&msg, ERR_LUN_INVALID_RANGE);
			return (msg);
		}

		/*
		 * Save the iscsi-name which we'll need to remove LUNs.
		 */
		if (tgt_find_value_str(targ, XML_ELEMENT_INAME, &prop) ==
		    False) {
			xml_rtn_msg(&msg, ERR_TARGCFG_MISSING_INAME);
			return (msg);
		}

		logout_targ(prop);
		thick_provo_stop(prop, lun_num);

		remove_target_common(targ->x_value, lun_num, &msg);
		if (msg != NULL)
			goto error;

		/* ISNS de-register target if it's the last lun */
		if (lun_num == 0 && isns_enabled() == True) {
			if (isns_dereg(prop) != 0)
				syslog(LOG_INFO, "ISNS dereg failed\n");
		}

		iscsi_inventory_change(prop);
		free(prop);
		change_made = True;
	}

	if (change_made == True) {
		if (mgmt_config_save2scf() == True)
			xml_rtn_msg(&msg, ERR_SUCCESS);
	} else {
		xml_rtn_msg(&msg, ERR_SYNTAX_MISSING_OPERAND);
	}

	return (msg);

error:
	if (c != NULL)
		tgt_node_free(c);
	if (prop != NULL)
		free(prop);
	return (msg);
}

static char *
remove_initiator(tgt_node_t *x)
{
	char		*msg	= NULL;
	char		*name;
	tgt_node_t	*node	= NULL;

	if (tgt_find_value_str(x, XML_ELEMENT_NAME, &name) == False) {
		xml_rtn_msg(&msg, ERR_SYNTAX_MISSING_NAME);
		return (msg);
	}
	while ((node = tgt_node_next(main_config, XML_ELEMENT_INIT, node)) !=
	    NULL) {
		if (strcmp(node->x_value, name) == 0)
			break;
	}
	free(name);
	if (node == NULL) {
		xml_rtn_msg(&msg, ERR_INIT_NOT_FOUND);
		return (msg);
	}
	if (tgt_find_value_str(x, XML_ELEMENT_ALL, &name) == False) {
		xml_rtn_msg(&msg, ERR_SYNTAX_MISSING_ALL);
		return (msg);
	}
	(void) tgt_node_remove(main_config, node, MatchBoth);

	if (mgmt_config_save2scf() == True)
		xml_rtn_msg(&msg, ERR_SUCCESS);

	return (msg);
}

static char *
remove_tpgt(tgt_node_t *x)
{
	char		*msg		= NULL;
	char		*prop		= NULL;
	tgt_node_t	*node		= NULL;
	tgt_node_t	*c		= NULL;
	Boolean_t	change_made	= False;

	if (tgt_find_value_str(x, XML_ELEMENT_NAME, &prop) == False) {
		xml_rtn_msg(&msg, ERR_SYNTAX_MISSING_NAME);
		return (msg);
	}
	while ((node = tgt_node_next(main_config, XML_ELEMENT_TPGT, node)) !=
	    NULL) {
		if (strcmp(node->x_value, prop) == 0)
			break;
	}
	free(prop);
	if (node == NULL) {
		xml_rtn_msg(&msg, ERR_TPGT_NOT_FOUND);
		return (msg);
	}
	if (tgt_find_value_str(x, XML_ELEMENT_IPADDR, &prop) == True) {
		if (prop == NULL) {
			xml_rtn_msg(&msg, ERR_SYNTAX_EMPTY_IPADDR);
			return (msg);
		}
		c = tgt_node_alloc(XML_ELEMENT_IPADDR, String, prop);
		if (tgt_node_remove(node, c, MatchBoth) == False) {
			xml_rtn_msg(&msg, ERR_INVALID_IP);
			goto error;
		}
		tgt_node_free(c);
		free(prop);
		change_made = True;
	}
	if ((change_made != True) &&
	    (tgt_find_value_str(x, XML_ELEMENT_ALL, &prop) == True)) {
		tgt_node_remove(main_config, node, MatchBoth);
		change_made = True;
	}

	if (change_made == True) {
		/* Isns re-register all target */
		if (isns_enabled() == True)
			isns_reg_all();
		if (mgmt_config_save2scf() == True)
			xml_rtn_msg(&msg, ERR_SUCCESS);
	} else {
		xml_rtn_msg(&msg, ERR_SYNTAX_MISSING_OPERAND);
	}

	return (msg);

error:
	if (c != NULL)
		tgt_node_free(c);
	if (prop != NULL)
		free(prop);
	return (msg);
}
