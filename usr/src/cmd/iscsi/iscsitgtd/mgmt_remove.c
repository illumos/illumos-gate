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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

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

static char *remove_target(tgt_node_t *x, ucred_t *cred);
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

	x = p->x_child;

	/*
	 * remove_zfs() does not affect SMF data
	 * therefore it is not covered by auth check
	 */
	if (x == NULL) {
		xml_rtn_msg(&reply_msg, ERR_SYNTAX_MISSING_OBJECT);
	} else if (strcmp(x->x_name, XML_ELEMENT_ZFS) == 0) {
		reply_msg = remove_zfs(x, cred);
	} else if (check_auth_addremove(cred) != True) {
		xml_rtn_msg(&reply_msg, ERR_NO_PERMISSION);
	} else {
		if (x->x_name == NULL) {
			xml_rtn_msg(&reply_msg, ERR_SYNTAX_MISSING_OBJECT);
		} else if (strcmp(x->x_name, XML_ELEMENT_TARG) == 0) {
			reply_msg = remove_target(x, cred);
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

/*
 * remove_zfs -- remove a ZFS property, or the entire ZVOL
 */
static char *
remove_zfs(tgt_node_t *x, ucred_t *cred)
{
	char		*msg		= NULL;
	char		*dataset	= NULL;
	char		*prop		= NULL;
	tgt_node_t	*n		= NULL;
	tgt_node_t	*t		= NULL;
	tgt_node_t	*list		= NULL;
	tgt_node_t	*c;
	Boolean_t	change_made	= False;
	uint64_t	size;
	int		status;

	(void) pthread_rwlock_wrlock(&targ_config_mutex);
	if (tgt_find_value_str(x, XML_ELEMENT_NAME, &dataset) == False) {
		xml_rtn_msg(&msg, ERR_SYNTAX_MISSING_NAME);
		goto error;
	}

	/*
	 * Check for existance of ZFS shareiscsi properties
	 */
	status = get_zfs_shareiscsi(dataset, &n, &size, cred);

	if ((status != ERR_SUCCESS) && (status != ERR_ZFS_ISCSISHARE_OFF) &&
	    (status != ERR_NULL_XML_MESSAGE)) {
		xml_rtn_msg(&msg, ERR_TARG_NOT_FOUND);
		goto error;
	}

	while ((t = tgt_node_next_child(targets_config, XML_ELEMENT_TARG, t))
	    != NULL) {
		if (strcmp(t->x_value, dataset) == 0)
			break;
	}

	if (t == NULL) {
		if (status == ERR_ZFS_ISCSISHARE_OFF) {
			/*
			 * This is iscsishare=off  request from zfs on a target
			 * which is already unshared. In that case, zfs expects
			 * "success" result.
			 */
			xml_rtn_msg(&msg, ERR_SUCCESS);
		} else {
			xml_rtn_msg(&msg, ERR_TARG_NOT_FOUND);
		}
		goto error;
	}

	if (tgt_find_value_str(x, XML_ELEMENT_TPGT, &prop) == True) {
		if (prop == NULL) {
			xml_rtn_msg(&msg, ERR_SYNTAX_EMPTY_TPGT);
			goto error;
		}
		if (status == ERR_ZFS_ISCSISHARE_OFF) {
			xml_rtn_msg(&msg, status);
			goto error;
		}

		/*
		 * Due to the fact that the targets_config differs from the
		 * ZVOL properties stored in zfs_shareiscsi, two lists need to
		 * be updated
		 */
		c = tgt_node_alloc(XML_ELEMENT_TPGT, String, prop);
		if ((list = tgt_node_next(t, XML_ELEMENT_TPGTLIST, NULL)) !=
		    NULL) {
			(void) tgt_node_remove(list, c, MatchBoth);
			if (list->x_child == NULL)
				(void) tgt_node_remove(t, list, MatchName);
		}
		if ((list = tgt_node_next(n, XML_ELEMENT_TPGTLIST, NULL)) !=
		    NULL) {
			(void) tgt_node_remove(list, c, MatchBoth);
			if (list->x_child == NULL)
				(void) tgt_node_remove(n, list, MatchName);
		}
		tgt_node_free(c);

		/* update isns */
		if (isns_enabled()) {
			if (isns_dev_update(t->x_value, ISNS_MOD_TPGT) != 0)
				syslog(LOG_ALERT, "ISNS register failed\n");
		}
		free(prop);
		prop = NULL;
		change_made = True;
	}

	if (tgt_find_value_str(x, XML_ELEMENT_ACL, &prop) == True) {
		if (prop == NULL) {
			xml_rtn_msg(&msg, ERR_SYNTAX_EMPTY_ACL);
			goto error;
		}
		if (status == ERR_ZFS_ISCSISHARE_OFF) {
			xml_rtn_msg(&msg, status);
			goto error;
		}
		/*
		 * Due to the fact that the targets_config differs from the
		 * ZVOL properties stored in zfs_shareiscsi, two lists need to
		 * be updated
		 */
		c = tgt_node_alloc(XML_ELEMENT_INIT, String, prop);
		if ((list = tgt_node_next(t, XML_ELEMENT_ACLLIST, NULL)) !=
		    NULL) {
			(void) tgt_node_remove(list, c, MatchBoth);
			if (list->x_child == NULL)
				(void) tgt_node_remove(t, list, MatchName);
		}
		if ((list = tgt_node_next(n, XML_ELEMENT_ACLLIST, NULL)) !=
		    NULL) {
			(void) tgt_node_remove(list, c, MatchBoth);
			if (list->x_child == NULL)
				(void) tgt_node_remove(n, list, MatchName);
		}
		tgt_node_free(c);
		free(prop);
		prop = NULL;
		change_made = True;
	}

	if (change_made == False) {
		if (tgt_find_value_str(t, XML_ELEMENT_INAME, &prop) == False) {
			xml_rtn_msg(&msg, ERR_TARGCFG_MISSING_INAME);
			goto error;
		}

		/* deregister zovl target from iSNS server. */
		if (isns_enabled() == True) {
			if (isns_dereg(prop) != 0)
				syslog(LOG_INFO, "ISNS dereg failed\n");
		}

		(void) tgt_node_remove(targets_config, t, MatchBoth);

		/*
		 * Wait until here to issue a logout to any initiators that
		 * might be logged into the target. Certain initiators are
		 * sneaky in that if asked to logout they will, but turn right
		 * around and log back into the target. By waiting here to issue
		 * the logout we'll have removed reference to the target such
		 * that this can't happen.
		 */
		logout_targ(prop);
		thick_provo_stop(prop, 0);

		xml_rtn_msg(&msg, ERR_SUCCESS);
	} else {
		status = put_zfs_shareiscsi(dataset, n);
		if (status != ERR_SUCCESS) {
			xml_rtn_msg(&msg, status);
			goto error;
		} else {
			xml_rtn_msg(&msg, ERR_SUCCESS);
		}
	}

error:
	if (prop)
		free(prop);
	if (n)
		tgt_node_free(n);
	if (dataset)
		free(dataset);
	(void) pthread_rwlock_unlock(&targ_config_mutex);
	return (msg);
}

static char *
remove_target(tgt_node_t *x, ucred_t *cred)
{
	char		*msg			= NULL;
	char		*prop			= NULL;
	tgt_node_t	*targ			= NULL;
	tgt_node_t	*list;
	tgt_node_t	*c			= NULL;
	Boolean_t	change_made		= False;
	int		lun_num;

	(void) pthread_rwlock_wrlock(&targ_config_mutex);
	if (tgt_find_value_str(x, XML_ELEMENT_NAME, &prop) == False) {
		xml_rtn_msg(&msg, ERR_SYNTAX_MISSING_NAME);
		goto error;
	}

	while ((targ = tgt_node_next_child(targets_config, XML_ELEMENT_TARG,
	    targ)) != NULL) {
		if (strcmp(targ->x_value, prop) == 0)
			break;
	}
	free(prop);
	prop = NULL;
	if (targ == NULL) {
		xml_rtn_msg(&msg, ERR_TARG_NOT_FOUND);
		goto error;
	}

	if (tgt_find_attr_str(targ, XML_ELEMENT_INCORE, &prop) == True) {
		if (strcmp(prop, "true") == 0) {
			free(prop);
			(void) pthread_rwlock_unlock(&targ_config_mutex);
			return (remove_zfs(x, cred));
		}
		free(prop);
	}

	if (tgt_find_value_str(x, XML_ELEMENT_ACL, &prop) == True) {
		if (prop == NULL) {
			xml_rtn_msg(&msg, ERR_SYNTAX_EMPTY_ACL);
			goto error;
		}
		if ((list = tgt_node_next(targ, XML_ELEMENT_ACLLIST, NULL)) ==
		    NULL) {
			xml_rtn_msg(&msg, ERR_ACL_NOT_FOUND);
			goto error;
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
			goto error;
		}
		if ((list = tgt_node_next(targ, XML_ELEMENT_TPGTLIST, NULL)) ==
		    NULL) {
			xml_rtn_msg(&msg, ERR_TPGT_NOT_FOUND);
			goto error;
		}
		c = tgt_node_alloc(XML_ELEMENT_TPGT, String, prop);
		if (tgt_node_remove(list, c, MatchBoth) == False) {
			xml_rtn_msg(&msg, ERR_TPGT_NOT_FOUND);
			goto error;
		}
		tgt_node_free(c);
		if (list->x_child == NULL)
			(void) tgt_node_remove(targ, list, MatchName);

		/* update isns */
		if (isns_enabled()) {
			if (isns_dev_update(targ->x_value, ISNS_MOD_TPGT) != 0)
				syslog(LOG_ALERT, "ISNS register failed\n");
		}

		free(prop);
		prop = NULL;
		change_made = True;
	}
	if (tgt_find_value_int(x, XML_ELEMENT_LUN, &lun_num) == True) {

		if (tgt_find_value_intchk(x, XML_ELEMENT_LUN, &lun_num) ==
		    False) {
			xml_rtn_msg(&msg, ERR_LUN_INVALID_RANGE);
			goto error;
		}

		/*
		 * Save the iscsi-name which we'll need to remove LUNs.
		 */
		if (tgt_find_value_str(targ, XML_ELEMENT_INAME, &prop) ==
		    False) {
			xml_rtn_msg(&msg, ERR_TARGCFG_MISSING_INAME);
			goto error;
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
		if (mgmt_config_save2scf() == True) {
			xml_rtn_msg(&msg, ERR_SUCCESS);
		} else {
			xml_rtn_msg(&msg, ERR_INTERNAL_ERROR);
		}
	} else {
		xml_rtn_msg(&msg, ERR_SYNTAX_MISSING_OPERAND);
	}

	(void) pthread_rwlock_unlock(&targ_config_mutex);
	return (msg);

error:
	if (c != NULL)
		tgt_node_free(c);
	if (prop != NULL)
		free(prop);
	(void) pthread_rwlock_unlock(&targ_config_mutex);
	return (msg);
}

static char *
remove_initiator(tgt_node_t *x)
{
	char		*msg	= NULL;
	char		*name;
	tgt_node_t	*node	= NULL;

	(void) pthread_rwlock_wrlock(&targ_config_mutex);
	if (tgt_find_value_str(x, XML_ELEMENT_NAME, &name) == False) {
		xml_rtn_msg(&msg, ERR_SYNTAX_MISSING_NAME);
		(void) pthread_rwlock_unlock(&targ_config_mutex);
		return (msg);
	}
	while ((node = tgt_node_next_child(main_config, XML_ELEMENT_INIT, node))
	    != NULL) {
		if (strcmp(node->x_value, name) == 0)
			break;
	}
	free(name);
	if (node == NULL) {
		xml_rtn_msg(&msg, ERR_INIT_NOT_FOUND);
		(void) pthread_rwlock_unlock(&targ_config_mutex);
		return (msg);
	}
	if (tgt_find_value_str(x, XML_ELEMENT_ALL, &name) == False) {
		xml_rtn_msg(&msg, ERR_SYNTAX_MISSING_ALL);
		(void) pthread_rwlock_unlock(&targ_config_mutex);
		return (msg);
	}
	(void) tgt_node_remove(main_config, node, MatchBoth);

	if (mgmt_config_save2scf() == True) {
		xml_rtn_msg(&msg, ERR_SUCCESS);
	} else {
		xml_rtn_msg(&msg, ERR_INTERNAL_ERROR);
	}

	free(name);
	(void) pthread_rwlock_unlock(&targ_config_mutex);
	return (msg);
}

static char *
remove_tpgt(tgt_node_t *x)
{
	char		*msg		= NULL;
	char		*prop		= NULL;
	tgt_node_t	*targ		= NULL;
	tgt_node_t	*lnode		= NULL;
	tgt_node_t	*lnp		= NULL;
	tgt_node_t	*node		= NULL;
	tgt_node_t	*c		= NULL;
	tgt_node_t	*list		= NULL;
	Boolean_t	change_made	= False;

	(void) pthread_rwlock_wrlock(&targ_config_mutex);
	if (tgt_find_value_str(x, XML_ELEMENT_NAME, &prop) == False) {
		xml_rtn_msg(&msg, ERR_SYNTAX_MISSING_NAME);
		(void) pthread_rwlock_unlock(&targ_config_mutex);
		return (msg);
	}
	while ((node = tgt_node_next_child(main_config, XML_ELEMENT_TPGT, node))
	    != NULL) {
		if (strcmp(node->x_value, prop) == 0)
			break;
	}
	if (node == NULL) {
		xml_rtn_msg(&msg, ERR_TPGT_NOT_FOUND);
		free(prop);
		(void) pthread_rwlock_unlock(&targ_config_mutex);
		return (msg);
	}
	while ((targ = tgt_node_next_child(targets_config, XML_ELEMENT_TARG,
	    targ)) != NULL) {
		if ((lnode = tgt_node_next(targ, XML_ELEMENT_TPGTLIST,
		    NULL)) != NULL) {
		lnp = NULL;
		while ((lnp = tgt_node_next_child(lnode, XML_ELEMENT_TPGT,
		    lnp)) != NULL)
			if (strcmp(lnp->x_value, prop) == 0) {
				xml_rtn_msg(&msg, ERR_TPGT_IN_USE);
				free(prop);
				(void) pthread_rwlock_unlock(
				    &targ_config_mutex);
				return (msg);
			}
		}
	}
	free(prop);
	if (tgt_find_value_str(x, XML_ELEMENT_IPADDR, &prop) == True) {
		if (prop == NULL) {
			xml_rtn_msg(&msg, ERR_SYNTAX_EMPTY_IPADDR);
			(void) pthread_rwlock_unlock(&targ_config_mutex);
			return (msg);
		}
		if ((list = tgt_node_next(node, XML_ELEMENT_IPADDRLIST, NULL))
		    == NULL) {
			xml_rtn_msg(&msg, ERR_TPGT_NO_IPADDR);
			goto error;
		}
		c = tgt_node_alloc(XML_ELEMENT_IPADDR, String, prop);
		if (tgt_node_remove(list, c, MatchBoth) == False) {
			xml_rtn_msg(&msg, ERR_INVALID_IP);
			goto error;
		}
		tgt_node_free(c);
		free(prop);
		if (list->x_child == NULL)
			(void) tgt_node_remove(node, list, MatchName);
		change_made = True;
	}
	if ((change_made != True) &&
	    (tgt_find_value_str(x, XML_ELEMENT_ALL, &prop) == True)) {
		(void) tgt_node_remove(main_config, node, MatchBoth);
		change_made = True;
		free(prop);
	}

	if (change_made == True) {
		/* Isns re-register all target */
		if (isns_enabled() == True)
			(void) isns_reg_all();
		if (mgmt_config_save2scf() == True) {
			xml_rtn_msg(&msg, ERR_SUCCESS);
		} else {
			xml_rtn_msg(&msg, ERR_INTERNAL_ERROR);
		}
	} else {
		xml_rtn_msg(&msg, ERR_SYNTAX_MISSING_OPERAND);
	}

	(void) pthread_rwlock_unlock(&targ_config_mutex);
	return (msg);

error:
	if (c != NULL)
		tgt_node_free(c);
	if (prop != NULL)
		free(prop);
	(void) pthread_rwlock_unlock(&targ_config_mutex);
	return (msg);
}
