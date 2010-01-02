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

#include <sys/types.h>
#include <time.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <sys/param.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <strings.h>
#include <assert.h>
#include <sys/socket.h>
#include <netdb.h>
#include <libgen.h>
#include <libzfs.h>
#include <syslog.h>

#include <iscsitgt_impl.h>
#include "queue.h"
#include "utility.h"
#include "iscsi_cmd.h"
#include "target.h"
#include "errcode.h"
#include "isns_client.h"
#include "mgmt_scf.h"

static char *modify_target(tgt_node_t *x, ucred_t *cred);
static char *modify_initiator(tgt_node_t *x);
static char *modify_admin(tgt_node_t *x);
static char *modify_tpgt(tgt_node_t *x);
static char *modify_zfs(tgt_node_t *x, ucred_t *cred);
static char *validate_zfs_iscsitgt(tgt_node_t *x);
static Boolean_t modify_element(char *, char *, tgt_node_t *, match_type_t);
static Boolean_t delete_element(char *,  tgt_node_t *, match_type_t);

/*
 * []----
 * | modify_func -- dispatch routine for objects
 * []----
 */
/*ARGSUSED*/
void
modify_func(tgt_node_t *p, target_queue_t *reply, target_queue_t *mgmt,
    ucred_t *cred)
{
	tgt_node_t	*x;
	char		*reply_msg	= NULL;

	x = p->x_child;

	if (p->x_child == NULL) {
		xml_rtn_msg(&reply_msg, ERR_SYNTAX_MISSING_OBJECT);
	} else if (strcmp(x->x_name, XML_ELEMENT_ZFS) == 0) {
		reply_msg = modify_zfs(x, cred);
	} else if (check_auth_modify(cred) != True) {
		xml_rtn_msg(&reply_msg, ERR_NO_PERMISSION);
	} else {
		if (x->x_name == NULL) {
			xml_rtn_msg(&reply_msg, ERR_SYNTAX_MISSING_OBJECT);
		} else if (strcmp(x->x_name, XML_ELEMENT_TARG) == 0) {
			reply_msg = modify_target(x, cred);
		} else if (strcmp(x->x_name, XML_ELEMENT_INIT) == 0) {
			reply_msg = modify_initiator(x);
		} else if (strcmp(x->x_name, XML_ELEMENT_ADMIN) == 0) {
			reply_msg = modify_admin(x);
		} else if (strcmp(x->x_name, XML_ELEMENT_TPGT) == 0) {
			reply_msg = modify_tpgt(x);
		} else {
			xml_rtn_msg(&reply_msg, ERR_INVALID_OBJECT);
		}
	}
	queue_message_set(reply, 0, msg_mgmt_rply, reply_msg);
}

/*
 * []----
 * | modify_target -- updates one or more properties for a target
 * []----
 */
static char *
modify_target(tgt_node_t *x, ucred_t *cred)
{
	char		*msg		= NULL;
	char		*name		= NULL;
	char		iscsi_path[MAXPATHLEN];
	char		targ_name[64];
	char		*iscsi		= NULL;
	char		*prop		= NULL;
	char		path[MAXPATHLEN];
	char		*m;
	char		buf[512];		/* one sector size block */
	tgt_node_t	*t		= NULL;
	tgt_node_t	*list		= NULL;
	tgt_node_t	*c		= NULL;
	tgt_node_t	*node		= NULL;
	tgt_node_t	*tpgt		= NULL;
	Boolean_t	change_made	= False;
	int		lun		= 0;
	int		fd;
	uint64_t	val, new_lu_size, cur_lu_size;
	struct stat	st;
	uint32_t	isns_mods	= 0;

	(void) pthread_rwlock_wrlock(&targ_config_mutex);
	if (tgt_find_value_str(x, XML_ELEMENT_NAME, &name) == False) {
		xml_rtn_msg(&msg, ERR_SYNTAX_MISSING_NAME);
		goto error;
	}

	while ((t = tgt_node_next_child(targets_config, XML_ELEMENT_TARG,
	    t)) != NULL) {
		if (strcmp(t->x_value, name) == 0) {
			break;
		}
	}
	if (t == NULL) {
		free(name);
		xml_rtn_msg(&msg, ERR_TARG_NOT_FOUND);
		goto error;
	}

	if (tgt_find_attr_str(t, XML_ELEMENT_INCORE, &m) == True) {
		if (strcmp(m, "true") == 0) {
			free(m);
			free(name);
			(void) pthread_rwlock_unlock(&targ_config_mutex);
			return (modify_zfs(x, cred));
		}
		free(m);
	}

	/*
	 * Under base dir, file 'target name' is a symbolic link
	 * to the real directory 'IQN name' which stores params and back
	 * storage. Therefore we can easily get IQN name from target
	 * name by read the symbolic link content.
	 */
	(void) snprintf(path, sizeof (path), "%s/%s", target_basedir, name);
	bzero(iscsi_path, sizeof (iscsi_path));
	(void) readlink(path, iscsi_path, sizeof (iscsi_path));
	iscsi = basename(iscsi_path);

	/* ---- Finished with these so go ahead and release the memory ---- */
	(void) strncpy(targ_name, name, sizeof (targ_name));
	free(name);

	/*
	 * Grow the LU. We currently do not support shrinking the LU and
	 * that is only because it's unknown if any applications could support
	 * that type of data loss. To support shrinking all that would be
	 * needed is to remove the new/old size check and perform a truncation.
	 * The actually truncation request should be shipped off to the T10
	 * layer so that the LU thread can remap the smaller size without
	 * anyone accessing the data.
	 */
	if (tgt_find_value_str(x, XML_ELEMENT_SIZE, &prop) == True) {
		if (prop == NULL) {
			xml_rtn_msg(&msg, ERR_SYNTAX_EMPTY_TPGT);
			goto error;
		}
		if (strtoll_multiplier(prop, &new_lu_size) == False) {
			free(prop);
			xml_rtn_msg(&msg, ERR_INVALID_SIZE);
			goto error;
		}
		free(prop);
		if ((new_lu_size % 512LL) != 0) {
			xml_rtn_msg(&msg, ERR_SIZE_MOD_BLOCK);
			goto error;
		}
		new_lu_size /= 512LL;

		/* ---- default to LUN 0 ---- */
		(void) tgt_find_value_int(x, XML_ELEMENT_LUN, &lun);

		/* ---- read in current parameters ---- */
		if (mgmt_get_param(&node, targ_name, lun) == False) {
			xml_rtn_msg(&msg, ERR_OPEN_PARAM_FILE_FAILED);
			goto error;
		}

		/* ---- validate that we're indeed growing the LU ---- */
		if (tgt_find_value_str(node, XML_ELEMENT_SIZE, &prop) ==
		    False) {
			xml_rtn_msg(&msg, ERR_INIT_XML_READER_FAILED);
			goto error;
		}
		if (strtoll_multiplier(prop, &cur_lu_size) == False) {
			free(prop);
			xml_rtn_msg(&msg, ERR_INVALID_SIZE);
			goto error;
		}
		free(prop);

		if (new_lu_size < cur_lu_size) {
			xml_rtn_msg(&msg, ERR_CANT_SHRINK_LU);
			goto error;
		}

		/* ---- check that this LU is of type 'disk' or 'tape' ---- */
		if (tgt_find_value_str(node, XML_ELEMENT_DTYPE, &prop) ==
		    False) {
			xml_rtn_msg(&msg, ERR_INIT_XML_READER_FAILED);
			goto error;
		}
		if ((strcmp(prop, TGT_TYPE_DISK) != 0) &&
		    (strcmp(prop, TGT_TYPE_TAPE) != 0)) {
			xml_rtn_msg(&msg, ERR_RESIZE_WRONG_DTYPE);
			free(prop);
			goto error;
		}
		free(prop);

		/* ---- validate the backing store is a regular file ---- */
		(void) snprintf(path, sizeof (path), "%s/%s/%s%d",
		    target_basedir, iscsi, LUNBASE, lun);
		if (stat(path, &st) == -1) {
			xml_rtn_msg(&msg, ERR_STAT_BACKING_FAILED);
			goto error;
		}
		if ((st.st_mode & S_IFMT) != S_IFREG) {
			xml_rtn_msg(&msg,
			    ERR_DISK_BACKING_MUST_BE_REGULAR_FILE);
			goto error;
		}

		/* ---- update the parameter node with new size ---- */
		if ((c = tgt_node_alloc(XML_ELEMENT_SIZE, Uint64, &new_lu_size))
		    == NULL) {
			xml_rtn_msg(&msg, ERR_NO_MEM);
			goto error;
		}
		tgt_node_replace(node, c, MatchName);
		tgt_node_free(c);

		/* ---- now update params file ---- */
		(void) mgmt_param_save2scf(node, targ_name, lun);

		/* ---- grow lu backing store ---- */
		(void) snprintf(path, sizeof (path), "%s/%s/%s%d",
		    target_basedir, iscsi, LUNBASE, lun);
		if ((fd = open(path, O_RDWR|O_CREAT|O_LARGEFILE, 0600)) < 0) {
			xml_rtn_msg(&msg, ERR_LUN_NOT_FOUND);
			goto error;
		}
		(void) lseek(fd, (new_lu_size * 512LL) - 512LL, 0);
		bzero(buf, sizeof (buf));
		if (write(fd, buf, sizeof (buf)) != sizeof (buf)) {
			xml_rtn_msg(&msg, ERR_LUN_NOT_GROWN);
			(void) close(fd);
			goto error;
		}
		(void) close(fd);

		/* ---- send updates to current initiators via ASC/ASCQ ---- */
		iscsi_capacity_change(iscsi, lun);

		prop = NULL;
		tgt_node_free(node);
		node = NULL;
		change_made = True;
	}

	if (tgt_find_value_str(x, XML_ELEMENT_TPGT, &prop) == True) {
		if (prop == NULL) {
			xml_rtn_msg(&msg, ERR_SYNTAX_EMPTY_TPGT);
			goto error;
		}

		/*
		 * Validate that the Target Portal Group Tag is reasonable.
		 */
		val = strtoll(prop, &m, 0);
		if ((val < TPGT_MIN) || (val > TPGT_MAX) ||
		    ((m != NULL) && (*m != '\0'))) {
			xml_rtn_msg(&msg, ERR_INVALID_TPGT);
			free(prop);
			goto error;
		}

		/* update isns only if TPGT contains ip_addr */
		tpgt = NULL;
		while ((tpgt = tgt_node_next_child(main_config,
		    XML_ELEMENT_TPGT, tpgt)) != NULL) {
			if (strcmp(prop, tpgt->x_value) != 0)
				continue;
			if (tgt_node_next(tpgt, XML_ELEMENT_IPADDR, NULL)
			    != NULL) {
				isns_mods |= ISNS_MOD_TPGT;
				break;
			} else {
				xml_rtn_msg(&msg, ERR_TPGT_NO_IPADDR);
				free(prop);
				goto error;
			}
		}

		if ((c = tgt_node_alloc(XML_ELEMENT_TPGT, String, prop)) ==
		    NULL) {
			free(prop);
			xml_rtn_msg(&msg, ERR_NO_MEM);
			goto error;
		}

		if ((list = tgt_node_next(t, XML_ELEMENT_TPGTLIST,
		    NULL)) != NULL) {
			tgt_node_replace(list, c, MatchBoth);
			/*
			 * tgt_node_replace will duplicate the child node
			 * tgt_node_add which is used below just links it
			 * into the tree.
			 */
			tgt_node_free(c);
		} else {
			list = tgt_node_alloc(XML_ELEMENT_TPGTLIST, String, "");
			if (list == NULL) {
				free(prop);
				xml_rtn_msg(&msg, ERR_NO_MEM);
				goto error;
			}
			tgt_node_add(list, c);
			tgt_node_add(t, list);
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

		c = tgt_node_alloc(XML_ELEMENT_INIT, String, prop);
		if (c == NULL) {
			xml_rtn_msg(&msg, ERR_NO_MEM);
			free(prop);
			goto error;
		}
		if ((list = tgt_node_next(t, XML_ELEMENT_ACLLIST,
		    NULL)) != NULL) {
			tgt_node_replace(list, c, MatchBoth);
			/* ---- See above usage ---- */
			tgt_node_free(c);
		} else {
			list = tgt_node_alloc(XML_ELEMENT_ACLLIST, String, "");
			if (list == NULL) {
				xml_rtn_msg(&msg, ERR_NO_MEM);
				free(prop);
				goto error;
			}
			tgt_node_add(list, c);
			tgt_node_add(t, list);
		}
		free(prop);
		prop = NULL;
		change_made = True;
	}

	if (tgt_find_value_str(x, XML_ELEMENT_ALIAS, &prop) == True) {
		if (prop == NULL) {
			xml_rtn_msg(&msg, ERR_SYNTAX_EMPTY_ALIAS);
			goto error;
		}

		if (modify_element(XML_ELEMENT_ALIAS, prop, t, MatchName) ==
		    False) {
			xml_rtn_msg(&msg, ERR_NO_MEM);
			free(prop);
			goto error;
		}
		free(prop);
		prop = NULL;
		isns_mods |= ISNS_MOD_ALIAS;
		change_made = True;
	}

	if (tgt_find_value_str(x, XML_ELEMENT_MAXRECV, &prop) == True) {
		if (prop == NULL) {
			xml_rtn_msg(&msg, ERR_SYNTAX_EMPTY_MAXRECV);
			goto error;
		}

		if ((strtoll_multiplier(prop, &val) == False) ||
		    (val < MAXRCVDATA_MIN) || (val > MAXRCVDATA_MAX)) {
			free(prop);
			xml_rtn_msg(&msg, ERR_INVALID_MAXRECV);
			goto error;
		}
		free(prop);
		if ((prop = malloc(32)) == NULL) {
			xml_rtn_msg(&msg, ERR_NO_MEM);
			goto error;
		}
		(void) snprintf(prop, 32, "%d", val);

		if (modify_element(XML_ELEMENT_MAXRECV, prop, t, MatchName) ==
		    False) {
			free(prop);
			xml_rtn_msg(&msg, ERR_NO_MEM);
			goto error;
		}
		free(prop);
		prop = NULL;
		change_made = True;
	}

	if (change_made == True) {
		if (mgmt_config_save2scf() == False) {
			xml_rtn_msg(&msg, ERR_UPDATE_TARGCFG_FAILED);
			goto error;
		}
		if (isns_enabled() == True) {
			if (isns_dev_update(t->x_value, isns_mods) != 0) {
				xml_rtn_msg(&msg, ERR_ISNS_ERROR);
				goto error;
			}
		}
		xml_rtn_msg(&msg, ERR_SUCCESS);
	} else {
		xml_rtn_msg(&msg, ERR_SYNTAX_MISSING_OPERAND);
	}

error:
	(void) pthread_rwlock_unlock(&targ_config_mutex);
	if (node)
		tgt_node_free(node);
	return (msg);
}

/*
 * []----
 * | modify_initiator -- store the CHAP information for an initiator
 * []----
 */
static char *
modify_initiator(tgt_node_t *x)
{
	char		*msg		= NULL;
	char		*name		= NULL;
	char		*prop		= NULL;
	tgt_node_t	*inode		= NULL;
	Boolean_t	changes_made	= False;

	(void) pthread_rwlock_wrlock(&targ_config_mutex);
	if (tgt_find_value_str(x, XML_ELEMENT_NAME, &name) == False) {
		xml_rtn_msg(&msg, ERR_SYNTAX_MISSING_NAME);
		goto error;
	}

	while ((inode = tgt_node_next_child(main_config, XML_ELEMENT_INIT,
	    inode)) != NULL) {
		if (strcmp(inode->x_value, name) == 0)
			break;
	}

	/*
	 * We no longer need the name since we should have found the node
	 * it refers to and this way we don't have to worry about freeing
	 * the storage later.
	 */
	free(name);

	if (inode == NULL) {
		xml_rtn_msg(&msg, ERR_INIT_NOT_FOUND);
		goto error;
	}

	if (tgt_find_value_str(x, XML_ELEMENT_CHAPSECRET, &prop) == True) {
		if (prop == NULL) {
			xml_rtn_msg(&msg, ERR_SYNTAX_EMPTY_CHAPSECRET);
			goto error;
		}

		if (modify_element(XML_ELEMENT_CHAPSECRET, prop, inode,
		    MatchName) == False) {
			free(prop);
			xml_rtn_msg(&msg, ERR_NO_MEM);
			goto error;
		}
		free(prop);
		changes_made = True;
	}

	if (tgt_find_value_str(x, XML_ELEMENT_DELETE_CHAPSECRET,
	    &prop) == True) {
		if (prop == NULL || strcmp(prop, XML_VALUE_TRUE) != 0) {
			if (prop != NULL)
				free(prop);
			xml_rtn_msg(&msg, ERR_SYNTAX_MISSING_OPERAND);
			goto error;
		}
		free(prop);

		if (delete_element(XML_ELEMENT_CHAPSECRET, inode,
		    MatchName) == False) {
			xml_rtn_msg(&msg, ERR_NO_MEM);
			goto error;
		}
		changes_made = True;
	}

	if (tgt_find_value_str(x, XML_ELEMENT_CHAPNAME, &prop) == True) {
		if (prop == NULL) {
			xml_rtn_msg(&msg, ERR_SYNTAX_EMPTY_CHAPNAME);
			goto error;
		}

		if (modify_element(XML_ELEMENT_CHAPNAME, prop, inode,
		    MatchName) == False) {
			xml_rtn_msg(&msg, ERR_NO_MEM);
			free(prop);
			goto error;
		}
		free(prop);
		changes_made = True;
	}

	if (tgt_find_value_str(x, XML_ELEMENT_DELETE_CHAPNAME, &prop) == True) {
		if (prop == NULL || strcmp(prop, XML_VALUE_TRUE) != 0) {
			if (prop != NULL)
				free(prop);
			xml_rtn_msg(&msg, ERR_SYNTAX_MISSING_OPERAND);
			goto error;
		}
		free(prop);


		if (delete_element(XML_ELEMENT_CHAPNAME, inode,
		    MatchName) == False) {
			xml_rtn_msg(&msg, ERR_NO_MEM);
			goto error;
		}
		changes_made = True;
	}

	if (changes_made == True) {
		if (mgmt_config_save2scf() == True) {
			xml_rtn_msg(&msg, ERR_SUCCESS);
		} else {
			xml_rtn_msg(&msg, ERR_INTERNAL_ERROR);
		}
	} else {
		xml_rtn_msg(&msg, ERR_SYNTAX_MISSING_OPERAND);
	}

error:
	(void) pthread_rwlock_unlock(&targ_config_mutex);
	return (msg);
}

/*
 * []----
 * | modify_admin -- modify one or more of the admin related props
 * []----
 */
static char *
modify_admin(tgt_node_t *x)
{
	char		*msg	= NULL;
	char		*prop;
	Boolean_t	changes_made = False;
	Boolean_t	update_isns = False;
	admin_table_t	*ap;

	for (ap = admin_prop_list; ap->name; ap++) {
		if (tgt_find_value_str(x, ap->name, &prop) == True) {

			if ((prop == NULL) || (strlen(prop) == 0))
				break;

			/*
			 * Do the function call first if it exists which
			 * will allow possible checking to be done first.
			 */
			if (ap->func) {
				msg = (*ap->func)(ap->name, prop);
				if (msg != NULL) {
					free(prop);
					return (msg);
				}
			}

			(void) pthread_rwlock_wrlock(&targ_config_mutex);
			if (ap->delete_name == NULL) {
				if (modify_element(ap->name, prop, main_config,
				    MatchName) == False) {
					xml_rtn_msg(&msg, ERR_NO_MEM);
					free(prop);
					(void) pthread_rwlock_unlock(
					    &targ_config_mutex);
					return (msg);
				}
			} else {
				if (strcmp(prop, XML_VALUE_TRUE) != 0) {
					xml_rtn_msg(&msg,
					    ERR_SYNTAX_MISSING_OPERAND);
					free(prop);
					(void) pthread_rwlock_unlock(
					    &targ_config_mutex);
					return (msg);
				}
				if (delete_element(ap->delete_name,
				    main_config, MatchName) == False) {
					xml_rtn_msg(&msg, ERR_NO_MEM);
					free(prop);
					(void) pthread_rwlock_unlock(
					    &targ_config_mutex);
					return (msg);
				}
			}
			(void) pthread_rwlock_unlock(&targ_config_mutex);
			if (0 == strcmp(ap->name, XML_ELEMENT_ISNS_ACCESS) ||
			    0 == strcmp(ap->name, XML_ELEMENT_ISNS_SERV)) {
				update_isns = True;
			}
			free(prop);
			changes_made = True;
		}
	}

	if (changes_made == True) {
		/* isns_update updates isns_access & isns server name */
		if (update_isns == True) {
			if (isns_update() != 0) {
				xml_rtn_msg(&msg, ERR_ISNS_ERROR);
				return (msg);
			}
		}
		if (mgmt_config_save2scf() == True) {
			xml_rtn_msg(&msg, ERR_SUCCESS);
		} else {
			xml_rtn_msg(&msg, ERR_INTERNAL_ERROR);
		}
	} else {
		xml_rtn_msg(&msg, ERR_SYNTAX_MISSING_OPERAND);
	}

	return (msg);
}

/*
 * []----
 * | modify_tpgt -- add an IP-address to a target portal group
 * []----
 */
static char *
modify_tpgt(tgt_node_t *x)
{
	struct addrinfo	*res	= NULL;
	char		*msg	= NULL;
	char		*name	= NULL;
	char		*ip_str	= NULL;
	tgt_node_t	*tnode	= NULL;
	tgt_node_t	*list	= NULL;

	(void) pthread_rwlock_wrlock(&targ_config_mutex);
	if (tgt_find_value_str(x, XML_ELEMENT_NAME, &name) == False) {
		xml_rtn_msg(&msg, ERR_SYNTAX_MISSING_NAME);
		goto error;
	}
	if (tgt_find_value_str(x, XML_ELEMENT_IPADDR, &ip_str) == False) {
		xml_rtn_msg(&msg, ERR_SYNTAX_MISSING_IPADDR);
		goto error;
	}
	if ((getaddrinfo(ip_str, NULL, NULL, &res) != 0) || (res == NULL)) {
		xml_rtn_msg(&msg, ERR_INVALID_IP);
		goto error;
	}
	while ((tnode = tgt_node_next_child(main_config, XML_ELEMENT_TPGT,
	    tnode)) != NULL) {
		if (strcmp(tnode->x_value, name) == 0)
			break;
	}
	if (tnode == NULL) {
		xml_rtn_msg(&msg, ERR_TPGT_NOT_FOUND);
		goto error;
	}

	if ((list = tgt_node_next(tnode, XML_ELEMENT_IPADDRLIST, NULL))
	    == NULL) {
		list = tgt_node_alloc(XML_ELEMENT_IPADDRLIST, String, "");
		if (list == NULL) {
			xml_rtn_msg(&msg, ERR_NO_MEM);
			goto error;
		}
		tgt_node_add(tnode, list);
	}
	if (modify_element(XML_ELEMENT_IPADDR, ip_str, list, MatchBoth) ==
	    False) {
		xml_rtn_msg(&msg, ERR_NO_MEM);
		goto error;
	}

	if (mgmt_config_save2scf() == True) {
		xml_rtn_msg(&msg, ERR_SUCCESS);
	} else {
		/* tpgt change should be updated to smf */
		xml_rtn_msg(&msg, ERR_INTERNAL_ERROR);
	}

	/*
	 * Re-register all targets, currently there's no method to
	 * update TPGT for individual target
	 */
	if (isns_enabled() == True) {
		(void) isns_reg_all();
	}

error:
	if (name)
		free(name);
	if (ip_str)
		free(ip_str);
	if (res)
		freeaddrinfo(res);
	(void) pthread_rwlock_unlock(&targ_config_mutex);
	return (msg);
}

/*
 * modify_zfs -- test for the existence of a certain dataset being shared
 *
 * Called when someone uses the iscsitgt_is_shared() function from libiscsitgt.
 * All that
 */
static char *
modify_zfs(tgt_node_t *x, ucred_t *cred)
{
	char		*msg		= NULL;
	char		*dataset	= NULL;
	char		*prop;
	char		*m;
	tgt_node_t	*n		= NULL;
	tgt_node_t	*t		= NULL;
	tgt_node_t	*list		= NULL;
	tgt_node_t	*c1, *c2;
	Boolean_t	change_made	= False;
	uint64_t	size;
	int		status;
	int		val;
	char		*tru = "true";

	(void) pthread_rwlock_wrlock(&targ_config_mutex);
	if (tgt_find_value_str(x, XML_ELEMENT_NAME, &dataset) == False) {
		xml_rtn_msg(&msg, ERR_SYNTAX_MISSING_NAME);
		goto error;
	}

	/*
	 * Validate request
	 */
	if (tgt_find_value_str(x, XML_ELEMENT_VALIDATE, &tru)) {
		(void) pthread_rwlock_unlock(&targ_config_mutex);
		if (tru)
			free(tru);
		free(dataset);
		return (validate_zfs_iscsitgt(x));
	}

	/*
	 * Check for existance of ZFS shareiscsi properties
	 */
	status = get_zfs_shareiscsi(dataset, &n, &size, cred);
	if ((status != ERR_SUCCESS) && (status != ERR_NULL_XML_MESSAGE)) {
		xml_rtn_msg(&msg, ERR_TARG_NOT_FOUND);
		goto error;
	}

	while ((t = tgt_node_next_child(targets_config, XML_ELEMENT_TARG, t))
	    != NULL) {
		if (strcmp(t->x_value, dataset) == 0)
			break;
	}
	if (t == NULL) {
		xml_rtn_msg(&msg, ERR_TARG_NOT_FOUND);
		goto error;
	}

	if (tgt_find_value_str(x, XML_ELEMENT_TPGT, &prop) == True) {
		if (prop == NULL) {
			xml_rtn_msg(&msg, ERR_SYNTAX_EMPTY_TPGT);
			goto error;
		}

		/*
		 * Validate that the Target Portal Group Tag is reasonable.
		 */
		val = strtoll(prop, &m, 0);
		if ((val < TPGT_MIN) || (val > TPGT_MAX) ||
		    ((m != NULL) && (*m != '\0'))) {
			xml_rtn_msg(&msg, ERR_INVALID_TPGT);
			goto error;
		}

		if ((c1 = tgt_node_alloc(XML_ELEMENT_TPGT, String, prop)) ==
		    NULL) {
			xml_rtn_msg(&msg, ERR_NO_MEM);
			goto error;
		}

		/*
		 * Due to the fact that the targets_config differs from the
		 * ZVOL properties stored in zfs_shareiscsi, two lists need to
		 * be updated
		 */
		c2 = tgt_node_dup(c1);
		if ((list = tgt_node_next(t, XML_ELEMENT_TPGTLIST, NULL))
		    != NULL) {
			/*
			 * tgt_node_replace will duplicate the child node
			 * tgt_node_add which is used below just links it
			 * into the tree.
			 */
			tgt_node_replace(list, c1, MatchBoth);
			tgt_node_free(c1);
		} else {
			list = tgt_node_alloc(XML_ELEMENT_TPGTLIST, String, "");
			if (list == NULL) {
				xml_rtn_msg(&msg, ERR_NO_MEM);
				goto error;
			}
			tgt_node_add(list, c1);
			tgt_node_add(t, list);
		}
		if ((list = tgt_node_next(n, XML_ELEMENT_TPGTLIST, NULL))
		    != NULL) {
			/*
			 * tgt_node_replace will duplicate the child node
			 * tgt_node_add which is used below just links it
			 * into the tree.
			 */
			tgt_node_replace(list, c2, MatchBoth);
			tgt_node_free(c2);
		} else {
			list = tgt_node_alloc(XML_ELEMENT_TPGTLIST, String, "");
			if (list == NULL) {
				xml_rtn_msg(&msg, ERR_NO_MEM);
				goto error;
			}
			tgt_node_add(list, c2);
			tgt_node_add(n, list);
		}
		change_made = True;
	}

	if (tgt_find_value_str(x, XML_ELEMENT_ACL, &prop) == True) {
		if (prop == NULL) {
			xml_rtn_msg(&msg, ERR_SYNTAX_EMPTY_ACL);
			goto error;
		}

		c1 = tgt_node_alloc(XML_ELEMENT_INIT, String, prop);
		if (c1 == NULL) {
			xml_rtn_msg(&msg, ERR_NO_MEM);
			goto error;
		}

		/*
		 * Due to the fact that the targets_config differs from the
		 * ZVOL properties stored in zfs_shareiscsi, two lists need to
		 * be updated
		 */
		c2 = tgt_node_dup(c1);
		if ((list = tgt_node_next(t, XML_ELEMENT_ACLLIST, NULL))
		    != NULL) {
			/*
			 * tgt_node_replace will duplicate the child node
			 * tgt_node_add which is used below just links it
			 * into the tree.
			 */
			tgt_node_replace(list, c1, MatchBoth);
			tgt_node_free(c1);
		} else {
			list = tgt_node_alloc(XML_ELEMENT_ACLLIST, String, "");
			if (list == NULL) {
				xml_rtn_msg(&msg, ERR_NO_MEM);
				goto error;
			}
			tgt_node_add(list, c1);
			tgt_node_add(t, list);
		}
		if ((list = tgt_node_next(n, XML_ELEMENT_ACLLIST, NULL))
		    != NULL) {
			/*
			 * tgt_node_replace will duplicate the child node
			 * tgt_node_add which is used below just links it
			 * into the tree.
			 */
			tgt_node_replace(list, c2, MatchBoth);
			tgt_node_free(c2);
		} else {
			list = tgt_node_alloc(XML_ELEMENT_ACLLIST, String, "");
			if (list == NULL) {
				xml_rtn_msg(&msg, ERR_NO_MEM);
				goto error;
			}
			tgt_node_add(list, c2);
			tgt_node_add(n, list);
		}

		change_made = True;
	}

	if (change_made == True) {
		status = put_zfs_shareiscsi(dataset, n);
		if (status != ERR_SUCCESS) {
			xml_rtn_msg(&msg, status);
			goto error;
		} else {
			xml_rtn_msg(&msg, ERR_SUCCESS);
		}
	} else {
		xml_rtn_msg(&msg, ERR_SUCCESS);
	}

error:
	if (n)
		tgt_node_free(n);
	if (dataset)
		free(dataset);

	(void) pthread_rwlock_unlock(&targ_config_mutex);
	return (msg);
}

/*
 * Just checking the existance of the given target. Here we check whether
 * both zfs and iscsitarget aware of the given target/volume. It neither
 * care about the credentials nor SHAREISCSI properties.
 */
static char *
validate_zfs_iscsitgt(tgt_node_t *x)
{
	char		*msg		= NULL;
	char		*prop		= NULL;
	char		*dataset	= NULL;
	libzfs_handle_t	*zh		= NULL;
	zfs_handle_t	*zfsh		= NULL;
	tgt_node_t	*n		= NULL;

	if (tgt_find_value_str(x, XML_ELEMENT_NAME, &dataset) == False) {
		xml_rtn_msg(&msg, ERR_SYNTAX_MISSING_NAME);
		return (msg);
	}

	if (((zh = libzfs_init()) == NULL) ||
	    ((zfsh = zfs_open(zh, dataset, ZFS_TYPE_DATASET)) == NULL)) {
		xml_rtn_msg(&msg, ERR_TARG_NOT_FOUND);
		goto error;
	}

	while ((n = tgt_node_next_child(targets_config, XML_ELEMENT_TARG, n)) !=
	    NULL) {
		if (strcmp(n->x_value, dataset) == 0)
			break;
	}
	if (n == NULL) {
		xml_rtn_msg(&msg, ERR_TARG_NOT_FOUND);
		goto error;
	}

	xml_rtn_msg(&msg, ERR_SUCCESS);

error:
	if (zfsh)
		zfs_close(zfsh);
	if (prop)
		free(prop);
	if (zh)
		libzfs_fini(zh);
	if (dataset)
		free(dataset);

	return (msg);

}


/*
 * []----
 * | modify_element -- helper function to create node and add it to parent
 * |
 * | A False return value indicates a failure to allocate enough memory.
 * []----
 */
static Boolean_t
modify_element(char *name, char *value, tgt_node_t *p, match_type_t m)
{
	tgt_node_t	*c;


	if ((c = tgt_node_alloc(name, String, value)) == NULL) {
		return (False);
	} else {
		tgt_node_replace(p, c, m);
		tgt_node_free(c);
		return (True);
	}
}

/*
 * []----
 * | delete_element -- helper function to remove a node from a parent
 * |
 * | A False return value indicates a failure to allocate enough memory.
 * []----
 */
static Boolean_t
delete_element(char *name, tgt_node_t *p, match_type_t m)
{
	tgt_node_t	*c;

	if ((c = tgt_node_alloc(name, String, NULL)) == NULL) {
		return (False);
	}
	(void) tgt_node_remove(p, c, m);
	tgt_node_free(c);
	return (True);
}

/*
 * []----
 * | update_basedir -- update the global target directory
 * |
 * | Most of the properties when updated require no futher processing. The
 * | target base directory however must be updated if it hasn't been set.
 * | On a new system the daemon will not have any location to place the
 * | backing store and target configuration files. On a live system we would
 * | screw things up if we changed the global variable if it was already
 * | in use, so we only allow the updating to occur if there are no targets.
 * []----
 */
/*ARGSUSED*/
char *
update_basedir(char *name, char *prop)
{
	tgt_node_t	*targ	= NULL;
	char		*msg	= NULL;
	char		*v;

	if ((prop == NULL) || (strlen(prop) == 0) || (prop[0] != '/')) {
		xml_rtn_msg(&msg, ERR_INVALID_BASEDIR);
		return (msg);
	}

	while ((targ = tgt_node_next_child(targets_config, XML_ELEMENT_TARG,
	    targ)) != NULL) {
		/*
		 * Traverse the list of configured targets, serching for any
		 * target that is using the current base-directory. Fail the
		 * update if found.
		 *
		 * The only targets that do not use the base-directory at this
		 * time are those targets persisted in ZFS.
		 */
		if (tgt_find_attr_str(targ, XML_ELEMENT_INCORE, &v) == True) {
			if (v != NULL) {
				if (strcmp(v, XML_VALUE_TRUE) == 0) {
					free(v);
					continue;
				}
				free(v);
			}
		}

		/*
		 * Found at least one target, so fail
		 */
		xml_rtn_msg(&msg, ERR_VALID_TARG_EXIST);
		return (msg);
	}

	if (target_basedir) {
		free(target_basedir);
	}
	target_basedir = strdup(prop);
	if ((mkdir(target_basedir, 0700) != 0) && (errno != EEXIST)) {
		xml_rtn_msg(&msg, ERR_CREATE_TARGET_DIR_FAILED);
		free(target_basedir);
		target_basedir = NULL;
	}
	return (msg);
}

/*
 * []----
 * | validate_radius -- validate that server[:port] are valid
 * []----
 */
char *
valid_radius_srv(char *name, char *prop)
{
	struct addrinfo	*res	= NULL;
	char		*msg	= NULL;
	char		*sp, *p;
	int		port;

	if ((sp = strdup(prop)) == NULL) {
		xml_rtn_msg(&msg, ERR_NO_MEM);
		return (msg);
	} else if ((p = strrchr(sp, ':')) != NULL) {
		*p++ = '\0';
		port = atoi(p);
		if ((port < 1) || (port > 65535)) {
			xml_rtn_msg(&msg, ERR_INVALID_RADSRV);
			free(sp);
			return (msg);
		}
	}
	if ((getaddrinfo(sp, NULL, NULL, &res) != 0) || (res == NULL))
		xml_rtn_msg(&msg, ERR_INVALID_RADSRV);
	else
		freeaddrinfo(res);
	free(sp);
	return (msg);
}

/*
 * []----
 * | validate_isns_server -- validate that server[:port] are valid
 * []----
 */
char *
valid_isns_srv(char *name, char *prop)
{
	char		*msg	= NULL;
	char		*sp, *p;
	int		so;
	int		port;

	if (strlen(prop) > MAXHOSTNAMELEN) {
		xml_rtn_msg(&msg, ERR_INVALID_ISNS_SRV);
		return (msg);
	}

	if ((sp = strdup(prop)) == NULL) {
		xml_rtn_msg(&msg, ERR_NO_MEM);
		return (msg);
	}
	if ((p = strrchr(sp, ':')) != NULL) {
		*p++ = '\0';
		port = atoi(p);
		if ((port < 1) || (port > 65535)) {
			xml_rtn_msg(&msg, ERR_INVALID_ISNS_SRV);
			free(sp);
			return (msg);
		}
	}

	so = isns_open(sp);
	if (so < 0) {
		if (isns_enabled() == True) {
			xml_rtn_msg(&msg, ERR_INVALID_ISNS_SRV);
		} else { /* Just print a warning and accept the server */
			syslog(LOG_ALERT,
			    "Check if the server:%s is valid", sp);
		}
	} else {
		isns_close(so);
	}
	free(sp);
	return (msg);
}
