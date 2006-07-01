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
#include <sys/stat.h>
#include <errno.h>
#include <strings.h>
#include <assert.h>
#include <sys/socket.h>
#include <netdb.h>

#include "xml.h"
#include "queue.h"
#include "utility.h"
#include "iscsi_cmd.h"
#include "target.h"
#include "errcode.h"

static char *modify_target(xml_node_t *x);
static char *modify_initiator(xml_node_t *x);
static char *modify_admin(xml_node_t *x);
static char *modify_tpgt(xml_node_t *x);
static Boolean_t modify_element(char *, char *, xml_node_t *, match_type_t);

/*
 * []----
 * | modify_func -- dispatch routine for objects
 * []----
 */
/*ARGSUSED*/
void
modify_func(xml_node_t *p, target_queue_t *reply, target_queue_t *mgmt)
{
	xml_node_t	*x;
	char		*reply_msg	= NULL;

	if (p->x_child == NULL) {
		xml_rtn_msg(&reply_msg, ERR_SYNTAX_MISSING_OBJECT);

	} else {
		x = p->x_child;

		if (x->x_name == NULL) {
			xml_rtn_msg(&reply_msg, ERR_SYNTAX_MISSING_OBJECT);
		} else if (strcmp(x->x_name, XML_ELEMENT_TARG) == 0) {
			reply_msg = modify_target(x);
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
modify_target(xml_node_t *x)
{
	char		*msg		= NULL,
			*name		= NULL,
			*iscsi,
			*prop		= NULL,
			size_str[16],
			path[MAXPATHLEN],
			*m,
			buf[512];		/* one sector size block */
	xml_node_t	*t		= NULL,
			*list		= NULL,
			*c		= NULL,
			*node;
	Boolean_t	change_made	= False;
	int		lun		= 0,
			fd,
			xml_fd;
	uint64_t	val,
			new_lu_size,
			cur_lu_size;
	struct stat	st;
	xmlTextReaderPtr	r;

	if (xml_find_value_str(x, XML_ELEMENT_NAME, &name) == False) {
		xml_rtn_msg(&msg, ERR_SYNTAX_MISSING_NAME);
		return (msg);
	}

	while ((t = xml_node_next(targets_config, XML_ELEMENT_TARG,
	    t)) != NULL) {
		if (strcmp(t->x_value, name) == 0) {
			break;
		}
	}

	/* ---- Finished with these so go ahead and release the memory ---- */
	free(name);

	if (t == NULL) {
		xml_rtn_msg(&msg, ERR_TARG_NOT_FOUND);
		return (msg);
	}

	/*
	 * Grow the LU. We currently do not support shrinking the LU and
	 * that is only because it's unknown if any applications could support
	 * that type of data loss. To support shrinking all that would be
	 * needed is to remove the new/old size check and perform a truncation.
	 * The actually truncation request should be shipped off to the T10
	 * layer so that the LU thread can remap the smaller size without
	 * anyone accessing the data.
	 */
	if (xml_find_value_str(x, XML_ELEMENT_SIZE, &prop) == True) {
		if (prop == NULL) {
			xml_rtn_msg(&msg, ERR_SYNTAX_EMPTY_TPGT);
			return (msg);
		}
		if (strtoll_multiplier(prop, &new_lu_size) == False) {
			free(prop);
			xml_rtn_msg(&msg, ERR_INVALID_SIZE);
			return (msg);
		}
		free(prop);
		if ((new_lu_size % 512LL) != 0) {
			xml_rtn_msg(&msg, ERR_SIZE_MOD_BLOCK);
			return (msg);
		}
		new_lu_size /= 512LL;

		if (xml_find_value_str(x, XML_ELEMENT_INAME, &iscsi) == False) {
			xml_rtn_msg(&msg, ERR_TARGCFG_MISSING_INAME);
			return (msg);
		}

		/* ---- default to LUN 0 ---- */
		(void) xml_find_value_int(x, XML_ELEMENT_LUN, &lun);

		/* ---- read in current paramaters ---- */
		snprintf(path, sizeof (path), "%s/%s/%s%d", target_basedir,
		    iscsi, PARAMBASE, lun);
		if ((xml_fd = open(path, O_RDONLY)) < 0) {
			xml_rtn_msg(&msg, ERR_OPEN_PARAM_FILE_FAILED);
			return (msg);
		}
		if ((r = (xmlTextReaderPtr)xmlReaderForFd(xml_fd, NULL, NULL,
		    0)) != NULL) {
			node = NULL;
			while (xmlTextReaderRead(r) == 1)
				if (xml_process_node(r, &node) == False)
					break;
		} else {
			xml_rtn_msg(&msg, ERR_INIT_XML_READER_FAILED);
			return (msg);
		}

		(void) close(xml_fd);
		xmlTextReaderClose(r);
		xmlFreeTextReader(r);

		/* ---- validate that we're indeed growing the LU ---- */
		if (xml_find_value_str(node, XML_ELEMENT_SIZE, &prop) ==
		    False) {
			xml_rtn_msg(&msg, ERR_INIT_XML_READER_FAILED);
			return (msg);
		}
		if (strtoll_multiplier(prop, &cur_lu_size) == False) {
			free(prop);
			xml_rtn_msg(&msg, ERR_INVALID_SIZE);
			return (msg);
		}
		free(prop);

		if (new_lu_size < cur_lu_size) {
			xml_rtn_msg(&msg, ERR_CANT_SHRINK_LU);
			return (msg);
		}

		/* ---- check that this LU is of type 'disk' or 'tape' ---- */
		if (xml_find_value_str(node, XML_ELEMENT_DTYPE, &prop) ==
		    False) {
			xml_rtn_msg(&msg, ERR_INIT_XML_READER_FAILED);
			return (msg);
		}
		if ((strcmp(prop, TGT_TYPE_DISK) != 0) &&
		    (strcmp(prop, TGT_TYPE_TAPE) != 0)) {
			xml_rtn_msg(&msg, ERR_RESIZE_WRONG_DTYPE);
			return (msg);
		}
		free(prop);

		/* ---- validate the backing store is a regular file ---- */
		snprintf(path, sizeof (path), "%s/%s/%s%d", target_basedir,
		    iscsi, LUNBASE, lun);
		if (stat(path, &st) == -1) {
			xml_rtn_msg(&msg, ERR_STAT_BACKING_FAILED);
			return (msg);
		}
		if ((st.st_mode & S_IFMT) != S_IFREG) {
			xml_rtn_msg(&msg,
			    ERR_DISK_BACKING_MUST_BE_REGULAR_FILE);
			return (msg);
		}

		/* ---- update the parameter node with new size ---- */
		snprintf(size_str, sizeof (size_str), "0x%llx", new_lu_size);
		if ((c = xml_alloc_node(XML_ELEMENT_SIZE, Uint64, size_str)) ==
		    False) {
			xml_rtn_msg(&msg, ERR_NO_MEM);
			return (msg);
		}
		xml_replace_child(node, c, MatchName);
		xml_tree_free(c);

		/* ---- now update params file ---- */
		snprintf(path, sizeof (path), "%s/%s/%s%d", target_basedir,
		    iscsi, PARAMBASE, lun);
		if (xml_dump2file(node, path) == False) {
			xml_rtn_msg(&msg, ERR_UPDATE_TARGCFG_FAILED);
			return (msg);
		}

		/* ---- grow lu backing store ---- */
		snprintf(path, sizeof (path), "%s/%s/%s%d", target_basedir,
		    iscsi, LUNBASE, lun);
		if ((fd = open(path, O_RDWR|O_CREAT|O_LARGEFILE, 0600)) < 0) {
			xml_rtn_msg(&msg, ERR_LUN_NOT_FOUND);
			return (msg);
		}
		(void) lseek(fd, (new_lu_size * 512LL) - 512LL, 0);
		bzero(buf, sizeof (buf));
		if (write(fd, buf, sizeof (buf)) != sizeof (buf)) {
			xml_rtn_msg(&msg, ERR_LUN_NOT_GROWN);
			return (msg);
		}
		(void) close(fd);

		/* ---- send updates to current initiators via ASC/ASCQ ---- */
		iscsi_capacity_change(iscsi, lun);

		free(iscsi);
		prop = NULL;
		xml_tree_free(node);
	}

	if (xml_find_value_str(x, XML_ELEMENT_TPGT, &prop) == True) {
		if (prop == NULL) {
			xml_rtn_msg(&msg, ERR_SYNTAX_EMPTY_ACL);
			return (msg);
		}

		/*
		 * Validate that the Target Portal Group Tag is reasonable.
		 */
		val = strtoll(prop, &m, 0);
		if ((val < TPGT_MIN) || (val > TPGT_MAX) ||
		    ((m != NULL) && (*m != '\0'))) {
			xml_rtn_msg(&msg, ERR_INVALID_TPGT);
			free(prop);
			return (msg);
		}

		if ((c = xml_alloc_node(XML_ELEMENT_TPGT, String, prop)) ==
		    NULL) {
			free(prop);
			xml_rtn_msg(&msg, ERR_NO_MEM);
			return (msg);
		}

		if ((list = xml_node_next(t, XML_ELEMENT_TPGTLIST,
		    NULL)) != NULL) {
			xml_replace_child(list, c, MatchBoth);
			/*
			 * xml_replace_child will duplicate the child node
			 * xml_add_child which is used below just links it
			 * into the tree.
			 */
			xml_tree_free(c);
		} else {
			list = xml_alloc_node(XML_ELEMENT_TPGTLIST, String, "");
			if (list == NULL) {
				free(prop);
				xml_rtn_msg(&msg, ERR_NO_MEM);
				return (msg);
			}
			(void) xml_add_child(list, c);
			(void) xml_add_child(t, list);
		}
		free(prop);
		prop = NULL;
		change_made = True;
	}

	if (xml_find_value_str(x, XML_ELEMENT_ACL, &prop) == True) {
		if (prop == NULL) {
			xml_rtn_msg(&msg, ERR_SYNTAX_EMPTY_ACL);
			return (msg);
		}

		c = xml_alloc_node(XML_ELEMENT_INIT, String, prop);
		if (c == NULL) {
			xml_rtn_msg(&msg, ERR_NO_MEM);
			return (msg);
		}
		if ((list = xml_node_next(t, XML_ELEMENT_ACLLIST,
		    NULL)) != NULL) {
			xml_replace_child(list, c, MatchBoth);
			/* ---- See above usage ---- */
			xml_tree_free(c);
		} else {
			list = xml_alloc_node(XML_ELEMENT_ACLLIST, String, "");
			if (list == NULL) {
				xml_rtn_msg(&msg, ERR_NO_MEM);
				return (msg);
			}
			(void) xml_add_child(list, c);
			(void) xml_add_child(t, list);
		}
		free(prop);
		prop = NULL;
		change_made = True;
	}

	if (xml_find_value_str(x, XML_ELEMENT_ALIAS, &prop) == True) {
		if (prop == NULL) {
			xml_rtn_msg(&msg, ERR_SYNTAX_EMPTY_ALIAS);
			return (msg);
		}

		if (modify_element(XML_ELEMENT_ALIAS, prop, t, MatchName) ==
		    False) {
			xml_rtn_msg(&msg, ERR_NO_MEM);
			return (msg);
		}
		free(prop);
		prop = NULL;
		change_made = True;
	}

	if (xml_find_value_str(x, XML_ELEMENT_MAXRECV, &prop) == True) {
		if (prop == NULL) {
			xml_rtn_msg(&msg, ERR_SYNTAX_EMPTY_MAXRECV);
			return (msg);
		}

		if ((strtoll_multiplier(prop, &val) == False) ||
		    (val < MAXRCVDATA_MIN) || (val > MAXRCVDATA_MAX)) {
			free(prop);
			xml_rtn_msg(&msg, ERR_INVALID_MAXRECV);
			return (msg);
		}
		free(prop);
		if ((prop = malloc(32)) == NULL) {
			xml_rtn_msg(&msg, ERR_NO_MEM);
			return (msg);
		}
		snprintf(prop, 32, "%d", val);

		if (modify_element(XML_ELEMENT_MAXRECV, prop, t, MatchName) ==
		    False) {
			free(prop);
			xml_rtn_msg(&msg, ERR_NO_MEM);
			return (msg);
		}
		free(prop);
		prop = NULL;
		change_made = True;
	}

	if (change_made == True) {
		if (update_config_targets(&msg) == True)
			xml_rtn_msg(&msg, ERR_SUCCESS);
	} else {
		xml_rtn_msg(&msg, ERR_SYNTAX_MISSING_OPERAND);
	}

	return (msg);
}

/*
 * []----
 * | modify_initiator -- store the CHAP information for an initiator
 * []----
 */
static char *
modify_initiator(xml_node_t *x)
{
	char		*msg		= NULL,
			*name		= NULL,
			*prop		= NULL;
	xml_node_t	*inode		= NULL;
	Boolean_t	changes_made	= False;

	if (xml_find_value_str(x, XML_ELEMENT_NAME, &name) == False) {
		xml_rtn_msg(&msg, ERR_SYNTAX_MISSING_NAME);
		return (msg);
	}

	while ((inode = xml_node_next(main_config, XML_ELEMENT_INIT,
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
		return (msg);
	}

	if (xml_find_value_str(x, XML_ELEMENT_CHAPSECRET, &prop) == True) {
		if (prop == NULL) {
			xml_rtn_msg(&msg, ERR_SYNTAX_EMPTY_CHAPSECRET);
			return (msg);
		}

		if (modify_element(XML_ELEMENT_CHAPSECRET, prop, inode,
		    MatchName) == False) {
			xml_rtn_msg(&msg, ERR_NO_MEM);
			return (msg);
		}
		free(prop);
		changes_made = True;
	}

	if (xml_find_value_str(x, XML_ELEMENT_CHAPNAME, &prop) == True) {
		if (prop == NULL) {
			xml_rtn_msg(&msg, ERR_SYNTAX_EMPTY_CHAPNAME);
			return (msg);
		}

		if (modify_element(XML_ELEMENT_CHAPNAME, prop, inode,
		    MatchName) == False) {
			xml_rtn_msg(&msg, ERR_NO_MEM);
			return (msg);
		}
		free(prop);
		changes_made = True;
	}

	if (changes_made == True) {
		if (update_config_main(&msg) == True)
			xml_rtn_msg(&msg, ERR_SUCCESS);
	} else {
		xml_rtn_msg(&msg, ERR_SYNTAX_MISSING_OPERAND);
	}

	return (msg);
}

/*
 * []----
 * | modify_admin -- modify one or more of the admin related props
 * []----
 */
static char *
modify_admin(xml_node_t *x)
{
	char		*msg	= NULL,
			*prop;
	Boolean_t	changes_made = False;
	admin_table_t	*ap;

	for (ap = admin_prop_list; ap->name; ap++) {
		if (xml_find_value_str(x, ap->name, &prop) == True) {

			if ((prop == NULL) || (strlen(prop) == 0))
				break;

			/*
			 * Do the function call first if it exists which
			 * will allow possible checking to be done first.
			 */
			if (ap->func) {
				if ((msg = (*ap->func)(ap->name, prop)) != NULL)
					return (msg);
			}
			if (modify_element(ap->name, prop, main_config,
			    MatchName) == False) {
				xml_rtn_msg(&msg, ERR_NO_MEM);
				return (msg);
			}
			free(prop);
			changes_made = True;
		}
	}

	if (changes_made == True) {
		if (update_config_main(&msg) == True)
			xml_rtn_msg(&msg, ERR_SUCCESS);
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
modify_tpgt(xml_node_t *x)
{
	struct addrinfo	*res	= NULL;
	char		*msg	= NULL,
			*name	= NULL,
			*ip_str	= NULL;
	xml_node_t	*tnode	= NULL;

	if (xml_find_value_str(x, XML_ELEMENT_NAME, &name) == False) {
		xml_rtn_msg(&msg, ERR_SYNTAX_MISSING_NAME);
		goto error;
	}
	if (xml_find_value_str(x, XML_ELEMENT_IPADDR, &ip_str) == False) {
		xml_rtn_msg(&msg, ERR_SYNTAX_MISSING_IPADDR);
		goto error;
	}
	if ((getaddrinfo(ip_str, NULL, NULL, &res) != 0) || (res == NULL)) {
		xml_rtn_msg(&msg, ERR_INVALID_IP);
		goto error;
	}
	while ((tnode = xml_node_next(main_config, XML_ELEMENT_TPGT,
	    tnode)) != NULL) {
		if (strcmp(tnode->x_value, name) == 0)
			break;
	}
	if (tnode == NULL) {
		xml_rtn_msg(&msg, ERR_TPGT_NOT_FOUND);
		goto error;
	}
	if (modify_element(XML_ELEMENT_IPADDR, ip_str, tnode, MatchBoth) ==
	    False) {
		xml_rtn_msg(&msg, ERR_NO_MEM);
		return (msg);
	}

	if (update_config_main(&msg) == True)
		xml_rtn_msg(&msg, ERR_SUCCESS);

error:
	if (name)
		free(name);
	if (ip_str)
		free(ip_str);
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
modify_element(char *name, char *value, xml_node_t *p, match_type_t m)
{
	xml_node_t	*c;

	if ((c = xml_alloc_node(name, String, value)) == NULL)
		return (False);
	else {
		xml_replace_child(p, c, m);
		xml_tree_free(c);
		return (True);
	}
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
	xml_node_t	*targ	= NULL;
	int		count	= 0;
	char		*msg	= NULL;

	if ((prop == NULL) || (strlen(prop) == 0) || (prop[0] != '/')) {
		xml_rtn_msg(&msg, ERR_INVALID_BASEDIR);
		return (msg);
	}

	while ((targ = xml_node_next(targets_config, XML_ELEMENT_TARG,
	    targ)) != NULL) {
		count++;
	}

	if (target_basedir == NULL) {
		target_basedir = strdup(prop);
	} else if (count == 0) {
		free(target_basedir);
		target_basedir = strdup(prop);
		if ((mkdir(target_basedir, 0700) != 0) && (errno != EEXIST)) {
			xml_rtn_msg(&msg, ERR_CREATE_TARGET_DIR_FAILED);
		} else {
			if (process_target_config() == False) {
				xml_rtn_msg(&msg, ERR_CREATE_TARGET_DIR_FAILED);
			}
		}
	} else {
		xml_rtn_msg(&msg, ERR_VALID_TARG_EXIST);
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
	char		*msg	= NULL,
			*sp,
			*p;
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
