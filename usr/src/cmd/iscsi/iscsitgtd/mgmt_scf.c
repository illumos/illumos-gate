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
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/conf.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <siginfo.h>
#include <libscf.h>
#include <syslog.h>
#include <synch.h>
#include <libxml/xmlreader.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <iscsitgt_impl.h>
#include <umem.h>
#include <priv.h>
#include <libgen.h>
#include <ctype.h>
#include <pthread.h>
#include <pwd.h>
#include <auth_attr.h>
#include <sasl/saslutil.h>
#include <sys/wait.h>

#include "mgmt_scf.h"
#include "port.h"
#include "iscsi_conn.h"
#include "target.h"
#include "utility.h"
#include "iscsi_ffp.h"
#include "errcode.h"
#include "t10.h"

#define	PGNAME_SIZE	64

static Boolean_t create_pg(targ_scf_t *h, char *pgname, char *prop);
static void new_property(targ_scf_t *h, tgt_node_t *n);
static void new_value_list(targ_scf_t *h, tgt_node_t *p);
static int isnumber(char *s);
static void backup(char *file, char *ext);
static pthread_mutex_t scf_conf_mutex;
static pthread_mutex_t scf_param_mutex;

static void pgname_encode(char *instr, char *outstr, int max_len);
static void pgname_decode(char *instr);

Boolean_t
mgmt_scf_init()
{
	(void) pthread_mutex_init(&scf_conf_mutex, NULL);
	(void) pthread_mutex_init(&scf_param_mutex, NULL);
	return (True);
}

void
mgmt_scf_fini()
{
	(void) pthread_mutex_destroy(&scf_conf_mutex);
	(void) pthread_mutex_destroy(&scf_param_mutex);
}

void
mgmt_handle_fini(targ_scf_t *h)
{
	if (h != NULL) {
		int	unbind = 0;
		if (h->t_scope != NULL) {
			unbind = 1;
			scf_scope_destroy(h->t_scope);
			h->t_scope = NULL;
		}
		if (h->t_instance != NULL) {
			scf_instance_destroy(h->t_instance);
			h->t_instance = NULL;
		}
		if (h->t_service != NULL) {
			scf_service_destroy(h->t_service);
			h->t_service = NULL;
		}
		if (h->t_pg != NULL) {
			scf_pg_destroy(h->t_pg);
			h->t_pg = NULL;
		}
		if (h->t_handle != NULL) {
			if (unbind)
				(void) scf_handle_unbind(h->t_handle);
			scf_handle_destroy(h->t_handle);
			h->t_handle = NULL;
		}
		free(h);
		h = NULL;
	}
}

targ_scf_t *
mgmt_handle_init(void)
{
	targ_scf_t	*h;

	h = calloc(1, sizeof (targ_scf_t));
	if (h == NULL)
		return (NULL);

	h->t_handle = scf_handle_create(SCF_VERSION);
	if (h->t_handle != NULL) {
		if (scf_handle_bind(h->t_handle) == 0) {
			h->t_scope	= scf_scope_create(h->t_handle);
			h->t_service	= scf_service_create(h->t_handle);
			h->t_pg		= scf_pg_create(h->t_handle);
			h->t_instance	= scf_instance_create(h->t_handle);
			if (scf_handle_get_scope(h->t_handle, SCF_SCOPE_LOCAL,
			    h->t_scope) == 0) {
				if (scf_scope_get_service(h->t_scope,
				    SA_TARGET_SVC_NAME, h->t_service) != 0)
					goto error;

			} else {
				syslog(LOG_ERR,
				    "Got local scope which is wrong\n");
				goto error;
			}
		} else
			goto error;
	} else {
		free(h);
		h = NULL;
		syslog(LOG_ERR,
		    "iscsitgt could not access SMF repository: %s\n",
		    scf_strerror(scf_error()));
	}

	return (h);
error:
	mgmt_handle_fini(h);
	syslog(LOG_ERR, "iscsitgt SMF initialization problem: %s\n",
	    scf_strerror(scf_error()));
	return (NULL);
}

/*
 * This function starts a transaction with name of a property group
 * and name of its property. If the property group does not exist
 * this function will create an empty property group.
 */
Boolean_t
mgmt_transaction_start(targ_scf_t *h, char *pg, char *prop)
{
	Boolean_t	ret = True;

	h->t_trans = scf_transaction_create(h->t_handle);
	if (h->t_trans != NULL) {
		if ((create_pg(h, pg, prop) == False) ||
		    (scf_transaction_start(h->t_trans, h->t_pg) != 0)) {
			scf_transaction_destroy(h->t_trans);
			h->t_trans = NULL;
			ret = False;
			syslog(LOG_ERR, "transaction_start start: %s\n",
			    scf_strerror(scf_error()));
		}
	} else {
		syslog(LOG_ERR, "transaction_start create: %s\n",
		    scf_strerror(scf_error()));
		ret = False;
	}
	return (ret);
}

Boolean_t
mgmt_transaction_end(targ_scf_t *h)
{
	Boolean_t	ret = True;

	if (scf_transaction_commit(h->t_trans) < 0)
		ret = False;
	(void) scf_pg_update(h->t_pg);
	(void) scf_transaction_destroy_children(h->t_trans);
	(void) scf_transaction_destroy(h->t_trans);
	h->t_trans = NULL;
	return (ret);
}

void
mgmt_transaction_abort(targ_scf_t *h)
{
	if (h->t_trans != NULL) {
		scf_transaction_reset_all(h->t_trans);
		scf_transaction_destroy_children(h->t_trans);
		scf_transaction_destroy(h->t_trans);
		h->t_trans = NULL;
	}
}

/*
 * process property group name first
 * a reasonable buf to receive encoded pgname is double size of pgname
 */
#define	PG_FACTOR	2
static Boolean_t
create_pg(targ_scf_t *h, char *pgname, char *prop)
{
	int len;
	char *buf = NULL;

	len = strlen(pgname);
	buf = (char *)calloc(1, len * PG_FACTOR);
	if (buf == NULL)
		return (False);

	pgname_encode(pgname, buf, len * PG_FACTOR);

	if (scf_service_get_pg(h->t_service, buf, h->t_pg) != 0) {
		if (scf_service_add_pg(h->t_service, buf,
		    prop, 0, h->t_pg) != 0) {
			free(buf);
			return (False);
		}
	}
	free(buf);
	return (True);
}

/*
 * mgmt_get_main_config() loads main configuration
 * from scf into a node tree.
 * Main configuration includes: admin/target/tpgt/initiator info.
 * admin info is stored in "iscsitgt" property group
 * target info is stored in "target_<name>" property group
 * initiator info is stored in "initiator_<name>" property group
 * tpgt info is stored in "tpgt_<number>" property group
 */
Boolean_t
mgmt_get_main_config(tgt_node_t **node)
{
	targ_scf_t *h = NULL;
	scf_property_t *prop = NULL;
	scf_value_t *value = NULL;
	scf_iter_t *iter = NULL;
	scf_iter_t *iter_v = NULL;
	scf_iter_t *iter_pv = NULL;
	char pname[32];
	char valuebuf[MAXPATHLEN];
	char passcode[32];
	unsigned int outlen;
	tgt_node_t	*n;
	tgt_node_t	*pn;
	tgt_node_t	*vn;
	Boolean_t	status = False;

	h = mgmt_handle_init();

	if (h == NULL)
		return (status);

	prop = scf_property_create(h->t_handle);
	value = scf_value_create(h->t_handle);
	iter = scf_iter_create(h->t_handle);

	(void) pthread_mutex_lock(&scf_conf_mutex);

	/* Basic Information is stored in iscsitgt pg */
	if (scf_service_get_pg(h->t_service, "iscsitgt", h->t_pg) == -1) {
		goto error;
	}

	*node = NULL;
	*node = tgt_node_alloc("main_config", String, NULL);
	if (*node == NULL)
		goto error;

	if (scf_iter_pg_properties(iter, h->t_pg) == -1) {
		goto error;
	}

	while (scf_iter_next_property(iter, prop) > 0) {
		(void) scf_property_get_value(prop, value);
		(void) scf_value_get_as_string(value, valuebuf, MAXPATHLEN);
		(void) scf_property_get_name(prop, pname, sizeof (pname));

		/* avoid load auth to incore data */
		if (strcmp(pname, ISCSI_READ_AUTHNAME) == 0 ||
		    strcmp(pname, ISCSI_MODIFY_AUTHNAME) == 0 ||
		    strcmp(pname, ISCSI_VALUE_AUTHNAME) == 0)
			continue;

		n = tgt_node_alloc(pname, String, valuebuf);
		if (n == NULL)
			goto error;

		/* put version info into root node's attr */
		if (strcmp(pname, XML_ELEMENT_VERS) == 0) {
			tgt_node_add_attr(*node, n);
		} else {
		/* add other basic info into root node */
			tgt_node_add(*node, n);
		}
	}

	/*
	 * targets/initiators/tpgt information is
	 * stored as type "configuration" in scf
	 * each target's param is stored as type "parameter"
	 */
	if (scf_iter_service_pgs_typed(iter, h->t_service, "configuration")
	    == -1) {
		goto error;
	}

	while (scf_iter_next_pg(iter, h->t_pg) > 0) {
		char *iname;

		(void) scf_pg_get_name(h->t_pg, pname, sizeof (pname));
		pgname_decode(pname);
		iname = strchr(pname, '_');
		if (iname == NULL) {
			/* the pg found here is not a tgt/initiator/tpgt */
			continue;
		}
		*iname = '\0';
		iname++;
		/*
		 * now pname is "target" or "initiator" or "tpgt"
		 * meanwhile iname is the actual name of the item
		 */

		n = tgt_node_alloc(pname, String, iname);
		if (n == NULL)
			goto error;

		iter_v = scf_iter_create(h->t_handle);
		if (scf_iter_pg_properties(iter_v, h->t_pg) == -1) {
			goto error;
		}
		while (scf_iter_next_property(iter_v, prop) > 0) {
			/* there may be many values in one property */
			char *vname;

			(void) scf_property_get_name(prop, pname,
			    sizeof (pname));
			/* avoid load auth to incore data */
			if (strcmp(pname, ISCSI_READ_AUTHNAME) == 0 ||
			    strcmp(pname, ISCSI_MODIFY_AUTHNAME) == 0 ||
			    strcmp(pname, ISCSI_VALUE_AUTHNAME) == 0)
				continue;

			vname = strstr(pname, "-list");
			if (vname == NULL) {
				(void) scf_property_get_value(prop, value);
				(void) scf_value_get_as_string(value, valuebuf,
				    MAXPATHLEN);

				pn = tgt_node_alloc(pname, String, valuebuf);
				if (pn == NULL)
					goto error;
				tgt_node_add(n, pn);
			} else {
				pn = tgt_node_alloc(pname, String, NULL);
				if (pn == NULL)
					goto error;
				tgt_node_add(n, pn);
				*vname = '\0';

				iter_pv = scf_iter_create(h->t_handle);
				(void) scf_iter_property_values(iter_pv, prop);
				while (scf_iter_next_value(iter_pv, value)
				    > 0) {
					(void) scf_value_get_as_string(
					    value, valuebuf, MAXPATHLEN);
					/*
					 * map 'acl' to 'initiator' since that
					 * is what used inside the acl-list.
					 */
					if (strcmp(pname, XML_ELEMENT_ACL)
					    == 0) {
						vn = tgt_node_alloc(
						    XML_ELEMENT_INIT,
						    String, valuebuf);
					} else {
						vn = tgt_node_alloc(
						    pname, String, valuebuf);
					}
					if (vn == NULL)
						goto error;
					tgt_node_add(pn, vn);
				}
				scf_iter_destroy(iter_pv);
				iter_pv = NULL;
			}
		}
		tgt_node_add(*node, n);
		scf_iter_destroy(iter_v);
		iter_v = NULL;
	}

	/* chap-secrets are stored in "passwords" pgroup as "application" */
	if (scf_service_get_pg(h->t_service, "passwords", h->t_pg) == 0) {
		if (scf_iter_pg_properties(iter, h->t_pg) == -1) {
			goto error;
		}

		while (scf_iter_next_property(iter, prop) > 0) {
			(void) scf_property_get_value(prop, value);
			(void) scf_value_get_as_string(value, valuebuf,
			    MAXPATHLEN);
			(void) scf_property_get_name(prop, pname,
			    sizeof (pname));

			/* avoid load auth to incore data */
			if (strcmp(pname, ISCSI_READ_AUTHNAME) == 0 ||
			    strcmp(pname, ISCSI_MODIFY_AUTHNAME) == 0 ||
			    strcmp(pname, ISCSI_VALUE_AUTHNAME) == 0)
				continue;

			/* max length of decoded passwd is 16B */
			(void) sasl_decode64(valuebuf, strlen(valuebuf),
			    passcode, sizeof (passcode), &outlen);

			if (strcmp(pname, "radius") == 0) {
				pn = tgt_node_alloc(XML_ELEMENT_RAD_SECRET,
				    String, passcode);
				tgt_node_add(*node, pn);
			} else if (strcmp(pname, "main") == 0) {
				pn = tgt_node_alloc(XML_ELEMENT_CHAPSECRET,
				    String, passcode);
				tgt_node_add(*node, pn);
			} else {
				/* find corresponding initiator */
				n = NULL;
				while (n = tgt_node_next_child(*node,
				    XML_ELEMENT_INIT, n)) {
					if (strcmp(pname + 2, n->x_value) != 0)
						continue;
					pn = tgt_node_alloc(
					    XML_ELEMENT_CHAPSECRET,
					    String, passcode);
					tgt_node_add(n, pn);
				}
			}
		}
	}

	status = True;
error:
	if ((status != True) && (*node != NULL))
		tgt_node_free(*node);
	(void) pthread_mutex_unlock(&scf_conf_mutex);
	if (iter_pv != NULL)
		scf_iter_destroy(iter_pv);
	if (iter_v != NULL)
		scf_iter_destroy(iter_v);
	scf_iter_destroy(iter);
	scf_value_destroy(value);
	scf_property_destroy(prop);
	mgmt_handle_fini(h);
	return (status);
}

static int
isnumber(char *s)
{
	register int c;

	if (!s || !(*s))
		return (0);
	while ((c = *(s++)) != '\0') {
		if (!isdigit(c))
			return (0);
	}
	return (1);
}

static void
new_property(targ_scf_t *h,
	    tgt_node_t *n)
{
	scf_transaction_entry_t *e = NULL;
	scf_value_t *v = NULL;
	scf_type_t type;

	assert(n != NULL);

	e = scf_entry_create(h->t_handle);
	v = scf_value_create(h->t_handle);

	if (strcmp(n->x_value, "true") == 0 ||
	    strcmp(n->x_value, "false") == 0) {
		type = SCF_TYPE_BOOLEAN;
	} else if (strcmp(n->x_name, "main") == 0 ||
	    strcmp(n->x_name, "radius") == 0) {
		type = SCF_TYPE_ASTRING;
	} else if (strncmp(n->x_name, "I_", 2) == 0) {
		type = SCF_TYPE_ASTRING;
	} else if (strcmp(n->x_name, XML_ELEMENT_VERS) == 0) {
		type = SCF_TYPE_ASTRING;
	} else if (isnumber(n->x_value)) {
		type = SCF_TYPE_COUNT;
	} else {
		type = SCF_TYPE_ASTRING;
	}
	(void) scf_transaction_property_new(h->t_trans, e, n->x_name, type);
	(void) scf_value_set_from_string(v, type, n->x_value);
	(void) scf_entry_add_value(e, v);
}

static void
new_value_list(targ_scf_t *h,
	    tgt_node_t *p)
{
	scf_transaction_entry_t *e = NULL;
	scf_value_t *v = NULL;
	tgt_node_t *c;
	char *name;

	assert(p != NULL);

	name = p->x_name;
	e = scf_entry_create(h->t_handle);
	(void) scf_transaction_property_new(h->t_trans, e, name,
	    SCF_TYPE_ASTRING);

	for (c = p->x_child; c; c = c->x_sibling) {
		v = scf_value_create(h->t_handle);
		(void) scf_value_set_astring(v, c->x_value);
		(void) scf_entry_add_value(e, v);
	}
}

/*
 * mgmt_config_save2scf() saves main configuration to scf
 * See also : mgmt_get_main_config()
 */
Boolean_t
mgmt_config_save2scf()
{
	targ_scf_t *h = NULL;
	scf_property_t *prop = NULL;
	scf_value_t *value = NULL;
	scf_iter_t *iter = NULL;
	char pgname[PGNAME_SIZE];
	char passcode[32];
	char *incore = NULL;
	unsigned int	outlen;
	tgt_node_t	*n = NULL;
	tgt_node_t	*pn = NULL;
	tgt_node_t	*tn = NULL;
	scf_transaction_t *tx = NULL;
	secret_list_t	*sl_head;
	secret_list_t	*sl_tail;

	h = mgmt_handle_init();

	if (h == NULL)
		return (False);

	prop = scf_property_create(h->t_handle);
	value = scf_value_create(h->t_handle);
	iter = scf_iter_create(h->t_handle);

	(void) pthread_mutex_lock(&scf_conf_mutex);

	if (mgmt_transaction_start(h, "iscsitgt", "basic") == True) {
		(void) scf_pg_delete(h->t_pg);
		(void) mgmt_transaction_end(h);
	}

	if (mgmt_transaction_start(h, "passwords", "application") == True) {
		(void) scf_pg_delete(h->t_pg);
		(void) mgmt_transaction_end(h);
	}

	if (scf_iter_service_pgs_typed(iter, h->t_service, "configuration")
	    == -1) {
		goto error;
	}

	tx = scf_transaction_create(h->t_handle);
	while (scf_iter_next_pg(iter, h->t_pg) > 0) {
		(void) scf_transaction_start(tx, h->t_pg);
		(void) scf_pg_delete(h->t_pg);
		(void) scf_transaction_commit(tx);
	}
	scf_transaction_reset(tx);
	scf_transaction_destroy(tx);

	sl_head = (secret_list_t *)calloc(1, sizeof (secret_list_t));
	sl_tail = sl_head;

	if (mgmt_transaction_start(h, "iscsitgt", "basic") == True) {
		for (n = main_config->x_child; n; n = n->x_sibling) {
			if ((tgt_find_attr_str(n, XML_ELEMENT_INCORE, &incore))
			    == True) {
				if (strcmp(incore, "true") == 0) {
					/*
					 * Ignore in core only elements.
					 * zvol target is the only one with
					 * incore attr as of now.
					 */
					free(incore);
					continue;
				}
				/* if incore is false continue on */
				free(incore);
			}
			if (strcmp(n->x_name,
			    XML_ELEMENT_CHAPSECRET) == 0) {
				sl_tail->next =  (secret_list_t *)
				    calloc(1, sizeof (secret_list_t));
				sl_tail = sl_tail->next;
				sl_tail->name = strdup("main");
				sl_tail->secret = strdup(n->x_value);
				continue;
			}
			/* so does the radius server secret */
			if (strcmp(n->x_name,
			    XML_ELEMENT_RAD_SECRET) == 0) {
				sl_tail->next =  (secret_list_t *)
				    calloc(1, sizeof (secret_list_t));
				sl_tail = sl_tail->next;
				sl_tail->name = strdup("radius");
				sl_tail->secret = strdup(n->x_value);
				continue;
			}
			if (n->x_child == NULL) {
				new_property(h, n);
			}
		}
		new_property(h, main_config->x_attr);
		n = tgt_node_alloc(ISCSI_MODIFY_AUTHNAME, String,
		    ISCSI_AUTH_MODIFY);
		new_property(h, n);
		tgt_node_free(n);
		n = tgt_node_alloc(ISCSI_VALUE_AUTHNAME, String,
		    ISCSI_AUTH_VALUE);
		new_property(h, n);
		tgt_node_free(n);
		(void) mgmt_transaction_end(h);
	}

	/* now update target/initiator/tpgt information */
	for (n = main_config->x_child; n; n = n->x_sibling) {
		if (n->x_child == NULL)
			continue;

		if ((tgt_find_attr_str(n, XML_ELEMENT_INCORE, &incore))
		    == True) {
			if (strcmp(incore, "true") == 0) {
				/*
				 * Ignore in core only elements.
				 * zvol target is the only one with
				 * incore attr as of now.
				 */
				free(incore);
				continue;
			}
			/* if incore is false continue on */
			free(incore);
		}

		(void) snprintf(pgname, sizeof (pgname), "%s_%s", n->x_name,
		    n->x_value);

		if (mgmt_transaction_start(h, pgname, "configuration")
		    == True) {
			for (pn = n->x_child; pn; pn = pn->x_sibling) {
				if (strcmp(pn->x_name,
				    XML_ELEMENT_CHAPSECRET) == 0) {
					sl_tail->next =  (secret_list_t *)
					    calloc(1, sizeof (secret_list_t));
					sl_tail = sl_tail->next;
					sl_tail->name = (char *)
					    calloc(1, strlen(n->x_value) + 3);
					(void) snprintf(sl_tail->name,
					    strlen(n->x_value) + 3,
					    "I_%s", n->x_value);
					sl_tail->secret = strdup(pn->x_value);
					continue;
				}
				if (pn->x_child == NULL) {
					/* normal property */
					new_property(h, pn);
				} else {
					/* pn -> xxx-list */
					new_value_list(h, pn);
				}
				tn = tgt_node_alloc(ISCSI_MODIFY_AUTHNAME,
				    String, ISCSI_AUTH_MODIFY);
				new_property(h, tn);
				tgt_node_free(tn);
				tn = tgt_node_alloc(ISCSI_VALUE_AUTHNAME,
				    String, ISCSI_AUTH_VALUE);
				new_property(h, tn);
				tgt_node_free(tn);
			}
			(void) mgmt_transaction_end(h);
		} else
			goto error;
	}

	if (mgmt_transaction_start(h, "passwords", "application") == True) {
		while (sl_head != NULL) {
			/* Here we use sl_tail as a temporari var */
			sl_tail = sl_head->next;
			if (sl_head->name) {
				/* max length of encoded passwd is 24B */
				(void) sasl_encode64(sl_head->secret,
				    strlen(sl_head->secret), passcode,
				    sizeof (passcode), &outlen);

				n = tgt_node_alloc(sl_head->name, String,
				    passcode);
				new_property(h, n);
				tgt_node_free(n);
			}
			if (sl_head->name)
				free(sl_head->name);
			if (sl_head->secret)
				free(sl_head->secret);
			free(sl_head);
			sl_head = sl_tail;
		}
		n = tgt_node_alloc(ISCSI_READ_AUTHNAME, String,
		    ISCSI_AUTH_READ);
		new_property(h, n);
		tgt_node_free(n);
		n = tgt_node_alloc(ISCSI_VALUE_AUTHNAME, String,
		    ISCSI_AUTH_VALUE);
		new_property(h, n);
		tgt_node_free(n);
		n = tgt_node_alloc(ISCSI_MODIFY_AUTHNAME, String,
		    ISCSI_AUTH_MODIFY);
		new_property(h, n);
		tgt_node_free(n);
		(void) mgmt_transaction_end(h);
	}

	if (smf_refresh_instance(SA_TARGET_SVC_INSTANCE_FMRI) != 0)
		goto error;

	(void) pthread_mutex_unlock(&scf_conf_mutex);
	scf_iter_destroy(iter);
	scf_value_destroy(value);
	scf_property_destroy(prop);
	return (True);

error:
	(void) pthread_mutex_unlock(&scf_conf_mutex);
	scf_iter_destroy(iter);
	scf_value_destroy(value);
	scf_property_destroy(prop);
	mgmt_handle_fini(h);
	return (False);
}

Boolean_t
mgmt_param_save2scf(tgt_node_t *node, char *target_name, int lun)
{
	targ_scf_t *h = NULL;
	scf_property_t *prop = NULL;
	scf_value_t *value = NULL;
	scf_iter_t *iter = NULL;
	char pgname[PGNAME_SIZE];
	tgt_node_t	*n = NULL;

	h = mgmt_handle_init();

	if (h == NULL)
		return (False);

	(void) snprintf(pgname, sizeof (pgname), "param_%s_%d", target_name,
	    lun);

	(void) pthread_mutex_lock(&scf_param_mutex);

	if (mgmt_transaction_start(h, pgname, "parameter") == True) {
		(void) scf_pg_delete(h->t_pg);
		(void) mgmt_transaction_end(h);
	}

	if (mgmt_transaction_start(h, pgname, "parameter") == True) {
		for (n = node->x_child; n; n = n->x_sibling) {
			if (n->x_child == NULL) {
			/* now n is node of basic property */
				new_property(h, n);
			}
		}
		new_property(h, node->x_attr);
		n = tgt_node_alloc(ISCSI_VALUE_AUTHNAME, String,
		    ISCSI_AUTH_VALUE);
		new_property(h, n);
		tgt_node_free(n);
		n = tgt_node_alloc(ISCSI_MODIFY_AUTHNAME, String,
		    ISCSI_AUTH_MODIFY);
		new_property(h, n);
		tgt_node_free(n);
		(void) mgmt_transaction_end(h);
	}

	(void) pthread_mutex_unlock(&scf_param_mutex);
	return (True);

error:
	(void) pthread_mutex_unlock(&scf_param_mutex);
	scf_iter_destroy(iter);
	scf_value_destroy(value);
	scf_property_destroy(prop);
	mgmt_handle_fini(h);
	return (False);
}

/*
 * mgmt_get_param() get parameter of a specific LUN from scf
 * Args:
 *  node - the node which parameters will be stored in mem
 *  target_name - the local target name
 *  lun - the LUN number
 * See also : mgmt_param_save2scf()
 */
Boolean_t
mgmt_get_param(tgt_node_t **node, char *target_name, int lun)
{
	targ_scf_t *h = NULL;
	scf_property_t *prop = NULL;
	scf_value_t *value = NULL;
	scf_iter_t *iter = NULL;
	char pname[64];
	char expgname[PGNAME_SIZE * PG_FACTOR];
	char pgname[PGNAME_SIZE];
	char valuebuf[MAXPATHLEN];
	tgt_node_t	*n;
	Boolean_t status = False;

	/* Set NULL as default output value */
	*node = NULL;
	h = mgmt_handle_init();

	if (h == NULL)
		return (status);

	prop = scf_property_create(h->t_handle);
	value = scf_value_create(h->t_handle);
	iter = scf_iter_create(h->t_handle);

	(void) snprintf(pgname, sizeof (pgname), "param_%s_%d", target_name,
	    lun);
	pgname_encode(pgname, expgname, PGNAME_SIZE);

	(void) pthread_mutex_lock(&scf_param_mutex);

	if (scf_service_get_pg(h->t_service, expgname, h->t_pg) == -1) {
		goto error;
	}

	*node = tgt_node_alloc(XML_ELEMENT_PARAMS, String, NULL);
	if (*node == NULL)
		goto error;

	if (scf_iter_pg_properties(iter, h->t_pg) == -1) {
		goto error;
	}

	while (scf_iter_next_property(iter, prop) > 0) {
		(void) scf_property_get_value(prop, value);
		(void) scf_value_get_as_string(value, valuebuf, MAXPATHLEN);
		(void) scf_property_get_name(prop, pname, sizeof (pname));

		/* avoid load auth to incore data */
		if (strcmp(pname, ISCSI_READ_AUTHNAME) == 0 ||
		    strcmp(pname, ISCSI_MODIFY_AUTHNAME) == 0 ||
		    strcmp(pname, ISCSI_VALUE_AUTHNAME) == 0)
			continue;

		n = tgt_node_alloc(pname, String, valuebuf);
		if (n == NULL)
			goto error;

		/* put version info into root node's attr */
		if (strcmp(pname, XML_ELEMENT_VERS) == 0) {
			tgt_node_add_attr(*node, n);
		} else {
		/* add other basic info into root node */
			tgt_node_add(*node, n);
		}
	}

	status = True;
error:
	(void) pthread_mutex_unlock(&scf_param_mutex);
	scf_iter_destroy(iter);
	scf_value_destroy(value);
	scf_property_destroy(prop);
	mgmt_handle_fini(h);
	return (status);
}

Boolean_t
mgmt_param_remove(char *target_name, int lun)
{
	targ_scf_t *h = NULL;
	char pgname[PGNAME_SIZE];

	h = mgmt_handle_init();
	if (h == NULL)
		return (False);

	(void) snprintf(pgname, sizeof (pgname), "param_%s_%d", target_name,
	    lun);

	if (mgmt_transaction_start(h, pgname, "parameter") == True) {
		(void) scf_pg_delete(h->t_pg);
		(void) mgmt_transaction_end(h);
		(void) mgmt_handle_fini(h);
		return (True);
	} else {
		mgmt_handle_fini(h);
		return (False);
	}
}

/*
 * mgmt_convert_param() converts legacy params file of each LUN
 * to scf data. It will convert LUNs under one target each time.
 * Args:
 *   dir - string of directory where param file is stored
 *   tnode - node tree which contains to a target
 */
Boolean_t
mgmt_convert_param(char *dir, tgt_node_t *tnode)
{
	Boolean_t	ret = False;
	char		path[MAXPATHLEN];
	int		xml_fd = -1;
	int		n;
	int		lun_num;
	tgt_node_t	*lun = NULL;
	tgt_node_t	*params = NULL;
	xmlTextReaderPtr	r;

	while ((lun = tgt_node_next(tnode, XML_ELEMENT_LUN, lun)) != NULL) {
		if ((tgt_find_value_int(lun, XML_ELEMENT_LUN, &lun_num)) ==
		    False)
			continue;
		(void) snprintf(path, sizeof (path), "%s/%s%d",
		    dir, PARAMBASE, lun_num);
		if ((xml_fd = open(path, O_RDONLY)) < 0)
			continue;
		if ((r = (xmlTextReaderPtr)xmlReaderForFd(xml_fd,
		    NULL, NULL, 0)) == NULL)
			continue;

		n = xmlTextReaderRead(r);
		while (n == 1) {
			if (tgt_node_process(r, &params) == False) {
				break;
			}
			n = xmlTextReaderRead(r);
		}
		if (n < 0) {
			ret = False;
			break;
		}

		if (mgmt_param_save2scf(params, tnode->x_value, lun_num)
		    != True) {
			ret = False;
			break;
		} else {
			backup(path, tnode->x_value);
			ret = True;
		}
		params = NULL;
		(void) close(xml_fd);
		(void) xmlTextReaderClose(r);
		xmlFreeTextReader(r);
	}

	if (ret == False)
		syslog(LOG_ERR, "Converting target %s params failed", dir);
	return (ret);
}

/*
 * this function tries to convert configuration in files into scf
 * it loads xml conf into node tree then dump them to scf with
 * mgmt_config_save2scf()
 * this function has 3 return values:
 * CONVERT_OK: successfully converted
 * CONVERT_INIT_NEW: configuration files dont exist, created a new scf entry
 * CONVERT_FAIL: some error occurred in conversion and no scf entry created.
 *               In this case, user have to check files manually and try
 *               conversion again.
 */
convert_ret_t
mgmt_convert_conf()
{
	targ_scf_t		*h = NULL;
	xmlTextReaderPtr	r;
	convert_ret_t		ret = CONVERT_FAIL;
	int			xml_fd = -1;
	int			n;
	tgt_node_t		*node = NULL;
	tgt_node_t		*next = NULL;
	char			path[MAXPATHLEN];
	char			*target = NULL;

	h = mgmt_handle_init();
	if (h == NULL)
		return (CONVERT_FAIL);

	/* check main config in pgroup iscsitgt */
	if (scf_service_get_pg(h->t_service, "iscsitgt", h->t_pg) == 0) {
		ret = CONVERT_OK;
		goto done;
	}

	/* check the conf files */
	if (access(config_file, R_OK) != 0) {
		/*
		 * if there is no configuration file, initialize
		 * an empty scf entry
		 */
		if (mgmt_transaction_start(h, "iscsitgt", "basic") == True) {
			ret = CONVERT_INIT_NEW;

			node = tgt_node_alloc(XML_ELEMENT_VERS, String, "1.0");
			new_property(h, node);
			tgt_node_free(node);
			/* "daemonize" is set to true by default */
			node = tgt_node_alloc(XML_ELEMENT_DBGDAEMON, String,
			    "true");
			new_property(h, node);
			tgt_node_free(node);
			node = NULL;
			node = tgt_node_alloc(ISCSI_MODIFY_AUTHNAME, String,
			    ISCSI_AUTH_MODIFY);
			new_property(h, node);
			tgt_node_free(node);
			node = tgt_node_alloc(ISCSI_VALUE_AUTHNAME, String,
			    ISCSI_AUTH_VALUE);
			new_property(h, node);
			tgt_node_free(node);
			(void) mgmt_transaction_end(h);
		} else {
			syslog(LOG_ERR, "Creating empty entry failed");
			ret = CONVERT_FAIL;
			goto done;
		}
		if (mgmt_transaction_start(h, "passwords", "application") ==
		    True) {
			node = tgt_node_alloc(ISCSI_READ_AUTHNAME, String,
			    ISCSI_AUTH_READ);
			new_property(h, node);
			tgt_node_free(node);
			node = tgt_node_alloc(ISCSI_MODIFY_AUTHNAME, String,
			    ISCSI_AUTH_MODIFY);
			new_property(h, node);
			tgt_node_free(node);
			node = tgt_node_alloc(ISCSI_VALUE_AUTHNAME, String,
			    ISCSI_AUTH_VALUE);
			new_property(h, node);
			tgt_node_free(node);
			(void) mgmt_transaction_end(h);
		} else {
			syslog(LOG_ERR, "Creating empty entry failed");
			ret = CONVERT_FAIL;
		}
		goto done;
	}

	if ((xml_fd = open(config_file, O_RDONLY)) >= 0)
		r = (xmlTextReaderPtr)xmlReaderForFd(xml_fd, NULL, NULL, 0);

	if (r != NULL) {
		n = xmlTextReaderRead(r);
		while (n == 1) {
			if (tgt_node_process(r, &node) == False) {
				break;
			}
			n = xmlTextReaderRead(r);
		}
		if (n < 0) {
			syslog(LOG_ERR, "Parsing main config failed");
			ret = CONVERT_FAIL;
			goto done;
		}

		main_config = node;

		(void) tgt_find_value_str(node, XML_ELEMENT_BASEDIR,
		    &target_basedir);

		if (target_basedir == NULL)
			target_basedir = strdup(DEFAULT_TARGET_BASEDIR);

		/* Now convert targets' config if possible */
		if (xml_fd != -1)
			(void) close(xml_fd);
		(void) xmlTextReaderClose(r);
		xmlFreeTextReader(r);
		xmlCleanupParser();
		r = NULL;
		xml_fd = -1;
		node = NULL;

		(void) snprintf(path, MAXPATHLEN, "%s/%s",
		    target_basedir, "config.xml");

		if ((xml_fd = open(path, O_RDONLY)) >= 0)
			r = (xmlTextReaderPtr)xmlReaderForFd(xml_fd,
			    NULL, NULL, 0);

		if (r != NULL) {
			n = xmlTextReaderRead(r);
			while (n == 1) {
				if (tgt_node_process(r, &node) == False) {
					break;
				}
				n = xmlTextReaderRead(r);
			}
			if (n < 0) {
				syslog(LOG_ERR, "Parsing target conf failed");
				ret = CONVERT_FAIL;
				goto done;
			}

			/* now combine main_config and node */
			if (node) {
				next = NULL;
				while ((next = tgt_node_next(node,
				    XML_ELEMENT_TARG, next)) != NULL) {
					tgt_node_add(main_config,
					    tgt_node_dup(next));
				}
				tgt_node_free(node);
			}

			if (mgmt_config_save2scf() != True) {
				syslog(LOG_ERR, "Converting config failed");
				if (xml_fd != -1)
					(void) close(xml_fd);
				(void) xmlTextReaderClose(r);
				xmlFreeTextReader(r);
				xmlCleanupParser();
				ret = CONVERT_FAIL;
				goto done;
			}

			/* Copy files into backup dir */
			(void) snprintf(path, sizeof (path), "%s/backup",
			    target_basedir);
			if ((mkdir(path, 0755) == -1) && (errno != EEXIST)) {
				syslog(LOG_ERR, "Creating backup dir failed");
				ret = CONVERT_FAIL;
				goto done;
			}
			backup(config_file, NULL);
			(void) snprintf(path, MAXPATHLEN, "%s/%s",
			    target_basedir, "config.xml");
			backup(path, NULL);


			while ((next = tgt_node_next(main_config,
			    XML_ELEMENT_TARG, next)) != NULL) {
				if (tgt_find_value_str(next, XML_ELEMENT_INAME,
				    &target) == False) {
					continue;
				}
				(void) snprintf(path, MAXPATHLEN, "%s/%s",
				    target_basedir, target);
				if (mgmt_convert_param(path, next)
				    != True) {
					ret = CONVERT_FAIL;
					goto done;
				}
				free(target);
			}

			ret = CONVERT_OK;
			syslog(LOG_NOTICE, "Conversion succeeded");

			(void) xmlTextReaderClose(r);
			xmlFreeTextReader(r);
			xmlCleanupParser();
		} else {
			syslog(LOG_ERR, "Reading targets config failed");
			ret = CONVERT_FAIL;
			goto done;
		}
	} else {
		syslog(LOG_ERR, "Reading main config failed");
		ret = CONVERT_FAIL;
		goto done;
	}

done:
	if (xml_fd != -1)
		(void) close(xml_fd);
	mgmt_handle_fini(h);
	return (ret);
}

/*
 * backup() moves configuration xml files into backup directory
 * under base-directory. It is called once when converting legacy
 * xml data into scf data.
 * Param files will be renamed as params.<lun#>.<initiatorname>
 */
static void
backup(char *file, char *ext)
{
	char	dest[MAXPATHLEN];
	char	*bname;

	bname = basename(file);
	if (ext) {
		(void) snprintf(dest, sizeof (dest), "%s/backup/%s.%s",
		    target_basedir, bname, ext);
	} else {
		(void) snprintf(dest, sizeof (dest), "%s/backup/%s",
		    target_basedir, bname);
	}

	if (fork() == 0) {
		(void) execl("/bin/mv", "mv", file, dest, (char *)0);
		exit(0);
	}
}

/*
 * check_auth() checks if a given cred has
 * the authorization to create/remove targets/initiators/tpgt
 * cred is from the door call.
 */
Boolean_t
check_auth_addremove(ucred_t *cred)
{
	targ_scf_t *h = NULL;
	Boolean_t ret = False;
	int exit_code = 1;
	uid_t uid;
	gid_t gid;
	pid_t pid;
	const priv_set_t	*eset;

	pid = fork();

	switch (pid) {
	case 0:
		/* Child process to check authorization */
		uid = ucred_geteuid(cred);
		if (seteuid(uid) != 0) {
			syslog(LOG_ERR, "not priviliged\n");
			exit(-1);
		}

		gid = ucred_getegid(cred);
		if (setegid(gid) != 0) {
			syslog(LOG_ERR, "not priviliged\n");
			exit(-1);
		}

		eset = ucred_getprivset(cred, PRIV_EFFECTIVE);
		(void) setppriv(PRIV_ON, PRIV_EFFECTIVE, eset);

		h = mgmt_handle_init();

		if (h == NULL) {
			exit(1);
		}
		if (mgmt_transaction_start(h, "dummy", "dummy") == True) {
			(void) scf_pg_delete(h->t_pg);
			(void) mgmt_transaction_end(h);
			exit_code = 0;
		} else {
			exit_code = 1;
		}
		mgmt_handle_fini(h);
		exit(exit_code);
		break;
	case -1:
		/* Fail to fork */
		exit(SMF_EXIT_ERR_CONFIG);
	default:
		(void) wait(&exit_code);
		exit_code = exit_code >> 8;
		if (exit_code == 0)
			ret = True;
		else
			ret = False;
		break;
	}

	return (ret);
}
/*
 * check_auth_modify() checks if a given cred has
 * the authorization to add/change/remove configuration values.
 * cred is from the door call.
 */
Boolean_t
check_auth_modify(ucred_t *cred)
{
	targ_scf_t *h = NULL;
	Boolean_t ret = False;
	int exit_code = -1;
	uid_t uid;
	gid_t gid;
	pid_t pid;
	tgt_node_t *n = NULL;
	scf_transaction_entry_t *ent = NULL;
	const priv_set_t	*eset;

	pid = fork();

	switch (pid) {
	case 0:
		/* Child process to check authorization */
		uid = ucred_geteuid(cred);
		if (seteuid(uid) != 0) {
			syslog(LOG_ERR, "not priviliged\n");
			exit(-1);
		}

		gid = ucred_getegid(cred);
		if (setegid(gid) != 0) {
			syslog(LOG_ERR, "not priviliged\n");
			exit(-1);
		}

		eset = ucred_getprivset(cred, PRIV_EFFECTIVE);
		(void) setppriv(PRIV_ON, PRIV_EFFECTIVE, eset);

		h = mgmt_handle_init();

		if (h == NULL) {
			exit(-1);
		}
		if (mgmt_transaction_start(h, "iscsitgt", "basic") == True) {
			n = tgt_node_alloc("dummy", String, "dummy");
			new_property(h, n);
			tgt_node_free(n);
			if (mgmt_transaction_end(h) == True) {
				exit_code = 0;
			} else {
				exit_code = -1;
			}
		} else {
			exit_code = -1;
		}
		if (exit_code != 0) {
			mgmt_handle_fini(h);
			exit(exit_code);
		}
		if (mgmt_transaction_start(h, "iscsitgt", "basic") == True) {
			ent = scf_entry_create(h->t_handle);
			if (ent) {
				(void) scf_transaction_property_delete(
				    h->t_trans, ent, "dummy");
			}
		}
		(void) mgmt_transaction_end(h);

		mgmt_handle_fini(h);
		exit(exit_code);
		break;
	case -1:
		/* Fail to fork */
		exit(SMF_EXIT_ERR_CONFIG);
	default:
		(void) wait(&exit_code);
		exit_code = exit_code >> 8;
		if (exit_code == 0)
			ret = True;
		else
			ret = False;
		break;
	}

	return (ret);
}

/*
 * Following two functions replace ':' and '.' in target/initiator
 * names into '__2' and '__1' when write to SMF, and do a reverse
 * replacement when read from SMF.
 * pgname_encode's buffers are allocated by caller.
 * see CR 6626684
 */
#define	SMF_COLON	"__2"
#define	SMF_DOT		"__1"

static void
pgname_encode(char *instr, char *outstr, int max_len)
{
	int i = 0;

	assert(instr != NULL && outstr != NULL);
	for (; *instr != '\0'; instr++) {
		switch (*instr) {
		case ':':
			strcpy(outstr + i, SMF_COLON);
			i += 3;
			break;
		case '.':
			strcpy(outstr + i, SMF_DOT);
			i += 3;
			break;
		default:
			*(outstr + i) = *instr;
			i ++;
			break;
		}
		/* in case of next possible ':' or '.', we cease on len-3 */
		if (i >= max_len - 3)
			break;
	}
	outstr[i] = '\0';
}

/*
 * pgname_decode use original buffer, since it reduces string length
 */
static void
pgname_decode(char *instr)
{
	char *buf;
	char *rec;

	assert(instr != NULL);
	buf = strdup(instr);

	if (buf == NULL)
		return;

	rec = buf;
	for (; *buf != '\0'; buf++) {
		if (*buf == '_') {
			if (memcmp(buf, SMF_COLON, strlen(SMF_COLON)) == 0) {
				*instr = ':';
				buf += 2;
			} else if (memcmp(buf, SMF_DOT, strlen(SMF_DOT)) == 0) {
				*instr = '.';
				buf += 2;
			} else {
				*instr = *buf;
			}
		} else {
			*instr = *buf;
		}
		instr ++;
	}
	*instr = '\0';
	free(rec);
}
