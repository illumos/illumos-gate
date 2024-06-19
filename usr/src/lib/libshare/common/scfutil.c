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
 *
 * Copyright 2023 Oxide Computer Company
 */

/* helper functions for using libscf with sharemgr */

#include <libscf.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include "libshare.h"
#include "libshare_impl.h"
#include "scfutil.h"
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <uuid/uuid.h>
#include <sys/param.h>
#include <signal.h>
#include <sys/time.h>
#include <libintl.h>

ssize_t scf_max_name_len;
extern struct sa_proto_plugin *sap_proto_list;
extern sa_handle_impl_t get_handle_for_root(xmlNodePtr);
static void set_transaction_tstamp(sa_handle_impl_t);
/*
 * The SMF facility uses some properties that must exist. We want to
 * skip over these when processing protocol options.
 */
static char *skip_props[] = {
	"modify_authorization",
	"action_authorization",
	"value_authorization",
	NULL
};

/*
 * sa_scf_fini(handle)
 *
 * Must be called when done. Called with the handle allocated in
 * sa_scf_init(), it cleans up the state and frees any SCF resources
 * still in use. Called by sa_fini().
 */

void
sa_scf_fini(scfutilhandle_t *handle)
{
	if (handle != NULL) {
		int unbind = 0;
		if (handle->scope != NULL) {
			unbind = 1;
			scf_scope_destroy(handle->scope);
		}
		if (handle->instance != NULL)
			scf_instance_destroy(handle->instance);
		if (handle->service != NULL)
			scf_service_destroy(handle->service);
		if (handle->pg != NULL)
			scf_pg_destroy(handle->pg);
		if (handle->handle != NULL) {
			handle->scf_state = SCH_STATE_UNINIT;
			if (unbind)
				(void) scf_handle_unbind(handle->handle);
			scf_handle_destroy(handle->handle);
		}
		free(handle);
	}
}

/*
 * sa_scf_init()
 *
 * Must be called before using any of the SCF functions. Called by
 * sa_init() during the API setup.
 */

scfutilhandle_t *
sa_scf_init(sa_handle_impl_t ihandle)
{
	scfutilhandle_t *handle;

	scf_max_name_len = scf_limit(SCF_LIMIT_MAX_NAME_LENGTH);
	if (scf_max_name_len <= 0)
		scf_max_name_len = SA_MAX_NAME_LEN + 1;

	handle = calloc(1, sizeof (scfutilhandle_t));
	if (handle == NULL)
		return (handle);

	ihandle->scfhandle = handle;
	handle->scf_state = SCH_STATE_INITIALIZING;
	handle->handle = scf_handle_create(SCF_VERSION);
	if (handle->handle == NULL) {
		free(handle);
		handle = NULL;
		(void) printf("libshare could not access SMF repository: %s\n",
		    scf_strerror(scf_error()));
		return (handle);
	}
	if (scf_handle_bind(handle->handle) != 0)
		goto err;

	handle->scope = scf_scope_create(handle->handle);
	handle->service = scf_service_create(handle->handle);
	handle->pg = scf_pg_create(handle->handle);

	/* Make sure we have sufficient SMF running */
	handle->instance = scf_instance_create(handle->handle);
	if (handle->scope == NULL || handle->service == NULL ||
	    handle->pg == NULL || handle->instance == NULL)
		goto err;
	if (scf_handle_get_scope(handle->handle,
	    SCF_SCOPE_LOCAL, handle->scope) != 0)
		goto err;
	if (scf_scope_get_service(handle->scope,
	    SA_GROUP_SVC_NAME, handle->service) != 0)
		goto err;

	handle->scf_state = SCH_STATE_INIT;
	if (sa_get_instance(handle, "default") != SA_OK) {
		sa_group_t defgrp;
		defgrp = sa_create_group((sa_handle_t)ihandle, "default", NULL);
		/* Only NFS enabled for "default" group. */
		if (defgrp != NULL)
			(void) sa_create_optionset(defgrp, "nfs");
	}

	return (handle);

	/* Error handling/unwinding */
err:
	(void) sa_scf_fini(handle);
	if (scf_error() != SCF_ERROR_NOT_FOUND) {
		(void) printf("libshare SMF initialization problem: %s\n",
		    scf_strerror(scf_error()));
	}
	return (NULL);
}

/*
 * get_scf_limit(name)
 *
 * Since we use  scf_limit a lot and do the same  check and return the
 * same  value  if  it  fails,   implement  as  a  function  for  code
 * simplification.  Basically, if  name isn't found, return MAXPATHLEN
 * (1024) so we have a reasonable default buffer size.
 */
static ssize_t
get_scf_limit(uint32_t name)
{
	ssize_t vallen;

	vallen = scf_limit(name);
	if (vallen == (ssize_t)-1)
		vallen = MAXPATHLEN;
	return (vallen);
}

/*
 * skip_property(name)
 *
 * Internal function to check to see if a property is an SMF magic
 * property that needs to be skipped.
 */
static int
skip_property(char *name)
{
	int i;

	for (i = 0; skip_props[i] != NULL; i++)
		if (strcmp(name, skip_props[i]) == 0)
			return (1);
	return (0);
}

/*
 * generate_unique_sharename(sharename)
 *
 * Shares are represented in SMF as property groups. Due to share
 * paths containing characters that are not allowed in SMF names and
 * the need to be unique, we use UUIDs to construct a unique name.
 */

static void
generate_unique_sharename(char *sharename)
{
	uuid_t uuid;

	uuid_generate(uuid);
	(void) strcpy(sharename, "S-");
	uuid_unparse(uuid, sharename + 2);
}

/*
 * valid_protocol(proto)
 *
 * Check to see if the specified protocol is a valid one for the
 * general sharemgr facility. We determine this by checking which
 * plugin protocols were found.
 */

static int
valid_protocol(char *proto)
{
	struct sa_proto_plugin *plugin;
	for (plugin = sap_proto_list; plugin != NULL;
	    plugin = plugin->plugin_next)
		if (strcmp(proto, plugin->plugin_ops->sa_protocol) == 0)
			return (1);
	return (0);
}

/*
 * sa_extract_pgroup(root, handle, pg, nodetype, proto, sectype)
 *
 * Extract the name property group and create the specified type of
 * node on the provided group.  type will be optionset or security.
 */

static int
sa_extract_pgroup(xmlNodePtr root, scfutilhandle_t *handle,
    scf_propertygroup_t *pg, char *nodetype, char *proto, char *sectype)
{
	xmlNodePtr node;
	scf_iter_t *iter;
	scf_property_t *prop;
	scf_value_t *value;
	char *name;
	char *valuestr;
	ssize_t vallen;
	int ret = SA_OK;

	vallen = get_scf_limit(SCF_LIMIT_MAX_VALUE_LENGTH);

	node = xmlNewChild(root, NULL, (xmlChar *)nodetype, NULL);
	if (node == NULL)
		return (ret);

	if (proto != NULL)
		(void) xmlSetProp(node, (xmlChar *)"type", (xmlChar *)proto);
	if (sectype != NULL)
		(void) xmlSetProp(node, (xmlChar *)"sectype",
		    (xmlChar *)sectype);
	/*
	 * Have node to work with so iterate over the properties
	 * in the pg and create option sub nodes.
	 */
	iter = scf_iter_create(handle->handle);
	value = scf_value_create(handle->handle);
	prop = scf_property_create(handle->handle);
	name = malloc(scf_max_name_len);
	valuestr = malloc(vallen);
	/*
	 * Want to iterate through the properties and add them
	 * to the base optionset.
	 */
	if (iter == NULL || value == NULL || prop == NULL ||
	    valuestr == NULL || name == NULL) {
		ret = SA_NO_MEMORY;
		goto out;
	}
	if (scf_iter_pg_properties(iter, pg) == 0) {
		/* Now iterate the properties in the group */
		while (scf_iter_next_property(iter, prop) > 0) {
			/* have a property */
			if (scf_property_get_name(prop, name,
			    scf_max_name_len) > 0) {
				sa_property_t saprop;
				/* Some properties are part of the framework */
				if (skip_property(name))
					continue;
				if (scf_property_get_value(prop, value) != 0)
					continue;
				if (scf_value_get_astring(value, valuestr,
				    vallen) < 0)
					continue;
				saprop = sa_create_property(name, valuestr);
				if (saprop != NULL) {
					/*
					 * Since in SMF, don't
					 * recurse. Use xmlAddChild
					 * directly, instead.
					 */
					(void) xmlAddChild(node,
					    (xmlNodePtr) saprop);
				}
			}
		}
	}
out:
	/* cleanup to avoid memory leaks */
	if (value != NULL)
		scf_value_destroy(value);
	if (iter != NULL)
		scf_iter_destroy(iter);
	if (prop != NULL)
		scf_property_destroy(prop);
	if (name != NULL)
		free(name);
	if (valuestr != NULL)
		free(valuestr);

	return (ret);
}

/*
 * sa_extract_attrs(root, handle, instance)
 *
 * Local function to extract the actual attributes/properties from the
 * property group of the service instance. These are the well known
 * attributes of "state" and "zfs". If additional attributes are
 * added, they should be added here.
 */

static void
sa_extract_attrs(xmlNodePtr root, scfutilhandle_t *handle,
    scf_instance_t *instance)
{
	scf_property_t *prop;
	scf_value_t *value;
	char *valuestr;
	ssize_t vallen;

	vallen = get_scf_limit(SCF_LIMIT_MAX_VALUE_LENGTH);
	prop = scf_property_create(handle->handle);
	value = scf_value_create(handle->handle);
	valuestr = malloc(vallen);
	if (prop == NULL || value == NULL || valuestr == NULL ||
	    scf_instance_get_pg(instance, "operation", handle->pg) != 0) {
		goto out;
	}
	/*
	 * Have a property group with desired name so now get
	 * the known attributes.
	 */
	if (scf_pg_get_property(handle->pg, "state", prop) == 0) {
		/* Found the property so get the value */
		if (scf_property_get_value(prop, value) == 0) {
			if (scf_value_get_astring(value, valuestr,
			    vallen) >= 0) {
				(void) xmlSetProp(root, (xmlChar *)"state",
				    (xmlChar *)valuestr);
			}
		}
	}
	if (scf_pg_get_property(handle->pg, "zfs", prop) == 0) {
		/* Found the property so get the value */
		if (scf_property_get_value(prop, value) == 0) {
			if (scf_value_get_astring(value, valuestr,
			    vallen) > 0) {
				(void) xmlSetProp(root, (xmlChar *)"zfs",
				    (xmlChar *)valuestr);
			}
		}
	}
out:
	if (valuestr != NULL)
		free(valuestr);
	if (value != NULL)
		scf_value_destroy(value);
	if (prop != NULL)
		scf_property_destroy(prop);
}

/*
 * List of known share attributes.
 */

static char *share_attr[] = {
	"path",
	"id",
	"drive-letter",
	"exclude",
	NULL,
};

static int
is_share_attr(char *name)
{
	int i;
	for (i = 0; share_attr[i] != NULL; i++)
		if (strcmp(name, share_attr[i]) == 0)
			return (1);
	return (0);
}

/*
 * _sa_make_resource(node, valuestr)
 *
 * Make a resource node on the share node. The valusestr will either
 * be old format (SMF acceptable string) or new format (pretty much an
 * arbitrary string with "nnn:" prefixing in order to persist
 * mapping). The input valuestr will get modified in place. This is
 * only used in SMF repository parsing. A possible third field will be
 * a "description" string.
 */

static void
_sa_make_resource(xmlNodePtr node, char *valuestr)
{
	char *idx;
	char *name;
	char *description = NULL;

	idx = valuestr;
	name = strchr(valuestr, ':');
	if (name == NULL) {
		/* this is old form so give an index of "0" */
		idx = "0";
		name = valuestr;
	} else {
		/* NUL the ':' and move past it */
		*name++ = '\0';
		/* There could also be a description string */
		description = strchr(name, ':');
		if (description != NULL)
			*description++ = '\0';
	}
	node = xmlNewChild(node, NULL, (xmlChar *)"resource", NULL);
	if (node != NULL) {
		(void) xmlSetProp(node, (xmlChar *)"name", (xmlChar *)name);
		(void) xmlSetProp(node, (xmlChar *)"id", (xmlChar *)idx);
		/* SMF values are always persistent */
		(void) xmlSetProp(node, (xmlChar *)"type",
		    (xmlChar *)"persist");
		if (description != NULL && strlen(description) > 0) {
			(void) xmlNewChild(node, NULL, (xmlChar *)"description",
			    (xmlChar *)description);
		}
	}
}


/*
 * sa_share_from_pgroup
 *
 * Extract the share definition from the share property group. We do
 * some sanity checking to avoid bad data.
 *
 * Since this is only constructing the internal data structures, we
 * don't use the sa_* functions most of the time.
 */
void
sa_share_from_pgroup(xmlNodePtr root, scfutilhandle_t *handle,
    scf_propertygroup_t *pg, char *id)
{
	xmlNodePtr node;
	char *name;
	scf_iter_t *iter;
	scf_property_t *prop;
	scf_value_t *value;
	ssize_t vallen;
	char *valuestr;
	int ret = SA_OK;
	int have_path = 0;

	/*
	 * While preliminary check (starts with 'S') passed before
	 * getting here. Need to make sure it is in ID syntax
	 * (Snnnnnn). Note that shares with properties have similar
	 * pgroups.
	 */
	vallen = strlen(id);
	if (*id == SA_SHARE_PG_PREFIX[0] && vallen == SA_SHARE_PG_LEN) {
		uuid_t uuid;
		if (strncmp(id, SA_SHARE_PG_PREFIX,
		    SA_SHARE_PG_PREFIXLEN) != 0 ||
		    uuid_parse(id + 2, uuid) < 0)
			return;
	} else {
		return;
	}

	vallen = get_scf_limit(SCF_LIMIT_MAX_VALUE_LENGTH);

	iter = scf_iter_create(handle->handle);
	value = scf_value_create(handle->handle);
	prop = scf_property_create(handle->handle);
	name = malloc(scf_max_name_len);
	valuestr = malloc(vallen);

	/*
	 * Construct the share XML node. It is similar to sa_add_share
	 * but never changes the repository. Also, there won't be any
	 * ZFS or transient shares.  Root will be the group it is
	 * associated with.
	 */
	node = xmlNewChild(root, NULL, (xmlChar *)"share", NULL);
	if (node != NULL) {
		/*
		 * Make sure the UUID part of the property group is
		 * stored in the share "id" property. We use this
		 * later.
		 */
		(void) xmlSetProp(node, (xmlChar *)"id", (xmlChar *)id);
		(void) xmlSetProp(node, (xmlChar *)"type",
		    (xmlChar *)"persist");
	}

	if (iter == NULL || value == NULL || prop == NULL || name == NULL)
		goto out;

	/* Iterate over the share pg properties */
	if (scf_iter_pg_properties(iter, pg) != 0)
		goto out;

	while (scf_iter_next_property(iter, prop) > 0) {
		ret = SA_SYSTEM_ERR; /* assume the worst */
		if (scf_property_get_name(prop, name, scf_max_name_len) > 0) {
			if (scf_property_get_value(prop, value) == 0) {
				if (scf_value_get_astring(value, valuestr,
				    vallen) >= 0) {
					ret = SA_OK;
				}
			} else if (strcmp(name, "resource") == 0) {
				ret = SA_OK;
			}
		}
		if (ret != SA_OK)
			continue;
		/*
		 * Check that we have the "path" property in
		 * name. The string in name will always be nul
		 * terminated if scf_property_get_name()
		 * succeeded.
		 */
		if (strcmp(name, "path") == 0)
			have_path = 1;
		if (is_share_attr(name)) {
			/*
			 * If a share attr, then simple -
			 * usually path and id name
			 */
			(void) xmlSetProp(node, (xmlChar *)name,
			    (xmlChar *)valuestr);
		} else if (strcmp(name, "resource") == 0) {
			/*
			 * Resource names handled differently since
			 * there can be multiple on each share. The
			 * "resource" id must be preserved since this
			 * will be used by some protocols in mapping
			 * "property spaces" to names and is always
			 * used to create SMF property groups specific
			 * to resources.  CIFS needs this.  The first
			 * value is present so add and then loop for
			 * any additional. Since this is new and
			 * previous values may exist, handle
			 * conversions.
			 */
			scf_iter_t *viter;
			viter = scf_iter_create(handle->handle);
			if (viter != NULL &&
			    scf_iter_property_values(viter, prop) == 0) {
				while (scf_iter_next_value(viter, value) > 0) {
					/* Have a value so process it */
					if (scf_value_get_ustring(value,
					    valuestr, vallen) >= 0) {
						/* have a ustring */
						_sa_make_resource(node,
						    valuestr);
					} else if (scf_value_get_astring(value,
					    valuestr, vallen) >= 0) {
						/* have an astring */
						_sa_make_resource(node,
						    valuestr);
					}
				}
				scf_iter_destroy(viter);
			}
		} else {
			if (strcmp(name, "description") == 0) {
				/* We have a description node */
				xmlNodePtr desc;
				desc = xmlNewChild(node, NULL,
				    (xmlChar *)"description", NULL);
				if (desc != NULL)
					(void) xmlNodeSetContent(desc,
					    (xmlChar *)valuestr);
			}
		}
	}
out:
	/*
	 * A share without a path is broken so we want to not include
	 * these.  They shouldn't happen but if you kill a sharemgr in
	 * the process of creating a share, it could happen.  They
	 * should be harmless.  It is also possible that another
	 * sharemgr is running and in the process of creating a share.
	 */
	if (have_path == 0 && node != NULL) {
		xmlUnlinkNode(node);
		xmlFreeNode(node);
	}
	if (name != NULL)
		free(name);
	if (valuestr != NULL)
		free(valuestr);
	if (value != NULL)
		scf_value_destroy(value);
	if (iter != NULL)
		scf_iter_destroy(iter);
	if (prop != NULL)
		scf_property_destroy(prop);
}

/*
 * find_share_by_id(shareid)
 *
 * Search all shares in all groups until we find the share represented
 * by "id".
 */

static sa_share_t
find_share_by_id(sa_handle_t handle, char *shareid)
{
	sa_group_t group;
	sa_share_t share = NULL;
	char *id = NULL;
	int done = 0;

	for (group = sa_get_group(handle, NULL);
	    group != NULL && !done;
	    group = sa_get_next_group(group)) {
		for (share = sa_get_share(group, NULL);
		    share != NULL;
		    share = sa_get_next_share(share)) {
			id = sa_get_share_attr(share, "id");
			if (id != NULL && strcmp(id, shareid) == 0) {
				sa_free_attr_string(id);
				id = NULL;
				done++;
				break;
			}
			if (id != NULL) {
				sa_free_attr_string(id);
				id = NULL;
			}
		}
	}
	return (share);
}

/*
 * find_resource_by_index(share, index)
 *
 * Search the resource records on the share for the id index.
 */
static sa_resource_t
find_resource_by_index(sa_share_t share, char *index)
{
	sa_resource_t resource;
	sa_resource_t found = NULL;
	char *id;

	for (resource = sa_get_share_resource(share, NULL);
	    resource != NULL && found == NULL;
	    resource = sa_get_next_resource(resource)) {
		id = (char *)xmlGetProp((xmlNodePtr)resource, (xmlChar *)"id");
		if (id != NULL) {
			if (strcmp(id, index) == 0) {
				/* found it so save in "found" */
				found = resource;
			}
			sa_free_attr_string(id);
		}
	}
	return (found);
}

/*
 * sa_share_props_from_pgroup(root, handle, pg, id, sahandle)
 *
 * Extract share properties from the SMF property group. More sanity
 * checks are done and the share object is created. We ignore some
 * errors that could exist in the repository and only worry about
 * property groups that validate in naming.
 */

static int
sa_share_props_from_pgroup(xmlNodePtr root, scfutilhandle_t *handle,
    scf_propertygroup_t *pg, char *id, sa_handle_t sahandle)
{
	xmlNodePtr node;
	char *name = NULL;
	scf_iter_t *iter = NULL;
	scf_property_t *prop = NULL;
	scf_value_t *value = NULL;
	ssize_t vallen;
	char *valuestr = NULL;
	int ret = SA_OK;
	char *sectype = NULL;
	char *proto = NULL;
	sa_share_t share;
	uuid_t uuid;

	/*
	 * While preliminary check (starts with 'S') passed before
	 * getting here. Need to make sure it is in ID syntax
	 * (Snnnnnn). Note that shares with properties have similar
	 * pgroups. If the pg name is more than SA_SHARE_PG_LEN
	 * characters, it is likely one of the protocol/security
	 * versions.
	 */
	vallen = strlen(id);
	if (*id != SA_SHARE_PG_PREFIX[0] || vallen <= SA_SHARE_PG_LEN) {
		/*
		 * It is ok to not have what we thought since someone might
		 * have added a name via SMF.
		 */
		return (ret);
	}
	if (strncmp(id, SA_SHARE_PG_PREFIX, SA_SHARE_PG_PREFIXLEN) == 0) {
		proto = strchr(id, '_');
		if (proto == NULL)
			return (ret);
		*proto++ = '\0';
		if (uuid_parse(id + SA_SHARE_PG_PREFIXLEN, uuid) < 0)
			return (ret);
		/*
		 * probably a legal optionset so check a few more
		 * syntax points below.
		 */
		if (*proto == '\0') {
			/* not a valid proto (null) */
			return (ret);
		}

		sectype = strchr(proto, '_');
		if (sectype != NULL)
			*sectype++ = '\0';
		if (!valid_protocol(proto))
			return (ret);
	}

	/*
	 * To get here, we have a valid protocol and possibly a
	 * security. We now have to find the share that it is really
	 * associated with. The "id" portion of the pgroup name will
	 * match.
	 */

	share = find_share_by_id(sahandle, id);
	if (share == NULL)
		return (SA_BAD_PATH);

	root = (xmlNodePtr)share;

	vallen = get_scf_limit(SCF_LIMIT_MAX_VALUE_LENGTH);

	if (sectype == NULL)
		node = xmlNewChild(root, NULL, (xmlChar *)"optionset", NULL);
	else {
		if (isdigit((int)*sectype)) {
			sa_resource_t resource;
			/*
			 * If sectype[0] is a digit, then it is an index into
			 * the resource names. We need to find a resource
			 * record and then get the properties into an
			 * optionset. The optionset becomes the "node" and the
			 * rest is hung off of the share.
			 */
			resource = find_resource_by_index(share, sectype);
			if (resource != NULL) {
				node = xmlNewChild(resource, NULL,
				    (xmlChar *)"optionset", NULL);
			} else {
				/* This shouldn't happen. */
				ret = SA_SYSTEM_ERR;
				goto out;
			}
		} else {
			/*
			 * If not a digit, then it is a security type
			 * (alternate option space). Security types start with
			 * an alphabetic.
			 */
			node = xmlNewChild(root, NULL, (xmlChar *)"security",
			    NULL);
			if (node != NULL)
				(void) xmlSetProp(node, (xmlChar *)"sectype",
				    (xmlChar *)sectype);
		}
	}
	if (node == NULL) {
		ret = SA_NO_MEMORY;
		goto out;
	}

	(void) xmlSetProp(node, (xmlChar *)"type", (xmlChar *)proto);
	/* now find the properties */
	iter = scf_iter_create(handle->handle);
	value = scf_value_create(handle->handle);
	prop = scf_property_create(handle->handle);
	name = malloc(scf_max_name_len);
	valuestr = malloc(vallen);

	if (iter == NULL || value == NULL || prop == NULL || name == NULL)
		goto out;

	/* iterate over the share pg properties */
	if (scf_iter_pg_properties(iter, pg) == 0) {
		while (scf_iter_next_property(iter, prop) > 0) {
			ret = SA_SYSTEM_ERR; /* assume the worst */
			if (scf_property_get_name(prop, name,
			    scf_max_name_len) > 0) {
				if (scf_property_get_value(prop, value) == 0) {
					if (scf_value_get_astring(value,
					    valuestr, vallen) >= 0) {
						ret = SA_OK;
					}
				}
			} else {
				ret = SA_SYSTEM_ERR;
			}
			if (ret == SA_OK) {
				sa_property_t prop;
				prop = sa_create_property(name, valuestr);
				if (prop != NULL)
					prop = (sa_property_t)xmlAddChild(node,
					    (xmlNodePtr)prop);
				else
					ret = SA_NO_MEMORY;
			}
		}
	} else {
		ret = SA_SYSTEM_ERR;
	}
out:
	if (iter != NULL)
		scf_iter_destroy(iter);
	if (value != NULL)
		scf_value_destroy(value);
	if (prop != NULL)
		scf_property_destroy(prop);
	if (name != NULL)
		free(name);
	if (valuestr != NULL)
		free(valuestr);
	return (ret);
}

/*
 * sa_extract_group(root, handle, instance)
 *
 * Get the config info for this instance of a group and create the XML
 * subtree from it.
 */

static int
sa_extract_group(xmlNodePtr root, scfutilhandle_t *handle,
    scf_instance_t *instance, sa_handle_t sahandle)
{
	char *buff;
	xmlNodePtr node;
	scf_iter_t *iter;
	char *proto;
	char *sectype;
	boolean_t have_shares = B_FALSE;
	boolean_t is_default = B_FALSE;
	boolean_t is_nfs = B_FALSE;
	int ret = SA_OK;
	int err;

	buff = malloc(scf_max_name_len);
	if (buff == NULL)
		return (SA_NO_MEMORY);

	iter = scf_iter_create(handle->handle);
	if (iter == NULL) {
		ret = SA_NO_MEMORY;
		goto out;
	}

	if (scf_instance_get_name(instance, buff, scf_max_name_len) > 0) {
		node = xmlNewChild(root, NULL, (xmlChar *)"group", NULL);
		if (node == NULL) {
			ret = SA_NO_MEMORY;
			goto out;
		}
		(void) xmlSetProp(node, (xmlChar *)"name", (xmlChar *)buff);
		if (strcmp(buff, "default") == 0)
			is_default = B_TRUE;

		sa_extract_attrs(node, handle, instance);
		/*
		 * Iterate through all the property groups
		 * looking for those with security or
		 * optionset prefixes. The names of the
		 * matching pgroups are parsed to get the
		 * protocol, and for security, the sectype.
		 * Syntax is as follows:
		 *    optionset | optionset_<proto>
		 *    security_default | security_<proto>_<sectype>
		 * "operation" is handled by
		 * sa_extract_attrs().
		 */
		if (scf_iter_instance_pgs(iter, instance) != 0) {
			ret = SA_NO_MEMORY;
			goto out;
		}
		while (scf_iter_next_pg(iter, handle->pg) > 0) {
			/* Have a pgroup so sort it out */
			ret = scf_pg_get_name(handle->pg, buff,
			    scf_max_name_len);
			if (ret <= 0)
				continue;
			is_nfs = B_FALSE;

			if (buff[0] == SA_SHARE_PG_PREFIX[0]) {
				sa_share_from_pgroup(node, handle,
				    handle->pg, buff);
				have_shares = B_TRUE;
			} else if (strncmp(buff, "optionset", 9) == 0) {
				char *nodetype = "optionset";
				/* Have an optionset */
				sectype = NULL;
				proto = strchr(buff, '_');
				if (proto != NULL) {
					*proto++ = '\0';
					sectype = strchr(proto, '_');
					if (sectype != NULL) {
						*sectype++ = '\0';
						nodetype = "security";
					}
					is_nfs = strcmp(proto, "nfs") == 0;
				} else if (strlen(buff) > 9) {
					/*
					 * This can only occur if
					 * someone has made changes
					 * via an SMF command. Since
					 * this would be an unknown
					 * syntax, we just ignore it.
					 */
					continue;
				}
				/*
				 * If the group is not "default" or is
				 * "default" and is_nfs, then extract the
				 * pgroup.  If it is_default and !is_nfs,
				 * then we have an error and should remove
				 * the extraneous protocols.  We don't care
				 * about errors on scf_pg_delete since we
				 * might not have permission during an
				 * extract only.
				 */
				if (!is_default || is_nfs) {
					ret = sa_extract_pgroup(node, handle,
					    handle->pg, nodetype, proto,
					    sectype);
				} else {
					err = scf_pg_delete(handle->pg);
					if (err == 0)
						(void) fprintf(stderr,
						    dgettext(TEXT_DOMAIN,
						    "Removed protocol \"%s\" "
						    "from group \"default\"\n"),
						    proto);
				}
			} else if (strncmp(buff, "security", 8) == 0) {
				/*
				 * Have a security (note that
				 * this should change in the
				 * future)
				 */
				proto = strchr(buff, '_');
				sectype = NULL;
				if (proto != NULL) {
					*proto++ = '\0';
					sectype = strchr(proto, '_');
					if (sectype != NULL)
						*sectype++ = '\0';
					if (strcmp(proto, "default") == 0)
						proto = NULL;
				}
				ret = sa_extract_pgroup(node, handle,
				    handle->pg, "security", proto, sectype);
			}
			/* Ignore everything else */
		}
		/*
		 * Make sure we have a valid default group.
		 * On first boot, default won't have any
		 * protocols defined and won't be enabled (but
		 * should be).  "default" only has NFS enabled on it.
		 */
		if (is_default) {
			char *state = sa_get_group_attr((sa_group_t)node,
			    "state");

			if (state == NULL) {
				/* set attribute to enabled */
				(void) sa_set_group_attr((sa_group_t)node,
				    "state", "enabled");
				(void) sa_create_optionset((sa_group_t)node,
				    "nfs");
			} else {
				sa_free_attr_string(state);
			}
		}
		/* Do a second pass if shares were found */
		if (have_shares && scf_iter_instance_pgs(iter, instance) == 0) {
			while (scf_iter_next_pg(iter, handle->pg) > 0) {
				/*
				 * Have a pgroup so see if it is a
				 * share optionset
				 */
				err = scf_pg_get_name(handle->pg, buff,
				    scf_max_name_len);
				if (err  <= 0)
					continue;
				if (buff[0] == SA_SHARE_PG_PREFIX[0]) {
					ret = sa_share_props_from_pgroup(node,
					    handle, handle->pg, buff,
					    sahandle);
				}
			}
		}
	}
out:
	if (iter != NULL)
		scf_iter_destroy(iter);
	if (buff != NULL)
		free(buff);
	return (ret);
}

/*
 * sa_extract_defaults(root, handle, instance)
 *
 * Local function to find the default properties that live in the
 * default instance's "operation" property group.
 */

static void
sa_extract_defaults(xmlNodePtr root, scfutilhandle_t *handle,
    scf_instance_t *instance)
{
	xmlNodePtr node;
	scf_property_t *prop;
	scf_value_t *value;
	char *valuestr;
	ssize_t vallen;

	vallen = get_scf_limit(SCF_LIMIT_MAX_VALUE_LENGTH);
	prop = scf_property_create(handle->handle);
	value = scf_value_create(handle->handle);
	valuestr = malloc(vallen);

	if (prop == NULL || value == NULL || vallen == 0 ||
	    scf_instance_get_pg(instance, "operation", handle->pg) != 0)
		goto out;

	if (scf_pg_get_property(handle->pg, "legacy-timestamp", prop) != 0)
		goto out;

	/* Found the property so get the value */
	if (scf_property_get_value(prop, value) == 0) {
		if (scf_value_get_astring(value, valuestr, vallen) > 0) {
			node = xmlNewChild(root, NULL, (xmlChar *)"legacy",
			    NULL);
			if (node != NULL) {
				(void) xmlSetProp(node, (xmlChar *)"timestamp",
				    (xmlChar *)valuestr);
				(void) xmlSetProp(node, (xmlChar *)"path",
				    (xmlChar *)SA_LEGACY_DFSTAB);
			}
		}
	}
out:
	if (valuestr != NULL)
		free(valuestr);
	if (value != NULL)
		scf_value_destroy(value);
	if (prop != NULL)
		scf_property_destroy(prop);
}


/*
 * sa_get_config(handle, root, doc, sahandle)
 *
 * Walk the SMF repository for /network/shares/group and find all the
 * instances. These become group names.  Then add the XML structure
 * below the groups based on property groups and properties.
 */
int
sa_get_config(scfutilhandle_t *handle, xmlNodePtr root, sa_handle_t sahandle)
{
	int ret = SA_OK;
	scf_instance_t *instance;
	scf_iter_t *iter;
	char buff[BUFSIZ * 2];

	instance = scf_instance_create(handle->handle);
	iter = scf_iter_create(handle->handle);
	if (instance != NULL && iter != NULL) {
		if ((ret = scf_iter_service_instances(iter,
		    handle->service)) == 0) {
			while ((ret = scf_iter_next_instance(iter,
			    instance)) > 0) {
				if (scf_instance_get_name(instance, buff,
				    sizeof (buff)) > 0) {
					if (strcmp(buff, "default") == 0)
						sa_extract_defaults(root,
						    handle, instance);
					ret = sa_extract_group(root, handle,
					    instance, sahandle);
				}
			}
		}
	}

	/* Always cleanup these */
	if (instance != NULL)
		scf_instance_destroy(instance);
	if (iter != NULL)
		scf_iter_destroy(iter);
	return (ret);
}

/*
 * sa_get_instance(handle, instance)
 *
 * Get the instance of the group service. This is actually the
 * specific group name. The instance is needed for all property and
 * control operations.
 */

int
sa_get_instance(scfutilhandle_t *handle, char *instname)
{
	if (scf_service_get_instance(handle->service, instname,
	    handle->instance) != 0) {
		return (SA_NO_SUCH_GROUP);
	}
	return (SA_OK);
}

/*
 * sa_create_instance(handle, instname)
 *
 * Create a new SMF service instance. There can only be one with a
 * given name.
 */

int
sa_create_instance(scfutilhandle_t *handle, char *instname)
{
	int ret = SA_OK;
	char instance[SA_GROUP_INST_LEN];
	if (scf_service_add_instance(handle->service, instname,
	    handle->instance) != 0) {
	/* better error returns need to be added based on real error */
		if (scf_error() == SCF_ERROR_PERMISSION_DENIED)
			ret = SA_NO_PERMISSION;
		else
			ret = SA_DUPLICATE_NAME;
	} else {
		/* have the service created, so enable it */
		(void) snprintf(instance, sizeof (instance), "%s:%s",
		    SA_SVC_FMRI_BASE, instname);
		(void) smf_enable_instance(instance, 0);
	}
	return (ret);
}

/*
 * sa_delete_instance(handle, instname)
 *
 * When a group goes away, we also remove the service instance.
 */

int
sa_delete_instance(scfutilhandle_t *handle, char *instname)
{
	int ret;

	if (strcmp(instname, "default") == 0) {
		ret = SA_NO_PERMISSION;
	} else {
		if ((ret = sa_get_instance(handle, instname)) == SA_OK) {
			if (scf_instance_delete(handle->instance) != 0)
				/* need better analysis */
				ret = SA_NO_PERMISSION;
		}
	}
	return (ret);
}

/*
 * sa_create_pgroup(handle, pgroup)
 *
 * create a new property group
 */

int
sa_create_pgroup(scfutilhandle_t *handle, char *pgroup)
{
	int ret = SA_OK;
	int persist = 0;

	/*
	 * Only create a handle if it doesn't exist. It is ok to exist
	 * since the pg handle will be set as a side effect.
	 */
	if (handle->pg == NULL)
		handle->pg = scf_pg_create(handle->handle);

	/*
	 * Special case for a non-persistent property group. This is
	 * internal use only.
	 */
	if (*pgroup == '*') {
		persist = SCF_PG_FLAG_NONPERSISTENT;
		pgroup++;
	}

	/*
	 * If the pgroup exists, we are done. If it doesn't, then we
	 * need to actually add one to the service instance.
	 */
	if (scf_instance_get_pg(handle->instance,
	    pgroup, handle->pg) != 0) {

		/* Doesn't exist so create one */
		if (scf_instance_add_pg(handle->instance, pgroup,
		    SCF_GROUP_APPLICATION, persist, handle->pg) != 0) {
			switch (scf_error()) {
			case SCF_ERROR_PERMISSION_DENIED:
				ret = SA_NO_PERMISSION;
				break;
			default:
				ret = SA_SYSTEM_ERR;
				break;
			}
		}
	}
	return (ret);
}

/*
 * sa_delete_pgroup(handle, pgroup)
 *
 * Remove the property group from the current instance of the service,
 * but only if it actually exists.
 */

int
sa_delete_pgroup(scfutilhandle_t *handle, char *pgroup)
{
	int ret = SA_OK;
	/*
	 * Only delete if it does exist.
	 */
	if (scf_instance_get_pg(handle->instance, pgroup, handle->pg) == 0) {
		/* does exist so delete it */
		if (scf_pg_delete(handle->pg) != 0)
			ret = SA_SYSTEM_ERR;
	} else {
		ret = SA_SYSTEM_ERR;
	}
	if (ret == SA_SYSTEM_ERR &&
	    scf_error() == SCF_ERROR_PERMISSION_DENIED) {
		ret = SA_NO_PERMISSION;
	}
	return (ret);
}

/*
 * sa_start_transaction(handle, pgroup)
 *
 * Start an SMF transaction so we can deal with properties. it would
 * be nice to not have to expose this, but we have to in order to
 * optimize.
 *
 * Basic model is to hold the transaction in the handle and allow
 * property adds/deletes/updates to be added then close the
 * transaction (or abort).  There may eventually be a need to handle
 * other types of transaction mechanisms but we don't do that now.
 *
 * An sa_start_transaction must be followed by either an
 * sa_end_transaction or sa_abort_transaction before another
 * sa_start_transaction can be done.
 */

int
sa_start_transaction(scfutilhandle_t *handle, char *propgroup)
{
	int ret = SA_OK;
	/*
	 * Lookup the property group and create it if it doesn't already
	 * exist.
	 */
	if (handle == NULL)
		return (SA_CONFIG_ERR);

	if (handle->scf_state == SCH_STATE_INIT) {
		ret = sa_create_pgroup(handle, propgroup);
		if (ret == SA_OK) {
			handle->trans = scf_transaction_create(handle->handle);
			if (handle->trans != NULL) {
				if (scf_transaction_start(handle->trans,
				    handle->pg) != 0) {
					ret = SA_SYSTEM_ERR;
				}
				if (ret != SA_OK) {
					scf_transaction_destroy(handle->trans);
					handle->trans = NULL;
				}
			} else {
				ret = SA_SYSTEM_ERR;
			}
		}
	}
	if (ret == SA_SYSTEM_ERR &&
	    scf_error() == SCF_ERROR_PERMISSION_DENIED) {
		ret = SA_NO_PERMISSION;
	}
	return (ret);
}


/*
 * sa_end_transaction(scfhandle, sahandle)
 *
 * Commit the changes that were added to the transaction in the
 * handle. Do all necessary cleanup.
 */

int
sa_end_transaction(scfutilhandle_t *handle, sa_handle_impl_t sahandle)
{
	int ret = SA_OK;

	if (handle == NULL || handle->trans == NULL || sahandle == NULL) {
		ret = SA_SYSTEM_ERR;
	} else {
		if (scf_transaction_commit(handle->trans) < 0)
			ret = SA_SYSTEM_ERR;
		scf_transaction_destroy_children(handle->trans);
		scf_transaction_destroy(handle->trans);
		if (ret == SA_OK)
			set_transaction_tstamp(sahandle);
		handle->trans = NULL;
	}
	return (ret);
}

/*
 * sa_abort_transaction(handle)
 *
 * Abort the changes that were added to the transaction in the
 * handle. Do all necessary cleanup.
 */

void
sa_abort_transaction(scfutilhandle_t *handle)
{
	if (handle->trans != NULL) {
		scf_transaction_reset_all(handle->trans);
		scf_transaction_destroy_children(handle->trans);
		scf_transaction_destroy(handle->trans);
		handle->trans = NULL;
	}
}

/*
 * set_transaction_tstamp(sahandle)
 *
 * After a successful transaction commit, update the timestamp of the
 * last transaction. This lets us detect changes from other processes.
 */
static void
set_transaction_tstamp(sa_handle_impl_t sahandle)
{
	char tstring[32];
	struct timeval tv;
	scfutilhandle_t *scfhandle;

	if (sahandle == NULL || sahandle->scfhandle == NULL)
		return;

	scfhandle = sahandle->scfhandle;

	if (sa_get_instance(scfhandle, "default") != SA_OK)
		return;

	if (gettimeofday(&tv, NULL) != 0)
		return;

	if (sa_start_transaction(scfhandle, "*state") != SA_OK)
		return;

	sahandle->tstrans = TSTAMP((*(timestruc_t *)&tv));
	(void) snprintf(tstring, sizeof (tstring), "%lld", sahandle->tstrans);
	if (sa_set_property(sahandle->scfhandle, "lastupdate", tstring) ==
	    SA_OK) {
		/*
		 * While best if it succeeds, a failure doesn't cause
		 * problems and we will ignore it anyway.
		 */
		(void) scf_transaction_commit(scfhandle->trans);
		scf_transaction_destroy_children(scfhandle->trans);
		scf_transaction_destroy(scfhandle->trans);
	} else {
		sa_abort_transaction(scfhandle);
	}
}

/*
 * sa_set_property(handle, prop, value)
 *
 * Set a property transaction entry into the pending SMF transaction.
 */

int
sa_set_property(scfutilhandle_t *handle, char *propname, char *valstr)
{
	int ret = SA_OK;
	scf_value_t *value;
	scf_transaction_entry_t *entry;
	/*
	 * Properties must be set in transactions and don't take
	 * effect until the transaction has been ended/committed.
	 */
	value = scf_value_create(handle->handle);
	entry = scf_entry_create(handle->handle);
	if (value != NULL && entry != NULL) {
		if (scf_transaction_property_change(handle->trans, entry,
		    propname, SCF_TYPE_ASTRING) == 0 ||
		    scf_transaction_property_new(handle->trans, entry,
		    propname, SCF_TYPE_ASTRING) == 0) {
			if (scf_value_set_astring(value, valstr) == 0) {
				if (scf_entry_add_value(entry, value) != 0) {
					ret = SA_SYSTEM_ERR;
					scf_value_destroy(value);
				}
				/* The value is in the transaction */
				value = NULL;
			} else {
				/* Value couldn't be constructed */
				ret = SA_SYSTEM_ERR;
			}
			/* The entry is in the transaction */
			entry = NULL;
		} else {
			ret = SA_SYSTEM_ERR;
		}
	} else {
		ret = SA_SYSTEM_ERR;
	}
	if (ret == SA_SYSTEM_ERR) {
		if (scf_error() == SCF_ERROR_PERMISSION_DENIED) {
			ret = SA_NO_PERMISSION;
		}
	}
	/*
	 * Cleanup if there were any errors that didn't leave these
	 * values where they would be cleaned up later.
	 */
	if (value != NULL)
		scf_value_destroy(value);
	if (entry != NULL)
		scf_entry_destroy(entry);
	return (ret);
}

/*
 * check_resource(share)
 *
 * Check to see if share has any persistent resources. We don't want
 * to save if they are all transient.
 */
static int
check_resource(sa_share_t share)
{
	sa_resource_t resource;
	int ret = B_FALSE;

	for (resource = sa_get_share_resource(share, NULL);
	    resource != NULL && ret == B_FALSE;
	    resource = sa_get_next_resource(resource)) {
		char *type;
		type = sa_get_resource_attr(resource, "type");
		if (type != NULL) {
			if (strcmp(type, "transient") != 0) {
				ret = B_TRUE;
			}
			sa_free_attr_string(type);
		}
	}
	return (ret);
}

/*
 * sa_set_resource_property(handle, prop, value)
 *
 * set a property transaction entry into the pending SMF
 * transaction. We don't want to include any transient resources
 */

static int
sa_set_resource_property(scfutilhandle_t *handle, sa_share_t share)
{
	int ret = SA_OK;
	scf_value_t *value;
	scf_transaction_entry_t *entry;
	sa_resource_t resource;
	char *valstr = NULL;
	char *idstr = NULL;
	char *description = NULL;
	char *propstr = NULL;
	size_t strsize;

	/* don't bother if no persistent resources */
	if (check_resource(share) == B_FALSE)
		return (ret);

	/*
	 * properties must be set in transactions and don't take
	 * effect until the transaction has been ended/committed.
	 */
	entry = scf_entry_create(handle->handle);
	if (entry == NULL)
		return (SA_SYSTEM_ERR);

	if (scf_transaction_property_change(handle->trans, entry,
	    "resource",	SCF_TYPE_ASTRING) != 0 &&
	    scf_transaction_property_new(handle->trans, entry,
	    "resource", SCF_TYPE_ASTRING) != 0) {
		scf_entry_destroy(entry);
		return (SA_SYSTEM_ERR);

	}
	for (resource = sa_get_share_resource(share, NULL);
	    resource != NULL;
	    resource = sa_get_next_resource(resource)) {
		value = scf_value_create(handle->handle);
		if (value == NULL) {
			ret = SA_NO_MEMORY;
			break;
		}
			/* Get size of complete string */
		valstr = sa_get_resource_attr(resource, "name");
		idstr = sa_get_resource_attr(resource, "id");
		description = sa_get_resource_description(resource);
		strsize = (valstr != NULL) ? strlen(valstr) : 0;
		strsize += (idstr != NULL) ? strlen(idstr) : 0;
		strsize += (description != NULL) ? strlen(description) : 0;
		if (strsize > 0) {
			strsize += 3; /* add nul and ':' */
			propstr = (char *)malloc(strsize);
			if (propstr == NULL) {
				scf_value_destroy(value);
				ret = SA_NO_MEMORY;
				goto err;
			}
			if (idstr == NULL)
				(void) snprintf(propstr, strsize, "%s",
				    valstr ? valstr : "");
			else
				(void) snprintf(propstr, strsize, "%s:%s:%s",
				    idstr, valstr ? valstr : "",
				    description ? description : "");
			if (scf_value_set_astring(value, propstr) != 0) {
				ret = SA_SYSTEM_ERR;
				free(propstr);
				scf_value_destroy(value);
				break;
			}
			if (scf_entry_add_value(entry, value) != 0) {
				ret = SA_SYSTEM_ERR;
				free(propstr);
				scf_value_destroy(value);
				break;
			}
			/* the value is in the transaction */
			value = NULL;
			free(propstr);
		}
err:
		if (valstr != NULL) {
			sa_free_attr_string(valstr);
			valstr = NULL;
		}
		if (idstr != NULL) {
			sa_free_attr_string(idstr);
			idstr = NULL;
		}
		if (description != NULL) {
			sa_free_share_description(description);
			description = NULL;
		}
	}
	/* the entry is in the transaction */
	entry = NULL;

	if (valstr != NULL)
		sa_free_attr_string(valstr);
	if (idstr != NULL)
		sa_free_attr_string(idstr);
	if (description != NULL)
		sa_free_share_description(description);

	if (ret == SA_SYSTEM_ERR) {
		if (scf_error() == SCF_ERROR_PERMISSION_DENIED) {
			ret = SA_NO_PERMISSION;
		}
	}
	/*
	 * cleanup if there were any errors that didn't leave
	 * these values where they would be cleaned up later.
	 */
	if (entry != NULL)
		scf_entry_destroy(entry);

	return (ret);
}

/*
 * sa_commit_share(handle, group, share)
 *
 *	Commit this share to the repository.
 *	properties are added if they exist but can be added later.
 *	Need to add to dfstab and sharetab, if appropriate.
 */
int
sa_commit_share(scfutilhandle_t *handle, sa_group_t group, sa_share_t share)
{
	int ret = SA_OK;
	char *groupname;
	char *name;
	char *description;
	char *sharename;
	ssize_t proplen;
	char *propstring;

	/*
	 * Don't commit in the zfs group. We do commit legacy
	 * (default) and all other groups/shares. ZFS is handled
	 * through the ZFS configuration rather than SMF.
	 */

	groupname = sa_get_group_attr(group, "name");
	if (groupname != NULL) {
		if (strcmp(groupname, "zfs") == 0) {
			/*
			 * Adding to the ZFS group will result in the sharenfs
			 * property being set but we don't want to do anything
			 * SMF related at this point.
			 */
			sa_free_attr_string(groupname);
			return (ret);
		}
	}

	proplen = get_scf_limit(SCF_LIMIT_MAX_VALUE_LENGTH);
	propstring = malloc(proplen);
	if (propstring == NULL)
		ret = SA_NO_MEMORY;

	if (groupname != NULL && ret == SA_OK) {
		ret = sa_get_instance(handle, groupname);
		sa_free_attr_string(groupname);
		groupname = NULL;
		sharename = sa_get_share_attr(share, "id");
		if (sharename == NULL) {
			/* slipped by */
			char shname[SA_SHARE_UUID_BUFLEN];
			generate_unique_sharename(shname);
			(void) xmlSetProp((xmlNodePtr)share, (xmlChar *)"id",
			    (xmlChar *)shname);
			sharename = strdup(shname);
		}
		if (sharename != NULL) {
			sigset_t old, new;
			/*
			 * Have a share name allocated so create a pgroup for
			 * it. It may already exist, but that is OK.  In order
			 * to avoid creating a share pgroup that doesn't have
			 * a path property, block signals around the critical
			 * region of creating the share pgroup and props.
			 */
			(void) sigprocmask(SIG_BLOCK, NULL, &new);
			(void) sigaddset(&new, SIGHUP);
			(void) sigaddset(&new, SIGINT);
			(void) sigaddset(&new, SIGQUIT);
			(void) sigaddset(&new, SIGTSTP);
			(void) sigprocmask(SIG_SETMASK, &new, &old);

			ret = sa_create_pgroup(handle, sharename);
			if (ret == SA_OK) {
				/*
				 * Now start the transaction for the
				 * properties that define this share. They may
				 * exist so attempt to update before create.
				 */
				ret = sa_start_transaction(handle, sharename);
			}
			if (ret == SA_OK) {
				name = sa_get_share_attr(share, "path");
				if (name != NULL) {
					/*
					 * There needs to be a path
					 * for a share to exist.
					 */
					ret = sa_set_property(handle, "path",
					    name);
					sa_free_attr_string(name);
				} else {
					ret = SA_NO_MEMORY;
				}
			}
			if (ret == SA_OK) {
				name = sa_get_share_attr(share, "drive-letter");
				if (name != NULL) {
					/* A drive letter may exist for SMB */
					ret = sa_set_property(handle,
					    "drive-letter", name);
					sa_free_attr_string(name);
				}
			}
			if (ret == SA_OK) {
				name = sa_get_share_attr(share, "exclude");
				if (name != NULL) {
					/*
					 * In special cases need to
					 * exclude proto enable.
					 */
					ret = sa_set_property(handle,
					    "exclude", name);
					sa_free_attr_string(name);
				}
			}
			if (ret == SA_OK) {
				/*
				 * If there are resource names, bundle them up
				 * and save appropriately.
				 */
				ret = sa_set_resource_property(handle, share);
			}

			if (ret == SA_OK) {
				description = sa_get_share_description(share);
				if (description != NULL) {
					ret = sa_set_property(handle,
					    "description",
					    description);
					sa_free_share_description(description);
				}
			}
			/* Make sure we cleanup the transaction */
			if (ret == SA_OK) {
				sa_handle_impl_t sahandle;
				sahandle = (sa_handle_impl_t)
				    sa_find_group_handle(group);
				if (sahandle != NULL)
					ret = sa_end_transaction(handle,
					    sahandle);
				else
					ret = SA_SYSTEM_ERR;
			} else {
				sa_abort_transaction(handle);
			}

			(void) sigprocmask(SIG_SETMASK, &old, NULL);

			free(sharename);
		}
	}
	if (ret == SA_SYSTEM_ERR) {
		int err = scf_error();
		if (err == SCF_ERROR_PERMISSION_DENIED)
			ret = SA_NO_PERMISSION;
	}
	if (propstring != NULL)
		free(propstring);
	if (groupname != NULL)
		sa_free_attr_string(groupname);

	return (ret);
}

/*
 * remove_resources(handle, share, shareid)
 *
 * If the share has resources, remove all of them and their
 * optionsets.
 */
static int
remove_resources(scfutilhandle_t *handle, sa_share_t share, char *shareid)
{
	sa_resource_t resource;
	sa_optionset_t opt;
	char *proto;
	char *id;
	ssize_t proplen;
	char *propstring;
	int ret = SA_OK;

	proplen = get_scf_limit(SCF_LIMIT_MAX_VALUE_LENGTH);
	propstring = malloc(proplen);
	if (propstring == NULL)
		return (SA_NO_MEMORY);

	for (resource = sa_get_share_resource(share, NULL);
	    resource != NULL; resource = sa_get_next_resource(resource)) {
		id = sa_get_resource_attr(resource, "id");
		if (id == NULL)
			continue;
		for (opt = sa_get_optionset(resource, NULL);
		    opt != NULL; opt = sa_get_next_optionset(resource)) {
			proto = sa_get_optionset_attr(opt, "type");
			if (proto != NULL) {
				(void) snprintf(propstring, proplen,
				    "%s_%s_%s", shareid, proto, id);
				ret = sa_delete_pgroup(handle, propstring);
				sa_free_attr_string(proto);
			}
		}
		sa_free_attr_string(id);
	}
	free(propstring);
	return (ret);
}

/*
 * sa_delete_share(handle, group, share)
 *
 * Remove the specified share from the group (and service instance).
 */

int
sa_delete_share(scfutilhandle_t *handle, sa_group_t group, sa_share_t share)
{
	int ret = SA_OK;
	char *groupname = NULL;
	char *shareid = NULL;
	sa_optionset_t opt;
	sa_security_t sec;
	ssize_t proplen;
	char *propstring;

	proplen = get_scf_limit(SCF_LIMIT_MAX_VALUE_LENGTH);
	propstring = malloc(proplen);
	if (propstring == NULL)
		ret = SA_NO_MEMORY;

	if (ret == SA_OK) {
		groupname = sa_get_group_attr(group, "name");
		shareid = sa_get_share_attr(share, "id");
		if (groupname == NULL || shareid == NULL) {
			ret = SA_CONFIG_ERR;
			goto out;
		}
		ret = sa_get_instance(handle, groupname);
		if (ret == SA_OK) {
			/* If a share has resources, remove them */
			ret = remove_resources(handle, share, shareid);
			/* If a share has properties, remove them */
			ret = sa_delete_pgroup(handle, shareid);
			for (opt = sa_get_optionset(share, NULL);
			    opt != NULL;
			    opt = sa_get_next_optionset(opt)) {
				char *proto;
				proto = sa_get_optionset_attr(opt, "type");
				if (proto != NULL) {
					(void) snprintf(propstring,
					    proplen, "%s_%s", shareid,
					    proto);
					ret = sa_delete_pgroup(handle,
					    propstring);
					sa_free_attr_string(proto);
				} else {
					ret = SA_NO_MEMORY;
				}
			}
			/*
			 * If a share has security/negotiable
			 * properties, remove them.
			 */
			for (sec = sa_get_security(share, NULL, NULL);
			    sec != NULL;
			    sec = sa_get_next_security(sec)) {
				char *proto;
				char *sectype;
				proto = sa_get_security_attr(sec, "type");
				sectype = sa_get_security_attr(sec, "sectype");
				if (proto != NULL && sectype != NULL) {
					(void) snprintf(propstring, proplen,
					    "%s_%s_%s", shareid,  proto,
					    sectype);
					ret = sa_delete_pgroup(handle,
					    propstring);
				} else {
					ret = SA_NO_MEMORY;
				}
				if (proto != NULL)
					sa_free_attr_string(proto);
				if (sectype != NULL)
					sa_free_attr_string(sectype);
			}
		}
	}
out:
	if (groupname != NULL)
		sa_free_attr_string(groupname);
	if (shareid != NULL)
		sa_free_attr_string(shareid);
	if (propstring != NULL)
		free(propstring);

	return (ret);
}
