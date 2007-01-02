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

/* helper functions for using libscf with sharemgr */

#include <libscf.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include "libshare.h"
#include "libshare_impl.h"
#include "scfutil.h"
#include <string.h>
#include <errno.h>
#include <uuid/uuid.h>
#include <sys/param.h>
#include <signal.h>

ssize_t scf_max_name_len;
extern struct sa_proto_plugin *sap_proto_list;

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
 * must be called when done. Called with the handle allocated in
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
 * must be called before using any of the SCF functions. Called by
 * sa_init() during the API setup.
 */

scfutilhandle_t *
sa_scf_init()
{
	scfutilhandle_t *handle;

	scf_max_name_len = scf_limit(SCF_LIMIT_MAX_NAME_LENGTH);
	if (scf_max_name_len <= 0)
	    scf_max_name_len = SA_MAX_NAME_LEN + 1;

	handle = calloc(1, sizeof (scfutilhandle_t));
	if (handle != NULL) {
	    handle->scf_state = SCH_STATE_INITIALIZING;
	    handle->handle = scf_handle_create(SCF_VERSION);
	    if (handle->handle != NULL) {
		if (scf_handle_bind(handle->handle) == 0) {
		    handle->scope = scf_scope_create(handle->handle);
		    handle->service = scf_service_create(handle->handle);
		    handle->pg = scf_pg_create(handle->handle);
		    handle->instance = scf_instance_create(handle->handle);
		    if (scf_handle_get_scope(handle->handle,
					SCF_SCOPE_LOCAL, handle->scope) == 0) {
			if (scf_scope_get_service(handle->scope,
						    SA_GROUP_SVC_NAME,
						    handle->service) != 0) {
			    goto err;
			}
			handle->scf_state = SCH_STATE_INIT;
			if (sa_get_instance(handle, "default") != SA_OK) {
			    char **protolist;
			    int numprotos, i;
			    sa_group_t defgrp;
			    defgrp = sa_create_group("default", NULL);
			    if (defgrp != NULL) {
				numprotos = sa_get_protocols(&protolist);
				for (i = 0; i < numprotos; i++) {
				    (void) sa_create_optionset(defgrp,
								protolist[i]);
				}
				if (protolist != NULL)
				    free(protolist);
			    }
			}
		    } else {
			goto err;
		    }
		} else {
		    goto err;
		}
	    } else {
		free(handle);
		handle = NULL;
		(void) printf("libshare could not access SMF repository: %s\n",
				scf_strerror(scf_error()));
	    }
	}
	return (handle);

	/* error handling/unwinding */
err:
	(void) sa_scf_fini(handle);
	(void) printf("libshare SMF initialization problem: %s\n",
			scf_strerror(scf_error()));
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
 * internal function to check to see if a property is an SMF magic
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
 * check to see if the specified protocol is a valid one for the
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
 * extract the name property group and create the specified type of
 * node on the provided group.  type will be optionset or security.
 */

static int
sa_extract_pgroup(xmlNodePtr root, scfutilhandle_t *handle,
			scf_propertygroup_t *pg,
			char *nodetype, char *proto, char *sectype)
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
	if (node != NULL) {
	    if (proto != NULL)
		xmlSetProp(node, (xmlChar *)"type", (xmlChar *)proto);
	    if (sectype != NULL)
		xmlSetProp(node, (xmlChar *)"sectype", (xmlChar *)sectype);
		/*
		 * have node to work with so iterate over the properties
		 * in the pg and create option sub nodes.
		 */
		iter = scf_iter_create(handle->handle);
		value = scf_value_create(handle->handle);
		prop = scf_property_create(handle->handle);
		name = malloc(scf_max_name_len);
		valuestr = malloc(vallen);
		/*
		 * want to iterate through the properties and add them
		 * to the base optionset.
		 */
		if (iter != NULL && value != NULL && prop != NULL &&
		    valuestr != NULL && name != NULL) {
		    if (scf_iter_pg_properties(iter, pg) == 0) {
			/* now iterate the properties in the group */
			while (scf_iter_next_property(iter, prop) > 0) {
			    /* have a property */
			    if (scf_property_get_name(prop, name,
							scf_max_name_len) > 0) {
				/* some properties are part of the framework */
				if (skip_property(name))
				    continue;
				if (scf_property_get_value(prop, value) == 0) {
				    if (scf_value_get_astring(value, valuestr,
								vallen) >= 0) {
					sa_property_t saprop;
					saprop = sa_create_property(name,
								    valuestr);
					if (saprop != NULL) {
					/*
					 * since in SMF, don't
					 * recurse. Use xmlAddChild
					 * directly, instead.
					 */
					    xmlAddChild(node,
							(xmlNodePtr) saprop);
					}
				    }
				}
			    }
			}
		    }
		} else {
		    ret = SA_NO_MEMORY;
		}
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
	}
	return (ret);
}

/*
 * sa_extract_attrs(root, handle, instance)
 *
 * local function to extract the actual attributes/properties from the
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
	if (prop != NULL && value != NULL && valuestr != NULL &&
	    scf_instance_get_pg(instance, "operation",
				handle->pg) == 0) {
		/*
		 * have a property group with desired name so now get
		 * the known attributes.
		 */
	    if (scf_pg_get_property(handle->pg, "state", prop) == 0) {
		/* found the property so get the value */
		if (scf_property_get_value(prop, value) == 0) {
		    if (scf_value_get_astring(value, valuestr, vallen) >= 0) {
			xmlSetProp(root, (xmlChar *)"state",
				    (xmlChar *)valuestr);
		    }
		}
	    }
	    if (scf_pg_get_property(handle->pg, "zfs", prop) == 0) {
		/* found the property so get the value */
		if (scf_property_get_value(prop, value) == 0) {
		    if (scf_value_get_astring(value, valuestr, vallen) > 0) {
			xmlSetProp(root, (xmlChar *)"zfs",
				    (xmlChar *)valuestr);
		    }
		}
	    }
	}
	if (valuestr != NULL)
	    free(valuestr);
	if (value != NULL)
	    scf_value_destroy(value);
	if (prop != NULL)
	    scf_property_destroy(prop);
}

/*
 * list of known share attributes.
 */

static char *share_attr[] = {
	"path",
	"id",
	"resource",
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
 * sa_share_from_pgroup
 *
 * extract the share definition from the share property group. We do
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
	    if (strncmp(id, SA_SHARE_PG_PREFIX, SA_SHARE_PG_PREFIXLEN) != 0 ||
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
	 * construct the share XML node. It is similar to sa_add_share
	 * but never changes the repository. Also, there won't be any
	 * ZFS or transient shares.  Root will be the group it is
	 * associated with.
	 */
	node = xmlNewChild(root, NULL, (xmlChar *)"share", NULL);
	if (node != NULL) {
		/*
		 * make sure the UUID part of the property group is
		 * stored in the share "id" property. We use this
		 * later.
		 */
	    xmlSetProp(node, (xmlChar *)"id", (xmlChar *)id);
	    xmlSetProp(node, (xmlChar *)"type", (xmlChar *)"persist");
	}

	if (iter != NULL && value != NULL && prop != NULL && name != NULL) {
		/* iterate over the share pg properties */
	    if (scf_iter_pg_properties(iter, pg) == 0) {
		while (scf_iter_next_property(iter, prop) > 0) {
		    ret = SA_SYSTEM_ERR; /* assume the worst */
		    if (scf_property_get_name(prop, name,
						scf_max_name_len) > 0) {
			if (scf_property_get_value(prop, value) == 0) {
			    if (scf_value_get_astring(value, valuestr,
							vallen) >= 0) {
				ret = SA_OK;
			    }
			}
		    }
		    if (ret == SA_OK) {
			/*
			 * check that we have the "path" property in
			 * name. The string in name will always be nul
			 * terminated if scf_property_get_name()
			 * succeeded.
			 */
			if (strcmp(name, "path") == 0)
			    have_path = 1;
			if (is_share_attr(name)) {
				/*
				 * if a share attr, then simple -
				 * usually path and resource name
				 */
			    xmlSetProp(node, (xmlChar *)name,
					(xmlChar *)valuestr);
			} else {
			    if (strcmp(name, "description") == 0) {
				/* we have a description node */
				xmlNodePtr desc;
				desc = xmlNewChild(node, NULL,
						    (xmlChar *)"description",
						    NULL);
				if (desc != NULL)
				    xmlNodeSetContent(desc,
							(xmlChar *)valuestr);
			    }
			}
		    }
		}
	    }
	}
	/*
	 * a share without a path is broken so we want to not include
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
find_share_by_id(char *shareid)
{
	sa_group_t group;
	sa_share_t share = NULL;
	char *id = NULL;
	int done = 0;

	for (group = sa_get_group(NULL); group != NULL && !done;
		group = sa_get_next_group(group)) {
		for (share = sa_get_share(group, NULL); share != NULL;
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
 * sa_share_props_from_pgroup(root, handle, pg, id)
 *
 * extract share properties from the SMF property group. More sanity
 * checks are done and the share object is created. We ignore some
 * errors that could exist in the repository and only worry about
 * property groups that validate in naming.
 */

static int
sa_share_props_from_pgroup(xmlNodePtr root, scfutilhandle_t *handle,
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
	char *sectype = NULL;
	char *proto;
	sa_share_t share;

	/*
	 * While preliminary check (starts with 'S') passed before
	 * getting here. Need to make sure it is in ID syntax
	 * (Snnnnnn). Note that shares with properties have similar
	 * pgroups. If the pg name is more than SA_SHARE_PG_LEN
	 * characters, it is likely one of the protocol/security
	 * versions.
	 */
	vallen = strlen(id);
	if (*id == SA_SHARE_PG_PREFIX[0] && vallen > SA_SHARE_PG_LEN) {
	    uuid_t uuid;
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
	} else {
	/*
	 * it is ok to not have what we thought since someone might
	 * have added a name via SMF.
	 */
	    return (ret);
	}

	/*
	 * to get here, we have a valid protocol and possibly a
	 * security. We now have to find the share that it is really
	 * associated with. The "id" portion of the pgroup name will
	 * match.
	 */

	share = find_share_by_id(id);
	if (share == NULL)
	    return (SA_BAD_PATH);

	root = (xmlNodePtr)share;

	vallen = get_scf_limit(SCF_LIMIT_MAX_VALUE_LENGTH);

	iter = scf_iter_create(handle->handle);
	value = scf_value_create(handle->handle);
	prop = scf_property_create(handle->handle);
	name = malloc(scf_max_name_len);
	valuestr = malloc(vallen);

	if (sectype == NULL)
	    node = xmlNewChild(root, NULL, (xmlChar *)"optionset", NULL);
	else {
	    node = xmlNewChild(root, NULL, (xmlChar *)"security", NULL);
	    if (node != NULL)
		xmlSetProp(node, (xmlChar *)"sectype", (xmlChar *)sectype);
	}
	if (node != NULL) {
	    xmlSetProp(node, (xmlChar *)"type", (xmlChar *)proto);
	    /* now find the properties */
	    if (iter != NULL && value != NULL && prop != NULL && name != NULL) {
		/* iterate over the share pg properties */
		if (scf_iter_pg_properties(iter, pg) == 0) {
		    while (scf_iter_next_property(iter, prop) > 0) {
			ret = SA_SYSTEM_ERR; /* assume the worst */
			if (scf_property_get_name(prop, name,
						    scf_max_name_len) > 0) {
			    if (scf_property_get_value(prop, value) == 0) {
				if (scf_value_get_astring(value, valuestr,
							    vallen) >= 0) {
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
	    }
	} else {
	    ret = SA_NO_MEMORY;
	}
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
 * get the config info for this instance of a group and create the XML
 * subtree from it.
 */

static int
sa_extract_group(xmlNodePtr root, scfutilhandle_t *handle,
			scf_instance_t *instance)
{
	char *buff;
	xmlNodePtr node;
	scf_iter_t *iter;
	char *proto;
	char *sectype;
	int have_shares = 0;
	int has_proto = 0;
	int is_default = 0;
	int ret = SA_OK;
	int err;

	buff = malloc(scf_max_name_len);
	iter = scf_iter_create(handle->handle);
	if (buff != NULL) {
	    if (scf_instance_get_name(instance, buff,
						scf_max_name_len) > 0) {
		node = xmlNewChild(root, NULL, (xmlChar *)"group", NULL);
		if (node != NULL) {
		    xmlSetProp(node, (xmlChar *)"name", (xmlChar *)buff);
		    if (strcmp(buff, "default") == 0)
			is_default++;
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
		    if (iter != NULL) {
			if (scf_iter_instance_pgs(iter, instance) == 0) {
			    while (scf_iter_next_pg(iter, handle->pg) > 0) {
				/* have a pgroup so sort it out */
				ret = scf_pg_get_name(handle->pg, buff,
							scf_max_name_len);
				if (ret  > 0) {
				    if (buff[0] == SA_SHARE_PG_PREFIX[0]) {
					sa_share_from_pgroup(node, handle,
								handle->pg,
								buff);
					have_shares++;
				    } else if (strncmp(buff, "optionset", 9) ==
						0) {
					char *nodetype = "optionset";
					/* have an optionset */
					sectype = NULL;
					proto = strchr(buff, '_');
					if (proto != NULL) {
					    *proto++ = '\0';
					    sectype = strchr(proto, '_');
					    if (sectype != NULL) {
						*sectype++ = '\0';
						nodetype = "security";
					    }
					}
					ret = sa_extract_pgroup(node, handle,
							    handle->pg,
							    nodetype,
							    proto, sectype);
					has_proto++;
				    } else if (strncmp(buff,
							"security", 8) == 0) {
					/*
					 * have a security (note that
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
							    handle->pg,
							    "security", proto,
							    sectype);
					has_proto++;
				    }
				    /* ignore everything else */
				}
			    }
			} else {
			    ret = SA_NO_MEMORY;
			}
			/*
			 * Make sure we have a valid default group.
			 * On first boot, default won't have any
			 * protocols defined and won't be enabled (but
			 * should be).
			 */
			if (is_default) {
			    char *state = sa_get_group_attr((sa_group_t)node,
							    "state");
			    char **protos;
			    int numprotos;
			    int i;

			    if (state == NULL) {
				/* set attribute to enabled */
				(void) sa_set_group_attr((sa_group_t)node,
							    "state",
							    "enabled");
				/* we can assume no protocols */
				numprotos = sa_get_protocols(&protos);
				for (i = 0; i < numprotos; i++)
				    (void) sa_create_optionset((sa_group_t)node,
								protos[i]);
				if (numprotos > 0)
				    free(protos);
			    } else {
				sa_free_attr_string(state);
			    }
			}
			/* do a second pass if shares were found */
			if (have_shares &&
				scf_iter_instance_pgs(iter, instance) == 0) {
			    while (scf_iter_next_pg(iter, handle->pg) > 0) {
				/*
				 * have a pgroup so see if it is a
				 * share optionset
				 */
				err = scf_pg_get_name(handle->pg, buff,
							scf_max_name_len);
				if (err  > 0) {
				    if (buff[0] == SA_SHARE_PG_PREFIX[0]) {
					ret = sa_share_props_from_pgroup(node,
								handle,
								handle->pg,
								buff);
				    }
				}
			    }
			}
		    }
		}
	    }
	}
	if (iter != NULL)
	    scf_iter_destroy(iter);
	if (buff != NULL)
	    free(buff);
	return (ret);
}

/*
 * sa_extract_defaults(root, handle, instance)
 *
 * local function to find the default properties that live in the
 * default instance's "operation" proprerty group.
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
	if (prop != NULL && value != NULL && vallen != NULL &&
	    scf_instance_get_pg(instance, "operation",
				handle->pg) == 0) {
	    if (scf_pg_get_property(handle->pg,
				    "legacy-timestamp", prop) == 0) {
		/* found the property so get the value */
		if (scf_property_get_value(prop, value) == 0) {
		    if (scf_value_get_astring(value, valuestr, vallen) > 0) {
			node = xmlNewChild(root, NULL, (xmlChar *)"legacy",
					    NULL);
			if (node != NULL) {
			    xmlSetProp(node, (xmlChar *)"timestamp",
					(xmlChar *)valuestr);
			    xmlSetProp(node, (xmlChar *)"path",
					(xmlChar *)SA_LEGACY_DFSTAB);
			}
		    }
		}
	    }
	}
	if (valuestr != NULL)
	    free(valuestr);
	if (value != NULL)
	    scf_value_destroy(value);
	if (prop != NULL)
	    scf_property_destroy(prop);
}


/*
 * sa_get_config(handle, root, doc)
 *
 * walk the SMF repository for /network/shares/group and find all the
 * instances. These become group names.  Then add the XML structure
 * below the groups based on property groups and properties.
 */
int
sa_get_config(scfutilhandle_t *handle, xmlNodePtr *root, xmlDocPtr *doc)
{
	int ret = SA_OK;
	scf_instance_t *instance;
	scf_iter_t *iter;
	char buff[BUFSIZ * 2];

	*doc = xmlNewDoc((xmlChar *)"1.0");
	*root = xmlNewNode(NULL, (xmlChar *)"sharecfg");
	instance = scf_instance_create(handle->handle);
	iter = scf_iter_create(handle->handle);
	if (*doc != NULL && *root != NULL && instance != NULL && iter != NULL) {
	    xmlDocSetRootElement(*doc, *root);
	    if ((ret = scf_iter_service_instances(iter,
						    handle->service)) == 0) {
		while ((ret = scf_iter_next_instance(iter,
							instance)) > 0) {
		    if (scf_instance_get_name(instance, buff,
						sizeof (buff)) > 0) {
			if (strcmp(buff, "default") == 0)
			    sa_extract_defaults(*root, handle, instance);
			ret = sa_extract_group(*root, handle, instance);
		    }
		}
	    }
	} else {
	    /* if we can't create the document, cleanup */
	    if (*doc != NULL)
		xmlFreeDoc(*doc);
	    if (*root != NULL)
		xmlFreeNode(*root);
	    *doc = NULL;
	    *root = NULL;
	}
	/* always cleanup these */
	if (instance != NULL)
	    scf_instance_destroy(instance);
	if (iter != NULL)
	    scf_iter_destroy(iter);
	return (ret);
}

/*
 * sa_get_instance(handle, instance)
 *
 * get the instance of the group service. This is actually the
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
	/*
	 * only create a handle if it doesn't exist. It is ok to exist
	 * since the pg handle will be set as a side effect.
	 */
	if (handle->pg == NULL) {
	    handle->pg = scf_pg_create(handle->handle);
	}
	/*
	 * if the pgroup exists, we are done. If it doesn't, then we
	 * need to actually add one to the service instance.
	 */
	if (scf_instance_get_pg(handle->instance,
				pgroup, handle->pg) != 0) {
	    /* doesn't exist so create one */
	    if (scf_instance_add_pg(handle->instance, pgroup,
				    SCF_GROUP_APPLICATION, 0,
				    handle->pg) != 0) {
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
 * remove the property group from the current instance of the service,
 * but only if it actually exists.
 */

int
sa_delete_pgroup(scfutilhandle_t *handle, char *pgroup)
{
	int ret = SA_OK;
	/*
	 * only delete if it does exist.
	 */
	if (scf_instance_get_pg(handle->instance,
				pgroup, handle->pg) == 0) {
	    /* does exist so delete it */
	    if (scf_pg_delete(handle->pg) != 0) {
		ret = SA_SYSTEM_ERR;
	    }
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
	 * lookup the property group and create it if it doesn't already
	 * exist.
	 */
	if (handle->scf_state == SCH_STATE_INIT) {
	    ret = sa_create_pgroup(handle, propgroup);
	    if (ret == SA_OK) {
		handle->trans = scf_transaction_create(handle->handle);
		if (handle->trans != NULL) {
		    if (scf_transaction_start(handle->trans, handle->pg) != 0) {
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
 * sa_end_transaction(handle)
 *
 * Commit the changes that were added to the transaction in the
 * handle. Do all necessary cleanup.
 */

int
sa_end_transaction(scfutilhandle_t *handle)
{
	int ret = SA_OK;

	if (handle->trans == NULL) {
	    ret = SA_SYSTEM_ERR;
	} else {
	    if (scf_transaction_commit(handle->trans) < 0)
		ret = SA_SYSTEM_ERR;
	    scf_transaction_destroy_children(handle->trans);
	    scf_transaction_destroy(handle->trans);
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
 * sa_set_property(handle, prop, value)
 *
 * set a property transaction entry into the pending SMF transaction.
 */

int
sa_set_property(scfutilhandle_t *handle, char *propname, char *valstr)
{
	int ret = SA_OK;
	scf_value_t *value;
	scf_transaction_entry_t *entry;
	/*
	 * properties must be set in transactions and don't take
	 * effect until the transaction has been ended/committed.
	 */
	value = scf_value_create(handle->handle);
	entry = scf_entry_create(handle->handle);
	if (value != NULL && entry != NULL) {
	    if (scf_transaction_property_change(handle->trans, entry,
						propname,
						SCF_TYPE_ASTRING) == 0 ||
		scf_transaction_property_new(handle->trans, entry,
						propname,
						SCF_TYPE_ASTRING) == 0) {
		if (scf_value_set_astring(value, valstr) == 0) {
		    if (scf_entry_add_value(entry, value) != 0) {
			ret = SA_SYSTEM_ERR;
			scf_value_destroy(value);
		    }
		    /* the value is in the transaction */
		    value = NULL;
		} else {
		    /* value couldn't be constructed */
		    ret = SA_SYSTEM_ERR;
		}
		/* the entry is in the transaction */
		entry = NULL;
	    } else {
		ret = SA_SYSTEM_ERR;
	    }
	} else {
	    ret = SA_SYSTEM_ERR;
	}
	if (ret == SA_SYSTEM_ERR) {
	    switch (scf_error()) {
	    case SCF_ERROR_PERMISSION_DENIED:
		ret = SA_NO_PERMISSION;
		break;
	    }
	}
	/*
	 * cleanup if there were any errors that didn't leave these
	 * values where they would be cleaned up later.
	 */
	if (value != NULL)
	    scf_value_destroy(value);
	if (entry != NULL)
	    scf_entry_destroy(entry);
	return (ret);
}

/*
 * sa_commit_share(handle, group, share)
 *
 *	commit this share to the repository.
 *	properties are added if they exist but can be added later.
 *	Need to add to dfstab and sharetab, if appropriate.
 */
int
sa_commit_share(scfutilhandle_t *handle, sa_group_t group, sa_share_t share)
{
	int ret = SA_OK;
	char *groupname;
	char *name;
	char *resource;
	char *description;
	char *sharename;
	ssize_t proplen;
	char *propstring;

	/*
	 * don't commit in the zfs group. We do commit legacy
	 * (default) and all other groups/shares. ZFS is handled
	 * through the ZFS configuration rather than SMF.
	 */

	groupname = sa_get_group_attr(group, "name");
	if (groupname != NULL) {
	    if (strcmp(groupname, "zfs") == 0) {
		/*
		 * adding to the ZFS group will result in the sharenfs
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
		xmlSetProp((xmlNodePtr)share, (xmlChar *)"id",
			    (xmlChar *)shname);
		sharename = strdup(shname);
	    }
	    if (sharename != NULL) {
		sigset_t old, new;
		/*
		 * have a share name allocated so create a pgroup for
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
			 * now start the transaction for the
			 * properties that define this share. They may
			 * exist so attempt to update before create.
			 */
		    ret = sa_start_transaction(handle, sharename);
		}
		if (ret == SA_OK) {
		    name = sa_get_share_attr(share, "path");
		    if (name != NULL) {
			/* there needs to be a path for a share to exist */
			ret = sa_set_property(handle, "path", name);
			sa_free_attr_string(name);
		    } else {
			ret = SA_NO_MEMORY;
		    }
		}
		if (ret == SA_OK) {
		    resource = sa_get_share_attr(share, "resource");
		    if (resource != NULL) {
			ret = sa_set_property(handle, "resource", resource);
			sa_free_attr_string(resource);
		    }
		}
		if (ret == SA_OK) {
		    description = sa_get_share_description(share);
		    if (description != NULL) {
			ret = sa_set_property(handle, "description",
						description);
			sa_free_share_description(description);
		    }
		}
		/* make sure we cleanup the transaction */
		if (ret == SA_OK) {
		    ret = sa_end_transaction(handle);
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
 * sa_delete_share(handle, group, share)
 *
 * remove the specified share from the group (and service instance).
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
	    if (groupname != NULL && shareid != NULL) {
		ret = sa_get_instance(handle, groupname);
		if (ret == SA_OK) {
		    /* if a share has properties, remove them */
		    ret = sa_delete_pgroup(handle, shareid);
		    for (opt = sa_get_optionset(share, NULL); opt != NULL;
			opt = sa_get_next_optionset(opt)) {
			char *proto;
			proto = sa_get_optionset_attr(opt, "type");
			if (proto != NULL) {
			    (void) snprintf(propstring, proplen, "%s_%s",
						shareid, proto);
			    ret = sa_delete_pgroup(handle, propstring);
			    sa_free_attr_string(proto);
			} else {
			    ret = SA_NO_MEMORY;
			}
		    }
			/*
			 * if a share has security/negotiable
			 * properties, remove them.
			 */
		    for (sec = sa_get_security(share, NULL, NULL); sec != NULL;
			sec = sa_get_next_security(sec)) {
			char *proto;
			char *sectype;
			proto = sa_get_security_attr(sec, "type");
			sectype = sa_get_security_attr(sec, "sectype");
			if (proto != NULL && sectype != NULL) {
			    (void) snprintf(propstring, proplen, "%s_%s_%s",
					shareid,
					proto, sectype);
			    ret = sa_delete_pgroup(handle, propstring);
			} else {
			    ret = SA_NO_MEMORY;
			}
			if (proto != NULL)
			    sa_free_attr_string(proto);
			if (sectype != NULL)
			    sa_free_attr_string(sectype);
		    }
		}
	    } else {
		ret = SA_CONFIG_ERR;
	    }
	}
	if (groupname != NULL)
	    sa_free_attr_string(groupname);
	if (shareid != NULL)
	    sa_free_attr_string(shareid);
	if (propstring != NULL)
	    free(propstring);

	return (ret);
}
