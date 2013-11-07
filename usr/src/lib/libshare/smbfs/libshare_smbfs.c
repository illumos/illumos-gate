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

/*
 * SMB specific functions
 */
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <zone.h>
#include <errno.h>
#include <locale.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include "libshare.h"
#include "libshare_impl.h"
#include <pwd.h>
#include <limits.h>
#include <libscf.h>
#include <strings.h>
#include "libshare_smbfs.h"
#include <rpcsvc/daemon_utils.h>
#include <arpa/inet.h>
#include <uuid/uuid.h>
#include <netsmb/smb_lib.h>

#define	SMBFS_PROTOCOL_NAME	"smbfs"

/* internal functions */
static uint64_t smbfs_features();
static int smbfs_init();
static void smbfs_fini();
static int smbfs_set_proto_prop(sa_property_t);
static sa_protocol_properties_t smbfs_get_proto_set();
static char *smbfs_get_status();
static int smbfs_delete_section(char *);
static int smbfs_delete_property_group(char *);

static int range_check_validator(int, char *, char *);
static int string_length_check_validator(int, char *, char *);
static int yes_no_validator(int, char *, char *);
static int ip_address_validator(int, char *, char *);
static int minauth_validator(int, char *, char *);
static int password_validator(int, char *, char *);
static int signing_validator(int, char *, char *);

int propset_changed = 0;

/*
 * ops vector that provides the protocol specific info and operations
 * for share management.
 */

struct sa_plugin_ops sa_plugin_ops = {
	SA_PLUGIN_VERSION,
	SMBFS_PROTOCOL_NAME,
	smbfs_init,
	smbfs_fini,
	NULL,	/* share */
	NULL,	/* unshare */
	NULL,	/* valid_prop */
	NULL,	/* valid_space */
	NULL,	/* security_prop */
	NULL,	/* legacy_opts */
	NULL,	/* legacy_format */
	smbfs_set_proto_prop,
	smbfs_get_proto_set,
	smbfs_get_status,
	NULL,	/* space_alias */
	NULL,	/* update_legacy */
	NULL,	/* delete_legacy */
	NULL,	/* change_notify */
	NULL,	/* enable_resource */
	NULL,	/* disable_resource */
	smbfs_features,
	NULL,	/* get_transient_shares */
	NULL,	/* notify_resource */
	NULL,	/* rename_resource */
	NULL,	/* run_command */
	NULL,	/* command_help */
	smbfs_delete_section,
};

/*
 * is_a_number(number)
 *
 * is the string a number in one of the forms we want to use?
 */

static int
is_a_number(char *number)
{
	int ret = 1;
	int hex = 0;

	if (strncmp(number, "0x", 2) == 0) {
		number += 2;
		hex = 1;
	} else if (*number == '-') {
		number++; /* skip the minus */
	}

	while (ret == 1 && *number != '\0') {
		if (hex) {
			ret = isxdigit(*number++);
		} else {
			ret = isdigit(*number++);
		}
	}
	return (ret);
}

/*
 * Protocol management functions
 *
 * properties defined in the default files are defined in
 * proto_option_defs for parsing and validation.
 */

struct smbclnt_proto_option_defs smbclnt_proto_options[] = {
	{ "section", NULL, PROTO_OPT_SECTION,
	    0, 0, MAX_VALUE_BUFLEN,
	    string_length_check_validator},
	{ "addr", NULL, PROTO_OPT_ADDR,
	    0, 0, MAX_VALUE_BUFLEN,
	    ip_address_validator},
	{ "minauth", NULL, PROTO_OPT_MINAUTH,
	    0, 0, MAX_VALUE_BUFLEN,
	    minauth_validator},
	{ "nbns_broadcast", NULL, PROTO_OPT_NBNS_BROADCAST,
	    0, 0, 0,
	    yes_no_validator},
	{ "nbns_enable", NULL, PROTO_OPT_NBNS_ENABLE,
	    0, 0, 0,
	    yes_no_validator},
	{ "nbns", NULL, PROTO_OPT_NBNSADDR,
	    0, 0, MAX_VALUE_BUFLEN,
	    ip_address_validator},
	{ "password", NULL, PROTO_OPT_PASSWORD,
	    0, 0, MAX_VALUE_BUFLEN,
	    password_validator},
	{ "timeout", NULL, PROTO_OPT_TIMEOUT,
	    0, 0, 60,
	    range_check_validator},
	{ "user", NULL, PROTO_OPT_USER,
	    0, 0, MAX_VALUE_BUFLEN,
	    string_length_check_validator},
	{ "domain", NULL, PROTO_OPT_DOMAIN,
	    0, 0, MAX_VALUE_BUFLEN,
	    string_length_check_validator},
	{ "workgroup", NULL, PROTO_OPT_WORKGROUP,
	    0, 0, MAX_VALUE_BUFLEN,
	    string_length_check_validator},
	{ "signing", NULL, PROTO_OPT_SIGNING,
	    0, 0, MAX_VALUE_BUFLEN,
	    signing_validator},
	{NULL}
};

/*
 * Check the range of value as int range.
 */
/*ARGSUSED*/
static int
range_check_validator(int index, char *section, char *value)
{
	int ret = SA_OK;

	if (value == NULL)
		return (SA_BAD_VALUE);
	if (strlen(value) == 0)
		return (SA_OK);
	if (!is_a_number(value)) {
		ret = SA_BAD_VALUE;
	} else {
		int val;
		val = strtoul(value, NULL, 0);
		if (val < smbclnt_proto_options[index].minval ||
		    val > smbclnt_proto_options[index].maxval)
			ret = SA_BAD_VALUE;
	}
	return (ret);
}

/*
 * Check the length of the string
 */
/*ARGSUSED*/
static int
string_length_check_validator(int index, char *section, char *value)
{
	int ret = SA_OK;

	if (value == NULL)
		return (SA_BAD_VALUE);
	if (strlen(value) == 0)
		return (SA_OK);
	if (strlen(value) > smbclnt_proto_options[index].maxval)
		ret = SA_BAD_VALUE;
	return (ret);
}

/*
 * Check yes/no
 */
/*ARGSUSED*/
static int
yes_no_validator(int index, char *section, char *value)
{
	if (value == NULL)
		return (SA_BAD_VALUE);
	if (strlen(value) == 0)
		return (SA_OK);
	if ((strcasecmp(value, "yes") == 0) ||
	    (strcasecmp(value, "no") == 0) ||
	    (strcasecmp(value, "true") == 0) ||
	    (strcasecmp(value, "false") == 0))
		return (SA_OK);
	return (SA_BAD_VALUE);
}

/*
 * Check IP address.
 */
/*ARGSUSED*/
static int
ip_address_validator(int index, char *section, char *value)
{
	int len;

	if (value == NULL)
		return (SA_BAD_VALUE);
	len = strlen(value);
	if (len == 0)
		return (SA_OK);
	if (len > MAX_VALUE_BUFLEN)
		return (SA_BAD_VALUE);
	return (SA_OK);
}

/*ARGSUSED*/
static int
minauth_validator(int index, char *section, char *value)
{
	if (value == NULL)
		return (SA_BAD_VALUE);
	if (strlen(value) == 0)
		return (SA_OK);
	if (strcmp(value, "kerberos") == 0 ||
	    strcmp(value, "ntlmv2") == 0 ||
	    strcmp(value, "ntlm") == 0 ||
	    strcmp(value, "lm") == 0 ||
	    strcmp(value, "none") == 0)
		return (SA_OK);
	else
		return (SA_BAD_VALUE);
}

/*ARGSUSED*/
static int
signing_validator(int index, char *section, char *value)
{
	if (value == NULL)
		return (SA_BAD_VALUE);
	if (strlen(value) == 0)
		return (SA_OK);
	if (strcmp(value, "disabled") == 0 ||
	    strcmp(value, "enabled") == 0 ||
	    strcmp(value, "required") == 0)
		return (SA_OK);
	else
		return (SA_BAD_VALUE);
}

/*ARGSUSED*/
static int
password_validator(int index, char *section, char *value)
{
	char buffer[100];

	/* mangled passwords will start with this pattern */
	if (strlen(value) == 0)
		return (SA_OK);
	if (strncmp(value, "$$1", 3) != 0)
		return (SA_PASSWORD_ENC);
	if (smb_simpledecrypt(buffer, value) != 0)
		return (SA_BAD_VALUE);
	return (SA_OK);
}


/*
 * the protoset holds the defined options so we don't have to read
 * them multiple times
 */
sa_protocol_properties_t protoset;

static int
findprotoopt(char *name)
{
	int i;
	for (i = 0; smbclnt_proto_options[i].name != NULL; i++) {
		if (strcasecmp(smbclnt_proto_options[i].name, name) == 0)
			return (i);
	}
	return (-1);
}

/*
 * Load the persistent settings from SMF.  Each section is an SMF
 * property group with an "S-" prefix and a UUID, and the section
 * is itself a property which can have a more flexible name than
 * a property group name can have.  The section name need not be
 * the first property, so we have to be a little flexible, but
 * the change of name of the property groups is a reliable way
 * to know that we're seeing a different section.
 */
int
smbclnt_config_load()
{
	scf_simple_app_props_t *props = NULL;
	scf_simple_prop_t *prop = NULL, *lastprop = NULL;
	char *lastpgname = NULL, *pgname = NULL;
	char *name = NULL, *value = NULL;
	sa_property_t sect, node;

	props = scf_simple_app_props_get(NULL, SMBC_DEFAULT_INSTANCE_FMRI);
	if (props == NULL)
		return (-1);

	for (;;) {
		lastprop = prop;
		prop = (scf_simple_prop_t *)
		    scf_simple_app_props_next(props, lastprop);
		if (prop == NULL)
			break;

		/* Ignore properties that don't have our prefix */
		pgname = scf_simple_prop_pgname(prop);
		if (strncmp("S-", pgname, 2) != 0)
			continue;

		/*
		 * Note property group name changes, which mark sections
		 *
		 * The memory allocated by sa_create_section is
		 * linked into the list of children under protoset,
		 * and will eventually be freed via that list.
		 */
		if (lastpgname == NULL || strcmp(lastpgname, pgname) != 0) {
			sect = sa_create_section(NULL, pgname+2);
			(void) xmlSetProp(sect, (xmlChar *)"type",
			    (xmlChar *)SMBFS_PROTOCOL_NAME);
			(void) sa_add_protocol_property(protoset, sect);
			if (lastpgname)
				free(lastpgname);
			lastpgname = strdup(pgname);
		}
		name = scf_simple_prop_name(prop);
		value = scf_simple_prop_next_astring(prop);

		/* If we get a section name, apply it and consume it */
		if (strncmp("section", name, 7) == 0 && value != NULL) {
			(void) xmlSetProp(sect, (xmlChar *)"name",
			    (xmlChar *)value);
			continue;
		}

		/*
		 * We have an ordinary property.  Add to the section.
		 *
		 * The memory allocated by sa_create_property is
		 * linked into the list of children under "sect",
		 * and will eventually be freed via that list.
		 */
		node = sa_create_property(name, value);
		(void) sa_add_protocol_property(sect, node);
	}
	scf_simple_app_props_free(props);

	if (lastpgname)
		free(lastpgname);
	return (0);
}

/*
 * Save the set of properties for a particular section, which is
 * stored as a single property group.  Properties will have been
 * changed earlier by one or more calls to smbfs_save_property(),
 * which only set the value in our array and marked them as
 * SMBC_MODIFIED.
 */
int
smbfs_save_propset()
{
	smb_scfhandle_t *handle = NULL;
	char propgroup[256];
	char *section = smbclnt_proto_options[PROTO_OPT_SECTION].value;
	char *uu = NULL;
	uuid_t uuid;
	int i, ret = 0;
	sa_property_t propset;
	int new = 0, nonnull = 0;

	propset = sa_get_protocol_section(protoset, section);
	(void) strlcpy(propgroup, SMBC_PG_PREFIX, sizeof (propgroup));
	propgroup[SMBC_PG_PREFIX_LEN] = '\0';
	uu = sa_get_property_attr(propset, "extra");
	if (uu != NULL) {
		(void) strlcat(propgroup, uu, sizeof (propgroup));
		free(uu);
	} else {
		new = 1;
		smbclnt_proto_options[PROTO_OPT_SECTION].flags |= SMBC_MODIFIED;
		uuid_generate(uuid);
		uuid_unparse(uuid, &propgroup[SMBC_PG_PREFIX_LEN]);
	}

	handle = smb_smf_scf_init(SMBC_FMRI_PREFIX);
	if (handle == NULL) {
		return (1);
	}

	if ((ret = smb_smf_instance_create(handle, SMBC_FMRI_PREFIX,
	    SMBC_PG_INSTANCE)) != SMBC_SMF_OK) {
		goto out;
	}

	if ((ret = smb_smf_create_instance_pgroup(handle, propgroup))
	    != SMBC_SMF_OK) {
		goto out;
	}

	if ((ret = smb_smf_start_transaction(handle)) != SMBC_SMF_OK) {
		goto out;
	}

	for (i = PROTO_OPT_SECTION+1; i <= SMBC_OPT_MAX; i++) {
		if ((smbclnt_proto_options[i].flags & SMBC_MODIFIED) == 0)
			continue;
		if (strcmp(smbclnt_proto_options[i].value, "") == 0)
			ret = smb_smf_delete_property(handle,
			    smbclnt_proto_options[i].name);
		else {
			ret = smb_smf_set_string_property(handle,
			    smbclnt_proto_options[i].name,
			    smbclnt_proto_options[i].value);
			nonnull = 1;
		}
		free(smbclnt_proto_options[i].value);
		smbclnt_proto_options[i].value = NULL;
		smbclnt_proto_options[i].flags &= ~SMBC_MODIFIED;
		if (ret != SMBC_SMF_OK)
			goto outtrans;
	}
	/*
	 * Suppress new, null entries by not saving the section name.
	 */
	if (!new || nonnull) {
		ret = smb_smf_set_string_property(handle,
		    smbclnt_proto_options[PROTO_OPT_SECTION].name,
		    smbclnt_proto_options[PROTO_OPT_SECTION].value);
		free(smbclnt_proto_options[PROTO_OPT_SECTION].value);
		smbclnt_proto_options[PROTO_OPT_SECTION].value = NULL;
		smbclnt_proto_options[PROTO_OPT_SECTION].flags &=
		    ~SMBC_MODIFIED;
	}
	propset_changed = 0;

outtrans:
	ret = smb_smf_end_transaction(handle);
out:
	smb_smf_scf_fini(handle);
	return (ret);
}

/*
 * initprotofromdefault()
 *
 * read the default file(s) and add the defined values to the
 * protoset.  Note that default values are known from the built in
 * table in case the file doesn't have a definition.
 */

static int
initprotofromdefault()
{
	protoset = sa_create_protocol_properties(SMBFS_PROTOCOL_NAME);
	if (protoset == NULL)
		return (SA_NO_MEMORY);
	if (smbclnt_config_load() != 0)
		return (SA_OK);

	return (SA_OK);
}

/*
 *
 * smbfs_features()
 *
 * Report the plugin's features
 */
static uint64_t
smbfs_features()
{
	return (SA_FEATURE_HAS_SECTIONS | SA_FEATURE_ADD_PROPERTIES);
}

/*
 * smbfs_init()
 *
 * Initialize the smb plugin.
 */

static int
smbfs_init()
{
	int ret = SA_OK;

	if (sa_plugin_ops.sa_init != smbfs_init) {
		return (SA_SYSTEM_ERR);
	}

	if (initprotofromdefault() != SA_OK) {
		return (SA_SYSTEM_ERR);
	}

	return (ret);
}

/*
 * smbfs_fini()
 *
 * uninitialize the smb plugin. Want to avoid memory leaks.
 */

static void
smbfs_fini()
{
	if (propset_changed)
		(void) smbfs_save_propset();
	xmlFreeNode(protoset);
	protoset = NULL;
}

/*
 * smbfs_get_proto_set()
 *
 * Return an optionset with all the protocol specific properties in
 * it.
 */

static sa_protocol_properties_t
smbfs_get_proto_set()
{
	return (protoset);
}

/*
 * smbfs_validate_proto_prop(index, name, value)
 *
 * Verify that the property specifed by name can take the new
 * value. This is a sanity check to prevent bad values getting into
 * the default files.
 */
static int
smbfs_validate_proto_prop(int index, char *section, char *name, char *value)
{
	if ((section == NULL) || (name == NULL) || (index < 0))
		return (SA_BAD_VALUE);

	if (smbclnt_proto_options[index].validator == NULL)
		return (SA_OK);

	return (smbclnt_proto_options[index].validator(index, section, value));
}

/*
 * Save a property to our array; it will be stored to SMF later by
 * smbfs_save_propset().
 */
int
smbfs_save_property(int index, char *section, char *value)
{
	char *s;

	if (index == PROTO_OPT_WORKGROUP) {
		index = PROTO_OPT_DOMAIN;
	}
	propset_changed = 1;
	s = strdup(section);
	if (s == NULL)
		return (-1);
	smbclnt_proto_options[PROTO_OPT_SECTION].value = s;
	s = strdup(value);
	if (s == NULL)
		return (-1);
	smbclnt_proto_options[index].value = s;
	smbclnt_proto_options[index].flags |= SMBC_MODIFIED;
	return (0);
}

/*
 * smbfs_set_proto_prop(prop)
 *
 * check that prop is valid.
 */
/*ARGSUSED*/
static int
smbfs_set_proto_prop(sa_property_t prop)
{
	int ret = SA_OK;
	char *name;
	char *value;
	char *section;
	int i = -1;

	section = sa_get_property_attr(prop, "section");
	if (section == NULL)
		return (SA_NO_SECTION);
	name = sa_get_property_attr(prop, "type");
	value = sa_get_property_attr(prop, "value");
	if (name != NULL && value != NULL) {
		i = findprotoopt(name);
		if (i >= 0) {
			ret = smbfs_validate_proto_prop(i, section,
			    name, value);
			if (ret == SA_OK) {
				if (smbfs_save_property(i, section,
				    value) != 0) {
					ret = SA_SYSTEM_ERR;
					errno = EIO;
				}
			}
		} else
			ret = SA_INVALID_NAME;
	}
	if (name != NULL)
		sa_free_attr_string(name);
	if (value != NULL)
		sa_free_attr_string(value);
	if (section != NULL)
		sa_free_attr_string(section);

	return (ret);
}

/*
 * smbfs_get_status()
 *
 * What is the current status of the smbd? We use the SMF state here.
 * Caller must free the returned value.
 */

static char *
smbfs_get_status()
{
	return (smf_get_state(SMBC_DEFAULT_INSTANCE_FMRI));
}

/*
 * Delete a section by its name, which we will have read into an
 * XML optionset above.  We need to find it and find its UUID to
 * be able to generate the property group name in order to call
 * smbfs_delete_property_group().
 */
static int
smbfs_delete_section(char *section)
{
	char propgroup[256];
	char *uu = NULL;
	sa_property_t propset;
	int ret = SA_SYSTEM_ERR;

	propset = sa_get_protocol_section(protoset, section);
	(void) strlcpy(propgroup, SMBC_PG_PREFIX, sizeof (propgroup));
	propgroup[SMBC_PG_PREFIX_LEN] = '\0';
	uu = sa_get_property_attr(propset, "extra");
	if (uu == NULL)
		goto out;
	(void) strlcat(propgroup, uu, sizeof (propgroup));
	free(uu);
	if ((ret = smbfs_delete_property_group(propgroup)) != SMBC_SMF_OK)
		goto out;
	ret = SA_OK;
out:
	return (ret);
}

/*
 * Delete a property group by its name.  Called to do a 'delsect'
 * or called when smbclnt_config_load() notices an empty section
 * at the end of the properties.
 */
static int
smbfs_delete_property_group(char *propgroup)
{
	smb_scfhandle_t *handle = NULL;
	int ret = SA_SYSTEM_ERR;

	handle = smb_smf_scf_init(SMBC_FMRI_PREFIX);
	if (handle == NULL)
		goto out;

	if ((ret = smb_smf_instance_create(handle, SMBC_FMRI_PREFIX,
	    SMBC_PG_INSTANCE)) != SMBC_SMF_OK)
		goto out;

	if ((ret = smb_smf_delete_instance_pgroup(handle, propgroup))
	    != SMBC_SMF_OK)
		goto out;
	ret = SA_OK;
out:
	smb_smf_scf_fini(handle);
	return (ret);
}
