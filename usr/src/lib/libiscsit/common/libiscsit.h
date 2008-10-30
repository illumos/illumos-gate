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

#ifndef	_LIBISCSIT_H
#define	_LIBISCSIT_H

#ifndef _KERNEL
#include <libnvpair.h>
#include <sys/socket.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

#define	ISCSIT_MODNAME		"iscsit"
#define	ISCSIT_NODE		"/devices/pseudo/iscsit@0:iscsit"

#define	MAX_TPGT	256
#define	CFG_TPGTLIST	"tpgt-list"

/*
 * Object Hierarchy
 *
 *  _______________________
 * |                       |
 * |  iSCSI Target Config  |
 * |      it_config_t      |
 * |_______________________|
 *    |     |
 *    |     |
 *    |     |      ________     ________              ________
 *    |     |     |        |   |        |            |        |
 *    |     |     | Target |-->| Target |--  - -  -->| Target |
 *    |     |     |________|   |________|            |________|
 *    |     |           |
 *    |     |           |
 *    |     |           |
 *    |     |           |       ______              ______
 *    |     |           |      |      |            |      |
 *    |     |           +----->| TPGT |--  - -  -->| TPGT |
 *    |     |                  |______|            |______|
 *    |     |                       |                   |
 *    |  +--+                       |                   |
 *    |  |   _______     _______    |         ______    |
 *    |  |  |       |   |       |<--+        |      |<--+
 *    |  +->|  TPG  |-->|  TPG  |--  - -  -->| TPG  |
 *    |     |_______|   |_______|            |______|
 *    |
 *    |      ___________     ___________              ___________
 *    |     |           |   |           |            |           |
 *    +---->| Initiator |-->| Initiator |--  - -  -->| Initiator |
 *          |  Context  |   |  Context  |            |  Context  |
 *          |___________|   |___________|            |___________|
 *
 *
 * it_config_t includes a list of global properties
 *
 * Targets include a list of properties which override the global properties
 * if set
 *
 * Initiators also include a list of properties but never inherit properties
 * from the global config.
 */

/*  Maximum size of a Target Portal Group name */
#define	MAX_TPG_NAMELEN		256		/* XXX */

/* Maximum size of an iSCSI Target Node name */
#define	MAX_ISCSI_NODENAMELEN	256		/* XXX */

/*
 * A target portal group tag is a binding between a target and a target
 * portal group along with a numerical value associated with that binding.
 * The numerical identifier is used as the 'target portal group tag' defined
 * in RFC3720.
 *
 *  tpgt_tpg_name	The name of the target portal group associated with
 *			this target portal group tag.
 *  tpgt_generation	Generation number which is incremented each time the
 *			structure changes.
 *  tpgt_next		Next target portal group tag in th list of target portal
 *			group tags.  If tpgt_next is NUL, then this is the last
 *			target portal group in the list.
 *  tpgt_tag		A numerical identifier that uniquely identifies a
 *			target portal group within the associated target node.
 */
typedef struct it_tpgt_s {
	char			tpgt_tpg_name[MAX_TPG_NAMELEN];
	uint64_t		tpgt_generation;
	struct it_tpgt_s	*tpgt_next;
	uint16_t		tpgt_tag;
} it_tpgt_t;

/*
 * An iSCSI target node is represented by an it_tgt_structure.  Each
 * target node includes a list of associated target portal group tags
 * and a list of properties.
 *
 *  tgt_name		The iSCSI target node name in either IQN or EUI
 *			format (see RFC3720).
 *  tgt_generation	Generation number which is incremented each time
 *			the structure changes.
 *  tgt_next		Next target in the list of targets.  If tgt_next
 *			is NULL, then this is the last target in the list.
 *  tgt_tpgt_list	A linked list representing the current target
 *			portal group tags associated with this target.
 *  tgt_tpgt_count	The number of currently defined target portal
 *			group tags.
 *  tgt_properties	An nvlist representation of the properties
 *			associated with this target.  This list can be
 *			manipulated using libnvpair(3lib), and should be
 *			validated and stored using it_tgt_setprop().
 *
 * Target nvlist Properties:
 *
 *  nvlist Key		Type		Valid Values
 *  --------------------------------------------------------------------
 *  targetchapuser	string		any string or "none" to remove
 *  targetchapsecret	string		string of at least 12 characters
 *					but not more than 255 characters.
 *					secret will be base64 encoded when
 *					stored.
 *  alias		string		any string or "none" to remove
 *  auth		string		"radius", "chap", or "none"
 *
 */
typedef struct it_tgt_s {
	char			tgt_name[MAX_ISCSI_NODENAMELEN];
	uint64_t		tgt_generation;
	struct it_tgt_s		*tgt_next;
	it_tpgt_t		*tgt_tpgt_list;
	uint32_t		tgt_tpgt_count;
	nvlist_t		*tgt_properties;
} it_tgt_t;

/*
 * A target portal is represented by an IP address and a listening
 * TCP port.
 *
 *  portal_addr		sockaddr_storage structure representing the
 *			IPv4 or IPv6 address and TCP port associated
 *			with the portal.
 *  portal_next		Next portal in the list of portals.  If
 *			portal_next is NULL, this is the last portal
 *			in the list.
 */
typedef struct it_portal_s {
	struct sockaddr_storage portal_addr;
	struct it_portal_s	*next;
} it_portal_t;

/*
 * A portal is an IP address and TCP port and a portal group is a set
 * of portals.  Each defined portal belongs to exactly one portal group.
 * Applications can associate a target portal group with a particular
 * target using a target portal group name.  Initiators can only connect
 * to targets through the portals associated with the target's target
 * portal group tags.
 *
 *  tpg_name		Identifier for the target portal group.
 *  tpg_generation	Generation number which is incremented each
 *			time this structure changes.
 *  tpg_next		Next target portal group in the list of target
 *			portal groups.  If tpg_next is NULL, this is the
 *			last target portal group in the list.
 *  tpg_portal_count	Number of it_portal_t structures in the list.
 *  tpg_portal_list	Linked list of it_portal_t structures.
 */
typedef struct it_tpg_s {
	char			tpg_name[MAX_TPG_NAMELEN];
	uint64_t		tpg_generation;
	struct it_tpg_s		*tpg_next;
	uint32_t		tpg_portal_count;
	it_portal_t		*tpg_portal_list;
} it_tpg_t;

/*
 * A context representing a remote iSCSI initiator node.  The purpose
 * of this structure is to maintain information specific to a remote
 * initiator such as the CHAP username and CHAP secret.
 *
 *  ini_name		the iSCSI node name of the remote initiator.
 *  ini_generation	Generation number which is incremented each
 *			time this structure changes.
 *  ini_next		Next initiator in the list of initiators.
 *			If ini_next is NULL, this is the last initiator
 *			in the list.
 *  ini_properties	Name/Value list containing the properties
 *			associated with the initiator context.  This list
 *			can be manipulated using libnvpair(3lib), and should
 *			be validated and stored using it_ini_setprop().
 *
 * Initiator nvlist Properties:
 *
 *  nvlist Key		Type		Valid Values
 *  --------------------------------------------------------------------
 *  chapuser		string		any string
 *  chapsecret		string		string of at least 12 characters
 *					but not more than 255 characters.
 *					secret will be base64 encoded when
 *					stored.
 */
typedef struct it_ini_s {
	char		ini_name[MAX_ISCSI_NODENAMELEN];
	uint64_t	ini_generation;
	struct it_ini_s	*ini_next;
	nvlist_t	*ini_properties;
} it_ini_t;


/*
 * This structure represents a complete configuration for the iscsit
 * port provider.  In addition to the global configuration, it_config_t
 * includes lists of child objects including targets, target portal
 * groups and initiator contexts.  Each object includes a "generation"
 * value which is used by the iscsit kernel driver to identify changes
 * from one configuration update to the next.
 *
 *  stmf_token		A uint64_t that contains the value returned from a
 *			successful call to stmfGetProviderDataProt(3STMF).
 *			This token is used to verify that the configuration
 *			data persistently stored in COMSTAR has not been
 *			modified since this version was loaded.
 *  config_version	Version number for this configuration structure
 *  config_tgt_list	Linked list of target contexts representing the
 *			currently defined targets.  Applications can add
 *			targets to or remove targets from this list using
 *			the it_tgt_create and it_tgt_delete functions.
 *  config_tgt_count	The number of currently defined targets.
 *  config_tpg_list	Linked list of target portal group contexts.
 *			Applications can add or remove target portal groups
 *			to/from this list using the it_tpg_create and
 *			it_tpg_delete functions.
 *  config_tpg_count	The number of currently defined target portal groups
 *  config_ini_list	Linked list of initiator contexts.  Applications
 *			can add initiator contexts or remove initiator
 *			contexts from this list using the it_ini_create
 *			and it_ini_delete functions.
 *  config_ini_count	The number of currently defined initiator contexts.
 *  config_global_properties
 *			Name/Value list representing the current global
 *			property settings.  This list can be manipulated
 *			using libnvpair(3lib), and should be validated
 *			and stored using it_config_setprop().
 *  config_isns_svr_list
 *			Linked list of currently defined iSNS servers.
 *			Applications can add or remove iSNS servers by
 *			using the it_config_setprop() function and changing
 *			the array of iSNS servers stored in the "isnsserver"
 *			property.
 *  config_isns_svr_count
 *			The number of currently defined iSNS servers.
 *
 * Global nvlist Properties:
 *
 *  nvlist Key		Type		Valid Values
 *  --------------------------------------------------------------------
 *  alias		string		any string
 *  auth		string		"radius", "chap", or "none"
 *  isns		boolean		B_TRUE, B_FALSE
 *  isnsserver		string array	Array of portal specifications of
 *					the form IPaddress:port.  Port
 *					is optional; if not specified, the
 *					default iSNS port number of 3205 will
 *					be used.  IPv6 addresses should
 *					be enclosed in square brackets '[' ']'.
 *					If "none" is specified, all defined
 *					iSNS servers will be removed from the
 *					configuration.
 *  radiusserver	string		IPaddress:port specification as
 *					described for 'isnsserver'.
 *  radiussecret	string		string of at least 12 characters
 *					but not more than 255 characters.
 *					secret will be base64 encoded when
 *					stored.
 */
typedef struct it_config_s {
	uint64_t		stmf_token;
	uint32_t		config_version;
	it_tgt_t		*config_tgt_list;
	uint32_t		config_tgt_count;
	it_tpg_t		*config_tpg_list;
	uint32_t		config_tpg_count;
	it_ini_t		*config_ini_list;
	uint32_t		config_ini_count;
	it_portal_t		*config_isns_svr_list;
	uint32_t		config_isns_svr_count;
	nvlist_t		*config_global_properties;
} it_config_t;

/*
 * Function:  it_config_load()
 *
 * Allocate and create an it_config_t structure representing the
 * current iSCSI configuration.  This structure is compiled using
 * the 'provider' data returned by stmfGetProviderData().  If there
 * is no provider data associated with iscsit, the it_config_t
 * structure will be set to a default configuration.
 *
 * Parameters:
 *    cfg		A C representation of the current iSCSI configuration
 *
 * Return Values:
 *    0			Success
 *    ENOMEM		Could not allocate resources
 *    EINVAL		Invalid parameter
 */
int
it_config_load(it_config_t **cfg);

/*
 * Function:  it_config_commit()
 *
 * Informs the iscsit service that the configuration has changed and
 * commits the new configuration to persistent store by calling
 * stmfSetProviderData.  This function can be called multiple times
 * during a configuration sequence if necessary.
 *
 * Parameters:
 *    cfg		A C representation of the current iSCSI configuration
 *
 * Return Values:
 *    0			Success
 *    ENOMEM		Could not allocate resources
 *    EINVAL		Invalid it_config_t structure
 *    STMF_ERROR_SERVICE_DATA_VERSION	Configuration was updated by another
 *			client.  See stmfSetProviderDataProt().
 */
int
it_config_commit(it_config_t *cfg);

/*
 * Function:  it_config_setprop()
 *
 * Validate the provided property list and set the global properties
 * for iSCSI Target.  If errlist is not NULL, returns detailed
 * errors for each property that failed.  The format for errorlist
 * is key = property, value = error string.
 *
 * Parameters:
 *
 *    cfg		The current iSCSI configuration obtained from
 *			it_config_load()
 *    proplist		nvlist_t containing properties for this target.
 *    errlist		(optional)  nvlist_t of errors encountered when
 *			validating the properties.
 *
 * Return Values:
 *    0			Success
 *    ENOMEM		Could not allocate resources
 *    EINVAL		Invalid property
 *
 */
int
it_config_setprop(it_config_t *cfg, nvlist_t *proplist, nvlist_t **errlist);

/*
 * Function:  it_config_free()
 *
 * Free any resources associated with the it_config_t structure.
 *
 * Parameters:
 *    cfg		A C representation of the current iSCSI configuration
 */
void
it_config_free(it_config_t *cfg);

/*
 * Function:  it_tgt_create()
 *
 * Allocate and create an it_tgt_t structure representing a new iSCSI
 * target node.  If tgt_name is NULL, then a unique target node name will
 * be generated automatically.  Otherwise, the value of tgt_name will be
 * used as the target node name.  The new it_tgt_t structure is added to
 * the target list (cfg_tgt_list) in the configuration structure, and the
 * new target will not be instantiated until the modified configuration
 * is committed by calling it_config_commit().
 *
 * Parameters:
 *    cfg		The current iSCSI configuration obtained from
 *			it_config_load()
 *    tgt		Pointer to an iSCSI target structure
 *    tgt_name		The target node name for the target to be created.
 *			The name must be in either IQN or EUI format.  If
 *			this value is NULL, a node name will be generated
 *			automatically in IQN format.
 *
 * Return Values:
 *    0			Success
 *    ENOMEM		Could not allocate resources
 *    EINVAL		Invalid parameter
 *    EEXIST		The requested target node name is already configured
 *    EFAULT		Invalid iSCSI target name
 */
int
it_tgt_create(it_config_t *cfg, it_tgt_t **tgt, char *tgt_name);

/*
 * Function:  it_tgt_setprop()
 *
 * Validate the provided property list and set the properties for
 * the specified target.  If errlist is not NULL, returns detailed
 * errors for each property that failed.  The format for errorlist
 * is key = property, value = error string.
 *
 * Parameters:
 *
 *    cfg		The current iSCSI configuration obtained from
 *			it_config_load()
 *    tgt		Pointer to an iSCSI target structure
 *    proplist		nvlist_t containing properties for this target.
 *    errlist		(optional)  nvlist_t of errors encountered when
 *			validating the properties.
 *
 * Return Values:
 *    0			Success
 *    ENOMEM		Could not allocate resources
 *    EINVAL		Invalid property
 *
 */
int
it_tgt_setprop(it_config_t *cfg, it_tgt_t *tgt, nvlist_t *proplist,
    nvlist_t **errlist);


/*
 * Function:  it_tgt_delete()
 *
 * Delete target represented by 'tgt', where 'tgt' is an existing
 * it_tgt_t structure within the configuration 'cfg'.  The target removal
 * will not take effect until the modified configuration is committed
 * by calling it_config_commit().
 *
 * Parameters:
 *    cfg		The current iSCSI configuration obtained from
 *			it_config_load()
 *    tgt		Pointer to an iSCSI target structure
 *    force		Set the target to offline before removing it from
 *			the config.  If not specified, the operation will
 *			fail if the target is determined to be online.
 *
 * Return Values:
 *    0			Success
 *    EBUSY		Target is online
 */
int
it_tgt_delete(it_config_t *cfg, it_tgt_t *tgt, boolean_t force);

/*
 * Function:  it_tpgt_create()
 *
 * Allocate and create an it_tpgt_t structure representing a new iSCSI
 * target portal group tag.  The new it_tpgt_t structure is added to the
 * target tpgt list (tgt_tpgt_list) in the it_tgt_t structure.  The new
 * target portal group tag will not be instantiated until the modified
 * configuration is committed by calling it_config_commit().
 *
 * Parameters:
 *    cfg		The current iSCSI configuration obtained from
 *			it_config_load()
 *    tgt		Pointer to the iSCSI target structure associated
 *			with the target portal group tag
 *    tpgt		Pointer to a target portal group tag structure
 *    tpg_name		The name of the TPG to be associated with this TPGT
 *    tpgt_tag		16-bit numerical identifier for this TPGT.  Valid
 *			values are 2 through 65535.  If tpgt_tag is '0',
 *			this function will assign an appropriate tag number.
 *			If tpgt_tag is != 0, and the requested number is
 *			unavailable, another value will be chosen.
 *
 * Return Values:
 *    0			Success
 *    ENOMEM		Could not allocate resources
 *    EINVAL		Invalid parameter
 *    EEXIST		Specified TPG is already associated with the target
 *    E2BIG		All tag numbers already in use
 */
int
it_tpgt_create(it_config_t *cfg, it_tgt_t *tgt, it_tpgt_t **tpgt,
    char *tpg_name, uint16_t tpgt_tag);

/*
 * Function:  it_tpgt_delete()
 *
 * Delete the target portal group tag represented by 'tpgt', where
 * 'tpgt' is an existing is_tpgt_t structure within the target 'tgt'.
 * The target portal group tag removal will not take effect until the
 * modified configuation is committed by calling it_config_commit().
 *
 * Parameters:
 *    cfg		The current iSCSI configuration obtained from
 *			it_config_load()
 *    tgt		Pointer to the iSCSI target structure associated
 *			with the target portal group tag
 *    tpgt		Pointer to a target portal group tag structure
 */
void
it_tpgt_delete(it_config_t *cfg, it_tgt_t *tgt, it_tpgt_t *tpgt);

/*
 * Function:  it_tpg_create()
 *
 * Allocate and create an it_tpg_t structure representing a new iSCSI
 * target portal group.  The new it_tpg_t structure is added to the global
 * tpg list (cfg_tgt_list) in the it_config_t structure.  The new target
 * portal group will not be instantiated until the modified configuration
 * is committed by calling it_config_commit().
 *
 * Parameters:
 *    cfg		The current iSCSI configuration obtained from
 *			it_config_load()
 *    tpg		Pointer to the it_tpg_t structure representing
 *			the target portal group
 *    tpg_name		Identifier for the target portal group
 *    portal_ip_port	A string containing an appropriatedly formatted
 *			IP address:port.  Both IPv4 and IPv6 addresses are
 *			permitted.  This value becomes the first portal in
 *			the TPG -- applications can add additional values
 *			using it_portal_create() before committing the TPG.
 * Return Values:
 *    0			Success
 *    ENOMEM		Cannot allocate resources
 *    EINVAL		Invalid parameter
 *    EEXIST		Portal already configured for another portal group
 *			associated with this target.
 */
int
it_tpg_create(it_config_t *cfg, it_tpg_t **tpg, char *tpg_name,
    char *portal_ip_port);

/*
 * Function:  it_tpg_delete()
 *
 * Delete target portal group represented by 'tpg', where 'tpg' is an
 * existing it_tpg_t structure within the global configuration 'cfg'.
 * The target portal group removal will not take effect until the
 * modified configuration is committed by calling it_config_commit().
 *
 * Parameters:
 *    cfg		The current iSCSI configuration obtained from
 *			it_config_load()
 *    tpg		Pointer to the it_tpg_t structure representing
 *			the target portal group
 *    force		Remove this target portal group even if it's
 *			associated with one or more targets.
 *
 * Return Values:
 *    0			Success
 *    EINVAL		Invalid parameter
 *    EBUSY		Portal group associated with one or more targets.
 */
int
it_tpg_delete(it_config_t *cfg, it_tpg_t *tpg, boolean_t force);

/*
 * Function:  it_portal_create()
 *
 * Add an it_portal_t structure representing a new portal to the specified
 * target portal group.  The change to the target portal group will not take
 * effect until the modified configuration is committed by calling
 * it_config_commit().
 *
 * Parameters:
 *    cfg		The current iSCSI configration obtained from
 *			it_config_load()
 *    tpg		Pointer to the it_tpg_t structure representing the
 *			target portal group or "none" to remove
 *    portal		Pointer to the it_portal_t structure representing
 *			the portal
 *    portal_ip_port	A string containing an appropriately formatted
 *			IP address or IP address:port in either IPv4 or
 *			IPv6 format.
 * Return Values:
 *    0			Success
 *    ENOMEM		Could not allocate resources
 *    EINVAL		Invalid parameter
 *    EEXIST		Portal already configured for another portal group
 */
int
it_portal_create(it_config_t *cfg, it_tpg_t *tpg, it_portal_t **portal,
    char *portal_ip_port);

/*
 * Function:  it_portal_delete()
 *
 * Remove the specified portal from the specified target portal group.
 * The portal removal will not take effect until the modified configuration
 * is committed by calling it_config_commit().
 *
 * Parameters:
 *    cfg		The current iSCSI configration obtained from
 *			it_config_load()
 *    tpg		Pointer to the it_tpg_t structure representing the
 *			target portal group
 *    portal		Pointer to the it_portal_t structure representing
 *			the portal
 */
void
it_portal_delete(it_config_t *cfg, it_tpg_t *tpg, it_portal_t *portal);

/*
 * Function:  it_ini_create()
 *
 * Add an initiator context to the global configuration. The new
 * initiator context will not be instantiated until the modified
 * configuration is committed by calling it_config_commit().
 *
 * Parameters:
 *    cfg		The current iSCSI configration obtained from
 *			it_config_load()
 *    ini		Pointer to the it_ini_t structure representing
 *			the initiator context.
 *    ini_node_name	The iSCSI node name of the remote initiator.
 *
 * Return Values:
 *    0			Success
 *    ENOMEM		Could not allocate resources
 *    EINVAL		Invalid parameter.
 *    EEXIST		Initiator already configured
 *    EFAULT		Invalid initiator name
 */
int
it_ini_create(it_config_t *cfg, it_ini_t **ini, char *ini_node_name);

/*
 * Function:  it_ini_setprop()
 *
 * Validate the provided property list and set the initiator properties.
 * If errlist is not NULL, returns detailed errors for each property
 * that failed.  The format for errorlist is
 *		 key = property, value = error string.
 *
 * Parameters:
 *
 *    ini		The initiator being updated.
 *    proplist		nvlist_t containing properties for this target.
 *    errlist		(optional)  nvlist_t of errors encountered when
 *			validating the properties.
 *
 * Return Values:
 *    0			Success
 *    ENOMEM		Could not allocate resources
 *    EINVAL		Invalid property
 *
 */
int
it_ini_setprop(it_ini_t *ini, nvlist_t *proplist, nvlist_t **errlist);

/*
 * Function:  it_ini_delete()
 *
 * Remove the specified initiator context from the global configuration.
 * The removal will not take effect until the modified configuration is
 * committed by calling it_config_commit().
 *
 * Parameters:
 *    cfg		The current iSCSI configration obtained from
 *			it_config_load()
 *    ini		Pointer to the it_ini_t structure representing
 *			the initiator context.
 */
void
it_ini_delete(it_config_t *cfg, it_ini_t *ini);

/*
 * Function:  it_config_free()
 *
 * Free any resources associated with the it_config_t structure.
 *
 * Parameters:
 *    cfg       A C representation of the current iSCSI configuration
 */
void
it_config_free(it_config_t *cfg);

/*
 * Function:  it_tgt_free()
 *
 * Frees an it_tgt_t structure.  If tgt_next is not NULL, frees
 * all structures in the list.
 */
void
it_tgt_free(it_tgt_t *tgt);

/*
 * Function:  it_tpgt_free()
 *
 * Deallocates resources of an it_tpgt_t structure.  If tpgt->next
 * is not NULL, frees all members of the list.
 */
void
it_tpgt_free(it_tpgt_t *tpgt);

/*
 * Function:  it_tpg_free()
 *
 * Deallocates resources associated with an it_tpg_t structure.
 * If tpg->next is not NULL, frees all members of the list.
 */
void
it_tpg_free(it_tpg_t *tpg);

/*
 * Function:  it_ini_free()
 *
 * Deallocates resources of an it_ini_t structure. If ini->next is
 * not NULL, frees all members of the list.
 */
void
it_ini_free(it_ini_t *ini);

/*
 * Function:  validate_iscsi_name()
 *
 * Ensures the passed-in string is a valid IQN or EUI iSCSI name
 */
boolean_t
validate_iscsi_name(char *in_name);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBISCSIT_H */
