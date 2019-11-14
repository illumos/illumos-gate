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
 */
/*
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef	_LIBISCSIT_H
#define	_LIBISCSIT_H

#ifndef _KERNEL
#include <libnvpair.h>
#include <sys/socket.h>
#endif

#include <sys/iscsit/iscsit_common.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	MAX_TARGETS	4095 /* maximum targets that may be created */
#define	MAX_TPGT	256
#define	CFG_TPGTLIST	"tpgt-list"

#define	IS_IQN_NAME(s) (strncmp((s), "iqn.", 4) == 0)
#define	IS_EUI_NAME(s) (strncmp((s), "eui.", 4) == 0)

/*
 * We change the default IQN here to org.illumos.
 * Other distros using it need to change accordingly.
 */

#define	DEFAULT_IQN	"iqn.2010-08.org.illumos:"

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
 *    EINVAL		Invalid parameter or creating would create too many
 *			targets.
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

/*
 * Function:  canonical_iscsi_name()
 *
 * Fold the iqn iscsi name to lower-case and the EUI-64 identifier of
 * the eui iscsi name to upper-case.
 * Ensures the passed-in string is a valid IQN or EUI iSCSI name
 */
void
canonical_iscsi_name(char *tgt);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBISCSIT_H */
