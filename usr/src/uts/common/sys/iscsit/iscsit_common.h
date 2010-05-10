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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _ISCSIT_COMMON_H_
#define	_ISCSIT_COMMON_H_

#ifdef	_KERNEL
#include <sys/nvpair.h>
#else
#include <libnvpair.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define	ISCSIT_API_VERS0		0

#define	ISCSIT_MODNAME		"iscsit"
#define	ISCSIT_NODE		"/devices/pseudo/iscsit@0:iscsit"

typedef enum {
	ITCFG_SUCCESS = 0,
	ITCFG_INVALID,
	ITCFG_TGT_CREATE_ERR,
	ITCFG_MISC_ERR
} it_cfg_status_t;

/*
 * This structure is passed back to the driver during ISCSIT_IOC_ENABLE_SVC
 * in order to provide the fully qualified hostname for use as the EID
 * by iSNS.
 */

#define	ISCSIT_MAX_HOSTNAME_LEN	256

typedef struct iscsit_hostinfo_s {
	uint32_t	length;
	char		fqhn[ISCSIT_MAX_HOSTNAME_LEN];
} iscsit_hostinfo_t;

#define	ISCSIT_IOC_SET_CONFIG		1
#define	ISCSIT_IOC_GET_STATE		2
#define	ISCSIT_IOC_ENABLE_SVC		101
#define	ISCSIT_IOC_DISABLE_SVC		102

/* XXX Rationalize these with other error values (used in it_smf.c */
#define	ITADM_SUCCESS		0
#define	ITADM_FATAL_ERROR	0x1
#define	ITADM_NO_MEM		0x2
#define	ITADM_INVALID		0x4
#define	ITADM_NODATA		0x8
#define	ITADM_PERM		0x10


#define	PROP_AUTH		"auth"
#define	PROP_ALIAS		"alias"
#define	PROP_CHAP_USER		"chapuser"
#define	PROP_CHAP_SECRET	"chapsecret"
#define	PROP_TARGET_CHAP_USER	"targetchapuser"
#define	PROP_TARGET_CHAP_SECRET	"targetchapsecret"
#define	PROP_RADIUS_SERVER	"radiusserver"
#define	PROP_RADIUS_SECRET	"radiussecret"
#define	PROP_ISNS_ENABLED	"isns"
#define	PROP_ISNS_SERVER	"isnsserver"
#define	PROP_OLD_TARGET_NAME	"oldtargetname"

#define	PA_AUTH_RADIUS		"radius"
#define	PA_AUTH_CHAP		"chap"
#define	PA_AUTH_NONE		"none"

typedef struct {
	int		set_cfg_vers;
	int		set_cfg_pnvlist_len;
	caddr_t		set_cfg_pnvlist;
} iscsit_ioc_set_config_t;

typedef struct {
	int		getst_vers;
	int		getst_pnvlist_len;
	char		*getst_pnvlist;
} iscsit_ioc_getstate_t;

#ifdef _SYSCALL32
typedef struct {
	int		set_cfg_vers;
	int		set_cfg_pnvlist_len;
	caddr32_t	set_cfg_pnvlist;
} iscsit_ioc_set_config32_t;

typedef struct {
	int		getst_vers;
	int		getst_pnvlist_len;
	caddr32_t	getst_pnvlist;
} iscsit_ioc_getstate32_t;
#endif /* _SYSCALL32 */

/* Shared user/kernel structures */
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
	struct it_portal_s	*portal_next;
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


/*  Functions to convert iSCSI target structures to/from nvlists. */
int
it_config_to_nv(it_config_t *cfg, nvlist_t **nvl);

/*
 * nvlist version of config is 3 list-of-list, + 1 proplist.  arrays
 * are interesting, but lists-of-lists are more useful when doing
 * individual lookups when we later add support for it.  Also, no
 * need to store name in individual struct representation.
 */
int
it_nv_to_config(nvlist_t *nvl, it_config_t **cfg);

int
it_nv_to_tgtlist(nvlist_t *nvl, uint32_t *count, it_tgt_t **tgtlist);

int
it_tgtlist_to_nv(it_tgt_t *tgtlist, nvlist_t **nvl);

int
it_tgt_to_nv(it_tgt_t *tgt, nvlist_t **nvl);

int
it_nv_to_tgt(nvlist_t *nvl, char *name, it_tgt_t **tgt);

int
it_tpgt_to_nv(it_tpgt_t *tpgt, nvlist_t **nvl);

int
it_nv_to_tpgt(nvlist_t *nvl, char *name, it_tpgt_t **tpgt);

int
it_tpgtlist_to_nv(it_tpgt_t *tpgtlist, nvlist_t **nvl);

int
it_nv_to_tpgtlist(nvlist_t *nvl, uint32_t *count, it_tpgt_t **tpgtlist);

int
it_tpg_to_nv(it_tpg_t *tpg, nvlist_t **nvl);

int
it_nv_to_tpg(nvlist_t *nvl, char *name, it_tpg_t **tpg);

int
it_tpglist_to_nv(it_tpg_t *tpglist, nvlist_t **nvl);

int
it_nv_to_tpglist(nvlist_t *nvl, uint32_t *count, it_tpg_t **tpglist);

int
it_ini_to_nv(it_ini_t *ini, nvlist_t **nvl);

int
it_nv_to_ini(nvlist_t *nvl, char *name, it_ini_t **ini);

int
it_inilist_to_nv(it_ini_t *inilist, nvlist_t **nvl);

int
it_nv_to_inilist(nvlist_t *nvl, uint32_t *count, it_ini_t **inilist);

it_tgt_t *
it_tgt_lookup(it_config_t *cfg, char *tgt_name);

it_tpg_t *
it_tpg_lookup(it_config_t *cfg, char *tpg_name);

it_portal_t *
it_sns_svr_lookup(it_config_t *cfg, struct sockaddr_storage *sa);

it_portal_t *
it_portal_lookup(it_tpg_t *cfg_tpg, struct sockaddr_storage *sa);

int
it_sa_compare(struct sockaddr_storage *sa1, struct sockaddr_storage *sa2);

/*
 * Convert a sockaddr to the string representation, suitable for
 * storing in an nvlist or printing out in a list.
 */
int
sockaddr_to_str(struct sockaddr_storage *sa, char **addr);

/*
 * Convert a char string to a sockaddr structure
 *
 * default_port should be the port to be used, if not specified
 * as part of the supplied string 'arg'.
 */
struct sockaddr_storage *
it_common_convert_sa(char *arg, struct sockaddr_storage *buf,
    uint32_t default_port);

/*
 * Convert an string array of IP-addr:port to a portal list
 */
int
it_array_to_portallist(char **arr, uint32_t count, uint32_t default_port,
    it_portal_t **portallist, uint32_t *list_count);

/*
 * Function:  it_config_free_cmn()
 *
 * Free any resources associated with the it_config_t structure.
 *
 * Parameters:
 *    cfg       A C representation of the current iSCSI configuration
 */
void
it_config_free_cmn(it_config_t *cfg);

/*
 * Function:  it_tgt_free_cmn()
 *
 * Frees an it_tgt_t structure.  If tgt_next is not NULL, frees
 * all structures in the list.
 */
void
it_tgt_free_cmn(it_tgt_t *tgt);

/*
 * Function:  it_tpgt_free_cmn()
 *
 * Deallocates resources of an it_tpgt_t structure.  If tpgt->next
 * is not NULL, frees all members of the list.
 */
void
it_tpgt_free_cmn(it_tpgt_t *tpgt);

/*
 * Function:  it_tpg_free_cmn()
 *
 * Deallocates resources associated with an it_tpg_t structure.
 * If tpg->next is not NULL, frees all members of the list.
 */
void
it_tpg_free_cmn(it_tpg_t *tpg);

/*
 * Function:  it_ini_free_cmn()
 *
 * Deallocates resources of an it_ini_t structure. If ini->next is
 * not NULL, frees all members of the list.
 */
void
it_ini_free_cmn(it_ini_t *ini);

/*
 * Function:  iscsi_binary_to_base64_str()
 *
 * Encodes a byte array into a base64 string.
 */
int
iscsi_binary_to_base64_str(uint8_t *in_buf, int in_buf_len,
    char *base64_str_buf, int base64_buf_len);

/*
 * Function:  iscsi_base64_str_to_binary()
 *
 * Decodes a base64 string into a byte array
 */
int
iscsi_base64_str_to_binary(char *hstr, int hstr_len,
    uint8_t *binary, int binary_buf_len, int *out_len);

#ifdef __cplusplus
}
#endif

#endif /* _ISCSIT_COMMON_H_ */
