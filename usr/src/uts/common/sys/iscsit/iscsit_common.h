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

#ifndef _ISCSIT_COMMON_H_
#define	_ISCSIT_COMMON_H_

#ifdef	_KERNEL
#include <sys/nvpair.h>
#else
#include <libnvpair.h>
#endif
/*
 * XXX Need to reverse this dependency, libiscsit.h should include
 * iscsit_common.h, and iscsit_common.h should have all the core
 * definitions.  Kernel drivers should not pull in library header files.
 */
#include <libiscsit.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	ISCSIT_API_VERS0		0

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
