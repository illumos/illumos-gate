/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SDSSC_H
#define	_SDSSC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This header supports DiskSuite cluster operations and describes the
 * functions that isolate it from cluster implementation.
 */

#include <meta.h>
#include <metacl.h>
#include <sys/types.h>
#ifdef CLUSTER_LIBRARY_SOURCE
#include <sys/mhd.h>
#include <scadmin/scconf.h>
#include <scadmin/scswitch.h>
#include <scadmin/scstat.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define	SDSSC_PROXY_PRIMARY	((char *)1)
#define	SDSSC_CLASS		"sds"	/* Service class name */
#define	SDSSC_MO_CLASS		"multi-owner-svm"
#define	SDSSC_SERVICE_CMD	"sds_ownership"
#define	SDSSC_DEFAULT_PREFERENCE	0


/*
 * IMPORTANT: Any change to the metaset "-C" option interface shall
 * be reflected in this number. Changes which do not affect shell
 * parsing such as elimination of spaces or substitution of spaces
 * for \n or addition of new non-interfering features may be indicated
 * by incrementing the minor number in the version. Changes in content
 * require the major portion of the version be incremented. All changes
 * shall be discussed with and approved by our current contract partner(s).
 */
#define	METASETIFVERSION	"1.0"

/*
 * XXX - This should be in some general purpose header but I can't
 * find it anywhere. - JST
 */
#define	SDSSC_MD_DIR		"/dev/md"
#define	SDSSC_SET_PATH		SDSSC_MD_DIR "/shared"
#define	SDSSC_SETNO_LINK	"shared"

/* This is a cluster-specific directory. */
#define	SDSSC_CL_GLOBAL	"/global/.devices/node@"

/*
 * Cluster specific directory which contains libdid.so
 */
#define	SDSSC_CL_LIBDIR	"/usr/cluster/lib"
#define	SDSSC_DID_LIB	SDSSC_CL_LIBDIR "/libdid.so"

/*
 * This information can't change unless a corresponding change to SC3.0
 * upgrade process is made. When a HA1.3 or SC2.2 system is upgraded
 * to SC3.0, the upgrade process will create our services with the following
 * properties:
 * SDSSC_PROP_INDEX: the current set number on the old HA pair
 * SDSSC_PROP_STATE: SDSSC_STATE_COMMIT
 */
#define	SDSSC_PROP_COUNT	4		/* Number of store props */
#define	SDSSC_PROP_INDEX	"index"		/* One of the properties */
#define	SDSSC_PROP_NODE		"node"		/* ditto */
#define	SDSSC_PROP_INCAR	"incarnation"	/* ditto */
#define	SDSSC_PROP_STATE	"state"		/* ditto */

#define	SDSSC_STATE_COMMIT	"commit"	/* state values */
#define	SDSSC_STATE_CREATE	"create"	/* ditto */
#define	SDSSC_STATE_DEL		"delete"	/* ditto */

/*
 * When creating services in the DCS the index used is either set
 * by the calling routine or sdssc_create_begin will pick the next
 * available one. To have the next available one picked the following
 * define should be used as the forth argument.
 */
#define	SDSSC_PICK_SETNO	0

/*
 * The following number was lifted from the Cluster Project source
 * code. Apparently they don't believe in using #define for constants.
 * For now we'll create one.
 */
#define	SDSSC_NODE_NAME_LEN 64

/*
 * We need to malloc a small amount of space for property values.
 * The two values are integer strings with a value of 1 to 64.
 */
#define	SDSSC_NODE_INDEX_LEN	20

/*
 * The maximum number of metadevices in a set is currently limited
 * to 8192.
 */
#define	SDSSC_METADDEV_MAX	8192

/*
 * To avoid the need for two separate files with definitions for the libraries
 * entry points the following macro is being used. CLUSTER_LIBRARY_SOURCE
 * is only defined in the libsdssc source just as the name implies. The
 * reference below becomes a function prototype. Otherwise a pointer to a
 * function is defined which can be used elsewhere in the commands.
 */
#ifdef CLUSTER_LIBRARY_SOURCE
#define	REF(method, args) _##method args
#else
#define	REF(method, args) (* method) args
#endif

struct sdssc_version {
	int	major;
	int	minor;
	int	library_level;
};

typedef struct {
	char	*fname;		/* function name found in library */
	void	**fptr;		/* pointer to storage for global pointer */
} func_table_t, *func_table_p;

enum rval1 {
	/*
	 * Function executed without errors. Duh
	 */
	SDSSC_OKAY,

	/*
	 * Some generic error condition occurred
	 */
	SDSSC_ERROR,

	/*
	 * sdssc_cmd_proxy was able to execute the command
	 * remotely.
	 */
	SDSSC_PROXY_DONE,

	/*
	 * When the libsds_sc.so is not found or the system isn't
	 * part of a cluster the interface routines will return this
	 * as indication
	 */
	SDSSC_NOT_BOUND,

	/*
	 * If the service isn't found in the CCR sdssc_get_primary
	 * will this enumeration.
	 */
	SDSSC_NO_SERVICE,

	/*
	 * When the libsds_sc.so is found, but this specific routine failed
	 * to bind, then this interface routine will return this error.
	 * This error indicates that an older version of the libsds_sc.so
	 * library which does not support this routine.
	 */
	SDSSC_NOT_BOUND_ERROR

};
enum dcs_state { SDSSC_COMMIT, SDSSC_CLEANUP };
enum sds_boolean { SDSSC_True, SDSSC_False };
enum sdssc_dcs_notify {	Make_Primary, Release_Primary, Shutdown_Services };

typedef enum rval1 rval_e;
typedef enum dcs_state dcs_set_state_e;
typedef struct sdssc_version sdssc_version_t;
typedef enum sds_boolean sdssc_boolean_e;
typedef enum sdssc_dcs_notify sdssc_dcs_notify_e;

rval_e sdssc_bind_library(void);
rval_e REF(sdssc_version, (sdssc_version_t *));
rval_e REF(sdssc_create_begin, (char *, int, char **, int));
rval_e REF(sdssc_mo_create_begin, (char *, int, char **, int));
rval_e REF(sdssc_create_end, (char *, dcs_set_state_e));
rval_e REF(sdssc_delete_begin, (char *));
rval_e REF(sdssc_delete_end, (char *, dcs_set_state_e));
rval_e REF(sdssc_get_index, (char *, set_t *));
rval_e REF(sdssc_add_hosts, (char *, int, char **));
rval_e REF(sdssc_delete_hosts, (char *, int, char **));
rval_e REF(sdssc_get_primary_host, (char *, char *, int));
rval_e REF(sdssc_cmd_proxy, (int, char **, char *host, int *));
rval_e REF(sdssc_getnodelist, (int **));
void REF(sdssc_freenodelist, (int *));
mdc_errno_t REF(sdssc_binddevs, (void));
rval_e REF(sdssc_gettransportbynode, (int, char **));
rval_e REF(sdssc_bindclusterdevs, (mdc_err_t ***));
void REF(sdssc_free_mdcerr_list, (mdc_err_t **));
rval_e REF(sdssc_clnt_bind_devs, (char *, mdc_err_t *));
rval_e REF(sdssc_property_get, (char *, char *, char **));
rval_e REF(sdssc_property_set, (char *, char *, char *));
rval_e REF(sdssc_get_services, (char ***));
rval_e REF(sdssc_get_services_free, (char **));
rval_e REF(sdssc_suspend, (const char *));
rval_e REF(sdssc_convert_cluster_path, (const char *, char **));
rval_e REF(sdssc_convert_ctd_path, (const char *, char **));
void REF(sdssc_convert_path_free, (char *));
rval_e REF(sdssc_notify_service, (const char *, sdssc_dcs_notify_e));
void REF(sdssc_cm_nm2nid, (char *));
void REF(sdssc_cm_sr_nm2nid, (md_set_record *));
void REF(sdssc_cm_nid2nm, (char *));
void REF(sdssc_cm_sr_nid2nm, (md_set_record *));
rval_e REF(sdssc_get_priv_ipaddr, (char *, struct in_addr *));
rval_e REF(sdssc_clnt_proxy_cmd, (uint_t, char **, uint_t, char **,
    char *, mdc_err_t *));

#ifdef CLUSTER_LIBRARY_SOURCE
/*
 * Support routines used with libsds_sc.so and not for public
 * consumption (see mapfile-vers for scoping).
 */
rval_e l_get_property(scconf_cfg_ds_t *, char *, char **);
void *l_get_incarnation(int);
char *l_incarnation_to_prop(int);
void *l_prop_to_incarnation(char *);
sdssc_boolean_e l_compare_incarnation(void *, void *);
rval_e l_build_hostlist(scconf_nodeid_t *, char ***);
#endif
#ifdef __cplusplus
}
#endif

#endif /* _SDSSC_H */
