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

#ifndef _CFG_CLUSTER_H
#define	_CFG_CLUSTER_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This file is a combination of interfaces culled from scstat.h,
 * scconf.h and the header files that they include.
 *
 * It exposes a subset of the interfaces defined in PSARC/2001/261
 * for use in NWS software.
 */

#include <sys/errno.h>
#include <sys/types.h>

/*
 * From sc_syslog_msg.h
 */

typedef enum sc_state_code_enum {
	ONLINE = 1,	/* resource is running */
	OFFLINE,	/* resource is stopped due to user action */
	FAULTED,	/* resource is stopped due to a failure */
	DEGRADED,	/* resource is running but has a minor problem */
	WAIT,		/* resource is in transition from a state to another */

	/*
	 * resource is monitored but state of the resource is
	 * not known because either the monitor went down or
	 * the monitor cannot report resource state temporarily.
	 */
	UNKNOWN,

	NOT_MONITORED	/* There is no monitor to check state of the resource */
} sc_state_code_t;

/*
 * End sc_syslog_msg.h
 */


/*
 * From scstat.h
 */

#define	SCSTAT_MAX_STRING_LEN	1024

/* Error codes returned by scstat functions. */
/* This definition is covered by PSARC/2001/261.  DO NOT change it. */
typedef enum scstat_errno {
	SCSTAT_ENOERR,		/* normal return - no error */
	SCSTAT_EUSAGE,		/* syntax error */
	SCSTAT_ENOMEM,		/* not enough memory */
	SCSTAT_ENOTCLUSTER,	/* not a cluster node */
	SCSTAT_ENOTCONFIGURED,	/* not found in CCR */
	SCSTAT_ESERVICENAME,	/* dcs: invalid service name */
	SCSTAT_EINVAL,		/* scconf: invalid argument */
	SCSTAT_EPERM,		/* not root */
	SCSTAT_ECLUSTERRECONFIG, /* cluster is reconfiguring */
	SCSTAT_ERGRECONFIG,	/* RG is reconfiguring */
	SCSTAT_EOBSOLETE,	/* Resource/RG has been updated */
	SCSTAT_EUNEXPECTED	/* internal or unexpected error */
} scstat_errno_t;

/* States a resource can be in */
/* This definition is covered by PSARC/2001/261.  DO NOT change it. */
typedef enum scstat_state_code {
	SCSTAT_ONLINE = ONLINE,		/* resource is running */
	SCSTAT_OFFLINE = OFFLINE, /* resource stopped due to user action */
	SCSTAT_FAULTED = FAULTED, /* resource stopped due to a failure */
	SCSTAT_DEGRADED = DEGRADED, /* resource running with a minor problem */
	SCSTAT_WAIT = WAIT,		/* resource is in transition */
	SCSTAT_UNKNOWN = UNKNOWN,	/* resource state is unknown */
	SCSTAT_NOTMONITORED = NOT_MONITORED	/* resource is not monitored */
} scstat_state_code_t;

/* States a replica of a resource can be in */
/* This definition is covered by PSARC/2001/261.  DO NOT change it. */
typedef enum scstat_node_pref {
	SCSTAT_PRIMARY,		/* replica is a primary */
	SCSTAT_SECONDARY,	/* replica is a secondary */
	SCSTAT_SPARE,		/* replica is a spare */
	SCSTAT_INACTIVE,	/* replica is inactive */
	SCSTAT_TRANSITION,	/* replica is changing state */
	SCSTAT_INVALID		/* replica is in an invalid state */
} scstat_node_pref_t;

/* component name */
typedef char *scstat_name_t;
typedef scstat_name_t scstat_cluster_name_t;	/* cluster name */
typedef scstat_name_t scstat_node_name_t;	/* node name */
typedef scstat_name_t scstat_adapter_name_t;	/* adapter name */
typedef scstat_name_t scstat_path_name_t;	/* path name */
typedef scstat_name_t scstat_ds_name_t;		/* device service name */
typedef scstat_name_t scstat_quorumdev_name_t;	/* quorum device name */
typedef scstat_name_t scstat_rs_name_t;		/* resource name */
typedef scstat_name_t scstat_rg_name_t;		/* rg name */

/* status string */
typedef char *scstat_statstr_t;
typedef scstat_statstr_t scstat_node_statstr_t;		/* node status */
typedef scstat_statstr_t scstat_path_statstr_t;		/* path status */
typedef scstat_statstr_t scstat_ds_statstr_t;		/* DS status */
typedef scstat_statstr_t scstat_node_quorum_statstr_t;	/* node quorum status */
typedef scstat_statstr_t scstat_quorumdev_statstr_t; 	/* quorum device stat */

/* ha device node status list */
/* This definition is covered by PSARC/2001/261.  DO NOT change it. */
typedef struct scstat_ds_node_state_struct {
	/* node name */
	scstat_node_name_t			scstat_node_name;
	/* node status */
	scstat_node_pref_t			scstat_node_state;
	/* next */
	struct scstat_ds_node_state_struct	*scstat_node_next;
} scstat_ds_node_state_t;

/* Cluster node status */
/* This definition is covered by PSARC/2001/261.  DO NOT change it. */
typedef struct scstat_node_struct {
	scstat_node_name_t	scstat_node_name;	/* node name */
	scstat_state_code_t	scstat_node_status;	/* cluster membership */
	scstat_node_statstr_t	scstat_node_statstr;	/* node status string */
	void			*pad;			/* Padding for */
							/* PSARC/2001/261. */
	struct scstat_node_struct *scstat_node_next;	/* next */
} scstat_node_t;

/* Cluster ha device status */
/* This definition is covered by PSARC/2001/261.  DO NOT change it. */
typedef struct scstat_ds_struct {
	/* ha device name */
	scstat_ds_name_t		scstat_ds_name;
	/* ha device status */
	scstat_state_code_t		scstat_ds_status;
	/* ha device statstr */
	scstat_ds_statstr_t		scstat_ds_statstr;
	/* node preference list */
	scstat_ds_node_state_t		*scstat_node_state_list;
	/* next */
	struct scstat_ds_struct		*scstat_ds_next;
} scstat_ds_t;

/*
 * scstat_strerr
 *
 * Map scstat_errno_t to a string.
 *
 * The supplied "errbuffer" should be of at least SCSTAT_MAX_STRING_LEN
 * in length.
 */
/* This definition is covered by PSARC/2001/261.  DO NOT change it. */
void scstat_strerr(scstat_errno_t, char *);

/*
 * Upon success, a list of objects of scstat_node_t are returned.
 * The caller is responsible for freeing the space.
 *
 * Possible return values:
 *
 *	SCSTAT_NOERR		- success
 *	SCSTAT_ENOMEM		- not enough memory
 *	SCSTAT_EPERM            - not root
 *      SCSTAT_ENOTCLUSTER      - there is no cluster
 *      SCCONF_EINVAL           - invalid argument
 *	SCSTAT_EUNEXPECTED	- internal or unexpected error
 */
/* This definition is covered by PSARC/2001/261.  DO NOT change it. */
scstat_errno_t scstat_get_nodes(scstat_node_t **pplnodes);

/*
 * Free all memory associated with a scstat_node_t structure.
 */
/* This definition is covered by PSARC/2001/261.  DO NOT change it. */
void scstat_free_nodes(scstat_node_t *plnodes);

/*
 * If the device service name passed in is NULL, then this function returns
 * the status of all device services, otherwise it returns the status of the
 * device service specified.
 * The caller is responsible for freeing the space.
 *
 * Possible return values:
 *
 *	SCSTAT_ENOERR		- success
 *	SCSTAT_ENOMEM		- not enough memory
 *	SCSTAT_EPERM            - not root
 *      SCSTAT_ENOTCLUSTER      - there is no cluster
 *      SCCONF_EINVAL           - invalid argument
 *	SCSTAT_ESERVICENAME	- invalid device group name
 *	SCSTAT_EUNEXPECTED	- internal or unexpected error
 */
/* This definition is covered by PSARC/2001/261.  DO NOT change it. */
scstat_errno_t scstat_get_ds_status(scstat_ds_name_t *dsname,
    scstat_ds_t **dsstatus);

/*
 * Free memory associated with a scstat_ds_t structure.
 */
/* This definition is covered by PSARC/2001/261.  DO NOT change it. */
void scstat_free_ds_status(scstat_ds_t *dsstatus);

/*
 * End scstat.h
 */

/*
 * From scconf.h
 */

/* Maximum message string length */
#define	SCCONF_MAXSTRINGLEN	1024

/* This definition is covered by PSARC/2001/261.  DO NOT change it. */
typedef enum scconf_errno {
	SCCONF_NOERR = 0,		/* normal return - no error */
	SCCONF_EPERM = 1,		/* permission denied */
	SCCONF_EEXIST = 2,		/* object already exists */
	SCCONF_ENOEXIST = 3,		/* object does not exist */
	SCCONF_ESTALE = 4,		/* object or handle is stale */
	SCCONF_EUNKNOWN = 5,		/* unkown type */
	SCCONF_ENOCLUSTER = 6,		/* cluster does not exist */
	SCCONF_ENODEID = 7,		/* ID used in place of node name */
	SCCONF_EINVAL = 8,		/* invalid argument */
	SCCONF_EUSAGE = 9,		/* command usage error */
	SCCONF_ETIMEDOUT = 10,		/* call timed out */
	SCCONF_EINUSE = 11,		/* already in use */
	SCCONF_EBUSY = 12,		/* busy, try again later */
	SCCONF_EINSTALLMODE = 13,	/* install mode */
	SCCONF_ENOMEM = 14,		/* not enough memory */
	SCCONF_ESETUP = 15,		/* setup attempt failed */
	SCCONF_EUNEXPECTED = 16,	/* internal or unexpected error */
	SCCONF_EBADVALUE = 17,		/* bad ccr table value */
	SCCONF_EOVERFLOW = 18,		/* message buffer overflow */
	SCCONF_EQUORUM = 19,		/* operation would compromise quorum */
	SCCONF_TM_EBADOPTS = 20,	/* bad transport TM "options" */
	SCCONF_TM_EINVAL = 21,		/* other transport TM error */
	SCCONF_DS_ESUSPENDED = 22,	/* Device service in suspended state */
	SCCONF_DS_ENODEINVAL = 23,	/* Node specified is not in cluster */
	SCCONF_EAUTH = 24,		/* authentication error */
	SCCONF_DS_EINVAL = 25,		/* Device service in an invalid state */
	SCCONF_EIO = 26			/* IO error */
} scconf_errno_t;

/* IDs */
/* This definition is covered by PSARC/2001/261.  DO NOT change it. */
typedef uint_t scconf_id_t;

/* This definition is covered by PSARC/2001/261.  DO NOT change it. */
typedef scconf_id_t scconf_nodeid_t;		/* node ID */

/* Cluster transport handle */
/* This definition is covered by PSARC/2001/261.  DO NOT change it. */
typedef void *		scconf_cltr_handle_t;

/* This definition is covered by PSARC/2001/261.  DO NOT change it. */
extern scconf_errno_t scconf_get_nodeid(char *nodename,
    scconf_nodeid_t *nodeidp);

/*
 * Get the name of a node from its "nodeid".  Upon success,
 * a pointer to the nodename is left in "nodenamep".
 *
 * It is the caller's responsibility to free memory allocated
 * for "nodename" using free(3C).
 *
 * Possible return values:
 *
 *	SCCONF_NOERR		- success
 *	SCCONF_EPERM		- not root
 *	SCCONF_ENOCLUSTER	- there is no cluster
 *	SCCONF_ENOMEM		- not enough memory
 *	SCCONF_EINVAL		- invalid argument
 *	SCCONF_EUNEXPECTED	- internal or unexpected error
 */
/* This definition is covered by PSARC/2001/261.  DO NOT change it. */
extern scconf_errno_t scconf_get_nodename(scconf_nodeid_t nodeid,
    char **nodenamep);

/*
 * Map scconf_errno_t to a string.
 *
 * The supplied "errbuffer" should be of at least SCCONF_MAXSTRINGLEN
 * in length.
 */
/* This definition is covered by PSARC/2001/261.  DO NOT change it. */
extern void scconf_strerr(char *errbuffer, scconf_errno_t err);

/*
 * Given a dev_t value, return the name of device service that contains this
 * device.
 *
 * The caller is responsible for freeing the memory returned in "name".
 *
 * Possible return values:
 *
 *      SCCONF_NOERR            - success
 *      SCCONF_EPERM            - not root
 *      SCCONF_ENOEXIST         - the given device is not configured
 *      SCCONF_ENOMEM           - not enough memory
 *      SCCONF_ENOCLUSTER       - cluster config does not exist
 *      SCCONF_EUNEXPECTED      - internal or unexpected error
 */
/* This definition is covered by PSARC/2001/261.  DO NOT change it. */
extern scconf_errno_t scconf_get_ds_by_devt(major_t maj, minor_t min,
    char **dsname);

/*
 * End scconf.h
 */

#ifdef	__cplusplus
}
#endif

#endif /* _CFG_CLUSTER_H */
