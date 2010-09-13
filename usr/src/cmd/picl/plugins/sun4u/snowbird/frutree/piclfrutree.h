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

#ifndef	_PICLFRUTREE_H
#define	_PICLFRUTREE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <syslog.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef enum {
	NONE		= 0x0,
	FRUTREE_INIT 	= 0x1,
	EVENTS 		= 0x2,
	HASHTABLE 	= 0x4,
	PERF_DATA	= 0x8,
	EV_COMPLETION	= 0x10,
	PRINT_ALL	= 0xFF
} frutree_debug_t;

#define	FRUTREE_DEBUG0(lvl, fmt) \
	if (lvl & frutree_debug) { \
		syslog(LOG_DEBUG, fmt);	\
	}
#define	FRUTREE_DEBUG1(lvl, fmt, d1) \
	if (lvl & frutree_debug) { \
		syslog(LOG_DEBUG, fmt, d1); \
	}
#define	FRUTREE_DEBUG2(lvl, fmt, d1, d2) \
	if (lvl & frutree_debug) { \
		syslog(LOG_DEBUG, fmt, d1, d2);	\
	}
#define	FRUTREE_DEBUG3(lvl, fmt, d1, d2, d3) \
	if (lvl & frutree_debug) { \
		syslog(LOG_DEBUG, fmt, d1, d2, d3); \
	}
#define	FRUTREE_DEBUG4(lvl, fmt, d1, d2, d3, d4) \
	if (lvl & frutree_debug) {\
		syslog(LOG_DEBUG, fmt, d1, d2, d3, d4); \
	}

/* environment variables to tune the variables */
#define	FRUTREE_DEBUG		"SUNW_FRUTREE_DEBUG"
#define	FRUTREE_POLL_TIMEOUT	"SUNW_FRUTREE_POLL_TIMEOUT"
#define	FRUTREE_DRWAIT		"SUNW_FRUTREE_DRWAIT_TIME"

/* PICL defines */
#define	PICL_NODE_CHASSIS		"chassis"

/* Sanibel specific defines */
#define	SANIBEL_PICLNODE_CPU		"CPU"
#define	SANIBEL_PICLNODE_PARALLEL	"ecpp"
#define	SANIBEL_NETWORK_LABEL		"ENET"
#define	SANIBEL_CPCISLOT_TYPE		"cpci"
#define	SANIBEL_NETWORK_PORT		"network"
#define	SANIBEL_SERIAL_PORT		"serial"
#define	SANIBEL_PARALLEL_PORT		"parallel"
#define	SANIBEL_SCSI_SLOT		"scsi"
#define	SANIBEL_IDE_SLOT		"ide"
#define	SANIBEL_UNKNOWN_SLOT		"unknown"
#define	DEVICE_CLASS_SCSI		"scsi"
#define	DEVICE_CLASS_IDE		"dada"

#define	MAX_BUFSIZE		512
#define	SUPER_USER		0
#define	DEVFSADM_CMD		"/usr/sbin/devfsadm -i"
#define	TEMP_DIR		"/var/tmp/"
#define	PROBE_FILE		"probed"
#define	NULLREAD		(int (*)(ptree_rarg_t *, void *))0
#define	NULLWRITE		(int (*)(ptree_warg_t *, const void *))0

#define	PTREE_CREATE_PROP_FAILED	\
	gettext("SUNW_frutree:Error in creating property:%s, "\
	"under %s(error=%d)")
#define	PTREE_POST_PICLEVENT_ERR	\
	gettext("SUNW_frutree:Error in posting picl event %s(%s)(error=%d)")
#define	PTREE_EVENT_HANDLING_ERR	\
	gettext("SUNW_frutree:Error in handling %s event on %s(error=%d)")
#define	GET_LOC_STATE_ERR	\
	gettext("SUNW_frutree:Error in getting state info for %s"\
	"(location)(error=%d)")
#define	GET_FRU_STATE_ERR	\
	gettext("SUNW_frutree:Error in getting state for %s(fru)(error=%d)")
#define	GET_FRU_COND_ERR	\
	gettext("SUNW_frutree:Error in getting condition for %s(fru)(error=%d)")
#define	CONNECT_FAILED_ERR	\
	gettext("SUNW_frutree:Connect operation on %s failed(error=%d)")
#define	CONFIGURE_FAILED_ERR	\
	gettext("SUNW_frutree:Configure operation on %s failed(error=%d)")
#define	UNCONFIG_FAILED_ERR	\
	gettext("SUNW_frutree:Unconfigure operation on %s failed(error=%d)")
#define	DISCONNECT_FAILED_ERR	\
	gettext("SUNW_frutree:Disconnect operation on %s failed(error=%d)")
#define	PROBE_FRU_ERR	\
	gettext("SUNW_frutree:Error in probing fru under %s(error=%d)")
#define	PTREE_UPDATE_PROP_ERR	\
	gettext("SUNW_frutree:Error updating %s of %s(error=%d)")
#define	PTREE_GET_PROPVAL_ERR	\
	gettext("SUNW_frutree:Error in getting value of %s(%s)(error=%d)")
#define	PTREE_DEVICE_CREATE_ERR	\
	gettext("SUNW_frutree:Error in creating nodes under %s(error=%d)")
#define	EVENT_NOT_HANDLED	\
	gettext("SUNW_frutree:Error in handling %s on %s(error=%d)")
#define	ERROR_REINIT	\
	gettext("SUNW_frutree:Error in reinitializing %s")

typedef enum {
	NO_WAIT = 0,
	WAIT
} frutree_wait_t;

typedef uint8_t frutree_frustate_t;
typedef uint8_t frutree_frucond_t;
typedef uint8_t	frutree_locstate_t;
typedef uint8_t frutree_port_type_t;
typedef uint8_t frutree_datatype_t;
typedef uint8_t frutree_loctype_t;

/* valid fru states */
#define	FRU_STATE_UNKNOWN		0x0
#define	FRU_STATE_CONFIGURED		0x1
#define	FRU_STATE_UNCONFIGURED		0x2
#define	FRU_STATE_CONFIGURING		0x3
#define	FRU_STATE_UNCONFIGURING		0x4

/* valid fru condition */
#define	FRU_COND_UNKNOWN		0x0
#define	FRU_COND_FAILED			0x1
#define	FRU_COND_FAILING		0x2
#define	FRU_COND_OK			0x3
#define	FRU_COND_TESTING		0x4

/* port states */
#define	PORT_STATE_DOWN			0x0
#define	PORT_STATE_UP			0x1
#define	PORT_STATE_UNKNOWN		0x2

/* port condition */
#define	PORT_COND_OK			0x0
#define	PORT_COND_FAILING		0x1
#define	PORT_COND_FAILED		0x2
#define	PORT_COND_TESTING		0x3
#define	PORT_COND_UNKNOWN		0x4

/* port types */
#define	NETWORK_PORT			0x0
#define	SERIAL_PORT			0x1
#define	PARALLEL_PORT			0x2
#define	UNKNOWN_PORT			0x4

/* location states */
#define	LOC_STATE_UNKNOWN		0x0
#define	LOC_STATE_EMPTY			0x1
#define	LOC_STATE_CONNECTED		0x2
#define	LOC_STATE_DISCONNECTED		0x3
#define	LOC_STATE_CONNECTING		0x4
#define	LOC_STATE_DISCONNECTING		0x5

/* types of nodes */
#define	LOC_TYPE			0x0
#define	FRU_TYPE			0x1
#define	PORT_TYPE			0x2

/* location managers */
#define	CFGADM_AP			0x0 /*  managed based on cfgadm data */
#define	PLUGIN_PVT			0x1 /* managed by other plugin */
#define	STATIC_LOC			0x2 /* managed based on libdevinfo */
#define	UNKNOWN				0x3 /* unknown */

typedef struct conf_cache {
	char 			buf[MAX_BUFSIZE];
	struct conf_cache	*next;
} frutree_cache_t;

typedef struct {
	picl_nodehdl_t	nodeh;
	picl_prophdl_t	device_tblhdl;
	picl_prophdl_t	env_tblhdl;
	frutree_cache_t	*first;
	frutree_cache_t	*last;
	boolean_t	create_cache;
} frutree_device_args_t;

typedef struct loc_node		frutree_locnode_t;
typedef struct fru_node		frutree_frunode_t;
typedef struct port_node	frutree_portnode_t;

/* information on a particular location */
struct loc_node {
	picl_nodehdl_t locnodeh;	/* handle of the loc node itself */
	char *name;
	boolean_t cpu_node;
	boolean_t dr_in_progress;
	boolean_t autoconfig_enabled;
	frutree_loctype_t state_mgr;	/* state manager */
	frutree_locstate_t state;	/* present state */
	frutree_locstate_t prev_state;	/* previous state */
	pthread_mutex_t	mutex;
	pthread_cond_t cond_cv;
};

/* information on a particular port */
struct port_node {
	picl_nodehdl_t portnodeh;
	char *name;
	int state;
	int cond;
	uint8_t instance;
	char driver[MAXPATHLEN];
};

/* information on a particular fru */
struct fru_node {
	/* variable data */
	picl_nodehdl_t frunodeh;
	char *name;
	frutree_frustate_t state;
	frutree_frustate_t prev_state;
	frutree_frucond_t cond;
	frutree_frucond_t prev_cond;
	boolean_t cpu_node;
	boolean_t autoconfig_enabled;
	boolean_t dr_in_progress;
	boolean_t busy;
	frutree_loctype_t state_mgr;
	char fru_path[MAXPATHLEN];
	pthread_mutex_t	mutex;
	pthread_cond_t	cond_cv;
	pthread_cond_t	busy_cond_cv;
};

#ifdef	__cplusplus
}
#endif

#endif	/* _PICLFRUTREE_H */
