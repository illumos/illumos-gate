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
 * Copyright 2012 Milan Jurik. All rights reserved.
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2015 Joyent, Inc.
 */

#include <alloca.h>
#include <dirent.h>
#include <devid.h>
#include <fm/libdiskstatus.h>
#include <inttypes.h>
#include <pthread.h>
#include <strings.h>
#include <string.h>
#include <unistd.h>
#include <sys/dkio.h>
#include <sys/fm/protocol.h>
#include <sys/libdevid.h>
#include <sys/scsi/scsi_types.h>
#include <sys/byteorder.h>
#include <pthread.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/ctfs.h>
#include <libcontract.h>
#include <poll.h>
#include <sys/contract/device.h>
#include <libsysevent.h>
#include <sys/sysevent/eventdefs.h>
#include <scsi/plugins/ses/vendor/sun.h>

#include "disk.h"
#include "ses.h"

#define	SES_VERSION	1

#define	SES_STARTING_SUBCHASSIS 256	/* valid subchassis IDs are uint8_t */
#define	NO_SUBCHASSIS	((uint64_t)-1)

static int ses_snap_freq = 250;		/* in milliseconds */

#define	SES_STATUS_UNAVAIL(s)	\
	((s) == SES_ESC_UNSUPPORTED || (s) >= SES_ESC_NOT_INSTALLED)

#define	HR_SECOND   1000000000

/*
 * Because multiple SES targets can be part of a single chassis, we construct
 * our own hierarchy that takes this into account.  These SES targets may refer
 * to the same devices (multiple paths) or to different devices (managing
 * different portions of the space).  We arrange things into a
 * ses_enum_enclosure_t, which contains a set of ses targets, and a list of all
 * nodes found so far.
 */
typedef struct ses_alt_node {
	topo_list_t		san_link;
	ses_node_t		*san_node;
} ses_alt_node_t;

typedef struct ses_enum_node {
	topo_list_t		sen_link;
	ses_node_t		*sen_node;
	topo_list_t		sen_alt_nodes;
	uint64_t		sen_type;
	uint64_t		sen_instance;
	ses_enum_target_t	*sen_target;
} ses_enum_node_t;

typedef struct ses_enum_chassis {
	topo_list_t		sec_link;
	topo_list_t		sec_subchassis;
	topo_list_t		sec_nodes;
	topo_list_t		sec_targets;
	const char		*sec_csn;
	ses_node_t		*sec_enclosure;
	ses_enum_target_t	*sec_target;
	topo_instance_t		sec_instance;
	topo_instance_t		sec_scinstance;
	topo_instance_t		sec_maxinstance;
	boolean_t		sec_hasdev;
	boolean_t		sec_internal;
} ses_enum_chassis_t;

typedef struct ses_enum_data {
	topo_list_t		sed_devs;
	topo_list_t		sed_chassis;
	ses_enum_chassis_t	*sed_current;
	ses_enum_target_t	*sed_target;
	int			sed_errno;
	char			*sed_name;
	topo_mod_t		*sed_mod;
	topo_instance_t		sed_instance;
} ses_enum_data_t;

typedef struct sas_connector_phy_data {
	uint64_t    scpd_index;
	uint64_t    scpd_pm;
} sas_connector_phy_data_t;

typedef struct sas_connector_type {
	uint64_t    sct_type;
	char	    *sct_name;
} sas_connector_type_t;

static const sas_connector_type_t sas_connector_type_list[] = {
	{   0x0, "Information unknown"  },
	{   0x1, "External SAS 4x receptacle (see SAS-2 and SFF-8470)"	},
	{   0x2, "Exteranl Mini SAS 4x receptacle (see SAS-2 and SFF-8088)" },
	{   0x3, "QSFP+ receptacle (see SAS-2.1 and SFF-8436)" },
	{   0x4, "Mini SAS 4x active receptacle (see SAS-2.1 and SFF-8088)" },
	{   0x5, "Mini SAS HD 4x receptacle (see SAS-2.1 and SFF-8644)" },
	{   0x6, "Mini SAS HD 8x receptacle (see SAS-2.1 and SFF-8644)" },
	{   0x7, "Mini SAS HD 16x receptacle (see SAS-2.1 and SFF-8644)" },
	{   0xF, "Vendor-specific external connector"	},
	{   0x10, "Internal wide SAS 4i plug (see SAS-2 and SFF-8484)"	},
	{   0x11,
	"Internal wide Mini SAS 4i receptacle (see SAS-2 and SFF-8087)"	},
	{   0x12, "Mini SAS HD 4i receptacle (see SAS-2.1 and SFF-8643)" },
	{   0x20, "Internal SAS Drive receptacle (see SAS-2 and SFF-8482)" },
	{   0x21, "Internal SATA host plug (see SAS-2 and SATA-2)"	},
	{   0x22, "Internal SAS Drive plug (see SAS-2 and SFF-8482)"	},
	{   0x23, "Internal SATA device plug (see SAS-2 and SATA-2)"	},
	{   0x24, "Micro SAS receptacle (see SAS-2.14)"	},
	{   0x25, "Micro SATA device plug (see SAS-2.1 and SATA)"	},
	{   0x26, "Micro SAS plug (see SAS-2.1 and SFF-8486)"	},
	{   0x27, "Micro SAS/SATA plug (see SAS-2.1 and SFF-8486)"	},
	{   0x28,
	"12 Gb/s SAS Drive backplane receptacle (see SAS-34 and SFF-8680)" },
	{   0x29, "12Gb/s SAS Drive Plug (see SAS-3 and SFF-8680)"	},
	{   0x2A, "Multifunction 12 Gb/s 6x Unshielded receptacle connector "
		"receptacle (see SAS-3 and SFF-8639)"	},
	{   0x2B, "Multifunction 12 Gb/s 6x Unshielded receptable connector "
		"plug (see SAS-3 and SFF-8639)"	},
	{   0x2F, "Internal SAS virtual connector"  },
	{   0x3F, "Vendor-specific internal connector"	},
	{   0x70, "Other Vendor-specific connector"	},
	{   0x71, "Other Vendor-specific connector"	},
	{   0x72, "Other Vendor-specific connector"	},
	{   0x73, "Other Vendor-specific connector"	},
	{   0x74, "Other Vendor-specific connector"	},
	{   0x75, "Other Vendor-specific connector"	},
	{   0x76, "Other Vendor-specific connector"	},
	{   0x77, "Other Vendor-specific connector"	},
	{   0x78, "Other Vendor-specific connector"	},
	{   0x79, "Other Vendor-specific connector"	},
	{   0x7A, "Other Vendor-specific connector"	},
	{   0x7B, "Other Vendor-specific connector"	},
	{   0x7C, "Other Vendor-specific connector"	},
	{   0x7D, "Other Vendor-specific connector"	},
	{   0x7E, "Other Vendor-specific connector"	},
	{   0x7F, "Other Vendor-specific connector"	},
	{   0x80, "Not Defined"	}
};

#define	SAS_CONNECTOR_TYPE_CODE_NOT_DEFINED  0x80
#define	SAS_CONNECTOR_TYPE_NOT_DEFINED \
	"Connector type not defined by SES-2 standard"
#define	SAS_CONNECTOR_TYPE_RESERVED \
	"Connector type reserved by SES-2 standard"

typedef struct phys_enum_type {
	uint64_t    pet_type;
	char	    *pet_nodename;
	char	    *pet_defaultlabel;
	boolean_t   pet_dorange;
} phys_enum_type_t;

static const phys_enum_type_t phys_enum_type_list[] = {
	{   SES_ET_ARRAY_DEVICE, BAY, "BAY", B_TRUE  },
	{   SES_ET_COOLING, FAN, "FAN", B_TRUE  },
	{   SES_ET_DEVICE, BAY, "BAY", B_TRUE  },
	{   SES_ET_ESC_ELECTRONICS, CONTROLLER, "CONTROLLER", B_TRUE  },
	{   SES_ET_POWER_SUPPLY, PSU, "PSU", B_TRUE  },
	{   SES_ET_SUNW_FANBOARD, FANBOARD, "FANBOARD", B_TRUE  },
	{   SES_ET_SUNW_FANMODULE, FANMODULE, "FANMODULE", B_TRUE  },
	{   SES_ET_SUNW_POWERBOARD, POWERBOARD, "POWERBOARD", B_TRUE  },
	{   SES_ET_SUNW_POWERMODULE, POWERMODULE, "POWERMODULE", B_TRUE  }
};

#define	N_PHYS_ENUM_TYPES (sizeof (phys_enum_type_list) / \
	sizeof (phys_enum_type_list[0]))

/*
 * Structure for the hierarchical tree for element nodes.
 */
typedef struct ses_phys_tree {
    ses_node_t	*spt_snode;
    ses_enum_node_t	*spt_senumnode;
    boolean_t	spt_isfru;
    uint64_t	spt_eonlyindex;
    uint64_t	spt_cindex;
    uint64_t	spt_pindex;
    uint64_t	spt_maxinst;
    struct ses_phys_tree    *spt_parent;
    struct ses_phys_tree    *spt_child;
    struct ses_phys_tree    *spt_sibling;
    tnode_t	*spt_tnode;
} ses_phys_tree_t;

typedef enum {
	SES_NEW_CHASSIS		= 0x1,
	SES_NEW_SUBCHASSIS	= 0x2,
	SES_DUP_CHASSIS		= 0x4,
	SES_DUP_SUBCHASSIS	= 0x8
} ses_chassis_type_e;


static const topo_pgroup_info_t storage_pgroup = {
	TOPO_PGROUP_STORAGE,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
	1
};

static const topo_pgroup_info_t smp_pgroup = {
	TOPO_PGROUP_SMP,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
	1
};

static const topo_pgroup_info_t ses_pgroup = {
	TOPO_PGROUP_SES,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
	1
};

static int ses_present(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);
static int ses_contains(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);

static const topo_method_t ses_component_methods[] = {
	{ TOPO_METH_PRESENT, TOPO_METH_PRESENT_DESC,
	    TOPO_METH_PRESENT_VERSION0, TOPO_STABILITY_INTERNAL, ses_present },
	{ TOPO_METH_FAC_ENUM, TOPO_METH_FAC_ENUM_DESC, 0,
	    TOPO_STABILITY_INTERNAL, ses_node_enum_facility },
	{ TOPO_METH_SENSOR_FAILURE, TOPO_METH_SENSOR_FAILURE_DESC,
	    TOPO_METH_SENSOR_FAILURE_VERSION, TOPO_STABILITY_INTERNAL,
	    topo_method_sensor_failure },
	{ NULL }
};

static const topo_method_t ses_bay_methods[] = {
	{ TOPO_METH_FAC_ENUM, TOPO_METH_FAC_ENUM_DESC, 0,
	    TOPO_STABILITY_INTERNAL, ses_node_enum_facility },
	{ NULL }
};

static const topo_method_t ses_enclosure_methods[] = {
	{ TOPO_METH_CONTAINS, TOPO_METH_CONTAINS_DESC,
	    TOPO_METH_CONTAINS_VERSION, TOPO_STABILITY_INTERNAL, ses_contains },
	{ TOPO_METH_FAC_ENUM, TOPO_METH_FAC_ENUM_DESC, 0,
	    TOPO_STABILITY_INTERNAL, ses_enc_enum_facility },
	{ NULL }
};

/*
 * Functions for tracking ses devices which we were unable to open. We retry
 * these at regular intervals using ses_recheck_dir() and if we find that we
 * can now open any of them then we send a sysevent to indicate that a new topo
 * snapshot should be taken.
 */
typedef struct ses_open_fail_list {
	struct ses_open_fail_list	*sof_next;
	char				*sof_path;
} ses_open_fail_list_t;

static ses_open_fail_list_t *ses_sofh;
static pthread_mutex_t ses_sofmt;
static void ses_ct_print(char *ptr);

static void
ses_recheck_dir()
{
	ses_target_t *target;
	sysevent_id_t eid;
	char buf[80];
	ses_open_fail_list_t *sof;

	/*
	 * check list of "unable to open" devices
	 */
	(void) pthread_mutex_lock(&ses_sofmt);
	for (sof = ses_sofh; sof != NULL; sof = sof->sof_next) {
		/*
		 * see if we can open it now
		 */
		if ((target = ses_open(LIBSES_VERSION,
		    sof->sof_path)) == NULL) {
			(void) snprintf(buf, sizeof (buf),
			    "recheck_dir - still can't open %s", sof->sof_path);
			ses_ct_print(buf);
			continue;
		}

		/*
		 * ok - better force a new snapshot
		 */
		(void) snprintf(buf, sizeof (buf),
		    "recheck_dir - can now open %s", sof->sof_path);
		ses_ct_print(buf);
		(void) sysevent_post_event(EC_PLATFORM, ESC_PLATFORM_SP_RESET,
		    SUNW_VENDOR, "fmd", NULL, &eid);
		ses_close(target);
		break;
	}
	(void) pthread_mutex_unlock(&ses_sofmt);
}

static void
ses_sof_alloc(topo_mod_t *mod, char *path)
{
	ses_open_fail_list_t *sof;

	(void) pthread_mutex_lock(&ses_sofmt);
	sof = topo_mod_zalloc(mod, sizeof (*sof));
	topo_mod_dprintf(mod, "sof_alloc %s", path);
	sof->sof_path = path;
	sof->sof_next = ses_sofh;
	ses_sofh = sof;
	(void) pthread_mutex_unlock(&ses_sofmt);
}

static void
ses_sof_freeall(topo_mod_t *mod)
{
	ses_open_fail_list_t *sof, *next_sof;

	(void) pthread_mutex_lock(&ses_sofmt);
	for (sof = ses_sofh; sof != NULL; sof = next_sof) {
		next_sof = sof->sof_next;
		topo_mod_dprintf(mod, "sof_freeall %s", sof->sof_path);
		topo_mod_strfree(mod, sof->sof_path);
		topo_mod_free(mod, sof, sizeof (*sof));
	}
	ses_sofh = NULL;
	(void) pthread_mutex_unlock(&ses_sofmt);
}

/*
 * functions for verifying that the ses_enum_target_t held in a device
 * contract's cookie field is still valid (it may have been freed by
 * ses_release()).
 */
typedef struct ses_stp_list {
	struct ses_stp_list	*ssl_next;
	ses_enum_target_t	*ssl_tgt;
} ses_stp_list_t;

static ses_stp_list_t *ses_sslh;
static pthread_mutex_t ses_sslmt;

static void
ses_ssl_alloc(topo_mod_t *mod, ses_enum_target_t *stp)
{
	ses_stp_list_t *ssl;

	(void) pthread_mutex_lock(&ses_sslmt);
	ssl = topo_mod_zalloc(mod, sizeof (*ssl));
	topo_mod_dprintf(mod, "ssl_alloc %p", stp);
	ssl->ssl_tgt = stp;
	ssl->ssl_next = ses_sslh;
	ses_sslh = ssl;
	(void) pthread_mutex_unlock(&ses_sslmt);
}

static void
ses_ssl_free(topo_mod_t *mod, ses_enum_target_t *stp)
{
	ses_stp_list_t *ssl, *prev_ssl;

	(void) pthread_mutex_lock(&ses_sslmt);
	prev_ssl = NULL;
	for (ssl = ses_sslh; ssl != NULL; ssl = ssl->ssl_next) {
		if (ssl->ssl_tgt == stp) {
			topo_mod_dprintf(mod, "ssl_free %p", ssl->ssl_tgt);
			if (prev_ssl == NULL)
				ses_sslh = ssl->ssl_next;
			else
				prev_ssl->ssl_next = ssl->ssl_next;
			topo_mod_free(mod, ssl, sizeof (*ssl));
			break;
		}
		prev_ssl = ssl;
	}
	(void) pthread_mutex_unlock(&ses_sslmt);
}

static int
ses_ssl_valid(ses_enum_target_t *stp)
{
	ses_stp_list_t *ssl;

	for (ssl = ses_sslh; ssl != NULL; ssl = ssl->ssl_next)
		if (ssl->ssl_tgt == stp)
			return (1);
	return (0);
}

/*
 * Functions for creating and destroying a background thread
 * (ses_contract_thread) used for detecting when ses devices have been
 * retired/unretired.
 */
static struct ses_thread_s {
	pthread_mutex_t mt;
	pthread_t tid;
	int thr_sig;
	int doexit;
	int count;
} sesthread = {
	PTHREAD_MUTEX_INITIALIZER,
	0,
	SIGTERM,
	0,
	0
};

typedef struct ses_mod_list {
	struct ses_mod_list	*smod_next;
	topo_mod_t		*smod_mod;
} ses_mod_list_t;

static ses_mod_list_t *ses_smod;

static void
ses_ct_print(char *ptr)
{
	(void) pthread_mutex_lock(&sesthread.mt);
	if (ses_smod != NULL && ses_smod->smod_mod != NULL)
		topo_mod_dprintf(ses_smod->smod_mod, ptr);
	(void) pthread_mutex_unlock(&sesthread.mt);
}

/*ARGSUSED*/
static void *
ses_contract_thread(void *arg)
{
	int efd, ctlfd, statfd;
	ct_evthdl_t ev;
	ctevid_t evid;
	uint_t event;
	char path[PATH_MAX];
	char buf[80];
	ses_enum_target_t *stp;
	ct_stathdl_t stathdl;
	ctid_t ctid;
	struct pollfd fds;
	int pollret;
	sigset_t sigset;

	ses_ct_print("start contract event thread");
	efd = open64(CTFS_ROOT "/device/pbundle", O_RDONLY);
	fds.fd = efd;
	fds.events = POLLIN;
	fds.revents = 0;
	sigaddset(&sigset, sesthread.thr_sig);
	pthread_sigmask(SIG_UNBLOCK, &sigset, NULL);
	for (;;) {
		/* check if we've been asked to exit */
		(void) pthread_mutex_lock(&sesthread.mt);
		if (sesthread.doexit) {
			(void) pthread_mutex_unlock(&sesthread.mt);
			break;
		}
		(void) pthread_mutex_unlock(&sesthread.mt);

		/* poll until an event arrives */
		if ((pollret = poll(&fds, 1, 10000)) <= 0) {
			if (pollret == 0)
				ses_recheck_dir();
			continue;
		}

		/* read the event */
		(void) pthread_mutex_lock(&ses_sslmt);
		ses_ct_print("read contract event");
		if (ct_event_read(efd, &ev) != 0) {
			(void) pthread_mutex_unlock(&ses_sslmt);
			continue;
		}

		/* see if it is an event we are expecting */
		ctid = ct_event_get_ctid(ev);
		(void) snprintf(buf, sizeof (buf),
		    "got contract event ctid=%d", ctid);
		ses_ct_print(buf);
		event = ct_event_get_type(ev);
		if (event != CT_DEV_EV_OFFLINE && event != CT_EV_NEGEND) {
			(void) snprintf(buf, sizeof (buf),
			    "bad contract event %x", event);
			ses_ct_print(buf);
			ct_event_free(ev);
			(void) pthread_mutex_unlock(&ses_sslmt);
			continue;
		}

		/* find target pointer saved in cookie */
		evid = ct_event_get_evid(ev);
		(void) snprintf(path, PATH_MAX, CTFS_ROOT "/device/%ld/status",
		    ctid);
		statfd = open64(path, O_RDONLY);
		(void) ct_status_read(statfd, CTD_COMMON, &stathdl);
		stp = (ses_enum_target_t *)(uintptr_t)
		    ct_status_get_cookie(stathdl);
		ct_status_free(stathdl);
		(void) close(statfd);

		/* check if target pointer is still valid */
		if (ses_ssl_valid(stp) == 0) {
			(void) snprintf(buf, sizeof (buf),
			    "contract already abandoned %x", event);
			ses_ct_print(buf);
			(void) snprintf(path, PATH_MAX,
			    CTFS_ROOT "/device/%ld/ctl", ctid);
			ctlfd = open64(path, O_WRONLY);
			if (event != CT_EV_NEGEND)
				(void) ct_ctl_ack(ctlfd, evid);
			else
				(void) ct_ctl_abandon(ctlfd);
			(void) close(ctlfd);
			ct_event_free(ev);
			(void) pthread_mutex_unlock(&ses_sslmt);
			continue;
		}

		/* find control device for ack/abandon */
		(void) pthread_mutex_lock(&stp->set_lock);
		(void) snprintf(path, PATH_MAX, CTFS_ROOT "/device/%ld/ctl",
		    ctid);
		ctlfd = open64(path, O_WRONLY);
		if (event != CT_EV_NEGEND) {
			/* if this is an offline event, do the offline */
			ses_ct_print("got contract offline event");
			if (stp->set_target) {
				ses_ct_print("contract thread rele");
				ses_snap_rele(stp->set_snap);
				ses_close(stp->set_target);
				stp->set_target = NULL;
			}
			(void) ct_ctl_ack(ctlfd, evid);
		} else {
			/* if this is the negend, then abandon the contract */
			ses_ct_print("got contract negend");
			if (stp->set_ctid) {
				(void) snprintf(buf, sizeof (buf),
				    "abandon old contract %d", stp->set_ctid);
				ses_ct_print(buf);
				stp->set_ctid = NULL;
			}
			(void) ct_ctl_abandon(ctlfd);
		}
		(void) close(ctlfd);
		(void) pthread_mutex_unlock(&stp->set_lock);
		ct_event_free(ev);
		(void) pthread_mutex_unlock(&ses_sslmt);
	}
	(void) close(efd);
	return (NULL);
}

int
find_thr_sig(void)
{
	int i;
	sigset_t oset, rset;
	int sig[] = {SIGTERM, SIGUSR1, SIGUSR2};
	int sig_sz = sizeof (sig) / sizeof (int);
	int rc = SIGTERM;

	/* prefered set of signals that are likely used to terminate threads */
	(void) sigemptyset(&oset);
	(void) pthread_sigmask(SIG_SETMASK, NULL, &oset);
	for (i = 0; i < sig_sz; i++) {
		if (sigismember(&oset, sig[i]) == 0) {
			return (sig[i]);
		}
	}

	/* reserved set of signals that are not allowed to terminate thread */
	(void) sigemptyset(&rset);
	(void) sigaddset(&rset, SIGABRT);
	(void) sigaddset(&rset, SIGKILL);
	(void) sigaddset(&rset, SIGSTOP);
	(void) sigaddset(&rset, SIGCANCEL);

	/* Find signal that is not masked and not in the reserved list. */
	for (i = 1; i < MAXSIG; i++) {
		if (sigismember(&rset, i) == 1) {
			continue;
		}
		if (sigismember(&oset, i) == 0) {
			return (i);
		}
	}

	return (rc);
}

/*ARGSUSED*/
static void
ses_handler(int sig)
{
}

static void
ses_thread_init(topo_mod_t *mod)
{
	pthread_attr_t *attr = NULL;
	struct sigaction act;
	ses_mod_list_t *smod;

	(void) pthread_mutex_lock(&sesthread.mt);
	sesthread.count++;
	smod = topo_mod_zalloc(mod, sizeof (*smod));
	smod->smod_mod = mod;
	smod->smod_next = ses_smod;
	ses_smod = smod;
	if (sesthread.tid == 0) {
		/* find a suitable signal to use for killing the thread below */
		sesthread.thr_sig = find_thr_sig();

		/* if don't have a handler for this signal, create one */
		(void) sigaction(sesthread.thr_sig, NULL, &act);
		if (act.sa_handler == SIG_DFL || act.sa_handler == SIG_IGN)
			act.sa_handler = ses_handler;
		(void) sigaction(sesthread.thr_sig, &act, NULL);

		/* create a thread to listen for offline events */
		(void) pthread_create(&sesthread.tid,
		    attr, ses_contract_thread, NULL);
	}
	(void) pthread_mutex_unlock(&sesthread.mt);
}

static void
ses_thread_fini(topo_mod_t *mod)
{
	ses_mod_list_t *smod, *prev_smod;

	(void) pthread_mutex_lock(&sesthread.mt);
	prev_smod = NULL;
	for (smod = ses_smod; smod != NULL; smod = smod->smod_next) {
		if (smod->smod_mod == mod) {
			if (prev_smod == NULL)
				ses_smod = smod->smod_next;
			else
				prev_smod->smod_next = smod->smod_next;
			topo_mod_free(mod, smod, sizeof (*smod));
			break;
		}
		prev_smod = smod;
	}
	if (--sesthread.count > 0) {
		(void) pthread_mutex_unlock(&sesthread.mt);
		return;
	}
	sesthread.doexit = 1;
	(void) pthread_mutex_unlock(&sesthread.mt);
	(void) pthread_kill(sesthread.tid, sesthread.thr_sig);
	(void) pthread_join(sesthread.tid, NULL);
	sesthread.tid = 0;
}

static void
ses_create_contract(topo_mod_t *mod, ses_enum_target_t *stp)
{
	int tfd, len, rval;
	char link_path[PATH_MAX];

	stp->set_ctid = NULL;

	/* convert "/dev" path into "/devices" path */
	if ((len = readlink(stp->set_devpath, link_path, PATH_MAX)) < 0) {
		topo_mod_dprintf(mod, "readlink failed");
		return;
	}
	link_path[len] = '\0';

	/* set up template to create new contract */
	tfd = open64(CTFS_ROOT "/device/template", O_RDWR);
	(void) ct_tmpl_set_critical(tfd, CT_DEV_EV_OFFLINE);
	(void) ct_tmpl_set_cookie(tfd, (uint64_t)(uintptr_t)stp);

	/* strip "../../devices" off the front and create the contract */
	if ((rval = ct_dev_tmpl_set_minor(tfd, &link_path[13])) != 0)
		topo_mod_dprintf(mod, "failed to set minor %s rval = %d",
		    &link_path[13], rval);
	else if ((rval = ct_tmpl_create(tfd, &stp->set_ctid)) != 0)
		topo_mod_dprintf(mod, "failed to create ctid rval = %d", rval);
	else
		topo_mod_dprintf(mod, "created ctid=%d", stp->set_ctid);
	(void) close(tfd);
}

static void
ses_target_free(topo_mod_t *mod, ses_enum_target_t *stp)
{
	if (--stp->set_refcount == 0) {
		/* check if already closed due to contract offline request */
		(void) pthread_mutex_lock(&stp->set_lock);
		if (stp->set_target) {
			ses_snap_rele(stp->set_snap);
			ses_close(stp->set_target);
			stp->set_target = NULL;
		}
		if (stp->set_ctid) {
			int ctlfd;
			char path[PATH_MAX];

			topo_mod_dprintf(mod, "abandon old contract %d",
			    stp->set_ctid);
			(void) snprintf(path, PATH_MAX,
			    CTFS_ROOT "/device/%ld/ctl", stp->set_ctid);
			ctlfd = open64(path, O_WRONLY);
			(void) ct_ctl_abandon(ctlfd);
			(void) close(ctlfd);
			stp->set_ctid = NULL;
		}
		(void) pthread_mutex_unlock(&stp->set_lock);
		ses_ssl_free(mod, stp);
		topo_mod_strfree(mod, stp->set_devpath);
		topo_mod_free(mod, stp, sizeof (ses_enum_target_t));
	}
}

static void
ses_data_free(ses_enum_data_t *sdp, ses_enum_chassis_t *pcp)
{
	topo_mod_t *mod = sdp->sed_mod;
	ses_enum_chassis_t *cp;
	ses_enum_node_t *np;
	ses_enum_target_t *tp;
	ses_alt_node_t *ap;
	topo_list_t *cpl;


	if (pcp != NULL)
		cpl = &pcp->sec_subchassis;
	else
		cpl = &sdp->sed_chassis;

	while ((cp = topo_list_next(cpl)) != NULL) {
		topo_list_delete(cpl, cp);

		while ((np = topo_list_next(&cp->sec_nodes)) != NULL) {
			while ((ap = topo_list_next(&np->sen_alt_nodes)) !=
			    NULL) {
				topo_list_delete(&np->sen_alt_nodes, ap);
				topo_mod_free(mod, ap, sizeof (ses_alt_node_t));
			}
			topo_list_delete(&cp->sec_nodes, np);
			topo_mod_free(mod, np, sizeof (ses_enum_node_t));
		}

		while ((tp = topo_list_next(&cp->sec_targets)) != NULL) {
			topo_list_delete(&cp->sec_targets, tp);
			ses_target_free(mod, tp);
		}

		topo_mod_free(mod, cp, sizeof (ses_enum_chassis_t));
	}

	if (pcp == NULL) {
		dev_list_free(mod, &sdp->sed_devs);
		topo_mod_free(mod, sdp, sizeof (ses_enum_data_t));
	}
}

/*
 * For enclosure nodes, we have a special contains method.  By default, the hc
 * walker will compare the node name and instance number to determine if an
 * FMRI matches.  For enclosures where the enumeration order is impossible to
 * predict, we instead use the chassis-id as a unique identifier, and ignore
 * the instance number.
 */
static int
fmri_contains(topo_mod_t *mod, nvlist_t *nv1, nvlist_t *nv2)
{
	uint8_t v1, v2;
	nvlist_t **hcp1, **hcp2;
	int err, i;
	uint_t nhcp1, nhcp2;
	nvlist_t *a1, *a2;
	char *c1, *c2;
	int mindepth;

	if (nvlist_lookup_uint8(nv1, FM_VERSION, &v1) != 0 ||
	    nvlist_lookup_uint8(nv2, FM_VERSION, &v2) != 0 ||
	    v1 > FM_HC_SCHEME_VERSION || v2 > FM_HC_SCHEME_VERSION)
		return (topo_mod_seterrno(mod, EMOD_FMRI_VERSION));

	err = nvlist_lookup_nvlist_array(nv1, FM_FMRI_HC_LIST, &hcp1, &nhcp1);
	err |= nvlist_lookup_nvlist_array(nv2, FM_FMRI_HC_LIST, &hcp2, &nhcp2);
	if (err != 0)
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));

	/*
	 * If the chassis-id doesn't match, then these FMRIs are not
	 * equivalent.  If one of the FMRIs doesn't have a chassis ID, then we
	 * have no choice but to fall back to the instance ID.
	 */
	if (nvlist_lookup_nvlist(nv1, FM_FMRI_AUTHORITY, &a1) == 0 &&
	    nvlist_lookup_nvlist(nv2, FM_FMRI_AUTHORITY, &a2) == 0 &&
	    nvlist_lookup_string(a1, FM_FMRI_AUTH_CHASSIS, &c1) == 0 &&
	    nvlist_lookup_string(a2, FM_FMRI_AUTH_CHASSIS, &c2) == 0) {
		if (strcmp(c1, c2) != 0)
			return (0);

		mindepth = 1;
	} else {
		mindepth = 0;
	}

	if (nhcp2 < nhcp1)
		return (0);

	for (i = 0; i < nhcp1; i++) {
		char *nm1 = NULL;
		char *nm2 = NULL;
		char *id1 = NULL;
		char *id2 = NULL;

		(void) nvlist_lookup_string(hcp1[i], FM_FMRI_HC_NAME, &nm1);
		(void) nvlist_lookup_string(hcp2[i], FM_FMRI_HC_NAME, &nm2);
		(void) nvlist_lookup_string(hcp1[i], FM_FMRI_HC_ID, &id1);
		(void) nvlist_lookup_string(hcp2[i], FM_FMRI_HC_ID, &id2);
		if (nm1 == NULL || nm2 == NULL || id1 == NULL || id2 == NULL)
			return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));

		if (strcmp(nm1, nm2) == 0 &&
		    (i < mindepth || strcmp(id1, id2) == 0))
			continue;

		return (0);
	}

	return (1);
}

/*ARGSUSED*/
static int
ses_contains(topo_mod_t *mod, tnode_t *tn, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	int ret;
	nvlist_t *nv1, *nv2;

	if (version > TOPO_METH_CONTAINS_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (nvlist_lookup_nvlist(in, TOPO_METH_FMRI_ARG_FMRI, &nv1) != 0 ||
	    nvlist_lookup_nvlist(in, TOPO_METH_FMRI_ARG_SUBFMRI, &nv2) != 0)
		return (topo_mod_seterrno(mod, EMOD_METHOD_INVAL));

	ret = fmri_contains(mod, nv1, nv2);
	if (ret < 0)
		return (-1);

	if (topo_mod_nvalloc(mod, out, NV_UNIQUE_NAME) == 0) {
		if (nvlist_add_uint32(*out, TOPO_METH_CONTAINS_RET,
		    ret) == 0)
			return (0);
		else
			nvlist_free(*out);
	}

	return (-1);

}

/*
 * Return a current instance of the node.  This is somewhat complicated because
 * we need to take a new snapshot in order to get the new data, but we don't
 * want to be constantly taking SES snapshots if the consumer is going to do a
 * series of queries.  So we adopt the strategy of assuming that the SES state
 * is not going to be rapidly changing, and limit our snapshot frequency to
 * some defined bounds.
 */
ses_node_t *
ses_node_lock(topo_mod_t *mod, tnode_t *tn)
{
	ses_enum_target_t *tp = topo_node_getspecific(tn);
	hrtime_t now;
	ses_snap_t *snap;
	int err;
	uint64_t nodeid;
	ses_node_t *np;

	if (tp == NULL) {
		(void) topo_mod_seterrno(mod, EMOD_METHOD_NOTSUP);
		return (NULL);
	}

	(void) pthread_mutex_lock(&tp->set_lock);

	/*
	 * Determine if we need to take a new snapshot.
	 */
	now = gethrtime();

	if (tp->set_target == NULL) {
		/*
		 * We may have closed the device but not yet abandoned the
		 * contract (ie we've had the offline event but not yet the
		 * negend). If so, just return failure.
		 */
		if (tp->set_ctid != NULL) {
			(void) topo_mod_seterrno(mod, EMOD_METHOD_NOTSUP);
			(void) pthread_mutex_unlock(&tp->set_lock);
			return (NULL);
		}

		/*
		 * The device has been closed due to a contract offline
		 * request, then we need to reopen it and create a new contract.
		 */
		if ((tp->set_target =
		    ses_open(LIBSES_VERSION, tp->set_devpath)) == NULL) {
			sysevent_id_t eid;

			(void) topo_mod_seterrno(mod, EMOD_METHOD_NOTSUP);
			(void) pthread_mutex_unlock(&tp->set_lock);
			topo_mod_dprintf(mod, "recheck_dir - "
			    "can no longer open %s", tp->set_devpath);
			(void) sysevent_post_event(EC_PLATFORM,
			    ESC_PLATFORM_SP_RESET, SUNW_VENDOR, "fmd", NULL,
			    &eid);
			return (NULL);
		}
		topo_mod_dprintf(mod, "reopen contract");
		ses_create_contract(mod, tp);
		tp->set_snap = ses_snap_hold(tp->set_target);
		tp->set_snaptime = gethrtime();
	} else if (now - tp->set_snaptime > (ses_snap_freq * 1000 * 1000) &&
	    (snap = ses_snap_new(tp->set_target)) != NULL) {
		if (ses_snap_generation(snap) !=
		    ses_snap_generation(tp->set_snap)) {
			/*
			 * If we find ourselves in this situation, we're in
			 * trouble.  The generation count has changed, which
			 * indicates that our current topology is out of date.
			 * But we need to consult the new topology in order to
			 * determine presence at this moment in time.  We can't
			 * go back and change the topo snapshot in situ, so
			 * we'll just have to fail the call in this unlikely
			 * scenario.
			 */
			ses_snap_rele(snap);
			(void) topo_mod_seterrno(mod, EMOD_METHOD_NOTSUP);
			(void) pthread_mutex_unlock(&tp->set_lock);
			return (NULL);
		} else {
			ses_snap_rele(tp->set_snap);
			tp->set_snap = snap;
		}
		tp->set_snaptime = gethrtime();
	}

	snap = tp->set_snap;

	verify(topo_prop_get_uint64(tn, TOPO_PGROUP_SES,
	    TOPO_PROP_NODE_ID, &nodeid, &err) == 0);
	verify((np = ses_node_lookup(snap, nodeid)) != NULL);

	return (np);
}

/*ARGSUSED*/
void
ses_node_unlock(topo_mod_t *mod, tnode_t *tn)
{
	ses_enum_target_t *tp = topo_node_getspecific(tn);

	verify(tp != NULL);

	(void) pthread_mutex_unlock(&tp->set_lock);
}

/*
 * Determine if the element is present.
 */
/*ARGSUSED*/
static int
ses_present(topo_mod_t *mod, tnode_t *tn, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	boolean_t present;
	ses_node_t *np;
	nvlist_t *props, *nvl;
	uint64_t status;

	if ((np = ses_node_lock(mod, tn)) == NULL)
		return (-1);

	verify((props = ses_node_props(np)) != NULL);
	verify(nvlist_lookup_uint64(props,
	    SES_PROP_STATUS_CODE, &status) == 0);

	ses_node_unlock(mod, tn);

	present = (status != SES_ESC_NOT_INSTALLED);

	if (topo_mod_nvalloc(mod, &nvl, NV_UNIQUE_NAME) != 0)
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));

	if (nvlist_add_uint32(nvl, TOPO_METH_PRESENT_RET,
	    present) != 0) {
		nvlist_free(nvl);
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
	}

	*out = nvl;

	return (0);
}

/*
 * Sets standard properties for a ses node (enclosure, bay, controller
 * or expander).
 * This includes setting the FRU, as well as setting the
 * authority information.  When  the fru topo node(frutn) is not NULL
 * its resouce should be used as FRU.
 */
static int
ses_set_standard_props(topo_mod_t *mod, tnode_t *frutn, tnode_t *tn,
    nvlist_t *auth, uint64_t nodeid, const char *path)
{
	int err;
	char *product, *chassis;
	nvlist_t *fmri;

	/*
	 * Set the authority explicitly if specified.
	 */
	if (auth) {
		verify(nvlist_lookup_string(auth, FM_FMRI_AUTH_PRODUCT,
		    &product) == 0);
		verify(nvlist_lookup_string(auth, FM_FMRI_AUTH_CHASSIS,
		    &chassis) == 0);
		if (topo_prop_set_string(tn, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_PRODUCT, TOPO_PROP_IMMUTABLE, product,
		    &err) != 0 ||
		    topo_prop_set_string(tn, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_CHASSIS, TOPO_PROP_IMMUTABLE, chassis,
		    &err) != 0 ||
		    topo_prop_set_string(tn, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_SERVER, TOPO_PROP_IMMUTABLE, "",
		    &err) != 0) {
			topo_mod_dprintf(mod, "failed to add authority "
			    "properties: %s\n", topo_strerror(err));
			return (topo_mod_seterrno(mod, err));
		}
	}

	/*
	 * Copy the resource and set that as the FRU.
	 */
	if (frutn != NULL) {
		if (topo_node_resource(frutn, &fmri, &err) != 0) {
			topo_mod_dprintf(mod,
			    "topo_node_resource() failed : %s\n",
			    topo_strerror(err));
			return (topo_mod_seterrno(mod, err));
		}
	} else {
		if (topo_node_resource(tn, &fmri, &err) != 0) {
			topo_mod_dprintf(mod,
			    "topo_node_resource() failed : %s\n",
			    topo_strerror(err));
			return (topo_mod_seterrno(mod, err));
		}
	}

	if (topo_node_fru_set(tn, fmri, 0, &err) != 0) {
		topo_mod_dprintf(mod,
		    "topo_node_fru_set() failed : %s\n",
		    topo_strerror(err));
		nvlist_free(fmri);
		return (topo_mod_seterrno(mod, err));
	}

	nvlist_free(fmri);

	/*
	 * Set the SES-specific properties so that consumers can query
	 * additional information about the particular SES element.
	 */
	if (topo_pgroup_create(tn, &ses_pgroup, &err) != 0) {
		topo_mod_dprintf(mod, "failed to create propgroup "
		    "%s: %s\n", TOPO_PGROUP_SES, topo_strerror(err));
		return (-1);
	}

	if (topo_prop_set_uint64(tn, TOPO_PGROUP_SES,
	    TOPO_PROP_NODE_ID, TOPO_PROP_IMMUTABLE,
	    nodeid, &err) != 0) {
		topo_mod_dprintf(mod,
		    "failed to create property %s: %s\n",
		    TOPO_PROP_NODE_ID, topo_strerror(err));
		return (-1);
	}

	if (topo_prop_set_string(tn, TOPO_PGROUP_SES,
	    TOPO_PROP_TARGET_PATH, TOPO_PROP_IMMUTABLE,
	    path, &err) != 0) {
		topo_mod_dprintf(mod,
		    "failed to create property %s: %s\n",
		    TOPO_PROP_TARGET_PATH, topo_strerror(err));
		return (-1);
	}

	return (0);
}

/*
 * Callback to add a disk to a given bay.  We first check the status-code to
 * determine if a disk is present, ignoring those that aren't in an appropriate
 * state.  We then scan the parent bay node's SAS address array to determine
 * possible attached SAS addresses.  We create a disk node if the disk is not
 * SAS or the SES target does not support the necessary pages for this; if we
 * find the SAS address, we create a disk node and also correlate it with
 * the corresponding Solaris device node to fill in the rest of the data.
 */
static int
ses_create_disk(ses_enum_data_t *sdp, tnode_t *pnode, nvlist_t *props)
{
	topo_mod_t *mod = sdp->sed_mod;
	uint64_t status;
	uint_t s, nsas;
	char **paths;
	int err, ret;
	tnode_t *child = NULL;

	/*
	 * Skip devices that are not in a present (and possibly damaged) state.
	 */
	if (nvlist_lookup_uint64(props, SES_PROP_STATUS_CODE, &status) != 0)
		return (0);

	if (status != SES_ESC_UNSUPPORTED &&
	    status != SES_ESC_OK &&
	    status != SES_ESC_CRITICAL &&
	    status != SES_ESC_NONCRITICAL &&
	    status != SES_ESC_UNRECOVERABLE &&
	    status != SES_ESC_NO_ACCESS &&
	    status != SES_ESC_UNKNOWN)
		return (0);

	topo_mod_dprintf(mod, "found attached disk");

	/*
	 * Create the disk range.
	 */
	if (topo_node_range_create(mod, pnode, DISK, 0, 0) != 0) {
		topo_mod_dprintf(mod,
		    "topo_node_create_range() failed: %s",
		    topo_mod_errmsg(mod));
		return (-1);
	}

	/*
	 * Look through all SAS addresses and attempt to correlate them to a
	 * known Solaris device.  If we don't find a matching node, then we
	 * don't enumerate the disk node.
	 * Note that TOPO_PROP_SAS_ADDR prop includes SAS address from
	 * alternate elements that represent the same device.
	 */
	if (topo_prop_get_string_array(pnode, TOPO_PGROUP_SES,
	    TOPO_PROP_SAS_ADDR, &paths, &nsas, &err) != 0)
		return (0);

	err = 0;

	for (s = 0; s < nsas; s++) {
		ret = disk_declare_addr(mod, pnode, &sdp->sed_devs, paths[s],
		    &child);
		if (ret == 0) {
			break;
		} else if (ret < 0) {
			err = -1;
			break;
		}
	}

	if (s == nsas)
		(void) disk_declare_non_enumerated(mod, pnode, &child);

	/* copy sas_addresses (target-ports) from parent (with 'w'added) */
	if (child != NULL) {
		int i;
		char **tports;
		uint64_t wwn;

		tports = topo_mod_zalloc(mod, sizeof (char *) * nsas);
		if (tports != NULL) {
			for (i = 0; i < nsas; i++) {
				if (scsi_wwnstr_to_wwn(paths[i], &wwn) !=
				    DDI_SUCCESS)
					break;
				tports[i] = scsi_wwn_to_wwnstr(wwn, 1, NULL);
				if (tports[i] == NULL)
					break;
			}
			/* if they all worked then create the property */
			if (i == nsas)
				(void) topo_prop_set_string_array(child,
				    TOPO_PGROUP_STORAGE,
				    TOPO_STORAGE_TARGET_PORT_L0IDS,
				    TOPO_PROP_IMMUTABLE, (const char **)tports,
				    nsas, &err);

			for (i = 0; i < nsas; i++)
				if (tports[i] != NULL)
					scsi_free_wwnstr(tports[i]);
			topo_mod_free(mod, tports, sizeof (char *) * nsas);
		}
	}

	for (s = 0; s < nsas; s++)
		topo_mod_free(mod, paths[s], strlen(paths[s]) + 1);
	topo_mod_free(mod, paths, nsas * sizeof (char *));

	return (err);
}

static int
ses_add_bay_props(topo_mod_t *mod, tnode_t *tn, ses_enum_node_t *snp)
{
	ses_alt_node_t *ap;
	ses_node_t *np;
	nvlist_t *props;

	nvlist_t **phys;
	uint_t i, j, n_phys, all_phys = 0;
	char **paths;
	uint64_t addr;
	size_t len;
	int terr, err = -1;

	for (ap = topo_list_next(&snp->sen_alt_nodes); ap != NULL;
	    ap = topo_list_next(ap)) {
		np = ap->san_node;
		props = ses_node_props(np);

		if (nvlist_lookup_nvlist_array(props, SES_SAS_PROP_PHYS,
		    &phys, &n_phys) != 0)
			continue;

		all_phys += n_phys;
	}

	if (all_phys == 0)
		return (0);

	if ((paths = topo_mod_zalloc(mod, all_phys * sizeof (char *))) == NULL)
		return (-1);

	for (i = 0, ap = topo_list_next(&snp->sen_alt_nodes); ap != NULL;
	    ap = topo_list_next(ap)) {
		np = ap->san_node;
		props = ses_node_props(np);

		if (nvlist_lookup_nvlist_array(props, SES_SAS_PROP_PHYS,
		    &phys, &n_phys) != 0)
			continue;

		for (j = 0; j < n_phys; j++) {
			if (nvlist_lookup_uint64(phys[j], SES_SAS_PROP_ADDR,
			    &addr) != 0)
				continue;

			len = snprintf(NULL, 0, "%016llx", addr) + 1;
			if ((paths[i] = topo_mod_alloc(mod, len)) == NULL)
				goto error;

			(void) snprintf(paths[i], len, "%016llx", addr);

			++i;
		}
	}

	err = topo_prop_set_string_array(tn, TOPO_PGROUP_SES,
	    TOPO_PROP_SAS_ADDR, TOPO_PROP_IMMUTABLE,
	    (const char **)paths, i, &terr);
	if (err != 0)
		err = topo_mod_seterrno(mod, terr);

error:
	for (i = 0; i < all_phys && paths[i] != NULL; i++)
		topo_mod_free(mod, paths[i], strlen(paths[i]) + 1);
	topo_mod_free(mod, paths, all_phys * sizeof (char *));

	return (err);
}

/*
 * Callback to create a basic node (bay, psu, fan, or controller and expander).
 */
static int
ses_create_generic(ses_enum_data_t *sdp, ses_enum_node_t *snp, tnode_t *pnode,
    tnode_t *frutn, const char *nodename, const char *labelname,
    tnode_t **node)
{
	ses_node_t *np = snp->sen_node;
	ses_node_t *parent;
	uint64_t instance = snp->sen_instance;
	topo_mod_t *mod = sdp->sed_mod;
	nvlist_t *props, *aprops;
	nvlist_t *auth = NULL, *fmri = NULL;
	tnode_t *tn = NULL;
	char label[128];
	int err;
	char *part = NULL, *serial = NULL, *revision = NULL;
	char *desc;
	boolean_t report;

	props = ses_node_props(np);

	(void) nvlist_lookup_string(props, LIBSES_PROP_PART, &part);
	(void) nvlist_lookup_string(props, LIBSES_PROP_SERIAL, &serial);

	topo_mod_dprintf(mod, "adding %s %llu", nodename, instance);

	/*
	 * Create the node.  The interesting information is all copied from the
	 * parent enclosure node, so there is not much to do.
	 */
	if ((auth = topo_mod_auth(mod, pnode)) == NULL)
		goto error;

	/*
	 * We want to report revision information for the controller nodes, but
	 * we do not get per-element revision information.  However, we do have
	 * revision information for the entire enclosure, and we can use the
	 * 'reported-via' property to know that this controller corresponds to
	 * the given revision information.  This means we cannot get revision
	 * information for targets we are not explicitly connected to, but
	 * there is little we can do about the situation.
	 */
	if (strcmp(nodename, CONTROLLER) == 0 &&
	    nvlist_lookup_boolean_value(props, SES_PROP_REPORT, &report) == 0 &&
	    report) {
		for (parent = ses_node_parent(np); parent != NULL;
		    parent = ses_node_parent(parent)) {
			if (ses_node_type(parent) == SES_NODE_ENCLOSURE) {
				(void) nvlist_lookup_string(
				    ses_node_props(parent),
				    SES_EN_PROP_REV, &revision);
				break;
			}
		}
	}

	if ((fmri = topo_mod_hcfmri(mod, pnode, FM_HC_SCHEME_VERSION,
	    nodename, (topo_instance_t)instance, NULL, auth, part, revision,
	    serial)) == NULL) {
		topo_mod_dprintf(mod, "topo_mod_hcfmri() failed: %s",
		    topo_mod_errmsg(mod));
		goto error;
	}

	if ((tn = topo_node_bind(mod, pnode, nodename,
	    instance, fmri)) == NULL) {
		topo_mod_dprintf(mod, "topo_node_bind() failed: %s",
		    topo_mod_errmsg(mod));
		goto error;
	}

	/*
	 * For the node label, we look for the following in order:
	 *
	 * 	<ses-description>
	 * 	<ses-class-description> <instance>
	 * 	<default-type-label> <instance>
	 */
	if (nvlist_lookup_string(props, SES_PROP_DESCRIPTION, &desc) != 0 ||
	    desc[0] == '\0') {
		parent = ses_node_parent(np);
		aprops = ses_node_props(parent);
		if (nvlist_lookup_string(aprops, SES_PROP_CLASS_DESCRIPTION,
		    &desc) != 0 || desc[0] == '\0')
			desc = (char *)labelname;
		(void) snprintf(label, sizeof (label), "%s %llu", desc,
		    instance);
		desc = label;
	}

	if (topo_node_label_set(tn, desc, &err) != 0)
		goto error;

	if (ses_set_standard_props(mod, frutn, tn, NULL, ses_node_id(np),
	    snp->sen_target->set_devpath) != 0)
		goto error;

	if (strcmp(nodename, BAY) == 0) {
		if (ses_add_bay_props(mod, tn, snp) != 0)
			goto error;

		if (ses_create_disk(sdp, tn, props) != 0)
			goto error;

		if (topo_method_register(mod, tn, ses_bay_methods) != 0) {
			topo_mod_dprintf(mod,
			    "topo_method_register() failed: %s",
			    topo_mod_errmsg(mod));
			goto error;
		}
	} else if ((strcmp(nodename, FAN) == 0) ||
	    (strcmp(nodename, PSU) == 0) ||
	    (strcmp(nodename, CONTROLLER) == 0)) {
		/*
		 * Only fan, psu, and controller nodes have a 'present' method.
		 * Bay nodes are always present, and disk nodes are present by
		 * virtue of being enumerated and SAS expander nodes and
		 * SAS connector nodes are also always present once
		 * the parent controller is found.
		 */
		if (topo_method_register(mod, tn, ses_component_methods) != 0) {
			topo_mod_dprintf(mod,
			    "topo_method_register() failed: %s",
			    topo_mod_errmsg(mod));
			goto error;
		}

	}

	snp->sen_target->set_refcount++;
	topo_node_setspecific(tn, snp->sen_target);

	nvlist_free(auth);
	nvlist_free(fmri);
	if (node != NULL) *node = tn;
	return (0);

error:
	nvlist_free(auth);
	nvlist_free(fmri);
	return (-1);
}

/*
 * Create SAS expander specific props.
 */
/*ARGSUSED*/
static int
ses_set_expander_props(ses_enum_data_t *sdp, ses_enum_node_t *snp,
    tnode_t *ptnode, tnode_t *tnode, int *phycount, int64_t *connlist)
{
	ses_node_t *np = snp->sen_node;
	topo_mod_t *mod = sdp->sed_mod;
	nvlist_t *auth = NULL, *fmri = NULL;
	nvlist_t *props, **phylist;
	int err, i;
	uint_t pcount;
	uint64_t sasaddr, connidx;
	char sasaddr_str[17];
	boolean_t found = B_FALSE, ses_found = B_FALSE;
	dev_di_node_t *dnode, *sesdnode;

	props = ses_node_props(np);

	/*
	 * the uninstalled expander is not enumerated by checking
	 * the element status code.  No present present' method provided.
	 */
	/*
	 * Get the Expander SAS address.  It should exist.
	 */
	if (nvlist_lookup_uint64(props, SES_EXP_PROP_SAS_ADDR,
	    &sasaddr) != 0) {
		topo_mod_dprintf(mod,
		    "Failed to get prop %s.", SES_EXP_PROP_SAS_ADDR);
		goto error;
	}

	(void) sprintf(sasaddr_str, "%llx", sasaddr);

	/* search matching dev_di_node. */
	for (dnode = topo_list_next(&sdp->sed_devs); dnode != NULL;
	    dnode = topo_list_next(dnode)) {
		for (i = 0; i < dnode->ddn_ppath_count; i++) {
			if ((dnode->ddn_target_port[i] != NULL) &&
			    (strstr(dnode->ddn_target_port[i],
			    sasaddr_str) != NULL)) {
				found = B_TRUE;
				break;
			}
		}
		if (found)
			break;
	}

	if (!found) {
		topo_mod_dprintf(mod,
		    "ses_set_expander_props: Failed to find matching "
		    "devinfo node for Exapnder SAS address %s",
		    SES_EXP_PROP_SAS_ADDR);
		/* continue on to get storage group props. */
	} else {
		/* create/set the devfs-path and devid in the smp group */
		if (topo_pgroup_create(tnode, &smp_pgroup, &err) != 0) {
			topo_mod_dprintf(mod, "ses_set_expander_props: "
			    "failed to create smp property group %s\n",
			    topo_strerror(err));
			goto error;
		} else {
			if (topo_prop_set_string(tnode, TOPO_PGROUP_SMP,
			    TOPO_PROP_SMP_TARGET_PORT, TOPO_PROP_IMMUTABLE,
			    dnode->ddn_target_port[i], &err) != 0) {
				topo_mod_dprintf(mod, "ses_set_expander_props: "
				    "set %S error %s\n", TOPO_PROP_SAS_ADDR,
				    topo_strerror(err));
			}
			if (topo_prop_set_string(tnode, TOPO_PGROUP_SMP,
			    TOPO_PROP_SMP_DEV_PATH, TOPO_PROP_IMMUTABLE,
			    dnode->ddn_dpath, &err) != 0) {
				topo_mod_dprintf(mod, "ses_set_expander_props: "
				    "set dev error %s\n", topo_strerror(err));
			}
			if (topo_prop_set_string(tnode, TOPO_PGROUP_SMP,
			    TOPO_PROP_SMP_DEVID, TOPO_PROP_IMMUTABLE,
			    dnode->ddn_devid, &err) != 0) {
				topo_mod_dprintf(mod, "ses_set_expander_props: "
				    "set devid error %s\n", topo_strerror(err));
			}
			if (dnode->ddn_ppath_count != 0 &&
			    topo_prop_set_string_array(tnode, TOPO_PGROUP_SMP,
			    TOPO_PROP_SMP_PHYS_PATH, TOPO_PROP_IMMUTABLE,
			    (const char **)dnode->ddn_ppath,
			    dnode->ddn_ppath_count, &err) != 0) {
				topo_mod_dprintf(mod, "ses_set_expander_props: "
				    "set phys-path error %s\n",
				    topo_strerror(err));
			}
		}
	}

	/* update the ses property group with SES target info */
	if ((topo_pgroup_create(tnode, &ses_pgroup, &err) != 0) &&
	    (err != ETOPO_PROP_DEFD)) {
		/* SES prop group doesn't exist but failed to be created. */
		topo_mod_dprintf(mod, "ses_set_expander_props: "
		    "ses pgroup create error %s\n", topo_strerror(err));
		goto error;
	} else {
		/* locate assciated enclosure dev_di_node. */
		for (sesdnode = topo_list_next(&sdp->sed_devs);
		    sesdnode != NULL; sesdnode = topo_list_next(sesdnode)) {
			for (i = 0; i < sesdnode->ddn_ppath_count; i++) {
				/*
				 * check if attached port exists and
				 * its node type is enclosure and
				 * attached port is same as sas address of
				 * the expander and
				 * bridge port for virtual phy indication
				 * exist.
				 */
				if ((sesdnode->ddn_attached_port[i] != NULL) &&
				    (sesdnode->ddn_dtype == DTYPE_ESI) &&
				    (strstr(sesdnode->ddn_attached_port[i],
				    sasaddr_str) != NULL) &&
				    (sesdnode->ddn_bridge_port[i] != NULL)) {
					ses_found = B_TRUE;
					break;
				}
			}
			if (ses_found) break;
		}

		if (ses_found) {
			if (topo_prop_set_string(tnode, TOPO_PGROUP_SES,
			    TOPO_PROP_SES_TARGET_PORT, TOPO_PROP_IMMUTABLE,
			    sesdnode->ddn_target_port[i], &err) != 0) {
				topo_mod_dprintf(mod, "ses_set_expander_props: "
				    "set ses %S error %s\n", TOPO_PROP_SAS_ADDR,
				    topo_strerror(err));
			}
			if (topo_prop_set_string(tnode, TOPO_PGROUP_SES,
			    TOPO_PROP_SES_DEV_PATH, TOPO_PROP_IMMUTABLE,
			    sesdnode->ddn_dpath, &err) != 0) {
				topo_mod_dprintf(mod, "ses_set_expander_props: "
				    "set ses dev error %s\n",
				    topo_strerror(err));
			}
			if (topo_prop_set_string(tnode, TOPO_PGROUP_SES,
			    TOPO_PROP_SES_DEVID, TOPO_PROP_IMMUTABLE,
			    sesdnode->ddn_devid, &err) != 0) {
				topo_mod_dprintf(mod, "ses_set_expander_props: "
				    "set ses devid error %s\n",
				    topo_strerror(err));
			}
			if (sesdnode->ddn_ppath_count != 0 &&
			    topo_prop_set_string_array(tnode, TOPO_PGROUP_SES,
			    TOPO_PROP_SES_PHYS_PATH, TOPO_PROP_IMMUTABLE,
			    (const char **)sesdnode->ddn_ppath,
			    sesdnode->ddn_ppath_count, &err) != 0) {
				topo_mod_dprintf(mod, "ses_set_expander_props: "
				    "set ses phys-path error %s\n",
				    topo_strerror(err));
			}

		}
	}

	/* create the storage group */
	if (topo_pgroup_create(tnode, &storage_pgroup, &err) != 0) {
		topo_mod_dprintf(mod, "ses_set_expander_props: "
		    "create storage error %s\n", topo_strerror(err));
		goto error;
	} else {
		/* set the SAS address prop out of expander element status. */
		if (topo_prop_set_string(tnode, TOPO_PGROUP_STORAGE,
		    TOPO_PROP_SAS_ADDR, TOPO_PROP_IMMUTABLE, sasaddr_str,
		    &err) != 0) {
			topo_mod_dprintf(mod, "ses_set_expander_props: "
			    "set %S error %s\n", TOPO_PROP_SAS_ADDR,
			    topo_strerror(err));
		}

		/* Get the phy information for the expander */
		if (nvlist_lookup_nvlist_array(props, SES_SAS_PROP_PHYS,
		    &phylist, &pcount) != 0) {
			topo_mod_dprintf(mod,
			    "Failed to get prop %s.", SES_SAS_PROP_PHYS);
		} else {
			/*
			 * For each phy, get the connector element index and
			 * stores into connector element index array.
			 */
			*phycount = pcount;
			for (i = 0; i < pcount; i++) {
				if (nvlist_lookup_uint64(phylist[i],
				    SES_PROP_CE_IDX, &connidx) == 0) {
					if (connidx != 0xff) {
						connlist[i] = connidx;
					} else {
						connlist[i] = -1;
					}
				} else {
					/* Fail to get the index. set to -1. */
					connlist[i] = -1;
				}
			}

			/* set the phy count prop of the expander. */
			if (topo_prop_set_uint64(tnode, TOPO_PGROUP_STORAGE,
			    TOPO_PROP_PHY_COUNT, TOPO_PROP_IMMUTABLE, pcount,
			    &err) != 0) {
				topo_mod_dprintf(mod, "ses_set_expander_props: "
				    "set %S error %s\n", TOPO_PROP_PHY_COUNT,
				    topo_strerror(err));
			}

			/*
			 * set the connector element index of
			 * the expander phys.
			 */
		}

		/* populate other misc storage group properties */
		if (found) {
			if (dnode->ddn_mfg && (topo_prop_set_string(tnode,
			    TOPO_PGROUP_STORAGE, TOPO_STORAGE_MANUFACTURER,
			    TOPO_PROP_IMMUTABLE, dnode->ddn_mfg, &err) != 0)) {
				topo_mod_dprintf(mod, "ses_set_expander_props: "
				    "set mfg error %s\n", topo_strerror(err));
			}

			if (dnode->ddn_model && (topo_prop_set_string(tnode,
			    TOPO_PGROUP_STORAGE, TOPO_STORAGE_MODEL,
			    TOPO_PROP_IMMUTABLE,
			    dnode->ddn_model, &err) != 0)) {
				topo_mod_dprintf(mod, "ses_set_expander_props: "
				    "set model error %s\n", topo_strerror(err));
			}

			if (dnode->ddn_serial && (topo_prop_set_string(tnode,
			    TOPO_PGROUP_STORAGE, TOPO_STORAGE_SERIAL_NUM,
			    TOPO_PROP_IMMUTABLE,
			    dnode->ddn_serial, &err) != 0)) {
				topo_mod_dprintf(mod, "ses_set_expander_props: "
				    "set serial error %s\n",
				    topo_strerror(err));
			}

			if (dnode->ddn_firm && (topo_prop_set_string(tnode,
			    TOPO_PGROUP_STORAGE,
			    TOPO_STORAGE_FIRMWARE_REV, TOPO_PROP_IMMUTABLE,
			    dnode->ddn_firm, &err) != 0)) {
				topo_mod_dprintf(mod, "ses_set_expander_props: "
				    "set firm error %s\n", topo_strerror(err));
			}
		}
	}

	return (0);

error:
	nvlist_free(auth);
	nvlist_free(fmri);
	return (-1);
}

/*
 * Create SAS expander specific props.
 */
/*ARGSUSED*/
static int
ses_set_connector_props(ses_enum_data_t *sdp, ses_enum_node_t *snp,
    tnode_t *tnode, int64_t phy_mask)
{
	ses_node_t *np = snp->sen_node;
	topo_mod_t *mod = sdp->sed_mod;
	nvlist_t *props;
	int err, i;
	uint64_t conntype;
	char phymask_str[17], *conntype_str;
	boolean_t   found;

	props = ses_node_props(np);

	/*
	 * convert phy mask to string.
	 */
	(void) snprintf(phymask_str, 17, "%llx", phy_mask);

	/* create the storage group */
	if (topo_pgroup_create(tnode, &storage_pgroup, &err) != 0) {
		topo_mod_dprintf(mod, "ses_set_expander_props: "
		    "create storage error %s\n", topo_strerror(err));
		return (-1);
	} else {
		/* set the SAS address prop of the expander. */
		if (topo_prop_set_string(tnode, TOPO_PGROUP_STORAGE,
		    TOPO_STORAGE_SAS_PHY_MASK, TOPO_PROP_IMMUTABLE,
		    phymask_str, &err) != 0) {
			topo_mod_dprintf(mod, "ses_set_expander_props: "
			    "set %S error %s\n", TOPO_STORAGE_SAS_PHY_MASK,
			    topo_strerror(err));
		}

		/* Get the connector type information for the expander */
		if (nvlist_lookup_uint64(props,
		    SES_SC_PROP_CONNECTOR_TYPE, &conntype) != 0) {
			topo_mod_dprintf(mod, "Failed to get prop %s.",
			    TOPO_STORAGE_SAS_PHY_MASK);
		} else {
			found = B_FALSE;
			for (i = 0; ; i++) {
				if (sas_connector_type_list[i].sct_type ==
				    SAS_CONNECTOR_TYPE_CODE_NOT_DEFINED) {
					break;
				}
				if (sas_connector_type_list[i].sct_type ==
				    conntype) {
					conntype_str =
					    sas_connector_type_list[i].sct_name;
					found = B_TRUE;
					break;
				}
			}

			if (!found) {
				if (conntype <
				    SAS_CONNECTOR_TYPE_CODE_NOT_DEFINED) {
					conntype_str =
					    SAS_CONNECTOR_TYPE_RESERVED;
				} else {
					conntype_str =
					    SAS_CONNECTOR_TYPE_NOT_DEFINED;
				}
			}

			/* set the phy count prop of the expander. */
			if (topo_prop_set_string(tnode, TOPO_PGROUP_STORAGE,
			    TOPO_STORAGE_SAS_CONNECTOR_TYPE,
			    TOPO_PROP_IMMUTABLE, conntype_str, &err) != 0) {
				topo_mod_dprintf(mod, "ses_set_expander_props: "
				    "set %S error %s\n", TOPO_PROP_PHY_COUNT,
				    topo_strerror(err));
			}
		}
	}

	return (0);
}

/*
 * Instantiate SAS expander nodes for a given ESC Electronics node(controller)
 * nodes.
 */
/*ARGSUSED*/
static int
ses_create_esc_sasspecific(ses_enum_data_t *sdp, ses_enum_node_t *snp,
    tnode_t *pnode, ses_enum_chassis_t *cp,
    boolean_t dorange)
{
	topo_mod_t *mod = sdp->sed_mod;
	tnode_t	*exptn, *contn;
	boolean_t found;
	sas_connector_phy_data_t connectors[64] = {NULL};
	uint64_t max;
	ses_enum_node_t *ctlsnp, *xsnp, *consnp;
	ses_node_t *np = snp->sen_node;
	nvlist_t *props, *psprops;
	uint64_t index, psindex, conindex, psstatus, i, j, count;
	int64_t cidxlist[256] = {NULL};
	int phycount;

	props = ses_node_props(np);

	if (nvlist_lookup_uint64(props, SES_PROP_ELEMENT_ONLY_INDEX,
	    &index) != 0)
		return (-1);

	/*
	 * For SES constroller node, check to see if there are
	 * associated SAS expanders.
	 */
	found = B_FALSE;
	max = 0;
	for (ctlsnp = topo_list_next(&cp->sec_nodes); ctlsnp != NULL;
	    ctlsnp = topo_list_next(ctlsnp)) {
		if (ctlsnp->sen_type == SES_ET_SAS_EXPANDER) {
			found = B_TRUE;
			if (ctlsnp->sen_instance > max)
				max = ctlsnp->sen_instance;
		}
	}

	/*
	 * No SAS expander found notthing to process.
	 */
	if (!found)
		return (0);

	topo_mod_dprintf(mod, "%s Controller %d: creating "
	    "%llu %s nodes", cp->sec_csn, index, max + 1, SASEXPANDER);

	/*
	 * The max number represent the number of elements
	 * deducted from the highest SES_PROP_ELEMENT_CLASS_INDEX
	 * of SET_ET_SAS_EXPANDER type element.
	 *
	 * There may be multiple ESC Electronics element(controllers)
	 * within JBOD(typicall two for redundancy) and SAS expander
	 * elements are associated with only one of them.  We are
	 * still creating the range based max number here.
	 * That will cover the case that all expanders are associated
	 * with one SES controller.
	 */
	if (dorange && topo_node_range_create(mod, pnode,
	    SASEXPANDER, 0, max) != 0) {
		topo_mod_dprintf(mod,
		    "topo_node_create_range() failed: %s",
		    topo_mod_errmsg(mod));
		return (-1);
	}

	/*
	 * Search exapnders with the parent index matching with
	 * ESC Electronics element index.
	 * Note the index used here is a global index across
	 * SES elements.
	 */
	for (xsnp = topo_list_next(&cp->sec_nodes); xsnp != NULL;
	    xsnp = topo_list_next(xsnp)) {
		if (xsnp->sen_type == SES_ET_SAS_EXPANDER) {
			/*
			 * get the parent ESC controller.
			 */
			psprops = ses_node_props(xsnp->sen_node);
			if (nvlist_lookup_uint64(psprops,
			    SES_PROP_STATUS_CODE, &psstatus) == 0) {
				if (psstatus == SES_ESC_NOT_INSTALLED) {
					/*
					 * Not installed.
					 * Don't create a ndoe.
					 */
					continue;
				}
			} else {
				/*
				 * The element should have status code.
				 * If not there is no way to find
				 * out if the expander element exist or
				 * not.
				 */
				continue;
			}

			/* Get the physical parent index to compare. */
			if (nvlist_lookup_uint64(psprops,
			    LIBSES_PROP_PHYS_PARENT, &psindex) == 0) {
				if (index == psindex) {
		/* indentation moved forward */
		/*
		 * Handle basic node information of SAS expander
		 * element - binding to parent node and
		 * allocating FMRI...
		 */
		if (ses_create_generic(sdp, xsnp, pnode, pnode, SASEXPANDER,
		    "SAS-EXPANDER", &exptn) != 0)
			continue;
		/*
		 * Now handle SAS expander unique portion of node creation.
		 * The max nubmer of the phy count is 256 since SES-2
		 * defines as 1 byte field.  The cidxlist has the same
		 * number of elements.
		 *
		 * We use size 64 array to store the connectors.
		 * Typically a connectors associated with 4 phys so that
		 * matches with the max number of connecters associated
		 * with an expander.
		 * The phy count goes up to 38 for Sun supported
		 * JBOD.
		 */
		(void) memset(cidxlist, 0, sizeof (int64_t) * 64);
		if (ses_set_expander_props(sdp, xsnp, pnode, exptn, &phycount,
		    cidxlist) != 0) {
			/*
			 * error on getting specific prop failed.
			 * continue on.  Note that the node is
			 * left bound.
			 */
			continue;
		}

		/*
		 * count represetns the number of connectors discovered so far.
		 */
		count = 0;
		(void) memset(connectors, 0,
		    sizeof (sas_connector_phy_data_t) * 64);
		for (i = 0; i < phycount; i++) {
			if (cidxlist[i] != -1) {
				/* connector index is valid. */
				for (j = 0; j < count; j++) {
					if (connectors[j].scpd_index ==
					    cidxlist[i]) {
						/*
						 * Just update phy mask.
						 * The postion for connector
						 * index lists(cidxlist index)
						 * is set.
						 */
						connectors[j].scpd_pm =
						    connectors[j].scpd_pm |
						    (1ULL << i);
						break;
					}
				}
				/*
				 * If j and count matche a  new connector
				 * index is found.
				 */
				if (j == count) {
					/* add a new index and phy mask. */
					connectors[count].scpd_index =
					    cidxlist[i];
					connectors[count].scpd_pm =
					    connectors[count].scpd_pm |
					    (1ULL << i);
					count++;
				}
			}
		}

		/*
		 * create range for the connector nodes.
		 * The class index of the ses connector element
		 * is set as the instance nubmer for the node.
		 * Even though one expander may not have all connectors
		 * are associated with we are creating the range with
		 * max possible instance number.
		 */
		found = B_FALSE;
		max = 0;
		for (consnp = topo_list_next(&cp->sec_nodes);
		    consnp != NULL; consnp = topo_list_next(consnp)) {
			if (consnp->sen_type == SES_ET_SAS_CONNECTOR) {
				psprops = ses_node_props(consnp->sen_node);
				found = B_TRUE;
				if (consnp->sen_instance > max)
					max = consnp->sen_instance;
			}
		}

		/*
		 * No SAS connector found nothing to process.
		 */
		if (!found)
			return (0);

		if (dorange && topo_node_range_create(mod, exptn,
		    RECEPTACLE, 0, max) != 0) {
			topo_mod_dprintf(mod,
			    "topo_node_create_range() failed: %s",
			    topo_mod_errmsg(mod));
			return (-1);
		}

		/* search matching connector element using the index. */
		for (i = 0; i < count; i++) {
			found = B_FALSE;
			for (consnp = topo_list_next(&cp->sec_nodes);
			    consnp != NULL; consnp = topo_list_next(consnp)) {
				if (consnp->sen_type == SES_ET_SAS_CONNECTOR) {
					psprops = ses_node_props(
					    consnp->sen_node);
					/*
					 * Get the physical parent index to
					 * compare.
					 * The connector elements are children
					 * of ESC Electronics element even
					 * though we enumerate them under
					 * an expander in libtopo.
					 */
					if (nvlist_lookup_uint64(psprops,
					    SES_PROP_ELEMENT_ONLY_INDEX,
					    &conindex) == 0) {
						if (conindex ==
						    connectors[i].scpd_index) {
							found = B_TRUE;
							break;
						}
					}
				}
			}

			/* now create a libtopo node. */
			if (found) {
				/* Create generic props. */
				if (ses_create_generic(sdp, consnp, exptn,
				    topo_node_parent(exptn),
				    RECEPTACLE, "RECEPTACLE", &contn) !=
				    0) {
					continue;
				}
				/* Create connector specific props. */
				if (ses_set_connector_props(sdp, consnp,
				    contn, connectors[i].scpd_pm) != 0) {
					continue;
				}
			}
		}
		/* end indentation change */
				}
			}
		}
	}

	return (0);
}

/*
 * Instantiate any protocol specific portion of a node.
 */
/*ARGSUSED*/
static int
ses_create_protocol_specific(ses_enum_data_t *sdp, ses_enum_node_t *snp,
    tnode_t *pnode, uint64_t type, ses_enum_chassis_t *cp,
    boolean_t dorange)
{

	if (type == SES_ET_ESC_ELECTRONICS) {
		/* create SAS specific children(expanders and connectors. */
		return (ses_create_esc_sasspecific(sdp, snp, pnode, cp,
		    dorange));
	}

	return (0);
}

/*
 * Instantiate any children of a given type.
 */
static int
ses_create_children(ses_enum_data_t *sdp, tnode_t *pnode, uint64_t type,
    const char *nodename, const char *defaultlabel, ses_enum_chassis_t *cp,
    boolean_t dorange)
{
	topo_mod_t *mod = sdp->sed_mod;
	boolean_t found;
	uint64_t max;
	ses_enum_node_t *snp;
	tnode_t	*tn;

	/*
	 * First go through and count how many matching nodes we have.
	 */
	max = 0;
	found = B_FALSE;
	for (snp = topo_list_next(&cp->sec_nodes); snp != NULL;
	    snp = topo_list_next(snp)) {
		if (snp->sen_type == type) {
			found = B_TRUE;
			if (snp->sen_instance > max)
				max = snp->sen_instance;
		}
	}

	/*
	 * No enclosure should export both DEVICE and ARRAY_DEVICE elements.
	 * Since we map both of these to 'disk', if an enclosure does this, we
	 * just ignore the array elements.
	 */
	if (!found ||
	    (type == SES_ET_ARRAY_DEVICE && cp->sec_hasdev))
		return (0);

	topo_mod_dprintf(mod, "%s: creating %llu %s nodes",
	    cp->sec_csn, max + 1, nodename);

	if (dorange && topo_node_range_create(mod, pnode,
	    nodename, 0, max) != 0) {
		topo_mod_dprintf(mod,
		    "topo_node_create_range() failed: %s",
		    topo_mod_errmsg(mod));
		return (-1);
	}

	for (snp = topo_list_next(&cp->sec_nodes); snp != NULL;
	    snp = topo_list_next(snp)) {
		if (snp->sen_type == type) {
			/*
			 * With flat layout of ses nodes there is no
			 * way to find out the direct FRU for a node.
			 * Passing NULL for fru topo node.  Note that
			 * ses_create_children_from_phys_tree() provides
			 * the actual direct FRU for a node.
			 */
			if (ses_create_generic(sdp, snp, pnode, NULL,
			    nodename, defaultlabel, &tn) != 0)
				return (-1);
			/*
			 * For some SES element there may be protocol specific
			 * information to process.   Here we are processing
			 * the association between enclosure controller and
			 * SAS expanders.
			 */
			if (type == SES_ET_ESC_ELECTRONICS) {
				/* create SAS expander node */
				if (ses_create_protocol_specific(sdp, snp,
				    tn, type, cp, dorange) != 0) {
					return (-1);
				}
			}

		}
	}

	return (0);
}

/*
 * Instantiate a new subchassis instance in the topology.
 */
static int
ses_create_subchassis(ses_enum_data_t *sdp, tnode_t *pnode,
    ses_enum_chassis_t *scp)
{
	topo_mod_t *mod = sdp->sed_mod;
	tnode_t *tn;
	nvlist_t *props;
	nvlist_t *auth = NULL, *fmri = NULL;
	uint64_t instance = scp->sec_instance;
	char *desc;
	char label[128];
	char **paths;
	int i, err;
	ses_enum_target_t *stp;
	int ret = -1;

	/*
	 * Copy authority information from parent enclosure node
	 */
	if ((auth = topo_mod_auth(mod, pnode)) == NULL)
		goto error;

	/*
	 * Record the subchassis serial number in the FMRI.
	 * For now, we assume that logical id is the subchassis serial number.
	 * If this assumption changes in future, then the following
	 * piece of code will need to be updated via an RFE.
	 */
	if ((fmri = topo_mod_hcfmri(mod, pnode, FM_HC_SCHEME_VERSION,
	    SUBCHASSIS, (topo_instance_t)instance, NULL, auth, NULL, NULL,
	    NULL)) == NULL) {
		topo_mod_dprintf(mod, "topo_mod_hcfmri() failed: %s",
		    topo_mod_errmsg(mod));
		goto error;
	}

	if ((tn = topo_node_bind(mod, pnode, SUBCHASSIS,
	    instance, fmri)) == NULL) {
		topo_mod_dprintf(mod, "topo_node_bind() failed: %s",
		    topo_mod_errmsg(mod));
		goto error;
	}

	props = ses_node_props(scp->sec_enclosure);

	/*
	 * Look for the subchassis label in the following order:
	 *	<ses-description>
	 *	<ses-class-description> <instance>
	 *	<default-type-label> <instance>
	 *
	 * For subchassis, the default label is "SUBCHASSIS"
	 */
	if (nvlist_lookup_string(props, SES_PROP_DESCRIPTION, &desc) != 0 ||
	    desc[0] == '\0') {
		if (nvlist_lookup_string(props, SES_PROP_CLASS_DESCRIPTION,
		    &desc) == 0 && desc[0] != '\0')
			(void) snprintf(label, sizeof (label), "%s %llu", desc,
			    instance);
		else
			(void) snprintf(label, sizeof (label),
			    "SUBCHASSIS %llu", instance);
		desc = label;
	}

	if (topo_node_label_set(tn, desc, &err) != 0)
		goto error;

	if (ses_set_standard_props(mod, NULL, tn, NULL,
	    ses_node_id(scp->sec_enclosure), scp->sec_target->set_devpath) != 0)
		goto error;

	/*
	 * Set the 'chassis-type' property for this subchassis.  This is either
	 * 'ses-class-description' or 'subchassis'.
	 */
	if (nvlist_lookup_string(props, SES_PROP_CLASS_DESCRIPTION, &desc) != 0)
		desc = "subchassis";

	if (topo_prop_set_string(tn, TOPO_PGROUP_SES,
	    TOPO_PROP_CHASSIS_TYPE, TOPO_PROP_IMMUTABLE, desc, &err) != 0) {
		topo_mod_dprintf(mod, "failed to create property %s: %s\n",
		    TOPO_PROP_CHASSIS_TYPE, topo_strerror(err));
		goto error;
	}

	/*
	 * For enclosures, we want to include all possible targets (for upgrade
	 * purposes).
	 */
	for (i = 0, stp = topo_list_next(&scp->sec_targets); stp != NULL;
	    stp = topo_list_next(stp), i++)
		;

	verify(i != 0);
	paths = alloca(i * sizeof (char *));

	for (i = 0, stp = topo_list_next(&scp->sec_targets); stp != NULL;
	    stp = topo_list_next(stp), i++)
		paths[i] = stp->set_devpath;

	if (topo_prop_set_string_array(tn, TOPO_PGROUP_SES,
	    TOPO_PROP_PATHS, TOPO_PROP_IMMUTABLE, (const char **)paths,
	    i, &err) != 0) {
		topo_mod_dprintf(mod, "failed to create property %s: %s\n",
		    TOPO_PROP_PATHS, topo_strerror(err));
		goto error;
	}

	if (topo_method_register(mod, tn, ses_enclosure_methods) != 0) {
		topo_mod_dprintf(mod, "topo_method_register() failed: %s",
		    topo_mod_errmsg(mod));
		goto error;
	}

	/*
	 * Create the nodes for controllers and bays.
	 */
	if (ses_create_children(sdp, tn, SES_ET_ESC_ELECTRONICS,
	    CONTROLLER, "CONTROLLER", scp, B_TRUE) != 0 ||
	    ses_create_children(sdp, tn, SES_ET_DEVICE,
	    BAY, "BAY", scp, B_TRUE) != 0 ||
	    ses_create_children(sdp, tn, SES_ET_ARRAY_DEVICE,
	    BAY, "BAY", scp, B_TRUE) != 0)
		goto error;

	ret = 0;

error:
	nvlist_free(auth);
	nvlist_free(fmri);
	return (ret);
}

/*
 * Function we use to insert a node.
 */
static int
ses_phys_tree_insert(topo_mod_t *mod, ses_phys_tree_t **sproot,
    ses_phys_tree_t *child)
{
	uint64_t ppindex, eindex, pindex;
	ses_phys_tree_t *node_ptr;
	int ret = 0;

	assert(sproot != NULL);
	assert(child != NULL);

	if (*sproot == NULL) {
		*sproot = child;
		return (0);
	}

	pindex = child->spt_pindex;
	ppindex = (*sproot)->spt_pindex;
	eindex = (*sproot)->spt_eonlyindex;

	/*
	 * If the element only index of the root is same as the physical
	 * parent index of a node to be added, add the node as a child of
	 * the current root.
	 */
	if (eindex == pindex) {
		(void) ses_phys_tree_insert(mod, &(*sproot)->spt_child, child);
		child->spt_parent = *sproot;
	} else if (ppindex == pindex) {
		/*
		 * if the physical parent of the current root and the child
		 * is same, then this should be a sibling node.
		 * Siblings can be different element types and arrange
		 * them by group.
		 */
		if ((*sproot)->spt_senumnode->sen_type ==
		    child->spt_senumnode->sen_type) {
			child->spt_sibling = *sproot;
			*sproot = child;
		} else {
			/* add a node in front of matching element type. */
			node_ptr = *sproot;
			while (node_ptr->spt_sibling != NULL) {
				if (node_ptr->spt_sibling->
				    spt_senumnode->sen_type ==
				    child->spt_senumnode->sen_type) {
					child->spt_sibling =
					    node_ptr->spt_sibling;
					node_ptr->spt_sibling = child;
					break;
				}
				node_ptr = node_ptr->spt_sibling;
			}
			/* no matching.  Add the child at the end. */
			if (node_ptr->spt_sibling == NULL) {
				node_ptr->spt_sibling = child;
			}
		}
		child->spt_parent = (*sproot)->spt_parent;
	} else {
		/*
		 * The root and the node is not directly related.
		 * Try to insert to the child sub-tree first and then try to
		 * insert to the sibling sub-trees.  If fails for both
		 * the caller will retry insertion later.
		 */
		if ((*sproot)->spt_child) {
			ret = ses_phys_tree_insert(mod, &(*sproot)->spt_child,
			    child);
		}
		if ((*sproot)->spt_child == NULL || ret != 0) {
			if ((*sproot)->spt_sibling) {
				ret = ses_phys_tree_insert(mod,
				    &(*sproot)->spt_sibling, child);
			} else {
				ret = 1;
			}
		}
		return (ret);
	}
	return (0);
}

/*
 * Construct tree view of ses elements through parent phyiscal element index.
 * The root of tree is already constructed using the enclosure element.
 */
static int
ses_construct_phys_tree(ses_enum_data_t *sdp, ses_enum_chassis_t *cp,
    ses_phys_tree_t *sproot)
{
	ses_enum_node_t *snp;
	ses_phys_tree_t	*child;
	ses_phys_tree_t	*u_watch = NULL;
	ses_phys_tree_t	*u_head = NULL;
	ses_phys_tree_t	*u_tail = NULL;
	int u_inserted = 0, u_left = 0;
	nvlist_t *props;
	topo_mod_t *mod = sdp->sed_mod;

	for (snp = topo_list_next(&cp->sec_nodes); snp != NULL;
	    snp = topo_list_next(snp)) {
		if ((child = topo_mod_zalloc(mod,
		    sizeof (ses_phys_tree_t))) == NULL) {
			topo_mod_dprintf(mod,
			    "failed to allocate root.");
			return (-1);
		}
		child->spt_snode = snp->sen_node;
		props = ses_node_props(snp->sen_node);
		if (nvlist_lookup_uint64(props,
		    LIBSES_PROP_PHYS_PARENT, &child->spt_pindex) != 0) {
			/*
			 * the prop should exist. continue to see if
			 * we can build a partial tree with other elements.
			 */
			topo_mod_dprintf(mod,
			    "ses_construct_phys_tree(): Failed to find prop %s "
			    "on ses element type %d and instance %d "
			    "(CSN %s).", LIBSES_PROP_PHYS_PARENT,
			    snp->sen_type, snp->sen_instance, cp->sec_csn);
			topo_mod_free(mod, child, sizeof (ses_phys_tree_t));
			continue;
		} else {
			if (nvlist_lookup_boolean_value(props,
			    LIBSES_PROP_FRU, &child->spt_isfru) != 0) {
				topo_mod_dprintf(mod,
				    "ses_construct_phys_tree(): Failed to "
				    "find prop %s on ses element type %d "
				    "and instance %d (CSN %s).",
				    LIBSES_PROP_FRU,
				    snp->sen_type, snp->sen_instance,
				    cp->sec_csn);
				/*
				 * Ignore if the prop doesn't exist.
				 * Note that the enclosure itself should be
				 * a FRU so if no FRU found the enclosure FRU
				 * can be a direct FRU.
				 */
			}
			verify(nvlist_lookup_uint64(props,
			    SES_PROP_ELEMENT_ONLY_INDEX,
			    &child->spt_eonlyindex) == 0);
			verify(nvlist_lookup_uint64(props,
			    SES_PROP_ELEMENT_CLASS_INDEX,
			    &child->spt_cindex) == 0);
		}
		child->spt_senumnode = snp;
		if (ses_phys_tree_insert(mod, &sproot, child) != 0) {
			/* collect unresolved element to process later. */
			if (u_head == NULL) {
				u_head = child;
				u_tail = child;
			} else {
				child->spt_sibling = u_head;
				u_head = child;
			}
		}
	}

	/*
	 * The parent of a child node may not be inserted yet.
	 * Trying to insert the child until no child is left or
	 * no child is not added further.  For the latter
	 * the hierarchical relationship between elements
	 * should be checked through SUNW,FRUID page.
	 * u_watch is a watch dog to check the prgress of unresolved
	 * node.
	 */
	u_watch = u_tail;
	while (u_head) {
		child = u_head;
		u_head = u_head->spt_sibling;
		if (u_head == NULL)
			u_tail = NULL;
		child->spt_sibling = NULL;
		if (ses_phys_tree_insert(mod, &sproot, child) != 0) {
			u_tail->spt_sibling = child;
			u_tail = child;
			if (child == u_watch) {
				/*
				 * We just scanned one round for the
				 * unresolved list. Check to see whether we
				 * have nodes inserted, if none, we should
				 * break in case of an indefinite loop.
				 */
				if (u_inserted == 0) {
					/*
					 * Indicate there is unhandled node.
					 * Chain free the whole unsolved
					 * list here.
					 */
					u_left++;
					break;
				} else {
					u_inserted = 0;
					u_watch = u_tail;
				}
			}
		} else {
			/*
			 * We just inserted one rpnode, increment the
			 * unsolved_inserted counter. We will utilize this
			 * counter to detect an indefinite insertion loop.
			 */
			u_inserted++;
			if (child == u_watch) {
				/*
				 * watch dog node itself is inserted.
				 * Set it to the tail and refresh the watching.
				 */
				u_watch = u_tail;
				u_inserted = 0;
				u_left = 0;
			}
		}
	}

	/* check if there is left out unresolved nodes. */
	if (u_left) {
		topo_mod_dprintf(mod, "ses_construct_phys_tree(): "
		    "Failed to construct physical view of the following "
		    "ses elements of Chassis CSN %s.", cp->sec_csn);
		while (u_head) {
			u_tail = u_head->spt_sibling;
			topo_mod_dprintf(mod,
			    "\telement type (%d) and instance (%d)",
			    u_head->spt_senumnode->sen_type,
			    u_head->spt_senumnode->sen_instance);
			topo_mod_free(mod, u_head, sizeof (ses_phys_tree_t));
			u_head = u_tail;
		}
		return (-1);
	}

	return (0);
}

/*
 * Free the whole phys tree.
 */
static void ses_phys_tree_free(topo_mod_t *mod, ses_phys_tree_t *sproot)
{
	if (sproot == NULL)
		return;

	/* Free child tree. */
	if (sproot->spt_child) {
		ses_phys_tree_free(mod, sproot->spt_child);
	}

	/* Free sibling trees. */
	if (sproot->spt_sibling) {
		ses_phys_tree_free(mod, sproot->spt_sibling);
	}

	/* Free root node itself. */
	topo_mod_free(mod, sproot, sizeof (ses_phys_tree_t));
}

/*
 * Parses phys_enum_type table to get the index of the given type.
 */
static boolean_t
is_type_enumerated(ses_phys_tree_t *node, int *index)
{
	int i;

	for (i = 0; i < N_PHYS_ENUM_TYPES; i++) {
		if (node->spt_senumnode->sen_type ==
		    phys_enum_type_list[i].pet_type) {
			*index = i;
			return (B_TRUE);
		}
	}
	return (B_FALSE);
}

/*
 * Recusrive routine for top-down enumeration of the tree.
 */
static int
ses_enumerate_node(ses_enum_data_t *sdp, tnode_t *pnode, ses_enum_chassis_t *cp,
    ses_phys_tree_t *parent, int mrange[])
{
	topo_mod_t *mod = sdp->sed_mod;
	ses_phys_tree_t *child = NULL;
	int i, ret = 0, ret_ch;
	uint64_t prevtype = SES_ET_UNSPECIFIED;
	ses_phys_tree_t *dirfru = NULL;
	tnode_t *tn = NULL, *frutn = NULL;

	if (parent == NULL) {
		return (0);
	}

	for (child = parent->spt_child; child != NULL;
	    child = child->spt_sibling) {
		if (is_type_enumerated(child, &i)) {
			if (prevtype != phys_enum_type_list[i].pet_type) {
				/* check if range needs to be created. */
				if (phys_enum_type_list[i].pet_dorange &&
				    topo_node_range_create(mod, pnode,
				    phys_enum_type_list[i].pet_nodename, 0,
				    mrange[i]) != 0) {
					topo_mod_dprintf(mod,
					    "topo_node_create_range() failed: "
					    "%s", topo_mod_errmsg(mod));
					return (-1);
				}
				prevtype = phys_enum_type_list[i].pet_type;
			}

			if (!(child->spt_isfru)) {
				for (dirfru = parent; dirfru != NULL;
				    dirfru = dirfru->spt_parent) {
					if (dirfru->spt_isfru) {
						break;
					}
				}
				/* found direct FRU node. */
				if (dirfru) {
					frutn = dirfru->spt_tnode;
				} else {
					frutn = NULL;
				}
			} else {
				frutn = NULL;
			}

			if (ses_create_generic(sdp, child->spt_senumnode,
			    pnode, frutn, phys_enum_type_list[i].pet_nodename,
			    phys_enum_type_list[i].pet_defaultlabel, &tn) != 0)
				return (-1);

			child->spt_tnode = tn;
			/*
			 * For some SES element there may be protocol specific
			 * information to process.   Here we are processing
			 * the association between enclosure controller and
			 * SAS expanders.
			 */
			if (phys_enum_type_list[i].pet_type ==
			    SES_ET_ESC_ELECTRONICS) {
				/* create SAS expander node */
				if (ses_create_protocol_specific(sdp,
				    child->spt_senumnode, tn,
				    phys_enum_type_list[i].pet_type,
				    cp, phys_enum_type_list[i].pet_dorange) !=
				    0) {
					return (-1);
				}
			}
		} else {
			continue;
		}
		ret_ch = ses_enumerate_node(sdp, tn, cp, child, mrange);
		if (ret_ch)
			ret = ret_ch; /* there was an error and set the ret. */
	}

	return (ret);
}

/*
 * Instantiate types of nodes that are specified in the hierarchy
 * element type list.
 */
static int
ses_create_children_from_phys_tree(ses_enum_data_t *sdp, tnode_t *pnode,
    ses_enum_chassis_t *cp, ses_phys_tree_t *phys_tree)
{
	topo_mod_t *mod = sdp->sed_mod;
	int mrange[N_PHYS_ENUM_TYPES] = { 0 };
	ses_enum_node_t *snp;
	int i, ret;

	/*
	 * First get max range for each type of element to be enumerated.
	 */
	for (i = 0; i < N_PHYS_ENUM_TYPES; i++) {
		if (phys_enum_type_list[i].pet_dorange) {
			for (snp = topo_list_next(&cp->sec_nodes); snp != NULL;
			    snp = topo_list_next(snp)) {
				if (snp->sen_type ==
				    phys_enum_type_list[i].pet_type) {
					if (snp->sen_instance > mrange[i])
						mrange[i] =
						    snp->sen_instance;
				}
			}
		}
	}

	topo_mod_dprintf(mod, "%s: creating nodes from FRU hierarchy tree.",
	    cp->sec_csn);

	if ((ret = ses_enumerate_node(sdp, pnode, cp, phys_tree, mrange)) !=
	    0) {
		topo_mod_dprintf(mod,
		    "ses_create_children_from_phys_tree() failed: ");
		return (ret);
	}

	return (0);
}

/*
 * Instantiate a new chassis instance in the topology.
 */
static int
ses_create_chassis(ses_enum_data_t *sdp, tnode_t *pnode, ses_enum_chassis_t *cp)
{
	topo_mod_t *mod = sdp->sed_mod;
	nvlist_t *props;
	char *raw_manufacturer, *raw_model, *raw_revision;
	char *manufacturer = NULL, *model = NULL, *product = NULL;
	char *revision = NULL;
	char *serial;
	char **paths;
	size_t prodlen;
	tnode_t *tn;
	nvlist_t *fmri = NULL, *auth = NULL;
	int ret = -1;
	ses_enum_node_t *snp;
	ses_enum_target_t *stp;
	ses_enum_chassis_t *scp;
	int i, err;
	uint64_t sc_count = 0, pindex;
	ses_phys_tree_t	*sproot = NULL;
	hrtime_t start;
	hrtime_t end;
	double duration;

	/*
	 * Ignore any internal enclosures.
	 */
	if (cp->sec_internal)
		return (0);

	/*
	 * Check to see if there are any devices presennt in the chassis.  If
	 * not, ignore the chassis alltogether.  This is most useful for
	 * ignoring internal HBAs that present a SES target but don't actually
	 * manage any of the devices.
	 */
	for (snp = topo_list_next(&cp->sec_nodes); snp != NULL;
	    snp = topo_list_next(snp)) {
		if (snp->sen_type == SES_ET_DEVICE ||
		    snp->sen_type == SES_ET_ARRAY_DEVICE)
			break;
	}

	if (snp == NULL)
		return (0);

	props = ses_node_props(cp->sec_enclosure);

	/*
	 * We use the following property mappings:
	 *
	 * 	manufacturer		vendor-id
	 * 	model			product-id
	 * 	serial-number		libses-chassis-serial
	 */
	verify(nvlist_lookup_string(props, SES_EN_PROP_VID,
	    &raw_manufacturer) == 0);
	verify(nvlist_lookup_string(props, SES_EN_PROP_PID, &raw_model) == 0);
	verify(nvlist_lookup_string(props, SES_EN_PROP_REV,
	    &raw_revision) == 0);
	verify(nvlist_lookup_string(props, LIBSES_EN_PROP_CSN, &serial) == 0);

	/*
	 * To construct the authority information, we 'clean' each string by
	 * removing any offensive characters and trimmming whitespace.  For the
	 * 'product-id', we use a concatenation of 'manufacturer-model'.  We
	 * also take the numerical serial number and convert it to a string.
	 */
	if ((manufacturer = disk_auth_clean(mod, raw_manufacturer)) == NULL ||
	    (model = disk_auth_clean(mod, raw_model)) == NULL ||
	    (revision = disk_auth_clean(mod, raw_revision)) == NULL) {
		goto error;
	}

	prodlen = strlen(manufacturer) + strlen(model) + 2;
	if ((product = topo_mod_alloc(mod, prodlen)) == NULL)
		goto error;

	(void) snprintf(product, prodlen, "%s-%s", manufacturer, model);

	/*
	 * Construct the topo node and bind it to our parent.
	 */
	if (topo_mod_nvalloc(mod, &auth, NV_UNIQUE_NAME) != 0)
		goto error;

	if (nvlist_add_string(auth, FM_FMRI_AUTH_PRODUCT, product) != 0 ||
	    nvlist_add_string(auth, FM_FMRI_AUTH_CHASSIS, serial) != 0) {
		(void) topo_mod_seterrno(mod, EMOD_NVL_INVAL);
		goto error;
	}

	/*
	 * We pass NULL for the parent FMRI because there is no resource
	 * associated with it.  For the toplevel enclosure, we leave the
	 * serial/part/revision portions empty, which are reserved for
	 * individual components within the chassis.
	 */
	if ((fmri = topo_mod_hcfmri(mod, NULL, FM_HC_SCHEME_VERSION,
	    SES_ENCLOSURE, cp->sec_instance, NULL, auth,
	    model, revision, serial)) == NULL) {
		topo_mod_dprintf(mod, "topo_mod_hcfmri() failed: %s",
		    topo_mod_errmsg(mod));
		goto error;
	}

	if ((tn = topo_node_bind(mod, pnode, SES_ENCLOSURE,
	    cp->sec_instance, fmri)) == NULL) {
		topo_mod_dprintf(mod, "topo_node_bind() failed: %s",
		    topo_mod_errmsg(mod));
		goto error;
	}

	if (topo_method_register(mod, tn, ses_enclosure_methods) != 0) {
		topo_mod_dprintf(mod,
		    "topo_method_register() failed: %s",
		    topo_mod_errmsg(mod));
		goto error;
	}

	if (ses_set_standard_props(mod, NULL, tn, auth,
	    ses_node_id(cp->sec_enclosure), cp->sec_target->set_devpath) != 0)
		goto error;

	/*
	 * For enclosures, we want to include all possible targets (for upgrade
	 * purposes).
	 */
	for (i = 0, stp = topo_list_next(&cp->sec_targets); stp != NULL;
	    stp = topo_list_next(stp), i++)
		;

	verify(i != 0);
	paths = alloca(i * sizeof (char *));

	for (i = 0, stp = topo_list_next(&cp->sec_targets); stp != NULL;
	    stp = topo_list_next(stp), i++)
		paths[i] = stp->set_devpath;


	if (topo_prop_set_string_array(tn, TOPO_PGROUP_SES,
	    TOPO_PROP_PATHS, TOPO_PROP_IMMUTABLE, (const char **)paths,
	    i, &err) != 0) {
		topo_mod_dprintf(mod,
		    "failed to create property %s: %s\n",
		    TOPO_PROP_PATHS, topo_strerror(err));
		goto error;
	}

	if (nvlist_lookup_uint64(props,
	    LIBSES_PROP_PHYS_PARENT, &pindex) == 0) {
		start = gethrtime(); /* to mearusre performance */
		/*
		 * The enclosure is supported through SUNW,FRUID.
		 * Need to enumerate the nodes through hierarchical order.
		 */
		if ((sproot = topo_mod_zalloc(mod,
		    sizeof (ses_phys_tree_t))) == NULL) {
			topo_mod_dprintf(mod,
			    "failed to allocate root: %s\n",
			    topo_strerror(err));
			goto error;
		}
		sproot->spt_pindex = pindex;
		if (nvlist_lookup_boolean_value(props,
		    LIBSES_PROP_FRU, &sproot->spt_isfru) != 0) {
			topo_mod_dprintf(mod,
			    "ses_create_chassis(): Failed to find prop %s "
			    "on enclosure element (CSN %s).",
			    LIBSES_PROP_FRU, cp->sec_csn);
			/* an enclosure should be a FRU. continue to process. */
			sproot->spt_isfru = B_TRUE;
		}
		if (nvlist_lookup_uint64(props,
		    SES_PROP_ELEMENT_ONLY_INDEX,
		    &sproot->spt_eonlyindex) != 0) {
			topo_mod_dprintf(mod,
			    "ses_create_chassis(): Failed to find prop %s "
			    "on enclosure element (CSN %s).",
			    LIBSES_PROP_PHYS_PARENT, cp->sec_csn);
			topo_mod_free(mod, sproot, sizeof (ses_phys_tree_t));
			goto error;
		}
		if (sproot->spt_pindex != sproot->spt_eonlyindex) {
			topo_mod_dprintf(mod, "ses_create_chassis(): "
			    "Enclosure element(CSN %s) should have "
			    "itself as the parent to be the root node "
			    "of FRU hierarchical tree.)", cp->sec_csn);
			topo_mod_free(mod, sproot, sizeof (ses_phys_tree_t));
			goto error;
		} else {
			sproot->spt_snode = cp->sec_enclosure;
			sproot->spt_tnode = tn;
			/* construct a tree. */
			if (ses_construct_phys_tree(sdp, cp, sproot) != 0) {
				topo_mod_dprintf(mod, "ses_create_chassis(): "
				    "Failed to construct FRU hierarchical "
				    "tree on enclosure (CSN %s.)",
				    cp->sec_csn);
			}

			/* enumerate elements from the tree. */
			if (ses_create_children_from_phys_tree(sdp, tn, cp,
			    sproot) != 0) {
				topo_mod_dprintf(mod, "ses_create_chassis(): "
				    "Failed to create children topo nodes out "
				    "of FRU hierarchical tree on enclosure "
				    "(CSN %s).", cp->sec_csn);
			}
			/* destroy the phys tree. */
			ses_phys_tree_free(mod, sproot);
		}

		end = gethrtime();
		duration = end - start;
		duration /= HR_SECOND;
		topo_mod_dprintf(mod,
		    "FRU boundary tree based enumeration: %.6f seconds",
		    duration);
	} else {
		/*
		 * Create the nodes for power supplies, fans, controllers and
		 * devices.  Note that SAS exopander nodes and connector nodes
		 * are handled through protocol specific processing of
		 * controllers.
		 */
		if (ses_create_children(sdp, tn, SES_ET_POWER_SUPPLY,
		    PSU, "PSU", cp, B_TRUE) != 0 ||
		    ses_create_children(sdp, tn, SES_ET_COOLING,
		    FAN, "FAN", cp, B_TRUE) != 0 ||
		    ses_create_children(sdp, tn, SES_ET_ESC_ELECTRONICS,
		    CONTROLLER, "CONTROLLER", cp, B_TRUE) != 0 ||
		    ses_create_children(sdp, tn, SES_ET_DEVICE,
		    BAY, "BAY", cp, B_TRUE) != 0 ||
		    ses_create_children(sdp, tn, SES_ET_ARRAY_DEVICE,
		    BAY, "BAY", cp, B_TRUE) != 0)
			goto error;
	}

	if (cp->sec_maxinstance >= 0 &&
	    (topo_node_range_create(mod, tn, SUBCHASSIS, 0,
	    cp->sec_maxinstance) != 0)) {
		topo_mod_dprintf(mod, "topo_node_create_range() failed: %s",
		    topo_mod_errmsg(mod));
		goto error;
	}

	for (scp = topo_list_next(&cp->sec_subchassis); scp != NULL;
	    scp = topo_list_next(scp)) {

		if (ses_create_subchassis(sdp, tn, scp) != 0)
			goto error;

		topo_mod_dprintf(mod, "created Subchassis node with "
		    "instance %u\nand target (%s) under Chassis with CSN %s",
		    scp->sec_instance, scp->sec_target->set_devpath,
		    cp->sec_csn);

		sc_count++;
	}

	topo_mod_dprintf(mod, "%s: created %llu %s nodes",
	    cp->sec_csn, sc_count, SUBCHASSIS);

	cp->sec_target->set_refcount++;
	topo_node_setspecific(tn, cp->sec_target);

	ret = 0;
error:
	topo_mod_strfree(mod, manufacturer);
	topo_mod_strfree(mod, model);
	topo_mod_strfree(mod, revision);
	topo_mod_strfree(mod, product);

	nvlist_free(fmri);
	nvlist_free(auth);
	return (ret);
}

/*
 * Create a bay node explicitly enumerated via XML.
 */
static int
ses_create_bays(ses_enum_data_t *sdp, tnode_t *pnode)
{
	topo_mod_t *mod = sdp->sed_mod;
	ses_enum_chassis_t *cp;

	/*
	 * Iterate over chassis looking for an internal enclosure.  This
	 * property is set via a vendor-specific plugin, and there should only
	 * ever be a single internal chassis in a system.
	 */
	for (cp = topo_list_next(&sdp->sed_chassis); cp != NULL;
	    cp = topo_list_next(cp)) {
		if (cp->sec_internal)
			break;
	}

	if (cp == NULL) {
		topo_mod_dprintf(mod, "failed to find internal chassis\n");
		return (-1);
	}

	if (ses_create_children(sdp, pnode, SES_ET_DEVICE,
	    BAY, "BAY", cp, B_FALSE) != 0 ||
	    ses_create_children(sdp, pnode, SES_ET_ARRAY_DEVICE,
	    BAY, "BAY", cp, B_FALSE) != 0)
		return (-1);

	return (0);
}

/*
 * Initialize chassis or subchassis.
 */
static int
ses_init_chassis(topo_mod_t *mod, ses_enum_data_t *sdp, ses_enum_chassis_t *pcp,
    ses_enum_chassis_t *cp, ses_node_t *np, nvlist_t *props,
    uint64_t subchassis, ses_chassis_type_e flags)
{
	boolean_t internal, ident;

	assert((flags & (SES_NEW_CHASSIS | SES_NEW_SUBCHASSIS |
	    SES_DUP_CHASSIS | SES_DUP_SUBCHASSIS)) != 0);

	assert(cp != NULL);
	assert(np != NULL);
	assert(props != NULL);

	if (flags & (SES_NEW_SUBCHASSIS | SES_DUP_SUBCHASSIS))
		assert(pcp != NULL);

	topo_mod_dprintf(mod, "ses_init_chassis: %s: index %llu, flags (%d)",
	    sdp->sed_name, subchassis, flags);

	if (flags & (SES_NEW_CHASSIS | SES_NEW_SUBCHASSIS)) {

		topo_mod_dprintf(mod, "new chassis/subchassis");
		if (nvlist_lookup_boolean_value(props,
		    LIBSES_EN_PROP_INTERNAL, &internal) == 0)
			cp->sec_internal = internal;

		cp->sec_enclosure = np;
		cp->sec_target = sdp->sed_target;

		if (flags & SES_NEW_CHASSIS) {
			if (!cp->sec_internal)
				cp->sec_instance = sdp->sed_instance++;
			topo_list_append(&sdp->sed_chassis, cp);
		} else {
			if (subchassis != NO_SUBCHASSIS)
				cp->sec_instance = subchassis;
			else
				cp->sec_instance = pcp->sec_scinstance++;

			if (cp->sec_instance > pcp->sec_maxinstance)
				pcp->sec_maxinstance = cp->sec_instance;

			topo_list_append(&pcp->sec_subchassis, cp);
		}

	} else {
		topo_mod_dprintf(mod, "dup chassis/subchassis");
		if (nvlist_lookup_boolean_value(props,
		    SES_PROP_IDENT, &ident) == 0) {
			topo_mod_dprintf(mod,  "overriding enclosure node");

			cp->sec_enclosure = np;
			cp->sec_target = sdp->sed_target;
		}
	}

	topo_list_append(&cp->sec_targets, sdp->sed_target);
	sdp->sed_current = cp;

	return (0);
}

/*
 * Gather nodes from the current SES target into our chassis list, merging the
 * results if necessary.
 */
static ses_walk_action_t
ses_enum_gather(ses_node_t *np, void *data)
{
	nvlist_t *props = ses_node_props(np);
	ses_enum_data_t *sdp = data;
	topo_mod_t *mod = sdp->sed_mod;
	ses_enum_chassis_t *cp, *scp;
	ses_enum_node_t *snp;
	ses_alt_node_t *sap;
	char *csn;
	uint64_t instance, type;
	uint64_t prevstatus, status;
	boolean_t report;
	uint64_t subchassis = NO_SUBCHASSIS;

	if (ses_node_type(np) == SES_NODE_ENCLOSURE) {
		/*
		 * If we have already identified the chassis for this target,
		 * then this is a secondary enclosure and we should ignore it,
		 * along with the rest of the tree (since this is depth-first).
		 */
		if (sdp->sed_current != NULL)
			return (SES_WALK_ACTION_TERMINATE);

		/*
		 * Go through the list of chassis we have seen so far and see
		 * if this serial number matches one of the known values.
		 * If so, check whether this enclosure is a subchassis.
		 */
		if (nvlist_lookup_string(props, LIBSES_EN_PROP_CSN,
		    &csn) != 0)
			return (SES_WALK_ACTION_TERMINATE);

		(void) nvlist_lookup_uint64(props, LIBSES_EN_PROP_SUBCHASSIS_ID,
		    &subchassis);

		topo_mod_dprintf(mod, "ses_enum_gather: Enclosure Node (%s) "
		    "CSN (%s), subchassis (%llu)", sdp->sed_name, csn,
		    subchassis);

		/*
		 * We need to determine whether this enclosure node
		 * represents a chassis or a subchassis. Since we may
		 * receive the enclosure nodes in a non-deterministic
		 * manner, we need to account for all possible combinations:
		 *	1. Chassis for the current CSN has not yet been
		 *	   allocated
		 *		1.1 This is a new chassis:
		 *			allocate and instantiate the chassis
		 *		1.2 This is a new subchassis:
		 *			allocate a placeholder chassis
		 *			allocate and instantiate the subchassis
		 *			link the subchassis to the chassis
		 *	2. Chassis for the current CSN has been allocated
		 *		2.1 This is a duplicate chassis enclosure
		 *			check whether to override old chassis
		 *			append to chassis' target list
		 *		2.2 Only placeholder chassis exists
		 *			fill in the chassis fields
		 *		2.3 This is a new subchassis
		 *			allocate and instantiate the subchassis
		 *			link the subchassis to the chassis
		 *		2.4 This is a duplicate subchassis enclosure
		 *			 check whether to override old chassis
		 *			 append to chassis' target list
		 */

		for (cp = topo_list_next(&sdp->sed_chassis); cp != NULL;
		    cp = topo_list_next(cp))
			if (strcmp(cp->sec_csn, csn) == 0)
				break;

		if (cp == NULL) {
			/* 1. Haven't seen a chassis with this CSN before */

			if ((cp = topo_mod_zalloc(mod,
			    sizeof (ses_enum_chassis_t))) == NULL)
				goto error;

			cp->sec_scinstance = SES_STARTING_SUBCHASSIS;
			cp->sec_maxinstance = -1;
			cp->sec_csn = csn;

			if (subchassis == NO_SUBCHASSIS) {
				/* 1.1 This is a new chassis */

				topo_mod_dprintf(mod, "%s: Initialize new "
				    "chassis with CSN %s", sdp->sed_name, csn);

				if (ses_init_chassis(mod, sdp, NULL, cp,
				    np, props, NO_SUBCHASSIS,
				    SES_NEW_CHASSIS) < 0)
					goto error;
			} else {
				/* 1.2 This is a new subchassis */

				topo_mod_dprintf(mod, "%s: Initialize new "
				    "subchassis with CSN %s and index %llu",
				    sdp->sed_name, csn, subchassis);

				if ((scp = topo_mod_zalloc(mod,
				    sizeof (ses_enum_chassis_t))) == NULL)
					goto error;

				scp->sec_csn = csn;

				if (ses_init_chassis(mod, sdp, cp, scp, np,
				    props, subchassis, SES_NEW_SUBCHASSIS) < 0)
					goto error;
			}
		} else {
			/*
			 * We have a chassis or subchassis with this CSN.  If
			 * it's a chassis, we must check to see whether it is
			 * a placeholder previously created because we found a
			 * subchassis with this CSN.  We will know that because
			 * the sec_target value will not be set; it is set only
			 * in ses_init_chassis().  In that case, initialise it
			 * as a new chassis; otherwise, it's a duplicate and we
			 * need to append only.
			 */
			if (subchassis == NO_SUBCHASSIS) {
				if (cp->sec_target != NULL) {
					/* 2.1 This is a duplicate chassis */

					topo_mod_dprintf(mod, "%s: Append "
					    "duplicate chassis with CSN (%s)",
					    sdp->sed_name, csn);

					if (ses_init_chassis(mod, sdp, NULL, cp,
					    np, props, NO_SUBCHASSIS,
					    SES_DUP_CHASSIS) < 0)
						goto error;
				} else {
					/* Placeholder chassis - init it up */
					topo_mod_dprintf(mod, "%s: Initialize"
					    "placeholder chassis with CSN %s",
					    sdp->sed_name, csn);

					if (ses_init_chassis(mod, sdp, NULL,
					    cp, np, props, NO_SUBCHASSIS,
					    SES_NEW_CHASSIS) < 0)
						goto error;

				}
			} else {
				/* This is a subchassis */

				for (scp = topo_list_next(&cp->sec_subchassis);
				    scp != NULL; scp = topo_list_next(scp))
					if (scp->sec_instance == subchassis)
						break;

				if (scp == NULL) {
					/* 2.3 This is a new subchassis */

					topo_mod_dprintf(mod, "%s: Initialize "
					    "new subchassis with CSN (%s) "
					    "and LID (%s)",
					    sdp->sed_name, csn);

					if ((scp = topo_mod_zalloc(mod,
					    sizeof (ses_enum_chassis_t)))
					    == NULL)
						goto error;

					scp->sec_csn = csn;

					if (ses_init_chassis(mod, sdp, cp, scp,
					    np, props, subchassis,
					    SES_NEW_SUBCHASSIS) < 0)
						goto error;
				} else {
					/* 2.4 This is a duplicate subchassis */

					topo_mod_dprintf(mod, "%s: Append "
					    "duplicate subchassis with "
					    "CSN (%s)", sdp->sed_name, csn);

					if (ses_init_chassis(mod, sdp, cp, scp,
					    np, props, subchassis,
					    SES_DUP_SUBCHASSIS) < 0)
						goto error;
				}
			}
		}
	} else if (ses_node_type(np) == SES_NODE_ELEMENT) {
		/*
		 * If we haven't yet seen an enclosure node and identified the
		 * current chassis, something is very wrong; bail out.
		 */
		if (sdp->sed_current == NULL)
			return (SES_WALK_ACTION_TERMINATE);

		/*
		 * If this isn't one of the element types we care about, then
		 * ignore it.
		 */
		verify(nvlist_lookup_uint64(props, SES_PROP_ELEMENT_TYPE,
		    &type) == 0);
		if (type != SES_ET_DEVICE &&
		    type != SES_ET_ARRAY_DEVICE &&
		    type != SES_ET_SUNW_FANBOARD &&
		    type != SES_ET_SUNW_FANMODULE &&
		    type != SES_ET_COOLING &&
		    type != SES_ET_SUNW_POWERBOARD &&
		    type != SES_ET_SUNW_POWERMODULE &&
		    type != SES_ET_POWER_SUPPLY &&
		    type != SES_ET_ESC_ELECTRONICS &&
		    type != SES_ET_SAS_EXPANDER &&
		    type != SES_ET_SAS_CONNECTOR)
			return (SES_WALK_ACTION_CONTINUE);

		/*
		 * Get the current instance number and see if we already know
		 * about this element.  If so, it means we have multiple paths
		 * to the same elements, and we should ignore the current path.
		 */
		verify(nvlist_lookup_uint64(props, SES_PROP_ELEMENT_CLASS_INDEX,
		    &instance) == 0);
		if (type == SES_ET_DEVICE || type == SES_ET_ARRAY_DEVICE)
			(void) nvlist_lookup_uint64(props, SES_PROP_BAY_NUMBER,
			    &instance);

		cp = sdp->sed_current;

		for (snp = topo_list_next(&cp->sec_nodes); snp != NULL;
		    snp = topo_list_next(snp)) {
			if (snp->sen_type == type &&
			    snp->sen_instance == instance)
				break;
		}

		/*
		 * We prefer the new element under the following circumstances:
		 *
		 * - The currently known element's status is unknown or not
		 *   available, but the new element has a known status.  This
		 *   occurs if a given element is only available through a
		 *   particular target.
		 *
		 * - This is an ESC_ELECTRONICS element, and the 'reported-via'
		 *   property is set.  This allows us to get reliable firmware
		 *   revision information from the enclosure node.
		 */
		if (snp != NULL) {
			if (nvlist_lookup_uint64(
			    ses_node_props(snp->sen_node),
			    SES_PROP_STATUS_CODE, &prevstatus) != 0)
				prevstatus = SES_ESC_UNSUPPORTED;
			if (nvlist_lookup_uint64(
			    props, SES_PROP_STATUS_CODE, &status) != 0)
				status = SES_ESC_UNSUPPORTED;
			if (nvlist_lookup_boolean_value(
			    props, SES_PROP_REPORT, &report) != 0)
				report = B_FALSE;

			if ((SES_STATUS_UNAVAIL(prevstatus) &&
			    !SES_STATUS_UNAVAIL(status)) ||
			    (type == SES_ET_ESC_ELECTRONICS &&
			    report)) {
				snp->sen_node = np;
				snp->sen_target = sdp->sed_target;
			}

			if ((sap = topo_mod_zalloc(mod,
			    sizeof (ses_alt_node_t))) == NULL)
				goto error;

			sap->san_node = np;
			topo_list_append(&snp->sen_alt_nodes, sap);

			return (SES_WALK_ACTION_CONTINUE);
		}

		if ((snp = topo_mod_zalloc(mod,
		    sizeof (ses_enum_node_t))) == NULL)
			goto error;

		if ((sap = topo_mod_zalloc(mod,
		    sizeof (ses_alt_node_t))) == NULL) {
			topo_mod_free(mod, snp, sizeof (ses_enum_node_t));
			goto error;
		}

		topo_mod_dprintf(mod, "%s: adding node (%llu, %llu)",
		    sdp->sed_name, type, instance);
		snp->sen_node = np;
		snp->sen_type = type;
		snp->sen_instance = instance;
		snp->sen_target = sdp->sed_target;
		sap->san_node = np;
		topo_list_append(&snp->sen_alt_nodes, sap);
		topo_list_append(&cp->sec_nodes, snp);

		if (type == SES_ET_DEVICE)
			cp->sec_hasdev = B_TRUE;
	}

	return (SES_WALK_ACTION_CONTINUE);

error:
	sdp->sed_errno = -1;
	return (SES_WALK_ACTION_TERMINATE);
}

static int
ses_process_dir(const char *dirpath, ses_enum_data_t *sdp)
{
	topo_mod_t *mod = sdp->sed_mod;
	DIR *dir;
	struct dirent *dp;
	char path[PATH_MAX];
	ses_enum_target_t *stp;
	int err = -1;

	/*
	 * Open the SES target directory and iterate over any available
	 * targets.
	 */
	if ((dir = opendir(dirpath)) == NULL) {
		/*
		 * If the SES target directory does not exist, then return as if
		 * there are no active targets.
		 */
		topo_mod_dprintf(mod, "failed to open ses "
		    "directory '%s'", dirpath);
		return (0);
	}

	while ((dp = readdir(dir)) != NULL) {
		if (strcmp(dp->d_name, ".") == 0 ||
		    strcmp(dp->d_name, "..") == 0)
			continue;

		/*
		 * Create a new target instance and take a snapshot.
		 */
		if ((stp = topo_mod_zalloc(mod,
		    sizeof (ses_enum_target_t))) == NULL)
			goto error;

		(void) pthread_mutex_init(&stp->set_lock, NULL);

		(void) snprintf(path, sizeof (path), "%s/%s", dirpath,
		    dp->d_name);

		/*
		 * We keep track of the SES device path and export it on a
		 * per-node basis to allow higher level software to get to the
		 * corresponding SES state.
		 */
		if ((stp->set_devpath = topo_mod_strdup(mod, path)) == NULL) {
			topo_mod_free(mod, stp, sizeof (ses_enum_target_t));
			goto error;
		}

		if ((stp->set_target =
		    ses_open(LIBSES_VERSION, path)) == NULL) {
			topo_mod_dprintf(mod, "failed to open ses target "
			    "'%s': %s", dp->d_name, ses_errmsg());
			ses_sof_alloc(mod, stp->set_devpath);
			topo_mod_free(mod, stp, sizeof (ses_enum_target_t));
			continue;
		}
		topo_mod_dprintf(mod, "open contract");
		ses_ssl_alloc(mod, stp);
		ses_create_contract(mod, stp);

		stp->set_refcount = 1;
		sdp->sed_target = stp;
		stp->set_snap = ses_snap_hold(stp->set_target);
		stp->set_snaptime = gethrtime();

		/*
		 * Enumerate over all SES elements and merge them into the
		 * correct ses_enum_chassis_t.
		 */
		sdp->sed_current = NULL;
		sdp->sed_errno = 0;
		sdp->sed_name = dp->d_name;
		(void) ses_walk(stp->set_snap, ses_enum_gather, sdp);

		if (sdp->sed_errno != 0)
			goto error;
	}

	err = 0;
error:
	(void) closedir(dir);
	return (err);
}

static void
ses_release(topo_mod_t *mod, tnode_t *tn)
{
	ses_enum_target_t *stp;

	if ((stp = topo_node_getspecific(tn)) != NULL) {
		topo_node_setspecific(tn, NULL);
		ses_target_free(mod, stp);
	}
}

/*ARGSUSED*/
static int
ses_enum(topo_mod_t *mod, tnode_t *rnode, const char *name,
    topo_instance_t min, topo_instance_t max, void *arg, void *notused)
{
	ses_enum_chassis_t *cp;
	ses_enum_data_t *data;

	/*
	 * Check to make sure we're being invoked sensibly, and that we're not
	 * being invoked as part of a post-processing step.
	 */
	if (strcmp(name, SES_ENCLOSURE) != 0 && strcmp(name, BAY) != 0)
		return (0);

	/*
	 * If this is the first time we've called our enumeration method, then
	 * gather information about any available enclosures.
	 */
	if ((data = topo_mod_getspecific(mod)) == NULL) {
		ses_sof_freeall(mod);
		if ((data = topo_mod_zalloc(mod, sizeof (ses_enum_data_t))) ==
		    NULL)
			return (-1);

		data->sed_mod = mod;
		topo_mod_setspecific(mod, data);

		if (dev_list_gather(mod, &data->sed_devs) != 0)
			goto error;

		/*
		 * We search both the ses(7D) and sgen(7D) locations, so we are
		 * independent of any particular driver class bindings.
		 */
		if (ses_process_dir("/dev/es", data) != 0 ||
		    ses_process_dir("/dev/scsi/ses", data) != 0)
			goto error;
	}

	if (strcmp(name, SES_ENCLOSURE) == 0) {
		/*
		 * This is a request to enumerate external enclosures.  Go
		 * through all the targets and create chassis nodes where
		 * necessary.
		 */
		for (cp = topo_list_next(&data->sed_chassis); cp != NULL;
		    cp = topo_list_next(cp)) {
			if (ses_create_chassis(data, rnode, cp) != 0)
				goto error;
		}
	} else {
		/*
		 * This is a request to enumerate a specific bay underneath the
		 * root chassis (for internal disks).
		 */
		if (ses_create_bays(data, rnode) != 0)
			goto error;
	}

	/*
	 * This is a bit of a kludge.  In order to allow internal disks to be
	 * enumerated and share snapshot-specific information with the external
	 * enclosure enumeration, we rely on the fact that we will be invoked
	 * for the 'ses-enclosure' node last.
	 */
	if (strcmp(name, SES_ENCLOSURE) == 0) {
		for (cp = topo_list_next(&data->sed_chassis); cp != NULL;
		    cp = topo_list_next(cp))
			ses_data_free(data, cp);
		ses_data_free(data, NULL);
		topo_mod_setspecific(mod, NULL);
	}
	return (0);

error:
	for (cp = topo_list_next(&data->sed_chassis); cp != NULL;
	    cp = topo_list_next(cp))
		ses_data_free(data, cp);
	ses_data_free(data, NULL);
	topo_mod_setspecific(mod, NULL);
	return (-1);
}

static const topo_modops_t ses_ops =
	{ ses_enum, ses_release };

static topo_modinfo_t ses_info =
	{ SES_ENCLOSURE, FM_FMRI_SCHEME_HC, SES_VERSION, &ses_ops };

/*ARGSUSED*/
int
_topo_init(topo_mod_t *mod, topo_version_t version)
{
	int rval;

	if (getenv("TOPOSESDEBUG") != NULL)
		topo_mod_setdebug(mod);

	topo_mod_dprintf(mod, "initializing %s enumerator\n",
	    SES_ENCLOSURE);

	if ((rval = topo_mod_register(mod, &ses_info, TOPO_VERSION)) == 0)
		ses_thread_init(mod);

	return (rval);
}

void
_topo_fini(topo_mod_t *mod)
{
	ses_thread_fini(mod);
	ses_sof_freeall(mod);
	topo_mod_unregister(mod);
}
