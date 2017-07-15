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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2012 Garrett D'Amore <garrett@damore.org>.  All rights reserved.
 */
/*
 * Fibre channel Transport Library (fctl)
 *
 * Function naming conventions:
 *		Functions called from ULPs begin with fc_ulp_
 *		Functions called from FCAs begin with fc_fca_
 *		Internal functions begin with fctl_
 *
 * Fibre channel packet layout:
 *	  +---------------------+<--------+
 *	  |			|	  |
 *	  | ULP Packet private	|	  |
 *	  |			|	  |
 *	  +---------------------+	  |
 *	  |			|---------+
 *	  |  struct  fc_packet	|---------+
 *	  |			|	  |
 *	  +---------------------+<--------+
 *	  |			|
 *	  | FCA Packet private	|
 *	  |			|
 *	  +---------------------+
 *
 * So you  loved  the  ascii  art ?  It's  strongly  desirable	to  cache
 * allocate the entire packet in one common  place.  So we define a set a
 * of rules.  In a  contiguous	block of memory,  the top  portion of the
 * block points to ulp packet  private	area, next follows the	fc_packet
 * structure used  extensively by all the consumers and what follows this
 * is the FCA packet private.  Note that given a packet	 structure, it is
 * possible  to get to the  ULP	 and  FCA  Packet  private  fields  using
 * ulp_private and fca_private fields (which hold pointers) respectively.
 *
 * It should be noted with a grain of salt that ULP Packet  private  size
 * varies  between two different  ULP types, So this poses a challenge to
 * compute the correct	size of the whole block on a per port basis.  The
 * transport  layer  doesn't have a problem in dealing with  FCA   packet
 * private  sizes as it is the sole  manager of ports  underneath.  Since
 * it's not a good idea to cache allocate  different  sizes of memory for
 * different ULPs and have the ability to choose from one of these caches
 * based on ULP type during every packet  allocation,  the transport some
 * what	 wisely (?)  hands off this job of cache  allocation  to the ULPs
 * themselves.
 *
 * That means FCAs need to make their  packet  private size  known to the
 * transport   to  pass	 it  up	 to  the   ULPs.  This	is  done   during
 * fc_fca_attach().  And the transport passes this size up to ULPs during
 * fc_ulp_port_attach() of each ULP.
 *
 * This	 leaves	 us with  another  possible  question;	How  are  packets
 * allocated for ELS's started by the transport	 itself ?  Well, the port
 * driver  during  attach  time, cache	allocates  on a per port basis to
 * handle ELSs too.
 */

#include <sys/note.h>
#include <sys/types.h>
#include <sys/varargs.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/uio.h>
#include <sys/buf.h>
#include <sys/modctl.h>
#include <sys/open.h>
#include <sys/kmem.h>
#include <sys/poll.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/promif.h>
#include <sys/byteorder.h>
#include <sys/fibre-channel/fc.h>
#include <sys/fibre-channel/impl/fc_ulpif.h>
#include <sys/fibre-channel/impl/fc_fcaif.h>
#include <sys/fibre-channel/impl/fctl_private.h>
#include <sys/fibre-channel/impl/fc_portif.h>

/* These are referenced by fp.c!  */
int did_table_size = D_ID_HASH_TABLE_SIZE;
int pwwn_table_size = PWWN_HASH_TABLE_SIZE;

static fc_ulp_module_t	*fctl_ulp_modules;
static fc_fca_port_t	*fctl_fca_portlist;
static fc_ulp_list_t	*fctl_ulp_list;

static char fctl_greeting[] =
	"fctl: %s ULP same type (0x%x) as existing module.\n";

static char *fctl_undefined = "Undefined";

/*
 * This lock protects the fc_ulp_module_t linked list (i.e. mod_next field)
 */

static krwlock_t fctl_ulp_lock;

/*
 * The fctl_mod_ports_lock protects the mod_ports element in the
 * fc_ulp_ports_t structure
 */

static krwlock_t fctl_mod_ports_lock;

/*
 * fctl_port_lock protects the linked list of local port structures
 * (fctl_fca_portlist).	 When walking the list, this lock must be obtained
 * prior to any local port locks.
 */

static kmutex_t fctl_port_lock;
static kmutex_t	fctl_ulp_list_mutex;

static fctl_nwwn_list_t		*fctl_nwwn_hash_table;
static kmutex_t			fctl_nwwn_hash_mutex;
int fctl_nwwn_table_size = NWWN_HASH_TABLE_SIZE;

#if	!defined(lint)
_NOTE(MUTEX_PROTECTS_DATA(fctl_nwwn_hash_mutex, fctl_nwwn_hash_table))
_NOTE(MUTEX_PROTECTS_DATA(fctl_ulp_list_mutex, fctl_ulp_list))
_NOTE(RWLOCK_PROTECTS_DATA(fctl_ulp_lock, ulp_module::mod_next))
_NOTE(RWLOCK_PROTECTS_DATA(fctl_mod_ports_lock, ulp_module::mod_ports
    ulp_ports::port_handle))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ulp_module::mod_info))
_NOTE(MUTEX_PROTECTS_DATA(ulp_ports::port_mutex, ulp_ports::port_statec
    ulp_ports::port_dstate))
#endif /* lint */

#define	FCTL_VERSION		"20090729-1.70"
#define	FCTL_NAME_VERSION	"SunFC Transport v" FCTL_VERSION

char *fctl_version = FCTL_NAME_VERSION;

extern struct mod_ops mod_miscops;

static struct modlmisc modlmisc = {
	&mod_miscops,			/* type of module */
	FCTL_NAME_VERSION		/* Module name */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

static struct bus_ops fctl_fca_busops = {
	BUSO_REV,
	nullbusmap,			/* bus_map */
	NULL,				/* bus_get_intrspec */
	NULL,				/* bus_add_intrspec */
	NULL,				/* bus_remove_intrspec */
	i_ddi_map_fault,		/* bus_map_fault */
	NULL,				/* bus_dma_map */
	ddi_dma_allochdl,		/* bus_dma_allochdl */
	ddi_dma_freehdl,		/* bus_dma_freehdl */
	ddi_dma_bindhdl,		/* bus_dma_bindhdl */
	ddi_dma_unbindhdl,		/* bus_unbindhdl */
	ddi_dma_flush,			/* bus_dma_flush */
	ddi_dma_win,			/* bus_dma_win */
	ddi_dma_mctl,			/* bus_dma_ctl */
	fctl_fca_bus_ctl,		/* bus_ctl */
	ddi_bus_prop_op,		/* bus_prop_op */
	NULL,				/* bus_get_eventcookie */
	NULL,				/* bus_add_eventcall */
	NULL,				/* bus_remove_event */
	NULL,				/* bus_post_event */
	NULL,				/* bus_intr_ctl */
	NULL,				/* bus_config */
	NULL,				/* bus_unconfig */
	NULL,				/* bus_fm_init */
	NULL,				/* bus_fm_fini */
	NULL,				/* bus_fm_access_enter */
	NULL,				/* bus_fm_access_exit */
	NULL,				/* bus_power */
	NULL
};

struct kmem_cache *fctl_job_cache;

static fc_errmap_t fc_errlist [] = {
	{ FC_FAILURE,		"Operation failed"			},
	{ FC_SUCCESS,		"Operation success"			},
	{ FC_CAP_ERROR,		"Capability error"			},
	{ FC_CAP_FOUND,		"Capability found"			},
	{ FC_CAP_SETTABLE,	"Capability settable"			},
	{ FC_UNBOUND,		"Port not bound"			},
	{ FC_NOMEM,		"No memory"				},
	{ FC_BADPACKET,		"Bad packet"				},
	{ FC_OFFLINE,		"Port offline"				},
	{ FC_OLDPORT,		"Old Port"				},
	{ FC_NO_MAP,		"No map available"			},
	{ FC_TRANSPORT_ERROR,	"Transport error"			},
	{ FC_ELS_FREJECT,	"ELS Frejected"				},
	{ FC_ELS_PREJECT,	"ELS PRejected"				},
	{ FC_ELS_BAD,		"Bad ELS request"			},
	{ FC_ELS_MALFORMED,	"Malformed ELS request"			},
	{ FC_TOOMANY,		"Too many commands"			},
	{ FC_UB_BADTOKEN,	"Bad Unsolicited buffer token"		},
	{ FC_UB_ERROR,		"Unsolicited buffer error"		},
	{ FC_UB_BUSY,		"Unsolicited buffer busy"		},
	{ FC_BADULP,		"Bad ULP"				},
	{ FC_BADTYPE,		"Bad Type"				},
	{ FC_UNCLAIMED,		"Not Claimed"				},
	{ FC_ULP_SAMEMODULE,	"Same ULP Module"			},
	{ FC_ULP_SAMETYPE,	"Same ULP Type"				},
	{ FC_ABORTED,		"Command Aborted"			},
	{ FC_ABORT_FAILED,	"Abort Failed"				},
	{ FC_BADEXCHANGE,	"Bad Exchange"				},
	{ FC_BADWWN,		"Bad World Wide Name"			},
	{ FC_BADDEV,		"Bad Device"				},
	{ FC_BADCMD,		"Bad Command"				},
	{ FC_BADOBJECT,		"Bad Object"				},
	{ FC_BADPORT,		"Bad Port"				},
	{ FC_NOTTHISPORT,	"Not on this Port"			},
	{ FC_PREJECT,		"Operation Prejected"			},
	{ FC_FREJECT,		"Operation Frejected"			},
	{ FC_PBUSY,		"Operation Pbusyed"			},
	{ FC_FBUSY,		"Operation Fbusyed"			},
	{ FC_ALREADY,		"Already done"				},
	{ FC_LOGINREQ,		"PLOGI Required"			},
	{ FC_RESETFAIL,		"Reset operation failed"		},
	{ FC_INVALID_REQUEST,	"Invalid Request"			},
	{ FC_OUTOFBOUNDS,	"Out of Bounds"				},
	{ FC_TRAN_BUSY,		"Command transport Busy"		},
	{ FC_STATEC_BUSY,	"State change Busy"			},
	{ FC_DEVICE_BUSY,	"Port driver is working on this device"	}
};

fc_pkt_reason_t remote_stop_reasons [] = {
	{ FC_REASON_ABTS,	"Abort Sequence"	},
	{ FC_REASON_ABTX,	"Abort Exchange"	},
	{ FC_REASON_INVALID,	NULL			}
};

fc_pkt_reason_t general_reasons [] = {
	{ FC_REASON_HW_ERROR,		"Hardware Error"		},
	{ FC_REASON_SEQ_TIMEOUT,	"Sequence Timeout"		},
	{ FC_REASON_ABORTED,		"Aborted"			},
	{ FC_REASON_ABORT_FAILED,	"Abort Failed"			},
	{ FC_REASON_NO_CONNECTION,	"No Connection"			},
	{ FC_REASON_XCHG_DROPPED,	"Exchange Dropped"		},
	{ FC_REASON_ILLEGAL_FRAME,	"Illegal Frame"			},
	{ FC_REASON_ILLEGAL_LENGTH,	"Illegal Length"		},
	{ FC_REASON_UNSUPPORTED,	"Unsuported"			},
	{ FC_REASON_RX_BUF_TIMEOUT,	"Receive Buffer Timeout"	},
	{ FC_REASON_FCAL_OPN_FAIL,	"FC AL Open Failed"		},
	{ FC_REASON_OVERRUN,		"Over run"			},
	{ FC_REASON_QFULL,		"Queue Full"			},
	{ FC_REASON_ILLEGAL_REQ,	"Illegal Request",		},
	{ FC_REASON_PKT_BUSY,		"Busy"				},
	{ FC_REASON_OFFLINE,		"Offline"			},
	{ FC_REASON_BAD_XID,		"Bad Exchange Id"		},
	{ FC_REASON_XCHG_BSY,		"Exchange Busy"			},
	{ FC_REASON_NOMEM,		"No Memory"			},
	{ FC_REASON_BAD_SID,		"Bad S_ID"			},
	{ FC_REASON_NO_SEQ_INIT,	"No Sequence Initiative"	},
	{ FC_REASON_DIAG_BUSY,		"Diagnostic Busy"		},
	{ FC_REASON_DMA_ERROR,		"DMA Error"			},
	{ FC_REASON_CRC_ERROR,		"CRC Error"			},
	{ FC_REASON_ABORT_TIMEOUT,	"Abort Timeout"			},
	{ FC_REASON_FCA_UNIQUE,		"FCA Unique"			},
	{ FC_REASON_INVALID,		NULL				}
};

fc_pkt_reason_t rjt_reasons [] = {
	{ FC_REASON_INVALID_D_ID,	"Invalid D_ID"			},
	{ FC_REASON_INVALID_S_ID,	"Invalid S_ID"			},
	{ FC_REASON_TEMP_UNAVAILABLE,	"Temporarily Unavailable"	},
	{ FC_REASON_PERM_UNAVAILABLE,	"Permamnently Unavailable"	},
	{ FC_REASON_CLASS_NOT_SUPP,	"Class Not Supported",		},
	{ FC_REASON_DELIMTER_USAGE_ERROR,
	    "Delimeter Usage Error"		},
	{ FC_REASON_TYPE_NOT_SUPP,	"Type Not Supported"		},
	{ FC_REASON_INVALID_LINK_CTRL,	"Invalid Link Control"		},
	{ FC_REASON_INVALID_R_CTL,	"Invalid R_CTL"			},
	{ FC_REASON_INVALID_F_CTL,	"Invalid F_CTL"			},
	{ FC_REASON_INVALID_OX_ID,	"Invalid OX_ID"			},
	{ FC_REASON_INVALID_RX_ID,	"Invalid RX_ID"			},
	{ FC_REASON_INVALID_SEQ_ID,	"Invalid Sequence ID"		},
	{ FC_REASON_INVALID_DF_CTL,	"Invalid DF_CTL"		},
	{ FC_REASON_INVALID_SEQ_CNT,	"Invalid Sequence count"	},
	{ FC_REASON_INVALID_PARAM,	"Invalid Parameter"		},
	{ FC_REASON_EXCH_ERROR,		"Exchange Error"		},
	{ FC_REASON_PROTOCOL_ERROR,	"Protocol Error"		},
	{ FC_REASON_INCORRECT_LENGTH,	"Incorrect Length"		},
	{ FC_REASON_UNEXPECTED_ACK,	"Unexpected Ack"		},
	{ FC_REASON_UNEXPECTED_LR,	"Unexpected Link reset"		},
	{ FC_REASON_LOGIN_REQUIRED,	"Login Required"		},
	{ FC_REASON_EXCESSIVE_SEQS,	"Excessive Sequences"
	    " Attempted"			},
	{ FC_REASON_EXCH_UNABLE,	"Exchange incapable"		},
	{ FC_REASON_ESH_NOT_SUPP,	"Expiration Security Header "
	    "Not Supported"			},
	{ FC_REASON_NO_FABRIC_PATH,	"No Fabric Path"		},
	{ FC_REASON_VENDOR_UNIQUE,	"Vendor Unique"			},
	{ FC_REASON_INVALID,		NULL				}
};

fc_pkt_reason_t n_port_busy_reasons [] = {
	{ FC_REASON_PHYSICAL_BUSY,		"Physical Busy"		},
	{ FC_REASON_N_PORT_RESOURCE_BSY,	"Resource Busy"		},
	{ FC_REASON_N_PORT_VENDOR_UNIQUE,	"Vendor Unique"		},
	{ FC_REASON_INVALID,			NULL			}
};

fc_pkt_reason_t f_busy_reasons [] = {
	{ FC_REASON_FABRIC_BSY,		"Fabric Busy"			},
	{ FC_REASON_N_PORT_BSY,		"N_Port Busy"			},
	{ FC_REASON_INVALID,		NULL				}
};

fc_pkt_reason_t ls_ba_rjt_reasons [] = {
	{ FC_REASON_INVALID_LA_CODE,	"Invalid Link Application Code"	},
	{ FC_REASON_LOGICAL_ERROR,	"Logical Error"			},
	{ FC_REASON_LOGICAL_BSY,	"Logical Busy"			},
	{ FC_REASON_PROTOCOL_ERROR_RJT,	"Protocol Error Reject"		},
	{ FC_REASON_CMD_UNABLE,		"Unable to Perform Command"	},
	{ FC_REASON_CMD_UNSUPPORTED,	"Unsupported Command"		},
	{ FC_REASON_VU_RJT,		"Vendor Unique"			},
	{ FC_REASON_INVALID,		NULL				}
};

fc_pkt_reason_t fs_rjt_reasons [] = {
	{ FC_REASON_FS_INVALID_CMD,	"Invalid Command"		},
	{ FC_REASON_FS_INVALID_VER,	"Invalid Version"		},
	{ FC_REASON_FS_LOGICAL_ERR,	"Logical Error"			},
	{ FC_REASON_FS_INVALID_IUSIZE,	"Invalid IU Size"		},
	{ FC_REASON_FS_LOGICAL_BUSY,	"Logical Busy"			},
	{ FC_REASON_FS_PROTOCOL_ERR,	"Protocol Error"		},
	{ FC_REASON_FS_CMD_UNABLE,	"Unable to Perform Command"	},
	{ FC_REASON_FS_CMD_UNSUPPORTED,	"Unsupported Command"		},
	{ FC_REASON_FS_VENDOR_UNIQUE,	"Vendor Unique"			},
	{ FC_REASON_INVALID,		NULL				}
};

fc_pkt_action_t	n_port_busy_actions [] = {
	{ FC_ACTION_SEQ_TERM_RETRY,	"Retry terminated Sequence"	},
	{ FC_ACTION_SEQ_ACTIVE_RETRY,	"Retry Active Sequence"		},
	{ FC_REASON_INVALID,		NULL				}
};

fc_pkt_action_t rjt_timeout_actions [] = {
	{ FC_ACTION_RETRYABLE,		"Retryable"			},
	{ FC_ACTION_NON_RETRYABLE,	"Non Retryable"			},
	{ FC_REASON_INVALID,		NULL				}
};

fc_pkt_expln_t ba_rjt_explns [] = {
	{ FC_EXPLN_NONE,		"No Explanation"		},
	{ FC_EXPLN_INVALID_OX_RX_ID,	"Invalid X_ID"			},
	{ FC_EXPLN_SEQ_ABORTED,		"Sequence Aborted"		},
	{ FC_EXPLN_INVALID,		NULL				}
};

fc_pkt_error_t fc_pkt_errlist[] = {
	{
		FC_PKT_SUCCESS,
		"Operation Success",
		NULL,
		NULL,
		NULL
	},
	{	FC_PKT_REMOTE_STOP,
	    "Remote Stop",
	    remote_stop_reasons,
	    NULL,
	    NULL
	},
	{
		FC_PKT_LOCAL_RJT,
		"Local Reject",
		general_reasons,
		rjt_timeout_actions,
		NULL
	},
	{
		FC_PKT_NPORT_RJT,
		"N_Port Reject",
		rjt_reasons,
		rjt_timeout_actions,
		NULL
	},
	{
		FC_PKT_FABRIC_RJT,
		"Fabric Reject",
		rjt_reasons,
		rjt_timeout_actions,
		NULL
	},
	{
		FC_PKT_LOCAL_BSY,
		"Local Busy",
		general_reasons,
		NULL,
		NULL,
	},
	{
		FC_PKT_TRAN_BSY,
		"Transport Busy",
		general_reasons,
		NULL,
		NULL,
	},
	{
		FC_PKT_NPORT_BSY,
		"N_Port Busy",
		n_port_busy_reasons,
		n_port_busy_actions,
		NULL
	},
	{
		FC_PKT_FABRIC_BSY,
		"Fabric Busy",
		f_busy_reasons,
		NULL,
		NULL,
	},
	{
		FC_PKT_LS_RJT,
		"Link Service Reject",
		ls_ba_rjt_reasons,
		NULL,
		NULL,
	},
	{
		FC_PKT_BA_RJT,
		"Basic Reject",
		ls_ba_rjt_reasons,
		NULL,
		ba_rjt_explns,
	},
	{
		FC_PKT_TIMEOUT,
		"Timeout",
		general_reasons,
		rjt_timeout_actions,
		NULL
	},
	{
		FC_PKT_FS_RJT,
		"Fabric Switch Reject",
		fs_rjt_reasons,
		NULL,
		NULL
	},
	{
		FC_PKT_TRAN_ERROR,
		"Packet Transport error",
		general_reasons,
		NULL,
		NULL
	},
	{
		FC_PKT_FAILURE,
		"Packet Failure",
		general_reasons,
		NULL,
		NULL
	},
	{
		FC_PKT_PORT_OFFLINE,
		"Port Offline",
		NULL,
		NULL,
		NULL
	},
	{
		FC_PKT_ELS_IN_PROGRESS,
		"ELS is in Progress",
		NULL,
		NULL,
		NULL
	}
};

int
_init()
{
	int rval;

	rw_init(&fctl_ulp_lock, NULL, RW_DRIVER, NULL);
	rw_init(&fctl_mod_ports_lock, NULL, RW_DRIVER, NULL);
	mutex_init(&fctl_port_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&fctl_nwwn_hash_mutex, NULL, MUTEX_DRIVER, NULL);

	fctl_nwwn_hash_table = kmem_zalloc(sizeof (*fctl_nwwn_hash_table) *
	    fctl_nwwn_table_size, KM_SLEEP);

	fctl_ulp_modules = NULL;
	fctl_fca_portlist = NULL;

	fctl_job_cache = kmem_cache_create("fctl_cache",
	    sizeof (job_request_t), 8, fctl_cache_constructor,
	    fctl_cache_destructor, NULL, NULL, NULL, 0);

	if (fctl_job_cache == NULL) {
		kmem_free(fctl_nwwn_hash_table,
		    sizeof (*fctl_nwwn_hash_table) * fctl_nwwn_table_size);
		mutex_destroy(&fctl_nwwn_hash_mutex);
		mutex_destroy(&fctl_port_lock);
		rw_destroy(&fctl_ulp_lock);
		rw_destroy(&fctl_mod_ports_lock);
		return (ENOMEM);
	}

	if ((rval = mod_install(&modlinkage)) != 0) {
		kmem_cache_destroy(fctl_job_cache);
		kmem_free(fctl_nwwn_hash_table,
		    sizeof (*fctl_nwwn_hash_table) * fctl_nwwn_table_size);
		mutex_destroy(&fctl_nwwn_hash_mutex);
		mutex_destroy(&fctl_port_lock);
		rw_destroy(&fctl_ulp_lock);
		rw_destroy(&fctl_mod_ports_lock);
	}

	return (rval);
}


/*
 * The mod_uninstall code doesn't call _fini when
 * there is living dependent module on fctl. So
 * there is no need to be extra careful here ?
 */
int
_fini()
{
	int rval;

	if ((rval = mod_remove(&modlinkage)) != 0) {
		return (rval);
	}

	kmem_cache_destroy(fctl_job_cache);
	kmem_free(fctl_nwwn_hash_table,
	    sizeof (*fctl_nwwn_hash_table) * fctl_nwwn_table_size);
	mutex_destroy(&fctl_nwwn_hash_mutex);
	mutex_destroy(&fctl_port_lock);
	rw_destroy(&fctl_ulp_lock);
	rw_destroy(&fctl_mod_ports_lock);

	return (rval);
}


int
_info(struct modinfo *modinfo_p)
{
	return (mod_info(&modlinkage, modinfo_p));
}


/* ARGSUSED */
static int
fctl_cache_constructor(void *buf, void *cdarg, int kmflag)
{
	job_request_t *job = (job_request_t *)buf;

	mutex_init(&job->job_mutex, NULL, MUTEX_DRIVER, NULL);
	sema_init(&job->job_fctl_sema, 0, NULL, SEMA_DEFAULT, NULL);
	sema_init(&job->job_port_sema, 0, NULL, SEMA_DEFAULT, NULL);

	return (0);
}


/* ARGSUSED */
static void
fctl_cache_destructor(void *buf, void *cdarg)
{
	job_request_t *job = (job_request_t *)buf;

	sema_destroy(&job->job_fctl_sema);
	sema_destroy(&job->job_port_sema);
	mutex_destroy(&job->job_mutex);
}


/*
 * fc_ulp_add:
 *		Add a ULP module
 *
 * Return Codes:
 *		FC_ULP_SAMEMODULE
 *		FC_SUCCESS
 *		FC_FAILURE
 *
 *   fc_ulp_add	 prints	 a warning message if there is	already a
 *   similar ULP type  attached and this is unlikely to change as
 *   we trudge along.  Further, this  function	returns a failure
 *   code if the same  module  attempts to add more than once for
 *   the same FC-4 type.
 */
int
fc_ulp_add(fc_ulp_modinfo_t *ulp_info)
{
	fc_ulp_module_t *mod;
	fc_ulp_module_t *prev;
	job_request_t	*job;
	fc_ulp_list_t	*new;
	fc_fca_port_t	*fca_port;
	int		ntry = 0;

	ASSERT(ulp_info != NULL);

	/*
	 * Make sure ulp_rev matches fctl version.
	 * Whenever non-private data structure or non-static interface changes,
	 * we should use an increased FCTL_ULP_MODREV_# number here and in all
	 * ulps to prevent version mismatch.
	 */
	if (ulp_info->ulp_rev != FCTL_ULP_MODREV_4) {
		cmn_err(CE_WARN, "fctl: ULP %s version mismatch;"
		    " ULP %s would not be loaded", ulp_info->ulp_name,
		    ulp_info->ulp_name);
		return (FC_BADULP);
	}

	new = kmem_zalloc(sizeof (*new), KM_SLEEP);
	ASSERT(new != NULL);

	mutex_enter(&fctl_ulp_list_mutex);
	new->ulp_info = ulp_info;
	if (fctl_ulp_list != NULL) {
		new->ulp_next = fctl_ulp_list;
	}
	fctl_ulp_list = new;
	mutex_exit(&fctl_ulp_list_mutex);

	while (rw_tryenter(&fctl_ulp_lock, RW_WRITER) == 0) {
		delay(drv_usectohz(1000000));
		if (ntry++ > FC_ULP_ADD_RETRY_COUNT) {
			fc_ulp_list_t	*list;
			fc_ulp_list_t	*last;
			mutex_enter(&fctl_ulp_list_mutex);
			for (last = NULL, list = fctl_ulp_list; list != NULL;
			    list = list->ulp_next) {
				if (list->ulp_info == ulp_info) {
					break;
				}
				last = list;
			}

			if (list) {
				if (last) {
					last->ulp_next = list->ulp_next;
				} else {
					fctl_ulp_list = list->ulp_next;
				}
				kmem_free(list, sizeof (*list));
			}
			mutex_exit(&fctl_ulp_list_mutex);
			cmn_err(CE_WARN, "fctl: ULP %s unable to load",
			    ulp_info->ulp_name);
			return (FC_FAILURE);
		}
	}

	for (mod = fctl_ulp_modules, prev = NULL; mod; mod = mod->mod_next) {
		ASSERT(mod->mod_info != NULL);

		if (ulp_info == mod->mod_info &&
		    ulp_info->ulp_type == mod->mod_info->ulp_type) {
			rw_exit(&fctl_ulp_lock);
			return (FC_ULP_SAMEMODULE);
		}

		if (ulp_info->ulp_type == mod->mod_info->ulp_type) {
			cmn_err(CE_NOTE, fctl_greeting, ulp_info->ulp_name,
			    ulp_info->ulp_type);
		}
		prev = mod;
	}

	mod = kmem_zalloc(sizeof (*mod), KM_SLEEP);
	mod->mod_info = ulp_info;
	mod->mod_next = NULL;

	if (prev) {
		prev->mod_next = mod;
	} else {
		fctl_ulp_modules = mod;
	}

	/*
	 * Schedule a job to each port's job_handler
	 * thread to attach their ports with this ULP.
	 */
	mutex_enter(&fctl_port_lock);
	for (fca_port = fctl_fca_portlist; fca_port != NULL;
	    fca_port = fca_port->port_next) {
		job = fctl_alloc_job(JOB_ATTACH_ULP, JOB_TYPE_FCTL_ASYNC,
		    NULL, NULL, KM_SLEEP);

		fctl_enque_job(fca_port->port_handle, job);
	}
	mutex_exit(&fctl_port_lock);

	rw_exit(&fctl_ulp_lock);

	return (FC_SUCCESS);
}


/*
 * fc_ulp_remove
 *	Remove a ULP module
 *
 * A misbehaving ULP may call this routine while I/Os are in progress.
 * Currently there is no mechanism to detect it to fail such a request.
 *
 * Return Codes:
 *		FC_SUCCESS
 *		FC_FAILURE
 */
int
fc_ulp_remove(fc_ulp_modinfo_t *ulp_info)
{
	fc_ulp_module_t *mod;
	fc_ulp_list_t	*list;
	fc_ulp_list_t	*last;
	fc_ulp_module_t *prev;

	mutex_enter(&fctl_ulp_list_mutex);

	for (last = NULL, list = fctl_ulp_list; list != NULL;
	    list = list->ulp_next) {
		if (list->ulp_info == ulp_info) {
			break;
		}
		last = list;
	}

	if (list) {
		if (last) {
			last->ulp_next = list->ulp_next;
		} else {
			fctl_ulp_list = list->ulp_next;
		}
		kmem_free(list, sizeof (*list));
	}

	mutex_exit(&fctl_ulp_list_mutex);

	rw_enter(&fctl_ulp_lock, RW_WRITER);

	for (mod = fctl_ulp_modules, prev = NULL; mod != NULL;
	    mod = mod->mod_next) {
		if (mod->mod_info == ulp_info) {
			break;
		}
		prev = mod;
	}

	if (mod) {
		fc_ulp_ports_t *next;

		if (prev) {
			prev->mod_next = mod->mod_next;
		} else {
			fctl_ulp_modules = mod->mod_next;
		}

		rw_enter(&fctl_mod_ports_lock, RW_WRITER);

		while ((next = mod->mod_ports) != NULL) {
			mod->mod_ports = next->port_next;
			fctl_dealloc_ulp_port(next);
		}

		rw_exit(&fctl_mod_ports_lock);
		rw_exit(&fctl_ulp_lock);

		kmem_free(mod, sizeof (*mod));

		return (FC_SUCCESS);
	}
	rw_exit(&fctl_ulp_lock);

	return (FC_FAILURE);
}


/*
 * The callers typically cache allocate the packet, complete the
 * DMA setup for pkt_cmd and pkt_resp fields of the packet and
 * call this function to see if the FCA is interested in doing
 * its own intialization. For example, socal may like to initialize
 * the soc_hdr which is pointed to by the pkt_fca_private field
 * and sitting right below fc_packet_t in memory.
 *
 * The caller is required to ensure that pkt_pd is populated with the
 * handle that it was given when the transport notified it about the
 * device this packet is associated with.  If there is no associated
 * device, pkt_pd must be set to NULL.	A non-NULL pkt_pd will cause an
 * increment of the reference count for said pd.  When the packet is freed,
 * the reference count will be decremented.  This reference count, in
 * combination with the PD_GIVEN_TO_ULPS flag guarantees that the pd
 * will not wink out of existence while there is a packet outstanding.
 *
 * This function and fca_init_pkt must not perform any operations that
 * would result in a call back to the ULP, as the ULP may be required
 * to hold a mutex across this call to ensure that the pd in question
 * won't go away prior the call to fc_ulp_transport.
 *
 * ULPs are responsible for using the handles they are given during state
 * change callback processing in a manner that ensures consistency.  That
 * is, they must be aware that they could be processing a state change
 * notification that tells them the device associated with a particular
 * handle has gone away at the same time they are being asked to
 * initialize a packet using that handle. ULPs must therefore ensure
 * that their state change processing and packet initialization code
 * paths are sufficiently synchronized to avoid the use of an
 * invalidated handle in any fc_packet_t struct that is passed to the
 * fc_ulp_init_packet() function.
 */
int
fc_ulp_init_packet(opaque_t port_handle, fc_packet_t *pkt, int sleep)
{
	int rval;
	fc_local_port_t *port = port_handle;
	fc_remote_port_t *pd;

	ASSERT(pkt != NULL);

	pd = pkt->pkt_pd;

	/* Call the FCA driver's fca_init_pkt entry point function. */
	rval = port->fp_fca_tran->fca_init_pkt(port->fp_fca_handle, pkt, sleep);

	if ((rval == FC_SUCCESS) && (pd != NULL)) {
		/*
		 * A !NULL pd here must still be a valid
		 * reference to the fc_remote_port_t.
		 */
		mutex_enter(&pd->pd_mutex);
		ASSERT(pd->pd_ref_count >= 0);
		pd->pd_ref_count++;
		mutex_exit(&pd->pd_mutex);
	}

	return (rval);
}


/*
 * This function is called before destroying the cache allocated
 * fc_packet to free up (and uninitialize) any resource specially
 * allocated by the FCA driver during tran_init_pkt().
 *
 * If the pkt_pd field in the given fc_packet_t struct is not NULL, then
 * the pd_ref_count reference count is decremented for the indicated
 * fc_remote_port_t struct.
 */
int
fc_ulp_uninit_packet(opaque_t port_handle, fc_packet_t *pkt)
{
	int rval;
	fc_local_port_t *port = port_handle;
	fc_remote_port_t *pd;

	ASSERT(pkt != NULL);

	pd = pkt->pkt_pd;

	/* Call the FCA driver's fca_un_init_pkt entry point function */
	rval = port->fp_fca_tran->fca_un_init_pkt(port->fp_fca_handle, pkt);

	if ((rval == FC_SUCCESS) && (pd != NULL)) {
		mutex_enter(&pd->pd_mutex);

		ASSERT(pd->pd_ref_count > 0);
		pd->pd_ref_count--;

		/*
		 * If at this point the state of this fc_remote_port_t
		 * struct is PORT_DEVICE_INVALID, it probably means somebody
		 * is cleaning up old (e.g. retried) packets. If the
		 * pd_ref_count has also dropped to zero, it's time to
		 * deallocate this fc_remote_port_t struct.
		 */
		if (pd->pd_state == PORT_DEVICE_INVALID &&
		    pd->pd_ref_count == 0) {
			fc_remote_node_t *node = pd->pd_remote_nodep;

			mutex_exit(&pd->pd_mutex);

			/*
			 * Also deallocate the associated fc_remote_node_t
			 * struct if it has no other associated
			 * fc_remote_port_t structs.
			 */
			if ((fctl_destroy_remote_port(port, pd) == 0) &&
			    (node != NULL)) {
				fctl_destroy_remote_node(node);
			}
			return (rval);
		}

		mutex_exit(&pd->pd_mutex);
	}

	return (rval);
}


int
fc_ulp_getportmap(opaque_t port_handle, fc_portmap_t **map, uint32_t *len,
    int flag)
{
	int		job_code;
	fc_local_port_t *port;
	job_request_t	*job;
	fc_portmap_t	*tmp_map;
	uint32_t	tmp_len;
	fc_portmap_t	*change_list = NULL;
	uint32_t	listlen = 0;

	port = port_handle;

	mutex_enter(&port->fp_mutex);
	if (port->fp_statec_busy) {
		mutex_exit(&port->fp_mutex);
		return (FC_STATEC_BUSY);
	}

	if (FC_PORT_STATE_MASK(port->fp_state) == FC_STATE_OFFLINE) {
		mutex_exit(&port->fp_mutex);
		return (FC_OFFLINE);
	}

	if (port->fp_dev_count && (port->fp_dev_count ==
	    port->fp_total_devices)) {
		mutex_exit(&port->fp_mutex);
		fctl_fillout_map(port, &change_list, &listlen, 1, 1, 0);
		if (listlen > *len) {
			tmp_map = (fc_portmap_t *)kmem_zalloc(
			    listlen * sizeof (fc_portmap_t), KM_NOSLEEP);
			if (tmp_map == NULL) {
				return (FC_NOMEM);
			}
			if (*map) {
				kmem_free(*map, (*len) * sizeof (fc_portmap_t));
			}
			*map = tmp_map;
		}
		if (change_list) {
			bcopy(change_list, *map,
			    listlen * sizeof (fc_portmap_t));
			kmem_free(change_list, listlen * sizeof (fc_portmap_t));
		}
		*len = listlen;
	} else {
		mutex_exit(&port->fp_mutex);

		switch (flag) {
		case FC_ULP_PLOGI_DONTCARE:
			job_code = JOB_PORT_GETMAP;
			break;

		case FC_ULP_PLOGI_PRESERVE:
			job_code = JOB_PORT_GETMAP_PLOGI_ALL;
			break;

		default:
			return (FC_INVALID_REQUEST);
		}
		/*
		 * Submit a job request to the job handler
		 * thread to get the map and wait
		 */
		job = fctl_alloc_job(job_code, 0, NULL, NULL, KM_SLEEP);
		job->job_private = (opaque_t)map;
		job->job_arg = (opaque_t)len;
		fctl_enque_job(port, job);

		fctl_jobwait(job);
		/*
		 * The result of the last I/O operation is
		 * in job_code. We don't care to look at it
		 * Rather we look at the number of devices
		 * that are found to fill out the map for
		 * ULPs.
		 */
		fctl_dealloc_job(job);
	}

	/*
	 * If we're here, we're returning a map to the caller, which means
	 * we'd better make sure every pd in that map has the
	 * PD_GIVEN_TO_ULPS flag set.
	 */

	tmp_len = *len;
	tmp_map = *map;

	while (tmp_len-- != 0) {
		if (tmp_map->map_state != PORT_DEVICE_INVALID) {
			fc_remote_port_t *pd =
			    (fc_remote_port_t *)tmp_map->map_pd;
			mutex_enter(&pd->pd_mutex);
			pd->pd_aux_flags |= PD_GIVEN_TO_ULPS;
			mutex_exit(&pd->pd_mutex);
		}
		tmp_map++;
	}

	return (FC_SUCCESS);
}


int
fc_ulp_login(opaque_t port_handle, fc_packet_t **ulp_pkt, uint32_t listlen)
{
	int			rval = FC_SUCCESS;
	int			job_flags;
	uint32_t		count;
	fc_packet_t		**tmp_array;
	job_request_t		*job;
	fc_local_port_t		*port = port_handle;
	fc_ulp_rscn_info_t	*rscnp =
	    (fc_ulp_rscn_info_t *)(ulp_pkt[0])->pkt_ulp_rscn_infop;

	/*
	 * If the port is OFFLINE, or if the port driver is
	 * being SUSPENDED/PM_SUSPENDED/DETACHED, block all
	 * PLOGI operations
	 */
	mutex_enter(&port->fp_mutex);
	if (port->fp_statec_busy) {
		mutex_exit(&port->fp_mutex);
		return (FC_STATEC_BUSY);
	}

	if ((FC_PORT_STATE_MASK(port->fp_state) == FC_STATE_OFFLINE) ||
	    (port->fp_soft_state &
	    (FP_SOFT_IN_DETACH | FP_SOFT_SUSPEND | FP_SOFT_POWER_DOWN))) {
		mutex_exit(&port->fp_mutex);
		return (FC_OFFLINE);
	}

	/*
	 * If the rscn count in the packet is not the same as the rscn count
	 * in the fc_local_port_t, then one or more new RSCNs has occurred.
	 */
	if ((rscnp != NULL) &&
	    (rscnp->ulp_rscn_count != FC_INVALID_RSCN_COUNT) &&
	    (rscnp->ulp_rscn_count != port->fp_rscn_count)) {
		mutex_exit(&port->fp_mutex);
		return (FC_DEVICE_BUSY_NEW_RSCN);
	}

	mutex_exit(&port->fp_mutex);

	tmp_array = kmem_zalloc(sizeof (*tmp_array) * listlen, KM_SLEEP);
	for (count = 0; count < listlen; count++) {
		tmp_array[count] = ulp_pkt[count];
	}

	job_flags = ((ulp_pkt[0]->pkt_tran_flags) & FC_TRAN_NO_INTR)
	    ? 0 : JOB_TYPE_FCTL_ASYNC;

#ifdef	DEBUG
	{
		int next;
		int count;
		int polled;

		polled = ((ulp_pkt[0]->pkt_tran_flags) &
		    FC_TRAN_NO_INTR) ? 0 : JOB_TYPE_FCTL_ASYNC;

		for (count = 0; count < listlen; count++) {
			next = ((ulp_pkt[count]->pkt_tran_flags)
			    & FC_TRAN_NO_INTR) ? 0 : JOB_TYPE_FCTL_ASYNC;
			ASSERT(next == polled);
		}
	}
#endif

	job = fctl_alloc_job(JOB_PLOGI_GROUP, job_flags, NULL, NULL, KM_SLEEP);
	job->job_ulp_pkts = tmp_array;
	job->job_ulp_listlen = listlen;

	while (listlen--) {
		fc_packet_t *pkt;

		pkt = tmp_array[listlen];
		if (pkt->pkt_pd == NULL) {
			pkt->pkt_state = FC_PKT_SUCCESS;
			continue;
		}

		mutex_enter(&pkt->pkt_pd->pd_mutex);
		if (pkt->pkt_pd->pd_flags == PD_ELS_IN_PROGRESS ||
		    pkt->pkt_pd->pd_flags == PD_ELS_MARK) {
			/*
			 * Set the packet state and let the port
			 * driver call the completion routine
			 * from its thread
			 */
			mutex_exit(&pkt->pkt_pd->pd_mutex);
			pkt->pkt_state = FC_PKT_ELS_IN_PROGRESS;
			continue;
		}

		if (pkt->pkt_pd->pd_state == PORT_DEVICE_INVALID ||
		    pkt->pkt_pd->pd_type == PORT_DEVICE_OLD) {
			mutex_exit(&pkt->pkt_pd->pd_mutex);
			pkt->pkt_state = FC_PKT_LOCAL_RJT;
			continue;
		}
		mutex_exit(&pkt->pkt_pd->pd_mutex);
		pkt->pkt_state = FC_PKT_SUCCESS;
	}

	fctl_enque_job(port, job);

	if (!(job_flags & JOB_TYPE_FCTL_ASYNC)) {
		fctl_jobwait(job);
		rval = job->job_result;
		fctl_dealloc_job(job);
	}

	return (rval);
}


opaque_t
fc_ulp_get_remote_port(opaque_t port_handle, la_wwn_t *pwwn, int *error,
    int create)
{
	fc_local_port_t		*port;
	job_request_t		*job;
	fc_remote_port_t	*pd;

	port = port_handle;
	pd = fctl_get_remote_port_by_pwwn(port, pwwn);

	if (pd != NULL) {
		*error = FC_SUCCESS;
		/*
		 * A ULP now knows about this pd, so mark it
		 */
		mutex_enter(&pd->pd_mutex);
		pd->pd_aux_flags |= PD_GIVEN_TO_ULPS;
		mutex_exit(&pd->pd_mutex);
		return (pd);
	}

	mutex_enter(&port->fp_mutex);
	if (FC_IS_TOP_SWITCH(port->fp_topology) && create) {
		uint32_t	d_id;
		fctl_ns_req_t	*ns_cmd;

		mutex_exit(&port->fp_mutex);

		job = fctl_alloc_job(JOB_NS_CMD, 0, NULL, NULL, KM_SLEEP);

		if (job == NULL) {
			*error = FC_NOMEM;
			return (pd);
		}

		ns_cmd = fctl_alloc_ns_cmd(sizeof (ns_req_gid_pn_t),
		    sizeof (ns_resp_gid_pn_t), sizeof (ns_resp_gid_pn_t),
		    0, KM_SLEEP);

		if (ns_cmd == NULL) {
			fctl_dealloc_job(job);
			*error = FC_NOMEM;
			return (pd);
		}
		ns_cmd->ns_cmd_code = NS_GID_PN;
		((ns_req_gid_pn_t *)(ns_cmd->ns_cmd_buf))->pwwn = *pwwn;

		job->job_result = FC_SUCCESS;
		job->job_private = (void *)ns_cmd;
		job->job_counter = 1;
		fctl_enque_job(port, job);
		fctl_jobwait(job);

		if (job->job_result != FC_SUCCESS) {
			*error = job->job_result;
			fctl_free_ns_cmd(ns_cmd);
			fctl_dealloc_job(job);
			return (pd);
		}
		d_id = ((ns_resp_gid_pn_t *)ns_cmd->ns_data_buf)->pid.port_id;
		fctl_free_ns_cmd(ns_cmd);

		ns_cmd = fctl_alloc_ns_cmd(sizeof (ns_req_gan_t),
		    sizeof (ns_resp_gan_t), 0, FCTL_NS_CREATE_DEVICE,
		    KM_SLEEP);
		ASSERT(ns_cmd != NULL);

		ns_cmd->ns_gan_max = 1;
		ns_cmd->ns_cmd_code = NS_GA_NXT;
		ns_cmd->ns_gan_sid = FCTL_GAN_START_ID;
		((ns_req_gan_t *)(ns_cmd->ns_cmd_buf))->pid.port_id = d_id - 1;
		((ns_req_gan_t *)(ns_cmd->ns_cmd_buf))->pid.priv_lilp_posit = 0;

		job->job_result = FC_SUCCESS;
		job->job_private = (void *)ns_cmd;
		job->job_counter = 1;
		fctl_enque_job(port, job);
		fctl_jobwait(job);

		fctl_free_ns_cmd(ns_cmd);
		if (job->job_result != FC_SUCCESS) {
			*error = job->job_result;
			fctl_dealloc_job(job);
			return (pd);
		}
		fctl_dealloc_job(job);

		/*
		 * Check if the port device is created now.
		 */
		pd = fctl_get_remote_port_by_pwwn(port, pwwn);

		if (pd == NULL) {
			*error = FC_FAILURE;
		} else {
			*error = FC_SUCCESS;

			/*
			 * A ULP now knows about this pd, so mark it
			 */
			mutex_enter(&pd->pd_mutex);
			pd->pd_aux_flags |= PD_GIVEN_TO_ULPS;
			mutex_exit(&pd->pd_mutex);
		}
	} else {
		mutex_exit(&port->fp_mutex);
		*error = FC_FAILURE;
	}

	return (pd);
}


/*
 * If a NS object exists in the host and query is performed
 * on that object, we should retrieve it from our basket
 * and return it right here, there by saving a request going
 * all the up to the Name Server.
 */
int
fc_ulp_port_ns(opaque_t port_handle, opaque_t pd, fc_ns_cmd_t *ns_req)
{
	int		rval;
	int		fabric;
	job_request_t	*job;
	fctl_ns_req_t	*ns_cmd;
	fc_local_port_t	*port = port_handle;

	mutex_enter(&port->fp_mutex);
	fabric = FC_IS_TOP_SWITCH(port->fp_topology) ? 1 : 0;
	mutex_exit(&port->fp_mutex);

	/*
	 * Name server query can't be performed for devices not in Fabric
	 */
	if (!fabric && pd) {
		return (FC_BADOBJECT);
	}

	if (FC_IS_CMD_A_REG(ns_req->ns_cmd)) {
		if (pd == NULL) {
			rval = fctl_update_host_ns_values(port, ns_req);
			if (rval != FC_SUCCESS) {
				return (rval);
			}
		} else {
			/*
			 * Guess what, FC-GS-2 currently prohibits (not
			 * in the strongest language though) setting of
			 * NS object values by other ports. But we might
			 * get that changed to at least accommodate setting
			 * symbolic node/port names - But if disks/tapes
			 * were going to provide a method to set these
			 * values directly (which in turn might register
			 * with the NS when they come up; yep, for that
			 * to happen the disks will have to be very well
			 * behaved Fabric citizen) we won't need to
			 * register the symbolic port/node names for
			 * other ports too (rather send down SCSI commands
			 * to the devices to set the names)
			 *
			 * Be that as it may, let's continue to fail
			 * registration requests for other ports. period.
			 */
			return (FC_BADOBJECT);
		}

		if (!fabric) {
			return (FC_SUCCESS);
		}
	} else if (!fabric) {
		return (fctl_retrieve_host_ns_values(port, ns_req));
	}

	job = fctl_alloc_job(JOB_NS_CMD, 0, NULL, NULL, KM_SLEEP);
	ASSERT(job != NULL);

	ns_cmd = fctl_alloc_ns_cmd(ns_req->ns_req_len,
	    ns_req->ns_resp_len, ns_req->ns_resp_len, 0, KM_SLEEP);
	ASSERT(ns_cmd != NULL);
	ns_cmd->ns_cmd_code = ns_req->ns_cmd;
	bcopy(ns_req->ns_req_payload, ns_cmd->ns_cmd_buf,
	    ns_req->ns_req_len);

	job->job_private = (void *)ns_cmd;
	fctl_enque_job(port, job);
	fctl_jobwait(job);
	rval = job->job_result;

	if (ns_req->ns_resp_len >= ns_cmd->ns_data_len) {
		bcopy(ns_cmd->ns_data_buf, ns_req->ns_resp_payload,
		    ns_cmd->ns_data_len);
	}
	bcopy(&ns_cmd->ns_resp_hdr, &ns_req->ns_resp_hdr,
	    sizeof (fc_ct_header_t));

	fctl_free_ns_cmd(ns_cmd);
	fctl_dealloc_job(job);

	return (rval);
}


int
fc_ulp_transport(opaque_t port_handle, fc_packet_t *pkt)
{
	int			rval;
	fc_local_port_t		*port;
	fc_remote_port_t	*pd, *newpd;
	fc_ulp_rscn_info_t	*rscnp =
	    (fc_ulp_rscn_info_t *)pkt->pkt_ulp_rscn_infop;

	port = port_handle;

	if (pkt->pkt_tran_flags & FC_TRAN_DUMPING) {
		return (port->fp_fca_tran->fca_transport(
		    port->fp_fca_handle, pkt));
	}

	mutex_enter(&port->fp_mutex);
	if (port->fp_statec_busy) {
		mutex_exit(&port->fp_mutex);
		return (FC_STATEC_BUSY);
	}

	/* A locus of race conditions */
	if (((FC_PORT_STATE_MASK(port->fp_state)) == FC_STATE_OFFLINE) ||
	    (port->fp_soft_state &
	    (FP_SOFT_IN_DETACH | FP_SOFT_SUSPEND | FP_SOFT_POWER_DOWN))) {
		mutex_exit(&port->fp_mutex);
		return (FC_OFFLINE);
	}

	/*
	 * If the rscn count in the packet is not the same as the rscn count
	 * in the fc_local_port_t, then one or more new RSCNs has occurred.
	 */
	if ((rscnp != NULL) &&
	    (rscnp->ulp_rscn_count != FC_INVALID_RSCN_COUNT) &&
	    (rscnp->ulp_rscn_count != port->fp_rscn_count)) {
		mutex_exit(&port->fp_mutex);
		return (FC_DEVICE_BUSY_NEW_RSCN);
	}

	pd = pkt->pkt_pd;
	if (pd) {
		if (pd->pd_type == PORT_DEVICE_OLD ||
		    pd->pd_state == PORT_DEVICE_INVALID) {

			newpd = fctl_get_remote_port_by_pwwn_mutex_held(port,
			    &pd->pd_port_name);

			/*
			 * The remote port (pd) in the packet is no longer
			 * usable, as the old pd still exists we can use the
			 * WWN to check if we have a current pd for the device
			 * we want. Either way we continue with the old logic
			 * whether we have a new pd or not, as the new pd
			 * could be bad, or have become unusable.
			 */
			if ((newpd) && (newpd != pd)) {

				/*
				 * There is a better remote port (pd) to try,
				 * so we need to fix the reference counts, etc.
				 */
				mutex_enter(&newpd->pd_mutex);
				newpd->pd_ref_count++;
				pkt->pkt_pd = newpd;
				mutex_exit(&newpd->pd_mutex);

				mutex_enter(&pd->pd_mutex);
				pd->pd_ref_count--;
				if ((pd->pd_state == PORT_DEVICE_INVALID) &&
				    (pd->pd_ref_count == 0)) {
					fc_remote_node_t *node =
					    pd->pd_remote_nodep;

					mutex_exit(&pd->pd_mutex);
					mutex_exit(&port->fp_mutex);

					/*
					 * This will create another PD hole
					 * where we have a reference to a pd,
					 * but someone else could remove it.
					 */
					if ((fctl_destroy_remote_port(port, pd)
					    == 0) && (node != NULL)) {
						fctl_destroy_remote_node(node);
					}
					mutex_enter(&port->fp_mutex);
				} else {
					mutex_exit(&pd->pd_mutex);
				}
				pd = newpd;
			}
		}

		if (pd->pd_state != PORT_DEVICE_LOGGED_IN) {
			rval = (pd->pd_state == PORT_DEVICE_VALID) ?
			    FC_LOGINREQ : FC_BADDEV;
			mutex_exit(&port->fp_mutex);
			return (rval);
		}

		if (pd->pd_flags != PD_IDLE) {
			mutex_exit(&port->fp_mutex);
			return (FC_DEVICE_BUSY);
		}

		if (pd->pd_type == PORT_DEVICE_OLD ||
		    pd->pd_state == PORT_DEVICE_INVALID) {
			mutex_exit(&port->fp_mutex);
			return (FC_BADDEV);
		}

	} else if (FC_IS_REAL_DEVICE(pkt->pkt_cmd_fhdr.d_id)) {
		mutex_exit(&port->fp_mutex);
		return (FC_BADPACKET);
	}
	mutex_exit(&port->fp_mutex);

	return (port->fp_fca_tran->fca_transport(port->fp_fca_handle, pkt));
}


int
fc_ulp_issue_els(opaque_t port_handle, fc_packet_t *pkt)
{
	int			rval;
	fc_local_port_t		*port = port_handle;
	fc_remote_port_t	*pd;
	fc_ulp_rscn_info_t	*rscnp =
	    (fc_ulp_rscn_info_t *)pkt->pkt_ulp_rscn_infop;

	/*
	 * If the port is OFFLINE, or if the port driver is
	 * being SUSPENDED/PM_SUSPENDED/DETACHED, block all
	 * ELS operations
	 */
	mutex_enter(&port->fp_mutex);
	if ((FC_PORT_STATE_MASK(port->fp_state) == FC_STATE_OFFLINE) ||
	    (port->fp_soft_state &
	    (FP_SOFT_IN_DETACH | FP_SOFT_SUSPEND | FP_SOFT_POWER_DOWN))) {
		mutex_exit(&port->fp_mutex);
		return (FC_OFFLINE);
	}

	if (port->fp_statec_busy) {
		mutex_exit(&port->fp_mutex);
		return (FC_STATEC_BUSY);
	}

	/*
	 * If the rscn count in the packet is not the same as the rscn count
	 * in the fc_local_port_t, then one or more new RSCNs has occurred.
	 */
	if ((rscnp != NULL) &&
	    (rscnp->ulp_rscn_count != FC_INVALID_RSCN_COUNT) &&
	    (rscnp->ulp_rscn_count != port->fp_rscn_count)) {
		mutex_exit(&port->fp_mutex);
		return (FC_DEVICE_BUSY_NEW_RSCN);
	}

	mutex_exit(&port->fp_mutex);

	if ((pd = pkt->pkt_pd) != NULL) {
		mutex_enter(&pd->pd_mutex);
		if (pd->pd_state != PORT_DEVICE_LOGGED_IN) {
			rval = (pd->pd_state == PORT_DEVICE_VALID) ?
			    FC_LOGINREQ : FC_BADDEV;
			mutex_exit(&pd->pd_mutex);
			return (rval);
		}

		if (pd->pd_flags != PD_IDLE) {
			mutex_exit(&pd->pd_mutex);
			return (FC_DEVICE_BUSY);
		}
		if (pd->pd_type == PORT_DEVICE_OLD ||
		    pd->pd_state == PORT_DEVICE_INVALID) {
			mutex_exit(&pd->pd_mutex);
			return (FC_BADDEV);
		}
		mutex_exit(&pd->pd_mutex);
	}

	return (port->fp_fca_tran->fca_els_send(port->fp_fca_handle, pkt));
}


int
fc_ulp_uballoc(opaque_t port_handle, uint32_t *count, uint32_t size,
    uint32_t type, uint64_t *tokens)
{
	fc_local_port_t *port = port_handle;

	return (port->fp_fca_tran->fca_ub_alloc(port->fp_fca_handle,
	    tokens, size, count, type));
}


int
fc_ulp_ubfree(opaque_t port_handle, uint32_t count, uint64_t *tokens)
{
	fc_local_port_t *port = port_handle;

	return (port->fp_fca_tran->fca_ub_free(port->fp_fca_handle,
	    count, tokens));
}


int
fc_ulp_ubrelease(opaque_t port_handle, uint32_t count, uint64_t *tokens)
{
	fc_local_port_t *port = port_handle;

	return (port->fp_fca_tran->fca_ub_release(port->fp_fca_handle,
	    count, tokens));
}


int
fc_ulp_abort(opaque_t port_handle, fc_packet_t *pkt, int flags)
{
	fc_local_port_t *port = port_handle;

	return (port->fp_fca_tran->fca_abort(port->fp_fca_handle, pkt, flags));
}


/*
 * Submit an asynchronous request to the job handler if the sleep
 * flag is set to KM_NOSLEEP, as such calls could have been made
 * in interrupt contexts, and the goal is to avoid busy waiting,
 * blocking on a conditional variable, a semaphore or any of the
 * synchronization primitives. A noticeable draw back with this
 * asynchronous request is that an FC_SUCCESS is returned long
 * before the reset is complete (successful or not).
 */
int
fc_ulp_linkreset(opaque_t port_handle, la_wwn_t *pwwn, int sleep)
{
	int		rval;
	fc_local_port_t *port;
	job_request_t	*job;

	port = port_handle;
	/*
	 * Many a times, this function is called from interrupt
	 * contexts and there have been several dead locks and
	 * hangs - One of the simplest work arounds is to fib
	 * if a RESET is in progress.
	 */
	mutex_enter(&port->fp_mutex);
	if (port->fp_soft_state & FP_SOFT_IN_LINK_RESET) {
		mutex_exit(&port->fp_mutex);
		return (FC_SUCCESS);
	}

	/*
	 * Ward off this reset if a state change is in progress.
	 */
	if (port->fp_statec_busy) {
		mutex_exit(&port->fp_mutex);
		return (FC_STATEC_BUSY);
	}
	port->fp_soft_state |= FP_SOFT_IN_LINK_RESET;
	mutex_exit(&port->fp_mutex);

	if (fctl_busy_port(port) != 0) {
		mutex_enter(&port->fp_mutex);
		port->fp_soft_state &= ~FP_SOFT_IN_LINK_RESET;
		mutex_exit(&port->fp_mutex);
		return (FC_FAILURE);
	}

	if (sleep == KM_SLEEP) {
		job = fctl_alloc_job(JOB_LINK_RESET, 0, NULL, NULL, sleep);
		ASSERT(job != NULL);

		job->job_private = (void *)pwwn;
		job->job_counter = 1;
		fctl_enque_job(port, job);
		fctl_jobwait(job);

		mutex_enter(&port->fp_mutex);
		port->fp_soft_state &= ~FP_SOFT_IN_LINK_RESET;
		mutex_exit(&port->fp_mutex);

		fctl_idle_port(port);

		rval = job->job_result;
		fctl_dealloc_job(job);
	} else {
		job = fctl_alloc_job(JOB_LINK_RESET, JOB_TYPE_FCTL_ASYNC,
		    fctl_link_reset_done, port, sleep);
		if (job == NULL) {
			mutex_enter(&port->fp_mutex);
			port->fp_soft_state &= ~FP_SOFT_IN_LINK_RESET;
			mutex_exit(&port->fp_mutex);
			fctl_idle_port(port);
			return (FC_NOMEM);
		}
		job->job_private = (void *)pwwn;
		job->job_counter = 1;
		fctl_priority_enque_job(port, job);
		rval = FC_SUCCESS;
	}

	return (rval);
}


int
fc_ulp_port_reset(opaque_t port_handle, uint32_t cmd)
{
	int		rval = FC_SUCCESS;
	fc_local_port_t *port = port_handle;

	switch (cmd) {
	case FC_RESET_PORT:
		rval = port->fp_fca_tran->fca_reset(
		    port->fp_fca_handle, FC_FCA_LINK_RESET);
		break;

	case FC_RESET_ADAPTER:
		rval = port->fp_fca_tran->fca_reset(
		    port->fp_fca_handle, FC_FCA_RESET);
		break;

	case FC_RESET_DUMP:
		rval = port->fp_fca_tran->fca_reset(
		    port->fp_fca_handle, FC_FCA_CORE);
		break;

	case FC_RESET_CRASH:
		rval = port->fp_fca_tran->fca_reset(
		    port->fp_fca_handle, FC_FCA_RESET_CORE);
		break;

	default:
		rval = FC_FAILURE;
	}

	return (rval);
}


int
fc_ulp_get_port_login_params(opaque_t port_handle, la_els_logi_t *login_params)
{
	fc_local_port_t *port = port_handle;

	/* Copy the login parameters */
	*login_params = port->fp_service_params;
	return (FC_SUCCESS);
}


int
fc_ulp_get_port_instance(opaque_t port_handle)
{
	fc_local_port_t *port = port_handle;

	return (port->fp_instance);
}


opaque_t
fc_ulp_get_port_handle(int port_instance)
{
	opaque_t	port_handle = NULL;
	fc_fca_port_t	*cur;

	mutex_enter(&fctl_port_lock);
	for (cur = fctl_fca_portlist; cur; cur = cur->port_next) {
		if (cur->port_handle->fp_instance == port_instance) {
			port_handle = (opaque_t)cur->port_handle;
			break;
		}
	}
	mutex_exit(&fctl_port_lock);

	return (port_handle);
}


int
fc_ulp_error(int fc_errno, char **errmsg)
{
	return (fctl_error(fc_errno, errmsg));
}


int
fc_ulp_pkt_error(fc_packet_t *pkt, char **state, char **reason,
    char **action, char **expln)
{
	return (fctl_pkt_error(pkt, state, reason, action, expln));
}


/*
 * If an ULP by the specified name exists, return FC_SUCCESS, else FC_FAILURE
 */
int
fc_ulp_is_name_present(caddr_t ulp_name)
{
	int		rval = FC_FAILURE;
	fc_ulp_list_t	*list;

	mutex_enter(&fctl_ulp_list_mutex);
	for (list = fctl_ulp_list; list != NULL; list = list->ulp_next) {
		if (strcmp(list->ulp_info->ulp_name, ulp_name) == 0) {
			rval = FC_SUCCESS;
			break;
		}
	}
	mutex_exit(&fctl_ulp_list_mutex);

	return (rval);
}


/*
 * Return port WWN for a port Identifier
 */
int
fc_ulp_get_pwwn_by_did(opaque_t port_handle, fc_portid_t d_id, la_wwn_t *pwwn)
{
	int			rval = FC_FAILURE;
	fc_remote_port_t	*pd;
	fc_local_port_t		*port = port_handle;

	pd = fctl_get_remote_port_by_did(port, d_id.port_id);
	if (pd != NULL) {
		mutex_enter(&pd->pd_mutex);
		*pwwn = pd->pd_port_name;
		mutex_exit(&pd->pd_mutex);
		rval = FC_SUCCESS;
	}

	return (rval);
}


/*
 * Return a port map for a port WWN
 */
int
fc_ulp_pwwn_to_portmap(opaque_t port_handle, la_wwn_t *bytes, fc_portmap_t *map)
{
	fc_local_port_t		*port = port_handle;
	fc_remote_node_t	*node;
	fc_remote_port_t	*pd;

	pd = fctl_get_remote_port_by_pwwn(port, bytes);
	if (pd == NULL) {
		return (FC_FAILURE);
	}

	mutex_enter(&pd->pd_mutex);
	map->map_pwwn = pd->pd_port_name;
	map->map_did = pd->pd_port_id;
	map->map_hard_addr = pd->pd_hard_addr;
	map->map_state = pd->pd_state;
	map->map_type = pd->pd_type;
	map->map_flags = 0;

	ASSERT(map->map_type <= PORT_DEVICE_DELETE);

	bcopy(pd->pd_fc4types, map->map_fc4_types, sizeof (pd->pd_fc4types));

	node = pd->pd_remote_nodep;
	mutex_exit(&pd->pd_mutex);

	if (node) {
		mutex_enter(&node->fd_mutex);
		map->map_nwwn = node->fd_node_name;
		mutex_exit(&node->fd_mutex);
	}
	map->map_pd = pd;

	return (FC_SUCCESS);
}


opaque_t
fc_ulp_get_fca_device(opaque_t port_handle, fc_portid_t d_id)
{
	fc_local_port_t	*port = port_handle;

	if (port->fp_fca_tran->fca_get_device == NULL) {
		return (NULL);
	}

	return (port->fp_fca_tran->fca_get_device(port->fp_fca_handle, d_id));
}


int
fc_ulp_port_notify(opaque_t port_handle, uint32_t cmd)
{
	int		rval = FC_SUCCESS;
	fc_local_port_t	*port = port_handle;

	if (port->fp_fca_tran->fca_notify) {
		mutex_enter(&port->fp_mutex);
		switch (cmd) {
		case FC_NOTIFY_TARGET_MODE:
			port->fp_options |= FP_TARGET_MODE;
			break;
		case FC_NOTIFY_NO_TARGET_MODE:
			port->fp_options &= ~FP_TARGET_MODE;
			break;
		}
		mutex_exit(&port->fp_mutex);
		rval = port->fp_fca_tran->fca_notify(port->fp_fca_handle, cmd);
	}

	return (rval);
}


void
fc_ulp_disable_relogin(opaque_t *fc_port, la_wwn_t *pwwn)
{
	fc_remote_port_t *pd =
	    fctl_get_remote_port_by_pwwn((fc_local_port_t *)fc_port, pwwn);

	if (pd) {
		mutex_enter(&pd->pd_mutex);
		pd->pd_aux_flags |= PD_DISABLE_RELOGIN;
		mutex_exit(&pd->pd_mutex);
	}
}


void
fc_ulp_enable_relogin(opaque_t *fc_port, la_wwn_t *pwwn)
{
	fc_remote_port_t *pd =
	    fctl_get_remote_port_by_pwwn((fc_local_port_t *)fc_port, pwwn);

	if (pd) {
		mutex_enter(&pd->pd_mutex);
		pd->pd_aux_flags &= ~PD_DISABLE_RELOGIN;
		mutex_exit(&pd->pd_mutex);
	}
}


/*
 * fc_fca_init
 *		Overload the FCA bus_ops vector in its dev_ops with
 *		fctl_fca_busops to handle all the INITchilds for "sf"
 *		in one common place.
 *
 *		Should be called from FCA _init routine.
 */
void
fc_fca_init(struct dev_ops *fca_devops_p)
{
#ifndef	__lock_lint
	fca_devops_p->devo_bus_ops = &fctl_fca_busops;
#endif	/* __lock_lint */
}


/*
 * fc_fca_attach
 */
int
fc_fca_attach(dev_info_t *fca_dip, fc_fca_tran_t *tran)
{
	/*
	 * When we are in a position to offer downward compatibility
	 * we should change the following check to allow lower revision
	 * of FCAs; But we aren't there right now.
	 */
	if (tran->fca_version != FCTL_FCA_MODREV_5) {
		const char *name = ddi_driver_name(fca_dip);

		ASSERT(name != NULL);

		cmn_err(CE_WARN, "fctl: FCA %s version mismatch"
		    " please upgrade %s", name, name);
		return (DDI_FAILURE);
	}

	ddi_set_driver_private(fca_dip, (caddr_t)tran);
	return (DDI_SUCCESS);
}


/*
 * fc_fca_detach
 */
int
fc_fca_detach(dev_info_t *fca_dip)
{
	ddi_set_driver_private(fca_dip, NULL);
	return (DDI_SUCCESS);
}


/*
 * Check if the frame is a Link response Frame; Handle all cases (P_RJT,
 * F_RJT, P_BSY, F_BSY fall into this category). Check also for some Basic
 * Link Service responses such as BA_RJT and Extended Link Service response
 * such as LS_RJT. If the response is a Link_Data Frame or something that
 * this function doesn't understand return FC_FAILURE; Otherwise, fill out
 * various fields (state, action, reason, expln) from the response gotten
 * in the packet and return FC_SUCCESS.
 */
int
fc_fca_update_errors(fc_packet_t *pkt)
{
	int ret = FC_SUCCESS;

	switch (pkt->pkt_resp_fhdr.r_ctl) {
	case R_CTL_P_RJT: {
		uint32_t prjt;

		prjt = pkt->pkt_resp_fhdr.ro;
		pkt->pkt_state = FC_PKT_NPORT_RJT;
		pkt->pkt_action = (prjt & 0xFF000000) >> 24;
		pkt->pkt_reason = (prjt & 0xFF0000) >> 16;
		break;
	}

	case R_CTL_F_RJT: {
		uint32_t frjt;

		frjt = pkt->pkt_resp_fhdr.ro;
		pkt->pkt_state = FC_PKT_FABRIC_RJT;
		pkt->pkt_action = (frjt & 0xFF000000) >> 24;
		pkt->pkt_reason = (frjt & 0xFF0000) >> 16;
		break;
	}

	case R_CTL_P_BSY: {
		uint32_t pbsy;

		pbsy = pkt->pkt_resp_fhdr.ro;
		pkt->pkt_state = FC_PKT_NPORT_BSY;
		pkt->pkt_action = (pbsy & 0xFF000000) >> 24;
		pkt->pkt_reason = (pbsy & 0xFF0000) >> 16;
		break;
	}

	case R_CTL_F_BSY_LC:
	case R_CTL_F_BSY_DF: {
		uchar_t fbsy;

		fbsy = pkt->pkt_resp_fhdr.type;
		pkt->pkt_state = FC_PKT_FABRIC_BSY;
		pkt->pkt_reason = (fbsy & 0xF0) >> 4;
		break;
	}

	case R_CTL_LS_BA_RJT: {
		uint32_t brjt;

		brjt = *(uint32_t *)pkt->pkt_resp;
		pkt->pkt_state = FC_PKT_BA_RJT;
		pkt->pkt_reason = (brjt & 0xFF0000) >> 16;
		pkt->pkt_expln = (brjt & 0xFF00) >> 8;
		break;
	}

	case R_CTL_ELS_RSP: {
		la_els_rjt_t *lsrjt;

		lsrjt = (la_els_rjt_t *)pkt->pkt_resp;
		if (lsrjt->ls_code.ls_code == LA_ELS_RJT) {
			pkt->pkt_state = FC_PKT_LS_RJT;
			pkt->pkt_reason = lsrjt->reason;
			pkt->pkt_action = lsrjt->action;
			break;
		}
	}
	/* FALLTHROUGH */

	default:
		ret = FC_FAILURE;
		break;
	}

	return (ret);
}


int
fc_fca_error(int fc_errno, char **errmsg)
{
	return (fctl_error(fc_errno, errmsg));
}


int
fc_fca_pkt_error(fc_packet_t *pkt, char **state, char **reason,
    char **action, char **expln)
{
	return (fctl_pkt_error(pkt, state, reason, action, expln));
}


/*
 * WWN to string goodie. Unpredictable results will happen
 * if enough memory isn't supplied in str argument. If you
 * are wondering how much does this routine need, it is just
 * (2 * WWN size + 1). So for a WWN size of 8 bytes the str
 * argument should have atleast 17 bytes allocated.
 */
void
fc_wwn_to_str(la_wwn_t *wwn, caddr_t str)
{
	int count;

	for (count = 0; count < FCTL_WWN_SIZE(wwn); count++, str += 2) {
		(void) sprintf(str, "%02x", wwn->raw_wwn[count]);
	}
	*str = '\0';
}

#define	FC_ATOB(x)	(((x) >= '0' && (x) <= '9') ? ((x) - '0') :	\
			((x) >= 'a' && (x) <= 'f') ?			\
			((x) - 'a' + 10) : ((x) - 'A' + 10))

void
fc_str_to_wwn(caddr_t str, la_wwn_t *wwn)
{
	int count = 0;
	uchar_t byte;

	while (*str) {
		byte = FC_ATOB(*str);
		str++;
		byte = byte << 4 | FC_ATOB(*str);
		str++;
		wwn->raw_wwn[count++] = byte;
	}
}

/*
 * FCA driver's intercepted bus control operations.
 */
static int
fctl_fca_bus_ctl(dev_info_t *fca_dip, dev_info_t *rip,
    ddi_ctl_enum_t op, void *arg, void *result)
{
	switch (op) {
	case DDI_CTLOPS_REPORTDEV:
		break;

	case DDI_CTLOPS_IOMIN:
		break;

	case DDI_CTLOPS_INITCHILD:
		return (fctl_initchild(fca_dip, (dev_info_t *)arg));

	case DDI_CTLOPS_UNINITCHILD:
		return (fctl_uninitchild(fca_dip, (dev_info_t *)arg));

	default:
		return (ddi_ctlops(fca_dip, rip, op, arg, result));
	}

	return (DDI_SUCCESS);
}


/*
 * FCAs indicate the maximum number of ports supported in their
 * tran structure. Fail the INITCHILD if the child port number
 * is any greater than the maximum number of ports supported
 * by the FCA.
 */
static int
fctl_initchild(dev_info_t *fca_dip, dev_info_t *port_dip)
{
	int		rval;
	int		port_no;
	int		port_len;
	char		name[20];
	fc_fca_tran_t	*tran;
	dev_info_t	*dip;
	int		portprop;

	port_len = sizeof (port_no);

	/* physical port do not has this property */
	portprop = ddi_prop_get_int(DDI_DEV_T_ANY, port_dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    "phyport-instance", -1);

	if ((portprop == -1) && ndi_dev_is_persistent_node(port_dip)) {
		/*
		 * Clear any addr bindings created by fcode interpreter
		 * in devi_last_addr so that a ndi_devi_find should never
		 * return this fcode node.
		 */
		ddi_set_name_addr(port_dip, NULL);
		return (DDI_FAILURE);
	}

	rval = ddi_prop_op(DDI_DEV_T_ANY, port_dip, PROP_LEN_AND_VAL_BUF,
	    DDI_PROP_DONTPASS | DDI_PROP_CANSLEEP, "port",
	    (caddr_t)&port_no, &port_len);

	if (rval != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	tran = (fc_fca_tran_t *)ddi_get_driver_private(fca_dip);
	ASSERT(tran != NULL);

	(void) sprintf((char *)name, "%x,0", port_no);
	ddi_set_name_addr(port_dip, name);

	dip = ndi_devi_find(fca_dip, ddi_binding_name(port_dip), name);

	/*
	 * Even though we never initialize FCode nodes of fp, such a node
	 * could still be there after a DR operation. There will only be
	 * one FCode node, so if this is the one, clear it and issue a
	 * ndi_devi_find again.
	 */
	if ((portprop == -1) && dip && ndi_dev_is_persistent_node(dip)) {
		ddi_set_name_addr(dip, NULL);
		dip = ndi_devi_find(fca_dip, ddi_binding_name(port_dip), name);
	}

	if ((portprop == -1) && dip && (dip != port_dip)) {
		/*
		 * Here we have a duplicate .conf entry. Clear the addr
		 * set previously and return failure.
		 */
		ddi_set_name_addr(port_dip, NULL);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}


/* ARGSUSED */
static int
fctl_uninitchild(dev_info_t *fca_dip, dev_info_t *port_dip)
{
	ddi_set_name_addr(port_dip, NULL);
	return (DDI_SUCCESS);
}


static dev_info_t *
fctl_findchild(dev_info_t *pdip, char *cname, char *caddr)
{
	dev_info_t *dip;
	char *addr;

	ASSERT(cname != NULL && caddr != NULL);
	/* ASSERT(DEVI_BUSY_OWNED(pdip)); */

	for (dip = ddi_get_child(pdip); dip != NULL;
	    dip = ddi_get_next_sibling(dip)) {
		if (strcmp(cname, ddi_node_name(dip)) != 0) {
			continue;
		}

		if ((addr = ddi_get_name_addr(dip)) == NULL) {
			if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip,
			    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
			    "bus-addr", &addr) == DDI_PROP_SUCCESS) {
				if (strcmp(caddr, addr) == 0) {
					ddi_prop_free(addr);
					return (dip);
				}
				ddi_prop_free(addr);
			}
		} else {
			if (strcmp(caddr, addr) == 0) {
				return (dip);
			}
		}
	}

	return (NULL);
}

int
fctl_check_npiv_portindex(dev_info_t *dip, int vindex)
{
	int i, instance;
	fc_local_port_t *port;

	instance = ddi_get_instance(dip);
	port = (fc_local_port_t *)fc_ulp_get_port_handle(instance);
	if ((!port) || (vindex <= 0) || (vindex >= FC_NPIV_MAX_PORT)) {
		return (0);
	}

	i = vindex-1;
	mutex_enter(&port->fp_mutex);
	if (port->fp_npiv_portindex[i] == 0) {
		mutex_exit(&port->fp_mutex);
		return (vindex);
	}
	mutex_exit(&port->fp_mutex);
	return (0);
}

int
fctl_get_npiv_portindex(dev_info_t *dip)
{
	int i, instance;
	fc_local_port_t *port;

	instance = ddi_get_instance(dip);
	port = (fc_local_port_t *)fc_ulp_get_port_handle(instance);
	if (!port) {
		return (0);
	}

	mutex_enter(&port->fp_mutex);
	for (i = 0; i < FC_NPIV_MAX_PORT; i++) {
		if (port->fp_npiv_portindex[i] == 0) {
			mutex_exit(&port->fp_mutex);
			return (i+1);
		}
	}
	mutex_exit(&port->fp_mutex);
	return (0);
}


void
fctl_set_npiv_portindex(dev_info_t *dip, int index)
{
	int instance;
	fc_local_port_t *port;

	instance = ddi_get_instance(dip);
	port = (fc_local_port_t *)fc_ulp_get_port_handle(instance);
	if (!port) {
		return;
	}
	mutex_enter(&port->fp_mutex);
	port->fp_npiv_portindex[index - 1] = 1;
	mutex_exit(&port->fp_mutex);
}


int
fctl_fca_create_npivport(dev_info_t *parent,
    dev_info_t *phydip, char *nname, char *pname, uint32_t *vindex)
{
	int rval = 0, devstrlen;
	char	*devname, *cname, *caddr, *devstr;
	dev_info_t	*child = NULL;
	int		portnum;

	if (*vindex == 0) {
		portnum = fctl_get_npiv_portindex(phydip);
		*vindex = portnum;
	} else {
		portnum = fctl_check_npiv_portindex(phydip, *vindex);
	}

	if (portnum == 0) {
		cmn_err(CE_WARN,
		    "Cann't find valid port index, fail to create devnode");
		return (NDI_FAILURE);
	}

	devname = kmem_zalloc(MAXNAMELEN, KM_SLEEP);
	(void) sprintf(devname, "fp@%x,0", portnum);
	devstrlen = strlen(devname) + 1;
	devstr = i_ddi_strdup(devname, KM_SLEEP);
	i_ddi_parse_name(devstr, &cname, &caddr, NULL);

	if (fctl_findchild(parent, cname, caddr) != NULL) {
		rval = NDI_FAILURE;
		goto freememory;
	}

	ndi_devi_alloc_sleep(parent, cname, DEVI_PSEUDO_NODEID, &child);
	if (child == NULL) {
		cmn_err(CE_WARN,
		    "fctl_create_npiv_port fail to create new devinfo");
		rval = NDI_FAILURE;
		goto freememory;
	}

	if (ndi_prop_update_string(DDI_DEV_T_NONE, child,
	    "bus-addr", caddr) != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "fctl%d: prop update bus-addr %s@%s failed",
		    ddi_get_instance(parent), cname, caddr);
		(void) ndi_devi_free(child);
		rval = NDI_FAILURE;
		goto freememory;
	}

	if (strlen(nname) != 0) {
		if (ndi_prop_update_string(DDI_DEV_T_NONE, child,
		    "node-name", nname) != DDI_PROP_SUCCESS) {
			(void) ndi_devi_free(child);
			rval = NDI_FAILURE;
			goto freememory;
		}
	}

	if (strlen(pname) != 0) {
		if (ndi_prop_update_string(DDI_DEV_T_NONE, child,
		    "port-name", pname) != DDI_PROP_SUCCESS) {
			(void) ndi_devi_free(child);
			rval = NDI_FAILURE;
			goto freememory;
		}
	}

	if (ddi_prop_update_int(DDI_DEV_T_NONE, child,
	    "port", portnum) != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "fp%d: prop_update port %s@%s failed",
		    ddi_get_instance(parent), cname, caddr);
		(void) ndi_devi_free(child);
		rval = NDI_FAILURE;
		goto freememory;
	}

	if (ddi_prop_update_int(DDI_DEV_T_NONE, child,
	    "phyport-instance", ddi_get_instance(phydip)) != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN,
		    "fp%d: prop_update phyport-instance %s@%s failed",
		    ddi_get_instance(parent), cname, caddr);
		(void) ndi_devi_free(child);
		rval = NDI_FAILURE;
		goto freememory;
	}

	rval = ndi_devi_online(child, NDI_ONLINE_ATTACH);
	if (rval != NDI_SUCCESS) {
		cmn_err(CE_WARN, "fp%d: online_driver %s failed",
		    ddi_get_instance(parent), cname);
		rval = NDI_FAILURE;
		goto freememory;
	}

	fctl_set_npiv_portindex(phydip, portnum);
freememory:
	kmem_free(devstr, devstrlen);
	kmem_free(devname, MAXNAMELEN);

	return (rval);
}


void
fctl_add_port(fc_local_port_t *port)
{
	fc_fca_port_t *new;

	new = kmem_zalloc(sizeof (*new), KM_SLEEP);

	mutex_enter(&fctl_port_lock);
	new->port_handle = port;
	new->port_next = fctl_fca_portlist;
	fctl_fca_portlist = new;
	mutex_exit(&fctl_port_lock);
}


void
fctl_remove_port(fc_local_port_t *port)
{
	fc_ulp_module_t		*mod;
	fc_fca_port_t		*prev;
	fc_fca_port_t		*list;
	fc_ulp_ports_t		*ulp_port;

	rw_enter(&fctl_ulp_lock, RW_WRITER);
	rw_enter(&fctl_mod_ports_lock, RW_WRITER);

	for (mod = fctl_ulp_modules; mod; mod = mod->mod_next) {
		ulp_port = fctl_get_ulp_port(mod, port);
		if (ulp_port == NULL) {
			continue;
		}

#ifndef	__lock_lint
		ASSERT((ulp_port->port_dstate & ULP_PORT_ATTACH) == 0);
#endif /* __lock_lint */

		(void) fctl_remove_ulp_port(mod, port);
	}

	rw_exit(&fctl_mod_ports_lock);
	rw_exit(&fctl_ulp_lock);

	mutex_enter(&fctl_port_lock);

	list = fctl_fca_portlist;
	prev = NULL;
	while (list != NULL) {
		if (list->port_handle == port) {
			if (prev == NULL) {
				fctl_fca_portlist = list->port_next;
			} else {
				prev->port_next = list->port_next;
			}
			kmem_free(list, sizeof (*list));
			break;
		}
		prev = list;
		list = list->port_next;
	}
	mutex_exit(&fctl_port_lock);
}


void
fctl_attach_ulps(fc_local_port_t *port, fc_attach_cmd_t cmd,
    struct modlinkage *linkage)
{
	int			rval;
	uint32_t		s_id;
	uint32_t		state;
	fc_ulp_module_t		*mod;
	fc_ulp_port_info_t	info;
	fc_ulp_ports_t		*ulp_port;

	ASSERT(!MUTEX_HELD(&port->fp_mutex));

	info.port_linkage = linkage;
	info.port_dip = port->fp_port_dip;
	info.port_handle = (opaque_t)port;
	info.port_dma_behavior = port->fp_dma_behavior;
	info.port_fcp_dma = port->fp_fcp_dma;
	info.port_acc_attr = port->fp_fca_tran->fca_acc_attr;
	info.port_fca_pkt_size = port->fp_fca_tran->fca_pkt_size;
	info.port_reset_action = port->fp_reset_action;

	mutex_enter(&port->fp_mutex);

	/*
	 * It is still possible that another thread could have gotten
	 * into the detach process before we got here.
	 */
	if (port->fp_soft_state & FP_SOFT_IN_DETACH) {
		mutex_exit(&port->fp_mutex);
		return;
	}

	s_id = port->fp_port_id.port_id;
	if (port->fp_statec_busy) {
		info.port_state = port->fp_bind_state;
	} else {
		info.port_state = port->fp_state;
	}

	switch (state = FC_PORT_STATE_MASK(info.port_state)) {
	case FC_STATE_LOOP:
	case FC_STATE_NAMESERVICE:
		info.port_state &= ~state;
		info.port_state |= FC_STATE_ONLINE;
		break;

	default:
		break;
	}
	ASSERT((info.port_state & FC_STATE_LOOP) == 0);

	info.port_flags = port->fp_topology;
	info.port_pwwn = port->fp_service_params.nport_ww_name;
	info.port_nwwn = port->fp_service_params.node_ww_name;
	mutex_exit(&port->fp_mutex);

	rw_enter(&fctl_ulp_lock, RW_READER);
	rw_enter(&fctl_mod_ports_lock, RW_WRITER);

	for (mod = fctl_ulp_modules; mod; mod = mod->mod_next) {
		if ((port->fp_soft_state & FP_SOFT_FCA_IS_NODMA) &&
		    (mod->mod_info->ulp_type == FC_TYPE_IS8802_SNAP)) {
			/*
			 * We don't support IP over FC on FCOE HBA
			 */
			continue;
		}

		if ((ulp_port = fctl_get_ulp_port(mod, port)) == NULL) {
			ulp_port = fctl_add_ulp_port(mod, port, KM_SLEEP);
			ASSERT(ulp_port != NULL);

			mutex_enter(&ulp_port->port_mutex);
			ulp_port->port_statec = ((info.port_state &
			    FC_STATE_ONLINE) ? FC_ULP_STATEC_ONLINE :
			    FC_ULP_STATEC_OFFLINE);
			mutex_exit(&ulp_port->port_mutex);
		}
	}

	rw_downgrade(&fctl_mod_ports_lock);

	for (mod = fctl_ulp_modules; mod; mod = mod->mod_next) {
		if ((port->fp_soft_state & FP_SOFT_FCA_IS_NODMA) &&
		    (mod->mod_info->ulp_type == FC_TYPE_IS8802_SNAP)) {
			/*
			 * We don't support IP over FC on FCOE HBA
			 */
			continue;
		}

		ulp_port = fctl_get_ulp_port(mod, port);
		ASSERT(ulp_port != NULL);

		if (fctl_pre_attach(ulp_port, cmd) == FC_FAILURE) {
			continue;
		}

		fctl_init_dma_attr(port, mod, &info);

		rval = mod->mod_info->ulp_port_attach(
		    mod->mod_info->ulp_handle, &info, cmd, s_id);

		fctl_post_attach(mod, ulp_port, cmd, rval);

		if (rval == FC_SUCCESS && cmd == FC_CMD_ATTACH &&
		    strcmp(mod->mod_info->ulp_name, "fcp") == 0) {
			ASSERT(ddi_get_driver_private(info.port_dip) != NULL);
		}
	}

	rw_exit(&fctl_mod_ports_lock);
	rw_exit(&fctl_ulp_lock);
}


static int
fctl_pre_attach(fc_ulp_ports_t *ulp_port, fc_attach_cmd_t cmd)
{
	int rval = FC_SUCCESS;

	mutex_enter(&ulp_port->port_mutex);

	switch (cmd) {
	case FC_CMD_ATTACH:
		if (ulp_port->port_dstate & ULP_PORT_ATTACH) {
			rval = FC_FAILURE;
		}
		break;

	case FC_CMD_RESUME:
		ASSERT((ulp_port->port_dstate & ULP_PORT_POWER_DOWN) == 0);
		if (!(ulp_port->port_dstate & ULP_PORT_ATTACH) ||
		    !(ulp_port->port_dstate & ULP_PORT_SUSPEND)) {
			rval = FC_FAILURE;
		}
		break;

	case FC_CMD_POWER_UP:
		if (!(ulp_port->port_dstate & ULP_PORT_ATTACH) ||
		    !(ulp_port->port_dstate & ULP_PORT_POWER_DOWN)) {
			rval = FC_FAILURE;
		}
		break;
	}

	if (rval == FC_SUCCESS) {
		ulp_port->port_dstate |= ULP_PORT_BUSY;
	}
	mutex_exit(&ulp_port->port_mutex);

	return (rval);
}


static void
fctl_post_attach(fc_ulp_module_t *mod, fc_ulp_ports_t *ulp_port,
    fc_attach_cmd_t cmd, int rval)
{
	int	be_chatty;

	ASSERT(cmd == FC_CMD_ATTACH || cmd == FC_CMD_RESUME ||
	    cmd == FC_CMD_POWER_UP);

	mutex_enter(&ulp_port->port_mutex);
	ulp_port->port_dstate &= ~ULP_PORT_BUSY;

	be_chatty = (rval == FC_FAILURE_SILENT) ? 0 : 1;

	if (rval != FC_SUCCESS) {
		caddr_t		op;
		fc_local_port_t *port = ulp_port->port_handle;

		mutex_exit(&ulp_port->port_mutex);

		switch (cmd) {
		case FC_CMD_ATTACH:
			op = "attach";
			break;

		case FC_CMD_RESUME:
			op = "resume";
			break;

		case FC_CMD_POWER_UP:
			op = "power up";
			break;
		}

		if (be_chatty) {
			cmn_err(CE_WARN, "!fctl(%d): %s failed for %s",
			    port->fp_instance, op, mod->mod_info->ulp_name);
		}

		return;
	}

	switch (cmd) {
	case FC_CMD_ATTACH:
		ulp_port->port_dstate |= ULP_PORT_ATTACH;
		break;

	case FC_CMD_RESUME:
		ulp_port->port_dstate &= ~ULP_PORT_SUSPEND;
		break;

	case FC_CMD_POWER_UP:
		ulp_port->port_dstate &= ~ULP_PORT_POWER_DOWN;
		break;
	}
	mutex_exit(&ulp_port->port_mutex);
}


int
fctl_detach_ulps(fc_local_port_t *port, fc_detach_cmd_t cmd,
    struct modlinkage *linkage)
{
	int			rval = FC_SUCCESS;
	fc_ulp_module_t		*mod;
	fc_ulp_port_info_t	info;
	fc_ulp_ports_t		*ulp_port;

	ASSERT(!MUTEX_HELD(&port->fp_mutex));

	info.port_linkage = linkage;
	info.port_dip = port->fp_port_dip;
	info.port_handle = (opaque_t)port;
	info.port_acc_attr = port->fp_fca_tran->fca_acc_attr;
	info.port_fca_pkt_size = port->fp_fca_tran->fca_pkt_size;

	rw_enter(&fctl_ulp_lock, RW_READER);
	rw_enter(&fctl_mod_ports_lock, RW_READER);

	for (mod = fctl_ulp_modules; mod; mod = mod->mod_next) {
		if ((ulp_port = fctl_get_ulp_port(mod, port)) == NULL) {
			continue;
		}

		if (fctl_pre_detach(ulp_port, cmd) != FC_SUCCESS) {
			continue;
		}

		fctl_init_dma_attr(port, mod, &info);

		rval = mod->mod_info->ulp_port_detach(
		    mod->mod_info->ulp_handle, &info, cmd);

		fctl_post_detach(mod, ulp_port, cmd, rval);

		if (rval != FC_SUCCESS) {
			break;
		}

		if (cmd == FC_CMD_DETACH && strcmp(mod->mod_info->ulp_name,
		    "fcp") == 0) {
			ASSERT(ddi_get_driver_private(info.port_dip) == NULL);
		}

		mutex_enter(&ulp_port->port_mutex);
		ulp_port->port_statec = FC_ULP_STATEC_DONT_CARE;
		mutex_exit(&ulp_port->port_mutex);
	}

	rw_exit(&fctl_mod_ports_lock);
	rw_exit(&fctl_ulp_lock);

	return (rval);
}

static	void
fctl_init_dma_attr(fc_local_port_t *port, fc_ulp_module_t *mod,
    fc_ulp_port_info_t	*info)
{

	if ((strcmp(mod->mod_info->ulp_name, "fcp") == 0) ||
	    (strcmp(mod->mod_info->ulp_name, "ltct") == 0)) {
		info->port_cmd_dma_attr =
		    port->fp_fca_tran->fca_dma_fcp_cmd_attr;
		info->port_data_dma_attr =
		    port->fp_fca_tran->fca_dma_fcp_data_attr;
		info->port_resp_dma_attr =
		    port->fp_fca_tran->fca_dma_fcp_rsp_attr;
	} else if (strcmp(mod->mod_info->ulp_name, "fcsm") == 0) {
		info->port_cmd_dma_attr =
		    port->fp_fca_tran->fca_dma_fcsm_cmd_attr;
		info->port_data_dma_attr =
		    port->fp_fca_tran->fca_dma_attr;
		info->port_resp_dma_attr =
		    port->fp_fca_tran->fca_dma_fcsm_rsp_attr;
	} else if (strcmp(mod->mod_info->ulp_name, "fcip") == 0) {
		info->port_cmd_dma_attr =
		    port->fp_fca_tran->fca_dma_fcip_cmd_attr;
		info->port_data_dma_attr =
		    port->fp_fca_tran->fca_dma_attr;
		info->port_resp_dma_attr =
		    port->fp_fca_tran->fca_dma_fcip_rsp_attr;
	} else {
		info->port_cmd_dma_attr = info->port_data_dma_attr =
		    info->port_resp_dma_attr =
		    port->fp_fca_tran->fca_dma_attr; /* default */
	}
}

static int
fctl_pre_detach(fc_ulp_ports_t *ulp_port, fc_detach_cmd_t cmd)
{
	int rval = FC_SUCCESS;

	mutex_enter(&ulp_port->port_mutex);

	switch (cmd) {
	case FC_CMD_DETACH:
		if ((ulp_port->port_dstate & ULP_PORT_ATTACH) == 0) {
			rval = FC_FAILURE;
		}
		break;

	case FC_CMD_SUSPEND:
		if (!(ulp_port->port_dstate & ULP_PORT_ATTACH) ||
		    ulp_port->port_dstate & ULP_PORT_SUSPEND) {
			rval = FC_FAILURE;
		}
		break;

	case FC_CMD_POWER_DOWN:
		if (!(ulp_port->port_dstate & ULP_PORT_ATTACH) ||
		    ulp_port->port_dstate & ULP_PORT_POWER_DOWN) {
			rval = FC_FAILURE;
		}
		break;
	}

	if (rval == FC_SUCCESS) {
		ulp_port->port_dstate |= ULP_PORT_BUSY;
	}
	mutex_exit(&ulp_port->port_mutex);

	return (rval);
}


static void
fctl_post_detach(fc_ulp_module_t *mod, fc_ulp_ports_t *ulp_port,
    fc_detach_cmd_t cmd, int rval)
{
	ASSERT(cmd == FC_CMD_DETACH || cmd == FC_CMD_SUSPEND ||
	    cmd == FC_CMD_POWER_DOWN);

	mutex_enter(&ulp_port->port_mutex);
	ulp_port->port_dstate &= ~ULP_PORT_BUSY;

	if (rval != FC_SUCCESS) {
		caddr_t		op;
		fc_local_port_t *port = ulp_port->port_handle;

		mutex_exit(&ulp_port->port_mutex);

		switch (cmd) {
		case FC_CMD_DETACH:
			op = "detach";
			break;

		case FC_CMD_SUSPEND:
			op = "suspend";
			break;

		case FC_CMD_POWER_DOWN:
			op = "power down";
			break;
		}

		cmn_err(CE_WARN, "!fctl(%d): %s failed for %s",
		    port->fp_instance, op, mod->mod_info->ulp_name);

		return;
	}

	switch (cmd) {
	case FC_CMD_DETACH:
		ulp_port->port_dstate &= ~ULP_PORT_ATTACH;
		break;

	case FC_CMD_SUSPEND:
		ulp_port->port_dstate |= ULP_PORT_SUSPEND;
		break;

	case FC_CMD_POWER_DOWN:
		ulp_port->port_dstate |= ULP_PORT_POWER_DOWN;
		break;
	}
	mutex_exit(&ulp_port->port_mutex);
}


static fc_ulp_ports_t *
fctl_add_ulp_port(fc_ulp_module_t *ulp_module, fc_local_port_t *port_handle,
    int sleep)
{
	fc_ulp_ports_t *last;
	fc_ulp_ports_t *next;
	fc_ulp_ports_t *new;

	ASSERT(RW_READ_HELD(&fctl_ulp_lock));
	ASSERT(RW_WRITE_HELD(&fctl_mod_ports_lock));

	last = NULL;
	next = ulp_module->mod_ports;

	while (next != NULL) {
		last = next;
		next = next->port_next;
	}

	new = fctl_alloc_ulp_port(sleep);
	if (new == NULL) {
		return (new);
	}

	new->port_handle = port_handle;
	if (last == NULL) {
		ulp_module->mod_ports = new;
	} else {
		last->port_next = new;
	}

	return (new);
}


static fc_ulp_ports_t *
fctl_alloc_ulp_port(int sleep)
{
	fc_ulp_ports_t *new;

	new = kmem_zalloc(sizeof (*new), sleep);
	if (new == NULL) {
		return (new);
	}
	mutex_init(&new->port_mutex, NULL, MUTEX_DRIVER, NULL);

	return (new);
}


static int
fctl_remove_ulp_port(struct ulp_module *ulp_module,
    fc_local_port_t *port_handle)
{
	fc_ulp_ports_t *last;
	fc_ulp_ports_t *next;

	ASSERT(RW_WRITE_HELD(&fctl_ulp_lock));
	ASSERT(RW_WRITE_HELD(&fctl_mod_ports_lock));

	last = NULL;
	next = ulp_module->mod_ports;

	while (next != NULL) {
		if (next->port_handle == port_handle) {
			if (next->port_dstate & ULP_PORT_ATTACH) {
				return (FC_FAILURE);
			}
			break;
		}
		last = next;
		next = next->port_next;
	}

	if (next != NULL) {
		ASSERT((next->port_dstate & ULP_PORT_ATTACH) == 0);

		if (last == NULL) {
			ulp_module->mod_ports = next->port_next;
		} else {
			last->port_next = next->port_next;
		}
		fctl_dealloc_ulp_port(next);

		return (FC_SUCCESS);
	} else {
		return (FC_FAILURE);
	}
}


static void
fctl_dealloc_ulp_port(fc_ulp_ports_t *next)
{
	mutex_destroy(&next->port_mutex);
	kmem_free(next, sizeof (*next));
}


static fc_ulp_ports_t *
fctl_get_ulp_port(struct ulp_module *ulp_module, fc_local_port_t *port_handle)
{
	fc_ulp_ports_t *next;

	ASSERT(RW_LOCK_HELD(&fctl_ulp_lock));
	ASSERT(RW_LOCK_HELD(&fctl_mod_ports_lock));

	for (next = ulp_module->mod_ports; next != NULL;
	    next = next->port_next) {
		if (next->port_handle == port_handle) {
			return (next);
		}
	}

	return (NULL);
}


/*
 * Pass state change notfications on to registered ULPs.
 *
 * Can issue wakeups to client callers who might be waiting for completions
 * on other threads.
 *
 * Caution: will silently deallocate any fc_remote_port_t and/or
 * fc_remote_node_t structs it finds that are not in use.
 */
void
fctl_ulp_statec_cb(void *arg)
{
	uint32_t		s_id;
	uint32_t		new_state;
	fc_local_port_t		*port;
	fc_ulp_ports_t		*ulp_port;
	fc_ulp_module_t		*mod;
	fc_port_clist_t		*clist = (fc_port_clist_t *)arg;

	ASSERT(clist != NULL);

	port = clist->clist_port;

	mutex_enter(&port->fp_mutex);
	s_id = port->fp_port_id.port_id;
	mutex_exit(&port->fp_mutex);

	switch (clist->clist_state) {
	case FC_STATE_ONLINE:
		new_state = FC_ULP_STATEC_ONLINE;
		break;

	case FC_STATE_OFFLINE:
		if (clist->clist_len) {
			new_state = FC_ULP_STATEC_OFFLINE_TIMEOUT;
		} else {
			new_state = FC_ULP_STATEC_OFFLINE;
		}
		break;

	default:
		new_state = FC_ULP_STATEC_DONT_CARE;
		break;
	}

#ifdef	DEBUG
	/*
	 * sanity check for presence of OLD devices in the hash lists
	 */
	if (clist->clist_size) {
		int			count;
		fc_remote_port_t	*pd;

		ASSERT(clist->clist_map != NULL);
		for (count = 0; count < clist->clist_len; count++) {
			if (clist->clist_map[count].map_state ==
			    PORT_DEVICE_INVALID) {
				la_wwn_t	pwwn;
				fc_portid_t	d_id;

				pd = clist->clist_map[count].map_pd;
				if (pd != NULL) {
					mutex_enter(&pd->pd_mutex);
					pwwn = pd->pd_port_name;
					d_id = pd->pd_port_id;
					mutex_exit(&pd->pd_mutex);

					pd = fctl_get_remote_port_by_pwwn(port,
					    &pwwn);

					ASSERT(pd != clist->clist_map[count].
					    map_pd);

					pd = fctl_get_remote_port_by_did(port,
					    d_id.port_id);
					ASSERT(pd != clist->clist_map[count].
					    map_pd);
				}
			}
		}
	}
#endif

	/*
	 * Check for duplicate map entries
	 */
	if (clist->clist_size) {
		int			count;
		fc_remote_port_t	*pd1, *pd2;

		ASSERT(clist->clist_map != NULL);
		for (count = 0; count < clist->clist_len-1; count++) {
			int count2;

			pd1 = clist->clist_map[count].map_pd;
			if (pd1 == NULL) {
				continue;
			}

			for (count2 = count+1;
			    count2 < clist->clist_len;
			    count2++) {

				pd2 = clist->clist_map[count2].map_pd;
				if (pd2 == NULL) {
					continue;
				}

				if (pd1 == pd2) {
					clist->clist_map[count].map_flags |=
					    PORT_DEVICE_DUPLICATE_MAP_ENTRY;
					break;
				}
			}
		}
	}


	rw_enter(&fctl_ulp_lock, RW_READER);
	for (mod = fctl_ulp_modules; mod; mod = mod->mod_next) {
		rw_enter(&fctl_mod_ports_lock, RW_READER);
		ulp_port = fctl_get_ulp_port(mod, port);
		rw_exit(&fctl_mod_ports_lock);

		if (ulp_port == NULL) {
			continue;
		}

		mutex_enter(&ulp_port->port_mutex);
		if (FCTL_DISALLOW_CALLBACKS(ulp_port->port_dstate)) {
			mutex_exit(&ulp_port->port_mutex);
			continue;
		}

		switch (ulp_port->port_statec) {
		case FC_ULP_STATEC_DONT_CARE:
			if (ulp_port->port_statec != new_state) {
				ulp_port->port_statec = new_state;
			}
			break;

		case FC_ULP_STATEC_ONLINE:
		case FC_ULP_STATEC_OFFLINE:
			if (ulp_port->port_statec == new_state) {
				mutex_exit(&ulp_port->port_mutex);
				continue;
			}
			ulp_port->port_statec = new_state;
			break;

		case FC_ULP_STATEC_OFFLINE_TIMEOUT:
			if (ulp_port->port_statec == new_state ||
			    new_state == FC_ULP_STATEC_OFFLINE) {
				mutex_exit(&ulp_port->port_mutex);
				continue;
			}
			ulp_port->port_statec = new_state;
			break;

		default:
			ASSERT(0);
			break;
		}

		mod->mod_info->ulp_statec_callback(
		    mod->mod_info->ulp_handle, (opaque_t)port,
		    clist->clist_state, clist->clist_flags,
		    clist->clist_map, clist->clist_len, s_id);

		mutex_exit(&ulp_port->port_mutex);
	}
	rw_exit(&fctl_ulp_lock);

	if (clist->clist_size) {
		int			count;
		fc_remote_node_t	*node;
		fc_remote_port_t	*pd;

		ASSERT(clist->clist_map != NULL);
		for (count = 0; count < clist->clist_len; count++) {

			if ((pd = clist->clist_map[count].map_pd) == NULL) {
				continue;
			}

			mutex_enter(&pd->pd_mutex);

			pd->pd_ref_count--;
			ASSERT(pd->pd_ref_count >= 0);

			if (clist->clist_map[count].map_state !=
			    PORT_DEVICE_INVALID) {
				mutex_exit(&pd->pd_mutex);
				continue;
			}

			node = pd->pd_remote_nodep;
			pd->pd_aux_flags &= ~PD_GIVEN_TO_ULPS;

			mutex_exit(&pd->pd_mutex);

			/*
			 * This fc_remote_port_t is no longer referenced
			 * by any ULPs. Deallocate it if its pd_ref_count
			 * has reached zero.
			 */
			if ((fctl_destroy_remote_port(port, pd) == 0) &&
			    (node != NULL)) {
				fctl_destroy_remote_node(node);
			}
		}

		kmem_free(clist->clist_map,
		    sizeof (*(clist->clist_map)) * clist->clist_size);
	}

	if (clist->clist_wait) {
		mutex_enter(&clist->clist_mutex);
		clist->clist_wait = 0;
		cv_signal(&clist->clist_cv);
		mutex_exit(&clist->clist_mutex);
	} else {
		kmem_free(clist, sizeof (*clist));
	}
}


/*
 * Allocate an fc_remote_node_t struct to represent a remote node for the
 * given nwwn.	This will also add the nwwn to the global nwwn table.
 *
 * Returns a pointer to the newly-allocated struct.  Returns NULL if
 * the kmem_zalloc fails or if the enlist_wwn attempt fails.
 */
fc_remote_node_t *
fctl_create_remote_node(la_wwn_t *nwwn, int sleep)
{
	fc_remote_node_t *rnodep;

	if ((rnodep = kmem_zalloc(sizeof (*rnodep), sleep)) == NULL) {
		return (NULL);
	}

	mutex_init(&rnodep->fd_mutex, NULL, MUTEX_DRIVER, NULL);

	rnodep->fd_node_name = *nwwn;
	rnodep->fd_flags = FC_REMOTE_NODE_VALID;
	rnodep->fd_numports = 1;

	if (fctl_enlist_nwwn_table(rnodep, sleep) != FC_SUCCESS) {
		mutex_destroy(&rnodep->fd_mutex);
		kmem_free(rnodep, sizeof (*rnodep));
		return (NULL);
	}

	return (rnodep);
}

/*
 * Deconstruct and free the given fc_remote_node_t struct (remote node struct).
 * Silently skips the deconstruct/free if there are any fc_remote_port_t
 * (remote port device) structs still referenced by the given
 * fc_remote_node_t struct.
 */
void
fctl_destroy_remote_node(fc_remote_node_t *rnodep)
{
	mutex_enter(&rnodep->fd_mutex);

	/*
	 * Look at the count and linked list of of remote ports
	 * (fc_remote_port_t structs); bail if these indicate that
	 * given fc_remote_node_t may be in use.
	 */
	if (rnodep->fd_numports != 0 || rnodep->fd_portlistp) {
		mutex_exit(&rnodep->fd_mutex);
		return;
	}

	mutex_exit(&rnodep->fd_mutex);

	mutex_destroy(&rnodep->fd_mutex);
	kmem_free(rnodep, sizeof (*rnodep));
}


/*
 * Add the given fc_remote_node_t to the global fctl_nwwn_hash_table[]. This
 * uses the nwwn in the fd_node_name.raw_wwn of the given struct.
 * This only fails if the kmem_zalloc fails.  This does not check for a
 * unique or pre-existing nwwn in the fctl_nwwn_hash_table[].
 * This is only called from fctl_create_remote_node().
 */
int
fctl_enlist_nwwn_table(fc_remote_node_t *rnodep, int sleep)
{
	int			index;
	fctl_nwwn_elem_t	*new;
	fctl_nwwn_list_t	*head;

	ASSERT(!MUTEX_HELD(&rnodep->fd_mutex));

	if ((new = kmem_zalloc(sizeof (*new), sleep)) == NULL) {
		return (FC_FAILURE);
	}

	mutex_enter(&fctl_nwwn_hash_mutex);
	new->fne_nodep = rnodep;

	mutex_enter(&rnodep->fd_mutex);
	ASSERT(fctl_is_wwn_zero(&rnodep->fd_node_name) == FC_FAILURE);
	index = HASH_FUNC(WWN_HASH_KEY(rnodep->fd_node_name.raw_wwn),
	    fctl_nwwn_table_size);
	mutex_exit(&rnodep->fd_mutex);

	head = &fctl_nwwn_hash_table[index];

	/* Link it in at the head of the hash list */
	new->fne_nextp = head->fnl_headp;
	head->fnl_headp = new;

	mutex_exit(&fctl_nwwn_hash_mutex);

	return (FC_SUCCESS);
}


/*
 * Remove the given fc_remote_node_t from the global fctl_nwwn_hash_table[].
 * This uses the nwwn in the fd_node_name.raw_wwn of the given struct.
 */
void
fctl_delist_nwwn_table(fc_remote_node_t *rnodep)
{
	int			index;
	fctl_nwwn_list_t	*head;
	fctl_nwwn_elem_t	*elem;
	fctl_nwwn_elem_t	*prev;

	ASSERT(MUTEX_HELD(&fctl_nwwn_hash_mutex));
	ASSERT(MUTEX_HELD(&rnodep->fd_mutex));

	index = HASH_FUNC(WWN_HASH_KEY(rnodep->fd_node_name.raw_wwn),
	    fctl_nwwn_table_size);

	head = &fctl_nwwn_hash_table[index];
	elem = head->fnl_headp;
	prev = NULL;

	while (elem != NULL) {
		if (elem->fne_nodep == rnodep) {
			/*
			 * Found it -- unlink it from the list & decrement
			 * the count for the hash chain.
			 */
			if (prev == NULL) {
				head->fnl_headp = elem->fne_nextp;
			} else {
				prev->fne_nextp = elem->fne_nextp;
			}
			break;
		}
		prev = elem;
		elem = elem->fne_nextp;
	}

	if (elem != NULL) {
		kmem_free(elem, sizeof (*elem));
	}
}


/*
 * Returns a reference to an fc_remote_node_t struct for the given node_wwn.
 * Looks in the global fctl_nwwn_hash_table[]. Identical to the
 * fctl_lock_remote_node_by_nwwn() function, except that this does NOT increment
 * the fc_count reference count in the f_device_t before returning.
 *
 * This function is called by: fctl_create_remote_port_t().
 *
 * OLD COMMENT:
 * Note: The calling thread needs to make sure it isn't holding any device
 * mutex (more so the fc_remote_node_t that could potentially have this wwn).
 */
fc_remote_node_t *
fctl_get_remote_node_by_nwwn(la_wwn_t *node_wwn)
{
	int			index;
	fctl_nwwn_elem_t	*elem;
	fc_remote_node_t	*next;
	fc_remote_node_t	*rnodep = NULL;

	index = HASH_FUNC(WWN_HASH_KEY(node_wwn->raw_wwn),
	    fctl_nwwn_table_size);
	ASSERT(index >= 0 && index < fctl_nwwn_table_size);

	mutex_enter(&fctl_nwwn_hash_mutex);
	elem = fctl_nwwn_hash_table[index].fnl_headp;
	while (elem != NULL) {
		next = elem->fne_nodep;
		if (next != NULL) {
			mutex_enter(&next->fd_mutex);
			if (fctl_wwn_cmp(node_wwn, &next->fd_node_name) == 0) {
				rnodep = next;
				mutex_exit(&next->fd_mutex);
				break;
			}
			mutex_exit(&next->fd_mutex);
		}
		elem = elem->fne_nextp;
	}
	mutex_exit(&fctl_nwwn_hash_mutex);

	return (rnodep);
}


/*
 * Returns a reference to an fc_remote_node_t struct for the given node_wwn.
 * Looks in the global fctl_nwwn_hash_table[]. Increments the fd_numports
 * reference count in the f_device_t before returning.
 *
 * This function is only called by fctl_create_remote_port_t().
 */
fc_remote_node_t *
fctl_lock_remote_node_by_nwwn(la_wwn_t *node_wwn)
{
	int			index;
	fctl_nwwn_elem_t	*elem;
	fc_remote_node_t	*next;
	fc_remote_node_t	*rnodep = NULL;

	index = HASH_FUNC(WWN_HASH_KEY(node_wwn->raw_wwn),
	    fctl_nwwn_table_size);
	ASSERT(index >= 0 && index < fctl_nwwn_table_size);

	mutex_enter(&fctl_nwwn_hash_mutex);
	elem = fctl_nwwn_hash_table[index].fnl_headp;
	while (elem != NULL) {
		next = elem->fne_nodep;
		if (next != NULL) {
			mutex_enter(&next->fd_mutex);
			if (fctl_wwn_cmp(node_wwn, &next->fd_node_name) == 0) {
				rnodep = next;
				rnodep->fd_numports++;
				mutex_exit(&next->fd_mutex);
				break;
			}
			mutex_exit(&next->fd_mutex);
		}
		elem = elem->fne_nextp;
	}
	mutex_exit(&fctl_nwwn_hash_mutex);

	return (rnodep);
}


/*
 * Allocate and initialize an fc_remote_port_t struct & returns a pointer to
 * the newly allocated struct.	Only fails if the kmem_zalloc() fails.
 */
fc_remote_port_t *
fctl_alloc_remote_port(fc_local_port_t *port, la_wwn_t *port_wwn,
    uint32_t d_id, uchar_t recepient, int sleep)
{
	fc_remote_port_t *pd;

	ASSERT(MUTEX_HELD(&port->fp_mutex));
	ASSERT(FC_IS_REAL_DEVICE(d_id));

	if ((pd = kmem_zalloc(sizeof (*pd), sleep)) == NULL) {
		return (NULL);
	}
	fctl_tc_constructor(&pd->pd_logo_tc, FC_LOGO_TOLERANCE_LIMIT,
	    FC_LOGO_TOLERANCE_TIME_LIMIT);

	mutex_init(&pd->pd_mutex, NULL, MUTEX_DRIVER, NULL);

	pd->pd_port_id.port_id = d_id;
	pd->pd_port_name = *port_wwn;
	pd->pd_port = port;
	pd->pd_state = PORT_DEVICE_VALID;
	pd->pd_type = PORT_DEVICE_NEW;
	pd->pd_recepient = recepient;

	return (pd);
}


/*
 * Deconstruct and free the given fc_remote_port_t struct (unconditionally).
 */
void
fctl_dealloc_remote_port(fc_remote_port_t *pd)
{
	ASSERT(!MUTEX_HELD(&pd->pd_mutex));

	fctl_tc_destructor(&pd->pd_logo_tc);
	mutex_destroy(&pd->pd_mutex);
	kmem_free(pd, sizeof (*pd));
}

/*
 * Add the given fc_remote_port_t onto the linked list of remote port
 * devices associated with the given fc_remote_node_t. Does NOT add the
 * fc_remote_port_t to the list if already exists on the list.
 */
void
fctl_link_remote_port_to_remote_node(fc_remote_node_t *rnodep,
    fc_remote_port_t *pd)
{
	fc_remote_port_t *last;
	fc_remote_port_t *ports;

	mutex_enter(&rnodep->fd_mutex);

	last = NULL;
	for (ports = rnodep->fd_portlistp; ports != NULL;
	    ports = ports->pd_port_next) {
		if (ports == pd) {
			/*
			 * The given fc_remote_port_t is already on the linked
			 * list chain for the given remote node, so bail now.
			 */
			mutex_exit(&rnodep->fd_mutex);
			return;
		}
		last = ports;
	}

	/* Add the fc_remote_port_t to the tail of the linked list */
	if (last != NULL) {
		last->pd_port_next = pd;
	} else {
		rnodep->fd_portlistp = pd;
	}
	pd->pd_port_next = NULL;

	/*
	 * Link the fc_remote_port_t back to the associated fc_remote_node_t.
	 */
	mutex_enter(&pd->pd_mutex);
	pd->pd_remote_nodep = rnodep;
	mutex_exit(&pd->pd_mutex);

	mutex_exit(&rnodep->fd_mutex);
}


/*
 * Remove the specified fc_remote_port_t from the linked list of remote ports
 * for the given fc_remote_node_t.
 *
 * Returns a count of the _remaining_ fc_remote_port_t structs on the linked
 * list of the fc_remote_node_t.
 *
 * The fd_numports on the given fc_remote_node_t is decremented, and if
 * it hits zero then this function also removes the fc_remote_node_t from the
 * global fctl_nwwn_hash_table[]. This appears to be the ONLY WAY that entries
 * are removed from the fctl_nwwn_hash_table[].
 */
int
fctl_unlink_remote_port_from_remote_node(fc_remote_node_t *rnodep,
    fc_remote_port_t *pd)
{
	int			rcount = 0;
	fc_remote_port_t	*last;
	fc_remote_port_t	*ports;

	ASSERT(!MUTEX_HELD(&rnodep->fd_mutex));
	ASSERT(!MUTEX_HELD(&pd->pd_mutex));

	last = NULL;

	mutex_enter(&fctl_nwwn_hash_mutex);

	mutex_enter(&rnodep->fd_mutex);

	/*
	 * Go thru the linked list of fc_remote_port_t structs for the given
	 * fc_remote_node_t; try to find the specified fc_remote_port_t (pd).
	 */
	ports = rnodep->fd_portlistp;
	while (ports != NULL) {
		if (ports == pd) {
			break;	/* Found the requested fc_remote_port_t */
		}
		last = ports;
		ports = ports->pd_port_next;
	}

	if (ports) {
		rcount = --rnodep->fd_numports;
		if (rcount == 0) {
			/* Note: this is only ever called from here */
			fctl_delist_nwwn_table(rnodep);
		}
		if (last) {
			last->pd_port_next = pd->pd_port_next;
		} else {
			rnodep->fd_portlistp = pd->pd_port_next;
		}
		mutex_enter(&pd->pd_mutex);
		pd->pd_remote_nodep = NULL;
		mutex_exit(&pd->pd_mutex);
	}

	pd->pd_port_next = NULL;

	mutex_exit(&rnodep->fd_mutex);
	mutex_exit(&fctl_nwwn_hash_mutex);

	return (rcount);
}


/*
 * Add the given fc_remote_port_t struct to the d_id table in the given
 * fc_local_port_t struct.  Hashes based upon the pd->pd_port_id.port_id in the
 * fc_remote_port_t.
 *
 * No memory allocs are required, so this never fails, but it does use the
 * (pd->pd_aux_flags & PD_IN_DID_QUEUE) to keep duplicates off the list.
 * (There does not seem to be a way to tell the caller that a duplicate
 * exists.)
 */
void
fctl_enlist_did_table(fc_local_port_t *port, fc_remote_port_t *pd)
{
	struct d_id_hash *head;

	ASSERT(MUTEX_HELD(&port->fp_mutex));
	ASSERT(MUTEX_HELD(&pd->pd_mutex));

	if (pd->pd_aux_flags & PD_IN_DID_QUEUE) {
		return;
	}

	head = &port->fp_did_table[D_ID_HASH_FUNC(pd->pd_port_id.port_id,
	    did_table_size)];

#ifdef	DEBUG
	{
		int			index;
		fc_remote_port_t	*tmp_pd;
		struct d_id_hash	*tmp_head;

		/*
		 * Search down in each bucket for a duplicate pd
		 * Also search for duplicate D_IDs
		 * This DEBUG code will force an ASSERT if a duplicate
		 * is ever found.
		 */
		for (index = 0; index < did_table_size; index++) {
			tmp_head = &port->fp_did_table[index];

			tmp_pd = tmp_head->d_id_head;
			while (tmp_pd != NULL) {
				ASSERT(tmp_pd != pd);

				if (tmp_pd->pd_state != PORT_DEVICE_INVALID &&
				    tmp_pd->pd_type != PORT_DEVICE_OLD) {
					ASSERT(tmp_pd->pd_port_id.port_id !=
					    pd->pd_port_id.port_id);
				}

				tmp_pd = tmp_pd->pd_did_hnext;
			}
		}
	}

	bzero(pd->pd_d_stack, sizeof (pd->pd_d_stack));
	pd->pd_d_depth = getpcstack(pd->pd_d_stack, FC_STACK_DEPTH);
#endif

	pd->pd_did_hnext = head->d_id_head;
	head->d_id_head = pd;

	pd->pd_aux_flags |= PD_IN_DID_QUEUE;
	head->d_id_count++;
}


/*
 * Remove the given fc_remote_port_t struct from the d_id table in the given
 * fc_local_port_t struct.  Hashes based upon the pd->pd_port_id.port_id in the
 * fc_remote_port_t.
 *
 * Does nothing if the requested fc_remote_port_t was not found.
 */
void
fctl_delist_did_table(fc_local_port_t *port, fc_remote_port_t *pd)
{
	uint32_t		d_id;
	struct d_id_hash	*head;
	fc_remote_port_t	*pd_next;
	fc_remote_port_t	*last;

	ASSERT(MUTEX_HELD(&port->fp_mutex));
	ASSERT(MUTEX_HELD(&pd->pd_mutex));

	d_id = pd->pd_port_id.port_id;
	head = &port->fp_did_table[D_ID_HASH_FUNC(d_id, did_table_size)];

	pd_next = head->d_id_head;
	last = NULL;
	while (pd_next != NULL) {
		if (pd == pd_next) {
			break;	/* Found the given fc_remote_port_t */
		}
		last = pd_next;
		pd_next = pd_next->pd_did_hnext;
	}

	if (pd_next) {
		/*
		 * Found the given fc_remote_port_t; now remove it from the
		 * d_id list.
		 */
		head->d_id_count--;
		if (last == NULL) {
			head->d_id_head = pd->pd_did_hnext;
		} else {
			last->pd_did_hnext = pd->pd_did_hnext;
		}
		pd->pd_aux_flags &= ~PD_IN_DID_QUEUE;
		pd->pd_did_hnext = NULL;
	}
}


/*
 * Add the given fc_remote_port_t struct to the pwwn table in the given
 * fc_local_port_t struct.  Hashes based upon the pd->pd_port_name.raw_wwn
 * in the fc_remote_port_t.
 *
 * No memory allocs are required, so this never fails.
 */
void
fctl_enlist_pwwn_table(fc_local_port_t *port, fc_remote_port_t *pd)
{
	int index;
	struct pwwn_hash *head;

	ASSERT(MUTEX_HELD(&port->fp_mutex));
	ASSERT(MUTEX_HELD(&pd->pd_mutex));

	ASSERT(fctl_is_wwn_zero(&pd->pd_port_name) == FC_FAILURE);

	index = HASH_FUNC(WWN_HASH_KEY(pd->pd_port_name.raw_wwn),
	    pwwn_table_size);

	head = &port->fp_pwwn_table[index];

#ifdef	DEBUG
	{
		int			index;
		fc_remote_port_t	*tmp_pd;
		struct pwwn_hash	*tmp_head;

		/*
		 * Search down in each bucket for a duplicate pd
		 * Search also for a duplicate WWN
		 * Throw an ASSERT if any duplicate is found.
		 */
		for (index = 0; index < pwwn_table_size; index++) {
			tmp_head = &port->fp_pwwn_table[index];

			tmp_pd = tmp_head->pwwn_head;
			while (tmp_pd != NULL) {
				ASSERT(tmp_pd != pd);

				if (tmp_pd->pd_state != PORT_DEVICE_INVALID &&
				    tmp_pd->pd_type != PORT_DEVICE_OLD) {
					ASSERT(fctl_wwn_cmp(
					    &tmp_pd->pd_port_name,
					    &pd->pd_port_name) != 0);
				}

				tmp_pd = tmp_pd->pd_wwn_hnext;
			}
		}
	}

	bzero(pd->pd_w_stack, sizeof (pd->pd_w_stack));
	pd->pd_w_depth = getpcstack(pd->pd_w_stack, FC_STACK_DEPTH);
#endif /* DEBUG */

	pd->pd_wwn_hnext = head->pwwn_head;
	head->pwwn_head = pd;

	head->pwwn_count++;
	/*
	 * Make sure we tie fp_dev_count to the size of the
	 * pwwn_table
	 */
	port->fp_dev_count++;
}


/*
 * Remove the given fc_remote_port_t struct from the pwwn table in the given
 * fc_local_port_t struct.  Hashes based upon the pd->pd_port_name.raw_wwn
 * in the fc_remote_port_t.
 *
 * Does nothing if the requested fc_remote_port_t was not found.
 */
void
fctl_delist_pwwn_table(fc_local_port_t *port, fc_remote_port_t *pd)
{
	int			index;
	la_wwn_t		pwwn;
	struct pwwn_hash	*head;
	fc_remote_port_t	*pd_next;
	fc_remote_port_t	*last;

	ASSERT(MUTEX_HELD(&port->fp_mutex));
	ASSERT(MUTEX_HELD(&pd->pd_mutex));

	pwwn = pd->pd_port_name;
	index = HASH_FUNC(WWN_HASH_KEY(pwwn.raw_wwn), pwwn_table_size);

	head = &port->fp_pwwn_table[index];

	last = NULL;
	pd_next = head->pwwn_head;
	while (pd_next != NULL) {
		if (pd_next == pd) {
			break;	/* Found the given fc_remote_port_t */
		}
		last = pd_next;
		pd_next = pd_next->pd_wwn_hnext;
	}

	if (pd_next) {
		/*
		 * Found the given fc_remote_port_t; now remove it from the
		 * pwwn list.
		 */
		head->pwwn_count--;
		/*
		 * Make sure we tie fp_dev_count to the size of the
		 * pwwn_table
		 */
		port->fp_dev_count--;
		if (last == NULL) {
			head->pwwn_head = pd->pd_wwn_hnext;
		} else {
			last->pd_wwn_hnext = pd->pd_wwn_hnext;
		}
		pd->pd_wwn_hnext = NULL;
	}
}


/*
 * Looks in the d_id table of the specified fc_local_port_t for the
 * fc_remote_port_t that matches the given d_id.  Hashes based upon
 * the given d_id.
 * Returns a pointer to the fc_remote_port_t struct, but does not update any
 * reference counts or otherwise indicate that the fc_remote_port_t is in
 * use.
 */
fc_remote_port_t *
fctl_get_remote_port_by_did(fc_local_port_t *port, uint32_t d_id)
{
	struct d_id_hash	*head;
	fc_remote_port_t	*pd;

	ASSERT(!MUTEX_HELD(&port->fp_mutex));

	mutex_enter(&port->fp_mutex);

	head = &port->fp_did_table[D_ID_HASH_FUNC(d_id, did_table_size)];

	pd = head->d_id_head;
	while (pd != NULL) {
		mutex_enter(&pd->pd_mutex);
		if (pd->pd_port_id.port_id == d_id) {
			/* Match found -- break out of the loop */
			mutex_exit(&pd->pd_mutex);
			break;
		}
		mutex_exit(&pd->pd_mutex);
		pd = pd->pd_did_hnext;
	}

	mutex_exit(&port->fp_mutex);

	return (pd);
}


#ifndef	__lock_lint		/* uncomment when there is a consumer */

void
fc_ulp_hold_remote_port(opaque_t port_handle)
{
	fc_remote_port_t *pd = port_handle;

	mutex_enter(&pd->pd_mutex);
	pd->pd_ref_count++;
	mutex_exit(&pd->pd_mutex);
}

/*
 * Looks in the d_id table of the specified fc_local_port_t for the
 * fc_remote_port_t that matches the given d_id.  Hashes based upon
 * the given d_id. Returns a pointer to the fc_remote_port_t struct.
 *
 * Increments pd_ref_count in the fc_remote_port_t if the
 * fc_remote_port_t is found at the given d_id.
 *
 * The fc_remote_port_t is ignored (treated as non-existent) if either
 * its pd_state == PORT_DEVICE_INVALID _OR_ its pd_type == PORT_DEVICE_OLD.
 */
fc_remote_port_t *
fctl_hold_remote_port_by_did(fc_local_port_t *port, uint32_t d_id)
{
	struct d_id_hash	*head;
	fc_remote_port_t	*pd;

	ASSERT(!MUTEX_HELD(&port->fp_mutex));

	mutex_enter(&port->fp_mutex);

	head = &port->fp_did_table[D_ID_HASH_FUNC(d_id, did_table_size)];

	pd = head->d_id_head;
	while (pd != NULL) {
		mutex_enter(&pd->pd_mutex);
		if (pd->pd_port_id.port_id == d_id && pd->pd_state !=
		    PORT_DEVICE_INVALID && pd->pd_type != PORT_DEVICE_OLD) {
			ASSERT(pd->pd_ref_count >= 0);
			pd->pd_ref_count++;
			mutex_exit(&pd->pd_mutex);
			break;
		}
		mutex_exit(&pd->pd_mutex);
		pd = pd->pd_did_hnext;
	}

	mutex_exit(&port->fp_mutex);

	return (pd);
}

#endif /* __lock_lint */

/*
 * Looks in the pwwn table of the specified fc_local_port_t for the
 * fc_remote_port_t that matches the given pwwn.  Hashes based upon the
 * given pwwn->raw_wwn. Returns a pointer to the fc_remote_port_t struct,
 * but does not update any reference counts or otherwise indicate that
 * the fc_remote_port_t is in use.
 */
fc_remote_port_t *
fctl_get_remote_port_by_pwwn(fc_local_port_t *port, la_wwn_t *pwwn)
{
	int			index;
	struct pwwn_hash	*head;
	fc_remote_port_t	*pd;

	ASSERT(!MUTEX_HELD(&port->fp_mutex));

	mutex_enter(&port->fp_mutex);

	index = HASH_FUNC(WWN_HASH_KEY(pwwn->raw_wwn), pwwn_table_size);
	head = &port->fp_pwwn_table[index];

	pd = head->pwwn_head;
	while (pd != NULL) {
		mutex_enter(&pd->pd_mutex);
		if (fctl_wwn_cmp(&pd->pd_port_name, pwwn) == 0) {
			mutex_exit(&pd->pd_mutex);
			break;
		}
		mutex_exit(&pd->pd_mutex);
		pd = pd->pd_wwn_hnext;
	}

	mutex_exit(&port->fp_mutex);

	return (pd);
}


/*
 * Basically the same as fctl_get_remote_port_by_pwwn(), but requires that
 * the caller already hold the fp_mutex in the fc_local_port_t struct.
 */
fc_remote_port_t *
fctl_get_remote_port_by_pwwn_mutex_held(fc_local_port_t *port, la_wwn_t *pwwn)
{
	int			index;
	struct pwwn_hash	*head;
	fc_remote_port_t	*pd;

	ASSERT(MUTEX_HELD(&port->fp_mutex));

	index = HASH_FUNC(WWN_HASH_KEY(pwwn->raw_wwn), pwwn_table_size);
	head = &port->fp_pwwn_table[index];

	pd = head->pwwn_head;
	while (pd != NULL) {
		mutex_enter(&pd->pd_mutex);
		if (fctl_wwn_cmp(&pd->pd_port_name, pwwn) == 0) {
			mutex_exit(&pd->pd_mutex);
			break;
		}
		mutex_exit(&pd->pd_mutex);
		pd = pd->pd_wwn_hnext;
	}

	return (pd);
}


/*
 * Looks in the pwwn table of the specified fc_local_port_t for the
 * fc_remote_port_t that matches the given d_id.  Hashes based upon the
 * given pwwn->raw_wwn. Returns a pointer to the fc_remote_port_t struct.
 *
 * Increments pd_ref_count in the fc_remote_port_t if the
 * fc_remote_port_t is found at the given pwwn.
 *
 * The fc_remote_port_t is ignored (treated as non-existent) if either
 * its pd_state == PORT_DEVICE_INVALID _OR_ its pd_type == PORT_DEVICE_OLD.
 */
fc_remote_port_t *
fctl_hold_remote_port_by_pwwn(fc_local_port_t *port, la_wwn_t *pwwn)
{
	int			index;
	struct pwwn_hash	*head;
	fc_remote_port_t	*pd;

	ASSERT(!MUTEX_HELD(&port->fp_mutex));

	mutex_enter(&port->fp_mutex);

	index = HASH_FUNC(WWN_HASH_KEY(pwwn->raw_wwn), pwwn_table_size);
	head = &port->fp_pwwn_table[index];

	pd = head->pwwn_head;
	while (pd != NULL) {
		mutex_enter(&pd->pd_mutex);
		if (fctl_wwn_cmp(&pd->pd_port_name, pwwn) == 0 &&
		    pd->pd_state != PORT_DEVICE_INVALID &&
		    pd->pd_type != PORT_DEVICE_OLD) {
			ASSERT(pd->pd_ref_count >= 0);
			pd->pd_ref_count++;
			mutex_exit(&pd->pd_mutex);
			break;
		}
		mutex_exit(&pd->pd_mutex);
		pd = pd->pd_wwn_hnext;
	}

	mutex_exit(&port->fp_mutex);

	return (pd);
}


/*
 * Unconditionally decrement pd_ref_count in the given fc_remote_port_t
 * struct.
 *
 * If pd_ref_count reaches zero, then this function will see if the
 * fc_remote_port_t has been marked for deallocation. If so (and also if there
 * are no other potential operations in progress, as indicated by the
 * PD_ELS_IN_PROGRESS & PD_ELS_MARK settings in the pd_flags), then
 * fctl_destroy_remote_port_t() is called to deconstruct/free the given
 * fc_remote_port_t (which will also remove it from the d_id and pwwn tables
 * on the associated fc_local_port_t).	If the associated fc_remote_node_t is no
 * longer in use, then it too is deconstructed/freed.
 */
void
fctl_release_remote_port(fc_remote_port_t *pd)
{
	int			remove = 0;
	fc_remote_node_t	*node;
	fc_local_port_t		*port;

	mutex_enter(&pd->pd_mutex);
	port = pd->pd_port;

	ASSERT(pd->pd_ref_count > 0);
	pd->pd_ref_count--;
	if (pd->pd_ref_count == 0 &&
	    (pd->pd_aux_flags & PD_NEEDS_REMOVAL) &&
	    (pd->pd_flags != PD_ELS_IN_PROGRESS) &&
	    (pd->pd_flags != PD_ELS_MARK)) {
		remove = 1;
		pd->pd_aux_flags &= ~PD_NEEDS_REMOVAL;
	}
	node = pd->pd_remote_nodep;
	ASSERT(node != NULL);

	mutex_exit(&pd->pd_mutex);

	if (remove) {
		/*
		 * The fc_remote_port_t struct has to go away now, so call the
		 * cleanup function to get it off the various lists and remove
		 * references to it in any other associated structs.
		 */
		if (fctl_destroy_remote_port(port, pd) == 0) {
			/*
			 * No more fc_remote_port_t references found in the
			 * associated fc_remote_node_t, so deallocate the
			 * fc_remote_node_t (if it even exists).
			 */
			if (node) {
				fctl_destroy_remote_node(node);
			}
		}
	}
}


void
fctl_fillout_map(fc_local_port_t *port, fc_portmap_t **map, uint32_t *len,
    int whole_map, int justcopy, int orphan)
{
	int			index;
	int			listlen;
	int			full_list;
	int			initiator;
	uint32_t		topology;
	struct pwwn_hash	*head;
	fc_remote_port_t	*pd;
	fc_remote_port_t	*old_pd;
	fc_remote_port_t	*last_pd;
	fc_portmap_t		*listptr;

	ASSERT(!MUTEX_HELD(&port->fp_mutex));

	mutex_enter(&port->fp_mutex);

	topology = port->fp_topology;

	if (orphan) {
		ASSERT(!FC_IS_TOP_SWITCH(topology));
	}

	for (full_list = listlen = index = 0;
	    index < pwwn_table_size; index++) {
		head = &port->fp_pwwn_table[index];
		pd = head->pwwn_head;
		while (pd != NULL) {
			full_list++;
			mutex_enter(&pd->pd_mutex);
			if (pd->pd_type != PORT_DEVICE_NOCHANGE) {
				listlen++;
			}
			mutex_exit(&pd->pd_mutex);
			pd = pd->pd_wwn_hnext;
		}
	}

	if (whole_map == 0) {
		if (listlen == 0 && *len == 0) {
			*map = NULL;
			*len = listlen;
			mutex_exit(&port->fp_mutex);
			return;
		}
	} else {
		if (full_list == 0 && *len == 0) {
			*map = NULL;
			*len = full_list;
			mutex_exit(&port->fp_mutex);
			return;
		}
	}

	if (*len == 0) {
		ASSERT(*map == NULL);
		if (whole_map == 0) {
			listptr = *map = kmem_zalloc(
			    sizeof (*listptr) * listlen, KM_SLEEP);
			*len = listlen;
		} else {
			listptr = *map = kmem_zalloc(
			    sizeof (*listptr) * full_list, KM_SLEEP);
			*len = full_list;
		}
	} else {
		/*
		 * By design this routine mandates the callers to
		 * ask for a whole map when they specify the length
		 * and the listptr.
		 */
		ASSERT(whole_map == 1);
		if (*len < full_list) {
			*len = full_list;
			mutex_exit(&port->fp_mutex);
			return;
		}
		listptr = *map;
		*len = full_list;
	}

	for (index = 0; index < pwwn_table_size; index++) {
		head = &port->fp_pwwn_table[index];
		last_pd = NULL;
		pd = head->pwwn_head;
		while (pd != NULL) {
			mutex_enter(&pd->pd_mutex);
			if ((whole_map == 0 &&
			    pd->pd_type == PORT_DEVICE_NOCHANGE) ||
			    pd->pd_state == PORT_DEVICE_INVALID) {
				mutex_exit(&pd->pd_mutex);
				last_pd = pd;
				pd = pd->pd_wwn_hnext;
				continue;
			}
			mutex_exit(&pd->pd_mutex);

			fctl_copy_portmap(listptr, pd);

			if (justcopy) {
				last_pd = pd;
				pd = pd->pd_wwn_hnext;
				listptr++;
				continue;
			}

			mutex_enter(&pd->pd_mutex);
			ASSERT(pd->pd_state != PORT_DEVICE_INVALID);
			if (pd->pd_type == PORT_DEVICE_OLD) {
				listptr->map_pd = pd;
				listptr->map_state = pd->pd_state =
				    PORT_DEVICE_INVALID;
				/*
				 * Remove this from the PWWN hash table.
				 */
				old_pd = pd;
				pd = old_pd->pd_wwn_hnext;

				if (last_pd == NULL) {
					ASSERT(old_pd == head->pwwn_head);

					head->pwwn_head = pd;
				} else {
					last_pd->pd_wwn_hnext = pd;
				}
				head->pwwn_count--;
				/*
				 * Make sure we tie fp_dev_count to the size
				 * of the pwwn_table
				 */
				port->fp_dev_count--;
				old_pd->pd_wwn_hnext = NULL;

				if (port->fp_topology == FC_TOP_PRIVATE_LOOP &&
				    port->fp_statec_busy && !orphan) {
					fctl_check_alpa_list(port, old_pd);
				}

				/*
				 * Remove if the port device has stealthily
				 * present in the D_ID hash table
				 */
				fctl_delist_did_table(port, old_pd);

				ASSERT(old_pd->pd_remote_nodep != NULL);

				initiator = (old_pd->pd_recepient ==
				    PD_PLOGI_INITIATOR) ? 1 : 0;

				mutex_exit(&old_pd->pd_mutex);
				mutex_exit(&port->fp_mutex);

				if (orphan) {
					fctl_print_if_not_orphan(port, old_pd);

					(void) fctl_add_orphan(port, old_pd,
					    KM_NOSLEEP);
				}

				if (FC_IS_TOP_SWITCH(topology) && initiator) {
					(void) fctl_add_orphan(port, old_pd,
					    KM_NOSLEEP);
				}
				mutex_enter(&port->fp_mutex);
			} else {
				listptr->map_pd = pd;
				pd->pd_type = PORT_DEVICE_NOCHANGE;
				mutex_exit(&pd->pd_mutex);
				last_pd = pd;
				pd = pd->pd_wwn_hnext;
			}
			listptr++;
		}
	}
	mutex_exit(&port->fp_mutex);
}


job_request_t *
fctl_alloc_job(int job_code, int job_flags, void (*comp) (opaque_t, uchar_t),
    opaque_t arg, int sleep)
{
	job_request_t *job;

	job = (job_request_t *)kmem_cache_alloc(fctl_job_cache, sleep);
	if (job != NULL) {
		job->job_result = FC_SUCCESS;
		job->job_code = job_code;
		job->job_flags = job_flags;
		job->job_cb_arg = arg;
		job->job_comp = comp;
		job->job_private = NULL;
		job->job_ulp_pkts = NULL;
		job->job_ulp_listlen = 0;
#ifndef __lock_lint
		job->job_counter = 0;
		job->job_next = NULL;
#endif /* __lock_lint */
	}

	return (job);
}


void
fctl_dealloc_job(job_request_t *job)
{
	kmem_cache_free(fctl_job_cache, (void *)job);
}


void
fctl_enque_job(fc_local_port_t *port, job_request_t *job)
{
	ASSERT(!MUTEX_HELD(&port->fp_mutex));

	mutex_enter(&port->fp_mutex);

	if (port->fp_job_tail == NULL) {
		ASSERT(port->fp_job_head == NULL);
		port->fp_job_head = port->fp_job_tail = job;
	} else {
		port->fp_job_tail->job_next = job;
		port->fp_job_tail = job;
	}
	job->job_next = NULL;

	cv_signal(&port->fp_cv);
	mutex_exit(&port->fp_mutex);
}


job_request_t *
fctl_deque_job(fc_local_port_t *port)
{
	job_request_t *job;

	ASSERT(MUTEX_HELD(&port->fp_mutex));

	if (port->fp_job_head == NULL) {
		ASSERT(port->fp_job_tail == NULL);
		job = NULL;
	} else {
		job = port->fp_job_head;
		if (job->job_next == NULL) {
			ASSERT(job == port->fp_job_tail);
			port->fp_job_tail = NULL;
		}
		port->fp_job_head = job->job_next;
	}

	return (job);
}


void
fctl_priority_enque_job(fc_local_port_t *port, job_request_t *job)
{
	ASSERT(!MUTEX_HELD(&port->fp_mutex));

	mutex_enter(&port->fp_mutex);
	if (port->fp_job_tail == NULL) {
		ASSERT(port->fp_job_head == NULL);
		port->fp_job_head = port->fp_job_tail = job;
		job->job_next = NULL;
	} else {
		job->job_next = port->fp_job_head;
		port->fp_job_head = job;
	}
	cv_signal(&port->fp_cv);
	mutex_exit(&port->fp_mutex);
}


void
fctl_jobwait(job_request_t *job)
{
	ASSERT(!(job->job_flags & JOB_TYPE_FCTL_ASYNC));
	sema_p(&job->job_fctl_sema);
	ASSERT(!MUTEX_HELD(&job->job_mutex));
}


void
fctl_jobdone(job_request_t *job)
{
	if (job->job_flags & JOB_TYPE_FCTL_ASYNC) {
		if (job->job_comp) {
			job->job_comp(job->job_cb_arg, job->job_result);
		}
		fctl_dealloc_job(job);
	} else {
		sema_v(&job->job_fctl_sema);
	}
}


/*
 * Compare two WWNs.
 * The NAA can't be omitted for comparison.
 *
 * Return Values:
 *   if src == dst return  0
 *   if src > dst  return  1
 *   if src < dst  return -1
 */
int
fctl_wwn_cmp(la_wwn_t *src, la_wwn_t *dst)
{
	uint8_t *l, *r;
	int i;
	uint64_t wl, wr;

	l = (uint8_t *)src;
	r = (uint8_t *)dst;

	for (i = 0, wl = 0; i < 8; i++) {
		wl <<= 8;
		wl |= l[i];
	}
	for (i = 0, wr = 0; i < 8; i++) {
		wr <<= 8;
		wr |= r[i];
	}

	if (wl > wr) {
		return (1);
	} else if (wl == wr) {
		return (0);
	} else {
		return (-1);
	}
}


/*
 * ASCII to Integer goodie with support for base 16, 10, 2 and 8
 */
int
fctl_atoi(char *s, int base)
{
	int val;
	int ch;

	for (val = 0; *s != '\0'; s++) {
		switch (base) {
		case 16:
			if (*s >= '0' && *s <= '9') {
				ch = *s - '0';
			} else if (*s >= 'a' && *s <= 'f') {
				ch = *s - 'a' + 10;
			} else if (*s >= 'A' && *s <= 'F') {
				ch = *s - 'A' + 10;
			} else {
				return (-1);
			}
			break;

		case 10:
			if (*s < '0' || *s > '9') {
				return (-1);
			}
			ch = *s - '0';
			break;

		case 2:
			if (*s < '0' || *s > '1') {
				return (-1);
			}
			ch = *s - '0';
			break;

		case 8:
			if (*s < '0' || *s > '7') {
				return (-1);
			}
			ch = *s - '0';
			break;

		default:
			return (-1);
		}
		val = (val * base) + ch;
	}
	return (val);
}


/*
 * Create the fc_remote_port_t struct for the given port_wwn and d_id.
 *
 * If the struct already exists (and is "valid"), then use it. Before using
 * it, the code below also checks: (a) if the d_id has changed, and (b) if
 * the device is maked as PORT_DEVICE_OLD.
 *
 * If no fc_remote_node_t struct exists for the given node_wwn, then that
 * struct is also created (and linked with the fc_remote_port_t).
 *
 * The given fc_local_port_t struct is updated with the info on the new
 * struct(s). The d_id and pwwn hash tables in the port_wwn are updated.
 * The global node_hash_table[] is updated (if necessary).
 */
fc_remote_port_t *
fctl_create_remote_port(fc_local_port_t *port, la_wwn_t *node_wwn,
    la_wwn_t *port_wwn, uint32_t d_id, uchar_t recepient, int sleep)
{
	int			invalid = 0;
	fc_remote_node_t	*rnodep;
	fc_remote_port_t	*pd;

	rnodep = fctl_get_remote_node_by_nwwn(node_wwn);
	if (rnodep) {
		/*
		 * We found an fc_remote_node_t for the remote node -- see if
		 * anyone has marked it as going away or gone.
		 */
		mutex_enter(&rnodep->fd_mutex);
		invalid = (rnodep->fd_flags == FC_REMOTE_NODE_INVALID) ? 1 : 0;
		mutex_exit(&rnodep->fd_mutex);
	}
	if (rnodep == NULL || invalid) {
		/*
		 * No valid remote node struct found -- create it.
		 * Note: this is the only place that this func is called.
		 */
		rnodep = fctl_create_remote_node(node_wwn, sleep);
		if (rnodep == NULL) {
			return (NULL);
		}
	}

	mutex_enter(&port->fp_mutex);

	/*
	 * See if there already is an fc_remote_port_t struct in existence
	 * on the specified fc_local_port_t for the given pwwn.	 If so, then
	 * grab a reference to it. The 'held' here just means that fp_mutex
	 * is held by the caller -- no reference counts are updated.
	 */
	pd = fctl_get_remote_port_by_pwwn_mutex_held(port, port_wwn);
	if (pd) {
		/*
		 * An fc_remote_port_t struct was found -- see if anyone has
		 * marked it as "invalid", which means that it is in the
		 * process of going away & we don't want to use it.
		 */
		mutex_enter(&pd->pd_mutex);
		invalid = (pd->pd_state == PORT_DEVICE_INVALID) ? 1 : 0;
		mutex_exit(&pd->pd_mutex);
	}

	if (pd == NULL || invalid) {
		/*
		 * No fc_remote_port_t was found (or the existing one is
		 * marked as "invalid".) Allocate a new one and use that.
		 * This call will also update the d_id and pwwn hash tables
		 * in the given fc_local_port_t struct with the newly allocated
		 * fc_remote_port_t.
		 */
		if ((pd = fctl_alloc_remote_port(port, port_wwn, d_id,
		    recepient, sleep)) == NULL) {
			/* Just give up if the allocation fails. */
			mutex_exit(&port->fp_mutex);
			fctl_destroy_remote_node(rnodep);
			return (pd);
		}

		/*
		 * Add the new fc_remote_port_t struct to the d_id and pwwn
		 * hash tables on the associated fc_local_port_t struct.
		 */
		mutex_enter(&pd->pd_mutex);
		pd->pd_remote_nodep = rnodep;
		fctl_enlist_did_table(port, pd);
		fctl_enlist_pwwn_table(port, pd);
		mutex_exit(&pd->pd_mutex);
		mutex_exit(&port->fp_mutex);

		/*
		 * Retrieve a pointer to the fc_remote_node_t (i.e., remote
		 * node) specified by the given node_wwn.  This looks in the
		 * global fctl_nwwn_hash_table[]. The fd_numports reference
		 * count in the fc_remote_node_t struct is incremented.
		 */
		rnodep = fctl_lock_remote_node_by_nwwn(node_wwn);

	} else {
		/*
		 * An existing and valid fc_remote_port_t struct already
		 * exists on the fc_local_port_t for the given pwwn.
		 */

		mutex_enter(&pd->pd_mutex);
		ASSERT(pd->pd_remote_nodep != NULL);

		if (pd->pd_port_id.port_id != d_id) {
			/*
			 * A very unlikely occurance in a well
			 * behaved environment.
			 */

			/*
			 * The existing fc_remote_port_t has a different
			 * d_id than what we were given. This code will
			 * update the existing one with the one that was
			 * just given.
			 */
			char string[(FCTL_WWN_SIZE(port_wwn) << 1) + 1];
			uint32_t old_id;

			fc_wwn_to_str(port_wwn, string);

			old_id = pd->pd_port_id.port_id;

			fctl_delist_did_table(port, pd);

			cmn_err(CE_NOTE, "!fctl(%d): D_ID of a device"
			    " with PWWN %s changed. New D_ID = %x,"
			    " OLD D_ID = %x", port->fp_instance, string,
			    d_id, old_id);

			pd->pd_port_id.port_id = d_id;

			/*
			 * Looks like we have to presume here that the
			 * remote port could be something entirely different
			 * from what was previously existing & valid at this
			 * pwwn.
			 */
			pd->pd_type = PORT_DEVICE_CHANGED;

			/* Record (update) the new d_id for the remote port */
			fctl_enlist_did_table(port, pd);

		} else if (pd->pd_type == PORT_DEVICE_OLD) {
			/*
			 * OK at least the old & new d_id's match. So for
			 * PORT_DEVICE_OLD, this assumes that the remote
			 * port had disappeared but now has come back.
			 * Update the pd_type and pd_state to put the
			 * remote port back into service.
			 */
			pd->pd_type = PORT_DEVICE_NOCHANGE;
			pd->pd_state = PORT_DEVICE_VALID;

			fctl_enlist_did_table(port, pd);

		} else {
			/*
			 * OK the old & new d_id's match, and the remote
			 * port struct is not marked as PORT_DEVICE_OLD, so
			 * presume that it's still the same device and is
			 * still in good shape.	 Also this presumes that we
			 * do not need to update d_id or pwwn hash tables.
			 */
			/* sanitize device values */
			pd->pd_type = PORT_DEVICE_NOCHANGE;
			pd->pd_state = PORT_DEVICE_VALID;
		}

		mutex_exit(&pd->pd_mutex);
		mutex_exit(&port->fp_mutex);

		if (rnodep != pd->pd_remote_nodep) {
			if ((rnodep != NULL) &&
			    (fctl_wwn_cmp(&pd->pd_remote_nodep->fd_node_name,
			    node_wwn) != 0)) {
				/*
				 * Rut-roh, there is an fc_remote_node_t remote
				 * node struct for the given node_wwn, but the
				 * fc_remote_port_t remote port struct doesn't
				 * know about it.  This just prints a warning
				 * message & fails the fc_remote_port_t
				 * allocation (possible leak here?).
				 */
				char	ww1_name[17];
				char	ww2_name[17];

				fc_wwn_to_str(
				    &pd->pd_remote_nodep->fd_node_name,
				    ww1_name);
				fc_wwn_to_str(node_wwn, ww2_name);

				cmn_err(CE_WARN, "fctl(%d) NWWN Mismatch: "
				    "Expected %s Got %s", port->fp_instance,
				    ww1_name, ww2_name);
			}

			return (NULL);
		}
	}

	/*
	 * Add	the fc_remote_port_t onto the linked list of remote port
	 * devices associated with the given fc_remote_node_t (remote node).
	 */
	fctl_link_remote_port_to_remote_node(rnodep, pd);

	return (pd);
}


/*
 * Disassociate the given fc_local_port_t and fc_remote_port_t structs. Removes
 * the fc_remote_port_t from the associated fc_remote_node_t. Also removes any
 * references to the fc_remote_port_t from the d_id and pwwn tables in the
 * given fc_local_port_t.  Deallocates the given fc_remote_port_t.
 *
 * Returns a count of the number of remaining fc_remote_port_t structs
 * associated with the fc_remote_node_t struct.
 *
 * If pd_ref_count in the given fc_remote_port_t is nonzero, then this
 * function just sets the pd->pd_aux_flags |= PD_NEEDS_REMOVAL and the
 * pd->pd_type = PORT_DEVICE_OLD and lets some other function(s) worry about
 * the cleanup.	 The function then also returns '1'
 * instead of the actual number of remaining fc_remote_port_t structs
 *
 * If there are no more remote ports on the remote node, return 0.
 * Otherwise, return non-zero.
 */
int
fctl_destroy_remote_port(fc_local_port_t *port, fc_remote_port_t *pd)
{
	fc_remote_node_t	*rnodep;
	int			rcount = 0;

	mutex_enter(&pd->pd_mutex);

	/*
	 * If pd_ref_count > 0, we can't pull the rug out from any
	 * current users of this fc_remote_port_t.  We'll mark it as old
	 * and in need of removal.  The same goes for any fc_remote_port_t
	 * that has a reference handle(s) in a ULP(s) but for which the ULP(s)
	 * have not yet been notified that the handle is no longer valid
	 * (i.e., PD_GIVEN_TO_ULPS is set).
	 */
	if ((pd->pd_ref_count > 0) ||
	    (pd->pd_aux_flags & PD_GIVEN_TO_ULPS)) {
		pd->pd_aux_flags |= PD_NEEDS_REMOVAL;
		pd->pd_type = PORT_DEVICE_OLD;
		mutex_exit(&pd->pd_mutex);
		return (1);
	}

	pd->pd_type = PORT_DEVICE_OLD;

	rnodep = pd->pd_remote_nodep;

	mutex_exit(&pd->pd_mutex);

	if (rnodep != NULL) {
		/*
		 * Remove the fc_remote_port_t from the linked list of remote
		 * ports for the given fc_remote_node_t. This is only called
		 * here and in fctl_destroy_all_remote_ports().
		 */
		rcount = fctl_unlink_remote_port_from_remote_node(rnodep, pd);
	}

	mutex_enter(&port->fp_mutex);
	mutex_enter(&pd->pd_mutex);

	fctl_delist_did_table(port, pd);
	fctl_delist_pwwn_table(port, pd);

	mutex_exit(&pd->pd_mutex);

	/*
	 * Deconstruct & free the fc_remote_port_t. This is only called
	 * here and in fctl_destroy_all_remote_ports().
	 */
	fctl_dealloc_remote_port(pd);

	mutex_exit(&port->fp_mutex);

	return (rcount);
}


/*
 * This goes thru the d_id table on the given fc_local_port_t.
 * For each fc_remote_port_t found, this will:
 *
 *  - Remove the fc_remote_port_t from the linked list of remote ports for
 *    the associated fc_remote_node_t.	If the linked list goes empty, then this
 *    tries to deconstruct & free the fc_remote_node_t (that also removes the
 *    fc_remote_node_t from the global fctl_nwwn_hash_table[]).
 *
 *  - Remove the fc_remote_port_t from the pwwn list on the given
 *    fc_local_port_t.
 *
 *  - Deconstruct and free the fc_remote_port_t.
 *
 *  - Removes the link to the fc_remote_port_t in the d_id table. Note, this
 *    does not appear to correctle decrement the d_id_count tho.
 */
void
fctl_destroy_all_remote_ports(fc_local_port_t *port)
{
	int			index;
	fc_remote_port_t	*pd;
	fc_remote_node_t	*rnodep;
	struct d_id_hash	*head;

	mutex_enter(&port->fp_mutex);

	for (index = 0; index < did_table_size; index++) {

		head = &port->fp_did_table[index];

		while (head->d_id_head != NULL) {
			pd = head->d_id_head;

			/*
			 * See if this remote port (fc_remote_port_t) has a
			 * reference to a remote node (fc_remote_node_t) in its
			 * pd->pd_remote_nodep pointer.
			 */
			mutex_enter(&pd->pd_mutex);
			rnodep = pd->pd_remote_nodep;
			mutex_exit(&pd->pd_mutex);

			if (rnodep != NULL) {
				/*
				 * An fc_remote_node_t reference exists. Remove
				 * the fc_remote_port_t from the linked list of
				 * remote ports for fc_remote_node_t.
				 */
				if (fctl_unlink_remote_port_from_remote_node(
				    rnodep, pd) == 0) {
					/*
					 * The fd_numports reference count
					 * in the fc_remote_node_t has come
					 * back as zero, so we can free the
					 * fc_remote_node_t. This also means
					 * that the fc_remote_node_t was
					 * removed from the
					 * fctl_nwwn_hash_table[].
					 *
					 * This will silently skip the
					 * kmem_free() if either the
					 * fd_numports is nonzero or
					 * the fd_port is not NULL in
					 * the fc_remote_node_t.
					 */
					fctl_destroy_remote_node(rnodep);
				}
			}

			/*
			 * Clean up the entry in the fc_local_port_t's pwwn
			 * table for the given fc_remote_port_t (i.e., the pd).
			 */
			mutex_enter(&pd->pd_mutex);
			fctl_delist_pwwn_table(port, pd);
			pd->pd_aux_flags &= ~PD_IN_DID_QUEUE;
			mutex_exit(&pd->pd_mutex);

			/*
			 * Remove the current entry from the d_id list.
			 */
			head->d_id_head = pd->pd_did_hnext;

			/*
			 * Deconstruct & free the fc_remote_port_t (pd)
			 * Note: this is only called here and in
			 * fctl_destroy_remote_port_t().
			 */
			fctl_dealloc_remote_port(pd);
		}
	}

	mutex_exit(&port->fp_mutex);
}


int
fctl_is_wwn_zero(la_wwn_t *wwn)
{
	int count;

	for (count = 0; count < sizeof (la_wwn_t); count++) {
		if (wwn->raw_wwn[count] != 0) {
			return (FC_FAILURE);
		}
	}

	return (FC_SUCCESS);
}


void
fctl_ulp_unsol_cb(fc_local_port_t *port, fc_unsol_buf_t *buf, uchar_t type)
{
	int			data_cb;
	int			check_type;
	int			rval;
	uint32_t		claimed;
	fc_ulp_module_t		*mod;
	fc_ulp_ports_t		*ulp_port;

	claimed = 0;
	check_type = 1;

	switch ((buf->ub_frame.r_ctl) & R_CTL_ROUTING) {
	case R_CTL_DEVICE_DATA:
		data_cb = 1;
		break;

	case R_CTL_EXTENDED_SVC:
		check_type = 0;
		/* FALLTHROUGH */

	case R_CTL_FC4_SVC:
		data_cb = 0;
		break;

	default:
		mutex_enter(&port->fp_mutex);
		ASSERT(port->fp_active_ubs > 0);
		if (--(port->fp_active_ubs) == 0) {
			port->fp_soft_state &= ~FP_SOFT_IN_UNSOL_CB;
		}
		mutex_exit(&port->fp_mutex);
		port->fp_fca_tran->fca_ub_release(port->fp_fca_handle,
		    1, &buf->ub_token);
		return;
	}

	rw_enter(&fctl_ulp_lock, RW_READER);
	for (mod = fctl_ulp_modules; mod; mod = mod->mod_next) {
		if (check_type && mod->mod_info->ulp_type != type) {
			continue;
		}

		rw_enter(&fctl_mod_ports_lock, RW_READER);
		ulp_port = fctl_get_ulp_port(mod, port);
		rw_exit(&fctl_mod_ports_lock);

		if (ulp_port == NULL) {
			continue;
		}

		mutex_enter(&ulp_port->port_mutex);
		if (FCTL_DISALLOW_CALLBACKS(ulp_port->port_dstate)) {
			mutex_exit(&ulp_port->port_mutex);
			continue;
		}
		mutex_exit(&ulp_port->port_mutex);

		if (data_cb == 1) {
			rval = mod->mod_info->ulp_data_callback(
			    mod->mod_info->ulp_handle,
			    (opaque_t)port, buf, claimed);
		} else {
			rval = mod->mod_info->ulp_els_callback(
			    mod->mod_info->ulp_handle,
			    (opaque_t)port, buf, claimed);
		}

		if (rval == FC_SUCCESS && claimed == 0) {
			claimed = 1;
		}
	}
	rw_exit(&fctl_ulp_lock);

	if (claimed == 0) {
		/*
		 * We should actually RJT since nobody claimed it.
		 */
		mutex_enter(&port->fp_mutex);
		ASSERT(port->fp_active_ubs > 0);
		if (--(port->fp_active_ubs) == 0) {
			port->fp_soft_state &= ~FP_SOFT_IN_UNSOL_CB;
		}
		mutex_exit(&port->fp_mutex);
		port->fp_fca_tran->fca_ub_release(port->fp_fca_handle,
		    1, &buf->ub_token);

	} else {
		mutex_enter(&port->fp_mutex);
		if (--port->fp_active_ubs == 0) {
			port->fp_soft_state &= ~FP_SOFT_IN_UNSOL_CB;
		}
		mutex_exit(&port->fp_mutex);
	}
}


/*
 * Both fd_mutex and pd_mutex are held (in that order) coming in to this func
 *
 * With all these mutexes held, we should make sure this function does not eat
 * up much time.
 */
void
fctl_copy_portmap_held(fc_portmap_t *map, fc_remote_port_t *pd)
{
	fc_remote_node_t *node;

	ASSERT(MUTEX_HELD(&pd->pd_mutex));

	map->map_pwwn = pd->pd_port_name;
	map->map_did = pd->pd_port_id;
	map->map_hard_addr = pd->pd_hard_addr;
	map->map_state = pd->pd_state;
	map->map_type = pd->pd_type;
	map->map_flags = 0;

	ASSERT(map->map_type <= PORT_DEVICE_DELETE);

	bcopy(pd->pd_fc4types, map->map_fc4_types, sizeof (pd->pd_fc4types));

	node = pd->pd_remote_nodep;

	ASSERT(MUTEX_HELD(&node->fd_mutex));

	if (node) {
		map->map_nwwn = node->fd_node_name;
	}
	map->map_pd = pd;
}

void
fctl_copy_portmap(fc_portmap_t *map, fc_remote_port_t *pd)
{
	fc_remote_node_t *node;

	ASSERT(!MUTEX_HELD(&pd->pd_mutex));

	mutex_enter(&pd->pd_mutex);
	map->map_pwwn = pd->pd_port_name;
	map->map_did = pd->pd_port_id;
	map->map_hard_addr = pd->pd_hard_addr;
	map->map_state = pd->pd_state;
	map->map_type = pd->pd_type;
	map->map_flags = 0;

	ASSERT(map->map_type <= PORT_DEVICE_DELETE);

	bcopy(pd->pd_fc4types, map->map_fc4_types, sizeof (pd->pd_fc4types));

	node = pd->pd_remote_nodep;
	mutex_exit(&pd->pd_mutex);

	if (node) {
		mutex_enter(&node->fd_mutex);
		map->map_nwwn = node->fd_node_name;
		mutex_exit(&node->fd_mutex);
	}
	map->map_pd = pd;
}


static int
fctl_update_host_ns_values(fc_local_port_t *port, fc_ns_cmd_t *ns_req)
{
	int	rval = FC_SUCCESS;

	switch (ns_req->ns_cmd) {
	case NS_RFT_ID: {
		int		count;
		uint32_t	*src;
		uint32_t	*dst;
		ns_rfc_type_t	*rfc;

		rfc = (ns_rfc_type_t *)ns_req->ns_req_payload;

		mutex_enter(&port->fp_mutex);
		src = (uint32_t *)port->fp_fc4_types;
		dst = (uint32_t *)rfc->rfc_types;

		for (count = 0; count < 8; count++) {
			*src++ |= *dst++;
		}
		mutex_exit(&port->fp_mutex);

		break;
	}

	case NS_RSPN_ID: {
		ns_spn_t *spn;

		spn = (ns_spn_t *)ns_req->ns_req_payload;

		mutex_enter(&port->fp_mutex);
		port->fp_sym_port_namelen = spn->spn_len;
		if (spn->spn_len) {
			bcopy((caddr_t)spn + sizeof (ns_spn_t),
			    port->fp_sym_port_name, spn->spn_len);
		}
		mutex_exit(&port->fp_mutex);

		break;
	}

	case NS_RSNN_NN: {
		ns_snn_t *snn;

		snn = (ns_snn_t *)ns_req->ns_req_payload;

		mutex_enter(&port->fp_mutex);
		port->fp_sym_node_namelen = snn->snn_len;
		if (snn->snn_len) {
			bcopy((caddr_t)snn + sizeof (ns_snn_t),
			    port->fp_sym_node_name, snn->snn_len);
		}
		mutex_exit(&port->fp_mutex);

		break;
	}

	case NS_RIP_NN: {
		ns_rip_t *rip;

		rip = (ns_rip_t *)ns_req->ns_req_payload;

		mutex_enter(&port->fp_mutex);
		bcopy(rip->rip_ip_addr, port->fp_ip_addr,
		    sizeof (rip->rip_ip_addr));
		mutex_exit(&port->fp_mutex);

		break;
	}

	case NS_RIPA_NN: {
		ns_ipa_t *ipa;

		ipa = (ns_ipa_t *)ns_req->ns_req_payload;

		mutex_enter(&port->fp_mutex);
		bcopy(ipa->ipa_value, port->fp_ipa, sizeof (ipa->ipa_value));
		mutex_exit(&port->fp_mutex);

		break;
	}

	default:
		rval = FC_BADOBJECT;
		break;
	}

	return (rval);
}


static int
fctl_retrieve_host_ns_values(fc_local_port_t *port, fc_ns_cmd_t *ns_req)
{
	int	rval = FC_SUCCESS;

	switch (ns_req->ns_cmd) {
	case NS_GFT_ID: {
		ns_rfc_type_t *rfc;

		rfc = (ns_rfc_type_t *)ns_req->ns_resp_payload;

		mutex_enter(&port->fp_mutex);
		bcopy(port->fp_fc4_types, rfc->rfc_types,
		    sizeof (rfc->rfc_types));
		mutex_exit(&port->fp_mutex);
		break;
	}

	case NS_GSPN_ID: {
		ns_spn_t *spn;

		spn = (ns_spn_t *)ns_req->ns_resp_payload;

		mutex_enter(&port->fp_mutex);
		spn->spn_len = port->fp_sym_port_namelen;
		if (spn->spn_len) {
			bcopy(port->fp_sym_port_name, (caddr_t)spn +
			    sizeof (ns_spn_t), spn->spn_len);
		}
		mutex_exit(&port->fp_mutex);

		break;
	}

	case NS_GSNN_NN: {
		ns_snn_t *snn;

		snn = (ns_snn_t *)ns_req->ns_resp_payload;

		mutex_enter(&port->fp_mutex);
		snn->snn_len = port->fp_sym_node_namelen;
		if (snn->snn_len) {
			bcopy(port->fp_sym_node_name, (caddr_t)snn +
			    sizeof (ns_snn_t), snn->snn_len);
		}
		mutex_exit(&port->fp_mutex);

		break;
	}

	case NS_GIP_NN: {
		ns_rip_t *rip;

		rip = (ns_rip_t *)ns_req->ns_resp_payload;

		mutex_enter(&port->fp_mutex);
		bcopy(port->fp_ip_addr, rip->rip_ip_addr,
		    sizeof (rip->rip_ip_addr));
		mutex_exit(&port->fp_mutex);

		break;
	}

	case NS_GIPA_NN: {
		ns_ipa_t *ipa;

		ipa = (ns_ipa_t *)ns_req->ns_resp_payload;

		mutex_enter(&port->fp_mutex);
		bcopy(port->fp_ipa, ipa->ipa_value, sizeof (ipa->ipa_value));
		mutex_exit(&port->fp_mutex);

		break;
	}

	default:
		rval = FC_BADOBJECT;
		break;
	}

	return (rval);
}


fctl_ns_req_t *
fctl_alloc_ns_cmd(uint32_t cmd_len, uint32_t resp_len, uint32_t data_len,
    uint32_t ns_flags, int sleep)
{
	fctl_ns_req_t *ns_cmd;

	ns_cmd = kmem_zalloc(sizeof (*ns_cmd), sleep);
	if (ns_cmd == NULL) {
		return (NULL);
	}

	if (cmd_len) {
		ns_cmd->ns_cmd_buf = kmem_zalloc(cmd_len, sleep);
		if (ns_cmd->ns_cmd_buf == NULL) {
			kmem_free(ns_cmd, sizeof (*ns_cmd));
			return (NULL);
		}
		ns_cmd->ns_cmd_size = cmd_len;
	}

	ns_cmd->ns_resp_size = resp_len;

	if (data_len) {
		ns_cmd->ns_data_buf = kmem_zalloc(data_len, sleep);
		if (ns_cmd->ns_data_buf == NULL) {
			if (ns_cmd->ns_cmd_buf && cmd_len) {
				kmem_free(ns_cmd->ns_cmd_buf, cmd_len);
			}
			kmem_free(ns_cmd, sizeof (*ns_cmd));
			return (NULL);
		}
		ns_cmd->ns_data_len = data_len;
	}
	ns_cmd->ns_flags = ns_flags;

	return (ns_cmd);
}


void
fctl_free_ns_cmd(fctl_ns_req_t *ns_cmd)
{
	if (ns_cmd->ns_cmd_size && ns_cmd->ns_cmd_buf) {
		kmem_free(ns_cmd->ns_cmd_buf, ns_cmd->ns_cmd_size);
	}
	if (ns_cmd->ns_data_len && ns_cmd->ns_data_buf) {
		kmem_free(ns_cmd->ns_data_buf, ns_cmd->ns_data_len);
	}
	kmem_free(ns_cmd, sizeof (*ns_cmd));
}


int
fctl_ulp_port_ioctl(fc_local_port_t *port, dev_t dev, int cmd,
    intptr_t data, int mode, cred_t *credp, int *rval)
{
	int			ret;
	int			save;
	uint32_t		claimed;
	fc_ulp_module_t		*mod;
	fc_ulp_ports_t		*ulp_port;

	save = *rval;
	*rval = ENOTTY;

	rw_enter(&fctl_ulp_lock, RW_READER);
	for (claimed = 0, mod = fctl_ulp_modules; mod; mod = mod->mod_next) {
		rw_enter(&fctl_mod_ports_lock, RW_READER);
		ulp_port = fctl_get_ulp_port(mod, port);
		rw_exit(&fctl_mod_ports_lock);

		if (ulp_port == NULL) {
			continue;
		}

		mutex_enter(&ulp_port->port_mutex);
		if (FCTL_DISALLOW_CALLBACKS(ulp_port->port_dstate) ||
		    mod->mod_info->ulp_port_ioctl == NULL) {
			mutex_exit(&ulp_port->port_mutex);
			continue;
		}
		mutex_exit(&ulp_port->port_mutex);

		ret = mod->mod_info->ulp_port_ioctl(
		    mod->mod_info->ulp_handle, (opaque_t)port,
		    dev, cmd, data, mode, credp, rval, claimed);

		if (ret == FC_SUCCESS && claimed == 0) {
			claimed = 1;
		}
	}
	rw_exit(&fctl_ulp_lock);

	ret = *rval;
	*rval = save;

	return (ret);
}

/*
 * raise power if necessary, and set the port busy
 *
 * this may cause power to be raised, so no power related locks should
 * be held
 */
int
fc_ulp_busy_port(opaque_t port_handle)
{
	fc_local_port_t *port = port_handle;

	return (fctl_busy_port(port));
}

void
fc_ulp_idle_port(opaque_t port_handle)
{
	fc_local_port_t *port = port_handle;
	fctl_idle_port(port);
}

void
fc_ulp_copy_portmap(fc_portmap_t *map, opaque_t pd)
{
	fctl_copy_portmap(map, (fc_remote_port_t *)pd);
}


int
fc_ulp_get_npiv_port_num(opaque_t port_handle)
{
	int portsnum = 0;
	fc_local_port_t *port = port_handle;
	fc_local_port_t *tmpport;

	mutex_enter(&port->fp_mutex);
	tmpport = port->fp_port_next;
	if (!tmpport) {
		mutex_exit(&port->fp_mutex);
		return (portsnum);
	}
	while (tmpport != port) {
		portsnum ++;
		tmpport = tmpport->fp_port_next;
	}
	mutex_exit(&port->fp_mutex);
	return (portsnum);
}

fc_local_port_t *
fc_get_npiv_port(fc_local_port_t *phyport, la_wwn_t *pwwn)
{
	fc_fca_port_t	*fca_port;
	fc_local_port_t	*tmpPort = phyport;

	mutex_enter(&fctl_port_lock);

	for (fca_port = fctl_fca_portlist; fca_port != NULL;
	    fca_port = fca_port->port_next) {
		tmpPort = fca_port->port_handle;
		if (tmpPort == NULL) {
			continue;
		}
		mutex_enter(&tmpPort->fp_mutex);
		if (bcmp(tmpPort->fp_service_params.nport_ww_name.raw_wwn,
		    pwwn->raw_wwn, sizeof (la_wwn_t)) == 0) {
			mutex_exit(&tmpPort->fp_mutex);
			mutex_exit(&fctl_port_lock);
			return (tmpPort);
		}
		mutex_exit(&tmpPort->fp_mutex);
	}

	mutex_exit(&fctl_port_lock);

	return (NULL);
}

int
fc_ulp_get_npiv_port_list(opaque_t port_handle, char *pathList)
{
	int portsnum = 0;
	fc_local_port_t *port = port_handle;
	fc_local_port_t *tmpport;

	mutex_enter(&port->fp_mutex);
	tmpport = port->fp_port_next;
	if (!tmpport || (port->fp_npiv_type == FC_NPIV_PORT)) {
		mutex_exit(&port->fp_mutex);
		return (portsnum);
	}

	while (tmpport != port) {
		(void) ddi_pathname(tmpport->fp_port_dip,
		    &pathList[MAXPATHLEN * portsnum]);
		portsnum ++;
		tmpport = tmpport->fp_port_next;
	}
	mutex_exit(&port->fp_mutex);

	return (portsnum);
}


fc_local_port_t *
fc_delete_npiv_port(fc_local_port_t *port, la_wwn_t *pwwn)
{
	fc_local_port_t *tmpport;

	mutex_enter(&port->fp_mutex);
	tmpport = port->fp_port_next;
	if (!tmpport || (port->fp_npiv_type == FC_NPIV_PORT)) {
		mutex_exit(&port->fp_mutex);
		return (NULL);
	}

	while (tmpport != port) {
		if ((bcmp(tmpport->fp_service_params.nport_ww_name.raw_wwn,
		    pwwn->raw_wwn, sizeof (la_wwn_t)) == 0) &&
		    (tmpport->fp_npiv_state == 0)) {
			tmpport->fp_npiv_state = FC_NPIV_DELETING;
			mutex_exit(&port->fp_mutex);
			return (tmpport);
		}
		tmpport = tmpport->fp_port_next;
	}

	mutex_exit(&port->fp_mutex);
	return (NULL);
}

/*
 * Get the list of Adapters.  On multi-ported adapters,
 * only ONE port on the adapter will be returned.
 * pathList should be (count * MAXPATHLEN) long.
 * The return value will be set to the number of
 * HBAs that were found on the system.	If the value
 * is greater than count, the routine should be retried
 * with a larger buffer.
 */
int
fc_ulp_get_adapter_paths(char *pathList, int count)
{
	fc_fca_port_t	*fca_port;
	int		in = 0, out = 0, check, skip, maxPorts = 0;
	fc_local_port_t		**portList;
	fc_local_port_t		*new_port, *stored_port;
	fca_hba_fru_details_t	*new_fru, *stored_fru;

	ASSERT(pathList != NULL);

	/* First figure out how many ports we have */
	mutex_enter(&fctl_port_lock);

	for (fca_port = fctl_fca_portlist; fca_port != NULL;
	    fca_port = fca_port->port_next) {
		maxPorts ++;
	}

	/* Now allocate a buffer to store all the pointers for comparisons */
	portList = kmem_zalloc(sizeof (fc_local_port_t *) * maxPorts, KM_SLEEP);

	for (fca_port = fctl_fca_portlist; fca_port != NULL;
	    fca_port = fca_port->port_next) {
		skip = 0;

		/* Lock the new port for subsequent comparisons */
		new_port = fca_port->port_handle;
		mutex_enter(&new_port->fp_mutex);
		new_fru = &new_port->fp_hba_port_attrs.hba_fru_details;

		/* Filter out secondary ports from the list */
		for (check = 0; check < out; check++) {
			if (portList[check] == NULL) {
				continue;
			}
			/* Guard against duplicates (should never happen) */
			if (portList[check] == fca_port->port_handle) {
				/* Same port */
				skip = 1;
				break;
			}

			/* Lock the already stored port for comparison */
			stored_port = portList[check];
			mutex_enter(&stored_port->fp_mutex);
			stored_fru =
			    &stored_port->fp_hba_port_attrs.hba_fru_details;

			/* Are these ports on the same HBA? */
			if (new_fru->high == stored_fru->high &&
			    new_fru->low == stored_fru->low) {
				/* Now double check driver */
				if (strncmp(
				    new_port->fp_hba_port_attrs.driver_name,
				    stored_port->fp_hba_port_attrs.driver_name,
				    FCHBA_DRIVER_NAME_LEN) == 0) {
					/* we don't need to grow the list */
					skip = 1;
					/* looking at a lower port index? */
					if (new_fru->port_index <
					    stored_fru->port_index) {
						/* Replace the port in list */
						mutex_exit(
						    &stored_port->fp_mutex);
						if (new_port->fp_npiv_type ==
						    FC_NPIV_PORT) {
							break;
						}
						portList[check] = new_port;
						break;
					} /* Else, just skip this port */
				}
			}

			mutex_exit(&stored_port->fp_mutex);
		}
		mutex_exit(&new_port->fp_mutex);

		if (!skip) {
			/*
			 * Either this is the first port for this HBA, or
			 * it's a secondary port and we haven't stored the
			 * primary/first port for that HBA.  In the latter case,
			 * will just filter it out as we proceed to loop.
			 */
			if (fca_port->port_handle->fp_npiv_type ==
			    FC_NPIV_PORT) {
				continue;
			} else {
				portList[out++] = fca_port->port_handle;
			}
		}
	}

	if (out <= count) {
		for (in = 0; in < out; in++) {
			(void) ddi_pathname(portList[in]->fp_port_dip,
			    &pathList[MAXPATHLEN * in]);
		}
	}
	mutex_exit(&fctl_port_lock);
	kmem_free(portList, sizeof (*portList) * maxPorts);
	return (out);
}

uint32_t
fc_ulp_get_rscn_count(opaque_t port_handle)
{
	uint32_t	count;
	fc_local_port_t	*port;

	port = (fc_local_port_t *)port_handle;
	mutex_enter(&port->fp_mutex);
	count = port->fp_rscn_count;
	mutex_exit(&port->fp_mutex);

	return (count);
}


/*
 * This function is a very similar to fctl_add_orphan except that it expects
 * that the fp_mutex and pd_mutex of the pd passed in are held coming in.
 *
 * Note that there is a lock hierarchy here (fp_mutex should be held first) but
 * since this function could be called with a different pd's pd_mutex held, we
 * should take care not to release fp_mutex in this function.
 */
int
fctl_add_orphan_held(fc_local_port_t *port, fc_remote_port_t *pd)
{
	int		rval = FC_FAILURE;
	la_wwn_t	pwwn;
	fc_orphan_t	*orp;
	fc_orphan_t	*orphan;

	ASSERT(MUTEX_HELD(&port->fp_mutex));
	ASSERT(MUTEX_HELD(&pd->pd_mutex));

	pwwn = pd->pd_port_name;

	for (orp = port->fp_orphan_list; orp != NULL; orp = orp->orp_next) {
		if (fctl_wwn_cmp(&orp->orp_pwwn, &pwwn) == 0) {
			return (FC_SUCCESS);
		}
	}

	orphan = kmem_zalloc(sizeof (*orphan), KM_NOSLEEP);
	if (orphan) {
		orphan->orp_pwwn = pwwn;
		orphan->orp_tstamp = ddi_get_lbolt();

		if (port->fp_orphan_list) {
			ASSERT(port->fp_orphan_count > 0);
			orphan->orp_next = port->fp_orphan_list;
		}
		port->fp_orphan_list = orphan;
		port->fp_orphan_count++;

		rval = FC_SUCCESS;
	}

	return (rval);
}

int
fctl_add_orphan(fc_local_port_t *port, fc_remote_port_t *pd, int sleep)
{
	int		rval = FC_FAILURE;
	la_wwn_t	pwwn;
	fc_orphan_t	*orp;
	fc_orphan_t	*orphan;

	mutex_enter(&port->fp_mutex);

	mutex_enter(&pd->pd_mutex);
	pwwn = pd->pd_port_name;
	mutex_exit(&pd->pd_mutex);

	for (orp = port->fp_orphan_list; orp != NULL; orp = orp->orp_next) {
		if (fctl_wwn_cmp(&orp->orp_pwwn, &pwwn) == 0) {
			mutex_exit(&port->fp_mutex);
			return (FC_SUCCESS);
		}
	}
	mutex_exit(&port->fp_mutex);

	orphan = kmem_zalloc(sizeof (*orphan), sleep);
	if (orphan != NULL) {
		mutex_enter(&port->fp_mutex);

		orphan->orp_pwwn = pwwn;
		orphan->orp_tstamp = ddi_get_lbolt();

		if (port->fp_orphan_list) {
			ASSERT(port->fp_orphan_count > 0);
			orphan->orp_next = port->fp_orphan_list;
		}
		port->fp_orphan_list = orphan;
		port->fp_orphan_count++;
		mutex_exit(&port->fp_mutex);

		rval = FC_SUCCESS;
	}

	return (rval);
}


int
fctl_remove_if_orphan(fc_local_port_t *port, la_wwn_t *pwwn)
{
	int		rval = FC_FAILURE;
	fc_orphan_t	*prev = NULL;
	fc_orphan_t	*orp;

	mutex_enter(&port->fp_mutex);
	for (orp = port->fp_orphan_list; orp != NULL; orp = orp->orp_next) {
		if (fctl_wwn_cmp(&orp->orp_pwwn, pwwn) == 0) {
			if (prev) {
				prev->orp_next = orp->orp_next;
			} else {
				ASSERT(port->fp_orphan_list == orp);
				port->fp_orphan_list = orp->orp_next;
			}
			port->fp_orphan_count--;
			rval = FC_SUCCESS;
			break;
		}
		prev = orp;
	}
	mutex_exit(&port->fp_mutex);

	if (rval == FC_SUCCESS) {
		kmem_free(orp, sizeof (*orp));
	}

	return (rval);
}


static void
fctl_print_if_not_orphan(fc_local_port_t *port, fc_remote_port_t *pd)
{
	char		ww_name[17];
	la_wwn_t	pwwn;
	fc_orphan_t	*orp;

	mutex_enter(&port->fp_mutex);

	mutex_enter(&pd->pd_mutex);
	pwwn = pd->pd_port_name;
	mutex_exit(&pd->pd_mutex);

	for (orp = port->fp_orphan_list; orp != NULL; orp = orp->orp_next) {
		if (fctl_wwn_cmp(&orp->orp_pwwn, &pwwn) == 0) {
			mutex_exit(&port->fp_mutex);
			return;
		}
	}
	mutex_exit(&port->fp_mutex);

	fc_wwn_to_str(&pwwn, ww_name);

	cmn_err(CE_WARN, "!fctl(%d): N_x Port with D_ID=%x, PWWN=%s"
	    " disappeared from fabric", port->fp_instance,
	    pd->pd_port_id.port_id, ww_name);
}


/* ARGSUSED */
static void
fctl_link_reset_done(opaque_t port_handle, uchar_t result)
{
	fc_local_port_t *port = port_handle;

	mutex_enter(&port->fp_mutex);
	port->fp_soft_state &= ~FP_SOFT_IN_LINK_RESET;
	mutex_exit(&port->fp_mutex);

	fctl_idle_port(port);
}


static int
fctl_error(int fc_errno, char **errmsg)
{
	int count;

	for (count = 0; count < sizeof (fc_errlist) /
	    sizeof (fc_errlist[0]); count++) {
		if (fc_errlist[count].fc_errno == fc_errno) {
			*errmsg = fc_errlist[count].fc_errname;
			return (FC_SUCCESS);
		}
	}
	*errmsg = fctl_undefined;

	return (FC_FAILURE);
}


/*
 * Return number of successful translations.
 *	Anybody with some userland programming experience would have
 *	figured it by now that the return value exactly resembles that
 *	of scanf(3c). This function returns a count of successful
 *	translations. It could range from 0 (no match for state, reason,
 *	action, expln) to 4 (successful matches for all state, reason,
 *	action, expln) and where translation isn't successful into a
 *	friendlier message the relevent field is set to "Undefined"
 */
static int
fctl_pkt_error(fc_packet_t *pkt, char **state, char **reason,
    char **action, char **expln)
{
	int		ret;
	int		len;
	int		index;
	fc_pkt_error_t	*error;
	fc_pkt_reason_t	*reason_b;	/* Base pointer */
	fc_pkt_action_t	*action_b;	/* Base pointer */
	fc_pkt_expln_t	*expln_b;	/* Base pointer */

	ret = 0;
	*state = *reason = *action = *expln = fctl_undefined;

	len = sizeof (fc_pkt_errlist) / sizeof fc_pkt_errlist[0];
	for (index = 0; index < len; index++) {
		error = fc_pkt_errlist + index;
		if (pkt->pkt_state == error->pkt_state) {
			*state = error->pkt_msg;
			ret++;

			reason_b = error->pkt_reason;
			action_b = error->pkt_action;
			expln_b = error->pkt_expln;

			while (reason_b != NULL &&
			    reason_b->reason_val != FC_REASON_INVALID) {
				if (reason_b->reason_val == pkt->pkt_reason) {
					*reason = reason_b->reason_msg;
					ret++;
					break;
				}
				reason_b++;
			}

			while (action_b != NULL &&
			    action_b->action_val != FC_ACTION_INVALID) {
				if (action_b->action_val == pkt->pkt_action) {
					*action = action_b->action_msg;
					ret++;
					break;
				}
				action_b++;
			}

			while (expln_b != NULL &&
			    expln_b->expln_val != FC_EXPLN_INVALID) {
				if (expln_b->expln_val == pkt->pkt_expln) {
					*expln = expln_b->expln_msg;
					ret++;
					break;
				}
				expln_b++;
			}
			break;
		}
	}

	return (ret);
}


/*
 * Remove all port devices that are marked OLD, remove
 * corresponding node devices (fc_remote_node_t)
 */
void
fctl_remove_oldies(fc_local_port_t *port)
{
	int			index;
	int			initiator;
	fc_remote_node_t	*node;
	struct pwwn_hash	*head;
	fc_remote_port_t	*pd;
	fc_remote_port_t	*old_pd;
	fc_remote_port_t	*last_pd;

	/*
	 * Nuke all OLD devices
	 */
	mutex_enter(&port->fp_mutex);

	for (index = 0; index < pwwn_table_size; index++) {
		head = &port->fp_pwwn_table[index];
		last_pd = NULL;
		pd = head->pwwn_head;

		while (pd != NULL) {
			mutex_enter(&pd->pd_mutex);
			if (pd->pd_type != PORT_DEVICE_OLD) {
				mutex_exit(&pd->pd_mutex);
				last_pd = pd;
				pd = pd->pd_wwn_hnext;
				continue;
			}

			/*
			 * Remove this from the PWWN hash table
			 */
			old_pd = pd;
			pd = old_pd->pd_wwn_hnext;

			if (last_pd == NULL) {
				ASSERT(old_pd == head->pwwn_head);
				head->pwwn_head = pd;
			} else {
				last_pd->pd_wwn_hnext = pd;
			}
			head->pwwn_count--;
			/*
			 * Make sure we tie fp_dev_count to the size of the
			 * pwwn_table
			 */
			port->fp_dev_count--;
			old_pd->pd_wwn_hnext = NULL;

			fctl_delist_did_table(port, old_pd);
			node = old_pd->pd_remote_nodep;
			ASSERT(node != NULL);

			initiator = (old_pd->pd_recepient ==
			    PD_PLOGI_INITIATOR) ? 1 : 0;

			mutex_exit(&old_pd->pd_mutex);

			if (FC_IS_TOP_SWITCH(port->fp_topology) && initiator) {
				mutex_exit(&port->fp_mutex);

				(void) fctl_add_orphan(port, old_pd,
				    KM_NOSLEEP);
			} else {
				mutex_exit(&port->fp_mutex);
			}

			if (fctl_destroy_remote_port(port, old_pd) == 0) {
				if (node) {
					fctl_destroy_remote_node(node);
				}
			}

			mutex_enter(&port->fp_mutex);
		}
	}

	mutex_exit(&port->fp_mutex);
}


static void
fctl_check_alpa_list(fc_local_port_t *port, fc_remote_port_t *pd)
{
	ASSERT(MUTEX_HELD(&port->fp_mutex));
	ASSERT(port->fp_topology == FC_TOP_PRIVATE_LOOP);

	if (fctl_is_alpa_present(port, pd->pd_port_id.port_id) == FC_SUCCESS) {
		return;
	}

	cmn_err(CE_WARN, "!fctl(%d): AL_PA=0x%x doesn't exist in LILP map",
	    port->fp_instance, pd->pd_port_id.port_id);
}


static int
fctl_is_alpa_present(fc_local_port_t *port, uchar_t alpa)
{
	int index;

	ASSERT(MUTEX_HELD(&port->fp_mutex));
	ASSERT(port->fp_topology == FC_TOP_PRIVATE_LOOP);

	for (index = 0; index < port->fp_lilp_map.lilp_length; index++) {
		if (port->fp_lilp_map.lilp_alpalist[index] == alpa) {
			return (FC_SUCCESS);
		}
	}

	return (FC_FAILURE);
}


fc_remote_port_t *
fctl_lookup_pd_by_did(fc_local_port_t *port, uint32_t d_id)
{
	int			index;
	struct pwwn_hash	*head;
	fc_remote_port_t	*pd;

	ASSERT(MUTEX_HELD(&port->fp_mutex));

	for (index = 0; index < pwwn_table_size; index++) {
		head = &port->fp_pwwn_table[index];
		pd = head->pwwn_head;

		while (pd != NULL) {
			mutex_enter(&pd->pd_mutex);
			if (pd->pd_port_id.port_id == d_id) {
				mutex_exit(&pd->pd_mutex);
				return (pd);
			}
			mutex_exit(&pd->pd_mutex);
			pd = pd->pd_wwn_hnext;
		}
	}

	return (pd);
}


/*
 * trace debugging
 */
void
fc_trace_debug(fc_trace_logq_t *logq, caddr_t name, int dflag, int dlevel,
    int errno, const char *fmt, ...)
{
	char	buf[FC_MAX_TRACE_BUF_LEN + 3]; /* 3 is for "\n" */
	char	*bufptr = buf;
	va_list	ap;
	int	cnt = 0;

	if ((dlevel & dflag) == 0) {
		return;
	}

	if (name) {
		cnt = snprintf(buf, FC_MAX_TRACE_BUF_LEN + 1, "%d=>%s::",
		    logq->il_id++, name);
	} else {
		cnt = snprintf(buf, FC_MAX_TRACE_BUF_LEN + 1, "%d=>trace::",
		    logq->il_id++);
	}

	if (cnt < FC_MAX_TRACE_BUF_LEN) {
		va_start(ap, fmt);
		cnt += vsnprintf(buf + cnt, FC_MAX_TRACE_BUF_LEN + 1 - cnt,
		    fmt, ap);
		va_end(ap);
	}

	if (cnt > FC_MAX_TRACE_BUF_LEN) {
		cnt = FC_MAX_TRACE_BUF_LEN;
	}
	if (errno && (cnt < FC_MAX_TRACE_BUF_LEN)) {
		cnt += snprintf(buf + cnt, FC_MAX_TRACE_BUF_LEN + 1 - cnt,
		    "error=0x%x\n", errno);
	}
	(void) snprintf(buf + cnt, FC_MAX_TRACE_BUF_LEN + 3 - cnt, "\n");

	if (logq && (dlevel & FC_TRACE_LOG_BUF) != 0) {
		fc_trace_logmsg(logq, buf, dlevel);
	}

	/*
	 * We do not want to print the log numbers that appear as
	 * random numbers at the console and messages files, to
	 * the user.
	 */
	if ((bufptr = strchr(buf, '>')) == NULL) {
		/*
		 * We would have added the a string with "=>" above and so,
		 * ideally, we should not get here at all. But, if we do,
		 * we'll just use the full buf.
		 */
		bufptr = buf;
	} else {
		bufptr++;
	}

	switch (dlevel & FC_TRACE_LOG_MASK) {
	case FC_TRACE_LOG_CONSOLE:
		cmn_err(CE_WARN, "%s", bufptr);
		break;

	case FC_TRACE_LOG_CONSOLE_MSG:
		cmn_err(CE_WARN, "%s", bufptr);
		break;

	case FC_TRACE_LOG_MSG:
		cmn_err(CE_WARN, "!%s", bufptr);
		break;

	default:
		break;
	}
}


/*
 * This function can block
 */
fc_trace_logq_t *
fc_trace_alloc_logq(int maxsize)
{
	fc_trace_logq_t *logq;

	logq = kmem_zalloc(sizeof (*logq), KM_SLEEP);

	mutex_init(&logq->il_lock, NULL, MUTEX_DRIVER, NULL);
	logq->il_hiwat = maxsize;
	logq->il_flags |= FC_TRACE_LOGQ_V2;

	return (logq);
}


void
fc_trace_free_logq(fc_trace_logq_t *logq)
{
	mutex_enter(&logq->il_lock);
	while (logq->il_msgh) {
		fc_trace_freemsg(logq);
	}
	mutex_exit(&logq->il_lock);

	mutex_destroy(&logq->il_lock);
	kmem_free(logq, sizeof (*logq));
}


/* ARGSUSED */
void
fc_trace_logmsg(fc_trace_logq_t *logq, caddr_t buf, int level)
{
	int		qfull = 0;
	fc_trace_dmsg_t	*dmsg;

	dmsg = kmem_alloc(sizeof (*dmsg), KM_NOSLEEP);
	if (dmsg == NULL) {
		mutex_enter(&logq->il_lock);
		logq->il_afail++;
		mutex_exit(&logq->il_lock);

		return;
	}

	gethrestime(&dmsg->id_time);

	dmsg->id_size = strlen(buf) + 1;
	dmsg->id_buf = kmem_alloc(dmsg->id_size, KM_NOSLEEP);
	if (dmsg->id_buf == NULL) {
		kmem_free(dmsg, sizeof (*dmsg));

		mutex_enter(&logq->il_lock);
		logq->il_afail++;
		mutex_exit(&logq->il_lock);

		return;
	}
	bcopy(buf, dmsg->id_buf, strlen(buf));
	dmsg->id_buf[strlen(buf)] = '\0';

	mutex_enter(&logq->il_lock);

	logq->il_size += dmsg->id_size;
	if (logq->il_size >= logq->il_hiwat) {
		qfull = 1;
	}

	if (qfull) {
		fc_trace_freemsg(logq);
	}

	dmsg->id_next = NULL;
	if (logq->il_msgt) {
		logq->il_msgt->id_next = dmsg;
	} else {
		ASSERT(logq->il_msgh == NULL);
		logq->il_msgh = dmsg;
	}
	logq->il_msgt = dmsg;

	mutex_exit(&logq->il_lock);
}


static void
fc_trace_freemsg(fc_trace_logq_t *logq)
{
	fc_trace_dmsg_t	*dmsg;

	ASSERT(MUTEX_HELD(&logq->il_lock));

	if ((dmsg = logq->il_msgh) != NULL) {
		logq->il_msgh = dmsg->id_next;
		if (logq->il_msgh == NULL) {
			logq->il_msgt = NULL;
		}

		logq->il_size -= dmsg->id_size;
		kmem_free(dmsg->id_buf, dmsg->id_size);
		kmem_free(dmsg, sizeof (*dmsg));
	} else {
		ASSERT(logq->il_msgt == NULL);
	}
}

/*
 * Used by T11 FC-HBA to fetch discovered ports by index.
 * Returns NULL if the index isn't valid.
 */
fc_remote_port_t *
fctl_lookup_pd_by_index(fc_local_port_t *port, uint32_t index)
{
	int			outer;
	int			match = 0;
	struct pwwn_hash	*head;
	fc_remote_port_t	*pd;

	ASSERT(MUTEX_HELD(&port->fp_mutex));

	for (outer = 0;
	    outer < pwwn_table_size && match <= index;
	    outer++) {
		head = &port->fp_pwwn_table[outer];
		pd = head->pwwn_head;
		if (pd != NULL) match ++;

		while (pd != NULL && match <= index) {
			pd = pd->pd_wwn_hnext;
			if (pd != NULL) match ++;
		}
	}

	return (pd);
}

/*
 * Search for a matching Node or Port WWN in the discovered port list
 */
fc_remote_port_t *
fctl_lookup_pd_by_wwn(fc_local_port_t *port, la_wwn_t wwn)
{
	int			index;
	struct pwwn_hash	*head;
	fc_remote_port_t	*pd;

	ASSERT(MUTEX_HELD(&port->fp_mutex));

	for (index = 0; index < pwwn_table_size; index++) {
		head = &port->fp_pwwn_table[index];
		pd = head->pwwn_head;

		while (pd != NULL) {
			mutex_enter(&pd->pd_mutex);
			if (bcmp(pd->pd_port_name.raw_wwn, wwn.raw_wwn,
			    sizeof (la_wwn_t)) == 0) {
				mutex_exit(&pd->pd_mutex);
				return (pd);
			}
			if (bcmp(pd->pd_remote_nodep->fd_node_name.raw_wwn,
			    wwn.raw_wwn, sizeof (la_wwn_t)) == 0) {
				mutex_exit(&pd->pd_mutex);
				return (pd);
			}
			mutex_exit(&pd->pd_mutex);
			pd = pd->pd_wwn_hnext;
		}
	}
	/* No match */
	return (NULL);
}


/*
 * Count the number of ports on this adapter.
 * This routine will walk the port list and count up the number of adapters
 * with matching fp_hba_port_attrs.hba_fru_details.high and
 * fp_hba_port_attrs.hba_fru_details.low.
 *
 * port->fp_mutex must not be held.
 */
int
fctl_count_fru_ports(fc_local_port_t *port, int npivflag)
{
	fca_hba_fru_details_t	*fru;
	fc_fca_port_t	*fca_port;
	fc_local_port_t	*tmpPort = NULL;
	uint32_t	count = 1;

	mutex_enter(&fctl_port_lock);

	mutex_enter(&port->fp_mutex);
	fru = &port->fp_hba_port_attrs.hba_fru_details;

	/* Detect FCA drivers that don't support linking HBA ports */
	if (fru->high == 0 && fru->low == 0 && fru->port_index == 0) {
		mutex_exit(&port->fp_mutex);
		mutex_exit(&fctl_port_lock);
		return (1);
	}

	for (fca_port = fctl_fca_portlist; fca_port != NULL;
	    fca_port = fca_port->port_next) {
		tmpPort = fca_port->port_handle;
		if (tmpPort == port) {
			continue;
		}
		mutex_enter(&tmpPort->fp_mutex);

		/*
		 * If an FCA driver returns unique fru->high and fru->low for
		 * ports on the same card, there is no way for the transport
		 * layer to determine that the two ports on the same FRU. So,
		 * the discovery of the ports on a same FRU  is limited to what
		 * the FCA driver can report back.
		 */
		if (tmpPort->fp_hba_port_attrs.hba_fru_details.high ==
		    fru->high &&
		    tmpPort->fp_hba_port_attrs.hba_fru_details.low ==
		    fru->low) {
			/* Now double check driver */
			if (strncmp(port->fp_hba_port_attrs.driver_name,
			    tmpPort->fp_hba_port_attrs.driver_name,
			    FCHBA_DRIVER_NAME_LEN) == 0) {
				if (!npivflag ||
				    (tmpPort->fp_npiv_type != FC_NPIV_PORT)) {
					count++;
				}
			} /* Else, different FCA driver */
		} /* Else not the same HBA FRU */
		mutex_exit(&tmpPort->fp_mutex);
	}

	mutex_exit(&port->fp_mutex);
	mutex_exit(&fctl_port_lock);

	return (count);
}

fc_fca_port_t *
fctl_local_port_list_add(fc_fca_port_t *list, fc_local_port_t *port)
{
	fc_fca_port_t *tmp = list, *newentry = NULL;

	newentry = kmem_zalloc(sizeof (fc_fca_port_t), KM_NOSLEEP);
	if (newentry == NULL) {
		return (list);
	}
	newentry->port_handle = port;

	if (tmp == NULL) {
		return (newentry);
	}
	while (tmp->port_next != NULL)	tmp = tmp->port_next;
	tmp->port_next = newentry;

	return (list);
}

void
fctl_local_port_list_free(fc_fca_port_t *list)
{
	fc_fca_port_t *tmp = list, *nextentry;

	if (tmp == NULL) {
		return;
	}

	while (tmp != NULL) {
		nextentry = tmp->port_next;
		kmem_free(tmp, sizeof (*tmp));
		tmp = nextentry;
	}
}

/*
 * Fetch another port on the HBA FRU based on index.
 * Returns NULL if index not found.
 *
 * port->fp_mutex must not be held.
 */
fc_local_port_t *
fctl_get_adapter_port_by_index(fc_local_port_t *port, uint32_t port_index)
{
	fca_hba_fru_details_t	*fru;
	fc_fca_port_t	*fca_port;
	fc_local_port_t	*tmpPort = NULL;
	fc_fca_port_t	*list = NULL, *tmpEntry;
	fc_local_port_t		*phyPort, *virPort = NULL;
	int	index, phyPortNum = 0;

	mutex_enter(&fctl_port_lock);

	mutex_enter(&port->fp_mutex);
	fru = &port->fp_hba_port_attrs.hba_fru_details;

	/* Are we looking for this port? */
	if (fru->port_index == port_index) {
		mutex_exit(&port->fp_mutex);
		mutex_exit(&fctl_port_lock);
		return (port);
	}

	/* Detect FCA drivers that don't support linking HBA ports */
	if (fru->high == 0 && fru->low == 0 && fru->port_index == 0) {
		mutex_exit(&port->fp_mutex);
		mutex_exit(&fctl_port_lock);
		return (NULL);
	}

	list = fctl_local_port_list_add(list, port);
	phyPortNum++;
	/* Loop through all known ports */
	for (fca_port = fctl_fca_portlist; fca_port != NULL;
	    fca_port = fca_port->port_next) {
		tmpPort = fca_port->port_handle;
		if (tmpPort == port) {
			/* Skip the port that was passed in as the argument */
			continue;
		}
		mutex_enter(&tmpPort->fp_mutex);

		/* See if this port is on the same HBA FRU (fast check) */
		if (tmpPort->fp_hba_port_attrs.hba_fru_details.high ==
		    fru->high &&
		    tmpPort->fp_hba_port_attrs.hba_fru_details.low ==
		    fru->low) {
			/* Now double check driver (slower check) */
			if (strncmp(port->fp_hba_port_attrs.driver_name,
			    tmpPort->fp_hba_port_attrs.driver_name,
			    FCHBA_DRIVER_NAME_LEN) == 0) {

				fru =
				    &tmpPort->fp_hba_port_attrs.hba_fru_details;
				/* Check for the matching port_index */
				if ((tmpPort->fp_npiv_type != FC_NPIV_PORT) &&
				    (fru->port_index == port_index)) {
					/* Found it! */
					mutex_exit(&tmpPort->fp_mutex);
					mutex_exit(&port->fp_mutex);
					mutex_exit(&fctl_port_lock);
					fctl_local_port_list_free(list);
					return (tmpPort);
				}
				if (tmpPort->fp_npiv_type != FC_NPIV_PORT) {
					(void) fctl_local_port_list_add(list,
					    tmpPort);
					phyPortNum++;
				}
			} /* Else, different FCA driver */
		} /* Else not the same HBA FRU */
		mutex_exit(&tmpPort->fp_mutex);

	}

	/* scan all physical port on same chip to find virtual port */
	tmpEntry = list;
	index = phyPortNum - 1;
	virPort = NULL;
	while (index < port_index) {
		if (tmpEntry == NULL) {
			break;
		}
		if (virPort == NULL) {
			phyPort = tmpEntry->port_handle;
			virPort = phyPort->fp_port_next;
			if (virPort == NULL) {
				tmpEntry = tmpEntry->port_next;
				continue;
			}
		} else {
			virPort = virPort->fp_port_next;
		}
		if (virPort == phyPort) {
			tmpEntry = tmpEntry->port_next;
			virPort = NULL;
		} else {
			index++;
		}
	}
	mutex_exit(&port->fp_mutex);
	mutex_exit(&fctl_port_lock);

	fctl_local_port_list_free(list);
	if (virPort) {
		return (virPort);
	}
	return (NULL);
}

int
fctl_busy_port(fc_local_port_t *port)
{
	ASSERT(!MUTEX_HELD(&port->fp_mutex));

	mutex_enter(&port->fp_mutex);
	if (port->fp_soft_state & FP_SOFT_NO_PMCOMP) {
		/*
		 * If fctl_busy_port() is called before we've registered our
		 * PM components, we return success. We need to be aware of
		 * this because the caller will eventually call fctl_idle_port.
		 * This wouldn't be a problem except that if we have
		 * registered our PM components in the meantime, we will
		 * then be idling a component that was never busied.  PM
		 * will be very unhappy if we do this.	Thus, we keep
		 * track of this with port->fp_pm_busy_nocomp.
		 */
		port->fp_pm_busy_nocomp++;
		mutex_exit(&port->fp_mutex);
		return (0);
	}
	port->fp_pm_busy++;
	mutex_exit(&port->fp_mutex);

	if (pm_busy_component(port->fp_port_dip,
	    FP_PM_COMPONENT) != DDI_SUCCESS) {
		mutex_enter(&port->fp_mutex);
		port->fp_pm_busy--;
		mutex_exit(&port->fp_mutex);
		return (ENXIO);
	}

	mutex_enter(&port->fp_mutex);
	if (port->fp_pm_level == FP_PM_PORT_DOWN) {
		mutex_exit(&port->fp_mutex);
		if (pm_raise_power(port->fp_port_dip, FP_PM_COMPONENT,
		    FP_PM_PORT_UP) != DDI_SUCCESS) {

			mutex_enter(&port->fp_mutex);
			port->fp_pm_busy--;
			mutex_exit(&port->fp_mutex);

			(void) pm_idle_component(port->fp_port_dip,
			    FP_PM_COMPONENT);
			return (EIO);
		}
		return (0);
	}
	mutex_exit(&port->fp_mutex);
	return (0);
}

void
fctl_idle_port(fc_local_port_t *port)
{
	ASSERT(!MUTEX_HELD(&port->fp_mutex));

	mutex_enter(&port->fp_mutex);

	/*
	 * If port->fp_pm_busy_nocomp is > 0, that means somebody had
	 * called fctl_busy_port prior to us registering our PM components.
	 * In that case, we just decrement fp_pm_busy_nocomp and return.
	 */

	if (port->fp_pm_busy_nocomp > 0) {
		port->fp_pm_busy_nocomp--;
		mutex_exit(&port->fp_mutex);
		return;
	}

	port->fp_pm_busy--;
	mutex_exit(&port->fp_mutex);

	(void) pm_idle_component(port->fp_port_dip, FP_PM_COMPONENT);
}

/*
 *     Function: fctl_tc_timer
 *
 *  Description: Resets the value of the timed counter.
 *
 *    Arguments: *tc		Timed counter
 *
 * Return Value: Nothing
 *
 *	Context: Kernel context.
 */
static void
fctl_tc_timer(void *arg)
{
	timed_counter_t	*tc = (timed_counter_t *)arg;

	ASSERT(tc != NULL);
	ASSERT(tc->sig == tc);

	mutex_enter(&tc->mutex);
	if (tc->active) {
		tc->active = B_FALSE;
		tc->counter = 0;
	}
	mutex_exit(&tc->mutex);
}

/*
 *     Function: fctl_tc_constructor
 *
 *  Description: Constructs a timed counter.
 *
 *    Arguments: *tc		Address where the timed counter will reside.
 *		 max_value	Maximum value the counter is allowed to take.
 *		 timer		Number of microseconds after which the counter
 *				will be reset. The timer is started when the
 *				value of the counter goes from 0 to 1.
 *
 * Return Value: Nothing
 *
 *	Context: Kernel context.
 */
void
fctl_tc_constructor(timed_counter_t *tc, uint32_t max_value, clock_t timer)
{
	ASSERT(tc != NULL);
	ASSERT(tc->sig != tc);

	bzero(tc, sizeof (*tc));
	mutex_init(&tc->mutex, NULL, MUTEX_DRIVER, NULL);
	tc->timer = drv_usectohz(timer);
	tc->active = B_FALSE;
	tc->maxed_out = B_FALSE;
	tc->max_value = max_value;
	tc->sig = tc;
}

/*
 *     Function: fctl_tc_destructor
 *
 *  Description: Destroyes a timed counter.
 *
 *    Arguments: *tc		Timed counter to destroy.
 *
 * Return Value: Nothing
 *
 *	Context: Kernel context.
 */
void
fctl_tc_destructor(timed_counter_t *tc)
{
	ASSERT(tc != NULL);
	ASSERT(tc->sig == tc);
	ASSERT(!mutex_owned(&tc->mutex));

	mutex_enter(&tc->mutex);
	if (tc->active) {
		tc->active = B_FALSE;
		mutex_exit(&tc->mutex);
		(void) untimeout(tc->tid);
		mutex_enter(&tc->mutex);
		tc->sig = NULL;
	}
	mutex_exit(&tc->mutex);
	mutex_destroy(&tc->mutex);
}

/*
 *     Function: fctl_tc_increment
 *
 *  Description: Increments a timed counter
 *
 *    Arguments: *tc		Timed counter to increment.
 *
 * Return Value: B_TRUE		Counter reached the max value.
 *		 B_FALSE	Counter hasn't reached the max value.
 *
 *	Context: Kernel or interrupt context.
 */
boolean_t
fctl_tc_increment(timed_counter_t *tc)
{
	ASSERT(tc != NULL);
	ASSERT(tc->sig == tc);

	mutex_enter(&tc->mutex);
	if (!tc->maxed_out) {
		/* Hasn't maxed out yet. */
		++tc->counter;
		if (tc->counter >= tc->max_value) {
			/* Just maxed out. */
			tc->maxed_out = B_TRUE;
		}
		if (!tc->active) {
			tc->tid = timeout(fctl_tc_timer, tc, tc->timer);
			tc->active = B_TRUE;
		}
	}
	mutex_exit(&tc->mutex);

	return (tc->maxed_out);
}

/*
 *     Function: fctl_tc_reset
 *
 *  Description: Resets a timed counter.  The caller of this function has to
 *		 to make sure that while in fctl_tc_reset() fctl_tc_increment()
 *		 is not called.
 *
 *    Arguments: *tc		Timed counter to reset.
 *
 * Return Value: 0		Counter reached the max value.
 *		 Not 0		Counter hasn't reached the max value.
 *
 *	Context: Kernel or interrupt context.
 */
void
fctl_tc_reset(timed_counter_t *tc)
{
	ASSERT(tc != NULL);
	ASSERT(tc->sig == tc);

	mutex_enter(&tc->mutex);
	tc->counter = 0;
	tc->maxed_out = B_FALSE;
	if (tc->active) {
		tc->active = B_FALSE;
		(void) untimeout(tc->tid);
	}
	mutex_exit(&tc->mutex);
}

void
fc_ulp_log_device_event(opaque_t port_handle, int type)
{
	fc_local_port_t *port = port_handle;
	nvlist_t *attr_list;

	if (nvlist_alloc(&attr_list, NV_UNIQUE_NAME_TYPE,
	    KM_SLEEP) != DDI_SUCCESS) {
		return;
	}

	if (nvlist_add_uint32(attr_list, "instance",
	    port->fp_instance) != DDI_SUCCESS) {
		goto error;
	}

	if (nvlist_add_byte_array(attr_list, "port-wwn",
	    port->fp_service_params.nport_ww_name.raw_wwn,
	    sizeof (la_wwn_t)) != DDI_SUCCESS) {
		goto error;
	}

	(void) ddi_log_sysevent(port->fp_port_dip, DDI_VENDOR_SUNW, EC_SUNFC,
	    (type == FC_ULP_DEVICE_ONLINE) ?
	    ESC_SUNFC_DEVICE_ONLINE : ESC_SUNFC_DEVICE_OFFLINE,
	    attr_list, NULL, DDI_SLEEP);
	nvlist_free(attr_list);
	return;

error:
	nvlist_free(attr_list);
}
