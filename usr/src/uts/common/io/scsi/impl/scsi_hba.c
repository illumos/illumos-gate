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
 * Copyright (c) 1994, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 */

#include <sys/note.h>

/*
 * Generic SCSI Host Bus Adapter interface implementation
 */
#include <sys/scsi/scsi.h>
#include <sys/scsi/generic/sas.h>
#include <sys/file.h>
#include <sys/disp.h>			/* for minclsyspri */
#include <sys/ddi_impldefs.h>
#include <sys/ndi_impldefs.h>
#include <sys/sunndi.h>
#include <sys/ddi.h>
#include <sys/sunmdi.h>
#include <sys/mdi_impldefs.h>
#include <sys/callb.h>
#include <sys/epm.h>
#include <sys/damap.h>
#include <sys/time.h>
#include <sys/sunldi.h>
#include <sys/fm/protocol.h>

extern struct scsi_pkt *scsi_init_cache_pkt(struct scsi_address *,
		    struct scsi_pkt *, struct buf *, int, int, int, int,
		    int (*)(caddr_t), caddr_t);
extern void	scsi_free_cache_pkt(struct scsi_address *, struct scsi_pkt *);
extern void	scsi_cache_dmafree(struct scsi_address *, struct scsi_pkt *);
extern void	scsi_sync_cache_pkt(struct scsi_address *, struct scsi_pkt *);
extern int	modrootloaded;

/*
 * Round up all allocations so that we can guarantee
 * long-long alignment.  This is the same alignment
 * provided by kmem_alloc().
 */
#define	ROUNDUP(x)	(((x) + 0x07) & ~0x07)

/* Magic number to track correct allocations in wrappers */
#define	PKT_WRAPPER_MAGIC	0xa110ced	/* alloced correctly */

kmutex_t	scsi_flag_nointr_mutex;
kcondvar_t	scsi_flag_nointr_cv;
kmutex_t	scsi_log_mutex;

/* asynchronous probe barrier deletion data structures */
static kmutex_t	scsi_hba_barrier_mutex;
static kcondvar_t	scsi_hba_barrier_cv;
static struct scsi_hba_barrier {
	struct scsi_hba_barrier	*barrier_next;
	clock_t			barrier_endtime;
	dev_info_t		*barrier_probe;
}		*scsi_hba_barrier_list;
static int	scsi_hba_devi_is_barrier(dev_info_t *probe);
static void	scsi_hba_barrier_tran_tgt_free(dev_info_t *probe);
static void	scsi_hba_barrier_add(dev_info_t *probe, int seconds);
static int	scsi_hba_remove_node(dev_info_t *child);
static void	scsi_hba_barrier_daemon(void *arg);

/* LUN-change ASC/ASCQ processing data structures (stage1 and stage2) */
static kmutex_t		scsi_lunchg1_mutex;
static kcondvar_t	scsi_lunchg1_cv;
static struct scsi_pkt	*scsi_lunchg1_list;
static void		scsi_lunchg1_daemon(void *arg);
static kmutex_t		scsi_lunchg2_mutex;
static kcondvar_t	scsi_lunchg2_cv;
static struct scsi_lunchg2 {
	struct scsi_lunchg2	*lunchg2_next;
	char			*lunchg2_path;
}			*scsi_lunchg2_list;
static void		scsi_lunchg2_daemon(void *arg);

static int	scsi_findchild(dev_info_t *self, char *name, char *addr,
    int init, dev_info_t **dchildp, mdi_pathinfo_t **pchildp, int *ppi);

/* return value defines for scsi_findchild */
#define	CHILD_TYPE_NONE		0
#define	CHILD_TYPE_DEVINFO	1
#define	CHILD_TYPE_PATHINFO	2

/*
 * Enumeration code path currently being followed. SE_BUSCONFIG results in
 * DEVI_SID_NODEID, and SE_HP (hotplug) results in DEVI_SID_HP_NODEID.
 *
 * Since hotplug enumeration is based on information obtained from hardware
 * (tgtmap/report_lun) the type/severity of enumeration error messages is
 * sometimes based SE_HP (indirectly via ndi_dev_is_hotplug_node()). By
 * convention, these messages are all produced by scsi_enumeration_failed().
 */
typedef enum { SE_BUSCONFIG = 0, SE_HP = 1 } scsi_enum_t;

/* compatible properties of driver to use during probe/enumeration operations */
static char	*compatible_probe = "scsa,probe";
static char	*compatible_nodev = "scsa,nodev";
static char	*scsi_probe_ascii[] = SCSIPROBE_ASCII;

/* number of LUNs we attempt to get on the first SCMD_REPORT_LUNS command */
int	scsi_lunrpt_default_max = 256;
int	scsi_lunrpt_timeout = 3;	/* seconds */

/*
 * Only enumerate one lun if reportluns fails on a SCSI_VERSION_3 device
 * (tunable based on calling context).
 */
int	scsi_lunrpt_failed_do1lun = (1 << SE_HP);

/* 'scsi-binding-set' value for legacy enumerated 'spi' transports */
char	*scsi_binding_set_spi = "spi";

/* enable NDI_DEVI_DEBUG for bus_[un]config operations */
int	scsi_hba_bus_config_debug = 0;

/* DEBUG: enable NDI_DEVI_REMOVE for bus_unconfig of dynamic node */
int	scsi_hba_bus_unconfig_remove = 0;

/* number of probe serilization messages */
int	scsi_hba_wait_msg = 5;

/*
 * Establish the timeout used to cache (in the probe node) the fact that the
 * device does not exist. This replaces the target specific probe cache.
 */
int	scsi_hba_barrier_timeout = (60);		/* seconds */

#ifdef	DEBUG
int	scsi_hba_bus_config_failure_msg = 0;
int	scsi_hba_bus_config_failure_dbg = 0;
int	scsi_hba_bus_config_success_msg = 0;
int	scsi_hba_bus_config_success_dbg = 0;
#endif	/* DEBUG */

/*
 * Structure for scsi_hba_iportmap_* implementation/wrap.
 */
typedef struct impl_scsi_iportmap {
	dev_info_t	*iportmap_hba_dip;
	damap_t		*iportmap_dam;
	int		iportmap_create_window;
	uint64_t	iportmap_create_time;		/* clock64_t */
	int		iportmap_create_csync_usec;
	int		iportmap_settle_usec;
	int		iportmap_sync_cnt;
} impl_scsi_iportmap_t;

/*
 * Structure for scsi_hba_tgtmap_* implementation/wrap.
 *
 * Every call to scsi_hba_tgtmap_set_begin will increment tgtmap_reports,
 * and a call to scsi_hba_tgtmap_set_end will reset tgtmap_reports to zero.
 * If, in scsi_hba_tgtmap_set_begin, we detect a tgtmap_reports value of
 * scsi_hba_tgtmap_reports_max we produce a message to indicate that
 * the caller is never completing an observation (i.e. we are not making
 * any forward progress). If this message occurs, it indicates that the
 * solaris hotplug ramifications at the target and lun level are no longer
 * tracking.
 *
 * NOTE: LUNMAPSIZE OK for now, but should be dynamic in reportlun code.
 */
typedef struct impl_scsi_tgtmap {
	scsi_hba_tran_t *tgtmap_tran;
	int		tgtmap_reports;			/* _begin, no _end */
	int		tgtmap_noisy;
	scsi_tgt_activate_cb_t		tgtmap_activate_cb;
	scsi_tgt_deactivate_cb_t	tgtmap_deactivate_cb;
	void		*tgtmap_mappriv;
	damap_t		*tgtmap_dam[SCSI_TGT_NTYPES];
	int		tgtmap_create_window;
	uint64_t	tgtmap_create_time;		/* clock64_t */
	int		tgtmap_create_csync_usec;
	int		tgtmap_settle_usec;
	int		tgtmap_sync_cnt;
} impl_scsi_tgtmap_t;
#define	LUNMAPSIZE 256		/* 256 LUNs/target */

/* Produce warning if number of begins without an end exceed this value */
int	scsi_hba_tgtmap_reports_max = 256;

static int	scsi_tgtmap_sync(scsi_hba_tgtmap_t *, int);

/* Default settle_usec damap_sync factor */
int	scsi_hba_map_settle_f = 10;


/* Prototype for static dev_ops devo_*() functions */
static int	scsi_hba_info(
			dev_info_t		*self,
			ddi_info_cmd_t		infocmd,
			void			*arg,
			void			**result);

/* Prototypes for static bus_ops bus_*() functions */
static int	scsi_hba_bus_ctl(
			dev_info_t		*self,
			dev_info_t		*child,
			ddi_ctl_enum_t		op,
			void			*arg,
			void			*result);

static int	scsi_hba_map_fault(
			dev_info_t		*self,
			dev_info_t		*child,
			struct hat		*hat,
			struct seg		*seg,
			caddr_t			addr,
			struct devpage		*dp,
			pfn_t			pfn,
			uint_t			prot,
			uint_t			lock);

static int	scsi_hba_get_eventcookie(
			dev_info_t		*self,
			dev_info_t		*child,
			char			*name,
			ddi_eventcookie_t	*eventp);

static int	scsi_hba_add_eventcall(
			dev_info_t		*self,
			dev_info_t		*child,
			ddi_eventcookie_t	event,
			void			(*callback)(
				dev_info_t		*dip,
				ddi_eventcookie_t	event,
				void			*arg,
				void			*bus_impldata),
			void			*arg,
			ddi_callback_id_t	*cb_id);

static int	scsi_hba_remove_eventcall(
			dev_info_t		*self,
			ddi_callback_id_t	id);

static int	scsi_hba_post_event(
			dev_info_t		*self,
			dev_info_t		*child,
			ddi_eventcookie_t	event,
			void			*bus_impldata);

static int	scsi_hba_bus_config(
			dev_info_t		*self,
			uint_t			flags,
			ddi_bus_config_op_t	op,
			void			*arg,
			dev_info_t		**childp);

static int	scsi_hba_bus_unconfig(
			dev_info_t		*self,
			uint_t			flags,
			ddi_bus_config_op_t	op,
			void			*arg);

static int	scsi_hba_fm_init_child(
			dev_info_t		*self,
			dev_info_t		*child,
			int			cap,
			ddi_iblock_cookie_t	*ibc);

static int	scsi_hba_bus_power(
			dev_info_t		*self,
			void			*impl_arg,
			pm_bus_power_op_t	op,
			void			*arg,
			void			*result);

/* bus_ops vector for SCSI HBA's. */
static struct bus_ops scsi_hba_busops = {
	BUSO_REV,
	nullbusmap,			/* bus_map */
	NULL,				/* bus_get_intrspec */
	NULL,				/* bus_add_intrspec */
	NULL,				/* bus_remove_intrspec */
	scsi_hba_map_fault,		/* bus_map_fault */
	NULL,				/* bus_dma_map */
	ddi_dma_allochdl,		/* bus_dma_allochdl */
	ddi_dma_freehdl,		/* bus_dma_freehdl */
	ddi_dma_bindhdl,		/* bus_dma_bindhdl */
	ddi_dma_unbindhdl,		/* bus_unbindhdl */
	ddi_dma_flush,			/* bus_dma_flush */
	ddi_dma_win,			/* bus_dma_win */
	ddi_dma_mctl,			/* bus_dma_ctl */
	scsi_hba_bus_ctl,		/* bus_ctl */
	ddi_bus_prop_op,		/* bus_prop_op */
	scsi_hba_get_eventcookie,	/* bus_get_eventcookie */
	scsi_hba_add_eventcall,		/* bus_add_eventcall */
	scsi_hba_remove_eventcall,	/* bus_remove_eventcall */
	scsi_hba_post_event,		/* bus_post_event */
	NULL,				/* bus_intr_ctl */
	scsi_hba_bus_config,		/* bus_config */
	scsi_hba_bus_unconfig,		/* bus_unconfig */
	scsi_hba_fm_init_child,		/* bus_fm_init */
	NULL,				/* bus_fm_fini */
	NULL,				/* bus_fm_access_enter */
	NULL,				/* bus_fm_access_exit */
	scsi_hba_bus_power		/* bus_power */
};

/* cb_ops for hotplug :devctl and :scsi support */
static struct cb_ops scsi_hba_cbops = {
	scsi_hba_open,
	scsi_hba_close,
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	scsi_hba_ioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* prop_op */
	NULL,			/* stream */
	D_NEW|D_MP|D_HOTPLUG,	/* cb_flag */
	CB_REV,			/* rev */
	nodev,			/* int (*cb_aread)() */
	nodev			/* int (*cb_awrite)() */
};

/* Prototypes for static scsi_hba.c/SCSA private lunmap interfaces */
static int	scsi_lunmap_create(
			dev_info_t		*self,
			impl_scsi_tgtmap_t	*tgtmap,
			char			*tgt_addr);
static void	scsi_lunmap_destroy(
			dev_info_t		*self,
			impl_scsi_tgtmap_t	*tgtmap,
			char			*tgt_addr);
static void	scsi_lunmap_set_begin(
			dev_info_t		*self,
			damap_t			*lundam);
static int	scsi_lunmap_set_add(
			dev_info_t		*self,
			damap_t			*lundam,
			char			*taddr,
			scsi_lun64_t		lun_num,
			int			lun_sfunc);
static void	scsi_lunmap_set_end(
			dev_info_t		*self,
			damap_t			*lundam);

/* Prototypes for static misc. scsi_hba.c private bus_config interfaces */
static int scsi_hba_bus_config_iports(dev_info_t *self, uint_t flags,
    ddi_bus_config_op_t op, void *arg, dev_info_t **childp);
static int scsi_hba_bus_config_spi(dev_info_t *self, uint_t flags,
    ddi_bus_config_op_t op, void *arg, dev_info_t **childp);
static dev_info_t *scsi_hba_bus_config_port(dev_info_t *self,
    char *nameaddr, scsi_enum_t se);

#ifdef	sparc
static int scsi_hba_bus_config_prom_node(dev_info_t *self, uint_t flags,
    void *arg, dev_info_t **childp);
#endif	/* sparc */


/*
 * SCSI_HBA_LOG is used for all messages. A logging level is specified when
 * generating a message. Some levels correspond directly to cmn_err levels,
 * some are associated with increasing levels diagnostic/debug output (LOG1-4),
 * and others are associated with specific levels of interface (LOGMAP).
 * For _LOG() messages, a __func__ prefix will identify the function origin
 * of the message. For _LOG_NF messages, there is no function prefix or
 * self/child context. Filtering of messages is provided based on logging
 * level, but messages with cmn_err logging level and messages generated
 * generated with _LOG_NF() are never filtered.
 *
 * For debugging, more complete information can be displayed with each message
 * (full device path and pointer values) by adjusting scsi_hba_log_info.
 */
/* logging levels */
#define	SCSI_HBA_LOGCONT	CE_CONT
#define	SCSI_HBA_LOGNOTE	CE_NOTE
#define	SCSI_HBA_LOGWARN	CE_WARN
#define	SCSI_HBA_LOGPANIC	CE_PANIC
#define	SCSI_HBA_LOGIGNORE	CE_IGNORE
#define	SCSI_HBA_LOG_CE_MASK	0x0000000F	/* no filter for these levels */
#define	SCSI_HBA_LOG1		0x00000010	/* DIAG1 level enable */
#define	SCSI_HBA_LOG2		0x00000020	/* DIAG2 level enable */
#define	SCSI_HBA_LOG3		0x00000040	/* DIAG3 level enable */
#define	SCSI_HBA_LOG4		0x00000080	/* DIAG4 level enable */
#define	SCSI_HBA_LOGMAPPHY	0x00000100	/* MAPPHY level enable */
#define	SCSI_HBA_LOGMAPIPT	0x00000200	/* MAPIPT level enable */
#define	SCSI_HBA_LOGMAPTGT	0x00000400	/* MAPTGT level enable */
#define	SCSI_HBA_LOGMAPLUN	0x00000800	/* MAPLUN level enable */
#define	SCSI_HBA_LOGMAPCFG	0x00001000	/* MAPCFG level enable */
#define	SCSI_HBA_LOGMAPUNCFG	0x00002000	/* MAPUNCFG level enable */
#define	SCSI_HBA_LOGTRACE	0x00010000	/* TRACE enable */
#if (CE_CONT | CE_NOTE | CE_WARN | CE_PANIC | CE_IGNORE) > SCSI_HBA_LOG_CE_MASK
Error, problem with CE_ definitions
#endif

/*
 * Tunable log message augmentation and filters: filters do not apply to
 * SCSI_HBA_LOG_CE_MASK level messages or LOG_NF() messages.
 *
 * An example set of /etc/system tunings to simplify debug a SCSA pHCI HBA
 * driver called "pmcs", including "scsi_vhci" operation, by capturing
 * log information in the system log might be:
 *
 * echo "set scsi:scsi_hba_log_filter_level=0x3ff0"		>> /etc/system
 * echo "set scsi:scsi_hba_log_filter_phci=\"pmcs\""		>> /etc/system
 * echo "set scsi:scsi_hba_log_filter_vhci=\"scsi_vhci\""	>> /etc/system
 *
 * To capture information on just HBA-SCSAv3 *map operation, use
 * echo "set scsi:scsi_hba_log_filter_level=0x3f10"		>> /etc/system
 *
 * For debugging an HBA driver, you may also want to set:
 *
 * echo "set scsi:scsi_hba_log_align=1"				>> /etc/system
 * echo "set scsi:scsi_hba_log_mt_disable=0x6"			>> /etc/system
 * echo "set mtc_off=1"						>> /etc/system
 * echo "set mdi_mtc_off=1"					>> /etc/system
 * echo "set scsi:scsi_hba_log_fcif=0"				>> /etc/system
 */
int		scsi_hba_log_filter_level =
			SCSI_HBA_LOG1 |
			0;
char		*scsi_hba_log_filter_phci = "\0\0\0\0\0\0\0\0\0\0\0\0";
char		*scsi_hba_log_filter_vhci = "\0\0\0\0\0\0\0\0\0\0\0\0";
int		scsi_hba_log_align = 0;	/* NOTE: will not cause truncation */
int		scsi_hba_log_fcif = '!'; /* "^!?" first char in format */
					/* NOTE: iff level > SCSI_HBA_LOG1 */
					/* '\0'0x00 -> console and system log */
					/* '^' 0x5e -> console_only */
					/* '!' 0x21 -> system log only */
					/* '?' 0x2F -> See cmn_err(9F) */
int		scsi_hba_log_info =	/* augmentation: extra info output */
			(0 << 0) |	/* 0x0001: process information */
			(0 << 1) |	/* 0x0002: full /devices path */
			(0 << 2);	/* 0x0004: devinfo pointer */

int		scsi_hba_log_mt_disable =
			/* SCSI_ENUMERATION_MT_LUN_DISABLE |	(ie 0x02) */
			/* SCSI_ENUMERATION_MT_TARGET_DISABLE |	(ie 0x04) */
			0;

/* static data for HBA logging subsystem */
static kmutex_t	scsi_hba_log_mutex;
static char	scsi_hba_log_i[512];
static char	scsi_hba_log_buf[512];
static char	scsi_hba_fmt[512];

/* Macros to use in scsi_hba.c source code below */
#define	SCSI_HBA_LOG(x)	scsi_hba_log x
#define	_LOG(level)	SCSI_HBA_LOG##level, __func__
#define	_MAP(map)	SCSI_HBA_LOGMAP##map, __func__
#define	_LOG_NF(level)	SCSI_HBA_LOG##level, NULL, NULL, NULL
#define	_LOG_TRACE	_LOG(TRACE)
#define	_LOGLUN		_MAP(LUN)
#define	_LOGTGT		_MAP(TGT)
#define	_LOGIPT		_MAP(IPT)
#define	_LOGPHY		_MAP(PHY)
#define	_LOGCFG		_MAP(CFG)
#define	_LOGUNCFG	_MAP(UNCFG)

/*PRINTFLIKE5*/
static void
scsi_hba_log(int level, const char *func, dev_info_t *self, dev_info_t *child,
    const char *fmt, ...)
{
	va_list		ap;
	int		clevel;
	int		align;
	char		*info;
	char		*f;
	char		*ua;

	/* derive self from child's parent */
	if ((self == NULL) && child)
		self = ddi_get_parent(child);

	/* no filtering of SCSI_HBA_LOG_CE_MASK or LOG_NF messages */
	if (((level & SCSI_HBA_LOG_CE_MASK) != level) && (func != NULL)) {
		/* scsi_hba_log_filter_level: filter on level as bitmask */
		if ((level & scsi_hba_log_filter_level) == 0)
			return;

		/* scsi_hba_log_filter_phci/vhci: on name of driver */
		if (*scsi_hba_log_filter_phci &&
		    ((self == NULL) ||
		    (ddi_driver_name(self) == NULL) ||
		    strcmp(ddi_driver_name(self), scsi_hba_log_filter_phci))) {
			/* does not match pHCI, check vHCI */
			if (*scsi_hba_log_filter_vhci &&
			    ((self == NULL) ||
			    (ddi_driver_name(self) == NULL) ||
			    strcmp(ddi_driver_name(self),
			    scsi_hba_log_filter_vhci))) {
				/* does not match vHCI */
				return;
			}
		}


		/* passed filters, determine align */
		align = scsi_hba_log_align;

		/* shorten func for filtered output */
		if (strncmp(func, "scsi_hba_", 9) == 0)
			func += 9;
		if (strncmp(func, "scsi_", 5) == 0)
			func += 5;
	} else {
		/* don't align output that is never filtered */
		align = 0;
	}

	/* determine the cmn_err form from the level */
	clevel = ((level & SCSI_HBA_LOG_CE_MASK) == level) ? level : CE_CONT;

	/* protect common buffers used to format output */
	mutex_enter(&scsi_hba_log_mutex);

	/* skip special first characters, we add them back below */
	f = (char *)fmt;
	if (*f && strchr("^!?", *f))
		f++;
	va_start(ap, fmt);
	(void) vsprintf(scsi_hba_log_buf, f, ap);
	va_end(ap);

	/* augment message with 'information' */
	info = scsi_hba_log_i;
	*info = '\0';
	if ((scsi_hba_log_info & 0x0001) && curproc && PTOU(curproc)->u_comm) {
		(void) sprintf(info, "%s[%d]%p ",
		    PTOU(curproc)->u_comm, curproc->p_pid, (void *)curthread);
		info += strlen(info);
	}
	if (self) {
		if ((scsi_hba_log_info & 0x0004) && (child || self)) {
			(void) sprintf(info, "%p ",
			    (void *)(child ? child : self));
			info += strlen(info);
		}
		if (scsi_hba_log_info & 0x0002)	{
			(void) ddi_pathname(child ? child : self, info);
			(void) strcat(info, " ");
			info += strlen(info);
		}

		/* always provide 'default' information about self &child */
		(void) sprintf(info, "%s%d ", ddi_driver_name(self),
		    ddi_get_instance(self));
		info += strlen(info);
		if (child) {
			ua = ddi_get_name_addr(child);
			(void) sprintf(info, "%s@%s ",
			    ddi_node_name(child), (ua && *ua) ? ua : "");
			info += strlen(info);
		}
	}

	/* turn off alignment if truncation would occur */
	if (align && ((strlen(func) > 18) || (strlen(scsi_hba_log_i) > 36)))
		align = 0;

	/* adjust for aligned output */
	if (align) {
		if (func == NULL)
			func = "";
		/* remove trailing blank with align output */
		if ((info != scsi_hba_log_i) && (*(info -1) == '\b'))
			*(info - 1) = '\0';
	}

	/* special "first character in format" must be in format itself */
	f = scsi_hba_fmt;
	if (fmt[0] && strchr("^!?", fmt[0]))
		*f++ = fmt[0];
	else if (scsi_hba_log_fcif && (level > SCSI_HBA_LOG1))
		*f++ = (char)scsi_hba_log_fcif;		/* add global fcif */
	if (align)
		(void) sprintf(f, "%s", "%-18.18s: %36.36s: %s%s");
	else
		(void) sprintf(f, "%s", func ? "%s: %s%s%s" : "%s%s%s");

	if (func)
		cmn_err(clevel, scsi_hba_fmt, func, scsi_hba_log_i,
		    scsi_hba_log_buf, clevel == CE_CONT ? "\n" : "");
	else
		cmn_err(clevel, scsi_hba_fmt, scsi_hba_log_i,
		    scsi_hba_log_buf, clevel == CE_CONT ? "\n" : "");
	mutex_exit(&scsi_hba_log_mutex);
}

int	scsi_enumeration_failed_panic = 0;
int	scsi_enumeration_failed_hotplug = 1;

static void
scsi_enumeration_failed(dev_info_t *child, scsi_enum_t se,
    char *arg, char *when)
{
	/* If 'se' is -1 the 'se' value comes from child. */
	if (se == -1) {
		ASSERT(child);
		se = ndi_dev_is_hotplug_node(child) ? SE_HP : SE_BUSCONFIG;
	}

	if (scsi_enumeration_failed_panic) {
		/* set scsi_enumeration_failed_panic to debug */
		SCSI_HBA_LOG((_LOG(PANIC), NULL, child,
		    "%s%senumeration failed during %s",
		    arg ? arg : "", arg ? " " : "", when));
	} else if (scsi_enumeration_failed_hotplug && (se == SE_HP)) {
		/* set scsi_enumeration_failed_hotplug for console messages */
		SCSI_HBA_LOG((_LOG(WARN), NULL, child,
		    "%s%senumeration failed during %s",
		    arg ? arg : "", arg ? " " : "", when));
	} else {
		/* default */
		SCSI_HBA_LOG((_LOG(2), NULL, child,
		    "%s%senumeration failed during %s",
		    arg ? arg : "", arg ? " " : "", when));
	}
}

/*
 * scsi_hba version of [nm]di_devi_enter/[nm]di_devi_exit that detects if HBA
 * is a PHCI, and chooses mdi/ndi locking implementation.
 */
static void
scsi_hba_devi_enter(dev_info_t *self, int *circp)
{
	if (MDI_PHCI(self))
		mdi_devi_enter(self, circp);
	else
		ndi_devi_enter(self, circp);
}

static int
scsi_hba_devi_tryenter(dev_info_t *self, int *circp)
{
	if (MDI_PHCI(self))
		return (mdi_devi_tryenter(self, circp));
	else
		return (ndi_devi_tryenter(self, circp));
}

static void
scsi_hba_devi_exit(dev_info_t *self, int circ)
{
	if (MDI_PHCI(self))
		mdi_devi_exit(self, circ);
	else
		ndi_devi_exit(self, circ);
}

static void
scsi_hba_devi_enter_phci(dev_info_t *self, int *circp)
{
	if (MDI_PHCI(self))
		mdi_devi_enter_phci(self, circp);
}

static void
scsi_hba_devi_exit_phci(dev_info_t *self, int circ)
{
	if (MDI_PHCI(self))
		mdi_devi_exit_phci(self, circ);
}

static int
scsi_hba_dev_is_sid(dev_info_t *child)
{
	/*
	 * Use ndi_dev_is_persistent_node instead of ddi_dev_is_sid to avoid
	 * any possible locking issues in mixed nexus devctl code (like usb).
	 */
	return (ndi_dev_is_persistent_node(child));
}

/*
 * Called from _init() when loading "scsi" module
 */
void
scsi_initialize_hba_interface()
{
	SCSI_HBA_LOG((_LOG_TRACE, NULL, NULL, __func__));

	/* We need "scsiprobe" and "scsinodev" as an alias or a driver. */
	if (ddi_name_to_major(compatible_probe) == DDI_MAJOR_T_NONE) {
		SCSI_HBA_LOG((_LOG_NF(WARN), "failed to resolve '%s' "
		    "driver alias, defaulting to 'nulldriver'",
		    compatible_probe));

		/* If no "nulldriver" driver nothing will work... */
		compatible_probe = "nulldriver";
		if (ddi_name_to_major(compatible_probe) == DDI_MAJOR_T_NONE)
			SCSI_HBA_LOG((_LOG_NF(WARN), "no probe '%s' driver, "
			    "system misconfigured", compatible_probe));
	}
	if (ddi_name_to_major(compatible_nodev) == DDI_MAJOR_T_NONE) {
		SCSI_HBA_LOG((_LOG_NF(WARN), "failed to resolve '%s' "
		    "driver alias, defaulting to 'nulldriver'",
		    compatible_nodev));

		/* If no "nulldriver" driver nothing will work... */
		compatible_nodev = "nulldriver";
		if (ddi_name_to_major(compatible_nodev) == DDI_MAJOR_T_NONE)
			SCSI_HBA_LOG((_LOG_NF(WARN), "no nodev '%s' driver, "
			    "system misconfigured", compatible_nodev));
	}

	/*
	 * Verify our special node name "probe" will not be used in other ways.
	 * Don't expect things to work if they are.
	 */
	if (ddi_major_to_name(ddi_name_to_major("probe")))
		SCSI_HBA_LOG((_LOG_NF(WARN),
		    "driver already using special node name 'probe'"));

	mutex_init(&scsi_log_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&scsi_flag_nointr_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&scsi_flag_nointr_cv, NULL, CV_DRIVER, NULL);
	mutex_init(&scsi_hba_log_mutex, NULL, MUTEX_DRIVER, NULL);

	/* initialize the asynchronous barrier deletion daemon */
	mutex_init(&scsi_hba_barrier_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&scsi_hba_barrier_cv, NULL, CV_DRIVER, NULL);
	(void) thread_create(NULL, 0,
	    (void (*)())scsi_hba_barrier_daemon, NULL,
	    0, &p0, TS_RUN, minclsyspri);

	/* initialize lun change ASC/ASCQ processing daemon (stage1 & stage2) */
	mutex_init(&scsi_lunchg1_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&scsi_lunchg1_cv, NULL, CV_DRIVER, NULL);
	(void) thread_create(NULL, 0,
	    (void (*)())scsi_lunchg1_daemon, NULL,
	    0, &p0, TS_RUN, minclsyspri);
	mutex_init(&scsi_lunchg2_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&scsi_lunchg2_cv, NULL, CV_DRIVER, NULL);
	(void) thread_create(NULL, 0,
	    (void (*)())scsi_lunchg2_daemon, NULL,
	    0, &p0, TS_RUN, minclsyspri);
}

int
scsi_hba_pkt_constructor(void *buf, void *arg, int kmflag)
{
	struct scsi_pkt_cache_wrapper *pktw;
	struct scsi_pkt		*pkt;
	scsi_hba_tran_t		*tran = (scsi_hba_tran_t *)arg;
	int			pkt_len;
	char			*ptr;

	/*
	 * allocate a chunk of memory for the following:
	 * scsi_pkt
	 * pcw_* fields
	 * pkt_ha_private
	 * pkt_cdbp, if needed
	 * (pkt_private always null)
	 * pkt_scbp, if needed
	 */
	pkt_len = tran->tran_hba_len + sizeof (struct scsi_pkt_cache_wrapper);
	if (tran->tran_hba_flags & SCSI_HBA_TRAN_CDB)
		pkt_len += DEFAULT_CDBLEN;
	if (tran->tran_hba_flags & SCSI_HBA_TRAN_SCB)
		pkt_len += DEFAULT_SCBLEN;
	bzero(buf, pkt_len);

	ptr = buf;
	pktw = buf;
	ptr += sizeof (struct scsi_pkt_cache_wrapper);
	pkt = &(pktw->pcw_pkt);
	pkt->pkt_ha_private = (opaque_t)ptr;

	pktw->pcw_magic = PKT_WRAPPER_MAGIC;	/* alloced correctly */
	/*
	 * keep track of the granularity at the time this handle was
	 * allocated
	 */
	pktw->pcw_granular = tran->tran_dma_attr.dma_attr_granular;

	if (ddi_dma_alloc_handle(tran->tran_hba_dip, &tran->tran_dma_attr,
	    kmflag == KM_SLEEP ? SLEEP_FUNC: NULL_FUNC, NULL,
	    &pkt->pkt_handle) != DDI_SUCCESS) {

		return (-1);
	}
	ptr += tran->tran_hba_len;
	if (tran->tran_hba_flags & SCSI_HBA_TRAN_CDB) {
		pkt->pkt_cdbp = (opaque_t)ptr;
		ptr += DEFAULT_CDBLEN;
	}
	pkt->pkt_private = NULL;
	if (tran->tran_hba_flags & SCSI_HBA_TRAN_SCB)
		pkt->pkt_scbp = (opaque_t)ptr;
	if (tran->tran_pkt_constructor)
		return ((*tran->tran_pkt_constructor)(pkt, arg, kmflag));
	else
		return (0);
}

#define	P_TO_TRAN(pkt)	((pkt)->pkt_address.a_hba_tran)

void
scsi_hba_pkt_destructor(void *buf, void *arg)
{
	struct scsi_pkt_cache_wrapper *pktw = buf;
	struct scsi_pkt		*pkt = &(pktw->pcw_pkt);
	scsi_hba_tran_t		*tran = (scsi_hba_tran_t *)arg;

	ASSERT(pktw->pcw_magic == PKT_WRAPPER_MAGIC);
	ASSERT((pktw->pcw_flags & PCW_BOUND) == 0);
	if (tran->tran_pkt_destructor)
		(*tran->tran_pkt_destructor)(pkt, arg);

	/* make sure nobody messed with our pointers */
	ASSERT(pkt->pkt_ha_private == (opaque_t)((char *)pkt +
	    sizeof (struct scsi_pkt_cache_wrapper)));
	ASSERT(((tran->tran_hba_flags & SCSI_HBA_TRAN_SCB) == 0) ||
	    (pkt->pkt_scbp == (opaque_t)((char *)pkt +
	    tran->tran_hba_len +
	    (((tran->tran_hba_flags & SCSI_HBA_TRAN_CDB) == 0) ?
	    0 : DEFAULT_CDBLEN) +
	    DEFAULT_PRIVLEN + sizeof (struct scsi_pkt_cache_wrapper))));
	ASSERT(((tran->tran_hba_flags & SCSI_HBA_TRAN_CDB) == 0) ||
	    (pkt->pkt_cdbp == (opaque_t)((char *)pkt +
	    tran->tran_hba_len +
	    sizeof (struct scsi_pkt_cache_wrapper))));
	ASSERT(pkt->pkt_handle);
	ddi_dma_free_handle(&pkt->pkt_handle);
	pkt->pkt_handle = NULL;
	pkt->pkt_numcookies = 0;
	pktw->pcw_total_xfer = 0;
	pktw->pcw_totalwin = 0;
	pktw->pcw_curwin = 0;
}

/*
 * Called by an HBA from _init() to plumb in common SCSA bus_ops and
 * cb_ops for the HBA's :devctl and :scsi minor nodes.
 */
int
scsi_hba_init(struct modlinkage *modlp)
{
	struct dev_ops *hba_dev_ops;

	SCSI_HBA_LOG((_LOG_TRACE, NULL, NULL, __func__));

	/*
	 * Get a pointer to the dev_ops structure of the HBA and plumb our
	 * bus_ops vector into the HBA's dev_ops structure.
	 */
	hba_dev_ops = ((struct modldrv *)(modlp->ml_linkage[0]))->drv_dev_ops;
	ASSERT(hba_dev_ops->devo_bus_ops == NULL);
	hba_dev_ops->devo_bus_ops = &scsi_hba_busops;

	/*
	 * Plumb our cb_ops vector into the HBA's dev_ops structure to
	 * provide getinfo and hotplugging ioctl support if the HBA driver
	 * does not already provide this support.
	 */
	if (hba_dev_ops->devo_cb_ops == NULL) {
		hba_dev_ops->devo_cb_ops = &scsi_hba_cbops;
	}
	if (hba_dev_ops->devo_cb_ops->cb_open == scsi_hba_open) {
		ASSERT(hba_dev_ops->devo_cb_ops->cb_close == scsi_hba_close);
		hba_dev_ops->devo_getinfo = scsi_hba_info;
	}
	return (0);
}

/*
 * Called by an HBA attach(9E) to allocate a scsi_hba_tran(9S) structure. An
 * HBA driver will then initialize the structure and then call
 * scsi_hba_attach_setup(9F).
 */
/*ARGSUSED*/
scsi_hba_tran_t *
scsi_hba_tran_alloc(
	dev_info_t		*self,
	int			flags)
{
	scsi_hba_tran_t		*tran;

	SCSI_HBA_LOG((_LOG_TRACE, self, NULL, __func__));

	/* allocate SCSA flavors for self */
	ndi_flavorv_alloc(self, SCSA_NFLAVORS);

	tran = kmem_zalloc(sizeof (scsi_hba_tran_t),
	    (flags & SCSI_HBA_CANSLEEP) ? KM_SLEEP : KM_NOSLEEP);

	if (tran) {
		tran->tran_interconnect_type = INTERCONNECT_PARALLEL;

		/*
		 * HBA driver called scsi_hba_tran_alloc(), so tran structure
		 * is proper size and unused/newer fields are zero.
		 *
		 * NOTE: We use SCSA_HBA_SCSA_TA as an obtuse form of
		 * versioning to detect old HBA drivers that do not use
		 * scsi_hba_tran_alloc, and would present garbage data
		 * (instead of valid/zero data) for newer tran fields.
		 */
		tran->tran_hba_flags |= SCSI_HBA_SCSA_TA;
	}

	return (tran);
}

/*
 * Called by an HBA to free a scsi_hba_tran structure
 */
void
scsi_hba_tran_free(
	scsi_hba_tran_t		*tran)
{
	SCSI_HBA_LOG((_LOG_TRACE, tran->tran_hba_dip, NULL, __func__));

	kmem_free(tran, sizeof (scsi_hba_tran_t));
}

int
scsi_tran_ext_alloc(
	scsi_hba_tran_t		*tran,
	size_t			length,
	int			flags)
{
	void	*tran_ext;
	int	ret = DDI_FAILURE;

	tran_ext = kmem_zalloc(length,
	    (flags & SCSI_HBA_CANSLEEP) ? KM_SLEEP : KM_NOSLEEP);
	if (tran_ext != NULL) {
		tran->tran_extension = tran_ext;
		ret = DDI_SUCCESS;
	}
	return (ret);
}

void
scsi_tran_ext_free(
	scsi_hba_tran_t		*tran,
	size_t			length)
{
	if (tran->tran_extension != NULL) {
		kmem_free(tran->tran_extension, length);
		tran->tran_extension = NULL;
	}
}

/*
 * Common nexus teardown code: used by both scsi_hba_detach() on SCSA HBA node
 * and iport_postdetach_tran_scsi_device() on a SCSA HBA iport node (and for
 * failure cleanup). Undo scsa_nexus_setup in reverse order.
 *
 * NOTE: Since we are in the Solaris IO framework, we can depend on
 * undocumented cleanup operations performed by other parts of the framework:
 * like detach_node() calling ddi_prop_remove_all() and
 * ddi_remove_minor_node(,NULL).
 */
static void
scsa_nexus_teardown(dev_info_t *self, scsi_hba_tran_t	*tran)
{
	/* Teardown FMA. */
	if (tran->tran_hba_flags & SCSI_HBA_SCSA_FM) {
		ddi_fm_fini(self);
		tran->tran_hba_flags &= ~SCSI_HBA_SCSA_FM;
	}
}

/*
 * Common nexus setup code: used by both scsi_hba_attach_setup() on SCSA HBA
 * node and iport_preattach_tran_scsi_device() on a SCSA HBA iport node.
 *
 * This code makes no assumptions about tran use by scsi_device children.
 */
static int
scsa_nexus_setup(dev_info_t *self, scsi_hba_tran_t *tran)
{
	int		capable;
	int		scsa_minor;

	/*
	 * NOTE: SCSA maintains an 'fm-capable' domain, in tran_fm_capable,
	 * that is not dependent (limited by) the capabilities of its parents.
	 * For example a devinfo node in a branch that is not
	 * DDI_FM_EREPORT_CAPABLE may report as capable, via tran_fm_capable,
	 * to its scsi_device children.
	 *
	 * Get 'fm-capable' property from driver.conf, if present. If not
	 * present, default to the scsi_fm_capable global (which has
	 * DDI_FM_EREPORT_CAPABLE set by default).
	 */
	if (tran->tran_fm_capable == DDI_FM_NOT_CAPABLE)
		tran->tran_fm_capable = ddi_prop_get_int(DDI_DEV_T_ANY, self,
		    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
		    "fm-capable", scsi_fm_capable);

	/*
	 * If an HBA is *not* doing its own fma support by calling
	 * ddi_fm_init() prior to scsi_hba_attach_setup(), we provide a minimal
	 * common SCSA implementation so that scsi_device children can generate
	 * ereports via scsi_fm_ereport_post().  We use ddi_fm_capable() to
	 * detect an HBA calling ddi_fm_init() prior to scsi_hba_attach_setup().
	 */
	if (tran->tran_fm_capable &&
	    (ddi_fm_capable(self) == DDI_FM_NOT_CAPABLE)) {
		/*
		 * We are capable of something, pass our capabilities up the
		 * tree, but use a local variable so our parent can't limit
		 * our capabilities (we don't want our parent to clear
		 * DDI_FM_EREPORT_CAPABLE).
		 *
		 * NOTE: iblock cookies are not important because scsi HBAs
		 * always interrupt below LOCK_LEVEL.
		 */
		capable = tran->tran_fm_capable;
		ddi_fm_init(self, &capable, NULL);

		/*
		 * Set SCSI_HBA_SCSA_FM bit to mark us as using the common
		 * minimal SCSA fm implementation -  we called ddi_fm_init(),
		 * so we are responsible for calling ddi_fm_fini() in
		 * scsi_hba_detach().
		 *
		 * NOTE: if ddi_fm_init fails to establish handle, SKIP cleanup.
		 */
		if (DEVI(self)->devi_fmhdl)
			tran->tran_hba_flags |= SCSI_HBA_SCSA_FM;
	}

	/* If SCSA responsible for for minor nodes, create :devctl minor. */
	scsa_minor = (ddi_get_driver(self)->devo_cb_ops->cb_open ==
	    scsi_hba_open) ? 1 : 0;
	if (scsa_minor && ((ddi_create_minor_node(self, "devctl", S_IFCHR,
	    INST2DEVCTL(ddi_get_instance(self)), DDI_NT_SCSI_NEXUS, 0) !=
	    DDI_SUCCESS))) {
		SCSI_HBA_LOG((_LOG(WARN), self, NULL,
		    "can't create :devctl minor node"));
		goto fail;
	}

	return (DDI_SUCCESS);

fail:	scsa_nexus_teardown(self, tran);
	return (DDI_FAILURE);
}

/*
 * Common tran teardown code: used by iport_postdetach_tran_scsi_device() on a
 * SCSA HBA iport node and (possibly) by scsi_hba_detach() on SCSA HBA node
 * (and for failure cleanup). Undo scsa_tran_setup in reverse order.
 *
 * NOTE: Since we are in the Solaris IO framework, we can depend on
 * undocumented cleanup operations performed by other parts of the framework:
 * like detach_node() calling ddi_prop_remove_all() and
 * ddi_remove_minor_node(,NULL).
 */
static void
scsa_tran_teardown(dev_info_t *self, scsi_hba_tran_t *tran)
{
	tran->tran_iport_dip = NULL;

	/* Teardown pHCI registration */
	if (tran->tran_hba_flags & SCSI_HBA_SCSA_PHCI) {
		(void) mdi_phci_unregister(self, 0);
		tran->tran_hba_flags &= ~SCSI_HBA_SCSA_PHCI;
	}
}

/*
 * Common tran setup code: used by iport_preattach_tran_scsi_device() on a
 * SCSA HBA iport node and (possibly) by scsi_hba_attach_setup() on SCSA HBA
 * node.
 */
static int
scsa_tran_setup(dev_info_t *self, scsi_hba_tran_t *tran)
{
	int			scsa_minor;
	int			id;
	char			*scsi_binding_set;
	static const char	*interconnect[] = INTERCONNECT_TYPE_ASCII;

	SCSI_HBA_LOG((_LOG_TRACE, self, NULL, __func__));

	/* If SCSA responsible for for minor nodes, create ":scsi" */
	scsa_minor = (ddi_get_driver(self)->devo_cb_ops->cb_open ==
	    scsi_hba_open) ? 1 : 0;
	if (scsa_minor && (ddi_create_minor_node(self, "scsi", S_IFCHR,
	    INST2SCSI(ddi_get_instance(self)),
	    DDI_NT_SCSI_ATTACHMENT_POINT, 0) != DDI_SUCCESS)) {
		SCSI_HBA_LOG((_LOG(WARN), self, NULL,
		    "can't create :scsi minor node"));
		goto fail;
	}

	/*
	 * If the property does not already exist on self then see if we can
	 * pull it from further up the tree and define it on self. If the
	 * property does not exist above (including options.conf) then use the
	 * default value specified (global variable). We pull things down from
	 * above for faster "DDI_PROP_NOTPROM | DDI_PROP_DONTPASS" runtime
	 * access.
	 *
	 * Future: Should we avoid creating properties when value == global?
	 */
#define	CONFIG_INT_PROP(s, p, dv)	{			\
	if ((ddi_prop_exists(DDI_DEV_T_ANY, s,			\
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, p) == 0) &&	\
	    (ndi_prop_update_int(DDI_DEV_T_NONE, s, p,		\
	    ddi_prop_get_int(DDI_DEV_T_ANY, ddi_get_parent(s),	\
	    DDI_PROP_NOTPROM, p, dv)) != DDI_PROP_SUCCESS))	\
		SCSI_HBA_LOG((_LOG(WARN), NULL, s,		\
		    "can't create property '%s'", p));		\
	}

	/* Decorate with scsi configuration properties */
	CONFIG_INT_PROP(self, "scsi-enumeration", scsi_enumeration);
	CONFIG_INT_PROP(self, "scsi-options", scsi_options);
	CONFIG_INT_PROP(self, "scsi-reset-delay", scsi_reset_delay);
	CONFIG_INT_PROP(self, "scsi-watchdog-tick", scsi_watchdog_tick);
	CONFIG_INT_PROP(self, "scsi-selection-timeout", scsi_selection_timeout);
	CONFIG_INT_PROP(self, "scsi-tag-age-limit", scsi_tag_age_limit);

	/*
	 * Pull down the scsi-initiator-id from further up the tree, or as
	 * defined by OBP. Place on node for faster access. NOTE: there is
	 * some confusion about what the name of the property should be.
	 */
	id = ddi_prop_get_int(DDI_DEV_T_ANY, self, 0, "initiator-id", -1);
	if (id == -1)
		id = ddi_prop_get_int(DDI_DEV_T_ANY, self, 0,
		    "scsi-initiator-id", -1);
	if (id != -1)
		CONFIG_INT_PROP(self, "scsi-initiator-id", id);

	/*
	 * If we are responsible for tran allocation, establish
	 * 'initiator-interconnect-type'.
	 */
	if ((tran->tran_hba_flags & SCSI_HBA_SCSA_TA) &&
	    (tran->tran_interconnect_type > 0) &&
	    (tran->tran_interconnect_type < INTERCONNECT_MAX)) {
		if (ndi_prop_update_string(DDI_DEV_T_NONE, self,
		    "initiator-interconnect-type",
		    (char *)interconnect[tran->tran_interconnect_type])
		    != DDI_PROP_SUCCESS) {
			SCSI_HBA_LOG((_LOG(WARN), self, NULL,
			    "failed to establish "
			    "'initiator-interconnect-type'"));
			goto fail;
		}
	}

	/*
	 * The 'scsi-binding-set' property can be defined in driver.conf
	 * files of legacy drivers on an as-needed basis. If 'scsi-binding-set'
	 * is not driver.conf defined, and the HBA is not implementing its own
	 * private bus_config, we define scsi-binding-set to the default
	 * 'spi' legacy value.
	 *
	 * NOTE: This default 'spi' value will be deleted if an HBA driver
	 * ends up using the scsi_hba_tgtmap_create() enumeration services.
	 *
	 * NOTE: If we were ever to decide to derive 'scsi-binding-set' from
	 * the IEEE-1275 'device_type' property then this is where that code
	 * should go - there is not enough consistency in 'device_type' to do
	 * this correctly at this point in time.
	 */
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, self,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "scsi-binding-set",
	    &scsi_binding_set) == DDI_PROP_SUCCESS) {
		SCSI_HBA_LOG((_LOG(2), NULL, self,
		    "external 'scsi-binding-set' \"%s\"", scsi_binding_set));
		ddi_prop_free(scsi_binding_set);
	} else if (scsi_binding_set_spi &&
	    ((tran->tran_bus_config == NULL) ||
	    (tran->tran_bus_config == scsi_hba_bus_config_spi))) {
		if (ndi_prop_update_string(DDI_DEV_T_NONE, self,
		    "scsi-binding-set", scsi_binding_set_spi) !=
		    DDI_PROP_SUCCESS) {
			SCSI_HBA_LOG((_LOG(WARN), self, NULL,
			    "failed to establish 'scsi_binding_set' default"));
			goto fail;
		}
		SCSI_HBA_LOG((_LOG(2), NULL, self,
		    "default 'scsi-binding-set' \"%s\"", scsi_binding_set_spi));
	} else
		SCSI_HBA_LOG((_LOG(2), NULL, self,
		    "no 'scsi-binding-set'"));

	/*
	 * If SCSI_HBA_TRAN_PHCI is set, take care of pHCI registration of the
	 * initiator.
	 */
	if ((tran->tran_hba_flags & SCSI_HBA_TRAN_PHCI) &&
	    (mdi_phci_register(MDI_HCI_CLASS_SCSI, self, 0) == MDI_SUCCESS))
		tran->tran_hba_flags |= SCSI_HBA_SCSA_PHCI;

	/* NOTE: tran_hba_dip is for DMA operation at the HBA node level */
	tran->tran_iport_dip = self;		/* for iport association */
	return (DDI_SUCCESS);

fail:	scsa_tran_teardown(self, tran);
	return (DDI_FAILURE);
}

/*
 * Called by a SCSA HBA driver to attach an instance of the driver to
 * SCSA HBA node  enumerated by PCI.
 */
int
scsi_hba_attach_setup(
	dev_info_t		*self,
	ddi_dma_attr_t		*hba_dma_attr,
	scsi_hba_tran_t		*tran,
	int			flags)
{
	int			len;
	char			cache_name[96];

	SCSI_HBA_LOG((_LOG_TRACE, self, NULL, __func__));

	/*
	 * Verify that we are a driver so other code does not need to
	 * check for NULL ddi_get_driver() result.
	 */
	if (ddi_get_driver(self) == NULL)
		return (DDI_FAILURE);

	/*
	 * Verify that we are called on a SCSA HBA node (function enumerated
	 * by PCI), not on an iport node.
	 */
	ASSERT(scsi_hba_iport_unit_address(self) == NULL);
	if (scsi_hba_iport_unit_address(self))
		return (DDI_FAILURE);		/* self can't be an iport */

	/* Caller must provide the tran. */
	ASSERT(tran);
	if (tran == NULL)
		return (DDI_FAILURE);

	/*
	 * Verify correct scsi_hba_tran_t form:
	 *
	 * o Both or none of tran_get_name/tran_get_addr.
	 *   NOTE: Older  SCSA HBA drivers for SCSI transports with addressing
	 *   that did not fit the SPI "struct scsi_address" model were required
	 *   to implement tran_get_name and tran_get_addr. This is no longer
	 *   true - modern transport drivers should now use common SCSA
	 *   enumeration services.  The SCSA enumeration code will represent
	 *   the unit-address using well-known address properties
	 *   (SCSI_ADDR_PROP_TARGET_PORT, SCSI_ADDR_PROP_LUN64) during
	 *   devinfo/pathinfo node creation. The HBA driver can obtain values
	 *   using scsi_device_prop_lookup_*() from its tran_tgt_init(9E).
	 *
	 */
	if ((tran->tran_get_name == NULL) ^ (tran->tran_get_bus_addr == NULL)) {
		SCSI_HBA_LOG((_LOG(WARN), self, NULL,
		    "should support both or neither: "
		    "tran_get_name, tran_get_bus_addr"));
		return (DDI_FAILURE);
	}

	/*
	 * Establish the devinfo context of this tran structure, preserving
	 * knowledge of how the tran was allocated.
	 */
	tran->tran_hba_dip = self;		/* for DMA */
	tran->tran_hba_flags = (flags & ~SCSI_HBA_SCSA_TA) |
	    (tran->tran_hba_flags & SCSI_HBA_SCSA_TA);

	/* Establish flavor of transport (and ddi_get_driver_private()) */
	ndi_flavorv_set(self, SCSA_FLAVOR_SCSI_DEVICE, tran);

	/*
	 * Note: We only need dma_attr_minxfer and dma_attr_burstsizes
	 * from the DMA attributes. scsi_hba_attach(9f) only guarantees
	 * that these two fields are initialized properly. If this
	 * changes, be sure to revisit the implementation of
	 * scsi_hba_attach(9F).
	 */
	(void) memcpy(&tran->tran_dma_attr, hba_dma_attr,
	    sizeof (ddi_dma_attr_t));

	/* Create tran_setup_pkt(9E) kmem_cache. */
	if (tran->tran_setup_pkt) {
		ASSERT(tran->tran_init_pkt == NULL);
		ASSERT(tran->tran_destroy_pkt == NULL);
		if (tran->tran_init_pkt || tran->tran_destroy_pkt)
			goto fail;

		tran->tran_init_pkt = scsi_init_cache_pkt;
		tran->tran_destroy_pkt = scsi_free_cache_pkt;
		tran->tran_sync_pkt = scsi_sync_cache_pkt;
		tran->tran_dmafree = scsi_cache_dmafree;

		len = sizeof (struct scsi_pkt_cache_wrapper);
		len += ROUNDUP(tran->tran_hba_len);
		if (tran->tran_hba_flags & SCSI_HBA_TRAN_CDB)
			len += ROUNDUP(DEFAULT_CDBLEN);
		if (tran->tran_hba_flags & SCSI_HBA_TRAN_SCB)
			len += ROUNDUP(DEFAULT_SCBLEN);

		(void) snprintf(cache_name, sizeof (cache_name),
		    "pkt_cache_%s_%d", ddi_driver_name(self),
		    ddi_get_instance(self));

		tran->tran_pkt_cache_ptr = kmem_cache_create(
		    cache_name, len, 8, scsi_hba_pkt_constructor,
		    scsi_hba_pkt_destructor, NULL, tran, NULL, 0);
	}

	/* Perform node setup independent of initiator role */
	if (scsa_nexus_setup(self, tran) != DDI_SUCCESS)
		goto fail;

	/*
	 * The SCSI_HBA_HBA flag is passed to scsi_hba_attach_setup when the
	 * HBA driver knows that *all* children of the SCSA HBA node will be
	 * 'iports'. If the SCSA HBA node can have iport children and also
	 * function as an initiator for xxx_device children then it should
	 * not specify SCSI_HBA_HBA in its scsi_hba_attach_setup call. An
	 * HBA driver that does not manage iports should not set SCSA_HBA_HBA.
	 */
	if (tran->tran_hba_flags & SCSI_HBA_HBA) {
		/*
		 * Set the 'ddi-config-driver-node' property on the nexus
		 * node that notify attach_driver_nodes() to configure all
		 * immediate children so that nodes which bind to the
		 * same driver as parent are able to be added into per-driver
		 * list.
		 */
		if (ndi_prop_create_boolean(DDI_DEV_T_NONE,
		    self, "ddi-config-driver-node") != DDI_PROP_SUCCESS)
			goto fail;
	} else {
		if (scsa_tran_setup(self, tran) != DDI_SUCCESS)
			goto fail;
	}

	return (DDI_SUCCESS);

fail:	(void) scsi_hba_detach(self);
	return (DDI_FAILURE);
}

/*
 * Called by an HBA to detach an instance of the driver. This may be called
 * for SCSA HBA nodes and for SCSA iport nodes.
 */
int
scsi_hba_detach(dev_info_t *self)
{
	scsi_hba_tran_t		*tran;

	ASSERT(scsi_hba_iport_unit_address(self) == NULL);
	if (scsi_hba_iport_unit_address(self))
		return (DDI_FAILURE);		/* self can't be an iport */

	/* Check all error return conditions upfront */
	tran = ndi_flavorv_get(self, SCSA_FLAVOR_SCSI_DEVICE);
	ASSERT(tran);
	if (tran == NULL)
		return (DDI_FAILURE);

	ASSERT(tran->tran_open_flag == 0);
	if (tran->tran_open_flag)
		return (DDI_FAILURE);

	if (!(tran->tran_hba_flags & SCSI_HBA_HBA))
		scsa_tran_teardown(self, tran);
	scsa_nexus_teardown(self, tran);

	/* Teardown tran_setup_pkt(9E) kmem_cache. */
	if (tran->tran_pkt_cache_ptr) {
		kmem_cache_destroy(tran->tran_pkt_cache_ptr);
		tran->tran_pkt_cache_ptr = NULL;
	}

	(void) memset(&tran->tran_dma_attr, 0, sizeof (ddi_dma_attr_t));

	/* Teardown flavor of transport (and ddi_get_driver_private()) */
	ndi_flavorv_set(self, SCSA_FLAVOR_SCSI_DEVICE, NULL);

	tran->tran_hba_dip = NULL;

	return (DDI_SUCCESS);
}


/*
 * Called by an HBA from _fini()
 */
void
scsi_hba_fini(struct modlinkage *modlp)
{
	struct dev_ops *hba_dev_ops;

	SCSI_HBA_LOG((_LOG_TRACE, NULL, NULL, __func__));

	/* Get the devops structure of this module and clear bus_ops vector. */
	hba_dev_ops = ((struct modldrv *)(modlp->ml_linkage[0]))->drv_dev_ops;

	if (hba_dev_ops->devo_cb_ops == &scsi_hba_cbops)
		hba_dev_ops->devo_cb_ops = NULL;

	if (hba_dev_ops->devo_getinfo == scsi_hba_info)
		hba_dev_ops->devo_getinfo = NULL;

	hba_dev_ops->devo_bus_ops = (struct bus_ops *)NULL;
}

/*
 * SAS specific functions
 */
smp_hba_tran_t *
smp_hba_tran_alloc(dev_info_t *self)
{
	/* allocate SCSA flavors for self */
	ndi_flavorv_alloc(self, SCSA_NFLAVORS);
	return (kmem_zalloc(sizeof (smp_hba_tran_t), KM_SLEEP));
}

void
smp_hba_tran_free(smp_hba_tran_t *tran)
{
	kmem_free(tran, sizeof (smp_hba_tran_t));
}

int
smp_hba_attach_setup(
	dev_info_t		*self,
	smp_hba_tran_t		*tran)
{
	ASSERT(scsi_hba_iport_unit_address(self) == NULL);
	if (scsi_hba_iport_unit_address(self))
		return (DDI_FAILURE);		/* self can't be an iport */

	/*
	 * The owner of the this devinfo_t was responsible
	 * for informing the framework already about
	 * additional flavors.
	 */
	ndi_flavorv_set(self, SCSA_FLAVOR_SMP, tran);
	return (DDI_SUCCESS);
}

int
smp_hba_detach(dev_info_t *self)
{
	ASSERT(scsi_hba_iport_unit_address(self) == NULL);
	if (scsi_hba_iport_unit_address(self))
		return (DDI_FAILURE);		/* self can't be an iport */

	ndi_flavorv_set(self, SCSA_FLAVOR_SMP, NULL);
	return (DDI_SUCCESS);
}

/*
 * SMP child flavored functions
 */
static int
smp_busctl_ua(dev_info_t *child, char *addr, int maxlen)
{
	char		*tport;
	char		*wwn;

	/* limit ndi_devi_findchild_by_callback to expected flavor */
	if (ndi_flavor_get(child) != SCSA_FLAVOR_SMP)
		return (DDI_FAILURE);

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, child,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    SCSI_ADDR_PROP_TARGET_PORT, &tport) == DDI_SUCCESS) {
		(void) snprintf(addr, maxlen, "%s", tport);
		ddi_prop_free(tport);
		return (DDI_SUCCESS);
	}

	/*
	 * NOTE: the following code should be deleted when mpt is changed to
	 * use SCSI_ADDR_PROP_TARGET_PORT instead of SMP_WWN.
	 */
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, child,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    SMP_WWN, &wwn) == DDI_SUCCESS) {
		(void) snprintf(addr, maxlen, "w%s", wwn);
		ddi_prop_free(wwn);
		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}

static int
smp_busctl_reportdev(dev_info_t *child)
{
	dev_info_t	*self = ddi_get_parent(child);
	char		*tport;
	char		*wwn;

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, child,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    SCSI_ADDR_PROP_TARGET_PORT, &tport) == DDI_SUCCESS) {
		SCSI_HBA_LOG((_LOG_NF(CONT), "?%s%d at %s%d: target-port %s",
		    ddi_driver_name(child), ddi_get_instance(child),
		    ddi_driver_name(self), ddi_get_instance(self), tport));
		ddi_prop_free(tport);
		return (DDI_SUCCESS);
	}

	/*
	 * NOTE: the following code should be deleted when mpt is changed to
	 * use SCSI_ADDR_PROP_TARGET_PORT instead of SMP_WWN.
	 */
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, child,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    SMP_WWN, &wwn) == DDI_SUCCESS) {
		SCSI_HBA_LOG((_LOG_NF(CONT), "?%s%d at %s%d: wwn %s",
		    ddi_driver_name(child), ddi_get_instance(child),
		    ddi_driver_name(self), ddi_get_instance(self), wwn));
		ddi_prop_free(wwn);
		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}

static int
smp_busctl_initchild(dev_info_t *child)
{
	dev_info_t		*self = ddi_get_parent(child);
	smp_hba_tran_t		*tran;
	dev_info_t		*dup;
	char			addr[SCSI_MAXNAMELEN];
	struct smp_device	*smp_sd;
	uint64_t		wwn;

	tran = ndi_flavorv_get(self, SCSA_FLAVOR_SMP);
	ASSERT(tran);
	if (tran == NULL)
		return (DDI_FAILURE);

	if (smp_busctl_ua(child, addr, sizeof (addr)) != DDI_SUCCESS)
		return (DDI_NOT_WELL_FORMED);
	if (scsi_wwnstr_to_wwn(addr, &wwn))
		return (DDI_NOT_WELL_FORMED);

	/* Prevent duplicate nodes.  */
	dup = ndi_devi_findchild_by_callback(self, ddi_node_name(child), addr,
	    smp_busctl_ua);
	if (dup) {
		ASSERT(ndi_flavor_get(dup) == SCSA_FLAVOR_SMP);
		if (ndi_flavor_get(dup) != SCSA_FLAVOR_SMP) {
			SCSI_HBA_LOG((_LOG(1), NULL, child,
			    "init failed: %s@%s: not SMP flavored",
			    ddi_node_name(child), addr));
			return (DDI_FAILURE);
		}
		if (dup != child) {
			SCSI_HBA_LOG((_LOG(4), NULL, child,
			    "init failed: %s@%s: detected duplicate %p",
			    ddi_node_name(child), addr, (void *)dup));
			return (DDI_FAILURE);
		}
	}


	/* set the node @addr string */
	ddi_set_name_addr(child, addr);

	/* Allocate and initialize smp_device. */
	smp_sd = kmem_zalloc(sizeof (struct smp_device), KM_SLEEP);
	smp_sd->smp_sd_dev = child;
	smp_sd->smp_sd_address.smp_a_hba_tran = tran;
	bcopy(&wwn, smp_sd->smp_sd_address.smp_a_wwn, SAS_WWN_BYTE_SIZE);

	ddi_set_driver_private(child, smp_sd);

	if (tran->smp_tran_init && ((*tran->smp_tran_init)(self, child,
	    tran, smp_sd) != DDI_SUCCESS)) {
		kmem_free(smp_sd, sizeof (struct smp_device));
		scsi_enumeration_failed(child, -1, NULL, "smp_tran_init");
		ddi_set_driver_private(child, NULL);
		ddi_set_name_addr(child, NULL);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
smp_busctl_uninitchild(dev_info_t *child)
{
	dev_info_t		*self = ddi_get_parent(child);
	struct smp_device	*smp_sd = ddi_get_driver_private(child);
	smp_hba_tran_t		*tran;

	tran = ndi_flavorv_get(self, SCSA_FLAVOR_SMP);
	ASSERT(smp_sd && tran);
	if ((smp_sd == NULL) || (tran == NULL))
		return (DDI_FAILURE);

	if (tran->smp_tran_free)
		(*tran->smp_tran_free) (self, child, tran, smp_sd);

	kmem_free(smp_sd, sizeof (*smp_sd));
	ddi_set_driver_private(child, NULL);
	ddi_set_name_addr(child, NULL);
	return (DDI_SUCCESS);
}

/* Find an "smp" child at the specified address. */
static dev_info_t *
smp_findchild(dev_info_t *self, char *addr)
{
	dev_info_t	*child;

	/* Search "smp" devinfo child at specified address. */
	ASSERT(self && DEVI_BUSY_OWNED(self) && addr);
	for (child = ddi_get_child(self); child;
	    child = ddi_get_next_sibling(child)) {
		/* skip non-"smp" nodes */
		if (ndi_flavor_get(child) != SCSA_FLAVOR_SMP)
			continue;

		/* Attempt initchild to establish unit-address */
		if (i_ddi_node_state(child) < DS_INITIALIZED)
			(void) ddi_initchild(self, child);

		/* Verify state and non-NULL unit-address. */
		if ((i_ddi_node_state(child) < DS_INITIALIZED) ||
		    (ddi_get_name_addr(child) == NULL))
			continue;

		/* Return "smp" child if unit-address matches. */
		if (strcmp(ddi_get_name_addr(child), addr) == 0)
			return (child);
	}
	return (NULL);
}

/*
 * Search for "smp" child of self at the specified address. If found, online
 * and return with a hold.  Unlike general SCSI configuration, we can assume
 * the the device is actually there when we are called (i.e., device is
 * created by hotplug, not by bus_config).
 */
int
smp_hba_bus_config(dev_info_t *self, char *addr, dev_info_t **childp)
{
	dev_info_t	*child;
	int		circ;

	ASSERT(self && addr && childp);
	*childp = NULL;

	/* Search for "smp" child. */
	scsi_hba_devi_enter(self, &circ);
	if ((child = smp_findchild(self, addr)) == NULL) {
		scsi_hba_devi_exit(self, circ);
		return (NDI_FAILURE);
	}

	/* Attempt online. */
	if (ndi_devi_online(child, 0) != NDI_SUCCESS) {
		scsi_hba_devi_exit(self, circ);
		return (NDI_FAILURE);
	}

	/* On success, return with active hold. */
	ndi_hold_devi(child);
	scsi_hba_devi_exit(self, circ);
	*childp = child;
	return (NDI_SUCCESS);
}



/* Create "smp" child devinfo node at specified unit-address. */
int
smp_hba_bus_config_taddr(dev_info_t *self, char *addr)
{
	dev_info_t		*child;
	int			circ;

	/*
	 * NOTE: If we ever uses a generic node name (.vs. a driver name)
	 * or define a 'compatible' property, this code will need to use
	 * a 'probe' node (ala scsi_device support) to obtain identity
	 * information from the device.
	 */

	/* Search for "smp" child. */
	scsi_hba_devi_enter(self, &circ);
	child = smp_findchild(self, addr);
	if (child) {
		/* Child exists, note if this was a new reinsert. */
		if (ndi_devi_device_insert(child))
			SCSI_HBA_LOG((_LOGCFG, self, NULL,
			    "devinfo smp@%s device_reinsert", addr));

		scsi_hba_devi_exit(self, circ);
		return (NDI_SUCCESS);
	}

	/* Allocate "smp" child devinfo node and establish flavor of child. */
	ndi_devi_alloc_sleep(self, "smp", DEVI_SID_HP_NODEID, &child);
	ASSERT(child);
	ndi_flavor_set(child, SCSA_FLAVOR_SMP);

	/* Add unit-address property to child. */
	if (ndi_prop_update_string(DDI_DEV_T_NONE, child,
	    SCSI_ADDR_PROP_TARGET_PORT, addr) != DDI_PROP_SUCCESS) {
		(void) ndi_devi_free(child);
		scsi_hba_devi_exit(self, circ);
		return (NDI_FAILURE);
	}

	/* Attempt to online the new "smp" node. */
	(void) ndi_devi_online(child, 0);

	scsi_hba_devi_exit(self, circ);
	return (NDI_SUCCESS);
}

/*
 * Wrapper to scsi_ua_get which takes a devinfo argument instead of a
 * scsi_device structure.
 */
static int
scsi_busctl_ua(dev_info_t *child, char *addr, int maxlen)
{
	struct scsi_device	*sd;

	/* limit ndi_devi_findchild_by_callback to expected flavor */
	if (ndi_flavor_get(child) != SCSA_FLAVOR_SCSI_DEVICE)
		return (DDI_FAILURE);

	/* nodes are named by tran_get_name or default "tgt,lun" */
	sd = ddi_get_driver_private(child);
	if (sd && (scsi_ua_get(sd, addr, maxlen) == 1))
		return (DDI_SUCCESS);

	return (DDI_FAILURE);
}

static int
scsi_busctl_reportdev(dev_info_t *child)
{
	dev_info_t		*self = ddi_get_parent(child);
	struct scsi_device	*sd = ddi_get_driver_private(child);
	scsi_hba_tran_t		*tran;
	char			ua[SCSI_MAXNAMELEN];
	char			ra[SCSI_MAXNAMELEN];

	SCSI_HBA_LOG((_LOG_TRACE, NULL, child, __func__));

	tran = ndi_flavorv_get(self, SCSA_FLAVOR_SCSI_DEVICE);
	ASSERT(tran && sd);
	if ((tran == NULL) || (sd == NULL))
		return (DDI_FAILURE);

	/* get the unit_address and bus_addr information */
	if ((scsi_ua_get(sd, ua, sizeof (ua)) == 0) ||
	    (scsi_ua_get_reportdev(sd, ra, sizeof (ra)) == 0)) {
		SCSI_HBA_LOG((_LOG(WARN), NULL, child, "REPORTDEV failure"));
		return (DDI_FAILURE);
	}

	if (tran->tran_get_name == NULL)
		SCSI_HBA_LOG((_LOG_NF(CONT), "?%s%d at %s%d: %s",
		    ddi_driver_name(child), ddi_get_instance(child),
		    ddi_driver_name(self), ddi_get_instance(self), ra));
	else if (*ra)
		SCSI_HBA_LOG((_LOG_NF(CONT),
		    "?%s%d at %s%d: unit-address %s: %s",
		    ddi_driver_name(child), ddi_get_instance(child),
		    ddi_driver_name(self), ddi_get_instance(self), ua, ra));
	else
		SCSI_HBA_LOG((_LOG_NF(CONT),
		    "?%s%d at %s%d: unit-address %s",
		    ddi_driver_name(child), ddi_get_instance(child),
		    ddi_driver_name(self), ddi_get_instance(self), ua));

	return (DDI_SUCCESS);
}


/*
 * scsi_busctl_initchild is called to initialize the SCSA transport for
 * communication with a particular child scsi target device. Successful
 * initialization requires properties on the node which describe the address
 * of the target device. If the address of the target device can't be
 * determined from properties then DDI_NOT_WELL_FORMED is returned. Nodes that
 * are DDI_NOT_WELL_FORMED are considered an implementation artifact and
 * are hidden from devinfo snapshots by calling ndi_devi_set_hidden().
 * The child may be one of the following types of devinfo nodes:
 *
 * OBP node:
 *	OBP does not enumerate target devices attached a SCSI bus. These
 *	template/stub/wild-card nodes are a legacy artifact for support of old
 *	driver loading methods. Since they have no properties,
 *	DDI_NOT_WELL_FORMED will be returned.
 *
 * SID node:
 *	The node may be either a:
 *	    o	probe/barrier SID node
 *	    o	a dynamic SID target node
 *
 * driver.conf node: The situation for this nexus is different than most.
 *	Typically a driver.conf node definition is used to either define a
 *	new child devinfo node or to further decorate (via merge) a SID
 *	child with properties. In our case we use the nodes for *both*
 *	purposes.
 *
 * In both the SID node and driver.conf node cases we must form the nodes
 * "@addr" from the well-known scsi(9P) device unit-address properties on
 * the node.
 *
 * For HBA drivers that implement the deprecated tran_get_name interface,
 * "@addr" construction involves having that driver interpret properties via
 * scsi_busctl_ua -> scsi_ua_get -> tran_get_name: there is no
 * requirement for the property names to be well-known.
 *
 * NOTE: We don't currently support "merge".  When this support is added a
 * specific property, like "unit-address", should *always* identify a
 * driver.conf node that needs to be merged into a specific SID node. When
 * enumeration is enabled, a .conf node without the "unit-address" property
 * should be ignored.  The best way to establish the "unit-address" property
 * would be to have the system assign parent= and unit-address= from an
 * instance=# driver.conf entry (by using the instance tree).
 */
static int
scsi_busctl_initchild(dev_info_t *child)
{
	dev_info_t		*self = ddi_get_parent(child);
	dev_info_t		*dup;
	scsi_hba_tran_t		*tran;
	struct scsi_device	*sd;
	scsi_hba_tran_t		*tran_clone;
	char			*class;
	int			tgt;
	int			lun;
	int			sfunc;
	int			err = DDI_FAILURE;
	char			addr[SCSI_MAXNAMELEN];

	ASSERT(DEVI_BUSY_OWNED(self));
	SCSI_HBA_LOG((_LOG(4), NULL, child, "init begin"));

	/*
	 * For a driver like fp with multiple upper-layer-protocols
	 * it is possible for scsi_hba_init in _init to plumb SCSA
	 * and have the load of fcp (which does scsi_hba_attach_setup)
	 * to fail.  In this case we may get here with a NULL hba.
	 */
	tran = ndi_flavorv_get(self, SCSA_FLAVOR_SCSI_DEVICE);
	if (tran == NULL)
		return (DDI_NOT_WELL_FORMED);

	/*
	 * OBP may create template/stub/wild-card nodes for legacy driver
	 * loading methods. These nodes have no properties, so we lack the
	 * addressing properties to initchild them. Hide the node and return
	 * DDI_NOT_WELL_FORMED.
	 *
	 * Future: define/use a ndi_devi_has_properties(dip) type interface.
	 *
	 * NOTE: It would be nice if we could delete these ill formed nodes by
	 * implementing a DDI_NOT_WELL_FORMED_DELETE return code. This can't
	 * be done until leadville debug code removes its dependencies
	 * on the devinfo still being present after a failed ndi_devi_online.
	 */
	if ((DEVI(child)->devi_hw_prop_ptr == NULL) &&
	    (DEVI(child)->devi_drv_prop_ptr == NULL) &&
	    (DEVI(child)->devi_sys_prop_ptr == NULL)) {
		SCSI_HBA_LOG((_LOG(4), NULL, child,
		    "init failed: no properties"));
		ndi_devi_set_hidden(child);
		return (DDI_NOT_WELL_FORMED);
	}

	/* get legacy SPI addressing properties */
	if ((tgt = ddi_prop_get_int(DDI_DEV_T_ANY, child,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    SCSI_ADDR_PROP_TARGET, -1)) == -1) {
		tgt = 0;
		/*
		 * A driver.conf node for merging always has a target= property,
		 * even if it is just a dummy that does not contain the real
		 * target address. However drivers that register devids may
		 * create stub driver.conf nodes without a target= property so
		 * that pathological devid resolution works. Hide the stub
		 * node and return DDI_NOT_WELL_FORMED.
		 */
		if (!scsi_hba_dev_is_sid(child)) {
			SCSI_HBA_LOG((_LOG(4), NULL, child,
			    "init failed: stub .conf node"));
			ndi_devi_set_hidden(child);
			return (DDI_NOT_WELL_FORMED);
		}
	}
	lun = ddi_prop_get_int(DDI_DEV_T_ANY, child,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, SCSI_ADDR_PROP_LUN, 0);
	sfunc = ddi_prop_get_int(DDI_DEV_T_ANY, child,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, SCSI_ADDR_PROP_SFUNC, -1);

	/*
	 * The scsi_address structure may not specify all the addressing
	 * information. For an old HBA that doesn't support tran_get_name
	 * (most pre-SCSI-3 HBAs) the scsi_address structure is still used,
	 * so the target property must exist and the LUN must be < 256.
	 */
	if ((tran->tran_get_name == NULL) &&
	    ((tgt >= USHRT_MAX) || (lun >= 256))) {
		SCSI_HBA_LOG((_LOG(1), NULL, child,
		    "init failed: illegal/missing properties"));
		ndi_devi_set_hidden(child);
		return (DDI_NOT_WELL_FORMED);
	}

	/*
	 * We need to initialize a fair amount of our environment to invoke
	 * tran_get_name (via scsi_busctl_ua and scsi_ua_get) to
	 * produce the "@addr" name from addressing properties. Allocate and
	 * initialize scsi device structure.
	 */
	sd = kmem_zalloc(sizeof (struct scsi_device), KM_SLEEP);
	mutex_init(&sd->sd_mutex, NULL, MUTEX_DRIVER, NULL);
	sd->sd_dev = child;
	sd->sd_pathinfo = NULL;
	sd->sd_uninit_prevent = 0;
	ddi_set_driver_private(child, sd);

	if (tran->tran_hba_flags & SCSI_HBA_ADDR_COMPLEX) {
		/*
		 * For a SCSI_HBA_ADDR_COMPLEX transport we store a pointer to
		 * scsi_device in the scsi_address structure.  This allows an
		 * HBA driver to find its per-scsi_device private data
		 * (accessible to the HBA given just the scsi_address by using
		 *  scsi_address_device(9F)/scsi_device_hba_private_get(9F)).
		 */
		sd->sd_address.a.a_sd = sd;
		tran_clone = NULL;
	} else {
		/*
		 * Initialize the scsi_address so that a SCSI-2 target driver
		 * talking to a SCSI-2 device on a SCSI-3 bus (spi) continues
		 * to work. We skew the secondary function value so that we
		 * can tell from the address structure if we are processing
		 * a secondary function request.
		 */
		sd->sd_address.a_target = (ushort_t)tgt;
		sd->sd_address.a_lun = (uchar_t)lun;
		if (sfunc == -1)
			sd->sd_address.a_sublun = (uchar_t)0;
		else
			sd->sd_address.a_sublun = (uchar_t)sfunc + 1;

		/*
		 * NOTE: Don't limit LUNs to scsi_options value because a
		 * scsi_device discovered via SPI dynamic enumeration might
		 * still support SCMD_REPORT_LUNS.
		 */

		/*
		 * Deprecated: Use SCSI_HBA_ADDR_COMPLEX:
		 *   Clone transport structure if requested. Cloning allows
		 *   an HBA to maintain target-specific information if
		 *   necessary, such as target addressing information that
		 *   does not adhere to the scsi_address structure format.
		 */
		if (tran->tran_hba_flags & SCSI_HBA_TRAN_CLONE) {
			tran_clone = kmem_alloc(
			    sizeof (scsi_hba_tran_t), KM_SLEEP);
			bcopy((caddr_t)tran,
			    (caddr_t)tran_clone, sizeof (scsi_hba_tran_t));
			tran = tran_clone;
			tran->tran_sd = sd;
		} else {
			tran_clone = NULL;
			ASSERT(tran->tran_sd == NULL);
		}
	}

	/* establish scsi_address pointer to the HBA's tran structure */
	sd->sd_address.a_hba_tran = tran;

	/*
	 * This is a grotty hack that allows direct-access (non-scsa) drivers
	 * (like chs, ata, and mlx which all make cmdk children) to put its
	 * own vector in the 'a_hba_tran' field. When all the drivers that do
	 * this are fixed, please remove this hack.
	 *
	 * NOTE: This hack is also shows up in the DEVP_TO_TRAN implementation
	 * in scsi_confsubr.c.
	 */
	sd->sd_tran_safe = tran;

	/*
	 * If the class property is not already established, set it to "scsi".
	 * This is done so that parent= driver.conf nodes have class.
	 */
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, child,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "class",
	    &class) == DDI_PROP_SUCCESS) {
		ddi_prop_free(class);
	} else if (ndi_prop_update_string(DDI_DEV_T_NONE, child,
	    "class", "scsi") != DDI_PROP_SUCCESS) {
		SCSI_HBA_LOG((_LOG(2), NULL, child, "init failed: class"));
		ndi_devi_set_hidden(child);
		err = DDI_NOT_WELL_FORMED;
		goto failure;
	}

	/* Establish the @addr name of the child. */
	*addr = '\0';
	if (scsi_busctl_ua(child, addr, sizeof (addr)) != DDI_SUCCESS) {
		/*
		 * Some driver.conf files add bogus target properties (relative
		 * to their nexus representation of target) to their stub
		 * nodes, causing the check above to not filter them.
		 */
		SCSI_HBA_LOG((_LOG(3), NULL, child,
		    "init failed: scsi_busctl_ua call"));
		ndi_devi_set_hidden(child);
		err = DDI_NOT_WELL_FORMED;
		goto failure;
	}
	if (*addr == '\0') {
		SCSI_HBA_LOG((_LOG(2), NULL, child, "init failed: ua"));
		ndi_devi_set_hidden(child);
		err = DDI_NOT_WELL_FORMED;
		goto failure;
	}

	/* Prevent duplicate nodes.  */
	dup = ndi_devi_findchild_by_callback(self, ddi_node_name(child), addr,
	    scsi_busctl_ua);
	if (dup) {
		ASSERT(ndi_flavor_get(dup) == SCSA_FLAVOR_SCSI_DEVICE);
		if (ndi_flavor_get(dup) != SCSA_FLAVOR_SCSI_DEVICE) {
			SCSI_HBA_LOG((_LOG(1), NULL, child,
			    "init failed: %s@%s: not SCSI_DEVICE flavored",
			    ddi_node_name(child), addr));
			goto failure;
		}
		if (dup != child) {
			SCSI_HBA_LOG((_LOG(4), NULL, child,
			    "init failed: %s@%s: detected duplicate %p",
			    ddi_node_name(child), addr, (void *)dup));
			goto failure;
		}
	}

	/* set the node @addr string */
	ddi_set_name_addr(child, addr);

	/* call HBA's target init entry point if it exists */
	if (tran->tran_tgt_init != NULL) {
		SCSI_HBA_LOG((_LOG(4), NULL, child, "init tran_tgt_init"));
		sd->sd_tran_tgt_free_done = 0;
		if ((*tran->tran_tgt_init)
		    (self, child, tran, sd) != DDI_SUCCESS) {
			scsi_enumeration_failed(child, -1, NULL,
			    "tran_tgt_init");
			goto failure;
		}
	}

	SCSI_HBA_LOG((_LOG(3), NULL, child, "init successful"));
	return (DDI_SUCCESS);

failure:
	if (tran_clone)
		kmem_free(tran_clone, sizeof (scsi_hba_tran_t));
	mutex_destroy(&sd->sd_mutex);
	kmem_free(sd, sizeof (*sd));
	ddi_set_driver_private(child, NULL);
	ddi_set_name_addr(child, NULL);

	return (err);		/* remove the node */
}

static int
scsi_busctl_uninitchild(dev_info_t *child)
{
	dev_info_t		*self = ddi_get_parent(child);
	struct scsi_device	*sd = ddi_get_driver_private(child);
	scsi_hba_tran_t		*tran;
	scsi_hba_tran_t		*tran_clone;

	ASSERT(DEVI_BUSY_OWNED(self));

	tran = ndi_flavorv_get(self, SCSA_FLAVOR_SCSI_DEVICE);
	ASSERT(tran && sd);
	if ((tran == NULL) || (sd == NULL))
		return (DDI_FAILURE);

	/*
	 * We use sd_uninit_prevent to avoid uninitializing barrier/probe
	 * nodes that are still in use. Since barrier/probe nodes are not
	 * attached we can't prevent their state demotion via ndi_hold_devi.
	 */
	if (sd->sd_uninit_prevent) {
		SCSI_HBA_LOG((_LOG(2), NULL, child, "uninit prevented"));
		return (DDI_FAILURE);
	}

	/*
	 * Don't uninitialize a client node if it still has paths.
	 */
	if (MDI_CLIENT(child) && mdi_client_get_path_count(child)) {
		SCSI_HBA_LOG((_LOG(2), NULL, child,
		    "uninit prevented, client has paths"));
		return (DDI_FAILURE);
	}

	SCSI_HBA_LOG((_LOG(3), NULL, child, "uninit begin"));

	if (tran->tran_hba_flags & SCSI_HBA_TRAN_CLONE) {
		tran_clone = sd->sd_address.a_hba_tran;

		/* ... grotty hack, involving sd_tran_safe, continued. */
		if (tran_clone != sd->sd_tran_safe) {
			tran_clone = sd->sd_tran_safe;
#ifdef	DEBUG
			/*
			 * Complain so things get fixed and hack can, at
			 * some point in time, be removed.
			 */
			SCSI_HBA_LOG((_LOG(WARN), self, NULL,
			    "'%s' is corrupting a_hba_tran", sd->sd_dev ?
			    ddi_driver_name(sd->sd_dev) : "unknown_driver"));
#endif	/* DEBUG */
		}

		ASSERT(tran_clone->tran_hba_flags & SCSI_HBA_TRAN_CLONE);
		ASSERT(tran_clone->tran_sd == sd);
		tran = tran_clone;
	} else {
		tran_clone = NULL;
		ASSERT(tran->tran_sd == NULL);
	}

	/*
	 * To simplify host adapter drivers we guarantee that multiple
	 * tran_tgt_init(9E) calls of the same unit address are never
	 * active at the same time.  This requires that we always call
	 * tran_tgt_free on probe/barrier nodes directly prior to
	 * uninitchild.
	 *
	 * NOTE: To correctly support SCSI_HBA_TRAN_CLONE, we must use
	 * the (possibly cloned) hba_tran pointer from the scsi_device
	 * instead of hba_tran.
	 */
	if (tran->tran_tgt_free) {
		if (!sd->sd_tran_tgt_free_done) {
			SCSI_HBA_LOG((_LOG(4), NULL, child,
			    "uninit tran_tgt_free"));
			(*tran->tran_tgt_free) (self, child, tran, sd);
			sd->sd_tran_tgt_free_done = 1;
		} else {
			SCSI_HBA_LOG((_LOG(4), NULL, child,
			    "uninit tran_tgt_free already done"));
		}
	}

	/*
	 * If a inquiry data is still allocated (by scsi_probe()) we
	 * free the allocation here. This keeps scsi_inq valid for the
	 * same duration as the corresponding inquiry properties. It
	 * also allows a tran_tgt_init() implementation that establishes
	 * sd_inq to deal with deallocation in its tran_tgt_free
	 * (setting sd_inq back to NULL) without upsetting the
	 * framework. Moving the inquiry free here also allows setting
	 * of sd_uninit_prevent to preserve the data for lun0 based
	 * scsi_get_device_type_scsi_options() calls.
	 */
	if (sd->sd_inq) {
		kmem_free(sd->sd_inq, SUN_INQSIZE);
		sd->sd_inq = (struct scsi_inquiry *)NULL;
	}

	mutex_destroy(&sd->sd_mutex);
	if (tran_clone)
		kmem_free(tran_clone, sizeof (scsi_hba_tran_t));
	kmem_free(sd, sizeof (*sd));

	ddi_set_driver_private(child, NULL);
	SCSI_HBA_LOG((_LOG(3), NULL, child, "uninit complete"));
	ddi_set_name_addr(child, NULL);
	return (DDI_SUCCESS);
}

static int
iport_busctl_ua(dev_info_t *child, char *addr, int maxlen)
{
	char	*iport_ua;

	/* limit ndi_devi_findchild_by_callback to expected flavor */
	if (ndi_flavor_get(child) != SCSA_FLAVOR_IPORT)
		return (DDI_FAILURE);

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, child,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    SCSI_ADDR_PROP_IPORTUA, &iport_ua) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	(void) snprintf(addr, maxlen, "%s", iport_ua);
	ddi_prop_free(iport_ua);
	return (DDI_SUCCESS);
}

static int
iport_busctl_reportdev(dev_info_t *child)
{
	dev_info_t	*self = ddi_get_parent(child);
	char		*iport_ua;
	char		*initiator_port = NULL;

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, child,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    SCSI_ADDR_PROP_IPORTUA, &iport_ua) != DDI_SUCCESS)
		return (DDI_FAILURE);

	(void) ddi_prop_lookup_string(DDI_DEV_T_ANY, child,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    SCSI_ADDR_PROP_INITIATOR_PORT, &initiator_port);

	if (initiator_port) {
		SCSI_HBA_LOG((_LOG_NF(CONT),
		    "?%s%d at %s%d: %s %s %s %s",
		    ddi_driver_name(child), ddi_get_instance(child),
		    ddi_driver_name(self), ddi_get_instance(self),
		    SCSI_ADDR_PROP_INITIATOR_PORT, initiator_port,
		    SCSI_ADDR_PROP_IPORTUA, iport_ua));
		ddi_prop_free(initiator_port);
	} else {
		SCSI_HBA_LOG((_LOG_NF(CONT), "?%s%d at %s%d: %s %s",
		    ddi_driver_name(child), ddi_get_instance(child),
		    ddi_driver_name(self), ddi_get_instance(self),
		    SCSI_ADDR_PROP_IPORTUA, iport_ua));
	}
	ddi_prop_free(iport_ua);
	return (DDI_SUCCESS);
}

/* initchild SCSA iport 'child' node */
static int
iport_busctl_initchild(dev_info_t *child)
{
	dev_info_t	*self = ddi_get_parent(child);
	dev_info_t	*dup = NULL;
	char		addr[SCSI_MAXNAMELEN];

	if (iport_busctl_ua(child, addr, sizeof (addr)) != DDI_SUCCESS)
		return (DDI_NOT_WELL_FORMED);

	/* Prevent duplicate nodes.  */
	dup = ndi_devi_findchild_by_callback(self, ddi_node_name(child), addr,
	    iport_busctl_ua);
	if (dup) {
		ASSERT(ndi_flavor_get(dup) == SCSA_FLAVOR_IPORT);
		if (ndi_flavor_get(dup) != SCSA_FLAVOR_IPORT) {
			SCSI_HBA_LOG((_LOG(1), NULL, child,
			    "init failed: %s@%s: not IPORT flavored",
			    ddi_node_name(child), addr));
			return (DDI_FAILURE);
		}
		if (dup != child) {
			SCSI_HBA_LOG((_LOG(4), NULL, child,
			    "init failed: %s@%s: detected duplicate %p",
			    ddi_node_name(child), addr, (void *)dup));
			return (DDI_FAILURE);
		}
	}

	/* set the node @addr string */
	ddi_set_name_addr(child, addr);

	return (DDI_SUCCESS);
}

/* uninitchild SCSA iport 'child' node */
static int
iport_busctl_uninitchild(dev_info_t *child)
{
	ddi_set_name_addr(child, NULL);
	return (DDI_SUCCESS);
}

/* Uninitialize scsi_device flavor of transport on SCSA iport 'child' node. */
static void
iport_postdetach_tran_scsi_device(dev_info_t *child)
{
	scsi_hba_tran_t		*tran;

	tran = ndi_flavorv_get(child, SCSA_FLAVOR_SCSI_DEVICE);
	if (tran == NULL)
		return;

	scsa_tran_teardown(child, tran);
	scsa_nexus_teardown(child, tran);

	ndi_flavorv_set(child, SCSA_FLAVOR_SCSI_DEVICE, NULL);
	scsi_hba_tran_free(tran);
}

/* Initialize scsi_device flavor of transport on SCSA iport 'child' node. */
static void
iport_preattach_tran_scsi_device(dev_info_t *child)
{
	dev_info_t	*hba = ddi_get_parent(child);
	scsi_hba_tran_t	*htran;
	scsi_hba_tran_t	*tran;

	/* parent HBA node scsi_device tran is required */
	htran = ndi_flavorv_get(hba, SCSA_FLAVOR_SCSI_DEVICE);
	ASSERT(htran);

	/* Allocate iport child's scsi_device transport vector */
	tran = scsi_hba_tran_alloc(child, SCSI_HBA_CANSLEEP);
	ASSERT(tran);

	/* Structure-copy scsi_device transport of HBA to iport. */
	*tran = *htran;

	/*
	 * Reset scsi_device transport fields not shared with the
	 * parent, and not established below.
	 */
	tran->tran_open_flag = 0;
	tran->tran_hba_private = NULL;

	/* Establish the devinfo context of this tran structure. */
	tran->tran_iport_dip = child;

	/* Clear SCSI_HBA_SCSA flags (except TA) */
	tran->tran_hba_flags &=
	    ~(SCSI_HBA_SCSA_FM | SCSI_HBA_SCSA_PHCI);	/* clear parent state */
	tran->tran_hba_flags |= SCSI_HBA_SCSA_TA;	/* always TA */
	tran->tran_hba_flags &= ~SCSI_HBA_HBA;		/* never HBA */

	/* Establish flavor of transport (and ddi_get_driver_private()) */
	ndi_flavorv_set(child, SCSA_FLAVOR_SCSI_DEVICE, tran);

	/* Setup iport node */
	if ((scsa_nexus_setup(child, tran) != DDI_SUCCESS) ||
	    (scsa_tran_setup(child, tran) != DDI_SUCCESS))
		iport_postdetach_tran_scsi_device(child);
}

/* Uninitialize smp_device flavor of transport on SCSA iport 'child' node. */
static void
iport_postdetach_tran_smp_device(dev_info_t *child)
{
	smp_hba_tran_t	*tran;

	tran = ndi_flavorv_get(child, SCSA_FLAVOR_SMP);
	if (tran == NULL)
		return;

	ndi_flavorv_set(child, SCSA_FLAVOR_SMP, NULL);
	smp_hba_tran_free(tran);
}

/* Initialize smp_device flavor of transport on SCSA iport 'child' node. */
static void
iport_preattach_tran_smp_device(dev_info_t *child)
{
	dev_info_t	*hba = ddi_get_parent(child);
	smp_hba_tran_t	*htran;
	smp_hba_tran_t	*tran;

	/* parent HBA node smp_device tran is optional */
	htran = ndi_flavorv_get(hba, SCSA_FLAVOR_SMP);
	if (htran == NULL) {
		ndi_flavorv_set(child, SCSA_FLAVOR_SMP, NULL);
		return;
	}

	/* Allocate iport child's smp_device transport vector */
	tran = smp_hba_tran_alloc(child);

	/* Structure-copy smp_device transport of HBA to iport. */
	*tran = *htran;

	/* Establish flavor of transport */
	ndi_flavorv_set(child, SCSA_FLAVOR_SMP, tran);
}

/*
 * Generic bus_ctl operations for SCSI HBA's,
 * hiding the busctl interface from the HBA.
 */
/*ARGSUSED*/
static int
scsi_hba_bus_ctl(
	dev_info_t		*self,
	dev_info_t		*child,
	ddi_ctl_enum_t		op,
	void			*arg,
	void			*result)
{
	int			child_flavor = 0;
	int			val;
	ddi_dma_attr_t		*attr;
	scsi_hba_tran_t		*tran;
	struct attachspec	*as;
	struct detachspec	*ds;

	/* For some ops, child is 'arg'. */
	if ((op == DDI_CTLOPS_INITCHILD) || (op == DDI_CTLOPS_UNINITCHILD))
		child = (dev_info_t *)arg;

	/* Determine the flavor of the child: scsi, smp, iport */
	child_flavor = ndi_flavor_get(child);

	switch (op) {
	case DDI_CTLOPS_INITCHILD:
		switch (child_flavor) {
		case SCSA_FLAVOR_SCSI_DEVICE:
			return (scsi_busctl_initchild(child));
		case SCSA_FLAVOR_SMP:
			return (smp_busctl_initchild(child));
		case SCSA_FLAVOR_IPORT:
			return (iport_busctl_initchild(child));
		default:
			return (DDI_FAILURE);
		}
		/* NOTREACHED */

	case DDI_CTLOPS_UNINITCHILD:
		switch (child_flavor) {
		case SCSA_FLAVOR_SCSI_DEVICE:
			return (scsi_busctl_uninitchild(child));
		case SCSA_FLAVOR_SMP:
			return (smp_busctl_uninitchild(child));
		case SCSA_FLAVOR_IPORT:
			return (iport_busctl_uninitchild(child));
		default:
			return (DDI_FAILURE);
		}
		/* NOTREACHED */

	case DDI_CTLOPS_REPORTDEV:
		switch (child_flavor) {
		case SCSA_FLAVOR_SCSI_DEVICE:
			return (scsi_busctl_reportdev(child));
		case SCSA_FLAVOR_SMP:
			return (smp_busctl_reportdev(child));
		case SCSA_FLAVOR_IPORT:
			return (iport_busctl_reportdev(child));
		default:
			return (DDI_FAILURE);
		}
		/* NOTREACHED */

	case DDI_CTLOPS_ATTACH:
		as = (struct attachspec *)arg;

		if (child_flavor != SCSA_FLAVOR_IPORT)
			return (DDI_SUCCESS);

		/* iport processing */
		if (as->when == DDI_PRE) {
			/* setup pre attach(9E) */
			iport_preattach_tran_scsi_device(child);
			iport_preattach_tran_smp_device(child);
		} else if ((as->when == DDI_POST) &&
		    (as->result != DDI_SUCCESS)) {
			/* cleanup if attach(9E) failed */
			iport_postdetach_tran_scsi_device(child);
			iport_postdetach_tran_smp_device(child);
		}
		return (DDI_SUCCESS);

	case DDI_CTLOPS_DETACH:
		ds = (struct detachspec *)arg;

		if (child_flavor != SCSA_FLAVOR_IPORT)
			return (DDI_SUCCESS);

		/* iport processing */
		if ((ds->when == DDI_POST) &&
		    (ds->result == DDI_SUCCESS)) {
			/* cleanup if detach(9E) was successful */
			iport_postdetach_tran_scsi_device(child);
			iport_postdetach_tran_smp_device(child);
		}
		return (DDI_SUCCESS);

	case DDI_CTLOPS_IOMIN:
		tran = ddi_get_driver_private(self);
		ASSERT(tran);
		if (tran == NULL)
			return (DDI_FAILURE);

		/*
		 * The 'arg' value of nonzero indicates 'streaming'
		 * mode. If in streaming mode, pick the largest
		 * of our burstsizes available and say that that
		 * is our minimum value (modulo what minxfer is).
		 */
		attr = &tran->tran_dma_attr;
		val = *((int *)result);
		val = maxbit(val, attr->dma_attr_minxfer);
		*((int *)result) = maxbit(val, ((intptr_t)arg ?
		    (1<<ddi_ffs(attr->dma_attr_burstsizes)-1) :
		    (1<<(ddi_fls(attr->dma_attr_burstsizes)-1))));

		return (ddi_ctlops(self, child, op, arg, result));

	case DDI_CTLOPS_SIDDEV:
		return (ndi_dev_is_persistent_node(child) ?
		    DDI_SUCCESS : DDI_FAILURE);

	case DDI_CTLOPS_POWER:
		return (DDI_SUCCESS);

	/*
	 * These ops correspond to functions that "shouldn't" be called
	 * by a SCSI target driver. So we whine when we're called.
	 */
	case DDI_CTLOPS_DMAPMAPC:
	case DDI_CTLOPS_REPORTINT:
	case DDI_CTLOPS_REGSIZE:
	case DDI_CTLOPS_NREGS:
	case DDI_CTLOPS_SLAVEONLY:
	case DDI_CTLOPS_AFFINITY:
	case DDI_CTLOPS_POKE:
	case DDI_CTLOPS_PEEK:
		SCSI_HBA_LOG((_LOG(WARN), self, NULL, "invalid op (%d)", op));
		return (DDI_FAILURE);

	/* Everything else we pass up */
	case DDI_CTLOPS_PTOB:
	case DDI_CTLOPS_BTOP:
	case DDI_CTLOPS_BTOPR:
	case DDI_CTLOPS_DVMAPAGESIZE:
	default:
		return (ddi_ctlops(self, child, op, arg, result));
	}
	/* NOTREACHED */
}

/*
 * Private wrapper for scsi_pkt's allocated via scsi_hba_pkt_alloc()
 */
struct scsi_pkt_wrapper {
	struct scsi_pkt		scsi_pkt;
	int			pkt_wrapper_magic;
	int			pkt_wrapper_len;
};

#if !defined(lint)
_NOTE(SCHEME_PROTECTS_DATA("unique per thread", scsi_pkt_wrapper))
_NOTE(SCHEME_PROTECTS_DATA("Unshared Data", dev_ops))
#endif

/*
 * Called by an HBA to allocate a scsi_pkt
 */
/*ARGSUSED*/
struct scsi_pkt *
scsi_hba_pkt_alloc(
	dev_info_t		*self,
	struct scsi_address	*ap,
	int			cmdlen,
	int			statuslen,
	int			tgtlen,
	int			hbalen,
	int			(*callback)(caddr_t arg),
	caddr_t			arg)
{
	struct scsi_pkt		*pkt;
	struct scsi_pkt_wrapper	*hba_pkt;
	caddr_t			p;
	int			acmdlen, astatuslen, atgtlen, ahbalen;
	int			pktlen;

	/* Sanity check */
	if (callback != SLEEP_FUNC && callback != NULL_FUNC)
		SCSI_HBA_LOG((_LOG(WARN), self, NULL,
		    "callback must be SLEEP_FUNC or NULL_FUNC"));

	/*
	 * Round up so everything gets allocated on long-word boundaries
	 */
	acmdlen = ROUNDUP(cmdlen);
	astatuslen = ROUNDUP(statuslen);
	atgtlen = ROUNDUP(tgtlen);
	ahbalen = ROUNDUP(hbalen);
	pktlen = sizeof (struct scsi_pkt_wrapper) +
	    acmdlen + astatuslen + atgtlen + ahbalen;

	hba_pkt = kmem_zalloc(pktlen,
	    (callback == SLEEP_FUNC) ? KM_SLEEP : KM_NOSLEEP);
	if (hba_pkt == NULL) {
		ASSERT(callback == NULL_FUNC);
		return (NULL);
	}

	/*
	 * Set up our private info on this pkt
	 */
	hba_pkt->pkt_wrapper_len = pktlen;
	hba_pkt->pkt_wrapper_magic = PKT_WRAPPER_MAGIC;	/* alloced correctly */
	pkt = &hba_pkt->scsi_pkt;

	/*
	 * Set up pointers to private data areas, cdb, and status.
	 */
	p = (caddr_t)(hba_pkt + 1);
	if (hbalen > 0) {
		pkt->pkt_ha_private = (opaque_t)p;
		p += ahbalen;
	}
	if (tgtlen > 0) {
		pkt->pkt_private = (opaque_t)p;
		p += atgtlen;
	}
	if (statuslen > 0) {
		pkt->pkt_scbp = (uchar_t *)p;
		p += astatuslen;
	}
	if (cmdlen > 0) {
		pkt->pkt_cdbp = (uchar_t *)p;
	}

	/*
	 * Initialize the pkt's scsi_address
	 */
	pkt->pkt_address = *ap;

	/*
	 * NB: It may not be safe for drivers, esp target drivers, to depend
	 * on the following fields being set until all the scsi_pkt
	 * allocation violations discussed in scsi_pkt.h are all resolved.
	 */
	pkt->pkt_cdblen = cmdlen;
	pkt->pkt_tgtlen = tgtlen;
	pkt->pkt_scblen = statuslen;

	return (pkt);
}

/*
 * Called by an HBA to free a scsi_pkt
 */
/*ARGSUSED*/
void
scsi_hba_pkt_free(
	struct scsi_address	*ap,
	struct scsi_pkt		*pkt)
{
	kmem_free(pkt, ((struct scsi_pkt_wrapper *)pkt)->pkt_wrapper_len);
}

/*
 * Return 1 if the scsi_pkt used a proper allocator.
 *
 * The DDI does not allow a driver to allocate it's own scsi_pkt(9S), a
 * driver should not have *any* compiled in dependencies on "sizeof (struct
 * scsi_pkt)". While this has been the case for many years, a number of
 * drivers have still not been fixed. This function can be used to detect
 * improperly allocated scsi_pkt structures, and produce messages identifying
 * drivers that need to be fixed.
 *
 * While drivers in violation are being fixed, this function can also
 * be used by the framework to detect packets that violated allocation
 * rules.
 *
 * NB: It is possible, but very unlikely, for this code to return a false
 * positive (finding correct magic, but for wrong reasons).  Careful
 * consideration is needed for callers using this interface to condition
 * access to newer scsi_pkt fields (those after pkt_reason).
 *
 * NB: As an aid to minimizing the amount of work involved in 'fixing' legacy
 * drivers that violate scsi_*(9S) allocation rules, private
 * scsi_pkt_size()/scsi_size_clean() functions are available (see their
 * implementation for details).
 *
 * *** Non-legacy use of scsi_pkt_size() is discouraged. ***
 *
 * NB: When supporting broken HBA drivers is not longer a concern, this
 * code should be removed.
 */
int
scsi_pkt_allocated_correctly(struct scsi_pkt *pkt)
{
	struct scsi_pkt_wrapper	*hba_pkt = (struct scsi_pkt_wrapper *)pkt;
	int	magic;
	major_t	major;
#ifdef	DEBUG
	int	*pspwm, *pspcwm;

	/*
	 * We are getting scsi packets from two 'correct' wrapper schemes,
	 * make sure we are looking at the same place in both to detect
	 * proper allocation.
	 */
	pspwm = &((struct scsi_pkt_wrapper *)0)->pkt_wrapper_magic;
	pspcwm = &((struct scsi_pkt_cache_wrapper *)0)->pcw_magic;
	ASSERT(pspwm == pspcwm);
#endif	/* DEBUG */


	/*
	 * Check to see if driver is scsi_size_clean(), assume it
	 * is using the scsi_pkt_size() interface everywhere it needs to
	 * if the driver indicates it is scsi_size_clean().
	 */
	major = ddi_driver_major(P_TO_TRAN(pkt)->tran_hba_dip);
	if (devnamesp[major].dn_flags & DN_SCSI_SIZE_CLEAN)
		return (1);		/* ok */

	/*
	 * Special case crossing a page boundary. If the scsi_pkt was not
	 * allocated correctly, then across a page boundary we have a
	 * fault hazard.
	 */
	if ((((uintptr_t)(&hba_pkt->scsi_pkt)) & MMU_PAGEMASK) ==
	    (((uintptr_t)(&hba_pkt->pkt_wrapper_magic)) & MMU_PAGEMASK)) {
		/* fastpath, no cross-page hazard */
		magic = hba_pkt->pkt_wrapper_magic;
	} else {
		/* add protection for cross-page hazard */
		if (ddi_peek32((dev_info_t *)NULL,
		    &hba_pkt->pkt_wrapper_magic, &magic) == DDI_FAILURE) {
			return (0);	/* violation */
		}
	}

	/* properly allocated packet always has correct magic */
	return ((magic == PKT_WRAPPER_MAGIC) ? 1 : 0);
}

/*
 * Private interfaces to simplify conversion of legacy drivers so they don't
 * depend on scsi_*(9S) size. Instead of using these private interface, HBA
 * drivers should use DDI sanctioned allocation methods:
 *
 *	scsi_pkt	Use scsi_hba_pkt_alloc(9F), or implement
 *			tran_setup_pkt(9E).
 *
 *	scsi_device	You are doing something strange/special, a scsi_device
 *			structure should only be allocated by scsi_hba.c
 *			initchild code or scsi_vhci.c code.
 *
 *	scsi_hba_tran	Use scsi_hba_tran_alloc(9F).
 */
size_t
scsi_pkt_size()
{
	return (sizeof (struct scsi_pkt));
}

size_t
scsi_hba_tran_size()
{
	return (sizeof (scsi_hba_tran_t));
}

size_t
scsi_device_size()
{
	return (sizeof (struct scsi_device));
}

/*
 * Legacy compliance to scsi_pkt(9S) allocation rules through use of
 * scsi_pkt_size() is detected by the 'scsi-size-clean' driver.conf property
 * or an HBA driver calling to scsi_size_clean() from attach(9E).  A driver
 * developer should only indicate that a legacy driver is clean after using
 * SCSI_SIZE_CLEAN_VERIFY to ensure compliance (see scsi_pkt.h).
 */
void
scsi_size_clean(dev_info_t *self)
{
	major_t		major;
	struct devnames	*dnp;

	ASSERT(self);
	major = ddi_driver_major(self);
	ASSERT(major < devcnt);
	if (major >= devcnt) {
		SCSI_HBA_LOG((_LOG(WARN), self, NULL,
		    "scsi_pkt_size: bogus major: %d", major));
		return;
	}

	/* Set DN_SCSI_SIZE_CLEAN flag in dn_flags. */
	dnp = &devnamesp[major];
	if ((dnp->dn_flags & DN_SCSI_SIZE_CLEAN) == 0) {
		LOCK_DEV_OPS(&dnp->dn_lock);
		dnp->dn_flags |= DN_SCSI_SIZE_CLEAN;
		UNLOCK_DEV_OPS(&dnp->dn_lock);
	}
}


/*
 * Called by an HBA to map strings to capability indices
 */
int
scsi_hba_lookup_capstr(
	char			*capstr)
{
	/*
	 * Capability strings: only add entries to mask the legacy
	 * '_' vs. '-' misery.  All new capabilities should use '-',
	 * and be captured be added to SCSI_CAP_ASCII.
	 */
	static struct cap_strings {
		char	*cap_string;
		int	cap_index;
	} cap_strings[] = {
		{ "dma_max",		SCSI_CAP_DMA_MAX		},
		{ "msg_out",		SCSI_CAP_MSG_OUT		},
		{ "wide_xfer",		SCSI_CAP_WIDE_XFER		},
		{ NULL,			0				}
	};
	static char		*cap_ascii[] = SCSI_CAP_ASCII;
	char			**cap;
	int			i;
	struct cap_strings	*cp;

	for (cap = cap_ascii, i = 0; *cap != NULL; cap++, i++)
		if (strcmp(*cap, capstr) == 0)
			return (i);

	for (cp = cap_strings; cp->cap_string != NULL; cp++)
		if (strcmp(cp->cap_string, capstr) == 0)
			return (cp->cap_index);

	return (-1);
}

/*
 * Called by an HBA to determine if the system is in 'panic' state.
 */
int
scsi_hba_in_panic()
{
	return (panicstr != NULL);
}

/*
 * If a SCSI target driver attempts to mmap memory,
 * the buck stops here.
 */
/*ARGSUSED*/
static int
scsi_hba_map_fault(
	dev_info_t		*self,
	dev_info_t		*child,
	struct hat		*hat,
	struct seg		*seg,
	caddr_t			addr,
	struct devpage		*dp,
	pfn_t			pfn,
	uint_t			prot,
	uint_t			lock)
{
	return (DDI_FAILURE);
}

static int
scsi_hba_get_eventcookie(
	dev_info_t		*self,
	dev_info_t		*child,
	char			*name,
	ddi_eventcookie_t	*eventp)
{
	scsi_hba_tran_t		*tran;

	tran = ddi_get_driver_private(self);
	if (tran->tran_get_eventcookie &&
	    ((*tran->tran_get_eventcookie)(self,
	    child, name, eventp) == DDI_SUCCESS)) {
		return (DDI_SUCCESS);
	}

	return (ndi_busop_get_eventcookie(self, child, name, eventp));
}

static int
scsi_hba_add_eventcall(
	dev_info_t		*self,
	dev_info_t		*child,
	ddi_eventcookie_t	event,
	void			(*callback)(
					dev_info_t *self,
					ddi_eventcookie_t event,
					void *arg,
					void *bus_impldata),
	void			*arg,
	ddi_callback_id_t	*cb_id)
{
	scsi_hba_tran_t		*tran;

	tran = ddi_get_driver_private(self);
	if (tran->tran_add_eventcall &&
	    ((*tran->tran_add_eventcall)(self, child,
	    event, callback, arg, cb_id) == DDI_SUCCESS)) {
		return (DDI_SUCCESS);
	}

	return (DDI_FAILURE);
}

static int
scsi_hba_remove_eventcall(dev_info_t *self, ddi_callback_id_t cb_id)
{
	scsi_hba_tran_t		*tran;
	ASSERT(cb_id);

	tran = ddi_get_driver_private(self);
	if (tran->tran_remove_eventcall &&
	    ((*tran->tran_remove_eventcall)(
	    self, cb_id) == DDI_SUCCESS)) {
		return (DDI_SUCCESS);
	}

	return (DDI_FAILURE);
}

static int
scsi_hba_post_event(
	dev_info_t		*self,
	dev_info_t		*child,
	ddi_eventcookie_t	event,
	void			*bus_impldata)
{
	scsi_hba_tran_t		*tran;

	tran = ddi_get_driver_private(self);
	if (tran->tran_post_event &&
	    ((*tran->tran_post_event)(self,
	    child, event, bus_impldata) == DDI_SUCCESS)) {
		return (DDI_SUCCESS);
	}

	return (DDI_FAILURE);
}

/*
 * Default getinfo(9e) for scsi_hba
 */
/* ARGSUSED */
static int
scsi_hba_info(dev_info_t *self, ddi_info_cmd_t infocmd, void *arg,
    void **result)
{
	int error = DDI_SUCCESS;

	switch (infocmd) {
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(intptr_t)(MINOR2INST(getminor((dev_t)arg)));
		break;
	default:
		error = DDI_FAILURE;
	}
	return (error);
}

/*
 * Default open and close routine for scsi_hba
 */
/* ARGSUSED */
int
scsi_hba_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	dev_info_t	*self;
	scsi_hba_tran_t	*tran;
	int		rv = 0;

	if (otyp != OTYP_CHR)
		return (EINVAL);

	if ((self = e_ddi_hold_devi_by_dev(*devp, 0)) == NULL)
		return (ENXIO);

	tran = ddi_get_driver_private(self);
	if (tran == NULL) {
		ddi_release_devi(self);
		return (ENXIO);
	}

	/*
	 * tran_open_flag bit field:
	 *	0:	closed
	 *	1:	shared open by minor at bit position
	 *	1 at 31st bit:	exclusive open
	 */
	mutex_enter(&(tran->tran_open_lock));
	if (flags & FEXCL) {
		if (tran->tran_open_flag != 0) {
			rv = EBUSY;		/* already open */
		} else {
			tran->tran_open_flag = TRAN_OPEN_EXCL;
		}
	} else {
		if (tran->tran_open_flag == TRAN_OPEN_EXCL) {
			rv = EBUSY;		/* already excl. open */
		} else {
			int minor = getminor(*devp) & TRAN_MINOR_MASK;
			tran->tran_open_flag |= (1 << minor);
			/*
			 * Ensure that the last framework reserved minor
			 * is unused. Otherwise, the exclusive open
			 * mechanism may break.
			 */
			ASSERT(minor != 31);
		}
	}
	mutex_exit(&(tran->tran_open_lock));

	ddi_release_devi(self);
	return (rv);
}

/* ARGSUSED */
int
scsi_hba_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	dev_info_t	*self;
	scsi_hba_tran_t	*tran;

	if (otyp != OTYP_CHR)
		return (EINVAL);

	if ((self = e_ddi_hold_devi_by_dev(dev, 0)) == NULL)
		return (ENXIO);

	tran = ddi_get_driver_private(self);
	if (tran == NULL) {
		ddi_release_devi(self);
		return (ENXIO);
	}

	mutex_enter(&(tran->tran_open_lock));
	if (tran->tran_open_flag == TRAN_OPEN_EXCL) {
		tran->tran_open_flag = 0;
	} else {
		int minor = getminor(dev) & TRAN_MINOR_MASK;
		tran->tran_open_flag &= ~(1 << minor);
	}
	mutex_exit(&(tran->tran_open_lock));

	ddi_release_devi(self);
	return (0);
}

/*
 * standard ioctl commands for SCSI hotplugging
 */
/* ARGSUSED */
int
scsi_hba_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	dev_info_t		*self;
	struct devctl_iocdata	*dcp = NULL;
	dev_info_t		*child = NULL;
	mdi_pathinfo_t		*path = NULL;
	struct scsi_device	*sd;
	scsi_hba_tran_t		*tran;
	uint_t			bus_state;
	int			rv = 0;
	int			circ;
	char			*name;
	char			*addr;

	self = e_ddi_hold_devi_by_dev(dev, 0);
	if (self == NULL) {
		rv = ENXIO;
		goto out;
	}

	tran = ddi_get_driver_private(self);
	if (tran == NULL) {
		rv = ENXIO;
		goto out;
	}

	/* Ioctls for which the generic implementation suffices. */
	switch (cmd) {
	case DEVCTL_BUS_GETSTATE:
		rv = ndi_devctl_ioctl(self, cmd, arg, mode, 0);
		goto out;
	}

	/* read devctl ioctl data */
	if (ndi_dc_allochdl((void *)arg, &dcp) != NDI_SUCCESS) {
		rv = EFAULT;
		goto out;
	}

	/* Ioctls that require child identification */
	switch (cmd) {
	case DEVCTL_DEVICE_GETSTATE:
	case DEVCTL_DEVICE_ONLINE:
	case DEVCTL_DEVICE_OFFLINE:
	case DEVCTL_DEVICE_REMOVE:
	case DEVCTL_DEVICE_RESET:
		name = ndi_dc_getname(dcp);
		addr = ndi_dc_getaddr(dcp);
		if ((name == NULL) || (addr == NULL)) {
			rv = EINVAL;
			goto out;
		}

		/*
		 * Find child with name@addr - might find a devinfo
		 * child (child), a pathinfo child (path), or nothing.
		 */
		scsi_hba_devi_enter(self, &circ);

		(void) scsi_findchild(self, name, addr, 1, &child, &path, NULL);
		if (path) {
			/* Found a pathinfo */
			ASSERT(path && (child == NULL));
			mdi_hold_path(path);
			scsi_hba_devi_exit_phci(self, circ);
			sd = NULL;
		} else if (child) {
			/* Found a devinfo */
			ASSERT(child && (path == NULL));

			/* verify scsi_device of child */
			if (ndi_flavor_get(child) == SCSA_FLAVOR_SCSI_DEVICE)
				sd = ddi_get_driver_private(child);
			else
				sd = NULL;
		} else {
			ASSERT((path == NULL) && (child == NULL));
			scsi_hba_devi_exit(self, circ);
			rv = ENXIO;			/* found nothing */
			goto out;
		}
		break;

	case DEVCTL_BUS_RESETALL:	/* ioctl that operate on any child */
		/*
		 * Find a child's scsi_address so we can invoke tran_reset.
		 *
		 * Future: If no child exists, we could fake a child. This will
		 * be a enhancement for the future - for now, we fall back to
		 * BUS_RESET.
		 */
		scsi_hba_devi_enter(self, &circ);
		child = ddi_get_child(self);
		sd = NULL;
		while (child) {
			/* verify scsi_device of child */
			if (ndi_flavor_get(child) == SCSA_FLAVOR_SCSI_DEVICE)
				sd = ddi_get_driver_private(child);
			if (sd != NULL) {
				/*
				 * NOTE: node has a scsi_device structure, so
				 * it must be initialized.
				 */
				ndi_hold_devi(child);
				break;
			}
			child = ddi_get_next_sibling(child);
		}
		scsi_hba_devi_exit(self, circ);
		break;
	}

	switch (cmd) {
	case DEVCTL_DEVICE_GETSTATE:
		if (path) {
			if (mdi_dc_return_dev_state(path, dcp) != MDI_SUCCESS)
				rv = EFAULT;
		} else if (child) {
			if (ndi_dc_return_dev_state(child, dcp) != NDI_SUCCESS)
				rv = EFAULT;
		} else {
			rv = ENXIO;
		}
		break;

	case DEVCTL_DEVICE_RESET:
		if (sd == NULL) {
			rv = ENOTTY;
			break;
		}
		if (tran->tran_reset == NULL) {
			rv = ENOTSUP;
			break;
		}

		/* Start with the small stick */
		if (scsi_reset(&sd->sd_address, RESET_LUN) == 1)
			break;		/* LUN reset worked */
		if (scsi_reset(&sd->sd_address, RESET_TARGET) != 1)
			rv = EIO;	/* Target reset failed */
		break;

	case DEVCTL_BUS_QUIESCE:
		if ((ndi_get_bus_state(self, &bus_state) == NDI_SUCCESS) &&
		    (bus_state == BUS_QUIESCED))
			rv = EALREADY;
		else if (tran->tran_quiesce == NULL)
			rv = ENOTSUP; /* man ioctl(7I) says ENOTTY */
		else if (tran->tran_quiesce(self) != 0)
			rv = EIO;
		else if (ndi_set_bus_state(self, BUS_QUIESCED) != NDI_SUCCESS)
			rv = EIO;
		break;

	case DEVCTL_BUS_UNQUIESCE:
		if ((ndi_get_bus_state(self, &bus_state) == NDI_SUCCESS) &&
		    (bus_state == BUS_ACTIVE))
			rv = EALREADY;
		else if (tran->tran_unquiesce == NULL)
			rv = ENOTSUP; /* man ioctl(7I) says ENOTTY */
		else if (tran->tran_unquiesce(self) != 0)
			rv = EIO;
		else if (ndi_set_bus_state(self, BUS_ACTIVE) != NDI_SUCCESS)
			rv = EIO;
		break;

	case DEVCTL_BUS_RESET:
		if (tran->tran_bus_reset == NULL)
			rv = ENOTSUP; /* man ioctl(7I) says ENOTTY */
		else if (tran->tran_bus_reset(self, RESET_BUS) != 1)
			rv = EIO;
		break;

	case DEVCTL_BUS_RESETALL:
		if ((sd != NULL) &&
		    (scsi_reset(&sd->sd_address, RESET_ALL) == 1)) {
			break;		/* reset all worked */
		}
		if (tran->tran_bus_reset == NULL) {
			rv = ENOTSUP; /* man ioctl(7I) says ENOTTY */
			break;
		}
		if (tran->tran_bus_reset(self, RESET_BUS) != 1)
			rv = EIO;	/* bus reset failed */
		break;

	case DEVCTL_BUS_CONFIGURE:
		if (ndi_devi_config(self, NDI_DEVFS_CLEAN | NDI_DEVI_PERSIST |
		    NDI_CONFIG_REPROBE) != NDI_SUCCESS) {
			rv = EIO;
		}
		break;

	case DEVCTL_BUS_UNCONFIGURE:
		if (ndi_devi_unconfig(self,
		    NDI_DEVFS_CLEAN | NDI_DEVI_REMOVE) != NDI_SUCCESS) {
			rv = EBUSY;
		}
		break;

	case DEVCTL_DEVICE_ONLINE:
		ASSERT(child || path);
		if (path) {
			if (mdi_pi_online(path, NDI_USER_REQ) != MDI_SUCCESS)
				rv = EIO;
		} else {
			if (ndi_devi_online(child, 0) != NDI_SUCCESS)
				rv = EIO;
		}
		break;

	case DEVCTL_DEVICE_OFFLINE:
		ASSERT(child || path);
		if (sd != NULL)
			(void) scsi_clear_task_set(&sd->sd_address);
		if (path) {
			if (mdi_pi_offline(path, NDI_USER_REQ) != MDI_SUCCESS)
				rv = EIO;
		} else {
			if (ndi_devi_offline(child,
			    NDI_DEVFS_CLEAN) != NDI_SUCCESS)
				rv = EIO;
		}
		break;

	case DEVCTL_DEVICE_REMOVE:
		ASSERT(child || path);
		if (sd != NULL)
			(void) scsi_clear_task_set(&sd->sd_address);
		if (path) {
			/* NOTE: don't pass NDI_DEVI_REMOVE to mdi_pi_offline */
			if (mdi_pi_offline(path, NDI_USER_REQ) == MDI_SUCCESS) {
				scsi_hba_devi_enter_phci(self, &circ);
				mdi_rele_path(path);

				/* ... here is the DEVICE_REMOVE part. */
				(void) mdi_pi_free(path, 0);
				path = NULL;
			} else {
				rv = EIO;
			}
		} else {
			if (ndi_devi_offline(child,
			    NDI_DEVFS_CLEAN | NDI_DEVI_REMOVE) != NDI_SUCCESS)
				rv = EIO;
		}
		break;

	default:
		ASSERT(dcp != NULL);
		rv = ENOTTY;
		break;
	}

	/* all done -- clean up and return */
out:
	/* release hold on what we found */
	if (path) {
		scsi_hba_devi_enter_phci(self, &circ);
		mdi_rele_path(path);
	}
	if (path || child)
		scsi_hba_devi_exit(self, circ);

	if (dcp)
		ndi_dc_freehdl(dcp);

	if (self)
		ddi_release_devi(self);

	*rvalp = rv;

	return (rv);
}

/*ARGSUSED*/
static int
scsi_hba_fm_init_child(dev_info_t *self, dev_info_t *child, int cap,
    ddi_iblock_cookie_t *ibc)
{
	scsi_hba_tran_t	*tran = ddi_get_driver_private(self);

	return (tran ? tran->tran_fm_capable : scsi_fm_capable);
}

static int
scsi_hba_bus_power(dev_info_t *self, void *impl_arg, pm_bus_power_op_t op,
    void *arg, void *result)
{
	scsi_hba_tran_t	*tran;

	tran = ddi_get_driver_private(self);
	if (tran && tran->tran_bus_power) {
		return (tran->tran_bus_power(self, impl_arg,
		    op, arg, result));
	}

	return (pm_busop_bus_power(self, impl_arg, op, arg, result));
}

/*
 * Return the lun64 value from a address string: "addr,lun[,sfunc]". Either
 * the lun is after the first ',' or the entire address string is the lun.
 * Return SCSI_LUN64_ILLEGAL if the format is incorrect. A lun64 is at most
 * 16 hex digits long.
 *
 * If the address string specified has incorrect syntax (busconfig one of
 * bogus /devices path) then scsi_addr_to_lun64 can return SCSI_LUN64_ILLEGAL.
 */
static scsi_lun64_t
scsi_addr_to_lun64(char *addr)
{
	scsi_lun64_t	lun64;
	char		*s;
	int		i;

	if (addr) {
		s = strchr(addr, ',');			/* "addr,lun" */
		if (s)
			s++;				/* skip ',', at lun */
		else
			s = addr;			/* "lun" */

		for (lun64 = 0, i = 0; *s && (i < 16); s++, i++) {
			if (*s >= '0' && *s <= '9')
				lun64 = (lun64 << 4) + (*s - '0');
			else if (*s >= 'A' && *s <= 'F')
				lun64 = (lun64 << 4) + 10 + (*s - 'A');
			else if (*s >= 'a' && *s <= 'f')
				lun64 = (lun64 << 4) + 10 + (*s - 'a');
			else
				break;
		}
		if (*s && (*s != ','))		/* [,sfunc] is OK */
			lun64 = SCSI_LUN64_ILLEGAL;
	} else
		lun64 = SCSI_LUN64_ILLEGAL;

	if (lun64 == SCSI_LUN64_ILLEGAL)
		SCSI_HBA_LOG((_LOG(2), NULL, NULL,
		    "addr_to_lun64 %s lun %" PRIlun64,
		    addr ? addr : "NULL", lun64));
	return (lun64);
}

/*
 * Return the sfunc value from a address string: "addr,lun[,sfunc]". Either the
 * sfunc is after the second ',' or the entire address string is the sfunc.
 * Return -1 if there is only one ',' in the address string or the string is
 * invalid. An sfunc is at most two hex digits long.
 */
static int
scsi_addr_to_sfunc(char *addr)
{
	int		sfunc;
	char		*s;
	int		i;

	if (addr) {
		s = strchr(addr, ',');			/* "addr,lun" */
		if (s) {
			s++;				/* skip ',', at lun */
			s = strchr(s, ',');		/* "lun,sfunc" */
			if (s == NULL)
				return (-1);		/* no ",sfunc" */
			s++;				/* skip ',', at sfunc */
		} else
			s = addr;			/* "sfunc" */

		for (sfunc = 0, i = 0; *s && (i < 2); s++, i++) {
			if (*s >= '0' && *s <= '9')
				sfunc = (sfunc << 4) + (*s - '0');
			else if (*s >= 'A' && *s <= 'F')
				sfunc = (sfunc << 4) + 10 + (*s - 'A');
			else if (*s >= 'a' && *s <= 'f')
				sfunc = (sfunc << 4) + 10 + (*s - 'a');
			else
				break;
		}
		if (*s)
			sfunc = -1;			/* illegal */
	} else
		sfunc = -1;
	return (sfunc);
}

/*
 * Convert scsi ascii string data to NULL terminated (semi) legal IEEE 1275
 * "compatible" (name) property form.
 *
 * For ASCII INQUIRY data, a one-way conversion algorithm is needed to take
 * SCSI_ASCII (20h - 7Eh) to a 1275-like compatible form. The 1275 spec allows
 * letters, digits, one ",", and ". _ + -", all limited by a maximum 31
 * character length. Since ", ." are used as separators in the compatible
 * string itself, they are converted to "_". All SCSI_ASCII characters that
 * are illegal in 1275, as well as any illegal SCSI_ASCII characters
 * encountered, are converted to "_". To reduce length, trailing blanks are
 * trimmed from SCSI_ASCII fields prior to conversion.
 *
 * Example: SCSI_ASCII "ST32550W SUN2.1G" -> "ST32550W_SUN2_1G"
 *
 * NOTE: the 1275 string form is always less than or equal to the scsi form.
 */
static char *
string_scsi_to_1275(char *s_1275, char *s_scsi, int len)
{
	(void) strncpy(s_1275, s_scsi, len);
	s_1275[len--] = '\0';

	while (len >= 0) {
		if (s_1275[len] == ' ')
			s_1275[len--] = '\0';	/* trim trailing " " */
		else
			break;
	}

	while (len >= 0) {
		if (((s_1275[len] >= 'a') && (s_1275[len] <= 'z')) ||
		    ((s_1275[len] >= 'A') && (s_1275[len] <= 'Z')) ||
		    ((s_1275[len] >= '0') && (s_1275[len] <= '9')) ||
		    (s_1275[len] == '_') ||
		    (s_1275[len] == '+') ||
		    (s_1275[len] == '-'))
			len--;			/* legal 1275  */
		else
			s_1275[len--] = '_';	/* illegal SCSI_ASCII | 1275 */
	}

	return (s_1275);
}

/*
 * Given the inquiry data, binding_set, and dtype_node for a scsi device,
 * return the nodename and compatible property for the device. The "compatible"
 * concept comes from IEEE-1275. The compatible information is returned is in
 * the correct form for direct use defining the "compatible" string array
 * property. Internally, "compatible" is also used to determine the nodename
 * to return.
 *
 * This function is provided as a separate entry point for use by drivers that
 * currently issue their own non-SCSA inquiry command and perform their own
 * node creation based their own private compiled in tables. Converting these
 * drivers to use this interface provides a quick easy way of obtaining
 * consistency as well as the flexibility associated with the 1275 techniques.
 *
 * The dtype_node is passed as a separate argument (instead of having the
 * implementation use inq_dtype). It indicates that information about
 * a secondary function embedded service should be produced.
 *
 * Callers must always use scsi_hba_nodename_compatible_free, even if
 * *nodenamep is null, to free the nodename and compatible information
 * when done.
 *
 * If a nodename can't be determined then **compatiblep will point to a
 * diagnostic string containing all the compatible forms.
 *
 * NOTE: some compatible strings may violate the 31 character restriction
 * imposed by IEEE-1275. This is not a problem because Solaris does not care
 * about this 31 character limit.
 *
 * Each compatible form belongs to a form-group.  The form-groups currently
 * defined are generic ("scsiclass"), binding-set ("scsa.b"), and failover
 * ("scsa.f").
 *
 * The following compatible forms, in high to low precedence
 * order, are defined for SCSI target device nodes.
 *
 *  scsiclass,DDEEFFF.vVVVVVVVV.pPPPPPPPPPPPPPPPP.rRRRR	(1 *1&2)
 *  scsiclass,DDEE.vVVVVVVVV.pPPPPPPPPPPPPPPPP.rRRRR	(2 *1)
 *  scsiclass,DDFFF.vVVVVVVVV.pPPPPPPPPPPPPPPPP.rRRRR	(3 *2)
 *  scsiclass,DD.vVVVVVVVV.pPPPPPPPPPPPPPPPP.rRRRR	(4)
 *  scsiclass,DDEEFFF.vVVVVVVVV.pPPPPPPPPPPPPPPPP	(5 *1&2)
 *  scsiclass,DDEE.vVVVVVVVV.pPPPPPPPPPPPPPPPP		(6 *1)
 *  scsiclass,DDFFF.vVVVVVVVV.pPPPPPPPPPPPPPPPP		(7 *2)
 *  scsiclass,DD.vVVVVVVVV.pPPPPPPPPPPPPPPPP		(8)
 *  scsa,DD.bBBBBBBBB					(8.5 *3)
 *  scsiclass,DDEEFFF					(9 *1&2)
 *  scsiclass,DDEE					(10 *1)
 *  scsiclass,DDFFF					(11 *2)
 *  scsiclass,DD					(12)
 *  scsa.fFFF						(12.5 *4)
 *  scsiclass						(13)
 *
 *	  *1 only produced on a secondary function node
 *	  *2 only produced when generic form-group flags exist.
 *	  *3 only produced when binding-set form-group legacy support is needed
 *	  *4 only produced when failover form-group flags exist.
 *
 *	where:
 *
 *	v			is the letter 'v'. Denotest the
 *				beginning of VVVVVVVV.
 *
 *	VVVVVVVV		Translated scsi_vendor.
 *
 *	p			is the letter 'p'. Denotes the
 *				beginning of PPPPPPPPPPPPPPPP.
 *
 *	PPPPPPPPPPPPPPPP	Translated scsi_product.
 *
 *	r			is the letter 'r'. Denotes the
 *				beginning of RRRR.
 *
 *	RRRR			Translated scsi_revision.
 *
 *	DD			is a two digit ASCII hexadecimal
 *				number. The value of the two digits is
 *				based one the SCSI "Peripheral device
 *				type" command set associated with the
 *				node. On a primary node this is the
 *				scsi_dtype of the primary command set,
 *				on a secondary node this is the
 *				scsi_dtype associated with the secondary
 *				function embedded command set.
 *
 *	EE			Same encoding used for DD. This form is
 *				only generated on secondary function
 *				nodes. The DD secondary function is embedded
 *				in an EE device.
 *
 *	FFF			Concatenation, in alphabetical order,
 *				of the flag characters within a form-group.
 *				For a given form-group, the following
 *				flags are defined.
 *
 *				scsiclass: (generic form-group):
 *				  R	Removable_Media: Used when
 *					inq_rmb is set.
 *				  S	SAF-TE device: Used when
 *					inquiry information indicates
 *					SAF-TE devices.
 *
 *				scsa.f:	(failover form-group):
 *				  E	Explicit Target_Port_Group: Used
 *					when inq_tpgse is set and 'G' is
 *					alse present.
 *				  G	GUID: Used when a GUID can be
 *					generated for the device.
 *				  I	Implicit Target_Port_Group: Used
 *					when inq_tpgs is set and 'G' is
 *					also present.
 *
 *				Forms using FFF are only be generated
 *				if there are applicable flag
 *				characters.
 *
 *	b			is the letter 'b'. Denotes the
 *				beginning of BBBBBBBB.
 *
 *	BBBBBBBB		Binding-set. Operating System Specific:
 *				scsi-binding-set property of HBA.
 */
#define	NCOMPAT		(1 + (13 + 2) + 1)
#define	COMPAT_LONGEST	(strlen( \
	"scsiclass,DDEEFFF.vVVVVVVVV.pPPPPPPPPPPPPPPPP.rRRRR" + 1))

/*
 * Private version with extra device 'identity' arguments to allow code
 * to determine GUID FFF support.
 */
static void
scsi_hba_ident_nodename_compatible_get(struct scsi_inquiry *inq,
    uchar_t *inq80, size_t inq80len, uchar_t *inq83, size_t inq83len,
    char *binding_set, int dtype_node, char *compat0,
    char **nodenamep, char **drivernamep,
    char ***compatiblep, int *ncompatiblep)
{
	char		vid[sizeof (inq->inq_vid) + 1 ];
	char		pid[sizeof (inq->inq_pid) + 1];
	char		rev[sizeof (inq->inq_revision) + 1];
	char		gf[sizeof ("RS\0")];
	char		ff[sizeof ("EGI\0")];
	int		dtype_device;
	int		ncompat;		/* number of compatible */
	char		**compatp;		/* compatible ptrs */
	int		i;
	char		*nname;			/* nodename */
	char		*dname;			/* driver name */
	char		**csp;
	char		*p;
	int		tlen;
	int		len;
	major_t		major;
	ddi_devid_t	devid;
	char		*guid;
	uchar_t		*iqd = (uchar_t *)inq;

	/*
	 * Nodename_aliases: This table was originally designed to be
	 * implemented via a new nodename_aliases file - a peer to the
	 * driver_aliases that selects a nodename based on compatible
	 * forms in much the same say driver_aliases is used to select
	 * driver bindings from compatible forms. Each compatible form
	 * is an 'alias'. Until a more general need for a
	 * nodename_aliases file exists, which may never occur, the
	 * scsi mappings are described here via a compiled in table.
	 *
	 * This table contains nodename mappings for self-identifying
	 * scsi devices enumerated by the Solaris kernel. For a given
	 * device, the highest precedence "compatible" form with a
	 * mapping is used to select the nodename for the device. This
	 * will typically be a generic nodename, however in some legacy
	 * compatibility cases a driver nodename mapping may be selected.
	 *
	 * Because of possible breakage associated with switching SCSI
	 * target devices from driver nodenames to generic nodenames,
	 * we are currently unable to support generic nodenames for all
	 * SCSI devices (binding-sets). Although /devices paths are
	 * defined as unstable, avoiding possible breakage is
	 * important. Some of the newer SCSI transports (USB) already
	 * use generic nodenames. All new SCSI transports and target
	 * devices should use generic nodenames. At times this decision
	 * may be architecture dependent (sparc .vs. intel) based on when
	 * a transport was supported on a particular architecture.
	 *
	 * We provide a base set of generic nodename mappings based on
	 * scsiclass dtype and higher-precedence driver nodename
	 * mappings based on scsa "binding-set" to cover legacy
	 * issues. The binding-set is typically associated with
	 * "scsi-binding-set" property value of the HBA. The legacy
	 * mappings are provided independent of whether the driver they
	 * refer to is installed. This allows a correctly named node
	 * be created at discovery time, and binding to occur when/if
	 * an add_drv of the legacy driver occurs.
	 *
	 * We also have mappings for legacy SUN hardware that
	 * misidentifies itself (enclosure services which identify
	 * themselves as processors). All future hardware should use
	 * the correct dtype.
	 *
	 * As SCSI HBAs are modified to use the SCSA interfaces for
	 * self-identifying SCSI target devices (PSARC/2004/116) the
	 * nodename_aliases table (PSARC/2004/420) should be augmented
	 * with legacy mappings in order to maintain compatibility with
	 * existing /devices paths, especially for devices that house
	 * an OS. Failure to do this may cause upgrade problems.
	 * Additions for new target devices or transports should not
	 * add scsa binding-set compatible mappings.
	 */
	static struct nodename_aliases {
		char	*na_nodename;		/* nodename */
		char	*na_alias;		/* compatible form match */
	} na[] = {
	/* # mapping to generic nodenames based on scsi dtype */
		{"disk",		"scsiclass,00"},
		{"tape",		"scsiclass,01"},
		{"printer",		"scsiclass,02"},
		{"processor",		"scsiclass,03"},
		{"worm",		"scsiclass,04"},
		{"cdrom",		"scsiclass,05"},
		{"scanner",		"scsiclass,06"},
		{"optical-disk",	"scsiclass,07"},
		{"medium-changer",	"scsiclass,08"},
		{"obsolete",		"scsiclass,09"},
		{"prepress-a",		"scsiclass,0a"},
		{"prepress-b",		"scsiclass,0b"},
		{"array-controller",	"scsiclass,0c"},
		{"enclosure",		"scsiclass,0d"},
		{"disk",		"scsiclass,0e"},
		{"card-reader",		"scsiclass,0f"},
		{"bridge",		"scsiclass,10"},
		{"object-store",	"scsiclass,11"},
		{"reserved",		"scsiclass,12"},
		{"reserved",		"scsiclass,13"},
		{"reserved",		"scsiclass,14"},
		{"reserved",		"scsiclass,15"},
		{"reserved",		"scsiclass,16"},
		{"reserved",		"scsiclass,17"},
		{"reserved",		"scsiclass,18"},
		{"reserved",		"scsiclass,19"},
		{"reserved",		"scsiclass,1a"},
		{"reserved",		"scsiclass,1b"},
		{"reserved",		"scsiclass,1c"},
		{"reserved",		"scsiclass,1d"},
		{"well-known-lun",	"scsiclass,1e"},
		{"unknown",		"scsiclass,1f"},

#ifdef	sparc
	/* # legacy mapping to driver nodenames for fcp binding-set */
		{"ssd",			"scsa,00.bfcp"},
		{"st",			"scsa,01.bfcp"},
		{"sgen",		"scsa,08.bfcp"},
		{"ses",			"scsa,0d.bfcp"},

	/* # legacy mapping to driver nodenames for vhci binding-set */
		{"ssd",			"scsa,00.bvhci"},
		{"st",			"scsa,01.bvhci"},
		{"sgen",		"scsa,08.bvhci"},
		{"ses",			"scsa,0d.bvhci"},
#else	/* sparc */
	/* # for x86 fcp and vhci use generic nodenames */
#endif	/* sparc */

	/* # legacy mapping to driver nodenames for spi binding-set */
		{"sd",			"scsa,00.bspi"},
		{"sd",			"scsa,05.bspi"},
		{"sd",			"scsa,07.bspi"},
		{"st",			"scsa,01.bspi"},
		{"ses",			"scsa,0d.bspi"},

	/* #				SUN misidentified spi hardware */
		{"ses",			"scsiclass,03.vSUN.pD2"},
		{"ses",			"scsiclass,03.vSYMBIOS.pD1000"},

	/* # legacy mapping to driver nodenames for atapi binding-set */
		{"sd",			"scsa,00.batapi"},
		{"sd",			"scsa,05.batapi"},
		{"sd",			"scsa,07.batapi"},
		{"st",			"scsa,01.batapi"},
		{"unknown",		"scsa,0d.batapi"},

	/* # legacy mapping to generic nodenames for usb binding-set */
		{"disk",		"scsa,05.busb"},
		{"disk",		"scsa,07.busb"},
		{"changer",		"scsa,08.busb"},
		{"comm",		"scsa,09.busb"},
		{"array_ctlr",		"scsa,0c.busb"},
		{"esi",			"scsa,0d.busb"},

	/*
	 * mapping nodenames for mpt based on scsi dtype
	 * for being compatible with the original node names
	 * under mpt controller
	 */
		{"sd",			"scsa,00.bmpt"},
		{"sd",			"scsa,05.bmpt"},
		{"sd",			"scsa,07.bmpt"},
		{"st",			"scsa,01.bmpt"},
		{"ses",			"scsa,0d.bmpt"},
		{"sgen",		"scsa,08.bmpt"},
		{NULL,		NULL}
	};
	struct nodename_aliases *nap;

	/* NOTE: drivernamep can be NULL */
	ASSERT(nodenamep && compatiblep && ncompatiblep &&
	    (binding_set == NULL || (strlen(binding_set) <= 8)));
	if ((nodenamep == NULL) || (compatiblep == NULL) ||
	    (ncompatiblep == NULL))
		return;

	/*
	 * In order to reduce runtime we allocate one block of memory that
	 * contains both the NULL terminated array of pointers to compatible
	 * forms and the individual compatible strings. This block is
	 * somewhat larger than needed, but is short lived - it only exists
	 * until the caller can transfer the information into the "compatible"
	 * string array property and call scsi_hba_nodename_compatible_free.
	 */
	tlen = NCOMPAT * COMPAT_LONGEST;
	compatp = kmem_alloc((NCOMPAT * sizeof (char *)) + tlen, KM_SLEEP);

	/* convert inquiry data from SCSI ASCII to 1275 string */
	(void) string_scsi_to_1275(vid, inq->inq_vid,
	    sizeof (inq->inq_vid));
	(void) string_scsi_to_1275(pid, inq->inq_pid,
	    sizeof (inq->inq_pid));
	(void) string_scsi_to_1275(rev, inq->inq_revision,
	    sizeof (inq->inq_revision));
	ASSERT((strlen(vid) <= sizeof (inq->inq_vid)) &&
	    (strlen(pid) <= sizeof (inq->inq_pid)) &&
	    (strlen(rev) <= sizeof (inq->inq_revision)));

	/*
	 * Form flags in ***ALPHABETICAL*** order within form-group:
	 *
	 * NOTE: When adding a new flag to an existing form-group, careful
	 * consideration must be given to not breaking existing bindings
	 * based on that form-group.
	 */

	/*
	 * generic form-group flags
	 *   R	removable:
	 *	Set when inq_rmb is set and for well known scsi dtypes. For a
	 *	bus where the entire device is removable (like USB), we expect
	 *	the HBA to intercept the inquiry data and set inq_rmb.
	 *	Since OBP does not distinguish removable media in its generic
	 *	name selection we avoid setting the 'R' flag if the root is not
	 *	yet mounted.
	 *   S	SAF-TE device
	 *	Set when the device type is SAT-TE.
	 */
	i = 0;
	dtype_device = inq->inq_dtype & DTYPE_MASK;
	if (modrootloaded && (inq->inq_rmb ||
	    (dtype_device == DTYPE_WORM) ||
	    (dtype_device == DTYPE_RODIRECT) ||
	    (dtype_device == DTYPE_OPTICAL)))
		gf[i++] = 'R';			/* removable */
	gf[i] = '\0';

	if (modrootloaded &&
	    (dtype_device == DTYPE_PROCESSOR) &&
	    (strncmp((char *)&iqd[44], "SAF-TE", 4) == 0))
		gf[i++] = 'S';
	gf[i] = '\0';

	/*
	 * failover form-group flags
	 *   E	Explicit Target_Port_Group_Supported:
	 *	Set for a device that has a GUID if inq_tpgse also set.
	 *   G	GUID:
	 *	Set when we have identity information, can determine a devid
	 *	from the identity information, and can generate a guid from
	 *	that devid.
	 *   I	Implicit Target_Port_Group_Supported:
	 *	Set for a device that has a GUID if inq_tpgs also set.
	 */
	i = 0;
	if ((inq80 || inq83) &&
	    (ddi_devid_scsi_encode(DEVID_SCSI_ENCODE_VERSION_LATEST, NULL,
	    (uchar_t *)inq, sizeof (*inq), inq80, inq80len, inq83, inq83len,
	    &devid) == DDI_SUCCESS)) {
		guid = ddi_devid_to_guid(devid);
		ddi_devid_free(devid);
	} else
		guid = NULL;
	if (guid && (inq->inq_tpgs & TPGS_FAILOVER_EXPLICIT))
		ff[i++] = 'E';			/* EXPLICIT TPGS */
	if (guid)
		ff[i++] = 'G';			/* GUID */
	if (guid && (inq->inq_tpgs & TPGS_FAILOVER_IMPLICIT))
		ff[i++] = 'I';			/* IMPLICIT TPGS */
	ff[i] = '\0';
	if (guid)
		ddi_devid_free_guid(guid);

	/*
	 * Construct all applicable compatible forms. See comment at the
	 * head of the function for a description of the compatible forms.
	 */
	csp = compatp;
	p = (char *)(compatp + NCOMPAT);

	/* ( 0) driver (optional, not documented in scsi(4)) */
	if (compat0) {
		*csp++ = p;
		(void) snprintf(p, tlen, "%s", compat0);
		len = strlen(p) + 1;
		p += len;
		tlen -= len;
	}

	/* ( 1) scsiclass,DDEEFFF.vV.pP.rR */
	if ((dtype_device != dtype_node) && *gf && *vid && *pid && *rev) {
		*csp++ = p;
		(void) snprintf(p, tlen, "scsiclass,%02x%02x%s.v%s.p%s.r%s",
		    dtype_node, dtype_device, gf, vid, pid, rev);
		len = strlen(p) + 1;
		p += len;
		tlen -= len;
	}

	/* ( 2) scsiclass,DDEE.vV.pP.rR */
	if ((dtype_device != dtype_node) && *vid && *pid && *rev) {
		*csp++ = p;
		(void) snprintf(p, tlen, "scsiclass,%02x%02x.v%s.p%s.r%s",
		    dtype_node, dtype_device, vid, pid, rev);
		len = strlen(p) + 1;
		p += len;
		tlen -= len;
	}

	/* ( 3) scsiclass,DDFFF.vV.pP.rR */
	if (*gf && *vid && *pid && *rev) {
		*csp++ = p;
		(void) snprintf(p, tlen, "scsiclass,%02x%s.v%s.p%s.r%s",
		    dtype_node, gf, vid, pid, rev);
		len = strlen(p) + 1;
		p += len;
		tlen -= len;
	}

	/* ( 4) scsiclass,DD.vV.pP.rR */
	if (*vid && *pid && *rev) {
		*csp++ = p;
		(void) snprintf(p, tlen, "scsiclass,%02x.v%s.p%s.r%s",
		    dtype_node, vid, pid, rev);
		len = strlen(p) + 1;
		p += len;
		tlen -= len;
	}

	/* ( 5) scsiclass,DDEEFFF.vV.pP */
	if ((dtype_device != dtype_node) && *gf && *vid && *pid) {
		*csp++ = p;
		(void) snprintf(p, tlen, "scsiclass,%02x%02x%s.v%s.p%s",
		    dtype_node, dtype_device, gf, vid, pid);
		len = strlen(p) + 1;
		p += len;
		tlen -= len;
	}

	/* ( 6) scsiclass,DDEE.vV.pP */
	if ((dtype_device != dtype_node) && *vid && *pid) {
		*csp++ = p;
		(void) snprintf(p, tlen, "scsiclass,%02x%02x.v%s.p%s",
		    dtype_node, dtype_device, vid, pid);
		len = strlen(p) + 1;
		p += len;
		tlen -= len;
	}

	/* ( 7) scsiclass,DDFFF.vV.pP */
	if (*gf && *vid && *pid) {
		*csp++ = p;
		(void) snprintf(p, tlen, "scsiclass,%02x%s.v%s.p%s",
		    dtype_node, gf, vid, pid);
		len = strlen(p) + 1;
		p += len;
		tlen -= len;
	}

	/* ( 8) scsiclass,DD.vV.pP */
	if (*vid && *pid) {
		*csp++ = p;
		(void) snprintf(p, tlen, "scsiclass,%02x.v%s.p%s",
		    dtype_node, vid, pid);
		len = strlen(p) + 1;
		p += len;
		tlen -= len;
	}

	/* (8.5) scsa,DD.bB (not documented in scsi(4)) */
	if (binding_set) {
		*csp++ = p;
		(void) snprintf(p, tlen, "scsa,%02x.b%s",
		    dtype_node, binding_set);
		len = strlen(p) + 1;
		p += len;
		tlen -= len;
	}

	/* ( 9) scsiclass,DDEEFFF */
	if ((dtype_device != dtype_node) && *gf) {
		*csp++ = p;
		(void) snprintf(p, tlen, "scsiclass,%02x%02x%s",
		    dtype_node, dtype_device, gf);
		len = strlen(p) + 1;
		p += len;
		tlen -= len;
	}

	/* (10) scsiclass,DDEE */
	if (dtype_device != dtype_node) {
		*csp++ = p;
		(void) snprintf(p, tlen, "scsiclass,%02x%02x",
		    dtype_node, dtype_device);
		len = strlen(p) + 1;
		p += len;
		tlen -= len;
	}

	/* (11) scsiclass,DDFFF */
	if (*gf) {
		*csp++ = p;
		(void) snprintf(p, tlen, "scsiclass,%02x%s",
		    dtype_node, gf);
		len = strlen(p) + 1;
		p += len;
		tlen -= len;
	}

	/* (12) scsiclass,DD */
	*csp++ = p;
	(void) snprintf(p, tlen, "scsiclass,%02x", dtype_node);
	len = strlen(p) + 1;
	p += len;
	tlen -= len;

	/* (12.5) scsa.fFFF */
	if (*ff) {
		*csp++ = p;
		(void) snprintf(p, tlen, "scsa.f%s", ff);
		len = strlen(p) + 1;
		p += len;
		tlen -= len;
	}

	/* (13) scsiclass */
	*csp++ = p;
	(void) snprintf(p, tlen, "scsiclass");
	len = strlen(p) + 1;
	p += len;
	tlen -= len;
	ASSERT(tlen >= 0);

	*csp = NULL;			/* NULL terminate array of pointers */
	ncompat = csp - compatp;

	/*
	 * When determining a nodename, a nodename_aliases specified
	 * mapping has precedence over using a driver_aliases specified
	 * driver binding as a nodename.
	 *
	 * See if any of the compatible forms have a nodename_aliases
	 * specified nodename. These mappings are described by
	 * nodename_aliases entries like:
	 *
	 *	disk		"scsiclass,00"
	 *	enclosure	"scsiclass,03.vSYMBIOS.pD1000"
	 *	ssd		"scsa,00.bfcp"
	 *
	 * All nodename_aliases mappings should idealy be to generic
	 * names, however a higher precedence legacy mapping to a
	 * driver name may exist. The highest precedence mapping
	 * provides the nodename, so legacy driver nodename mappings
	 * (if they exist) take precedence over generic nodename
	 * mappings.
	 */
	for (nname = NULL, csp = compatp; (nname == NULL) && *csp; csp++) {
		for (nap = na; nap->na_nodename; nap++) {
			if (strcmp(*csp, nap->na_alias) == 0) {
				nname = nap->na_nodename;
				break;
			}
		}
	}

	/*
	 * Determine the driver name based on compatible (which may
	 * have the passed in compat0 as the first item). The driver_aliases
	 * file has entries like
	 *
	 *	sd	"scsiclass,00"
	 *
	 * that map compatible forms to specific drivers. These entries are
	 * established by add_drv/update_drv. We use the most specific
	 * driver binding as the nodename. This matches the eventual
	 * ddi_driver_compatible_major() binding that will be
	 * established by bind_node()
	 */
	for (dname = NULL, csp = compatp; *csp; csp++) {
		major = ddi_name_to_major(*csp);
		if ((major == DDI_MAJOR_T_NONE) ||
		    (devnamesp[major].dn_flags & DN_DRIVER_REMOVED))
			continue;
		if (dname = ddi_major_to_name(major))
			break;
	}

	/*
	 * If no nodename_aliases mapping exists then use the
	 * driver_aliases specified driver binding as a nodename.
	 */
	if (nname == NULL)
		nname = dname;

	/* return results */
	if (nname) {
		*nodenamep = kmem_alloc(strlen(nname) + 1, KM_SLEEP);
		(void) strcpy(*nodenamep, nname);
	} else {
		*nodenamep = NULL;

		/*
		 * If no nodename could be determined return a special
		 * 'compatible' to be used for a diagnostic message. This
		 * compatible contains all compatible forms concatenated
		 * into a single string pointed to by the first element.
		 */
		for (csp = compatp; *(csp + 1); csp++)
			*((*csp) + strlen(*csp)) = ' ';
		*(compatp + 1) = NULL;
		ncompat = 1;

	}
	if (drivernamep) {
		if (dname) {
			*drivernamep = kmem_alloc(strlen(dname) + 1, KM_SLEEP);
			(void) strcpy(*drivernamep, dname);
		} else
			*drivernamep = NULL;
	}
	*compatiblep = compatp;
	*ncompatiblep = ncompat;
}

/*
 * Free allocations associated with scsi_hba_ident_nodename_compatible_get.
 */
static void
scsi_hba_ident_nodename_compatible_free(char *nodename, char *drivername,
    char **compatible)
{
	if (nodename)
		kmem_free(nodename, strlen(nodename) + 1);
	if (drivername)
		kmem_free(drivername, strlen(drivername) + 1);
	if (compatible)
		kmem_free(compatible, (NCOMPAT * sizeof (char *)) +
		    (NCOMPAT * COMPAT_LONGEST));
}

void
scsi_hba_nodename_compatible_get(struct scsi_inquiry *inq,
    char *binding_set, int dtype_node, char *compat0,
    char **nodenamep, char ***compatiblep, int *ncompatiblep)
{
	scsi_hba_ident_nodename_compatible_get(inq,
	    NULL, 0, NULL, 0, binding_set, dtype_node, compat0, nodenamep,
	    NULL, compatiblep, ncompatiblep);
}

void
scsi_hba_nodename_compatible_free(char *nodename, char **compatible)
{
	scsi_hba_ident_nodename_compatible_free(nodename, NULL, compatible);
}

/* return the unit_address associated with a scsi_device */
char *
scsi_device_unit_address(struct scsi_device *sd)
{
	mdi_pathinfo_t	*pip;

	ASSERT(sd && sd->sd_dev);
	if ((sd == NULL) || (sd->sd_dev == NULL))
		return (NULL);

	pip = (mdi_pathinfo_t *)sd->sd_pathinfo;
	if (pip)
		return (mdi_pi_get_addr(pip));
	else
		return (ddi_get_name_addr(sd->sd_dev));
}

/* scsi_device property interfaces */
#define	_TYPE_DEFINED(flags)						\
	(((flags & SCSI_DEVICE_PROP_TYPE_MSK) == SCSI_DEVICE_PROP_PATH) || \
	((flags & SCSI_DEVICE_PROP_TYPE_MSK) == SCSI_DEVICE_PROP_DEVICE))

#define	_DEVICE_PIP(sd, flags)						\
	((((flags & SCSI_DEVICE_PROP_TYPE_MSK) == SCSI_DEVICE_PROP_PATH) && \
	sd->sd_pathinfo) ? (mdi_pathinfo_t *)sd->sd_pathinfo : NULL)

int
scsi_device_prop_get_int(struct scsi_device *sd, uint_t flags,
    char *name, int defval)
{
	mdi_pathinfo_t	*pip;
	int		v = defval;
	int		data;
	int		rv;

	ASSERT(sd && name && sd->sd_dev && _TYPE_DEFINED(flags));
	if ((sd == NULL) || (name == NULL) || (sd->sd_dev == NULL) ||
	    !_TYPE_DEFINED(flags))
		return (v);

	pip = _DEVICE_PIP(sd, flags);
	if (pip) {
		rv = mdi_prop_lookup_int(pip, name, &data);
		if (rv == DDI_PROP_SUCCESS)
			v = data;
	} else
		v = ddi_prop_get_int(DDI_DEV_T_ANY, sd->sd_dev,
		    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, name, v);
	return (v);
}


int64_t
scsi_device_prop_get_int64(struct scsi_device *sd, uint_t flags,
    char *name, int64_t defval)
{
	mdi_pathinfo_t	*pip;
	int64_t		v = defval;
	int64_t		data;
	int		rv;

	ASSERT(sd && name && sd->sd_dev && _TYPE_DEFINED(flags));
	if ((sd == NULL) || (name == NULL) || (sd->sd_dev == NULL) ||
	    !_TYPE_DEFINED(flags))
		return (v);

	pip = _DEVICE_PIP(sd, flags);
	if (pip) {
		rv = mdi_prop_lookup_int64(pip, name, &data);
		if (rv == DDI_PROP_SUCCESS)
			v = data;
	} else
		v = ddi_prop_get_int64(DDI_DEV_T_ANY, sd->sd_dev,
		    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, name, v);
	return (v);
}

int
scsi_device_prop_lookup_byte_array(struct scsi_device *sd, uint_t flags,
    char *name, uchar_t **data, uint_t *nelements)
{
	mdi_pathinfo_t	*pip;
	int		rv;

	ASSERT(sd && name && sd->sd_dev && _TYPE_DEFINED(flags));
	if ((sd == NULL) || (name == NULL) || (sd->sd_dev == NULL) ||
	    !_TYPE_DEFINED(flags))
		return (DDI_PROP_INVAL_ARG);

	pip = _DEVICE_PIP(sd, flags);
	if (pip)
		rv = mdi_prop_lookup_byte_array(pip, name, data, nelements);
	else
		rv = ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, sd->sd_dev,
		    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
		    name, data, nelements);
	return (rv);
}

int
scsi_device_prop_lookup_int_array(struct scsi_device *sd, uint_t flags,
    char *name, int **data, uint_t *nelements)
{
	mdi_pathinfo_t	*pip;
	int		rv;

	ASSERT(sd && name && sd->sd_dev && _TYPE_DEFINED(flags));
	if ((sd == NULL) || (name == NULL) || (sd->sd_dev == NULL) ||
	    !_TYPE_DEFINED(flags))
		return (DDI_PROP_INVAL_ARG);

	pip = _DEVICE_PIP(sd, flags);
	if (pip)
		rv = mdi_prop_lookup_int_array(pip, name, data, nelements);
	else
		rv = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, sd->sd_dev,
		    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
		    name, data, nelements);
	return (rv);
}


int
scsi_device_prop_lookup_string(struct scsi_device *sd, uint_t flags,
    char *name, char **data)
{
	mdi_pathinfo_t	*pip;
	int		rv;

	ASSERT(sd && name && sd->sd_dev && _TYPE_DEFINED(flags));
	if ((sd == NULL) || (name == NULL) || (sd->sd_dev == NULL) ||
	    !_TYPE_DEFINED(flags))
		return (DDI_PROP_INVAL_ARG);

	pip = _DEVICE_PIP(sd, flags);
	if (pip)
		rv = mdi_prop_lookup_string(pip, name, data);
	else
		rv = ddi_prop_lookup_string(DDI_DEV_T_ANY, sd->sd_dev,
		    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
		    name, data);
	return (rv);
}

int
scsi_device_prop_lookup_string_array(struct scsi_device *sd, uint_t flags,
    char *name, char ***data, uint_t *nelements)
{
	mdi_pathinfo_t	*pip;
	int		rv;

	ASSERT(sd && name && sd->sd_dev && _TYPE_DEFINED(flags));
	if ((sd == NULL) || (name == NULL) || (sd->sd_dev == NULL) ||
	    !_TYPE_DEFINED(flags))
		return (DDI_PROP_INVAL_ARG);

	pip = _DEVICE_PIP(sd, flags);
	if (pip)
		rv = mdi_prop_lookup_string_array(pip, name, data, nelements);
	else
		rv = ddi_prop_lookup_string_array(DDI_DEV_T_ANY, sd->sd_dev,
		    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
		    name, data, nelements);
	return (rv);
}

int
scsi_device_prop_update_byte_array(struct scsi_device *sd, uint_t flags,
    char *name, uchar_t *data, uint_t nelements)
{
	mdi_pathinfo_t	*pip;
	int		rv;

	ASSERT(sd && name && sd->sd_dev && _TYPE_DEFINED(flags));
	if ((sd == NULL) || (name == NULL) || (sd->sd_dev == NULL) ||
	    !_TYPE_DEFINED(flags))
		return (DDI_PROP_INVAL_ARG);

	pip = _DEVICE_PIP(sd, flags);
	if (pip)
		rv = mdi_prop_update_byte_array(pip, name, data, nelements);
	else
		rv = ndi_prop_update_byte_array(DDI_DEV_T_NONE, sd->sd_dev,
		    name, data, nelements);
	return (rv);
}

int
scsi_device_prop_update_int(struct scsi_device *sd, uint_t flags,
    char *name, int data)
{
	mdi_pathinfo_t	*pip;
	int		rv;

	ASSERT(sd && name && sd->sd_dev && _TYPE_DEFINED(flags));
	if ((sd == NULL) || (name == NULL) || (sd->sd_dev == NULL) ||
	    !_TYPE_DEFINED(flags))
		return (DDI_PROP_INVAL_ARG);

	pip = _DEVICE_PIP(sd, flags);
	if (pip)
		rv = mdi_prop_update_int(pip, name, data);
	else
		rv = ndi_prop_update_int(DDI_DEV_T_NONE, sd->sd_dev,
		    name, data);
	return (rv);
}

int
scsi_device_prop_update_int64(struct scsi_device *sd, uint_t flags,
    char *name, int64_t data)
{
	mdi_pathinfo_t	*pip;
	int		rv;

	ASSERT(sd && name && sd->sd_dev && _TYPE_DEFINED(flags));
	if ((sd == NULL) || (name == NULL) || (sd->sd_dev == NULL) ||
	    !_TYPE_DEFINED(flags))
		return (DDI_PROP_INVAL_ARG);

	pip = _DEVICE_PIP(sd, flags);
	if (pip)
		rv = mdi_prop_update_int64(pip, name, data);
	else
		rv = ndi_prop_update_int64(DDI_DEV_T_NONE, sd->sd_dev,
		    name, data);
	return (rv);
}

int
scsi_device_prop_update_int_array(struct scsi_device *sd, uint_t flags,
    char *name, int *data, uint_t nelements)
{
	mdi_pathinfo_t	*pip;
	int		rv;

	ASSERT(sd && name && sd->sd_dev && _TYPE_DEFINED(flags));
	if ((sd == NULL) || (name == NULL) || (sd->sd_dev == NULL) ||
	    !_TYPE_DEFINED(flags))
		return (DDI_PROP_INVAL_ARG);

	pip = _DEVICE_PIP(sd, flags);
	if (pip)
		rv = mdi_prop_update_int_array(pip, name, data, nelements);
	else
		rv = ndi_prop_update_int_array(DDI_DEV_T_NONE, sd->sd_dev,
		    name, data, nelements);
	return (rv);
}

int
scsi_device_prop_update_string(struct scsi_device *sd, uint_t flags,
    char *name, char *data)
{
	mdi_pathinfo_t	*pip;
	int		rv;

	ASSERT(sd && name && sd->sd_dev && _TYPE_DEFINED(flags));
	if ((sd == NULL) || (name == NULL) || (sd->sd_dev == NULL) ||
	    !_TYPE_DEFINED(flags))
		return (DDI_PROP_INVAL_ARG);

	pip = _DEVICE_PIP(sd, flags);
	if (pip)
		rv = mdi_prop_update_string(pip, name, data);
	else
		rv = ndi_prop_update_string(DDI_DEV_T_NONE, sd->sd_dev,
		    name, data);
	return (rv);
}

int
scsi_device_prop_update_string_array(struct scsi_device *sd, uint_t flags,
    char *name, char **data, uint_t nelements)
{
	mdi_pathinfo_t	*pip;
	int		rv;

	ASSERT(sd && name && sd->sd_dev && _TYPE_DEFINED(flags));
	if ((sd == NULL) || (name == NULL) || (sd->sd_dev == NULL) ||
	    !_TYPE_DEFINED(flags))
		return (DDI_PROP_INVAL_ARG);

	pip = _DEVICE_PIP(sd, flags);
	if (pip)
		rv = mdi_prop_update_string_array(pip, name, data, nelements);
	else
		rv = ndi_prop_update_string_array(DDI_DEV_T_NONE, sd->sd_dev,
		    name, data, nelements);
	return (rv);
}

int
scsi_device_prop_remove(struct scsi_device *sd, uint_t flags, char *name)
{
	mdi_pathinfo_t	*pip;
	int		rv;

	ASSERT(sd && name && sd->sd_dev && _TYPE_DEFINED(flags));
	if ((sd == NULL) || (name == NULL) || (sd->sd_dev == NULL) ||
	    !_TYPE_DEFINED(flags))
		return (DDI_PROP_INVAL_ARG);

	pip = _DEVICE_PIP(sd, flags);
	if (pip)
		rv = mdi_prop_remove(pip, name);
	else
		rv = ndi_prop_remove(DDI_DEV_T_NONE, sd->sd_dev, name);
	return (rv);
}

void
scsi_device_prop_free(struct scsi_device *sd, uint_t flags, void *data)
{
	mdi_pathinfo_t	*pip;

	ASSERT(sd && data && sd->sd_dev && _TYPE_DEFINED(flags));
	if ((sd == NULL) || (data == NULL) || (sd->sd_dev == NULL) ||
	    !_TYPE_DEFINED(flags))
		return;

	pip = _DEVICE_PIP(sd, flags);
	if (pip)
		(void) mdi_prop_free(data);
	else
		ddi_prop_free(data);
}

/* SMP device property interfaces */
int
smp_device_prop_get_int(struct smp_device *smp_sd, char *name, int defval)
{
	int		v = defval;

	ASSERT(smp_sd && name && smp_sd->smp_sd_dev);
	if ((smp_sd == NULL) || (name == NULL) || (smp_sd->smp_sd_dev == NULL))
		return (v);

	v = ddi_prop_get_int(DDI_DEV_T_ANY, smp_sd->smp_sd_dev,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, name, v);
	return (v);
}


int64_t
smp_device_prop_get_int64(struct smp_device *smp_sd, char *name, int64_t defval)
{
	int64_t		v = defval;

	ASSERT(smp_sd && name && smp_sd->smp_sd_dev);
	if ((smp_sd == NULL) || (name == NULL) || (smp_sd->smp_sd_dev == NULL))
		return (v);

	v = ddi_prop_get_int64(DDI_DEV_T_ANY, smp_sd->smp_sd_dev,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, name, v);
	return (v);
}

int
smp_device_prop_lookup_byte_array(struct smp_device *smp_sd, char *name,
    uchar_t **data, uint_t *nelements)
{
	int		rv;

	ASSERT(smp_sd && name && smp_sd->smp_sd_dev);
	if ((smp_sd == NULL) || (name == NULL) || (smp_sd->smp_sd_dev == NULL))
		return (DDI_PROP_INVAL_ARG);

	rv = ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, smp_sd->smp_sd_dev,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    name, data, nelements);
	return (rv);
}

int
smp_device_prop_lookup_int_array(struct smp_device *smp_sd, char *name,
    int **data, uint_t *nelements)
{
	int		rv;

	ASSERT(smp_sd && name && smp_sd->smp_sd_dev);
	if ((smp_sd == NULL) || (name == NULL) || (smp_sd->smp_sd_dev == NULL))
		return (DDI_PROP_INVAL_ARG);

	rv = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, smp_sd->smp_sd_dev,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    name, data, nelements);
	return (rv);
}


int
smp_device_prop_lookup_string(struct smp_device *smp_sd, char *name,
    char **data)
{
	int		rv;

	ASSERT(smp_sd && name && smp_sd->smp_sd_dev);
	if ((smp_sd == NULL) || (name == NULL) || (smp_sd->smp_sd_dev == NULL))
		return (DDI_PROP_INVAL_ARG);

	rv = ddi_prop_lookup_string(DDI_DEV_T_ANY, smp_sd->smp_sd_dev,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    name, data);
	return (rv);
}

int
smp_device_prop_lookup_string_array(struct smp_device *smp_sd, char *name,
    char ***data, uint_t *nelements)
{
	int		rv;

	ASSERT(smp_sd && name && smp_sd->smp_sd_dev);
	if ((smp_sd == NULL) || (name == NULL) || (smp_sd->smp_sd_dev == NULL))
		return (DDI_PROP_INVAL_ARG);

	rv = ddi_prop_lookup_string_array(DDI_DEV_T_ANY, smp_sd->smp_sd_dev,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    name, data, nelements);
	return (rv);
}

int
smp_device_prop_update_byte_array(struct smp_device *smp_sd, char *name,
    uchar_t *data, uint_t nelements)
{
	int		rv;

	ASSERT(smp_sd && name && smp_sd->smp_sd_dev);
	if ((smp_sd == NULL) || (name == NULL) || (smp_sd->smp_sd_dev == NULL))
		return (DDI_PROP_INVAL_ARG);

	rv = ndi_prop_update_byte_array(DDI_DEV_T_NONE, smp_sd->smp_sd_dev,
	    name, data, nelements);
	return (rv);
}

int
smp_device_prop_update_int(struct smp_device *smp_sd, char *name, int data)
{
	int		rv;

	ASSERT(smp_sd && name && smp_sd->smp_sd_dev);
	if ((smp_sd == NULL) || (name == NULL) || (smp_sd->smp_sd_dev == NULL))
		return (DDI_PROP_INVAL_ARG);

	rv = ndi_prop_update_int(DDI_DEV_T_NONE, smp_sd->smp_sd_dev,
	    name, data);
	return (rv);
}

int
smp_device_prop_update_int64(struct smp_device *smp_sd, char *name,
    int64_t data)
{
	int		rv;

	ASSERT(smp_sd && name && smp_sd->smp_sd_dev);
	if ((smp_sd == NULL) || (name == NULL) || (smp_sd->smp_sd_dev == NULL))
		return (DDI_PROP_INVAL_ARG);

	rv = ndi_prop_update_int64(DDI_DEV_T_NONE, smp_sd->smp_sd_dev,
	    name, data);
	return (rv);
}

int
smp_device_prop_update_int_array(struct smp_device *smp_sd, char *name,
    int *data, uint_t nelements)
{
	int		rv;

	ASSERT(smp_sd && name && smp_sd->smp_sd_dev);
	if ((smp_sd == NULL) || (name == NULL) || (smp_sd->smp_sd_dev == NULL))
		return (DDI_PROP_INVAL_ARG);

	rv = ndi_prop_update_int_array(DDI_DEV_T_NONE, smp_sd->smp_sd_dev,
	    name, data, nelements);
	return (rv);
}

int
smp_device_prop_update_string(struct smp_device *smp_sd, char *name, char *data)
{
	int		rv;

	ASSERT(smp_sd && name && smp_sd->smp_sd_dev);
	if ((smp_sd == NULL) || (name == NULL) || (smp_sd->smp_sd_dev == NULL))
		return (DDI_PROP_INVAL_ARG);

	rv = ndi_prop_update_string(DDI_DEV_T_NONE, smp_sd->smp_sd_dev,
	    name, data);
	return (rv);
}

int
smp_device_prop_update_string_array(struct smp_device *smp_sd, char *name,
    char **data, uint_t nelements)
{
	int		rv;

	ASSERT(smp_sd && name && smp_sd->smp_sd_dev);
	if ((smp_sd == NULL) || (name == NULL) || (smp_sd->smp_sd_dev == NULL))
		return (DDI_PROP_INVAL_ARG);

	rv = ndi_prop_update_string_array(DDI_DEV_T_NONE, smp_sd->smp_sd_dev,
	    name, data, nelements);
	return (rv);
}

int
smp_device_prop_remove(struct smp_device *smp_sd, char *name)
{
	int		rv;

	ASSERT(smp_sd && name && smp_sd->smp_sd_dev);
	if ((smp_sd == NULL) || (name == NULL) || (smp_sd->smp_sd_dev == NULL))
		return (DDI_PROP_INVAL_ARG);

	rv = ndi_prop_remove(DDI_DEV_T_NONE, smp_sd->smp_sd_dev, name);
	return (rv);
}

void
smp_device_prop_free(struct smp_device *smp_sd, void *data)
{
	ASSERT(smp_sd && data && smp_sd->smp_sd_dev);
	if ((smp_sd == NULL) || (data == NULL) || (smp_sd->smp_sd_dev == NULL))
		return;

	ddi_prop_free(data);
}

/*
 * scsi_hba_ua_set: given "unit-address" string, set properties.
 *
 * Function to set the properties on a devinfo or pathinfo node from
 * the "unit-address" part of a "name@unit-address" /devices path 'name'
 * string.
 *
 * This function works in conjunction with scsi_ua_get()/scsi_hba_ua_get()
 * (and possibly with an HBA driver's tran_tgt_init() implementation).
 */
static int
scsi_hba_ua_set(char *ua, dev_info_t *dchild, mdi_pathinfo_t *pchild)
{
	char		*p;
	int		tgt;
	char		*tgt_port_end;
	char		*tgt_port;
	int		tgt_port_len;
	int		sfunc;
	scsi_lun64_t	lun64;

	/* Caller must choose to decorate devinfo *or* pathinfo */
	ASSERT((dchild != NULL) ^ (pchild != NULL));
	if (dchild && pchild)
		return (0);

	/*
	 * generic implementation based on "tgt,lun[,sfunc]" address form.
	 * parse hex "tgt" part of "tgt,lun[,sfunc]"
	 */
	p = ua;
	tgt_port_end = NULL;
	for (tgt = 0; *p && *p != ','; p++) {
		if (*p >= '0' && *p <= '9')
			tgt = (tgt << 4) + (*p - '0');
		else if (*p >= 'a' && *p <= 'f')
			tgt = (tgt << 4) + 10 + (*p - 'a');
		else
			tgt = -1;		/* non-numeric */

		/*
		 * if non-numeric or our of range set tgt to -1 and
		 * skip forward
		 */
		if (tgt < 0) {
			tgt = -1;
			for (; *p && *p != ','; p++)
				;
			break;
		}
	}
	tgt_port_end = p;

	/* parse hex ",lun" part of "tgt,lun[,sfunc]" */
	if (*p)
		p++;
	for (lun64 = 0; *p && *p != ','; p++) {
		if (*p >= '0' && *p <= '9')
			lun64 = (lun64 << 4) + (*p - '0');
		else if (*p >= 'a' && *p <= 'f')
			lun64 = (lun64 << 4) + 10 + (*p - 'a');
		else
			return (0);
	}

	/* parse hex ",sfunc" part of "tgt,lun[,sfunc]" */
	if (*p) {
		p++;
		for (sfunc = 0; *p; p++) {
			if (*p >= '0' && *p <= '9')
				sfunc = (sfunc << 4) + (*p - '0');
			else if (*p >= 'a' && *p <= 'f')
				sfunc = (sfunc << 4) + 10 + (*p - 'a');
			else
				return (0);
		}
	} else
		sfunc = -1;

	if (dchild) {
		/*
		 * Decorate a devinfo node with unit address properties.
		 * This adds the the addressing properties needed to
		 * DDI_CTLOPS_UNINITCHILD the devinfo node (i.e. perform
		 * the reverse operation - form unit address from properties).
		 */
		if ((tgt != -1) && (ndi_prop_update_int(DDI_DEV_T_NONE, dchild,
		    SCSI_ADDR_PROP_TARGET, tgt) != DDI_PROP_SUCCESS))
			return (0);

		if (tgt_port_end) {
			tgt_port_len = tgt_port_end - ua + 1;
			tgt_port = kmem_alloc(tgt_port_len, KM_SLEEP);
			(void) strlcpy(tgt_port, ua, tgt_port_len);
			if (ndi_prop_update_string(DDI_DEV_T_NONE, dchild,
			    SCSI_ADDR_PROP_TARGET_PORT, tgt_port) !=
			    DDI_PROP_SUCCESS) {
				kmem_free(tgt_port, tgt_port_len);
				return (0);
			}
			kmem_free(tgt_port, tgt_port_len);
		}

		/* Set the appropriate lun properties. */
		if (lun64 < SCSI_32LUNS_PER_TARGET) {
			if (ndi_prop_update_int(DDI_DEV_T_NONE, dchild,
			    SCSI_ADDR_PROP_LUN, (int)lun64) != DDI_PROP_SUCCESS)
				return (0);
		}
		if (ndi_prop_update_int64(DDI_DEV_T_NONE, dchild,
		    SCSI_ADDR_PROP_LUN64, lun64) != DDI_PROP_SUCCESS)
			return (0);

		/* Set the sfunc property */
		if ((sfunc != -1) &&
		    (ndi_prop_update_int(DDI_DEV_T_NONE, dchild,
		    SCSI_ADDR_PROP_SFUNC, (int)sfunc) != DDI_PROP_SUCCESS))
			return (0);
	} else if (pchild) {
		/*
		 * Decorate a pathinfo node with unit address properties.
		 */
		if ((tgt != -1) && (mdi_prop_update_int(pchild,
		    SCSI_ADDR_PROP_TARGET, tgt) != DDI_PROP_SUCCESS))
			return (0);

		if (tgt_port_end) {
			tgt_port_len = tgt_port_end - ua + 1;
			tgt_port = kmem_alloc(tgt_port_len, KM_SLEEP);
			(void) strlcpy(tgt_port, ua, tgt_port_len);
			if (mdi_prop_update_string(pchild,
			    SCSI_ADDR_PROP_TARGET_PORT, tgt_port) !=
			    DDI_PROP_SUCCESS) {
				kmem_free(tgt_port, tgt_port_len);
				return (0);
			}
			kmem_free(tgt_port, tgt_port_len);
		}

		/* Set the appropriate lun properties */
		if (lun64 < SCSI_32LUNS_PER_TARGET) {
			if (mdi_prop_update_int(pchild, SCSI_ADDR_PROP_LUN,
			    (int)lun64) != DDI_PROP_SUCCESS)
				return (0);
		}

		if (mdi_prop_update_int64(pchild, SCSI_ADDR_PROP_LUN64,
		    lun64) != DDI_PROP_SUCCESS)
			return (0);

		/* Set the sfunc property */
		if ((sfunc != -1) &&
		    (mdi_prop_update_int(pchild,
		    SCSI_ADDR_PROP_SFUNC, (int)sfunc) != DDI_PROP_SUCCESS))
			return (0);
	}
	return (1);
}

/*
 * Private ndi_devi_find/mdi_pi_find implementation - find the child
 * dev_info/path_info of self whose phci name matches "name@caddr".
 * We have our own implementation because we need to search with both
 * forms of sibling lists (dev_info and path_info) and we need to be able
 * to search with a NULL name in order to find siblings already associated
 * with a given unit-address (same @addr). NOTE: NULL name search will never
 * return probe node.
 *
 * If pchildp is NULL and we find a pathinfo child, we return the client
 * devinfo node in *dchildp.
 *
 * The init flag argument should be clear when called from places where
 * recursion could occur (like scsi_busctl_initchild) and when the caller
 * has already performed a search for name@addr with init set (performance).
 *
 * Future: Integrate ndi_devi_findchild_by_callback into scsi_findchild.
 */
static int
scsi_findchild(dev_info_t *self, char *name, char *addr, int init,
    dev_info_t **dchildp, mdi_pathinfo_t **pchildp, int *ppi)
{
	dev_info_t	*dchild;	/* devinfo child */
	mdi_pathinfo_t	*pchild;	/* pathinfo child */
	int		found = CHILD_TYPE_NONE;
	char		*daddr;

	ASSERT(self && DEVI_BUSY_OWNED(self));
	ASSERT(addr && dchildp);
	if ((self == NULL) || (addr == NULL) || (dchildp == NULL))
		return (CHILD_TYPE_NONE);

	*dchildp = NULL;
	if (pchildp)
		*pchildp = NULL;
	if (ppi)
		*ppi = 0;

	/* Walk devinfo child list to find a match */
	for (dchild = ddi_get_child(self); dchild;
	    dchild = ddi_get_next_sibling(dchild)) {
		if (i_ddi_node_state(dchild) < DS_INITIALIZED)
			continue;

		daddr = ddi_get_name_addr(dchild);
		if (daddr && (strcmp(addr, daddr) == 0) &&
		    ((name == NULL) ||
		    (strcmp(name, DEVI(dchild)->devi_node_name) == 0))) {
			/*
			 * If we are asked to find "anything" at a given
			 * unit-address (name == NULL), we don't realy want
			 * to find the 'probe' node. The existance of
			 * a probe node on a 'name == NULL' search should
			 * fail.  This will trigger slow-path code where
			 * we explicity look for, and synchronize against,
			 * a node named "probe" at the unit-address.
			 */
			if ((name == NULL) &&
			    scsi_hba_devi_is_barrier(dchild)) {
				SCSI_HBA_LOG((_LOG(4), NULL, dchild,
				    "%s@%s 'probe' devinfo found, skip",
				    name ? name : "", addr));
				continue;
			}

			/* We have found a match. */
			found |= CHILD_TYPE_DEVINFO;
			SCSI_HBA_LOG((_LOG(4), NULL, dchild,
			    "%s@%s devinfo found", name ? name : "", addr));
			*dchildp = dchild;		/* devinfo found */
			break;
		}
	}

	/*
	 * Walk pathinfo child list to find a match.
	 *
	 * NOTE: Unlike devinfo nodes, pathinfo nodes have a string searchable
	 * unit-address from creation - so there is no need for an 'init'
	 * search block of code for pathinfo nodes below.
	 */
	pchild = mdi_pi_find(self, NULL, addr);
	if (pchild) {
		/*
		 * NOTE: If name specified and we match a pathinfo unit
		 * address, we don't check the client node name.
		 */
		if (ppi)
			*ppi = mdi_pi_get_path_instance(pchild);
		found |= CHILD_TYPE_PATHINFO;

		if (pchildp) {
			SCSI_HBA_LOG((_LOG(4), self, NULL,
			    "%s pathinfo found", mdi_pi_spathname(pchild)));
			*pchildp = pchild;		/* pathinfo found */
		} else if (*dchildp == NULL) {
			/*
			 * Did not find a devinfo node, found a pathinfo node,
			 * but caller did not ask us to return a pathinfo node:
			 * we return the 'client' devinfo node instead (but
			 * with CHILD_TYPE_PATHINFO 'found' return value).
			 */
			dchild = mdi_pi_get_client(pchild);
			SCSI_HBA_LOG((_LOG(4), NULL, dchild,
			    "%s pathinfo found, client switch",
			    mdi_pi_spathname(pchild)));

			/*
			 * A pathinfo node always has a 'client' devinfo node,
			 * but we need to ensure that the 'client' is
			 * initialized and has a scsi_device structure too.
			 */
			ASSERT(dchild);
			if (i_ddi_node_state(dchild) < DS_INITIALIZED) {
				SCSI_HBA_LOG((_LOG(4), NULL, dchild,
				    "%s found client, initchild",
				    mdi_pi_spathname(pchild)));
				(void) ddi_initchild(ddi_get_parent(dchild),
				    dchild);
			}
			if (i_ddi_node_state(dchild) >= DS_INITIALIZED) {
				/* client found and initialized */
				*dchildp = dchild;
			} else {
				SCSI_HBA_LOG((_LOG(4), NULL, dchild,
				    "%s found client, but failed initchild",
				    mdi_pi_spathname(pchild)));
			}
		}
	}

	/* Try devinfo again with initchild of uninitialized nodes */
	if ((found == CHILD_TYPE_NONE) && init) {
		for (dchild = ddi_get_child(self); dchild;
		    dchild = ddi_get_next_sibling(dchild)) {
			/* skip if checked above */
			if (i_ddi_node_state(dchild) >= DS_INITIALIZED)
				continue;
			/* attempt initchild to establish unit-address */
			(void) ddi_initchild(self, dchild);
			if (i_ddi_node_state(dchild) < DS_INITIALIZED)
				continue;
			daddr = ddi_get_name_addr(dchild);
			if (daddr &&
			    ((name == NULL) || (strcmp(name,
			    DEVI(dchild)->devi_node_name) == 0)) &&
			    (strcmp(addr, daddr) == 0)) {
				found |= CHILD_TYPE_DEVINFO;
				SCSI_HBA_LOG((_LOG(4), NULL, dchild,
				    "%s@%s devinfo found post initchild",
				    name ? name : "", addr));
				*dchildp = dchild;	/* devinfo found */
				break;	/* node found */
			}
		}
	}

	/*
	 * We should never find devinfo and pathinfo at the same
	 * unit-address.
	 */
	ASSERT(found != (CHILD_TYPE_DEVINFO | CHILD_TYPE_PATHINFO));
	if (found == (CHILD_TYPE_DEVINFO | CHILD_TYPE_PATHINFO)) {
		found = CHILD_TYPE_NONE;
		*dchildp = NULL;
		*pchildp = NULL;
	}
	return (found);
}

/*
 * Given information about a child device (contained on probe node) construct
 * and return a pointer to the dynamic SID devinfo node associated with the
 * device. In the creation of this SID node a compatible property for the
 * device is formed and used to establish a nodename (via
 * /etc/nodename_aliases) and to bind a driver (via /etc/driver_aliases).
 *
 * If this routine is called then we got a response from a device and
 * obtained the inquiry data from the device. Some inquiry results indicate
 * that the specific LUN we addressed does not exist, and we don't want to
 * bind a standard target driver to the node we create. Even though the
 * specific LUN is not usable, the framework may still want to bind a
 * target driver to the device for internal communication with the device -
 * an example would be issuing a report_lun to enumerate other LUNs under a
 * DPQ_NEVER LUN0. Another example would be wanting to known that the
 * DPQ_NEVER LUN0 device exists in BUS_CONFIG_ONE for non-existent LUN
 * caching optimizations. To support this we let the caller specify a
 * compatible property (or driver). If LUN0 inquiry data indicates that the
 * LUN does not exist then we establish compat0 as the highest precedence(0)
 * compatible form. If used, this compat0 driver will never be called on to
 * issue external commands to the device.
 *
 * If no driver binds to the device using driver_alias we establish the driver
 * passed in as the node name.
 */

extern int e_devid_cache_pathinfo(mdi_pathinfo_t *, ddi_devid_t);

static int
scsi_device_createchild(dev_info_t *self, char *addr, scsi_enum_t se,
    struct scsi_device *sdprobe, dev_info_t **dchildp, mdi_pathinfo_t **pchildp)
{
	scsi_lun64_t		lun64;
	int			dtype;
	int			dpq;
	int			dpq_vu;
	int			dtype_node;
	int			lunexists;
	char			*compat0;
	char			*nname;
	char			**compat = NULL;
	int			ncompat;
	dev_info_t		*dchild = NULL;
	mdi_pathinfo_t		*pchild = NULL;
	dev_info_t		*probe = sdprobe->sd_dev;
	struct scsi_inquiry	*inq = sdprobe->sd_inq;
	uchar_t			*inq80 = NULL;
	uchar_t			*inq83 = NULL;
	uint_t			inq80len, inq83len;
	char			*binding_set = NULL;
	char			*dname = NULL;
	ddi_devid_t		devid;
	int			have_devid = 0;
	ddi_devid_t		cdevid;
	int			have_cdevid = 0;
	char			*devid_str;
	char			*guid = NULL;

	ASSERT(self && addr && *addr && DEVI_BUSY_OWNED(self));
	ASSERT(dchildp && pchildp);

	/*
	 * Determine the lun and whether the lun exists. We may need to create
	 * a node for LUN0 (with compat0 driver binding) even if the lun does
	 * not exist - so we can run report_lun to find additional LUNs.
	 */
	lun64 = scsi_addr_to_lun64(addr);
	dtype = inq->inq_dtype & DTYPE_MASK;		/* device */
	dpq = inq->inq_dtype & DPQ_MASK;
	dpq_vu = inq->inq_dtype & DPQ_VUNIQ ? 1 : 0;

	dtype_node = scsi_addr_to_sfunc(addr);		/* secondary function */
	if (dtype_node == -1)
		dtype_node = dtype;			/* node for device */

	lunexists = (dtype != dtype_node) ||		/* override */
	    ((dpq_vu == 0) && (dpq == DPQ_POSSIBLE)) ||	/* ANSII */
	    (dpq_vu && (lun64 == 0));			/* VU LUN0 */
	if (dtype == DTYPE_UNKNOWN)
		lunexists = 0;

	SCSI_HBA_LOG((_LOG(4), self, NULL,
	    "@%s dtype %x %x dpq_vu %d dpq %x: %d",
	    addr, dtype, dtype_node, dpq_vu, dpq, lunexists));

	/* A non-existent LUN0 uses compatible_nodev. */
	if (lunexists) {
		compat0 = NULL;				/* compat0 not needed */
	} else if (lun64 == 0) {
		compat0 = compatible_nodev;
		SCSI_HBA_LOG((_LOG(2), self, NULL,
		    "@%s lun 0 with compat0 %s", addr, compat0));
	} else
		goto out;				/* no node created */

	/* Obtain identity information from probe node. */
	if (ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, probe,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "inquiry-page-80",
	    &inq80, &inq80len) != DDI_PROP_SUCCESS)
		inq80 = NULL;
	if (ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, probe,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "inquiry-page-83",
	    &inq83, &inq83len) != DDI_PROP_SUCCESS)
		inq83 = NULL;

	/* Get "scsi-binding-set" property (if there is one). */
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, self,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    "scsi-binding-set", &binding_set) == DDI_PROP_SUCCESS)
		SCSI_HBA_LOG((_LOG(2), NULL, probe,
		    "binding_set '%s'", binding_set));

	/* determine the node name and compatible information */
	scsi_hba_ident_nodename_compatible_get(inq,
	    inq80, inq80len, inq83, inq83len, binding_set, dtype_node,
	    compat0, &nname, &dname, &compat, &ncompat);

	if (nname == NULL) {
		/*
		 * We will not be able to create a node because we could not
		 * determine a node name. Print out a NODRIVER level warning
		 * message with the compatible forms for the device. Note that
		 * there may be a driver.conf node that attaches to the device,
		 * which is why we only produce this warning message for debug
		 * kernels.
		 */
		SCSI_HBA_LOG((_LOG(1), NULL, self,
		    "no node_name for device @%s:\n	 compatible: %s",
		    addr, *compat));
		goto out;
	}

	/*
	 * FUTURE: some day we may want an accurate "compatible" on the probe
	 * node so that vhci_is_dev_supported() in scsi_vhci could, at
	 * least in part, determine/configure based on "compatible".
	 *
	 *	if (ndi_prop_update_string_array(DDI_DEV_T_NONE, probe,
	 *	    "compatible", compat, ncompat) != DDI_PROP_SUCCESS) {
	 *		SCSI_HBA_LOG((_LOG(3), self, NULL,
	 *		    "%s@%s failed probe compatible decoration",
	 *		    nname, addr));
	 *		goto out;
	 *	}
	 */

	/* Encode devid from identity information. */
	if (ddi_devid_scsi_encode(DEVID_SCSI_ENCODE_VERSION_LATEST, dname,
	    (uchar_t *)inq, sizeof (*inq), inq80, inq80len, inq83, inq83len,
	    &devid) == DDI_SUCCESS) {
		have_devid = 1;

		/* Attempt to form guid from devid. */
		guid = ddi_devid_to_guid(devid);

		/* Produce string devid for debug. */
		devid_str = ddi_devid_str_encode(devid, NULL);
		SCSI_HBA_LOG((_LOG(3), self, probe, "devid '%s' guid '%s'",
		    devid_str ? devid_str : "NULL", guid ? guid : "NULL"));
		ddi_devid_str_free(devid_str);
	}


	/*
	 * Determine if the device should be enumerated as under the vHCI
	 * (client node) or under the pHCI. By convention scsi_vhci expects
	 * the "cinfo" argument identity information to be represented as a
	 * devinfo node with the needed information (i.e. the pHCI probe node).
	 */
	if ((guid == NULL) ||
	    (mdi_is_dev_supported(MDI_HCI_CLASS_SCSI, self, sdprobe) !=
	    MDI_SUCCESS)) {
		SCSI_HBA_LOG((_LOG(3), self, probe, "==> devinfo"));

		/*
		 * Enumerate under pHCI:
		 *
		 * Create dynamic SID dchild node. No attempt is made to
		 * transfer information (except the addressing and identity
		 * information) from the probe node to the dynamic node since
		 * there may be HBA specific side effects that the framework
		 * does not known how to transfer.
		 */
		ndi_devi_alloc_sleep(self, nname,
		    (se == SE_HP) ? DEVI_SID_HP_NODEID : DEVI_SID_NODEID,
		    &dchild);
		ASSERT(dchild);
		ndi_flavor_set(dchild, SCSA_FLAVOR_SCSI_DEVICE);

		/*
		 * Decorate new node with addressing properties (via
		 * scsi_hba_ua_set()), compatible, identity information, and
		 * class.
		 */
		if ((scsi_hba_ua_set(addr, dchild, NULL) == 0) ||
		    (ndi_prop_update_string_array(DDI_DEV_T_NONE, dchild,
		    "compatible", compat, ncompat) != DDI_PROP_SUCCESS) ||
		    (inq80 && (ndi_prop_update_byte_array(DDI_DEV_T_NONE,
		    dchild, "inquiry-page-80", inq80, inq80len) !=
		    DDI_PROP_SUCCESS)) ||
		    (inq83 && (ndi_prop_update_byte_array(DDI_DEV_T_NONE,
		    dchild, "inquiry-page-83", inq83, inq83len) !=
		    DDI_PROP_SUCCESS)) ||
		    (ndi_prop_update_string(DDI_DEV_T_NONE, dchild,
		    "class", "scsi") != DDI_PROP_SUCCESS)) {
			SCSI_HBA_LOG((_LOG(2), self, NULL,
			    "devinfo @%s failed decoration", addr));
			(void) scsi_hba_remove_node(dchild);
			dchild = NULL;
			goto out;
		}

		/* Bind the driver */
		if (ndi_devi_bind_driver(dchild, 0) != NDI_SUCCESS) {
			/* need to bind in order to register a devid */
			SCSI_HBA_LOG((_LOGCFG, NULL, dchild,
			    "devinfo @%s created, no driver-> "
			    "no devid_register", addr));
			goto out;
		}

		/* Register devid */
		if (have_devid) {
			if (ddi_devid_register(dchild, devid) == DDI_FAILURE)
				SCSI_HBA_LOG((_LOG(1), NULL, dchild,
				    "devinfo @%s created, "
				    "devid register failed", addr));
			else
				SCSI_HBA_LOG((_LOG(2), NULL, dchild,
				    "devinfo @%s created with devid", addr));
		} else
			SCSI_HBA_LOG((_LOG(2), NULL, dchild,
			    "devinfo @%s created, no devid", addr));
	} else {
		/*
		 * Enumerate under vHCI:
		 *
		 * Create a pathinfo pchild node.
		 */
		SCSI_HBA_LOG((_LOG(3), self, probe, "==>pathinfo"));

		if (mdi_pi_alloc_compatible(self, nname, guid, addr, compat,
		    ncompat, 0, &pchild) != MDI_SUCCESS) {
			SCSI_HBA_LOG((_LOG(2), self, probe,
			    "pathinfo alloc failed"));
			goto out;
		}

		ASSERT(pchild);
		dchild = mdi_pi_get_client(pchild);
		ASSERT(dchild);
		ndi_flavor_set(dchild, SCSA_FLAVOR_SCSI_DEVICE);

		/*
		 * Decorate new node with addressing properties via
		 * scsi_hba_ua_set().
		 */
		if (scsi_hba_ua_set(addr, NULL, pchild) == 0) {
			SCSI_HBA_LOG((_LOG(1), self, NULL,
			    "pathinfo %s decoration failed",
			    mdi_pi_spathname(pchild)));
			(void) mdi_pi_free(pchild, 0);
			pchild = NULL;
			goto out;
		}

		/* Bind the driver */
		if (ndi_devi_bind_driver(dchild, 0) != NDI_SUCCESS) {
			/* need to bind in order to register a devid */
			SCSI_HBA_LOG((_LOGCFG, self, NULL,
			    "pathinfo %s created, no client driver-> "
			    "no devid_register", mdi_pi_spathname(pchild)));
			goto out;
		}

		/* Watch out for inconsistancies in devids. */
		if (ddi_devid_get(dchild, &cdevid) == DDI_SUCCESS)
			have_cdevid = 1;

		if (have_devid && !have_cdevid) {
			/* Client does not yet have devid, register ours. */
			if (ddi_devid_register(dchild, devid) == DDI_FAILURE)
				SCSI_HBA_LOG((_LOG(1), self, NULL,
				    "pathinfo %s created, "
				    "devid register failed",
				    mdi_pi_spathname(pchild)));
			else
				SCSI_HBA_LOG((_LOG(2), self, NULL,
				    "pathinfo %s created with devid",
				    mdi_pi_spathname(pchild)));
		} else if (have_devid && have_cdevid) {
			/*
			 * We have devid and client already has devid:
			 * they must be the same.
			 */
			if (ddi_devid_compare(cdevid, devid) != 0) {
				SCSI_HBA_LOG((_LOG(WARN), NULL, dchild,
				    "mismatched devid on path %s",
				    mdi_pi_spathname(pchild)));
			}
		} else if (!have_devid && have_cdevid) {
			/*
			 * Client already has a devid, but we don't:
			 * we should not have missing devids.
			 */
			SCSI_HBA_LOG((_LOG(WARN), NULL, dchild,
			    "missing devid on path %s",
			    mdi_pi_spathname(pchild)));
		} else if (!have_cdevid && !have_devid) {
			/* devid not supported */
			SCSI_HBA_LOG((_LOG(2), self, NULL,
			    "pathinfo %s created, no devid",
			    mdi_pi_spathname(pchild)));
		}

		/*
		 * The above has registered devid for the device under
		 * the client node.  Now register it under the full pHCI
		 * path to the device.  We'll get an entry equivalent to
		 * booting with mpxio disabled.  This is needed for
		 * telemetry during enumeration.
		 */
		if (e_devid_cache_pathinfo(pchild, devid) == DDI_SUCCESS) {
			SCSI_HBA_LOG((_LOG(2), NULL, dchild,
			    "pathinfo @%s created with devid", addr));
		} else {
			SCSI_HBA_LOG((_LOG(1), NULL, dchild,
			    "pathinfo @%s devid cache failed", addr));
		}
	}

	/* free the node name and compatible information */
out:	if (have_devid)
		ddi_devid_free(devid);
	if (have_cdevid)
		ddi_devid_free(cdevid);
	if (guid)
		ddi_devid_free_guid(guid);
	if (compat)
		scsi_hba_ident_nodename_compatible_free(nname, dname, compat);
	if (inq80)
		ddi_prop_free(inq80);
	if (inq83)
		ddi_prop_free(inq83);
	if (binding_set)
		ddi_prop_free(binding_set);

	/* return child_type results */
	if (pchild) {
		*dchildp = NULL;
		*pchildp = pchild;
		return (CHILD_TYPE_PATHINFO);
	} else if (dchild) {
		*dchildp = dchild;
		*pchildp = NULL;
		return (CHILD_TYPE_DEVINFO);
	}

	return (CHILD_TYPE_NONE);
}

/*
 * Call scsi_device_createchild and then initchild the new node.
 */
static dev_info_t *
scsi_device_configchild(dev_info_t *self, char *addr, scsi_enum_t se,
    struct scsi_device *sdprobe, int *circp, int *ppi)
{
	int		child_type;
	dev_info_t	*dchild;
	mdi_pathinfo_t	*pchild;
	dev_info_t	*child;
	int		rval;

	ASSERT(self && addr && *addr && DEVI_BUSY_OWNED(self));
	if (ppi)
		*ppi = 0;

	child_type = scsi_device_createchild(self, addr, se, sdprobe,
	    &dchild, &pchild);

	/*
	 * Prevent multiple initialized (tran_tgt_init) nodes associated with
	 * the same @addr at the same time by calling tran_tgt_free() on the
	 * probe node prior to promotion of the 'real' node.  After the call
	 * to scsi_hba_barrier_tran_tgt_free(), the HBA no longer has any
	 * probe node context.
	 */
	scsi_hba_barrier_tran_tgt_free(sdprobe->sd_dev);

	switch (child_type) {
	case CHILD_TYPE_NONE:
		child = NULL;
		break;

	case CHILD_TYPE_PATHINFO:
		/*
		 * Online pathinfo: Hold the path and exit the pHCI while
		 * calling mdi_pi_online() to avoid deadlock with power
		 * management of pHCI.
		 */
		ASSERT(MDI_PHCI(self));
		mdi_hold_path(pchild);
		scsi_hba_devi_exit_phci(self, *circp);

		rval = mdi_pi_online(pchild, 0);

		scsi_hba_devi_enter_phci(self, circp);
		mdi_rele_path(pchild);

		if (rval != MDI_SUCCESS) {
			/* pathinfo form of "failed during tran_tgt_init" */
			scsi_enumeration_failed(NULL, se,
			    mdi_pi_spathname(pchild), "path online");
			(void) mdi_pi_free(pchild, 0);
			return (NULL);
		}

		/*
		 * Return the path_instance of the pathinfo node.
		 *
		 * NOTE: We assume that sd_inq is not path-specific.
		 */
		if (ppi)
			*ppi = mdi_pi_get_path_instance(pchild);


		/*
		 * Fallthrough into CHILD_TYPE_DEVINFO code to promote
		 * the 'client' devinfo node as a dchild.
		 */
		dchild = mdi_pi_get_client(pchild);
		SCSI_HBA_LOG((_LOG(4), NULL, dchild,
		    "pathinfo online successful"));
		/* FALLTHROUGH */

	case CHILD_TYPE_DEVINFO:
		/*
		 * For now, we ndi_devi_online() the child because some other
		 * parts of the IO framework, like degenerate devid code,
		 * depend on bus_config driving nodes to DS_ATTACHED. At some
		 * point in the future, to keep things light-weight, we would
		 * like to change the ndi_devi_online call below to be
		 *
		 *	if (ddi_initchild(self, dchild) != DDI_SUCCESS)
		 *
		 * This would promote the node so that framework code could
		 * find the child with an @addr search, but does not incur
		 * attach(9E) overhead for BUS_CONFIG_ALL cases where the
		 * framework is not interested in attach of the node.
		 *
		 * NOTE: If the addr specified has incorrect syntax (busconfig
		 * one of bogus /devices path) then call below can fail.
		 */
		if (ndi_devi_online(dchild, 0) != NDI_SUCCESS) {
			SCSI_HBA_LOG((_LOG(2), NULL, dchild,
			    "devinfo online failed"));

			/* failed online does not remove the node */
			(void) scsi_hba_remove_node(dchild);
			return (NULL);
		}
		SCSI_HBA_LOG((_LOG(4), NULL, dchild,
		    "devinfo initchild successful"));
		child = dchild;
		break;
	}
	return (child);
}

void
scsi_hba_pkt_comp(struct scsi_pkt *pkt)
{
	scsi_hba_tran_t	*tran;
	uint8_t		*sensep;

	ASSERT(pkt);

	/*
	 * Catch second call on the same packet before doing anything else.
	 */
	if (pkt->pkt_flags & FLAG_PKT_COMP_CALLED) {
		cmn_err(
#ifdef DEBUG
		    CE_PANIC,
#else
		    CE_WARN,
#endif
		    "%s duplicate scsi_hba_pkt_comp(9F) on same scsi_pkt(9S)",
		    mod_containing_pc(caller()));
	}

	pkt->pkt_flags |= FLAG_PKT_COMP_CALLED;

	if (pkt->pkt_comp == NULL)
		return;

	/*
	 * For HBA drivers that implement tran_setup_pkt(9E), if we are
	 * completing a 'consistent' mode DMA operation then we must
	 * perform dma_sync prior to calling pkt_comp to ensure that
	 * the target driver sees the correct data in memory.
	 */
	ASSERT((pkt->pkt_flags & FLAG_NOINTR) == 0);
	if (((pkt->pkt_dma_flags & DDI_DMA_CONSISTENT) &&
	    (pkt->pkt_dma_flags & DDI_DMA_READ)) &&
	    ((P_TO_TRAN(pkt)->tran_setup_pkt) != NULL)) {
		scsi_sync_pkt(pkt);
	}

	/*
	 * If the HBA driver is using SCSAv3 scsi_hba_tgtmap_create enumeration
	 * then we detect the special ASC/ASCQ completion codes that indicate
	 * that the lun configuration of a target has changed. Since we need to
	 * be determine scsi_device given scsi_address enbedded in
	 * scsi_pkt (via scsi_address_device(9F)), we also require use of
	 * SCSI_HBA_ADDR_COMPLEX.
	 */
	tran = pkt->pkt_address.a_hba_tran;
	ASSERT(tran);
	if ((tran->tran_tgtmap == NULL) ||
	    !(tran->tran_hba_flags & SCSI_HBA_ADDR_COMPLEX))
		goto comp;		/* not using tgtmap */

	/*
	 * Check for lun-change notification and queue the scsi_pkt for
	 * lunchg1 processing. The 'pkt_comp' call to the target driver
	 * is part of lunchg1 processing.
	 */
	if ((pkt->pkt_reason == CMD_CMPLT) &&
	    (((*pkt->pkt_scbp) & STATUS_MASK) == STATUS_CHECK) &&
	    (pkt->pkt_state & STATE_ARQ_DONE)) {
		sensep = (uint8_t *)&(((struct scsi_arq_status *)(uintptr_t)
		    (pkt->pkt_scbp))->sts_sensedata);
		if (((scsi_sense_key(sensep) == KEY_UNIT_ATTENTION) &&
		    (scsi_sense_asc(sensep) == 0x3f) &&
		    (scsi_sense_ascq(sensep) == 0x0e)) ||

		    ((scsi_sense_key(sensep) == KEY_UNIT_ATTENTION) &&
		    (scsi_sense_asc(sensep) == 0x25) &&
		    (scsi_sense_ascq(sensep) == 0x00))) {
			/*
			 * The host adaptor is done with the packet, we use
			 * pkt_stmp stage-temporary to link the packet for
			 * lunchg1 processing.
			 *
			 * NOTE: pkt_ha_private is not available since its use
			 * extends to tran_teardown_pkt.
			 */
			mutex_enter(&scsi_lunchg1_mutex);
			pkt->pkt_stmp = scsi_lunchg1_list;
			scsi_lunchg1_list = pkt;
			if (pkt->pkt_stmp == NULL)
				(void) cv_signal(&scsi_lunchg1_cv);
			mutex_exit(&scsi_lunchg1_mutex);
			return;
		}
	}

comp:	(*pkt->pkt_comp)(pkt);
}

/*
 * return 1 if the specified node is a barrier/probe node
 */
static int
scsi_hba_devi_is_barrier(dev_info_t *probe)
{
	if (probe && (strcmp(ddi_node_name(probe), "probe") == 0))
		return (1);
	return (0);
}

/*
 * A host adapter driver is easier to write if we prevent multiple initialized
 * (tran_tgt_init) scsi_device structures to the same unit-address at the same
 * time.  We prevent this from occurring all the time during the barrier/probe
 * node to real child hand-off by calling scsi_hba_barrier_tran_tgt_free
 * on the probe node prior to ddi_inichild of the 'real' node.  As part of
 * this early tran_tgt_free implementation, we must also call this function
 * as we put a probe node on the scsi_hba_barrier_list.
 */
static void
scsi_hba_barrier_tran_tgt_free(dev_info_t *probe)
{
	struct scsi_device	*sdprobe;
	dev_info_t		*self;
	scsi_hba_tran_t		*tran;

	ASSERT(probe && scsi_hba_devi_is_barrier(probe));

	/* Return if we never called tran_tgt_init(9E). */
	if (i_ddi_node_state(probe) < DS_INITIALIZED)
		return;

	sdprobe = ddi_get_driver_private(probe);
	self = ddi_get_parent(probe);
	ASSERT(sdprobe && self);
	tran = ddi_get_driver_private(self);
	ASSERT(tran);

	if (tran->tran_tgt_free) {
		/*
		 * To correctly support TRAN_CLONE, we need to use the same
		 * cloned scsi_hba_tran(9S) structure for both tran_tgt_init(9E)
		 * and tran_tgt_free(9E).
		 */
		if (tran->tran_hba_flags & SCSI_HBA_TRAN_CLONE)
			tran = sdprobe->sd_address.a_hba_tran;

		if (!sdprobe->sd_tran_tgt_free_done) {
			SCSI_HBA_LOG((_LOG(4), NULL, probe,
			    "tran_tgt_free EARLY"));
			(*tran->tran_tgt_free) (self, probe, tran, sdprobe);
			sdprobe->sd_tran_tgt_free_done = 1;
		} else {
			SCSI_HBA_LOG((_LOG(4), NULL, probe,
			    "tran_tgt_free EARLY already done"));
		}
	}
}

/*
 * Add an entry to the list of barrier nodes to be asynchronously deleted by
 * the scsi_hba_barrier_daemon after the specified timeout. Nodes on
 * the barrier list are used to implement the bus_config probe cache
 * of non-existent devices. The nodes are at DS_INITIALIZED, so their
 * @addr is established for searching. Since devi_ref of a DS_INITIALIZED
 * node will *not* prevent demotion, demotion is prevented by setting
 * sd_uninit_prevent. Devinfo snapshots attempt to attach probe cache
 * nodes, and on failure attempt to demote the node (without the participation
 * of bus_unconfig) to DS_BOUND - this demotion is prevented via
 * sd_uninit_prevent causing any attempted DDI_CTLOPS_UNINITCHILD to fail.
 * Probe nodes are bound to nulldriver. The list is sorted by
 * expiration time.
 *
 * NOTE: If we drove a probe node to DS_ATTACHED, we could use ndi_hold_devi()
 * to prevent demotion (instead of sd_uninit_prevent).
 */
static void
scsi_hba_barrier_add(dev_info_t *probe, int seconds)
{
	struct scsi_hba_barrier	*nb;
	struct scsi_hba_barrier	*b;
	struct scsi_hba_barrier	**bp;
	clock_t			endtime;

	ASSERT(scsi_hba_devi_is_barrier(probe));

	/* HBA is no longer responsible for nodes on the barrier list. */
	scsi_hba_barrier_tran_tgt_free(probe);
	nb = kmem_alloc(sizeof (struct scsi_hba_barrier), KM_SLEEP);
	mutex_enter(&scsi_hba_barrier_mutex);
	endtime = ddi_get_lbolt() + drv_usectohz(seconds * MICROSEC);
	for (bp = &scsi_hba_barrier_list; (b = *bp) != NULL;
	    bp = &b->barrier_next)
		if (b->barrier_endtime > endtime)
			break;
	nb->barrier_next = *bp;
	nb->barrier_endtime = endtime;
	nb->barrier_probe = probe;
	*bp = nb;
	if (bp == &scsi_hba_barrier_list)
		(void) cv_signal(&scsi_hba_barrier_cv);
	mutex_exit(&scsi_hba_barrier_mutex);
}

/*
 * Attempt to remove devinfo node node, return 1 if removed. We
 * don't try to remove barrier nodes that have sd_uninit_prevent set
 * (even though they should fail device_uninitchild).
 */
static int
scsi_hba_remove_node(dev_info_t *child)
{
	dev_info_t		*self = ddi_get_parent(child);
	struct scsi_device	*sd;
	int			circ;
	int			remove = 1;
	int			ret = 0;
	char			na[SCSI_MAXNAMELEN];

	scsi_hba_devi_enter(self, &circ);

	/* Honor sd_uninit_prevent on barrier nodes */
	if (scsi_hba_devi_is_barrier(child)) {
		sd = ddi_get_driver_private(child);
		if (sd && sd->sd_uninit_prevent)
			remove = 0;
	}

	if (remove) {
		(void) ddi_deviname(child, na);
		if (ddi_remove_child(child, 0) != DDI_SUCCESS) {
			SCSI_HBA_LOG((_LOG(2), NULL, child,
			    "remove_node failed"));
		} else {
			child = NULL;		/* child is gone */
			SCSI_HBA_LOG((_LOG(4), self, NULL,
			    "remove_node removed %s", *na ? &na[1] : na));
			ret = 1;
		}
	} else {
		SCSI_HBA_LOG((_LOG(4), NULL, child, "remove_node prevented"));
	}
	scsi_hba_devi_exit(self, circ);
	return (ret);
}

/*
 * The asynchronous barrier deletion daemon. Waits for a barrier timeout
 * to expire, then deletes the barrier (removes it as a child).
 */
/*ARGSUSED*/
static void
scsi_hba_barrier_daemon(void *arg)
{
	struct scsi_hba_barrier	*b;
	dev_info_t		*probe;
	callb_cpr_t		cprinfo;
	int			circ;
	dev_info_t		*self;

	CALLB_CPR_INIT(&cprinfo, &scsi_hba_barrier_mutex,
	    callb_generic_cpr, "scsi_hba_barrier_daemon");
again:	mutex_enter(&scsi_hba_barrier_mutex);
	for (;;) {
		b = scsi_hba_barrier_list;
		if (b == NULL) {
			/* all barriers expired, wait for barrier_add */
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			(void) cv_wait(&scsi_hba_barrier_cv,
			    &scsi_hba_barrier_mutex);
			CALLB_CPR_SAFE_END(&cprinfo, &scsi_hba_barrier_mutex);
		} else {
			if (ddi_get_lbolt() >= b->barrier_endtime) {
				/*
				 * Drop and retry if ordering issue. Do this
				 * before calling scsi_hba_remove_node() and
				 * deadlocking.
				 */
				probe = b->barrier_probe;
				self = ddi_get_parent(probe);
				if (scsi_hba_devi_tryenter(self, &circ) == 0) {
delay:					mutex_exit(&scsi_hba_barrier_mutex);
					delay_random(5);
					goto again;
				}

				/* process expired barrier */
				if (!scsi_hba_remove_node(probe)) {
					/* remove failed, delay and retry */
					SCSI_HBA_LOG((_LOG(4), NULL, probe,
					    "delay expire"));
					scsi_hba_devi_exit(self, circ);
					goto delay;
				}
				scsi_hba_barrier_list = b->barrier_next;
				kmem_free(b, sizeof (struct scsi_hba_barrier));
				scsi_hba_devi_exit(self, circ);
			} else {
				/* establish timeout for next barrier expire */
				(void) cv_timedwait(&scsi_hba_barrier_cv,
				    &scsi_hba_barrier_mutex,
				    b->barrier_endtime);
			}
		}
	}
}

/*
 * Remove all barriers associated with the specified HBA. This is called
 * from from the bus_unconfig implementation to remove probe nodes associated
 * with the specified HBA (self) so that probe nodes that have not expired
 * will not prevent DR of the HBA.
 */
static void
scsi_hba_barrier_purge(dev_info_t *self)
{
	struct scsi_hba_barrier	**bp;
	struct scsi_hba_barrier	*b;

	mutex_enter(&scsi_hba_barrier_mutex);
	for (bp = &scsi_hba_barrier_list; (b = *bp) != NULL; ) {
		if (ddi_get_parent(b->barrier_probe) == self) {
			if (scsi_hba_remove_node(b->barrier_probe)) {
				*bp = b->barrier_next;
				kmem_free(b, sizeof (struct scsi_hba_barrier));
			} else {
				SCSI_HBA_LOG((_LOG(4), NULL, b->barrier_probe,
				    "skip purge"));
			}
		} else
			bp = &b->barrier_next;
	}

	mutex_exit(&scsi_hba_barrier_mutex);
}

/*
 * LUN-change processing daemons: processing occurs in two stages:
 *
 * Stage 1:	Daemon waits for a lunchg1 queued scsi_pkt, dequeues the pkt,
 *		forms the path, completes the scsi_pkt (pkt_comp), and
 *		queues the path for stage 2 processing. The use of stage 1
 *		avoids issues related to memory allocation in interrupt context
 *		(scsi_hba_pkt_comp()). We delay the pkt_comp completion until
 *		after lunchg1 processing forms the path for stage 2 - this is
 *		done to prevent the target driver from detaching until the
 *		path formation is complete (driver with outstanding commands
 *		should not detach).
 *
 * Stage 2:	Daemon waits for a lunchg2 queued request, dequeues the
 *		request, and opens the path using ldi_open_by_name(). The
 *		path opened uses a special "@taddr,*" unit address that will
 *		trigger lun enumeration in scsi_hba_bus_configone(). We
 *		trigger lun enumeration in stage 2 to avoid problems when
 *		initial ASC/ASCQ trigger occurs during discovery.
 */
/*ARGSUSED*/
static void
scsi_lunchg1_daemon(void *arg)
{
	callb_cpr_t		cprinfo;
	struct scsi_pkt		*pkt;
	scsi_hba_tran_t		*tran;
	dev_info_t		*self;
	struct scsi_device	*sd;
	char			*ua, *p;
	char			taddr[SCSI_MAXNAMELEN];
	char			path[MAXPATHLEN];
	struct scsi_lunchg2	*lunchg2;

	CALLB_CPR_INIT(&cprinfo, &scsi_lunchg1_mutex,
	    callb_generic_cpr, "scsi_lunchg1_daemon");
	mutex_enter(&scsi_lunchg1_mutex);
	for (;;) {
		pkt = scsi_lunchg1_list;
		if (pkt == NULL) {
			/* All lunchg1 processing requests serviced, wait. */
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			(void) cv_wait(&scsi_lunchg1_cv,
			    &scsi_lunchg1_mutex);
			CALLB_CPR_SAFE_END(&cprinfo, &scsi_lunchg1_mutex);
			continue;
		}

		/* Unlink and perform lunchg1 processing on pkt. */
		scsi_lunchg1_list = pkt->pkt_stmp;

		/* Determine initiator port (self) from the pkt_address. */
		tran = pkt->pkt_address.a_hba_tran;
		ASSERT(tran && tran->tran_tgtmap && tran->tran_iport_dip);
		self = tran->tran_iport_dip;

		/*
		 * Determine scsi_devie from pkt_address (depends on
		 * SCSI_HBA_ADDR_COMPLEX).
		 */
		sd = scsi_address_device(&(pkt->pkt_address));
		ASSERT(sd);
		if (sd == NULL) {
			(*pkt->pkt_comp)(pkt);
			continue;
		}

		/* Determine unit-address from scsi_device. */
		ua = scsi_device_unit_address(sd);

		/* Extract taddr from the unit-address. */
		for (p = taddr; (*ua != ',') && (*ua != '\0'); )
			*p++ = *ua++;
		*p = '\0';			/* NULL terminate taddr */

		/*
		 * Form path using special "@taddr,*" notation to trigger
		 * lun enumeration.
		 */
		(void) ddi_pathname(self, path);
		(void) strcat(path, "/luns@");
		(void) strcat(path, taddr);
		(void) strcat(path, ",*");

		/*
		 * Now that we have the path, complete the pkt that
		 * triggered lunchg1 processing.
		 */
		(*pkt->pkt_comp)(pkt);

		/* Allocate element for stage2 processing queue. */
		lunchg2 = kmem_alloc(sizeof (*lunchg2), KM_SLEEP);
		lunchg2->lunchg2_path = strdup(path);

		/* Queue and dispatch to stage 2. */
		SCSI_HBA_LOG((_LOG(2), self, NULL,
		    "lunchg stage1: queue %s", lunchg2->lunchg2_path));
		mutex_enter(&scsi_lunchg2_mutex);
		lunchg2->lunchg2_next = scsi_lunchg2_list;
		scsi_lunchg2_list = lunchg2;
		if (lunchg2->lunchg2_next == NULL)
			(void) cv_signal(&scsi_lunchg2_cv);
		mutex_exit(&scsi_lunchg2_mutex);
	}
}

/*ARGSUSED*/
static void
scsi_lunchg2_daemon(void *arg)
{
	callb_cpr_t		cprinfo;
	struct scsi_lunchg2	*lunchg2;
	ldi_ident_t		li;
	ldi_handle_t		lh;

	CALLB_CPR_INIT(&cprinfo, &scsi_lunchg2_mutex,
	    callb_generic_cpr, "scsi_lunchg2_daemon");

	li = ldi_ident_from_anon();
	mutex_enter(&scsi_lunchg2_mutex);
	for (;;) {
		lunchg2 = scsi_lunchg2_list;
		if (lunchg2 == NULL) {
			/* All lunchg2 processing requests serviced, wait. */
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			(void) cv_wait(&scsi_lunchg2_cv,
			    &scsi_lunchg2_mutex);
			CALLB_CPR_SAFE_END(&cprinfo, &scsi_lunchg2_mutex);
			continue;
		}

		/* Unlink and perform lunchg2 processing on pkt. */
		scsi_lunchg2_list = lunchg2->lunchg2_next;

		/*
		 * Open and close the path to trigger lun enumeration.  We
		 * don't expect the open to succeed, but we do expect code in
		 * scsi_hba_bus_configone() to trigger lun enumeration.
		 */
		SCSI_HBA_LOG((_LOG(2), NULL, NULL,
		    "lunchg stage2: open %s", lunchg2->lunchg2_path));
		if (ldi_open_by_name(lunchg2->lunchg2_path,
		    FREAD, kcred, &lh, li) == 0)
			(void) ldi_close(lh, FREAD, kcred);

		/* Free path and linked element. */
		strfree(lunchg2->lunchg2_path);
		kmem_free(lunchg2, sizeof (*lunchg2));
	}
}

/*
 * Enumerate a child at the specified @addr. If a device exists @addr then
 * ensure that we have the appropriately named devinfo node for it. Name is
 * NULL in the bus_config_all case. This routine has no knowledge of the
 * format of an @addr string or associated addressing properties.
 *
 * The caller must guarantee that there is an open scsi_hba_devi_enter on the
 * parent. We return the scsi_device structure for the child device. This
 * scsi_device structure is valid until the caller scsi_hba_devi_exit the
 * parent. The caller can add do ndi_hold_devi of the child prior to the
 * scsi_hba_devi_exit to extend the validity of the child.
 *
 * In some cases the returned scsi_device structure may be used to drive
 * additional SCMD_REPORT_LUNS operations by bus_config_all callers.
 *
 * The first operation performed is to see if there is a dynamic SID nodes
 * already attached at the specified "name@addr". This is the fastpath
 * case for resolving a reference to a node that has already been created.
 * All other references are serialized for a given @addr prior to probing
 * to determine the type of device, if any, at the specified @addr.
 * If no device is present then NDI_FAILURE is returned. The fact that a
 * device does not exist may be determined via the barrier/probe cache,
 * minimizing the probes of non-existent devices.
 *
 * When there is a device present the dynamic SID node is created based on
 * the device found. If a driver.conf node exists for the same @addr it
 * will either merge into the dynamic SID node (if the SID node bound to
 * that driver), or exist independently. To prevent the actions of one driver
 * causing side effects in another, code prevents multiple SID nodes from
 * binding to the same "@addr" at the same time. There is autodetach code
 * to allow one device to be replaced with another at the same @addr for
 * slot addressed SCSI bus implementations (SPI). For compatibility with
 * legacy driver.conf behavior, the code does not prevent multiple driver.conf
 * nodes from attaching to the same @addr at the same time.
 *
 * This routine may have the side effect of creating nodes for devices other
 * than the one being sought. It is possible that there is a different type of
 * target device at that target/lun address than we were asking for. In that
 * It is the caller's responsibility to determine whether the device we found,
 * if any, at the specified address, is the one it really wanted.
 */
static struct scsi_device *
scsi_device_config(dev_info_t *self, char *name, char *addr, scsi_enum_t se,
    int *circp, int *ppi)
{
	dev_info_t		*child = NULL;
	dev_info_t		*probe = NULL;
	struct scsi_device	*sdchild;
	struct scsi_device	*sdprobe;
	dev_info_t		*dsearch;
	mdi_pathinfo_t		*psearch;
	major_t			major;
	int			sp;
	int			pi = 0;
	int			wait_msg = scsi_hba_wait_msg;
	int			chg;

	ASSERT(self && addr && DEVI_BUSY_OWNED(self));

	SCSI_HBA_LOG((_LOG(4), self, NULL, "%s@%s wanted",
	    name ? name : "", addr));

	/* playing with "probe" node name is dangerous */
	if (name && (strcmp(name, "probe") == 0))
		return (NULL);

	/*
	 * NOTE: use 'goto done;' or 'goto fail;'. There should only be one
	 * 'return' statement from here to the end of the function - the one
	 * on the last line of the function.
	 */

	/*
	 * Fastpath: search to see if we are requesting a named SID node that
	 * already exists (we already created) - probe node does not count.
	 * scsi_findchild() does not hold the returned devinfo node, but
	 * this is OK since the caller has a scsi_hba_devi_enter on the
	 * attached parent HBA (self). The caller is responsible for attaching
	 * and placing a hold on the child (directly via ndi_hold_devi or
	 * indirectly via ndi_busop_bus_config) before doing an
	 * scsi_hba_devi_exit on the parent.
	 *
	 * NOTE: This fastpath prevents detecting a driver binding change
	 * (autodetach) if the same nodename is used for old and new binding.
	 */
	/* first call is with init set */
	(void) scsi_findchild(self, name, addr, 1, &dsearch, NULL, &pi);
	if (dsearch && scsi_hba_dev_is_sid(dsearch) &&
	    !scsi_hba_devi_is_barrier(dsearch)) {
		SCSI_HBA_LOG((_LOG(4), NULL, dsearch,
		    "%s@%s devinfo fastpath", name ? name : "", addr));
		child = dsearch;
		goto done;
	}

	/*
	 * Create a barrier devinfo node used to "probe" the device with. We
	 * need to drive this node to DS_INITIALIZED so that the
	 * DDI_CTLOPS_INITCHILD has occurred, bringing the SCSA transport to
	 * a state useable state for issuing our "probe" commands. We establish
	 * this barrier node with a node name of "probe" and compatible
	 * property of "scsiprobe". The compatible property must be associated
	 * in /etc/driver_aliases with a scsi target driver available in the
	 * root file system (sd).
	 *
	 * The "probe" that we perform on the barrier node, after it is
	 * DS_INITIALIZED, is used to find the information needed to create a
	 * dynamic devinfo (SID) node. This "probe" is separate from the
	 * probe(9E) call associated with the transition of a node from
	 * DS_INITIALIZED to DS_PROBED. The probe(9E) call that eventually
	 * occurs against the created SID node should find ddi_dev_is_sid and
	 * just return DDI_PROBE_DONTCARE.
	 *
	 * Trying to avoid the use of a barrier node is not a good idea
	 * because we may have an HBA driver that uses generic bus_config
	 * (this code) but implements its own DDI_CTLOPS_INITCHILD with side
	 * effects that we can't duplicate (such as the ATA nexus driver).
	 *
	 * The probe/barrier node plays an integral part of the locking scheme.
	 * The objective is to single thread probes of the same device (same
	 * @addr) while allowing parallelism for probes of different devices
	 * with the same parent. At this point we are serialized on our self.
	 * For parallelism we will need to release our self. Prior to release
	 * we construct a barrier for probes of the same device to serialize
	 * against. The "probe@addr" node acts as this barrier. An entering
	 * thread must wait until the probe node does not exist - it can then
	 * create and link the probe node - dropping the HBA (self) lock after
	 * the node is linked and visible (after ddi_initchild). A side effect
	 * of this is that transports should not "go over the wire" (i.e. do
	 * things that incur significant delays) until after tran_target_init.
	 * This means that the first "over the wire" operation should occur
	 * at tran_target_probe time - when things are running in parallel
	 * again.
	 *
	 * If the probe node exists then another probe with the same @addr is
	 * in progress, we must wait until there is no probe in progress
	 * before proceeding, and when we proceed we must continue to hold the
	 * HBA (self) until we have linked a new probe node as a barrier.
	 *
	 * When a device is found to *not* exist, its probe/barrier node may be
	 * marked with DEVICE_REMOVED with node deletion scheduled for some
	 * future time (seconds). This asynchronous deletion allows the
	 * framework to detect repeated requests to the same non-existent
	 * device and avoid overhead associated with contacting a non-existent
	 * device again and again.
	 */
	for (;;) {
		/*
		 * Search for probe node - they should only exist as devinfo
		 * nodes.
		 */
		(void) scsi_findchild(self, "probe", addr,
		    0, &probe, &psearch, NULL);
		if (probe == NULL) {
			if (psearch)
				SCSI_HBA_LOG((_LOG(2), self,
				    mdi_pi_get_client(psearch),
				    "???? @%s 'probe' search found "
				    "pathinfo: %p", addr, (void *)psearch));
			break;
		}

		/*
		 * The barrier node may cache the non-existence of a device
		 * by leaving the barrier node in place (with
		 * DEVI_DEVICE_REMOVED flag set ) for some amount of time after
		 * the failure of a probe. This flag is used to fail
		 * additional probes until the barrier probe node is deleted,
		 * which will occur from a timeout some time after a failed
		 * probe. The failed probe will use DEVI_SET_DEVICE_REMOVED
		 * and schedule probe node deletion from a timeout. The callers
		 * scsi_hba_devi_exit on the way out of the first failure will
		 * do the cv_broadcast associated with the cv_wait below - this
		 * handles threads that wait prior to DEVI_DEVICE_REMOVED being
		 * set.
		 */
		if (DEVI_IS_DEVICE_REMOVED(probe)) {
			SCSI_HBA_LOG((_LOG(3), NULL, probe,
			    "detected probe DEVICE_REMOVED"));
			probe = NULL;	/* deletion already scheduled */
			goto fail;
		}

		/*
		 * Drop the lock on the HBA (self) and wait until the probe in
		 * progress has completed. A changes in the sibling list from
		 * removing the probe node will cause cv_wait to return
		 * (scsi_hba_devi_exit does the cv_broadcast).
		 */
		if (wait_msg) {
			wait_msg--;
			SCSI_HBA_LOG((_LOG(2), NULL, probe,
			    "exists, probe already in progress: %s", wait_msg ?
			    "waiting..." : "last msg, but still waiting..."));
		}

		/*
		 * NOTE: we could avoid rare case of one second delay by
		 * implementing scsi_hba_devi_exit_and_wait based on
		 * ndi/mdi_devi_exit_and_wait (and consider switching devcfg.c
		 * code to use these ndi/mdi interfaces too).
		 */
		scsi_hba_devi_exit(self, *circp);
		mutex_enter(&DEVI(self)->devi_lock);
		(void) cv_timedwait(&DEVI(self)->devi_cv,
		    &DEVI(self)->devi_lock,
		    ddi_get_lbolt() + drv_usectohz(MICROSEC));
		mutex_exit(&DEVI(self)->devi_lock);
		scsi_hba_devi_enter(self, circp);
	}
	ASSERT(probe == NULL);

	/*
	 * Search to see if we are requesting a SID node that already exists.
	 * We hold the HBA (self) and there is not another probe in progress at
	 * the same @addr. scsi_findchild() does not hold the returned
	 * devinfo node but this is OK since we hold the HBA (self).
	 */
	if (name) {
		(void) scsi_findchild(self, name, addr, 1, &dsearch, NULL, &pi);
		if (dsearch && scsi_hba_dev_is_sid(dsearch)) {
			SCSI_HBA_LOG((_LOG(4), NULL, dsearch,
			    "%s@%s probe devinfo fastpath",
			    name ? name : "", addr));
			child = dsearch;
			goto done;
		}
	}

	/*
	 * We are looking for a SID node that does not exist or a driver.conf
	 * node.
	 *
	 * To avoid probe side effects, before we probe the device at the
	 * specified address we need to check to see if there is already an
	 * initialized child "@addr".
	 *
	 * o If we find an initialized SID child and name is NULL or matches
	 *   the name or the name of the attached driver then we return the
	 *   existing node.
	 *
	 * o If we find a non-matching SID node, we will attempt to autodetach
	 *   and remove the node in preference to our new node.
	 *
	 * o If SID node found does not match and can't be autodetached, we
	 *   fail: we only allow one SID node at an address.
	 *
	 * NOTE: This code depends on SID nodes showing up prior to
	 * driver.conf nodes in the sibling list.
	 */
	for (;;) {
		/* first NULL name call is with init set */
		(void) scsi_findchild(self, NULL, addr, 1, &dsearch, NULL, &pi);
		if (dsearch == NULL)
			break;
		ASSERT(!scsi_hba_devi_is_barrier(dsearch));

		/*
		 * To detect changes in driver binding that should attempt
		 * autodetach we determine the major number of the driver
		 * that should currently be associated with the device based
		 * on the compatible property.
		 */
		major = DDI_MAJOR_T_NONE;
		if (scsi_hba_dev_is_sid(dsearch))
			major = ddi_compatible_driver_major(dsearch, NULL);
		if ((major == DDI_MAJOR_T_NONE) && (name == NULL))
			major = ddi_driver_major(dsearch);

		if ((scsi_hba_dev_is_sid(dsearch) ||
		    (i_ddi_node_state(dsearch) >= DS_INITIALIZED)) &&
		    ((name == NULL) ||
		    (strcmp(ddi_node_name(dsearch), name) == 0) ||
		    (strcmp(ddi_driver_name(dsearch), name) == 0)) &&
		    (major == ddi_driver_major(dsearch))) {
			SCSI_HBA_LOG((_LOG(3), NULL, dsearch,
			    "already attached @addr"));
			child = dsearch;
			goto done;
		}

		if (!scsi_hba_dev_is_sid(dsearch))
			break;			/* driver.conf node */

		/*
		 * Implement autodetach of SID node for situations like a
		 * previously "scsinodev" LUN0 coming into existence (or a
		 * disk/tape on an SPI transport at same addr but never both
		 * powered on at the same time). Try to autodetach the existing
		 * SID node @addr. If that works, search again - otherwise fail.
		 */
		SCSI_HBA_LOG((_LOG(2), NULL, dsearch,
		    "looking for %s@%s: SID @addr exists, autodetach",
		    name ? name : "", addr));
		if (!scsi_hba_remove_node(dsearch)) {
			SCSI_HBA_LOG((_LOG(2), NULL, dsearch,
			    "autodetach @%s failed: fail %s@%s",
			    addr, name ? name : "", addr));
			goto fail;
		}
		SCSI_HBA_LOG((_LOG(2), self, NULL, "autodetach @%s OK", addr));
	}

	/*
	 * We will be creating a new SID node, allocate probe node
	 * used to find out information about the device located @addr.
	 * The probe node also acts as a barrier against additional
	 * configuration at the same address, and in the case of non-existent
	 * devices it will (for some amount of time) avoid re-learning that
	 * the device does not exist on every reference. Once the probe
	 * node is DS_LINKED we can drop the HBA (self).
	 *
	 * The probe node is allocated as a hidden node so that it does not
	 * show up in devinfo snapshots.
	 */
	ndi_devi_alloc_sleep(self, "probe",
	    (se == SE_HP) ? DEVI_SID_HP_HIDDEN_NODEID : DEVI_SID_HIDDEN_NODEID,
	    &probe);
	ASSERT(probe);
	ndi_flavor_set(probe, SCSA_FLAVOR_SCSI_DEVICE);

	/*
	 * Decorate the probe node with the property representation of @addr
	 * unit-address string prior to initchild so that initchild can
	 * construct the name of the node from properties and tran_tgt_init
	 * implementation can determine what LUN is being referenced.
	 *
	 * If the addr specified has incorrect syntax (busconfig one of bogus
	 * /devices path) then scsi_hba_ua_set can fail.  If the address
	 * is not understood by the SCSA HBA driver then this operation will
	 * work, but tran_tgt_init may still fail (for example the HBA
	 * driver may not support secondary functions).
	 */
	if (scsi_hba_ua_set(addr, probe, NULL) == 0) {
		SCSI_HBA_LOG((_LOG(2), NULL, probe,
		    "@%s failed scsi_hba_ua_set", addr));
		goto fail;
	}

	/*
	 * Set the class property to "scsi". This is sufficient to distinguish
	 * the node for HBAs that have multiple classes of children (like uata
	 * - which has "dada" class for ATA children and "scsi" class for
	 * ATAPI children) and may not use our scsi_busctl_initchild()
	 * implementation. We also add a "compatible" property of "scsiprobe"
	 * to select the probe driver.
	 */
	if ((ndi_prop_update_string(DDI_DEV_T_NONE, probe,
	    "class", "scsi") != DDI_PROP_SUCCESS) ||
	    (ndi_prop_update_string_array(DDI_DEV_T_NONE, probe,
	    "compatible", &compatible_probe, 1) != DDI_PROP_SUCCESS)) {
		SCSI_HBA_LOG((_LOG(1), NULL, probe,
		    "@%s failed node decoration", addr));
		goto fail;
	}

	/*
	 * Promote probe node to DS_INITIALIZED so that transport can be used
	 * for scsi_probe. After this the node is linked and visible as a
	 * barrier for serialization of other @addr operations.
	 *
	 * NOTE: If we attached the probe node, we could get rid of
	 * uninit_prevent.
	 */
	if (ddi_initchild(self, probe) != DDI_SUCCESS) {
		SCSI_HBA_LOG((_LOG(2), NULL, probe,
		    "@%s failed initchild", addr));

		/* probe node will be removed in fail exit path */
		goto fail;
	}

	/* get the scsi_device structure of the probe node */
	sdprobe = ddi_get_driver_private(probe);
	ASSERT(sdprobe);

	/*
	 * Do scsi_probe. The probe node is linked and visible as a barrier.
	 * We prevent uninitialization of the probe node and drop our HBA (self)
	 * while we run scsi_probe() of this "@addr". This allows the framework
	 * to support multiple scsi_probes for different devices attached to
	 * the same HBA (self) in parallel. We prevent node demotion of the
	 * probe node from DS_INITIALIZED by setting sd_uninit_prevent. The
	 * probe node can not be successfully demoted below DS_INITIALIZED
	 * (scsi_busctl_uninitchild will fail) until we zero sd_uninit_prevent
	 * as we are freeing the node via scsi_hba_remove_node(probe).
	 */
	sdprobe->sd_uninit_prevent++;
	scsi_hba_devi_exit(self, *circp);
	sp = scsi_probe(sdprobe, SLEEP_FUNC);

	/* Introduce a small delay here to increase parallelism. */
	delay_random(5);

	if (sp == SCSIPROBE_EXISTS) {
		/*
		 * For a device that exists, while still running in parallel,
		 * also get identity information from device. This is done
		 * separate from scsi_probe/tran_tgt_probe/scsi_hba_probe
		 * since the probe code path may still be used for HBAs
		 * that don't use common bus_config services (we don't want
		 * to expose that code path to a behavior change). This
		 * operation is called 'identity' to avoid confusion with
		 * deprecated identify(9E).
		 *
		 * Future: We may eventually want to allow HBA customization via
		 * scsi_identity/tran_tgt_identity/scsi_device_identity, but for
		 * now we just scsi_device_identity.
		 *
		 * The identity operation will establish additional properties
		 * on the probe node related to device identity:
		 *
		 *	"inquiry-page-80"	byte array of SCSI page 80
		 *	"inquiry-page-83"	byte array of SCSI page 83
		 *
		 * These properties will be used to generate a devid
		 * (ddi_devid_scsi_encode) and guid - and to register
		 * (ddi_devid_register) a devid for the device.
		 *
		 * If identify fails (non-zero return), the we had allocation
		 * problems or the device returned inconsistent results then
		 * we pretend that device does not exist.
		 */
		if (scsi_device_identity(sdprobe, SLEEP_FUNC)) {
			scsi_enumeration_failed(probe, -1, NULL, "identify");
			sp = SCSIPROBE_FAILURE;
		}

		/*
		 * Future: Is there anything more we can do here to help avoid
		 * serialization on iport parent during scsi_device attach(9E)?
		 */
	}
	scsi_hba_devi_enter(self, circp);
	sdprobe->sd_uninit_prevent--;

	if (sp != SCSIPROBE_EXISTS) {
		scsi_enumeration_failed(probe, -1, NULL, "probe");

		if ((se != SE_HP) && scsi_hba_barrier_timeout) {
			/*
			 * Target does not exist. Mark the barrier probe node
			 * as DEVICE_REMOVED and schedule an asynchronous
			 * deletion of the node in scsi_hba_barrier_timeout
			 * seconds. We keep our hold on the probe node
			 * until we are ready perform the asynchronous node
			 * deletion.
			 */
			SCSI_HBA_LOG((_LOG(3), NULL, probe,
			    "set probe DEVICE_REMOVED"));
			mutex_enter(&DEVI(probe)->devi_lock);
			DEVI_SET_DEVICE_REMOVED(probe);
			mutex_exit(&DEVI(probe)->devi_lock);

			scsi_hba_barrier_add(probe, scsi_hba_barrier_timeout);
			probe = NULL;
		}
		goto fail;
	}

	/* Create the child node from the inquiry data in the probe node. */
	if ((child = scsi_device_configchild(self, addr, se, sdprobe,
	    circp, &pi)) == NULL) {
		/*
		 * This may fail because there was no driver binding identified
		 * via driver_alias. We may still have a conf node.
		 */
		if (name) {
			(void) scsi_findchild(self, name, addr,
			    0, &child, NULL, &pi);
			if (child)
				SCSI_HBA_LOG((_LOG(2), NULL, child,
				    "using driver.conf driver binding"));
		}
		if (child == NULL) {
			SCSI_HBA_LOG((_LOG(2), NULL, probe,
			    "device not configured"));
			goto fail;
		}
	}

	/*
	 * Transfer the inquiry data from the probe node to the child
	 * SID node to avoid an extra scsi_probe. Callers depend on
	 * established inquiry data for the returned scsi_device.
	 */
	sdchild = ddi_get_driver_private(child);
	if (sdchild && (sdchild->sd_inq == NULL)) {
		sdchild->sd_inq = sdprobe->sd_inq;
		sdprobe->sd_inq = NULL;
	}

	/*
	 * If we are doing a bus_configone and the node we created has the
	 * wrong node and driver name then switch the return result to a
	 * driver.conf node with the correct name - if such a node exists.
	 */
	if (name && (strcmp(ddi_node_name(child), name) != 0) &&
	    (strcmp(ddi_driver_name(child), name) != 0)) {
		(void) scsi_findchild(self, name, addr,
		    0, &dsearch, NULL, &pi);
		if (dsearch == NULL) {
			SCSI_HBA_LOG((_LOG(2), NULL, child,
			    "wrong device configured %s@%s", name, addr));
			/*
			 * We can't remove when modrootloaded == 0 in case
			 * boot-device a uses generic name and
			 * scsi_hba_nodename_compatible_get() returned a
			 * legacy binding-set driver oriented name.
			 */
			if (modrootloaded) {
				(void) scsi_hba_remove_node(child);
				child = NULL;
				goto fail;
			}
		} else {
			SCSI_HBA_LOG((_LOG(2), NULL, dsearch,
			    "device configured, but switching to driver.conf"));
			child = dsearch;
		}
	}

	/* get the scsi_device structure from the node */
	SCSI_HBA_LOG((_LOG(3), NULL, child, "device configured"));

	if (child) {
done:		ASSERT(child);
		sdchild = ddi_get_driver_private(child);
		ASSERT(sdchild);

		/*
		 * We may have ended up here after promotion of a previously
		 * demoted node, where demotion deleted sd_inq data in
		 * scsi_busctl_uninitchild.  We redo the scsi_probe() to
		 * reestablish sd_inq.  We also want to redo the scsi_probe
		 * for devices are currently device_isremove in order to
		 * detect new device_insert.
		 */
		if ((sdchild->sd_inq == NULL) ||
		    ((pi == NULL) && ndi_devi_device_isremoved(child))) {

			/* hotplug_node can only be revived via hotplug. */
			if ((se == SE_HP) || !ndi_dev_is_hotplug_node(child)) {
				SCSI_HBA_LOG((_LOG(3), NULL, child,
				    "scsi_probe() demoted devinfo"));

				sp = scsi_probe(sdchild, SLEEP_FUNC);

				if (sp == SCSIPROBE_EXISTS) {
					ASSERT(sdchild->sd_inq);

					/*
					 * Devinfo child exists and we are
					 * talking to the device, report
					 * reinsert and note if this was a
					 * new reinsert.
					 */
					chg = ndi_devi_device_insert(child);
					SCSI_HBA_LOG((_LOGCFG, NULL, child,
					    "devinfo %s@%s device_reinsert%s",
					    name ? name : "", addr,
					    chg ? "" : "ed already"));
				} else {
					scsi_enumeration_failed(child, se,
					    NULL, "reprobe");

					chg = ndi_devi_device_remove(child);
					SCSI_HBA_LOG((_LOG(2), NULL, child,
					    "%s device_remove%s",
					    (sp > (sizeof (scsi_probe_ascii) /
					    sizeof (scsi_probe_ascii[0]))) ?
					    "UNKNOWN" : scsi_probe_ascii[sp],
					    chg ? "" : "ed already"));

					child = NULL;
					sdchild = NULL;
				}
			} else {
				SCSI_HBA_LOG((_LOG(2), NULL, child,
				    "no reprobe"));

				child = NULL;
				sdchild = NULL;
			}
		}
	} else {
fail:		ASSERT(child == NULL);
		sdchild = NULL;
	}
	if (probe) {
		/*
		 * Clean up probe node, destroying node if uninit_prevent
		 * it is going to zero. Destroying the probe node (deleting
		 * from the sibling list) will wake up any people waiting on
		 * the probe node barrier.
		 */
		SCSI_HBA_LOG((_LOG(4), NULL, probe, "remove probe"));
		if (!scsi_hba_remove_node(probe)) {
			/*
			 * Probe node removal should not fail, but if it
			 * does we hand that responsibility over to the
			 * async barrier deletion thread - other references
			 * to the same unit-address can hang until the
			 * probe node delete completes.
			 */
			SCSI_HBA_LOG((_LOG(4), NULL, probe,
			    "remove probe failed, go async"));
			scsi_hba_barrier_add(probe, 1);
		}
		probe = NULL;
	}

	/*
	 * If we successfully resolved via a pathinfo node, we need to find
	 * the pathinfo node and ensure that it is online (if possible). This
	 * is done for the case where the device was open when
	 * scsi_device_unconfig occurred, so mdi_pi_free did not occur. If the
	 * device has now been reinserted, we want the path back online.
	 * NOTE: This needs to occur after destruction of the probe node to
	 * avoid ASSERT related to two nodes at the same unit-address.
	 */
	if (sdchild && pi && (probe == NULL)) {
		ASSERT(MDI_PHCI(self));

		(void) scsi_findchild(self, NULL, addr,
		    0, &dsearch, &psearch, NULL);
		ASSERT((psearch == NULL) ||
		    (mdi_pi_get_client(psearch) == child));

		if (psearch && mdi_pi_device_isremoved(psearch)) {
			/*
			 * Verify that we can talk to the device, and if
			 * so note if this is a new device_insert.
			 *
			 * NOTE: We depend on mdi_path_select(), when given
			 * a specific path_instance, to select that path
			 * even if the path is offline.
			 *
			 * NOTE: A Client node is not ndi_dev_is_hotplug_node().
			 */
			if (se == SE_HP) {
				SCSI_HBA_LOG((_LOG(3), NULL, child,
				    "%s scsi_probe() demoted pathinfo",
				    mdi_pi_spathname(psearch)));

				sp = scsi_hba_probe_pi(sdchild, SLEEP_FUNC, pi);

				if (sp == SCSIPROBE_EXISTS) {
					/*
					 * Pathinfo child exists and we are
					 * talking to the device, report
					 * reinsert and note if this
					 * was a new reinsert.
					 */
					chg = mdi_pi_device_insert(psearch);
					SCSI_HBA_LOG((_LOGCFG, self, NULL,
					    "pathinfo %s device_reinsert%s",
					    mdi_pi_spathname(psearch),
					    chg ? "" : "ed already"));

					if (chg)
						(void) mdi_pi_online(psearch,
						    0);

					/*
					 * Report client reinsert and note if
					 * this was a new reinsert.
					 */
					chg = ndi_devi_device_insert(child);
					SCSI_HBA_LOG((_LOGCFG, NULL, child,
					    "client devinfo %s@%s "
					    "device_reinsert%s",
					    name ? name : "", addr,
					    chg ? "" : "ed already"));
				} else {
					scsi_enumeration_failed(child, se,
					    mdi_pi_spathname(psearch),
					    "reprobe");
					child = NULL;
					sdchild = NULL;
				}

			} else {
				SCSI_HBA_LOG((_LOG(2), NULL, child,
				    "%s no reprobe",
				    mdi_pi_spathname(psearch)));

				child = NULL;
				sdchild = NULL;
			}
		}
	}

	/* If asked for path_instance, return it. */
	if (ppi)
		*ppi = pi;

	return (sdchild);
}

static void
scsi_device_unconfig(dev_info_t *self, char *name, char *addr, int *circp)
{
	dev_info_t		*child = NULL;
	mdi_pathinfo_t		*path = NULL;
	char			*spathname;
	int			rval;

	ASSERT(self && addr && DEVI_BUSY_OWNED(self));

	/*
	 * We have a catch-22. We may have a demoted node that we need to find
	 * and offline/remove. To find the node if it isn't demoted, we
	 * use scsi_findchild. If it's demoted, we then use
	 * ndi_devi_findchild_by_callback.
	 */
	(void) scsi_findchild(self, name, addr, 0, &child, &path, NULL);

	if ((child == NULL) && (path == NULL)) {
		child = ndi_devi_findchild_by_callback(self, name, addr,
		    scsi_busctl_ua);
		if (child) {
			SCSI_HBA_LOG((_LOGUNCFG, self, NULL,
			    "devinfo %s@%s found by callback",
			    name ? name : "", addr));
			ASSERT(ndi_flavor_get(child) ==
			    SCSA_FLAVOR_SCSI_DEVICE);
			if (ndi_flavor_get(child) != SCSA_FLAVOR_SCSI_DEVICE) {
				SCSI_HBA_LOG((_LOGUNCFG, self, NULL,
				    "devinfo %s@%s not SCSI_DEVICE flavored",
				    name ? name : "", addr));
				child = NULL;
			}
		}
	}

	if (child) {
		ASSERT(child && (path == NULL));

		/* Don't unconfig probe nodes. */
		if (scsi_hba_devi_is_barrier(child)) {
			SCSI_HBA_LOG((_LOGUNCFG, self, NULL,
			    "devinfo %s@%s is_barrier, skip",
			    name ? name : "", addr));
			return;
		}

		/* Attempt to offline/remove the devinfo node */
		if (ndi_devi_offline(child,
		    NDI_DEVFS_CLEAN | NDI_DEVI_REMOVE) == DDI_SUCCESS) {
			SCSI_HBA_LOG((_LOGUNCFG, self, NULL,
			    "devinfo %s@%s offlined and removed",
			    name ? name : "", addr));
		} else if (ndi_devi_device_remove(child)) {
			/* Offline/remove failed, note new device_remove */
			SCSI_HBA_LOG((_LOGUNCFG, self, NULL,
			    "devinfo %s@%s offline failed, device_remove",
			    name ? name : "", addr));
		}
	} else if (path) {
		ASSERT(path && (child == NULL));

		/*
		 * Attempt to offline/remove the pathinfo node.
		 *
		 * NOTE: mdi_pi_offline of last path will fail if the
		 * device is open (i.e. the client can't be offlined).
		 *
		 * NOTE: For mdi there is no REMOVE flag for mdi_pi_offline().
		 * When mdi_pi_offline returns MDI_SUCCESS, we are responsible
		 * for remove via mdi_pi_free().
		 */
		mdi_hold_path(path);
		spathname = mdi_pi_spathname(path);	/* valid after free */
		scsi_hba_devi_exit_phci(self, *circp);
		rval = mdi_pi_offline(path, 0);
		scsi_hba_devi_enter_phci(self, circp);

		/* Note new device_remove */
		if (mdi_pi_device_remove(path))
			SCSI_HBA_LOG((_LOGUNCFG, self, NULL,
			    "pathinfo %s note device_remove", spathname));

		mdi_rele_path(path);
		if (rval == MDI_SUCCESS) {
			(void) mdi_pi_free(path, 0);
			SCSI_HBA_LOG((_LOGUNCFG, self, NULL,
			    "pathinfo %s offlined, then freed", spathname));
		}
	} else {
		ASSERT((path == NULL) && (child == NULL));

		SCSI_HBA_LOG((_LOGUNCFG, self, NULL,
		    "%s@%s not found", name ? name : "", addr));
	}
}

/*
 * configure the device at the specified "@addr" address.
 */
static struct scsi_device *
scsi_hba_bus_configone_addr(dev_info_t *self, char *addr, scsi_enum_t se)
{
	int			circ;
	struct scsi_device	*sd;

	scsi_hba_devi_enter(self, &circ);
	sd = scsi_device_config(self, NULL, addr, se, &circ, NULL);
	scsi_hba_devi_exit(self, circ);
	return (sd);
}

/*
 * unconfigure the device at the specified "@addr" address.
 */
static void
scsi_hba_bus_unconfigone_addr(dev_info_t *self, char *addr)
{
	int			circ;

	scsi_hba_devi_enter(self, &circ);
	(void) scsi_device_unconfig(self, NULL, addr, &circ);
	scsi_hba_devi_exit(self, circ);
}

/*
 * The bus_config_all operations are multi-threaded for performance. A
 * separate thread per target and per LUN is used. The config handle is used
 * to coordinate all the threads at a given level and the config thread data
 * contains the required information for a specific thread to identify what it
 * is processing and the handle under which this is being processed.
 */

/* multi-threaded config handle */
struct	scsi_hba_mte_h {
	dev_info_t		*h_self;	/* initiator port */
	int			h_thr_count;
	kmutex_t		h_lock;
	kcondvar_t		h_cv;
};

/* target of 'self' config thread data */
struct scsi_hba_mte_td {
	struct scsi_hba_mte_h	*td_h;
	char			*td_taddr;	/* target port */
	int			td_mt;
	scsi_enum_t		td_se;
};

/* Invoke callback on a vector of taddrs from multiple threads */
static void
scsi_hba_thread_taddrs(dev_info_t *self, char **taddrs, int mt,
    scsi_enum_t se, void (*callback)(void *arg))
{
	struct scsi_hba_mte_h	*h;	/* HBA header */
	struct scsi_hba_mte_td	*td;	/* target data */
	char			**taddr;

	/* allocate and initialize the handle */
	h = kmem_zalloc(sizeof (*h), KM_SLEEP);
	mutex_init(&h->h_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&h->h_cv, NULL, CV_DEFAULT, NULL);
	h->h_self = self;

	/* loop over all the targets */
	for (taddr = taddrs; *taddr; taddr++) {
		/* allocate a thread data structure for target */
		td = kmem_alloc(sizeof (*td), KM_SLEEP);
		td->td_h = h;
		td->td_taddr = *taddr;
		td->td_mt = mt;
		td->td_se = se;

		/* process the target */
		mutex_enter(&h->h_lock);
		h->h_thr_count++;
		mutex_exit(&h->h_lock);

		if (mt & SCSI_ENUMERATION_MT_TARGET_DISABLE)
			callback((void *)td);
		else
			(void) thread_create(NULL, 0, callback, (void *)td,
			    0, &p0, TS_RUN, minclsyspri);
	}

	/* wait for all the target threads to complete */
	mutex_enter(&h->h_lock);
	while (h->h_thr_count > 0)
		cv_wait(&h->h_cv, &h->h_lock);
	mutex_exit(&h->h_lock);

	/* free the handle */
	cv_destroy(&h->h_cv);
	mutex_destroy(&h->h_lock);
	kmem_free(h, sizeof (*h));
}


/* lun/secondary function of lun0 config thread data */
struct scsi_hba_mte_ld {
	struct scsi_hba_mte_h	*ld_h;
	char			*ld_taddr;	/* target port */
	scsi_lun64_t		ld_lun64;	/* lun */
	int			ld_sfunc;	/* secondary function */
	scsi_enum_t		ld_se;
};

/*
 * Enumerate the LUNs and secondary functions of the specified target. The
 * target portion of the "@addr" is already represented as a string in the
 * thread data, we add a ",lun" representation to this and perform a
 * bus_configone byte of enumeration on that "@addr".
 */
static void
scsi_hba_enum_lsf_of_tgt_thr(void *arg)
{
	struct scsi_hba_mte_ld	*ld = (struct scsi_hba_mte_ld *)arg;
	struct scsi_hba_mte_h	*h = ld->ld_h;
	dev_info_t		*self = h->h_self;
	char			addr[SCSI_MAXNAMELEN];

	/* make string form of "@taddr,lun[,sfunc]" and see if it exists */
	if (ld->ld_sfunc == -1)
		(void) snprintf(addr, sizeof (addr),
		    "%s,%" PRIx64, ld->ld_taddr, ld->ld_lun64);
	else
		(void) snprintf(addr, sizeof (addr),
		    "%s,%" PRIx64 ",%x",
		    ld->ld_taddr, ld->ld_lun64, ld->ld_sfunc);

	/* configure device at that unit-address address */
	(void) scsi_hba_bus_configone_addr(self, addr, ld->ld_se);

	/* signal completion of this LUN thread to the target */
	mutex_enter(&h->h_lock);
	if (--h->h_thr_count == 0)
		cv_broadcast(&h->h_cv);
	mutex_exit(&h->h_lock);

	/* free config thread data */
	kmem_free(ld, sizeof (*ld));
}

/* Format of SCSI REPORT_LUNS report */
typedef struct scsi_lunrpt {
	uchar_t		lunrpt_len_msb;		/* # LUNs being reported */
	uchar_t		lunrpt_len_mmsb;
	uchar_t		lunrpt_len_mlsb;
	uchar_t		lunrpt_len_lsb;
	uchar_t		lunrpt_reserved[4];
	scsi_lun_t	lunrpt_luns[1];		/* LUNs, variable size */
} scsi_lunrpt_t;

/*
 * scsi_device_reportluns()
 *
 * Callers of this routine should ensure that the 'sd0' scsi_device structure
 * and 'pi' path_instance specified are associated with a responding LUN0.
 * This should not be called for SCSI-1 devices.
 *
 * To get a LUN report, we must allocate a buffer. To know how big to make the
 * buffer, we must know the number of LUNs. To know the number of LUNs, we must
 * get a LUN report. We first issue a SCMD_REPORT_LUNS command using a
 * reasonably sized buffer that's big enough to report all LUNs for most
 * typical devices. If it turns out that we needed a bigger buffer, we attempt
 * to allocate a buffer of sufficient size, and reissue the command. If the
 * first command succeeds, but the second fails, we return whatever we were
 * able to get the first time. We return enough information for the caller to
 * tell whether he got all the LUNs or only a subset.
 *
 * If successful, we allocate an array of scsi_lun_t to hold the results. The
 * caller must kmem_free(*lunarrayp, *sizep) when finished with it. Upon
 * successful return return value is NDI_SUCCESS and:
 *
 *	*lunarrayp points to the allocated array,
 *	*nlunsp is the number of valid LUN entries in the array,
 *	*tlunsp is the total number of LUNs in the target,
 *	*sizep is the size of the lunarrayp array, which must be freed.
 *
 * If the *nlunsp is less than *tlunsp, then we were only able to retrieve a
 * subset of the total set of LUNs in the target.
 */
static int
scsi_device_reportluns(struct scsi_device *sd0, char *taddr, int pi,
    scsi_lun_t **lunarrayp, uint32_t *nlunsp, uint32_t *tlunsp, size_t *sizep)
{
	struct buf	*lunrpt_bp;
	struct scsi_pkt *lunrpt_pkt;
	scsi_lunrpt_t	*lunrpt;
	uint32_t	bsize;
	uint32_t	tluns, nluns;
	int		default_maxluns = scsi_lunrpt_default_max;
	dev_info_t	*child;

	ASSERT(sd0 && lunarrayp && nlunsp && tlunsp && sizep);

	/*
	 * NOTE: child should only be used in SCSI_HBA_LOG context since with
	 * vHCI enumeration it may be the vHCI 'client' devinfo child instead
	 * of a child of the 'self' pHCI we are enumerating.
	 */
	child = sd0->sd_dev;

	/* first try, look for up to scsi_lunrpt_default_max LUNs */
	nluns = default_maxluns;

again:	bsize = sizeof (struct scsi_lunrpt) +
	    ((nluns - 1) * sizeof (struct scsi_lun));

	lunrpt_bp = scsi_alloc_consistent_buf(&sd0->sd_address,
	    (struct buf *)NULL, bsize, B_READ, SLEEP_FUNC, NULL);
	if (lunrpt_bp == NULL) {
		SCSI_HBA_LOG((_LOG(1), NULL, child, "failed alloc"));
		return (NDI_NOMEM);
	}

	lunrpt_pkt = scsi_init_pkt(&sd0->sd_address,
	    (struct scsi_pkt *)NULL, lunrpt_bp, CDB_GROUP5,
	    sizeof (struct scsi_arq_status), 0, PKT_CONSISTENT,
	    SLEEP_FUNC, NULL);
	if (lunrpt_pkt == NULL) {
		SCSI_HBA_LOG((_LOG(1), NULL, child, "failed init"));
		scsi_free_consistent_buf(lunrpt_bp);
		return (NDI_NOMEM);
	}

	(void) scsi_setup_cdb((union scsi_cdb *)lunrpt_pkt->pkt_cdbp,
	    SCMD_REPORT_LUNS, 0, bsize, 0);

	lunrpt_pkt->pkt_time = scsi_lunrpt_timeout;

	/*
	 * When sd0 is a vHCI scsi device, we need reportlun to be issued
	 * against a specific LUN0 path_instance that we are enumerating.
	 */
	lunrpt_pkt->pkt_path_instance = pi;
	lunrpt_pkt->pkt_flags |= FLAG_PKT_PATH_INSTANCE;

	/*
	 * NOTE: scsi_poll may not allow HBA specific recovery from TRAN_BUSY.
	 */
	if (scsi_poll(lunrpt_pkt) < 0) {
		SCSI_HBA_LOG((_LOG(2), NULL, child, "reportlun not supported"));
		scsi_destroy_pkt(lunrpt_pkt);
		scsi_free_consistent_buf(lunrpt_bp);
		return (NDI_FAILURE);
	}

	scsi_destroy_pkt(lunrpt_pkt);

	lunrpt = (scsi_lunrpt_t *)lunrpt_bp->b_un.b_addr;

	/* Compute the total number of LUNs in the target */
	tluns = (((uint_t)lunrpt->lunrpt_len_msb << 24) |
	    ((uint_t)lunrpt->lunrpt_len_mmsb << 16) |
	    ((uint_t)lunrpt->lunrpt_len_mlsb << 8) |
	    ((uint_t)lunrpt->lunrpt_len_lsb)) >> 3;

	if (tluns == 0) {
		/* Illegal response -- this target is broken */
		SCSI_HBA_LOG((_LOG(1), NULL, child, "illegal tluns of zero"));
		scsi_free_consistent_buf(lunrpt_bp);
		return (DDI_NOT_WELL_FORMED);
	}

	if (tluns > nluns) {
		/* have more than we allocated space for */
		if (nluns == default_maxluns) {
			/* first time around, reallocate larger */
			scsi_free_consistent_buf(lunrpt_bp);
			nluns = tluns;
			goto again;
		}

		/* uh oh, we got a different tluns the second time! */
		SCSI_HBA_LOG((_LOG(1), NULL, child,
		    "tluns changed from %d to %d", nluns, tluns));
	} else
		nluns = tluns;

	/*
	 * Now we have:
	 *	lunrpt_bp is the buffer we're using;
	 *	tluns is the total number of LUNs the target says it has;
	 *	nluns is the number of LUNs we were able to get into the buffer.
	 *
	 * Copy the data out of scarce iopb memory into regular kmem.
	 * The caller must kmem_free(*lunarrayp, *sizep) when finished with it.
	 */
	*lunarrayp = (scsi_lun_t *)kmem_alloc(
	    nluns * sizeof (scsi_lun_t), KM_SLEEP);
	if (*lunarrayp == NULL) {
		SCSI_HBA_LOG((_LOG(1), NULL, child, "NULL lunarray"));
		scsi_free_consistent_buf(lunrpt_bp);
		return (NDI_NOMEM);
	}

	*sizep = nluns * sizeof (scsi_lun_t);
	*nlunsp = nluns;
	*tlunsp = tluns;
	bcopy((void *)&lunrpt->lunrpt_luns, (void *)*lunarrayp, *sizep);
	scsi_free_consistent_buf(lunrpt_bp);
	SCSI_HBA_LOG((_LOG(3), NULL, child,
	    "@%s,0 path %d: %d/%d luns", taddr, pi, nluns, tluns));
	return (NDI_SUCCESS);
}

/*
 * Enumerate all the LUNs and secondary functions of the specified 'taddr'
 * target port as accessed via 'self' pHCI.  Note that sd0 may be associated
 * with a child of the vHCI instead of 'self' - in this case the 'pi'
 * path_instance is used to ensure that the SCMD_REPORT_LUNS command is issued
 * through the 'self' pHCI path.
 *
 * We multi-thread across all the LUNs and secondary functions and enumerate
 * them. Which LUNs exist is based on SCMD_REPORT_LUNS data.
 *
 * The scsi_device we are called with should be for LUN0 and has been probed.
 *
 * This function is structured so that an HBA that has a different target
 * addressing structure can still use this function to enumerate the its
 * LUNs if it uses "taddr,lun" for its LUN space.
 *
 * We make assumptions about other LUNs associated with the target:
 *
 *	For SCSI-2 and SCSI-3 target we will issue the SCSI report_luns
 *	command. If this fails or we have a SCSI-1 then the number of
 *	LUNs is determined based on SCSI_OPTIONS_NLUNS. For a SCSI-1
 *	target we never probe above LUN 8, even if SCSI_OPTIONS_NLUNS
 *	indicates we should.
 *
 * HBA drivers wanting a different set of assumptions should implement their
 * own LUN enumeration code.
 */
static int
scsi_hba_enum_lsf_of_t(struct scsi_device *sd0,
    dev_info_t *self, char *taddr, int pi, int mt, scsi_enum_t se)
{
	dev_info_t		*child;
	scsi_hba_tran_t		*tran;
	impl_scsi_tgtmap_t	*tgtmap;
	damap_id_t		tgtid;
	damap_t			*tgtdam;
	damap_t			*lundam = NULL;
	struct scsi_hba_mte_h	*h;
	struct scsi_hba_mte_ld	*ld;
	int			aver;
	scsi_lun_t		*lunp = NULL;
	int			lun;
	uint32_t		nluns;
	uint32_t		tluns;
	size_t			size;
	scsi_lun64_t		lun64;
	int			maxluns;

	/*
	 * If LUN0 failed then we have no other LUNs.
	 *
	 * NOTE: We need sd_inq to be valid to check ansi version. Since
	 * scsi_unprobe is now a noop (sd_inq freeded in
	 * scsi_busctl_uninitchild) sd_inq remains valid even if a target
	 * driver detach(9E) occurs, resulting in a scsi_unprobe call
	 * (sd_uninit_prevent keeps sd_inq valid by failing any
	 * device_uninitchild attempts).
	 */
	ASSERT(sd0 && sd0->sd_uninit_prevent && sd0->sd_dev && sd0->sd_inq);
	if ((sd0 == NULL) || (sd0->sd_dev == NULL) || (sd0->sd_inq == NULL)) {
		SCSI_HBA_LOG((_LOG(1), NULL, sd0 ? sd0->sd_dev : NULL,
		    "not setup correctly:%s%s%s",
		    (sd0 == NULL) ? " device" : "",
		    (sd0 && (sd0->sd_dev == NULL)) ? " dip" : "",
		    (sd0 && (sd0->sd_inq == NULL)) ? " inq" : ""));
		return (DDI_FAILURE);
	}

	/*
	 * NOTE: child should only be used in SCSI_HBA_LOG context since with
	 * vHCI enumeration it may be the vHCI 'client' devinfo child instead
	 * of a child of the 'self' pHCI we are enumerating.
	 */
	child = sd0->sd_dev;

	/* Determine if we are reporting lun observations into lunmap. */
	tran = ndi_flavorv_get(self, SCSA_FLAVOR_SCSI_DEVICE);
	tgtmap = (impl_scsi_tgtmap_t *)tran->tran_tgtmap;
	if (tgtmap) {
		tgtdam = tgtmap->tgtmap_dam[SCSI_TGT_SCSI_DEVICE];
		tgtid = damap_lookup(tgtdam, taddr);
		if (tgtid != NODAM) {
			lundam = damap_id_priv_get(tgtdam, tgtid);
			damap_id_rele(tgtdam, tgtid);
			ASSERT(lundam);
		}
	}

	if (lundam) {
		/* If using lunmap, start the observation */
		scsi_lunmap_set_begin(self, lundam);
	} else {
		/* allocate and initialize the LUN handle */
		h = kmem_zalloc(sizeof (*h), KM_SLEEP);
		mutex_init(&h->h_lock, NULL, MUTEX_DEFAULT, NULL);
		cv_init(&h->h_cv, NULL, CV_DEFAULT, NULL);
		h->h_self = self;
	}

	/* See if SCMD_REPORT_LUNS works for SCSI-2 and beyond */
	aver = sd0->sd_inq->inq_ansi;
	if ((aver >= SCSI_VERSION_2) && (scsi_device_reportluns(sd0,
	    taddr, pi, &lunp, &nluns, &tluns, &size) == NDI_SUCCESS)) {

		ASSERT(lunp && (size > 0) && (nluns > 0) && (tluns > 0));

		/* loop over the reported LUNs */
		SCSI_HBA_LOG((_LOG(2), NULL, child,
		    "@%s,0 path %d: enumerating %d reported lun%s", taddr, pi,
		    nluns, nluns > 1 ? "s" : ""));

		for (lun = 0; lun < nluns; lun++) {
			lun64 = scsi_lun_to_lun64(lunp[lun]);

			if (lundam) {
				if (scsi_lunmap_set_add(self, lundam,
				    taddr, lun64, -1) != DDI_SUCCESS) {
					SCSI_HBA_LOG((_LOG_NF(WARN),
					    "@%s,%" PRIx64 " failed to create",
					    taddr, lun64));
				}
			} else {
				if (lun64 == 0)
					continue;

				/* allocate a thread data structure for LUN */
				ld = kmem_alloc(sizeof (*ld), KM_SLEEP);
				ld->ld_h = h;
				ld->ld_taddr = taddr;
				ld->ld_lun64 = lun64;
				ld->ld_sfunc = -1;
				ld->ld_se = se;

				/* process the LUN */
				mutex_enter(&h->h_lock);
				h->h_thr_count++;
				mutex_exit(&h->h_lock);

				if (mt & SCSI_ENUMERATION_MT_LUN_DISABLE)
					scsi_hba_enum_lsf_of_tgt_thr(
					    (void *)ld);
				else
					(void) thread_create(NULL, 0,
					    scsi_hba_enum_lsf_of_tgt_thr,
					    (void *)ld, 0, &p0, TS_RUN,
					    minclsyspri);
			}
		}

		/* free the LUN array allocated by scsi_device_reportluns */
		kmem_free(lunp, size);
	} else {
		/* Determine the number of LUNs to enumerate. */
		maxluns = scsi_get_scsi_maxluns(sd0);

		/* Couldn't get SCMD_REPORT_LUNS data */
		if (aver >= SCSI_VERSION_3) {
			scsi_enumeration_failed(child, se, taddr, "report_lun");

			/*
			 * Based on calling context tunable, only enumerate one
			 * lun (lun0) if scsi_device_reportluns() fails on a
			 * SCSI_VERSION_3 or greater device.
			 */
			if (scsi_lunrpt_failed_do1lun & (1 << se))
				maxluns = 1;
		}

		/* loop over possible LUNs, skipping LUN0 */
		if (maxluns > 1)
			SCSI_HBA_LOG((_LOG(2), NULL, child,
			    "@%s,0 path %d: enumerating luns 1-%d", taddr, pi,
			    maxluns - 1));
		else
			SCSI_HBA_LOG((_LOG(2), NULL, child,
			    "@%s,0 path %d: enumerating just lun0", taddr, pi));

		for (lun64 = 0; lun64 < maxluns; lun64++) {
			if (lundam) {
				if (scsi_lunmap_set_add(self, lundam,
				    taddr, lun64, -1) != DDI_SUCCESS) {
					SCSI_HBA_LOG((_LOG_NF(WARN),
					    "@%s,%" PRIx64 " failed to create",
					    taddr, lun64));
				}
			} else {
				if (lun64 == 0)
					continue;

				/* allocate a thread data structure for LUN */
				ld = kmem_alloc(sizeof (*ld), KM_SLEEP);
				ld->ld_h = h;
				ld->ld_taddr = taddr;
				ld->ld_lun64 = lun64;
				ld->ld_sfunc = -1;
				ld->ld_se = se;

				/* process the LUN */
				mutex_enter(&h->h_lock);
				h->h_thr_count++;
				mutex_exit(&h->h_lock);
				if (mt & SCSI_ENUMERATION_MT_LUN_DISABLE)
					scsi_hba_enum_lsf_of_tgt_thr(
					    (void *)ld);
				else
					(void) thread_create(NULL, 0,
					    scsi_hba_enum_lsf_of_tgt_thr,
					    (void *)ld, 0, &p0, TS_RUN,
					    minclsyspri);
			}
		}
	}

	/*
	 * If we have an embedded service as a secondary function on LUN0 and
	 * the primary LUN0 function is different than the secondary function
	 * then enumerate the secondary function. The sfunc value is the dtype
	 * associated with the embedded service.
	 *
	 * inq_encserv: enclosure service and our dtype is not DTYPE_ESI
	 * or DTYPE_UNKNOWN then create a separate DTYPE_ESI node for
	 * enclosure service access.
	 */
	ASSERT(sd0->sd_inq);
	if (sd0->sd_inq->inq_encserv &&
	    ((sd0->sd_inq->inq_dtype & DTYPE_MASK) != DTYPE_UNKNOWN) &&
	    ((sd0->sd_inq->inq_dtype & DTYPE_MASK) != DTYPE_ESI) &&
	    ((sd0->sd_inq->inq_ansi >= SCSI_VERSION_3))) {
		if (lundam) {
			if (scsi_lunmap_set_add(self, lundam,
			    taddr, 0, DTYPE_ESI) != DDI_SUCCESS) {
				SCSI_HBA_LOG((_LOG_NF(WARN),
				    "@%s,0,%x failed to create",
				    taddr, DTYPE_ESI));
			}
		} else {
			/* allocate a thread data structure for sfunc */
			ld = kmem_alloc(sizeof (*ld), KM_SLEEP);
			ld->ld_h = h;
			ld->ld_taddr = taddr;
			ld->ld_lun64 = 0;
			ld->ld_sfunc = DTYPE_ESI;
			ld->ld_se = se;

			/* process the LUN */
			mutex_enter(&h->h_lock);
			h->h_thr_count++;
			mutex_exit(&h->h_lock);
			if (mt & SCSI_ENUMERATION_MT_LUN_DISABLE)
				scsi_hba_enum_lsf_of_tgt_thr((void *)ld);
			else
				(void) thread_create(NULL, 0,
				    scsi_hba_enum_lsf_of_tgt_thr, (void *)ld,
				    0, &p0, TS_RUN, minclsyspri);
		}
	}

	/*
	 * Future: Add secondary function support for:
	 *	inq_mchngr (DTYPE_CHANGER)
	 *	inq_sccs (DTYPE_ARRAY_CTRL)
	 */

	if (lundam) {
		/* If using lunmap, end the observation */
		scsi_lunmap_set_end(self, lundam);
	} else {
		/* wait for all the LUN threads of this target to complete */
		mutex_enter(&h->h_lock);
		while (h->h_thr_count > 0)
			cv_wait(&h->h_cv, &h->h_lock);
		mutex_exit(&h->h_lock);

		/* free the target handle */
		cv_destroy(&h->h_cv);
		mutex_destroy(&h->h_lock);
		kmem_free(h, sizeof (*h));
	}

	return (DDI_SUCCESS);
}

/*
 * Enumerate LUN0 and all other LUNs and secondary functions associated with
 * the specified target address.
 *
 * Return NDI_SUCCESS if we might have created a new node.
 * Return NDI_FAILURE if we definitely did not create a new node.
 */
static int
scsi_hba_bus_config_taddr(dev_info_t *self, char *taddr, int mt, scsi_enum_t se)
{
	char			addr[SCSI_MAXNAMELEN];
	struct scsi_device	*sd;
	int			circ;
	int			ret;
	int			pi;

	/* See if LUN0 of the specified target exists. */
	(void) snprintf(addr, sizeof (addr), "%s,0", taddr);

	scsi_hba_devi_enter(self, &circ);
	sd = scsi_device_config(self, NULL, addr, se, &circ, &pi);

	if (sd) {
		/*
		 * LUN0 exists, enumerate all the other LUNs.
		 *
		 * With vHCI enumeration, when 'self' is a pHCI the sd
		 * scsi_device may be associated with the vHCI 'client'.
		 * In this case 'pi' is the path_instance needed to
		 * continue enumeration communication LUN0 via 'self'
		 * pHCI and specific 'taddr' target address.
		 *
		 * We prevent the removal of LUN0 until we are done with
		 * prevent/allow because we must exit the parent for
		 * multi-threaded scsi_hba_enum_lsf_of_t().
		 *
		 * NOTE: scsi_unprobe is a noop, sd->sd_inq is valid until
		 * device_uninitchild - so sd_uninit_prevent keeps sd_inq valid
		 * by failing any device_uninitchild attempts.
		 */
		ret = NDI_SUCCESS;
		sd->sd_uninit_prevent++;
		scsi_hba_devi_exit(self, circ);

		(void) scsi_hba_enum_lsf_of_t(sd, self, taddr, pi, mt, se);

		scsi_hba_devi_enter(self, &circ);
		sd->sd_uninit_prevent--;
	} else
		ret = NDI_FAILURE;
	scsi_hba_devi_exit(self, circ);
	return (ret);
}

/* Config callout from scsi_hba_thread_taddrs */
static void
scsi_hba_taddr_config_thr(void *arg)
{
	struct scsi_hba_mte_td	*td = (struct scsi_hba_mte_td *)arg;
	struct scsi_hba_mte_h	*h = td->td_h;

	(void) scsi_hba_bus_config_taddr(h->h_self, td->td_taddr,
	    td->td_mt, td->td_se);

	/* signal completion of this target thread to the HBA */
	mutex_enter(&h->h_lock);
	if (--h->h_thr_count == 0)
		cv_broadcast(&h->h_cv);
	mutex_exit(&h->h_lock);

	/* free config thread data */
	kmem_free(td, sizeof (*td));
}

/*
 * Enumerate all the children of the specified SCSI parallel interface (spi).
 * An HBA associated with a non-parallel scsi bus should be using another bus
 * level enumeration implementation (possibly their own) and calling
 * scsi_hba_bus_config_taddr to do enumeration of devices associated with a
 * particular target address.
 *
 * On an spi bus the targets are sequentially enumerated based on the
 * width of the bus. We also take care to try to skip the HBAs own initiator
 * id. See scsi_hba_enum_lsf_of_t() for LUN and secondary function enumeration.
 *
 * Return NDI_SUCCESS if we might have created a new node.
 * Return NDI_FAILURE if we definitely did not create a new node.
 *
 * Note: At some point we may want to expose this interface in transport.h
 * if we find an hba that implements bus_config but still uses spi-like target
 * addresses.
 */
static int
scsi_hba_bus_configall_spi(dev_info_t *self, int mt)
{
	int	options;
	int	ntargets;
	int	id;
	int	tgt;
	char	**taddrs;
	char	**taddr;
	char	*tbuf;

	/*
	 * Find the number of targets supported on the bus. Look at the per
	 * bus scsi-options property on the HBA node and check its
	 * SCSI_OPTIONS_WIDE setting.
	 */
	options = ddi_prop_get_int(DDI_DEV_T_ANY, self,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "scsi-options", -1);
	if ((options != -1) && ((options & SCSI_OPTIONS_WIDE) == 0))
		ntargets = NTARGETS;			/* 8 */
	else
		ntargets = NTARGETS_WIDE;		/* 16 */

	/*
	 * Find the initiator-id for the HBA so we can skip that. We get the
	 * cached value on the HBA node, established in scsi_hba_attach_setup.
	 * If we were unable to determine the id then we rely on the HBA to
	 * fail gracefully when asked to enumerate itself.
	 */
	id = ddi_prop_get_int(DDI_DEV_T_ANY, self,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "scsi-initiator-id", -1);
	if (id > ntargets) {
		SCSI_HBA_LOG((_LOG(1), self, NULL,
		    "'scsi-initiator-id' bogus for %d target bus: %d",
		    ntargets, id));
		id = -1;
	}
	SCSI_HBA_LOG((_LOG(2), self, NULL,
	    "enumerating targets 0-%d skip %d", ntargets, id));

	/* form vector of target addresses */
	taddrs = kmem_zalloc(sizeof (char *) * (ntargets + 1), KM_SLEEP);
	for (tgt = 0, taddr = taddrs; tgt < ntargets; tgt++) {
		/* skip initiator */
		if (tgt == id)
			continue;

		/* convert to string and enumerate the target address */
		tbuf = kmem_alloc(((tgt/16) + 1) + 1, KM_SLEEP);
		(void) sprintf(tbuf, "%x", tgt);
		ASSERT(strlen(tbuf) == ((tgt/16) + 1));
		*taddr++ = tbuf;
	}

	/* null terminate vector of target addresses */
	*taddr = NULL;

	/* configure vector of target addresses */
	scsi_hba_thread_taddrs(self, taddrs, mt, SE_BUSCONFIG,
	    scsi_hba_taddr_config_thr);

	/* free vector of target addresses */
	for (taddr = taddrs; *taddr; taddr++)
		kmem_free(*taddr, strlen(*taddr) + 1);
	kmem_free(taddrs, sizeof (char *) * (ntargets + 1));
	return (NDI_SUCCESS);
}

/*
 * Transport independent bus_configone BUS_CONFIG_ONE implementation.  Takes
 * same arguments, minus op, as scsi_hba_bus_config(), tran_bus_config(),
 * and scsi_hba_bus_config_spi().
 */
int
scsi_hba_bus_configone(dev_info_t *self, uint_t flags, char *arg,
    dev_info_t **childp)
{
	int			ret;
	int			circ;
	char			*name, *addr;
	char			*lcp;
	char			sc1, sc2;
	char			nameaddr[SCSI_MAXNAMELEN];
	extern int		i_ndi_make_spec_children(dev_info_t *, uint_t);
	struct scsi_device	*sd0, *sd;
	scsi_lun64_t		lun64;
	int			mt;

	/* parse_name modifies arg1, we must duplicate "name@addr" */
	(void) strcpy(nameaddr, arg);
	i_ddi_parse_name(nameaddr, &name, &addr, NULL);

	/* verify the form of the node - we need an @addr */
	if ((name == NULL) || (addr == NULL) ||
	    (*name == '\0') || (*addr == '\0')) {
		/*
		 * OBP may create ill formed template/stub/wild-card
		 * nodes (no @addr) for legacy driver loading methods -
		 * ignore them.
		 */
		SCSI_HBA_LOG((_LOG(2), self, NULL, "%s ill formed", arg));
		return (NDI_FAILURE);
	}

	/*
	 * Check to see if this is a non-scsi flavor configuration operation.
	 */
	if (strcmp(name, "smp") == 0) {
		/*
		 * Configure the child, and if we're successful return with
		 * active hold.
		 */
		return (smp_hba_bus_config(self, addr, childp));
	}

	/*
	 * The framework does not ensure the creation of driver.conf
	 * nodes prior to calling a nexus bus_config. For legacy
	 * support of driver.conf file nodes we want to create our
	 * driver.conf file children now so that we can detect if we
	 * are being asked to bus_configone one of these nodes.
	 *
	 * Needing driver.conf file nodes prior to bus config is unique
	 * to scsi_enumeration mixed mode (legacy driver.conf and
	 * dynamic SID node) support. There is no general need for the
	 * framework to make driver.conf children prior to bus_config.
	 *
	 * We enter our HBA (self) prior to scsi_device_config, and
	 * pass it our circ. The scsi_device_config may exit the
	 * HBA around scsi_probe() operations to allow for parallelism.
	 * This is done after the probe node "@addr" is available as a
	 * barrier to prevent parallel probes of the same device. The
	 * probe node is also configured in a way that it can't be
	 * removed by the framework until we are done with it.
	 *
	 * NOTE: The framework is currently preventing many parallel
	 * sibling operations (such as attaches), so the parallelism
	 * we are providing is of marginal use until that is improved.
	 * The most logical way to solve this would be to have separate
	 * target and lun nodes. This would be a large change in the
	 * format of /devices paths and is not being pursued at this
	 * time. The need for parallelism will become more of an issue
	 * with top-down attach for mpxio/vhci and for iSCSI support.
	 * We may want to eventually want a dual mode implementation,
	 * where the HBA determines if we should construct separate
	 * target and lun devinfo nodes.
	 */
	scsi_hba_devi_enter(self, &circ);
	SCSI_HBA_LOG((_LOG(4), self, NULL, "%s@%s config_one", name, addr));
	(void) i_ndi_make_spec_children(self, flags);

	/*
	 * For bus_configone, we make sure that we can find LUN0
	 * first. This allows the delayed probe/barrier deletion for a
	 * non-existent LUN0 (if enabled in scsi_device_config) to
	 * cover all LUNs on the target. This is done to minimize the
	 * number of independent target selection timeouts that occur
	 * when a target with many LUNs is no longer accessible
	 * (powered off). This removes the need for target driver
	 * probe cache implementations.
	 *
	 * This optimization may not be desirable in a pure bridge
	 * environment where targets on the other side of the bridge
	 * show up as LUNs to the host. If we ever need to support
	 * such a configuration then we should consider implementing a
	 * SCSI_OPTIONS_ILUN0 bit.
	 *
	 * NOTE: we are *not* applying any target limitation filtering
	 * to bus_configone, which means that we are relying on the
	 * HBA tran_tgt_init entry point invoked by scsi_busctl_initchild
	 * to fail.
	 */
	sd0 = (struct scsi_device *)-1;
	lcp = strchr(addr, ',');		/* "addr,lun[,sfunc]" */
	if (lcp) {
		/*
		 * With "tgt,lun[,sfunc]" addressing, multiple addressing levels
		 * have been compressed into single devinfo node unit-address.
		 * This presents a mismatch - there is no bus_config to discover
		 * LUNs below a specific target, the only choice is to
		 * BUS_CONFIG_ALL the HBA. To support BUS_CONFIG_ALL_LUNS below
		 * a specific target, a bus_configone with lun address of "*"
		 * triggers lun discovery below a target.
		 */
		if (*(lcp + 1) == '*') {
			mt = ddi_prop_get_int(DDI_DEV_T_ANY, self,
			    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
			    "scsi-enumeration", scsi_enumeration);
			mt |= scsi_hba_log_mt_disable;

			SCSI_HBA_LOG((_LOG(2), self, NULL,
			    "%s@%s lun enumeration triggered", name, addr));
			*lcp = '\0';		/* turn ',' into '\0' */
			scsi_hba_devi_exit(self, circ);
			(void) scsi_hba_bus_config_taddr(self, addr,
			    mt, SE_BUSCONFIG);
			return (NDI_FAILURE);
		}

		/* convert hex lun number from ascii */
		lun64 = scsi_addr_to_lun64(lcp + 1);

		if ((lun64 != 0) && (lun64 != SCSI_LUN64_ILLEGAL)) {
			/*
			 * configure ",0" lun first, saving off
			 * original lun characters.
			 */
			sc1 = *(lcp + 1);
			sc2 = *(lcp + 2);
			*(lcp + 1) = '0';
			*(lcp + 2) = '\0';
			sd0 = scsi_device_config(self,
			    NULL, addr, SE_BUSCONFIG, &circ, NULL);

			/* restore original lun */
			*(lcp + 1) = sc1;
			*(lcp + 2) = sc2;

			/*
			 * Apply maxlun filtering.
			 *
			 * Future: We still have the kludged
			 * scsi_check_ss2_LUN_limit() filtering off
			 * scsi_probe() to catch bogus driver.conf
			 * entries.
			 */
			if (sd0 && (lun64 < SCSI_32LUNS_PER_TARGET) &&
			    (lun64 >= scsi_get_scsi_maxluns(sd0))) {
				sd0 = NULL;
				SCSI_HBA_LOG((_LOG(4), self, NULL,
				    "%s@%s filtered", name, addr));
			} else
				SCSI_HBA_LOG((_LOG(4), self, NULL,
				    "%s@%s lun 0 %s", name, addr,
				    sd0 ? "worked" : "failed"));
		}
	}

	/*
	 * configure the requested device if LUN0 exists or we were
	 * unable to determine the lun format to determine if LUN0
	 * exists.
	 */
	if (sd0) {
		sd = scsi_device_config(self,
		    name, addr, SE_BUSCONFIG, &circ, NULL);
	} else {
		sd = NULL;
		SCSI_HBA_LOG((_LOG(2), self, NULL,
		    "%s@%s no lun 0 or filtered lun", name, addr));
	}

	/*
	 * We know what we found, to reduce overhead we finish BUS_CONFIG_ONE
	 * processing without calling back to the frameworks
	 * ndi_busop_bus_config (unless we goto framework below).
	 *
	 * If the reference is to a driver name and we created a generic name
	 * (bound to that driver) we will still succeed.  This is important
	 * for correctly resolving old drivername references to device that now
	 * uses a generic names across the transition to generic naming. This
	 * is effectively an internal implementation of the NDI_DRIVERNAME flag.
	 *
	 * We also need to special case the resolve_pathname OBP boot-device
	 * case (modrootloaded == 0) where reference is to a generic name but
	 * we created a legacy driver name node by returning just returning
	 * the node created.
	 */
	if (sd && sd->sd_dev &&
	    ((strcmp(ddi_node_name(sd->sd_dev), name) == 0) ||
	    (strcmp(ddi_driver_name(sd->sd_dev), name) == 0) ||
	    (modrootloaded == 0)) &&
	    (ndi_devi_online(sd->sd_dev,
	    flags & NDI_NO_EVENT) == NDI_SUCCESS)) {

		/* device attached, return devinfo node with hold */
		ret = NDI_SUCCESS;
		*childp = sd->sd_dev;
		ndi_hold_devi(sd->sd_dev);
	} else {
		/*
		 * In the process of failing we may have added nodes to the HBA
		 * (self), clearing DEVI_MADE_CHILDREN. To reduce the overhead
		 * associated with the frameworks reaction to this we clear the
		 * flag here.
		 */
		mutex_enter(&DEVI(self)->devi_lock);
		DEVI(self)->devi_flags &= ~DEVI_MADE_CHILDREN;
		mutex_exit(&DEVI(self)->devi_lock);
		ret = NDI_FAILURE;

		/*
		 * The framework may still be able to succeed with
		 * with its GENERIC_PROP code.
		 */
		scsi_hba_devi_exit(self, circ);
		if (flags & NDI_DRV_CONF_REPROBE)
			flags |= NDI_CONFIG_REPROBE;
		flags |= NDI_MDI_FALLBACK;	/* devinfo&pathinfo children */
		return (ndi_busop_bus_config(self, flags, BUS_CONFIG_ONE,
		    (void *)arg, childp, 0));
	}

	scsi_hba_devi_exit(self, circ);
	return (ret);
}

/*
 * Perform SCSI Parallel Interconnect bus_config
 */
static int
scsi_hba_bus_config_spi(dev_info_t *self, uint_t flags,
    ddi_bus_config_op_t op, void *arg, dev_info_t **childp)
{
	int			ret;
	int			mt;

	/*
	 * Enumerate scsi target devices: See if we are doing generic dynamic
	 * enumeration: if driver.conf has not specified the 'scsi-enumeration'
	 * knob then use the global scsi_enumeration knob.
	 */
	mt = ddi_prop_get_int(DDI_DEV_T_ANY, self,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    "scsi-enumeration", scsi_enumeration);
	mt |= scsi_hba_log_mt_disable;

	if ((mt & SCSI_ENUMERATION_ENABLE) == 0) {
		/*
		 * Static driver.conf file enumeration:
		 *
		 * Force reprobe for BUS_CONFIG_ONE or when manually
		 * reconfiguring via devfsadm(1m) to emulate deferred attach.
		 * Reprobe only discovers driver.conf enumerated nodes, more
		 * dynamic implementations probably require their own
		 * bus_config.
		 */
		if ((op == BUS_CONFIG_ONE) || (flags & NDI_DRV_CONF_REPROBE))
			flags |= NDI_CONFIG_REPROBE;
		flags |= NDI_MDI_FALLBACK;	/* devinfo&pathinfo children */
		return (ndi_busop_bus_config(self, flags, op, arg, childp, 0));
	}

	if (scsi_hba_bus_config_debug)
		flags |= NDI_DEVI_DEBUG;

	/*
	 * Generic spi dynamic bus config enumeration to discover and enumerate
	 * the target device nodes we are looking for.
	 */
	switch (op) {
	case BUS_CONFIG_ONE:	/* enumerate the named child */
		ret = scsi_hba_bus_configone(self, flags, (char *)arg, childp);
		break;

	case BUS_CONFIG_ALL:	/* enumerate all children on the bus */
	case BUS_CONFIG_DRIVER: /* enumerate all children that bind to driver */
		SCSI_HBA_LOG((_LOG(3), self, NULL,
		    "BUS_CONFIG_%s mt %x",
		    (op == BUS_CONFIG_ALL) ? "ALL" : "DRIVER", mt));

		/*
		 * Enumerate targets on SCSI parallel interconnect and let the
		 * framework finish the operation (attach the nodes).
		 */
		if ((ret = scsi_hba_bus_configall_spi(self, mt)) == NDI_SUCCESS)
			ret = ndi_busop_bus_config(self, flags, op,
			    arg, childp, 0);
		break;

	default:
		ret = NDI_FAILURE;
		break;
	}
	return (ret);
}

/*
 * Perform SCSI Parallel Interconnect bus_unconfig
 */
static int
scsi_hba_bus_unconfig_spi(dev_info_t *self, uint_t flags,
    ddi_bus_config_op_t op, void *arg)
{
	int	mt;
	int	circ;
	int	ret;

	/*
	 * See if we are doing generic dynamic enumeration: if driver.conf has
	 * not specified the 'scsi-enumeration' knob then use the global
	 * scsi_enumeration knob.
	 */
	mt = ddi_prop_get_int(DDI_DEV_T_ANY, self,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    "scsi-enumeration", scsi_enumeration);
	mt |= scsi_hba_log_mt_disable;

	if ((mt & SCSI_ENUMERATION_ENABLE) == 0)
		return (ndi_busop_bus_unconfig(self, flags, op, arg));

	if (scsi_hba_bus_config_debug)
		flags |= NDI_DEVI_DEBUG;

	scsi_hba_devi_enter(self, &circ);
	switch (op) {
	case BUS_UNCONFIG_ONE:
		SCSI_HBA_LOG((_LOG(3), self, NULL,
		    "unconfig one: %s", (char *)arg));
		ret = NDI_SUCCESS;
		break;

	case BUS_UNCONFIG_ALL:
	case BUS_UNCONFIG_DRIVER:
		ret = NDI_SUCCESS;
		break;

	default:
		ret = NDI_FAILURE;
		break;
	}

	/* Perform the generic default bus unconfig */
	if (ret == NDI_SUCCESS)
		ret = ndi_busop_bus_unconfig(self, flags, op, arg);

	scsi_hba_devi_exit(self, circ);

	return (ret);
}

static int
scsi_hba_bus_config_tgtmap(dev_info_t *self, uint_t flags,
    ddi_bus_config_op_t op, void *arg, dev_info_t **childp)
{
	scsi_hba_tran_t		*tran;
	impl_scsi_tgtmap_t	*tgtmap;
	uint64_t		tsa = 0;	/* clock64_t */
	int			maxdev;
	int			sync_usec;
	int			synced;
	int			ret = NDI_FAILURE;

	if ((op != BUS_CONFIG_ONE) && (op != BUS_CONFIG_ALL) &&
	    (op != BUS_CONFIG_DRIVER))
		goto out;

	tran = ndi_flavorv_get(self, SCSA_FLAVOR_SCSI_DEVICE);
	tgtmap = (impl_scsi_tgtmap_t *)tran->tran_tgtmap;
	ASSERT(tgtmap);

	/*
	 * MPXIO is never a sure thing (and we have mixed children), so
	 * set NDI_NDI_FALLBACK so that ndi_busop_bus_config will
	 * search for both devinfo and pathinfo children.
	 *
	 * Future: Remove NDI_MDI_FALLBACK since devcfg.c now looks for
	 * devinfo/pathinfo children in parallel (instead of old way of
	 * looking for one form of child and then doing "fallback" to
	 * look for other form of child).
	 */
	flags |= NDI_MDI_FALLBACK;	/* devinfo&pathinfo children */

	/*
	 * If bus_config occurred within the map create-to-hotplug_sync window,
	 * we need the framework to wait for children that are physicaly
	 * present at map create time to show up (via tgtmap hotplug config).
	 *
	 * The duration of this window is specified by the HBA driver at
	 * scsi_hba_tgtmap_create(9F) time (during attach(9E)). Its
	 * 'csync_usec' value is selected based on how long it takes the HBA
	 * driver to get from map creation to initial observation for something
	 * already plugged in. Estimate high, a low estimate can result in
	 * devices not showing up correctly on first reference. The call to
	 * ndi_busop_bus_config needs a timeout value large enough so that
	 * the map sync call further down is not a noop (i.e. done against
	 * an empty map when something is infact plugged in). With
	 * BUS_CONFIG_ONE, the call to ndi_busop_bus_config will return as
	 * soon as the desired device is enumerated via hotplug - so we are
	 * not committed to waiting the entire time.
	 *
	 * We are typically outside the window, so timeout is 0.
	 */
	sync_usec = tgtmap->tgtmap_create_csync_usec;
	if (tgtmap->tgtmap_create_window) {
		tsa = ddi_get_lbolt64() - tgtmap->tgtmap_create_time;
		if (tsa < drv_usectohz(sync_usec)) {
			tsa = drv_usectohz(sync_usec) - tsa;
			ret = ndi_busop_bus_config(self,
			    flags, op, arg, childp, (clock_t)tsa);
		} else
			tsa = 0;	/* passed window */

		/* First one out closes the window. */
		tgtmap->tgtmap_create_window = 0;
	} else if (op == BUS_CONFIG_ONE)
		ret = ndi_busop_bus_config(self, flags, op, arg, childp, 0);

	/* Return if doing a BUS_CONFIG_ONE and we found what we want. */
	if ((op == BUS_CONFIG_ONE) && (ret == NDI_SUCCESS))
		goto out;		/* performance path */

	/*
	 * We sync if we were in the window, on the first bus_config_one, and
	 * every bus_config_all (or bus_config_driver).
	 */
	if (tsa || (tgtmap->tgtmap_sync_cnt == 0) ||
	    (op != BUS_CONFIG_ONE)) {
		/*
		 * Sync current observations in the map and look again.  We
		 * place an upper bound on the amount of time we will wait for
		 * sync to complete to avoid a bad device causing this
		 * busconfig operation to hang.
		 *
		 * We are typically stable, so damap_sync returns immediately.
		 *
		 * Max time to wait for sync is settle_usec per possible device.
		 */
		tgtmap->tgtmap_sync_cnt++;
		maxdev = damap_size(tgtmap->tgtmap_dam[SCSI_TGT_SCSI_DEVICE]);
		maxdev = (maxdev > scsi_hba_map_settle_f) ? maxdev :
		    scsi_hba_map_settle_f;
		sync_usec = maxdev * tgtmap->tgtmap_settle_usec;
		synced = scsi_tgtmap_sync((scsi_hba_tgtmap_t *)tgtmap,
		    sync_usec);
		if (!synced)
			SCSI_HBA_LOG((_LOGCFG, self, NULL,
			    "tgtmap_sync timeout"));
	} else
		synced = -1;

	if (op == BUS_CONFIG_ONE)
		ret = scsi_hba_bus_configone(self, flags, arg, childp);
	else
		ret = ndi_busop_bus_config(self, flags, op, arg, childp, 0);

out:
#ifdef	DEBUG
	if (ret != NDI_SUCCESS) {
		if (scsi_hba_bus_config_failure_msg ||
		    scsi_hba_bus_config_failure_dbg) {
			scsi_hba_bus_config_failure_msg--;
			printf("%s%d: bus_config_tgtmap %p failure on %s: "
			    "%d %d\n",
			    ddi_driver_name(self), ddi_get_instance(self),
			    (void *)tgtmap,
			    (op == BUS_CONFIG_ONE) ? (char *)arg : "ALL",
			    (int)tsa, synced);
		}
		if (scsi_hba_bus_config_failure_dbg) {
			scsi_hba_bus_config_failure_dbg--;
			debug_enter("config_tgtmap failure");
		}
	} else if (scsi_hba_bus_config_success_msg ||
	    scsi_hba_bus_config_success_dbg) {
		scsi_hba_bus_config_success_msg--;
		printf("%s%d: bus_config_tgtmap %p success on %s: %d %d\n",
		    ddi_driver_name(self), ddi_get_instance(self),
		    (void *)tgtmap,
		    (op == BUS_CONFIG_ONE) ? (char *)arg : "ALL",
		    (int)tsa, synced);
		if (scsi_hba_bus_config_success_dbg) {
			scsi_hba_bus_config_success_dbg--;
			debug_enter("config_tgtmap success");
		}
	}
#endif	/* DEBUG */
	return (ret);
}

static int
scsi_hba_bus_unconfig_tgtmap(dev_info_t *self, uint_t flags,
    ddi_bus_config_op_t op, void *arg)
{
	int ret = NDI_FAILURE;

	switch (op) {
	case BUS_UNCONFIG_ONE:
	case BUS_UNCONFIG_DRIVER:
	case BUS_UNCONFIG_ALL:
		ret = NDI_SUCCESS;
		break;
	default:
		break;
	}

	if (ret == NDI_SUCCESS) {
		flags &= ~NDI_DEVI_REMOVE;
		ret = ndi_busop_bus_unconfig(self, flags, op, arg);
	}
	return (ret);
}

static int
scsi_hba_bus_config_iportmap(dev_info_t *self, uint_t flags,
    ddi_bus_config_op_t op, void *arg, dev_info_t **childp)
{
	scsi_hba_tran_t		*tran;
	impl_scsi_iportmap_t	*iportmap;
	dev_info_t		*child;
	int			circ;
	uint64_t		tsa = 0;	/* clock64_t */
	int			sync_usec;
	int			synced;
	int			ret = NDI_FAILURE;

	if ((op != BUS_CONFIG_ONE) && (op != BUS_CONFIG_ALL) &&
	    (op != BUS_CONFIG_DRIVER))
		goto out;

	tran = ndi_flavorv_get(self, SCSA_FLAVOR_SCSI_DEVICE);
	iportmap = (impl_scsi_iportmap_t *)tran->tran_iportmap;
	ASSERT(iportmap);

	/*
	 * MPXIO is never a sure thing (and we have mixed children), so
	 * set NDI_NDI_FALLBACK so that ndi_busop_bus_config will
	 * search for both devinfo and pathinfo children.
	 *
	 * Future: Remove NDI_MDI_FALLBACK since devcfg.c now looks for
	 * devinfo/pathinfo children in parallel (instead of old way of
	 * looking for one form of child and then doing "fallback" to
	 * look for other form of child).
	 */
	flags |= NDI_MDI_FALLBACK;	/* devinfo&pathinfo children */

	/*
	 * If bus_config occurred within the map create-to-hotplug_sync window,
	 * we need the framework to wait for children that are physicaly
	 * present at map create time to show up (via iportmap hotplug config).
	 *
	 * The duration of this window is specified by the HBA driver at
	 * scsi_hba_iportmap_create(9F) time (during attach(9E)). Its
	 * 'csync_usec' value is selected based on how long it takes the HBA
	 * driver to get from map creation to initial observation for something
	 * already plugged in. Estimate high, a low estimate can result in
	 * devices not showing up correctly on first reference. The call to
	 * ndi_busop_bus_config needs a timeout value large enough so that
	 * the map sync call further down is not a noop (i.e. done against
	 * an empty map when something is infact plugged in). With
	 * BUS_CONFIG_ONE, the call to ndi_busop_bus_config will return as
	 * soon as the desired device is enumerated via hotplug - so we are
	 * not committed to waiting the entire time.
	 *
	 * We are typically outside the window, so timeout is 0.
	 */
	sync_usec = iportmap->iportmap_create_csync_usec;
	if (iportmap->iportmap_create_window) {
		tsa = ddi_get_lbolt64() - iportmap->iportmap_create_time;
		if (tsa < drv_usectohz(sync_usec)) {
			tsa = drv_usectohz(sync_usec) - tsa;
			ret = ndi_busop_bus_config(self,
			    flags, op, arg, childp, (clock_t)tsa);
		} else
			tsa = 0;	/* passed window */

		/* First one out closes the window. */
		iportmap->iportmap_create_window = 0;
	} else if (op == BUS_CONFIG_ONE)
		ret = ndi_busop_bus_config(self, flags, op, arg, childp, 0);

	/* Return if doing a BUS_CONFIG_ONE and we found what we want. */
	if ((op == BUS_CONFIG_ONE) && (ret == NDI_SUCCESS))
		goto out;		/* performance path */

	/*
	 * We sync if we were in the window, on the first bus_config_one, and
	 * every bus_config_all (or bus_config_driver).
	 */
	if (tsa || (iportmap->iportmap_sync_cnt == 0) ||
	    (op != BUS_CONFIG_ONE)) {
		/*
		 * Sync current observations in the map and look again.  We
		 * place an upper bound on the amount of time we will wait for
		 * sync to complete to avoid a bad device causing this
		 * busconfig operation to hang.
		 *
		 * We are typically stable, so damap_sync returns immediately.
		 *
		 * Max time to wait for sync is settle_usec times settle factor.
		 */
		iportmap->iportmap_sync_cnt++;
		synced = damap_sync(iportmap->iportmap_dam, sync_usec);
		if (!synced)
			SCSI_HBA_LOG((_LOGCFG, self, NULL,
			    "iportmap_sync timeout"));
	} else
		synced = -1;

	if (op == BUS_CONFIG_ONE) {
		/* create the iport node child */
		scsi_hba_devi_enter(self, &circ);
		if ((child = scsi_hba_bus_config_port(self, (char *)arg,
		    SE_BUSCONFIG)) != NULL) {
			if (childp) {
				ndi_hold_devi(child);
				*childp = child;
			}
			ret = NDI_SUCCESS;
		}
		scsi_hba_devi_exit(self, circ);
	} else
		ret = ndi_busop_bus_config(self, flags, op, arg, childp, 0);

out:
#ifdef	DEBUG
	if (ret != NDI_SUCCESS) {
		if (scsi_hba_bus_config_failure_msg ||
		    scsi_hba_bus_config_failure_dbg) {
			scsi_hba_bus_config_failure_msg--;
			printf("%s%d: bus_config_iportmap %p failure on %s: "
			    "%d %d\n",
			    ddi_driver_name(self), ddi_get_instance(self),
			    (void *)iportmap,
			    (op == BUS_CONFIG_ONE) ? (char *)arg : "ALL",
			    (int)tsa, synced);
		}
		if (scsi_hba_bus_config_failure_dbg) {
			scsi_hba_bus_config_failure_dbg--;
			debug_enter("config_iportmap failure");
		}
	} else if (scsi_hba_bus_config_success_msg ||
	    scsi_hba_bus_config_success_dbg) {
		scsi_hba_bus_config_success_msg--;
		printf("%s%d: bus_config_iportmap %p success on %s: %d %d\n",
		    ddi_driver_name(self), ddi_get_instance(self),
		    (void *)iportmap,
		    (op == BUS_CONFIG_ONE) ? (char *)arg : "ALL",
		    (int)tsa, synced);
		if (scsi_hba_bus_config_success_dbg) {
			scsi_hba_bus_config_success_dbg--;
			debug_enter("config_iportmap success");
		}
	}
#endif	/* DEBUG */
	return (ret);
}

static int
scsi_hba_bus_unconfig_iportmap(dev_info_t *self, uint_t flags,
    ddi_bus_config_op_t op, void *arg)
{
	flags &= ~NDI_DEVI_REMOVE;
	return (ndi_busop_bus_unconfig(self, flags, op, arg));
}

/*
 * SCSI HBA bus config enumeration entry point. Called via the bus_ops
 * bus_config entry point for all SCSA HBA drivers.
 *
 *  o	If an HBA implements its own bus_config via tran_bus_config then we
 *	invoke it. An HBA that implements its own tran_bus_config entry	point
 *	may still call back into common SCSA code bus_config code for:
 *
 *	o SPI bus_config (scsi_hba_bus_spi)
 *	o LUN and secondary function enumeration (scsi_hba_enum_lsf_of_t()).
 *	o configuration of a specific device (scsi_device_config).
 *	o determining 1275 SCSI nodename and compatible property
 *	  (scsi_hba_nodename_compatible_get/_free).
 *
 *   o	Otherwise we implement a SCSI parallel interface (spi) bus config.
 *
 * Return NDI_SUCCESS if we might have created a new node.
 * Return NDI_FAILURE if we definitely did not create a new node.
 */
static int
scsi_hba_bus_config(dev_info_t *self, uint_t flags,
    ddi_bus_config_op_t op, void *arg, dev_info_t **childp)
{
	scsi_hba_tran_t	*tran;
	int		ret;

	/* make sure that we will not disappear */
	ASSERT(DEVI(self)->devi_ref);

	tran = ndi_flavorv_get(self, SCSA_FLAVOR_SCSI_DEVICE);
	if (tran == NULL) {
		/* NULL tran driver.conf config (used by cmdk). */
		if ((op == BUS_CONFIG_ONE) || (flags & NDI_DRV_CONF_REPROBE))
			flags |= NDI_CONFIG_REPROBE;
		return (ndi_busop_bus_config(self, flags, op, arg, childp, 0));
	}

	/* Check if self is HBA-only node. */
	if (tran->tran_hba_flags & SCSI_HBA_HBA) {
		/* The bus_config request is to configure iports below HBA. */

#ifdef	sparc
		/*
		 * Sparc's 'boot-device' OBP property value lacks an /iport@X/
		 * component. Prior to the mount of root, we drive a disk@
		 * BUS_CONFIG_ONE operatino down a level to resolve an
		 * OBP 'boot-device' path.
		 *
		 * Future: Add (modrootloaded == 0) below, and insure that
		 * all attempts bus_conf of 'bo_name' (in OBP form) occur
		 * prior to 'modrootloaded = 1;' assignment in vfs_mountroot.
		 */
		if ((op == BUS_CONFIG_ONE) &&
		    (strncmp((char *)arg, "disk@", strlen("disk@")) == 0)) {
			return (scsi_hba_bus_config_prom_node(self,
			    flags, arg, childp));
		}
#endif	/* sparc */

		if (tran->tran_iportmap) {
			/* config based on scsi_hba_iportmap API */
			ret = scsi_hba_bus_config_iportmap(self,
			    flags, op, arg, childp);
		} else {
			/* config based on 'iport_register' API */
			ret = scsi_hba_bus_config_iports(self,
			    flags, op, arg, childp);
		}
		return (ret);
	}

	/* Check to see how the iport/HBA does target/lun bus config. */
	if (tran->tran_bus_config) {
		/* HBA config based on Sun-private/legacy tran_bus_config */
		ret = tran->tran_bus_config(self, flags, op, arg, childp);
	} else if (tran->tran_tgtmap) {
		/* SCSAv3 config based on scsi_hba_tgtmap_*() API */
		ret =  scsi_hba_bus_config_tgtmap(self, flags, op, arg, childp);
	} else {
		/* SCSA config based on SCSI Parallel Interconnect */
		ret = scsi_hba_bus_config_spi(self, flags, op, arg, childp);
	}
	return (ret);
}

/*
 * Called via the bus_ops bus_unconfig entry point for SCSI HBA drivers.
 */
static int
scsi_hba_bus_unconfig(dev_info_t *self, uint_t flags,
    ddi_bus_config_op_t op, void *arg)
{
	int		circ;
	scsi_hba_tran_t	*tran;
	int		ret;

	tran = ddi_get_driver_private(self);
	if (tran == NULL) {
		/* NULL tran driver.conf unconfig (used by cmdk). */
		return (ndi_busop_bus_unconfig(self, flags, op, arg));
	}

	/*
	 * Purge barrier/probe node children. We do this prior to
	 * tran_bus_unconfig in case the unconfig implementation calls back
	 * into the common code at a different enumeration level, such a
	 * scsi_device_config, which still creates barrier/probe nodes.
	 */
	scsi_hba_devi_enter(self, &circ);
	scsi_hba_barrier_purge(self);
	scsi_hba_devi_exit(self, circ);

	/* DEBUG: for testing, allow bus_unconfig do drive removal. */
	if (scsi_hba_bus_unconfig_remove)
		flags |= NDI_DEVI_REMOVE;

	/* Check if self is HBA-only node. */
	if (tran->tran_hba_flags & SCSI_HBA_HBA) {
		/* The bus_config request is to unconfigure iports below HBA. */
		if (tran->tran_iportmap) {
			/* SCSAv3 unconfig based on scsi_hba_iportmap API */
			ret = scsi_hba_bus_unconfig_iportmap(self,
			    flags, op, arg);
		} else if (tran->tran_bus_unconfig) {
			/* HBA unconfig based on Sun-private/legacy API */
			ret = tran->tran_bus_unconfig(self, flags, op, arg);
		} else {
			/* Standard framework unconfig. */
			ret = ndi_busop_bus_unconfig(self, flags, op, arg);
		}
		return (ret);
	}

	/* Check to see how the iport/HBA does target/lun bus unconfig. */
	if (tran->tran_bus_unconfig) {
		/* HBA unconfig based on Sun-private/legacy tran_bus_unconfig */
		ret = tran->tran_bus_unconfig(self, flags, op, arg);
	} else if (tran->tran_tgtmap) {
		/* SCSAv3 unconfig based on scsi_hba_tgtmap_*() API */
		ret = scsi_hba_bus_unconfig_tgtmap(self, flags, op, arg);
	} else {
		/* SCSA unconfig based on SCSI Parallel Interconnect */
		ret = scsi_hba_bus_unconfig_spi(self, flags, op, arg);
	}
	return (ret);
}

static int
scsi_tgtmap_scsi_config(void *arg, damap_t *mapp, damap_id_t tgtid)
{
	scsi_hba_tran_t		*tran = (scsi_hba_tran_t *)arg;
	dev_info_t		*self = tran->tran_iport_dip;
	impl_scsi_tgtmap_t	*tgtmap;
	char			*tgtaddr;
	int			cfg_status, mt;

	tgtmap = (impl_scsi_tgtmap_t *)tran->tran_tgtmap;
	tgtaddr = damap_id2addr(mapp, tgtid);

	if (scsi_lunmap_create(self, tgtmap, tgtaddr) != DDI_SUCCESS) {
		SCSI_HBA_LOG((_LOG_NF(WARN),
		    "failed to create lunmap for %s", tgtaddr));
	}

	mt = ddi_prop_get_int(DDI_DEV_T_ANY, self,
	    DDI_PROP_NOTPROM | DDI_PROP_DONTPASS, "scsi-enumeration",
	    scsi_enumeration);
	mt |= scsi_hba_log_mt_disable;

	cfg_status = scsi_hba_bus_config_taddr(self, tgtaddr, mt, SE_HP);
	if (cfg_status != NDI_SUCCESS) {
		SCSI_HBA_LOG((_LOGCFG, self, NULL, "%s @%s config status %d",
		    damap_name(mapp), tgtaddr, cfg_status));
		scsi_lunmap_destroy(self, tgtmap, tgtaddr);
		return (DAM_FAILURE);
	}

	return (DAM_SUCCESS);
}


static int
scsi_tgtmap_scsi_unconfig(void *arg, damap_t *mapp, damap_id_t tgtid)
{
	scsi_hba_tran_t		*tran = (scsi_hba_tran_t *)arg;
	dev_info_t		*self = tran->tran_iport_dip;
	impl_scsi_tgtmap_t	*tgtmap;
	char			*tgt_addr;

	tgtmap = (impl_scsi_tgtmap_t *)tran->tran_tgtmap;
	tgt_addr = damap_id2addr(mapp, tgtid);

	SCSI_HBA_LOG((_LOGUNCFG, self, NULL, "%s @%s", damap_name(mapp),
	    tgt_addr));
	scsi_lunmap_destroy(self, tgtmap, tgt_addr);
	return (DAM_SUCCESS);
}

static int
scsi_tgtmap_smp_config(void *arg, damap_t *mapp, damap_id_t tgtid)
{
	scsi_hba_tran_t	*tran = (scsi_hba_tran_t *)arg;
	dev_info_t	*self = tran->tran_iport_dip;
	char		*addr;

	addr = damap_id2addr(mapp, tgtid);
	SCSI_HBA_LOG((_LOGCFG, self, NULL, "%s @%s", damap_name(mapp), addr));

	return ((smp_hba_bus_config_taddr(self, addr) == NDI_SUCCESS) ?
	    DAM_SUCCESS : DAM_FAILURE);
}

static int
scsi_tgtmap_smp_unconfig(void *arg, damap_t *mapp, damap_id_t tgtid)
{
	scsi_hba_tran_t	*tran = (scsi_hba_tran_t *)arg;
	dev_info_t	*self = tran->tran_iport_dip;
	char		*addr;
	dev_info_t	*child;
	char		nameaddr[SCSI_MAXNAMELEN];
	int		circ;

	addr = damap_id2addr(mapp, tgtid);
	SCSI_HBA_LOG((_LOGUNCFG, self, NULL, "%s @%s", damap_name(mapp), addr));

	(void) snprintf(nameaddr, sizeof (nameaddr), "smp@%s", addr);
	scsi_hba_devi_enter(self, &circ);
	if ((child = ndi_devi_findchild(self, nameaddr)) == NULL) {
		scsi_hba_devi_exit(self, circ);
		return (DAM_SUCCESS);
	}

	if (ndi_devi_offline(child,
	    NDI_DEVFS_CLEAN | NDI_DEVI_REMOVE) == DDI_SUCCESS) {
		SCSI_HBA_LOG((_LOGUNCFG, self, NULL,
		    "devinfo smp@%s offlined and removed", addr));
	} else if (ndi_devi_device_remove(child)) {
		/* Offline/remove failed, note new device_remove */
		SCSI_HBA_LOG((_LOGUNCFG, self, NULL,
		    "devinfo smp@%s offline failed, device_remove",
		    addr));
	}
	scsi_hba_devi_exit(self, circ);
	return (DAM_SUCCESS);
}

/* ARGSUSED1 */
static void
scsi_tgtmap_smp_activate(void *map_priv, char *tgt_addr, int addrid,
    void **tgt_privp)
{
	impl_scsi_tgtmap_t	*tgtmap = (impl_scsi_tgtmap_t *)map_priv;
	dev_info_t		*self = tgtmap->tgtmap_tran->tran_iport_dip;

	if (tgtmap->tgtmap_activate_cb) {
		SCSI_HBA_LOG((_LOGTGT, self, NULL, "%s @%s activated",
		    damap_name(tgtmap->tgtmap_dam[SCSI_TGT_SMP_DEVICE]),
		    tgt_addr));

		(*tgtmap->tgtmap_activate_cb)(tgtmap->tgtmap_mappriv,
		    tgt_addr, SCSI_TGT_SMP_DEVICE, tgt_privp);
	}
}

/* ARGSUSED1 */
static void
scsi_tgtmap_smp_deactivate(void *map_priv, char *tgt_addr, int addrid,
    void *tgt_privp, damap_deact_rsn_t damap_rsn)
{
	impl_scsi_tgtmap_t	*tgtmap = (impl_scsi_tgtmap_t *)map_priv;
	dev_info_t		*self = tgtmap->tgtmap_tran->tran_iport_dip;
	boolean_t		tgtmap_rereport;
	scsi_tgtmap_deact_rsn_t	tgtmap_rsn;

	if (tgtmap->tgtmap_deactivate_cb) {
		SCSI_HBA_LOG((_LOGTGT, self, NULL, "%s @%s deactivated %d",
		    damap_name(tgtmap->tgtmap_dam[SCSI_TGT_SMP_DEVICE]),
		    tgt_addr, damap_rsn));

		if (damap_rsn == DAMAP_DEACT_RSN_GONE)
			tgtmap_rsn = SCSI_TGT_DEACT_RSN_GONE;
		else if (damap_rsn == DAMAP_DEACT_RSN_CFG_FAIL)
			tgtmap_rsn = SCSI_TGT_DEACT_RSN_CFG_FAIL;
		else if (damap_rsn == DAMAP_DEACT_RSN_UNSTBL)
			tgtmap_rsn = SCSI_TGT_DEACT_RSN_UNSTBL;
		else {
			SCSI_HBA_LOG((_LOG(WARN), self, NULL,
			    "%s @%s deactivated with unknown rsn",
			    damap_name(tgtmap->tgtmap_dam[SCSI_TGT_SMP_DEVICE]),
			    tgt_addr));
			return;
		}

		tgtmap_rereport = (*tgtmap->tgtmap_deactivate_cb)
		    (tgtmap->tgtmap_mappriv, tgt_addr,
		    SCSI_TGT_SMP_DEVICE, tgt_privp, tgtmap_rsn);

		if ((tgtmap_rsn == SCSI_TGT_DEACT_RSN_CFG_FAIL) &&
		    (tgtmap_rereport == B_FALSE)) {
			SCSI_HBA_LOG((_LOG(WARN), NULL, self,
			    "%s enumeration failed, no more retries until "
			    "config change occurs", tgt_addr));
		}
	}
}

/* ARGSUSED1 */
static void
scsi_tgtmap_scsi_activate(void *map_priv, char *tgt_addr, int addrid,
    void **tgt_privp)
{
	impl_scsi_tgtmap_t	*tgtmap = (impl_scsi_tgtmap_t *)map_priv;
	dev_info_t		*self = tgtmap->tgtmap_tran->tran_iport_dip;

	if (tgtmap->tgtmap_activate_cb) {
		SCSI_HBA_LOG((_LOGTGT, self, NULL, "%s @%s activated",
		    damap_name(tgtmap->tgtmap_dam[SCSI_TGT_SCSI_DEVICE]),
		    tgt_addr));

		(*tgtmap->tgtmap_activate_cb)(tgtmap->tgtmap_mappriv,
		    tgt_addr, SCSI_TGT_SCSI_DEVICE, tgt_privp);
	}
}

/* ARGSUSED1 */
static void
scsi_tgtmap_scsi_deactivate(void *map_priv, char *tgt_addr, int addrid,
    void *tgt_privp, damap_deact_rsn_t damap_rsn)
{
	impl_scsi_tgtmap_t	*tgtmap = (impl_scsi_tgtmap_t *)map_priv;
	dev_info_t		*self = tgtmap->tgtmap_tran->tran_iport_dip;
	boolean_t		tgtmap_rereport;
	scsi_tgtmap_deact_rsn_t	tgtmap_rsn;

	if (tgtmap->tgtmap_deactivate_cb) {
		SCSI_HBA_LOG((_LOGTGT, self, NULL, "%s @%s deactivated %d",
		    damap_name(tgtmap->tgtmap_dam[SCSI_TGT_SCSI_DEVICE]),
		    tgt_addr, damap_rsn));

		if (damap_rsn == DAMAP_DEACT_RSN_GONE)
			tgtmap_rsn = SCSI_TGT_DEACT_RSN_GONE;
		else if (damap_rsn == DAMAP_DEACT_RSN_CFG_FAIL)
			tgtmap_rsn = SCSI_TGT_DEACT_RSN_CFG_FAIL;
		else if (damap_rsn == DAMAP_DEACT_RSN_UNSTBL)
			tgtmap_rsn = SCSI_TGT_DEACT_RSN_UNSTBL;
		else {
			SCSI_HBA_LOG((_LOG(WARN), self, NULL,
			    "%s @%s deactivated with unknown rsn", damap_name(
			    tgtmap->tgtmap_dam[SCSI_TGT_SCSI_DEVICE]),
			    tgt_addr));
			return;
		}

		tgtmap_rereport = (*tgtmap->tgtmap_deactivate_cb)
		    (tgtmap->tgtmap_mappriv, tgt_addr,
		    SCSI_TGT_SCSI_DEVICE, tgt_privp, tgtmap_rsn);

		if ((tgtmap_rsn == SCSI_TGT_DEACT_RSN_CFG_FAIL) &&
		    (tgtmap_rereport == B_FALSE)) {
			SCSI_HBA_LOG((_LOG(WARN), NULL, self,
			    "%s enumeration failed, no more retries until "
			    "config change occurs", tgt_addr));
		}
	}
}


int
scsi_hba_tgtmap_create(dev_info_t *self, scsi_tgtmap_mode_t mode,
    int csync_usec, int settle_usec, void *tgtmap_priv,
    scsi_tgt_activate_cb_t activate_cb, scsi_tgt_deactivate_cb_t deactivate_cb,
    scsi_hba_tgtmap_t **handle)
{
	scsi_hba_tran_t		*tran;
	damap_t			*mapp;
	char			context[64];
	impl_scsi_tgtmap_t	*tgtmap;
	damap_rptmode_t		rpt_style;
	char			*scsi_binding_set;
	int			optflags;

	if (self == NULL || csync_usec == 0 ||
	    settle_usec == 0 || handle == NULL)
		return (DDI_FAILURE);

	*handle = NULL;

	if (scsi_hba_iport_unit_address(self) == NULL)
		return (DDI_FAILURE);

	switch (mode) {
	case SCSI_TM_FULLSET:
		rpt_style = DAMAP_REPORT_FULLSET;
		break;
	case SCSI_TM_PERADDR:
		rpt_style = DAMAP_REPORT_PERADDR;
		break;
	default:
		return (DDI_FAILURE);
	}

	tran = (scsi_hba_tran_t *)ddi_get_driver_private(self);
	ASSERT(tran);
	if (tran == NULL)
		return (DDI_FAILURE);

	tgtmap = kmem_zalloc(sizeof (*tgtmap), KM_SLEEP);
	tgtmap->tgtmap_tran = tran;
	tgtmap->tgtmap_activate_cb = activate_cb;
	tgtmap->tgtmap_deactivate_cb = deactivate_cb;
	tgtmap->tgtmap_mappriv = tgtmap_priv;

	tgtmap->tgtmap_create_window = 1;	/* start with window */
	tgtmap->tgtmap_create_time = ddi_get_lbolt64();
	tgtmap->tgtmap_create_csync_usec = csync_usec;
	tgtmap->tgtmap_settle_usec = settle_usec;
	tgtmap->tgtmap_sync_cnt = 0;

	optflags = (ddi_prop_get_int(DDI_DEV_T_ANY, self,
	    DDI_PROP_NOTPROM | DDI_PROP_DONTPASS, "scsi-enumeration",
	    scsi_enumeration) & SCSI_ENUMERATION_MT_TARGET_DISABLE) ?
	    DAMAP_SERIALCONFIG : DAMAP_MTCONFIG;

	(void) snprintf(context, sizeof (context), "%s%d.tgtmap.scsi",
	    ddi_driver_name(self), ddi_get_instance(self));
	SCSI_HBA_LOG((_LOGTGT, self, NULL, "%s", context));
	if (damap_create(context, rpt_style, optflags, settle_usec,
	    tgtmap, scsi_tgtmap_scsi_activate, scsi_tgtmap_scsi_deactivate,
	    tran, scsi_tgtmap_scsi_config, scsi_tgtmap_scsi_unconfig,
	    &mapp) != DAM_SUCCESS) {
		kmem_free(tgtmap, sizeof (*tgtmap));
		return (DDI_FAILURE);
	}
	tgtmap->tgtmap_dam[SCSI_TGT_SCSI_DEVICE] = mapp;

	(void) snprintf(context, sizeof (context), "%s%d.tgtmap.smp",
	    ddi_driver_name(self), ddi_get_instance(self));
	SCSI_HBA_LOG((_LOGTGT, self, NULL, "%s", context));
	if (damap_create(context, rpt_style, optflags,
	    settle_usec, tgtmap, scsi_tgtmap_smp_activate,
	    scsi_tgtmap_smp_deactivate,
	    tran, scsi_tgtmap_smp_config, scsi_tgtmap_smp_unconfig,
	    &mapp) != DAM_SUCCESS) {
		damap_destroy(tgtmap->tgtmap_dam[SCSI_TGT_SCSI_DEVICE]);
		kmem_free(tgtmap, sizeof (*tgtmap));
		return (DDI_FAILURE);
	}
	tgtmap->tgtmap_dam[SCSI_TGT_SMP_DEVICE] = mapp;

	tran->tran_tgtmap = (scsi_hba_tgtmap_t *)tgtmap;
	*handle = (scsi_hba_tgtmap_t *)tgtmap;

	/*
	 * We have now set tran_tgtmap, marking the tran as using tgtmap
	 * enumeration services.  To prevent the generation of legacy spi
	 * 'binding-set' compatible forms, remove the 'scsi-binding-set'
	 * property.
	 */
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, self,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "scsi-binding-set",
	    &scsi_binding_set) == DDI_PROP_SUCCESS) {
		if (strcmp(scsi_binding_set, scsi_binding_set_spi) == 0)
			(void) ndi_prop_remove(DDI_DEV_T_NONE, self,
			    "scsi-binding-set");
		ddi_prop_free(scsi_binding_set);
	}
	return (DDI_SUCCESS);
}

void
scsi_hba_tgtmap_destroy(scsi_hba_tgtmap_t *handle)
{
	impl_scsi_tgtmap_t	*tgtmap = (impl_scsi_tgtmap_t *)handle;
	dev_info_t		*self = tgtmap->tgtmap_tran->tran_iport_dip;
	int			i;

	for (i = 0; i < SCSI_TGT_NTYPES; i++) {
		if (tgtmap->tgtmap_dam[i]) {
			SCSI_HBA_LOG((_LOGTGT, self, NULL,
			    "%s", damap_name(tgtmap->tgtmap_dam[i])));
			damap_destroy(tgtmap->tgtmap_dam[i]);
		}
	}
	kmem_free(tgtmap, sizeof (*tgtmap));
}

/* return 1 if all maps ended up syned */
static int
scsi_tgtmap_sync(scsi_hba_tgtmap_t *handle, int sync_usec)
{
	impl_scsi_tgtmap_t	*tgtmap = (impl_scsi_tgtmap_t *)handle;
	dev_info_t		*self = tgtmap->tgtmap_tran->tran_iport_dip;
	int			all_synced = 1;
	int			synced;
	int			i;

	for (i = 0; i < SCSI_TGT_NTYPES; i++) {
		if (tgtmap->tgtmap_dam[i]) {
			SCSI_HBA_LOG((_LOGTGT, self, NULL, "%s sync begin",
			    damap_name(tgtmap->tgtmap_dam[i])));
			synced = damap_sync(tgtmap->tgtmap_dam[i], sync_usec);
			all_synced &= synced;
			SCSI_HBA_LOG((_LOGTGT, self, NULL, "%s sync end %d",
			    damap_name(tgtmap->tgtmap_dam[i]), synced));

		}
	}
	return (all_synced);
}

/* return 1 if all maps ended up empty */
static int
scsi_tgtmap_is_empty(scsi_hba_tgtmap_t *handle)
{
	impl_scsi_tgtmap_t	*tgtmap = (impl_scsi_tgtmap_t *)handle;
	dev_info_t		*self = tgtmap->tgtmap_tran->tran_iport_dip;
	int			all_empty = 1;
	int			empty;
	int			i;

	for (i = 0; i < SCSI_TGT_NTYPES; i++) {
		if (tgtmap->tgtmap_dam[i]) {
			empty = damap_is_empty(tgtmap->tgtmap_dam[i]);
			all_empty &= empty;
			SCSI_HBA_LOG((_LOGTGT, self, NULL, "%s is_empty %d",
			    damap_name(tgtmap->tgtmap_dam[i]), empty));
		}
	}

	return (all_empty);
}

static int
scsi_tgtmap_beginf(scsi_hba_tgtmap_t *handle, boolean_t do_begin)
{
	impl_scsi_tgtmap_t	*tgtmap = (impl_scsi_tgtmap_t *)handle;
	dev_info_t		*self = tgtmap->tgtmap_tran->tran_iport_dip;
	char			*context;
	int			rv = DAM_SUCCESS;
	int			i;

	for (i = 0; i < SCSI_TGT_NTYPES; i++) {
		if (tgtmap->tgtmap_dam[i] == NULL) {
			continue;
		}

		context = damap_name(tgtmap->tgtmap_dam[i]);
		if (do_begin == B_TRUE) {
			if (i == SCSI_TGT_SCSI_DEVICE) {
				/*
				 * In scsi_device context, so we have the
				 * 'context' string, diagnose the case where
				 * the tgtmap caller is failing to make
				 * forward progress, i.e. the caller is never
				 * completing an observation by calling
				 * scsi_hbg_tgtmap_set_end. If this occurs,
				 * the solaris target/lun state may be out
				 * of sync with hardware.
				 */
				if (tgtmap->tgtmap_reports++ >=
				    scsi_hba_tgtmap_reports_max) {
					tgtmap->tgtmap_noisy++;
					if (tgtmap->tgtmap_noisy == 1) {
						SCSI_HBA_LOG((_LOG(WARN),
						    self, NULL,
						    "%s: failing tgtmap begin",
						    context));
					}
				}
			}

			rv = damap_addrset_begin(tgtmap->tgtmap_dam[i]);
		} else {
			rv = damap_addrset_flush(tgtmap->tgtmap_dam[i]);
		}

		if (rv != DAM_SUCCESS) {
			SCSI_HBA_LOG((_LOGTGT, self, NULL, "%s FAIL", context));
		} else {
			SCSI_HBA_LOG((_LOGTGT, self, NULL, "%s", context));
		}
	}

	return ((rv == DAM_SUCCESS) ? DDI_SUCCESS : DDI_FAILURE);
}


int
scsi_hba_tgtmap_set_begin(scsi_hba_tgtmap_t *handle)
{
	return (scsi_tgtmap_beginf(handle, B_TRUE));
}

int
scsi_hba_tgtmap_set_flush(scsi_hba_tgtmap_t *handle)
{
	return (scsi_tgtmap_beginf(handle, B_FALSE));
}

int
scsi_hba_tgtmap_set_add(scsi_hba_tgtmap_t *handle,
    scsi_tgtmap_tgt_type_t tgt_type, char *tgt_addr, void *tgt_priv)
{
	impl_scsi_tgtmap_t	*tgtmap = (impl_scsi_tgtmap_t *)handle;
	dev_info_t		*self = tgtmap->tgtmap_tran->tran_iport_dip;

	if (tgt_type >= SCSI_TGT_NTYPES || !tgtmap->tgtmap_dam[tgt_type])
		return (DDI_FAILURE);

	SCSI_HBA_LOG((_LOGTGT, self, NULL,
	    "%s @%s", damap_name(tgtmap->tgtmap_dam[tgt_type]), tgt_addr));

	return ((damap_addrset_add(tgtmap->tgtmap_dam[tgt_type], tgt_addr,
	    NULL, NULL, tgt_priv) == DAM_SUCCESS) ? DDI_SUCCESS : DDI_FAILURE);
}

/*ARGSUSED*/
int
scsi_hba_tgtmap_set_end(scsi_hba_tgtmap_t *handle, uint_t flags)
{
	impl_scsi_tgtmap_t	*tgtmap = (impl_scsi_tgtmap_t *)handle;
	dev_info_t		*self = tgtmap->tgtmap_tran->tran_iport_dip;
	char			*context;
	int			rv = DDI_SUCCESS;
	int			i;

	tgtmap->tgtmap_reports = tgtmap->tgtmap_noisy = 0;

	for (i = 0; i < SCSI_TGT_NTYPES; i++) {
		if (tgtmap->tgtmap_dam[i] == NULL)
			continue;
		context = damap_name(tgtmap->tgtmap_dam[i]);
		if (damap_addrset_end(
		    tgtmap->tgtmap_dam[i], 0) != DAM_SUCCESS) {
			SCSI_HBA_LOG((_LOGTGT, self, NULL, "%s FAIL", context));
			rv = DDI_FAILURE;
			continue;
		}

		SCSI_HBA_LOG((_LOGTGT, self, NULL, "%s", context));
	}
	return (rv);
}

int
scsi_hba_tgtmap_tgt_add(scsi_hba_tgtmap_t *handle,
    scsi_tgtmap_tgt_type_t tgt_type, char *tgt_addr, void *tgt_priv)

{
	impl_scsi_tgtmap_t	*tgtmap = (impl_scsi_tgtmap_t *)handle;
	dev_info_t		*self = tgtmap->tgtmap_tran->tran_iport_dip;

	if (tgt_type >= SCSI_TGT_NTYPES || !tgtmap->tgtmap_dam[tgt_type])
		return (DDI_FAILURE);

	SCSI_HBA_LOG((_LOGTGT, self, NULL,
	    "%s @%s", damap_name(tgtmap->tgtmap_dam[tgt_type]), tgt_addr));

	return ((damap_addr_add(tgtmap->tgtmap_dam[tgt_type], tgt_addr, NULL,
	    NULL, tgt_priv) == DAM_SUCCESS) ? DDI_SUCCESS : DDI_FAILURE);
}

int
scsi_hba_tgtmap_tgt_remove(scsi_hba_tgtmap_t *handle,
    scsi_tgtmap_tgt_type_t tgt_type, char *tgt_addr)
{
	impl_scsi_tgtmap_t	*tgtmap = (impl_scsi_tgtmap_t *)handle;
	dev_info_t		*self = tgtmap->tgtmap_tran->tran_iport_dip;

	if (tgt_type >= SCSI_TGT_NTYPES || !tgtmap->tgtmap_dam[tgt_type])
		return (DDI_FAILURE);

	SCSI_HBA_LOG((_LOGTGT, self, NULL,
	    "%s @%s", damap_name(tgtmap->tgtmap_dam[tgt_type]), tgt_addr));

	return ((damap_addr_del(tgtmap->tgtmap_dam[tgt_type],
	    tgt_addr) == DAM_SUCCESS) ? DDI_SUCCESS : DDI_FAILURE);
}

int
scsi_hba_tgtmap_lookup(scsi_hba_tgtmap_t *handle,
    char *tgt_addr, scsi_tgtmap_tgt_type_t *r_type)
{
	impl_scsi_tgtmap_t	*tgtmap = (impl_scsi_tgtmap_t *)handle;
	dev_info_t		*self = tgtmap->tgtmap_tran->tran_iport_dip;
	damap_id_t		tgtid;
	int			i;

	for (i = 0; i < SCSI_TGT_NTYPES; i++) {
		tgtid = damap_lookup(tgtmap->tgtmap_dam[i], tgt_addr);
		if (tgtid != NODAM) {
			*r_type = i;
			SCSI_HBA_LOG((_LOG(3), self, NULL,
			    "%s @%s found: type %d",
			    damap_name(tgtmap->tgtmap_dam[i]), tgt_addr, i));
			damap_id_rele(tgtmap->tgtmap_dam[i], tgtid);
			return (DDI_SUCCESS);
		}
	}

	SCSI_HBA_LOG((_LOG(3), self, NULL,
	    "%s%d.tgtmap @%s not found",
	    ddi_driver_name(self), ddi_get_instance(self), tgt_addr));
	return (DDI_FAILURE);
}

/*
 * Return the unit-address of an 'iport' node, or NULL for non-iport node.
 */
char *
scsi_hba_iport_unit_address(dev_info_t *self)
{
	/*
	 * NOTE: Since 'self' could be a SCSA iport node or a SCSA HBA node,
	 * we can't use SCSA flavors: the flavor of a SCSA HBA node is not
	 * established/owned by SCSA, it is established by the nexus that
	 * created the SCSA HBA node (PCI) as a child.
	 *
	 * NOTE: If we want to support a node_name other than "iport" for
	 * an iport node then we can add support for a "scsa-iport-node-name"
	 * property on the SCSA HBA node.  A SCSA HBA driver would set this
	 * property on the SCSA HBA node prior to using the iport API.
	 */
	if (strcmp(ddi_node_name(self), "iport") == 0)
		return (ddi_get_name_addr(self));
	else
		return (NULL);
}

/*
 * Define a SCSI initiator port (bus/channel) for an HBA card that needs to
 * support multiple SCSI ports, but only has a single HBA devinfo node. This
 * function should be called from the HBA's attach(9E) implementation (when
 * processing the HBA devinfo node attach) after the number of SCSI ports on
 * the card is known or when the HBA driver DR handler detects a new port.
 * The function returns 0 on failure and 1 on success.
 *
 * The implementation will add the port value into the "scsi-iports" property
 * value maintained on the HBA node as. These properties are used by the generic
 * scsi bus_config implementation to dynamicaly enumerate the specified iport
 * children. The enumeration code will, on demand, create the appropriate
 * iport children with a SCSI_ADDR_PROP_IPORTUA unit address. This node will
 * bind to the same driver as the HBA node itself. This means that an HBA
 * driver that uses iports should expect probe(9E), attach(9E), and detach(9E)
 * calls on the iport children of the HBA.  If configuration for all ports was
 * already done during HBA node attach, the driver should just return
 * DDI_SUCCESS when confronted with an iport node.
 *
 * A maximum of 32 iport ports are supported per HBA devinfo node.
 *
 * A NULL "port" can be used to indicate that the framework should enumerate
 * target children on the HBA node itself, in addition to enumerating target
 * children on any iport nodes declared. There are two reasons that an HBA may
 * wish to have target children enumerated on both the HBA node and iport
 * node(s):
 *
 *   o  If, in the past, HBA hardware had only a single physical port but now
 *      supports multiple physical ports, the updated driver that supports
 *      multiple physical ports may want to avoid /devices path upgrade issues
 *      by enumerating the first physical port under the HBA instead of as a
 *      iport.
 *
 *   o  Some hardware RAID HBA controllers (mlx, chs, etc) support multiple
 *      SCSI physical ports configured so that various physical devices on
 *      the physical ports are amalgamated into virtual devices on a virtual
 *      port.  Amalgamated physical devices no longer appear to the host OS
 *      on the physical ports, but other non-amalgamated devices may still be
 *      visible on the physical ports.  These drivers use a model where the
 *      physical ports are iport nodes and the HBA node is the virtual port to
 *      the configured virtual devices.
 */
int
scsi_hba_iport_register(dev_info_t *self, char *port)
{
	unsigned int ports = 0;
	int rval, i;
	char **iports, **newiports;

	ASSERT(self);
	if (self == NULL)
		return (DDI_FAILURE);

	rval = ddi_prop_lookup_string_array(DDI_DEV_T_ANY, self,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "scsi-iports", &iports,
	    &ports);

	if (ports >= SCSI_HBA_MAX_IPORTS) {
		ddi_prop_free(iports);
		return (DDI_FAILURE);
	}

	if (rval == DDI_PROP_SUCCESS) {
		for (i = 0; i < ports; i++) {
			if (strcmp(port, iports[i]) == 0) {
				/* iport already registered */
				ddi_prop_free(iports);
				return (DDI_SUCCESS);
			}
		}
	}

	newiports = kmem_alloc((sizeof (char *) * (ports + 1)), KM_SLEEP);

	for (i = 0; i < ports; i++) {
		newiports[i] = strdup(iports[i]);
	}
	newiports[ports] = strdup(port);
	ports++;

	if (ddi_prop_update_string_array(DDI_DEV_T_NONE, self,
	    "scsi-iports", newiports, ports) != DDI_PROP_SUCCESS) {
		SCSI_HBA_LOG((_LOG(WARN), self, NULL,
		    "failed to establish %s %s",
		    SCSI_ADDR_PROP_IPORTUA, port));
		rval = DDI_FAILURE;
	} else {
		rval = DDI_SUCCESS;
	}

	/* If there is iport exist, free property */
	if (ports > 1)
		ddi_prop_free(iports);
	for (i = 0; i < ports; i++) {
		strfree(newiports[i]);
	}
	kmem_free(newiports, (sizeof (char *)) * ports);

	return (rval);
}

/*
 * Check if the HBA has any scsi_hba_iport_register()ed children.
 */
int
scsi_hba_iport_exist(dev_info_t *self)
{
	unsigned int ports = 0;
	char **iports;
	int rval;

	rval = ddi_prop_lookup_string_array(DDI_DEV_T_ANY, self,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "scsi-iports", &iports,
	    &ports);

	if (rval != DDI_PROP_SUCCESS)
		return (0);

	/* If there is now at least 1 iport, then iports is valid */
	if (ports > 0) {
		rval = 1;
	} else
		rval = 0;
	ddi_prop_free(iports);

	return (rval);
}

dev_info_t *
scsi_hba_iport_find(dev_info_t *self, char *portnm)
{
	char		*addr = NULL;
	char		**iports;
	unsigned int	num_iports = 0;
	int		rval = DDI_FAILURE;
	int		i = 0;
	dev_info_t	*child = NULL;

	/* check to see if this is an HBA that defined scsi iports */
	rval = ddi_prop_lookup_string_array(DDI_DEV_T_ANY, self,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "scsi-iports", &iports,
	    &num_iports);

	if (rval != DDI_SUCCESS) {
		return (NULL);
	}
	ASSERT(num_iports > 0);

	/* check to see if this port was registered */
	for (i = 0; i < num_iports; i++) {
		if (strcmp(iports[i], portnm) == 0)
			break;
	}

	if (i == num_iports) {
		child = NULL;
		goto out;
	}

	addr = kmem_zalloc(SCSI_MAXNAMELEN, KM_SLEEP);
	(void) snprintf(addr, SCSI_MAXNAMELEN, "iport@%s", portnm);
	rval = ndi_devi_config_one(self, addr, &child, NDI_NO_EVENT);
	kmem_free(addr, SCSI_MAXNAMELEN);

	if (rval != DDI_SUCCESS) {
		child = NULL;
	}
out:
	ddi_prop_free(iports);
	return (child);
}

/*
 * Search/create the specified iport node
 */
static dev_info_t *
scsi_hba_bus_config_port(dev_info_t *self, char *nameaddr, scsi_enum_t se)
{
	dev_info_t	*child;		/* iport child of HBA node */
	scsi_hba_tran_t	*tran;
	char		*addr;
	char		*compat;

	/*
	 * See if the iport node already exists.
	 */
	addr = nameaddr + strlen("iport@");
	if (child = ndi_devi_findchild(self, nameaddr)) {
		if (ndi_devi_device_isremoved(child)) {
			if ((se == SE_HP) || !ndi_dev_is_hotplug_node(child)) {
				if (ndi_devi_device_insert(child))
					SCSI_HBA_LOG((_LOGCFG, self, NULL,
					    "devinfo iport@%s device_reinsert",
					    addr));
			} else
				return (NULL);
		}
		return (child);
	}


	/*
	 * If config based on scsi_hba_iportmap API, only allow create
	 * from hotplug.
	 */
	tran = ndi_flavorv_get(self, SCSA_FLAVOR_SCSI_DEVICE);
	ASSERT(tran);
	if (tran->tran_iportmap && (se != SE_HP))
		return (NULL);

	/* allocate and initialize a new "iport" node */
	ndi_devi_alloc_sleep(self, "iport",
	    (se == SE_HP) ? DEVI_SID_HP_NODEID : DEVI_SID_NODEID,
	    &child);
	ASSERT(child);
	/*
	 * Set the flavor of the child to be IPORT flavored
	 */
	ndi_flavor_set(child, SCSA_FLAVOR_IPORT);

	/*
	 * Add the SCSI_ADDR_PROP_IPORTUA addressing property for this child.
	 * This property is used to identify a iport node, and to represent the
	 * nodes @addr form via node properties.
	 *
	 * Add "compatible" property to the "scsi-iport" node to cause it bind
	 * to the same driver as the HBA  driver. Use the "driver" name
	 * instead of the "binding name" to distinguish from hw node.
	 *
	 * Give the HBA a chance, via tran_set_name_prop, to set additional
	 * iport node properties or to change the "compatible" binding
	 * prior to init_child.
	 *
	 * NOTE: the order of these operations is important so that
	 * scsi_hba_iport works when called.
	 */
	compat = (char *)ddi_driver_name(self);
	if ((ndi_prop_update_string(DDI_DEV_T_NONE, child,
	    SCSI_ADDR_PROP_IPORTUA, addr) != DDI_PROP_SUCCESS) ||
	    (ndi_prop_update_string_array(DDI_DEV_T_NONE, child,
	    "compatible", &compat, 1) != DDI_PROP_SUCCESS) ||
	    ddi_pathname_obp_set(child, NULL) != DDI_SUCCESS) {
		SCSI_HBA_LOG((_LOG_NF(WARN), "%s failed dynamic decoration",
		    nameaddr));
		(void) ddi_remove_child(child, 0);
		child = NULL;
	} else {
		/*
		 * Online/attach in order to get events so devfsadm will
		 * create public names.
		 */
		ndi_hold_devi(child);
		if (ndi_devi_online(child, 0) != NDI_SUCCESS) {
			ndi_rele_devi(child);
			ndi_prop_remove_all(child);
			(void) ndi_devi_free(child);
			child = NULL;
		} else
			ndi_rele_devi(child);
	}

	return (child);
}

#ifdef	sparc
/*
 * Future: When iportmap boot support is added, consider rewriting this to
 * perform a scsi_hba_bus_config(BUS_CONFIG_ALL) on self (HBA) followed by
 * a scsi_hba_bus_config(BUS_CONFIG_ONE) on each child of self (each iport).
 */
/* ARGSUSED */
static int
scsi_hba_bus_config_prom_node(dev_info_t *self, uint_t flags,
    void *arg, dev_info_t **childp)
{
	char		**iports;
	int		circ, i;
	int		ret = NDI_FAILURE;
	unsigned int	num_iports = 0;
	dev_info_t	*pdip = NULL;
	char		*addr = NULL;

	/* check to see if this is an HBA that defined scsi iports */
	ret = ddi_prop_lookup_string_array(DDI_DEV_T_ANY, self,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "scsi-iports", &iports,
	    &num_iports);

	if (ret != DDI_SUCCESS) {
		return (ret);
	}

	ASSERT(num_iports > 0);

	addr = kmem_zalloc(SCSI_MAXNAMELEN, KM_SLEEP);

	ret = NDI_FAILURE;

	scsi_hba_devi_enter(self, &circ);

	/* create iport nodes for each scsi port/bus */
	for (i = 0; i < num_iports; i++) {
		bzero(addr, SCSI_MAXNAMELEN);
		/* Prepend the iport name */
		(void) snprintf(addr, SCSI_MAXNAMELEN, "iport@%s",
		    iports[i]);
		if (pdip = scsi_hba_bus_config_port(self, addr, SE_BUSCONFIG)) {
			if (ndi_busop_bus_config(self, NDI_NO_EVENT,
			    BUS_CONFIG_ONE, addr, &pdip, 0) !=
			    NDI_SUCCESS) {
				continue;
			}
			/*
			 * Try to configure child under iport see wehter
			 * request node is the child of the iport node
			 */
			if (ndi_devi_config_one(pdip, arg, childp,
			    NDI_NO_EVENT) == NDI_SUCCESS) {
				ret = NDI_SUCCESS;
				break;
			}
		}
	}

	scsi_hba_devi_exit(self, circ);

	kmem_free(addr, SCSI_MAXNAMELEN);

	ddi_prop_free(iports);

	return (ret);
}
#endif

/*
 * Perform iport port/bus bus_config.
 */
static int
scsi_hba_bus_config_iports(dev_info_t *self, uint_t flags,
    ddi_bus_config_op_t op, void *arg, dev_info_t **childp)
{
	char		*nameaddr, *addr;
	char		**iports;
	int		circ, i;
	int		ret = NDI_FAILURE;
	unsigned int	num_iports = 0;

	/* check to see if this is an HBA that defined scsi iports */
	ret = ddi_prop_lookup_string_array(DDI_DEV_T_ANY, self,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "scsi-iports", &iports,
	    &num_iports);

	if (ret != DDI_SUCCESS) {
		return (ret);
	}

	ASSERT(num_iports > 0);

	scsi_hba_devi_enter(self, &circ);

	switch (op) {
	case BUS_CONFIG_ONE:
		/* return if this operation is not against an iport node */
		nameaddr = (char *)arg;
		if ((nameaddr == NULL) ||
		    (strncmp(nameaddr, "iport@", strlen("iport@")) != 0)) {
			ret = NDI_FAILURE;
			scsi_hba_devi_exit(self, circ);
			ddi_prop_free(iports);
			return (ret);
		}

		/* parse the port number from "iport@%s" */
		addr = nameaddr + strlen("iport@");

		/* check to see if this port was registered */
		for (i = 0; i < num_iports; i++) {
			if (strcmp((iports[i]), addr) == 0)
				break;
		}

		if (i == num_iports) {
			ret = NDI_FAILURE;
			break;
		}

		/* create the iport node child */
		if (scsi_hba_bus_config_port(self, nameaddr, SE_BUSCONFIG)) {
			ret = NDI_SUCCESS;
		}
		break;

	case BUS_CONFIG_ALL:
	case BUS_CONFIG_DRIVER:
		addr = kmem_zalloc(SCSI_MAXNAMELEN, KM_SLEEP);
		/* create iport nodes for each scsi port/bus */
		for (i = 0; i < num_iports; i++) {
			bzero(addr, SCSI_MAXNAMELEN);
			/* Prepend the iport name */
			(void) snprintf(addr, SCSI_MAXNAMELEN, "iport@%s",
			    iports[i]);
			(void) scsi_hba_bus_config_port(self, addr,
			    SE_BUSCONFIG);
		}

		kmem_free(addr, SCSI_MAXNAMELEN);
		ret = NDI_SUCCESS;
		break;
	}
	if (ret == NDI_SUCCESS) {
#ifdef sparc
		/*
		 * Mask NDI_PROMNAME since PROM doesn't have iport
		 * node at all.
		 */
		flags &= (~NDI_PROMNAME);
#endif
		flags |= NDI_MDI_FALLBACK;	/* devinfo&pathinfo children */
		ret = ndi_busop_bus_config(self, flags, op,
		    arg, childp, 0);
	}
	scsi_hba_devi_exit(self, circ);

	ddi_prop_free(iports);

	return (ret);
}

static int
scsi_iportmap_config(void *arg, damap_t *mapp, damap_id_t tgtid)
{
	dev_info_t	*self = (dev_info_t *)arg;
	int		circ;
	char		nameaddr[SCSI_MAXNAMELEN];
	char		*iport_addr;
	dev_info_t	*childp;

	scsi_hba_devi_enter(self, &circ);

	iport_addr = damap_id2addr(mapp, tgtid);
	SCSI_HBA_LOG((_LOGIPT, self, NULL,
	    "%s @%s", damap_name(mapp), iport_addr));

	(void) snprintf(nameaddr, sizeof (nameaddr), "iport@%s", iport_addr);
	childp = scsi_hba_bus_config_port(self, nameaddr, SE_HP);
	scsi_hba_devi_exit(self, circ);
	return (childp != NULL ? DAM_SUCCESS : DAM_FAILURE);
}

static int
scsi_iportmap_unconfig(void *arg, damap_t *mapp, damap_id_t tgtid)
{
	dev_info_t	*self = arg;
	dev_info_t	*childp;	/* iport child of HBA node */
	int		circ, empty;
	char		*addr;
	char		nameaddr[SCSI_MAXNAMELEN];
	scsi_hba_tran_t	*tran;

	addr = damap_id2addr(mapp, tgtid);
	SCSI_HBA_LOG((_LOGIPT, self, NULL, "%s @%s", damap_name(mapp), addr));

	(void) snprintf(nameaddr, sizeof (nameaddr), "iport@%s", addr);
	scsi_hba_devi_enter(self, &circ);
	if ((childp = ndi_devi_findchild(self, nameaddr)) == NULL) {
		scsi_hba_devi_exit(self, circ);
		return (DAM_FAILURE);
	}

	tran = ddi_get_driver_private(childp);
	ASSERT(tran);

	ndi_hold_devi(childp);
	scsi_hba_devi_exit(self, circ);

	/*
	 * A begin/end (clear) against the iport's
	 * tgtmap will trigger unconfigure of all
	 * targets on the iport.
	 *
	 * Future: This bit of code only works if the
	 * target map reporting style is are full
	 * reports and not per-address. Maybe we
	 * should plan on handling this by
	 * auto-unconfiguration when destroying the
	 * target map(s).
	 */
	(void) scsi_hba_tgtmap_set_begin(tran->tran_tgtmap);
	(void) scsi_hba_tgtmap_set_end(tran->tran_tgtmap, 0);

	/* wait for unconfigure */
	(void) scsi_tgtmap_sync(tran->tran_tgtmap, 0);
	empty = scsi_tgtmap_is_empty(tran->tran_tgtmap);

	scsi_hba_devi_enter(self, &circ);
	ndi_rele_devi(childp);

	/* If begin/end/sync ends in empty map, offline/remove. */
	if (empty) {
		if (ndi_devi_offline(childp,
		    NDI_DEVFS_CLEAN | NDI_DEVI_REMOVE) == DDI_SUCCESS) {
			SCSI_HBA_LOG((_LOGUNCFG, self, NULL,
			    "devinfo iport@%s offlined and removed",
			    addr));
		} else if (ndi_devi_device_remove(childp)) {
			/* Offline/rem failed, note new device_remove */
			SCSI_HBA_LOG((_LOGUNCFG, self, NULL,
			    "devinfo iport@%s offline failed, "
			    "device_remove", addr));
		}
	}
	scsi_hba_devi_exit(self, circ);
	return (empty ? DAM_SUCCESS : DAM_FAILURE);
}


int
scsi_hba_iportmap_create(dev_info_t *self, int csync_usec, int settle_usec,
    scsi_hba_iportmap_t **handle)
{
	scsi_hba_tran_t		*tran;
	damap_t			*mapp;
	char			context[64];
	impl_scsi_iportmap_t	*iportmap;

	if (self == NULL || csync_usec == 0 ||
	    settle_usec == 0 || handle == NULL)
		return (DDI_FAILURE);

	*handle = NULL;

	if (scsi_hba_iport_unit_address(self) != NULL)
		return (DDI_FAILURE);

	tran = (scsi_hba_tran_t *)ddi_get_driver_private(self);
	ASSERT(tran);
	if (tran == NULL)
		return (DDI_FAILURE);

	(void) snprintf(context, sizeof (context), "%s%d.iportmap",
	    ddi_driver_name(self), ddi_get_instance(self));

	if (damap_create(context, DAMAP_REPORT_PERADDR, DAMAP_SERIALCONFIG,
	    settle_usec, NULL, NULL, NULL, self,
	    scsi_iportmap_config, scsi_iportmap_unconfig, &mapp) !=
	    DAM_SUCCESS) {
		return (DDI_FAILURE);
	}
	iportmap = kmem_zalloc(sizeof (*iportmap), KM_SLEEP);
	iportmap->iportmap_hba_dip = self;
	iportmap->iportmap_dam = mapp;

	iportmap->iportmap_create_window = 1;	/* start with window */
	iportmap->iportmap_create_time = ddi_get_lbolt64();
	iportmap->iportmap_create_csync_usec = csync_usec;
	iportmap->iportmap_settle_usec = settle_usec;
	iportmap->iportmap_sync_cnt = 0;

	tran->tran_iportmap = (scsi_hba_iportmap_t *)iportmap;
	*handle = (scsi_hba_iportmap_t *)iportmap;

	SCSI_HBA_LOG((_LOGIPT, self, NULL, "%s", damap_name(mapp)));
	return (DDI_SUCCESS);
}

void
scsi_hba_iportmap_destroy(scsi_hba_iportmap_t *handle)
{
	impl_scsi_iportmap_t	*iportmap = (impl_scsi_iportmap_t *)handle;
	dev_info_t		*self = iportmap->iportmap_hba_dip;

	SCSI_HBA_LOG((_LOGIPT, self, NULL,
	    "%s", damap_name(iportmap->iportmap_dam)));

	damap_destroy(iportmap->iportmap_dam);
	kmem_free(iportmap, sizeof (*iportmap));
}

int
scsi_hba_iportmap_iport_add(scsi_hba_iportmap_t *handle,
    char *iport_addr, void *iport_priv)
{
	impl_scsi_iportmap_t	*iportmap = (impl_scsi_iportmap_t *)handle;
	dev_info_t		*self = iportmap->iportmap_hba_dip;

	SCSI_HBA_LOG((_LOGIPT, self, NULL,
	    "%s @%s", damap_name(iportmap->iportmap_dam), iport_addr));

	return ((damap_addr_add(iportmap->iportmap_dam, iport_addr, NULL,
	    NULL, iport_priv) == DAM_SUCCESS) ? DDI_SUCCESS : DDI_FAILURE);
}

int
scsi_hba_iportmap_iport_remove(scsi_hba_iportmap_t *handle,
    char *iport_addr)
{
	impl_scsi_iportmap_t	*iportmap = (impl_scsi_iportmap_t *)handle;
	dev_info_t		*self = iportmap->iportmap_hba_dip;

	SCSI_HBA_LOG((_LOGIPT, self, NULL,
	    "%s @%s", damap_name(iportmap->iportmap_dam), iport_addr));

	return ((damap_addr_del(iportmap->iportmap_dam,
	    iport_addr) == DAM_SUCCESS) ? DDI_SUCCESS : DDI_FAILURE);
}

int
scsi_hba_iportmap_lookup(scsi_hba_iportmap_t *handle,
    char *iport_addr)
{
	impl_scsi_iportmap_t	*iportmap = (impl_scsi_iportmap_t *)handle;
	dev_info_t		*self = iportmap->iportmap_hba_dip;
	damap_id_t		iportid;

	iportid = damap_lookup(iportmap->iportmap_dam, iport_addr);
	if (iportid != NODAM) {
		SCSI_HBA_LOG((_LOG(3), self, NULL,
		    "%s @%s found",
		    damap_name(iportmap->iportmap_dam), iport_addr));
		damap_id_rele(iportmap->iportmap_dam, iportid);
		return (DDI_SUCCESS);
	}

	SCSI_HBA_LOG((_LOG(3), self, NULL,
	    "%s @%s not found",
	    damap_name(iportmap->iportmap_dam), iport_addr));
	return (DDI_FAILURE);
}


static int
scsi_lunmap_config(void *arg, damap_t *lundam, damap_id_t lunid)
{
	impl_scsi_tgtmap_t	*tgtmap = (impl_scsi_tgtmap_t *)arg;
	scsi_hba_tran_t		*tran = tgtmap->tgtmap_tran;
	dev_info_t		*self = tran->tran_iport_dip;
	char			*addr;

	addr = damap_id2addr(lundam, lunid);
	SCSI_HBA_LOG((_LOGLUN, self, NULL,
	    "%s @%s", damap_name(lundam), addr));
	if (scsi_hba_bus_configone_addr(self, addr, SE_HP) != NULL)
		return (DAM_SUCCESS);
	else
		return (DAM_FAILURE);
}

static int
scsi_lunmap_unconfig(void *arg, damap_t *lundam, damap_id_t lunid)
{
	impl_scsi_tgtmap_t	*tgtmap = (impl_scsi_tgtmap_t *)arg;
	scsi_hba_tran_t		*tran = tgtmap->tgtmap_tran;
	dev_info_t		*self = tran->tran_iport_dip;
	char			*addr;

	addr = damap_id2addr(lundam, lunid);
	SCSI_HBA_LOG((_LOGLUN, self, NULL, "%s @%s", damap_name(lundam),
	    addr));

	scsi_hba_bus_unconfigone_addr(self, addr);
	return (DAM_SUCCESS);
}

static int
scsi_lunmap_create(dev_info_t *self, impl_scsi_tgtmap_t *tgtmap, char *taddr)
{
	char			context[64];
	damap_t			*tgtdam;
	damap_id_t		tgtid;
	damap_t			*lundam;
	int			optflags;

	(void) snprintf(context, sizeof (context), "%s%d.%s.lunmap",
	    ddi_driver_name(self), ddi_get_instance(self), taddr);

	tgtdam = tgtmap->tgtmap_dam[SCSI_TGT_SCSI_DEVICE];
	tgtid = damap_lookup(tgtdam, taddr);
	if (tgtid == NODAM) {
		SCSI_HBA_LOG((_LOG(1), self, NULL,
		    "target %s not found", context));
		return (DDI_FAILURE);
	}

	lundam = damap_id_priv_get(tgtdam, tgtid);
	if (lundam) {
		SCSI_HBA_LOG((_LOG(1), self, NULL,
		    "lunmap %s already created", context));
		damap_id_rele(tgtdam, tgtid);
		return (DDI_FAILURE);
	}

	optflags = (ddi_prop_get_int(DDI_DEV_T_ANY, self,
	    DDI_PROP_NOTPROM | DDI_PROP_DONTPASS, "scsi-enumeration",
	    scsi_enumeration) & SCSI_ENUMERATION_MT_LUN_DISABLE) ?
	    DAMAP_SERIALCONFIG : DAMAP_MTCONFIG;

	/* NOTE: expected ref at tgtid/taddr: 2: caller + lookup. */
	ASSERT(damap_id_ref(tgtdam, tgtid) == 2);
	SCSI_HBA_LOG((_LOGLUN, self, NULL, "%s creat, id %d ref %d",
	    context, tgtid, damap_id_ref(tgtdam, tgtid)));

	/* create lundam */
	if (damap_create(context, DAMAP_REPORT_FULLSET, optflags, 1,
	    NULL, NULL, NULL, tgtmap, scsi_lunmap_config, scsi_lunmap_unconfig,
	    &lundam) != DAM_SUCCESS) {
		SCSI_HBA_LOG((_LOG(1), self, NULL,
		    "%s create failed, id %d ref %d",
		    context, tgtid, damap_id_ref(tgtdam, tgtid)));
		damap_id_rele(tgtdam, tgtid);
		return (DDI_FAILURE);
	}

	/*
	 * Return with damap_id_hold at tgtid/taddr from damap_lookup to
	 * account for damap_id_prv_set below.
	 */
	damap_id_priv_set(tgtdam, tgtid, lundam);
	return (DDI_SUCCESS);
}

static void
scsi_lunmap_destroy(dev_info_t *self, impl_scsi_tgtmap_t *tgtmap, char *taddr)
{
	char			context[64];
	damap_t			*tgtdam;
	damap_id_t		tgtid;
	damap_t			*lundam;

	(void) snprintf(context, sizeof (context), "%s%d.%s.lunmap",
	    ddi_driver_name(self), ddi_get_instance(self), taddr);

	tgtdam = tgtmap->tgtmap_dam[SCSI_TGT_SCSI_DEVICE];
	tgtid = damap_lookup(tgtdam, taddr);
	if (tgtid == NODAM) {
		SCSI_HBA_LOG((_LOG(1), self, NULL,
		    "target %s not found", context));
		return;
	}

	lundam = (damap_t *)damap_id_priv_get(tgtdam, tgtid);
	if (lundam == NULL) {
		damap_id_rele(tgtdam, tgtid);		/* from damap_lookup */
		SCSI_HBA_LOG((_LOG(1), self, NULL,
		    "lunmap %s already destroyed", context));
		return;
	}

	/* NOTE: expected ref at tgtid/taddr: 3: priv_set + caller + lookup. */
	ASSERT(damap_id_ref(tgtdam, tgtid) == 3);
	SCSI_HBA_LOG((_LOGLUN, self, NULL, "%s, id %d ref %d",
	    damap_name(lundam), tgtid, damap_id_ref(tgtdam, tgtid)));

	/*
	 * A begin/end (clear) against a target's lunmap will trigger
	 * unconfigure of all LUNs on the target.
	 */
	scsi_lunmap_set_begin(self, lundam);
	scsi_lunmap_set_end(self, lundam);

	SCSI_HBA_LOG((_LOGLUN, self, NULL,
	    "%s sync begin", damap_name(lundam)));

	(void) damap_sync(lundam, 0);	/* wait for unconfigure */

	SCSI_HBA_LOG((_LOGLUN, self, NULL,
	    "%s sync end", damap_name(lundam)));

	damap_id_priv_set(tgtdam, tgtid, NULL);

	/* release hold established by damap_lookup above */
	damap_id_rele(tgtdam, tgtid);

	/* release hold established since scsi_lunmap_create() */
	damap_id_rele(tgtdam, tgtid);

	damap_destroy(lundam);
}

static void
scsi_lunmap_set_begin(dev_info_t *self, damap_t *lundam)
{
	SCSI_HBA_LOG((_LOGLUN, self, NULL, "%s", damap_name(lundam)));

	(void) damap_addrset_begin(lundam);
}

static int
scsi_lunmap_set_add(dev_info_t *self, damap_t *lundam,
    char *taddr, scsi_lun64_t lun64, int sfunc)
{
	char	ua[SCSI_MAXNAMELEN];

	/* make unit address string form of "@taddr,lun[,sfunc]" */
	if (sfunc == -1)
		(void) snprintf(ua, sizeof (ua), "%s,%" PRIx64, taddr, lun64);
	else
		(void) snprintf(ua, sizeof (ua), "%s,%" PRIx64 ",%x",
		    taddr, lun64, sfunc);

	SCSI_HBA_LOG((_LOGLUN, self, NULL, "%s @%s", damap_name(lundam), ua));

	return ((damap_addrset_add(lundam, ua, NULL, NULL,
	    NULL) == DAM_SUCCESS) ? DDI_SUCCESS : DDI_FAILURE);
}

static void
scsi_lunmap_set_end(dev_info_t *self, damap_t *lundam)
{
	SCSI_HBA_LOG((_LOGLUN, self, NULL, "%s", damap_name(lundam)));

	(void) damap_addrset_end(lundam, 0);
}

int
scsi_lunmap_lookup(dev_info_t *self, damap_t *lundam, char *addr)
{
	damap_id_t		lunid;

	if ((lunid = damap_lookup(lundam, addr)) != NODAM) {
		SCSI_HBA_LOG((_LOG(3), self, NULL,
		    "%s @%s found", damap_name(lundam), addr));
		damap_id_rele(lundam, lunid);
		return (DDI_SUCCESS);
	}

	SCSI_HBA_LOG((_LOG(3), self, NULL,
	    "%s @%s not found", damap_name(lundam), addr));
	return (DDI_FAILURE);
}

/*
 * phymap implementation
 *
 * We manage the timed aggregation of phys into a phy map * by creating a
 * SAS port construct (based upon 'name' of "local,remote" SAS addresses)
 * upon the first link up. As time goes on additional phys may join that port.
 * After an appropriate amount of settle time, we trigger the activation
 * callback which will then take the resultant bit mask of phys (phymask) in
 * the SAS port and use that to call back to the callback function
 * provided by the additional caller.
 *
 * We cross check to make sure that phys only exist in one SAS port at a
 * time by having soft state for each phy point back to the created
 * SAS port.
 *
 * NOTE: Make SAS_PHY_UA_LEN max(SAS_PHY_PHYMASK_LEN, SAS_PHY_NAME_LEN)
 * so we have enough space if sas_phymap_bitset2phymaskua phymask address
 * is already in use, and we end up using port name as unit address.
 */
#define	SAS_PHY_NAME_FMT	"%" PRIx64 ",%" PRIx64
#define	SAS_PHY_NAME_LEN	(16 + 1 + 16 + 1)
#define	SAS_PHY_NPHY		(SAS2_PHYNUM_MAX + 1)
#define	SAS_PHY_PHYMASK_LEN	((roundup(SAS_PHY_NPHY, 4)) / 4)
#if	(SAS_PHY_PHYMASK_LEN > SAS_PHY_NAME_LEN)
#define	SAS_PHY_UA_LEN		SAS_PHY_PHYMASK_LEN
#else
#define	SAS_PHY_UA_LEN		SAS_PHY_NAME_LEN
#endif
typedef struct impl_sas_physet {	/* needed for name2phys destroy */
	struct impl_sas_physet		*physet_next;
	char				*physet_name;
	bitset_t			*physet_phys;
} impl_sas_physet_t;
typedef struct impl_sas_phymap {
	dev_info_t			*phymap_self;

	kmutex_t			phymap_lock;
	damap_t				*phymap_dam;
	void				*phymap_phy2name;
	ddi_soft_state_bystr		*phymap_name2phys;	/* bitset */
	ddi_soft_state_bystr		*phymap_name2ua;
	ddi_soft_state_bystr		*phymap_ua2name;

	/* Noisy phy information - ensure forward progress for noisy phys */
	int				phymap_phy_max;		/* max phy# */
	int				phymap_reports;		/* per period */
	int				phymap_reports_max;	/* scales */
	int				phymap_phys_noisy;	/* detected */

	/* These are for callbacks to the consumer. */
	sas_phymap_activate_cb_t	phymap_acp;
	sas_phymap_deactivate_cb_t	phymap_dcp;
	void				*phymap_private;

	struct impl_sas_physet		*phymap_physets;
} impl_sas_phymap_t;

/* Detect noisy phy: max changes per stabilization period per phy. */
static int sas_phymap_phy_max_factor = 16;

/*
 * Convert bitset into a unit-address string. The maximum string length would
 * be the maximum number of phys, rounded up by 4 and divided by 4.
 */
static void
sas_phymap_bitset2phymaskua(bitset_t *phys, char *buf)
{
	char			*ptr;
	int			grp;
	int			cur;
	uint_t			bit;

	bit = roundup(SAS_PHY_NPHY, 4);
	grp = 4;
	ptr = buf;
	cur = 0;
	do {
		bit -= 1;
		grp -= 1;
		if (bitset_in_set(phys, bit)) {
			cur |= (1 << grp);
		}
		if (grp == 0) {
			grp = 4;
			if (cur || ptr != buf) {
				*ptr++ = "0123456789abcdef"[cur];
				*ptr = 0;
			}
			cur = 0;
		}
	} while (bit != 0);
	if (ptr == buf) {
		*ptr++ = '0';
		*ptr = 0;
	}
}

static int
sas_phymap_config(void *arg, damap_t *phydam, damap_id_t phyid)
{
	impl_sas_phymap_t	*phymap = (impl_sas_phymap_t *)arg;
	char			*context = damap_name(phymap->phymap_dam);
	char			*damn;
	char			*name;
	bitset_t		*phys;
	char			*ua;
	void			*ua_priv;

	ASSERT(context);

	mutex_enter(&phymap->phymap_lock);
	phymap->phymap_reports = phymap->phymap_phys_noisy = 0;

	/* Get the name ("local,remote" address string) from damap. */
	damn = damap_id2addr(phydam, phyid);

	/* Get the bitset of phys currently forming the port. */
	phys = ddi_soft_state_bystr_get(phymap->phymap_name2phys, damn);
	if (phys == NULL) {
		SCSI_HBA_LOG((_LOG_NF(WARN), "%s: %s: no phys",
		    context, damn));
		mutex_exit(&phymap->phymap_lock);
		return (DAM_FAILURE);
	}

	/* allocate, get, and initialize name index of name2ua map */
	if (ddi_soft_state_bystr_zalloc(phymap->phymap_name2ua, damn) !=
	    DDI_SUCCESS) {
		SCSI_HBA_LOG((_LOG_NF(WARN),
		    "%s: %s: failed name2ua alloc", context, damn));
		mutex_exit(&phymap->phymap_lock);
		return (DAM_FAILURE);
	}
	if (!(ua = ddi_soft_state_bystr_get(phymap->phymap_name2ua, damn))) {
		SCSI_HBA_LOG((_LOG_NF(WARN),
		    "%s: %s: no name2ua", context, damn));
		mutex_exit(&phymap->phymap_lock);
		return (DAM_FAILURE);
	}
	sas_phymap_bitset2phymaskua(phys, ua);		/* set ua */

	/* see if phymask ua index already allocated in ua2name map */
	if (name = ddi_soft_state_bystr_get(phymap->phymap_ua2name, ua)) {
		/*
		 * The 'phymask' sas_phymap_bitset2phymaskua ua is
		 * already in use. This means that original phys have
		 * formed into a new port, and that the original port
		 * still exists (it has migrated to some completely
		 * different set of phys). In this corner-case we use
		 * "local,remote" name as a 'temporary' unit address.
		 * Reset ua in name2ua map.
		 */
		(void) strlcpy(ua, damn, SAS_PHY_NAME_LEN);
		name = ddi_soft_state_bystr_get(phymap->phymap_ua2name, ua);
		if (name) {
			/* The "local,remote" ua should be new... */
			SCSI_HBA_LOG((_LOG_NF(WARN),
			    "%s: %s ua already configured",
			    context, ua));
			mutex_exit(&phymap->phymap_lock);
			return (DAM_SUCCESS);
		}
	}

	/* allocate, get, and init ua index of ua2name map */
	if (ddi_soft_state_bystr_zalloc(phymap->phymap_ua2name, ua) !=
	    DDI_SUCCESS) {
		ddi_soft_state_bystr_free(phymap->phymap_name2ua, damn);
		SCSI_HBA_LOG((_LOG_NF(WARN), "%s: %s: failed ua2name alloc",
		    context, damn));
		mutex_exit(&phymap->phymap_lock);
		return (DAM_FAILURE);
	}
	name = ddi_soft_state_bystr_get(phymap->phymap_ua2name, ua);
	if (name == NULL) {
		ddi_soft_state_bystr_free(phymap->phymap_name2ua, damn);
		SCSI_HBA_LOG((_LOG_NF(WARN),
		    "%s: %s: no ua2name", context, ua));
		mutex_exit(&phymap->phymap_lock);
		return (DAM_FAILURE);
	}

	/* set name in ua2name map */
	(void) strlcpy(name, damn, SAS_PHY_NAME_LEN);

	SCSI_HBA_LOG((_LOGPHY, phymap->phymap_self, NULL,
	    "%s: %s: ua %s: activate", context, damn, ua));

	if (phymap->phymap_acp) {
		/*
		 * drop our lock and invoke the activation callback
		 */
		mutex_exit(&phymap->phymap_lock);
		ua_priv = NULL;
		(phymap->phymap_acp)(phymap->phymap_private, ua, &ua_priv);
		mutex_enter(&phymap->phymap_lock);
		damap_id_priv_set(phydam, phyid, ua_priv);
	}
	SCSI_HBA_LOG((_LOGPHY, phymap->phymap_self, NULL,
	    "%s: %s: ua %s: activate complete", context, damn, ua));
	mutex_exit(&phymap->phymap_lock);
	return (DAM_SUCCESS);
}

/*ARGSUSED*/
static int
sas_phymap_unconfig(void *arg, damap_t *phydam, damap_id_t phyid)
{
	impl_sas_phymap_t	*phymap = (impl_sas_phymap_t *)arg;
	char			*context = damap_name(phymap->phymap_dam);
	char			*damn;
	char			*ua;
	void			*ua_priv;

	ASSERT(context);

	mutex_enter(&phymap->phymap_lock);
	phymap->phymap_reports = phymap->phymap_phys_noisy = 0;

	/* Get the name ("local,remote" address string) from damap. */
	damn = damap_id2addr(phydam, phyid);

	if (!(ua = ddi_soft_state_bystr_get(phymap->phymap_name2ua, damn))) {
		SCSI_HBA_LOG((_LOG_NF(WARN),
		    "%s: %s: no name2ua", context, damn));
		mutex_exit(&phymap->phymap_lock);
		return (DAM_FAILURE);
	}

	SCSI_HBA_LOG((_LOGPHY, phymap->phymap_self, NULL,
	    "%s: %s: ua %s: deactivate", context, damn, ua));
	if (phymap->phymap_dcp) {
		ua_priv = damap_id_priv_get(phydam, phyid);
		mutex_exit(&phymap->phymap_lock);
		(phymap->phymap_dcp)(phymap->phymap_private, ua, ua_priv);
		mutex_enter(&phymap->phymap_lock);
	}
	SCSI_HBA_LOG((_LOGPHY, phymap->phymap_self, NULL,
	    "%s: %s: ua %s: deactivate complete", context, damn, ua));

	/* delete ua<->name mappings */
	ddi_soft_state_bystr_free(phymap->phymap_ua2name, ua);
	ddi_soft_state_bystr_free(phymap->phymap_name2ua, damn);
	mutex_exit(&phymap->phymap_lock);
	return (DAM_SUCCESS);
}

int
sas_phymap_create(dev_info_t *self, int settle_usec,
    sas_phymap_mode_t mode, void *mode_argument, void *phymap_priv,
    sas_phymap_activate_cb_t  activate_cb,
    sas_phymap_deactivate_cb_t deactivate_cb,
    sas_phymap_t **handlep)
{
	_NOTE(ARGUNUSED(mode_argument));
	char			context[64];
	impl_sas_phymap_t	*phymap;

	if (self == NULL || settle_usec == 0 || handlep == NULL)
		return (DDI_FAILURE);

	if (mode != PHYMAP_MODE_SIMPLE)
		return (DDI_FAILURE);

	phymap = kmem_zalloc(sizeof (*phymap), KM_SLEEP);
	phymap->phymap_self = self;
	phymap->phymap_reports_max = 1 * sas_phymap_phy_max_factor;
	phymap->phymap_acp = activate_cb;
	phymap->phymap_dcp = deactivate_cb;
	phymap->phymap_private = phymap_priv;
	mutex_init(&phymap->phymap_lock, NULL, MUTEX_DRIVER, NULL);

	(void) snprintf(context, sizeof (context), "%s%d.phymap",
	    ddi_driver_name(self), ddi_get_instance(self));
	SCSI_HBA_LOG((_LOGPHY, self, NULL, "%s", context));

	if (ddi_soft_state_init(&phymap->phymap_phy2name,
	    SAS_PHY_NAME_LEN, SAS_PHY_NPHY) != 0)
		goto fail;
	if (ddi_soft_state_bystr_init(&phymap->phymap_name2phys,
	    sizeof (bitset_t), SAS_PHY_NPHY) != 0)
		goto fail;

	if (ddi_soft_state_bystr_init(&phymap->phymap_name2ua,
	    SAS_PHY_UA_LEN, SAS_PHY_NPHY) != 0)
		goto fail;
	if (ddi_soft_state_bystr_init(&phymap->phymap_ua2name,
	    SAS_PHY_NAME_LEN, SAS_PHY_NPHY) != 0)
		goto fail;

	if (damap_create(context, DAMAP_REPORT_PERADDR, DAMAP_SERIALCONFIG,
	    settle_usec, NULL, NULL, NULL,
	    phymap, sas_phymap_config, sas_phymap_unconfig,
	    &phymap->phymap_dam) != DAM_SUCCESS)
		goto fail;


	*handlep = (sas_phymap_t *)phymap;
	return (DDI_SUCCESS);

fail:	sas_phymap_destroy((sas_phymap_t *)phymap);
	*handlep = NULL;
	return (DDI_FAILURE);
}

void
sas_phymap_destroy(sas_phymap_t *handle)
{
	impl_sas_phymap_t	*phymap = (impl_sas_phymap_t *)handle;
	char			*context;
	struct impl_sas_physet	*physet, *nphyset;
	bitset_t		*phys;
	char			*name;

	context = phymap->phymap_dam ?
	    damap_name(phymap->phymap_dam) : "unknown";
	SCSI_HBA_LOG((_LOGPHY, phymap->phymap_self, NULL, "%s", context));

	if (phymap->phymap_dam)
		damap_destroy(phymap->phymap_dam);

	/* free the bitsets of allocated physets */
	for (physet = phymap->phymap_physets; physet; physet = nphyset) {
		nphyset = physet->physet_next;
		phys = physet->physet_phys;
		name = physet->physet_name;

		if (phys)
			bitset_fini(phys);
		if (name) {
			ddi_soft_state_bystr_free(
			    phymap->phymap_name2phys, name);
			strfree(name);
		}
		kmem_free(physet, sizeof (*physet));
	}

	/* free the maps */
	if (phymap->phymap_ua2name)
		ddi_soft_state_bystr_fini(&phymap->phymap_ua2name);
	if (phymap->phymap_name2ua)
		ddi_soft_state_bystr_fini(&phymap->phymap_name2ua);

	if (phymap->phymap_name2phys)
		ddi_soft_state_bystr_fini(&phymap->phymap_name2phys);
	if (phymap->phymap_phy2name)
		ddi_soft_state_fini(&phymap->phymap_phy2name);

	mutex_destroy(&phymap->phymap_lock);
	kmem_free(phymap, sizeof (*phymap));
}


int
sas_phymap_phy_add(sas_phymap_t *handle,
    int phy, uint64_t local, uint64_t remote)
{
	impl_sas_phymap_t	*phymap = (impl_sas_phymap_t *)handle;
	char			*context = damap_name(phymap->phymap_dam);
	char			port[SAS_PHY_NAME_LEN];
	char			*name;
	int			phy2name_allocated = 0;
	bitset_t		*phys;
	struct impl_sas_physet	*physet;
	int			rv;

	/* Create the SAS port name from the local and remote addresses. */
	(void) snprintf(port, SAS_PHY_NAME_LEN, SAS_PHY_NAME_FMT,
	    local, remote);

	mutex_enter(&phymap->phymap_lock);
	SCSI_HBA_LOG((_LOGPHY, phymap->phymap_self, NULL, "%s: %s: add phy %d",
	    context, port, phy));

	/* Check for conflict in phy2name map */
	name = ddi_get_soft_state(phymap->phymap_phy2name, phy);
	if (name) {
		if (strcmp(name, port) != 0)
			SCSI_HBA_LOG((_LOG_NF(WARN), "%s: %s: add phy %d: "
			    "already in %s", context, port, phy, name));
		else
			SCSI_HBA_LOG((_LOG_NF(WARN), "%s: %s: add phy %d: "
			    "duplicate add", context, port, phy));
		mutex_exit(&phymap->phymap_lock);
		return (DDI_FAILURE);
	}

	/* allocate, get, and initialize phy index of phy2name map */
	if (ddi_soft_state_zalloc(
	    phymap->phymap_phy2name, phy) != DDI_SUCCESS) {
		SCSI_HBA_LOG((_LOG_NF(WARN),
		    "%s: %s: failed phy2name alloc", context, port));
		goto fail;
	}
	name = ddi_get_soft_state(phymap->phymap_phy2name, phy);
	if (name == NULL) {
		SCSI_HBA_LOG((_LOG_NF(WARN),
		    "%s: %s: no phy2name", context, port));
		goto fail;
	}
	phy2name_allocated = 1;
	(void) strlcpy(name, port, SAS_PHY_NAME_LEN);	/* set name */

	/* Find/alloc, initialize name index of name2phys map */
	phys = ddi_soft_state_bystr_get(phymap->phymap_name2phys, name);
	if (phys == NULL) {
		if (ddi_soft_state_bystr_zalloc(phymap->phymap_name2phys,
		    name) != DDI_SUCCESS) {
			SCSI_HBA_LOG((_LOG_NF(WARN),
			    "%s: %s: failed name2phys alloc", context, name));
			goto fail;
		}
		phys = ddi_soft_state_bystr_get(phymap->phymap_name2phys, name);
		if (phys == NULL) {
			SCSI_HBA_LOG((_LOG_NF(WARN),
			    "%s: %s: no name2phys", context, name));
			goto fail;
		}

		/* Initialize bitset of phys. */
		bitset_init(phys);
		bitset_resize(phys, SAS_PHY_NPHY);

		/* Keep a list of information for destroy. */
		physet = kmem_zalloc(sizeof (*physet), KM_SLEEP);
		physet->physet_name = strdup(name);
		physet->physet_phys = phys;
		physet->physet_next = phymap->phymap_physets;
		phymap->phymap_physets = physet;
	}
	ASSERT(phys);

	/* Reflect 'add' in phys bitset. */
	if (bitset_atomic_test_and_add(phys, phy) < 0) {
		/* It is an error if the phy was already recorded. */
		SCSI_HBA_LOG((_LOG_NF(WARN),
		    "%s: %s: phy bit %d already in port", context, name, phy));
		goto fail;
	}

	/*
	 * Check to see if we have a new phy_max for this map, and if so
	 * scale phymap_reports_max to the new number of phys.
	 */
	if (phy > phymap->phymap_phy_max) {
		phymap->phymap_phy_max = phy + 1;
		phymap->phymap_reports_max = phymap->phymap_phy_max *
		    sas_phymap_phy_max_factor;
	}

	/*
	 * If we have not reached phymap_reports_max, start/restart the
	 * activate timer. Otherwise, if phymap->phymap_reports add/rem reports
	 * ever exceeds phymap_reports_max due to noisy phys, then report the
	 * noise and force stabilization by stopping reports into the damap.
	 *
	 * The first config/unconfig callout out of the damap will reset
	 * phymap->phymap_reports.
	 */
	rv = DDI_SUCCESS;
	if (phymap->phymap_reports++ < phymap->phymap_reports_max) {
		if (damap_addr_add(phymap->phymap_dam, name,
		    NULL, NULL, NULL) == DAM_SUCCESS) {
			SCSI_HBA_LOG((_LOGPHY, phymap->phymap_self, NULL,
			    "%s: %s: damap_addr_add", context, name));
		} else {
			SCSI_HBA_LOG((_LOG_NF(WARN),
			    "%s: %s: damap_addr_add failed", context, name));
			rv = DDI_FAILURE;
		}
	} else {
		phymap->phymap_phys_noisy++;
		if (phymap->phymap_phys_noisy == 1)
			SCSI_HBA_LOG((_LOG_NF(WARN),
			    "%s: %s: noisy phys", context, name));
	}
	mutex_exit(&phymap->phymap_lock);
	return (rv);

fail:	if (phy2name_allocated)
		ddi_soft_state_free(phymap->phymap_phy2name, phy);
	mutex_exit(&phymap->phymap_lock);
	return (DDI_FAILURE);
}

int
sas_phymap_phy_rem(sas_phymap_t *handle, int phy)
{
	impl_sas_phymap_t	*phymap = (impl_sas_phymap_t *)handle;
	char			*context = damap_name(phymap->phymap_dam);
	char			*name;
	bitset_t		*phys;
	int			rv = DDI_FAILURE;

	ASSERT(context);

	mutex_enter(&phymap->phymap_lock);
	phymap->phymap_reports++;

	/* Find and free phy index of phy2name map */
	name = ddi_get_soft_state(phymap->phymap_phy2name, phy);
	if (name == NULL) {
		SCSI_HBA_LOG((_LOG_NF(WARN), "%s: rem phy %d: never added",
		    context, phy));
		goto fail;
	}
	/* NOTE: always free phy index of phy2name map before return... */

	SCSI_HBA_LOG((_LOGPHY, phymap->phymap_self, NULL, "%s: %s: rem phy %d",
	    context, name, phy));

	/* Get bitset of phys currently associated with named port. */
	phys = ddi_soft_state_bystr_get(phymap->phymap_name2phys, name);
	if (phys == NULL) {
		SCSI_HBA_LOG((_LOG_NF(WARN), "%s: %s: name2phys failed",
		    context, name));
		goto fail;
	}

	/* Reflect 'rem' in phys bitset. */
	if (bitset_atomic_test_and_del(phys, phy) < 0) {
		/* It is an error if the phy wasn't one of the port's phys. */
		SCSI_HBA_LOG((_LOG_NF(WARN),
		    "%s: %s: phy bit %d not in port", context, name, phy));
		goto fail;
	}

	/* If this was the last phy in the port, start the deactivate timer. */
	if (bitset_is_null(phys) &&
	    (phymap->phymap_reports++ < phymap->phymap_reports_max)) {
		if (damap_addr_del(phymap->phymap_dam, name) == DAM_SUCCESS) {
			SCSI_HBA_LOG((_LOGPHY, phymap->phymap_self, NULL,
			    "%s: %s: damap_addr_del", context, name));
		} else {
			SCSI_HBA_LOG((_LOG_NF(WARN),
			    "%s: %s: damap_addr_del failure", context, name));
			goto fail;
		}
	}
	rv = DDI_SUCCESS;

	/* free phy index of phy2name map */
fail:	if (name)
		ddi_soft_state_free(phymap->phymap_phy2name, phy); /* free */
	mutex_exit(&phymap->phymap_lock);
	return (rv);
}

char *
sas_phymap_lookup_ua(sas_phymap_t *handle, uint64_t local, uint64_t remote)
{
	impl_sas_phymap_t	*phymap = (impl_sas_phymap_t *)handle;
	char			*context = damap_name(phymap->phymap_dam);
	char			name[SAS_PHY_NAME_LEN];
	char			*ua;

	ASSERT(context);

	(void) snprintf(name, SAS_PHY_NAME_LEN, SAS_PHY_NAME_FMT,
	    local, remote);

	mutex_enter(&phymap->phymap_lock);
	ua = ddi_soft_state_bystr_get(phymap->phymap_name2ua, name);
	SCSI_HBA_LOG((_LOG(3), phymap->phymap_self, NULL,
	    "%s: %s: ua %s", context, name, ua ? ua : "NULL"));
	mutex_exit(&phymap->phymap_lock);
	return (ua);
}

void *
sas_phymap_lookup_uapriv(sas_phymap_t *handle, char *ua)
{
	impl_sas_phymap_t	*phymap = (impl_sas_phymap_t *)handle;
	char			*context = damap_name(phymap->phymap_dam);
	char			*name;
	damap_id_t		phyid;
	void			*ua_priv = NULL;

	ASSERT(context);

	mutex_enter(&phymap->phymap_lock);
	name = ddi_soft_state_bystr_get(phymap->phymap_ua2name, ua);
	if (name) {
		phyid = damap_lookup(phymap->phymap_dam, name);
		if (phyid != NODAM) {
			ua_priv = damap_id_priv_get(phymap->phymap_dam, phyid);
			damap_id_rele(phymap->phymap_dam, phyid);
		}
	}

	SCSI_HBA_LOG((_LOG(3), phymap->phymap_self, NULL,
	    "%s: %s: ua %s ua_priv %p", context, name,
	    ua ? ua : "NULL", ua_priv));
	mutex_exit(&phymap->phymap_lock);
	return (ua_priv);
}

int
sas_phymap_uahasphys(sas_phymap_t *handle, char *ua)
{
	impl_sas_phymap_t	*phymap = (impl_sas_phymap_t *)handle;
	char			*name;
	bitset_t		*phys;
	int			n = 0;

	mutex_enter(&phymap->phymap_lock);
	name = ddi_soft_state_bystr_get(phymap->phymap_ua2name, ua);
	if (name) {
		phys = ddi_soft_state_bystr_get(phymap->phymap_name2phys, name);
		if (phys)
			n = bitset_is_null(phys) ? 0 : 1;
	}
	mutex_exit(&phymap->phymap_lock);
	return (n);
}

sas_phymap_phys_t *
sas_phymap_ua2phys(sas_phymap_t *handle, char *ua)
{
	impl_sas_phymap_t	*phymap = (impl_sas_phymap_t *)handle;
	char			*name;
	bitset_t		*phys;
	bitset_t		*cphys = NULL;

	mutex_enter(&phymap->phymap_lock);
	name = ddi_soft_state_bystr_get(phymap->phymap_ua2name, ua);
	if (name == NULL)
		goto fail;

	phys = ddi_soft_state_bystr_get(phymap->phymap_name2phys, name);
	if (phys == NULL)
		goto fail;

	/* dup the phys and return */
	cphys = kmem_alloc(sizeof (*cphys), KM_SLEEP);
	bitset_init(cphys);
	bitset_resize(cphys, SAS_PHY_NPHY);
	bitset_copy(phys, cphys);

fail:	mutex_exit(&phymap->phymap_lock);
	return ((sas_phymap_phys_t *)cphys);
}

int
sas_phymap_phys_next(sas_phymap_phys_t *phys)
{
	bitset_t	*cphys = (bitset_t *)phys;
	int		phy;

	phy = bitset_find(cphys);
	if (phy != -1)
		bitset_del(cphys, phy);
	return (phy);
}

void
sas_phymap_phys_free(sas_phymap_phys_t *phys)
{
	bitset_t	*cphys = (bitset_t *)phys;

	if (cphys) {
		bitset_fini(cphys);
		kmem_free(cphys, sizeof (*cphys));
	}
}

char *
sas_phymap_phy2ua(sas_phymap_t *handle, int phy)
{
	impl_sas_phymap_t	*phymap = (impl_sas_phymap_t *)handle;
	char			*name;
	char			*ua;
	char			*rua = NULL;

	mutex_enter(&phymap->phymap_lock);
	name = ddi_get_soft_state(phymap->phymap_phy2name, phy);
	if (name == NULL)
		goto fail;
	ua = ddi_soft_state_bystr_get(phymap->phymap_name2ua, name);
	if (ua == NULL)
		goto fail;

	/* dup the ua and return */
	rua = strdup(ua);

fail:	mutex_exit(&phymap->phymap_lock);
	return (rua);
}

void
sas_phymap_ua_free(char *ua)
{
	if (ua)
		strfree(ua);
}
