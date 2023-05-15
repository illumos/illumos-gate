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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2015-2023 RackTop Systems, Inc.
 * Copyright 2019 Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/modctl.h>
#include <sys/cred.h>
#include <sys/disp.h>
#include <sys/id_space.h>
#include <sys/ioccom.h>
#include <sys/policy.h>
#include <sys/cmn_err.h>
#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_ioctl.h>

#ifdef	_FAKE_KERNEL
#error	"See libfksmbsrv"
#endif	/* _FAKE_KERNEL */

static int smb_drv_open(dev_t *, int, int, cred_t *);
static int smb_drv_open_ctl(dev_t *, int, int, cred_t *);
static int smb_drv_open_lib(dev_t *, int, int, cred_t *);
static int smb_drv_close(dev_t, int, int, cred_t *);
static int smb_drv_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int smb_drv_attach(dev_info_t *, ddi_attach_cmd_t);
static int smb_drv_detach(dev_info_t *, ddi_detach_cmd_t);
static int smb_drv_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);



/*
 * *****************************************************************************
 * ****************************** Global Variables *****************************
 * *****************************************************************************
 *
 * These variables can only be changed through the /etc/system file.
 */

/*
 * Maximum buffer size for NT: configurable based on the client environment.
 * IR104720 Experiments with Windows 2000 indicate that we achieve better
 * SmbWriteX performance with a buffer size of 64KB instead of the 37KB used
 * with Windows NT4.0. Previous experiments with NT4.0 resulted in directory
 * listing problems so this buffer size is configurable based on the end-user
 * environment. When in doubt use 37KB.
 */
int	smb_maxbufsize = SMB_NT_MAXBUF;
int	smb_flush_required = 1;
int	smb_dirsymlink_enable = 1;
int	smb_sign_debug = 0;
uint_t	smb_audit_flags =
#ifdef	DEBUG
    SMB_AUDIT_NODE;
#else
    0;
#endif

int smb_allow_advisory_locks = 0;	/* See smb_vops.c */

/*
 * Maximum number of simultaneous authentication, share mapping, pipe open
 * requests to be processed.
 */
int	smb_ssetup_threshold = SMB_AUTHSVC_MAXTHREAD;
int	smb_tcon_threshold = 1024;
int	smb_opipe_threshold = 1024;
int	smb_logoff_threshold = 1024;

/*
 * Number of milliseconds that a request will be stalled if it comes in after
 * the maximum number of inflight operations are being proccessed.
 */
int	smb_ssetup_timeout = (30 * 1000);
int	smb_tcon_timeout = (30 * 1000);
int	smb_opipe_timeout = (30 * 1000);
int	smb_logoff_timeout = (600 * 1000);

/*
 * Thread priorities used in smbsrv.
 *
 * The SMB server runs at a priority a little below the maximum for
 * user-level process threads so it won't monopolize the CPU.
 * Todo: make this configurable
 *
 * Aside from that, we want these relative priorities: (a) timers,
 * (b) notify + oplock completions, (c) workers, (d) receivers, etc.
 * The "base" is somewhat arbirary, and what shows up in prstat
 * because it's used for the main thread in newproc().
 */
int smbsrv_timer_pri	= MINCLSYSPRI;		/* smb_server_timers */
int smbsrv_base_pri	= MINCLSYSPRI - 1;	/* kshare thread, newproc */
int smbsrv_notify_pri	= MINCLSYSPRI - 1;	/* oplocks, notify */
/* Gap in which user-level administrative stuff runs. */
int smbsrv_worker_pri	= MINCLSYSPRI - 7;
int smbsrv_receive_pri	= MINCLSYSPRI - 8;
int smbsrv_listen_pri	= MINCLSYSPRI - 9;


/*
 * *****************************************************************************
 * ********************** Static Variables / Module Linkage ********************
 * *****************************************************************************
 */

static struct cb_ops cbops = {
	smb_drv_open,		/* cb_open */
	smb_drv_close,		/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	smb_drv_ioctl,		/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* cb_streamtab */
	D_MP,			/* cb_flag */
	CB_REV,			/* cb_rev */
	nodev,			/* cb_aread */
	nodev,			/* cb_awrite */
};

static struct dev_ops devops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	smb_drv_getinfo,	/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	smb_drv_attach,		/* devo_attach */
	smb_drv_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&cbops,			/* devo_cb_ops */
	NULL,			/* devo_bus_ops */
	NULL,			/* devo_power */
	ddi_quiesce_not_needed,		/* devo_quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,					/* drv_modops */
	"CIFS Server Protocol",				/* drv_linkinfo */
	&devops,
};

static struct modlinkage modlinkage = {
	MODREV_1,	/* revision of the module, must be: MODREV_1	*/
	&modldrv,	/* ptr to linkage structures			*/
	NULL,
};

static dev_info_t *smb_drv_dip = NULL;
static id_space_t *smb_drv_minors = NULL;

/*
 * ****************************************************************************
 *				    Module Interface
 * ****************************************************************************
 */

int
_init(void)
{
	int rc;

	if ((rc = smb_server_g_init()) != 0) {
		return (rc);
	}

	if ((rc = mod_install(&modlinkage)) != 0) {
		smb_server_g_fini();
	}

	return (rc);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	int	rc;

	if (smb_server_get_count() != 0)
		return (EBUSY);

	if ((rc = mod_remove(&modlinkage)) == 0) {
		smb_server_g_fini();
	}

	return (rc);
}

/*
 * ****************************************************************************
 *				Pseudo Device Entry Points
 * ****************************************************************************
 */
/* ARGSUSED */
static int
smb_drv_open(dev_t *devp, int flag, int otyp, cred_t *cr)
{
	int rc;
	minor_t m = getminor(*devp);

	/* See ddi_create_minor_node below */
	switch (m) {
	case 0: /* smbsrv (smbd only) */
		rc = smb_drv_open_ctl(devp, flag, otyp, cr);
		break;
	case 1: /* smbsrv1 (lib access) */
		rc = smb_drv_open_lib(devp, flag, otyp, cr);
		break;
	default:
		rc = ENXIO;
		break;
	}
	return (rc);
}

/*
 * The smbsrvctl device is exclusively for smbd.
 * On open, this creates an smb_server_t instance.
 * Always exclusive open here.
 */
static int
smb_drv_open_ctl(dev_t *devp, int flag, int otyp, cred_t *cr)
{
	dev_t clone;
	minor_t mi;
	int rc;

	/*
	 * Check caller's privileges.
	 */
	if (secpolicy_smb(cr) != 0)
		return (SET_ERROR(EPERM));

	mi = id_allocff(smb_drv_minors);
	clone = makedevice(getmajor(*devp), mi);

	/*
	 * Start SMB service state machine
	 * Note: sets sv->sv_dev = clone
	 */
	rc = smb_server_create(clone);
	if (rc == 0) {
		*devp = clone;
	} else {
		/* Open fails, eg EBUSY */
		id_free(smb_drv_minors, mi);
	}

	return (rc);
}

/*
 * The smbsrv device is for library access to smbsrv state.
 * Multiple open instances are allowed (clone-open).
 */
static int
smb_drv_open_lib(dev_t *devp, int flag, int otyp, cred_t *cr)
{
	minor_t mi;

	mi = id_allocff(smb_drv_minors);
	*devp = makedevice(getmajor(*devp), mi);

	return (0);
}

/*
 * Close on unit zero (detected as: sv->sv_dev == dev)
 * destroys the smb_server_t instance.
 */
/*
 * The smbd process keeps the control device open for the life of
 * smbd (service process).  We know the control device is closing
 * when the device passed to close matches the server sv_dev.
 * When the control device closes, destroy the kernel smb_server_t
 */
/* ARGSUSED */
static int
smb_drv_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	smb_server_t	*sv;

	if (smb_server_lookup(&sv) == 0) {
		if (sv->sv_dev == dev) {
			/* Note releases the ref on sv. */
			(void) smb_server_delete(sv);
		} else {
			smb_server_release(sv);
		}
	}
	id_free(smb_drv_minors, getminor(dev));

	return (0);
}

/* ARGSUSED */
static int
smb_drv_ioctl(dev_t dev, int cmd, intptr_t argp, int flags, cred_t *cred,
    int *retval)
{
	smb_ioc_header_t ioc_hdr;
	smb_ioc_t	*ioc;
	smb_server_t	*sv = NULL;
	uint32_t	crc;
	boolean_t	copyout = B_FALSE;
	int		rc = 0;
	size_t		alloclen;

	if (ddi_copyin((void *)argp, &ioc_hdr, sizeof (ioc_hdr), flags))
		return (SET_ERROR(EFAULT));

	/*
	 * Check version and length.
	 *
	 * Note that some ioctls (i.e. SMB_IOC_SVCENUM) have payload
	 * data after the ioctl struct, in which case they specify a
	 * length much larger than sizeof smb_ioc_t.  The theoretical
	 * largest ioctl data is therefore the size of the union plus
	 * the max size of the payload (which is SMB_IOC_DATA_SIZE).
	 */
	if (ioc_hdr.version != SMB_IOC_VERSION ||
	    ioc_hdr.len < sizeof (ioc_hdr) ||
	    ioc_hdr.len > (sizeof (*ioc) + SMB_IOC_DATA_SIZE))
		return (SET_ERROR(EINVAL));

	crc = ioc_hdr.crc;
	ioc_hdr.crc = 0;
	if (smb_crc_gen((uint8_t *)&ioc_hdr, sizeof (ioc_hdr)) != crc)
		return (SET_ERROR(EINVAL));

	/*
	 * Note that smb_ioc_t is a union, and callers set ioc_hdr.len
	 * to the size of the actual union arm.  If some caller were to
	 * set that size too small, we could end up passing under-sized
	 * memory to one of the type-specific handler functions.  Avoid
	 * that problem by allocating at least the size of the union,
	 * (zeroed out) and then copy in the caller specified length.
	 */
	alloclen = MAX(ioc_hdr.len, sizeof (*ioc));
	ioc = kmem_zalloc(alloclen, KM_SLEEP);
	if (ddi_copyin((void *)argp, ioc, ioc_hdr.len, flags)) {
		rc = SET_ERROR(EFAULT);
		goto out;
	}

	/* Don't allow the request size to change mid-ioctl */
	if (ioc_hdr.len != ioc->ioc_hdr.len) {
		rc = SET_ERROR(EINVAL);
		goto out;
	}

	rc = smb_server_lookup(&sv);
	if (rc != 0) {
		sv = NULL;
		goto out;
	}

	/*
	 * Access control by category of ioctl codes, based on
	 * which device was opened, and privilege checks.
	 */
	switch (cmd) {
	case SMB_IOC_NUMOPEN:
	case SMB_IOC_SVCENUM:
		/*
		 * Non-modifying ops. no special priv.
		 * beyond dev open permissions.
		 */
		break;

	case SMB_IOC_FILE_CLOSE:
	case SMB_IOC_SESSION_CLOSE:
		/*
		 * Modifying ops. Require privilege
		 * (chose one smbd normally has)
		 */
		if ((rc = secpolicy_basic_proc(cred)) != 0)
			goto out;
		break;
	default:
		/*
		 * The rest are only allowed on the control device.
		 * Note: secpolicy_smb checked in open.
		 */
		if (sv->sv_dev != dev) {
			rc = SET_ERROR(EPERM);
			goto out;
		}
		break;
	}

	/*
	 * See similar in libfksmbrv fksmbsrv_drv_ioctl()
	 */
	switch (cmd) {
	case SMB_IOC_CONFIG:
		rc = smb_server_configure(sv, &ioc->ioc_cfg);
		break;
	case SMB_IOC_START:
		rc = smb_server_start(sv, &ioc->ioc_start);
		break;
	case SMB_IOC_STOP:
		rc = smb_server_stop(sv);
		break;
	case SMB_IOC_EVENT:
		rc = smb_server_notify_event(sv, &ioc->ioc_event);
		break;
	case SMB_IOC_GMTOFF:
		rc = smb_server_set_gmtoff(sv, &ioc->ioc_gmt);
		break;
	case SMB_IOC_SHARE:
		rc = smb_kshare_export_list(sv, &ioc->ioc_share);
		break;
	case SMB_IOC_UNSHARE:
		rc = smb_kshare_unexport_list(sv, &ioc->ioc_share);
		break;
	case SMB_IOC_SHAREINFO:
		rc = smb_kshare_info(sv, &ioc->ioc_shareinfo);
		copyout = B_TRUE;
		break;
	case SMB_IOC_SHAREACCESS:
		rc = smb_kshare_access(sv, &ioc->ioc_shareaccess);
		break;
	case SMB_IOC_NUMOPEN:
		rc = smb_server_numopen(sv, &ioc->ioc_opennum);
		copyout = B_TRUE;
		break;
	case SMB_IOC_SVCENUM:
		rc = smb_server_enum(sv, &ioc->ioc_svcenum);
		copyout = B_TRUE;
		break;
	case SMB_IOC_SESSION_CLOSE:
		rc = smb_server_session_close(sv, &ioc->ioc_session);
		break;
	case SMB_IOC_FILE_CLOSE:
		rc = smb_server_file_close(sv, &ioc->ioc_fileid);
		break;
	case SMB_IOC_SPOOLDOC:
		rc = smb_server_spooldoc(sv, &ioc->ioc_spooldoc);
		copyout = B_TRUE;
		break;
	default:
		rc = SET_ERROR(ENOTTY);
		break;
	}
	if ((rc == 0) && copyout) {
		if (ddi_copyout(ioc, (void *)argp, ioc_hdr.len, flags))
			rc = SET_ERROR(EFAULT);
	}
out:
	if (sv != NULL)
		smb_server_release(sv);
	kmem_free(ioc, alloclen);
	return (rc);
}

/*
 * ****************************************************************************
 *				Pseudo Device Operations
 * ****************************************************************************
 */
static int
smb_drv_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	/* we only allow instance 0 to attach */
	if (ddi_get_instance(dip) != 0)
		return (DDI_FAILURE);

	/* Create the minor nodes.  See smb_drv_open */
	if (ddi_create_minor_node(dip, "smbsrv", S_IFCHR, 0,
	    DDI_PSEUDO, 0) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "smb_drv_attach:"
		    " failed creating minor node 0");
		return (DDI_FAILURE);
	}
	if (ddi_create_minor_node(dip, "smbsrv1", S_IFCHR, 1,
	    DDI_PSEUDO, 0) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "smb_drv_attach:"
		    " failed creating minor node 1");
		ddi_remove_minor_node(dip, NULL);
		return (DDI_FAILURE);
	}

	/* Reserved: control dev = 0, library dev = 1 */
	smb_drv_minors = id_space_create("smbsrv drv minors", 2, INT32_MAX);
	smb_drv_dip = dip;

	return (DDI_SUCCESS);
}

static int
smb_drv_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	ASSERT(dip == smb_drv_dip);
	smb_drv_dip = NULL;

	id_space_destroy(smb_drv_minors);
	smb_drv_minors = NULL;

	ddi_remove_minor_node(dip, NULL);

	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
smb_drv_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	ulong_t instance = getminor((dev_t)arg);

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = smb_drv_dip;
		return (DDI_SUCCESS);

	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)instance;
		return (DDI_SUCCESS);

	default:
		break;
	}

	return (DDI_FAILURE);
}
