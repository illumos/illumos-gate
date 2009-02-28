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

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/modctl.h>
#include <sys/cred.h>
#include <sys/ioccom.h>
#include <sys/policy.h>
#include <sys/cmn_err.h>
#include <smbsrv/smb_incl.h>
#include <smbsrv/smb_door_svc.h>
#include <smbsrv/smb_ioctl.h>
#include <smbsrv/smb_kproto.h>

static int smb_drv_open(dev_t *, int, int, cred_t *);
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
int	smb_oplock_timeout = OPLOCK_STD_TIMEOUT;
int	smb_flush_required = 1;
int	smb_dirsymlink_enable = 1;
int	smb_announce_quota = 0;
int	smb_sign_debug = 0;
uint_t	smb_audit_flags =
#ifdef	DEBUG
    SMB_AUDIT_NODE;
#else
    0;
#endif

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

/*
 * ****************************************************************************
 *				    Module Interface
 * ****************************************************************************
 */

int
_init(void)
{
	int	rc;

	rc = smb_server_svc_init();
	if (rc == 0) {
		rc = mod_install(&modlinkage);
		if (rc != 0)
			(void) smb_server_svc_fini();
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

	rc = mod_remove(&modlinkage);
	if (rc == 0)
		rc = smb_server_svc_fini();
	return (rc);
}

/*
 * ****************************************************************************
 *				Pseudo Device Entry Points
 * ****************************************************************************
 */
/* ARGSUSED */
static int
smb_drv_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	/*
	 * Check caller's privileges.
	 */
	if (secpolicy_smb(credp) != 0)
		return (EPERM);

	/*
	 * Start SMB service state machine
	 */
	return (smb_server_create());
}

/* ARGSUSED */
static int
smb_drv_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	return (smb_server_delete());
}

/* ARGSUSED */
static int
smb_drv_ioctl(dev_t drv, int cmd, intptr_t argp, int flag, cred_t *cred,
    int *retval)
{
	int		rc = 0;
	smb_io_t	smb_io;
	uint32_t	crc1;
	uint32_t	crc2;

	if (ddi_copyin((smb_io_t *)argp, &smb_io, sizeof (smb_io), flag) ||
	    (smb_io.sio_version != SMB_IOC_VERSION))
		return (EFAULT);

	crc1 = smb_io.sio_crc;
	smb_io.sio_crc = 0;
	crc2 = smb_crc_gen((uint8_t *)&smb_io, sizeof (smb_io_t));

	if (crc1 != crc2)
		return (EFAULT);

	switch (cmd) {
	case SMB_IOC_CONFIG:
		rc = smb_server_configure(&smb_io.sio_data.cfg);
		break;
	case SMB_IOC_START:
		rc = smb_server_start(&smb_io.sio_data.start);
		break;
	case SMB_IOC_NBT_LISTEN:
		rc = smb_server_nbt_listen(smb_io.sio_data.error);
		break;
	case SMB_IOC_TCP_LISTEN:
		rc = smb_server_tcp_listen(smb_io.sio_data.error);
		break;
	case SMB_IOC_NBT_RECEIVE:
		rc = smb_server_nbt_receive();
		break;
	case SMB_IOC_TCP_RECEIVE:
		rc = smb_server_tcp_receive();
		break;
	case SMB_IOC_GMTOFF:
		rc = smb_server_set_gmtoff(smb_io.sio_data.gmtoff);
		break;
	default:
		rc = ENOTTY;
		break;
	}

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
	if (cmd == DDI_ATTACH) {
		/* we only allow instance 0 to attach */
		if (ddi_get_instance(dip) == 0) {
			/* create the minor node */
			if (ddi_create_minor_node(dip, "smbsrv", S_IFCHR, 0,
			    DDI_PSEUDO, 0) == DDI_SUCCESS) {
				smb_drv_dip = dip;
				return (DDI_SUCCESS);
			} else {
				cmn_err(CE_WARN, "smb_drv_attach:"
				    " failed creating minor node");
			}
		}
	}
	return (DDI_FAILURE);
}

static int
smb_drv_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd == DDI_DETACH) {
		ASSERT(dip == smb_drv_dip);
		ddi_remove_minor_node(dip, NULL);
		smb_drv_dip = NULL;
		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
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
