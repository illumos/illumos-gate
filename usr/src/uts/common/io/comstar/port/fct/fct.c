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
 * Copyright 2012 Nexenta Systems, Inc. All rights reserved.
 */

#include <sys/conf.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/scsi/scsi.h>
#include <sys/scsi/impl/scsi_reset_notify.h>
#include <sys/disp.h>
#include <sys/byteorder.h>
#include <sys/varargs.h>
#include <sys/atomic.h>
#include <sys/sdt.h>

#include <sys/stmf.h>
#include <sys/stmf_ioctl.h>
#include <sys/portif.h>
#include <sys/fct.h>
#include <sys/fctio.h>

#include "fct_impl.h"
#include "discovery.h"

static int fct_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int fct_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int fct_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg,
    void **result);
static int fct_open(dev_t *devp, int flag, int otype, cred_t *credp);
static int fct_close(dev_t dev, int flag, int otype, cred_t *credp);
static int fct_ioctl(dev_t dev, int cmd, intptr_t data, int mode,
    cred_t *credp, int *rval);
static int fct_fctiocmd(intptr_t data, int mode);
void fct_init_kstats(fct_i_local_port_t *iport);

static dev_info_t *fct_dip;
static struct cb_ops fct_cb_ops = {
	fct_open,			/* open */
	fct_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	fct_ioctl,			/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* chpoll */
	ddi_prop_op,			/* cb_prop_op */
	0,				/* streamtab */
	D_NEW | D_MP,			/* cb_flag */
	CB_REV,				/* rev */
	nodev,				/* aread */
	nodev				/* awrite */
};

static struct dev_ops fct_ops = {
	DEVO_REV,
	0,
	fct_getinfo,
	nulldev,		/* identify */
	nulldev,		/* probe */
	fct_attach,
	fct_detach,
	nodev,			/* reset */
	&fct_cb_ops,
	NULL,			/* bus_ops */
	NULL			/* power */
};

#define	FCT_NAME	"COMSTAR FCT"
#define	FCT_MODULE_NAME	"fct"

extern struct mod_ops mod_driverops;
static struct modldrv modldrv = {
	&mod_driverops,
	FCT_NAME,
	&fct_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

static uint32_t	rportid_table_size = FCT_HASH_TABLE_SIZE;
static int max_cached_ncmds = FCT_MAX_CACHED_CMDS;
static fct_i_local_port_t *fct_iport_list = NULL;
static kmutex_t fct_global_mutex;
uint32_t fct_rscn_options = RSCN_OPTION_VERIFY;

int
_init(void)
{
	int ret;

	ret = mod_install(&modlinkage);
	if (ret)
		return (ret);
	/* XXX */
	mutex_init(&fct_global_mutex, NULL, MUTEX_DRIVER, NULL);
	return (ret);
}

int
_fini(void)
{
	int ret;

	ret = mod_remove(&modlinkage);
	if (ret)
		return (ret);
	/* XXX */
	mutex_destroy(&fct_global_mutex);
	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/* ARGSUSED */
static int
fct_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = fct_dip;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)ddi_get_instance(fct_dip);
		break;
	default:
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
fct_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		fct_dip = dip;

		if (ddi_create_minor_node(dip, "admin", S_IFCHR, 0,
		    DDI_NT_STMF_PP, 0) != DDI_SUCCESS) {
			break;
		}
		ddi_report_dev(dip);
		return (DDI_SUCCESS);
	}

	return (DDI_FAILURE);
}

static int
fct_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		ddi_remove_minor_node(dip, 0);
		return (DDI_SUCCESS);
	}

	return (DDI_FAILURE);
}

/* ARGSUSED */
static int
fct_open(dev_t *devp, int flag, int otype, cred_t *credp)
{
	if (otype != OTYP_CHR)
		return (EINVAL);
	return (0);
}

/* ARGSUSED */
static int
fct_close(dev_t dev, int flag, int otype, cred_t *credp)
{
	return (0);
}

/* ARGSUSED */
static int
fct_ioctl(dev_t dev, int cmd, intptr_t data, int mode,
    cred_t *credp, int *rval)
{
	int		ret = 0;

	if ((cmd & 0xff000000) != FCT_IOCTL) {
		return (ENOTTY);
	}

	if (drv_priv(credp) != 0) {
		return (EPERM);
	}

	switch (cmd) {
	case FCTIO_CMD:
		ret = fct_fctiocmd(data, mode);
		break;
	default:
		ret = ENOTTY;
		break;
	}

	return (ret);
}

int
fct_copyin_iocdata(intptr_t data, int mode, fctio_t **fctio,
    void **ibuf, void **abuf, void **obuf)
{
	int ret = 0;

	*ibuf = NULL;
	*abuf = NULL;
	*obuf = NULL;
	*fctio = kmem_zalloc(sizeof (fctio_t), KM_SLEEP);
	if (ddi_copyin((void *)data, *fctio, sizeof (fctio_t), mode)) {
		ret = EFAULT;
		goto copyin_iocdata_done;
	}

	if ((*fctio)->fctio_ilen) {
		*ibuf = kmem_zalloc((*fctio)->fctio_ilen, KM_SLEEP);
		if (ddi_copyin((void *)(unsigned long)(*fctio)->fctio_ibuf,
		    *ibuf, (*fctio)->fctio_ilen, mode)) {
			ret = EFAULT;
			goto copyin_iocdata_done;
		}
	}
	if ((*fctio)->fctio_alen) {
		*abuf = kmem_zalloc((*fctio)->fctio_alen, KM_SLEEP);
		if (ddi_copyin((void *)(unsigned long)(*fctio)->fctio_abuf,
		    *abuf, (*fctio)->fctio_alen, mode)) {
			ret = EFAULT;
			goto copyin_iocdata_done;
		}
	}
	if ((*fctio)->fctio_olen)
		*obuf = kmem_zalloc((*fctio)->fctio_olen, KM_SLEEP);
	if (ret == 0)
		return (0);
	ret = EFAULT;
copyin_iocdata_done:
	if (*obuf) {
		kmem_free(*obuf, (*fctio)->fctio_olen);
		*obuf = NULL;
	}
	if (*abuf) {
		kmem_free(*abuf, (*fctio)->fctio_alen);
		*abuf = NULL;
	}
	if (*ibuf) {
		kmem_free(*ibuf, (*fctio)->fctio_ilen);
		*ibuf = NULL;
	}
	kmem_free(*fctio, sizeof (fctio_t));
	return (ret);
}

int
fct_copyout_iocdata(intptr_t data, int mode, fctio_t *fctio, void *obuf)
{
	int ret = 0;

	if (fctio->fctio_olen) {
		ret = ddi_copyout(obuf,
		    (void *)(unsigned long)fctio->fctio_obuf, fctio->fctio_olen,
		    mode);
		if (ret) {
			return (EFAULT);
		}
	}
	ret = ddi_copyout(fctio, (void *)data, sizeof (fctio_t), mode);
	if (ret) {
		return (EFAULT);
	}
	return (0);
}

int
fct_get_port_list(char *pathList, int count)
{
	fct_i_local_port_t *iport;
	int	i = 0, maxPorts = 0;

	ASSERT(pathList != NULL);

	mutex_enter(&fct_global_mutex);
	for (iport = fct_iport_list; iport; iport = iport->iport_next) {
		if (i < count)
			bcopy(iport->iport_port->port_pwwn,
			    pathList + 8 * i, 8);
		maxPorts ++;
		i++;
	}
	mutex_exit(&fct_global_mutex);
	return (maxPorts);
}

/* invoked with fct_global_mutex locked */
fct_i_local_port_t *
fct_get_iport_per_wwn(uint8_t *pwwn)
{
	fct_i_local_port_t *iport;

	ASSERT(mutex_owned(&fct_global_mutex));
	for (iport = fct_iport_list; iport; iport = iport->iport_next) {
		if (bcmp(iport->iport_port->port_pwwn, pwwn, 8) == 0)
			return (iport);
	}
	return (NULL);
}

int
fct_get_adapter_attr(uint8_t *pwwn, fc_tgt_hba_adapter_attributes_t *hba_attr,
    uint32_t *err_detail)
{
	fct_i_local_port_t *iport;
	fct_port_attrs_t *attr;

	hba_attr->version = FCT_HBA_ADAPTER_ATTRIBUTES_VERSION;
	iport = fct_get_iport_per_wwn(pwwn);
	if (!iport) {
		*err_detail = FCTIO_BADWWN;
		return (ENXIO);
	}

	attr = (fct_port_attrs_t *)kmem_zalloc(sizeof (fct_port_attrs_t),
	    KM_SLEEP);
	mutex_exit(&fct_global_mutex);
	iport->iport_port->port_populate_hba_details(iport->iport_port, attr);
	mutex_enter(&fct_global_mutex);

	bcopy(attr->manufacturer, hba_attr->Manufacturer,
	    sizeof (hba_attr->Manufacturer));
	bcopy(attr->serial_number, hba_attr->SerialNumber,
	    sizeof (hba_attr->SerialNumber));
	bcopy(attr->model, hba_attr->Model, sizeof (hba_attr->Model));
	bcopy(attr->model_description, hba_attr->ModelDescription,
	    sizeof (hba_attr->ModelDescription));
	if (iport->iport_port->port_sym_node_name)
		bcopy(iport->iport_port->port_sym_node_name,
		    hba_attr->NodeSymbolicName,
		    strlen(iport->iport_port->port_sym_node_name));
	else
		bcopy(utsname.nodename, hba_attr->NodeSymbolicName,
		    strlen(utsname.nodename));
	bcopy(attr->hardware_version, hba_attr->HardwareVersion,
	    sizeof (hba_attr->HardwareVersion));
	bcopy(attr->option_rom_version, hba_attr->OptionROMVersion,
	    sizeof (hba_attr->OptionROMVersion));
	bcopy(attr->firmware_version, hba_attr->FirmwareVersion,
	    sizeof (hba_attr->FirmwareVersion));
	hba_attr->VendorSpecificID = attr->vendor_specific_id;
	bcopy(iport->iport_port->port_nwwn, hba_attr->NodeWWN,
	    sizeof (hba_attr->NodeWWN));

	bcopy(attr->driver_name, hba_attr->DriverName,
	    sizeof (hba_attr->DriverName));
	bcopy(attr->driver_version, hba_attr->DriverVersion,
	    sizeof (hba_attr->DriverVersion));


	/* hba_attr->NumberOfPorts = fct_count_fru_ports(iport); */
	hba_attr->NumberOfPorts = 1;

	kmem_free(attr, sizeof (fct_port_attrs_t));
	return (0);
}

int
fct_get_adapter_port_attr(fct_i_local_port_t *ilport, uint8_t *pwwn,
    fc_tgt_hba_port_attributes_t *port_attr, uint32_t *err_detail)
{
	fct_i_local_port_t *iport = ilport;
	fct_i_remote_port_t *irp = NULL;
	fct_port_attrs_t *attr;
	int i = 0;

	port_attr->version = FCT_HBA_PORT_ATTRIBUTES_VERSION;

	if (!ilport) {
		iport = fct_get_iport_per_wwn(pwwn);
		if (!iport) {
			*err_detail = FCTIO_BADWWN;
			return (ENXIO);
		}
	}

	attr = (fct_port_attrs_t *)kmem_zalloc(sizeof (fct_port_attrs_t),
	    KM_SLEEP);
	mutex_exit(&fct_global_mutex);
	iport->iport_port->port_populate_hba_details(iport->iport_port, attr);
	mutex_enter(&fct_global_mutex);

	port_attr->lastChange = iport->iport_last_change;
	bcopy(iport->iport_port->port_nwwn, port_attr->NodeWWN,
	    sizeof (port_attr->NodeWWN));
	bcopy(iport->iport_port->port_pwwn, port_attr->PortWWN,
	    sizeof (port_attr->PortWWN));
	bzero(port_attr->FabricName, sizeof (port_attr->FabricName));
	port_attr->PortFcId = iport->iport_link_info.portid;
	if ((iport->iport_link_state & S_LINK_ONLINE) ||
	    (iport->iport_link_state & S_RCVD_LINK_UP)) {
		port_attr->PortState = FC_HBA_PORTSTATE_ONLINE;
	} else {
		port_attr->PortState = FC_HBA_PORTSTATE_OFFLINE;
	}
	switch (iport->iport_link_info.port_topology) {
		case PORT_TOPOLOGY_PT_TO_PT:
			port_attr->PortType = FC_HBA_PORTTYPE_PTP;
			break;
		case PORT_TOPOLOGY_PRIVATE_LOOP:
			port_attr->PortType = FC_HBA_PORTTYPE_LPORT;
			break;
		case PORT_TOPOLOGY_PUBLIC_LOOP:
			port_attr->PortType = FC_HBA_PORTTYPE_NLPORT;
			break;
		case PORT_TOPOLOGY_FABRIC_PT_TO_PT:
			port_attr->PortType = FC_HBA_PORTTYPE_FPORT;
			break;
		default:
			port_attr->PortType = FC_HBA_PORTTYPE_UNKNOWN;
			break;
	}
	port_attr->PortSupportedClassofService = attr->supported_cos;
	port_attr->PortSupportedFc4Types[0] = 0;
	port_attr->PortActiveFc4Types[2] = 1;
	if (iport->iport_port->port_sym_port_name)
		bcopy(iport->iport_port->port_sym_port_name,
		    port_attr->PortSymbolicName,
		    strlen(iport->iport_port->port_sym_port_name));
	else if (iport->iport_port->port_default_alias)
		bcopy(iport->iport_port->port_default_alias,
		    port_attr->PortSymbolicName,
		    strlen(iport->iport_port->port_default_alias));
	else
		port_attr->PortSymbolicName[0] = 0;
	/* the definition is different so need to translate */
	if (attr->supported_speed & PORT_SPEED_1G)
		port_attr->PortSupportedSpeed |= FC_HBA_PORTSPEED_1GBIT;
	if (attr->supported_speed & PORT_SPEED_2G)
		port_attr->PortSupportedSpeed |= FC_HBA_PORTSPEED_2GBIT;
	if (attr->supported_speed & PORT_SPEED_4G)
		port_attr->PortSupportedSpeed |= FC_HBA_PORTSPEED_4GBIT;
	if (attr->supported_speed & PORT_SPEED_8G)
		port_attr->PortSupportedSpeed |= FC_HBA_PORTSPEED_8GBIT;
	if (attr->supported_speed & PORT_SPEED_10G)
		port_attr->PortSupportedSpeed |= FC_HBA_PORTSPEED_10GBIT;
	switch (iport->iport_link_info.port_speed) {
		case PORT_SPEED_1G:
			port_attr->PortSpeed = FC_HBA_PORTSPEED_1GBIT;
			break;
		case PORT_SPEED_2G:
			port_attr->PortSpeed = FC_HBA_PORTSPEED_2GBIT;
			break;
		case PORT_SPEED_4G:
			port_attr->PortSpeed = FC_HBA_PORTSPEED_4GBIT;
			break;
		case PORT_SPEED_8G:
			port_attr->PortSpeed = FC_HBA_PORTSPEED_8GBIT;
			break;
		case PORT_SPEED_10G:
			port_attr->PortSpeed = FC_HBA_PORTSPEED_10GBIT;
			break;
		default:
			port_attr->PortSpeed = FC_HBA_PORTSPEED_UNKNOWN;
			break;
	}
	port_attr->PortMaxFrameSize = attr->max_frame_size;
	rw_enter(&iport->iport_lock, RW_READER);
	port_attr->NumberofDiscoveredPorts = iport->iport_nrps_login;
	for (; i < iport->iport_port->port_max_logins; i++) {
		irp = iport->iport_rp_slots[i];
		if (irp && irp->irp_flags & IRP_PLOGI_DONE) {
			if (FC_WELL_KNOWN_ADDR(irp->irp_portid))
				port_attr->NumberofDiscoveredPorts --;
		}
	}
	rw_exit(&iport->iport_lock);

	kmem_free(attr, sizeof (fct_port_attrs_t));

	return (0);
}

int
fct_get_discovered_port_attr(fct_i_remote_port_t *remote_port,
    uint8_t *port_wwn, uint32_t index, fc_tgt_hba_port_attributes_t *port_attr,
    uint32_t *error_detail)
{
	fct_i_local_port_t *iport;
	fct_i_remote_port_t *irp = remote_port;
	int	count = 0, i = 0;

	port_attr->version = FCT_HBA_PORT_ATTRIBUTES_VERSION;
	if (!remote_port) {
		iport = fct_get_iport_per_wwn(port_wwn);
		if (!iport) {
			*error_detail = FCTIO_BADWWN;
			return (ENXIO);
		}

		rw_enter(&iport->iport_lock, RW_READER);

		if (index >= iport->iport_nrps_login) {
			rw_exit(&iport->iport_lock);
			*error_detail = FCTIO_OUTOFBOUNDS;
			return (EINVAL);
		}
		for (; i < iport->iport_port->port_max_logins; i++) {
			irp = iport->iport_rp_slots[i];
			if (irp && irp->irp_flags & IRP_PLOGI_DONE &&
			    !FC_WELL_KNOWN_ADDR(irp->irp_portid)) {
				count ++;
				if ((index + 1) <= count)
					break;
			}
		}
		if (i >= iport->iport_port->port_max_logins) {
			rw_exit(&iport->iport_lock);
			*error_detail = FCTIO_OUTOFBOUNDS;
			return (EINVAL);
		}
		ASSERT(irp);
	} else {
		iport = (fct_i_local_port_t *)
		    irp->irp_rp->rp_port->port_fct_private;
	}
	port_attr->lastChange = iport->iport_last_change;
	rw_enter(&irp->irp_lock, RW_READER);
	bcopy(irp->irp_rp->rp_pwwn, port_attr->PortWWN,
	    sizeof (port_attr->PortWWN));
	bcopy(irp->irp_rp->rp_nwwn, port_attr->NodeWWN,
	    sizeof (port_attr->NodeWWN));
	port_attr->PortFcId = irp->irp_portid;
	if (irp->irp_spn)
		(void) strncpy(port_attr->PortSymbolicName, irp->irp_spn,
		    strlen(irp->irp_spn));
	else
		port_attr->PortSymbolicName[0] = '\0';
	port_attr->PortSupportedClassofService = irp->irp_cos;
	bcopy((caddr_t)irp->irp_fc4types, port_attr->PortActiveFc4Types,
	    sizeof (irp->irp_fc4types));
	bcopy((caddr_t)irp->irp_fc4types, port_attr->PortSupportedFc4Types,
	    sizeof (irp->irp_fc4types));
	if (irp->irp_flags & IRP_PLOGI_DONE)
		port_attr->PortState = FC_HBA_PORTSTATE_ONLINE;
	else
		port_attr->PortState = FC_HBA_PORTSTATE_UNKNOWN;

	port_attr->PortType = FC_HBA_PORTTYPE_UNKNOWN;
	port_attr->PortSupportedSpeed = FC_HBA_PORTSPEED_UNKNOWN;
	port_attr->PortSpeed = FC_HBA_PORTSPEED_UNKNOWN;
	port_attr->PortMaxFrameSize = 0;
	port_attr->NumberofDiscoveredPorts = 0;
	rw_exit(&irp->irp_lock);
	if (!remote_port) {
		rw_exit(&iport->iport_lock);
	}
	return (0);
}

int
fct_get_port_attr(uint8_t *port_wwn,
    fc_tgt_hba_port_attributes_t *port_attr, uint32_t *error_detail)
{
	fct_i_local_port_t *iport;
	fct_i_remote_port_t *irp;
	int i, ret;

	iport = fct_get_iport_per_wwn(port_wwn);
	if (iport) {
		return (fct_get_adapter_port_attr(iport, port_wwn,
		    port_attr, error_detail));
	}
	/* else */
	for (iport = fct_iport_list; iport; iport = iport->iport_next) {
		rw_enter(&iport->iport_lock, RW_READER);
		for (i = 0; i < rportid_table_size; i++) {
			irp = iport->iport_rp_tb[i];
			while (irp) {
				if (bcmp(irp->irp_rp->rp_pwwn,
				    port_wwn, 8) == 0 &&
				    irp->irp_flags & IRP_PLOGI_DONE) {
					ret = fct_get_discovered_port_attr(
					    irp, NULL, 0, port_attr,
					    error_detail);
					rw_exit(&iport->iport_lock);
					return (ret);
				}
				irp = irp->irp_next;
			}
		}
		rw_exit(&iport->iport_lock);
	}
	*error_detail = FCTIO_BADWWN;
	return (ENXIO);
}

/* ARGSUSED */
int
fct_get_port_stats(uint8_t *port_wwn,
    fc_tgt_hba_adapter_port_stats_t *port_stats, uint32_t *error_detail)
{
	int ret;
	fct_i_local_port_t *iport = fct_get_iport_per_wwn(port_wwn);
	fct_port_link_status_t	stat;
	uint32_t buf_size = sizeof (fc_tgt_hba_adapter_port_stats_t);

	if (!iport)
		return (ENXIO);
	port_stats->version = FCT_HBA_ADAPTER_PORT_STATS_VERSION;

	if (iport->iport_port->port_info == NULL) {
		*error_detail = FCTIO_FAILURE;
		return (EIO);
	}
	ret = iport->iport_port->port_info(FC_TGT_PORT_RLS,
	    iport->iport_port, NULL, (uint8_t *)&stat, &buf_size);
	if (ret != STMF_SUCCESS) {
		*error_detail = FCTIO_FAILURE;
		return (EIO);
	}

	port_stats->SecondsSinceLastReset = 0;
	port_stats->TxFrames = 0;
	port_stats->TxWords = 0;
	port_stats->RxFrames = 0;
	port_stats->RxWords = 0;
	port_stats->LIPCount = 0;
	port_stats->NOSCount = 0;
	port_stats->ErrorFrames = 0;
	port_stats->DumpedFrames = 0;
	port_stats->LinkFailureCount = stat.LinkFailureCount;
	port_stats->LossOfSyncCount = stat.LossOfSyncCount;
	port_stats->LossOfSignalCount = stat.LossOfSignalsCount;
	port_stats->PrimitiveSeqProtocolErrCount =
	    stat.PrimitiveSeqProtocolErrorCount;
	port_stats->InvalidTxWordCount =
	    stat.InvalidTransmissionWordCount;
	port_stats->InvalidCRCCount = stat.InvalidCRCCount;

	return (ret);
}

int
fct_get_link_status(uint8_t *port_wwn, uint64_t *dest_id,
    fct_port_link_status_t *link_status, uint32_t *error_detail)
{
	fct_i_local_port_t *iport = fct_get_iport_per_wwn(port_wwn);
	fct_i_remote_port_t *irp = NULL;
	uint32_t buf_size = sizeof (fct_port_link_status_t);
	stmf_status_t ret = 0;
	int i;
	fct_cmd_t *cmd = NULL;

	if (!iport) {
		*error_detail = FCTIO_BADWWN;
		return (ENXIO);
	}

	/*
	 * If what we are requesting is zero or same as local port,
	 * then we use port_info()
	 */
	if (dest_id == NULL || *dest_id == iport->iport_link_info.portid) {
		if (iport->iport_port->port_info == NULL) {
			*error_detail = FCTIO_FAILURE;
			return (EIO);
		}
		ret = iport->iport_port->port_info(FC_TGT_PORT_RLS,
		    iport->iport_port, NULL,
		    (uint8_t *)link_status, &buf_size);
		if (ret == STMF_SUCCESS) {
			return (0);
		} else {
			*error_detail = FCTIO_FAILURE;
			return (EIO);
		}
	}

	/*
	 * For remote port, we will send RLS
	 */
	for (i = 0; i < rportid_table_size; i++) {
		irp = iport->iport_rp_tb[i];
		while (irp) {
			if (irp->irp_rp->rp_id == *dest_id &&
			    irp->irp_flags & IRP_PLOGI_DONE) {
				goto SEND_RLS_ELS;
			}
			irp = irp->irp_next;
		}
	}
	return (ENXIO);

SEND_RLS_ELS:
	cmd = fct_create_solels(iport->iport_port,
	    irp->irp_rp, 0, ELS_OP_RLS,
	    0, fct_rls_cb);
	if (!cmd)
		return (ENOMEM);
	iport->iport_rls_cb_data.fct_link_status = link_status;
	CMD_TO_ICMD(cmd)->icmd_cb_private = &iport->iport_rls_cb_data;
	fct_post_to_solcmd_queue(iport->iport_port, cmd);
	sema_p(&iport->iport_rls_sema);
	if (iport->iport_rls_cb_data.fct_els_res != FCT_SUCCESS)
		ret = EIO;
	return (ret);
}

static int
fct_forcelip(uint8_t *port_wwn, uint32_t *fctio_errno)
{
	fct_status_t		 rval;
	fct_i_local_port_t	*iport;

	mutex_enter(&fct_global_mutex);
	iport = fct_get_iport_per_wwn(port_wwn);
	mutex_exit(&fct_global_mutex);
	if (iport == NULL) {
		return (-1);
	}

	iport->iport_port->port_ctl(iport->iport_port,
	    FCT_CMD_FORCE_LIP, &rval);
	if (rval != FCT_SUCCESS) {
		*fctio_errno = FCTIO_FAILURE;
	} else {
		*fctio_errno = 0;
	}

	return (0);
}

static int
fct_fctiocmd(intptr_t data, int mode)
{
	int ret	 = 0;
	void		*ibuf = NULL;
	void		*obuf = NULL;
	void		*abuf = NULL;
	fctio_t		*fctio;
	uint32_t	attr_length;

	ret = fct_copyin_iocdata(data, mode, &fctio, &ibuf, &abuf, &obuf);
	if (ret) {
		return (ret);
	}

	switch (fctio->fctio_cmd) {
	case FCTIO_ADAPTER_LIST: {
		fc_tgt_hba_list_t *list = (fc_tgt_hba_list_t *)obuf;
		int		count;

		if (fctio->fctio_olen < sizeof (fc_tgt_hba_list_t)) {
			ret = EINVAL;
			break;
		}
		list->numPorts = (fctio->fctio_olen -
		    sizeof (fc_tgt_hba_list_t))/8 + 1;

		list->version = FCT_HBA_LIST_VERSION;
		count = fct_get_port_list((char *)list->port_wwn,
		    list->numPorts);
		if (count < 0) {
			ret = ENXIO;
			break;
		}
		if (count > list->numPorts) {
			fctio->fctio_errno = FCTIO_MOREDATA;
			ret = ENOSPC;
		}
		list->numPorts = count;
		break;
		}
	case FCTIO_GET_ADAPTER_ATTRIBUTES: {
		fc_tgt_hba_adapter_attributes_t *hba_attr;
		uint8_t	*port_wwn = (uint8_t *)ibuf;

		attr_length = sizeof (fc_tgt_hba_adapter_attributes_t);
		if (fctio->fctio_olen < attr_length ||
		    fctio->fctio_xfer != FCTIO_XFER_READ) {
			ret = EINVAL;
			break;
		}
		hba_attr = (fc_tgt_hba_adapter_attributes_t *)obuf;

		mutex_enter(&fct_global_mutex);
		ret = fct_get_adapter_attr(port_wwn, hba_attr,
		    &fctio->fctio_errno);
		mutex_exit(&fct_global_mutex);

		break;
		}
	case FCTIO_GET_ADAPTER_PORT_ATTRIBUTES: {
		fc_tgt_hba_port_attributes_t *port_attr;

		uint8_t *port_wwn = (uint8_t *)ibuf;

		attr_length = sizeof (fc_tgt_hba_port_attributes_t);
		if (fctio->fctio_olen < attr_length ||
		    fctio->fctio_xfer != FCTIO_XFER_READ) {
			ret = EINVAL;
			break;
		}
		port_attr = (fc_tgt_hba_port_attributes_t *)obuf;

		mutex_enter(&fct_global_mutex);
		ret = fct_get_adapter_port_attr(NULL, port_wwn, port_attr,
		    &fctio->fctio_errno);
		mutex_exit(&fct_global_mutex);

		break;
		}
	case FCTIO_GET_DISCOVERED_PORT_ATTRIBUTES: {
		uint8_t *port_wwn = (uint8_t *)ibuf;
		uint32_t *port_index = (uint32_t *)abuf;
		fc_tgt_hba_port_attributes_t *port_attr;

		attr_length = sizeof (fc_tgt_hba_port_attributes_t);
		if (fctio->fctio_olen < attr_length ||
		    fctio->fctio_xfer != FCTIO_XFER_READ) {
			ret = EINVAL;
			break;
		}
		port_attr = (fc_tgt_hba_port_attributes_t *)obuf;

		mutex_enter(&fct_global_mutex);
		ret = fct_get_discovered_port_attr(NULL, port_wwn,
		    *port_index, port_attr, &fctio->fctio_errno);
		mutex_exit(&fct_global_mutex);

		break;
		}
	case FCTIO_GET_PORT_ATTRIBUTES: {
		uint8_t *port_wwn = (uint8_t *)ibuf;
		fc_tgt_hba_port_attributes_t *port_attr;

		attr_length = sizeof (fc_tgt_hba_port_attributes_t);
		if (fctio->fctio_olen < attr_length ||
		    fctio->fctio_xfer != FCTIO_XFER_READ) {
			ret = EINVAL;
			break;
		}

		port_attr = (fc_tgt_hba_port_attributes_t *)obuf;

		mutex_enter(&fct_global_mutex);
		ret = fct_get_port_attr(port_wwn, port_attr,
		    &fctio->fctio_errno);
		mutex_exit(&fct_global_mutex);

		break;
		}
	case FCTIO_GET_ADAPTER_PORT_STATS: {
		uint8_t *port_wwn = (uint8_t *)ibuf;
		fc_tgt_hba_adapter_port_stats_t *port_stats =
		    (fc_tgt_hba_adapter_port_stats_t *)obuf;
		mutex_enter(&fct_global_mutex);
		ret = fct_get_port_stats(port_wwn, port_stats,
		    &fctio->fctio_errno);
		mutex_exit(&fct_global_mutex);
		break;
		}
	case FCTIO_GET_LINK_STATUS: {
		uint8_t *port_wwn = (uint8_t *)ibuf;
		fct_port_link_status_t *link_status =
		    (fct_port_link_status_t *)obuf;
		uint64_t *dest_id = abuf;

		mutex_enter(&fct_global_mutex);
		ret = fct_get_link_status(port_wwn, dest_id, link_status,
		    &fctio->fctio_errno);
		mutex_exit(&fct_global_mutex);
		break;
		}

	case FCTIO_FORCE_LIP:
		ret = fct_forcelip((uint8_t *)ibuf, &fctio->fctio_errno);
		break;

	default:
		break;
	}
	if (ret == 0) {
		ret = fct_copyout_iocdata(data, mode, fctio, obuf);
	} else if (fctio->fctio_errno) {
		(void) fct_copyout_iocdata(data, mode, fctio, obuf);
	}

	if (obuf) {
		kmem_free(obuf, fctio->fctio_olen);
		obuf = NULL;
	}
	if (abuf) {
		kmem_free(abuf, fctio->fctio_alen);
		abuf = NULL;
	}

	if (ibuf) {
		kmem_free(ibuf, fctio->fctio_ilen);
		ibuf = NULL;
	}
	kmem_free(fctio, sizeof (fctio_t));
	return (ret);
}

typedef struct {
	void	*bp;	/* back pointer from internal struct to main struct */
	int	alloc_size;
	fct_struct_id_t struct_id;
} __ifct_t;

typedef struct {
	__ifct_t	*fp;	/* Framework private */
	void		*cp;	/* Caller private */
	void		*ss;	/* struct specific */
} __fct_t;

static struct {
	int shared;
	int fw_private;
	int struct_specific;
} fct_sizes[] = { { 0, 0, 0 },
	{ GET_STRUCT_SIZE(fct_local_port_t),
		GET_STRUCT_SIZE(fct_i_local_port_t), 0 },
	{ GET_STRUCT_SIZE(fct_remote_port_t),
		GET_STRUCT_SIZE(fct_i_remote_port_t), 0 },
	{ GET_STRUCT_SIZE(fct_cmd_t),
		GET_STRUCT_SIZE(fct_i_cmd_t), GET_STRUCT_SIZE(fct_els_t) },
	{ GET_STRUCT_SIZE(fct_cmd_t),
		GET_STRUCT_SIZE(fct_i_cmd_t), GET_STRUCT_SIZE(fct_els_t) },
	{ GET_STRUCT_SIZE(fct_cmd_t),
		GET_STRUCT_SIZE(fct_i_cmd_t), GET_STRUCT_SIZE(fct_sol_ct_t) },
	{ GET_STRUCT_SIZE(fct_cmd_t), GET_STRUCT_SIZE(fct_i_cmd_t),
		GET_STRUCT_SIZE(fct_rcvd_abts_t) },
	{ GET_STRUCT_SIZE(fct_cmd_t),	/* FCT_STRUCT_CMD_FCP_XCHG */
		GET_STRUCT_SIZE(fct_i_cmd_t), 0 },
	{ GET_STRUCT_SIZE(fct_dbuf_store_t),
		GET_STRUCT_SIZE(__ifct_t), 0 }
};

void *
fct_alloc(fct_struct_id_t struct_id, int additional_size, int flags)
{
	int fct_size;
	int kmem_flag;
	__fct_t *sh;

	if ((struct_id == 0) || (struct_id >= FCT_MAX_STRUCT_IDS))
		return (NULL);

	if ((curthread->t_flag & T_INTR_THREAD) || (flags & AF_FORCE_NOSLEEP)) {
		kmem_flag = KM_NOSLEEP;
	} else {
		kmem_flag = KM_SLEEP;
	}

	additional_size = (additional_size + 7) & (~7);
	fct_size = fct_sizes[struct_id].shared +
	    fct_sizes[struct_id].fw_private +
	    fct_sizes[struct_id].struct_specific + additional_size;

	if (struct_id == FCT_STRUCT_LOCAL_PORT) {
		stmf_local_port_t *lport;

		lport = (stmf_local_port_t *)stmf_alloc(
		    STMF_STRUCT_STMF_LOCAL_PORT, fct_size, flags);
		if (lport) {
			sh = (__fct_t *)lport->lport_port_private;
			sh->ss = lport;
		} else {
			return (NULL);
		}
	} else if (struct_id == FCT_STRUCT_DBUF_STORE) {
		stmf_dbuf_store_t *ds;

		ds = (stmf_dbuf_store_t *)stmf_alloc(STMF_STRUCT_DBUF_STORE,
		    fct_size, flags);
		if (ds) {
			sh = (__fct_t *)ds->ds_port_private;
			sh->ss = ds;
		} else {
			return (NULL);
		}
	} else {
		sh = (__fct_t *)kmem_zalloc(fct_size, kmem_flag);
	}

	if (sh == NULL)
		return (NULL);

	sh->fp = (__ifct_t *)GET_BYTE_OFFSET(sh, fct_sizes[struct_id].shared);
	sh->cp = GET_BYTE_OFFSET(sh->fp, fct_sizes[struct_id].fw_private);
	if (fct_sizes[struct_id].struct_specific)
		sh->ss = GET_BYTE_OFFSET(sh->cp, additional_size);

	sh->fp->bp = sh;
	sh->fp->alloc_size = fct_size;
	sh->fp->struct_id = struct_id;

	if (struct_id == FCT_STRUCT_CMD_FCP_XCHG) {
		((fct_cmd_t *)sh)->cmd_type = FCT_CMD_FCP_XCHG;
	} else if (struct_id == FCT_STRUCT_CMD_RCVD_ELS) {
		((fct_cmd_t *)sh)->cmd_type = FCT_CMD_RCVD_ELS;
	} else if (struct_id == FCT_STRUCT_CMD_SOL_ELS) {
		((fct_cmd_t *)sh)->cmd_type = FCT_CMD_SOL_ELS;
	} else if (struct_id == FCT_STRUCT_CMD_RCVD_ABTS) {
		((fct_cmd_t *)sh)->cmd_type = FCT_CMD_RCVD_ABTS;
	} else if (struct_id == FCT_STRUCT_CMD_SOL_CT) {
		((fct_cmd_t *)sh)->cmd_type = FCT_CMD_SOL_CT;
	}

	return (sh);
}

void
fct_free(void *ptr)
{
	__fct_t *sh = (__fct_t *)ptr;
	fct_struct_id_t struct_id = sh->fp->struct_id;

	if (struct_id == FCT_STRUCT_CMD_SOL_CT) {
		fct_sol_ct_t *ct = (fct_sol_ct_t *)
		    ((fct_cmd_t *)ptr)->cmd_specific;

		if (ct->ct_req_alloc_size) {
			kmem_free(ct->ct_req_payload, ct->ct_req_alloc_size);
		}
		if (ct->ct_resp_alloc_size) {
			kmem_free(ct->ct_resp_payload, ct->ct_resp_alloc_size);
		}
	} else if ((struct_id == FCT_STRUCT_CMD_RCVD_ELS) ||
	    (struct_id == FCT_STRUCT_CMD_SOL_ELS)) {
		fct_els_t *els = (fct_els_t *)
			((fct_cmd_t *)ptr)->cmd_specific;
		if (els->els_req_alloc_size)
			kmem_free(els->els_req_payload,
				els->els_req_alloc_size);
		if (els->els_resp_alloc_size)
			kmem_free(els->els_resp_payload,
				els->els_resp_alloc_size);
	}

	if (struct_id == FCT_STRUCT_LOCAL_PORT) {
		stmf_free(((fct_local_port_t *)ptr)->port_lport);
	} else if (struct_id == FCT_STRUCT_DBUF_STORE) {
		stmf_free(((fct_dbuf_store_t *)ptr)->fds_ds);
	} else {
		kmem_free(ptr, sh->fp->alloc_size);
	}
}

stmf_data_buf_t *
fct_alloc_dbuf(scsi_task_t *task, uint32_t size, uint32_t *pminsize,
    uint32_t flags)
{
	fct_local_port_t *port = (fct_local_port_t *)
	    task->task_lport->lport_port_private;

	return (port->port_fds->fds_alloc_data_buf(port, size,
	    pminsize, flags));
}

stmf_status_t
fct_setup_dbuf(scsi_task_t *task, stmf_data_buf_t *dbuf, uint32_t flags)
{
	fct_local_port_t *port = (fct_local_port_t *)
	    task->task_lport->lport_port_private;

	ASSERT(port->port_fds->fds_setup_dbuf != NULL);
	if (port->port_fds->fds_setup_dbuf == NULL)
		return (STMF_FAILURE);

	return (port->port_fds->fds_setup_dbuf(port, dbuf, flags));
}

void
fct_teardown_dbuf(stmf_dbuf_store_t *ds, stmf_data_buf_t *dbuf)
{
	fct_dbuf_store_t *fds = ds->ds_port_private;

	fds->fds_teardown_dbuf(fds, dbuf);
}

void
fct_free_dbuf(stmf_dbuf_store_t *ds, stmf_data_buf_t *dbuf)
{
	fct_dbuf_store_t *fds;

	fds = (fct_dbuf_store_t *)ds->ds_port_private;

	fds->fds_free_data_buf(fds, dbuf);
}

static uint32_t taskq_cntr = 0;

fct_status_t
fct_register_local_port(fct_local_port_t *port)
{
	fct_i_local_port_t	*iport;
	stmf_local_port_t	*lport;
	fct_cmd_slot_t		*slot;
	int			i;
	char			taskq_name[FCT_TASKQ_NAME_LEN];

	iport = (fct_i_local_port_t *)port->port_fct_private;
	if (port->port_fca_version != FCT_FCA_MODREV_1) {
		cmn_err(CE_WARN,
		    "fct: %s driver version mismatch",
		    port->port_default_alias);
		return (FCT_FAILURE);
	}
	if (port->port_default_alias) {
		int l = strlen(port->port_default_alias);

		if (l < 16) {
			iport->iport_alias = iport->iport_alias_mem;
		} else {
			iport->iport_alias =
			    (char *)kmem_zalloc(l+1, KM_SLEEP);
		}
		(void) strcpy(iport->iport_alias, port->port_default_alias);
	} else {
		iport->iport_alias = NULL;
	}
	stmf_wwn_to_devid_desc((scsi_devid_desc_t *)iport->iport_id,
	    port->port_pwwn, PROTOCOL_FIBRE_CHANNEL);
	(void) snprintf(taskq_name, sizeof (taskq_name), "stmf_fct_taskq_%d",
	    atomic_inc_32_nv(&taskq_cntr));
	if ((iport->iport_worker_taskq = ddi_taskq_create(NULL,
	    taskq_name, 1, TASKQ_DEFAULTPRI, 0)) == NULL) {
		return (FCT_FAILURE);
	}
	mutex_init(&iport->iport_worker_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&iport->iport_worker_cv, NULL, CV_DRIVER, NULL);
	rw_init(&iport->iport_lock, NULL, RW_DRIVER, NULL);
	sema_init(&iport->iport_rls_sema, 0, NULL, SEMA_DRIVER, NULL);

	/* Remote port mgmt */
	iport->iport_rp_slots = (fct_i_remote_port_t **)kmem_zalloc(
	    port->port_max_logins * sizeof (fct_i_remote_port_t *), KM_SLEEP);
	iport->iport_rp_tb = kmem_zalloc(rportid_table_size *
	    sizeof (fct_i_remote_port_t *), KM_SLEEP);

	/* fct_cmds for SCSI traffic */
	iport->iport_total_alloced_ncmds = 0;
	iport->iport_cached_ncmds = 0;
	port->port_fca_fcp_cmd_size =
	    (port->port_fca_fcp_cmd_size + 7) & ~7;
	iport->iport_cached_cmdlist = NULL;
	mutex_init(&iport->iport_cached_cmd_lock, NULL, MUTEX_DRIVER, NULL);

	/* Initialize cmd slots */
	iport->iport_cmd_slots = (fct_cmd_slot_t *)kmem_zalloc(
	    port->port_max_xchges * sizeof (fct_cmd_slot_t), KM_SLEEP);
	iport->iport_next_free_slot = 0;
	for (i = 0; i < port->port_max_xchges; ) {
		slot = &iport->iport_cmd_slots[i];
		slot->slot_no = (uint16_t)i;
		slot->slot_next = (uint16_t)(++i);
	}
	slot->slot_next = FCT_SLOT_EOL;
	iport->iport_nslots_free = port->port_max_xchges;

	iport->iport_task_green_limit =
	    (port->port_max_xchges * FCT_TASK_GREEN_LIMIT) / 100;
	iport->iport_task_yellow_limit =
	    (port->port_max_xchges * FCT_TASK_YELLOW_LIMIT) / 100;
	iport->iport_task_red_limit =
	    (port->port_max_xchges * FCT_TASK_RED_LIMIT) / 100;

	/* Start worker thread */
	atomic_and_32(&iport->iport_flags, ~IPORT_TERMINATE_WORKER);
	(void) ddi_taskq_dispatch(iport->iport_worker_taskq,
	    fct_port_worker, port, DDI_SLEEP);
	/* Wait for taskq to start */
	while ((iport->iport_flags & IPORT_WORKER_RUNNING) == 0) {
		delay(1);
	}

	lport = port->port_lport;
	lport->lport_id = (scsi_devid_desc_t *)iport->iport_id;
	lport->lport_alias = iport->iport_alias;
	lport->lport_pp = port->port_pp;
	port->port_fds->fds_ds->ds_alloc_data_buf = fct_alloc_dbuf;
	port->port_fds->fds_ds->ds_free_data_buf = fct_free_dbuf;
	port->port_fds->fds_ds->ds_setup_dbuf = fct_setup_dbuf;
	port->port_fds->fds_ds->ds_teardown_dbuf = fct_teardown_dbuf;
	lport->lport_ds = port->port_fds->fds_ds;
	lport->lport_xfer_data = fct_xfer_scsi_data;
	lport->lport_send_status = fct_send_scsi_status;
	lport->lport_task_free = fct_scsi_task_free;
	lport->lport_abort = fct_scsi_abort;
	lport->lport_ctl = fct_ctl;
	lport->lport_info = fct_info;
	lport->lport_event_handler = fct_event_handler;
	/* set up as alua participating port */
	stmf_set_port_alua(lport);
	if (stmf_register_local_port(port->port_lport) != FCT_SUCCESS) {
		goto fct_regport_fail1;
	}
	(void) stmf_lport_add_event(lport, LPORT_EVENT_INITIAL_LUN_MAPPED);

	mutex_enter(&fct_global_mutex);
	iport->iport_next = fct_iport_list;
	iport->iport_prev = NULL;
	if (iport->iport_next)
		iport->iport_next->iport_prev = iport;
	fct_iport_list = iport;
	mutex_exit(&fct_global_mutex);

	fct_init_kstats(iport);

	fct_log_local_port_event(port, ESC_SUNFC_PORT_ATTACH);

	return (FCT_SUCCESS);

fct_regport_fail1:;
	/* Stop the taskq 1st */
	if (iport->iport_flags & IPORT_WORKER_RUNNING) {
		atomic_or_32(&iport->iport_flags, IPORT_TERMINATE_WORKER);
		cv_broadcast(&iport->iport_worker_cv);
		while (iport->iport_flags & IPORT_WORKER_RUNNING) {
			delay(1);
		}
	}
	ddi_taskq_destroy(iport->iport_worker_taskq);
	if (iport->iport_rp_tb) {
		kmem_free(iport->iport_rp_tb, rportid_table_size *
		    sizeof (fct_i_remote_port_t *));
	}
	return (FCT_FAILURE);
}

fct_status_t
fct_deregister_local_port(fct_local_port_t *port)
{
	fct_i_local_port_t	*iport;
	fct_i_cmd_t		*icmd, *next_icmd;
	int			ndx;

	iport = (fct_i_local_port_t *)port->port_fct_private;

	if ((iport->iport_state != FCT_STATE_OFFLINE) ||
	    iport->iport_state_not_acked) {
		return (FCT_FAILURE);
	}

	/* Stop the taskq 1st */
	if (iport->iport_flags & IPORT_WORKER_RUNNING) {
		atomic_or_32(&iport->iport_flags, IPORT_TERMINATE_WORKER);
		cv_broadcast(&iport->iport_worker_cv);
		for (ndx = 0; ndx < 100; ndx++) {
			if ((iport->iport_flags & IPORT_WORKER_RUNNING)
			    == 0) {
				break;
			}
			delay(drv_usectohz(10000));
		}
		if (ndx == 100) {
			atomic_and_32(&iport->iport_flags,
			    ~IPORT_TERMINATE_WORKER);
			return (FCT_WORKER_STUCK);
		}
	}

	if (stmf_deregister_local_port(port->port_lport) != FCT_SUCCESS) {
		goto fct_deregport_fail1;
	}

	mutex_enter(&fct_global_mutex);
	if (iport->iport_next)
		iport->iport_next->iport_prev = iport->iport_prev;
	if (iport->iport_prev)
		iport->iport_prev->iport_next = iport->iport_next;
	else
		fct_iport_list = iport->iport_next;
	mutex_exit(&fct_global_mutex);
	/*
	 * At this time, there should be no outstanding and pending
	 * I/Os, so we can just release resources.
	 */
	ASSERT(iport->iport_total_alloced_ncmds == iport->iport_cached_ncmds);
	for (icmd = iport->iport_cached_cmdlist; icmd; icmd = next_icmd) {
		next_icmd = icmd->icmd_next;
		fct_free(icmd->icmd_cmd);
	}
	mutex_destroy(&iport->iport_cached_cmd_lock);
	kmem_free(iport->iport_cmd_slots, port->port_max_xchges *
	    sizeof (fct_cmd_slot_t));
	kmem_free(iport->iport_rp_slots, port->port_max_logins *
	    sizeof (fct_i_remote_port_t *));
	rw_destroy(&iport->iport_lock);
	cv_destroy(&iport->iport_worker_cv);
	sema_destroy(&iport->iport_rls_sema);
	mutex_destroy(&iport->iport_worker_lock);
	ddi_taskq_destroy(iport->iport_worker_taskq);
	if (iport->iport_rp_tb) {
		kmem_free(iport->iport_rp_tb, rportid_table_size *
		    sizeof (fct_i_remote_port_t *));
	}

	if (iport->iport_kstat_portstat) {
		kstat_delete(iport->iport_kstat_portstat);
	}

	fct_log_local_port_event(port, ESC_SUNFC_PORT_DETACH);
	return (FCT_SUCCESS);

fct_deregport_fail1:;
	/* Restart the worker */
	atomic_and_32(&iport->iport_flags, ~IPORT_TERMINATE_WORKER);
	(void) ddi_taskq_dispatch(iport->iport_worker_taskq,
	    fct_port_worker, port, DDI_SLEEP);
	/* Wait for taskq to start */
	while ((iport->iport_flags & IPORT_WORKER_RUNNING) == 0) {
		delay(1);
	}
	return (FCT_FAILURE);
}

/* ARGSUSED */
void
fct_handle_event(fct_local_port_t *port, int event_id, uint32_t event_flags,
		caddr_t arg)
{
	char			info[FCT_INFO_LEN];
	fct_i_event_t		*e;
	fct_i_local_port_t	*iport = (fct_i_local_port_t *)
	    port->port_fct_private;

	e = kmem_zalloc(sizeof (fct_i_event_t), KM_NOSLEEP);

	if (e == NULL) {
		/*
		 * XXX Throw HBA fatal error event
		 */
		(void) snprintf(info, sizeof (info),
		    "fct_handle_event: iport-%p, allocation "
		    "of fct_i_event failed", (void *)iport);
		(void) fct_port_shutdown(iport->iport_port,
		    STMF_RFLAG_FATAL_ERROR | STMF_RFLAG_RESET, info);
		return;
	}
	/* Just queue the event */
	e->event_type = event_id;
	mutex_enter(&iport->iport_worker_lock);
	if (iport->iport_event_head == NULL) {
		iport->iport_event_head = iport->iport_event_tail = e;
	} else {
		iport->iport_event_tail->event_next = e;
		iport->iport_event_tail = e;
	}
	if (IS_WORKER_SLEEPING(iport))
		cv_signal(&iport->iport_worker_cv);
	mutex_exit(&iport->iport_worker_lock);
}

/*
 * Called with iport_lock held as reader.
 */
fct_i_remote_port_t *
fct_portid_to_portptr(fct_i_local_port_t *iport, uint32_t portid)
{
	fct_i_remote_port_t	*irp;

	irp = iport->iport_rp_tb[FCT_PORTID_HASH_FUNC(portid)];
	for (; irp != NULL; irp = irp->irp_next) {
		if (irp->irp_portid == portid)
			return (irp);
	}

	return (NULL);

}

/*
 * Called with irp_lock held as writer.
 */
void
fct_queue_rp(fct_i_local_port_t *iport, fct_i_remote_port_t *irp)
{
	int hash_key =
	    FCT_PORTID_HASH_FUNC(irp->irp_portid);

	irp->irp_next = iport->iport_rp_tb[hash_key];
	iport->iport_rp_tb[hash_key] = irp;
	iport->iport_nrps++;
}

/*
 * Called with irp_lock and iport_lock held as writer.
 */
void
fct_deque_rp(fct_i_local_port_t *iport, fct_i_remote_port_t *irp)
{
	fct_i_remote_port_t	*irp_next = NULL;
	fct_i_remote_port_t	*irp_last = NULL;
	int hash_key			  =
	    FCT_PORTID_HASH_FUNC(irp->irp_portid);

	irp_next = iport->iport_rp_tb[hash_key];
	irp_last = NULL;
	while (irp_next != NULL) {
		if (irp == irp_next) {
			if (irp->irp_flags & IRP_PLOGI_DONE) {
				atomic_dec_32(&iport->iport_nrps_login);
			}
			atomic_and_32(&irp->irp_flags,
			    ~(IRP_PLOGI_DONE | IRP_PRLI_DONE));
			break;
		}
		irp_last = irp_next;
		irp_next = irp_next->irp_next;
	}

	if (irp_next) {
		if (irp_last == NULL) {
			iport->iport_rp_tb[hash_key] =
			    irp->irp_next;
		} else {
			irp_last->irp_next = irp->irp_next;
		}
		irp->irp_next = NULL;
		iport->iport_nrps--;
	}
}

int
fct_is_irp_logging_out(fct_i_remote_port_t *irp, int force_implicit)
{
	int logging_out = 0;

	rw_enter(&irp->irp_lock, RW_WRITER);
	if ((irp->irp_flags & IRP_IN_DISCOVERY_QUEUE) == 0) {
		logging_out = 0;
		goto ilo_done;
	}
	if ((irp->irp_els_list == NULL) && (irp->irp_deregister_timer)) {
		if (force_implicit && irp->irp_nonfcp_xchg_count) {
			logging_out = 0;
		} else {
			logging_out = 1;
		}
		goto ilo_done;
	}
	if (irp->irp_els_list) {
		fct_i_cmd_t *icmd;
		/* Last session affecting ELS should be a LOGO */
		for (icmd = irp->irp_els_list; icmd; icmd = icmd->icmd_next) {
			uint8_t op = (ICMD_TO_ELS(icmd))->els_req_payload[0];
			if (op == ELS_OP_LOGO) {
				if (force_implicit) {
					if (icmd->icmd_flags & ICMD_IMPLICIT)
						logging_out = 1;
					else
						logging_out = 0;
				} else {
					logging_out = 1;
				}
			} else if ((op == ELS_OP_PLOGI) ||
			    (op == ELS_OP_PRLI) ||
			    (op == ELS_OP_PRLO) || (op == ELS_OP_TPRLO)) {
				logging_out = 0;
			}
		}
	}
ilo_done:;
	rw_exit(&irp->irp_lock);

	return (logging_out);
}

/*
 * The force_implicit flag enforces the implicit semantics which may be
 * needed if a received logout got stuck e.g. a response to a received
 * LOGO never came back from the FCA.
 */
int
fct_implicitly_logo_all(fct_i_local_port_t *iport, int force_implicit)
{
	fct_i_remote_port_t	*irp = NULL;
	fct_cmd_t		*cmd = NULL;
	int			 i   = 0;
	int			nports = 0;

	if (!iport->iport_nrps) {
		return (nports);
	}

	rw_enter(&iport->iport_lock, RW_WRITER);
	for (i = 0; i < rportid_table_size; i++) {
		irp = iport->iport_rp_tb[i];
		while (irp) {
			if ((!(irp->irp_flags & IRP_PLOGI_DONE)) &&
			    (fct_is_irp_logging_out(irp, force_implicit))) {
				irp = irp->irp_next;
				continue;
			}

			cmd = fct_create_solels(iport->iport_port, irp->irp_rp,
			    1, ELS_OP_LOGO, 0, fct_logo_cb);
			if (cmd == NULL) {
				stmf_trace(iport->iport_alias,
				    "fct_implictly_logo_all: cmd null");
				rw_exit(&iport->iport_lock);

				return (nports);
			}

			fct_post_implicit_logo(cmd);
			nports++;
			irp = irp->irp_next;
		}
	}
	rw_exit(&iport->iport_lock);

	return (nports);
}

void
fct_rehash(fct_i_local_port_t *iport)
{
	fct_i_remote_port_t **iport_rp_tb_tmp;
	fct_i_remote_port_t **iport_rp_tb_new;
	fct_i_remote_port_t *irp;
	fct_i_remote_port_t *irp_next;
	int i;

	iport_rp_tb_new = kmem_zalloc(rportid_table_size *
	    sizeof (fct_i_remote_port_t *), KM_SLEEP);
	rw_enter(&iport->iport_lock, RW_WRITER);
	/* reconstruct the hash table */
	iport_rp_tb_tmp = iport->iport_rp_tb;
	iport->iport_rp_tb = iport_rp_tb_new;
	iport->iport_nrps = 0;
	for (i = 0; i < rportid_table_size; i++) {
		irp = iport_rp_tb_tmp[i];
		while (irp) {
			irp_next = irp->irp_next;
			fct_queue_rp(iport, irp);
			irp = irp_next;
		}
	}
	rw_exit(&iport->iport_lock);
	kmem_free(iport_rp_tb_tmp, rportid_table_size *
	    sizeof (fct_i_remote_port_t *));

}

uint8_t
fct_local_port_cleanup_done(fct_i_local_port_t *iport)
{
	fct_i_remote_port_t *irp;
	int i;

	if (iport->iport_nrps_login)
		return (0);
	/* loop all rps to check if the cmd have already been drained */
	for (i = 0; i < rportid_table_size; i++) {
		irp = iport->iport_rp_tb[i];
		while (irp) {
			if (irp->irp_fcp_xchg_count ||
			    irp->irp_nonfcp_xchg_count)
				return (0);
			irp = irp->irp_next;
		}
	}
	return (1);
}

fct_cmd_t *
fct_scsi_task_alloc(fct_local_port_t *port, uint16_t rp_handle,
		uint32_t rportid, uint8_t *lun, uint16_t cdb_length,
		uint16_t task_ext)
{
	fct_cmd_t *cmd;
	fct_i_cmd_t *icmd;
	fct_i_local_port_t *iport =
	    (fct_i_local_port_t *)port->port_fct_private;
	fct_i_remote_port_t *irp;
	scsi_task_t *task;
	fct_remote_port_t *rp;
	uint16_t cmd_slot;

	rw_enter(&iport->iport_lock, RW_READER);
	if ((iport->iport_link_state & S_LINK_ONLINE) == 0) {
		rw_exit(&iport->iport_lock);
		stmf_trace(iport->iport_alias, "cmd alloc called while the port"
		    " was offline");
		return (NULL);
	}

	if (rp_handle == FCT_HANDLE_NONE) {
		irp = fct_portid_to_portptr(iport, rportid);
		if (irp == NULL) {
			rw_exit(&iport->iport_lock);
			stmf_trace(iport->iport_alias, "cmd received from "
			    "non existent port %x", rportid);
			return (NULL);
		}
	} else {
		if ((rp_handle >= port->port_max_logins) ||
		    ((irp = iport->iport_rp_slots[rp_handle]) == NULL)) {
			rw_exit(&iport->iport_lock);
			stmf_trace(iport->iport_alias, "cmd received from "
			    "invalid port handle %x", rp_handle);
			return (NULL);
		}
	}
	rp = irp->irp_rp;

	rw_enter(&irp->irp_lock, RW_READER);
	if ((irp->irp_flags & IRP_PRLI_DONE) == 0) {
		rw_exit(&irp->irp_lock);
		rw_exit(&iport->iport_lock);
		stmf_trace(iport->iport_alias, "cmd alloc called while fcp "
		    "login was not done. portid=%x, rp=%p", rp->rp_id, rp);
		return (NULL);
	}

	mutex_enter(&iport->iport_cached_cmd_lock);
	if ((icmd = iport->iport_cached_cmdlist) != NULL) {
		iport->iport_cached_cmdlist = icmd->icmd_next;
		iport->iport_cached_ncmds--;
		cmd = icmd->icmd_cmd;
	} else {
		icmd = NULL;
	}
	mutex_exit(&iport->iport_cached_cmd_lock);
	if (icmd == NULL) {
		cmd = (fct_cmd_t *)fct_alloc(FCT_STRUCT_CMD_FCP_XCHG,
		    port->port_fca_fcp_cmd_size, 0);
		if (cmd == NULL) {
			rw_exit(&irp->irp_lock);
			rw_exit(&iport->iport_lock);
			stmf_trace(iport->iport_alias, "Ran out of "
			    "memory, port=%p", port);
			return (NULL);
		}

		icmd = (fct_i_cmd_t *)cmd->cmd_fct_private;
		icmd->icmd_next = NULL;
		cmd->cmd_port = port;
		atomic_inc_32(&iport->iport_total_alloced_ncmds);
	}

	/*
	 * The accuracy of iport_max_active_ncmds is not important
	 */
	if ((iport->iport_total_alloced_ncmds - iport->iport_cached_ncmds) >
	    iport->iport_max_active_ncmds) {
		iport->iport_max_active_ncmds =
		    iport->iport_total_alloced_ncmds -
		    iport->iport_cached_ncmds;
	}

	/* Lets get a slot */
	cmd_slot = fct_alloc_cmd_slot(iport, cmd);
	if (cmd_slot == FCT_SLOT_EOL) {
		rw_exit(&irp->irp_lock);
		rw_exit(&iport->iport_lock);
		stmf_trace(iport->iport_alias, "Ran out of xchg resources");
		cmd->cmd_handle = 0;
		fct_cmd_free(cmd);
		return (NULL);
	}
	atomic_inc_16(&irp->irp_fcp_xchg_count);
	cmd->cmd_rp = rp;
	icmd->icmd_flags |= ICMD_IN_TRANSITION | ICMD_KNOWN_TO_FCA;
	rw_exit(&irp->irp_lock);
	rw_exit(&iport->iport_lock);

	icmd->icmd_start_time = ddi_get_lbolt();

	cmd->cmd_specific = stmf_task_alloc(port->port_lport, irp->irp_session,
	    lun, cdb_length, task_ext);
	if ((task = (scsi_task_t *)cmd->cmd_specific) != NULL) {
		task->task_port_private = cmd;
		return (cmd);
	}

	fct_cmd_free(cmd);

	return (NULL);
}

void
fct_scsi_task_free(scsi_task_t *task)
{
	fct_cmd_t *cmd = (fct_cmd_t *)task->task_port_private;

	cmd->cmd_comp_status = task->task_completion_status;
	fct_cmd_free(cmd);
}

void
fct_post_rcvd_cmd(fct_cmd_t *cmd, stmf_data_buf_t *dbuf)
{
	fct_dbuf_store_t *fds;

	if (cmd->cmd_type == FCT_CMD_FCP_XCHG) {
		fct_i_cmd_t *icmd = (fct_i_cmd_t *)cmd->cmd_fct_private;
		fct_i_local_port_t *iport =
		    (fct_i_local_port_t *)cmd->cmd_port->port_fct_private;
		fct_i_remote_port_t *irp =
		    (fct_i_remote_port_t *)cmd->cmd_rp->rp_fct_private;
		scsi_task_t *task = (scsi_task_t *)cmd->cmd_specific;

		uint16_t irp_task = irp->irp_fcp_xchg_count;
		uint32_t load = iport->iport_total_alloced_ncmds -
		    iport->iport_cached_ncmds;

		DTRACE_FC_4(scsi__command,
		    fct_cmd_t, cmd,
		    fct_i_local_port_t, iport,
		    scsi_task_t, task,
		    fct_i_remote_port_t, irp);

		if (load >= iport->iport_task_green_limit) {
			if ((load < iport->iport_task_yellow_limit &&
			    irp_task >= 4) ||
			    (load >= iport->iport_task_yellow_limit &&
			    load < iport->iport_task_red_limit &&
			    irp_task >= 1) ||
			    (load >= iport->iport_task_red_limit))
				task->task_additional_flags |=
				    TASK_AF_PORT_LOAD_HIGH;
		}
		/*
		 * If the target driver accepts sglists, fill in task fields.
		 */
		fds = cmd->cmd_port->port_fds;
		if (fds->fds_setup_dbuf != NULL) {
			task->task_additional_flags |= TASK_AF_ACCEPT_LU_DBUF;
			task->task_copy_threshold = fds->fds_copy_threshold;
			task->task_max_xfer_len = fds->fds_max_sgl_xfer_len;
			/*
			 * A single stream load encounters a little extra
			 * latency if large xfers are done in 1 chunk.
			 * Give a hint to the LU that starting the xfer
			 * with a smaller chunk would be better in this case.
			 * For any other load, use maximum chunk size.
			 */
			if (load == 1) {
				/* estimate */
				task->task_1st_xfer_len = 128*1024;
			} else {
				/* zero means no hint */
				task->task_1st_xfer_len = 0;
			}
		}

		stmf_post_task((scsi_task_t *)cmd->cmd_specific, dbuf);
		atomic_and_32(&icmd->icmd_flags, ~ICMD_IN_TRANSITION);
		return;
	}
	/* We dont need dbuf for other cmds */
	if (dbuf) {
		cmd->cmd_port->port_fds->fds_free_data_buf(
		    cmd->cmd_port->port_fds, dbuf);
		dbuf = NULL;
	}
	if (cmd->cmd_type == FCT_CMD_RCVD_ELS) {
		fct_handle_els(cmd);
		return;
	}
	if (cmd->cmd_type == FCT_CMD_RCVD_ABTS) {
		fct_handle_rcvd_abts(cmd);
		return;
	}

	ASSERT(0);
}

/*
 * This function bypasses fct_handle_els()
 */
void
fct_post_implicit_logo(fct_cmd_t *cmd)
{
	fct_local_port_t *port = cmd->cmd_port;
	fct_i_local_port_t *iport =
	    (fct_i_local_port_t *)port->port_fct_private;
	fct_i_cmd_t *icmd = (fct_i_cmd_t *)cmd->cmd_fct_private;
	fct_remote_port_t *rp = cmd->cmd_rp;
	fct_i_remote_port_t *irp = (fct_i_remote_port_t *)rp->rp_fct_private;

	icmd->icmd_start_time = ddi_get_lbolt();

	rw_enter(&irp->irp_lock, RW_WRITER);
	atomic_or_32(&icmd->icmd_flags, ICMD_IMPLICIT_CMD_HAS_RESOURCE);
	atomic_inc_16(&irp->irp_nonfcp_xchg_count);
	atomic_inc_16(&irp->irp_sa_elses_count);
	/*
	 * An implicit LOGO can also be posted to a irp where a PLOGI might
	 * be in process. That PLOGI will reset this flag and decrement the
	 * iport_nrps_login counter.
	 */
	if (irp->irp_flags & IRP_PLOGI_DONE) {
		atomic_dec_32(&iport->iport_nrps_login);
	}
	atomic_and_32(&irp->irp_flags, ~(IRP_PLOGI_DONE | IRP_PRLI_DONE));
	atomic_or_32(&icmd->icmd_flags, ICMD_SESSION_AFFECTING);
	fct_post_to_discovery_queue(iport, irp, icmd);
	rw_exit(&irp->irp_lock);
}

/*
 * called with iport_lock held, return the slot number
 */
uint16_t
fct_alloc_cmd_slot(fct_i_local_port_t *iport, fct_cmd_t *cmd)
{
	uint16_t cmd_slot;
	uint32_t old, new;
	fct_i_cmd_t *icmd = (fct_i_cmd_t *)cmd->cmd_fct_private;

	do {
		old = iport->iport_next_free_slot;
		cmd_slot = old & 0xFFFF;
		if (cmd_slot == FCT_SLOT_EOL)
			return (cmd_slot);
		/*
		 * We use high order 16 bits as a counter which keeps on
		 * incrementing to avoid ABA issues with atomic lists.
		 */
		new = ((old + (0x10000)) & 0xFFFF0000);
		new |= iport->iport_cmd_slots[cmd_slot].slot_next;
	} while (atomic_cas_32(&iport->iport_next_free_slot, old, new) != old);

	atomic_dec_16(&iport->iport_nslots_free);
	iport->iport_cmd_slots[cmd_slot].slot_cmd = icmd;
	cmd->cmd_handle = (uint32_t)cmd_slot | 0x80000000 |
	    (((uint32_t)(iport->iport_cmd_slots[cmd_slot].slot_uniq_cntr))
	    << 24);
	return (cmd_slot);
}

/*
 * If icmd is not NULL, irp_lock must be held
 */
void
fct_post_to_discovery_queue(fct_i_local_port_t *iport,
    fct_i_remote_port_t *irp, fct_i_cmd_t *icmd)
{
	fct_i_cmd_t	**p;

	ASSERT(!MUTEX_HELD(&iport->iport_worker_lock));
	if (icmd) {
		icmd->icmd_next = NULL;
		for (p = &irp->irp_els_list; *p != NULL;
		    p = &((*p)->icmd_next))
			;

		*p = icmd;
		atomic_or_32(&icmd->icmd_flags, ICMD_IN_IRP_QUEUE);
	}

	mutex_enter(&iport->iport_worker_lock);
	if ((irp->irp_flags & IRP_IN_DISCOVERY_QUEUE) == 0) {

		/*
		 * CAUTION: do not grab local_port/remote_port locks after
		 * grabbing the worker lock.
		 */
		irp->irp_discovery_next = NULL;
		if (iport->iport_rpwe_tail) {
			iport->iport_rpwe_tail->irp_discovery_next = irp;
			iport->iport_rpwe_tail = irp;
		} else {
			iport->iport_rpwe_head = iport->iport_rpwe_tail = irp;
		}

		atomic_or_32(&irp->irp_flags, IRP_IN_DISCOVERY_QUEUE);
	}

	/*
	 * We need always signal the port worker irrespective of the fact that
	 * irp is already in discovery queue or not.
	 */
	if (IS_WORKER_SLEEPING(iport)) {
		cv_signal(&iport->iport_worker_cv);
	}
	mutex_exit(&iport->iport_worker_lock);
}

stmf_status_t
fct_xfer_scsi_data(scsi_task_t *task, stmf_data_buf_t *dbuf, uint32_t ioflags)
{
	fct_cmd_t *cmd = (fct_cmd_t *)task->task_port_private;

	DTRACE_FC_5(xfer__start,
	    fct_cmd_t, cmd,
	    fct_i_local_port_t, cmd->cmd_port->port_fct_private,
	    scsi_task_t, task,
	    fct_i_remote_port_t, cmd->cmd_rp->rp_fct_private,
	    stmf_data_buf_t, dbuf);

	return (cmd->cmd_port->port_xfer_scsi_data(cmd, dbuf, ioflags));
}

void
fct_scsi_data_xfer_done(fct_cmd_t *cmd, stmf_data_buf_t *dbuf, uint32_t ioflags)
{
	fct_i_cmd_t	*icmd = (fct_i_cmd_t *)cmd->cmd_fct_private;
	uint32_t	old, new;
	uint32_t	iof = 0;

	DTRACE_FC_5(xfer__done,
	    fct_cmd_t, cmd,
	    fct_i_local_port_t, cmd->cmd_port->port_fct_private,
	    scsi_task_t, ((scsi_task_t *)cmd->cmd_specific),
	    fct_i_remote_port_t, cmd->cmd_rp->rp_fct_private,
	    stmf_data_buf_t, dbuf);

	if (ioflags & FCT_IOF_FCA_DONE) {
		do {
			old = new = icmd->icmd_flags;
			if (old & ICMD_BEING_ABORTED) {
				return;
			}
			new &= ~ICMD_KNOWN_TO_FCA;
		} while (atomic_cas_32(&icmd->icmd_flags, old, new) != old);
		iof = STMF_IOF_LPORT_DONE;
		cmd->cmd_comp_status = dbuf->db_xfer_status;
	}

	if (icmd->icmd_flags & ICMD_BEING_ABORTED)
		return;
	stmf_data_xfer_done((scsi_task_t *)cmd->cmd_specific, dbuf, iof);
}

stmf_status_t
fct_send_scsi_status(scsi_task_t *task, uint32_t ioflags)
{
	fct_cmd_t *cmd = (fct_cmd_t *)task->task_port_private;

	DTRACE_FC_4(scsi__response,
	    fct_cmd_t, cmd,
	    fct_i_local_port_t,
	    (fct_i_local_port_t *)cmd->cmd_port->port_fct_private,
	    scsi_task_t, task,
	    fct_i_remote_port_t,
	    (fct_i_remote_port_t *)cmd->cmd_rp->rp_fct_private);

	return (cmd->cmd_port->port_send_cmd_response(cmd, ioflags));
}

void
fct_send_response_done(fct_cmd_t *cmd, fct_status_t s, uint32_t ioflags)
{
	fct_i_cmd_t	*icmd = (fct_i_cmd_t *)cmd->cmd_fct_private;
	fct_local_port_t *port = cmd->cmd_port;
	fct_i_local_port_t *iport = (fct_i_local_port_t *)
	    port->port_fct_private;
	uint32_t old, new;

	if ((ioflags & FCT_IOF_FCA_DONE) == 0) {
		/* Until we support confirmed completions, this is an error */
		fct_queue_cmd_for_termination(cmd, s);
		return;
	}
	do {
		old = new = icmd->icmd_flags;
		if (old & ICMD_BEING_ABORTED) {
			return;
		}
		new &= ~ICMD_KNOWN_TO_FCA;
	} while (atomic_cas_32(&icmd->icmd_flags, old, new) != old);

	cmd->cmd_comp_status = s;
	if (cmd->cmd_type == FCT_CMD_FCP_XCHG) {
		stmf_send_status_done((scsi_task_t *)cmd->cmd_specific, s,
		    STMF_IOF_LPORT_DONE);
		return;
	}

	if (cmd->cmd_type == FCT_CMD_RCVD_ELS) {
		fct_cmd_free(cmd);
		return;
	} else if (cmd->cmd_type == FCT_CMD_SOL_ELS) {
		fct_handle_sol_els_completion(iport, icmd);
	} else if (cmd->cmd_type == FCT_CMD_SOL_CT) {
		/* Tell the caller that we are done */
		atomic_or_32(&icmd->icmd_flags, ICMD_CMD_COMPLETE);
	} else {
		ASSERT(0);
	}
}

void
fct_cmd_free(fct_cmd_t *cmd)
{
	char			info[FCT_INFO_LEN];
	fct_i_cmd_t		*icmd = (fct_i_cmd_t *)cmd->cmd_fct_private;
	fct_local_port_t	*port = cmd->cmd_port;
	fct_i_local_port_t	*iport = (fct_i_local_port_t *)
	    port->port_fct_private;
	fct_i_remote_port_t	*irp = NULL;
	int			do_abts_acc = 0;
	uint32_t		old, new;

	ASSERT(!mutex_owned(&iport->iport_worker_lock));
	/* Give the slot back */
	if (CMD_HANDLE_VALID(cmd->cmd_handle)) {
		uint16_t n = CMD_HANDLE_SLOT_INDEX(cmd->cmd_handle);
		fct_cmd_slot_t *slot;

		/*
		 * If anything went wrong, grab the lock as writer. This is
		 * probably unnecessary.
		 */
		if ((cmd->cmd_comp_status != FCT_SUCCESS) ||
		    (icmd->icmd_flags & ICMD_ABTS_RECEIVED)) {
			rw_enter(&iport->iport_lock, RW_WRITER);
		} else {
			rw_enter(&iport->iport_lock, RW_READER);
		}

		if ((icmd->icmd_flags & ICMD_ABTS_RECEIVED) &&
		    (cmd->cmd_link != NULL)) {
			do_abts_acc = 1;
		}

		/* XXX Validate slot before freeing */

		slot = &iport->iport_cmd_slots[n];
		slot->slot_uniq_cntr++;
		slot->slot_cmd = NULL;
		do {
			old = iport->iport_next_free_slot;
			slot->slot_next = old & 0xFFFF;
			new = (old + 0x10000) & 0xFFFF0000;
			new |= slot->slot_no;
		} while (atomic_cas_32(&iport->iport_next_free_slot,
		    old, new) != old);
		cmd->cmd_handle = 0;
		atomic_inc_16(&iport->iport_nslots_free);
		if (cmd->cmd_rp) {
			irp = (fct_i_remote_port_t *)
			    cmd->cmd_rp->rp_fct_private;
			if (cmd->cmd_type == FCT_CMD_FCP_XCHG)
				atomic_dec_16(&irp->irp_fcp_xchg_count);
			else
				atomic_dec_16(&irp->irp_nonfcp_xchg_count);
		}
		rw_exit(&iport->iport_lock);
	} else if ((icmd->icmd_flags & ICMD_IMPLICIT) &&
	    (icmd->icmd_flags & ICMD_IMPLICIT_CMD_HAS_RESOURCE)) {
		/* for implicit cmd, no cmd slot is used */
		if (cmd->cmd_rp) {
			irp = (fct_i_remote_port_t *)
			    cmd->cmd_rp->rp_fct_private;
			if (cmd->cmd_type == FCT_CMD_FCP_XCHG)
				atomic_dec_16(&irp->irp_fcp_xchg_count);
			else
				atomic_dec_16(&irp->irp_nonfcp_xchg_count);
		}
	}

	if (do_abts_acc) {
		fct_cmd_t *lcmd = cmd->cmd_link;
		fct_fill_abts_acc(lcmd);
		if (port->port_send_cmd_response(lcmd,
		    FCT_IOF_FORCE_FCA_DONE) != FCT_SUCCESS) {
			/*
			 * XXX Throw HBA fatal error event
			 * Later shutdown svc will terminate the ABTS in the end
			 */
			(void) snprintf(info, sizeof (info),
			    "fct_cmd_free: iport-%p, ABTS_ACC"
			    " port_send_cmd_response failed", (void *)iport);
			(void) fct_port_shutdown(iport->iport_port,
			    STMF_RFLAG_FATAL_ERROR | STMF_RFLAG_RESET, info);
			return;
		} else {
			fct_cmd_free(lcmd);
			cmd->cmd_link = NULL;
		}
	}

	/* Free the cmd */
	if (cmd->cmd_type == FCT_CMD_FCP_XCHG) {
		if (iport->iport_cached_ncmds < max_cached_ncmds) {
			icmd->icmd_flags = 0;
			mutex_enter(&iport->iport_cached_cmd_lock);
			icmd->icmd_next = iport->iport_cached_cmdlist;
			iport->iport_cached_cmdlist = icmd;
			iport->iport_cached_ncmds++;
			mutex_exit(&iport->iport_cached_cmd_lock);
		} else {
			atomic_dec_32(&iport->iport_total_alloced_ncmds);
			fct_free(cmd);
		}
	} else {
		fct_free(cmd);
	}
}

/* ARGSUSED */
stmf_status_t
fct_scsi_abort(stmf_local_port_t *lport, int abort_cmd, void *arg,
							uint32_t flags)
{
	stmf_status_t ret = STMF_SUCCESS;
	scsi_task_t *task;
	fct_cmd_t *cmd;
	fct_i_cmd_t *icmd;
	fct_local_port_t *port;
	uint32_t old, new;

	ASSERT(abort_cmd == STMF_LPORT_ABORT_TASK);

	task = (scsi_task_t *)arg;
	cmd = (fct_cmd_t *)task->task_port_private;
	icmd = (fct_i_cmd_t *)cmd->cmd_fct_private;
	port = (fct_local_port_t *)lport->lport_port_private;

	do {
		old = new = icmd->icmd_flags;
		if ((old & ICMD_KNOWN_TO_FCA) == 0)
			return (STMF_NOT_FOUND);
		ASSERT((old & ICMD_FCA_ABORT_CALLED) == 0);
		new |= ICMD_BEING_ABORTED | ICMD_FCA_ABORT_CALLED;
	} while (atomic_cas_32(&icmd->icmd_flags, old, new) != old);
	ret = port->port_abort_cmd(port, cmd, 0);
	if ((ret == FCT_NOT_FOUND) || (ret == FCT_ABORT_SUCCESS)) {
		atomic_and_32(&icmd->icmd_flags, ~ICMD_KNOWN_TO_FCA);
	} else if (ret == FCT_BUSY) {
		atomic_and_32(&icmd->icmd_flags, ~ICMD_FCA_ABORT_CALLED);
	}

	return (ret);
}

void
fct_ctl(struct stmf_local_port *lport, int cmd, void *arg)
{
	fct_local_port_t *port;
	fct_i_local_port_t *iport;
	stmf_change_status_t st;
	stmf_change_status_t *pst;

	ASSERT((cmd == STMF_CMD_LPORT_ONLINE) ||
	    (cmd == STMF_ACK_LPORT_ONLINE_COMPLETE) ||
	    (cmd == STMF_CMD_LPORT_OFFLINE) ||
	    (cmd == STMF_ACK_LPORT_OFFLINE_COMPLETE) ||
	    (cmd == FCT_CMD_PORT_ONLINE_COMPLETE) ||
	    (cmd == FCT_CMD_PORT_OFFLINE_COMPLETE));

	port = (fct_local_port_t *)lport->lport_port_private;
	pst = (stmf_change_status_t *)arg;
	st.st_completion_status = STMF_SUCCESS;
	st.st_additional_info = NULL;

	iport = (fct_i_local_port_t *)port->port_fct_private;
	/*
	 * We are mostly a passthrough, except during offline.
	 */
	switch (cmd) {
	case STMF_CMD_LPORT_ONLINE:
		if (iport->iport_state == FCT_STATE_ONLINE)
			st.st_completion_status = STMF_ALREADY;
		else if (iport->iport_state != FCT_STATE_OFFLINE)
			st.st_completion_status = STMF_INVALID_ARG;
		if (st.st_completion_status != STMF_SUCCESS) {
			(void) stmf_ctl(STMF_CMD_LPORT_ONLINE_COMPLETE, lport,
			    &st);
			break;
		}
		iport->iport_state_not_acked = 1;
		iport->iport_state = FCT_STATE_ONLINING;
		port->port_ctl(port, FCT_CMD_PORT_ONLINE, arg);
		break;
	case FCT_CMD_PORT_ONLINE_COMPLETE:
		ASSERT(iport->iport_state == FCT_STATE_ONLINING);
		if (pst->st_completion_status != FCT_SUCCESS) {
			iport->iport_state = FCT_STATE_OFFLINE;
			iport->iport_state_not_acked = 0;
		} else {
			iport->iport_state = FCT_STATE_ONLINE;
		}
		(void) stmf_ctl(STMF_CMD_LPORT_ONLINE_COMPLETE, lport, arg);
		break;
	case STMF_ACK_LPORT_ONLINE_COMPLETE:
		ASSERT(iport->iport_state == FCT_STATE_ONLINE);
		iport->iport_state_not_acked = 0;
		port->port_ctl(port, FCT_ACK_PORT_ONLINE_COMPLETE, arg);
		break;

	case STMF_CMD_LPORT_OFFLINE:
		if (iport->iport_state == FCT_STATE_OFFLINE)
			st.st_completion_status = STMF_ALREADY;
		else if (iport->iport_state != FCT_STATE_ONLINE)
			st.st_completion_status = STMF_INVALID_ARG;
		if (st.st_completion_status != STMF_SUCCESS) {
			(void) stmf_ctl(STMF_CMD_LPORT_OFFLINE_COMPLETE, lport,
			    &st);
			break;
		}
		iport->iport_state_not_acked = 1;
		iport->iport_state = FCT_STATE_OFFLINING;
		port->port_ctl(port, FCT_CMD_PORT_OFFLINE, arg);
		break;
	case FCT_CMD_PORT_OFFLINE_COMPLETE:
		ASSERT(iport->iport_state == FCT_STATE_OFFLINING);
		if (pst->st_completion_status != FCT_SUCCESS) {
			iport->iport_state = FCT_STATE_ONLINE;
			iport->iport_state_not_acked = 0;
			(void) stmf_ctl(STMF_CMD_LPORT_OFFLINE_COMPLETE, lport,
			    pst);
			break;
		}

		/*
		 * If FCA's offline was successful, we dont tell stmf yet.
		 * Becasue now we have to do the cleanup before we go upto
		 * stmf. That cleanup is done by the worker thread.
		 */

		/* FCA is offline, post a link down, its harmless anyway */
		fct_handle_event(port, FCT_EVENT_LINK_DOWN, 0, 0);

		/* Trigger port offline processing by the worker */
		iport->iport_offline_prstate = FCT_OPR_START;
		break;
	case STMF_ACK_LPORT_OFFLINE_COMPLETE:
		ASSERT(iport->iport_state == FCT_STATE_OFFLINE);
		iport->iport_state_not_acked = 0;
		port->port_ctl(port, FCT_ACK_PORT_OFFLINE_COMPLETE, arg);
		break;
	}
}

/* ARGSUSED */
stmf_status_t
fct_info(uint32_t cmd, stmf_local_port_t *lport, void *arg, uint8_t *buf,
						uint32_t *bufsizep)
{
	return (STMF_NOT_SUPPORTED);
}

/*
 * implicit: if it's true, it means it will only be used in fct module, or else
 * it will be sent to the link.
 */
fct_cmd_t *
fct_create_solels(fct_local_port_t *port, fct_remote_port_t *rp, int implicit,
    uchar_t elsop, uint32_t wkdid, fct_icmd_cb_t icmdcb)
{
	fct_cmd_t		*cmd	= NULL;
	fct_i_cmd_t		*icmd	= NULL;
	fct_els_t		*els	= NULL;
	fct_i_remote_port_t	*irp	= NULL;
	uint8_t			*p	= NULL;
	uint32_t		 ptid	= 0;

	cmd = (fct_cmd_t *)fct_alloc(FCT_STRUCT_CMD_SOL_ELS,
	    port->port_fca_sol_els_private_size, 0);
	if (!cmd) {
		return (NULL);
	}

	if (rp) {
		irp = RP_TO_IRP(rp);
	} else if (((irp = fct_portid_to_portptr(PORT_TO_IPORT(port),
	    wkdid)) == NULL) && (elsop != ELS_OP_PLOGI)) {
		stmf_trace(PORT_TO_IPORT(port)->iport_alias,
		    "fct_create_solels: Must PLOGI to %x first", wkdid);
		fct_free(cmd);
		return (NULL);
	}

	cmd->cmd_port	= port;
	cmd->cmd_oxid	= PTR2INT(cmd, uint16_t);
	cmd->cmd_rxid	= 0xFFFF;
	cmd->cmd_handle = 0;
	icmd		= CMD_TO_ICMD(cmd);
	els		= ICMD_TO_ELS(icmd);
	icmd->icmd_cb	= icmdcb;
	if (irp) {
		cmd->cmd_rp	   = irp->irp_rp;
		cmd->cmd_rp_handle = irp->irp_rp->rp_handle;
		cmd->cmd_rportid   = irp->irp_rp->rp_id;
	} else {
		cmd->cmd_rp_handle = FCT_HANDLE_NONE;
		cmd->cmd_rportid   = wkdid;
	}
	cmd->cmd_lportid = (PORT_TO_IPORT(port))->iport_link_info.portid;

	if (implicit) {
		/*
		 * Since we will not send it to FCA, so we only allocate space
		 */
		ASSERT(elsop & (ELS_OP_LOGO | ELS_OP_PLOGI));
		icmd->icmd_flags |= ICMD_IMPLICIT;
		if (elsop == ELS_OP_LOGO) {
			/*
			 * Handling implicit LOGO should dependent on as less
			 * as resources. So a trick here.
			 */
			els->els_req_size = 1;
			els->els_req_payload = cmd->cmd_fca_private;
		} else {
			els->els_req_alloc_size = els->els_req_size = 116;
			els->els_resp_alloc_size = els->els_resp_size = 116;
			els->els_req_payload = (uint8_t *)
			    kmem_zalloc(els->els_req_size, KM_SLEEP);
			els->els_resp_payload = (uint8_t *)
			    kmem_zalloc(els->els_resp_size, KM_SLEEP);
		}
	} else {
		/*
		 * Allocate space for its request and response
		 * Fill the request payload according to spec.
		 */
		switch (elsop) {
		case ELS_OP_LOGO:
			els->els_resp_alloc_size = els->els_resp_size = 4;
			els->els_resp_payload = (uint8_t *)kmem_zalloc(
			    els->els_resp_size, KM_SLEEP);
			els->els_req_alloc_size = els->els_req_size = 16;
			els->els_req_payload = (uint8_t *)kmem_zalloc(
			    els->els_req_size, KM_SLEEP);
			ptid = PORT_TO_IPORT(port)->iport_link_info.portid;
			fct_value_to_netbuf(ptid, els->els_req_payload + 5, 3);
			bcopy(port->port_pwwn, els->els_req_payload + 8, 8);
			break;

		case ELS_OP_RSCN:
			els->els_resp_alloc_size = els->els_resp_size = 4;
			els->els_resp_payload = (uint8_t *)kmem_zalloc(
			    els->els_resp_size, KM_SLEEP);
			els->els_req_size = els->els_req_alloc_size = 8;
			els->els_req_payload = (uint8_t *)kmem_zalloc(
			    els->els_req_size, KM_SLEEP);
			els->els_req_payload[1] = 0x04;
			els->els_req_payload[3] = 0x08;
			els->els_req_payload[4] |= 0x80;
			ptid = PORT_TO_IPORT(port)->iport_link_info.portid;
			fct_value_to_netbuf(ptid, els->els_req_payload + 5, 3);
			break;

		case ELS_OP_PLOGI:
			els->els_resp_alloc_size = els->els_resp_size = 116;
			els->els_resp_payload = (uint8_t *)
			    kmem_zalloc(els->els_resp_size, KM_SLEEP);
			els->els_req_alloc_size = els->els_req_size = 116;
			p = els->els_req_payload = (uint8_t *)
			    kmem_zalloc(els->els_req_size, KM_SLEEP);
			bcopy(port->port_pwwn, p + 20, 8);
			bcopy(port->port_nwwn, p + 28, 8);

			/*
			 * Common service parameters
			 */
			p[0x04] = 0x09;		/* high version */
			p[0x05] = 0x08;		/* low version */
			p[0x06] = 0x00;		/* BB credit: 0x0065 */
			p[0x07] = 0x65;

			/* CI0: Continuously Increasing Offset - 1 */
			/* RRO: Randomly Relative Offset - 0 */
			/* VVV: Vendor Version Level - 0 */
			/* N-F: N or F Port Payload Sender - 0 (N) */
			/* BBM: BB Credit Management - 0 (Normal) */
			p[0x08] = 0x80;
			p[0x09] = 0x00;

			/* Max RX size */
			p[0x0A] = 0x08;
			p[0x0B] = 0x00;

			/* NPTCS: N Port Total Concurrent Sequences - 0x0000 */
			p[0x0C] = 0x00;
			p[0x0D] = 0x00;

			/* ROIC: Relative Offset By Info - 0xFFFF */
			p[0x0E] = 0xFF;
			p[0x0F] = 0xFF;

			/* EDTOV: Error Detect Timeout - 0x000007D0 */
			p[0x10] = 0x00;
			p[0x11] = 0x00;
			p[0x12] = 0x07;
			p[0x13] = 0xD0;

			/*
			 * Class-3 Parameters
			 */
			/* C3-VAL: Class 3 Value - 1 */
			/* C3-XID: X_ID Reassignment - 0 */
			/* C3-IPA: Initial Process Assignment */
			/* C3-AI-DCC: Data compression capable */
			/* C3-AI-DC-HB: Data compression history buffer size */
			/* C3-AI-DCE: Data encrytion capable */
			/* C3-AI-CSC: Clock synchronization capable */
			/* C3-ErrPol: Error pliciy */
			/* C3-CatSeq: Information Cat. Per Sequence */
			/* C3-AR-DCC: */
			/* C3-AR-DC-HB: */
			/* C3-AR-DCE: */
			/* C3-AR-CSC */
			p[0x44] = 0x80;
			p[0x45] = 0x00;
			p[0x46] = 0x00;
			p[0x47] = 0x00;
			p[0x48] = 0x00;
			p[0x49] = 0x00;

			/* C3-RxSize: Class 3 receive data size */
			p[0x4A] = 0x08;
			p[0x4B] = 0x00;

			/* C3-ConSeq: Class 3 Concourrent sequences */
			p[0x4C] = 0x00;
			p[0x4D] = 0xFF;

			/* C3-OSPE: Class 3 open sequence per exchange */
			p[0x50] = 0x00;
			p[0x51] = 0x01;

			break;

		case ELS_OP_SCR:
			els->els_resp_alloc_size = els->els_resp_size = 4;
			els->els_resp_payload = (uint8_t *)
			    kmem_zalloc(els->els_resp_size, KM_SLEEP);
			els->els_req_alloc_size = els->els_req_size = 8;
			p = els->els_req_payload = (uint8_t *)
			    kmem_zalloc(els->els_req_size, KM_SLEEP);
			p[7] = FC_SCR_FULL_REGISTRATION;
			break;
		case ELS_OP_RLS:
			els->els_resp_alloc_size = els->els_resp_size = 28;
			els->els_resp_payload = (uint8_t *)
			    kmem_zalloc(els->els_resp_size, KM_SLEEP);
			els->els_req_alloc_size = els->els_req_size = 8;
			p = els->els_req_payload = (uint8_t *)
			    kmem_zalloc(els->els_req_size, KM_SLEEP);
			ptid = PORT_TO_IPORT(port)->iport_link_info.portid;
			fct_value_to_netbuf(ptid, els->els_req_payload + 5, 3);
			break;

		default:
			ASSERT(0);
		}
	}

	els->els_req_payload[0] = elsop;
	return (cmd);
}

fct_cmd_t *
fct_create_solct(fct_local_port_t *port, fct_remote_port_t *query_rp,
    uint16_t ctop, fct_icmd_cb_t icmdcb)
{
	fct_cmd_t		*cmd	 = NULL;
	fct_i_cmd_t		*icmd	 = NULL;
	fct_sol_ct_t		*ct	 = NULL;
	uint8_t			*p	 = NULL;
	fct_i_remote_port_t	*irp	 = NULL;
	fct_i_local_port_t	*iport	 = NULL;
	char			*nname	 = NULL;
	int			 namelen = 0;

	/*
	 * Allocate space
	 */
	cmd = fct_alloc(FCT_STRUCT_CMD_SOL_CT,
	    port->port_fca_sol_ct_private_size, 0);
	if (!cmd) {
		return (NULL);
	}

	/*
	 * We should have PLOGIed to the name server (0xFFFFFC)
	 * Caution: this irp is not query_rp->rp_fct_private.
	 */
	irp = fct_portid_to_portptr((fct_i_local_port_t *)
	    port->port_fct_private, FS_NAME_SERVER);
	if (irp == NULL) {
		stmf_trace(PORT_TO_IPORT(port)->iport_alias,
		    "fct_create_solct: Must PLOGI name server first");
		fct_free(cmd);
		return (NULL);
	}

	cmd->cmd_port	   = port;
	cmd->cmd_rp	   = irp->irp_rp;
	cmd->cmd_rp_handle = irp->irp_rp->rp_handle;
	cmd->cmd_rportid   = irp->irp_rp->rp_id;
	cmd->cmd_lportid   = (PORT_TO_IPORT(port))->iport_link_info.portid;
	cmd->cmd_oxid	   = PTR2INT(cmd, uint16_t);
	cmd->cmd_rxid	   = 0xFFFF;
	cmd->cmd_handle	   = 0;
	icmd		   = CMD_TO_ICMD(cmd);
	ct		   = ICMD_TO_CT(icmd);
	icmd->icmd_cb	   = icmdcb;
	iport		   = ICMD_TO_IPORT(icmd);

	switch (ctop) {
	case NS_GSNN_NN:
		/*
		 * Allocate max space for its sybolic name
		 */
		ct->ct_resp_alloc_size = ct->ct_resp_size = 272;
		ct->ct_resp_payload = (uint8_t *)kmem_zalloc(ct->ct_resp_size,
		    KM_SLEEP);

		ct->ct_req_size = ct->ct_req_alloc_size = 24;
		p = ct->ct_req_payload = (uint8_t *)kmem_zalloc(ct->ct_req_size,
		    KM_SLEEP);

		bcopy(query_rp->rp_nwwn, p + 16, 8);
		break;

	case NS_RNN_ID:
		ct->ct_resp_alloc_size = ct->ct_resp_size = 16;
		ct->ct_resp_payload = (uint8_t *)kmem_zalloc(ct->ct_resp_size,
		    KM_SLEEP);
		ct->ct_req_size = ct->ct_req_alloc_size = 28;
		p = ct->ct_req_payload = (uint8_t *)kmem_zalloc(ct->ct_req_size,
		    KM_SLEEP);

		/*
		 * Port Identifier
		 */
		p[17] = (iport->iport_link_info.portid >> 16) & 0xFF;
		p[18] = (iport->iport_link_info.portid >>  8) & 0xFF;
		p[19] = (iport->iport_link_info.portid >>  0) & 0xFF;

		/*
		 * Node Name
		 */
		bcopy(port->port_nwwn, p + 20, 8);
		break;

	case NS_RCS_ID:
		ct->ct_resp_alloc_size = ct->ct_resp_size = 16;
		ct->ct_resp_payload = (uint8_t *)kmem_zalloc(ct->ct_resp_size,
		    KM_SLEEP);
		ct->ct_req_size = ct->ct_req_alloc_size = 24;
		p = ct->ct_req_payload = (uint8_t *)kmem_zalloc(ct->ct_req_size,
		    KM_SLEEP);

		/*
		 * Port Identifier
		 */
		p[17] = (iport->iport_link_info.portid >> 16) & 0xFF;
		p[18] = (iport->iport_link_info.portid >>  8) & 0xFF;
		p[19] = (iport->iport_link_info.portid >>  0) & 0xFF;

		/*
		 * Class of Service
		 */
		*(p + 23) = FC_NS_CLASS3;
		break;

	case NS_RFT_ID:
		ct->ct_resp_alloc_size = ct->ct_resp_size = 16;
		ct->ct_resp_payload = (uint8_t *)kmem_zalloc(ct->ct_resp_size,
		    KM_SLEEP);
		ct->ct_req_size = ct->ct_req_alloc_size = 52;
		p = ct->ct_req_payload = (uint8_t *)kmem_zalloc(ct->ct_req_size,
		    KM_SLEEP);

		/*
		 * Port Identifier
		 */
		p[17] = (iport->iport_link_info.portid >> 16) & 0xFF;
		p[18] = (iport->iport_link_info.portid >>  8) & 0xFF;
		p[19] = (iport->iport_link_info.portid >>  0) & 0xFF;

		/*
		 * FC-4 Protocol Types
		 */
		*(p + 22) = 0x1;	/* 0x100 */
		break;

	case NS_RSPN_ID:
		/*
		 * If we get here, port->port_sym_port_name is always not NULL.
		 */
		ASSERT(port->port_sym_port_name);
		namelen = strlen(port->port_sym_port_name);
		ct->ct_resp_alloc_size = ct->ct_resp_size = 16;
		ct->ct_resp_payload = (uint8_t *)kmem_zalloc(ct->ct_resp_size,
		    KM_SLEEP);
		ct->ct_req_size = ct->ct_req_alloc_size =
		    (21 + namelen + 3) & ~3;
		p = ct->ct_req_payload = (uint8_t *)kmem_zalloc(ct->ct_req_size,
		    KM_SLEEP);

		/*
		 * Port Identifier
		 */
		p[17] = (iport->iport_link_info.portid >> 16) & 0xFF;
		p[18] = (iport->iport_link_info.portid >>  8) & 0xFF;
		p[19] = (iport->iport_link_info.portid >>  0) & 0xFF;

		/*
		 * String length
		 */
		p[20] = namelen;

		/*
		 * Symbolic port name
		 */
		bcopy(port->port_sym_port_name, p + 21, ct->ct_req_size - 21);
		break;

	case NS_RSNN_NN:
		namelen = port->port_sym_node_name == NULL ?
		    strlen(utsname.nodename) :
		    strlen(port->port_sym_node_name);
		nname = port->port_sym_node_name == NULL ?
		    utsname.nodename : port->port_sym_node_name;

		ct->ct_resp_alloc_size = ct->ct_resp_size = 16;
		ct->ct_resp_payload = (uint8_t *)kmem_zalloc(ct->ct_resp_size,
		    KM_SLEEP);
		ct->ct_req_size = ct->ct_req_alloc_size =
		    (25 + namelen + 3) & ~3;
		p = ct->ct_req_payload = (uint8_t *)kmem_zalloc(ct->ct_req_size,
		    KM_SLEEP);

		/*
		 * Node name
		 */
		bcopy(port->port_nwwn, p + 16, 8);

		/*
		 * String length
		 */
		p[24] = namelen;

		/*
		 * Symbolic node name
		 */
		bcopy(nname, p + 25, ct->ct_req_size - 25);
		break;

	case NS_GSPN_ID:
		ct->ct_resp_alloc_size = ct->ct_resp_size = 272;
		ct->ct_resp_payload = (uint8_t *)kmem_zalloc(ct->ct_resp_size,
		    KM_SLEEP);
		ct->ct_req_size = ct->ct_req_alloc_size = 20;
		p = ct->ct_req_payload = (uint8_t *)kmem_zalloc(ct->ct_req_size,
		    KM_SLEEP);
		/*
		 * Port Identifier
		 */
		p[17] = (query_rp->rp_id >> 16) & 0xFF;
		p[18] = (query_rp->rp_id >>  8) & 0xFF;
		p[19] = (query_rp->rp_id >>  0) & 0xFF;
		break;

	case NS_GCS_ID:
		ct->ct_resp_alloc_size = ct->ct_resp_size = 20;
		ct->ct_resp_payload = (uint8_t *)kmem_zalloc(ct->ct_resp_size,
		    KM_SLEEP);
		ct->ct_req_size = ct->ct_req_alloc_size = 20;
		p = ct->ct_req_payload = (uint8_t *)kmem_zalloc(ct->ct_req_size,
		    KM_SLEEP);
		/*
		 * Port Identifier
		 */
		p[17] = (query_rp->rp_id >> 16) & 0xFF;
		p[18] = (query_rp->rp_id >>  8) & 0xFF;
		p[19] = (query_rp->rp_id >>  0) & 0xFF;
		break;

	case NS_GFT_ID:
		ct->ct_resp_alloc_size = ct->ct_resp_size = 48;
		ct->ct_resp_payload = (uint8_t *)kmem_zalloc(ct->ct_resp_size,
		    KM_SLEEP);
		ct->ct_req_size = ct->ct_req_alloc_size = 20;
		p = ct->ct_req_payload = (uint8_t *)kmem_zalloc(ct->ct_req_size,
		    KM_SLEEP);
		/*
		 * Port Identifier
		 */
		p[17] = (query_rp->rp_id >> 16) & 0xFF;
		p[18] = (query_rp->rp_id >>  8) & 0xFF;
		p[19] = (query_rp->rp_id >>  0) & 0xFF;
		break;

	case NS_GID_PN:
		ct->ct_resp_alloc_size = ct->ct_resp_size = 20;
		ct->ct_resp_payload = (uint8_t *)kmem_zalloc(ct->ct_resp_size,
		    KM_SLEEP);

		ct->ct_req_size = ct->ct_req_alloc_size = 24;
		p = ct->ct_req_payload = (uint8_t *)kmem_zalloc(ct->ct_req_size,
		    KM_SLEEP);

		bcopy(query_rp->rp_pwwn, p + 16, 8);
		break;

	default:
		/* CONSTCOND */
		ASSERT(0);
	}

	FCT_FILL_CTIU_PREAMBLE(p, ctop);
	return (cmd);
}

/*
 * Cmd can only be solicited CT/ELS. They will be dispatched to the discovery
 * queue eventually too.
 * We queue solicited cmds here to track solicited cmds and to take full use
 * of single thread mechanism.
 * But in current implmentation, we don't use  this mechanism on SOL_CT, PLOGI.
 * To avoid to interrupt current flow, ICMD_IN_SOLCMD_QUEUE is used here.
 */
void
fct_post_to_solcmd_queue(fct_local_port_t *port, fct_cmd_t *cmd)
{
	fct_i_local_port_t	*iport	= (fct_i_local_port_t *)
	    port->port_fct_private;
	fct_i_cmd_t *icmd		= (fct_i_cmd_t *)cmd->cmd_fct_private;

	mutex_enter(&iport->iport_worker_lock);
	icmd->icmd_solcmd_next = iport->iport_solcmd_queue;
	iport->iport_solcmd_queue = icmd;
	atomic_or_32(&icmd->icmd_flags, ICMD_IN_SOLCMD_QUEUE | ICMD_SOLCMD_NEW);
	if (IS_WORKER_SLEEPING(iport)) {
		cv_signal(&iport->iport_worker_cv);
	}
	mutex_exit(&iport->iport_worker_lock);
}

/* ARGSUSED */
void
fct_event_handler(stmf_local_port_t *lport, int eventid, void *arg,
    uint32_t flags)
{
	fct_local_port_t	*port  = (fct_local_port_t *)
	    lport->lport_port_private;
	fct_i_local_port_t	*iport = (fct_i_local_port_t *)
	    port->port_fct_private;
	stmf_scsi_session_t	*ss;
	fct_i_remote_port_t	*irp;

	switch (eventid) {
	case LPORT_EVENT_INITIAL_LUN_MAPPED:
		ss = (stmf_scsi_session_t *)arg;
		irp = (fct_i_remote_port_t *)ss->ss_port_private;
		stmf_trace(iport->iport_alias,
		    "Initial LUN mapped to session ss-%p, irp-%p", ss, irp);
		break;

	default:
		stmf_trace(iport->iport_alias,
		    "Unknown event received, %d", eventid);
	}
}

void
fct_send_cmd_done(fct_cmd_t *cmd, fct_status_t s, uint32_t ioflags)
{
	/* XXX For now just call send_resp_done() */
	fct_send_response_done(cmd, s, ioflags);
}

void
fct_cmd_fca_aborted(fct_cmd_t *cmd, fct_status_t s, uint32_t ioflags)
{
	fct_i_cmd_t		*icmd = (fct_i_cmd_t *)cmd->cmd_fct_private;
	char			info[FCT_INFO_LEN];
	unsigned long long	st;

	st = s;	/* To make gcc happy */
	ASSERT(icmd->icmd_flags & ICMD_BEING_ABORTED);
	if ((((s != FCT_ABORT_SUCCESS) && (s != FCT_NOT_FOUND))) ||
	    ((ioflags & FCT_IOF_FCA_DONE) == 0)) {
		(void) snprintf(info, sizeof (info),
		    "fct_cmd_fca_aborted: cmd-%p, "
		    "s-%llx, iofalgs-%x", (void *)cmd, st, ioflags);
		(void) fct_port_shutdown(cmd->cmd_port,
		    STMF_RFLAG_FATAL_ERROR | STMF_RFLAG_RESET, info);
		return;
	}

	atomic_and_32(&icmd->icmd_flags, ~ICMD_KNOWN_TO_FCA);
	/* For non FCP Rest of the work is done by the terminator */
	/* For FCP stuff just call stmf */
	if (cmd->cmd_type == FCT_CMD_FCP_XCHG) {
		stmf_task_lport_aborted((scsi_task_t *)cmd->cmd_specific,
		    s, STMF_IOF_LPORT_DONE);
	}
}

/*
 * FCA drivers will use it, when they want to abort some FC transactions
 * due to lack of resource.
 */
uint16_t
fct_get_rp_handle(fct_local_port_t *port, uint32_t rportid)
{
	fct_i_remote_port_t	*irp;

	irp = fct_portid_to_portptr(
	    (fct_i_local_port_t *)(port->port_fct_private), rportid);
	if (irp == NULL) {
		return (0xFFFF);
	} else {
		return (irp->irp_rp->rp_handle);
	}
}

fct_cmd_t *
fct_handle_to_cmd(fct_local_port_t *port, uint32_t fct_handle)
{
	fct_cmd_slot_t *slot;
	uint16_t ndx;

	if (!CMD_HANDLE_VALID(fct_handle))
		return (NULL);
	if ((ndx = CMD_HANDLE_SLOT_INDEX(fct_handle)) >= port->port_max_xchges)
		return (NULL);

	slot = &((fct_i_local_port_t *)port->port_fct_private)->iport_cmd_slots[
	    ndx];

	if ((slot->slot_uniq_cntr | 0x80) != (fct_handle >> 24))
		return (NULL);
	return (slot->slot_cmd->icmd_cmd);
}

void
fct_queue_scsi_task_for_termination(fct_cmd_t *cmd, fct_status_t s)
{
	fct_i_cmd_t *icmd = (fct_i_cmd_t *)cmd->cmd_fct_private;

	uint32_t old, new;

	do {
		old = icmd->icmd_flags;
		if ((old & (ICMD_BEING_ABORTED | ICMD_KNOWN_TO_FCA)) !=
		    ICMD_KNOWN_TO_FCA)
			return;
		new = old | ICMD_BEING_ABORTED;
	} while (atomic_cas_32(&icmd->icmd_flags, old, new) != old);
	stmf_abort(STMF_QUEUE_TASK_ABORT, (scsi_task_t *)cmd->cmd_specific,
	    s, NULL);
}

void
fct_fill_abts_acc(fct_cmd_t *cmd)
{
	fct_rcvd_abts_t *abts = (fct_rcvd_abts_t *)cmd->cmd_specific;
	uint8_t *p;

	abts->abts_resp_rctl = BLS_OP_BA_ACC;
	p = abts->abts_resp_payload;
	bzero(p, 12);
	*((uint16_t *)(p+4)) = BE_16(cmd->cmd_oxid);
	*((uint16_t *)(p+6)) = BE_16(cmd->cmd_rxid);
	p[10] = p[11] = 0xff;
}

void
fct_handle_rcvd_abts(fct_cmd_t *cmd)
{
	char			info[FCT_INFO_LEN];
	fct_local_port_t	*port = cmd->cmd_port;
	fct_i_local_port_t	*iport =
	    (fct_i_local_port_t *)port->port_fct_private;
	fct_i_cmd_t		*icmd = (fct_i_cmd_t *)cmd->cmd_fct_private;
	fct_i_remote_port_t	*irp;
	fct_cmd_t		*c = NULL;
	fct_i_cmd_t		*ic = NULL;
	int			found = 0;
	int			i;

	icmd->icmd_start_time = ddi_get_lbolt();
	icmd->icmd_flags |= ICMD_KNOWN_TO_FCA;

	rw_enter(&iport->iport_lock, RW_WRITER);
	/* Make sure local port is sane */
	if ((iport->iport_link_state & S_LINK_ONLINE) == 0) {
		rw_exit(&iport->iport_lock);
		stmf_trace(iport->iport_alias, "ABTS not posted becasue"
		    "port state was %x", iport->iport_link_state);
		fct_queue_cmd_for_termination(cmd, FCT_LOCAL_PORT_OFFLINE);
		return;
	}

	if (cmd->cmd_rp_handle == FCT_HANDLE_NONE)
		irp = fct_portid_to_portptr(iport, cmd->cmd_rportid);
	else if (cmd->cmd_rp_handle < port->port_max_logins)
		irp = iport->iport_rp_slots[cmd->cmd_rp_handle];
	else
		irp = NULL;
	if (irp == NULL) {
		/* XXX Throw a logout to the initiator */
		rw_exit(&iport->iport_lock);
		stmf_trace(iport->iport_alias, "ABTS received from"
		    " %x without a session", cmd->cmd_rportid);
		fct_queue_cmd_for_termination(cmd, FCT_NOT_LOGGED_IN);
		return;
	}

	DTRACE_FC_3(abts__receive,
	    fct_cmd_t, cmd,
	    fct_local_port_t, port,
	    fct_i_remote_port_t, irp);

	cmd->cmd_rp = irp->irp_rp;

	/*
	 * No need to allocate an xchg resource. ABTSes use the same
	 * xchg resource as the cmd they are aborting.
	 */
	rw_enter(&irp->irp_lock, RW_WRITER);
	mutex_enter(&iport->iport_worker_lock);
	/* Lets find the command first */
	for (i = 0; i < port->port_max_xchges; i++) {
		if ((ic = iport->iport_cmd_slots[i].slot_cmd) == NULL)
			continue;
		if ((ic->icmd_flags & ICMD_KNOWN_TO_FCA) == 0)
			continue;
		c = ic->icmd_cmd;
		if (!CMD_HANDLE_VALID(c->cmd_handle))
			continue;
		if ((c->cmd_rportid != cmd->cmd_rportid) ||
		    (c->cmd_oxid != cmd->cmd_oxid))
			continue;
		/* Found the command */
		found = 1;
		break;
	}
	if (!found) {
		mutex_exit(&iport->iport_worker_lock);
		rw_exit(&irp->irp_lock);
		rw_exit(&iport->iport_lock);
		/* Dont even bother queueing it. Just respond */
		fct_fill_abts_acc(cmd);
		if (port->port_send_cmd_response(cmd,
		    FCT_IOF_FORCE_FCA_DONE) != FCT_SUCCESS) {
			/*
			 * XXX Throw HBA fatal error event
			 * Later shutdown svc will terminate the ABTS in the end
			 */
			(void) snprintf(info, sizeof (info),
			    "fct_handle_rcvd_abts: iport-%p, "
			    "ABTS_ACC port_send_cmd_response failed",
			    (void *)iport);
			(void) fct_port_shutdown(iport->iport_port,
			    STMF_RFLAG_FATAL_ERROR | STMF_RFLAG_RESET, info);
		} else {
			fct_cmd_free(cmd);
		}
		return;
	}

	/* Check if this an abts retry */
	if (c->cmd_link && (ic->icmd_flags & ICMD_ABTS_RECEIVED)) {
		/* Kill this abts. */
		fct_q_for_termination_lock_held(iport, icmd, FCT_ABORTED);
		if (IS_WORKER_SLEEPING(iport))
			cv_signal(&iport->iport_worker_cv);
		mutex_exit(&iport->iport_worker_lock);
		rw_exit(&irp->irp_lock);
		rw_exit(&iport->iport_lock);
		return;
	}
	c->cmd_link = cmd;
	atomic_or_32(&ic->icmd_flags, ICMD_ABTS_RECEIVED);
	cmd->cmd_link = c;
	mutex_exit(&iport->iport_worker_lock);
	rw_exit(&irp->irp_lock);
	fct_queue_cmd_for_termination(c, FCT_ABTS_RECEIVED);
	rw_exit(&iport->iport_lock);
}

void
fct_queue_cmd_for_termination(fct_cmd_t *cmd, fct_status_t s)
{
	fct_local_port_t *port = cmd->cmd_port;
	fct_i_local_port_t *iport = (fct_i_local_port_t *)
	    port->port_fct_private;
	fct_i_cmd_t *icmd = (fct_i_cmd_t *)cmd->cmd_fct_private;

	if (cmd->cmd_type == FCT_CMD_FCP_XCHG) {
		fct_queue_scsi_task_for_termination(cmd, s);
		return;
	}
	mutex_enter(&iport->iport_worker_lock);
	fct_q_for_termination_lock_held(iport, icmd, s);
	if (IS_WORKER_SLEEPING(iport))
		cv_signal(&iport->iport_worker_cv);
	mutex_exit(&iport->iport_worker_lock);
}

/*
 * This function will not be called for SCSI CMDS
 */
void
fct_q_for_termination_lock_held(fct_i_local_port_t *iport, fct_i_cmd_t *icmd,
		fct_status_t s)
{
	uint32_t old, new;
	fct_i_cmd_t **ppicmd;

	do {
		old = icmd->icmd_flags;
		if (old & ICMD_BEING_ABORTED)
			return;
		new = old | ICMD_BEING_ABORTED;
	} while (atomic_cas_32(&icmd->icmd_flags, old, new) != old);

	icmd->icmd_start_time = ddi_get_lbolt();
	icmd->icmd_cmd->cmd_comp_status = s;

	icmd->icmd_next = NULL;
	for (ppicmd = &(iport->iport_abort_queue); *ppicmd != NULL;
	    ppicmd = &((*ppicmd)->icmd_next))
		;

	*ppicmd = icmd;
}

/*
 * For those cmds, for which we called fca_abort but it has not yet completed,
 * reset the FCA_ABORT_CALLED flag, so that abort can be called again.
 * This is done after a FCA offline. The reason is that after offline, the
 * firmware is not running so abort will never complete. But if we call it
 * again, the FCA will detect that it is not offline and it will
 * not call the firmware at all. Most likely it will abort in a synchronous
 * manner i.e. return FCT_ABORT_SUCCESS or FCT_NOT_FOUND.
 */
void
fct_reset_flag_abort_called(fct_i_local_port_t *iport)
{
	fct_i_cmd_t *icmd;
	uint32_t old, new;
	int i, do_clear;

	ASSERT(mutex_owned(&iport->iport_worker_lock));
	mutex_exit(&iport->iport_worker_lock);
	rw_enter(&iport->iport_lock, RW_WRITER);
	mutex_enter(&iport->iport_worker_lock);

	for (i = 0; i < iport->iport_port->port_max_xchges; i++) {
		if (iport->iport_cmd_slots[i].slot_cmd == NULL)
			continue;

		icmd = iport->iport_cmd_slots[i].slot_cmd;

		do {
			old = new = icmd->icmd_flags;
			if ((old & (ICMD_KNOWN_TO_FCA |
			    ICMD_FCA_ABORT_CALLED)) == (ICMD_KNOWN_TO_FCA |
			    ICMD_FCA_ABORT_CALLED)) {
				new &= ~ICMD_FCA_ABORT_CALLED;
				do_clear = 1;
			} else {
				do_clear = 0;
				break;
			}
		} while (atomic_cas_32(&icmd->icmd_flags, old, new) != old);
		if (do_clear &&
		    (icmd->icmd_cmd->cmd_type == FCT_CMD_FCP_XCHG)) {
			stmf_abort(STMF_REQUEUE_TASK_ABORT_LPORT,
			    icmd->icmd_cmd->cmd_specific, 0, NULL);
		}
	}

	rw_exit(&iport->iport_lock);
}

/*
 * Modify the irp_deregister_timer such that the ports start deregistering
 * quickly.
 */
void
fct_irp_deregister_speedup(fct_i_local_port_t *iport)
{
	fct_i_remote_port_t *irp;
	int i;

	if (!iport->iport_nrps)
		return;

	for (i = 0; i < rportid_table_size; i++) {
		irp = iport->iport_rp_tb[i];
		while (irp) {
			irp->irp_deregister_timer = ddi_get_lbolt() - 1;
			irp = irp->irp_next;
		}
	}
}

disc_action_t
fct_handle_port_offline(fct_i_local_port_t *iport)
{
	if (iport->iport_offline_prstate == FCT_OPR_START) {
		fct_reset_flag_abort_called(iport);
		iport->iport_offline_prstate = FCT_OPR_CMD_CLEANUP_WAIT;
		/* fct_ctl has already submitted a link offline event */
		return (DISC_ACTION_DELAY_RESCAN);
	}
	if (iport->iport_offline_prstate == FCT_OPR_CMD_CLEANUP_WAIT) {
		if (iport->iport_link_state != PORT_STATE_LINK_DOWN)
			return (DISC_ACTION_DELAY_RESCAN);
		/*
		 * All I/Os have been killed at this time. Lets speedup
		 * the port deregister process.
		 */
		mutex_exit(&iport->iport_worker_lock);
		rw_enter(&iport->iport_lock, RW_WRITER);
		fct_irp_deregister_speedup(iport);
		rw_exit(&iport->iport_lock);
		mutex_enter(&iport->iport_worker_lock);
		iport->iport_offline_prstate = FCT_OPR_INT_CLEANUP_WAIT;
		return (DISC_ACTION_RESCAN);
	}
	if (iport->iport_offline_prstate == FCT_OPR_INT_CLEANUP_WAIT) {
		stmf_change_status_t st;

		if (iport->iport_solcmd_queue) {
			return (DISC_ACTION_DELAY_RESCAN);
		}

		if (iport->iport_nrps) {
			/*
			 * A port logout may have gone when implicit logo all
			 * was retried. So do the port speedup again here.
			 */
			mutex_exit(&iport->iport_worker_lock);
			rw_enter(&iport->iport_lock, RW_WRITER);
			fct_irp_deregister_speedup(iport);
			rw_exit(&iport->iport_lock);
			mutex_enter(&iport->iport_worker_lock);
			return (DISC_ACTION_DELAY_RESCAN);
		}

		if (iport->iport_event_head != NULL) {
			return (DISC_ACTION_DELAY_RESCAN);
		}

		st.st_completion_status = STMF_SUCCESS;
		st.st_additional_info = NULL;
		iport->iport_offline_prstate = FCT_OPR_DONE;
		iport->iport_state = FCT_STATE_OFFLINE;
		mutex_exit(&iport->iport_worker_lock);
		(void) stmf_ctl(STMF_CMD_LPORT_OFFLINE_COMPLETE,
		    iport->iport_port->port_lport, &st);
		mutex_enter(&iport->iport_worker_lock);
		return (DISC_ACTION_DELAY_RESCAN);
	}

	/* NOTREACHED */
	return (0);
}

/*
 * See stmf.h for information on rflags. Additional info is just a text
 * description of the reason for this call. Additional_info can be NULL.
 * Also the caller can declare additional info on the stack. stmf_ctl
 * makes a copy of it before returning.
 */
fct_status_t
fct_port_initialize(fct_local_port_t *port, uint32_t rflags,
				char *additional_info)
{
	stmf_state_change_info_t st;

	st.st_rflags = rflags;
	st.st_additional_info = additional_info;
	stmf_trace(NULL, "fct_port_initialize: port-%p, %s", port,
	    additional_info? additional_info : "no more information");
	return (stmf_ctl(STMF_CMD_LPORT_ONLINE, port->port_lport, &st));
}

fct_status_t
fct_port_shutdown(fct_local_port_t *port, uint32_t rflags,
				char *additional_info)
{
	stmf_state_change_info_t st;

	st.st_rflags = rflags;
	st.st_additional_info = additional_info;
	stmf_trace(NULL, "fct_port_shutdown: port-%p, %s", port,
	    additional_info? additional_info : "no more information");
	return (stmf_ctl(STMF_CMD_LPORT_OFFLINE, port->port_lport, &st));
}

/*
 * Called by worker thread. The aim is to terminate the command
 * using whatever means it takes.
 * Called with worker lock held.
 */
disc_action_t
fct_cmd_terminator(fct_i_local_port_t *iport)
{
	char			info[FCT_INFO_LEN];
	clock_t			endtime;
	fct_i_cmd_t		**ppicmd;
	fct_i_cmd_t		*icmd;
	fct_cmd_t		*cmd;
	fct_local_port_t	*port = iport->iport_port;
	disc_action_t		ret = DISC_ACTION_NO_WORK;
	fct_status_t		abort_ret;
	int			fca_done, fct_done, cmd_implicit = 0;
	int			flags;
	unsigned long long	st;

	/* Lets Limit each run to 20ms max. */
	endtime = ddi_get_lbolt() + drv_usectohz(20000);

	/* Start from where we left off last time */
	if (iport->iport_ppicmd_term) {
		ppicmd = iport->iport_ppicmd_term;
		iport->iport_ppicmd_term = NULL;
	} else {
		ppicmd = &iport->iport_abort_queue;
	}

	/*
	 * Once a command gets on discovery queue, this is the only thread
	 * which can access it. So no need for the lock here.
	 */
	mutex_exit(&iport->iport_worker_lock);

	while ((icmd = *ppicmd) != NULL) {
		cmd = icmd->icmd_cmd;

		/* Always remember that cmd->cmd_rp can be NULL */
		if ((icmd->icmd_flags & (ICMD_KNOWN_TO_FCA |
		    ICMD_FCA_ABORT_CALLED)) == ICMD_KNOWN_TO_FCA) {
			atomic_or_32(&icmd->icmd_flags, ICMD_FCA_ABORT_CALLED);
			if (CMD_HANDLE_VALID(cmd->cmd_handle))
				flags = 0;
			else
				flags = FCT_IOF_FORCE_FCA_DONE;
			abort_ret = port->port_abort_cmd(port, cmd, flags);
			if ((abort_ret != FCT_SUCCESS) &&
			    (abort_ret != FCT_ABORT_SUCCESS) &&
			    (abort_ret != FCT_NOT_FOUND)) {
				if (flags & FCT_IOF_FORCE_FCA_DONE) {
					/*
					 * XXX trigger port fatal,
					 * Abort the termination, and shutdown
					 * svc will trigger fct_cmd_termination
					 * again.
					 */
					(void) snprintf(info, sizeof (info),
					    "fct_cmd_terminator:"
					    " iport-%p, port_abort_cmd with "
					    "FORCE_FCA_DONE failed",
					    (void *)iport);
					(void) fct_port_shutdown(
					    iport->iport_port,
					    STMF_RFLAG_FATAL_ERROR |
					    STMF_RFLAG_RESET, info);

					mutex_enter(&iport->iport_worker_lock);
					iport->iport_ppicmd_term = ppicmd;
					return (DISC_ACTION_DELAY_RESCAN);
				}
				atomic_and_32(&icmd->icmd_flags,
				    ~ICMD_FCA_ABORT_CALLED);
			} else if ((flags & FCT_IOF_FORCE_FCA_DONE) ||
			    (abort_ret == FCT_ABORT_SUCCESS) ||
			    (abort_ret == FCT_NOT_FOUND)) {
				atomic_and_32(&icmd->icmd_flags,
				    ~ICMD_KNOWN_TO_FCA);
			}
			ret |= DISC_ACTION_DELAY_RESCAN;
		} else if (icmd->icmd_flags & ICMD_IMPLICIT) {
			if (cmd->cmd_type == FCT_CMD_SOL_ELS)
				cmd->cmd_comp_status = FCT_ABORTED;
			atomic_or_32(&icmd->icmd_flags, ICMD_FCA_ABORT_CALLED);
			cmd_implicit = 1;
		}
		if ((icmd->icmd_flags & ICMD_KNOWN_TO_FCA) == 0)
			fca_done = 1;
		else
			fca_done = 0;
		if ((icmd->icmd_flags & ICMD_IN_IRP_QUEUE) == 0)
			fct_done = 1;
		else
			fct_done = 0;
		if ((fca_done || cmd_implicit) && fct_done) {
			mutex_enter(&iport->iport_worker_lock);
			ASSERT(*ppicmd == icmd);
			*ppicmd = (*ppicmd)->icmd_next;
			mutex_exit(&iport->iport_worker_lock);
			if ((cmd->cmd_type == FCT_CMD_RCVD_ELS) ||
			    (cmd->cmd_type == FCT_CMD_RCVD_ABTS)) {
				/* Free the cmd */
				fct_cmd_free(cmd);
			} else if (cmd->cmd_type == FCT_CMD_SOL_ELS) {
				fct_handle_sol_els_completion(iport, icmd);
				if (icmd->icmd_flags & ICMD_IMPLICIT) {
					if (IS_LOGO_ELS(icmd)) {
						/* IMPLICIT LOGO is special */
						fct_cmd_free(cmd);
					}
				}
			} else if (cmd->cmd_type == FCT_CMD_SOL_CT) {
				fct_sol_ct_t *ct = ICMD_TO_CT(icmd);

				/* Tell the caller that we are done */
				atomic_or_32(&icmd->icmd_flags,
				    ICMD_CMD_COMPLETE);
				if (fct_netbuf_to_value(
				    ct->ct_req_payload + 8, 2) == NS_GID_PN) {
					fct_i_remote_port_t *irp;

					rw_enter(&iport->iport_lock, RW_READER);
					irp = fct_lookup_irp_by_portwwn(iport,
					    ct->ct_req_payload + 16);

					if (irp) {
						atomic_and_32(&irp->irp_flags,
						    ~IRP_RSCN_QUEUED);
					}
					rw_exit(&iport->iport_lock);
				}
			} else {
				ASSERT(0);
			}
		} else {
			clock_t	timeout_ticks;
			if (port->port_fca_abort_timeout)
				timeout_ticks = drv_usectohz(
				    port->port_fca_abort_timeout*1000);
			else
				/* 10 seconds by default */
				timeout_ticks = drv_usectohz(10 * 1000000);
			if ((ddi_get_lbolt() >
			    (icmd->icmd_start_time+timeout_ticks)) &&
			    iport->iport_state == FCT_STATE_ONLINE) {
				/* timeout, reset the port */
				char cmd_type[10];
				if (cmd->cmd_type == FCT_CMD_RCVD_ELS ||
				    cmd->cmd_type == FCT_CMD_SOL_ELS) {
					fct_els_t *els = cmd->cmd_specific;
					(void) snprintf(cmd_type,
					    sizeof (cmd_type), "%x.%x",
					    cmd->cmd_type,
					    els->els_req_payload[0]);
				} else if (cmd->cmd_type == FCT_CMD_SOL_CT) {
					fct_sol_ct_t *ct = cmd->cmd_specific;
					(void) snprintf(cmd_type,
					    sizeof (cmd_type), "%x.%02x%02x",
					    cmd->cmd_type,
					    ct->ct_req_payload[8],
					    ct->ct_req_payload[9]);
				} else {
					cmd_type[0] = 0;
				}
				st = cmd->cmd_comp_status;	/* gcc fix */
				(void) snprintf(info, sizeof (info),
				    "fct_cmd_terminator:"
				    " iport-%p, cmd_type(0x%s),"
				    " reason(%llx)", (void *)iport, cmd_type,
				    st);
				(void) fct_port_shutdown(port,
				    STMF_RFLAG_FATAL_ERROR | STMF_RFLAG_RESET,
				    info);
			}
			ppicmd = &((*ppicmd)->icmd_next);
		}

		if (ddi_get_lbolt() > endtime) {
			mutex_enter(&iport->iport_worker_lock);
			iport->iport_ppicmd_term = ppicmd;
			return (DISC_ACTION_DELAY_RESCAN);
		}
	}
	mutex_enter(&iport->iport_worker_lock);
	if (iport->iport_abort_queue)
		return (DISC_ACTION_DELAY_RESCAN);
	if (ret == DISC_ACTION_NO_WORK)
		return (DISC_ACTION_RESCAN);
	return (ret);
}

/*
 * Send a syslog event for adapter port level events.
 */
void
fct_log_local_port_event(fct_local_port_t *port, char *subclass)
{
	nvlist_t *attr_list;
	int port_instance;

	if (!fct_dip)
		return;
	port_instance = ddi_get_instance(fct_dip);

	if (nvlist_alloc(&attr_list, NV_UNIQUE_NAME_TYPE,
	    KM_SLEEP) != DDI_SUCCESS) {
		goto alloc_failed;
	}

	if (nvlist_add_uint32(attr_list, "instance", port_instance)
	    != DDI_SUCCESS) {
		goto error;
	}

	if (nvlist_add_byte_array(attr_list, "port-wwn",
	    port->port_pwwn, 8) != DDI_SUCCESS) {
		goto error;
	}

	(void) ddi_log_sysevent(fct_dip, DDI_VENDOR_SUNW, EC_SUNFC,
	    subclass, attr_list, NULL, DDI_SLEEP);

	nvlist_free(attr_list);
	return;

error:
	nvlist_free(attr_list);
alloc_failed:
	stmf_trace(((fct_i_local_port_t *)port->port_fct_private)->iport_alias,
	    "Unable to send %s event", subclass);
}

void
fct_log_remote_port_event(fct_local_port_t *port, char *subclass,
    uint8_t *rp_pwwn, uint32_t rp_id)
{
	nvlist_t *attr_list;
	int port_instance;

	if (!fct_dip)
		return;
	port_instance = ddi_get_instance(fct_dip);

	if (nvlist_alloc(&attr_list, NV_UNIQUE_NAME_TYPE,
	    KM_SLEEP) != DDI_SUCCESS) {
		goto alloc_failed;
	}

	if (nvlist_add_uint32(attr_list, "instance", port_instance)
	    != DDI_SUCCESS) {
		goto error;
	}

	if (nvlist_add_byte_array(attr_list, "port-wwn",
	    port->port_pwwn, 8) != DDI_SUCCESS) {
		goto error;
	}

	if (nvlist_add_byte_array(attr_list, "target-port-wwn",
	    rp_pwwn, 8) != DDI_SUCCESS) {
		goto error;
	}

	if (nvlist_add_uint32(attr_list, "target-port-id",
	    rp_id) != DDI_SUCCESS) {
		goto error;
	}

	(void) ddi_log_sysevent(fct_dip, DDI_VENDOR_SUNW, EC_SUNFC,
	    subclass, attr_list, NULL, DDI_SLEEP);

	nvlist_free(attr_list);
	return;

error:
	nvlist_free(attr_list);
alloc_failed:
	stmf_trace(((fct_i_local_port_t *)port->port_fct_private)->iport_alias,
	    "Unable to send %s event", subclass);
}

uint64_t
fct_netbuf_to_value(uint8_t *buf, uint8_t nbytes)
{
	uint64_t	ret = 0;
	uint8_t		idx = 0;

	do {
		ret |= (buf[idx] << (8 * (nbytes -idx - 1)));
	} while (++idx < nbytes);

	return (ret);
}

void
fct_value_to_netbuf(uint64_t value, uint8_t *buf, uint8_t nbytes)
{
	uint8_t		idx = 0;

	for (idx = 0; idx < nbytes; idx++) {
		buf[idx] = 0xFF & (value >> (8 * (nbytes - idx - 1)));
	}
}

/*
 * from_ptr: ptr to uchar_t array of size WWN_SIZE
 * to_ptr: char ptr to string of size WWN_SIZE*2+1
 */
void
fct_wwn_to_str(char *to_ptr, const uint8_t *from_ptr)
{
	ASSERT(to_ptr != NULL && from_ptr != NULL);

	(void) sprintf(to_ptr, "%02x%02x%02x%02x%02x%02x%02x%02x",
	    from_ptr[0], from_ptr[1], from_ptr[2], from_ptr[3],
	    from_ptr[4], from_ptr[5], from_ptr[6], from_ptr[7]);
}

static int
fct_update_stats(kstat_t *ks, int rw)
{
	fct_i_local_port_t *iport;
	fct_port_stat_t *port_kstat;
	fct_port_link_status_t stat;
	uint32_t	buf_size = sizeof (stat);
	int		ret;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	iport = (fct_i_local_port_t *)ks->ks_private;
	port_kstat = (fct_port_stat_t *)ks->ks_data;

	if (iport->iport_port->port_info == NULL) {
		return (EIO);
	}
	ret = iport->iport_port->port_info(FC_TGT_PORT_RLS,
	    iport->iport_port, NULL, (uint8_t *)&stat, &buf_size);
	if (ret != STMF_SUCCESS) {
		return (EIO);
	}

	port_kstat->link_failure_cnt.value.ui32 =
	    stat.LinkFailureCount;
	port_kstat->loss_of_sync_cnt.value.ui32 =
	    stat.LossOfSyncCount;
	port_kstat->loss_of_signals_cnt.value.ui32 =
	    stat.LossOfSignalsCount;
	port_kstat->prim_seq_protocol_err_cnt.value.ui32 =
	    stat.PrimitiveSeqProtocolErrorCount;
	port_kstat->invalid_tx_word_cnt.value.ui32 =
	    stat.InvalidTransmissionWordCount;
	port_kstat->invalid_crc_cnt.value.ui32 =
	    stat.InvalidCRCCount;

	return (0);
}

void
fct_init_kstats(fct_i_local_port_t *iport)
{
	kstat_t *ks;
	fct_port_stat_t *port_kstat;
	char	name[256];

	if (iport->iport_alias)
		(void) sprintf(name, "iport_%s", iport->iport_alias);
	else
		(void) sprintf(name, "iport_%"PRIxPTR"", (uintptr_t)iport);
	ks = kstat_create(FCT_MODULE_NAME, 0, name, "rawdata",
	    KSTAT_TYPE_NAMED, sizeof (fct_port_stat_t) / sizeof (kstat_named_t),
	    0);

	if (ks == NULL) {
		return;
	}
	port_kstat = (fct_port_stat_t *)ks->ks_data;

	iport->iport_kstat_portstat = ks;
	kstat_named_init(&port_kstat->link_failure_cnt,
	    "Link_failure_cnt", KSTAT_DATA_UINT32);
	kstat_named_init(&port_kstat->loss_of_sync_cnt,
	    "Loss_of_sync_cnt", KSTAT_DATA_UINT32);
	kstat_named_init(&port_kstat->loss_of_signals_cnt,
	    "Loss_of_signals_cnt", KSTAT_DATA_UINT32);
	kstat_named_init(&port_kstat->prim_seq_protocol_err_cnt,
	    "Prim_seq_protocol_err_cnt", KSTAT_DATA_UINT32);
	kstat_named_init(&port_kstat->invalid_tx_word_cnt,
	    "Invalid_tx_word_cnt", KSTAT_DATA_UINT32);
	kstat_named_init(&port_kstat->invalid_crc_cnt,
	    "Invalid_crc_cnt", KSTAT_DATA_UINT32);
	ks->ks_update = fct_update_stats;
	ks->ks_private = (void *)iport;
	kstat_install(ks);

}
