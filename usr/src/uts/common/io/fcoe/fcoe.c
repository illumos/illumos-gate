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
/*
 * Copyright 2012 Garrett D'Amore <garrett@damore.org>.  All rights reserved.
 */

/*
 * The following notice accompanied the original version of this file:
 *
 * BSD LICENSE
 *
 * Copyright(c) 2007 Intel Corporation. All rights reserved.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Common FCoE interface interacts with MAC and FCoE clients, managing
 * FCoE ports, doing MAC address discovery/managment, and FC frame
 * encapsulation/decapsulation
 */

#include <sys/stat.h>
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/cred.h>

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/byteorder.h>
#include <sys/atomic.h>
#include <sys/sysmacros.h>
#include <sys/cmn_err.h>
#include <sys/crc32.h>
#include <sys/strsubr.h>

#include <sys/mac_client.h>

/*
 * FCoE header files
 */
#include <sys/fcoe/fcoeio.h>
#include <sys/fcoe/fcoe_common.h>

/*
 * Driver's own header files
 */
#include <fcoe.h>
#include <fcoe_fc.h>
#include <fcoe_eth.h>

/*
 * Function forward declaration
 */
static int fcoe_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int fcoe_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int fcoe_bus_ctl(dev_info_t *fca_dip, dev_info_t *rip,
    ddi_ctl_enum_t op, void *arg, void *result);
static int fcoe_open(dev_t *devp, int flag, int otype, cred_t *credp);
static int fcoe_close(dev_t dev, int flag, int otype, cred_t *credp);
static int fcoe_ioctl(dev_t dev, int cmd, intptr_t data, int mode,
    cred_t *credp, int *rval);
static int fcoe_copyin_iocdata(intptr_t data, int mode, fcoeio_t **fcoeio,
    void **ibuf, void **abuf, void **obuf);
static int fcoe_copyout_iocdata(intptr_t data, int mode, fcoeio_t *fcoeio,
    void *obuf);
static int fcoe_iocmd(fcoe_soft_state_t *ss, intptr_t data, int mode);
static int fcoe_attach_init(fcoe_soft_state_t *this_ss);
static int fcoe_detach_uninit(fcoe_soft_state_t *this_ss);
static int fcoe_initchild(dev_info_t *fcoe_dip, dev_info_t *client_dip);
static int fcoe_uninitchild(dev_info_t *fcoe_dip, dev_info_t *client_dip);
static void fcoe_init_wwn_from_mac(uint8_t *wwn, uint8_t *mac,
    int is_pwwn, uint8_t idx);
static fcoe_mac_t *fcoe_create_mac_by_id(datalink_id_t linkid);
static int fcoe_cmp_wwn(fcoe_mac_t *checkedmac);
static void fcoe_watchdog(void *arg);
static void fcoe_worker_init();
static int fcoe_worker_fini();
static void fcoe_worker_frame();
static int fcoe_get_port_list(fcoe_port_instance_t *ports, int count);
static boolean_t fcoe_mac_existed(fcoe_mac_t *pmac);

/*
 * Driver identificaton stuff
 */
static struct cb_ops fcoe_cb_ops = {
	fcoe_open,
	fcoe_close,
	nodev,
	nodev,
	nodev,
	nodev,
	nodev,
	fcoe_ioctl,
	nodev,
	nodev,
	nodev,
	nochpoll,
	ddi_prop_op,
	0,
	D_MP | D_NEW | D_HOTPLUG,
	CB_REV,
	nodev,
	nodev
};

static struct bus_ops fcoe_busops = {
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
	fcoe_bus_ctl,			/* bus_ctl */
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

static struct dev_ops fcoe_ops = {
	DEVO_REV,
	0,
	nodev,
	nulldev,
	nulldev,
	fcoe_attach,
	fcoe_detach,
	nodev,
	&fcoe_cb_ops,
	&fcoe_busops,
	ddi_power,
	ddi_quiesce_not_needed
};

#define	FCOE_VERSION	"20091123-1.02"
#define	FCOE_NAME	"FCoE Transport v" FCOE_VERSION
#define	TASKQ_NAME_LEN	32

static struct modldrv modldrv = {
	&mod_driverops,
	FCOE_NAME,
	&fcoe_ops,
};

static struct modlinkage modlinkage = {
	MODREV_1, &modldrv, NULL
};

/*
 * TRACE for all FCoE related modules
 */
static kmutex_t fcoe_trace_buf_lock;
static int	fcoe_trace_buf_curndx	= 0;
static int	fcoe_trace_on		= 1;
static caddr_t	fcoe_trace_buf		= NULL;
static clock_t	fcoe_trace_start	= 0;
static caddr_t	ftb			= NULL;
static int	fcoe_trace_buf_size	= (1 * 1024 * 1024);

/*
 * Driver's global variables
 */
const fcoe_ver_e	 fcoe_ver_now	  = FCOE_VER_NOW;
static void		*fcoe_state	  = NULL;
fcoe_soft_state_t	*fcoe_global_ss	  = NULL;
int			 fcoe_use_ext_log = 1;

static ddi_taskq_t	*fcoe_worker_taskq;
static fcoe_worker_t	*fcoe_workers;
static uint32_t		fcoe_nworkers_running;

const char		*fcoe_workers_num = "workers-number";
volatile int		fcoe_nworkers;

/*
 * Common loadable module entry points _init, _fini, _info
 */

int
_init(void)
{
	int ret;

	ret = ddi_soft_state_init(&fcoe_state, sizeof (fcoe_soft_state_t), 0);
	if (ret == 0) {
		ret = mod_install(&modlinkage);
		if (ret != 0) {
			ddi_soft_state_fini(&fcoe_state);
		} else {
			fcoe_trace_start = ddi_get_lbolt();
			ftb = kmem_zalloc(fcoe_trace_buf_size,
			    KM_SLEEP);
			fcoe_trace_buf = ftb;
			mutex_init(&fcoe_trace_buf_lock, NULL, MUTEX_DRIVER, 0);
		}
	}

	FCOE_LOG("fcoe", "exit _init with %x", ret);

	return (ret);
}

int
_fini(void)
{
	int ret;

	ret = mod_remove(&modlinkage);
	if (ret == 0) {
		ddi_soft_state_fini(&fcoe_state);
	}

	FCOE_LOG("fcoe", "exit _fini with %x", ret);
	if (ret == 0) {
		kmem_free(fcoe_trace_buf, fcoe_trace_buf_size);
		mutex_destroy(&fcoe_trace_buf_lock);
	}

	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * Autoconfiguration entry points: attach, detach, getinfo
 */

static int
fcoe_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int			 ret = DDI_FAILURE;
	int			 fcoe_ret;
	int			 instance;
	fcoe_soft_state_t	*ss;

	instance = ddi_get_instance(dip);
	switch (cmd) {
	case DDI_ATTACH:
		ret = ddi_soft_state_zalloc(fcoe_state, instance);
		if (ret == DDI_FAILURE) {
			FCOE_LOG(0, "soft_state_zalloc-%x/%x", ret, instance);
			return (ret);
		}

		ss = ddi_get_soft_state(fcoe_state, instance);
		ss->ss_dip = dip;

		ASSERT(fcoe_global_ss == NULL);
		fcoe_global_ss = ss;
		fcoe_ret = fcoe_attach_init(ss);
		if (fcoe_ret == FCOE_SUCCESS) {
			ret = DDI_SUCCESS;
		}

		FCOE_LOG("fcoe", "fcoe_attach_init end with-%x", fcoe_ret);
		break;

	case DDI_RESUME:
		ret = DDI_SUCCESS;
		break;

	default:
		FCOE_LOG("fcoe", "unsupported attach cmd-%x", cmd);
		break;
	}

	return (ret);
}

static int
fcoe_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int			 ret = DDI_FAILURE;
	int			 fcoe_ret;
	int			 instance;
	fcoe_soft_state_t	*ss;

	instance = ddi_get_instance(dip);
	ss = ddi_get_soft_state(fcoe_state, instance);
	if (ss == NULL) {
		return (ret);
	}

	ASSERT(fcoe_global_ss != NULL);
	ASSERT(dip == fcoe_global_ss->ss_dip);
	switch (cmd) {
	case DDI_DETACH:
		fcoe_ret = fcoe_detach_uninit(ss);
		if (fcoe_ret == FCOE_SUCCESS) {
			ret = DDI_SUCCESS;
			fcoe_global_ss = NULL;
		}

		break;

	case DDI_SUSPEND:
		ret = DDI_SUCCESS;
		break;

	default:
		FCOE_LOG(0, "unsupported detach cmd-%x", cmd);
		break;
	}

	return (ret);
}

/*
 * FCA driver's intercepted bus control operations.
 */
static int
fcoe_bus_ctl(dev_info_t *fcoe_dip, dev_info_t *rip,
    ddi_ctl_enum_t op, void *clientarg, void *result)
{
	int ret;
	switch (op) {
	case DDI_CTLOPS_REPORTDEV:
	case DDI_CTLOPS_IOMIN:
		ret = DDI_SUCCESS;
		break;

	case DDI_CTLOPS_INITCHILD:
		ret = fcoe_initchild(fcoe_dip, (dev_info_t *)clientarg);
		break;

	case DDI_CTLOPS_UNINITCHILD:
		ret = fcoe_uninitchild(fcoe_dip, (dev_info_t *)clientarg);
		break;

	default:
		ret = ddi_ctlops(fcoe_dip, rip, op, clientarg, result);
		break;
	}

	return (ret);
}

/*
 * We need specify the dev address for client driver's instance, or we
 * can't online client driver's instance.
 */
/* ARGSUSED */
static int
fcoe_initchild(dev_info_t *fcoe_dip, dev_info_t *client_dip)
{
	char	client_addr[FCOE_STR_LEN];
	int	rval;

	rval = ddi_prop_get_int(DDI_DEV_T_ANY, client_dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "mac_id", -1);
	if (rval == -1) {
		FCOE_LOG(__FUNCTION__, "no mac_id property: %p", client_dip);
		return (DDI_FAILURE);
	}

	bzero(client_addr, FCOE_STR_LEN);
	(void) sprintf((char *)client_addr, "%x,0", rval);
	ddi_set_name_addr(client_dip, client_addr);
	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
fcoe_uninitchild(dev_info_t *fcoe_dip, dev_info_t *client_dip)
{
	ddi_set_name_addr(client_dip, NULL);
	return (DDI_SUCCESS);
}

/*
 * Device access entry points
 */
static int
fcoe_open(dev_t *devp, int flag, int otype, cred_t *credp)
{
	int			 instance;
	fcoe_soft_state_t	*ss;

	if (otype != OTYP_CHR) {
		return (EINVAL);
	}

	/*
	 * Since this is for debugging only, only allow root to issue ioctl now
	 */
	if (drv_priv(credp) != 0) {
		return (EPERM);
	}

	instance = (int)getminor(*devp);
	ss = ddi_get_soft_state(fcoe_state, instance);
	if (ss == NULL) {
		return (ENXIO);
	}

	mutex_enter(&ss->ss_ioctl_mutex);
	if (ss->ss_ioctl_flags & FCOE_IOCTL_FLAG_EXCL) {
		/*
		 * It is already open for exclusive access.
		 * So shut the door on this caller.
		 */
		mutex_exit(&ss->ss_ioctl_mutex);
		return (EBUSY);
	}

	if (flag & FEXCL) {
		if (ss->ss_ioctl_flags & FCOE_IOCTL_FLAG_OPEN) {
			/*
			 * Exclusive operation not possible
			 * as it is already opened
			 */
			mutex_exit(&ss->ss_ioctl_mutex);
			return (EBUSY);
		}
		ss->ss_ioctl_flags |= FCOE_IOCTL_FLAG_EXCL;
	}

	ss->ss_ioctl_flags |= FCOE_IOCTL_FLAG_OPEN;
	mutex_exit(&ss->ss_ioctl_mutex);

	return (0);
}

/* ARGSUSED */
static int
fcoe_close(dev_t dev, int flag, int otype, cred_t *credp)
{
	int			 instance;
	fcoe_soft_state_t	*ss;

	if (otype != OTYP_CHR) {
		return (EINVAL);
	}

	instance = (int)getminor(dev);
	ss = ddi_get_soft_state(fcoe_state, instance);
	if (ss == NULL) {
		return (ENXIO);
	}

	mutex_enter(&ss->ss_ioctl_mutex);
	if ((ss->ss_ioctl_flags & FCOE_IOCTL_FLAG_OPEN) == 0) {
		mutex_exit(&ss->ss_ioctl_mutex);
		return (ENODEV);
	}

	ss->ss_ioctl_flags &= ~FCOE_IOCTL_FLAG_MASK;
	mutex_exit(&ss->ss_ioctl_mutex);

	return (0);
}

/* ARGSUSED */
static int
fcoe_ioctl(dev_t dev, int cmd, intptr_t data, int mode,
    cred_t *credp, int *rval)
{
	fcoe_soft_state_t	*ss;
	int			 ret = 0;

	if (drv_priv(credp) != 0) {
		return (EPERM);
	}

	ss = ddi_get_soft_state(fcoe_state, (int32_t)getminor(dev));
	if (ss == NULL) {
		return (ENXIO);
	}

	mutex_enter(&ss->ss_ioctl_mutex);
	if ((ss->ss_ioctl_flags & FCOE_IOCTL_FLAG_OPEN) == 0) {
		mutex_exit(&ss->ss_ioctl_mutex);
		return (ENXIO);
	}
	mutex_exit(&ss->ss_ioctl_mutex);

	switch (cmd) {
	case FCOEIO_CMD:
		ret = fcoe_iocmd(ss, data, mode);
		break;
	default:
		FCOE_LOG(0, "fcoe_ioctl: ioctl-0x%02X", cmd);
		ret = ENOTTY;
		break;
	}

	return (ret);
}

static int
fcoe_copyin_iocdata(intptr_t data, int mode, fcoeio_t **fcoeio,
    void **ibuf, void **abuf, void **obuf)
{
	int ret = 0;

	*ibuf = NULL;
	*abuf = NULL;
	*obuf = NULL;
	*fcoeio = kmem_zalloc(sizeof (fcoeio_t), KM_SLEEP);
	if (ddi_copyin((void *)data, *fcoeio, sizeof (fcoeio_t), mode) != 0) {
		ret = EFAULT;
		goto copyin_iocdata_fail;
	}

	if ((*fcoeio)->fcoeio_ilen > FCOEIO_MAX_BUF_LEN ||
	    (*fcoeio)->fcoeio_alen > FCOEIO_MAX_BUF_LEN ||
	    (*fcoeio)->fcoeio_olen > FCOEIO_MAX_BUF_LEN) {
		ret = EFAULT;
		goto copyin_iocdata_fail;
	}

	if ((*fcoeio)->fcoeio_ilen) {
		*ibuf = kmem_zalloc((*fcoeio)->fcoeio_ilen, KM_SLEEP);
		if (ddi_copyin((void *)(unsigned long)(*fcoeio)->fcoeio_ibuf,
		    *ibuf, (*fcoeio)->fcoeio_ilen, mode) != 0) {
			ret = EFAULT;
			goto copyin_iocdata_fail;
		}
	}

	if ((*fcoeio)->fcoeio_alen) {
		*abuf = kmem_zalloc((*fcoeio)->fcoeio_alen, KM_SLEEP);
		if (ddi_copyin((void *)(unsigned long)(*fcoeio)->fcoeio_abuf,
		    *abuf, (*fcoeio)->fcoeio_alen, mode) != 0) {
			ret = EFAULT;
			goto copyin_iocdata_fail;
		}
	}

	if ((*fcoeio)->fcoeio_olen) {
		*obuf = kmem_zalloc((*fcoeio)->fcoeio_olen, KM_SLEEP);
	}
	return (ret);

copyin_iocdata_fail:
	if (*abuf) {
		kmem_free(*abuf, (*fcoeio)->fcoeio_alen);
		*abuf = NULL;
	}

	if (*ibuf) {
		kmem_free(*ibuf, (*fcoeio)->fcoeio_ilen);
		*ibuf = NULL;
	}

	kmem_free(*fcoeio, sizeof (fcoeio_t));
	return (ret);
}

static int
fcoe_copyout_iocdata(intptr_t data, int mode, fcoeio_t *fcoeio, void *obuf)
{
	if (fcoeio->fcoeio_olen) {
		if (ddi_copyout(obuf,
		    (void *)(unsigned long)fcoeio->fcoeio_obuf,
		    fcoeio->fcoeio_olen, mode) != 0) {
			return (EFAULT);
		}
	}

	if (ddi_copyout(fcoeio, (void *)data, sizeof (fcoeio_t), mode) != 0) {
		return (EFAULT);
	}
	return (0);
}

static int
fcoe_iocmd(fcoe_soft_state_t *ss, intptr_t data, int mode)
{
	int		ret;
	fcoe_mac_t	*fcoe_mac;
	void		*ibuf = NULL;
	void		*obuf = NULL;
	void		*abuf = NULL;
	fcoeio_t	*fcoeio;

	ret = fcoe_copyin_iocdata(data, mode, &fcoeio, &ibuf, &abuf, &obuf);
	if (ret != 0) {
		goto fcoeiocmd_release_buf;
	}

	/*
	 * If an exclusive open was demanded during open, ensure that
	 * only one thread can execute an ioctl at a time
	 */
	mutex_enter(&ss->ss_ioctl_mutex);
	if (ss->ss_ioctl_flags & FCOE_IOCTL_FLAG_EXCL) {
		if (ss->ss_ioctl_flags & FCOE_IOCTL_FLAG_EXCL_BUSY) {
			mutex_exit(&ss->ss_ioctl_mutex);
			fcoeio->fcoeio_status = FCOEIOE_BUSY;
			ret = EBUSY;
			goto fcoeiocmd_release_buf;
		}
		ss->ss_ioctl_flags |= FCOE_IOCTL_FLAG_EXCL_BUSY;
	}
	mutex_exit(&ss->ss_ioctl_mutex);

	fcoeio->fcoeio_status = 0;

	switch (fcoeio->fcoeio_cmd) {
	case FCOEIO_CREATE_FCOE_PORT: {
		fcoeio_create_port_param_t	*param =
		    (fcoeio_create_port_param_t *)ibuf;
		int		cmpwwn = 0;
		fcoe_port_t	*eport;

		if (fcoeio->fcoeio_ilen !=
		    sizeof (fcoeio_create_port_param_t) ||
		    fcoeio->fcoeio_xfer != FCOEIO_XFER_WRITE) {
			fcoeio->fcoeio_status = FCOEIOE_INVAL_ARG;
			ret = EINVAL;
			break;
		}

		mutex_enter(&ss->ss_ioctl_mutex);
		fcoe_mac = fcoe_create_mac_by_id(param->fcp_mac_linkid);
		if (fcoe_mac == NULL) {
			mutex_exit(&ss->ss_ioctl_mutex);
			fcoeio->fcoeio_status = FCOEIOE_CREATE_MAC;
			ret = EIO;
			break;
		}

		if (fcoe_mac->fm_flags & FCOE_MAC_FLAG_ENABLED) {
			mutex_exit(&ss->ss_ioctl_mutex);
			fcoeio->fcoeio_status = FCOEIOE_ALREADY;
			ret = EALREADY;
			break;
		} else {
			ret = fcoe_open_mac(fcoe_mac, param->fcp_force_promisc,
			    &fcoeio->fcoeio_status);
			if (ret != 0) {
				fcoe_destroy_mac(fcoe_mac);
				mutex_exit(&ss->ss_ioctl_mutex);
				if (fcoeio->fcoeio_status == 0) {
					fcoeio->fcoeio_status =
					    FCOEIOE_OPEN_MAC;
				}
				ret = EIO;
				break;
			} else {
				fcoe_mac->fm_flags |= FCOE_MAC_FLAG_ENABLED;
			}
		}

		/*
		 * Provide PWWN and NWWN based on mac address
		 */
		eport = &fcoe_mac->fm_eport;
		if (!param->fcp_pwwn_provided) {
			fcoe_init_wwn_from_mac(eport->eport_portwwn,
			    fcoe_mac->fm_current_addr, 1, 0);
		} else {
			(void) memcpy(eport->eport_portwwn, param->fcp_pwwn, 8);
		}

		if (!param->fcp_nwwn_provided) {
			fcoe_init_wwn_from_mac(eport->eport_nodewwn,
			    fcoe_mac->fm_current_addr, 0, 0);
		} else {
			(void) memcpy(eport->eport_nodewwn, param->fcp_nwwn, 8);
		}

		cmpwwn = fcoe_cmp_wwn(fcoe_mac);

		if (cmpwwn != 0) {
			if (cmpwwn == 1) {
				fcoeio->fcoeio_status = FCOEIOE_PWWN_CONFLICTED;
			} else if (cmpwwn == -1) {
				fcoeio->fcoeio_status = FCOEIOE_NWWN_CONFLICTED;
			}
			(void) fcoe_close_mac(fcoe_mac);
			fcoe_destroy_mac(fcoe_mac);
			mutex_exit(&ss->ss_ioctl_mutex);
			ret = ENOTUNIQ;
			break;
		}

		if (ret == 0) {
			ret = fcoe_create_port(ss->ss_dip,
			    fcoe_mac,
			    (param->fcp_port_type == FCOE_CLIENT_TARGET));
			if (ret != 0) {
				if (fcoe_mac_existed(fcoe_mac) == B_TRUE) {
					(void) fcoe_close_mac(fcoe_mac);
					fcoe_destroy_mac(fcoe_mac);
				}
				fcoeio->fcoeio_status = FCOEIOE_CREATE_PORT;
				ret = EIO;
			}
		}
		mutex_exit(&ss->ss_ioctl_mutex);

		break;
	}

	case FCOEIO_DELETE_FCOE_PORT: {
		fcoeio_delete_port_param_t *del_port_param =
		    (fcoeio_delete_port_param_t *)ibuf;
		uint64_t *is_target = (uint64_t *)obuf;

		if (fcoeio->fcoeio_ilen < sizeof (fcoeio_delete_port_param_t) ||
		    fcoeio->fcoeio_olen != sizeof (uint64_t) ||
		    fcoeio->fcoeio_xfer != FCOEIO_XFER_RW) {
			fcoeio->fcoeio_status = FCOEIOE_INVAL_ARG;
			ret = EINVAL;
			break;
		}

		mutex_enter(&ss->ss_ioctl_mutex);
		ret = fcoe_delete_port(ss->ss_dip, fcoeio,
		    del_port_param->fdp_mac_linkid, is_target);
		mutex_exit(&ss->ss_ioctl_mutex);
		FCOE_LOG("fcoe", "fcoe_delete_port %x return: %d",
		    del_port_param->fdp_mac_linkid, ret);
		break;
	}

	case FCOEIO_GET_FCOE_PORT_LIST: {
		fcoe_port_list_t *list = (fcoe_port_list_t *)obuf;
		int		count;

		if (fcoeio->fcoeio_xfer != FCOEIO_XFER_READ ||
		    fcoeio->fcoeio_olen < sizeof (fcoe_port_list_t)) {
			fcoeio->fcoeio_status = FCOEIOE_INVAL_ARG;
			ret = EINVAL;
			break;
		}
		mutex_enter(&ss->ss_ioctl_mutex);

		list->numPorts = 1 + (fcoeio->fcoeio_olen -
		    sizeof (fcoe_port_list_t))/sizeof (fcoe_port_instance_t);

		count = fcoe_get_port_list(list->ports, list->numPorts);

		if (count > list->numPorts) {
			fcoeio->fcoeio_status = FCOEIOE_MORE_DATA;
			ret = ENOSPC;
		}
		list->numPorts = count;
		mutex_exit(&ss->ss_ioctl_mutex);

		break;

	}

	default:
		return (ENOTTY);
	}

	FCOE_LOG("fcoe", "fcoe_ioctl %x returned %d, fcoeio_status = %d",
	    fcoeio->fcoeio_cmd, ret, fcoeio->fcoeio_status);

fcoeiocmd_release_buf:
	if (ret == 0) {
		ret = fcoe_copyout_iocdata(data, mode, fcoeio, obuf);
	} else if (fcoeio->fcoeio_status) {
		(void) fcoe_copyout_iocdata(data, mode, fcoeio, obuf);
	}

	if (obuf != NULL) {
		kmem_free(obuf, fcoeio->fcoeio_olen);
		obuf = NULL;
	}
	if (abuf != NULL) {
		kmem_free(abuf, fcoeio->fcoeio_alen);
		abuf = NULL;
	}

	if (ibuf != NULL) {
		kmem_free(ibuf, fcoeio->fcoeio_ilen);
		ibuf = NULL;
	}
	kmem_free(fcoeio, sizeof (fcoeio_t));

	return (ret);
}

/*
 * Finish final initialization
 */
static int
fcoe_attach_init(fcoe_soft_state_t *ss)
{
	char taskq_name[TASKQ_NAME_LEN];

	if (ddi_create_minor_node(ss->ss_dip, "admin", S_IFCHR,
	    ddi_get_instance(ss->ss_dip), DDI_PSEUDO, 0) != DDI_SUCCESS) {
		FCOE_LOG("FCOE", "ddi_create_minor_node failed");
		return (FCOE_FAILURE);
	}

	/*
	 * watchdog responsible for release frame and dispatch events
	 */
	(void) snprintf(taskq_name, sizeof (taskq_name), "fcoe_mac");
	taskq_name[TASKQ_NAME_LEN - 1] = 0;
	if ((ss->ss_watchdog_taskq = ddi_taskq_create(NULL,
	    taskq_name, 2, TASKQ_DEFAULTPRI, 0)) == NULL) {
		return (FCOE_FAILURE);
	}

	ss->ss_ioctl_flags = 0;
	mutex_init(&ss->ss_ioctl_mutex, NULL, MUTEX_DRIVER, NULL);
	list_create(&ss->ss_mac_list, sizeof (fcoe_mac_t),
	    offsetof(fcoe_mac_t, fm_ss_node));
	list_create(&ss->ss_pfrm_list, sizeof (fcoe_i_frame_t),
	    offsetof(fcoe_i_frame_t, fmi_pending_node));

	mutex_init(&ss->ss_watch_mutex, 0, MUTEX_DRIVER, 0);
	cv_init(&ss->ss_watch_cv, NULL, CV_DRIVER, NULL);
	ss->ss_flags &= ~SS_FLAG_TERMINATE_WATCHDOG;
	(void) ddi_taskq_dispatch(ss->ss_watchdog_taskq,
	    fcoe_watchdog, ss, DDI_SLEEP);
	while ((ss->ss_flags & SS_FLAG_WATCHDOG_RUNNING) == 0) {
		delay(10);
	}
	fcoe_nworkers = ddi_prop_get_int(DDI_DEV_T_ANY, ss->ss_dip,
	    DDI_PROP_NOTPROM | DDI_PROP_DONTPASS, (char *)fcoe_workers_num, 4);
	if (fcoe_nworkers < 1) {
		fcoe_nworkers = 4;
	}
	fcoe_worker_init();

	ddi_report_dev(ss->ss_dip);
	return (FCOE_SUCCESS);
}

/*
 * Finish final uninitialization
 */
static int
fcoe_detach_uninit(fcoe_soft_state_t *ss)
{
	int ret;
	if (!list_is_empty(&ss->ss_mac_list)) {
		FCOE_LOG("fcoe", "ss_mac_list is not empty when detach");
		return (FCOE_FAILURE);
	}

	if ((ret = fcoe_worker_fini()) != FCOE_SUCCESS) {
		return (ret);
	}

	/*
	 * Stop watchdog
	 */
	if (ss->ss_flags & SS_FLAG_WATCHDOG_RUNNING) {
		mutex_enter(&ss->ss_watch_mutex);
		ss->ss_flags |= SS_FLAG_TERMINATE_WATCHDOG;
		cv_broadcast(&ss->ss_watch_cv);
		mutex_exit(&ss->ss_watch_mutex);
		while (ss->ss_flags & SS_FLAG_WATCHDOG_RUNNING) {
			delay(10);
		}
	}

	ddi_taskq_destroy(ss->ss_watchdog_taskq);
	mutex_destroy(&ss->ss_watch_mutex);
	cv_destroy(&ss->ss_watch_cv);

	ddi_remove_minor_node(ss->ss_dip, NULL);
	mutex_destroy(&ss->ss_ioctl_mutex);
	list_destroy(&ss->ss_mac_list);

	return (FCOE_SUCCESS);
}

/*
 * Return mac instance if it exist, or else return NULL.
 */
fcoe_mac_t *
fcoe_lookup_mac_by_id(datalink_id_t linkid)
{
	fcoe_mac_t	*mac = NULL;

	ASSERT(MUTEX_HELD(&fcoe_global_ss->ss_ioctl_mutex));
	for (mac = list_head(&fcoe_global_ss->ss_mac_list); mac;
	    mac = list_next(&fcoe_global_ss->ss_mac_list, mac)) {
		if (linkid != mac->fm_linkid) {
			continue;
		}
		return (mac);
	}
	return (NULL);
}

/*
 * Return B_TRUE if mac exists, or else return B_FALSE
 */
static boolean_t
fcoe_mac_existed(fcoe_mac_t *pmac)
{
	fcoe_mac_t	*mac = NULL;

	ASSERT(MUTEX_HELD(&fcoe_global_ss->ss_ioctl_mutex));
	for (mac = list_head(&fcoe_global_ss->ss_mac_list); mac;
	    mac = list_next(&fcoe_global_ss->ss_mac_list, mac)) {
		if (mac == pmac) {
			return (B_TRUE);
		}
	}
	return (B_FALSE);
}

/*
 * port wwn will start with 20:..., node wwn will start with 10:...
 */
static void
fcoe_init_wwn_from_mac(uint8_t *wwn, uint8_t *mac, int is_pwwn, uint8_t idx)
{
	ASSERT(wwn != NULL);
	ASSERT(mac != NULL);
	wwn[0] = (is_pwwn + 1) << 4;
	wwn[1] = idx;
	bcopy(mac, wwn + 2, ETHERADDRL);
}

/*
 * Return fcoe_mac if it exists, otherwise create a new one
 */
static fcoe_mac_t *
fcoe_create_mac_by_id(datalink_id_t linkid)
{
	fcoe_mac_t	*mac = NULL;
	ASSERT(MUTEX_HELD(&fcoe_global_ss->ss_ioctl_mutex));

	mac = fcoe_lookup_mac_by_id(linkid);
	if (mac != NULL) {
		FCOE_LOG("fcoe", "fcoe_create_mac_by_id found one mac %d",
		    linkid);
		return (mac);
	}

	mac = kmem_zalloc(sizeof (fcoe_mac_t), KM_SLEEP);
	mac->fm_linkid = linkid;
	mac->fm_flags = 0;
	mac->fm_ss = fcoe_global_ss;
	list_insert_tail(&mac->fm_ss->ss_mac_list, mac);
	FCOE_LOG("fcoe", "fcoe_create_mac_by_id created one mac %d", linkid);
	return (mac);
}

void
fcoe_destroy_mac(fcoe_mac_t *mac)
{
	ASSERT(mac != NULL);
	list_remove(&mac->fm_ss->ss_mac_list, mac);
	kmem_free(mac, sizeof (fcoe_mac_t));
}

/*
 * raw frame layout:
 * ethernet header + vlan header (optional) + FCoE header +
 * FC frame + FCoE tailer
 */
/* ARGSUSED */
mblk_t *
fcoe_get_mblk(fcoe_mac_t *mac, uint32_t raw_frame_size)
{
	mblk_t	*mp;
	int	 err;

	/*
	 * FCFH_SIZE + PADDING_SIZE
	 */
	ASSERT(raw_frame_size >= 60);
	while ((mp = allocb((size_t)raw_frame_size, 0)) == NULL) {
		if ((err = strwaitbuf((size_t)raw_frame_size, BPRI_LO)) != 0) {
			FCOE_LOG("fcoe_get_mblk", "strwaitbuf return %d", err);
			return (NULL);
		}
	}
	mp->b_wptr = mp->b_rptr + raw_frame_size;

	/*
	 * We should always zero FC frame header
	 */
	bzero(mp->b_rptr + PADDING_HEADER_SIZE,
	    sizeof (fcoe_fc_frame_header_t));
	return (mp);
}

static void
fcoe_watchdog(void *arg)
{
	fcoe_soft_state_t	*ss	   = (fcoe_soft_state_t *)arg;
	fcoe_i_frame_t		*fmi;
	fcoe_mac_t		*mac = NULL;

	FCOE_LOG("fcoe", "fcoe_soft_state is %p", ss);

	mutex_enter(&ss->ss_watch_mutex);
	ss->ss_flags |= SS_FLAG_WATCHDOG_RUNNING;
	while ((ss->ss_flags & SS_FLAG_TERMINATE_WATCHDOG) == 0) {
		while (fmi = (fcoe_i_frame_t *)list_head(&ss->ss_pfrm_list)) {
			list_remove(&ss->ss_pfrm_list, fmi);
			mutex_exit(&ss->ss_watch_mutex);

			mac = EPORT2MAC(fmi->fmi_frame->frm_eport);
			mac->fm_client.ect_release_sol_frame(fmi->fmi_frame);

			mutex_enter(&ss->ss_watch_mutex);
			mac->fm_frm_cnt--;
		}

		ss->ss_flags |= SS_FLAG_DOG_WAITING;
		(void) cv_wait(&ss->ss_watch_cv, &ss->ss_watch_mutex);
		ss->ss_flags &= ~SS_FLAG_DOG_WAITING;
	}

	ss->ss_flags &= ~SS_FLAG_WATCHDOG_RUNNING;
	mutex_exit(&ss->ss_watch_mutex);
}

static void
fcoe_worker_init()
{
	uint32_t i;

	fcoe_nworkers_running = 0;
	fcoe_worker_taskq = ddi_taskq_create(0, "FCOE_WORKER_TASKQ",
	    fcoe_nworkers, TASKQ_DEFAULTPRI, 0);
	fcoe_workers = (fcoe_worker_t *)kmem_zalloc(sizeof (fcoe_worker_t) *
	    fcoe_nworkers, KM_SLEEP);
	for (i = 0; i < fcoe_nworkers; i++) {
		fcoe_worker_t *w = &fcoe_workers[i];
		mutex_init(&w->worker_lock, NULL, MUTEX_DRIVER, NULL);
		cv_init(&w->worker_cv, NULL, CV_DRIVER, NULL);
		w->worker_flags &= ~FCOE_WORKER_TERMINATE;
		list_create(&w->worker_frm_list, sizeof (fcoe_i_frame_t),
		    offsetof(fcoe_i_frame_t, fmi_pending_node));
		(void) ddi_taskq_dispatch(fcoe_worker_taskq, fcoe_worker_frame,
		    w, DDI_SLEEP);
	}
	while (fcoe_nworkers_running != fcoe_nworkers) {
		delay(10);
	}
}

static int
fcoe_worker_fini()
{
	uint32_t i;

	for (i = 0; i < fcoe_nworkers; i++) {
		fcoe_worker_t *w = &fcoe_workers[i];
		mutex_enter(&w->worker_lock);
		if (w->worker_flags & FCOE_WORKER_STARTED) {
			w->worker_flags |= FCOE_WORKER_TERMINATE;
			cv_signal(&w->worker_cv);
		}
		mutex_exit(&w->worker_lock);
	}

	while (fcoe_nworkers_running != 0) {
		delay(drv_usectohz(10000));
	}

	ddi_taskq_destroy(fcoe_worker_taskq);
	kmem_free(fcoe_workers, sizeof (fcoe_worker_t) * fcoe_nworkers);
	fcoe_workers = NULL;
	return (FCOE_SUCCESS);
}

static int
fcoe_crc_verify(fcoe_frame_t *frm)
{
	uint32_t crc;
	uint8_t *crc_array = FRM2FMI(frm)->fmi_fft->fft_crc;
	uint32_t crc_from_frame = ~(crc_array[0] | (crc_array[1] << 8) |
	    (crc_array[2] << 16) | (crc_array[3] << 24));
	CRC32(crc, frm->frm_fc_frame, frm->frm_fc_frame_size, -1U, crc32_table);
	return (crc == crc_from_frame ? FCOE_SUCCESS : FCOE_FAILURE);
}

static void
fcoe_worker_frame(void *arg)
{
	fcoe_worker_t	*w = (fcoe_worker_t *)arg;
	fcoe_i_frame_t	*fmi;
	int		ret;

	atomic_inc_32(&fcoe_nworkers_running);
	mutex_enter(&w->worker_lock);
	w->worker_flags |= FCOE_WORKER_STARTED | FCOE_WORKER_ACTIVE;
	while ((w->worker_flags & FCOE_WORKER_TERMINATE) == 0) {
		/*
		 * loop through the frames
		 */
		while (fmi = list_head(&w->worker_frm_list)) {
			list_remove(&w->worker_frm_list, fmi);
			mutex_exit(&w->worker_lock);
			/*
			 * do the checksum
			 */
			ret = fcoe_crc_verify(fmi->fmi_frame);
			if (ret == FCOE_SUCCESS) {
				fmi->fmi_mac->fm_client.ect_rx_frame(
				    fmi->fmi_frame);
			} else {
				fcoe_release_frame(fmi->fmi_frame);
			}
			mutex_enter(&w->worker_lock);
			w->worker_ntasks--;
		}
		w->worker_flags &= ~FCOE_WORKER_ACTIVE;
		cv_wait(&w->worker_cv, &w->worker_lock);
		w->worker_flags |= FCOE_WORKER_ACTIVE;
	}
	w->worker_flags &= ~(FCOE_WORKER_STARTED | FCOE_WORKER_ACTIVE);
	mutex_exit(&w->worker_lock);
	atomic_dec_32(&fcoe_nworkers_running);
	list_destroy(&w->worker_frm_list);
}

void
fcoe_post_frame(fcoe_frame_t *frm)
{
	fcoe_worker_t *w;
	uint16_t	oxid = FRM_OXID(frm);

	w = &fcoe_workers[oxid % fcoe_nworkers_running];
	mutex_enter(&w->worker_lock);
	list_insert_tail(&w->worker_frm_list, frm->frm_fcoe_private);
	w->worker_ntasks++;
	if ((w->worker_flags & FCOE_WORKER_ACTIVE) == 0) {
		cv_signal(&w->worker_cv);
	}
	mutex_exit(&w->worker_lock);
}

/*
 * The max length of every LOG is 158
 */
void
fcoe_trace(caddr_t ident, const char *fmt, ...)
{
	va_list args;
	char	tbuf[160];
	int	len;
	clock_t curclock;
	clock_t usec;

	if (fcoe_trace_on == 0) {
		return;
	}

	curclock = ddi_get_lbolt();
	usec = (curclock - fcoe_trace_start) * usec_per_tick;
	len = snprintf(tbuf, 158, "%lu.%03lus 0t%lu %s ", (usec /
	    (1000 * 1000)), ((usec % (1000 * 1000)) / 1000),
	    curclock, (ident ? ident : "unknown"));
	va_start(args, fmt);
	len += vsnprintf(tbuf + len, 158 - len, fmt, args);
	va_end(args);

	if (len > 158) {
		len = 158;
	}
	tbuf[len++] = '\n';
	tbuf[len] = 0;

	mutex_enter(&fcoe_trace_buf_lock);
	bcopy(tbuf, &fcoe_trace_buf[fcoe_trace_buf_curndx], len+1);
	fcoe_trace_buf_curndx += len;
	if (fcoe_trace_buf_curndx > (fcoe_trace_buf_size - 320)) {
		fcoe_trace_buf_curndx = 0;
	}
	mutex_exit(&fcoe_trace_buf_lock);
}

/*
 * Check whether the pwwn or nwwn already exist or not
 * Return value:
 * 1: PWWN conflicted
 * -1: NWWN conflicted
 * 0: No conflict
 */
static int
fcoe_cmp_wwn(fcoe_mac_t *checkedmac)
{
	fcoe_mac_t	*mac;
	uint8_t		*nwwn, *pwwn, *cnwwn, *cpwwn;

	cnwwn = checkedmac->fm_eport.eport_nodewwn;
	cpwwn = checkedmac->fm_eport.eport_portwwn;
	ASSERT(MUTEX_HELD(&fcoe_global_ss->ss_ioctl_mutex));

	for (mac = list_head(&fcoe_global_ss->ss_mac_list); mac;
	    mac = list_next(&fcoe_global_ss->ss_mac_list, mac)) {
		if (mac == checkedmac) {
			continue;
		}
		nwwn = mac->fm_eport.eport_nodewwn;
		pwwn = mac->fm_eport.eport_portwwn;

		if (memcmp(nwwn, cnwwn, 8) == 0) {
			return (-1);
		}

		if (memcmp(pwwn, cpwwn, 8) == 0) {
			return (1);
		}
	}
	return (0);
}

static int
fcoe_get_port_list(fcoe_port_instance_t *ports, int count)
{
	fcoe_mac_t	*mac = NULL;
	int		i = 0;

	ASSERT(ports != NULL);
	ASSERT(MUTEX_HELD(&fcoe_global_ss->ss_ioctl_mutex));

	for (mac = list_head(&fcoe_global_ss->ss_mac_list); mac;
	    mac = list_next(&fcoe_global_ss->ss_mac_list, mac)) {
		if (i < count) {
			bcopy(mac->fm_eport.eport_portwwn,
			    ports[i].fpi_pwwn, 8);
			ports[i].fpi_mac_linkid = mac->fm_linkid;
			bcopy(mac->fm_current_addr,
			    ports[i].fpi_mac_current_addr, ETHERADDRL);
			bcopy(mac->fm_primary_addr,
			    ports[i].fpi_mac_factory_addr, ETHERADDRL);
			ports[i].fpi_port_type =
			    EPORT_CLT_TYPE(&mac->fm_eport);
			ports[i].fpi_mtu_size =
			    mac->fm_eport.eport_mtu;
			ports[i].fpi_mac_promisc =
			    mac->fm_promisc_handle != NULL ? 1 : 0;
		}
		i++;
	}
	return (i);
}
