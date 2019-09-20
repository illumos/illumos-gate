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
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/stropts.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunldi.h>
#include <sys/file.h>
#include <sys/priv_names.h>
#include <inet/common.h>

#define	_SUN_TPI_VERSION 2
#include <sys/tihdr.h>
#include <sys/timod.h>
#include <sys/tiuser.h>
#include <sys/suntpi.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <inet/common.h>
#include <inet/ip.h>
#include <inet/mi.h>
#include <sys/policy.h>
#include "sys/random.h"
#include <inet/sdp_itf.h>
#include <sys/ib/ibtl/ibti.h>


/*
 * This is a pseudo driver which creates an entry for /dev/sdp in the device
 * tree. A regular installation will end up adding a file to sock2path.d
 * announcing support for sdp using AF_INET/SOCK_STREAM/PROTO_SDP parameters in
 * socket call. On a non IB hardware, following are the constraints within
 * which the sdp project operates. The sdpib driver which is the real driver
 * (in terms of moving data) should not be loaded since it has dependency on
 * ibcm and ibtl modules which will be loaded in the memory. This will consume
 * precious memory and needs to be avoided. As a result the sdpib driver
 * should fail its init() call to disallow loading on other modules. Due to
 * this we do not get a chance to create a /dev/sdp entry in the device tree
 * in the regular sdpib driver. During the boottime, this will cause a warning
 * message when  soconfig processes the entry for sdp in sock2path file . In
 * order to avoid this a pseudo driver is introduced which creates an entry
 * for /dev/sdp regardless of the hardware. When a socket  call is made on the
 * sdp subsystem, the call will end up in this driver, which then forwards
 * this call to the real sdp driver.  On a non-ib hardware system the call
 * will fail
 */

#define	SDP_NAME	"sdp"
#define	SDP_DEVDESC	"SDP STREAMS driver"
#define	SDP_DEVMINOR	0

static dev_info_t *sdp_dev_info;

ldi_ident_t sdp_li;
krwlock_t	sdp_transport_lock;
ldi_handle_t	sdp_transport_handle = NULL;

static int
sdp_gen_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	int	ret;

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	sdp_dev_info = devi;

	ret = ddi_create_minor_node(devi, SDP_NAME, S_IFCHR,
	    SDP_DEVMINOR, DDI_PSEUDO, 0);
	if (ret != DDI_SUCCESS) {
		return (ret);
	}
	return (DDI_SUCCESS);
}

static int
sdp_gen_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	ASSERT(devi == sdp_dev_info);

	ddi_remove_minor_node(devi, NULL);

	return (DDI_SUCCESS);
}

/* open routine. */
/*ARGSUSED*/
static int
sdp_gen_open(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	qprocson(q);
	qenable(q);
	return (0);
}

/* open routine. */
/*ARGSUSED*/
static int
sdp_gen_close(queue_t *q, int flag, cred_t *credp)
{
	qprocsoff(q);
	return (0);
}

static int
sdp_open_sdpib_driver()
{
	int ret = 0;

	rw_enter(&sdp_transport_lock, RW_WRITER);
	if (sdp_transport_handle != 0) {
		/*
		 * Someone beat us to it.
		 */
		goto done;
	}

	if (ibt_hw_is_present() == 0) {
		ret = ENODEV;
		goto done;
	}

	if (sdp_li == NULL) {
		ret = EPROTONOSUPPORT;
		goto done;
	}

	ret = ldi_open_by_name("/devices/ib/sdpib@0:sdpib",
	    FREAD | FWRITE, kcred, &sdp_transport_handle, sdp_li);
	if (ret != 0) {
		ret = EPROTONOSUPPORT;
		sdp_transport_handle = NULL;
		goto done;
	}

done:
	rw_exit(&sdp_transport_lock);
	return (ret);
}


static void
sdp_gen_ioctl(queue_t *q, mblk_t *mp)
{
	struct iocblk *iocp;
	int32_t enable = 0;
	int ret;
	boolean_t priv = B_TRUE;

	/* LINTED */
	iocp = (struct iocblk *)mp->b_rptr;
	switch (iocp->ioc_cmd) {
			int32_t send_enable;
		case SIOCSENABLESDP:
			bcopy(mp->b_cont->b_rptr, &enable, sizeof (int));

			send_enable = enable;

			/*
			 * Check for root privs.
			 * if not net config privs - return state of system SDP
			 */
			if (secpolicy_net_config(CRED(), B_FALSE) != 0) {
				priv = B_FALSE;
			}


			/*
			 * The sdpib driver is loaded if root enables sdp the
			 * first time (sdp_transport_handle is NULL). It is
			 * unloaded during the following first disable. At all
			 * other times for root as well as non-root users, the
			 * action of enabling/disabling sdp is simply acked.
			 */
			rw_enter(&sdp_transport_lock, RW_READER);
			if ((send_enable == 1) &&
			    (sdp_transport_handle == NULL) &&
			    (priv == B_TRUE)) {
				/* Initialize sdpib transport driver */
				rw_exit(&sdp_transport_lock);
				ret = sdp_open_sdpib_driver();
				rw_enter(&sdp_transport_lock,
				    RW_READER);
				if (ret != 0) {
					/* Transport failed to load */
					rw_exit(&sdp_transport_lock);
					enable = 0;
					goto done;
				}
				(void) ldi_ioctl(sdp_transport_handle,
				    iocp->ioc_cmd, (intptr_t)&send_enable,
				    FKIOCTL, CRED(), (int *)&enable);
			} else if (sdp_transport_handle != NULL) {
				(void) ldi_ioctl(sdp_transport_handle,
				    iocp->ioc_cmd, (intptr_t)&send_enable,
				    FKIOCTL, CRED(), (int *)&enable);
				if (send_enable == 0 && priv == B_TRUE) {
					(void) ldi_close(sdp_transport_handle,
					    FNDELAY, kcred);
					sdp_transport_handle = NULL;
				}
			} else {
				enable = 0;
			}
			rw_exit(&sdp_transport_lock);

done:
			bcopy(&enable, mp->b_cont->b_rptr, sizeof (int));

			/* ACK the ioctl */
			mp->b_datap->db_type = M_IOCACK;
			iocp->ioc_count = sizeof (int);
			qreply(q, mp);
			break;
		default:
			miocnak(q, mp, 0, ENOTSUP);
	}
}

/*
 * Received a put from sockfs. We only support ndd get/set
 */
static int
sdp_gen_wput(queue_t *q, mblk_t *mp)
{
	switch (mp->b_datap->db_type) {
	case M_IOCTL:
		sdp_gen_ioctl(q, mp);
		break;
	case M_FLUSH:
		*mp->b_rptr &= ~FLUSHW;
		if (*mp->b_rptr & FLUSHR)
			qreply(q, mp);
		else
			freemsg(mp);
		break;
	default:
		freemsg(mp);
		return (0);
	}
	return (0);
}

static struct module_info info = {
	0, "sdp", 1, INFPSZ, 65536, 1024
};

static struct qinit rinit = {
	NULL, NULL, sdp_gen_open, sdp_gen_close, NULL,
	&info, NULL, NULL, NULL, STRUIOT_NONE
};

static struct qinit winit = {
	sdp_gen_wput, NULL,  sdp_gen_open, sdp_gen_close,
	NULL, &info, NULL, NULL, NULL, STRUIOT_NONE
};

struct streamtab sdpinfo = {
	&rinit, &winit, NULL, NULL
};

DDI_DEFINE_STREAM_OPS(sdp_devops, nulldev, nulldev, sdp_gen_attach,
    sdp_gen_detach, nodev, NULL, D_MP, &sdpinfo, ddi_quiesce_not_needed);

/*
 * Module linkage information for the kernel.
 */
static struct modldrv modldrv = {
	&mod_driverops,
	SDP_DEVDESC,
	&sdp_devops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

int
_init(void)
{
	int	ret;

	ret = mod_install(&modlinkage);
	if (ret != 0)
		goto done;
	ret = ldi_ident_from_mod(&modlinkage, &sdp_li);
	if (ret != 0)
		sdp_li = NULL;
done:
	return (ret);
}

int
_fini(void)
{
	int	ret;

	ret = mod_remove(&modlinkage);
	if (ret != 0) {
		return (ret);
	}

	ldi_ident_release(sdp_li);
	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
