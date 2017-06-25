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


#include <sys/types.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/cmn_err.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/stat.h>

#include <sys/callb.h>
#include <sys/strlog.h>
#include <sys/lom_io.h>
#include <sys/time.h>
#include <sys/glvc.h>
#include <sys/kmem.h>
#include <netinet/in.h>
#include <sys/inttypes.h>

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunldi.h>

/* common defines */
#ifndef MIN
#define	MIN(x, y) ((x) < (y) ? (x) : (y))
#endif
#ifndef MAX
#define	MAX(x, y) ((x) > (y) ? (x) : (y))
#endif
#ifndef	ABS
#define	ABS(x)	((x) < (0) ? (-(x)) : (x))
#endif

#define	LOMIOCALCTL_OLD		_IOW('a', 4, ts_aldata_t)
#define	LOMIOCALSTATE_OLD	_IOWR('a', 5, ts_aldata_t)

#define	PCP_CKSUM_ENABLE
#define	PCP_DEF_MTU_SZ	100

#define	PCP_MAX_TRY_CNT		5
#define	PCP_GLVC_SLEEP		5
#define	PCP_COMM_TIMEOUT	0x10

#define	PCP_IO_OP_READ		(1)
#define	PCP_IO_OP_WRITE		(2)
#define	PCP_IO_OP_PEEK		(3)


/* Error codes for 'status' field in response message header */
#define	TSAL_PCP_ERROR		(-1)
#define	TSAL_PCP_OK		(0)	/* message received okay */

/*
 * magic number for Platform Channel Protocol (PCP)
 * ~(rot13("PCP_") = 0xAFBCAFA0
 * rot13 is a simple Caesar-cypher encryption that replaces each English letter
 * with the one 13 places forward or back along the alphabet.
 */
#define	 PCP_MAGIC_NUM		(0xAFBCAFA0)

/* Platform channel protocol versions. */
#define	PCP_PROT_VER_1		1

/* defines for 'timeout' */
#define	PCP_TO_NO_RESPONSE	(0xFFFFFFFF)	/* no response required */
#define	PCP_TO_WAIT_FOREVER	(0)	/* wait forever..(in reality, */
					/* it waits until glvc driver */
					/* call returns; curently glvc */
					/* calls are blocking calls. */

/* Message Types */
#define	PCP_ALARM_CONTROL	15
#define	PCP_ALARM_CONTROL_R	16

/* alarm_action */
#define	PCP_ALARM_ENABLE	1
#define	PCP_ALARM_DISABLE	2
#define	PCP_ALARM_STATUS	3

/* alarm_id */
#define	PCP_ALARM_CRITICAL	0
#define	PCP_ALARM_MAJOR		1
#define	PCP_ALARM_MINOR		2
#define	PCP_ALARM_USER		3

/* alarm_state */
#define	ALARM_STATE_ON		1
#define	ALARM_STATE_OFF		2
#define	ALARM_STATE_UNKNOWN	3

/* Status Types */
#define	PCP_ALARM_OK		(1)
#define	PCP_ALARM_ERROR		(2)

/* tsalarm service channel */
#define	ALARM_CHANNEL	"/devices/virtual-devices@100/telco-alarm@f:glvc"

/* Driver state  flags */
#define	TSAL_OPENED		0x1
#define	TSAL_IDENTED		0x2

/*
 * Platform Channel Request Message Header.
 */
typedef	struct tsal_pcp_req_msg_hdr {
	uint32_t	magic_num;	/* magic number */
	uint8_t		proto_ver;	/* version info for */
					/* backward compatibility */
	uint8_t		msg_type;	/* provided by user apps */
	uint8_t		sub_type;	/* provided by user apps */
	uint8_t		rsvd_pad;	/* padding bits */
	uint32_t	xid;		/* transaction id */
	uint32_t	timeout;	/* timeout in seconds */
	uint32_t	msg_len;	/* length of request or response data */
	uint16_t	msg_cksum;	/* 16-bit checksum of req msg data */
	uint16_t	hdr_cksum;	/* 16-bit checksum of req hdr */
} tsal_pcp_req_msg_hdr_t;

/*
 * Platform Channel Response Message Header.
 */
typedef struct tsal_pcp_resp_msg_hdr {
	uint32_t	magic_num;	/* magic number */
	uint8_t		proto_ver;	/* version info for */
					/* backward compatibility */
	uint8_t		msg_type;	/* passed to user apps */
	uint8_t		sub_type;	/* passed to user apps */
	uint8_t		rsvd_pad;	/* for padding */
	uint32_t	xid;		/* transaction id */
	uint32_t	timeout;	/* timeout in seconds */
	uint32_t	msg_len;	/* length of request or response data */
	uint32_t	status;		/* response status */
	uint16_t	msg_cksum;	/* 16-bit checksum of resp msg data */
	uint16_t	hdr_cksum;	/* 16-bit checksum of resp hdr */
} tsal_pcp_resp_msg_hdr_t;

/*
 * PCP user apps message format
 */
typedef struct tsal_pcp_msg {
	uint8_t		msg_type;
	uint8_t		sub_type;
	uint16_t	rsvd_pad;
	uint32_t	msg_len;
	void		*msg_data;
} tsal_pcp_msg_t;

/*
 * alarm set/get request message
 */
typedef struct tsal_pcp_alarm_req {
	uint32_t	alarm_id;
	uint32_t	alarm_action;
} tsal_pcp_alarm_req_t;

/*
 * alarm set/get response message
 */
typedef struct tsal_pcp_alarm_resp {
	uint32_t	status;
	uint32_t	alarm_id;
	uint32_t	alarm_state;
} tsal_pcp_alarm_resp_t;

/*
 * tsalarm driver soft structure
 */
typedef struct tsalarm_softc {
	ldi_handle_t	lh;
	ldi_ident_t	li;
	dev_info_t	*dip;
	minor_t		minor;
	int		flags;
	kmutex_t	mutex;
	uint32_t	msg_xid;
	uint32_t	mtu_size;
	uint8_t		*read_head;
	uint8_t		*read_tail;
	uint8_t		*read_area;
	uint8_t		*peek_area;
	uint8_t		*peek_read_area;
	tsal_pcp_alarm_req_t	*req_ptr;
	tsal_pcp_alarm_resp_t	*resp_ptr;
	tsal_pcp_req_msg_hdr_t	*req_msg_hdr;
	tsal_pcp_resp_msg_hdr_t	*resp_msg_hdr;
}tsalarm_softc_t;

/*
 * Forward declarations.
 */
static int tsal_pcp_send_req_msg_hdr(tsalarm_softc_t *sc,
					tsal_pcp_req_msg_hdr_t *req_hdr);
static int tsal_pcp_recv_resp_msg_hdr(tsalarm_softc_t *sc,
					tsal_pcp_resp_msg_hdr_t *resp_hdr);
static int tsal_pcp_io_op(tsalarm_softc_t *sc, void *buf,
					int byte_cnt, int io_op);
static int tsal_pcp_read(tsalarm_softc_t *sc, uint8_t *buf, int buf_len);
static int tsal_pcp_write(tsalarm_softc_t *sc, uint8_t *buf, int buf_len);
static int tsal_pcp_peek(tsalarm_softc_t *sc, uint8_t *buf, int buf_len);
static int tsal_pcp_peek_read(tsalarm_softc_t *sc, uint8_t *buf, int buf_len);
static int tsal_pcp_frame_error_handle(tsalarm_softc_t *sc);
static int check_magic_byte_presence(tsalarm_softc_t *sc, int byte_cnt,
					uint8_t *byte_val, int *ispresent);
static int tsal_pcp_send_recv(tsalarm_softc_t *sc, tsal_pcp_msg_t *req_msg,
			tsal_pcp_msg_t *resp_msg, uint32_t timeout);
static uint32_t tsal_pcp_get_xid(tsalarm_softc_t *sc);
static uint16_t checksum(uint16_t *addr, int32_t count);
static int glvc_alarm_get(int alarm_type, int *alarm_state,
					tsalarm_softc_t *sc);
static int glvc_alarm_set(int alarm_type, int new_state,
					tsalarm_softc_t *sc);

#define	getsoftc(minor)	\
		((struct tsalarm_softc *)ddi_get_soft_state(statep, (minor)))

/*
 * Driver entry points
 */

/* dev_ops and cb_ops entry point function declarations */

static int	tsalarm_attach(dev_info_t *, ddi_attach_cmd_t);
static int	tsalarm_detach(dev_info_t *, ddi_detach_cmd_t);
static int	tsalarm_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);

static int	tsalarm_open(dev_t *, int, int, cred_t *);
static int	tsalarm_close(dev_t, int, int, cred_t *);
static int	tsalarm_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

static struct cb_ops tsalarm_cb_ops = {
	tsalarm_open,	/* open */
	tsalarm_close,	/* close */
	nodev,		/* strategy() */
	nodev,		/* print() */
	nodev,		/* dump() */
	nodev,		/* read() */
	nodev,		/* write() */
	tsalarm_ioctl,	/* ioctl() */
	nodev,		/* devmap() */
	nodev,		/* mmap() */
	ddi_segmap,	/* segmap() */
	nochpoll,	/* poll() */
	ddi_prop_op,    /* prop_op() */
	NULL,		/* cb_str */
	D_NEW | D_MP	/* cb_flag */
};


static struct dev_ops tsalarm_ops = {
	DEVO_REV,
	0,			/* ref count */
	tsalarm_getinfo,	/* getinfo() */
	nulldev,		/* identify() */
	nulldev,		/* probe() */
	tsalarm_attach,		/* attach() */
	tsalarm_detach,		/* detach */
	nodev,			/* reset */
	&tsalarm_cb_ops,	/* pointer to cb_ops structure */
	(struct bus_ops *)NULL,
	nulldev,		/* power() */
	ddi_quiesce_not_needed,		/* quiesce() */
};

/*
 * Loadable module support.
 */
extern struct mod_ops mod_driverops;
static void    *statep;

static struct modldrv modldrv = {
	&mod_driverops,			/* Type of module. This is a driver */
	"tsalarm control driver",	/* Name of the module */
	&tsalarm_ops			/* pointer to the dev_ops structure */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

int
_init(void)
{
	int    e;

	if (e = ddi_soft_state_init(&statep,
				sizeof (struct tsalarm_softc), 1)) {
		return (e);
	}

	if ((e = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&statep);
	}

	return (e);
}

int
_fini(void)
{
	int e;

	if ((e = mod_remove(&modlinkage)) != 0) {
		return (e);
	}

	ddi_soft_state_fini(&statep);

	return (DDI_SUCCESS);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/* ARGSUSED */
static int
tsalarm_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	int	inst = getminor((dev_t)arg);
	int	retval = DDI_SUCCESS;
	struct tsalarm_softc *softc;

	switch (cmd) {

	case DDI_INFO_DEVT2DEVINFO:
		if ((softc = getsoftc(inst)) == NULL) {
			*result = (void *)NULL;
			retval = DDI_FAILURE;
		} else {
			*result = (void *)softc->dip;
		}
		break;

	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)inst;
		break;

	default:
		retval = DDI_FAILURE;
	}

	return (retval);
}

static int
tsalarm_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{

	int inst;
	struct tsalarm_softc *softc = NULL;

	switch (cmd) {

	case DDI_ATTACH:
		inst = ddi_get_instance(dip);
		/*
		 * Allocate a soft state structure for this instance.
		 */
		if (ddi_soft_state_zalloc(statep, inst) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "Failed to allocate memory");
			goto attach_failed;
		}

		softc = getsoftc(inst);
		softc->dip = dip;
		softc->mtu_size = PCP_DEF_MTU_SZ;
		softc->msg_xid = 0;
		softc->read_area = NULL;
		softc->read_head = NULL;
		softc->read_tail = NULL;
		softc->req_ptr = NULL;
		softc->resp_ptr = NULL;

		mutex_init(&softc->mutex, NULL, MUTEX_DRIVER, NULL);
		/*
		 * Create minor node.  The minor device number, inst, has no
		 * meaning.  The model number above, which will be added to
		 * the device's softc, is used to direct peculiar behavior.
		 */
		if (ddi_create_minor_node(dip, "lom", S_IFCHR, 0,
		    DDI_PSEUDO, NULL) == DDI_FAILURE) {
			goto attach_failed;
		}

		ddi_report_dev(dip);
		return (DDI_SUCCESS);

	case DDI_RESUME:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

attach_failed:
	/* Free soft state, if allocated. remove minor node if added earlier */
	if (softc) {
		mutex_destroy(&softc->mutex);
		ddi_soft_state_free(statep, inst);
	}

	ddi_remove_minor_node(dip, NULL);

	return (DDI_FAILURE);
}

static int
tsalarm_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int inst;
	struct tsalarm_softc *softc;

	switch (cmd) {

	case DDI_DETACH:
		inst = ddi_get_instance(dip);
		if ((softc = getsoftc(inst)) == NULL)
			return (DDI_FAILURE);
		/*
		 * Free the soft state and remove minor node added earlier.
		 */
		ddi_remove_minor_node(dip, NULL);
		mutex_destroy(&softc->mutex);
		ddi_soft_state_free(statep, inst);
		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);

	}
}

/* ARGSUSED */
static int
tsalarm_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	int	rv, inst = getminor(*devp);
	struct tsalarm_softc *softc;
	glvc_xport_opt_op_t	channel_op;
	int rval;

	softc = (struct tsalarm_softc *)getsoftc(inst);
	if (softc == NULL) {
		cmn_err(CE_WARN, "getsoftc failed\n");
		return (EIO);
	}

	mutex_enter(&softc->mutex);

	rv = ldi_ident_from_dev(*devp, &softc->li);
	if (rv != 0) {
		cmn_err(CE_WARN, "ldi_ident_from_dev failed\n");
		goto FAIL;
	}
	softc->flags |= TSAL_IDENTED;

	rv = ldi_open_by_name(ALARM_CHANNEL, FREAD | FWRITE, kcred, &softc->lh,
	    softc->li);
	if (rv != 0) {
		cmn_err(CE_WARN, "ldi_open_by_name failed\n");
		goto FAIL;
	}
	softc->flags |= TSAL_OPENED;

	/* Get the MTU of the target channel */
	channel_op.op_sel = GLVC_XPORT_OPT_GET;
	channel_op.opt_sel = GLVC_XPORT_OPT_MTU_SZ;
	channel_op.opt_val = 0;

	if ((rv = ldi_ioctl(softc->lh, GLVC_XPORT_IOCTL_OPT_OP,
	    (intptr_t)&channel_op, FKIOCTL, kcred, &rval)) < 0) {
		cmn_err(CE_WARN, "ldi_ioctl failed\n");
		goto FAIL;
	}
	softc->mtu_size = channel_op.opt_val;

	if ((softc->req_ptr = (tsal_pcp_alarm_req_t *)kmem_zalloc(
	    sizeof (tsal_pcp_alarm_req_t),
	    KM_NOSLEEP)) == NULL) {
		goto FAIL;
	}
	if ((softc->resp_ptr = (tsal_pcp_alarm_resp_t *)kmem_zalloc(
	    sizeof (tsal_pcp_alarm_resp_t),
	    KM_NOSLEEP)) == NULL) {
		goto FAIL;
	}
	if ((softc->req_msg_hdr = (tsal_pcp_req_msg_hdr_t *)kmem_zalloc(
	    sizeof (tsal_pcp_req_msg_hdr_t),
	    KM_NOSLEEP)) == NULL) {
		goto FAIL;
	}
	if ((softc->resp_msg_hdr = (tsal_pcp_resp_msg_hdr_t *)kmem_zalloc(
	    sizeof (tsal_pcp_resp_msg_hdr_t),
	    KM_NOSLEEP)) == NULL) {
		goto FAIL;
	}
	if ((softc->peek_area = (uint8_t *)kmem_zalloc(softc->mtu_size,
	    KM_NOSLEEP)) == NULL) {
		goto FAIL;
	}
	if ((softc->peek_read_area = (uint8_t *)kmem_zalloc(2*softc->mtu_size,
	    KM_NOSLEEP)) == NULL) {
		goto FAIL;
	}

	rv = 0;

FAIL:
	if (rv != 0) {
		if (softc->flags & TSAL_OPENED)
			(void) ldi_close(softc->lh, FREAD|FWRITE, credp);
		if (softc->flags * TSAL_IDENTED)
			(void) ldi_ident_release(softc->li);
		softc->flags &= ~(TSAL_OPENED | TSAL_IDENTED);
		if (softc->req_ptr != NULL)
			kmem_free(softc->req_ptr,
			    sizeof (tsal_pcp_alarm_req_t));
		if (softc->resp_ptr != NULL)
			kmem_free(softc->resp_ptr,
			    sizeof (tsal_pcp_alarm_resp_t));
		if (softc->req_msg_hdr != NULL)
			kmem_free(softc->req_msg_hdr,
			    sizeof (tsal_pcp_req_msg_hdr_t));
		if (softc->resp_msg_hdr != NULL)
			kmem_free(softc->resp_msg_hdr,
			    sizeof (tsal_pcp_resp_msg_hdr_t));
		if (softc->peek_area != NULL)
			kmem_free(softc->peek_area, softc->mtu_size);
		if (softc->peek_read_area != NULL)
			kmem_free(softc->peek_read_area, 2*softc->mtu_size);
	}
	mutex_exit(&softc->mutex);

	return (rv);
}


/* ARGSUSED */
static int
tsalarm_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	int rv,	inst = getminor(dev);
	struct tsalarm_softc *softc;

	softc = (struct tsalarm_softc *)getsoftc(inst);

	if (softc == NULL) {
		return (EIO);
	}

	mutex_enter(&softc->mutex);

	rv = ldi_close(softc->lh, FREAD | FWRITE, kcred);
	if (rv != 0) {
		cmn_err(CE_WARN, "ldi_close failed \n");
	}

	ldi_ident_release(softc->li);
	softc->flags &= ~(TSAL_OPENED | TSAL_IDENTED);

	mutex_exit(&softc->mutex);

	/*
	 * free global buffers
	 */
	if (softc->read_area != NULL) {
		kmem_free(softc->read_area, 2*softc->mtu_size);
		softc->read_area = NULL;
	}
	if (softc->req_ptr != NULL) {
		kmem_free(softc->req_ptr,
		    sizeof (tsal_pcp_alarm_req_t));
		softc->req_ptr = NULL;
	}
	if (softc->resp_ptr != NULL) {
		kmem_free(softc->resp_ptr,
		    sizeof (tsal_pcp_alarm_resp_t));
		softc->resp_ptr = NULL;
	}
	if (softc->req_msg_hdr != NULL) {
		kmem_free(softc->req_msg_hdr,
		    sizeof (tsal_pcp_req_msg_hdr_t));
		softc->req_msg_hdr = NULL;
	}
	if (softc->resp_msg_hdr != NULL) {
		kmem_free(softc->resp_msg_hdr,
		    sizeof (tsal_pcp_resp_msg_hdr_t));
		softc->resp_msg_hdr = NULL;
	}
	if (softc->peek_area != NULL) {
		kmem_free(softc->peek_area, softc->mtu_size);
		softc->peek_area = NULL;
	}
	if (softc->peek_read_area != NULL) {
		kmem_free(softc->peek_read_area, 2*softc->mtu_size);
		softc->peek_read_area = NULL;
	}

	return (rv);
}


/* ARGSUSED */
static int
tsalarm_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
    cred_t *credp, int *rvalp)
{
	int		inst = getminor(dev);
	struct tsalarm_softc *softc;
	int retval = 0;
	ts_aldata_t ts_alinfo;
	int alarm_type, alarm_state = 0;

	if ((softc = getsoftc(inst)) == NULL)
		return (ENXIO);

	mutex_enter(&softc->mutex);

	switch (cmd) {

	case LOMIOCALSTATE:
	case LOMIOCALSTATE_OLD:
		{
			if (ddi_copyin((caddr_t)arg, (caddr_t)&ts_alinfo,
			    sizeof (ts_aldata_t), mode) != 0) {
				retval = EFAULT;
				goto end;
			}

			alarm_type = ts_alinfo.alarm_no;
			if ((alarm_type < ALARM_CRITICAL) ||
			    (alarm_type > ALARM_USER)) {
				retval = EINVAL;
				goto end;
			}

			retval = glvc_alarm_get(alarm_type, &alarm_state,
			    softc);

			if (retval != 0)
				goto end;

			if ((alarm_state != 0) && (alarm_state != 1)) {
				retval = EIO;
				goto end;
			}

			ts_alinfo.alarm_state = alarm_state;
			if (ddi_copyout((caddr_t)&ts_alinfo, (caddr_t)arg,
			    sizeof (ts_aldata_t), mode) != 0) {
				retval = EFAULT;
				goto end;
			}
		}
		break;

	case LOMIOCALCTL:
	case LOMIOCALCTL_OLD:
		{
			if (ddi_copyin((caddr_t)arg, (caddr_t)&ts_alinfo,
			    sizeof (ts_aldata_t), mode) != 0) {
				retval = EFAULT;
				goto end;
			}

			alarm_type = ts_alinfo.alarm_no;
			alarm_state = ts_alinfo.alarm_state;

			if ((alarm_type < ALARM_CRITICAL) ||
			    (alarm_type > ALARM_USER)) {
				retval = EINVAL;
				goto end;
			}
			if ((alarm_state < ALARM_OFF) ||
			    (alarm_state > ALARM_ON)) {
				retval = EINVAL;
				goto end;
			}

			retval = glvc_alarm_set(alarm_type, alarm_state, softc);
		}
		break;

	default:
		retval = EINVAL;
		break;
	}

end:
	mutex_exit(&softc->mutex);

	return (retval);
}

static int
glvc_alarm_get(int alarm_type, int *alarm_state, tsalarm_softc_t *sc)
{
	tsal_pcp_alarm_req_t	*req_ptr = NULL;
	tsal_pcp_alarm_resp_t	*resp_ptr = NULL;
	tsal_pcp_msg_t		send_msg;
	tsal_pcp_msg_t		recv_msg;
	int			status = -1;

	/*
	 * setup the request data to attach to the libpcp msg
	 */
	if (sc->req_ptr == NULL) {
		goto alarm_return;
	}

	req_ptr = sc->req_ptr;

	req_ptr->alarm_action = PCP_ALARM_STATUS;
	req_ptr->alarm_id = alarm_type;

	send_msg.msg_type = PCP_ALARM_CONTROL;
	send_msg.sub_type = NULL;
	send_msg.msg_len = sizeof (tsal_pcp_alarm_req_t);
	send_msg.msg_data = (uint8_t *)req_ptr;

	/*
	 * send the request, receive the response
	 */
	if (tsal_pcp_send_recv(sc, &send_msg, &recv_msg,
	    PCP_COMM_TIMEOUT) < 0) {
		/* we either timed out or erred; either way try again */
		(void) delay(PCP_COMM_TIMEOUT * drv_usectohz(1000000));

		if (tsal_pcp_send_recv(sc, &send_msg, &recv_msg,
		    PCP_COMM_TIMEOUT) < 0) {
			cmn_err(CE_WARN, "tsalarm: communication failure");
			goto alarm_return;
		}
	}

	/*
	 * validate that this data was meant for us
	 */
	if (recv_msg.msg_type != PCP_ALARM_CONTROL_R) {
		cmn_err(CE_WARN, "tsalarm: unbound packet received");
		goto alarm_return;
	}

	/*
	 * verify that the Alarm action has taken place
	 */
	resp_ptr = (tsal_pcp_alarm_resp_t *)recv_msg.msg_data;
	if (resp_ptr->status == PCP_ALARM_ERROR) {
		cmn_err(CE_WARN, "tsalarm: failed to get alarm status");
		goto alarm_return;
	}

	if (resp_ptr->alarm_state == ALARM_STATE_UNKNOWN)
		cmn_err(CE_WARN, "tsalarm: ALARM set to unknown state");

	*alarm_state = resp_ptr->alarm_state;
	status = TSAL_PCP_OK;

alarm_return:
	return (status);
}

static int
glvc_alarm_set(int alarm_type, int new_state, tsalarm_softc_t *sc)
{
	tsal_pcp_alarm_req_t	*req_ptr = NULL;
	tsal_pcp_alarm_resp_t	*resp_ptr = NULL;
	tsal_pcp_msg_t		send_msg;
	tsal_pcp_msg_t		recv_msg;
	int			status = -1;

	/*
	 * setup the request data to attach to the libpcp msg
	 */
	if (sc->req_ptr == NULL) {
		if ((sc->req_ptr = (tsal_pcp_alarm_req_t *)kmem_zalloc(
		    sizeof (tsal_pcp_alarm_req_t),
		    KM_NOSLEEP)) == NULL)
			goto alarm_return;
	}

	req_ptr = sc->req_ptr;

	if (new_state == ALARM_ON)
		req_ptr->alarm_action = PCP_ALARM_ENABLE;
	else if (new_state == ALARM_OFF)
		req_ptr->alarm_action = PCP_ALARM_DISABLE;

	req_ptr->alarm_id = alarm_type;

	send_msg.msg_type = PCP_ALARM_CONTROL;
	send_msg.sub_type = NULL;
	send_msg.msg_len = sizeof (tsal_pcp_alarm_req_t);
	send_msg.msg_data = (uint8_t *)req_ptr;

	/*
	 * send the request, receive the response
	 */
	if (tsal_pcp_send_recv(sc, &send_msg, &recv_msg,
	    PCP_COMM_TIMEOUT) < 0) {
		/* we either timed out or erred; either way try again */
		(void) delay(PCP_COMM_TIMEOUT * drv_usectohz(1000000));

		if (tsal_pcp_send_recv(sc, &send_msg, &recv_msg,
		    PCP_COMM_TIMEOUT) < 0) {
			goto alarm_return;
		}
	}

	/*
	 * validate that this data was meant for us
	 */
	if (recv_msg.msg_type != PCP_ALARM_CONTROL_R) {
		cmn_err(CE_WARN, "tsalarm: unbound packet received");
		goto alarm_return;
	}

	/*
	 * verify that the Alarm action has taken place
	 */
	resp_ptr = (tsal_pcp_alarm_resp_t *)recv_msg.msg_data;
	if (resp_ptr->status == PCP_ALARM_ERROR) {
		cmn_err(CE_WARN, "tsalarm: failed to set alarm status");
		goto alarm_return;
	}

	/*
	 * ensure the Alarm action taken is the one requested
	 */
	if ((req_ptr->alarm_action == PCP_ALARM_DISABLE) &&
	    (resp_ptr->alarm_state != ALARM_STATE_OFF)) {
		cmn_err(CE_WARN, "tsalarm: failed to set alarm");
		goto alarm_return;
	} else if ((req_ptr->alarm_action == PCP_ALARM_ENABLE) &&
	    (resp_ptr->alarm_state != ALARM_STATE_ON)) {
		cmn_err(CE_WARN, "tsalarm: failed to set alarm");
		goto alarm_return;
	} else if (resp_ptr->alarm_state == ALARM_STATE_UNKNOWN) {
		cmn_err(CE_WARN, "tsalarm: Alarm set to unknown state");
		goto alarm_return;
	}

	status = TSAL_PCP_OK;

alarm_return:
	return (status);
}
/*
 * Function: Send and Receive messages on platform channel.
 * Arguments:
 * int channel_fd      - channel file descriptor.
 * tsal_pcp_msg_t *req_msg  - Request Message to send to other end of channel.
 * tsal_pcp_msg_t *resp_msg - Response Message to be received.
 * uint32_t timeout    - timeout field when waiting for data from channel.
 * Returns:
 *	0    - success (TSAL_PCP_OK).
 *	(-1) - failure (TSAL_PCP_ERROR).
 */
static int
tsal_pcp_send_recv(tsalarm_softc_t *sc, tsal_pcp_msg_t *req_msg,
    tsal_pcp_msg_t *resp_msg, uint32_t timeout)
{
	void		*datap;
	void		*resp_msg_data = NULL;
	uint32_t	status;
	uint16_t	cksum = 0;
	int		ret;
	int		resp_hdr_ok;
	tsal_pcp_req_msg_hdr_t *req_msg_hdr = NULL;
	tsal_pcp_resp_msg_hdr_t *resp_msg_hdr = NULL;
#ifdef PCP_CKSUM_ENABLE
	uint16_t	bkup_resp_hdr_cksum;
#endif


	if (req_msg == NULL) {
		return (TSAL_PCP_ERROR);
	}

	if ((req_msg->msg_len != 0) && ((datap = req_msg->msg_data) == NULL))
		return (TSAL_PCP_ERROR);

	req_msg_hdr = sc->req_msg_hdr;

	if (req_msg_hdr == NULL)
		return (TSAL_PCP_ERROR);

	if (req_msg->msg_len != 0) {
		/* calculate request msg_cksum */
		cksum = checksum((uint16_t *)datap, req_msg->msg_len);
	}

	/*
	 * Fill in the message header for the request packet
	 */
	req_msg_hdr->magic_num = PCP_MAGIC_NUM;
	req_msg_hdr->proto_ver = PCP_PROT_VER_1;
	req_msg_hdr->msg_type = req_msg->msg_type;
	req_msg_hdr->sub_type = req_msg->sub_type;
	req_msg_hdr->rsvd_pad = 0;
	req_msg_hdr->xid = tsal_pcp_get_xid(sc);
	req_msg_hdr->msg_len  = req_msg->msg_len;
	req_msg_hdr->timeout = timeout;
	req_msg_hdr->msg_cksum = cksum;
	req_msg_hdr->hdr_cksum = 0;

	/* fill request header checksum */
	req_msg_hdr->hdr_cksum = checksum((uint16_t *)req_msg_hdr,
	    sizeof (tsal_pcp_req_msg_hdr_t));

	/*
	 * send request message header
	 */
	if ((ret = tsal_pcp_send_req_msg_hdr(sc, req_msg_hdr))) {
		return (ret);
	}

	/*
	 * send request message
	 */
	if (req_msg->msg_len != 0) {
		if ((ret = tsal_pcp_io_op(sc, datap, req_msg->msg_len,
		    PCP_IO_OP_WRITE))) {
			return (ret);
		}
	}

	if (timeout == (uint32_t)PCP_TO_NO_RESPONSE)
		return (TSAL_PCP_OK);

	resp_msg_hdr = sc->resp_msg_hdr;

	if (resp_msg_hdr == NULL) {
		return (TSAL_PCP_ERROR);
	}

	resp_hdr_ok = 0;
	while (!resp_hdr_ok) {
		/*
		 * Receive response message header
		 * Note: frame error handling is done in
		 * 'tsal_pcp_recv_resp_msg_hdr()'.
		 */
		if ((ret = tsal_pcp_recv_resp_msg_hdr(sc, resp_msg_hdr))) {
			return (ret);
		}

		/*
		 * Check header checksum if it matches with the received hdr
		 * checksum.
		 */
#ifdef PCP_CKSUM_ENABLE
		bkup_resp_hdr_cksum = resp_msg_hdr->hdr_cksum;
		resp_msg_hdr->hdr_cksum = 0;
		cksum = checksum((uint16_t *)resp_msg_hdr,
		    sizeof (tsal_pcp_resp_msg_hdr_t));

		if (cksum != bkup_resp_hdr_cksum) {
			return (TSAL_PCP_ERROR);
		}
#endif
		/*
		 * Check for matching request and response messages
		 */
		if (resp_msg_hdr->xid != req_msg_hdr->xid) {
			continue; /* continue reading response header */
		}
		resp_hdr_ok = 1;
	}

	/*
	 * check status field for any channel protocol errors
	 * This field signifies something happend during request
	 * message trasmission. This field is set by the receiver.
	 */
	status = resp_msg_hdr->status;
	if (status != TSAL_PCP_OK) {
		return (TSAL_PCP_ERROR);
	}

	if (resp_msg_hdr->msg_len != 0) {
		if (sc->resp_ptr == NULL)
			return (TSAL_PCP_ERROR);

		resp_msg_data = (uint8_t *)sc->resp_ptr;
		/*
		 * Receive response message.
		 */
		if ((ret = tsal_pcp_io_op(sc, resp_msg_data,
		    resp_msg_hdr->msg_len,
		    PCP_IO_OP_READ))) {
			return (ret);
		}

#ifdef PCP_CKSUM_ENABLE
		/* verify response message data checksum */
		cksum = checksum((uint16_t *)resp_msg_data,
		    resp_msg_hdr->msg_len);
		if (cksum != resp_msg_hdr->msg_cksum) {
			return (TSAL_PCP_ERROR);
		}
#endif
	}
	/* Everything is okay put the received data into user */
	/* resp_msg struct */
	resp_msg->msg_len = resp_msg_hdr->msg_len;
	resp_msg->msg_type = resp_msg_hdr->msg_type;
	resp_msg->sub_type = resp_msg_hdr->sub_type;
	resp_msg->msg_data = (uint8_t *)resp_msg_data;

	return (TSAL_PCP_OK);
}

/*
 * Function: wrapper for handling glvc calls (read/write/peek).
 */
static int
tsal_pcp_io_op(tsalarm_softc_t *sc, void *buf, int byte_cnt, int io_op)
{
	int	rv;
	int	n;
	uint8_t	*datap;
	int	(*func_ptr)(tsalarm_softc_t *, uint8_t *, int);
	int	io_sz;
	int	try_cnt;

	if ((buf == NULL) || (byte_cnt < 0)) {
		return (TSAL_PCP_ERROR);
	}

	switch (io_op) {
		case PCP_IO_OP_READ:
			func_ptr = tsal_pcp_read;
			break;
		case PCP_IO_OP_WRITE:
			func_ptr = tsal_pcp_write;
			break;
		case PCP_IO_OP_PEEK:
			func_ptr = tsal_pcp_peek;
			break;
		default:
			return (TSAL_PCP_ERROR);
	}

	/*
	 * loop until all I/O done, try limit exceded, or real failure
	 */

	rv = 0;
	datap = buf;
	while (rv < byte_cnt) {
		io_sz = MIN((byte_cnt - rv), sc->mtu_size);
		try_cnt = 0;
		while ((n = (*func_ptr)(sc, datap, io_sz)) < 0) {
			try_cnt++;
			if (try_cnt > PCP_MAX_TRY_CNT) {
				rv = n;
				goto done;
			}
			/* waiting 5 secs. Do we need 5 Secs? */
			(void) delay(PCP_GLVC_SLEEP * drv_usectohz(1000000));
		} /* while trying the io operation */

		if (n < 0) {
			rv = n;
			goto done;
		}
		rv += n;
		datap += n;
	} /* while still have more data */

done:
	if (rv == byte_cnt)
		return (0);
	else
		return (TSAL_PCP_ERROR);
}

/*
 * For peeking 'bytes_cnt' bytes in channel (glvc) buffers.
 * If data is available, the data is copied into 'buf'.
 */
static int
tsal_pcp_peek(tsalarm_softc_t *sc, uint8_t *buf, int bytes_cnt)
{
	int			ret, rval;
	glvc_xport_msg_peek_t	peek_ctrl;
	int			n, m;

	if (bytes_cnt < 0 || bytes_cnt > sc->mtu_size) {
		return (TSAL_PCP_ERROR);
	}

	/*
	 * initialization of buffers used for peeking data in channel buffers.
	 */
	if (sc->peek_area == NULL) {
		return (TSAL_PCP_ERROR);
	}

	/*
	 * peek max MTU size bytes
	 */
	peek_ctrl.buf = (caddr_t)sc->peek_area;
	peek_ctrl.buflen = sc->mtu_size;
	peek_ctrl.flags = 0;

	if ((ret = ldi_ioctl(sc->lh, GLVC_XPORT_IOCTL_DATA_PEEK,
	    (intptr_t)&peek_ctrl, FKIOCTL, kcred, &rval)) < 0) {
		return (ret);
	}

	n = peek_ctrl.buflen;

	if (n < 0)
		return (TSAL_PCP_ERROR);

	/*
	 * satisfy request as best as we can
	 */
	m = MIN(bytes_cnt, n);
	(void) memcpy(buf, sc->peek_area, m);

	return (m);
}

/*
 * Function: write 'byte_cnt' bytes from 'buf' to channel.
 */
static int
tsal_pcp_write(tsalarm_softc_t *sc, uint8_t *buf, int byte_cnt)
{
	int		ret;
	struct uio	uio;
	struct iovec	iov;

	/* check for valid arguments */
	if (buf == NULL || byte_cnt < 0 || byte_cnt > sc->mtu_size) {
		return (TSAL_PCP_ERROR);
	}
	bzero(&uio, sizeof (uio));
	bzero(&iov, sizeof (iov));
	iov.iov_base = (int8_t *)buf;
	iov.iov_len = byte_cnt;
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_loffset = 0;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_resid = byte_cnt;

	if ((ret = ldi_write(sc->lh, &uio, kcred)) < 0) {
		return (ret);
	}
	return (byte_cnt - iov.iov_len);
}

/*
 * In current implementaion of glvc driver, streams reads are not supported.
 * tsal_pcp_read mimics stream reads by first reading all the bytes present in
 * channel buffer into a local buffer and from then on read requests
 * are serviced from local buffer. When read requests are not serviceble
 * from local buffer, it repeates by first reading data from channel buffers.
 */

static int
tsal_pcp_read(tsalarm_softc_t *sc, uint8_t *buf, int byte_cnt)
{
	int			ret;
	int			n, m, i;
	struct uio		uio;
	struct iovec		iov;
	int			read_area_size = 0;

	if (byte_cnt < 0 || byte_cnt > sc->mtu_size) {
		return (TSAL_PCP_ERROR);
	}

	read_area_size = 2*sc->mtu_size;
	/*
	 * initialization of local read buffer
	 * from which the stream read requests are serviced.
	 */
	if (sc->read_area == NULL) {
		sc->read_area = (uint8_t *)kmem_zalloc(read_area_size,
		    KM_NOSLEEP);
		if (sc->read_area == NULL) {
			return (TSAL_PCP_ERROR);
		}
		sc->read_head = sc->read_area;
		sc->read_tail = sc->read_area;
	}

	/*
	 * if we already read this data then copy from local buffer it self
	 * without calling new read.
	 */
	if (byte_cnt <= (sc->read_tail - sc->read_head)) {
		(void) memcpy(buf, sc->read_head, byte_cnt);
		sc->read_head += byte_cnt;
		return (byte_cnt);
	}

	/*
	 * if the request is not satisfied from the buffered data, then move
	 * remaining data to front of the buffer and read new data.
	 */
	for (i = 0; i < (sc->read_tail - sc->read_head); ++i) {
		sc->read_area[i] = sc->read_head[i];
	}
	sc->read_head = sc->read_area;
	sc->read_tail = sc->read_head + i;

	/*
	 * do a peek to see how much data is available and read complete data.
	 */

	if ((m = tsal_pcp_peek(sc, sc->read_tail, sc->mtu_size)) < 0) {
		return (m);
	}

	bzero(&uio, sizeof (uio));
	bzero(&iov, sizeof (iov));
	iov.iov_base = (int8_t *)sc->read_tail;
	iov.iov_len = m;
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_loffset = 0;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_resid = m;

	if ((ret = ldi_read(sc->lh, &uio, kcred)) != 0) {
		return (ret);
	}

	sc->read_tail += (m - iov.iov_len);

	/*
	 * copy the requested bytes.
	 */
	n = MIN(byte_cnt, (sc->read_tail - sc->read_head));
	(void) memcpy(buf, sc->read_head, n);

	sc->read_head += n;

	return (n);
}
/*
 * This function is slight different from tsal_pcp_peek. The peek requests are
 * serviced from local read buffer, if data is available. If the peek request
 * is not serviceble from local read buffer, then the data is peeked from
 * channel buffer. This function is mainly used for proper protocol framing
 * error handling.
 */
static int
tsal_pcp_peek_read(tsalarm_softc_t *sc, uint8_t *buf, int byte_cnt)
{
	int	n, m, i;
	uint8_t	*peek_read_head = NULL;
	uint8_t *peek_read_tail = NULL;

	if (byte_cnt < 0 || byte_cnt > sc->mtu_size) {
		return (TSAL_PCP_ERROR);
	}

	/*
	 * if we already have the data in local read buffer then copy
	 * from local buffer it self w/out calling new peek
	 */
	if (byte_cnt <= (sc->read_tail - sc->read_head)) {
		(void) memcpy(buf, sc->read_head, byte_cnt);
		return (byte_cnt);
	}


	if (sc->peek_read_area == NULL) {
		return (TSAL_PCP_ERROR);
	}
	peek_read_head = sc->peek_read_area;
	peek_read_tail = sc->peek_read_area;

	/*
	 * if the request is not satisfied from local read buffer, then first
	 * copy the remaining data in local read buffer to peek_read_area and
	 * then issue new peek.
	 */
	for (i = 0; i < (sc->read_tail - sc->read_head); ++i) {
		sc->peek_read_area[i] = sc->read_head[i];
	}
	peek_read_head = sc->peek_read_area;
	peek_read_tail = peek_read_head + i;

	/*
	 * do a peek to see how much data is available and read complete data.
	 */

	if ((m = tsal_pcp_peek(sc, peek_read_tail, sc->mtu_size)) < 0) {
		return (m);
	}

	peek_read_tail += m;

	/*
	 * copy the requested bytes
	 */
	n = MIN(byte_cnt, (peek_read_tail - peek_read_head));
	(void) memcpy(buf, peek_read_head, n);

	return (n);
}
/*
 * Send Request Message Header.
 */
static int
tsal_pcp_send_req_msg_hdr(tsalarm_softc_t *sc, tsal_pcp_req_msg_hdr_t *req_hdr)
{
	tsal_pcp_req_msg_hdr_t	*hdrp;
	int			hdr_sz;
	int			ret;

	hdr_sz = sizeof (tsal_pcp_req_msg_hdr_t);
	if ((hdrp = (tsal_pcp_req_msg_hdr_t *)kmem_zalloc(hdr_sz,
	    KM_NOSLEEP)) == NULL) {
		return (TSAL_PCP_ERROR);
	}

	hdrp->magic_num = htonl(req_hdr->magic_num);
	hdrp->proto_ver = req_hdr->proto_ver;
	hdrp->msg_type = req_hdr->msg_type;
	hdrp->sub_type = req_hdr->sub_type;
	hdrp->rsvd_pad = htons(req_hdr->rsvd_pad);
	hdrp->xid = htonl(req_hdr->xid);
	hdrp->timeout = htonl(req_hdr->timeout);
	hdrp->msg_len = htonl(req_hdr->msg_len);
	hdrp->msg_cksum = htons(req_hdr->msg_cksum);
	hdrp->hdr_cksum = htons(req_hdr->hdr_cksum);

	if ((ret = tsal_pcp_io_op(sc, (char *)hdrp, hdr_sz,
	    PCP_IO_OP_WRITE)) != 0) {
		kmem_free(hdrp, hdr_sz);
		return (ret);
	}
	kmem_free(hdrp, hdr_sz);
	return (TSAL_PCP_OK);
}
/*
 * Receive Response message header.
 */
static int
tsal_pcp_recv_resp_msg_hdr(tsalarm_softc_t *sc,
    tsal_pcp_resp_msg_hdr_t *resp_hdr)
{
	uint32_t	magic_num;
	uint8_t		proto_ver;
	uint8_t		msg_type;
	uint8_t		sub_type;
	uint8_t		rsvd_pad;
	uint32_t	xid;
	uint32_t	timeout;
	uint32_t	msg_len;
	uint32_t	status;
	uint16_t	msg_cksum;
	uint16_t	hdr_cksum;
	int		ret;

	if (resp_hdr == NULL) {
		return (TSAL_PCP_ERROR);
	}

	/*
	 * handle protocol framing errors.
	 * tsal_pcp_frame_error_handle() returns when proper frame arrived
	 * (magic seq) or if an error happens while reading data from
	 * channel.
	 */
	if ((ret = tsal_pcp_frame_error_handle(sc)) != 0) {
		return (TSAL_PCP_ERROR);
	}

	/* read magic number first */
	if ((ret = tsal_pcp_io_op(sc, &magic_num, sizeof (magic_num),
	    PCP_IO_OP_READ)) != 0) {
		return (ret);
	}

	magic_num = ntohl(magic_num);

	if (magic_num != PCP_MAGIC_NUM) {
		return (TSAL_PCP_ERROR);
	}

	/* read version field */
	if ((ret = tsal_pcp_io_op(sc, &proto_ver, sizeof (proto_ver),
	    PCP_IO_OP_READ)) != 0) {
		return (ret);
	}

	/* check protocol version */
	if (proto_ver != PCP_PROT_VER_1) {
		return (TSAL_PCP_ERROR);
	}

	/* Read message type */
	if ((ret = tsal_pcp_io_op(sc, &msg_type, sizeof (msg_type),
	    PCP_IO_OP_READ)) != 0) {
		return (ret);
	}

	/* Read message sub type */
	if ((ret = tsal_pcp_io_op(sc, &sub_type, sizeof (sub_type),
	    PCP_IO_OP_READ)) != 0) {
		return (ret);
	}

	/* Read rcvd_pad bits */
	if ((ret = tsal_pcp_io_op(sc, &rsvd_pad, sizeof (rsvd_pad),
	    PCP_IO_OP_READ)) != 0) {
		return (ret);
	}

	/* receive transaction id */
	if ((ret = tsal_pcp_io_op(sc, &xid, sizeof (xid),
	    PCP_IO_OP_READ)) != 0) {
		return (ret);
	}

	xid = ntohl(xid);

	/* receive timeout value */
	if ((ret = tsal_pcp_io_op(sc, &timeout, sizeof (timeout),
	    PCP_IO_OP_READ)) != 0) {
		return (ret);
	}

	timeout = ntohl(timeout);

	/* receive message length */
	if ((ret = tsal_pcp_io_op(sc, &msg_len, sizeof (msg_len),
	    PCP_IO_OP_READ)) != 0) {
		return (ret);
	}

	msg_len = ntohl(msg_len);

	/* receive status field */
	if ((ret = tsal_pcp_io_op(sc, &status, sizeof (status),
	    PCP_IO_OP_READ)) != 0) {
		return (ret);
	}

	status = ntohl(status);

	/* receive message checksum */
	if ((ret = tsal_pcp_io_op(sc, &msg_cksum, sizeof (msg_cksum),
	    PCP_IO_OP_READ)) != 0) {
		return (ret);
	}

	msg_cksum = ntohs(msg_cksum);

	/* receive header checksum */
	if ((ret = tsal_pcp_io_op(sc, &hdr_cksum, sizeof (hdr_cksum),
	    PCP_IO_OP_READ)) != 0) {
		return (ret);
	}

	hdr_cksum = ntohs(hdr_cksum);

	/* copy to resp_hdr */

	resp_hdr->magic_num = magic_num;
	resp_hdr->proto_ver = proto_ver;
	resp_hdr->msg_type = msg_type;
	resp_hdr->sub_type = sub_type;
	resp_hdr->rsvd_pad = rsvd_pad;
	resp_hdr->xid = xid;
	resp_hdr->timeout = timeout;
	resp_hdr->msg_len = msg_len;
	resp_hdr->status = status;
	resp_hdr->msg_cksum = msg_cksum;
	resp_hdr->hdr_cksum = hdr_cksum;

	return (TSAL_PCP_OK);
}

/*
 * Get next xid for including in request message.
 * Every request and response message are matched
 * for same xid.
 */

static uint32_t
tsal_pcp_get_xid(tsalarm_softc_t *sc)
{
	uint32_t		ret;
	static boolean_t	xid_initialized = B_FALSE;

	if (xid_initialized == B_FALSE) {
		xid_initialized = B_TRUE;
		/*
		 * starting xid is initialized to a different value everytime
		 * user application is restarted so that user apps will not
		 * receive previous session's packets.
		 *
		 * Note: The algorithm for generating initial xid is partially
		 * taken from Solaris rpc code.
		 */
		sc->msg_xid = (uint32_t)gethrtime();
	}

	ret = sc->msg_xid++;

	/* zero xid is not allowed */
	if (ret == 0)
		ret = sc->msg_xid++;

	return (ret);
}

/*
 * This function handles channel framing errors. It waits until proper
 * frame with starting sequence as magic numder (0xAFBCAFA0)
 * is arrived. It removes unexpected data (before the magic number sequence)
 * on the channel. It returns when proper magic number sequence is seen
 * or when any failure happens while reading/peeking the channel.
 */
static int
tsal_pcp_frame_error_handle(tsalarm_softc_t *sc)
{
	uint8_t		magic_num_buf[4];
	int		ispresent = 0;
	uint32_t	net_magic_num; /* magic byte in network byte order */
	uint32_t	host_magic_num = PCP_MAGIC_NUM;
	uint8_t		buf[2];

	net_magic_num =	 htonl(host_magic_num);
	(void) memcpy(magic_num_buf, (uint8_t *)&net_magic_num, 4);

	while (!ispresent) {
		/*
		 * Check if next four bytes matches pcp magic number.
		 * if mathing not found, discard 1 byte and continue checking.
		 */
		if (!check_magic_byte_presence(sc, 4, &magic_num_buf[0],
		    &ispresent)) {
			if (!ispresent) {
				/* remove 1 byte */
				(void) tsal_pcp_io_op(sc, buf, 1,
				    PCP_IO_OP_READ);
			}
		} else {
			return (-1);
		}
	}

	return (0);
}

/*
 * checks whether certain byte sequence is present in the data stream.
 */
static int
check_magic_byte_presence(tsalarm_softc_t *sc,
    int byte_cnt, uint8_t *byte_seq, int *ispresent)
{
	int		ret, i;
	uint8_t		buf[4];

	if ((ret = tsal_pcp_peek_read(sc, buf, byte_cnt)) < 0) {
		return (ret);
	}

	/* 'byte_cnt' bytes not present */
	if (ret != byte_cnt) {
		*ispresent = 0;
		return (0);
	}

	for (i = 0; i < byte_cnt; ++i) {
		if (buf[i] != byte_seq[i]) {
			*ispresent = 0;
			return (0);
		}
	}
	*ispresent = 1;

	return (0);
}

/*
 * 16-bit simple internet checksum
 */
static uint16_t
checksum(uint16_t *addr, int32_t count)
{
	/*
	 * Compute Internet Checksum for "count" bytes
	 * beginning at location "addr".
	 */

	register uint32_t	sum = 0;

	while (count > 1)  {
		/*  This is the inner loop */
		sum += *(unsigned short *)addr++;
		count -= 2;
	}

	/*  Add left-over byte, if any */
	if (count > 0)
		sum += * (unsigned char *)addr;

	/* Fold 32-bit sum to 16 bits */
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	sum = (~sum) & 0xffff;
	if (sum == 0)
		sum = 0xffff;

	return (sum);
}
