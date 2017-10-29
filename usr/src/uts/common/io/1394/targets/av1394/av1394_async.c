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

/*
 * Copyright 2017 Joyent, Inc.
 */

/*
 * av1394 asynchronous module
 */
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/1394/targets/av1394/av1394_impl.h>

/* configuration routines */
static void	av1394_async_cleanup(av1394_inst_t *, int);
static int	av1394_async_create_minor_node(av1394_inst_t *);
static void	av1394_async_remove_minor_node(av1394_inst_t *);
static int	av1394_async_update_targetinfo(av1394_inst_t *);
static int	av1394_async_db2arq_type(int);
static void	av1394_async_putbq(av1394_queue_t *, mblk_t *);

static int	av1394_ioctl_arq_get_ibuf_size(av1394_inst_t *, void *, int);
static int	av1394_ioctl_arq_set_ibuf_size(av1394_inst_t *, void *, int);

#define	AV1394_TNF_ENTER(func)	\
	TNF_PROBE_0_DEBUG(func##_enter, AV1394_TNF_ASYNC_STACK, "");

#define	AV1394_TNF_EXIT(func)	\
	TNF_PROBE_0_DEBUG(func##_exit, AV1394_TNF_ASYNC_STACK, "");

/* tunables */
int av1394_ibuf_size_default = 64 * 1024;	/* default ibuf size */
int av1394_ibuf_size_max = 1024 * 1024;		/* max ibuf size */

/*
 *
 * --- configuration entry points
 *
 */
int
av1394_async_attach(av1394_inst_t *avp)
{
	av1394_async_t	*ap = &avp->av_a;
	ddi_iblock_cookie_t ibc = avp->av_attachinfo.iblock_cookie;

	AV1394_TNF_ENTER(av1394_async_attach);

	mutex_init(&ap->a_mutex, NULL, MUTEX_DRIVER, ibc);
	av1394_initq(&ap->a_rq, ibc, av1394_ibuf_size_default);

	if (av1394_fcp_attach(avp) != DDI_SUCCESS) {
		av1394_async_cleanup(avp, 1);
		AV1394_TNF_EXIT(av1394_async_attach);
		return (DDI_FAILURE);
	}

	if (av1394_cfgrom_init(avp) != DDI_SUCCESS) {
		av1394_async_cleanup(avp, 2);
		AV1394_TNF_EXIT(av1394_async_attach);
		return (DDI_FAILURE);
	}

	if (av1394_async_create_minor_node(avp) != DDI_SUCCESS) {
		av1394_async_cleanup(avp, 3);
		AV1394_TNF_EXIT(av1394_async_attach);
		return (DDI_FAILURE);
	}

	if (av1394_async_update_targetinfo(avp) != DDI_SUCCESS) {
		av1394_async_cleanup(avp, 4);
		AV1394_TNF_EXIT(av1394_async_attach);
		return (DDI_FAILURE);
	}

	AV1394_TNF_EXIT(av1394_async_attach);
	return (DDI_SUCCESS);
}

void
av1394_async_detach(av1394_inst_t *avp)
{
	AV1394_TNF_ENTER(av1394_async_detach);

	av1394_async_cleanup(avp, AV1394_CLEANUP_LEVEL_MAX);

	AV1394_TNF_EXIT(av1394_async_detach);
}

void
av1394_async_bus_reset(av1394_inst_t *avp)
{
	av1394_async_t	*ap = &avp->av_a;
	mblk_t		*bp;

	AV1394_TNF_ENTER(av1394_async_bus_reset);

	(void) av1394_async_update_targetinfo(avp);

	mutex_enter(&ap->a_mutex);
	if (ap->a_nopen > 0) {
		mutex_exit(&ap->a_mutex);
		return;
	}
	mutex_exit(&ap->a_mutex);

	/* queue up a bus reset message */
	if ((bp = allocb(1, BPRI_HI)) == NULL) {
		TNF_PROBE_0(av1394_async_bus_reset_error_allocb,
		    AV1394_TNF_ASYNC_ERROR, "");
	} else {
		DB_TYPE(bp) = AV1394_M_BUS_RESET;
		av1394_async_putq_rq(avp, bp);
	}

	AV1394_TNF_EXIT(av1394_async_bus_reset);
}

int
av1394_async_cpr_resume(av1394_inst_t *avp)
{
	int	ret;

	AV1394_TNF_ENTER(av1394_async_cpr_resume);

	ret = av1394_async_update_targetinfo(avp);

	AV1394_TNF_EXIT(av1394_async_cpr_resume);
	return (ret);
}

void
av1394_async_reconnect(av1394_inst_t *avp)
{
	AV1394_TNF_ENTER(av1394_async_reconnect);

	(void) av1394_async_update_targetinfo(avp);

	AV1394_TNF_EXIT(av1394_async_reconnect);
}

int
av1394_async_open(av1394_inst_t *avp, int flag)
{
	av1394_async_t	*ap = &avp->av_a;

	AV1394_TNF_ENTER(av1394_async_open);

	mutex_enter(&ap->a_mutex);
	if (ap->a_nopen == 0) {
		ap->a_pollevents = 0;
	}
	ap->a_nopen++;
	ap->a_oflag = flag;
	mutex_exit(&ap->a_mutex);

	AV1394_TNF_EXIT(av1394_async_open);
	return (0);
}

/*ARGSUSED*/
int
av1394_async_close(av1394_inst_t *avp, int flag)
{
	av1394_async_t	*ap = &avp->av_a;

	AV1394_TNF_ENTER(av1394_async_close);

	av1394_cfgrom_close(avp);

	av1394_flushq(&ap->a_rq);

	mutex_enter(&ap->a_mutex);
	ap->a_nopen = 0;
	ap->a_pollevents = 0;
	mutex_exit(&ap->a_mutex);

	AV1394_TNF_EXIT(av1394_async_close);
	return (0);
}

int
av1394_async_read(av1394_inst_t *avp, struct uio *uiop)
{
	av1394_async_t	*ap = &avp->av_a;
	av1394_queue_t	*q = &ap->a_rq;
	iec61883_arq_t	arq;
	int		ret = 0;
	mblk_t		*mp;
	int		dbtype;
	int		len;

	AV1394_TNF_ENTER(av1394_async_read);

	/* copyout as much as we can */
	while ((uiop->uio_resid > 0) && (ret == 0)) {
		/*
		 * if data is available, copy it out. otherwise wait until
		 * data arrives, unless opened with non-blocking flag
		 */
		if ((mp = av1394_getq(q)) == NULL) {
			if (ap->a_oflag & FNDELAY) {
				AV1394_TNF_EXIT(av1394_async_read);
				return (EAGAIN);
			}
			if (av1394_qwait_sig(q) <= 0) {
				ret = EINTR;
			}
			continue;
		}
		dbtype = AV1394_DBTYPE(mp);

		/* generate and copyout ARQ header, if not already */
		if (!AV1394_IS_NOHDR(mp)) {
			/* headers cannot be partially read */
			if (uiop->uio_resid < sizeof (arq)) {
				av1394_async_putbq(q, mp);
				ret = EINVAL;
				break;
			}

			arq.arq_type = av1394_async_db2arq_type(dbtype);
			arq.arq_len = MBLKL(mp);
			arq.arq_data.octlet = 0;

			/* copy ARQ-embedded data */
			len = min(arq.arq_len, sizeof (arq.arq_data));
			bcopy(mp->b_rptr, &arq.arq_data.buf[0], len);

			/* copyout the ARQ */
			ret = uiomove(&arq, sizeof (arq), UIO_READ, uiop);
			if (ret != 0) {
				av1394_async_putbq(q, mp);
				break;
			}
			mp->b_rptr += len;
			AV1394_MARK_NOHDR(mp);
		}

		/* any data left? */
		if (MBLKL(mp) == 0) {
			freemsg(mp);
			continue;
		}

		/* now we have some data and some user buffer space to fill */
		len = min(uiop->uio_resid, MBLKL(mp));
		if (len > 0) {
			ret = uiomove(mp->b_rptr, len, UIO_READ, uiop);
			if (ret != 0) {
				av1394_async_putbq(q, mp);
				break;
			}
			mp->b_rptr += len;
		}

		/* save the rest of the data for later */
		if (MBLKL(mp) > 0) {
			av1394_async_putbq(q, mp);
		}
	}

	AV1394_TNF_EXIT(av1394_async_read);
	return (0);
}

int
av1394_async_write(av1394_inst_t *avp, struct uio *uiop)
{
	iec61883_arq_t	arq;
	int		ret;

	AV1394_TNF_ENTER(av1394_async_write);

	/* all data should arrive in ARQ format */
	while (uiop->uio_resid >= sizeof (arq)) {
		if ((ret = uiomove(&arq, sizeof (arq), UIO_WRITE, uiop)) != 0) {
			break;
		}

		switch (arq.arq_type) {
		case IEC61883_ARQ_FCP_CMD:
		case IEC61883_ARQ_FCP_RESP:
			ret = av1394_fcp_write(avp, &arq, uiop);
			break;
		default:
			ret = EINVAL;
		}
		if (ret != 0) {
			break;
		}
	}

	AV1394_TNF_EXIT(av1394_async_write);
	return (ret);
}

/*ARGSUSED*/
int
av1394_async_ioctl(av1394_inst_t *avp, int cmd, intptr_t arg, int mode,
    int *rvalp)
{
	int	ret = EINVAL;

	AV1394_TNF_ENTER(av1394_async_ioctl);

	switch (cmd) {
	case IEC61883_ARQ_GET_IBUF_SIZE:
		ret = av1394_ioctl_arq_get_ibuf_size(avp, (void *)arg, mode);
		break;
	case IEC61883_ARQ_SET_IBUF_SIZE:
		ret = av1394_ioctl_arq_set_ibuf_size(avp, (void *)arg, mode);
		break;
	case IEC61883_NODE_GET_BUS_NAME:
		ret = av1394_ioctl_node_get_bus_name(avp, (void *)arg, mode);
		break;
	case IEC61883_NODE_GET_UID:
		ret = av1394_ioctl_node_get_uid(avp, (void *)arg, mode);
		break;
	case IEC61883_NODE_GET_TEXT_LEAF:
		ret = av1394_ioctl_node_get_text_leaf(avp, (void *)arg, mode);
	}

	AV1394_TNF_EXIT(av1394_async_ioctl);
	return (ret);
}

int
av1394_async_poll(av1394_inst_t *avp, short events, int anyyet, short *reventsp,
    struct pollhead **phpp)
{
	av1394_async_t	*ap = &avp->av_a;
	av1394_queue_t	*rq = &ap->a_rq;

	AV1394_TNF_ENTER(av1394_async_poll);

	if (events & (POLLIN | POLLET)) {
		if ((events & POLLIN) && av1394_peekq(rq)) {
			*reventsp |= POLLIN;
		}

		if ((!*reventsp && !anyyet) || (events & POLLET)) {
			mutex_enter(&ap->a_mutex);
			if (events & POLLIN) {
				ap->a_pollevents |= POLLIN;
			}
			*phpp = &ap->a_pollhead;
			mutex_exit(&ap->a_mutex);
		}
	}

	AV1394_TNF_EXIT(av1394_async_poll);
	return (0);
}


/*
 * put a message on the read queue, take care of polling
 */
void
av1394_async_putq_rq(av1394_inst_t *avp, mblk_t *mp)
{
	av1394_async_t	*ap = &avp->av_a;

	if (!av1394_putq(&ap->a_rq, mp)) {
		freemsg(mp);
		TNF_PROBE_0(av1394_async_putq_rq_error_putq,
		    AV1394_TNF_ASYNC_ERROR, "");
	} else {
		mutex_enter(&ap->a_mutex);
		if (ap->a_pollevents & POLLIN) {
			ap->a_pollevents &= ~POLLIN;
			mutex_exit(&ap->a_mutex);
			pollwakeup(&ap->a_pollhead, POLLIN);
		} else {
			mutex_exit(&ap->a_mutex);
		}
	}
}

/*
 *
 * --- configuration routines
 *
 * av1394_async_cleanup()
 *    Cleanup after attach
 */
static void
av1394_async_cleanup(av1394_inst_t *avp, int level)
{
	av1394_async_t	*ap = &avp->av_a;

	ASSERT((level > 0) && (level <= AV1394_CLEANUP_LEVEL_MAX));

	switch (level) {
	default:
		av1394_async_remove_minor_node(avp);
		/* FALLTHRU */
	case 3:
		av1394_cfgrom_fini(avp);
		/* FALLTHRU */
	case 2:
		av1394_fcp_detach(avp);
		/* FALLTHRU */
	case 1:
		av1394_destroyq(&ap->a_rq);
		mutex_destroy(&ap->a_mutex);
	}
}

/*
 * av1394_async_create_minor_node()
 *    Create async minor node
 */
static int
av1394_async_create_minor_node(av1394_inst_t *avp)
{
	int	ret;

	ret = ddi_create_minor_node(avp->av_dip, "async",
	    S_IFCHR, AV1394_ASYNC_INST2MINOR(avp->av_instance),
	    DDI_NT_AV_ASYNC, NULL);
	if (ret != DDI_SUCCESS) {
		TNF_PROBE_0(av1394_async_create_minor_node_error,
		    AV1394_TNF_ASYNC_ERROR, "");
	}
	return (ret);
}

/*
 * av1394_async_remove_minor_node()
 *    Remove async minor node
 */
static void
av1394_async_remove_minor_node(av1394_inst_t *avp)
{
	ddi_remove_minor_node(avp->av_dip, "async");
}

/*
 * av1394_async_update_targetinfo()
 *    Retrieve target info and bus generation
 */
static int
av1394_async_update_targetinfo(av1394_inst_t *avp)
{
	av1394_async_t	*ap = &avp->av_a;
	uint_t		bg;
	int		ret;

	mutex_enter(&avp->av_mutex);
	bg = avp->av_attachinfo.localinfo.bus_generation;
	mutex_exit(&avp->av_mutex);

	mutex_enter(&ap->a_mutex);
	ret = t1394_get_targetinfo(avp->av_t1394_hdl, bg, 0, &ap->a_targetinfo);
	ap->a_bus_generation = bg;
	mutex_exit(&ap->a_mutex);

	return (ret);
}

static int
av1394_async_db2arq_type(int dbtype)
{
	int	arq_type;

	switch (dbtype) {
	case AV1394_M_FCP_RESP:
		arq_type = IEC61883_ARQ_FCP_RESP;
		break;
	case AV1394_M_FCP_CMD:
		arq_type = IEC61883_ARQ_FCP_CMD;
		break;
	case AV1394_M_BUS_RESET:
		arq_type = IEC61883_ARQ_BUS_RESET;
		break;
	default:
		ASSERT(0);	/* cannot happen */
	}
	return (arq_type);
}

static void
av1394_async_putbq(av1394_queue_t *q, mblk_t *mp)
{
	if (!av1394_putbq(q, mp)) {
		freemsg(mp);
		TNF_PROBE_0(av1394_async_putbq_error,
		    AV1394_TNF_ASYNC_ERROR, "");
	}
}

/*ARGSUSED*/
static int
av1394_ioctl_arq_get_ibuf_size(av1394_inst_t *avp, void *arg, int mode)
{
	av1394_async_t	*ap = &avp->av_a;
	int		sz;
	int		ret = 0;

	AV1394_TNF_ENTER(av1394_ioctl_arq_get_ibuf_size);

	sz = av1394_getmaxq(&ap->a_rq);

	if (ddi_copyout(&sz, arg, sizeof (sz), mode) != 0) {
		ret = EFAULT;
	}

	AV1394_TNF_EXIT(av1394_ioctl_arq_get_ibuf_size);
	return (ret);
}

/*ARGSUSED*/
static int
av1394_ioctl_arq_set_ibuf_size(av1394_inst_t *avp, void *arg, int mode)
{
	av1394_async_t	*ap = &avp->av_a;
	int		sz;
	int		ret = 0;

	AV1394_TNF_ENTER(av1394_ioctl_arq_set_ibuf_size);

	sz = (int)(intptr_t)arg;

	if ((sz < 0) || (sz > av1394_ibuf_size_max)) {
		ret = EINVAL;
	} else {
		av1394_setmaxq(&ap->a_rq, sz);
	}

	AV1394_TNF_EXIT(av1394_ioctl_arq_set_ibuf_size);
	return (ret);
}
