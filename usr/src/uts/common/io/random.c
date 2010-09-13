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
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * Random number generator pseudo-driver
 *
 * This is a lightweight driver which calls in to the Kernel Cryptographic
 * Framework to do the real work. Kernel modules should NOT depend on this
 * driver for /dev/random kernel API.
 *
 * Applications may ask for 2 types of random bits:
 * . High quality random by reading from /dev/random. The output is extracted
 *   only when a minimum amount of entropy is available.
 * . Pseudo-random, by reading from /dev/urandom, that can be generated any
 *   time.
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/stat.h>

#include <sys/file.h>
#include <sys/open.h>
#include <sys/poll.h>
#include <sys/uio.h>
#include <sys/cred.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/random.h>
#include <sys/crypto/impl.h>

#define	DEVRANDOM		0
#define	DEVURANDOM		1

#define	HASHSIZE		20	/* Assuming a SHA1 hash algorithm */
#define	WRITEBUFSIZE		512	/* Size of buffer for write request */
#define	MAXRETBYTES		1040	/* Max bytes returned per read. */
					/* Must be a multiple of HASHSIZE */
static dev_info_t *rnd_dip;

static int rnd_open(dev_t *, int, int, cred_t *);
static int rnd_close(dev_t, int, int, cred_t *);
static int rnd_read(dev_t, struct uio *, cred_t *);
static int rnd_write(dev_t, struct uio *, cred_t *);
static int rnd_chpoll(dev_t, short, int, short *, struct pollhead **);
static int rnd_attach(dev_info_t *, ddi_attach_cmd_t);
static int rnd_detach(dev_info_t *, ddi_detach_cmd_t);
static int rnd_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);

/* DDI declarations */
static struct cb_ops rnd_cb_ops = {
	rnd_open,		/* open */
	rnd_close,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	rnd_read,		/* read */
	rnd_write,		/* write */
	nodev,			/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	rnd_chpoll,		/* chpoll */
	ddi_prop_op,		/* prop_op */
	NULL,			/* streamtab  */
	(D_NEW | D_MP), 	/* cb_flag */
	CB_REV,			/* cb_rev */
	nodev,			/* aread */
	nodev			/* awrite */
};

static struct dev_ops rnd_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	rnd_getinfo,		/* get_dev_info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	rnd_attach,		/* attach */
	rnd_detach,		/* detach */
	nodev,			/* reset */
	&rnd_cb_ops,		/* driver operations */
	NULL,			/* bus operations */
	NULL,			/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

/* Modlinkage */
static struct modldrv modldrv = {
	&mod_driverops,
	"random number device",
	&rnd_ops
};

static struct modlinkage modlinkage = {	MODREV_1, { &modldrv, NULL } };


/* DDI glue */

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
rnd_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	if (ddi_create_minor_node(dip, "random", S_IFCHR, DEVRANDOM,
	    DDI_PSEUDO, 0) == DDI_FAILURE) {
		ddi_remove_minor_node(dip, NULL);
		return (DDI_FAILURE);
	}
	if (ddi_create_minor_node(dip, "urandom", S_IFCHR, DEVURANDOM,
	    DDI_PSEUDO, 0) == DDI_FAILURE) {
		ddi_remove_minor_node(dip, NULL);
		return (DDI_FAILURE);
	}

	rnd_dip = dip;

	return (DDI_SUCCESS);
}

static int
rnd_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	rnd_dip = NULL;
	ddi_remove_minor_node(dip, NULL);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
rnd_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	int error;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = rnd_dip;
		error = DDI_SUCCESS;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
	}
	return (error);
}

/*ARGSUSED3*/
static int
rnd_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	switch (getminor(*devp)) {
	case DEVRANDOM:
		if (!kcf_rngprov_check())
			return (ENXIO);
		break;
	case DEVURANDOM:
		break;
	default:
		return (ENXIO);
	}
	if (otyp != OTYP_CHR)
		return (EINVAL);

	if (flag & FEXCL)
		return (EINVAL);
	return (0);
}

/*ARGSUSED*/
static int
rnd_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	return (0);
}

/*ARGSUSED2*/
static int
rnd_read(dev_t dev, struct uio *uiop, cred_t *credp)
{
	size_t len;
	minor_t devno;
	int error = 0;
	int nbytes = 0;
	uint8_t random_bytes[2 * HASHSIZE];

	devno = getminor(dev);

	while (error == 0 && uiop->uio_resid > 0) {
		len = min(sizeof (random_bytes), uiop->uio_resid);
		switch (devno) {
		case DEVRANDOM:
			error = kcf_rnd_get_bytes(random_bytes, len,
			    uiop->uio_fmode & (FNDELAY|FNONBLOCK));
			break;
		case DEVURANDOM:
			error = kcf_rnd_get_pseudo_bytes(random_bytes, len);
			break;
		default:
			return (ENXIO);
		}

		if (error == 0) {
			/*
			 * /dev/[u]random is not a seekable device. To prevent
			 * uio offset from growing and eventually exceeding
			 * the maximum, reset the offset here for every call.
			 */
			uiop->uio_loffset = 0;
			error = uiomove(random_bytes, len, UIO_READ, uiop);

			nbytes += len;

			if (devno == DEVRANDOM && nbytes >= MAXRETBYTES)
				break;

		} else if ((error == EAGAIN) && (nbytes > 0)) {
			error = 0;
			break;
		}
	}
	return (error);
}

/*ARGSUSED*/
static int
rnd_write(dev_t dev, struct uio *uiop, cred_t *credp)
{
	int error;
	uint8_t buf[WRITEBUFSIZE];
	size_t bytes;
	minor_t devno;

	devno = getminor(dev);

	while (uiop->uio_resid > 0) {
		bytes = min(sizeof (buf), uiop->uio_resid);

		/* See comments in rnd_read() */
		uiop->uio_loffset = 0;
		if ((error = uiomove(buf, bytes, UIO_WRITE, uiop)) != 0)
			return (error);

		switch (devno) {
		case DEVRANDOM:
			if ((error = random_add_entropy(buf, bytes, 0)) != 0)
				return (error);
			break;
		case DEVURANDOM:
			if ((error = random_add_pseudo_entropy(buf, bytes,
			    0)) != 0)
				return (error);
			break;
		default:
			return (ENXIO);
		}
	}

	return (0);
}

static struct pollhead urnd_pollhd;

/*
 * poll(2) is supported as follows:
 * . Only POLLIN, POLLOUT, and POLLRDNORM events are supported.
 * . POLLOUT always succeeds.
 * . POLLIN and POLLRDNORM from /dev/urandom always succeeds.
 * . POLLIN and POLLRDNORM from /dev/random will block until a
 *   minimum amount of entropy is available.
 */
static int
rnd_chpoll(dev_t dev, short events, int anyyet, short *reventsp,
    struct pollhead **phpp)
{
	switch (getminor(dev)) {
	case DEVURANDOM:
		*reventsp = events & (POLLOUT | POLLIN | POLLRDNORM);

		/*
		 * A non NULL pollhead pointer should be returned in case
		 * user polls for 0 events.
		 */
		if (*reventsp == 0 && !anyyet)
			*phpp = &urnd_pollhd;

		break;
	case DEVRANDOM:
		kcf_rnd_chpoll(events, anyyet, reventsp, phpp);
		break;
	default:
		return (ENXIO);
	}

	return (0);
}
