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


/*
 * System message redirection driver for Sun.
 *
 * Redirects system message output to the device designated as the underlying
 * "hardware" console, as given by the value of sysmvp.  The implementation
 * assumes that sysmvp denotes a STREAMS device; the assumption is justified
 * since consoles must be capable of effecting tty semantics.
 */

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/open.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/signal.h>
#include <sys/cred.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/session.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/poll.h>
#include <sys/debug.h>
#include <sys/sysmsg_impl.h>
#include <sys/conf.h>
#include <sys/termios.h>
#include <sys/errno.h>
#include <sys/modctl.h>
#include <sys/pathname.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/consdev.h>
#include <sys/policy.h>

/*
 * internal functions
 */
static int sysmopen(dev_t *, int, int, cred_t *);
static int sysmclose(dev_t, int, int, cred_t *);
static int sysmread(dev_t, struct uio *, cred_t *);
static int sysmwrite(dev_t, struct uio *, cred_t *);
static int sysmioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int sysmpoll(dev_t, short, int, short *, struct pollhead **);
static int sysm_info(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int sysm_attach(dev_info_t *, ddi_attach_cmd_t);
static int sysm_detach(dev_info_t *, ddi_detach_cmd_t);
static void bind_consadm_conf(char *);
static int checkarg(dev_t);

static dev_info_t *sysm_dip;		/* private copy of devinfo pointer */

static struct cb_ops sysm_cb_ops = {

	sysmopen,		/* open */
	sysmclose,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	sysmread,		/* read */
	sysmwrite,		/* write */
	sysmioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	sysmpoll,		/* poll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* streamtab  */
	D_NEW | D_MP,		/* Driver compatibility flag */
	CB_REV,			/* cb_rev */
	nodev,			/* aread */
	nodev			/* awrite */
};

static struct dev_ops sysm_ops = {

	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	sysm_info,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	sysm_attach,		/* attach */
	sysm_detach,		/* detach */
	nodev,			/* reset */
	&sysm_cb_ops,		/* driver operations */
	(struct bus_ops *)0,	/* bus operations */
	nulldev,		/* power */
	ddi_quiesce_not_needed,		/* quiesce */

};

/*
 * Global variables associated with the console device:
 */

#define	SYS_SYSMIN	0	/* sysmsg minor number */
#define	SYS_MSGMIN	1	/* msglog minor number */
#define	SYSPATHLEN	255	/* length of device path */

/*
 * Private driver state:
 */

#define	MAXDEVS 5

typedef struct {
	dev_t	dca_devt;
	int	dca_flags;
	vnode_t	*dca_vp;
	krwlock_t	dca_lock;
	char	dca_name[SYSPATHLEN];
} devicecache_t;

/* list of dyn. + persist. config'ed dev's */
static devicecache_t sysmcache[MAXDEVS];
static kmutex_t	dcvp_mutex;
static vnode_t	*dcvp = NULL;
static boolean_t sysmsg_opened;
static boolean_t msglog_opened;

/* flags for device cache */
#define	SYSM_DISABLED	0x0
#define	SYSM_ENABLED	0x1

/*
 * Module linkage information for the kernel.
 */

static struct modldrv modldrv = {
	&mod_driverops, /* Type of module.  This one is a pseudo driver */
	"System message redirection (fanout) driver",
	&sysm_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

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

/*
 * DDI glue routines
 */
static int
sysm_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	int i;

	switch (cmd) {
	case DDI_ATTACH:
		ASSERT(sysm_dip == NULL);

		if (ddi_create_minor_node(devi, "sysmsg", S_IFCHR,
		    SYS_SYSMIN, DDI_PSEUDO, 0) == DDI_FAILURE ||
		    ddi_create_minor_node(devi, "msglog", S_IFCHR,
		    SYS_MSGMIN, DDI_PSEUDO, 0) == DDI_FAILURE) {
			ddi_remove_minor_node(devi, NULL);
			return (DDI_FAILURE);
		}

		for (i = 0; i < MAXDEVS; i++) {
			rw_init(&sysmcache[i].dca_lock, NULL, RW_DRIVER, NULL);
		}

		sysm_dip = devi;
		return (DDI_SUCCESS);
	case DDI_SUSPEND:
	case DDI_PM_SUSPEND:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
}

static int
sysm_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	int i;

	switch (cmd) {
	case DDI_DETACH:
		ASSERT(sysm_dip == devi);

		for (i = 0; i < MAXDEVS; i++)
			rw_destroy(&sysmcache[i].dca_lock);

		ddi_remove_minor_node(devi, NULL);
		sysm_dip = NULL;
		return (DDI_SUCCESS);

	case DDI_SUSPEND:
	case DDI_PM_SUSPEND:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

}

/* ARGSUSED */
static int
sysm_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	int rval = DDI_FAILURE;
	minor_t instance;

	instance = getminor((dev_t)arg);

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (sysm_dip != NULL &&
		    (instance == SYS_SYSMIN || instance == SYS_MSGMIN)) {
			*result = sysm_dip;
			rval = DDI_SUCCESS;
		}
		break;

	case DDI_INFO_DEVT2INSTANCE:
		if (instance == SYS_SYSMIN || instance == SYS_MSGMIN) {
			*result = NULL;
			rval = DDI_SUCCESS;
		}
		break;

	default:
		break;
	}

	return (rval);
}

/*
 * Parse the contents of the buffer, and bind the named
 * devices as auxiliary consoles using our own ioctl routine.
 *
 * Comments begin with '#' and are terminated only by a newline
 * Device names begin with a '/', and are terminated by a newline,
 * space, '#' or tab.
 */
static void
parse_buffer(char *buf, ssize_t fsize)
{
	char *ebuf = buf + fsize;
	char *devname = NULL;
	int eatcomments = 0;

	while (buf < ebuf) {
		if (eatcomments) {
			if (*buf++ == '\n')
				eatcomments = 0;
			continue;
		}
		switch (*buf) {
		case '/':
			if (devname == NULL)
				devname = buf;
			break;
		case '#':
			eatcomments = 1;
			/*FALLTHROUGH*/
		case ' ':
		case '\t':
		case '\n':
			*buf = '\0';
			if (devname == NULL)
				break;
			(void) sysmioctl(NODEV, CIOCSETCONSOLE,
			    (intptr_t)devname, FNATIVE|FKIOCTL|FREAD|FWRITE,
			    kcred, NULL);
			devname = NULL;
			break;
		default:
			break;
		}
		buf++;
	}
}

#define	CNSADM_BYTES_MAX	2000	/* XXX  nasty fixed size */

static void
bind_consadm_conf(char *path)
{
	struct vattr vattr;
	vnode_t *vp;
	void *buf;
	size_t size;
	ssize_t resid;
	int err = 0;

	if (vn_open(path, UIO_SYSSPACE, FREAD, 0, &vp, 0, 0) != 0)
		return;
	vattr.va_mask = AT_SIZE;
	if ((err = VOP_GETATTR(vp, &vattr, 0, kcred, NULL)) != 0) {
		cmn_err(CE_WARN, "sysmsg: getattr: '%s': error %d",
		    path, err);
		goto closevp;
	}

	size = vattr.va_size > CNSADM_BYTES_MAX ?
	    CNSADM_BYTES_MAX : (ssize_t)vattr.va_size;
	buf = kmem_alloc(size, KM_SLEEP);

	if ((err = vn_rdwr(UIO_READ, vp, buf, size, (offset_t)0,
	    UIO_SYSSPACE, 0, (rlim64_t)0, kcred, &resid)) != 0)
		cmn_err(CE_WARN, "sysmsg: vn_rdwr: '%s': error %d",
		    path, err);
	else
		parse_buffer(buf, size - resid);

	kmem_free(buf, size);
closevp:
	(void) VOP_CLOSE(vp, FREAD, 1, (offset_t)0, kcred, NULL);
	VN_RELE(vp);
}

/* ARGSUSED */
static int
sysmopen(dev_t *dev, int flag, int state, cred_t *cred)
{
	int	i;
	vnode_t	*vp;
	minor_t instance;
	static boolean_t initialized;

	instance = getminor(*dev);

	if (state != OTYP_CHR || (instance != 0 && instance != 1))
		return (ENXIO);

	mutex_enter(&dcvp_mutex);
	if ((dcvp == NULL) && (vn_open("/dev/console",
	    UIO_SYSSPACE, FWRITE, 0, &dcvp, 0, 0) != 0)) {
		mutex_exit(&dcvp_mutex);
		return (ENXIO);
	}

	if (instance == SYS_SYSMIN)
		sysmsg_opened = B_TRUE;
	else
		msglog_opened = B_TRUE;

	if (!initialized) {
		bind_consadm_conf("/etc/consadm.conf");
		initialized = B_TRUE;
	}
	mutex_exit(&dcvp_mutex);

	for (i = 0; i < MAXDEVS; i++) {
		rw_enter(&sysmcache[i].dca_lock, RW_WRITER);
		if ((sysmcache[i].dca_flags & SYSM_ENABLED) &&
		    sysmcache[i].dca_vp == NULL) {
			/*
			 * 4196476 - FTRUNC was causing E10K to return EINVAL
			 * on open
			 */
			flag = flag & ~FTRUNC;
			/*
			 * Open failures on the auxiliary consoles are
			 * not returned because we don't care if some
			 * subset get an error. We know the default console
			 * is okay, and preserve the semantics of the
			 * open for the default console.
			 * Set NONBLOCK|NDELAY in case there's no carrier.
			 */
			if (vn_open(sysmcache[i].dca_name, UIO_SYSSPACE,
			    flag | FNONBLOCK | FNDELAY, 0, &vp, 0, 0) == 0)
				sysmcache[i].dca_vp = vp;
		}
		rw_exit(&sysmcache[i].dca_lock);
	}

	return (0);
}

/* ARGSUSED */
static int
sysmclose(dev_t dev, int flag, int state, cred_t *cred)
{
	int	i;
	minor_t instance;

	ASSERT(dcvp != NULL);

	if (state != OTYP_CHR)
		return (ENXIO);

	instance = getminor(dev);

	mutex_enter(&dcvp_mutex);
	if (instance == SYS_SYSMIN)
		sysmsg_opened = B_FALSE;
	else
		msglog_opened = B_FALSE;

	if (sysmsg_opened || msglog_opened) {
		mutex_exit(&dcvp_mutex);
		return (0);
	}

	(void) VOP_CLOSE(dcvp, FWRITE, 1, (offset_t)0, kcred, NULL);
	VN_RELE(dcvp);
	dcvp = NULL;
	mutex_exit(&dcvp_mutex);

	/*
	 * Close the auxiliary consoles, we're not concerned with
	 * passing up the errors.
	 */
	for (i = 0; i < MAXDEVS; i++) {
		rw_enter(&sysmcache[i].dca_lock, RW_WRITER);
		if (sysmcache[i].dca_vp != NULL) {
			(void) VOP_CLOSE(sysmcache[i].dca_vp, flag,
			    1, (offset_t)0, cred, NULL);
			VN_RELE(sysmcache[i].dca_vp);
			sysmcache[i].dca_vp = NULL;
		}
		rw_exit(&sysmcache[i].dca_lock);
	}

	return (0);
}

/* Reads occur only on the default console */

/* ARGSUSED */
static int
sysmread(dev_t dev, struct uio *uio, cred_t *cred)
{
	ASSERT(dcvp != NULL);
	return (VOP_READ(dcvp, uio, 0, cred, NULL));
}

/* ARGSUSED */
static int
sysmwrite(dev_t dev, struct uio *uio, cred_t *cred)
{
	int	i = 0;
	iovec_t	uio_iov;
	struct uio	tuio;

	ASSERT(dcvp != NULL);
	ASSERT(uio != NULL);

	for (i = 0; i < MAXDEVS; i++) {
		rw_enter(&sysmcache[i].dca_lock, RW_READER);
		if (sysmcache[i].dca_vp != NULL &&
		    (sysmcache[i].dca_flags & SYSM_ENABLED)) {
			tuio = *uio;
			uio_iov = *(uio->uio_iov);
			tuio.uio_iov = &uio_iov;
			(void) VOP_WRITE(sysmcache[i].dca_vp, &tuio, 0, cred,
			    NULL);
		}
		rw_exit(&sysmcache[i].dca_lock);
	}
	return (VOP_WRITE(dcvp, uio, 0, cred, NULL));
}

/* ARGSUSED */
static int
sysmioctl(dev_t dev, int cmd, intptr_t arg, int flag, cred_t *cred, int *rvalp)
{
	int	rval = 0;
	int	error = 0;
	size_t	size = 0;
	int	i;
	char	*infop;
	char	found = 0;
	dev_t	newdevt = (dev_t)NODEV;	/* because 0 == /dev/console */
	vnode_t	*vp;

	switch (cmd) {
	case CIOCGETCONSOLE:
		/* Sum over the number of enabled devices */
		for (i = 0; i < MAXDEVS; i++) {
			if (sysmcache[i].dca_flags & SYSM_ENABLED)
				/* list is space separated, followed by NULL */
				size += strlen(sysmcache[i].dca_name) + 1;
		}
		if (size == 0)
			return (0);
		break;
	case CIOCSETCONSOLE:
	case CIOCRMCONSOLE:
		size = sizeof (sysmcache[0].dca_name);
		break;
	case CIOCTTYCONSOLE:
	{
		dev_t	d;
		dev32_t	d32;
		extern dev_t rwsconsdev, rconsdev, uconsdev;
		proc_t	*p;

		if (drv_getparm(UPROCP, &p) != 0)
			return (ENODEV);
		else
			d = cttydev(p);
		/*
		 * If the controlling terminal is the real
		 * or workstation console device, map to what the
		 * user thinks is the console device.
		 */
		if (d == rwsconsdev || d == rconsdev)
			d = uconsdev;
		if ((flag & FMODELS) != FNATIVE) {
			if (!cmpldev(&d32, d))
				return (EOVERFLOW);
			if (ddi_copyout(&d32, (caddr_t)arg, sizeof (d32),
			    flag))
				return (EFAULT);
		} else {
			if (ddi_copyout(&d, (caddr_t)arg, sizeof (d), flag))
				return (EFAULT);
		}
		return (0);
	}
	default:
		/* everything else is sent to the console device */
		return (VOP_IOCTL(dcvp, cmd, arg, flag, cred, rvalp, NULL));
	}

	if ((rval = secpolicy_console(cred)) != 0)
		return (EPERM);

	infop = kmem_alloc(size, KM_SLEEP);
	if (flag & FKIOCTL)
		error = copystr((caddr_t)arg, infop, size, NULL);
	else
		error = copyinstr((caddr_t)arg, infop, size, NULL);

	if (error) {
		switch (cmd) {
		case CIOCGETCONSOLE:
			/*
			 * If the buffer is null, then return a byte count
			 * to user land.
			 */
			*rvalp = size;
			goto err_exit;
		default:
			rval = EFAULT;
			goto err_exit;
		}
	}

	if (infop[0] != '\0') {
		if ((rval = lookupname(infop, UIO_SYSSPACE, FOLLOW,
		    NULLVPP, &vp)) == 0) {
			if (vp->v_type != VCHR) {
				VN_RELE(vp);
				rval = EINVAL;
				goto err_exit;
			}
			newdevt = vp->v_rdev;
			VN_RELE(vp);
		} else
			goto err_exit;
	}

	switch (cmd) {
	case CIOCGETCONSOLE:
		/*
		 * Return the list of device names that are enabled.
		 */
		for (i = 0; i < MAXDEVS; i++) {
			rw_enter(&sysmcache[i].dca_lock, RW_READER);
			if (sysmcache[i].dca_flags & SYSM_ENABLED) {
				if (infop[0] != '\0')
					(void) strcat(infop, " ");
				(void) strcat(infop, sysmcache[i].dca_name);
			}
			rw_exit(&sysmcache[i].dca_lock);
		}
		if (rval == 0 && copyoutstr(infop, (void *)arg, size, NULL))
			rval = EFAULT;
		break;

	case CIOCSETCONSOLE:
		if ((rval = checkarg(newdevt)) != 0)
			break;
		/*
		 * The device does not have to be open or disabled to
		 * perform the set console.
		 */
		for (i = 0; i < MAXDEVS; i++) {
			rw_enter(&sysmcache[i].dca_lock, RW_WRITER);
			if (sysmcache[i].dca_devt == newdevt &&
			    (sysmcache[i].dca_flags & SYSM_ENABLED)) {
				(void) strcpy(sysmcache[i].dca_name, infop);
				rval = EEXIST;
				rw_exit(&sysmcache[i].dca_lock);
				break;
			} else if (sysmcache[i].dca_devt == newdevt &&
			    sysmcache[i].dca_flags == SYSM_DISABLED) {
				sysmcache[i].dca_flags |= SYSM_ENABLED;
				(void) strcpy(sysmcache[i].dca_name, infop);
				rw_exit(&sysmcache[i].dca_lock);
				found = 1;
				break;
			} else if (sysmcache[i].dca_devt == 0) {
				ASSERT(sysmcache[i].dca_vp == NULL &&
				    sysmcache[i].dca_flags == SYSM_DISABLED);
				(void) strcpy(sysmcache[i].dca_name, infop);
				sysmcache[i].dca_flags = SYSM_ENABLED;
				sysmcache[i].dca_devt = newdevt;
				rw_exit(&sysmcache[i].dca_lock);
				found = 1;
				break;
			}
			rw_exit(&sysmcache[i].dca_lock);
		}
		if (found == 0 && rval == 0)
			rval = ENOENT;
		break;

	case CIOCRMCONSOLE:
		for (i = 0; i < MAXDEVS; i++) {
			rw_enter(&sysmcache[i].dca_lock, RW_WRITER);
			if (sysmcache[i].dca_devt == newdevt) {
				sysmcache[i].dca_flags = SYSM_DISABLED;
				sysmcache[i].dca_name[0] = '\0';
				rw_exit(&sysmcache[i].dca_lock);
				found = 1;
				break;
			}
			rw_exit(&sysmcache[i].dca_lock);
		}
		if (found == 0)
			rval = ENOENT;
		break;

	default:
		break;
	}

err_exit:
	kmem_free(infop, size);
	return (rval);
}

/* As with the read, we poll only the default console */

/* ARGSUSED */
static int
sysmpoll(dev_t dev, short events, int anyyet, short *reventsp,
    struct pollhead **phpp)
{
	return (VOP_POLL(dcvp, events, anyyet, reventsp, phpp, NULL));
}

/* Sanity check that the device is good */
static int
checkarg(dev_t devt)
{
	int rval = 0;
	dev_t sysmsg_dev, msglog_dev;
	extern dev_t rwsconsdev, rconsdev, uconsdev;

	if (devt == rconsdev || devt == rwsconsdev || devt == uconsdev) {
		rval = EBUSY;
	} else {
		sysmsg_dev = makedevice(ddi_driver_major(sysm_dip), SYS_SYSMIN);
		msglog_dev = makedevice(ddi_driver_major(sysm_dip), SYS_MSGMIN);
		if (devt == sysmsg_dev || devt == msglog_dev)
			rval = EINVAL;
	}

	return (rval);
}
