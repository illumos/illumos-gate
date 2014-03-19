/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2014 Joyent, Inc.  All rights reserved.
 */

#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <stropts.h>
#include <stdio.h>
#include <zone.h>
#include <assert.h>
#include <sys/sysmacros.h>

#include <sys/vnd.h>
#include <libvnd.h>

struct vnd_handle {
	int vh_fd;
	uint32_t vh_errno;
	int vh_syserr;
};

static const char *vnd_strerror_tbl[] = {
	"no error",					/* VND_E_SUCCESS */
	"not enough memory available",			/* VND_E_NOMEM */
	"no such datalink",				/* VND_E_NODATALINK */
	"datalink not of type DL_ETHER",		/* VND_E_NOTETHER */
	"unknown dlpi failure",				/* VND_E_DLPIINVAL */
	"DL_ATTACH_REQ failed",				/* VND_E_ATTACHFAIL */
	"DL_BIND_REQ failed",				/* VND_E_PROMISCFAIL */
	"DL_PROMISCON_REQ failed",			/* VND_E_PROMISCFAIL */
	"DLD_CAPAB_DIRECT enable failed",		/* VND_E_DIRECTFAIL */
	"bad datalink capability",			/* VND_E_CAPACKINVAL */
	"bad datalink subcapability",			/* VND_E_SUBCAPINVAL */
	"bad dld version",				/* VND_E_DLDBADVERS */
	"failed to create kstats",			/* VND_E_KSTATCREATE */
	"no such vnd link",				/* VND_E_NODEV */
	"netstack doesn't exist",			/* VND_E_NONETSTACK */
	"device already associated",			/* VND_E_ASSOCIATED */
	"device already attached",			/* VND_E_ATTACHED */
	"device already linked",			/* VND_E_LINKED */
	"invalid name",					/* VND_E_BADNAME */
	"permission denied",				/* VND_E_PERM */
	"no such zone",					/* VND_E_NOZONE */
	"failed to initialize vnd stream module",	/* VND_E_STRINIT */
	"device not attached",				/* VND_E_NOTATTACHED */
	"device not linked",				/* VND_E_NOTLINKED */
	"another device has the same link name",	/* VND_E_LINKEXISTS */
	"failed to create minor node",			/* VND_E_MINORNODE */
	"requested buffer size is too large",		/* VND_E_BUFTOOBIG */
	"requested buffer size is too small",		/* VND_E_TOOSMALL */
	"unable to obtain exclusive access to dlpi link, link busy",
							/* VND_E_DLEXCL */
	"DLD direct capability not supported over data link",
							/* VND_E_DIRECTNOTSUP */
	"invalid property size",			/* VND_E_BADPROPSIZE */
	"invalid property",				/* VND_E_BADPROP */
	"property is read only",			/* VND_E_PROPRDONLY */
	"unexpected system error",			/* VND_E_SYS */
	"capabilities invalid, pass-through module detected",
							/* VND_E_CAPABPASS */
	"unknown error"					/* VND_E_UNKNOWN */
};

vnd_errno_t
vnd_errno(vnd_handle_t *vhp)
{
	return (vhp->vh_errno);
}

const char *
vnd_strerror(vnd_errno_t err)
{
	if (err >= VND_E_UNKNOWN)
		err = VND_E_UNKNOWN;
	return (vnd_strerror_tbl[err]);
}

int
vnd_syserrno(vnd_handle_t *vhp)
{
	return (vhp->vh_syserr);
}

const char *
vnd_strsyserror(int err)
{
	return (strerror(err));
}

static int
vnd_ioc_return(vnd_handle_t *vhp, uint32_t err)
{
	if (err != VND_E_SUCCESS) {
		vhp->vh_errno = err;
		vhp->vh_syserr = 0;
	} else {
		if (errno == EFAULT)
			abort();
		vhp->vh_errno = VND_E_SYS;
		vhp->vh_syserr = errno;
	}
	return (-1);
}

void
vnd_close(vnd_handle_t *vhp)
{
	int ret;

	if (vhp->vh_fd >= 0) {
		ret = close(vhp->vh_fd);
		assert(ret == 0);
	}
	free(vhp);
}

static int
vnd_link(vnd_handle_t *vhp, const char *name)
{
	vnd_ioc_link_t vil;

	if (strlen(name) >= VND_NAMELEN) {
		errno = ENAMETOOLONG;
		return (-1);
	}

	(void) strlcpy(vil.vil_name, name, sizeof (vil.vil_name));
	vil.vil_errno = VND_E_SUCCESS;
	if (ioctl(vhp->vh_fd, VND_IOC_LINK, &vil) != 0)
		return (vnd_ioc_return(vhp, vil.vil_errno));

	return (0);
}

static vnd_handle_t *
vnd_open_ctl(vnd_errno_t *vnderr, int *syserr)
{
	int fd;
	vnd_handle_t *vhp;

	vhp = malloc(sizeof (vnd_handle_t));
	if (vhp == NULL) {
		if (vnderr != NULL)
			*vnderr = VND_E_NOMEM;
		if (syserr != NULL)
			*syserr = 0;
		return (NULL);
	}
	bzero(vhp, sizeof (vnd_handle_t));

	fd = open("/dev/vnd/ctl", O_RDWR);
	if (fd < 0) {
		if (vnderr != NULL)
			*vnderr = VND_E_SYS;
		if (syserr != NULL)
			*syserr = errno;
		free(vhp);
		return (NULL);
	}

	vhp->vh_fd = fd;
	return (vhp);
}

vnd_handle_t *
vnd_create(const char *zonename, const char *datalink, const char *linkname,
    vnd_errno_t *vnderr, int *syserr)
{
	int ret;
	vnd_handle_t *vhp;
	vnd_ioc_attach_t via;
	zoneid_t zid;

	if (strlen(datalink) >= VND_NAMELEN) {
		if (vnderr != NULL)
			*vnderr = VND_E_BADNAME;
		if (syserr != NULL)
			*syserr = 0;
		return (NULL);
	}

	vhp = vnd_open_ctl(vnderr, syserr);
	if (vhp == NULL)
		return (NULL);	/* errno set for us */

	if (zonename != NULL) {
		zid = getzoneidbyname(zonename);
		if (zid == -1) {
			vnd_close(vhp);
			if (vnderr != NULL)
				*vnderr = VND_E_NOZONE;
			if (syserr != NULL)
				*syserr = 0;
			return (NULL);
		}
		via.via_zoneid = zid;
	} else {
		via.via_zoneid = -1;
	}

	(void) strlcpy(via.via_name, datalink, sizeof (via.via_name));
	via.via_errno = VND_E_SUCCESS;
	if (ioctl(vhp->vh_fd, VND_IOC_ATTACH, &via) != 0) {
		if (via.via_errno != VND_E_SUCCESS) {
			if (vnderr != NULL)
				*vnderr = via.via_errno;
			if (syserr != NULL)
				*syserr = 0;
		} else {
			if (vnderr != NULL)
				*vnderr = VND_E_SYS;
			if (syserr != NULL)
				*syserr = errno;
		}
		vnd_close(vhp);
		return (NULL);
	}

	ret = vnd_link(vhp, linkname);
	if (ret != 0) {
		if (vnderr != NULL)
			*vnderr = vhp->vh_errno;
		if (syserr != NULL)
			*syserr = vhp->vh_syserr;
		vnd_close(vhp);
		return (NULL);
	}

	if (vnderr != NULL)
		*vnderr = VND_E_SUCCESS;
	if (syserr != NULL)
		*syserr = 0;

	return (vhp);
}

vnd_handle_t *
vnd_open(const char *zone, const char *link, vnd_errno_t *vnderr, int *syserr)
{
	int fd, ret;
	char path[MAXPATHLEN];
	vnd_handle_t *vhp;

	if (zone != NULL)
		ret = snprintf(path, sizeof (path), "/dev/vnd/zone/%s/%s",
		    zone, link);
	else
		ret = snprintf(path, sizeof (path), "/dev/vnd/%s", link);

	if (ret >= sizeof (path)) {
		if (vnderr != NULL)
			*vnderr = VND_E_BADNAME;
		if (syserr != NULL)
			*syserr = 0;
		return (NULL);
	}

	fd = open(path, O_RDWR);
	if (fd < 0) {
		if (vnderr != NULL)
			*vnderr = VND_E_SYS;
		if (syserr != NULL)
			*syserr = errno;
		return (NULL);
	}

	vhp = malloc(sizeof (vnd_handle_t));
	if (vhp == NULL) {
		if (vnderr != NULL)
			*vnderr = VND_E_NOMEM;
		if (syserr != NULL)
			*syserr = 0;
		ret = close(fd);
		assert(ret == 0);
		return (NULL);
	}

	bzero(vhp, sizeof (vnd_handle_t));
	vhp->vh_fd = fd;

	return (vhp);
}

int
vnd_unlink(vnd_handle_t *vhp)
{
	vnd_ioc_unlink_t viu;
	viu.viu_errno = VND_E_SUCCESS;

	if (ioctl(vhp->vh_fd, VND_IOC_UNLINK, &viu) != 0)
		return (vnd_ioc_return(vhp, viu.viu_errno));

	return (0);
}

int
vnd_pollfd(vnd_handle_t *vhp)
{
	return (vhp->vh_fd);
}

int
vnd_walk(vnd_walk_cb_t func, void *arg, vnd_errno_t *vnderr, int *syserr)
{
	vnd_handle_t *vhp;
	vnd_ioc_list_t vl;
	vnd_ioc_info_t *viip;
	int i, ret;

	vl.vl_nents = 0;
	vl.vl_ents = NULL;

	vhp = vnd_open_ctl(vnderr, syserr);
	if (vhp == NULL)
		return (-1);	/* errno is set for us */

	/* VND_IOC_LIST only returns generic errnos */
	if (ioctl(vhp->vh_fd, VND_IOC_LIST, &vl) != 0) {
		if (vnderr != NULL)
			*vnderr = VND_E_SYS;
		if (syserr != NULL)
			*syserr = errno;
		(void) vnd_ioc_return(vhp, VND_E_SUCCESS);
		vnd_close(vhp);

		return (-1);
	}

	if (vl.vl_actents == 0) {
		vnd_close(vhp);
		return (0);
	}

	viip = malloc(sizeof (vnd_ioc_info_t) * vl.vl_actents);
	if (viip == NULL) {
		if (vnderr != NULL)
			*vnderr = VND_E_NOMEM;
		if (syserr != NULL)
			*syserr = 0;
		vnd_close(vhp);
		return (-1);
	}

	vl.vl_nents = vl.vl_actents;
	vl.vl_ents = viip;

	if (ioctl(vhp->vh_fd, VND_IOC_LIST, &vl) != 0) {
		if (vnderr != NULL)
			*vnderr = VND_E_SYS;
		if (syserr != NULL)
			*syserr = errno;
		(void) vnd_ioc_return(vhp, VND_E_SUCCESS);
		free(viip);
		vnd_close(vhp);
		return (-1);
	}

	ret = 0;
	for (i = 0; i < MIN(vl.vl_nents, vl.vl_actents); i++) {
		if (func((vnd_info_t *)(viip + i), arg) != 0) {
			ret = 1;
			break;
		}
	}

	free(viip);
	vnd_close(vhp);

	return (ret);
}

static int
vnd_prop_readonly(vnd_handle_t *vhp)
{
	vhp->vh_syserr = 0;
	vhp->vh_errno = VND_E_PROPRDONLY;
	return (-1);
}

/*ARGSUSED*/
static int
vnd_prop_getbuf(vnd_handle_t *vhp, int cmd, void *buf, size_t len)
{
	vnd_ioc_buf_t vib;
	vnd_prop_buf_t *vpbp = (vnd_prop_buf_t *)buf;
	vib.vib_errno = 0;

	if (ioctl(vhp->vh_fd, cmd, &vib) != 0)
		return (vnd_ioc_return(vhp, vib.vib_errno));

	vpbp->vpb_size = vib.vib_size;
	return (0);
}

/*ARGSUSED*/
static int
vnd_prop_setbuf(vnd_handle_t *vhp, int cmd, void *buf, size_t len)
{
	vnd_ioc_buf_t vib;
	vnd_prop_buf_t *vpbp = (vnd_prop_buf_t *)buf;

	vib.vib_errno = 0;
	vib.vib_size = vpbp->vpb_size;
	if (ioctl(vhp->vh_fd, cmd, &vib) != 0)
		return (vnd_ioc_return(vhp, vib.vib_errno));

	return (0);
}

typedef int (*vpt_prop_f)(vnd_handle_t *, int, void *, size_t);
typedef struct vnd_prop_tab {
	vnd_prop_t vpt_prop;
	size_t vpt_size;
	int vpt_ioctl_get;
	int vpt_ioctl_set;
	vpt_prop_f vpt_get;
	vpt_prop_f vpt_set;
} vnd_prop_tab_t;

static vnd_prop_tab_t vnd_props[] = {
	{ VND_PROP_RXBUF, sizeof (vnd_prop_buf_t), VND_IOC_GETRXBUF,
		VND_IOC_SETRXBUF, vnd_prop_getbuf, vnd_prop_setbuf},
	{ VND_PROP_TXBUF, sizeof (vnd_prop_buf_t), VND_IOC_GETTXBUF,
		VND_IOC_SETTXBUF, vnd_prop_getbuf, vnd_prop_setbuf },
	{ VND_PROP_MAXBUF, sizeof (vnd_prop_buf_t), VND_IOC_GETMAXBUF,
		-1, vnd_prop_getbuf, NULL },
	{ VND_PROP_MINTU, sizeof (vnd_prop_buf_t), VND_IOC_GETMINTU,
		-1, vnd_prop_getbuf, NULL },
	{ VND_PROP_MAXTU, sizeof (vnd_prop_buf_t), VND_IOC_GETMAXTU,
		-1, vnd_prop_getbuf, NULL },
	{ VND_PROP_MAX }
};

static int
vnd_prop(vnd_handle_t *vhp, vnd_prop_t prop, void *buf, size_t len,
    boolean_t get)
{
	vnd_prop_tab_t *vpt;

	for (vpt = vnd_props; vpt->vpt_prop != VND_PROP_MAX; vpt++) {
		if (vpt->vpt_prop != prop)
			continue;

		if (len != vpt->vpt_size) {
			vhp->vh_errno = VND_E_BADPROPSIZE;
			vhp->vh_syserr = 0;
			return (-1);
		}

		if (get == B_TRUE) {
			return (vpt->vpt_get(vhp, vpt->vpt_ioctl_get, buf,
			    len));
		} else {
			if (vpt->vpt_set == NULL)
				return (vnd_prop_readonly(vhp));
			return (vpt->vpt_set(vhp, vpt->vpt_ioctl_set, buf,
			    len));
		}
	}

	vhp->vh_errno = VND_E_BADPROP;
	vhp->vh_syserr = 0;
	return (-1);
}

int
vnd_prop_get(vnd_handle_t *vhp, vnd_prop_t prop, void *buf, size_t len)
{
	return (vnd_prop(vhp, prop, buf, len, B_TRUE));
}

int
vnd_prop_set(vnd_handle_t *vhp, vnd_prop_t prop, void *buf, size_t len)
{
	return (vnd_prop(vhp, prop, buf, len, B_FALSE));
}

int
vnd_prop_writeable(vnd_prop_t prop, boolean_t *write)
{
	vnd_prop_tab_t *vpt;

	for (vpt = vnd_props; vpt->vpt_prop != VND_PROP_MAX; vpt++) {
		if (vpt->vpt_prop != prop)
			continue;

		*write = (vpt->vpt_set != NULL);
		return (0);
	}

	return (-1);
}

int
vnd_prop_iter(vnd_handle_t *vhp, vnd_prop_iter_f func, void *arg)
{
	int i;

	for (i = 0; i < VND_PROP_MAX; i++) {
		if (func(vhp, i, arg) != 0)
			return (1);
	}

	return (0);
}

int
vnd_frameio_read(vnd_handle_t *vhp, frameio_t *fiop)
{
	int ret;

	ret = ioctl(vhp->vh_fd, VND_IOC_FRAMEIO_READ, fiop);
	if (ret == -1) {
		vhp->vh_errno = VND_E_SYS;
		vhp->vh_syserr = errno;
	}

	return (ret);
}

int
vnd_frameio_write(vnd_handle_t *vhp, frameio_t *fiop)
{
	int ret;

	ret = ioctl(vhp->vh_fd, VND_IOC_FRAMEIO_WRITE, fiop);
	if (ret == -1) {
		vhp->vh_errno = VND_E_SYS;
		vhp->vh_syserr = errno;
	}

	return (ret);
}
