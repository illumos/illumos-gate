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
 * IP Policy Framework config driver
 */

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/cpuvar.h>
#include <sys/open.h>
#include <sys/stat.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/stream.h>
#include <ipp/ipp.h>
#include <ipp/ippctl.h>
#include <sys/nvpair.h>
#include <sys/policy.h>

/*
 * Debug switch.
 */

#if	defined(DEBUG)
#define	IPPCTL_DEBUG
#endif

/*
 * Debug macros.
 */

#ifdef	IPPCTL_DEBUG

#define	DBG_MODLINK	0x00000001ull
#define	DBG_DEVOPS	0x00000002ull
#define	DBG_CBOPS	0x00000004ull

static	uint64_t	ippctl_debug_flags =
/*
 * DBG_MODLINK |
 * DBG_DEVOPS |
 * DBG_CBOPS |
 */
0;

static kmutex_t	debug_mutex[1];

/*PRINTFLIKE3*/
static void	ippctl_debug(uint64_t, char *, char *, ...)
	__PRINTFLIKE(3);

#define	DBG0(_type, _fmt)		    			\
	ippctl_debug((_type), __FN__, (_fmt));

#define	DBG1(_type, _fmt, _a1) 					\
	ippctl_debug((_type), __FN__, (_fmt), (_a1));

#define	DBG2(_type, _fmt, _a1, _a2)				\
	ippctl_debug((_type), __FN__, (_fmt), (_a1), (_a2));

#define	DBG3(_type, _fmt, _a1, _a2, _a3)			\
	ippctl_debug((_type), __FN__, (_fmt), (_a1), (_a2),	\
	    (_a3));

#define	DBG4(_type, _fmt, _a1, _a2, _a3, _a4)			\
	ippctl_debug((_type), __FN__, (_fmt), (_a1), (_a2),	\
	    (_a3), (_a4));

#define	DBG5(_type, _fmt, _a1, _a2, _a3, _a4, _a5)		\
	ippctl_debug((_type), __FN__, (_fmt), (_a1), (_a2),	\
	    (_a3), (_a4), (_a5));

#else	/* IPPCTL_DBG */

#define	DBG0(_type, _fmt)
#define	DBG1(_type, _fmt, _a1)
#define	DBG2(_type, _fmt, _a1, _a2)
#define	DBG3(_type, _fmt, _a1, _a2, _a3)
#define	DBG4(_type, _fmt, _a1, _a2, _a3, _a4)
#define	DBG5(_type, _fmt, _a1, _a2, _a3, _a4, _a5)

#endif	/* IPPCTL_DBG */

/*
 * cb_ops
 */

static int	ippctl_open(dev_t *, int, int, cred_t *);
static int	ippctl_close(dev_t, int, int, cred_t *);
static int	ippctl_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

static	struct cb_ops	ippctl_cb_ops = {
	ippctl_open,	/* cb_open */
	ippctl_close,	/* cb_close */
	nodev,		/* cb_strategy */
	nodev,		/* cb_print */
	nodev,		/* cb_dump */
	nodev,		/* cb_read */
	nodev,		/* cb_write */
	ippctl_ioctl,	/* cb_ioctl */
	nodev,		/* cb_devmap */
	nodev,		/* cb_mmap */
	nodev,		/* cb_segmap */
	nochpoll,	/* cb_chpoll */
	ddi_prop_op,	/* cb_prop_op */
	0,		/* cb_str */
	D_NEW | D_MP,	/* cb_flag */
	CB_REV,		/* cb_rev */
	nodev,		/* cb_aread */
	nodev		/* cb_awrite */
};

/*
 * dev_ops
 */

static	int	ippctl_info(dev_info_t *, ddi_info_cmd_t, void *, void **);
static	int	ippctl_attach(dev_info_t *, ddi_attach_cmd_t);
static	int	ippctl_detach(dev_info_t *, ddi_detach_cmd_t);

static	struct dev_ops	ippctl_dev_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* devo_refcnt  */
	ippctl_info,		/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	ippctl_attach,		/* devo_attach */
	ippctl_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&ippctl_cb_ops,		/* devo_cb_ops */
	(struct bus_ops *)0,	/* devo_bus_ops */
	NULL,			/* devo_power */
	ddi_quiesce_not_needed,		/* devo_quiesce */
};

static	struct modldrv modldrv = {
	&mod_driverops,
	"IP Policy Configuration Driver",
	&ippctl_dev_ops,
};

static	struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

/*
 * Local definitions, types and prototypes.
 */

#define	MAXUBUFLEN	(1 << 16)

#define	FREE_TEXT(_string)					\
	kmem_free((_string), strlen(_string) + 1)

#define	FREE_TEXT_ARRAY(_array, _nelt)				\
	{							\
		int	j;					\
								\
		for (j = 0; j < (_nelt); j++)			\
			if ((_array)[j] != NULL)		\
				FREE_TEXT((_array)[j]);		\
		kmem_free((_array), (_nelt) * sizeof (char *));	\
	}

typedef	struct ippctl_buf	ippctl_buf_t;

struct ippctl_buf {
	char	*buf;
	size_t	buflen;
};

static int	ippctl_copyin(caddr_t, int, char **, size_t *);
static int	ippctl_copyout(caddr_t, int, char *, size_t);
static int	ippctl_extract_op(nvlist_t *, uint8_t *);
static int	ippctl_extract_aname(nvlist_t *, char **);
static int	ippctl_extract_modname(nvlist_t *, char **);
static int	ippctl_attach_modname(nvlist_t *nvlp, char *val);
static int	ippctl_attach_modname_array(nvlist_t *nvlp, char **val, int);
static int	ippctl_attach_aname_array(nvlist_t *nvlp, char **val, int);
static int	ippctl_extract_flags(nvlist_t *, ipp_flags_t *);
static int	ippctl_cmd(char *, size_t, size_t *);
static int	ippctl_action_create(char *, char *, nvlist_t *, ipp_flags_t);
static int	ippctl_action_destroy(char *, ipp_flags_t);
static int	ippctl_action_modify(char *, nvlist_t *, ipp_flags_t);
static int	ippctl_action_info(char *, ipp_flags_t);
static int	ippctl_action_mod(char *);
static int	ippctl_list_mods(void);
static int	ippctl_mod_list_actions(char *);
static int	ippctl_data(char **, size_t *, size_t *);
static void	ippctl_flush(void);
static int	ippctl_add_nvlist(nvlist_t *, int);
static int	ippctl_callback(nvlist_t *, void *);
static int	ippctl_set_rc(int);
static void	ippctl_alloc(int);
static void	ippctl_realloc(void);
static void	ippctl_free(void);

/*
 * Global data
 */

static dev_info_t	*ippctl_dip = NULL;
static kmutex_t		ippctl_lock;
static boolean_t	ippctl_busy;
static ippctl_buf_t	*ippctl_array = NULL;
static int		ippctl_limit = -1;
static int		ippctl_rindex = -1;
static int		ippctl_windex = -1;

/*
 * Module linkage functions
 */

#define	__FN__	"_init"
int
_init(
	void)
{
	int	rc;

	if ((rc = mod_install(&modlinkage)) != 0) {
		DBG0(DBG_MODLINK, "mod_install failed\n");
		return (rc);
	}

	return (rc);
}
#undef	__FN__

#define	__FN__	"_fini"
int
_fini(
	void)
{
	int	rc;

	if ((rc = mod_remove(&modlinkage)) == 0) {
		return (rc);
	}

	DBG0(DBG_MODLINK, "mod_remove failed\n");
	return (rc);
}
#undef	__FN__

#define	__FN__	"_info"
int
_info(
	struct modinfo	*modinfop)
{
	DBG0(DBG_MODLINK, "calling mod_info\n");
	return (mod_info(&modlinkage, modinfop));
}
#undef	__FN__

/*
 * Driver interface functions (dev_ops and cb_ops)
 */

#define	__FN__	"ippctl_info"
/*ARGSUSED*/
static	int
ippctl_info(
	dev_info_t	*dip,
	ddi_info_cmd_t	cmd,
	void		*arg,
	void 		**result)
{
	int		rc = DDI_FAILURE;

	switch (cmd) {
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;	/* Single instance driver */
		rc = DDI_SUCCESS;
		break;
	case DDI_INFO_DEVT2DEVINFO:
		*result = (void *)ippctl_dip;
		rc = DDI_SUCCESS;
		break;
	default:
		break;
	}

	return (rc);
}
#undef	__FN__

#define	__FN__	"ippctl_attach"
static	int
ippctl_attach(
	dev_info_t		*dip,
	ddi_attach_cmd_t	cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_PM_RESUME:
		/*FALLTHRU*/
	case DDI_RESUME:
		/*FALLTHRU*/
	default:
		return (DDI_FAILURE);
	}

	DBG0(DBG_DEVOPS, "DDI_ATTACH\n");

	/*
	 * This is strictly a single instance driver.
	 */

	if (ippctl_dip != NULL)
		return (DDI_FAILURE);

	/*
	 * Create minor node.
	 */

	if (ddi_create_minor_node(dip, "ctl", S_IFCHR, 0,
	    DDI_PSEUDO, 0) != DDI_SUCCESS)
		return (DDI_FAILURE);

	/*
	 * No need for per-instance structure, just store vital data in
	 * globals.
	 */

	ippctl_dip = dip;
	mutex_init(&ippctl_lock, NULL, MUTEX_DRIVER, NULL);
	ippctl_busy = B_FALSE;

	return (DDI_SUCCESS);
}
#undef	__FN__

#define	__FN__	"ippctl_detach"
/*ARGSUSED*/
static	int
ippctl_detach(
	dev_info_t		*dip,
	ddi_detach_cmd_t	cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_PM_SUSPEND:
		/*FALLTHRU*/
	case DDI_SUSPEND:
		/*FALLTHRU*/
	default:
		return (DDI_FAILURE);
	}

	DBG0(DBG_DEVOPS, "DDI_DETACH\n");

	ASSERT(dip == ippctl_dip);

	ddi_remove_minor_node(dip, NULL);
	mutex_destroy(&ippctl_lock);
	ippctl_dip = NULL;

	return (DDI_SUCCESS);
}
#undef	__FN__

#define	__FN__	"ippctl_open"
/*ARGSUSED*/
static	int
ippctl_open(
	dev_t	*devp,
	int	flag,
	int	otyp,
	cred_t	*credp)
{
	minor_t	minor = getminor(*devp);
#define	LIMIT	4

	DBG0(DBG_CBOPS, "open\n");

	/*
	 * Only allow privileged users to open our device.
	 */

	if (secpolicy_net_config(credp, B_FALSE) != 0) {
		DBG0(DBG_CBOPS, "not privileged user\n");
		return (EPERM);
	}

	/*
	 * Sanity check other arguments.
	 */

	if (minor != 0) {
		DBG0(DBG_CBOPS, "bad minor\n");
		return (ENXIO);
	}

	if (otyp != OTYP_CHR) {
		DBG0(DBG_CBOPS, "bad device type\n");
		return (EINVAL);
	}

	/*
	 * This is also a single dev_t driver.
	 */

	mutex_enter(&ippctl_lock);
	if (ippctl_busy) {
		mutex_exit(&ippctl_lock);
		return (EBUSY);
	}
	ippctl_busy = B_TRUE;
	mutex_exit(&ippctl_lock);

	/*
	 * Allocate data buffer array (starting with length LIMIT, defined
	 * at the start of this function).
	 */

	ippctl_alloc(LIMIT);

	DBG0(DBG_CBOPS, "success\n");

	return (0);

#undef	LIMIT
}
#undef	__FN__

#define	__FN__	"ippctl_close"
/*ARGSUSED*/
static	int
ippctl_close(
	dev_t	dev,
	int	flag,
	int	otyp,
	cred_t	*credp)
{
	minor_t	minor = getminor(dev);

	DBG0(DBG_CBOPS, "close\n");

	ASSERT(minor == 0);

	/*
	 * Free the data buffer array.
	 */

	ippctl_free();

	mutex_enter(&ippctl_lock);
	ippctl_busy = B_FALSE;
	mutex_exit(&ippctl_lock);

	DBG0(DBG_CBOPS, "success\n");

	return (0);
}
#undef	__FN__

#define	__FN__	"ippctl_ioctl"
static int
ippctl_ioctl(
	dev_t			dev,
	int			cmd,
	intptr_t		arg,
	int			mode,
	cred_t			*credp,
	int			*rvalp)
{
	minor_t			minor = getminor(dev);
	char			*cbuf;
	char			*dbuf;
	size_t			cbuflen;
	size_t			dbuflen;
	size_t			nextbuflen;
	int			rc;

	/*
	 * Paranoia check.
	 */

	if (secpolicy_net_config(credp, B_FALSE) != 0) {
		DBG0(DBG_CBOPS, "not privileged user\n");
		return (EPERM);
	}

	if (minor != 0) {
		DBG0(DBG_CBOPS, "bad minor\n");
		return (ENXIO);
	}

	switch (cmd) {
	case IPPCTL_CMD:
		DBG0(DBG_CBOPS, "command\n");

		/*
		 * Copy in the command buffer from user space.
		 */

		if ((rc = ippctl_copyin((caddr_t)arg, mode, &cbuf,
		    &cbuflen)) != 0)
			break;

		/*
		 * Execute the command.
		 */

		rc = ippctl_cmd(cbuf, cbuflen, &nextbuflen);

		/*
		 * Pass back the length of the first data buffer.
		 */

		DBG1(DBG_CBOPS, "nextbuflen = %lu\n", nextbuflen);
		*rvalp = nextbuflen;

		/*
		 * Free the kernel copy of the command buffer.
		 */

		kmem_free(cbuf, cbuflen);
		break;

	case IPPCTL_DATA:
		DBG0(DBG_CBOPS, "data\n");

		/*
		 * Grab the next data buffer from the array of pending
		 * buffers.
		 */

		if ((rc = ippctl_data(&dbuf, &dbuflen, &nextbuflen)) != 0)
			break;

		/*
		 * Copy it out to user space.
		 */

		rc = ippctl_copyout((caddr_t)arg, mode, dbuf, dbuflen);

		/*
		 * Pass back the length of the next data buffer.
		 */

		DBG1(DBG_CBOPS, "nextbuflen = %lu\n", nextbuflen);
		*rvalp = nextbuflen;
		break;

	default:
		DBG0(DBG_CBOPS, "unrecognized ioctl\n");
		rc = EINVAL;
		break;
	}

	DBG1(DBG_CBOPS, "rc = %d\n", rc);
	return (rc);
}
#undef	__FN__

/*
 * Local functions
 */

#define	__FN__	"ippctl_copyin"
static int
ippctl_copyin(
	caddr_t		arg,
	int		mode,
	char		**kbufp,
	size_t		*kbuflenp)
{
	ippctl_ioctl_t	iioc;
	caddr_t		ubuf;
	char		*kbuf;
	size_t		ubuflen;

	DBG0(DBG_CBOPS, "copying in ioctl structure\n");

	/*
	 * Copy in the ioctl structure from user-space, converting from 32-bit
	 * as necessary.
	 */

#ifdef	_MULTI_DATAMODEL
	switch (ddi_model_convert_from(mode & FMODELS)) {
	case DDI_MODEL_ILP32:
		{
			ippctl_ioctl32_t	iioc32;

			DBG0(DBG_CBOPS, "converting from 32-bit\n");

			if (ddi_copyin(arg, (caddr_t)&iioc32,
			    sizeof (ippctl_ioctl32_t), mode) != 0)
				return (EFAULT);

			ubuf = (caddr_t)(uintptr_t)iioc32.ii32_buf;
			ubuflen = (size_t)iioc32.ii32_buflen;
		}
		break;
	case DDI_MODEL_NONE:
		if (ddi_copyin(arg, (caddr_t)&iioc, sizeof (ippctl_ioctl_t),
		    mode) != 0)
			return (EFAULT);

		ubuf = iioc.ii_buf;
		ubuflen = iioc.ii_buflen;
		break;
	default:
		return (EFAULT);
	}
#else	/* _MULTI_DATAMODEL */
	if (ddi_copyin(arg, (caddr_t)&iioc, sizeof (ippctl_ioctl_t),
	    mode) != 0)
		return (EFAULT);

	ubuf = iioc.ii_buf;
	ubuflen = iioc.ii_buflen;
#endif	/* _MULTI_DATAMODEL */

	DBG1(DBG_CBOPS, "ubuf = 0x%p\n", (void *)ubuf);
	DBG1(DBG_CBOPS, "ubuflen = %lu\n", ubuflen);

	/*
	 * Sanity check the command buffer information.
	 */

	if (ubuflen == 0 || ubuf == NULL)
		return (EINVAL);
	if (ubuflen > MAXUBUFLEN)
		return (E2BIG);

	/*
	 * Allocate some memory for the command buffer and copy it in.
	 */

	kbuf = kmem_zalloc(ubuflen, KM_SLEEP);
	DBG0(DBG_CBOPS, "copying in nvlist\n");
	if (ddi_copyin(ubuf, (caddr_t)kbuf, ubuflen, mode) != 0) {
		kmem_free(kbuf, ubuflen);
		return (EFAULT);
	}

	*kbufp = kbuf;
	*kbuflenp = ubuflen;
	return (0);
}
#undef	__FN__

#define	__FN__	"ippctl_copyout"
static int
ippctl_copyout(
	caddr_t		arg,
	int		mode,
	char		*kbuf,
	size_t		kbuflen)
{
	ippctl_ioctl_t	iioc;
	caddr_t		ubuf;
	int		ubuflen;

	DBG0(DBG_CBOPS, "copying out ioctl structure\n");

	/*
	 * Copy in the ioctl structure from user-space, converting from 32-bit
	 * as necessary.
	 */

#ifdef	_MULTI_DATAMODEL
	switch (ddi_model_convert_from(mode & FMODELS)) {
	case DDI_MODEL_ILP32:
		{
			ippctl_ioctl32_t	iioc32;

			if (ddi_copyin(arg, (caddr_t)&iioc32,
			    sizeof (ippctl_ioctl32_t), mode) != 0)
				return (EFAULT);

			ubuf = (caddr_t)(uintptr_t)iioc32.ii32_buf;
			ubuflen = iioc32.ii32_buflen;
		}
		break;
	case DDI_MODEL_NONE:
		if (ddi_copyin(arg, (caddr_t)&iioc, sizeof (ippctl_ioctl_t),
		    mode) != 0)
			return (EFAULT);

		ubuf = iioc.ii_buf;
		ubuflen = iioc.ii_buflen;
		break;
	default:
		return (EFAULT);
	}
#else	/* _MULTI_DATAMODEL */
	if (ddi_copyin(arg, (caddr_t)&iioc, sizeof (ippctl_ioctl_t),
	    mode) != 0)
		return (EFAULT);

	ubuf = iioc.ii_buf;
	ubuflen = iioc.ii_buflen;
#endif	/* _MULTI_DATAMODEL */

	DBG1(DBG_CBOPS, "ubuf = 0x%p\n", (void *)ubuf);
	DBG1(DBG_CBOPS, "ubuflen = %d\n", ubuflen);

	/*
	 * Sanity check the data buffer details.
	 */

	if (ubuflen == 0 || ubuf == NULL)
		return (EINVAL);

	if (ubuflen < kbuflen)
		return (ENOSPC);
	if (ubuflen > MAXUBUFLEN)
		return (E2BIG);

	/*
	 * Copy out the data buffer to user space.
	 */

	DBG0(DBG_CBOPS, "copying out nvlist\n");
	if (ddi_copyout((caddr_t)kbuf, ubuf, kbuflen, mode) != 0)
		return (EFAULT);

	return (0);
}
#undef	__FN__

#define	__FN__	"ippctl_extract_op"
static int
ippctl_extract_op(
	nvlist_t	*nvlp,
	uint8_t		*valp)
{
	int		rc;

	/*
	 * Look-up and remove the opcode passed from libipp from the
	 * nvlist.
	 */

	if ((rc = nvlist_lookup_byte(nvlp, IPPCTL_OP, valp)) != 0)
		return (rc);

	(void) nvlist_remove_all(nvlp, IPPCTL_OP);
	return (0);
}
#undef	__FN__

#define	__FN__	"ippctl_extract_aname"
static int
ippctl_extract_aname(
	nvlist_t	*nvlp,
	char		**valp)
{
	int		rc;
	char		*ptr;

	/*
	 * Look-up and remove the action name passed from libipp from the
	 * nvlist.
	 */

	if ((rc = nvlist_lookup_string(nvlp, IPPCTL_ANAME, &ptr)) != 0)
		return (rc);

	*valp = kmem_alloc(strlen(ptr) + 1, KM_SLEEP);
	(void) strcpy(*valp, ptr);
	(void) nvlist_remove_all(nvlp, IPPCTL_ANAME);
	return (0);
}
#undef	__FN__

#define	__FN__	"ippctl_extract_modname"
static int
ippctl_extract_modname(
	nvlist_t	*nvlp,
	char		**valp)
{
	int		rc;
	char		*ptr;

	/*
	 * Look-up and remove the module name passed from libipp from the
	 * nvlist.
	 */

	if ((rc = nvlist_lookup_string(nvlp, IPPCTL_MODNAME, &ptr)) != 0)
		return (rc);

	*valp = kmem_alloc(strlen(ptr) + 1, KM_SLEEP);
	(void) strcpy(*valp, ptr);
	(void) nvlist_remove_all(nvlp, IPPCTL_MODNAME);
	return (0);
}
#undef	__FN__

#define	__FN__	"ippctl_attach_modname"
static int
ippctl_attach_modname(
	nvlist_t	*nvlp,
	char		*modname)
{
	/*
	 * Add a module name to an nvlist for passing back to user
	 * space.
	 */

	return (nvlist_add_string(nvlp, IPPCTL_MODNAME, modname));
}
#undef	__FN__

#define	__FN__	"ippctl_attach_modname_array"
static int
ippctl_attach_modname_array(
	nvlist_t	*nvlp,
	char		**modname_array,
	int		nelt)
{
	/*
	 * Add a module name array to an nvlist for passing back to user
	 * space.
	 */

	return (nvlist_add_string_array(nvlp, IPPCTL_MODNAME_ARRAY,
	    modname_array, nelt));
}
#undef	__FN__

#define	__FN__	"ippctl_attach_aname_array"
static int
ippctl_attach_aname_array(
	nvlist_t	*nvlp,
	char		**aname_array,
	int		nelt)
{
	/*
	 * Add an action name array to an nvlist for passing back to user
	 * space.
	 */

	return (nvlist_add_string_array(nvlp, IPPCTL_ANAME_ARRAY,
	    aname_array, nelt));
}
#undef	__FN__

#define	__FN__	"ippctl_extract_flags"
static int
ippctl_extract_flags(
	nvlist_t	*nvlp,
	ipp_flags_t	*valp)
{
	int		rc;

	/*
	 * Look-up and remove the flags passed from libipp from the
	 * nvlist.
	 */

	if ((rc = nvlist_lookup_uint32(nvlp, IPPCTL_FLAGS,
	    (uint32_t *)valp)) != 0)
		return (rc);

	(void) nvlist_remove_all(nvlp, IPPCTL_FLAGS);
	return (0);
}
#undef	__FN__

#define	__FN__	"ippctl_cmd"
static int
ippctl_cmd(
	char		*cbuf,
	size_t		cbuflen,
	size_t		*nextbuflenp)
{
	nvlist_t	*nvlp = NULL;
	int		rc;
	char		*aname = NULL;
	char		*modname = NULL;
	ipp_flags_t	flags;
	uint8_t		op;

	/*
	 * Start a new command cycle by flushing any previous data buffers.
	 */

	ippctl_flush();
	*nextbuflenp = 0;

	/*
	 * Unpack the nvlist from the command buffer.
	 */

	if ((rc = nvlist_unpack(cbuf, cbuflen, &nvlp, KM_SLEEP)) != 0)
		return (rc);

	/*
	 * Extract the opcode to find out what we should do.
	 */

	if ((rc = ippctl_extract_op(nvlp, &op)) != 0) {
		nvlist_free(nvlp);
		return (rc);
	}

	switch (op) {
	case IPPCTL_OP_ACTION_CREATE:
		/*
		 * Create a new action.
		 */

		DBG0(DBG_CBOPS, "op = IPPCTL_OP_ACTION_CREATE\n");

		/*
		 * Extract the module name, action name and flags from the
		 * nvlist.
		 */

		if ((rc = ippctl_extract_modname(nvlp, &modname)) != 0) {
			nvlist_free(nvlp);
			return (rc);
		}

		if ((rc = ippctl_extract_aname(nvlp, &aname)) != 0) {
			FREE_TEXT(modname);
			nvlist_free(nvlp);
			return (rc);
		}

		if ((rc = ippctl_extract_flags(nvlp, &flags)) != 0) {
			FREE_TEXT(aname);
			FREE_TEXT(modname);
			nvlist_free(nvlp);
			return (rc);
		}


		rc = ippctl_action_create(modname, aname, nvlp, flags);
		break;

	case IPPCTL_OP_ACTION_MODIFY:

		/*
		 * Modify an existing action.
		 */

		DBG0(DBG_CBOPS, "op = IPPCTL_OP_ACTION_MODIFY\n");

		/*
		 * Extract the action name and flags from the nvlist.
		 */

		if ((rc = ippctl_extract_aname(nvlp, &aname)) != 0) {
			nvlist_free(nvlp);
			return (rc);
		}

		if ((rc = ippctl_extract_flags(nvlp, &flags)) != 0) {
			FREE_TEXT(aname);
			nvlist_free(nvlp);
			return (rc);
		}

		rc = ippctl_action_modify(aname, nvlp, flags);
		break;

	case IPPCTL_OP_ACTION_DESTROY:

		/*
		 * Destroy an action.
		 */

		DBG0(DBG_CBOPS, "op = IPPCTL_OP_ACTION_DESTROY\n");

		/*
		 * Extract the action name and flags from the nvlist.
		 */

		if ((rc = ippctl_extract_aname(nvlp, &aname)) != 0) {
			nvlist_free(nvlp);
			return (rc);
		}

		if ((rc = ippctl_extract_flags(nvlp, &flags)) != 0) {
			FREE_TEXT(aname);
			nvlist_free(nvlp);
			return (rc);
		}

		nvlist_free(nvlp);
		rc = ippctl_action_destroy(aname, flags);
		break;

	case IPPCTL_OP_ACTION_INFO:

		/*
		 * Retrive the configuration of an action.
		 */

		DBG0(DBG_CBOPS, "op = IPPCTL_OP_ACTION_INFO\n");

		/*
		 * Extract the action name and flags from the nvlist.
		 */

		if ((rc = ippctl_extract_aname(nvlp, &aname)) != 0) {
			nvlist_free(nvlp);
			return (rc);
		}

		if ((rc = ippctl_extract_flags(nvlp, &flags)) != 0) {
			nvlist_free(nvlp);
			FREE_TEXT(aname);
			return (rc);
		}

		nvlist_free(nvlp);
		rc = ippctl_action_info(aname, flags);
		break;

	case IPPCTL_OP_ACTION_MOD:

		/*
		 * Find the module that implements a given action.
		 */

		DBG0(DBG_CBOPS, "op = IPPCTL_OP_ACTION_MOD\n");

		/*
		 * Extract the action name from the nvlist.
		 */

		if ((rc = ippctl_extract_aname(nvlp, &aname)) != 0) {
			nvlist_free(nvlp);
			return (rc);
		}

		nvlist_free(nvlp);
		rc = ippctl_action_mod(aname);
		break;

	case IPPCTL_OP_LIST_MODS:

		/*
		 * List all the modules.
		 */

		DBG0(DBG_CBOPS, "op = IPPCTL_OP_LIST_MODS\n");

		nvlist_free(nvlp);
		rc = ippctl_list_mods();
		break;

	case IPPCTL_OP_MOD_LIST_ACTIONS:

		/*
		 * List all the actions for a given module.
		 */

		DBG0(DBG_CBOPS, "op = IPPCTL_OP_LIST_MODS\n");

		if ((rc = ippctl_extract_modname(nvlp, &modname)) != 0) {
			nvlist_free(nvlp);
			return (rc);
		}

		nvlist_free(nvlp);
		rc = ippctl_mod_list_actions(modname);
		break;

	default:

		/*
		 * Unrecognized opcode.
		 */

		nvlist_free(nvlp);
		rc = EINVAL;
		break;
	}

	/*
	 * The length of buffer that we need to notify back to libipp with
	 * the command ioctl's return is the length of the first data buffer
	 * in the array. We only expact to pass back data buffers if the
	 * operation succeeds (NOTE: this does not mean the kernel call has
	 * to succeed, merely that we successfully issued it and processed
	 * the results).
	 */

	if (rc == 0)
		*nextbuflenp = ippctl_array[0].buflen;

	return (rc);
}
#undef	__FN__

#define	__FN__	"ippctl_action_create"
static int
ippctl_action_create(
	char		*modname,
	char		*aname,
	nvlist_t	*nvlp,
	ipp_flags_t	flags)
{
	int		ipp_rc;
	int		rc;
	ipp_mod_id_t	mid;
	ipp_action_id_t	aid;

	/*
	 * Look up the module id from the name and create the new
	 * action.
	 */

	mid = ipp_mod_lookup(modname);
	FREE_TEXT(modname);

	ipp_rc = ipp_action_create(mid, aname, &nvlp, flags, &aid);
	FREE_TEXT(aname);

	/*
	 * Add an nvlist containing the kernel return code to the
	 * set of nvlists to pass back to libipp.
	 */

	if ((rc = ippctl_set_rc(ipp_rc)) != 0) {
		if (nvlp != NULL) {
			nvlist_free(nvlp);
			if (ipp_action_destroy(aid, 0) != 0) {
				cmn_err(CE_PANIC,
				    "ippctl: unrecoverable error (aid = %d)",
				    aid);
				/*NOTREACHED*/
			}
		}
		return (rc);
	}

	/*
	 * If the module passed back an nvlist, add this as
	 * well.
	 */

	if (nvlp != NULL) {
		rc = ippctl_callback(nvlp, NULL);
		nvlist_free(nvlp);
	} else
		rc = 0;

	return (rc);
}
#undef	__FN__

#define	__FN__	"ippctl_action_destroy"
static int
ippctl_action_destroy(
	char		*aname,
	ipp_flags_t	flags)
{
	ipp_action_id_t	aid;
	int		ipp_rc;
	int		rc;

	/*
	 * Look up the action id and destroy the action.
	 */

	aid = ipp_action_lookup(aname);
	FREE_TEXT(aname);

	ipp_rc = ipp_action_destroy(aid, flags);

	/*
	 * Add an nvlist containing the kernel return code to the
	 * set of nvlists to pass back to libipp.
	 */

	if ((rc = ippctl_set_rc(ipp_rc)) != 0)
		return (rc);

	/*
	 * There's no more information to pass back.
	 */

	return (0);
}
#undef	__FN__

#define	__FN__	"ippctl_action_modify"
static int
ippctl_action_modify(
	char		*aname,
	nvlist_t	*nvlp,
	ipp_flags_t	flags)
{
	ipp_action_id_t	aid;
	int		ipp_rc;
	int		rc;

	/*
	 * Look up the action id and modify the action.
	 */

	aid = ipp_action_lookup(aname);
	FREE_TEXT(aname);

	ipp_rc = ipp_action_modify(aid, &nvlp, flags);

	/*
	 * Add an nvlist containing the kernel return code to the
	 * set of nvlists to pass back to libipp.
	 */

	if ((rc = ippctl_set_rc(ipp_rc)) != 0) {
		nvlist_free(nvlp);
		return (rc);
	}

	/*
	 * If the module passed back an nvlist, add this as
	 * well.
	 */

	if (nvlp != NULL) {
		rc = ippctl_callback(nvlp, NULL);
		nvlist_free(nvlp);
	} else
		rc = 0;

	return (rc);
}
#undef	__FN__

#define	__FN__	"ippctl_action_info"
static int
ippctl_action_info(
	char		*aname,
	ipp_flags_t	flags)
{
	ipp_action_id_t	aid;
	int		ipp_rc;
	int		rc;

	/*
	 * Look up the action and call the information retrieval
	 * entry point.
	 *
	 * NOTE: The callback function that is passed in packs and
	 * stores each of the nvlists it is called with in the array
	 * that will be passed back to libipp.
	 */

	aid = ipp_action_lookup(aname);
	FREE_TEXT(aname);

	ipp_rc = ipp_action_info(aid, ippctl_callback, NULL, flags);

	/*
	 * Add an nvlist containing the kernel return code to the
	 * set of nvlists to pass back to libipp.
	 */

	if ((rc = ippctl_set_rc(ipp_rc)) != 0)
		return (rc);

	/*
	 * There's no more information to pass back.
	 */

	return (0);
}
#undef	__FN__

#define	__FN__	"ippctl_action_mod"
static int
ippctl_action_mod(
	char		*aname)
{
	ipp_mod_id_t	mid;
	ipp_action_id_t	aid;
	char		*modname;
	nvlist_t	*nvlp;
	int		ipp_rc;
	int		rc;

	/*
	 * Look up the action id and get the id of the module that
	 * implements the action. If that succeeds then look up the
	 * name of the module.
	 */

	aid = ipp_action_lookup(aname);
	FREE_TEXT(aname);

	if ((ipp_rc = ipp_action_mod(aid, &mid)) == 0)
		ipp_rc = ipp_mod_name(mid, &modname);

	/*
	 * Add an nvlist containing the kernel return code to the
	 * set of nvlists to pass back to libipp.
	 */

	if ((rc = ippctl_set_rc(ipp_rc)) != 0)
		return (rc);

	/*
	 * If everything succeeded add an nvlist containing the
	 * module name to the set of nvlists to pass back to libipp.
	 */

	if (ipp_rc == 0) {
		if ((rc = nvlist_alloc(&nvlp, NV_UNIQUE_NAME, KM_SLEEP)) != 0)
			return (rc);

		if ((rc = ippctl_attach_modname(nvlp, modname)) != 0) {
			nvlist_free(nvlp);
			return (rc);
		}

		FREE_TEXT(modname);

		rc = ippctl_callback(nvlp, NULL);
		nvlist_free(nvlp);
	} else
		rc = 0;

	return (rc);
}
#undef	__FN__

#define	__FN__	"ippctl_list_mods"
static int
ippctl_list_mods(
	void)
{
	nvlist_t	*nvlp;
	int		ipp_rc;
	int		rc = 0;
	ipp_mod_id_t	*mid_array;
	char		**modname_array = NULL;
	int		nelt;
	int		length;
	int		i;

	/*
	 * Get a list of all the module ids. If that succeeds,
	 * translate the ids into names.
	 *
	 * NOTE: This translation may fail if a module is
	 * unloaded during this operation. If this occurs, EAGAIN
	 * will be passed back to libipp note that a transient
	 * problem occured.
	 */

	if ((ipp_rc = ipp_list_mods(&mid_array, &nelt)) == 0) {

		/*
		 * It is possible that there are no modules
		 * registered.
		 */

		if (nelt > 0) {
			length = nelt * sizeof (char *);
			modname_array = kmem_zalloc(length, KM_SLEEP);

			for (i = 0; i < nelt; i++) {
				if (ipp_mod_name(mid_array[i],
				    &modname_array[i]) != 0) {
					kmem_free(mid_array, nelt *
					    sizeof (ipp_mod_id_t));
					FREE_TEXT_ARRAY(modname_array, nelt);
					ipp_rc = EAGAIN;
					goto done;
				}
			}

			kmem_free(mid_array, nelt * sizeof (ipp_mod_id_t));

			if ((rc = nvlist_alloc(&nvlp, NV_UNIQUE_NAME,
			    KM_SLEEP)) != 0) {
				FREE_TEXT_ARRAY(modname_array, nelt);
				return (rc);
			}

			if ((rc = ippctl_attach_modname_array(nvlp,
			    modname_array, nelt)) != 0) {
				FREE_TEXT_ARRAY(modname_array, nelt);
				nvlist_free(nvlp);
				return (rc);
			}

			FREE_TEXT_ARRAY(modname_array, nelt);

			if ((rc = ippctl_callback(nvlp, NULL)) != 0) {
				nvlist_free(nvlp);
				return (rc);
			}

			nvlist_free(nvlp);
		}
	}

done:
	/*
	 * Add an nvlist containing the kernel return code to the
	 * set of nvlists to pass back to libipp.
	 */

	if ((rc = ippctl_set_rc(ipp_rc)) != 0)
		return (rc);

	return (0);
}
#undef	__FN__

#define	__FN__	"ippctl_mod_list_actions"
static int
ippctl_mod_list_actions(
	char		*modname)
{
	ipp_mod_id_t	mid;
	nvlist_t	*nvlp;
	int		ipp_rc;
	int		rc = 0;
	ipp_action_id_t	*aid_array;
	char		**aname_array = NULL;
	int		nelt;
	int		length;
	int		i;

	/*
	 * Get the module id.
	 */

	mid = ipp_mod_lookup(modname);
	FREE_TEXT(modname);

	/*
	 * Get a list of all the action ids for the module. If that succeeds,
	 * translate the ids into names.
	 *
	 * NOTE: This translation may fail if an action is
	 * destroyed during this operation. If this occurs, EAGAIN
	 * will be passed back to libipp note that a transient
	 * problem occured.
	 */

	if ((ipp_rc = ipp_mod_list_actions(mid, &aid_array, &nelt)) == 0) {

		/*
		 * It is possible that there are no actions defined.
		 * (This is unlikely though as the module would normally
		 * be auto-unloaded fairly quickly)
		 */

		if (nelt > 0) {
			length = nelt * sizeof (char *);
			aname_array = kmem_zalloc(length, KM_SLEEP);

			for (i = 0; i < nelt; i++) {
				if (ipp_action_name(aid_array[i],
				    &aname_array[i]) != 0) {
					kmem_free(aid_array, nelt *
					    sizeof (ipp_action_id_t));
					FREE_TEXT_ARRAY(aname_array, nelt);
					ipp_rc = EAGAIN;
					goto done;
				}
			}

			kmem_free(aid_array, nelt * sizeof (ipp_action_id_t));

			if ((rc = nvlist_alloc(&nvlp, NV_UNIQUE_NAME,
			    KM_SLEEP)) != 0) {
				FREE_TEXT_ARRAY(aname_array, nelt);
				return (rc);
			}

			if ((rc = ippctl_attach_aname_array(nvlp, aname_array,
			    nelt)) != 0) {
				FREE_TEXT_ARRAY(aname_array, nelt);
				nvlist_free(nvlp);
				return (rc);
			}

			FREE_TEXT_ARRAY(aname_array, nelt);

			if ((rc = ippctl_callback(nvlp, NULL)) != 0) {
				nvlist_free(nvlp);
				return (rc);
			}

			nvlist_free(nvlp);
		}
	}

done:
	/*
	 * Add an nvlist containing the kernel return code to the
	 * set of nvlists to pass back to libipp.
	 */

	if ((rc = ippctl_set_rc(ipp_rc)) != 0)
		return (rc);

	return (0);
}
#undef	__FN__

#define	__FN__	"ippctl_data"
static int
ippctl_data(
	char	**dbufp,
	size_t	*dbuflenp,
	size_t	*nextbuflenp)
{
	int	i;

	DBG0(DBG_CBOPS, "called\n");

	/*
	 * Get the next data buffer from the array by looking at the
	 * 'read index'. If this is the same as the 'write index' then
	 * there's no more buffers in the array.
	 */

	i = ippctl_rindex;
	if (i == ippctl_windex)
		return (ENOENT);

	/*
	 * Extract the buffer details. It is a pre-packed nvlist.
	 */

	*dbufp = ippctl_array[i].buf;
	*dbuflenp = ippctl_array[i].buflen;

	DBG2(DBG_CBOPS, "accessing nvlist[%d], length %lu\n", i, *dbuflenp);
	ASSERT(*dbufp != NULL);

	/*
	 * Advance the 'read index' and check if there's another buffer.
	 * If there is then we need to pass back its length to libipp so that
	 * another data ioctl will be issued.
	 */

	i++;
	if (i < ippctl_windex)
		*nextbuflenp = ippctl_array[i].buflen;
	else
		*nextbuflenp = 0;

	ippctl_rindex = i;
	return (0);
}
#undef	__FN__

#define	__FN__	"ippctl_flush"
static void
ippctl_flush(
	void)
{
	int	i;
	char	*buf;
	size_t	buflen;

	/*
	 * Free any buffers left in the array.
	 */

	for (i = 0; i < ippctl_limit; i++) {
		if ((buflen = ippctl_array[i].buflen) > 0) {
			buf = ippctl_array[i].buf;
			ASSERT(buf != NULL);
			kmem_free(buf, buflen);
		}
	}

	/*
	 * NULL all the entries.
	 */

	bzero(ippctl_array, ippctl_limit * sizeof (ippctl_buf_t));

	/*
	 * Reset the indexes.
	 */

	ippctl_rindex = 0;
	ippctl_windex = 1;
}
#undef	__FN__

#define	__FN__	"ippctl_add_nvlist"
static int
ippctl_add_nvlist(
	nvlist_t	*nvlp,
	int		i)
{
	char		*buf;
	size_t		buflen;
	int		rc;

	/*
	 * NULL the buffer pointer so that a buffer is automatically
	 * allocated for us.
	 */

	buf = NULL;

	/*
	 * Pack the nvlist and get back the buffer pointer and length.
	 */

	if ((rc = nvlist_pack(nvlp, &buf, &buflen, NV_ENCODE_NATIVE,
	    KM_SLEEP)) != 0) {
		ippctl_array[i].buf = NULL;
		ippctl_array[i].buflen = 0;
		return (rc);
	}

	DBG2(DBG_CBOPS, "added nvlist[%d]: length %lu\n", i, buflen);

	/*
	 * Store the pointer an length in the array at the given index.
	 */

	ippctl_array[i].buf = buf;
	ippctl_array[i].buflen = buflen;

	return (0);
}
#undef	__FN__

#define	__FN__	"ippctl_callback"
/*ARGSUSED*/
static int
ippctl_callback(
	nvlist_t	*nvlp,
	void		*arg)
{
	int		i;
	int		rc;

	/*
	 * Check the 'write index' to see if there's space in the array for
	 * a new entry.
	 */

	i = ippctl_windex;
	ASSERT(i != 0);

	/*
	 * If there's no space, re-allocate the array (see comments in
	 * ippctl_realloc() for details).
	 */

	if (i == ippctl_limit)
		ippctl_realloc();

	/*
	 * Add the nvlist to the array.
	 */

	if ((rc = ippctl_add_nvlist(nvlp, i)) == 0)
		ippctl_windex++;

	return (rc);
}
#undef	__FN__

#define	__FN__	"ippctl_set_rc"
static int
ippctl_set_rc(
	int		val)
{
	nvlist_t	*nvlp;
	int		rc;

	/*
	 * Create an nvlist to store the return code,
	 */

	if ((rc = nvlist_alloc(&nvlp, NV_UNIQUE_NAME, KM_SLEEP)) != 0)
		return (ENOMEM);

	if ((rc = nvlist_add_int32(nvlp, IPPCTL_RC, val)) != 0) {
		nvlist_free(nvlp);
		return (rc);
	}

	/*
	 * Add it at the beginning of the array.
	 */

	rc = ippctl_add_nvlist(nvlp, 0);

	nvlist_free(nvlp);
	return (rc);
}
#undef	__FN__

#define	__FN__	"ippctl_alloc"
static void
ippctl_alloc(
	int	limit)
{
	/*
	 * Allocate the data buffer array and initialize the indexes.
	 */

	ippctl_array = kmem_zalloc(limit * sizeof (ippctl_buf_t), KM_SLEEP);
	ippctl_limit = limit;
	ippctl_rindex = 0;
	ippctl_windex = 1;
}
#undef	__FN__

#define	__FN__	"ippctl_realloc"
static void
ippctl_realloc(
	void)
{
	ippctl_buf_t	*array;
	int		limit;
	int		i;

	/*
	 * Allocate a new array twice the size of the old one.
	 */

	limit = ippctl_limit << 1;
	array = kmem_zalloc(limit * sizeof (ippctl_buf_t), KM_SLEEP);

	/*
	 * Copy across the information from the old array into the new one.
	 */

	for (i = 0; i < ippctl_limit; i++)
		array[i] = ippctl_array[i];

	/*
	 * Free the old array.
	 */

	kmem_free(ippctl_array, ippctl_limit * sizeof (ippctl_buf_t));

	ippctl_array = array;
	ippctl_limit = limit;
}
#undef	__FN__

#define	__FN__	"ippctl_free"
static void
ippctl_free(
	void)
{
	/*
	 * Flush the array prior to freeing it to make sure no buffers are
	 * leaked.
	 */

	ippctl_flush();

	/*
	 * Free the array.
	 */

	kmem_free(ippctl_array, ippctl_limit * sizeof (ippctl_buf_t));
	ippctl_array = NULL;
	ippctl_limit = -1;
	ippctl_rindex = -1;
	ippctl_windex = -1;
}
#undef	__FN__

#ifdef	IPPCTL_DEBUG
static void
ippctl_debug(
	uint64_t	type,
	char		*fn,
	char		*fmt,
			...)
{
	char		buf[255];
	va_list		adx;

	if ((type & ippctl_debug_flags) == 0)
		return;

	mutex_enter(debug_mutex);
	va_start(adx, fmt);
	(void) vsnprintf(buf, 255, fmt, adx);
	va_end(adx);

	printf("%s: %s", fn, buf);
	mutex_exit(debug_mutex);
}
#endif	/* IPPCTL_DBG */
