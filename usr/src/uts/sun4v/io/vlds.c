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
 * LDOMs Domain Services Device Driver
 */
#include <sys/types.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/ksynch.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/taskq.h>
#include <sys/disp.h>
#include <sys/note.h>
#include <sys/mach_descrip.h>
#include <sys/mdesc.h>
#include <sys/mdeg.h>
#include <sys/ldc.h>
#include <sys/ds.h>
#include <sys/ds_impl.h>
#include <sys/vlds.h>
#include <sys/bitmap.h>
#include <sys/sysevent.h>

static dev_info_t *vlds_devi;


typedef struct vlds_state {
	dev_info_t	*dip;
	int		instance;
	evchan_t	*evchan;
} vlds_state_t;

static void *vlds_statep;

typedef struct vlds_recv_hdr {
	struct vlds_recv_hdr	*next;		/* next in recv list */
	void			*data;		/* the data itself */
	size_t			datasz;		/* size of the data */
} vlds_recv_hdr_t;

typedef struct vlds_svc_info {
	int		state;		/* driver svc info state VLDS_RECV* */
	vlds_recv_hdr_t	*recv_headp;	/* ptr to head of recv queue */
	vlds_recv_hdr_t	*recv_tailp;	/* ptr to tail of recv queue */
	size_t		recv_size;	/* no. of bytes in recv queue */
	uint_t		recv_cnt;	/* no of messages in recv queue */
	kmutex_t	recv_lock;	/* lock for recv queue */
	kcondvar_t	recv_cv;	/* condition variable for recv queue */
	int		recv_nreaders;	/* no of currently waiting readers */
} vlds_svc_info_t;

#define	VLDS_RECV_OK		1
#define	VLDS_RECV_UNREG_PENDING	2
#define	VLDS_RECV_OVERFLOW	3

static int vlds_ports_inited = 0;

static uint_t vlds_flags_to_svc(uint64_t flags);


#define	VLDS_NAME		"vlds"
static int vlds_open(dev_t *devp, int flag, int otyp, cred_t *credp);
static int vlds_close(dev_t dev, int flag, int otyp, cred_t *credp);
static int vlds_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp);
static int vlds_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg,
    void **resultp);
static int vlds_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int vlds_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);

/* mdeg register functions */
static void vlds_mdeg_init(void);
static int vlds_mdeg_cb(void *cb_argp, mdeg_result_t *resp);
static int vlds_mdeg_register(void);
static int vlds_mdeg_unregister(void);
static int vlds_add_mdeg_port(md_t *mdp, mde_cookie_t node);

/* driver utilities */
static void vlds_user_reg_cb(ds_cb_arg_t arg, ds_ver_t *ver, ds_svc_hdl_t hdl);
static void vlds_user_unreg_cb(ds_cb_arg_t arg);
static void vlds_user_data_cb(ds_cb_arg_t arg, void *buf, size_t buflen);
static void vlds_recvq_init(vlds_svc_info_t *dpsp);
static void vlds_recvq_destroy(vlds_svc_info_t *dpsp);
static int vlds_recvq_get_data(vlds_svc_info_t *dpsp, void *buf, size_t buflen,
    size_t *msglenp, int mode);
static void vlds_recvq_drain(vlds_svc_info_t *dpsp);
static int vlds_recvq_put_data(vlds_svc_info_t *dpsp, void *buf, size_t buflen);
static int vlds_recv_msg(ds_svc_hdl_t hdl, void *buf, size_t buflen,
    size_t *msglenp, int mode);

/*
 * DS driver Ops Vector
 */
static struct cb_ops vlds_cb_ops = {
	vlds_open,		/* cb_open */
	vlds_close,		/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	vlds_ioctl,		/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	(struct streamtab *)NULL, /* cb_str */
	D_MP | D_64BIT,		/* cb_flag */
	CB_REV,			/* cb_rev */
	nodev,			/* cb_aread */
	nodev			/* cb_awrite */
};

static struct dev_ops vlds_dev_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	vlds_getinfo,		/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	vlds_attach,		/* devo_attach */
	vlds_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&vlds_cb_ops,		/* devo_cb_ops */
	(struct bus_ops *)NULL,	/* devo_bus_ops */
	nulldev			/* devo_power */
};

static struct modldrv modldrv = {
	&mod_driverops,
	"Domain Services Driver 1.0",
	&vlds_dev_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

/*
 * Callback ops for user-land services.
 */
static ds_clnt_ops_t ds_user_ops = {
	vlds_user_reg_cb,		/* register */
	vlds_user_unreg_cb,		/* unregister */
	vlds_user_data_cb,		/* data */
	NULL				/* ds_ucap_init will fill in */
};

static size_t vlds_recvq_maxsize = DS_STREAM_MTU * 8;
static uint_t vlds_recvq_maxmsg = 16;

#define	VLDS_MINOR_MAX			SHRT_MAX

/* Definitions for binding handle array */
static ulong_t vlds_bitmap_initial = 1;	/* index 0 indicates error */
static ulong_t *vlds_minor_bitmap = &vlds_bitmap_initial;
static size_t vlds_minor_bits = BT_NBIPUL;
static kmutex_t vlds_minor_mutex;

/*
 * Following vlds_minor_* routines map a binding handle to a minor number.
 * Has to be called w/ locks held.
 */
static ulong_t *
vlds_minor_alloc(void)
{
	ulong_t *bhst = vlds_minor_bitmap;

	/* Increase bitmap by one BT_NBIPUL */
	if (vlds_minor_bits + BT_NBIPUL > VLDS_MINOR_MAX) {
		return ((ulong_t *)NULL);
	}
	vlds_minor_bitmap = kmem_zalloc(
	    BT_SIZEOFMAP(vlds_minor_bits + BT_NBIPUL), KM_SLEEP);
	bcopy(bhst, vlds_minor_bitmap, BT_SIZEOFMAP(vlds_minor_bits));
	if (bhst != &vlds_bitmap_initial)
		kmem_free(bhst, BT_SIZEOFMAP(vlds_minor_bits));
	vlds_minor_bits += BT_NBIPUL;

	return (vlds_minor_bitmap);
}

static void
vlds_minor_free(ulong_t *bitmap)
{
	if (bitmap != &vlds_bitmap_initial)
		kmem_free(bitmap, BT_SIZEOFMAP(vlds_minor_bits));
}

static index_t
vlds_minor_get(void)
{
	index_t idx;
	ulong_t *bhst;

	/* Search for an available index */
	mutex_enter(&vlds_minor_mutex);
	if ((idx = bt_availbit(vlds_minor_bitmap,
	    vlds_minor_bits)) == -1) {
		/* All busy - allocate additional binding handle bitmap space */
		if ((bhst = vlds_minor_alloc()) == NULL) {
			/* Reached our maximum of id's == SHRT_MAX */
			mutex_exit(&vlds_minor_mutex);
			return (0);
		} else {
			vlds_minor_bitmap = bhst;
		}
		idx = bt_availbit(vlds_minor_bitmap, vlds_minor_bits);
	}
	BT_SET(vlds_minor_bitmap, idx);
	mutex_exit(&vlds_minor_mutex);
	return (idx);
}

static void
vlds_minor_rele(index_t idx)
{
	mutex_enter(&vlds_minor_mutex);
	ASSERT(BT_TEST(vlds_minor_bitmap, idx) == 1);
	BT_CLEAR(vlds_minor_bitmap, idx);
	mutex_exit(&vlds_minor_mutex);
}

static void
vlds_minor_init(void)
{
	mutex_init(&vlds_minor_mutex, NULL, MUTEX_DEFAULT, NULL);
}

int
_init(void)
{
	int s;

	if ((s = ddi_soft_state_init(&vlds_statep, sizeof (vlds_state_t), 0))
	    != 0)
		return (s);

	if ((s = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&vlds_statep);
		return (s);
	}

	vlds_mdeg_init();

	return (s);
}

int
_fini(void)
{
	int s;

	if ((s = mod_remove(&modlinkage)) != 0)
		return (s);

	ddi_soft_state_fini(&vlds_statep);

	return (s);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}



/*ARGSUSED*/
static int
vlds_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **resultp)
{
	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*resultp = vlds_devi;
		return (DDI_SUCCESS);
	case DDI_INFO_DEVT2INSTANCE:
		*resultp = 0;
		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}


static int
vlds_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	if (ddi_create_minor_node(devi, VLDS_NAME, S_IFCHR,
	    0, DDI_PSEUDO, 0) == DDI_FAILURE) {
		ddi_remove_minor_node(devi, NULL);
		return (DDI_FAILURE);
	}
	vlds_devi = devi;

	vlds_minor_init();

	(void) vlds_mdeg_register();

	return (DDI_SUCCESS);
}


/*ARGSUSED*/
static int
vlds_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}

	vlds_minor_free(vlds_minor_bitmap);
	ddi_remove_minor_node(devi, NULL);
	(void) vlds_mdeg_unregister();
	return (DDI_SUCCESS);
}


/*ARGSUSED*/
static int
vlds_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	int minor;

	if (otyp != OTYP_CHR)
		return (EINVAL);

	if (getminor(*devp) != 0)
		return (ENXIO);

	minor = vlds_minor_get();
	if (minor == 0)
		/* All minors are busy */
		return (EBUSY);

	if (ddi_soft_state_zalloc(vlds_statep, minor) != DDI_SUCCESS) {
		vlds_minor_rele(minor);
		return (ENOMEM);
	}

	*devp = makedevice(getmajor(*devp), minor);

	return (0);
}


/*ARGSUSED*/
static int
vlds_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	int minor = (int)getminor(dev);
	vlds_state_t *sp;

	DS_DBG_VLDS(CE_NOTE, "vlds_close");

	/*
	 * Unregister all handles associated with this process.
	 */
	ds_unreg_all(minor);

	if (otyp != OTYP_CHR)
		return (EINVAL);

	sp = ddi_get_soft_state(vlds_statep, minor);
	if (sp == NULL) {
		return (ENXIO);
	}

	if (sp->evchan) {
		(void) sysevent_evc_unbind(sp->evchan);
		sp->evchan = NULL;
	}

	ddi_soft_state_free(vlds_statep, minor);
	vlds_minor_rele(minor);

	return (0);
}

int
vlds_init_sysevent(vlds_state_t *sp, uint32_t flags)
{
	char evchan_name[MAX_CHNAME_LEN];
	int rv;

	if (flags & DSSF_ANYCB_VALID) {
		if (sp->evchan) {
			DS_DBG_VLDS(CE_NOTE, "%s: sysevent already bound",
			    __func__);
			return (0);
		}
		(void) sprintf(evchan_name, VLDS_SYSEV_CHAN_FMT, ddi_get_pid());
		if ((rv = sysevent_evc_bind(evchan_name, &sp->evchan,
		    EVCH_CREAT|EVCH_HOLD_PEND)) != 0) {
			cmn_err(CE_WARN, "%s: can't bind to '%s' (%d)",
			    __func__, evchan_name, rv);
			return (rv);
		}

		DS_DBG_VLDS(CE_NOTE, "%s: sysevent bind to '%s' successful",
		    __func__, evchan_name);
	}
	return (0);
}

#define	ARGTOPTR(x)	((void *)((uintptr_t)(x)))
#define	ARGTOUINT(x)	((uint_t)(x))
#define	ARGTOINT(x)	((int)(x))

static int
vlds_get_string(vlds_string_t *strp, char **rstrp, int mode)
{
	char *str;
	uint_t len = strp->vlds_strlen;
	uint_t slen;

	if (len == 0) {
		*rstrp = NULL;
		return (0);
	}
	if (len > MAXNAMELEN) {
		DS_DBG_VLDS(CE_NOTE, "%s: invalid string length: %d", __func__,
		    len);
		return (EINVAL);
	}
	str = DS_MALLOC(len);
	if (ddi_copyin(ARGTOPTR(strp->vlds_strp), str, len, mode) != 0) {
		DS_DBG_VLDS(CE_NOTE, "%s: ddi copyin failed (%p)", __func__,
		    ARGTOPTR(strp->vlds_strp));
		DS_FREE(str, len);
		return (EFAULT);
	}
	slen = strlen(str) + 1;
	if (slen != len) {
		DS_DBG_VLDS(CE_NOTE, "%s: invalid string len: %d != len: %d",
		    __func__, slen, len);
		DS_FREE(str, len);
		return (EINVAL);
	}
	*rstrp = str;
	return (0);
}

static int
vlds_put_string(char *str, vlds_string_t *strp, int mode)
{
	uint_t len;
	char *tstr = NULL;
	int rv;

	if (str == NULL) {
		str = "";
	}
	len = strlen(str) + 1;

	/*
	 * If string is longer than user buffer, return a
	 * truncated, null-terminated string.
	 */
	if (len > strp->vlds_strlen) {
		len = strp->vlds_strlen;
		if (len > 0) {
			tstr = DS_MALLOC(len);
			(void) memcpy(tstr, str, len - 1);
			tstr[len - 1] = '\0';
			str = tstr;
		}
	}
	rv = ddi_copyout(str, ARGTOPTR(strp->vlds_strp), len, mode);
	if (tstr) {
		DS_FREE(tstr, len);
	}
	if (rv) {
		DS_DBG_VLDS(CE_NOTE, "%s: copyout (%p) failed", __func__,
		    ARGTOPTR(strp->vlds_strp));
		return (EFAULT);
	}
	return (0);
}

static int
vlds_get_ucap(vlds_cap_t *capp, ds_capability_t *ucap, int mode)
{
	char *servp;
	vlds_ver_t *dsvp;
	vlds_cap_t vlds_cap;
	uint_t n;
	uint_t nver;
	int i;
	int rv;

	if (ddi_copyin(capp, &vlds_cap, sizeof (vlds_cap), mode) != 0) {
		DS_DBG_VLDS(CE_NOTE, "%s: cap copyin failed (%p)", __func__,
		    (void *)capp);
		return (EFAULT);
	}

	nver = ARGTOUINT(vlds_cap.vlds_nver);

	if (nver > VLDS_MAX_VERS) {
		DS_DBG_VLDS(CE_NOTE, "%s: vlds_nver (%d) invalid", __func__,
		    nver);
		return (EINVAL);
	}

	if ((rv = vlds_get_string(&vlds_cap.vlds_service, &servp, mode)) != 0) {
		DS_DBG_VLDS(CE_NOTE, "%s: vlds_get_string vlds_service failed "
		    "(%d)", __func__, rv);
		return (rv);
	} else if (servp == NULL) {
		DS_DBG_VLDS(CE_NOTE, "%s: vlds_get_string vlds_service is NULL",
		    __func__);
		return (EINVAL);
	}

	n = nver * sizeof (vlds_ver_t);
	dsvp = DS_MALLOC(n);

	if (ddi_copyin(ARGTOPTR(vlds_cap.vlds_versp), dsvp, n, mode) != 0) {
		DS_DBG_VLDS(CE_NOTE, "%s: copyin of vers (%p, %d) failed",
		    __func__, ARGTOPTR(vlds_cap.vlds_versp), n);
		DS_FREE(servp, strlen(servp) + 1);
		DS_FREE(dsvp, n);
		return (EFAULT);
	}

	ucap->svc_id = servp;
	ucap->vers = DS_MALLOC(nver * sizeof (ds_ver_t));
	for (i = 0; i < nver; i++) {
		ucap->vers[i].major = dsvp[i].vlds_major;
		ucap->vers[i].minor = dsvp[i].vlds_minor;
	}
	ucap->nvers = nver;
	DS_FREE(dsvp, n);
	return (0);
}

static void
vlds_free_ucap(ds_capability_t *ucap)
{
	kmem_free(ucap->svc_id, strlen(ucap->svc_id) + 1);
	kmem_free(ucap->vers, ucap->nvers * sizeof (ds_ver_t));
}

/*ARGSUSED*/
static int
vlds_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	vlds_state_t *sp;
	ds_svc_hdl_t hdl;
	ds_domain_hdl_t dhdl;
	char *servicep;
	int rv;
	int minor = (int)getminor(dev);

	if ((sp = ddi_get_soft_state(vlds_statep, minor)) == NULL)
		return (ENXIO);

	switch (cmd) {

	case VLDS_SVC_REG:
	{
		vlds_svc_reg_arg_t vlds_arg;
		ds_capability_t ucap;
		uint64_t hdl_arg;
		uint_t flags;

		if (ddi_copyin((void *)arg, &vlds_arg, sizeof (vlds_arg),
		    mode) != 0) {
			DS_DBG_VLDS(CE_NOTE, "%s: SVC REG arg copyin failed",
			    __func__);
			return (EFAULT);
		}

		if ((rv = vlds_get_ucap(ARGTOPTR(vlds_arg.vlds_capp), &ucap,
		    mode)) != 0) {
			DS_DBG_VLDS(CE_NOTE, "%s: SVC REG get_ucap failed (%d)",
			    __func__, rv);
			return (rv);
		}

		flags = vlds_flags_to_svc(vlds_arg.vlds_reg_flags);
		if ((rv = vlds_init_sysevent(sp, flags)) != 0) {
			vlds_free_ucap(&ucap);
			return (rv);
		}

		rv = ds_ucap_init(&ucap, &ds_user_ops,
		    vlds_flags_to_svc(vlds_arg.vlds_reg_flags) | DSSF_ISUSER,
		    minor, &hdl);

		vlds_free_ucap(&ucap);

		if (rv) {
			DS_DBG_VLDS(CE_NOTE, "%s: SVC REG ds_ucap_init failed "
			    "(%d)", __func__, rv);
			return (rv);
		}

		hdl_arg = hdl;
		if (ddi_copyout(&hdl_arg, ARGTOPTR(vlds_arg.vlds_hdlp),
		    sizeof (hdl_arg), mode) != 0) {
			DS_DBG_VLDS(CE_NOTE, "%s: SVC REG copyout failed",
			    __func__);
			return (EFAULT);
		}
		DS_DBG_VLDS(CE_NOTE, "%s: SVC REG succeeded: hdl: %lx",
		    __func__, hdl);
		break;
	}

	case VLDS_UNREG_HDL:
	{
		vlds_unreg_hdl_arg_t vlds_arg;

		if (ddi_copyin((void *)arg, &vlds_arg, sizeof (vlds_arg),
		    mode) != 0) {
			DS_DBG_VLDS(CE_NOTE, "%s: UNREG_HDL arg copyin failed",
			    __func__);
			return (EFAULT);
		}

		hdl = vlds_arg.vlds_hdl;

		if ((rv = ds_is_my_hdl(hdl, minor)) != 0) {
			DS_DBG_VLDS(CE_NOTE, "%s: UNREG_HDL ds_is_my_hdl "
			    " hdl: %lx inst: %d failed (%d)", __func__,
			    hdl, rv, minor);
			return (rv);
		}

		if ((rv = ds_unreg_hdl(hdl)) != 0) {
			DS_DBG_VLDS(CE_NOTE, "%s: UNREG_HDL ds_cap_unreg "
			    " hdl: %lx failed (%d)", __func__, hdl, rv);
			return (rv);
		}
		DS_DBG_VLDS(CE_NOTE, "%s: UNREG_HDL hdl: %lx succeeded",
		    __func__, hdl);
		break;
	}

	case VLDS_HDL_LOOKUP:
	{
		vlds_hdl_lookup_arg_t vlds_arg;
		ds_svc_hdl_t *hdlsp;
		uint_t is_client, maxhdls, nhdls;
		uint64_t nhdls_arg;

		if (ddi_copyin((void *)arg, &vlds_arg, sizeof (vlds_arg),
		    mode) != 0) {
			DS_DBG_VLDS(CE_NOTE, "%s: HDL_LOOKUP arg copyin failed",
			    __func__);
			return (EFAULT);
		}

		is_client = ARGTOUINT(vlds_arg.vlds_isclient);
		maxhdls = ARGTOUINT(vlds_arg.vlds_maxhdls);
		if (maxhdls == 0) {
			DS_DBG_VLDS(CE_NOTE, "%s: HDL_LOOKUP invalid maxhdls "
			    "%d", __func__, maxhdls);
			return (EINVAL);
		}

		if ((rv = vlds_get_string(&vlds_arg.vlds_service, &servicep,
		    mode)) != 0) {
			DS_DBG_VLDS(CE_NOTE, "%s: HDL_LOOKUP vlds_get_string "
			    "(service) failed (%d)", __func__, rv);
			return (EFAULT);
		} else if (servicep == NULL) {
			DS_DBG_VLDS(CE_NOTE, "%s: HDL_LOOKUP vlds_get_string "
			    " service is NULL", __func__);
			return (EINVAL);
		}

		if (ARGTOPTR(vlds_arg.vlds_hdlsp) == 0) {
			hdlsp = NULL;
		} else {
			hdlsp = DS_MALLOC(maxhdls * sizeof (*hdlsp));
		}

		DS_DBG_VLDS(CE_NOTE, "%s: HDL_LOOKUP (%s, %d) entered",
		    __func__, servicep, is_client);
		rv = ds_hdl_lookup(servicep, is_client, hdlsp, maxhdls, &nhdls);

		DS_FREE(servicep, strlen(servicep) + 1);
		if (rv) {
			if (hdlsp) {
				DS_FREE(hdlsp, maxhdls * sizeof (*hdlsp));
			}
			DS_DBG_VLDS(CE_NOTE, "%s: HDL_LOOKUP failed: (%d)",
			    __func__, rv);
			return (rv);
		}

		if (hdlsp != NULL && nhdls > 0 &&
		    ddi_copyout(hdlsp, ARGTOPTR(vlds_arg.vlds_hdlsp),
		    nhdls * sizeof (ds_svc_hdl_t), mode) != 0) {
			if (hdlsp) {
				DS_FREE(hdlsp, maxhdls * sizeof (*hdlsp));
			}
			DS_DBG_VLDS(CE_NOTE, "%s: HDL_LOOKUP copyout of hdls "
			    " failed", __func__);
			return (EFAULT);
		}
		if (hdlsp) {
			DS_FREE(hdlsp, maxhdls * sizeof (*hdlsp));
		}

		nhdls_arg = nhdls;
		if (ddi_copyout(&nhdls_arg, ARGTOPTR(vlds_arg.vlds_nhdlsp),
		    sizeof (nhdls_arg), mode) != 0) {
			DS_DBG_VLDS(CE_NOTE, "%s: HDL_LOOKUP copyout of nhdls "
			    " failed", __func__);
			return (EFAULT);
		}
		DS_DBG_VLDS(CE_NOTE, "%s: HDL_LOOKUP succeeded: nhdls: %d",
		    __func__, nhdls);
		break;
	}

	case VLDS_DMN_LOOKUP:
	{
		vlds_dmn_lookup_arg_t vlds_arg;
		uint64_t dhdl_arg;

		if (ddi_copyin((void *)arg, &vlds_arg, sizeof (vlds_arg),
		    mode) != 0) {
			DS_DBG_VLDS(CE_NOTE, "%s: DMN_LOOKUP arg copyin failed",
			    __func__);
			return (EFAULT);
		}

		hdl = vlds_arg.vlds_hdl;

		if ((rv = ds_domain_lookup(hdl, &dhdl)) != 0) {
			DS_DBG_VLDS(CE_NOTE, "%s: DMN_LOOKUP lookup hdl: 0x%lx "
			    "failed (%d)", __func__, hdl, rv);
			return (rv);
		}

		dhdl_arg = dhdl;

		if (ddi_copyout(&dhdl_arg, ARGTOPTR(vlds_arg.vlds_dhdlp),
		    sizeof (dhdl_arg), mode) != 0) {
			DS_DBG_VLDS(CE_NOTE, "%s: DMN_LOOKUP copyout "
			    "failed (%d)", __func__, rv);
			return (rv);
		}

		DS_DBG_VLDS(CE_NOTE, "%s: DMN_LOOKUP hdl: 0x%lx, dhdl: 0x%lx "
		    "succeeded", __func__, hdl, dhdl);
		break;
	}

	case VLDS_SEND_MSG:
	{
		vlds_send_msg_arg_t vlds_arg;
		size_t buflen;
		char *bufp;

		if (ddi_copyin((void *)arg, &vlds_arg, sizeof (vlds_arg),
		    mode) != 0) {
			DS_DBG_VLDS(CE_NOTE, "%s: SEND_MSG arg copyin failed",
			    __func__);
			return (EFAULT);
		}

		hdl = vlds_arg.vlds_hdl;
		if ((rv = ds_is_my_hdl(hdl, minor)) != 0) {
			DS_DBG_VLDS(CE_NOTE, "%s: SEND_MSG ds_is_my_hdl "
			    " hdl: %lx inst: %d failed (%d)", __func__,
			    hdl, rv, minor);
			return (rv);
		}

		buflen = ARGTOUINT(vlds_arg.vlds_buflen);
		bufp = DS_MALLOC(buflen);
		DS_DBG_VLDS(CE_NOTE, "%s: SEND_MSG (hdl: %lx, bufp: %p, "
		    "buflen: %ld", __func__, hdl, ARGTOPTR(vlds_arg.vlds_bufp),
		    buflen);

		if (ddi_copyin(ARGTOPTR(vlds_arg.vlds_bufp), bufp, buflen,
		    mode) != 0) {
			DS_DBG_VLDS(CE_NOTE, "%s: SEND_MSG buf (%p, %ld) "
			    "copyin failed", __func__,
			    ARGTOPTR(vlds_arg.vlds_bufp), buflen);
			DS_FREE(bufp, buflen);
			return (EFAULT);
		}

		if ((rv = ds_cap_send(hdl, bufp, buflen)) != 0) {
			DS_FREE(bufp, buflen);
			DS_DBG_VLDS(CE_NOTE, "%s: SEND_MSG ds_cap_send failed "
			    "(%d)", __func__, rv);
			return (rv);
		}
		DS_DBG_VLDS(CE_NOTE, "%s: SEND_MSG hdl: %lx, bufp: %p, "
		    "buflen: %ld succeeded", __func__, hdl, (void *)bufp,
		    buflen);
		DS_DUMP_MSG(DS_DBG_FLAG_VLDS, bufp, buflen);
		DS_FREE(bufp, buflen);
		break;
	}

	case VLDS_RECV_MSG:
	{
		vlds_recv_msg_arg_t vlds_arg;
		size_t buflen, msglen;
		uint64_t msglen_arg;

		if (ddi_copyin((void *)arg, &vlds_arg, sizeof (vlds_arg),
		    mode) != 0) {
			DS_DBG_VLDS(CE_NOTE, "%s: RECV_MSG arg copyin failed",
			    __func__);
			return (EFAULT);
		}

		hdl = vlds_arg.vlds_hdl;
		if ((rv = ds_is_my_hdl(hdl, minor)) != 0) {
			DS_DBG_VLDS(CE_NOTE, "%s: RECV_MSG ds_is_my_hdl "
			    " hdl: %lx inst: %d failed (%d)", __func__,
			    hdl, rv, minor);
			return (rv);
		}

		buflen = ARGTOUINT(vlds_arg.vlds_buflen);

		if ((rv = vlds_recv_msg(hdl, ARGTOPTR(vlds_arg.vlds_bufp),
		    buflen, &msglen, mode)) != 0 && rv != EFBIG) {
			DS_DBG_VLDS(CE_NOTE, "%s: RECV_MSG vlds_recv_msg "
			    " failed (%d)", __func__, rv);
			return (rv);
		}

		msglen_arg = msglen;
		if (ddi_copyout(&msglen_arg, ARGTOPTR(vlds_arg.vlds_msglenp),
		    sizeof (msglen_arg), mode) != 0) {
			DS_DBG_VLDS(CE_NOTE, "%s: RECV_MSG copyout of msglen "
			    "failed", __func__);
			return (EFAULT);
		}

		if (rv == EFBIG) {
			return (EFBIG);
		}

		DS_DBG_VLDS(CE_NOTE, "%s: RECV_MSG hdl: %lx, "
		    "msglen: %ld succeeded", __func__, hdl, buflen);
		break;
	}

	case VLDS_HDL_ISREADY:
	{
		vlds_hdl_isready_arg_t vlds_arg;
		ds_svc_hdl_t hdl;
		uint64_t is_ready_arg;
		uint_t is_ready;

		if (ddi_copyin((void *)arg, &vlds_arg, sizeof (vlds_arg),
		    mode) != 0) {
			DS_DBG_VLDS(CE_NOTE, "%s: HDL_ISREADY arg copyin "
			    "failed", __func__);
			return (EFAULT);
		}

		hdl = vlds_arg.vlds_hdl;
		if ((rv = ds_hdl_isready(hdl, &is_ready)) != 0) {
			DS_DBG_VLDS(CE_NOTE, "%s: HDL_ISREADY ds_hdl_isready "
			    "error (%d)", __func__, rv);
			return (rv);
		}

		is_ready_arg = is_ready;
		if (ddi_copyout(&is_ready_arg, ARGTOPTR(vlds_arg.vlds_isreadyp),
		    sizeof (is_ready_arg), mode) != 0) {
			DS_DBG_VLDS(CE_NOTE, "%s: HDL_ISREADY copyout of "
			    "vlds_isready failed", __func__);
			return (EFAULT);
		}
		DS_DBG_VLDS(CE_NOTE, "%s: HDL_ISREADY succeeded hdl: %lx, "
		    "is_ready: %d", __func__, hdl, is_ready);
		break;
	}

	case VLDS_DOM_NAM2HDL:
	{
		vlds_dom_nam2hdl_arg_t vlds_arg;
		char *domain_name;
		uint64_t dhdl_arg;
		ds_domain_hdl_t dhdl;

		if (ddi_copyin((void *)arg, &vlds_arg, sizeof (vlds_arg),
		    mode) != 0) {
			DS_DBG_VLDS(CE_NOTE, "%s: DOM_NAM2HDL arg copyin "
			    "failed", __func__);
			return (EFAULT);
		}

		if ((rv = vlds_get_string(&vlds_arg.vlds_domain_name,
		    &domain_name, mode)) != 0) {
			DS_DBG_VLDS(CE_NOTE, "%s: DOM_NAM2HDL vlds_get_string "
			    "domain_name failed (%d)", __func__, rv);
			return (EFAULT);
		} else if (servicep == NULL) {
			DS_DBG_VLDS(CE_NOTE, "%s: DOM_NAM2HDL vlds_get_string "
			    " domain_name is NULL", __func__);
			return (EINVAL);
		}

		DS_DBG_VLDS(CE_NOTE, "%s: DOM_NAM2HDL (%s) entered", __func__,
		    domain_name);

		if ((rv = ds_dom_name_to_hdl(domain_name, &dhdl)) != 0) {
			DS_DBG_VLDS(CE_NOTE, "%s: DOM_NAM2HDL name: '%s' "
			    "failed: (%d)", __func__, domain_name, rv);
			DS_FREE(domain_name, strlen(domain_name) + 1);
			return (rv);
		}

		dhdl_arg = dhdl;
		if (ddi_copyout(&dhdl_arg, ARGTOPTR(vlds_arg.vlds_dhdlp),
		    sizeof (dhdl_arg), mode) != 0) {
			DS_FREE(domain_name, strlen(domain_name) + 1);
			DS_DBG_VLDS(CE_NOTE, "%s: DOM_NAM2HDL copyout of dhdl "
			    " failed", __func__);
			return (EFAULT);
		}

		DS_DBG_VLDS(CE_NOTE, "%s: DOM_NAM2HDL succeeded: name: '%s', "
		    "dhdl: 0x%lx", __func__, domain_name, dhdl);
		DS_FREE(domain_name, strlen(domain_name) + 1);
		break;
	}

	case VLDS_DOM_HDL2NAM:
	{
		vlds_dom_hdl2nam_arg_t vlds_arg;
		ds_domain_hdl_t dhdl;
		char *domain_name;

		if (ddi_copyin((void *)arg, &vlds_arg, sizeof (vlds_arg),
		    mode) != 0) {
			DS_DBG_VLDS(CE_NOTE, "%s: DOM_HDL2NAM arg copyin "
			    "failed", __func__);
			return (EFAULT);
		}

		dhdl = vlds_arg.vlds_dhdl;
		if ((rv = ds_dom_hdl_to_name(dhdl, &domain_name)) != 0) {
			DS_DBG_VLDS(CE_NOTE, "%s: DOM_HDL2NAM lookup dhdl: %lx "
			    "failed (%d)", __func__, dhdl, rv);
			return (rv);
		}

		if ((rv = vlds_put_string(domain_name,
		    &vlds_arg.vlds_domain_name, mode)) != 0) {
			DS_DBG_VLDS(CE_NOTE, "%s: DOM_HDL2NAM vlds_put_string "
			    "'%s' failed (%d)", __func__, domain_name, rv);
			return (rv);
		}

		DS_DBG_VLDS(CE_NOTE, "%s: DOM_HDL2NAM dhdl: 0x%lx name: '%s'",
		    __func__, dhdl, domain_name);
		break;
	}

	default:
		return (EINVAL);
	}
	return (0);
}

static uint_t
vlds_flags_to_svc(uint64_t flags)
{
	uint_t sflags = 0;

	if (flags & VLDS_REG_CLIENT)
		sflags |= DSSF_ISCLIENT;
	if (flags & VLDS_REGCB_VALID)
		sflags |= DSSF_REGCB_VALID;
	if (flags & VLDS_UNREGCB_VALID)
		sflags |= DSSF_UNREGCB_VALID;
	if (flags & VLDS_DATACB_VALID)
		sflags |= DSSF_DATACB_VALID;
	return (sflags);
}

/*
 * MD registration code.
 * Placed in vlds rather than ds module due to cirular dependency of
 * platsvc module which contains the mdeg code.
 */
mdeg_handle_t	vlds_mdeg_hdl;

/*
 * Look for "virtual-device-service" node among the
 * "virtual-device" nodes.
 */
static mdeg_prop_spec_t vlds_prop_template[] = {
	{ MDET_PROP_STR,	"name",	VLDS_MD_VIRT_ROOT_NAME },
	{ MDET_LIST_END,	NULL,	NULL    }
};

static mdeg_node_spec_t vlds_node_template =
	{ VLDS_MD_VIRT_DEV_NAME,	vlds_prop_template };

/*
 * Matching criteria passed to the MDEG to register interest
 * in changes to domain services port nodes identified by their
 * 'id' property.
 */
static md_prop_match_t vlds_port_prop_match[] = {
	{ MDET_PROP_VAL,    "id"   },
	{ MDET_LIST_END,    NULL    }
};

static mdeg_node_match_t vlds_port_match = { VLDS_MD_VIRT_PORT_NAME,
					vlds_port_prop_match };

/* mdeg callback */
static int
vlds_mdeg_cb(void *cb_argp, mdeg_result_t *resp)
{
	_NOTE(ARGUNUSED(cb_argp))
	int		idx;
	uint64_t	portno;
	int		rv;
	md_t		*mdp;
	mde_cookie_t	node;

	if (resp == NULL) {
		DS_DBG_VLDS(CE_NOTE, "vlds_mdeg_cb: no result returned");
		return (MDEG_FAILURE);
	}

	DS_DBG_VLDS(CE_NOTE, "%s: added=%d, removed=%d, matched=%d", __func__,
	    resp->added.nelem, resp->removed.nelem, resp->match_prev.nelem);

	/* process added ports */
	for (idx = 0; idx < resp->added.nelem; idx++) {
		mdp = resp->added.mdp;
		node = resp->added.mdep[idx];

		DS_DBG_VLDS(CE_NOTE, "%s: processing added node 0x%lx",
		    __func__, node);

		/* attempt to add a port */
		if ((rv = vlds_add_mdeg_port(mdp, node)) != MDEG_SUCCESS) {
			if (vlds_ports_inited) {
				cmn_err(CE_NOTE, "%s: unable to add port, "
				    "err = %d", __func__, rv);
			}
		}
	}

	/* process removed ports */
	for (idx = 0; idx < resp->removed.nelem; idx++) {
		mdp = resp->removed.mdp;
		node = resp->removed.mdep[idx];

		DS_DBG_VLDS(CE_NOTE, "%s: processing removed node 0x%lx",
		    __func__, node);

		/* read in the port's id property */
		if (md_get_prop_val(mdp, node, "id", &portno)) {
			cmn_err(CE_NOTE, "%s: node 0x%lx of removed list "
			    "has no 'id' property", __func__, node);
			continue;
		}

		/* attempt to remove a port */
		if ((rv = ds_remove_port(portno, 0)) != 0) {
			cmn_err(CE_NOTE, "%s: unable to remove port %lu, "
			    " err %d", __func__, portno, rv);
		}
	}

	vlds_ports_inited = 1;

	return (MDEG_SUCCESS);
}

/* register callback to mdeg */
static int
vlds_mdeg_register(void)
{
	int		rv;

	DS_DBG_VLDS(CE_NOTE, "vlds_mdeg_register: entered");

	/* perform the registration */
	rv = mdeg_register(&vlds_node_template, &vlds_port_match, vlds_mdeg_cb,
	    NULL, &vlds_mdeg_hdl);

	if (rv != MDEG_SUCCESS) {
		cmn_err(CE_NOTE, "vlds_mdeg_register: mdeg_register "
		    "failed, err = %d", rv);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/* unregister callback from mdeg */
static int
vlds_mdeg_unregister(void)
{
	DS_DBG_VLDS(CE_NOTE, "vlds_mdeg_unregister: hdl=0x%lx", vlds_mdeg_hdl);

	return (mdeg_unregister(vlds_mdeg_hdl));
}

static int
vlds_get_port_channel(md_t *mdp, mde_cookie_t node, uint64_t *ldc_id)
{
	int num_nodes, nchan;
	size_t listsz;
	mde_cookie_t *listp;

	/*
	 * Find the channel-endpoint node(s) (which should be under this
	 * port node) which contain the channel id(s).
	 */
	if ((num_nodes = md_node_count(mdp)) <= 0) {
		cmn_err(CE_NOTE, "%s: invalid number of channel-endpoint nodes "
		    "found (%d)", __func__, num_nodes);
		return (-1);
	}

	/* allocate space for node list */
	listsz = num_nodes * sizeof (mde_cookie_t);
	listp = kmem_alloc(listsz, KM_SLEEP);

	nchan = md_scan_dag(mdp, node, md_find_name(mdp, "channel-endpoint"),
	    md_find_name(mdp, "fwd"), listp);

	if (nchan <= 0) {
		cmn_err(CE_NOTE, "%s: no channel-endpoint nodes found",
		    __func__);
		kmem_free(listp, listsz);
		return (-1);
	}

	DS_DBG_VLDS(CE_NOTE, "%s: %d channel-endpoint nodes found", __func__,
	    nchan);

	/* use property from first node found */
	if (md_get_prop_val(mdp, listp[0], "id", ldc_id)) {
		cmn_err(CE_NOTE, "%s: channel-endpoint has no 'id' property",
		    __func__);
		kmem_free(listp, listsz);
		return (-1);
	}

	kmem_free(listp, listsz);

	return (0);
}

/* add a DS services port */
static int
vlds_add_mdeg_port(md_t *mdp, mde_cookie_t node)
{
	uint64_t	portno;
	uint64_t	ldc_id;
	int		rv;
	uint64_t	dhdl;
	char		*dom_name;

	/* read in the port's id property */
	if (md_get_prop_val(mdp, node, "id", &portno)) {
		cmn_err(CE_NOTE, "%s: node 0x%lx of added list has no "
		    "'id' property", __func__, node);
		return (MDEG_FAILURE);
	}

	if (portno >= DS_MAX_PORTS) {
		cmn_err(CE_NOTE, "%s: found port number (%lu) "
		    "larger than maximum supported number of ports", __func__,
		    portno);
		return (MDEG_FAILURE);
	}

	/* get all channels for this device (currently only one) */
	if (vlds_get_port_channel(mdp, node, &ldc_id) == -1) {
		return (MDEG_FAILURE);
	}

	if (md_get_prop_val(mdp, node, VLDS_MD_REM_DOMAIN_HDL, &dhdl) != 0) {
		cmn_err(CE_NOTE, "!ds%lx: %s no %s property", portno, __func__,
		    VLDS_MD_REM_DOMAIN_HDL);
		dhdl = DS_DHDL_INVALID;
	}

	if (md_get_prop_str(mdp, node, VLDS_MD_REM_DOMAIN_NAME, &dom_name)
	    != 0) {
		cmn_err(CE_NOTE, "!ds%lx: %s no %s property", portno, __func__,
		    VLDS_MD_REM_DOMAIN_NAME);
		dom_name = NULL;
	}

	rv = ds_add_port(portno, ldc_id, dhdl, dom_name, vlds_ports_inited);

	if (rv != 0) {
		if (vlds_ports_inited) {
			DS_DBG_VLDS(CE_NOTE, "ds%lx: %s LDC chan: %lx "
			    "failed err = %d", portno, __func__, ldc_id, rv);
		}
		return (MDEG_FAILURE);
	}

	DS_DBG_VLDS(CE_NOTE, "ds%lx: %s LDC chan: %lx inited", portno,
	    __func__, ldc_id);

	return (MDEG_SUCCESS);
}

static void
vlds_mdeg_init(void)
{
	md_t		*mdp;
	int		num_nodes;
	int		listsz;
	mde_cookie_t	rootnode;
	mde_cookie_t	vldsnode;
	mde_cookie_t	*vlds_nodes = NULL;
	int		nvlds;
	int		i;
	ds_domain_hdl_t	dhdl;
	char		*dom_name;
	char		*svc_name;

	if ((mdp = md_get_handle()) == NULL) {
		cmn_err(CE_NOTE, "Unable to initialize machine description");
		return;
	}

	num_nodes = md_node_count(mdp);
	ASSERT(num_nodes > 0);

	listsz = num_nodes * sizeof (mde_cookie_t);

	/* allocate temporary storage for MD scans */
	vlds_nodes = kmem_zalloc(listsz, KM_SLEEP);

	rootnode = md_root_node(mdp);
	ASSERT(rootnode != MDE_INVAL_ELEM_COOKIE);

	/*
	 * Search for Virtual Domain Service node.
	 */
	nvlds = md_scan_dag(mdp, rootnode, md_find_name(mdp,
	    VLDS_MD_VIRT_DEV_NAME), md_find_name(mdp, "fwd"), vlds_nodes);

	if (nvlds <= 0) {
		DS_DBG_MD(CE_NOTE, "No '%s' nodes in MD",
		    VLDS_MD_VIRT_DEV_NAME);
		goto done;
	}

	for (i = 0; i < nvlds; i++) {
		if (md_get_prop_str(mdp, vlds_nodes[i], "name", &svc_name)) {
			DS_DBG_MD(CE_NOTE, "%s: missing 'name' property for"
			    " IO node %d\n", __func__, i);
			continue;
		}

		if (strcmp(svc_name, VLDS_MD_VIRT_ROOT_NAME) == 0) {
			vldsnode = vlds_nodes[i];
			break;
		}
	}

	if (i >= nvlds) {
		DS_DBG_MD(CE_NOTE, "No '%s' node in MD",
		    VLDS_MD_VIRT_ROOT_NAME);
		goto done;
	}

	if (md_get_prop_val(mdp, vldsnode, VLDS_MD_DOMAIN_HDL, &dhdl) != 0) {
		DS_DBG_MD(CE_NOTE, "No '%s' property for '%s' node in MD",
		    VLDS_MD_DOMAIN_HDL, VLDS_MD_VIRT_ROOT_NAME);
		dhdl = DS_DHDL_INVALID;
	}
	if (md_get_prop_str(mdp, vldsnode, VLDS_MD_DOMAIN_NAME, &dom_name)
	    != 0) {
		DS_DBG_MD(CE_NOTE, "No '%s' property for '%s' node in MD",
		    VLDS_MD_DOMAIN_NAME, VLDS_MD_VIRT_ROOT_NAME);
		dom_name = NULL;
	}
	DS_DBG_MD(CE_NOTE, "My Domain Hdl: 0x%lx, Name: '%s'", dhdl,
	    dom_name == NULL ? "NULL" : dom_name);
	ds_set_my_dom_hdl_name(dhdl, dom_name);

done:
	DS_FREE(vlds_nodes, listsz);

	(void) md_fini_handle(mdp);
}

static void
vlds_user_reg_cb(ds_cb_arg_t arg, ds_ver_t *ver, ds_svc_hdl_t hdl)
{
	nvlist_t *nvl = NULL;
	ds_domain_hdl_t dhdl;
	char *servicep;
	uint32_t flags;
	int minor;
	vlds_state_t *sp;
	vlds_svc_info_t *dpsp;

	ds_cbarg_get_flags(arg, &flags);
	ASSERT((flags & DSSF_ISUSER) != 0);

	if ((flags & DSSF_DATACB_VALID) == 0) {
		/*
		 * must allocate and init the svc read queue.
		 */
		DS_DBG_VLDS(CE_NOTE, "%s: hdl: 0x%lx initing recvq", __func__,
		    hdl);
		dpsp = DS_MALLOC(sizeof (vlds_svc_info_t));
		vlds_recvq_init(dpsp);
		ds_cbarg_set_drv_per_svc_ptr(arg, dpsp);
	}

	if ((flags & DSSF_REGCB_VALID) != 0) {
		ds_cbarg_get_drv_info(arg, &minor);
		sp = ddi_get_soft_state(vlds_statep, minor);
		ASSERT(sp != NULL);
		ASSERT(sp->evchan != NULL);
		ds_cbarg_get_domain(arg, &dhdl);
		ds_cbarg_get_service_id(arg, &servicep);
		DS_DBG_VLDS(CE_NOTE, "%s: regcb: hdl: 0x%lx, ver%d.%d, "
		    " dhdl: 0x%lx", __func__, hdl, ver->major,
		    ver->minor, dhdl);
		if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, KM_SLEEP) ||
		    nvlist_add_uint64(nvl, VLDS_HDL, hdl) ||
		    nvlist_add_uint16(nvl, VLDS_VER_MAJOR, ver->major) ||
		    nvlist_add_uint16(nvl, VLDS_VER_MINOR, ver->minor) ||
		    nvlist_add_uint64(nvl, VLDS_DOMAIN_HDL, dhdl) ||
		    nvlist_add_string(nvl, VLDS_SERVICE_ID, servicep) ||
		    nvlist_add_boolean_value(nvl, VLDS_ISCLIENT,
		    (flags & DSSF_ISCLIENT) != 0) ||
		    sysevent_evc_publish(sp->evchan, EC_VLDS,
		    ESC_VLDS_REGISTER, "sun.com", "kernel", nvl, EVCH_SLEEP)) {
			cmn_err(CE_WARN, "Failed to send REG Callback");
		} else {
			DS_DBG_VLDS(CE_NOTE, "%s: sysevent_evc_publish "
			    "succeeded", __func__);
		}
		nvlist_free(nvl);
	}
}

static void
vlds_user_unreg_cb(ds_cb_arg_t arg)
{
	nvlist_t *nvl = NULL;
	int minor;
	ds_svc_hdl_t hdl;
	vlds_state_t *sp;
	void *dpsp;
	uint32_t flags;

	ds_cbarg_get_flags(arg, &flags);
	ASSERT((flags & DSSF_ISUSER) != 0);

	if ((flags & DSSF_DATACB_VALID) == 0) {
		ds_cbarg_get_drv_per_svc_ptr(arg, &dpsp);
		if (dpsp) {
			DS_DBG_VLDS(CE_NOTE, "%s: unregcb draining recvq",
			    __func__);
			vlds_recvq_drain(dpsp);
			vlds_recvq_destroy(dpsp);
			ds_cbarg_set_drv_per_svc_ptr(arg, NULL);
		}
	}

	if ((flags & DSSF_UNREGCB_VALID) != 0) {
		ds_cbarg_get_hdl(arg, &hdl);
		DS_DBG_VLDS(CE_NOTE, "%s: unregcb hdl: 0x%lx", __func__,
		    hdl);
		ds_cbarg_get_drv_info(arg, &minor);
		sp = ddi_get_soft_state(vlds_statep, minor);
		ASSERT(sp != NULL);
		ASSERT(sp->evchan != NULL);
		if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, KM_SLEEP) ||
		    nvlist_add_uint64(nvl, VLDS_HDL, hdl) ||
		    sysevent_evc_publish(sp->evchan, EC_VLDS,
		    ESC_VLDS_UNREGISTER, "sun.com", "kernel", nvl,
		    EVCH_SLEEP)) {
			cmn_err(CE_WARN, "Failed to send UNREG Callback");
		}
		nvlist_free(nvl);
	}
}

static void
vlds_user_data_cb(ds_cb_arg_t arg, void *buf, size_t buflen)
{
	nvlist_t *nvl = NULL;
	ds_svc_hdl_t hdl;
	int minor;
	void *dpsp;
	vlds_state_t *sp;
	uint32_t flags;

	ds_cbarg_get_flags(arg, &flags);
	ASSERT((flags & DSSF_ISUSER) != 0);

	if ((flags & DSSF_DATACB_VALID) == 0) {
		ds_cbarg_get_drv_per_svc_ptr(arg, &dpsp);
		ASSERT(dpsp != NULL);
		DS_DBG_VLDS(CE_NOTE, "%s: datacb: to recvq: buflen: %ld",
		    __func__, buflen);
		(void) vlds_recvq_put_data(dpsp, buf, buflen);
	} else {
		ds_cbarg_get_hdl(arg, &hdl);
		DS_DBG_VLDS(CE_NOTE, "%s: datacb: usercb: hdl: 0x%lx, "
		    " buflen: %ld", __func__, hdl, buflen);
		ds_cbarg_get_drv_info(arg, &minor);
		sp = ddi_get_soft_state(vlds_statep, minor);
		ASSERT(sp != NULL);
		ASSERT(sp->evchan != NULL);
		if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, KM_SLEEP) ||
		    nvlist_add_uint64(nvl, VLDS_HDL, hdl) ||
		    nvlist_add_byte_array(nvl, VLDS_DATA, buf, buflen) ||
		    sysevent_evc_publish(sp->evchan, EC_VLDS,
		    ESC_VLDS_DATA, "sun.com", "kernel", nvl, EVCH_SLEEP)) {
			cmn_err(CE_WARN, "Failed to send DATA Callback");
		}
	}
	nvlist_free(nvl);
}

/*
 * Initialize receive queue if request is from user land but
 * data callback is null (implying user will be using ds_recv_msg).
 */
static void
vlds_recvq_init(vlds_svc_info_t *dpsp)
{
	dpsp->state = VLDS_RECV_OK;
	mutex_init(&dpsp->recv_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&dpsp->recv_cv, NULL, CV_DRIVER, NULL);
	dpsp->recv_headp = NULL;
	dpsp->recv_tailp = NULL;
	dpsp->recv_size = 0;
	dpsp->recv_cnt = 0;
}

static void
vlds_recvq_destroy(vlds_svc_info_t *dpsp)
{
	ASSERT(dpsp->state == VLDS_RECV_UNREG_PENDING);
	ASSERT(dpsp->recv_size == 0);
	ASSERT(dpsp->recv_cnt == 0);
	ASSERT(dpsp->recv_headp == NULL);
	ASSERT(dpsp->recv_tailp == NULL);

	mutex_destroy(&dpsp->recv_lock);
	cv_destroy(&dpsp->recv_cv);
	DS_FREE(dpsp, sizeof (vlds_svc_info_t));
}

static int
vlds_recvq_get_data(vlds_svc_info_t *dpsp, void *buf, size_t buflen,
    size_t *msglenp, int mode)
{
	vlds_recv_hdr_t *rhp;
	int rv;
	size_t msglen;

	mutex_enter(&dpsp->recv_lock);
	while (dpsp->recv_size == 0) {
		ASSERT(dpsp->recv_cnt == 0);
		if (dpsp->state == VLDS_RECV_UNREG_PENDING)
			break;

		if (dpsp->state == VLDS_RECV_OVERFLOW) {
			DS_DBG_RCVQ(CE_NOTE, "%s: user data queue overflow",
			    __func__);
			dpsp->state = VLDS_RECV_OK;
			mutex_exit(&dpsp->recv_lock);
			return (ENOBUFS);
		}
		/*
		 * Passing in a buflen of 0 allows user to poll for msgs.
		 */
		if (buflen == 0) {
			mutex_exit(&dpsp->recv_lock);
			*msglenp = 0;
			return (EFBIG);
		}
		dpsp->recv_nreaders += 1;
		rv = cv_wait_sig(&dpsp->recv_cv, &dpsp->recv_lock);
		dpsp->recv_nreaders -= 1;
		if (rv == 0) {
			DS_DBG_RCVQ(CE_NOTE, "%s: signal EINTR", __func__);
			mutex_exit(&dpsp->recv_lock);
			return (EINTR);
		}
	}
	if (dpsp->state == VLDS_RECV_UNREG_PENDING) {
		DS_DBG_RCVQ(CE_NOTE, "%s: unreg pending", __func__);
		cv_broadcast(&dpsp->recv_cv);
		mutex_exit(&dpsp->recv_lock);
		return (EINVAL);
	}
	ASSERT(dpsp->recv_headp != NULL);
	rhp = dpsp->recv_headp;

	/*
	 * Don't transfer truncated data, return EFBIG error if user-supplied
	 * buffer is too small.
	 */
	if (rhp->datasz > buflen) {
		*msglenp = rhp->datasz;
		mutex_exit(&dpsp->recv_lock);
		return (EFBIG);
	}
	if (rhp == dpsp->recv_tailp) {
		dpsp->recv_headp = NULL;
		dpsp->recv_tailp = NULL;
	} else {
		dpsp->recv_headp = rhp->next;
		ASSERT(dpsp->recv_headp != NULL);
	}
	ASSERT(dpsp->recv_cnt > 0);
	dpsp->recv_size -= rhp->datasz;
	dpsp->recv_cnt -= 1;
	mutex_exit(&dpsp->recv_lock);

	msglen = rhp->datasz;
	rv = ddi_copyout(rhp->data, buf, msglen, mode);

	if (rv == 0) {
		DS_DBG_VLDS(CE_NOTE, "%s: user data dequeued msglen: %ld",
		    __func__, rhp->datasz);
		DS_DUMP_MSG(DS_DBG_FLAG_VLDS, rhp->data, rhp->datasz);
	}

	DS_FREE(rhp->data, rhp->datasz);
	DS_FREE(rhp, sizeof (vlds_recv_hdr_t));

	if (rv != 0) {
		DS_DBG_VLDS(CE_NOTE, "%s: copyout failed", __func__);
		return (EFAULT);
	}

	*msglenp = msglen;
	return (0);
}

uint64_t vlds_recv_drain_delay_time = 1 * MILLISEC;

static void
vlds_recvq_drain(vlds_svc_info_t *dpsp)
{
	vlds_recv_hdr_t	*rhp, *nextp;

	mutex_enter(&dpsp->recv_lock);
	dpsp->state = VLDS_RECV_UNREG_PENDING;
	for (rhp = dpsp->recv_tailp; rhp != NULL; rhp = nextp) {
		nextp = rhp->next;
		DS_FREE(rhp->data, rhp->datasz);
		DS_FREE(rhp, sizeof (vlds_recv_hdr_t));
	}
	dpsp->recv_headp = NULL;
	dpsp->recv_tailp = NULL;
	dpsp->recv_size = 0;
	dpsp->recv_cnt = 0;

	/*
	 * Make sure other readers have exited.
	 */
	while (dpsp->recv_nreaders > 0) {
		cv_broadcast(&dpsp->recv_cv);
		mutex_exit(&dpsp->recv_lock);
		delay(vlds_recv_drain_delay_time);
		mutex_enter(&dpsp->recv_lock);
	}

	mutex_exit(&dpsp->recv_lock);
}

static int
vlds_recvq_put_data(vlds_svc_info_t *dpsp, void *buf, size_t buflen)
{
	vlds_recv_hdr_t	*rhp;

	mutex_enter(&dpsp->recv_lock);
	if (dpsp->state != VLDS_RECV_UNREG_PENDING) {
		/*
		 * If we've already encountered an overflow, or there
		 * are pending messages and either queue size and
		 * message limits will be exceeded with this message,
		 * we mark the recvq as overflowed and return an ENOBUFS
		 * error.  This allows the enqueuing of one big message
		 * or several little messages.
		 */
		if ((dpsp->state == VLDS_RECV_OVERFLOW) ||
		    ((dpsp->recv_cnt != 0) &&
		    ((dpsp->recv_size + buflen) > vlds_recvq_maxsize) ||
		    ((dpsp->recv_cnt + 1) > vlds_recvq_maxmsg))) {
			DS_DBG_RCVQ(CE_NOTE, "%s: user data queue overflow",
			    __func__);
			dpsp->state = VLDS_RECV_OVERFLOW;
			cv_broadcast(&dpsp->recv_cv);
			mutex_exit(&dpsp->recv_lock);
			return (ENOBUFS);
		}

		DS_DBG_RCVQ(CE_NOTE, "%s: user data enqueued msglen: %ld",
		    __func__, buflen);
		DS_DUMP_MSG(DS_DBG_FLAG_RCVQ, buf, buflen);
		rhp = DS_MALLOC(sizeof (vlds_recv_hdr_t));
		rhp->data = DS_MALLOC(buflen);
		(void) memcpy(rhp->data, buf, buflen);
		rhp->datasz = buflen;
		rhp->next = NULL;
		if (dpsp->recv_headp == NULL) {
			dpsp->recv_headp = rhp;
			dpsp->recv_tailp = rhp;
		} else {
			dpsp->recv_tailp->next = rhp;
			dpsp->recv_tailp = rhp;
		}
		dpsp->recv_size += rhp->datasz;
		dpsp->recv_cnt += 1;
		cv_broadcast(&dpsp->recv_cv);
	}
	mutex_exit(&dpsp->recv_lock);
	return (0);
}

static int
vlds_recv_msg(ds_svc_hdl_t hdl, void *buf, size_t buflen, size_t *msglenp,
    int mode)
{
	void *dpsp;
	ds_cb_arg_t cbarg;
	uint32_t flags;
	int rv;

	if ((rv = ds_hdl_get_cbarg(hdl, &cbarg)) != 0) {
		DS_DBG_VLDS(CE_NOTE, "%s: handle %lx not found (%d)", __func__,
		    hdl, rv);
		return (rv);
	}
	ds_cbarg_get_flags(cbarg, &flags);
	if ((flags & DSSF_ISUSER) == 0 || (flags & DSSF_DATACB_VALID) != 0) {
		DS_DBG_VLDS(CE_NOTE, "%s: invalid flags: %x", __func__, flags);
		return (EINVAL);
	}
	ds_cbarg_get_drv_per_svc_ptr(cbarg, &dpsp);
	if (dpsp == NULL) {
		DS_DBG_VLDS(CE_NOTE, "%s: recv on non-ready handle: %x",
		    __func__, flags);
		return (ENXIO);
	}
	rv = vlds_recvq_get_data(dpsp, buf, buflen, msglenp, mode);
	return (rv);
}
