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
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/policy.h>
#include <sys/pool.h>
#include <sys/pool_impl.h>

/*
 * The kernel pools subsystem is accessed and manipulated through the pool
 * device, which has two minor nodes /dev/pool, and /dev/poolctl.  User
 * processes can comminicate with pools through ioctls on these devices.
 *
 * The poolctl device (POOL_CTL_PARENT) can be used to modify and take
 * snapshot of the current configuration.  Only one process on the system
 * can have it open at any given time.  This device is also used to enable
 * or disable pools.  If pools are disabled, the pool driver can be unloaded
 * and completely removed from the system.
 *
 * The pool "info" device (POOL_INFO_PARENT) can only be used to obtain
 * snapshots of the current configuration and change/query pool bindings.
 * While some reconfiguration transaction via the poolctl device is in
 * progress, all processes using this "info" device will be provided with
 * the snapshot taken at the beginning of that transaction.
 */

#define	POOL_CTL_PARENT		0
#define	POOL_INFO_PARENT	1

static dev_info_t *pool_devi;	/* pool device information */
static int pool_openctl;	/* poolctl device is already open */

/*ARGSUSED*/
static int
pool_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	int error = DDI_FAILURE;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = pool_devi;
		error = DDI_SUCCESS;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		/*
		 * All dev_t's map to the same, single instance.
		 */
		*result = NULL;
		error = DDI_SUCCESS;
		break;
	default:
		break;
	}
	return (error);
}

static int
pool_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	int ret = DDI_SUCCESS;

	switch (cmd) {
	case DDI_DETACH:
		pool_lock();
		if (pool_state == POOL_ENABLED) {
			ret = DDI_FAILURE;
			pool_unlock();
			break;
		}
		ddi_remove_minor_node(devi, NULL);
		pool_devi = NULL;
		pool_unlock();
		break;
	default:
		ret = DDI_FAILURE;
	}
	return (ret);
}

static int
pool_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		if (pool_devi != NULL)
			return (DDI_FAILURE);
		if (ddi_create_minor_node(devi, "poolctl", S_IFCHR,
		    POOL_CTL_PARENT, DDI_PSEUDO, 0) == DDI_FAILURE ||
		    ddi_create_minor_node(devi, "pool", S_IFCHR,
		    POOL_INFO_PARENT, DDI_PSEUDO, 0) == DDI_FAILURE) {
			ddi_remove_minor_node(devi, NULL);
			return (DDI_FAILURE);
		}
		pool_devi = devi;
		ddi_report_dev(devi);
		break;
	case DDI_RESUME:
		break;
	default:
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);

}

/*
 * There is only one instance of the pool control device, poolctl,
 * and multiple instances of the pool info device, pool.
 */
/*ARGSUSED*/
static int
pool_open(dev_t *devp, int flag, int otype, cred_t *credp)
{
	minor_t minor = getminor(*devp);

	if (otype != OTYP_CHR)
		return (EINVAL);

	switch (minor) {
	case POOL_CTL_PARENT:
		if (secpolicy_pool(CRED()) != 0)
			return (EPERM);
		if (pool_lock_intr() != 0)
			return (EINTR);
		if (pool_openctl == 1) {
			pool_unlock();
			return (EBUSY);
		}
		pool_openctl = 1;
		pool_unlock();
		break;
	case POOL_INFO_PARENT:
		break;
	default:
		return (ENXIO);
	}
	return (0);
}

/*ARGSUSED*/
static int
pool_close(dev_t dev, int flag, int otype, cred_t *credp)
{
	if (otype != OTYP_CHR)
		return (EINVAL);
	if (getminor(dev) == 0) {
		/*
		 * We could be closing the poolctl device without finishing
		 * the commit transaction first, so do that now.
		 */
		pool_lock();
		(void) pool_commit(0);	/* cannot fail since arg is 0 */
		pool_openctl = 0;
		pool_unlock();
	}
	return (0);
}

/*
 * Main pool interface.
 */
/* ARGSUSED4 */
static int
pool_ioctl(dev_t dev, int cmd, intptr_t arg, int  mode, cred_t *credp,
    int *rvalp)
{
	pool_xtransfer_t xtransfer;
	pool_transfer_t transfer;
	pool_destroy_t destroy;
	pool_propget_t propget;
	pool_propput_t propput;
	pool_proprm_t proprm;
	pool_status_t status;
	pool_dissoc_t dissoc;
	pool_create_t create;
	pool_assoc_t assoc;
	pool_bindq_t bindq;
	pool_query_t query;
	pool_bind_t bind;
#ifdef	_MULTI_DATAMODEL
	pool_xtransfer32_t xtransfer32;
	pool_propput32_t propput32;
	pool_propget32_t propget32;
	pool_proprm32_t proprm32;
	pool_query32_t query32;
#endif	/* _MULTI_DATAMODEL */
	char *kbuf = NULL;
	size_t kbufsz = 0;
	int snapshot = 0;
	char *prop_name;
	size_t size = 0;
	nvlist_t *list;
	nvpair_t *pair;
	char *listbuf;
	minor_t minor;
	uint_t model;
	id_t *id_buf;
	int ret = 0;

	model = ddi_model_convert_from(mode & FMODELS);
	minor = getminor(dev);

	/*
	 * Check basic permissions first.
	 */
	switch (cmd) {
	case POOL_STATUS:
	case POOL_CREATE:
	case POOL_ASSOC:
	case POOL_DISSOC:
	case POOL_DESTROY:
	case POOL_TRANSFER:
	case POOL_XTRANSFER:
	case POOL_PROPPUT:
	case POOL_PROPRM:
	case POOL_COMMIT:
		if (minor != POOL_CTL_PARENT)
			return (EINVAL);
		/*FALLTHROUGH*/
	case POOL_BIND:
		if (secpolicy_pool(CRED()) != 0)
			return (EPERM);
		break;
	}

	switch (cmd) {
	case POOL_STATUS:
		if (ddi_copyin((void *)arg, &status,
		    sizeof (pool_status_t), mode) != 0)
			return (EFAULT);
		if (pool_lock_intr() != 0)
			return (EINTR);
		ret = pool_status(status.ps_io_state);
		pool_unlock();
		break;
	case POOL_STATUSQ:
		/*
		 * No need to grab pool_lock() to look at the current state.
		 */
		status.ps_io_state = pool_state;
		if (ddi_copyout(&status, (void *)arg,
		    sizeof (pool_status_t), mode) != 0)
			return (EFAULT);
		break;
	case POOL_QUERY:
		switch (model) {
#ifdef _MULTI_DATAMODEL
		case DDI_MODEL_ILP32:
			if (ddi_copyin((void *)arg, &query32,
			    sizeof (pool_query32_t), mode) != 0)
				return (EFAULT);
			query.pq_io_bufsize = query32.pq_io_bufsize;
			query.pq_io_buf = (char *)(uintptr_t)query32.pq_io_buf;
			break;
#endif	/* _MULTI_DATAMODEL */
		default:
		case DDI_MODEL_NONE:
			if (ddi_copyin((void *)arg, &query,
			    sizeof (pool_query_t), mode) != 0)
				return (EFAULT);
		}
		if (pool_lock_intr() != 0)
			return (EINTR);
		if (pool_state == POOL_DISABLED) {
			pool_unlock();
			return (ENOTACTIVE);
		}
		if (minor != 0 && pool_buf != NULL) {
			/*
			 * Return last snapshot if some
			 * transaction is still in progress
			 */
			if (kbufsz != 0 && pool_bufsz > kbufsz) {
				pool_unlock();
				return (ENOMEM);
			}
			kbuf = pool_buf;
			kbufsz = size = pool_bufsz;
			snapshot = 1;
		} else if (query.pq_io_bufsize != 0) {
			kbufsz = query.pq_io_bufsize;
			kbuf = kmem_alloc(kbufsz, KM_NOSLEEP);
			if (kbuf == NULL) {
				pool_unlock();
				return (ENOMEM);
			}
			ret = pool_pack_conf(kbuf, kbufsz, &size);
		} else {
			ret = pool_pack_conf(NULL, 0, &size);
		}
		if (ret == 0) {
			switch (model) {
#ifdef	_MULTI_DATAMODEL
			case DDI_MODEL_ILP32:
				query32.pq_io_bufsize = size;
				if (ddi_copyout((caddr_t)&query32, (void *)arg,
				    sizeof (pool_query32_t), mode) != 0)
					ret = EFAULT;
				break;
#endif	/* _MULTI_DATAMODEL */
			default:
			case DDI_MODEL_NONE:
				query.pq_io_bufsize = size;
				if (ddi_copyout(&query, (void *)arg,
				    sizeof (pool_query_t), mode) != 0)
					ret = EFAULT;
			}
			if (ret == 0 && query.pq_io_buf != NULL &&
			    ddi_copyout(kbuf, query.pq_io_buf, size, mode) != 0)
				ret = EFAULT;
		}
		pool_unlock();
		if (snapshot == 0)
			kmem_free(kbuf, kbufsz);
		break;
	case POOL_CREATE:
		if (ddi_copyin((void *)arg,
		    &create, sizeof (pool_create_t), mode) != 0)
			return (EFAULT);
		if (pool_lock_intr() != 0)
			return (EINTR);
		ret = pool_create(create.pc_o_type,
		    create.pc_o_sub_type, &create.pc_i_id);
		pool_unlock();
		if (ret == 0 && ddi_copyout(&create, (void *)arg,
		    sizeof (pool_create_t), mode) != 0)
			ret = EFAULT;
		break;
	case POOL_ASSOC:
		if (ddi_copyin((void *)arg, &assoc,
		    sizeof (pool_assoc_t), mode) != 0)
			return (EFAULT);
		if (pool_lock_intr() != 0)
			return (EINTR);
		ret = pool_assoc(assoc.pa_o_pool_id,
		    assoc.pa_o_id_type, assoc.pa_o_res_id);
		pool_unlock();
		break;
	case POOL_DISSOC:
		if (ddi_copyin((void *)arg, &dissoc,
		    sizeof (pool_dissoc_t), mode) != 0)
			return (EFAULT);
		if (pool_lock_intr() != 0)
			return (EINTR);
		ret = pool_dissoc(dissoc.pd_o_pool_id, dissoc.pd_o_id_type);
		pool_unlock();
		break;
	case POOL_DESTROY:
		if (ddi_copyin((void *)arg, &destroy,
		    sizeof (pool_destroy_t), mode) != 0)
			return (EFAULT);
		if (pool_lock_intr() != 0)
			return (EINTR);
		ret = pool_destroy(destroy.pd_o_type, destroy.pd_o_sub_type,
		    destroy.pd_o_id);
		pool_unlock();
		break;
	case POOL_TRANSFER:
		if (ddi_copyin((void *)arg, &transfer,
		    sizeof (pool_transfer_t), mode) != 0)
			return (EFAULT);
		if (pool_lock_intr() != 0)
			return (EINTR);
		ret = pool_transfer(transfer.pt_o_id_type, transfer.pt_o_src_id,
		    transfer.pt_o_tgt_id, transfer.pt_o_qty);
		pool_unlock();
		break;
	case POOL_XTRANSFER:
		switch (model) {
#ifdef _MULTI_DATAMODEL
		case DDI_MODEL_ILP32:
			if (ddi_copyin((void *)arg, &xtransfer32,
			    sizeof (pool_xtransfer32_t), mode) != 0)
				return (EFAULT);
			xtransfer.px_o_id_type = xtransfer32.px_o_id_type;
			xtransfer.px_o_src_id = xtransfer32.px_o_src_id;
			xtransfer.px_o_tgt_id = xtransfer32.px_o_tgt_id;
			xtransfer.px_o_complist_size =
			    xtransfer32.px_o_complist_size;
			xtransfer.px_o_comp_list =
			    (id_t *)(uintptr_t)xtransfer32.px_o_comp_list;
			break;
#endif /* _MULTI_DATAMODEL */
		default:
		case DDI_MODEL_NONE:
			if (ddi_copyin((void *)arg, &xtransfer,
			    sizeof (pool_xtransfer_t), mode) != 0)
				return (EFAULT);
		}
		/*
		 * Copy in IDs to transfer from the userland
		 */
		if (xtransfer.px_o_complist_size > POOL_IDLIST_SIZE)
			return (EINVAL);
		id_buf = kmem_alloc(xtransfer.px_o_complist_size *
		    sizeof (id_t), KM_SLEEP);
		if (ddi_copyin((void *)xtransfer.px_o_comp_list, id_buf,
		    xtransfer.px_o_complist_size * sizeof (id_t), mode) != 0) {
			kmem_free(id_buf, xtransfer.px_o_complist_size *
			    sizeof (id_t));
			return (EFAULT);
		}
		if (pool_lock_intr() != 0) {
			kmem_free(id_buf, xtransfer.px_o_complist_size *
			    sizeof (id_t));
			return (EINTR);
		}
		ret = pool_xtransfer(xtransfer.px_o_id_type,
		    xtransfer.px_o_src_id, xtransfer.px_o_tgt_id,
		    xtransfer.px_o_complist_size, id_buf);
		pool_unlock();
		kmem_free(id_buf, xtransfer.px_o_complist_size *
		    sizeof (id_t));
		break;
	case POOL_BIND:
		if (ddi_copyin((void *)arg, &bind,
		    sizeof (pool_bind_t), mode) != 0)
			return (EFAULT);
		if (pool_lock_intr() != 0)
			return (EINTR);
		ret = pool_bind(bind.pb_o_pool_id, bind.pb_o_id_type,
		    bind.pb_o_id);
		pool_unlock();
		break;
	case POOL_BINDQ:
		if (ddi_copyin((void *)arg, &bindq,
		    sizeof (pool_bindq_t), mode) != 0) {
			return (EFAULT);
		}
		if (pool_lock_intr() != 0)
			return (EINTR);
		if ((ret = pool_query_binding(bindq.pb_o_id_type,
		    bindq.pb_o_id, &bindq.pb_i_id)) == 0 &&
		    ddi_copyout(&bindq, (void *)arg,
		    sizeof (pool_bindq_t), mode) != 0)
			ret = EFAULT;
		pool_unlock();
		break;
	case POOL_PROPGET:
		switch (model) {
#ifdef _MULTI_DATAMODEL
		case DDI_MODEL_ILP32:
			if (ddi_copyin((void *)arg, &propget32,
			    sizeof (pool_propget32_t), mode) != 0)
				return (EFAULT);
			propget.pp_o_id = propget32.pp_o_id;
			propget.pp_o_id_type = propget32.pp_o_id_type;
			propget.pp_o_id_subtype = propget32.pp_o_id_subtype;
			propget.pp_o_prop_name =
			    (char *)(uintptr_t)propget32.pp_o_prop_name;
			propget.pp_o_prop_name_size =
			    propget32.pp_o_prop_name_size;
			propget.pp_i_buf =
			    (char *)(uintptr_t)propget32.pp_i_buf;
			propget.pp_i_bufsize = propget32.pp_i_bufsize;
			break;
#endif	/* _MULTI_DATAMODEL */
		default:
		case DDI_MODEL_NONE:
			if (ddi_copyin((void *)arg, &propget,
			    sizeof (pool_propget_t), mode) != 0)
				return (EFAULT);
		}
		if (propget.pp_o_prop_name_size + 1 > POOL_PROPNAME_SIZE)
			return (EINVAL);
		prop_name = kmem_alloc(propget.pp_o_prop_name_size + 1,
		    KM_SLEEP);
		if (ddi_copyin(propget.pp_o_prop_name, prop_name,
		    propget.pp_o_prop_name_size + 1, mode) != 0) {
			kmem_free(prop_name, propget.pp_o_prop_name_size + 1);
			return (EFAULT);
		}
		list = NULL;
		if (pool_lock_intr() != 0) {
			kmem_free(prop_name, propget.pp_o_prop_name_size + 1);
			return (EINTR);
		}
		ret = pool_propget(prop_name, propget.pp_o_id_type,
		    propget.pp_o_id_subtype, propget.pp_o_id, &list);
		pool_unlock();
		kmem_free(prop_name, propget.pp_o_prop_name_size + 1);
		if (ret != 0)
			return (ret);
		ret = nvlist_pack(list, &kbuf, &kbufsz, NV_ENCODE_NATIVE, 0);
		if (ret != 0) {
			nvlist_free(list);
			return (ret);
		}
		switch (model) {
#ifdef	_MULTI_DATAMODEL
		case DDI_MODEL_ILP32:
			propget32.pp_i_bufsize = kbufsz;
			if (ddi_copyout((caddr_t)&propget32, (void *)arg,
			    sizeof (pool_propget32_t), mode) != 0)
				ret = EFAULT;
			break;
#endif	/* _MULTI_DATAMODEL */
		default:
		case DDI_MODEL_NONE:
			if (ddi_copyout(&propget, (void *)arg,
			    sizeof (pool_propget_t), mode) != 0)
				ret = EFAULT;
		}
		if (ret == 0) {
			if (propget.pp_i_buf == NULL) {
				ret = 0;
			} else if (propget.pp_i_bufsize >= kbufsz) {
				if (ddi_copyout(kbuf, propget.pp_i_buf,
				    kbufsz, mode) != 0)
					ret = EFAULT;
			} else {
				ret = ENOMEM;
			}
		}
		kmem_free(kbuf, kbufsz);
		nvlist_free(list);
		break;
	case POOL_PROPPUT:
		switch (model) {
#ifdef _MULTI_DATAMODEL
		case DDI_MODEL_ILP32:
			if (ddi_copyin((void *)arg, &propput32,
			    sizeof (pool_propput32_t), mode) != 0)
				return (EFAULT);
			propput.pp_o_id_type = propput32.pp_o_id_type;
			propput.pp_o_id_sub_type = propput32.pp_o_id_sub_type;
			propput.pp_o_id = propput32.pp_o_id;
			propput.pp_o_bufsize = propput32.pp_o_bufsize;
			propput.pp_o_buf =
			    (char *)(uintptr_t)propput32.pp_o_buf;
			break;
#endif	/* _MULTI_DATAMODEL */
		default:
		case DDI_MODEL_NONE:
			if (ddi_copyin((void *)arg, &propput,
			    sizeof (pool_propput_t), mode) != 0)
				return (EFAULT);
		}
		if (propput.pp_o_bufsize > POOL_PROPBUF_SIZE)
			return (EINVAL);
		listbuf = kmem_alloc(propput.pp_o_bufsize, KM_SLEEP);
		if (ddi_copyin(propput.pp_o_buf, listbuf,
		    propput.pp_o_bufsize, mode) != 0) {
			kmem_free(listbuf, propput.pp_o_bufsize);
			return (EFAULT);
		}
		if (nvlist_unpack(listbuf, propput.pp_o_bufsize,
		    &list, KM_SLEEP) != 0) {
			kmem_free(listbuf, propput.pp_o_bufsize);
			return (EFAULT);
		}
		if (pool_lock_intr() != 0) {
			nvlist_free(list);
			kmem_free(listbuf, propput.pp_o_bufsize);
			return (EINTR);
		}
		/*
		 * Extract the nvpair from the list. The list may
		 * contain multiple properties.
		 */
		for (pair = nvlist_next_nvpair(list, NULL); pair != NULL;
		    pair = nvlist_next_nvpair(list, pair)) {
			if ((ret = pool_propput(propput.pp_o_id_type,
			    propput.pp_o_id_sub_type,
			    propput.pp_o_id, pair)) != 0)
				break;
		}
		pool_unlock();
		nvlist_free(list);
		kmem_free(listbuf, propput.pp_o_bufsize);
		break;
	case POOL_PROPRM:
		switch (model) {
#ifdef _MULTI_DATAMODEL
		case DDI_MODEL_ILP32:
			if (ddi_copyin((void *)arg, &proprm32,
			    sizeof (pool_proprm32_t), mode) != 0)
				return (EFAULT);
			proprm.pp_o_id_type = proprm32.pp_o_id_type;
			proprm.pp_o_id_sub_type = proprm32.pp_o_id_sub_type;
			proprm.pp_o_id = proprm32.pp_o_id;
			proprm.pp_o_prop_name_size =
			    proprm32.pp_o_prop_name_size;
			proprm.pp_o_prop_name =
			    (void *)(uintptr_t)proprm32.pp_o_prop_name;
			break;
#endif	/* _MULTI_DATAMODEL */
		default:
		case DDI_MODEL_NONE:
			if (ddi_copyin((void *)arg, &proprm,
			    sizeof (pool_proprm_t), mode) != 0)
				return (EFAULT);
		}
		if (proprm.pp_o_prop_name_size + 1 > POOL_PROPNAME_SIZE)
			return (EINVAL);
		prop_name = kmem_alloc(proprm.pp_o_prop_name_size + 1,
		    KM_SLEEP);
		if (ddi_copyin(proprm.pp_o_prop_name, prop_name,
		    proprm.pp_o_prop_name_size + 1, mode) != 0) {
			kmem_free(prop_name, proprm.pp_o_prop_name_size + 1);
			return (EFAULT);
		}
		if (pool_lock_intr() != 0) {
			kmem_free(prop_name, proprm.pp_o_prop_name_size + 1);
			return (EINTR);
		}
		ret = pool_proprm(proprm.pp_o_id_type,
		    proprm.pp_o_id_sub_type, proprm.pp_o_id, prop_name);
		pool_unlock();
		kmem_free(prop_name, proprm.pp_o_prop_name_size + 1);
		break;
	case POOL_COMMIT:
		if (pool_lock_intr() != 0)
			return (EINTR);
		ret = pool_commit((int)arg);
		pool_unlock();
		break;
	default:
		return (EINVAL);
	}
	return (ret);
}

static struct cb_ops pool_cb_ops = {
	pool_open,		/* open */
	pool_close,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	pool_ioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	nodev,			/* cb_prop_op */
	(struct streamtab *)0,	/* streamtab */
	D_NEW | D_MP		/* driver compatibility flags */
};

static struct dev_ops pool_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt */
	pool_info,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	pool_attach,		/* attach */
	pool_detach,		/* detach */
	nodev,			/* reset */
	&pool_cb_ops,		/* cb_ops */
	(struct bus_ops *)NULL,	/* bus_ops */
	nulldev,		/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

/*
 * Module linkage information for the kernel
 */
static struct modldrv modldrv = {
	&mod_driverops,		/* this one is a pseudo driver */
	"pool driver",
	&pool_ops
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
