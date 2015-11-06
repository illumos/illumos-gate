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
 * Copyright 2015 Nexenta Systems, Inc. All rights reserved.
 */


/*
 * kernel statistics driver
 */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/file.h>
#include <sys/cmn_err.h>
#include <sys/t_lock.h>
#include <sys/proc.h>
#include <sys/fcntl.h>
#include <sys/uio.h>
#include <sys/kmem.h>
#include <sys/cred.h>
#include <sys/mman.h>
#include <sys/errno.h>
#include <sys/ioccom.h>
#include <sys/cpuvar.h>
#include <sys/stat.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/kobj.h>
#include <sys/kstat.h>
#include <sys/atomic.h>
#include <sys/policy.h>
#include <sys/zone.h>

static dev_info_t *kstat_devi;

static int
read_kstat_data(int *rvalp, void *user_ksp, int flag)
{
	kstat_t user_kstat, *ksp;
#ifdef _MULTI_DATAMODEL
	kstat32_t user_kstat32;
#endif
	void *kbuf = NULL;
	size_t kbufsize, ubufsize, copysize;
	int error = 0;
	uint_t model;

	switch (model = ddi_model_convert_from(flag & FMODELS)) {
#ifdef _MULTI_DATAMODEL
	case DDI_MODEL_ILP32:
		if (copyin(user_ksp, &user_kstat32, sizeof (kstat32_t)) != 0)
			return (EFAULT);
		user_kstat.ks_kid = user_kstat32.ks_kid;
		user_kstat.ks_data = (void *)(uintptr_t)user_kstat32.ks_data;
		user_kstat.ks_data_size = (size_t)user_kstat32.ks_data_size;
		break;
#endif
	default:
	case DDI_MODEL_NONE:
		if (copyin(user_ksp, &user_kstat, sizeof (kstat_t)) != 0)
			return (EFAULT);
	}

	ksp = kstat_hold_bykid(user_kstat.ks_kid, getzoneid());
	if (ksp == NULL) {
		/*
		 * There is no kstat with the specified KID
		 */
		return (ENXIO);
	}
	if (ksp->ks_flags & KSTAT_FLAG_INVALID) {
		/*
		 * The kstat exists, but is momentarily in some
		 * indeterminate state (e.g. the data section is not
		 * yet initialized).  Try again in a few milliseconds.
		 */
		kstat_rele(ksp);
		return (EAGAIN);
	}

	/*
	 * If it's a fixed-size kstat, allocate the buffer now, so we
	 * don't have to do it under the kstat's data lock.  (If it's a
	 * var-size kstat or one with long strings, we don't know the size
	 * until after the update routine is called, so we can't do this
	 * optimization.)
	 * The allocator relies on this behavior to prevent recursive
	 * mutex_enter in its (fixed-size) kstat update routine.
	 * It's a zalloc to prevent unintentional exposure of random
	 * juicy morsels of (old) kernel data.
	 */
	if (!(ksp->ks_flags & (KSTAT_FLAG_VAR_SIZE | KSTAT_FLAG_LONGSTRINGS))) {
		kbufsize = ksp->ks_data_size;
		kbuf = kmem_zalloc(kbufsize + 1, KM_NOSLEEP);
		if (kbuf == NULL) {
			kstat_rele(ksp);
			return (EAGAIN);
		}
	}
	KSTAT_ENTER(ksp);
	if ((error = KSTAT_UPDATE(ksp, KSTAT_READ)) != 0) {
		KSTAT_EXIT(ksp);
		kstat_rele(ksp);
		if (kbuf != NULL)
			kmem_free(kbuf, kbufsize + 1);
		return (error);
	}

	kbufsize = ksp->ks_data_size;
	ubufsize = user_kstat.ks_data_size;

	if (ubufsize < kbufsize) {
		error = ENOMEM;
	} else {
		if (kbuf == NULL)
			kbuf = kmem_zalloc(kbufsize + 1, KM_NOSLEEP);
		if (kbuf == NULL) {
			error = EAGAIN;
		} else {
			error = KSTAT_SNAPSHOT(ksp, kbuf, KSTAT_READ);
		}
	}

	/*
	 * The following info must be returned to user level,
	 * even if the the update or snapshot failed.  This allows
	 * kstat readers to get a handle on variable-size kstats,
	 * detect dormant kstats, etc.
	 */
	user_kstat.ks_ndata	= ksp->ks_ndata;
	user_kstat.ks_data_size	= kbufsize;
	user_kstat.ks_flags	= ksp->ks_flags;
	user_kstat.ks_snaptime	= ksp->ks_snaptime;

	*rvalp = kstat_chain_id;
	KSTAT_EXIT(ksp);
	kstat_rele(ksp);

	if (kbuf == NULL)
		goto out;

	/*
	 * Copy the buffer containing the kstat back to userland.
	 */
	copysize = kbufsize;

	switch (model) {
	int i;
#ifdef _MULTI_DATAMODEL
	kstat32_t *k32;
	kstat_t *k;

	case DDI_MODEL_ILP32:

		if (ksp->ks_type == KSTAT_TYPE_NAMED) {
			kstat_named_t *kn = kbuf;
			char *strbuf = (char *)((kstat_named_t *)kn +
			    ksp->ks_ndata);

			for (i = 0; i < user_kstat.ks_ndata; kn++, i++)
				switch (kn->data_type) {
				/*
				 * Named statistics have fields of type 'long'.
				 * For a 32-bit application looking at a 64-bit
				 * kernel, forcibly truncate these 64-bit
				 * quantities to 32-bit values.
				 */
				case KSTAT_DATA_LONG:
					kn->value.i32 = (int32_t)kn->value.l;
					kn->data_type = KSTAT_DATA_INT32;
					break;
				case KSTAT_DATA_ULONG:
					kn->value.ui32 = (uint32_t)kn->value.ul;
					kn->data_type = KSTAT_DATA_UINT32;
					break;
				/*
				 * Long strings must be massaged before being
				 * copied out to userland.  Do that here.
				 */
				case KSTAT_DATA_STRING:
					if (KSTAT_NAMED_STR_PTR(kn) == NULL)
						break;
					/*
					 * If the string lies outside of kbuf
					 * copy it there and update the pointer.
					 */
					if (KSTAT_NAMED_STR_PTR(kn) <
					    (char *)kbuf ||
					    KSTAT_NAMED_STR_PTR(kn) +
					    KSTAT_NAMED_STR_BUFLEN(kn) >
					    (char *)kbuf + kbufsize + 1) {
						bcopy(KSTAT_NAMED_STR_PTR(kn),
						    strbuf,
						    KSTAT_NAMED_STR_BUFLEN(kn));

						KSTAT_NAMED_STR_PTR(kn) =
						    strbuf;
						strbuf +=
						    KSTAT_NAMED_STR_BUFLEN(kn);
						ASSERT(strbuf <=
						    (char *)kbuf +
						    kbufsize + 1);
					}
					/*
					 * The offsets within the buffers are
					 * the same, so add the offset to the
					 * beginning of the new buffer to fix
					 * the pointer.
					 */
					KSTAT_NAMED_STR_PTR(kn) =
					    (char *)user_kstat.ks_data +
					    (KSTAT_NAMED_STR_PTR(kn) -
					    (char *)kbuf);
					/*
					 * Make sure the string pointer lies
					 * within the allocated buffer.
					 */
					ASSERT(KSTAT_NAMED_STR_PTR(kn) +
					    KSTAT_NAMED_STR_BUFLEN(kn) <=
					    ((char *)user_kstat.ks_data +
					    ubufsize));
					ASSERT(KSTAT_NAMED_STR_PTR(kn) >=
					    (char *)((kstat_named_t *)
					    user_kstat.ks_data +
					    user_kstat.ks_ndata));
					/*
					 * Cast 64-bit ptr to 32-bit.
					 */
					kn->value.str.addr.ptr32 =
					    (caddr32_t)(uintptr_t)
					    KSTAT_NAMED_STR_PTR(kn);
					break;
				default:
					break;
				}
		}

		if (user_kstat.ks_kid != 0)
			break;

		/*
		 * This is the special case of the kstat header
		 * list for the entire system.  Reshape the
		 * array in place, then copy it out.
		 */
		k32 = kbuf;
		k = kbuf;
		for (i = 0; i < user_kstat.ks_ndata; k32++, k++, i++) {
			k32->ks_crtime		= k->ks_crtime;
			k32->ks_next		= 0;
			k32->ks_kid		= k->ks_kid;
			(void) strcpy(k32->ks_module, k->ks_module);
			k32->ks_resv		= k->ks_resv;
			k32->ks_instance	= k->ks_instance;
			(void) strcpy(k32->ks_name, k->ks_name);
			k32->ks_type		= k->ks_type;
			(void) strcpy(k32->ks_class, k->ks_class);
			k32->ks_flags		= k->ks_flags;
			k32->ks_data		= 0;
			k32->ks_ndata		= k->ks_ndata;
			if (k->ks_data_size > UINT32_MAX) {
				error = EOVERFLOW;
				break;
			}
			k32->ks_data_size = (size32_t)k->ks_data_size;
			k32->ks_snaptime	= k->ks_snaptime;
		}

		/*
		 * XXX	In this case we copy less data than is
		 *	claimed in the header.
		 */
		copysize = user_kstat.ks_ndata * sizeof (kstat32_t);
		break;
#endif	/* _MULTI_DATAMODEL */
	default:
	case DDI_MODEL_NONE:
		if (ksp->ks_type == KSTAT_TYPE_NAMED) {
			kstat_named_t *kn = kbuf;
			char *strbuf = (char *)((kstat_named_t *)kn +
			    ksp->ks_ndata);

			for (i = 0; i < user_kstat.ks_ndata; kn++, i++)
				switch (kn->data_type) {
#ifdef _LP64
				case KSTAT_DATA_LONG:
					kn->data_type =
					    KSTAT_DATA_INT64;
					break;
				case KSTAT_DATA_ULONG:
					kn->data_type =
					    KSTAT_DATA_UINT64;
					break;
#endif	/* _LP64 */
				case KSTAT_DATA_STRING:
					if (KSTAT_NAMED_STR_PTR(kn) == NULL)
						break;
					/*
					 * If the string lies outside of kbuf
					 * copy it there and update the pointer.
					 */
					if (KSTAT_NAMED_STR_PTR(kn) <
					    (char *)kbuf ||
					    KSTAT_NAMED_STR_PTR(kn) +
					    KSTAT_NAMED_STR_BUFLEN(kn) >
					    (char *)kbuf + kbufsize + 1) {
						bcopy(KSTAT_NAMED_STR_PTR(kn),
						    strbuf,
						    KSTAT_NAMED_STR_BUFLEN(kn));

						KSTAT_NAMED_STR_PTR(kn) =
						    strbuf;
						strbuf +=
						    KSTAT_NAMED_STR_BUFLEN(kn);
						ASSERT(strbuf <=
						    (char *)kbuf +
						    kbufsize + 1);
					}

					KSTAT_NAMED_STR_PTR(kn) =
					    (char *)user_kstat.ks_data +
					    (KSTAT_NAMED_STR_PTR(kn) -
					    (char *)kbuf);
					ASSERT(KSTAT_NAMED_STR_PTR(kn) +
					    KSTAT_NAMED_STR_BUFLEN(kn) <=
					    ((char *)user_kstat.ks_data +
					    ubufsize));
					ASSERT(KSTAT_NAMED_STR_PTR(kn) >=
					    (char *)((kstat_named_t *)
					    user_kstat.ks_data +
					    user_kstat.ks_ndata));
					break;
				default:
					break;
				}
		}
		break;
	}

	if (error == 0 &&
	    copyout(kbuf, user_kstat.ks_data, copysize))
		error = EFAULT;
	kmem_free(kbuf, kbufsize + 1);

out:
	/*
	 * We have modified the ks_ndata, ks_data_size, ks_flags, and
	 * ks_snaptime fields of the user kstat; now copy it back to userland.
	 */
	switch (model) {
#ifdef _MULTI_DATAMODEL
	case DDI_MODEL_ILP32:
		if (kbufsize > UINT32_MAX) {
			error = EOVERFLOW;
			break;
		}
		user_kstat32.ks_ndata		= user_kstat.ks_ndata;
		user_kstat32.ks_data_size	= (size32_t)kbufsize;
		user_kstat32.ks_flags		= user_kstat.ks_flags;
		user_kstat32.ks_snaptime	= user_kstat.ks_snaptime;
		if (copyout(&user_kstat32, user_ksp, sizeof (kstat32_t)) &&
		    error == 0)
			error = EFAULT;
		break;
#endif
	default:
	case DDI_MODEL_NONE:
		if (copyout(&user_kstat, user_ksp, sizeof (kstat_t)) &&
		    error == 0)
			error = EFAULT;
		break;
	}

	return (error);
}

static int
write_kstat_data(int *rvalp, void *user_ksp, int flag, cred_t *cred)
{
	kstat_t user_kstat, *ksp;
	void *buf = NULL;
	size_t bufsize;
	int error = 0;

	if (secpolicy_sys_config(cred, B_FALSE) != 0)
		return (EPERM);

	switch (ddi_model_convert_from(flag & FMODELS)) {
#ifdef _MULTI_DATAMODEL
		kstat32_t user_kstat32;

	case DDI_MODEL_ILP32:
		if (copyin(user_ksp, &user_kstat32, sizeof (kstat32_t)))
			return (EFAULT);
		/*
		 * These are the only fields we actually look at.
		 */
		user_kstat.ks_kid = user_kstat32.ks_kid;
		user_kstat.ks_data = (void *)(uintptr_t)user_kstat32.ks_data;
		user_kstat.ks_data_size = (size_t)user_kstat32.ks_data_size;
		user_kstat.ks_ndata = user_kstat32.ks_ndata;
		break;
#endif
	default:
	case DDI_MODEL_NONE:
		if (copyin(user_ksp, &user_kstat, sizeof (kstat_t)))
			return (EFAULT);
	}

	bufsize = user_kstat.ks_data_size;
	buf = kmem_alloc(bufsize + 1, KM_NOSLEEP);
	if (buf == NULL)
		return (EAGAIN);

	if (copyin(user_kstat.ks_data, buf, bufsize)) {
		kmem_free(buf, bufsize + 1);
		return (EFAULT);
	}

	ksp = kstat_hold_bykid(user_kstat.ks_kid, getzoneid());
	if (ksp == NULL) {
		kmem_free(buf, bufsize + 1);
		return (ENXIO);
	}
	if (ksp->ks_flags & KSTAT_FLAG_INVALID) {
		kstat_rele(ksp);
		kmem_free(buf, bufsize + 1);
		return (EAGAIN);
	}
	if (!(ksp->ks_flags & KSTAT_FLAG_WRITABLE)) {
		kstat_rele(ksp);
		kmem_free(buf, bufsize + 1);
		return (EACCES);
	}

	/*
	 * With KSTAT_FLAG_VAR_SIZE, one must call the kstat's update callback
	 * routine to ensure ks_data_size is up to date.
	 * In this case it makes sense to do it anyhow, as it will be shortly
	 * followed by a KSTAT_SNAPSHOT().
	 */
	KSTAT_ENTER(ksp);
	error = KSTAT_UPDATE(ksp, KSTAT_READ);
	if (error || user_kstat.ks_data_size != ksp->ks_data_size ||
	    user_kstat.ks_ndata != ksp->ks_ndata) {
		KSTAT_EXIT(ksp);
		kstat_rele(ksp);
		kmem_free(buf, bufsize + 1);
		return (error ? error : EINVAL);
	}

	/*
	 * We have to ensure that we don't accidentally change the type of
	 * existing kstat_named statistics when writing over them.
	 * Since read_kstat_data() modifies some of the types on their way
	 * out, we need to be sure to handle these types seperately.
	 */
	if (ksp->ks_type == KSTAT_TYPE_NAMED) {
		void *kbuf;
		kstat_named_t *kold;
		kstat_named_t *knew = buf;
		int i;

#ifdef	_MULTI_DATAMODEL
		int model = ddi_model_convert_from(flag & FMODELS);
#endif

		/*
		 * Since ksp->ks_data may be NULL, we need to take a snapshot
		 * of the published data to look at the types.
		 */
		kbuf = kmem_alloc(bufsize + 1, KM_NOSLEEP);
		if (kbuf == NULL) {
			KSTAT_EXIT(ksp);
			kstat_rele(ksp);
			kmem_free(buf, bufsize + 1);
			return (EAGAIN);
		}
		error = KSTAT_SNAPSHOT(ksp, kbuf, KSTAT_READ);
		if (error) {
			KSTAT_EXIT(ksp);
			kstat_rele(ksp);
			kmem_free(kbuf, bufsize + 1);
			kmem_free(buf, bufsize + 1);
			return (error);
		}
		kold = kbuf;

		/*
		 * read_kstat_data() changes the types of
		 * KSTAT_DATA_LONG / KSTAT_DATA_ULONG, so we need to
		 * make sure that these (modified) types are considered
		 * valid.
		 */
		for (i = 0; i < ksp->ks_ndata; i++, kold++, knew++) {
			switch (kold->data_type) {
#ifdef	_MULTI_DATAMODEL
			case KSTAT_DATA_LONG:
				switch (model) {
				case DDI_MODEL_ILP32:
					if (knew->data_type ==
					    KSTAT_DATA_INT32) {
						knew->value.l =
						    (long)knew->value.i32;
						knew->data_type =
						    KSTAT_DATA_LONG;
					}
					break;
				default:
				case DDI_MODEL_NONE:
#ifdef _LP64
					if (knew->data_type ==
					    KSTAT_DATA_INT64) {
						knew->value.l =
						    (long)knew->value.i64;
						knew->data_type =
						    KSTAT_DATA_LONG;
					}
#endif /* _LP64 */
					break;
				}
				break;
			case KSTAT_DATA_ULONG:
				switch (model) {
				case DDI_MODEL_ILP32:
					if (knew->data_type ==
					    KSTAT_DATA_UINT32) {
						knew->value.ul =
						    (ulong_t)knew->value.ui32;
						knew->data_type =
						    KSTAT_DATA_ULONG;
					}
					break;
				default:
				case DDI_MODEL_NONE:
#ifdef _LP64
					if (knew->data_type ==
					    KSTAT_DATA_UINT64) {
						knew->value.ul =
						    (ulong_t)knew->value.ui64;
						knew->data_type =
						    KSTAT_DATA_ULONG;
					}
#endif /* _LP64 */
					break;
				}
				break;
#endif /* _MULTI_DATAMODEL */
			case KSTAT_DATA_STRING:
				if (knew->data_type != KSTAT_DATA_STRING) {
					KSTAT_EXIT(ksp);
					kstat_rele(ksp);
					kmem_free(kbuf, bufsize + 1);
					kmem_free(buf, bufsize + 1);
					return (EINVAL);
				}

#ifdef _MULTI_DATAMODEL
				if (model == DDI_MODEL_ILP32)
					KSTAT_NAMED_STR_PTR(knew) =
					    (char *)(uintptr_t)
						knew->value.str.addr.ptr32;
#endif
				/*
				 * Nothing special for NULL
				 */
				if (KSTAT_NAMED_STR_PTR(knew) == NULL)
					break;

				/*
				 * Check to see that the pointers all point
				 * to within the buffer and after the array
				 * of kstat_named_t's.
				 */
				if (KSTAT_NAMED_STR_PTR(knew) <
				    (char *)
				    ((kstat_named_t *)user_kstat.ks_data +
				    ksp->ks_ndata)) {
					KSTAT_EXIT(ksp);
					kstat_rele(ksp);
					kmem_free(kbuf, bufsize + 1);
					kmem_free(buf, bufsize + 1);
					return (EINVAL);
				}
				if (KSTAT_NAMED_STR_PTR(knew) +
				    KSTAT_NAMED_STR_BUFLEN(knew) >
				    ((char *)user_kstat.ks_data +
				    ksp->ks_data_size)) {
					KSTAT_EXIT(ksp);
					kstat_rele(ksp);
					kmem_free(kbuf, bufsize + 1);
					kmem_free(buf, bufsize + 1);
					return (EINVAL);
				}

				/*
				 * Update the pointers within the buffer
				 */
				KSTAT_NAMED_STR_PTR(knew) =
				    (char *)buf +
				    (KSTAT_NAMED_STR_PTR(knew) -
				    (char *)user_kstat.ks_data);
				break;
			default:
				break;
			}
		}

		kold = kbuf;
		knew = buf;

		/*
		 * Now make sure the types are what we expected them to be.
		 */
		for (i = 0; i < ksp->ks_ndata; i++, kold++, knew++)
			if (kold->data_type != knew->data_type) {
				KSTAT_EXIT(ksp);
				kstat_rele(ksp);
				kmem_free(kbuf, bufsize + 1);
				kmem_free(buf, bufsize + 1);
				return (EINVAL);
			}

		kmem_free(kbuf, bufsize + 1);
	}

	error = KSTAT_SNAPSHOT(ksp, buf, KSTAT_WRITE);
	if (!error)
		error = KSTAT_UPDATE(ksp, KSTAT_WRITE);
	*rvalp = kstat_chain_id;
	KSTAT_EXIT(ksp);
	kstat_rele(ksp);
	kmem_free(buf, bufsize + 1);
	return (error);
}

/*ARGSUSED*/
static int
kstat_ioctl(dev_t dev, int cmd, intptr_t data, int flag, cred_t *cr, int *rvalp)
{
	int rc = 0;

	switch (cmd) {

	case KSTAT_IOC_CHAIN_ID:
		*rvalp = kstat_chain_id;
		break;

	case KSTAT_IOC_READ:
		rc = read_kstat_data(rvalp, (void *)data, flag);
		break;

	case KSTAT_IOC_WRITE:
		rc = write_kstat_data(rvalp, (void *)data, flag, cr);
		break;

	default:
		/* invalid request */
		rc = EINVAL;
	}
	return (rc);
}

/* ARGSUSED */
static int
kstat_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
	void **result)
{
	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = kstat_devi;
		return (DDI_SUCCESS);
	case DDI_INFO_DEVT2INSTANCE:
		*result = NULL;
		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}

static int
kstat_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	if (ddi_create_minor_node(devi, "kstat", S_IFCHR,
	    0, DDI_PSEUDO, NULL) == DDI_FAILURE) {
		ddi_remove_minor_node(devi, NULL);
		return (DDI_FAILURE);
	}
	kstat_devi = devi;
	return (DDI_SUCCESS);
}

static int
kstat_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	ddi_remove_minor_node(devi, NULL);
	return (DDI_SUCCESS);
}

static struct cb_ops kstat_cb_ops = {
	nulldev,		/* open */
	nulldev,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	kstat_ioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* prop_op */
	0,			/* streamtab  */
	D_NEW | D_MP		/* Driver compatibility flag */
};

static struct dev_ops kstat_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	kstat_info,		/* get_dev_info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	kstat_attach,		/* attach */
	kstat_detach,		/* detach */
	nodev,			/* reset */
	&kstat_cb_ops,		/* driver operations */
	(struct bus_ops *)0,	/* no bus operations */
	NULL,			/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops, "kernel statistics driver", &kstat_ops,
};

static struct modlinkage modlinkage = {
	MODREV_1, &modldrv, NULL
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
