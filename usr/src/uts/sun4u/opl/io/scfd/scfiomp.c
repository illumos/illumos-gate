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
 * All Rights Reserved, Copyright (c) FUJITSU LIMITED 2006
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/open.h>
#include <sys/uio.h>
#include <sys/cred.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/scfd/scfparam.h>

#ifdef DEBUG
/*
 * Function list
 */
void	scf_add_scf(scf_state_t *statep);
void	scf_del_scf(scf_state_t *statep);
int	scf_meta_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
	cred_t *cred_p, int *rval_p, int u_mode);
int	scf_inst_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
	cred_t *cred_p, int *rval_p, int u_mode);
void	scf_inst_getstat32(scf_state_t *statep,
	struct fiompstatus_32 *status32_p, char *message_p, int flag);
void	scf_inst_getstat(scf_state_t *statep,
	struct fiompstatus *status_p, char *message_p, int flag);
void	scf_path_stmsg(scf_state_t *statep, char *message_p);

/*
 * External function
 */
extern	void	scf_dscp_stop(uint32_t factor);


/*
 *  Multi path control table add
 */
void
scf_add_scf(scf_state_t *statep)
{
#define	SCF_FUNC_NAME		"scf_add_scf() "
	scf_state_t		**iomp_scf;
	int			alloc_size;

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG1(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": start instance = %d",
		statep->instance);

	alloc_size = (sizeof (scf_state_t *) * (statep->instance + 1));
	if (alloc_size < (sizeof (scf_state_t *) * SCF_MAX_INSTANCE)) {
		alloc_size = (sizeof (scf_state_t *) * SCF_MAX_INSTANCE);
	}
	if ((scf_comtbl.alloc_size < alloc_size) ||
		(scf_comtbl.iomp_scf == 0)) {
		/* IOMP control table re-get */
		iomp_scf = (scf_state_t **)kmem_zalloc((size_t)(alloc_size),
			KM_SLEEP);
		if (scf_comtbl.alloc_size != 0) {
			bcopy(scf_comtbl.iomp_scf, iomp_scf,
				scf_comtbl.alloc_size);
			kmem_free((void *)scf_comtbl.iomp_scf,
				(size_t)scf_comtbl.alloc_size);
		}
		scf_comtbl.iomp_scf = iomp_scf;
		scf_comtbl.alloc_size = alloc_size;
	}
	scf_comtbl.iomp_scf[statep->instance] = statep;
	/* SCF path count up */
	if (scf_comtbl.path_num < (statep->instance + 1)) {
		scf_comtbl.path_num = statep->instance + 1;
	}

	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": end");
}

/*
 * Multi path control table delete
 */
void
scf_del_scf(scf_state_t *statep)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_del_scf() "
	int			ii;
	int			path_num = 0;

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG1(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": start instance = %d",
		statep->instance);

	scf_comtbl.iomp_scf[statep->instance] = 0;

	/* SCF path count up */
	for (ii = 0; ii < scf_comtbl.alloc_size / sizeof (scf_state_t *);
		ii++) {
		if (scf_comtbl.iomp_scf[ii]) {
			path_num = scf_comtbl.iomp_scf[ii]->instance + 1;
		}
	}
	scf_comtbl.path_num = path_num;

	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": end");
}


/*
 * Meta management ioctl
 */
/* ARGSUSED */
int
scf_meta_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *cred_p,
	int *rval_p, int u_mode)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_meta_ioctl() "
	int			ret = 0;
	int			all_num;
	int			path_num;

	SCFDBGMSG1(SCF_DBGFLAG_IOMP,
		SCF_FUNC_NAME ": start cmd = 0x%08x", (uint_t)cmd);

	switch ((unsigned int)cmd) {
	case FIOMPNEW:
		SCFDBGMSG(SCF_DBGFLAG_IOMP, "FIOMPNEW proc");

		ret = ENOTTY;
		break;

	case FIOMPENCAP:
		SCFDBGMSG(SCF_DBGFLAG_IOMP, "FIOMPENCAP proc");

		ret = ENOTTY;
		break;

	case FIOMPDEVINFO:
		SCFDBGMSG(SCF_DBGFLAG_IOMP, "FIOMPDEVINFO proc");

		if (u_mode == DDI_MODEL_ILP32) {
			/* DDI_MODEL_ILP32 */
			struct fiomp_devinfo_32 *fiomp_devinfo32_p;

			fiomp_devinfo32_p =
				(struct fiomp_devinfo_32 *)kmem_zalloc
				((size_t)(sizeof (struct fiomp_devinfo_32)),
					KM_SLEEP);

			if (ddi_copyin((void *)arg,
				(void *)fiomp_devinfo32_p,
				sizeof (struct fiomp_devinfo_32), mode) != 0) {
				SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
					"m_ioctl ", 8);
				ret = EFAULT;
				goto END_DEVINFO32;
			}
			if (fiomp_devinfo32_p->inst_no != 0) {
				/* Invalid inst_no */
				SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
					"m_ioctl ", 8);
				ret = EINVAL;
				goto END_DEVINFO32;
			}
			mutex_enter(&scf_comtbl.attach_mutex);
			if (!(scf_comtbl.resource_flag & DID_MUTEX_ALL)) {
				/* Not attach device */
				path_num = 0;
			} else {
				/* Is attach device */
				mutex_enter(&scf_comtbl.all_mutex);

				path_num = scf_comtbl.path_num;

				mutex_exit(&scf_comtbl.all_mutex);
			}
			mutex_exit(&scf_comtbl.attach_mutex);
			/* Set output information */
			strcpy(fiomp_devinfo32_p->real_name, SCF_REAL_NAME);
			strcpy(fiomp_devinfo32_p->user_path, SCF_USER_PATH);
			fiomp_devinfo32_p->path_num = path_num;
			fiomp_devinfo32_p->mpmode = FIOMP_FALSE;
			fiomp_devinfo32_p->autopath = FIOMP_TRUE;
			fiomp_devinfo32_p->block = FIOMP_TRUE;
			fiomp_devinfo32_p->needsync = FIOMP_FALSE;
			if (ddi_copyout((void *)fiomp_devinfo32_p,
				(void *)arg, sizeof (struct fiomp_devinfo_32),
				mode) != 0) {
				SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
					"m_ioctl ", 8);
				ret = EFAULT;
			}

/*
 * END_DEVINFO32
 */
	END_DEVINFO32:

			if (fiomp_devinfo32_p) {
			kmem_free((void *)fiomp_devinfo32_p,
				(size_t)(sizeof (struct fiomp_devinfo_32)));
			}
		} else {
			/* DDI_MODEL_NONE */
			struct fiomp_devinfo *fiomp_devinfo_p;

			fiomp_devinfo_p =
				(struct fiomp_devinfo *)kmem_zalloc
				((size_t)(sizeof (struct fiomp_devinfo)),
					KM_SLEEP);

			if (ddi_copyin((void *)arg, (void *)fiomp_devinfo_p,
				sizeof (struct fiomp_devinfo), mode) != 0) {
				SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
					"m_ioctl ", 8);
				ret = EFAULT;
				goto END_DEVINFO;
			}
			if (fiomp_devinfo_p->inst_no != 0) {
				/* Invalid inst_no */
				SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
					"m_ioctl ", 8);
				ret = EINVAL;
				goto END_DEVINFO;
			}
			mutex_enter(&scf_comtbl.attach_mutex);
			if (!(scf_comtbl.resource_flag & DID_MUTEX_ALL)) {
				/* Not attach device */
				path_num = 0;
			} else {
				/* Is attach device */
				mutex_enter(&scf_comtbl.all_mutex);

				path_num = scf_comtbl.path_num;

				mutex_exit(&scf_comtbl.all_mutex);
			}
			mutex_exit(&scf_comtbl.attach_mutex);
			/* Set output information */
			strcpy(fiomp_devinfo_p->real_name,
				SCF_REAL_NAME);
			strcpy(fiomp_devinfo_p->user_path,
				SCF_USER_PATH);
			fiomp_devinfo_p->path_num = path_num;
			fiomp_devinfo_p->mpmode = FIOMP_FALSE;
			fiomp_devinfo_p->autopath = FIOMP_TRUE;
			fiomp_devinfo_p->block = FIOMP_TRUE;
			fiomp_devinfo_p->needsync = FIOMP_FALSE;
			if (ddi_copyout((void *)fiomp_devinfo_p,
				(void *)arg, sizeof (struct fiomp_devinfo),
				mode) != 0) {
				SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
					"m_ioctl ", 8);
				ret = EFAULT;
			}

/*
 * END_DEVINFO
 */
	END_DEVINFO:

			if (fiomp_devinfo_p) {
			kmem_free((void *)fiomp_devinfo_p,
				(size_t)(sizeof (struct fiomp_devinfo)));
			}
		}
		break;

	case FIOMPALLINSTNUM:
		SCFDBGMSG(SCF_DBGFLAG_IOMP, "FIOMPALLINSTNUM proc");

		mutex_enter(&scf_comtbl.attach_mutex);
		/* Set output information */
		if (!(scf_comtbl.resource_flag & DID_MUTEX_ALL)) {
			/* Not attach device */
			all_num = 0;
		} else {
			/* Is attach device */
			all_num = 1;
		}
		mutex_exit(&scf_comtbl.attach_mutex);
		if (ddi_copyout((void *)&all_num, (void *)arg,
			sizeof (int), mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"m_ioctl ", 8);
			ret = EFAULT;
		}
		break;

	case FIOMPALLDEVINFO:
		SCFDBGMSG(SCF_DBGFLAG_IOMP, "FIOMPALLDEVINFO proc");

		if (u_mode == DDI_MODEL_ILP32) {
			/* DDI_MODEL_ILP32 */
			struct fiomp_all_devinfo_32 fiomp_all_devinfo32;
			struct fiomp_devinfo_32 *fiomp_devinfo32_p;

			fiomp_devinfo32_p =
				(struct fiomp_devinfo_32 *)kmem_zalloc
				((size_t)(sizeof (struct fiomp_devinfo_32)),
					KM_SLEEP);

	if (ddi_copyin((void *)arg, (void *)&fiomp_all_devinfo32,
		sizeof (struct fiomp_all_devinfo_32), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "m_ioctl ", 8);
		ret = EFAULT;
		goto END_ALLDEVINFO32;
	}
	if (fiomp_all_devinfo32.num != 1) {
		/* Set 1 in num */
		fiomp_all_devinfo32.num = 1;
	} else {
		if (ddi_copyin((void *)(uintptr_t)fiomp_all_devinfo32.devinfo,
			(void *)fiomp_devinfo32_p,
			sizeof (struct fiomp_devinfo_32),
			mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"m_ioctl ", 8);
			ret = EFAULT;
			goto END_ALLDEVINFO32;
		}
		mutex_enter(&scf_comtbl.attach_mutex);
		if (!(scf_comtbl.resource_flag & DID_MUTEX_ALL)) {
			/* Not attach device */
			path_num = 0;
		} else {
			/* Is attach device */
			mutex_enter(&scf_comtbl.all_mutex);

			path_num = scf_comtbl.path_num;

			mutex_exit(&scf_comtbl.all_mutex);
		}
		mutex_exit(&scf_comtbl.attach_mutex);
		/* Set output information */
		fiomp_devinfo32_p->inst_no = 0;
		strcpy(fiomp_devinfo32_p->real_name, SCF_REAL_NAME);
		strcpy(fiomp_devinfo32_p->user_path, SCF_USER_PATH);
		fiomp_devinfo32_p->path_num = path_num;
		fiomp_devinfo32_p->mpmode = FIOMP_FALSE;
		fiomp_devinfo32_p->autopath = FIOMP_TRUE;
		fiomp_devinfo32_p->block = FIOMP_TRUE;
		fiomp_devinfo32_p->needsync = FIOMP_FALSE;
		if (ddi_copyout((void *)fiomp_devinfo32_p,
			(void *)(uintptr_t)fiomp_all_devinfo32.devinfo,
			sizeof (struct fiomp_devinfo_32), mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"m_ioctl ", 8);
			ret = EFAULT;
			goto END_ALLDEVINFO32;
		}
	}
	if (ddi_copyout((void *)&fiomp_all_devinfo32, (void *)arg,
		sizeof (struct fiomp_all_devinfo_32), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "m_ioctl ", 8);
		ret = EFAULT;
	}

/*
 * END_ALLDEVINFO32
 */
	END_ALLDEVINFO32:

			if (fiomp_devinfo32_p) {
			kmem_free((void *)fiomp_devinfo32_p,
				(size_t)(sizeof (struct fiomp_devinfo_32)));
			}
		} else {
			/* DDI_MODEL_NONE */
			struct fiomp_all_devinfo fiomp_all_devinfo;
			struct fiomp_devinfo *fiomp_devinfo_p;

			fiomp_devinfo_p =
				(struct fiomp_devinfo *)kmem_zalloc
				((size_t)(sizeof (struct fiomp_devinfo)),
					KM_SLEEP);

	if (ddi_copyin((void *)arg, (void *)&fiomp_all_devinfo,
		sizeof (struct fiomp_all_devinfo), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "m_ioctl ", 8);
		ret = EFAULT;
		goto END_ALLDEVINFO;
	}
	if (fiomp_all_devinfo.num != 1) {
		/* Set 1 in num */
		fiomp_all_devinfo.num = 1;
	} else {
		if (ddi_copyin((void *)fiomp_all_devinfo.devinfo,
			(void *)fiomp_devinfo_p,
			sizeof (struct fiomp_devinfo), mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"m_ioctl ", 8);
			ret = EFAULT;
			goto END_ALLDEVINFO;
		}
		mutex_enter(&scf_comtbl.attach_mutex);
		if (!(scf_comtbl.resource_flag & DID_MUTEX_ALL)) {
			/* Not attach device */
			path_num = 0;
		} else {
			/* Is attach device */
			mutex_enter(&scf_comtbl.all_mutex);

			path_num = scf_comtbl.path_num;

			mutex_exit(&scf_comtbl.all_mutex);
		}
		mutex_exit(&scf_comtbl.attach_mutex);
		/* Set output information */
		fiomp_devinfo_p->inst_no = 0;
		strcpy(fiomp_devinfo_p->real_name, SCF_REAL_NAME);
		strcpy(fiomp_devinfo_p->user_path, SCF_USER_PATH);
		fiomp_devinfo_p->path_num = path_num;
		fiomp_devinfo_p->mpmode = FIOMP_FALSE;
		fiomp_devinfo_p->autopath = FIOMP_TRUE;
		fiomp_devinfo_p->block = FIOMP_TRUE;
		fiomp_devinfo_p->needsync = FIOMP_FALSE;
		if (ddi_copyout((void *)fiomp_devinfo_p,
			(void *)fiomp_all_devinfo.devinfo,
			sizeof (struct fiomp_devinfo), mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"m_ioctl ", 8);
			ret = EFAULT;
			goto END_ALLDEVINFO;
		}
	}
	if (ddi_copyout((void *)&fiomp_all_devinfo, (void *)arg,
		sizeof (struct fiomp_all_devinfo), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "m_ioctl ", 8);
		ret = EFAULT;
	}

/*
 * END_ALLDEVINFO
 */
	END_ALLDEVINFO:

			if (fiomp_devinfo_p) {
			kmem_free((void *)fiomp_devinfo_p,
				(size_t)(sizeof (struct fiomp_devinfo)));
			}
		}
		break;

	case FIOMPGETEVENT:
		SCFDBGMSG(SCF_DBGFLAG_IOMP, "FIOMPGETEVENT proc");

		ret = ENOTTY;
		break;

	default:
		/* undefined */
		SCFDBGMSG(SCF_DBGFLAG_IOMP, "undefined ioctl command");
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "m_ioctl ", 8);
		ret = ENOTTY;
	}

/*
 * END_meta_ioctl
 */
	END_meta_ioctl:

	SCFDBGMSG1(SCF_DBGFLAG_IOMP, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}

/*
 * Instans management ioctl
 */
/* ARGSUSED */
int
scf_inst_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *cred_p,
	int *rval_p, int u_mode)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_inst_ioctl() "
	scf_state_t		*statep;
	scf_state_t		*wkstatep;
	struct scf_cmd		scf_cmd;
	int			ret = 0;
	int			all_num;
	int			pathnum;
	int			ii;
	int			jj;
	int			num_cmp_flag = 0;
	int			alloc_num;

	SCFDBGMSG1(SCF_DBGFLAG_IOMP,
		SCF_FUNC_NAME ": start cmd = 0x%08x", (uint_t)cmd);

	mutex_enter(&scf_comtbl.attach_mutex);
	if (!(scf_comtbl.resource_flag & DID_MUTEX_ALL)) {
		/* Not attach device */
		mutex_exit(&scf_comtbl.attach_mutex);
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "i_ioctl ", 8);
		ret = ENXIO;
		goto END_inst_ioctl;
	}
	mutex_exit(&scf_comtbl.attach_mutex);

	switch ((unsigned int)cmd) {
	case FIOMPMAXPATHNUM:
		SCFDBGMSG(SCF_DBGFLAG_IOMP, "FIOMPMAXPATHNUM proc");

		mutex_enter(&scf_comtbl.all_mutex);
		/* Set output information */
		all_num = scf_comtbl.path_num;
		mutex_exit(&scf_comtbl.all_mutex);
		if (ddi_copyout((void *)&all_num, (void *)arg,
			sizeof (int), mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"i_ioctl ", 8);
			ret = EFAULT;
		}
		break;

	case FIOMPSETPROP:
		SCFDBGMSG(SCF_DBGFLAG_IOMP, "FIOMPSETPROP proc");

		ret = ENOTTY;
		break;

	case FIOMPGETPROP:
		SCFDBGMSG(SCF_DBGFLAG_IOMP, "FIOMPGETPROP proc");

		if (u_mode == DDI_MODEL_ILP32) {
	/* DDI_MODEL_ILP32 */
	struct fiompprop_32 fiompprop32;
	char		*work_name_p = 0;
	char		*iomp_name_p = 0;
	char		*iomp_real_name_p = 0;
	char		*iomp_user_path_p = 0;
	char		*iomp_status_p = 0;
	caddr32_t	*iomp_path_p = 0;
	caddr32_t	*iomp_logical_path_p = 0;
	caddr32_t	*iomp_path_status_p = 0;
	caddr32_t	*iomp_path_block_p = 0;
	char		*iomp_path = 0;
	char		*iomp_logical_path = 0;
	char		*iomp_path_status = 0;
	char		*iomp_path_block = 0;

	if (ddi_copyin((void *)arg, (void *)&fiompprop32,
		sizeof (struct fiompprop_32), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "i_ioctl ", 8);
		ret = EFAULT;
		goto END_inst_ioctl;
	}
	alloc_num = fiompprop32.num;
	iomp_name_p = (char *)kmem_zalloc((size_t)(FIOMP_MAX_STR),
		KM_SLEEP);
	iomp_real_name_p = (char *)kmem_zalloc((size_t)(FIOMP_MAX_STR),
		KM_SLEEP);
	iomp_user_path_p = (char *)kmem_zalloc((size_t)(FIOMP_MAX_STR),
		KM_SLEEP);
	iomp_status_p = (char *)kmem_zalloc((size_t)(FIOMP_MAX_STR),
		KM_SLEEP);
	if (fiompprop32.num != 0) {
		/* buffer allocation */
		work_name_p = (char *)kmem_zalloc
		((size_t)(FIOMP_MAX_STR), KM_SLEEP);
		iomp_path_p = (caddr32_t *)kmem_zalloc
		((size_t)((sizeof (caddr32_t)) * alloc_num), KM_SLEEP);
		iomp_logical_path_p = (caddr32_t *)kmem_zalloc
		((size_t)((sizeof (caddr32_t)) * alloc_num), KM_SLEEP);
		iomp_path_status_p = (caddr32_t *)kmem_zalloc
		((size_t)((sizeof (caddr32_t)) * alloc_num), KM_SLEEP);
		iomp_path_block_p = (caddr32_t *)kmem_zalloc
		((size_t)((sizeof (caddr32_t)) * alloc_num), KM_SLEEP);
		iomp_path = (char *)kmem_zalloc
		((size_t)(FIOMP_MAX_STR * alloc_num), KM_SLEEP);
		iomp_logical_path = (char *)kmem_zalloc
		((size_t)(FIOMP_MAX_STR * alloc_num), KM_SLEEP);
		iomp_path_status = (char *)kmem_zalloc
		((size_t)(FIOMP_MAX_STR * alloc_num), KM_SLEEP);
		iomp_path_block = (char *)kmem_zalloc
		((size_t)(FIOMP_MAX_STR * alloc_num), KM_SLEEP);
	}

	mutex_enter(&scf_comtbl.all_mutex);
	if (fiompprop32.num != scf_comtbl.path_num) {
		/*
		 * When different from appointed num, perform only num setting
		 */
		fiompprop32.num = scf_comtbl.path_num;
		num_cmp_flag = 1;
	} else {
		/* Set output information */
		strcpy(iomp_name_p, SCF_IOMP_NAME);
		strcpy(iomp_real_name_p, SCF_REAL_NAME);
		strcpy(iomp_user_path_p, SCF_USER_PATH);
		if ((scf_comtbl.scf_path_p) || (scf_comtbl.scf_exec_p)) {
			strcpy(iomp_status_p, "online");
		} else if ((scf_comtbl.scf_stop_p) ||
			(scf_comtbl.scf_err_p)) {
			strcpy(iomp_status_p, "offline");
		} else {
			strcpy(iomp_status_p, "unconfigured");
		}
		for (ii = 0, jj = 0; ii < fiompprop32.num;
			ii++, jj += FIOMP_MAX_STR) {
			/* Output information setting every pass */
			iomp_path[jj] = '\0';
			iomp_logical_path[jj] = '\0';
			iomp_path_status[jj] = '\0';
			iomp_path_block[jj] = '\0';
			if ((statep = scf_comtbl.iomp_scf[ii]) != 0) {
				if (ddi_pathname(statep->dip,
					work_name_p)) {
					sprintf(&iomp_path[jj], "%s:scfc%d",
						work_name_p, statep->instance);
				}
				sprintf(&iomp_logical_path[jj],
					"/dev/FJSVhwr/scfc%d",
					statep->instance);
				switch (statep->path_status) {
				case FIOMP_STAT_ACTIVE:
					strcpy(&iomp_path_status[jj],
						"active");
					break;
				case FIOMP_STAT_STANDBY:
					strcpy(&iomp_path_status[jj],
						"standby");
					break;
				case FIOMP_STAT_STOP:
					strcpy(&iomp_path_status[jj],
						"stop");
					break;
				case FIOMP_STAT_FAIL:
					strcpy(&iomp_path_status[jj],
						"fail");
					break;
				case FIOMP_STAT_DISCON:
					strcpy(&iomp_path_status[jj],
						"disconnected");
					break;
				default:
					strcpy(&iomp_path_status[jj],
						"empty");
				}
				strcpy(&iomp_path_block[jj], "block");
			}
		}
	}
	mutex_exit(&scf_comtbl.all_mutex);
	if (num_cmp_flag == 0) {
		if (ddi_copyout((void *)iomp_name_p,
			(void *)(uintptr_t)fiompprop32.iomp_name,
			FIOMP_MAX_STR, mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"i_ioctl ", 8);
			ret = EFAULT;
			goto END_GETPROP32;
		}
		if (ddi_copyout((void *)iomp_real_name_p,
			(void *)(uintptr_t)fiompprop32.iomp_real_name,
			FIOMP_MAX_STR, mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"i_ioctl ", 8);
			ret = EFAULT;
			goto END_GETPROP32;
		}
		if (ddi_copyout((void *)iomp_user_path_p,
			(void *)(uintptr_t)fiompprop32.iomp_user_path,
			FIOMP_MAX_STR, mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"i_ioctl ", 8);
			ret = EFAULT;
			goto END_GETPROP32;
		}
		if (ddi_copyout((void *)iomp_status_p,
			(void *)(uintptr_t)fiompprop32.iomp_status,
			FIOMP_MAX_STR, mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"i_ioctl ", 8);
			ret = EFAULT;
			goto END_GETPROP32;
		}
		if (fiompprop32.num) {
			if (fiompprop32.iomp_path) {
	if (ddi_copyin((void *)(uintptr_t)fiompprop32.iomp_path,
		(void *)iomp_path_p,
		((sizeof (caddr32_t)) * fiompprop32.num), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
			"i_ioctl ", 8);
		ret = EFAULT;
		goto END_GETPROP32;
	}
			}
			if (fiompprop32.iomp_logical_path) {
	if (ddi_copyin((void *)(uintptr_t)fiompprop32.iomp_logical_path,
		(void *)iomp_logical_path_p,
		((sizeof (caddr32_t)) * fiompprop32.num), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
			"i_ioctl ", 8);
		ret = EFAULT;
		goto END_GETPROP32;
	}
			}
			if (fiompprop32.iomp_path_status) {
	if (ddi_copyin((void *)(uintptr_t)fiompprop32.iomp_path_status,
		(void *)iomp_path_status_p,
		((sizeof (caddr32_t)) * fiompprop32.num), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
			"i_ioctl ", 8);
		ret = EFAULT;
		goto END_GETPROP32;
	}
			}
			if (fiompprop32.iomp_path_block) {
	if (ddi_copyin((void *)(uintptr_t)fiompprop32.iomp_path_block,
		(void *)iomp_path_block_p,
		((sizeof (caddr32_t)) * fiompprop32.num), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
			"i_ioctl ", 8);
		ret = EFAULT;
		goto END_GETPROP32;
	}
			}
		}
		for (ii = 0, jj = 0; ii < fiompprop32.num;
			ii++, jj += FIOMP_MAX_STR) {
			if (iomp_path_p[ii]) {
	if (ddi_copyout((void *)&iomp_path[jj],
		(void *)(uintptr_t)iomp_path_p[ii],
		FIOMP_MAX_STR, mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
			"i_ioctl ", 8);
		ret = EFAULT;
		goto END_GETPROP32;
	}
			}
			if (iomp_logical_path_p[ii]) {
	if (ddi_copyout((void *)&iomp_logical_path[jj],
		(void *)(uintptr_t)iomp_logical_path_p[ii],
		FIOMP_MAX_STR, mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
			"i_ioctl ", 8);
		ret = EFAULT;
		goto END_GETPROP32;
	}
			}
			if (iomp_path_status_p[ii]) {
	if (ddi_copyout((void *)&iomp_path_status[jj],
		(void *)(uintptr_t)iomp_path_status_p[ii],
		FIOMP_MAX_STR, mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
			"i_ioctl ", 8);
		ret = EFAULT;
		goto END_GETPROP32;
	}
			}
			if (iomp_path_block_p[ii]) {
	if (ddi_copyout((void *)&iomp_path_block[jj],
		(void *)(uintptr_t)iomp_path_block_p[ii],
		FIOMP_MAX_STR, mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
			"i_ioctl ", 8);
		ret = EFAULT;
		goto END_GETPROP32;
	}
			}
		}
	}
	if (ddi_copyout((void *)&fiompprop32, (void *)arg,
		sizeof (struct fiompprop_32), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
			"i_ioctl ", 8);
		ret = EFAULT;
	}

/*
 * END_GETPROP32
 */
	END_GETPROP32:

	/* Buffer release */
	if (work_name_p) {
		kmem_free((void *)work_name_p, (size_t)FIOMP_MAX_STR);
	}
	if (iomp_name_p) {
		kmem_free((void *)iomp_name_p, (size_t)FIOMP_MAX_STR);
	}
	if (iomp_real_name_p) {
		kmem_free((void *)iomp_real_name_p, (size_t)FIOMP_MAX_STR);
	}
	if (iomp_user_path_p) {
		kmem_free((void *)iomp_user_path_p, (size_t)FIOMP_MAX_STR);
	}
	if (iomp_status_p) {
		kmem_free((void *)iomp_status_p, (size_t)FIOMP_MAX_STR);
	}
	if (iomp_path_p) {
		kmem_free((void *)iomp_path_p,
			(size_t)((sizeof (caddr32_t)) * alloc_num));
	}
	if (iomp_logical_path_p) {
		kmem_free((void *)iomp_logical_path_p,
			(size_t)((sizeof (caddr32_t)) * alloc_num));
	}
	if (iomp_path_status_p) {
		kmem_free((void *)iomp_path_status_p,
			(size_t)((sizeof (caddr32_t)) * alloc_num));
	}
	if (iomp_path_block_p) {
		kmem_free((void *)iomp_path_block_p,
			(size_t)((sizeof (caddr32_t)) * alloc_num));
	}
	if (iomp_path) {
		kmem_free((void *)iomp_path,
			(size_t)(FIOMP_MAX_STR * alloc_num));
	}
	if (iomp_logical_path) {
		kmem_free((void *)iomp_logical_path,
			(size_t)(FIOMP_MAX_STR * alloc_num));
	}
	if (iomp_path_status) {
		kmem_free((void *)iomp_path_status,
			(size_t)(FIOMP_MAX_STR * alloc_num));
	}
	if (iomp_path_block) {
		kmem_free((void *)iomp_path_block,
			(size_t)(FIOMP_MAX_STR * alloc_num));
	}
		} else {
	/* DDI_MODEL_NONE */
	struct fiompprop fiompprop;
	char		*work_name_p = 0;
	char		*iomp_name_p = 0;
	char		*iomp_real_name_p = 0;
	char		*iomp_user_path_p = 0;
	char		*iomp_status_p = 0;
	caddr_t		*iomp_path_p = 0;
	caddr_t		*iomp_logical_path_p = 0;
	caddr_t		*iomp_path_status_p = 0;
	caddr_t		*iomp_path_block_p = 0;
	char		*iomp_path = 0;
	char		*iomp_logical_path = 0;
	char		*iomp_path_status = 0;
	char		*iomp_path_block = 0;

	if (ddi_copyin((void *)arg, (void *)&fiompprop,
		sizeof (struct fiompprop), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "i_ioctl ", 8);
		ret = EFAULT;
		goto END_inst_ioctl;
	}
	alloc_num = fiompprop.num;
	if (fiompprop.num != 0) {
	/* Buffer allocation */
		work_name_p = (char *)kmem_zalloc
		((size_t)(FIOMP_MAX_STR), KM_SLEEP);
		iomp_name_p = (char *)kmem_zalloc
		((size_t)(FIOMP_MAX_STR), KM_SLEEP);
		iomp_real_name_p = (char *)kmem_zalloc
		((size_t)(FIOMP_MAX_STR), KM_SLEEP);
		iomp_user_path_p = (char *)kmem_zalloc
		((size_t)(FIOMP_MAX_STR), KM_SLEEP);
		iomp_status_p = (char *)kmem_zalloc
		((size_t)(FIOMP_MAX_STR), KM_SLEEP);
		iomp_path_p = (caddr_t *)kmem_zalloc
		((size_t)((sizeof (caddr_t)) * alloc_num), KM_SLEEP);
		iomp_logical_path_p = (caddr_t *)kmem_zalloc
		((size_t)((sizeof (caddr_t)) * alloc_num), KM_SLEEP);
		iomp_path_status_p = (caddr_t *)kmem_zalloc
		((size_t)((sizeof (caddr_t)) * alloc_num), KM_SLEEP);
		iomp_path_block_p = (caddr_t *)kmem_zalloc
		((size_t)((sizeof (caddr_t)) * alloc_num), KM_SLEEP);
		iomp_path = (char *)kmem_zalloc
		((size_t)(FIOMP_MAX_STR * alloc_num), KM_SLEEP);
		iomp_logical_path = (char *)kmem_zalloc
		((size_t)(FIOMP_MAX_STR * alloc_num), KM_SLEEP);
		iomp_path_status = (char *)kmem_zalloc
		((size_t)(FIOMP_MAX_STR * alloc_num), KM_SLEEP);
		iomp_path_block = (char *)kmem_zalloc
		((size_t)(FIOMP_MAX_STR * alloc_num), KM_SLEEP);
	}

	mutex_enter(&scf_comtbl.all_mutex);
	if (fiompprop.num != scf_comtbl.path_num) {
		/*
		 * When different from appointed num, perform only num setting
		 */
		fiompprop.num = scf_comtbl.path_num;
		num_cmp_flag = 1;
	} else {
	/* Set output information */
		strcpy(iomp_name_p, SCF_IOMP_NAME);
		strcpy(iomp_real_name_p, SCF_REAL_NAME);
		strcpy(iomp_user_path_p, SCF_USER_PATH);
		if ((scf_comtbl.scf_path_p) || (scf_comtbl.scf_exec_p)) {
			strcpy(iomp_status_p, "online");
		} else if ((scf_comtbl.scf_stop_p) || (scf_comtbl.scf_err_p)) {
			strcpy(iomp_status_p, "offline");
		} else {
			strcpy(iomp_status_p, "unconfigured");
		}
		for (ii = 0, jj = 0; ii < fiompprop.num;
			ii++, jj += FIOMP_MAX_STR) {
			/* Output information setting every pass */
			iomp_path[jj] = '\0';
			iomp_logical_path[jj] = '\0';
			iomp_path_status[jj] = '\0';
			iomp_path_block[jj] = '\0';
			if ((statep = scf_comtbl.iomp_scf[ii]) != 0) {
				if (ddi_pathname(statep->dip, work_name_p)) {
					sprintf(&iomp_path[jj], "%s:scfc%d",
						work_name_p, statep->instance);
				}
				sprintf(&iomp_logical_path[jj],
					"/dev/FJSVhwr/scfc%d",
					statep->instance);
				switch (statep->path_status) {
				case FIOMP_STAT_ACTIVE:
					strcpy(&iomp_path_status[jj],
						"active");
					break;
				case FIOMP_STAT_STANDBY:
					strcpy(&iomp_path_status[jj],
						"standby");
					break;
				case FIOMP_STAT_STOP:
					strcpy(&iomp_path_status[jj],
						"stop");
					break;
				case FIOMP_STAT_FAIL:
					strcpy(&iomp_path_status[jj],
						"fail");
					break;
				case FIOMP_STAT_DISCON:
					strcpy(&iomp_path_status[jj],
						"disconnected");
					break;
				default:
					strcpy(&iomp_path_status[jj],
						"empty");
				}
				strcpy(&iomp_path_block[jj], "block");
			}
		}
	}
	mutex_exit(&scf_comtbl.all_mutex);
	if (num_cmp_flag == 0) {
		if (ddi_copyout((void *)iomp_name_p,
			(void *)fiompprop.iomp_name,
			FIOMP_MAX_STR, mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"i_ioctl ", 8);
			ret = EFAULT;
			goto END_GETPROP;
		}
		if (ddi_copyout((void *)iomp_real_name_p,
			(void *)fiompprop.iomp_real_name,
			FIOMP_MAX_STR, mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"i_ioctl ", 8);
			ret = EFAULT;
			goto END_GETPROP;
		}
		if (ddi_copyout((void *)iomp_user_path_p,
			(void *)fiompprop.iomp_user_path,
			FIOMP_MAX_STR, mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"i_ioctl ", 8);
			ret = EFAULT;
			goto END_GETPROP;
		}
		if (ddi_copyout((void *)iomp_status_p,
			(void *)fiompprop.iomp_status,
			FIOMP_MAX_STR, mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"i_ioctl ", 8);
			ret = EFAULT;
			goto END_GETPROP;
		}
		if (fiompprop.num) {
			if (fiompprop.iomp_path) {
	if (ddi_copyin((void *)fiompprop.iomp_path,
		(void *)iomp_path_p,
		((sizeof (caddr_t)) * fiompprop.num), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "i_ioctl ", 8);
		ret = EFAULT;
		goto END_GETPROP;
	}
			}
			if (fiompprop.iomp_logical_path) {
	if (ddi_copyin((void *)fiompprop.iomp_logical_path,
		(void *)iomp_logical_path_p,
		((sizeof (caddr_t)) * fiompprop.num), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "i_ioctl ", 8);
		ret = EFAULT;
		goto END_GETPROP;
	}
			}
			if (fiompprop.iomp_path_status) {
	if (ddi_copyin((void *)fiompprop.iomp_path_status,
		(void *)iomp_path_status_p,
		((sizeof (caddr_t)) * fiompprop.num), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "i_ioctl ", 8);
		ret = EFAULT;
		goto END_GETPROP;
	}
			}
			if (fiompprop.iomp_path_block) {
	if (ddi_copyin((void *)fiompprop.iomp_path_block,
		(void *)iomp_path_block_p,
		((sizeof (caddr_t)) * fiompprop.num), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "i_ioctl ", 8);
		ret = EFAULT;
		goto END_GETPROP;
	}
			}
		}
		for (ii = 0, jj = 0; ii < fiompprop.num;
			ii++, jj += FIOMP_MAX_STR) {
			if (iomp_path_p[ii]) {
	if (ddi_copyout((void *)&iomp_path[jj],
		(void *)iomp_path_p[ii],
		FIOMP_MAX_STR, mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "i_ioctl ", 8);
		ret = EFAULT;
		goto END_GETPROP;
	}
			}
			if (iomp_logical_path_p[ii]) {
	if (ddi_copyout((void *)&iomp_logical_path[jj],
		(void *)iomp_logical_path_p[ii],
		FIOMP_MAX_STR, mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "i_ioctl ", 8);
		ret = EFAULT;
		goto END_GETPROP;
	}
			}
			if (iomp_path_status_p[ii]) {
	if (ddi_copyout((void *)&iomp_path_status[jj],
		(void *)iomp_path_status_p[ii],
		FIOMP_MAX_STR, mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "i_ioctl ", 8);
		ret = EFAULT;
		goto END_GETPROP;
	}
			}
			if (iomp_path_block_p[ii]) {
	if (ddi_copyout((void *)&iomp_path_block[jj],
		(void *)iomp_path_block_p[ii],
		FIOMP_MAX_STR, mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "i_ioctl ", 8);
		ret = EFAULT;
		goto END_GETPROP;
	}
			}
		}
	}
	if (ddi_copyout((void *)&fiompprop, (void *)arg,
		sizeof (struct fiompprop), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "i_ioctl ", 8);
		ret = EFAULT;
	}

/*
 * END_GETPROP
 */
	END_GETPROP:

	/* Buffer release */
	if (work_name_p) {
		kmem_free((void *)work_name_p, (size_t)FIOMP_MAX_STR);
	}
	if (iomp_name_p) {
		kmem_free((void *)iomp_name_p, (size_t)FIOMP_MAX_STR);
	}
	if (iomp_real_name_p) {
		kmem_free((void *)iomp_real_name_p, (size_t)FIOMP_MAX_STR);
	}
	if (iomp_user_path_p) {
		kmem_free((void *)iomp_user_path_p, (size_t)FIOMP_MAX_STR);
	}
	if (iomp_status_p) {
		kmem_free((void *)iomp_status_p, (size_t)FIOMP_MAX_STR);
	}
	if (iomp_path_p) {
		kmem_free((void *)iomp_path_p,
			(size_t)((sizeof (caddr_t)) * alloc_num));
	}
	if (iomp_logical_path_p) {
		kmem_free((void *)iomp_logical_path_p,
			(size_t)((sizeof (caddr_t)) * alloc_num));
	}
	if (iomp_path_status_p) {
		kmem_free((void *)iomp_path_status_p,
			(size_t)((sizeof (caddr_t)) * alloc_num));
	}
	if (iomp_path_block_p) {
		kmem_free((void *)iomp_path_block_p,
			(size_t)((sizeof (caddr_t)) * alloc_num));
	}
	if (iomp_path) {
		kmem_free((void *)iomp_path,
			(size_t)(FIOMP_MAX_STR * alloc_num));
	}
	if (iomp_logical_path) {
		kmem_free((void *)iomp_logical_path,
			(size_t)(FIOMP_MAX_STR * alloc_num));
	}
	if (iomp_path_status) {
		kmem_free((void *)iomp_path_status,
			(size_t)(FIOMP_MAX_STR * alloc_num));
	}
	if (iomp_path_block) {
		kmem_free((void *)iomp_path_block,
			(size_t)(FIOMP_MAX_STR * alloc_num));
	}
	}
		break;

	case FIOMPDESTROY:
		SCFDBGMSG(SCF_DBGFLAG_IOMP, "FIOMPDESTROY proc");
		ret = ENOTTY;
		break;

	case FIOMPSTOP:
		SCFDBGMSG(SCF_DBGFLAG_IOMP, "FIOMPSTOP proc");

		if (ddi_copyin((void *)arg, (void *)&pathnum,
			sizeof (int), mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"i_ioctl ", 8);
			ret = EFAULT;
			goto END_inst_ioctl;
		}
		mutex_enter(&scf_comtbl.all_mutex);
		if (pathnum == FIOMP_PATH_ALL) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"i_ioctl ", 8);
			ret = EINVAL;

			mutex_exit(&scf_comtbl.all_mutex);
			goto END_inst_ioctl;
		} else {
			/* PATH appointment */
			if (scf_comtbl.path_num < (pathnum + 1)) {
				/* Invalid PATH */
				SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
					"i_ioctl ", 8);
				ret = EINVAL;

				mutex_exit(&scf_comtbl.all_mutex);
				goto END_inst_ioctl;
			}
	if ((statep = scf_comtbl.iomp_scf[pathnum]) != 0) {
		/* SCF command send sync stop */
		ret = scf_make_send_cmd(&scf_cmd, SCF_USE_STOP);
		if (ret != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"i_ioctl ", 8);
			goto END_STOP;
		}
		if ((statep->path_status != FIOMP_STAT_ACTIVE) &&
			(statep->path_status != FIOMP_STAT_STANDBY)) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"i_ioctl ", 8);
			ret = EINVAL;
		} else {
			if (statep->path_status == FIOMP_STAT_ACTIVE) {
				/* Exec SCF device appointment */
				if (scf_comtbl.scf_wait_p == 0) {
					/* Last deveice stop is error */
					SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR,
						__LINE__, "i_ioctl ", 8);
					ret = EINVAL;
				} else {
					/* Device interrupt disable */
					scf_forbid_intr(statep);
					scf_chg_scf(statep, FIOMP_STAT_STOP);
					/* Send path change command */
					statep = scf_comtbl.scf_wait_p;
					scf_comtbl.scf_wait_p = statep->next;
					scf_chg_scf(statep, FIOMP_STAT_ACTIVE);
					scf_comtbl.scf_exec_p = 0;
					scf_comtbl.scf_path_p = 0;
					scf_comtbl.scf_pchg_event_sub =
						EVENT_SUB_PCHG_WAIT;
					scf_next_cmd_check(statep);

					/* DCSP interface stop */
					scf_dscp_stop(FACTOR_PATH_CHG);
				}
			} else {
				/* Not exec device appointment */
				scf_del_queue(statep);
				scf_forbid_intr(statep);
				scf_chg_scf(statep, FIOMP_STAT_STOP);
			}
		}
/*
 * END_STOP
 */
	END_STOP:

		/* SCF command send sync start */
		(void) scf_make_send_cmd(&scf_cmd, SCF_USE_START);
	} else {
		/* Appointed path is already out of managemen */
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "i_ioctl ", 8);
		ret = EINVAL;
	}
		}
		mutex_exit(&scf_comtbl.all_mutex);
		break;

	case FIOMPSTART:
		SCFDBGMSG(SCF_DBGFLAG_IOMP, "FIOMPSTART proc");

		if (ddi_copyin((void *)arg, (void *)&pathnum,
			sizeof (int), mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"i_ioctl ", 8);
			ret = EFAULT;
			goto END_inst_ioctl;
		}
		mutex_enter(&scf_comtbl.all_mutex);
		if (pathnum == FIOMP_PATH_ALL) {
			/* PATH_ALL appointment */
			if ((statep = scf_comtbl.scf_stop_p) != 0) {
	/* Check stop queue */
	scf_comtbl.scf_stop_p = 0;
	while (statep) {
		wkstatep = statep->next;
		/* Interupt disable */
		scf_permit_intr(statep, 1);
		if ((scf_comtbl.scf_path_p) ||
			(scf_comtbl.scf_exec_p)) {
			scf_chg_scf(statep, FIOMP_STAT_STANDBY);
		} else {
			if (scf_comtbl.watchdog_after_resume) {
				scf_comtbl.alive_running = SCF_ALIVE_START;
				scf_comtbl.watchdog_after_resume = 0;
			}
			scf_chg_scf(statep, FIOMP_STAT_ACTIVE);
			/* Send path change command */
			scf_comtbl.scf_exec_p = 0;
			scf_comtbl.scf_path_p = 0;

			scf_comtbl.scf_pchg_event_sub = EVENT_SUB_PCHG_WAIT;
			scf_next_cmd_check(statep);
		}
		statep = wkstatep;
	}
			}
		} else {
			/* PATH appointment */
			if (scf_comtbl.path_num < (pathnum + 1)) {
				/* Invalid PATH */
				SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
					"i_ioctl ", 8);
				ret = EINVAL;
				mutex_exit(&scf_comtbl.all_mutex);
				goto END_inst_ioctl;
			}
			if ((statep = scf_comtbl.iomp_scf[pathnum]) != 0) {
				if (statep->path_status == FIOMP_STAT_STOP) {
	/* Check stop queue */
	scf_del_queue(statep);
	/* Interrupt enable */
	scf_permit_intr(statep, 1);
	if ((scf_comtbl.scf_path_p) ||
		(scf_comtbl.scf_exec_p)) {
		scf_chg_scf(statep, FIOMP_STAT_STANDBY);
	} else {
		if (scf_comtbl.watchdog_after_resume) {
			scf_comtbl.alive_running = SCF_ALIVE_START;
			scf_comtbl.watchdog_after_resume = 0;
		}
		scf_chg_scf(statep, FIOMP_STAT_ACTIVE);
		/* Send path change command */
		scf_comtbl.scf_exec_p = 0;
		scf_comtbl.scf_path_p = 0;
		scf_comtbl.scf_pchg_event_sub = EVENT_SUB_PCHG_WAIT;
		scf_next_cmd_check(statep);
	}
				} else {
					SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR,
						__LINE__, "i_ioctl ", 8);
					ret = EINVAL;
				}
			} else {
				/* Appointed path is already out of managemen */
				SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
					"i_ioctl ", 8);
				ret = EINVAL;
			}
		}
		mutex_exit(&scf_comtbl.all_mutex);
		break;

	case FIOMPRECOVER:
		SCFDBGMSG(SCF_DBGFLAG_IOMP, "FIOMPRECOVER proc");

		if (ddi_copyin((void *)arg, (void *)&pathnum,
			sizeof (int), mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"i_ioctl ", 8);
			ret = EFAULT;
			goto END_inst_ioctl;
		}
		mutex_enter(&scf_comtbl.all_mutex);
		if (pathnum == FIOMP_PATH_ALL) {
			/* PATH_ALL appointment */

			/* Check fail queue */
			if ((statep = scf_comtbl.scf_err_p) != 0) {
				scf_comtbl.scf_err_p = 0;
				while (statep) {
					wkstatep = statep->next;
					/* Interrupt enable */
					scf_forbid_intr(statep);
					statep->scf_herr = 0;
					statep->tesum_rcnt = 0;
					statep->resum_rcnt = 0;
					statep->cmd_to_rcnt = 0;
					scf_chg_scf(statep, FIOMP_STAT_STOP);
					statep = wkstatep;
				}
			}
		} else {
			/* PATH appointment */
			if (scf_comtbl.path_num < (pathnum + 1)) {
				/* Invalid PATH */
				SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
					"i_ioctl ", 8);
				ret = EINVAL;
				mutex_exit(&scf_comtbl.all_mutex);
				goto END_inst_ioctl;
			}
			if ((statep = scf_comtbl.iomp_scf[pathnum]) != 0) {
				if (statep->path_status == FIOMP_STAT_FAIL) {
					scf_del_queue(statep);
					scf_forbid_intr(statep);
					statep->scf_herr = 0;
					statep->tesum_rcnt = 0;
					statep->resum_rcnt = 0;
					statep->cmd_to_rcnt = 0;
					scf_chg_scf(statep, FIOMP_STAT_STOP);
				} else {
					SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR,
						__LINE__, "i_ioctl ", 8);
					ret = EINVAL;
				}
			} else {
				/* Appointed path is already out of managemen */
				SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
					"i_ioctl ", 8);
				ret = EINVAL;
			}
		}
		mutex_exit(&scf_comtbl.all_mutex);
		break;

	case FIOMPLIST:
		SCFDBGMSG(SCF_DBGFLAG_IOMP, "FIOMPLIST proc");

		if (u_mode == DDI_MODEL_ILP32) {
	/* DDI_MODEL_ILP32 */
	struct fiompdev_32 fiompdev32;
	char		*work_name_p = 0;
	caddr32_t	*devs_p = 0;
	char		*devs = 0;

	if (ddi_copyin((void *)arg, (void *)&fiompdev32,
		sizeof (struct fiompdev_32), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "i_ioctl ", 8);
		ret = EFAULT;
		goto END_inst_ioctl;
	}
	if (fiompdev32.api_level != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "i_ioctl ", 8);
		ret = EINVAL;
		goto END_inst_ioctl;
	}
	alloc_num = fiompdev32.num;
	if (fiompdev32.num != 0) {
	/* Buffer allocation */
		work_name_p = (char *)kmem_zalloc((size_t)(FIOMP_MAX_STR),
			KM_SLEEP);
		devs_p = (caddr32_t *)kmem_zalloc
		((size_t)((sizeof (caddr32_t)) * alloc_num), KM_SLEEP);
		devs = (char *)kmem_zalloc
		((size_t)(FIOMP_MAX_STR * alloc_num), KM_SLEEP);
	}

	mutex_enter(&scf_comtbl.all_mutex);
	if (fiompdev32.num != scf_comtbl.path_num) {
		/*
		 * When different from appointed num, perform only num setting
		 */
		fiompdev32.num = scf_comtbl.path_num;
		num_cmp_flag = 1;
	} else {
	/* Set output information */
		fiompdev32.inst_no = 0;
		fiompdev32.inst_minor = SCF_INST_INSTANCE;
		fiompdev32.user_minor = SCF_USER_INSTANCE;
		fiompdev32.mpmode = FIOMP_FALSE;
		fiompdev32.autopath = FIOMP_TRUE;
		fiompdev32.needsync = FIOMP_FALSE;
		for (ii = 0, jj = 0; ii < fiompdev32.num;
			ii++, jj += FIOMP_MAX_STR) {
			/* Output information setting every pass */
			devs[jj] = '\0';
			if ((statep = scf_comtbl.iomp_scf[ii]) != 0) {
				if (ddi_pathname(statep->dip, work_name_p)) {
					sprintf(&devs[jj], "%s:scfc%d",
						work_name_p, statep->instance);
				}
			}
		}
	}
	mutex_exit(&scf_comtbl.all_mutex);
	if ((num_cmp_flag == 0) && (fiompdev32.num != 0)) {
		if (fiompdev32.devs) {
			if (ddi_copyin((void *)(uintptr_t)fiompdev32.devs,
				(void *)devs_p,
				((sizeof (caddr32_t)) * fiompdev32.num),
				mode) != 0) {
				SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
					"i_ioctl ", 8);
				ret = EFAULT;
				goto END_LIST32;
			}
		}
		for (ii = 0, jj = 0; ii < fiompdev32.num;
			ii++, jj += FIOMP_MAX_STR) {
			if (devs_p[ii]) {
				if (ddi_copyout((void *)&devs[jj],
					(void *)(uintptr_t)devs_p[ii],
					FIOMP_MAX_STR, mode) != 0) {
					SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR,
						__LINE__, "i_ioctl ", 8);
					ret = EFAULT;
					goto END_LIST32;
				}
			}
		}
	}
	if (ddi_copyout((void *)&fiompdev32, (void *)arg,
		sizeof (struct fiompdev_32), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "i_ioctl ", 8);
		ret = EFAULT;
	}

/*
 * END_LIST32
 */
	END_LIST32:

	/* Buffer release */
	if (work_name_p) {
		kmem_free((void *)work_name_p, (size_t)FIOMP_MAX_STR);
	}
	if (devs_p) {
		kmem_free((void *)devs_p,
			(size_t)((sizeof (caddr32_t)) * alloc_num));
	}
	if (devs) {
		kmem_free((void *)devs,
			(size_t)(FIOMP_MAX_STR * alloc_num));
	}
		} else {
	/* DDI_MODEL_NONE */
	struct fiompdev fiompdev;
	char		*work_name_p = 0;
	caddr_t		*devs_p = 0;
	char		*devs = 0;

	if (ddi_copyin((void *)arg, (void *)&fiompdev,
		sizeof (struct fiompdev), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "i_ioctl ", 8);
		ret = EFAULT;
		goto END_inst_ioctl;
	}
	if (fiompdev.api_level != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "i_ioctl ", 8);
		ret = EINVAL;
		goto END_inst_ioctl;
	}
	alloc_num = fiompdev.num;
	if (fiompdev.num != 0) {
		/* Buffer allocation */
		work_name_p = (char *)kmem_zalloc
		((size_t)(FIOMP_MAX_STR), KM_SLEEP);
		devs_p = (caddr_t *)kmem_zalloc
		((size_t)((sizeof (caddr_t)) * alloc_num), KM_SLEEP);
		devs = (char *)kmem_zalloc
		((size_t)(FIOMP_MAX_STR * alloc_num), KM_SLEEP);
	}

	mutex_enter(&scf_comtbl.all_mutex);
	if (fiompdev.num != scf_comtbl.path_num) {
		/*
		 * When different from appointed num, perform only num setting
		 */
		fiompdev.num = scf_comtbl.path_num;
		num_cmp_flag = 1;
	} else {
	/* Set output information */
		fiompdev.inst_no = 0;
		fiompdev.inst_minor = SCF_INST_INSTANCE;
		fiompdev.user_minor = SCF_USER_INSTANCE;
		fiompdev.mpmode = FIOMP_FALSE;
		fiompdev.autopath = FIOMP_TRUE;
		fiompdev.needsync = FIOMP_FALSE;
		for (ii = 0, jj = 0; ii < fiompdev.num;
			ii++, jj += FIOMP_MAX_STR) {
			/* Output information setting every pass */
			devs[jj] = '\0';
			if ((statep = scf_comtbl.iomp_scf[ii]) != 0) {
				if (ddi_pathname(statep->dip, work_name_p)) {
					sprintf(&devs[jj], "%s:scfc%d",
						work_name_p, statep->instance);
				}
			}
		}
	}
	mutex_exit(&scf_comtbl.all_mutex);
	if ((num_cmp_flag == 0) && (fiompdev.num != 0)) {
		if (fiompdev.devs) {
			if (ddi_copyin((void *)fiompdev.devs,
				(void *)devs_p,
				((sizeof (caddr_t)) * fiompdev.num),
				mode) != 0) {
				SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
					"i_ioctl ", 8);
				ret = EFAULT;
				goto END_LIST;
			}
		}
		for (ii = 0, jj = 0; ii < fiompdev.num;
			ii++, jj += FIOMP_MAX_STR) {
			if (devs_p[ii]) {
				if (ddi_copyout((void *)&devs[jj],
					(void *)devs_p[ii],
					FIOMP_MAX_STR, mode) != 0) {
					SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR,
						__LINE__, "i_ioctl ", 8);
					ret = EFAULT;
					goto END_LIST;
				}
			}
		}
	}
	if (ddi_copyout((void *)&fiompdev, (void *)arg,
		sizeof (struct fiompdev), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "i_ioctl ", 8);
		ret = EFAULT;
	}

/*
 * END_LIST
 */
	END_LIST:

	/* Buffer release */
	if (work_name_p) {
		kmem_free((void *)work_name_p, (size_t)FIOMP_MAX_STR);
	}
	if (devs_p) {
		kmem_free((void *)devs_p,
			(size_t)((sizeof (caddr_t)) * alloc_num));
	}
	if (devs) {
		kmem_free((void *)devs,
			(size_t)(FIOMP_MAX_STR * alloc_num));
	}
		}
		break;

	case FIOMPSTATUS:
		SCFDBGMSG(SCF_DBGFLAG_IOMP, "FIOMPSTATUS proc");

		if (u_mode == DDI_MODEL_ILP32) {	/* DDI_MODEL_ILP32 */
			struct fiompstatus_32 fiompstatus32;
			char		*message_p;

			message_p = (char *)kmem_zalloc
			((size_t)(FIOMP_MAX_STR), KM_SLEEP);

			if (ddi_copyin((void *)arg, (void *)&fiompstatus32,
				sizeof (struct fiompstatus_32), mode) != 0) {
				SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
					"i_ioctl ", 8);
				ret = EFAULT;
				goto END_STATUS32;
			}
			pathnum = fiompstatus32.pathnum;
			if (pathnum == FIOMP_PATH_ALL) {
				SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
					"i_ioctl ", 8);
				ret = EINVAL;
				goto END_STATUS32;
			}
			mutex_enter(&scf_comtbl.all_mutex);
			if (scf_comtbl.path_num < (pathnum + 1)) {
				/* Invalid path */
				SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
					"i_ioctl ", 8);
				ret = EINVAL;
				mutex_exit(&scf_comtbl.all_mutex);
				goto END_STATUS32;
			}
			if ((statep = scf_comtbl.iomp_scf[pathnum]) != 0) {
				scf_inst_getstat32(statep, &fiompstatus32,
					message_p, 1);
			} else {
				/*
				 * Appointed path is already out of management
				 */
				SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
					"i_ioctl ", 8);
				ret = EINVAL;
				mutex_exit(&scf_comtbl.all_mutex);
				goto END_STATUS32;
			}
			mutex_exit(&scf_comtbl.all_mutex);
			if (ddi_copyout((void *)message_p,
				(void *)(uintptr_t)fiompstatus32.message,
				FIOMP_MAX_STR, mode) != 0) {
				SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
					"i_ioctl ", 8);
				ret = EFAULT;
				goto END_STATUS32;
			}

			if (ddi_copyout((void *)&fiompstatus32, (void *)arg,
				sizeof (struct fiompstatus_32), mode) != 0) {
				SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
					"i_ioctl ", 8);
				ret = EFAULT;
			}

/*
 * END_STATUS32
 */
	END_STATUS32:

			if (message_p) {
				kmem_free((void *)message_p,
					(size_t)FIOMP_MAX_STR);
			}
		} else {				/* DDI_MODEL_NONE */
			struct fiompstatus fiompstatus;
			char		*message_p;

			message_p = (char *)kmem_zalloc
			((size_t)(FIOMP_MAX_STR), KM_SLEEP);

			if (ddi_copyin((void *)arg, (void *)&fiompstatus,
				sizeof (struct fiompstatus), mode) != 0) {
				SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
					"i_ioctl ", 8);
				ret = EFAULT;
				goto END_STATUS;
			}
			pathnum = fiompstatus.pathnum;
			if (pathnum == FIOMP_PATH_ALL) {
				SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
					"i_ioctl ", 8);
				ret = EINVAL;
				goto END_STATUS;
			}
			mutex_enter(&scf_comtbl.all_mutex);
			if (scf_comtbl.path_num < (pathnum + 1)) {
				/* Invalid path */
				SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
					"i_ioctl ", 8);
				ret = EINVAL;
				mutex_exit(&scf_comtbl.all_mutex);
				goto END_STATUS;
			}
			if ((statep = scf_comtbl.iomp_scf[pathnum]) != 0) {
				scf_inst_getstat(statep, &fiompstatus,
					message_p, 1);
			} else {
				/*
				 * Appointed path is already out of managemen
				 */
				SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
					"i_ioctl ", 8);
				ret = EINVAL;
				mutex_exit(&scf_comtbl.all_mutex);
				goto END_STATUS;
			}
			mutex_exit(&scf_comtbl.all_mutex);
			if (ddi_copyout((void *)message_p,
				(void *)fiompstatus.message,
				FIOMP_MAX_STR, mode) != 0) {
				SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
					"i_ioctl ", 8);
				ret = EFAULT;
				goto END_STATUS;
			}

			if (ddi_copyout((void *)&fiompstatus,
				(void *)arg, sizeof (struct fiompstatus),
				mode) != 0) {
				SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
					"i_ioctl ", 8);
				ret = EFAULT;
			}

/*
 * END_STATUS
 */
	END_STATUS:

			if (message_p) {
				kmem_free((void *)message_p,
					(size_t)FIOMP_MAX_STR);
			}
		}
		break;

	case FIOMPADD:
		SCFDBGMSG(SCF_DBGFLAG_IOMP, "FIOMPADD proc");

		ret = ENOTTY;
		break;

	case FIOMPDEL:
		SCFDBGMSG(SCF_DBGFLAG_IOMP, "FIOMPDEL proc");

		ret = ENOTTY;
		break;

	case FIOMPACTIVE:
		SCFDBGMSG(SCF_DBGFLAG_IOMP, "FIOMPACTIVE proc");

		ret = ENOTTY;
		break;

	case FIOMPDISCONNECT:
		SCFDBGMSG(SCF_DBGFLAG_IOMP, "FIOMPDISCONNECT proc");

		if (ddi_copyin((void *)arg, (void *)&pathnum,
			sizeof (int), mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"i_ioctl ", 8);
			ret = EFAULT;
			goto END_inst_ioctl;
		}
		mutex_enter(&scf_comtbl.all_mutex);
		if (pathnum == FIOMP_PATH_ALL) {
			/* PATH_ALL appointment */

			/* Check stop queue */
			if ((statep = scf_comtbl.scf_stop_p) != 0) {
				scf_comtbl.scf_stop_p = 0;
				while (statep) {
					wkstatep = statep->next;
					scf_chg_scf(statep, FIOMP_STAT_DISCON);
					statep = wkstatep;
				}
			}
			/* Check fail queue */
			if ((statep = scf_comtbl.scf_err_p) != 0) {
				scf_comtbl.scf_err_p = 0;
				while (statep) {
					wkstatep = statep->next;
					scf_chg_scf(statep, FIOMP_STAT_DISCON);
					statep = wkstatep;
				}
			}
		} else {
			/* PATH appointment */
			if (scf_comtbl.path_num < (pathnum + 1)) {
				/* Invalid path */
				SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
					"i_ioctl ", 8);
				ret = EINVAL;
				mutex_exit(&scf_comtbl.all_mutex);
				goto END_inst_ioctl;
			}
			if ((statep = scf_comtbl.iomp_scf[pathnum]) != 0) {
				if ((statep->path_status == FIOMP_STAT_STOP) ||
					(statep->path_status ==
					FIOMP_STAT_FAIL)) {
					scf_del_queue(statep);
					scf_chg_scf(statep, FIOMP_STAT_DISCON);
				} else {
					SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR,
						__LINE__, "i_ioctl ", 8);
					ret = EINVAL;
				}
			} else {
				/* Appointed path is already out of managemen */
				SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
					"i_ioctl ", 8);
				ret = EINVAL;
			}
		}

		mutex_exit(&scf_comtbl.all_mutex);
		break;

	case FIOMPCONNECT:
		SCFDBGMSG(SCF_DBGFLAG_IOMP, "FIOMPCONNECT proc");

		if (ddi_copyin((void *)arg, (void *)&pathnum,
			sizeof (int), mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"i_ioctl ", 8);
			ret = EFAULT;
			goto END_inst_ioctl;
		}
		mutex_enter(&scf_comtbl.all_mutex);
		if (pathnum == FIOMP_PATH_ALL) {
			/* PATH_ALL appointment */

			/* Check disconnect queue */
			if ((statep = scf_comtbl.scf_disc_p) != 0) {
				scf_comtbl.scf_disc_p = 0;
				while (statep) {
					wkstatep = statep->next;
					if (statep->scf_herr) {
						scf_chg_scf(statep,
							FIOMP_STAT_FAIL);
					} else {
						scf_chg_scf(statep,
							FIOMP_STAT_STOP);
					}
					statep = wkstatep;
				}
			}
		} else {
			/* PATH appointment */
			if (scf_comtbl.path_num < (pathnum + 1)) {
				/* Invalid path */
				SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
					"i_ioctl ", 8);
				ret = EINVAL;
				mutex_exit(&scf_comtbl.all_mutex);
				goto END_inst_ioctl;
			}
			if ((statep = scf_comtbl.iomp_scf[pathnum]) != 0) {
				if (statep->path_status == FIOMP_STAT_DISCON) {
					scf_del_queue(statep);
					if (statep->scf_herr) {
						scf_chg_scf(statep,
							FIOMP_STAT_FAIL);
					} else {
						scf_chg_scf(statep,
							FIOMP_STAT_STOP);
					}
				} else {
					SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR,
						__LINE__, "i_ioctl ", 8);
					ret = EINVAL;
				}
			} else {
				/* Appointed path is already out of managemen */
				SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
					"i_ioctl ", 8);
				ret = EINVAL;
			}
		}
		mutex_exit(&scf_comtbl.all_mutex);
		break;

	case FIOMPSTANDBY:
		SCFDBGMSG(SCF_DBGFLAG_IOMP, "FIOMPSTANDBY proc");

		ret = ENOTTY;
		break;

	case FIOMPBLOCK:
		SCFDBGMSG(SCF_DBGFLAG_IOMP, "FIOMPBLOCK proc");

		ret = ENOTTY;
		break;

	case FIOMPUNBLOCK:
		SCFDBGMSG(SCF_DBGFLAG_IOMP, "FIOMPUNBLOCK proc");

		ret = ENOTTY;
		break;

	case FIOMPDIAGON:
		SCFDBGMSG(SCF_DBGFLAG_IOMP, "FIOMPDIAGON proc");

		ret = ENOTTY;
		break;

	case FIOMPDIAGOFF:
		SCFDBGMSG(SCF_DBGFLAG_IOMP, "FIOMPDIAGOFF proc");

		ret = ENOTTY;
		break;

	case FIOMPGETALLSTAT:
		SCFDBGMSG(SCF_DBGFLAG_IOMP, "FIOMPGETALLSTAT proc");

		if (u_mode == DDI_MODEL_ILP32) {
	/* DDI_MODEL_ILP32 */
	struct fiomp_all_stat_32 fiomp_all_stat32;
	struct fiompstatus_32 *fiompstatus32_p = 0;
	char		*message_p = 0;

	if (ddi_copyin((void *)arg, (void *)&fiomp_all_stat32,
		sizeof (struct fiomp_all_stat_32), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "i_ioctl ", 8);
		ret = EFAULT;
		goto END_inst_ioctl;
	}
	alloc_num = fiomp_all_stat32.num;
	if (fiomp_all_stat32.num != 0) {
		/* Buffer allocation */
		fiompstatus32_p =
			(struct fiompstatus_32 *)kmem_zalloc
			((size_t)((sizeof (struct fiompstatus_32)) * alloc_num),
				KM_SLEEP);
		message_p = (char *)kmem_zalloc
		((size_t)(FIOMP_MAX_STR * alloc_num), KM_SLEEP);
	}

	if (fiomp_all_stat32.num != 0) {
		if (ddi_copyin((void *)(uintptr_t)fiomp_all_stat32.status,
			(void *)fiompstatus32_p,
			((sizeof (struct fiompstatus_32)) *
			fiomp_all_stat32.num), mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"i_ioctl ", 8);
			ret = EFAULT;
			goto END_GETALLSTAT32;
		}
	}
	mutex_enter(&scf_comtbl.all_mutex);
	if (scf_comtbl.path_num != fiomp_all_stat32.num) {
		/*
		 * When different from appointed num, perform only num setting
		 */
		fiomp_all_stat32.num = scf_comtbl.path_num;
		num_cmp_flag = 1;
	} else {
		/* Output information setting every pass */
		for (ii = 0, jj = 0; ii < fiomp_all_stat32.num;
			ii++, jj += FIOMP_MAX_STR) {
			statep = scf_comtbl.iomp_scf[ii];
			scf_inst_getstat32(statep, &fiompstatus32_p[ii],
				&message_p[jj], 1);
		}
	}
	mutex_exit(&scf_comtbl.all_mutex);
	if (num_cmp_flag == 0 && fiomp_all_stat32.num != 0) {
		if (ddi_copyout((void *)fiompstatus32_p,
			(void *)(uintptr_t)fiomp_all_stat32.status,
			((sizeof (struct fiompstatus_32)) *
			fiomp_all_stat32.num), mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"i_ioctl ", 8);
			ret = EFAULT;
			goto END_GETALLSTAT32;
		}
		for (ii = 0, jj = 0; ii < fiomp_all_stat32.num;
			ii++, jj += FIOMP_MAX_STR) {
			if (ddi_copyout((void *)&message_p[jj],
				(void *)(uintptr_t)fiompstatus32_p[ii].message,
				FIOMP_MAX_STR, mode) != 0) {
				SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
					"i_ioctl ", 8);
				ret = EFAULT;
				goto END_GETALLSTAT32;
			}
		}
	}
	if (ddi_copyout((void *)&fiomp_all_stat32, (void *)arg,
		sizeof (struct fiomp_all_stat_32), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "i_ioctl ", 8);
		ret = EFAULT;
	}

/*
 * END_GETALLSTAT32
 */
	END_GETALLSTAT32:

	/* Buffer release */
	if (fiompstatus32_p) {
		kmem_free((void *)fiompstatus32_p,
			(size_t)((sizeof (struct fiompstatus_32)) * alloc_num));
	}
	if (message_p) {
		kmem_free((void *)message_p,
			(size_t)(FIOMP_MAX_STR * alloc_num));
	}
		} else {
	/* DDI_MODEL_NONE */
	struct fiomp_all_stat fiomp_all_stat;
	struct fiompstatus *fiompstatus_p = 0;
	char		*message_p = 0;

	if (ddi_copyin((void *)arg, (void *)&fiomp_all_stat,
		sizeof (struct fiomp_all_stat), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "i_ioctl ", 8);
		ret = EFAULT;
		goto END_inst_ioctl;
	}
	alloc_num = fiomp_all_stat.num;
	if (fiomp_all_stat.num != 0) {
		/* Buffer allocation */
		fiompstatus_p =
			(struct fiompstatus *)kmem_zalloc
			((size_t)((sizeof (struct fiompstatus)) * alloc_num),
				KM_SLEEP);
		message_p = (char *)kmem_zalloc
		((size_t)(FIOMP_MAX_STR * alloc_num), KM_SLEEP);
	}

	if (fiomp_all_stat.num != 0) {
		if (ddi_copyin((void *)fiomp_all_stat.status,
			(void *)fiompstatus_p,
			((sizeof (struct fiompstatus)) * fiomp_all_stat.num),
			mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"i_ioctl ", 8);
			ret = EFAULT;
			goto END_GETALLSTAT;
		}
	}
	mutex_enter(&scf_comtbl.all_mutex);
	if (scf_comtbl.path_num != fiomp_all_stat.num) {
		/*
		 * When different from appointed num, perform only num setting
		 */
		fiomp_all_stat.num = scf_comtbl.path_num;
		num_cmp_flag = 1;
	} else {
		/* Output information setting every pass */
		for (ii = 0, jj = 0; ii < fiomp_all_stat.num;
			ii++, jj += FIOMP_MAX_STR) {
			statep = scf_comtbl.iomp_scf[ii];
			scf_inst_getstat(statep, &fiompstatus_p[ii],
				&message_p[jj], 1);
		}
	}
	mutex_exit(&scf_comtbl.all_mutex);
	if (num_cmp_flag == 0 && fiomp_all_stat.num != 0) {
		if (ddi_copyout((void *)fiompstatus_p,
			(void *)fiomp_all_stat.status,
			((sizeof (struct fiompstatus)) * fiomp_all_stat.num),
			mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"i_ioctl ", 8);
			ret = EFAULT;
			goto END_GETALLSTAT;
		}
		for (ii = 0, jj = 0; ii < fiomp_all_stat.num;
			ii++, jj += FIOMP_MAX_STR) {
			if (ddi_copyout((void *)&message_p[jj],
				(void *)fiompstatus_p[ii].message,
				FIOMP_MAX_STR, mode) != 0) {
				SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
					"i_ioctl ", 8);
				ret = EFAULT;
				goto END_GETALLSTAT;
			}
		}
	}
	if (ddi_copyout((void *)&fiomp_all_stat, (void *)arg,
		sizeof (struct fiomp_all_stat), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "i_ioctl ", 8);
		ret = EFAULT;
	}

/*
 * END_GETALLSTAT
 */
	END_GETALLSTAT:

	/* Buffer release */
	if (fiompstatus_p) {
		kmem_free((void *)fiompstatus_p,
			(size_t)((sizeof (struct fiompstatus)) * alloc_num));
	}
	if (message_p) {
		kmem_free((void *)message_p,
			(size_t)(FIOMP_MAX_STR * alloc_num));
	}
		}
		break;

	case FIOMPCHG:
		SCFDBGMSG(SCF_DBGFLAG_IOMP, "FIOMPCHG proc");

		ret = ENOTTY;
		break;

	case FIOMPGETEVENT:
		SCFDBGMSG(SCF_DBGFLAG_IOMP, "FIOMPGETEVENT proc");

		ret = ENOTTY;
		break;

	default:
		/* undefined */
		SCFDBGMSG(SCF_DBGFLAG_IOMP, "undefined ioctl command");
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "i_ioctl ", 8);
		ret = ENOTTY;
	}

/*
 * END_inst_ioctl
 */
	END_inst_ioctl:

	SCFDBGMSG1(SCF_DBGFLAG_IOMP, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}

/*
 * Make path status : FIOMPSTATUS, FIOMPGETALLSTAT : 32bit-64bit
 */
void
scf_inst_getstat32(scf_state_t *statep, struct fiompstatus_32 *status32_p,
	char *message_p, int flag)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_inst_getstat32() "
	int			path_status;

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_IOMP, SCF_FUNC_NAME ": start");

	if (statep) {
		if (flag) {
			/* Current status */
			path_status = statep->path_status;
		} else {
			/* Former status */
			path_status = statep->old_path_status;
		}
		/* Set status */
		switch (path_status) {
		case FIOMP_STAT_ACTIVE:
			status32_p->status = FIOMP_STAT_ACTIVE;
			break;
		case FIOMP_STAT_STANDBY:
			status32_p->status = FIOMP_STAT_STANDBY;
			break;
		case FIOMP_STAT_STOP:
			status32_p->status = FIOMP_STAT_STOP;
			break;
		case FIOMP_STAT_DISCON:
			status32_p->status = FIOMP_STAT_DISCON;
			break;
		case FIOMP_STAT_FAIL:
			status32_p->status = FIOMP_STAT_FAIL;
			break;
		default:
			status32_p->status = FIOMP_STAT_EMPTY;
		}
		/* IOMP details message making */
		scf_path_stmsg(statep, message_p);
	} else {
		status32_p->status = FIOMP_STAT_EMPTY;
		message_p[0] = '\0';
	}
	status32_p->block_status = FIOMP_BSTAT_BLOCK;

	SCFDBGMSG(SCF_DBGFLAG_IOMP, SCF_FUNC_NAME ": end");
}

/*
 * Make path status : FIOMPSTATUS, FIOMPGETALLSTAT : 64bit-64bit/32bit-32bit
 */
void
scf_inst_getstat(scf_state_t *statep, struct fiompstatus *status_p,
	char *message_p, int flag)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_inst_getstat() "
	int			path_status;

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_IOMP, SCF_FUNC_NAME ": start");

	if (statep) {
		if (flag) {
			/* Current status */
			path_status = statep->path_status;
		} else {
			/* Former status */
			path_status = statep->old_path_status;
		}
		/* Set status */
		switch (path_status) {
		case FIOMP_STAT_ACTIVE:
			status_p->status = FIOMP_STAT_ACTIVE;
			break;
		case FIOMP_STAT_STANDBY:
			status_p->status = FIOMP_STAT_STANDBY;
			break;
		case FIOMP_STAT_STOP:
			status_p->status = FIOMP_STAT_STOP;
			break;
		case FIOMP_STAT_DISCON:
			status_p->status = FIOMP_STAT_DISCON;
			break;
		case FIOMP_STAT_FAIL:
			status_p->status = FIOMP_STAT_FAIL;
			break;
		default:
			status_p->status = FIOMP_STAT_EMPTY;
		}
		/* IOMP details message making */
		scf_path_stmsg(statep, message_p);
	} else {
		status_p->status = FIOMP_STAT_EMPTY;
		message_p[0] = '\0';
	}
	status_p->block_status = FIOMP_BSTAT_BLOCK;

	SCFDBGMSG(SCF_DBGFLAG_IOMP, SCF_FUNC_NAME ": end");
}

/*
 * IOMP details message making
 */
void
scf_path_stmsg(scf_state_t *statep, char *message_p)

{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_path_stmsg() "

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_IOMP, SCF_FUNC_NAME ": start");

	if (statep->scf_herr & HERR_TESUM) {
		strcpy(message_p, "Command error");
	} else if (statep->scf_herr & HERR_RESUM) {
		strcpy(message_p, "Sumcheck error");
	} else if (statep->scf_herr & HERR_CMD_RTO) {
		strcpy(message_p, "Command timeout");
	} else if (statep->scf_herr & HERR_BUSY_RTO) {
		strcpy(message_p, "Command busy timeout");
	} else if (statep->scf_herr & HERR_DSCP_INTERFACE) {
		strcpy(message_p, "SCF communication path error");
	} else if (statep->scf_herr & HERR_DSCP_ACKTO) {
		strcpy(message_p, "DSCP ack response timeout");
	} else if (statep->scf_herr & HERR_DSCP_ENDTO) {
		strcpy(message_p, "DSCP end response timeout");
	} else {
		strcpy(message_p, "Good");
	}

	SCFDBGMSG(SCF_DBGFLAG_IOMP, SCF_FUNC_NAME ": end");
}
#endif
