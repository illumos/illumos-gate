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
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/scfd/scfparam.h>
#include <sys/scfd/scfdscp.h>

#ifdef DEBUG
/*
 * Function list
 */
int	scf_snapshotsize(intptr_t arg, int mode);
int	scf_get_snapize(int type, int info);
int	scf_snapshot(intptr_t arg, int mode);
int	scf_get_snap(int type, int info, scfsnap_value_t *snap_p,
		int snap_size);


/*
 * External function
 */
extern	scf_dscp_comtbl_t	scf_dscp_comtbl;


/*
 * scf_snapshotsize()
 */
int
scf_snapshotsize(intptr_t arg, int mode)
{
#define	SCF_FUNC_NAME		"scf_snapshotsize() "
	int			snap_size;
	scfsnapsize_t		scfsnapsize;
	int			ret = 0;

	SCFDBGMSG(SCF_DBGFLAG_SNAP, SCF_FUNC_NAME ": start");

	if (ddi_copyin((void *)arg, (void *)&scfsnapsize,
		sizeof (scfsnapsize_t), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "dbg_snap", 8);
		ret = EFAULT;
		goto END_snapshotsize;
	}

	if (mutex_tryenter(&scf_comtbl.all_mutex) != 0) {
		snap_size = scf_get_snapize(scfsnapsize.type, scfsnapsize.info);

		mutex_exit(&scf_comtbl.all_mutex);

		if (snap_size == (-1)) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"dbg_snap", 8);
			ret = EINVAL;
			goto END_snapshotsize;
		}

		scfsnapsize.size = snap_size;

		if (ddi_copyout((void *)&scfsnapsize, (void *)arg,
			sizeof (scfsnapsize_t), mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"dbg_snap", 8);
			ret = EFAULT;
		}
	} else {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "dbg_snap", 8);
		ret = EBUSY;
	}

/*
 * END_snapshotsize
 */
	END_snapshotsize:

	SCFDBGMSG1(SCF_DBGFLAG_SNAP, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_get_snapize()
 */
int
scf_get_snapize(int type, int info)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_get_snapize() "
	scf_state_t		*statep = NULL;
	int			wk_size;
	int			ii;
	int			snap_driver_size;
	int			snap_register_size;
	int			snap_sram_size;
	int			ret = 0;

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG1(SCF_DBGFLAG_SNAP, SCF_FUNC_NAME ": start type = %d", type);

	if (info == SCFSNAPINFO_AUTO) {
		statep = scf_comtbl.scf_exec_p;
		if (statep == NULL) {
			statep = scf_comtbl.scf_path_p;
		}
	} else if (info < scf_comtbl.path_num) {
		statep = scf_comtbl.iomp_scf[info];
	} else {
		SC_DBG_DRV_TRACE(TC_ERR, __LINE__, "snapsize", 8);
		ret = (-1);
		goto END_get_snapize;
	}

	/* Set driver area size */
	wk_size = DRV_ID_SIZE;
	wk_size = sizeof (scfsnap_value_t) +
	    ((wk_size + SCF_S_CNT_15) & SCF_LENGTH_16BYTE_CNV);
	snap_driver_size = wk_size;

	wk_size = sizeof (scf_timer);
	wk_size = sizeof (scfsnap_value_t) +
		((wk_size + SCF_S_CNT_15) & SCF_LENGTH_16BYTE_CNV);
	snap_driver_size += wk_size;

	wk_size = sizeof (scf_comtbl_t);
	wk_size = sizeof (scfsnap_value_t) +
		((wk_size + SCF_S_CNT_15) & SCF_LENGTH_16BYTE_CNV);
	snap_driver_size += wk_size;

	if (statep != NULL) {
		wk_size = sizeof (scf_state_t);
		wk_size = sizeof (scfsnap_value_t) +
			((wk_size + SCF_S_CNT_15) & SCF_LENGTH_16BYTE_CNV);
		snap_driver_size += wk_size;
	}

	wk_size = sizeof (scf_dscp_comtbl_t);
	wk_size = sizeof (scfsnap_value_t) +
		((wk_size + SCF_S_CNT_15) & SCF_LENGTH_16BYTE_CNV);
	snap_driver_size += wk_size;

	if (scf_dscp_comtbl.tx_dscp != NULL) {
		wk_size = scf_dscp_comtbl.tx_dscsize;
		wk_size = sizeof (scfsnap_value_t) +
			((wk_size + SCF_S_CNT_15) & SCF_LENGTH_16BYTE_CNV);
		snap_driver_size += wk_size;
	}

	if (scf_dscp_comtbl.rx_dscp != NULL) {
		wk_size = scf_dscp_comtbl.rx_dscsize;
		wk_size = sizeof (scfsnap_value_t) +
			((wk_size + SCF_S_CNT_15) & SCF_LENGTH_16BYTE_CNV);
		snap_driver_size += wk_size;
	}

	if (scf_dscp_comtbl.tx_sramp != NULL) {
		wk_size = scf_dscp_comtbl.tx_sramsize;
		wk_size = sizeof (scfsnap_value_t) +
			((wk_size + SCF_S_CNT_15) & SCF_LENGTH_16BYTE_CNV);
		snap_driver_size += wk_size;
	}

	for (ii = 0; ii < MBIF_MAX; ii++) {
		if (scf_dscp_comtbl.scf_dscp_main[ii].ev_quep != NULL) {
			wk_size = scf_dscp_comtbl.scf_dscp_main[ii].ev_quesize;
			wk_size = sizeof (scfsnap_value_t) +
				((wk_size + SCF_S_CNT_15) &
				SCF_LENGTH_16BYTE_CNV);
			snap_driver_size += wk_size;
		}
		if (scf_dscp_comtbl.scf_dscp_main[ii].rd_datap != NULL) {
			wk_size = scf_dscp_comtbl.scf_dscp_main[ii].rd_datasize;
			wk_size = sizeof (scfsnap_value_t) +
				((wk_size + SCF_S_CNT_15) &
				SCF_LENGTH_16BYTE_CNV);
			snap_driver_size += wk_size;
		}
	}

	/* Set register area size */
	if (statep != NULL) {
		wk_size = sizeof (scf_regs_t) + sizeof (scf_regs_c_t);
		wk_size = sizeof (scfsnap_value_t) +
			((wk_size + SCF_S_CNT_15) & SCF_LENGTH_16BYTE_CNV);
		snap_register_size = wk_size;
	} else {
		snap_register_size = 0;
	}

	/* Set sram area size */
	if (statep != NULL) {
		wk_size = sizeof (scf_dscp_sram_t) +
			sizeof (scf_sys_sram_t) + statep->scf_reg_drvtrc_len;
		wk_size = sizeof (scfsnap_value_t) +
			((wk_size + SCF_S_CNT_15) & SCF_LENGTH_16BYTE_CNV);
		snap_sram_size = wk_size;
	} else {
		snap_sram_size = 0;
	}

	switch (type) {
	case SCFSNAPTYPE_ALL:
		/* Set all area snap size */
		if (statep != NULL) {
			ret = snap_driver_size + snap_register_size +
				snap_sram_size;
		} else {
			ret = snap_driver_size;
		}
		break;

	case SCFSNAPTYPE_DRIVER:
		/* Set driver area snap size */
		ret = snap_driver_size;
		break;

	case SCFSNAPTYPE_REGISTER:
		/* Set register area snap size */
		ret = snap_register_size;
		break;

	case SCFSNAPTYPE_SRAM:
		/* Set use SRAM area snap size */
		ret = snap_sram_size;
		break;

	default:
		/* Invalid parameter */
		SC_DBG_DRV_TRACE(TC_ERR, __LINE__, "snapsize", 8);
		ret = (-1);
		break;
	}

/*
 * END_get_snapize
 */
	END_get_snapize:

	SCFDBGMSG1(SCF_DBGFLAG_SNAP, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_snapshot()
 */
int
scf_snapshot(intptr_t arg, int mode)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_snapshot() "
	int			snap_size;
	scfsnap_t		scfsnap;
	scfsnap32_t		scfsnap32;
	scfsnap_value_t		*scfsnap_p = NULL;
	int			ret = 0;

	SCFDBGMSG(SCF_DBGFLAG_SNAP, SCF_FUNC_NAME ": start");

#ifdef _MULTI_DATAMODEL
	switch (ddi_model_convert_from(mode & FMODELS)) {
	case DDI_MODEL_ILP32:
		if (ddi_copyin((void *)arg, (void *)&scfsnap32,
			sizeof (scfsnap32_t), mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"dbg_snap", 8);
			ret = EFAULT;
			goto END_snapshot;
		}
		scfsnap.type = scfsnap32.type;
		scfsnap.info = scfsnap32.info;
		break;

	case DDI_MODEL_NONE:
		if (ddi_copyin((void *)arg, (void *)&scfsnap,
			sizeof (scfsnap_t), mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"dbg_snap", 8);
			ret = EFAULT;
			goto END_snapshot;
		}
		break;
	}
#else /* ! _MULTI_DATAMODEL */
	if (ddi_copyin((void *)arg, (void *)&scfsnap,
		sizeof (scfsnap_t), mode) != 0) {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "dbg_snap", 8);
		ret = EFAULT;
		goto END_snapshot;
	}
#endif /* _MULTI_DATAMODEL */

	if (mutex_tryenter(&scf_comtbl.all_mutex) != 0) {

		snap_size = scf_get_snapize(scfsnap.type, scfsnap.info);

		if (snap_size == (-1)) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"dbg_snap", 8);
			mutex_exit(&scf_comtbl.all_mutex);
			ret = EINVAL;
			goto END_snapshot;
		}

		if (snap_size != 0) {
			scfsnap_p = kmem_zalloc((size_t)snap_size, KM_SLEEP);

			ret = scf_get_snap(scfsnap.type, scfsnap.info,
				scfsnap_p, snap_size);
		} else {
			ret = ENODATA;
		}

		mutex_exit(&scf_comtbl.all_mutex);
	} else {
		SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__, "dbg_snap", 8);
		ret = EBUSY;
	}

	if (ret == 0) {

#ifdef _MULTI_DATAMODEL
		switch (ddi_model_convert_from(mode & FMODELS)) {
		case DDI_MODEL_ILP32:
			if (ddi_copyout((void *)scfsnap_p,
				(void *)(uintptr_t)scfsnap32.ss_entries,
				(size_t)snap_size, mode) != 0) {
				SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
					"dbg_snap", 8);
				ret = EFAULT;
			}

			break;

		case DDI_MODEL_NONE:
			if (ddi_copyout((void *)scfsnap_p,
				(void *)scfsnap.ss_entries,
				(size_t)snap_size, mode) != 0) {
				SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
					"dbg_snap", 8);
				ret = EFAULT;
			}
			break;
		}

#else /* ! _MULTI_DATAMODEL */
		if (ddi_copyout((void *)scfsnap_p, (void *)scfsnap.ss_entries,
			(size_t)snap_size, mode) != 0) {
			SC_DBG_DRV_TRACE(TC_IOCTL|TC_ERR, __LINE__,
				"dbg_snap", 8);
			ret = EFAULT;
		}
#endif /* _MULTI_DATAMODEL */
	}

/*
 * END_snapshot
 */
	END_snapshot:

	if (scfsnap_p) {
		kmem_free((void *)scfsnap_p,
			(size_t)snap_size);
	}

	SCFDBGMSG1(SCF_DBGFLAG_SNAP, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_get_snap()
 */
int
scf_get_snap(int type, int info, scfsnap_value_t *snap_top_p, int snap_size)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_get_snap() "
	scf_state_t		*statep;
	scfsnap_value_t		*snap_p;
	int			wk_size;
	int			wk_nextoff;
	int			exec_model;
	uint8_t			*wk_in_p;
	uint8_t			*wk_out_p;
	scf_dscp_main_t		*mainp;
	scf_regs_t		*wk_regs_p;
	scf_regs_c_t		*wk_regs_c_p;
	int			ii;

	int			ret = 0;

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG1(SCF_DBGFLAG_SNAP, SCF_FUNC_NAME ": start type = %d", type);

#ifdef _MULTI_DATAMODEL
	exec_model = SCF_DRIVER_64BIT;
#else /* ! _MULTI_DATAMODEL */
	exec_model = SCF_DRIVER_32BIT;
#endif /* _MULTI_DATAMODEL */

	if ((scf_get_snapize(type, info) > snap_size) || (snap_size <= 0)) {
		SC_DBG_DRV_TRACE(TC_ERR, __LINE__, "snapshot", 8);
		ret = EINVAL;
		goto END_get_snap;
	}

	if (info == SCFSNAPINFO_AUTO) {
		statep = scf_comtbl.scf_exec_p;
		if (statep == NULL) {
			statep = scf_comtbl.scf_path_p;
		}
	} else if (info < scf_comtbl.path_num) {
		statep = scf_comtbl.iomp_scf[info];
	} else {
		SC_DBG_DRV_TRACE(TC_ERR, __LINE__, "snapshot", 8);
		ret = EINVAL;
		goto END_get_snap;
	}

	snap_p = snap_top_p;
	wk_nextoff = 0;
	if ((type == SCFSNAPTYPE_ALL) || (type == SCFSNAPTYPE_DRIVER)) {
		/* Set driver vl area */
		strcpy((char *)&snap_p->ss_name[0], SNAP_SCF_DRIVER_VL);
		wk_size = sizeof (SCF_DRIVER_VERSION);
		if (wk_size > DRV_ID_SIZE) {
			wk_size = DRV_ID_SIZE;
		}
		wk_nextoff += (sizeof (scfsnap_value_t) +
		    ((wk_size + SCF_S_CNT_15) & SCF_LENGTH_16BYTE_CNV));
		snap_p->ss_flag = exec_model;
		snap_p->ss_size = wk_size;
		snap_p->ss_nextoff = wk_nextoff;
		bcopy((void *)SCF_DRIVER_VERSION,
			(void *)(snap_p + 1), wk_size);
		snap_p = (void *)((caddr_t)snap_top_p + wk_nextoff);

		/* Set driver timer area */
		strcpy((char *)&snap_p->ss_name[0], SNAP_SCF_TIMER_TBL);
		wk_size = sizeof (scf_timer);
		wk_nextoff += (sizeof (scfsnap_value_t) +
			((wk_size + SCF_S_CNT_15) & SCF_LENGTH_16BYTE_CNV));
		snap_p->ss_flag = exec_model;
		snap_p->ss_size = wk_size;
		snap_p->ss_nextoff = wk_nextoff;
		bcopy((void *)scf_timer, (void *)(snap_p + 1), wk_size);
		snap_p = (void *)((caddr_t)snap_top_p + wk_nextoff);

		/* Set driver common area */
		strcpy((char *)&snap_p->ss_name[0], SNAP_SCF_COMTBL);
		wk_size = sizeof (scf_comtbl);
		wk_nextoff += (sizeof (scfsnap_value_t) +
			((wk_size + SCF_S_CNT_15) & SCF_LENGTH_16BYTE_CNV));
		snap_p->ss_flag = exec_model;
		snap_p->ss_size = wk_size;
		snap_p->ss_nextoff = wk_nextoff;
		bcopy((void *)&scf_comtbl, (void *)(snap_p + 1), wk_size);
		snap_p = (void *)((caddr_t)snap_top_p + wk_nextoff);

		if (statep != NULL) {
			/* Set device area */
			strcpy((char *)&snap_p->ss_name[0], SNAP_SCF_STATE);
			wk_size = sizeof (scf_state_t);
			wk_nextoff += (sizeof (scfsnap_value_t) +
				((wk_size + SCF_S_CNT_15) &
				SCF_LENGTH_16BYTE_CNV));
			snap_p->ss_flag = exec_model;
			snap_p->ss_size = wk_size;
			snap_p->ss_nextoff = wk_nextoff;
			bcopy((void *)statep, (void *)(snap_p + 1), wk_size);
			snap_p = (void *)((caddr_t)snap_top_p + wk_nextoff);
		}

		/* Set driver DSCP common area */
		strcpy((char *)&snap_p->ss_name[0], SNAP_SCF_DSCP_COMTBL);
		wk_size = sizeof (scf_dscp_comtbl_t);
		wk_nextoff += (sizeof (scfsnap_value_t) +
			((wk_size + SCF_S_CNT_15) & SCF_LENGTH_16BYTE_CNV));
		snap_p->ss_flag = exec_model;
		snap_p->ss_size = wk_size;
		snap_p->ss_nextoff = wk_nextoff;
		bcopy((void *)&scf_dscp_comtbl, (void *)(snap_p + 1), wk_size);
		snap_p = (void *)((caddr_t)snap_top_p + wk_nextoff);

		/* Set driver DSCP TxDSC area */
		if (scf_dscp_comtbl.tx_dscp != NULL) {
			strcpy((char *)&snap_p->ss_name[0],
				SNAP_SCF_DSCP_TXDSC);
			wk_size = scf_dscp_comtbl.tx_dscsize;
			wk_nextoff += (sizeof (scfsnap_value_t) +
				((wk_size + SCF_S_CNT_15) &
				SCF_LENGTH_16BYTE_CNV));
			snap_p->ss_flag = exec_model;
			snap_p->ss_size = wk_size;
			snap_p->ss_nextoff = wk_nextoff;
			bcopy((void *)scf_dscp_comtbl.tx_dscp,
				(void *)(snap_p + 1), wk_size);
			snap_p = (void *)((caddr_t)snap_top_p + wk_nextoff);
		}

		/* Set driver DSCP RxDSC area */
		if (scf_dscp_comtbl.rx_dscp != NULL) {
			strcpy((char *)&snap_p->ss_name[0],
				SNAP_SCF_DSCP_RXDSC);
			wk_size = scf_dscp_comtbl.rx_dscsize;
			wk_nextoff += (sizeof (scfsnap_value_t) +
				((wk_size + SCF_S_CNT_15) &
				SCF_LENGTH_16BYTE_CNV));
			snap_p->ss_flag = exec_model;
			snap_p->ss_size = wk_size;
			snap_p->ss_nextoff = wk_nextoff;
			bcopy((void *)scf_dscp_comtbl.rx_dscp,
				(void *)(snap_p + 1), wk_size);
			snap_p = (void *)((caddr_t)snap_top_p + wk_nextoff);
		}

		/* Set driver DSCP Tx SRAM area */
		if (scf_dscp_comtbl.tx_sramp != NULL) {
			strcpy((char *)&snap_p->ss_name[0],
				SNAP_SCF_DSCP_TXSRAM);
			wk_size = scf_dscp_comtbl.tx_sramsize;
			wk_nextoff += (sizeof (scfsnap_value_t) +
				((wk_size + SCF_S_CNT_15) &
				SCF_LENGTH_16BYTE_CNV));
			snap_p->ss_flag = exec_model;
			snap_p->ss_size = wk_size;
			snap_p->ss_nextoff = wk_nextoff;
			bcopy((void *)scf_dscp_comtbl.tx_sramp,
				(void *)(snap_p + 1), wk_size);
			snap_p = (void *)((caddr_t)snap_top_p + wk_nextoff);
		}

		for (ii = 0; ii < MBIF_MAX; ii++) {
			mainp = &scf_dscp_comtbl.scf_dscp_main[ii];
			/* Set driver DSCP Event data area */
			if (mainp->ev_quep != NULL) {
				strcpy((char *)&snap_p->ss_name[0],
					SNAP_SCF_DSCP_EVENT);
				wk_size = mainp->ev_quesize;
				wk_nextoff += (sizeof (scfsnap_value_t) +
					((wk_size + SCF_S_CNT_15) &
					SCF_LENGTH_16BYTE_CNV));
				snap_p->ss_flag = exec_model;
				snap_p->ss_size = wk_size;
				snap_p->ss_nextoff = wk_nextoff;
				bcopy((void *)mainp->ev_quep,
					(void *)(snap_p + 1), wk_size);
				snap_p = (void *)((caddr_t)snap_top_p +
					wk_nextoff);
			}
			/* Set driver DSCP Recv data area */
			if (mainp->rd_datap != NULL) {
				strcpy((char *)&snap_p->ss_name[0],
					SNAP_SCF_DSCP_RDATA);
				wk_size = mainp->rd_datasize;
				wk_nextoff += (sizeof (scfsnap_value_t) +
					((wk_size + SCF_S_CNT_15) &
					SCF_LENGTH_16BYTE_CNV));
				snap_p->ss_flag = exec_model;
				snap_p->ss_size = wk_size;
				snap_p->ss_nextoff = wk_nextoff;
				bcopy((void *)mainp->rd_datap,
					(void *)(snap_p + 1), wk_size);
				snap_p = (void *)((caddr_t)snap_top_p +
					wk_nextoff);
			}
		}
	}

	if ((type == SCFSNAPTYPE_ALL) || (type == SCFSNAPTYPE_REGISTER)) {
		if (statep != NULL) {
			/* Set register area */
			strcpy((char *)&snap_p->ss_name[0], SNAP_REGISTER);
			wk_size = sizeof (scf_regs_t) + sizeof (scf_regs_c_t);
			wk_nextoff += (sizeof (scfsnap_value_t) +
				((wk_size + SCF_S_CNT_15) &
				SCF_LENGTH_16BYTE_CNV));
			snap_p->ss_flag = exec_model;
			snap_p->ss_size = wk_size;
			snap_p->ss_nextoff = wk_nextoff;

			wk_regs_p = (scf_regs_t *)(snap_p + 1);
			wk_regs_p->COMMAND = SCF_DDI_GET16(statep,
				statep->scf_regs_handle,
				&statep->scf_regs->COMMAND);
			wk_regs_p->STATUS = SCF_DDI_GET16(statep,
				statep->scf_regs_handle,
				&statep->scf_regs->STATUS);
			wk_regs_p->VERSION = SCF_DDI_GET8(statep,
				statep->scf_regs_handle,
				&statep->scf_regs->VERSION);
			wk_regs_p->TDATA0 = SCF_DDI_GET32(statep,
				statep->scf_regs_handle,
				&statep->scf_regs->TDATA0);
			wk_regs_p->TDATA1 = SCF_DDI_GET32(statep,
				statep->scf_regs_handle,
				&statep->scf_regs->TDATA1);
			wk_regs_p->TDATA2 = SCF_DDI_GET32(statep,
				statep->scf_regs_handle,
				&statep->scf_regs->TDATA2);
			wk_regs_p->TDATA3 = SCF_DDI_GET32(statep,
				statep->scf_regs_handle,
				&statep->scf_regs->TDATA3);
			wk_regs_p->RDATA0 = SCF_DDI_GET32(statep,
				statep->scf_regs_handle,
				&statep->scf_regs->RDATA0);
			wk_regs_p->RDATA1 = SCF_DDI_GET32(statep,
				statep->scf_regs_handle,
				&statep->scf_regs->RDATA1);
			wk_regs_p->RDATA2 = SCF_DDI_GET32(statep,
				statep->scf_regs_handle,
				&statep->scf_regs->RDATA2);
			wk_regs_p->RDATA3 = SCF_DDI_GET32(statep,
				statep->scf_regs_handle,
				&statep->scf_regs->RDATA3);
			wk_regs_p->COMMAND_ExR = SCF_DDI_GET8(statep,
				statep->scf_regs_handle,
				&statep->scf_regs->COMMAND_ExR);
			wk_regs_p->ACR = SCF_DDI_GET8(statep,
				statep->scf_regs_handle,
				&statep->scf_regs->ACR);
			wk_regs_p->ATR = SCF_DDI_GET8(statep,
				statep->scf_regs_handle,
				&statep->scf_regs->ATR);
			wk_regs_p->STATUS_ExR = SCF_DDI_GET32(statep,
				statep->scf_regs_handle,
				&statep->scf_regs->STATUS_ExR);
			wk_regs_p->DCR = SCF_DDI_GET8(statep,
				statep->scf_regs_handle,
				&statep->scf_regs->DCR);
			wk_regs_p->DSR = SCF_DDI_GET8(statep,
				statep->scf_regs_handle,
				&statep->scf_regs->DSR);
			wk_regs_p->TxDCR_C_FLAG = SCF_DDI_GET16(statep,
				statep->scf_regs_handle,
				&statep->scf_regs->TxDCR_C_FLAG);
			wk_regs_p->TxDCR_OFFSET = SCF_DDI_GET16(statep,
				statep->scf_regs_handle,
				&statep->scf_regs->TxDCR_OFFSET);
			wk_regs_p->TxDCR_LENGTH = SCF_DDI_GET32(statep,
				statep->scf_regs_handle,
				&statep->scf_regs->TxDCR_LENGTH);
			wk_regs_p->TxDSR_C_FLAG = SCF_DDI_GET16(statep,
				statep->scf_regs_handle,
				&statep->scf_regs->TxDSR_C_FLAG);
			wk_regs_p->TxDSR_OFFSET = SCF_DDI_GET16(statep,
				statep->scf_regs_handle,
				&statep->scf_regs->TxDSR_OFFSET);
			wk_regs_p->RxDCR_C_FLAG = SCF_DDI_GET16(statep,
				statep->scf_regs_handle,
				&statep->scf_regs->RxDCR_C_FLAG);
			wk_regs_p->RxDCR_OFFSET = SCF_DDI_GET16(statep,
				statep->scf_regs_handle,
				&statep->scf_regs->RxDCR_OFFSET);
			wk_regs_p->RxDCR_LENGTH = SCF_DDI_GET32(statep,
				statep->scf_regs_handle,
				&statep->scf_regs->RxDCR_LENGTH);
			wk_regs_p->RxDSR_C_FLAG = SCF_DDI_GET16(statep,
				statep->scf_regs_handle,
				&statep->scf_regs->RxDSR_C_FLAG);
			wk_regs_p->RxDSR_OFFSET = SCF_DDI_GET16(statep,
				statep->scf_regs_handle,
				&statep->scf_regs->RxDSR_OFFSET);

			wk_regs_c_p = (scf_regs_c_t *)(wk_regs_p + 1);
			wk_regs_c_p->CONTROL = SCF_DDI_GET16(statep,
				statep->scf_regs_c_handle,
				&statep->scf_regs_c->CONTROL);
			wk_regs_c_p->INT_ST = SCF_DDI_GET16(statep,
				statep->scf_regs_c_handle,
				&statep->scf_regs_c->INT_ST);

			snap_p = (void *)((caddr_t)snap_top_p + wk_nextoff);
		} else {
			if (type == SCFSNAPTYPE_REGISTER) {
				ret = ENODATA;
			}
		}
	}


	if ((type == SCFSNAPTYPE_ALL) || (type == SCFSNAPTYPE_SRAM)) {
		if (statep != NULL) {
			/* Set use SRAM area */
			strcpy((char *)&snap_p->ss_name[0], SNAP_SRAM);
			wk_size = sizeof (scf_dscp_sram_t) +
				sizeof (scf_sys_sram_t) +
				statep->scf_reg_drvtrc_len;
			wk_nextoff += (sizeof (scfsnap_value_t) +
				((wk_size + SCF_S_CNT_15) &
				SCF_LENGTH_16BYTE_CNV));
			snap_p->ss_flag = exec_model;
			snap_p->ss_size = wk_size;
			snap_p->ss_nextoff = wk_nextoff;

			wk_in_p = (uint8_t *)&statep->scf_dscp_sram->DATA[0];
			wk_out_p = (uint8_t *)(snap_p + 1);
			for (ii = 0; ii < sizeof (scf_dscp_sram_t);
				ii++, wk_in_p++, wk_out_p++) {
				*wk_out_p = SCF_DDI_GET8(statep,
					statep->scf_dscp_sram_handle, wk_in_p);
			}

			wk_in_p = (uint8_t *)&statep->scf_sys_sram->DATA[0];
			for (ii = 0; ii < sizeof (scf_sys_sram_t);
				ii++, wk_in_p++, wk_out_p++) {
				*wk_out_p = SCF_DDI_GET8(statep,
					statep->scf_sys_sram_handle, wk_in_p);
			}

			wk_in_p = (uint8_t *)statep->scf_reg_drvtrc;
			for (ii = 0; ii < statep->scf_reg_drvtrc_len;
				ii++, wk_in_p++, wk_out_p++) {
				*wk_out_p = SCF_DDI_GET8(statep,
					statep->scf_reg_drvtrc_handle, wk_in_p);
			}
			snap_p = (void *)((caddr_t)snap_top_p + wk_nextoff);
		} else {
			if (type == SCFSNAPTYPE_SRAM) {
				ret = ENODATA;
			}
		}
	}

/*
 * END_get_snap
 */
	END_get_snap:

	SCFDBGMSG1(SCF_DBGFLAG_SNAP, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}
#endif /* DEBUG */
