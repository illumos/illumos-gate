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

#include <sys/ksynch.h>
#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/scfd/scfparam.h>


/*
 * scf_service_putinfo()
 *
 * Description: Data request to send processing from the OS to ESCF.
 *
 */
/* ARGSUSED */
int
scf_service_putinfo(uint32_t key, uint8_t type, uint32_t transid,
	uint32_t length, void *datap)
{
#define	SCF_FUNC_NAME		"scf_service_putinfo() "
	scf_cmd_t		scf_cmd;	/* SCF command table */
	uchar_t			*bufp = NULL;	/* Working value : buff addr */
	int			ret = 0;	/* Return value */
	timeout_id_t		save_tmids[SCF_TIMERCD_MAX];
	int			tm_stop_cnt;

	SCFDBGMSG(SCF_DBGFLAG_SRV, SCF_FUNC_NAME ": start");
	SC_DBG_DRV_TRACE(TC_S_PUTINFO | TC_IN, __LINE__, &key, sizeof (key));

	/* SCF command table clear */
	bzero((void *)&scf_cmd, sizeof (scf_cmd_t));

	/* Lock driver mutex */
	mutex_enter(&scf_comtbl.all_mutex);

	/* Check "key" */
	if (key != KEY_ESCF) {
		/* Invalid "key" */
		SC_DBG_DRV_TRACE(TC_S_PUTINFO | TC_ERRCD, __LINE__, &key,
			sizeof (key));
		ret = EINVAL;
		goto END_service_putinfo;
	}

	/* Check "length" and "datap" */
	if ((length != 0) && (datap == NULL)) {
		/* Invalid "length" or "datap" */
		SC_DBG_DRV_TRACE(TC_S_PUTINFO | TC_ERRCD, __LINE__, &length,
			sizeof (length));
		ret = EINVAL;
		goto END_service_putinfo;
	}

	/* Check "length" is max length */
	if (length > SCF_L_CNT_MAX) {
		/* Invalid "length" */
		SC_DBG_DRV_TRACE(TC_S_PUTINFO | TC_ERRCD, __LINE__, &length,
			sizeof (length));
		ret = EINVAL;
		goto END_service_putinfo;
	}

	/* Check putinfo exec flag */
	if (scf_comtbl.putinfo_exec_flag == FLAG_ON) {
	/* Multiplex, putinfo */
		SC_DBG_DRV_TRACE(TC_S_PUTINFO, __LINE__,
			&scf_comtbl.putinfo_exec_flag,
			sizeof (scf_comtbl.putinfo_exec_flag));
		ret = EBUSY;
		goto END_service_putinfo;
	}

	/* putinfo exec flag ON */
	scf_comtbl.putinfo_exec_flag = FLAG_ON;

	/* Check "length" is 0 */
	if (length != 0) {
		/* Send buffer allocation */
		bufp = (uchar_t *)kmem_zalloc(length, KM_SLEEP);

		/* Data copy to send buffer */
		bcopy(datap, bufp, length);
	}

	/* Make SCF command */
	scf_cmd.flag = SCF_USE_L_BUF;
	scf_cmd.cmd = CMD_OS_XSCF_CTL;
	scf_cmd.subcmd = type;
	scf_cmd.sbuf = bufp;
	scf_cmd.scount = length;
	scf_cmd.rbuf = NULL;
	scf_cmd.rcount = 0;

	/* Send SCF command */
	ret = scf_send_cmd_check_bufful(&scf_cmd);

	/* Check send buffer */
	if (bufp != NULL) {
		/* Send data release */
		kmem_free((void *)bufp, length);
	}

	/* putinfo exec flag OFF */
	scf_comtbl.putinfo_exec_flag = FLAG_OFF;

/*
 * END_service_putinfo
 */
	END_service_putinfo:

	/* Collect the timers which need to be stopped */
	tm_stop_cnt = scf_timer_stop_collect(save_tmids, SCF_TIMERCD_MAX);

	/* Unlock driver mutex */
	mutex_exit(&scf_comtbl.all_mutex);

	/* Timer stop */
	if (tm_stop_cnt != 0) {
		scf_timer_untimeout(save_tmids, SCF_TIMERCD_MAX);
	}

	SC_DBG_DRV_TRACE(TC_S_PUTINFO | TC_OUT, __LINE__, &ret, sizeof (ret));
	SCFDBGMSG1(SCF_DBGFLAG_SRV, SCF_FUNC_NAME ": end return = %d", ret);

	return (ret);
}


/*
 * scf_service_getinfo()
 *
 * Description: Data request to receive processing from the OS to ESCF.
 *
 */
int
scf_service_getinfo(uint32_t key, uint8_t type, uint32_t transid,
	uint32_t *lengthp, void *datap)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_service_getinfo() "
	scf_cmd_t		scf_cmd;	/* SCF command table */
	scf_short_buffer_t	sbuf;		/* Send buffer */
	uchar_t			*bufp = NULL;	/* Working value : buff addr */
	uint_t			wkleng;		/* Working value : length */
	int			ret = 0;	/* Return value */
	timeout_id_t		save_tmids[SCF_TIMERCD_MAX];
	int			tm_stop_cnt;

	SCFDBGMSG(SCF_DBGFLAG_SRV, SCF_FUNC_NAME ": start");
	SC_DBG_DRV_TRACE(TC_S_GETINFO | TC_IN, __LINE__,  &key, sizeof (key));

	/* SCF command table/Send buffer clear */
	bzero((void *)&scf_cmd, sizeof (scf_cmd_t));
	bzero((void *)&sbuf.b[0], SCF_S_CNT_16);

	/* Lock driver mutex */
	mutex_enter(&scf_comtbl.all_mutex);

	/* Check "key" */
	if (key != KEY_ESCF) {
		/* Invalid "key" */
		SC_DBG_DRV_TRACE(TC_S_GETINFO | TC_ERRCD, __LINE__, &key,
			sizeof (key));
		ret = EINVAL;
		goto END_service_getinfo;
	}

	/* Check "lengthp" and "datap" */
	if (lengthp == NULL) {
		/* Invalid "lengthp" */
		SC_DBG_DRV_TRACE(TC_S_GETINFO | TC_ERRCD, __LINE__, &lengthp,
			sizeof (lengthp));
		ret = EINVAL;
		goto END_service_getinfo;
	}

	/* Check "lengthp" is max length */
	if (*lengthp > SCF_L_CNT_MAX) {
		/* Invalid "lengthp" */
		SC_DBG_DRV_TRACE(TC_S_GETINFO | TC_ERRCD, __LINE__, lengthp,
			sizeof (*lengthp));
		ret = EINVAL;
		goto END_service_getinfo;
	}

	/* Check, parameter "length" and "datap" */
	if ((*lengthp != 0) && (datap == NULL)) {
		/* Invalid "lengthp" or "datap" */
		SC_DBG_DRV_TRACE(TC_S_GETINFO | TC_ERRCD, __LINE__, lengthp,
			sizeof (*lengthp));
		ret = EINVAL;
		goto END_service_getinfo;
	}

	/* Check getinfo exec flag */
	if (scf_comtbl.getinfo_exec_flag == FLAG_ON) {
		/* Multiplex, getinfo */
		SC_DBG_DRV_TRACE(TC_S_GETINFO, __LINE__,
			&scf_comtbl.getinfo_exec_flag,
			sizeof (scf_comtbl.getinfo_exec_flag));
		ret = EBUSY;
		goto END_service_getinfo;
	}

	/* getinfo exec flag ON */
	scf_comtbl.getinfo_exec_flag = FLAG_ON;

	/* Check "lengthp" is 0 */
	if (*lengthp != 0) {
		/*
		 * Receive buffer allocation
		 */
		wkleng = *lengthp;
		bufp = (uchar_t *)kmem_zalloc(wkleng, KM_SLEEP);
	} else {
		wkleng = 0;
	}

	/* Make SCF command */
	sbuf.four_bytes_access[0] = transid;
	scf_cmd.flag = SCF_USE_SLBUF;
	scf_cmd.cmd = CMD_OS_XSCF_CTL;
	scf_cmd.subcmd = type;
	scf_cmd.scount = SCF_S_CNT_15;
	scf_cmd.sbuf = &sbuf.b[0];
	scf_cmd.rcount = wkleng;
	scf_cmd.rbuf = bufp;

	/* Send SCF command */
	ret = scf_send_cmd_check_bufful(&scf_cmd);

	/* Check return code */
	if (ret == 0) {
		/* Set receive length */
		if (*lengthp > scf_cmd.rbufleng) {
			/* Set receive data length */
			*lengthp = scf_cmd.rbufleng;
		}

		/* Check receive data length is not 0 */
		if (*lengthp != 0) {
			/* Data copy to "datap" */
			bcopy(bufp, datap, *lengthp);
		}
	}

	/* Check receive buffer */
	if (bufp != NULL) {
		/*
		 * Receive data release
		 */
		kmem_free((void *)bufp, wkleng);
	}

	/* getinfo exec flag OFF */
	scf_comtbl.getinfo_exec_flag = FLAG_OFF;

/*
 * END_service_getinfo
 */
	END_service_getinfo:

	/* Collect the timers which need to be stopped */
	tm_stop_cnt = scf_timer_stop_collect(save_tmids, SCF_TIMERCD_MAX);

	/* Unlock driver mutex */
	mutex_exit(&scf_comtbl.all_mutex);

	/* Timer stop */
	if (tm_stop_cnt != 0) {
		scf_timer_untimeout(save_tmids, SCF_TIMERCD_MAX);
	}

	SC_DBG_DRV_TRACE(TC_S_GETINFO | TC_OUT, __LINE__, &ret, sizeof (ret));
	SCFDBGMSG1(SCF_DBGFLAG_SRV, SCF_FUNC_NAME ": end return = %d", ret);

	return (ret);
}
