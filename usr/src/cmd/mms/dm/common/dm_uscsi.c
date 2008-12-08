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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <sys/types.h>
#include <sys/scsi/impl/uscsi.h>
#include <sys/scsi/generic/sense.h>
#include <sys/scsi/generic/status.h>
#include <unistd.h>
#include <stropts.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <mms_trace.h>
#include <dmd_impl.h>
#include <dm_impl.h>
#include <dm_drive.h>
#include <dm_msg.h>
#include <mms_sym.h>
#include <mms_list.h>
#include <mms_scsi.h>
#include <dm_proto.h>
#include <mms_strapp.h>

static	char *_SrcFile = __FILE__;

/*
 * Process scsi error
 */
void
dm_scsi_error(int err, int status,
    int cdblen, uchar_t *cdb, int senlen, uchar_t *sense)
{
	char		dumpbuf[MMS_DUMPBUF_SIZE(DRV_SENSE_LEN)];
	char		*error;
	char		*scsi_err;
	drv_skaa_t	*skaa;
	char		*buf;

	serr->se_errno = err;
	serr->se_status = status;
	/* Save cdb */
	memcpy((char *)serr->se_cdb, cdb, cdblen);
	serr->se_cdblen = cdblen;
	serr->se_senlen = senlen;
	if (senlen > 0) {
		/* Save sense */
		memcpy((char *)serr->se_sense, sense, senlen);
		serr->se_flags |= DRV_SE_SEN_VALID;
		if (serr->se_flags & DRV_SE_USCSI) {
			/*
			 * If uscsi, save sense key in erreg
			 */
			serr->se_senkey = serr->se_sense[2] & 0x0f;
		}
		if (serr->se_resid == -1) {
			/* get resid from sense bytes if not already have it */
			char_to_int64((signed char *)serr->se_sense + 3, 4,
			    (int64_t *)&serr->se_resid);
		}
		serr->se_flags |= serr->se_sense[0] & 0x80 ?
		    DRV_SE_SEN_VALID : 0;
		serr->se_flags |= serr->se_sense[2] & 0x20 ?
		    DRV_SE_ILI : 0;
		drv->drv_flags |= serr->se_sense[2] & 0x80 ?
		    DRV_TM : 0;
		drv->drv_flags |= serr->se_sense[2] & 0x40 ?
		    DRV_EOM : 0;
	}

	/*
	 * Trace the error
	 */
	(void) mms_trace_dump((char *)serr->se_cdb, serr->se_cdblen, dumpbuf,
	    sizeof (dumpbuf));
	TRACE((MMS_ERR, "SCSI command error: %s, cdb %s",
	    mms_scsi_status(serr->se_status), dumpbuf));
	error = mms_strnew("%s", strerror(serr->se_errno));

	if (serr->se_status == STATUS_CHECK) {
		if (serr->se_senlen) {
			skaa = dm_skaa_lookup(serr->se_senkey, serr->se_asc,
			    serr->se_ascq);
			serr->se_errcl = skaa->drv_ec;
			(void) mms_trace_dump((char *)serr->se_sense,
			    serr->se_senlen, dumpbuf, sizeof (dumpbuf));
			TRACE((MMS_ERR, "Sense bytes: %s", dumpbuf));
			buf = mms_format_sense((struct scsi_extended_sense *)
			    &serr->se_sense);
			if (buf) {
				TRACE((MMS_ERR, "Sense Data: %s", buf));
				free(buf);
			}
			scsi_err = mms_strnew("key %s, acs %2.2x, "
			    "acsq %2.2x, resid %lld: %s",
			    mms_scsi_sensekey(serr->se_senkey),
			    serr->se_asc, serr->se_ascq, serr->se_resid,
			    skaa->drv_text);
			serr->se_err_text = skaa->drv_text;
		}
	} else {
		scsi_err = mms_strnew("%s", "no sense bytes");
	}
	DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
	    "%s, status %s, %s",
	    error, mms_scsi_status(serr->se_status), scsi_err));
	free(error);
	free(scsi_err);
	mms_trace_flush();
}

int
dm_uscsi(struct uscsi_cmd *us)
{
	int		rc;
	uchar_t		senbuf[DRV_SENSE_LEN];

	if (us->uscsi_buflen > DRV_IOBUF_LEN) {
		/* Reduce io size to size of io buf */
		us->uscsi_buflen = DRV_IOBUF_LEN;
	}
	us->uscsi_rqlen = DRV_SENSE_LEN;
	us->uscsi_rqbuf = (char *)senbuf;
	/* must set USCSI_RQENABLE to get sense */
	us->uscsi_flags |= (USCSI_SILENT | USCSI_RQENABLE);

	memset(serr, 0, sizeof (drv_scsi_err_t));
	rc = dm_ioctl(USCSICMD, us);
	return (rc);
}

void
dm_err_trace(void)
{
	TRACE((MMS_ERR, "type %d, status %s, sense key %s, resid %lld, "
	    "fileno %lld, blkno %lld, flags %16.16x",
	    serr->se_type, mms_scsi_status(serr->se_status),
	    mms_scsi_sensekey(serr->se_senkey), serr->se_resid,
	    serr->se_fileno, serr->se_blkno, serr->se_flags));

}

void
dm_get_mtstat(int save)
{
	struct		mtget mtstat;
	int		err = errno;

	if (ioctl(drv->drv_fd, MTIOCGET, &mtstat)) {
		TRACE((MMS_ERR, "Unable to get error status"));
		return;
	}

	memset(serr, 0, sizeof (drv_scsi_err_t));
	serr->se_errno = err;
	serr->se_type = mtstat.mt_type;
	serr->se_status = mtstat.mt_dsreg;
	serr->se_senkey = mtstat.mt_erreg;
	serr->se_resid = mtstat.mt_resid;
	serr->se_fileno = mtstat.mt_fileno;
	serr->se_blkno = mtstat.mt_blkno;
	serr->se_mt_flags = mtstat.mt_flags;
	serr->se_mt_bf = mtstat.mt_bf;

	TRACE((MMS_DEBUG, "mtget: type=%lld, dsreg=%s, erreg=%s, resid=%lld, "
	    "fileno=%lld, blkno=%lld, flags=0x%llx, bf=%lld",
	    serr->se_type, mms_scsi_status(serr->se_status),
	    mms_scsi_sensekey(serr->se_senkey), serr->se_resid,
	    serr->se_fileno, serr->se_blkno, serr->se_mt_flags,
	    serr->se_mt_bf));

	if (save == DRV_SAVE_STAT && (drv->drv_flags & DRV_VALID_STAT) == 0) {
		drv->drv_mtget = serr->se_mtget;
		drv->drv_flags |= DRV_VALID_STAT;
	}
}

int
dm_mtiocltop(drv_req_t *op)
{
	int		err = 0;
	struct	mtlop	mtlop;
	struct	mtop	mtop;
	int		cmd;
	void		*arg;
	int		rc;

	/*
	 * If this is an MTIOCLTOP request, then arg points to a
	 * struct mtlop.
	 * We'll only use MTIOCLTOP if it is request by the application.
	 * Otherwise we use MTIOCTOP.
	 */
	if (wka->dm_request != NULL &&
	    wka->dm_request->drm_req_type == DRM_REQ_MTIOCLTOP) {
		mtlop.mt_op = op->drv_op;
		mtlop.mt_count = op->drv_count;
		cmd = MTIOCLTOP;
		arg = &mtlop;
	} else {
		mtop.mt_op = op->drv_op;
		mtop.mt_count = op->drv_count;
		cmd = MTIOCTOP;
		arg = &mtop;
	}

	memset(serr, 0, sizeof (drv_scsi_err_t));
	rc = dm_ioctl(cmd, arg);
	err = errno;
	if (wka->dm_request != NULL &&
	    wka->dm_request->drm_req_type == DRM_REQ_MTIOCLTOP) {
		op->drv_op = mtlop.mt_op;
		op->drv_count = mtlop.mt_count;
	} else {
		op->drv_op = mtop.mt_op;
		op->drv_count = mtop.mt_count;
	}

	if (rc != 0) {
		TRACE((MMS_ERR, "MTIOCLTOP error: %s", strerror(err)));
	}
	errno = err;			/* original errno */
	return (rc);
}

void
dm_disallowed(void)
{
	uchar_t		mask[DMD_DISALLOWED_MASK_SIZE];
	int		*ac;
	int		num_ac;
	int		i;
	char		dumpbuf[1024];

	/*
	 * Set up disallowed USCSI cmds
	 */
	ac = drv->drv_disallowed_cmds;
	if (ac != NULL) {
		num_ac = *(drv->drv_num_disallowed_cmds);
		memset(mask, 0, sizeof (mask));
		for (i = 0; i < num_ac; i++) {
			DMD_SET_MASK(mask, ac[i]);
		}
		(void) dm_ioctl(DRM_DISALLOWED_CMDS, mask);
	}
	(void) mms_trace_dump((char *)mask, DMD_DISALLOWED_MASK_SIZE, dumpbuf,
	    sizeof (dumpbuf));
	TRACE((MMS_DEBUG, "disallowed_cmd mask: %s", dumpbuf));
	/*
	 * Set up disallowed ioctls
	 */
	ac = drv->drv_disallowed_ioctls;
	if (ac != NULL) {
		num_ac = *(drv->drv_num_disallowed_ioctls);
		memset(mask, 0, sizeof (mask));
		for (i = 0; i < num_ac; i++) {
			DMD_SET_MASK(mask, ac[i] - MTIOC);
		}
		(void) dm_ioctl(DRM_DISALLOWED_IOCTLS, mask);
	}
	(void) mms_trace_dump((char *)mask, DMD_DISALLOWED_MASK_SIZE, dumpbuf,
	    sizeof (dumpbuf));
	TRACE((MMS_DEBUG, "disallowed_ioctl mask: %s", dumpbuf));
}

int
dm_chk_uscsi_error(int ret, struct uscsi_cmd *us, int err)
{
	int		senlen;

	if (ret == 0 && us->uscsi_status == STATUS_GOOD) {
		/* No error */
		return (0);
	}

	if (ret < 0) {
		/* An error occured */
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "USCSICMD error: %s", strerror(err)));
	}

	if (err != EIO) {
		/* Not an I/O error */
		return (-1);
	}

	/*
	 * An I/O error
	 */
	dm_get_mtstat(~DRV_SAVE_STAT);
	senlen = us->uscsi_rqlen - us->uscsi_rqresid;
	serr->se_flags |= DRV_SE_USCSI;
	dm_scsi_error(err, us->uscsi_status,
	    us->uscsi_cdblen, (uchar_t *)us->uscsi_cdb,
	    senlen, (uchar_t *)us->uscsi_rqbuf);

	drv->drv_mtget.drm_dsreg = serr->se_status;
	drv->drv_mtget.drm_erreg = serr->se_senkey;

	return (-1);
}

int
dm_ioctl(int cmd, void *arg)
{
	int		rc;
	int		err;

	memset(serr, 0, sizeof (drv_scsi_err_t));
	rc = ioctl(drv->drv_fd, cmd, arg);
	err = errno;
	if (rc == -1) {
		TRACE((MMS_ERR, "ioctl error: errno = %d", err));
		errno = err;
	}
	if (cmd == USCSICMD) {
		rc = dm_chk_uscsi_error(rc, arg, err);
	} else if (rc != 0) {
		serr->se_resid = -1;
		dm_get_mtstat(~DRV_SAVE_STAT);
		dm_get_mt_error(err);
	}

	if (rc != 0) {
		if (serr->se_flags & DRV_SE_SEN_VALID) {
			TRACE((MMS_DEBUG, "Calling drv_proc_error"));
			DRV_CALL(drv_proc_error, ());
			/*
			 * Record error if drive is loaded.
			 * Hitting a tapemark is not an error
			 */
			if ((drv->drv_flags & DRV_TM) == 0) {
				if (serr->se_senkey != KEY_NOT_READY ||
				    (drv->drv_flags & DRV_LOADED) ||
				    (serr->se_cmd != SCMD_TEST_UNIT_READY)) {
					(void) dm_send_error();
				}
			}
		}
		if (serr->se_senkey == KEY_HARDWARE_ERROR) {
			/* set DriveBroken to "yes" */
			(void) dm_send_drive_broken();
		} else if (serr->se_senkey == KEY_MEDIUM_ERROR) {
			/* Set CartridgeMediaError to "yes" */
			(void) dm_send_cartridge_media_error();
		}
	}

	/* If error and no saved stat, save it */
	if (rc != 0 && (drv->drv_flags & DRV_VALID_STAT) == 0) {
		memcpy(&drv->drv_mtget, &serr->se_mtget, sizeof (drm_mtget_t));
		drv->drv_flags |= DRV_VALID_STAT;
	}

	errno = err;
	return (rc);
}

void
dm_get_mt_error(int err)
{
	uchar_t			cdb[MMS_MAX_CDB_LEN];
	struct mterror_entry	mtee = { 0, cdb };
	struct mterror_entry	*mte = &mtee;
	uchar_t			arqbuf[DRV_SENSE_LEN];
	int			have_sense = 0;

	mtee.mtee_cdb_len =  sizeof (cdb);
	mte->mtee_arq_status_len = drv->drv_mtee_stat_len;
	mte->mtee_arq_status = (struct scsi_arq_status *)(void *)arqbuf;
	serr->se_flags &= ~DRV_SE_SEN_VALID;
	while (ioctl(drv->drv_fd, MTIOCGETERROR, mte) == 0) {
		dm_scsi_error(err,
		    *(uchar_t *)&mte->mtee_arq_status->sts_status,
		    mte->mtee_cdb_len, cdb,
		    drv->drv_num_sen_bytes,
		    (uchar_t *)&mte->mtee_arq_status->sts_sensedata);
		mte->mtee_cdb_len = sizeof (cdb);
		serr->se_flags |= DRV_SE_SEN_VALID;
		have_sense = 1;
	}
	if (have_sense == 0) {
		TRACE((MMS_DEBUG, "No sense info available"));
	}
	if ((serr->se_flags & DRV_SE_SEN_VALID) == 0) {
		/* No valid sense bytes, then use what we already know */
		TRACE((MMS_DEBUG, "Sense not valid"));
		if (serr->se_erreg == SUN_KEY_EOF) {
			drv->drv_flags |= DRV_TM;
		} else if (serr->se_erreg == SUN_KEY_EOT) {
			drv->drv_flags |= DRV_EOM;
		}
	}
}

int
dm_get_log_sense_parm(uchar_t *page, int code, uint64_t *val)
{
	uint32_t	len;
	uchar_t		*pp;
	uint32_t	pcode;
	uint32_t	psize;
	uchar_t		*limit;

	char_to_uint32(page + 2, 2, &len);	/* page length */
	pp = page + 4;
	limit = page + len;

	while (pp < limit) {
		char_to_uint32(pp, 2, &pcode);
		pp += 3;
		psize = pp[0];
		pp++;
		if (pcode == code) {		/* found matching code */
			char_to_uint64(pp, psize, val);
			return (0);
		}
		pp += psize;
	}
	return (-1);				/* no matching code */
}

drv_skaa_t *
dm_skaa_lookup(uchar_t senkey, uchar_t asc, uchar_t ascq)
{
	drv_skaa_t	*ele;

	for (ele = drv->drv_skaa_tab;
	    ele->drv_ec != DRV_EC_UNKNOWN_ERR;
	    ele++) {
		if ((ele->drv_senkey == senkey || ele->drv_senkey == 0xff) &&
		    (ele->drv_asc == asc || ele->drv_asc == 0xff) &&
		    (ele->drv_ascq == ascq || ele->drv_ascq == 0xff)) {
			return (ele);
		}
	}
	return (ele);
}
