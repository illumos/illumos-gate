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


#include <thread.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/mkdev.h>
#include <sys/file.h>
#include <synch.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stropts.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <pthread.h>
#include <sys/scsi/generic/sense.h>
#include <sys/scsi/impl/uscsi.h>
#include <mms_list.h>
#include <dmd_impl.h>
#include <dm_impl.h>
#include <dm_msg.h>
#include <mms_trace.h>
#include <mms_dmd.h>
#include <dm_proto.h>
#include <mms_strapp.h>

static	char *_SrcFile = __FILE__;

void
dm_get_request(void)
{
	/*
	 * Get request from driver
	 */
	if (ioctl(wka->dm_drm_fd, DRM_REQUEST, &wka->dm_reqbuf)) {
		/*
		 * No request, process error
		 */
		TRACE((MMS_DEBUG, "dm_get_request: "
		    "No request: %s", strerror(errno)));
		return;
	}
	wka->dm_request = &wka->dm_reqbuf;
}

void
dm_proc_request(void)
{
	int		rc = 0;
	drm_request_t	*req;
	drm_reply_t	rep;
	tapepos_t	pos;
	char		dbuf[4096];

	dm_msg_destroy();			/* cleanup any left over msg */

	if (DRV_CALL(drv_get_pos, (&pos)) == 0) {
		TRACE((MMS_DEBUG, "dm_proc_request: Entered at position %lld",
		    pos.lgclblkno));
	}

	memset(&rep, 0, sizeof (rep));
	req = wka->dm_request;
	(void) mms_trace_dump((char *)req, sizeof (drm_request_t), dbuf,
	    sizeof (dbuf));
	TRACE((MMS_DEBUG, "dm_proc_request: Request:\n%s", dbuf));

	/*
	 * Save I/O counts
	 */
	drv->drv_rdbytes += req->drm_req_rdbytes;
	drv->drv_wrbytes += req->drm_req_wrbytes;

	if (req->drm_req_type != DRM_REQ_OPEN &&
	    req->drm_req_type != DRM_REQ_CLOSE) {
		/*
		 * If not an open or close request and not in user data,
		 * then allow only status requests.
		 */
		if ((drv->drv_flags & DRV_UDATA) == 0 &&
		    req->drm_req_type != DRM_REQ_MTGET) {
			DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
			    "file not positioned correctly"));
			rc = EACCES;
			goto done;
		}
	}

	if (req->drm_req_flags & DRM_REQ_MOVED) {
		TRACE((MMS_DEBUG, "dm_get_request: Tape Moved"));
		drv->drv_flags &= ~(DRV_VALID_STAT | DRV_MOVE_FLAGS);
	}

	memset(&rep, 0, sizeof (drm_reply_t));
	switch (req->drm_req_type) {
	case DRM_REQ_MTIOCTOP:
		TRACE((MMS_INFO, "dm_get_request: "
		    "Got request DRM_REQ_MTIOCTOP"));
		rc = dm_ioctl_mtiocltop(req, &rep);
		break;
	case DRM_REQ_MTIOCLTOP:
		TRACE((MMS_INFO, "dm_get_request: "
		    "Got request DRM_REQ_MTIOCLTOP"));
		rc = dm_ioctl_mtiocltop(req, &rep);
		break;
	case DRM_REQ_OPEN:
		TRACE((MMS_INFO, "dm_get_request: "
		    "Got open request DRM_REQ_OPEN"));
		rc = dm_open(req, &rep);
		break;
	case DRM_REQ_CLOSE:
		TRACE((MMS_INFO, "dm_get_request: "
		    "Got close request DRM_REQ_CLOSE"));
		rc = dm_close();
		break;
	case DRM_REQ_READ:
		TRACE((MMS_INFO, "dm_get_request: "
		    "Got read request DRM_REQ_READ"));
		rc = dm_read(&rep);
		break;
	case DRM_REQ_READ_TM:
		TRACE((MMS_INFO, "dm_get_request: "
		    "Got read FM request DRM_REQ_READ_TM"));
		rc = dm_read_tm(req);
		break;
	case DRM_REQ_READ_ERR:
		TRACE((MMS_INFO, "dm_get_request: "
		    "Got read ERR request DRM_REQ_READ_ERR"));
		rc = dm_read_err(req, &rep);
		break;
	case DRM_REQ_WRITE:
		TRACE((MMS_INFO, "dm_get_request: "
		    "Got write request DRM_REQ_WRITE"));
		rc = dm_write(&rep);
		break;
	case DRM_REQ_WRITE0:
		TRACE((MMS_INFO, "dm_get_request: "
		    "Got write0 request DRM_REQ_WRITE0"));
		rc = dm_write_0(req, &rep);
		break;
	case DRM_REQ_WRITE_ERR:
		TRACE((MMS_INFO, "dm_get_request: "
		    "Got write err request DRM_REQ_WRITE_ERR"));
		rc = dm_write_err(req, &rep);
		break;
	case DRM_REQ_MTGET:
		TRACE((MMS_INFO, "dm_get_request: "
		    "Got request DRM_REQ_MTGET"));
		rc = dm_ioctl_mtget(req, &rep);
		break;
	case DRM_REQ_CLRERR:
		TRACE((MMS_INFO, "dm_get_request: "
		    "Got request DRM_REQ_CLRERR"));
		rc = dm_ioctl_clrerr(&rep);
		break;
	case DRM_REQ_BLK_LIMIT:
		TRACE((MMS_INFO, "dm_get_request: "
		    "Got request MMS_REQ_BLK_LIMIT"));
		if (drv->drv_flags & DRV_FATAL) {
			rc = EIO;
			break;
		}
		rc = DRV_CALL(drv_blk_limit, (&rep.drm_blk_limit_rep));
		break;
	case DRM_REQ_GET_POS:
		TRACE((MMS_INFO, "dm_get_request: "
		    "Got request MMS_REQ_GET_POS"));
		rc = dm_ioctl_getpos(&rep);
		break;
	case DRM_REQ_MTGETPOS:
		TRACE((MMS_INFO, "dm_get_request: "
		    "Got request MMS_REQ_GET_POS"));
		rc = dm_ioctl_mtgetpos(&rep);
		break;
	case DRM_REQ_MTRESTPOS:
		TRACE((MMS_INFO, "dm_get_request: "
		    "Got request MMS_REQ_GET_POS"));
		rc = dm_ioctl_mtrestpos(req);
		break;
	case DRM_REQ_LOCATE:
		TRACE((MMS_INFO, "dm_get_request: "
		    "Got request MMS_REQ_LOCATE"));
		rc = dm_ioctl_locate(req);
		break;
	case DRM_REQ_GET_CAPACITY:
		TRACE((MMS_INFO, "dm_get_request: "
		    "Got request MMS_REQ_GET_CAPACITY"));
		rc = dm_ioctl_get_capacity(&rep);
		break;
	case DRM_REQ_UPT_CAPACITY:
		TRACE((MMS_INFO, "dm_get_request: "
		    "Got request MMS_REQ_UPT_CAPACITY"));
		rc = dm_ioctl_upt_capacity();
		break;
	case DRM_REQ_SET_DENSITY:
		TRACE((MMS_INFO, "dm_get_request: "
		    "Got request MMS_REQ_SET_DENSITY"));
		rc = dm_ioctl_set_density();
		break;
	case DRM_REQ_GET_DENSITY:
		TRACE((MMS_INFO, "dm_get_request: "
		    "Got request MMS_REQ_GET_DENSITY"));
		rc = dm_ioctl_get_density(&rep);
		break;

	default:
		rc = EINVAL;
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "invalid request from driver %lld", req->drm_req_type));
		rc = EINVAL;
		break;
	}

done:
	dm_msg_destroy();			/* clean up left over msg */
	/*
	 * If at EOF and don't have a valid EOF position, then get it.
	 */
	if (drv->drv_flags & DRV_EOF) {
		(void) dm_get_eof_pos();
	}

	rep.drm_rep_rc = rc;
	if (drv->drv_flags & DRV_EOF) {
		TRACE((MMS_DEBUG, "dm_get_request: "
		    "At EOF"));
		rep.drm_rep_flags |= DRM_REP_EOF;
	}

	if (drv->drv_flags & DRV_FATAL) {
		TRACE((MMS_DEBUG, "dm_get_request: "
		    "Fatal error occured"));
		rep.drm_rep_flags |= DRM_REP_FATAL;
	}
	if (drv->drv_flags & DRV_TERM_FILE) {
		TRACE((MMS_DEBUG, "dm_get_request: "
		    "Catch next read"));
		rep.drm_rep_flags |= DRM_REP_NOTIFY_READ;
	} else {
		TRACE((MMS_DEBUG, "dm_get_request: "
		    "Catch next write"));
		rep.drm_rep_flags |= DRM_REP_NOTIFY_WRITE;
	}
	if (req->drm_req_flags & DRM_REQ_NOTIFY_READ) {
		TRACE((MMS_DEBUG, "dm_get_request: "
		    "Notify read in effect"));
		rep.drm_rep_flags |= DRM_REP_NOTIFY_READ;
	}
	if (req->drm_req_flags & DRM_REQ_NOTIFY_WRITE) {
		TRACE((MMS_DEBUG, "dm_get_request: "
		    "Notify write in effect"));
		rep.drm_rep_flags |= DRM_REP_NOTIFY_WRITE;
	}

	if (DRV_CALL(drv_get_pos, (&pos)) == 0) {
		TRACE((MMS_DEBUG, "dm_proc_request: Resumed at position %lld",
		    pos.lgclblkno));
	}

	wka->dm_request = NULL;		/* request done */
	ioctl(wka->dm_drm_fd, DRM_RESUME, &rep);
	TRACE((MMS_DEBUG, "Resume with rc = %lld", rep.drm_rep_rc));

	if (req->drm_req_type == DRM_REQ_OPEN) {
		if (rep.drm_rep_rc == 0) {
			/* Opened successfully */
			wka->dm_flags |= DM_OPENED;
		}

	}

}

int
dm_ioctl_mtiocltop(drm_request_t *req, drm_reply_t *rep)
{
	drm_mtop_t	*op = &req->drm_mtop_req;
	int		rc = 0;

	rep->drm_mtop_rep.drm_op = op->drm_op;
	rep->drm_mtop_rep.drm_count = op->drm_count;

	switch (op->drm_op) {
	case MTREW:
	case MTRETEN:
		TRACE((MMS_INFO, "dm_ioctl_mtiocltop: MTREW/MTRETEN"));
		rc = dm_ioctl_rewind();
		break;
	case MTSEEK:
		TRACE((MMS_INFO, "dm_ioctl_mtiocltop: MTSEEK"));
		rc = dm_ioctl_seek(op->drm_count);
		break;
	case MTTELL:
		TRACE((MMS_INFO, "dm_ioctl_mtiocltop: MTTELL"));
		drv->drv_flags &= ~DRV_VALID_STAT;
		rc = DRV_CALL(drv_tell,
		    ((uint64_t *)&rep->drm_mtop_rep.drm_count));
		if (rc) {
			DM_MSG_SEND((DM_ADM_ERR, DM_6523_MSG, DM_MSG_REASON));
		}
		break;
	case MTFSF:
		TRACE((MMS_INFO, "dm_ioctl_mtiocltop: MTFSF"));
		rc = dm_ioctl_fsf(op->drm_count);
		break;
	case MTFSR:
		TRACE((MMS_INFO, "dm_ioctl_mtiocltop: MTFSR"));
		rc = dm_ioctl_fsb(op->drm_count);
		break;
	case MTBSF:
		TRACE((MMS_INFO, "dm_ioctl_mtiocltop: MTBSF"));
		rc = dm_ioctl_bsf(op->drm_count);
		break;
	case MTBSR:
		TRACE((MMS_INFO, "dm_ioctl_mtiocltop: MTBSR"));
		rc = dm_ioctl_bsb(op->drm_count);
		break;
	case MTWEOF:
		TRACE((MMS_INFO, "dm_ioctl_mtiocltop: MTWEOF"));
		rc = dm_ioctl_wtm(op->drm_count);
		break;
	case MTEOM:
		TRACE((MMS_INFO, "dm_ioctl_mtiocltop: MTEOM"));
		rc = dm_goto_eof();
		break;
	case MTSRSZ:
		TRACE((MMS_INFO, "dm_ioctl_mtiocltop: MTSRSZ"));
		/*
		 * You're allowed to set any record size any time.
		 */
		rc = dm_ioctl_set_blksize(op->drm_count);
		break;
	case MTGRSZ:
		TRACE((MMS_INFO, "dm_ioctl_mtiocltop: MTGRSZ"));
		if (drv->drv_flags & DRV_FATAL) {
			rc = EIO;
			break;
		}
		rc = DRV_CALL(drv_get_blksize,
		    ((uint64_t *)&rep->drm_mtop_rep.drm_count));
		if (rc) {
			DM_MSG_SEND((DM_ADM_ERR, DM_6514_MSG, DM_MSG_REASON));
		}
		rep->drm_mtop_rep.drm_op = MTGRSZ;
		break;

	default:
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "0x%x", (int)op->drm_op));
		DM_MSG_SEND((DM_ADM_ERR, DM_6515_MSG, DM_MSG_REASON));
		rc = EINVAL;
		break;
	}

	return (rc);
}


int
dm_open(drm_request_t *req, drm_reply_t *rep)
{
	int		newfile = 0;
	drm_open_t	*oreq = &req->drm_open_req;
	tapepos_t	pos;
	int		rc = 0;
	char		*user;

	TRACE((MMS_DEBUG, "dm_open: Enter dm_open"));

	/*
	 * Must be attached to open
	 */
	if ((drv->drv_flags & DRV_ATTACHED) == 0) {
		/* Not attached */
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "Drive not attached"));
		rc = ENODEV;
		goto fatal;
	}

	if (wka->dm_hdl_minor != oreq->drm_open_minor) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "Target ID mismatch, requested %lld, have %d",
		    oreq->drm_open_minor, wka->dm_hdl_minor));
		rc = ENODEV;
		goto fatal;
	}

	/* Return EBUSY if already opened */
	if (wka->dm_app_pid) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "Already opened by pid = %d", wka->dm_app_pid));
		rc = EBUSY;
		goto fatal;
	}

	/*
	 * Save application's pid and user name
	 */
	wka->dm_app_pid = req->drm_req_pid;
	user = dm_get_user(req->drm_req_pid);
	if (user == NULL) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "Unable to get user from uid %lld", req->drm_req_uid));
		rc = EPERM;
		goto fatal;
	}

	/*
	 * Check user authentication
	 */
	if (dm_chk_dev_auth(user) != 0) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "User %s is not authorized to use MMS",
		    user));
		rc = EPERM;
		goto fatal;
	}


	if ((drv->drv_flags & DRV_LOADED) == 0) {
		/* Cartridge is not loaded */
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "Cartridge %s, Volume %s not loaded",
		    mnt->mnt_pcl, mnt->mnt_volumename));
		rc = ENOTTY;
		goto fatal;
	}

	/*
	 * Check MMS mode
	 */
	if ((mnt->mnt_flags & MNT_MMS) == 0) {
		/* In raw mode */
		TRACE((MMS_DEBUG, "dm_open: RAW mode"));
		rc = ioctl(wka->dm_drm_fd, DRM_MMS_MODE, 0);
		if (rc < 0) {
			rc = errno;
			DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
			    "Cannot set raw mode: %s", strerror(rc)));
			goto fatal;
		}

		if (DRV_CALL(drv_bind_raw_dev,
		    (req->drm_open_req.drm_open_flags | FNDELAY)) != 0) {
			rc = errno;
			DM_MSG_PREPEND(("Cannot set raw mode: %s: ",
			    strerror(rc)));
			goto fatal;
		}
		/* The entire tape is user data in non MMS mode */
		drv->drv_flags |= DRV_UDATA;
		drv->drv_numopens++;	/* 1 more open */
		drv->drv_flags |= DRV_OPENED;
		/*
		 * Set the bit format
		 */
		if (dm_update_bitformat()) {
			DM_MSG_PREPEND(("update bit format error: "));
			rc = EIO;
			goto fatal;
		}

		return (0);
	}

	/*
	 * MMS mode
	 */

	/*
	 * Save open flags
	 */
	drv->drv_oflags = oreq->drm_open_flags;

	/*
	 * Set readonly/readwrite flags
	 */
	if ((drv->drv_oflags & O_RDONLY) ||
	    (mnt->mnt_flags & MNT_READONLY)) {
		TRACE((MMS_DEBUG, "readonly open option"));
		drv->drv_flags |= DRV_READONLY;
	}

	if (mnt->mnt_flags & MNT_READWRITE) {
		if (drv->drv_flags & DRV_READONLY) {
			TRACE((MMS_DEBUG, "dm_open: explicit readwrite "
			    "on mount command overrides readonly option"));
			drv->drv_flags &= ~DRV_READONLY;
		}
	}

	if (drv->drv_flags & DRV_WRITEPROTECTED) {
		TRACE((MMS_DEBUG, "dm_open: cartridge writeprotected"));
		drv->drv_flags |= DRV_READONLY;
	}

	/*
	 * Set disposition of file
	 */
	if ((drv->drv_oflags & FCREAT) || (mnt->mnt_flags & MNT_CREAT)) {
		drv->drv_flags |= DRV_CREAT;
	}

	if (drv->drv_oflags & FAPPEND) {
		drv->drv_flags |= DRV_APPEND;
	}

	/*
	 * Save current tape position before validation. We may have to
	 * return to this position if the rest of open fails.
	 */
	if (DRV_CALL(drv_get_pos, (&pos)) != 0) {
		DM_MSG_PREPEND(("unable to get current position: "));
		rc = EIO;
		goto fatal;
	}
	drv->drv_cur_pos = pos;

	/*
	 * Determine if a new file should be created
	 */
	if (drv->drv_lbl_type != DRV_NL) {
		rc = dm_open_labeled(&newfile);
	} else {
		rc = dm_open_nonlabeled(&newfile);
	}
	if (rc != 0) {
		goto fatal;
	}

	if (newfile &&
	    (drv->drv_flags & DRV_READONLY)) {
		/* Readonly is for old only */
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "cannot write to readonly"));
		rc = EACCES;
		goto fatal;
	}

	/*
	 * Set record format
	 */
	if (mnt->mnt_flags & MNT_FIXED) {
		drv->drv_flags |= DRV_FIXED;
		drv->drv_flags &= ~DRV_VARIABLE;
	} else {
		drv->drv_flags &= ~DRV_FIXED;
		drv->drv_flags |= DRV_VARIABLE;
	}

	TRACE((MMS_DEBUG, "dm_open: %s, %s, %s, %s",
	    drv->drv_flags & DRV_CREAT ? "CREAT" : "OLD",
	    drv->drv_flags & DRV_READONLY ? "READONLY" : "READWRITE",
	    drv->drv_flags & DRV_APPEND ? "APPEND" : "NOT_APPEND",
	    drv->drv_flags & DRV_FIXED ? "FIXED" : "VARIABLE"));

	if (newfile) {
		/* Turn off append */
		drv->drv_flags &= ~DRV_APPEND;

		/*
		 * Check expiration date.
		 */
		if (drv->drv_lbl_type != DRV_NL) {
			if (dm_validate_xdate() != 0) {
				DM_MSG_PREPEND(("Existing file not expired: "));
				/* Existing file not expired */
				rc = EACCES;
				goto fatal;
			}
		}

		if (dm_set_label_blksize() != 0) {
			DM_MSG_PREPEND(("Set label blksize error: "));
			rc = EIO;
			goto fatal;
		}
		if (mnt->mnt_fseq == 1) {
			/*
			 * If mounted tape is NL, then decide whether to
			 * write new label to AL.
			 */
			if (drv->drv_lbl_type == DRV_NL) {
				if (dm_ask_write_lbl("NL", "AL",
				    mnt->mnt_pcl) != 0) {
					/* Don't write new label */
					rc = EACCES;
					goto fatal;
				}
			}
			/*
			 * If creating the first file, rewind
			 * to BOM and set density and create
			 * VOL1 again
			 */
			if (DRV_CALL(drv_rewind, ())) {
				rc = EIO;
				goto fatal;
			}
			if ((mnt->mnt_flags & MNT_AUTO_DEN) == 0) {
				if (DRV_CALL(drv_set_density, (mnt->
				    mnt_density->sym_code)) != 0) {
					rc = EIO;
					goto fatal;
				}
			}
			if (dm_create_vol1() != 0) {
				rc = EIO;
				goto fatal;
			}
		} else {
			/* fseq != 1 */
			if (DRV_CALL(drv_locate, (&pos)) != 0) {
				rc = EIO;
				goto fatal;
			}
		}
		/* Create file, write hdr label */
		if (dm_create_hdr1() != 0) {
			rc = EIO;
			goto fatal;
		}
		if (dm_create_hdr2() != 0) {
			rc = EIO;
			goto fatal;
		}
		if (DRV_CALL(drv_wtm, (1)) != 0) {
			rc = EIO;
			goto fatal;
		}
		drv->drv_flags &= ~DRV_TM;
		drv->drv_flags |=
		    (DRV_TERM_FILE | DRV_BOF | DRV_UDATA |
		    DRV_VALIDATED_FNAME);
		if (dm_get_bof_pos() != 0) {
			rc = EIO;
			goto fatal;
		}
	}

	if ((drv->drv_flags & DRV_VALIDATED_FNAME) == 0) {
		/*
		 * File must be validated by now
		 */
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "Unable to validate filename"));
		rc = EACCES;
		goto fatal;
	}

	if ((drv->drv_flags & DRV_UDATA) == 0) {
		/*
		 * Validated and not in user data, then
		 * position file to BOF
		 */
		if (DRV_CALL(drv_fsf, (1)) != 0) {
			DM_MSG_PREPEND(("spacing to user data error: "));
			rc = EIO;
			goto fatal;
		}
		drv->drv_flags &= ~DRV_TM;
		drv->drv_flags |= (DRV_BOF | DRV_UDATA);
		if (dm_get_bof_pos() != 0) {
			DM_MSG_PREPEND(("cannot get bof position: "));
			rc = EIO;
			goto fatal;
		}
	}

	if ((drv->drv_flags & DRV_UDATA) == 0) {
		/*
		 * Must be in user data now
		 */
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "Unable to reach user data in file"));
		rc = EACCES;
		goto fatal;
	}

	if ((drv->drv_flags & DRV_VALID_BOF_POS) == 0) {
		/*
		 * Must have BOF position
		 */
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "Unable to get BOF position"));
		rc = EACCES;
		goto fatal;
	}

	/*
	 * Get EOF position from MM
	 */
	if (newfile) {
		drv->drv_flags &= ~DRV_VALID_EOF_POS;
		drv->drv_flags |= DRV_UPDATE_EOF_POS;
		/* ignore send error */
		(void) dm_send_eof_pos();
	} else if ((drv->drv_flags & DRV_VALID_EOF_POS) == 0) {
		if (dm_show_eof_pos() != 0) {
			drv->drv_flags &= ~DRV_VALID_EOF_POS;
		}
	}

	/*
	 * Position in the file
	 */
	if (newfile == 0) {
		if (dm_open_pos() != 0) {
			/* Error */
			DM_MSG_PREPEND(("unable to reposition file: "));
			rc = EIO;
			goto fatal;
		}
	}

	/*
	 * Now that the file is positioned correctly, reset the disposition
	 * so that open flags will be used.
	 */
	mnt->mnt_flags &= ~(MNT_CREAT | MNT_OLD);
	drv->drv_flags &= ~DRV_CREAT;		/* and turn off create */

	/*
	 * Switch to user's file
	 */
	if (DRV_CALL(drv_bind_raw_dev,
	    (req->drm_open_req.drm_open_flags | FNDELAY) != 0)) {
		rc = errno;
		DM_MSG_PREPEND(("Raw device open error: %s: ", strerror(rc)));
		wka->dm_app_pid = 0;
		goto fatal;
	}
	TRACE((MMS_DEBUG, "Opened by pid %d", (int)wka->dm_app_pid));

	/*
	 * Set up file blksize, density and compression
	 */
	if (dm_set_file_blksize(-1) != 0) {
		/*
		 * Rebind to target base
		 */
		DM_MSG_PREPEND(("set file blocksize error: "));
		if (DRV_CALL(drv_rebind_target, ()) != 0) {
			DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
			    "Rebind base device error: %s",
			    strerror(errno)));
		}
		rc = EIO;
		goto fatal;
	}

	/*
	 * Set the bit format
	 */
	if (dm_update_bitformat() != 0) {
		DM_MSG_PREPEND(("unable to update bit format: "));
		rc = EIO;
		goto fatal;
	}
	rep->drm_rep_flags |= (DRM_REP_NOTIFY_WRITE | DRM_REP_NOTIFY_READ);
	if (rc == 0) {
		/* Successfully positioned, turn off append */
		drv->drv_flags &= ~DRV_APPEND;
		drv->drv_flags |= DRV_OPENED;
	}
	free(user);
	return (rc);

fatal:
	free(user);
	wka->dm_app_pid = 0;
	DRV_CALL(drv_locate, (&pos));
	DM_MSG_SEND((DM_ADM_ERR, DM_6516_MSG, DM_MSG_REASON));
	(void) dm_set_label_blksize();
	return (rc);

}

int
dm_open_labeled(int *newfile)
{
	/*
	 * Position to the file seq
	 */
	if (dm_pos_fseq() != 0) {
		return (EIO);
	}

	if (drv->drv_fseq != mnt->mnt_fseq) {
		/*
		 * We must be at the file requested by the user
		 */
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "Unable to reach requested file"));
		return (EIO);
	}

	/*
	 * Determine if a new file will be created
	 */

	*newfile = 0;
	if (drv->drv_flags & DRV_CREAT) {
		/*
		 * Create a new file
		 */
		*newfile = 1;
		if (drv->drv_flags & DRV_UDATA) {
			if (drv->drv_fseq == 1) {
				if (DRV_CALL(drv_rewind, ()) != 0 ||
				    DRV_CALL(drv_fsb, (1,
				    DRV_LOGICAL_CROSS_TM)) != 0) {
					DM_MSG_PREPEND(("unable to "
					    "position cartridge: "));
					return (EIO);
				}
			} else {
				if (dm_rewind_file() != 0 ||
				    DRV_CALL(drv_bsf, (2)) != 0 ||
				    DRV_CALL(drv_fsf, (1)) != 0) {
					DM_MSG_PREPEND(("unable to "
					    "position cartridge: "));
					return (EIO);
				}
			}
			drv->drv_flags &= ~DRV_UDATA;
		}
		if ((drv->drv_flags & DRV_VALIDATED_FNAME) != 0) {
			if (dm_validate_fname() != 0) {
				return (ENOENT);
			}
		}
		drv->drv_flags |= DRV_VALIDATED_FNAME;
	} else {
		/*
		 * Writing over an existing file
		 */
		if ((drv->drv_flags & DRV_UDATA) == 0) {
			/* Not in user data and validate filename */
			if ((drv->drv_flags & DRV_VALIDATED_FNAME) == 0) {
				if (dm_validate_fname() != 0) {
					return (EACCES);
				}
			}
		}
	}

	/*
	 * Set up blocksize
	 */
	if (drv->drv_flags & DRV_CREAT) {
		drv->drv_file_blksize = mnt->mnt_blksize > 0 ?
		    mnt->mnt_blksize : drv->drv_dflt_blksize;
	} else {
		drv->drv_file_blksize = mnt->mnt_blksize > 0 ?
		    mnt->mnt_blksize : drv->drv_lbl_blksize;
	}
	return (0);
}

int
dm_open_nonlabeled(int *newfile)
{
	/*
	 * Mounted cartridge is NL
	 * If mount option is AL, then create label if not done already
	 */
	if (mnt->mnt_lbl_type == DRV_AL && (drv->drv_flags & DRV_BOM)) {
		/* Can only create fseq 1 */
		if (mnt->mnt_fseq > 1) {
			DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
			    "Do not support fseq = %d", mnt->mnt_fseq));
			return (ENOENT);
		}
		/*
		 * Must create a new file
		 */
		*newfile = 1;

		/*
		 * Set up blocksize
		 */
		drv->drv_file_blksize = mnt->mnt_blksize > 0 ?
		    mnt->mnt_blksize : drv->drv_dflt_blksize;
	}

	return (0);
}

int
dm_validate_xdate(void)
{
	time_t		curtime;
	int		curdate;
	int		xdate;
	int		tmp;
	int		i;
	char		lxdate[7];
	struct		tm tm;

	if (mnt->mnt_lbl_type == DRV_NL) {
		/* nonlabeled */
		return (0);
	}

	strncpy(lxdate, drv->drv_hdr1.hdr1_xdate, 6);
	lxdate[6] = '\0';
	if (strncmp(lxdate + 1, "00000", 5) == 0) {
		/* No expiration date used */
		return (0);
	}

	/*
	 * If date is invalid, then ignore
	 */
	if (lxdate[0] != ' ' && lxdate[0] != '0') {
		goto invalid_xdate;
	}
	for (i = 0; i < 5; i++) {
		if (!isdigit(lxdate[1 + i])) {
			goto invalid_xdate;
		}
	}
	sscanf(lxdate + 3, "%d", &tmp);
	if (tmp < 1 || tmp > 366) {
		goto invalid_xdate;
	}

	if ((drv->drv_flags & DRV_VALIDATE_XDATE) == 0) {
		/* Don't validate expiration date */
		return (0);
	}

	/*
	 * Get expiration date since 1900
	 */
	sscanf(lxdate + 1, "%d", &xdate);
	if (lxdate[0] == '0') {
		/* years since 1900 */
		xdate += 100000;
	}

	/*
	 * Get current date since 1900
	 */
	curtime = time(NULL);
	localtime_r(&curtime, &tm);
	curdate = tm.tm_year * 1000 + tm.tm_yday + 1;

	if (xdate > curdate) {
		/* file not expired */
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "Existing file not expired: "
		    "expiration date = %s", lxdate));
		return (-1);
	} else {
		/* File expired */
		return (0);
	}

invalid_xdate:
	TRACE((MMS_DEBUG, "invalid expiration date: %s", lxdate));
	return (0);
}

/*
 * Currently, only one file is supported on each volume, so fseq can only be 1.
 */

int
dm_pos_fseq(void)
{
	if (drv->drv_fseq == 0) {
		/* Tape not positioned */
		if (DRV_CALL(drv_rewind, ()) != 0) {
			return (EIO);
		}
		if (drv->drv_lbl_type != DRV_NL) {
			if (DRV_CALL(drv_fsb, (1, DRV_LOGICAL_CROSS_TM))) {
				return (EIO);
			}
		}
		drv->drv_flags &= ~(DRV_UDATA | DRV_BOF |
		    DRV_EOF | DRV_TM | DRV_HDR1 |
		    DRV_HDR2 | DRV_EOF1 | DRV_EOF2);
		drv->drv_fseq = 1;
	}

	if (mnt->mnt_fseq == drv->drv_fseq) {
		/* Already positioned to file */
		return (0);
	}

	/*
	 * We don't support fseq > 1 for the time being
	 */
	if (mnt->mnt_fseq > 1) {
		return (EINVAL);
	}

	return (0);
}

int
dm_get_bof_pos(void)
{
	if ((drv->drv_flags & DRV_BOF) == 0) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "Not at BOF. Can't get BOF position"));
		return (EACCES);
	}

	if (DRV_CALL(drv_get_pos, (&drv->drv_bof_pos)) != 0) {
		return (EIO);
	}
	drv->drv_flags |= DRV_VALID_BOF_POS;
	return (0);
}

int
dm_get_eof_pos(void)
{
	if ((drv->drv_flags & DRV_EOF) == 0) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "not at EOF. cannot get EOF position"));
		return (EACCES);
	}

	if (DRV_CALL(drv_get_pos, (&drv->drv_eof_pos)) != 0) {
		return (EIO);
	}
	drv->drv_flags |= DRV_VALID_EOF_POS;
	drv->drv_cur_pos = drv->drv_eof_pos;
	return (0);
}

int
dm_open_pos(void)
{
	if ((drv->drv_flags & DRV_UDATA) == 0) {
		/*
		 * Must be in uset data to do positioning at open
		 */
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "Not in user data. Can't do open position"));
		return (EACCES);
	}

	if ((drv->drv_flags & DRV_VALID_BOF_POS) == 0) {
		/*
		 * Must have BOF position
		 */
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "Don't have BOF position. " "Can't do open position"));
		return (EACCES);
	}

	if (drv->drv_flags & DRV_CREAT) {
		if (DRV_CALL(drv_locate, (&drv->drv_bof_pos)) != 0) {
			return (EIO);
		}
		drv->drv_cur_pos = drv->drv_bof_pos;
	} else if (drv->drv_flags & DRV_APPEND) {
		/* Go to eof */
		return (dm_goto_eof());
	}
	return (0);
}

int
dm_goto_eof(void)
{
	char		buf[80] = "";
	int		rc;
	tapepos_t	cur_pos = drv->drv_cur_pos;

	if (drv->drv_flags & DRV_FATAL) {
		return (EIO);
	}

	if ((drv->drv_flags & DRV_UDATA) == 0) {
		/*
		 * Must be in user data to go to EOF
		 */
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "Not in user data. Can't go to EOF"));
		return (EACCES);
	}

	if (DRV_CALL(drv_get_pos, (&cur_pos)) != 0) {
		return (EIO);
	}
	drv->drv_flags &= ~(DRV_TM | DRV_EOF);

	/*
	 * If eof position is valid, then locate to it
	 */
	if (dm_set_label_blksize()) {
		return (EIO);
	}
	if (drv->drv_flags & DRV_VALID_EOF_POS) {
		if (DRV_CALL(drv_locate, (&drv->drv_eof_pos)) != 0) {
			goto repos;
		}
		drv->drv_cur_pos = drv->drv_eof_pos;
		/*
		 * If this is really EOF, then the next block must be a
		 * tapemark followed by the trailor label.
		 */
		if (DRV_CALL(drv_fsb, (1, DRV_LOGICAL_CROSS_TM)) != 0) {
			/* Could not space 1 block */
			/* We're at EOF if we hit EOM or blank check */
			drv->drv_flags &= ~DRV_VALID_STAT;
			if (serr->se_senkey == SUN_KEY_EOT ||
			    serr->se_senkey == KEY_BLANK_CHECK) {
				TRACE((MMS_DEBUG, "Hit EOT/BLANK CHECK"));
				goto done;
			}
			/*
			 * Hit a tapemark, read the next block to see if it is a
			 * trailor label.
			 */
			if ((drv->drv_flags & DRV_TM) != 0) {
				if (DRV_CALL(drv_read, (buf, 80)) != 80) {
					/*
					 * We're at EOF if we hit EOM or
					 * blank check
					 */
					if (serr->se_senkey == SUN_KEY_EOT ||
					    serr->se_senkey ==
					    KEY_BLANK_CHECK) {
						TRACE((MMS_DEBUG,
						    "Hit EOT/BLANK CHECK"));
						drv->drv_flags &=
						    ~DRV_VALID_EOF_POS;
						goto done;
					} else {
						/* other error */
						goto repos;
					}
				}
				/*
				 * Read an 80 byte record
				 */
				if (dm_verify_trailor_label(buf) == 0) {
					TRACE((MMS_DEBUG, "Found EOF"));
					if (DRV_CALL(drv_locate,
					    (&drv->drv_eof_pos)) != 0) {
						/*
						 * Can't reposition
						 * to EOF
						 */
						goto repos;
					}
					drv->drv_cur_pos = drv->drv_eof_pos;
					goto done;
				}
			} else {
				/* All errors, do it the hard way */
				goto repos;
			}
		} else {
			/* Skipped a block, this is not EOF for sure */
			goto repos;
		}
repos:
		/*
		 * Don't find trailor label.
		 * Return to where we started and try to locate EOF
		 * the hard way.
		 */
		if (dm_set_file_blksize(drv->drv_cur_blksize)) {
			return (EIO);
		}
		drv->drv_flags &= ~DRV_VALID_EOF_POS;
		buf[0] = '\0';
		if (DRV_CALL(drv_locate, (&cur_pos)) != 0) {
			return (EIO);
		}
		drv->drv_cur_pos = cur_pos;
		drv->drv_flags &= ~(DRV_TM | DRV_EOF);
	}

	/*
	 * Eof position is not valid, find eof the hard way
	 */

	if (dm_set_label_blksize()) {
		return (EIO);
	}
	for (;;) {
		if (DRV_CALL(drv_fsf, (1)) != 0) {
			/* We're at EOF if we hit EOM or blank check */
			if (serr->se_senkey == SUN_KEY_EOT ||
			    serr->se_senkey == KEY_BLANK_CHECK) {
				TRACE((MMS_DEBUG, "Hit EOT/BLANK CHECK"));
				goto done;
			}
			goto err;
		}
		/*
		 * Try to read the next block to see if it is a trailor label.
		 * Skip over any tapemark we encounter
		 */
		while ((rc = DRV_CALL(drv_read, (buf, 80))) != 80) {
			/* We're at EOF if we hit EOM or blank check */
			if (serr->se_senkey == SUN_KEY_EOT ||
			    serr->se_senkey == KEY_BLANK_CHECK) {
				TRACE((MMS_DEBUG, "Hit EOT/BLANK CHECK"));
				drv->drv_flags |= DRV_EOF;
				DRV_CALL(drv_clrerr, ());
				goto done;
			} else if (drv->drv_flags & DRV_TM) {
				/* Hit a tapemark */
				continue;	/* Check for eof label */
			} else if (rc > 0) {
				/* Read a short block */
				continue;
			} else {
				/* other error */
				goto err;
			}
		}
		if (rc != 80) {
			/* Read a short block */
			continue;
		}
		/*
		 * Read an 80 byte record
		 */
		if (strncmp(buf, "EOF1", 4) == 0 ||
		    strncmp(buf, "EOV1", 4) == 0) {
			if (dm_verify_trailor_label(buf) != 0) {
				/* Invalid label structure */
				TRACE((MMS_ERR, "Invalid trailor label"));
				errno = EINVAL;
				goto err;
			}
			/* Found the EOF/EOV label */
			TRACE((MMS_DEBUG, "Found EOF"));
			break;
		}
	}
	/*
	 * We've read a trailor label. Position to the end of user data.
	 */
	if (DRV_CALL(drv_bsf, (1)) != 0) {
		goto err;
	}

done:
	drv->drv_flags &= ~DRV_TM;
	drv->drv_flags |= DRV_EOF;
	if (dm_set_file_blksize(drv->drv_cur_blksize)) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "Set file blksize error"));
		goto err;
	}

	if ((drv->drv_flags & DRV_VALID_EOF_POS) == 0) {
		if (dm_get_eof_pos()) {
			TRACE((MMS_DEBUG, "Can't get EOF pos"));
			goto err;
		}
		drv->drv_flags |= DRV_UPDATE_EOF_POS;
	}
	return (0);

err:
	/*
	 * Error going to EOF, reposition to where we started and return error
	 */
	DRV_CALL(drv_clrerr, ());
	DRV_CALL(drv_locate, (&cur_pos));
	if (dm_set_file_blksize(drv->drv_cur_blksize)) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "Set file blksize error"));
	}
	return (EIO);
}

int
dm_verify_trailor_label(char *buf)
{
	drv_eof1_t	*eof1 = (drv_eof1_t *)buf;
	drv_eov1_t	*eov1 = (drv_eov1_t *)buf;
	drv_hdr1_t	*hdr1 = &drv->drv_hdr1;

	if (strncmp(eof1->eof1_id, "EOF1", 4) == 0) {
		if (strncmp(eof1->eof1_fseq, hdr1->hdr1_fseq, 4)) {
			/*
			 * EOF1 does not match HDR1
			 */
			DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
			    "EOF1 label does not match HDR1 label"));
			return (-1);
		}
	} else if (strncmp(eov1->eov1_id, "EOV1", 4) == 0) {
		if (strncmp(eov1->eov1_fseq, hdr1->hdr1_fseq, 4)) {
			/*
			 * EOV1 does not match HDR1
			 */
			DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
			    "EOV1 label does not match HDR1 label"));
			return (-1);
		}
	}

	return (0);
}

int
dm_chk_eof(void)
{
	int		rc;
	char		buf[80] = "";
	tapepos_t	pos;

	if (DRV_CALL(drv_get_pos, (&pos)) != 0) {
		return (EIO);
	}

	if ((rc = DRV_CALL(drv_read, (buf, 80))) <= 0) {
		/* We're at EOF if we hit EOM or blank check */
		if (serr->se_senkey == SUN_KEY_EOT ||
		    serr->se_senkey == KEY_BLANK_CHECK) {
			TRACE((MMS_DEBUG, "Hit EOT/BLANK CHECK"));
			drv->drv_flags |= DRV_EOF;
			if (dm_get_eof_pos()) {
				rc = EIO;
			} else {
				rc = 0;
			}
		} else {
			/* Other error */
			DRV_CALL(drv_clrerr, ());
			rc = EIO;
		}
	} else if (rc >= 80 &&
	    (strncmp(buf, "EOF1", 4) == 0 || strncmp(buf, "EOV1", 4) == 0)) {
		TRACE((MMS_DEBUG, "Found EOF1/EOV1"));
		rc = 0;
	}

	DRV_CALL(drv_locate, (&pos));
	return (rc);
}

int
dm_validate_fname(void)
{
	int		rc;
	drv_hdr1_t	*hdr1 = &drv->drv_hdr1;
	drv_hdr2_t	*hdr2 = &drv->drv_hdr2;
	char		tmp[18];

	drv->drv_flags &= ~DRV_FIXED;	/* assume variable */
	drv->drv_flags |= DRV_VARIABLE;
	drv->drv_file_blksize = drv->drv_dflt_blksize;	/* default blksize */

	if ((drv->drv_flags & DRV_HDR1) == 0) {
		rc = DRV_CALL(drv_read, ((char *)&drv->drv_hdr1, 80));
		if (rc != 80 ||
		    strncmp(drv->drv_hdr1.hdr1_id, "HDR1", 4) != 0) {
			DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
			    "invalid header label structure, no HDR1"));
			return (EINVAL);
		}
		drv->drv_flags |= DRV_HDR1;

		strncpy(drv->drv_fid, drv->drv_hdr1.hdr1_fid, 17);
		drv->drv_fid[17] = '\0';
	}

	/*
	 * Validate filename
	 */
	if (drv->drv_flags & DRV_VALIDATE_FNAME) {
		/* validate filename */
		if (strncmp(drv->drv_hdr1.hdr1_fid, mnt->mnt_fname, 17) != 0) {
			/* Mismatch filename */
			strncpy(tmp, drv->drv_hdr1.hdr1_fid, 17);
			tmp[17] = '\0';
			DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
			    "filename mismatch: "
			    "label %s, specified %s", tmp, mnt->mnt_fname));
		} else {
			/* File verified */
			drv->drv_flags |= DRV_VALIDATED_FNAME;
		}
	} else {
		/* File verified */
		drv->drv_flags |= DRV_VALIDATED_FNAME;
	}

	/*
	 * HDR2 is optional
	 */
	if ((drv->drv_flags & DRV_HDR2) == 0) {
		rc = DRV_CALL(drv_read, ((char *)&drv->drv_hdr2, 80));

		/*
		 * HDR2 optional. If no HDR2, then there must be a tapemark.
		 */
		if ((drv->drv_flags & DRV_TM) != 0) {
			TRACE((MMS_DEBUG, "No HDR2"));
			return (0);
		}

		if (rc != 80 ||
		    strncmp(drv->drv_hdr2.hdr2_id, "HDR2", 4) != 0) {
			DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
			    "invalid header label structure, "
			    "invalid HDR2"));
			return (EIO);
		}

		drv->drv_flags |= DRV_HDR2;

		if (hdr2->hdr2_rformat == 'F') {
			drv->drv_flags |= DRV_FIXED;
			drv->drv_flags &= ~DRV_VARIABLE;
		} else {
			drv->drv_flags &= ~DRV_FIXED;
			drv->drv_flags |= DRV_VARIABLE;
		}

		if (strncmp(hdr1->hdr1_impid, DRV_IMPID, DRV_IMPID_LEN) == 0 ||
		    strncmp(hdr1->hdr1_impid, DRV_IMPID2, DRV_IMPID_LEN) == 0) {
			/* Label created by MMS */
			strncpy(tmp, hdr2->hdr2_blksize,
			    sizeof (hdr2->hdr2_blksize));
			tmp[sizeof (hdr2->hdr2_blksize)] = '\0';
			sscanf(tmp, "%d", &drv->drv_lbl_blksize);
		} else {
			/* Label not created by MMS */
			strncpy(tmp, hdr2->hdr2_blklen, 5);
			tmp[5] = '\0';
			sscanf(tmp, "%d", &drv->drv_lbl_blksize);
			if (drv->drv_lbl_blksize >= 99999) {
				drv->drv_lbl_blksize = drv->drv_dflt_blksize;
			}
		}
	}
	return (0);
}


int
dm_close(void)
{
	TRACE((MMS_DEBUG, "Closing file"));

	/*
	 * In MMS mode, terminate the tape if necessary
	 */
	if (mnt->mnt_flags & MNT_MMS) {
		if (drv->drv_flags & DRV_UDATA) {
			if (drv->drv_flags & DRV_TERM_FILE) {
				drv->drv_flags |= DRV_EOF;
				if (drv->drv_flags & DRV_UPDATE_EOF_POS) {
					(void) dm_get_eof_pos();
				}
				/*
				 * Ignore error since there isn't anything
				 * we can do except get it recorded.
				 */
				(void) dm_terminate_file();
				drv->drv_flags &= ~DRV_TERM_FILE;
			}
			if ((mnt->mnt_flags & MNT_NOREWIND) == 0) {
				/* Rewind at close */
				TRACE((MMS_DEBUG, "Rewind on close"));
				DRV_CALL(drv_locate, (&drv->drv_bof_pos));
				drv->drv_cur_pos = drv->drv_bof_pos;
			}
		}
	}

	/*
	 * Rebind to target base
	 */
	if (DRV_CALL(drv_rebind_target, ()) != 0) {
		TRACE((MMS_ERR, "Rebind base device error: %s",
		    strerror(errno)));
		drv->drv_flags |= DRV_FATAL;
		TRACE((MMS_DEBUG, "FATAL error"));
	}
	dm_clear_dev();

	ioctl(wka->dm_drm_fd, DRM_MMS_MODE, 1);
	if (drv->drv_flags & DRV_UPDATE_EOF_POS) {
		wka->dm_flags |= DM_SEND_EOF_POS;
		drv->drv_flags &= ~DRV_UPDATE_EOF_POS;
	}
	if (drv->drv_flags & DRV_UPDATE_CAPACITY) {
		wka->dm_flags |= DM_SEND_CAPACITY;
		drv->drv_flags &= ~DRV_UPDATE_CAPACITY;
	}
	wka->dm_app_pid = 0;
	TRACE((MMS_DEBUG, "Closed by pid %d", (int)wka->dm_app_pid));
	drv->drv_flags &= ~DRV_OPENED;
	pthread_mutex_lock(&wka->dm_worker_mutex);
	wka->dm_work_todo = 1;
	pthread_cond_broadcast(&wka->dm_work_cv);
	pthread_mutex_unlock(&wka->dm_worker_mutex);
	return (0);
}

/*
 * Terminate a acrtridge by writing either two tapemarks or trailor labels
 */
int
dm_terminate_file(void)
{
	tapepos_t	pos;
	int		rc = 0;
	int		i;

	/*
	 * At EOF now
	 */
	drv->drv_flags |= DRV_EOF;

	if ((drv->drv_flags & DRV_UDATA) == 0) {
		/*
		 * Must be in user data to terminate file
		 */
		TRACE((MMS_ERR, "Not in user data. Can't terminate file"));
		return (EACCES);
	}

	if ((drv->drv_flags & DRV_TERM_FILE) == 0) {
		/*
		 * Must have set DRV_TERM_FILE to terminate a file
		 */
		TRACE((MMS_ERR,
		    "DRV_TERM_FILE not set. Can't terminate file"));
	}

	/*
	 * Save EOF pos
	 */
	(void) dm_get_eof_pos();

	/*
	 * Save capacity of cartridge
	 */
	drv->drv_avail = DRV_CALL(drv_get_avail_capacity, ());
	drv->drv_pc_avail = (drv->drv_avail * 100) / drv->drv_capacity;
	drv->drv_flags |= DRV_UPDATE_CAPACITY;

	if (DRV_CALL(drv_get_pos, (&pos)) != 0) {
		TRACE((MMS_ERR, "Can't read position"));
		return (EIO);
	}

	ioctl(drv->drv_fd, MTIOCLRERR, 0);	/* clear outstanding error */
	if (drv->drv_lbl_type == DRV_NL) {
		/* write 2 tapemarks to terminate a NL tape */
		for (i = 0; i < 2; i++) {
			if (DRV_CALL(drv_wtm, (2)) != 0) {
				DRV_CALL(drv_clrerr, ());
				continue;
			}
			break;
		}
		if (i == 2) {
			TRACE((MMS_ERR, "Can't terminate cartridge"));
			rc = EIO;
		}
	} else {
		/*
		 * Write EOF/EOV labels
		 */
		rc = dm_create_trailor_lbls();
	}

	/*
	 * Reposition to the end of user data
	 */
	if (rc != 0) {
		DRV_CALL(drv_clrerr, ());
	}
	if (DRV_CALL(drv_locate, (&drv->drv_eof_pos)) != 0) {
		TRACE((MMS_ERR, "Can't reposition to EOF"));
		rc = EIO;
	}
	if (dm_set_file_blksize(drv->drv_cur_blksize)) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "Set file blksize error"));
		rc = EIO;
	}
	drv->drv_flags &= ~DRV_TM;
	drv->drv_cur_pos = drv->drv_eof_pos;
	if (rc == 0) {
		/*
		 * Successfully wrote trailor labels and return to end of
		 * user data. We'er at EOF.
		 */
		drv->drv_flags |= DRV_EOF;
	}

	return (rc);
}

int
dm_create_trailor_lbls(void)
{
	int		i;

	for (i = 0; i < 2; i++) {
		if (DRV_CALL(drv_wtm, (1)) != 0) {
			if (serr->se_status == SUN_KEY_EOT &&
			    serr->se_resid == 1) {
				DRV_CALL(drv_wtm, (1));
			}
			continue;
		}
		break;
	}
	if (i == 2) {
		TRACE((MMS_ERR, "Can't write terminating FM"));
		return (EIO);
	}

	if (dm_set_label_blksize() != 0) {
		return (EIO);
	}

	for (i = 0; i < 2; i++) {
		if (dm_create_eof1() != 0) {
			continue;
		}
		break;
	}
	if (i == 2) {
		return (EIO);
	}

	for (i = 0; i < 2; i++) {
		if (dm_create_eof2() != 0) {
			continue;
		}
		break;
	}
	if (i == 2) {
		return (EIO);
	}

	for (i = 0; i < 2; i++) {
		if (DRV_CALL(drv_wtm, (2)) != 0) {
			continue;
		}
		break;
	}
	if (i == 2) {
		return (EIO);
	}

	return (0);
}

/*
 * dm_read and dm_write are entered because we asked for it
 */
int
dm_read(drm_reply_t *rep)
{
	TRACE((MMS_DEBUG, "Starting to Read"));
	if (drv->drv_flags & DRV_FATAL) {
		return (EIO);
	}
	memset(rep, 0, sizeof (rep));

	if (drv->drv_flags & DRV_TERM_FILE) {
		/*
		 * The previous movement command was an output command.
		 * Let the driver fail this read.
		 */
		TRACE((MMS_ERR, "attempted read after write"));
		return (0);
	}
	/*
	 * Notify when switching to output
	 */
	rep->drm_rep_flags |= DRM_REP_NOTIFY_WRITE;
	return (0);
}

int
dm_read_tm(drm_request_t *req)
{
	uint64_t	flags;
	char		buf[4096];
	tapepos_t	cur_pos = drv->drv_cur_pos;

	/*
	 * Hit a tapemark.
	 * Check to see if we reached EOF
	 */
	if (mnt->mnt_flags & MNT_NOBSD) {
		/*
		 * Alway cross TM to check trailor labels
		 */
		DRV_CALL(drv_fsf, (1));
	}

	if (dm_set_label_blksize()) {
		goto err;
	}
	if (drv->drv_flags & DRV_VALID_EOF_POS) {
		if (DRV_CALL(drv_get_pos, (&cur_pos)) != 0) {
			goto err;
		}
		if (cur_pos.lgclblkno > drv->drv_eof_pos.lgclblkno) {
			if (DRV_CALL(drv_locate, (&drv->drv_eof_pos)) != 0) {
				goto err;
			}
			drv->drv_cur_pos = drv->drv_eof_pos;
			drv->drv_flags &= ~DRV_TM;
			drv->drv_flags |= DRV_EOF;
		}
	} else if (dm_chk_eof() == 0) {
		if (DRV_CALL(drv_bsf, (1)) != 0) {
			goto err;
		}
		drv->drv_cur_pos = cur_pos;
		drv->drv_flags &= ~DRV_TM;
		drv->drv_flags |= DRV_EOF;
		(void) dm_get_eof_pos();
	}

	if ((drv->drv_flags & DRV_EOF) == 0) {
		/* Not at EOF */
		if (mnt->mnt_flags & MNT_NOBSD) {
			DRV_CALL(drv_bsf, (1));
			read(drv->drv_fd, buf, sizeof (buf));
		}
		drv->drv_flags |= DRV_TM;
		drv->drv_flags &= ~DRV_EOF;
	}

	flags = drv->drv_flags & (DRV_TM | DRV_EOF);
	dm_get_mtstat(DRV_SAVE_STAT);
	drv->drv_flags &= ~(DRV_TM | DRV_EOF);
	drv->drv_flags |= flags;

	drv->drv_mtget.drm_resid = req->drm_err_req.drm_resid;
	if (dm_set_file_blksize(drv->drv_cur_blksize)) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "Set file blksize error"));
		goto err;
	}
	return ((int)req->drm_err_req.drm_errno);

err:
	if (dm_set_file_blksize(drv->drv_cur_blksize)) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "Set file blksize error"));
	}
	drv->drv_mtget.drm_resid = req->drm_err_req.drm_resid;
	drv->drv_flags |= DRV_FATAL;
	TRACE((MMS_DEBUG, "FATAL error"));
	return (EIO);
}

int
dm_read_err(drm_request_t *req, drm_reply_t *rep)
{
	TRACE((MMS_ERR, "Read error: resid = %lld, errno = %lld, %s",
	    req->drm_err_req.drm_resid, req->drm_err_req.drm_errno,
	    strerror(req->drm_err_req.drm_errno)));
	drv->drv_flags &= ~DRV_VALID_STAT;
	dm_get_mtstat(DRV_SAVE_STAT);
	dm_get_mt_error(EIO);
	DRV_CALL(drv_proc_error, ());
	if (serr->se_senkey == KEY_HARDWARE_ERROR) {
		/* set DriveBroken to "yes" */
		(void) dm_send_drive_broken();
	} else if (serr->se_senkey == KEY_MEDIUM_ERROR) {
		/* Set CartridgeMediaError to "yes" */
		(void) dm_send_cartridge_media_error();
	}
	rep->drm_rep_flags |= DRM_REP_NOTIFY_WRITE;
	drv->drv_mtget.drm_resid = req->drm_err_req.drm_resid;
	return ((int)req->drm_err_req.drm_errno);

}

int
dm_write(drm_reply_t *rep)
{

	TRACE((MMS_DEBUG, "In dm_write"));

	if (drv->drv_flags & DRV_FATAL) {
		return (EIO);
	}

	/*
	 * Readonly, can't write to it
	 */
	if (drv->drv_flags & DRV_READONLY) {
		return (EACCES);
	}

	memset(rep, 0, sizeof (rep));
	drv->drv_flags |= DRV_TERM_FILE;
	drv->drv_flags &= ~DRV_VALID_EOF_POS;
	/*
	 * DRV_UPDATE_EOF_POS is only set when valid eof flag is updated
	 */
	if ((drv->drv_flags & DRV_UPDATE_EOF_POS) == 0) {
		drv->drv_flags |= DRV_UPDATE_EOF_POS;
		(void) dm_send_eof_pos();
	}
	/*
	 * Notify when switching to input
	 */
	if (mnt->mnt_flags & MNT_MMS) {
		rep->drm_rep_flags |= DRM_REP_NOTIFY_READ;
	}
	drv->drv_flags &= ~DRV_MOVE_FLAGS;
	return (0);
}

int
dm_write_0(drm_request_t *req, drm_reply_t *rep)
{
	TRACE((MMS_DEBUG, "In dm_write_0"));

	memset(rep, 0, sizeof (rep));
	dm_get_mtstat(DRV_SAVE_STAT);
	/*
	 * Notify when switching to input
	 */
	rep->drm_rep_flags |= DRM_REP_NOTIFY_READ;
	drv->drv_mtget.drm_resid = req->drm_err_req.drm_resid;
	return ((int)req->drm_err_req.drm_errno);
}

int
dm_write_err(drm_request_t *req, drm_reply_t *rep)
{
	TRACE((MMS_ERR, "Write error: resid = %lld, errno = %lld, %s",
	    req->drm_err_req.drm_resid, req->drm_err_req.drm_errno,
	    strerror(req->drm_err_req.drm_errno)));
	drv->drv_flags &= ~DRV_VALID_STAT;
	dm_get_mtstat(DRV_SAVE_STAT);
	dm_get_mt_error(EIO);
	DRV_CALL(drv_proc_error, ());
	if (serr->se_senkey == KEY_HARDWARE_ERROR) {
		/* set DriveBroken to "yes" */
		(void) dm_send_drive_broken();
	} else if (serr->se_senkey == KEY_MEDIUM_ERROR) {
		/* Set CartridgeMediaError to "yes" */
		(void) dm_send_cartridge_media_error();
	}
	rep->drm_rep_flags |= DRM_REP_NOTIFY_READ;
	drv->drv_mtget.drm_resid = req->drm_err_req.drm_resid;
	return ((int)req->drm_err_req.drm_errno);
}

int
dm_create_vol1(void)
{
	drv_vol1_t	*vol1 = &drv->drv_vol1;
	char		dumpbuf[MMS_DUMPBUF_SIZE(80)];
	char		*vp;
	char		*buf;

	memset(vol1, ' ', sizeof (drv_vol1_t));
	strncpy(vol1->vol1_id, "VOL1", 4);
	if (mnt->mnt_vid == NULL) {
		vp = mnt->mnt_pcl;
	} else {
		vp = mnt->mnt_vid;
	}

	buf = mms_strapp(NULL,
	    "%-6.6s", vp);
	strncpy(vol1->vol1_vid, buf, 6);
	free(buf);
	vol1->vol1_acc = ' ';
	strncpy(vol1->vol1_impid, DRV_IMPID, 13);
	strncpy(vol1->vol1_owner, VOL1_OWNER, 14);
	vol1->vol1_ver = '4';
	(void) mms_trace_dump((char *)vol1, 80, dumpbuf, sizeof (dumpbuf));
	TRACE((MMS_DEBUG, "VOL1 label:\n%s",
	    mms_trace_dump((char *)vol1, 80, dumpbuf, sizeof (dumpbuf))));

	if (DRV_CALL(drv_write, ((char *)vol1, 80)) != 80) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "Unable to write VOL1 label"));
		return (EIO);
	}
	drv->drv_lbl_type = DRV_AL;
	TRACE((MMS_DEBUG, "Wrote VOL1"));
	strncpy(drv->drv_vid, vol1->vol1_vid, 6);
	drv->drv_flags |= (DRV_VOL1 | DRV_IDENTIFIED);
	drv->drv_fseq = 1;
	return (0);
}

int
dm_create_hdr1(void)
{
	drv_hdr1_t	*hdr1 = &drv->drv_hdr1;
	char		*buf;
	char		dumpbuf[MMS_DUMPBUF_SIZE(80)];
	time_t		curtime;
	struct		tm tm;
	char		*tmp;

	memset(hdr1, ' ', sizeof (drv_hdr1_t));

	/*
	 * Get creation date
	 */
	curtime = time(NULL);
	localtime_r(&curtime, &tm);
	if (tm.tm_year > 100) {
		tm.tm_year -= 100;
		hdr1->hdr1_cdate[0] = '0';
	} else {
		hdr1->hdr1_cdate[0] = ' ';
	}
	tmp = mms_strapp(NULL,
	    "%2.2d", tm.tm_year);
	strncpy(hdr1->hdr1_cdate + 1, tmp, 2);
	free(tmp);
	tmp = mms_strapp(NULL,
	    "%3.3d", tm.tm_yday + 1);
	free(tmp);
	strncpy(hdr1->hdr1_cdate + 3, tmp, 3);

	/*
	 * Get expiration date
	 */
	if (drv->drv_retention == 0) {
		/* Don't use expiration date */
		strncpy(hdr1->hdr1_xdate, "000000", 6);
	} else if (drv->drv_retention == 99999) {
		/* Never expires */
		strncpy(hdr1->hdr1_xdate, "099366", 6);
	} else {
		/* expire time */
		curtime += ((drv->drv_retention + 1) * 24 * 60 * 60);
		localtime_r(&curtime, &tm);
		if (tm.tm_year > 100) {
			tm.tm_year -= 100;
			hdr1->hdr1_xdate[0] = '0';
		} else {
			hdr1->hdr1_xdate[0] = ' ';
		}
		tmp = mms_strapp(NULL,
		    "%2.2d", tm.tm_year);
		strncpy(hdr1->hdr1_xdate + 1, tmp, 2);
		free(tmp);
		tmp = mms_strapp(NULL,
		    "%3.3d", tm.tm_yday + 1);
		strncpy(hdr1->hdr1_xdate + 3, tmp, 3);
		free(tmp);
	}

	strncpy(hdr1->hdr1_id, "HDR1", 4);
	strncpy(hdr1->hdr1_fid, mnt->mnt_fname, 17);
	strncpy(hdr1->hdr1_fsnum, "0001", 4);
	buf = mms_strapp(NULL,
	    "%4.4d", mnt->mnt_fseq);
	strncpy(hdr1->hdr1_fseq, buf, 4);
	free(buf);
	strncpy(hdr1->hdr1_gnum, "0001", 4);
	strncpy(hdr1->hdr1_gver, "00", 2);
	strncpy(hdr1->hdr1_bcount, "000000", 6);
	strncpy(hdr1->hdr1_impid, DRV_IMPID, 13);
	(void) mms_trace_dump((char *)hdr1, 80, dumpbuf, sizeof (dumpbuf));
	TRACE((MMS_DEBUG, "HDR1 label:\n%s", dumpbuf));


	if (DRV_CALL(drv_write, ((char *)hdr1, 80)) != 80) {
		TRACE((MMS_ERR, "Unable to write HDR1 label"));
		return (EIO);
	}
	TRACE((MMS_DEBUG, "Wrote HDR1"));
	strncpy(drv->drv_fid, mnt->mnt_fname, 17);
	drv->drv_fid[17] = '\0';
	drv->drv_flags |= (DRV_HDR1 | DRV_VALIDATED_FNAME);
	return (0);
}

int
dm_create_hdr2(void)
{
	drv_hdr2_t	*hdr2 = &drv->drv_hdr2;
	char		*buf;
	char		dumpbuf[MMS_DUMPBUF_SIZE(80)];

	memset(hdr2, ' ', 80);
	strncpy(hdr2->hdr2_id, "HDR2", 4);
	if (drv->drv_flags & DRV_FIXED) {
		hdr2->hdr2_rformat = 'F';
	} else {
		hdr2->hdr2_rformat = 'D';
	}

	/*
	 * Put file blksize in label
	 */
	drv->drv_lbl_blksize = drv->drv_file_blksize;
	if (mnt->mnt_blksize < 99999) {
		buf = mms_strapp(NULL,
		    "%5.5d", drv->drv_lbl_blksize);
		strncpy(hdr2->hdr2_blklen, buf, sizeof (hdr2->hdr2_blklen));
		strncpy(hdr2->hdr2_rcdlen, buf, sizeof (hdr2->hdr2_rcdlen));
		free(buf);
	} else {
		strncpy(hdr2->hdr2_blklen, "99999", sizeof (hdr2->hdr2_blklen));
		strncpy(hdr2->hdr2_rcdlen, "99999", sizeof (hdr2->hdr2_rcdlen));
	}
	buf = mms_strapp(NULL,
	    "%10.10d", drv->drv_lbl_blksize);
	strncpy(hdr2->hdr2_blksize, buf, sizeof (hdr2->hdr2_blksize));
	free(buf);
	strncpy(hdr2->hdr2_off, "00", sizeof (hdr2->hdr2_off));
	(void) mms_trace_dump((char *)hdr2, 80, dumpbuf, sizeof (dumpbuf));
	TRACE((MMS_DEBUG, "HDR2 label:\n%s", dumpbuf));

	if (DRV_CALL(drv_write, ((char *)hdr2, 80)) != 80) {
		TRACE((MMS_ERR, "Unable to write HDR2 label"));
		return (EIO);
	}
	TRACE((MMS_DEBUG, "Wrote HDR2"));
	drv->drv_flags |= DRV_HDR2;
	return (0);
}

int
dm_create_eof1(void)
{
	drv_eof1_t	*eof1 = &drv->drv_eof1;
	char		*buf;
	char		dumpbuf[MMS_DUMPBUF_SIZE(80)];

	memset(eof1, ' ', sizeof (drv_eof1_t));
	strncpy(eof1->eof1_id, "EOF1", 4);
	strncpy(eof1->eof1_fid, mnt->mnt_fname, 17);
	strncpy(eof1->eof1_fsnum, "0001", 4);
	buf = mms_strapp(NULL,
	    "%4.4d", mnt->mnt_fseq);
	strncpy(eof1->eof1_fseq, buf, sizeof (eof1->eof1_fseq));
	strncpy(eof1->eof1_gnum, "0001", sizeof (eof1->eof1_gnum));
	strncpy(eof1->eof1_gver, "00", sizeof (eof1->eof1_gver));
	strncpy(eof1->eof1_cdate, drv->drv_hdr1.hdr1_cdate,
	    sizeof (eof1->eof1_cdate));
	strncpy(eof1->eof1_xdate, drv->drv_hdr1.hdr1_xdate,
	    sizeof (eof1->eof1_xdate));
	strncpy(eof1->eof1_bcount, "000000", sizeof (eof1->eof1_bcount));
	strncpy(eof1->eof1_impid, DRV_IMPID, sizeof (eof1->eof1_impid));
	free(buf);
	(void) mms_trace_dump((char *)eof1, 80, dumpbuf, sizeof (dumpbuf));
	TRACE((MMS_DEBUG, "EOF1 label:\n%s", dumpbuf));

	if (DRV_CALL(drv_write, ((char *)eof1, 80)) != 80) {
		TRACE((MMS_ERR, "Unable to write EOF1 label"));
		return (EIO);
	}
	TRACE((MMS_DEBUG, "Wrote EOF1"));
	strncpy(drv->drv_fid, mnt->mnt_fname, sizeof (drv->drv_fid));
	drv->drv_fid[17] = '\0';
	drv->drv_flags |= DRV_EOF1;
	return (0);
}

int
dm_create_eof2(void)
{
	drv_eof2_t	*eof2 = &drv->drv_eof2;
	char		*buf;
	char		dumpbuf[MMS_DUMPBUF_SIZE(80)];

	memset(eof2, ' ', 80);
	strncpy(eof2->eof2_id, "EOF2", 4);
	if (drv->drv_flags & DRV_FIXED) {
		eof2->eof2_rformat = 'F';
	} else {
		eof2->eof2_rformat = 'D';
	}
	if (mnt->mnt_blksize < 99999) {
		buf = mms_strapp(NULL,
		    "%5.5d", drv->drv_lbl_blksize);
		strncpy(eof2->eof2_blklen, buf, sizeof (eof2->eof2_blklen));
		strncpy(eof2->eof2_rcdlen, buf, sizeof (eof2->eof2_blklen));
		free(buf);
	} else {
		strncpy(eof2->eof2_blklen, "99999", sizeof (eof2->eof2_blklen));
		strncpy(eof2->eof2_rcdlen, "99999", sizeof (eof2->eof2_blklen));
	}
	buf = mms_strapp(NULL,
	    "%10.10d", drv->drv_lbl_blksize);
	strncpy(eof2->eof2_blksize, buf, sizeof (eof2->eof2_blksize));
	strncpy(eof2->eof2_off, "00", sizeof (eof2->eof2_off));
	free(buf);
	(void) mms_trace_dump((char *)eof2, 80, dumpbuf, sizeof (dumpbuf));
	TRACE((MMS_DEBUG, "EOF2 label:\n%s", dumpbuf));

	if (DRV_CALL(drv_write, ((char *)eof2, 80)) != 80) {
		TRACE((MMS_ERR, "Unable to write EOF2 label"));
		return (EIO);
	}
	TRACE((MMS_DEBUG, "Wrote EOF2"));
	drv->drv_flags |= DRV_EOF2;
	return (0);
}

int
dm_rewind_file(void)
{
	if ((drv->drv_flags & DRV_UDATA) == 0) {
		/*
		 * Must be in user data to rewind
		 */
		TRACE((MMS_ERR, "Not in user data. Can't rewind file"));
		return (EACCES);
	}

	if ((drv->drv_flags & DRV_VALID_BOF_POS) == 0) {
		/*
		 * Must have valid BOF position
		 */
		TRACE((MMS_ERR,
		    "Don't have BOF position. Can't rewind file"));
		return (EACCES);
	}

	if (drv->drv_flags & DRV_BOF) {
		/* Already at BOF */
		return (0);
	}
	if (DRV_CALL(drv_locate, (&drv->drv_bof_pos))) {
		TRACE((MMS_ERR, "Rewind file error"));
		return (EIO);
	}
	if (DRV_CALL(drv_bsb, (1, DRV_LOGICAL_CROSS_TM)) != 0) {
		if ((drv->drv_flags & DRV_TM)) {
			/* Hit a TM */
			DRV_CALL(drv_fsf, (1));
		} else if ((drv->drv_flags & DRV_BOM) == 0) {
			/* Did not hit BOM. Must be an error */
			return (EIO);
		}
	} else {
		/* Not at BOF */
		return (EIO);
	}

	drv->drv_mtget.drm_resid = 0;
	drv->drv_flags &= ~(DRV_BOM | DRV_TM);
	drv->drv_flags |= DRV_BOF;

	drv->drv_cur_pos = drv->drv_bof_pos;

	return (0);
}

int
dm_ioctl_clrerr(drm_reply_t *rep)
{
	int		rc = 0;

	memset(rep, 0, sizeof (drm_reply_t));
	rc = DRV_CALL(drv_clrerr, ());
	return (rc);
}

int
dm_ioctl_mtget(drm_request_t *req, drm_reply_t *rep)
{
	if ((req->drm_req_flags & DRM_REQ_MOVED) ||
	    (drv->drv_flags & DRV_VALID_STAT) == 0) {
		/* If tape moved since last signal, get new status */
		drv->drv_flags &= ~DRV_VALID_STAT;
		dm_get_mtstat(DRV_SAVE_STAT);
	}

	memcpy(&rep->drm_mtget_rep, &drv->drv_mtget, sizeof (drm_mtget_t));

	if (drv->drv_flags & DRV_BOF) {
		rep->drm_mtget_rep.drm_erreg = SUN_KEY_BOT;
	} else if (drv->drv_flags & DRV_EOF) {
		rep->drm_mtget_rep.drm_erreg = SUN_KEY_EOT;
	} else if (drv->drv_flags & DRV_TM) {
		rep->drm_mtget_rep.drm_erreg = SUN_KEY_EOF;
	}

	return (0);
}

int
dm_ioctl_rewind(void)
{
	int		rc = 0;

	if (drv->drv_flags & DRV_FATAL) {
		return (EIO);
	}

	drv->drv_flags &= ~(DRV_VALID_STAT | DRV_MOVE_FLAGS);
	if (drv->drv_flags & DRV_TERM_FILE) {
		if (dm_terminate_file() != 0) {
			TRACE((MMS_ERR, "Unable to terminate file"));
			rc = EIO;
		}
		drv->drv_flags &= ~DRV_TERM_FILE;
	}

	rc = dm_rewind_file();

	return (rc);
}

int
dm_ioctl_fsf(int count)
{
	int		rc = 0;
	char		buf[80];
	int		bytes;
	int		i;

	drv->drv_mtget.drm_resid = count;
	if (drv->drv_flags & DRV_FATAL) {
		return (EIO);
	}

	drv->drv_flags &= ~(DRV_VALID_STAT | DRV_MOVE_FLAGS);
	drv->drv_flags &= ~DRV_EOF;
	if (dm_set_label_blksize()) {
		return (EIO);
	}
	for (i = 0; i < count; i++) {
		if (DRV_CALL(drv_fsf, (1)) != 0) {
			rc = EIO;
			break;
		}
		/*
		 * Try to read the next block to see if it is a trailor label.
		 */
		while ((drv->drv_flags & DRV_EOF) == 0) {
			if ((bytes = DRV_CALL(drv_read, (buf, 80))) == 80) {
				if (strncmp(buf, "EOF1", 4) == 0 ||
				    strncmp(buf, "EOV1", 4) == 0) {
					/* Read trailor label */
					/* Reposition to EOF */
					TRACE((MMS_DEBUG, "Found EOF1/EOV1"));
					DRV_CALL(drv_bsf, (1));
					drv->drv_flags &= ~DRV_TM;
					drv->drv_flags |= DRV_EOF;
					(void) dm_get_eof_pos();
					rc = EIO;
					break;
				}
			}

			if (bytes > 0) {
				/*
				 * Read something other than a label
				 */
				if (i == (count - 1)) {
					/*
					 * Spaced requested TM
					 */
					DRV_CALL(drv_bsb,
					    (1, DRV_LOGICAL_CROSS_TM));
				}
				break;
			} else if (drv->drv_flags & DRV_TM) {
				/* Read another tapemark */
				drv->drv_flags &= ~DRV_TM;
				if (i == (count - 1)) {
					/*
					 * Spaced requested TM
					 */
					DRV_CALL(drv_bsf, (1));
					drv->drv_flags |= DRV_TM;
					break;
				} else {
					i++;		/* skipped another TM */
				}
				continue;	/* try to read label again */
			} else if (rc < 0) {
				if (serr->se_senkey == SUN_KEY_EOT ||
				    serr->se_senkey == KEY_BLANK_CHECK) {
					/* Hit EOM or blank check */
					TRACE((MMS_DEBUG,
					    "Hit EOT/BLANK CHECK"));
					drv->drv_flags |= DRV_EOF;
					if (dm_get_eof_pos()) {
						rc = EIO;
						goto done;
					}
					break;
				} else {
					/* Other error */
					rc = EIO;
					goto done;
				}
			} else {
				/*
				 * Some unknown error
				 */
				rc = EIO;
				break;
			}
		}

		/*
		 * Done if we are at EOF
		 */
		if (drv->drv_flags & DRV_EOF) {
			break;
		}
	}


done:
	dm_get_mtstat(DRV_SAVE_STAT);
	if (dm_set_file_blksize(drv->drv_cur_blksize)) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "Set file blksize error"));
		rc = EIO;
	}
	drv->drv_mtget.drm_resid = count - i;

	return (rc);
}

int
dm_ioctl_fsb(int count)
{
	uint64_t	flags;
	uint64_t	resid = 0;
	int		rc = 0;
	tapepos_t	pos;

	if (drv->drv_flags & DRV_FATAL) {
		return (EIO);
	}

	drv->drv_flags &= ~DRV_VALID_STAT;
	drv->drv_flags &= ~DRV_MOVE_FLAGS;

	if (dm_set_label_blksize()) {
		return (EIO);
	}
	if (DRV_CALL(drv_fsb, (count, DRV_LOGICAL_CROSS_TM)) != 0) {
		resid = serr->se_resid;
		if (drv->drv_flags & DRV_TM) {
			/*
			 * Hit a tapemark.
			 * Check to see if we reached EOF
			 */
			DRV_CALL(drv_get_pos, (&pos));
			if (drv->drv_flags & DRV_VALID_EOF_POS) {
				if (pos.lgclblkno >=
				    drv->drv_eof_pos.lgclblkno) {
					/* passed EOF position */
					DRV_CALL(drv_bsf, (1));
					drv->drv_flags &= ~DRV_TM;
					drv->drv_flags |= DRV_EOF;
					drv->drv_cur_pos = drv->drv_eof_pos;
				}
			} else if (dm_chk_eof() == 0) {
				/* Not at EOF, check if at EOF */
				DRV_CALL(drv_bsf, (1));
				drv->drv_flags &= ~DRV_TM;
				drv->drv_flags |= DRV_EOF;
			}
			/*
			 * If at EOF, and don't have EOF position, get it
			 */
			if (drv->drv_flags & DRV_EOF) {
				if ((drv->drv_flags & DRV_VALID_EOF_POS) == 0) {
					(void) dm_get_eof_pos();
					drv->drv_cur_pos = drv->drv_eof_pos;
				}
			} else {
				/*
				 * If not at EOF, must have hit a TM
				 */
				drv->drv_flags |= DRV_TM;
				/*
				 * Deal with Solaris BSB/NOBSD behavior
				 */
				if ((mnt->mnt_flags & MNT_MMS_TM) == 0) {
					/* Not MMS TM, then do not cross TM */
					DRV_CALL(drv_bsf, (1));
					DRV_CALL(drv_fsb,
					    (1, ~DRV_LOGICAL_CROSS_TM));
				}
			}
		}
		rc = EIO;
	}

	if (dm_set_file_blksize(drv->drv_cur_blksize)) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "Set file blksize error"));
		rc = EIO;
	}
	flags = drv->drv_flags & (DRV_EOF | DRV_TM);
	dm_get_mtstat(DRV_SAVE_STAT);
	drv->drv_flags &= ~(DRV_EOF | DRV_TM);
	drv->drv_flags |= flags;
	drv->drv_mtget.drm_resid = resid;

	return (rc);
}

int
dm_ioctl_bsf(int count)
{
	int		rc = 0;
	int		i;
	tapepos_t	pos;

	if (drv->drv_flags & DRV_FATAL) {
		return (EIO);
	}
	if (drv->drv_flags & DRV_TERM_FILE) {
		if (dm_terminate_file() != 0) {
			TRACE((MMS_ERR, "Write trailor label error"));
			rc = EIO;
		}
		drv->drv_flags &= ~DRV_TERM_FILE;
	}

	drv->drv_flags &= ~DRV_VALID_STAT;
	drv->drv_flags &= ~DRV_MOVE_FLAGS;
	for (i = 0; i < count; i++) {
		DRV_CALL(drv_bsf, (1));
		DRV_CALL(drv_get_pos, (&pos));
		if (pos.lgclblkno < drv->drv_bof_pos.lgclblkno) {
			DRV_CALL(drv_locate, (&drv->drv_bof_pos));
			drv->drv_flags |= DRV_BOF;
			drv->drv_cur_pos = drv->drv_bof_pos;
			rc = EIO;
			break;
		}
	}

	dm_get_mtstat(DRV_SAVE_STAT);
	drv->drv_mtget.drm_resid = count - i;
	if (serr->se_resid == 0) {
		drv->drv_flags |= DRV_TM;
	}

	return (rc);
}

int
dm_ioctl_bsb(int count)
{
	tapepos_t	pos;
	int		cross;
	int		resid = 0;
	int		flags;
	int		rc = 0;
	int		err = 0;

	if (drv->drv_flags & DRV_FATAL) {
		return (EIO);
	}

	if (drv->drv_flags & DRV_TERM_FILE) {
		if (dm_terminate_file() != 0) {
			TRACE((MMS_ERR, "Write trailor label error"));
			return (EIO);
		}
		drv->drv_flags &= ~DRV_TERM_FILE;
	}

	drv->drv_flags &= ~DRV_VALID_STAT;
	drv->drv_flags &= ~DRV_MOVE_FLAGS;
	if (mnt->mnt_flags & MNT_MMS_TM) {
		cross = DRV_LOGICAL_CROSS_TM;
	} else {
		cross = ~DRV_LOGICAL_CROSS_TM;
	}
	if (DRV_CALL(drv_bsb, (count, cross)) != 0) {
		err = errno;
		resid = serr->se_resid;
		if (drv->drv_flags & DRV_TM) {
			/* Hit a tapemark */
			DRV_CALL(drv_get_pos, (&pos));
			if (pos.lgclblkno <= drv->drv_bof_pos.lgclblkno) {
				if (DRV_CALL(drv_locate, (&drv->drv_bof_pos))) {
					/* Failed to reposition */
					rc = EIO;
				} else {
					drv->drv_flags &= ~DRV_TM;
					drv->drv_flags |= DRV_BOF;
					drv->drv_cur_pos = drv->drv_bof_pos;
				}
			}
		}
		rc = EIO;
		errno = err;
	}

	flags = drv->drv_flags & (DRV_TM | DRV_BOF);
	dm_get_mtstat(DRV_SAVE_STAT);
	drv->drv_flags &= ~(DRV_TM | DRV_BOF);
	drv->drv_flags |= flags;
	drv->drv_mtget.drm_resid = resid;

	return (rc);
}

int
dm_ioctl_seek(int count)
{
	int		rc = 0;
	uint64_t	flags;

	if (drv->drv_flags & DRV_FATAL) {
		return (EIO);
	}

	if (drv->drv_flags & DRV_TERM_FILE) {
		if (dm_terminate_file() != 0) {
			TRACE((MMS_ERR, "Write trailor label error"));
			return (EIO);
		}
		drv->drv_flags &= ~DRV_TERM_FILE;
	}

	drv->drv_flags &= ~DRV_VALID_STAT;
	drv->drv_flags &= ~DRV_MOVE_FLAGS;

	rc = DRV_CALL(drv_seek, ((uint64_t)count));
	if (rc) {
		DM_MSG_SEND((DM_ADM_ERR, DM_6522_MSG, DM_MSG_REASON));
		rc = EIO;
	}

	flags = drv->drv_flags & (DRV_TM | DRV_BOF);
	dm_get_mtstat(DRV_SAVE_STAT);
	drv->drv_flags &= ~(DRV_TM | DRV_BOF);
	drv->drv_flags |= flags;

	return (rc);
}

int
dm_ioctl_wtm(int count)
{
	int		rc = 0;
	int		resid = 0;

	if (drv->drv_flags & DRV_FATAL) {
		return (EIO);
	}

	/*
	 * Readonly, can't write to it
	 */
	if (drv->drv_flags & DRV_READONLY) {
		if (count > 0) {
			return (EACCES);
		}
	}

	drv->drv_flags &= ~DRV_MOVE_FLAGS;
	drv->drv_flags &= ~DRV_VALID_EOF_POS;
	drv->drv_flags &= ~DRV_VALID_STAT;
	if (count > 0) {
		/* Terminate file if writing TM to tape */
		drv->drv_flags |= DRV_TERM_FILE;
	}

	if (DRV_CALL(drv_wtm, (count)) != 0) {
		resid = serr->se_resid;
		rc = EIO;
	}
	dm_get_mtstat(DRV_SAVE_STAT);
	if (resid != count) {
		/* Wrote some TM */
		drv->drv_flags |= DRV_TM;
	}
	drv->drv_mtget.drm_resid = resid;

	return (rc);
}

int
dm_ioctl_set_blksize(uint64_t blksize)
{
	int	rc;

	rc = DRV_CALL(drv_set_blksize, (blksize));

	if (rc) {
		DM_MSG_SEND((DM_ADM_ERR, DM_6513_MSG, DM_MSG_REASON));
		return (rc);
	}
	if ((drv->drv_cur_blksize = blksize) == 0) {
		drv->drv_flags &= ~DRV_FIXED;
	} else {
		drv->drv_flags |= DRV_FIXED;
	}
	return (0);
}

int
dm_ioctl_getpos(drm_reply_t *rep)
{
	tapepos_t	pos;

	if (drv->drv_flags & DRV_FATAL) {
		return (EIO);
	}

	if (DRV_CALL(drv_get_pos, (&pos)) != 0) {
		return (EIO);
	}
	rep->drm_pos_rep.mms_pos = pos.lgclblkno;

	return (0);
}

int
dm_ioctl_mtgetpos(drm_reply_t *rep)
{
	if (drv->drv_flags & DRV_FATAL) {
		return (EIO);
	}

	if (DRV_CALL(drv_get_pos, (&rep->drm_mtpos_rep)) != 0) {
		return (EIO);
	}

	return (0);
}

int
dm_ioctl_mtrestpos(drm_request_t *req)
{
	if (drv->drv_flags & DRV_FATAL) {
		return (EIO);
	}

	if (DRV_CALL(drv_locate, (&req->drm_mtpos_req)) != 0) {
		return (EIO);
	}

	return (0);
}

int
dm_ioctl_locate(drm_request_t *req)
{
	int		rc = 0;
	uint64_t	blkno = req->drm_pos_req.mms_pos;
	tapepos_t	pos;

	if (drv->drv_flags & DRV_FATAL) {
		return (EIO);
	}

	if ((drv->drv_flags & DRV_VALID_EOF_POS) &&
	    drv->drv_eof_pos.lgclblkno < blkno) {
		TRACE((MMS_ERR, "Invalid locate to position: %lld",
		    blkno));
		return (EINVAL);
	}
	if (drv->drv_flags & DRV_TERM_FILE) {
		if (dm_terminate_file() != 0) {
			TRACE((MMS_ERR, "Unable to terminate file"));
			rc = EIO;
		}
		drv->drv_flags &= ~DRV_TERM_FILE;
	}

	memset(&pos, 0, sizeof (tapepos_t));
	pos.lgclblkno = blkno;
	pos.eof = ST_NO_EOF;
	pos.pmode = logical;
	if (DRV_CALL(drv_locate, (&pos)) != 0) {
		rc = EIO;
	}
	return (rc);
}

int
dm_ioctl_get_capacity(drm_reply_t *rep)
{
	int		rc = 0;
	mms_capacity_t	*cap = &rep->drm_cap_rep;

	if (DRV_CALL(drv_get_capacity, (cap)) != 0) {
		rc = EIO;
	}
	return (rc);
}

int
dm_ioctl_upt_capacity(void)
{
	int		rc = 0;

	if (dm_update_capacity() != 0) {
		rc = EIO;
	}
	return (rc);
}

int
dm_ioctl_set_density(void)
{
	int		rc = 0;

	if (drv->drv_flags & DRV_FATAL) {
		return (EIO);
	}

	if ((mnt->mnt_flags & MNT_AUTO_DEN) == 0) {
		if (DRV_CALL(drv_set_density,
		    (mnt->mnt_density->sym_code)) != 0) {
			drv->drv_flags |= DRV_FATAL;
			TRACE((MMS_DEBUG, "FATAL error"));
			rc = EIO;
		}
	}
	return (rc);
}

int
dm_ioctl_get_density(drm_reply_t *rep)
{
	int		rc = 0;
	int		den;

	if (DRV_CALL(drv_get_density, (&den, NULL)) != 0) {
		rc = EIO;
	} else {
		rep->drm_den_rep = den;
	}
	return (rc);
}

void
dm_clear_dev(void)
{
	int		i;

	/*
	 * Get rid of all attentions
	 */
	for (i = 0; i < 10; i++) {
		DRV_CALL(drv_tur, ());
	}
}

int
dm_set_label_blksize(void)
{
	if (DRV_CALL(drv_set_blksize, (0)) != 0) {
		return (EIO);
	}
	if (DRV_CALL(drv_set_compression, (0)) != 0) {
		return (EIO);
	}
	return (0);
}

int
dm_set_file_blksize(int blksize)
{
	int		rc;
	int		comp;
	int		bz;
	drm_blksize_t	blk;

	if (drv->drv_flags & DRV_FATAL) {
		return (EIO);
	}

	/*
	 * If blksize == -1, determine the blocksize.
	 * If blksize >= 0, use blksize
	 */
	if (blksize == -1) {
		if (drv->drv_file_blksize <= 0) {
			drv->drv_file_blksize = drv->drv_dflt_blksize;
		}

		if (drv->drv_flags & DRV_FIXED) {
			bz = drv->drv_file_blksize;
		} else {
			bz = 0;
		}
	} else {
		bz = blksize;
	}

	/*
	 * Set tape compression
	 */
	comp = (mnt->mnt_flags & MNT_COMPRESSION) ? 1 : 0;

	if (DRV_CALL(drv_set_blksize, (bz)) != 0) {
		TRACE((MMS_ERR, "Unable to set tape blksize"));
		return (EIO);
	} else if (DRV_CALL(drv_set_compression, (comp)) != 0) {
		TRACE((MMS_ERR, "Unable to set tape compression: %d",
		    comp));
		return (EIO);
	} else {
		drv->drv_cur_blksize = bz;
		blk.drm_fixed = (drv->drv_flags & DRV_FIXED) ? 1 : 0;
		blk.drm_blksize = drv->drv_file_blksize;
		rc = ioctl(drv->drv_fd, DRM_BLKSIZE, &blk);
		TRACE((MMS_DEBUG, "Max blksize %lld", blk.drm_blksize));
	}

	return (rc == 0 ? 0 : EIO);
}
