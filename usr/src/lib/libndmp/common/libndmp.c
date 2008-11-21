/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * BSD 3 Clause License
 *
 * Copyright (c) 2007, The Storage Networking Industry Association.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 	- Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 *
 * 	- Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in
 *	  the documentation and/or other materials provided with the
 *	  distribution.
 *
 *	- Neither the name of The Storage Networking Industry Association (SNIA)
 *	  nor the names of its contributors may be used to endorse or promote
 *	  products derived from this software without specific prior written
 *	  permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <locale.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <door.h>
#include <thread.h>
#include <ndmpd_door.h>
#include <libndmp.h>

static int ndmp_door_fildes = -1;
static char *buf;
static ndmp_door_ctx_t *dec_ctx;
static ndmp_door_ctx_t *enc_ctx;
static door_arg_t arg;
static mutex_t ndmp_lock = DEFAULTMUTEX;

static int ndmp_door_setup(int opcode);
static int ndmp_door_call(void);
static int ndmp_door_fini(void);

/* ndmp library APIs */
int
ndmp_get_devinfo(ndmp_devinfo_t **dip, size_t *size)
{
	ndmp_devinfo_t *dipptr;
	int i;
	int opcode = NDMP_DEVICES_GET_INFO;

	(void) mutex_lock(&ndmp_lock);
	if (ndmp_door_setup(opcode))
		goto err;

	if (ndmp_door_call())
		goto err;

	/* get the number of devices available */
	*size = ndmp_door_get_uint32(dec_ctx);

	*dip = malloc(sizeof (ndmp_devinfo_t) * *size);
	if (!*dip) {
		free(buf);
		ndmp_errno = ENDMP_MEM_ALLOC;
		goto err;
	}
	dipptr = *dip;
	for (i = 0; i < *size; i++, dipptr++) {
		dipptr->nd_dev_type = ndmp_door_get_int32(dec_ctx);
		dipptr->nd_name = ndmp_door_get_string(dec_ctx);
		dipptr->nd_lun = ndmp_door_get_int32(dec_ctx);
		dipptr->nd_sid = ndmp_door_get_int32(dec_ctx);
		dipptr->nd_vendor = ndmp_door_get_string(dec_ctx);
		dipptr->nd_product = ndmp_door_get_string(dec_ctx);
		dipptr->nd_revision = ndmp_door_get_string(dec_ctx);
		dipptr->nd_serial = ndmp_door_get_string(dec_ctx);
		dipptr->nd_wwn = ndmp_door_get_string(dec_ctx);
	}
	if (ndmp_door_fini()) {
		free(*dip);
		goto err;
	}
	(void) mutex_unlock(&ndmp_lock);
	return (0);
err:
	(void) mutex_unlock(&ndmp_lock);
	return (-1);
}

void
ndmp_get_devinfo_free(ndmp_devinfo_t *dip, size_t size)
{
	ndmp_devinfo_t *dipptr;
	int i;

	dipptr = dip;
	for (i = 0; i < size; i++, dipptr++) {
		free(dipptr->nd_name);
		free(dipptr->nd_vendor);
		free(dipptr->nd_product);
		free(dipptr->nd_revision);
	}
	free(dip);
}

int
ndmp_terminate_session(int session)
{
	int ret;
	int opcode = NDMP_TERMINATE_SESSION_ID;

	(void) mutex_lock(&ndmp_lock);
	if (ndmp_door_setup(opcode))
		goto err;

	ndmp_door_put_uint32(enc_ctx, session);
	if (ndmp_door_call())
		goto err;

	ret = ndmp_door_get_uint32(dec_ctx);
	if (ndmp_door_fini())
		goto err;

	(void) mutex_unlock(&ndmp_lock);
	return (ret);
err:
	(void) mutex_unlock(&ndmp_lock);
	return (-1);
}

int
ndmp_get_session_info(ndmp_session_info_t **sinfo, size_t *size)
{
	int status;
	int i, j;
	ndmp_session_info_t *sp;
	ndmp_dt_pval_t *ep;
	ndmp_dt_name_t *np;
	ndmp_dt_name_v3_t *npv3;
	int opcode = NDMP_SHOW;

	(void) mutex_lock(&ndmp_lock);
	if (ndmp_door_setup(opcode))
		goto err;

	if (ndmp_door_call())
		goto err;

	/* number of sessions */
	*size = ndmp_door_get_int32(dec_ctx);

	*sinfo = malloc((sizeof (ndmp_session_info_t)) * *size);
	if (!*sinfo) {
		free(buf);
		ndmp_errno = ENDMP_MEM_ALLOC;
		goto err;
	}
	sp = *sinfo;
	for (i = 0; i < *size; i++, sp++) {
		status = ndmp_door_get_int32(dec_ctx);
		if (status == NDMP_SESSION_NODATA)
			continue;

		/* connection common info */
		sp->nsi_sid = ndmp_door_get_int32(dec_ctx);
		sp->nsi_pver = ndmp_door_get_int32(dec_ctx);
		sp->nsi_auth = ndmp_door_get_int32(dec_ctx);
		sp->nsi_eof = ndmp_door_get_int32(dec_ctx);
		sp->nsi_cl_addr = ndmp_door_get_string(dec_ctx);
		/*
		 * scsi and tape data are same for all version,
		 * so keep reading
		 */
		/* connection common scsi info.   */
		sp->nsi_scsi.ns_scsi_open = ndmp_door_get_int32(dec_ctx);
		sp->nsi_scsi.ns_adapter_name = ndmp_door_get_string(dec_ctx);
		sp->nsi_scsi.ns_valid_target_set = ndmp_door_get_int32(dec_ctx);
		if (sp->nsi_scsi.ns_valid_target_set) {
			sp->nsi_scsi.ns_scsi_id = ndmp_door_get_int32(dec_ctx);
			sp->nsi_scsi.ns_lun = ndmp_door_get_int32(dec_ctx);
		}

		/* connection common tape info.   */
		sp->nsi_tape.nt_fd = ndmp_door_get_int32(dec_ctx);
		if (sp->nsi_tape.nt_fd != -1) {
			sp->nsi_tape.nt_rec_count =
			    ndmp_door_get_uint64(dec_ctx);
			sp->nsi_tape.nt_mode = ndmp_door_get_int32(dec_ctx);
			sp->nsi_tape.nt_dev_name =
			    ndmp_door_get_string(dec_ctx);
			sp->nsi_tape.nt_adapter_name =
			    ndmp_door_get_string(dec_ctx);
			sp->nsi_tape.nt_sid = ndmp_door_get_int32(dec_ctx);
			sp->nsi_tape.nt_lun = ndmp_door_get_int32(dec_ctx);
		}
		/* all the V2 mover data are same as V3/V4 */
		sp->nsi_mover.nm_state = ndmp_door_get_int32(dec_ctx);
		sp->nsi_mover.nm_mode = ndmp_door_get_int32(dec_ctx);
		sp->nsi_mover.nm_pause_reason = ndmp_door_get_int32(dec_ctx);
		sp->nsi_mover.nm_halt_reason = ndmp_door_get_int32(dec_ctx);
		sp->nsi_mover.nm_rec_size = ndmp_door_get_uint64(dec_ctx);
		sp->nsi_mover.nm_rec_num = ndmp_door_get_uint64(dec_ctx);
		sp->nsi_mover.nm_mov_pos = ndmp_door_get_uint64(dec_ctx);
		sp->nsi_mover.nm_window_offset = ndmp_door_get_uint64(dec_ctx);
		sp->nsi_mover.nm_window_length = ndmp_door_get_uint64(dec_ctx);
		sp->nsi_mover.nm_sock = ndmp_door_get_int32(dec_ctx);

		/* Read V3/V4 mover info */
		if ((sp->nsi_pver == NDMP_V3) || (sp->nsi_pver == NDMP_V4)) {
			sp->nsi_mover.nm_listen_sock =
			    ndmp_door_get_int32(dec_ctx);
			sp->nsi_mover.nm_addr_type =
			    ndmp_door_get_int32(dec_ctx);
			sp->nsi_mover.nm_tcp_addr =
			    ndmp_door_get_string(dec_ctx);
		}

		/* connection common data info */
		sp->nsi_data.nd_oper = ndmp_door_get_int32(dec_ctx);
		sp->nsi_data.nd_state = ndmp_door_get_int32(dec_ctx);
		sp->nsi_data.nd_halt_reason = ndmp_door_get_int32(dec_ctx);
		sp->nsi_data.nd_sock = ndmp_door_get_int32(dec_ctx);
		sp->nsi_data.nd_addr_type = ndmp_door_get_int32(dec_ctx);
		sp->nsi_data.nd_abort = ndmp_door_get_int32(dec_ctx);
		sp->nsi_data.nd_read_offset = ndmp_door_get_uint64(dec_ctx);
		sp->nsi_data.nd_read_length = ndmp_door_get_uint64(dec_ctx);
		sp->nsi_data.nd_total_size = ndmp_door_get_uint64(dec_ctx);
		sp->nsi_data.nd_env_len = ndmp_door_get_uint64(dec_ctx);
		sp->nsi_data.nd_env =
		    malloc(sizeof (ndmp_dt_pval_t) * sp->nsi_data.nd_env_len);
		if (!sp->nsi_data.nd_env) {
			free(buf);
			ndmp_errno = ENDMP_MEM_ALLOC;
			goto err;
		}
		ep = sp->nsi_data.nd_env;
		for (j = 0; j < sp->nsi_data.nd_env_len; j++, ep++) {
			ep->np_name = ndmp_door_get_string(dec_ctx);
			ep->np_value = ndmp_door_get_string(dec_ctx);
		}
		sp->nsi_data.nd_tcp_addr = ndmp_door_get_string(dec_ctx);

		/* Read V2 data info */
		if (sp->nsi_pver == NDMP_V2) {
			sp->nsi_data.nld_nlist_len =
			    ndmp_door_get_int64(dec_ctx);
			sp->nsi_data.nd_nlist.nld_nlist =
			    malloc(sizeof (ndmp_dt_name_t) *
			    sp->nsi_data.nld_nlist_len);
			if (!sp->nsi_data.nd_nlist.nld_nlist) {
				free(buf);
				ndmp_errno = ENDMP_MEM_ALLOC;
				goto err;
			}
			np = sp->nsi_data.nd_nlist.nld_nlist;

			for (j = 0; j < sp->nsi_data.nld_nlist_len; j++, np++) {
				np->nn_name = ndmp_door_get_string(dec_ctx);
				np->nn_dest = ndmp_door_get_string(dec_ctx);
			}
		} else if ((sp->nsi_pver == NDMP_V3) ||
		    (sp->nsi_pver == NDMP_V4)) {
			/* Read V3/V4 data info */
			sp->nsi_data.nd_nlist.nld_dt_v3.dv3_listen_sock =
			    ndmp_door_get_int32(dec_ctx);
			sp->nsi_data.nd_nlist.nld_dt_v3.dv3_bytes_processed =
			    ndmp_door_get_uint64(dec_ctx);
			sp->nsi_data.nld_nlist_len =
			    ndmp_door_get_uint64(dec_ctx);
			sp->nsi_data.nd_nlist.nld_dt_v3.dv3_nlist =
			    malloc(sizeof (ndmp_dt_name_v3_t) *
			    sp->nsi_data.nld_nlist_len);
			if (!sp->nsi_data.nd_nlist.nld_dt_v3.dv3_nlist) {
				free(buf);
				ndmp_errno = ENDMP_MEM_ALLOC;
				goto err;
			}
			npv3 = sp->nsi_data.nd_nlist.nld_dt_v3.dv3_nlist;
			for (j = 0; j < sp->nsi_data.nld_nlist_len;
			    j++, npv3++) {
				npv3->nn3_opath = ndmp_door_get_string(dec_ctx);
				npv3->nn3_dpath = ndmp_door_get_string(dec_ctx);
				npv3->nn3_node = ndmp_door_get_uint64(dec_ctx);
				npv3->nn3_fh_info =
				    ndmp_door_get_uint64(dec_ctx);
			}
		}
	}

	if (ndmp_door_fini())
		goto err;

	(void) mutex_unlock(&ndmp_lock);
	return (0);
err:
	(void) mutex_unlock(&ndmp_lock);
	return (-1);
}

void
ndmp_get_session_info_free(ndmp_session_info_t *sinfo, size_t size)
{
	ndmp_session_info_t *sp;
	ndmp_dt_pval_t *ep;
	ndmp_dt_name_t *np;
	ndmp_dt_name_v3_t *npv3;
	int i, j;

	sp = sinfo;
	for (i = 0; i < size; i++, sp++) {
		free(sp->nsi_cl_addr);
		free(sp->nsi_scsi.ns_adapter_name);
		if (sp->nsi_tape.nt_fd != -1) {
			free(sp->nsi_tape.nt_dev_name);
			free(sp->nsi_tape.nt_adapter_name);
		}
		if ((sp->nsi_pver == NDMP_V3) || (sp->nsi_pver == NDMP_V4))
			free(sp->nsi_mover.nm_tcp_addr);

		ep = sp->nsi_data.nd_env;
		for (j = 0; j < sp->nsi_data.nd_env_len; j++, ep++) {
			free(ep->np_name);
			free(ep->np_value);
		}
		free(sp->nsi_data.nd_env);
		free(sp->nsi_data.nd_tcp_addr);

		if (sp->nsi_pver == NDMP_V2) {
			np = sp->nsi_data.nd_nlist.nld_nlist;
			for (j = 0; j < sp->nsi_data.nld_nlist_len; j++, np++) {
				free(np->nn_name);
				free(np->nn_dest);
			}
			free(sp->nsi_data.nd_nlist.nld_nlist);
		} else if ((sp->nsi_pver == NDMP_V3) ||
		    (sp->nsi_pver == NDMP_V4)) {
			npv3 = sp->nsi_data.nd_nlist.nld_dt_v3.dv3_nlist;
			for (j = 0; j < sp->nsi_data.nld_nlist_len;
			    j++, npv3++) {
				free(npv3->nn3_opath);
				free(npv3->nn3_dpath);
			}
			free(sp->nsi_data.nd_nlist.nld_dt_v3.dv3_nlist);
		}
	}
	free(sinfo);
}

/* ARGSUSED */
int
ndmp_get_stats(ndmp_stat_t *statp)
{
	int opcode = NDMP_GET_STAT;

	(void) mutex_lock(&ndmp_lock);
	if (!statp) {
		ndmp_errno = ENDMP_INVALID_ARG;
		goto err;
	}

	if (ndmp_door_setup(opcode))
		goto err;

	if (ndmp_door_call())
		goto err;

	statp->ns_trun = ndmp_door_get_uint32(dec_ctx);
	statp->ns_twait = ndmp_door_get_uint32(dec_ctx);
	statp->ns_nbk = ndmp_door_get_uint32(dec_ctx);
	statp->ns_nrs = ndmp_door_get_uint32(dec_ctx);
	statp->ns_rfile = ndmp_door_get_uint32(dec_ctx);
	statp->ns_wfile = ndmp_door_get_uint32(dec_ctx);
	statp->ns_rdisk = ndmp_door_get_uint64(dec_ctx);
	statp->ns_wdisk = ndmp_door_get_uint64(dec_ctx);
	statp->ns_rtape = ndmp_door_get_uint64(dec_ctx);
	statp->ns_wtape = ndmp_door_get_uint64(dec_ctx);

	if (ndmp_door_fini())
		goto err;

	(void) mutex_unlock(&ndmp_lock);
	return (0);
err:
	(void) mutex_unlock(&ndmp_lock);
	return (-1);
}

int
ndmp_door_status(void)
{
	int opcode = NDMP_GET_DOOR_STATUS;

	(void) mutex_lock(&ndmp_lock);
	if (ndmp_door_setup(opcode))
		goto err;

	if (ndmp_door_call())
		goto err;

	if (ndmp_door_fini())
		goto err;

	(void) mutex_unlock(&ndmp_lock);
	return (0);
err:
	(void) mutex_unlock(&ndmp_lock);
	return (-1);
}

static int
ndmp_door_setup(int opcode)
{
	/* Open channel to NDMP service */
	if ((ndmp_door_fildes == -1) &&
	    (ndmp_door_fildes = open(NDMP_DOOR_SVC, O_RDONLY)) < 0) {
		ndmp_errno = ENDMP_DOOR_OPEN;
		return (-1);
	}

	buf = malloc(NDMP_DOOR_SIZE);
	if (!buf) {
		ndmp_errno = ENDMP_MEM_ALLOC;
		return (-1);
	}

	enc_ctx = ndmp_door_encode_start(buf, NDMP_DOOR_SIZE);
	if (enc_ctx == 0) {
		free(buf);
		ndmp_errno = ENDMP_DOOR_ENCODE_START;
		return (-1);
	}
	ndmp_door_put_uint32(enc_ctx, opcode);
	return (0);
}

static int
ndmp_door_call(void)
{
	uint32_t used;
	int rc;

	if ((ndmp_door_encode_finish(enc_ctx, &used)) != 0) {
		free(buf);
		ndmp_errno = ENDMP_DOOR_ENCODE_FINISH;
		return (-1);
	}

	arg.data_ptr = buf;
	arg.data_size = used;
	arg.desc_ptr = NULL;
	arg.desc_num = 0;
	arg.rbuf = buf;
	arg.rsize = NDMP_DOOR_SIZE;

	if (door_call(ndmp_door_fildes, &arg) < 0) {
		free(buf);
		ndmp_errno = ENDMP_DOOR_SRV_TIMEOUT;
		(void) close(ndmp_door_fildes);
		ndmp_door_fildes = -1;
		return (-1);
	}

	dec_ctx = ndmp_door_decode_start(arg.data_ptr, arg.data_size);
	rc = ndmp_door_get_uint32(dec_ctx);
	if (rc != NDMP_DOOR_SRV_SUCCESS) {
		free(buf);
		ndmp_errno = ENDMP_DOOR_SRV_OPERATION;
		return (-1);
	}
	return (0);
}

static int
ndmp_door_fini(void)
{
	if ((ndmp_door_decode_finish(dec_ctx)) != 0) {
		free(buf);
		ndmp_errno = ENDMP_DOOR_DECODE_FINISH;
		return (-1);
	}
	free(buf);
	return (0);
}
