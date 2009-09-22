/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
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

/* This file contains all the door server code */

#include <door.h>
#include <alloca.h>
#include <errno.h>
#include <note.h>
#include <libintl.h>
#include <ndmpd_door.h>
#include "ndmpd.h"

/* static variables */
static int 	ndmp_door_fildes = -1;
static mutex_t	ndmp_doorsrv_mutex;

/* static routines */
static void ndmp_door_server(void *cookie, char *ptr, size_t size,
    door_desc_t *dp, uint_t n_desc);

/*
 * Statistics used in ndmpstat command
 */
ndmp_stat_t ndstat;

int
ndmp_door_init(void)
{
	int fd;

	(void) mutex_lock(&ndmp_doorsrv_mutex);

	if (ndmp_door_fildes != -1) {
		NDMP_LOG(LOG_DEBUG,
		    "ndmp_door_init: ndmpd service is already running.");
		(void) mutex_unlock(&ndmp_doorsrv_mutex);
		return (0);
	}

	if ((ndmp_door_fildes = door_create(ndmp_door_server,
	    NULL, DOOR_UNREF)) < 0) {
		NDMP_LOG(LOG_DEBUG, "ndmp_door_init: Could not create door.");
		(void) mutex_unlock(&ndmp_doorsrv_mutex);
		return (-1);
	}

	(void) unlink(NDMP_DOOR_SVC);

	if ((fd = creat(NDMP_DOOR_SVC, 0444)) < 0) {
		NDMP_LOG(LOG_DEBUG, "ndmp_door_init: Can't create %s: %m.",
		    NDMP_DOOR_SVC);
		(void) door_revoke(ndmp_door_fildes);
		ndmp_door_fildes = -1;
		(void) mutex_unlock(&ndmp_doorsrv_mutex);
		return (-1);
	}

	(void) close(fd);
	(void) fdetach(NDMP_DOOR_SVC);

	if (fattach(ndmp_door_fildes, NDMP_DOOR_SVC) < 0) {
		NDMP_LOG(LOG_DEBUG, "ndmp_door_init: fattach failed %m");
		(void) door_revoke(ndmp_door_fildes);
		ndmp_door_fildes = -1;
		(void) mutex_unlock(&ndmp_doorsrv_mutex);
		return (-1);
	}

	NDMP_LOG(LOG_DEBUG, "ndmp_door_init: Door server successfully started");
	(void) mutex_unlock(&ndmp_doorsrv_mutex);
	return (0);
}

void
ndmp_door_fini(void)
{
	(void) mutex_lock(&ndmp_doorsrv_mutex);

	if (ndmp_door_fildes != -1) {
		(void) fdetach(NDMP_DOOR_SVC);
		(void) door_revoke(ndmp_door_fildes);
		ndmp_door_fildes = -1;
	}

	(void) mutex_unlock(&ndmp_doorsrv_mutex);
}

boolean_t
ndmp_door_check(void)
{
	door_info_t info;
	int door;

	if ((door = open(NDMP_DOOR_SVC, O_RDONLY)) < 0)
		return (0);

	if (door_info(door, &info) < 0) {
		(void) close(door);
		return (0);
	}

	if (info.di_target > 0) {
		NDMP_LOG(LOG_ERR,
		    "Service already running: pid %ld", info.di_target);
		(void) close(door);
		return (1);
	}

	(void) close(door);
	return (0);
}

/* door server */
/*ARGSUSED*/
void
ndmp_door_server(void *cookie, char *ptr, size_t size,
    door_desc_t *dp, uint_t n_desc)
{
	NOTE(ARGUNUSED(cookie,dp,n_desc))
	int req_type;
	char *buf;
	int buflen;
	unsigned int used;
	ndmp_door_ctx_t *dec_ctx;
	ndmp_door_ctx_t *enc_ctx;
	unsigned int dec_status;
	unsigned int enc_status;

	dec_ctx = ndmp_door_decode_start(ptr, size);
	if (dec_ctx == 0)
		return;

	req_type = ndmp_door_get_uint32(dec_ctx);
	buflen = NDMP_DOOR_SIZE;

	if ((buf = alloca(buflen)) == NULL) {
		NDMP_LOG(LOG_DEBUG, "Out of memory.");
		(void) ndmp_door_decode_finish(dec_ctx);
		return;
	}

	enc_ctx = ndmp_door_encode_start(buf, buflen);
	if (enc_ctx == 0) {
		(void) ndmp_door_decode_finish(dec_ctx);
		return;
	}

	if (req_type != NDMP_GET_STAT)
		NDMP_LOG(LOG_DEBUG, "ndmp_door_server: req_type=%d", req_type);

	switch (req_type) {
	case NDMP_GET_DOOR_STATUS: {
		ndmp_door_put_int32(enc_ctx, NDMP_DOOR_SRV_SUCCESS);
		break;
		}
	case NDMP_DEVICES_GET_INFO: {
		ndmp_door_put_int32(enc_ctx, NDMP_DOOR_SRV_SUCCESS);
		ndmpd_get_devs(enc_ctx);
		break;
		}
	case NDMP_SHOW: {
		ndmp_door_put_int32(enc_ctx, NDMP_DOOR_SRV_SUCCESS);
		ndmp_connect_list_get(enc_ctx);
		break;
		}
	case NDMP_TERMINATE_SESSION_ID: {
		int status, id;
		id = ndmp_door_get_int32(dec_ctx);
		status = ndmpd_connect_kill_id(id);
		if (status == -1) /* session not found */
			ndmp_door_put_int32(enc_ctx,
			    NDMP_DOOR_SRV_SUCCESS);
		else
			ndmp_door_put_int32(enc_ctx,
			    NDMP_DOOR_SRV_SUCCESS);
		ndmp_door_put_int32(enc_ctx, status);
		break;
		}

	case NDMP_GET_STAT:
		ndmp_door_put_int32(enc_ctx, NDMP_DOOR_SRV_SUCCESS);
		ndmp_door_put_uint32(enc_ctx, ndstat.ns_trun);
		ndmp_door_put_uint32(enc_ctx, ndstat.ns_twait);
		ndmp_door_put_uint32(enc_ctx, ndstat.ns_nbk);
		ndmp_door_put_uint32(enc_ctx, ndstat.ns_nrs);
		ndmp_door_put_uint32(enc_ctx, ndstat.ns_rfile);
		ndmp_door_put_uint32(enc_ctx, ndstat.ns_wfile);
		ndmp_door_put_uint64(enc_ctx, ndstat.ns_rdisk);
		ndmp_door_put_uint64(enc_ctx, ndstat.ns_wdisk);
		ndmp_door_put_uint64(enc_ctx, ndstat.ns_rtape);
		ndmp_door_put_uint64(enc_ctx, ndstat.ns_wtape);
		break;

	default:
		NDMP_LOG(LOG_DEBUG,
		    "ndmp_door_server: Invalid request type 0x%x", req_type);
		goto decode_error;
	}

	if ((dec_status = ndmp_door_decode_finish(dec_ctx)) != 0)
		goto decode_error;

	if ((enc_status = ndmp_door_encode_finish(enc_ctx, &used)) != 0)
		goto encode_error;

	(void) door_return(buf, used, NULL, 0);

	return;

decode_error:
	ndmp_door_put_int32(enc_ctx, NDMP_DOOR_SRV_ERROR);
	ndmp_door_put_uint32(enc_ctx, dec_status);
	(void) ndmp_door_encode_finish(enc_ctx, &used);
	(void) door_return(buf, used, NULL, 0);
	return;

encode_error:
	enc_ctx = ndmp_door_encode_start(buf, buflen);
	ndmp_door_put_int32(enc_ctx, NDMP_DOOR_SRV_ERROR);
	ndmp_door_put_uint32(enc_ctx, enc_status);
	(void) ndmp_door_encode_finish(enc_ctx, &used);
	(void) door_return(buf, used, NULL, 0);
}
