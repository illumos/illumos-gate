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
/* Copyright (c) 2007, The Storage Networking Industry Association. */
/* Copyright (c) 1996, 1997 PDC, Network Appliance. All Rights Reserved */

#include <sys/types.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include "ndmpd_common.h"
#include "ndmpd.h"
#include <string.h>
#include <sys/scsi/impl/uscsi.h>
#include <sys/scsi/scsi.h>

static void scsi_open_send_reply(ndmp_connection_t *connection, int err);
static void common_open(ndmp_connection_t *connection, char *devname);
static void common_set_target(ndmp_connection_t *connection, char *device,
    ushort_t controller, ushort_t sid, ushort_t lun);


/*
 * ************************************************************************
 * NDMP V2 HANDLERS
 * ************************************************************************
 */

/*
 * ndmpd_scsi_open_v2
 *
 * This handler opens the specified SCSI device.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   body       (input) - request message body.
 *
 * Returns:
 *   void
 */
void
ndmpd_scsi_open_v2(ndmp_connection_t *connection, void *body)
{
	ndmp_scsi_open_request_v2 *request = (ndmp_scsi_open_request_v2 *)body;

	common_open(connection, request->device.name);
}


/*
 * ndmpd_scsi_close_v2
 *
 * This handler closes the currently open SCSI device.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   body       (input) - request message body.
 *
 * Returns:
 *   void
 */
/*ARGSUSED*/
void
ndmpd_scsi_close_v2(ndmp_connection_t *connection, void *body)
{
	ndmp_scsi_close_reply reply;
	ndmpd_session_t *session = ndmp_get_client_data(connection);

	if (session->ns_scsi.sd_is_open == -1) {
		NDMP_LOG(LOG_ERR, "SCSI device is not open.");
		reply.error = NDMP_DEV_NOT_OPEN_ERR;
		ndmp_send_reply(connection, (void *) &reply,
		    "sending scsi_close reply");
		return;
	}
	(void) ndmp_open_list_del(session->ns_scsi.sd_adapter_name,
	    session->ns_scsi.sd_sid,
	    session->ns_scsi.sd_lun);
	(void) close(session->ns_scsi.sd_devid);

	session->ns_scsi.sd_is_open = -1;
	session->ns_scsi.sd_devid = -1;
	session->ns_scsi.sd_sid = 0;
	session->ns_scsi.sd_lun = 0;
	session->ns_scsi.sd_valid_target_set = FALSE;
	(void) memset(session->ns_scsi.sd_adapter_name, 0,
	    sizeof (session->ns_scsi.sd_adapter_name));

	reply.error = NDMP_NO_ERR;
	ndmp_send_reply(connection, (void *) &reply,
	    "sending scsi_close reply");
}


/*
 * ndmpd_scsi_get_state_v2
 *
 * This handler returns state information for the currently open SCSI device.
 * Since the implementation only supports the opening of a specific SCSI
 * device, as opposed to a device that can talk to multiple SCSI targets,
 * this request is not supported. This request is only appropriate for
 * implementations that support device files that can target multiple
 * SCSI devices.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   body       (input) - request message body.
 *
 * Returns:
 *   void
 */
/*ARGSUSED*/
void
ndmpd_scsi_get_state_v2(ndmp_connection_t *connection, void *body)
{
	ndmp_scsi_get_state_reply reply;
	ndmpd_session_t *session = ndmp_get_client_data(connection);

	if (session->ns_scsi.sd_is_open == -1)
		reply.error = NDMP_DEV_NOT_OPEN_ERR;
	else if (!session->ns_scsi.sd_valid_target_set) {
		reply.error = NDMP_NO_ERR;
		reply.target_controller = -1;
		reply.target_id = -1;
		reply.target_lun = -1;
	} else {
		reply.error = NDMP_NO_ERR;
		reply.target_controller = 0;
		reply.target_id = session->ns_scsi.sd_sid;
		reply.target_lun = session->ns_scsi.sd_lun;
	}

	ndmp_send_reply(connection, (void *) &reply,
	    "sending scsi_get_state reply");
}


/*
 * ndmpd_scsi_set_target_v2
 *
 * This handler sets the SCSI target of the SCSI device.
 * It is only valid to use this request if the opened SCSI device
 * is capable of talking to multiple SCSI targets.
 * Since the implementation only supports the opening of a specific SCSI
 * device, as opposed to a device that can talk to multiple SCSI targets,
 * this request is not supported. This request is only appropriate for
 * implementations that support device files that can target multiple
 * SCSI devices.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   body       (input) - request message body.
 *
 * Returns:
 *   void
 */
void
ndmpd_scsi_set_target_v2(ndmp_connection_t *connection, void *body)
{
	ndmp_scsi_set_target_request_v2 *request;

	request = (ndmp_scsi_set_target_request_v2 *) body;

	common_set_target(connection, request->device.name,
	    request->target_controller, request->target_id,
	    request->target_lun);
}


/*
 * ndmpd_scsi_reset_device_v2
 *
 * This handler resets the currently targeted SCSI device.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   body       (input) - request message body.
 *
 * Returns:
 *   void
 */
/*ARGSUSED*/
void
ndmpd_scsi_reset_device_v2(ndmp_connection_t *connection, void *body)
{
	ndmp_scsi_reset_device_reply reply;


	ndmpd_session_t *session = ndmp_get_client_data(connection);
	struct uscsi_cmd  cmd;

	if (session->ns_scsi.sd_devid == -1) {
		NDMP_LOG(LOG_ERR, "SCSI device is not open.");
		reply.error = NDMP_DEV_NOT_OPEN_ERR;
	} else {
		reply.error = NDMP_NO_ERR;
		(void) memset((void*)&cmd, 0, sizeof (cmd));
		cmd.uscsi_flags |= USCSI_RESET;
		if (ioctl(session->ns_scsi.sd_devid, USCSICMD, &cmd) < 0) {
			NDMP_LOG(LOG_ERR, "USCSI reset failed: %m.");
			NDMP_LOG(LOG_DEBUG,
			    "ioctl(USCSICMD) USCSI_RESET failed: %m.");
			reply.error = NDMP_IO_ERR;
		}
	}

	ndmp_send_reply(connection, (void *) &reply,
	    "sending scsi_reset_device reply");
}


/*
 * ndmpd_scsi_reset_bus_v2
 *
 * This handler resets the currently targeted SCSI bus.
 *
 * Request not yet supported.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   body       (input) - request message body.
 *
 * Returns:
 *   void
 */
/*ARGSUSED*/
void
ndmpd_scsi_reset_bus_v2(ndmp_connection_t *connection, void *body)
{
	ndmp_scsi_reset_bus_reply reply;

	NDMP_LOG(LOG_DEBUG, "request not supported");
	reply.error = NDMP_NOT_SUPPORTED_ERR;

	ndmp_send_reply(connection, (void *) &reply,
	    "sending scsi_reset_bus reply");
}


/*
 * ndmpd_scsi_execute_cdb_v2
 *
 * This handler sends the CDB to the currently targeted SCSI device.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   body       (input) - request message body.
 *
 * Returns:
 *   void
 */
void
ndmpd_scsi_execute_cdb_v2(ndmp_connection_t *connection, void *body)
{
	ndmp_execute_cdb_request *request = (ndmp_execute_cdb_request *) body;
	ndmp_execute_cdb_reply reply;
	ndmpd_session_t *session = ndmp_get_client_data(connection);

	if (session->ns_scsi.sd_is_open == -1 ||
	    !session->ns_scsi.sd_valid_target_set) {
		(void) memset((void *) &reply, 0, sizeof (reply));

		NDMP_LOG(LOG_ERR, "SCSI device is not open.");
		reply.error = NDMP_DEV_NOT_OPEN_ERR;
		ndmp_send_reply(connection, (void *) &reply,
		    "sending scsi_execute_cdb reply");
	} else {
		ndmp_execute_cdb(session, session->ns_scsi.sd_adapter_name,
		    session->ns_scsi.sd_sid, session->ns_scsi.sd_lun, request);
	}
}


/*
 * ************************************************************************
 * NDMP V3 HANDLERS
 * ************************************************************************
 */

/*
 * ndmpd_scsi_open_v3
 *
 * This handler opens the specified SCSI device.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   body       (input) - request message body.
 *
 * Returns:
 *   void
 */
void
ndmpd_scsi_open_v3(ndmp_connection_t *connection, void *body)
{
	ndmp_scsi_open_request_v3 *request = (ndmp_scsi_open_request_v3 *)body;

	common_open(connection, request->device);
}


/*
 * ndmpd_scsi_set_target_v3
 *
 * This handler sets the SCSI target of the SCSI device.
 * It is only valid to use this request if the opened SCSI device
 * is capable of talking to multiple SCSI targets.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   body       (input) - request message body.
 *
 * Returns:
 *   void
 */
void
ndmpd_scsi_set_target_v3(ndmp_connection_t *connection, void *body)
{
	ndmp_scsi_set_target_request_v3 *request;

	request = (ndmp_scsi_set_target_request_v3 *) body;

	common_set_target(connection, request->device,
	    request->target_controller, request->target_id,
	    request->target_lun);
}


/*
 * ************************************************************************
 * NDMP V4 HANDLERS
 * ************************************************************************
 */

/*
 * ************************************************************************
 * LOCALS
 * ************************************************************************
 */


/*
 * scsi_open_send_reply
 *
 * Send a reply for SCSI open command
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   err        (input) - ndmp error code
 *
 * Returns:
 *   void
 */
static void
scsi_open_send_reply(ndmp_connection_t *connection, int err)
{
	ndmp_scsi_open_reply reply;

	reply.error = err;
	ndmp_send_reply(connection, (void *) &reply, "sending scsi_open reply");
}


/*
 * common_open
 *
 * Common SCSI open function for all NDMP versions
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   devname (input) - device name to open.
 *
 * Returns:
 *   void
 */
static void
common_open(ndmp_connection_t *connection, char *devname)
{
	ndmpd_session_t *session = ndmp_get_client_data(connection);
	char adptnm[SCSI_MAX_NAME];
	int sid, lun;
	int err;
	scsi_adapter_t *sa;
	int devid;

	err = NDMP_NO_ERR;

	if (session->ns_tape.td_fd != -1 || session->ns_scsi.sd_is_open != -1) {
		NDMP_LOG(LOG_ERR,
		    "Session already has a tape or scsi device open.");
		err = NDMP_DEVICE_OPENED_ERR;
	} else if ((sa = scsi_get_adapter(0)) != NULL) {
		NDMP_LOG(LOG_DEBUG, "Adapter device found: %s", devname);
		(void) strlcpy(adptnm, devname, SCSI_MAX_NAME-2);
		adptnm[SCSI_MAX_NAME-1] = '\0';
		sid = lun = -1;

		scsi_find_sid_lun(sa, devname, &sid, &lun);
		if (ndmp_open_list_find(devname, sid, lun) == NULL &&
		    (devid = open(devname, O_RDWR | O_NDELAY)) < 0) {
			NDMP_LOG(LOG_ERR, "Failed to open device %s: %m.",
			    devname);
			err = NDMP_NO_DEVICE_ERR;
		}
	} else {
		NDMP_LOG(LOG_ERR, "%s: No such SCSI adapter.", devname);
		err = NDMP_NO_DEVICE_ERR;
	}

	if (err != NDMP_NO_ERR) {
		scsi_open_send_reply(connection, err);
		return;
	}

	switch (ndmp_open_list_add(connection, adptnm, sid, lun, devid)) {
	case 0:
		/* OK */
		break;
	case EBUSY:
		err = NDMP_DEVICE_BUSY_ERR;
		break;
	case ENOMEM:
		err = NDMP_NO_MEM_ERR;
		break;
	default:
		err = NDMP_IO_ERR;
	}
	if (err != NDMP_NO_ERR) {
		scsi_open_send_reply(connection, err);
		return;
	}

	(void) strlcpy(session->ns_scsi.sd_adapter_name, adptnm, SCSI_MAX_NAME);
	session->ns_scsi.sd_is_open = 1;
	session->ns_scsi.sd_devid = devid;
	if (sid != -1) {
		session->ns_scsi.sd_sid = sid;
		session->ns_scsi.sd_lun = lun;
		session->ns_scsi.sd_valid_target_set = TRUE;
	} else {
		session->ns_scsi.sd_sid = session->ns_scsi.sd_lun = -1;
		session->ns_scsi.sd_valid_target_set = FALSE;
	}

	scsi_open_send_reply(connection, err);
}


/*
 * common_set_target
 *
 * Set the SCSI target (SCSI number, LUN number, controller number)
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   device (input) - device name.
 *   controller (input) - controller number.
 *   sid (input) - SCSI target ID.
 *   lun (input) - LUN number.
 *
 * Returns:
 *   0: on success
 *  -1: otherwise
 */
/*ARGSUSED*/
static void
common_set_target(ndmp_connection_t *connection, char *device,
    ushort_t controller, ushort_t sid, ushort_t lun)
{
	ndmp_scsi_set_target_reply reply;
	ndmpd_session_t *session = ndmp_get_client_data(connection);
	int type;

	reply.error = NDMP_NO_ERR;

	if (session->ns_scsi.sd_is_open == -1) {
		reply.error = NDMP_DEV_NOT_OPEN_ERR;
	} else if (!scsi_dev_exists(session->ns_scsi.sd_adapter_name, sid,
	    lun)) {
		NDMP_LOG(LOG_ERR, "No such SCSI device: target %d lun %d.",
		    sid, lun);
		reply.error = NDMP_NO_DEVICE_ERR;
	} else {
		type = scsi_get_devtype(session->ns_scsi.sd_adapter_name, sid,
		    lun);
		if (type != DTYPE_SEQUENTIAL && type != DTYPE_CHANGER) {
			NDMP_LOG(LOG_ERR,
			    "Not a tape or robot device: target %d lun %d.",
			    sid, lun);
			reply.error = NDMP_ILLEGAL_ARGS_ERR;
		}
	}

	if (reply.error != NDMP_NO_ERR) {
		ndmp_send_reply(connection, (void *) &reply,
		    "sending scsi_set_target reply");
		return;
	}

	/*
	 * The open_list must be updated if the SID or LUN are going to be
	 * changed.  Close uses the same SID & LUN for removing the entry
	 * from the open_list.
	 */
	if (sid != session->ns_scsi.sd_sid || lun != session->ns_scsi.sd_lun) {
		switch (ndmp_open_list_add(connection,
		    session->ns_scsi.sd_adapter_name, sid, lun, 0)) {
		case 0:
			(void) ndmp_open_list_del(session->
			    ns_scsi.sd_adapter_name, session->ns_scsi.sd_sid,
			    session->ns_scsi.sd_lun);
			break;
		case EBUSY:
			reply.error = NDMP_DEVICE_BUSY_ERR;
			break;
		case ENOMEM:
			reply.error = NDMP_NO_MEM_ERR;
			break;
		default:
			reply.error = NDMP_IO_ERR;
		}
	}

	if (reply.error == NDMP_NO_ERR) {
		NDMP_LOG(LOG_DEBUG, "Updated sid %d lun %d", sid, lun);
		session->ns_scsi.sd_sid = sid;
		session->ns_scsi.sd_lun = lun;
		session->ns_scsi.sd_valid_target_set = TRUE;
	}

	ndmp_send_reply(connection, (void *) &reply,
	    "sending scsi_set_target reply");
}

/*
 * scsi_find_sid_lun
 *
 * gets the adapter, and returns the sid and lun number
 */
void
scsi_find_sid_lun(scsi_adapter_t *sa, char *devname, int *sid, int *lun)
{
	scsi_link_t *sl;
	char *name;

	for (sl = sa->sa_link_head.sl_next; sl && sl != &sa->sa_link_head;
	    sl = sl->sl_next) {
		name = sasd_slink_name(sl);
		if (strcmp(devname, name) == 0) {
			*sid = sl->sl_sid;
			*lun = sl->sl_lun;
			return;
		}
	}

	*sid = -1;
	*lun = -1;
}
