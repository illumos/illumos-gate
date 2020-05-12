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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Domain Services Module Common Code.
 *
 * This module is intended to be used by both Solaris and the VBSC
 * module.
 */

#include <sys/modctl.h>
#include <sys/ksynch.h>
#include <sys/taskq.h>
#include <sys/disp.h>
#include <sys/cmn_err.h>
#include <sys/note.h>
#include <sys/mach_descrip.h>
#include <sys/mdesc.h>
#include <sys/ldc.h>
#include <sys/ds.h>
#include <sys/ds_impl.h>

#ifndef MIN
#define	MIN(a, b)	((a) < (b) ? (a) : (b))
#endif

#define	DS_DECODE_BUF_LEN		30

/*
 * All DS ports in the system
 *
 * The list of DS ports is read in from the MD when the DS module is
 * initialized and is never modified. This eliminates the need for
 * locking to access the port array itself. Access to the individual
 * ports are synchronized at the port level.
 */
ds_port_t	ds_ports[DS_MAX_PORTS];
ds_portset_t	ds_allports;	/* all DS ports in the system */
ds_portset_t	ds_nullport;	/* allows test against null portset */

/* DS SP port id */
uint64_t ds_sp_port_id = DS_PORTID_INVALID;

/*
 * Table of registered services
 *
 * Locking: Accesses to the table of services are synchronized using
 *   a mutex lock. The reader lock must be held when looking up service
 *   information in the table. The writer lock must be held when any
 *   service information is being modified.
 */
ds_svcs_t	ds_svcs;

/*
 * Flag to prevent callbacks while in the middle of DS teardown.
 */
boolean_t ds_enabled = B_FALSE;	/* enable/disable taskq processing */

/*
 * Retry count and delay for LDC reads and writes
 */
#ifndef DS_DEFAULT_RETRIES
#define	DS_DEFAULT_RETRIES	10000	/* number of times to retry */
#endif
#ifndef DS_DEFAULT_DELAY
#define	DS_DEFAULT_DELAY	1000	/* usecs to wait between retries */
#endif

static int ds_retries = DS_DEFAULT_RETRIES;
static clock_t ds_delay = DS_DEFAULT_DELAY;

/*
 * Supported versions of the DS message protocol
 *
 * The version array must be sorted in order from the highest
 * supported version to the lowest. Support for a particular
 * <major>.<minor> version implies all lower minor versions of
 * that same major version are supported as well.
 */
static ds_ver_t ds_vers[] = { { 1, 0 } };

#define	DS_NUM_VER	(sizeof (ds_vers) / sizeof (ds_vers[0]))


/* incoming message handling functions */
typedef void (*ds_msg_handler_t)(ds_port_t *port, caddr_t buf, size_t len);
static void ds_handle_init_req(ds_port_t *port, caddr_t buf, size_t len);
static void ds_handle_init_ack(ds_port_t *port, caddr_t buf, size_t len);
static void ds_handle_init_nack(ds_port_t *port, caddr_t buf, size_t len);
static void ds_handle_reg_req(ds_port_t *port, caddr_t buf, size_t len);
static void ds_handle_reg_ack(ds_port_t *port, caddr_t buf, size_t len);
static void ds_handle_reg_nack(ds_port_t *port, caddr_t buf, size_t len);
static void ds_handle_unreg_req(ds_port_t *port, caddr_t buf, size_t len);
static void ds_handle_unreg_ack(ds_port_t *port, caddr_t buf, size_t len);
static void ds_handle_unreg_nack(ds_port_t *port, caddr_t buf, size_t len);
static void ds_handle_data(ds_port_t *port, caddr_t buf, size_t len);
static void ds_handle_nack(ds_port_t *port, caddr_t buf, size_t len);

/*
 * DS Message Handler Dispatch Table
 *
 * A table used to dispatch all incoming messages. This table
 * contains handlers for all the fixed message types, as well as
 * the the messages defined in the 1.0 version of the DS protocol.
 * The handlers are indexed based on the DS header msg_type values
 */
static const ds_msg_handler_t ds_msg_handlers[] = {
	ds_handle_init_req,		/* DS_INIT_REQ */
	ds_handle_init_ack,		/* DS_INIT_ACK */
	ds_handle_init_nack,		/* DS_INIT_NACK */
	ds_handle_reg_req,		/* DS_REG_REQ */
	ds_handle_reg_ack,		/* DS_REG_ACK */
	ds_handle_reg_nack,		/* DS_REG_NACK */
	ds_handle_unreg_req,		/* DS_UNREG */
	ds_handle_unreg_ack,		/* DS_UNREG_ACK */
	ds_handle_unreg_nack,		/* DS_UNREG_NACK */
	ds_handle_data,			/* DS_DATA */
	ds_handle_nack			/* DS_NACK */
};



/* initialization functions */
static int ds_ldc_init(ds_port_t *port);

/* event processing functions */
static uint_t ds_ldc_cb(uint64_t event, caddr_t arg);
static int ds_recv_msg(ds_port_t *port, caddr_t msgp, size_t *sizep);
static void ds_handle_up_event(ds_port_t *port);
static void ds_handle_down_reset_events(ds_port_t *port);
static void ds_handle_recv(void *arg);
static void ds_dispatch_event(void *arg);

/* message sending functions */
static int ds_send_msg(ds_port_t *port, caddr_t msg, size_t msglen);
static int ds_send_reg_req(ds_svc_t *svc, ds_port_t *port);
static void ds_send_unreg_nack(ds_port_t *port, ds_svc_hdl_t bad_hdl);
static void ds_send_data_nack(ds_port_t *port, ds_svc_hdl_t bad_hdl);

/* walker functions */
static int ds_svc_isfree(ds_svc_t *svc, void *arg);
static int ds_svc_unregister(ds_svc_t *svc, void *arg);
static int ds_svc_port_up(ds_svc_t *svc, void *arg);

/* service utilities */
static void ds_reset_svc(ds_svc_t *svc, ds_port_t *port);
static int ds_svc_register_onport(ds_svc_t *svc, ds_port_t *port);
static int ds_svc_register_onport_walker(ds_svc_t *svc, void *arg);
static void ds_set_port_ready(ds_port_t *port, uint16_t major, uint16_t minor);

/* port utilities */
static void ds_port_reset(ds_port_t *port);
static ldc_status_t ds_update_ldc_state(ds_port_t *port);

/* misc utilities */
static void min_max_versions(int num_versions, ds_ver_t *sup_versionsp,
    uint16_t *min_major, uint16_t *max_major);

/* debug */
static char *decode_ldc_events(uint64_t event, char *buf);

/* loopback */
static void ds_loopback_register(ds_svc_hdl_t hdl);
static void ds_loopback_unregister(ds_svc_hdl_t hdl);
static void ds_loopback_send(ds_svc_hdl_t hdl, void *buf, size_t buflen);
static int ds_loopback_set_svc(ds_svc_t *svc, ds_capability_t *cap,
    ds_svc_hdl_t *lb_hdlp);

/* client handling */
static int i_ds_hdl_lookup(char *service, uint_t is_client, ds_svc_hdl_t *hdlp,
    uint_t maxhdls);
static ds_svc_t *ds_find_clnt_svc_by_hdl_port(ds_svc_hdl_t hdl,
    ds_port_t *port);
static ds_svc_t *ds_find_svc_by_id_port(char *svc_id, int is_client,
    ds_port_t *port);
static ds_svc_t *ds_svc_clone(ds_svc_t *svc);
static void ds_check_for_dup_services(ds_svc_t *svc);
static void ds_delete_svc_entry(ds_svc_t *svc);

char *
ds_strdup(char *str)
{
	char *newstr;

	newstr = DS_MALLOC(strlen(str) + 1);
	(void) strcpy(newstr, str);
	return (newstr);
}

void
ds_common_init(void)
{
	/* Validate version table */
	ASSERT(ds_vers_isvalid(ds_vers, DS_NUM_VER) == DS_VERS_OK);

	/* Initialize services table */
	ds_init_svcs_tbl(DS_MAXSVCS_INIT);

	/* enable callback processing */
	ds_enabled = B_TRUE;
}

/* BEGIN LDC SUPPORT FUNCTIONS */

static char *
decode_ldc_events(uint64_t event, char *buf)
{
	buf[0] = 0;
	if (event & LDC_EVT_DOWN)	(void) strcat(buf, " DOWN");
	if (event & LDC_EVT_RESET)	(void) strcat(buf, " RESET");
	if (event & LDC_EVT_UP)		(void) strcat(buf, " UP");
	if (event & LDC_EVT_READ)	(void) strcat(buf, " READ");
	if (event & LDC_EVT_WRITE)	(void) strcat(buf, " WRITE");
	return (buf);
}

static ldc_status_t
ds_update_ldc_state(ds_port_t *port)
{
	ldc_status_t	ldc_state;
	int		rv;
	char		ebuf[DS_EBUFSIZE];

	ASSERT(MUTEX_HELD(&port->lock));

	/*
	 * Read status and update ldc state info in port structure.
	 */
	if ((rv = ldc_status(port->ldc.hdl, &ldc_state)) != 0) {
		cmn_err(CE_WARN, "ds@%lx: %s: ldc_status error: %s" DS_EOL,
		    PORTID(port), __func__, ds_errno_to_str(rv, ebuf));
		ldc_state = port->ldc.state;
	} else {
		port->ldc.state = ldc_state;
	}

	return (ldc_state);
}

static void
ds_handle_down_reset_events(ds_port_t *port)
{
	DS_DBG_LDC(CE_NOTE, "ds@%lx: %s: entered" DS_EOL, PORTID(port),
	    __func__);

	mutex_enter(&ds_svcs.lock);
	mutex_enter(&port->lock);

	ds_sys_drain_events(port);

	(void) ds_update_ldc_state(port);

	/* reset the port state */
	ds_port_reset(port);

	/* acknowledge the reset */
	(void) ldc_up(port->ldc.hdl);

	mutex_exit(&port->lock);
	mutex_exit(&ds_svcs.lock);

	ds_handle_up_event(port);

	DS_DBG_LDC(CE_NOTE, "ds@%lx: %s: exit" DS_EOL, PORTID(port), __func__);
}

static void
ds_handle_up_event(ds_port_t *port)
{
	ldc_status_t	ldc_state;

	DS_DBG_LDC(CE_NOTE, "ds@%lx: %s: entered" DS_EOL, PORTID(port),
	    __func__);

	mutex_enter(&port->lock);

	ldc_state = ds_update_ldc_state(port);

	mutex_exit(&port->lock);

	if ((ldc_state == LDC_UP) && IS_DS_PORT(port)) {
		/*
		 * Initiate the handshake.
		 */
		ds_send_init_req(port);
	}

	DS_DBG_LDC(CE_NOTE, "ds@%lx: %s: exit" DS_EOL, PORTID(port), __func__);
}

static uint_t
ds_ldc_cb(uint64_t event, caddr_t arg)
{
	ds_port_t	*port = (ds_port_t *)arg;
	char		evstring[DS_DECODE_BUF_LEN];

	DS_DBG_LDC(CE_NOTE, "ds@%lx: %s: %s event (%llx) received" DS_EOL,
	    PORTID(port), __func__, decode_ldc_events(event, evstring),
	    (u_longlong_t)event);

	if (!ds_enabled) {
		DS_DBG_LDC(CE_NOTE, "ds@%lx: %s: callback handling is disabled"
		    DS_EOL, PORTID(port), __func__);
		return (LDC_SUCCESS);
	}

	if (event & (LDC_EVT_DOWN | LDC_EVT_RESET)) {
		ds_handle_down_reset_events(port);
		goto done;
	}

	if (event & LDC_EVT_UP) {
		ds_handle_up_event(port);
	}

	if (event & LDC_EVT_READ) {
		if (port->ldc.state != LDC_UP) {
			cmn_err(CE_WARN, "ds@%lx: %s: LDC READ event while "
			    "port not up" DS_EOL, PORTID(port), __func__);
			goto done;
		}

		if (ds_sys_dispatch_func(ds_handle_recv, port)) {
			cmn_err(CE_WARN, "ds@%lx: error initiating LDC READ "
			    " event", PORTID(port));
		}
	}

	if (event & LDC_EVT_WRITE) {
		DS_DBG_LDC(CE_NOTE, "ds@%lx: %s: LDC WRITE event received, "
		    "not supported" DS_EOL, PORTID(port), __func__);
	}

	if (event & ~(LDC_EVT_UP | LDC_EVT_READ)) {
		cmn_err(CE_WARN, "ds@%lx: %s: Unexpected LDC event received: "
		    "0x%llx" DS_EOL, PORTID(port), __func__,
		    (u_longlong_t)event);
	}
done:
	DS_DBG_LDC(CE_NOTE, "ds@%lx: %s: exit" DS_EOL, PORTID(port), __func__);

	return (LDC_SUCCESS);
}

static int
ds_ldc_init(ds_port_t *port)
{
	int		rv;
	ldc_attr_t	ldc_attr;
	caddr_t		ldc_cb_arg = (caddr_t)port;
	char		ebuf[DS_EBUFSIZE];

	ASSERT(MUTEX_HELD(&port->lock));

	DS_DBG_LDC(CE_NOTE, "ds@%lx: %s: ldc_id=%lld" DS_EOL,
	    PORTID(port), __func__, (u_longlong_t)port->ldc.id);

	ldc_attr.devclass = LDC_DEV_GENERIC;
	ldc_attr.instance = 0;
	ldc_attr.mode = LDC_MODE_RELIABLE;
	ldc_attr.mtu = DS_STREAM_MTU;

	if ((rv = ldc_init(port->ldc.id, &ldc_attr, &port->ldc.hdl)) != 0) {
		cmn_err(CE_WARN, "ds@%lx: %s: ldc_id: %lx, ldc_init error: %s"
		    DS_EOL, PORTID(port), __func__, port->ldc.id,
		    ds_errno_to_str(rv, ebuf));
		return (rv);
	}

	rv = ldc_reg_callback(port->ldc.hdl, ds_ldc_cb, ldc_cb_arg);
	if (rv != 0) {
		cmn_err(CE_WARN, "ds@%lx: %s: ldc_reg_callback error: %s"
		    DS_EOL, PORTID(port), __func__, ds_errno_to_str(rv, ebuf));
		return (rv);
	}

	ds_sys_ldc_init(port);
	return (0);
}

int
ds_ldc_fini(ds_port_t *port)
{
	int	rv;
	char	ebuf[DS_EBUFSIZE];

	ASSERT(port->state >= DS_PORT_LDC_INIT);
	ASSERT(MUTEX_HELD(&port->lock));

	DS_DBG_LDC(CE_NOTE, "ds@%lx: %s: ldc_id=%ld" DS_EOL, PORTID(port),
	    __func__, port->ldc.id);

	if ((rv = ldc_close(port->ldc.hdl)) != 0) {
		cmn_err(CE_WARN, "ds@%lx: %s: ldc_close error: %s" DS_EOL,
		    PORTID(port), __func__, ds_errno_to_str(rv, ebuf));
		return (rv);
	}

	if ((rv = ldc_unreg_callback(port->ldc.hdl)) != 0) {
		cmn_err(CE_WARN, "ds@%lx: %s: ldc_unreg_callback error: %s"
		    DS_EOL, PORTID(port), __func__, ds_errno_to_str(rv, ebuf));
		return (rv);
	}

	if ((rv = ldc_fini(port->ldc.hdl)) != 0) {
		cmn_err(CE_WARN, "ds@%lx: %s: ldc_fini error: %s" DS_EOL,
		    PORTID(port), __func__, ds_errno_to_str(rv, ebuf));
		return (rv);
	}

	port->ldc.id = (uint64_t)-1;
	port->ldc.hdl = 0;
	port->ldc.state = 0;

	return (rv);
}

/*
 * Attempt to read a specified number of bytes from a particular LDC.
 * Returns zero for success or the return code from the LDC read on
 * failure. The actual number of bytes read from the LDC is returned
 * in the size parameter.
 */
static int
ds_recv_msg(ds_port_t *port, caddr_t msgp, size_t *sizep)
{
	int	rv = 0;
	size_t	bytes_req = *sizep;
	size_t	bytes_left = bytes_req;
	size_t	nbytes;
	int	retry_count = 0;
	char	ebuf[DS_EBUFSIZE];

	ASSERT(MUTEX_HELD(&port->rcv_lock));

	*sizep = 0;

	DS_DBG_LDC(CE_NOTE, "ds@%lx: attempting to read %ld bytes" DS_EOL,
	    PORTID(port), bytes_req);

	while (bytes_left > 0) {

		nbytes = bytes_left;

		mutex_enter(&port->lock);
		if (port->ldc.state == LDC_UP) {
			rv = ldc_read(port->ldc.hdl, msgp, &nbytes);
		} else
			rv = ENXIO;
		mutex_exit(&port->lock);
		if (rv != 0) {
			if (rv == ECONNRESET) {
				break;
			} else if (rv != EAGAIN) {
				cmn_err(CE_NOTE, "ds@%lx: %s: %s" DS_EOL,
				    PORTID(port), __func__,
				    ds_errno_to_str(rv, ebuf));
				break;
			}
		} else {
			if (nbytes != 0) {
				DS_DBG_LDC(CE_NOTE, "ds@%lx: "
				    "read %ld bytes, %d retries" DS_EOL,
				    PORTID(port), nbytes, retry_count);

				*sizep += nbytes;
				msgp += nbytes;
				bytes_left -= nbytes;

				/* reset counter on a successful read */
				retry_count = 0;
				continue;
			}

			/*
			 * No data was read. Check if this is the
			 * first attempt. If so, just return since
			 * nothing has been read yet.
			 */
			if (bytes_left == bytes_req) {
				DS_DBG_LDC(CE_NOTE, "ds@%lx: read zero bytes, "
				    " no data available" DS_EOL, PORTID(port));
				break;
			}
		}

		/*
		 * A retry is necessary because the read returned
		 * EAGAIN, or a zero length read occurred after
		 * reading a partial message.
		 */
		if (retry_count++ >= ds_retries) {
			DS_DBG_LDC(CE_NOTE, "ds@%lx: timed out waiting for "
			    "message" DS_EOL, PORTID(port));
			break;
		}

		drv_usecwait(ds_delay);
	}

	return (rv);
}

static void
ds_handle_recv(void *arg)
{
	ds_port_t	*port = (ds_port_t *)arg;
	char		*hbuf;
	size_t		msglen;
	size_t		read_size;
	boolean_t	hasdata;
	ds_hdr_t	hdr;
	uint8_t		*msg;
	char		*currp;
	int		rv;
	ds_event_t	*devent;

	DS_DBG_LDC(CE_NOTE, "ds@%lx: %s..." DS_EOL, PORTID(port), __func__);

	/*
	 * Read messages from the channel until there are none
	 * pending. Valid messages are dispatched to be handled
	 * by a separate thread while any malformed messages are
	 * dropped.
	 */

	mutex_enter(&port->rcv_lock);

	for (;;) {
		mutex_enter(&port->lock);
		if (port->ldc.state == LDC_UP) {
			rv = ldc_chkq(port->ldc.hdl, &hasdata);
		} else
			rv = ENXIO;
		mutex_exit(&port->lock);
		if (rv != 0 || !hasdata)
			break;

		DS_DBG(CE_NOTE, "ds@%lx: %s: reading next message" DS_EOL,
		    PORTID(port), __func__);

		/*
		 * Read in the next message.
		 */
		hbuf = (char *)&hdr;
		bzero(hbuf, DS_HDR_SZ);
		read_size = DS_HDR_SZ;
		currp = hbuf;

		/* read in the message header */
		if ((rv = ds_recv_msg(port, currp, &read_size)) != 0) {
			break;
		}

		if (read_size < DS_HDR_SZ) {
			/*
			 * A zero length read is a valid signal that
			 * there is no data left on the channel.
			 */
			if (read_size != 0) {
				cmn_err(CE_WARN, "ds@%lx: invalid message "
				    "length, received %ld bytes, expected %ld"
				    DS_EOL, PORTID(port), read_size, DS_HDR_SZ);
			}
			continue;
		}

		/* get payload size and allocate a buffer */
		read_size = ((ds_hdr_t *)hbuf)->payload_len;
		msglen = DS_HDR_SZ + read_size;
		msg = DS_MALLOC(msglen);
		if (!msg) {
			cmn_err(CE_WARN, "Memory allocation failed attempting "
			    " to allocate %d bytes." DS_EOL, (int)msglen);
			continue;
		}

		DS_DBG(CE_NOTE, "ds@%lx: %s: message payload len %d" DS_EOL,
		    PORTID(port), __func__, (int)read_size);

		/* move message header into buffer */
		(void) memcpy(msg, hbuf, DS_HDR_SZ);
		currp = (char *)(msg) + DS_HDR_SZ;

		/* read in the message body */
		if ((rv = ds_recv_msg(port, currp, &read_size)) != 0) {
			DS_FREE(msg, msglen);
			break;
		}

		/* validate the size of the message */
		if ((DS_HDR_SZ + read_size) != msglen) {
			cmn_err(CE_WARN, "ds@%lx: %s: invalid message length, "
			    "received %ld bytes, expected %ld" DS_EOL,
			    PORTID(port), __func__, (DS_HDR_SZ + read_size),
			    msglen);
			DS_FREE(msg, msglen);
			continue;
		}

		DS_DUMP_MSG(DS_DBG_FLAG_LDC, msg, msglen);

		/*
		 * Send the message for processing, and store it
		 * in the log. The memory is deallocated only when
		 * the message is removed from the log.
		 */

		devent = DS_MALLOC(sizeof (ds_event_t));
		devent->port = port;
		devent->buf = (char *)msg;
		devent->buflen = msglen;

		/* log the message */
		(void) ds_log_add_msg(DS_LOG_IN(port->id), msg, msglen);

		if (ds_sys_dispatch_func(ds_dispatch_event, devent)) {
			cmn_err(CE_WARN, "ds@%lx: error initiating "
			    "event handler", PORTID(port));
			DS_FREE(devent, sizeof (ds_event_t));
		}
	}

	mutex_exit(&port->rcv_lock);

	/* handle connection reset errors returned from ds_recv_msg */
	if (rv == ECONNRESET) {
		ds_handle_down_reset_events(port);
	}

	DS_DBG_LDC(CE_NOTE, "ds@%lx: %s done" DS_EOL, PORTID(port), __func__);
}

static void
ds_dispatch_event(void *arg)
{
	ds_event_t	*event = (ds_event_t *)arg;
	ds_hdr_t	*hdr;
	ds_port_t	*port;

	port = event->port;

	hdr = (ds_hdr_t *)event->buf;

	if (DS_MSG_TYPE_VALID(hdr->msg_type)) {
		DS_DBG(CE_NOTE, "ds@%lx: dispatch_event: msg_type=%d" DS_EOL,
		    PORTID(port), hdr->msg_type);

		(*ds_msg_handlers[hdr->msg_type])(port, event->buf,
		    event->buflen);
	} else {
		cmn_err(CE_WARN, "ds@%lx: dispatch_event: invalid msg "
		    "type (%d)" DS_EOL, PORTID(port), hdr->msg_type);
	}

	DS_FREE(event->buf, event->buflen);
	DS_FREE(event, sizeof (ds_event_t));
}

int
ds_send_msg(ds_port_t *port, caddr_t msg, size_t msglen)
{
	int	rv;
	caddr_t	currp = msg;
	size_t	amt_left = msglen;
	int	loopcnt = 0;

	DS_DBG_LDC(CE_NOTE, "ds@%lx: %s msglen: %ld" DS_EOL, PORTID(port),
	    __func__, msglen);
	DS_DUMP_MSG(DS_DBG_FLAG_LDC, msg, msglen);

	(void) ds_log_add_msg(DS_LOG_OUT(port->id), (uint8_t *)msg, msglen);

	/*
	 * Ensure that no other messages can be sent on this port by holding
	 * the tx_lock mutex in case the write doesn't get sent with one write.
	 * This guarantees that the message doesn't become fragmented.
	 */
	mutex_enter(&port->tx_lock);

	do {
		mutex_enter(&port->lock);
		if (port->ldc.state == LDC_UP) {
			rv = ldc_write(port->ldc.hdl, currp, &msglen);
		} else
			rv = ENXIO;
		mutex_exit(&port->lock);
		if (rv != 0) {
			if (rv == ECONNRESET) {
				mutex_exit(&port->tx_lock);
				(void) ds_sys_dispatch_func((void (*)(void *))
				    ds_handle_down_reset_events, port);
				return (rv);
			} else if ((rv == EWOULDBLOCK) &&
			    (loopcnt++ < ds_retries)) {
				drv_usecwait(ds_delay);
			} else {
				DS_DBG_PRCL(CE_NOTE, "ds@%lx: send_msg: "
				    "ldc_write failed (%d), %d bytes "
				    "remaining" DS_EOL, PORTID(port), rv,
				    (int)amt_left);
				goto error;
			}
		} else {
			amt_left -= msglen;
			currp += msglen;
			msglen = amt_left;
			loopcnt = 0;
		}
	} while (amt_left > 0);
error:
	mutex_exit(&port->tx_lock);

	return (rv);
}

/* END LDC SUPPORT FUNCTIONS */


/* BEGIN DS PROTOCOL SUPPORT FUNCTIONS */

static void
ds_handle_init_req(ds_port_t *port, caddr_t buf, size_t len)
{
	ds_hdr_t	*hdr;
	ds_init_ack_t	*ack;
	ds_init_nack_t	*nack;
	char		*msg;
	size_t		msglen;
	ds_init_req_t	*req;
	size_t		explen = DS_MSG_LEN(ds_init_req_t);
	uint16_t	new_major;
	uint16_t	new_minor;
	boolean_t	match;

	/* sanity check the incoming message */
	if (len != explen) {
		cmn_err(CE_WARN, "ds@%lx: <init_req: invalid message "
		    "length (%ld), expected %ld" DS_EOL, PORTID(port), len,
		    explen);
		return;
	}

	req = (ds_init_req_t *)(buf + DS_HDR_SZ);

	DS_DBG_PRCL(CE_NOTE, "ds@%lx: <init_req: ver=%d.%d" DS_EOL,
	    PORTID(port), req->major_vers, req->minor_vers);

	match = negotiate_version(DS_NUM_VER, &ds_vers[0],
	    req->major_vers, &new_major, &new_minor);

	/*
	 * Check version info. ACK only if the major numbers exactly
	 * match. The service entity can retry with a new minor
	 * based on the response sent as part of the NACK.
	 */
	if (match) {
		msglen = DS_MSG_LEN(ds_init_ack_t);
		msg = DS_MALLOC(msglen);

		hdr = (ds_hdr_t *)msg;
		hdr->msg_type = DS_INIT_ACK;
		hdr->payload_len = sizeof (ds_init_ack_t);

		ack = (ds_init_ack_t *)(msg + DS_HDR_SZ);
		ack->minor_vers = MIN(new_minor, req->minor_vers);

		DS_DBG_PRCL(CE_NOTE, "ds@%lx: init_ack>: minor=0x%04X" DS_EOL,
		    PORTID(port), MIN(new_minor, req->minor_vers));
	} else {
		msglen = DS_MSG_LEN(ds_init_nack_t);
		msg = DS_MALLOC(msglen);

		hdr = (ds_hdr_t *)msg;
		hdr->msg_type = DS_INIT_NACK;
		hdr->payload_len = sizeof (ds_init_nack_t);

		nack = (ds_init_nack_t *)(msg + DS_HDR_SZ);
		nack->major_vers = new_major;

		DS_DBG_PRCL(CE_NOTE, "ds@%lx: init_nack>: major=0x%04X" DS_EOL,
		    PORTID(port), new_major);
	}

	/*
	 * Send the response
	 */
	(void) ds_send_msg(port, msg, msglen);
	DS_FREE(msg, msglen);

	if (match) {
		ds_set_port_ready(port, req->major_vers, ack->minor_vers);
	}
}

static void
ds_handle_init_ack(ds_port_t *port, caddr_t buf, size_t len)
{
	ds_init_ack_t	*ack;
	ds_ver_t	*ver;
	uint16_t	major;
	uint16_t	minor;
	size_t		explen = DS_MSG_LEN(ds_init_ack_t);

	/* sanity check the incoming message */
	if (len != explen) {
		cmn_err(CE_WARN, "ds@%lx: <init_ack: invalid message "
		    "length (%ld), expected %ld" DS_EOL, PORTID(port), len,
		    explen);
		return;
	}

	ack = (ds_init_ack_t *)(buf + DS_HDR_SZ);

	mutex_enter(&port->lock);

	if (port->state == DS_PORT_READY) {
		DS_DBG_PRCL(CE_NOTE, "ds@%lx: <init_ack: port ready" DS_EOL,
		    PORTID(port));
		mutex_exit(&port->lock);
		return;
	}

	if (port->state != DS_PORT_INIT_REQ) {
		DS_DBG_PRCL(CE_NOTE, "ds@%lx: <init_ack: invalid state: %d"
		    DS_EOL, PORTID(port), port->state);
		mutex_exit(&port->lock);
		return;
	}

	ver = &(ds_vers[port->ver_idx]);
	major = ver->major;
	minor = MIN(ver->minor, ack->minor_vers);
	mutex_exit(&port->lock);

	DS_DBG_PRCL(CE_NOTE, "ds@%lx: <init_ack: port ready v%d.%d" DS_EOL,
	    PORTID(port), major, minor);

	ds_set_port_ready(port, major, minor);
}

static void
ds_handle_init_nack(ds_port_t *port, caddr_t buf, size_t len)
{
	int		idx;
	ds_init_nack_t	*nack;
	ds_ver_t	*ver;
	size_t		explen = DS_MSG_LEN(ds_init_nack_t);

	/* sanity check the incoming message */
	if (len != explen) {
		DS_DBG_PRCL(CE_WARN, "ds@%lx: <init_nack: invalid message "
		    "length (%ld), expected %ld" DS_EOL, PORTID(port), len,
		    explen);
		return;
	}

	nack = (ds_init_nack_t *)(buf + DS_HDR_SZ);

	mutex_enter(&port->lock);

	if (port->state != DS_PORT_INIT_REQ) {
		DS_DBG_PRCL(CE_NOTE, "ds@%lx: <init_nack: invalid state: %d"
		    DS_EOL, PORTID(port), port->state);
		mutex_exit(&port->lock);
		return;
	}

	ver = &(ds_vers[port->ver_idx]);

	DS_DBG_PRCL(CE_NOTE, "ds@%lx: <init_nack: req=v%d.%d, nack=v%d.x"
	    DS_EOL, PORTID(port), ver->major, ver->minor, nack->major_vers);

	if (nack->major_vers == 0) {
		/* no supported protocol version */
		DS_DBG_PRCL(CE_WARN, "ds@%lx: <init_nack: DS not supported"
		    DS_EOL, PORTID(port));
		mutex_exit(&port->lock);
		return;
	}

	/*
	 * Walk the version list, looking for a major version
	 * that is as close to the requested major version as
	 * possible.
	 */
	for (idx = port->ver_idx; idx < DS_NUM_VER; idx++) {
		if (ds_vers[idx].major <= nack->major_vers) {
			/* found a version to try */
			goto done;
		}
	}

	if (idx == DS_NUM_VER) {
		/* no supported version */
		DS_DBG_PRCL(CE_WARN, "ds@%lx: <init_nack: DS v%d.x not "
		    "supported" DS_EOL, PORTID(port), nack->major_vers);

		mutex_exit(&port->lock);
		return;
	}

done:
	/* start the handshake again */
	port->ver_idx = idx;
	port->state = DS_PORT_LDC_INIT;
	mutex_exit(&port->lock);

	ds_send_init_req(port);

}

static ds_svc_t *
ds_find_svc_by_id_port(char *svc_id, int is_client, ds_port_t *port)
{
	int		idx;
	ds_svc_t	*svc, *found_svc = 0;
	uint32_t	flag_match = is_client ? DSSF_ISCLIENT : 0;

	ASSERT(MUTEX_HELD(&ds_svcs.lock));

	/* walk every table entry */
	for (idx = 0; idx < ds_svcs.maxsvcs; idx++) {
		svc = ds_svcs.tbl[idx];
		if (DS_SVC_ISFREE(svc))
			continue;
		if (strcmp(svc->cap.svc_id, svc_id) != 0)
			continue;
		if ((svc->flags & DSSF_ISCLIENT) != flag_match)
			continue;
		if (port != NULL && svc->port == port) {
			return (svc);
		} else if (svc->state == DS_SVC_INACTIVE) {
			found_svc = svc;
		} else if (!found_svc) {
			found_svc = svc;
		}
	}

	return (found_svc);
}

static void
ds_handle_reg_req(ds_port_t *port, caddr_t buf, size_t len)
{
	ds_reg_req_t	*req;
	ds_hdr_t	*hdr;
	ds_reg_ack_t	*ack;
	ds_reg_nack_t	*nack;
	char		*msg;
	size_t		msglen;
	size_t		explen = DS_MSG_LEN(ds_reg_req_t);
	ds_svc_t	*svc = NULL;
	ds_ver_t	version;
	uint16_t	new_major;
	uint16_t	new_minor;
	boolean_t	match;

	/* sanity check the incoming message */
	if (len < explen) {
		cmn_err(CE_WARN, "ds@%lx: <reg_req: invalid message "
		    "length (%ld), expected at least %ld" DS_EOL,
		    PORTID(port), len, explen);
		return;
	}

	req = (ds_reg_req_t *)(buf + DS_HDR_SZ);

	DS_DBG_PRCL(CE_NOTE, "ds@%lx: <reg_req: '%s' ver=%d.%d, hdl=0x%llx"
	    DS_EOL, PORTID(port), req->svc_id, req->major_vers, req->minor_vers,
	    (u_longlong_t)req->svc_handle);

	mutex_enter(&ds_svcs.lock);
	svc = ds_find_svc_by_id_port(req->svc_id,
	    DS_HDL_ISCLIENT(req->svc_handle) == 0, port);
	if (svc == NULL) {

do_reg_nack:
		mutex_exit(&ds_svcs.lock);

		msglen = DS_MSG_LEN(ds_reg_nack_t);
		msg = DS_MALLOC(msglen);

		hdr = (ds_hdr_t *)msg;
		hdr->msg_type = DS_REG_NACK;
		hdr->payload_len = sizeof (ds_reg_nack_t);

		nack = (ds_reg_nack_t *)(msg + DS_HDR_SZ);
		nack->svc_handle = req->svc_handle;
		nack->result = DS_REG_VER_NACK;
		nack->major_vers = 0;

		DS_DBG_PRCL(CE_NOTE, "ds@%lx: reg_nack>: '%s'" DS_EOL,
		    PORTID(port), req->svc_id);
		/*
		 * Send the response
		 */
		(void) ds_send_msg(port, msg, msglen);
		DS_FREE(msg, msglen);
		return;
	}
	DS_DBG_PRCL(CE_NOTE, "ds@%lx: <reg_req: '%s' found, hdl: 0x%llx" DS_EOL,
	    PORTID(port), req->svc_id, (u_longlong_t)svc->hdl);

	/*
	 * A client sends out a reg req in order to force service providers to
	 * initiate a reg req from their end (limitation in the protocol).  We
	 * expect the service provider to be in the inactive (DS_SVC_INACTIVE)
	 * state.  If the service provider has already sent out a reg req (the
	 * state is DS_SVC_REG_PENDING) or has already handshaken (the
	 * state is DS_SVC_ACTIVE), then we can simply ignore this reg
	 * req.  For any other state, we force an unregister before initiating
	 * a reg req.
	 */

	if (DS_HDL_ISCLIENT(req->svc_handle)) {
		switch (svc->state) {

		case DS_SVC_REG_PENDING:
		case DS_SVC_ACTIVE:
			DS_DBG_PRCL(CE_NOTE, "ds@%lx: <reg_req: '%s' pinging "
			    "client, state (%x)" DS_EOL, PORTID(port),
			    req->svc_id, svc->state);
			mutex_exit(&ds_svcs.lock);
			return;

		case DS_SVC_INACTIVE:
			DS_DBG_PRCL(CE_NOTE, "ds@%lx: <reg_req: '%s' pinging "
			    "client" DS_EOL, PORTID(port), req->svc_id);
			break;

		default:
			DS_DBG_PRCL(CE_NOTE, "ds@%lx: <reg_req: '%s' pinging "
			    "client forced unreg, state (%x)" DS_EOL,
			    PORTID(port), req->svc_id, svc->state);
			(void) ds_svc_unregister(svc, port);
			break;
		}
		(void) ds_svc_port_up(svc, port);
		(void) ds_svc_register_onport(svc, port);
		mutex_exit(&ds_svcs.lock);
		return;
	}

	/*
	 * Only remote service providers can initiate a registration.  The
	 * local sevice from here must be a client service.
	 */

	match = negotiate_version(svc->cap.nvers, svc->cap.vers,
	    req->major_vers, &new_major, &new_minor);

	/*
	 * Check version info. ACK only if the major numbers exactly
	 * match. The service entity can retry with a new minor
	 * based on the response sent as part of the NACK.
	 */
	if (match) {
		DS_DBG_PRCL(CE_NOTE, "ds@%lx: <reg_req: '%s' svc%d: state: %x "
		    "svc_portid: %d" DS_EOL, PORTID(port), req->svc_id,
		    (int)DS_HDL2IDX(svc->hdl), svc->state,
		    (int)(svc->port == NULL ? -1 : PORTID(svc->port)));
		/*
		 * If the current local service is already in use and
		 * it's not on this port, clone it.
		 */
		if (svc->state != DS_SVC_INACTIVE) {
			if (svc->port != NULL && port == svc->port) {
				/*
				 * Someone probably dropped an unreg req
				 * somewhere.  Force a local unreg.
				 */
				(void) ds_svc_unregister(svc, port);
			} else if (!DS_HDL_ISCLIENT(svc->hdl)) {
				/*
				 * Can't clone a non-client (service provider)
				 * handle.  This is because old in-kernel
				 * service providers can't deal with multiple
				 * handles.
				 */
				goto do_reg_nack;
			} else {
				svc = ds_svc_clone(svc);
			}
		}
		svc->port = port;
		svc->svc_hdl = req->svc_handle;
		svc->state = DS_SVC_ACTIVE;

		msglen = DS_MSG_LEN(ds_reg_ack_t);
		msg = DS_MALLOC(msglen);

		hdr = (ds_hdr_t *)msg;
		hdr->msg_type = DS_REG_ACK;
		hdr->payload_len = sizeof (ds_reg_ack_t);

		ack = (ds_reg_ack_t *)(msg + DS_HDR_SZ);
		ack->svc_handle = req->svc_handle;
		ack->minor_vers = MIN(new_minor, req->minor_vers);


		if (svc->ops.ds_reg_cb) {
			/* Call the registration callback */
			version.major = req->major_vers;
			version.minor = ack->minor_vers;
			(*svc->ops.ds_reg_cb)(svc->ops.cb_arg, &version,
			    svc->hdl);
		}
		mutex_exit(&ds_svcs.lock);

		DS_DBG_PRCL(CE_NOTE, "ds@%lx: reg_ack>: '%s' minor=0x%04X"
		    DS_EOL, PORTID(port), svc->cap.svc_id,
		    MIN(new_minor, req->minor_vers));
	} else {
		mutex_exit(&ds_svcs.lock);

		msglen = DS_MSG_LEN(ds_reg_nack_t);
		msg = DS_MALLOC(msglen);

		hdr = (ds_hdr_t *)msg;
		hdr->msg_type = DS_REG_NACK;
		hdr->payload_len = sizeof (ds_reg_nack_t);

		nack = (ds_reg_nack_t *)(msg + DS_HDR_SZ);
		nack->svc_handle = req->svc_handle;
		nack->result = DS_REG_VER_NACK;
		nack->major_vers = new_major;

		DS_DBG_PRCL(CE_NOTE, "ds@%lx: reg_nack>: '%s' major=0x%04X"
		    DS_EOL, PORTID(port), svc->cap.svc_id, new_major);
	}

	/* send message */
	(void) ds_send_msg(port, msg, msglen);
	DS_FREE(msg, msglen);
}

static void
ds_handle_reg_ack(ds_port_t *port, caddr_t buf, size_t len)
{
	ds_reg_ack_t	*ack;
	ds_ver_t	*ver;
	ds_ver_t	tmpver;
	ds_svc_t	*svc;
	size_t		explen = DS_MSG_LEN(ds_reg_ack_t);

	/* sanity check the incoming message */
	if (len != explen) {
		cmn_err(CE_WARN, "ds@%lx: <reg_ack: invalid message "
		    "length (%ld), expected %ld" DS_EOL, PORTID(port), len,
		    explen);
		return;
	}

	ack = (ds_reg_ack_t *)(buf + DS_HDR_SZ);

	mutex_enter(&ds_svcs.lock);

	/*
	 * This searches for service based on how we generate handles
	 * and so only works because this is a reg ack.
	 */
	if (DS_HDL_ISCLIENT(ack->svc_handle) ||
	    (svc = ds_get_svc(ack->svc_handle)) == NULL) {
		cmn_err(CE_WARN, "ds@%lx: <reg_ack: invalid handle 0x%llx"
		    DS_EOL, PORTID(port), (u_longlong_t)ack->svc_handle);
		goto done;
	}

	/* make sure the message makes sense */
	if (svc->state != DS_SVC_REG_PENDING) {
		cmn_err(CE_WARN, "ds@%lx: <reg_ack: invalid state (%d)" DS_EOL,
		    PORTID(port), svc->state);
		goto done;
	}

	ver = &(svc->cap.vers[svc->ver_idx]);

	/* major version has been agreed upon */
	svc->ver.major = ver->major;

	if (ack->minor_vers >= ver->minor) {
		/*
		 * Use the minor version specified in the
		 * original request.
		 */
		svc->ver.minor = ver->minor;
	} else {
		/*
		 * Use the lower minor version returned in
		 * the ack. By defninition, all lower minor
		 * versions must be supported.
		 */
		svc->ver.minor = ack->minor_vers;
	}

	svc->state = DS_SVC_ACTIVE;
	svc->port = port;

	DS_DBG_PRCL(CE_NOTE, "ds@%lx: <reg_ack: '%s' v%d.%d ready, hdl=0x%llx"
	    DS_EOL, PORTID(port), svc->cap.svc_id, svc->ver.major,
	    svc->ver.minor, (u_longlong_t)svc->hdl);

	/* notify the client that registration is complete */
	if (svc->ops.ds_reg_cb) {
		/*
		 * Use a temporary version structure so that
		 * the copy in the svc structure cannot be
		 * modified by the client.
		 */
		tmpver.major = svc->ver.major;
		tmpver.minor = svc->ver.minor;

		(*svc->ops.ds_reg_cb)(svc->ops.cb_arg, &tmpver, svc->hdl);
	}

done:
	mutex_exit(&ds_svcs.lock);
}

static boolean_t
ds_port_is_ready(ds_port_t *port)
{
	boolean_t is_ready;

	mutex_enter(&port->lock);
	is_ready = (port->ldc.state == LDC_UP) &&
	    (port->state == DS_PORT_READY);
	mutex_exit(&port->lock);
	return (is_ready);
}

static void
ds_try_next_port(ds_svc_t *svc, int portid)
{
	ds_port_t *port;
	ds_portset_t totry;
	int i;

	DS_DBG_LDC(CE_NOTE, "ds@%x %s" DS_EOL, portid, __func__);

	/*
	 * Get the ports that haven't been tried yet and are available to try.
	 */
	DS_PORTSET_DUP(totry, svc->avail);
	for (i = 0; i < DS_MAX_PORTS; i++) {
		if (DS_PORT_IN_SET(svc->tried, i))
			DS_PORTSET_DEL(totry, i);
	}

	if (DS_PORTSET_ISNULL(totry))
		return;

	for (i = 0; i < DS_MAX_PORTS; i++, portid++) {
		if (portid >= DS_MAX_PORTS) {
			portid = 0;
		}

		/*
		 * If the port is not in the available list,
		 * it is not a candidate for registration.
		 */
		if (!DS_PORT_IN_SET(totry, portid)) {
			continue;
		}

		port = &ds_ports[portid];

		if (!ds_port_is_ready(port))
			continue;

		DS_DBG_LDC(CE_NOTE, "ds@%x: %s trying ldc.id: %d" DS_EOL,
		    portid, __func__, (uint_t)(port->ldc.id));

		DS_PORTSET_ADD(svc->tried, portid);

		if (ds_send_reg_req(svc, port) == 0) {
			DS_DBG_LDC(CE_NOTE, "ds@%x: %s reg msg send OK" DS_EOL,
			    portid, __func__);
			/* register sent successfully */
			break;
		}
		DS_DBG_LDC(CE_NOTE, "ds@%x: %s reg msg send FAIL" DS_EOL,
		    portid, __func__);

		/* reset the service to try the next port */
		ds_reset_svc(svc, port);
	}
}

static void
ds_handle_reg_nack(ds_port_t *port, caddr_t buf, size_t len)
{
	ds_reg_nack_t	*nack;
	ds_svc_t	*svc;
	int		idx;
	size_t		explen = DS_MSG_LEN(ds_reg_nack_t);

	/* sanity check the incoming message */
	if (len != explen) {
		cmn_err(CE_WARN, "ds@%lx: <reg_nack: invalid message "
		    "length (%ld), expected %ld" DS_EOL, PORTID(port), len,
		    explen);
		return;
	}

	nack = (ds_reg_nack_t *)(buf + DS_HDR_SZ);

	mutex_enter(&ds_svcs.lock);

	/*
	 * We expect a reg_nack for a client ping.
	 */
	if (DS_HDL_ISCLIENT(nack->svc_handle)) {
		DS_DBG_PRCL(CE_NOTE, "ds@%lx: <reg_nack: ping hdl: 0x%llx"
		    DS_EOL, PORTID(port), (u_longlong_t)nack->svc_handle);
		goto done;
	}

	/*
	 * This searches for service based on how we generate handles
	 * and so only works because this is a reg nack.
	 */
	if ((svc = ds_get_svc(nack->svc_handle)) == NULL) {
		cmn_err(CE_WARN, "ds@%lx: <reg_nack: invalid handle 0x%llx"
		    DS_EOL, PORTID(port), (u_longlong_t)nack->svc_handle);
		goto done;
	}

	/* make sure the message makes sense */
	if (svc->state != DS_SVC_REG_PENDING) {
		DS_DBG_PRCL(CE_NOTE, "ds@%lx: <reg_nack: '%s' handle: 0x%llx "
		    "invalid state (%d)" DS_EOL, PORTID(port), svc->cap.svc_id,
		    (u_longlong_t)nack->svc_handle, svc->state);
		goto done;
	}

	if (nack->result == DS_REG_DUP) {
		cmn_err(CE_WARN, "ds@%lx: <reg_nack: duplicate registration "
		    " for %s" DS_EOL, PORTID(port), svc->cap.svc_id);
		ds_reset_svc(svc, port);
		goto done;
	}

	/*
	 * A major version of zero indicates that the
	 * service is not supported at all.
	 */
	if (nack->major_vers == 0) {
		DS_DBG_PRCL(CE_NOTE, "ds@%lx: <reg_nack: '%s' not supported"
		    DS_EOL, PORTID(port), svc->cap.svc_id);
		ds_reset_svc(svc, port);
		if ((svc->flags & DSSF_ISCLIENT) == 0)
			ds_try_next_port(svc, PORTID(port) + 1);
		goto done;
	}

	DS_DBG_PRCL(CE_NOTE, "ds@%lx: <reg_nack: '%s' hdl=0x%llx, nack=%d.x"
	    DS_EOL, PORTID(port), svc->cap.svc_id,
	    (u_longlong_t)nack->svc_handle, nack->major_vers);

	/*
	 * Walk the version list for the service, looking for
	 * a major version that is as close to the requested
	 * major version as possible.
	 */
	for (idx = svc->ver_idx; idx < svc->cap.nvers; idx++) {
		if (svc->cap.vers[idx].major <= nack->major_vers) {
			/* found a version to try */
			break;
		}
	}

	if (idx == svc->cap.nvers) {
		/* no supported version */
		DS_DBG_PRCL(CE_NOTE, "ds@%lx: <reg_nack: %s v%d.x not supported"
		    DS_EOL, PORTID(port), svc->cap.svc_id, nack->major_vers);
		ds_reset_svc(svc, port);
		if ((svc->flags & DSSF_ISCLIENT) == 0)
			ds_try_next_port(svc, PORTID(port) + 1);
		goto done;
	}

	/* start the handshake again */
	svc->state = DS_SVC_INACTIVE;
	svc->ver_idx = idx;

	(void) ds_svc_register(svc, NULL);

done:
	mutex_exit(&ds_svcs.lock);
}

static void
ds_handle_unreg_req(ds_port_t *port, caddr_t buf, size_t len)
{
	ds_hdr_t	*hdr;
	ds_unreg_req_t	*req;
	ds_unreg_ack_t	*ack;
	ds_svc_t	*svc;
	char		*msg;
	size_t		msglen;
	size_t		explen = DS_MSG_LEN(ds_unreg_req_t);
	boolean_t	is_up;

	/* sanity check the incoming message */
	if (len != explen) {
		cmn_err(CE_WARN, "ds@%lx: <unreg_req: invalid message "
		    "length (%ld), expected %ld" DS_EOL, PORTID(port), len,
		    explen);
		return;
	}

	req = (ds_unreg_req_t *)(buf + DS_HDR_SZ);

	mutex_enter(&ds_svcs.lock);

	/* lookup appropriate client or service */
	if (DS_HDL_ISCLIENT(req->svc_handle) ||
	    ((svc = ds_find_clnt_svc_by_hdl_port(req->svc_handle, port))
	    == NULL && ((svc = ds_get_svc(req->svc_handle)) == NULL ||
	    svc->port != port))) {
		mutex_exit(&ds_svcs.lock);
		mutex_enter(&port->lock);
		is_up = (port->ldc.state == LDC_UP);
		mutex_exit(&port->lock);
		if (!is_up)
			return;
		DS_DBG_PRCL(CE_NOTE, "ds@%lx: <unreg_req: invalid handle 0x%llx"
		    DS_EOL, PORTID(port), (u_longlong_t)req->svc_handle);
		ds_send_unreg_nack(port, req->svc_handle);
		return;
	}

	DS_DBG_PRCL(CE_NOTE, "ds@%lx: <unreg_req: '%s' handle 0x%llx" DS_EOL,
	    PORTID(port), svc->cap.svc_id, (u_longlong_t)req->svc_handle);

	(void) ds_svc_unregister(svc, svc->port);

	DS_DBG_PRCL(CE_NOTE, "ds@%lx: unreg_ack>: '%s' hdl=0x%llx" DS_EOL,
	    PORTID(port), svc->cap.svc_id, (u_longlong_t)req->svc_handle);

	ds_check_for_dup_services(svc);

	mutex_exit(&ds_svcs.lock);

	msglen = DS_HDR_SZ + sizeof (ds_unreg_ack_t);
	msg = DS_MALLOC(msglen);

	hdr = (ds_hdr_t *)msg;
	hdr->msg_type = DS_UNREG_ACK;
	hdr->payload_len = sizeof (ds_unreg_ack_t);

	ack = (ds_unreg_ack_t *)(msg + DS_HDR_SZ);
	ack->svc_handle = req->svc_handle;

	/* send message */
	(void) ds_send_msg(port, msg, msglen);
	DS_FREE(msg, msglen);

}

static void
ds_handle_unreg_ack(ds_port_t *port, caddr_t buf, size_t len)
{
	ds_unreg_ack_t	*ack;
	size_t		explen = DS_MSG_LEN(ds_unreg_ack_t);

	/* sanity check the incoming message */
	if (len != explen) {
		cmn_err(CE_WARN, "ds@%lx: <unreg_ack: invalid message "
		    "length (%ld), expected %ld" DS_EOL, PORTID(port), len,
		    explen);
		return;
	}

	ack = (ds_unreg_ack_t *)(buf + DS_HDR_SZ);

	DS_DBG_PRCL(CE_NOTE, "ds@%lx: <unreg_ack: hdl=0x%llx" DS_EOL,
	    PORTID(port), (u_longlong_t)ack->svc_handle);

#ifdef DEBUG
	mutex_enter(&ds_svcs.lock);

	/*
	 * Since the unregister request was initiated locally,
	 * the service structure has already been torn down.
	 * Just perform a sanity check to make sure the message
	 * is appropriate.
	 */
	if (ds_get_svc(ack->svc_handle) != NULL) {
		DS_DBG_PRCL(CE_NOTE, "ds@%lx: <unreg_ack: handle 0x%llx in use"
		    DS_EOL, PORTID(port), (u_longlong_t)ack->svc_handle);
	}

	mutex_exit(&ds_svcs.lock);
#endif	/* DEBUG */
}

static void
ds_handle_unreg_nack(ds_port_t *port, caddr_t buf, size_t len)
{
	ds_unreg_nack_t	*nack;
	size_t		explen = DS_MSG_LEN(ds_unreg_nack_t);

	/* sanity check the incoming message */
	if (len != explen) {
		cmn_err(CE_WARN, "ds@%lx: <unreg_nack: invalid message "
		    "length (%ld), expected %ld" DS_EOL, PORTID(port), len,
		    explen);
		return;
	}

	nack = (ds_unreg_nack_t *)(buf + DS_HDR_SZ);

	DS_DBG_PRCL(CE_NOTE, "ds@%lx: <unreg_nack: hdl=0x%llx" DS_EOL,
	    PORTID(port), (u_longlong_t)nack->svc_handle);

#ifdef DEBUG
	mutex_enter(&ds_svcs.lock);

	/*
	 * Since the unregister request was initiated locally,
	 * the service structure has already been torn down.
	 * Just perform a sanity check to make sure the message
	 * is appropriate.
	 */
	if (ds_get_svc(nack->svc_handle) != NULL) {
		DS_DBG_PRCL(CE_NOTE, "ds@%lx: <unreg_nack: handle 0x%llx in use"
		    DS_EOL, PORTID(port), (u_longlong_t)nack->svc_handle);
	}

	mutex_exit(&ds_svcs.lock);
#endif	/* DEBUG */
}

static void
ds_handle_data(ds_port_t *port, caddr_t buf, size_t len)
{
	ds_data_handle_t	*data;
	ds_svc_t		*svc;
	char			*msg;
	int			msgsz;
	int			hdrsz;
	size_t			explen = DS_MSG_LEN(ds_data_handle_t);

	/* sanity check the incoming message */
	if (len < explen) {
		cmn_err(CE_WARN, "ds@%lx: <data: invalid message length "
		    "(%ld), expected at least %ld" DS_EOL, PORTID(port), len,
		    explen);
		return;
	}

	data = (ds_data_handle_t *)(buf + DS_HDR_SZ);

	hdrsz = DS_HDR_SZ + sizeof (ds_data_handle_t);
	msgsz = len - hdrsz;

	/* strip off the header for the client */
	msg = (msgsz) ? (buf + hdrsz) : NULL;

	mutex_enter(&ds_svcs.lock);

	if ((svc = ds_find_clnt_svc_by_hdl_port(data->svc_handle, port))
	    == NULL) {
		if ((svc = ds_get_svc(data->svc_handle)) == NULL) {
			mutex_exit(&ds_svcs.lock);
			cmn_err(CE_WARN, "ds@%lx: <data: invalid handle 0x%llx"
			    DS_EOL, PORTID(port),
			    (u_longlong_t)data->svc_handle);
			ds_send_data_nack(port, data->svc_handle);
			return;
		}
	}

	mutex_exit(&ds_svcs.lock);

	DS_DBG_PRCL(CE_NOTE, "ds@%lx: <data: '%s' hdl=0x%llx" DS_EOL,
	    PORTID(port), svc->cap.svc_id, (u_longlong_t)svc->hdl);
	DS_DUMP_MSG(DS_DBG_FLAG_PRCL, msg, msgsz);

	/* dispatch this message to the client */
	(*svc->ops.ds_data_cb)(svc->ops.cb_arg, msg, msgsz);
}

static void
ds_handle_nack(ds_port_t *port, caddr_t buf, size_t len)
{
	ds_svc_t	*svc;
	ds_data_nack_t	*nack;
	size_t		explen = DS_MSG_LEN(ds_data_nack_t);

	/* sanity check the incoming message */
	if (len != explen) {
		cmn_err(CE_WARN, "ds@%lx: <data_nack: invalid message "
		    "length (%ld), expected %ld" DS_EOL, PORTID(port), len,
		    explen);
		return;
	}

	nack = (ds_data_nack_t *)(buf + DS_HDR_SZ);

	DS_DBG_PRCL(CE_NOTE, "ds@%lx: data_nack: hdl=0x%llx, result=0x%llx"
	    DS_EOL, PORTID(port), (u_longlong_t)nack->svc_handle,
	    (u_longlong_t)nack->result);

	if (nack->result == DS_INV_HDL) {

		mutex_enter(&ds_svcs.lock);

		if ((svc = ds_find_clnt_svc_by_hdl_port(nack->svc_handle,
		    port)) == NULL) {
			if ((svc = ds_get_svc(nack->svc_handle)) == NULL) {
				mutex_exit(&ds_svcs.lock);
				return;
			}
		}

		cmn_err(CE_WARN, "ds@%lx: <data_nack: handle 0x%llx reported "
		    " as invalid" DS_EOL, PORTID(port),
		    (u_longlong_t)nack->svc_handle);

		(void) ds_svc_unregister(svc, svc->port);

		mutex_exit(&ds_svcs.lock);
	}
}

/* Initialize the port */
void
ds_send_init_req(ds_port_t *port)
{
	ds_hdr_t	*hdr;
	ds_init_req_t	*init_req;
	size_t		msglen;
	ds_ver_t	*vers = &ds_vers[port->ver_idx];

	mutex_enter(&port->lock);
	if (port->state != DS_PORT_LDC_INIT) {
		DS_DBG_PRCL(CE_NOTE, "ds@%lx: init_req>: invalid state: %d"
		    DS_EOL, PORTID(port), port->state);
		mutex_exit(&port->lock);
		return;
	}
	mutex_exit(&port->lock);

	DS_DBG_PRCL(CE_NOTE, "ds@%lx: init_req>: req=v%d.%d" DS_EOL,
	    PORTID(port), vers->major, vers->minor);

	msglen = DS_HDR_SZ + sizeof (ds_init_req_t);
	hdr = DS_MALLOC(msglen);

	hdr->msg_type = DS_INIT_REQ;
	hdr->payload_len = sizeof (ds_init_req_t);

	init_req = (ds_init_req_t *)((caddr_t)hdr + DS_HDR_SZ);
	init_req->major_vers = vers->major;
	init_req->minor_vers = vers->minor;

	if (ds_send_msg(port, (caddr_t)hdr, msglen) == 0) {
		/*
		 * We've left the port state unlocked over the malloc/send,
		 * make sure no one has changed the state under us before
		 * we update the state.
		 */
		mutex_enter(&port->lock);
		if (port->state == DS_PORT_LDC_INIT)
			port->state = DS_PORT_INIT_REQ;
		mutex_exit(&port->lock);
	}
	DS_FREE(hdr, msglen);
}

static int
ds_send_reg_req(ds_svc_t *svc, ds_port_t *port)
{
	ds_ver_t	*ver;
	ds_hdr_t	*hdr;
	caddr_t		msg;
	size_t		msglen;
	ds_reg_req_t	*req;
	size_t		idlen;
	int		rv;

	if ((svc->state != DS_SVC_INACTIVE) &&
	    ((svc->flags & DSSF_ISCLIENT) == 0)) {
		DS_DBG_PRCL(CE_NOTE, "ds@%lx: reg_req>: invalid svc state (%d) "
		    "for svc '%s'" DS_EOL, PORTID(port), svc->state,
		    svc->cap.svc_id);
		return (-1);
	}

	mutex_enter(&port->lock);

	/* check on the LDC to Zeus */
	if (port->ldc.state != LDC_UP) {
		/* can not send message */
		DS_DBG_PRCL(CE_NOTE, "ds@%lx: reg_req>: channel %ld is not up"
		    DS_EOL, PORTID(port), port->ldc.id);
		mutex_exit(&port->lock);
		return (-1);
	}

	/* make sure port is ready */
	if (port->state != DS_PORT_READY) {
		/* can not send message */
		DS_DBG_PRCL(CE_NOTE, "ds@%lx: reg_req>: port is not ready"
		    DS_EOL, PORTID(port));
		mutex_exit(&port->lock);
		return (-1);
	}

	mutex_exit(&port->lock);

	/* allocate the message buffer */
	idlen = strlen(svc->cap.svc_id);
	msglen = DS_HDR_SZ + sizeof (ds_reg_req_t) + idlen;
	msg = DS_MALLOC(msglen);

	/* copy in the header data */
	hdr = (ds_hdr_t *)msg;
	hdr->msg_type = DS_REG_REQ;
	hdr->payload_len = sizeof (ds_reg_req_t) + idlen;

	req = (ds_reg_req_t *)(msg + DS_HDR_SZ);
	req->svc_handle = svc->hdl;
	ver = &(svc->cap.vers[svc->ver_idx]);
	req->major_vers = ver->major;
	req->minor_vers = ver->minor;

	/* copy in the service id */
	(void) memcpy(req->svc_id, svc->cap.svc_id, idlen + 1);

	/* send the message */
	DS_DBG_PRCL(CE_NOTE, "ds@%lx: reg_req>: '%s' ver=%d.%d, hdl=0x%llx"
	    DS_EOL, PORTID(port), svc->cap.svc_id, ver->major, ver->minor,
	    (u_longlong_t)svc->hdl);

	if ((rv = ds_send_msg(port, msg, msglen)) != 0) {
		svc->port = port;
		rv = -1;
	} else if ((svc->flags & DSSF_ISCLIENT) == 0) {
		svc->state = DS_SVC_REG_PENDING;
	}
	DS_FREE(msg, msglen);

	return (rv);
}

/*
 * Keep around in case we want this later
 */
int
ds_send_unreg_req(ds_svc_t *svc)
{
	caddr_t		msg;
	size_t		msglen;
	ds_hdr_t	*hdr;
	ds_unreg_req_t	*req;
	ds_port_t	*port = svc->port;
	int		rv;

	if (port == NULL) {
		DS_DBG(CE_NOTE, "send_unreg_req: service '%s' not "
		    "associated with a port" DS_EOL, svc->cap.svc_id);
		return (-1);
	}

	mutex_enter(&port->lock);

	/* check on the LDC to Zeus */
	if (port->ldc.state != LDC_UP) {
		/* can not send message */
		cmn_err(CE_WARN, "ds@%lx: unreg_req>: channel %ld is not up"
		    DS_EOL, PORTID(port), port->ldc.id);
		mutex_exit(&port->lock);
		return (-1);
	}

	/* make sure port is ready */
	if (port->state != DS_PORT_READY) {
		/* can not send message */
		cmn_err(CE_WARN, "ds@%lx: unreg_req>: port is not ready" DS_EOL,
		    PORTID(port));
		mutex_exit(&port->lock);
		return (-1);
	}

	mutex_exit(&port->lock);

	msglen = DS_HDR_SZ + sizeof (ds_unreg_req_t);
	msg = DS_MALLOC(msglen);

	/* copy in the header data */
	hdr = (ds_hdr_t *)msg;
	hdr->msg_type = DS_UNREG;
	hdr->payload_len = sizeof (ds_unreg_req_t);

	req = (ds_unreg_req_t *)(msg + DS_HDR_SZ);
	if (svc->flags & DSSF_ISCLIENT) {
		req->svc_handle = svc->svc_hdl;
	} else {
		req->svc_handle = svc->hdl;
	}

	/* send the message */
	DS_DBG_PRCL(CE_NOTE, "ds@%lx: unreg_req>: '%s' hdl=0x%llx" DS_EOL,
	    PORTID(port), (svc->cap.svc_id) ? svc->cap.svc_id : "NULL",
	    (u_longlong_t)svc->hdl);

	if ((rv = ds_send_msg(port, msg, msglen)) != 0) {
		rv = -1;
	}
	DS_FREE(msg, msglen);

	return (rv);
}

static void
ds_send_unreg_nack(ds_port_t *port, ds_svc_hdl_t bad_hdl)
{
	caddr_t		msg;
	size_t		msglen;
	ds_hdr_t	*hdr;
	ds_unreg_nack_t	*nack;

	mutex_enter(&port->lock);

	/* check on the LDC to Zeus */
	if (port->ldc.state != LDC_UP) {
		/* can not send message */
		cmn_err(CE_WARN, "ds@%lx: unreg_nack>: channel %ld is not up"
		    DS_EOL, PORTID(port), port->ldc.id);
		mutex_exit(&port->lock);
		return;
	}

	/* make sure port is ready */
	if (port->state != DS_PORT_READY) {
		/* can not send message */
		cmn_err(CE_WARN, "ds@%lx: unreg_nack>: port is not ready"
		    DS_EOL, PORTID(port));
		mutex_exit(&port->lock);
		return;
	}

	mutex_exit(&port->lock);

	msglen = DS_HDR_SZ + sizeof (ds_unreg_nack_t);
	msg = DS_MALLOC(msglen);

	/* copy in the header data */
	hdr = (ds_hdr_t *)msg;
	hdr->msg_type = DS_UNREG_NACK;
	hdr->payload_len = sizeof (ds_unreg_nack_t);

	nack = (ds_unreg_nack_t *)(msg + DS_HDR_SZ);
	nack->svc_handle = bad_hdl;

	/* send the message */
	DS_DBG_PRCL(CE_NOTE, "ds@%lx: unreg_nack>: hdl=0x%llx" DS_EOL,
	    PORTID(port), (u_longlong_t)bad_hdl);

	(void) ds_send_msg(port, msg, msglen);
	DS_FREE(msg, msglen);
}

static void
ds_send_data_nack(ds_port_t *port, ds_svc_hdl_t bad_hdl)
{
	caddr_t		msg;
	size_t		msglen;
	ds_hdr_t	*hdr;
	ds_data_nack_t	*nack;

	mutex_enter(&port->lock);

	/* check on the LDC to Zeus */
	if (port->ldc.state != LDC_UP) {
		/* can not send message */
		cmn_err(CE_WARN, "ds@%lx: data_nack>: channel %ld is not up"
		    DS_EOL, PORTID(port), port->ldc.id);
		mutex_exit(&port->lock);
		return;
	}

	/* make sure port is ready */
	if (port->state != DS_PORT_READY) {
		/* can not send message */
		cmn_err(CE_WARN, "ds@%lx: data_nack>: port is not ready" DS_EOL,
		    PORTID(port));
		mutex_exit(&port->lock);
		return;
	}

	mutex_exit(&port->lock);

	msglen = DS_HDR_SZ + sizeof (ds_data_nack_t);
	msg = DS_MALLOC(msglen);

	/* copy in the header data */
	hdr = (ds_hdr_t *)msg;
	hdr->msg_type = DS_NACK;
	hdr->payload_len = sizeof (ds_data_nack_t);

	nack = (ds_data_nack_t *)(msg + DS_HDR_SZ);
	nack->svc_handle = bad_hdl;
	nack->result = DS_INV_HDL;

	/* send the message */
	DS_DBG_PRCL(CE_NOTE, "ds@%lx: data_nack>: hdl=0x%llx" DS_EOL,
	    PORTID(port), (u_longlong_t)bad_hdl);

	(void) ds_send_msg(port, msg, msglen);
	DS_FREE(msg, msglen);
}

/* END DS PROTOCOL SUPPORT FUNCTIONS */

#ifdef DEBUG

#define	BYTESPERLINE	8
#define	LINEWIDTH	((BYTESPERLINE * 3) + (BYTESPERLINE + 2) + 1)
#define	ASCIIOFFSET	((BYTESPERLINE * 3) + 2)
#define	ISPRINT(c)	((c >= ' ') && (c <= '~'))

/*
 * Output a buffer formatted with a set number of bytes on
 * each line. Append each line with the ASCII equivalent of
 * each byte if it falls within the printable ASCII range,
 * and '.' otherwise.
 */
void
ds_dump_msg(void *vbuf, size_t len)
{
	int	i, j;
	char	*curr;
	char	*aoff;
	char	line[LINEWIDTH];
	uint8_t	*buf = vbuf;

	if (len > 128)
		len = 128;

	/* walk the buffer one line at a time */
	for (i = 0; i < len; i += BYTESPERLINE) {

		bzero(line, LINEWIDTH);

		curr = line;
		aoff = line + ASCIIOFFSET;

		/*
		 * Walk the bytes in the current line, storing
		 * the hex value for the byte as well as the
		 * ASCII representation in a temporary buffer.
		 * All ASCII values are placed at the end of
		 * the line.
		 */
		for (j = 0; (j < BYTESPERLINE) && ((i + j) < len); j++) {
			(void) sprintf(curr, " %02x", buf[i + j]);
			*aoff = (ISPRINT(buf[i + j])) ? buf[i + j] : '.';
			curr += 3;
			aoff++;
		}

		/*
		 * Fill in to the start of the ASCII translation
		 * with spaces. This will only be necessary if
		 * this is the last line and there are not enough
		 * bytes to fill the whole line.
		 */
		while (curr != (line + ASCIIOFFSET))
			*curr++ = ' ';

		cmn_err(CE_NOTE, "%s" DS_EOL, line);
	}
}
#endif /* DEBUG */


/*
 * Walk the table of registered services, executing the specified callback
 * function for each service on a port. A non-zero return value from the
 * callback is used to terminate the walk, not to indicate an error. Returns
 * the index of the last service visited.
 */
int
ds_walk_svcs(svc_cb_t svc_cb, void *arg)
{
	int		idx;
	ds_svc_t	*svc;

	ASSERT(MUTEX_HELD(&ds_svcs.lock));

	/* walk every table entry */
	for (idx = 0; idx < ds_svcs.maxsvcs; idx++) {
		svc = ds_svcs.tbl[idx];

		/* execute the callback */
		if ((*svc_cb)(svc, arg) != 0)
			break;
	}

	return (idx);
}

static int
ds_svc_isfree(ds_svc_t *svc, void *arg)
{
	_NOTE(ARGUNUSED(arg))

	/*
	 * Looking for a free service. This may be a NULL entry
	 * in the table, or an unused structure that could be
	 * reused.
	 */

	if (DS_SVC_ISFREE(svc)) {
		/* yes, it is free */
		return (1);
	}

	/* not a candidate */
	return (0);
}

int
ds_svc_ismatch(ds_svc_t *svc, void *arg)
{
	if (DS_SVC_ISFREE(svc)) {
		return (0);
	}

	if (strcmp(svc->cap.svc_id, arg) == 0 &&
	    (svc->flags & DSSF_ISCLIENT) == 0) {
		/* found a match */
		return (1);
	}

	return (0);
}

int
ds_svc_clnt_ismatch(ds_svc_t *svc, void *arg)
{
	if (DS_SVC_ISFREE(svc)) {
		return (0);
	}

	if (strcmp(svc->cap.svc_id, arg) == 0 &&
	    (svc->flags & DSSF_ISCLIENT) != 0) {
		/* found a match */
		return (1);
	}

	return (0);
}

int
ds_svc_free(ds_svc_t *svc, void *arg)
{
	_NOTE(ARGUNUSED(arg))

	if (svc == NULL) {
		return (0);
	}

	if (svc->cap.svc_id) {
		DS_FREE(svc->cap.svc_id, strlen(svc->cap.svc_id) + 1);
		svc->cap.svc_id = NULL;
	}

	if (svc->cap.vers) {
		DS_FREE(svc->cap.vers, svc->cap.nvers * sizeof (ds_ver_t));
		svc->cap.vers = NULL;
	}

	DS_FREE(svc, sizeof (ds_svc_t));

	return (0);
}

static void
ds_set_svc_port_tried(char *svc_id, ds_port_t *port)
{
	int		idx;
	ds_svc_t	*svc;

	ASSERT(MUTEX_HELD(&ds_svcs.lock));

	/* walk every table entry */
	for (idx = 0; idx < ds_svcs.maxsvcs; idx++) {
		svc = ds_svcs.tbl[idx];
		if (!DS_SVC_ISFREE(svc) && (svc->flags & DSSF_ISCLIENT) != 0 &&
		    strcmp(svc_id, svc->cap.svc_id) == 0)
			DS_PORTSET_ADD(svc->tried, PORTID(port));
	}
}

static int
ds_svc_register_onport(ds_svc_t *svc, ds_port_t *port)
{
	ASSERT(MUTEX_HELD(&ds_svcs.lock));

	if (DS_SVC_ISFREE(svc))
		return (0);

	if (!DS_PORT_IN_SET(svc->avail, PORTID(port)))
		return (0);

	if (DS_PORT_IN_SET(svc->tried, PORTID(port)))
		return (0);

	if (!ds_port_is_ready(port))
		return (0);

	if ((svc->flags & DSSF_ISCLIENT) == 0) {
		if (svc->state != DS_SVC_INACTIVE)
			return (0);
		DS_PORTSET_ADD(svc->tried, PORTID(port));
	} else {
		ds_set_svc_port_tried(svc->cap.svc_id, port);

		/*
		 * Never send a client reg req to the SP.
		 */
		if (PORTID(port) == ds_sp_port_id) {
			return (0);
		}
	}

	if (ds_send_reg_req(svc, port) == 0) {
		/* register sent successfully */
		return (1);
	}

	if ((svc->flags & DSSF_ISCLIENT) == 0) {
		/* reset the service */
		ds_reset_svc(svc, port);
	}
	return (0);
}

static int
ds_svc_register_onport_walker(ds_svc_t *svc, void *arg)
{
	ASSERT(MUTEX_HELD(&ds_svcs.lock));

	if (DS_SVC_ISFREE(svc))
		return (0);

	(void) ds_svc_register_onport(svc, arg);
	return (0);
}

int
ds_svc_register(ds_svc_t *svc, void *arg)
{
	_NOTE(ARGUNUSED(arg))
	ds_portset_t ports;
	ds_port_t *port;
	int	idx;

	ASSERT(MUTEX_HELD(&ds_svcs.lock));

	if (DS_SVC_ISFREE(svc))
		return (0);

	DS_PORTSET_DUP(ports, svc->avail);
	if (svc->flags & DSSF_ISCLIENT) {
		for (idx = 0; idx < DS_MAX_PORTS; idx++) {
			if (DS_PORT_IN_SET(svc->tried, idx))
				DS_PORTSET_DEL(ports, idx);
		}
	} else if (svc->state != DS_SVC_INACTIVE)
		return (0);

	if (DS_PORTSET_ISNULL(ports))
		return (0);

	/*
	 * Attempt to register the service. Start with the lowest
	 * numbered port and continue until a registration message
	 * is sent successfully, or there are no ports left to try.
	 */
	for (idx = 0; idx < DS_MAX_PORTS; idx++) {

		/*
		 * If the port is not in the available list,
		 * it is not a candidate for registration.
		 */
		if (!DS_PORT_IN_SET(ports, idx)) {
			continue;
		}

		port = &ds_ports[idx];
		if (ds_svc_register_onport(svc, port)) {
			if ((svc->flags & DSSF_ISCLIENT) == 0)
				break;
		}
	}

	return (0);
}

static int
ds_svc_unregister(ds_svc_t *svc, void *arg)
{
	ds_port_t *port = (ds_port_t *)arg;
	ds_svc_hdl_t hdl;

	ASSERT(MUTEX_HELD(&ds_svcs.lock));

	if (DS_SVC_ISFREE(svc)) {
		return (0);
	}

	/* make sure the service is using this port */
	if (svc->port != port) {
		return (0);
	}

	if (port) {
		DS_DBG(CE_NOTE, "ds@%lx: svc_unreg: id='%s', ver=%d.%d, "
		    " hdl=0x%09lx" DS_EOL, PORTID(port), svc->cap.svc_id,
		    svc->ver.major, svc->ver.minor, svc->hdl);
	} else {
		DS_DBG(CE_NOTE, "port=NULL: svc_unreg: id='%s', ver=%d.%d, "
		    " hdl=0x%09lx" DS_EOL, svc->cap.svc_id, svc->ver.major,
		    svc->ver.minor, svc->hdl);
	}

	/* reset the service structure */
	ds_reset_svc(svc, port);

	/* call the client unregister callback */
	if (svc->ops.ds_unreg_cb) {
		(*svc->ops.ds_unreg_cb)(svc->ops.cb_arg);
	}

	/* increment the count in the handle to prevent reuse */
	hdl = DS_ALLOC_HDL(DS_HDL2IDX(svc->hdl), DS_HDL2COUNT(svc->hdl));
	if (DS_HDL_ISCLIENT(svc->hdl)) {
		DS_HDL_SET_ISCLIENT(hdl);
	}
	svc->hdl = hdl;

	if (svc->state != DS_SVC_UNREG_PENDING) {
		/* try to initiate a new registration */
		(void) ds_svc_register(svc, NULL);
	}

	return (0);
}

static int
ds_svc_port_up(ds_svc_t *svc, void *arg)
{
	ds_port_t *port = (ds_port_t *)arg;

	if (DS_SVC_ISFREE(svc)) {
		/* nothing to do */
		return (0);
	}

	DS_PORTSET_ADD(svc->avail, port->id);
	DS_PORTSET_DEL(svc->tried, port->id);

	return (0);
}

static void
ds_set_port_ready(ds_port_t *port, uint16_t major, uint16_t minor)
{
	boolean_t was_ready;

	mutex_enter(&port->lock);
	was_ready = (port->state == DS_PORT_READY);
	if (!was_ready) {
		port->state = DS_PORT_READY;
		port->ver.major = major;
		port->ver.minor = minor;
	}
	mutex_exit(&port->lock);

	if (!was_ready) {

		/*
		 * The port came up, so update all the services
		 * with this information. Follow that up with an
		 * attempt to register any service that is not
		 * already registered.
		 */
		mutex_enter(&ds_svcs.lock);

		(void) ds_walk_svcs(ds_svc_port_up, port);
		(void) ds_walk_svcs(ds_svc_register_onport_walker, port);

		mutex_exit(&ds_svcs.lock);
	}
}

ds_svc_t *
ds_alloc_svc(void)
{
	int		idx;
	uint_t		newmaxsvcs;
	ds_svc_t	**newtbl;
	ds_svc_t	*newsvc;

	ASSERT(MUTEX_HELD(&ds_svcs.lock));

	idx = ds_walk_svcs(ds_svc_isfree, NULL);

	if (idx != ds_svcs.maxsvcs) {
		goto found;
	}

	/*
	 * There was no free space in the table. Grow
	 * the table to double its current size.
	 */
	newmaxsvcs = ds_svcs.maxsvcs * 2;
	newtbl = DS_MALLOC(newmaxsvcs * sizeof (ds_svc_t *));

	/* copy old table data to the new table */
	(void) memcpy(newtbl, ds_svcs.tbl,
	    ds_svcs.maxsvcs * sizeof (ds_svc_t *));

	/* clean up the old table */
	DS_FREE(ds_svcs.tbl, ds_svcs.maxsvcs * sizeof (ds_svc_t *));
	ds_svcs.tbl = newtbl;
	ds_svcs.maxsvcs = newmaxsvcs;

	/* search for a free space again */
	idx = ds_walk_svcs(ds_svc_isfree, NULL);

	/* the table is locked so should find a free slot */
	ASSERT(idx != ds_svcs.maxsvcs);

found:
	/* allocate a new svc structure if necessary */
	if ((newsvc = ds_svcs.tbl[idx]) == NULL) {
		/* allocate a new service */
		newsvc = DS_MALLOC(sizeof (ds_svc_t));
		ds_svcs.tbl[idx] = newsvc;
	}

	/* fill in the handle */
	newsvc->hdl = DS_ALLOC_HDL(idx, DS_HDL2COUNT(newsvc->hdl));
	newsvc->state = DS_SVC_FREE;	/* Mark as free temporarily */

	return (newsvc);
}

static void
ds_reset_svc(ds_svc_t *svc, ds_port_t *port)
{
	ASSERT(MUTEX_HELD(&ds_svcs.lock));

	if (svc->state != DS_SVC_UNREG_PENDING)
		svc->state = DS_SVC_INACTIVE;
	svc->ver_idx = 0;
	svc->ver.major = 0;
	svc->ver.minor = 0;
	svc->port = NULL;
	if (port) {
		DS_PORTSET_DEL(svc->avail, port->id);
	}
}

ds_svc_t *
ds_get_svc(ds_svc_hdl_t hdl)
{
	int		idx;
	ds_svc_t	*svc;

	ASSERT(MUTEX_HELD(&ds_svcs.lock));

	if (hdl == DS_INVALID_HDL)
		return (NULL);

	idx = DS_HDL2IDX(hdl);

	/* check if index is out of bounds */
	if ((idx < 0) || (idx >= ds_svcs.maxsvcs))
		return (NULL);

	svc = ds_svcs.tbl[idx];

	/* check for a valid service */
	if (DS_SVC_ISFREE(svc))
		return (NULL);

	/* make sure the handle is an exact match */
	if (svc->hdl != hdl)
		return (NULL);

	return (svc);
}

static void
ds_port_reset(ds_port_t *port)
{
	ASSERT(MUTEX_HELD(&ds_svcs.lock));
	ASSERT(MUTEX_HELD(&port->lock));

	/* connection went down, mark everything inactive */
	(void) ds_walk_svcs(ds_svc_unregister, port);

	port->ver_idx = 0;
	port->ver.major = 0;
	port->ver.minor = 0;
	port->state = DS_PORT_LDC_INIT;
}

/*
 * Verify that a version array is sorted as expected for the
 * version negotiation to work correctly.
 */
ds_vers_check_t
ds_vers_isvalid(ds_ver_t *vers, int nvers)
{
	uint16_t	curr_major;
	uint16_t	curr_minor;
	int		idx;

	curr_major = vers[0].major;
	curr_minor = vers[0].minor;

	/*
	 * Walk the version array, verifying correct ordering.
	 * The array must be sorted from highest supported
	 * version to lowest supported version.
	 */
	for (idx = 0; idx < nvers; idx++) {
		if (vers[idx].major > curr_major) {
			DS_DBG(CE_NOTE, "ds_vers_isvalid: version array has "
			    " increasing major versions" DS_EOL);
			return (DS_VERS_INCREASING_MAJOR_ERR);
		}

		if (vers[idx].major < curr_major) {
			curr_major = vers[idx].major;
			curr_minor = vers[idx].minor;
			continue;
		}

		if (vers[idx].minor > curr_minor) {
			DS_DBG(CE_NOTE, "ds_vers_isvalid: version array has "
			    " increasing minor versions" DS_EOL);
			return (DS_VERS_INCREASING_MINOR_ERR);
		}

		curr_minor = vers[idx].minor;
	}

	return (DS_VERS_OK);
}

/*
 * Extended user capability init.
 */
int
ds_ucap_init(ds_capability_t *cap, ds_clnt_ops_t *ops, uint32_t flags,
    int instance, ds_svc_hdl_t *hdlp)
{
	ds_vers_check_t	status;
	ds_svc_t	*svc;
	int		rv = 0;
	ds_svc_hdl_t	lb_hdl, hdl;
	int		is_loopback;
	int		is_client;

	/* sanity check the args */
	if ((cap == NULL) || (ops == NULL)) {
		cmn_err(CE_NOTE, "%s: invalid arguments" DS_EOL, __func__);
		return (EINVAL);
	}

	/* sanity check the capability specifier */
	if ((cap->svc_id == NULL) || (cap->vers == NULL) || (cap->nvers == 0)) {
		cmn_err(CE_NOTE, "%s: invalid capability specifier" DS_EOL,
		    __func__);
		return (EINVAL);
	}

	/* sanity check the version array */
	if ((status = ds_vers_isvalid(cap->vers, cap->nvers)) != DS_VERS_OK) {
		cmn_err(CE_NOTE, "%s: invalid capability version array "
		    "for %s service: %s" DS_EOL, __func__, cap->svc_id,
		    (status == DS_VERS_INCREASING_MAJOR_ERR) ?
		    "increasing major versions" :
		    "increasing minor versions");
		return (EINVAL);
	}

	/* data and register callbacks are required */
	if ((ops->ds_data_cb == NULL) || (ops->ds_reg_cb == NULL)) {
		cmn_err(CE_NOTE, "%s: invalid ops specifier for %s service"
		    DS_EOL, __func__, cap->svc_id);
		return (EINVAL);
	}

	flags &= DSSF_USERFLAGS;
	is_client = flags & DSSF_ISCLIENT;

	DS_DBG_USR(CE_NOTE, "%s: svc_id='%s', data_cb=0x%lx, cb_arg=0x%lx"
	    DS_EOL, __func__, cap->svc_id, PTR_TO_LONG(ops->ds_data_cb),
	    PTR_TO_LONG(ops->cb_arg));

	mutex_enter(&ds_svcs.lock);

	/* check if the service is already registered */
	if (i_ds_hdl_lookup(cap->svc_id, is_client, NULL, 1) == 1) {
		/* already registered */
		DS_DBG_USR(CE_NOTE, "Service '%s'/%s already registered" DS_EOL,
		    cap->svc_id,
		    (flags & DSSF_ISCLIENT) ? "client" : "service");
		mutex_exit(&ds_svcs.lock);
		return (EALREADY);
	}

	svc = ds_alloc_svc();
	if (is_client) {
		DS_HDL_SET_ISCLIENT(svc->hdl);
	}

	svc->state = DS_SVC_FREE;
	svc->svc_hdl = DS_BADHDL1;

	svc->flags = flags;
	svc->drvi = instance;
	svc->drv_psp = NULL;

	/*
	 * Check for loopback.  "pri" is a legacy service that assumes it
	 * will never use loopback mode.
	 */
	if (strcmp(cap->svc_id, "pri") == 0) {
		is_loopback = 0;
	} else if (i_ds_hdl_lookup(cap->svc_id, is_client == 0, &lb_hdl, 1)
	    == 1) {
		if ((rv = ds_loopback_set_svc(svc, cap, &lb_hdl)) != 0) {
			DS_DBG_USR(CE_NOTE, "%s: ds_loopback_set_svc '%s' err "
			    " (%d)" DS_EOL, __func__, cap->svc_id, rv);
			mutex_exit(&ds_svcs.lock);
			return (rv);
		}
		is_loopback = 1;
	} else
		is_loopback = 0;

	/* copy over all the client information */
	(void) memcpy(&svc->cap, cap, sizeof (ds_capability_t));

	/* make a copy of the service name */
	svc->cap.svc_id = ds_strdup(cap->svc_id);

	/* make a copy of the version array */
	svc->cap.vers = DS_MALLOC(cap->nvers * sizeof (ds_ver_t));
	(void) memcpy(svc->cap.vers, cap->vers, cap->nvers * sizeof (ds_ver_t));

	/* copy the client ops vector */
	(void) memcpy(&svc->ops, ops, sizeof (ds_clnt_ops_t));

	svc->state = DS_SVC_INACTIVE;
	svc->ver_idx = 0;
	DS_PORTSET_DUP(svc->avail, ds_allports);
	DS_PORTSET_SETNULL(svc->tried);

	ds_svcs.nsvcs++;

	hdl = svc->hdl;

	/*
	 * kludge to allow user callback code to get handle and user args.
	 * Make sure the callback arg points to the svc structure.
	 */
	if ((flags & DSSF_ISUSER) != 0) {
		ds_cbarg_set_cookie(svc);
	}

	if (is_loopback) {
		ds_loopback_register(hdl);
		ds_loopback_register(lb_hdl);
	}

	/*
	 * If this is a client or a non-loopback service provider, send
	 * out register requests.
	 */
	if (!is_loopback || (flags & DSSF_ISCLIENT) != 0)
		(void) ds_svc_register(svc, NULL);

	if (hdlp) {
		*hdlp = hdl;
	}

	mutex_exit(&ds_svcs.lock);

	DS_DBG_USR(CE_NOTE, "%s: service '%s' assigned handle 0x%09lx" DS_EOL,
	    __func__, svc->cap.svc_id, hdl);

	return (0);
}

/*
 * ds_cap_init interface for previous revision.
 */
int
ds_cap_init(ds_capability_t *cap, ds_clnt_ops_t *ops)
{
	return (ds_ucap_init(cap, ops, 0, DS_INVALID_INSTANCE, NULL));
}

/*
 * Interface for ds_unreg_hdl in lds driver.
 */
int
ds_unreg_hdl(ds_svc_hdl_t hdl)
{
	ds_svc_t	*svc;
	int		is_loopback;
	ds_svc_hdl_t	lb_hdl;

	DS_DBG_USR(CE_NOTE, "%s: hdl=0x%09lx" DS_EOL, __func__, hdl);

	mutex_enter(&ds_svcs.lock);
	if ((svc = ds_get_svc(hdl)) == NULL) {
		mutex_exit(&ds_svcs.lock);
		DS_DBG_USR(CE_NOTE, "%s: unknown hdl: 0x%llx" DS_EOL, __func__,
		    (u_longlong_t)hdl);
		return (ENXIO);
	}

	DS_DBG_USR(CE_NOTE, "%s: svcid='%s', hdl=0x%llx" DS_EOL, __func__,
	    svc->cap.svc_id, (u_longlong_t)svc->hdl);

	svc->state = DS_SVC_UNREG_PENDING;

	is_loopback = ((svc->flags & DSSF_LOOPBACK) != 0);
	lb_hdl = svc->svc_hdl;

	if (svc->port) {
		(void) ds_send_unreg_req(svc);
	}

	(void) ds_svc_unregister(svc, svc->port);

	ds_delete_svc_entry(svc);

	if (is_loopback) {
		ds_loopback_unregister(lb_hdl);
	}

	mutex_exit(&ds_svcs.lock);

	return (0);
}

int
ds_cap_fini(ds_capability_t *cap)
{
	ds_svc_hdl_t	hdl;
	int rv;
	uint_t nhdls = 0;

	DS_DBG(CE_NOTE, "%s: '%s'" DS_EOL, __func__, cap->svc_id);
	if ((rv = ds_hdl_lookup(cap->svc_id, 0, &hdl, 1, &nhdls)) != 0) {
		DS_DBG(CE_NOTE, "%s: ds_hdl_lookup '%s' err (%d)" DS_EOL,
		    __func__, cap->svc_id, rv);
		return (rv);
	}

	if (nhdls == 0) {
		DS_DBG(CE_NOTE, "%s: no such service '%s'" DS_EOL,
		    __func__, cap->svc_id);
		return (ENXIO);
	}

	if ((rv = ds_is_my_hdl(hdl, DS_INVALID_INSTANCE)) != 0) {
		DS_DBG(CE_NOTE, "%s: ds_is_my_handle err (%d)" DS_EOL, __func__,
		    rv);
		return (rv);
	}

	if ((rv = ds_unreg_hdl(hdl)) != 0) {
		DS_DBG(CE_NOTE, "%s: ds_unreg_hdl err (%d)" DS_EOL, __func__,
		    rv);
		return (rv);
	}

	return (0);
}

int
ds_cap_send(ds_svc_hdl_t hdl, void *buf, size_t len)
{
	int		rv;
	ds_hdr_t	*hdr;
	caddr_t		msg;
	size_t		msglen;
	size_t		hdrlen;
	caddr_t		payload;
	ds_svc_t	*svc;
	ds_port_t	*port;
	ds_data_handle_t *data;
	ds_svc_hdl_t	svc_hdl;
	int		is_client = 0;

	DS_DBG(CE_NOTE, "%s: hdl: 0x%llx, buf: %lx, len: %ld" DS_EOL, __func__,
	    (u_longlong_t)hdl, (ulong_t)buf, len);

	mutex_enter(&ds_svcs.lock);

	if ((svc = ds_get_svc(hdl)) == NULL) {
		cmn_err(CE_WARN, "%s: invalid handle 0x%llx" DS_EOL, __func__,
		    (u_longlong_t)hdl);
		mutex_exit(&ds_svcs.lock);
		return (ENXIO);
	}

	if (svc->state != DS_SVC_ACTIVE) {
		/* channel is up, but svc is not registered */
		DS_DBG(CE_NOTE, "%s: invalid service state 0x%x" DS_EOL,
		    __func__, svc->state);
		mutex_exit(&ds_svcs.lock);
		return (ENOTCONN);
	}

	if (svc->flags & DSSF_LOOPBACK) {
		hdl = svc->svc_hdl;
		mutex_exit(&ds_svcs.lock);
		ds_loopback_send(hdl, buf, len);
		return (0);
	}

	if ((port = svc->port) == NULL) {
		DS_DBG(CE_NOTE, "%s: service '%s' not associated with a port"
		    DS_EOL, __func__, svc->cap.svc_id);
		mutex_exit(&ds_svcs.lock);
		return (ECONNRESET);
	}

	if (svc->flags & DSSF_ISCLIENT) {
		is_client = 1;
		svc_hdl = svc->svc_hdl;
	}

	mutex_exit(&ds_svcs.lock);

	/* check that the LDC channel is ready */
	if (port->ldc.state != LDC_UP) {
		DS_DBG(CE_NOTE, "%s: LDC channel is not up" DS_EOL, __func__);
		return (ECONNRESET);
	}

	hdrlen = DS_HDR_SZ + sizeof (ds_data_handle_t);

	msg = DS_MALLOC(len + hdrlen);
	hdr = (ds_hdr_t *)msg;
	payload = msg + hdrlen;
	msglen = len + hdrlen;

	hdr->payload_len = len + sizeof (ds_data_handle_t);
	hdr->msg_type = DS_DATA;

	data = (ds_data_handle_t *)(msg + DS_HDR_SZ);
	if (is_client) {
		data->svc_handle = svc_hdl;
	} else {
		data->svc_handle = hdl;
	}

	if ((buf != NULL) && (len != 0)) {
		(void) memcpy(payload, buf, len);
	}

	DS_DBG_PRCL(CE_NOTE, "ds@%lx: data>: hdl=0x%llx, len=%ld, "
	    " payload_len=%d" DS_EOL, PORTID(port), (u_longlong_t)svc->hdl,
	    msglen, hdr->payload_len);
	DS_DUMP_MSG(DS_DBG_FLAG_PRCL, msg, msglen);

	if ((rv = ds_send_msg(port, msg, msglen)) != 0) {
		rv = (rv == EIO) ? ECONNRESET : rv;
	}
	DS_FREE(msg, msglen);

	return (rv);
}

void
ds_port_common_init(ds_port_t *port)
{
	int rv;

	if ((port->flags & DS_PORT_MUTEX_INITED) == 0) {
		mutex_init(&port->lock, NULL, MUTEX_DRIVER, NULL);
		mutex_init(&port->tx_lock, NULL, MUTEX_DRIVER, NULL);
		mutex_init(&port->rcv_lock, NULL, MUTEX_DRIVER, NULL);
		port->flags |= DS_PORT_MUTEX_INITED;
	}

	port->state = DS_PORT_INIT;
	DS_PORTSET_ADD(ds_allports, port->id);

	ds_sys_port_init(port);

	mutex_enter(&port->lock);
	rv = ds_ldc_init(port);
	mutex_exit(&port->lock);

	/*
	 * If LDC successfully init'ed, try to kick off protocol for this port.
	 */
	if (rv == 0) {
		ds_handle_up_event(port);
	}
}

void
ds_port_common_fini(ds_port_t *port)
{
	ASSERT(MUTEX_HELD(&port->lock));

	port->state = DS_PORT_FREE;

	DS_PORTSET_DEL(ds_allports, port->id);

	ds_sys_port_fini(port);
}

/*
 * Initialize table of registered service classes
 */
void
ds_init_svcs_tbl(uint_t nentries)
{
	int	tblsz;

	ds_svcs.maxsvcs = nentries;

	tblsz = ds_svcs.maxsvcs * sizeof (ds_svc_t *);
	ds_svcs.tbl = (ds_svc_t **)DS_MALLOC(tblsz);

	ds_svcs.nsvcs = 0;
}

/*
 * Find the max and min version supported.
 * Hacked from zeus workspace, support.c
 */
static void
min_max_versions(int num_versions, ds_ver_t *sup_versionsp,
    uint16_t *min_major, uint16_t *max_major)
{
	int i;

	*min_major = sup_versionsp[0].major;
	*max_major = *min_major;

	for (i = 1; i < num_versions; i++) {
		if (sup_versionsp[i].major < *min_major)
			*min_major = sup_versionsp[i].major;

		if (sup_versionsp[i].major > *max_major)
			*max_major = sup_versionsp[i].major;
	}
}

/*
 * Check whether the major and minor numbers requested by the peer can be
 * satisfied. If the requested major is supported, true is returned, and the
 * agreed minor is returned in new_minor. If the requested major is not
 * supported, the routine returns false, and the closest major is returned in
 * *new_major, upon which the peer should re-negotiate. The closest major is
 * the just lower that the requested major number.
 *
 * Hacked from zeus workspace, support.c
 */
boolean_t
negotiate_version(int num_versions, ds_ver_t *sup_versionsp,
    uint16_t req_major, uint16_t *new_majorp, uint16_t *new_minorp)
{
	int i;
	uint16_t major, lower_major;
	uint16_t min_major = 0, max_major;
	boolean_t found_match = B_FALSE;

	min_max_versions(num_versions, sup_versionsp, &min_major, &max_major);

	DS_DBG(CE_NOTE, "negotiate_version: req_major = %u, min = %u, max = %u"
	    DS_EOL, req_major, min_major, max_major);

	/*
	 * If the minimum version supported is greater than
	 * the version requested, return the lowest version
	 * supported
	 */
	if (min_major > req_major) {
		*new_majorp = min_major;
		return (B_FALSE);
	}

	/*
	 * If the largest version supported is lower than
	 * the version requested, return the largest version
	 * supported
	 */
	if (max_major < req_major) {
		*new_majorp = max_major;
		return (B_FALSE);
	}

	/*
	 * Now we know that the requested version lies between the
	 * min and max versions supported. Check if the requested
	 * major can be found in supported versions.
	 */
	lower_major = min_major;
	for (i = 0; i < num_versions; i++) {
		major = sup_versionsp[i].major;
		if (major == req_major) {
			found_match = B_TRUE;
			*new_majorp = req_major;
			*new_minorp = sup_versionsp[i].minor;
			break;
		} else {
			if ((major < req_major) && (major > lower_major))
				lower_major = major;
		}
	}

	/*
	 * If no match is found, return the closest available number
	 */
	if (!found_match)
		*new_majorp = lower_major;

	return (found_match);
}

/*
 * Specific errno's that are used by ds.c and ldc.c
 */
static struct {
	int ds_errno;
	char *estr;
} ds_errno_to_str_tab[] = {
	{ EIO,		"I/O error" },
	{ ENXIO,	"No such device or address" },
	{ EAGAIN,	"Resource temporarily unavailable" },
	{ ENOMEM,	"Not enough space" },
	{ EACCES,	"Permission denied" },
	{ EFAULT,	"Bad address" },
	{ EBUSY,	"Device busy" },
	{ EINVAL,	"Invalid argument" },
	{ ENOSPC,	"No space left on device" },
	{ ENOMSG,	"No message of desired type" },
#ifdef	ECHRNG
	{ ECHRNG,	"Channel number out of range" },
#endif
	{ ENOTSUP,	"Operation not supported" },
	{ EMSGSIZE,	"Message too long" },
	{ EADDRINUSE,	"Address already in use" },
	{ ECONNRESET,	"Connection reset by peer" },
	{ ENOBUFS,	"No buffer space available" },
	{ ENOTCONN,	"Socket is not connected" },
	{ ECONNREFUSED,	"Connection refused" },
	{ EALREADY,	"Operation already in progress" },
	{ 0,		NULL },
};

char *
ds_errno_to_str(int ds_errno, char *ebuf)
{
	int i, en;

	for (i = 0; (en = ds_errno_to_str_tab[i].ds_errno) != 0; i++) {
		if (en == ds_errno) {
			(void) strcpy(ebuf, ds_errno_to_str_tab[i].estr);
			return (ebuf);
		}
	}

	(void) sprintf(ebuf, "ds_errno (%d)", ds_errno);
	return (ebuf);
}

static void
ds_loopback_register(ds_svc_hdl_t hdl)
{
	ds_ver_t ds_ver;
	ds_svc_t *svc;

	ASSERT(MUTEX_HELD(&ds_svcs.lock));
	DS_DBG_LOOP(CE_NOTE, "%s: entered hdl: 0x%llx" DS_EOL, __func__,
	    (u_longlong_t)hdl);
	if ((svc = ds_get_svc(hdl)) == NULL) {
		DS_DBG_LOOP(CE_NOTE, "%s: invalid hdl: 0x%llx" DS_EOL, __func__,
		    (u_longlong_t)hdl);
		return;
	}

	svc->state = DS_SVC_ACTIVE;

	if (svc->ops.ds_reg_cb) {
		DS_DBG_LOOP(CE_NOTE, "%s: loopback regcb: hdl: 0x%llx" DS_EOL,
		    __func__, (u_longlong_t)hdl);
		ds_ver.major = svc->ver.major;
		ds_ver.minor = svc->ver.minor;
		(*svc->ops.ds_reg_cb)(svc->ops.cb_arg, &ds_ver, hdl);
	}
}

static void
ds_loopback_unregister(ds_svc_hdl_t hdl)
{
	ds_svc_t *svc;

	ASSERT(MUTEX_HELD(&ds_svcs.lock));
	if ((svc = ds_get_svc(hdl)) == NULL) {
		DS_DBG_LOOP(CE_NOTE, "%s: invalid hdl: 0x%llx" DS_EOL, __func__,
		    (u_longlong_t)hdl);
		return;
	}

	DS_DBG_LOOP(CE_NOTE, "%s: entered hdl: 0x%llx" DS_EOL, __func__,
	    (u_longlong_t)hdl);

	svc->flags &= ~DSSF_LOOPBACK;
	svc->svc_hdl = DS_BADHDL2;
	svc->state = DS_SVC_INACTIVE;

	if (svc->ops.ds_unreg_cb) {
		DS_DBG_LOOP(CE_NOTE, "%s: loopback unregcb: hdl: 0x%llx" DS_EOL,
		    __func__, (u_longlong_t)hdl);
		(*svc->ops.ds_unreg_cb)(svc->ops.cb_arg);
	}
}

static void
ds_loopback_send(ds_svc_hdl_t hdl, void *buf, size_t buflen)
{
	ds_svc_t *svc;

	mutex_enter(&ds_svcs.lock);
	if ((svc = ds_get_svc(hdl)) == NULL) {
		mutex_exit(&ds_svcs.lock);
		DS_DBG_LOOP(CE_NOTE, "%s: invalid hdl: 0x%llx" DS_EOL, __func__,
		    (u_longlong_t)hdl);
		return;
	}
	mutex_exit(&ds_svcs.lock);

	DS_DBG_LOOP(CE_NOTE, "%s: entered hdl: 0x%llx" DS_EOL, __func__,
	    (u_longlong_t)hdl);

	if (svc->ops.ds_data_cb) {
		DS_DBG_LOOP(CE_NOTE, "%s: loopback datacb hdl: 0x%llx" DS_EOL,
		    __func__, (u_longlong_t)hdl);
		(*svc->ops.ds_data_cb)(svc->ops.cb_arg, buf, buflen);
	}
}

static int
ds_loopback_set_svc(ds_svc_t *svc, ds_capability_t *cap, ds_svc_hdl_t *lb_hdlp)
{
	ds_svc_t *lb_svc;
	ds_svc_hdl_t lb_hdl = *lb_hdlp;
	int i;
	int match = 0;
	uint16_t new_major;
	uint16_t new_minor;

	if ((lb_svc = ds_get_svc(lb_hdl)) == NULL) {
		DS_DBG_LOOP(CE_NOTE, "%s: loopback: hdl: 0x%llx invalid" DS_EOL,
		    __func__, (u_longlong_t)lb_hdl);
		return (ENXIO);
	}

	/* negotiate a version between loopback services, if possible */
	for (i = 0; i < lb_svc->cap.nvers && match == 0; i++) {
		match = negotiate_version(cap->nvers, cap->vers,
		    lb_svc->cap.vers[i].major, &new_major, &new_minor);
	}
	if (!match) {
		DS_DBG_LOOP(CE_NOTE, "%s: loopback version negotiate failed"
		    DS_EOL, __func__);
		return (ENOTSUP);
	}

	/*
	 * If a client service is not inactive, clone it.  If the service is
	 * not a client service and has a reg req pending (usually from OBP
	 * in boot state not acking/nacking reg req's), it's OK to ignore that,
	 * since there are never multiple service clients.  Also reg req pending
	 * only happens for non-client services, so it's OK to skip
	 * this block that does client service cloning.
	 */
	if (lb_svc->state != DS_SVC_INACTIVE &&
	    lb_svc->state != DS_SVC_REG_PENDING) {
		DS_DBG_LOOP(CE_NOTE, "%s: loopback active: hdl: 0x%llx"
		    DS_EOL, __func__, (u_longlong_t)lb_hdl);
		if ((lb_svc->flags & DSSF_ISCLIENT) == 0) {
			DS_DBG_LOOP(CE_NOTE, "%s: loopback busy hdl: 0x%llx"
			    DS_EOL, __func__, (u_longlong_t)lb_hdl);
			return (EBUSY);
		}
		svc->state = DS_SVC_INACTIVE;	/* prevent alloc'ing svc */
		lb_svc = ds_svc_clone(lb_svc);
		DS_DBG_LOOP(CE_NOTE, "%s: loopback clone: ohdl: 0x%llx "
		    "nhdl: 0x%llx" DS_EOL, __func__, (u_longlong_t)lb_hdl,
		    (u_longlong_t)lb_svc->hdl);
		*lb_hdlp = lb_svc->hdl;
	}

	svc->flags |= DSSF_LOOPBACK;
	svc->svc_hdl = lb_svc->hdl;
	svc->port = NULL;
	svc->ver.major = new_major;
	svc->ver.minor = new_minor;

	lb_svc->flags |= DSSF_LOOPBACK;
	lb_svc->svc_hdl = svc->hdl;
	lb_svc->port = NULL;
	lb_svc->ver.major = new_major;
	lb_svc->ver.minor = new_minor;

	DS_DBG_LOOP(CE_NOTE, "%s: setting loopback between: 0x%llx and 0x%llx"
	    DS_EOL, __func__, (u_longlong_t)svc->hdl,
	    (u_longlong_t)lb_svc->hdl);
	return (0);
}

static ds_svc_t *
ds_find_clnt_svc_by_hdl_port(ds_svc_hdl_t hdl, ds_port_t *port)
{
	int		idx;
	ds_svc_t	*svc;

	DS_DBG_PRCL(CE_NOTE, "ds@%lx: %s looking up clnt hdl: 0x%llx" DS_EOL,
	    PORTID(port), __func__, (u_longlong_t)hdl);
	ASSERT(MUTEX_HELD(&ds_svcs.lock));

	/* walk every table entry */
	for (idx = 0; idx < ds_svcs.maxsvcs; idx++) {
		svc = ds_svcs.tbl[idx];
		if (DS_SVC_ISFREE(svc))
			continue;
		if ((svc->flags & DSSF_ISCLIENT) != 0 &&
		    svc->svc_hdl == hdl && svc->port == port) {
			DS_DBG_PRCL(CE_NOTE, "ds@%lx: %s found clnt hdl "
			    "0x%llx: svc%d" DS_EOL, PORTID(port), __func__,
			    (u_longlong_t)hdl, (uint_t)DS_HDL2IDX(svc->hdl));
			return (svc);
		}
	}
	DS_DBG_PRCL(CE_NOTE, "ds@%lx: %s clnt hdl: 0x%llx not found" DS_EOL,
	    PORTID(port), __func__, (u_longlong_t)hdl);

	return (NULL);
}

static ds_svc_t *
ds_svc_clone(ds_svc_t *svc)
{
	ds_svc_t *newsvc;
	ds_svc_hdl_t hdl;

	ASSERT(svc->flags & DSSF_ISCLIENT);

	newsvc = ds_alloc_svc();

	/* Can only clone clients for now */
	hdl = newsvc->hdl | DS_HDL_ISCLIENT_BIT;
	DS_DBG_USR(CE_NOTE, "%s: cloning client: old hdl: 0x%llx new hdl: "
	    "0x%llx" DS_EOL, __func__, (u_longlong_t)svc->hdl,
	    (u_longlong_t)hdl);
	(void) memcpy(newsvc, svc, sizeof (ds_svc_t));
	newsvc->hdl = hdl;
	newsvc->flags &= ~DSSF_LOOPBACK;
	newsvc->port = NULL;
	newsvc->svc_hdl = DS_BADHDL2;
	newsvc->cap.svc_id = ds_strdup(svc->cap.svc_id);
	newsvc->cap.vers = DS_MALLOC(svc->cap.nvers * sizeof (ds_ver_t));
	(void) memcpy(newsvc->cap.vers, svc->cap.vers,
	    svc->cap.nvers * sizeof (ds_ver_t));

	/*
	 * Kludge to allow lds driver user callbacks to get access to current
	 * svc structure.  Arg could be index to svc table or some other piece
	 * of info to get to the svc table entry.
	 */
	if (newsvc->flags & DSSF_ISUSER) {
		newsvc->ops.cb_arg = (ds_cb_arg_t)(newsvc);
	}
	return (newsvc);
}

/*
 * Internal handle lookup function.
 */
static int
i_ds_hdl_lookup(char *service, uint_t is_client, ds_svc_hdl_t *hdlp,
    uint_t maxhdls)
{
	int idx;
	int nhdls = 0;
	ds_svc_t *svc;
	uint32_t client_flag = is_client ? DSSF_ISCLIENT : 0;

	ASSERT(MUTEX_HELD(&ds_svcs.lock));

	for (idx = 0; idx < ds_svcs.maxsvcs && nhdls < maxhdls; idx++) {
		svc = ds_svcs.tbl[idx];
		if (DS_SVC_ISFREE(svc))
			continue;
		if (strcmp(svc->cap.svc_id, service) == 0 &&
		    (svc->flags & DSSF_ISCLIENT) == client_flag) {
			if (hdlp != NULL && nhdls < maxhdls) {
				hdlp[nhdls] = svc->hdl;
				nhdls++;
			} else {
				nhdls++;
			}
		}
	}
	return (nhdls);
}

/*
 * Interface for ds_hdl_lookup in lds driver.
 */
int
ds_hdl_lookup(char *service, uint_t is_client, ds_svc_hdl_t *hdlp,
    uint_t maxhdls, uint_t *nhdlsp)
{
	mutex_enter(&ds_svcs.lock);
	*nhdlsp = i_ds_hdl_lookup(service, is_client, hdlp, maxhdls);
	mutex_exit(&ds_svcs.lock);
	return (0);
}

/*
 * After an UNREG REQ, check if this is a client service with multiple
 * handles.  If it is, then we can eliminate this entry.
 */
static void
ds_check_for_dup_services(ds_svc_t *svc)
{
	if ((svc->flags & DSSF_ISCLIENT) != 0 &&
	    svc->state == DS_SVC_INACTIVE &&
	    i_ds_hdl_lookup(svc->cap.svc_id, 1, NULL, 2) == 2) {
		ds_delete_svc_entry(svc);
	}
}

static void
ds_delete_svc_entry(ds_svc_t *svc)
{
	ds_svc_hdl_t tmp_hdl;

	ASSERT(MUTEX_HELD(&ds_svcs.lock));

	/*
	 * Clear out the structure, but do not deallocate the
	 * memory. It can be reused for the next registration.
	 */
	DS_FREE(svc->cap.svc_id, strlen(svc->cap.svc_id) + 1);
	DS_FREE(svc->cap.vers, svc->cap.nvers * sizeof (ds_ver_t));

	/* save the handle to prevent reuse */
	tmp_hdl = svc->hdl;
	bzero((void *)svc, sizeof (ds_svc_t));

	/* initialize for next use */
	svc->hdl = tmp_hdl;
	svc->state = DS_SVC_FREE;

	ds_svcs.nsvcs--;
}
