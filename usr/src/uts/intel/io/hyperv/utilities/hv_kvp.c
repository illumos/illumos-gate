/*
 * Copyright (c) 2014,2016 Microsoft Corp.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2017 by Delphix. All rights reserved.
 */

/*
 *	Author:	Sainath Varanasi.
 *	Date:	4/2012
 *	Email:	bsdic@microsoft.com
 */

#include <sys/param.h>
#include <sys/conf.h>
#include <sys/uio.h>
#include <sys/reboot.h>
#include <sys/lock.h>
#include <sys/poll.h>
#include <sys/proc.h>
#include <sys/un.h>
#include <sys/signal.h>
#include <sys/syslog.h>
#include <sys/systm.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/mutex.h>
#include <sys/sunddi.h>

#include <sys/hyperv.h>
#include <sys/vmbus.h>
#include "hv_utilreg.h"
#include "vmbus_icreg.h"
#include "vmbus_icvar.h"

#include "unicode.h"
#include "hv_kvp.h"

/* hv_kvp defines */
#define	BUFFERSIZE	sizeof (struct hv_kvp_msg)
#define	kvp_hdr		hdr.kvp_hdr

#define	KVP_FWVER_MAJOR		3
#define	KVP_FWVER		VMBUS_IC_VERSION(KVP_FWVER_MAJOR, 0)

#define	KVP_MSGVER_MAJOR	4
#define	KVP_MSGVER		VMBUS_IC_VERSION(KVP_MSGVER_MAJOR, 0)

#define	HV_KVP_DAEMON_TIMEOUT	5

enum kvp_debug_level {
	HV_KVP_LOG_NONE		= 0,
	HV_KVP_LOG_ERR		= 1,
	HV_KVP_LOG_INFO		= 2,
	HV_KVP_LOG_ALL
};

/*
 * hv_kvp debug log level
 */
int hv_kvp_log = HV_KVP_LOG_ERR;

#define	hv_kvp_log_error(sc, ...) do {					\
	if (hv_kvp_log >= HV_KVP_LOG_ERR)				\
		dev_err((sc)->dev, CE_WARN, __VA_ARGS__);	\
_NOTE(CONSTCOND) } while (0)

#define	hv_kvp_log_info(sc, ...) do {					\
	if (hv_kvp_log >= HV_KVP_LOG_INFO)				\
		dev_err((sc)->dev, CE_NOTE, __VA_ARGS__);	\
_NOTE(CONSTCOND) } while (0)

static void *hv_kvp_state;

/*
 * Global state to track and synchronize multiple
 * KVP transaction requests from the host.
 */
typedef struct hv_kvp_sc {
	struct vmbus_ic_softc	util_sc;
	dev_info_t		*dev;

	/*
	 * Unless specified the pending mutex should be
	 * used to alter the values of the following parameters:
	 * 1. req_in_progress
	 * 2. req_timed_out
	 */
	kmutex_t		pending_mutex;

	/* Used to sleep while waiting for a response from the daemon */
	kcondvar_t		pending_cv;

	ddi_taskq_t		*requesttq;

	/* To track if transaction is active or not */
	boolean_t		req_in_progress;
	/* Tracks if daemon did not reply back in time */
	boolean_t		req_timed_out;
	/* Tracks if daemon is serving a request currently */
	boolean_t		daemon_busy;

	/* Length of host message */
	uint32_t		host_msg_len;

	/* Host message id */
	uint64_t		host_msg_id;

	/* Current kvp message from the host */
	struct hv_kvp_msg	*host_kvp_msg;

	/* Current kvp message for daemon */
	struct hv_kvp_msg	daemon_kvp_msg;

	/* Rcv buffer for communicating with the host */
	uint8_t			*rcv_buf;

	/* Device semaphore to control communication */
	ksema_t			dev_sema;

	/* Indicates if daemon registered with driver */
	boolean_t		register_done;

	/* Character device status */
	boolean_t		dev_accessed;

	struct proc		*daemon_task;

	struct pollhead		hv_kvp_pollhead;
} hv_kvp_sc;

/* hv_kvp prototypes */
static int	hv_kvp_req_in_progress(hv_kvp_sc *sc);
static void	hv_kvp_transaction_init(hv_kvp_sc *sc, uint32_t, uint64_t,
		    uint8_t *);
static void	hv_kvp_send_msg_to_daemon(hv_kvp_sc *sc);
static void	hv_kvp_process_request(void *context);

/*
 * hv_kvp low level functions
 */

/*
 * Check if kvp transaction is in progres
 */
static int
hv_kvp_req_in_progress(hv_kvp_sc *sc)
{

	return (sc->req_in_progress);
}


/*
 * This routine is called whenever a message is received from the host
 */
static void
hv_kvp_transaction_init(hv_kvp_sc *sc, uint32_t rcv_len,
    uint64_t request_id, uint8_t *rcv_buf)
{

	/* Store all the relevant message details in the global structure */
	/* Do not need to use mutex for req_in_progress here */
	sc->req_in_progress = B_TRUE;
	sc->host_msg_len = rcv_len;
	sc->host_msg_id = request_id;
	sc->rcv_buf = rcv_buf;
	sc->host_kvp_msg = (struct hv_kvp_msg *)&rcv_buf[
	    sizeof (struct hv_vmbus_pipe_hdr) +
	    sizeof (struct hv_vmbus_icmsg_hdr)];
}

/*
 * Convert ip related info in umsg from utf8 to utf16 and store in hmsg
 */
static int
hv_kvp_convert_utf8_ipinfo_to_utf16(struct hv_kvp_msg *umsg,
    struct hv_kvp_ip_msg *host_ip_msg)
{
	int err_ip, err_subnet, err_gway, err_dns, err_adap;
	int UNUSED_FLAG = 1;

	(void) utf8_to_utf16((uint16_t *)host_ip_msg->kvp_ip_val.ip_addr,
	    MAX_IP_ADDR_SIZE,
	    (char *)umsg->body.kvp_ip_val.ip_addr,
	    strlen((char *)umsg->body.kvp_ip_val.ip_addr),
	    UNUSED_FLAG,
	    &err_ip);
	(void) utf8_to_utf16((uint16_t *)host_ip_msg->kvp_ip_val.sub_net,
	    MAX_IP_ADDR_SIZE,
	    (char *)umsg->body.kvp_ip_val.sub_net,
	    strlen((char *)umsg->body.kvp_ip_val.sub_net),
	    UNUSED_FLAG,
	    &err_subnet);
	(void) utf8_to_utf16((uint16_t *)host_ip_msg->kvp_ip_val.gate_way,
	    MAX_GATEWAY_SIZE,
	    (char *)umsg->body.kvp_ip_val.gate_way,
	    strlen((char *)umsg->body.kvp_ip_val.gate_way),
	    UNUSED_FLAG,
	    &err_gway);
	(void) utf8_to_utf16((uint16_t *)host_ip_msg->kvp_ip_val.dns_addr,
	    MAX_IP_ADDR_SIZE,
	    (char *)umsg->body.kvp_ip_val.dns_addr,
	    strlen((char *)umsg->body.kvp_ip_val.dns_addr),
	    UNUSED_FLAG,
	    &err_dns);
	(void) utf8_to_utf16((uint16_t *)host_ip_msg->kvp_ip_val.adapter_id,
	    MAX_IP_ADDR_SIZE,
	    (char *)umsg->body.kvp_ip_val.adapter_id,
	    strlen((char *)umsg->body.kvp_ip_val.adapter_id),
	    UNUSED_FLAG,
	    &err_adap);

	host_ip_msg->kvp_ip_val.dhcp_enabled =
	    umsg->body.kvp_ip_val.dhcp_enabled;
	host_ip_msg->kvp_ip_val.addr_family = umsg->body.kvp_ip_val.addr_family;

	return (err_ip | err_subnet | err_gway | err_dns | err_adap);
}

/*
 * If the umsg's adapter_id is set to a vmbus networking device, replace the
 * adapter GUID with its driver binding name.
 */
static int
hv_kvp_walk_netdevs_cb(dev_info_t *dev, void *arg)
{
	char *classid;
	struct hv_kvp_msg *umsg = arg;

	if (strncmp(ddi_get_name(dev), "hv_netvsc", sizeof ("hv_netvsc")) != 0)
		return (DDI_WALK_CONTINUE);

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dev, 0, VMBUS_CLASSID,
	    &classid) != DDI_PROP_SUCCESS)
		return (DDI_WALK_CONTINUE);
	/*
	 * The string in the 'kvp_ip_val.adapter_id' has
	 * braces around the GUID; skip the leading brace
	 * in 'kvp_ip_val.adapter_id'.
	 */
	if (strncmp(classid, ((char *)&umsg->body.kvp_ip_val.adapter_id) + 1,
	    HYPERV_GUID_STRLEN) == 0) {
		(void) strlcpy((char *)umsg->body.kvp_ip_val.adapter_id,
		    ddi_get_name(dev), MAX_ADAPTER_ID_SIZE);

		ddi_prop_free(classid);
		return (DDI_WALK_TERMINATE);
	}

	ddi_prop_free(classid);
	return (DDI_WALK_CONTINUE);
}

/*
 * Convert ip related info in hmsg from utf16 to utf8 and store in umsg
 */
static int
hv_kvp_convert_utf16_ipinfo_to_utf8(struct hv_kvp_ip_msg *host_ip_msg,
    struct hv_kvp_msg *umsg)
{
	int err_ip, err_subnet, err_gway, err_dns, err_adap;
	int UNUSED_FLAG = 1;

	/* IP Address */
	(void) utf16_to_utf8((char *)umsg->body.kvp_ip_val.ip_addr,
	    MAX_IP_ADDR_SIZE,
	    (uint16_t *)host_ip_msg->kvp_ip_val.ip_addr,
	    MAX_IP_ADDR_SIZE,
	    UNUSED_FLAG,
	    &err_ip);

	/* Adapter ID : GUID */
	(void) utf16_to_utf8((char *)umsg->body.kvp_ip_val.adapter_id,
	    MAX_ADAPTER_ID_SIZE,
	    (uint16_t *)host_ip_msg->kvp_ip_val.adapter_id,
	    MAX_ADAPTER_ID_SIZE,
	    UNUSED_FLAG,
	    &err_adap);

	/*
	 * Replace the Adapter ID GUID if the adapter is a vmbus networking
	 * device.
	 */
	vmbus_walk_children(&hv_kvp_walk_netdevs_cb, umsg);

	/* Address Family , DHCP , SUBNET, Gateway, DNS */
	umsg->kvp_hdr.operation = host_ip_msg->operation;
	umsg->body.kvp_ip_val.addr_family = host_ip_msg->kvp_ip_val.addr_family;
	umsg->body.kvp_ip_val.dhcp_enabled =
	    host_ip_msg->kvp_ip_val.dhcp_enabled;
	(void) utf16_to_utf8((char *)umsg->body.kvp_ip_val.sub_net,
	    MAX_IP_ADDR_SIZE, (uint16_t *)host_ip_msg->kvp_ip_val.sub_net,
	    MAX_IP_ADDR_SIZE,
	    UNUSED_FLAG,
	    &err_subnet);

	(void) utf16_to_utf8((char *)umsg->body.kvp_ip_val.gate_way,
	    MAX_GATEWAY_SIZE, (uint16_t *)host_ip_msg->kvp_ip_val.gate_way,
	    MAX_GATEWAY_SIZE,
	    UNUSED_FLAG,
	    &err_gway);

	(void) utf16_to_utf8((char *)umsg->body.kvp_ip_val.dns_addr,
	    MAX_IP_ADDR_SIZE, (uint16_t *)host_ip_msg->kvp_ip_val.dns_addr,
	    MAX_IP_ADDR_SIZE,
	    UNUSED_FLAG,
	    &err_dns);

	return (err_ip | err_subnet | err_gway | err_dns | err_adap);
}


/*
 * Prepare a user kvp msg based on host kvp msg (utf16 to utf8)
 * Ensure utf16_utf8 takes care of the additional string terminating char!!
 */
static int
hv_kvp_convert_hostmsg_to_usermsg(struct hv_kvp_msg *hmsg,
    struct hv_kvp_msg *umsg)
{
	int utf_err = 0;
	uint32_t value_type;
	char *umsg_value;
	struct hv_kvp_ip_msg *host_ip_msg;

	host_ip_msg = (struct hv_kvp_ip_msg *)hmsg;
	(void) memset(umsg, 0, sizeof (struct hv_kvp_msg));

	umsg->kvp_hdr.operation = hmsg->kvp_hdr.operation;
	umsg->kvp_hdr.pool = hmsg->kvp_hdr.pool;

	switch (umsg->kvp_hdr.operation) {
	case HV_KVP_OP_SET_IP_INFO:
		(void) hv_kvp_convert_utf16_ipinfo_to_utf8(host_ip_msg, umsg);
		break;

	case HV_KVP_OP_GET_IP_INFO:
		(void) utf16_to_utf8((char *)umsg->body.kvp_ip_val.adapter_id,
		    MAX_ADAPTER_ID_SIZE,
		    (uint16_t *)host_ip_msg->kvp_ip_val.adapter_id,
		    MAX_ADAPTER_ID_SIZE, 1, &utf_err);

		umsg->body.kvp_ip_val.addr_family =
		    host_ip_msg->kvp_ip_val.addr_family;
		break;

	case HV_KVP_OP_SET:
		value_type = hmsg->body.kvp_set.data.value_type;
		umsg_value = (char *)umsg->body.kvp_set.data.msg_value.value;

		switch (value_type) {
		case HV_REG_SZ:
			umsg->body.kvp_set.data.value_size =
			    utf16_to_utf8(umsg_value,
			    HV_KVP_EXCHANGE_MAX_VALUE_SIZE - 1,
			    (uint16_t *)hmsg->body.kvp_set.data.msg_value.value,
			    hmsg->body.kvp_set.data.value_size, 1, &utf_err);
			/* utf8 encoding */
			umsg->body.kvp_set.data.value_size =
			    umsg->body.kvp_set.data.value_size / 2;
			break;

		case HV_REG_U32:
			umsg->body.kvp_set.data.value_size =
			    snprintf(umsg_value, HV_KVP_EXCHANGE_MAX_VALUE_SIZE,
			    "%lu", (unsigned long)
			    hmsg->body.kvp_set.data.msg_value.value_u32) + 1;
			break;

		case HV_REG_U64:
			umsg->body.kvp_set.data.value_size =
			    snprintf(umsg_value, HV_KVP_EXCHANGE_MAX_VALUE_SIZE,
			    "%llu", (unsigned long long)
			    hmsg->body.kvp_set.data.msg_value.value_u64) + 1;
			break;
		}

		umsg->body.kvp_set.data.key_size =
		    utf16_to_utf8((char *)umsg->body.kvp_set.data.key,
		    HV_KVP_EXCHANGE_MAX_KEY_SIZE - 1,
		    (uint16_t *)hmsg->body.kvp_set.data.key,
		    hmsg->body.kvp_set.data.key_size, 1, &utf_err);

		/* utf8 encoding */
		umsg->body.kvp_set.data.key_size =
		    umsg->body.kvp_set.data.key_size / 2;
		break;

	case HV_KVP_OP_GET:
		umsg->body.kvp_get.data.key_size =
		    utf16_to_utf8((char *)umsg->body.kvp_get.data.key,
		    HV_KVP_EXCHANGE_MAX_KEY_SIZE - 1,
		    (uint16_t *)hmsg->body.kvp_get.data.key,
		    hmsg->body.kvp_get.data.key_size, 1, &utf_err);
		/* utf8 encoding */
		umsg->body.kvp_get.data.key_size =
		    umsg->body.kvp_get.data.key_size / 2;
		break;

	case HV_KVP_OP_DELETE:
		umsg->body.kvp_delete.key_size =
		    utf16_to_utf8((char *)umsg->body.kvp_delete.key,
		    HV_KVP_EXCHANGE_MAX_KEY_SIZE - 1,
		    (uint16_t *)hmsg->body.kvp_delete.key,
		    hmsg->body.kvp_delete.key_size, 1, &utf_err);
		/* utf8 encoding */
		umsg->body.kvp_delete.key_size =
		    umsg->body.kvp_delete.key_size / 2;
		break;

	case HV_KVP_OP_ENUMERATE:
		umsg->body.kvp_enum_data.index =
		    hmsg->body.kvp_enum_data.index;
		break;

	default:
		return (EINVAL);
	}

	return (0);
}


/*
 * Prepare a host kvp msg based on user kvp msg (utf8 to utf16)
 */
static int
hv_kvp_convert_usermsg_to_hostmsg(struct hv_kvp_msg *umsg,
    struct hv_kvp_msg *hmsg)
{
	int hkey_len = 0, hvalue_len = 0, utf_err = 0;
	struct hv_kvp_exchg_msg_value *host_exchg_data;
	char *key_name, *value;

	struct hv_kvp_ip_msg *host_ip_msg = (struct hv_kvp_ip_msg *)hmsg;

	switch (hmsg->kvp_hdr.operation) {
	case HV_KVP_OP_GET_IP_INFO:
		return (hv_kvp_convert_utf8_ipinfo_to_utf16(umsg, host_ip_msg));

	case HV_KVP_OP_SET_IP_INFO:
	case HV_KVP_OP_SET:
	case HV_KVP_OP_DELETE:
		return (0);

	case HV_KVP_OP_ENUMERATE:
		host_exchg_data = &hmsg->body.kvp_enum_data.data;
		key_name = (char *)umsg->body.kvp_enum_data.data.key;
		hkey_len = utf8_to_utf16((uint16_t *)host_exchg_data->key,
		    ((HV_KVP_EXCHANGE_MAX_KEY_SIZE / 2) - 2),
		    key_name, strlen(key_name), 1, &utf_err);
		/* utf16 encoding */
		host_exchg_data->key_size = 2 * (hkey_len + 1);
		value = (char *)umsg->body.kvp_enum_data.data.msg_value.value;
		hvalue_len = utf8_to_utf16(
		    (uint16_t *)host_exchg_data->msg_value.value,
		    ((HV_KVP_EXCHANGE_MAX_VALUE_SIZE / 2) - 2),
		    value, strlen(value), 1, &utf_err);
		host_exchg_data->value_size = 2 * (hvalue_len + 1);
		host_exchg_data->value_type = HV_REG_SZ;

		if (hvalue_len < 0)
			return (EINVAL);

		return (0);

	case HV_KVP_OP_GET:
		host_exchg_data = &hmsg->body.kvp_get.data;
		value = (char *)umsg->body.kvp_get.data.msg_value.value;
		hvalue_len = utf8_to_utf16(
		    (uint16_t *)host_exchg_data->msg_value.value,
		    ((HV_KVP_EXCHANGE_MAX_VALUE_SIZE / 2) - 2),
		    value, strlen(value), 1, &utf_err);
		/* Convert value size to uft16 */
		host_exchg_data->value_size = 2 * (hvalue_len + 1);
		/* Use values by string */
		host_exchg_data->value_type = HV_REG_SZ;

		if ((hkey_len < 0) || (hvalue_len < 0))
			return (EINVAL);

		return (0);

	default:
		return (EINVAL);
	}
}


/*
 * Send the response back to the host.
 */
static void
hv_kvp_respond_host(hv_kvp_sc *sc, uint32_t error)
{
	struct hv_vmbus_icmsg_hdr *hv_icmsg_hdrp;

	hv_icmsg_hdrp = (struct hv_vmbus_icmsg_hdr *)
	    &sc->rcv_buf[sizeof (struct hv_vmbus_pipe_hdr)];

	hv_icmsg_hdrp->status = error;
	hv_icmsg_hdrp->icflags = HV_ICMSGHDRFLAG_TRANSACTION |
	    HV_ICMSGHDRFLAG_RESPONSE;

	error = vmbus_chan_send(vmbus_get_channel(sc->dev),
	    VMBUS_CHANPKT_TYPE_INBAND, 0, sc->rcv_buf, sc->host_msg_len,
	    sc->host_msg_id);
	if (error)
		hv_kvp_log_info(sc,
		    "%s: hv_kvp_respond_host: sendpacket error:%d",
		    __func__, error);
}


/*
 * This is the main kvp kernel process that interacts with both user daemon
 * and the host
 */
static void
hv_kvp_send_msg_to_daemon(hv_kvp_sc *sc)
{
	struct hv_kvp_msg *hmsg = sc->host_kvp_msg;
	struct hv_kvp_msg *umsg = &sc->daemon_kvp_msg;

	/* Prepare kvp_msg to be sent to user */
	if (hv_kvp_convert_hostmsg_to_usermsg(hmsg, umsg) != 0) {
		hv_kvp_log_info(sc,
		    "%s: daemon_kvp_msg: Invalid operation : %d",
		    __func__, umsg->kvp_hdr.operation);
	}

	/* Send the msg to user via function deamon_read - setting sema */
	sema_v(&sc->dev_sema);

	/* We should wake up the daemon, in case it's doing poll() */
	pollwakeup(&sc->hv_kvp_pollhead, POLLIN);
}


/*
 * Function to read the kvp request buffer from host
 * and interact with daemon
 */
static void
hv_kvp_process_request(void *context)
{
	uint8_t *kvp_buf;
	struct vmbus_channel *channel;
	int recvlen = 0;
	uint64_t requestid;
	struct hv_vmbus_icmsg_hdr *icmsghdrp;
	int ret = 0, error;
	hv_kvp_sc *sc = (hv_kvp_sc*)context;

	hv_kvp_log_info(sc, "%s: entering hv_kvp_process_request", __func__);

	kvp_buf = sc->util_sc.ic_buf;
	channel = vmbus_get_channel(sc->dev);

	recvlen = sc->util_sc.ic_buflen;
	ret = vmbus_chan_recv(channel, kvp_buf, &recvlen, &requestid);
	/*
	 * hvkvp recvbuf must be large enough
	 */
	ASSERT3S(ret, !=, ENOBUFS);
	/* XXX check recvlen to make sure that it contains enough data */

	while ((ret == 0) && (recvlen > 0)) {
		icmsghdrp = (struct hv_vmbus_icmsg_hdr *)
		    &kvp_buf[sizeof (struct hv_vmbus_pipe_hdr)];

		hv_kvp_transaction_init(sc, recvlen, requestid, kvp_buf);
		if (icmsghdrp->icmsgtype == HV_ICMSGTYPE_NEGOTIATE) {
			error = vmbus_ic_negomsg(&sc->util_sc,
			    kvp_buf, &recvlen, KVP_FWVER, KVP_MSGVER);
			/* XXX handle vmbus_ic_negomsg failure. */
			if (!error)
				hv_kvp_respond_host(sc, HV_S_OK);
			else
				hv_kvp_respond_host(sc, HV_E_FAIL);
			/*
			 * It is ok to not acquire the mutex before setting
			 * req_in_progress here because negotiation is the
			 * first thing that happens and hence there is no
			 * chance of a race condition.
			 */

			sc->req_in_progress = B_FALSE;
			hv_kvp_log_info(sc, "%s :version negotiated",
			    __func__);

		} else {
			if (!sc->daemon_busy) {

				hv_kvp_log_info(sc,
				    "%s: issuing query to daemon", __func__);
				mutex_enter(&sc->pending_mutex);
				sc->req_timed_out = B_FALSE;
				sc->daemon_busy = B_TRUE;
				mutex_exit(&sc->pending_mutex);

				hv_kvp_send_msg_to_daemon(sc);
				hv_kvp_log_info(sc,
				    "%s: waiting for daemon", __func__);
			}

			/* Wait 5 seconds for daemon to respond back */
			mutex_enter(&sc->pending_mutex);
			while (sc->daemon_busy) {
				(void) cv_reltimedwait(&sc->pending_cv,
				    &sc->pending_mutex,
				    SEC_TO_TICK(HV_KVP_DAEMON_TIMEOUT),
				    TR_CLOCK_TICK);
			}
			mutex_exit(&sc->pending_mutex);
			hv_kvp_log_info(sc, "%s: came out of wait", __func__);
		}

		mutex_enter(&sc->pending_mutex);

		/*
		 * Notice that once req_timed_out is set to true
		 * it will remain true until the next request is
		 * sent to the daemon. The response from daemon
		 * is forwarded to host only when this flag is
		 * false.
		 */
		sc->req_timed_out = B_TRUE;

		/*
		 * Cancel request if so need be.
		 */
		if (hv_kvp_req_in_progress(sc)) {
			hv_kvp_log_info(sc, "%s: request was still active "
			    "after wait so failing", __func__);
			hv_kvp_respond_host(sc, HV_E_FAIL);
			sc->req_in_progress = B_FALSE;
		}

		mutex_exit(&sc->pending_mutex);

		/*
		 * Try reading next buffer
		 */
		recvlen = sc->util_sc.ic_buflen;
		ret = vmbus_chan_recv(channel, kvp_buf, &recvlen, &requestid);
		/*
		 * KVP recvbuf must be large enough
		 */
		ASSERT3S(ret, !=, ENOBUFS);
		/* XXX check recvlen contains enough data */

		hv_kvp_log_info(sc, "%s: read: context %p, ret =%d, "
		    "recvlen=%d", __func__, context, ret, recvlen);
	}
}


/*
 * Callback routine that gets called whenever there is a message from host
 */
/* ARGSUSED */
static void
hv_kvp_callback(struct vmbus_channel *chan, void *context)
{
	hv_kvp_sc *sc = (hv_kvp_sc*)context;
	/*
	 * The first request from host will not be handled until daemon is
	 * registered.  when callback is triggered without a registered daemon,
	 * callback just return.  When a new daemon gets registered, this
	 * callback is trigged from _write op.
	 */
	if (sc->register_done) {
		hv_kvp_log_info(sc, "%s: Queuing work item", __func__);
		(void) ddi_taskq_dispatch(sc->requesttq,
		    hv_kvp_process_request, sc, DDI_SLEEP);
	}
}

/* ARGSUSED */
static int
hv_kvp_dev_open(dev_t *devp, int oflags, int devtype, cred_t *cred)
{
	hv_kvp_sc *sc = ddi_get_soft_state(hv_kvp_state, getminor(*devp));

	hv_kvp_log_info(sc, "%s: Opened device \"hv_kvp_device\" "
	    "successfully.", __func__);
	if (sc->dev_accessed)
		return (EBUSY);

	sc->daemon_task = curproc;
	sc->dev_accessed = B_TRUE;
	sc->daemon_busy = B_FALSE;
	return (0);
}


/* ARGSUSED */
static int
hv_kvp_dev_close(dev_t dev, int fflag, int otype, cred_t *cred)
{
	hv_kvp_sc *sc = ddi_get_soft_state(hv_kvp_state, getminor(dev));

	hv_kvp_log_info(sc, "%s: Closing device \"hv_kvp_device\".",
	    __func__);
	sc->dev_accessed = B_FALSE;
	sc->register_done = B_FALSE;
	return (0);
}


/*
 * hv_kvp_daemon read invokes this function
 * acts as a send to daemon
 */
/* ARGSUSED */
static int
hv_kvp_dev_daemon_read(dev_t dev, struct uio *uio, cred_t *cred)
{
	size_t amt;
	int error = 0;
	struct hv_kvp_msg *hv_kvp_dev_buf;
	hv_kvp_sc *sc = ddi_get_soft_state(hv_kvp_state, getminor(dev));

	/* Read is not allowed util registering is done. */
	if (!sc->register_done)
		return (EPERM);

	sema_p(&sc->dev_sema);

	hv_kvp_dev_buf = kmem_zalloc(sizeof (struct hv_kvp_msg), KM_SLEEP);
	(void) memcpy(hv_kvp_dev_buf, &sc->daemon_kvp_msg,
	    sizeof (struct hv_kvp_msg));

	amt = MIN(uio->uio_resid, uio->uio_offset >= BUFFERSIZE + 1 ? 0 :
	    BUFFERSIZE + 1 - uio->uio_offset);

	if ((error = uiomove(hv_kvp_dev_buf, amt, UIO_READ, uio)) != 0) {
		hv_kvp_log_info(sc, "%s: hv_kvp uiomove read failed!",
		    __func__);
	}

	kmem_free(hv_kvp_dev_buf, sizeof (struct hv_kvp_msg));
	return (error);
}


/*
 * hv_kvp_daemon write invokes this function
 * acts as a receive from daemon
 */
/* ARGSUSED */
static int
hv_kvp_dev_daemon_write(dev_t dev, struct uio *uio, cred_t *cred)
{
	size_t amt;
	int error = 0;
	struct hv_kvp_msg *hv_kvp_dev_buf;
	hv_kvp_sc *sc = ddi_get_soft_state(hv_kvp_state, getminor(dev));

	uio->uio_offset = 0;
	hv_kvp_dev_buf = kmem_zalloc(sizeof (struct hv_kvp_msg), KM_SLEEP);

	amt = MIN(uio->uio_resid, BUFFERSIZE);
	error = uiomove(hv_kvp_dev_buf, amt, UIO_WRITE, uio);

	if (error != 0) {
		kmem_free(hv_kvp_dev_buf, sizeof (struct hv_kvp_msg));
		return (error);
	}
	(void) memcpy(&sc->daemon_kvp_msg, hv_kvp_dev_buf,
	    sizeof (struct hv_kvp_msg));

	kmem_free(hv_kvp_dev_buf, sizeof (struct hv_kvp_msg));
	if (sc->register_done == B_FALSE) {
		if (sc->daemon_kvp_msg.kvp_hdr.operation ==
		    HV_KVP_OP_REGISTER) {
			sc->register_done = B_TRUE;
			hv_kvp_callback(vmbus_get_channel(sc->dev), sc);
		} else {
			hv_kvp_log_info(sc, "%s, KVP Registration Failed",
			    __func__);
			return (EINVAL);
		}
	} else {

		mutex_enter(&sc->pending_mutex);

		if (!sc->req_timed_out) {
			struct hv_kvp_msg *hmsg = sc->host_kvp_msg;
			struct hv_kvp_msg *umsg = &sc->daemon_kvp_msg;

			error = hv_kvp_convert_usermsg_to_hostmsg(umsg, hmsg);
			hv_kvp_respond_host(sc, umsg->hdr.error);
			cv_broadcast(&sc->pending_cv);
			sc->req_in_progress = B_FALSE;
			if (umsg->hdr.error != HV_S_OK)
				hv_kvp_log_info(sc,
				    "%s, Error 0x%x from daemon",
				    __func__, umsg->hdr.error);
			if (error)
				hv_kvp_log_info(sc, "%s, Error from convert",
				    __func__);
		}

		sc->daemon_busy = B_FALSE;
		mutex_exit(&sc->pending_mutex);
	}

	return (error);
}


/*
 * hv_kvp_daemon poll invokes this function to check if data is available
 * for daemon to read.
 */
/* ARGSUSED */
static int
hv_kvp_dev_daemon_poll(dev_t dev, short events, int anyyet, short *reventsp,
    struct pollhead **phpp)
{
	hv_kvp_sc *sc = ddi_get_soft_state(hv_kvp_state, getminor(dev));

	mutex_enter(&sc->pending_mutex);
	/*
	 * We check global flag daemon_busy for the data availiability for
	 * userland to read. Deamon_busy is set to true before driver has data
	 * for daemon to read. It is set to false after daemon sends
	 * then response back to driver.
	 */
	if (sc->daemon_busy == B_TRUE) {
		*reventsp = POLLIN;
	} else {
		*reventsp = 0;
		if (!anyyet)
			*phpp = &sc->hv_kvp_pollhead;
	}

	mutex_exit(&sc->pending_mutex);

	return (0);
}

static int
hv_kvp_attach(dev_info_t *dev, ddi_attach_cmd_t cmd)
{
	int error;
	int instance = ddi_get_instance(dev);

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	/* create character device */
	if (ddi_create_minor_node(dev, HV_KVP_MINOR_NAME, S_IFCHR, instance,
	    DDI_PSEUDO, 0) == DDI_FAILURE) {
		ddi_remove_minor_node(dev, NULL);
		return (DDI_FAILURE);
	}

	if ((error = ddi_soft_state_zalloc(hv_kvp_state, instance)) !=
	    DDI_SUCCESS) {
		ddi_remove_minor_node(dev, NULL);
		return (error);
	}

	hv_kvp_sc *sc = ddi_get_soft_state(hv_kvp_state, instance);

	sc->dev = dev;
	sema_init(&sc->dev_sema, 0, "hv_kvp device semaphore", SEMA_DRIVER,
	    NULL);
	mutex_init(&sc->pending_mutex, "hv_kvp pending mutex", MUTEX_DRIVER,
	    NULL);
	cv_init(&sc->pending_cv, "hv_kvp pending condvar", CV_DRIVER, NULL);

	sc->requesttq = ddi_taskq_create(sc->dev, "kvp request", 1,
	    TASKQ_DEFAULTPRI, 0);

	if (sc->requesttq == NULL) {
		ddi_soft_state_free(hv_kvp_state, instance);
		ddi_remove_minor_node(dev, NULL);
		return (error);
	}

	error = vmbus_ic_attach(dev, hv_kvp_callback, &sc->util_sc);
	if (error != 0) {
		ddi_soft_state_free(hv_kvp_state, instance);
		ddi_remove_minor_node(dev, NULL);
		ddi_taskq_destroy(sc->requesttq);
	}

	return (error);
}

static int
hv_kvp_detach(dev_info_t *dev, ddi_detach_cmd_t cmd)
{
	int error;
	int instance = ddi_get_instance(dev);
	hv_kvp_sc *sc = ddi_get_soft_state(hv_kvp_state, instance);

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	error = vmbus_ic_detach(dev, &sc->util_sc);
	if (error != 0) {
		hv_kvp_log_error(sc, "detatch failed, error: %d", error);
		return (error);
	}

	if (sc->daemon_task != NULL)
		psignal(sc->daemon_task, SIGKILL);

	if (sc->requesttq != NULL)
		ddi_taskq_destroy(sc->requesttq);

	ddi_soft_state_free(hv_kvp_state, instance);
	ddi_remove_minor_node(dev, HV_KVP_MINOR_NAME);

	return (DDI_SUCCESS);
}

static struct cb_ops hv_kvp_cb_ops = {
	.cb_open =	hv_kvp_dev_open,
	.cb_close =	hv_kvp_dev_close,
	.cb_strategy =	nodev,
	.cb_print =	nodev,
	.cb_dump =	nodev,
	.cb_read =	hv_kvp_dev_daemon_read,
	.cb_write =	hv_kvp_dev_daemon_write,
	.cb_ioctl =	nodev,
	.cb_devmap =	nodev,
	.cb_mmap =	nodev,
	.cb_segmap =	nodev,
	.cb_chpoll =	hv_kvp_dev_daemon_poll,
	.cb_prop_op =	ddi_prop_op,
	.cb_str =	NULL,
	.cb_flag =	D_NEW | D_MP
};

static struct dev_ops hv_kvp_dev_ops = {
	.devo_rev =		DEVO_REV,
	.devo_refcnt =		0,
	.devo_getinfo =		ddi_getinfo_1to1,
	.devo_identify =	nulldev,
	.devo_probe =		nulldev,
	.devo_attach =		hv_kvp_attach,
	.devo_detach =		hv_kvp_detach,
	.devo_reset =		nodev,
	.devo_cb_ops =		&hv_kvp_cb_ops,
	.devo_bus_ops =		NULL,
	.devo_power =		NULL,
	.devo_quiesce =		ddi_quiesce_not_needed,
};

extern struct mod_ops mod_driverops;

static struct modldrv hv_kvp_modldrv = {
	&mod_driverops,
	"Hyper-V KVP Driver",
	&hv_kvp_dev_ops,
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&hv_kvp_modldrv,
	NULL
};

int
_init(void)
{
	int error;

	if ((error = ddi_soft_state_init(&hv_kvp_state,
	    sizeof (struct hv_kvp_sc), 0)) != 0)
		return (error);

	if ((error = mod_install(&modlinkage)) != 0)
		ddi_soft_state_fini(&hv_kvp_state);

	return (error);
}

int
_fini(void)
{
	int error;

	if ((error = mod_remove(&modlinkage)) == 0)
		ddi_soft_state_fini(&hv_kvp_state);

	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
