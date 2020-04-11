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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * WARNING: The contents of this file are shared by all projects
 * that  wish to  perform  remote  Dynamic Reconfiguration  (DR)
 * operations. Copies of this file can be found in the following
 * locations:
 *
 *	Project	    Location
 *	-------	    --------
 *	Solaris	    usr/src/cmd/dcs/sparc/sun4u/%M%
 *	SMS	    src/sms/lib/librdr/%M%
 *
 * In order for proper communication to occur,  the files in the
 * above locations must match exactly. Any changes that are made
 * to this file should  be made to all of the files in the list.
 */

/*
 * This file is a module that contains an interface for performing
 * remote Dynamic Reconfiguration (DR) operations. It hides all
 * network operations such as establishing a connection, sending
 * and receiving messages, and closing a connection. It also handles
 * the packing and unpacking of messages for network transport.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <dlfcn.h>
#include <netdb.h>
#include <libdscp.h>
#include <sys/socket.h>
#include <sys/systeminfo.h>
#include <netinet/tcp.h>

#include "dcs.h"
#include "remote_cfg.h"
#include "rdr_param_types.h"
#include "rdr_messages.h"


/*
 * Structure holding information about
 * all possible variable length fields
 * that can be present in an RDR message.
 */
typedef struct {
	int	ap_id_int_size;
	int	ap_id_char_size;
	int	*ap_id_sizes;
	char	*ap_id_chars;
	int	errstring_strlen;
	int	errstring_pad_sz;
	int	options_strlen;
	int	options_pad_sz;
	int	listopts_strlen;
	int	listopts_pad_sz;
	int	function_strlen;
	int	function_pad_sz;
} rdr_variable_message_info_t;

/*
 * A table of maximum sizes for each message type. Message size is
 * validated when the message header is first received. This prevents
 * a situation where a corrupted or bad header can cause too much
 * memory to be allocated.
 *
 * The message size limits were chosen to be a very generous upper bound
 * on the amount of data each message can send. They are not intended to
 * be a precise measurement of the data size.
 */
#define	NOMSG		0
#define	SHORTMSG	(150 * 1024)		/* 150 KB */
#define	LONGMSG		(3 * 1024 * 1024)	/* 3 MB */

struct {
	ulong_t	req_max;
	ulong_t	reply_max;
} msg_sizes[] = {
	/*
	 * request	reply
	 * -------	-----
	 */
	{  NOMSG,	NOMSG	  },	/*  Invalid Opcode		*/
	{  SHORTMSG,	SHORTMSG  },	/*  RDR_SES_REQ			*/
	{  NOMSG,	NOMSG	  },	/*  RDR_SES_ESTBL		*/
	{  NOMSG,	NOMSG	  },	/*  RDR_SES_END			*/
	{  SHORTMSG,	SHORTMSG  },	/*  RDR_CONF_CHANGE_STATE	*/
	{  SHORTMSG,	SHORTMSG  },	/*  RDR_CONF_PRIVATE_FUNC	*/
	{  SHORTMSG,	SHORTMSG  },	/*  RDR_CONF_TEST		*/
	{  SHORTMSG,	LONGMSG	  },	/*  RDR_CONF_LIST_EXT		*/
	{  SHORTMSG,	NOMSG	  },	/*  RDR_CONF_HELP		*/
	{  SHORTMSG,	NOMSG	  },	/*  RDR_CONF_AP_ID_CMP		*/
	{  SHORTMSG,	NOMSG	  },	/*  RDR_CONF_ABORT_CMD		*/
	{  SHORTMSG,	SHORTMSG  },	/*  RDR_CONF_CONFIRM_CALLBACK	*/
	{  SHORTMSG,	NOMSG	  },	/*  RDR_CONF_MSG_CALLBACK	*/
	{  SHORTMSG,	LONGMSG	  }	/*  RDR_RSRC_INFO		*/
};


#define	RDR_BAD_FD		(-1)

#define	RDR_MSG_HDR_SIZE	sizeof (rdr_msg_hdr_t)

static const int RDR_ALIGN_64_BIT = 8;   /* 8 bytes */

/*
 * Interfaces for dynamic use of libdscp.
 */

#define	LIBDSCP_PATH	"/usr/platform/%s/lib/libdscp.so.1"

#define	LIBDSCP_BIND	"dscpBind"
#define	LIBDSCP_SECURE	"dscpSecure"
#define	LIBDSCP_AUTH	"dscpAuth"

typedef enum {
	LIBDSCP_UNKNOWN = 0,
	LIBDSCP_AVAILABLE,
	LIBDSCP_UNAVAILABLE
} dscp_status_t;

typedef struct {
	dscp_status_t	status;
	int		(*bind)(int, int, int);
	int		(*secure)(int, int);
	int		(*auth)(int, struct sockaddr *, int);
} libdscp_t;

static libdscp_t libdscp;

/*
 * Static Function Declarations
 */

/*
 * Socket Related Routines
 */
static int rdr_setopt(int fd, int name, int level);

static int rdr_bind(int fd, struct sockaddr *addr);

static int rdr_secure(int fd, struct sockaddr *addr);

static int rdr_auth(struct sockaddr *addr, int len);

static int rdr_snd(int fd, rdr_msg_hdr_t *hdr, char *data, int data_sz,
			int timeout);
static int rdr_snd_raw(int fd, char *msg, int data_sz, int timeout);

static int rdr_rcv(int fd, rdr_msg_hdr_t *hdr, char **data, int timeout);

static int rdr_rcv_raw(int fd, char *msg, int data_size, int timeout);

/*
 * Data Validation Routines
 */
static int validate_header(rdr_msg_hdr_t *hdr);


/*
 * Session Request Routines
 */
static int pack_ses_req_request(ses_req_params_t *params, char **buf,
			int *buf_size);
static int unpack_ses_req_request(ses_req_params_t *params, const char *buf);

static int pack_ses_req_reply(ses_req_params_t *params, char **buf,
			int *buf_size);
static int unpack_ses_req_reply(ses_req_params_t *params, const char *buf);


/*
 * Change State Routines
 */
static int pack_change_state_request(change_state_params_t *params,
			char **buf, int *buf_size);
static int unpack_change_state_request(change_state_params_t *params,
			const char *buf);
static int pack_change_state_reply(change_state_params_t *params,
			char **buf, int *buf_size);
static int unpack_change_state_reply(change_state_params_t *params,
			const char *buf);

/*
 * Private Func Routines
 */
static int pack_private_func_request(private_func_params_t *params,
			char **buf, int *buf_size);
static int unpack_private_func_request(private_func_params_t *params,
			const char *buf);
static int pack_private_func_reply(private_func_params_t *params,
			char **buf, int *buf_size);
static int unpack_private_func_reply(private_func_params_t *params,
			const char *buf);

/*
 * Test Routines
 */
static int pack_test_request(test_params_t *params, char **buf, int *buf_size);

static int unpack_test_request(test_params_t *params, const char *buf);

static int pack_test_reply(test_params_t *params, char **buf, int *buf_size);

static int unpack_test_reply(test_params_t *params, const char *buf);


/*
 * List Ext Routines
 */
static int pack_list_ext_request(list_ext_params_t *params, char **buf,
			int *buf_size);
static int unpack_list_ext_request(list_ext_params_t *params, const char *buf);

static int pack_list_ext_reply(list_ext_params_t *params, char **buf,
			int *buf_size);
static int unpack_list_ext_reply(list_ext_params_t *params, const char *buf);


/*
 * Help Routines
 */
static int pack_help_request(help_params_t *params, char **buf, int *buf_size);

static int unpack_help_request(help_params_t *params, const char *buf);


/*
 * Ap Id Cmp Routines
 */
static int pack_ap_id_cmp_request(ap_id_cmp_params_t *params, char **buf,
			int *buf_size);
static int unpack_ap_id_cmp_request(ap_id_cmp_params_t *params,
			const char *buf);

/*
 * Abort Routines
 */
static int pack_abort_cmd_request(abort_cmd_params_t *params, char **buf,
			int *buf_size);
static int unpack_abort_cmd_request(abort_cmd_params_t *params,
			const char *buf);

/*
 * Confirm Callback Routines
 */
static int pack_confirm_request(confirm_callback_params_t *params, char **buf,
			int *buf_size);
static int unpack_confirm_request(confirm_callback_params_t *params,
			const char *buf);
static int pack_confirm_reply(confirm_callback_params_t *params,
			char **buf, int *buf_size);
static int unpack_confirm_reply(confirm_callback_params_t *params,
			const char *buf);

/*
 * Message Callback Routines
 */
static int pack_message_request(msg_callback_params_t *params, char **buf,
			int *buf_size);
static int unpack_message_request(msg_callback_params_t *params,
			const char *buf);

/*
 * Resource Info Routines
 */
static int pack_rsrc_info_request(rsrc_info_params_t *params, char **buf,
			int *buf_size);
static int unpack_rsrc_info_request(rsrc_info_params_t *params,
			const char *buf);
static int pack_rsrc_info_reply(rsrc_info_params_t *params, char **buf,
			int *buf_size, int encoding);
static int unpack_rsrc_info_reply(rsrc_info_params_t *params, const char *buf);

/*
 * General Pack/Unpack Routines
 */
static int pack_ap_ids(int num_ap_ids, char *const *ap_ids,
			rdr_variable_message_info_t *var_msg_info);
static int unpack_ap_ids(int num_ap_ids, char **ap_ids, const char *buf,
			rdr_variable_message_info_t *var_msg_info);

/*
 * Find Variable Info Sizes
 */
static int find_options_sizes(char *options,
			rdr_variable_message_info_t *var_msg_info);
static int find_listopts_sizes(char *listopts,
			rdr_variable_message_info_t *var_msg_info);
static int find_function_sizes(char *function,
			rdr_variable_message_info_t *var_msg_info);
static int find_errstring_sizes(char **errstring,
			rdr_variable_message_info_t *var_msg_info);

/*
 * Extract Info From Buffers
 */
static int get_ap_ids_from_buf(char ***ap_id_ptr, int num_ap_ids,
			rdr_variable_message_info_t *var_msg_info,
			const char *buf);
static int get_string_from_buf(char **stringptr, int strsize, const char *buf);


/*
 * Cleanup Routines
 */
static int cleanup_ap_ids(int num_ap_ids, char **ap_ids);

static int cleanup_errstring(char **errstring);

static void cleanup_variable_ap_id_info(
			rdr_variable_message_info_t *var_msg_info);

/*
 * Functions for loading libdscp.
 */
static int load_libdscp(libdscp_t *libdscp);

/*
 * Public Functions
 */


/*
 * rdr_open:
 *
 * Establish a transport endpoint to prepare for a new
 * connection. Returns a file descriptor representing the
 * new transport if successful or RDR_BAD_FD upon failure.
 */
int
rdr_open(int family)
{
	int	newfd;


	if ((newfd = socket(family, SOCK_STREAM, 0)) == -1) {
		return (RDR_BAD_FD);
	}

	return (newfd);
}


/*
 * rdr_init:
 *
 * Initialize a transport endpoint. This involves binding to
 * a particular port and setting any user specified socket
 * options.
 */
int
rdr_init(int fd, struct sockaddr *addr, int *opts, int num_opts, int blog)
{
	int	i;


	/* sanity checks */
	if ((fd < 0) || (addr == NULL)) {
		return (RDR_ERROR);
	}

	if ((opts == NULL) || (num_opts < 0)) {
		num_opts = 0;
	}

	/* turn on security features */
	if (rdr_secure(fd, addr) != RDR_OK) {
		return (RDR_NET_ERR);
	}

	/* bind the address, if is not already bound */
	if (rdr_bind(fd, addr) != RDR_OK) {
		return (RDR_NET_ERR);
	}

	/*
	 * Set TCP_NODELAY for this endpoint. This disables Nagle's
	 * algorithm that can cause a delay in sending small sized
	 * messages. Since most of the RDR messages are small, this
	 * is a restriction that negatively impacts performance.
	 */
	if (rdr_setopt(fd, TCP_NODELAY, IPPROTO_TCP) != RDR_OK) {
		return (RDR_NET_ERR);
	}

	/* set the user specified socket options */
	for (i = 0; i < num_opts; i++) {
		if (rdr_setopt(fd, opts[i], SOL_SOCKET) != RDR_OK) {
			return (RDR_NET_ERR);
		}
	}

	/*
	 * If blog is not zero, it is a server that is being
	 * initialized. In order for it to be able to accept
	 * connections, we have to set the size of the incoming
	 * connection queue.
	 */
	if (blog != 0) {
		if (listen(fd, blog) == -1) {
			return (RDR_NET_ERR);
		}
	}

	return (RDR_OK);
}


/*
 * rdr_connect_clnt:
 *
 * Perform the necessary steps for a client to connect to
 * a server process. The required information is the file
 * descriptor for the transport endpoint, and the remote
 * address.
 */
int
rdr_connect_clnt(int fd, struct sockaddr *addr)
{
	unsigned int	addr_len;


	/* sanity check */
	if (addr == NULL) {
		return (RDR_ERROR);
	}

	/* initialize the address length */
	switch (addr->sa_family) {

	case AF_INET:
		addr_len = sizeof (struct sockaddr_in);
		break;

	case AF_INET6:
		addr_len = sizeof (struct sockaddr_in6);
		break;

	default:
		return (RDR_ERROR);
	}

	/* attempt the connection */
	if (connect(fd, addr, addr_len) == -1) {
		return (RDR_NET_ERR);
	}

	return (RDR_OK);
}


/*
 * rdr_connect_srv:
 *
 * Perform the necessary steps for a server to connect to a
 * pending client request. The new connection is allocated a
 * new file descriptor, separate from the one used to accept
 * the connection.
 */
int
rdr_connect_srv(int fd)
{
	int			newfd;
	unsigned int		faddr_len;
	struct sockaddr_storage	faddr;


	/* accept the connection */
	faddr_len = sizeof (faddr);
	if ((newfd = accept(fd, (struct sockaddr *)&faddr, &faddr_len)) == -1) {
		return (RDR_BAD_FD);
	}

	/* if the peer doesn't authenticate properly, reject */
	if (rdr_auth((struct sockaddr *)&faddr, faddr_len) != RDR_OK) {
		(void) close(newfd);
		return (RDR_BAD_FD);
	}

	return (newfd);
}


/*
 * rdr_reject:
 *
 * Reject an incoming connection attempt. This requires
 * that the connection be accepted first.
 */
int
rdr_reject(int fd)
{
	unsigned int		faddr_len;
	struct sockaddr_storage	faddr;


	/* first accept the connection */
	faddr_len = sizeof (faddr);
	if (accept(fd, (struct sockaddr *)&faddr, &faddr_len) == -1) {
		return (RDR_NET_ERR);
	}

	/* then close it */
	(void) close(fd);

	return (RDR_OK);
}


/*
 * rdr_close:
 *
 * Close down an given connection.
 */
int
rdr_close(int fd)
{
	(void) close(fd);

	return (RDR_OK);
}


/*
 * rdr_snd_msg:
 *
 * Public interface for sending an RDR message. The data
 * passed in through hdr and param are packed for network
 * transport and sent.
 */
int
rdr_snd_msg(int fd, rdr_msg_hdr_t *hdr, cfga_params_t *param, int timeout)
{
	int	err;
	char	*pack_buf = NULL;
	int	pack_buf_sz = 0;


	/* sanity checks */
	if ((hdr == NULL) || (param == NULL)) {
		return (RDR_ERROR);
	}

	/*
	 * Pack the message for transport
	 */
	switch (hdr->message_opcode) {

		case RDR_SES_REQ: {

			ses_req_params_t *rparam;
			rparam = (ses_req_params_t *)param;

			if (hdr->data_type == RDR_REQUEST) {
				err = pack_ses_req_request(rparam,
				    &pack_buf, &pack_buf_sz);
			} else {
				err = pack_ses_req_reply(rparam,
				    &pack_buf, &pack_buf_sz);
			}

			break;
		}

		case RDR_SES_ESTBL:
		case RDR_SES_END:

			/*
			 * This is not an error condition because
			 * there is no extra information to pack.
			 */
			err = RDR_OK;
			break;

		case RDR_CONF_CHANGE_STATE: {

			change_state_params_t *cparam;
			cparam = (change_state_params_t *)param;

			if (hdr->data_type == RDR_REQUEST) {
				err = pack_change_state_request(cparam,
				    &pack_buf, &pack_buf_sz);
			} else {
				err = pack_change_state_reply(cparam,
				    &pack_buf, &pack_buf_sz);
			}
			break;
		}

		case RDR_CONF_PRIVATE_FUNC: {

			private_func_params_t *pparam;
			pparam = (private_func_params_t *)param;

			if (hdr->data_type == RDR_REQUEST) {
				err = pack_private_func_request(pparam,
				    &pack_buf, &pack_buf_sz);
			} else {
				err = pack_private_func_reply(pparam,
				    &pack_buf, &pack_buf_sz);
			}
			break;
		}

		case RDR_CONF_TEST: {

			test_params_t *tparam;
			tparam = (test_params_t *)param;

			if (hdr->data_type == RDR_REQUEST) {
				err = pack_test_request(tparam,
				    &pack_buf, &pack_buf_sz);
			} else {
				err = pack_test_reply(tparam,
				    &pack_buf, &pack_buf_sz);
			}
			break;
		}

		case RDR_CONF_LIST_EXT: {

			list_ext_params_t *lparam;
			lparam = (list_ext_params_t *)param;

			if (hdr->data_type == RDR_REQUEST) {
				err = pack_list_ext_request(lparam, &pack_buf,
				    &pack_buf_sz);
			} else {
				err = pack_list_ext_reply(lparam, &pack_buf,
				    &pack_buf_sz);
			}
			break;
		}

		case RDR_CONF_HELP: {

			help_params_t *hparam;
			hparam = (help_params_t *)param;

			if (hdr->data_type == RDR_REQUEST) {
				err = pack_help_request(hparam,
				    &pack_buf, &pack_buf_sz);
			} else {

				/*
				 * This is not an error because help
				 * reply does not have any extra information
				 * to pack.
				 */
				err = RDR_OK;
			}
			break;
		}

		case RDR_CONF_AP_ID_CMP: {

			ap_id_cmp_params_t *aparam;
			aparam = (ap_id_cmp_params_t *)param;

			if (hdr->data_type == RDR_REQUEST) {
				err = pack_ap_id_cmp_request(aparam,
				    &pack_buf, &pack_buf_sz);
			} else {

				/*
				 * This is not an error because ap_id_cmp
				 * reply does not have any extra information
				 * to pack.
				 */
				err = RDR_OK;
			}
			break;
		}

		case RDR_CONF_ABORT_CMD: {

			abort_cmd_params_t *aparam;
			aparam = (abort_cmd_params_t *)param;

			if (hdr->data_type == RDR_REQUEST) {
				err = pack_abort_cmd_request(aparam,
				    &pack_buf, &pack_buf_sz);
			} else {
				/*
				 * This is not an error because session
				 * abort reply does not have any extra
				 * information to pack.
				 */
				err = RDR_OK;
			}
			break;
		}

		case RDR_CONF_CONFIRM_CALLBACK: {

			confirm_callback_params_t *cparam;
			cparam = (confirm_callback_params_t *)param;

			if (hdr->data_type == RDR_REQUEST) {
				err = pack_confirm_request(cparam,
				    &pack_buf, &pack_buf_sz);
			} else {
				err = pack_confirm_reply(cparam, &pack_buf,
				    &pack_buf_sz);
			}
			break;
		}

		case RDR_CONF_MSG_CALLBACK: {

			msg_callback_params_t *mparam;
			mparam = (msg_callback_params_t *)param;

			if (hdr->data_type == RDR_REQUEST) {
				err = pack_message_request(mparam,
				    &pack_buf, &pack_buf_sz);
			} else {
				/*
				 * It is an error to send a reply
				 * to a message callback.
				 */
				err = RDR_MSG_INVAL;
			}
			break;
		}

		case RDR_RSRC_INFO: {

			rsrc_info_params_t *rparam;
			rparam = (rsrc_info_params_t *)param;

			if (hdr->data_type == RDR_REQUEST) {
				err = pack_rsrc_info_request(rparam, &pack_buf,
				    &pack_buf_sz);
			} else {
				if ((hdr->major_version == 1) &&
				    (hdr->minor_version == 0)) {
					err = pack_rsrc_info_reply(rparam,
					    &pack_buf, &pack_buf_sz,
					    NV_ENCODE_NATIVE);
				} else {
					err = pack_rsrc_info_reply(rparam,
					    &pack_buf, &pack_buf_sz,
					    NV_ENCODE_XDR);
				}
			}
			break;
		}

		default:
			err = RDR_MSG_INVAL;
			break;
	}

	/* check if packed correctly */
	if (err != RDR_OK) {
		return (err);
	}

	/* send the message */
	err = rdr_snd(fd, hdr, pack_buf, pack_buf_sz, timeout);

	free((void *)pack_buf);

	return (err);
}


/*
 * rdr_rcv_msg:
 *
 * Public interface for receiving an RDR message. Data is
 * unpacked into the hdr and param paramters.
 */
int
rdr_rcv_msg(int fd, rdr_msg_hdr_t *hdr, cfga_params_t *param, int timeout)
{
	int	err;
	char	*unpack_buf = NULL;


	/* sanity checks */
	if ((hdr == NULL) || (param == NULL)) {
		return (RDR_ERROR);
	}

	(void) memset(param, 0, sizeof (cfga_params_t));

	/* receive the message */
	if ((err = rdr_rcv(fd, hdr, &unpack_buf, timeout)) != RDR_OK) {
		return (err);
	}

	/*
	 * Unpack the message
	 */
	switch (hdr->message_opcode) {

		case RDR_SES_REQ: {

			ses_req_params_t *rparam;
			rparam = (ses_req_params_t *)param;

			if (hdr->data_type == RDR_REQUEST) {
				err = unpack_ses_req_request(rparam,
				    unpack_buf);
			} else {
				err = unpack_ses_req_reply(rparam, unpack_buf);
			}
			break;
		}

		case RDR_SES_ESTBL:
		case RDR_SES_END:

			/* no information to unpack */
			(void) memset(param, 0, sizeof (cfga_params_t));
			err = RDR_OK;
			break;

		case RDR_CONF_CHANGE_STATE: {

			change_state_params_t *cparam;
			cparam = (change_state_params_t *)param;

			if (hdr->data_type == RDR_REQUEST) {
				err = unpack_change_state_request(cparam,
				    unpack_buf);
			} else {
				err = unpack_change_state_reply(cparam,
				    unpack_buf);
			}
			break;
		}

		case RDR_CONF_PRIVATE_FUNC: {

			private_func_params_t *pparam;
			pparam = (private_func_params_t *)param;

			if (hdr->data_type == RDR_REQUEST) {
				err = unpack_private_func_request(pparam,
				    unpack_buf);
			} else {
				err = unpack_private_func_reply(pparam,
				    unpack_buf);
			}
			break;
		}

		case RDR_CONF_TEST: {

			test_params_t *tparam;
			tparam = (test_params_t *)param;

			if (hdr->data_type == RDR_REQUEST) {
				err = unpack_test_request(tparam, unpack_buf);
			} else {
				err = unpack_test_reply(tparam, unpack_buf);
			}
			break;
		}

		case RDR_CONF_LIST_EXT: {

			list_ext_params_t *lparam;
			lparam = (list_ext_params_t *)param;

			if (hdr->data_type == RDR_REQUEST) {
				err = unpack_list_ext_request(lparam,
				    unpack_buf);
			} else {
				err = unpack_list_ext_reply(lparam, unpack_buf);
			}
			break;
		}

		case RDR_CONF_HELP: {

			help_params_t *hparam;
			hparam = (help_params_t *)param;

			if (hdr->data_type == RDR_REQUEST) {
				err = unpack_help_request(hparam,
				    unpack_buf);
			} else {
				/*
				 * This is not an error because help
				 * reply does not have any extra information
				 * to unpack.
				 */
				err = RDR_OK;
			}
			break;
		}

		case RDR_CONF_AP_ID_CMP: {

			ap_id_cmp_params_t *aparam;
			aparam = (ap_id_cmp_params_t *)param;

			if (hdr->data_type == RDR_REQUEST) {
				err = unpack_ap_id_cmp_request(aparam,
				    unpack_buf);
			} else {
				/*
				 * This is not an error because ap_id_cmp
				 * reply does not have any extra information
				 * to pack.
				 */
				err = RDR_OK;
			}
			break;
		}

		case RDR_CONF_ABORT_CMD: {

			abort_cmd_params_t *aparam;
			aparam = (abort_cmd_params_t *)param;

			if (hdr->data_type == RDR_REQUEST) {
				err = unpack_abort_cmd_request(aparam,
				    unpack_buf);
			} else {
				/* no information to unpack */
				(void) memset(param, 0, sizeof (cfga_params_t));
				err = RDR_OK;
			}

			break;
		}

		case RDR_CONF_CONFIRM_CALLBACK: {

			confirm_callback_params_t *cparam;
			cparam = (confirm_callback_params_t *)param;

			if (hdr->data_type == RDR_REQUEST) {
				err = unpack_confirm_request(cparam,
				    unpack_buf);
			} else {
				err = unpack_confirm_reply(cparam, unpack_buf);
			}
			break;
		}

		case RDR_CONF_MSG_CALLBACK: {

			msg_callback_params_t *mparam;
			mparam = (msg_callback_params_t *)param;

			if (hdr->data_type == RDR_REQUEST) {
				err = unpack_message_request(mparam,
				    unpack_buf);
			} else {
				/*
				 * It is an error to send a reply
				 * to a message callback.
				 */
				(void) memset(param, 0, sizeof (cfga_params_t));
				err = RDR_MSG_INVAL;
			}
			break;
		}

		case RDR_RSRC_INFO: {

			rsrc_info_params_t *rparam;
			rparam = (rsrc_info_params_t *)param;

			if (hdr->data_type == RDR_REQUEST) {
				err = unpack_rsrc_info_request(rparam,
				    unpack_buf);
			} else {
				err = unpack_rsrc_info_reply(rparam,
				    unpack_buf);
			}
			break;
		}

		default:
			err = RDR_MSG_INVAL;
			break;
	}

	free(unpack_buf);

	/* check if unpacked correctly */
	if (err != RDR_OK) {
		return (err);
	}

	return (RDR_OK);
}


/*
 * rdr_cleanup_params:
 *
 * Deallocate any memory that was allocated in unpacking a
 * message.
 */
int
rdr_cleanup_params(rdr_msg_opcode_t message_opcode, cfga_params_t *param)
{
	/* sanity check */
	if ((param == NULL)) {
		return (RDR_ERROR);
	}

	/*
	 * Deallocate memory depending on
	 * the operation.
	 */
	switch (message_opcode) {

	case RDR_SES_REQ: {

		ses_req_params_t *sparam;
		sparam = (ses_req_params_t *)param;

		if (sparam->locale_str != NULL) {
			free((void *)sparam->locale_str);
			sparam->locale_str = NULL;
		}
		break;
	}

	case RDR_SES_ESTBL:
	case RDR_SES_END:

		/* nothing to deallocate */
		break;

	case RDR_CONF_CHANGE_STATE: {

		change_state_params_t *cparam;
		cparam = (change_state_params_t *)param;

		cleanup_ap_ids(cparam->num_ap_ids, (char **)cparam->ap_ids);
		cparam->ap_ids = NULL;
		if (cparam->options != NULL) {
			free((void *)cparam->options);
			cparam->options = NULL;
		}
		if (cparam->confp != NULL) {
			free((void *)cparam->confp);
			cparam->confp = NULL;
		}
		if (cparam->msgp != NULL) {
			free((void *)cparam->msgp);
			cparam->msgp = NULL;
		}
		cleanup_errstring(cparam->errstring);
		break;
	}

	case RDR_CONF_PRIVATE_FUNC: {

		private_func_params_t *pparam;
		pparam = (private_func_params_t *)param;

		cleanup_ap_ids(pparam->num_ap_ids, (char **)pparam->ap_ids);
		pparam->ap_ids = NULL;
		if (pparam->options != NULL) {
			free((void *)pparam->options);
			pparam->options = NULL;
		}
		if (pparam->confp != NULL) {
			free((void *)pparam->confp);
			pparam->confp = NULL;
		}
		if (pparam->msgp != NULL) {
			free((void *)pparam->msgp);
			pparam->msgp = NULL;
		}
		cleanup_errstring(pparam->errstring);
		break;
	}

	case RDR_CONF_TEST: {

		test_params_t *tparam;
		tparam = (test_params_t *)param;

		cleanup_ap_ids(tparam->num_ap_ids, (char **)tparam->ap_ids);
		tparam->ap_ids = NULL;
		if (tparam->options != NULL) {
			free((void *)tparam->options);
			tparam->options = NULL;
		}
		if (tparam->msgp != NULL) {
			free((void *)tparam->msgp);
			tparam->msgp = NULL;
		}
		cleanup_errstring(tparam->errstring);
		break;
	}

	case RDR_CONF_LIST_EXT: {

		list_ext_params_t *lparam;
		lparam = (list_ext_params_t *)param;

		cleanup_ap_ids(lparam->num_ap_ids, (char **)lparam->ap_ids);
		lparam->ap_ids = NULL;

		if (lparam->nlist != NULL) {
			free((void *)lparam->nlist);
			lparam->nlist = NULL;
		}
		if (lparam->ap_id_list != NULL) {
			if (*lparam->ap_id_list != NULL) {
				free((void *)*lparam->ap_id_list);
			}
			free((void *)lparam->ap_id_list);
			lparam->ap_id_list = NULL;
		}
		if (lparam->ap_id_list != NULL) {
			free((void *)lparam->ap_id_list);
			lparam->ap_id_list = NULL;
		}

		if (lparam->options != NULL) {
			free((void *)lparam->options);
			lparam->options = NULL;
		}
		if (lparam->listopts != NULL) {
			free((void *)lparam->listopts);
			lparam->listopts = NULL;
		}
		cleanup_errstring(lparam->errstring);
		break;
	}

	case RDR_CONF_HELP: {

		help_params_t *hparam;
		hparam = (help_params_t *)param;

		cleanup_ap_ids(hparam->num_ap_ids, (char **)hparam->ap_ids);
		hparam->ap_ids = NULL;
		if (hparam->msgp != NULL) {
			free((void *)hparam->msgp);
			hparam->msgp = NULL;
		}
		if (hparam->options != NULL) {
			free((void *)hparam->options);
			hparam->options = NULL;
		}
		break;
	}

	case RDR_CONF_AP_ID_CMP: {

		ap_id_cmp_params_t *aparam;
		aparam = (ap_id_cmp_params_t *)param;

		if (aparam->ap_log_id1 != NULL) {
			free((void *)aparam->ap_log_id1);
			aparam->ap_log_id1 = NULL;
		}
		if (aparam->ap_log_id2 != NULL) {
			free((void *)aparam->ap_log_id2);
			aparam->ap_log_id2 = NULL;
		}
		break;
	}

	case RDR_CONF_ABORT_CMD:

		/* nothing to deallocate */
		break;

	case RDR_CONF_CONFIRM_CALLBACK: {

		confirm_callback_params_t *cparam;
		cparam = (confirm_callback_params_t *)param;

		if (cparam->confp != NULL) {
			free((void *)cparam->confp);
			cparam->confp = NULL;
		}
		if (cparam->message != NULL) {
			free((void *)cparam->message);
			cparam->message = NULL;
		}
		break;
	}

	case RDR_CONF_MSG_CALLBACK: {

		msg_callback_params_t *mparam;
		mparam = (msg_callback_params_t *)param;

		if (mparam->msgp != NULL) {
			free((void *)mparam->msgp);
			mparam->msgp = NULL;
		}
		if (mparam->message != NULL) {
			free((void *)mparam->message);
			mparam->message = NULL;
		}
		break;
	}

	default:
		return (RDR_ERROR);
		/* NOTREACHED */
		break;

	}

	return (RDR_OK);
}

/*
 * rdr_setsockopt:
 *
 * Wrapper of the setsockopt(3SOCKET) library function.
 */
int
rdr_setsockopt(int fd, int level, int optname, const void *optval, int optlen)
{
	if (setsockopt(fd, level, optname, optval, optlen) == -1)
		return (RDR_NET_ERR);
	else
		return (RDR_OK);
}


/*
 * Private (static) Functions
 */


/*
 * rdr_setopt:
 *
 * Set the specified option for a given transport endpoint.
 * This function only sets boolean options. It does not
 * provide the ability to unset an option, or set a non-
 * boolean option.
 */
static int
rdr_setopt(int fd, int name, int level)
{
	int	on = 1;


	if (setsockopt(fd, level, name, &on, sizeof (on)) == -1) {
		return (RDR_NET_ERR);
	}

	return (RDR_OK);
}


/*
 * rdr_bind:
 *
 * Bind the specified file descriptor to a specified
 * address. If the address is already bound, no error is
 * returned. This is the expected behavior if a server
 * has been started by inetd (1M).
 */
static int
rdr_bind(int fd, struct sockaddr *addr)
{
	unsigned int		addr_len;
	int			rc;


	/* initialize the address */
	switch (addr->sa_family) {

	case AF_INET:
		addr_len = sizeof (struct sockaddr_in);
		break;

	case AF_INET6:
		addr_len = sizeof (struct sockaddr_in6);
		break;

	default:
		return (RDR_ERROR);
	}

	/* attempt to bind the address */
	rc = bind(fd, addr, addr_len);

	/*
	 * Ignore the error if EINVAL is returned. In
	 * this case, we assume that this means that
	 * the address was already bound. This is not
	 * an error for servers started by inetd (1M).
	 */
	if ((rc == -1) && (errno != EINVAL)) {
		return (RDR_NET_ERR);
	}

	/*
	 * Retreive the address information of the
	 * address that was actually bound.
	 */
	addr_len = sizeof (*addr);
	if (getsockname(fd, addr, &addr_len) == -1) {
		(void) memset(addr, 0, sizeof (*addr));
		return (RDR_NET_ERR);
	}

	return (RDR_OK);
}


/*
 * rdr_secure:
 *
 * Activate security features for a socket.
 *
 * Some platforms have libdscp, which provides additional
 * security features.  An attempt is made to load libdscp
 * and use these features.
 *
 * Nothing is done if libdscp is not available.
 */
static int
rdr_secure(int fd, struct sockaddr *addr)
{
	struct sockaddr_in	*sin;
	int			port;
	int			error;

	if (use_libdscp == 0) {
		return (RDR_OK);
	}

	if (load_libdscp(&libdscp) != 1) {
		return (RDR_ERROR);
	}

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	sin = (struct sockaddr_in *)addr;
	port = ntohs(sin->sin_port);
	error = libdscp.bind(0, fd, port);

	if ((error != DSCP_OK) && (error != DSCP_ERROR_ALREADY)) {
		return (RDR_ERROR);
	}

	if (libdscp.secure(0, fd) != DSCP_OK) {
		return (RDR_ERROR);
	}
	return (RDR_OK);
}

/*
 * rdr_auth:
 *
 * Authenticate if a connection is really from the service
 * processor.  This is dependent upon functionality from
 * libdscp, so an attempt to load and use libdscp is made.
 *
 * Without libdscp, this function does nothing.
 */
static int
rdr_auth(struct sockaddr *addr, int len)
{
	if (use_libdscp != 0) {
		if ((load_libdscp(&libdscp) == 0) ||
		    (libdscp.auth(0, addr, len) != DSCP_OK)) {
			return (RDR_ERROR);
		}
	}

	return (RDR_OK);
}

/*
 * rdr_snd:
 *
 * Send a message in two stages. First the header is sent,
 * followed by the packed buffer containing the message
 * contents.
 */
static int
rdr_snd(int fd, rdr_msg_hdr_t *hdr, char *data, int data_sz, int timeout)
{
	int	err;


	/* sanity check */
	if (hdr == NULL) {
		return (RDR_ERROR);
	}

	/* ensure null pad bytes */
	hdr->pad_byte1 = 0;
	hdr->pad_byte2 = 0;

	/* initialize size information */
	hdr->data_length = data_sz;

	/* send message header */
	err = rdr_snd_raw(fd, (char *)hdr, RDR_MSG_HDR_SIZE, timeout);
	if (err != RDR_OK) {
		return (err);
	}

	/* check if more to send */
	if (data_sz == 0) {
		return (RDR_OK);
	}

	/* send message data */
	err = rdr_snd_raw(fd, data, data_sz, timeout);
	if (err != RDR_OK) {
		return (err);
	}

	return (RDR_OK);
}


/*
 * rdr_snd_raw:
 *
 * Send a raw buffer of information. This function handles
 * the low level details of the send operation.
 */
static int
rdr_snd_raw(int fd, char *msg, int data_sz, int timeout)
{
	int		err;
	int		num_bytes;
	int		bytes_left;
	char		*bufp;
	struct pollfd	pfd;


	bufp = (char *)msg;

	bytes_left = data_sz;

	pfd.fd = fd;
	pfd.events = POLLOUT;

	while (bytes_left > 0) {

		pfd.revents = 0;

		/* wait until we can send the data */
		if ((err = poll(&pfd, 1, timeout)) == -1) {

			/* poll was interrupted */
			if (errno == EINTR) {
				return (RDR_ABORTED);
			}

			return (RDR_ERROR);

		} else if (err == 0) {
			return (RDR_TIMEOUT);
		}

		/* ready to send data */
		if (pfd.revents & POLLOUT) {

			num_bytes = write(fd, bufp, bytes_left);

			if (num_bytes == -1) {

				/*
				 * Distinguish between an aborted
				 * session and other network errors.
				 */
				if (errno == EPIPE) {
					return (RDR_ABORTED);
				} else {
					return (RDR_NET_ERR);
				}
			}

			/* wrote 0 bytes, so operation was aborted */
			if (num_bytes == 0) {
				return (RDR_ABORTED);
			}

		} else {
			return (RDR_NET_ERR);
		}

		bytes_left -= num_bytes;
		bufp += num_bytes;
	}

	return (RDR_OK);
}


/*
 * rdr_rcv:
 *
 * Receive a message in two stages. First the header is
 * received, followed by the packed buffer containing the
 * message contents.
 */
static int
rdr_rcv(int fd, rdr_msg_hdr_t *hdr, char **data, int timeout)
{
	int	err;
	int	data_sz;
	char	hdr_buf[RDR_MSG_HDR_SIZE];
	char	*buf = NULL;


	/* sanity check */
	if (hdr == NULL) {
		return (RDR_ERROR);
	}

	/* receive the header */
	err = rdr_rcv_raw(fd, hdr_buf, RDR_MSG_HDR_SIZE, timeout);
	if (err != RDR_OK) {
		return (err);
	}

	/* verify that the data is good */
	/* LINTED Pointer Cast Alignment Warning */
	if (validate_header((rdr_msg_hdr_t *)hdr_buf) != RDR_OK) {
		return (RDR_MSG_INVAL);
	}

	/* LINTED Pointer Cast Alignment Warning */
	data_sz = ((rdr_msg_hdr_t *)hdr_buf)->data_length;

	buf = (char *)malloc(data_sz);
	if (!buf) {
		return (RDR_MEM_ALLOC);
	}

	if (data_sz != 0) {

		/* receive the rest of the message */
		err = rdr_rcv_raw(fd, buf, data_sz, timeout);
		if (err != RDR_OK) {
			free((void *)buf);
			return (err);
		}
	}

	/* copy out data */
	*data = buf;
	(void) memcpy(hdr, hdr_buf, RDR_MSG_HDR_SIZE);

	return (RDR_OK);
}


/*
 * rdr_rcv_raw:
 *
 * Receive a raw buffer of information. This function handles
 * the low level details of the receive operation.
 */
static int
rdr_rcv_raw(int fd, char *msg, int data_size, int timeout)
{
	int		num_bytes;
	int		err;
	int		bytes_left;
	char		*bufp;
	struct pollfd	pollfd;


	bufp = (char *)msg;
	bytes_left = data_size;

	pollfd.fd = fd;
	pollfd.events = POLLIN;

	while (bytes_left > 0) {

		errno = 0;
		pollfd.revents = 0;

		if ((err = poll(&pollfd, 1, timeout)) == -1) {

			/*
			 * In the DCA, if a session is aborted, SIGINT
			 * is delivered to all active sessions. This
			 * mistakenly causes all sessions waiting in
			 * the poll to be interrupted. So, if EINTR
			 * is returned, it is ignored. If another error
			 * occurs right away, the current session really
			 * was aborted. All other sessions won't encounter
			 * an error and will proceed normally.
			 */
			if ((errno == 0) || (errno == EINTR)) {
				continue;
			}

			return (RDR_ABORTED);

		} else if (err == 0) {
			return (RDR_TIMEOUT);
		}

		/* ready to receive data */
		if (pollfd.revents & POLLIN) {

			num_bytes = read(fd, bufp, bytes_left);

			if (num_bytes == -1) {

				/*
				 * Distinguish between an aborted
				 * session and other network errors.
				 */
				if (errno == ECONNRESET) {
					return (RDR_ABORTED);
				} else {
					return (RDR_NET_ERR);
				}
			}

			/* read 0 bytes, so operation was aborted */
			if (num_bytes == 0) {
				return (RDR_ABORTED);
			}

		} else {
			return (RDR_NET_ERR);
		}

		bytes_left -= num_bytes;
		bufp += num_bytes;
	}

	return (RDR_OK);
}


/*
 * validate_header:
 *
 * Perform a series of sanity checks on the header data that is
 * received. This gets called before the variable length data is
 * read in to make sure that the information in the header can
 * be trusted.
 */
static int
validate_header(rdr_msg_hdr_t *hdr)
{
	unsigned char	op;


	if (hdr == NULL) {
		return (RDR_ERROR);
	}

	op = hdr->message_opcode;

	/* validate opcode */
	if ((op < RDR_SES_REQ) || (op >= RDR_NUM_OPS)) {
		return (RDR_ERROR);
	}

	/* validate message size (and type) for op */
	switch (hdr->data_type) {

	case RDR_REQUEST:
		if (hdr->data_length > msg_sizes[op].req_max) {
			return (RDR_ERROR);
		}
		break;

	case RDR_REPLY:
		if (hdr->data_length > msg_sizes[op].reply_max) {
			return (RDR_ERROR);
		}
		break;

	default:
		/* invalid data type */
		return (RDR_ERROR);
	}

	/* all checks passed */
	return (RDR_OK);
}


/*
 * pack_ses_req_request:
 *
 * Handle packing a session request request message.
 */
static int
pack_ses_req_request(ses_req_params_t *params, char **buf, int *buf_size)
{
	char		*bufptr;
	int		locale_str_len;
	rdr_ses_req_t	ses_req;


	if ((params == NULL) || (buf == NULL) || (buf_size == NULL)) {
		return (RDR_ERROR);
	}

	/*
	 * Determine the size of the locale string
	 */
	if (params->locale_str != NULL) {
		locale_str_len = strlen(params->locale_str) + 1;
	} else {
		locale_str_len = 0;
	}

	/*
	 * Collect size info specific to the ses_req request message
	 * and allocate a buffer
	 */
	*buf_size = sizeof (rdr_ses_req_t);
	*buf_size += locale_str_len;

	*buf = (char *)malloc(*buf_size);
	if (*buf == NULL) {
		return (RDR_MEM_ALLOC);
	}

	/*
	 * Set fixed locale size label by name
	 */
	ses_req.locale_size = locale_str_len;

	/*
	 * Set variable information using memcpy
	 */
	bufptr = *buf;

	(void) memcpy(bufptr, &ses_req, sizeof (rdr_ses_req_t));
	bufptr += sizeof (rdr_ses_req_t);

	if (params->locale_str != NULL) {
		(void) memcpy(bufptr, params->locale_str, locale_str_len);
		bufptr += locale_str_len;
	}

	return (RDR_OK);
}


/*
 * unpack_ses_req_request:
 *
 * Handle unpacking a session request request message.
 */
static int
unpack_ses_req_request(ses_req_params_t *params, const char *buf)
{
	char		*bufptr;
	rdr_ses_req_t	ses_req_data;


	if ((params == NULL) || (buf == NULL)) {
		return (RDR_ERROR);
	}

	bufptr = (char *)buf;
	(void) memcpy(&ses_req_data, bufptr, sizeof (rdr_ses_req_t));
	bufptr += sizeof (rdr_ses_req_t);

	/*
	 * handle getting the locale string
	 */
	if (get_string_from_buf(&(params->locale_str),
	    ses_req_data.locale_size, bufptr)) {
		return (RDR_ERROR);
	}

	return (RDR_OK);
}


/*
 * pack_ses_req_reply:
 *
 * Handle packing a session request reply message.
 */
static int
pack_ses_req_reply(ses_req_params_t *params, char **buf, int *buf_size)
{
	rdr_ses_req_reply_t	ses_req_reply_data;


	if ((params == NULL) || (buf == NULL) || (buf_size == NULL)) {
		return (RDR_ERROR);
	}

	/*
	 * Collect size info specific to the session request reply
	 * message and allocate a buffer
	 */
	*buf_size = sizeof (rdr_ses_req_reply_t);

	*buf = (char *)malloc(*buf_size);
	if (*buf == NULL) {
		return (RDR_MEM_ALLOC);
	}

	/*
	 * Set fixed session identifier
	 */
	ses_req_reply_data.session_id = params->session_id;

	/*
	 * Copy information using memcpy
	 */
	(void) memcpy(*buf, &ses_req_reply_data, sizeof (rdr_ses_req_reply_t));

	return (RDR_OK);
}


/*
 * unpack_ses_req_request:
 *
 * Handle unpacking a session request reply message.
 */
static int
unpack_ses_req_reply(ses_req_params_t *params, const char *buf)
{
	rdr_ses_req_reply_t	*ses_req_reply_datap;


	if ((params == NULL) || (buf == NULL)) {
		return (RDR_ERROR);
	}

	/* LINTED Pointer Cast Alignment Warning */
	ses_req_reply_datap = (rdr_ses_req_reply_t *)buf;

	/*
	 * copy out the session information
	 */
	params->session_id = ses_req_reply_datap->session_id;

	return (RDR_OK);
}


/*
 * pack_change_state_request:
 *
 * Handle packing a change state request message.
 */
static int
pack_change_state_request(change_state_params_t *params, char **buf,
    int *buf_size)
{
	int				i;
	char				*bufptr;
	rdr_change_state_t		change_state_data;
	rdr_variable_message_info_t	var_msg_info;


	if ((params == NULL) || (buf == NULL) || (buf_size == NULL)) {
		return (RDR_ERROR);
	}

	(void) memset(&var_msg_info, 0, sizeof (rdr_variable_message_info_t));

	/*
	 * Set variable length fields and make a call to partially
	 * pack it.
	 */
	if (pack_ap_ids(params->num_ap_ids, params->ap_ids, &var_msg_info)) {
		cleanup_variable_ap_id_info(&var_msg_info);
		return (RDR_ERROR);
	}
	if (find_options_sizes(params->options, &var_msg_info)) {
		cleanup_variable_ap_id_info(&var_msg_info);
		return (RDR_ERROR);
	}

	/*
	 * Collect size info specific to the change_state request
	 * message and allocate a buffer
	 */
	*buf_size = sizeof (rdr_change_state_t);
	*buf_size += var_msg_info.ap_id_int_size;
	*buf_size += var_msg_info.ap_id_char_size;
	*buf_size += var_msg_info.options_strlen;
	*buf_size += var_msg_info.options_pad_sz;

	*buf = (char *)malloc(*buf_size);
	if (*buf == NULL) {
		cleanup_variable_ap_id_info(&var_msg_info);
		return (RDR_MEM_ALLOC);
	}

	/*
	 * Set fixed address labels by name
	 */
	change_state_data.num_ap_ids = params->num_ap_ids;
	change_state_data.ap_id_char_size = var_msg_info.ap_id_char_size;
	change_state_data.options_size = var_msg_info.options_strlen +
	    var_msg_info.options_pad_sz;

	if (params->confp != NULL) {
		change_state_data.confirm_callback_id =
		    (unsigned long)params->confp->confirm;
		change_state_data.confirm_appdata_ptr =
		    (unsigned long)params->confp->appdata_ptr;
	} else {
		change_state_data.confirm_callback_id = 0;
		change_state_data.confirm_appdata_ptr = 0;
	}
	if (params->msgp != NULL) {
		change_state_data.msg_callback_id =
		    (unsigned long)params->msgp->message_routine;
		change_state_data.msg_appdata_ptr =
		    (unsigned long)params->msgp->appdata_ptr;
	} else {
		change_state_data.msg_callback_id = 0;
		change_state_data.msg_appdata_ptr = 0;
	}

	change_state_data.flags = params->flags;
	change_state_data.timeval = params->timeval;
	change_state_data.state_change_cmd = params->state_change;
	if (params->errstring != NULL) {
		change_state_data.error_msg_ctl = RDR_GENERATE_ERR_MSGS;
	} else {
		change_state_data.error_msg_ctl = RDR_DONT_GENERATE_ERR_MSGS;
	}
	change_state_data.retries = params->retries;

	/*
	 * Set variable information using memcpy
	 */
	bufptr = *buf;

	(void) memcpy(bufptr, &change_state_data, sizeof (rdr_change_state_t));
	bufptr += sizeof (rdr_change_state_t);

	if (var_msg_info.ap_id_sizes != NULL) {
		(void) memcpy(bufptr, var_msg_info.ap_id_sizes,
		    var_msg_info.ap_id_int_size);
		bufptr += var_msg_info.ap_id_int_size;
	}

	if (var_msg_info.ap_id_chars != NULL) {
		(void) memcpy(bufptr, var_msg_info.ap_id_chars,
		    var_msg_info.ap_id_char_size);
		bufptr += var_msg_info.ap_id_char_size;
	}

	if (params->options != NULL) {
		(void) memcpy(bufptr, params->options,
		    var_msg_info.options_strlen);
		bufptr += var_msg_info.options_strlen;
		for (i = 0; i < var_msg_info.options_pad_sz; i++) {
			bufptr[i] = 0;
		}
		bufptr += var_msg_info.options_pad_sz;
	}

	cleanup_variable_ap_id_info(&var_msg_info);

	return (RDR_OK);
}


/*
 * unpack_change_state_request:
 *
 * Handle unpacking a change state request message.
 */
static int
unpack_change_state_request(change_state_params_t *params, const char *buf)
{
	char				*bufptr;
	rdr_variable_message_info_t	var_msg_info;
	rdr_change_state_t		change_state_data;


	if ((params == NULL) || (buf == NULL)) {
		return (RDR_ERROR);
	}

	(void) memset(&var_msg_info, 0, sizeof (rdr_variable_message_info_t));

	bufptr = (char *)buf;
	(void) memcpy(&change_state_data, bufptr, sizeof (rdr_change_state_t));
	bufptr += sizeof (rdr_change_state_t);

	/*
	 * handle getting the ap_ids
	 */
	var_msg_info.ap_id_char_size = change_state_data.ap_id_char_size;
	if (get_ap_ids_from_buf((char ***)&(params->ap_ids),
	    change_state_data.num_ap_ids, &var_msg_info, bufptr)) {
		return (RDR_ERROR);
	}
	bufptr += var_msg_info.ap_id_int_size;
	bufptr += var_msg_info.ap_id_char_size;

	/*
	 * handle getting the options
	 */
	if (get_string_from_buf(&(params->options),
	    change_state_data.options_size, bufptr)) {
		return (RDR_ERROR);
	}
	bufptr += change_state_data.options_size;

	/*
	 * Set fixed address labels by name
	 */
	params->state_change = (cfga_cmd_t)change_state_data.state_change_cmd;
	params->num_ap_ids = change_state_data.num_ap_ids;

	params->confp = (struct cfga_confirm *)
	    malloc(sizeof (struct cfga_confirm));
	if (params->confp == NULL) {
		return (RDR_MEM_ALLOC);
	}

	/* set params->confp->confirm using memcpy */
	(void) memcpy((void*)params->confp,
	    &(change_state_data.confirm_callback_id), sizeof (unsigned long));
	params->confp->appdata_ptr =
	    (void*)change_state_data.confirm_appdata_ptr;

	params->msgp = (struct cfga_msg *)malloc(sizeof (struct cfga_msg));
	if (params->msgp == NULL) {
		return (RDR_MEM_ALLOC);
	}

	/* set params->msgp->message_routine using memcpy */
	(void) memcpy((void*)params->msgp,
	    &(change_state_data.msg_callback_id), sizeof (unsigned long));
	params->msgp->appdata_ptr =
	    (void*)change_state_data.msg_appdata_ptr;

	if (change_state_data.error_msg_ctl == RDR_GENERATE_ERR_MSGS) {
		params->errstring = (char **)malloc(sizeof (char *));
		if (params->errstring == NULL) {
			return (RDR_MEM_ALLOC);
		}
		*(params->errstring) = NULL;
	} else {	/* error_msg_ctl == RDR_DONT_GENERATE_ERR_MSGS */
		params->errstring = NULL;
	}
	params->flags = change_state_data.flags;
	params->timeval = change_state_data.timeval;
	params->retries = change_state_data.retries;

	return (RDR_OK);
}


/*
 * pack_change_state_reply:
 *
 * Handle packing a change state reply message.
 */
static int
pack_change_state_reply(change_state_params_t *params, char **buf,
    int *buf_size)
{
	int				i;
	char				*bufptr;
	rdr_change_state_reply_t	change_state_data;
	rdr_variable_message_info_t	var_msg_info;


	(void) memset(&var_msg_info, 0, sizeof (rdr_variable_message_info_t));

	if ((params == NULL) || (buf == NULL) || (buf_size == NULL)) {
		return (RDR_ERROR);
	}

	/*
	 * Set variable length fields (size info)
	 */
	if (find_errstring_sizes(params->errstring, &var_msg_info)) {
		return (RDR_ERROR);
	}

	/*
	 * Collect size info specific to the change_state reply
	 * message and allocate a buffer
	 */
	*buf_size = sizeof (rdr_change_state_reply_t);
	*buf_size += var_msg_info.errstring_strlen;
	*buf_size += var_msg_info.errstring_pad_sz;

	*buf = (char *)malloc(*buf_size);
	if (*buf == NULL) {
		return (RDR_MEM_ALLOC);
	}

	/*
	 * Set fixed address labels by name
	 */
	change_state_data.errstring_size = var_msg_info.errstring_strlen +
	    var_msg_info.errstring_pad_sz;

	/*
	 * Set variable information using memcpy
	 */
	bufptr = *buf;

	(void) memcpy(bufptr, &change_state_data,
	    sizeof (rdr_change_state_reply_t));
	bufptr += sizeof (rdr_change_state_reply_t);

	if ((params->errstring != NULL) && (*(params->errstring) != NULL)) {
		(void) memcpy(bufptr, *(params->errstring),
		    var_msg_info.errstring_strlen);
		bufptr += var_msg_info.errstring_strlen;
		for (i = 0; i < var_msg_info.errstring_pad_sz; i++) {
			bufptr[i] = 0;
		}
		bufptr += var_msg_info.errstring_pad_sz;
	}

	return (RDR_OK);
}


/*
 * unpack_change_state_reply:
 *
 * Handle unpacking a change state reply message.
 */
static int
unpack_change_state_reply(change_state_params_t *params, const char *buf)
{
	char				*bufptr;
	rdr_change_state_reply_t	change_state_data;

	if ((params == NULL) || (buf == NULL)) {
		return (RDR_ERROR);
	}

	bufptr = (char *)buf;
	(void) memcpy(&change_state_data, bufptr,
	    sizeof (rdr_change_state_reply_t));
	bufptr += sizeof (rdr_change_state_reply_t);

	/*
	 * handle getting the errstring
	 */
	params->errstring = (char **)malloc(sizeof (char *));
	if (params->errstring == NULL) {
		return (RDR_MEM_ALLOC);
	}
	if (get_string_from_buf(params->errstring,
	    change_state_data.errstring_size, bufptr)) {
		return (RDR_ERROR);
	}
	bufptr += change_state_data.errstring_size;

	return (RDR_OK);
}


/*
 * pack_private_func_request:
 *
 * Handle packing a private function request message.
 */
static int
pack_private_func_request(private_func_params_t *params, char **buf,
    int *buf_size)
{
	int				i;
	char				*bufptr;
	rdr_private_func_t		private_func_data;
	rdr_variable_message_info_t	var_msg_info;


	if ((params == NULL) || (buf == NULL) || (buf_size == NULL)) {
		return (RDR_ERROR);
	}

	(void) memset(&var_msg_info, 0, sizeof (rdr_variable_message_info_t));

	/*
	 * Set variable length fields and make a call to partially
	 * pack it.
	 */
	if (pack_ap_ids(params->num_ap_ids, params->ap_ids, &var_msg_info)) {
		cleanup_variable_ap_id_info(&var_msg_info);
		return (RDR_ERROR);
	}
	if (find_options_sizes(params->options, &var_msg_info)) {
		cleanup_variable_ap_id_info(&var_msg_info);
		return (RDR_ERROR);
	}
	if (find_function_sizes(params->function, &var_msg_info)) {
		cleanup_variable_ap_id_info(&var_msg_info);
		return (RDR_ERROR);
	}

	/*
	 * Collect size info specific to the private_func request
	 * message and allocate a buffer
	 */
	*buf_size = sizeof (rdr_private_func_t);
	*buf_size += var_msg_info.ap_id_int_size;
	*buf_size += var_msg_info.ap_id_char_size;
	*buf_size += var_msg_info.options_strlen;
	*buf_size += var_msg_info.options_pad_sz;
	*buf_size += var_msg_info.function_strlen;
	*buf_size += var_msg_info.function_pad_sz;

	*buf = (char *)malloc(*buf_size);
	if (*buf == NULL) {
		cleanup_variable_ap_id_info(&var_msg_info);
		return (RDR_MEM_ALLOC);
	}

	/*
	 * Set fixed address labels by name
	 */
	private_func_data.num_ap_ids = params->num_ap_ids;
	private_func_data.ap_id_char_size = var_msg_info.ap_id_char_size;
	private_func_data.options_size = var_msg_info.options_strlen +
	    var_msg_info.options_pad_sz;
	private_func_data.function_size = var_msg_info.function_strlen +
	    var_msg_info.function_pad_sz;

	if (params->confp != NULL) {
		private_func_data.confirm_callback_id =
		    (unsigned long)params->confp->confirm;
		private_func_data.confirm_appdata_ptr =
		    (unsigned long)params->confp->appdata_ptr;
	} else {
		private_func_data.confirm_callback_id = 0;
		private_func_data.confirm_appdata_ptr = 0;
	}
	if (params->msgp != NULL) {
		private_func_data.msg_callback_id =
		    (unsigned long)params->msgp->message_routine;
		private_func_data.msg_appdata_ptr =
		    (unsigned long)params->msgp->appdata_ptr;
	} else {
		private_func_data.msg_callback_id = 0;
		private_func_data.msg_appdata_ptr = 0;
	}

	private_func_data.flags = params->flags;

	if (params->errstring != NULL) {
		private_func_data.error_msg_ctl = RDR_GENERATE_ERR_MSGS;
	} else {
		private_func_data.error_msg_ctl = RDR_DONT_GENERATE_ERR_MSGS;
	}

	/*
	 * Set variable information using memcpy
	 */
	bufptr = *buf;

	(void) memcpy(bufptr, &private_func_data, sizeof (rdr_private_func_t));
	bufptr += sizeof (rdr_private_func_t);

	if (var_msg_info.ap_id_sizes != NULL) {
		(void) memcpy(bufptr, var_msg_info.ap_id_sizes,
		    var_msg_info.ap_id_int_size);
		bufptr += var_msg_info.ap_id_int_size;
	}

	if (var_msg_info.ap_id_chars != NULL) {
		(void) memcpy(bufptr, var_msg_info.ap_id_chars,
		    var_msg_info.ap_id_char_size);
		bufptr += var_msg_info.ap_id_char_size;
	}

	if (params->options != NULL) {
		(void) memcpy(bufptr, params->options,
		    var_msg_info.options_strlen);
		bufptr += var_msg_info.options_strlen;
		for (i = 0; i < var_msg_info.options_pad_sz; i++) {
			bufptr[i] = 0;
		}
		bufptr += var_msg_info.options_pad_sz;
	}

	if (params->function != NULL) {
		(void) memcpy(bufptr, params->function,
		    var_msg_info.function_strlen);
		bufptr += var_msg_info.function_strlen;
		for (i = 0; i < var_msg_info.function_pad_sz; i++) {
			bufptr[i] = 0;
		}
		bufptr += var_msg_info.function_pad_sz;
	}

	cleanup_variable_ap_id_info(&var_msg_info);

	return (RDR_OK);
}


/*
 * unpack_private_func_request:
 *
 * Handle unpacking a private function request message.
 */
static int
unpack_private_func_request(private_func_params_t *params, const char *buf)
{
	char				*bufptr;
	rdr_variable_message_info_t	var_msg_info;
	rdr_private_func_t		private_func_data;


	(void) memset(&var_msg_info, 0, sizeof (rdr_variable_message_info_t));

	if ((params == NULL) || (buf == NULL)) {
		return (RDR_ERROR);
	}

	bufptr = (char *)buf;
	(void) memcpy(&private_func_data, bufptr, sizeof (rdr_private_func_t));
	bufptr += sizeof (rdr_private_func_t);

	/*
	 * handle getting the ap_ids
	 */
	var_msg_info.ap_id_char_size = private_func_data.ap_id_char_size;
	if (get_ap_ids_from_buf((char ***)&(params->ap_ids),
	    private_func_data.num_ap_ids, &var_msg_info, bufptr)) {
		return (RDR_ERROR);
	}
	bufptr += var_msg_info.ap_id_int_size;
	bufptr += var_msg_info.ap_id_char_size;

	/*
	 * handle getting the options and function
	 */
	if (get_string_from_buf(&(params->options),
	    private_func_data.options_size, bufptr)) {
		return (RDR_ERROR);
	}
	bufptr += private_func_data.options_size;

	if (get_string_from_buf(&(params->function),
	    private_func_data.function_size, bufptr)) {
		return (RDR_ERROR);
	}
	bufptr += private_func_data.function_size;

	/*
	 * Set fixed address labels by name
	 */
	params->num_ap_ids = private_func_data.num_ap_ids;

	params->confp = (struct cfga_confirm *)
	    malloc(sizeof (struct cfga_confirm));
	if (params->confp == NULL) {
		return (RDR_MEM_ALLOC);
	}

	/* set params->confp->confirm using memcpy */
	(void) memcpy((void*)params->confp,
	    &(private_func_data.confirm_callback_id), sizeof (unsigned long));
	params->confp->appdata_ptr =
	    (void*)private_func_data.confirm_appdata_ptr;

	params->msgp = (struct cfga_msg *)malloc(sizeof (struct cfga_msg));
	if (params->msgp == NULL) {
		return (RDR_MEM_ALLOC);
	}

	/* set params->msgp->message_routine using memcpy */
	(void) memcpy((void*)params->msgp,
	    &(private_func_data.msg_callback_id), sizeof (unsigned long));
	params->msgp->appdata_ptr =
	    (void*)private_func_data.msg_appdata_ptr;

	if (private_func_data.error_msg_ctl == RDR_GENERATE_ERR_MSGS) {
		params->errstring = (char **)malloc(sizeof (char *));
		if (params->errstring == NULL) {
			return (RDR_MEM_ALLOC);
		}
		*(params->errstring) = NULL;
	} else {	/* error_msg_ctl == RDR_DONT_GENERATE_ERR_MSGS */
		params->errstring = NULL;
	}
	params->flags = private_func_data.flags;

	return (RDR_OK);
}


/*
 * pack_private_func_reply:
 *
 * Handle packing a private function reply message.
 */
static int
pack_private_func_reply(private_func_params_t *params, char **buf,
    int *buf_size)
{
	int				i;
	char				*bufptr;
	rdr_private_func_reply_t	private_func_data;
	rdr_variable_message_info_t	var_msg_info;


	(void) memset(&var_msg_info, 0, sizeof (rdr_variable_message_info_t));

	if ((params == NULL) || (buf == NULL) || (buf_size == NULL)) {
		return (RDR_ERROR);
	}

	/*
	 * Set variable length fields (size info)
	 */
	if (find_errstring_sizes(params->errstring, &var_msg_info)) {
		return (RDR_ERROR);
	}

	/*
	 * Collect size info specific to the private_func reply
	 * message and allocate a buffer
	 */
	*buf_size = sizeof (rdr_private_func_reply_t);
	*buf_size += var_msg_info.errstring_strlen;
	*buf_size += var_msg_info.errstring_pad_sz;

	*buf = (char *)malloc(*buf_size);
	if (*buf == NULL) {
		return (RDR_MEM_ALLOC);
	}

	/*
	 * Set fixed address labels by name
	 */
	private_func_data.errstring_size = var_msg_info.errstring_strlen +
	    var_msg_info.errstring_pad_sz;

	/*
	 * Set variable information using memcpy
	 */
	bufptr = *buf;

	(void) memcpy(bufptr, &private_func_data,
	    sizeof (rdr_private_func_reply_t));
	bufptr += sizeof (rdr_private_func_reply_t);
	if ((params->errstring != NULL) && (*(params->errstring) != NULL)) {
		(void) memcpy(bufptr, *(params->errstring),
		    var_msg_info.errstring_strlen);
		bufptr += var_msg_info.errstring_strlen;
		for (i = 0; i < var_msg_info.errstring_pad_sz; i++) {
			bufptr[i] = 0;
		}
		bufptr += var_msg_info.errstring_pad_sz;
	}

	return (RDR_OK);
}


/*
 * unpack_private_func_reply:
 *
 * Handle unpacking a private function reply message.
 */
static int
unpack_private_func_reply(private_func_params_t *params, const char *buf)
{
	char				*bufptr;
	rdr_private_func_reply_t	private_func_data;

	if ((params == NULL) || (buf == NULL)) {
		return (RDR_ERROR);
	}

	bufptr = (char *)buf;
	(void) memcpy(&private_func_data, bufptr,
	    sizeof (rdr_private_func_reply_t));
	bufptr += sizeof (rdr_private_func_reply_t);

	/*
	 * handle getting the errstring
	 */
	params->errstring = (char **)malloc(sizeof (char *));
	if (params->errstring == NULL) {
		return (RDR_MEM_ALLOC);
	}
	if (get_string_from_buf(params->errstring,
	    private_func_data.errstring_size, bufptr)) {
		return (RDR_ERROR);
	}
	bufptr += private_func_data.errstring_size;

	return (RDR_OK);
}


/*
 * pack_test_request:
 *
 * Handle packing a test request message.
 */
static int
pack_test_request(test_params_t *params, char **buf, int *buf_size)
{
	int				i;
	char				*bufptr;
	rdr_test_t			test_data;
	rdr_variable_message_info_t	var_msg_info;


	if ((params == NULL) || (buf == NULL) || (buf_size == NULL)) {
		return (RDR_ERROR);
	}

	(void) memset(&var_msg_info, 0, sizeof (rdr_variable_message_info_t));

	/*
	 * Set variable length fields and make a call to partially
	 * pack it.
	 */
	if (pack_ap_ids(params->num_ap_ids, params->ap_ids, &var_msg_info)) {
		cleanup_variable_ap_id_info(&var_msg_info);
		return (RDR_ERROR);
	}
	if (find_options_sizes(params->options, &var_msg_info)) {
		cleanup_variable_ap_id_info(&var_msg_info);
		return (RDR_ERROR);
	}

	/*
	 * Collect size info specific to the test request
	 * message and allocate a buffer
	 */
	*buf_size = sizeof (rdr_test_t);
	*buf_size += var_msg_info.ap_id_int_size;
	*buf_size += var_msg_info.ap_id_char_size;
	*buf_size += var_msg_info.options_strlen;
	*buf_size += var_msg_info.options_pad_sz;

	*buf = (char *)malloc(*buf_size);
	if (*buf == NULL) {
		cleanup_variable_ap_id_info(&var_msg_info);
		return (RDR_MEM_ALLOC);
	}

	/*
	 * Set fixed address labels by name
	 */
	test_data.num_ap_ids = params->num_ap_ids;
	test_data.ap_id_char_size = var_msg_info.ap_id_char_size;
	test_data.options_size = var_msg_info.options_strlen +
	    var_msg_info.options_pad_sz;

	if (params->msgp != NULL) {
		test_data.msg_callback_id =
		    (unsigned long)params->msgp->message_routine;
		test_data.msg_appdata_ptr =
		    (unsigned long)params->msgp->appdata_ptr;
	} else {
		test_data.msg_callback_id = 0;
		test_data.msg_appdata_ptr = 0;
	}

	test_data.flags = params->flags;

	if (params->errstring != NULL) {
		test_data.error_msg_ctl = RDR_GENERATE_ERR_MSGS;
	} else {
		test_data.error_msg_ctl = RDR_DONT_GENERATE_ERR_MSGS;
	}

	/*
	 * Set variable information using memcpy
	 */
	bufptr = *buf;

	(void) memcpy(bufptr, &test_data, sizeof (rdr_test_t));
	bufptr += sizeof (rdr_test_t);

	if (var_msg_info.ap_id_sizes != NULL) {
		(void) memcpy(bufptr, var_msg_info.ap_id_sizes,
		    var_msg_info.ap_id_int_size);
		bufptr += var_msg_info.ap_id_int_size;
	}

	if (var_msg_info.ap_id_chars != NULL) {
		(void) memcpy(bufptr, var_msg_info.ap_id_chars,
		    var_msg_info.ap_id_char_size);
		bufptr += var_msg_info.ap_id_char_size;
	}

	if (params->options != NULL) {
		(void) memcpy(bufptr, params->options,
		    var_msg_info.options_strlen);
		bufptr += var_msg_info.options_strlen;
		for (i = 0; i < var_msg_info.options_pad_sz; i++) {
			bufptr[i] = 0;
		}
		bufptr += var_msg_info.options_pad_sz;
	}

	cleanup_variable_ap_id_info(&var_msg_info);

	return (RDR_OK);
}


/*
 * unpack_test_request:
 *
 * Handle unpacking a test request message.
 */
static int
unpack_test_request(test_params_t *params, const char *buf)
{
	char				*bufptr;
	rdr_variable_message_info_t	var_msg_info;
	rdr_test_t			test_data;


	if ((params == NULL) || (buf == NULL)) {
		return (RDR_ERROR);
	}

	(void) memset(&var_msg_info, 0, sizeof (rdr_variable_message_info_t));

	bufptr = (char *)buf;
	(void) memcpy(&test_data, bufptr, sizeof (rdr_test_t));
	bufptr += sizeof (rdr_test_t);

	/*
	 * handle getting the ap_ids
	 */
	var_msg_info.ap_id_char_size = test_data.ap_id_char_size;
	if (get_ap_ids_from_buf((char ***)&(params->ap_ids),
	    test_data.num_ap_ids, &var_msg_info, bufptr)) {
		return (RDR_ERROR);
	}
	bufptr += var_msg_info.ap_id_int_size;
	bufptr += var_msg_info.ap_id_char_size;

	/*
	 * handle getting the options
	 */
	if (get_string_from_buf(&(params->options),
	    test_data.options_size, bufptr)) {
		return (RDR_ERROR);
	}
	bufptr += test_data.options_size;

	/*
	 * Set fixed address labels by name
	 */
	params->num_ap_ids = test_data.num_ap_ids;

	params->msgp = (struct cfga_msg *)malloc(sizeof (struct cfga_msg));
	if (params->msgp == NULL) {
		return (RDR_MEM_ALLOC);
	}

	/* set params->msgp->message_routine using memcpy */
	(void) memcpy((void*)params->msgp,
	    &(test_data.msg_callback_id), sizeof (unsigned long));
	params->msgp->appdata_ptr =
	    (void*)test_data.msg_appdata_ptr;

	if (test_data.error_msg_ctl == RDR_GENERATE_ERR_MSGS) {
		params->errstring = (char **)malloc(sizeof (char *));
		if (params->errstring == NULL) {
			return (RDR_MEM_ALLOC);
		}
		*(params->errstring) = NULL;
	} else {	/* error_msg_ctl == RDR_DONT_GENERATE_ERR_MSGS */
		params->errstring = NULL;
	}
	params->flags = test_data.flags;

	return (RDR_OK);
}


/*
 * pack_test_reply:
 *
 * Handle packing a test reply message.
 */
static int
pack_test_reply(test_params_t *params, char **buf, int *buf_size)
{
	int				i;
	char				*bufptr;
	rdr_test_reply_t		test_data;
	rdr_variable_message_info_t	var_msg_info;


	if ((params == NULL) || (buf == NULL) || (buf_size == NULL)) {
		return (RDR_ERROR);
	}

	(void) memset(&var_msg_info, 0, sizeof (rdr_variable_message_info_t));

	/*
	 * Set variable length fields (size info)
	 */
	if (find_errstring_sizes(params->errstring, &var_msg_info)) {
		return (RDR_ERROR);
	}

	/*
	 * Collect size info specific to the test reply
	 * message and allocate a buffer
	 */
	*buf_size = sizeof (rdr_test_reply_t);
	*buf_size += var_msg_info.errstring_strlen;
	*buf_size += var_msg_info.errstring_pad_sz;

	*buf = (char *)malloc(*buf_size);
	if (*buf == NULL) {
		return (RDR_MEM_ALLOC);
	}

	/*
	 * Set fixed address labels by name
	 */
	test_data.errstring_size = var_msg_info.errstring_strlen +
	    var_msg_info.errstring_pad_sz;

	/*
	 * Set variable information using memcpy
	 */
	bufptr = *buf;

	(void) memcpy(bufptr, &test_data, sizeof (rdr_test_reply_t));
	bufptr += sizeof (rdr_test_reply_t);
	if ((params->errstring != NULL) && (*(params->errstring) != NULL)) {
		(void) memcpy(bufptr, *(params->errstring),
		    var_msg_info.errstring_strlen);
		bufptr += var_msg_info.errstring_strlen;
		for (i = 0; i < var_msg_info.errstring_pad_sz; i++) {
			bufptr[i] = 0;
		}
		bufptr += var_msg_info.errstring_pad_sz;
	}

	return (RDR_OK);
}


/*
 * unpack_test_reply:
 *
 * Handle unpacking a test reply message.
 */
static int
unpack_test_reply(test_params_t *params, const char *buf)
{
	char			*bufptr;
	rdr_test_reply_t	test_data;


	if ((params == NULL) || (buf == NULL)) {
		return (RDR_ERROR);
	}

	bufptr = (char *)buf;
	(void) memcpy(&test_data, bufptr, sizeof (rdr_test_reply_t));
	bufptr += sizeof (rdr_test_reply_t);

	/*
	 * handle getting the errstring
	 */
	params->errstring = (char **)malloc(sizeof (char *));
	if (params->errstring == NULL) {
		return (RDR_MEM_ALLOC);
	}
	if (get_string_from_buf(params->errstring,
	    test_data.errstring_size, bufptr)) {
		return (RDR_ERROR);
	}
	bufptr += test_data.errstring_size;

	return (RDR_OK);
}


/*
 * pack_list_ext_request:
 *
 * Handle packing a list request message.
 */
static int
pack_list_ext_request(list_ext_params_t *params, char **buf, int *buf_size)
{
	int				i;
	char				*bufptr;
	rdr_list_ext_t			list_ext_data;
	rdr_variable_message_info_t	var_msg_info;


	if ((params == NULL) || (buf == NULL) || (buf_size == NULL)) {
		return (RDR_ERROR);
	}

	(void) memset(&var_msg_info, 0, sizeof (rdr_variable_message_info_t));

	/*
	 * Set variable length fields and make a call to partially
	 * pack it.
	 */
	if (pack_ap_ids(params->num_ap_ids, params->ap_ids, &var_msg_info)) {
		cleanup_variable_ap_id_info(&var_msg_info);
		return (RDR_ERROR);
	}
	if (find_options_sizes(params->options, &var_msg_info)) {
		cleanup_variable_ap_id_info(&var_msg_info);
		return (RDR_ERROR);
	}
	if (find_listopts_sizes(params->listopts, &var_msg_info)) {
		cleanup_variable_ap_id_info(&var_msg_info);
		return (RDR_ERROR);
	}


	/*
	 * Collect size info specific to the list_ext request
	 * message and allocate a buffer
	 */
	*buf_size = sizeof (rdr_list_ext_t);
	*buf_size += var_msg_info.ap_id_int_size;
	*buf_size += var_msg_info.ap_id_char_size;
	*buf_size += var_msg_info.options_strlen;
	*buf_size += var_msg_info.options_pad_sz;
	*buf_size += var_msg_info.listopts_strlen;
	*buf_size += var_msg_info.listopts_pad_sz;

	*buf = (char *)malloc(*buf_size);
	if (*buf == NULL) {
		cleanup_variable_ap_id_info(&var_msg_info);
		return (RDR_MEM_ALLOC);
	}

	/*
	 * Set fixed address labels by name
	 */
	list_ext_data.num_ap_ids = params->num_ap_ids;
	list_ext_data.ap_id_char_size = var_msg_info.ap_id_char_size;
	list_ext_data.options_size = var_msg_info.options_strlen +
	    var_msg_info.options_pad_sz;
	list_ext_data.listopts_size = var_msg_info.listopts_strlen +
	    var_msg_info.listopts_pad_sz;
	if (params->errstring != NULL) {
		list_ext_data.error_msg_ctl = RDR_GENERATE_ERR_MSGS;
	} else {
		list_ext_data.error_msg_ctl = RDR_DONT_GENERATE_ERR_MSGS;
	}
	if ((params->num_ap_ids != 0) || (params->ap_ids != NULL)) {
		list_ext_data.list_msg_ctl = RDR_LIST_ONLY_PARAM_APS;
	} else {
		list_ext_data.list_msg_ctl = RDR_LIST_ALL_APS;
	}
	list_ext_data.flags = params->flags;
	list_ext_data.permissions = params->permissions;

	/*
	 * Set variable information using memcpy
	 */
	bufptr = *buf;

	(void) memcpy(bufptr, &list_ext_data, sizeof (rdr_list_ext_t));
	bufptr += sizeof (rdr_list_ext_t);

	if (var_msg_info.ap_id_sizes != NULL) {
		(void) memcpy(bufptr, var_msg_info.ap_id_sizes,
		    var_msg_info.ap_id_int_size);
		bufptr += var_msg_info.ap_id_int_size;
	}

	if (var_msg_info.ap_id_chars != NULL) {
		(void) memcpy(bufptr, var_msg_info.ap_id_chars,
		    var_msg_info.ap_id_char_size);
		bufptr += var_msg_info.ap_id_char_size;
	}

	if (params->options != NULL) {
		(void) memcpy(bufptr, params->options,
		    var_msg_info.options_strlen);
		bufptr += var_msg_info.options_strlen;
		for (i = 0; i < var_msg_info.options_pad_sz; i++) {
			bufptr[i] = 0;
		}
		bufptr += var_msg_info.options_pad_sz;
	}

	if (params->listopts != NULL) {
		(void) memcpy(bufptr, params->listopts,
		    var_msg_info.listopts_strlen);
		bufptr += var_msg_info.listopts_strlen;
		for (i = 0; i < var_msg_info.listopts_pad_sz; i++) {
			bufptr[i] = 0;
		}
		bufptr += var_msg_info.listopts_pad_sz;
	}

	cleanup_variable_ap_id_info(&var_msg_info);

	return (RDR_OK);
}


/*
 * unpack_list_ext_request:
 *
 * Handle unpacking a list request message.
 */
static int
unpack_list_ext_request(list_ext_params_t *params, const char *buf)
{
	char				*bufptr;
	rdr_variable_message_info_t	var_msg_info;
	rdr_list_ext_t			list_ext_data;


	if ((params == NULL) || (buf == NULL)) {
		return (RDR_ERROR);
	}

	(void) memset(&var_msg_info, 0, sizeof (rdr_variable_message_info_t));

	bufptr = (char *)buf;
	(void) memcpy(&list_ext_data, bufptr, sizeof (rdr_list_ext_t));
	bufptr += sizeof (rdr_list_ext_t);

	/*
	 * handle getting the ap_ids
	 */
	var_msg_info.ap_id_char_size = list_ext_data.ap_id_char_size;
	if (get_ap_ids_from_buf(&(params->ap_ids), list_ext_data.num_ap_ids,
	    &var_msg_info, bufptr)) {
		return (RDR_ERROR);
	}
	bufptr += var_msg_info.ap_id_int_size;
	bufptr += var_msg_info.ap_id_char_size;

	/*
	 * handle getting the options
	 */
	if (get_string_from_buf(&(params->options),
	    list_ext_data.options_size, bufptr)) {
		return (RDR_ERROR);
	}
	bufptr += list_ext_data.options_size;

	/*
	 * handle getting the listopts
	 */
	if (get_string_from_buf(&(params->listopts),
	    list_ext_data.listopts_size, bufptr)) {
		return (RDR_ERROR);
	}
	bufptr += list_ext_data.listopts_size;

	/*
	 * Set fixed address labels by name
	 */
	params->num_ap_ids = list_ext_data.num_ap_ids;

	params->ap_id_list = (rdr_list_t **)malloc(sizeof (rdr_list_t *));
	if (params->ap_id_list == NULL) {
		return (RDR_MEM_ALLOC);
	}
	*(params->ap_id_list) = NULL;

	params->nlist = (int *)malloc(sizeof (int));
	if (params->nlist == NULL) {
		return (RDR_MEM_ALLOC);
	}
	if (list_ext_data.error_msg_ctl == RDR_GENERATE_ERR_MSGS) {
		params->errstring = (char **)malloc(sizeof (char *));
		if (params->errstring == NULL) {
			return (RDR_MEM_ALLOC);
		}
		*(params->errstring) = NULL;
	} else {	/* error_msg_ctl == RDR_DONT_GENERATE_ERR_MSGS */
		params->errstring = NULL;
	}
	params->flags = list_ext_data.flags;
	params->permissions = list_ext_data.permissions;

	return (RDR_OK);
}


/*
 * pack_list_ext_reply:
 *
 * Handle packing a list reply message.
 */
static int
pack_list_ext_reply(list_ext_params_t *params, char **buf, int *buf_size)
{
	int				i;
	char				*bufptr;
	rdr_list_ext_reply_t		list_ext_data;
	rdr_variable_message_info_t	var_msg_info;
	int				list_data_size;


	(void) memset(&var_msg_info, 0, sizeof (rdr_variable_message_info_t));

	if ((params == NULL) || (buf == NULL) || (buf_size == NULL)) {
		return (RDR_ERROR);
	}

	/*
	 * Set variable length fields (size info)
	 */
	if (find_errstring_sizes(params->errstring, &var_msg_info)) {
		return (RDR_ERROR);
	}

	if (params->nlist == NULL) {
		list_data_size = 0;
	} else {
		list_data_size = *(params->nlist) * sizeof (rdr_list_t);
	}

	/*
	 * Collect size info specific to the list_ext reply
	 * message and allocate a buffer
	 */
	*buf_size = sizeof (rdr_list_ext_reply_t);
	*buf_size += list_data_size;
	*buf_size += var_msg_info.errstring_strlen;
	*buf_size += var_msg_info.errstring_pad_sz;

	*buf = (char *)malloc(*buf_size);
	if (*buf == NULL) {
		return (RDR_MEM_ALLOC);
	}

	/*
	 * Set fixed address labels by name
	 */
	list_ext_data.num_ap_ids = (params->nlist) ? *(params->nlist) : 0;
	list_ext_data.errstring_size = var_msg_info.errstring_strlen +
	    var_msg_info.errstring_pad_sz;

	/*
	 * Set variable information using memcpy
	 */
	bufptr = *buf;

	(void) memcpy(bufptr, &list_ext_data, sizeof (rdr_list_ext_reply_t));
	bufptr += sizeof (rdr_list_ext_reply_t);

	if ((params->ap_id_list != NULL) && (*(params->ap_id_list) != NULL)) {
		(void) memcpy(bufptr, *(params->ap_id_list), list_data_size);
		bufptr += list_data_size;
	} else if (list_data_size) {
		/*
		 * Something is out of sync. We were expecting
		 * some data to copy, but instead we found a
		 * NULL pointer.
		 */
		(void) free((void *)*buf);
		*buf = NULL;
		return (RDR_ERROR);
	}

	if ((params->errstring != NULL) && (*(params->errstring) != NULL)) {
		(void) memcpy(bufptr, *(params->errstring),
		    var_msg_info.errstring_strlen);
		bufptr += var_msg_info.errstring_strlen;
		for (i = 0; i < var_msg_info.errstring_pad_sz; i++) {
			bufptr[i] = 0;
		}
		bufptr += var_msg_info.errstring_pad_sz;
	}

	return (RDR_OK);
}


/*
 * unpack_list_ext_reply:
 *
 * Handle unpacking a list reply message.
 */
static int
unpack_list_ext_reply(list_ext_params_t *params, const char *buf)
{
	int			list_data_size;
	char			*bufptr;
	rdr_list_ext_reply_t	list_ext_data;


	if ((params == NULL) || (buf == NULL)) {
		return (RDR_ERROR);
	}

	bufptr = (char *)buf;
	(void) memcpy(&list_ext_data, bufptr, sizeof (rdr_list_ext_reply_t));
	bufptr += sizeof (rdr_list_ext_reply_t);

	/*
	 * handle getting the ap_id rcfga_list_data_t's.
	 */
	if (list_ext_data.num_ap_ids > 0) {
		params->nlist = (int *)malloc(sizeof (int));
		if (params->nlist == NULL) {
			return (RDR_MEM_ALLOC);
		}
		*(params->nlist) = list_ext_data.num_ap_ids;
		params->ap_id_list = (rdr_list_t **)
		    malloc(sizeof (rdr_list_t *));
		if (params->ap_id_list == NULL) {
			return (RDR_MEM_ALLOC);
		}
		*(params->ap_id_list) = (rdr_list_t *)
		    malloc(sizeof (rdr_list_t) * list_ext_data.num_ap_ids);
		if (*(params->ap_id_list) == NULL) {
			return (RDR_MEM_ALLOC);
		}
		list_data_size = list_ext_data.num_ap_ids * sizeof (rdr_list_t);
		(void) memcpy(*(params->ap_id_list), bufptr, list_data_size);
		bufptr += list_data_size;
	}

	/*
	 * handle getting the errstring
	 */
	params->errstring = (char **)malloc(sizeof (char *));
	if (params->errstring == NULL) {
		return (RDR_MEM_ALLOC);
	}
	if (get_string_from_buf(params->errstring,
	    list_ext_data.errstring_size, bufptr)) {
		return (RDR_ERROR);
	}
	bufptr += list_ext_data.errstring_size;

	return (RDR_OK);
}


/*
 * pack_help_request:
 *
 * Handle packing a help request message.
 */
static int
pack_help_request(help_params_t *params, char **buf, int *buf_size)
{
	int				i;
	char				*bufptr;
	rdr_help_t			help_data;
	rdr_variable_message_info_t	var_msg_info;


	(void) memset(&var_msg_info, 0, sizeof (rdr_variable_message_info_t));

	if ((params == NULL) || (buf == NULL) || (buf_size == NULL)) {
		return (RDR_ERROR);
	}

	/*
	 * Set variable length fields and make a call to partially
	 * pack it.
	 */
	if (pack_ap_ids(params->num_ap_ids, params->ap_ids, &var_msg_info)) {
		cleanup_variable_ap_id_info(&var_msg_info);
		return (RDR_ERROR);
	}
	if (find_options_sizes(params->options, &var_msg_info)) {
		cleanup_variable_ap_id_info(&var_msg_info);
		return (RDR_ERROR);
	}

	/*
	 * Collect size info specific to the help request message and
	 * and allocate a buffer
	 */
	*buf_size = sizeof (rdr_help_t);
	*buf_size += var_msg_info.ap_id_int_size;
	*buf_size += var_msg_info.ap_id_char_size;
	*buf_size += var_msg_info.options_strlen;
	*buf_size += var_msg_info.options_pad_sz;

	*buf = (char *)malloc(*buf_size);
	if (*buf == NULL) {
		cleanup_variable_ap_id_info(&var_msg_info);
		return (RDR_MEM_ALLOC);
	}

	/*
	 * Set fixed address labels by name
	 */
	help_data.num_ap_ids = params->num_ap_ids;
	help_data.ap_id_char_size = var_msg_info.ap_id_char_size;
	help_data.options_size = var_msg_info.options_strlen +
	    var_msg_info.options_pad_sz;

	if (params->msgp != NULL) {
		help_data.msg_callback_id =
		    (unsigned long)params->msgp->message_routine;
		help_data.msg_appdata_ptr =
		    (unsigned long)params->msgp->appdata_ptr;
	} else {
		help_data.msg_callback_id = 0;
		help_data.msg_appdata_ptr = 0;
	}

	help_data.flags = params->flags;

	/*
	 * Set variable information using memcpy
	 */
	bufptr = *buf;

	(void) memcpy(bufptr, &help_data, sizeof (rdr_help_t));
	bufptr += sizeof (rdr_help_t);

	if (var_msg_info.ap_id_sizes != NULL) {
		(void) memcpy(bufptr, var_msg_info.ap_id_sizes,
		    var_msg_info.ap_id_int_size);
		bufptr += var_msg_info.ap_id_int_size;
	}

	if (var_msg_info.ap_id_chars != NULL) {
		(void) memcpy(bufptr, var_msg_info.ap_id_chars,
		    var_msg_info.ap_id_char_size);
		bufptr += var_msg_info.ap_id_char_size;
	}

	if (params->options != NULL) {
		(void) memcpy(bufptr, params->options,
		    var_msg_info.options_strlen);
		bufptr += var_msg_info.options_strlen;
		for (i = 0; i < var_msg_info.options_pad_sz; i++) {
			bufptr[i] = 0;
		}
		bufptr += var_msg_info.options_pad_sz;
	}

	cleanup_variable_ap_id_info(&var_msg_info);

	return (RDR_OK);
}


/*
 * unpack_help_request:
 *
 * Handle unpacking a help request message.
 */
static int
unpack_help_request(help_params_t *params, const char *buf)
{
	char				*bufptr;
	rdr_variable_message_info_t	var_msg_info;
	rdr_help_t			help_data;


	if ((params == NULL) || (buf == NULL)) {
		return (RDR_ERROR);
	}

	(void) memset(&var_msg_info, 0, sizeof (rdr_variable_message_info_t));

	bufptr = (char *)buf;
	(void) memcpy(&help_data, bufptr, sizeof (rdr_help_t));
	bufptr += sizeof (rdr_help_t);

	/*
	 * handle getting the ap_ids
	 */
	var_msg_info.ap_id_char_size = help_data.ap_id_char_size;
	if (get_ap_ids_from_buf((char ***)&(params->ap_ids),
	    help_data.num_ap_ids, &var_msg_info, bufptr)) {
		return (RDR_ERROR);
	}
	bufptr += var_msg_info.ap_id_int_size;
	bufptr += var_msg_info.ap_id_char_size;

	/*
	 * handle getting the options
	 */
	if (get_string_from_buf(&(params->options),
	    help_data.options_size, bufptr)) {
		return (RDR_ERROR);
	}
	bufptr += help_data.options_size;

	/*
	 * Set fixed address labels by name
	 */
	params->num_ap_ids = help_data.num_ap_ids;

	params->msgp = (struct cfga_msg *)malloc(sizeof (struct cfga_msg));
	if (params->msgp == NULL) {
		return (RDR_MEM_ALLOC);
	}

	/* set params->msgp->message_routine using memcpy */
	(void) memcpy((void*)params->msgp, &(help_data.msg_callback_id),
	    sizeof (unsigned long));

	params->msgp->appdata_ptr = (void*)help_data.msg_appdata_ptr;
	params->flags = help_data.flags;

	return (RDR_OK);
}


/*
 * pack_ap_id_cmp_request:
 *
 * Handle packing an attachment point comparison request message.
 */
static int
pack_ap_id_cmp_request(ap_id_cmp_params_t *params, char **buf, int *buf_size)
{
	int			i;
	char			*bufptr;
	rdr_ap_id_cmp_t		ap_id_cmp_data;
	int			ap_id1_strlen;
	int			ap_id1_pad_sz;
	int			ap_id2_strlen;
	int			ap_id2_pad_sz;


	if ((params == NULL) || (buf == NULL) || (buf_size == NULL)) {
		return (RDR_ERROR);
	}

	/*
	 * Set variable length fields and make a call to partially
	 * pack it.
	 */
	if (params->ap_log_id1 != NULL) {
		ap_id1_strlen = strlen(params->ap_log_id1) + 1;
		ap_id1_pad_sz = RDR_ALIGN_64_BIT -
		    (ap_id1_strlen % RDR_ALIGN_64_BIT);
	} else {
		ap_id1_strlen = 0;
		ap_id1_pad_sz = 0;
	}

	if (params->ap_log_id2 != NULL) {
		ap_id2_strlen = strlen(params->ap_log_id2) + 1;
		ap_id2_pad_sz = RDR_ALIGN_64_BIT -
		    (ap_id2_strlen % RDR_ALIGN_64_BIT);
	} else {
		ap_id2_strlen = 0;
		ap_id2_pad_sz = 0;
	}

	/*
	 * Collect size info specific to the ap id compare request
	 * message and allocate a buffer
	 */
	*buf_size = sizeof (rdr_ap_id_cmp_t);
	*buf_size += ap_id1_strlen;
	*buf_size += ap_id1_pad_sz;
	*buf_size += ap_id2_strlen;
	*buf_size += ap_id2_pad_sz;

	*buf = (char *)malloc(*buf_size);
	if (*buf == NULL) {
		return (RDR_MEM_ALLOC);
	}

	/*
	 * Set fixed address labels by name
	 */
	ap_id_cmp_data.ap_id1_size = ap_id1_strlen + ap_id1_pad_sz;
	ap_id_cmp_data.ap_id2_size = ap_id2_strlen + ap_id2_pad_sz;


	/*
	 * Set variable information using memcpy
	 */
	bufptr = *buf;

	(void) memcpy(bufptr, &ap_id_cmp_data, sizeof (rdr_ap_id_cmp_t));
	bufptr += sizeof (rdr_ap_id_cmp_t);

	if (params->ap_log_id1 != NULL) {
		(void) memcpy(bufptr, params->ap_log_id1, ap_id1_strlen);
		bufptr += ap_id1_strlen;
		for (i = 0; i < ap_id1_pad_sz; i++) {
			bufptr[i] = 0;
		}
		bufptr += ap_id1_pad_sz;
	}

	if (params->ap_log_id2 != NULL) {
		(void) memcpy(bufptr, params->ap_log_id2, ap_id2_strlen);
		bufptr += ap_id2_strlen;
		for (i = 0; i < ap_id2_pad_sz; i++) {
			bufptr[i] = 0;
		}
		bufptr += ap_id2_pad_sz;
	}

	return (RDR_OK);
}


/*
 * unpack_ap_id_cmp_request:
 *
 * Handle unpacking an attachment point comparison request message.
 */
static int
unpack_ap_id_cmp_request(ap_id_cmp_params_t *params, const char *buf)
{
	char			*bufptr;
	rdr_ap_id_cmp_t		ap_id_cmp_data;


	if ((params == NULL) || (buf == NULL)) {
		return (RDR_ERROR);
	}

	bufptr = (char *)buf;
	(void) memcpy(&ap_id_cmp_data, bufptr, sizeof (rdr_ap_id_cmp_t));
	bufptr += sizeof (rdr_ap_id_cmp_t);

	/*
	 * handle getting the cmp ap ids
	 */
	if (get_string_from_buf(&(params->ap_log_id1),
	    ap_id_cmp_data.ap_id1_size, bufptr)) {
		return (RDR_ERROR);
	}
	bufptr += ap_id_cmp_data.ap_id1_size;

	if (get_string_from_buf(&(params->ap_log_id2),
	    ap_id_cmp_data.ap_id2_size, bufptr)) {
		return (RDR_ERROR);
	}
	bufptr += ap_id_cmp_data.ap_id2_size;

	return (RDR_OK);
}


/*
 * pack_abort_cmd_request:
 *
 * Handle packing an abort request message.
 */
static int
pack_abort_cmd_request(abort_cmd_params_t *params, char **buf, int *buf_size)
{
	rdr_abort_cmd_t		abort_cmd_data;


	if ((params == NULL) || (buf == NULL) || (buf_size == NULL)) {
		return (RDR_ERROR);
	}

	/*
	 * Collect size info specific to the abort cmd request
	 * message and allocate a buffer
	 */
	*buf_size = sizeof (rdr_abort_cmd_t);

	*buf = (char *)malloc(*buf_size);
	if (*buf == NULL) {
		return (RDR_MEM_ALLOC);
	}

	/*
	 * Set fixed session identifier
	 */
	abort_cmd_data.session_id = params->session_id;

	/*
	 * Copy information using memcpy
	 */
	(void) memcpy(*buf, &abort_cmd_data, sizeof (rdr_abort_cmd_t));

	return (RDR_OK);
}


/*
 * unpack_abort_cmd_request:
 *
 * Handle unpacking an abort request message.
 */
static int
unpack_abort_cmd_request(abort_cmd_params_t *params, const char *buf)
{
	rdr_abort_cmd_t		*abort_cmd_datap;


	if ((params == NULL) || (buf == NULL)) {
		return (RDR_ERROR);
	}

	/* LINTED Pointer Cast Alignment Warning */
	abort_cmd_datap = (rdr_abort_cmd_t *)buf;

	/*
	 * copy out the session information
	 */

	params->session_id = abort_cmd_datap->session_id;

	return (RDR_OK);
}


/*
 * pack_confirm_request:
 *
 * Handle packing a confirm callback request.
 */
static int
pack_confirm_request(confirm_callback_params_t *params, char **buf,
    int *buf_size)
{
	int				i;
	char				*bufptr;
	rdr_confirm_callback_t		confirm_callback_data;
	int				message_strlen;
	int				message_pad_sz;


	if ((params == NULL) || (buf == NULL) || (buf_size == NULL)) {
		return (RDR_ERROR);
	}

	/*
	 * Set variable length fields and make a call to partially
	 * pack it.
	 */
	if (params->message != NULL) {
		message_strlen = strlen(params->message) + 1;
		message_pad_sz = RDR_ALIGN_64_BIT -
		    (message_strlen % RDR_ALIGN_64_BIT);
	} else {
		message_strlen = 0;
		message_pad_sz = 0;
	}


	/*
	 * Collect size info specific to the confirm callback request
	 * message and allocate a buffer
	 */
	*buf_size = sizeof (rdr_confirm_callback_t);
	*buf_size += message_strlen;
	*buf_size += message_pad_sz;

	*buf = (char *)malloc(*buf_size);
	if (*buf == NULL) {
		return (RDR_MEM_ALLOC);
	}

	/*
	 * Set fixed address labels by name
	 */
	if (params->confp != NULL) {
		confirm_callback_data.confirm_callback_id =
		    (unsigned long)params->confp->confirm;
		confirm_callback_data.appdata_ptr =
		    (unsigned long)params->confp->appdata_ptr;
	} else {
		confirm_callback_data.confirm_callback_id = 0;
		confirm_callback_data.appdata_ptr = 0;
	}
	confirm_callback_data.message_size = message_strlen + message_pad_sz;

	/*
	 * Set variable information using memcpy
	 */
	bufptr = *buf;
	(void) memcpy(bufptr, &confirm_callback_data,
	    sizeof (rdr_confirm_callback_t));
	bufptr += sizeof (rdr_confirm_callback_t);

	if (params->message != NULL) {
		(void) memcpy(bufptr, params->message, message_strlen);
		bufptr += message_strlen;
		for (i = 0; i < message_pad_sz; i++) {
			bufptr[i] = 0;
		}
		bufptr += message_pad_sz;
	}

	return (RDR_OK);
}


/*
 * unpack_confirm_request:
 *
 * Handle unpacking a confirm callback request.
 */
static int
unpack_confirm_request(confirm_callback_params_t *params, const char *buf)
{
	char				*bufptr;
	rdr_confirm_callback_t		confirm_callback_data;


	if ((params == NULL) || (buf == NULL)) {
		return (RDR_ERROR);
	}

	bufptr = (char *)buf;
	(void) memcpy(&confirm_callback_data, bufptr,
	    sizeof (rdr_confirm_callback_t));
	bufptr += sizeof (rdr_confirm_callback_t);

	/*
	 * handle getting the message text
	 */
	if (get_string_from_buf(&(params->message),
	    confirm_callback_data.message_size, bufptr)) {
		return (RDR_ERROR);
	}
	bufptr += confirm_callback_data.message_size;

	/*
	 * Set fixed address labels by name
	 */
	params->confp = (struct cfga_confirm *)
	    malloc(sizeof (struct cfga_confirm));
	if (params->confp == NULL) {
		return (RDR_MEM_ALLOC);
	}

	/* set params->confp->confirm using memcpy */
	(void) memcpy((void*)params->confp,
	    &(confirm_callback_data.confirm_callback_id),
	    sizeof (unsigned long));

	params->confp->appdata_ptr =
	    (void*)confirm_callback_data.appdata_ptr;

	return (RDR_OK);
}


/*
 * pack_confirm_reply:
 *
 * Handle packing a confirm callback reply.
 */
static int
pack_confirm_reply(confirm_callback_params_t *params, char **buf, int *buf_size)
{
	char				*bufptr;
	rdr_confirm_callback_reply_t	confirm_callback_data;


	if ((params == NULL) || (buf == NULL) || (buf_size == NULL)) {
		return (RDR_ERROR);
	}

	/*
	 * Collect size info specific to the confirm callback reply
	 * message and allocate a buffer
	 */
	*buf_size = sizeof (confirm_callback_params_t);
	*buf = (char *)malloc(*buf_size);
	if (*buf == NULL) {
		return (RDR_MEM_ALLOC);
	}

	/*
	 * Set fixed address labels by name
	 */
	if (params->confp != NULL) {
		confirm_callback_data.confirm_callback_id =
		    (unsigned long)params->confp->confirm;
		confirm_callback_data.appdata_ptr =
		    (unsigned long)params->confp->appdata_ptr;
	} else {
		confirm_callback_data.confirm_callback_id = 0;
		confirm_callback_data.appdata_ptr = 0;
	}
	confirm_callback_data.response = params->response;

	/*
	 * Set variable information using memcpy
	 */
	bufptr = *buf;

	(void) memcpy(bufptr, &confirm_callback_data,
	    sizeof (rdr_confirm_callback_reply_t));

	return (RDR_OK);
}


/*
 * unpack_confirm_reply:
 *
 * Handle unpacking a confirm callback reply.
 */
static int
unpack_confirm_reply(confirm_callback_params_t *params, const char *buf)
{
	char				*bufptr;
	rdr_confirm_callback_reply_t	confirm_callback_data;

	if ((params == NULL) || (buf == NULL)) {
		return (RDR_ERROR);
	}

	bufptr = (char *)buf;
	(void) memcpy(&confirm_callback_data, bufptr,
	    sizeof (rdr_confirm_callback_reply_t));
	bufptr += sizeof (confirm_callback_params_t);

	/*
	 * Set fixed address labels by name
	 */
	params->confp = (struct cfga_confirm *)
	    malloc(sizeof (struct cfga_confirm));
	if (params->confp == NULL) {
		return (RDR_MEM_ALLOC);
	}

	/* set params->confp->confirm using memcpy */
	(void) memcpy((void*)params->confp,
	    &(confirm_callback_data.confirm_callback_id),
	    sizeof (unsigned long));

	params->confp->appdata_ptr =
	    (void*)confirm_callback_data.appdata_ptr;
	params->response = confirm_callback_data.response;

	return (RDR_OK);
}


/*
 * pack_message_request:
 *
 * Handle packing a message callback request.
 */
static int
pack_message_request(msg_callback_params_t *params, char **buf, int *buf_size)
{
	int			i;
	char			*bufptr;
	rdr_msg_callback_t	msg_callback_data;
	int			message_strlen;
	int			message_pad_sz;

	if ((params == NULL) || (buf == NULL) || (buf_size == NULL)) {
		return (RDR_ERROR);
	}

	/*
	 * Set variable length fields and make a call to partially
	 * pack it.
	 */
	if (params->message != NULL) {
		message_strlen = strlen(params->message) + 1;
		message_pad_sz = RDR_ALIGN_64_BIT -
		    (message_strlen % RDR_ALIGN_64_BIT);
	} else {
		message_strlen = 0;
		message_pad_sz = 0;
	}


	/*
	 * Collect size info specific to the message callback request
	 * message and allocate a buffer
	 */
	*buf_size = sizeof (rdr_msg_callback_t);
	*buf_size += message_strlen;
	*buf_size += message_pad_sz;

	*buf = (char *)malloc(*buf_size);
	if (*buf == NULL) {
		return (RDR_MEM_ALLOC);
	}

	/*
	 * Set fixed address labels by name
	 */
	if (params->msgp != NULL) {
		msg_callback_data.msg_callback_id =
		    (unsigned long)params->msgp->message_routine;
		msg_callback_data.appdata_ptr =
		    (unsigned long)params->msgp->appdata_ptr;
	} else {
		msg_callback_data.msg_callback_id = 0;
		msg_callback_data.appdata_ptr = 0;
	}
	msg_callback_data.message_size = message_strlen + message_pad_sz;

	/*
	 * Set variable information using memcpy
	 */
	bufptr = *buf;

	(void) memcpy(bufptr, &msg_callback_data, sizeof (rdr_msg_callback_t));
	bufptr += sizeof (rdr_msg_callback_t);

	if (params->message != NULL) {
		(void) memcpy(bufptr, params->message, message_strlen);
		bufptr += message_strlen;
		for (i = 0; i < message_pad_sz; i++) {
			bufptr[i] = 0;
		}
		bufptr += message_pad_sz;
	}

	return (RDR_OK);
}


/*
 * unpack_message_request:
 *
 * Handle unpacking a message callback request.
 */
static int
unpack_message_request(msg_callback_params_t *params, const char *buf)
{
	char			*bufptr;
	rdr_msg_callback_t	msg_callback_data;

	if ((params == NULL) || (buf == NULL)) {
		return (RDR_ERROR);
	}

	bufptr = (char *)buf;
	(void) memcpy(&msg_callback_data, bufptr, sizeof (rdr_msg_callback_t));
	bufptr += sizeof (rdr_msg_callback_t);

	/*
	 * handle getting the message text
	 */
	if (get_string_from_buf(&(params->message),
	    msg_callback_data.message_size, bufptr)) {
		return (RDR_ERROR);
	}
	bufptr += msg_callback_data.message_size;

	/*
	 * Set fixed address labels by name
	 */
	params->msgp = (struct cfga_msg *)malloc(sizeof (struct cfga_msg));
	if (params->msgp == NULL) {
		return (RDR_MEM_ALLOC);
	}

	/* set params->msgp->message_routine using memcpy */
	(void) memcpy((void*)params->msgp, &(msg_callback_data.msg_callback_id),
	    sizeof (unsigned long));

	params->msgp->appdata_ptr = (void*)msg_callback_data.appdata_ptr;

	return (RDR_OK);
}

/*
 * pack_rsrc_info_request:
 *
 * Handle packing a resource info request.
 */
static int
pack_rsrc_info_request(rsrc_info_params_t *params, char **buf, int *buf_size)
{
	char				*bufptr;
	rdr_rsrc_info_t			rsrc_info_data;
	rdr_variable_message_info_t	var_msg_info;


	if ((params == NULL) || (buf == NULL) || (buf_size == NULL)) {
		return (RDR_ERROR);
	}

	(void) memset(&var_msg_info, 0, sizeof (rdr_variable_message_info_t));

	/*
	 * Set variable length fields and make a call to partially
	 * pack it.
	 */
	if (pack_ap_ids(params->num_ap_ids, params->ap_ids, &var_msg_info)) {
		cleanup_variable_ap_id_info(&var_msg_info);
		return (RDR_ERROR);
	}

	/*
	 * Collect size info specific to the resource info request
	 * message and allocate a buffer.
	 */
	*buf_size = sizeof (rdr_rsrc_info_t);
	*buf_size += var_msg_info.ap_id_int_size;
	*buf_size += var_msg_info.ap_id_char_size;

	*buf = (char *)malloc(*buf_size);
	if (*buf == NULL) {
		return (RDR_MEM_ALLOC);
	}

	/*
	 * Set fixed address labels by name.
	 */
	rsrc_info_data.num_ap_ids = params->num_ap_ids;
	rsrc_info_data.ap_id_char_size = var_msg_info.ap_id_char_size;
	rsrc_info_data.flags = params->flags;

	/*
	 * Set variable information using memcpy.
	 */
	bufptr = *buf;

	(void) memcpy(bufptr, &rsrc_info_data, sizeof (rdr_rsrc_info_t));
	bufptr += sizeof (rdr_rsrc_info_t);

	if (var_msg_info.ap_id_sizes != NULL) {
		(void) memcpy(bufptr, var_msg_info.ap_id_sizes,
		    var_msg_info.ap_id_int_size);
		bufptr += var_msg_info.ap_id_int_size;
	}

	if (var_msg_info.ap_id_chars != NULL) {
		(void) memcpy(bufptr, var_msg_info.ap_id_chars,
		    var_msg_info.ap_id_char_size);
		bufptr += var_msg_info.ap_id_char_size;
	}

	cleanup_variable_ap_id_info(&var_msg_info);

	return (RDR_OK);
}


/*
 * unpack_rsrc_info_request:
 *
 * Handle unpacking a resource info request message.
 */
static int
unpack_rsrc_info_request(rsrc_info_params_t *params, const char *buf)
{
	char				*bufptr;
	rdr_variable_message_info_t	var_msg_info;
	rdr_rsrc_info_t			rsrc_info_data;


	if ((params == NULL) || (buf == NULL)) {
		return (RDR_ERROR);
	}

	(void) memset(&var_msg_info, 0, sizeof (rdr_variable_message_info_t));

	bufptr = (char *)buf;
	(void) memcpy(&rsrc_info_data, bufptr, sizeof (rdr_rsrc_info_t));
	bufptr += sizeof (rdr_rsrc_info_t);

	/*
	 * Handle getting the ap_ids.
	 */
	var_msg_info.ap_id_char_size = rsrc_info_data.ap_id_char_size;
	if (get_ap_ids_from_buf(&(params->ap_ids), rsrc_info_data.num_ap_ids,
	    &var_msg_info, bufptr)) {
		return (RDR_ERROR);
	}
	bufptr += var_msg_info.ap_id_int_size;
	bufptr += var_msg_info.ap_id_char_size;

	/*
	 * Set fixed address labels by name.
	 */
	params->num_ap_ids = rsrc_info_data.num_ap_ids;
	params->flags = rsrc_info_data.flags;

	return (RDR_OK);
}


/*
 * pack_rsrc_info_reply:
 *
 * Handle packing a resource info reply message.
 */
static int
pack_rsrc_info_reply(rsrc_info_params_t *params, char **buf, int *buf_size,
    int encoding)
{
	char				*bufptr;
	rdr_rsrc_info_reply_t		rsrc_info_data;
	int				pack_status;
	caddr_t				rsrc_info_bufp = NULL;
	size_t				rsrc_info_size;


	if ((params == NULL) || (buf == NULL) || (buf_size == NULL)) {
		return (RDR_ERROR);
	}

	/*
	 * Pack snapshot handle data.
	 */
	pack_status = ri_pack(params->hdl, &rsrc_info_bufp, &rsrc_info_size,
	    encoding);
	if (pack_status != 0) {
		return (RDR_ERROR);
	}

	/*
	 * Collect size info specific to the rsrc_info reply message
	 * and allocate a buffer.
	 */
	*buf_size = sizeof (rdr_rsrc_info_reply_t);
	*buf_size += rsrc_info_size;

	*buf = (char *)malloc(*buf_size);
	if (*buf == NULL) {
		free(rsrc_info_bufp);
		return (RDR_MEM_ALLOC);
	}

	/*
	 * Set fixed address labels by name.
	 */
	rsrc_info_data.packed_hdl_size = rsrc_info_size;

	/*
	 * Set variable information using memcpy.
	 */
	bufptr = *buf;

	(void) memcpy(bufptr, &rsrc_info_data, sizeof (rdr_rsrc_info_reply_t));
	bufptr += sizeof (rdr_rsrc_info_reply_t);

	if (rsrc_info_bufp) {
		(void) memcpy(bufptr, rsrc_info_bufp, rsrc_info_size);
		free(rsrc_info_bufp);
	}

	return (RDR_OK);
}


/*
 * unpack_rsrc_info_reply:
 *
 * Handle unpacking a resource info reply message.
 */
static int
unpack_rsrc_info_reply(rsrc_info_params_t *params, const char *buf)
{
	int			unpack_status;
	char			*bufptr;
	rdr_rsrc_info_reply_t	rsrc_info_data;


	if ((params == NULL) || (buf == NULL)) {
		return (RDR_ERROR);
	}

	bufptr = (char *)buf;
	(void) memcpy(&rsrc_info_data, bufptr, sizeof (rdr_rsrc_info_reply_t));
	bufptr += sizeof (rdr_rsrc_info_reply_t);

	/*
	 * Unpack buf into resource info handle.
	 */
	unpack_status = ri_unpack(bufptr, rsrc_info_data.packed_hdl_size,
	    &params->hdl);

	return ((unpack_status == 0) ? RDR_OK : RDR_ERROR);
}


/*
 * pack_ap_ids:
 *
 * Pack a list of attachment point identifiers into a single buffer.
 * This buffer is stored in the specified rdr_variable_message_info_t
 * and is padded to be 64-bit aligned.
 */
static int
pack_ap_ids(int num_ap_ids, char *const *ap_ids,
    rdr_variable_message_info_t *var_msg_info)
{
	int	i;
	int	ap_id_pad_sz;
	char	*bufptr;


	if (var_msg_info == NULL) {
		return (RDR_ERROR);
	}

	/*
	 * NULL is a valid value for ap_ids in the list_ext
	 * case. For list_ext, no specified attachment points
	 * indicates that _all_ attachment points should be
	 * displayed. However, if ap_ids is NULL, num_ap_ids
	 * should be 0.
	 */
	if ((ap_ids == NULL) && (num_ap_ids != 0)) {
		num_ap_ids = 0;
	}

	var_msg_info->ap_id_int_size = sizeof (int) * num_ap_ids;
	if (num_ap_ids > 0) {
		var_msg_info->ap_id_sizes = (int *)malloc(sizeof (int) *
		    var_msg_info->ap_id_int_size);
		if (var_msg_info->ap_id_sizes == NULL) {
			return (RDR_MEM_ALLOC);
		}
	}
	for (i = 0; i < num_ap_ids; i++) {
		if (ap_ids[i] != NULL) {
			var_msg_info->ap_id_sizes[i] = strlen(ap_ids[i]) + 1;
			var_msg_info->ap_id_char_size +=
			    var_msg_info->ap_id_sizes[i];
		}
	}
	if (var_msg_info->ap_id_char_size > 0) {
		ap_id_pad_sz = RDR_ALIGN_64_BIT -
		    (var_msg_info->ap_id_char_size % RDR_ALIGN_64_BIT);
		var_msg_info->ap_id_char_size += ap_id_pad_sz;
		var_msg_info->ap_id_chars = (char *)
		    malloc(var_msg_info->ap_id_char_size);
		if (var_msg_info->ap_id_chars == NULL) {
			return (RDR_MEM_ALLOC);
		}

		bufptr = var_msg_info->ap_id_chars;
		for (i = 0; i < num_ap_ids; i++) {
			(void) memcpy(bufptr, ap_ids[i],
			    var_msg_info->ap_id_sizes[i]);
			bufptr += var_msg_info->ap_id_sizes[i];
		}
		for (i = 0; i < ap_id_pad_sz; i++) {
			bufptr[i] = 0;
		}
	} else {
		ap_id_pad_sz = 0;
	}

	return (RDR_OK);
}


/*
 * unpack_ap_ids:
 *
 * Unpack a buffer containing a concatenation of a list of
 * attachment point identifiers. The resulting list of strings
 * are stored in an array in the specified rdr_variable_message_info_t.
 */
static int
unpack_ap_ids(int num_ap_ids, char **ap_ids, const char *buf,
    rdr_variable_message_info_t *var_msg_info)
{
	int	i;
	int	ap_id_size;
	int	chars_copied;
	char	*bufptr;


	if ((ap_ids == NULL) || (buf == NULL) || (var_msg_info == NULL)) {
		return (RDR_ERROR);
	}
	bufptr = (char *)buf;

	var_msg_info->ap_id_int_size = sizeof (int) * num_ap_ids;
	if (num_ap_ids > 0) {
		var_msg_info->ap_id_sizes = (int *)
		    malloc(sizeof (int) * var_msg_info->ap_id_int_size);
		if (var_msg_info->ap_id_sizes == NULL) {
			return (RDR_MEM_ALLOC);
		}
		(void) memcpy(var_msg_info->ap_id_sizes, bufptr,
		    var_msg_info->ap_id_int_size);
	}
	bufptr += var_msg_info->ap_id_int_size;

	chars_copied = 0;
	for (i = 0; i < num_ap_ids; i++) {
		ap_id_size = var_msg_info->ap_id_sizes[i];
		if (ap_id_size <= 0) {
			continue;
		}
		if ((chars_copied + ap_id_size) >
		    var_msg_info->ap_id_char_size) {
			return (RDR_ERROR);
		}
		ap_ids[i] = (char *)malloc(ap_id_size);
		if (ap_ids[i] == NULL) {
			return (RDR_MEM_ALLOC);
		}
		(void) memcpy(ap_ids[i], bufptr, ap_id_size);
		bufptr += ap_id_size;
		chars_copied += ap_id_size;
	}
	return (RDR_OK);
}


/*
 * find_options_sizes:
 *
 * Determine the size of a specified option string. The information
 * is stored in the specified rdr_variable_message_info_t.
 */
static int
find_options_sizes(char *options, rdr_variable_message_info_t *var_msg_info)
{
	if (var_msg_info == NULL) {
		return (RDR_ERROR);
	}
	if (options != NULL) {
		var_msg_info->options_strlen = strlen(options) + 1;
		var_msg_info->options_pad_sz = RDR_ALIGN_64_BIT -
		    (var_msg_info->options_strlen % RDR_ALIGN_64_BIT);
	} else {
		var_msg_info->options_strlen = 0;
		var_msg_info->options_pad_sz = 0;
	}
	return (RDR_OK);
}


/*
 * find_listopts_sizes:
 *
 * Determine the size of a specified list option string. The information
 * is stored in the specified rdr_variable_message_info_t.
 */
static int
find_listopts_sizes(char *listopts, rdr_variable_message_info_t *var_msg_info)
{
	if (var_msg_info == NULL) {
		return (RDR_ERROR);
	}
	if (listopts != NULL) {
		var_msg_info->listopts_strlen = strlen(listopts) + 1;
		var_msg_info->listopts_pad_sz = RDR_ALIGN_64_BIT -
		    (var_msg_info->listopts_strlen % RDR_ALIGN_64_BIT);
	} else {
		var_msg_info->listopts_strlen = 0;
		var_msg_info->listopts_pad_sz = 0;
	}
	return (RDR_OK);
}


/*
 * find_function_size:
 *
 * Determine the size of a specified private function string. The
 * information is stored in the specified rdr_variable_message_info_t.
 */
static int
find_function_sizes(char *function, rdr_variable_message_info_t *var_msg_info)
{
	if (var_msg_info == NULL) {
		return (RDR_ERROR);
	}
	if (function != NULL) {
		var_msg_info->function_strlen = strlen(function) + 1;
		var_msg_info->function_pad_sz = RDR_ALIGN_64_BIT -
		    (var_msg_info->function_strlen % RDR_ALIGN_64_BIT);
	} else {
		var_msg_info->function_strlen = 0;
		var_msg_info->function_pad_sz = 0;
	}
	return (RDR_OK);
}


/*
 * find_errstring_sizes:
 *
 * Determine the size of a specified error string. The information
 * is stored in the specified rdr_variable_message_info_t.
 */
static int
find_errstring_sizes(char **errstring,
    rdr_variable_message_info_t *var_msg_info)
{
	if ((errstring != NULL) && (*errstring != NULL)) {
		var_msg_info->errstring_strlen = strlen(*errstring) + 1;
		var_msg_info->errstring_pad_sz = RDR_ALIGN_64_BIT -
		    (var_msg_info->errstring_strlen % RDR_ALIGN_64_BIT);
	} else {
		var_msg_info->errstring_strlen = 0;
		var_msg_info->errstring_pad_sz = 0;
	}
	return (RDR_OK);
}


/*
 * get_ap_ids_from_buf:
 *
 * Unpack a buffer containing a concatenation of a list of attachment
 * point identifiers. An appropriately sized buffer is allocated and
 * the resulting list of strings are stored in an array in the specified
 * rdr_variable_message_info_t.
 */
static int
get_ap_ids_from_buf(char ***ap_id_ptr, int num_ap_ids,
    rdr_variable_message_info_t *var_msg_info, const char *buf)
{
	if ((ap_id_ptr == NULL) || (buf == NULL) || (var_msg_info == NULL)) {
		return (RDR_ERROR);
	}
	if (num_ap_ids > 0) {
		*ap_id_ptr = (char **)malloc(sizeof (char *) * num_ap_ids);
		if (*ap_id_ptr == NULL) {
			return (RDR_MEM_ALLOC);
		}
		if (unpack_ap_ids(num_ap_ids, *ap_id_ptr, buf, var_msg_info)) {
			cleanup_variable_ap_id_info(var_msg_info);
			return (RDR_ERROR);
		}

	} else if (num_ap_ids < 0) {
		return (RDR_ERROR);
	}

	cleanup_variable_ap_id_info(var_msg_info);

	return (RDR_OK);
}


/*
 * get_string_from_buf:
 *
 * Copy a string to a new buffer. Memory is allocated for the
 * new buffer and the original string is copied to the new buffer.
 * This is primarily used when a string is located in a packed
 * buffer that will eventually get deallocated.
 */
static int
get_string_from_buf(char **stringptr, int strsize, const char *buf)
{
	if (buf == NULL) {
		return (RDR_ERROR);
	}

	/*
	 * A stringptr of NULL is a valid value. The errstring param
	 * in an rconfig_xxx call is valid and is passed to this
	 * function. For example, see errstring in the call to this
	 * function in unpack_change_state_reply.
	 */
	if (stringptr != NULL) {
		if (strsize > 0) {
			*stringptr = (char *)malloc(strsize);
			if (*stringptr == NULL) {
				return (RDR_MEM_ALLOC);
			}
			(void) memcpy(*stringptr, buf, strsize);
		} else if (strsize == 0) {
			*stringptr = NULL;
		} else if (strsize < 0) {
			*stringptr = NULL;
			return (RDR_ERROR);
		}
	}
	return (RDR_OK);
}


/*
 * cleanup_ap_ids:
 *
 * Deallocate the specified array of attachment point identifiers.
 */
static int
cleanup_ap_ids(int num_ap_ids, char ** ap_ids)
{
	int	i;

	if (ap_ids == NULL) {
		return (RDR_ERROR);
	}
	for (i = 0; i < num_ap_ids; i++) {
		if (ap_ids[i] != NULL) {
			free((void *)ap_ids[i]);
			ap_ids[i] = NULL;
		}
	}
	return (RDR_OK);
}


/*
 * cleanup_errstring:
 *
 * Deallocate the specified error string.
 */
static int
cleanup_errstring(char **errstring)
{
	if (errstring) {
		if (*errstring) {
			free((void *)*errstring);
		}
		free((void *)errstring);
		errstring = NULL;
	}

	return (RDR_OK);
}


/*
 * cleanup_variable_ap_id_info:
 *
 * Deallocate the ap_id information from the specified
 * rdr_variable_message_info_t.
 */
static void
cleanup_variable_ap_id_info(rdr_variable_message_info_t *var_msg_info)
{
	if (var_msg_info != NULL) {
		if (var_msg_info->ap_id_sizes != NULL) {
			free((void *)var_msg_info->ap_id_sizes);
			var_msg_info->ap_id_sizes = NULL;
		}
		if (var_msg_info->ap_id_chars != NULL) {
			free((void *)var_msg_info->ap_id_chars);
			var_msg_info->ap_id_chars = NULL;
		}
	}
}

/*
 * load_libdscp:
 *
 * Try to dynamically link with libdscp.
 *
 * Returns:	0 if libdscp not available,
 *		1 if libdscp is available.
 */
static int
load_libdscp(libdscp_t *libdscp)
{
	int		len;
	void		*lib;
	static char	platform[100];
	static char	pathname[MAXPATHLEN];

	/*
	 * Only try to load libdscp once.  Use the saved
	 * status in the libdscp interface to know the
	 * results of previous attempts.
	 */
	if (libdscp->status == LIBDSCP_AVAILABLE) {
		return (1);
	}
	if (libdscp->status == LIBDSCP_UNAVAILABLE) {
		return (0);
	}

	/*
	 * Construct a platform specific pathname for libdscp.
	 */
	len = sysinfo(SI_PLATFORM, platform, sizeof (platform));
	if ((len < 0) || (len > sizeof (platform))) {
		return (0);
	}
	len = snprintf(pathname, MAXPATHLEN, LIBDSCP_PATH, platform);
	if (len >= MAXPATHLEN) {
		libdscp->status = LIBDSCP_UNAVAILABLE;
		return (0);
	}

	/*
	 * Try dynamically loading libdscp.
	 */
	if ((lib = dlopen(pathname, RTLD_LAZY)) == NULL) {
		libdscp->status = LIBDSCP_UNAVAILABLE;
		return (0);
	}

	/*
	 * Try to resolve all the symbols.
	 */
	libdscp->bind = (int (*)(int, int, int))dlsym(lib, LIBDSCP_BIND);
	libdscp->secure = (int (*)(int, int))dlsym(lib, LIBDSCP_SECURE);
	libdscp->auth = (int (*)(int, struct sockaddr *, int))dlsym(lib,
	    LIBDSCP_AUTH);

	if ((libdscp->bind == NULL) ||
	    (libdscp->secure == NULL) ||
	    (libdscp->auth == NULL)) {
		(void) dlclose(lib);
		libdscp->status = LIBDSCP_UNAVAILABLE;
		return (0);
	}

	/*
	 * Success.
	 * Update the status to indicate libdscp is available.
	 */
	libdscp->status = LIBDSCP_AVAILABLE;
	return (1);
}
