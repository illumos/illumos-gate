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

#ifndef	_DCS_H
#define	_DCS_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <poll.h>
#include <signal.h>

#include "remote_cfg.h"
#include "rdr_param_types.h"


#define	DCS_SERVICE		"sun-dr"
#define	SUN_DR_PORT		665
#define	DCS_BACKLOG		10

#define	BLOCKFOREVER		(-1)
#define	DCS_SND_TIMEOUT		60000		/* 1 minute */
#define	DCS_RCV_TIMEOUT		300000		/* 5 minutes */
#define	DCS_RCV_CB_TIMEOUT	43200000	/* 12 hours */

#define	DCS_ERR_OFFSET		12000
#define	MAX_MSG_LEN		512

#define	DCS_MAX_SESSIONS	128

/*
 * Header files for per-socket IPsec
 */
#include <netinet/in.h>
#include <net/pfkeyv2.h>


/*
 * The IPsec socket option struct, from ipsec(4P):
 *
 *     typedef struct ipsec_req {
 *         uint_t      ipsr_ah_req;            AH request
 *         uint_t      ipsr_esp_req;           ESP request
 *         uint_t      ipsr_self_encap_req;    Self-Encap request
 *         uint8_t     ipsr_auth_alg;          Auth algs for AH
 *         uint8_t     ipsr_esp_alg;           Encr algs for ESP
 *         uint8_t     ipsr_esp_auth_alg;      Auth algs for ESP
 *     } ipsec_req_t;
 *
 * The -a option sets the ipsr_auth_alg field. Allowable arguments
 * are "none", "md5", or "sha1". The -e option sets the ipsr_esp_alg
 * field. Allowable arguments are "none", "des", or "3des". "none"
 * is the default for both options. The -u option sets the ipsr_esp_auth_alg
 * field. Allowable arguments are the same as -a.
 *
 * The arguments ("md5", "des", etc.) are named so that they match
 * kmd(8)'s accepted arguments which are listed on the SC in
 * /etc/opt/SUNWSMS/SMS/config/kmd_policy.cf.
 */
#define	AH_REQ		(IPSEC_PREF_REQUIRED | IPSEC_PREF_UNIQUE)
#define	ESP_REQ		(IPSEC_PREF_REQUIRED | IPSEC_PREF_UNIQUE)
#define	SELF_ENCAP_REQ	0x0

/*
 * A type to hold the command line argument string used to select a
 * particular authentication header (AH) or encapsulating security
 * payload (ESP) algorithm and the ID used for that algorithm when
 * filling the ipsec_req_t structure which is passed to
 * setsockopt(3SOCKET).
 */
typedef struct dcs_alg {
	char		*arg_name;
	uint8_t		alg_id;
} dcs_alg_t;


/*
 * Debugging
 */
#define	DBG_NONE	0x00000000
#define	DBG_ALL		0xFFFFFFFF
#define	DBG_INFO	0x00000001
#define	DBG_MSG		0x00000002
#define	DBG_SES		0x00000004
#define	DBG_STATE	0x00000008

#ifdef DCS_DEBUG

/*
 * supported options for debug version:
 *
 * -d  control the amount of debugging
 * -S  control standalone mode
 * -s  control maximum active sessions
 * -a  control the IPsec AH algorithm ("none", "md5", or "sha1")
 * -e  control the IPsec ESP encr algorithm ("none", "des", or "3des")
 * -u  control the IPsec ESP auth algorithm ("none", "md5", or "sha1")
 * -l  control the use of libdscp for endpoint authentication.
 */
#define	OPT_STR		"d:Ss:a:e:u:l"

#else /* DCS_DEBUG */

/*
 * supported options for non-debug version:
 *
 * -s  control maximum active sessions
 * -a  control the IPsec AH algorithm ("none", "md5", or "sha1")
 * -e  control the IPsec ESP encr algorithm ("none", "des", or "3des")
 * -u  control the IPsec ESP auth algorithm ("none", "md5", or "sha1")
 * -l  control the use of libdscp for endpoint authentication.
 */
#define	OPT_STR		"s:a:e:u:l"

#endif /* DCS_DEBUG */


/*
 * Error codes that are used internally in the DCS. These error codes
 * are mapped to the strings listed to the right of each error code
 * as a comment.
 */
typedef enum {

	/*
	 * Network Errors:
	 */
	DCS_INIT_ERR = 0,   /* network initialization failed		   */
	DCS_NO_PORT,	    /* failed to acquire reserved port		   */
	DCS_CONNECT_ERR,    /* connection attempt failed		   */
	DCS_RECEIVE_ERR,    /* unable to receive message		   */
	DCS_OP_REPLY_ERR,   /* unable to send message for %s operation	   */
	DCS_NO_SERV,	    /* %s service not found, using reserved	   */
			    /* port 665					   */
	DCS_DISCONNECT,	    /* client disconnected			   */

	/*
	 * Session Errors:
	 */
	DCS_SES_HAND_ERR,   /* failed to start a new session handler	   */
	DCS_ABORT_ERR,	    /* abort attempt of session, %d, unsuccessful  */
	DCS_VER_INVAL,	    /* unsupported message protocol version %d.%d  */
	DCS_SES_ABORTED,    /* session aborted				   */

	/*
	 * DR Request Errors:
	 */
	DCS_UNKNOWN_OP,	    /* unknown operation requested		   */
	DCS_OP_FAILED,	    /* operation failed				   */
	DCS_SES_SEQ_INVAL,  /* invalid session establishment sequence	   */
	DCS_NO_SES_ESTBL,   /* %s operation issued before session	   */
			    /* established				   */
	DCS_MSG_INVAL,	    /* received an invalid message		   */
	DCS_CONF_CB_ERR,    /* confirm callback failed, aborting operation */
	DCS_MSG_CB_ERR,	    /* message callback failed, continuing	   */
	DCS_BAD_RETRY_VAL,  /* retry value invalid (%d)			   */
	DCS_BAD_TIME_VAL,   /* timeout value invalid (%d)		   */
	DCS_RETRY,	    /* retrying operation, attempt %d		   */

	/*
	 * General Errors:
	 */
	DCS_NO_PRIV,	    /* permission denied			   */
	DCS_INT_ERR,	    /* internal error: %s: %s			   */
	DCS_UNKNOWN_ERR,    /* unrecognized error reported		   */
	DCS_BAD_OPT,	    /* illegal option (-%c), exiting		   */
	DCS_BAD_OPT_ARG,    /* illegal argument to -%c flag (%s), %s	   */
	DCS_CFGA_UNKNOWN,   /* configuration administration unknown error  */
	DCS_CFGA_ERR,	    /* %s: %s					   */
	DCS_RSRC_ERR,	    /* resource info init error (%d)		   */
	DCS_NO_ERR,	    /* no error					   */
	DCS_MSG_COUNT	    /* NULL					   */

} dcs_err_code;


/*
 * Public error codes. These error codes are returned to the
 * client in the event of a fatal error. Since the DCS can
 * report either a libcfgadm or internal error, there is a
 * possiblity of conflicting error codes. To avoid this, the
 * DCS error codes are offset by a constant value. However,
 * 0 will always indicate that no errors have occurred.
 */
typedef enum {
	DCS_OK = 0,
	DCS_ERROR = DCS_ERR_OFFSET,
	DCS_MSG_INVAL_ERR,
	DCS_VER_INVAL_ERR,
	DCS_NO_SES_ERR,
	DCS_SES_INVAL_ERR,
	DCS_SES_SEQ_INVAL_ERR,
	DCS_SES_ABORTED_ERR
} dcs_err_t;


/*
 * DCS states. These states are the states that the DCS moves
 * through as it processes a DR request. The order represents
 * the transitions performed in a successful operation.
 */
typedef enum {
	DCS_CONNECTED = 1,
	DCS_SES_REQ,
	DCS_SES_ESTBL,
	DCS_CONF_PENDING,
	DCS_CONF_DONE,
	DCS_SES_END
} dcs_ses_state_t;


/*
 * Message Contents
 */
typedef struct message {
	rdr_msg_hdr_t	*hdr;
	cfga_params_t	*params;
} message_t;


/*
 * Session information
 */
typedef struct session {
	unsigned long	id;
	unsigned short	major_version;
	unsigned short	minor_version;
	unsigned long	random_req;
	unsigned long	random_resp;

	int		fd;
	dcs_ses_state_t	state;
	message_t	curr_msg;
} session_t;


/*
 * Message Direction
 */
typedef enum {
	DCS_SEND,
	DCS_RECEIVE
} dcs_msg_type_t;


/*
 * Globals
 */
extern ulong_t	dcs_debug;
extern int	standalone;
extern ulong_t	max_sessions;
extern int	use_libdscp;


/*
 * From dcs.c:
 */
int dcs_dispatch_message(rdr_msg_hdr_t *hdr, cfga_params_t *params);
void init_msg(rdr_msg_hdr_t *hdr);

/*
 * From dcs_ses.c:
 */
int ses_start(int fd);
int ses_close(int err_code);
int ses_abort(long ses_id);
void ses_abort_enable(void);
void ses_abort_disable(void);
void abort_handler(void);
int ses_setlocale(char *locale);
void ses_init_signals(sigset_t *mask);
void ses_sleep(int sec);
int ses_poll(struct pollfd fds[], nfds_t nfds, int timeout);
session_t *curr_ses(void);
long curr_ses_id(void);

/*
 * From dcs_msg.c:
 */
void dcs_log_msg(int priority, int code, ...);
char *dcs_cfga_str(char **err_str, int err_code);
void dcs_dbg(int level, char *fmt, ...);
void print_msg_hdr(dcs_msg_type_t type, rdr_msg_hdr_t *hdr);
const char *dcs_strerror(int err_code);


/*
 * If the dcs_debug global variable is not set, no
 * debugging messages will be logged.
 */
#define	DCS_DBG		if (dcs_debug) dcs_dbg
#define	PRINT_MSG_DBG	if (dcs_debug) print_msg_hdr


#ifdef	__cplusplus
}
#endif

#endif /* _DCS_H */
