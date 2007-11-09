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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * PRIVATE header file for the icap client vs_icap.c
 */

#ifndef _VS_ICAP_H_
#define	_VS_ICAP_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/* macros */
#define	MATCH(a, b)	(!strncasecmp((a), (b), strlen((b))))

#define	VS_ICAP_VER	"ICAP/1.0"

/* max sizes for vs_options_t */
#define	VS_DEFN_SZ	32
#define	VS_SERVICE_SZ	64

#define	VS_BUF_SZ	4096	/* keep this a power-of-two value. */
#define	VS_HDR_SZ	8	/* > length of VS_BUF_SZ in hex + 2 for \r\n */
#define	VS_TAIL_SZ	8	/* > \r\n */
#define	VS_ENCAP_SZ	64	/* space reserved in header for encap offsets */
#define	VS_TERMINATION	"0\r\n\r\n"

/*
 * The Symantec ICAP server REQUIRES the "avscan" resource name
 * after the IP address in the OPTIONS and  RESPMOD requests
 * This is ignored by the other ICAP servers.
 */
#define	VS_SERVICE_NAME "avscan"

/* infection/violation record processing */
#define	VS_VIOLATION_LINES   4
#define	VS_INFECTION_FIELDS  3

/* previewing files */
#define	VS_MIN_PREVIEW_LEN	4

/* defines which files types should be previewed */
typedef enum {
	VS_PREVIEW_ALL = 1,	/* preview all files */
	VS_PREVIEW_NONE,	/* preview no files, transfer all complete */
	VS_PREVIEW_LIST,	/* preview only files of listed types */
	VS_PREVIEW_EXCEPT	/* preview all files except listed types */
} vs_preview_t;

/* valid ICAP response codes */
typedef enum {
	VS_RESP_CONTINUE	= 100,
	VS_RESP_OK		= 200,
	VS_RESP_CREATED		= 201, /* file repaired. */
	VS_RESP_NO_CONT_NEEDED	= 204,
	VS_RESP_BAD_REQ		= 400,
	VS_RESP_FORBIDDEN	= 403, /* virus found but not repairable */
	VS_RESP_NOT_FOUND	= 404,
	VS_RESP_NOT_ALLOWED	= 405,
	VS_RESP_TIMEOUT		= 408,
	VS_RESP_INTERNAL_ERR	= 500,
	VS_RESP_NOT_IMPL	= 501,
	VS_RESP_SERV_UNAVAIL	= 503,  /* service unavailable or overloaded */
	VS_RESP_ICAP_VER_UNSUPP	= 505,
	/* Symantec additions - not ICAP standard */
	VS_RESP_SCAN_ERR	= 533,
	VS_RESP_NO_LICENSE	= 539,
	VS_RESP_RES_UNAVAIL	= 551,
	/* all else */
	VS_RESP_UNKNOWN
} vs_icap_resp_t;


/* the ICAP OPTIONS HEADERS used by NAS AVA */
typedef enum {
	VS_OPT_SERVICE = 1,
	VS_OPT_ISTAG,
	VS_OPT_METHODS,
	VS_OPT_ALLOW,
	VS_OPT_PREVIEW,
	VS_OPT_XFER_PREVIEW,
	VS_OPT_XFER_COMPLETE,
	VS_OPT_MAX_CONNECTIONS,
	VS_OPT_TTL,
	VS_OPT_X_DEF_INFO,
	VS_OPT_HDR_MAX = VS_OPT_X_DEF_INFO
} vs_option_hdr_t;


/*
 * the ICAP RESPMOD RESPONSE HEADERS used by NAS AVA
 *
 * Do NOT change the order of:
 * VS_RESP_X_VIRUS_ID, VS_RESP_X_INFECTION, VS_RESP_X_VIOLATIONS
 * Virus data saved from any one of these headers may be replaced
 * with data found in a preferable header (one with more info).
 * They are listed in order of preference.
 */
typedef enum {
	VS_RESP_ENCAPSULATED = 1,
	VS_RESP_ISTAG,
	VS_RESP_X_VIRUS_ID,
	VS_RESP_X_INFECTION,
	VS_RESP_X_VIOLATIONS,
	VS_RESP_HDR_MAX = VS_RESP_X_VIOLATIONS
} vs_resp_hdr_t;


/*
 * vs_options_t
 * vs_impl.c manages an array of vs_options_t, one per scan engine.
 * vs_options_t is used to store the scan engine configuration info
 * returned from the scan engine in the ICAP OPTIONS RESPONSE.
 * This information is then used to determine how to communicate with
 * the scan engines (eg which files to preview), when to resend the
 * ICAP OPTIONS REQUEST, and the istag is used as the scanstamp of
 * the file. The istag is also returned in the ICAP RESPMOD RESPONSE
 * and is used to update the stored one if it has changed.
 */
typedef struct vs_options {
	/* host & port used to detect config changes */
	char vso_host[MAXHOSTNAMELEN];
	int vso_port;

	/* configuration options returned from scan engine */
	int vso_preview_len;		/* the preview supported */
	int vso_allow;			/* allow 204 */
	vs_scanstamp_t vso_scanstamp;	/* from istag received */
	char vso_defninfo[VS_DEFN_SZ];	/* virus definition info */
	char vso_service[VS_SERVICE_SZ]; /* name of SE service */
	int vso_respmod;		/* set if RESPMOD method supported */
	vs_preview_t vso_xfer_how;	/* transfer preview or complete */
	iovec_t *vso_xfer_preview;	/* file exts supporting preview */
	iovec_t *vso_xfer_complete;	/* file exts to be sent complete */
	long vso_ttl;			/* after this expiry, re-get options */
	time_t vso_req_time;		/* time when option was last sent */
} vs_options_t;


/*
 * vs_info_t
 *
 * vs_info_t is part of the context created for each scan engine request.
 * It contains send/recv buffers and other temporary storage required
 * during the processing of the request/response.
 * threat_hdr_t defines from which header the virus information was
 * obtained. This is used to determine whether to overwrite existing
 * info if a 'better' header is found.
 */
typedef struct vs_info {
	char vsi_send_hdr[VS_HDR_SZ];
	char vsi_send_buf[VS_BUF_SZ + VS_TAIL_SZ];
	char vsi_recv_buf[VS_BUF_SZ];

	/*  response header information */
	boolean_t vsi_res_hdr;
	boolean_t vsi_res_body;
	boolean_t vsi_html_content;	/* L8R - set, not used */
	int	vsi_content_len;	/* L8R - set, not used */
	int	vsi_icap_rc;
	int	vsi_http_rc;
	int	vsi_threat_hdr;
} vs_info_t;


/*
 * vs_scan_ctx_t
 *
 * A vs_scan_ctx_t is created for each scan request. It will contain
 * everything that is needed to process the scan request and return
 * the response to the caller.
 * - engine connection information used to identify which scan engine
 *   the request is being sent to,
 * - information about the file being scanned,
 * - a place to store information about the file that will be created
 *   to hold cleaned data if the scan engine detects an infection
 *   and returns a cleaned version of the file,
 * - a copy of the vs_options_t for the scan engine. This allows the
 *   NAS AVA scan engine connection parameters to be reconfigured without
 *   affecting any in-progress requests,
 * - a vs_info_t - the temporary storage needed to process the request,
 * - a vs_result_t - a place to store the  scan result information to be
 *   returned to the caller.
 */
typedef struct vs_scan_ctx {
	/* scan engine idx and connection info */
	int vsc_idx;
	char vsc_host[MAXHOSTNAMELEN];
	int vsc_port;
	int vsc_sockfd;

	/* info about file to be scanned */
	int vsc_fd;
	char *vsc_fname;
	uint64_t vsc_fsize;
	int vsc_flags;

	/* file to hold repaired data */
	boolean_t vsc_repair;
	int vsc_repair_fd;
	char *vsc_repair_fname;

	vs_options_t vsc_options;
	vs_info_t vsc_info;
	vs_result_t *vsc_result;
} vs_scan_ctx_t;


/*
 * vs_icap_hdr_t
 *
 * vs_icap.c defines tables of handlers for each ICAP OPTIONS RESPONSE HEADER
 * and each ICAP RESPMOD RESPONSE HEADER which NAS AVA uses.
 * Each entry in these tables is an vs_hdr_t.
 */
typedef struct vs_hdr {
	int  vsh_id;
	char *vsh_name;
	int  (*vsh_func)(vs_scan_ctx_t *, int, char *);
}vs_hdr_t;


/*
 * vs_resp_msg_t
 *
 * vs_icap.c defines a table mapping ICAP response code values to text strings.
 * Each entry in this tables is a vs_resp_msg_t.
 */
typedef struct vs_resp_msg {
	int vsm_rc;
	char *vsm_msg;
} vs_resp_msg_t;

#ifdef __cplusplus
}
#endif

#endif /* _VS_ICAP_H_ */
