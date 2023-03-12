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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Description:  Module contains supporting functions used by functions
 * defined in vs_svc.c. It also contains some internal(static) functions.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <syslog.h>
#include <ctype.h>
#include <strings.h>
#include <string.h>
#include <limits.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/debug.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "vs_incl.h"
#include "vs_icap.h"

/*  prototypes of local functions  */
static int  vs_icap_option_request(vs_scan_ctx_t *);
static int  vs_icap_send_option_req(vs_scan_ctx_t *);
static int  vs_icap_read_option_resp(vs_scan_ctx_t *);

static int  vs_icap_respmod_request(vs_scan_ctx_t *);
static int  vs_icap_may_preview(vs_scan_ctx_t *);
static char *vs_icap_find_ext(char *);
static int  vs_icap_send_preview(vs_scan_ctx_t *);
static int  vs_icap_send_respmod_hdr(vs_scan_ctx_t *, int);
static int  vs_icap_create_respmod_hdr(vs_scan_ctx_t *, int);
static int  vs_icap_uri_encode(char *, int, char *);
static int  vs_icap_uri_illegal_char(char);

static int  vs_icap_read_respmod_resp(vs_scan_ctx_t *);
static int  vs_icap_read_resp_code(vs_scan_ctx_t *);
static int  vs_icap_read_hdr(vs_scan_ctx_t *, vs_hdr_t *, int);

static int  vs_icap_set_scan_result(vs_scan_ctx_t *);
static int  vs_icap_read_encap_hdr(vs_scan_ctx_t *);
static void vs_icap_read_encap_data(vs_scan_ctx_t *);
static int  vs_icap_create_repair_file(vs_scan_ctx_t *);
static int  vs_icap_read_resp_body(vs_scan_ctx_t *);
static int  vs_icap_read_body_chunk(vs_scan_ctx_t *);

static int  vs_icap_send_chunk(vs_scan_ctx_t *, int);
static int  vs_icap_send_termination(vs_scan_ctx_t *);
static int  vs_icap_readline(vs_scan_ctx_t *, char *, int);

static int  vs_icap_write(int, char *, int);
static int  vs_icap_read(int, char *, int);

/* process options and respmod headers */
static void vs_icap_parse_hdrs(char, char *, char **, char **);
static int  vs_icap_opt_value(vs_scan_ctx_t *, int, char *);
static int  vs_icap_opt_ext(vs_scan_ctx_t *, int, char *);
static int  vs_icap_resp_violations(vs_scan_ctx_t *, int, char *);
static int  vs_icap_resp_violation_rec(vs_scan_ctx_t *, int);
static int  vs_icap_resp_infection(vs_scan_ctx_t *, int, char *);
static int  vs_icap_resp_virus_id(vs_scan_ctx_t *, int, char *);
static int  vs_icap_resp_encap(vs_scan_ctx_t *, int, char *);
static int  vs_icap_resp_istag(vs_scan_ctx_t *, int, char *);
static void vs_icap_istag_to_scanstamp(char *, vs_scanstamp_t);

/* Utility functions for handling OPTIONS data: vs_options_t */
static void vs_icap_free_options(vs_options_t *);
static void vs_icap_copy_options(vs_options_t *, vs_options_t *);
static void vs_icap_update_options(vs_scan_ctx_t *);
static int vs_icap_compare_se(int, char *, int);

static iovec_t *vs_icap_make_strvec(char *, const char *);
static iovec_t *vs_icap_copy_strvec(iovec_t *);
static int  vs_icap_check_ext(char *, iovec_t *);
static void vs_icap_trimspace(char *);

/* icap response message */
static char *vs_icap_resp_str(int);

/*
 * local variables
 */

/* option headers  - and handler functions */
vs_hdr_t option_hdrs[] = {
	{ VS_OPT_SERVICE,	"Service",		vs_icap_opt_value},
	{ VS_OPT_ISTAG,		"ISTag",		vs_icap_opt_value},
	{ VS_OPT_METHODS,	"Methods",		vs_icap_opt_value},
	{ VS_OPT_ALLOW,		"Allow",		vs_icap_opt_value},
	{ VS_OPT_PREVIEW,	"Preview",		vs_icap_opt_value},
	{ VS_OPT_XFER_PREVIEW,	"Transfer-Preview",	vs_icap_opt_ext},
	{ VS_OPT_XFER_COMPLETE,	"Transfer-Complete",	vs_icap_opt_ext},
	{ VS_OPT_MAX_CONNECTIONS, "Max-Connections",	vs_icap_opt_value},
	{ VS_OPT_TTL,		"Options-TTL",		vs_icap_opt_value},
	{ VS_OPT_X_DEF_INFO,	"X-Definition-Info",	vs_icap_opt_value}
};


/* resp hdrs  - and handler functions */
vs_hdr_t resp_hdrs[] = {
	{ VS_RESP_ENCAPSULATED,	"Encapsulated",	vs_icap_resp_encap},
	{ VS_RESP_ISTAG,	"ISTag",	vs_icap_resp_istag},
	{ VS_RESP_X_VIRUS_ID,	"X-Virus-ID",	vs_icap_resp_virus_id},
	{ VS_RESP_X_INFECTION,	"X-Infection-Found",	vs_icap_resp_infection},
	{ VS_RESP_X_VIOLATIONS,	"X-Violations-Found",	vs_icap_resp_violations}
};

/* ICAP response code to string mappings */
vs_resp_msg_t icap_resp[] = {
	{ VS_RESP_CONTINUE,		"Continue"},
	{ VS_RESP_OK,			"OK"},
	{ VS_RESP_CREATED,		"Virus Detected and Repaired"},
	{ VS_RESP_NO_CONT_NEEDED,	"No Content Necessary"},
	{ VS_RESP_BAD_REQ,		"Bad Request"},
	{ VS_RESP_FORBIDDEN,		"File Infected and not repaired"},
	{ VS_RESP_NOT_FOUND,		"URI not found"},
	{ VS_RESP_NOT_ALLOWED,		"Method not allowed"},
	{ VS_RESP_TIMEOUT,		"Request timedout"},
	{ VS_RESP_INTERNAL_ERR,		"Internal server error"},
	{ VS_RESP_NOT_IMPL,		"Method not implemented"},
	{ VS_RESP_SERV_UNAVAIL,		"Service unavailable/overloaded"},
	{ VS_RESP_ICAP_VER_UNSUPP,	"ICAP version not supported"},
	{ VS_RESP_SCAN_ERR,		"Error scanning file"},
	{ VS_RESP_NO_LICENSE,		"No AV License"},
	{ VS_RESP_RES_UNAVAIL,		"Resource unavailable"},
	{ VS_RESP_UNKNOWN,		"Unknown Error"},
};

static const char *EXT_SEPARATOR =  ",";
static vs_options_t vs_options[VS_SE_MAX];
static pthread_mutex_t vs_opt_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * vs_icap_init
 * initialization performed when daemon is loaded
 */
void
vs_icap_init()
{

	(void) pthread_mutex_lock(&vs_opt_mutex);
	(void) memset(vs_options, 0, sizeof (vs_options_t));
	(void) pthread_mutex_unlock(&vs_opt_mutex);
}


/*
 * vs_icap_fini
 * cleanup  performed when daemon is unloaded
 */
void
vs_icap_fini()
{
	int i;

	(void) pthread_mutex_lock(&vs_opt_mutex);

	for (i = 0; i < VS_SE_MAX; i++)
		vs_icap_free_options(&vs_options[i]);

	(void) pthread_mutex_unlock(&vs_opt_mutex);
}


/*
 * vs_icap_config
 *
 * When a new VSCAN configuration is specified, this will be
 * called per scan engine. If the scan engine host or port has
 * changed delete the vs_options entry for that scan engine.
 */
void
vs_icap_config(int idx, char *host, int port)
{
	(void) pthread_mutex_lock(&vs_opt_mutex);
	if (vs_icap_compare_se(idx, host, port) != 0) {
		vs_icap_free_options(&vs_options[idx]);
		(void) strlcpy(vs_options[idx].vso_host, host,
		    sizeof (vs_options[idx].vso_host));
		vs_options[idx].vso_port = port;
	}
	(void) pthread_mutex_unlock(&vs_opt_mutex);
}


/*
 * vs_icap_scan_file
 *
 * Create a context (vs_scan_ctx_t) for the scan operation and initialize
 * its options info. If the scan engine connection's IP or port is different
 * from that held in vs_options the vs_options info is old and should
 * be deleted (vs_icap_free_options). Otherwise, copy the vs_options info
 * into the context.
 * file name, size and decsriptor are also copied into the context
 *
 * Handle the ICAP protocol communication with the external Scan Engine to
 * perform the scan
 *  - send an OPTIONS request if necessary
 *  - send RESPMOD scan request
 *  - process the response and save any cleaned data to file
 *
 * Returns: result->vsr_rc
 */
int
vs_icap_scan_file(vs_eng_ctx_t *eng, char *devname, char *fname,
    uint64_t fsize, int flags, vs_result_t *result)
{
	vs_scan_ctx_t ctx;
	int fd;

	fd = open(devname, O_RDONLY);

	/* retry once on ENOENT as /dev link may not be created yet */
	if ((fd == -1) && (errno == ENOENT)) {
		(void) sleep(1);
		fd = open(devname, O_RDONLY);
	}

	if (fd == -1) {
		syslog(LOG_ERR, "Failed to open device %s - %s",
		    devname, strerror(errno));
		result->vsr_rc = VS_RESULT_ERROR;
		return (result->vsr_rc);
	}

	/* initialize context */
	(void) memset(&ctx, 0, sizeof (vs_scan_ctx_t));
	ctx.vsc_idx = eng->vse_eidx;
	(void) strlcpy(ctx.vsc_host, eng->vse_host, sizeof (ctx.vsc_host));
	ctx.vsc_port = eng->vse_port;
	ctx.vsc_sockfd = eng->vse_sockfd;
	ctx.vsc_fd = fd;
	ctx.vsc_fname = fname;
	ctx.vsc_fsize = fsize;
	ctx.vsc_flags = flags;
	ctx.vsc_result = result;

	/* Hooks for future saving of repaired data, not yet in use */
	ctx.vsc_flags |= VS_NO_REPAIR;
	ctx.vsc_repair = 0;
	ctx.vsc_repair_fname = NULL;
	ctx.vsc_repair_fd = -1;

	/* take a copy of vs_options[idx] if they match the SE specified */
	(void) pthread_mutex_lock(&vs_opt_mutex);
	if (vs_icap_compare_se(ctx.vsc_idx, ctx.vsc_host, ctx.vsc_port) == 0) {
		vs_icap_copy_options(&ctx.vsc_options,
		    &vs_options[ctx.vsc_idx]);
	}

	(void) pthread_mutex_unlock(&vs_opt_mutex);

	/*
	 * default the result to scan engine error.
	 * Any non scan-engine errors will reset it to VS_RESULT_ERROR
	 */
	result->vsr_rc = VS_RESULT_SE_ERROR;

	/* do the scan */
	if (vs_icap_option_request(&ctx) == 0)
		(void) vs_icap_respmod_request(&ctx);

	(void) close(fd);
	vs_icap_free_options(&ctx.vsc_options);
	return (result->vsr_rc);
}


/* ********************************************************************* */
/*			Local Function definitions			 */
/* ********************************************************************* */

/*
 * vs_icap_option_request
 *
 * Send ICAP options message and await/process the response.
 *
 * The ICAP options request needs to be sent when a connection
 * is first made with the scan engine. Unless the scan engine
 * determines that the options will never expire (which we save
 * as optione_req_time == -1) the request should be resent after
 * the expiry time specified by the icap server.
 *
 * Returns: 0 - success
 *         -1 - error
 */
static int
vs_icap_option_request(vs_scan_ctx_t *ctx)
{
	if (ctx->vsc_options.vso_req_time != -1 &&
	    ((time(0) - ctx->vsc_options.vso_req_time) >
	    ctx->vsc_options.vso_ttl)) {

		if (vs_icap_send_option_req(ctx) < 0)
			return (-1);

		if (vs_icap_read_option_resp(ctx) < 0)
			return (-1);

		vs_icap_update_options(ctx);
	}

	return (0);
}


/*
 * vs_icap_send_option_req
 *
 * Send an OPTIONS request to the scan engine
 * The Symantec ICAP server REQUIRES the resource name (VS_SERVICE_NAME)
 * after the IP address, otherwise it closes the connection.
 *
 * Returns: 0 - success
 *         -1 - error
 */
static int
vs_icap_send_option_req(vs_scan_ctx_t *ctx)
{
	char my_host_name[MAXHOSTNAMELEN];
	int  bufsp = VS_BUF_SZ;
	char *buf0 = ctx->vsc_info.vsi_send_buf;
	char *bufp = buf0;
	int  tlen;

	if (gethostname(my_host_name, sizeof (my_host_name)) != 0) {
		/* non SE error */
		ctx->vsc_result->vsr_rc = VS_RESULT_ERROR;
		return (-1);
	}

	(void) memset(ctx->vsc_info.vsi_send_buf, 0,
	    sizeof (ctx->vsc_info.vsi_send_buf));

	tlen = snprintf(bufp, bufsp, "OPTIONS icap://%s:%d/%s %s\r\n",
	    ctx->vsc_host, ctx->vsc_port, VS_SERVICE_NAME, VS_ICAP_VER);
	bufp += tlen;
	bufsp -= tlen;

	tlen = snprintf(bufp, bufsp, "Host: %s\r\n\r\n", my_host_name);
	bufp += tlen;

	if (vs_icap_write(ctx->vsc_sockfd, buf0, (bufp - buf0)) < 0)
		return (-1);

	return (0);
}


/*
 * vs_icap_read_option_resp
 *
 * Returns: 0 - success
 *         -1 - error
 */
static int
vs_icap_read_option_resp(vs_scan_ctx_t *ctx)
{
	if (vs_icap_read_resp_code(ctx) < 0)
		return (-1);

	if (ctx->vsc_info.vsi_icap_rc != VS_RESP_OK) {
		syslog(LOG_ERR, "ICAP protocol error "
		    "- unexpected option response: %s",
		    vs_icap_resp_str(ctx->vsc_info.vsi_icap_rc));
		return (-1);
	}

	if (vs_icap_read_hdr(ctx, option_hdrs, VS_OPT_HDR_MAX) != 0)
		return (-1);

	if ((ctx->vsc_options.vso_scanstamp[0] == 0) ||
	    (ctx->vsc_options.vso_respmod == 0) ||
	    (ctx->vsc_options.vso_req_time == 0)) {
		syslog(LOG_ERR, "ICAP protocol error "
		    "- missing or invalid option response hdrs");
		return (-1);
	}

	return (0);
}


/*
 * vs_icap_respmod_request
 *
 * Send respmod request and receive and process ICAP response.
 * Preview:
 *   ICAP allows for an optional "preview" request.  In the option negotiation,
 *   the server may ask for a list of types to be previewed, or to be sent
 *   complete (no preview).
 *   This is advisory. It is ok to skip the preview step, as done when the file
 *   is smaller than the preview_len.
 * Process Response:
 * - read and parse the RESPMOD response headers
 * - populate the result structure
 * - read any encapsulated response headers
 * - read any encapsulated response body and, if it represents cleaned
 *   file data, overwrite the file with it
 *
 * Returns: 0 - success
 *         -1 - error
 */
static int
vs_icap_respmod_request(vs_scan_ctx_t *ctx)
{
	int rv;
	int bytes_sent, send_len;
	uint64_t resid = ctx->vsc_fsize;

	if (vs_icap_may_preview(ctx)) {

		if ((rv = vs_icap_send_preview(ctx)) < 0)
			return (-1);

		if (vs_icap_read_respmod_resp(ctx) < 0)
			return (-1);

		if (ctx->vsc_info.vsi_icap_rc != VS_RESP_CONTINUE)
			return (0);

		bytes_sent = rv;

		/* If > block (VS_BUF_SZ) remains, re-align to block boundary */
		if ((ctx->vsc_fsize - (uint64_t)bytes_sent) > VS_BUF_SZ) {
			send_len = VS_BUF_SZ - bytes_sent;
			if ((rv = vs_icap_send_chunk(ctx, send_len)) < 0)
				return (-1);
			bytes_sent += rv;
		}

		resid -= (uint64_t)bytes_sent;

	} else {

		if (vs_icap_send_respmod_hdr(ctx, 0) < 0)
			return (-1);
	}

	/* Send the remainder of the file...  */
	while (resid) {
		send_len = (resid > VS_BUF_SZ) ? VS_BUF_SZ : resid;

		if ((rv = vs_icap_send_chunk(ctx, send_len)) < 0)
			return (-1);

		if (rv == 0)
			break;

		resid  -= (uint64_t)rv;
	}

	if (vs_icap_send_termination(ctx) < 0)
		return (-1);

	/* sending of ICAP request complete */
	if (vs_icap_read_respmod_resp(ctx) < 0)
		return (-1);

	return (0);
}


/*
 *	vs_icap_may_preview
 *
 *	Returns: 1  - preview
 *	         0 - don't preview
 */
static int
vs_icap_may_preview(vs_scan_ctx_t *ctx)
{
	int  in_list = 0;
	char *ext;
	vs_options_t *opts = &ctx->vsc_options;

	if (opts->vso_xfer_how == VS_PREVIEW_NONE)
		return (0);

	/* if the file is smaller than the preview size, don't preview */
	if (ctx->vsc_fsize < (uint64_t)ctx->vsc_options.vso_preview_len)
		return (0);

	switch (opts->vso_xfer_how) {
	case VS_PREVIEW_ALL:
		return (1);
	case VS_PREVIEW_EXCEPT:
		/* Preview everything except types in xfer_complete */
		if ((ext = vs_icap_find_ext(ctx->vsc_fname)) != 0)
			in_list = vs_icap_check_ext(ext,
			    opts->vso_xfer_complete);
		return ((in_list) ? 0 : 1);
	case VS_PREVIEW_LIST:
		/* Preview only types in the the xfer_preview list  */
		if ((ext = vs_icap_find_ext(ctx->vsc_fname)) != 0)
			in_list = vs_icap_check_ext(ext,
			    opts->vso_xfer_preview);
		return ((in_list) ? 1 : 0);
	}

	return (1);
}


/*
 * vs_icap_find_ext
 *
 * Returns: ptr to file's extension in fname
 *          0 if no extension
 */
static char *
vs_icap_find_ext(char *fname)
{
	char *last_comp, *ext_str = 0;

	if ((last_comp = strrchr(fname, '/')) != 0) {
		last_comp++;
	} else {
		last_comp = fname;
	}

	/* Get file extension */
	if ((ext_str = strrchr(last_comp, '.')) != 0) {
		ext_str++;
		if (strlen(ext_str) == 0)
			ext_str = 0;
	}

	return (ext_str);
}


/*
 * vs_icap_send_preview
 *
 * Returns:  bytes sent (preview + alignment)
 *           -1 - error
 */
static int
vs_icap_send_preview(vs_scan_ctx_t *ctx)
{
	int preview_len = ctx->vsc_options.vso_preview_len;
	int bytes_sent;

	/* Send a RESPMOD request with "preview" mode.  */
	if (vs_icap_send_respmod_hdr(ctx, 'P') < 0)
		return (-1);

	if ((bytes_sent = vs_icap_send_chunk(ctx, preview_len)) < 0)
		return (-1);

	if (bytes_sent < preview_len)
		return (-1);

	if (vs_icap_send_termination(ctx) < 0)
		return (-1);

	return (bytes_sent);
}


/*
 * vs_icap_send_respmod_hdr
 *
 * Create and send the RESPMOD request headers to the scan engine.
 *
 * Returns: 0 success
 *        < 0 error
 */
static int
vs_icap_send_respmod_hdr(vs_scan_ctx_t *ctx, int ispreview)
{
	int len;

	if ((len = vs_icap_create_respmod_hdr(ctx, ispreview)) == -1) {
		/* non SE error */
		ctx->vsc_result->vsr_rc = VS_RESULT_ERROR;
		return (-1);
	}

	/* send the headers */
	if (vs_icap_write(ctx->vsc_sockfd,
	    ctx->vsc_info.vsi_send_buf, len) < 0) {
		return (-1);
	}

	return (0);
}


/*
 * vs_icap_create_respmod_hdr
 *
 * Create the RESPMOD request headers.
 * - RESPMOD, Host, Allow, [Preview], Encapsulated, encapsulated request hdr,
 *   encapsulated response hdr
 * Encapsulated data is sent separately subsequent to vs_icap_send_respmod_hdr,
 * via calls to vs_icap_send_chunk.
 *
 * The Symantec ICAP server REQUIRES the resource name (VS_SERVICE_NAME)
 * after the IP address, otherwise it closes the connection.
 *
 * Returns: -1 error
 *           length of headers data
 */
static int
vs_icap_create_respmod_hdr(vs_scan_ctx_t *ctx, int ispreview)
{
	char my_host_name[MAXHOSTNAMELEN];
	int  hbufsp = VS_BUF_SZ;
	char *hbuf0  = ctx->vsc_info.vsi_send_buf;
	char *hbufp  = hbuf0;
	char *encap_hdr, *encap_off0, *req_hdr, *res_hdr, *res_body;
	int preview_len = ctx->vsc_options.vso_preview_len;
	int  tlen;

	if (gethostname(my_host_name, sizeof (my_host_name)) != 0) {
		/* non SE error */
		ctx->vsc_result->vsr_rc = VS_RESULT_ERROR;
		return (-1);
	}

	(void) memset(hbufp, 0, hbufsp);

	/* First the ICAP "request" part. (at offset 0) */
	tlen = snprintf(hbufp, hbufsp, "RESPMOD icap://%s:%d/%s %s\r\n",
	    ctx->vsc_host, ctx->vsc_port, VS_SERVICE_NAME, VS_ICAP_VER);
	if (tlen >= hbufsp)
		return (-1);
	hbufp += tlen; hbufsp -= tlen;

	tlen = snprintf(hbufp, hbufsp, "Host: %s\r\n", my_host_name);
	if (tlen >= hbufsp)
		return (-1);
	hbufp += tlen; hbufsp -= tlen;

	tlen = snprintf(hbufp, hbufsp, "Allow: 204\r\n");
	if (tlen >= hbufsp)
		return (-1);
	hbufp += tlen; hbufsp -= tlen;

	if (ispreview) {
		tlen = snprintf(hbufp, hbufsp, "Preview: %d\r\n", preview_len);
		if (tlen >= hbufsp)
			return (-1);
		hbufp += tlen; hbufsp -= tlen;
	}

	/* Reserve space to later insert encapsulation offsets, & blank line */
	encap_hdr = hbufp;
	tlen = snprintf(hbufp, hbufsp, "%*.*s\r\n\r\n",
	    VS_ENCAP_SZ, VS_ENCAP_SZ, "");
	if (tlen >= hbufsp)
		return (-1);
	hbufp += tlen; hbufsp -= tlen;

	/* "offset zero" for the encapsulated parts that follow */
	encap_off0 = hbufp;

	/* Encapsulated request header (req_hdr) & blank line */
	req_hdr = hbufp;
	tlen = snprintf(hbufp, hbufsp, "GET http://%s", my_host_name);
	if (tlen >= hbufsp)
		return (-1);
	hbufp += tlen; hbufsp -= tlen;

	tlen = vs_icap_uri_encode(hbufp, hbufsp, ctx->vsc_fname);
	if (tlen < 0)
		return (-1);
	hbufp += tlen; hbufsp -= tlen;

	tlen = snprintf(hbufp, hbufsp, " HTTP/1.1\r\n\r\n");
	if (tlen >= hbufsp)
		return (-1);
	hbufp += tlen; hbufsp -= tlen;

	/* Encapsulated response header (res_hdr) & blank line */
	res_hdr = hbufp;
	tlen = snprintf(hbufp, hbufsp, "HTTP/1.1 200 OK\r\n");
	if (tlen >= hbufsp)
		return (-1);
	hbufp += tlen; hbufsp -= tlen;

	tlen = snprintf(hbufp, hbufsp, "Transfer-Encoding: chunked\r\n\r\n");
	if (tlen >= hbufsp)
		return (-1);
	hbufp += tlen; hbufsp -= tlen;

	/* response body section - res-body ("chunked data") */
	res_body = hbufp;

	/* Insert offsets in encap_hdr */
	tlen = snprintf(encap_hdr, VS_ENCAP_SZ, "Encapsulated: "
	    "req-hdr=%d, res-hdr=%d, res-body=%d",
	    req_hdr - encap_off0, res_hdr - encap_off0, res_body - encap_off0);
	/* undo the null from snprintf */
	encap_hdr[tlen] = ' ';

	/* return length */
	return (hbufp - hbuf0);
}


/*
 * vs_icap_read_respmod_resp
 *
 * Used for both preview and final RESMOD response
 */
static int
vs_icap_read_respmod_resp(vs_scan_ctx_t *ctx)
{
	if (vs_icap_read_resp_code(ctx) < 0)
		return (-1);

	if (vs_icap_read_hdr(ctx, resp_hdrs, VS_RESP_HDR_MAX) < 0)
		return (-1);

	if (ctx->vsc_info.vsi_icap_rc == VS_RESP_CONTINUE) {
		/* A VS_RESP_CONTINUE should not have encapsulated data */
		if ((ctx->vsc_info.vsi_res_hdr) ||
		    (ctx->vsc_info.vsi_res_body)) {
			syslog(LOG_ERR, "ICAP protocol error -"
			    "- encapsulated data in Continue response");
			return (-1);
		}
	} else {
		if (vs_icap_set_scan_result(ctx) < 0)
			return (-1);

		if (ctx->vsc_info.vsi_res_hdr) {
			if (vs_icap_read_encap_hdr(ctx) < 0)
				return (-1);
		}

		if (ctx->vsc_info.vsi_res_body)
			vs_icap_read_encap_data(ctx);
		else if (ctx->vsc_result->vsr_rc == VS_RESULT_CLEANED)
			ctx->vsc_result->vsr_rc = VS_RESULT_FORBIDDEN;
	}

	return (0);
}


/*
 * vs_icap_read_resp_code
 *
 * Get the response code from the icap response messages
 */
static int
vs_icap_read_resp_code(vs_scan_ctx_t *ctx)
{
	char *buf = ctx->vsc_info.vsi_recv_buf;
	int  retval;

	/* Break on error or non-blank line. */
	for (;;) {
		(void) memset(buf, '\0', VS_BUF_SZ);

		if ((retval = vs_icap_readline(ctx, buf, VS_BUF_SZ)) < 0)
			return (-1);

		if (retval && buf[0]) {
			if (MATCH(buf, VS_ICAP_VER)) {
				(void) sscanf(buf+8, "%d",
				    &ctx->vsc_info.vsi_icap_rc);
				return (0);
			}

			syslog(LOG_ERR, "ICAP protocol error -"
			    "- expected ICAP/1.0, received %s", buf);

			return (-1);
		}
	}
}


/*
 * vs_icap_read_hdr
 *
 * Reads all response headers.
 * As each line is read it is parsed and passed to the appropriate handler.
 *
 * Returns: 0 - success
 *         -1 - error
 */
static int
vs_icap_read_hdr(vs_scan_ctx_t *ctx, vs_hdr_t hdrs[], int num_hdrs)
{
	char *buf = ctx->vsc_info.vsi_recv_buf;
	int  i, retval;
	char *name, *val;

	/* Break on error or blank line. */
	for (;;) {
		(void) memset(buf, '\0', VS_BUF_SZ);

		if ((retval = vs_icap_readline(ctx, buf, VS_BUF_SZ)) < 0)
			return (-1);

		/* Empty line (CR/LF) normal break */
		if ((retval == 0) || (!buf[0]))
			break;

		vs_icap_parse_hdrs(':', buf, &name, &val);

		for (i = 0; i < num_hdrs; i++) {
			if (strcmp(name, hdrs[i].vsh_name) == 0) {
				hdrs[i].vsh_func(ctx, hdrs[i].vsh_id, val);
				break;
			}
		}
	}

	return ((retval >= 0) ? 0 : -1);
}


/*
 * vs_icap_set_scan_result
 *
 * Sets the vs_result_t vsr_rc from the icap_resp_code and
 * any violation information in vs_result_t
 *
 * Returns: 0 - success
 *         -1 - error
 */
static int
vs_icap_set_scan_result(vs_scan_ctx_t *ctx)
{
	int i;
	vs_result_t *result = ctx->vsc_result;

	(void) strlcpy(result->vsr_scanstamp,
	    ctx->vsc_options.vso_scanstamp, sizeof (vs_scanstamp_t));

	switch (ctx->vsc_info.vsi_icap_rc) {
	case VS_RESP_NO_CONT_NEEDED:
		result->vsr_rc = VS_RESULT_CLEAN;
		break;

	case VS_RESP_OK:
		/* if we have no violations , that means all ok */
		if (result->vsr_nviolations == 0) {
			result->vsr_rc = VS_RESULT_CLEAN;
			break;
		}

		/* Any infections not repaired? */
		result->vsr_rc = VS_RESULT_CLEANED;
		for (i = 0; i < result->vsr_nviolations; i++) {
			if (result->vsr_vrec[i].vr_res !=
			    VS_RES_FILE_REPAIRED) {
				result->vsr_rc = VS_RESULT_FORBIDDEN;
				break;
			}
		}
		break;

	case VS_RESP_CREATED :
		/* file is repaired */
		result->vsr_rc = VS_RESULT_CLEANED;
		break;

	case VS_RESP_FORBIDDEN:
		/* file is infected and could not be repaired */
		result->vsr_rc = VS_RESULT_FORBIDDEN;
		break;

	default:
		syslog(LOG_ERR, "ICAP protocol error "
		    "- unsupported scan result: %s",
		    vs_icap_resp_str(ctx->vsc_info.vsi_icap_rc));
		return (-1);
	}

	return (0);
}


/*
 * vs_icap_read_encap_hdr
 *
 * Read the encapsulated response header to determine the length of
 * encapsulated data and, in some cases, to detect the infected state
 * of the file.
 *
 * Use of http response code:
 * Trend IWSS does not return virus information in the RESPMOD response
 * headers unless the OPTIONAL "include X_Infection_Found" checkbox is
 * checked and "disable_infected_url_block=yes" is set in intscan.ini.
 * Thus if we haven't already detected the infected/cleaned status
 * (ie if vsr_rc == VS_RESULT_CLEAN) we attempt to detect the
 * infected/cleaned state of a file from a combination of the ICAP and
 * http resp codes.
 * Here are the response code values that Trend IWSS returns:
 *  - clean:      icap resp = VS_RESP_NO_CONT_NEEDED
 *  - quarantine: icap resp = VS_RESP_OK, http resp = VS_RESP_FORBIDDEN
 *  - cleaned:    icap resp = VS_RESP_OK, http resp = VS_RESP_OK
 * For all other vendors' scan engines (so far) the infected/cleaned
 * state of the file has already been detected from the RESPMOD
 * response headers.
 */
static int
vs_icap_read_encap_hdr(vs_scan_ctx_t *ctx)
{
	char *buf = ctx->vsc_info.vsi_recv_buf;
	char *name, *value;
	int  retval;

	/* Break on error or blank line. */
	for (;;) {
		if ((retval = vs_icap_readline(ctx, buf, VS_BUF_SZ)) < 0)
			return (-1);

		/* Empty line (CR/LF) normal break */
		if ((retval == 0) || (!buf[0]))
			break;

		if (MATCH(buf, "HTTP/1.1")) {
			(void) sscanf(buf + 8, "%d",
			    &ctx->vsc_info.vsi_http_rc);
			ctx->vsc_info.vsi_html_content = B_TRUE;

			/* if not yet detected infection, interpret http_rc */
			if (ctx->vsc_result->vsr_rc == VS_RESULT_CLEAN) {
				if ((ctx->vsc_info.vsi_icap_rc == VS_RESP_OK) &&
				    (ctx->vsc_info.vsi_http_rc == VS_RESP_OK)) {
					ctx->vsc_result->vsr_rc =
					    VS_RESULT_CLEANED;
				} else {
					ctx->vsc_result->vsr_rc =
					    VS_RESULT_FORBIDDEN;
				}
			}
		} else {
			vs_icap_parse_hdrs(':', buf, &name, &value);
			if (name && (MATCH(name, "Content-Length"))) {
				(void) sscanf(value, "%d",
				    &ctx->vsc_info.vsi_content_len);
			}
		}
	}

	return (0);
}


/*
 * vs_icap_read_encap_data
 *
 * Read the encapsulated response data.
 *
 * If the response data represents cleaned file data (for an infected file)
 * and VS_NO_REPAIR is not set, open repair file to save the reponse body
 * data in. Set the repair flag in the scan context. The repair flag is used
 * during the processing of the response data. If the flag is set then the
 * data is written to file. If any error occurs which invalidates the repaired
 * data file the repair flag gets reset to 0, and the data will be discarded.
 *
 * The result is reset to VS_RESULT_FORBIDDEN until all of the cleaned data
 * has been successfully received and processed. It is then reset to
 * VS_RESULT_CLEANED.
 *
 * If the data doesn't represent cleaned file data, or we cannot (or don't
 * want to) write the cleaned data to file, the data is discarded (repair flag
 * in ctx == 0).
 */
static void
vs_icap_read_encap_data(vs_scan_ctx_t *ctx)
{
	if (ctx->vsc_result->vsr_rc == VS_RESULT_CLEANED) {
		ctx->vsc_result->vsr_rc = VS_RESULT_FORBIDDEN;

		if (!(ctx->vsc_flags & VS_NO_REPAIR)) {
			if (vs_icap_create_repair_file(ctx) == 0)
				ctx->vsc_repair = B_TRUE;
		}
	}

	/*
	 * vs_icap_read_resp_body handles errors internally;
	 * resets ctx->vsc_repair
	 */
	(void) vs_icap_read_resp_body(ctx);

	if (ctx->vsc_repair_fd != -1) {
		(void) close(ctx->vsc_repair_fd);

		if (ctx->vsc_repair) {
			/* repair file contains the cleaned data */
			ctx->vsc_result->vsr_rc = VS_RESULT_CLEANED;
		} else {
			/* error occured processing data. Remove repair file */
			(void) unlink(ctx->vsc_repair_fname);
		}
	}
}


/*
 * vs_icap_create_repair_file
 *
 * Create and open a file to save cleaned data in.
 */
static int
vs_icap_create_repair_file(vs_scan_ctx_t *ctx)
{
	if (ctx->vsc_repair_fname == NULL)
		return (-1);

	if ((ctx->vsc_repair_fd = open(ctx->vsc_repair_fname,
	    O_RDWR | O_CREAT | O_EXCL | O_TRUNC, 0644)) == -1) {
		return (-1);
	}

	return (0);
}


/*
 * vs_icap_read_resp_body
 *
 * Repeatedly call vs_icap_read_body_chunk until it returns:
 *    0 indicating that there's no more data to read or
 *   -1 indicating a read error -> reset ctx->vsc_repair 0
 *
 * Returns: 0 success
 *         -1 error
 */
static int
vs_icap_read_resp_body(vs_scan_ctx_t *ctx)
{
	int retval;

	while ((retval = vs_icap_read_body_chunk(ctx)) > 0)
		;

	if (retval < 0)
		ctx->vsc_repair = B_FALSE;

	return (retval);
}


/*
 * vs_icap_read_body_chunk
 *
 * Read the chunk size, then read the chunk of data and write the
 * data to file repair_fd (or discard it).
 * If the data cannot be successfully written to file, set repair
 * flag in ctx to 0, and discard all subsequent data.
 *
 * Returns: chunk size
 *          -1 on error
 */
static int
vs_icap_read_body_chunk(vs_scan_ctx_t *ctx)
{
	char *lbuf = ctx->vsc_info.vsi_recv_buf;
	unsigned int chunk_size, resid;
	int rsize;

	/* Read and parse the chunk size. */
	if ((vs_icap_readline(ctx, lbuf, VS_BUF_SZ) < 0) ||
	    (!sscanf(lbuf, "%x", &chunk_size))) {
		return (-1);
	}

	/* Read and save/discard chunk */
	resid = chunk_size;
	while (resid) {
		rsize = (resid < VS_BUF_SZ) ? resid : VS_BUF_SZ;

		if ((rsize = vs_icap_read(ctx->vsc_sockfd, lbuf, rsize)) <= 0)
			return (-1);

		if (ctx->vsc_repair) {
			if (vs_icap_write(ctx->vsc_repair_fd, lbuf, rsize) < 0)
				ctx->vsc_repair = B_FALSE;
		}

		resid -= rsize;
	}

	/* Eat one CR/LF after the data */
	if (vs_icap_readline(ctx, lbuf, VS_BUF_SZ) < 0)
		return (-1);

	if (lbuf[0]) {
		syslog(LOG_ERR, "ICAP protocol error - expected blank line");
		return (-1);
	}

	return (chunk_size);
}


/* *********************************************************************** */
/*			Utility read, write functions			   */
/* *********************************************************************** */

/*
 * vs_icap_write
 *
 * Return: 0 if all data successfully written
 *        -1 otherwise
 */
static int
vs_icap_write(int fd, char *buf, int buflen)
{
	char *ptr = buf;
	int resid = buflen;
	int bytes_sent = 0;

	while (resid > 0) {
		errno = 0;
		bytes_sent = write(fd, ptr, resid);
		if (bytes_sent < 0) {
			if (errno == EINTR)
				continue;
			else
				return (-1);
		}
		resid -= bytes_sent;
		ptr += bytes_sent;
	}

	return (0);
}


/*
 * vs_icap_read
 *
 * Returns: bytes_read (== len unless EOF hit before len bytes read)
 *          -1 error
 */
static int
vs_icap_read(int fd, char *buf, int len)
{
	char *ptr = buf;
	int resid = len;
	int bytes_read = 0;

	while (resid > 0) {
		errno = 0;
		bytes_read = read(fd, ptr, resid);
		if (bytes_read < 0) {
			if (errno == EINTR)
				continue;
			else
				return (-1);
		}
		resid -= bytes_read;
		ptr += bytes_read;
	}

	return (len - resid);
}


/*
 * vs_icap_send_chunk
 *
 * Send a "chunk" of file data, containing:
 * - Length (in hex) CR/NL
 * - [optiona data]
 * - CR/NL
 *
 * Returns: data length sent (not including encapsulation)
 *          -1 - error
 */
static int
vs_icap_send_chunk(vs_scan_ctx_t *ctx, int chunk_len)
{
	char *hdr = ctx->vsc_info.vsi_send_hdr;
	char *dbuf = ctx->vsc_info.vsi_send_buf;
	char *tail;
	char head[VS_HDR_SZ + 1];
	int nread = 0, hlen, tlen = 2;

	if (chunk_len > VS_BUF_SZ)
		chunk_len = VS_BUF_SZ;

	/* Read the data. */
	if ((nread = vs_icap_read(ctx->vsc_fd, dbuf, chunk_len)) < 0)
		return (-1);

	if (nread > 0) {
		/* wrap data in a header and trailer */
		hlen = snprintf(head, sizeof (head), "%x\r\n", nread);
		hdr += (VS_HDR_SZ - hlen);
		(void) memcpy(hdr, head, hlen);
		tail = dbuf + nread;
		tail[0] = '\r';
		tail[1] = '\n';

		if (vs_icap_write(ctx->vsc_sockfd, hdr,
		    hlen + nread + tlen) < 0) {
			return (-1);
		}
	}

	return (nread);
}


/*
 * vs_icap_send_termination
 *
 * Send 0 length termination to scan engine: "0\r\n\r\n"
 *
 * Returns: 0 - success
 *         -1 - error
 */
static int
vs_icap_send_termination(vs_scan_ctx_t *ctx)
{
	if (vs_icap_write(ctx->vsc_sockfd, VS_TERMINATION,
	    strlen(VS_TERMINATION)) < 0) {
		return (-1);
	}

	return (0);
}


/*
 * vs_icap_readline
 *
 * Read a line of response data from the socket. \n indicates end of line.
 *
 *  Returns: bytes read
 *          -1 - error
 */
static int
vs_icap_readline(vs_scan_ctx_t *ctx, char *buf, int buflen)
{
	char c;
	int i, retval;

	i = 0;
	for (;;) {
		errno = 0;
		retval = recv(ctx->vsc_sockfd, &c, 1, 0);

		if (retval < 0 && errno == EINTR)
			continue;

		if (retval <= 0) {
			if (vscand_get_state() != VS_STATE_SHUTDOWN) {
				syslog(LOG_ERR, "Error receiving data from "
				    "Scan Engine: %s", strerror(errno));
			}
			return (-1);
		}

		buf[i++] = c;
		if (c == '\n')
			break;

		if (i >= (buflen - 2))
			return (-1);
	}

	buf[i] = '\0';

	/* remove preceding and trailing whitespace */
	vs_icap_trimspace(buf);

	return (i);
}


/* ************************************************************************ */
/*				HEADER processing			    */
/* ************************************************************************ */

/*
 * vs_icap_parse_hdrs
 *
 * parse an icap hdr line to find name and value
 */
static void
vs_icap_parse_hdrs(char delimiter, char *line, char **name, char **val)
{
	char *q = line;
	int line_len;

	/* strip any spaces */
	while (*q == ' ')
		q++;

	*name = q;
	*val = 0;

	/* Empty line is normal termination */
	if ((line_len = strlen(line)) == 0)
		return;

	if ((q = strchr(line, delimiter)) != 0) {
		*q++ = '\0';
	} else {
		q = line + line_len;
	}

	/* value part follows spaces */
	while (*q == ' ')
		q++;

	*val = q;
}


/*
 * vs_icap_resp_violations
 */
/*ARGSUSED*/
static int
vs_icap_resp_violations(vs_scan_ctx_t *ctx, int hdr_id, char *line)
{
	int i, rv, vcnt;

	(void) sscanf(line, "%d", &vcnt);

	ctx->vsc_result->vsr_nviolations =
	    (vcnt > VS_MAX_VIOLATIONS) ? VS_MAX_VIOLATIONS : vcnt;

	ctx->vsc_info.vsi_threat_hdr = VS_RESP_X_VIOLATIONS;

	for (i = 0; i < vcnt; i++) {
		if ((rv = vs_icap_resp_violation_rec(ctx, i)) < 0)
			return (rv);

	}

	return (1);
}


/*
 * vs_icap_resp_violation_rec
 *
 * take all violation data (up to VS_MAX_VIOLATIONS) and save it
 * in violation_info.
 * each violation has 4 lines of info: doc name, virus name,
 * virus id and resolution
 */
static int
vs_icap_resp_violation_rec(vs_scan_ctx_t *ctx, int vr_idx)
{
	int vline;
	int retval = 0;
	char *buf = ctx->vsc_info.vsi_recv_buf;
	vs_vrec_t *vr;

	if (vr_idx < VS_MAX_VIOLATIONS) {
		vr = &ctx->vsc_result->vsr_vrec[vr_idx];
	} else {
		vr = 0;
	}

	for (vline = 0; vline < VS_VIOLATION_LINES; vline++) {
		if ((retval = vs_icap_readline(ctx, buf, VS_BUF_SZ)) < 0)
			return (-1);

		/* empty line? */
		if ((retval == 0) || (!buf[0]))
			break;

		if (vr) {
			switch (vline) {
			case 0: /* doc name */
				break;
			case 1: /* Threat Description */
				(void) strlcpy(vr->vr_desc, buf,
				    VS_DESCRIPTION_MAX);
				break;
			case 2: /* Problem ID */
				(void) sscanf(buf, "%d", &vr->vr_id);
				break;
			case 3: /* Resolution */
				(void) sscanf(buf, "%d", &vr->vr_res);
				break;
			}
		}
	}

	return (1);
}


/*
 * vs_icap_opt_value
 * given an icap options hdr string, process value
 */
static int
vs_icap_opt_value(vs_scan_ctx_t *ctx, int hdr_id, char *line)
{
	int x;
	long val;
	char *end;

	switch (hdr_id) {
	case VS_OPT_PREVIEW:
		(void) sscanf(line, "%d", &x);
		if (x < VS_MIN_PREVIEW_LEN)
			x = VS_MIN_PREVIEW_LEN;
		if (x > VS_BUF_SZ)
			x = VS_BUF_SZ;
		ctx->vsc_options.vso_preview_len = x;
		break;

	case VS_OPT_TTL:
		if (*line == 0) {
			ctx->vsc_options.vso_req_time = -1;
			break;
		}

		val = strtol(line, &end, 10);
		if ((end != (line + strlen(line))) || (val < 0))
			break;

		ctx->vsc_options.vso_ttl = val;
		ctx->vsc_options.vso_req_time = time(0);
		break;

	case VS_OPT_ALLOW:
		(void) sscanf(line, "%d", &ctx->vsc_options.vso_allow);
		break;

	case VS_OPT_SERVICE:
		(void) strlcpy(ctx->vsc_options.vso_service, line,
		    VS_SERVICE_SZ);
		break;

	case VS_OPT_X_DEF_INFO:
		(void) strlcpy(ctx->vsc_options.vso_defninfo, line,
		    VS_DEFN_SZ);
		break;

	case VS_OPT_METHODS:
		if (strstr(line, "RESPMOD") != NULL)
			ctx->vsc_options.vso_respmod = 1;
		break;

	case VS_OPT_ISTAG:
		vs_icap_istag_to_scanstamp(line,
		    ctx->vsc_options.vso_scanstamp);
		break;

	default:
		break;

	}

	return (1);
}


/*
 * vs_icap_resp_istag
 *
 * Called to handle ISTAG when received in RESPMOD response.
 *  - populate result->vsr_scanstamp from istag
 *  - update the scanstamp in vs_options and log the update.
 */
/*ARGSUSED*/
static int
vs_icap_resp_istag(vs_scan_ctx_t *ctx, int hdr_id, char *line)
{
	vs_icap_istag_to_scanstamp(line, ctx->vsc_result->vsr_scanstamp);

	/* update the scanstamp in vs_options */
	(void) pthread_mutex_lock(&vs_opt_mutex);
	if (vs_icap_compare_se(ctx->vsc_idx,
	    ctx->vsc_host, ctx->vsc_port) == 0) {
		if (strcmp(vs_options[ctx->vsc_idx].vso_scanstamp,
		    ctx->vsc_result->vsr_scanstamp) != 0) {
			(void) strlcpy(vs_options[ctx->vsc_idx].vso_scanstamp,
			    ctx->vsc_result->vsr_scanstamp,
			    sizeof (vs_scanstamp_t));
		}
	}
	(void) pthread_mutex_unlock(&vs_opt_mutex);

	return (1);
}


/*
 * vs_icap_istag_to_scanstamp
 *
 * Copies istag into scanstamp, stripping leading and trailing
 * quotes '"' from istag. If the istag is invalid (too long)
 * scanstamp will be left unchanged.
 *
 * vs_scanstamp_t is defined to be large enough to hold the
 * istag plus a null terminator.
 */
static void
vs_icap_istag_to_scanstamp(char *istag, vs_scanstamp_t scanstamp)
{
	char *p = istag;
	int len;

	/* eliminate preceding '"' */
	if (p[0] == '"')
		++p;

	/* eliminate trailing '"' */
	len = strlen(p);
	if (p[len - 1] == '"')
		--len;

	if (len < sizeof (vs_scanstamp_t))
		(void) strlcpy(scanstamp, p, len + 1);
}


/*
 * vs_icap_opt_ext
 *
 * read the transfer preview / transfer complete headers to
 * determine which file types can be previewed
 */
static int
vs_icap_opt_ext(vs_scan_ctx_t *ctx, int hdr_id, char *line)
{
	vs_options_t *opt = &ctx->vsc_options;

	switch (hdr_id) {
	case VS_OPT_XFER_PREVIEW:
		if (opt->vso_xfer_preview) {
			free(opt->vso_xfer_preview);
			opt->vso_xfer_preview = 0;
		}
		if (strstr(line, "*")) {
			opt->vso_xfer_how = VS_PREVIEW_ALL;
		} else {
			opt->vso_xfer_preview = vs_icap_make_strvec
			    (line, EXT_SEPARATOR);
			opt->vso_xfer_how = VS_PREVIEW_LIST;
		}
		break;

	case VS_OPT_XFER_COMPLETE :
		if (opt->vso_xfer_complete) {
			free(opt->vso_xfer_complete);
			opt->vso_xfer_complete = 0;
		}
		if (strstr(line, "*")) {
			opt->vso_xfer_how = VS_PREVIEW_NONE;
		} else {
			opt->vso_xfer_complete = vs_icap_make_strvec
			    (line, EXT_SEPARATOR);
			opt->vso_xfer_how = VS_PREVIEW_EXCEPT;
		}
		break;
	default:
		break;
	}

	return (1);
}


/*
 * vs_icap_resp_infection
 *
 * read the type, resolution and threat description for each
 * reported violation and save in ctx->vsc_result
 */
/*ARGSUSED*/
static int
vs_icap_resp_infection(vs_scan_ctx_t *ctx, int hdr_id, char *line)
{
	char *name, *val;
	int i, got = 0;
	int type = 0, res = 0;
	char *desc = 0;
	vs_vrec_t *vr = 0;

	for (i = 0; i < VS_INFECTION_FIELDS; i++) {
		vs_icap_parse_hdrs('=', line, &name, &val);

		switch (i) {
		case 0:
			if (MATCH(name, "Type")) {
				(void) sscanf(val, "%d", &type);
				got++;
			}
			break;
		case 1:
			if (MATCH(name, "Resolution")) {
				(void) sscanf(val, "%d", &res);
				got++;
			}
			break;
		case 2:
			if (MATCH(name, "Threat")) {
				desc = val;
				got++;
			}
			break;
		default :
			break;
		}

		if ((line = strstr(val, ";")))
			line++;
	}

	if (got != VS_INFECTION_FIELDS)
		return (0);

	/*
	 * We may have info from an X-Violations-Found record, (which provides
	 * more complete information). If so, don't destroy what we have.
	 */
	if ((ctx->vsc_result->vsr_nviolations == 0) ||
	    (ctx->vsc_info.vsi_threat_hdr < VS_RESP_X_INFECTION)) {
		vr = &ctx->vsc_result->vsr_vrec[0];
		vr->vr_id = type;
		vr->vr_res = res;
		(void) strlcpy(vr->vr_desc, desc, VS_DESCRIPTION_MAX);
		ctx->vsc_result->vsr_nviolations = 1;

		ctx->vsc_info.vsi_threat_hdr = VS_RESP_X_INFECTION;
	}

	return (1);
}


/*
 * vs_icap_resp_virus_id
 *
 * X-Virus-ID is defined as being a shorter alternative to X-Infection-Found.
 * If we already have virus information, from either X-Infection-Found or
 * X-Violations-Found, it will be more complete, so don't overwrite it with
 * the info from X-Virus-ID.
 */
/*ARGSUSED*/
static int
vs_icap_resp_virus_id(vs_scan_ctx_t *ctx, int hdr_id, char *line)
{
	vs_vrec_t *vr = 0;

	if (ctx->vsc_result->vsr_nviolations == 0) {
		vr = &ctx->vsc_result->vsr_vrec[0];
		vr->vr_id = 0;
		vr->vr_res = 0;
		(void) strlcpy(vr->vr_desc, line, VS_DESCRIPTION_MAX);
		ctx->vsc_result->vsr_nviolations = 1;

		ctx->vsc_info.vsi_threat_hdr = VS_RESP_X_VIRUS_ID;
	}

	return (1);
}


/*
 * vs_icap_resp_encap
 *
 * get the encapsulated header info
 */
/*ARGSUSED*/
static int
vs_icap_resp_encap(vs_scan_ctx_t *ctx, int hdr_id, char *line)
{
	if (strstr(line, "res-hdr"))
		ctx->vsc_info.vsi_res_hdr = B_TRUE;

	if (strstr(line, "res-body"))
		ctx->vsc_info.vsi_res_body = B_TRUE;

	return (1);
}


/*
 * Utility functions for handling OPTIONS data: vs_options_t
 */

/*
 * vs_icap_compare_scanstamp
 * compare scanstamp with that stored for engine idx
 *
 * Returns: 0 - if equal
 */
int
vs_icap_compare_scanstamp(int idx, vs_scanstamp_t scanstamp)
{
	int rc;

	if (!scanstamp || scanstamp[0] == '\0')
		return (-1);

	(void) pthread_mutex_lock(&vs_opt_mutex);
	rc = strcmp(scanstamp, vs_options[idx].vso_scanstamp);
	(void) pthread_mutex_unlock(&vs_opt_mutex);

	return (rc);
}


/*
 * vs_icap_compare_se
 * compare host and port with that stored for engine idx
 *
 * Returns: 0 - if equal
 */
static int
vs_icap_compare_se(int idx, char *host, int port)
{
	if (vs_options[idx].vso_port != port)
		return (-1);

	if (strcmp(vs_options[idx].vso_host, host) != 0)
		return (-1);

	return (0);
}


/*
 * vs_icap_free_options
 *
 * Free dynamic parts of vs_options_t: xfer_preview, xfer_complete
 */
static void
vs_icap_free_options(vs_options_t *options)
{
	if (options->vso_xfer_preview)
		free(options->vso_xfer_preview);

	if (options->vso_xfer_complete)
		free(options->vso_xfer_complete);

	(void) memset(options, 0, sizeof (vs_options_t));
}


/*
 * vs_icap_copy_options
 */
void
vs_icap_copy_options(vs_options_t *to_opt, vs_options_t *from_opt)
{
	*to_opt = *from_opt;

	if (from_opt->vso_xfer_preview) {
		to_opt->vso_xfer_preview =
		    vs_icap_copy_strvec(from_opt->vso_xfer_preview);
	}

	if (from_opt->vso_xfer_complete) {
		to_opt->vso_xfer_complete =
		    vs_icap_copy_strvec(from_opt->vso_xfer_complete);
	}
}


/*
 * vs_icap_update_options
 */
static void
vs_icap_update_options(vs_scan_ctx_t *ctx)
{
	int idx = ctx->vsc_idx;

	(void) pthread_mutex_lock(&vs_opt_mutex);

	if (vs_icap_compare_se(idx, ctx->vsc_host, ctx->vsc_port) == 0) {
		vs_icap_free_options(&vs_options[idx]);
		vs_icap_copy_options(&vs_options[idx], &ctx->vsc_options);
	}

	(void) pthread_mutex_unlock(&vs_opt_mutex);
}


/*
 * vs_icap_make_strvec
 *
 * Populate a iovec_t from line, where line is a string of 'sep'
 * separated fields. Within the copy of line in the iovec_t each
 * field will be null terminated with leading & trailing whitespace
 * removed. This allows for fast searching.
 *
 * The iovec_t itself and the data it points to are allocated
 * as a single chunk.
 */
static iovec_t *
vs_icap_make_strvec(char *line, const char *sep)
{
	iovec_t *vec;
	char *tmp, *ctx;
	int datalen, len;

	datalen = strlen(line) + 1;
	len = sizeof (iovec_t) + datalen;

	if ((vec = (iovec_t *)calloc(1, len)) == 0)
		return (0);

	vec->iov_len = len;
	vec->iov_base = (char *)vec + sizeof (iovec_t);
	(void) strlcpy(vec->iov_base, line, datalen);

	/* tokenize data for easier searching */
	for (tmp = strtok_r(vec->iov_base, sep, &ctx); tmp;
	    tmp = strtok_r(0, sep, &ctx)) {
	}

	return (vec);
}


/*
 * vs_icap_copy_strvec
 *
 * allocate and copy strvec
 */
static iovec_t *
vs_icap_copy_strvec(iovec_t *from_vec)
{
	iovec_t *to_vec;

	if ((to_vec = (iovec_t *)calloc(1, from_vec->iov_len)) == 0)
		return (0);

	bcopy(from_vec, to_vec, from_vec->iov_len);
	to_vec->iov_base = (char *)to_vec + sizeof (iovec_t);

	return (to_vec);
}


/*
 * vs_icap_check_ext
 *
 * Returns: 1 - if ext in strvec
 *          0 - otherwise
 */
static int
vs_icap_check_ext(char *ext, iovec_t *vec)
{
	char *p, *end = (char *)vec + vec->iov_len;

	for (p = vec->iov_base;  p < end; p += strlen(p) + 1) {
		if (MATCH(ext, p))
			return (1);
	}

	return (0);
}


/*
 * vs_icap_resp_str
 */
static char *
vs_icap_resp_str(int rc)
{
	vs_resp_msg_t *p = icap_resp;

	if (rc < 0)
		rc = -rc;

	while (p->vsm_rc != VS_RESP_UNKNOWN) {
		if (p->vsm_rc == rc)
			break;
		p++;
	}

	return (p->vsm_msg);
}


/*
 * vs_icap_trimspace
 *
 * Trims whitespace from both the beginning and end of a string. This
 * function alters the string buffer in-place.
 *
 * Whitespaces found at the beginning of the string are eliminated by
 * moving forward the start of the string at the first non-whitespace
 * character.
 * Whitespace found at the end of the string are overwritten with nulls.
 *
 */
static void
vs_icap_trimspace(char *buf)
{
	char *p = buf;
	char *q = buf;

	if (buf == 0)
		return;

	while (*p && isspace(*p))
		++p;

	while ((*q = *p++) != 0)
	++q;

	if (q != buf) {
		while ((--q, isspace(*q)) != 0)
			*q = '\0';
	}
}


/*
 * vs_icap_uri_encode
 *
 * Encode uri data (eg filename) in accordance with RFC 2396
 * 'Illegal' characters should be replaced with %hh, where hh is
 * the hex value of the character. For example a space would be
 * replaced with %20.
 * Filenames are all already UTF-8 encoded. Any UTF-8 octects that
 * are 'illegal' characters will be encoded as described above.
 *
 * Paramaters: data - string to be encoded (NULL terminated)
 *             buf  - output buffer (NULL terminated)
 *             size - size of output buffer
 *
 * Returns: strlen of encoded data on success
 *			-1 size on error (contents of buf undefined)
 */
static int
vs_icap_uri_encode(char *buf, int size, char *data)
{
	unsigned char *iptr;
	char *optr = buf;
	int len = strlen(data);

	/* modify the data */
	for (iptr = (unsigned char *)data; *iptr; iptr++) {
		if (vs_icap_uri_illegal_char(*iptr)) {
			if ((len += 2) >= size)
				return (-1);
			(void) sprintf(optr, "%%%0x", *iptr);
			optr += 3;
		} else {
			if (len >= size)
				return (-1);
			*optr++ = *iptr;
		}
	}

	*optr = '\0';
	return (len);
}


/*
 * vs_icap_uri_illegal_char
 *
 * The following us-ascii characters (UTF-8 octets) are 'illegal':
 * < > # % " { } | \ ^ [ ] ` space, 0x01 -> 0x1F & 0x7F
 * All non us-ascii UTF-8 octets ( >= 0x80) are illegal.
 *
 * Returns: 1 if character is not allowed in a URI
 *          0 otherwise
 */
static int
vs_icap_uri_illegal_char(char c)
{
	static const char *uri_illegal_chars = "<>#%\" {}|\\^[]`";

	/* us-ascii non printable characters or non us-ascii */
	if ((c <= 0x1F) || (c >= 0x7F))
		return (1);

	/* us-ascii dis-allowed characters */
	if (strchr(uri_illegal_chars, c))
		return (1);

	return (0);

}
