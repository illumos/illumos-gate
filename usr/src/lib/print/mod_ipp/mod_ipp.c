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
 *
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

/* $Id: mod_ipp.c 149 2006-04-25 16:55:01Z njacobs $ */

/*
 * Internet Printing Protocol (IPP) module for Apache.
 */

#include "ap_config.h"

#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <values.h>
#include <libintl.h>
#include <alloca.h>

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_log.h"
#include "http_main.h"
#ifndef	APACHE2
#include "apr_compat.h"
#define	apr_table_get ap_table_get
#endif	/* APACHE2 */

#include "papi.h"

#include <papi.h>
#include <ipp-listener.h>

#ifndef APACHE2
module MODULE_VAR_EXPORT ipp_module;
#else
module AP_MODULE_DECLARE_DATA ipp_module;
#endif

#ifndef AP_INIT_TAKE1	/* Apache 2.X has this, but 1.3.X does not */
#define	AP_INIT_NO_ARGS(directive, action, arg, where, mesg) \
	{ directive, action, arg, where, NO_ARGS, mesg }
#define	AP_INIT_TAKE1(directive, action, arg, where, mesg) \
	{ directive, action, arg, where, TAKE1, mesg }
#define	AP_INIT_TAKE2(directive, action, arg, where, mesg) \
	{ directive, action, arg, where, TAKE2, mesg }
#endif

typedef struct {
	int conformance;
	char *default_user;
	char *default_svc;
	papi_attribute_t **operations;
} IPPListenerConfig;

#ifdef DEBUG
void
dump_buffer(FILE *fp, char *tag, char *buffer, int bytes)
{
	int i, j, ch;

	fprintf(fp, "%s %d(0x%x) bytes\n", (tag ? tag : ""), bytes, bytes);
	for (i = 0; i < bytes; i += 16) {
		fprintf(fp, "%s   ", (tag ? tag : ""));

		for (j = 0; j < 16 && (i + j) < bytes; j ++)
			fprintf(fp, " %02X", buffer[i + j] & 255);

		while (j < 16) {
			fprintf(fp, "   ");
			j++;
		}

		fprintf(fp, "    ");
		for (j = 0; j < 16 && (i + j) < bytes; j ++) {
			ch = buffer[i + j] & 255;
			if (ch < ' ' || ch == 127)
				ch = '.';
			putc(ch, fp);
		}
		putc('\n', fp);
	}
	fflush(fp);
}
#endif

static ssize_t
read_data(void *fd, void *buf, size_t siz)
{
	ssize_t len_read;
	request_rec *ap_r = (request_rec *)fd;

	len_read = ap_get_client_block(ap_r, buf, siz);
#ifndef APACHE2
	ap_reset_timeout(ap_r);
#endif

#ifdef DEBUG
	fprintf(stderr, "read_data(0x%8.8x, 0x%8.8x, %d): %d",
	    fd, buf, siz, len_read);
	if (len_read < 0)
		fprintf(stderr, ": %s", strerror(errno));
	putc('\n', stderr);
	dump_buffer(stderr, "read_data:", buf, len_read);
#endif

	return (len_read);
}

static ssize_t
write_data(void *fd, void *buf, size_t siz)
{
	ssize_t len_written;
	request_rec *ap_r = (request_rec *)fd;

#ifndef APACHE2
	ap_reset_timeout(ap_r);
#endif
#ifdef DEBUG
	dump_buffer(stderr, "write_data:", buf, siz);
#endif
	len_written = ap_rwrite(buf, siz, ap_r);

	return (len_written);
}

static void
discard_data(request_rec *r)
{
#ifdef APACHE2
	(void) ap_discard_request_body(r);
#else
	/*
	 * This is taken from ap_discard_request_body().  The reason we can't
	 * just use it in Apache 1.3 is that it does various timeout things we
	 * don't want it to do.  Apache 2.0 doesn't do that, so we can safely
	 * use the normal function.
	 */
	if (r->read_chunked || r->remaining > 0) {
		char dumpbuf[HUGE_STRING_LEN];
		int i;

		do {
			i = ap_get_client_block(r, dumpbuf, HUGE_STRING_LEN);
#ifdef DEBUG
			dump_buffer(stderr, "discarded", dumpbuf, i);
#endif
		} while (i > 0);
	}
#endif
}

void _log_rerror(const char *file, int line, int level, request_rec *r,
	const char *fmt, ...)
{
	va_list args;
	size_t size;
	char *message = alloca(BUFSIZ);

	va_start(args, fmt);
	/*
	 * fill in the message.	 If the buffer is too small, allocate
	 * one that is large enough and fill it in.
	 */
	if ((size = vsnprintf(message, BUFSIZ, fmt, args)) >= BUFSIZ)
		if ((message = alloca(size)) != NULL)
			vsnprintf(message, size, fmt, args);
	va_end(args);

#ifdef APACHE2
	ap_log_rerror(file, line, level, APR_SUCCESS, r, message);
#else
	ap_log_rerror(file, line, level, r, message);
#endif
}

static int
ipp_handler(request_rec *r)
{
	papi_attribute_t **request = NULL, **response = NULL;
	IPPListenerConfig *config;
	papi_status_t status;
	const char *s;
	int sockfd = -1;
	int ret;

	/* Really, IPP is all POST requests */
	if (r->method_number != M_POST)
		return (DECLINED);

	/*
	 * An IPP request must have a MIME type of "application/ipp"
	 * (RFC-2910, Section 4, page 19).  If it doesn't match this
	 * MIME type, we should decline the request and let someone else
	 * try and handle it.
	 */
	if (r->headers_in == NULL)
		return (DECLINED);
	s = apr_table_get(r->headers_in, "Content-Type");
	if ((s == NULL) || (strcasecmp(s, "application/ipp") != 0))
		return (DECLINED);

	/* CHUNKED_DECHUNK might not work right for IPP? */
	if ((ret = ap_setup_client_block(r, REQUEST_CHUNKED_DECHUNK)) != OK)
		return (ret);

	if (!ap_should_client_block(r))
		return (HTTP_INTERNAL_SERVER_ERROR);

#ifndef APACHE2
	ap_soft_timeout("ipp_module: read/reply request ", r);
#endif
	/* read the IPP request off the network */
	status = ipp_read_message(read_data, r, &request, IPP_TYPE_REQUEST);

	if (status != PAPI_OK)
		_log_rerror(APLOG_MARK, APLOG_ERR, r,
		    "read failed: %s\n", papiStatusString(status));
#ifdef DEBUG
	papiAttributeListPrint(stderr, request, "request (%d)  ", getpid());
#endif

#ifdef APACHE2
	s = ap_get_remote_host(r->connection, r->per_dir_config,
	    REMOTE_NAME, NULL);
#else
	s = ap_get_remote_host(r->connection, r->per_dir_config,
	    REMOTE_NAME);
#endif
	(void) papiAttributeListAddString(&request, PAPI_ATTR_EXCL,
	    "originating-host", (char *)s);

	(void) papiAttributeListAddInteger(&request, PAPI_ATTR_EXCL,
	    "uri-port", ap_get_server_port(r));

	if (r->headers_in != NULL) {
		char *host = (char *)apr_table_get(r->headers_in, "Host");

		if ((host == NULL) || (host[0] == '\0'))
			host = (char *)ap_get_server_name(r);

		(void) papiAttributeListAddString(&request, PAPI_ATTR_EXCL,
		    "uri-host", host);
	}
	(void) papiAttributeListAddString(&request, PAPI_ATTR_EXCL,
	    "uri-path", r->uri);

	config = ap_get_module_config(r->per_dir_config, &ipp_module);
	if (config != NULL) {
		(void) papiAttributeListAddInteger(&request, PAPI_ATTR_EXCL,
		    "conformance", config->conformance);
		(void) papiAttributeListAddCollection(&request, PAPI_ATTR_EXCL,
		    "operations", config->operations);
		if (config->default_user != NULL)
			(void) papiAttributeListAddString(&request,
			    PAPI_ATTR_EXCL, "default-user",
			    config->default_user);
		if (config->default_svc != NULL)
			(void) papiAttributeListAddString(&request,
			    PAPI_ATTR_EXCL, "default-service",
			    config->default_svc);
	}

	/*
	 * For Trusted Solaris, pass the fd number of the socket connection
	 * to the backend so the it can be forwarded to the backend print
	 * service to retrieve the sensativity label off of a multi-level
	 * port.
	 */
#ifdef	APACHE2
	/*
	 * In Apache 2.4 and later, could use: ap_get_conn_socket()
	 * Apache 2.2 uses ap_get_module_config() but that needs
	 * &core_module, for .module_index (which is just zero).
	 * Could either inline that with index zero, or declare
	 * core_module here.  Latter seems less evil.
	 */
	{
		extern module core_module;
		apr_socket_t *csd = ap_get_module_config(
		    r->connection->conn_config, &core_module);
		if (csd != NULL)
			(void) apr_os_sock_get(&sockfd, csd);
	}
#else
	sockfd = ap_bfileno(r->connection->client, B_RD);
#endif
	if (sockfd != -1) {
		(void) papiAttributeListAddInteger(&request,
		    PAPI_ATTR_EXCL, "peer-socket", sockfd);
	}

	/* process the request */
	status = ipp_process_request(request, &response, read_data, r);
	if (status != PAPI_OK) {
		errno = 0;
		_log_rerror(APLOG_MARK, APLOG_ERR, r,
		    "request failed: %s\n", papiStatusString(status));
		discard_data(r);
	}
#ifdef DEBUG
	fprintf(stderr, "processing result: %s\n", papiStatusString(status));
	papiAttributeListPrint(stderr, response, "response (%d)  ", getpid());
#endif

	/*
	 * If the client is using chunking and we have not yet received the
	 * final "0" sized chunk, we need to discard any data that may
	 * remain in the post request.
	 */
	if ((r->read_chunked != 0) &&
	    (apr_table_get(r->headers_in, "Content-Length") == NULL))
		discard_data(r);

	/* write an IPP response back to the network */
	r->content_type = "application/ipp";

#ifndef	APACHE2
	ap_send_http_header(r);
#endif

	status = ipp_write_message(write_data, r, response);
	if (status != PAPI_OK)
		_log_rerror(APLOG_MARK, APLOG_ERR, r,
		    "write failed: %s\n", papiStatusString(status));
#ifdef DEBUG
	fprintf(stderr, "write result: %s\n", papiStatusString(status));
	fflush(stderr);
#endif

	papiAttributeListFree(request);
	papiAttributeListFree(response);

#ifndef APACHE2
	ap_kill_timeout(r);
	if (ap_rflush(r) < 0)
		_log_rerror(APLOG_MARK, APLOG_ERR, r,
		    "flush failed, response may not have been sent");
#endif

	return (OK);
}


/*ARGSUSED1*/
static void *
create_ipp_dir_config(
#ifndef APACHE2
	pool *p,
#else
	apr_pool_t *p,
#endif
	char *dirspec)
{
	IPPListenerConfig *config;
#ifndef APACHE2
	config = ap_pcalloc(p, sizeof (*config));
#else
	config = apr_pcalloc(p, sizeof (*config));
#endif

	if (config != NULL) {
		(void) memset(config, 0, sizeof (*config));
		config->conformance = IPP_PARSE_CONFORMANCE_RASH;
		config->default_user = NULL;
		config->default_svc = NULL;
		(void) ipp_configure_operation(&config->operations,
		    "required", "enable");
	}

	return (config);
}

/*ARGSUSED0*/
static const char *
ipp_conformance(cmd_parms *cmd, void *cfg, const char *arg)
{
	IPPListenerConfig *config = (IPPListenerConfig *)cfg;

	if (strncasecmp(arg, "automatic", 4) == 0) {
		config->conformance = IPP_PARSE_CONFORMANCE_RASH;
	} else if (strcasecmp(arg, "1.0") == 0) {
		config->conformance = IPP_PARSE_CONFORMANCE_LOOSE;
	} else if (strcasecmp(arg, "1.1") == 0) {
		config->conformance = IPP_PARSE_CONFORMANCE_STRICT;
	} else {
		return ("unknown conformance, try (automatic/1.0/1.1)");
	}

	return (NULL);
}

/*ARGSUSED0*/
static const char *
ipp_operation(cmd_parms *cmd, void *cfg, const char *op, const char *toggle)
{
	IPPListenerConfig *config = (IPPListenerConfig *)cfg;
	papi_status_t status;

	status = ipp_configure_operation(&config->operations,
	    (char *)op, (char *)toggle);
	switch (status) {
	case PAPI_OK:
		return (NULL);
	case PAPI_BAD_ARGUMENT:
		return (gettext("internal error (invalid argument)"));
	default:
		return (papiStatusString(status));
	}

	/* NOTREACHED */
	/* return (gettext("contact your software vendor")); */
}

static const char *
ipp_default_user(cmd_parms *cmd, void *cfg, const char *arg)
{
	IPPListenerConfig *config = (IPPListenerConfig *)cfg;

	config->default_user = (char *)arg;

	return (NULL);
}

static const char *
ipp_default_svc(cmd_parms *cmd, void *cfg, const char *arg)
{
	IPPListenerConfig *config = (IPPListenerConfig *)cfg;

	config->default_svc = (char *)arg;

	return (NULL);
}

#ifdef DEBUG
/*ARGSUSED0*/
volatile int ipp_module_hang_sleeping = 1;
static const char *
ipp_module_hang(cmd_parms *cmd, void *cfg)
{

	/*
	 * Wait so we can attach with a debugger.  Once attached,
	 * assign ipp_module_hang_sleeping = 0 and step through.
	 */
	while (ipp_module_hang_sleeping)
		sleep(1);

	return (NULL);
}
#endif /* DEBUG */

static const command_rec ipp_cmds[] =
{
	AP_INIT_TAKE1("ipp-conformance", ipp_conformance, NULL, ACCESS_CONF,
		"IPP protocol conformance (loose/strict)"),
	AP_INIT_TAKE2("ipp-operation", ipp_operation, NULL, ACCESS_CONF,
		"IPP protocol operations to enable/disable)"),
	AP_INIT_TAKE1("ipp-default-user", ipp_default_user, NULL, ACCESS_CONF,
		"default user for various operations"),
	AP_INIT_TAKE1("ipp-default-service", ipp_default_svc, NULL, ACCESS_CONF,
		"default service for various operations"),
#ifdef DEBUG
	AP_INIT_NO_ARGS("ipp-module-hang", ipp_module_hang, NULL, ACCESS_CONF,
		"hang the module until we can attach a debugger (no args)"),
#endif
	{ NULL }
};

#ifdef APACHE2
/*ARGSUSED0*/
static const char *
ipp_scheme(const request_rec *r)
{
	return ("ipp");
}

/*ARGSUSED0*/
static unsigned short
ipp_port(const request_rec *r)
{
	return (631);
}

/* Dispatch list for API hooks */
/*ARGSUSED0*/
static void
ipp_register_hooks(apr_pool_t *p)
{
	static const char * const modules[] = { "mod_dir.c", NULL };

	/* Need to make sure we don't get directory listings by accident */
	ap_hook_handler(ipp_handler, NULL, modules, APR_HOOK_MIDDLE);
	ap_hook_default_port(ipp_port, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_http_scheme(ipp_scheme, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA ipp_module = {
	STANDARD20_MODULE_STUFF,
	create_ipp_dir_config,		/* create per-dir    config	*/
	NULL,				/* merge  per-dir    config	*/
	NULL,				/* create per-server config	*/
	NULL,				/* merge  per-server config	*/
	ipp_cmds,			/* table of config commands	*/
	ipp_register_hooks		/* register hooks		*/
};

#else	/* Apache 1.X */

/* Dispatch list of content handlers */
static const handler_rec ipp_handlers[] = {
	/*
	 * This handler association causes all IPP request with the
	 * correct MIME type to call the protocol handler.
	 */
	{ "application/ipp", ipp_handler },
	/*
	 * This hander association is causes everything to go through the IPP
	 * protocol request handler.  This is necessary because client POST
	 * request may be for something outside of the normal printer-uri
	 * space.
	 */
	{ "*/*", ipp_handler },

	{ NULL, NULL }
};


module MODULE_VAR_EXPORT ipp_module = {
	STANDARD_MODULE_STUFF,
	NULL,			/* module initializer			*/
	create_ipp_dir_config,	/* create per-dir    config structures	*/
	NULL,			/* merge  per-dir    config structures	*/
	NULL,			/* create per-server config structures	*/
	NULL,			/* merge  per-server config structures	*/
	ipp_cmds,		/* table of config file commands	*/
	ipp_handlers,		/* [#8] MIME-typed-dispatched handlers	*/
	NULL,			/* [#1] URI to filename translation	*/
	NULL,			/* [#4] validate user id from request	*/
	NULL,			/* [#5] check if the user is ok _here_	*/
	NULL,			/* [#3] check access by host address	*/
	NULL,			/* [#6] determine MIME type		*/
	NULL,			/* [#7] pre-run fixups			*/
	NULL,			/* [#9] log a transaction		*/
	NULL,			/* [#2] header parser			*/
	NULL,			/* child_init				*/
	NULL,			/* child_exit				*/
	NULL			/* [#0] post read-request		*/
};
#endif
