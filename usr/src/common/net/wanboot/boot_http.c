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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2012, OmniTI Computer Consulting, Inc. All rights reserved.
 */

#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <netdb.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/pkcs12.h>

/* this must be included after ssl.h to avoid re-defining 'offsetof' */
#include <sys/sysmacros.h>

#include <boot_http.h>
#include <socket_inet.h>
#include <p12access.h>

#include "bootlog.h"

#define	BOOT_HTTP_MAJOR_VERSION	1
#define	BOOT_HTTP_MINOR_VERSION	0
#define	BOOT_HTTP_MICRO_VERSION	0

static boot_http_ver_t boot_http_ver = {
	BOOT_HTTP_MAJOR_VERSION,
	BOOT_HTTP_MINOR_VERSION,
	BOOT_HTTP_MICRO_VERSION
};

static int	early_err;	/* Error from before error occurred */

static boolean_t verbosemode = B_FALSE;
static char	*cipher_list = NULL; /* Ciphers supported (if not default) */

typedef struct {
	int	i;		/* current position in buffer */
	int	n;		/* number of bytes in buffer */
	char	buf[512];	/* buffer */
} buf_struct_t;

typedef struct {
	uint_t	errsrc;		/* Source of this error */
	ulong_t	error;		/* Which error? */
} errent_t;


typedef enum {
	HTTP_REQ_TYPE_HEAD = 1,
	HTTP_REQ_TYPE_GET
} http_req_t;

#define	FAILSAFE 20		/* Max # empty lines to accept */
#define	DEFAULT_TIMEOUT	10	/* Default socket read timeout value */
#define	HTTP_CONN_INFO 0x90919293 /* Identifies a http_conn_t struct */
#define	ESTACK_SIZE	20	/* Size of the stack */

typedef struct http_conn_t {
	uint_t	signature;	/* Cookie indicating this is a handle */
	int	fd;		/* Connection's fd... */
	SSL_CTX *ctx;
	void	*ssl;		/* Handle to ssl data structure */
	int	read_timeout;	/* Timeout to use on read requests in sec */
	char    *basic_auth_userid;   /* Basic authentication user ID */
	char   	*basic_auth_password; /* and password */
	char	is_multipart;	/* B_TRUE if doing multipart/mixed download */
	char	is_firstpart;	/* B_TRUE if first part in a multipart xfer */
	char	is_firstchunk;	/* B_TRUE if first chunk in chunked xfer */
	char	is_chunked;	/* B_TRUE if message body is chunked */
	boolean_t keepalive;
	struct	sockaddr_in  host_addr; /* Address of host */
	url_t		uri;   		/* The current URI */
	url_hport_t	proxy;		/* The proxy info */
	boolean_t 	proxied;	/* Connection is proxied */
	char	*random_file;	/* File with seed info for pseudo random  */
				/* number generator */
	char	*client_cert_file;	/* File holding client's certificate */
	char	*private_key_file;	/* File with the private key */
	char	*file_password;	/* file with password to key or pkcs12 file. */
	http_respinfo_t resp;	/* Response summary info */
	char	**resphdr;	/* Array of header response lines */
	buf_struct_t inbuf;
	char	*boundary;	/* Boundary text (multipart downloads only) */
	uint_t	boundary_len;	/* Length of boundary string */
	uint_t	numerrs;
	uint_t	nexterr;	/* Next error to return */
	ssize_t	body_size;	/* Size of message body or chunk */
	ssize_t	body_read;	/* # of bytes of body_size processed */
	ssize_t	body_size_tot;	/* Total message body size */
	ssize_t	body_read_tot;	/* # of bytes of body_size_tot processed */
	errent_t errs[ESTACK_SIZE]; /* stack of errors on the last request */
				/* (libssl can return multiple errors on one */
				/* operation) */
} http_conn_t;

/*
 * Convenient macros for accessing fields in connection structure.
 */
#define	CONN_HOSTNAME		c_id->uri.hport.hostname
#define	CONN_PORT		c_id->uri.hport.port
#define	CONN_ABSPATH		c_id->uri.abspath
#define	CONN_HTTPS		c_id->uri.https
#define	CONN_PROXY_HOSTNAME	c_id->proxy.hostname
#define	CONN_PROXY_PORT		c_id->proxy.port

#define	RESET_ERR(c_id)	(c_id)->numerrs = 0, (c_id)->nexterr = 0
#define	SET_ERR(c_id, src, err)	if ((c_id)->numerrs < ESTACK_SIZE) \
		(c_id)->errs[(c_id)->numerrs].errsrc = (src), \
		(c_id)->errs[(c_id)->numerrs ++].error = (err)

#define	GET_ERR(c_id, e_src, e_code) \
		if ((c_id)->nexterr < (c_id)->numerrs) \
			(e_src) = (c_id)->errs[((c_id)->nexterr)].errsrc, \
			(e_code) = (c_id)->errs[((c_id)->nexterr)++].error; \
		else \
			(e_src) = 0, (e_code) = 0

/*
 * Macro used to increment message body read counters
 */
#define	INC_BREAD_CNT(bool, bcnt) \
	if (bool) { \
		bcnt--; \
		c_id->body_read++;\
		c_id->body_read_tot++; \
	}

static int	ssl_init = 0;		/* 1 when ssl has been initialized */
static char	*ca_verify_file;	/* List of trusted CA's  */
static int	verify_depth = 16;	/* Certificate chain depth to verify */
static int	p12_format = 0;		/* Default to PEM format */


/* prototypes for local functions */
static int	http_req(http_handle_t, const char *, http_req_t, offset_t,
    offset_t);
static boolean_t http_check_conn(http_conn_t *);
static SSL_CTX *initialize_ctx(http_conn_t *);
static int	tcp_connect(http_conn_t *, const char *, uint16_t);
static int	readline(http_conn_t *, int, char *, int);
static int	proxy_connect(http_conn_t *);
static int	check_cert_chain(http_conn_t *, char *);
static void	print_ciphers(SSL *);
static int	read_headerlines(http_conn_t *, boolean_t);
static void	free_response(http_conn_t *, int);
static int	free_ctx_ssl(http_conn_t *);
static int	get_chunk_header(http_conn_t *);
static int	init_bread(http_conn_t *);
static int	get_msgcnt(http_conn_t *, ssize_t *);
static int	getaline(http_conn_t *, char *, int, boolean_t);
static int	getbytes(http_conn_t *, char *, int);
static int	http_srv_send(http_conn_t *, const void *, size_t);
static int	http_srv_recv(http_conn_t *, void *, size_t);
static void	handle_ssl_error(http_conn_t *, int);
static int	count_digits(int);
static int	hexdigit(char);
static char	*eat_ws(const char *);
static boolean_t startswith(const char **strp, const char *starts);

/* ---------------------- public functions ----------------------- */

/*
 * http_set_p12_format - Set flag indicating that certs & keys will be in
 *                    pkcs12 format.
 *
 * Default is PEM certs.  When this is called, the default can be changed to
 * pcs12 format.
 */
void
http_set_p12_format(int on_off)
{
	p12_format = on_off;
}

/*
 * http_get_version - Get current boot http support version
 *
 *     pVer = http_get_version();
 *
 * Arguments:
 *	None.
 *
 * Returns:
 *	Pointer to struct with version information.
 *
 * Returns the version of the http support in the current library.  This
 * is a struct with unsigned integsrs for <major>, <minor> and
 * <micro> version numbers.  <major> changes when an incompatible change
 * is made.  <minor> changes when an upwardly-compatible API change is
 * made.  <micro> consists of bug fixes, etc.
 */
boot_http_ver_t const *
http_get_version(void)
{
	return (&boot_http_ver);
}

/*
 * http_set_verbose - Turn verbose on/off
 *
 *     http_set_verbose(on_off);
 *
 * Arguments:
 *	on_off	- When TRUE, turn verbose mode one.  When FALSE, turn
 *		  verbose off.
 *
 * Returns:
 *	None.
 *
 * When enabled, information is logged to bootlog (or the Solaris equivalent).
 */
void
http_set_verbose(boolean_t on_off)
{
	verbosemode = on_off;
}

/*
 * http_set_cipher_list - Change the list of ciphers that can be used.
 *
 *     ret = http_set_cipher_list(handle, list);
 *
 * Arguments:
 *	list	- List of ciphers that can be used.
 *
 * Returns:
 *	0	- Success
 *	-1	- An error occurred.  Check http_get_lasterr().
 */
int
http_set_cipher_list(const char *list)
{
	early_err = 0;

	if (list != NULL) {
		list = strdup(list);
		if (list == NULL) {
			early_err = EHTTP_NOMEM;
			return (-1);
		}
	}

	free(cipher_list);
	cipher_list = (char *)list;
	return (0);
}

/*
 * http_srv_init - Set up a structure for a connection.
 *
 *     handle = http_srv_init(url);
 *
 * Arguments:
 *	url - the structure that contains the URI.
 *
 * Returns:
 *	!= NULL	- A handle for referring to this connection.
 *	== NULL - An error occurred.  Get the exact error from
 *                http_get_lasterr().
 */
http_handle_t
http_srv_init(const url_t *url)
{
	http_conn_t	*c_id;

	early_err = 0;
	if (url == NULL) {
		early_err = EHTTP_BADARG;
		return (NULL);
	}

	if ((c_id = malloc(sizeof (*c_id))) == NULL) {
		early_err = EHTTP_NOMEM;
		return (NULL);
	}

	bzero(c_id, sizeof (*c_id));
	c_id->uri = *url;
	c_id->proxied = B_FALSE;
	c_id->read_timeout = DEFAULT_TIMEOUT;
	c_id->keepalive = B_TRUE;
	c_id->fd = -1;

	/* Do this at the end, just in case.... */
	c_id->signature = HTTP_CONN_INFO;

	return (c_id);
}

/*
 * http_conn_is_https - Determine whether the scheme is http or https.
 *
 *	B_TRUE	- Connection is an SSL connection.
 *	B_FALSE - Connection isn't SSL.
 *
 *     ret = http_conn_is_https(handle, boolean_t *bool);
 *
 * Arguments:
 *	handle	- Handle associated with the desired connection
 *	bool	- Ptr to boolean in which to place result
 *
 * Returns:
 *	0	- Success
 *	-1	- Some error occurred.
 */
int
http_conn_is_https(http_handle_t handle, boolean_t *bool)
{
	http_conn_t	*c_id = handle;

	if (!http_check_conn(c_id))
		return (-1);

	*bool = CONN_HTTPS;
	return (0);
}

/*
 * http_set_proxy - Establish the proxy name/port.
 *
 *     ret = http_set_proxy(handle, proxy);
 *
 * Arguments:
 *	handle	- Handle associated with the desired connection
 *	proxy	- The hostport definition for the proxy. If NULL,
 *		  The next connect will not use a proxy.
 *
 * Returns:
 *	0	- Success
 *	-1	- An error occurred.  Check http_get_lasterr().
 */
int
http_set_proxy(http_handle_t handle, const url_hport_t *proxy)
{
	http_conn_t *c_id = handle;

	if (!http_check_conn(c_id))
		return (-1);

	if (proxy != NULL) {
		c_id->proxy = *proxy;
		c_id->proxied = B_TRUE;
	} else {
		CONN_PROXY_HOSTNAME[0] = '\0';
		c_id->proxied = B_FALSE;
	}

	return (0);
}

/*
 * http_set_keepalive - Set keepalive for this connection.
 *
 *     http_set_keepalive(handle, on_off);
 *
 * Arguments:
 *	handle	- Handle associated with the desired connection
 *	on_off	- Boolean turning keepalive on (TRUE) or off (FALSE)
 *
 * Returns:
 *	0	- Success.
 *	-1	- An error occurred.  Check http_get_lasterr().
 *
 * This setting takes effect next time a connection is opened using this
 * handle.
 */
int
http_set_keepalive(http_handle_t handle, boolean_t on_off)
{
	http_conn_t *c_id = handle;

	if (!http_check_conn(c_id))
		return (-1);

	c_id->keepalive = on_off;
	return (0);
}

/*
 * http_set_socket_read_timeout - Set the timeout reads
 *
 *     http_set_socket_read_timeout(handle, timeout);
 *
 * Arguments:
 *	handle	- Handle associated with the desired connection
 *	timeout	- Timeout, in seconds.  Zero will default to 10 second
 *		  timeouts.
 *
 * Returns:
 *	0	- Success.
 *	-1	- An error occurred.  Check http_get_lasterr().
 *
 * This setting takes effect beginning with the next read operation on this
 * connection.
 */
int
http_set_socket_read_timeout(http_handle_t handle, uint_t timout)
{
	http_conn_t *c_id = handle;

	if (!http_check_conn(c_id))
		return (-1);

	c_id->read_timeout = (timout) ? timout : DEFAULT_TIMEOUT;
	return (0);
}

/*
 * http_set_basic_auth - Set the basic authorization user ID and password
 *
 *     ret = http_set_basic_auth(handle, userid, password);
 *
 * Arguments:
 *	handle	- Handle associated with the desired connection
 *	userid	- ID to pass as part of http/https request
 *	password- Password which goes with the user ID
 *
 * Returns:
 *	0	- Success
 *	-1	- An error occurred.  Check http_get_lasterr().
 *
 * This must be set before a https connection is made.
 */
int
http_set_basic_auth(http_handle_t handle, const char *userid,
    const char *password)
{
	http_conn_t *c_id = handle;

	if (!http_check_conn(c_id))
		return (-1);

	if (password == NULL || userid == NULL || userid[0] == '\0') {
		SET_ERR(c_id, ERRSRC_LIBHTTP, EHTTP_BADARG);
		return (-1);
	}

	userid = strdup(userid);
	password = strdup(password);
	if (userid == NULL || password == NULL) {
		free((void *)userid);
		free((void *)password);
		SET_ERR(c_id, ERRSRC_LIBHTTP, EHTTP_NOMEM);
		return (-1);
	}

	free(c_id->basic_auth_userid);
	c_id->basic_auth_userid = (char *)userid;
	free(c_id->basic_auth_password);
	c_id->basic_auth_password = (char *)password;
	return (0);
}

/*
 * http_set_random_file - See the pseudo random number generator with file data
 *
 *     ret = http_set_random_file(handle, filename);
 *
 * Arguments:
 *	handle	- Handle associated with the desired connection
 *	filename
 *		- filename (including path) with random number seed.
 *
 * Returns:
 *	0	- Success
 *	-1	- An error occurred.  Check http_get_lasterr().
 *
 * This must be set before a https connection is made.
 */
int
http_set_random_file(http_handle_t handle, const char *fname)
{
	http_conn_t *c_id = handle;

	if (!http_check_conn(c_id))
		return (-1);

	if (fname != NULL) {
		fname = strdup(fname);
		if (fname == NULL) {
			SET_ERR(c_id, ERRSRC_LIBHTTP, EHTTP_NOMEM);
			return (-1);
		}
	}

	free(c_id->random_file);
	c_id->random_file = (char *)fname;
	return (0);
}

/*
 * http_set_certificate_authority_file - Set the CA file.
 *
 *     ret = http_set_certificate_authority_file(filename);
 *
 * Arguments:
 *	filename- File with the certificate authority certs
 *
 * Returns:
 *	0	- Success
 *	-1	- An error occurred.  Check http_get_lasterr().
 *
 * This must be set before https connections to the servers is done.
 */
int
http_set_certificate_authority_file(const char *fname)
{
	early_err = 0;

	if (fname != NULL) {
		fname = strdup(fname);
		if (fname == NULL) {
			early_err = EHTTP_NOMEM;
			return (-1);
		}
	}

	free(ca_verify_file);
	ca_verify_file = (char *)fname;
	return (0);
}

/*
 * http_set_client_certificate_file - Set the file containing the PKCS#12
 *		client certificate and optionally its certificate chain.
 *
 *     ret = http_set_client_certificate_file(handle, filename);
 *
 * Arguments:
 *	handle	- Handle associated with the desired connection
 *	filename- File (including path) containing certificate, etc.
 *
 * Returns:
 *	0	- Success
 *	-1	- An error occurred.  Check http_get_lasterr().
 *
 * This must be set before the handle is used to make a https connection
 * which will require a client certificate.
 */
int
http_set_client_certificate_file(http_handle_t handle, const char *fname)
{
	http_conn_t *c_id = handle;

	if (!http_check_conn(c_id))
		return (-1);

	if (fname != NULL) {
		fname = strdup(fname);
		if (fname == NULL) {
			SET_ERR(c_id, ERRSRC_LIBHTTP, EHTTP_NOMEM);
			return (-1);
		}
	}

	free(c_id->client_cert_file);
	c_id->client_cert_file = (char *)fname;
	return (0);
}

/*
 * http_set_password - Set the password for the private key or pkcs12 file.
 *
 *     ret = http_set_password(handle, password);
 *
 * Arguments:
 *	handle	- Handle associated with the desired connection
 *	password- Password for the client's private key file or pkcs12 file.
 *
 * Returns:
 *	0	- Success
 *	-1	- An error occurred.  Check http_get_lasterr().
 *
 * This must be set before the handle is used to make a https connection.
 */
int
http_set_password(http_handle_t handle, const char *password)
{
	http_conn_t *c_id = handle;

	if (!http_check_conn(c_id))
		return (-1);

	if (password != NULL) {
		password = strdup(password);
		if (password == NULL) {
			SET_ERR(c_id, ERRSRC_LIBHTTP, EHTTP_NOMEM);
			return (-1);
		}
	}

	free(c_id->file_password);
	c_id->file_password = (char *)password;
	return (0);
}

/*
 * http_set_key_file_password - Set the password for the private key
 *		file.
 *
 *     ret = http_set_key_file_password(handle, password);
 *
 * Arguments:
 *	handle	- Handle associated with the desired connection
 *	password- Password for the client's private key file.
 *
 * Returns:
 *	0	- Success
 *	-1	- An error occurred.  Check http_get_lasterr().
 *
 * This must be set before the handle is used to make a https connection.
 */
int
http_set_key_file_password(http_handle_t handle, const char *password)
{
	return (http_set_password(handle, password));
}

/*
 * http_set_private_key_file - Set the file containing the PKCS#12
 *		private key for this client.
 *
 *     ret = http_set_private_key_file(handle, filename);
 *
 * Arguments:
 *	handle	- Handle associated with the desired connection
 *	filename- File (including path) containing the private key.
 *
 * Returns:
 *	0	- Success
 *	-1	- An error occurred.  Check http_get_lasterr().
 *
 * This must be set before the handle is used to make a https connection.
 */
int
http_set_private_key_file(http_handle_t handle, const char *fname)
{
	http_conn_t *c_id = handle;

	if (!http_check_conn(c_id))
		return (-1);

	if (fname != NULL) {
		fname = strdup(fname);
		if (fname == NULL) {
			SET_ERR(c_id, ERRSRC_LIBHTTP, EHTTP_NOMEM);
			return (-1);
		}
	}

	free(c_id->private_key_file);
	c_id->private_key_file = (char *)fname;
	return (0);
}

/*
 * http_srv_connect - Establish a connection to the server
 *
 *     ret = http_srv_connect(handle);
 *
 * Arguments:
 *	handle	- Handle associated with the desired connection
 *
 * Returns:
 *	0	- Success
 *	-1	- An error occurred.  Check http_get_lasterr() for specifics.
 */
int
http_srv_connect(http_handle_t handle)
{
	http_conn_t	*c_id = handle;
	SSL_CTX		*ctx = NULL;
	int		retval;

	ERR_clear_error();
	if (!http_check_conn(c_id))
		return (-1);

	if (CONN_HTTPS) {
		/* Build our SSL context (this function sets any errors) */
		ctx = initialize_ctx(c_id);
		if (ctx == NULL) {
			libbootlog(BOOTLOG_CRIT,
			    "http_srv_connect: initialize_ctx returned NULL");
			return (-1);
		}
	}

	/* Connect the TCP socket */
	if (c_id->proxied) {
		c_id->fd = proxy_connect(c_id);
	} else {
		c_id->fd = tcp_connect(c_id, CONN_HOSTNAME, CONN_PORT);
	}

	if (c_id->fd < 0) {
		if (ctx != NULL)
			SSL_CTX_free(ctx);
		libbootlog(BOOTLOG_CRIT, "http_srv_connect: %s returned %d",
		    (c_id->proxied) ? "proxy_connect" : "tcp_connect",
		    c_id->fd);
		return (-1);
	}

	if (CONN_HTTPS) {
		/* Connect the SSL socket */
		if ((c_id->ssl = SSL_new(ctx)) == NULL) {
			ulong_t err;
			while ((err = ERR_get_error()) != 0)
				SET_ERR(c_id, ERRSRC_LIBSSL, err);
				libbootlog(BOOTLOG_CRIT,
				    "http_srv_connect: SSL_new returned "
				    "NULL");
			(void) free_ctx_ssl(c_id);
			return (-1);
		}
		if (verbosemode)
			print_ciphers(c_id->ssl);

		/* Ensure automatic negotiations will do things right */
		SSL_set_connect_state(c_id->ssl);

		if (SSL_set_fd(c_id->ssl, c_id->fd) == 0) {
			ulong_t err;
			while ((err = ERR_get_error()) != 0)
				SET_ERR(c_id, ERRSRC_LIBSSL, err);
				libbootlog(BOOTLOG_CRIT,
				    "http_srv_connect: SSL_set_fd returned 0");
			(void) free_ctx_ssl(c_id);
			return (-1);
		}

		if ((retval = SSL_connect(c_id->ssl)) <= 0) {
			handle_ssl_error(c_id, retval);
			libbootlog(BOOTLOG_CRIT,
			    "http_srv_connect: SSL_connect");
			(void) free_ctx_ssl(c_id);
			return (-1);
		}

		if (check_cert_chain(c_id, CONN_HOSTNAME) != 0) {
			(void) free_ctx_ssl(c_id);
			return (-1);
		}

		if (verbosemode)
			print_ciphers(c_id->ssl);
	}

	return (0);
}

/*
 * http_head_request - Issue http HEAD request
 *
 *     ret = http_head_request(handle, abs_path);
 *
 * Arguments:
 *	handle	- Handle associated with the desired connection
 *	abs_path- File name portion of the URI, beginning with a /.  Query,
 *		  segment, etc are allowed.
 *
 * Returns:
 *	0	- Success
 *	-1	- An error occurred.  Check http_get_lasterr().
 */
int
http_head_request(http_handle_t handle, const char *abs_path)
{
	return (http_req(handle, abs_path, HTTP_REQ_TYPE_HEAD, 0, 0));
}

/*
 * http_get_request - Issue http GET request without a range.
 *
 *     ret = http_get_request(handle, abs_path);
 *
 * Arguments:
 *	handle	- Handle associated with the desired connection
 *	abs_path- File name portion of the URI, beginning with a /.  Query,
 *		  segment, etc are allowed.
 *
 * Returns:
 *	0	- Success
 *	-1	- An error occurred.  Check http_get_lasterr().
 */
int
http_get_request(http_handle_t handle, const char *abs_path)
{
	return (http_req(handle, abs_path, HTTP_REQ_TYPE_GET, -1, 0));
}

/*
 * http_get_range_request - Issue http GET request using a range.
 *
 *     ret = http_get_range_request(handle, abs_path, curpos, len);
 *
 * Arguments:
 *	handle	- Handle associated with the desired connection
 *	abs_path- File name portion of the URI, beginning with a /.  Query,
 *		  segment, etc are allowed.
 *	curpos  - >=0 - Beginning of range
 *	len	- = 0 - Range ends at the end of the file
 *		  > 0 - Length of range.
 *
 * Returns:
 *	0	- Success
 *	-1	- An error occurred.  Check http_get_lasterr().
 */
int
http_get_range_request(http_handle_t handle, const char *abs_path,
    offset_t curpos, offset_t len)
{
	http_conn_t *c_id = handle;

	if (!http_check_conn(c_id))
		return (-1);

	if (curpos < 0) {
		SET_ERR(c_id, ERRSRC_LIBHTTP, EHTTP_BADARG);
		return (-1);
	}

	return (http_req(handle, abs_path, HTTP_REQ_TYPE_GET, curpos, len));
}

/*
 * http_free_respinfo - Free a respinfo structure
 *
 *     ret = http_free_respinfo(resp);
 *
 * Arguments:
 *	resp	- respinfo structure presumably allocated by
 *		  http_process_headers() or http_process_part_headers()
 *
 * Note that if resp is NULL, then this results in a NOOP.
 *
 */
void
http_free_respinfo(http_respinfo_t *resp)
{
	if (resp == NULL) {
		return;
	}

	if (resp->statusmsg != NULL) {
		free(resp->statusmsg);
	}
	free(resp);
}

/*
 * http_process_headers - Read in the header lines from the response
 *
 *     ret = http_process_headers(handle, resp);
 *
 * Arguments:
 *	handle	- Handle associated with the connection where the request
 *		  was made.
 *	resp	- Summary information about the response.
 *
 * Returns:
 *	0	- Success
 *	< 0	- An error occurred.  Specifics of the error can
 *		  be gotten using http_get_lasterr().
 *
 * Process the HTTP headers in the response. Check for a valid response
 * status line.  Allocate and return response information via the 'resp'
 * argument. Header lines are stored locally, are are returned using calls
 * to http_get_response_header() and http_get_header_value().
 *
 * Note that the errors will be set in the http_conn_t struct before the
 * function which detected the error returns.
 *
 * Note that if resp is non-NULL, then upon a successful return, information
 * about the status line, the code in the status line and the number of
 * header lines are returned in the http_respinfo_t structure. The caller is
 * responsible for freeing the resources allocated to this structure via
 * http_free_respinfo().
 *
 * Note that the counters used to read message bodies are initialized here.
 *
 * Calling this function replaces the header information which is
 * queried using http_get_response_header() and http_get_header_value().
 * Once this function is called, headers read by the previous call
 * to http_process_headers() or http_process_part_headers() is lost.
 */
int
http_process_headers(http_handle_t handle, http_respinfo_t **resp)
{
	http_conn_t *c_id = handle;
	http_respinfo_t *lresp;
	char	line[MAXHOSTNAMELEN];
	char	*ptr;
	int	i;

	ERR_clear_error();
	if (!http_check_conn(c_id))
		return (-1);

	if (resp != NULL) {
		if ((lresp = malloc(sizeof (http_respinfo_t))) == NULL) {
			SET_ERR(c_id, ERRSRC_LIBHTTP, EHTTP_NOMEM);
			return (-1);
		}

		bzero(lresp, sizeof (http_respinfo_t));
	}

	/*
	 * check the response status line, expecting
	 * HTTP/1.1 200 OK
	 */
	i = getaline(c_id, line, sizeof (line), B_FALSE);
	if (i == 0) {
		if (resp != NULL) {
			*resp = lresp;
		}
		return (0);
	}

	if (i < 0) {
		/*
		 * Cause of I/O error was already put into
		 * error stack.  This is an additional error.
		 */
		http_free_respinfo(lresp);
		SET_ERR(c_id, ERRSRC_LIBHTTP, EHTTP_NODATA);
		return (-1);
	}

	free_response(c_id, B_TRUE);

	if (verbosemode)
		libbootlog(BOOTLOG_VERBOSE, "http_process_headers: %s", line);

	ptr = line;
	if (strncmp(ptr, "HTTP/1.1", 8) != 0) {
		http_free_respinfo(lresp);
		SET_ERR(c_id, ERRSRC_LIBHTTP, EHTTP_NOT_1_1);
		return (-1);
	}

	/* skip to the code */
	ptr += 8;
	while (isspace(*ptr))
		ptr++;

	/* make sure it's three digits */
	i = 0;
	while (isdigit(ptr[i]))
		i++;
	if (i != 3) {
		http_free_respinfo(lresp);
		SET_ERR(c_id, ERRSRC_LIBHTTP, EHTTP_BADHDR);
		return (-1);
	}
	c_id->resp.code = strtol(ptr, NULL, 10);

	/* skip to the message */
	ptr += 3;
	while (isspace(*ptr))
		ptr++;

	/* save the message */
	c_id->resp.statusmsg = malloc(strlen(ptr) + 1);
	if (c_id->resp.statusmsg == NULL) {
		http_free_respinfo(lresp);
		SET_ERR(c_id, ERRSRC_LIBHTTP, EHTTP_NOMEM);
		return (-1);
	}
	(void) strcpy(c_id->resp.statusmsg, ptr);

	if ((i = read_headerlines(c_id, B_FALSE)) < 0) {
		/*
		 * Error stack was already set at a lower level.
		 * 'statusmsg' will be cleaned up next time
		 * headers are read.
		 */
		http_free_respinfo(lresp);
		return (-1);
	}

	/*
	 * See if there is a 'content-type: multipart/mixed' line in the
	 * headers.  If so, get the boundary string.
	 */
	ptr = http_get_header_value(handle, "Content-Type");
	if (ptr != NULL) {
		char *ptr2;

		ptr2 = ptr;
		while (isspace(*ptr2))
			ptr2 ++;
		if (startswith((const char **)&ptr2, "Multipart/Mixed;")) {
			while (isspace(*ptr2))
				ptr2 ++;
			if (startswith((const char **)&ptr2, "Boundary=")) {
				if (ptr2[0] == '"') {
					ptr2 ++;
					if (ptr2[strlen(ptr2) - 1] == '"')
						ptr2[strlen(ptr2) - 1] = '\0';
				}
				c_id->boundary = strdup(ptr2);
				if (c_id->boundary == NULL) {
					free(ptr);
					http_free_respinfo(lresp);
					SET_ERR(c_id, ERRSRC_LIBHTTP,
					    EHTTP_NOMEM);
					return (-1);
				}
				c_id->boundary_len = strlen(c_id->boundary);
				c_id->is_multipart = B_TRUE;
				c_id->is_firstpart = B_TRUE;
			}
		}
		free(ptr);
	}

	/*
	 * Initialize the counters used to process message bodies.
	 */
	if (init_bread(c_id) != 0) {
		/*
		 * Error stack was already set at a lower level.
		 */
		http_free_respinfo(lresp);
		return (-1);
	}

	/* Copy fields to the caller's structure */
	if (resp != NULL) {
		lresp->code = c_id->resp.code;
		lresp->nresphdrs = c_id->resp.nresphdrs;
		lresp->statusmsg = strdup(c_id->resp.statusmsg);
		if (lresp->statusmsg == NULL) {
			http_free_respinfo(lresp);
			SET_ERR(c_id, ERRSRC_LIBHTTP, EHTTP_NOMEM);
			return (-1);
		}
		*resp = lresp;
	}

	return (0);
}

/*
 * http_process_part_headers - Read in part boundary and header lines for the
 *                             next part of a multipart message.
 *
 *        ret = http_process_part_headers(handle, resp);
 *
 * Arguments:
 *   handle	- Handle associated with the connection where the request
 *		  was made.
 *   resp	- Return address for summary information about the
 *		  header block.
 *
 * Returns:
 *   = 1	- The end part was found.
 *   = 0	- Success, with header info returned in 'resp'
 *   = -1	- An error occurred.  Specifics of the error can
 *		  be gotten using http_get_lasterr().
 *
 * This function reads any \r\n sequences (empty lines) and expects to get
 * a boundary line as the next non-empty line.  It then reads header lines
 * (content-length, etc) until it gets another empty lines, which ends the
 * header section.
 *
 * Note that if resp is non-NULL, then upon a successful return, information
 * about the the number of header lines is returned in the http_respinfo_t
 * structure. The caller is responsible for freeing the resources allocated
 * to this structure via http_free_respinfo().
 *
 * Headers values can be returned using http_get_response_header() and
 * http_get_header_value().
 *
 * Calling this function replaces the header information which is
 * queried using http_get_response_header() and http_get_header_value().
 * Once this function is called, information returned by the previous call
 * to http_process_headers() or http_process_part_headers() is gone.
 */
int
http_process_part_headers(http_handle_t handle, http_respinfo_t **resp)
{
	http_conn_t *c_id = handle;
	char	line[MAXHOSTNAMELEN];
	int	count;
	int 	limit;
	int	i;

	ERR_clear_error();
	if (!http_check_conn(c_id))
		return (-1);

	if (c_id->is_multipart == 0) {
		SET_ERR(c_id, ERRSRC_LIBHTTP, EHTTP_NOTMULTI);
		return (-1);
	}

	/*
	 * Figure out how many empty lines to allow.  Before the first
	 * boundary of the transmission, there can be any number of
	 * empty lines (from 0 up).  Limit these to some reasonable
	 * failsafe.
	 *
	 * For the 2nd and later boundaries, there is supposed to be
	 * one crlf pair.  However, many implementations don't require
	 * it.  So don't require it.
	 */
	if (c_id->is_firstpart) {
		limit = FAILSAFE;
		c_id->is_firstpart = B_FALSE;
	} else
		limit = 1;

	/* Look for the boundary line. */
	count = 0;
	while ((i = getaline(c_id, line, sizeof (line), B_TRUE)) == 0 &&
	    count < FAILSAFE)
		count ++;
	if (i < 0 || count > limit) {
		/*
		 * If I/O error, cause was already put into
		 * error stack.  This is an additional error.
		 */
		SET_ERR(c_id, ERRSRC_LIBHTTP, EHTTP_NOBOUNDARY);
		return (-1);
	}

	free_response(c_id, B_FALSE);

	if (verbosemode)
		libbootlog(BOOTLOG_VERBOSE,
		    "http_process_part_headers: %s", line);

	/* Look for boundary line - '--<boundary text> */
	if (line[0] != '-' || line[1] != '-' ||
	    strncmp(&line[2], c_id->boundary, c_id->boundary_len) != 0) {
		/* No boundary line.... */
		SET_ERR(c_id, ERRSRC_LIBHTTP, EHTTP_NOBOUNDARY);
		return (-1);
	}

	/* Is this the end-of-parts boundary (ends with a trailing '--') */
	if (strcmp(&line[c_id->boundary_len + 2], "--") == 0) {
		return (1);
	}

	free_response(c_id, B_FALSE);
	if (read_headerlines(c_id, B_TRUE) < 0) {
		/* Error stack was already set at a lower level. */
		return (-1);
	}

	/* Copy fields to the caller's structure */
	if (resp != NULL) {
		if ((*resp = malloc(sizeof (http_respinfo_t))) == NULL) {
			SET_ERR(c_id, ERRSRC_LIBHTTP, EHTTP_NOMEM);
			return (-1);
		}
		bzero(*resp, sizeof (http_respinfo_t));
		(*resp)->code = ' ';
		(*resp)->nresphdrs = c_id->resp.nresphdrs;
	}

	return (0);
}

/*
 * http_get_response_header - Get a line from the response header
 *
 *     ret = http_get_response_header(handle, whichline);
 *
 * Arguments:
 *	handle	- Handle associated with the desired connection
 *	whichline - Which line of the header to return.  This must be between
 *		  zero and resp.nresphdrs which was returned by the call to
 *		  http_process_headers().
 *
 * Returns:
 *	ptr	- Points to a copy of the header line.
 *	NULL	- An error occurred.  Check http_get_lasterr().
 */
char *
http_get_response_header(http_handle_t handle, uint_t which)
{
	http_conn_t *c_id = handle;
	char *res;

	if (!http_check_conn(c_id))
		return (NULL);

	if (which >= c_id->resp.nresphdrs) {
		SET_ERR(c_id, ERRSRC_LIBHTTP, EHTTP_OORANGE);
		return (NULL);
	}

	res = strdup(c_id->resphdr[which]);
	if (res == NULL) {
		SET_ERR(c_id, ERRSRC_LIBHTTP, EHTTP_NOMEM);
		return (NULL);
	}
	return (res);
}

/*
 * http_get_header_value - Get the value of a header line.
 *
 *     ret = http_get_header_value(handle, what);
 *
 * Arguments:
 *	handle	- Handle associated with the desired connection
 *	what	- The field name to look up.
 *
 * Returns:
 *	ptr	- Points to a copy of the header value.
 *	NULL	- An error occurred.  Check http_get_lasterr().
 */
char *
http_get_header_value(http_handle_t handle, const char *field_name)
{
	http_conn_t *c_id = handle;
	char	*ptr;
	char	*res;
	int	i;
	int	n;

	if (!http_check_conn(c_id))
		return (NULL);

	if (field_name == NULL || field_name[0] == '\0') {
		SET_ERR(c_id, ERRSRC_LIBHTTP, EHTTP_BADARG);
		return (NULL);
	}

	for (i = 0; i < c_id->resp.nresphdrs; i++) {
		ptr = c_id->resphdr[i];
		n = strlen(field_name);
		if (strncasecmp(field_name, ptr, n) == 0 && ptr[n] == ':') {
			ptr += n + 1;

			while (isspace(*ptr))
				ptr++;

			res = strdup(ptr);
			if (res == NULL) {
				SET_ERR(c_id, ERRSRC_LIBHTTP, EHTTP_NOMEM);
				return (NULL);
			}
			return (res);
		}
	}
	SET_ERR(c_id, ERRSRC_LIBHTTP, EHTTP_NOMATCH);
	return (NULL);
}

/*
 * http_read_body - Read the HTTP response body.
 *
 *     ret = http_read_body(handle, recv_buf_ptr, recv_buf_size);
 *
 * Arguments:
 *	handle	- Handle associated with the relevant connection
 *	recv_buf_ptr - Points to buffer to receive buffer
 *	recv_buf_size - Length in bytes of buffer.
 *
 * Returns:
 *	n	- Number of bytes read..
 *	< 0	- An error occurred.  This is (the number of bytes gotten + 1),
 *		  negated.  In other words, if 'n' bytes were read and then an
 *		  error occurred, this will return (-(n+1)).  So zero bytes
 *		  were read and then an error occurs, this will return -1.  If
 *		  1 byte was read, it will return -2, etc.  Specifics of the
 *		  error can be gotten using http_get_lasterr().
 *
 * Note that the errors will be set in the http_conn_t struct before the
 * function which detected the error returns.
 */
int
http_read_body(http_handle_t handle, char *recv_buf_ptr, size_t recv_buf_size)
{
	http_conn_t *c_id = handle;

	ERR_clear_error();
	if (!http_check_conn(c_id))
		return (-1);

	if (recv_buf_ptr == NULL || recv_buf_size == 0) {
		SET_ERR(c_id, ERRSRC_LIBHTTP, EHTTP_BADARG);
		return (-1);
	}

	return (getbytes(c_id, recv_buf_ptr, recv_buf_size));
}

/*
 * http_srv_disconnect - Get rid of the connection to the server without
 *			freeing the http_conn_t structure.
 *
 *     ret = http_srv_disconnect(handle);
 *
 * Arguments:
 *	handle	- Handle associated with the connection
 *
 * Returns:
 *	0	- Success
 *	-1	- An error occurred.  Specifics of the error can
 *		  be gotten using http_get_lasterr().
 */
int
http_srv_disconnect(http_handle_t handle)
{
	http_conn_t *c_id = handle;
	int err_ret;

	ERR_clear_error();
	if (!http_check_conn(c_id))
		return (-1);

	err_ret = free_ctx_ssl(c_id);
	bzero(&c_id->inbuf, sizeof (c_id->inbuf));
	free_response(c_id, B_TRUE);

	return (err_ret);
}

/*
 * http_srv_close - Close the connection and clean up the http_conn_t
 *		structure.
 *
 *     http_srv_close(handle);
 *
 * Arguments:
 *	handle	- Handle associated with the desired connection
 *
 * Returns:
 *	0	- Success
 *	-1	- An error occurred.  Specifics of the error can
 *		  be gotten using http_get_lasterr().
 */
int
http_srv_close(http_handle_t handle)
{
	http_conn_t *c_id = handle;
	int err_ret = 0;

	if (!http_check_conn(c_id))
		return (-1);

	if (c_id->ctx != NULL || c_id->ssl != NULL || c_id->fd != -1)
		err_ret = http_srv_disconnect(handle);

	free(c_id->basic_auth_userid);
	free(c_id->basic_auth_password);
	free(c_id->resp.statusmsg);
	free(c_id->client_cert_file);
	free(c_id->private_key_file);
	free(c_id->random_file);
	free(c_id->file_password);
	c_id->signature = 0;

	free(c_id);
	return (err_ret);
}

/*
 * http_get_conn_info - Return current information about the connection
 *
 *     err = http_get_conn_info(handle);
 *
 * Arguments:
 *	handle	- Handle associated with the connection in question
 *
 * Returns:
 *	non_NULL- Points to structure
 *	NULL	- An error exists.  Check http_get_lasterr().
 */
http_conninfo_t *
http_get_conn_info(http_handle_t handle)
{
	http_conn_t *c_id = handle;
	http_conninfo_t *info;

	if (!http_check_conn(c_id))
		return (NULL);

	info = malloc(sizeof (*info));
	if (info == NULL) {
		SET_ERR(c_id, ERRSRC_LIBHTTP, EHTTP_NOMEM);
		return (NULL);
	}

	bzero(info, sizeof (*info));

	info->uri = c_id->uri;
	info->proxy = c_id->proxy;
	info->keepalive = c_id->keepalive;
	info->read_timeout = c_id->read_timeout;

	return (info);
}

/*
 * http_get_lasterr - Return the next error on the last operation
 *
 *     err = http_get_lasterr(handle, errsrc);
 *
 * Arguments:
 *	handle	- Handle associated with the connection in question
 *		  If no valid handle exists yet, this can be NULL.
 *		  However, it must be checked with the very next call.
 *	errsrc	- Returns the Sources of errors (ERRSRC_* values).
 *
 * Returns:
 *	0	- No error exists
 *	<> 0	- The error.
 */
ulong_t
http_get_lasterr(http_handle_t handle, uint_t *errsrc)
{
	http_conn_t *c_id = handle;
	ulong_t src;
	ulong_t err;

	if (c_id == NULL || c_id->signature != HTTP_CONN_INFO) {
		if (errsrc)
			*errsrc = ERRSRC_LIBHTTP;
		err = early_err;
		early_err = 0;
		return (err);
	}

	GET_ERR(c_id, src, err);
	if (src == 0 && err == 0) {
		if (errsrc)
			*errsrc = ERRSRC_LIBHTTP;
		err = early_err;
		early_err = 0;
		return (err);
	}
	if (errsrc)
		*errsrc = src;
	return (err);
}

/*
 * http_decode_err - Decode a libssl error
 *
 *     err = http_decode_err(err, errlib, errfunc, errcode);
 *
 * Arguments:
 *	err	- libssl/libcrypto error returned.
 *	errlib	- returns libssl/libcrypto sublibrary that caused the error
 *	errfunc	- returns function in that library
 *	errcode - returns error code
 *
 * Returns:
 *	None other than the above.
 */
void
http_decode_err(ulong_t err, int *errlib, int *errfunc, int *errcode)
{
	if (errlib)
		*errlib = ERR_GET_LIB(err);
	if (errfunc)
		*errfunc = ERR_GET_FUNC(err);
	if (errcode)
		*errcode = ERR_GET_REASON(err);
}

/* ---------------------- private functions ----------------------- */

/*
 * http_req - Issue http request (either HEAD or GET)
 *
 *     ret = http_req(handle, abs_path, reqtype, curpos, len);
 *
 * Arguments:
 *	handle	- Handle associated with the desired connection
 *	abs_path- File name portion of the URI, beginning with a /.  Query,
 *		  segment, etc are allowed.
 *	type	- HTTP_REQ_TYPE_HEAD or HTTP_REQ_TYPE_GET
 *
 *	In the case of GET requests,
 *	  curpos- -1  - Range not used
 *		  >=0 - Beginning of range
 *	  len	- 0   - Range ends at the end of the file
 *		  >0  - Length of range.
 *
 * Returns:
 *	0	- Success
 *	-1	- An error occurred.  Check http_get_lasterr().
 */
static int
http_req(http_handle_t handle, const char *abs_path, http_req_t type,
    offset_t curpos, offset_t len)
{
	http_conn_t *c_id = handle;
	char	*request;
	char	*reqtypename;
	char	*newreq;
	int	requestlen;
	int	retval;
	int	j;

	ERR_clear_error();
	if (!http_check_conn(c_id))
		return (-1);

	if (abs_path == NULL || abs_path[0] == '\0') {
		SET_ERR(c_id, ERRSRC_LIBHTTP, EHTTP_BADARG);
		return (-1);
	}

	/* Determine the name for the request type */
	switch (type) {
	case HTTP_REQ_TYPE_GET:
		reqtypename = "GET";
		if (curpos < 0 && curpos != -1) {
			SET_ERR(c_id, ERRSRC_LIBHTTP, EHTTP_BADARG);
			return (-1);
		}
		break;

	case HTTP_REQ_TYPE_HEAD:
		reqtypename = "HEAD";
		break;

	default:
		SET_ERR(c_id, ERRSRC_LIBHTTP, EHTTP_BADARG);
		return (-1);
	}

	/* Do rudimentary checks on the absolute path */
	if (abs_path == NULL || *abs_path != '/') {
		SET_ERR(c_id, ERRSRC_LIBHTTP, EHTTP_BADARG);
		libbootlog(BOOTLOG_CRIT, "http_req: invalid file path");
		if (abs_path != NULL)
			libbootlog(BOOTLOG_CRIT, " %s", abs_path);
		return (-1);
	}
	(void) strlcpy(CONN_ABSPATH, abs_path, MAXHOSTNAMELEN);

	/*
	 * Size the request.
	 *
	 * With proxy:
	 *   reqtypename + " http://" + host + ":" + port + path +
	 *						" HTTP/1.1\r\n" +
	 * Without proxy:
	 *   reqtypename + " " + path + " HTTP/1.1\r\n" +
	 */
	requestlen = strlen(reqtypename) + 8 + strlen(CONN_HOSTNAME) + 1 +
	    count_digits(CONN_PORT) + strlen(CONN_ABSPATH) + 11;

	/*
	 * Plus the rest:
	 *   "Host: " + targethost + ":" + count_digits(port) + "\r\n" +
	 *   "Connection: Keep-Alive\r\n" plus trailing "\r\n\0"
	 */
	requestlen += 6 + strlen(CONN_HOSTNAME) + 1 +
	    count_digits(CONN_PORT) + 2 + 24 + 3;
	if ((request = malloc(requestlen)) == NULL) {
		SET_ERR(c_id, ERRSRC_LIBHTTP, EHTTP_NOMEM);
		return (-1);
	}

	/* The request line */
	if (c_id->proxied && c_id->ssl == NULL) {
		j = snprintf(request, requestlen,
		    "%s http://%s:%d%s HTTP/1.1\r\n",
		    reqtypename, CONN_HOSTNAME, CONN_PORT,
		    CONN_ABSPATH);
	} else {
		j = snprintf(request, requestlen, "%s %s HTTP/1.1\r\n",
		    reqtypename, CONN_ABSPATH);
	}

	/* Ancillary headers */
	j += snprintf(&request[j], requestlen - j, "Host: %s:%d\r\n",
	    CONN_HOSTNAME, CONN_PORT);
	if (!c_id->keepalive)
		j += snprintf(&request[j], requestlen - j,
		    "Connection: close\r\n");
	else
		j += snprintf(&request[j], requestlen - j,
		    "Connection: Keep-Alive\r\n");
	/*
	 * We only send the range header on GET requests
	 *
	 * "Range: bytes=" + from + "-" + end + "\r\n" or
	 * "Range: bytes=" + from + "-"  "\r\n"
	 */
	if (type == HTTP_REQ_TYPE_GET && curpos >= 0) {
		offset_t endpos;

		requestlen += 13 + count_digits(curpos) + 1 + 2;
		if (len > 0) {
			endpos = curpos + len - 1;
			requestlen += count_digits(endpos);
		}

		if ((newreq = realloc(request, requestlen)) == NULL) {
			free(request);
			SET_ERR(c_id, ERRSRC_LIBHTTP, EHTTP_NOMEM);
			return (-1);
		}
		request = newreq;

		j += sprintf(&request[j], "Range: bytes=%lld-", curpos);
		if (len > 0)
			j += sprintf(&request[j], "%lld", endpos);
		j += sprintf(&request[j], "\r\n");
	}

	/*
	 * Authorization is added only if provided (RFC 2617, Section 2)
	 *
	 * "Authorization: Basic " + authencstr + "\r\n"
	 */
	if (c_id->basic_auth_userid && c_id->basic_auth_password) {
		char *authstr;
		char *authencstr;
		int authlen;

		/*
		 * Allow for concat(basic_auth_userid ":" basic_auth_password)
		 */
		authlen = strlen(c_id->basic_auth_userid) + 2 +
		    strlen(c_id->basic_auth_password);
		if ((authstr = malloc(authlen + 1)) == NULL) {
			free(request);
			SET_ERR(c_id, ERRSRC_LIBHTTP, EHTTP_NOMEM);
			return (-1);
		}
		(void) snprintf(authstr, authlen + 1, "%s:%s",
		    c_id->basic_auth_userid, c_id->basic_auth_password);

		/* 3 bytes encoded as 4 (round up) with null termination */
		if ((authencstr = malloc((authlen + 2) / 3 * 4 + 1)) == NULL) {
			free(authstr);
			free(request);
			SET_ERR(c_id, ERRSRC_LIBHTTP, EHTTP_NOMEM);
			return (-1);
		}

		(void) EVP_EncodeBlock((unsigned char *)authencstr,
		    (unsigned char *)authstr, authlen);

		/*
		 * Finally do concat(Authorization: Basic " authencstr "\r\n")
		 */
		requestlen += 21 + strlen(authencstr) + 2;
		if ((newreq = realloc(request, requestlen)) == NULL) {
			free(authencstr);
			free(authstr);
			free(request);
			SET_ERR(c_id, ERRSRC_LIBHTTP, EHTTP_NOMEM);
			return (-1);
		}
		request = newreq;

		j += snprintf(&request[j], requestlen - j,
		    "Authorization: Basic %s\r\n", authencstr);

		free(authencstr);
		free(authstr);
	}

	j += sprintf(&request[j], "\r\n");

	if (verbosemode)
		libbootlog(BOOTLOG_VERBOSE, "%s", request);

	/* send the HTTP request */
	retval = http_srv_send(c_id, request, j);

	free(request);
	if (retval != j) {
		/* Assume error in was set by send request. */
		return (-1);
	}

	return (0);
}

/*
 * password_cb - Callback to get private key password and return it
 *               to SSL.  (Used for PEM certificates only.)
 *
 * 	len = passwd_cb(buf, buflen, rwflag, userdata);
 *
 *  Arguments:
 *     buf	- Buffer for the password
 *     buflen	- Length of 'buf'
 *     rwflag	- password will be used for reading/decryption (== 0)
 *		  or writing/encryption (== 1).
 *     userdata	- Points to connection-specific information.
 *
 *  Returns:
 *     > 0	- Length of password that was put into 'buf'.
 *     0 	- No password was returned (usually error occurred)
 *
 * NOTE:  The password code is not thread safe
 */
/* ARGSUSED */
static int
password_cb(char *buf, int buflen, int rwflag, void *userdata)
{
	http_conn_t *c_id = userdata;

	if (c_id == NULL || c_id->signature != HTTP_CONN_INFO)
		return (0);

	if (c_id->file_password == NULL ||
	    buflen < strlen(c_id->file_password) + 1)
		return (0);

	return (strlcpy(buf, c_id->file_password, buflen));
}

/*
 * initialize_ctx - Initialize the context for a connection.
 *
 *       ctx = initialize_ctx(c_id);
 *
 *  Arguments:
 *     None.
 *
 *  Returns:
 *     non-NULL	- Points to ctx structure.
 *     NULL	- An error occurred.  Any cleanup is done and error
 *                information is in the error stack.
 */
static SSL_CTX *
initialize_ctx(http_conn_t *c_id)
{
#if OPENSSL_VERSION_NUMBER < 0x10000000L
	SSL_METHOD	*meth;
#else
	const SSL_METHOD	*meth;
#endif
	SSL_CTX		*ctx;

	ERR_clear_error();

	/* Global system initialization */
	if (ssl_init == 0) {
		sunw_crypto_init();
		SSL_load_error_strings();
		ssl_init = 1;
	}

	/* Create our context */
	meth = SSLv3_client_method();
	if ((ctx = SSL_CTX_new(meth)) == NULL) {
		ulong_t err;
		while ((err = ERR_get_error()) != 0)
			SET_ERR(c_id, ERRSRC_LIBSSL, err);
			libbootlog(BOOTLOG_CRIT,
			    "initialize_ctx: SSL_CTX_new returned NULL");
		return (NULL);
	}

	/*
	 * Ensure that any renegotiations for blocking connections will
	 * be done automatically.  (The alternative is to return partial
	 * reads to the caller and let it oversee the renegotiations.)
	 */
	if (SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY) == 0) {
		ulong_t err;
		while ((err = ERR_get_error()) != 0)
			SET_ERR(c_id, ERRSRC_LIBSSL, err);
			libbootlog(BOOTLOG_CRIT,
			    "initialize_ctx: SSL_CTX_set_mode returned 0");
		(void) SSL_CTX_free(ctx);
		return (NULL);
	}

	/* set cipher list if provided */
	if (cipher_list != NULL) {
		if (!SSL_CTX_set_cipher_list(ctx, cipher_list)) {
			ulong_t err;
			while ((err = ERR_get_error()) != 0)
				SET_ERR(c_id, ERRSRC_LIBSSL, err);
				libbootlog(BOOTLOG_CRIT,
				    "initialize_ctx: Error in cipher list");
			SSL_CTX_free(ctx);
			return (NULL);
		}
	}

	/*
	 * We attempt to use the client_certificate_file for the private
	 * key input scheme *only* in the absence of private_key_file. In
	 * this instance the scheme will be the same as that used for the
	 * certificate input.
	 */

	/* Load our certificates */
	if (c_id->client_cert_file != NULL) {
		if (p12_format) {
			/* Load pkcs12-formated files */
			if (sunw_p12_use_certfile(ctx, c_id->client_cert_file,
			    c_id->file_password)
			    <= 0) {
				ulong_t err;
				while ((err = ERR_get_error()) != 0)
					SET_ERR(c_id, ERRSRC_LIBSSL, err);
					libbootlog(BOOTLOG_CRIT,
					    "initialize_ctx: Couldn't read "
					    "PKCS12 certificate file");
				SSL_CTX_free(ctx);
				return (NULL);
			}
		} else {
			/* Load PEM-formated files */
			if (SSL_CTX_use_certificate_file(ctx,
			    c_id->client_cert_file, SSL_FILETYPE_PEM) <= 0) {
				ulong_t err;
				while ((err = ERR_get_error()) != 0)
					SET_ERR(c_id, ERRSRC_LIBSSL, err);
					libbootlog(BOOTLOG_CRIT,
					    "initialize_ctx: Couldn't read "
					    "PEM certificate file");
				SSL_CTX_free(ctx);
				return (NULL);
			}
		}
		if (c_id->private_key_file == NULL)
			c_id->private_key_file = c_id->client_cert_file;
	}

	/* Load our keys */
	if (p12_format) {
		/* Load pkcs12-formated files */
		if (c_id->private_key_file != NULL) {
			if (sunw_p12_use_keyfile(ctx, c_id->private_key_file,
			    c_id->file_password)
			    <= 0) {
				ulong_t err;
				while ((err = ERR_get_error()) != 0)
					SET_ERR(c_id, ERRSRC_LIBSSL, err);
					libbootlog(BOOTLOG_CRIT,
					    "initialize_ctx: Couldn't read "
					    "PKCS12 key file");
				SSL_CTX_free(ctx);
				return (NULL);
			}
		}
	} else {
		/* Load PEM-formated files */
		SSL_CTX_set_default_passwd_cb(ctx, password_cb);
		SSL_CTX_set_default_passwd_cb_userdata(ctx, c_id);
		if (c_id->private_key_file != NULL) {
			if (SSL_CTX_use_PrivateKey_file(ctx,
			    c_id->private_key_file, SSL_FILETYPE_PEM) <= 0) {
				ulong_t err;
				while ((err = ERR_get_error()) != 0)
					SET_ERR(c_id, ERRSRC_LIBSSL, err);
					libbootlog(BOOTLOG_CRIT,
					    "initialize_ctx: Couldn't read "
					    "PEM key file");
				SSL_CTX_free(ctx);
				return (NULL);
			}
		}
	}

	/* Load the CAs we trust */
	if (ca_verify_file != NULL) {
		if (p12_format) {
			if (sunw_p12_use_trustfile(ctx, ca_verify_file,
			    c_id->file_password)
			    <= 0) {
				ulong_t err;
				while ((err = ERR_get_error()) != 0)
					SET_ERR(c_id, ERRSRC_LIBSSL, err);
					libbootlog(BOOTLOG_CRIT,
					    "initialize_ctx: Couldn't read "
					    "PKCS12 CA list file");
				SSL_CTX_free(ctx);
				return (NULL);
			}
		} else {
			if (SSL_CTX_load_verify_locations(ctx, ca_verify_file,
			    NULL) == 0) {
				ulong_t err;
				while ((err = ERR_get_error()) != 0)
					SET_ERR(c_id, ERRSRC_LIBSSL, err);
					libbootlog(BOOTLOG_CRIT,
					    "initialize_ctx: Couldn't read PEM"
					    " CA list file");
				SSL_CTX_free(ctx);
				return (NULL);
			}
		}
	}

	SSL_CTX_set_verify_depth(ctx, verify_depth);

	/* Load randomness */
	if (c_id->random_file != NULL &&
	    RAND_load_file(c_id->random_file, 1024 * 1024) <= 0) {
		ulong_t err;
		while ((err = ERR_get_error()) != 0)
			SET_ERR(c_id, ERRSRC_LIBSSL, err);
			libbootlog(BOOTLOG_CRIT,
			    "initialize_ctx: Couldn't load random file");
		SSL_CTX_free(ctx);
		return (NULL);
	}
	if (RAND_status() <= 0) {
		ulong_t err;
		while ((err = ERR_get_error()) != 0)
			SET_ERR(c_id, ERRSRC_LIBSSL, err);
			libbootlog(BOOTLOG_CRIT,
			    "initialize_ctx: PRNG not seeded");
		SSL_CTX_free(ctx);
		return (NULL);
	}

	return (ctx);
}

/*
 * tcp_connect - Set up a TCP connection.
 *
 *         sock = tcp_connect(c_id, hostname, port);
 *
 * Arguments:
 *      c_id	 - Structure associated with the desired connection
 *	hostname - the host to connect to
 *	port	 - the port to connect to
 *
 * Returns:
 *      >= 0	- Socket number.
 *      -1	- Error occurred.  Error information is set in the
 *                error stack.  Any cleanup is done.
 *
 * This function established a connection to the target host.  When
 * it returns, the connection is ready for a HEAD or GET request.
 */
static int
tcp_connect(http_conn_t *c_id, const char *hostname, uint16_t port)
{
	struct hostent	*hp;
	struct sockaddr_in addr;
	int	sock;
	int	status;

	if ((hp = gethostbyname(hostname)) == NULL) {
		SET_ERR(c_id, ERRSRC_RESOLVE, h_errno);
		return (-1);
	}

	bzero(&addr, sizeof (addr));
	/* LINTED */
	addr.sin_addr = *(struct in_addr *)hp->h_addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

	if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		SET_ERR(c_id, ERRSRC_SYSTEM, errno);
		return (-1);
	}

	status = connect(sock, (struct sockaddr *)&addr, sizeof (addr));
	if (status < 0) {
		SET_ERR(c_id, ERRSRC_SYSTEM, errno);
		(void) socket_close(sock);
		return (-1);
	}

	c_id->host_addr = addr;	/* save for future sendto calls */
	c_id->fd = sock;

	return (sock);
}

/*
 * readline - Get a line from the socket.  Discard the end-of-line
 *            (CR or CR/LF or LF).
 *
 *         ret = readline(c_id, sock, buf, len);
 *
 * Arguments:
 *      c_id	- Structure associated with the desired connection
 *      sock	- Socket to read
 *      buf   	- Buffer for the line
 *      len	- Length of the buffer
 *
 * Returns:
 *      0	- Success.  'buf' contains the line.
 *      -1	- Error occurred.  Error information is set in the
 *                error stack.
 */
static int
readline(http_conn_t *c_id, int sock, char *buf, int len)
{
	int	n, r;
	char	*ptr = buf;

	for (n = 0; n < len; n++) {
		r = socket_read(sock, ptr, 1, c_id->read_timeout);

		if (r < 0) {
			SET_ERR(c_id, ERRSRC_SYSTEM, errno);
			return (-1);
		} else if (r == 0) {
			libbootlog(BOOTLOG_WARNING, "Readline: no data");
			return (0);
		}

		if (*ptr == '\n') {
			*ptr = '\0';

			/* Strip off the CR if it's there */
			if (buf[n-1] == '\r') {
				buf[n-1] = '\0';
				n--;
			}

			return (n);
		}

		ptr++;
	}

	libbootlog(BOOTLOG_WARNING, "readline: Buffer too short\n");
	return (0);
}

/*
 * proxy_connect - Set up a proxied TCP connection to the target host.
 *
 *         sock = proxy_connect(c_id);
 *
 * Arguments:
 *      c_id  -	Structure associated with the desired connection
 *
 * Returns:
 *      >= 0	- Socket number.
 *      -1	- Error occurred.  Error information is set in the
 *                error stack.  Any cleanup is done.
 *
 * This function established a connection to the proxy and then sends
 * the request to connect to the target host.  It reads the response
 * (the status line and any headers).  When it returns, the connection
 * is ready for a HEAD or GET request.
 */
static int
proxy_connect(http_conn_t *c_id)
{
	struct sockaddr_in addr;
	int	sock;
	char	buf[1024];
	char	*ptr;
	int	i;

	if ((sock = tcp_connect(c_id, CONN_PROXY_HOSTNAME,
	    CONN_PROXY_PORT)) < 0) {
		return (-1);
	}

	if (!CONN_HTTPS) {
		return (sock);
	}

	/* Now that we're connected, do the proxy request */
	(void) snprintf(buf, sizeof (buf),
	    "CONNECT %s:%d HTTP/1.0\r\n\r\n", CONN_HOSTNAME, CONN_PORT);

	/* socket_write sets the errors */
	if (socket_write(sock, buf, strlen(buf), &addr) <= 0) {
		SET_ERR(c_id, ERRSRC_SYSTEM, errno);
		(void) socket_close(sock);
		return (-1);
	}

	/* And read the response */
	i = readline(c_id, sock, buf, sizeof (buf));
	if (i <= 0) {
		if (i == 0)
			SET_ERR(c_id, ERRSRC_LIBHTTP, EHTTP_NORESP);
			libbootlog(BOOTLOG_CRIT,
			    "proxy_connect: Empty response from proxy");
		(void) socket_close(sock);
		return (-1);
	}

	ptr = buf;
	if (strncmp(ptr, "HTTP", 4) != 0) {
		SET_ERR(c_id, ERRSRC_LIBHTTP, EHTTP_NOT_1_1);
		libbootlog(BOOTLOG_CRIT,
		    "proxy_connect: Unrecognized protocol");
		(void) socket_close(sock);
		return (-1);
	}

	/* skip to the code */
	ptr += 4;
	while (*ptr != ' ' && *ptr != '\0')
		ptr++;
	while (*ptr == ' ' && *ptr != '\0')
		ptr++;

	/* make sure it's three digits */
	if (strncmp(ptr, "200", 3) != 0) {
		SET_ERR(c_id, ERRSRC_LIBHTTP, EHTTP_BADRESP);
		libbootlog(BOOTLOG_CRIT,
		    "proxy_connect: Received error from proxy server");
		(void) socket_close(sock);
		return (-1);
	}
	ptr += 3;
	if (isdigit(*ptr)) {
		SET_ERR(c_id, ERRSRC_LIBHTTP, EHTTP_BADRESP);
		(void) socket_close(sock);
		return (-1);
	}

	/* Look for the blank line that signals end of proxy header */
	while ((i = readline(c_id, sock, buf, sizeof (buf))) > 0)
		;

	if (i < 0) {
		(void) socket_close(sock);
		return (-1);
	}

	return (sock);
}

/*
 * check_cert_chain - Check if we have a valid certificate chain.
 *
 *      ret = check_cert_chain(c_id, host);
 *
 * Arguments:
 *    c_id	- Connection info.
 *    host	- Name to compare with the common name in the certificate.
 *
 * Returns:
 *    0		- Certificate chain and common name are both OK.
 *    -1	- Certificate chain and/or common name is not valid.
 */
static int
check_cert_chain(http_conn_t *c_id, char *host)
{
	X509	*peer;
	char	peer_CN[256];
	long	verify_err;

	if ((verify_err = SSL_get_verify_result(c_id->ssl)) != X509_V_OK) {
		SET_ERR(c_id, ERRSRC_VERIFERR, verify_err);
		libbootlog(BOOTLOG_CRIT,
		    "check_cert_chain: Certificate doesn't verify");
		return (-1);
	}

	/*
	 * Check the cert chain. The chain length
	 * is automatically checked by OpenSSL when we
	 * set the verify depth in the ctx
	 *
	 * All we need to do here is check that the CN
	 * matches
	 */

	/* Check the common name */
	if ((peer = SSL_get_peer_certificate(c_id->ssl)) == NULL) {
		SET_ERR(c_id, ERRSRC_LIBHTTP, EHTTP_NOCERT);
		libbootlog(BOOTLOG_CRIT,
		    "check_cert_chain: Peer did not present a certificate");
		return (-1);
	}
	(void) X509_NAME_get_text_by_NID(X509_get_subject_name(peer),
	    NID_commonName, peer_CN, 256);

	if (verbosemode)
		libbootlog(BOOTLOG_VERBOSE,
		    "server cert's peer_CN is %s, host is %s", peer_CN, host);

	if (strcasecmp(peer_CN, host)) {
		SET_ERR(c_id, ERRSRC_LIBHTTP, EHTTP_NOMATCH);
		libbootlog(BOOTLOG_CRIT,
		    "check_cert_chain: Common name doesn't match host name");
		libbootlog(BOOTLOG_CRIT,
		    "peer_CN = %s, host = %s", peer_CN, host);
		return (-1);
	}

	return (0);
}

/*
 * print_ciphers - Print the list of ciphers for debugging.
 *
 *       print_ciphers(ssl);
 *
 * Arguments:
 *     ssl	- SSL connection.
 *
 * Returns:
 *     none
 */
static void
print_ciphers(SSL *ssl)
{
	SSL_CIPHER	*c;
	STACK_OF(SSL_CIPHER)	*sk;
	int	i;
	const char	*name;

	if (ssl == NULL)
		return;

	sk = SSL_get_ciphers(ssl);
	if (sk == NULL)
		return;

	for (i = 0; i < sk_SSL_CIPHER_num(sk); i++) {
		/* LINTED */
		c = sk_SSL_CIPHER_value(sk, i);
		libbootlog(BOOTLOG_VERBOSE, "%08lx %s", c->id, c->name);
	}
	name = SSL_get_cipher_name(ssl);
	if (name == NULL)
		name = "";
	libbootlog(BOOTLOG_VERBOSE, "Current cipher = %s", name);
}

/*
 * read_headerlines - Get the header lines from the server.  This reads
 *              lines until it gets a empty line indicating end of headers.
 *
 *       ret = read_headerlines(c_id);
 *
 * Arguments:
 *     c_id	- Info about the connection being read.
 *     bread	- TRUE if the headerlines are part of the message body.
 *
 * Returns:
 *     0	- Header lines were read.
 *     -1	- Error occurred.  The errors information is already in
 *                the error stack.
 *
 *  Read the lines.  If the current line begins with a space or tab, it is
 *  a continuation.  Take the new line and append it to the end of the
 *  previous line rather than making an entry for another line in
 *  c_id->resphdr.
 *
 *  Note that I/O errors are put into the error stack by http_srv_recv(),
 *  which is called by getaline().
 */
static int
read_headerlines(http_conn_t *c_id, boolean_t bread)
{
	char	line[MAXHOSTNAMELEN];
	char	**new_buf;
	char	*ptr;
	int	next;
	int	cur;
	int	n;

	/* process headers, stop when we get to an empty line */
	cur = 0;
	next = 0;
	while ((n = getaline(c_id, line, sizeof (line), bread)) > 0) {

		if (verbosemode)
			libbootlog(BOOTLOG_VERBOSE,
			    "read_headerlines: %s", line);
		/*
		 * See if this is a continuation line (first col is a
		 * space or a tab)
		 */
		if (line[0] != ' ' && line[0] != '	') {
			cur = next;
			next ++;
			new_buf =
			    realloc(c_id->resphdr, (cur + 1) * sizeof (void *));
			if (new_buf == NULL) {
				SET_ERR(c_id, ERRSRC_LIBHTTP, EHTTP_NOMEM);
				return (-1);
			}
			c_id->resphdr = new_buf;

			c_id->resphdr[cur] = strdup(line);
			if (c_id->resphdr[cur] == NULL) {
				SET_ERR(c_id, ERRSRC_LIBHTTP, EHTTP_NOMEM);
				return (-1);
			}
		} else {
			ptr = line;
			while (isspace(*ptr))
				ptr ++;
			c_id->resphdr[cur] = realloc(c_id->resphdr[cur],
			    strlen(c_id->resphdr[cur]) + strlen(ptr) + 1);
			if (c_id->resphdr[cur] == NULL) {
				SET_ERR(c_id, ERRSRC_LIBHTTP, EHTTP_NOMEM);
				return (-1);
			}
			(void) strcat(c_id->resphdr[cur], ptr);
		}
		ptr = &(c_id->resphdr[cur][strlen(c_id->resphdr[cur]) - 1]);
		while (ptr > c_id->resphdr[cur] && isspace(*ptr))
			ptr --;
	}
	c_id->resp.nresphdrs = next;

	/* Cause of any I/O error was already put into error stack. */
	return (n >= 0 ? 0 : -1);
}

static void
free_response(http_conn_t *c_id, int free_boundary)
{
	int i;

	/* free memory from previous calls */
	if (c_id->resp.statusmsg != NULL) {
		free(c_id->resp.statusmsg);
		c_id->resp.statusmsg = NULL;
	}
	for (i = 0; i < c_id->resp.nresphdrs; i++) {
		free(c_id->resphdr[i]);
		c_id->resphdr[i] = NULL;
	}
	c_id->resp.nresphdrs = 0;
	if (c_id->resphdr != NULL) {
		free(c_id->resphdr);
		c_id->resphdr = NULL;
	}

	if (free_boundary && c_id->boundary) {
		free(c_id->boundary);
		c_id->boundary = NULL;
		c_id->is_multipart = B_FALSE;
	}
}

static int
free_ctx_ssl(http_conn_t *c_id)
{
	int err_ret = 0;

	if (c_id->ssl != NULL) {
		if (SSL_shutdown(c_id->ssl) <= 0) {
			ulong_t err;
			while ((err = ERR_get_error()) != 0)
				SET_ERR(c_id, ERRSRC_LIBSSL, err);
			err_ret = -1;
		}
		SSL_free(c_id->ssl);
		c_id->ssl = NULL;
	}

	if (c_id->fd != -1 && socket_close(c_id->fd) < 0) {
		SET_ERR(c_id, ERRSRC_SYSTEM, errno);
		err_ret = -1;
	}
	c_id->fd = -1;

	if (c_id->ctx != NULL) {
		SSL_CTX_free(c_id->ctx);
		c_id->ctx = NULL;
	}

	return (err_ret);
}

/*
 * get_chunk_header - Get a chunk header line
 *
 * Arguments:
 *   c_id   - Structure describing the connection in question.
 *
 * Returns:
 *  >=0	- Length of next chunk
 *  -1	- Error occurred.  The error information is in the error stack.
 */
static int
get_chunk_header(http_conn_t *c_id)
{
	char	line[MAXHOSTNAMELEN];
	char	*ptr;
	int	value;
	int	ok;
	int	i;

	/*
	 * Determine whether an extra crlf pair will precede the
	 * chunk header.  For the first one, there is no preceding
	 * crlf.  For later chunks, there is one crlf.
	 */
	if (c_id->is_firstchunk) {
		ok = 1;
		c_id->is_firstchunk = B_FALSE;
	} else {
		ok = ((i = getaline(c_id, line, sizeof (line), B_FALSE)) == 0);
	}

	if (ok)
		i = getaline(c_id, line, sizeof (line), B_FALSE);
	if (!ok || i < 0) {
		/*
		 * If I/O error, the Cause was already put into
		 * error stack.  This is an additional error.
		 */
		SET_ERR(c_id, ERRSRC_LIBHTTP, EHTTP_NOHEADER);
		return (-1);
	}

	if (verbosemode)
		libbootlog(BOOTLOG_VERBOSE, "get_chunk_header: <%s>", line);


	/*
	 * The first (and probably only) field in the line is the hex
	 * length of the chunk.
	 */
	ptr = line;
	value = 0;
	while (*ptr != '\0' && (i = hexdigit(*ptr)) >= 0) {
		value = (value << 4) + i;
		ptr ++;
	}

	return (value);
}

/*
 * init_bread - Initialize the counters used to read message bodies.
 *
 * Arguments:
 *   c_id   - Structure describing the connection in question.
 *
 * Returns:
 *   0	- Success
 *  -1	- Error occurred.  The error information is in the error stack.
 *
 *  This routine will determine whether the message body being received is
 *  chunked or non-chunked. Once determined, the counters used to read
 *  message bodies will be initialized.
 */
static int
init_bread(http_conn_t *c_id)
{
	char	*hdr;
	char	*ptr;
	boolean_t sized = B_FALSE;

	/*
	 * Assume non-chunked reads until proven otherwise.
	 */
	c_id->is_chunked = B_FALSE;
	c_id->is_firstchunk = B_FALSE;
	hdr = http_get_header_value(c_id, "Content-Length");
	if (hdr != NULL) {
		c_id->body_size = strtol(hdr, NULL, 10);
		if (c_id->body_size == 0 && errno != 0) {
			free(hdr);
			SET_ERR(c_id, ERRSRC_LIBHTTP, EHTTP_BADSIZE);
			return (-1);
		}
		free(hdr);
		sized = B_TRUE;
	}

	/*
	 * If size was not determined above, then see if this is a
	 * chunked message. Keep in mind that the first chunk size is
	 * "special".
	 */
	if (!sized) {
		hdr = http_get_header_value(c_id, "Transfer-Encoding");
		if (hdr != NULL) {
			ptr = eat_ws(hdr);
			if (startswith((const char **)&ptr, "chunked;") ||
			    strcasecmp(ptr, "chunked") == 0) {
				c_id->is_firstchunk = B_TRUE;
				c_id->is_chunked = B_TRUE;
			}
			free(hdr);
			if (c_id->is_chunked) {
				c_id->body_size = get_chunk_header(c_id);
				if (c_id->body_size == -1) {
					/*
					 * Error stack was already set at a
					 * lower level.
					 */
					return (-1);
				}
				sized = B_TRUE;
			}
		}
	}

	/*
	 * Well, isn't this a fine predicament? It wasn't chunked or
	 * non-chunked as far as we can tell.
	 */
	if (!sized) {
		SET_ERR(c_id, ERRSRC_LIBHTTP, EHTTP_BADSIZE);
		return (-1);
	}

	c_id->body_read = 0;
	c_id->body_size_tot = c_id->body_size;
	c_id->body_read_tot = 0;

	return (0);
}

/*
 * get_msgcnt - Get the number of bytes left in the message body or chunk.
 *
 * Arguments:
 *   c_id   - Structure describing the connection in question.
 *   msgcnt - Where to store the message count.
 *
 * Returns:
 *   0	- Success
 *  -1	- Error occurred.  The error information is in the error stack.
 *
 *  Note that if the message being read is not chunked, then the byte count
 *  is simply the message size minus the bytes read thus far. In the case of
 *  chunked messages, the byte count returned will be the number of bytes
 *  left in the chunk. If the current chunk has been exhausted, then this
 *  routine will determine the size of the next chunk. When the next chunk
 *  size is zero, the message has been read in its entirety.
 */
static int
get_msgcnt(http_conn_t *c_id, ssize_t *msgcnt)
{
	/*
	 * If there are more bytes in the message, then return.
	 */
	*msgcnt = c_id->body_size - c_id->body_read;
	if (*msgcnt != 0) {
		return (0);
	}
	/*
	 * If this is not a chunked message and the body has been
	 * read, then we're done.
	 */
	if (!c_id->is_chunked) {
		return (0);
	}

	/*
	 * We're looking at a chunked message whose immediate
	 * chunk has been totally processed. See if there is
	 * another chunk.
	 */
	c_id->body_size = get_chunk_header(c_id);
	if (c_id->body_size == -1) {
		/*
		 * Error stack was already set at a
		 * lower level.
		 */
		return (-1);
	}

	/*
	 * No bytes of this chunk have been processed yet.
	 */
	c_id->body_read = 0;

	/*
	 * A zero length chunk signals the end of the
	 * message body and chunking.
	 */
	if (c_id->body_size == 0) {
		c_id->is_chunked = B_FALSE;
		return (0);
	}

	/*
	 * There is another chunk.
	 */
	c_id->body_size_tot += c_id->body_size;
	*msgcnt = c_id->body_size - c_id->body_read;

	return (0);
}

/*
 * getaline - Get lines of data from the HTTP response, up to 'len' bytes.
 *	  NOTE: the line will not end with a NULL if all 'len' bytes
 *	  were read.
 *
 * Arguments:
 *   c_id   - Structure describing the connection in question.
 *   line   - Where to store the data.
 *   len    - Maximum number of bytes in the line.
 *   bread  - TRUE if the lines are part of the message body.
 *
 * Returns:
 *   >=0    - The number of bytes successfully read.
 *   <0	    - An error occurred.  This is (the number of bytes gotten + 1),
 *	      negated.  In other words, if 'n' bytes were read and then an
 *	      error occurred, this will return (-(n+1)).  So zero bytes read
 *	      and then an error occurs, this will return -1.  If 1 bytes
 *	      was read, it will return -2, etc.
 *
 *	      Specifics of the error can be gotten using http_get_lasterr();
 *
 *  Note that I/O errors are put into the error stack by http_srv_recv().1
 */
static int
getaline(http_conn_t *c_id, char *line, int len, boolean_t bread)
{
	int	i = 0;
	ssize_t	msgcnt = 0;
	ssize_t	cnt;

	while (i < len) {
		/*
		 * Special processing required for message body reads.
		 */
		if (bread) {
			/*
			 * See if there is another chunk. Obviously, in the
			 * case of non-chunked messages, there won't be.
			 * But in either case, chunked or not, if msgcnt
			 * is still zero after the call to get_msgcnt(),
			 * then we're done.
			 */
			if (msgcnt == 0) {
				if (get_msgcnt(c_id, &msgcnt) == -1) {
					return (-(i+1));
				}
				if (msgcnt == 0) {
					break;
				}
			}
			cnt = MIN(msgcnt, sizeof (c_id->inbuf.buf));
		} else {
			cnt = sizeof (c_id->inbuf.buf);
		}

		/* read more data if buffer empty */
		if (c_id->inbuf.i == c_id->inbuf.n) {
			c_id->inbuf.i = 0;
			c_id->inbuf.n = http_srv_recv(c_id, c_id->inbuf.buf,
			    cnt);
			if (c_id->inbuf.n == 0) {
				return (i);
			}
			if (c_id->inbuf.n < 0) {
				return (-(i+1));
			}
		}
		/* skip CR */
		if (c_id->inbuf.buf[c_id->inbuf.i] == '\r') {
			INC_BREAD_CNT(bread, msgcnt);
			c_id->inbuf.i++;
			continue;
		}
		if (c_id->inbuf.buf[c_id->inbuf.i] == '\n') {
			INC_BREAD_CNT(bread, msgcnt);
			c_id->inbuf.i++;
			line[i] = '\0';
			return (i);
		}
		/* copy buf from internal buffer */
		INC_BREAD_CNT(bread, msgcnt);
		line[i++] = c_id->inbuf.buf[c_id->inbuf.i++];
	}
	return (i);
}

/*
 * getbytes - Get a block from the HTTP response. Used for the HTTP body.
 *
 * Arguments:
 *   c_id   - Structure describing the connection in question.
 *   line   - Where to store the data.
 *   len    - Maximum number of bytes in the block.
 *
 * Returns:
 *   >=0    - The number of bytes successfully read.
 *   <0	    - An error occurred.  This is (the number of bytes gotten + 1),
 *	      negated.  In other words, if 'n' bytes were read and then an
 *	      error occurred, this will return (-(n+1)).  So zero bytes read
 *	      and then an error occurs, this will return -1.  If 1 bytes
 *	      was read, it will return -2, etc.
 *
 *	      Specifics of the error can be gotten using http_get_lasterr();
 *
 *  Note that all reads performed here assume that a message body is being
 *  read. If this changes in the future, then the logic should more closely
 *  resemble getaline().
 *
 *  Note that I/O errors are put into the error stack by http_srv_recv().
 */
static int
getbytes(http_conn_t *c_id, char *line, int len)
{
	int	i = 0;
	ssize_t	msgcnt = 0;
	ssize_t	cnt;
	int	nbytes;

	while (i < len) {
		/*
		 * See if there is another chunk. Obviously, in the
		 * case of non-chunked messages, there won't be.
		 * But in either case, chunked or not, if msgcnt
		 * is still zero after the call to get_msgcnt(), then
		 * we're done.
		 */
		if (msgcnt == 0) {
			if (get_msgcnt(c_id, &msgcnt) == -1) {
				return (-(i+1));
			}
			if (msgcnt == 0) {
				break;
			}
		}

		cnt = MIN(msgcnt, len - i);

		if (c_id->inbuf.n != c_id->inbuf.i) {
			nbytes = (int)MIN(cnt, c_id->inbuf.n - c_id->inbuf.i);
			(void) memcpy(line, &c_id->inbuf.buf[c_id->inbuf.i],
			    nbytes);
			c_id->inbuf.i += nbytes;
		} else {
			nbytes = http_srv_recv(c_id, line, cnt);
			if (nbytes == 0) {
				return (i);
			}
			if (nbytes < 0) {
				return (-(i+1));
			}
		}

		i += nbytes;
		line += nbytes;
		msgcnt -= nbytes;
		c_id->body_read += nbytes;
		c_id->body_read_tot += nbytes;
	}

	return (i);
}

static int
http_srv_send(http_conn_t *c_id, const void *buf, size_t nbyte)
{
	int	retval;

	if (c_id->ssl != NULL) {
		if ((retval = SSL_write(c_id->ssl, buf, nbyte)) <= 0) {
			handle_ssl_error(c_id, retval);
		}
		return (retval);
	} else {
		retval = socket_write(c_id->fd, buf, nbyte, &c_id->host_addr);
		if (retval < 0) {
			SET_ERR(c_id, ERRSRC_SYSTEM, errno);
			return (-1);
		}
		return (retval);
	}
}

static int
http_srv_recv(http_conn_t *c_id, void *buf, size_t nbyte)
{
	int	retval;

	if (c_id->ssl != NULL) {
		if ((retval = SSL_read(c_id->ssl, buf, nbyte)) <= 0) {
			handle_ssl_error(c_id, retval);
		}
		return (retval);
	} else {
		retval = socket_read(c_id->fd, buf, nbyte, c_id->read_timeout);
		if (retval < 0) {
			SET_ERR(c_id, ERRSRC_SYSTEM, errno);
			return (-1);
		}
		return (retval);
	}
}

static boolean_t
http_check_conn(http_conn_t *c_id)
{
	early_err = 0;
	if (c_id == NULL || c_id->signature != HTTP_CONN_INFO) {
		early_err = EHTTP_BADARG;
		return (B_FALSE);
	}
	RESET_ERR(c_id);
	return (B_TRUE);
}

static void
handle_ssl_error(http_conn_t *c_id, int retval)
{
	ulong_t err;

	err = SSL_get_error(c_id->ssl, retval);

	switch (err) {
	case SSL_ERROR_NONE:
		return;

	case SSL_ERROR_ZERO_RETURN:
		SET_ERR(c_id, ERRSRC_LIBHTTP, EHTTP_CONCLOSED);
		return;

	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
	case SSL_ERROR_WANT_CONNECT:
	case SSL_ERROR_WANT_X509_LOOKUP:
		SET_ERR(c_id, ERRSRC_LIBHTTP, EHTTP_UNEXPECTED);
		return;

	case SSL_ERROR_SYSCALL:
		err = ERR_get_error();
		if (err == 0)
			SET_ERR(c_id, ERRSRC_LIBHTTP, EHTTP_EOFERR);
		else if (err == (ulong_t)-1)
			SET_ERR(c_id, ERRSRC_SYSTEM, errno);
		else {
			SET_ERR(c_id, ERRSRC_LIBSSL, err);
			while ((err = ERR_get_error()) != 0)
				SET_ERR(c_id, ERRSRC_LIBSSL, err);
		}
		return;

	case SSL_ERROR_SSL:
		while ((err = ERR_get_error()) != 0) {
			SET_ERR(c_id, ERRSRC_LIBSSL, err);
		}
		return;
	}
}

static int
count_digits(int value)
{
	int	count = 1;

	if (value < 0) {
		count++;
		value = -value;
	}

	while (value > 9) {
		value /= 10;
		count++;
	}
	return (count);
}

static int
hexdigit(char ch)
{
	if (ch >= '0' && ch <= '9')
		return (ch - '0');
	if (ch >= 'A' && ch <= 'F')
		return (ch - 'A' + 10);
	if (ch >= 'a' && ch <= 'f')
		return (ch - 'a' + 10);
	return (-1);
}

static char *
eat_ws(const char *buf)
{
	char *ptr = (char *)buf;

	while (isspace(*ptr))
		ptr++;

	return (ptr);
}

static boolean_t
startswith(const char **strp, const char *starts)
{
	int len = strlen(starts);

	if (strncasecmp(*strp, starts, len) == 0) {
		*strp += len;
		return (B_TRUE);
	}
	return (B_FALSE);
}
